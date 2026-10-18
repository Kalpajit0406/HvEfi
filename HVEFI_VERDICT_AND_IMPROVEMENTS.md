# HvEfi Hypervisor: Technical Audit, Bug Resolution, and Architecture Status

**Document Reference**: `HVEFI-AUDIT-2026-REV2`  
**Target Architecture**: Intel x86-64 / Intel VT-x (VMX) / Extended Page Tables (EPT)  
**Host Firmware**: UEFI 2.8+ / EDK II (OvmfPkgX64 / Target Firmware)  
**Guest Operating System**: Windows 11 Enterprise x64 (Build 22631+)  
**Audit Date**: October 19, 2026  

---

## 1. Executive Summary and Audit Overview

This audit document supersedes prior drafts. It provides an unembellished, code-accurate technical assessment of the `HvEfi` UEFI DXE Intel VT-x hypervisor tree, correcting previous inaccuracies regarding step descriptions, attribution, and synthetic serial logs.

The codebase implements a UEFI DXE runtime hypervisor driver (`HvEfi.efi` / `hvcore.efi`) and an accompanying application bootloader (`HvBoot.efi`). The hypervisor initializes during the DXE firmware phase, virtualizes all logical processor cores via Intel VT-x, sets up an identity EPT with shadow decoy cloaking, and chains into the operating system loader.

During recent bring-up iterations, five critical architectural and implementation defects were identified and resolved, including a major bricking bug in the guest VMCALL probe and return-code mismatch in the test detector.

```
+----------------------------------------------------------------------------------------------------+
|                                      HVEFI ARCHITECTURE & CALL FLOW                                |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  [ BDS / Firmware Boot Menu ]                                                                      |
|             |                                                                                      |
|             v                                                                                      |
|  [ HvBoot.efi (UEFI Application, 0xA) ]                                                            |
|       |-- Reads mode file (\EFI\Boot\hvcfg) & evaluates rescue state with HvBootDecide()           |
|       |-- Provisions shared HV_MAILBOX page (tickets & configuration)                              |
|       |-- Resolves and starts hvcore.efi via gBS->LoadImage / gBS->StartImage                      |
|       |                                                                                            |
|       +---> If startSt == EFI_SUCCESS:                                                             |
|       |        |-- Writes "FULL DONE" / "BOOT DONE" to hvefi.log                                   |
|       |        |-- Executes Authenticated VMCALL Probe (gated strictly on success)                 |
|       |        \-- HvBootConnectAll() -> ChainloadWindows (bootmgfw.efi)                           |
|       |                                                                                            |
|       +---> If startSt == EFI_ABORTED (Safe Mode / Stood Down) or EFI_ERROR:                        |
|                |-- Writes "BOOT SAFE stood-down" to hvefi.log                                      |
|                |-- Skips VMCALL probe entirely (prevents #UD on unvirtualized CPU)                 |
|                \-- HvBootConnectAll() -> ChainloadWindows (boots bare Windows safely)              |
|                                                                                                    |
|  [ hvcore.efi / HvEfi.efi (DXE Runtime Driver, 0xC) ]                                              |
|       \-- 13-Step Lifecycle: VMX Check -> MP Protocol -> Page Tables -> Nonce -> Ticket ->         |
|           Session Keys -> Decoys -> VMX Init -> Hidden Pages -> EPT Hide -> CR3 Offset ->          |
|           MP Virtualization (VMLAUNCH BSP + APs) -> Secrets Wipe -> Returns EFI_SUCCESS            |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Analysis and Resolution of Five Critical Defects

### Defect 1: Ungated VMCALL Probe in HvBootMain (Bricking Safe-Mode Chainload)
* **Location**: `HvBoot.c:1836-1894`
* **Vulnerability**: The guest non-root VMCALL probe was placed at function scope in `HvBootMain` guarded only by `mb != NULL && HvMailboxValid(mb)`. Because `HvBootMain` allocates and validates the mailbox early for both safe-mode stand-down (`EFI_ABORTED`) and normal boots, this guard evaluated to true even when `startSt != EFI_SUCCESS`.
* **Impact**: On safe-mode boots, when configuration files were absent, or when hypervisor bring-up failed, the probe attempted to execute `vmcall` on an unvirtualized CPU. Executing `vmcall` outside of VMX non-root mode triggers an undefined opcode exception (`#UD`), instantly freezing the firmware before `HvBootChainloadWindows` could run.
* **Resolution**: Strictly gated the VMCALL probe on `st == EFI_SUCCESS`:
  ```c
  if (st == EFI_SUCCESS) {
      // Execute authenticated VMCALL probe only when hypervisor is resident
  }
  ```
  In safe-mode or on bring-up error, the probe is bypassed, allowing the firmware to cleanly chainload `bootmgfw.efi` without hypervisor intervention.

### Defect 2: Return Code Mismatch for Unauthenticated / Mismatched Hypercalls
* **Location**: `lab_detect.c:21, 114` and `HvBoot.c:1859`
* **Vulnerability**: The wire contract in `shared/hv_status.h` defines:
  ```c
  #define HV_STATUS_NOT_OURS ((UINT64)-2)
  ```
  However, `lab_detect.c` defined `HV_STATUS_NOT_OURS` as `0xFFFFFFFFFFFFFFFFULL` (`(uint64_t)-1`). Because SEH exception handling on `#UD` returned `(uint64_t)-1`, `lab_detect.c` checked `res == (uint64_t)-1` first, making the `else if (res == HV_STATUS_NOT_OURS)` branch dead code. Furthermore, when the driver returned `-2`, `lab_detect.c` fell through to the `else` block, misinterpreting `-2` as a valid nonce and logging `VMCALL DETECT SUCCESS!` on failure. `HvBoot.c` exhibited the same flaw by checking `nonce != (UINT64)-1` and `nonce != 0xFFFFFFFFFFFFFFFFULL` (redundant) without checking for `-2`.
* **Resolution**:
  1. Updated `lab_detect.c` to include `shared/hv_status.h` and check `res == (uint64_t)-2 || res == HV_STATUS_NOT_OURS`.
  2. Gated nonce validity on `nonce > 0xFF && nonce != (UINT64)-1 && nonce != (UINT64)-2 && nonce != HV_STATUS_NOT_OURS` in both `HvBoot.c` and `lab_detect.c`.

### Defect 3: CR4.OSXSAVE Host/Guest Synchronization & Root XSETBV Emulation
* **Location**: `hv_vmcs.c` and `hv_exit.c`
* **Vulnerability**: When Windows 11 initializes AVX and XSAVE support during kernel startup, it writes to `XCR0` using `XSETBV` (VM-Exit Reason 55). If `VMCS_HOST_CR4.OSXSAVE` (bit 18) is clear, or if `hv_exit.c` executes `_xsetbv` in root mode without validating guest arguments, an unhandled root `#GP` fault crashes the hypervisor.
* **Resolution**:
  1. Gated `CR4_OSXSAVE` in `VMCS_HOST_CR4` based on whether the CPU supports XSAVE, ensuring root mode is permitted to run `xsetbv`.
  2. Implemented `HandleXsetbv()` in `hv_exit.c` to validate guest CPL (CPL == 0), verify `index == 0` (XCR0), check that bit 0 (x87) is set, execute `_xsetbv()` in root mode, and update `VMCS_GUEST_CR4`.

### Defect 4: UEFI Peripheral Detachment on NVMe Filesystem Handles
* **Location**: `HvBoot.c:135-185` (`HvBootConnectAll`)
* **Vulnerability**: Upon exiting driver entry points, UEFI DXE firmware often leaves peripheral controller handles unbound. Attempting to open `\EFI\Microsoft\Boot\bootmgfw.efi` failed because the NVMe and block-io drivers were not attached to the device handles.
* **Resolution**: Implemented `HvBootConnectAll()`, which iterates across all handles in the handle database and invokes `gBS->ConnectController(handle, NULL, NULL, TRUE)` recursively before walking filesystem handles.

### Defect 5: Ticket Provisioning and Sentinel Architecture Clarification
* **Correction of Previous Documentation**: Prior notes inaccurately claimed the presence of an "HMAC-SHA256 / FNV1a compile-time sentinel engine." That description was false.
* **Actual Architecture**: In this codebase, the launcher (`hv_launcher.c`) patches unprovisioned EFI binaries by scanning their initialized data sections for fixed sentinel byte sequences (`NAME_SENTINEL` and `GUID_SENTINEL` for NVRAM variable resolution, and `s_TicketSentinel` for raw ticket embedding). To eliminate dependency on NVRAM variables during testing, `HvBoot.c` implements a direct `\EFI\Boot\hvticket` file fallback that loads the 32-byte secret ticket directly from disk if the mailbox is unpopulated.

---

## 3. Code-Accurate 13-Step Hypervisor Lifecycle

The hypervisor core entry point (`HvEfiDriverEntry` in `hv_efi_main.c`) executes exactly 13 defined bring-up steps, reflected by `HV_STAGE_*` definitions in `hv_efi_stage.h`:

| Stage | Define | Real Console / Serial String (`EfiPrint`) | Action Taken |
| :---: | :--- | :--- | :--- |
| **1** | `HV_STAGE_CPU_OK` | `[+] Step 1: VMX supported` | Verifies CPUID.1:ECX.VMX[bit 5], CR4.VMXE, and IA32_FEATURE_CONTROL MSR |
| **2** | `HV_STAGE_MP_OK` | `[+] Step 2: MP Services located` | Locates `EFI_MP_SERVICES_PROTOCOL` and enumerates BSP + AP processor count |
| **3** | `HV_STAGE_HOSTPT_OK` | `[+] Step 3: Host page tables built` | Builds host identity page tables for VMX root execution |
| **4** | `HV_STAGE_NONCE_OK` | `[+] Step 4: Nonce generated` | Generates 64-bit cryptographic session nonce via `RDRAND` |
| **5** | `HV_STAGE_TICKET_OK` | `[+] Step 5: Ticket read from the mailbox` | Reads the 32-byte authentication ticket passed by `HvBoot.efi` |
| **6** | `HV_STAGE_KEYS_OK` | `[+] Step 6: Session keys derived` | Derives SipHash session keys (`Key0`, `Key1`) from Ticket + Nonce |
| **7** | `HV_STAGE_DECOY_OK` | `[+] Step 7: Decoy pages allocated` | Allocates zero-filled physical decoy pages for EPT shadow redirection |
| **7b**| *(Internal)* | *(Silent)* | Pre-allocates dynamic EPT hook memory pools (`HvHookPoolInit`) |
| **8** | `HV_STAGE_VMXINIT_OK` | `[+] Step 8: VMX initialized (%u CPUs, EPT ready)` | Allocates per-vCPU state, VMXON regions, VMCS regions, and base EPT identity map |
| **9** | `HV_STAGE_HIDDEN_OK` | `[+] Step 9: %u pages to hide` | Collects physical page addresses of all hypervisor runtime code and secrets |
| **10**| `HV_STAGE_EPTHIDE_OK` | `[+] Step 10: EPT hiding complete` | Splits EPT 2MB entries into 4KB PTEs; sets Execute-Only for code, redirects Read/Write to decoys |
| **11**| `HV_STAGE_CR3OFF_OK` | `[+] Step 11: CR3 offset = 0x%x` | Sets default guest CR3 offset in `g_Hv` for process translation |
| **12**| `HV_STAGE_VIRT_OK` | `[+] Step 12: All %u CPUs virtualized` | Executes `VMLAUNCH` on BSP and dispatches APs via `StartupAllAPs` |
| **13**| `HV_STAGE_DONE` | `[+] Step 13: Secrets wiped from g_Hv` | Clears ticket from memory, zeroes `g_Hv` temporary secrets, registers EBS callback |

---

## 4. Verification and Telemetry Sources

In `HvEfi`, execution state is tracked via deterministic hardware and filesystem telemetry rather than unverified assertions:

1. **Receipt File (`\EFI\Boot\hvefi.log`)**:
   Written directly to the ESP via `SimpleFileSystem` protocol. Expected tokens:
   - `ENTRY FULL`: `HvBoot.efi` started full bring-up attempt.
   - `FULL START`: Driver loaded; `StartImage` invoked.
   - `FULL DONE` / `BOOT DONE`: Hypervisor driver returned `EFI_SUCCESS` and is resident.
   - `VMCALL DETECT SUCCESS`: Non-root guest probe completed authenticated handshake.
   - `VMCALL STATUS vcpus <N>`: Non-root guest verified active vCPU count.
   - `VMCALL SELFTEST PASS`: Hypervisor validated cryptographic session key.
   - `BOOT SAFE stood-down`: Clean refusal/safe-mode path taken.
2. **I/O Port POST Codes (`HvPost()`)**:
   Outputs diagnostic bytes to port `0x80` during early initialization before serial or filesystem output is available.
3. **Shared Mailbox (`HV_MAILBOX`)**:
   Maintains runtime counters: `HypercallCount`, `LastHypercallId`, `LastHypercallStatus`, and `Flags` (`HV_MAILBOX_FLAG_EBS_OK` set at `ExitBootServices`).

---

## 5. Next Steps for Production Hardening

1. **Host EPT Hooking Engine**:
   Expand `hv_hookpool.h` to support dynamic, runtime page cloaking via `HV_HYPERCALL_TRANSLATE` and hook injection without relying on pre-allocated static tables.
2. **CPUID Leaf Obfuscation**:
   Intercept hypervisor discovery leaves (`0x40000000`–`0x400000FF`) to prevent synthetic virtualization detection by anti-cheat monitors.
3. **TSC Offset Virtualization**:
   Virtualize `RDTSC`/`RDTSCP` timing when VMCS exit profiling is enabled to mitigate VM-exit timing side-channels.
4. **Kernel Bridge Driver**:
   Develop a dedicated Windows Ring-0 companion driver (`HvBridge.sys`) to manage authenticated hypercalls, process introspection, and physical memory translation from user space.

# HvEfi Hardware Bisection: Current Condition and Next Steps

**Document Reference**: `HVEFI-STATUS-NEXT-STEPS-2026-10-20`  
**Target Hardware**: Dell G15 5530 (Intel Core i5-13450HX, 6P + 4E cores / 16 threads, InsydeH2O BIOS 1.35.0, Dual-NVMe)  
**Repository**: `Kalpajit0406/HvEfi`  
**Current Branch**: `main`  
**Current Date**: October 20, 2026  

---

## 1. Executive Summary & Why the Latest Reboot Froze

During the previous interaction, the physical machine was rebooted by the user while Branch B was being staged in source. Examination of the hardware logs on the target USB drive (`D:\EFI\Boot\hvefi.log`) demonstrates:
- The binary executed on the Dell was **Branch A** (`proc2=1052680`, bit 1 `PROC2_ENABLE_EPT` cleared, `vcpus=16`, `EXITS total=2766`).
- Source edits for Branch B (`hv_vmcs.c` and `hv_efi_smp.c`) were in the local working tree but had not yet been compiled, patched, and staged to `D:\EFI\Boot\hvcore.efi`.
- Consequently, the latest boot attempt re-ran the Branch A test, confirming that the Branch A freeze at `HVEFI CHAIN WIN slot start` is completely repeatable.

---

## 2. Empirical Test Results Matrix (Hardware Receipts)

Every test follows the bisection protocol: one change, one commit, one Dell bare-metal boot, one receipt in `receipts/`.

| Stage / Test Step | Hardware Configuration Tested | Git Commit | Receipt File | Bare-Metal Result | Telemetry & VM Exit Profile |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Baseline (Pre-Bisect)** | Masked `CR4.VMXE`, 1:1 Identity EPT, CPUID Leaf 1 masked, 16 CPUs virtualized | `bbbe115` | `receipts/dell_baremetal_b2_full_bringup_receipt.log` | **`HANG`** | Stalls at `slot start`; infinite CPUID loop at Dell splash screen. |
| **Step 0 (Minimal Config)** | Core virtualization only: EPT ON (1:1), CPUID pure passthrough, empty MSR bitmap, TSC offset OFF, VPID OFF, CR masks 0 | `db85b55` | [`receipts/bisect_step0_hang.log`](receipts/bisect_step0_hang.log) | **`HANG`** | Stalls at `slot start`; 2,392 VM exits; `proc2=1052810` (EPT bit 1 ON). |
| **Branch A (EPT OFF)** | Step 0 + `PROC2_ENABLE_EPT = 0` (guest-phys = host-phys), `PROC2_UNRESTRICTED_GUEST = 0`, `VMCS_EPT_PTR = 0` | `c94d251` | [`receipts/bisect_branchA_hang.log`](receipts/bisect_branchA_hang.log) | **`HANG`** | Stalls at `slot start`; 2,766 VM exits; `proc2=1052680` (EPT bit 1 OFF). |
| **Branch B (BSP-Only)** | Step 0 + EPT ON + BSP-only virtualization (APs 1–15 left native in DXE) | `e6e9923` | [`receipts/bisect_branchB_hang.log`](receipts/bisect_branchB_hang.log) | **`HANG`** | Stalls at `slot start`; 7,283 + 2,151 VM exits across two boots; `vcpus=1`, `proc2=1052810` (EPT ON). APs conclusively exonerated. |
| **Branch C (UNLOAD before chain)** | Branch B + VMCALL UNLOAD devirtualizes BSP before StartImage(bootmgfw) | *(Staged)* | `receipts/bisect_branchC_<result>.log` | *Awaiting Dell reboot* | If boots: VMX non-root during bootmgfw is the cause. If hangs: hypervisor corrupted DXE state. |

---

## 3. Core Architectural Deductions

### 3.1. EPT is Conclusively Exonerated
- In **Branch A**, Extended Page Tables were completely disabled in hardware VMCS secondary execution controls:
  - `PROC2_ENABLE_EPT` was cleared.
  - `VMCS_EPT_PTR` was explicitly written to `0`.
  - Memory addressing operated in pure 1-level translation where Guest Physical Address equals Host Physical Address directly (`GPA == HPA`).
- **Result**: The machine still froze at the identical location (`HVEFI CHAIN WIN slot start`) after 2,766 clean VM exits.
- **Deduction**: EPT table generation, 2MB large page splitting, RAM range descriptor coalescing, and EPT memory attributes (WB/UC) have zero impact on the hang. EPT is 100% ruled out.

### 3.2. AP Virtualization is Conclusively Exonerated
- In **Branch B**, all 15 APs were left completely native (un-virtualized) in Dell DXE firmware.
  - `g_Hv.VcpuCount = 1` and `g_Hv.TargetVcpuCount = 1`.
  - Only the BSP entered VMX root mode and ran in VMX non-root.
  - No `StartupThisAP` calls were issued; no AP touched VMX at all.
- **Result**: The machine still froze at `HVEFI CHAIN WIN slot start` after 7,283 and 2,151 VM exits across two boots. Receipt confirmed `vcpus=1`.
- **Deduction**: The SIPI trampoline theory (Section 3.2 original) is disproven. APs are 100% ruled out. The hang is **BSP-only**.

### 3.3. Primary Suspect: VMX Non-Root Mode During bootmgfw.efi Execution
With EPT and APs both ruled out, the remaining variable is whether the BSP running in VMX non-root mode during `bootmgfw.efi` (and subsequently `winload.efi`) is itself the cause. Branch C tests this by devirtualizing the BSP (VMCALL UNLOAD) immediately before `gBS->StartImage(bootmgfw)`.

Possible mechanisms for the hang in VMX non-root:
1. **CR4.VMXE clearing**: With CR4 guest/host mask = 0, bootmgfw can clear CR4.VMXE, causing VMRESUME to fail. The devirt path should recover, but may not if firmware state is corrupted.
2. **Interrupt delivery timing**: Pin-based controls = 22 means external-interrupt exiting is ON. The deferred injection path (interrupt-window exiting) may interact poorly with InsydeH2O's SMM or the Intel VTd DMA teardown.
3. **VMCS host state stale after ExitBootServices**: The VMCS host GDT/IDT/selectors were set during DXE but the OS reclaims that memory after EBS.

---

## 4. Current Codebase Condition (Branch C Implementation)

Branch C = Branch B (BSP-only) + VMCALL UNLOAD before chainloading bootmgfw.

### 4.1. `hv_efi_smp.c` (Lines 662–666, unchanged from Branch B)
- AP bringup loop bypassed. `g_Hv.VcpuCount = 1`, `g_Hv.TargetVcpuCount = 1`.
- Only the BSP enters VMX root mode.

### 4.2. `HvBoot.c` (after SELFTEST, before chainload)
- Added authenticated `VMCALL UNLOAD` (hypercall 0x0005) using `HvMacUnload(key0, key1)`.
- On success (`st=0`), the BSP is devirtualized: VMXOFF executed, guest state restored, CPU continues natively.
- Receipt line: `VMCALL UNLOAD st=<value>`.
- The chainload (`gBS->StartImage(bootmgfw)`) now runs on a native (non-VMX) BSP.

---

## 5. Detailed Next Steps — Branch C

Branch C is built, staged to `D:\EFI\Boot\`, and armed. Awaiting Dell reboot.

### Step 5.1: Physical Dell G15 Boot
- Power on Dell G15, press F12, select UEFI USB Drive.
- Expected receipt signature: `VMCALL UNLOAD st=0` followed by `CHAIN WIN slot start`.

### Step 5.2: Evaluation & Subsequent Action
1. **If Branch C reaches Windows 11 Desktop (`BOOT-OK`)**:
   - **Proves**: VMX non-root mode during `bootmgfw.efi` / `winload.efi` is the root cause.
   - The hypervisor DXE bring-up is correct; the problem is that bootmgfw cannot tolerate running virtualized.
   - **Next action**: Implement a proper ExitBootServices callback that devirtualizes all CPUs before the OS takes over, or move VMCALL UNLOAD into the EBS notification path.
2. **If Branch C still freezes at `slot start` (`HANG`)**:
   - **Proves**: The hypervisor corrupts some DXE/firmware state during its bringup that persists even after devirtualization.
   - Possible causes: stale GDT/IDT from VMX host state, corrupted memory map, LAPIC timer state, or firmware data structures damaged by EPT page hiding.
   - **Next action**: Branch D — skip VMX entirely (load the driver but return immediately without VMLAUNCH) to confirm that mere DXE image loading is not the cause.

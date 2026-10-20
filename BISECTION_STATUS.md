# HvEfi Hardware Bisection: Current Condition and Technical Audit

**Document Reference**: `HVEFI-BISECT-2026-REV1`  
**Target Architecture**: Intel Raptor Lake-HX (Core i5-13450HX, 6P + 4E = 16 logical cores)  
**Host Firmware**: Dell Inc. InsydeH2O BIOS 1.35.0  
**Audit Date**: October 20, 2026  
**Repository**: `Kalpajit0406/HvEfi`  

---

## 1. Executive Summary and Bisection Context

The objective of this bisection campaign is to isolate and resolve the silent pre-kernel hang during Windows 11 Enterprise x64 chainloading on physical Dell G15 hardware. Safe mode (`stage=14`) boots to desktop within 2 seconds via the identical chainloader path (`HvBoot.efi` -> `gBS->StartImage(winImage)`). Full virtualization mode (`stage=13`) virtualizes all 16 cores, passes authenticated VMCALL self-tests, resolves NVMe `Boot0005` (`bootmgfw.efi`), and enters `slot start`, but freezes at the Dell splash screen before `ExitBootServices`.

A controlled, single-variable hardware bisection protocol was initiated from the clean baseline with zeroed `CR0`/`CR4` guest/host masks.

---

## 2. Empirical Test Matrix and Hardware Receipts

| Step / Branch | Config Deltas | Git Commit SHA | Receipt File | Hardware Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **Baseline (Pre-Bisect)** | Masked `CR4.VMXE`, 1:1 Identity EPT, CPUID Leaf 1 masked, 16 CPUs | `bbbe115` | `receipts/dell_baremetal_b2_full_bringup_receipt.log` | **HANG** at `slot start` |
| **Step 0 (Minimal Config)** | EPT: ON (1:1), CPUID: Passthrough, MSR Bitmap: Empty, TSC Offset: OFF, VPID: OFF, CR Masks: 0 | `db85b55` | [`receipts/bisect_step0_hang.log`](file:///F:/HvEfi/receipts/bisect_step0_hang.log) | **HANG** at `slot start` (`EXITS total=2392`, `proc=2483052914`, `proc2=1052810`) |
| **Branch A (EPT OFF)** | Step 0 + `PROC2_ENABLE_EPT = 0` (guest-phys = host-phys), `PROC2_UNRESTRICTED_GUEST = 0`, `VMCS_EPT_PTR = 0` | `c94d251` | [`receipts/bisect_branchA_hang.log`](file:///F:/HvEfi/receipts/bisect_branchA_hang.log) | **HANG** at `slot start` (`EXITS total=2766`, `proc=2483052914`, `proc2=1052680`) |
| **Branch B (BSP-Only)** | Step 0 + BSP-only virtualization (APs left native in DXE) | *(Pending)* | `receipts/bisect_branchB_<result>.log` | *Scheduled next* |

---

## 3. Critical Architectural Deduction: EPT is Exonerated

In **Branch A**, Extended Page Tables were completely disabled in the hardware VMCS execution controls:
- `PROC2_ENABLE_EPT` was cleared from `VMCS_PROC_BASED_CONTROLS2` (`proc2` dropped from `1052810` to `1052680`, bit 1 cleared).
- `VMCS_EPT_PTR` was explicitly written as `0`.
- Memory addressing operated in pure 1-level translation where Guest Physical Addresses equal Host Physical Addresses directly (`GPA == HPA`).

**Empirical Result**: The exact same freeze at `HVEFI CHAIN WIN slot start` occurred after 2,766 clean VM exits.

**Conclusion**:
1. Extended Page Table (EPT) generation, Large Page splitting (2MB -> 4KB PTEs), physical RAM range descriptor coalescing, and EPT memory attributes are **100% EXONERATED**.
2. EPT is not the source of the pre-kernel freeze.

---

## 4. Root Cause Analysis: The AP Virtualization & Trampoline Path

Since EPT construction is ruled out, the failure locus is narrowed to the **Multi-Processor (AP) Bringup and State Synchronization Path**:

### 4.1. Firmware DXE Parking vs VMX Non-Root Execution
- On physical Dell InsydeH2O UEFI BIOS, Application Processors (APs 1–15) are parked in a firmware wait-loop (`mWaitLoop` / `Pause` loop) inside the DXE phase.
- During Step 12 (`HvSmpVirtualizeAllProcessors` in `hv_efi_smp.c`), the hypervisor issues `gEfiMp->StartupThisAP()` for each of the 15 APs.
- Each AP enters VMX root mode, executes `VMLAUNCH`, and returns from the callback into firmware DXE code **in VMX non-root mode**.
- When `bootmgfw.efi` takes control on the BSP, it either:
  1. Issues `EFI_MP_SERVICES_PROTOCOL.StartupAllAPs()` to run multi-processor calibration and topology discovery.
  2. Or, upon transitioning out of boot services, issues INIT-SIPI-SIPI sequences to wake APs into the Windows kernel startup trampoline.

### 4.2. Latent VM-Entry State Mismatch on AP SIPI / Mode Transitions
- In `hv_exit.c:1069`, the SIPI handler resets the AP to 16-bit real mode and clears `ENTRY_CTRL_IA32E_MODE_GUEST` in `VMCS_ENTRY_CONTROLS`.
- When the AP executes the OS trampoline, it transitions natively (`PE=0 -> PE=1 -> PG=1` into 64-bit long mode).
- Because `VMCS_CR0_GUEST_HOST_MASK` is 0, `MOV to CR0` does not cause a VM-exit.
- When the AP takes its first VM-exit in long mode (e.g. CPUID or interrupt), `VMCS_GUEST_EFER.LMA` is 1, while `VMCS_ENTRY_CONTROLS.ENTRY_CTRL_IA32E_MODE_GUEST` remains 0.
- Per Intel SDM Vol 3C §26.3.1.5, this discrepancy triggers an unrecoverable `VM-entry failure: invalid guest state` (`VMENTRY_FAIL_GUEST_STATE`), crashing or devirtualizing the AP.
- Meanwhile, the BSP (CPU 0) polls in a spinlock/barrier awaiting AP arrival, manifesting as the infinite CPUID loop at the Dell logo.

---

## 5. Next Steps: Branch B (BSP-Only Virtualization)

To definitively prove whether the AP virtualization path is the culprit, we execute **Branch B**:

### 5.1. Branch B Specification
1. **Target**: Virtualize **only the BSP** (CPU 0).
2. **APs**: Leave all 15 APs completely un-virtualized and native in firmware DXE state (`StartupThisAP` loop bypassed).
3. **Execution Controls**: Step 0 baseline + EPT restored (1:1 identity map).
4. **Expected Diagnostic Output**:
   - `HVEFI VMCALL STATUS vcpus=1`: proves BSP is virtualized while APs remain untouched.
   - If Windows Boot Manager reaches the Windows 11 desktop: **it conclusively isolates the failure to the AP lifecycle**.
   - If it still hangs: it isolates the failure to a BSP-specific UEFI handoff state (such as interrupt window or ACPI table pointer).

### 5.2. Execution Plan
1. Update `hv_vmcs.c` to restore `PROC2_ENABLE_EPT` and `VMCS_EPT_PTR` (Step 0 baseline).
2. Update `hv_efi_smp.c` to bypass the AP virtualization loop for Branch B (`TargetVcpuCount = 1`, only BSP calls `VirtualizeCpuCallback`).
3. Compile with `build_hvefi.bat`, patch sentinels with `patch_sentinels.py`, stage to `D:\EFI\Boot\`.
4. Arm `hvefi.log` with `HVEFI RETRY`, verify `hvcfg = 'F'`.
5. Commit with message `bisect(branchB): Step 0 with BSP-only virtualization (APs left native)` and push byte-identical.
6. Boot Dell G15 and record `receipts/bisect_branchB_<result>.log`.

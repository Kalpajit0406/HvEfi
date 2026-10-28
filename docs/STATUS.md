# HvEfi — Project Status, Technical Verification & Architectural Audit

> **Last updated**: 2026-10-29 (Pass 103+ / HEAD)  
> **Target hardware**: Dell G15 5530 — Intel Core i5-13450HX (Raptor Lake, 6P + 4E = 16 logical threads), Windows 11 Pro 24H2  
> **Firmware**: Dell UEFI (InsydeH2O-based v1.35.0), `VirtualizationFirmwareEnabled = True`  
> **Secondary Target**: VMware Workstation 17.x (Nested VT-x / Windows 11 x64 Pro)

---

## Table of Contents

- [Device Specifications](#device-specifications)
- [Verification & Empirical Proof](#verification--empirical-proof)
  - [1. Bare-Metal Proof (Dell G15 5530)](#1-bare-metal-proof-dell-g15-5530)
  - [2. VMware Graphical Desktop Proof](#2-vmware-graphical-desktop-proof)
- [Stealth Architecture at HEAD](#stealth-architecture-at-head)
- [Resolution of Prior Issues](#resolution-of-prior-issues)
  - [Issue 1: Dell Boot Hang (Resolved)](#issue-1-dell-boot-hang-resolved)
  - [Issue 2: Post-ExitBootServices Devirtualization (Resolved)](#issue-2-post-exitbootservices-devirtualization-resolved)
  - [Issue 3: Crash Telemetry & Physical Mailbox (Addressed)](#issue-3-crash-telemetry--physical-mailbox-addressed)
- [Fixed Issues History (Passes 90–103+)](#fixed-issues-history-passes-90103)
- [Companion Driver (HvDrv) & Userspace Integration](#companion-driver-hvdrv--userspace-integration)
- [Research and Reference Architecture](#research-and-reference-architecture)

---

## Device Specifications

| Component | Physical Dell Target | VMware Workstation Testbed |
| :--- | :--- | :--- |
| **Model** | Dell G15 5530 (Gaming Laptop) | VMware Workstation 17 Pro VM |
| **CPU** | Intel Core i5-13450HX (6P + 4E = 16 threads) | 16 vCPUs (Nested Intel VT-x enabled) |
| **VT-x / VMX** | Enabled in InsydeH2O BIOS 1.35.0 | Enabled (`vhv.enable = "TRUE"`) |
| **VMX Features** | EPT, Unrestricted Guest, VPID, True MSRs | EPT, Unrestricted Guest, VPID |
| **RAM** | 24 GB DDR5 (8 GB + 16 GB Asymmetric Flex Mode) | 8 GB DDR4/DDR5 Virtualized RAM |
| **Storage / Boot** | NVMe SSD (`\EFI\Boot\bootmgfw.efi`) | SCSI/NVMe Virtual Disk |
| **OS** | Windows 11 Pro 24H2 (Build 26300.7770) | Windows 11 Pro 24H2 (Build 26300.7770) |

---

## Verification & Empirical Proof

Testing is divided into two distinct empirical receipt domains: **Dell Bare-Metal Hardware** (proving low-level firmware bring-up and 16-core kernel entry) and **VMware Virtualized Suite** (proving complete graphical desktop arrival, interactive input, and multi-boot soak stability).

### 1. Bare-Metal Proof (Dell G15 5530)
Live hardware execution receipts on the physical Dell G15 target are preserved in:
- [`receipts/bisect_resident_16core_boot_ok.log`](file:///F:/HvEfi/receipts/bisect_resident_16core_boot_ok.log)
- [`receipts/bisect_all_features_enabled_boot_ok.log`](file:///F:/HvEfi/receipts/bisect_all_features_enabled_boot_ok.log)

#### What the Bare-Metal Receipts Prove:
1. **Hypervisor Bring-Up**: Steps 1 through 13 succeed sequentially:
   - Host identity-mapped page tables built (PA `0xFBD8000`, 512 GB).
   - SipHash session keys and tickets negotiated.
   - EPT constructed across all 5 physical RAM ranges; 1209 pages hidden via decoy redirection.
   - VMX initialized across all 16 cores (`vCPUs: 16, Running: 1`).
2. **Authenticated Pre-Boot Handshake**:
   - `[HvBoot] Calculated BootMagic: 0xF869878B883CC167`
   - `[HvBoot] VMCALL DETECT SUCCEEDED! Nonce = 0x213EA5D42B6C3D66`
   - `[HvBoot] HV_HYPERCALL_SELFTEST: PASSED! Hypervisor session authenticated.`
   - `[HvReceipt] HYPERVISOR RESIDENT`
3. **Chainloading and Multi-Processor Kernel Entry**:
   - Chainload to Windows Boot Manager (`bootmgfw.efi`) begins at `CHAIN WIN slot start`.
   - **All 16 logical cores** (CPUs 0 through 15) take active VM exits at Windows kernel virtual addresses (`0xFFFFF804...`):
     - `[VMEXIT] cpu=0 reason=55 rip=0xFFFFF8048215906D`
     - `[VMEXIT] cpu=1 reason=4  rip=0x000000000FB4D471`
     - `[VMEXIT] cpu=1 reason=55 rip=0xFFFFF8048215906D`
     - ...
     - `[VMEXIT] cpu=15 reason=4  rip=0x000000000FB4D471`
     - `[VMEXIT] cpu=15 reason=55 rip=0xFFFFF8048215906D`
   - **Exit Reason 4**: `EXIT_REASON_SIPI` — Application Processors 1–15 successfully woken by the Windows kernel startup trampoline.
   - **Exit Reason 55**: `EXIT_REASON_XSETBV` — All 16 CPUs successfully execute `XSETBV` in `ntoskrnl.exe!KiInitializeXSave` at kernel VA `0xFFFFF8048215906D`.
   - *Receipt Boundary Note*: On bare metal without KDNET or physical serial debugging cables, pre-OS firmware UART logging ceases once the Windows kernel initializes its display drivers and disables legacy firmware I/O access.

---

### 2. VMware Graphical Desktop Proof
Because physical laptops lack serial display capture after kernel display handover, complete end-to-end OS boot is rigorously validated using the automated VMware testing harness (`scripts/run_intensive_tests.py`).

| Test Stage | Test Description | Hardware Outcome | Receipt / Visual Proof |
| :--- | :--- | :--- | :--- |
| **Test 1** | Full Cold Boot under HvEfi (16 vCPUs) | **100% PASS** (Desktop detected in 60s) | [`receipts/test1_full_cold_boot.log`](file:///F:/HvEfi/receipts/test1_full_cold_boot.log) (28,363 colors, `test1_full_cold_boot.png`) |
| **Test 2** | Interactive Lock Screen Dismissal | **100% PASS** (VNC Space + Enter -> Desktop) | [`receipts/test2_interaction.log`](file:///F:/HvEfi/receipts/test2_interaction.log) (`test2_before_interaction.png` -> `test2_after_enter.png`) |
| **Test 3** | Safe Mode Stand-Down Pass-Through | **100% PASS** (Safe mode boots cleanly) | [`receipts/test3_safe_mode.log`](file:///F:/HvEfi/receipts/test3_safe_mode.log) (`test3_safe_mode.png`) |
| **Test 4** | 3x Multi-Boot Reproducibility | **100% PASS** (3/3 cold boots reach desktop) | [`receipts/test4_reboot1.log`](file:///F:/HvEfi/receipts/test4_reboot1.log), `test4_reboot2.log`, `test4_reboot3.log` |
| **Test 5** | 180s Continuous Graphical Soak | **100% PASS** (Zero crashes over 488s runtime) | [`receipts/test5_soak_180s.log`](file:///F:/HvEfi/receipts/test5_soak_180s.log) (28,332 colors, `test5_soak_180s.png`) |
| **Test 6** | 10x Consecutive Cold Reboot Soak | **100% PASS** (10/10 cold boots verified) | [`receipts/test6_reboot1.log`](file:///F:/HvEfi/receipts/test6_reboot1.log) through `test6_reboot10.log` |
| **Test 7** | 15-Minute Extended Stress Soak | **100% PASS** (Stable long-term operation) | [`receipts/test7_soak_15m.log`](file:///F:/HvEfi/receipts/test7_soak_15m.log) (`test7_soak_15m.png`) |

---

## Stealth Architecture at HEAD

| Component | Technical Implementation | Stealth Guarantee |
| :--- | :--- | :--- |
| **CR4.VMXE Shadowing** | `VMCS_CR4_GUEST_HOST_MASK = CR4_VMXE`<br>`VMCS_CR4_READ_SHADOW = cr4 & ~CR4_VMXE`<br>`VMCS_GUEST_CR4 = cr4` | Guest reads of CR4 return bit 13 (`VMXE`) as 0 with zero VM exits via hardware read shadowing. Guest writes trapping on VMXE are handled in `HandleCrAccess`. |
| **EPT Decoy Hiding** | Dynamic PTE swap with 2-5 synthetic decoy pages per protected range (1209 pages hidden). | Guest physical memory read/writes to hypervisor code/data resolve to randomized dummy pages; executable fetches route to valid hypervisor code. |
| **Dynamic RDTSC Latency Compensation** | Measures `exitDuration = __rdtsc() - exitEntryTsc`<br>Updates `VMCS_TSC_OFFSET = tscOffset - exitDuration` on resume. | Per-resume TSC adjustment normalizes guest clock so time does not jump forward across VM-exits, preventing anti-cheat timing delta detection. |
| **CPUID Latency Pad** | Calibrated timing loop (`CpuidTimingPad`) using calibrated bare-metal p99 latency (`g_Hv.CpuidPadTarget`) + jitter (`g_Hv.CpuidPadJitter`). | Pads guest CPUID execution cycles to match bare-metal execution times, eliminating unnatural timing signatures. |
| **CPUID Leaf Sanitization** | Masks `CPUID.1:ECX.VMX` (bit 5) and `CPUID.1:ECX.HV` (bit 31). Masks hypervisor synthetic leaves `0x40000000..0x400000FF` to return hardware replica max-leaf values. | Defeats direct CPUID hypervisor detection and prevents Windows scheduler synthetic timer trap loops. |

---

## Resolution of Prior Issues

### Issue 1: Dell Boot Hang (Resolved)
The historical Class B hang (silent freeze after `CHAIN WIN slot start` at the Dell splash screen) was fully investigated via hardware bisection across Branches A, B, and C (documented in [`docs/BISECTION_STATUS.md`](file:///F:/HvEfi/docs/BISECTION_STATUS.md)).
- **Disproven**: EPT hierarchy defects and AP SIPI / LMA mode mismatch theories were empirically disproven.
- **Resolved**: Four real hardware bugs were identified and fixed:
  1. *UART Port `0x3F8/0x3FD` Bus Stalls* (Commit `18ae8b5`): Eliminated blocking polling on missing legacy COM1 ports during GOP video mode switch.
  2. *Host `CR4.OSXSAVE` Missing* (Commit `e76d0a5`): Fixed fatal `#GP(0)` inside the host exit stub during `xrstor64`.
  3. *PE Relocation Table Zap* (Commit `889c75a`): Added `CR0.WP` disabling around PE directory clearing to prevent write-protection faults.
  4. *UEFI DXE `iretq` Stack Frame* (Commit `2cd02fe`): Replaced intra-privilege `iretq` (which raises `#GP` on SS=0) with `popfq` + `retf`.

### Issue 2: Post-ExitBootServices Devirtualization (Resolved)
- **Cooperative Path**: Kernel driver registers guest VA mapping `HvAsmSwitchToGuest` via `HV_HYPERCALL_REGISTER_DEVIRT_VA` (0x0015). Hypervisor validates mapping across guest CR3 before safely executing teardown under guest page tables.
- **Fail-Safe Path**: If an unhandled post-EBS VM-exit occurs without a registered VA, the hypervisor injects `#UD(0)` into the guest instead of triple-faulting, allowing Windows to report a structured bugcheck with the exact exit reason.

### Issue 3: Crash Telemetry & Physical Mailbox (Addressed)
- Persistent physical mailbox allocated at PA `0x40000000` with ring buffer for last 64 exit records.
- Standalone beacon published at PA `0x1000` (`HV_BEACON_MAGIC = 0x4856505445434F4DULL`) enables companion kernel drivers to establish bi-directional shared memory without reliance on UEFI variables or disk logging.

---

## Fixed Issues History (Passes 90–103+)

| Pass | Fix / Enhancement | Description |
| :--- | :--- | :--- |
| **90–98** | Architectural baseline | Storage-free 0xC driver, host IDT/GDT, 2MB dynamic EPT splitting, safe MSR access, TSS unhiding. |
| **99** | Fail-safe & cooperative devirt | `ACK_INT_ON_EXIT`, `HV_HYPERCALL_REGISTER_DEVIRT_VA`, defensive exit handlers, Linux cross-build. |
| **100** | CPUID stealth & leaf sanitization | CPUID Leaf 1 VMX masking, zeroing synthetic hypervisor leaves `0x40000000..0x400000FF`. |
| **101** | Hardware bisection & timing fix | `TSC_OFFSET` zero-base fix; hardware bisection isolates pre-kernel freeze on Dell G15. |
| **102** | UART & XSAVE bare-metal fixes | Removed blocking UART 0x3F8 polling (`18ae8b5`); initialized host `CR4.OSXSAVE` for `xrstor64` (`e76d0a5`). |
| **103** | 16-Core resident boot & desktop proof | Verified 16-core kernel execution on Dell bare metal (`2cd02fe`); complete 5-stage VMware test pass. |
| **HEAD** | Reorganization & stealth closure | illusion-rs structure, CR4.VMXE read-shadowing, dynamic RDTSC compensation, and CPUID pad restoration. |

---

## Companion Driver (HvDrv) & Userspace Integration

The repository integrates a complete ring-0/ring-3 verification and operation stack:
1. **`driver/HvDrv/`**: Dual-mode Windows kernel driver. Operates either as a standard WDM service (`\\.\HvDrv`) or in manual-mapped stealth mode (discovering hypervisor via PA `0x1000` beacon, servicing commands via background thread without driver objects).
2. **`client/lab_detect.exe`**: Diagnostic and benchmarking tool supporting direct Ring-3/Ring-0 VMCALL dispatch, ticket discovery, latency benchmarking (`--bench`), and driver-bridged memory inspection (`--driver`).
3. **`illusion-rs/`**: Rust-based EFI bootloader and companion crate reference for stealth Hyper-V abstraction.

---

## Research and Reference Architecture

HvEfi was engineered with reference to:
- **Intel SDM Volume 3C**: VMX Operation, VMCS Fields, EPT, and Interrupt Virtualization.
- **RedLotus-RS**: Three-stage UEFI bootkit hook chain and `LOADER_PARAMETER_BLOCK` parsing.
- **HyperDeceit**: Hyper-V hypercall emulation and `HvcallCodeVa` dispatch.
- **BlackLotus (CVE-2022-21894)**: ExitBootServices transitions and memory persistence.
- **KEVLAR**: User-mode kernel driver emulation and hook timing latency compensation.
- **Echo AC PoC (CVE-2023-38817)**: EPROCESS offsets and SipHash VMCALL threat modeling.

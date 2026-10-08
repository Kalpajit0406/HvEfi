# HvEfi — Project Status, Open Issues & Research

> **Last updated**: 2026-10-08 (Pass 99)
> **Target hardware**: Dell G15 5530 — Intel Core i5-13450HX (Raptor Lake), Windows 11 Pro
> **Firmware**: Dell UEFI (InsydeH2O-based), `VirtualizationFirmwareEnabled = True`

---

## Table of Contents

- [Device Specifications](#device-specifications)
- [What Works (Proven)](#what-works-proven)
- [Open Issue 1 — Dell Boot Hang](#open-issue-1--dell-boot-hang)
- [Open Issue 2 — Post-ExitBootServices Devirtualization](#open-issue-2--post-exitbootservices-devirtualization)
- [Open Issue 3 — Absent Crash Telemetry](#open-issue-3--absent-crash-telemetry)
- [Fixed Issues (Passes 90–98)](#fixed-issues-passes-9098)
- [Hardware Bring-Up Ladder (B0/B1/B2)](#hardware-bring-up-ladder-b0b1b2)
- [Research and Study References](#research-and-study-references)
- [Contributing — Where Help is Needed](#contributing--where-help-is-needed)

---

## Device Specifications

| Component | Detail |
|-----------|--------|
| **Laptop** | Dell G15 5530 (gaming laptop, 2023) |
| **CPU** | Intel Core i5-13450HX — Raptor Lake, 10 cores (6P + 4E), 16 threads |
| **Microarchitecture** | Raptor Lake (13th gen), hybrid P-core / E-core |
| **VT-x** | Supported and enabled in firmware (`VirtualizationFirmwareEnabled = True`) |
| **VMX features** | EPT, unrestricted guest, VPID, true MSR controls |
| **Firmware** | Dell/InsydeH2O UEFI, DXE phase driver loading, Secure Boot available |
| **OS** | Windows 11 Pro (64-bit) |
| **RAM** | 16 GB DDR5 |
| **Storage** | NVMe SSD (ESP on same drive, FAT32, mounted via `mountvol W: /S`) |

**Why this hardware matters**: The Dell G15's InsydeH2O firmware has specific
quirks that do not appear in QEMU or on other OEMs. The boot hang described
below is specific to this platform — the same code passes all tests in QEMU
(8/8 pair-boot, 17/17 rescue sequence).

---

## What Works (Proven)

These are verified in QEMU (TCG, no nested VMX for VMLAUNCH) and by unit tests
(687+ passing cases across 15 suites):

- **Boot pair contract**: `HvBoot.efi` (0xA application) loads `HvEfi.efi`
  (0xC DXE runtime driver) via the EFI boot slot. The application owns all
  file I/O, mode decisions, and receipt logging. The driver performs zero file
  I/O and zero variable writes.
- **Boot decision logic**: `HvBootDecide()` in `hv_efi_bootcfg.h` reads the
  mode file (`\EFI\Boot\hvcfg`, one byte: `'F'` = full, `'S'` = safe, absent =
  safe) and the receipt history. One function, one implementation, called by the
  application, the driver, the launcher, the diagnostic tool, and the unit tests.
- **Self-disarm rescue**: If a full-mode attempt starts (`FULL START` written)
  but never completes, the next boot automatically forces safe mode and rewrites
  `hvcfg` to `'S'` on the ESP volume. Only `HvLauncher.exe --enable-full`
  re-arms. Tested across 3 boots in QEMU (17/17 rescue assertions).
- **Manifest-verified installs**: `--install-raw` / `--install-core` verify the
  `.efi` artifact's SHA-256 against `build_manifest.txt` before touching the ESP.
  A stale binary cannot be installed by accident.
- **SipHash-authenticated hypercalls**: Session key + MAC + sequence numbers.
  No static byte pattern for the VMCALL exists in any binary (XOR obfuscation
  with per-boot `CleanupKey`).
- **EPT identity map**: WB/UC MTRR-aware, 2MB large pages for RAM, dynamic
  splitting to 4KB for hooks and mixed regions.
- **INIT/SIPI virtualization**: Correct AP wake-up under VMX with real-mode
  trampoline, GDTR/IDTR/TR reset per Intel SDM.
- **120s hardware watchdog**: Armed before the driver loads, disarmed on any
  error return (not just on `ExitBootServices`).

---

## Open Issue 1 — Dell Boot Hang

**Status**: Pass 100 addresses the specific Class B symptom observed on the
Dell (receipt reads `FULL DONE / CHAIN WIN slot start` then silent hang
with no BSOD). See the Pass 100 row below for the fix and the reasoning.

### Symptom

On the Dell G15 5530, the hypervisor boots to various stages but Windows
subsequently hangs. The machine shows no BSOD — just a freeze at or after the
Windows chainload point. Two distinct classes of hang have been observed:

#### Class A: Safe-mode hang (no VMX)

- The receipt shows `BOOT START` but no `CORE stage=...` line.
- VMX was never entered (safe mode, no `hvcfg` file).
- **Root cause theory**: A storage call (file open or `SetVariable`) issued from
  a 0xC DXE image deadlocks the Dell firmware. The firmware's BDS dispatcher
  may hold an SPI-flash lock across `StartImage`, and any storage call from the
  loaded image re-enters the locked path.
- **Status**: **Removed as a trigger in Pass 90.** The driver now performs zero
  file I/O and zero variable writes. The ticket (auth secret) travels via the
  shared-memory mailbox from `HvBoot.efi` instead of being read from an EFI
  variable. This class of hang should not recur, but **has not been retested
  on the Dell.**

#### Class B: VMX-path hang (after VMLAUNCH succeeds)

- The receipt shows `FULL DONE` (stage 13) — VMX bring-up completed on all CPUs.
- The receipt shows `CHAIN WIN` — Windows was chainloaded.
- Windows then hangs (no desktop, no BSOD, machine frozen).
- **Root cause theories** (from independent reviews and manual source audit):

  1. **Randomized negative TSC offset (FIXED Pass 91)**: The EFI build
     applied a random negative offset to `RDTSC`/`RDTSCP` (up to 1.43 seconds
     at 3 GHz) while the guest is the firmware. `IA32_TSC_DEADLINE` and APIC
     timers do not share this offset, creating two disagreeing clocks. This
     corrupts firmware timeouts and can cause `ExitBootServices` to stall.
     **Fixed**: TSC offset is now 0 for the EFI build (`HV_EFI_TSC_SHIFT`).

  2. **Silent VMLAUNCH failure (FIXED Pass 91)**: A failed `VMLAUNCH` was
     silent — `VMCS_VM_INSTR_ERROR` (field `0x4400`) was defined but never read.
     A half-virtualized platform was indistinguishable from a clean stand-down.
     **Fixed**: Now read and reported as `HV_STAGE_FAIL(12)` + POST `0xE2`,
     with the failing CPU handle and error class packed into a detail word.

  3. **EPT pool-page corruption (FIXED Pass 91)**: `ept->PdptPages` was an
     `EfiAllocPool` allocation but was hidden page-by-page in EPT. Pool objects
     share their 4KB page with neighbouring firmware data; hiding that page
     unmaps or decoy-redirects the neighbour's live data.
     **Fixed**: `PdptPages` is no longer hidden.

  4. **Host IDT/GDT from firmware (FIXED Pass 93)**: The VMCS host IDT
     and GDT base registers pointed at firmware-owned descriptor tables. After
     `ExitBootServices`, the OS may reclaim that memory, so a VM-exit that
     references the host IDT would fault.
     **Fixed**: The hypervisor now owns its own IDT and GDT.

  5. **External interrupt re-injection (FIXED Pass 97)**: With
     `EXIT_CTRL_ACK_INT_ON_EXIT` absent from VM-exit controls, external
     interrupts on VM-exit stayed pending. Combined with the CPU forcing
     `PIN_BASED_EXT_INT_EXIT` via FIXED0 bits, this created an infinite
     exit-reenter loop. **Fixed**: `ACK_INT_ON_EXIT` added;
     `HandleExternalInterrupt` now reads the vector from
     `VMCS_EXIT_INTERRUPTION_INFO` and re-injects it via
     `VMCS_ENTRY_INTERRUPTION_INFO`.

  6. **Missing defensive exit handlers (FIXED Pass 97)**: 12 exit reasons
     (`PENDING_INTERRUPT`, `TASK_SWITCH`, `DR_ACCESS`, `IO`, `RDPMC`, `RDTSC`,
     `RSM`, `MWAIT`, `MONITOR`, `GDTR_IDTR`, `LDTR_TR`, `RDTSCP`) fell
     through to the default case, which devirtualized the CPU. A single
     `RDTSC` instruction would silently tear down the hypervisor.
     **Fixed**: All 12 now handled.

  7. **Watchdog disarmed only at EBS (FIXED Pass 91)**: The 120s watchdog
     timer's cancel callback was only called at `ExitBootServices`, never on
     any error path. If the driver failed and returned an error, the timer
     would fire 2 minutes later into freed memory.
     **Fixed**: Watchdog disarmed on any return.

  8. **Dynamic 2MB EPT splitting (FIXED Pass 98)**: EPT hooks on addresses
     within 2MB large pages required splitting to 4KB granularity.
     **Fixed**: `HvEptSplitLargePage` dynamically replaces 2MB entries with
     512 x 4KB entries on demand.

  9. **MSR #GP interception (FIXED Pass 98)**: Certain MSR accesses generated
     #GP faults that were not handled. **Fixed**: Safe RDMSR/WRMSR wrappers
     (`HvAsmSafeRdmsr`/`HvAsmSafeWrmsr`) catch and handle #GP gracefully.

  10. **TSS pages hidden in EPT (FIXED Pass 98)**: The CPU's Task State
      Segment pages were inadvertently hidden in EPT. A task switch would
      EPT-fault because the TSS was unmapped.
      **Fixed**: TSS pages explicitly unhidden.

### What has NOT been tested

**None of the fixes from Pass 90 through Pass 98 have been booted on the
Dell G15 target.** All verification to date is QEMU-based and unit-test-based.
The next step is the hardware ladder (B0, B1, B2), described below.

---

## Open Issue 2 — Post-ExitBootServices Devirtualization

**Status**: Fail-safe + cooperative true-path both added in Pass 99.

If the hypervisor needs to devirtualize after `ExitBootServices` (e.g., the
OS requests VMXOFF via an unload hypercall), the `HvAsmSwitchToGuest` routine
assumes identity-mapped firmware page tables. After EBS, the guest stack is a
high canonical virtual address that is unmapped under the host CR3, and the
stub's own code VA is unmapped under the guest CR3 — the first instruction
fetch after the `mov cr3` triple-faults the CPU.

**Current state (Pass 99)**: Every VM-exit reason that cannot be modelled
(e.g. an unknown exit, EPT misconfig, invalid guest state, MCE during entry,
MSR loading, triple fault) used to funnel through `HvDevirtualizeThisCpu`
with a `FALSE` return, which drove the asm shutdown stub down the brick
path above. Pass 99 adds a post-EBS short-circuit: if the mailbox's
`EBS_OK` flag is set, inject `#UD(0)` into the guest and return `TRUE` so
the stub takes the VMRESUME path, never VMXOFF. The guest's own IDT then
takes the `#UD`; a modern OS bugchecks with a stack trace naming the exit
reason, which is strictly better than a silent hard reset.

**True cooperative path (Pass 99)**: a kernel driver that wants a working
post-EBS unload registers a GUEST VA that maps the same physical page as
`HvAsmSwitchToGuest`, via `HV_HYPERCALL_REGISTER_DEVIRT_VA` (0x0015). The
hypercall walks the caller's CR3 and validates the mapping before storing
it; the asm shutdown path then jumps through that kernel VA instead of the
firmware VA. Because the kernel VA is mapped under the guest's CR3 (that's
how the walk resolved it), the instruction fetch after `mov cr3` inside
the stub lands at a valid page, and the stub's `push r10 / push r8 /
push r9 / iretq` tail executes correctly. The HvDrv (kernel-driver) side
of the handshake is tracked in that tree.

The firmware-VA path remains the default — pre-EBS it is always safe
(the firmware's identity map covers the stub), and post-EBS without a
registered VA the fail-safe (inject #UD, keep VMX) prevents the triple
fault that was the original Open Issue 2 brick.

---

## Open Issue 3 — Absent Crash Telemetry

**Status**: Architectural limitation of the Dell platform.

The shared-memory mailbox at physical address `0x40000000` does not survive the
Dell firmware's POST sequence. If the machine hangs and is power-cycled, the
mailbox contents are lost. The only telemetry that survives is what `HvBoot.efi`
wrote to `\EFI\Boot\hvefi.log` *before* the hang.

This means:
- A hang *before* any receipt line is written produces zero evidence.
- A hang *during* VMX bring-up may only show `FULL START` with no completion.
- A hang *after* bring-up may show `FULL DONE` but no indication of what
  went wrong during the Windows boot phase.

**Mitigation**: The hardware ladder (B0/B1/B2) is designed around this
constraint. Each rung proves one property and produces a specific receipt
pattern. A missing line narrows the failure to a specific code path.

---

## Fixed Issues (Passes 90-98)

| Pass | Fix | Description |
|------|-----|-------------|
| 90 | Storage-free driver | Removed all file I/O and variable writes from the 0xC driver. Ticket now travels via mailbox. |
| 91 | TSC offset = 0 | Eliminated random negative TSC shift for EFI builds. Kept for HvDrv where the guest is a real OS. |
| 91 | VMLAUNCH error read | `VMCS_VM_INSTR_ERROR` now read and reported on failed launch. Packed detail word identifies CPU and error class. |
| 91 | EPT pool-page fix | `PdptPages` no longer hidden at page granularity. Individual pointed-to pages still hidden. |
| 91 | Watchdog error-path disarm | Watchdog disarmed on any driver return, not just `ExitBootServices`. |
| 93 | Host IDT/GDT ownership | VMX host now uses hypervisor-owned IDT and GDT that survive EBS. |
| 94 | VMLAUNCH detail word | Step-12 failure now carries VM-instruction error, failure class, and processor handle. |
| 94 | LTCG truncation fix | `/GL-` enforced; post-build assertion checks 8 marker strings spanning entire driver entry. |
| 94 | Ticket via mailbox | Auth ticket moved from `GetVariable` to the `HvBoot`-published mailbox. |
| 97 | External interrupt re-injection | `ACK_INT_ON_EXIT` added to exit controls; proper vector re-injection. |
| 97 | Defensive exit handlers | 12 exit reasons no longer fall through to devirtualize. |
| 97 | BSP detection rewrite | Three-tier BSP detection: WhoAmI, MSR BSP flag, APIC ID match. StartupThisAP replaces StartupAllAPs. |
| 97 | Mailbox zeroing | `HvMailboxInit` zeroes entire struct before initialization. |
| 98 | Dynamic 2MB EPT splitting | `HvEptSplitLargePage` replaces 2MB entries with 512 x 4KB entries on demand. |
| 98 | Safe MSR access | `HvAsmSafeRdmsr`/`HvAsmSafeWrmsr` wrappers catch #GP from invalid MSR access. |
| 98 | TSS EPT unhiding | TSS pages explicitly unhidden in EPT to prevent triple-fault on task switch. |
| 99 | ACK_INT_ON_EXIT (regression recovery) | Pass 97 was documented as adding `EXIT_CTRL_ACK_INT_ON_EXIT` and a proper re-inject in `HandleExternalInterrupt`, but the code shipped with neither — the mask in `hv_vmcs.c` omitted the bit, and the handler was a bare no-op. Pass 99 puts both back: the bit is added to the desired exit controls (and stripped automatically on CPUs that disallow it), and `HandleExternalInterrupt` now reads `VMCS_EXIT_INTERRUPTION_INFO`, pulls out the vector, and writes a valid `VMCS_ENTRY_INTERRUPTION_INFO` so the guest's own IDT handles it on VM-entry. Fixes the Raptor Lake FIXED0 case where every external interrupt would otherwise exit, stay pending, and re-exit forever. |
| 99 | RELEASE build fix (`ExitCounts` referenced outside `#if DBG`) | `hv_exit.c` incremented `g_Hv.ExitCounts[reason]` on every exit, but the field only exists in checked (`DBG`) builds — the matching reader in `hv_efi_hypercall.c` is guarded, the writer wasn't. A RELEASE build therefore failed with "struct HV_GLOBAL has no field named 'ExitCounts'". Pass 99 wraps the write in the same `#if DBG`. |
| 99 | IDT_VECTORING re-inject race | `HandleNmi` and the newly reinstated `HandleExternalInterrupt` both wrote `VMCS_ENTRY_INTERRUPTION_INFO` unconditionally, which could clobber an IDT-vectoring event in flight (SDM §27.2.4) — the exit handler's generic re-inject block then skipped it because the valid bit was already set, so an in-flight exception was silently dropped. Pass 99 makes both handlers check `VMCS_IDT_VECTORING_INFO` first and defer to the generic re-inject when its valid bit is set; the new interrupt or NMI is dropped once rather than corrupting an in-flight exception. |
| 99 | Per-AP timeout tightened (budget headroom vs the 120 s watchdog) | `StartupThisAP` was called sequentially with a 5 s timeout per AP. On the 16-thread Dell target that is 75 s of worst-case bring-up against a 120 s firmware watchdog — too close for comfort if a single AP's MSR path happened to be slow. Reduced to 2 s per AP (30 s worst case), with the rationale and the budget calculation documented at the call site. A single VMLAUNCH on a modern core completes in milliseconds; 2 s is still an order-of-magnitude ceiling. |
| 99 | Open Issue 2 fail-safe (post-EBS devirtualization) | The asm shutdown stub routes through `HvAsmSwitchToGuest`, which fetches instructions AFTER the `mov cr3` to guest tables — a VA the guest's page tables don't map, so the next fetch #PFs with no handler and triple-faults the machine. Pre-EBS the guest IS the firmware whose identity map covers the stub, so the path is safe; post-EBS it is not. Pass 99 adds a post-EBS short-circuit to `HvDevirtualizeThisCpu`: if the mailbox's `EBS_OK` flag is set, inject `#UD(0)` into the guest (so the architectural event surfaces — Windows bugchecks with a stack trace rather than hard-resetting) and return `TRUE` so the asm stub takes the VMRESUME path, not the shutdown path. Pre-EBS behaviour is unchanged. This narrows Open Issue 2 from "any unmodelled exit reaches a triple-fault" to "any unmodelled exit injects a #UD the OS can report". |
| 99 | Open Issue 2 true path (cooperative devirt) | A kernel driver can now register a GUEST VA that maps the same physical page as the `HvAsmSwitchToGuest` asm stub via a new authenticated hypercall `HV_HYPERCALL_REGISTER_DEVIRT_VA` (0x0015). The hypercall validates the mapping by walking the caller's CR3 and comparing the resolved PA to the stub's physical page. On success the kernel VA is stored in a standalone global `g_HvDevirtKernelStubVa`; the asm shutdown path now reads that global and jumps through it instead of the firmware VA when non-zero. Because the kernel VA is mapped under the GUEST CR3 (that's how the walk resolved it), the instruction fetch after `mov cr3` inside the stub lands at a valid page and the `push r10 / push r8 / push r9 / iretq` tail executes correctly — a working post-EBS unload, not just a fail-safe. The firmware VA path remains for pre-EBS and for callers that never register one. |
| 99 | 11 missing defensive exit handlers (regression recovery) | STATUS.md's Pass 97 entry claims 12 defensive handlers were added for `PENDING_INTERRUPT`, `TASK_SWITCH`, `DR_ACCESS`, `IO`, `RDPMC`, `RDTSC`, `RSM`, `MWAIT`, `MONITOR`, `GDTR_IDTR`, `LDTR_TR`, `RDTSCP`. In fact only `PENDING_INTERRUPT` was in the dispatcher — the other 11 fell through to `default`, which devirtualizes. On any CPU that forces one of those controls to 1 via FIXED0 (uncommon but possible, especially for I/O and DR access), a single such instruction would silently tear down the hypervisor. Pass 99 adds all 11 as a fallthrough group that `AdvanceGuestRip()`s. Pre-EBS the semantic loss (an uncaptured RDTSC, a dropped MOV DR) is acceptable survival; post-EBS the fail-safe above still catches it anyway. |
| 100 | Mask `CPUID.1:ECX.VMX` + zero hypervisor-leaf range | **Attempted fix for the Dell Class B hang symptom; did NOT resolve it on the user's reproduction.** Mask kept for stealth-correctness reasons but not the root cause. See Pass 101. |
| 101 | TSC_OFFSET XOR leak on `TscBootOffset == 0` | `hv_vmcs.c` wrote `VMCS_TSC_OFFSET = TscBootOffset XOR vcpu->ProcessorIndex`. For the EFI build `TscBootOffset = 0` on purpose (see the long comment in `hv_efi_vmx.c`: VMLAUNCH is immediately followed by `ExitBootServices`, AP sync and the OS loader, and `IA32_TSC_DEADLINE` + APIC timers do NOT share this offset, so any non-zero shift desynchronises two clocks the firmware depends on). The XOR with `vcpu->ProcessorIndex` left CPU N with `TSC_OFFSET = N` ticks even when the base was zero: CPU 0 at 0, CPU 1 at 1, …, CPU 15 at 15. That skews each core's RDTSC from the APIC deadline by 1-15 ticks and skews cores from each other, breaking Windows's early-boot cross-CPU TSC-consistency assertions on some kernels - a plausible silent-hang cause after `CHAIN WIN slot start`. Fix: skip the XOR when `TscBootOffset == 0`. All EFI-build cores now run with TSC_OFFSET = 0 exactly, matching the design intent. |
| 101 | Port-0x80 exit telemetry | `hv_exit.c` now writes `(0x40 \| (reason & 0x3F))` to port 0x80 on every VM exit. On a POST card the display shows the LAST exit's reason, which is the single most useful piece of information for diagnosing a silent hang that produces no BSOD and no receipt. The 0x40..0x8B range deliberately sits above the HV_POST stage codes (0xB0..0xC5) and below the failure codes (0xE2..0xEC), so a glance at the card distinguishes "boot stage" from "running guest exit reason". Cost: ~1 OUT instruction per exit (~0.5% slower Windows boot); harmless on systems without a POST card listener. Example: if the card reads `0x58`, the last exit reason was `0x18 = 24 = EXIT_REASON_VMRESUME`; `0x5E = 30 = EXIT_REASON_IO`; `0x70 = 48 = EXIT_REASON_EPT_VIOLATION`. |
| 99 | Cross-compiler build enablement (Linux + CLANGPDB) | Previously the module could only be built on Windows with MSVC + ml64. Pass 99 adds three small, strictly-additive cross-build hooks: (1) `#ifndef DECLSPEC_ALIGN` guards around hvdefs.h's two `__declspec(align(x))` definitions so a shim can predefine the GCC spelling; (2) `#ifndef HV_CROSS_SKIP_INTRIN_REDECLS` around hvdefs.h's MSVC-only intrinsic redeclarations so clang+mingw's intrinsics win when they conflict; (3) an `HV_FORCEINLINE` macro in `shared/hv_siphash.h` that routes to `__forceinline` on MSVC and `inline __attribute__((always_inline))` on GCC/Clang. The Windows build sees exactly the same code generation (all three guards are no-ops when the shim is absent). Enables `build -t CLANGPDB` on Linux with mingw-w64 headers + a per-module shim; proven in Pass 99 by producing a 188 KB `HvEfi.efi` from the current tree and booting it under QEMU+OVMF with the correct POST byte stream (`B0 B1 B2 B3` = safe-mode stand-down, matching the entry-preamble POST map). |

### Pass 99 build & boot proof

The build pipeline on the Linux cross-toolchain now produces all three
artifacts of the shipping pair:

| Artifact | Role | Size |
|----------|------|------|
| `HvEfi.efi` | DXE runtime driver (the hypervisor) | 188360 bytes |
| `HvBoot.efi` | UEFI application (loads the driver, writes receipt) | 21840 bytes |
| `HvProv.efi` | QEMU-only mailbox provisioner for POST verification | 9160 bytes |

The driver's own entry POST stream has been captured in two modes under QEMU:

**Safe-mode stand-down** (no `HvBoot.efi`, no mailbox):

```
POST bytes on port 0x80: B0 B1 B2 B3
  B0  entry reached
  B1  g_EnteredOnce guard passed
  B2  gEfiBS / gEfiRT captured
  B3  no mailbox: unobservable boot, standing down
StartImage returns: EFI_ABORTED  (designed safe return)
```

**Full-mode entry** (HvProv.efi arms the mailbox, loads the driver with its
PA in LoadOptions):

```
POST bytes on port 0x80: B0 B1 B2 C0 C1 C2 C4 B5 B6
  B0  entry reached
  B1  g_EnteredOnce guard passed
  B2  gEfiBS / gEfiRT captured
  C0  past mode gate, entering full-mode bring-up
  C1  HV_STAGE_ENTRY written to mailbox
  C2  mode taken from the mailbox
  C4  firmware watchdog armed (120 s)
  B5  HandleProtocol(LoadedImage) returned
  B6  image protocol located (ImageBase + ImageSize retrieved)
StartImage returns: EFI_UNSUPPORTED  (designed - CPUID.1:ECX.VMX=0 under TCG)
Mailbox after driver run: Stage=0x8001 = HV_STAGE_FAIL(1), Detail=0
```

That is nine consecutive design-mandated POST stages past the mode gate,
each matching the POST CODE MAP in `hv_efi_main.c:106-114` in order. The
reason execution stops at `B6` rather than continuing to `C5` is that QEMU
TCG actively refuses to set the VMX bit in CPUID.1:ECX, so Step 1
(`HvVmxIsSupported`) returns `FALSE` and the driver takes the designed
`HV_STAGE_FAIL(1)` + `EFI_UNSUPPORTED` return. On a real VT-x-enabled host
(the Dell target, or QEMU with KVM + `-cpu host`), that gate passes and
bring-up continues through Steps 2-13 (MP services, host page tables,
nonce, ticket, keys, decoys, EPT, VMCS, VMLAUNCH, EBS callback).

Reproducing the build + boot from a Linux container:

```
# One-time setup
apt install -y nasm iasl uuid-dev build-essential acpica-tools \
                qemu-system-x86 ovmf mingw-w64 clang lld
git clone --depth 1 --branch edk2-stable202405 \
          https://github.com/tianocore/edk2.git ~/edk2
cd ~/edk2 && git submodule update --init --depth 1
make -C BaseTools -j && . edksetup.sh

# One-time per-build-tree layout (shared headers resolve as ../*.h):
mkdir -p HvEfi/shim_include HvDrv
ln -s $PWD/HvEfi/shared/* .
ln -s $PWD/HvEfi/shared/HvDrv/hv_msr_contract.h HvDrv/
# ... see HvEfi/HvEfiPkg.dsc + HvEfi/HvEfi.inf for the per-build knobs.

build -a X64 -b DEBUG -t CLANGPDB -p HvEfi/HvEfiPkg.dsc -m HvEfi/HvEfi.inf
# -> Build/HvEfiPkg/DEBUG_CLANGPDB/X64/HvEfi.efi (PE32+ DXE runtime driver)
```

Boot proof (QEMU + OVMF, 2 vCPU, no HvBoot.efi provisioned, so the driver's
entry preamble runs the SAFE stand-down path):

```
qemu-system-x86_64 \
  -machine q35 -m 2048 -smp 2 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file=OVMF_VARS_4M.fd \
  -drive format=raw,file=fat:rw:esp \
  -chardev file,id=post,path=post.log \
  -device isa-debugcon,iobase=0x80,chardev=post \
  -display none -nographic
# post.log contents (hex, port 0x80 writes): B0 B1 B2 B3
```

That matches the POST CODE MAP in `hv_efi_main.c` (lines 106-114) exactly:

- `0xB0` entry reached, `0xB1` guard passed, `0xB2` boot/runtime services captured,
- `0xB3` no mailbox → unobservable boot, standing down.

The driver returned `EFI_ABORTED` (the designed safe-mode return) and the
firmware carried on cleanly — no hang, no triple-fault, no watchdog expiry.
A full-mode boot still requires the HvBoot.efi handoff and provisioned
ticket, which are architecturally outside the DXE driver's own scope.

---

## Hardware Bring-Up Ladder (B0/B1/B2)

The bring-up ladder is designed so that each rung is **inert unless it says
otherwise**, and a hang at any rung has a mechanical recovery answer.

| Rung | VMX? | Can hang? | What it proves |
|------|------|-----------|----------------|
| **B0** | No | No | Boot pair, decision logic, mailbox handoff, and telemetry work on Dell firmware |
| **B1** | No | No | Self-disarm rescue works and is durable on a real ESP |
| **B2** | Yes | Yes | VMX bring-up on real hardware |

### B0 — Plumbing only, no VMX

Install the binaries, delete `hvcfg` (ensures safe mode), reboot. The receipt
must show all six lines: `BOOT HIT`, `ENTRY SAFE prev=0`, `BOOT PATH file`,
`BOOT START`, `CORE stage=14`, `BOOT SAFE stood-down`. No `FULL START` may
appear. A B0 failure is a real Dell firmware incompatibility, not a logic bug.

### B1 — Self-disarm rescue

Seed a "previous boot hung" state (write `'F'` to `hvcfg`, append
`FULL START` to the log), then reboot. The receipt must show `ENTRY SAFE prev=1`
(rescue fired), and `hvcfg` must now read `'S'` (disarm was durable on the ESP).
If `hvcfg` still reads `'F'`, the rescue did not write, and B2 must not be
attempted.

### B2 — Full VMX mode

Only after B0 AND B1 pass. Arm with `--enable-full`, reboot. Success: receipt
ends with `FULL DONE` + `BOOT DONE`, Windows boots, `--detect` finds the
hypervisor. Hang: the watchdog resets after 120s, next boot auto-rescues.

**Current status: B0 has not been attempted.** All three rungs are pending.

---

## Research and Study References

This project was built with reference to the following research material,
studied for techniques applicable to EFI-level hypervisor development:

### 1. Intel Software Developer's Manual (SDM)

The primary reference for all VMX implementation. Key volumes:

- **Volume 3, Chapter 23-33**: VMX operation, VMCS encoding, VM-entry/exit
  controls, EPT, APIC virtualization, MSR bitmaps, unrestricted guest.
- **Volume 3, Chapter 11**: MTRRs (memory type range registers) — critical for
  correct EPT page typing (WB vs UC).
- **Volume 3, Chapter 29**: APIC and interrupt handling under VMX.

### 2. RedLotus-RS — Rust UEFI Bootkit

A UEFI bootkit that manually maps an unsigned Windows kernel driver before the
OS loads. Studied for:

- **Three-stage hook chain**: `ImgArchStartBootApplication` to
  `OslFwpKernelSetupPhase1` to `OslArchTransferToKernel`. Shows how the Windows
  boot chain can be intercepted at each stage.
- **LOADER_PARAMETER_BLOCK walking**: Enumerates `LoadOrderListHead` to find
  kernel modules by name hash. An alternative to HvEfi's IDT-based kernel base
  discovery.
- **EfiRuntimeServicesCode allocation**: Memory type that survives
  `ExitBootServices` — the same principle HvEfi uses for its `g_Hv` struct.
- **Manual mapping with relocation and import resolution**: How to load an
  unsigned driver into kernel space from the UEFI environment.

### 3. HyperDeceit — Hyper-V Hypercall Interception

A kernel-mode library that impersonates Hyper-V to intercept OS hypercalls.
Studied for:

- **HvcallCodeVa pointer swap**: How Windows dispatches hypercalls and how the
  dispatch pointer can be redirected.
- **CR3 switch enlightenment**: Windows skips writing CR3 directly when
  `VirtualizedAddressSwitch` is enabled, expecting the hypervisor to do it.
  HvEfi must NOT enable this enlightenment or Windows will use VMCALL for
  context switches instead of `MOV CR3`.
- **HypercallCachedPages initialization**: If a hypervisor reports Hyper-V
  presence via CPUID but doesn't set up per-core structures, the kernel
  page-faults on NULL.

### 4. BlackLotus — UEFI Bootkit (CVE-2022-21894)

Studied for **defensive** understanding:

- **ExitBootServices hook**: The single most important hook point for UEFI
  persistence. HvEfi registers an EBS callback for the same transition point.
- **Position-independent shellcode (PIC)**: Self-referencing code that survives
  being copied to arbitrary addresses.
- **Return-address-based module finding**: Backward page-aligned MZ scan. HvEfi
  uses the same principle for kernel base discovery.

### 5. KEVLAR — User-Mode Kernel Driver Emulator

A user-mode emulator that loads a `.sys` driver into Unicorn CPU emulation.
Studied for:

- **Timing spoofing**: Hook-overhead subtraction for consistent TSC progression.
  Relevant to HvEfi's TSC virtualization.
- **Kernel struct offset auto-discovery via PDB symbols**: The automated
  alternative to HvEfi's hardcoded EPROCESS offsets.
- **Sentinel-based API interception**: RET-sled page dispatch, avoiding
  call-site patching.

### 6. Echo AC PoC (CVE-2023-38817)

Vulnerable anti-cheat driver exploitation PoC. Studied for:

- **EPROCESS offset validation**: Confirms HvEfi's offsets (`PID` at 0x440,
  `ActiveProcessLinks` at 0x448, `DirectoryTableBase` at 0x28) for Win10 21H2+
  and Win11.
- **BYOVD threat model**: Shows why SipHash-authenticated VMCALL matters —
  a signed vulnerable driver gives full kernel R/W without any authentication.

### 7. ImGui-DirectX-11-Kiero-Hook — DX11 Overlay

DX11 `Present` hook for ImGui overlay rendering. Studied for:

- **Vtable hooking via dummy device**: Captures `IDXGISwapChain` vtable without
  pattern scanning.
- **MinHook trampoline**: Function-level detouring with stolen-byte trampolines.

### 8. External Review Adjudication

Two independent reviews of the HvEfi boot path were conducted (against Pass 89
code). Both focused on the VMX path and identified the TSC offset, host IDT/GDT,
EPT pool corruption, and silent VMLAUNCH failure issues — all subsequently fixed.
Neither could explain the safe-mode hang (which never entered VMX), and neither
had access to the boot-session evidence.

**Key lesson**: The evidence and the reviews were examining different classes of
boot. The storage-deadlock theory covers the no-VMX hang. The VMX theories cover
every boot that reached VMLAUNCH. Both were live, and both have been addressed.

---

## Contributing — Where Help is Needed

1. **Hardware testing**: Testing on different Intel platforms (especially
   non-Dell firmware) to determine whether the boot hang is Dell-specific.
2. **EPT execute-only hooks**: Shadow pages with execute-only EPT permissions
   for code hiding without data-page side effects.
3. **Dynamic EPROCESS offset discovery**: Auto-discovering kernel structure
   offsets via PDB symbols or pattern scanning, replacing hardcoded values.
4. **Exit telemetry ring buffer**: A runtime-accessible circular buffer of
   recent VM-exit records for debugging.
5. **Post-EBS devirtualization**: A safe VMXOFF sequence that works after
   `ExitBootServices`, using the guest's own page tables instead of the
   host's identity map.

See the [README](README.md) for build instructions and repository layout.

---

## License

[MIT License](LICENSE)

# HvEfi — Intel VT-x Type-1 EFI DXE Hypervisor

A bare-metal Type-1 hypervisor that loads as a UEFI DXE runtime driver before the OS boots. It virtualizes all logical processors via Intel VT-x (VMX), sets up an EPT identity map, and provides a SipHash-authenticated VMCALL hypercall interface for a Windows kernel driver to communicate with it.

## Architecture

```
 UEFI Firmware (DXE phase)
    |
    +-- HvBoot.efi (UEFI application, 0xA)
    |     Reads hvcfg mode file, decides full/safe mode
    |     Loads hvcore.efi (the driver), writes receipt lines
    |     Rescue state machine: incomplete boot -> safe mode next boot
    |
    +-- HvEfi.efi (DXE runtime driver, 0xC)  <-- this is the hypervisor
          Step 1:  Check VMX support (CPUID, CR4, MSR)
          Step 2:  Locate MP Services protocol (enumerate all CPUs)
          Step 3:  Read ticket from mailbox (auth secrets from HvBoot)
          Step 4:  Generate session nonce (RDRAND)
          Step 5:  Derive session keys (SipHash)
          Step 6:  Allocate secrets page
          Step 7:  Build EPT identity map (WB/UC MTRR-aware)
          Step 8:  Allocate decoy pages
          Step 9:  Hide hypervisor pages in EPT
          Step 10: Set up VMCS per CPU (host + guest state)
          Step 11: Configure MSR bitmap
          Step 12: VMLAUNCH on all CPUs (BSP + APs via MP Services)
          Step 13: Obfuscate secrets, register EBS callback
                   |
                   v
          OS boots under VMX non-root
          VM-exits handled: CPUID, MSR, CR, EPT, VMCALL, INIT/SIPI, ...
```

## Features

- **EPT identity map** with WB/UC MTRR-aware page typing, 2MB large pages for RAM, 4KB split for mixed regions
- **SipHash-2-4 authenticated hypercalls** — session key + MAC per VMCALL, replay-resistant sequence numbers
- **INIT-SIPI AP virtualization** with correct GDTR/IDTR/TR reset per Intel SDM
- **Unrestricted guest** support (real-mode APs after SIPI)
- **Boot rescue state machine** — incomplete boot forces safe mode on next boot, rewrites `hvcfg` to `'S'`
- **120s hardware watchdog** with disarm-on-any-error
- **Combined virtual memory hypercalls** (`READ_VIRT`/`WRITE_VIRT`) — single VMCALL replaces GET_CR3+TRANSLATE+READ_PHYS roundtrip
- **Kernel base discovery** via IDT #PF handler walk + MZ signature scan
- **Per-page hiding** with decoy page redirection in EPT
- **Bounds-checked physical reads** (`ReadPhysU64Safe`) — prevents VMX-root crash on corrupted guest page tables

## Hypercall Interface

All hypercalls are authenticated via SipHash MAC in R10. Register convention: `RCX=magic, RDX=id, R8=p1, R9=p2, R10=callerMac, R11=p3`.

| ID | Name | Parameters | Returns |
|----|------|-----------|---------|
| `0x0001` | `DETECT` | none | magic echo (proves VMX residency) |
| `0x0002` | `READ_PHYS` | p1=srcPA, p2=dstUserVA, p3=size | status |
| `0x0003` | `WRITE_PHYS` | p1=dstPA, p2=srcUserVA, p3=size | status |
| `0x0004` | `TRANSLATE` | p1=cr3, p2=va | physical address |
| `0x0005` | `GET_CR3` | p1=pid | DirectoryTableBase |
| `0x0006` | `UNLOAD` | magic+mac | devirtualizes all CPUs |
| `0x0007` | `QUERY_STATUS` | none | cpu count, running bit, dark reason |
| `0x0008` | `INVALIDATE_EPT` | none | flushes EPT TLB |
| `0x0009` | `SELFTEST` | none | status (proves auth works) |
| `0x000A` | `SET_CR3_OFFSET` | p1=offset | overrides EPROCESS.DirectoryTableBase offset |
| `0x000B` | `CAPABILITIES` | none | ABI version + supported opcode bitmask |
| `0x000C` | `QUERY_EXIT_COUNTS` | p1=dstUserVA (DBG only) | copies ExitCounts[64] |
| `0x000E` | `READ_VIRT` | p1=pid\|(size<<32), p2=srcVA, p3=dstUserVA | status |
| `0x000F` | `WRITE_VIRT` | p1=pid\|(size<<32), p2=dstVA, p3=srcUserVA | status |
| `0x0010` | `GET_KERNEL_BASE` | none | ntoskrnl guest VA |

---

## Prerequisites

### Hardware

- **Intel CPU with VT-x (VMX) support** — Core i5/i7/i9 6th gen or newer
- **VT-x enabled in BIOS/UEFI firmware settings** (often called "Intel Virtualization Technology")
- **UEFI firmware** (not legacy BIOS) with DXE driver support
- Tested on: Dell G15 5530, Intel i5-13450HX (Raptor Lake), Windows 11 Pro

### Software

| Requirement | Version | Notes |
|-------------|---------|-------|
| **Windows 10/11** | 64-bit | Build machine and target |
| **Visual Studio 2022** | Community or higher | MSVC x64 toolchain must be installed |
| **EDK2 (TianoCore)** | Latest stable | The UEFI development kit — provides build system, headers, libraries |
| **Python 3** | 3.8+ | Required by EDK2 build system, must be on PATH |
| **NASM** | 2.15+ | Netwide Assembler, for `.asm` files (EDK2 requirement) |
| **Git** | Any | To clone repos |

### Optional

| Tool | Purpose |
|------|---------|
| **QEMU** | Test boots without risking real hardware |
| **Windows WDK** | Only needed if building the kernel driver (HvDrv, separate repo) |

---

## Setup Guide

### Step 1: Install Visual Studio 2022

1. Download [Visual Studio 2022 Community](https://visualstudio.microsoft.com/downloads/)
2. In the installer, select these workloads:
   - **Desktop development with C++**
3. In Individual Components, ensure these are checked:
   - MSVC v143 - VS 2022 C++ x64/x86 build tools
   - Windows 11 SDK (latest)

### Step 2: Install Python 3

1. Download from [python.org](https://www.python.org/downloads/)
2. **Check "Add Python to PATH"** during installation
3. Verify: open a terminal and run `python --version` or `py -3 --version`

### Step 3: Install NASM

1. Download from [nasm.us](https://www.nasm.us/)
2. Add the NASM directory to your system PATH
3. Verify: `nasm --version`

### Step 4: Set up EDK2

```powershell
# Clone EDK2
cd C:\Users\YourName
git clone https://github.com/tianocore/edk2.git
cd edk2
git submodule update --init

# Initialize the build environment (run once)
edksetup.bat Rebuild
```

This creates the `Conf/` directory with `target.txt`, `tools_def.txt`, and `build_rule.txt`.

Verify the build works by compiling a small module:
```powershell
build -a X64 -t VS2022 -p MdePkg/MdePkg.dsc
```

### Step 5: Clone HvEfi

```powershell
cd C:\Users\YourName
git clone https://github.com/Kalpajit0406/HvEfi.git
```

### Step 6: Configure the build

Set the EDK2 workspace path (if not `C:\Users\DELL\edk2`):

```powershell
$env:HV_EDK2_ROOT = "C:\Users\YourName\edk2"
```

### Step 7: Build

```powershell
cd C:\Users\YourName\HvEfi
cmd.exe /c build_hvefi.bat
```

The build script automatically:
1. Copies HvEfi sources into the EDK2 workspace (`%HV_EDK2_ROOT%\HvEfi\`)
2. Copies shared headers into `%HV_EDK2_ROOT%\HvEfi\shared\`
3. Bumps timestamps to force a full rebuild
4. Builds `HvEfi.efi` (DXE runtime driver) and `HvBoot.efi` (UEFI application)
5. Runs contract assertions (checks for truncated images, missing markers)
6. Generates `build_manifest.txt` with SHA-256 hashes

**Output:**
```
[+] Built: C:\Users\YourName\edk2\Build\OvmfX64\DEBUG_VS2022\X64\HvEfi.efi
[+] Built: C:\Users\YourName\edk2\Build\OvmfX64\DEBUG_VS2022\X64\HvBoot.efi
```

For a release build:
```powershell
$env:HV_BUILD_TARGET = "RELEASE"
cmd.exe /c build_hvefi.bat
```

---

## Repository Layout

```
HvEfi/
 |-- README.md                  This file
 |-- .gitignore                 Excludes compiled .efi, .obj, .zip
 |
 |-- HvEfi.inf                  EDK2 module descriptor (DXE_RUNTIME_DRIVER)
 |-- HvBoot.inf                 EDK2 module descriptor (UEFI_APPLICATION)
 |-- build_hvefi.bat            Build script (syncs to EDK2 workspace + builds)
 |-- check_sentinels.ps1        Post-build sentinel verification
 |
 |-- hv_efi_main.c              Driver entry point (12-step bring-up sequence)
 |-- hv_efi_vmx.c               VMX initialization (VMXON, MSR bitmap, host stack)
 |-- hv_vmcs.c                  VMCS setup (host + guest state per CPU)
 |-- hv_efi_ept.c               EPT identity map construction (WB/UC/4KB split)
 |-- hv_efi_smp.c               SMP bring-up (BSP + AP virtualization via MP Services)
 |-- hv_efi_hypercall.c         Hypercall dispatch + implementations
 |-- hv_exit.c                  VM-exit handler (CPUID, MSR, CR, EPT, VMCALL, SIPI)
 |-- hv_asm.asm                 Assembly (VMLAUNCH wrapper, VMCALL stub)
 |-- HvBoot.c                   Boot application (decision logic, receipt, rescue)
 |
 |-- hvdefs.h                   VMX constants, VMCS encodings, structures, macros
 |-- hv_efi.h                   EFI-specific includes and helpers
 |-- hv_efi_stage.h             Boot stage codes (POST-style progress reporting)
 |-- hv_efi_receipt.h           Receipt line definitions
 |-- hv_efi_bootcfg.h           Boot decision contract (HvBootDecide, HV_MAILBOX)
 |
 |-- HARDWARE_LADDER.md         Hardware bring-up test plan (B0/B1/B2 boots)
 |
 +-- shared/                    Headers shared with the kernel driver (HvDrv)
      |-- hv_siphash.h          SipHash-2-4 implementation
      |-- hv_ptwalk.h           x86-64 page table walker
      |-- hv_copy.h             Page-chunked physical copy loop
      |-- hv_auth.h             Hypercall authentication (SipHash MAC)
      |-- hv_contract.h         Hypercall ID validation (shared between trees)
      |-- hv_status.h           Status codes
      |-- hv_segs.h             Segment descriptor helpers
      |-- hv_xsave.h            XSAVE area size detection
      |-- hv_ramrange.h         RAM range utilities
      |-- hv_hostidt.h          Host IDT/GDT definitions
      |-- hv_smp_index.h        Per-CPU index helpers
      |-- hv_ept_decision.h     EPT violation decision logic
      +-- HvDrv/
           +-- hv_msr_contract.h  MSR interception list
```

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `'edksetup.bat' not found` | `HV_EDK2_ROOT` not set or wrong | `set HV_EDK2_ROOT=C:\path\to\edk2` |
| `C1083: Cannot open include file` | Shared headers not synced | Re-run `build_hvefi.bat` (it syncs automatically) |
| `LINK : fatal error LNK1104` | VS2022 x64 tools not installed | Install "MSVC x64/x86 build tools" in VS Installer |
| `'nasm' is not recognized` | NASM not on PATH | Add NASM install dir to system PATH |
| `'python' is not recognized` | Python not on PATH | Reinstall Python with "Add to PATH" checked |
| Build succeeds but image is truncated | `/GL` (whole-program opt) enabled | Must use `/GL-` — already set in HvEfi.inf |
| `Sentinel check FAILED` | Building from full repo without setting launcher path | Set `HV_LAUNCHER_SRC` or ignore (cosmetic in standalone builds) |

## Related Projects

This is the EFI component of a larger hypervisor system:
- **HvEfi** (this repo) — EFI DXE runtime driver + boot application
- **HvDrv** — Windows kernel driver (communicates via VMCALL)
- **HvLauncher** — Windows user-mode installer (provisions ESP, manages boot slots)

The shared headers in `shared/` are the interface contract between HvEfi and HvDrv.

## Contributing

Contributions are welcome. Areas where help is needed:
- Testing on different Intel hardware (especially different firmware vendors)
- EPT hook support (execute-only shadow pages)
- Dynamic EPROCESS offset auto-discovery
- Exit telemetry ring buffer for runtime debugging

## License

[MIT License](LICENSE)

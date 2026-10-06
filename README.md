# HvEfi — Intel VT-x Type-1 EFI DXE Hypervisor

A bare-metal Type-1 hypervisor that loads as a UEFI DXE runtime driver, virtualizes all logical processors via Intel VT-x (VMX), and communicates with a Windows kernel driver through authenticated VMCALL hypercalls.

## Architecture

- **HvEfi.efi** (DXE runtime driver): sets up VMX, EPT identity map, VMCS per-CPU, intercepts VM-exits
- **HvBoot.efi** (UEFI application): boot decision logic, rescue state machine, shared-memory mailbox
- **Hypercall interface**: authenticated via SipHash MAC — `READ_PHYS`, `WRITE_PHYS`, `READ_VIRT`, `WRITE_VIRT`, `GET_KERNEL_BASE`, `TRANSLATE`, `GET_CR3`, etc.

## Key Features

- Full EPT identity map with WB/UC MTRR-aware typing and per-page hiding
- SipHash-2-4 authenticated hypercall interface (session key + MAC)
- INIT-SIPI AP virtualization with correct GDTR/IDTR/TR reset
- Unrestricted guest support (real-mode APs)
- Boot rescue state machine — incomplete boot forces safe mode on next boot
- 120s hardware watchdog with disarm-on-error
- Combined virtual memory hypercalls (READ_VIRT/WRITE_VIRT) with page-chunked copy
- Kernel base discovery via IDT #PF handler walk

## Building

Requires:
- EDK2 workspace (OVMF package)
- Visual Studio 2022 (MSVC toolchain)

```
build_hvefi.bat
```

Builds both `HvEfi.efi` (driver) and `HvBoot.efi` (application) and runs contract assertions.

## Repository Layout

```
*.c, *.h, *.asm    HvEfi source files
*.inf              EDK2 build descriptors
shared/            Headers shared with the parent hypervisor project
                   (hv_ptwalk.h, hv_siphash.h, hv_contract.h, etc.)
```

## Related

This is the EFI component of a larger hypervisor project. The shared headers in `shared/` are the interface contract between the EFI driver and the Windows kernel driver (HvDrv).

## License

All rights reserved. This code is provided for educational and research purposes.

// hv_smp_index.h - pure VCPU-index resolution for multi-processor bring-up.
//
// WHY THIS FILE EXISTS (Pass 94, PI Spec audit of EFI_MP_SERVICES_PROTOCOL)
//
// HvEfi/hv_efi_smp.c resolves "which VCPU struct belongs to the CPU I am running
// on" through CurrentCpuIndex(), which has two branches using two DIFFERENT index
// spaces:
//
//   1. gEfiMp->WhoAmI() -> the EFI_MP_SERVICES_PROTOCOL processor handle, which
//      the PI spec defines as a dense 0..(EnabledProcessorCount-1) enumeration.
//
//   2. On failure, a fallback to HvReadApicIdLocal(), which returns the x2APIC
//      ID (CPUID.0Bh.0:EDX, else CPUID.1:EBX[31:24]).
//
// Those are unrelated numberings, and the fallback's result was fed straight into
// g_Hv.Vcpus[idx], which is indexed BY HANDLE. On any topology whose x2APIC IDs
// are not 0..N-1 in order - the common case on Intel client parts, where a
// 12-thread CPU reports 0,2,4,...,22 - the fallback either:
//
//   (a) yields an index >= VcpuCount, so VirtualizeCpuBody returns early and the
//       AP is silently never virtualized (boot with 1 of 12 CPUs covered), or
//   (b) yields an in-range index belonging to a DIFFERENT CPU, so this AP writes
//       its ApicId / VmxonPhysical / Launched into another CPU's VCPU struct and
//       two processors share one VMXON region and one VMCS.
//
// Neither is a crash by itself, so nothing reported them. The count check in
// HvSmpVirtualizeAllProcessors catches (a) as "only N/M CPUs launched" and
// completely misses (b).
//
// The fix is to fail CLOSED: if the handle cannot be resolved, do not virtualize
// that CPU. A CPU left un-virtualized is a count mismatch the existing rollback
// already handles correctly; a CPU virtualized into the wrong slot is silent
// corruption. The old fallback had precisely the inverse risk profile.
//
// The runtime lookup (after ExitBootServices, when gEfiMp no longer exists) is a
// different and correct operation, and is NOT here: it MATCHES the live x2APIC ID
// against the ApicId recorded per VCPU at bring-up and returns NULL on no match.
// That is a lookup by value, never an index. It stays inline in
// HvGetCurrentVcpu() because the table is an array of VCPU structs, not of APIC
// IDs; pulling it in here would mean either a parallel array nobody maintains or
// a stride-parameterised signature, and neither is worth it for a loop that is
// already correct.
//
// Keep this file free of Uefi.h, EDK2 types and firmware calls: the EDK2 build,
// the WDK build and a plain host unit test all include it. Keep it ASCII-only.

#ifndef HV_SMP_INDEX_H
#define HV_SMP_INDEX_H

// Resolve which VCPU a bring-up callback should use.
//
//   whoAmI       the handle WhoAmI returned for THIS CPU
//   vcpuCount    g_Hv.VcpuCount, i.e. the number of VCPU structs allocated
//   outIndex     receives the handle to use; written only on a 1 return
//
// Returns 1 when this CPU may be virtualized (and *outIndex is set), 0 when it
// must be skipped. A 0 return never guesses and never clamps: clamping would
// land on a live neighbouring VCPU, which is failure mode (b) above.
//
// There is deliberately no "is this handle valid" parameter. An earlier revision
// had one, and its only non-1 argument came from a unit test: the one production
// caller already fails closed on EFI_ERROR(WhoAmI(...)) before calling, so the
// flag modelled a state the caller filters out upstream, and the branch existed
// only to be covered. outIndex is likewise never NULL from a caller.
static __inline int HvSmpResolveVcpuIndex(unsigned int whoAmI,
                                          unsigned int vcpuCount,
                                          unsigned int *outIndex)
{
    if (whoAmI >= vcpuCount) return 0;   // firmware enumerated a different CPU
                                         // set than HvVmxInitialize sized for
    *outIndex = whoAmI;
    return 1;
}

#endif // HV_SMP_INDEX_H

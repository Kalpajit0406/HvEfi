// hv_efi_vmx.c - VMX lifecycle using EFI Boot Services for allocation.
//
// EFI equivalent of HvDrv/hv_vmx.c.  Uses AllocatePages instead of
// MmAllocateContiguousMemory and identity mapping (VA == PA) throughout.

#include "hv_efi.h"
#include "shared/HvDrv/hv_msr_contract.h"

// ── Global VMX state ────────────────────────────────────────────────────────

HV_GLOBAL g_Hv = {0};

// ── Extended-state save policy for the VM-exit stub ────────────────────────
// Recomputed here (never on the exit path) so hv_asm.asm can read two memory
// operands instead of executing CPUID on every exit and every resume — that
// CPUID added its latency to each hypercall and EPT violation, which is both
// overhead and a timing signature of its own.
//
//   Mode 0 = FXSAVE/FXRSTOR, 1 = XSAVE/XRSTOR (OSXSAVE available)
//   Mask  = the XCR0 components that fit the reserved area, in EDX:EAX form
//
// The mask has to follow XCR0 rather than be fixed: a guest that enables a
// component later would otherwise be resumed with that component's state never
// saved, and the C exit handler's own SIMD use would have overwritten it.
//
// External linkage on purpose: hv_asm.asm refers to both symbols directly.
UINT32 g_HvStateSaveMode = 0;
UINT32 g_HvStateSaveMask = 0;

// The environment snapshot the shared decision (hv_xsave.h) consumes. Retained
// after refresh so HandleXsetbv can apply the same fit rule to a guest's new
// XCR0 before it reaches the real XSETBV.
static HV_XSAVE_ENV g_XsaveEnv = {0};

// Probe the CPU into the shared decision's input format.
static void ProbeXsaveEnv(HV_XSAVE_ENV *env) {
    int info[4] = {0, 0, 0, 0};
    UINT32 bit;

    RtlZeroMemory(env, sizeof(*env));
    __cpuid(info, 1);
    env->Osxsave = (info[2] & (1 << 27)) != 0;
    if (!env->Osxsave) return;

    env->Xcr0 = _xgetbv(0);
    for (bit = 0; bit < 32; bit++) {
        int comp[4] = {0, 0, 0, 0};
        __cpuidex(comp, 0xD, (int)bit);
        env->Size[bit]   = (UINT32)comp[0];
        env->Offset[bit] = (UINT32)comp[1];
    }
}

// Recompute the stub's save policy from the live XCR0. The decision itself
// (which components fit HV_XSAVE_AREA_BYTES) is shared with the WDK build in
// hv_xsave.h and covered by tools/unit/hvxsave_test.c.
//
// Returns FALSE when an XCR0-enabled component does NOT fit the area: the
// caller refuses to start VMX rather than resume guests with unsaved state.
// (With the current 16 KB area every component defined today fits, including
// AMX tile data, so this only fires on a genuinely larger future component.)
BOOLEAN HvRefreshStateSaveMask(void) {
    ProbeXsaveEnv(&g_XsaveEnv);

    if (!g_XsaveEnv.Osxsave) {
        g_HvStateSaveMode = 0;         // no XSAVE at all: FXSAVE/FXRSTOR only
        g_HvStateSaveMask = 0;
        return TRUE;
    }

    g_HvStateSaveMode = 1;             // XSAVE/XRSTOR
    g_HvStateSaveMask = HvXsaveMaskForArea(&g_XsaveEnv, HV_XSAVE_AREA_BYTES);

    // These two are shared by every CPU, while XCR0 is per-logical-processor.
    // An OS sets the same XCR0 everywhere, so in practice the refresh from any
    // CPU describes them all. A guest that deliberately sets a *narrower* XCR0
    // on one CPU after another enabled more would leave the mask too wide for
    // it until that CPU's next XSETBV — wide, not narrow, so nothing is left
    // unsaved; making that exact requires a per-CPU mask the stub cannot index
    // without the VCPU, which is not worth the exit-path cost.
    return HvXsaveMaskReady(&g_XsaveEnv, HV_XSAVE_AREA_BYTES);
}

// Would an XSETBV that leaves XCR0 at newXcr0 name a component the exit stub
// cannot save? Exposed for the XSETBV handler so the guest sees a #GP — what
// bare metal shows for an illegal XCR0 — instead of silently entering a state
// where its extended state is never saved.
BOOLEAN HvXsaveNewBitsSavable(UINT64 newXcr0) {
    return HvXsaveNewBitsFit(newXcr0, g_XsaveEnv.Size, g_XsaveEnv.Offset,
                             HV_XSAVE_AREA_BYTES);
}

// ── VMX support check ───────────────────────────────────────────────────────

BOOLEAN HvVmxIsSupported(void) {
    int regs[4] = {0};
    __cpuid(regs, 1);
    if (!(regs[2] & (1 << 5))) return FALSE;

    UINT64 fc = __readmsr(MSR_IA32_FEATURE_CONTROL);
    if ((fc & FEATURE_CONTROL_LOCKED) && !(fc & FEATURE_CONTROL_VMXON_OUTSIDE))
        return FALSE;

    UINT64 procCtls = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS);
    if (!((procCtls >> 32) & PROC_BASED_ACTIVATE_SECONDARY))
        return FALSE;

    UINT64 procCtls2 = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
    if (!((procCtls2 >> 32) & PROC2_ENABLE_EPT))
        return FALSE;
    // VPID is programmed in every VMCS (hv_vmcs.c writes VMCS_VPID), so the
    // control must be allowed — mirrors HvDrv/hv_vmx.c. Without it VMLAUNCH
    // fails on CPUs that cannot do VPID.
    if (!((procCtls2 >> 32) & PROC2_ENABLE_VPID))
        return FALSE;
    // EPT / VPID capability gate (Pass 94). Mirrors HvDrv/hv_vmx.c.
    //
    // The first two checks were already here and were CORRECT - Pass 94 verified
    // both against Intel's machine-readable SDM header (MiniVisorPkg ia32.h:
    // PAGE_WALK_LENGTH_4 = bit 6, INVEPT_ALL_CONTEXTS = bit 26,
    // INVEPT_SINGLE_CONTEXT = bit 25) rather than assuming. What was missing is
    // everything else the design structurally depends on: 2 MB PDEs (every RAM
    // leaf is a large page), the WB and UC memory types, and the INVVPID
    // instruction itself - the PROC2_ENABLE_VPID check above is the CONTROL bit,
    // which says whether a VMCS may enable VPID, not whether the instruction
    // exists. Without this the first INVLPG would #UD in VMX root.
    {
        UINT64 eptCap = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
        if (!(eptCap & (1ULL << EPTCAP_PAGE_WALK_LENGTH_4)))
            return FALSE;   // 4-level EPT walk: the tables assume it
        if (!(eptCap & (1ULL << EPTCAP_PDE_2MB_PAGES)))
            return FALSE;   // 2 MB PDEs: every RAM leaf uses them
        if (!(eptCap & (1ULL << EPTCAP_MEMORY_TYPE_WRITE_BACK)))
            return FALSE;   // WB: the memory type for all RAM
        if (!(eptCap & (1ULL << EPTCAP_MEMORY_TYPE_UNCACHEABLE)))
            return FALSE;   // UC: MMIO and the unclassifiable fallback
        if (!(eptCap & (1ULL << EPTCAP_INVEPT)))
            return FALSE;   // INVEPT at all
        if (!(eptCap & (1ULL << EPTCAP_INVEPT_ALL_CONTEXTS)))
            return FALSE;   // HvEptInvalidate issues all-contexts INVEPT
        if (!(eptCap & (1ULL << EPTCAP_INVVPID)))
            return FALSE;   // the INVVPID instruction itself
    }

    return TRUE;
}

// ── Allocate a VMX region (VMXON / VMCS) ────────────────────────────────────
// Must be below 4 GB, page-aligned, zeroed, with revision ID in first dword.

static PVOID AllocVmxRegion(UINT32 revisionId, UINT64 *outPhysical) {
    PVOID va = EfiAllocPagesBelow4G(1);
    if (!va) return NULL;
    *(UINT32 *)va = revisionId;
    *outPhysical = EfiVaToPA(va);
    return va;
}

// ── MSR bitmap setup ────────────────────────────────────────────────────────

static void SetMsrBit(PUCHAR bitmap, UINT32 msr, BOOLEAN read, BOOLEAN write) {
    UINT32 byte, bit;
    if (msr <= 0x1FFF) {
        byte = msr / 8;
        bit  = msr % 8;
    } else if (msr >= 0xC0000000 && msr <= 0xC0001FFF) {
        byte = 1024 + (msr - 0xC0000000) / 8;
        bit  = (msr - 0xC0000000) % 8;
    } else {
        return;
    }
    if (read)  bitmap[byte]        |= (UINT8)(1 << bit);
    if (write) bitmap[2048 + byte] |= (UINT8)(1 << bit);
}

static void FillMsrBitmap(PUCHAR bitmap) {
    RtlZeroMemory(bitmap, PAGE_SIZE);
    static const UINT32 kIntercepted[] = { HV_INTERCEPTED_MSRS };
    for (int i = 0; i < (int)(sizeof(kIntercepted) / sizeof(kIntercepted[0])); i++)
        SetMsrBit(bitmap, kIntercepted[i], TRUE, TRUE);
    // Deliberate non-interceptions are documented in hv_msr_contract.h.
}

// ── VMX Initialize ──────────────────────────────────────────────────────────

NTSTATUS HvVmxInitialize(void) {
    // Measure bare-metal CPUID latency first, before any VMXON work on this or
    // any other CPU: the CPUID pad exists to match unvirtualized latency, so
    // the samples must be taken while this CPU is still unrestricted.
    HvCalibrateCpuidLatency();

    // Must happen before any VM entry: hv_asm.asm reads both symbols on every
    // exit and resume, and a zero mask would XSAVE nothing meaningful. A FALSE
    // return means an XCR0-enabled component does not fit the reserved save
    // area — the guest's extended state could never be saved across an exit —
    // so refuse to start rather than corrupt guest state later.
    if (!HvRefreshStateSaveMask()) {
        EfiFatal("an XCR0 component exceeds the %u-byte XSAVE save area\n",
                 (UINT32)HV_XSAVE_AREA_BYTES);
        return STATUS_NOT_SUPPORTED;
    }

    UINT64 vmxBasic = __readmsr(MSR_IA32_VMX_BASIC);
    g_Hv.VmxRevisionId = (UINT32)(vmxBasic & 0x7FFFFFFF);

    UINTN cpuCount = 0;
    UINTN enabledCount = 0;
    EFI_STATUS st = gEfiMp->GetNumberOfProcessors(gEfiMp, &cpuCount, &enabledCount);
    if (EFI_ERROR(st) || cpuCount == 0) {
        EfiFatal("GetNumberOfProcessors failed: %r\n", st);
        return STATUS_NOT_SUPPORTED;
    }
    if (enabledCount != cpuCount) {
        EfiFatal("Disabled CPUs present (%u/%u) — all CPUs must be enabled\n",
                 (UINT32)enabledCount, (UINT32)cpuCount);
        return STATUS_NOT_SUPPORTED;
    }
    g_Hv.VcpuCount = (UINT32)cpuCount;

    UINT64 vcpuBytes = (UINT64)g_Hv.VcpuCount * sizeof(VCPU);
    if (vcpuBytes > MAXULONG64 - (PAGE_SIZE - 1))
        return STATUS_INSUFFICIENT_RESOURCES;
    UINT64 vcpuPages = (vcpuBytes + PAGE_SIZE - 1) / PAGE_SIZE;
    if (vcpuPages == 0 || vcpuPages > 0xFFFFFFFFULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    g_Hv.VcpusPageCount = (UINT32)vcpuPages;
    g_Hv.Vcpus = (PVCPU)EfiAllocPagesBelow4G(g_Hv.VcpusPageCount);
    if (!g_Hv.Vcpus) return STATUS_INSUFFICIENT_RESOURCES;

    for (UINT32 i = 0; i < g_Hv.VcpuCount; i++) {
        PVCPU v = &g_Hv.Vcpus[i];
        v->ProcessorIndex = i;
        v->GuestCr8 = 0;   // emulated guest TPR; see HandleCrAccess

        v->VmxonRegion = (PVMXON_REGION)AllocVmxRegion(
            g_Hv.VmxRevisionId, (UINT64 *)&v->VmxonPhysical.QuadPart);
        if (!v->VmxonRegion) goto fail;

        v->VmcsRegion = (PVMCS_REGION)AllocVmxRegion(
            g_Hv.VmxRevisionId, (UINT64 *)&v->VmcsPhysical.QuadPart);
        if (!v->VmcsRegion) goto fail;

        v->MsrBitmap = EfiAllocPagesBelow4G(1);
        if (!v->MsrBitmap) goto fail;
        v->MsrBitmapPhysical.QuadPart = (INT64)EfiVaToPA(v->MsrBitmap);
        FillMsrBitmap((PUCHAR)v->MsrBitmap);

        // Host stack. Must exceed HV_XSAVE_AREA_BYTES, which the exit stub
        // reserves off the top for XSAVE/XRSTOR, plus room for the C handler's
        // own frames. Kept as small as that allows on purpose: every page here
        // is also a page that has to fit in the hidden-page list, so a larger
        // stack lowers the CPU count the hypervisor can hide itself on.
        v->HostStackSize = 8 * PAGE_SIZE;
        v->HostStack = EfiAllocPagesBelow4G(8);
        if (!v->HostStack) goto fail;
    }

    // Require 4-level EPT walk capability (bit 6 of IA32_VMX_EPT_VPID_CAP).
    // Bit 6 = support for page-walk length of 4. If the CPU does not advertise
    // this, EPT will mis-walk the page tables and produce random translations.
    {
        UINT64 eptVpidCap = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
        if (!(eptVpidCap & (1ULL << 6))) {
            EfiFatal("CPU lacks 4-level EPT walk (IA32_VMX_EPT_VPID_CAP bit 6)\n");
            goto fail;
        }
    }

    NTSTATUS ns = HvEptInitialize(&g_Hv.Ept);
    if (!NT_SUCCESS(ns)) goto fail;

    // TSC base shift: ZERO in this build, on purpose.
    //
    // HvDrv/hv_vmx.c randomises the guest TSC so a usermode scan cannot
    // correlate it with boot time, and that trade is sound when the guest is an
    // operating system. This guest is not an operating system. It is the
    // firmware itself, mid-BDS, moments away from ExitBootServices, AP
    // synchronisation and the OS loader. With PROC_BASED_USE_TSC_OFFSET set,
    // RDTSC and RDTSCP return the hardware TSC plus this offset, while
    // IA32_TSC_DEADLINE and the local-APIC timers do NOT receive it - so a
    // per-boot shift of up to -2^32 ticks (-1.43 s at 3 GHz) installs two
    // disagreeing clocks inside code we neither control nor can instrument.
    // Firmware that samples the TSC across a deadline, or subtracts two TSC
    // reads unsigned, sees time step backwards at the exact instant VMLAUNCH
    // takes effect. This driver also arms a 120 s firmware watchdog
    // (hv_efi_main.c), which is a timer on the other side of that jump that
    // will not have moved.
    //
    // The randomisation is kept in HvDrv, where the guest is a real OS. To put
    // it back here, set HV_EFI_TSC_SHIFT to 1 - nothing else changes, and the
    // reason it is off lives next to the switch.
#define HV_EFI_TSC_SHIFT 0
#if HV_EFI_TSC_SHIFT
    {
        // Written once here, before any IPI; each vCPU XORs it with its
        // processor index during VMCS setup. HvRandomU64 gates RDRAND on
        // CPUID.1:ECX[30] and falls back to the TSC on pre-Ivy Bridge CPUs.
        UINT64 rnd = HvRandomU64();
        g_Hv.TscBootOffset = -(INT64)(rnd & 0x00000000FFFFFFFFULL);
        if (g_Hv.TscBootOffset == 0) g_Hv.TscBootOffset = -1;
    }
#else
    g_Hv.TscBootOffset = 0;
#endif

    return STATUS_SUCCESS;

fail:
    HvVmxShutdown();
    return STATUS_INSUFFICIENT_RESOURCES;
}

// ── Dark mode ───────────────────────────────────────────────────────────────
//
// DARK MODE TEARDOWN CONTRACT
// UNLOAD is accepted regardless of dark mode (the dispatch table checks UNLOAD
// before the dark gate, so teardown is always reachable).  Each HV_DARK_REASON
// converges on the same exit path: HvAuthUnload → HvSmpDevirtualizeAllProcessors
// → VMXOFF on every vCPU → HV_STATE_SHUTDOWN.  After SHUTDOWN no VMCALLs are
// processed; the next DETECT raises #UD (hypervisor gone).

void HvEnterDarkMode(HV_DARK_REASON reason) {
    g_Hv.State      = HV_STATE_DARK;
    g_Hv.DarkReason = reason;
    g_Hv.Dark       = TRUE;  // legacy shim kept for transition period
    EfiFatal("HvVmx: dark mode (reason %u)\n", (UINT32)reason);
}

BOOLEAN HvTransitionState(HV_STATE from, HV_STATE to) {
    // EDK2's intrinsic (intrin.h) takes `volatile long *` and `long` operands.
    // This tree typedefs LONG as INT32 — EDK2 has no LONG — so casting to
    // `volatile LONG *` is a different type and /W4 reports C4057. Use the
    // intrinsic's own spelling; both are 32-bit on every EDK2 target. The WDK
    // copy of this code needs no such care: there LONG *is* long.
    LONG old = (LONG)_InterlockedCompareExchange((volatile long *)&g_Hv.State,
                                                (long)to, (long)from);
    if (old == (LONG)from) return TRUE;
    HvEnterDarkMode(HV_DARK_ILLEGAL_TRANSITION);
    return FALSE;
}

// ── VMX Shutdown ────────────────────────────────────────────────────────────

void HvVmxShutdown(void) {
    // A peer AP may still be inside VirtualizeCpuBody (HvEfi/hv_efi_smp.c set
    // TeardownUnsafe when it observed a bring-up timeout with callbacks still
    // running). Everything below frees pages that CPU is writing, and the host
    // page tables it is holding as CR3 — freeing either is a use-after-free
    // that faults in VMX root with no handler and triple-faults the machine.
    // Leaking is the recoverable outcome: the allocation is never referenced
    // again, the driver returns EFI_ABORTED, and the firmware carries on.
    if (g_Hv.TeardownUnsafe) {
        EfiFatal("HvEfi: teardown unsafe (AP callback in flight) — "
                 "leaking VMX/EPT/host-PT allocations\n");
        return;
    }

    if (g_Hv.Running) {
        HvSmpDevirtualizeAllProcessors();
        g_Hv.Running = FALSE;
    }

    // Host page tables first: nothing above may dereference them after this.
    // (HvEptDestroy and the per-vCPU frees below only touch firmware-identity
    // memory, not the host map.)
    HvDestroyHostPageTables();
    HvHostTablesTeardown();

    HvEptDestroy(&g_Hv.Ept);

    if (g_Hv.Vcpus) {
        for (UINT32 i = 0; i < g_Hv.VcpuCount; i++) {
            PVCPU v = &g_Hv.Vcpus[i];
            // Zero before free, mirroring HvDrv/hv_vmx.c. The VMCS holds the
            // host CR3/RSP/RIP and the live EPTP; EFI-freed pages are handed
            // straight back to firmware and then to the OS, so zeroing matters
            // more here than in the driver, not less. What cannot be zeroed is
            // this image's own text — we execute from it — so a memory scan
            // after boot can still find the code; that is physics, not policy,
            // and the EPT hides it from the guest instead.
            if (v->VmxonRegion) {
                RtlSecureZeroMemory(v->VmxonRegion, PAGE_SIZE);
                EfiFreePages(v->VmxonRegion, 1);
            }
            if (v->VmcsRegion) {
                RtlSecureZeroMemory(v->VmcsRegion, PAGE_SIZE);
                EfiFreePages(v->VmcsRegion, 1);
            }
            if (v->MsrBitmap) {
                RtlSecureZeroMemory(v->MsrBitmap, PAGE_SIZE);
                EfiFreePages(v->MsrBitmap, 1);
            }
            if (v->HostStack) {
                RtlSecureZeroMemory(v->HostStack, 8 * PAGE_SIZE);
                EfiFreePages(v->HostStack, 8);
            }
        }
        RtlSecureZeroMemory(g_Hv.Vcpus,
                            (UINTN)g_Hv.VcpuCount * sizeof(VCPU));
        EfiFreePages(g_Hv.Vcpus, g_Hv.VcpusPageCount);
        g_Hv.Vcpus = NULL;
        g_Hv.VcpusPageCount = 0;
    }
}

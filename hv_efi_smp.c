// hv_efi_smp.c - Multi-processor VMX launch via EFI_MP_SERVICES_PROTOCOL.
//
// EFI equivalent of HvDrv/hv_smp.c.  Uses StartupAllAPs + direct BSP call
// instead of KeIpiGenericCall.

#include "hv_efi.h"
// Fail-closed resolution of a processor handle to a VCPU slot (Pass 94). The
// old fallback below fed an x2APIC ID into an array indexed BY HANDLE.
#include "shared/hv_smp_index.h"

// ── Per-CPU index ───────────────────────────────────────────────────────────
// In EFI, MpServices->WhoAmI gives a sequential processor number — but only
// while boot services are alive. After ExitBootServices gEfiMp dangles, so
// the runtime path (every VM exit) resolves the VCPU from the APIC ID table
// recorded at bring-up instead.

// Read the current CPU's APIC ID with no firmware service.
static UINT32 HvReadApicIdLocal(void) {
    int regs[4] = {0};
    __cpuid(regs, 1);
    // X2APIC supported (and the 0Bh topology leaf present, which x2APIC
    // implies — checked anyway against broken CPUID): full 32-bit ID.
    if (regs[2] & (1 << 21)) {
        int maxLeaf[4] = {0};
        __cpuid(maxLeaf, 0);
        if (maxLeaf[0] >= 0x0B) {
            int regs0b[4] = {0};
            __cpuidex(regs0b, 0x0B, 0);
            return (UINT32)regs0b[3];
        }
    }
    // Otherwise the 8-bit initial APIC ID from CPUID.1:EBX[31:24].
    return (UINT32)((regs[1] >> 24) & 0xFF);
}

// Set once every CPU has recorded its APIC ID (end of successful bring-up).
// Before that, HvGetCurrentVcpu falls back to WhoAmI (valid in DXE).
static BOOLEAN g_ApicIdsRecorded = FALSE;

// Resolve this CPU's VCPU slot, or fail.
//
// PI spec: WhoAmI returns the processor HANDLE, a dense 0..(EnabledProcessorCount-1)
// enumeration. That is exactly g_Hv.Vcpus[]'s index space, so it is the only
// sound source here.
//
// Pass 94 removed the old fallback to HvReadApicIdLocal(). The x2APIC ID is a
// different numbering, and on the usual Intel client layout (a 12-thread part
// reports APIC IDs 0,2,4,...,22) feeding it to a handle-indexed array either
// skipped the AP outright or - worse - wrote this CPU's VMXON/VMCS pointers into
// a DIFFERENT CPU's VCPU struct, leaving two processors sharing one VMCS. Neither
// is a crash, so neither was ever reported.
//
// Failing closed turns both cases into the count mismatch the rollback path
// already handles correctly. A CPU left un-virtualized is recoverable; a CPU
// virtualized into the wrong slot is silent corruption.
static BOOLEAN TryCurrentCpuIndex(UINT32 *outIndex) {
    UINTN cpuNum = 0;
    unsigned int idx = 0;

    if (!gEfiMp) return FALSE;
    if (EFI_ERROR(gEfiMp->WhoAmI(gEfiMp, &cpuNum))) return FALSE;
    if (!HvSmpResolveVcpuIndex((unsigned int)cpuNum, g_Hv.VcpuCount, &idx))
        return FALSE;
    if (outIndex) *outIndex = (UINT32)idx;
    return TRUE;
}

PVCPU HvGetCurrentVcpu(void) {
    if (g_ApicIdsRecorded) {
        UINT32 apic = HvReadApicIdLocal();
        for (UINT32 i = 0; i < g_Hv.VcpuCount; i++) {
            if (g_Hv.Vcpus[i].ApicId == apic)
                return &g_Hv.Vcpus[i];
        }
        // Unknown CPU: the exit handler treats NULL as "devirtualize".
        return NULL;
    }
    // Pre-bring-up and rollback paths run while gEfiMp is alive, so the
    // handle is available. Never fall back to an APIC ID as an index here
    // either - the exit handler treats a NULL vCPU as devirtualize, which
    // is the right answer when the identity genuinely cannot be resolved.
    UINT32 idx = 0;
    if (!TryCurrentCpuIndex(&idx)) return NULL;
    return &g_Hv.Vcpus[idx];
}

// ── Virtualize one CPU ──────────────────────────────────────────────────────

static volatile LONG g_VmxonSuccess = 0;

// Thin wrapper so the in-flight count covers EVERY exit path of the body below
// (which has six returns, and one of them is a successful VMLAUNCH that never
// returns to the BSP's C frame in the usual sense). Bracketing here rather than
// in the body means the count cannot drift if a return is added later.
static void VirtualizeCpuBody(PVOID context);

static void VirtualizeCpuCallback(PVOID context) {
    // This tree typedefs LONG as INT32, and the _Interlocked* intrinsics take
    // `volatile long *` — the same spelling issue the increment below already
    // documents.
    _InterlockedIncrement((volatile long *)&g_Hv.CbInFlight);
    VirtualizeCpuBody(context);
    _InterlockedDecrement((volatile long *)&g_Hv.CbInFlight);
}

static void VirtualizeCpuBody(PVOID context) {
    UNREFERENCED_PARAMETER(context);

    UINT32 idx = 0;
    if (!TryCurrentCpuIndex(&idx)) {
        // Unresolvable handle: refuse this CPU rather than guess a slot.
        // Reported as a stage-12 failure so the receipt names the class,
        // instead of only showing a count that came up short.
        // Deliberately no mailbox write here. Every AP shares one
        // Stage/Detail pair, so N failing APs raced on it and the
        // receipt named an arbitrary CPU. The BSP writes a single
        // deterministic summary once the IPI returns, and infers
        // "unresolvable handle" from a short count with no per-CPU
        // LaunchError recorded. See HvReportBringUpSummary().
        return;
    }
    if (idx >= g_Hv.VcpuCount) return;
    PVCPU vcpu = &g_Hv.Vcpus[idx];

    // Record the APIC ID now (MP Services valid in DXE): the runtime exit
    // path resolves VCPUs from this table and never touches gEfiMp.
    vcpu->ApicId = HvReadApicIdLocal();

    // Enable VMX in CR4
    UINT64 cr4 = __readcr4();
    cr4 |= CR4_VMXE;
    __writecr4(cr4);

    // Adjust CR0 fixed bits
    UINT64 cr0 = __readcr0();
    cr0 |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);
    cr0 &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
    __writecr0(cr0);

    // Adjust CR4 fixed bits
    cr4 = __readcr4();
    cr4 |= __readmsr(MSR_IA32_VMX_CR4_FIXED0);
    cr4 &= __readmsr(MSR_IA32_VMX_CR4_FIXED1);
    __writecr4(cr4);

    // Enable VMXON outside SMX if not already locked.
    //
    // NOTE: this latches VT-x on at the firmware level, and the LOCK means the
    // machine keeps it across reboots. The WDK build does not do this (it fails
    // closed unless the firmware already allowed VMXON). It is required here
    // because the caller is the platform firmware path, but it is a machine
    // level side effect, not a per-boot one — the guest still reads a
    // virtualised FEATURE_CONTROL (LOCKED only), so its view stays
    // self-consistent with the CPUID story.
    UINT64 fc = __readmsr(MSR_IA32_FEATURE_CONTROL);
    if (!(fc & FEATURE_CONTROL_LOCKED)) {
        fc |= FEATURE_CONTROL_LOCKED | FEATURE_CONTROL_VMXON_OUTSIDE;
        __writemsr(MSR_IA32_FEATURE_CONTROL, fc);
    }

    // VMXON. The VMX intrinsics take unsigned __int64 *, and a &QuadPart
    // lvalue is a signed LONGLONG *, so go through typed PA locals (the
    // HvDrv tree does the same against the real WDK headers).
    UINT64 vmxonPa = vcpu->VmxonPhysical.QuadPart;
    unsigned char status = __vmx_on(&vmxonPa);
    if (status) {
        __writecr4(__readcr4() & ~CR4_VMXE);
        vcpu->LaunchError = HvStage12DetailEncode(HV_STAGE12_CLASS_VMXON, status,
                                                 vcpu->ProcessorIndex);
        return;
    }
    vcpu->VmxEnabled = TRUE;

    // VMCLEAR + VMPTRLD
    UINT64 vmcsPa = vcpu->VmcsPhysical.QuadPart;
    if (__vmx_vmclear(&vmcsPa) != 0) {
        HV_LOG(("HvEfi: VMCLEAR failed on AP\n"));
        __vmx_off();
        __writecr4(__readcr4() & ~CR4_VMXE);
        vcpu->VmxEnabled = FALSE;
        vcpu->LaunchError = HvStage12DetailEncode(HV_STAGE12_CLASS_VMCLEAR, 0,
                                                 vcpu->ProcessorIndex);
        return;
    }
    if (__vmx_vmptrld(&vmcsPa) != 0) {
        HV_LOG(("HvEfi: VMPTRLD failed on AP\n"));
        __vmx_off();
        __writecr4(__readcr4() & ~CR4_VMXE);
        vcpu->VmxEnabled = FALSE;
        vcpu->LaunchError = HvStage12DetailEncode(HV_STAGE12_CLASS_VMPTRLD, 0,
                                                 vcpu->ProcessorIndex);
        return;
    }

    // Setup VMCS
    NTSTATUS ns = HvVmcsSetupCpu(vcpu);
    if (!NT_SUCCESS(ns)) {
        __vmx_off();
        __writecr4(__readcr4() & ~CR4_VMXE);
        vcpu->VmxEnabled = FALSE;
        vcpu->LaunchError = HvStage12DetailEncode(HV_STAGE12_CLASS_VMCS, (UINT32)ns,
                                                 vcpu->ProcessorIndex);
        return;
    }

    // VMLAUNCH — HvAsmVmxLaunch returns 0 on success (guest resumes),
    // non-zero on failure (stays in root mode). The two failure classes are
    // distinguished by the asm: 1 = CF set = VM-entry failed, and only then is
    // MSR 0x4400 (VM-instruction error) valid; 2 = ZF set = the VMX root
    // operation itself failed, e.g. this CPU was already virtualized.
    //
    // Reading that error is the whole point. Until now this branch was a bare
    // VMXOFF-and-return, so a platform that ended up half-virtualized reported
    // nothing at all and was indistinguishable from a clean stand-down - the one
    // failure this step is most likely to produce. detail carries the class in
    // bit 8 and the error code in the low byte, so the receipt can say which.
    int rc = HvAsmVmxLaunch();
    if (rc != 0) {
        UINT64 vmInstrError = 0;
        if (rc == 2 || rc == 1) {
            __vmx_vmread(VMCS_VM_INSTR_ERROR, &vmInstrError);
        }
        vcpu->LaunchError =
            HvStage12DetailEncode(HV_STAGE12_CLASS_VMENTRY,
                                (UINT32)vmInstrError,
                                vcpu->ProcessorIndex);
        HV_POST(0xE2);
        HV_LOG(("HvEfi: VMLAUNCH failed on CPU %u (class=%u vm-instr-error=0x%lX)\n",
                vcpu->ProcessorIndex, (unsigned)rc, (unsigned long)vmInstrError));
        __vmx_off();
        __writecr4(__readcr4() & ~CR4_VMXE);
        vcpu->VmxEnabled = FALSE;
        return;
    }

    vcpu->Launched = TRUE;
    // _InterlockedIncrement (intrin.h) takes `volatile long *`; this tree
    // typedefs LONG as INT32, so the cast must use the intrinsic's own
    // spelling or /W4 reports C4057. Same reasoning as the
    // _InterlockedCompareExchange call in hv_efi_vmx.c.
    _InterlockedIncrement((volatile long *)&g_VmxonSuccess);
}

// AP wrapper for EFI_MP_SERVICES_PROTOCOL callback signature
static VOID EFIAPI ApVirtualizeCallback(VOID *buffer) {
    VirtualizeCpuCallback(buffer);
}

// ── Devirtualize (UNLOAD) guest-state capture/restore ───────────────────────
// The asm stub (_vmexit_do_vmxoff) snapshots the VMCS guest state while still
// in VMX operation, issues VMXOFF, then hands the snapshot here to put the
// CPU back exactly where the guest was.

// EDK2's STATIC_ASSERT, not _Static_assert: under MSVC (_MSC_EXTENSIONS) Base.h
// maps STATIC_ASSERT to C11 static_assert, while a bare _Static_assert is not a
// keyword this compiler accepts (error C2143).
STATIC_ASSERT(sizeof(HV_UNLOAD_STATE) == HV_UNLOAD_STATE_SIZE,
              "HV_UNLOAD_STATE size drifted from the asm EQU");

// VMREAD one guest field; a failure here can only mean a wrong field
// encoding (a programming error) — the VMCS is current, we are in VMX
// operation. Halting beats restoring a zeroed field and triple-faulting
// on the first segment load.
//
// Writes POST 0xBE ("VMREAD failed in teardown") and then halts the CPU.
// `__halt` emits HLT, which parks the CPU until an interrupt — an interrupt
// will resume it, which is why we loop. We cannot return from here without
// corrupting the devirtualization snapshot.
void __outbyte(unsigned short Port, unsigned char Data);
void __halt(void);
#define HV_VMREAD_OR_HALT(field, dst)                                   \
    do {                                                                \
        if (__vmx_vmread((field), (dst)) != 0) {                         \
            EfiFatal("HvEfi: VMREAD failed, field 0x%x\n",                \
                     (unsigned)(field));                                 \
            __outbyte(0x80, 0xBE);                                        \
            for (;;) { __halt(); }                                        \
        }                                                               \
    } while (0)

void HvCaptureUnloadState(PHV_UNLOAD_STATE s) {
    // All reads must succeed: these fields are always valid in the VMCS.
    RtlZeroMemory(s, sizeof(*s));
    HV_VMREAD_OR_HALT(VMCS_GUEST_CR3, &s->Cr3);
    HV_VMREAD_OR_HALT(VMCS_GUEST_RIP, &s->Rip);
    HV_VMREAD_OR_HALT(VMCS_GUEST_RSP, &s->Rsp);
    HV_VMREAD_OR_HALT(VMCS_GUEST_CS_SEL, &s->CsSel);
    HV_VMREAD_OR_HALT(VMCS_GUEST_GDTR_BASE, &s->GdtrBase);
    HV_VMREAD_OR_HALT(VMCS_GUEST_GDTR_LIMIT, &s->GdtrLimit);
    HV_VMREAD_OR_HALT(VMCS_GUEST_IDTR_BASE, &s->IdtrBase);
    HV_VMREAD_OR_HALT(VMCS_GUEST_IDTR_LIMIT, &s->IdtrLimit);
    HV_VMREAD_OR_HALT(VMCS_GUEST_DS_SEL, &s->DsSel);
    HV_VMREAD_OR_HALT(VMCS_GUEST_ES_SEL, &s->EsSel);
    HV_VMREAD_OR_HALT(VMCS_GUEST_FS_SEL, &s->FsSel);
    HV_VMREAD_OR_HALT(VMCS_GUEST_GS_SEL, &s->GsSel);
    HV_VMREAD_OR_HALT(VMCS_GUEST_SS_SEL, &s->SsSel);
    HV_VMREAD_OR_HALT(VMCS_GUEST_TR_SEL, &s->TrSel);
    HV_VMREAD_OR_HALT(VMCS_GUEST_LDTR_SEL, &s->LdtrSel);
    HV_VMREAD_OR_HALT(VMCS_GUEST_FS_BASE, &s->FsBase);
    HV_VMREAD_OR_HALT(VMCS_GUEST_GS_BASE, &s->GsBase);
    HV_VMREAD_OR_HALT(VMCS_GUEST_PAT, &s->Pat);
    HV_VMREAD_OR_HALT(VMCS_GUEST_EFER, &s->Efer);
    HV_VMREAD_OR_HALT(VMCS_GUEST_RFLAGS, &s->Rflags);
    HV_VMREAD_OR_HALT(VMCS_GUEST_CR0, &s->Cr0);
    HV_VMREAD_OR_HALT(VMCS_GUEST_CR4, &s->Cr4);
    HV_VMREAD_OR_HALT(VMCS_GUEST_DR7, &s->Dr7);
    // CR2 is deliberately not captured: VMX transitions never modify it, and
    // the exit stub performs no faulting accesses, so the guest's CR2 is
    // already intact. (If the stub ever faulted, CR2 would be the least of
    // our problems — there is no host fault handler.)
}

// Read one physical qword through the host identity map. Anything at or above
// HostPml4Units × 512 GB is outside the map and would fault in this context
// (post-VMXOFF, no fault handler), so bounds-check first.
static BOOLEAN UnloadReadPhys(UINT64 pa, PUINT64 out, PVOID ctx) {
    UNREFERENCED_PARAMETER(ctx);
    UINT64 hostMapBytes = (UINT64)g_Hv.HostPml4Units << 39;
    if (pa >= hostMapBytes || (pa & 7)) return FALSE;
    *out = *(volatile UINT64 *)(UINTN)pa;
    return TRUE;
}

// Translate a guest VA to PA through the guest's own page tables (s->Cr3).
// Presence at every level is all we require: the GDT is kernel memory and
// every caller only reads/writes the TSS descriptor through the result.
static UINT64 UnloadGuestVaToPa(UINT64 cr3, UINT64 va) {
    return HvPtWalk(UnloadReadPhys, NULL, cr3, va, 0);
}

static BOOLEAN UnloadReadGuestVa(UINT64 cr3, UINT64 va, PUINT64 out) {
    UINT64 pa = UnloadGuestVaToPa(cr3, va);
    if (pa == HV_PA_INVALID) return FALSE;
    return UnloadReadPhys(pa, out, NULL);
}

static BOOLEAN UnloadWriteGuestVa(UINT64 cr3, UINT64 va, UINT64 val) {
    UINT64 pa = UnloadGuestVaToPa(cr3, va);
    if (pa == HV_PA_INVALID) return FALSE;
    UINT64 hostMapBytes = (UINT64)g_Hv.HostPml4Units << 39;
    if (pa >= hostMapBytes || (pa & 7)) return FALSE;
    *(volatile UINT64 *)(UINTN)pa = val;
    return TRUE;
}

void HvUnloadRestoreState(PHV_UNLOAD_STATE s) {
    // We are out of VMX (VMXOFF done, CR4.VMXE clear) but still on the host
    // stack under the host CR3. Register-only operations (LGDT/LIDT,
    // segment selectors, WRMSR) are safe anywhere. Anything that
    // DEREFERENCES a guest virtual address is not: post-ExitBootServices the
    // guest's tables live at high canonical VAs the host identity map does
    // not cover, so the TSS/LDT work below translates the guest GDTR base to
    // a physical address first and touches it through the identity map.
    //
    // Interrupts stay disabled throughout (the exit stub entered with IF
    // clear); the stub's final IRETQ restores the guest RFLAGS atomically.
    //
    // Ordering: the scratch GDTR is installed BEFORE any guest selector is
    // loaded. Every selector load (DS/ES/FS/GS/SS, TR, LDTR) resolves
    // against the live GDTR; loading guest selectors while the host GDT is
    // still installed would resolve them against the wrong table.
    //
    // Returns to the asm stub, which then loads the address-space switch
    // args (CR3/RSP/CS/RIP/RFLAGS) from the snapshot and jumps to
    // HvAsmSwitchToGuest. Guest RAX (the hypercall result) is preserved by
    // the stub, not here.
    //
    // Reachability note: every devirtualization path in this driver runs in
    // DXE (bring-up rollback, entry-point fail_vmx), where the guest IS the
    // firmware and host/guest share the identity-mapped address space and
    // the firmware GDT. The UNLOAD hypercall is additionally reachable in
    // principle post-EBS, but its RIP-in-image authorization makes that
    // unreachable in practice (no issuer can place a VMCALL inside the
    // hidden image range). The translation machinery below keeps the code
    // correct for the general case anyway.

    // The scratch GDTR points at the physical page backing the guest GDT's
    // first byte. Every descriptor the CPU reads must live in that same
    // physical page: adjacent guest-virtual pages are not guaranteed to be
    // physically adjacent, so a GDT straddling a page boundary would make
    // the scratch mapping read the wrong bytes past the boundary. Verify
    // single-page containment before trusting it.
    UINT64 gdtPa = HV_PA_INVALID;
    if (((s->GdtrBase & 0xFFFULL) + (s->GdtrLimit & 0xFFFFULL)) < 0x1000ULL)
        gdtPa = UnloadGuestVaToPa(s->Cr3, s->GdtrBase);
    // Scratch GDT first (see ordering note above). If the GDT straddles a
    // page or is unreachable, the host GDTR stays live: in DXE it IS the
    // guest GDT, so the selector loads below are still correct; the
    // unreachable post-EBS case is the only one that would want more.
    if (gdtPa != HV_PA_INVALID)
        HvAsmLoadGdtr((UINT16)s->GdtrLimit, gdtPa);  // scratch, phys

    HvAsmLoadIdtr((UINT16)s->IdtrLimit, s->IdtrBase);
    HvAsmLoadSegments((UINT16)s->DsSel, (UINT16)s->EsSel,
                      (UINT16)s->FsSel, (UINT16)s->GsSel, (UINT16)s->SsSel);

    // TR/LDTR: both instructions read the GDT. The scratch GDTR installed
    // above makes the guest's descriptors readable; the real guest base is
    // loaded (register-only) after.
    {
        UINT64 trOff = s->TrSel & ~7ULL;
        if (trOff != 0 && trOff + 15 <= s->GdtrLimit &&
            gdtPa != HV_PA_INVALID) {
            // The CPU marks the guest TSS busy in the guest GDT on every VM
            // entry and never clears it on exit, but LTR faults on a busy
            // TSS. Clear the busy bit in the guest's own GDT entry first.
            // Single-page containment was verified above, so the 8-byte
            // translated access cannot straddle a page.
            UINT64 lo = 0;
            if (UnloadReadGuestVa(s->Cr3, s->GdtrBase + trOff, &lo) &&
                ((lo >> 40) & 0xFULL) == 0xBULL)   // busy 64-bit TSS
                UnloadWriteGuestVa(s->Cr3, s->GdtrBase + trOff,
                                   lo & ~(1ULL << 41));  // -> available (0x9)
            HvAsmLoadTr((UINT16)s->TrSel);
            if ((s->LdtrSel & ~7ULL) != 0)
                HvAsmLoadLdtr((UINT16)s->LdtrSel);
        }
        // else: TR/LDTR stay at host values. In DXE those ARE the guest's
        // (same firmware tables); failing closed here would need a fault
        // handler we do not have, and halting would brick the boot.
    }
    HvAsmLoadGdtr((UINT16)s->GdtrLimit, s->GdtrBase);  // real base, reg-only
    // FS/GS bases are MSRs, not covered by the selector loads.
    __writemsr(MSR_IA32_FS_BASE, s->FsBase);
    __writemsr(MSR_IA32_GS_BASE, s->GsBase);
    // The VM exit loaded the *host* PAT/EFER/DR7; put the guest's back. All
    // were live in the guest moments ago, so the values are valid in long
    // mode. (The guest's SYSENTER MSRs were never virtualized — still live.)
    __writemsr(MSR_IA32_PAT, s->Pat);
    __writemsr(MSR_IA32_EFER, s->Efer);
    HvAsmWriteDr7(s->Dr7);
    // Control registers last: the GDT writes above are done, and the CR3
    // switch (with its TLB flush) happens in the asm stub after we return.
    // VMXE is masked out unconditionally — the guest never had it.
    __writecr0(s->Cr0);
    __writecr4(s->Cr4 & ~(1ULL << 13));
    // Return to the stub; it performs the CR3/RSP switch + IRETQ to the guest.
}

// ── Devirtualize one CPU ────────────────────────────────────────────────────
// No teardown credentials are cached: UNLOAD is authorized by the caller's
// position (guest RIP inside our own image range, checked in VMX root), so
// there is no secret for anyone to lift from our data segment.

static void DevirtualizeCpuCallback(PVOID context) {
    UNREFERENCED_PARAMETER(context);

    // Only a CPU that actually entered non-root mode may issue VMCALL. In VMX
    // root operation VMCALL raises #UD, and a DXE #UD has no recovery — the
    // firmware's default handler dead-loops with the F12 menu dead. A CPU
    // whose bring-up failed before VMLAUNCH (VMXON done or not) just needs
    // VMXOFF + CR4.VMXE cleared locally; anything more would fault.
    PVCPU vcpu = HvGetCurrentVcpu();
    if (vcpu && vcpu->Launched) {
        // UNLOAD is fully authenticated (HvAuthUnload): a VMCALL with
        // magic=0/mac=0 fails auth -> #UD injected -> DXE hangs with no
        // recovery (the original brick). Pass the real session credentials
        // from the hidden secrets page.
        PHV_SECRETS secrets = GetSecretsPage();
        UINT64 magic = secrets ? secrets->SessionMagic : 0;
        UINT64 mac   = secrets ? secrets->UnloadMac : 0;
        HvAsmVmcallUnload(magic, HV_HYPERCALL_UNLOAD, 0, 0, mac, 0);
    } else if (vcpu && vcpu->VmxEnabled) {
        __vmx_off();
    }

    // Verify the assembly stub cleared CR4.VMXE (VMXOFF + CR4 write by the stub).
    if (__readcr4() & CR4_VMXE) {
        EfiFatal("HvEfi: CR4.VMXE still set after VMXOFF on teardown CPU!\n");
        __writecr4(__readcr4() & ~CR4_VMXE);
    }
    if (vcpu) {
        vcpu->Launched = FALSE;
        vcpu->VmxEnabled = FALSE;
    }
}

static VOID EFIAPI ApDevirtualizeCallback(VOID *buffer) {
    DevirtualizeCpuCallback(buffer);
}

// ── Public entry points ─────────────────────────────────────────────────────
// Write the ONE step-12 failure report for this boot.
//
// Every AP records its own failure in vcpu->LaunchError and writes nothing to
// the mailbox. That split is the whole point: the mailbox has a single
// Stage/Detail pair, so N failing APs used to race on it and the receipt named
// whichever one wrote last - an arbitrary CPU, and an arbitrary VM-instruction
// error with it. On the Dell that is the difference between "one AP could not
// launch" and "no idea which of twelve".
//
// This runs on the BSP, after StartupAllAPs has returned, so it is the single
// writer and the result is deterministic: the LOWEST-numbered failing CPU wins,
// every time.
//
// A short count with no per-CPU LaunchError means the CPUs that never reached
// VirtualizeCpuBody at all - i.e. their processor handle was unresolvable
// (HvSmpResolveVcpuIndex refused). That case has no VCPU to attach an error to,
// which is exactly why it is inferred here instead of recorded there.
//
// failedList is StartupAllAPs' FailedCpuList (may be NULL). Per PI spec its
// FIRST element is the number of failed APs, followed by that many handles and
// terminated by END_OF_CPU_LIST. It names the APs whose Procedure was TERMINATED
// at the timeout; those CPUs never got to record anything either, so they fold
// into the same summary unless a VCPU already carries a more specific cause.
//
// The handles are read here and the buffer freed by the caller - MP Services
// allocates it, so the caller owns the free, and the summary must not keep the
// pointer past that.
static VOID HvReportBringUpSummary(const UINTN *failedList) {
    UINT32 failedCount = 0;
    UINT32 i;
    UINT32 worstClass = 0;
    UINT32 worstErr = 0;
    UINT32 worstHandle = 0;
    BOOLEAN found = FALSE;

    for (i = 0; i < g_Hv.VcpuCount; i++) {
        PVCPU v = &g_Hv.Vcpus[i];
        if (v->LaunchError == 0) continue;
        // Lowest index wins: the loop runs in order and never overwrites.
        if (!found) {
            worstClass = HvStage12DetailClass(v->LaunchError);
            worstErr = HvStage12DetailVmErr(v->LaunchError);
            worstHandle = HvStage12DetailHandle(v->LaunchError);
            found = TRUE;
        }
    }

    if (failedList != NULL)
        failedCount = (UINT32)failedList[0];

    if (!found && failedCount > 0) {
        worstClass = HV_STAGE12_CLASS_TIMEOUT;
        worstErr = 0;
        // failedList[1] is the first failed handle; [0] is the count.
        worstHandle = (failedCount > 1) ? (UINT32)failedList[1]
                                        : (UINT32)failedCount;
        found = TRUE;
    }

    if (!found) {
        // Count is short but nothing recorded why: the CPUs that never reached
        // the callback could not resolve their own handle.
        worstClass = HV_STAGE12_CLASS_NO_HANDLE;
    }

    HV_POST(0xE2);
    HvReportStage(HV_STAGE_FAIL(12),
                  HvStage12DetailEncode(worstClass, worstErr, worstHandle));
}


NTSTATUS HvSmpVirtualizeAllProcessors(void) {
    g_VmxonSuccess = 0;
    // PI spec: if the timeout expires, "Procedure on the failed APs is terminated"
    // and FailedCpuList names them. MP Services allocates the buffer with
    // AllocatePool, so the caller owns freeing it - passing NULL used to throw
    // that information away and left the receipt with a bare count.
    UINTN  *failedList = NULL;

    // Pre-initialize Host GDT and IDT with all VCPU TSS descriptors on BSP
    HV_DTR gdtr;
#ifdef HV_EFI_BUILD
    __sgdt(&gdtr);
#else
    HvReadGdtr(&gdtr);
#endif
    UINT16 cs = __readcs();
    NTSTATUS hostTblSt = HvHostTablesInit(gdtr.Base, (UINT16)gdtr.Limit, (UINT16)(cs & ~7), g_Hv.VcpuCount);
    if (!NT_SUCCESS(hostTblSt)) {
        EfiFatal("HvHostTablesInit failed: 0x%x\n", hostTblSt);
        return hostTblSt;
    }

    // Virtualize BSP first (the current processor)
    VirtualizeCpuCallback(NULL);

    // If the BSP itself failed to launch, skip the APs: the count check below
    // triggers the rollback path regardless, and attempting AP bring-up would
    // only burn the 5 s timeout (plus a VMXON/VMLAUNCH cycle per AP) for nothing.
    // VirtualizeCpuCallback increments g_VmxonSuccess only after a successful
    // VMLAUNCH, so a zero count here means the BSP never launched.
    if (g_Hv.VcpuCount > 1 && (UINT32)g_VmxonSuccess > 0) {
        // 5-second timeout: an AP that hangs in VirtualizeCpuCallback (e.g.
        // VMXON fails, VMPTRLD hangs, VMLAUNCH faults) must not stall the BSP
        // indefinitely. If the timeout fires, EFI_TIMEOUT is returned and we
        // fall through to the partial-rollback path below.
        EFI_STATUS st = gEfiMp->StartupAllAPs(
            gEfiMp,
            ApVirtualizeCallback,
            TRUE,       // SingleThread = TRUE (sequential bring-up)
            NULL,       // WaitEvent = NULL (blocking)
            5000000,    // TimeoutInMicroseconds = 5 s
            NULL,       // ProcedureArgument
            &failedList  // real list: names the APs terminated at the timeout
        );
        if (EFI_ERROR(st) && st != EFI_TIMEOUT) {
            EfiFatal("StartupAllAPs failed: %r\n", st);
        }
        // EFI_TIMEOUT falls through: g_VmxonSuccess < VcpuCount triggers rollback
    }

    // Read the terminated-AP list into the summary BEFORE freeing it:
    // MP Services owns the allocation, so this is the only chance.
    if ((UINT32)g_VmxonSuccess < g_Hv.VcpuCount) {
        HvReportBringUpSummary((const UINTN *)failedList);
    }
    if (failedList != NULL) {
        gEfiBS->FreePool(failedList);
        failedList = NULL;
    }

    // Verify all CPUs succeeded.
    //
    // Before acting on the count, ask whether any callback is STILL RUNNING.
    // StartupAllAPs returning EFI_TIMEOUT (or an error) does not distinguish
    // "the AP never arrived" — harmless, nothing of ours is executing — from
    // "the AP is part-way through VirtualizeCpuBody" — where it is actively
    // writing the very VMXON/VMCS/EPT/host-stack pages the rollback below
    // frees, and holds CR3 = g_Hv.HostPml4Pa while it does so.
    //
    // Freeing under it is a use-after-free on a CPU in VMX root mode: the next
    // page walk dereferences a freed (or zeroed) PML4, faults with no handler
    // installed, and triple-faults. On the BSP that is a brick. Flipping that
    // into a leak — pages that stay allocated, zeroed or not, and are simply
    // never reused — costs a few MB of firmware pool and cannot hang anything.
    //
    // This is the only place that needs the distinction, which is why it lives
    // here and not in the callback: the callback cannot know whether anyone
    // is still counting it.
    if ((UINT32)g_Hv.CbInFlight != 0) {
        g_Hv.TeardownUnsafe = TRUE;
        EfiFatal("HvEfi: %d callback(s) still in flight at bring-up timeout\n",
                 (int)g_Hv.CbInFlight);
    }

    if ((UINT32)g_VmxonSuccess < g_Hv.VcpuCount) {
        // Disable hypercall interface before logging or rolling back, so that
        // any hypercalls issued during the window are silently refused.
        HvEnterDarkMode(HV_DARK_PARTIAL_LAUNCH);
        EfiFatal("VMX: only %d/%d CPUs launched, rolling back\n",
                 g_VmxonSuccess, g_Hv.VcpuCount);

        // Partial success — devirtualize those that succeeded
        g_Hv.Running = TRUE;  // devirtualize path needs Running set
        g_Hv.State   = HV_STATE_RUNNING;
        HvSmpDevirtualizeAllProcessors();
        return STATUS_UNSUCCESSFUL;
    }

    HvTransitionState(HV_STATE_HIDDEN, HV_STATE_RUNNING);
    g_Hv.Running = TRUE;  // legacy shim
    // Every CPU recorded its APIC ID above: the exit path can now resolve
    // VCPUs without MP Services (which dangle after ExitBootServices).
    g_ApicIdsRecorded = TRUE;
    return STATUS_SUCCESS;
}

void HvSmpDevirtualizeAllProcessors(void) {
    if (!g_Hv.Running) return;

    // Devirtualize BSP
    DevirtualizeCpuCallback(NULL);

    // Devirtualize all APs
    if (g_Hv.VcpuCount > 1) {
        // 5-second timeout, mirroring bring-up: a wedged AP must not hang the
        // BSP forever on unload. EFI_TIMEOUT is best-effort here (teardown
        // continues); any other failure is fatal-logged.
        EFI_STATUS st = gEfiMp->StartupAllAPs(
            gEfiMp,
            ApDevirtualizeCallback,
            TRUE, NULL, 5000000, NULL,
            NULL    // FailedCpuList - teardown does not need it
        );
        if (EFI_ERROR(st) && st != EFI_TIMEOUT) {
            EfiFatal("HvEfi: AP devirtualize StartupAllAPs failed: %r\n", st);
        }
    }

    HvTransitionState(HV_STATE_RUNNING, HV_STATE_SHUTDOWN);
    g_Hv.Running = FALSE;  // legacy shim
}

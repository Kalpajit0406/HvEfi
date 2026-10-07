// hv_vmcs.c - VMCS (Virtual Machine Control Structure) setup for the EFI DXE
// hypervisor.
//
// This file is kept functionally identical to HvDrv/hv_vmcs.c.
// Any change must be applied to BOTH copies.
// Genuine differences (EFI vs WDK host environment) are #ifdef HV_EFI_BUILD guarded:
//   - GDTR/IDTR reading: EFI uses __sgdt/__sidt (EDK2 intrinsics); WDK uses
//     HvReadGdtr/HvReadIdtr (asm stubs that repack the hardware format).
//   - HOST_CR3: EFI uses g_Hv.HostPml4Pa (our own identity-mapped page tables
//     built during EFI init); WDK uses g_Hv.HostCr3 (System process CR3).
//
// Called once per CPU after VMXON, from the IPI handler in hv_smp.c.

#include "hvdefs.h"
#include "../hv_hostidt.h"
#include "hv_efi.h"  // EfiFatal (via DEBUG) for the two fail-hard VMCS aborts below

// ── GDT / Segment helpers ───────────────────────────────────────────────────
//
// The descriptor layouts and the decoding (base/limit/access-rights over a
// 64-bit GDT) live in hv_segs.h, shared with the WDK build and executed
// off-target by tools/unit/hvsegs_test.c. What remains here is the reader over
// the live GDT and the call sites that fill VMCS guest state.

// HV_EFI_BUILD: __sgdt / __sidt write to the hardware-format packed descriptor
// (2-byte limit at offset 0, 8-byte base at offset 2). HvReadGdtr / HvReadIdtr
// repack into HV_DTR (naturally aligned); for EFI the raw intrinsic is used
// directly with the same HV_DTR struct (EDK2's BaseLib guarantees the layout).
#ifdef HV_EFI_BUILD
typedef struct {
    UINT16 Limit;
    UINT64 Base;
} GDTR;
#else
typedef HV_DTR GDTR;
#endif

// The live GDT is identity-mapped firmware memory; a plain copy is the reader.
// hv_segs.h bounds every access against gdtr.Limit first, so this can never
// read past the table.
static BOOLEAN HvGdtRead(UINT64 gdtBase, UINT32 offset, UINT32 bytes,
                         PVOID out, PVOID ctx) {
    UNREFERENCED_PARAMETER(ctx);
    RtlCopyMemory(out, (const void *)(gdtBase + offset), bytes);
    return TRUE;
}

// NOTE: not named GetSegmentBase/GetSegmentLimit/GetSegmentAccessRights —
// wdm.h (and anything that mirrors it) defines
// `#define GetSegmentLimit __segmentlimit`, which would rename these helpers
// into MSVC intrinsics and fail the build.
static UINT64 HvGetSegmentBase(UINT64 gdtBase, UINT16 gdtrLimit, UINT16 selector) {
    return HvSegmentBase(HvGdtRead, gdtBase, gdtrLimit, selector, NULL);
}

static UINT32 HvGetSegmentAccessRights(UINT64 gdtBase, UINT16 gdtrLimit,
                                       UINT16 selector) {
    return (UINT32)HvSegmentAccessRights(HvGdtRead, gdtBase, gdtrLimit,
                                         selector, NULL);
}

static UINT32 HvGetSegmentLimit(UINT64 gdtBase, UINT16 gdtrLimit, UINT16 selector) {
    return HvSegmentLimit(HvGdtRead, gdtBase, gdtrLimit, selector, NULL);
}

// ── Adjust VMX controls to allowed 0/1 bits ─────────────────────────────────

static UINT32 AdjustControls(UINT32 desired, UINT32 msrIndex) {
    // TRUE_* MSRs (0x48D-0x490) are only valid when IA32_VMX_BASIC[55]=1.
    // If the bit is clear, fall back to the non-TRUE counterparts (0x481-0x484).
    // The clamp itself and the fallback rule live in hv_contract.h, where both
    // trees share them and tools/unit can run them; only the privileged MSR
    // reads stay here.
    if (msrIndex >= MSR_IA32_VMX_TRUE_PINBASED_CTLS &&
        msrIndex <= MSR_IA32_VMX_TRUE_ENTRY_CTLS) {
        msrIndex = HvVmxControlsMsrIndex(msrIndex, __readmsr(MSR_IA32_VMX_BASIC),
                                         MSR_IA32_VMX_TRUE_PINBASED_CTLS,
                                         MSR_IA32_VMX_TRUE_ENTRY_CTLS);
    }
    return HvVmxAdjustControls(desired, __readmsr(msrIndex));
}

// ── VMCS setup for one CPU ──────────────────────────────────────────────────


// ── Host-owned IDT and GDT (see hv_hostidt.h for the full rationale) ────────
//
// The processor reloads the host IDTR/GDTR from the VMCS on EVERY VM-exit. If
// those bases point at the firmware's own tables - as they did until this
// header - the setup is valid at VMLAUNCH and becomes a latent fault the moment
// EDK2 reclaims the firmware tables around ExitBootServices. The exit stub's
// `cli` does not protect against it: IF masks only maskable interrupts, while
// NMI and machine-check are delivered against the host IDTR regardless.
//
// These live in the image's own .data, which stays resident for as long as the
// exit handler's code does, so the tables outlive the OS.
//
// Tables live in the image's own .data, which stays resident for as long as the
// exit handler's code does, so the tables outlive the OS.

static UINT8 g_HvHostIdt[HV_IDT_ENTRIES * HV_IDT_GATE_BYTES];
static UINT8 g_HvHostGdt[HV_HOST_GDT_MAX_BYTES];
static UINT32 g_HvHostGdtLimit = 0;
static UINT16 g_HvHostBaseTssSlot = 0;
static BOOLEAN g_HvHostTablesInitialized = FALSE;

// Set if the host ever takes an unexpected exception in VMX root. Read by the
// EBS callback path for diagnosis; never cleared.
volatile UINT32 g_HvHostFaultSeen;

// Defined by EDK2 BaseLib for the EFI build; an MSVC intrinsic for the
// WDK build. Declared here the way hv_efi_smp.c already does.
void __halt(void);

// Handler for every host IDT gate.
VOID HvHostException(VOID) {
    g_HvHostFaultSeen++;
    for (;;) { __halt(); }
}

void HvHostTablesTeardown(void) {
    g_HvHostTablesInitialized = FALSE;
    g_HvHostGdtLimit = 0;
    g_HvHostBaseTssSlot = 0;
    RtlZeroMemory(g_HvHostIdt, sizeof(g_HvHostIdt));
    RtlZeroMemory(g_HvHostGdt, sizeof(g_HvHostGdt));
}

NTSTATUS HvHostTablesInit(UINT64 firmwareGdtBase, UINT16 firmwareGdtLimit,
                         UINT16 csSelector, UINT32 vcpuCount)
{
    if (firmwareGdtBase == 0 || vcpuCount == 0 || vcpuCount > g_Hv.VcpuCount) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(g_HvHostIdt, sizeof(g_HvHostIdt));
    RtlZeroMemory(g_HvHostGdt, sizeof(g_HvHostGdt));

    if (HvBuildHostIdt(g_HvHostIdt, (UINT32)sizeof(g_HvHostIdt),
                       (UINT64)HvHostException, (UINT16)(csSelector & ~7)) !=
        HV_IDT_ENTRIES) {
        EfiFatal("HvVmcs: host IDT build failed\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (HvCopyHostGdt(g_HvHostGdt, (UINT32)sizeof(g_HvHostGdt),
                      firmwareGdtBase, firmwareGdtLimit) == 0) {
        EfiFatal("HvVmcs: host GDT copy failed (firmware limit 0x%X)\n", firmwareGdtLimit);
        return STATUS_INVALID_PARAMETER;
    }

    UINT16 tr = __readtr();
    UINT32 trAr = (tr != 0) ? HvGetSegmentAccessRights(firmwareGdtBase, firmwareGdtLimit, tr) : (UINT32)HV_SEG_UNUSABLE;

    if (tr == 0 || (trAr & (UINT32)HV_SEG_UNUSABLE) || !(trAr & (1 << 7))) {
        // No usable TSS in firmware GDT (UEFI DXE). Allocate 16-byte TSS slots for all VCPUs.
        UINT32 baseTssSlot = ((UINT32)firmwareGdtLimit + 1u + 7u) & ~7u;
        UINT32 totalLimit = baseTssSlot + (vcpuCount * 16u) - 1u;

        if (totalLimit >= sizeof(g_HvHostGdt)) {
            EfiFatal("HvVmcs: total GDT limit 0x%x overflows host GDT buffer\n", totalLimit);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        for (UINT32 i = 0; i < vcpuCount; i++) {
            PVCPU v = &g_Hv.Vcpus[i];
            UINT64 hostRsp = (UINT64)v->HostStack + v->HostStackSize;
            hostRsp &= ~0x3FULL; // 64-byte align (XSAVE requirement)

            RtlZeroMemory(&v->Tss, sizeof(v->Tss));
            v->Tss.Rsp0 = hostRsp;
            v->Tss.IoMapBase = (UINT16)sizeof(HV_TSS64);

            UINT32 tssSlot = baseTssSlot + (i * 16u);
            HvSetTssDescriptor(g_HvHostGdt, (UINT16)tssSlot, (UINT64)&v->Tss,
                               (UINT32)(sizeof(HV_TSS64) - 1));
        }

        g_HvHostBaseTssSlot = (UINT16)baseTssSlot;
        g_HvHostGdtLimit = totalLimit;
    } else {
        // Usable TSS already exists (WDK / Windows kernel).
        g_HvHostBaseTssSlot = tr & ~7;
        g_HvHostGdtLimit = firmwareGdtLimit;
    }

    g_HvHostTablesInitialized = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS HvVmcsSetupCpu(PVCPU vcpu) {
    GDTR gdtr, idtr;
#ifdef HV_EFI_BUILD
    __sgdt(&gdtr);
    __sidt(&idtr);
#else
    HvReadGdtr((HV_DTR *)&gdtr);
    HvReadIdtr((HV_DTR *)&idtr);
#endif

    UINT16 cs = __readcs();
    UINT16 ss = __readss();
    UINT16 ds = __readds();
    UINT16 es = __reades();
    UINT16 fs = __readfs();
    UINT16 gs = __readgs();
    UINT16 tr = __readtr();
    UINT16 ldtr = __readldtr();

    UINT64 cr0 = __readcr0();
    UINT64 cr3 = __readcr3();
    UINT64 cr4 = __readcr4();
    UINT64 dr7 = __readdr(7);

    // Ensure host tables are initialized
    if (!g_HvHostTablesInitialized) {
        NTSTATUS st = HvHostTablesInit(gdtr.Base, gdtr.Limit, cs, g_Hv.VcpuCount);
        if (!NT_SUCCESS(st)) return st;
    }

    // ── VM-execution controls ───────────────────────────────────────────

    // Pin-based: none. NMI exiting is deliberately NOT enabled — it would make
    // every NMI trap into a handler that only re-injects it, paying an exit for
    // nothing. With no pin-based control, NMIs pass straight through.
    UINT32 pinCtls = AdjustControls(0, MSR_IA32_VMX_TRUE_PINBASED_CTLS);
    HvVmWriteChecked(VMCS_PIN_BASED_CONTROLS, pinCtls);

    // Primary proc-based: enable secondary controls, MSR bitmaps, and TSC
    // offset. See HvDrv/hv_vmcs.c for the full rationale. Per-boot random
    // shift stored in g_Hv.TscBootOffset; no per-exit adjustment.
    UINT32 procCtls = AdjustControls(
        PROC_BASED_ACTIVATE_SECONDARY | PROC_BASED_USE_MSR_BITMAPS |
        PROC_BASED_USE_TSC_OFFSET,
        MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
    HvVmWriteChecked(VMCS_PROC_BASED_CONTROLS, procCtls);
    HvVmWriteChecked(VMCS_TSC_OFFSET,
                  (UINT64)(INT64)(g_Hv.TscBootOffset ^ (INT64)vcpu->ProcessorIndex));

    // Secondary: EPT, VPID, RDTSCP, INVPCID, XSAVES, unrestricted guest.
    // Unrestricted guest is required for INIT-SIPI AP bringup: the OS sends
    // INIT-SIPI to wake APs, which must start in real mode (PE=0, PG=0).
    // Without unrestricted guest, the VMCS cannot hold real-mode state.
    // (no TRUE variant MSR exists for secondary proc-based controls)
    UINT32 procCtls2 = AdjustControls(
        PROC2_ENABLE_EPT | PROC2_ENABLE_VPID | PROC2_ENABLE_RDTSCP |
        PROC2_ENABLE_INVPCID | PROC2_ENABLE_XSAVES |
        PROC2_UNRESTRICTED_GUEST,
        MSR_IA32_VMX_PROCBASED_CTLS2);
    if (!(procCtls2 & PROC2_ENABLE_EPT)) {
        EfiFatal("HvVmcs: PROC2_ENABLE_EPT cleared by AdjustControls on CPU %u — "
                 "EPT not available, refusing VMCS setup\n", vcpu->ProcessorIndex);
        return STATUS_NOT_SUPPORTED;
    }
    if (!(procCtls2 & PROC2_UNRESTRICTED_GUEST)) {
        EfiFatal("HvVmcs: PROC2_UNRESTRICTED_GUEST unavailable on CPU %u — "
                 "cannot support OS AP bringup, refusing VMCS setup\n",
                 vcpu->ProcessorIndex);
        return STATUS_NOT_SUPPORTED;
    }
    HvVmWriteChecked(VMCS_PROC_BASED_CONTROLS2, procCtls2);

    // Exit controls: 64-bit host, save/load EFER/PAT.
    //
    // IA32_PERF_GLOBAL_CTRL is deliberately NOT in the load/save set. This is a
    // partitioned hypervisor: the "guest" is the real Windows system and the
    // "host" is our exit stub, so there is exactly one PMU view. The SDM defines
    // only a "load IA32_PERF_GLOBAL_CTRL" exit control (bit 12) with no matching
    // "save" control; enabling it overwrites the running system's real PMU
    // programming with the host-state field on EVERY exit and can never capture
    // a guest write back into VMCS_GUEST_IA32_PERF_GLOBAL_CTRL. That silently
    // disables all hardware counters for the machine (and is a loud tell).
    // Leaving the control clear means VMX never touches the MSR at all, so the
    // PMU stays transparent across every exit/entry without a bitmap trap.
    UINT32 exitCtls = AdjustControls(
        EXIT_CTRL_HOST_ADDR_SPACE_SIZE | EXIT_CTRL_SAVE_EFER |
        EXIT_CTRL_LOAD_EFER | EXIT_CTRL_SAVE_PAT | EXIT_CTRL_LOAD_PAT |
        EXIT_CTRL_ACK_INT_ON_EXIT,
        MSR_IA32_VMX_TRUE_EXIT_CTLS);
    HvVmWriteChecked(VMCS_EXIT_CONTROLS, exitCtls);

    // Entry controls: IA-32e guest, load EFER/PAT.
    // PERF_GLOBAL_CTRL is intentionally absent here too — see the exit-control
    // note above. Loading a never-updated guest field on entry would clobber any
    // PMU programming the system did while running.
    UINT32 entryCtls = AdjustControls(
        ENTRY_CTRL_IA32E_MODE_GUEST | ENTRY_CTRL_LOAD_EFER | ENTRY_CTRL_LOAD_PAT,
        MSR_IA32_VMX_TRUE_ENTRY_CTLS);
    HvVmWriteChecked(VMCS_ENTRY_CONTROLS, entryCtls);

    // ── Control fields ──────────────────────────────────────────────────

    HvVmWriteChecked(VMCS_EXCEPTION_BITMAP,    0);
    HvVmWriteChecked(VMCS_PF_ERROR_CODE_MASK,  0);
    HvVmWriteChecked(VMCS_PF_ERROR_CODE_MATCH, 0);
    HvVmWriteChecked(VMCS_CR3_TARGET_COUNT,    0);
    // CR0 mask owns PE and PG so the exit handler can track real-mode ↔
    // long-mode transitions during INIT-SIPI AP bringup. In steady state
    // (all CPUs in long mode, PE=1 PG=1), no CR0 write changes either bit,
    // so the mask adds zero exits to normal operation.
    HvVmWriteChecked(VMCS_CR0_GUEST_HOST_MASK, CR0_PE | CR0_PG);
    // CR4's mask MUST own VMXE (bit 13). A guest read of CR4 returns the read
    // shadow only for bits set in the mask, so leaving the mask at 0 made
    // VMCS_CR4_READ_SHADOW dead and handed the guest the real CR4 — with
    // VMXE=1, the single loudest VT-x tell. The read shadow below clears VMXE,
    // and only a write that actually changes bit 13 now causes an exit
    // (handled in hv_exit.c); every other CR4 bit stays guest-owned and free.
    HvVmWriteChecked(VMCS_CR4_GUEST_HOST_MASK, CR4_VMXE);
    HvVmWriteChecked(VMCS_CR0_READ_SHADOW,     cr0);
    HvVmWriteChecked(VMCS_CR4_READ_SHADOW,     cr4 & ~CR4_VMXE);

    // MSR bitmap — all zeros = pass through all MSRs (no VM-exit)
    HvVmWriteChecked(VMCS_MSR_BITMAP, vcpu->MsrBitmapPhysical.QuadPart);

    // VPID — unique per vCPU (0 is invalid)
    HvVmWriteChecked(VMCS_VPID, (UINT64)(vcpu->ProcessorIndex + 1));

    // EPT pointer
    HvVmWriteChecked(VMCS_EPT_PTR, g_Hv.Ept.EptPointer);

    // VMCS link pointer = -1 (no shadow VMCS)
    HvVmWriteChecked(VMCS_GUEST_VMCS_LINK_PTR, (UINT64)-1);

    // ── Host stack and TSS ──────────────────────────────────────────────
    UINT64 hostRsp = (UINT64)vcpu->HostStack + vcpu->HostStackSize;
    hostRsp &= ~0x3FULL; // 64-byte align (XSAVE requirement)

    // Determine TSS selector for Host and Guest state.
    // In UEFI DXE, firmware runs without loading TR (tr == 0) and has no TSS in
    // its GDT. In Windows (WDK build), tr is 0x40 and already in the GDT.
    // If tr is 0 or unusable, use the pre-allocated TSS slot from g_HvHostGdt.
    UINT16 hostTr = tr & ~7;
    UINT64 hostTrBase = 0;
    UINT16 guestTr = tr;
    UINT64 guestTrBase = 0;
    UINT32 guestTrLimit = 0;
    UINT32 guestTrAccess = 0;
    UINT64 guestGdtBase = gdtr.Base;
    UINT32 guestGdtLimit = gdtr.Limit;

    UINT32 trAr = (tr != 0) ? HvGetSegmentAccessRights(gdtr.Base, gdtr.Limit, tr) : (UINT32)HV_SEG_UNUSABLE;
    if (tr == 0 || (trAr & (UINT32)HV_SEG_UNUSABLE) || !(trAr & (1 << 7))) {
        // Firmware has no usable TSS. Use pre-allocated TSS slot from g_HvHostGdt.
        UINT16 tssSlot = g_HvHostBaseTssSlot + (UINT16)(vcpu->ProcessorIndex * 16u);

        hostTr = tssSlot;
        hostTrBase = (UINT64)&vcpu->Tss;

        // Guest TR must also be valid for VMLAUNCH (Intel SDM 26.3.1.2:
        // TR unusable bit must be 0, type must be 11 or 9, present must be 1).
        guestTr = tssSlot;
        guestTrBase = (UINT64)&vcpu->Tss;
        guestTrLimit = (UINT32)(sizeof(HV_TSS64) - 1);
        guestTrAccess = 0x8B; // Present (0x80), DPL 0, System (0x00), Type 11 (64-bit Busy TSS)

        // Point guest GDTR to g_HvHostGdt so GDT limit covers all TSS descriptors
        guestGdtBase = (UINT64)g_HvHostGdt;
        guestGdtLimit = g_HvHostGdtLimit;
    } else {
        hostTrBase = HvGetSegmentBase(gdtr.Base, gdtr.Limit, tr);
        guestTrBase = hostTrBase;
        guestTrLimit = HvGetSegmentLimit(gdtr.Base, gdtr.Limit, tr);
        guestTrAccess = trAr;
    }

    // ── Guest state ─────────────────────────────────────────────────────
    // Mirror the current CPU state so the guest continues transparently.

    HvVmWriteChecked(VMCS_GUEST_CS_SEL,   cs);
    HvVmWriteChecked(VMCS_GUEST_SS_SEL,   ss);
    HvVmWriteChecked(VMCS_GUEST_DS_SEL,   ds);
    HvVmWriteChecked(VMCS_GUEST_ES_SEL,   es);
    HvVmWriteChecked(VMCS_GUEST_FS_SEL,   fs);
    HvVmWriteChecked(VMCS_GUEST_GS_SEL,   gs);
    HvVmWriteChecked(VMCS_GUEST_TR_SEL,   guestTr);
    HvVmWriteChecked(VMCS_GUEST_LDTR_SEL, ldtr);

    HvVmWriteChecked(VMCS_GUEST_CS_LIMIT,   HvGetSegmentLimit(gdtr.Base, gdtr.Limit, cs));
    HvVmWriteChecked(VMCS_GUEST_SS_LIMIT,   HvGetSegmentLimit(gdtr.Base, gdtr.Limit, ss));
    HvVmWriteChecked(VMCS_GUEST_DS_LIMIT,   HvGetSegmentLimit(gdtr.Base, gdtr.Limit, ds));
    HvVmWriteChecked(VMCS_GUEST_ES_LIMIT,   HvGetSegmentLimit(gdtr.Base, gdtr.Limit, es));
    HvVmWriteChecked(VMCS_GUEST_FS_LIMIT,   HvGetSegmentLimit(gdtr.Base, gdtr.Limit, fs));
    HvVmWriteChecked(VMCS_GUEST_GS_LIMIT,   HvGetSegmentLimit(gdtr.Base, gdtr.Limit, gs));
    HvVmWriteChecked(VMCS_GUEST_TR_LIMIT,   guestTrLimit);
    HvVmWriteChecked(VMCS_GUEST_LDTR_LIMIT, HvGetSegmentLimit(gdtr.Base, gdtr.Limit, ldtr));
    HvVmWriteChecked(VMCS_GUEST_GDTR_LIMIT, guestGdtLimit);
    HvVmWriteChecked(VMCS_GUEST_IDTR_LIMIT, idtr.Limit);

    HvVmWriteChecked(VMCS_GUEST_CS_ACCESS,   HvGetSegmentAccessRights(gdtr.Base, gdtr.Limit, cs));
    HvVmWriteChecked(VMCS_GUEST_SS_ACCESS,   HvGetSegmentAccessRights(gdtr.Base, gdtr.Limit, ss));
    HvVmWriteChecked(VMCS_GUEST_DS_ACCESS,   HvGetSegmentAccessRights(gdtr.Base, gdtr.Limit, ds));
    HvVmWriteChecked(VMCS_GUEST_ES_ACCESS,   HvGetSegmentAccessRights(gdtr.Base, gdtr.Limit, es));
    HvVmWriteChecked(VMCS_GUEST_FS_ACCESS,   HvGetSegmentAccessRights(gdtr.Base, gdtr.Limit, fs));
    HvVmWriteChecked(VMCS_GUEST_GS_ACCESS,   HvGetSegmentAccessRights(gdtr.Base, gdtr.Limit, gs));
    HvVmWriteChecked(VMCS_GUEST_TR_ACCESS,   guestTrAccess);
    HvVmWriteChecked(VMCS_GUEST_LDTR_ACCESS, HvGetSegmentAccessRights(gdtr.Base, gdtr.Limit, ldtr));

    HvVmWriteChecked(VMCS_GUEST_CS_BASE,   HvGetSegmentBase(gdtr.Base, gdtr.Limit, cs));
    HvVmWriteChecked(VMCS_GUEST_SS_BASE,   HvGetSegmentBase(gdtr.Base, gdtr.Limit, ss));
    HvVmWriteChecked(VMCS_GUEST_DS_BASE,   HvGetSegmentBase(gdtr.Base, gdtr.Limit, ds));
    HvVmWriteChecked(VMCS_GUEST_ES_BASE,   HvGetSegmentBase(gdtr.Base, gdtr.Limit, es));
    HvVmWriteChecked(VMCS_GUEST_FS_BASE,   __readmsr(MSR_IA32_FS_BASE));
    HvVmWriteChecked(VMCS_GUEST_GS_BASE,   __readmsr(MSR_IA32_GS_BASE));
    HvVmWriteChecked(VMCS_GUEST_TR_BASE,   guestTrBase);
    HvVmWriteChecked(VMCS_GUEST_LDTR_BASE, HvGetSegmentBase(gdtr.Base, gdtr.Limit, ldtr));
    HvVmWriteChecked(VMCS_GUEST_GDTR_BASE, guestGdtBase);
    HvVmWriteChecked(VMCS_GUEST_IDTR_BASE, idtr.Base);

    HvVmWriteChecked(VMCS_GUEST_CR0, cr0);
    HvVmWriteChecked(VMCS_GUEST_CR3, cr3);
    HvVmWriteChecked(VMCS_GUEST_CR4, cr4);
    HvVmWriteChecked(VMCS_GUEST_DR7, dr7);

    HvVmWriteChecked(VMCS_GUEST_DEBUGCTL,      __readmsr(MSR_IA32_DEBUGCTL));
    HvVmWriteChecked(VMCS_GUEST_SYSENTER_CS,   __readmsr(MSR_IA32_SYSENTER_CS));
    HvVmWriteChecked(VMCS_GUEST_SYSENTER_ESP,  __readmsr(MSR_IA32_SYSENTER_ESP));
    HvVmWriteChecked(VMCS_GUEST_SYSENTER_EIP,  __readmsr(MSR_IA32_SYSENTER_EIP));
    HvVmWriteChecked(VMCS_GUEST_PAT,           __readmsr(MSR_IA32_PAT));
    HvVmWriteChecked(VMCS_GUEST_EFER,          __readmsr(MSR_IA32_EFER));
    // NOTE: VMCS_GUEST_IA32_PERF_GLOBAL_CTRL is not written. That field only
    // exists when the "load IA32_PERF_GLOBAL_CTRL" VM-entry control is 1, which
    // we intentionally leave clear (see the control setup above). The PMU MSR is
    // passed through untouched, so it needs neither a VMCS field nor an
    // MSR-bitmap trap.

    // Guest RIP/RSP will be set by the assembly launch stub (hv_asm.asm)
    // to the instruction following VMLAUNCH, so the guest resumes exactly
    // where it was when the IPI handler called us.
    // HvVmWriteChecked(VMCS_GUEST_RSP, ...);  // set by asm
    // HvVmWriteChecked(VMCS_GUEST_RIP, ...);  // set by asm

    HvVmWriteChecked(VMCS_GUEST_RFLAGS, __readeflags());
    HvVmWriteChecked(VMCS_GUEST_ACTIVITY_STATE, 0);
    HvVmWriteChecked(VMCS_GUEST_INTERRUPTIBILITY, 0);
    HvVmWriteChecked(VMCS_GUEST_PENDING_DBG_EXCEPT, 0);

    // ── Host state ──────────────────────────────────────────────────────
    // The host state defines where the CPU lands on VM-exit.

    HvVmWriteChecked(VMCS_HOST_CR0, cr0);
    // HOST_CR3: EFI uses the hypervisor's own identity-mapped page tables
    // (g_Hv.HostPml4Pa) built during DXE init. The firmware's page tables (the
    // current CR3) are reclaimed after ExitBootServices, but our tables are
    // allocated as EfiRuntimeServicesData and persist.
    // WDK uses g_Hv.HostCr3 (System process CR3, which lives as long as the
    // kernel) — see HvResolveHostCr3. Both guarantee the host exits onto a page
    // table that outlives the guest.
#ifdef HV_EFI_BUILD
    if (g_Hv.HostPml4Pa == 0) {
        EfiFatal("HvVmcs: HostPml4Pa is zero on CPU %u — page table init failed; "
                 "aborting VMCS setup\n", vcpu->ProcessorIndex);
        return STATUS_INVALID_PARAMETER;
    }
    HvVmWriteChecked(VMCS_HOST_CR3, g_Hv.HostPml4Pa);
#else
    if (g_Hv.HostCr3 == 0) {
        HV_LOG(("HvVmcs: HostCr3 is zero on CPU %u — aborting VMCS setup\n",
                 vcpu->ProcessorIndex));
        return STATUS_INVALID_PARAMETER;
    }
    HvVmWriteChecked(VMCS_HOST_CR3, g_Hv.HostCr3);
#endif

    HvVmWriteChecked(VMCS_HOST_CR4, cr4);

    HvVmWriteChecked(VMCS_HOST_CS_SEL, cs & ~7);
    HvVmWriteChecked(VMCS_HOST_SS_SEL, ss & ~7);
    HvVmWriteChecked(VMCS_HOST_DS_SEL, ds & ~7);
    HvVmWriteChecked(VMCS_HOST_ES_SEL, es & ~7);
    HvVmWriteChecked(VMCS_HOST_FS_SEL, fs & ~7);
    HvVmWriteChecked(VMCS_HOST_GS_SEL, gs & ~7);
    HvVmWriteChecked(VMCS_HOST_TR_SEL, hostTr);

    HvVmWriteChecked(VMCS_HOST_FS_BASE,   __readmsr(MSR_IA32_FS_BASE));
    HvVmWriteChecked(VMCS_HOST_GS_BASE,   __readmsr(MSR_IA32_GS_BASE));
    HvVmWriteChecked(VMCS_HOST_TR_BASE,   hostTrBase);

    HvVmWriteChecked(VMCS_HOST_GDTR_BASE, (UINT64)g_HvHostGdt);
    HvVmWriteChecked(VMCS_HOST_IDTR_BASE, (UINT64)g_HvHostIdt);

    HvVmWriteChecked(VMCS_HOST_SYSENTER_CS,  __readmsr(MSR_IA32_SYSENTER_CS));
    HvVmWriteChecked(VMCS_HOST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
    HvVmWriteChecked(VMCS_HOST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
    HvVmWriteChecked(VMCS_HOST_PAT,          __readmsr(MSR_IA32_PAT));
    HvVmWriteChecked(VMCS_HOST_EFER,         __readmsr(MSR_IA32_EFER));
    // NOTE: VMCS_HOST_IA32_PERF_GLOBAL_CTRL is not written (and the exit control
    // that would consume it is clear). Writing 0 here previously zeroed the
    // machine's PMU control on every VM exit.

    HvVmWriteChecked(VMCS_HOST_RSP, hostRsp);

    // Host RIP = VM-exit entry point (assembly stub that saves guest regs,
    // calls HvExitHandler, restores guest regs, does VMRESUME)
    HvVmWriteChecked(VMCS_HOST_RIP, (UINT64)HvAsmVmxEntry);

    return STATUS_SUCCESS;
}

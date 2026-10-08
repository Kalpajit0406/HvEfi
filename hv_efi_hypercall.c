// hv_efi_hypercall.c - Hypercall dispatch for the EFI VMX hypervisor.
//
// EFI equivalent of HvDrv/hv_hypercall.c.  Physical memory access uses
// identity-mapped host page tables (VA == PA in VMX root mode) so
// MmGetVirtualForPhysical/MmMapIoSpace are simple casts.
// PsLookupProcessByProcessId is replaced by a guest page-table walk.

#include "hv_efi.h"

// ── CR3 offset for EPROCESS (default for Windows 10/11 22H2) ────────────────

// Configurable via HV_HYPERCALL_SET_CR3_OFFSET from the guest client.
// Default 0x28 works for all recent Windows 10/11 builds.

// ── Physical memory access (identity mapping) ───────────────────────────────
// In VMX root mode with our identity-mapped host page tables, PA == VA.

static inline PVOID PhysToVirt(UINT64 pa) {
    return (PVOID)(UINTN)pa;
}

static UINT64 ReadPhysU64(UINT64 pa) {
    return *(volatile UINT64 *)PhysToVirt(pa);
}

static BOOLEAN ReadPhysU64Safe(UINT64 pa, UINT64 *out) {
    UINT64 limit = (UINT64)g_Hv.HostPml4Units << 39;
    if (pa + 8 > limit || (pa & 7)) return FALSE;
    *out = *(volatile UINT64 *)PhysToVirt(pa);
    return TRUE;
}

// ── Read PTE at physical address ────────────────────────────────────────────

// Page-table entry reader for the shared walk in hv_ptwalk.h. The address is
// guest-controlled (it comes from the previous level's PTE), so it must be
// validated before dereferencing: the host identity map only spans
// HostPml4Units × 512 GB, and anything above it faults in VMX root mode with
// no handler. A FALSE return makes HvPtWalk report HV_PA_INVALID instead of
// crashing the hypervisor on a crafted page-table chain.
static BOOLEAN ReadPteAtPa(UINT64 physAddr, PUINT64 outVal, PVOID ctx) {
    UNREFERENCED_PARAMETER(ctx);
    UINT64 hostMapBytes = (UINT64)g_Hv.HostPml4Units << 39;
    if (physAddr >= hostMapBytes || (physAddr & 7)) return FALSE;
    *outVal = ReadPhysU64(physAddr);
    return TRUE;
}

// ── Page table walk (guest VA → PA) ─────────────────────────────────────────

static UINT64 TranslateGuestVa(UINT64 cr3, UINT64 va) {
    // Presence at every level only: these are kernel/EPROCESS addresses, so no
    // U/S requirement, and every caller only reads through the result.
    return HvPtWalk(ReadPteAtPa, NULL, cr3, va, 0);
}

// ── User VA → PA through the caller's page tables ────────────────────────────
//
// Same reasoning as HvDrv/hv_hypercall.c: VM-exit loads CR3 from the VMCS
// host-state area, which for the EFI build is the hypervisor's own identity
// map. That map resolves *physical* addresses, so a caller-supplied user VA
// cannot be dereferenced in root. The hypercall translates it through the
// guest's page tables (saved in VMCS_GUEST_CR3 on exit) and copies via the
// physical page, which the identity map does resolve.
//
// Unlike TranslateGuestVa, this also enforces the permission bits a user
// buffer needs: every level present and user-accessible, and the leaf writable
// when the caller asked for a write. The translation is the validation; the
// EFI build has no SEH, so there is no probe backstop to fall back on.

static UINT64 TranslateUserPage(UINT64 cr3, UINT64 va, BOOLEAN write) {
    return HvPtWalk(ReadPteAtPa, NULL, cr3, va,
                    HV_PT_USER | (write ? HV_PT_WRITE : 0u));
}

// ── Get process CR3 by PID ──────────────────────────────────────────────────
// Walks the guest kernel's EPROCESS linked list through physical memory.
// Requires the guest to be running Windows.

// Windows EPROCESS offsets (22H2 / 23H2 / 24H2)
#define EPROCESS_ACTIVE_LINKS   0x448
#define EPROCESS_UNIQUE_PID     0x440

static UINT32 HvAutoDiscoverCr3Offset(UINT64 guestCr3, UINT64 currentEproc) {
    if (g_Hv.DirectoryTableOffset != 0) {
        // Verify existing offset against current EPROCESS
        UINT64 cr3Pa = TranslateGuestVa(guestCr3, currentEproc + g_Hv.DirectoryTableOffset);
        if (cr3Pa != (UINT64)-1) {
            UINT64 cr3Val = 0;
            if (ReadPhysU64Safe(cr3Pa, &cr3Val) && (cr3Val & ~0xFFFULL) == (guestCr3 & ~0xFFFULL)) {
                return g_Hv.DirectoryTableOffset;
            }
        }
    }

    // Scan candidate 8-byte aligned offsets in [0x18, 0x80]
    for (UINT32 off = 0x18; off <= 0x80; off += 8) {
        UINT64 cr3Pa = TranslateGuestVa(guestCr3, currentEproc + off);
        if (cr3Pa == (UINT64)-1) continue;
        UINT64 cr3Val = 0;
        if (ReadPhysU64Safe(cr3Pa, &cr3Val) && (cr3Val & ~0xFFFULL) == (guestCr3 & ~0xFFFULL)) {
            g_Hv.DirectoryTableOffset = off;
            return off;
        }
    }

    if (g_Hv.DirectoryTableOffset == 0) {
        g_Hv.DirectoryTableOffset = 0x28; // fallback
    }
    return g_Hv.DirectoryTableOffset;
}

static UINT64 HcGetProcessCr3(UINT64 targetPid) {
    // Use the current guest's CR3 to walk the process list
    SIZE_T guestCr3 = 0;
    __vmx_vmread(VMCS_GUEST_CR3, &guestCr3);
    if (guestCr3 == 0 || guestCr3 == (SIZE_T)-1) return (UINT64)-1;

    // Read GS base to find KPCR → CurrentThread → Process (current EPROCESS)
    SIZE_T gsBase = 0;
    __vmx_vmread(VMCS_GUEST_GS_BASE, &gsBase);
    if (gsBase < 0x100000) return (UINT64)-1;

    // KPCR + 0x180 = KPRCB, KPRCB + 0x008 = CurrentThread (KTHREAD*)
    UINT64 kthreadPa = TranslateGuestVa((UINT64)guestCr3, (UINT64)gsBase + 0x188);
    if (kthreadPa == (UINT64)-1) return (UINT64)-1;
    UINT64 kthread;
    if (!ReadPhysU64Safe(kthreadPa, &kthread)) return (UINT64)-1;
    if (kthread < 0x100000) return (UINT64)-1;

    // KTHREAD + 0x220 = Process (EPROCESS*)
    UINT64 eprocPa = TranslateGuestVa((UINT64)guestCr3, kthread + 0x220);
    if (eprocPa == (UINT64)-1) return (UINT64)-1;
    UINT64 startEproc;
    if (!ReadPhysU64Safe(eprocPa, &startEproc)) return (UINT64)-1;
    if (startEproc < 0x100000) return (UINT64)-1;

    // Auto-discover / verify DirectoryTableBase offset against the calling process
    UINT32 cr3Off = HvAutoDiscoverCr3Offset((UINT64)guestCr3, startEproc);

    // Walk ActiveProcessLinks list
    UINT64 current = startEproc;
    for (UINT32 attempt = 0; attempt < 4096; attempt++) {
        // Read PID
        UINT64 pidPa = TranslateGuestVa((UINT64)guestCr3,
                                         current + EPROCESS_UNIQUE_PID);
        if (pidPa == (UINT64)-1) break;
        UINT64 pid;
        if (!ReadPhysU64Safe(pidPa, &pid)) break;

        if (pid == targetPid) {
            UINT64 cr3Pa = TranslateGuestVa((UINT64)guestCr3, current + cr3Off);
            if (cr3Pa == (UINT64)-1) return (UINT64)-1;
            UINT64 cr3;
            if (!ReadPhysU64Safe(cr3Pa, &cr3)) return (UINT64)-1;
            if (cr3 == 0 || cr3 == (UINT64)-1) return (UINT64)-1;
            return cr3;
        }

        // Follow Flink
        UINT64 linkPa = TranslateGuestVa((UINT64)guestCr3,
                                          current + EPROCESS_ACTIVE_LINKS);
        if (linkPa == (UINT64)-1) break;
        UINT64 flink;
        if (!ReadPhysU64Safe(linkPa, &flink)) break;
        if (flink < 0x100000) break;

        current = flink - EPROCESS_ACTIVE_LINKS;
        if (current == startEproc) break;
    }

    return (UINT64)-1;
}

// ── Hypercall: Get Process Token ────────────────────────────────────────────
// Walks the EPROCESS list by PID and reads the Token field at +0x4B8.
// Returns the raw EX_FAST_REF token value (bottom 4 bits are ref count).

static UINT64 HcGetToken(UINT64 targetPid) {
    SIZE_T guestCr3 = 0;
    __vmx_vmread(VMCS_GUEST_CR3, &guestCr3);
    if (guestCr3 == 0 || guestCr3 == (SIZE_T)-1) return (UINT64)-1;

    SIZE_T gsBase = 0;
    __vmx_vmread(VMCS_GUEST_GS_BASE, &gsBase);
    if (gsBase < 0x100000) return (UINT64)-1;

    UINT64 kthreadPa = TranslateGuestVa((UINT64)guestCr3, (UINT64)gsBase + 0x188);
    if (kthreadPa == (UINT64)-1) return (UINT64)-1;
    UINT64 kthread;
    if (!ReadPhysU64Safe(kthreadPa, &kthread)) return (UINT64)-1;
    if (kthread < 0x100000) return (UINT64)-1;

    UINT64 eprocPa = TranslateGuestVa((UINT64)guestCr3, kthread + 0x220);
    if (eprocPa == (UINT64)-1) return (UINT64)-1;
    UINT64 startEproc;
    if (!ReadPhysU64Safe(eprocPa, &startEproc)) return (UINT64)-1;
    if (startEproc < 0x100000) return (UINT64)-1;

    UINT64 current = startEproc;
    for (UINT32 attempt = 0; attempt < 4096; attempt++) {
        UINT64 pidPa = TranslateGuestVa((UINT64)guestCr3,
                                         current + EPROCESS_UNIQUE_PID);
        if (pidPa == (UINT64)-1) break;
        UINT64 pid;
        if (!ReadPhysU64Safe(pidPa, &pid)) break;

        if (pid == targetPid) {
            UINT64 tokenPa = TranslateGuestVa((UINT64)guestCr3,
                                               current + EPROCESS_TOKEN_OFFSET);
            if (tokenPa == (UINT64)-1) return (UINT64)-1;
            UINT64 token;
            if (!ReadPhysU64Safe(tokenPa, &token)) return (UINT64)-1;
            return token;
        }

        UINT64 linkPa = TranslateGuestVa((UINT64)guestCr3,
                                          current + EPROCESS_ACTIVE_LINKS);
        if (linkPa == (UINT64)-1) break;
        UINT64 flink;
        if (!ReadPhysU64Safe(linkPa, &flink)) break;
        if (flink < 0x100000) break;

        current = flink - EPROCESS_ACTIVE_LINKS;
        if (current == startEproc) break;
    }

    return (UINT64)-1;
}

// ── Hypercall: EPT stealth hook ─────────────────────────────────────────────
// Installs a split-view EPT hook: shadow page (X-only) has the hooked code,
// original page (RW, no X) is shown on reads. EPT violation + MTF handles
// the transition.

static UINT64 HcEptHook(UINT64 targetGva, UINT64 hookBytesVa, UINT64 hookLen) {
    if (hookLen == 0 || hookLen > 256) return HV_STATUS_INVALID_PARAM;

    SIZE_T guestCr3 = 0;
    __vmx_vmread(VMCS_GUEST_CR3, &guestCr3);
    UINT64 cr3 = (UINT64)guestCr3;

    UINT64 targetGpa = TranslateGuestVa(cr3, targetGva);
    if (targetGpa == (UINT64)-1) return HV_STATUS_INVALID_PARAM;

    UINT8 hookBuf[256];
    for (UINT32 i = 0; i < hookLen; i++) {
        UINT64 bytePa = TranslateGuestVa(cr3, hookBytesVa + i);
        if (bytePa == (UINT64)-1) return HV_STATUS_INVALID_PARAM;
        UINT64 limit = (UINT64)g_Hv.HostPml4Units << 39;
        if (bytePa >= limit) return HV_STATUS_INVALID_PARAM;
        hookBuf[i] = *(volatile UINT8 *)(UINTN)bytePa;
    }

    NTSTATUS ns = HvEptInstallHook(&g_Hv.Ept, targetGpa, hookBuf, (UINT32)hookLen);
    if (!NT_SUCCESS(ns)) return HV_STATUS_INVALID_PARAM;
    return HV_STATUS_SUCCESS;
}

static UINT64 HcEptUnhook(UINT64 targetGva) {
    SIZE_T guestCr3 = 0;
    __vmx_vmread(VMCS_GUEST_CR3, &guestCr3);

    UINT64 targetGpa = TranslateGuestVa((UINT64)guestCr3, targetGva);
    if (targetGpa == (UINT64)-1) return HV_STATUS_INVALID_PARAM;

    NTSTATUS ns = HvEptRemoveHook(&g_Hv.Ept, targetGpa);
    if (!NT_SUCCESS(ns)) return HV_STATUS_INVALID_PARAM;
    return HV_STATUS_SUCCESS;
}

// ── Accessors for the shared copy loop in hv_copy.h ─────────────────────────
//
// HvCopyPhysical owns the page chunking; these supply the tree-specific memory
// access: the user VA is translated through the guest page tables, and a
// physical range is dereferenced through the identity map.

static UINT64 HvTranslateUserCtx(UINT64 va, BOOLEAN write, PVOID ctx) {
    return TranslateUserPage(*(UINT64 *)ctx, va, write);
}

static HV_COPY_STATUS HvMoveIdentity(UINT64 dstPa, UINT64 srcPa, UINT64 size,
                                     PVOID ctx) {
    UNREFERENCED_PARAMETER(ctx);
    RtlCopyMemory(PhysToVirt(dstPa), PhysToVirt(srcPa), (SIZE_T)size);
    return HvCopyOk;
}

// ── Hypervisor-page guard ───────────────────────────────────────────────────
// Linear scan of the hidden-page array. The array is zeroed after VMLAUNCH
// HiddenPages[] is intentionally preserved after launch (see Step 13 in
// hv_efi_main.c): this check is live on every physical hypercall, a second
// line of defence behind the EPT decoy mappings.
static BOOLEAN HvEfiIsHypervisorPage(UINT64 gpa) {
    UINT64 page = gpa & ~0xFFFULL;
    for (UINT32 i = 0; i < g_Hv.HiddenPageCount; i++) {
        if (g_Hv.HiddenPages[i] == page)
            return TRUE;
    }
    return FALSE;
}

// Every page of [gpa, gpa+size) must be EPT-mapped RAM and none may be a
// hypervisor-owned page. A single-page check is insufficient on two counts:
// the range can straddle a 4K boundary (size up to 4096), and HvEptLookup4K
// returns NULL for the 2MB large pages backing nearly all RAM, so it rejected
// legitimate reads outright while pretending to validate. HvValidateCopyU64
// already established 1 <= size <= PAGE_SIZE with no wraparound, so the range
// covers at most two pages.
// Every page of [gpa, gpa+size) must be EPT-mapped RAM and none may be a
// hypervisor-owned page. See the WDK HvValidatePhysRange for the full
// exhaustiveness and race-freedom argument; the EFI tree provides the same
// guarantees via HvEfiIsHypervisorPage (hidden list) and HvEptIsRamPage
// (MTRR-validated WB check). The validation and the copy run in the same
// VM-exit handler, in VMX root, with interrupts disabled — the check-then-use
// window is closed.
static UINT64 HvValidatePhysRange(UINT64 gpa, UINT64 size) {
    UINT64 first = gpa & ~0xFFFULL;
    UINT64 last  = (gpa + size - 1) & ~0xFFFULL;
    for (UINT64 p = first; ; p += 0x1000) {
        if (HvEfiIsHypervisorPage(p))
            return HV_STATUS_ACCESS_DENIED;
        if (!HvEptIsRamPage(&g_Hv.Ept, p))
            return HV_STATUS_INVALID_PARAM;
        if (p == last) break;
    }
    return HV_STATUS_SUCCESS;
}

// ── Hypercall: Read Physical Memory ─────────────────────────────────────────
// VALIDATION:
//   p1 (srcPhysAddr): HvValidateCopyU64 (size in [1,4096], no wraparound);
//                     HvValidatePhysRange — every 4K page of the range must be
//                     EPT-mapped WB RAM (large-page aware) and none may be a
//                     hypervisor hidden page.
//   p2 (guestDstVa):  user-space VA; HvTranslateUserCtx verifies U/S=1.
//   p3 (size):        capped at 4096 by HvValidateCopyU64; no overflow.
// Copies from a guest physical address into the caller's user buffer, one page
// at a time: a translation covers a single page, so a range that straddles a
// boundary is walked rather than rejected.

static UINT64 HcReadPhysical(UINT64 srcPhysAddr, UINT64 guestDstVa, UINT64 size) {
    UINT64 valid = HvValidateCopyU64(srcPhysAddr, guestDstVa, size);
    if (valid != HV_STATUS_SUCCESS) return valid;
    valid = HvValidatePhysRange(srcPhysAddr, size);
    if (valid != HV_STATUS_SUCCESS) return valid;

    SIZE_T guestCr3 = 0;
    __vmx_vmread(VMCS_GUEST_CR3, &guestCr3);
    UINT64 cr3 = (UINT64)guestCr3;

    // Read direction: the physical range is the source, the caller's buffer is
    // the (writable) destination.
    return HvCopyStatusToHvStatus(HvCopyPhysical(HvTranslateUserCtx, HvMoveIdentity,
                                                 &cr3, srcPhysAddr, guestDstVa,
                                                 size, TRUE));
}

// ── Hypercall: Write Physical Memory ────────────────────────────────────────
// VALIDATION:
//   p1 (dstPhysAddr): HvValidateCopyU64 (size in [1,4096], no wraparound);
//                     HvValidatePhysRange — every 4K page of the range must be
//                     EPT-mapped WB RAM (large-page aware) and none may be a
//                     hypervisor hidden page.
//   p2 (guestSrcVa):  user-space VA; HvTranslateUserCtx verifies U/S=1.
//   p3 (size):        capped at 4096 by HvValidateCopyU64; no overflow.

static UINT64 HcWritePhysical(UINT64 dstPhysAddr, UINT64 guestSrcVa, UINT64 size) {
    UINT64 valid = HvValidateCopyU64(dstPhysAddr, guestSrcVa, size);
    if (valid != HV_STATUS_SUCCESS) return valid;
    valid = HvValidatePhysRange(dstPhysAddr, size);
    if (valid != HV_STATUS_SUCCESS) return valid;

    SIZE_T guestCr3 = 0;
    __vmx_vmread(VMCS_GUEST_CR3, &guestCr3);
    UINT64 cr3 = (UINT64)guestCr3;

    // Write direction: the caller's buffer is the (read-only) source, the
    // physical range is the destination.
    return HvCopyStatusToHvStatus(HvCopyPhysical(HvTranslateUserCtx, HvMoveIdentity,
                                                 &cr3, dstPhysAddr, guestSrcVa,
                                                 size, FALSE));
}

// ── Secrets page accessor ───────────────────────────────────────────────────

PHV_SECRETS GetSecretsPage(void) {
    if (g_Hv.PointersObfuscated) {
        return (PHV_SECRETS)((UINT64)g_Hv.SecretsPageVa ^ g_Hv.CleanupKey);
    }
    return (PHV_SECRETS)g_Hv.SecretsPageVa;
}

UINT64 HvGetSessionMagic(void) {
    PHV_SECRETS s = GetSecretsPage();
    return s ? s->SessionMagic : 0;
}

UINT64 HvComputeUnloadMac(void) {
    PHV_SECRETS s = GetSecretsPage();
    return s ? s->UnloadMac : 0;
}

// ── Hypercall: Scatter-gather read ─────────────────────────────────────────
// p1 = guest VA of HV_SCATTER_REQUEST; p2 = guest VA of flat output buffer;
// p3 = entry count (must match req->Count). All entries validated before any
// copy (fail-closed). Uses identity map for struct read — no MapPhys needed.

static UINT64 HcReadScatter(PVCPU vcpu, UINT64 reqVa, UINT64 outBufVa,
                             UINT64 count) {
    UNREFERENCED_PARAMETER(vcpu);
    UINT32 i;
    if (count == 0 || count > HV_SCATTER_MAX_DESCS)
        return HV_STATUS_INVALID_PARAM;

    SIZE_T guestCr3Raw = 0;
    __vmx_vmread(VMCS_GUEST_CR3, &guestCr3Raw);
    UINT64 callerCr3 = (UINT64)guestCr3Raw;

    UINT64 reqGpa = TranslateUserPage(callerCr3, reqVa, FALSE);
    if (reqGpa == (UINT64)-1)
        return HV_STATUS_INVALID_PARAM;

    // Struct must not straddle a page boundary.
    if ((reqGpa >> 12) != ((reqGpa + sizeof(HV_SCATTER_REQUEST) - 1) >> 12))
        return HV_STATUS_INVALID_PARAM;

    // Verify the struct page is RAM (not a hypervisor page, not device memory).
    if (HvEfiIsHypervisorPage(reqGpa & ~0xFFFULL) ||
        !HvEptIsRamPage(&g_Hv.Ept, reqGpa & ~0xFFFULL))
        return HV_STATUS_INVALID_PARAM;

    // Identity map: PA == VA in VMX root, so dereference directly.
    HV_SCATTER_REQUEST local_req;
    RtlCopyMemory(&local_req, PhysToVirt(reqGpa), sizeof(HV_SCATTER_REQUEST));

    UINT64 valid = HvScatterValidate(&local_req, (UINT32)count);
    if (valid != HV_STATUS_SUCCESS)
        return valid;

    // Validate ALL entries before copying any (fail-closed).
    for (i = 0; i < local_req.Count; i++) {
        valid = HvValidatePhysRange(local_req.Descs[i].Gpa,
                                    local_req.Descs[i].Size);
        if (valid != HV_STATUS_SUCCESS)
            return valid;
    }

    // All clear — perform the copies.
    for (i = 0; i < local_req.Count; i++) {
        UINT64 outSlotVa = outBufVa + (UINT64)i * PAGE_SIZE;
        HV_COPY_STATUS cs = HvCopyPhysical(HvTranslateUserCtx, HvMoveIdentity,
                                           &callerCr3,
                                           local_req.Descs[i].Gpa,
                                           outSlotVa,
                                           local_req.Descs[i].Size,
                                           TRUE);
        if (cs != HvCopyOk)
            return HvCopyStatusToHvStatus(cs);
    }
    return HV_STATUS_SUCCESS;
}

// ── Hypercall: Read Virtual Memory (combined operation) ─────────────────────
// One-shot read from a target process's virtual address space into the
// caller's user buffer. Replaces the three-VMCALL roundtrip pattern
// (GET_CR3 → TRANSLATE → READ_PHYS) with a single authenticated call.
//   p1 = pid | (size << 32)  — low 32 = target PID (0 = caller's CR3),
//                              high 32 = byte count (1..PAGE_SIZE)
//   p2 = source virtual address in the target process
//   p3 = destination user VA in the caller's address space

static UINT64 HcReadVirt(UINT64 pidAndSize, UINT64 srcVa, UINT64 dstUserVa) {
    UINT32 targetPid = (UINT32)(pidAndSize & 0xFFFFFFFF);
    UINT64 size = pidAndSize >> 32;
    if (size == 0 || size > PAGE_SIZE) return HV_STATUS_INVALID_PARAM;
    if (srcVa == 0) return HV_STATUS_INVALID_PARAM;

    SIZE_T callerCr3Raw = 0;
    __vmx_vmread(VMCS_GUEST_CR3, &callerCr3Raw);
    UINT64 callerCr3 = (UINT64)callerCr3Raw;

    UINT64 targetCr3;
    if (targetPid == 0) {
        targetCr3 = callerCr3;
    } else {
        targetCr3 = HcGetProcessCr3(targetPid);
        if (targetCr3 == (UINT64)-1) return HV_STATUS_ACCESS_DENIED;
    }

    UINT64 remaining = size;
    UINT64 srcCur = srcVa;
    UINT64 dstCur = dstUserVa;

    while (remaining > 0) {
        UINT64 pageOff = srcCur & 0xFFF;
        UINT64 chunk = PAGE_SIZE - pageOff;
        if (chunk > remaining) chunk = remaining;

        UINT64 srcPa = TranslateGuestVa(targetCr3, srcCur);
        if (srcPa == (UINT64)-1) return HV_STATUS_ACCESS_DENIED;

        UINT64 valid = HvValidatePhysRange(srcPa, chunk);
        if (valid != HV_STATUS_SUCCESS) return valid;

        HV_COPY_STATUS cs = HvCopyPhysical(HvTranslateUserCtx, HvMoveIdentity,
                                           &callerCr3, srcPa, dstCur,
                                           chunk, TRUE);
        if (cs != HvCopyOk) return HvCopyStatusToHvStatus(cs);

        srcCur += chunk;
        dstCur += chunk;
        remaining -= chunk;
    }
    return HV_STATUS_SUCCESS;
}

// ── Hypercall: Write Virtual Memory (combined operation) ────────────────────
// One-shot write into a target process's virtual address space from the
// caller's user buffer.
//   p1 = pid | (size << 32)  — low 32 = target PID (0 = caller's CR3),
//                              high 32 = byte count (1..PAGE_SIZE)
//   p2 = destination virtual address in the target process
//   p3 = source user VA in the caller's address space

static UINT64 HcWriteVirt(UINT64 pidAndSize, UINT64 dstVa, UINT64 srcUserVa) {
    UINT32 targetPid = (UINT32)(pidAndSize & 0xFFFFFFFF);
    UINT64 size = pidAndSize >> 32;
    if (size == 0 || size > PAGE_SIZE) return HV_STATUS_INVALID_PARAM;
    if (dstVa == 0) return HV_STATUS_INVALID_PARAM;

    SIZE_T callerCr3Raw = 0;
    __vmx_vmread(VMCS_GUEST_CR3, &callerCr3Raw);
    UINT64 callerCr3 = (UINT64)callerCr3Raw;

    UINT64 targetCr3;
    if (targetPid == 0) {
        targetCr3 = callerCr3;
    } else {
        targetCr3 = HcGetProcessCr3(targetPid);
        if (targetCr3 == (UINT64)-1) return HV_STATUS_ACCESS_DENIED;
    }

    UINT64 remaining = size;
    UINT64 dstCur = dstVa;
    UINT64 srcCur = srcUserVa;

    while (remaining > 0) {
        UINT64 pageOff = dstCur & 0xFFF;
        UINT64 chunk = PAGE_SIZE - pageOff;
        if (chunk > remaining) chunk = remaining;

        UINT64 dstPa = TranslateGuestVa(targetCr3, dstCur);
        if (dstPa == (UINT64)-1) return HV_STATUS_ACCESS_DENIED;

        UINT64 valid = HvValidatePhysRange(dstPa, chunk);
        if (valid != HV_STATUS_SUCCESS) return valid;

        HV_COPY_STATUS cs = HvCopyPhysical(HvTranslateUserCtx, HvMoveIdentity,
                                           &callerCr3, dstPa, srcCur,
                                           chunk, FALSE);
        if (cs != HvCopyOk) return HvCopyStatusToHvStatus(cs);

        dstCur += chunk;
        srcCur += chunk;
        remaining -= chunk;
    }
    return HV_STATUS_SUCCESS;
}

// ── Hypercall: Get Kernel Base ──────────────────────────────────────────────
// Walks the guest's IDT entry 14 (#PF) to find an ISR inside ntoskrnl.exe,
// then pages backwards to find the PE header (MZ signature). Returns the
// guest virtual address of the kernel image base, or -1 on failure.

static UINT64 HcGetKernelBase(void) {
    SIZE_T guestCr3Raw = 0;
    __vmx_vmread(VMCS_GUEST_CR3, &guestCr3Raw);
    UINT64 guestCr3 = (UINT64)guestCr3Raw;
    if (guestCr3 == 0) return (UINT64)-1;

    SIZE_T idtBase = 0;
    __vmx_vmread(VMCS_GUEST_IDTR_BASE, &idtBase);
    if (idtBase < 0xFFFF800000000000ULL) return (UINT64)-1;

    // Read IDT entry 14 (#PF handler — always in ntoskrnl)
    UINT64 idtEntryVa = (UINT64)idtBase + 14 * 16;
    UINT64 idtEntryPa = TranslateGuestVa(guestCr3, idtEntryVa);
    if (idtEntryPa == (UINT64)-1) return (UINT64)-1;

    // IDT gate descriptor: offset[15:0] at +0, offset[31:16] at +6, offset[63:32] at +8
    UINT64 hostMapBytes = (UINT64)g_Hv.HostPml4Units << 39;
    if (idtEntryPa + 12 >= hostMapBytes) return (UINT64)-1;

    UINT8 *gate = (UINT8 *)PhysToVirt(idtEntryPa);
    UINT64 isrVa = (UINT64)(*(UINT16 *)(gate + 0))
                 | ((UINT64)(*(UINT16 *)(gate + 6)) << 16)
                 | ((UINT64)(*(UINT32 *)(gate + 8)) << 32);

    if (isrVa < 0xFFFF800000000000ULL) return (UINT64)-1;

    // Page backwards from the ISR to find the PE header (MZ signature).
    // ntoskrnl is page-aligned; search up to 32 MB back.
    UINT64 searchBase = isrVa & ~0xFFFULL;
    for (UINT64 off = 0; off < 0x2000000ULL; off += PAGE_SIZE) {
        UINT64 candidateVa = searchBase - off;
        if (candidateVa < 0xFFFF800000000000ULL) break;

        UINT64 candidatePa = TranslateGuestVa(guestCr3, candidateVa);
        if (candidatePa == (UINT64)-1) continue;
        if (candidatePa >= hostMapBytes) continue;

        UINT16 sig = *(UINT16 *)PhysToVirt(candidatePa);
        if (sig == 0x5A4D) { // 'MZ'
            return candidateVa;
        }
    }
    return (UINT64)-1;
}

// ── Hypercall dispatch ──────────────────────────────────────────────────────

UINT64 HvHypercallDispatch(PVCPU vcpu, UINT64 magic, UINT64 id, UINT64 p1,
                            UINT64 p2, UINT64 callerMac, UINT64 p3Real) {
    UNREFERENCED_PARAMETER(vcpu);

    if (g_Mailbox != NULL && HvMailboxValid(g_Mailbox)) {
        g_Mailbox->HypercallCount++;
        g_Mailbox->LastHypercallMagicLow  = (UINT32)magic;
        g_Mailbox->LastHypercallMagicHigh = (UINT32)(magic >> 32);
        g_Mailbox->LastHypercallId        = (UINT32)id;
    }

    // Dark mode: HvEnterDarkMode() was called (e.g. bring-up failure). Silently
    // reject every call so the hypervisor is invisible to the launcher.
    //
    // UNLOAD is exempt: teardown issues it internally — the partial-rollback
    // path in HvSmpVirtualizeAllProcessors runs HvSmpDevirtualizeAllProcessors
    // AFTER HvEnterDarkMode — and refusing it would inject #UD into the
    // teardown CPU instead of devirtualizing, freezing DXE. UNLOAD stays fully
    // authenticated (session magic + unload MAC via HvAuthUnload below), so the
    // exemption opens nothing to an unauthenticated caller.
    if ((UINT32)id != HV_HYPERCALL_UNLOAD && g_Hv.State == HV_STATE_DARK) {
        if (g_Mailbox != NULL && HvMailboxValid(g_Mailbox)) g_Mailbox->LastHypercallStatus = 0xFFFFFFFEu;
        return HV_STATUS_NOT_OURS;
    }

    PHV_SECRETS secrets = GetSecretsPage();

    // DETECT is the only unauthenticated call; the caller proves ticket
    // possession by presenting HvBootMagic(ticket). There is no fixed magic.
    // Compare the low 32 bits exactly as the WDK build does, so both trees
    // dispatch the same code for the same full 64-bit id.
    if ((UINT32)id == HV_HYPERCALL_DETECT) {
        if (HvAuthDetect(secrets, magic) != HV_STATUS_SUCCESS) {
            if (g_Mailbox != NULL && HvMailboxValid(g_Mailbox)) g_Mailbox->LastHypercallStatus = 0xFFFFFFFEu;
            return HV_STATUS_NOT_OURS;
        }
        if (g_Mailbox != NULL && HvMailboxValid(g_Mailbox)) g_Mailbox->LastHypercallStatus = (UINT32)g_Hv.Nonce;
        return g_Hv.Nonce;
    }

    // UNLOAD uses the pre-computed MAC and is exempt from the sequence counter.
    if ((UINT32)id == HV_HYPERCALL_UNLOAD) {
        UINT64 res = HvAuthUnload(secrets, g_Hv.Running, magic, callerMac);
        if (g_Mailbox != NULL && HvMailboxValid(g_Mailbox)) g_Mailbox->LastHypercallStatus = (UINT32)res;
        return res;
    }

    // All other calls: verify session magic and MAC, then advance the sequence
    // (same code as the WDK build, in hv_auth.h).
    UINT64 auth = HvAuthCall(secrets, magic, id, p1, p2, p3Real, callerMac);
    if (auth != HV_STATUS_SUCCESS) {
        if (g_Mailbox != NULL && HvMailboxValid(g_Mailbox)) g_Mailbox->LastHypercallStatus = (UINT32)auth;
        return auth;
    }

    // Past authentication: reject a code this build does not implement.
    if (!HvHypercallCodeKnown(id)) {
        if (g_Mailbox != NULL && HvMailboxValid(g_Mailbox)) g_Mailbox->LastHypercallStatus = (UINT32)HV_STATUS_INVALID_CALL;
        return HV_STATUS_INVALID_CALL;
    }

    UINT64 result = HV_STATUS_INVALID_CALL;

    // Dispatch
    switch ((UINT32)id) {
        case HV_HYPERCALL_READ_PHYS:
            result = HcReadPhysical(p1, p2, p3Real);
            break;

        case HV_HYPERCALL_WRITE_PHYS:
            result = HcWritePhysical(p1, p2, p3Real);
            break;

        case HV_HYPERCALL_TRANSLATE:
            result = TranslateGuestVa(p1, p2);
            break;

        case HV_HYPERCALL_GET_CR3:
            result = HcGetProcessCr3(p1);
            break;

        case HV_HYPERCALL_QUERY_STATUS: {
            UINT64 st = 0;
            st |= (g_Hv.VcpuCount & HV_STATUS_CPU_MASK);
            if (g_Hv.Running) st |= HV_STATUS_RUNNING_BIT;
            st |= ((UINT64)(UINT32)g_Hv.DarkReason << HV_STATUS_DARK_REASON_SHIFT);
            st |= ((UINT64)(UINT32)g_Hv.TscPerQpc256 << HV_STATUS_TSC_SHIFT);
            result = st;
            break;
        }

        case HV_HYPERCALL_INVALIDATE_EPT:
            HvEptInvalidate();
            result = HV_STATUS_SUCCESS;
            break;

        case HV_HYPERCALL_SELFTEST:
            result = HV_STATUS_SUCCESS;
            break;

        case HV_HYPERCALL_SET_CR3_OFFSET:
            // Re-learn KPROCESS.DirectoryTableBase for a guest build that
            // differs from the one detected at load. Mirrored in HvDrv.
            if (!HvCr3OffsetValid(p1)) {
                result = HV_STATUS_INVALID_PARAM;
            } else {
                g_Hv.DirectoryTableOffset = (UINT32)p1;
                result = HV_STATUS_SUCCESS;
            }
            break;

        case HV_HYPERCALL_READ_SCATTER:
            result = HcReadScatter(vcpu, p1, p2, p3Real);
            break;

        case HV_HYPERCALL_READ_VIRT:
            result = HcReadVirt(p1, p2, p3Real);
            break;

        case HV_HYPERCALL_WRITE_VIRT:
            result = HcWriteVirt(p1, p2, p3Real);
            break;

        case HV_HYPERCALL_GET_KERNEL_BASE:
            result = HcGetKernelBase();
            break;

        case HV_HYPERCALL_GET_TOKEN:
            result = HcGetToken(p1);
            break;

        case HV_HYPERCALL_EPT_HOOK:
            result = HcEptHook(p1, p2, p3Real);
            break;

        case HV_HYPERCALL_EPT_UNHOOK:
            result = HcEptUnhook(p1);
            break;

        case HV_HYPERCALL_REGISTER_DEVIRT_VA: {
            // Cooperative post-EBS devirt (Open Issue 2 true path).
            //
            // A kernel-mode driver that wants a working post-EBS unload
            // tells us a GUEST kernel VA that maps the same physical page
            // as HvAsmSwitchToGuest. We record it; the exit handler, when
            // it decides to really devirt post-EBS, uses that VA for the
            // instruction fetch that follows `mov cr3`. The fail-safe
            // (inject #UD) remains for callers that never register one.
            //
            // Validation: p1 must be a canonical kernel VA (bit 47 → 63
            // all one) and map, through the current guest CR3, to the
            // same physical page as HvAsmSwitchToGuest. If the walk
            // confirms both, record; otherwise reject and leave the
            // fail-safe in place.
            UINT64 kernelVa = p1;
            SIZE_T guestCr3Raw = 0;
            __vmx_vmread(VMCS_GUEST_CR3, &guestCr3Raw);
            UINT64 callerCr3 = (UINT64)guestCr3Raw;

            // Canonical kernel-half check: top 17 bits must be 1.
            if (((INT64)kernelVa >> 47) != -1) {
                result = HV_STATUS_INVALID_PARAM;
                break;
            }

            UINT64 stubPa = (UINT64)(UINTN)&HvAsmSwitchToGuest & ~0xFFFULL;
            UINT64 mappedPa = HvPtWalk(ReadPteAtPa, NULL,
                                       callerCr3, kernelVa, 0);
            if (mappedPa == HV_PA_INVALID ||
                (mappedPa & ~0xFFFULL) != stubPa) {
                result = HV_STATUS_INVALID_PARAM;
                break;
            }

            // Record the kernel VA aligned to the stub's exact entry
            // address: p1 is a page-base, and the stub lives at some
            // offset inside that page, so we add the known offset so the
            // exit handler can jump directly to the function entry. The
            // asm shutdown path reads this through external linkage.
            extern UINT64 g_HvDevirtKernelStubVa;
            g_HvDevirtKernelStubVa = (kernelVa & ~0xFFFULL) |
                ((UINT64)(UINTN)&HvAsmSwitchToGuest & 0xFFFULL);
            result = HV_STATUS_SUCCESS;
        } break;

        case HV_HYPERCALL_QUERY_EXIT_TELEMETRY: {
            // p1 = user buffer VA, p2 = max records (clamped to 64)
            UINT64 userBufVa = p1;
            UINT32 maxRecords = (UINT32)p2;
            if (userBufVa == 0 || userBufVa > (UINT64)0x00007FFFFFFFFFFF) {
                result = HV_STATUS_INVALID_PARAM;
            } else {
                if (maxRecords > 64) maxRecords = 64;
                SIZE_T guestCr3Raw = 0;
                __vmx_vmread(VMCS_GUEST_CR3, &guestCr3Raw);
                UINT64 callerCr3 = (UINT64)guestCr3Raw;
                UINT32 count = 0;
                LONG64 totalExits = g_Hv.ExitLogIndex;
                UINT32 avail = (totalExits < 64) ? (UINT32)totalExits : 64;
                if (maxRecords > avail) maxRecords = avail;

                for (UINT32 i = 0; i < maxRecords; i++) {
                    UINT32 slot = (UINT32)((totalExits - maxRecords + i) & 63);
                    HV_EXIT_RECORD rec = g_Hv.ExitLog[slot];
                    UINT64 dstVa = userBufVa + (UINT64)i * sizeof(HV_EXIT_RECORD);
                    if (HvCopyPhysical(HvTranslateUserCtx, HvMoveIdentity, &callerCr3,
                                       (UINT64)(UINTN)&rec, dstVa, sizeof(HV_EXIT_RECORD), TRUE) != HvCopyOk) {
                        break;
                    }
                    count++;
                }
                result = count;
            }
            break;
        }

        case HV_HYPERCALL_CAPABILITIES: {
            UINT32 supported = (1U << HV_HYPERCALL_DETECT)              |
                               (1U << HV_HYPERCALL_READ_PHYS)            |
                               (1U << HV_HYPERCALL_WRITE_PHYS)           |
                               (1U << HV_HYPERCALL_TRANSLATE)            |
                               (1U << HV_HYPERCALL_GET_CR3)              |
                               (1U << HV_HYPERCALL_UNLOAD)               |
                               (1U << HV_HYPERCALL_QUERY_STATUS)         |
                               (1U << HV_HYPERCALL_INVALIDATE_EPT)       |
                               (1U << HV_HYPERCALL_SELFTEST)             |
                               (1U << HV_HYPERCALL_SET_CR3_OFFSET)       |
                               (1U << HV_HYPERCALL_READ_SCATTER)         |
                               (1U << HV_HYPERCALL_CAPABILITIES)         |
                               (1U << HV_HYPERCALL_QUERY_CPID_PAD)       |
                               (1U << HV_HYPERCALL_READ_VIRT)            |
                               (1U << HV_HYPERCALL_WRITE_VIRT)           |
                               (1U << HV_HYPERCALL_GET_KERNEL_BASE)      |
                               (1U << HV_HYPERCALL_QUERY_EXIT_TELEMETRY) |
                               (1U << HV_HYPERCALL_GET_TOKEN)            |
                               (1U << HV_HYPERCALL_EPT_HOOK)             |
                               (1U << HV_HYPERCALL_EPT_UNHOOK)             |
                               (1U << HV_HYPERCALL_REGISTER_DEVIRT_VA);
            result = (UINT64)HV_ABI_VERSION | ((UINT64)supported << 16);
            break;
        }

        case HV_HYPERCALL_QUERY_CPID_PAD:
            // B1's pre-VMXON measurement, readable by an observer harness. No
            // guest pointer involved, so unlike QUERY_EXIT_COUNTS there is
            // nothing here that can fail or need a page-table walk. Mirrored in
            // HvDrv/hv_hypercall.c.
            result = HvPackCpuidPad(g_Hv.CpuidPadP50, g_Hv.CpuidPadP99,
                                    g_Hv.CpuidPadTarget, g_Hv.CpuidPadJitter);
            break;

#if DBG
        case HV_HYPERCALL_QUERY_EXIT_COUNTS: {
            // p1 = guest VA of UINT64[64] output buffer. Copies ExitCounts[] to guest.
            if (p1 == 0 || p1 > (UINT64)0x00007FFFFFFFFFFF - 63 * sizeof(UINT64)) {
                result = HV_STATUS_INVALID_PARAM;
            } else {
                SIZE_T guestCr3Raw = 0;
                __vmx_vmread(VMCS_GUEST_CR3, &guestCr3Raw);
                UINT64 callerCr3 = (UINT64)guestCr3Raw;
                for (UINT32 i = 0; i < 64; i++) {
                    UINT64 slotVa = p1 + (UINT64)i * sizeof(UINT64);
                    UINT64 val    = (UINT64)g_Hv.ExitCounts[i];
                    HvCopyPhysical(HvTranslateUserCtx, HvMoveIdentity, &callerCr3,
                                   (UINT64)(UINTN)&val, slotVa, sizeof(UINT64), TRUE);
                }
                result = HV_STATUS_SUCCESS;
            }
            break;
        }
#endif

        default:
            result = HV_STATUS_INVALID_CALL;
            break;
    }

    if (g_Mailbox != NULL && HvMailboxValid(g_Mailbox)) {
        g_Mailbox->LastHypercallStatus = (UINT32)result;
    }
    return result;
}

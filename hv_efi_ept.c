// hv_efi_ept.c - Extended Page Tables using EFI GetMemoryMap for RAM discovery.
//
// EFI equivalent of HvDrv/hv_ept.c.  Uses GetMemoryMap instead of
// MmGetPhysicalMemoryRanges, and EFI page allocation (VA == PA) throughout.
// Identity maps the low 512 GB (PML4 unit 0) plus any further 512GB units
// needed to cover RAM reported above 512GB: RAM as WB, MMIO as UC, mixed
// regions get 4KB page tables.

#include "hv_efi.h"

// ── RAM range helpers ───────────────────────────────────────────────────────
// The RAM map is collected once by HvBuildHostPageTables and shared with the host
// identity map so both cover exactly the same range. It is then NORMALISED once
// (base-sorted, overlapping and adjacent ranges merged) into ept->NormRanges[].
//
// Why normalisation is not an optimisation: the old search assumed `end` was
// monotone across base-sorted ranges, which the UEFI memory map does not
// guarantee. See the note above EptNormalizeRamRanges for the UC-RAM ->
// infinite-#PF-loop failure that assumption produced.

// RAM range helpers (Pass 94)
//
// The region predicates below used to run their own binary search over
// ept->RamRanges[] on the predicate `end > pa`. That search is only sound when
// `end` is monotone across the array, and base-sorted order does not imply that:
// a legal UEFI memory map can hold [0,16M) then [1M,2M) then [17M,18M), whose
// ends run 16M, 2M, 18M.
//
// When the search landed on the wrong index, EptRegionOverlapsRam answered FALSE
// for a region that really was RAM, the region was mapped UC instead of WB, and
// the first guest access raised an EPT violation. HvEptLookup4K returns NULL for
// a large page, so HandleEptViolation injected #PF - and a #PF cannot fix an EPT
// restriction, so the firmware handler returns, the instruction retries, and the
// machine hangs. That is the Dell brick recorded in ../hv_ept_decision.h.
//
// The fix is to normalise once (sort by base, merge overlapping and adjacent
// ranges), which makes `end` monotone and the binary search sound. The
// normalised copy lives in ept->NormRanges[]; RamRanges[] stays as the raw
// firmware map because HvEptPml4Units() and the shared host-map snapshot read it.
//
// Every query is therefore O(log n), and none of them can disagree with the
// others about which pages are RAM - which is the property that mattered.

static UINT32 EptNormalizeRamRanges(PEPT_STATE ept) {
    UINT32 i;
    UINT32 n = ept->RamRangeCount;
    if (n > HV_MAX_RAM_RANGES) n = HV_MAX_RAM_RANGES;

    for (i = 0; i < n; i++) {
        UINT64 base = (UINT64)ept->RamRanges[i].BaseAddress.QuadPart;
        UINT64 bytes = (UINT64)ept->RamRanges[i].NumberOfBytes.QuadPart;
        ept->NormRanges[i].base = base;
        ept->NormRanges[i].end = HvRangeEndOf(base, bytes);
    }
    ept->NormRangeCount = HvRangeNormalize(ept->NormRanges, n);
    return ept->NormRangeCount;
}

// Fully-RAM / non-RAM / mixed classification for one 2 MB region, and the
// per-page memory type. Both read the normalised view, so a region can never be
// called "mixed" by one and "no RAM" by the other - a disagreement between the
// two is what put a WB region behind a UC large page.
static UINT64 EptMemTypeForPa(PEPT_STATE ept, UINT64 pa) {
    UINT8 mtrrType = HvMtrrTypeForPa(&ept->Mtrr, pa);
    return HvEptMemTypeFromMtrr(mtrrType,
            (BOOLEAN)HvRangeContains(ept->NormRanges, ept->NormRangeCount, pa));
}

// ── EPT entry helpers ───────────────────────────────────────────────────────

static void EptSetLargePage(PEPT_PTE entry, UINT64 pa, UINT64 memType) {
    entry->Value = 0;
    entry->Read     = 1;
    entry->Write    = 1;
    entry->Execute  = 1;
    entry->LargePage = 1;
    entry->MemoryType = memType;
    // >> 12, NOT >> 21, and this is not a typo to be "cleaned up".
    // EPT_PTE.PhysAddr is a 40-bit field, but for a 2MB leaf the CPU
    // only reads bits 51:21 - the low 9 bits are ignored, not
    // undefined. A 2MB-aligned `pa` therefore stores a value whose low
    // 9 bits are already zero, and (PhysAddr << 12) | offset reconstructs
    // the original address for every offset in the region. Writing
    // `pa >> 21` would drop bits 20:12 and alias the region 512x lower.
    // tools/unit/ept_units_test.c pins both directions of this.
    entry->PhysAddr = pa >> 12;
}

static void EptFillIdentityPtPage(PEPT_STATE ept, PEPT_PTE pt, UINT64 regionBase) {
    for (UINT32 i = 0; i < 512; i++) {
        UINT64 pa = regionBase + (UINT64)i * PAGE_SIZE;
        pt[i].Value = 0;
        pt[i].Read    = 1;
        pt[i].Write   = 1;
        pt[i].Execute = 1;
        pt[i].MemoryType = EptMemTypeForPa(ept, pa);
        pt[i].PhysAddr = pa >> 12;
    }
}

// origPd is the PD entry a split replaced (0 for an init-time mixed region),
// so unhide can collapse the region back to its original large page.
static void EptRecordPtPage(PEPT_STATE ept, PEPT_PTE ptVa, UINT64 regionBase,
                            UINT64 origPd) {
    if (ept->SplitCount < HV_MAX_SPLIT_PAGES) {
        ept->SplitPages[ept->SplitCount]      = ptVa;
        ept->SplitRegionBase[ept->SplitCount]  = regionBase;
        ept->SplitOriginalPd[ept->SplitCount]  = origPd;
        ept->SplitCount++;
    }
}

static PEPT_PTE EptBuildMixedPtPage(PEPT_STATE ept, UINT64 regionBase) {
    PEPT_PTE pt = (PEPT_PTE)EfiAllocPagesBelow4G(1);
    if (!pt) return NULL;
    EptFillIdentityPtPage(ept, pt, regionBase);
    // origPd = 0: a mixed region was never a large page, so unhide leaves its
    // PD entry pointing at this PT page.
    EptRecordPtPage(ept, pt, regionBase, 0);
    return pt;
}

// ── RAM range collection from EFI GetMemoryMap ──────────────────────────────
// Exported so HvBuildHostPageTables can share the same snapshot and build a host
// identity map covering exactly the range the EPT covers.

NTSTATUS HvEptCollectRamRanges(PEPT_STATE ept) {
    UINTN mapSize = 0, mapKey = 0, descSize = 0;
    UINT32 descVersion = 0;

    // First call: get required buffer size
    EFI_STATUS st = gEfiBS->GetMemoryMap(&mapSize, NULL, &mapKey, &descSize, &descVersion);
    if (st != EFI_BUFFER_TOO_SMALL) return STATUS_UNSUCCESSFUL;

    mapSize += 2 * descSize;  // margin for map growth
    VOID *mapBuf = EfiAllocPool(mapSize);
    if (!mapBuf) return STATUS_INSUFFICIENT_RESOURCES;

    st = gEfiBS->GetMemoryMap(&mapSize, (EFI_MEMORY_DESCRIPTOR *)mapBuf,
                               &mapKey, &descSize, &descVersion);
    if (EFI_ERROR(st)) {
        EfiFreePool(mapBuf);
        return STATUS_UNSUCCESSFUL;
    }
    // A zero descriptor size would make the walk below (`ptr += descSize`)
    // spin forever — fail closed on broken firmware instead of hanging DXE.
    if (descSize == 0) {
        EfiFreePool(mapBuf);
        return STATUS_UNSUCCESSFUL;
    }

    ept->RamRangeCount = 0;
    UINT8 *ptr = (UINT8 *)mapBuf;
    UINT8 *end = ptr + mapSize;

    while (ptr < end) {
        EFI_MEMORY_DESCRIPTOR *desc = (EFI_MEMORY_DESCRIPTOR *)ptr;
        ptr += descSize;

        // Count conventional RAM, boot services, and runtime services memory
        // as usable RAM for EPT WB mapping.
        BOOLEAN isRam = FALSE;
        switch (desc->Type) {
            case EfiConventionalMemory:
            case EfiBootServicesCode:
            case EfiBootServicesData:
            case EfiRuntimeServicesCode:
            case EfiRuntimeServicesData:
            case EfiLoaderCode:
            case EfiLoaderData:
            case EfiACPIReclaimMemory:
                isRam = TRUE;
                break;
            default:
                break;
        }

        if (!isRam) continue;
        if (ept->RamRangeCount >= HV_MAX_RAM_RANGES) {
            EfiFreePool(mapBuf);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ept->RamRanges[ept->RamRangeCount].BaseAddress.QuadPart =
            (INT64)desc->PhysicalStart;
        ept->RamRanges[ept->RamRangeCount].NumberOfBytes.QuadPart =
            (INT64)(desc->NumberOfPages * PAGE_SIZE);
        ept->RamRangeCount++;
    }

    EfiFreePool(mapBuf);

    // Sort once so the interval predicates above stay O(log N). The memory
    // map usually arrives in ascending order already; this is the guarantee.
    ept->NormRangeCount = EptNormalizeRamRanges(ept);
    return STATUS_SUCCESS;
}

// ── EPT Initialize ──────────────────────────────────────────────────────────

NTSTATUS HvEptInitialize(PEPT_STATE ept) {
    // The RAM map is collected once, by HvBuildHostPageTables, and shared with
    // the host identity map so both cover exactly the same range. Preserve it
    // across the reset below; collect it here only if it is not present yet.
    PHYSICAL_MEMORY_RANGE ranges[HV_MAX_RAM_RANGES];
    UINT32 rangeCount = ept->RamRangeCount;
    if (rangeCount > HV_MAX_RAM_RANGES) rangeCount = 0;   // corrupt → re-collect
    if (rangeCount)
        RtlCopyMemory(ranges, ept->RamRanges,
                      (SIZE_T)rangeCount * sizeof(ranges[0]));

    RtlZeroMemory(ept, sizeof(EPT_STATE));

    if (rangeCount) {
        RtlCopyMemory(ept->RamRanges, ranges,
                      (SIZE_T)rangeCount * sizeof(ranges[0]));
        ept->RamRangeCount = rangeCount;
        // Defensive: the shared snapshot was normalised at collection, but the
        ept->NormRangeCount = EptNormalizeRamRanges(ept);
        EfiPrint("[VMX] EPT: %u RAM ranges (shared with host map)\n", rangeCount);
    } else {
        NTSTATUS ns = HvEptCollectRamRanges(ept);
        if (!NT_SUCCESS(ns)) return ns;
        EfiPrint("[VMX] EPT: %u RAM ranges collected\n", ept->RamRangeCount);
    }

    // Snapshot MTRRs for memory-type validation. EptMemTypeForPa intersects
    // this with RamRanges: MTRR non-WB wins (MMIO wins -> UC).
    HvMtrrInitialize(&ept->Mtrr);

    // Decide how many 512GB PML4 units to identity-map. Unit 0 is always
    // mapped; further units cover RAM that reports above 512GB, so an address
    // the guest has legitimately mapped resolves instead of faulting.
    UINT32 units = HvEptPml4Units(ept->RamRanges, ept->RamRangeCount);

    UINT32 gbCount = units * 512;
    ept->PdptUnitCount = units;
    ept->PdptCount = gbCount;
    ept->PdptPages = (PEPT_PTE *)EfiAllocPool((UINTN)gbCount * sizeof(PEPT_PTE));
    if (!ept->PdptPages) goto fail;

    for (UINT32 u = 0; u < units; u++) {
        PEPT_PTE pdpt = (PEPT_PTE)EfiAllocPagesBelow4G(1);
        if (!pdpt) goto fail;
        ept->PdptVa[u] = pdpt;
        ept->Pml4[u].Value = EfiVaToPA(pdpt) | EPT_RWX;

        for (UINT32 e = 0; e < 512; e++) {
            UINT32 g = u * 512 + e;   // flat 1GB index

            PEPT_PTE pd = (PEPT_PTE)EfiAllocPagesBelow4G(1);
            if (!pd) goto fail;
            ept->PdptPages[g] = pd;
            pdpt[e].Value = EfiVaToPA(pd) | EPT_RWX;

            for (UINT32 mi = 0; mi < 512; mi++) {   // 2MB index within GB
                UINT64 regionBase = ((UINT64)g << EPT_PDPT_SHIFT) |
                                    ((UINT64)mi << EPT_PD_SHIFT);

                if (HvRangeFullyCovers(ept->NormRanges, ept->NormRangeCount,
                                      regionBase, 1ULL << EPT_PD_SHIFT)) {
                    EptSetLargePage(&pd[mi], regionBase, EPT_MEMORY_TYPE_WB);
                } else if (!HvRangeOverlaps(ept->NormRanges, ept->NormRangeCount,
                                           regionBase, 1ULL << EPT_PD_SHIFT)) {
                    EptSetLargePage(&pd[mi], regionBase, EPT_MEMORY_TYPE_UC);
                } else {
                    // Mixed region: split into 4KB pages
                    PEPT_PTE pt = EptBuildMixedPtPage(ept, regionBase);
                    if (!pt) goto fail;
                    pd[mi].Value = EfiVaToPA(pt) | EPT_RWX;
                }
            }
        }
    }

    // Build EPTP: WB memory type, 4-level walk, no A/D bits
    UINT64 pml4Pa = EfiVaToPA(&ept->Pml4[0]);
    ept->EptPointer = pml4Pa | EPT_MEMORY_TYPE_WB | EPT_PAGE_WALK_LENGTH_4;

    EfiPrint("[VMX] EPT: identity mapped %u GB / %u unit(s), EPTP=0x%lx, %u splits\n",
             gbCount, units, ept->EptPointer, ept->SplitCount);

    return STATUS_SUCCESS;

fail:
    HvEptDestroy(ept);
    return STATUS_INSUFFICIENT_RESOURCES;
}

// ── EPT Destroy ─────────────────────────────────────────────────────────────

void HvEptDestroy(PEPT_STATE ept) {
    // Zero before free, mirroring HvDrv/hv_ept.c: the split PT pages and the
    // PD/PDPT pages together map every hidden physical page, and EFI-freed
    // memory is reused by the OS after boot — leave zeros behind, not the
    // layout.
    for (UINT32 i = 0; i < ept->SplitCount; i++) {
        if (ept->SplitPages[i]) {
            RtlSecureZeroMemory(ept->SplitPages[i], PAGE_SIZE);
            EfiFreePages(ept->SplitPages[i], 1);
        }
    }
    RtlSecureZeroMemory(ept->SplitRegionBase,
                        sizeof(ept->SplitRegionBase[0]) * ept->SplitCount);
    RtlSecureZeroMemory(ept->SplitOriginalPd,
                        sizeof(ept->SplitOriginalPd[0]) * ept->SplitCount);
    ept->SplitCount = 0;

    if (ept->PdptPages) {
        for (UINT32 i = 0; i < ept->PdptCount; i++) {
            if (ept->PdptPages[i]) {
                RtlSecureZeroMemory(ept->PdptPages[i], PAGE_SIZE);
                EfiFreePages(ept->PdptPages[i], 1);
            }
        }
        EfiFreePool(ept->PdptPages);
        ept->PdptPages = NULL;
    }

    for (UINT32 u = 0; u < ept->PdptUnitCount; u++) {
        if (ept->PdptVa[u]) {
            RtlSecureZeroMemory(ept->PdptVa[u], PAGE_SIZE);
            EfiFreePages(ept->PdptVa[u], 1);
            ept->PdptVa[u] = NULL;
        }
        ept->Pml4[u].Value = 0;
    }

    ept->Pml4[0].Value = 0;
    ept->PdptCount = 0;
    ept->PdptUnitCount = 0;
    ept->EptPointer = 0;
}

// ── EPT translation ─────────────────────────────────────────────────────────

BOOLEAN HvEptTranslateGpa(PEPT_STATE ept, UINT64 gpa, PUINT64 hpa) {
    UINT64 pml4i = (gpa >> EPT_PML4_SHIFT) & EPT_ENTRY_MASK;
    if (!ept->Pml4[pml4i].Read) return FALSE;

    PEPT_PTE pdpt = (PEPT_PTE)EfiPaToVa(ept->Pml4[pml4i].PhysAddr << 12);
    UINT64 pdpti = (gpa >> EPT_PDPT_SHIFT) & EPT_ENTRY_MASK;
    if (!pdpt[pdpti].Read) return FALSE;
    if (pdpt[pdpti].LargePage) {
        *hpa = (pdpt[pdpti].PhysAddr << 12) | (gpa & ((1ULL << EPT_PDPT_SHIFT) - 1));
        return TRUE;
    }

    PEPT_PTE pd = (PEPT_PTE)EfiPaToVa(pdpt[pdpti].PhysAddr << 12);
    UINT64 pdi = (gpa >> EPT_PD_SHIFT) & EPT_ENTRY_MASK;
    if (!pd[pdi].Read) return FALSE;
    if (pd[pdi].LargePage) {
        *hpa = (pd[pdi].PhysAddr << 12) | (gpa & ((1ULL << EPT_PD_SHIFT) - 1));
        return TRUE;
    }

    PEPT_PTE pt = (PEPT_PTE)EfiPaToVa(pd[pdi].PhysAddr << 12);
    UINT64 pti = (gpa >> EPT_PT_SHIFT) & EPT_ENTRY_MASK;
    if (!pt[pti].Read) return FALSE;
    *hpa = (pt[pti].PhysAddr << 12) | (gpa & (PAGE_SIZE - 1));
    return TRUE;
}

// ── EPT 4KB entry lookup ────────────────────────────────────────────────────

EPT_PTE *HvEptLookup4K(PEPT_STATE ept, UINT64 gpa) {
    UINT64 pml4i = (gpa >> EPT_PML4_SHIFT) & EPT_ENTRY_MASK;
    if (!ept->Pml4[pml4i].Read) return NULL;

    PEPT_PTE pdpt = (PEPT_PTE)EfiPaToVa(ept->Pml4[pml4i].PhysAddr << 12);
    UINT64 pdpti = (gpa >> EPT_PDPT_SHIFT) & EPT_ENTRY_MASK;
    if (!pdpt[pdpti].Read || pdpt[pdpti].LargePage) return NULL;

    PEPT_PTE pd = (PEPT_PTE)EfiPaToVa(pdpt[pdpti].PhysAddr << 12);
    UINT64 pdi = (gpa >> EPT_PD_SHIFT) & EPT_ENTRY_MASK;
    if (!pd[pdi].Read || pd[pdi].LargePage) return NULL;

    PEPT_PTE pt = (PEPT_PTE)EfiPaToVa(pd[pdi].PhysAddr << 12);
    UINT64 pti = (gpa >> EPT_PT_SHIFT) & EPT_ENTRY_MASK;
    return &pt[pti];
}

// ── Is this GPA mapped as normal RAM? ───────────────────────────────────────
// HvEptLookup4K returns NULL for large pages, which back nearly all RAM, so a
// NULL from it does NOT mean "not RAM". Walk to the leaf (1GB, 2MB, or 4K)
// and require a readable WB mapping; UC (MMIO/device) and unmapped GPAs fail.
// Large-page aware, unlike HvEptLookup4K. Callers must still reject
// hypervisor-owned pages separately: decoy-redirected hidden pages are
// readable WB mappings and pass this test by design.

BOOLEAN HvEptIsRamPage(PEPT_STATE ept, UINT64 gpa) {
    UINT64 pml4i = (gpa >> EPT_PML4_SHIFT) & EPT_ENTRY_MASK;
    if (!ept->Pml4[pml4i].Read) return FALSE;

    PEPT_PTE pdpt = (PEPT_PTE)EfiPaToVa(ept->Pml4[pml4i].PhysAddr << 12);
    UINT64 pdpti = (gpa >> EPT_PDPT_SHIFT) & EPT_ENTRY_MASK;
    if (!pdpt[pdpti].Read) return FALSE;
    if (pdpt[pdpti].LargePage)
        return pdpt[pdpti].MemoryType == EPT_MEMORY_TYPE_WB;

    PEPT_PTE pd = (PEPT_PTE)EfiPaToVa(pdpt[pdpti].PhysAddr << 12);
    UINT64 pdi = (gpa >> EPT_PD_SHIFT) & EPT_ENTRY_MASK;
    if (!pd[pdi].Read) return FALSE;
    if (pd[pdi].LargePage)
        return pd[pdi].MemoryType == EPT_MEMORY_TYPE_WB;

    PEPT_PTE pt = (PEPT_PTE)EfiPaToVa(pd[pdi].PhysAddr << 12);
    UINT64 pti = (gpa >> EPT_PT_SHIFT) & EPT_ENTRY_MASK;
    if (!pt[pti].Read) return FALSE;
    return pt[pti].MemoryType == EPT_MEMORY_TYPE_WB;
}

// ── EPT split large page ────────────────────────────────────────────────────

static NTSTATUS EptSplitLargePage(PEPT_STATE ept, PEPT_PTE pdEntry, UINT64 regionBase) {
    if (!pdEntry->LargePage) return STATUS_SUCCESS;  // already split
    if (ept->SplitCount >= HV_MAX_SPLIT_PAGES) return STATUS_INSUFFICIENT_RESOURCES;

    UINT64 origMemType = pdEntry->MemoryType;
    UINT64 origIgnorePat = pdEntry->IgnorePat;
    // Saved so unhide can collapse the region back to the exact 2MB mapping it
    // had before the split instead of leaving it split for ever.
    UINT64 origPd = pdEntry->Value;

    PEPT_PTE pt = (PEPT_PTE)EfiAllocPagesBelow4G(1);
    if (!pt) return STATUS_INSUFFICIENT_RESOURCES;

    for (UINT32 i = 0; i < 512; i++) {
        UINT64 pa = regionBase + (UINT64)i * PAGE_SIZE;
        pt[i].Value = 0;
        pt[i].Read      = 1;
        pt[i].Write     = 1;
        pt[i].Execute   = 1;
        pt[i].MemoryType = origMemType;
        pt[i].IgnorePat  = origIgnorePat;
        pt[i].PhysAddr   = pa >> 12;
    }

    EptRecordPtPage(ept, pt, regionBase, origPd);

    pdEntry->Value = 0;
    pdEntry->Read    = 1;
    pdEntry->Write   = 1;
    pdEntry->Execute = 1;
    pdEntry->PhysAddr = EfiVaToPA(pt) >> 12;
    // LargePage bit stays 0

    return STATUS_SUCCESS;
}

// ── EPT Invalidate ──────────────────────────────────────────────────────────

void HvEptInvalidate(void) {
    struct { UINT64 eptp; UINT64 gpa; } desc;
    desc.eptp = g_Hv.Ept.EptPointer;
    desc.gpa  = 0;

    if (HvAsmInvept(INVEPT_ALL_CONTEXTS, &desc) != 0) {
        struct { UINT64 vpid; UINT64 addr; } vdesc = {0, 0};
        HvAsmInvvpid(INVVPID_ALL_CONTEXTS, &vdesc);
    }
}

// ── Decoy index (RDRAND-based randomisation) ────────────────────────────────

static UINT32 NextDecoyIndex(UINT32 decoyCount) {
    return (UINT32)(HvRandomU64() % decoyCount);
}

// ── Hide single page ────────────────────────────────────────────────────────

static NTSTATUS EptHideOnePageEx(PEPT_STATE ept, UINT64 pagePA,
                                   UINT64 *decoyPas, UINT32 decoyCount,
                                   BOOLEAN allowExecute) {
    UINT64 regionBase = pagePA & ~((1ULL << EPT_PD_SHIFT) - 1);
    UINT64 pml4i = (pagePA >> EPT_PML4_SHIFT) & EPT_ENTRY_MASK;
    UINT64 pdpti = (pagePA >> EPT_PDPT_SHIFT) & EPT_ENTRY_MASK;
    UINT64 pdi   = (pagePA >> EPT_PD_SHIFT)   & EPT_ENTRY_MASK;
    UINT64 pti   = (pagePA >> EPT_PT_SHIFT)   & EPT_ENTRY_MASK;

    if (!ept->Pml4[pml4i].Read) return STATUS_INVALID_PARAMETER;

    PEPT_PTE pdpt = (PEPT_PTE)EfiPaToVa(ept->Pml4[pml4i].PhysAddr << 12);
    if (!pdpt[pdpti].Read) return STATUS_INVALID_PARAMETER;
    if (pdpt[pdpti].LargePage) return STATUS_INVALID_PARAMETER;

    PEPT_PTE pd = (PEPT_PTE)EfiPaToVa(pdpt[pdpti].PhysAddr << 12);

    if (pd[pdi].LargePage) {
        NTSTATUS ns = EptSplitLargePage(ept, &pd[pdi], regionBase);
        if (!NT_SUCCESS(ns)) return ns;
    }

    PEPT_PTE pt = (PEPT_PTE)EfiPaToVa(pd[pdi].PhysAddr << 12);
    EPT_PTE *leaf = &pt[pti];

    // Idempotent: if already redirected off identity, skip
    UINT64 identityPfn = pagePA >> 12;
    if (leaf->PhysAddr != identityPfn) return STATUS_ALREADY_COMPLETE;

    if (allowExecute) {
        // Driver's own image: must remain executable in non-root mode after
        // VMLAUNCH (the post-launch continuation runs from the image). Use
        // identity mapping with full RWX — decoy redirect would fetch decoy
        // code on instruction fetch. Data-scan hiding for the image is a
        // stealth refinement, not a boot-safety requirement.
        leaf->Value = 0;
        leaf->Read    = 1;
        leaf->Write   = 1;
        leaf->Execute = 1;
        leaf->MemoryType = EPT_MEMORY_TYPE_WB;
        leaf->PhysAddr = identityPfn;
        // No DECOY_TAG: identity mapped, not redirected.
    } else {
        UINT32 di = NextDecoyIndex(decoyCount);
        leaf->Value = 0;
        leaf->Read    = 1;
        leaf->Write   = 0;
        leaf->Execute = 0;
        leaf->MemoryType = EPT_MEMORY_TYPE_WB;
        leaf->PhysAddr = decoyPas[di] >> 12;
        leaf->Value |= EPT_DECOY_TAG;
    }

    return STATUS_SUCCESS;
}

// Wrapper for non-executable hides (existing callers).
static NTSTATUS EptHideOnePage(PEPT_STATE ept, UINT64 pagePA,
                               UINT64 *decoyPas, UINT32 decoyCount) {
    return EptHideOnePageEx(ept, pagePA, decoyPas, decoyCount, FALSE);
}

// ── EPT Hide Pages (multi-pass) ─────────────────────────────────────────────

NTSTATUS HvEptHidePages(PEPT_STATE ept, UINT64 *pages, UINT32 count,
                         UINT64 *decoyPas, UINT32 decoyCount) {
    // Empty request is a no-op, not an error — mirrors HvDrv/hv_ept.c. In
    // particular pages may be NULL when count is 0; the loop below would
    // otherwise dereference it.
    if (!pages || count == 0 || !decoyPas || decoyCount == 0)
        return STATUS_SUCCESS;

    UINT32 failCount = 0;

    // Pass 0: hide requested pages
    for (UINT32 i = 0; i < count; i++) {
        NTSTATUS ns = EptHideOnePage(ept, pages[i], decoyPas, decoyCount);
        if (!NT_SUCCESS(ns)) failCount++;
    }

    // Passes 1-3: hide PT pages created by splits.
    // EptHideOnePage returns STATUS_SUCCESS for a new hide,
    // STATUS_ALREADY_COMPLETE for an idempotent skip.
    //
    // SplitCount is snapshotted per pass. Hiding a PT page splits the 2MB
    // region holding that page, which records a new PT page; iterating to the
    // live SplitCount would chase that growing tail inside a single pass until
    // the split table filled. Bounded by the snapshot, each pass hides exactly
    // the pages that existed when it began and the 1-3 pass cap stays meaningful.
    for (UINT32 pass = 1; pass <= 3; pass++) {
        UINT32 passCount = ept->SplitCount;
        BOOLEAN newHides = FALSE;
        for (UINT32 i = 0; i < passCount; i++) {
            if (!ept->SplitPages[i]) continue;
            UINT64 ptPa = EfiVaToPA(ept->SplitPages[i]);

            NTSTATUS ns = EptHideOnePage(ept, ptPa, decoyPas, decoyCount);
            if (ns == STATUS_SUCCESS) newHides = TRUE;
        }
        if (!newHides) break;
    }

    return (failCount == 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
// Hide pages but keep them executable (for driver's own image).
// Uses identity mapping with RWX — no decoy redirect.
NTSTATUS HvEptHidePagesExecutable(PEPT_STATE ept, UINT64 *pages, UINT32 count,
                                  UINT64 *decoyPas, UINT32 decoyCount) {
    if (!pages || count == 0)
        return STATUS_SUCCESS;
    UINT32 failCount = 0;
    for (UINT32 i = 0; i < count; i++) {
        NTSTATUS ns = EptHideOnePageEx(ept, pages[i], decoyPas, decoyCount, TRUE);
        if (!NT_SUCCESS(ns)) failCount++;
    }
    return (failCount == 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}


// ── EPT Unhide Pages ────────────────────────────────────────────────────────

void HvEptUnhidePages(PEPT_STATE ept) {
    for (UINT32 i = 0; i < ept->SplitCount; i++) {
        if (!ept->SplitPages[i]) continue;

        UINT64 base = ept->SplitRegionBase[i];
        EptFillIdentityPtPage(ept, ept->SplitPages[i], base);

        // A region that was a 2MB large page before the split gets that entry
        // back, so hiding leaves no trace in the PD either. A mixed region
        // (SplitOriginalPd == 0) is not a large page — leave its PD entry.
        UINT64 origPd = ept->SplitOriginalPd[i];
        if (origPd != 0) {
            UINT32 g = (UINT32)(base >> EPT_PDPT_SHIFT);
            if (g < ept->PdptCount) {
                PEPT_PTE pdPage = ept->PdptPages[g];
                if (pdPage) {
                    UINT32 pdIdx = (UINT32)((base >> EPT_PD_SHIFT) & EPT_ENTRY_MASK);
                    pdPage[pdIdx].Value = origPd;
                }
            }
        }
        // Teardown path: EPT must not be live after this returns.
        RtlSecureZeroMemory(ept->SplitPages[i], PAGE_SIZE);
        EfiFreePages(ept->SplitPages[i], 1);
        ept->SplitPages[i] = NULL;
    }
    SetMem(ept->SplitRegionBase, ept->SplitCount * sizeof(ept->SplitRegionBase[0]), 0);
    SetMem(ept->SplitOriginalPd, ept->SplitCount * sizeof(ept->SplitOriginalPd[0]), 0);
    ept->SplitCount = 0;
}

// ── EPT stealth hook support ────────────────────────────────────────────────
// Split-view EPT: shadow page has hooked code (X-only), original page is
// shown on reads (RW, no X). MTF single-steps the transition back.

static NTSTATUS EptRuntimeSplit(PEPT_STATE ept, PEPT_PTE pdEntry,
                                UINT64 regionBase) {
    if (!pdEntry->LargePage) return STATUS_SUCCESS;
    if (ept->SplitCount >= HV_MAX_SPLIT_PAGES) return STATUS_INSUFFICIENT_RESOURCES;
    if (g_Hv.SparePtsUsed >= HV_MAX_EPT_HOOKS) return STATUS_INSUFFICIENT_RESOURCES;

    PEPT_PTE pt = (PEPT_PTE)g_Hv.SparePtPool[g_Hv.SparePtsUsed++];
    if (!pt) return STATUS_INSUFFICIENT_RESOURCES;

    UINT64 origMemType = pdEntry->MemoryType;
    UINT64 origIgnorePat = pdEntry->IgnorePat;
    UINT64 origPd = pdEntry->Value;

    for (UINT32 i = 0; i < 512; i++) {
        UINT64 pa = regionBase + (UINT64)i * PAGE_SIZE;
        pt[i].Value = 0;
        pt[i].Read      = 1;
        pt[i].Write     = 1;
        pt[i].Execute   = 1;
        pt[i].MemoryType = origMemType;
        pt[i].IgnorePat  = origIgnorePat;
        pt[i].PhysAddr   = pa >> 12;
    }

    EptRecordPtPage(ept, pt, regionBase, origPd);

    pdEntry->Value = 0;
    pdEntry->Read    = 1;
    pdEntry->Write   = 1;
    pdEntry->Execute = 1;
    pdEntry->PhysAddr = EfiVaToPA(pt) >> 12;

    return STATUS_SUCCESS;
}

UINT32 HvEptFindHook(UINT64 gpa) {
    UINT64 page = gpa & ~0xFFFULL;
    for (UINT32 i = 0; i < g_Hv.EptHookCount; i++) {
        if (g_Hv.EptHooks[i].Active && g_Hv.EptHooks[i].TargetGpa == page)
            return i;
    }
    return 0xFFFFFFFFu;
}

NTSTATUS HvEptInstallHook(PEPT_STATE ept, UINT64 targetGpa,
                          const UINT8 *hookBytes, UINT32 hookLen) {
    if (g_Hv.EptHookCount >= HV_MAX_EPT_HOOKS) return STATUS_INSUFFICIENT_RESOURCES;
    if (g_Hv.ShadowPagesUsed >= HV_MAX_EPT_HOOKS) return STATUS_INSUFFICIENT_RESOURCES;

    UINT64 pageGpa = targetGpa & ~0xFFFULL;
    UINT32 offset  = (UINT32)(targetGpa & 0xFFF);
    if ((UINT64)offset + hookLen > PAGE_SIZE) return STATUS_INVALID_PARAMETER;

    if (HvEptFindHook(pageGpa) != 0xFFFFFFFFu)
        return STATUS_ALREADY_REGISTERED;

    UINT64 regionBase = pageGpa & ~((1ULL << EPT_PD_SHIFT) - 1);
    UINT64 pml4i = (pageGpa >> EPT_PML4_SHIFT) & EPT_ENTRY_MASK;
    UINT64 pdpti = (pageGpa >> EPT_PDPT_SHIFT) & EPT_ENTRY_MASK;
    UINT64 pdi   = (pageGpa >> EPT_PD_SHIFT)   & EPT_ENTRY_MASK;
    UINT64 pti   = (pageGpa >> EPT_PT_SHIFT)   & EPT_ENTRY_MASK;

    if (!ept->Pml4[pml4i].Read) return STATUS_INVALID_PARAMETER;
    PEPT_PTE pdpt = (PEPT_PTE)EfiPaToVa(ept->Pml4[pml4i].PhysAddr << 12);
    if (!pdpt[pdpti].Read || pdpt[pdpti].LargePage) return STATUS_INVALID_PARAMETER;
    PEPT_PTE pd = (PEPT_PTE)EfiPaToVa(pdpt[pdpti].PhysAddr << 12);

    if (pd[pdi].LargePage) {
        NTSTATUS ns = EptRuntimeSplit(ept, &pd[pdi], regionBase);
        if (!NT_SUCCESS(ns)) return ns;
    }

    PEPT_PTE pt = (PEPT_PTE)EfiPaToVa(pd[pdi].PhysAddr << 12);
    PEPT_PTE pte = &pt[pti];

    PVOID shadow = g_Hv.ShadowPagePool[g_Hv.ShadowPagesUsed++];
    if (!shadow) return STATUS_INSUFFICIENT_RESOURCES;

    RtlCopyMemory(shadow, (PVOID)(UINTN)pageGpa, PAGE_SIZE);
    RtlCopyMemory((UINT8 *)shadow + offset, hookBytes, hookLen);

    UINT32 idx = g_Hv.EptHookCount++;
    g_Hv.EptHooks[idx].TargetGpa    = pageGpa;
    g_Hv.EptHooks[idx].ShadowPagePa = EfiVaToPA(shadow);
    g_Hv.EptHooks[idx].OrigPteValue = pte->Value;
    g_Hv.EptHooks[idx].PtePtr       = pte;
    g_Hv.EptHooks[idx].Active       = 1;

    pte->PhysAddr = g_Hv.EptHooks[idx].ShadowPagePa >> 12;
    pte->Read    = 0;
    pte->Write   = 0;
    pte->Execute = 1;

    HvEptInvalidate();
    return STATUS_SUCCESS;
}

NTSTATUS HvEptRemoveHook(PEPT_STATE ept, UINT64 targetGpa) {
    UNREFERENCED_PARAMETER(ept);
    UINT64 pageGpa = targetGpa & ~0xFFFULL;
    UINT32 idx = HvEptFindHook(pageGpa);
    if (idx == 0xFFFFFFFFu) return STATUS_NOT_FOUND;

    HV_EPT_HOOK *hook = &g_Hv.EptHooks[idx];
    hook->PtePtr->Value = hook->OrigPteValue;
    hook->Active = 0;

    HvEptInvalidate();
    return STATUS_SUCCESS;
}

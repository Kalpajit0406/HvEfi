// hv_efi_ept.c - Extended Page Tables using EFI GetMemoryMap for RAM discovery.
//
// EFI equivalent of HvDrv/hv_ept.c.  Uses GetMemoryMap instead of
// MmGetPhysicalMemoryRanges, and EFI page allocation (VA == PA) throughout.
// Identity maps the low 512 GB (PML4 unit 0) plus any further 512GB units
// needed to cover RAM reported above 512GB: RAM as WB, MMIO as UC, mixed
// regions get 4KB page tables.

#include "hv_efi.h"
#include "../hv_ept_gen.h"    // HvEptGenNext / HvEptGenNeedsFlush
#include "../hv_hookpool.h"   // HvHookPool* / HvHookRegion* / HvHookTag*

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
//
// Exactly one record per region is enforced HERE, because this is the only
// place a record is ever created. A second record for the same base is not a
// bookkeeping nit: SplitCount would stop describing the table, and so would the
// region reference count that HvHookRegionRefCount feeds - coalescing would
// remove one record and free one PT page while the other record still named
// that page. FALSE means the caller must give its PT page back and fail closed.
static BOOLEAN EptRecordPtPage(PEPT_STATE ept, PEPT_PTE ptVa, UINT64 regionBase,
                               UINT64 origPd) {
    UINT32 existing = HvHookFindRegionIndex(regionBase, ept->SplitRegionBase,
                                            ept->SplitCount);

    if (!HvSplitRecordAllowed(existing, ept->SplitCount, HV_MAX_SPLIT_PAGES))
        return FALSE;

    ept->SplitPages[ept->SplitCount]      = ptVa;
    ept->SplitRegionBase[ept->SplitCount]  = regionBase;
    ept->SplitOriginalPd[ept->SplitCount]  = origPd;
    ept->SplitCount++;
    return TRUE;
}

static PEPT_PTE EptBuildMixedPtPage(PEPT_STATE ept, UINT64 regionBase) {
    PEPT_PTE pt = (PEPT_PTE)EfiAllocPagesBelow4G(1);
    if (!pt) return NULL;
    EptFillIdentityPtPage(ept, pt, regionBase);
    // origPd = 0: a mixed region was never a large page, so unhide leaves its
    // PD entry pointing at this PT page.
    if (!EptRecordPtPage(ept, pt, regionBase, 0)) {
        EfiFreePages(pt, 1);
        return NULL;
    }
    return pt;
}

// ── Split-record lifecycle: one owner per undo step ─────────────────────
//
// Three callers undo a split - the hook path (the last hook leaving one
// region), unhide (the whole table) and destroy (teardown). Each used to carry
// its own copy of the loop, which is how the hook path came to leave its
// regions split for good, and how a page owned by the spare-PT pool could be
// freed from one path while the pool still held the pointer.

// Give a PT page back to whichever pool owns it. A page taken from
// g_Hv.SparePtPool goes back INTO that pool (the pool frees it at teardown);
// one allocated at init for a mixed RAM region is allocator-owned and is freed
// here. Freeing a pool page from here would leave the pool holding a dangling
// pointer that the next split would hand out as a live PT page.
static void EptReleasePtPage(PEPT_PTE pt) {
    UINT32 poolSlot;

    if (pt == NULL) return;

    poolSlot = HvHookPoolFindPtr((const void *const *)g_Hv.SparePtPool,
                                 HV_MAX_EPT_HOOKS, (const void *)pt);
    RtlSecureZeroMemory(pt, PAGE_SIZE);

    if (poolSlot != HV_HOOK_SLOT_NONE) {
        // Atomic: this runs from the live coalesce path, so a concurrent
        // EptRuntimeSplit claiming a DIFFERENT spare entry would otherwise have
        // its claim lost by a read-modify-write here - and that entry would stay
        // marked used, with its page unreachable, for the rest of the boot.
        HvHookPoolReleaseAtomic((volatile long *)&g_Hv.SparePtUsedMask,
                                poolSlot);
        return;   // the pool still owns it
    }
    EfiFreePages(pt, 1);
}

// Drop a split record without touching its page (the caller has already
// released the page, or is about to). Swap with the last so the array stays
// dense: unhide and destroy both walk [0, SplitCount).
static void EptRemoveSplitRecord(PEPT_STATE ept, UINT32 i) {
    UINT32 last;

    if (i >= ept->SplitCount) return;
    last = ept->SplitCount - 1;

    ept->SplitPages[i]      = ept->SplitPages[last];
    ept->SplitRegionBase[i] = ept->SplitRegionBase[last];
    ept->SplitOriginalPd[i] = ept->SplitOriginalPd[last];

    ept->SplitPages[last]      = NULL;
    ept->SplitRegionBase[last] = 0;
    ept->SplitOriginalPd[last] = 0;
    ept->SplitCount = last;
}

// Collapse one region back to the original large-page PD entry and hand its PT
// page back. Only legal when no hook still lives in the region - see
// HvHookRegionShouldCoalesce in ../hv_hookpool.h.
static void EptCoalesceRegion(PEPT_STATE ept, UINT32 i) {
    UINT64 regionBase = ept->SplitRegionBase[i];
    UINT64 origPd     = ept->SplitOriginalPd[i];
    UINT32 g          = (UINT32)(regionBase >> EPT_PDPT_SHIFT);
    PEPT_PTE pt       = ept->SplitPages[i];

    if (g < ept->PdptCount && ept->PdptPages[g] != NULL) {
        UINT32 pdIdx = (UINT32)((regionBase >> EPT_PD_SHIFT) & EPT_ENTRY_MASK);
        ept->PdptPages[g][pdIdx].Value = origPd;
    }

    EptReleasePtPage(pt);
    EptRemoveSplitRecord(ept, i);

    // The claim is NOT released here. The caller owns it for the whole operation
    // (see the contract note on HvEptRemoveHook): releasing it here would let the
    // next processor claim the region while this one is still finishing, which is
    // the window that lets a leaf write land in a page already handed back.
}

// Forget every hook without restoring any EPT entry: the callers here are
// rebuilding or tearing the table down wholesale, so the entries are about to
// be replaced anyway. A pending MTF restore is deliberately left to fail its
// own checks in the exit handler - Active is 0 and the slot's epoch is stale,
// which is exactly the rejection those checks exist for.
static void EptDropAllHooks(void) {
    UINT32 i;
    for (i = 0; i < HV_MAX_EPT_HOOKS; i++) {
        g_Hv.EptHooks[i].Active = 0;
        g_Hv.EptHooks[i].PtePtr = NULL;
    }
    g_Hv.EptHookUsedMask = 0;
}

// How many live hooks name this region. The pure counter in ../hv_hookpool.h
// takes a plain array, so one is rebuilt here from the live records on every
// call: there is no second copy of the state that could fall out of step.
// Slots whose mask bit is clear are skipped by the counter, so a base left
// behind in a freed slot cannot contribute.
static UINT32 EptLiveRegionRefs(UINT64 regionBase) {
    UINT64 bases[HV_MAX_EPT_HOOKS];
    UINT32 i;

    for (i = 0; i < HV_MAX_EPT_HOOKS; i++)
        bases[i] = g_Hv.EptHooks[i].RegionBase;

    return HvHookRegionRefCount(bases, g_Hv.EptHookUsedMask, regionBase,
                                HV_MAX_EPT_HOOKS);
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
    // The hook pools go first, and the order is load-bearing: a split record can
    // name a spare-PT-pool page, so freeing the pool while such a record stands
    // would free the same page twice - once from the pool, once from the sweep
    // below. HvEptHookPoolsFree() unlinks those records before it frees
    // anything. Without this call the pools leaked for the life of the boot.
    HvEptHookPoolsFree();

    for (UINT32 i = 0; i < ept->SplitCount; i++) {
        EptReleasePtPage(ept->SplitPages[i]);
    }
    RtlSecureZeroMemory(ept->SplitRegionBase,
                        sizeof(ept->SplitRegionBase[0]) * ept->SplitCount);
    RtlSecureZeroMemory(ept->SplitOriginalPd,
                        sizeof(ept->SplitOriginalPd[0]) * ept->SplitCount);
    ept->SplitCount = 0;
    ept->SplitClaim = 0;

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

    if (!EptRecordPtPage(ept, pt, regionBase, origPd)) {
        // A record for this region already exists, and this function's contract
        // is "split AND record". Fail closed rather than leave a second record,
        // or a PT page the table does not know about, behind.
        EfiFreePages(pt, 1);
        return STATUS_UNSUCCESSFUL;
    }

    pdEntry->Value = 0;
    pdEntry->Read    = 1;
    pdEntry->Write   = 1;
    pdEntry->Execute = 1;
    pdEntry->PhysAddr = EfiVaToPA(pt) >> 12;
    // LargePage bit stays 0

    return STATUS_SUCCESS;
}

// ── EPT Invalidate ──────────────────────────────────────────────────────────
//
// Four entry points. What separates them is WHICH processor they fix and
// whether they are allowed outside VMX root. ../hv_ept_gen.h carries the full
// reasoning; the one-line version is that INVEPT is local to the executing
// logical processor, a remote processor is in VMX non-root where INVEPT is
// #UD, and a VM exit is therefore the only context in which a processor can
// invalidate itself.

// The raw operation: invalidate this processor's cached EPT translations. No
// counter traffic, so a caller that must not touch the generation (a teardown
// path, or a re-flush after one already published) can still use it.
void HvEptFlushLocal(void) {
    struct { UINT64 eptp; UINT64 gpa; } desc;
    desc.eptp = g_Hv.Ept.EptPointer;
    desc.gpa  = 0;

    if (HvAsmInvept(INVEPT_ALL_CONTEXTS, &desc) != 0) {
        struct { UINT64 vpid; UINT64 addr; } vdesc = {0, 0};
        HvAsmInvvpid(INVVPID_ALL_CONTEXTS, &vdesc);
    }
}

// Publish a mutation WITHOUT invalidating. This must be called before the first
// EPT entry is modified, not after the last one: a processor that takes its exit
// inside the window between the entry write and the publication reads the old
// generation, concludes it is up to date, and keeps its pre-change translation
// for the rest of the boot. Its staleness would be unbounded rather than one
// exit - the INVARIANT note in ../hv_ept_gen.h.
//
// Safe in VMX non-root: it is a store and nothing else. HvEfiOnExitBootServices
// is the caller that depends on that.
void HvEptPublishMutation(void) {
    // Atomic. Two processors can publish at once - a hypercall on one, the MTF
    // restore for a hook hit on another - and a read-modify-write that lost one
    // update would leave a mutation that really happened unpublished, which is
    // unbounded staleness rather than one exit. _InterlockedIncrement is the
    // spelling this tree already uses outside #if DBG (hv_efi_smp.c).
    _InterlockedIncrement((volatile long *)&g_Hv.EptGeneration);
}

// Called at the top of HvExitHandler: this processor is in root, so this is
// where a published mutation reaches it. One load and one compare on the exit
// path; no INVEPT unless something actually changed.
void HvEptGenerationSync(PVCPU vcpu) {
    LONG current = g_Hv.EptGeneration;
    if (!HvEptGenNeedsFlush(vcpu->EptSeenGeneration, current)) return;
    HvEptFlushLocal();
    vcpu->EptSeenGeneration = current;
}

// Publish and fix THIS processor immediately. Every caller reaches here in VMX
// root (the hypercall path, bring-up, teardown), so the local flush is valid;
// the other processors follow at their next VM exit. This replaced a bare
// local flush - correct only while every mutation happened before VMLAUNCH,
// when there was no other processor to hold a stale translation.
void HvEptInvalidate(void) {
    PVCPU vcpu;
    LONG current;

    HvEptPublishMutation();
    current = g_Hv.EptGeneration;

    HvEptFlushLocal();

    vcpu = HvGetCurrentVcpu();
    if (vcpu) vcpu->EptSeenGeneration = current;
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
    // Rebuilding every split region wholesale invalidates any hook that lived in
    // one: its saved PtePtr is aimed into a PT page this loop is about to hand
    // back. Drop the hooks rather than leave a restore path pointing at memory
    // the pool can reissue.
    EptDropAllHooks();

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
        // Teardown path: EPT must not be live after this returns. The page goes
        // back to whichever pool owns it - freeing a spare PT page here would
        // leave the pool pointing at freed memory.
        EptReleasePtPage(ept->SplitPages[i]);
        ept->SplitPages[i] = NULL;
    }
    SetMem(ept->SplitRegionBase, ept->SplitCount * sizeof(ept->SplitRegionBase[0]), 0);
    SetMem(ept->SplitOriginalPd, ept->SplitCount * sizeof(ept->SplitOriginalPd[0]), 0);
    ept->SplitCount = 0;
    // Every region is back to a large page, so no split is in flight and the
    // claim word must not keep naming one.
    ept->SplitClaim = 0;
}

// ── EPT stealth hook support ────────────────────────────────────────────────
// Split-view EPT: shadow page has hooked code (X-only), original page is
// shown on reads (RW, no X). MTF single-steps the transition back.

// Split one 2MB region for a stealth hook, and record it EXACTLY once.
//
// Two processors that both find the region still a large page would otherwise
// each take a spare PT page, each append a record for the SAME region and each
// rewrite the same PD entry. The duplicate record is the damaging part: it
// makes SplitCount, and therefore the region reference count, stop describing
// the table.
//
// CONTRACT: the caller already holds this region's split claim (HvSplitClaimTake
// succeeded) and releases it. The claim is deliberately owned by the caller
// rather than taken here, because the hook being installed goes into a leaf of
// the very PT page this split creates, and that leaf must stay protected until
// the hook is committed - see the note in ../hv_hookpool.h. This function then
// has exactly one processor to itself, and so does the record it appends.
static NTSTATUS EptRuntimeSplit(PEPT_STATE ept, PEPT_PTE pdEntry,
                                UINT64 regionBase) {
    UINT32 poolSlot;
    PEPT_PTE pt;
    UINT64 origMemType, origIgnorePat, origPd;

    if (!pdEntry->LargePage) return STATUS_SUCCESS;
    if (ept->SplitCount >= HV_MAX_SPLIT_PAGES) return STATUS_INSUFFICIENT_RESOURCES;

    // Every failure from here is a pool problem, and the caller owns the claim.
    pt = NULL;
    poolSlot = HvHookPoolClaim((volatile long *)&g_Hv.SparePtUsedMask,
                               HV_MAX_EPT_HOOKS);
    if (poolSlot != HV_HOOK_SLOT_NONE)
        pt = (PEPT_PTE)g_Hv.SparePtPool[poolSlot];
    if (pt == NULL) goto fail;
    // The entry was claimed atomically above, so it is already marked used, and
    // it is handed back when the region is coalesced (EptReleasePtPage): a
    // region that is split and later collapsed leaves the pool as it found it.

    origMemType = pdEntry->MemoryType;
    origIgnorePat = pdEntry->IgnorePat;
    origPd = pdEntry->Value;

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

    // Belt and braces. With the claim held this cannot find an existing record -
    // the caller only gets here while the region is still a large page, and a
    // split region has no large page - but a second record for one region is
    // exactly the state this path must never produce, so it is refused rather
    // than assumed impossible.
    if (!EptRecordPtPage(ept, pt, regionBase, origPd)) goto fail;

    pdEntry->Value = 0;
    pdEntry->Read    = 1;
    pdEntry->Write   = 1;
    pdEntry->Execute = 1;
    pdEntry->PhysAddr = EfiVaToPA(pt) >> 12;

    return STATUS_SUCCESS;

fail:
    if (poolSlot != HV_HOOK_SLOT_NONE)
        HvHookPoolReleaseAtomic((volatile long *)&g_Hv.SparePtUsedMask,
                                poolSlot);
    return STATUS_INSUFFICIENT_RESOURCES;
}

// ── EPT Ensure 4KB entry (split dynamically if currently a 2MB large page) ──

EPT_PTE *HvEptEnsure4K(PEPT_STATE ept, UINT64 gpa) {
    UINT64 pml4i = (gpa >> EPT_PML4_SHIFT) & EPT_ENTRY_MASK;
    if (!ept->Pml4[pml4i].Read) return NULL;

    PEPT_PTE pdpt = (PEPT_PTE)EfiPaToVa(ept->Pml4[pml4i].PhysAddr << 12);
    UINT64 pdpti = (gpa >> EPT_PDPT_SHIFT) & EPT_ENTRY_MASK;
    if (!pdpt[pdpti].Read || pdpt[pdpti].LargePage) return NULL;

    PEPT_PTE pd = (PEPT_PTE)EfiPaToVa(pdpt[pdpti].PhysAddr << 12);
    UINT64 pdi = (gpa >> EPT_PD_SHIFT) & EPT_ENTRY_MASK;
    if (!pd[pdi].Read) return NULL;

    if (pd[pdi].LargePage) {
        UINT64 regionBase = gpa & ~((1ULL << EPT_PD_SHIFT) - 1);
        UINT32 regionTag = HvSplitRegionTag(regionBase);
        if (HvSplitClaimTake((volatile long *)&ept->SplitClaim, regionTag)) {
            NTSTATUS status = EptRuntimeSplit(ept, &pd[pdi], regionBase);
            HvSplitClaimRelease((volatile long *)&ept->SplitClaim);
            if (!NT_SUCCESS(status)) return NULL;
        } else {
            if (pd[pdi].LargePage) return NULL;
        }
    }

    PEPT_PTE pt = (PEPT_PTE)EfiPaToVa(pd[pdi].PhysAddr << 12);
    UINT64 pti = (gpa >> EPT_PT_SHIFT) & EPT_ENTRY_MASK;
    return &pt[pti];
}

UINT32 HvEptFindHook(UINT64 gpa) {
    UINT64 page = gpa & ~0xFFFULL;
    // Every slot, not the first N: slots are reused now, so the installed hooks
    // are the set of Active slots rather than a prefix of the array.
    for (UINT32 i = 0; i < HV_MAX_EPT_HOOKS; i++) {
        if (g_Hv.EptHooks[i].Active && g_Hv.EptHooks[i].TargetGpa == page)
            return i;
    }
    return HV_HOOK_SLOT_NONE;
}

NTSTATUS HvEptInstallHook(PEPT_STATE ept, UINT64 targetGpa,
                          const UINT8 *hookBytes, UINT32 hookLen) {
    UINT32 slot, shadowSlot, splitIdx, decision, regionTag;
    PVOID  shadow;
    UINT64 pageGpa, offset, regionBase, pml4i, pdpti, pdi, pti;
    PEPT_PTE pdpt, pd, pt, pte;
    // STATUS_INVALID_PARAMETER is the default because the EPT-walk refusals
    // below are exactly that; the resource paths set their own status.
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    BOOLEAN claimHeld = FALSE;

    slot = HV_HOOK_SLOT_NONE;
    shadowSlot = HV_HOOK_SLOT_NONE;

    pageGpa = targetGpa & ~0xFFFULL;
    offset  = targetGpa & 0xFFF;
    if (offset + hookLen > PAGE_SIZE) return STATUS_INVALID_PARAMETER;

    if (HvEptFindHook(pageGpa) != HV_HOOK_SLOT_NONE)
        return STATUS_ALREADY_REGISTERED;

    // CLAIM both pool entries up front, and atomically. HvHookPoolClaim() reads
    // and writes the mask in ONE step, so two processors installing at the same
    // instant cannot come away with the same slot, or copy their hook bytes
    // into the same shadow page. The read-then-write this replaced could do
    // both, and one of the two hooks was then silently lost while every counter
    // still looked consistent.
    //
    // Pool entries are claimed before the region, and the region claim is taken
    // further down (it needs regionBase). Both are released by `fail`, so the
    // order does not matter for correctness - only that neither is held while
    // waiting for anything, which it never is.
    //
    // A claim is a claim, so every return below has to give the entries back;
    // they all funnel through `fail`. That is also what keeps install/remove
    // cycles repeatable - the original version consumed a slot and a shadow
    // page on the way in and gave neither of them back at all.
    slot = HvHookPoolClaim((volatile long *)&g_Hv.EptHookUsedMask,
                           HV_MAX_EPT_HOOKS);
    if (slot == HV_HOOK_SLOT_NONE) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto fail;
    }

    shadowSlot = HvHookPoolClaim((volatile long *)&g_Hv.ShadowPageUsedMask,
                                 HV_MAX_EPT_HOOKS);
    if (shadowSlot == HV_HOOK_SLOT_NONE) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto fail;
    }

    shadow = g_Hv.ShadowPagePool[shadowSlot];
    if (shadow == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto fail;
    }

    // Mutate first, publish afterwards: the HvEptInvalidate() at the end of
    // this function is the publish. That order is a correctness requirement
    // rather than a style choice - a processor that took its exit between a
    // publish and this mutation would flush, re-walk the unchanged table,
    // cache the pre-hook mapping, and record the new generation as seen, so
    // nothing would ever invalidate it again. See the INVARIANT note in
    // ../hv_ept_gen.h.
    regionBase = pageGpa & ~((1ULL << EPT_PD_SHIFT) - 1);
    regionTag  = HvSplitRegionTag(regionBase);
    pml4i = (pageGpa >> EPT_PML4_SHIFT) & EPT_ENTRY_MASK;
    pdpti = (pageGpa >> EPT_PDPT_SHIFT) & EPT_ENTRY_MASK;
    pdi   = (pageGpa >> EPT_PD_SHIFT)   & EPT_ENTRY_MASK;
    pti   = (pageGpa >> EPT_PT_SHIFT)   & EPT_ENTRY_MASK;

    if (!ept->Pml4[pml4i].Read) goto fail;
    pdpt = (PEPT_PTE)EfiPaToVa(ept->Pml4[pml4i].PhysAddr << 12);
    if (!pdpt[pdpti].Read || pdpt[pdpti].LargePage) goto fail;
    pd = (PEPT_PTE)EfiPaToVa(pdpt[pdpti].PhysAddr << 12);

    // ── Take the region claim, and hold it until the hook is committed.
    //
    // The leaf this hook goes into lives in the region's PT page, and the last
    // unhook in the region hands that page back to the spare pool. Writing the
    // leaf without holding the claim is therefore a write into a page that may
    // already be free - and it would land inside a page about to be reissued as
    // some other region's PT, i.e. a wrong EPT leaf, which is a guest #PF the
    // guest cannot fix. So the claim covers the whole operation, not just the
    // split.
    //
    // The decision table is the shared one: a taken claim refuses every action
    // on the region, with the tag saying whether it is this region or another.
    // Losing is a bounded, retryable refusal and never a wait.
    splitIdx = HvHookFindRegionIndex(regionBase, ept->SplitRegionBase,
                                     ept->SplitCount);
    decision = HvSplitDecide(splitIdx, ept->SplitCount, HV_MAX_SPLIT_PAGES,
                             (unsigned int)ept->SplitClaim, regionTag);
    if (decision == HV_SPLIT_EXHAUSTED) {
        // No record and no room to make one: this region can never be split, so
        // it cannot be hooked at a 4KB granularity at all.
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto fail;
    }
    if (decision != HV_SPLIT_DO && decision != HV_SPLIT_REUSE) {
        status = STATUS_INSUFFICIENT_RESOURCES;   // another processor owns it
        goto fail;
    }
    // The decision is an observation, so it has to be applied atomically; the
    // compare-exchange is what makes it a claim rather than a stale reading.
    if (!HvSplitClaimTake((volatile long *)&ept->SplitClaim, regionTag)) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto fail;
    }
    claimHeld = TRUE;

    if (decision == HV_SPLIT_DO) {
        status = EptRuntimeSplit(ept, &pd[pdi], regionBase);
        if (!NT_SUCCESS(status)) goto fail;
        // A split replaced the PD entry, so re-derive the PT page from it.
        // Nothing can change it now: this processor holds the claim.
    } else if (pd[pdi].LargePage) {
        // HV_SPLIT_REUSE with the region still a large page: the split table and
        // the EPT disagree about whether this region is split. EptRecordPtPage
        // refuses a duplicate, so this is unreachable by construction - but
        // treating a 2MB leaf as a PT pointer would write a leaf into whatever
        // page it names, so it fails closed rather than trusting that.
        status = STATUS_UNSUCCESSFUL;
        goto fail;
    }

    pt  = (PEPT_PTE)EfiPaToVa(pd[pdi].PhysAddr << 12);
    pte = &pt[pti];

    RtlCopyMemory(shadow, (PVOID)(UINTN)pageGpa, PAGE_SIZE);
    RtlCopyMemory((UINT8 *)shadow + offset, hookBytes, hookLen);

    // ── Commit. Nothing below can fail, and both pool entries are already
    // marked: the claim above is what marked them.
    // A fresh epoch stamps this occupancy of the slot: a pending MTF restore
    // from a previous occupant carries that occupant's epoch and is refused by
    // HvHookTagMatches in the exit handler rather than rewriting this page.
    _InterlockedIncrement((volatile long *)&g_Hv.EptHookEpoch);

    HV_EPT_HOOK *rec = &g_Hv.EptHooks[slot];
    rec->TargetGpa    = pageGpa;
    rec->ShadowPagePa = EfiVaToPA(shadow);
    rec->OrigPteValue = pte->Value;
    rec->PtePtr       = pte;
    rec->RegionBase   = regionBase;
    rec->ShadowSlot   = shadowSlot;
    rec->Epoch        = (UINT32)g_Hv.EptHookEpoch;
    rec->Active       = 1;

    pte->PhysAddr = rec->ShadowPagePa >> 12;
    pte->Read    = 0;
    pte->Write   = 0;
    pte->Execute = 1;

    HvEptInvalidate();
    // Released last, and only now: until the hook is committed the region's PT
    // page must stay protected from a coalesce in another processor.
    HvSplitClaimRelease((volatile long *)&ept->SplitClaim);
    return STATUS_SUCCESS;

fail:
    // Hand every claim back. HvHookPoolReleaseAtomic() ignores a slot past the
    // mask width, so an entry that was never claimed (HV_HOOK_SLOT_NONE) is a
    // no-op rather than a second, unrelated bit.
    if (claimHeld)
        HvSplitClaimRelease((volatile long *)&ept->SplitClaim);
    if (slot != HV_HOOK_SLOT_NONE)
        HvHookPoolReleaseAtomic((volatile long *)&g_Hv.EptHookUsedMask, slot);
    if (shadowSlot != HV_HOOK_SLOT_NONE)
        HvHookPoolReleaseAtomic((volatile long *)&g_Hv.ShadowPageUsedMask,
                                shadowSlot);
    return status;
}

NTSTATUS HvEptRemoveHook(PEPT_STATE ept, UINT64 targetGpa) {
    UINT64 pageGpa = targetGpa & ~0xFFFULL;
    UINT32 idx = HvEptFindHook(pageGpa);
    UINT32 splitIdx, refsAfter, regionTag;
    UINT64 regionBase;
    HV_EPT_HOOK *hook;

    if (idx == HV_HOOK_SLOT_NONE) return STATUS_NOT_FOUND;

    hook = &g_Hv.EptHooks[idx];
    regionBase = hook->RegionBase;

    // CONTRACT: the region claim is held from before the first write until the
    // whole removal - including the coalesce - is done, and it is released at
    // the end of this function. That is what stops two unhooks in one region
    // interleaving: without it, this processor could write hook->PtePtr after
    // the other one had already handed that PT page back to the pool, leaving a
    // stale large-page entry inside a page about to be reissued as some other
    // region's PT. Losing the claim is a bounded, retryable refusal, never a
    // wait for the other processor to finish.
    regionTag = HvSplitRegionTag(regionBase);
    if (!HvSplitClaimTake((volatile long *)&ept->SplitClaim, regionTag))
        return STATUS_INSUFFICIENT_RESOURCES;

    // Counted before the release below, so this includes the hook being
    // removed; HvHookRegionRefAfterRemoval is the saturating decrement.
    refsAfter = HvHookRegionRefAfterRemoval(EptLiveRegionRefs(regionBase));

    // Same ordering rule as install: restore the entry, then publish (the
    // HvEptInvalidate() below). Publishing first would let a peer flush against
    // the still-shadowed table and record the new generation. See the
    // INVARIANT note in ../hv_ept_gen.h.
    hook->PtePtr->Value = hook->OrigPteValue;
    hook->Active = 0;
    hook->PtePtr = NULL;

    // Both pool entries go back. Clearing Active first means a pending MTF
    // restore anywhere is already refused by the Active test; the epoch tag is
    // what refuses it after this slot has been REUSED by the next hook.
    //
    // Released atomically: two processors removing different hooks at once would
    // otherwise each write back a mask read before the other's release, and one
    // of the two slots would stay marked used for the life of the boot.
    HvHookPoolReleaseAtomic((volatile long *)&g_Hv.EptHookUsedMask, idx);
    if (hook->ShadowSlot < HV_MAX_EPT_HOOKS)
        HvHookPoolReleaseAtomic((volatile long *)&g_Hv.ShadowPageUsedMask,
                                hook->ShadowSlot);

    // Collapse the region only when no hook still shadows a page in it: until
    // then the 512 4KB leaves must stay, because a sibling hook's saved PtePtr
    // points into that PT page. HvHookRegionShouldCoalesce also refuses a region
    // that was split at init for a RAM boundary - it was never a large page, so
    // there is no large-page entry to restore.
    splitIdx = HvHookFindRegionIndex(regionBase, ept->SplitRegionBase,
                                     ept->SplitCount);
    if (splitIdx != HV_HOOK_SLOT_NONE &&
        HvHookRegionShouldCoalesce(refsAfter, ept->SplitOriginalPd[splitIdx])) {
        EptCoalesceRegion(ept, splitIdx);
    }

    HvEptInvalidate();
    // Last, so that everything above - the restore, the pool releases and any
    // coalesce - happened while this processor owned the region.
    HvSplitClaimRelease((volatile long *)&ept->SplitClaim);
    return STATUS_SUCCESS;
}

// ── Return both pre-allocated hook pools ────────────────────────────────
//
// They are allocated once in HvEfiDriverEntryImpl (Step 7b) and, before this,
// were freed by nothing: every boot leaked 128 KB of firmware pages, and a
// bring-up that failed after Step 7b leaked them too.
//
// The order is deliberate. A split record can name a page that came from the
// spare pool, and if the pool were freed first then HvEptDestroy's or unhide's
// own sweep would free that same page a second time. So pool-owned split
// records are unlinked here, with their regions collapsed first so no live EPT
// entry is left pointing at a page the pool is about to release.
//
// Idempotent - the pools are NULLed and the masks cleared, so a second call is a
// no-op. That matters because it runs from HvEptDestroy and from the driver's
// failure funnel, and both can be reached on the same exit path.
void HvEptHookPoolsFree(void) {
    UINT32 i, slot;

    EptDropAllHooks();

    for (i = 0; i < g_Hv.Ept.SplitCount; ) {
        slot = HvHookPoolFindPtr((const void *const *)g_Hv.SparePtPool,
                                 HV_MAX_EPT_HOOKS,
                                 (const void *)g_Hv.Ept.SplitPages[i]);
        if (slot == HV_HOOK_SLOT_NONE) { i++; continue; }

        if (g_Hv.Ept.SplitOriginalPd[i] != 0) {
            UINT64 regionBase = g_Hv.Ept.SplitRegionBase[i];
            UINT32 g = (UINT32)(regionBase >> EPT_PDPT_SHIFT);
            if (g < g_Hv.Ept.PdptCount && g_Hv.Ept.PdptPages[g] != NULL) {
                UINT32 pdIdx =
                    (UINT32)((regionBase >> EPT_PD_SHIFT) & EPT_ENTRY_MASK);
                g_Hv.Ept.PdptPages[g][pdIdx].Value = g_Hv.Ept.SplitOriginalPd[i];
            }
        }
        HvHookPoolReleaseAtomic((volatile long *)&g_Hv.SparePtUsedMask, slot);
        EptRemoveSplitRecord(&g_Hv.Ept, i);
    }

    for (i = 0; i < HV_MAX_EPT_HOOKS; i++) {
        if (g_Hv.ShadowPagePool[i] != NULL) {
            // Zero before free: firmware pages are reused by the OS, and a
            // shadow page holds a copy of the hooked code.
            RtlSecureZeroMemory(g_Hv.ShadowPagePool[i], PAGE_SIZE);
            EfiFreePages(g_Hv.ShadowPagePool[i], 1);
            g_Hv.ShadowPagePool[i] = NULL;
        }
        if (g_Hv.SparePtPool[i] != NULL) {
            RtlSecureZeroMemory(g_Hv.SparePtPool[i], PAGE_SIZE);
            EfiFreePages(g_Hv.SparePtPool[i], 1);
            g_Hv.SparePtPool[i] = NULL;
        }
    }

    g_Hv.ShadowPageUsedMask = 0;
    g_Hv.SparePtUsedMask = 0;
    // No split can be in flight while the table is being torn down, but leaving
    // a stale tag in the claim word would make a later split of that region
    // (after a re-init) refuse itself.
    g_Hv.Ept.SplitClaim = 0;
}

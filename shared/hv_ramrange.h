// hv_ramrange.h - interval search over a base-sorted physical-memory map.
//
// WHY THIS FILE EXISTS (Pass 94, EPT walk audit vs SDM Vol 3C ch. 29)
//
// HvEfi/hv_efi_ept.c classifies every 2 MB EPT region as WB (fully RAM), UC (no
// RAM overlap) or "mixed" (split to 4 KB) by binary-searching the ranges
// collected from GetMemoryMap. The original search was:
//
//     EptFirstRangeEndingAfter(): find the first range whose end > pa,
//     implemented as a textbook binary search on `end > pa`.
//
// That is only valid when `end` is MONOTONE across the array. The array is
// sorted by BASE, which does NOT imply monotone ends: a map holding
// [0, 16 MB) and then [1 MB, 2 MB) is base-sorted but its ends go 16 MB, 2 MB.
// The UEFI memory map is not required to be disjoint, so that input is legal.
//
// When the search lands on the wrong index, EptRegionOverlapsRam() answers FALSE
// for a region that really is RAM, the region is mapped UC instead of WB, and the
// first guest access to it raises an EPT violation. HvEptLookup4K() returns NULL
// for a large page, so HandleEptViolation injects #PF - and a #PF cannot fix an
// EPT restriction. The firmware handler returns, the instruction retries, the
// same violation fires again: an infinite #PF loop, which is the exact brick
// this project already recorded from the Dell (see the invariant (A) note in
// ../hv_ept_decision.h).
//
// The fix is to NORMALISE the map once, at collection time: sort by base, then
// merge overlapping and adjacent ranges. The result is base-sorted AND
// end-monotone, which makes an end-based binary search sound. Normalisation only
// ever shrinks the array, so HV_MAX_RAM_RANGES still bounds it.
//
// Normalisation also makes the chained region tests exact and O(n) rather than
// O(n) searches, and it means EPT region classification no longer depends on the
// firmware's descriptor ordering at all.
//
// Keep this file free of OS and firmware dependencies: the EDK2 build, the WDK
// build and a plain host unit test all include it. Keep it ASCII-only.

#ifndef HV_RAMRANGE_H
#define HV_RAMRANGE_H

// A half-open physical interval [base, end). `end` is stored EXCLUSIVE and is
// pre-saturated by the callers so that base/end arithmetic never wraps.
typedef struct {
    unsigned long long base;
    unsigned long long end;
} HV_RANGE;

// Sentinel for "no such range". This CANNOT be 0: index 0 is a legitimate
// answer, and an earlier revision used 0u here, which made every query that
// legitimately hit range 0 report "not found". tools/unit/hvramrange_test.c
// caught it on the first run. -1 with an int return is unambiguous.
#define HV_RANGE_NONE (-1)

// Saturating [base, base+bytes) -> exclusive end. A base+bytes that would wrap
// pins to the maximum address rather than silently becoming a tiny range, which
// would classify real memory as a hole.
static __inline unsigned long long HvRangeEndOf(unsigned long long base,
                                                unsigned long long bytes)
{
    if (bytes > (0xFFFFFFFFFFFFFFFFULL - base)) {
        return 0xFFFFFFFFFFFFFFFFULL;
    }
    return base + bytes;
}

// Insertion sort by base ascending. N <= HV_MAX_RAM_RANGES (128) and this runs
// once per boot; the sort also breaks ties on `end` so the merge below sees
// shorter intervals first and swallows duplicates deterministically.
static __inline void HvRangeSortByBase(HV_RANGE *r, unsigned n)
{
    unsigned i;
    if (r == 0) return;
    for (i = 1; i < n; i++) {
        HV_RANGE key = r[i];
        unsigned j = i;
        while (j > 0 && (r[j - 1].base > key.base ||
                         (r[j - 1].base == key.base && r[j - 1].end > key.end))) {
            r[j] = r[j - 1];
            j--;
        }
        r[j] = key;
    }
}

// Merge overlapping OR ADJACENT intervals in place. Requires base-sorted input
// (run HvRangeSortByBase first). Adjacency is merged too because [0,1) and
// [1,2) describe one usable region; leaving them split would still be correct
// but would double-count the boundary.
//
// Empty intervals (end <= base) are dropped: they can describe nothing.
//
// Returns the new count, which is always <= n. The tail of the array is left
// holding stale copies and must not be read past the returned count.
static __inline unsigned HvRangeMergeOverlap(HV_RANGE *r, unsigned n)
{
    unsigned read, write;
    if (r == 0) return 0;
    if (n == 0) return 0;

    write = 0;
    for (read = 0; read < n; read++) {
        if (r[read].end <= r[read].base) continue;      // empty: drop
        if (write > 0 && r[read].base <= r[write - 1].end) {
            // Overlaps or touches the range we are extending.
            if (r[read].end > r[write - 1].end) {
                r[write - 1].end = r[read].end;
            }
            continue;
        }
        r[write++] = r[read];
    }
    return write;
}

// Sort + merge in one call: the normalisation the EPT performs once after
// collecting the memory map. After this, `end` is monotone across the array and
// every query below is a sound binary search.
static __inline unsigned HvRangeNormalize(HV_RANGE *r, unsigned n)
{
    HvRangeSortByBase(r, n);
    return HvRangeMergeOverlap(r, n);
}

// Index of the first range whose end > pa, or HV_RANGE_NONE.
//
// REQUIRES a normalised array (HvRangeNormalize). With base-sorted AND
// end-monotone input, `end > pa` is a monotone predicate and this binary search
// is correct. Passing an un-normalised array reintroduces the Pass 94 bug, so
// the EPT calls HvRangeNormalize once and then only ever queries.
static __inline int HvRangeIndexForPa(const HV_RANGE *r, unsigned n,
                                        unsigned long long pa)
{
    int lo = 0;
    int hi = (int)n - 1;
    int ans = HV_RANGE_NONE;
    if (r == 0) return HV_RANGE_NONE;
    while (lo <= hi) {
        int mid = lo + ((hi - lo) >> 1);
        if (r[mid].end > pa) { ans = mid; hi = mid - 1; }
        else                 { lo = mid + 1; }
    }
    return ans;
}

// Is `pa` inside any range? True exactly when the covering range starts at or
// below pa, which the index search guarantees for a normalised array.
static __inline int HvRangeContains(const HV_RANGE *r, unsigned n,
                                    unsigned long long pa)
{
    int i = HvRangeIndexForPa(r, n, pa);
    if (i == HV_RANGE_NONE) return 0;
    return r[i].base <= pa;
}

// Does the union of all ranges cover [base, base+size) with no gap? Walks the
// covering chain forward. `size` of 0 means an empty interval, which is trivially
// covered. REQUIRES a normalised array, where "the next range that ends after
// cur" is the next range that can extend coverage.
static __inline int HvRangeFullyCovers(const HV_RANGE *r, unsigned n,
                                       unsigned long long base,
                                       unsigned long long size)
{
    unsigned long long end, cur;
    int i;
    if (size == 0) return 1;
    end = HvRangeEndOf(base, size);
    if (end <= base) return 0;                 // wrapped: refuse
    i = HvRangeIndexForPa(r, n, base);
    if (i == HV_RANGE_NONE) return 0;         // base is in a hole
    cur = base;
    while (cur < end) {
        if ((unsigned)i >= n) return 0;         // ran off the end mid-region
        if (r[i].base > cur) return 0;         // gap: not fully covered
        if (r[i].end > cur) cur = r[i].end;
        i++;
    }
    return 1;
}

// Does any range intersect [base, base+size)? The first range ending after
// `base` is the only one that can start before `end`, because ranges are
// base-sorted. An empty interval overlaps nothing.
static __inline int HvRangeOverlaps(const HV_RANGE *r, unsigned n,
                                    unsigned long long base,
                                    unsigned long long size)
{
    unsigned long long end;
    int i;
    if (size == 0) return 0;
    end = HvRangeEndOf(base, size);
    if (end <= base) return 0;                 // wrapped: refuse
    i = HvRangeIndexForPa(r, n, base);
    if (i == HV_RANGE_NONE) return 0;
    return r[i].base < end;
}

#endif // HV_RAMRANGE_H

// hv_hookpool.h - the pure decisions behind the EPT stealth-hook lifecycle.
//
// WHY THIS EXISTS
//
//   The first cut of the EPT hook feature (HV_HYPERCALL_EPT_HOOK / _UNHOOK)
//   allocated out of three fixed 16-entry pools and never gave anything back:
//
//     * HvEptInstallHook took the next slot with `EptHookCount++` and the next
//       shadow page with `ShadowPagesUsed++`, while HvEptRemoveHook cleared
//       only the slot's Active flag. The 16th install was therefore the last
//       this machine would ever perform, even if every one of them had been
//       uninstalled - a stealth feature with a lifetime budget, and any
//       install/uninstall pair a client reasonably expects to be repeatable
//       ends in HV_STATUS_INSUFFICIENT_RESOURCES and looks like a full table.
//     * A 2MB region split by EptRuntimeSplit stayed split for good: the 512
//       4KB leaves were never collapsed back to their original large-page PD
//       entry, and the spare PT page that backed them was never returned.
//     * HvEptRemoveHook left MtfRestorePending alone, and the MTF handler
//       trusted `vcpu->MtfHookIdx` as an index - guarded only by Active. The
//       moment a slot is reusable that guard is not enough: a slot freed by
//       one unhook and taken by the next hook would be restored by a pending
//       single-step from the PREVIOUS occupancy, rewriting the wrong page's
//       EPT entry to the wrong shadow page. Two hooks in one region make it
//       worse still: coalescing the region while a second hook is still live
//       would leave that hook's saved PtePtr aimed into a PT page that has
//       been handed back to the pool.
//
//   Each of those is a decision, not a side effect, so each one lives here as
//   a pure function - the hv_ept_decision.h precedent: no I/O, no VMX
//   intrinsics, no globals, nothing that needs a real multi-CPU boot to
//   execute. tools/unit/hv_hookpool_test.c drives every one of them.
//
// WHAT "PURE" MEANS FOR THE REGION COUNT
//
//   HvHookRegionRefCount is handed a plain array of per-slot region bases plus
//   the occupancy mask, rather than being handed the hook records. The array
//   is rebuilt by the caller from the live records, so there is no second copy
//   of the state to fall out of step with the first; slots whose mask bit is
//   clear are ignored, so a stale base left in a freed slot cannot contribute.
//
// Keep this file ASCII-only and free of OS and firmware dependencies: the EDK2
// build and a plain host unit test both include it.

#ifndef HV_HOOKPOOL_H
#define HV_HOOKPOOL_H

// "No slot". This CANNOT be 0: index 0 is a legitimate slot, and an earlier
// generation of this code used 0 as its "not found" answer, which silently
// made slot 0 unremovable.
#define HV_HOOK_SLOT_NONE 0xFFFFFFFFu

// ── Pool occupancy ──────────────────────────────────────────────────────────
// One 32-bit mask per pool (hook slots, shadow pages, spare PT pages). A mask
// rather than a count is what makes reuse possible at all: a count cannot say
// WHICH entry is free, so the append-only counter it replaced could only ever
// hand out the next index.

// Lowest free slot, or HV_HOOK_SLOT_NONE when the pool is full.
static __inline unsigned int HvHookPoolAlloc(unsigned int usedMask,
                                            unsigned int capacity) {
    unsigned int i;
    if (capacity > 32u) capacity = 32u;   // the mask is 32 bits wide
    for (i = 0; i < capacity; i++) {
        if (!(usedMask & (1u << i)))
            return i;
    }
    return HV_HOOK_SLOT_NONE;
}

static __inline int HvHookPoolInUse(unsigned int usedMask, unsigned int slot) {
    if (slot >= 32u) return 0;
    return (usedMask & (1u << slot)) != 0;
}

static __inline unsigned int HvHookPoolMarkUsed(unsigned int usedMask,
                                                unsigned int slot) {
    if (slot >= 32u) return usedMask;
    return usedMask | (1u << slot);
}

static __inline unsigned int HvHookPoolRelease(unsigned int usedMask,
                                               unsigned int slot) {
    if (slot >= 32u) return usedMask;
    return usedMask & ~(1u << slot);
}

// Index of the pool entry holding `value`, or HV_HOOK_SLOT_NONE. Used to give a
// spare PT page back to the pool it came from: the pool slot is not recorded
// in the EPT's split record, because an init-time split (a 2MB region that
// straddles a RAM boundary) legitimately owns a PT page from the allocator
// instead, and that one must be freed rather than returned. Finding it by value
// makes the two cases tell themselves apart with no extra state.
//
// `value` is compared as an integer address; a NULL pool entry never matches a
// non-NULL value.
static __inline unsigned int HvHookPoolFindPtr(const void *const *pool,
                                              unsigned int capacity,
                                              const void *value) {
    unsigned int i;
    if (capacity > 32u) capacity = 32u;
    if (value == 0) return HV_HOOK_SLOT_NONE;
    for (i = 0; i < capacity; i++) {
        if (pool[i] == value) return i;
    }
    return HV_HOOK_SLOT_NONE;
}

// ── Region reference counting ───────────────────────────────────────────────
// A 2MB region may hold more than one hooked page, and it is split at most
// once. The split is undone when the LAST hook in that region goes away, and
// not before - see the coalescing note above for what breaking this costs.

// How many occupied slots name this region.
static __inline unsigned int HvHookRegionRefCount(
        const unsigned long long *regionBases,
        unsigned int usedMask,
        unsigned long long regionBase,
        unsigned int capacity) {
    unsigned int i, refs = 0;
    if (capacity > 32u) capacity = 32u;
    for (i = 0; i < capacity; i++) {
        if (!(usedMask & (1u << i))) continue;      // stale base ignored
        if (regionBases[i] == regionBase) refs++;
    }
    return refs;
}

// The count a region is left with once one of its hooks is removed. Saturating,
// because a count that is already 0 means the bookkeeping was already wrong and
// wrapping it to 0xFFFFFFFF would install a permanent phantom reference.
static __inline unsigned int HvHookRegionRefAfterRemoval(unsigned int refsBefore) {
    return refsBefore > 0u ? refsBefore - 1u : 0u;
}

// Collapse the region back to its original 2MB PD entry?
//
// Both halves matter. `refsAfter != 0` means another hook still shadows a page
// in this region: collapsing would free the PT page its saved PtePtr points
// into. `originalPdValue == 0` means this split was made at init for a region
// that straddles a RAM boundary - it was never a large page, so there is no
// large-page entry to restore and its PD entry must keep pointing at the PT.
static __inline int HvHookRegionShouldCoalesce(unsigned int refsAfter,
                                              unsigned long long originalPdValue) {
    return refsAfter == 0u && originalPdValue != 0ull;
}

// Index of the split record covering `regionBase`, or HV_HOOK_SLOT_NONE.
static __inline unsigned int HvHookFindRegionIndex(
        unsigned long long regionBase,
        const unsigned long long *splitRegionBases,
        unsigned int count) {
    unsigned int i;
    for (i = 0; i < count; i++) {
        if (splitRegionBases[i] == regionBase) return i;
    }
    return HV_HOOK_SLOT_NONE;
}

// ── Epoch-tagged slot references ────────────────────────────────────────────
// A pending MTF restore names a slot that must still be the SAME hook when the
// single-step finally arrives. An index alone cannot express that: the slot may
// have been released by an unhook and taken by the next hook in the meantime,
// and restoring the previous occupancy's shadow page would rewrite the wrong
// EPT entry. Each install stamps a fresh, monotonically increasing epoch into
// its slot; the tag carries both halves, and a mismatch is a rejection rather
// than a restore.

static __inline unsigned long long HvHookTagMake(unsigned int slot,
                                                unsigned int epoch) {
    return ((unsigned long long)epoch << 32) | (unsigned long long)slot;
}

static __inline unsigned int HvHookTagSlot(unsigned long long tag) {
    return (unsigned int)(tag & 0xFFFFFFFFull);
}

static __inline unsigned int HvHookTagEpoch(unsigned long long tag) {
    return (unsigned int)(tag >> 32);
}

// TRUE only when the tag names THIS slot at THIS epoch - the check that makes a
// recycled slot safe.
static __inline int HvHookTagMatches(unsigned long long tag, unsigned int slot,
                                     unsigned int epoch) {
    return HvHookTagSlot(tag) == slot && HvHookTagEpoch(tag) == epoch;
}

// ── Atomic, bounded claims ──────────────────────────────────────────────────
//
// The masks above are read-modify-write by nature, and a read-then-write is not
// a claim. Two processors that read the same mask before either writes it
// compute the SAME free slot, copy their hook bytes into the SAME shadow page
// and take the same pool entry: one hook is silently lost while every count
// still looks consistent. The decision therefore has to be applied in one step
// that observes and publishes at once -
//
//     InterlockedCompareExchange(mask, old | bit, old)
//
// - and a compare-exchange that fails means the mask moved between the read and
// the write, so the decision is re-made against the new value. That is the
// whole retry, and it is BOUNDED. Nothing here waits: no processor blocks on
// another processor's progress, no state is held across a fault, and there is
// no timeout anywhere because there is no wait to time out. The bound exists so
// that a pathological interleaving cannot spin at all; exhausting it returns
// HV_HOOK_SLOT_NONE (or leaves the bit set), which fails the caller closed with
// a retryable status. A lock - with or without a timeout - is the freeze this
// design exists to avoid, and an unbounded wait inside the hypervisor is a
// frozen machine.
//
// The compare-exchange is spelled with the WDK name because that is the one
// spelling every build path can reach: ntddk.h provides it in the WDK tree,
// tools/syntax-check/ntddk.h maps it for the syntax gate, and HvEfi/hvdefs.h
// aliases it to the MSVC intrinsic beside the InterlockedIncrement alias it
// already carries. The pointer type is `volatile long *`, the type the
// intrinsic itself is declared with; a caller whose field is typed `LONG` casts
// at the call site, because EDK2's LONG is `int` while the intrinsic wants
// `long`.

#define HV_HOOK_CLAIM_MAX_TRIES 64u

// Apply ONE claim decision atomically: set `slot` in the mask, but only if the
// mask still holds the value that decision was made against. TRUE when this
// processor owns the slot.
//
// This - not the scan - is what makes two racing claims land on different
// slots, and the unit suite demonstrates precisely that by taking a decision
// from a mask and then applying it against a mask another claimant has already
// moved.
static __inline int HvHookPoolClaimCas(volatile long *mask,
                                      unsigned int expected,
                                      unsigned int slot) {
    unsigned int want = HvHookPoolMarkUsed(expected, slot);
    if (slot >= 32u || want == expected) return 0;   // out of range: no claim
    return InterlockedCompareExchange(mask, (long)want, (long)expected) ==
           (long)expected;
}

// The lowest free slot, CLAIMED atomically, or HV_HOOK_SLOT_NONE. Bounded: at
// most HV_HOOK_CLAIM_MAX_TRIES attempts, and it never waits.
static __inline unsigned int HvHookPoolClaim(volatile long *mask,
                                            unsigned int capacity) {
    unsigned int tries;
    if (capacity > 32u) capacity = 32u;
    for (tries = 0; tries < HV_HOOK_CLAIM_MAX_TRIES; tries++) {
        unsigned int observed = (unsigned int)*mask;
        unsigned int slot = HvHookPoolAlloc(observed, capacity);
        if (slot == HV_HOOK_SLOT_NONE) return HV_HOOK_SLOT_NONE;   // full
        if (HvHookPoolClaimCas(mask, observed, slot)) return slot;
        // The mask moved: another processor claimed or released in between.
        // The decision is stale, so it is re-made - not waited on.
    }
    return HV_HOOK_SLOT_NONE;
}

// Give a slot back atomically. Two processors removing different hooks at once
// would otherwise each write back a mask they read before the other's release,
// and one of the two slots would stay marked used for the life of the boot.
static __inline void HvHookPoolReleaseAtomic(volatile long *mask,
                                            unsigned int slot) {
    unsigned int tries;
    if (slot >= 32u) return;
    for (tries = 0; tries < HV_HOOK_CLAIM_MAX_TRIES; tries++) {
        unsigned int observed = (unsigned int)*mask;
        unsigned int want = HvHookPoolRelease(observed, slot);
        if (want == observed) return;                    // already clear
        if (InterlockedCompareExchange(mask, (long)want,
                                       (long)observed) == (long)observed)
            return;
    }
    // Bounded. A release that lost every race leaves one bit set, which costs
    // one pool entry for the rest of the boot. It cannot hand the same entry
    // out twice, so this is the safe direction to fail in - and it is not
    // retried for ever.
}

// ── Region split claims ─────────────────────────────────────────────────────
//
// A 2MB region is split at most once. Two processors that both find the region
// still a large page each allocate a PT page, each append a split record for
// the SAME region, and each write the same PD entry. The second record is a
// duplicate, and a duplicate is not a bookkeeping nit: SplitCount stops
// describing the table, and the region reference-count rule above stops
// describing reality - coalescing removes one record and frees one PT page
// while the other record still names a page the pool has already been told
// about, so that page can be handed out as a live PT page while still in use.
//
// So the record has to be created exactly once per region, and "exactly once"
// needs a claim: one word per EPT holding the tag of the region whose split is
// in flight, and 0 when none is.

// The tag that stands for one 2MB region in the claim word.
//
// `regionBase >> 21` is already unique per 2MB region. The "+ 1" makes region 0
// - real memory at physical address zero - a claim rather than the empty
// sentinel (the same mistake as a 0-valued slot sentinel; see HV_HOOK_SLOT_NONE).
// Two distinct regions would have to be 2^53 bytes apart to collide here, which
// is wider than the 52-bit physical address space an EPT can map.
static __inline unsigned int HvSplitRegionTag(unsigned long long regionBase) {
    return (unsigned int)(regionBase >> 21) + 1u;
}

// TRUE when the claim word names the region whose tag is `tag` - i.e. when the
// split in flight is THIS processor's region, rather than some other region's.
static __inline int HvSplitClaimNames(unsigned int claimWord,
                                     unsigned int tag) {
    return claimWord != 0u && claimWord == tag;
}

// What this processor may do about a region it has to split. Total and pure, so
// every combination of (record present?, table room?, claim free?) lands on
// exactly one answer and the unit suite can enumerate the cross product.
#define HV_SPLIT_DO          0   // no record, claim free: split and record it
#define HV_SPLIT_REUSE       1   // a record covers this region: use its PT page
#define HV_SPLIT_RETRY_SAME  2   // another processor is splitting THIS region
#define HV_SPLIT_RETRY_OTHER 3   // another processor is splitting a different one
#define HV_SPLIT_EXHAUSTED   4   // the split table is full

// The claim is checked FIRST, and that order is load-bearing rather than
// stylistic. What the claim protects is not only the record: the record's PT
// page holds the leaf a hook is installed into, and the last unhook in a region
// hands that page back. A processor that touched the leaf while holding no
// claim could therefore write into a page another processor had already
// returned to the pool - a stray leaf value inside a page that is about to be
// reissued as some other region's PT. So a taken claim refuses EVERY action on
// the region, including the reuse of an existing record, and "the claim is
// free" is a precondition for all of them.
static __inline int HvSplitDecide(unsigned int recordIndex,
                                  unsigned int recordCount,
                                  unsigned int capacity,
                                  unsigned int claimWord,
                                  unsigned int tag) {
    if (HvSplitClaimNames(claimWord, tag)) return HV_SPLIT_RETRY_SAME;
    if (claimWord != 0u) return HV_SPLIT_RETRY_OTHER;
    // No claim is in flight, so the record table is stable for this decision.
    // A committed record means the region is already split: attach to that PT
    // page instead of making a second one. It is checked before the capacity
    // because a full table is no obstacle to reusing an existing record.
    if (recordIndex != HV_HOOK_SLOT_NONE) return HV_SPLIT_REUSE;
    if (recordCount >= capacity) return HV_SPLIT_EXHAUSTED;
    return HV_SPLIT_DO;
}

// Take the split claim for `tag`, atomically and without waiting. TRUE when
// this processor owns the split. FALSE means another processor owns one - this
// region's or another's - which the caller fails closed on; the client retries.
static __inline int HvSplitClaimTake(volatile long *claim, unsigned int tag) {
    if (tag == 0u) return 0;              // never claim with the empty tag
    return InterlockedCompareExchange(claim, (long)tag, 0L) == 0L;
}

// Release it, once the record is committed and therefore visible. A plain store
// rather than a read-modify-write: only the owner ever clears it, and it is
// cleared unconditionally.
static __inline void HvSplitClaimRelease(volatile long *claim) {
    *claim = 0L;
}

// The record choke point's rule: may this processor append a record for its
// region? FALSE when one already exists - a second record for the same region
// is the duplicate described above.
static __inline int HvSplitRecordAllowed(unsigned int existingRecordIndex,
                                        unsigned int recordCount,
                                        unsigned int capacity) {
    if (existingRecordIndex != HV_HOOK_SLOT_NONE) return 0;
    if (recordCount >= capacity) return 0;
    return 1;
}

#endif // HV_HOOKPOOL_H

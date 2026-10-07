// hv_ept_gen.h - the EPT mutation generation: how one processor tells every
// other processor that its cached EPT translations are stale.
//
// WHY THIS EXISTS
//
//   INVEPT is a LOCAL operation. INVEPT_ALL_CONTEXTS invalidates the cached EPT
//   translations of the logical processor that executes it, and of no other
//   (Intel SDM Vol 3C 28.3.3 - the invalidation is performed on the current
//   logical processor). Every EPT mutation in both trees ended with
//   HvEptInvalidate() and nothing else, which was correct for as long as the
//   only mutations happened before VMLAUNCH: every translation cache was cold,
//   so no other processor could be holding a stale translation to miss.
//
//   EPT stealth hooks (HV_HYPERCALL_EPT_HOOK / _UNHOOK, plus the MTF restore
//   that follows a read or a write of a hooked page) ended that. They mutate
//   live EPT entries while the other processors are executing the guest. A
//   processor that is never told cannot invalidate, so it keeps using the
//   translation it cached:
//
//     * a hook installed on one processor need not fire on another, and
//     * a page restored by the MTF path can stay shadowed everywhere else.
//
//   The hook is then not merely late - it is inconsistently effective across
//   processors, which is observable, and the exact opposite of the stealth
//   property it was installed to provide.
//
// WHY A GENERATION COUNTER AND NOT AN IPI
//
//   Broadcasting the invalidation is the obvious fix and it CANNOT BE DONE
//   SAFELY in this architecture. Attempting it is a freeze, so this is a design
//   constraint rather than an optimisation:
//
//     * A remote processor is executing the GUEST - it is in VMX non-root.
//       INVEPT is a VMX instruction; executed in non-root it raises #UD in the
//       guest, which is a bugcheck in the WDK tree and a firmware-level crash
//       in the DXE tree. A remote processor therefore cannot simply be told to
//       run HvEptFlushLocal().
//     * An IPI or an AP procedure call does not reach root either: the
//       interrupt is delivered to the guest, whose own handler runs it. In the
//       WDK tree KeIpiGenericCall then waits for a rendezvous that can never
//       complete - a hard hang with the machine still running. In the DXE tree
//       StartupAllAPs dispatches firmware code onto an AP that is in non-root
//       as well, with the same #UD.
//     * HvEfiOnExitBootServices is documented as memory-stores-only for the
//       same reason: any firmware call from the ExitBootServices callback can
//       deadlock this firmware and reboot-loop the machine.
//
//   The only moment a processor is guaranteed to be in VMX root - and is
//   therefore able to invalidate its own caches - is when it takes a VM exit of
//   its own. That is the mechanism here: a monotonic generation, published on
//   every mutation, that each processor compares against the value it last saw.
//   A processor that is behind invalidates at its next exit. Staleness is
//   bounded by one exit instead of by the lifetime of the boot.
//
// INVARIANT - THE ORDERING RULE (this is the part that is easy to get wrong)
//
//   The publish MUST come AFTER the mutation it announces - after the last EPT
//   entry has been written - and every mutation MUST be followed by one.
//
//   The tempting reading is the reverse: "publish first, so no processor can be
//   mid-walk when the change lands". That is backwards, and backwards is
//   unbounded staleness:
//
//     * A publish is only a signal. What makes a peer coherent is the INVEPT it
//       then runs at its own next exit, and that flush re-walks the EPT. If the
//       publish precedes the mutation, a peer can take its exit in between: it
//       reads the new generation, flushes, re-walks a page table that has not
//       been changed yet, caches the OLD mapping - and records the new
//       generation as seen. Its recorded value already matches the current one,
//       so nothing will ever invalidate it again. That processor is stale for
//       the rest of the boot.
//
//     * With the publish after the mutation, every flush the publish provokes is
//       necessarily later than the completed change, so the re-walk sees the new
//       mapping. A processor that cached the old mapping before the publish is
//       simply one exit behind - which is the bound this design promises.
//
//   HvEptInvalidate() obeys this by construction: callers call it after the
//   entries are written, and it publishes and then flushes locally, so its own
//   flush also re-walks the completed change. A mutation that is published
//   without any following flush (HvEptPublishMutation() alone, as at
//   HvEfiOnExitBootServices) is correct for the same reason - the peer flushes
//   at its next exit, which is by then after the mutation.
//
// WHY EQUALITY AND NOT ORDERING, AND WHY THE COUNTER IS 32 BITS
//
//   The test is `seen != current`, not `seen < current`. Ordering is wrong
//   across a wrap: after 2^32 mutations the counter returns to 0, and an
//   ordering test would then report every processor as permanently up to date.
//   Equality stays correct through the wrap and costs the same single compare.
//
//   The counter is 32 bits because that is the width for which BOTH trees have
//   an atomic increment available on every build path - InterlockedIncrement /
//   _InterlockedIncrement, already used by non-DBG code in each. The 64-bit
//   spellings are reachable only behind `#if DBG` in the EFI tree and are not
//   part of the shipping syntax or gate build.
//
//   The increment must be atomic. Two processors can publish concurrently - a
//   hypercall on one while the other runs the MTF restore for a hook hit - and
//   a read-modify-write that lost one update would leave the generation
//   unchanged for a mutation that really happened. A processor that had already
//   recorded that unchanged value would never flush: unbounded staleness again,
//   this time intermittently.
//
//   What 32 bits costs: a processor that took no VM exit at all while 2^32
//   mutations were published would find the counter wrapped back to the value
//   it holds and would not flush. 2^32 mutations is billions of hook installs,
//   or hook hits, against a processor that is running a live guest and taking
//   no exit for the whole time - not a state this hypervisor can be in. The
//   predicate is written against `unsigned long long` so a future 64-bit
//   counter needs no change here; widening is injective, so equality survives
//   any narrower field width.
//
// WHAT THIS HEADER MUST NOT DO
//
//   No VMX intrinsics, no globals, no I/O, no tree headers - hv_ept_decision.h
//   is the precedent and for the same reason. This decides whether a remote
//   processor ever observes a mapping change, and the only place that can be
//   exercised without a real multi-CPU boot is the off-target unit suite
//   (tools/unit/hv_ept_gen_test.c, run against both trees).
//
// Keep this file ASCII-only and free of OS and firmware dependencies: the EDK2
// build, the WDK build and a plain host unit test all include it.

#ifndef HV_EPT_GEN_H
#define HV_EPT_GEN_H

// The next generation. Unsigned arithmetic, so the wrap is defined - and the
// equality predicate below stays correct through it, which an ordering test
// would not.
static __inline unsigned long long HvEptGenNext(unsigned long long current) {
    return current + 1ULL;
}

// Non-zero when `seen` is not the currently published generation, i.e. when the
// calling processor must invalidate before it trusts any cached EPT
// translation.
//
// `seen` is 0 for a processor that has never synchronised, and the counter also
// starts at 0, so "0 against 0" correctly reports nothing to do before the
// first mutation. After that first publish the generation is 1 and every
// unsynchronised processor reports stale.
static __inline int HvEptGenNeedsFlush(unsigned long long seen,
                                       unsigned long long current) {
    return seen != current;
}

#endif // HV_EPT_GEN_H

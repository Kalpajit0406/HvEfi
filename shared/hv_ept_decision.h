// hv_ept_decision.h — pure decision function for the EPT violation handler.
//
// The brick-prevention logic in HandleEptViolation is extracted into this one
// header so it can be unit-tested exhaustively off-target, with no VMX
// intrinsics and no __vmx_vmread/vmwrite dependency. tools/unit drives every
// (qual, entry-state) tuple through HvEptDecide and checks the result against
// the invariants that make bare-metal boot safe.
//
// WHY THIS IS SHARED, NOT PER-TREE
//
// The decision is the single brick-critical branch in the whole hypervisor: it
// decides whether a VM exit ends in "resume the guest" or "inject a fault into
// the guest". Before this header it existed twice - once in HvEfi/hv_exit.c
// (Pass 78, then widened by Pass 80) and once in HvDrv/hv_exit.c (still the
// narrow pre-Pass-78 form). Two copies of a branch whose wrong answer is a
// hard hang is exactly the drift the PiDDB AVL mirror was pinned shut for in
// Pass 76. Both trees now call HvEptDecide, and one test covers both.
//
// Invariants (what the tests verify):
//
//   (A) For every GPA with an entry in our EPT (entryExists = TRUE), the
//       function MUST return handled = TRUE and injectPf = FALSE.
//       Reason: injecting #PF for a page we own creates an infinite loop in
//       EFI DXE context — the firmware's #PF handler cannot fix EPT
//       restrictions, the instruction retries, the same EPT violation fires,
//       and the machine hangs. Three bare-metal Dell bricks confirmed this.
//
//   (B) For every write access to a page tagged EPT_DECOY_TAG, Write must be
//       granted. (Preserves the decoy-write detection channel.)
//
//   (C) For every other access, grant the attempted bits: R always, W if the
//       access was a write, X if the access was an instruction fetch.
//
//   (D) When no entry exists (entryExists = FALSE), the function MUST set
//       injectPf = TRUE and return handled = FALSE. (Unmapped GPAs beyond
//       HostPml4Units × 512 GB fall here; the guest sees a conventional #PF
//       instead of an opaque EPT violation.)
//
//   (E) An instruction fetch from a decoy-redirected entry must NEVER be
//       granted Execute. Such an entry's PhysAddr points at a decoy page whose
//       contents are RDRAND fill, so granting X makes the CPU execute random
//       bytes: an immediate, unexplainable guest crash. It must also not be
//       #PF'd, because (A)'s loop applies. Injecting #UD is the only remaining
//       option, and it is the good one: the guest's #UD handler runs, the
//       offending instruction does not retry, and the failure is a single
//       deterministic fault instead of a hang or garbage execution.
//       Note this is a DELIBERATE deviation from bare-metal semantics, which
//       would raise #PF here. The architecturally-correct answer is a
//       guaranteed hang, so we take the one that terminates.
//
// Qualification bits (SDM 27.2.1 Table 27-9):
//   bit 0 — data read attempted
//   bit 1 — data write attempted
//   bit 2 — instruction fetch attempted
//
// Reads bits 1 and 2; bit 0 is implied by "neither 1 nor 2".

#ifndef HV_EPT_DECISION_H
#define HV_EPT_DECISION_H

// Decision result. All fields are OR-masks the caller applies to the live
// EPT entry (or ignored when a fault is injected).
typedef struct _HV_EPT_DECISION {
    unsigned char grantRead;     // 1 → set EPT_READ    on the entry
    unsigned char grantWrite;    // 1 → set EPT_WRITE   on the entry
    unsigned char grantExecute;  // 1 → set EPT_EXECUTE on the entry
    unsigned char injectPf;      // 1 → inject #PF (no entry we own)
    unsigned char injectUd;      // 1 → inject #UD (fetch from decoy bait)
    unsigned char handled;       // 1 → resume guest, 0 → devirtualise
} HV_EPT_DECISION;

// Pure decision function. No VMX ops, no globals, no I/O.
//
//   qual         exit qualification (only the low 3 bits are read)
//   entryExists  did HvEptLookup4K return non-NULL for this GPA
//   entryXWR     low 3 bits of the entry's permission flags (EPT_READ /
//                EPT_WRITE / EPT_EXECUTE) — informational only; the grants
//                below are OR-masks applied to the live entry, so starting
//                from whatever the entry already holds is correct and the
//                caller does not need to pre-clear anything.
//   entryDecoy   non-zero if the entry has EPT_DECOY_TAG set — i.e. the entry
//                redirects to decoy bait rather than to its own physical page.
//                Ignored when entryExists is 0.
static __inline HV_EPT_DECISION HvEptDecide(unsigned long long qual,
                                            unsigned char entryExists,
                                            unsigned char entryXWR,
                                            unsigned char entryDecoy) {
    HV_EPT_DECISION out;
    out.grantRead    = 0;
    out.grantWrite   = 0;
    out.grantExecute = 0;
    out.injectPf     = 0;
    out.injectUd     = 0;
    out.handled      = 0;

    if (!entryExists) {
        // No entry in our EPT — unmapped region. Inject conventional #PF so
        // the guest sees a normal page fault, not an opaque EPT violation.
        // This is the one case where we do NOT resume: there is no entry to
        // fix, and the guest owns the decision about what an unmapped GPA
        // means (map it, or fault).
        out.injectPf = 1;
        return out;
    }

    (void)entryXWR;  // the grants below are OR-masks onto the live entry, so
                     // the current permission bits do not change the answer.
                     // Callers pass them for test visibility and symmetry
                     // with HvEptLookup4K.

    int isWrite = (qual & 2ULL) != 0;
    int isFetch = (qual & 4ULL) != 0;

    // Invariant (E): never make decoy bait executable. `isWrite` is excluded
    // from the fetch test so a (physically impossible) qualification carrying
    // both bits still takes the write path, which keeps invariant (B) true for
    // every input rather than only for the ones hardware actually produces.
    if (entryDecoy && isFetch && !isWrite) {
        out.injectUd = 1;
        out.handled  = 1;
        return out;
    }

    // Decoy write path: the bait page is readable-but-not-writable from
    // install, so only writes can violate here. Grant W and leave the
    // DECOY_TAG alone — the caller only ORs the permission bits, and
    // Write=1 remaining set is the detection signal for an observer.
    if (entryDecoy && isWrite) {
        out.grantWrite = 1;
        out.handled    = 1;
        return out;
    }

    // Any other access to a page we own: grant R unconditionally (EPT needs
    // R to permit W, and granting R on a pure read is the correct response),
    // W if the access was a write, X if it was an instruction fetch.
    // Reaching this branch with a decoy entry means a read of the bait, which
    // is already permitted — the grant is a no-op that keeps the branch free
    // of special cases.
    out.grantRead    = 1;
    out.grantWrite   = isWrite ? 1 : 0;
    out.grantExecute = isFetch ? 1 : 0;
    out.handled      = 1;
    return out;
}

#endif // HV_EPT_DECISION_H
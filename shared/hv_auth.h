// hv_auth.h - hypercall authentication with the secrets page injected.
//
// WHY
//   Everything standing in front of a hypercall handler — the secrets-page
//   presence check, DETECT, UNLOAD, the session-magic check and the SipHash
//   MAC/sequence authentication — is what a guest can probe. The two trees had
//   their own copies and had drifted: they disagreed on the status for a missing
//   secrets page and on whether the run flag or the magic was checked first for
//   UNLOAD, which changes which answer a probe sees. Neither copy had ever
//   executed off-target.
//
// INJECTION
//   The functions take the resolved secrets page (PHV_SECRETS) as a parameter,
//   exactly as the page-table walk takes a page reader and the copy loop takes a
//   translator. A unit test passes a synthetic HV_SECRETS and runs the real MAC
//   and sequence code; the dispatchers pass GetSecretsPage().
//
// INCLUDE POSITION
//   Include this at the end of a tree's hvdefs.h, after HV_SECRETS and the
//   HV_STATUS_* codes are defined (it uses both) and after hv_siphash.h.
//
// OBSERVABLE CONTRACT
//   - The only sentinel is HV_STATUS_NOT_OURS, which the exit handler turns into
//     a #UD so a probe cannot tell the hypervisor from a bare VMCALL. Anything
//     that is not provably ours must return exactly that, never a distinct code
//     that only a hypervisor could produce: a missing secrets page and a wrong
//     magic are both NOT_OURS, whatever the state.
//   - A correct magic with a wrong MAC is HV_STATUS_ACCESS_DENIED. Only a caller
//     that already holds the session magic (i.e. knows the ticket) can reach it.
//   - A replayed or stale sequence MAC is ACCESS_DENIED and must not consume a
//     sequence number, so a failed guess cannot desynchronise the client.
//   - Success returns HV_STATUS_SUCCESS.

#pragma once

// The value HV_HYPERCALL_DETECT returns for a caller that presents the boot
// magic. It must not be 0 or -1 (the client reads those as "no answer") and must
// not equal the NOT_OURS sentinel, or a valid DETECT would be turned into #UD
// and look like a foreign VMCALL. Applied wherever the nonce is generated.
static __inline UINT64 HvSanitizeNonce(UINT64 nonce) {
    if (nonce <= 0xFF || nonce == (UINT64)-1 || nonce == HV_STATUS_NOT_OURS)
        return 0x100;
    return nonce;
}

// DETECT: the only unauthenticated call. The magic must be the ticket-derived
// boot magic; anything else, including a missing secrets page, is "not ours".
static __inline UINT64 HvAuthDetect(PHV_SECRETS secrets, UINT64 magic) {
    if (!secrets)                     return HV_STATUS_NOT_OURS;
    if (magic != secrets->BootMagic)  return HV_STATUS_NOT_OURS;
    return HV_STATUS_SUCCESS;
}

// UNLOAD: session magic, then the sequence-independent unload MAC, then the
// running flag. The magic is checked first so the answer never depends on the
// run state — a wrong magic is #UD before and after teardown alike.
static __inline UINT64 HvAuthUnload(PHV_SECRETS secrets, BOOLEAN running,
                                    UINT64 magic, UINT64 callerMac) {
    if (!secrets)                        return HV_STATUS_NOT_OURS;
    if (magic != secrets->SessionMagic)  return HV_STATUS_NOT_OURS;
    if (callerMac != secrets->UnloadMac) return HV_STATUS_ACCESS_DENIED;
    if (!running)                        return HV_STATUS_ACCESS_DENIED;
    return HV_STATUS_SUCCESS;
}

// Every other call: session magic, then a MAC over the full parameter tuple plus
// the next sequence number. The counter is advanced with a compare-exchange so
// two CPUs cannot both accept the same sequence, and it is only advanced once
// the MAC verifies — a rejected call leaves it untouched, so a replay fails and
// a failed attempt cannot consume a sequence number.
static __inline UINT64 HvAuthCall(PHV_SECRETS secrets, UINT64 magic, UINT64 id,
                                  UINT64 p1, UINT64 p2, UINT64 p3Real,
                                  UINT64 callerMac) {
    if (!secrets)                       return HV_STATUS_NOT_OURS;
    if (magic != secrets->SessionMagic) return HV_STATUS_NOT_OURS;

    for (;;) {
        UINT64 cur  = (UINT64)secrets->LastSeq;
        UINT64 next = cur + 1;
        UINT64 words[6] = { magic, id, p1, p2, p3Real, next };
        UINT64 expected = HvMacTuple(secrets->SessionKey0, secrets->SessionKey1,
                                     words);
        if (callerMac != expected)
            return HV_STATUS_ACCESS_DENIED;
        if (InterlockedCompareExchange64(&secrets->LastSeq,
                                         (LONG64)next, (LONG64)cur) == (LONG64)cur)
            break;
    }
    return HV_STATUS_SUCCESS;
}

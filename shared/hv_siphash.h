// hv_siphash.h - SipHash-2-4 keyed PRF for hypercall authentication.
//
// Shared between the kernel driver (HvDrv) and the usermode client (Hypervisor).
// Provides a non-invertible MAC: knowing (message, MAC) does not reveal the key.
//
// There is deliberately NO compiled-in pre-shared key. The session key is
// derived at boot from a ticket that is provisioned at install time (see
// HvDeriveSession) and lives outside both binaries. This header therefore
// contains only the PRF, plus the small derivations both sides must agree on.
//
// Reference: Jean-Philippe Aumasson & Daniel J. Bernstein, "SipHash: a fast
// short-input PRF" (2012). https://131002.net/siphash/

#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <stdint.h>
#include <stddef.h>
typedef unsigned __int64 UINT64;
#endif

// Cross-compiler force-inline hint. MSVC spells it __forceinline; GCC/Clang
// prefer `inline __attribute__((always_inline))`. On MSVC+WDK the EDK2 build
// defines __forceinline natively; on clang-targeting-windows-gnu (our cross
// build), mingw's _mingw.h expands __forceinline to `extern __inline__ ...`
// which collides with a leading `static`. Routing through this macro keeps
// both toolchains happy without touching the hv_siphash.h call sites.
#if defined(_MSC_VER) && !defined(__clang__)
#  define HV_FORCEINLINE static __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#  define HV_FORCEINLINE static inline __attribute__((always_inline))
#else
#  define HV_FORCEINLINE static inline
#endif

#define HV_ROTL64(x, b)  (((x) << (b)) | ((x) >> (64 - (b))))

#define HV_SIPROUND(v0, v1, v2, v3) do {   \
    (v0) += (v1);                           \
    (v1) = HV_ROTL64((v1), 13);             \
    (v1) ^= (v0);                           \
    (v0) = HV_ROTL64((v0), 32);             \
    (v2) += (v3);                           \
    (v3) = HV_ROTL64((v3), 16);             \
    (v3) ^= (v2);                           \
    (v0) += (v3);                           \
    (v3) = HV_ROTL64((v3), 21);             \
    (v3) ^= (v0);                           \
    (v2) += (v1);                           \
    (v1) = HV_ROTL64((v1), 17);             \
    (v1) ^= (v2);                           \
    (v2) = HV_ROTL64((v2), 32);             \
} while (0)

// SipHash-2-4 over an arbitrary byte string. k0/k1 are the 128-bit key.
// Little-endian block loads (x64 is LE), byte-by-byte so it is also correct
// if this is ever compiled for a big-endian target.
HV_FORCEINLINE UINT64 HvSipHash(UINT64 k0, UINT64 k1,
                                      const void *msg, size_t len) {
    const unsigned char *m = (const unsigned char *)msg;

    UINT64 v0 = k0 ^ 0x736f6d6570736575ULL;
    UINT64 v1 = k1 ^ 0x646f72616e646f6dULL;
    UINT64 v2 = k0 ^ 0x6c7967656e657261ULL;
    UINT64 v3 = k1 ^ 0x7465646279746573ULL;

    size_t blocks = len / 8;
    for (size_t i = 0; i < blocks; i++) {
        UINT64 mi = 0;
        for (int b = 0; b < 8; b++)
            mi |= (UINT64)m[i * 8 + b] << (8 * b);
        v3 ^= mi;
        HV_SIPROUND(v0, v1, v2, v3);
        HV_SIPROUND(v0, v1, v2, v3);
        v0 ^= mi;
    }

    // Final block: remaining <8 bytes plus the length in the top byte.
    UINT64 last = ((UINT64)(len & 0xFF)) << 56;
    const unsigned char *tail = m + blocks * 8;
    size_t rem = len & 7;
    for (size_t i = 0; i < rem; i++)
        last |= (UINT64)tail[i] << (8 * i);

    v3 ^= last;
    HV_SIPROUND(v0, v1, v2, v3);
    HV_SIPROUND(v0, v1, v2, v3);
    v0 ^= last;

    v2 ^= 0xFF;
    HV_SIPROUND(v0, v1, v2, v3);
    HV_SIPROUND(v0, v1, v2, v3);
    HV_SIPROUND(v0, v1, v2, v3);
    HV_SIPROUND(v0, v1, v2, v3);

    return v0 ^ v1 ^ v2 ^ v3;
}

// Single 8-byte message (kept for existing call sites).
HV_FORCEINLINE UINT64 HvSipHash64(UINT64 k0, UINT64 k1, UINT64 msg) {
    return HvSipHash(k0, k1, &msg, sizeof(msg));
}

// ── Session derivations (must match exactly between driver and client) ──────
//
// The ticket is a 32-byte install-time secret (4 words). The nonce is public
// (HV_HYPERCALL_DETECT returns it); it only serves to rotate the session key
// every boot. The key is therefore only recoverable by someone who holds the
// ticket.

HV_FORCEINLINE void HvDeriveSession(const UINT64 ticket[4], UINT64 nonce,
                                          UINT64 *key0, UINT64 *key1) {
    *key0 = HvSipHash(ticket[0], ticket[1], &nonce, sizeof(nonce));
    UINT64 inv = ~nonce;
    *key1 = HvSipHash(ticket[2], ticket[3], &inv, sizeof(inv));
}

// Per-boot R10 value registered as the "our hypercall" magic. Not a constant
// any more, so a disassembly of the client does not reveal a static signature.
HV_FORCEINLINE UINT64 HvSessionMagic(UINT64 key0, UINT64 key1) {
    UINT64 tag = 0x4D4147494321ULL;   // 'MAGIC!'
    return HvSipHash(key0, key1, &tag, sizeof(tag));
}

// Boot-time magic for the DETECT handshake, derived directly from the ticket
// (no nonce, since it must be computable before the nonce is known). This
// replaces the old static 'HVMM' constant, so neither binary contains a
// fixed hypervisor signature. Domain-separated from the session MACs via a
// distinct tag.
HV_FORCEINLINE UINT64 HvBootMagic(const UINT64 ticket[4]) {
    UINT64 tag = 0x2147414D54544F42ULL;   // 'BOTTMA\x47!' domain separator
    UINT64 words[5];
    words[0] = ticket[0];
    words[1] = ticket[1];
    words[2] = ticket[2];
    words[3] = ticket[3];
    words[4] = tag;
    return HvSipHash(ticket[0] ^ ticket[2], ticket[1] ^ ticket[3],
                     words, sizeof(words));
}

// MAC over a 6-word tuple: magic, id, p1, p2, p3Real, seq.
// Commits to every word independently (unlike the old XOR fold, which made
// joint-XOR parameter substitution possible without the key).
HV_FORCEINLINE UINT64 HvMacTuple(UINT64 key0, UINT64 key1,
                                       const UINT64 words[6]) {
    return HvSipHash(key0, key1, words, 6 * sizeof(UINT64));
}

// MAC for the devirtualization hypercall.
HV_FORCEINLINE UINT64 HvMacUnload(UINT64 key0, UINT64 key1) {
    UINT64 tag = 0x554E4C4F4144ULL;   // 'UNLOAD'
    return HvSipHash(key0, key1, &tag, sizeof(tag));
}

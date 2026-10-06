// hv_xsave.h - extended-state save-mask decision, shared by both trees.
//
// WHY
//   The VM-exit stub saves the guest's extended state (XSAVE/FXSAVE) into an
//   area reserved below the host stack top. Which components it saves is the
//   g_HvStateSaveMask computed from the live XCR0, and the rule is: a component
//   is included only if its CPUID.0xD offset+size fits the reserved area.
//   XSAVE writes a named component in full, so naming one larger than the
//   buffer would run off the end. Both trees carried that loop as duplicated
//   bodies inside HvRefreshStateSaveMask, with a silent policy failure: a
//   component that did NOT fit was dropped from the mask without anyone
//   noticing — the guest would then be resumed with that component's state
//   never saved and clobbered by the C handler's own SIMD use.
//
//   The decision is extracted here as pure data in / pure data out so
//   tools/unit can drive it: an HV_XSAVE_ENV carries the probe results
//   (CPUID.1 OSXSAVE, live XCR0, per-component size and offset), and the two
//   functions answer "which components fit" and "is the environment fully
//   savable". The trees keep only the probes themselves and the two asm-visible
//   symbols; the policy lives here.
//
//   THE POLICY, now explicit and fail-closed:
//   - HvXsaveMaskReady(areaBytes) is the VMX-start condition. If any
//     XCR0-enabled component does not fit, the hypervisor refuses to start
//     rather than corrupting guest state later. With the current 16 KB area
//     every component defined today fits (AMX tile data ~11 KB included), so
//     this only fires on a genuinely larger future component.
//   - An XSETBV that would enable a component which does not fit is rejected
//     with #GP before it reaches the real XSETBV — the same way an unsupported
//     or non-canonical value is. The guest sees exactly what bare metal shows
//     for an illegal XCR0, and the hypervisor never enters an unsavable state.
//
// INCLUDE POSITION
//   After HV_XSAVE_AREA_BYTES is defined. Uses nothing else.

#pragma once

// One probe snapshot: everything the decision needs, so a test can synthesize
// a CPU with any component layout. Size[n]/Offset[n] are CPUID.0xD:n:EAX/EBX
// and are only meaningful when bit n is set in Xcr0 (and Osxsave is TRUE).
typedef struct _HV_XSAVE_ENV {
    BOOLEAN Osxsave;          // CPUID.1:ECX[27]
    UINT64  Xcr0;             // live XCR0
    UINT32  Size[32];         // CPUID.0xD:n:EAX
    UINT32  Offset[32];       // CPUID.0xD:n:EBX
} HV_XSAVE_ENV;

// The component mask (EDX:EAX low word) for XSAVE into an area of areaBytes:
// XCR0-enabled components whose offset+size fit. This is the exact loop the
// trees ran, extracted; the only judgement is the fit test.
static __inline UINT32 HvXsaveMaskForArea(const HV_XSAVE_ENV *env,
                                          UINT64 areaBytes) {
    UINT32 mask = 0;
    UINT32 bit;

    if (!env->Osxsave)
        return 0;             // no XSAVE at all: caller uses FXSAVE mode

    for (bit = 0; bit < 32; bit++) {
        if (!((env->Xcr0 >> bit) & 1)) continue;

        UINT64 size   = env->Size[bit];
        UINT64 offset = env->Offset[bit];
        if (offset + size <= areaBytes)
            mask |= (1u << bit);
    }
    return mask;
}

// TRUE when every XCR0-enabled component fits the area — the fail-closed
// condition for VMX start. FALSE means at least one enabled component would
// never be saved across an exit.
static __inline BOOLEAN HvXsaveMaskReady(const HV_XSAVE_ENV *env,
                                         UINT64 areaBytes) {
    return HvXsaveMaskForArea(env, areaBytes) == (UINT32)env->Xcr0;
}

// TRUE when enabling `newBits` (an XSETBV delta) would name a component that
// does not fit the area. The XSETBV handler rejects those values with #GP so
// the hypervisor never enters an unsavable state.
static __inline BOOLEAN HvXsaveNewBitsFit(UINT64 newXcr0, const UINT32 *sizes,
                                          const UINT32 *offsets,
                                          UINT64 areaBytes) {
    UINT32 bit;
    for (bit = 0; bit < 32; bit++) {
        if (!((newXcr0 >> bit) & 1)) continue;
        if ((UINT64)offsets[bit] + sizes[bit] > areaBytes)
            return FALSE;
    }
    return TRUE;
}

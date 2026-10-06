// hv_contract.h - hypercall and EPT decisions shared verbatim by both trees.
//
// WHY
//   The validation and dispatch decisions — what a guest may ask for, which
//   hypercall codes exist, which copy status maps to which HV_STATUS, and how
//   many 512GB PML4 units the EPT must map — are things the two trees must agree
//   on exactly, because a guest can observe a disagreement (Pass 34 found the
//   WDK build missing SET_CR3_OFFSET and the two trees returning different
//   statuses for the same request). They lived as duplicated static inline
//   blocks in each hvdefs.h, checked only by reading. One definition here is
//   checked by the identical case sets running in both trees.
//
// INCLUDE POSITION
//   After hv_copy.h: it uses HV_COPY_STATUS. Also after the HV_STATUS_*,
//   HV_HYPERCALL_* and EPT constants, and the PHYSICAL_MEMORY_RANGE type, which
//   each tree's hvdefs.h defines before including this file.

#pragma once

// ── Copy-loop status mapping ────────────────────────────────────────────────
// HvCopyPhysical (hv_copy.h) reports a page-wise copy as HV_COPY_STATUS; a
// hypercall reports it as one of the HV_STATUS_* codes. The two are not the
// same: a physical range that could not be mapped is a bad parameter, while a
// user VA that did not translate — or a fault during the move — is a denied
// access. The EFI build has no mappable-failure path (its identity map cannot
// fail to resolve), so it collapses BadPhys into the denied answer; the WDK
// build distinguishes them. Each tree keeps the mapping its memory model can
// observe; tools/unit/hvcopy_test.c and hvcopy_efi_test.c pin each one.

// ── Hypercall argument validation ───────────────────────────────────────────
// The checks HcReadPhysical/HcWritePhysical run before they reach the page-table
// walk. A legal request is 1..PAGE_SIZE bytes; neither the physical nor the user
// range may wrap; and the whole user range — not merely its start — must lie
// below the user limit, so a request that walks off the end of the user address
// space is rejected instead of being handed to the walk.

#define HV_MAX_USER_VA  0x00007FFFFFFFFFFFULL

// ── VMX capability-MSR control clamping ─────────────────────────────────────
// Both trees clamp every VM-execution control field through this, so the rule
// lives here rather than as a second copy in each hv_vmcs.c. Intel SDM Vol. 3B:
// the low 32 bits of a capability MSR are the "allowed 0" settings (a bit that
// must read 1 when the control is clear) and the high 32 are "allowed 1". A
// requested bit survives only if it is permitted to be 1, and a bit that must
// read 0 is forced there regardless of what was requested.
//
// `capabilityMsr` is the raw MSR value, not an index: reading an MSR needs
// __readmsr, which is a privileged instruction, so the caller supplies the
// value and this stays pure enough to run off-target.
//
// This used to be AdjustControls() in hv_vmcs.c, untested, which is why a
// wrong bit order here would only ever show up as a VM-entry failure on real
// hardware — on a machine where this driver has never run.
static __inline UINT32 HvVmxAdjustControls(UINT32 desired, UINT64 capabilityMsr) {
    return (UINT32)(((UINT64)desired | (UINT32)capabilityMsr) &
                    (UINT32)(capabilityMsr >> 32));
}

// The TRUE_* control MSRs (0x48D-0x490) may only be read when
// IA32_VMX_BASIC[55] is set; otherwise the legacy counterparts live 0xC below.
// The TRUE_* bounds are passed in because the MSR numbers are tree-local
// constants. Returns the MSR index to actually read.
static __inline UINT32 HvVmxControlsMsrIndex(UINT32 trueMsrIndex, UINT64 vmxBasic,
                                             UINT32 firstTrue, UINT32 lastTrue) {
    if (trueMsrIndex >= firstTrue && trueMsrIndex <= lastTrue &&
        !(vmxBasic & (1ULL << 55)))
        return trueMsrIndex - 0xC;
    return trueMsrIndex;
}

static __inline UINT64 HvValidateCopyU64(UINT64 physAddr, UINT64 userVa,
                                         UINT64 size) {
    if (size == 0 || size > PAGE_SIZE)      return HV_STATUS_INVALID_PARAM;
    if (physAddr + size < physAddr)         return HV_STATUS_INVALID_PARAM;
    if (userVa > HV_MAX_USER_VA)            return HV_STATUS_INVALID_PARAM;
    if (userVa + size < userVa)             return HV_STATUS_INVALID_PARAM;
    if (userVa + size > HV_MAX_USER_VA + 1) return HV_STATUS_INVALID_PARAM;
    return HV_STATUS_SUCCESS;
}

// HV_HYPERCALL_SET_CR3_OFFSET: DirectoryTableBase is a small, naturally-aligned
// field in KPROCESS, so the offset must be 8-byte aligned and well under 4 KB.
static __inline BOOLEAN HvCr3OffsetValid(UINT64 offset) {
    return (BOOLEAN)(offset < 0x1000 && (offset & 7) == 0);
}

// HV_HYPERCALL_QUERY_CPID_PAD: the CPUID timing-pad calibration result.
//
// B1 measures pre-VMXON CPUID latency once per boot and stores the outcome in
// g_Hv.CpuidPad*, but until now nothing outside the exit handler could read it.
// An observer harness had no choice but to run itself twice (with and without
// the driver) and difference the two, which cannot separate the driver's pad
// from run-to-run drift. This call returns the measurement directly.
//
// The return value packs four UINT32 fields, low half first:
//
//   bits [15:0]   p50     median measured CPUID latency, in TSC ticks
//   bits [31:16]  p99     99th percentile — the value the pad actually floors to
//   bits [47:32]  target  g_Hv.CpuidPadTarget, the floor CpuidTimingPad applies
//   bits [63:48]  jitter  g_Hv.CpuidPadJitter, the spread added on top of target
//
// target == p99 and jitter == clamp(p99 - p50, 0, 64) after a successful
// calibration; when calibration was skipped (implausible measurement, or a
// build that never ran it) target/jitter hold the HV_CPUID_PAD_DEFAULT_*
// fallbacks and p50/p99 report 0, so a caller can tell "measured" from
// "fallback" without a second round trip.
//
// Read-only and pointer-free: no argument is a guest address, so there is no
// user-pointer validation and no page-table walk on this path — deliberately
// unlike QUERY_EXIT_COUNTS, whose copy is the one part of the debug telemetry
// that can fail.
#define HV_CPID_PAD_P50_SHIFT    0
#define HV_CPID_PAD_P99_SHIFT    16
#define HV_CPID_PAD_TARGET_SHIFT 32
#define HV_CPID_PAD_JITTER_SHIFT 48

static __inline UINT64 HvPackCpuidPad(UINT32 p50, UINT32 p99,
                                      UINT32 target, UINT32 jitter) {
    return ((UINT64)p50   << HV_CPID_PAD_P50_SHIFT)    |
           ((UINT64)p99   << HV_CPID_PAD_P99_SHIFT)    |
           ((UINT64)target << HV_CPID_PAD_TARGET_SHIFT) |
           ((UINT64)jitter << HV_CPID_PAD_JITTER_SHIFT);
}

static __inline UINT32 HvCpuidPadField(UINT64 packed, UINT32 shift) {
    return (UINT32)((packed >> shift) & 0xFFFF);
}

// The complete set of hypercall codes both builds dispatch. HvHypercallDispatch
// rejects anything outside it, and tools/unit asserts the list for both trees so
// they cannot drift apart (the WDK build once lacked SET_CR3_OFFSET).
static __inline BOOLEAN HvHypercallCodeKnown(UINT64 id) {
    switch ((UINT32)id) {
        case HV_HYPERCALL_DETECT:
        case HV_HYPERCALL_READ_PHYS:
        case HV_HYPERCALL_WRITE_PHYS:
        case HV_HYPERCALL_TRANSLATE:
        case HV_HYPERCALL_GET_CR3:
        case HV_HYPERCALL_UNLOAD:
        case HV_HYPERCALL_QUERY_STATUS:
        case HV_HYPERCALL_INVALIDATE_EPT:
        case HV_HYPERCALL_SELFTEST:
        case HV_HYPERCALL_SET_CR3_OFFSET:
        case HV_HYPERCALL_READ_SCATTER:
        case HV_HYPERCALL_CAPABILITIES:
        // Unlike QUERY_EXIT_COUNTS below this one is NOT under #if DBG: the
        // calibration runs in release builds too, so gating it would make the
        // baseline unreadable in exactly the builds that ship.
        case HV_HYPERCALL_QUERY_CPID_PAD:
        case HV_HYPERCALL_READ_VIRT:
        case HV_HYPERCALL_WRITE_VIRT:
        case HV_HYPERCALL_GET_KERNEL_BASE:
            return TRUE;
#if DBG
        case HV_HYPERCALL_QUERY_EXIT_COUNTS:
            return TRUE;
#endif
        default:
            return FALSE;
    }
}

// ── EPT coverage ────────────────────────────────────────────────────────────
// How many 512GB PML4 units the identity EPT must map to cover the RAM map,
// clamped to [1, HV_MAX_EPT_PML4_UNITS]. Unit 0 alone before this: a machine
// whose RAM (or a high device BAR) sits above 512GB had those addresses
// unmapped and the guest faulted on its own memory. Pure so it can be
// unit-tested without a kernel.
// Saturating round-up from an exclusive-end physical address to the number of
// 512GB PML4 units needed.  Extracted so it can be unit-tested independently
// of the PHYSICAL_MEMORY_RANGE iteration that produces maxPhys.
//
// WHY the saturation guard: adding (1<<39)-1 to a maxPhys near UINT64_MAX
// wraps the 64-bit sum to a tiny value, then >> 39 → 0, then the minimum
// clamp returns 1 instead of HV_MAX_EPT_PML4_UNITS.  Any maxPhys at or above
// the 64-unit ceiling already mandates the cap, so guard before the addition.
static __inline UINT32 HvEptPml4UnitsForMaxPhys(UINT64 maxPhys) {
    const UINT64 saturation = (UINT64)HV_MAX_EPT_PML4_UNITS << EPT_PML4_SHIFT;
    if (maxPhys >= saturation) return HV_MAX_EPT_PML4_UNITS;
    {
        UINT32 units =
            (UINT32)((maxPhys + (1ULL << EPT_PML4_SHIFT) - 1) >> EPT_PML4_SHIFT);
        if (units == 0) units = 1;
        return units;
    }
}

static __inline UINT32 HvEptPml4Units(const PHYSICAL_MEMORY_RANGE *ranges,
                                      UINT32 count) {
    UINT64 maxPhys = 0;
    UINT32 i;
    for (i = 0; i < count; i++) {
        UINT64 end = (UINT64)ranges[i].BaseAddress.QuadPart +
                     (UINT64)ranges[i].NumberOfBytes.QuadPart;
        if (end > maxPhys) maxPhys = end;
    }
    return HvEptPml4UnitsForMaxPhys(maxPhys);
}

// ── MTRR-based memory type validation ───────────────────────────────────────
// WHY
//   EptMemTypeForPa used to classify purely from the OS/firmware RAM map:
//   "in RAM → WB, else → UC". That is the WB-as-RAM heuristic, and it has a
//   hole: firmware can mark a RAM-map region as UC/WC via MTRRs (SMM memory,
//   framebuffers, device memory that the OS still lists as RAM). Mapping such
//   a region WB lets the CPU speculate into device registers — side effects on
//   hardware. The fix intersects the RAM map with the MTRR type: MTRR non-WB
//   always wins (MMIO wins → UC), and a region MTRR-classified WB must still
//   appear in the RAM map to earn WB. Unclassifiable → UC (fail closed).
//
// SCOPE
//   Both trees call HvMtrrInitialize once during HvEptInitialize, then
//   HvMtrrTypeForPa for each page/large-page during EPT build. The MSR reads
//   use __readmsr, available in both the WDK and EDK2 (MSVC) builds.
//   Pure computation after init, so the type-resolution half is unit-testable.

// MTRR memory types (Intel SDM Vol 3, 11.11.2)
#define HV_MTRR_TYPE_UC  0
#define HV_MTRR_TYPE_WC  1
#define HV_MTRR_TYPE_WT  4
#define HV_MTRR_TYPE_WP  5
#define HV_MTRR_TYPE_WB  6

// MTRR MSRs (Intel SDM Vol 3, 11.11.1)
#define HV_IA32_MTRR_CAP              0xFE
#define HV_IA32_MTRR_DEF_TYPE         0x2FF
#define HV_IA32_MTRR_PHYSBASE(n)      (0x200 + 2*(n))
#define HV_IA32_MTRR_PHYSMASK(n)      (0x201 + 2*(n))
#define HV_IA32_MTRR_FIX64K_00000     0x250
#define HV_IA32_MTRR_FIX16K_80000     0x258
#define HV_IA32_MTRR_FIX16K_A0000     0x259
#define HV_IA32_MTRR_FIX4K_C0000      0x268  // 0x268..0x26F

#define HV_MTRR_MAX_VARIABLE  16
#define HV_MTRR_FIXED_COUNT   11  // 1 (64K) + 2 (16K) + 8 (4K)

typedef struct _HV_MTRR_STATE {
    UINT8  Enabled;                          // IA32_MTRR_DEF_TYPE[11]
    UINT8  FixedEnabled;                     // IA32_MTRR_DEF_TYPE[10]
    UINT8  DefaultType;                      // IA32_MTRR_DEF_TYPE[7:0]
    UINT8  VarCount;                         // IA32_MTRR_CAP[7:0], capped
    UINT64 VarBase[HV_MTRR_MAX_VARIABLE];     // cached PHYSBASE values
    UINT64 VarMask[HV_MTRR_MAX_VARIABLE];     // cached PHYSMASK values
    UINT64 Fixed[HV_MTRR_FIXED_COUNT];        // cached fixed-MTRR values
} HV_MTRR_STATE;

// Snapshot all MTRRs once. Must run before any HvMtrrTypeForPa call.
// Safe at any IRQL/TPL: __readmsr is a single instruction, no memory access.
static __inline void HvMtrrInitialize(HV_MTRR_STATE *m) {
    UINT64 defType, cap;
    UINT8 i;

    defType = __readmsr(HV_IA32_MTRR_DEF_TYPE);
    m->Enabled      = (UINT8)((defType >> 11) & 1);
    m->FixedEnabled = (UINT8)((defType >> 10) & 1);
    m->DefaultType  = (UINT8)(defType & 0xFF);

    cap = __readmsr(HV_IA32_MTRR_CAP);
    m->VarCount = (UINT8)(cap & 0xFF);
    if (m->VarCount > HV_MTRR_MAX_VARIABLE)
        m->VarCount = HV_MTRR_MAX_VARIABLE;

    for (i = 0; i < m->VarCount; i++) {
        m->VarBase[i] = __readmsr(HV_IA32_MTRR_PHYSBASE(i));
        m->VarMask[i] = __readmsr(HV_IA32_MTRR_PHYSMASK(i));
    }
    // Zero the rest so an uninitialized read can never leak into a decision.
    for (; i < HV_MTRR_MAX_VARIABLE; i++) {
        m->VarBase[i] = 0;
        m->VarMask[i] = 0;
    }

    m->Fixed[0] = __readmsr(HV_IA32_MTRR_FIX64K_00000);
    m->Fixed[1] = __readmsr(HV_IA32_MTRR_FIX16K_80000);
    m->Fixed[2] = __readmsr(HV_IA32_MTRR_FIX16K_A0000);
    for (i = 0; i < 8; i++)
        m->Fixed[3 + i] = __readmsr(HV_IA32_MTRR_FIX4K_C0000 + i);
}

// Fixed-MTRR type for PA < 1MB. Each fixed MSR holds 8 type bytes, one per
// sub-range (SDM Vol 3, Table 11-7).
static __inline UINT8 HvMtrrFixedTypeForPa(const HV_MTRR_STATE *m, UINT64 pa) {
    UINT64 reg;
    UINT32 shift;

    if (pa < 0x80000) {
        // 8 × 64KB ranges in FIX64K_00000
        reg = m->Fixed[0];
        shift = (UINT32)((pa >> 16) & 0x7) * 8;
    } else if (pa < 0xA0000) {
        // 8 × 16KB ranges in FIX16K_80000
        reg = m->Fixed[1];
        shift = (UINT32)(((pa - 0x80000) >> 14) & 0x7) * 8;
    } else if (pa < 0xC0000) {
        // 8 × 16KB ranges in FIX16K_A0000
        reg = m->Fixed[2];
        shift = (UINT32)(((pa - 0xA0000) >> 14) & 0x7) * 8;
    } else {
        // 8 registers × 8 × 4KB ranges for 0xC0000–0xFFFFF
        UINT64 off = pa - 0xC0000;
        UINT32 regIdx = (UINT32)(off >> 15);          // 32KB per register
        reg = m->Fixed[3 + regIdx];
        shift = (UINT32)((off >> 12) & 0x7) * 8;
    }
    return (UINT8)((reg >> shift) & 0xFF);
}

// MTRR memory type for one physical address (SDM Vol 3, 11.11.2.2 precedence).
// Returns one of HV_MTRR_TYPE_*. Callers map non-WB to EPT UC.
static __inline UINT8 HvMtrrTypeForPa(const HV_MTRR_STATE *m, UINT64 pa) {
    UINT8 i;
    UINT8 found = 0xFF;  // no variable MTRR matched yet

    // MTRRs disabled: CPU uses the default type for everything.
    if (!m->Enabled)
        return m->DefaultType;

    // Fixed MTRRs cover the first 1MB when enabled.
    if (pa < 0x100000 && m->FixedEnabled)
        return HvMtrrFixedTypeForPa(m, pa);

    // Variable MTRRs: bit 11 of PHYSMASK = valid. A PA matches when
    // (pa & mask) == (base & mask) over the implemented physical bits.
    // Precedence: UC beats everything, so return it on first sight; among
    // the rest, WT beats WB (SDM 11.11.2.2). WC/WP are returned as-is and
    // the caller maps them to EPT UC.
    for (i = 0; i < m->VarCount; i++) {
        UINT64 mask = m->VarMask[i];
        UINT64 base;
        UINT64 maskBits;
        UINT8  type;

        if (!(mask & (1ULL << 11)))
            continue;  // not valid

        base = m->VarBase[i];
        // Address mask is bits MAXPHYADDR-1:12 (CPUID.80000008 EAX[7:0]);
        // the CPU leaves unimplemented high bits zero. Take every address
        // bit the MSR provides instead of truncating to 35:12, so variable
        // MTRRs covering regions above 64GB still match on modern CPUs.
        maskBits = mask & ~0xFFFULL;
        if ((pa & maskBits) != (base & maskBits))
            continue;

        type = (UINT8)(base & 0xFF);
        if (type == HV_MTRR_TYPE_UC)
            return HV_MTRR_TYPE_UC;
        if (found == 0xFF)
            found = type;
        else if (type == HV_MTRR_TYPE_WT)
            found = HV_MTRR_TYPE_WT;
    }

    if (found != 0xFF)
        return found;
    return m->DefaultType;
}

// ── MTRR + RAM-map intersection policy ──────────────────────────────────────
// Pure: mtrrType from HvMtrrTypeForPa, paInRam from the OS/firmware RAM map.
//   MTRR non-WB  → UC. Firmware wins: a region the MTRRs mark UC/WC/WT/WP is
//                  device/SMM/special memory even if the RAM map lists it.
//   MTRR WB      → WB only if the RAM map covers the PA, else UC. A WB
//                  classification for an address the OS does not call RAM is
//                  unclassifiable → fail closed to UC.
// This is the function the 9-bar asks for: the type classification is the
// intersection, not either source alone.
static __inline UINT32 HvEptMemTypeFromMtrr(UINT8 mtrrType, BOOLEAN paInRam) {
    if (mtrrType != HV_MTRR_TYPE_WB)
        return EPT_MEMORY_TYPE_UC;
    return paInRam ? EPT_MEMORY_TYPE_WB : EPT_MEMORY_TYPE_UC;
}

// ── Scatter-gather read contract ────────────────────────────────────────────
// Wire format for HV_HYPERCALL_READ_SCATTER:
//   p1 = GVA of HV_SCATTER_REQUEST (in caller's virtual address space)
//   p2 = GVA of flat output buffer (Count * PAGE_SIZE max)
//   p3 = Count (must equal Request.Count; redundant but checked)
//
// The hypervisor validates ALL entries before copying any (fail closed):
// if any entry fails HvValidatePhysRange, the whole batch is rejected and no
// bytes are written to the output buffer.
//
// On success, entry i's Size bytes appear at outBuf[i * PAGE_SIZE].
// Entries beyond Count are ignored; the output buffer need not be zeroed.
//
// Both trees (WDK and EFI) share this wire format. The EFI tree reads the
// request struct directly via the identity map (PA == VA); the WDK tree
// translates the guest VA to a physical address before reading.
#define HV_SCATTER_VERSION 1

// Per-entry: read Size bytes from Gpa into outBuf[i * PAGE_SIZE].
typedef struct {
    UINT64 Gpa;    // source guest physical address
    UINT32 Size;   // bytes to read (1..PAGE_SIZE)
    UINT32 Pad;    // must be 0
} HV_SCATTER_DESC;

// Top-level request struct. Caller fills Version, Count, Generation, Descs[0..Count-1].
typedef struct {
    UINT32 Version;    // must equal HV_SCATTER_VERSION
    UINT32 Count;      // number of valid Descs entries (1..HV_SCATTER_MAX_DESCS)
    UINT64 Generation; // monotonic per-frame tag; informational only
    HV_SCATTER_DESC Descs[HV_SCATTER_MAX_DESCS];
} HV_SCATTER_REQUEST;

// Pure validation — no kernel APIs. Returns HV_STATUS_SUCCESS or the first
// field that fails. Both trees call this before any physical access.
static __inline UINT64 HvScatterValidate(const HV_SCATTER_REQUEST *req,
                                         UINT32 expectedCount) {
    UINT32 i;
    if (!req)                              return HV_STATUS_INVALID_PARAM;
    if (req->Version != HV_SCATTER_VERSION) return HV_STATUS_INVALID_PARAM;
    if (req->Count == 0 ||
        req->Count > HV_SCATTER_MAX_DESCS) return HV_STATUS_INVALID_PARAM;
    if (req->Count != expectedCount)       return HV_STATUS_INVALID_PARAM;
    for (i = 0; i < req->Count; i++) {
        if (req->Descs[i].Size == 0 ||
            req->Descs[i].Size > PAGE_SIZE) return HV_STATUS_INVALID_PARAM;
        if (req->Descs[i].Pad != 0)         return HV_STATUS_INVALID_PARAM;
    }
    return HV_STATUS_SUCCESS;
}

// hv_segs.h - GDT descriptor decoding behind an injected table reader.
//
// WHY
//   HvVmcsSetupCpu mirrors the running CPU's segments into VMCS guest state by
//   decoding GDT descriptors. That code builds the exact fields VM-entry
//   validates: one wrong access-rights byte (type, S, DPL, P, L/D/B, G) fails
//   VM-entry outright, and the decoding had never executed — no WDK/EDK2 boot
//   exists to run it. Both trees carried identical copies, so a fix in one
//   would not reach the other.
//
// INJECTION
//   The functions take a ReadGdt callback instead of a raw GDT pointer, the
//   same seam as the page-table walk's reader and the auth header's secrets
//   page. The drivers pass a reader over the live GDT via gdtr.Base; a unit
//   test passes one over a synthetic descriptor array and drives the real
//   decoding, including descriptors that would fault if addressed directly
//   (selector past the GDT limit).
//
// CONTRACT (Intel SDM Vol 3)
//   - Selector 0 is the null selector: base 0, limit 0, access rights 0x10000
//     (bit 16 = unusable, the VMX encoding).
//   - Bits 3:0 of the selector (TI/LDT) make the selector unusable for this
//     build: base 0, limit 0, access rights 0x10000. Both trees treated this as
//     "null" but only for access rights — base returned the GDT word at
//     selector 0 and limit returned 0; they now agree on unusable for all three.
//   - A selector whose offset lands beyond gdtr.Limit is out of the table: the
//     CPU would #GP the load, so the decoders return the unusable encoding
//     rather than reading unallocated memory. The old code read the byte at
//     gdtBase + offset with no bounds check — a real (if never-triggered) OOB.
//   - Access-rights byte layout: [3:0] type, [4] S, [6:5] DPL, [7] P; the upper
//     byte comes from Granularity[7:4]: [12] AVL, [13] L, [14] D/B, [15] G.
//     Bit 16 is the VMX unusable flag, set when P is clear or the selector is
//     null/LDT/out-of-range.
//   - A system descriptor (Access bit 4 clear) is an 8-byte-extended 16-byte
//     descriptor in long mode: its base includes BaseUpper[63:32].
//   - Limit is LimitLow | Granularity[3:0]<<16, shifted by 12 with 0xFFF
//     appended when the G bit is set.

#pragma once

// Descriptor layouts (Intel SDM Vol 3, 3.4.5 / 4.8). Shared so the decoding
// below and both trees' readers agree on the byte order.
#pragma pack(push, 1)
typedef struct _SEGMENT_DESCRIPTOR {
    UINT16 LimitLow;
    UINT16 BaseLow;
    UINT8  BaseMiddle;
    UINT8  Access;
    UINT8  Granularity;
    UINT8  BaseHigh;
} SEGMENT_DESCRIPTOR;

typedef struct _SEGMENT_DESCRIPTOR_64 {
    SEGMENT_DESCRIPTOR Desc;
    UINT32 BaseUpper;
    UINT32 Reserved;
} SEGMENT_DESCRIPTOR_64;
#pragma pack(pop)

typedef BOOLEAN (*HV_GDT_READER)(UINT64 gdtBase, UINT32 offset, UINT32 bytes,
                                 PVOID out, PVOID ctx);

#define HV_SEG_UNUSABLE 0x10000ULL

static __inline BOOLEAN HvSegRead(HV_GDT_READER Read, UINT64 gdtBase, PVOID ctx,
                                  UINT32 offset, UINT32 bytes, PVOID out) {
    return Read(gdtBase, offset, bytes, out, ctx);
}

static __inline UINT64 HvSegmentBase(HV_GDT_READER Read, UINT64 gdtBase,
                                     UINT16 gdtrLimit, UINT16 selector,
                                     PVOID ctx) {
    if (!selector || (selector & 0x4)) return 0;
    if ((selector & ~7) + 7 > gdtrLimit) return 0;   // beyond the table

    SEGMENT_DESCRIPTOR desc;
    if (!HvSegRead(Read, gdtBase, ctx, selector & ~7, sizeof(desc), &desc))
        return 0;

    UINT64 base = (UINT64)desc.BaseLow |
                  ((UINT64)desc.BaseMiddle << 16) |
                  ((UINT64)desc.BaseHigh   << 24);

    // System segment in long mode? (type & 0x10 == 0 means system descriptor)
    if (!(desc.Access & 0x10)) {
        // The 16-byte descriptor's upper half must also be inside the table;
        // a GDT that ends right after the first 8 bytes is malformed, and the
        // CPU would #GP the load. Return 0 rather than read past the limit.
        UINT32 upper;
        if ((selector & ~7) + 15 > gdtrLimit) return 0;
        if (!HvSegRead(Read, gdtBase, ctx, (selector & ~7) + 8, sizeof(upper),
                       &upper))
            return 0;
        base |= ((UINT64)upper << 32);
    }
    return base;
}

static __inline UINT64 HvSegmentAccessRights(HV_GDT_READER Read, UINT64 gdtBase,
                                             UINT16 gdtrLimit, UINT16 selector,
                                             PVOID ctx) {
    if (!selector || (selector & 0x4)) return HV_SEG_UNUSABLE;
    if ((selector & ~7) + 7 > gdtrLimit) return HV_SEG_UNUSABLE;

    SEGMENT_DESCRIPTOR desc;
    if (!HvSegRead(Read, gdtBase, ctx, selector & ~7, sizeof(desc), &desc))
        return HV_SEG_UNUSABLE;

    // VMX access rights format (Intel SDM 24.4.1):
    // bits [3:0]  = type
    // bit  4      = S (descriptor type: 0=system, 1=code/data)
    // bits [6:5]  = DPL
    // bit  7      = P (present)
    // bits [11:8] = reserved (0)
    // bit  12     = AVL
    // bit  13     = L (64-bit mode)
    // bit  14     = D/B
    // bit  15     = G (granularity)
    // bit  16     = unusable
    UINT32 ar = (UINT32)desc.Access | (((UINT32)desc.Granularity & 0xF0) << 8);

    if (!(ar & (1 << 7)))    // not present → mark unusable
        ar |= (UINT32)HV_SEG_UNUSABLE;

    return ar;
}

static __inline UINT32 HvSegmentLimit(HV_GDT_READER Read, UINT64 gdtBase,
                                      UINT16 gdtrLimit, UINT16 selector,
                                      PVOID ctx) {
    if (!selector || (selector & 0x4)) return 0;
    if ((selector & ~7) + 7 > gdtrLimit) return 0;

    SEGMENT_DESCRIPTOR desc;
    if (!HvSegRead(Read, gdtBase, ctx, selector & ~7, sizeof(desc), &desc))
        return 0;

    UINT32 limit = (UINT32)desc.LimitLow |
                   (((UINT32)desc.Granularity & 0x0F) << 16);

    if (desc.Granularity & 0x80) // G bit → 4KB granularity
        limit = (limit << 12) | 0xFFF;

    return limit;
}

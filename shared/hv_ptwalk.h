// hv_ptwalk.h - x86-64 page-table walk with a caller-supplied page reader.
//
// WHY ONE HEADER
//   Both builds translate a virtual address by walking a 4-level page table:
//   the WDK driver over the caller's tables (HvDrv/hv_hypercall.c) and the EFI
//   driver over the same kind of tables (HvEfi/hv_efi_hypercall.c). The rules —
//   which bits must be set at each level, when U/S matters, when R/W matters,
//   how a large-page leaf composes its physical address — are identical and
//   must not drift between the two trees. Keeping them here means there is one
//   implementation, not two that agree only by inspection.
//
// WHY THE READER IS A PARAMETER
//   The walk only ever reads one 8-byte entry at a physical address. In VMX root
//   those reads go through the kernel direct map (HvDrv) or are plain
//   dereferences under the identity map (HvEfi). Off-target, a unit test passes
//   its own reader over synthetic tables, so tools/unit/ptwalk_test.c executes
//   this exact code with no kernel, no VMX and no boot.
//
// CONTRACT (both callers depend on all of it)
//   - cr3 must contain a non-zero page-frame address. The low 12 bits (PCID /
//     flags) are masked off, matching how every other consumer in the driver
//     treats a process CR3 from EPROCESS.
//   - Every level must be present. With HV_PT_USER every level must also be
//     user-accessible (U/S = 1).
//   - With HV_PT_WRITE the leaf — 1 GB, 2 MB or 4 KB — must be writable.
//   - Any violated rule, or a failed read, returns HV_PA_INVALID.
//   - The result is the leaf frame plus the original page offset, so an
//     unaligned VA inside a leaf yields an unaligned PA.
//
// RESERVED BITS
//   The walk does not reject reserved bits; it masks the address field to the
//   architecturally meaningful width (bits 51:12 for a table pointer or a 4 KB
//   leaf, 51:30 for a 1 GB leaf, 51:21 for a 2 MB leaf) so bits the CPU ignores
//   cannot corrupt the address it returns. tools/unit/ptwalk_test.c pins that.
//   The one exception is the PS bit at the PDPT and PD levels, which is exactly
//   what selects a large-page leaf.
//
// TYPES
//   UINT64, UINT32, BOOLEAN, PUINT64 and PVOID must already be visible. Both
//   hvdefs.h headers define or include them before including this file, and the
//   unit test includes hvdefs.h for the same reason.

#pragma once

// Reads the 8-byte page-table entry at physAddr into *outVal. Returns FALSE if
// it cannot be read (address outside the reader's range). ctx is passed through
// untouched so a caller can carry its own state.
typedef BOOLEAN (*HV_PT_READER)(UINT64 physAddr, PUINT64 outVal, PVOID ctx);

#define HV_PA_INVALID   ((UINT64)-1)

// Require U/S = 1 at every level (the address must be user-accessible).
#define HV_PT_USER      0x1u
// Require R/W = 1 on the leaf (the access is a write).
#define HV_PT_WRITE     0x2u

#define HV_PT_PHYS_MASK 0x000FFFFFFFFFF000ULL   // table pointer / 4 KB leaf frame
#define HV_PT_1G_MASK   0x000FFFFFC0000000ULL   // 1 GB leaf frame
#define HV_PT_2M_MASK   0x000FFFFFFFE00000ULL   // 2 MB leaf frame
#define HV_PT_PS        (1ULL << 7)             // large-page bit at PDPT / PD

static __inline UINT64 HvPtWalk(HV_PT_READER Read, PVOID ctx,
                                UINT64 cr3, UINT64 va, UINT32 flags) {
    UINT64 base = cr3 & HV_PT_PHYS_MASK;
    if (base == 0) return HV_PA_INVALID;

    // Bit 0 is Present at every level; bit 2 is U/S, required only for HV_PT_USER.
    const UINT64 need = 1ULL | ((flags & HV_PT_USER) ? 4ULL : 0ULL);
    const BOOLEAN write = (flags & HV_PT_WRITE) != 0;

    UINT64 e;

    // PML4
    if (!Read(base + ((va >> 39) & 0x1FF) * 8, &e, ctx)) return HV_PA_INVALID;
    if ((e & need) != need) return HV_PA_INVALID;

    // PDPT — PS set means a 1 GB leaf
    if (!Read((e & HV_PT_PHYS_MASK) + ((va >> 30) & 0x1FF) * 8, &e, ctx))
        return HV_PA_INVALID;
    if ((e & need) != need) return HV_PA_INVALID;
    if (e & HV_PT_PS) {
        if (write && !(e & 2)) return HV_PA_INVALID;
        return (e & HV_PT_1G_MASK) | (va & 0x3FFFFFFFULL);
    }

    // PD — PS set means a 2 MB leaf
    if (!Read((e & HV_PT_PHYS_MASK) + ((va >> 21) & 0x1FF) * 8, &e, ctx))
        return HV_PA_INVALID;
    if ((e & need) != need) return HV_PA_INVALID;
    if (e & HV_PT_PS) {
        if (write && !(e & 2)) return HV_PA_INVALID;
        return (e & HV_PT_2M_MASK) | (va & 0x1FFFFFULL);
    }

    // PT — 4 KB leaf
    if (!Read((e & HV_PT_PHYS_MASK) + ((va >> 12) & 0x1FF) * 8, &e, ctx))
        return HV_PA_INVALID;
    if ((e & need) != need) return HV_PA_INVALID;
    if (write && !(e & 2)) return HV_PA_INVALID;
    return (e & HV_PT_PHYS_MASK) | (va & 0xFFFULL);
}

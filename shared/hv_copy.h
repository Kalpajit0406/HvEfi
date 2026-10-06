// hv_copy.h - page-wise physical<->user copy with caller-supplied accessors.
//
// WHY
//   Moving bytes between a caller's buffer and a guest physical address is a
//   loop, not a memcpy: one page-table translation describes exactly one 4 KB
//   page, so a range that starts mid-page or spans several pages must be walked
//   page by page. Both trees (HvDrv/hv_hypercall.c HcReadPhysical/HcWritePhysical
//   and HvEfi/hv_efi_hypercall.c) ran that same loop with only the memory
//   accessor differing, and the chunking is exactly where a correct page-table
//   walk can still copy the wrong bytes or misreport a partial range. One copy
//   of the loop here means one behavior to test.
//
// WHAT IS INJECTED
//   Translate(va, write, ctx) -> physical address of that VA's page, or
//   HV_PA_INVALID.  Move(dstPa, srcPa, size, ctx) -> moves `size` bytes between
//   two physical ranges the caller can map; size never crosses a page.
//
// CONTRACT
//   - The range is chunked to page boundaries: chunk = min(page end, remaining).
//     No translation is ever reused across a 4 KB boundary.
//   - The user side is the destination when toUser, otherwise the source. The
//     direction is passed to Translate as `write`, so a write to a read-only
//     user leaf is rejected by the walk, while reading it is allowed.
//   - size == 0 translates nothing, moves nothing, and returns HvCopyOk.
//   - A translation failure returns HvCopyDenied with bytes already moved left
//     in place; a failed Move returns its own status. The caller decides how to
//     report a partial copy.
//
//   Callers map the result to their status codes: HvCopyDenied is
//   HV_STATUS_ACCESS_DENIED, HvCopyBadPhys is HV_STATUS_INVALID_PARAM.
//
// TYPES
//   UINT64, BOOLEAN, PVOID (and HV_PA_INVALID from hv_ptwalk.h) must be visible.

#pragma once
#include "hv_ptwalk.h"

typedef enum _HV_COPY_STATUS {
    HvCopyOk = 0,     // the whole range was moved
    HvCopyDenied,     // a VA did not translate (caller: ACCESS_DENIED)
    HvCopyBadPhys,    // a physical range could not be mapped (INVALID_PARAM)
} HV_COPY_STATUS;

// Translates a user VA to its physical page, or HV_PA_INVALID. `write` is TRUE
// when the loop will write through the result.
typedef UINT64 (*HV_COPY_TRANSLATE)(UINT64 va, BOOLEAN write, PVOID ctx);

// Moves `size` bytes to dstPa from srcPa. `size` never exceeds one page.
typedef HV_COPY_STATUS (*HV_COPY_MOVE)(UINT64 dstPa, UINT64 srcPa, UINT64 size,
                                       PVOID ctx);

static __inline HV_COPY_STATUS
HvCopyPhysical(HV_COPY_TRANSLATE Translate, HV_COPY_MOVE Move, PVOID ctx,
               UINT64 physAddr, UINT64 userVa, UINT64 size, BOOLEAN toUser) {
    UINT64 done = 0;
    while (done < size) {
        // One translation covers one page, so never copy across a boundary.
        UINT64 chunk = 0x1000 - ((userVa + done) & 0xFFF);
        if (chunk > size - done) chunk = size - done;

        UINT64 pa = Translate(userVa + done, toUser, ctx);
        if (pa == HV_PA_INVALID) return HvCopyDenied;

        UINT64 dstPa = toUser ? pa : physAddr + done;
        UINT64 srcPa = toUser ? physAddr + done : pa;
        HV_COPY_STATUS st = Move(dstPa, srcPa, chunk, ctx);
        if (st != HvCopyOk) return st;

        done += chunk;
    }
    return HvCopyOk;
}

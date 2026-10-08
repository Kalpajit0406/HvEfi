// hv_efi_bootcfg.h - the boot-mode contract shared by every program that takes
// part in a HvEfi boot: the HvBoot application (which decides), the HvEfi
// driver (which obeys), HvLauncher.exe (which arms and disarms from Windows),
// tools/diag/hv_efi_diag.c (which explains what will happen next) and the unit
// tests (which pin the rules off-target).
//
// WHY THIS FILE EXISTS
//
// Two things went wrong on the Dell target that a shared contract prevents:
//
//   1. The mode decision was implemented TWICE - once in the application and
//      once in the driver, each re-deriving it from its own inputs (the app
//      from the receipt plus NVRAM, the driver from NVRAM again). Two
//      implementations of one decision can disagree, and when they do the
//      receipt stops describing reality: the app writes "ENTRY FULL /
//      FULL START" while the driver stands down, and the next boot's rescue
//      rule then reads a hang that never happened and disarms full mode
//      permanently. Here there is exactly one function, HvBootDecide().
//
//   2. Telemetry could not be written from the driver at all. Every storage
//      call issued by the 0xC runtime-driver image - a file append, a
//      SetVariable - deadlocks this firmware (six boots of evidence; the last
//      was safe mode with no VMX and no variable write, and it still hung
//      before its first receipt line). So the driver writes nothing to disk or
//      NVRAM; it reports progress into a shared memory page, and the 0xA
//      application - whose file I/O works every time - turns that into receipt
//      lines. The page's layout is defined here once, so the writer and the
//      reader cannot drift.
//
// MODE IS A FILE, NOT AN EFI VARIABLE
//
// `\\EFI\\Boot\\hvcfg` holds one byte: 'F' (full mode allowed) or 'S' (safe
// mode). Absent means safe. Files are the channel this firmware demonstrably
// supports from the 0xA layer: HvProbe and HvBoot have written the receipt on
// every one of five boots, while every firmware-phase variable write hung the
// machine. It also works across a power cycle, which the volatile
// HvEfiBootPending flag never did, and - the point - the application can
// rewrite it to 'S' by itself when it detects an unfinished full attempt, so a
// hung machine disarms itself on the next boot with no user action. The legacy
// HvEfiFullMode / HvEfiSafeMode / HvEfiBootPending variables are ignored from
// Pass 90 on; the launcher still writes them best-effort for older binaries.
//
// Deliberately dependency-free (no Uefi.h, no EDK2 types, no <string.h>): the
// EDK2 build, the Win32 launcher and a plain Win32 unit test all include it.
// Keep it ASCII-only and free of any OS calls - it is pure logic over values.

#ifndef HV_EFI_BOOTCFG_H
#define HV_EFI_BOOTCFG_H

#include "hv_efi_receipt.h"

// ── Mode config file ────────────────────────────────────────────────────────

// The mode byte, next to the images the launcher installs on the boot ESP.
// Wide because EFI_FILE_PROTOCOL.Open wants it; the Win32 side uses the ASCII
// helper below rather than spelling the path a second time (three programs name
// this file, and a name disagreement is a silent failure: the boot would read
// "no config" and stand down while the launcher believed it had armed it).
#define HV_CFG_PATH   L"\\EFI\\Boot\\hvcfg"

#define HV_CFG_FULL   'F'   // arm full-mode bring-up on the next boot
#define HV_CFG_SAFE   'S'   // stand down (also the meaning of an absent file)

// HV_CFG_PATH as ASCII, for the Win32 side (launcher, diag). Returns the byte
// count written (excluding the NUL), or 0 if it does not fit. Same contract as
// HvReceiptPathAnsi in the receipt header.
static __inline int HvCfgPathAnsi(char *out, int cap)
{
    static const unsigned short wide[] = L"\\EFI\\Boot\\hvcfg";
    int i = 0;
    if (!out || cap <= 0) return 0;
    for (; wide[i]; i++) {
        if (i + 1 >= cap) { out[0] = 0; return 0; }
        out[i] = (char)(wide[i] < 0x80 ? wide[i] : '?');
    }
    out[i] = 0;
    return i;
}

// Does a config byte arm full mode? Anything that is not exactly 'F' - absent,
// empty, truncated, hand-edited, a stale 'S' - means safe. Fail-closed on
// purpose: this decides whether the machine attempts VMX bring-up.
static __inline int HvCfgAllowsFull(int cfgByte)
{
    return cfgByte == HV_CFG_FULL;
}

// ── Mailbox: driver -> application telemetry over shared memory ─────────────

// 4-byte tag, so a stale or unrelated page is not mistaken for a mailbox.
#define HV_MAILBOX_MAGIC            0x4856424Du   // "HMBV"

// Size of the auth ticket, fixed by the launcher (which provisions exactly 32
// bytes) and by the driver, which rejected any other size before this
// ticket moved into the mailbox.
// hv_ticket.h already defines this for the Win32 side. Guard rather than
// redefine: hv_launcher.c includes BOTH headers, and a second #define of the
// same macro (even to the same value) is C4005 and builds as an error.
#ifndef HV_TICKET_BYTES
#define HV_TICKET_BYTES             32u
#endif

// Flags (low half of FlagsSeq). Written by the application before StartImage
// and by the driver's ExitBootServices callback afterwards.
#define HV_MAILBOX_FLAG_FORCE_SAFE  0x00000001u   // app: obey - run safe mode
#define HV_MAILBOX_FLAG_RESCUED     0x00000002u   // app: this stand-down is a rescue
#define HV_MAILBOX_FLAG_EBS_OK      0x00000004u   // core: reached ExitBootServices

// Layout. Stage is an HV_STAGE_* code (HvEfi/hv_efi_stage.h); Detail is a
// stage-specific sub-code (a step number, an index, a count). FlagsSeq keeps
// the flags in the low 16 bits and a write sequence in the high 16, so a reader
// can tell "this page was never written" from "it was written and then stopped
// at stage N" independently of the stage value.
// Ticket is the 32-byte auth blob the launcher provisions as an EFI variable.
// It travels through the mailbox rather than being read by the core with
// GetVariable, so the core makes NO runtime-service call on its boot path. That
// is the whole lesson of Pass 89: this image has hung the machine, and every
// service call removed from before ExitBootServices is one less place to hang.
// HvBoot (an application, which already uses the variable stack for its own
// decisions) reads the variable once and hands the bytes over as plain memory.
//
// TicketSize is the discriminator: exactly HV_TICKET_BYTES means "supplied and
// complete". Anything else - 0, a short write, a stale page - means the core
// must refuse to start. Fail-closed, because the alternative is a hypervisor
// that runs with an uninitialised key schedule.
//
// Every field is 4 bytes so the Win32 reader on the other side of the page can
// use ordinary 32-bit loads; Ticket is 8 words rather than 4 longs for the same
// reason (no alignment requirement on the reader).
typedef struct {
    unsigned int Magic;
    unsigned int Stage;
    unsigned int Detail;
    unsigned int FlagsSeq;
    unsigned int TicketSize;    // HV_TICKET_BYTES when supplied, else 0
    unsigned int Ticket[HV_TICKET_BYTES / 4u];

    // Telemetry & Diagnostics (Pass 95)
    unsigned int DevirtCount;
    unsigned int DevirtCause;
    unsigned int DevirtExitReason;
    unsigned int DevirtExitQualLow;
    unsigned int DevirtExitQualHigh;
    unsigned int DevirtGuestRipLow;
    unsigned int DevirtGuestRipHigh;
    unsigned int DevirtGuestRspLow;
    unsigned int DevirtGuestRspHigh;
    unsigned int DevirtGuestCr0Low;
    unsigned int DevirtGuestCr0High;
    unsigned int DevirtGuestCr4Low;
    unsigned int DevirtGuestCr4High;
    unsigned int DevirtGuestEferLow;
    unsigned int DevirtGuestEferHigh;
    unsigned int DevirtCpuIndex;
    unsigned int DevirtApicId;
    unsigned int VmresumeFailCount;
    unsigned int VmresumeFailInstrErr;
    unsigned int TotalExitCount;
    unsigned int HypercallCount;
    unsigned int LastHypercallMagicLow;
    unsigned int LastHypercallMagicHigh;
    unsigned int LastHypercallId;
    unsigned int LastHypercallStatus;
    unsigned int LastExitReason[16];
    unsigned int LastExitCpu[16];
    unsigned int LastExitRipLow[16];
    unsigned int LastExitRipHigh[16];

    // Core Exclusion Mask (Pass 96)
    unsigned int CoreExclusionMaskLow;
    unsigned int CoreExclusionMaskHigh;
} HV_MAILBOX;

// Core Exclusion Mask accessors
static __inline unsigned long long HvMailboxCoreExclusionMaskGet(const volatile HV_MAILBOX *mb)
{
    if (mb == 0) return 0;
    return (unsigned long long)mb->CoreExclusionMaskLow | ((unsigned long long)mb->CoreExclusionMaskHigh << 32);
}

static __inline void HvMailboxCoreExclusionMaskSet(volatile HV_MAILBOX *mb, unsigned long long mask)
{
    if (mb == 0) return;
    mb->CoreExclusionMaskLow = (unsigned int)(mask & 0xFFFFFFFFu);
    mb->CoreExclusionMaskHigh = (unsigned int)(mask >> 32);
}

// Does the mailbox carry a complete, correctly-sized ticket?
static __inline int HvMailboxTicketValid(const volatile HV_MAILBOX *mb)
{
    return (mb != 0) && (mb->TicketSize == HV_TICKET_BYTES);
}

// HvBoot side. Copies len bytes in, and publishes TicketSize LAST so a reader
// that sees a non-zero TicketSize is guaranteed to see the whole blob - the
// same reason the stage writer bumps the sequence number after its stores.
static __inline void HvMailboxTicketSet(volatile HV_MAILBOX *mb,
                                        const unsigned char *bytes,
                                        unsigned int len)
{
    unsigned int i;
    if (mb == 0) return;
    mb->TicketSize = 0;
    if (bytes == 0 || len != HV_TICKET_BYTES) return;
    for (i = 0; i < HV_TICKET_BYTES / 4u; i++) {
        mb->Ticket[i] = (unsigned int)bytes[i * 4u] |
                        ((unsigned int)bytes[i * 4u + 1u] << 8) |
                        ((unsigned int)bytes[i * 4u + 2u] << 16) |
                        ((unsigned int)bytes[i * 4u + 3u] << 24);
    }
    mb->TicketSize = HV_TICKET_BYTES;
}

// Core side. Fails closed: any size other than exactly HV_TICKET_BYTES leaves
// out[] zeroed and returns 0.
static __inline int HvMailboxTicketGet(const volatile HV_MAILBOX *mb,
                                       unsigned char out[HV_TICKET_BYTES])
{
    unsigned int i;
    if (out == 0) return 0;
    for (i = 0; i < HV_TICKET_BYTES; i++) out[i] = 0;
    if (!HvMailboxTicketValid(mb)) return 0;
    for (i = 0; i < HV_TICKET_BYTES / 4u; i++) {
        unsigned int w = mb->Ticket[i];
        out[i * 4u]      = (unsigned char)(w & 0xFFu);
        out[i * 4u + 1u] = (unsigned char)((w >> 8) & 0xFFu);
        out[i * 4u + 2u] = (unsigned char)((w >> 16) & 0xFFu);
        out[i * 4u + 3u] = (unsigned char)((w >> 24) & 0xFFu);
    }
    return 1;
}

static __inline unsigned int HvMailboxFlags(const volatile HV_MAILBOX *mb)
{
    return (mb == 0) ? 0u : (mb->FlagsSeq & 0xFFFFu);
}

static __inline unsigned int HvMailboxSeq(const volatile HV_MAILBOX *mb)
{
    return (mb == 0) ? 0u : (mb->FlagsSeq >> 16);
}

static __inline int HvMailboxValid(const volatile HV_MAILBOX *mb)
{
    return (mb != 0) && (mb->Magic == HV_MAILBOX_MAGIC);
}

// Arm a freshly allocated page. Called by the application.
// Zeroes the entire struct first so stale data from a previous boot
// (especially CoreExclusionMask) cannot persist and silently alter behavior.
static __inline void HvMailboxInit(volatile HV_MAILBOX *mb, unsigned int flags)
{
    if (mb == 0) return;
    {
        volatile unsigned char *p = (volatile unsigned char *)mb;
        unsigned int i;
        for (i = 0; i < sizeof(HV_MAILBOX); i++) p[i] = 0;
    }
    mb->Magic    = HV_MAILBOX_MAGIC;
    mb->Stage    = 0;
    mb->Detail   = 0;
    mb->FlagsSeq = (flags & 0xFFFFu);
}

// Record a stage. Called by the driver: a plain memory store, no firmware
// calls, cannot hang. The sequence counter increments so a partly written value
// is visible as such to the next boot.
//
// SINGLE WRITER - and that is what makes this correct, not an accident.
//
// The sequence bump below is a read-modify-write of FlagsSeq with no
// interlock. That is safe here ONLY because exactly one CPU ever calls this:
// the BSP. As of Pass 94 every AP records its bring-up result in its own
// VCPU.LaunchError and HvReportBringUpSummary() folds them on the BSP, so no
// AP touches this page at all. Readers are HvBoot, which runs before
// StartImage or after it returns, and the next boot after a reset - never
// concurrently with a writer.
//
// So do NOT "fix" this with an atomic or a lock. That would be defending
// against a race this design does not have, and it would bury the invariant
// that actually makes it safe. If you ever need an AP to report a stage here,
// the whole page contract has to be redesigned first - a per-CPU slot plus a
// BSP publish, the same shape VCPU.LaunchError already uses.
//
// Ordering note: Stage and Detail are stored BEFORE the sequence is bumped.
// A reader that samples the sequence before and after its read therefore sees
// no change while a write is in flight, and can accept a Stage from the new
// write paired with a Detail from the old one. That is harmless here and is
// deliberate: the reader is never concurrent, so the window does not exist in
// practice, and the useful property - "the last stage reached survives a
// hang" - depends on the sequence being bumped last.
static __inline void HvMailboxReport(volatile HV_MAILBOX *mb,
                                     unsigned int stage,
                                     unsigned int detail)
{
    unsigned int seq;
    if (mb == 0) return;
    mb->Stage  = stage;
    mb->Detail = detail;
    seq = (mb->FlagsSeq >> 16) + 1u;
    mb->FlagsSeq = (mb->FlagsSeq & 0xFFFFu) | ((seq & 0xFFFFu) << 16);
}

static __inline void HvMailboxSetFlag(volatile HV_MAILBOX *mb, unsigned int flag)
{
    if (mb == 0) return;
    mb->FlagsSeq |= flag;
}

// ── The decision: one implementation, one set of inputs ─────────────────────

// Lines the application must append to the receipt, in order. Both are ordinary
// C strings so the EDK2 side and the Win32 side can share them; an empty string
// means "write nothing".
typedef struct {
    int         RunFull;       // 1 = attempt full-mode bring-up
    int         Rescued;       // 1 = stood down because a full attempt did not finish
    int         WriteCfgSafe;  // 1 = the application must rewrite hvcfg to 'S'
    const char *Line1;
    const char *Line2;
} HV_BOOT_DECISION;

// Inputs:
//   cfgByte      - the mode byte read from HV_CFG_PATH, or 0 when absent
//   legacyPending- HvEfiBootPending (volatile, pre-Pass-90 arm). Kept as an
//                  input because a machine that hung under a pre-Pass-90 binary
//                  may still have it set on the next boot; it can only ever
//                  force safe mode, never enable it.
//   st           - the receipt scan of the tail (may be NULL)
//
// Rules, in order:
//   armed    = cfg says FULL, no legacy Pending, and the receipt does not
//              already require a stand-down
//
//   Note the condition is the receipt's ForceSafeMode (an unfinished attempt
//   with no RETRY after it), NOT mere unfinishedness: a full attempt the user
//   explicitly retried must be allowed to run again, or --enable-full could
//   never re-arm after a hang. hvefi_bootcfg_test.c pins exactly this case -
//   getting it wrong is silent (full mode becomes permanently unreachable).
//   full     -> "ENTRY FULL" then "FULL START" (FULL START is the rescue arm:
//               written BEFORE the driver is loaded, so a hang is visible even
//               when the driver never gets to report anything)
//   otherwise-> "ENTRY SAFE prev=N", and when full mode was requested but
//               denied, rewrite hvcfg to 'S' so the stand-down is sticky across
//               power cycles. A full-mode attempt that hangs must never be
//               retried automatically - that is a reboot loop, not a rescue.
//               Only an explicit HvLauncher.exe --enable-full (which writes 'F'
//               and appends RETRY) clears it.
static __inline void HvBootDecide(int cfgByte,
                                  int legacyPending,
                                  const HV_RECEIPT_STATE *st,
                                  HV_BOOT_DECISION *d)
{
    int wantsFull;
    int rescued;
    int armed;

    if (d == 0) return;
    d->RunFull      = 0;
    d->Rescued      = 0;
    d->WriteCfgSafe = 0;
    d->Line1        = "";
    d->Line2        = "";

    wantsFull = HvCfgAllowsFull(cfgByte);
    // ForceSafeMode, not UnfinishedFull: an attempt the user explicitly
    // retried (--enable-full appends RETRY) must be permitted to run again.
    rescued   = (legacyPending != 0) ||
                ((st != 0) && (st->ForceSafeMode != 0));
    armed     = wantsFull && !rescued;

    if (armed) {
        d->RunFull = 1;
        d->Line1   = "ENTRY FULL";
        d->Line2   = "FULL START";
        return;
    }

    d->Rescued = rescued;
    d->Line1   = rescued ? "ENTRY SAFE prev=1" : "ENTRY SAFE prev=0";
    // Denying a requested full-mode boot is the case that must be durable: the
    // config file is the only input the next boot reads.
    d->WriteCfgSafe = (wantsFull && !armed) ? 1 : 0;
}

#endif // HV_EFI_BOOTCFG_H

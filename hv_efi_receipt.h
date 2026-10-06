// hv_efi_receipt.h - the HvEfi boot receipt: line format + the pure self-rescue
// decision. Shared by the DXE driver (which writes it), HvLauncher.exe (which
// appends RETRY / prints it) and tools/unit/hvefi_receipt_test.c (which drives
// this logic off-target).
//
// Why a file on the ESP and not just EFI variables:
//
//   Dell's runtime service exposes NV variables only. Every volatile (0x06)
//   marker HvEfiEntryMarker / HvReportStage writes during boot - including the
//   one that proves the entry point was reached - is invisible from Windows.
//   (That is why tools/diag/hv_efi_diag.c must never read "marker absent" as
//   "entry never ran".) A file on the boot ESP has neither problem: it is
//   readable from the OS and it survives a reset, which is exactly what the
//   self-rescue decision needs.
//
// Append-only: every boot adds lines, so a later boot cannot destroy an earlier
// boot's evidence, and the tail is the recent history.
//
// Line format (ASCII, one event per line, '\n' terminated, no NULs):
//
//   HVEFI ENTRY SAFE prev=1     stood down to safe mode; prev=1 means the
//                               rescue rule fired (a full attempt did not
//                               finish and the user has not retried since)
//   HVEFI ENTRY FULL            proceeding to full-mode bring-up
//   HVEFI FULL START            about to hand control to the driver's entry -
//                               the line a hang stops at, because it is written
//                               BEFORE the driver is loaded (Pass 90)
//   HVEFI FULL DONE             bring-up completed and returned success
//   HVEFI FULL EBS              legacy: the old in-core writer's completion
//                               line; still counts as a completion so a receipt
//                               from a pre-Pass-90 binary reads correctly
//   HVEFI FULL FAIL step=12     bring-up failed at that step (hv_efi_stage.h)
//   HVEFI RETRY                 the user asked for a retry
//                               (HvLauncher.exe --enable-full)
//
// WHO WRITES WHAT (Pass 90): the 0xA HvBoot application writes ENTRY SAFE /
// ENTRY FULL / FULL START / FULL DONE. The 0xC driver writes NOTHING to disk or
// NVRAM - every storage call from that image deadlocks the target firmware (six
// boots of evidence) - and reports its stages into a shared mailbox that HvBoot
// turns into receipt lines. FULL FAIL and FULL EBS are consequently legacy
// tokens: still matched so an older binary's receipt is read correctly, no
// longer written by this tree.
//
// Tokens are matched with their leading space, so a tail window that starts
// mid-line ("ULL START") can never be mistaken for the event.
//
// Self-rescue rule - sticky until the user explicitly retries:
//
//   done       = the last " FULL DONE", or (legacy) " FULL EBS" offset
//   unfinished = a " FULL START" exists and no completion after it
//   forceSafe  = unfinished && no " RETRY" after that same " FULL START"
//
// Sticky on purpose. If a full-mode boot never reached EBS, retrying it
// automatically on every other boot is a reboot loop; only a deliberate
// `HvLauncher.exe --enable-full` clears it.
//
// Deliberately dependency-free (no Uefi.h, no EDK2 types, no <string.h>): the
// EDK2 build and a plain Win32 unit test both include this file. Keep it
// ASCII-only and free of any OS calls - it is pure logic over a byte window.

#ifndef HV_EFI_RECEIPT_H
#define HV_EFI_RECEIPT_H

// Every line written by the driver or the launcher starts with this prefix.
#define HV_RECEIPT_PREFIX   "HVEFI "

// Event tokens (the leading space is part of the token on purpose).
#define HV_RECEIPT_EV_ENTRY_SAFE   " ENTRY SAFE"
#define HV_RECEIPT_EV_ENTRY_FULL   " ENTRY FULL"
#define HV_RECEIPT_EV_FULL_START   " FULL START"
#define HV_RECEIPT_EV_FULL_DONE    " FULL DONE"
#define HV_RECEIPT_EV_FULL_EBS     " FULL EBS"    // legacy completion (pre-Pass-90)
#define HV_RECEIPT_EV_FULL_FAIL    " FULL FAIL"   // legacy (pre-Pass-90)
#define HV_RECEIPT_EV_RETRY        " RETRY"

// How much of the receipt tail the driver reads back for the rescue decision.
// A few boots of history is all the rule needs, and this bounds a file read
// that happens inside Boot#### StartImage context.
#define HV_RECEIPT_TAIL_BYTES      4096

// The receipt lives next to the images the launcher installs on the boot ESP.
// Wide because that is what EFI_FILE_PROTOCOL.Open wants; the Win32 tools below
// need the ASCII form and must not spell the path out a third time.
#define HV_RECEIPT_PATH            L"\\EFI\\Boot\\hvefi.log"

// HV_RECEIPT_PATH as ASCII, for the Win32 side (launcher, diag).
// Returns the byte count written (excluding the NUL), or 0 if it does not fit.
// The path is ASCII in the literal, so this is a truncation of the UTF-16 form
// rather than a real encoding conversion - but it refuses rather than halves a
// non-ASCII character, because a half-written path is how a tool ends up
// reporting "no receipt" on a volume that has one.
static __inline int HvReceiptPathAnsi(char *out, int cap)
{
    static const unsigned short wide[] =
        L"\\EFI\\Boot\\hvefi.log";
    int i = 0;
    if (!out || cap <= 0) return 0;
    for (; wide[i]; i++) {
        if (i + 1 >= cap) { out[0] = 0; return 0; }
        out[i] = (char)(wide[i] < 0x80 ? wide[i] : '?');
    }
    out[i] = 0;
    return i;
}

typedef struct {
    int FullStarts;        // " FULL START" occurrences in the window
    int FullEbs;           // " FULL EBS" occurrences (legacy completion)
    int FullDones;         // " FULL DONE" occurrences
    int Retries;           // " RETRY" occurrences
    int SafeStands;        // " ENTRY SAFE" occurrences (informational)
    int LastFullStart;     // byte offset of the last one, -1 if none
    int LastEbs;           // byte offset of the last legacy completion, -1 if none
    int LastDone;          // offset of the last completion (DONE or legacy EBS)
    int LastRetry;         // byte offset of the last one, -1 if none
    int UnfinishedFull;    // a full attempt has no matching completion
    int ForceSafeMode;     // stand down to safe mode on this boot
} HV_RECEIPT_STATE;

// Length of a NUL-terminated string, without <string.h>.
static __inline int HvReceiptStrLen(const char *s)
{
    int n = 0;
    while (s[n]) n++;
    return n;
}

// Does tok occur in buf[0..len)? Returns the offset of the LAST occurrence,
// or -1. tokLen is passed by the caller so the loop never recomputes it.
static __inline int HvReceiptLastMatch(const char *buf, int len,
                                       const char *tok, int tokLen)
{
    int i;
    if (tokLen <= 0 || len < tokLen) return -1;
    for (i = len - tokLen; i >= 0; i--) {
        int k = 0;
        while (k < tokLen && buf[i + k] == tok[k]) k++;
        if (k == tokLen) return i;
    }
    return -1;
}

// Count occurrences of tok in buf[0..len).
static __inline int HvReceiptCount(const char *buf, int len,
                                   const char *tok, int tokLen)
{
    int i, n = 0;
    if (tokLen <= 0 || len < tokLen) return 0;
    for (i = 0; i + tokLen <= len; i++) {
        int k = 0;
        while (k < tokLen && buf[i + k] == tok[k]) k++;
        if (k == tokLen) n++;
    }
    return n;
}

// Scan a receipt window. len is clamped to >= 0; a window that starts
// mid-line is handled by the leading-space tokens above.
static __inline void HvReceiptScan(const char *tail, int len, HV_RECEIPT_STATE *st)
{
    static const char kSafe[]  = HV_RECEIPT_EV_ENTRY_SAFE;
    static const char kFull[]  = HV_RECEIPT_EV_ENTRY_FULL;
    static const char kStart[] = HV_RECEIPT_EV_FULL_START;
    static const char kDone[]  = HV_RECEIPT_EV_FULL_DONE;
    static const char kEbs[]   = HV_RECEIPT_EV_FULL_EBS;
    static const char kRetry[] = HV_RECEIPT_EV_RETRY;

    if (len < 0) len = 0;

    st->FullStarts    = HvReceiptCount(tail, len, kStart, (int)sizeof(kStart) - 1);
    st->FullEbs       = HvReceiptCount(tail, len, kEbs,   (int)sizeof(kEbs)   - 1);
    st->FullDones     = HvReceiptCount(tail, len, kDone,  (int)sizeof(kDone)  - 1);
    st->Retries       = HvReceiptCount(tail, len, kRetry, (int)sizeof(kRetry) - 1);
    st->SafeStands    = HvReceiptCount(tail, len, kSafe,  (int)sizeof(kSafe)  - 1)
                      + HvReceiptCount(tail, len, kFull,  (int)sizeof(kFull)  - 1);
    st->LastFullStart = HvReceiptLastMatch(tail, len, kStart, (int)sizeof(kStart) - 1);
    st->LastEbs       = HvReceiptLastMatch(tail, len, kEbs,   (int)sizeof(kEbs)   - 1);
    st->LastRetry     = HvReceiptLastMatch(tail, len, kRetry, (int)sizeof(kRetry) - 1);

    // A completion is either the application's " FULL DONE" (Pass 90 on) or the
    // legacy in-core " FULL EBS". A receipt window can contain both, so take
    // whichever came last - the question is only whether anything completed
    // after the most recent arm.
    {
        int lastDone = HvReceiptLastMatch(tail, len, kDone, (int)sizeof(kDone) - 1);
        st->LastDone = (lastDone > st->LastEbs) ? lastDone : st->LastEbs;
    }

    // A full attempt is unfinished when it started after the last completion.
    st->UnfinishedFull = (st->LastFullStart >= 0) && (st->LastDone < st->LastFullStart);

    // ... and it stays unfinished until the user explicitly retries after it.
    st->ForceSafeMode = st->UnfinishedFull
                     && !(st->LastRetry > st->LastFullStart);
}

// Format one receipt line: "HVEFI " + event + '\n'. event is the human text,
// e.g. "ENTRY FULL" or "FULL FAIL step=12"; it must contain the event token
// that the decision above matches on.
//
// Leading spaces in `event` are collapsed away, so both call styles produce the
// same bytes. That matters because the EV_ constants above carry the leading
// space (the scanner needs it to reject a mid-line window), while the driver
// calls this with plain literals ("FULL START"). Passing a constant straight
// through used to write "HVEFI  RETRY" - still matched, but not the format the
// file documents, and a second space is a needless difference between what the
// driver and the launcher write into the same log.
//
// All or nothing: the total length is computed first, so a buffer that is too
// small is left completely untouched. A partial line written into the caller's
// buffer would put a truncated event - or a fragment of the prefix - on the
// ESP, and the scanner matches the prefix, not the line end.
//
// Returns the byte count written (including the NUL), or 0 if it does not fit.
static __inline int HvReceiptLine(char *out, int cap, const char *event)
{
    const char *p = HV_RECEIPT_PREFIX;
    int prefixLen = HvReceiptStrLen(p);
    int evStart = 0, evLen;
    int need, n = 0, i;

    if (!event) return 0;
    while (event[evStart] == ' ') evStart++;
    evLen = HvReceiptStrLen(event + evStart);
    need  = prefixLen + evLen + 2;   // prefix + event + '\n' + NUL

    if (cap <= 0 || need > cap) return 0;
    for (i = 0; i < prefixLen; i++) out[n++] = p[i];
    for (i = 0; i < evLen; i++)     out[n++] = event[evStart + i];
    out[n++] = '\n';
    out[n]   = 0;
    return n;
}

#endif // HV_EFI_RECEIPT_H

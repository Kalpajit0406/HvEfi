/** @file
  HvBoot.c — UEFI_APPLICATION bootstrap for HvEfi.efi.

  WHY THIS EXISTS
  ---------------
  An earlier hypothesis held that Dell's BDS only calls Boot#### entries whose
  image subsystem is EFI_APPLICATION (0xA) and silently skips 0xC runtime
  drivers. That hypothesis is DISPROVEN: the HvProbe one-shot recorded
  "[probe] v1 enter" and the direct 0xC driver in the same slot demonstrably
  ran (it hung inside its own entry point on a pre-Pass-88 NV SetVariable —
  a hang requires execution). The bridge is therefore NOT required for
  correctness; it survives as an optional two-file layout and as a diagnostic
  instrument: it records receipt lines around the core's start, so a boot
  that never reaches "BOOT HIT" indicts the slot, and a "BOOT FAIL" names the
  exact stage with the EFI_STATUS in the line.

  THIS MODULE
  -----------
  Boot#### points at HvBoot.efi (0xA). We:

    1. Resolve our own EFI_LOADED_IMAGE_PROTOCOL.
    2. Build the device path for \EFI\Boot\hvcore.efi by taking our own
       FilePath and replacing its trailing MEDIA/FILE node. LoadImage on that
       path makes the DXE core resolve the ESP itself, which sets the LOADED
       image's LoadedImage->DeviceHandle — the core's receipt writer and any
       other DeviceHandle-keyed logic depend on it.
    3. gBS->LoadImage (device path). Fallback: read hvcore.efi into a buffer
       and LoadImage from the buffer. THE FALLBACK HAS A KNOWN LIMITATION:
       EDK2 leaves LoadedImage->DeviceHandle NULL for buffer loads with no
       FilePath (CoreLocateDevicePath returns EFI_INVALID_PARAMETER on a NULL
       path, and Image.c stores that NULL), so the core's own receipt writes
       silently no-op. Bring-up still works; telemetry does not. The device
       path load is why the primary path exists.
    4. gBS->StartImage. The DXE core allocates the core's code pages as
       EfiRuntimeServicesCode based on the IMAGE's subsystem (0xC) — that is
       what makes the hypervisor persist across ExitBootServices. On
       EFI_SUCCESS from a driver, CoreStartImage does NOT unload it.
    5. Return an ERROR to BDS in every case. Never EFI_SUCCESS: BdsEntry.c
       BootBootOptions() stops the BootOrder walk on EFI_SUCCESS when a
       platform boot manager menu exists and boots the menu instead of
       Windows. Any error status makes BDS continue down BootOrder to the
       Windows Boot Manager. HvBoot is an application, so CoreStartImage
       unloads it either way, and because CoreUnloadAndCloseImage does not
       recurse into child images, the resident core survives our unload.

  Receipt: same file and line format as the driver (HvEfi/hv_efi_receipt.h),
  appended correctly (256-byte EFI_FILE_INFO buffer — sizeof(EFI_FILE_INFO)
  alone is EFI_BUFFER_TOO_SMALL for a real filename and made every early
  build overwrite the start of the file instead of appending).

  PASS 90 — THIS MODULE OWNS THE WHOLE BOOT DECISION AND ALL TELEMETRY:

    * It reads the mode file (\EFI\Boot\hvcfg), the receipt tail and the
      legacy Pending flag, then decides with HvBootDecide() — ONE
      implementation of that decision, shared with the core, the launcher,
      the diagnostic and the unit tests. The core OBEYS the result through the
      mailbox instead of re-deriving it, because two implementations of one
      decision can disagree, and a disagreement makes the receipt describe a
      boot that never happened.
    * It writes the ARM lines ("ENTRY FULL" / "FULL START") BEFORE the core is
      loaded, so a hang is visible even when the core never reports anything,
      and "FULL DONE" only after bring-up returned success.
    * It allocates the shared mailbox page, arms it with the decision, and
      passes its address to the core through LoadOptions (AllocatePool — never
      a pointer into a stack frame that dies when this function returns).
    * When a requested full-mode boot is denied it rewrites \EFI\Boot\hvcfg to
      'S'. That is the self-disarm: durable across a power cycle, needing no
      NVRAM and no user action — which the volatile Pending flag never was.

  Deliberately absent: no NVRAM writes, no watchdog manipulation (BDS arms
  its own 5-minute timer around every StartImage — BmBoot.c — and clears it
  after the image returns), no VMX, no EPT.

  Build: HvEfi\HvBoot.inf through EDK2. Install via:
    HvLauncher.exe --install-core <HvEfi.efi>   (writes hvcore.efi, patched)
    HvLauncher.exe --install-raw  <HvBoot.efi>  (points the tracked slot here)

  Copyright (c) 2026. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause
**/

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/DevicePath.h>
#include <Guid/FileInfo.h>
#include <Guid/GlobalVariable.h>
// The boot-mode contract: mailbox layout, the mode file, and HvBootDecide() -
// the one implementation of the mode/rescue decision. Also pulls in
// hv_efi_receipt.h (tokens + the rescue rule) so this module and the driver
// cannot disagree about either.
#include "hv_efi_bootcfg.h"

// Path on the ESP where the launcher's --install-core writes the hypervisor
// core. Separate from the Boot#### slot's own file path (which points at
// HvBoot.efi) so a single ESP can hold both without name collision.
#define HV_BOOT_CORE_PATH L"\\EFI\\Boot\\hvcore.efi"
#define HV_BOOT_WINDOWS_PATH L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi"
#define BOOT_OPTION_MAX 4096
#define BOOT_SLOT_FALLBACK 0x0005

// Receipt format identical to hv_efi_receipt.h. Duplicated inline here so
// this module has zero shared source with the hypervisor — the module whose
// job is to prove the entry point gets called must share no bugs with it.
#define HV_RECEIPT_PATH L"\\EFI\\Boot\\hvefi.log"

// Device path constants used by the path builder (no DevicePathLib needed —
// the module walks and copies raw nodes only).
#define HV_DP_TYPE_MEDIA    0x04
#define HV_DP_SUBTYPE_FILE  0x04

// ── Receipt append (correct: position at EOF) ───────────────────────────────

STATIC VOID
HvBootReceiptLine (
  IN EFI_FILE_PROTOCOL  *Vol,
  IN CONST CHAR8        *Message
  )
{
  EFI_FILE_PROTOCOL  *file = NULL;
  UINT64             pos   = 0;
  UINTN              n;

  if (Vol == NULL || Message == NULL) {
    return;
  }

  if (EFI_ERROR (Vol->Open (Vol, &file, HV_RECEIPT_PATH,
                            EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE |
                            EFI_FILE_MODE_CREATE, 0))) {
    return;
  }

  // Append: SetPosition to end. GetInfo requires a buffer large enough for
  // EFI_FILE_INFO + the filename as CHAR16. sizeof(EFI_FILE_INFO) alone (~80
  // bytes with a 1-char FileName placeholder) returns EFI_BUFFER_TOO_SMALL
  // on Dell, which left pos=0 and caused every HvBoot line to overwrite the
  // start of the receipt. A 256-byte buffer accommodates realistic names.
  {
    UINT8          infoBuffer[256];
    UINTN          infoSize = sizeof (infoBuffer);
    EFI_FILE_INFO  *info    = (EFI_FILE_INFO *)infoBuffer;
    EFI_GUID       infoGuid = EFI_FILE_INFO_ID;
    if (!EFI_ERROR (file->GetInfo (file, &infoGuid, &infoSize, infoBuffer))) {
      pos = info->FileSize;
    }
  }
  file->SetPosition (file, pos);

  // Compute length of message (NUL-terminated)
  for (n = 0; Message[n] != 0; n++) {
    // bound
    if (n > 240) { break; }
  }

  // Line: "HVEFI " + Message + "\n"
  {
    CHAR8   line[256];
    UINTN   idx = 0;
    STATIC CONST CHAR8  prefix[] = "HVEFI ";
    UINTN   i;
    for (i = 0; i < sizeof (prefix) - 1 && idx < sizeof (line); i++) {
      line[idx++] = prefix[i];
    }
    for (i = 0; i < n && idx < sizeof (line) - 1; i++) {
      line[idx++] = Message[i];
    }
    if (idx < sizeof (line)) { line[idx++] = '\n'; }
    {
      UINTN  wrote = idx;
      file->Write (file, &wrote, line);
    }
  }

  file->Flush (file);
  file->Close (file);
}

// Same line with the EFI_STATUS appended as 16 hex digits:
//   "HVEFI <Message> st=800000000000000E\n"
// A FAIL line without the status forced a second boot every time — the
// status is the difference between "file missing", "security violation"
// and "the core stood down by design".
STATIC VOID
HvBootReceiptStatus (
  IN EFI_FILE_PROTOCOL  *Vol,
  IN CONST CHAR8        *Message,
  IN EFI_STATUS         Status
  )
{
  CHAR8  buf[96];
  UINTN  idx = 0;
  UINTN  i;
  STATIC CONST CHAR8  hex[] = "0123456789ABCDEF";

  for (i = 0; Message[i] != 0 && idx < sizeof (buf) - 24; i++) {
    buf[idx++] = Message[i];
  }
  if (idx < sizeof (buf) - 20) {
    buf[idx++] = ' ';
    buf[idx++] = 's';
    buf[idx++] = 't';
    buf[idx++] = '=';
    for (i = 0; i < 16; i++) {
      buf[idx++] = hex[(Status >> (60 - 4 * i)) & 0xF];
    }
  }
  buf[idx] = 0;
  HvBootReceiptLine (Vol, buf);
}

// A decimal number on its own receipt line: "HVEFI CORE stage=14". The stage
// codes are the numbers the diagnostic maps back to step names, so they belong
// in decimal - the 16-digit EFI_STATUS formatter is for statuses.
STATIC VOID
HvBootReceiptNum (
  IN EFI_FILE_PROTOCOL  *Vol,
  IN CONST CHAR8        *Label,
  IN UINT32             Value
  )
{
  CHAR8  buf[64];
  CHAR8  digits[10];
  UINTN  idx = 0;
  UINTN  n   = 0;
  UINTN  i;

  for (i = 0; Label[i] != 0 && idx < sizeof (buf) - 12; i++) {
    buf[idx++] = Label[i];
  }
  if (idx < sizeof (buf) - 2) {
    buf[idx++] = '=';
  }
  if (Value == 0) {
    digits[n++] = '0';
  } else {
    UINT32 v = Value;
    while ((v != 0) && (n < sizeof (digits))) {
      digits[n++] = (CHAR8)('0' + (v % 10u));
      v /= 10u;
    }
  }
  while ((n > 0) && (idx < sizeof (buf) - 1)) {
    buf[idx++] = digits[--n];
  }
  buf[idx] = 0;
  HvBootReceiptLine (Vol, buf);
}

// ── Mode file, receipt tail, mailbox ────────────────────────────────────────
//
// Everything in this section is this application's job alone: the 0xC core
// cannot touch a file (its storage calls deadlock this firmware) and no longer
// touches the variable stack either. See HvEfi/hv_efi_bootcfg.h for the contract
// these functions implement.

// Read the receipt tail (READ-only) into text, NUL-terminated. Returns the byte
// count, or 0 when the file is absent/unreadable/short. A window that starts
// mid-line is safe: the event tokens carry their leading space precisely so a
// truncated line cannot be mistaken for an event.
STATIC UINTN
HvBootReceiptReadTail (
  IN  EFI_FILE_PROTOCOL  *Vol,
  OUT CHAR8              *Text,
  IN  UINTN              Cap
  )
{
  EFI_FILE_PROTOCOL  *file = NULL;
  UINT8              infoBuffer[256];
  UINTN              infoSize = sizeof (infoBuffer);
  EFI_FILE_INFO      *info    = (EFI_FILE_INFO *)infoBuffer;
  EFI_GUID           infoGuid = EFI_FILE_INFO_ID;
  UINT64             size;
  UINTN              got;

  if ((Vol == NULL) || (Text == NULL) || (Cap < 2)) {
    return 0;
  }
  Text[0] = 0;

  if (EFI_ERROR (Vol->Open (Vol, &file, HV_RECEIPT_PATH, EFI_FILE_MODE_READ, 0))) {
    return 0;
  }
  if (EFI_ERROR (file->GetInfo (file, &infoGuid, &infoSize, infoBuffer))) {
    file->Close (file);
    return 0;
  }
  size = info->FileSize;
  if ((size == 0) || (size > 0x40000000ULL)) {
    file->Close (file);
    return 0;
  }

  if ((UINTN)size >= Cap) {
    // Last Cap-1 bytes: the recent history is what the rule needs.
    file->SetPosition (file, size - (UINT64)(Cap - 1));
    got = Cap - 1;
  } else {
    file->SetPosition (file, 0);
    got = (UINTN)size;
  }

  if (EFI_ERROR (file->Read (file, &got, Text))) {
    file->Close (file);
    return 0;
  }
  file->Close (file);
  Text[got] = 0;
  return got;
}

// Read the mode byte from \EFI\Boot\hvcfg. Anything other than a clean single
// 'F' byte means safe (HvCfgAllowsFull() decides), so this returns 0 for
// absent, unreadable, empty and short files alike.
STATIC INT32
HvBootReadCfg (
  IN EFI_FILE_PROTOCOL  *Vol
  )
{
  EFI_FILE_PROTOCOL  *file = NULL;
  CHAR8              byte  = 0;
  UINTN              got   = 1;

  if (Vol == NULL) {
    return 0;
  }
  if (EFI_ERROR (Vol->Open (Vol, &file, HV_CFG_PATH, EFI_FILE_MODE_READ, 0))) {
    return 0;   // no config file: the designed default is safe mode
  }
  file->SetPosition (file, 0);
  if (EFI_ERROR (file->Read (file, &got, &byte)) || (got != 1)) {
    file->Close (file);
    return 0;
  }
  file->Close (file);
  return (INT32)(unsigned char)byte;
}

// Rewrite the mode byte to 'S' (creating the file when needed). This is the
// self-disarm, and it is the reason a hung full-mode attempt cannot be retried
// by accident: the next boot reads this file, not the volatile flag that died
// with the power. Best effort - a failure is reported and the boot still
// proceeds in safe mode, because the receipt line is the primary record.
STATIC BOOLEAN
HvBootWriteCfgSafe (
  IN EFI_FILE_PROTOCOL  *Vol
  )
{
  EFI_FILE_PROTOCOL  *file = NULL;
  CHAR8              byte  = (CHAR8)HV_CFG_SAFE;
  UINTN              wrote = sizeof (byte);

  if (Vol == NULL) {
    return FALSE;
  }
  if (EFI_ERROR (Vol->Open (Vol, &file, HV_CFG_PATH,
                            EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE |
                            EFI_FILE_MODE_CREATE, 0))) {
    return FALSE;
  }
  file->SetPosition (file, 0);
  if (EFI_ERROR (file->Write (file, &wrote, &byte)) || (wrote != sizeof (byte))) {
    file->Close (file);
    return FALSE;
  }
  file->Flush (file);
  file->Close (file);
  return TRUE;
}

// Where the mailbox ended up, plus what a PREVIOUS boot left in the same page.
typedef struct {
  UINT64  Pa;          // 0 = no mailbox this boot (the core then stands down)
  UINT32  LeftStage;   // HV_STAGE_* left behind, 0xFFFFFFFF when none
  UINT32  LeftSeq;     // write sequence left behind
  UINT32  LeftFlags;   // flags left behind
} HV_BOOT_MAILBOX;

// Fixed addresses are tried AFTER a general allocation. Rationale: the fixed
// addresses were originally first (so a hung boot's mailbox could be read on
// the next boot), but on Dell G15 5530 (Intel 13th gen) the 112-144 MB range
// overlaps SMRAM/TSEG and other firmware-reserved regions. AllocatePages
// (AllocateAddress) occasionally returns success for memory the firmware
// still owns, and writes to that memory trigger an SMI that hangs the system
// at Dell logo with no receipt progression past "BOOT START". Falling back
// to AllocateAnyPages first gets safe DRAM; the warm-reset mailbox read is
// still attempted as a diagnostic bonus but is no longer load-bearing.
//
// Chosen range: 1-2 GB. Modern Intel laptops have usable DRAM here; lower
// (< 256 MB) collides with Dell firmware reservations, and higher (> 2 GB)
// is more likely to be PCI BAR space on some chipsets. Order from highest
// to lowest matches the original intent (try first-choice fixed PA first).
STATIC CONST UINT64  mFixedMailboxPa[] = { 0x40000000ULL, 0x50000000ULL, 0x60000000ULL };

// Legacy mode-gate GUID (pre-Pass-90 binaries). Read-only, and only for the
// volatile Pending flag - the Pass-90 mode file is the authority now.
STATIC EFI_GUID  mLegacyModeGuid = {
  0x8F3A9D21, 0x7C64, 0x4A2B,
  { 0x9E, 0x1D, 0xB5, 0x08, 0x3F, 0x2A, 0x6C, 0x81 }
};

//
// The auth ticket: the launcher writes it to an EFI variable under a
// RANDOMISED name and GUID, then patches those same two values into this
// image at provision time. The byte patterns below are the sentinels it looks
// for, and they MUST stay byte-identical to the ones in
// HvEfi/hv_efi_main.c - otherwise the launcher patches one binary and not the
// other, and the ticket silently never arrives.
//
// This is why the randomised name is worth the trouble: the ticket is 32 bytes
// of the key schedule, and a fixed variable name is a fixed target.
STATIC CHAR16 mHvTicketVarName[64] = { 0xEFEF, 0xBEBE, 0xADAD, 0xDEDE, 0x0000 };
STATIC EFI_GUID mHvTicketGuid       = {
    0xDEADC0DE, 0xDEAD, 0xC0DE,
    {0xDE, 0xAD, 0xC0, 0xDE, 0xDE, 0xAD, 0xC0, 0xDE}
};

// Load the provisioned ticket into the mailbox so the CORE never has to call
// GetVariable.
//
// Before Pass 94 the core read this itself. That was the last runtime-service
// call on its boot path, and the lesson of Pass 89 is that this image has hung
// the machine more than once - fewer service calls before ExitBootServices is
// strictly better. HvBoot is an application that already uses the variable
// stack (the legacy Pending read above), so the call happens somewhere that is
// already trusted, once, and the core sees only a plain memory load.
//
// Returns 1 when a correctly-sized ticket was published, 0 otherwise. A 0 is
// NOT fatal here: the core fails closed on the same condition and prints the
// remedy. Failing early and loudly at the application is strictly better than
// failing deep inside the driver, where the receipt cannot name the cause.
STATIC BOOLEAN
HvBootLoadTicket (
  IN  volatile HV_MAILBOX  *Mb
  )
{
  UINT8  Ticket[HV_TICKET_BYTES];
  UINTN  Size;
  UINT32 Attrs;

  ZeroMem (Ticket, sizeof (Ticket));

  // Unprovisioned image: the sentinels were never overwritten. Do NOT call
  // GetVariable with the sentinel as a name - publish nothing and let the core
  // report "not provisioned" with the right instruction.
  if ((mHvTicketVarName[0] == 0xEFEF) && (mHvTicketVarName[1] == 0xBEBE)) {
    return FALSE;
  }
  if (mHvTicketGuid.Data1 == 0xDEADC0DE) {
    return FALSE;
  }

  Size  = sizeof (Ticket);
  Attrs = 0;
  if (EFI_ERROR (gRT->GetVariable (mHvTicketVarName, &mHvTicketGuid,
                                   &Attrs, &Size, Ticket))) {
    return FALSE;
  }
  // Exactly the provisioned size, no more and no less. A longer variable is a
  // different thing wearing this name; a shorter one is a torn write.
  if (Size != HV_TICKET_BYTES) {
    return FALSE;
  }

  HvMailboxTicketSet (Mb, Ticket, (unsigned int)Size);
  ZeroMem (Ticket, sizeof (Ticket));
  return (BOOLEAN)HvMailboxTicketValid (Mb);
}

STATIC VOID
HvBootMailboxSetup (
  IN  EFI_FILE_PROTOCOL  *Vol,
  IN  UINT32             Flags,
  OUT HV_BOOT_MAILBOX    *Out
  )
{
  EFI_PHYSICAL_ADDRESS  pa = 0;
  volatile HV_MAILBOX   *mb;
  UINTN                 i;

  Out->Pa        = 0;
  Out->LeftStage = 0xFFFFFFFFu;
  Out->LeftSeq   = 0;
  Out->LeftFlags = 0;

  HV_MAILBOX leftover;
  BOOLEAN hasLeftover = FALSE;

  // Snapshot leftover BEFORE AllocatePages zeroes the memory
  for (i = 0; i < sizeof (mFixedMailboxPa) / sizeof (mFixedMailboxPa[0]); i++) {
    volatile HV_MAILBOX *candidate = (volatile HV_MAILBOX *)(UINTN)mFixedMailboxPa[i];
    if (HvMailboxValid (candidate) && (HvMailboxSeq (candidate) != 0)) {
      CopyMem (&leftover, (VOID *)(UINTN)candidate, sizeof (HV_MAILBOX));
      hasLeftover = TRUE;
      break;
    }
  }

  // Try fixed addresses first for warm-reset mailbox persistence (so the next
  // boot's HvBoot can read the stage a hung boot left behind). The 1-2 GB
  // range is safe DRAM on modern Intel laptops - the old 112-144 MB range
  // collided with Dell's SMRAM/firmware-reserved memory. Writes to those
  // addresses either triggered SMIs that hung the boot or were silently
  // dropped, and in either case the mailbox magic read back as garbage.
  // AllocateAnyPages is the fallback.
  for (i = 0; i < sizeof (mFixedMailboxPa) / sizeof (mFixedMailboxPa[0]); i++) {
    pa = mFixedMailboxPa[i];
    if (!EFI_ERROR (gBS->AllocatePages (AllocateAddress, EfiRuntimeServicesData, 1, &pa))) {
      break;
    }
    pa = 0;
  }
  if (pa == 0) {
    if (!EFI_ERROR (gBS->AllocatePages (AllocateAnyPages, EfiRuntimeServicesData, 1, &pa))) {
      // Fallback succeeded with dynamic runtime page
    } else {
      // No channel: the core will find no mailbox and stand down (fail-closed).
      HvBootReceiptLine (Vol, "BOOT WARN no mailbox");
      return;
    }
  }

  // Record the mailbox PA to the receipt as a diagnostic so a hang can be
  // correlated to a specific physical address.
  HvBootReceiptNum (Vol, "MBOX pa", (UINT32)pa);

  mb = (volatile HV_MAILBOX *)(UINTN)pa;

  // Report a leftover BEFORE re-arming the page.
  if (hasLeftover) {
    Out->LeftStage = leftover.Stage;
    Out->LeftSeq   = (leftover.FlagsSeq >> 16);
    Out->LeftFlags = (leftover.FlagsSeq & 0xFFFFu);
    if (leftover.DevirtCount > 0) {
      HvBootReceiptNum (Vol, "LAST DEVIRT count", leftover.DevirtCount);
      HvBootReceiptNum (Vol, "LAST DEVIRT cause", leftover.DevirtCause);
      HvBootReceiptNum (Vol, "LAST DEVIRT reason", leftover.DevirtExitReason);
      HvBootReceiptNum (Vol, "LAST DEVIRT qual_lo", leftover.DevirtExitQualLow);
      HvBootReceiptNum (Vol, "LAST DEVIRT qual_hi", leftover.DevirtExitQualHigh);
      HvBootReceiptNum (Vol, "LAST DEVIRT rip_lo", leftover.DevirtGuestRipLow);
      HvBootReceiptNum (Vol, "LAST DEVIRT rip_hi", leftover.DevirtGuestRipHigh);
      HvBootReceiptNum (Vol, "LAST DEVIRT rsp_lo", leftover.DevirtGuestRspLow);
      HvBootReceiptNum (Vol, "LAST DEVIRT rsp_hi", leftover.DevirtGuestRspHigh);
      HvBootReceiptNum (Vol, "LAST DEVIRT cr0_lo", leftover.DevirtGuestCr0Low);
      HvBootReceiptNum (Vol, "LAST DEVIRT cr4_lo", leftover.DevirtGuestCr4Low);
      HvBootReceiptNum (Vol, "LAST DEVIRT efer_lo", leftover.DevirtGuestEferLow);
      HvBootReceiptNum (Vol, "LAST DEVIRT cpu", leftover.DevirtCpuIndex);
      HvBootReceiptNum (Vol, "LAST DEVIRT apic", leftover.DevirtApicId);
    }
    if (leftover.VmresumeFailCount > 0) {
      HvBootReceiptNum (Vol, "LAST VMRESUME fails", leftover.VmresumeFailCount);
      HvBootReceiptNum (Vol, "LAST VMRESUME err", leftover.VmresumeFailInstrErr);
    }
    if (leftover.HypercallCount > 0) {
      HvBootReceiptNum (Vol, "LAST HCALL count", leftover.HypercallCount);
      HvBootReceiptNum (Vol, "LAST HCALL last_id", leftover.LastHypercallId);
      HvBootReceiptNum (Vol, "LAST HCALL status", leftover.LastHypercallStatus);
      HvBootReceiptNum (Vol, "LAST HCALL magic_lo", leftover.LastHypercallMagicLow);
      HvBootReceiptNum (Vol, "LAST HCALL magic_hi", leftover.LastHypercallMagicHigh);
    }
    if (leftover.TotalExitCount > 0) {
      UINT32 lastIdx, ri;
      HvBootReceiptNum (Vol, "LAST EXITS total", leftover.TotalExitCount);
      lastIdx = (leftover.TotalExitCount - 1u) & 15u;
      HvBootReceiptNum (Vol, "LAST EXIT reason", leftover.LastExitReason[lastIdx]);
      HvBootReceiptNum (Vol, "LAST EXIT cpu", leftover.LastExitCpu[lastIdx]);
      HvBootReceiptNum (Vol, "LAST EXIT rip_lo", leftover.LastExitRipLow[lastIdx]);
      HvBootReceiptNum (Vol, "LAST EXIT rip_hi", leftover.LastExitRipHigh[lastIdx]);
      for (ri = 0; ri < 16; ri++) {
        UINT32 slot = (leftover.TotalExitCount - 16u + ri) & 15u;
        HvBootReceiptNum (Vol, "LAST RING reason", leftover.LastExitReason[slot]);
      }
    }
    if (leftover.ActualPinCtls != 0 || leftover.ActualExitCtls != 0) {
      HvBootReceiptNum (Vol, "LAST VMCS pin", leftover.ActualPinCtls);
      HvBootReceiptNum (Vol, "LAST VMCS exit", leftover.ActualExitCtls);
    }
  } else if (HvMailboxValid (mb)) {
    HvBootReceiptLine (Vol, "CORE LAST none (prev driver did not run)");
  }

  HvMailboxInit (mb, Flags);

  // Publish the auth ticket after arming, before the core is ever told where
  // the page is. Order matters: the core cannot observe the page until
  // Out->Pa is handed over, so anything written here is visible before the
  // core's first read of it.
  if (!HvBootLoadTicket (mb)) {
    HvBootReceiptLine (Vol, "BOOT WARN no ticket");
  }

  Out->Pa = (UINT64)pa;
}

// Hand the mailbox address to the core through its LoadOptions. Allocated with
// gBS->AllocatePool rather than pointing at a local: EDK2 in this tree does not
// free LoadOptions (no FreePool of it anywhere in MdeModulePkg/MdePkg), so the
// stack form would not crash today - but a pointer into a frame that dies when
// this function returns is exactly the kind of detail that becomes a bug the
// moment any other consumer reads it. 8 bytes is a cheap way not to find out.
STATIC BOOLEAN
HvBootSetLoadOptions (
  IN EFI_HANDLE  CoreImage,
  IN UINT64      MailboxPa
  )
{
  EFI_LOADED_IMAGE_PROTOCOL  *coreLi = NULL;
  UINT64                     *blob   = NULL;
  EFI_GUID                   lipGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;

  if (MailboxPa == 0) {
    return FALSE;
  }
  if (EFI_ERROR (gBS->HandleProtocol (CoreImage, &lipGuid, (VOID **)&coreLi)) ||
      (coreLi == NULL)) {
    return FALSE;
  }
  if (EFI_ERROR (gBS->AllocatePool (EfiBootServicesData, sizeof (UINT64),
                                    (VOID **)&blob)) || (blob == NULL)) {
    return FALSE;
  }
  *blob                   = MailboxPa;
  coreLi->LoadOptions     = blob;
  coreLi->LoadOptionsSize = sizeof (UINT64);
  return TRUE;
}

// ── Device path builder ─────────────────────────────────────────────────────

STATIC UINT16
HvDpNodeLen (
  IN EFI_DEVICE_PATH_PROTOCOL  *Node
  )
{
  return (UINT16)(Node->Length[0] | ((UINT16)Node->Length[1] << 8));
}

STATIC BOOLEAN
HvDpIsEnd (
  IN EFI_DEVICE_PATH_PROTOCOL  *Node
  )
{
  return (Node->Type == 0x7F) && (Node->SubType == 0xFF);
}

// Build the device path for HV_BOOT_CORE_PATH from the device path of the
// ESP partition HANDLE (li->DeviceHandle), appending a FILE node for
// hvcore.efi. The handle's device path (PciRoot…SATA…Partition GUID) uniquely
// pins the partition — which li->FilePath alone does NOT: the first bridge
// boot returned EFI_NOT_FOUND because a FilePath-derived path resolved to a
// different volume on this dual-ESP machine. Loading through this path makes
// the DXE core resolve the ESP and set the loaded image's DeviceHandle —
// which the core's receipt writer requires.
//
// Returns NULL when the handle has no device path or on allocation failure;
// the caller then falls back to the buffer load.
STATIC EFI_DEVICE_PATH_PROTOCOL *
HvBootBuildFilePath (
  IN EFI_HANDLE    EspHandle,
  IN CONST CHAR16  *FilePath
  )
{
  EFI_DEVICE_PATH_PROTOCOL  *src = NULL;
  EFI_DEVICE_PATH_PROTOCOL  *node;
  EFI_DEVICE_PATH_PROTOCOL  *out;
  UINTN   srcLen = 0;   // bytes of the handle's path, END node excluded
  UINTN   filePathChars = 0;
  UINTN   fileNodeLen;
  UINTN   total;
  CHAR16  *dst;
  UINTN   i;
  EFI_STATUS st;

  while (FilePath[filePathChars] != L'\0') {
    filePathChars++;
  }
  filePathChars++; // include NUL terminator

  {
    STATIC EFI_GUID dpGuid = { 0x09576e91, 0x6d3f, 0x11d2,
                               { 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
    st = gBS->HandleProtocol (EspHandle, &dpGuid, (VOID **)&src);
    if (EFI_ERROR (st) || src == NULL) {
      return NULL;
    }
  }

  node = src;
  while (!HvDpIsEnd (node)) {
    UINT16 len = HvDpNodeLen (node);
    if (len < 4) {
      return NULL;                       // malformed node
    }
    // A path with no END (corrupt or hostile) would walk off memory; real
    // device paths are far below this cap, so bound the walk instead of
    // trusting the terminator.
    if (srcLen > 4096) {
      return NULL;
    }
    srcLen += len;
    node = (EFI_DEVICE_PATH_PROTOCOL *)((UINT8 *)node + len);
  }

  // FILE node: 4-byte header + the full wide string including NUL.
  fileNodeLen = 4 + filePathChars * sizeof (CHAR16);
  total       = srcLen + fileNodeLen + 4;   // + END node

  st = gBS->AllocatePool (EfiBootServicesData, total, (VOID **)&out);
  if (EFI_ERROR (st)) {
    return NULL;
  }

  SetMem (out, total, 0);
  if (srcLen > 0) {
    CopyMem (out, src, srcLen);
  }

  node = (EFI_DEVICE_PATH_PROTOCOL *)((UINT8 *)out + srcLen);
  node->Type      = HV_DP_TYPE_MEDIA;
  node->SubType   = HV_DP_SUBTYPE_FILE;
  node->Length[0] = (UINT8)(fileNodeLen & 0xFF);
  node->Length[1] = (UINT8)(fileNodeLen >> 8);

  dst = (CHAR16 *)((UINT8 *)out + srcLen + 4);
  for (i = 0; i < filePathChars; i++) {
    dst[i] = FilePath[i];
  }

  node = (EFI_DEVICE_PATH_PROTOCOL *)((UINT8 *)out + srcLen + fileNodeLen);
  node->Type      = 0x7F;
  node->SubType   = 0xFF;
  node->Length[0] = 4;
  node->Length[1] = 0;

  return out;
}

STATIC EFI_DEVICE_PATH_PROTOCOL *
HvBootBuildCorePath (
  IN EFI_HANDLE  EspHandle
  )
{
  return HvBootBuildFilePath (EspHandle, HV_BOOT_CORE_PATH);
}

// ── Buffer file reader ───────────────────────────────────────────────────────

STATIC EFI_STATUS
HvBootReadFile (
  IN  EFI_FILE_PROTOCOL  *Vol,
  IN  CONST CHAR16       *FilePath,
  OUT VOID               **OutBuf,
  OUT UINTN              *OutSize
  )
{
  EFI_FILE_PROTOCOL  *file = NULL;
  EFI_STATUS         st;
  UINT64             fileSize = 0;
  VOID               *buf     = NULL;
  UINTN              readSize;

  *OutBuf  = NULL;
  *OutSize = 0;

  st = Vol->Open (Vol, &file, (CHAR16 *)FilePath, EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR (st)) {
    return st;
  }

  // File size via GetInfo — the same 256-byte EFI_FILE_INFO buffer every
  // other receipt code path uses (sizeof(EFI_FILE_INFO) alone is
  // EFI_BUFFER_TOO_SMALL for a real filename).
  {
    UINT8          infoBuffer[256];
    UINTN          infoSize = sizeof (infoBuffer);
    EFI_FILE_INFO  *info    = (EFI_FILE_INFO *)infoBuffer;
    EFI_GUID       infoGuid = EFI_FILE_INFO_ID;
    if (!EFI_ERROR (file->GetInfo (file, &infoGuid, &infoSize, infoBuffer))) {
      fileSize = info->FileSize;
    }
  }
  if (fileSize == 0 || fileSize > 0x4000000ULL /*64 MiB cap*/) {
    file->Close (file);
    return EFI_LOAD_ERROR;
  }
  file->SetPosition (file, 0);

  st = gBS->AllocatePool (EfiBootServicesData, (UINTN)fileSize, &buf);
  if (EFI_ERROR (st)) {
    file->Close (file);
    return st;
  }

  readSize = (UINTN)fileSize;
  st = file->Read (file, &readSize, buf);
  file->Close (file);

  if (EFI_ERROR (st) || readSize != (UINTN)fileSize) {
    gBS->FreePool (buf);
    return EFI_LOAD_ERROR;
  }

  *OutBuf  = buf;
  *OutSize = (UINTN)fileSize;
  return EFI_SUCCESS;
}

STATIC EFI_STATUS
HvBootReadCore (
  IN  EFI_FILE_PROTOCOL  *Vol,
  OUT VOID               **OutBuf,
  OUT UINTN              *OutSize
  )
{
  return HvBootReadFile (Vol, HV_BOOT_CORE_PATH, OutBuf, OutSize);
}

// ── Windows Boot Manager Chainloader ────────────────────────────────────────

STATIC VOID
HvBootFormatHexSlot (
  OUT CHAR16  Name[9],
  IN  UINT16  Slot
  )
{
  STATIC CONST CHAR16 hex[] = L"0123456789ABCDEF";
  Name[0] = L'B';
  Name[1] = L'o';
  Name[2] = L'o';
  Name[3] = L't';
  Name[4] = hex[(Slot >> 12) & 0xF];
  Name[5] = hex[(Slot >> 8)  & 0xF];
  Name[6] = hex[(Slot >> 4)  & 0xF];
  Name[7] = hex[Slot         & 0xF];
  Name[8] = L'\0';
}

STATIC BOOLEAN
HvBootPathEndsWithBootMgr (
  IN CONST CHAR16  *Path,
  IN UINTN         MaxChars
  )
{
  STATIC CONST CHAR16 suffix[] = L"bootmgfw.efi";
  UINTN length = 0;
  UINTN i;

  while (length < MaxChars && Path[length] != L'\0') {
    length++;
  }
  if (length < sizeof (suffix) / sizeof (CHAR16) - 1) {
    return FALSE;
  }

  for (i = 0; i < sizeof (suffix) / sizeof (CHAR16) - 1; i++) {
    CHAR16 ch = Path[length - (sizeof (suffix) / sizeof (CHAR16) - 1) + i];
    if (ch >= L'A' && ch <= L'Z') {
      ch = (CHAR16)(ch + 32);
    }
    if (ch != suffix[i]) {
      return FALSE;
    }
  }
  return TRUE;
}

STATIC BOOLEAN
HvBootPathTargetsBootMgr (
  IN EFI_DEVICE_PATH_PROTOCOL  *DevicePath,
  IN UINTN                     PathLength
  )
{
  UINT8 *cursor = (UINT8 *)DevicePath;
  UINTN walked = 0;

  while (walked + sizeof (EFI_DEVICE_PATH_PROTOCOL) <= PathLength) {
    CONST UINT8 *node = cursor + walked;
    UINTN nodeLength = (UINTN)(node[2] | ((UINTN)node[3] << 8));

    if (nodeLength < sizeof (EFI_DEVICE_PATH_PROTOCOL) || walked + nodeLength > PathLength) {
      return FALSE;
    }
    if (node[0] == 0x7F && node[1] == 0xFF) {
      return FALSE;
    }
    if (node[0] == HV_DP_TYPE_MEDIA && node[1] == HV_DP_SUBTYPE_FILE) {
      CONST CHAR16 *path = (CONST CHAR16 *)(node + sizeof (EFI_DEVICE_PATH_PROTOCOL));
      UINTN maxChars = (nodeLength - sizeof (EFI_DEVICE_PATH_PROTOCOL)) / sizeof (CHAR16);
      if (HvBootPathEndsWithBootMgr (path, maxChars)) {
        return TRUE;
      }
    }
    walked += nodeLength;
  }
  return FALSE;
}

STATIC EFI_STATUS
HvBootTryChainSlot (
  IN     UINT16              Slot,
  IN     EFI_HANDLE          ImageHandle,
  IN     EFI_HANDLE          EspHandle,
  IN OUT EFI_FILE_PROTOCOL   **VolRef,
  OUT    BOOLEAN             *Found
  )
{
  EFI_STATUS                 status;
  UINT8                      *buffer = NULL;
  UINTN                      size = BOOT_OPTION_MAX;
  UINT32                     attrs = 0;
  CHAR16                     name[12];
  UINTN                      offset;
  UINT16                     fpLength;
  EFI_DEVICE_PATH_PROTOCOL   *path;
  UINT8                      *options;
  UINTN                      optionsSize;
  EFI_HANDLE                 winImage = NULL;
  EFI_LOADED_IMAGE_PROTOCOL  *info = NULL;
  EFI_GUID                   lipGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;

  *Found = FALSE;

  status = gBS->AllocatePool (EfiBootServicesData, size, (VOID **)&buffer);
  if (EFI_ERROR (status)) {
    return status;
  }

  HvBootFormatHexSlot (name, Slot);
  status = gRT->GetVariable (name, &gEfiGlobalVariableGuid, &attrs, &size, buffer);
  if (EFI_ERROR (status) || size < 6) {
    gBS->FreePool (buffer);
    return status;
  }

  CopyMem (&fpLength, buffer + 4, sizeof (fpLength));

  for (offset = 6; offset + 2 <= size; offset += 2) {
    UINT16 ch;
    CopyMem (&ch, buffer + offset, sizeof (ch));
    if (ch == 0) {
      offset += 2;
      break;
    }
  }

  if (offset > size || fpLength > size - offset) {
    gBS->FreePool (buffer);
    return EFI_INVALID_PARAMETER;
  }

  path = (EFI_DEVICE_PATH_PROTOCOL *)(buffer + offset);
  if (!HvBootPathTargetsBootMgr (path, fpLength)) {
    gBS->FreePool (buffer);
    return EFI_NOT_FOUND;
  }

  options     = buffer + offset + fpLength;
  optionsSize = size - (offset + fpLength);

  if (VolRef != NULL && *VolRef != NULL) {
    HvBootReceiptLine (*VolRef, "CHAIN WIN slot load");
  }

  // 1. Try loading via the device path stored in the Boot#### slot
  status = gBS->LoadImage (TRUE, ImageHandle, path, NULL, 0, &winImage);

  // 2. If short-form path fails on Dell firmware, build canonical ESP path
  if (EFI_ERROR (status) && EspHandle != NULL) {
    EFI_DEVICE_PATH_PROTOCOL *winPath = HvBootBuildFilePath (EspHandle, HV_BOOT_WINDOWS_PATH);
    if (winPath != NULL) {
      if (VolRef != NULL && *VolRef != NULL) {
        HvBootReceiptLine (*VolRef, "CHAIN WIN esp retry");
      }
      status = gBS->LoadImage (TRUE, ImageHandle, winPath, NULL, 0, &winImage);
      gBS->FreePool (winPath);
    }
  }

  // 3. If device path loading still failed, try buffer load
  if (EFI_ERROR (status) && VolRef != NULL && *VolRef != NULL) {
    VOID       *winBuf = NULL;
    UINTN      winSize = 0;
    EFI_STATUS readSt  = HvBootReadFile (*VolRef, HV_BOOT_WINDOWS_PATH, &winBuf, &winSize);
    if (!EFI_ERROR (readSt) && winBuf != NULL && winSize > 0) {
      if (VolRef != NULL && *VolRef != NULL) {
        HvBootReceiptLine (*VolRef, "CHAIN WIN buf retry");
      }
      status = gBS->LoadImage (TRUE, ImageHandle, NULL, winBuf, winSize, &winImage);
      gBS->FreePool (winBuf);
    }
  }

  if (EFI_ERROR (status) || winImage == NULL) {
    if (VolRef != NULL && *VolRef != NULL) {
      HvBootReceiptStatus (*VolRef, "CHAIN WARN slot LoadImage", status);
    }
    gBS->FreePool (buffer);
    return status;
  }

  // Set LoadOptions (BCD parameters from the Boot#### option)
  status = gBS->HandleProtocol (winImage, &lipGuid, (VOID **)&info);
  if (!EFI_ERROR (status) && info != NULL && optionsSize > 0) {
    info->LoadOptions     = options;
    info->LoadOptionsSize = (UINT32)optionsSize;
  }

  *Found = TRUE;

  if (VolRef != NULL && *VolRef != NULL) {
    HvBootReceiptLine (*VolRef, "CHAIN WIN slot start");
    (*VolRef)->Close (*VolRef);
    *VolRef = NULL;
  }

  status = gBS->StartImage (winImage, NULL, NULL);

  gBS->FreePool (buffer);
  return status;
}

STATIC EFI_STATUS
HvBootChainloadWindows (
  IN     EFI_HANDLE          ImageHandle,
  IN     EFI_HANDLE          EspHandle,
  IN OUT EFI_FILE_PROTOCOL   **VolRef
  )
{
  EFI_STATUS  status;
  UINT32      attrs = 0;
  UINTN       orderSize = 0;
  UINT16      *order = NULL;
  UINTN       i;
  UINTN       count;
  BOOLEAN     found = FALSE;

  // 1. Walk BootOrder to chainload Windows Boot Manager using its configured NVRAM slot
  status = gRT->GetVariable ((CHAR16 *)L"BootOrder", &gEfiGlobalVariableGuid, &attrs, &orderSize, NULL);
  if (status == EFI_BUFFER_TOO_SMALL && orderSize > 0) {
    if (!EFI_ERROR (gBS->AllocatePool (EfiBootServicesData, orderSize, (VOID **)&order)) && order != NULL) {
      if (!EFI_ERROR (gRT->GetVariable ((CHAR16 *)L"BootOrder", &gEfiGlobalVariableGuid, &attrs, &orderSize, order))) {
        count = orderSize / sizeof (UINT16);
        for (i = 0; i < count; i++) {
          status = HvBootTryChainSlot (order[i], ImageHandle, EspHandle, VolRef, &found);
          if (found) {
            gBS->FreePool (order);
            return status;
          }
        }
      }
      gBS->FreePool (order);
    }
  }

  // 2. Try the standard Windows Boot Manager slot (Boot0005) directly
  status = HvBootTryChainSlot ((UINT16)BOOT_SLOT_FALLBACK, ImageHandle, EspHandle, VolRef, &found);
  if (found) {
    return status;
  }

  // 3. Fallback: Build device path for \EFI\Microsoft\Boot\bootmgfw.efi on this ESP handle
  if (EspHandle != NULL) {
    EFI_DEVICE_PATH_PROTOCOL  *winPath;
    EFI_HANDLE                winImage = NULL;

    winPath = HvBootBuildFilePath (EspHandle, HV_BOOT_WINDOWS_PATH);
    if (winPath != NULL) {
      if (VolRef != NULL && *VolRef != NULL) {
        HvBootReceiptLine (*VolRef, "CHAIN WIN esp path");
      }
      status = gBS->LoadImage (TRUE, ImageHandle, winPath, NULL, 0, &winImage);
      gBS->FreePool (winPath);
      if (!EFI_ERROR (status) && winImage != NULL) {
        if (VolRef != NULL && *VolRef != NULL) {
          HvBootReceiptLine (*VolRef, "CHAIN WIN esp start");
          (*VolRef)->Close (*VolRef);
          *VolRef = NULL;
        }
        return gBS->StartImage (winImage, NULL, NULL);
      }
      if (VolRef != NULL && *VolRef != NULL) {
        HvBootReceiptStatus (*VolRef, "CHAIN WARN esp LoadImage", status);
      }
    }
  }

  // 4. Fallback: Read \EFI\Microsoft\Boot\bootmgfw.efi into memory buffer
  if (VolRef != NULL && *VolRef != NULL) {
    VOID       *winBuf = NULL;
    UINTN      winSize = 0;
    EFI_HANDLE winImage = NULL;

    status = HvBootReadFile (*VolRef, HV_BOOT_WINDOWS_PATH, &winBuf, &winSize);
    if (!EFI_ERROR (status) && winBuf != NULL && winSize > 0) {
      HvBootReceiptLine (*VolRef, "CHAIN WIN buf load");
      status = gBS->LoadImage (TRUE, ImageHandle, NULL, winBuf, winSize, &winImage);
      gBS->FreePool (winBuf);
      if (!EFI_ERROR (status) && winImage != NULL) {
        HvBootReceiptLine (*VolRef, "CHAIN WIN buf start");
        (*VolRef)->Close (*VolRef);
        *VolRef = NULL;
        return gBS->StartImage (winImage, NULL, NULL);
      }
      if (*VolRef != NULL) {
        HvBootReceiptStatus (*VolRef, "CHAIN FAIL buf LoadImage", status);
      }
    } else {
      HvBootReceiptStatus (*VolRef, "CHAIN FAIL buf ReadFile", status);
    }
  }

  return EFI_NOT_FOUND;
}

// ── Entry point ─────────────────────────────────────────────────────────────

EFI_STATUS
EFIAPI
HvBootMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                       st;
  EFI_STATUS                       startSt;
  EFI_LOADED_IMAGE_PROTOCOL        *li   = NULL;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *fs   = NULL;
  EFI_FILE_PROTOCOL                *vol  = NULL;
  EFI_GUID                         lipGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
  EFI_GUID                         fsGuid  = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
  EFI_DEVICE_PATH_PROTOCOL         *corePath  = NULL;
  VOID                             *coreBuf   = NULL;
  UINTN                            coreSize   = 0;
  EFI_HANDLE                       coreImage  = NULL;
  HV_BOOT_MAILBOX                  mbox;
  UINT32                           mailboxFlags = 0;

  (void)SystemTable;   // only gBS/gImageHandle-level services are needed here

  // Step 1: our LoadedImage → DeviceHandle → ESP volume
  st = gBS->HandleProtocol (ImageHandle, &lipGuid, (VOID **)&li);
  if (EFI_ERROR (st) || li == NULL || li->DeviceHandle == NULL) {
    return EFI_LOAD_ERROR;
  }

  st = gBS->HandleProtocol (li->DeviceHandle, &fsGuid, (VOID **)&fs);
  if (EFI_ERROR (st) || fs == NULL) {
    return EFI_LOAD_ERROR;
  }

  st = fs->OpenVolume (fs, &vol);
  if (EFI_ERROR (st) || vol == NULL) {
    return EFI_LOAD_ERROR;
  }

  // Receipt line: entry point reached. Primary purpose of this module.
  HvBootReceiptLine (vol, "BOOT HIT");

  // ── Mode + rescue decision ─────────────────────────────────────────────
  //
  // This application owns the decision AND all disk I/O. Inputs: the mode file,
  // the receipt tail (the only durable record of what earlier boots did), and
  // the legacy volatile Pending flag from a pre-Pass-90 binary. Outputs: the
  // receipt lines that ARM the rescue rule, the mailbox flags the core obeys,
  // and - when a requested full-mode boot is denied - a rewrite of the mode
  // file to 'S' so the stand-down survives the next power cycle.
  {
    CHAR8             tail[HV_RECEIPT_TAIL_BYTES + 1];
    HV_RECEIPT_STATE  rst;
    HV_BOOT_DECISION  dec;
    INT32             cfg;
    UINT32            pending = 0;
    UINTN             size    = sizeof (pending);
    UINT32            attrs   = 0;
    UINTN             got;

    ZeroMem (&rst, sizeof (rst));
    cfg = HvBootReadCfg (vol);
    got = HvBootReceiptReadTail (vol, tail, sizeof (tail));
    if (got > 0) {
      HvReceiptScan (tail, (int)got, &rst);
    }

    // Legacy arm (volatile, only ever set by a pre-Pass-90 binary). It can only
    // ever force safe mode, never enable it, so keeping the read costs nothing
    // and covers a machine whose receipt was lost.
    if (EFI_ERROR (gRT->GetVariable ((CHAR16 *)L"HvEfiBootPending", &mLegacyModeGuid,
                                     &attrs, &size, &pending)) || (pending == 0)) {
      pending = 0;
    }

    HvBootDecide ((int)cfg, (int)pending, &rst, &dec);

    if (dec.WriteCfgSafe && !HvBootWriteCfgSafe (vol)) {
      HvBootReceiptLine (vol, "BOOT WARN cfg not disarmed");
    }
    if (dec.Line1[0] != 0) {
      HvBootReceiptLine (vol, dec.Line1);
    }
    if (dec.Line2[0] != 0) {
      HvBootReceiptLine (vol, dec.Line2);
    }

    mailboxFlags = (dec.RunFull ? 0u : HV_MAILBOX_FLAG_FORCE_SAFE) |
                   (dec.Rescued ? HV_MAILBOX_FLAG_RESCUED : 0u);
  }

  // Step 2: load hvcore.efi — device path first (the loaded core then gets a
  // real DeviceHandle, which its receipt writer and image-context logic
  // need), buffer fallback second (bring-up works, telemetry does not).
  // Mailbox: the core's ONLY telemetry channel, and the only way this boot can
  // be observed at all - it opens no file and reads no variable. Allocated
  // before the core is loaded; the address travels in LoadOptions below.
  HvBootMailboxSetup (vol, mailboxFlags, &mbox);
  if ((mbox.Pa != 0) && (mbox.LeftStage != 0xFFFFFFFFu)) {
    // A previous boot left a WRITTEN mailbox behind: it stopped before coming
    // back through this function normally (a hang, or a reset). The stage it
    // got to is the evidence a hang could never put in the receipt.
    HvBootReceiptNum (vol, "CORE LAST stage", mbox.LeftStage);
    if ((mbox.LeftFlags & HV_MAILBOX_FLAG_EBS_OK) != 0) {
      HvBootReceiptLine (vol, "CORE LAST EBS");
    }
  }

  corePath = HvBootBuildCorePath (li->DeviceHandle);
  if (corePath != NULL) {
    HvBootReceiptLine (vol, "BOOT PATH file");
    st = gBS->LoadImage (TRUE, ImageHandle, corePath, NULL, 0, &coreImage);
    gBS->FreePool (corePath);
  } else {
    st = EFI_UNSUPPORTED;              // force the fallback
  }

  if (EFI_ERROR (st)) {
    if (corePath != NULL) {
      // The device-path load failed — say why, then try the buffer.
      HvBootReceiptStatus (vol, "BOOT WARN fileload", st);
    }
    HvBootReceiptLine (vol, "BOOT PATH buffer");

    st = HvBootReadCore (vol, &coreBuf, &coreSize);
    if (EFI_ERROR (st)) {
      HvBootReceiptStatus (vol, "BOOT FAIL read-core", st);
      vol->Close (vol);
      return st;
    }

    st = gBS->LoadImage (TRUE, ImageHandle, NULL, coreBuf, coreSize, &coreImage);
    gBS->FreePool (coreBuf);
    if (EFI_ERROR (st)) {
      HvBootReceiptStatus (vol, "BOOT FAIL LoadImage", st);
      vol->Close (vol);
      return st;
    }
  }

  // Hand the mailbox address to the core. If this fails the core finds no valid
  // mailbox and stands down to safe mode - fail-closed by design - so it is
  // reported here and the boot continues instead of aborting.
  if (!HvBootSetLoadOptions (coreImage, mbox.Pa)) {
    HvBootReceiptLine (vol, "BOOT WARN no loadoptions");
  }

  // Step 3: StartImage. HvEfiDriverEntry runs. If it VMLAUNCHes, the guest
  // resumes here and StartImage returns EFI_SUCCESS. If it stood down to
  // safe mode, it returns EFI_ABORTED BY DESIGN — that is the mode gate's
  // contract, not a failure.
  HvBootReceiptLine (vol, "BOOT START");
  startSt = gBS->StartImage (coreImage, NULL, NULL);

  // Report what the core left in the mailbox. On a RETURN this is its stage
  // trace; after a hang nothing reaches here and the next boot reads the same
  // page (the fixed address is why) or, at minimum, sees "FULL START with no
  // completion".
  if (mbox.Pa != 0) {
    volatile HV_MAILBOX *mb = (volatile HV_MAILBOX *)(UINTN)mbox.Pa;
    if (HvMailboxValid (mb) && (HvMailboxSeq (mb) != 0)) {
      HvBootReceiptNum (vol, "CORE stage", (UINT32)mb->Stage);
      HvBootReceiptNum (vol, "CORE detail", (UINT32)mb->Detail);
      if (mb->EptPml4Units != 0) {
        HvBootReceiptNum (vol, "EPT units", mb->EptPml4Units);
        HvBootReceiptNum (vol, "EPT ranges", mb->EptRamRangeCount);
        HvBootReceiptNum (vol, "EPT maxphys_lo", mb->EptMaxPhysLow);
        HvBootReceiptNum (vol, "EPT maxphys_hi", mb->EptMaxPhysHigh);
        HvBootReceiptNum (vol, "EPT splits", mb->EptSplitCount);
        HvBootReceiptNum (vol, "EPT gb", mb->EptGbMapped);
      }
      if (mb->ActualPinCtls != 0 || mb->ActualExitCtls != 0) {
        HvBootReceiptNum (vol, "VMCS pin", mb->ActualPinCtls);
        HvBootReceiptNum (vol, "VMCS proc", mb->ActualProcCtls);
        HvBootReceiptNum (vol, "VMCS exit", mb->ActualExitCtls);
        HvBootReceiptNum (vol, "VMCS proc2", mb->ActualProcCtls2);
      }
      if (mb->TotalExitCount != 0)
        HvBootReceiptNum (vol, "EXITS total", mb->TotalExitCount);
      if (mb->VmresumeFailCount != 0)
        HvBootReceiptNum (vol, "VMRESUME fails", mb->VmresumeFailCount);
      if (mb->HostFaultCount != 0)
        HvBootReceiptNum (vol, "HOST faults", mb->HostFaultCount);
      if ((HvMailboxFlags (mb) & HV_MAILBOX_FLAG_EBS_OK) != 0) {
        HvBootReceiptLine (vol, "CORE EBS");
      }
    }
  }

  if (startSt == EFI_ABORTED) {
    // Designed stand-down (safe mode / self-rescue / clean bring-up
    // refusal). The core returned an error, so CoreStartImage unloaded its
    // image — correct, nothing is resident.
    HvBootReceiptStatus (vol, "BOOT SAFE stood-down", startSt);
    st = startSt;
  } else if (EFI_ERROR (startSt)) {
    HvBootReceiptStatus (vol, "BOOT FAIL StartImage", startSt);
    st = startSt;
  } else {
    // Hypervisor resident. CoreStartImage does not unload a driver that
    // returned success — the exit handler keeps executing from
    // EfiRuntimeServicesCode after ExitBootServices.
    //
    // FULL DONE closes the rescue rule. It means "bring-up returned success",
    // NOT "ExitBootServices was reached": that happens later, inside the OS
    // loader, which this application cannot observe. The core sets
    // HV_MAILBOX_FLAG_EBS_OK in its EBS callback and the NEXT boot can read
    // that off the leftover page (reported above as CORE LAST EBS).
    HvBootReceiptLine (vol, "FULL DONE");
    HvBootReceiptLine (vol, "BOOT DONE");
    st = EFI_SUCCESS;
  }

  // Chainload Windows Boot Manager directly instead of returning error to BDS.
  // On Dell / OEM UEFI firmwares, returning an error to BDS causes Dell firmware
  // to display "No bootable devices found" or halt POST instead of advancing.
  // Chainloading bootmgfw.efi directly boots Windows seamlessly with the
  // hypervisor remaining resident in memory.
  {
    EFI_STATUS chainSt = HvBootChainloadWindows (ImageHandle, li->DeviceHandle, &vol);
    if (vol != NULL) {
      HvBootReceiptStatus (vol, "CHAIN FAIL final", chainSt);
      vol->Close (vol);
      vol = NULL;
    }
  }

  return EFI_ERROR (st) ? st : EFI_ABORTED;
}


// hv_efi_main.c - EFI DXE Runtime Driver entry point.
//
// Replaces HvDrv/hv_driver.c's DriverEntry with an EFI DXE image entry.
// Loads before the OS kernel — no PsLoadedModuleList, no SCM service,
// PatchGuard never sees it.
//
// Boot sequence:
//   1. UEFI firmware loads HvEfi.efi as a DXE runtime driver - in this tree,
//      normally through HvBoot.efi (the 0xA application that owns all disk
//      I/O and every mode/rescue decision) via the Boot#### slot.
//   2. HvEfiDriverEntry runs during DXE phase (identity-mapped, all CPUs up).
//      The mode gate comes first and has ONE input: the shared mailbox HvBoot
//      armed before loading this image. SAFE MODE unless that mailbox says
//      full - and a boot with no mailbox always stands down, because an
//      unobservable full-mode attempt is what Pass 89 spent six boots on.
//   3. Checks VMX support, builds host page tables, initialises VMX
//   4. Reads auth ticket from EFI variable (set by launcher)
//   5. Derives session keys, sets up EPT, hides hypervisor pages
//   6. Virtualises all CPUs via EFI_MP_SERVICES_PROTOCOL
//   7. Wipes secrets from g_Hv, returns EFI_SUCCESS
//   8. Firmware calls ExitBootServices; OS kernel boots under the hypervisor
//
// After ExitBootServices, only the VMX exit handler runs. No EFI services
// are called from VMX root mode.
//
// Return status is load-bearing. MdeModulePkg/Core/Dxe/Image/Image.c unloads
// any image whose StartImage returns an error - including a driver image, which
// would free the very pages the VMX exit handler executes from. So every step
// before VMLAUNCH returns a real error (nothing is resident yet, and BDS then
// continues with the next BootOrder entry), while the success path must return
// EFI_SUCCESS. Safe mode is the deliberate exception: it is not resident, so it
// returns EFI_ABORTED rather than pretending to have booted the machine.
//
// Telemetry: this driver writes NOTHING to disk or NVRAM - both deadlock the
// target firmware when reached from this image. Progress goes to a shared
// memory mailbox (HvMailbox below) that HvBoot reads back and reports into
// \EFI\Boot\hvefi.log (written by HvBoot, whose file I/O is safe).

#include "hv_efi.h"
// Boot-stage codes (HV_STAGE_*) written into the status variable by
// HvReportStage below and decoded by tools/diag/hv_efi_diag.c. The header is
// deliberately dependency-free so the Win32 diagnostic tool can include it too.
#include "hv_efi_stage.h"
// The boot-mode contract shared with HvBoot, hv_launcher.c, the diagnostic and
// the unit tests: the mailbox layout this driver reports into (writer side) and
// the mode decision it OBEYS (reader side). One implementation of the decision
// lives there, not two - see the header for why that matters.
#include "hv_efi_bootcfg.h"
// NOTE: this driver performs ZERO disk I/O - no file opens, no variable
// writes. Storage-subsystem calls from this 0xC runtime-driver image deadlock
// the target firmware (six boots of evidence, see the variable-write ban and
// the mailbox block below); ALL telemetry goes through the shared mailbox
// page, and HvBoot (the 0xA application that loads this driver) owns the
// receipt file.

// ── EFI globals ─────────────────────────────────────────────────────────────

EFI_BOOT_SERVICES        *gEfiBS = NULL;
EFI_RUNTIME_SERVICES     *gEfiRT = NULL;
EFI_MP_SERVICES_PROTOCOL *gEfiMp = NULL;

// Patchable EFI variable name. Initialized with a sentinel pattern so the
// static string "HvDrvTicket" never appears in the binary. InstallEfiBinary()
// in hv_launcher.c scans for the sentinel bytes (UTF-16 LE: EF EF BE BE AD AD
// DE DE 00 00) and overwrites this buffer with a random name before installation.
// The EFI driver fails gracefully if the sentinel is still present at boot.
CHAR16 gHvVarName[24] = {0xEFEF, 0xBEBE, 0xADAD, 0xDEDE, 0};

// Patchable EFI GUID for the auth ticket variable. Sentinel Data1 = 0xDEADC0DE.
// InstallEfiBinary() scans for these 16 sentinel bytes and overwrites them with
// a randomly generated GUID before writing to the ESP, so the static GUID never
// appears in the shipped binary. HvReadTicket() checks for the sentinel at boot.
EFI_GUID gHvTicketGuid = {
    0xDEADC0DE, 0xDEAD, 0xC0DE,
    {0xDE, 0xAD, 0xC0, 0xDE, 0xDE, 0xAD, 0xC0, 0xDE}
};

// ── Pre-entry diagnostics (unconditional, no sentinel gate) ─────────────────
// The regular HvReportStage path (below) is silenced when the launcher's
// sentinel patches have not taken effect (unpatched GUID/name). That is
// correct for stealth, but it leaves no way to distinguish "firmware never
// called entry" from "entry ran but sentinels were stale".
//
// This pair runs ahead of all of that:
//   - HV_POST writes a byte to I/O port 0x80 (standard POST code port). A
//     POST reader (if attached) displays it; otherwise the write is harmless.
//   - The shared mailbox page (HvMailbox below) is the execution evidence:
//     HvBoot reads it back and writes the receipt, which survives power
//     cycles and is always readable from Windows. Storage I/O and variable
//     writes are BANNED in this driver - they deadlock the target firmware.
//
// Both are called at the very top of HvEfiDriverEntry before any other work.

// __outbyte and HV_POST live in hv_efi.h as of pass 91, because hv_efi_smp.c
// posts stage bytes from the per-AP launch failure path too and a second copy
// of this macro would be a second thing to keep in sync.

// POST CODE MAP — keep every value distinct.
//
// Port 0x80 holds one byte and only the LAST write survives, so a brick is
// diagnosed by reading that byte back. A value reused at two points on the
// path destroys that: the reader cannot tell which of the two points was
// reached, which is the entire question being asked. Claim a new code
// rather than reusing one:
//
//   Entry preamble (pre mode-gate, cannot hang firmware):
//     0xB0  entry reached
//     0xB1  g_EnteredOnce guard passed
//     0xB2  gEfiBS/gEfiRT captured
//     0xB9  second entry (already-started early return)
//     0xB3  no valid mailbox: unobservable boot, standing down (Pass 90)
//     0xBA  SAFE MODE standing down (returns EFI_ABORTED by design)
//     0xBE  the stand-down is a rescue - the mailbox says a full attempt did
//           not finish and the user has not retried since
//
//   Full-mode bring-up prologue (0xC-range):
//     0xC0  past mode gate, entering full-mode bring-up
//     0xC1  HvReportStage(HV_STAGE_ENTRY) written
//     0xC2  mode taken from the mailbox (Pass 90: nothing is written here)
//     0xC4  firmware watchdog armed (120 s)
//     0xC5  ExitBootServices callback registered (end of bring-up)
//
//   Retired: 0xC3 (HvEfiBootPending arm), 0xAA (the receipt-based rescue, which
//   is now decided by HvBoot BEFORE this image is loaded) and every
//   HvEfiEntryMarker write - all were SetVariable calls, and a SetVariable from
//   this driver deadlocks the target firmware. See the variable-write ban.
//
//   Hypervisor bring-up (unchanged from Pass 80):
//     0xB5  HandleProtocol done                   0xBB  EPT hiding complete
//     0xB6  image protocol located                0xBC  about to hide EFI image
//     0xB7  about to virtualize every CPU         0xBD  image hide complete
//     0xB8  about to hide EPT pages               0xBF  bring-up complete
//
//   Failure codes:
//     0xE5  image protocol failed
//     0xE7  CPU virtualization failed
//     0xEA  EPT hide failed
//     0xEC  image hide failed

// ── VARIABLE-WRITE BAN (read this before re-adding any SetVariable) ─────────
//
// Five boots on the Dell target (Oct 5) established the following: every boot
// in which the driver executed a SetVariable call hung the machine with zero
// receipt trace, and the one boot whose executed path contained none (safe
// mode, bridge 1) returned cleanly. The deadlock is independent of the
// attributes — volatile BS|RT (0x06) writes hang exactly like NV (0x07) —
// and of the call site. Pass 88's SPI-flash-lock finding explains the NV
// case (the Boot Manager holds the flash lock across StartImage); the
// volatile case indicates Dell's variable driver serializes EVERY write
// behind that same lock. HvProbe once measured a successful volatile write
// from this context, but five driver boots outweigh one probe data point.
//
// RULE (Pass 90, tightened): ZERO variable WRITES - before ExitBootServices
// and after it - and ZERO FILE operations, ever. The mode decision now arrives
// through the shared mailbox, so the three GetVariable mode reads that used to
// sit in the gate are gone as well.
//
// Exactly one firmware datum still comes from the variable stack: the auth
// ticket at Step 5 (HvReadTicket). That read is deliberate, it happens before
// VMLAUNCH, and it has never actually executed on this firmware - no full-mode
// boot has ever got past the gate to reach it. The mailbox stage codes are how
// its first real run will be observed. Moving the ticket into the mailbox
// (HvBoot reads it and passes the bytes) is the next hardening step.
//
// ALL telemetry goes to the mailbox page: plain memory stores, no firmware
// call on any path, so no telemetry write can hang.

// UEFI-defined event group for ExitBootServices. Hard-coded here so we don't
// need to add gEfiEventExitBootServicesGuid to HvEfi.inf's [Guids] list.
// Spec reference: UEFI 2.10 section 7.1.
static EFI_GUID gEfiEventExitBootServicesGuid = {
    0x27abf055, 0xb1b8, 0x4c26,
    {0x80, 0x48, 0x74, 0x8f, 0x37, 0xba, 0xa2, 0xdf}
};

// The mode-gate variables (HvEfiFullMode / HvEfiSafeMode / HvEfiBootPending)
// and their fixed GUID are GONE from this driver as of Pass 90: it neither
// reads nor writes them. The mode arrives in the mailbox, the arming decision
// belongs to HvBoot, and the durable state lives in the \\EFI\\Boot\\hvcfg
// file. tools/diag/hv_efi_diag.c still knows the old GUID so it can explain a
// machine left behind by a pre-Pass-90 binary.

// ── Boot mailbox (shared-memory telemetry, zero storage I/O) ────────────
//
// Six boots on the Dell target established that ANY storage-subsystem call
// made from this 0xC runtime-driver image - a file open on the ESP, a
// SetVariable, anything reaching the disk or variable stack - deadlocks the
// firmware, while the IDENTICAL calls from the 0xA HvBoot application (which
// loads this driver) succeed every time. The in-driver receipt writer is
// therefore gone: this core must not touch the disk at all.
//
// Telemetry flows through a shared "mailbox" page instead: HvBoot allocates
// it at a fixed physical address, arms it, and passes the address via this
// image's LoadOptions. Every stage write here is a plain memory store - no
// firmware calls, cannot hang. HvBoot reads the mailbox back after
// StartImage and writes the receipt (its file I/O is proven safe), and -
// because the fixed address survives warm resets - the stage from a boot
// that HUNG is still there for the next boot's HvBoot to report.

// The layout, the flags and the reader/writer helpers live in
// HvEfi/hv_efi_bootcfg.h - the same header HvBoot, hv_launcher.c and the unit
// tests include, so the writer and the reader of this page cannot drift apart.
// Everything this driver does with it is a plain memory store: no firmware
// call, so no path through this page can hang.
volatile HV_MAILBOX *g_Mailbox = NULL;

// ExitBootServices callback: proves the full-mode boot reached a point
// where the OS loader is about to take over, i.e. no hang between
// HvEfiDriverEntry and here. Disarms the firmware watchdog so a slow but
// intact subsequent boot is not auto-reset.
//
// Deliberately contains ZERO variable writes: the "released SPI lock at EBS"
// assumption behind the old NV writes here was never verified on hardware,
// and a deadlock inside this callback would reboot-loop the machine (the
// receipt's FULL EBS line would already be down, so the rescue rule would
// not stand the next boot down). The receipt is the success record;
// HvLauncher.exe --detect is the definitive residency check.
static VOID EFIAPI HvEfiOnExitBootServices(EFI_EVENT ev, VOID *ctx) {
    (void)ev; (void)ctx;

    // Flag EBS in the mailbox (a memory store - the ONLY safe kind of write
    // here). HvBoot writes the receipt's "FULL EBS" line when StartImage
    // returns success, which is the rescue-rule completion signal.
    HvMailboxSetFlag(g_Mailbox, HV_MAILBOX_FLAG_EBS_OK);

    // Publish any EPT mutation so every processor invalidates at its own next
    // VM exit - i.e. as Windows takes over. Store-only, which is why it is
    // admissible in this callback at all; a broadcast INVEPT is not, because
    // the other processors are in VMX non-root and this one may not call
    // firmware here. See ../hv_ept_gen.h.
    HvSmpBroadcastEptFlush();

    if (gEfiBS) {
        gEfiBS->SetWatchdogTimer(0, 0, 0, NULL);
    }
    HV_POST(0xBF);  // "bring-up complete, OS about to take over"
}

// ── Boot-stage reporting (mailbox-only) ────────────────────────────
// Every stage writes its HV_STAGE_* value into the shared mailbox - a plain
// memory store, no firmware calls, cannot hang. HvBoot reads the mailbox
// after StartImage (or the next boot's HvBoot reads the leftover after a
// hang - the fixed page survives warm resets) and writes the receipt.
// Unprovisioned binaries report too: the mailbox is ephemeral memory, there
// is nothing to gate on, and the stage trace is exactly what a hang needs.

void HvReportStage(UINT32 stage, UINT32 detail) {
    HvMailboxReport(g_Mailbox, stage, detail);
}

// ── Random number generation ────────────────────────────────────────────────

static UINT64 HvRandom64(void) {
    // HvRandomU64 gates RDRAND on CPUID.1:ECX[30]; no bare _rdrand64_step here.
    return HvRandomU64();
}

// ── Host page table builder ─────────────────────────────────────────────────
// Build identity-mapped x86-64 page tables (2MB large pages) for HOST_CR3.
// These persist after ExitBootServices because they're allocated as
// EfiRuntimeServicesData.
//
// Structure: PML4 → one PDPT per 512GB unit → 512 PD pages of 512 × 2MB entries.
// The unit count comes from the same HvEptPml4Units decision the EPT uses, so
// the host maps exactly what the EPT maps.
//
// This must cover all of RAM, not just the low 512GB. In VMX root the CPU runs
// on this address space (identity mapped, VA == PA), and the hypercall path
// dereferences *guest* physical addresses directly: TranslateGuestVa/ReadPteAtPa
// walk guest page tables, and HcReadPhysical/HcWritePhysical copy to and from a
// caller-supplied physical address. Once the EPT maps RAM above 512GB so the
// guest can use it, a host access there must resolve too, or the first such
// hypercall faults in root with no handler and bugchecks.

NTSTATUS HvBuildHostPageTables(UINT64 imageBase, UINT64 imageSize) {
    // Share the RAM snapshot with the EPT so both cover exactly the same range.
    if (g_Hv.Ept.RamRangeCount == 0) {
        NTSTATUS ns = HvEptCollectRamRanges(&g_Hv.Ept);
        if (!NT_SUCCESS(ns)) return ns;
    }

    UINT32 units = HvEptPml4Units(g_Hv.Ept.RamRanges, g_Hv.Ept.RamRangeCount);

    // NX (bit 63) is reserved in page-table entries when EFER.NXE is clear;
    // setting it then would #PF on the first access. Gate the whole NX pass.
    BOOLEAN nxUsable = (__readmsr(MSR_IA32_EFER) & (1ULL << 11)) != 0;

    // PML4 page
    UINT64 *pml4 = (UINT64 *)EfiAllocPagesBelow4G(1);
    if (!pml4) return STATUS_INSUFFICIENT_RESOURCES;

    for (UINT32 u = 0; u < units; u++) {
        // One PDPT page per 512GB unit
        UINT64 *pdpt = (UINT64 *)EfiAllocPagesBelow4G(1);
        if (!pdpt) goto unwind;
        pml4[u] = EfiVaToPA(pdpt) | 0x03;  // P + RW

        // 512 PD pages, each mapping 512 × 2MB large pages
        for (UINT32 i = 0; i < 512; i++) {
            UINT64 *pd = (UINT64 *)EfiAllocPagesBelow4G(1);
            if (!pd) goto unwind;

            // The 1GB index is flat across units: unit u, PDPT slot i → (u*512+i) GB
            for (UINT32 j = 0; j < 512; j++) {
                UINT64 pa = ((UINT64)(u * 512 + i) << 30) | ((UINT64)j << 21);
                // NX on every 2MB leaf except the ones covering our own image:
                // VMX root executes only the image, and a non-executable host
                // map keeps a stray guest-physical dereference from ever
                // executing data as code. Bit 63 is reserved when EFER.NXE is
                // clear, so it is only set when NXE is actually on.
                UINT64 entry = pa | 0x83;  // P + RW + PS (2MB page)
                UINT64 imageEnd = imageBase + imageSize;
                BOOLEAN overlapsImage =
                    !(pa + (1ULL << 21) <= imageBase || pa >= imageEnd);
                if (nxUsable && !overlapsImage)
                    entry |= (1ULL << 63);  // NX
                pd[j] = entry;
            }

            pdpt[i] = EfiVaToPA(pd) | 0x03;  // P + RW
        }
    }

    g_Hv.HostPml4Va = pml4;
    g_Hv.HostPml4Pa = EfiVaToPA(pml4);
    g_Hv.HostPml4Units = units;

    EfiPrint("[VMX] Host page tables built at PA=0x%lx (%u GB / %u unit(s))\n",
             g_Hv.HostPml4Pa, units * 512, units);

    return STATUS_SUCCESS;
unwind:
    // Every page is identity mapped, so the partially built tables are walkable
    // and can be released exactly.
    for (UINT32 uu = 0; uu < units; uu++) {
        if (!(pml4[uu] & 1)) continue;
        UINT64 *pdpt = (UINT64 *)(UINTN)(pml4[uu] & ~0xFFFULL);
        for (UINT32 i = 0; i < 512; i++) {
            if (pdpt[i] & 1)
                EfiFreePages((VOID *)(UINTN)(pdpt[i] & ~0xFFFULL), 1);
        }
        EfiFreePages(pdpt, 1);
    }
    EfiFreePages(pml4, 1);
    return STATUS_INSUFFICIENT_RESOURCES;
}

// ── Host page table teardown ────────────────────────────────────────────────
// Frees the PML4 and every mapped unit's PDPT plus its 512 PD pages. Called
// from HvVmxShutdown so every teardown path (driver-entry fail_vmx, VMX init
// failure, unload) releases the host map — it was previously leaked on all of
// them. Every page is identity mapped, so the tables are walkable here exactly
// as in the builder's unwind path.

void HvDestroyHostPageTables(void) {
    if (!g_Hv.HostPml4Va) return;

    // Same guard as HvVmxShutdown: when a peer AP may still be inside
    // VirtualizeCpuBody it is running with this page table as CR3. Zeroing and
    // freeing it under that CPU turns its next instruction fetch into a #PF in
    // VMX root mode, which has no handler and triple-faults. The `fail:` path in
    // HvEfiDriverEntry reaches this function directly, so guarding only inside
    // HvVmxShutdown would not cover it.
    if (g_Hv.TeardownUnsafe) {
        EfiFatal("HvEfi: host page tables left allocated "
                 "(AP callback in flight)\n");
        g_Hv.HostPml4Va = NULL;
        g_Hv.HostPml4Pa = 0;
        g_Hv.HostPml4Units = 0;
        return;
    }

    UINT64 *pml4 = (UINT64 *)g_Hv.HostPml4Va;
    for (UINT32 u = 0; u < g_Hv.HostPml4Units; u++) {
        if (!(pml4[u] & 1)) continue;
        UINT64 *pdpt = (UINT64 *)(UINTN)(pml4[u] & ~0xFFFULL);
        for (UINT32 k = 0; k < 512; k++) {
            if (pdpt[k] & 1) {
                RtlSecureZeroMemory((VOID *)(UINTN)(pdpt[k] & ~0xFFFULL),
                                    PAGE_SIZE);
                EfiFreePages((VOID *)(UINTN)(pdpt[k] & ~0xFFFULL), 1);
            }
        }
        RtlSecureZeroMemory(pdpt, PAGE_SIZE);
        EfiFreePages(pdpt, 1);
        pml4[u] = 0;
    }
    RtlSecureZeroMemory(pml4, PAGE_SIZE);
    EfiFreePages(pml4, 1);

    g_Hv.HostPml4Va = NULL;
    g_Hv.HostPml4Pa = 0;
    g_Hv.HostPml4Units = 0;
}

// ── Ticket read from EFI variable ───────────────────────────────────────────
// The launcher writes a 32-byte ticket to an EFI variable before rebooting.
// HvBoot - an application, and one that already uses the variable stack for its
// own boot decision - reads it and publishes it into the mailbox. The core
// never touches the variable stack.
//
// Pass 94 moved this here->mailbox. The GetVariable call that used to live in
// this function was the last runtime-service call on the core's boot path, and
// this image has hung the machine enough times that "one fewer service call
// before ExitBootServices" is worth a small amount of coupling. The trust
// boundary is unchanged: both images are provisioned from the same patched
// random variable name, and the size check that used to reject a wrong-sized
// variable is now the TicketSize check on the mailbox.
//
// The sentinel guards below still run. They now answer "was the CORE
// provisioned" rather than "can the core find its variable" - still worth
// knowing, because an unprovisioned core was never told to run at all.
//
// The ticket is deliberately NOT consumed or cleared. Deleting the variable
// before bring-up is known to have succeeded made any later failure permanent:
// the ticket was already gone, so every subsequent boot failed identically,
// indistinguishable from a driver that never loaded, and unrecoverable without
// re-running --provision. A ticket that stays put is harmless - 32 random bytes
// under a random name - and "ticket PRESENT" in the diag no longer means "never
// ran"; the receipt and HvLauncher --detect are the residency evidence.

static BOOLEAN HvReadTicket(UINT64 ticket[4]) {
    // Guard: if InstallEfiBinary() never patched this binary, gHvVarName and/or
    // gHvTicketGuid still hold their sentinel values. Fail gracefully.
    if (gHvVarName[0] == 0xEFEF && gHvVarName[1] == 0xBEBE) {
        // Pre-launch: VMX not started. Dark mode makes no sense here; just abort.
        EfiFatal("EFI binary not provisioned — run launcher --provision --efi first\n");
        return FALSE;
    }
    if (gHvTicketGuid.Data1 == 0xDEADC0DE) {
        EfiFatal("EFI GUID sentinel not patched — run launcher --provision --efi first\n");
        return FALSE;
    }

    unsigned char raw[HV_TICKET_BYTES];
    UINT32 i;

    if (!HvMailboxTicketGet(g_Mailbox, raw)) {
        // Three distinct causes needing three different fixes, so name all of
        // them instead of reporting a bare "no ticket":
        //   - the core is unprovisioned      (the sentinel guards above fired)
        //   - HvBoot.efi is unprovisioned, so it could not read the variable
        //   - the variable is missing or the wrong size
        // None of these hang the machine: this returns before any VMX state
        // exists, so the boot continues with no hypervisor rather than freezing.
        EfiFatal("No auth ticket in the mailbox.\n"
                 "    HvBoot.efi must be provisioned too: run the launcher with\n"
                 "    --provision, then install the patched HvBoot.efi\n"
                 "    with --install-raw.\n");
        return FALSE;
    }

    for (i = 0; i < HV_TICKET_BYTES / 8u; i++) {
        ticket[i] = (UINT64)raw[i * 8u]
                  | ((UINT64)raw[i * 8u + 1u] << 8)
                  | ((UINT64)raw[i * 8u + 2u] << 16)
                  | ((UINT64)raw[i * 8u + 3u] << 24)
                  | ((UINT64)raw[i * 8u + 4u] << 32)
                  | ((UINT64)raw[i * 8u + 5u] << 40)
                  | ((UINT64)raw[i * 8u + 6u] << 48)
                  | ((UINT64)raw[i * 8u + 7u] << 56);
    }
    RtlSecureZeroMemory(raw, sizeof(raw));

    // The ticket is deliberately NOT deleted here. Deleting it at this point,
    // before bring-up is known to have succeeded, made any later failure
    // (Steps 6-12) permanent: the ticket was already gone, so every subsequent
    // boot failed right here with "not found" - indistinguishable from a driver
    // that never loaded, and unrecoverable without re-running --provision.
    // The ticket is deliberately never DELETED any more: the only delete
    // path was a SetVariable, which deadlocks this firmware. A ticket that
    // stays in NVRAM is harmless — it is 32 random bytes under a random
    // name — and "ticket PRESENT" in the diag no longer means "never ran";
    // the receipt and HvLauncher --detect are the residency evidence.

    return TRUE;
}

// ── Hidden page collection ──────────────────────────────────────────────────

static void AddHiddenPage(UINT64 pa) {
    if (g_Hv.HiddenPageCount < HV_MAX_HIDDEN_PAGES) {
        g_Hv.HiddenPages[g_Hv.HiddenPageCount++] = pa & ~0xFFFULL;
    }
}

static void AddHiddenRange(UINT64 basePa, UINT64 bytes) {
    for (UINT64 off = 0; off < bytes; off += PAGE_SIZE) {
        AddHiddenPage(basePa + off);
    }
}

static void AddHiddenVa(PVOID va) {
    // In EFI identity mapping, VA == PA
    AddHiddenPage(EfiVaToPA(va));
}

static void AddHiddenVaRange(PVOID va, UINT64 bytes) {
    // In EFI identity mapping, each virtual page maps to the same physical page
    if (!va || bytes == 0) return;
    UINT64 base = EfiVaToPA(va);
    if (bytes > MAXULONG64 - base) return;
    AddHiddenRange(base, bytes);
}

// ── Driver Entry ────────────────────────────────────────────────────────────

static const char * const g_StepMarkers[] = {
    "Step 1: VMX supported",
    "Step 4: Nonce generated",
    "Ticket read from the mailbox",
    "Session keys derived",
    "Decoy pages allocated",
    "EPT hiding complete",
    "All %u CPUs virtualized",
    "Secrets wiped from g_Hv"
};

static BOOLEAN g_EnteredOnce = FALSE;

// The real body. HvEfiDriverEntry below wraps it for exactly one reason:
// disarming the watchdog on every error return. See the wrapper.
static EFI_STATUS EFIAPI HvEfiDriverEntryImpl(
    EFI_HANDLE        imageHandle,
    EFI_SYSTEM_TABLE  *systemTable)
{
    (VOID)g_StepMarkers;
    // Guard against an accidental second start.
    //
    // DXE_RUNTIME_DRIVER lifecycle note: SetVirtualAddressMap is delivered as an
    // EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE event, NOT by reinvoking this entry
    // point.  We do not register for that event because VMX root uses its own
    // identity-mapped host page tables (HOST_CR3) and never calls EFI services
    // after VMLAUNCH.  All allocations are identity-mapped and persist as-is.
    // ABSOLUTE first — port 0x80 POST code and NVRAM entry marker. These run
    // before any firmware-dependent logic and before the sentinel-patch gate,
    // so a brick that happens later leaves recoverable evidence that entry
    // was reached. HV_POST writes a byte that a POST reader (if attached)
    // displays; HvEfiEntryMarker writes a fixed-GUID NVRAM variable that
    // hv_efi_diag.exe reads back from the OS after recovery.
    HV_POST(0xB0);

    if (g_EnteredOnce) {
        HV_POST(0xB9);
        return EFI_ALREADY_STARTED;
    }
    g_EnteredOnce = TRUE;
    HV_POST(0xB1);

    // Store EFI service pointers before any firmware call.
    gEfiBS = systemTable->BootServices;
    gEfiRT = systemTable->RuntimeServices;
    HV_POST(0xB2);

    // Mailbox handoff: HvBoot allocated a fixed-address page and passed its
    // physical address via this image's LoadOptions (8 bytes). Validating the
    // magic makes a stale or absent mailbox harmless - the boot proceeds
    // without telemetry rather than trusting garbage. Writing stage 0 here is
    // the ran / never-ran discriminator for every boot: it is a plain memory
    // store, cannot hang, and HvBoot reports it into the receipt.
    {
        EFI_LOADED_IMAGE_PROTOCOL *li = NULL;
        EFI_GUID lipGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
        if (!EFI_ERROR(gEfiBS->HandleProtocol(imageHandle, &lipGuid,
                                              (VOID **)&li)) && li != NULL &&
            li->LoadOptions != NULL && li->LoadOptionsSize >= sizeof(UINT64)) {
            UINT64 pa = 0;
            CopyMem(&pa, li->LoadOptions, sizeof(pa));
            if (pa != 0 && (pa & 0xFFF) == 0) {
                volatile HV_MAILBOX *mb = (volatile HV_MAILBOX *)(UINTN)pa;
                if (HvMailboxValid(mb)) {
                    g_Mailbox = mb;
                    HvMailboxReport(mb, 0, 0);   // stage 0 = entry hit
                }
            }
        }
    }

    // ── Mode gate: the mailbox is the ONLY input ─────────────────────────────
    //
    // HvBoot (the 0xA application) read the receipt tail, the mode file
    // (\EFI\Boot\hvcfg) and the legacy Pending flag, wrote the receipt lines
    // that ARM the rescue rule, and put its decision into the mailbox flags.
    // This driver OBEYS that decision; it does not re-derive it. Two
    // implementations of one decision can disagree, and when they do the
    // receipt stops describing reality: an "ENTRY FULL / FULL START" that this
    // driver then stood down from reads, on the next boot, as a hang that never
    // happened - which disarms full mode permanently and silently.
    //
    // The three GetVariable mode reads that used to live here are gone. Reads
    // take no flash lock and are almost certainly safe, but this image has hung
    // the machine five times, the decision has already been made elsewhere, and
    // nothing on this path needs the variable stack to make it. Fewer firmware
    // calls on the boot path is the entire lesson of Pass 89.
    //
    // Safe mode therefore does only: POST codes, two pointer stores, one
    // memory-only mailbox report, and the return. No variable access, no file
    // access, no VMX state.
    //
    // FAIL CLOSED: no mailbox means this boot cannot be observed, and an
    // unobservable full-mode bring-up is the exact thing six boots were spent
    // chasing. Stand down instead of running blind.
    if (g_Mailbox == NULL || !HvMailboxValid(g_Mailbox)) {
        HV_POST(0xB3);   // no mailbox: unobservable boot, standing down
        return EFI_ABORTED;
    }

    {
        // The decision, in one place, made by HvBoot: FORCE_SAFE means it
        // evaluated the mode file and the receipt and stood this boot down.
        BOOLEAN runFull = (HvMailboxFlags(g_Mailbox) & HV_MAILBOX_FLAG_FORCE_SAFE) == 0;
        BOOLEAN rescued = (HvMailboxFlags(g_Mailbox) & HV_MAILBOX_FLAG_RESCUED) != 0;

        if (!runFull) {
            HV_POST(rescued ? 0xBE : 0xBA);
            // The ENTRY SAFE receipt line is HvBoot's job now (it owns all
            // disk I/O); this driver only records the stand-down in the
            // mailbox, which HvBoot reports after StartImage returns.
            HvMailboxReport(g_Mailbox, HV_STAGE_DARK, 0);

            // Return a NON-success status. Nothing is resident in safe mode, so
            // the DXE core's unload-on-error path (MdeModulePkg/Core/Dxe/Image
            // /Image.c: "If the image returned an error ... unload it") frees
            // nothing that matters here, and a failed status is what makes BDS
            // continue with the next BootOrder entry instead of stopping the
            // walk to present the Boot Manager Menu (BdsEntry.c
            // BootBootOptions() breaks on EFI_SUCCESS when a boot manager menu
            // exists; the status it tests is the image's StartImage return,
            // BmBoot.c). Returning EFI_SUCCESS here is how a diagnostic slot
            // "succeeds" without ever booting an OS.
            //
            // NOTE: this is only safe because safe mode is not resident. After
            // VMLAUNCH an error return would unload this image - code the
            // hypervisor's exit handler executes from - so the success path
            // below must keep returning EFI_SUCCESS.
            return EFI_ABORTED;
        }
    }
    HV_POST(0xC0);  // past mode gate, entering full-mode bring-up

    HvReportStage(HV_STAGE_ENTRY, 0);
    HV_POST(0xC1);

    // Receipt: the mode, then the arm point. Both are written before any VMX
    // work, so a hang after this leaves "started, never reached EBS" for the
    // next boot's self-rescue rule to find.
    // The ENTRY FULL / FULL START receipt lines are HvBoot's (it owns disk
    // I/O and writes them before loading this image). Nothing to do here.
    HV_POST(0xC2);  // mode recorded in the mailbox

    // NOTE: the old HvEfiBootPending arm is retired — it was a SetVariable,
    // and every SetVariable from this driver deadlocks this firmware (see the
    // variable-write ban). The receipt's "FULL START" line is the rescue
    // signal: it survives the reset the Pending flag never did, and the next
    // boot's mode gate reads it.

    // Firmware watchdog: 120 seconds. If anything between here and EBS
    // hangs, the firmware auto-resets. Recovery does not depend on it: HvBoot
    // already wrote "FULL START" before loading this image, so the next boot's
    // HvBoot reads an unfinished full attempt, stands down to safe mode AND
    // rewrites \EFI\Boot\hvcfg to 'S' - which works across a power cycle, and
    // is why the retired Pending flag (volatile, lost on power removal) is no
    // longer needed.
    // (BDS additionally arms its own 5-minute timer around every StartImage
    // — BmBoot.c "Before calling the image, enable the Watchdog Timer" — and
    // clears it after the image returns, so a hang inside this entry point is
    // double-bounded no matter which path reaches a stop.)
    gEfiBS->SetWatchdogTimer(120 /*sec*/, 0xFFFF, 0, NULL);
    HV_POST(0xC4);  // watchdog armed

    // NOTE: the ExitBootServices callback is registered at the very END of
    // bring-up (just before the success return), NOT here. Reason: this
    // entry point is started by BDS via StartImage, and EDK2's CoreStartImage
    // UNLOADS any image whose StartImage returns an error — including driver
    // images (Image.c: "If the image returned an error, or if the image is an
    // application unload it"). Every failure path below returns an error, so
    // the image's pages are freed on the way out. An EVT_SIGNAL_EXIT_BOOT_
    // SERVICES event registered up here would survive that unload (EDK2 does
    // not reclaim an image's events), and the callback would then execute
    // from freed code the moment Windows calls ExitBootServices — a delayed
    // brick that looks like a random crash minutes into a "successful" boot.
    // Registering after every failure return means there is no failure path
    // that can leave the event armed. The callback's work (clear Pending,
    // NV success markers, deferred ticket delete) all happens at EBS time
    // either way.

    // Locate our own image. VMX root executes it through the identity-mapped
    // HOST_CR3, so we refuse to start if firmware placed it outside that map —
    // but the map's extent is only known once Step 3 builds it.
    EFI_LOADED_IMAGE_PROTOCOL *loadedImage = NULL;
    EFI_GUID lipGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
    EFI_STATUS imageStatus = gEfiBS->HandleProtocol(
        imageHandle, &lipGuid, (VOID **)&loadedImage);
    HV_POST(0xB5);  // HandleProtocol done (per POST map)
    if (EFI_ERROR(imageStatus) || !loadedImage || !loadedImage->ImageBase) {
        HV_POST(0xE5);
        // Error return; Pending stays set so next boot falls to safe mode.
        return EFI_LOAD_ERROR;
    }
    UINT64 imageBase = (UINT64)(UINTN)loadedImage->ImageBase;
    UINT64 imageSize = (UINT64)loadedImage->ImageSize;
    HV_POST(0xB6);  // image protocol located (per POST map)

    EfiPrint("\n[HvEfi] EFI DXE VMX Hypervisor — starting (full mode)\n");

    // ── Step 1: Check VMX support ───────────────────────────────────────────
    if (!HvVmxIsSupported()) {
        EfiFatal("CPU does not support VMX or VMX is disabled in BIOS\n");
        HvReportStage(HV_STAGE_FAIL(1), 0);
        return EFI_UNSUPPORTED;
    }
    EfiPrint("[+] Step 1: VMX supported\n");
    HvReportStage(HV_STAGE_CPU_OK, 0);

    // Refuse to start if VMX is already enabled. At boot time CR4.VMXE can
    // only mean another boot-time VMX entity got there first (a second DXE
    // driver, or firmware-created VMX such as an already-running guest);
    // VMXON under it would exit into that entity instead of taking effect.
    // There is no DETECT-style VMCALL probe here on purpose: bare metal #UDs
    // VMCALL, and in DXE an unexpected #UD means a hung boot rather than a
    // clean refusal — the CR4 bit is the safe, sufficient check at this
    // point in the boot.
    if (__readcr4() & CR4_VMXE) {
        EfiFatal("CR4.VMXE already set — another VMX entity is active\n");
        HvReportStage(HV_STAGE_FAIL(1), 1);
        return EFI_UNSUPPORTED;
    }

    // ── Step 2: Locate MP Services Protocol ─────────────────────────────────
    EFI_GUID mpGuid = EFI_MP_SERVICES_PROTOCOL_GUID;
    EFI_STATUS st = gEfiBS->LocateProtocol(&mpGuid, NULL, (VOID **)&gEfiMp);
    if (EFI_ERROR(st) || !gEfiMp) {
        EfiFatal("EFI_MP_SERVICES_PROTOCOL not found: %r\n", st);
        HvReportStage(HV_STAGE_FAIL(2), (UINT32)st);
        return EFI_UNSUPPORTED;
    }
    EfiPrint("[+] Step 2: MP Services located\n");
    HvReportStage(HV_STAGE_MP_OK, 0);

    // ── Step 3: Build host page tables ──────────────────────────────────────
    // The image location is passed so the builder can leave the image's own
    // 2MB leaves executable while marking everything else NX.
    NTSTATUS ns = HvBuildHostPageTables(imageBase, imageSize);
    if (!NT_SUCCESS(ns)) {
        EfiFatal("Failed to build host page tables\n");
        HvReportStage(HV_STAGE_FAIL(3), (UINT32)ns);
        return EFI_OUT_OF_RESOURCES;
    }
    EfiPrint("[+] Step 3: Host page tables built\n");
    HvReportStage(HV_STAGE_HOSTPT_OK, 0);

    // The image must lie inside the map just built, which now spans every 512GB
    // unit that holds RAM (mirroring the EPT).
    {
        UINT64 hostMapBytes = (UINT64)g_Hv.HostPml4Units << 39;
        if (imageBase >= hostMapBytes || imageSize > hostMapBytes - imageBase) {
            EfiFatal("EFI image is outside the host identity map\n");
            HvReportStage(HV_STAGE_FAIL(3), 2);
            HvDestroyHostPageTables();
            return EFI_UNSUPPORTED;
        }
    }

    // ── Step 4: Generate nonce ──────────────────────────────────────────────
    // The nonce feeds session-key derivation, so it is key material: RDRAND
    // only, fail closed when the CPU has no RDRAND (HvRandomU64's TSC
    // fallback is observable and low-entropy — fine for decoy fill, not for
    // keys).
    {
        UINT64 nonceRaw = 0;
        if (!HvRandomKeyU64(&nonceRaw)) {
            EfiFatal("RDRAND unavailable for session nonce — refusing to start\n");
            HvReportStage(HV_STAGE_FAIL(4), 0);
            HvDestroyHostPageTables();
            return EFI_SECURITY_VIOLATION;
        }
        g_Hv.Nonce = HvSanitizeNonce(nonceRaw);
    }
    EfiPrint("[+] Step 4: Nonce generated\n");
    HvReportStage(HV_STAGE_NONCE_OK, 0);

    // ── Step 5: Take the auth ticket from the mailbox ──────────────────────────
    UINT64 ticket[4] = {0};
    if (!HvReadTicket(ticket)) {
        // HvReadTicket has already explained WHICH of the two provisioning
        // steps is missing (this binary, or HvBoot.efi). Printing a second,
        // vaguer line here used to blame --provision alone, which sent people
        // to re-provision a core that was already fine. Nothing here: the
        // helper owns the diagnosis.
        HvReportStage(HV_STAGE_FAIL(5), 0);
        HvDestroyHostPageTables();
        return EFI_SECURITY_VIOLATION;
    }
    EfiPrint("[+] Step 5: Ticket read from the mailbox\n");
    HvReportStage(HV_STAGE_TICKET_OK, 0);

    // ── Step 6: Derive session keys ─────────────────────────────────────────
    PVOID secretsPage = EfiAllocPagesBelow4G(1);
    if (!secretsPage) {
        RtlSecureZeroMemory(ticket, sizeof(ticket));
        HvReportStage(HV_STAGE_FAIL(6), 0);
        HvDestroyHostPageTables();
        return EFI_OUT_OF_RESOURCES;
    }
    g_Hv.SecretsPageVa = secretsPage;
    g_Hv.SecretsPagePa = EfiVaToPA(secretsPage);

    PHV_SECRETS secrets = (PHV_SECRETS)secretsPage;
    HvDeriveSession(ticket, g_Hv.Nonce,
                    &secrets->SessionKey0, &secrets->SessionKey1);
    secrets->SessionMagic = HvSessionMagic(secrets->SessionKey0, secrets->SessionKey1);
    secrets->BootMagic    = HvBootMagic(ticket);
    secrets->UnloadMac    = HvMacUnload(secrets->SessionKey0, secrets->SessionKey1);
    secrets->LastSeq      = 0;

    RtlSecureZeroMemory(ticket, sizeof(ticket));
    EfiPrint("[+] Step 6: Session keys derived\n");
    HvReportStage(HV_STAGE_KEYS_OK, 0);

    // ── Step 7: Allocate decoy pages ────────────────────────────────────────
    // Count varies per boot: 2 + (rand % 4) → range [2, 5], to vary the EPT
    // fingerprint across boots. Array is always sized HV_DECOY_COUNT.
    g_Hv.DecoyActiveCount = 2 + (UINT32)(HvRandom64() % 4);
    for (UINT32 i = 0; i < g_Hv.DecoyActiveCount; i++) {
        g_Hv.DecoyPageVa[i] = EfiAllocPagesBelow4G(1);
        if (!g_Hv.DecoyPageVa[i]) {
            EfiFatal("Decoy page allocation failed\n");
            HvReportStage(HV_STAGE_FAIL(7), i);
            goto fail;
        }
        g_Hv.DecoyPagePa[i] = EfiVaToPA(g_Hv.DecoyPageVa[i]);

        // Fill with RDRAND data
        UINT64 *p = (UINT64 *)g_Hv.DecoyPageVa[i];
        for (UINT32 j = 0; j < 512; j++) {
            p[j] = HvRandom64();
        }
    }
    EfiPrint("[+] Step 7: Decoy pages allocated\n");
    HvReportStage(HV_STAGE_DECOY_OK, 0);

    // ── Step 7b: Pre-allocate EPT hook pools ────────────────────────────────
    // Occupancy masks, not used-counters: install takes the lowest free entry
    // and remove gives it back, so the pools stay reusable for the life of the
    // boot instead of being consumed by the first 16 installs. See
    // ../hv_hookpool.h for the decisions taken over them.
    g_Hv.EptHookUsedMask = 0;
    g_Hv.ShadowPageUsedMask = 0;
    g_Hv.SparePtUsedMask = 0;
    for (UINT32 i = 0; i < HV_MAX_EPT_HOOKS; i++) {
        g_Hv.ShadowPagePool[i] = EfiAllocPagesBelow4G(1);
        g_Hv.SparePtPool[i]    = EfiAllocPagesBelow4G(1);
        if (!g_Hv.ShadowPagePool[i] || !g_Hv.SparePtPool[i]) {
            EfiFatal("EPT hook pool allocation failed\n");
            goto fail;
        }
        RtlZeroMemory(g_Hv.ShadowPagePool[i], PAGE_SIZE);
        RtlZeroMemory(g_Hv.SparePtPool[i], PAGE_SIZE);
    }

    // ── Step 8: Initialize VMX (allocate per-CPU state + EPT) ───────────────
    ns = HvVmxInitialize();
    if (!NT_SUCCESS(ns)) {
        EfiFatal("VMX initialization failed\n");
        HvReportStage(HV_STAGE_FAIL(8), (UINT32)ns);
        goto fail;
    }
    HvTransitionState(HV_STATE_INIT, HV_STATE_VMX_READY);
    EfiPrint("[+] Step 8: VMX initialized (%u CPUs, EPT ready)\n", g_Hv.VcpuCount);
    HvReportStage(HV_STAGE_VMXINIT_OK, g_Hv.VcpuCount);

    // ── Step 9: Collect hidden pages ────────────────────────────────────────
    g_Hv.HiddenPageCount = 0;

    // Secrets page
    AddHiddenPage(g_Hv.SecretsPagePa);

    // Per-CPU VMX state
    for (UINT32 i = 0; i < g_Hv.VcpuCount; i++) {
        PVCPU v = &g_Hv.Vcpus[i];
        AddHiddenPage(v->VmxonPhysical.QuadPart);
        AddHiddenPage(v->VmcsPhysical.QuadPart);
        AddHiddenPage(v->MsrBitmapPhysical.QuadPart);
        AddHiddenVaRange(v->HostStack, v->HostStackSize);
    }

    // EPT metadata: PML4, PDPT, PD pages
    AddHiddenVa(&g_Hv.Ept.Pml4[0]);
    for (UINT32 u = 0; u < g_Hv.Ept.PdptUnitCount; u++) {
        if (g_Hv.Ept.PdptVa[u]) AddHiddenVa(g_Hv.Ept.PdptVa[u]);
    }
    for (UINT32 i = 0; i < g_Hv.Ept.PdptCount; i++) {
        if (g_Hv.Ept.PdptPages[i])
            AddHiddenVa(g_Hv.Ept.PdptPages[i]);
    }

    // The two allocations that INDEX everything above. They are not VMX
    // structures themselves, but a page full of page-aligned sub-4GB pointers
    // is exactly what a guest physical scan looks for: the VCPU array hands
    // over every VMCS/VMXON/bitmap address, and the PDPT-page array hands over
    // the whole EPT. Hiding the targets while leaving the index visible leaves
    // the hypervisor one pointer-chase away.
    //
    // Vcpus comes from EfiAllocPagesBelow4G (hv_efi_vmx.c): whole pages we own
    // outright, and under EFI's identity mapping VA == PA, so walking the range
    // page by page covers exactly the pages that get hidden.
    if (g_Hv.Vcpus)
        AddHiddenVaRange(g_Hv.Vcpus, (UINT64)g_Hv.VcpuCount * sizeof(VCPU));

    // ept->PdptPages deliberately does NOT get the same treatment, and used to.
    // It comes from EfiAllocPool (hv_efi_ept.c), so it shares its 4 KB page with
    // whatever else the firmware's pool placed there: hiding the page unmaps (or
    // decoy-redirects) a neighbour's live data as well. Page-granularity EPT
    // hiding over a pool object is firmware corruption we would own, not
    // concealment, and no pool allocation can be proven page-exclusive. It is
    // left visible instead - what it contains is pointers, and the pages those
    // name are hidden individually a few lines above.

    // Host page tables — the PML4, plus every mapped unit's PDPT and its 512 PD
    // pages. Every unit must be hidden, not just unit 0: when RAM reports above
    // 512 GB the host map spans those units too, and their pages are as
    // scannable as the low ones.
    AddHiddenVa(g_Hv.HostPml4Va);
    {
        UINT64 *pml4 = (UINT64 *)g_Hv.HostPml4Va;
        for (UINT32 u = 0; u < g_Hv.HostPml4Units; u++) {
            if (!(pml4[u] & 1)) continue;
            UINT64 *pdpt = (UINT64 *)(UINTN)(pml4[u] & ~0xFFFULL);  // identity mapped
            AddHiddenPage((UINT64)(UINTN)pdpt);
            for (UINT32 k = 0; k < 512; k++) {
                if (pdpt[k] & 1)
                    AddHiddenPage(pdpt[k] & ~0xFFFULL);
            }
        }
    }

    // EFI image pages are NOT added to HiddenPages — they use executable
    // hiding (HvEptHidePagesExecutable) in Step 10. The decoy-redirect hide
    // (X=0) would fault on the first instruction fetch after VMLAUNCH,
    // hanging the boot. The image stays RWX identity-mapped in EPT.
    EfiPrint("[+]   EFI image: %u pages at 0x%lx (executable hide)\n",
             (UINT32)((imageSize + PAGE_SIZE - 1) / PAGE_SIZE), imageBase);

    // Decoy pages themselves. Only the ACTIVE slots were allocated: slots at
    // and beyond DecoyActiveCount still hold the NULL that Step 7 left in
    // them, and AddHiddenPage(0) would decoy-redirect physical page 0 — the
    // real-mode IVT/BIOS page — and, worse, leave page 0 in HiddenPages so
    // HvEfiIsHypervisorPage() later reports it as ours. Bounding by the active
    // count is what Step 7 and Step 13 already do everywhere else.
    for (UINT32 i = 0; i < g_Hv.DecoyActiveCount; i++) {
        AddHiddenPage(g_Hv.DecoyPagePa[i]);
    }

    if (g_Hv.HiddenPageCount >= HV_MAX_HIDDEN_PAGES) {
        EfiFatal("Hidden page list overflow (%u >= %u)\n",
                 g_Hv.HiddenPageCount, HV_MAX_HIDDEN_PAGES);
        HvReportStage(HV_STAGE_FAIL(9), g_Hv.HiddenPageCount);
        goto fail_vmx;
    }

    EfiPrint("[+] Step 9: %u pages to hide\n", g_Hv.HiddenPageCount);
    HvReportStage(HV_STAGE_HIDDEN_OK, g_Hv.HiddenPageCount);

    // ── Step 10: EPT hide hypervisor pages ──────────────────────────────────
    // 0xB8, not 0xBA. The POST bytes are the only pre-OS diagnosis channel for
    // a brick, so every stage needs a distinct value: 0xBA already means "safe
    // mode, returned cleanly" on the early-exit path below, and reusing it here
    // meant a brick inside Step 10 was indistinguishable from a boot that had
    // never tried. The 0xB8-0xBD block is allocated to this step alone.
    HV_POST(0xB8);
    ns = HvEptHidePages(&g_Hv.Ept, g_Hv.HiddenPages, g_Hv.HiddenPageCount,
                         g_Hv.DecoyPagePa, g_Hv.DecoyActiveCount);
    if (!NT_SUCCESS(ns)) {
        EfiFatal("EPT hiding failed\n");
        HvReportStage(HV_STAGE_FAIL(10), (UINT32)ns);
        HV_POST(0xEA);
        goto fail_vmx;
    }
    HV_POST(0xBB);
    // Executable hide for our own image: RWX identity (no decoy redirect).
    // The post-VMLAUNCH continuation executes from the image in non-root
    // mode; X=0 would #PF-loop on the first fetch after launch.
    //
    // Image size cap: imgPages[512] holds up to 2 MB of pages. imageSize
    // for our ~200 KB binary is well under that; a silent truncation would
    // leave some image pages at the 2 MB EPT default (RWX via large page),
    // which is still executable, so even an oversized image boots. The
    // explicit cap guards against stack-overflow on an unexpectedly huge
    // ImageSize report from firmware.
    {
        UINT64 imgPages[512];
        UINT32 imgCount = 0;
        UINT64 base = imageBase & ~0xFFFULL;
        UINT64 end = (imageBase + imageSize + 0xFFFULL) & ~0xFFFULL;
        for (UINT64 pa = base; pa < end && imgCount < 512; pa += PAGE_SIZE)
            imgPages[imgCount++] = pa;
        HV_POST(0xBC);
        ns = HvEptHidePagesExecutable(&g_Hv.Ept, imgPages, imgCount,
                                      g_Hv.DecoyPagePa, g_Hv.DecoyActiveCount);
        if (!NT_SUCCESS(ns)) {
            EfiFatal("EPT executable hide failed\n");
            HvReportStage(HV_STAGE_FAIL(10), (UINT32)ns);
            HV_POST(0xEC);
            goto fail_vmx;
        }
        HV_POST(0xBD);
    }
    HvTransitionState(HV_STATE_VMX_READY, HV_STATE_HIDDEN);
    EfiPrint("[+] Step 10: EPT hiding complete\n");
    HvReportStage(HV_STAGE_EPTHIDE_OK, 0);

    // ── Step 11: Default CR3 offset ─────────────────────────────────────────
    g_Hv.DirectoryTableOffset = 0x28;
    EfiPrint("[+] Step 11: CR3 offset = 0x%x (default; configurable via hypercall)\n",
             g_Hv.DirectoryTableOffset);
    HvReportStage(HV_STAGE_CR3OFF_OK, 0);

    // ── Step 12: Virtualize all CPUs ────────────────────────────────────────
    // The critical boundary: this calls VMLAUNCH on every logical processor.
    // Each VMLAUNCH returns with the CPU in VMX non-root mode, executing from
    // the image. Any issue in EPT setup (image not RWX, hidden pages not
    // accessible for firmware's post-VMLAUNCH activity) causes an EPT
    // violation #PF loop here. The universal EPT violation handler in
    // hv_exit.c now grants any access to a page we own, closing the loop.
    HV_POST(0xB7);
    ns = HvSmpVirtualizeAllProcessors();
    if (!NT_SUCCESS(ns)) {
        EfiFatal("CPU virtualization failed\n");
        // HvReportBringUpSummary (inside HvSmpVirtualizeAllProcessors) already
        // wrote HV_STAGE_FAIL(12) with the encoded class/vmErr/handle detail.
        // A second HvReportStage here would OVERWRITE that with the raw NTSTATUS
        // (0xC0000001), destroying the only diagnostic that names which CPU and
        // which VMX operation failed.
        HV_POST(0xE7);
        goto fail_vmx;
    }
    EfiPrint("[+] Step 12: All %u CPUs virtualized\n", g_Hv.VcpuCount);
    HvReportStage(HV_STAGE_VIRT_OK, g_Hv.VcpuCount);

    // ── Step 12b: Boot self-test (deliberately absent in EFI build) ──────────
    // The WDK driver issues HV_HYPERCALL_DETECT from kernel mode (BSP, guest
    // mode) and enters dark mode on failure. The EFI DXE driver cannot do the
    // equivalent safely: VMCALL raises #UD if a #VMEXIT mismatch occurs, and
    // DXE exception handlers do not recover from #UD — the platform halts.
    // The EFI build instead relies on the per-AP VMLAUNCH return-code check
    // (hv_efi_smp.c) and the g_VmxonSuccess count to detect bring-up failures.
    // If a post-launch DETECT self-test is added, it must be gated on
    // CPUID.1:ECX[5] and wrapped in a DXE fault-tolerant trampoline.

    // ── Step 13: Wipe secrets from g_Hv ─────────────────────────────────────
    // The cleanup key obfuscates the secrets/decoy pointers, so it is key
    // material: RDRAND only, fail closed. Failing here runs fail_vmx, which
    // devirtualizes while the secrets page is still directly readable
    // (obfuscation below has not run yet).
    {
        UINT64 cleanupKey = 0;
        if (!HvRandomKeyU64(&cleanupKey)) {
            EfiFatal("RDRAND unavailable for cleanup key — refusing to continue\n");
            HvReportStage(HV_STAGE_FAIL(13), 0);
            goto fail_vmx;
        }
        g_Hv.CleanupKey = cleanupKey;
    }
    g_Hv.SecretsPageVa = (PVOID)((UINT64)g_Hv.SecretsPageVa ^ g_Hv.CleanupKey);
    // Only obfuscate ACTIVE decoys: slots beyond DecoyActiveCount are NULL,
    // and XORing NULL would create a non-NULL garbage pointer that defeats
    // the teardown NULL guard.
    for (UINT32 i = 0; i < g_Hv.DecoyActiveCount; i++) {
        g_Hv.DecoyPageVa[i] = (PVOID)((UINT64)g_Hv.DecoyPageVa[i] ^ g_Hv.CleanupKey);
    }
    g_Hv.PointersObfuscated = TRUE;

    // HiddenPages[] intentionally not wiped here — HvEfiIsHypervisorPage()
    // consults it on every physical hypercall as a second line of defence.
    g_Hv.Ept.EptPointer = 0;
    RtlSecureZeroMemory(g_Hv.DecoyPagePa, sizeof(g_Hv.DecoyPagePa));
    g_Hv.SecretsPagePa = 0;

    EfiPrint("[+] Step 13: Secrets wiped from g_Hv\n");
    EfiPrint("\n[HvEfi] VMX hypervisor active. OS will boot under virtualization.\n\n");

    // Bring-up is complete: this is the only place the ticket is consumed, so a
    // failure at any earlier step leaves it in NVRAM for the next boot to retry.
    HvReportStage(HV_STAGE_DONE, 0);
    HV_POST(0xBF);

    // Register the ExitBootServices callback — the LAST action of bring-up.
    // Reaching EBS means the firmware handed off to the OS loader with the
    // hypervisor active and no hang; a successful boot is proven. The
    // callback clears the Pending flag, writes the NV (0x07) success markers
    // and runs the deferred ticket delete, and disarms the firmware watchdog
    // so a slow but intact boot isn't reset.
    //
    // Placed after every failure return on purpose: CoreStartImage unloads
    // this image on an error return (Image.c "If the image returned an error,
    // or if the image is an application"), and EDK2 does not reclaim an
    // image's events at unload. Registered only on the success path, there is
    // no failure path that can leave an armed EBS callback executing from
    // freed image memory. If CreateEventEx fails here, the boot still
    // proceeds (the hypervisor is already resident); the receipt just won't
    // get its "FULL EBS" line, so the next boot stands down to safe mode —
    // the same conservative outcome the registration-failure path always had.
    {
        EFI_EVENT ebsEvent = NULL;
        EFI_STATUS cestat = gEfiBS->CreateEventEx(
            0x00000200 /*EVT_NOTIFY_SIGNAL*/,
            16 /*TPL_CALLBACK*/,
            HvEfiOnExitBootServices,
            NULL,
            &gEfiEventExitBootServicesGuid,
            &ebsEvent);
        (void)cestat; (void)ebsEvent;
        // Failure here is non-fatal: see the comment above. The receipt-based
        // rescue rule covers the next boot.
    }
    HV_POST(0xC5);  // EBS callback registered (end of bring-up)

    return EFI_SUCCESS;

fail_vmx:
    HvVmxShutdown();
fail:
    // Host page tables: freed here for the `goto fail` paths (e.g. decoy
    // alloc) that bypass HvVmxShutdown. Idempotent — already NULL after
    // HvVmxShutdown ran above.
    HvDestroyHostPageTables();
    // The EPT hook pools are allocated at Step 7b, so every failure from there
    // on - including the pool allocation loop itself, which `goto fail`s on a
    // partial result - would otherwise leak the pages already allocated.
    // Idempotent, and a no-op before Step 7b.
    HvEptHookPoolsFree();
    if (g_Hv.SecretsPageVa) {
        RtlSecureZeroMemory(g_Hv.SecretsPageVa, PAGE_SIZE);
        EfiFreePages(g_Hv.SecretsPageVa, 1);
        g_Hv.SecretsPageVa = NULL;
    }
    for (UINT32 i = 0; i < HV_DECOY_COUNT; i++) {
        if (g_Hv.DecoyPageVa[i]) {
            // Zero before free (mirrors the driver's teardown): freed EFI pages
            // are reused by the OS; leave nothing readable behind.
            RtlSecureZeroMemory(g_Hv.DecoyPageVa[i], PAGE_SIZE);
            EfiFreePages(g_Hv.DecoyPageVa[i], 1);
            g_Hv.DecoyPageVa[i] = NULL;
        }
    }
    return EFI_ABORTED;
}

// ── Entry wrapper: the watchdog must never outlive a failed bring-up -------
//
// Bring-up arms the firmware watchdog for 120 s, and only the
// ExitBootServices callback disarms it - because reaching EBS is the only
// success path. Every other exit returns an error: a refusal, a failed VMCS
// setup, an AP that refused to launch, the fail: funnel. EDK2's CoreStartImage
// UNLOADS any image whose StartImage returns an error, so a watchdog left
// armed on an unloaded image expires two minutes later and calls into pages
// that have already been freed and may since have gone to the OS loader. The
// machine then resets - or hangs harder than before. From outside, that reads
// as "it booted, then it died on its own", which is indistinguishable from the
// hang we are trying to diagnose. It is also the shape of the "hung on a boot,
// then later looked dead" symptom this whole pass exists to explain.
//
// So the disarm lives in one place, on the way out of every error return -
// including the ones somebody adds next year. The safe-mode stand-down path
// returns before the watchdog is ever armed, so the call is a no-op there.
// A genuine hang never reaches this line, which is the entire reason the
// watchdog is armed: the timeout still fires, and the next boot finds
// "FULL START" with no completion and stands itself down.
EFI_STATUS EFIAPI HvEfiDriverEntry(
    EFI_HANDLE        imageHandle,
    EFI_SYSTEM_TABLE  *systemTable)
{
    EFI_STATUS status = HvEfiDriverEntryImpl (imageHandle, systemTable);

    if (EFI_ERROR (status) && gEfiBS != NULL) {
        gEfiBS->SetWatchdogTimer (0, 0, 0, NULL);
    }
    return status;
}

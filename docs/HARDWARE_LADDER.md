# HvEfi hardware ladder — B0, B1, B2

The only thing that cannot be automated here is the boot. This is the procedure,
written so that each rung is **inert unless it says otherwise**, and so that a
hang at any rung has a mechanical answer that does not depend on the code under
test working.

Everything below is *run elevated from Windows* (`cmd` or PowerShell as
Administrator), on the Dell G15 5530 target.

---

## The invariants

Three properties make this ladder survivable. They are properties of the
**0xA application** (`HvBoot`), not of the driver, so they hold even when the
driver is the thing that is broken.

1. **Absent `\EFI\Boot\hvcfg` means safe mode.** Safe mode never reaches VMX. If
   you are unsure what state the machine is in, deleting `hvcfg` is always the
   safe direction.
2. **A full-mode attempt is armed before it starts.** `HVEFI FULL START` is
   written *before* `LoadImage` of the driver, so an attempt that kills the
   machine still leaves a record.
3. **An unfinished attempt disarms the machine by itself.** The next boot reads
   that record, forces safe mode, and rewrites `hvcfg` to `'S'` — on the volume,
   so it survives a power cycle, with no user action. Only
   `HvLauncher.exe --enable-full` clears it.

**Recovery, in order, if a boot hangs:**

```
1. Hold the power button 10 seconds.
2. F12 at the Dell logo -> "Windows Boot Manager"        (proven working)
3. Black screen instead? Unplug AC, hold power 30 s, then retry.
4. Still nothing? Unplug the SSD, or USB-boot and rename
   \EFI\Boot\memtest.efi so the tracked slot's target no longer exists.
5. Last resort: BIOS defaults (Ctrl+Esc during POST), or F12 -> UEFI Boot.
```

Never rely on the watchdog as your recovery path. It is bounded insurance for
the machine, not a way to read the evidence.

---

## Before every rung

```bat
cd /d F:\Hypervisor
bash tools\unit\run.sh
bash tools\syntax-check\run.sh
HvEfi\build_hvefi.bat
type HvEfi\build_manifest.txt
```

Record the two hashes in the rung's log file. **Never trust a hash quoted in a
document** — EDK2 stamps the image, so `build_manifest.txt` moves on every
rebuild and is the only authority. The launcher checks it for you now
(`--install-raw` / `--install-core` refuse an artifact that does not match the
manifest beside it, before touching the ESP).

---

## B0 — plumbing only, no VMX

**Goal**: prove on real firmware that the boot pair runs, decides, hands over
through the mailbox, and stands down — with **no possibility of VMX**, because
`hvcfg` is absent.

This is the first rung because it is the one that has never been run on this
machine, and it cannot hang the boot in any way the code controls: no mode file
means no full-mode attempt, no VMXON, no EPT, no `StartupAllAPs`.

### Install

```bat
Hypervisor\HvLauncher.exe --install-core F:\Hypervisor\HvEfi\HvEfi.efi
Hypervisor\HvLauncher.exe --install-raw  F:\Hypervisor\HvEfi\HvBoot.efi
```

Both must print `[+] Manifest : matches ...` and then a verified write. A
`REFUSING` line means you are about to install a stale binary — stop and
rebuild.

### The one precondition that makes B0 inert

```bat
mountvol X: /S
dir X:\EFI\Boot\hvcfg
del X:\EFI\Boot\hvcfg        REM only if it exists
del X:\EFI\Boot\hvefi.log    REM optional: start from an empty history
mountvol X: /D
```

Then confirm what the *next boot will do*, without booting:

```bat
Hypervisor\HvLauncher.exe --boot-report
```

Expect it to say the mode file does not arm full mode, and that `HvBoot` will
write `ENTRY SAFE prev=0`.

### Boot and read the evidence

```bat
shutdown /r /t 0
:: ... after Windows is back ...
tools\diag\hv_efi_diag.exe > reports\ladderB0.txt
```

### Pass criteria — the receipt must contain all five

```
HVEFI BOOT HIT                 HvBoot's entry point ran (BDS reached the slot)
HVEFI ENTRY SAFE prev=0        no mode file -> safe; not a rescue
HVEFI BOOT PATH file           the driver was loaded by device path
HVEFI BOOT START               the arm line, written before StartImage
HVEFI CORE stage=14            the driver RAN and reported HV_STAGE_DARK
HVEFI BOOT SAFE stood-down     it returned EFI_ABORTED and HvBoot recorded it
```

Six lines, in that order. This exact sequence is what
[`BootLab/qemu-pair.sh`](../BootLab/qemu-pair.sh) asserts in QEMU (8/8), so a B0
failure is a real-hardware difference, not a logic difference — that is the
whole reason to run it.

**Also required:** `HVEFI FULL START` must **not** appear anywhere in the
receipt. If it does, the next boot will see a finished-looking attempt that
never happened; delete the receipt and re-run B0.

### What a B0 failure means

| receipt stops after | meaning | next step |
|---|---|---|
| nothing at all | BDS never started the slot image | `--efi-status`; is the slot still in BootOrder? |
| `BOOT HIT` only | `HvBoot` ran; its first file write hung | the 0xA layer has a storage problem — capture, do not retry |
| `BOOT PATH file`, no `BOOT START` | the driver's `LoadImage` hung | Dell DXE core + a 0xC image; capture `debugcon` if a debug build is installed |
| `BOOT START`, no `CORE stage` | the driver started and hung inside itself, or the mailbox was unreadable | this is the case the mailbox exists to diagnose; capture and go to B1 first |

---

## B1 — the self-disarm rescue, on real hardware

**Goal**: prove the safety net itself works, still without VMX. This is the rung
that makes B2 safe to attempt, and it is worth doing even if B0 was perfect.

It reproduces, from Windows, exactly the state a hung boot leaves behind: full
mode requested, and an attempt that started and never completed.

### Seed the "previous boot hung" state

```bat
mountvol X: /S
echo|set /p=F> X:\EFI\Boot\hvcfg                 REM one byte, no newline
echo HVEFI FULL START>> X:\EFI\Boot\hvefi.log    REM an attempt that never finished
mountvol X: /D
Hypervisor\HvLauncher.exe --boot-report
```

`--boot-report` should now predict a **rescue**: full mode is requested, an
attempt is unfinished, no `RETRY` follows it.

### Boot and verify

```bat
shutdown /r /t 0
:: ... after Windows is back ...
tools\diag\hv_efi_diag.exe > reports\ladderB1.txt
mountvol X: /S
type X:\EFI\Boot\hvcfg
dir X:\EFI\Boot\hvefi.log
mountvol X: /D
```

### Pass criteria

1. `HVEFI ENTRY SAFE prev=1` — the rescue fired.
2. **No new** `HVEFI FULL START` was written by this boot (count the lines
   before and after; the seeded one stays).
3. `HVEFI CORE stage=14` + `HVEFI BOOT SAFE stood-down` — the driver was told to
   stand down and obeyed.
4. `type X:\EFI\Boot\hvcfg` prints **`S`**. This is the load-bearing assertion:
   the stand-down was made durable on the volume, by the boot itself.
5. No `BOOT WARN cfg not disarmed` line.

If `hvcfg` still reads `F`, the rescue did not write, and **B2 must not be
attempted**.

### After B1

The machine is now disarmed, which is the correct resting state. B1 also proves
the re-arm path is the only way back:

```bat
Hypervisor\HvLauncher.exe --enable-full   REM writes 'F' + appends HVEFI RETRY
Hypervisor\HvLauncher.exe --boot-report    REM now predicts a full attempt
```

---

> [!warning] B2 is the only rung that touches variable services
> In safe mode the driver returns `EFI_ABORTED` before step 5, so B0 and B1 make
> **no** variable-services call from the 0xC image. Full mode does: step 5 reads
> the auth ticket with `GetVariable` (`HvEfi/hv_efi_main.c:412`). That is the
> same class of call the original bricking was attributed to, and whether a read
> can deadlock where a write did is **unverified**. If B2 hangs with
> `CORE stage=4` or `stage=5` as the last report, this is the first thing to
> suspect - and the fix is to move the ticket read into `HvBoot` and pass it
> through the mailbox, the same split the receipt got.

## B2 — full mode, for real

Only after B0 **and** B1 pass.

```bat
Hypervisor\HvLauncher.exe --enable-full
Hypervisor\HvLauncher.exe --boot-report
shutdown /r /t 0
```

### Outcomes

**Success** — the receipt ends:

```
HVEFI FULL DONE       bring-up returned success (NOT the same as EBS reached)
HVEFI BOOT DONE       HvBoot saw EFI_SUCCESS from StartImage
```

Windows boots. `HvLauncher.exe --detect` should then report the hypervisor, and
the EBS flag shows up on the *next* boot as `CORE LAST EBS` (the driver can no
longer write after EBS — the mailbox it left is the only trace, which is why the
next boot is the one that reports it).

**Clean failure** — the receipt names the step:

```
HVEFI FULL FAIL step=N
```

Read N against the stage table in [`tools/diag/README.md`](../tools/diag/README.md).
Steps 1-11 are preparation; step 12 is `StartupAllAPs`/`VMLAUNCH`, the classic
real-hardware failure, and now reports the VM-instruction error in its detail
field instead of returning silently.

### Decoding a step-12 detail (Pass 94)

Step 12 used to report only "N of M CPUs virtualised". It now carries a
packed detail word, so a failure names the *class* of fault, the CPU it
happened on, and the VM-instruction error - which is the difference between
"the 12-core part has a broken core 7" and "bring-up failed". Decoded by
`tools/diag/hv_efi_diag.exe`, or by hand:

| bits | meaning |
|---|---|
| 7:0   | VM-instruction error (e.g. a raw MSR 0x4400 value from a failed VMLAUNCH) |
| 15:8  | class, see below |
| 23:16 | processor handle whose bring-up failed (0 = unknown) |
| 31:24 | unused |

| class | meaning | what to do |
|---|---|---|
| 1 | `VMENTRY` - VMLAUNCH failed | the error byte is the MSR value; a specific CPU is at fault |
| 2 | `VMXON` | VMXON refused on that CPU - usually a per-core disable |
| 3 | `VMCLEAR` | stale VMCS state; rare, and fatal for that CPU |
| 4 | `VMPTRLD` | VMCS pointer not accepted |
| 5 | `VMCS` | `HvVmcsSetupCpu` refused - VMCS fields the CPU will not take |
| 6 | `NO_HANDLE` | the processor handle could not be resolved at all |
| 7 | `TIMEOUT` | `StartupAllAPs` timed out; handle is the AP that was terminated |

Class 7 is new in Pass 94 and needs the most care: it means an AP did not
finish, and the handle names **which** one. `HvEfi/hv_efi_smp.c` now passes
a real `FailedCpuList` to `StartupAllAPs` and reads it before freeing it
(MP Services allocates it), so the handle is the AP that was still running
at the 5-second timeout.

If step 12 reports a failure at all, the CPU it names is the CPU to look at.
Do not re-arm to "see if it happens again" - read this first, then decide.

**Hang** — the watchdog is armed for 120 s, so the machine resets itself. The
next boot then sees `FULL START` with no completion, rescues itself, and lands in
B1's state. **That is the design working.** Read the receipt from the boot after
the reset: `ENTRY SAFE prev=1` plus whatever `CORE LAST stage=N` recorded from
the hung attempt's leftover mailbox page.

### After any B2 hang

```bat
tools\diag\hv_efi_diag.exe > reports\ladderB2.txt
Hypervisor\HvLauncher.exe --disable-full    REM writes 'S'; makes the stand-down explicit
```

Then stop. Do not re-arm until the receipt has been read and the stage
identified — re-arming to "see what happens again" is how a machine ends up in a
loop.

---

## What each rung is allowed to prove

| rung | VMX | hang possible | proves |
|---|---|---|---|
| B0 | no | no | the boot pair, the decision, the mailbox handoff and the telemetry work on this firmware |
| B1 | no | no | the self-disarm rescue works and is durable on a real ESP |
| B2 | yes | yes | VMX bring-up, and only that |

Nothing below B2 exercises VMX. Nothing above B2 can brick the machine. Keep it
that way until B0 and B1 have been read, not just booted.

---

## Recording

Per rung, keep: the manifest hashes, the launcher's install output, the
`--boot-report` output taken *before* the boot, the post-boot
`hv_efi_diag.exe` output, and one line saying what the receipt proved. Those five
artifacts are what makes the next failure diagnosable — the failure mode this
whole pass exists to fix was never a crash, it was a boot that produced no
evidence and therefore no conclusion.

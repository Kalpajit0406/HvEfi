#!/usr/bin/env python3
# decode_receipt.py - parse \EFI\Boot\hvefi.log receipts written by HvBoot.efi
# on the Dell target, and classify the boot outcome. Pairs with decode_post.py
# (which handles the port-0x80 byte stream): the receipt is the OS-readable
# half of the Pass 90 telemetry split.
#
# Line format defined in hv_efi_receipt.h.
#   HVEFI ENTRY SAFE prev=1   stood down (rescue fired if prev=1)
#   HVEFI ENTRY FULL          proceeding to full-mode bring-up
#   HVEFI FULL  START         handing control to the driver's entry
#   HVEFI FULL  DONE          driver returned success (full bring-up complete)
#   HVEFI FULL  EBS           legacy completion marker from pre-Pass-90 builds
#   HVEFI FULL  FAIL step=N   driver reported HV_STAGE_FAIL(N)
#   HVEFI RETRY               user re-armed with --enable-full
#
# Classification:
#   OK      a full completion follows the latest FULL START with no FAIL
#   HUNG    a FULL START exists with neither a DONE/EBS nor a FAIL after it
#   FAIL    a FULL FAIL step=N line is the tail
#   SAFE    only ENTRY SAFE / RETRY lines; no full-mode attempt
#   EMPTY   the file is zero bytes (HvBoot never wrote)

import re
import sys

LINE_RE = re.compile(
    r"^HVEFI\s+(?P<kind>ENTRY|FULL|RETRY)(?:\s+(?P<subkind>SAFE|FULL|START|DONE|EBS|FAIL))?(?:\s+(?P<kv>\S+))?.*$"
)

STEP_LABELS = {
    1: "CPU does not support VMX or VMX disabled in BIOS",
    2: "EFI_MP_SERVICES_PROTOCOL not found",
    3: "host page tables build failed",
    4: "RDRAND unavailable for session nonce",
    5: "auth ticket missing from mailbox (unprovisioned HvBoot?)",
    6: "secrets page allocation failed",
    7: "decoy page allocation failed",
    8: "VMX initialization failed",
    9: "hidden-page list overflow",
    10: "EPT hiding failed",
    11: "CR3 offset init failure (should never fire)",
    12: "VMLAUNCH failed on one or more CPUs",
    13: "cleanup-key RDRAND unavailable",
}

def classify(lines):
    last_start = -1
    last_done  = -1
    last_fail  = -1
    last_mode  = None
    for i, l in enumerate(lines):
        m = LINE_RE.match(l.strip())
        if not m: continue
        k, sk = m.group("kind"), m.group("subkind")
        if k == "ENTRY" and sk in ("SAFE","FULL"):
            last_mode = sk
        elif k == "FULL":
            if sk == "START": last_start = i
            elif sk in ("DONE","EBS"): last_done = i
            elif sk == "FAIL":
                last_fail = i

    if last_fail > last_start:
        return "FAIL", last_fail
    if last_done > last_start and last_start >= 0:
        return "OK", last_done
    if last_start > max(last_done, last_fail):
        return "HUNG", last_start
    if last_mode == "SAFE":
        return "SAFE", -1
    return "UNKNOWN", -1

def main(path):
    try:
        with open(path, "r", errors="replace") as f:
            text = f.read()
    except FileNotFoundError:
        print(f"[decode_receipt] {path}: not found")
        return 1
    if not text:
        print(f"[decode_receipt] {path}: empty — HvBoot never wrote (slot never called?)")
        return 1
    lines = text.splitlines()
    print(f"[decode_receipt] {path}: {len(lines)} line(s)")
    for l in lines[-20:]:
        print("  " + l.rstrip())
    kind, idx = classify(lines)
    print()
    if kind == "OK":
        print("[decode_receipt] OK: full bring-up completed in the latest attempt.")
        return 0
    if kind == "HUNG":
        print("[decode_receipt] HUNG: FULL START written but no DONE/FAIL — the")
        print("                       boot froze inside the driver. Rescue rule")
        print("                       disarms full mode on the next boot.")
        print("                       Pair with decode_post.py over the port-0x80")
        print("                       capture (if available) to pin the stage.")
        return 2
    if kind == "FAIL":
        line = lines[idx]
        m = re.search(r"step=(\d+)", line)
        step = int(m.group(1)) if m else None
        label = STEP_LABELS.get(step, "(unknown stage)")
        print(f"[decode_receipt] FAIL at step {step}: {label}")
        return 3
    if kind == "SAFE":
        print("[decode_receipt] SAFE: driver stood down (no full attempt).")
        return 0
    print("[decode_receipt] UNKNOWN pattern — paste the receipt tail.")
    return 4

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: decode_receipt.py <path to EFI/Boot/hvefi.log>", file=sys.stderr)
        sys.exit(64)
    sys.exit(main(sys.argv[1]))

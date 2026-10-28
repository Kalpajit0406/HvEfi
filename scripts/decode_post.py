#!/usr/bin/env python3
# decode_post.py - decode the port-0x80 POST byte stream HvEfi writes during
# boot into stage names from the POST CODE MAP in hv_efi_main.c:106-114.
# Takes one argument: path to a binary file containing the raw bytes QEMU
# captured via `-chardev file,id=post,path=... -device
# isa-debugcon,iobase=0x80,chardev=post`, or that a POST reader attached to
# the real Dell logged.
import sys

LABELS = {
    0xB0: "entry reached",
    0xB1: "g_EnteredOnce guard passed",
    0xB2: "gEfiBS / gEfiRT captured",
    0xB3: "no mailbox: unobservable boot, standing down",
    0xB5: "HandleProtocol(LoadedImage) done",
    0xB6: "image protocol located (ImageBase + ImageSize)",
    0xB7: "virtualize every CPU",
    0xB8: "about to hide EPT pages",
    0xB9: "second entry: already-started early return",
    0xBA: "SAFE MODE standing down",
    0xBB: "EPT hiding complete",
    0xBC: "about to hide EFI image",
    0xBD: "image hide complete",
    0xBE: "rescue stand-down",
    0xBF: "bring-up complete (OS taking over)",
    0xC0: "past mode gate, entering full-mode bring-up",
    0xC1: "HV_STAGE_ENTRY written to mailbox",
    0xC2: "mode taken from the mailbox",
    0xC4: "firmware watchdog armed (120 s)",
    0xC5: "EBS callback registered (end of bring-up)",
    0xE2: "VMLAUNCH failed (step 12)",
    0xE5: "image protocol failed",
    0xE7: "CPU virtualization failed",
    0xEA: "EPT hide failed",
    0xEC: "image hide failed",
}

EXPECTED_SAFE = [0xB0, 0xB1, 0xB2, 0xB3]
EXPECTED_FULL_PREFIX = [0xB0, 0xB1, 0xB2, 0xC0, 0xC1, 0xC2, 0xC4, 0xB5, 0xB6]
EXPECTED_FULL_COMPLETE = EXPECTED_FULL_PREFIX + [0xB7, 0xB8, 0xBB, 0xBC, 0xBD, 0xC5, 0xBF]

def main(path):
    with open(path, "rb") as f:
        data = f.read()
    if not data:
        print(f"[decode_post] {path}: empty — driver never wrote a POST byte")
        return 1
    print(f"[decode_post] {path}: {len(data)} byte(s)")
    for b in data:
        print(f"  0x{b:02X}  {LABELS.get(b, '(unknown stage)')}")
    seq = list(data)
    if seq == EXPECTED_SAFE:
        print("[decode_post] = safe-mode stand-down (designed, matches hv_efi_main.c POST MAP)")
        return 0
    if seq == EXPECTED_FULL_PREFIX:
        print("[decode_post] = full-mode entry up to Step 1 (VMX capability check)")
        print("[decode_post]   = TCG without VMX forces HV_STAGE_FAIL(1); on real")
        print("[decode_post]     VT-x hardware bring-up continues through Steps 2-13.")
        return 0
    if seq == EXPECTED_FULL_COMPLETE:
        print("[decode_post] = FULL BRING-UP COMPLETE (B7..BF: VMX bring-up finished)")
        return 0
    print("[decode_post] = non-standard sequence; see hv_efi_main.c:106-114 for the map")
    return 2

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: decode_post.py <post-log-file>", file=sys.stderr)
        sys.exit(64)
    sys.exit(main(sys.argv[1]))

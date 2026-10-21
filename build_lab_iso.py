import os
import sys
import subprocess
import make_fat16

shell_path = r'C:\Users\DELL\edk2\Build\OvmfX64\DEBUG_VS2022\X64\Shell.efi'
hvboot_path = r'F:\HvEfi\HvBoot_patched.efi'
hvcore_path = r'F:\HvEfi\hvcore.efi'
ticket_path = r'F:\HvEfi\hvticket'

with open(shell_path, 'rb') as f:
    shell_data = f.read()

with open(hvboot_path, 'rb') as f:
    hvboot_data = f.read()

with open(hvcore_path, 'rb') as f:
    hvcore_data = f.read()

with open(ticket_path, 'rb') as f:
    ticket_data = f.read()

assert len(ticket_data) == 32, f"Ticket size is {len(ticket_data)}, expected 32"

startup_text = (
    "echo HVLAB-TEST-BRINGUP\r\n"
    "connect -r\r\n"
    "setvar HvV_TESTTICKET -guid 7A3F1B2C-9E5D-4A8B-B6C1-D0E2F3A4B5C6 -bs -rt -nv =0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\r\n"
    "fs0:\r\n"
    "cd EFI\\Boot\r\n"
    "HvBoot.efi\r\n"
    "if exist fs1:\\EFI\\Microsoft\\Boot\\bootmgfw.efi then\r\n"
    "  echo Booting Windows from fs1...\r\n"
    "  fs1:\\EFI\\Microsoft\\Boot\\bootmgfw.efi\r\n"
    "endif\r\n"
    "if exist fs2:\\EFI\\Microsoft\\Boot\\bootmgfw.efi then\r\n"
    "  echo Booting Windows from fs2...\r\n"
    "  fs2:\\EFI\\Microsoft\\Boot\\bootmgfw.efi\r\n"
    "endif\r\n"
)
startup_data = startup_text.encode('ascii')

mode_char = sys.argv[1].upper() if len(sys.argv) > 1 else 'F'
cfg_data = mode_char.encode('ascii')
print(f"[*] Building ISO with mode: {mode_char}")

fat_files = {
    'EFI/BOOT/BOOTX64.EFI': shell_data,
    'EFI/BOOT/HVBOOT.EFI': hvboot_data,
    'EFI/BOOT/HVCORE.EFI': hvcore_data,
    'EFI/BOOT/HVCFG': cfg_data,
    'EFI/BOOT/HVTICKET': ticket_data,
    'EFI/BOOT/STARTUP.NSH': startup_data,
    'STARTUP.NSH': startup_data,
}

print("[*] Generating test_esp.img (16MB)...")
make_fat16.make_fat16('F:/HvEfi/test_esp.img', 16, fat_files)

# Also stage to iso_root
iso_root = r'F:\HvEfi\iso_root'
os.makedirs(os.path.join(iso_root, 'EFI', 'Boot'), exist_ok=True)

with open(os.path.join(iso_root, 'startup.nsh'), 'wb') as f:
    f.write(startup_data)
with open(os.path.join(iso_root, 'EFI', 'Boot', 'startup.nsh'), 'wb') as f:
    f.write(startup_data)
with open(os.path.join(iso_root, 'EFI', 'Boot', 'BOOTX64.EFI'), 'wb') as f:
    f.write(shell_data)
with open(os.path.join(iso_root, 'EFI', 'Boot', 'HvBoot.efi'), 'wb') as f:
    f.write(hvboot_data)
with open(os.path.join(iso_root, 'EFI', 'Boot', 'hvcore.efi'), 'wb') as f:
    f.write(hvcore_data)
with open(os.path.join(iso_root, 'EFI', 'Boot', 'hvcfg'), 'wb') as f:
    f.write(cfg_data)
with open(os.path.join(iso_root, 'EFI', 'Boot', 'hvticket'), 'wb') as f:
    f.write(ticket_data)

print("[*] Running oscdimg...")
oscdimg_exe = r'C:\Program Files\MiniTool Partition Wizard 13\oscdimg.exe'
cmd = [
    oscdimg_exe,
    '-m', '-o', '-u2', '-udfver102',
    '-bootdata:1#pEF,e,bF:\\HvEfi\\test_esp.img',
    iso_root,
    r'F:\HvEfi\hvefi_boot.iso'
]

res = subprocess.run(cmd, capture_output=True, text=True)
print(res.stdout)
if res.stderr:
    print(res.stderr)
print(f"[+] ISO build completed (returncode {res.returncode})")

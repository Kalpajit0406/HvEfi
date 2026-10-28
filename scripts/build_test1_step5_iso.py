import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import os
import subprocess
import make_fat16

shell_path = r'C:\Users\DELL\edk2\Build\OvmfX64\DEBUG_VS2022\X64\Shell.efi'
hvboot_path = r'F:\HvEfi\HvBoot.efi'
hvcore_path = r'F:\HvEfi\HvEfi.efi'

with open(shell_path, 'rb') as f:
    shell_data = f.read()

with open(hvboot_path, 'rb') as f:
    hvboot_data = f.read()

with open(hvcore_path, 'rb') as f:
    hvcore_data = f.read()

# Startup script: connect drivers, switch to fs0:, run HvBoot.efi
# NO TICKET is set. This triggers the designed Step 5 check.
startup_text = (
    "echo HVLAB-STEP5-UNPROVISIONED-TEST\r\n"
    "connect -r\r\n"
    "fs0:\r\n"
    "cd EFI\\Boot\r\n"
    "HvBoot.efi\r\n"
)
startup_data = startup_text.encode('ascii')
cfg_data = b'F'  # Full mode requested

fat_files = {
    'EFI/BOOT/BOOTX64.EFI': shell_data,
    'EFI/BOOT/HVBOOT.EFI': hvboot_data,
    'EFI/BOOT/HVCORE.EFI': hvcore_data,
    'EFI/BOOT/HVCFG': cfg_data,
    # NO HVTICKET!
    'EFI/BOOT/STARTUP.NSH': startup_data,
    'STARTUP.NSH': startup_data,
}

print("[*] Generating test_esp.img for Step 5 test...")
make_fat16.make_fat16('F:/HvEfi/test_esp.img', 16, fat_files)

# Stage files to iso_root
iso_root = r'F:\HvEfi\iso_root'
os.makedirs(os.path.join(iso_root, 'EFI', 'Boot'), exist_ok=True)

# Remove any old hvticket from iso_root
old_ticket = os.path.join(iso_root, 'EFI', 'Boot', 'hvticket')
if os.path.exists(old_ticket):
    os.remove(old_ticket)

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

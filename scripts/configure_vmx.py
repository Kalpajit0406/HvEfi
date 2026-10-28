import os

vmx_path = r'C:\Users\DELL\Documents\Virtual Machines\Windows 11 x64\Windows 11 x64.vmx'
with open(vmx_path, 'r', encoding='windows-1252') as f:
    lines = f.readlines()

new_lines = []
skip_keys = {
    'numvcpus', 'cpuid.coresPerSocket', 'memsize', 'numa.autosize.vcpu.maxPerVirtualNode',
    'smbios.reflectHost', 'SMBIOS.noOEMStrings', 'smbios.addHostVendor',
    'smbios.system.manufacturer', 'smbios.system.productName', 'smbios.system.version',
    'smbios.system.serialNumber', 'smbios.bios.vendor', 'smbios.bios.version',
    'smbios.bios.releaseDate', 'smbios.board.manufacturer', 'smbios.board.product',
    'smbios.board.version', 'smbios.board.serialNumber'
}

for line in lines:
    key = line.split('=')[0].strip() if '=' in line else ''
    if key in skip_keys:
        continue
    new_lines.append(line)

# Add optimized Dell G15 specifications
new_lines.append('\n# Dell G15 5530 Specs & SMBIOS\n')
new_lines.append('numvcpus = "16"\n')
new_lines.append('cpuid.coresPerSocket = "16"\n')
new_lines.append('memsize = "8192"\n')
new_lines.append('numa.autosize.vcpu.maxPerVirtualNode = "16"\n')
new_lines.append('smbios.reflectHost = "TRUE"\n')
new_lines.append('SMBIOS.noOEMStrings = "TRUE"\n')
new_lines.append('smbios.addHostVendor = "TRUE"\n')
new_lines.append('smbios.system.manufacturer = "Dell Inc."\n')
new_lines.append('smbios.system.productName = "Dell G15 5530"\n')
new_lines.append('smbios.system.version = "1.35.0"\n')
new_lines.append('smbios.system.serialNumber = "B362824"\n')
new_lines.append('smbios.bios.vendor = "Dell Inc."\n')
new_lines.append('smbios.bios.version = "1.35.0"\n')
new_lines.append('smbios.bios.releaseDate = "07/23/2026"\n')
new_lines.append('smbios.board.manufacturer = "Dell Inc."\n')
new_lines.append('smbios.board.product = "04TT83"\n')
new_lines.append('smbios.board.version = "A02"\n')
new_lines.append('smbios.board.serialNumber = "/B362824/CNCMC0042M08B6/"\n')

with open(vmx_path, 'w', encoding='windows-1252') as f:
    f.writelines(new_lines)
print('Successfully configured VMX for Dell G15 5530!')

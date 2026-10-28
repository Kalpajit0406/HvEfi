import struct, os, math

def make_fat16(filename, size_mb, files_map):
    # files_map: {'EFI/BOOT/BOOTX64.EFI': b'...', 'STARTUP.NSH': b'...'}
    sector_size = 512
    sec_per_clus = 4  # 2KB clusters
    clus_size = sec_per_clus * sector_size
    res_sec = 4
    num_fats = 2
    root_entries = 512
    root_sec = (root_entries * 32) // sector_size
    total_sec = (size_mb * 1024 * 1024) // sector_size
    
    # Calculate sec_per_fat
    # data_sec = total_sec - res_sec - num_fats * sec_per_fat - root_sec
    # total_clus = data_sec / sec_per_clus
    # sec_per_fat = ceil(total_clus * 2 / 512)
    sec_per_fat = int(math.ceil(((total_sec - res_sec - root_sec) / sec_per_clus * 2) / 512))
    data_sec = total_sec - res_sec - num_fats * sec_per_fat - root_sec
    total_clus = data_sec // sec_per_clus
    
    assert 4085 <= total_clus < 65525, f'Clusters {total_clus} not in FAT16 range!'
    
    img = bytearray(total_sec * sector_size)
    
    # BPB
    img[0:3] = b'\xEB\x3C\x90'
    img[3:11] = b'MSDOS5.0'
    struct.pack_into('<H', img, 11, sector_size)
    img[13] = sec_per_clus
    struct.pack_into('<H', img, 14, res_sec)
    img[16] = num_fats
    struct.pack_into('<H', img, 17, root_entries)
    struct.pack_into('<H', img, 19, 0 if total_sec > 65535 else total_sec)
    img[21] = 0xF8
    struct.pack_into('<H', img, 22, sec_per_fat)
    struct.pack_into('<H', img, 24, 63)
    struct.pack_into('<H', img, 26, 255)
    struct.pack_into('<I', img, 28, 0)
    struct.pack_into('<I', img, 32, total_sec if total_sec > 65535 else 0)
    img[36] = 0x80
    img[38] = 0x29
    struct.pack_into('<I', img, 39, 0x12345678)
    img[43:54] = b'NO NAME    '
    img[54:62] = b'FAT16   '
    img[510:512] = b'\x55\xAA'
    
    fat1_offset = res_sec * sector_size
    fat2_offset = fat1_offset + sec_per_fat * sector_size
    root_offset = fat2_offset + sec_per_fat * sector_size
    data_offset = root_offset + root_sec * sector_size
    
    def write_fat(clus, val):
        struct.pack_into('<H', img, fat1_offset + clus * 2, val)
        struct.pack_into('<H', img, fat2_offset + clus * 2, val)
        
    write_fat(0, 0xFFF8)
    write_fat(1, 0xFFFF)
    
    alloc_clus = 2
    def allocate_cluster():
        nonlocal alloc_clus
        c = alloc_clus
        alloc_clus += 1
        assert alloc_clus < total_clus, 'Out of disk space in FAT image!'
        return c
        
    # We will build directory structure
    # Hierarchy: { 'EFI': { 'BOOT': { 'BOOTX64.EFI': bytes } }, 'STARTUP.NSH': bytes }
    tree = {}
    for p, content in files_map.items():
        parts = p.replace('\\', '/').strip('/').split('/')
        curr = tree
        for part in parts[:-1]:
            curr = curr.setdefault(part.upper(), {})
        curr[parts[-1].upper()] = content
        
    def to_83(name):
        if '.' in name:
            b, e = name.split('.', 1)
            return f'{b[:8]:<8}{e[:3]:<3}'.encode('ascii')
        return f'{name[:8]:<8}{"   "}'.encode('ascii')

    def write_dir(dir_dict, parent_clus=0, is_root=False):
        nonlocal root_offset, data_offset
        entries = []
        if not is_root:
            # . and ..
            entries.append((b'.          ', 0x10, parent_clus, 0))
            entries.append((b'..         ', 0x10, 0, 0)) # parent
            
        subdirs_to_write = []
        files_to_write = []
        
        for k, v in dir_dict.items():
            if isinstance(v, dict):
                subdirs_to_write.append((k, v))
            else:
                files_to_write.append((k, v))
                
        # Allocate clusters for subdirectories and files
        for name, subdict in subdirs_to_write:
            s_clus = allocate_cluster()
            write_fat(s_clus, 0xFFFF)
            entries.append((to_83(name), 0x10, s_clus, 0))
            
        for name, content in files_to_write:
            f_size = len(content)
            num_c = int(math.ceil(f_size / clus_size)) if f_size > 0 else 0
            if num_c == 0:
                entries.append((to_83(name), 0x20, 0, 0))
            else:
                first_c = allocate_cluster()
                prev_c = first_c
                for _ in range(num_c - 1):
                    next_c = allocate_cluster()
                    write_fat(prev_c, next_c)
                    prev_c = next_c
                write_fat(prev_c, 0xFFFF)
                
                # Write data
                c = first_c
                off = 0
                while off < f_size:
                    chunk = content[off:off+clus_size]
                    c_off = data_offset + (c - 2) * clus_size
                    img[c_off:c_off+len(chunk)] = chunk
                    off += clus_size
                    c = struct.unpack_from('<H', img, fat1_offset + c * 2)[0]
                entries.append((to_83(name), 0x20, first_c, f_size))
                
        # Write directory entries into cluster or root
        raw_entries = bytearray()
        for ename, attr, clus, sz in entries:
            e = bytearray(32)
            e[0:11] = ename
            e[11] = attr
            struct.pack_into('<H', e, 26, clus)
            struct.pack_into('<I', e, 28, sz)
            raw_entries += e
            
        if is_root:
            img[root_offset:root_offset+len(raw_entries)] = raw_entries
        else:
            c_off = data_offset + (parent_clus - 2) * clus_size
            img[c_off:c_off+len(raw_entries)] = raw_entries
            
        # Recurse subdirs
        for (name, subdict), (_, _, s_clus, _) in zip(subdirs_to_write, [e for e in entries if e[1] == 0x10 and e[0] not in (b'.          ', b'..         ')]):
            write_dir(subdict, parent_clus=s_clus, is_root=False)
            
    write_dir(tree, is_root=True)
    
    with open(filename, 'wb') as f:
        f.write(img)
    print(f'FAT16 image written: {filename} ({len(img)} bytes)')

# Test with Shell.efi
with open(r'C:\Users\DELL\edk2\Build\OvmfX64\DEBUG_VS2022\X64\Shell.efi', 'rb') as f:
    shell_data = f.read()

make_fat16('test_esp.img', 16, {
    'EFI/BOOT/BOOTX64.EFI': shell_data,
    'STARTUP.NSH': b'echo HVLAB-SHELL-READY\r\n'
})

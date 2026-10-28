import os
import sys
import struct
import ctypes

NAME_SENTINEL = bytes([0xEF, 0xEF, 0xBE, 0xBE, 0xAD, 0xAD, 0xDE, 0xDE, 0x00, 0x00])
GUID_SENTINEL = bytes([0xDE, 0xC0, 0xAD, 0xDE, 0xAD, 0xDE, 0xDE, 0xC0, 0xDE, 0xAD, 0xC0, 0xDE, 0xDE, 0xAD, 0xC0, 0xDE])

# Default test variable name and GUID
TEST_VAR_NAME = "HvV_TESTTICKET"
# 7A3F1B2C-9E5D-4A8B-B6C1-D0E2F3A4B5C6
TEST_GUID_BYTES = bytes([
    0x2C, 0x1B, 0x3F, 0x7A,  # Data1 = 0x7A3F1B2C (LE)
    0x5D, 0x9E,              # Data2 = 0x9E5D (LE)
    0x8B, 0x4A,              # Data3 = 0x4A8B (LE)
    0xB6, 0xC1, 0xD0, 0xE2, 0xF3, 0xA4, 0xB5, 0xC6  # Data4
])

def update_pe_checksum(buf: bytearray, pe_offset: int) -> int:
    try:
        imagehlp = ctypes.windll.imagehlp
        hdr_sum = ctypes.c_ulong(0)
        file_sum = ctypes.c_ulong(0)
        buf_type = ctypes.c_char * len(buf)
        c_buf = buf_type.from_buffer(buf)
        res = imagehlp.CheckSumMappedFile(ctypes.byref(c_buf), len(buf), ctypes.byref(hdr_sum), ctypes.byref(file_sum))
        if res:
            struct.pack_into("<I", buf, pe_offset + 0x58, file_sum.value)
            return file_sum.value
    except Exception as e:
        print(f"[!] Warning: ctypes CheckSumMappedFile failed ({e}), using Python fallback")
    
    # Python fallback
    struct.pack_into("<I", buf, pe_offset + 0x58, 0)
    csum = 0
    for i in range(0, len(buf), 2):
        if i + 1 < len(buf):
            word = buf[i] | (buf[i+1] << 8)
        else:
            word = buf[i]
        csum += word
        csum = (csum & 0xFFFF) + (csum >> 16)
    csum = (csum & 0xFFFF) + (csum >> 16)
    csum = (csum + len(buf)) & 0xFFFFFFFF
    struct.pack_into("<I", buf, pe_offset + 0x58, csum)
    return csum

def patch_efi(src_path: str, dst_path: str, var_name: str = TEST_VAR_NAME, guid_bytes: bytes = TEST_GUID_BYTES):
    with open(src_path, "rb") as f:
        data = bytearray(f.read())
    
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError(f"{src_path} is not a valid PE image (no MZ)")
    
    lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if lfanew + 24 > len(data):
        raise ValueError("Bogus e_lfanew")
    
    num_sections = struct.unpack_from("<H", data, lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, lfanew + 20)[0]
    sec_offset = lfanew + 24 + opt_size
    
    data_off = None
    data_size = None
    for i in range(num_sections):
        s = sec_offset + i * 40
        if s + 40 > len(data):
            break
        chars = struct.unpack_from("<I", data, s + 36)[0]
        cnt_init = (chars & 0x40) != 0
        write = (chars & 0x80000000) != 0
        if cnt_init and write:
            data_off = struct.unpack_from("<I", data, s + 20)[0]
            data_size = struct.unpack_from("<I", data, s + 16)[0]
            break
            
    if data_off is None or data_size is None or data_off + data_size > len(data):
        raise ValueError(f"{src_path}: no writable initialized .data section found")
        
    data_sec = data[data_off : data_off + data_size]
    name_hits = []
    guid_hits = []
    
    idx = 0
    while True:
        pos = data_sec.find(NAME_SENTINEL, idx)
        if pos == -1:
            break
        name_hits.append(data_off + pos)
        idx = pos + 1
        
    idx = 0
    while True:
        pos = data_sec.find(GUID_SENTINEL, idx)
        if pos == -1:
            break
        guid_hits.append(data_off + pos)
        idx = pos + 1
        
    if len(name_hits) != 1 or len(guid_hits) != 1:
        raise ValueError(f"{src_path}: unexpected sentinel counts: name={len(name_hits)}, guid={len(guid_hits)}")
        
    name_off = name_hits[0]
    guid_off = guid_hits[0]
    
    # Overwrite 48 bytes for name (UTF-16LE, zero padded)
    encoded_name = var_name.encode("utf-16le")
    if len(encoded_name) > 46:
        raise ValueError("var_name too long")
    name_buf = bytearray(48)
    name_buf[:len(encoded_name)] = encoded_name
    data[name_off : name_off + 48] = name_buf
    
    # Overwrite 16 bytes for GUID
    data[guid_off : guid_off + 16] = guid_bytes
    
    # Verify both sentinels are completely gone
    data_sec_after = data[data_off : data_off + data_size]
    if NAME_SENTINEL in data_sec_after or GUID_SENTINEL in data_sec_after:
        raise ValueError("Patch verification failed: sentinels still present")
        
    csum = update_pe_checksum(data, lfanew)
    with open(dst_path, "wb") as f:
        f.write(data)
        
    print(f"[+] Successfully patched {src_path} -> {dst_path}")
    print(f"    Name patched at 0x{name_off:X} ('{var_name}')")
    print(f"    GUID patched at 0x{guid_off:X}")
    print(f"    New PE checksum: 0x{csum:08X}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python patch_sentinels.py <src.efi> <dst.efi>")
        sys.exit(1)
    patch_efi(sys.argv[1], sys.argv[2])

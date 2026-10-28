import socket
import struct
import sys
from PIL import Image

def capture_vnc(host="127.0.0.1", port=5900, out_path="F:/HvEfi/vnc_screen.png"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((host, port))
    
    # 1. Version handshake
    server_ver = s.recv(12)
    print(f"[*] Server version: {server_ver}")
    s.sendall(b"RFB 003.008\n")
    
    # 2. Security types
    num_sec = struct.unpack("!B", s.recv(1))[0]
    sec_types = s.recv(num_sec)
    print(f"[*] Sec types: {list(sec_types)}")
    if 1 in sec_types:
        s.sendall(struct.pack("!B", 1)) # None
    else:
        print("[-] Type 1 (None) not found!")
        s.close()
        return False
        
    # Security result
    sec_res = struct.unpack("!I", s.recv(4))[0]
    if sec_res != 0:
        print(f"[-] Security failed: {sec_res}")
        s.close()
        return False
        
    # 3. ClientInit (shared=1)
    s.sendall(struct.pack("!B", 1))
    
    # 4. ServerInit
    data = s.recv(24)
    w, h = struct.unpack("!HH", data[:4])
    pix_format = data[4:20]
    bpp, depth, big_endian, true_color = struct.unpack("!BBBB", pix_format[:4])
    name_len = struct.unpack("!I", data[20:24])[0]
    name = s.recv(name_len).decode('latin1', errors='ignore')
    print(f"[*] Connected to '{name}' ({w}x{h}, bpp={bpp}, depth={depth})")
    
    # 5. Set encodings: 0 = Raw
    enc_req = struct.pack("!BBH", 2, 0, 1) + struct.pack("!i", 0)
    s.sendall(enc_req)
    
    # 6. Request FramebufferUpdate (incremental=0, full)
    fb_req = struct.pack("!BBHHHH", 3, 0, 0, 0, w, h)
    s.sendall(fb_req)
    
    # 7. Read FramebufferUpdate
    msg_type = struct.unpack("!B", s.recv(1))[0]
    assert msg_type == 0, f"Expected 0 (FramebufferUpdate), got {msg_type}"
    s.recv(1) # padding
    num_rects = struct.unpack("!H", s.recv(2))[0]
    print(f"[*] Rectangles received: {num_rects}")
    
    img = Image.new("RGB", (w, h))
    pixels = bytearray(w * h * 4)
    
    for _ in range(num_rects):
        rx, ry, rw, rh, enc = struct.unpack("!HHHHi", s.recv(12))
        assert enc == 0, f"Unsupported encoding {enc}"
        bytes_needed = rw * rh * (bpp // 8)
        rect_data = bytearray()
        while len(rect_data) < bytes_needed:
            chunk = s.recv(min(4096, bytes_needed - len(rect_data)))
            if not chunk:
                break
            rect_data.extend(chunk)
            
        # Draw into image
        rect_img = Image.frombytes("RGB", (rw, rh), bytes(rect_data), "raw", "BGRX")
        img.paste(rect_img, (rx, ry))
        
    img.save(out_path)
    print(f"[+] Screen successfully saved to {out_path}")
    s.close()
    return True

if __name__ == "__main__":
    capture_vnc()

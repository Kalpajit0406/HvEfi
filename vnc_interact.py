import socket
import struct
import time
import sys
from PIL import Image

def send_key(s, keysym, delay=0.05):
    # key down
    s.sendall(struct.pack("!BB2xI", 4, 1, keysym))
    time.sleep(delay)
    # key up
    s.sendall(struct.pack("!BB2xI", 4, 0, keysym))
    time.sleep(delay)

def send_click(s, x, y, delay=0.1):
    # pointer move + button down (mask=1)
    s.sendall(struct.pack("!BBHH", 5, 1, x, y))
    time.sleep(delay)
    # button up (mask=0)
    s.sendall(struct.pack("!BBHH", 5, 0, x, y))
    time.sleep(delay)

def vnc_action(keys=None, text=None, click=None, wait_after=2.0, out_path="F:/HvEfi/vnc_screen.png"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(("127.0.0.1", 5900))
    
    # 1. Version handshake
    s.recv(12)
    s.sendall(b"RFB 003.008\n")
    
    # 2. Security
    num_sec = struct.unpack("!B", s.recv(1))[0]
    sec_types = s.recv(num_sec)
    s.sendall(struct.pack("!B", 1)) # None
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
    
    # Set encodings: Raw
    s.sendall(struct.pack("!BBH", 2, 0, 1) + struct.pack("!i", 0))
    
    if click:
        send_click(s, click[0], click[1])
            
    if keys:
        for k in keys:
            send_key(s, k)
            
    if text:
        for ch in text:
            send_key(s, ord(ch))
            
    time.sleep(wait_after)
    
    # Request FramebufferUpdate
    s.sendall(struct.pack("!BBHHHH", 3, 0, 0, 0, w, h))
    
    msg_type = struct.unpack("!B", s.recv(1))[0]
    assert msg_type == 0
    s.recv(1)
    num_rects = struct.unpack("!H", s.recv(2))[0]
    
    img = Image.new("RGB", (w, h))
    for _ in range(num_rects):
        rx, ry, rw, rh, enc = struct.unpack("!HHHHi", s.recv(12))
        assert enc == 0
        bytes_needed = rw * rh * (bpp // 8)
        rect_data = bytearray()
        while len(rect_data) < bytes_needed:
            chunk = s.recv(min(8192, bytes_needed - len(rect_data)))
            if not chunk:
                break
            rect_data.extend(chunk)
        rect_img = Image.frombytes("RGB", (rw, rh), bytes(rect_data), "raw", "BGRX")
        img.paste(rect_img, (rx, ry))
        
    img.save(out_path)
    print(f"[+] Action complete, screen saved to {out_path}")
    s.close()
    return True

if __name__ == "__main__":
    # Press spacebar (0x0020) to dismiss lock screen
    vnc_action(keys=[0x0020], wait_after=2.0)

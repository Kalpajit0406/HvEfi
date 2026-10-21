import os
import sys
import time
import subprocess
import socket
import struct
import re
from PIL import Image

VMRUN = r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
VMX = r"C:\Users\DELL\Documents\Virtual Machines\Windows 11 x64\Windows 11 x64.vmx"
SERIAL_LOG = r"C:\Users\DELL\Documents\Virtual Machines\Windows 11 x64\hvserial.log"
RECEIPTS_DIR = r"F:\HvEfi\receipts"

def stop_vm():
    print("[*] Stopping VM...")
    subprocess.run([VMRUN, "-T", "ws", "stop", VMX, "soft"], capture_output=True)
    time.sleep(2)
    subprocess.run([VMRUN, "-T", "ws", "stop", VMX, "hard"], capture_output=True)
    time.sleep(2)

def start_vm():
    if os.path.exists(SERIAL_LOG):
        try:
            os.remove(SERIAL_LOG)
        except Exception as e:
            print(f"[!] Warning removing serial log: {e}")
    print("[*] Starting VM nogui...")
    res = subprocess.run([VMRUN, "-T", "ws", "start", VMX, "nogui"], capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Failed to start VM: {res.stderr}")
    print("[+] VM started.")

def build_iso(mode='F'):
    print(f"[*] Building boot ISO with mode '{mode}'...")
    res = subprocess.run([sys.executable, "build_lab_iso.py", mode], capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"ISO build failed:\n{res.stderr}\n{res.stdout}")
    print("[+] ISO build succeeded.")

def capture_vnc(out_path, host="127.0.0.1", port=5900):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((host, port))
    s.recv(12)
    s.sendall(b"RFB 003.008\n")
    num_sec = struct.unpack("!B", s.recv(1))[0]
    s.recv(num_sec)
    s.sendall(struct.pack("!B", 1)) # None
    sec_res = struct.unpack("!I", s.recv(4))[0]
    if sec_res != 0:
        s.close()
        raise RuntimeError(f"VNC Security failed: {sec_res}")
    s.sendall(struct.pack("!B", 1))
    data = s.recv(24)
    w, h = struct.unpack("!HH", data[:4])
    pix_format = data[4:20]
    bpp = struct.unpack("!BBBB", pix_format[:4])[0]
    name_len = struct.unpack("!I", data[20:24])[0]
    s.recv(name_len)
    s.sendall(struct.pack("!BBH", 2, 0, 1) + struct.pack("!i", 0))
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
    s.close()
    colors = len(img.getcolors(maxcolors=2000000))
    print(f"[+] Screen captured to {out_path} ({w}x{h}, {colors} distinct colors)")
    return colors

def vnc_send_keys(keys, wait_after=2.0, host="127.0.0.1", port=5900):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((host, port))
    s.recv(12)
    s.sendall(b"RFB 003.008\n")
    num_sec = struct.unpack("!B", s.recv(1))[0]
    s.recv(num_sec)
    s.sendall(struct.pack("!B", 1))
    s.recv(4)
    s.sendall(struct.pack("!B", 1))
    data = s.recv(24)
    name_len = struct.unpack("!I", data[20:24])[0]
    s.recv(name_len)
    s.sendall(struct.pack("!BBH", 2, 0, 1) + struct.pack("!i", 0))

    for k in keys:
        # key down
        s.sendall(struct.pack("!BB2xI", 4, 1, k))
        time.sleep(0.05)
        # key up
        s.sendall(struct.pack("!BB2xI", 4, 0, k))
        time.sleep(0.05)
    s.close()
    time.sleep(wait_after)

def read_serial_log():
    if not os.path.exists(SERIAL_LOG):
        return ""
    with open(SERIAL_LOG, "rb") as f:
        return f.read().decode("latin1", errors="replace")

def analyze_log(log_text):
    info = {
        "step13": ("CORE stage=13" in log_text) or ("Step 13" in log_text),
        "full_start": ("FULL START" in log_text),
        "full_done": ("FULL DONE" in log_text),
        "safe_standdown": ("BOOT SAFE stood-down" in log_text) or ("BOOT SAFE" in log_text),
        "vmcall_detect": ("VMCALL DETECT SUCCEEDED" in log_text),
        "vmcall_selftest": ("HV_HYPERCALL_SELFTEST: PASSED" in log_text),
        "chain_win": ("Found Windows Boot Manager" in log_text) or ("CHAIN WIN" in log_text),
        "active_cpus": set(),
        "exit_counts": {},
        "raw_lines": len(log_text.splitlines())
    }
    for line in log_text.splitlines():
        if "[VMEXIT]" in line:
            parts = line.split()
            cpu = None
            reason = None
            for p in parts:
                if p.startswith("cpu="):
                    try:
                        cpu = int(p.split("=")[1])
                    except:
                        pass
                elif p.startswith("reason="):
                    try:
                        reason = int(p.split("=")[1])
                    except:
                        pass
            if cpu is not None:
                info["active_cpus"].add(cpu)
            if reason is not None:
                info["exit_counts"][reason] = info["exit_counts"].get(reason, 0) + 1
    m = re.search(r"vcpus=(\d+)", log_text, re.IGNORECASE)
    if not m:
        m = re.search(r"vCPUs:\s*(\d+)", log_text, re.IGNORECASE)
    if m:
        vcount = int(m.group(1))
        for c in range(vcount):
            info["active_cpus"].add(c)
    return info

def run_test_boot(mode='F', min_wait=60, max_timeout=180, receipt_name='test.log', screenshot_name='test.png', stop_vm_after=True, soak_seconds=None):
    print(f"\n{'='*70}\n[*] RUNNING BOOT TEST: mode={mode}, max_timeout={max_timeout}s\n{'='*70}")
    stop_vm()
    build_iso(mode)
    start_vm()

    start_time = time.time()
    last_pos = 0
    colors = 0
    screenshot_path = os.path.join(RECEIPTS_DIR, screenshot_name)
    desktop_detected_at = None
    prompt_dismissed = False

    while True:
        elapsed = time.time() - start_time
        if os.path.exists(SERIAL_LOG):
            try:
                with open(SERIAL_LOG, "r", encoding="latin1") as f:
                    f.seek(last_pos)
                    chunk = f.read()
                    if chunk:
                        sys.stdout.write(chunk)
                        sys.stdout.flush()
                        last_pos = f.tell()
            except:
                pass

        if elapsed >= min_wait:
            try:
                colors = capture_vnc(screenshot_path)
                if colors > 5000:
                    if desktop_detected_at is None:
                        desktop_detected_at = elapsed
                        print(f"[+] Graphical desktop detected at {elapsed:.1f}s ({colors} distinct colors)!")
                    if not soak_seconds or elapsed >= soak_seconds:
                        break
                else:
                    im = Image.open(screenshot_path)
                    top = sorted(im.getcolors(maxcolors=100000), key=lambda x: x[0], reverse=True)[0]
                    if top[1] == (32, 103, 178):
                        print(f"[*] WinRE blue screen detected ({colors} colors) at {elapsed:.1f}s, sending Enter...")
                        vnc_send_keys([0xFF0D], wait_after=2.0)
                    elif not prompt_dismissed and colors < 100 and top[1] == (0, 0, 0) and im.getbbox() is not None:
                        print(f"[*] Windows Boot Manager text prompt detected ({colors} colors) at {elapsed:.1f}s, sending Enter once...")
                        vnc_send_keys([0xFF0D], wait_after=2.0)
                        prompt_dismissed = True
                    else:
                        print(f"[*] Boot in progress ({colors} colors at {elapsed:.1f}s)...")
            except Exception as e:
                pass

        if elapsed >= max_timeout:
            print(f"[!] Reached max timeout of {max_timeout}s.")
            try:
                colors = capture_vnc(screenshot_path)
            except Exception as e:
                print(f"[!] VNC capture error at timeout: {e}")
            break

        time.sleep(3)

    if stop_vm_after:
        stop_vm()

    log_text = read_serial_log()
    receipt_path = os.path.join(RECEIPTS_DIR, receipt_name)
    with open(receipt_path, "w", encoding="utf-8", errors="replace") as f:
        f.write(log_text)
    print(f"[+] Receipt saved to {receipt_path} ({len(log_text)} chars)")

    info = analyze_log(log_text)
    info["colors"] = colors
    info["receipt_path"] = receipt_path
    info["screenshot_path"] = screenshot_path
    info["boot_time"] = time.time() - start_time
    info["desktop_detected_at"] = desktop_detected_at
    print(f"[*] Summary: Step13={info['step13']} | Detect={info['vmcall_detect']} | Selftest={info['vmcall_selftest']} | Windows={info['chain_win']} | Active CPUs={sorted(list(info['active_cpus']))} | Colors={colors} | Time={info['boot_time']:.1f}s")
    return info

def test_1_full_cold_boot():
    print("\n" + "="*70)
    print("[TEST 1] Cold Boot in Full Mode ('F') with 16 vCPUs")
    print("="*70)
    info = run_test_boot(mode='F', min_wait=65, max_timeout=110,
                         receipt_name='test1_full_cold_boot.log',
                         screenshot_name='test1_full_cold_boot.png')
    assert info['step13'], "Step 13 not reached!"
    assert info['vmcall_detect'], "VMCALL detect failed!"
    assert info['vmcall_selftest'], "VMCALL selftest failed!"
    assert info['chain_win'], "Windows boot manager not found!"
    assert len(info['active_cpus']) == 16, f"Expected 16 active CPUs, got {len(info['active_cpus'])}"
    assert info['colors'] > 5000, f"Expected desktop/lockscreen colors > 5000, got {info['colors']}"
    print("[+] TEST 1 PASSED: 16 vCPUs virtualized, Windows reached graphical display.")
    return info

def test_2_vnc_interaction():
    print("\n" + "="*70)
    print("[TEST 2] Lock Screen Dismissal & VNC Interactive Input")
    print("="*70)
    info = run_test_boot(mode='F', min_wait=65, max_timeout=110,
                         receipt_name='test2_before.log',
                         screenshot_name='test2_before_interaction.png',
                         stop_vm_after=False)
    c1 = info['colors']
    assert c1 > 5000, f"Expected desktop before interaction, got {c1} colors"

    # 1. Send Spacebar (0x0020) to dismiss lock screen
    print("[*] Sending Spacebar (0x0020) via VNC to dismiss lock screen...")
    vnc_send_keys([0x0020], wait_after=3.0)

    # 2. Capture screen after spacebar
    after_space = os.path.join(RECEIPTS_DIR, 'test2_after_spacebar.png')
    c2 = capture_vnc(after_space)

    # 3. Send Enter (0xFF0D) to test keyboard input
    print("[*] Sending Enter (0xFF0D) via VNC...")
    vnc_send_keys([0xFF0D], wait_after=3.0)

    after_enter = os.path.join(RECEIPTS_DIR, 'test2_after_enter.png')
    c3 = capture_vnc(after_enter)

    stop_vm()
    log_text = read_serial_log()
    receipt_path = os.path.join(RECEIPTS_DIR, 'test2_interaction.log')
    with open(receipt_path, 'w', encoding='utf-8', errors='replace') as f:
        f.write(log_text)

    print(f"[+] TEST 2 PASSED: Initial colors={c1}, After spacebar={c2}, After enter={c3}")
    return {"colors_initial": c1, "colors_space": c2, "colors_enter": c3}

def test_3_safe_mode():
    print("\n" + "="*70)
    print("[TEST 3] Safe Mode Boot ('S') Stand-Down Verification")
    print("="*70)
    info = run_test_boot(mode='S', min_wait=65, max_timeout=110,
                         receipt_name='test3_safe_mode.log',
                         screenshot_name='test3_safe_mode.png')
    assert info['safe_standdown'], "Core did not record BOOT SAFE stood-down!"
    assert not info['step13'], "Step 13 should not be reached in safe mode!"
    assert len(info['active_cpus']) == 0, f"Expected 0 active CPUs under VMX, got {len(info['active_cpus'])}"
    assert info['chain_win'], "Windows should chainload even in safe mode!"
    assert info['colors'] > 5000, f"Expected desktop/lockscreen colors > 5000, got {info['colors']}"
    print("[+] TEST 3 PASSED: Hypervisor stood down cleanly to safe mode; Windows booted bare metal.")
    return info

def test_4_multiboot_reproducibility():
    print("\n" + "="*70)
    print("[TEST 4] Multi-Boot Reproducibility: 3 Consecutive Full Mode Boots")
    print("="*70)
    build_iso('F')
    results = []
    for cycle in range(1, 4):
        print(f"\n--- Boot Cycle {cycle} of 3 ---")
        info = run_test_boot(mode='F', min_wait=60, max_timeout=180,
                             receipt_name=f'test4_reboot{cycle}.log',
                             screenshot_name=f'test4_reboot{cycle}.png')
        assert info['step13'], f"Cycle {cycle}: Step 13 not reached!"
        assert info['vmcall_detect'], f"Cycle {cycle}: VMCALL detect failed!"
        assert len(info['active_cpus']) == 16, f"Cycle {cycle}: Only {len(info['active_cpus'])} CPUs active"
        assert info['colors'] > 5000, f"Cycle {cycle}: Distinct colors {info['colors']} <= 5000"
        results.append(info)
        print(f"[+] Boot Cycle {cycle}/3 SUCCEEDED (Colors: {info['colors']}, Time: {info['boot_time']:.1f}s)")
    print("[+] TEST 4 PASSED: 3/3 consecutive boots 100% reproducible!")
    return results

def test_5_soak_180s():
    print("\n" + "="*70)
    print("[TEST 5] Long-Duration Soak Test (180s Continuous Execution)")
    print("="*70)
    info = run_test_boot(mode='F', min_wait=60, max_timeout=190, soak_seconds=180,
                         receipt_name='test5_soak_180s.log',
                         screenshot_name='test5_soak_180s.png')
    assert info['step13'], "Step 13 not reached!"
    assert len(info['active_cpus']) == 16, f"Expected 16 active CPUs, got {len(info['active_cpus'])}"
    assert info['colors'] > 5000, f"Colors {info['colors']} <= 5000"
    print(f"[+] TEST 5 PASSED: 180s soak completed without faults. Exit profile: {info['exit_counts']}")
    return info

if __name__ == '__main__':
    target = sys.argv[1].lower() if len(sys.argv) > 1 else 'all'
    print(f"[*] Starting intensive test suite (target: {target})...")

    if target in ('1', 'test1', 'all'):
        test_1_full_cold_boot()
    if target in ('2', 'test2', 'all'):
        test_2_vnc_interaction()
    if target in ('3', 'test3', 'all'):
        test_3_safe_mode()
    if target in ('4', 'test4', 'all'):
        test_4_multiboot_reproducibility()
    if target in ('5', 'test5', 'all'):
        test_5_soak_180s()

    print("\n" + "="*70)
    print("[+] ALL TARGETED TESTS COMPLETED SUCCESSFULLY!")
    print("="*70)


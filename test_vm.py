import os
import sys
import time
import subprocess
import vnc_capture

VMRUN = r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
VMX = r"C:\Users\DELL\Documents\Virtual Machines\Windows 11 x64\Windows 11 x64.vmx"
SERIAL_LOG = r"C:\Users\DELL\Documents\Virtual Machines\Windows 11 x64\hvserial.log"
SCREENSHOT = r"F:\HvEfi\vnc_screen.png"

def run_test(duration=60):
    print("=" * 70)
    print(f"[*] Starting VM Test (Duration: {duration}s)")
    print("=" * 70)

    # 1. Stop VM if already running
    subprocess.run([VMRUN, "-T", "ws", "stop", VMX, "hard"], capture_output=True)
    time.sleep(2)

    # 2. Clear serial log
    if os.path.exists(SERIAL_LOG):
        try:
            os.remove(SERIAL_LOG)
        except Exception as e:
            print(f"[!] Warning: Could not remove serial log: {e}")

    # 3. Start VM nogui
    print("[*] Launching VM in headless mode (nogui)...")
    res = subprocess.run([VMRUN, "-T", "ws", "start", VMX, "nogui"], capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[-] Failed to start VM: {res.stderr}")
        return False

    print("[*] VM started successfully. Monitoring serial output...")
    start_time = time.time()
    last_pos = 0

    while time.time() - start_time < duration:
        if os.path.exists(SERIAL_LOG):
            try:
                with open(SERIAL_LOG, "r", encoding="latin1") as f:
                    f.seek(last_pos)
                    new_text = f.read()
                    if new_text:
                        sys.stdout.write(new_text)
                        sys.stdout.flush()
                        last_pos = f.tell()
            except Exception:
                pass
        time.sleep(1)

    print("\n[*] Time elapsed. Capturing VNC screen...")
    try:
        vnc_capture.capture_vnc(out_path=SCREENSHOT)
    except Exception as e:
        print(f"[!] VNC capture error: {e}")

    print("[*] Stopping VM...")
    subprocess.run([VMRUN, "-T", "ws", "stop", VMX, "hard"], capture_output=True)
    print("[+] VM stopped. Test completed.")

    # Read final serial log
    if os.path.exists(SERIAL_LOG):
        with open(SERIAL_LOG, "rb") as f:
            final_bytes = f.read()
        final_content = final_bytes.decode('utf-8', errors='replace')
        print("\n" + "=" * 70)
        print("FINAL SERIAL LOG OUTPUT:")
        print("=" * 70)
        print(final_content.encode('ascii', errors='replace').decode('ascii'))
        print("=" * 70)

    return True

if __name__ == "__main__":
    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    run_test(dur)

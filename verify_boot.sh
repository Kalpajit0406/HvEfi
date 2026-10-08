#!/usr/bin/env bash
# verify_boot.sh - end-to-end build + QEMU boot + POST-decode harness for
# HvEfi on a Linux host. Run from the repo root. Produces three artifacts
# (HvEfi.efi, HvBoot.efi, HvProv.efi) via EDK2 CLANGPDB, then boots them
# under QEMU + OVMF (both safe and full-mode) and decodes the port-0x80
# POST byte stream into the stage names from hv_efi_main.c's POST CODE MAP.
#
# Prerequisites (Ubuntu 24.04 example):
#   sudo apt-get install -y nasm iasl uuid-dev build-essential acpica-tools \
#        qemu-system-x86 ovmf mingw-w64 clang lld python3
#
# EDK2 workspace layout (set once):
#   git clone --depth 1 --branch edk2-stable202405 \
#             https://github.com/tianocore/edk2.git ~/edk2
#   cd ~/edk2 && git submodule update --init --depth 1 && \
#     make -C BaseTools -j && . edksetup.sh
#   export HV_WORKSPACE=~/edk2
#
# Then from the HvEfi repo root:
#   ./verify_boot.sh

set -euo pipefail

: "${HV_WORKSPACE:?Set HV_WORKSPACE to your EDK2 workspace root}"
HVROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="${HV_WORKSPACE}/Build/HvEfiPkg/DEBUG_CLANGPDB/X64"

echo "[+] Staging sources into $HV_WORKSPACE/HvEfi"
mkdir -p "$HV_WORKSPACE/HvEfi/shim_include" "$HV_WORKSPACE/HvDrv"
cp "$HVROOT"/*.c "$HVROOT"/*.h "$HVROOT"/*.asm "$HVROOT"/*.inf "$HV_WORKSPACE/HvEfi/"
for f in "$HVROOT"/shared/*.h; do
    ln -sf "$f" "$HV_WORKSPACE/$(basename $f)"
done
ln -sf "$HVROOT/shared/HvDrv/hv_msr_contract.h" "$HV_WORKSPACE/HvDrv/"
# Workspace-only cross-build helpers (not in the repo; symlink if present):
for f in HvProv.c HvProv.inf HvEfiPkg.dsc hv_clang_shim.h hv_asm.nasm; do
    [ -f "$HVROOT/.verify/$f" ] && cp "$HVROOT/.verify/$f" "$HV_WORKSPACE/HvEfi/" || true
done

echo "[+] Building via EDK2 CLANGPDB"
cd "$HV_WORKSPACE"
export WORKSPACE="$HV_WORKSPACE"
export PACKAGES_PATH="$HV_WORKSPACE"
export CLANG_BIN=/usr/bin/
export EDK_TOOLS_PATH="$HV_WORKSPACE/BaseTools"
export PATH="$EDK_TOOLS_PATH/BinWrappers/PosixLike:$PATH"
. "$HV_WORKSPACE/edksetup.sh" > /dev/null
build -a X64 -b DEBUG -t CLANGPDB \
      -p HvEfi/HvEfiPkg.dsc 2>&1 | tail -5

[ -f "$OUT/HvEfi.efi" ] || { echo "[-] HvEfi.efi missing"; exit 1; }
echo "[+] Artifacts:"; ls -la "$OUT"/*.efi

echo "[+] Preparing ESP"
RUNDIR="$(mktemp -d)"
trap "rm -rf $RUNDIR" EXIT
mkdir -p "$RUNDIR/esp/EFI/Boot"
cp "$OUT/HvEfi.efi"  "$RUNDIR/esp/EFI/Boot/"
cp "$OUT/HvBoot.efi" "$RUNDIR/esp/EFI/Boot/"
[ -f "$OUT/HvProv.efi" ] && cp "$OUT/HvProv.efi" "$RUNDIR/esp/EFI/Boot/"
cp /usr/share/OVMF/OVMF_CODE_4M.fd "$RUNDIR/code.fd"
cp /usr/share/OVMF/OVMF_VARS_4M.fd "$RUNDIR/vars.fd"

qemu_boot() {
    local script="$1"
    local post="$2"
    cat > "$RUNDIR/esp/EFI/Boot/startup.nsh" <<< "$script"
    cp /usr/share/OVMF/OVMF_VARS_4M.fd "$RUNDIR/vars.fd"
    local extra=""
    [ -r /dev/kvm ] && [ -w /dev/kvm ] && extra="-enable-kvm -cpu host"
    timeout 25 qemu-system-x86_64 \
        $extra \
        -machine q35 -m 2048 -smp 1 \
        -drive if=pflash,format=raw,readonly=on,file="$RUNDIR/code.fd" \
        -drive if=pflash,format=raw,file="$RUNDIR/vars.fd" \
        -drive format=raw,file=fat:rw:"$RUNDIR/esp" \
        -net none \
        -chardev file,id=post,path="$post" \
        -device isa-debugcon,iobase=0x80,chardev=post \
        -display none -nographic > /dev/null 2>&1 &
    local pid=$!
    sleep 22
    kill $pid 2>/dev/null || true
    wait $pid 2>/dev/null || true
}

echo
echo "[+] Boot run 1 — safe-mode (no HvProv)"
qemu_boot $'fs0:\\EFI\\Boot\\HvEfi.efi\nreset -s\n' "$RUNDIR/post_safe.log"
python3 "$HVROOT/decode_post.py" "$RUNDIR/post_safe.log"

if [ -f "$OUT/HvProv.efi" ]; then
    echo
    echo "[+] Boot run 2 — full-mode (via HvProv mailbox provisioner)"
    qemu_boot $'fs0:\\EFI\\Boot\\HvProv.efi\nreset -s\n' "$RUNDIR/post_full.log"
    python3 "$HVROOT/decode_post.py" "$RUNDIR/post_full.log"
fi

echo
echo "[+] Done. Expected safe-mode: B0 B1 B2 B3"
echo "    Expected full-mode (TCG):     B0 B1 B2 C0 C1 C2 C4 B5 B6"
echo "    Expected full-mode (KVM/HW):  …through B7 B8 BB BC BD C5 BF"

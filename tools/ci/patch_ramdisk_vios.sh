#!/bin/bash
# V-iOS Phase 2 / macOS runner stage.
# Turn the stock raw-APFS restore ramdisk into the dual-shell target ramdisk.
#
#   patch_ramdisk_vios.sh <stock-ramdisk.dmg> <out-dir> <repo-root>
#
# Outputs (all uploaded as CI artifacts, none committed back to the repo):
#   ramdisk.vios.dmg   patched raw APFS image  -> E:/V-iOS/firmware/ramdisk.dmg
#   ramdisk.tc         trustcache              -> E:/V-iOS/firmware/ramdisk.tc
#   all_hashes         cdhash list             -> evidence only
#   report.json        forensic answers for A4 / U4 / U5
#
# WHY THIS RUNS ON macOS: hdiutil (mount + write APFS), chown, codesign.
# Everything else (IPSW extract, img4 unwrap, dt_fixup, build_tc) is cross-platform
# and already done on Windows. See docs/板级引导自检_2026-11-06.md H7-H10.
#
# Compliance: Apple firmware never goes into a public repo. Use a PRIVATE repo,
# delete the ramdisk parts + artifacts as soon as the two outputs are back on Windows.

set -euo pipefail

RAMDISK="${1:?usage: patch_ramdisk_vios.sh <ramdisk.dmg> <out-dir> <repo-root>}"
OUT="${2:?missing out-dir}"
ROOT="${3:?missing repo-root}"

[[ "$(uname)" == "Darwin" ]] || { echo "ERROR: needs macOS (hdiutil/chown/codesign)"; exit 1; }
[[ -f "${RAMDISK}" ]]        || { echo "ERROR: no ramdisk at ${RAMDISK}"; exit 1; }

mkdir -p "${OUT}"
MNT="$(mktemp -d /tmp/vios-ramdisk.XXXXXX)"
WORK="$(mktemp -d /tmp/vios-work.XXXXXX)"

cleanup() {
    hdiutil detach "${MNT}" -force >/dev/null 2>&1 || true
    rmdir "${MNT}" 2>/dev/null || true
    rm -rf "${WORK}"
}
trap cleanup EXIT

echo "=== [1/9] sanity: raw APFS container ==="
# NXSB must sit at offset 0x20. QEMU mmaps the whole file and does NOT parse it,
# so the patched image stays a raw image - no UDIF rewrap needed.
python3 - "${RAMDISK}" <<'PY'
import sys
d = open(sys.argv[1], "rb").read(36)
assert d[0x20:0x24] == b"NXSB", "not a raw APFS container (NXSB missing at 0x20)"
print("raw APFS OK, size", __import__("os").path.getsize(sys.argv[1]))
PY
cp "${RAMDISK}" "${OUT}/ramdisk.vios.dmg"
chmod u+w "${OUT}/ramdisk.vios.dmg"

echo "=== [2/9] attach (owners off, writable) ==="
hdiutil attach -owners off -mountpoint "${MNT}" "${OUT}/ramdisk.vios.dmg"

echo "=== [3/9] forensic snapshot BEFORE touching anything (A4 / U4 / U5) ==="
mkdir -p "${WORK}/forensics"
cp "${MNT}/etc/passwd" "${WORK}/forensics/passwd"          2>/dev/null || true
cp "${MNT}/etc/group"  "${WORK}/forensics/group"           2>/dev/null || true
ls -1 "${MNT}/System/Library/LaunchDaemons" > "${WORK}/forensics/LaunchDaemons.original.txt" 2>/dev/null || true
# BSD/macOS xargs has no GNU '-r'; sed is portable and handles empty input cleanly.
find "${MNT}/System/Library/LaunchDaemons" -maxdepth 1 -name '*.plist' -print 2>/dev/null \
    | sed 's#.*/##' | sort > "${WORK}/forensics/launchdaemons_plists.txt" || true
# U5: are amfid / secinitd / sandboxd present as daemons in the stock ramdisk?
grep -iE 'amfid|secinitd|sandboxd' "${WORK}/forensics/launchdaemons_plists.txt" \
    > "${WORK}/forensics/userland_sandbox_daemons.txt" || true
# A4/U4: does 'mobile' already exist in passwd?
grep -E '^mobile:' "${WORK}/forensics/passwd" > "${WORK}/forensics/mobile_entry.txt" || true

echo "=== [4/9] replace LaunchDaemons (keep the original for later analysis) ==="
LD="${MNT}/System/Library/LaunchDaemons"
if [[ -d "${MNT}/System/Library/LaunchDaemons.old" ]]; then
    echo "already patched - refusing to patch twice"
    exit 1
fi
mv "${LD}" "${MNT}/System/Library/LaunchDaemons.old"
mkdir -p "${LD}"
cp "${ROOT}/tools/launchdaemons/com.vios.root.plist" "${LD}/"
cp "${ROOT}/tools/launchdaemons/com.vios.user.plist" "${LD}/"
# Upstream reference job: root bash on uart0 (/dev/console) = R0 manual fallback.
cp "${ROOT}/qemu/darwin-vm/launchdaemons/com.jprx.bash.plist" "${LD}/" 2>/dev/null || true
chmod 644 "${LD}"/*.plist
sudo chown root:wheel "${LD}"/*.plist 2>/dev/null || true

echo "=== [5/9] layout: /vios/* and App container paths (P1 sandbox path match) ==="
mkdir -p "${MNT}/vios/root" "${MNT}/vios/out" "${MNT}/vios/probes" "${MNT}/vios/logs"
mkdir -p "${MNT}/var/containers/Bundle/Application/00000000-0000-0000-0000-000000000000"
mkdir -p "${MNT}/var/mobile/Containers/Data/Application/00000000-0000-0000-0000-000000000000"
# /vios/out is writable by the U (mobile) shell; everything else stays root.
sudo chown -R 501:501 "${MNT}/vios/out" 2>/dev/null || true
chmod 0777 "${MNT}/vios/out"
sudo chown -R root:wheel "${MNT}/vios/root" "${MNT}/vios/probes" 2>/dev/null || true

echo "=== [6/9] unpack upstream arm64e sysroot (bash / coreutils / dropbear) ==="
tar xzf "${ROOT}/qemu/darwin-vm/sysroot/ios_sysroot.tar.gz" \
    --directory "${MNT}" --strip-components 1

# Optional prebuilt sandbox probe (only if it has been cross-compiled already).
if [[ -f "${ROOT}/tools/bin/vios_sandbox_probe" ]]; then
    cp "${ROOT}/tools/bin/vios_sandbox_probe" \
       "${MNT}/var/containers/Bundle/Application/00000000-0000-0000-0000-000000000000/"
    cp "${ROOT}/tools/bin/vios_sandbox_probe" "${MNT}/vios/probes/"
fi

echo "=== [7/9] non-interactive permission fix + ad-hoc codesign ==="
# NOTE: do NOT call upstream fix_perms.sh - it has an interactive read -p and hangs CI.
sudo chown -R root:wheel "${MNT}/bin" "${MNT}/sbin" "${MNT}/libexec" "${MNT}/System" 2>/dev/null || true
find "${MNT}/bin" "${MNT}/sbin" "${MNT}/libexec" "${MNT}/vios/probes" \
     -type f -perm +111 -exec codesign -s - -f {} \; 2>/dev/null || true
if [[ -d "${MNT}/var/containers/Bundle/Application/00000000-0000-0000-0000-000000000000" ]]; then
    find "${MNT}/var/containers/Bundle/Application/00000000-0000-0000-0000-000000000000" \
         -type f -perm +111 -exec codesign -s - -f {} \; 2>/dev/null || true
fi

echo "=== [8/9] collect cdhash and build trustcache ==="
# Match upstream get_files.sh: cut on '=' (case-insensitive CDHash= vs cdhash=),
# cover arm64e.x1 too, and keep ONLY 40-hex SHA1 CDHashes - build_tc.py stores
# 20-byte CDHash entries (hashType=2) and asserts len==40.
find "${MNT}" -type f -perm +111 \
    \( -exec codesign -a arm64      -d -vvv {} \; -o -true \) \
    \( -exec codesign -a arm64e     -d -vvv {} \; -o -true \) \
    \( -exec codesign -a arm64e.x1  -d -vvv {} \; -o -true \) \
    2>&1 | grep -i 'cdhash=' | cut -d= -f2- | tr -d ' ' \
         | grep -E '^[0-9a-fA-F]{40}$' | sort -u > "${OUT}/all_hashes" || true
NUM="$(wc -l < "${OUT}/all_hashes" | tr -d ' ')"
echo "cdhash entries: ${NUM}"
[[ "${NUM}" -gt 100 ]] || { echo "ERROR: cdhash collection looks broken"; exit 1; }
python3 "${ROOT}/qemu/darwin-vm/build_tc.py" "${OUT}/all_hashes" "${OUT}/ramdisk.tc"
python3 - "${OUT}/ramdisk.tc" <<'PY'
import struct, sys
d = open(sys.argv[1], "rb").read()
ver, _, n = struct.unpack_from("<I16sI", d, 0)
assert ver == 1 and 24 + 22 * n == len(d), "bad trustcache"
print("trustcache OK: version=%d entries=%d bytes=%d" % (ver, n, len(d)))
PY

echo "=== [9/9] report + detach ==="
python3 - "${WORK}/forensics" "${OUT}" "${ROOT}" <<'PY'
import json, os, sys, hashlib
fdir, out, root = sys.argv[1:4]
def read(name):
    p = os.path.join(fdir, name)
    return open(p, "r", errors="replace").read() if os.path.isfile(p) else None
passwd = read("passwd") or ""
r = {
  "stage": "macos-ramdisk-patch",
  "a4_passwd_has_mobile": any(l.startswith("mobile:") for l in passwd.splitlines()),
  "a4_mobile_entry": read("mobile_entry.txt"),
  "u5_userland_sandbox_daemons": (read("userland_sandbox_daemons.txt") or "").split(),
  "launchdaemons_original_count": len((read("LaunchDaemons.original.txt") or "").split()),
  "passwd_sha256": hashlib.sha256(passwd.encode()).hexdigest()[:16],
  "outputs": {},
  "notes": [
    "ramdisk.vios.dmg is a RAW APFS image (NXSB @0x20); QEMU -ramdisk mmaps it verbatim.",
    "ramdisk.tc must be passed via -tc at boot; trustcache cannot be appended at runtime.",
    "sandbox_enforced stays FALSE until S5 A/B control passes on the live VM.",
  ],
}
for f in ("ramdisk.vios.dmg", "ramdisk.tc", "all_hashes"):
    p = os.path.join(out, f)
    if os.path.isfile(p):
        r["outputs"][f] = {
            "size": os.path.getsize(p),
            "sha256": hashlib.sha256(open(p, "rb").read()).hexdigest(),
        }
open(os.path.join(out, "report.json"), "w").write(json.dumps(r, indent=2, ensure_ascii=False))
print(json.dumps({k: v for k, v in r.items() if k != "notes"}, indent=2, ensure_ascii=False))
PY

hdiutil detach "${MNT}" -force >/dev/null 2>&1 || hdiutil detach "${MNT}"
trap - EXIT
rmdir "${MNT}" 2>/dev/null || true
rm -rf "${WORK}"

echo "=== DONE ==="
ls -lh "${OUT}"

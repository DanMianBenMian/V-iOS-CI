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
# Explicitly record whether /etc/passwd exists at all. sha256("") in the report
# means "file missing", NOT "passwd exists but has no mobile entry".
if [[ -f "${MNT}/etc/passwd" ]]; then
    echo "present" > "${WORK}/forensics/passwd_exists.txt"
else
    echo "absent" > "${WORK}/forensics/passwd_exists.txt"
fi
ls -la "${MNT}/etc" > "${WORK}/forensics/etc_listing.txt" 2>/dev/null || true
# iOS stores users in dslocal, not /etc/passwd. Inventory it for A4.
find "${MNT}/var/db/dslocal" -maxdepth 6 -print 2>/dev/null \
    | head -100 > "${WORK}/forensics/dslocal_listing.txt" || true
ls -1 "${MNT}/System/Library/LaunchDaemons" > "${WORK}/forensics/LaunchDaemons.original.txt" 2>/dev/null || true
# BSD/macOS xargs has no GNU '-r'; sed is portable and handles empty input cleanly.
find "${MNT}/System/Library/LaunchDaemons" -maxdepth 1 -name '*.plist' -print 2>/dev/null \
    | sed 's#.*/##' | sort > "${WORK}/forensics/launchdaemons_plists.txt" || true
# U5: are amfid / secinitd / sandboxd present as daemons in the stock ramdisk?
grep -iE 'amfid|secinitd|sandboxd' "${WORK}/forensics/launchdaemons_plists.txt" \
    > "${WORK}/forensics/userland_sandbox_daemons.txt" || true
# A4/U4: does 'mobile' already exist in passwd?
grep -E '^mobile:' "${WORK}/forensics/passwd" > "${WORK}/forensics/mobile_entry.txt" || true

echo "=== [4/9] preserve original LaunchDaemons + append R/U research shells ==="
LD="${MNT}/System/Library/LaunchDaemons"
if [[ -d "${MNT}/System/Library/LaunchDaemons.orig" ]]; then
    echo "already patched - refusing to patch twice"
    exit 1
fi
# RESEARCH FIDELITY: the restore ramdisk must boot into a restore environment
# that is near-identical to a normal running system, only missing the GUI/
# SpringBoard (headless). The previous 'mv LaunchDaemons away' step stripped ALL
# 10 stock Apple daemons (restored_external, syslogd, diskimagesiod, driverkitd,
# the camera daemons, ...) which gutted the native environment and reduced the
# VM to a bare shell. Instead we KEEP the stock daemon set in place (back it up
# to LaunchDaemons.orig for forensics) and APPEND our two research shells, so the
# VM boots a complete restore environment AND keeps R/U dual-shell access.
cp -a "${LD}" "${MNT}/System/Library/LaunchDaemons.orig"
cp "${ROOT}/tools/launchdaemons/com.vios.root.plist" "${LD}/"
cp "${ROOT}/tools/launchdaemons/com.vios.user.plist" "${LD}/"
# NOTE: deliberately NOT copying qemu/darwin-vm/launchdaemons/com.jprx.bash.plist.
# H17 root cause: a root bash that binds a qemuport via socat never reads host
# input, and (with KeepAlive) its respawn loop floods the serial driver and trips
# an sptm kernel panic that kills BOTH shells. The R shell is com.vios.root on
# uart0 (/dev/console) = R0, so a second uart0 job (com.jprx.bash) would collide.
# Keep exactly ONE root bash on uart0 (com.vios.root) + the U shell on qemuport1.
# NOTE: do NOT chown here. The volume was attached with '-owners off', so chown
# is silently ineffective. Ownership is fixed in step [9/9] after re-attaching
# with '-owners on' (this is exactly what upstream fix_perms.sh does).

echo "--- B-plan fallback: inject a minimal passwd/group so UserName=mobile can resolve ---"
# The stock restore ramdisk has NO /etc/passwd at all (runner forensics:
# passwd_sha256 == sha256("") and 'passwd: No such file'). iOS normally uses
# /var/db/dslocal, but writing a 2-line passwd is harmless and gives getpwnam()
# a deterministic answer. Final chown/chmod happens in [9/9].
mkdir -p "${MNT}/etc"
cat > "${MNT}/etc/passwd" <<'EOF'
root:*:0:0:System Administrator:/var/root:/bin/sh
mobile:*:501:501:Mobile User:/var/mobile:/bin/sh
EOF
cat > "${MNT}/etc/group" <<'EOF'
wheel:*:0:root
mobile:*:501:mobile
EOF
chmod 644 "${MNT}/etc/passwd" "${MNT}/etc/group"

echo "=== [5/9] layout: /vios/* and App container paths (P1 sandbox path match) ==="
mkdir -p "${MNT}/vios/root" "${MNT}/vios/out" "${MNT}/vios/probes" "${MNT}/vios/logs"
mkdir -p "${MNT}/var/containers/Bundle/Application/00000000-0000-0000-0000-000000000000"
mkdir -p "${MNT}/var/mobile/Containers/Data/Application/00000000-0000-0000-0000-000000000000"

echo "--- shell bridge: exec the TRUSTED Mach-O /bin/bash directly ---"
# We do NOT use a wrapper script. iOS/AMFI denies `process-exec-interpreter
# /bin/bash` for an untrusted script (the script itself is not in the
# trustcache), so a /vios/loop.sh wrapper silently fails to start a shell.
# Instead the plist does `socat EXEC:/bin/bash,pty,echo=0,stderr`, and the host
# relay (vios_relay.py) holds a PERMANENT connection to each qemuport chardev
# (H14), so bash never receives EOF and stays alive for the VM's lifetime.
# /bin/bash is already in the trustcache (479 entries) and is proven to run
# host commands.
# /vios/out is writable by the U (mobile) shell; everything else stays root.
sudo chown -R 501:501 "${MNT}/vios/out" 2>/dev/null || true
chmod 0777 "${MNT}/vios/out"
sudo chown -R root:wheel "${MNT}/vios/root" "${MNT}/vios/probes" 2>/dev/null || true

echo "=== [6/9] compile guest sandbox probe (if .c present) + unpack arm64e sysroot ==="
# Best-effort cross-compile of the native Seatbelt probe. Only runs on a macOS
# runner with Xcode command-line tools + the iOS SDK (xcrun --sdk iphoneos).
# If the source is absent or the toolchain is missing, we skip it gracefully:
# the ramdisk simply ships without the native probe (S1/S3/S4 stay deferred),
# and the JS-level probes still report an honest 'absent' verdict.
PROBE_SRC="${ROOT}/tools/vios_sandbox_probe.c"
PROBE_BIN="${ROOT}/tools/bin/vios_sandbox_probe"
mkdir -p "${ROOT}/tools/bin"
if [[ -f "${PROBE_SRC}" ]]; then
    if command -v xcrun >/dev/null 2>&1 && xcrun --sdk iphoneos --show-sdk-path >/dev/null 2>&1; then
        echo "--- compiling vios_sandbox_probe (arm64e, fptrauth-calls, iphoneos SDK) ---"
        if xcrun --sdk iphoneos clang -arch arm64e -fptrauth-calls \
                 -isysroot "$(xcrun --sdk iphoneos --show-sdk-path)" \
                 -o "${PROBE_BIN}" "${PROBE_SRC}" 2>/tmp/vios_probe_build.log; then
            codesign -s - -f "${PROBE_BIN}" 2>/dev/null || true
            echo "compiled + ad-hoc signed: ${PROBE_BIN}"
        else
            echo "WARN: vios_sandbox_probe compile failed (see /tmp/vios_probe_build.log)"
            echo "--- build log ---"; tail -n 20 /tmp/vios_probe_build.log || true
        fi
    else
        echo "WARN: xcrun/iphoneos SDK not available - skipping native probe compile"
    fi
else
    echo "no vios_sandbox_probe.c - skipping native probe compile"
fi

tar xzf "${ROOT}/qemu/darwin-vm/sysroot/ios_sysroot.tar.gz" \
    --directory "${MNT}" --strip-components 1

# Inject the native sandbox probe if it exists (compiled above, or prebuilt).
if [[ -f "${PROBE_BIN}" ]]; then
    cp "${PROBE_BIN}" \
       "${MNT}/var/containers/Bundle/Application/00000000-0000-0000-0000-000000000000/"
    cp "${PROBE_BIN}" "${MNT}/vios/probes/"
    echo "native sandbox probe injected into ramdisk"
else
    echo "native sandbox probe NOT injected (binary absent - S1/S3/S4 deferred)"
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

echo "=== [9/9] re-attach with owners ON and fix ownership ==="
# launchd refuses LaunchDaemons plists unless they are root:wheel AND 0644
# (boot log: "error = 122: Path had bad ownership/permissions").
# The first mount used '-owners off' for easy writing; ownership is only
# meaningful after re-attaching with '-owners on' (upstream fix_perms.sh).
hdiutil detach "${MNT}" -force >/dev/null 2>&1 || true
hdiutil attach -owners on -mountpoint "${MNT}" "${OUT}/ramdisk.vios.dmg" >/dev/null
LD="${MNT}/System/Library/LaunchDaemons"
sudo chown -R root:wheel "${MNT}/System" "${MNT}/bin" "${MNT}/sbin" \
     "${MNT}/libexec" "${MNT}/vios" "${MNT}/etc" 2>/dev/null || true
sudo chown root:wheel "${LD}"/*.plist "${MNT}/etc/passwd" "${MNT}/etc/group"
sudo chmod 644 "${LD}"/*.plist "${MNT}/etc/passwd" "${MNT}/etc/group"
sudo chmod 755 "${LD}" "${MNT}/System/Library" "${MNT}/etc"
echo "--- ownership self-check (launchd requires root:wheel + 0644) ---"
stat -f '%Su:%Sg %Sp %N' "${LD}"/*.plist "${MNT}/System/Library/LaunchDaemons" \
     "${MNT}/etc/passwd" "${MNT}/etc/group"
python3 - "${LD}" <<'PY'
import os, stat, sys
ld = sys.argv[1]
bad = []
for n in sorted(os.listdir(ld)):
    if not n.endswith(".plist"):
        continue
    p = os.path.join(ld, n)
    st = os.stat(p)
    mode = stat.S_IMODE(st.st_mode)
    if st.st_uid != 0 or st.st_gid != 0 or mode != 0o644:
        bad.append((n, st.st_uid, st.st_gid, oct(mode)))
print("plist ownership check:", "ALL OK" if not bad else "FAILED %r" % bad)
if bad:
    sys.exit(1)
PY

echo "=== [9b/9] report + detach ==="
python3 - "${WORK}/forensics" "${OUT}" "${ROOT}" <<'PY'
import json, os, sys, hashlib
fdir, out, root = sys.argv[1:4]
def read(name):
    p = os.path.join(fdir, name)
    return open(p, "r", errors="replace").read() if os.path.isfile(p) else None
passwd = read("passwd") or ""
etc_listing = read("etc_listing.txt") or ""
dslocal = (read("dslocal_listing.txt") or "").splitlines()
r = {
  "stage": "macos-ramdisk-patch",
  "a4_passwd_exists": (read("passwd_exists.txt") or "unknown").strip(),
  "a4_passwd_has_mobile": any(l.startswith("mobile:") for l in passwd.splitlines()),
  "a4_mobile_entry": read("mobile_entry.txt"),
  "a4_bplan_passwd_injected": True,
  "u4_dslocal_paths_sample": dslocal[:30],
  "u4_etc_listing": etc_listing.splitlines()[:30],
  "u5_userland_sandbox_daemons": (read("userland_sandbox_daemons.txt") or "").split(),
  "launchdaemons_original_count": len((read("LaunchDaemons.original.txt") or "").split()),
  "launchdaemons_original_names": (read("launchdaemons_plists.txt") or "").split(),
  "plist_ownership_fixed": "owners on re-attach + root:wheel 0644",
  "passwd_sha256": hashlib.sha256(passwd.encode()).hexdigest()[:16],
  "outputs": {},
  "notes": [
    "ramdisk.vios.dmg is a RAW APFS image (NXSB @0x20); QEMU -ramdisk mmaps it verbatim.",
    "ramdisk.tc must be passed via -tc at boot; trustcache cannot be appended at runtime.",
    "sandbox_enforced stays FALSE until S5 A/B control passes on the live VM.",
    "RESEARCH FIDELITY: stock LaunchDaemons are PRESERVED (backed up to LaunchDaemons.orig) and kept in place; com.vios.root (uart0) + com.vios.user (qemuport1) are APPENDED. The VM now boots a near-complete restore environment (only GUI/SpringBoard absent) plus the R/U dual-shell.",
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

# IMPORTANT: the report above was written BEFORE detach. hdiutil flushes APFS
# metadata when detaching, so the on-disk image hash changes. Recompute it now
# and mark the original as a pre-detach snapshot - otherwise the report's sha256
# will never match the artifact and looks like corruption.
python3 - "${OUT}" <<'PY'
import hashlib, json, os, sys
out = sys.argv[1]
p = os.path.join(out, "ramdisk.vios.dmg")
rpath = os.path.join(out, "report.json")
h = hashlib.sha256(open(p, "rb").read()).hexdigest()
r = json.load(open(rpath))
prev = r.get("outputs", {}).get("ramdisk.vios.dmg", {}).get("sha256")
r.setdefault("outputs", {}).setdefault("ramdisk.vios.dmg", {})["sha256_pre_detach"] = prev
r["outputs"]["ramdisk.vios.dmg"]["sha256"] = h
r["outputs"]["ramdisk.vios.dmg"]["sha256_is_post_detach"] = True
open(rpath, "w").write(json.dumps(r, indent=2, ensure_ascii=False))
print("post-detach ramdisk sha256:", h)
PY

echo "=== DONE ==="
ls -lh "${OUT}"

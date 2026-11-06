# V-iOS CI (public runner)

Builds the V-iOS dual-shell target ramdisk on a macOS GitHub Actions runner.

**This repository contains NO Apple firmware.** It holds only scripts, launchd
plists, `build_tc.py` and the open-source arm64e sysroot from `jprx/darwin-vm`.
The runner downloads the 230 MB RestoreRamDisk itself from Apple's CDN using HTTP
Range requests (`ipsw extract --remote`), patches it, and returns the result as an
**AES-encrypted artifact with a one-time key**. Download, decrypt, delete the
artifact immediately.

Public repo = free Actions minutes (no quota burn). See
`.github/workflows/ramdisk-patch.yml` for the full pipeline.

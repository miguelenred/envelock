#!/usr/bin/env bash
# Build the Envelock assistant into one self-contained window executable for the CURRENT OS.
# PyInstaller does not cross-compile: run this on Linux for the Linux build and on macOS for the
# macOS build. The Windows .exe is built on Windows, or here under Wine with a Windows Python
# (see docs/BUILDING.md). cryptography comes from prebuilt/python-wheels (offline) when this
# system has a folder there, otherwise from PyPI checked against requirements.lock; PyInstaller
# (a build tool, not shipped in the repo) is pinned.
#
# Usage: bash scripts/build-gui.sh [python]
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
py="${1:-python3}"

"$py" -c 'import tkinter' 2>/dev/null || {
  echo "This Python has no Tkinter. Install it (e.g. 'apt install python3-tk', or use the" >&2
  echo "official python.org build on Windows/macOS, which already includes it)." >&2
  exit 2
}
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) wheels=linux_x86_64 ;;
  Linux-aarch64) wheels=linux_aarch64 ;;
  Darwin-arm64) wheels=macos_arm64 ;;
  *) wheels="" ;;
esac
# The Linux wheels are for glibc; on musl (e.g. Alpine) use the lock instead. Source checkouts
# may not contain prebuilt wheels at all, even for a supported OS; do not try an absent folder.
if [ "$(uname -s)" = Linux ] && ldd --version 2>&1 | grep -qi musl; then wheels=""; fi
if [ -n "$wheels" ] && [ ! -d "$root/prebuilt/python-wheels/$wheels" ]; then
  echo "No bundled wheels for $wheels; using the hash-locked requirements instead." >&2
  wheels=""
fi
if [ -n "$wheels" ]; then
  # Install only wheels whose hashes match prebuilt/SHA256SUMS.
  "$py" - "$root" "$wheels" <<'PY'
import hashlib, sys
from pathlib import Path
root, folder = Path(sys.argv[1]), sys.argv[2]
sums = dict(reversed(line.split("  ", 1)) for line in (root / "prebuilt/SHA256SUMS").read_text().splitlines())
for wheel in (root / "prebuilt/python-wheels" / folder).iterdir():
    if sums.get(f"python-wheels/{folder}/{wheel.name}") != hashlib.sha256(wheel.read_bytes()).hexdigest():
        sys.exit(f"{wheel}: not listed in prebuilt/SHA256SUMS or hash differs; refusing to install")
PY
  "$py" -m pip install --quiet --no-index --find-links "$root/prebuilt/python-wheels/$wheels" cryptography==50.0.2
else
  "$py" -m pip install --quiet --require-hashes -r "$root/requirements.lock"
fi
# PyInstaller is a build tool (not shipped). Install it with pinned hashes when a per-OS lock is
# present, so the executable that will carry your signing keys is not built with a tampered build
# tool (ENV-AUD-16). Generate the lock on each OS with:
#   pip download pyinstaller==6.22.3 -d /tmp/pi && \
#   (cd /tmp/pi && for f in *; do printf '%s \\\n    --hash=sha256:%s\n' \
#     "${f%%-*}==<ver>" "$(sha256sum "$f" | cut -d' ' -f1)"; done) > scripts/pyinstaller-<os>.lock
# (or: pip-compile --generate-hashes). The lock is per-OS/arch because PyInstaller ships platform
# wheels; it is optional, and its absence only drops hash verification of the build tool.
pi_lock="$root/scripts/pyinstaller-$(uname -s)-$(uname -m).lock"
if [ -f "$pi_lock" ]; then
  "$py" -m pip install --quiet --require-hashes -r "$pi_lock"
else
  echo "WARNING: $pi_lock not found; installing PyInstaller==6.22.3 WITHOUT hash verification." >&2
  echo "         PyInstaller's code goes into the executable, and the assistant handles your owner and" >&2
  echo "         recipient private keys and their passwords: a tampered build tool could leak them." >&2
  echo "         Create the lock (see the comment above) before building an assistant for real keys." >&2
  "$py" -m pip install --quiet pyinstaller==6.22.3
fi
cd "$root"
rm -rf "build/gui-$(uname -s)" "dist"
"$py" -m PyInstaller --clean --noconfirm \
  --distpath dist --workpath "build/gui-$(uname -s)" gui/envelock-assistant.spec
echo "Built: $root/dist/envelock-assistant (run it; it needs no Python installed)."

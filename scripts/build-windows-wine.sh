#!/usr/bin/env bash
# Build php_envelock.dll for Windows x64 from Linux, with Microsoft's own compiler (MSVC) run
# under Wine. The DLL is generic (no keys), like every Envelock loader. Inputs (see
# docs/BUILDING.md, "Windows loader from Linux"):
#   MSVC      folder lib/native of the VisualCppTools.Community.VS2017Layout NuGet package
#   WINSDK    folder c/ of the Microsoft.Windows.SDK.CPP NuGet package (headers)
#   WINSDK64  folder c/ of the Microsoft.Windows.SDK.CPP.x64 NuGet package (libraries)
#   OPENSSL   OpenSSL 3.x include folder configured for Windows x64
#   PHPDEV    extracted php-devel-pack-<version>[-nts]-Win32-<vs>-x64 folder
#   PHPZIP    extracted PHP for Windows of the same version and thread safety (for libcrypto)
# Usage: bash scripts/build-windows-wine.sh <nts|ts> <output .dll>
set -euo pipefail
# Defense in depth (ENV-2026-02): the bytecode emit/run surface is never compiled into a server DLL.
unset ENVELOCK_BCPOC ENVELOCK_BCEMIT ENVELOCK_BCRUN 2>/dev/null || true
if [ "$#" -ne 2 ] || { [ "$1" != nts ] && [ "$1" != ts ]; }; then
  echo "Usage: MSVC=... WINSDK=... WINSDK64=... OPENSSL=... PHPDEV=... PHPZIP=... \\" >&2
  echo "       bash scripts/build-windows-wine.sh <nts|ts> <output .dll>" >&2
  exit 2
fi
: "${MSVC:?}" "${WINSDK:?}" "${WINSDK64:?}" "${OPENSSL:?}" "${PHPDEV:?}" "${PHPZIP:?}"
# The requested thread safety must be the one of the devel pack and of the PHP zip: a DLL compiled
# with /D ZTS=1 against php8.lib (or without it against php8ts.lib) builds, then fails to load
# (or worse) on the server. The import library of the devel pack (php8ts.lib / php8.lib) and the
# engine DLL of the PHP zip (php8ts.dll / php8.dll) say which one they are.
case "$1" in
  ts)  want_lib=php8ts.lib; want_dll=php8ts.dll ;;
  nts) want_lib=php8.lib;   want_dll=php8.dll ;;
esac
if [ ! -f "$PHPDEV/lib/$want_lib" ] || [ ! -f "$PHPZIP/$want_dll" ]; then
  echo "Thread-safety mismatch: '$1' was asked, but PHPDEV has $(ls "$PHPDEV/lib" 2>/dev/null | grep -E '^php8(ts)?\.lib$' | tr '\n' ' ')and PHPZIP has $(ls "$PHPZIP" 2>/dev/null | grep -E '^php8(ts)?\.dll$' | tr '\n' ' ')." >&2
  echo "Use the $1 devel pack and the $1 PHP zip of the same version." >&2
  exit 2
fi
root="$(cd "$(dirname "$0")/.." && pwd)"
output="$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$2")"
[ -e "$output" ] && { echo "Refusing to overwrite: $output" >&2; exit 1; }
win() { printf 'Z:%s' "$(cd "$1" && pwd)"; }           # Linux folder -> Wine path
sdkinc="$(win "$WINSDK")/Include/$(ls "$WINSDK/Include" | grep -m1 '^10\.')"
msvc="$(win "$MSVC")"
export WINEDEBUG=-all
export INCLUDE="$msvc/include;$sdkinc/ucrt;$sdkinc/um;$sdkinc/shared"
export LIB="$msvc/lib/x64;$(win "$WINSDK64")/ucrt/x64;$(win "$WINSDK64")/um/x64"
# Wine needs a terminal for console tools; the output of the last tool is kept in tool.log.
run() { script -qefc "wine $msvc/bin/Hostx64/x64/$*" /dev/null > tool.log 2>&1 || true; }
fail() {
  echo "$1:" >&2
  tr -d '\r' < tool.log | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' | grep -iE 'error|unresolved|cannot' >&2 || true
  exit 1
}
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
cp "$root"/extension/envelock*.c "$root"/extension/envelock*.h "$root"/extension/php_envelock.h "$scratch/"
cp -R "$root"/extension/opcache "$scratch/opcache"
cd "$scratch"
# Per-version bytecode layer (objective O1), mirroring config.m4/config.w32: detect the PHP minor
# from the devel pack and compile the matching opcache/php<MM>/ layer if it exists; otherwise a
# source-only loader (FLAG_BYTECODE refused at run time). ENVELOCK_BCPOC=1 adds the pack/test-only
# bc_emit/bc_run functions (NEVER build a server DLL with it).
mm="$(awk '/define PHP_MAJOR_VERSION/{maj=$3} /define PHP_MINOR_VERSION/{min=$3} END{print "php" maj min}' "$PHPDEV/include/main/php_version.h")"
core="envelock.c envelock_crypto.c envelock_file.c envelock_secret.c envelock_integrity.c envelock_licence.c envelock_clock.c envelock_trusted_time.c envelock_vm.c"
# Per-version bytecode layer (objective O1): compile the matching opcache/php<MM>/ layer when it
# exists (now Windows-portable too), otherwise a source-only loader (FLAG_BYTECODE refused at run
# time). ENVELOCK_BCPOC=1 adds the pack/test-only bc_emit/bc_run functions (NEVER ship a server DLL
# with it).
have_bc=0; bc_src=""; bc_inc=""
# ENV-2026-03: the bytecode layer is not thread-safe, so a TS (thread-safe) DLL is built source-only.
# A ZTS build that included the layer would hit the #error in envelock_accel_shim.h.
if [ "$1" = ts ]; then
  echo "note: thread-safe (ts) build is source-only; the bytecode layer is not ZTS-safe (ENV-2026-03)" >&2
elif [ -f "$scratch/opcache/$mm/envelock_bc.c" ]; then
  have_bc=1
  bc_src="envelock_bcpoc.c opcache/$mm/envelock_arena.c opcache/$mm/envelock_bc.c opcache/$mm/envelock_persist.c opcache/$mm/envelock_file_cache.c opcache/$mm/envelock_script.c"
  bc_inc="/I opcache/$mm"
else
  echo "warning: no bytecode layer for $mm; source-only DLL" >&2
fi
# The pack/test-only bytecode emit/run surface is NEVER compiled into a distributed Windows DLL
# (ENV-2026-02): this script builds server loaders only and passes no such define. The emitter, when
# needed for packing, is built on the developer's own platform with --enable-envelock-bcemit.
bcpoc=""
# Import library for the libcrypto DLL that this PHP ships (OpenSSL 3.x keeps its ABI).
cp "$PHPZIP/libcrypto-3-x64.dll" .
run "dumpbin.exe /nologo /exports /out:exports.txt libcrypto-3-x64.dll"
python3 - <<'PY'
import re
names = [m.group(1) for line in open("exports.txt", errors="replace")
         if (m := re.match(r"\s+\d+\s+[0-9A-F]+\s+[0-9A-F]{8}\s+(\S+)", line))]
if len(names) < 1000:
    raise SystemExit("libcrypto exports not found")
open("libcrypto.def", "w").write("LIBRARY libcrypto-3-x64.dll\nEXPORTS\n" + "".join(f"    {n}\n" for n in names))
PY
run "lib.exe /nologo /def:libcrypto.def /machine:x64 /out:libcrypto.lib"
[ -f libcrypto.lib ] || fail "Import library failed"
dev="$(win "$PHPDEV")"
phplib="$want_lib"                    # checked against the devel pack at the top
zts=""
[ "$1" = ts ] && zts="/D ZTS=1"
# The flags PHP's own build system (confutils.js) uses for a release extension, with the
# security flags /guard:cf; the C sources need nothing newer than this compiler.
run "cl.exe /nologo /c /I . $bc_inc /I $dev/include /I $dev/include/main /I $dev/include/Zend \
  /I $dev/include/TSRM /I $dev/include/ext /I $(win "$OPENSSL") /D _WINDOWS /D WINDOWS=1 \
  /D ZEND_WIN32=1 /D PHP_WIN32=1 /D WIN32 /D _MBCS /D _USE_MATH_DEFINES /FD /wd4996 /guard:cf \
  /Zc:inline /Zc:wchar_t /LD /MD /Ox /D NDebug /D NDEBUG /GF /D ZEND_DEBUG=0 $zts \
  /D ZEND_COMPILE_DL_EXT=1 /D COMPILE_DL_ENVELOCK /D ENVELOCK_EXPORTS=1 \
  /D ENVELOCK_HAVE_BYTECODE=$have_bc $bcpoc /W3 \
  $core $bc_src"
[ -f envelock.obj ] && [ -f envelock_crypto.obj ] && [ -f envelock_vm.obj ] || fail "Compilation failed"
run "link.exe /nologo /dll /out:php_envelock.dll *.obj \
  $dev/lib/$phplib libcrypto.lib advapi32.lib kernel32.lib /guard:cf /DYNAMICBASE /NXCOMPAT \
  /HIGHENTROPYVA /CETCOMPAT /RELEASE /OPT:REF /OPT:ICF"
[ -f php_envelock.dll ] || fail "Link failed"
mkdir -p "$(dirname "$output")"
cp php_envelock.dll "$output"
echo "Built: $output"

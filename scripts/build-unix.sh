#!/usr/bin/env bash
# Native Linux/macOS build. The module is GENERIC: it embeds no keys. Per-server keys
# live in the identity file named by the envelock.identity php.ini directive (see MANUAL).
set -euo pipefail
umask 077
# Defense in depth (ENV-2026-02): never let an inherited variable pull the bytecode emit/run surface
# into a server loader. config.m4 no longer reads ENVELOCK_BCPOC, and this build passes none of the
# --enable-envelock-bc* flags, but clear them so nothing downstream can either.
unset ENVELOCK_BCPOC ENVELOCK_BCEMIT ENVELOCK_BCRUN 2>/dev/null || true
if [ "$#" -ne 1 ]; then
  echo "Usage: bash scripts/build-unix.sh release/envelock.so" >&2
  exit 2
fi
root="$(cd "$(dirname "$0")/.." && pwd)"
output="$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$1")"
phpizebin="${PHPIZE:-phpize}"
phpconfig="${PHP_CONFIG:-php-config}"
# Load-test with the PHP that matches php-config (same module API), unless PHP is given.
phpbin="${PHP:-$("$phpconfig" --php-binary)}"
if [ -e "$output" ]; then echo "Refusing to overwrite: $output" >&2; exit 1; fi
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
# Every top-level source and header, not a hand-kept list: this list drifted once already when
# envelock_secret.* was added, and a build that copies stale sources fails in a confusing place.
# config.m4's PHP_NEW_EXTENSION remains the authority on what is actually compiled.
for file in "$root"/extension/*.c "$root"/extension/*.h "$root"/extension/config.m4; do
  cp "$file" "$scratch/"
done
# O1 bytecode layer: vendored, per PHP version (config.m4 picks the directory).
cp -R "$root/extension/opcache" "$scratch/opcache"
# -Wformat is required for -Werror=format-security: GCC >= 14 makes "format-security without
# -Wformat" a hard error (it was silently ignored before), which aborted the hardened build and
# silently fell back to an unhardened module. -Wformat is harmless on older compilers.
# _FORTIFY_SOURCE=3 where the compiler and C library support it (GCC 12+ or Clang 9+ with glibc
# 2.34+; elsewhere glibc warns "treated like 2"), else 2. -U first: recent toolchains (Ubuntu 24.04,
# Fedora) already default to 3, and a plain -D_FORTIFY_SOURCE=2 lowered it (with a redefinition warning).
fortify=2
# shellcheck disable=SC2086 # $CC may carry its own flags
if printf '#include <string.h>\nint main(void) { return 0; }\n' \
    | ${CC:-cc} -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -Werror -x c -c -o /dev/null - >/dev/null 2>&1; then
  fortify=3
fi
base_cflags="-O2 -fstack-protector-strong -fvisibility=hidden -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=$fortify -Wformat -Werror=format-security"
base_ldflags=""
if [ "$(uname -s)" = Linux ]; then
  base_ldflags="-Wl,-z,relro,-z,now,-z,noexecstack,-z,separate-code"
  base_cflags="$base_cflags -fstack-clash-protection"
  case "$(uname -m)" in
    x86_64|amd64) base_cflags="$base_cflags -fcf-protection=full" ;;  # Intel CET, x86-64 only
  esac
fi
# Portable Linux loader (HOST-2, docs/HOSTING.md §2.2). ENVELOCK_OPENSSL_STATIC=<prefix of an
# OpenSSL 3 built with no-shared and -fPIC> links OpenSSL into the module and keeps its symbols out
# of the dynamic table (--exclude-libs), so the module needs only the C library: not the system's
# libssl.so.3/libcrypto.so.3, which the RHEL 8 family lacks, and with nothing to clash with the
# OpenSSL the PHP process itself already uses. Built on an old C library (e.g. AlmaLinux 8, glibc
# 2.28), it then loads on every newer one. ENVELOCK_MAX_GLIBC=2.28 makes the build refuse a module
# that needs a newer glibc than that (a toolchain or header that crept forward).
if [ -n "${ENVELOCK_OPENSSL_STATIC:-}" ]; then
  osl_lib=""
  for d in lib64 lib; do
    if [ -f "$ENVELOCK_OPENSSL_STATIC/$d/libcrypto.a" ] && [ -f "$ENVELOCK_OPENSSL_STATIC/$d/libssl.a" ]; then
      osl_lib="$ENVELOCK_OPENSSL_STATIC/$d"
      break
    fi
  done
  if [ -z "$osl_lib" ]; then
    echo "ENVELOCK_OPENSSL_STATIC: no libssl.a/libcrypto.a under $ENVELOCK_OPENSSL_STATIC" >&2; exit 1
  fi
  if ls "$osl_lib"/libcrypto.so* >/dev/null 2>&1; then
    echo "ENVELOCK_OPENSSL_STATIC must be a no-shared OpenSSL build (found libcrypto.so in $osl_lib)" >&2; exit 1
  fi
  export PKG_CONFIG_PATH="$osl_lib/pkgconfig"
  export PKG_CONFIG="${PKG_CONFIG:-pkg-config} --static"
  base_ldflags="$base_ldflags -Wl,--exclude-libs,ALL"
fi
# Inherited CFLAGS/LDFLAGS FIRST, hardening LAST: with -f*/-D*/-z options the compiler and linker
# take the last occurrence, so the hardening must win over any conflicting inherited value (an
# inherited -fvisibility=default would otherwise re-export the envelock_* API; -D_FORTIFY_SOURCE=0
# or -z norelro would drop the other guarantees).
export LDFLAGS="${LDFLAGS:-} $base_ldflags"
(
  cd "$scratch"
  "$phpizebin"
  # -ffile-prefix-map: no temporary build path embedded in the binary (reproducible builds).
  CFLAGS="${CFLAGS:-} $base_cflags -ffile-prefix-map=$scratch=." \
    ./configure --enable-envelock --with-php-config="$(command -v "$phpconfig")"
  make -j"${ENVELOCK_JOBS:-2}"
)
module="$scratch/modules/envelock.so"
if command -v strip >/dev/null 2>&1; then
  case "$(uname -s)" in
    Darwin) strip -x "$module" ;;
    Linux) strip --strip-unneeded "$module" ;;
  esac
else
  echo "warning: strip not found; module ships with a full symbol table (names only, API stays hidden)" >&2
fi
# Post-build security gate. The production module must export ONLY get_module; it must never expose
# the envelock_* internals (the decrypt/key-unwrap API — M-01) or any bytecode emit/run symbol. The
# hardening is applied above but was never asserted, so any regression (an inherited flag, a stray
# export macro, a compiler that ignored -fvisibility) shipped silently. Fail closed if it did.
case "$(uname -s)" in
  Linux)  exported="$(nm -D --defined-only "$module" 2>/dev/null | awk '{print $NF}')" ;;
  Darwin) exported="$(nm -gU "$module" 2>/dev/null | awk '{print $NF}')" ;;
  *)      exported="" ;;
esac
if printf '%s\n' "$exported" | grep -Eq 'envelock_|bc_emit|bc_run'; then
  echo "SECURITY: module exports forbidden symbols (must export only get_module):" >&2
  printf '%s\n' "$exported" | grep -E 'envelock_|bc_emit|bc_run' >&2
  exit 1
fi
if [ -n "${ENVELOCK_OPENSSL_STATIC:-}" ]; then
  # The portable module must neither need the system OpenSSL nor export its own copy's symbols.
  if readelf -d "$module" | grep -E 'NEEDED.*(libssl|libcrypto)' >&2; then
    echo "PORTABILITY: the module still needs the system OpenSSL (ENVELOCK_OPENSSL_STATIC)" >&2; exit 1
  fi
  # __bss_start/_edata/_end: section markers older linkers (binutils 2.30, RHEL 8) put in the
  # dynamic table of every shared object; they carry no code.
  others="$(printf '%s\n' "$exported" | grep -Ev '^(get_module|_init|_fini|__bss_start|_edata|_end|)$' || true)"
  if [ -n "$others" ]; then
    echo "PORTABILITY: the module exports symbols other than get_module:" >&2
    printf '%s\n' "$others" | head -20 >&2; exit 1
  fi
fi
if [ -n "${ENVELOCK_MAX_GLIBC:-}" ] && [ "$(uname -s)" = Linux ]; then
  needed_glibc="$(readelf -V "$module" | grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' | sed 's/GLIBC_//' | sort -uV | tail -1)"
  if [ -n "$needed_glibc" ] && [ "$(printf '%s\n%s\n' "$needed_glibc" "$ENVELOCK_MAX_GLIBC" | sort -V | tail -1)" != "$ENVELOCK_MAX_GLIBC" ]; then
    echo "PORTABILITY: the module needs glibc $needed_glibc, newer than ENVELOCK_MAX_GLIBC=$ENVELOCK_MAX_GLIBC" >&2; exit 1
  fi
  printf 'glibc needed: %s (limit %s)\n' "${needed_glibc:-none}" "$ENVELOCK_MAX_GLIBC"
fi
"$phpbin" -n -d opcache.enable=0 -d opcache.enable_cli=0 -d extension="$module" --ri envelock
# Runtime exposure gate (ENV-2026-02). -fvisibility=hidden makes the PoC functions LOCAL symbols, so
# the nm -D check above cannot see them even when they are compiled into the module's function table
# and callable from userland PHP. Asking the loaded module whether the functions exist is the only
# reliable check. A server loader must expose NEITHER the emitter NOR the runner.
exposed="$("$phpbin" -n -d opcache.enable=0 -d opcache.enable_cli=0 -d extension="$module" -r \
  'echo (function_exists("envelock_bc_run") || function_exists("envelock_bc_emit")) ? "EXPOSED" : "ok";' 2>/dev/null)"
if [ "$exposed" != "ok" ]; then
  echo "SECURITY: this server loader exposes the bytecode emit/run surface (ENV-2026-02); refusing to ship it." >&2
  exit 1
fi
# Exclusive output creation: two builds cannot silently overwrite one another.
python3 - "$module" "$output" <<'PY'
import os,pathlib,shutil,sys
source, destination = map(pathlib.Path, sys.argv[1:])
destination.parent.mkdir(parents=True, exist_ok=True)
fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
try:
    with source.open('rb') as src, os.fdopen(fd, 'wb') as dst:
        shutil.copyfileobj(src, dst)
    os.chmod(destination, 0o644)   # world-readable module: umask 077 would otherwise leave it 0600 (ENV-18)
except BaseException:
    destination.unlink(missing_ok=True)
    raise
PY
printf 'Built and load-tested: %s\n' "$output"
printf 'This module is generic. On each server, create an identity file with\n'
printf '  envelock.py export-identity --recipient R.json --owner owner.json --out identity.bin\n'
printf 'and point envelock.identity at it in php.ini. Keep identity.bin and private JSON secret.\n'

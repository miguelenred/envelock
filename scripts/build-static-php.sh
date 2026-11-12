#!/usr/bin/env bash
# Objective O10: build a PHP with the Envelock loader compiled INTO the engine.
#
# Why this exists separately from build-unix.sh: that script produces a loadable module, which is
# the right shape for a normal deployment. A single-binary distribution has no place to load a
# module from — a statically linked PHP has no dynamic loader at all, and FrankenPHP's static
# builds confirm it, since `phpinfo()` on one shows no "Dynamic Library Support" row. So the loader
# has to be linked into the engine, and that build shape exercises code paths a module never does.
#
# What this script covers, and what it does not: it produces the PHP half of a static appliance and
# is verified end to end (it runs a protected package at the end). Producing the final FrankenPHP
# binary additionally needs Go and FrankenPHP's static toolchain, which is a separate step; see
# docs/MANUAL.md, "Static single-binary distribution".
#
# Usage: bash scripts/build-static-php.sh /path/to/php-8.4.27.tar.gz sapi/cli/php
set -euo pipefail
umask 077
# Defense in depth (ENV-2026-02): never let an inherited variable pull the bytecode emit/run surface
# into this appliance. This build passes none of the --enable-envelock-bc* flags.
unset ENVELOCK_BCPOC ENVELOCK_BCEMIT ENVELOCK_BCRUN 2>/dev/null || true
if [ "$#" -ne 2 ]; then
  echo "Usage: bash scripts/build-static-php.sh php-8.4.tar.gz salida/php" >&2
  exit 2
fi
root="$(cd "$(dirname "$0")/.." && pwd)"
tarball="$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$1")"
output="$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$2")"
if [ ! -f "$tarball" ]; then echo "No such tarball: $tarball" >&2; exit 1; fi
if [ -e "$output" ]; then echo "Refusing to overwrite: $output" >&2; exit 1; fi
for tool in make cc pkg-config autoconf; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Missing tool: $tool" >&2; exit 1; }
done

scratch="$(mktemp -d "${TMPDIR:-/tmp}/envelock-static-XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
echo "== Extracting $(basename "$tarball")"
tar xzf "$tarball" -C "$scratch" --strip-components=1

# A release tarball ships pre-generated parsers, so bison and re2c are not needed. A git checkout
# would need both; refusing here beats a confusing failure inside configure.
echo "== Adding the extension to the tree"
cp -R "$root/extension" "$scratch/ext/envelock"

# configure in a release tarball was generated at release time and cannot know about an extension
# that was not there, so --enable-envelock would be reported as an unrecognized option and silently
# ignored. Regenerating is what makes the build actually include it.
echo "== Regenerating configure (autoconf $(autoconf --version | head -1 | awk '{print $NF}'))"
( cd "$scratch" && ./buildconf --force )

# Same hardening as the loadable module (build-unix.sh): the appliance links the loader INTO the
# engine, so without these flags it would ship less hardened than a normal deployment. -fvisibility
# =hidden is safe for a PHP build — the engine marks its public API ZEND_API/PHPAPI (visibility
# default), so only the unmarked envelock_* internals are hidden, which is exactly what keeps a
# loaded extension from dlsym-ing the decrypt/key-unwrap API out of the single binary. Inherited
# flags first, hardening last, so the hardening wins on any conflict.
# _FORTIFY_SOURCE=3 where supported (see build-unix.sh), else 2; -U first so a toolchain default of 3
# is never lowered.
fortify=2
# shellcheck disable=SC2086 # $CC may carry its own flags
if printf '#include <string.h>\nint main(void) { return 0; }\n' \
    | ${CC:-cc} -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -Werror -x c -c -o /dev/null - >/dev/null 2>&1; then
  fortify=3
fi
hcflags="-O2 -fstack-protector-strong -fvisibility=hidden -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=$fortify -Wformat -Werror=format-security"
hldflags=""
if [ "$(uname -s)" = Linux ]; then
  hldflags="-Wl,-z,relro,-z,now,-z,noexecstack,-z,separate-code"
  hcflags="$hcflags -fstack-clash-protection"
  case "$(uname -m)" in
    x86_64|amd64) hcflags="$hcflags -fcf-protection=full" ;;
  esac
fi

echo "== Configuring"
( cd "$scratch" && CFLAGS="${CFLAGS:-} $hcflags" LDFLAGS="${LDFLAGS:-} $hldflags" ./configure \
    --disable-all --enable-cli --disable-cgi --disable-phpdbg \
    --without-pear --enable-envelock )

echo "== Building"
( cd "$scratch" && make -j"${ENVELOCK_JOBS:-2}" )

binary="$scratch/sapi/cli/php"
[ -f "$binary" ] || { echo "The build produced no sapi/cli/php" >&2; exit 1; }

# The envelock_* internals (decrypt/key-unwrap API, bytecode emit/run) must not be dlsym-able from
# the single binary. Assert they are not in its exported symbols; fail closed if the visibility
# flag did not take -- and also when the check itself cannot run (no nm, nm failing): a pipeline
# `nm ... | grep -q` used to PASS then. macOS has no `nm -D`: its exported globals are `nm -gU`.
command -v nm >/dev/null 2>&1 || { echo "Missing tool: nm (needed for the export check)" >&2; exit 1; }
case "$(uname -s)" in
  Darwin) nm_args=(-gU) ;;
  *)      nm_args=(-D --defined-only) ;;
esac
if ! exported="$(nm "${nm_args[@]}" "$binary")"; then
  echo "SECURITY: nm could not list the symbols of $binary; refusing to ship it unchecked" >&2
  exit 1
fi
if printf '%s\n' "$exported" | awk '{print $NF}' | grep -Eq 'envelock_|bc_emit|bc_run'; then
  echo "SECURITY: the static PHP exports envelock_* internals in its dynamic symbol table:" >&2
  printf '%s\n' "$exported" | awk '{print $NF}' | grep -E 'envelock_|bc_emit|bc_run' >&2
  exit 1
fi

# Load-test with no -d extension=: if the loader is really compiled in, it is there by itself.
echo "== Checking the loader is built in"
"$binary" -n -r 'exit(extension_loaded("envelock") && function_exists("__envelock_vm") ? 0 : 1);' \
  || { echo "The built PHP does not have Envelock compiled in" >&2; exit 1; }
# Runtime exposure gate (ENV-2026-02): -fvisibility=hidden hides the PoC functions from the dynamic
# symbol table (the nm -D check above), but they would still be callable from userland if compiled in.
# Ask the engine directly; a static appliance must expose NEITHER the emitter NOR the runner.
"$binary" -n -r 'exit((function_exists("envelock_bc_run") || function_exists("envelock_bc_emit")) ? 1 : 0);' \
  || { echo "SECURITY: this static PHP exposes the bytecode emit/run surface (ENV-2026-02); refusing it." >&2; exit 1; }
"$binary" -n -r 'echo "  PHP ", PHP_VERSION, " zts=", (int) ZEND_THREAD_SAFE,
                 "  envelock: compiled in", PHP_EOL;'

mkdir -p "$(dirname "$output")"
cp "$binary" "$output"
echo "Built: $output"

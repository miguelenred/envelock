#!/usr/bin/env bash
# Local review helper. Requires clang, phpize, pkg-config, Python dependencies.
set -euo pipefail
umask 077
root="$(cd "$(dirname "$0")/.." && pwd)"
work="${1:?Usage: bash scripts/audit-native.sh /absolute/empty-audit-directory}"
mkdir "$work"
work="$(cd "$work" && pwd)"
python3 "$root/scripts/demo_material.py" --output "$work/demo" --fuzz-header "$work/audit_keys.h"
clang --analyze -Xanalyzer -analyzer-output=text "$root/extension/envelock_crypto.c" \
  $(pkg-config --cflags libcrypto) > "$work/clang-crypto.txt" 2>&1
clang -g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined \
  -I"$work" -I"$root/extension" "$root/tests/fuzz_crypto.c" "$root/extension/envelock_crypto.c" \
  $(pkg-config --cflags --libs libcrypto) -o "$work/fuzz-crypto"
mkdir "$work/corpus"
python3 - "$root" "$work" <<'PY'
import importlib.util, pathlib, sys, uuid
root, work = map(pathlib.Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location('demo', root / 'scripts/demo_material.py')
demo = importlib.util.module_from_spec(spec); spec.loader.exec_module(demo)
a = demo.a
owner, recipient = demo.get_material()
source = work / 'source'; source.mkdir()
(source / 'index.php').write_text('<?php echo "audit-only";')
# allow_demo=True: this fuzz corpus is built from the PUBLIC demo owner key on purpose (it is
# throwaway material, never a real package), which pack_tree refuses by default.
a.pack_tree(source, work / 'packed', [a.recipient_public(recipient)], owner, str(uuid.uuid4()),
            allow_demo=True)
blob = (work / 'packed/index.php').read_bytes()
(work / 'corpus/valid').write_bytes(blob)
signer = a.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(owner['signing_private']))
base = len(a.STUB) + a.HEADER.size + len('index.php')  # recipient table (after the path)
# ephemeral_pub, wrap_nonce, wrapped_key, ciphertext — validly signed but broken payloads
for i, offset in enumerate([base+32, base+64, base+76, base+a.RECIPIENT_SIZE]):
    body = bytearray(blob[:-64]); body[offset] ^= 128
    (work / f'corpus/signed-invalid-{i}').write_bytes(bytes(body) + signer.sign(bytes(body)))
PY
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  "$work/fuzz-crypto" -runs="${ENVELOCK_FUZZ_RUNS:-30000}" -max_len=65536 "$work/corpus" \
  > "$work/fuzz.txt" 2>&1
# Static-analyze EVERY translation unit, not just crypto/zend/file, and with the bytecode layer
# ENABLED (-DENVELOCK_HAVE_BYTECODE=1) so the opcache-derived persistence code and the 2.0 modules
# (vm, licence, trusted_time, secret, integrity, clock) are covered too (ENV-2026-33). The extension's
# own headers live beside the sources, so -I"$root/extension" resolves every local include. The
# per-version bytecode layer is the one matching the PHP this machine builds against.
mm="php$(php-config --version | awk -F. '{print $1 $2}')"
bc_flags=""
if [ -d "$root/extension/opcache/$mm" ]; then
  bc_flags="-I$root/extension/opcache/$mm -DENVELOCK_HAVE_BYTECODE=1"
fi
common_inc="$(php-config --includes) -I$root/extension $(pkg-config --cflags libcrypto) $bc_flags"
for unit in envelock.c envelock_crypto.c envelock_file.c envelock_secret.c envelock_integrity.c \
            envelock_licence.c envelock_clock.c envelock_trusted_time.c envelock_vm.c; do
  clang --analyze -Xanalyzer -analyzer-output=text $common_inc \
    "$root/extension/$unit" > "$work/clang-${unit%.c}.txt" 2>&1 || true
done
# The opcache bytecode layer itself (per PHP version), with the same -DENVELOCK_HAVE_BYTECODE=1.
if [ -n "$bc_flags" ]; then
  for unit in "$root/extension/opcache/$mm/"*.c; do
    base="$(basename "$unit" .c)"
    clang --analyze -Xanalyzer -analyzer-output=text $common_inc \
      "$unit" > "$work/clang-bc-$base.txt" 2>&1 || true
  done
fi
printf 'Completed local analysis/fuzzing. Review logs in %s\n' "$work"
printf 'Passing tools does not prove absence of vulnerabilities.\n'

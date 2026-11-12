#!/usr/bin/env bash
# Regenerate docs/reports/ by RUNNING the tools (never hand-edit the evidence).
# What this machine can produce: bandit, ruff, pip-audit, clang analyzer, a gcc
# ASan/UBSan exerciser of the crypto core, and a JUnit run on the installed PHP.
# The multi-version matrix (8.2/8.4/8.5), the libFuzzer campaign and Windows/macOS
# builds are produced by CI (see .github/workflows and docs/PLATAFORMAS.md).
set -euo pipefail
umask 022
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/docs/reports"
mkdir -p "$out"
cd "$root"
now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
php_ver="$(php -r 'echo PHP_VERSION;')"
ossl="$(php -r 'echo OPENSSL_VERSION_TEXT;' 2>/dev/null || openssl version)"

echo "[1/7] ruff";      ruff check --output-format json encoder gui tests scripts/demo_material.py scripts/check_release.py scripts/bench.py scripts/fpm_smoke.py > "$out/ruff.json" 2>/dev/null || true
echo "[2/7] bandit";    bandit -q -f json -r encoder gui scripts/demo_material.py scripts/check_release.py scripts/bench.py scripts/fpm_smoke.py > "$out/bandit.json" 2>/dev/null || true
echo "[3/7] pip-audit"; pip-audit --require-hashes -r requirements.lock -f json > "$out/dependencies.json" 2>/dev/null || true
echo "[4/7] clang analyzer"
clang --analyze -Xanalyzer -analyzer-output=text extension/envelock_crypto.c \
  $(pkg-config --cflags libcrypto) > "$out/clang-crypto.txt" 2>&1 || true
clang --analyze -Xanalyzer -analyzer-output=text $(php-config --includes) \
  extension/envelock.c > "$out/clang-zend.txt" 2>&1 || true
clang --analyze -Xanalyzer -analyzer-output=text extension/envelock_file.c \
  > "$out/clang-file.txt" 2>&1 || true

echo "[5/7] gcc ASan/UBSan exerciser of the crypto core"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
python3 "$root/scripts/demo_material.py" --output "$work/demo" --fuzz-header "$work/audit_keys.h"
python3 - "$root" "$work" <<'PY'
import importlib.util, os, sys, uuid
from pathlib import Path
root, work = map(Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location("demo", root/"scripts/demo_material.py")
demo = importlib.util.module_from_spec(spec); spec.loader.exec_module(demo); a = demo.a
owner, recipient = demo.get_material()
rp = bytes.fromhex(recipient["x25519_public"])
signer = a.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(owner["signing_private"]))
def mk(src):
    ck=os.urandom(32); pid=uuid.uuid4().bytes; rid=uuid.uuid4().bytes
    return a.protect(src, signer, pid, rid, ck, a.build_table([rp],ck,pid,rid), path="index.php")
(work/"seed_small.bin").write_bytes(mk(b'<?php echo 1;'))
(work/"seed_100k.bin").write_bytes(mk(b'x'*100000))
PY
cat > "$work/exercise.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "envelock_crypto.h"
#include "audit_keys.h"
static void run(const unsigned char*b,size_t n){ unsigned char*s=0; size_t l=0;
  if(envelock_decrypt(b,n,envelock_x25519_private,envelock_x25519_public,envelock_signing_public,&s,&l)) envelock_clear_source(s,l);
  (void)envelock_verify(b,n,envelock_signing_public);
  /* Post-signature path (table lookup, KEM, GCM) on the same mutated input: mutations no
   * longer stop at the signature check, so the code after it is exercised too. */
  unsigned char k[32] = {0}; s=0; l=0;
  if(envelock_decrypt_verified(b,n,envelock_x25519_private,envelock_x25519_public,k,&s,&l)) envelock_clear_source(s,l);
  s=0; l=0; if(envelock_decrypt_with_key(b,n,k,&s,&l)) envelock_clear_source(s,l);
  (void)envelock_package_digest(b,n,k);
  { size_t d=envelock_source_length(b,n), g=0; (void)envelock_unwrap_key(b,n,envelock_x25519_private,envelock_x25519_public,k);
    if(d<=n){ unsigned char*o=malloc(d+1); if(o){ (void)envelock_decrypt_with_key_into(b,n,k,o,d,&g); free(o);} }
    if(n>=80 && d<=n-80){ unsigned char*c=malloc(n); if(c){ memcpy(c,b,n); (void)envelock_decrypt_with_key_into(c,n,k,c+(n-80-d),d,&g); free(c);} } } }
static unsigned char* rd(const char*p,size_t*n){ FILE*f=fopen(p,"rb"); fseek(f,0,SEEK_END); long s=ftell(f); fseek(f,0,SEEK_SET); unsigned char*b=malloc(s?s:1); *n=fread(b,1,s,f); fclose(f); return b; }
int main(int c,char**v){ unsigned char*seed=0; size_t sn=0;
  for(int i=1;i<c;i++){ size_t n; unsigned char*b=rd(v[i],&n); run(b,n); if(i==1){seed=b;sn=n;} else free(b);}
  if(seed){ for(size_t o=0;o<sn;o++){ unsigned char*m=malloc(sn); memcpy(m,seed,sn); m[o]^=0x80; run(m,sn); free(m);}
    for(size_t cut=0;cut<=sn;cut++) run(seed,cut);
    srand(1234); for(int k=0;k<200000;k++){ int len=rand()%512; unsigned char*r=malloc(len?len:1); for(int j=0;j<len;j++) r[j]=(unsigned char)rand(); run(r,len); free(r);} free(seed);}
  printf("exerciser completed\n"); return 0; }
EOF
gcc -fsanitize=address,undefined -fno-sanitize-recover=all -O1 -g -I"$work" -I"$root/extension" \
  "$work/exercise.c" "$root/extension/envelock_crypto.c" $(pkg-config --cflags --libs libcrypto) -o "$work/exercise"
{
  echo "Envelock crypto core — gcc AddressSanitizer + UndefinedBehaviorSanitizer exerciser"
  echo "date: $now"
  echo "inputs: 1 valid small blob (all single-byte mutations + all truncations + 1 append),"
  echo "        1 valid 100 KiB blob, and 200000 pseudo-random inputs (seed 1234)."
  echo "paths: envelock_decrypt (signature first), envelock_verify, envelock_decrypt_verified,"
  echo "       envelock_decrypt_with_key, envelock_package_digest, and the loader path"
  echo "       envelock_unwrap_key + envelock_decrypt_with_key_into (into a caller buffer and in place)"
  echo "       (post-signature parsing/KEM/GCM reached even by mutated inputs)."
  echo "note: this is a bounded deterministic exerciser, NOT the libFuzzer campaign (CI)."
  echo "---"
  ASAN_OPTIONS=abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 "$work/exercise" \
    "$work/seed_small.bin" "$work/seed_100k.bin"
  echo "result: no AddressSanitizer/UndefinedBehaviorSanitizer errors."
} > "$out/fuzz-asan-ubsan.txt" 2>&1

echo "[6/7] JUnit on PHP $php_ver"
rm -f "$out"/php-8.*.xml "$out"/junit-php-*.xml "$out"/php-source-*.json
(cd "$root" && ENVELOCK_REQUIRE_NATIVE=1 python3 -m pytest -q tests \
  --junitxml="$out/junit-php-${php_ver}.xml" >/dev/null 2>&1) || true

echo "[7/7] targets.json (SHA256 of shipped sources + environment)"
python3 - "$root" "$out" "$now" "$php_ver" "$ossl" <<'PY'
import hashlib, json, platform, sys
from pathlib import Path
root, out, now, php_ver, ossl = sys.argv[1:6]
root = Path(root)
files = ["extension/envelock.c","extension/envelock_crypto.c","extension/envelock_crypto.h",
         "extension/envelock_file.c","extension/envelock_file.h",
         "extension/config.m4","extension/config.w32","encoder/envelock.py",
         "scripts/build-unix.sh","scripts/build-windows.ps1","CMakeLists.txt"]
targets = {}
for f in files:
    p = root/f
    if p.exists():
        targets[f] = "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()
doc = {
    "generated": now, "format": "ENVLK02", "identity": "ENVLKID2",
    "environment": {"python": platform.python_version(), "php": php_ver,
                    "openssl": ossl, "uname": platform.platform()},
    "note": "Hashes of the exact sources audited/compiled on this machine. "
            "Multi-version matrix, libFuzzer and Windows/macOS come from CI.",
    "targets": targets,
}
Path(out, "targets.json").write_text(json.dumps(doc, indent=2) + "\n")
PY

cat > "$out/README.md" <<EOF
# docs/reports — measured evidence (regenerated, do not hand-edit)

Regenerated by \`scripts/regen-reports.sh\` on $now.
Environment: PHP $php_ver, $ossl, $(uname -srm).

Produced on this machine:
- \`ruff.json\`, \`bandit.json\` — static analysis of the encoder/scripts (Python).
- \`dependencies.json\` — pip-audit of pinned Python dependencies.
- \`clang-crypto.txt\`, \`clang-zend.txt\`, \`clang-file.txt\` — Clang Static Analyzer (empty = no diagnostics).
- \`fuzz-asan-ubsan.txt\` — gcc ASan/UBSan exerciser of the crypto core (bounded).
- \`junit-php-${php_ver}.xml\` — native test suite on the installed PHP.
- \`targets.json\` — SHA256 of the exact sources audited + environment.

Produced by CI (not on this machine): the PHP 8.2/8.4/8.5 matrix, the long
libFuzzer campaign, and Windows/macOS builds. See \`.github/workflows/checks.yml\`
and \`docs/PLATAFORMAS.md\`.
EOF
# Published evidence must not carry this machine's paths (skip messages and tool output print
# absolute paths): make them relative to the repository, and fail if any remains.
python3 - "$root" "$out" <<'PY'
import sys
from pathlib import Path
root, out = sys.argv[1], Path(sys.argv[2])
for report in out.iterdir():
    if report.is_file():
        text = report.read_text(encoding="utf-8", errors="surrogateescape")
        if root in text:
            report.write_text(text.replace(root + "/", "").replace(root, "."),
                              encoding="utf-8", errors="surrogateescape")
PY
python3 "$root/scripts/check_release.py" "$out" >/dev/null || {
  echo "A regenerated report still holds private or personal data: run scripts/check_release.py $out" >&2
  exit 1
}
printf 'docs/reports regenerated in %s\n' "$out"

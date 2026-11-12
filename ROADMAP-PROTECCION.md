# Envelock — source-protection roadmap

Goal: raise the cost of reading or extracting the protected PHP source as high as possible while the
application keeps working unchanged on a real web server. Reliability is part of the strength, not a
brake: a protector that breaks the app protects nothing.

> **Version note.** The anti-root architecture this roadmap calls "2.0" is the internal **codename** for
> the work, not a released version number. Nothing is published yet; it ships as part of Envelock's first
> **1.0.0** release (all of it opt-in and off by default). "2.0" throughout this file means that codename.

**Honest threat model.** Envelock does not fully defeat the administrator/root of the server that
runs the application: with full control, root can still read process memory. No tool in this class
(including the mature commercial encoders) defeats that either — they are also decompiled. "Maximum
protection" here means moving the attacker from "dump and `cat` in minutes" to "defeat bytecode +
obfuscation", which is incomplete and expensive, without ever breaking the app.

## 1.0 — the recommended release

The 1.0 line is the strongest source cipher in its class and is the release recommended for
publication: per-server asymmetric keys (no universal loader carrying a global secret), AES-256-GCM
content encryption, X25519+HKDF key wrap, Ed25519 signing verified before any key operation, and an
opt-in protection stack: comment stripping, compaction, string-literal encoding, local/private-symbol
obfuscation, conservative flow obfuscation, the in-C literal vault (`--vault-strings`), include
protection, `--no-prepend`, `--no-ffi`, sealed mode (`--sealed`), and a signed manifest enforced at
deploy (`verify`) and at runtime (`--enforce-manifest`). Three external audits were reproduced and
fixed (see `docs/AUDITORIA.md`). Every capability is opt-in and off by default; a 1.0 source package
keeps running under 2.0.

## 2.0 — anti-root architecture (in development)

The 2.0 line removes the decrypted PHP *source* from the package and from process memory. Objectives
and current status:

| # | Objective | Status |
|---|-----------|--------|
| O1 | Precompile to a serialized `zend_op_array`, ship it encrypted+signed instead of source (`--bytecode`). Bound to the exact PHP build (an Envelock bytecode identity — PHP version, Zend build id, data layout, VM kind — fail-closed; it replaced `zend_system_id`, which differs between the CLI and FPM of one build). Per-version layer under `extension/opcache/<ver>/`, optional. | Done; per-version layers for 8.2–8.5; round-trip verified on Linux. AST→bytecode combination verified on 8.3.6. |
| O2 | `memfd_secret` (Linux ≥5.14) for transient plaintext and keys; `mlock`+`MADV_DONTDUMP` fallback. | Done. |
| O3 | Anti-rehook self-check (own `compile_file` intact, foreign `zend_ast_process`/`TracerPid`), opt-in paranoid mode. | Done. |
| O4 | Opcode mini-VM for marked functions. | **Experimental / laboratory only**, behind `--unsafe-vm-laboratory`; not part of the production recommendation. |
| O5 | Root-owned identity install (`identity.bin` `0400 root:root`, `server-install`). | Done. |
| O6 | Global AST obfuscation (classes/methods/properties/functions) within a closed boundary with an allow-list; public renaming opt-in only. | Done; differential fuzzer at 0 divergences. |
| O7 | String-literal vault encrypted at rest inside the plaintext, decrypted per access. | Done (format bit 7). |
| O8 | Deployment licensing (expiry, domain, IP, machine fingerprint) with verified online trusted time. | Done. |
| O9 | Per-worker in-RAM opcode cache. | **Dropped on security grounds** — it would reverse the "nothing decrypted persists between requests" guarantee. O1 is the performance answer instead. |
| O10 | Static single-binary distribution (loader + app). | Loader half done; the static PHP build and the single-binary wrapper are produced in CI. |
| O11 | Real end-to-end validation with Laravel and Symfony (protect own code only; keep `vendor/` and runtime caches outside the sealed tree). | Packaging demonstrated on a real Laravel application (526 files, 0 with cleartext); boot-and-compare runs in CI. **WordPress** (2086 files) and **Joomla** (5902 files) validated end-to-end, both source-cipher and bytecode, byte-for-byte identical to baseline — surfaced and fixed the bytecode autoglobal-arming bug. **Drupal 11** (13641 files) validated end-to-end in **both source-cipher and bytecode**, byte-for-byte identical (uses PHP 8 attributes, no annotation issue; the full-tree bytecode emit crash was the arena-sizing bug, fixed Pass 25). **PrestaShop 9** (34138 files) validated encrypted end-to-end with the `docs/DEPLOYING-APPS.md` §7 recipe (`var/` clear + exclude the `@ORM` entities) — renders identical to baseline (189 products); its bytecode **emit** validated on 100 % of files (render inferred from the three validated bytecode sites). All four CMSs validated. The **optional obfuscation/hardening option matrix is now measured on all four** (Pass 29): Joomla 5.2.2 and PrestaShop 9 added empirically — PrestaShop breaks under `--strip-comments`/`--compact` (its `AbstractLazyArray` reads `@arrayAccess` docblocks at run time, now flagged by `preflight`'s `reads-own-docblock` detector); Joomla tolerates the full set incl. `--sealed` with the allowlist; `--obfuscate-properties` breaks every CMS (Composer autoloader). See `docs/AUDITORIA.md` Passes 19–29 and `docs/DEPLOYING-APPS.md`. |

## Measured limitations (current)

- **Root extraction.** O1 keeps decrypted *source* out of the package and process memory, which
  raises the cost markedly, but root can still dump the deserialized op_array, literals and runtime
  data. Known design limit; not resolved.
- **Obfuscation.** Global AST renaming and conservative flow obfuscation are in; real control-flow
  flattening and constant mixing are unfinished, and the opcode VM (O4) is laboratory-only and not
  production-hardened. A competent analyst can still recover logic, especially from bytecode.
- **Windows 2.0 — done (verified under Wine).** The 2.0 native modules and the bytecode layer (O1)
  were ported to the MSVC/Windows toolchain; all 8 DLLs build and the bytecode round-trip runs on
  8.4/8.5 NTS under Wine. Real-Windows confirmation (ACLs, non-ASCII paths, VCRUNTIME) is still the
  user's to make. Linux 2.0 is complete and tested; macOS source is portable, validated by CI.
- **OPcache.** Protected files are refused under OPcache SHM by default (fail-closed); coexistence is
  opt-in via `opcache.blacklist_filename`. Decrypted code is never cached between requests, by design.

## Remaining work to close 2.0

- The AST→bytecode combination on 8.2/8.5 and the real Laravel/Symfony boot-and-compare (O11): run in
  CI (no tokenizer on those builds here, and running downloaded application code is not possible in
  the development sandbox).
- Rebuild and publish the 2.0 loaders for every target (Linux/Windows/ARM64 × versions) from CI and
  regenerate `prebuilt/SHA256SUMS`.
- Confirm the Windows 2.0 DLLs (now ported and Wine-verified, bytecode included) on real Windows
  (ACLs, non-ASCII paths, VCRUNTIME), and build/validate the macOS 2.0 loader on a real Mac / CI.
- An accredited external audit of the C/Zend and of the packaging.

See `docs/AUDITORIA.md` for the per-pass review record and `docs/VERIFICACION.md` for measured
counts.

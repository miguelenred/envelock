# Verification (v2 format, 1.0.0)

> **Current checkout, November 2026:** the matrix below is a historical record, not a fresh
> cross-platform validation. The complete distribution ships, under `prebuilt/` (all in
> `prebuilt/SHA256SUMS`), the five Linux loaders, the eight Windows loaders, the Linux and Windows
> assistants, the portable Python distributions and the wheel bundle; the source-only distribution
> ships none of them. See [prebuilt/README.md](../prebuilt/README.md) and the project
> [roadmap](../ROADMAP-PROTECCION.md) for current, scoped test results and open objectives.

**Historical environment:** October 24, 2026 (updated November 1). Ubuntu 24.04 x86-64 (glibc 2.39), OpenSSL 3.0.13, Python 3.13, gcc/clang 18. PHP 8.3.6 from the distribution, and PHP 8.2.35, 8.4.27 (NTS and ZTS) and 8.5.12 compiled from php-src.

All the evidence in `docs/reports/` is **regenerated** by running `scripts/regen-reports.sh` (it is not hand-edited). What this machine produces and what corresponds to CI is in `docs/reports/README.md`.

## Anti-root architecture verification (November 5, 2026)

After adopting the independent anti-root continuation (see `docs/AUDITORIA.md`, Pass 15), the suite was
re-run in this environment. Honest status, with what could not be verified here named explicitly.

| Check | Tool / PHP | Result |
|---|---|---|
| Full native suite (build + real decryption) | `pytest ENVELOCK_REQUIRE_NATIVE=1`, PHP 8.3.6 (the only PHP here with the tokenizer) | **985 passed / 0 failed / 9 skipped** (November 2026, after the internal hardening audit — adds the bytecode deserializer crash-safety fuzz and `script->size` re-anchor regressions, and the Python-side release-guard and `__halt_compiler` regressions; 975 earlier, after the harder self-audit — adds the truncation sweep, the payload byte-flip sweep, the sealed_cleartext trailing-slash/multi-entry test, and two worker-reuse stress tests (50 sealed+vault on NTS, 40 sealed on ZTS). The loader's security subset also passes on **8.2, 8.4, 8.4-ZTS and 8.5** (35/35 each). 970 after the first self-audit round added `test_php_sealed_cleartext_allowlist_respects_path_boundary`, the regression for the sealed_cleartext prefix-boundary bypass; 969 after the CMS-matrix round added `test_php_sealed_cleartext_allowlist` for the `envelock.sealed_cleartext` directive; 968 after the two external-audit rounds with the negative-`clock_tolerance` and long-lived-worker watermark regressions; 966/965/964/963/962/960 earlier on Nov 8–9, 956 on November 5). Includes the AST-obfuscation→bytecode combination, now that 8.3.6 has both the tokenizer and a bytecode layer. (Earlier run, before the 8.3 layer: 941/3/22, the 3 failures being exactly that combination.) The five Linux production loaders export zero `envelock_*` symbols and contain neither `envelock_bc_emit` nor `envelock_bc_run` (the PoC bytecode functions, gated behind the explicit `./configure` flags `--enable-envelock-bcemit` / `--enable-envelock-bcrun-unsafe`, which a production build never passes). |
| Encoder + Python suite | `pytest --ignore=tests/test_native.py`, PHP 8.3.6 | **486 passed / 5 skipped** (November 9; adds `test_recommend_options_is_conservative_and_matches_the_cms_matrix` and the two assistant-action tests for the new `recommend` command, on top of the external-audit regressions for ENV-02/03/04 and NU-02/04/05, the `preflight` WordPress-FSE-header and `reads-own-docblock` detectors, the vault-nonce and bytecode-temp tests, and `test_project_url_allowed_but_other_personal_refs_flagged` for the project-page attribution URL) |
| O1 bytecode round-trip (pack→encrypt→decrypt→deserialize→run, no source in package) | native, PHP 8.2.35 / 8.3.6 / 8.4.27 / 8.5.12 | **13 / 13** bytecode round-trip on each of the four (per-version layers `extension/opcache/php8{2,3,4,5}/`); plus 16/16 bytecode+AST→bytecode on 8.3.6. On 8.2/8.5, `test_bytecode_refuses_the_literal_vault` cannot run (its `--vault-strings` step needs the tokenizer, absent on those `/opt` builds); it passes on 8.3.6 |
| O2 secret handling + O3 anti-rehook + O8 licensing/trusted-time | native, PHP 8.4.27 | **27 / 27** |
| O6 global obfuscation differential fuzzer | `scripts/fuzz_obfuscator.py`, PHP 8.3.6 | **0 divergences** (original vs transformed output) |

**Pending verification (environment-blocked, to close in CI / Miguel's environment):**

- **AST→bytecode combination.** *Cleared on November 5*: a per-version bytecode layer was added for
  8.3.6, which already has the tokenizer, so both now coexist and the combination passes.
- **Per-version bytecode layers.** *Done for 8.2, 8.3, 8.4 and 8.5* (November 5): all four compile
  and pass the bytecode round-trip. Per-version deltas handled: `get_class_name_map_ptr` is
  `uint32_t` on 8.3 and `void` on 8.2/8.4/8.5; 8.5 split the SHM loader into `..._load_ex` (added to
  the generator's DROP set). Remaining: run the AST→bytecode combination on 8.2/8.5 in CI (a PHP with
  both the tokenizer and the bytecode layer), since the `/opt` 8.2/8.5 here have no tokenizer.
- **Real Laravel/Symfony end-to-end (O11).** *Run on 2026-11-10* on native Windows 11 (PHP 8.4.27 NTS):
  Laravel 13.40 (10 routes plus a session hand-off through deploy and rollback) and Symfony 8.1 (7 routes)
  packed as bytecode are identical to the cleartext apps, and so is the options recommender's suggested
  command run as printed (web routes and console). `scripts/framework-smoke.py`; `TEST-STATUS.md`.
- **Windows DLL runtime validation.** *Done on 2026-11-10* on native Windows 11 with the official PHP
  for Windows builds: the 8 DLLs are now built there (`scripts/build-windows.ps1`) and pass
  `tests/test_native.py` with 0 failures; see `TEST-STATUS.md` and `docs/AUDITORIA.md` (Pass 32).
- **Linux loaders and assistant.** *Rebuilt on 2026-11-12* from the current source as portable builds
  (AlmaLinux 8, glibc 2.28+, OpenSSL linked in) and tested there and on Ubuntu 24.04 with its own PHP;
  results, and what WSL1 could not run, in `TEST-STATUS.md`.

## What was run here

| Check | Tool | Result | Report |
|---|---|---|---|
| **Native Windows 11, after the 2026-11-10 audit** (official php.net PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, NTS and TS) | `scripts/build-windows.ps1` (8 production DLLs + 4 test DLLs with `--enable-envelock-bcrun-unsafe`); `tests/test_native.py` per DLL; the whole suite on 8.4 NTS; `tests/test_bytecode_guard.py`; corruption sweeps; the fuzzers; `scripts/framework-smoke.py`; the assistant `--e2e` | native suite **0 failed** on all eight DLLs (932/70 skipped on 8.2–8.4, 943/59 on 8.5); whole suite 1572 passed / 115 skipped / 3 failed (the 55 files missing from the complete ZIP, restored when the release ZIPs are built); bytecode guard and bytecode tests 0 failed on 8.2–8.5; sweeps 0 crashes; fuzzers 0 divergences; Laravel and Symfony identical; DLLs export only `get_module` and embed no build path | `TEST-STATUS.md`, `docs/AUDITORIA.md` Pass 32 |
| Full suite (native build + real decryption) | pytest, `ENVELOCK_REQUIRE_NATIVE=1` (October 29; re-run November 1, and again November 2 after the three external audits of Pass 14 — the developer-bound minimum and `ENVLKID3` format, the developer-indexed include protection, the lexically-normalized sealed path, the UNC manifest open and the Windows identity-I/O fixes) | **0 failed**: full suite on PHP 8.3.6 — 372 collected, 367 passed, 5 skipped. The native suite `tests/test_native.py` (build of the extension + real decryption): **81 passed / 3 skipped** on PHP 8.3.6, including the `--vault-strings` cases (runs identically, per-file tables do not cross, unaffected without the flag, a malformed but signed vault table is rejected cleanly), the `--no-ffi` refusal, the four `--sealed` cases (plain PHP under the tree refused, `eval()` refused, both allowed when the package is not sealed, and plain PHP outside the sealed folder still runs), the five `--enforce-manifest` cases (runs intact, refuses a deleted/missing/tampered manifest, unaffected without the flag) and `test_php_eval_runs_without_any_protected_file` (regression for the ZTS `sealed_active` zero-init bug below). Skips: the window tests (no Tkinter in that Python; they pass separately with a display: 33 assistant tests), Windows-only cases and the strip/obfuscate tests on PHP builds without the tokenizer | `junit-php-8.3.6.xml` |
| Real PHP-FPM requests | `scripts/fpm_smoke.py` (as root: also root master + `nobody` pool) | all checks pass on PHP 8.2, 8.4 and 8.5 | — |
| Committed loaders (`prebuilt/loader/`, Linux x86-64) | `tests/test_prebuilt.py` (checks `SHA256SUMS`, that the committed loaders export no `envelock_*` symbols, and runs the committed loader matching the local PHP) | **4 passed**. All five Linux loaders were rebuilt on November 2 from the Pass-14 sources and run a protected file with the `ENVLKID3` identity; `SHA256SUMS` regenerated and verified. The committed loaders are built from the same sources as the self-built extension tested at 81/3 above | — |
| Windows x64 loaders (`prebuilt/loader/windows-x64/`) | built with MSVC 14.11 + Windows SDK 10.0.22000 under Wine (`scripts/build-windows-wine.sh`, with `/CETCOMPAT`); `tests/test_native.py` with `ENVELOCK_TEST_EXTENSION` and PHP for Windows under Wine | all eight DLLs were rebuilt again on November 2 from the Pass-14 sources (developer-bound minimum / `ENVLKID3`, developer-indexed include protection, lexically-normalized sealed path, UNC manifest open). Each is a valid PE32+/x64 module exporting `get_module`. **Runtime Wine validation could not be re-run this session**: the environment's Wine has no VS2022 (14.44) runtime, so the Windows PHP builds do not start (plain PHP fails identically, independent of the loader) — the Windows runtime matrix is validated by the Windows CI job. The November-1 run below is the last full Wine matrix: all eight DLLs run November 1 for the `--no-ffi`, `--sealed`, `--enforce-manifest` and `--vault-strings` flags, each through the full native suite under Wine with its matching PHP for Windows (the vault's four native cases run and pass on all eight; the Wine matrix also caught a PHP-8.5-only bug where the build's CLI printed a new deprecation to stdout and corrupted the transform's JSON — fixed by forcing `display_errors=stderr`): **0 failed on all eight** (8.2.35, 8.3.36, 8.4.27 × NTS/TS → 59 passed, 19 skipped; 8.5.12 × NTS/TS → 70 passed, 8 skipped), NTS and TS identical per version. The only difference between versions is 11 OPcache-coexistence tests that skip where OPcache is unavailable under Wine (8.2–8.4) and run (and pass) on 8.5.12, where it loads; the other skips are identical across versions (phpdbg of the same build, Windows ACL, `VirtualLock` without `/proc`, building a second extension, and the non-ASCII identity-path test — its Z: drive cannot present a non-ASCII Linux filename as the UTF-16 name the loader looks up, so ENV-14 stays a real-Windows check). The `--no-ffi` refusal, all four `--sealed` cases and all five `--enforce-manifest` cases run and pass on all eight. **This Wine matrix caught a thread-safe (ZTS) regression in the first `--sealed` build**: the per-request `sealed_active` counter was not zero-initialized by TSRM, so on the TS DLLs a worker that compiled no protected file spuriously refused `eval()` and then faulted when a plain include scanned the uninitialized roots table (nondeterministic page faults on the TS builds; NTS and native Linux ZTS were clean because their globals happen to start zeroed). Fixed by zero-initializing `sealed_active` in GINIT and resetting it in RINIT (like `request_ready`); regression test `test_php_eval_runs_without_any_protected_file`, and all eight DLLs then pass. PHP inputs (SHA-256): php-8.2.35-nts `dcde2389…82d7`, -ts `188dc95c…1d25`, devel nts `490e2a13…744c`, ts `a3ec27c8…7162`; 8.3.36 nts `7c949fe8…f78f`, ts `c2bc745d…082d`, devel nts `c5634c64…3736`, ts `9250c338…acd4`; 8.4.27 nts `b4c0b797…22c3`, ts `ab56b5e4…6fb0`, devel nts `cb788965…d949`, ts `80984af3…db3`; 8.5.12 nts `768dfb66…82c`, ts `c073ba7b…add4b`, devel nts `7c1b6eb0…505c`, ts `bc90870e…c68a` (builds of the official sources, not the php.net files byte for byte). Microsoft NuGet packages matched their catalog SHA-512 | — |
| Assistant executables (`prebuilt/assistant/`) | `--e2e` (with `ENVELOCK_E2E_PHP`: runs a real PHP from the executable) | Linux x86-64 natively and Windows x64 under Wine: `--e2e` passes (create keys, pack, reopen, PHP download). The Windows executable bundles the Visual C++ runtime 14.44 and `ctypes.wintypes` (needed by the Windows new-file ACL hardening). The inherited-search-path fix and the Windows ACL cannot be fully reproduced under Wine: confirm on real Windows | — |
| Libraries built from `third_party/` with the network disabled | OpenSSL 4.0.3 (`./Configure no-shared`), cffi 2.1.1, pycparser 3.12, cryptography 50.0.2 (vendored crates, rustc 1.97) | October 29: cryptography built in 72 s, reports `OpenSSL 4.0.3`; the encoder, hardening and assistant tests passed with it (**151** at that date); typing_extensions 4.16.0 also builds offline. The `third_party/` sources are unchanged since; the review tests added October 31 – November 1 run on the standard toolchain above (encoder+hardening **161**, transform included **190**, assistant **32**), plus the differential obfuscator fuzzer `scripts/fuzz_obfuscator.py` (original vs transformed output on generated programs with random flag combinations, now including `--obfuscate-flow` and the `--vault-strings` literal vault; 0 divergences over 1500 programs × 3 seeds; run in CI and from `test_fuzz_obfuscator_finds_no_divergence`) | — |
| Portable Python (`prebuilt/python/`) | the `envelock` launchers | Linux x86-64: keys, `pack`, identity file, and the protected file run by the committed loader; all the command-line equivalents of `docs/ASSISTANT.md` through `./envelock`; Windows x64 under Wine: `envelock.cmd` and the assistant's `--selftest`; Linux ARM64 under qemu: keys and `pack`. macOS not run. Archives match the hashes published by their release | — |
| Repository round trip | `git init/add/commit/clone`, plain and with `core.autocrlf=true`, then every `.cargo-checksum.json`, `third_party/SHA256SUMS` and `prebuilt/SHA256SUMS`, the release guard and `./envelock new-project` in the clone | 0 mismatches in both clones; `envelock.cmd` keeps CRLF (without the folders' `.gitattributes`: 504 files of `third_party/` and ~1,250 of `prebuilt/` altered by end-of-line conversion, all reported by the release guard) | — |
| Official wheels in `prebuilt/python-wheels/` | offline `pip install --no-index` | Linux x86-64 and Windows x64 (under Wine) install and run the encoder; ARM64 and macOS not run | — |
| Static analysis of the C code | Clang Static Analyzer | no diagnostics | `clang-crypto.txt`, `clang-file.txt`, `clang-zend.txt` (empty) |
| Memory safety of the C core | gcc ASan + UBSan (bounded exerciser) | no errors | `fuzz-asan-ubsan.txt` |
| Coverage-guided fuzzing of the C core | libFuzzer + ASan + UBSan, leak detection (`scripts/audit-native.sh`) | 5,000,000 executions, no crashes, no leaks | — |
| Static analysis of the encoder/scripts | bandit 1.9.4 | 0 findings | `bandit.json` |
| Style/lint | ruff 0.17.2 | no issues | `ruff.json` (`[]`) |
| Dependencies (full hash-pinned lock) | pip-audit 2.10.1 | 0 known vulnerabilities | `dependencies.json` |
| Hashes of the audited sources + environment | SHA256 | — | `targets.json` |

The ASan/UBSan exerciser traverses a small valid container with **mutation of each byte**, **all truncations** and an append, a valid 100 KiB container, and 200,000 pseudo-random entries, through both the signature-first path and the post-signature path (`envelock_decrypt_verified`), so mutated inputs also reach the table lookup, key agreement and GCM code.

## Relevant functional results

- Real per-recipient decryption (X25519+HKDF+AES-GCM) and Ed25519 verification before decrypting.
- **Cross decryption impossible:** a package addressed to one recipient is not opened by another.
- **Anti-downgrade:** the loader rejects the v1 format (`ENVLK01`).
- **Trust store:** untrusted signer rejected; recovery key accepted only if it is in the store; malformed identity file, mismatched key pair, lax permissions or foreign ownership rejected **with the reason** (startup warning and compile error).
- **Multiple projects with different keys in the same process/host.**
- `require_once`, autoload, `include_path`, `__FILE__`/`__DIR__`, `strict_types`, templates, line numbers, default include return, `ParseError` recovery, 2000 repeated inclusions.
- **OPcache** (all checks use `opcache.file_update_protection=0`; otherwise OPcache skips files modified in the last 2 s and a "not cached" result proves nothing):
  - SHM cache active and no opt-in ⇒ the protected file fails closed; plain PHP is unaffected.
  - Active is decided exactly as OPcache does: `opcache.enable` parsed as a boolean (a quoted `"On"` counts) and, for CLI/phpdbg, `opcache.enable_cli` too. CLI with the stock defaults (`enable=1`, `enable_cli=0`, always present on PHP 8.5) runs protected files, because OPcache does not cache there.
  - `envelock.allow_opcache=1` + `opcache.blacklist_filename` on the protected tree ⇒ the protected file runs and `opcache_get_status()` shows it is **not** cached, while a plain file in the same run **is** cached (proving OPcache is active and only the protected tree is excluded). With the opt-in but **without** the blacklist the loader now **fails closed** (it detects OPcache is about to cache the file), instead of silently caching it.
  - `opcache.file_cache`/`file_cache_only`/preloading are always refused.
- **PHP-FPM production layout** (root master, `nobody` pool): identity file `root:0600` works and the worker cannot read it; an identity file owned by the pool user is refused.
- **Key rotation** through the real loader: after `promote-recovery`, new packages run on a server that was not updated; after `developer set` + `developer remove`, packages signed with the stolen key are refused.
- **PHP-FPM** (2 workers, several requests each): protected files run, plain PHP is unaffected, a tampered file is refused and the pool keeps serving, and the OPcache cases above hold across requests.
- **Encoder:** secrets are refused as assets by name and by content (identity magic, private-key field names in any encoding including UTF-16, PEM keys); links or junctions leaving the source tree are refused; links inside excluded folders are skipped.
- `inspect` emits only public data (verified: never private keys).

## Measured performance

Machine: Intel Xeon @ 2.1 GHz (2 vCPU). 300 PHP files of ~1.9 KB included in one process, OPcache off for the protected files, minimum of 7 runs (`python scripts/bench.py <envelock.so> [php]`):

| PHP | Plain (µs/file) | Protected (µs/file) | **Overhead (µs/file)** |
|---|---:|---:|---:|
| 8.2.35 | 25 | 262 | **237** |
| 8.3.6 | 27 | 245 | **218** |
| 8.4.27 | 24 | 250 | **226** |
| 8.5.12 | 26 | 256 | **230** |

The signature is verified once per include and each recipient key pair once at startup; measured with the same script on the same machine, this lowered the overhead from ~404 to ~230 µs per file (about −43 %). Since protected files are not cached by OPcache, the cost is paid per request: loading 300 protected files adds roughly 70 ms.

That per-file cost is dominated by the Ed25519 signature verify (on a faster host — this container, `openssl speed` — Ed25519 verify measured 87 µs). For `--enforce-manifest` packages the manifest fast path (`envelock.manifest_fastpath`, now **on by default**) collapses the per-file Ed25519 into the manifest's single signature, which is verified every request for enforcement anyway. A/B on this host (400 files, min of 9, PHP 8.3.6, startup subtracted): first compile ~127 µs/file without it, **~24 µs/file with it (about 5×)**, with identical output; `envelock.manifest_fastpath=0` restores the per-file verify (~121 µs/file). The change was reviewed at the time as adding no new trust; the 2026-11-10 audit showed that is only true when the server trusts a single developer (a trusted developer's manifest could otherwise vouch for another developer's file), so the fast path is now off whenever two or more developers are trusted, and the digests are seeded only after the whole manifest validates (`docs/AUDITORIA.md`, Pass 32). Fewer and larger files reduce the number of decryptions; measure with your real application.

## Measured memory

Synthetic large project: 2,000 class files (40 methods each), 11.0 MB of source, **all loaded on every request** (worst case; with autoloading a real application loads only the classes it uses). PHP 8.4.27 NTS, Linux x86-64.

**Envelock itself adds almost nothing.** Without OPcache, plain and protected use the same PHP memory:

| Without OPcache | PHP memory (peak) | Process RSS | Time |
|---|---:|---:|---:|
| Plain | 102.0 MB | 108.1 MB | 342 ms |
| Protected | 102.0 MB | 111.9 MB | 837 ms |

Per protected file the loader decrypts **in place**, inside the buffer where PHP read the encrypted file, and hands that same buffer to the compiler: the file is in memory only once (as ciphertext, then as plaintext), never twice, and the buffer is cleared and freed as soon as the file is compiled. Nothing is kept between requests. The maximum source size per protected file is 16 MiB.

Peak RSS of one PHP process loading one large protected file (11.4 MB, 10,000 methods with 22-line docblocks), PHP 8.4 NTS, OPcache off, best of 5 (`memory_limit=-1`):

| Loader | Peak RSS | With `pack --strip-comments` |
|---|---:|---:|
| Plain file, no loader (reference) | 46.9 MB | — |
| Previous loader (separate decryption buffer) | 72.6 MB | 31.0 MB |
| Decrypting into PHP's buffer | 61.8 MB | 29.9 MB |
| **Decrypting in place (current)** | **50.8 MB** | **28.9 MB** |

`--strip-comments` removes the docblocks PHP would otherwise keep in the compiled code (on the 2,000-class project with docblocks: 134 → 100 MB of PHP memory, −25 %). Regression tests: `test_php_protected_file_is_not_held_twice_in_memory`, `test_php_strip_comments_runs_and_saves_memory` and `test_php_later_compile_hook_cannot_orphan_the_plaintext`.

The extra protections (path binding, release consistency, minimum serial, include protection, no-prepend, FFI/`dl()` refusal, sealed tree, runtime manifest enforcement, debugger refusal) are checked once per file from the already-verified header, before decryption, and do not change the measured figures (the sealed-tree and `eval()` checks run only while a sealed package is active this request, so a package without `--sealed` pays nothing): on an A/B on the same machine (PHP 8.4, `scripts/bench.py`) the per-file overhead matches the previous version, and peak RSS for the 11.4 MB file stays at 50.6 MB (previous release 50.8 MB). Regression tests `test_php_file_bound_to_its_packaged_path`, `test_php_no_mixed_releases_in_one_folder`, `test_php_minimum_serial_refuses_old_releases`, `test_php_include_protection`, `test_php_include_protection_entry_under_web_sapi`, `test_php_include_protection_survives_userspace_stream_wrapper`, `test_php_include_protection_not_bypassed_by_another_developer`, `test_php_no_prepend`, `test_php_no_ffi_refuses_only_when_ffi_reachable`, `test_php_sealed_refuses_plain_php_under_tree`, `test_php_sealed_refuses_eval`, `test_php_enforce_manifest_detects_missing_file`, `test_php_enforce_manifest_bound_to_release`, `test_php_vault_runs_and_keeps_literals_out_of_the_source`, `test_php_vault_rejects_malformed_table`, `test_php_vault_runs_under_web_sapi_across_requests`, `test_php_rejects_zend_multibyte`, `test_php_opcache_without_blacklist_fails_closed`, `test_php_harden_memory_locks_keys`, `test_php_refuses_debugging_extensions`, `test_php_refuses_phpdbg`, plus `tests/test_transform.py` for `--obfuscate`; each fails if its protection is removed (mutation-checked).

**No leaks.** 20,000 includes of a protected file in one process: PHP memory 0.42 MB and process RSS 12.4 MB from the 100th include to the 20,000th. PHP-FPM, one worker, 30 requests each loading the 2,000 protected files: worker RSS 108.9 MB, unchanged from request 10 to request 30.

**The real difference is OPcache**, which cannot cache protected files (PHP-FPM, OPcache on with the opt-in + blacklist, one worker):

| Request | Plain (served from OPcache's shared memory) | Protected (compiled every request) |
|---|---:|---:|
| 1st | 24.0 MB | 100.0 MB |
| 2nd | 12.0 MB | 100.0 MB |
| 3rd | 6.0 MB | 100.0 MB |

Without OPcache's help, the compiled code of protected files lives in each request's own memory: it counts towards `memory_limit` and each FPM worker keeps that memory. See the recommendations in `MANUAL.md` (sections 14 and 19).

## Not verified here / pending CI

| Scope | Status |
|---|---|
| Windows x64 NTS/TS DLL | **CI** (cannot be built in this environment). The loader's Windows ACL check was compiled with mingw-w64 and partially exercised under Wine (which synthesises DACLs from Unix permissions). The encoder's Windows code ran with CPython for Windows under Wine (3.12 on October 29, 3.13.15 re-run October 31 after the `--no-ffi` change: 143 encoder/hardening tests pass, 5 skipped, the 2 symlink/junction tests fail) and identity-file replacement works; Wine does not emulate NTFS reparse points or real DACLs, so those two symlink/junction tests and the ACL tests are left to the Windows CI job |
| macOS, Linux ARM64, musl | **CI**/pending; no binaries built here |
| ZTS under real concurrent threads (threaded web server) | not verified; the ZTS build passes the suite in the single-threaded CLI |
| Apache SAPI, concurrent production load | not verified |
| Real third-party commercial applications | not verified |
| External audit / formal proof | not performed |

## Correct interpretation

This evidence reduces uncertainty within a specific scope. It does not prove the absence of bugs, does not certify all environments, and does not prevent the server administrator from capturing the decrypted source or reading the identity file. The limitations are not replaced by "maximum security".

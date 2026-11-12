# Code and security reviews — v2 format (1.0.0)

**Date:** October 24, 2026. **Type:** internal review by the team that implemented the code, with tools and tests executed, **plus independent reviews** by agents who did not write the code (one per large change, a comprehensive one, and a second full audit with verification of its fixes). **It is not an accredited external audit, a certification, or a guarantee of zero bugs.**

The results cover the files and the environment described. They do not prove advanced resistance to reverse engineering, confidentiality against root, or the security of untested systems. The measured evidence is in `docs/reports/` (regenerated with `scripts/regen-reports.sh`, not hand-edited).

> **Note on version naming.** The anti-root bytecode layer and the full-obfuscation work were developed internally under the **"2.0" codename**, and several passes below still refer to "the 2.0 architecture / tree / loaders". Nothing has been published yet: this work ships as part of Envelock's **first 1.0.0 release** (every anti-root/obfuscation capability is opt-in and off by default). "2.0" in this file is that development codename, not a released version.

## Pass 1: threat model and cryptography (v2)

The key flow, the signing≠encrypting separation, the order of verification, the domains/AAD, the nonces, the limits, the signature, and the absence of network in the loader were reviewed.

Conclusions:

- The content key is wrapped **per recipient** with X25519 + HKDF-SHA256 + AES-256-GCM (an ephemeral pair per wrapping). The `info`/AAD binds domain, version, project, release, ephemeral key, and recipient key: one entry does not work for another recipient or another release.
- **Only whoever holds the X25519 private key decrypts.** The loader is generic and public; having the engine or another developer's keys does not open other parties' packages. The restriction depends on holding the key, not on an `if`.
- Ed25519 is verified **before** any key agreement or decryption. The container is non-malleable (the signature covers everything except the final 64 bytes).
- **Anti-downgrade:** the v2 loader only accepts `ENVLK02`/version 2; magic and version are signed.
- **Per-installation trust store** (never from the package), with `developer_id = SHA256(public key)` and an optional recovery key (primary or recovery verify).
- There is no anti-replay/anti-rollback, expiration, hardware binding, or closed global manifest. The administrator can replace the loader or the files with normal PHP. The content AAD does not bind the file path (see "Open risks").

## Pass 2: independent reviews per change

Each large change was reviewed by an agent who did not write the code, comparing against the threat model. Summary (detail in the change log and in `VERIFICACION.md`):

- **KEM + `ENVLK02` format (obj 6):** no high findings. Fixed: reserve the Zend buffer before decrypting (do not leave cleartext uncleaned in the face of an OOM *bailout*) and require ownership of the identity file. The lack of path binding is documented.
- **`ENVLKID2` trust store + recovery (obj 7):** no high/medium findings. Fixed: rejection of an all-zeros primary signer; signature verification only once to choose the signer (avoids CPU amplification); reference decoder aligned with the loader.
- **CLI `inspect`/`recipient add`/`keygen` (obj 8):** no secret leakage via `inspect` and no high/medium findings. Fixed: `inspect` validates the exact package length; `recipient add` uses bounded reading and fills in a recovery key that was missing.

## Pass 3: static analysis and dependencies

Run on the v2 code (reports in `docs/reports/`):

- **Clang Static Analyzer** on `envelock_crypto.c`, `envelock_file.c` and the Zend adapter: no diagnostics.
- **bandit 1.9.4** on the encoder and scripts: 0 findings.
- **ruff 0.17.2**: no issues.
- **pip-audit 2.10.1** on the full hash-pinned lock (`requirements.lock`, all transitive dependencies): 0 known vulnerabilities (it does not cover unknown vulnerabilities, nor the system's PHP/OpenSSL, nor the whole native chain).
- Strict compilation of the C core and of `envelock_file.c` with `-Wall -Wextra -Wconversion -Wsign-conversion -Wshadow`: no warnings (the Windows part of `envelock_file.c` compiled with mingw-w64, same flags).

## Pass 4: dynamic testing and sanitizers

- **gcc AddressSanitizer + UndefinedBehaviorSanitizer** exerciser of the C core: valid container with mutation of each byte, all truncations and append, a 100 KiB container, and 200,000 random entries, through both the signature-first path and the post-signature path (`envelock_decrypt_verified`). No memory errors.
- **libFuzzer + ASan + UBSan** campaign (`scripts/audit-native.sh`), with leak detection, on a corpus that includes validly signed but broken payloads: **5,000,000 executions, no crashes, no leaks**.
- Native suite (real build of the extension + decryption) on **PHP 8.2.35, 8.3.6, 8.4.27 and 8.5.12** (Linux x86-64): **144 tests, 0 failures on each**. Includes impossible cross decryption, anti-downgrade, trust store/recovery, malformed identity file, permissions, OPcache refusal/opt-in with a control proving the cache probe works.
- **Real PHP-FPM** (`scripts/fpm_smoke.py`) on PHP 8.2, 8.4 and 8.5: protected files across workers and requests, plain PHP, tampered file, OPcache refusal, opt-in + blacklist not cached, and a control showing that without the blacklist the protected file *is* cached.
- **The sanitizers cover the cryptographic core, not a full instrumented build of Zend/PHP.** Windows, macOS and ARM64 run only in CI.

## Pass 5: binary hardening

`scripts/build-unix.sh` compiles the generic extension (no keys) with: `-O2`, `-fstack-protector-strong`, `-fvisibility=hidden`, `-D_FORTIFY_SOURCE=2`, and on Linux additionally `-fstack-clash-protection`, `-fcf-protection=full` (CET, x86-64), linked with `-Wl,-z,relro,-z,now,-z,noexecstack,-z,separate-code`, `-ffile-prefix-map` (no build paths embedded) and `strip` of local symbols. Checked on the delivered Linux binaries with `readelf`/`nm`: full RELRO + BIND_NOW, non-executable stack, CET (IBT, SHSTK), stack protector present. No `_chk` FORTIFY calls appear because every buffer size is provable at compile time; the flag was verified to reach the compiler. Removing symbols and hardening the binary increases the difficulty of analysis; it does **not** constitute a cryptographic barrier.

## Pass 6: comprehensive independent review

An agent who did not write the code audited the whole of v2 (key lifecycle and end-to-end cleartext, loader↔crypto↔Zend interaction, parsing of untrusted inputs, binary hardening, encoder, and model↔implementation coherence), additionally verifying that the hashes in `targets.json` match the live sources. **Verdict: no high or medium findings**; the whole is coherent, with no half-states, double frees, or length confusion, and it fails closed on all paths. Four low/informative observations, of which three were applied:

- **[applied]** The loader reserved the Zend buffer with a size taken from the header (up to 16 MiB) before verifying, without cross-checking it against the actual file size: a tiny file that lied about its size forced a large transient reservation. Now the total declared length is cross-checked against the real blob before reserving.
- **[applied]** `build-unix.sh` replaced the hardening if the environment brought `CFLAGS`/`LDFLAGS`; now it concatenates (FORTIFY/stack-protector/RELRO… are never lost) and `-Werror=format-security` and `-Wl,-z,separate-code` are added.
- **[applied]** The encoder sets `umask(0o077)` so that the parent directories of the secret files do not depend on the operator's umask (the files were already `0600`).
- **[informative, optional]** `_FORTIFY_SOURCE=3` where available and hardening equivalents for macOS if native binaries are distributed; noted for objective 11.

No secret leakage was detected (including via `inspect`), no trust store bypass, and no breach of any threat-model guarantee.

## Pass 7: second independent audit and verification of its fixes

A new agent, without access to the previous audit, reviewed the whole code against the threat model and confirmed its findings with proofs of concept. **No critical or high findings.** All findings were fixed, each with a test that fails without the fix, and the same agent then re-ran its proofs of concept on the fixed code:

- **[medium, fixed]** OPcache directives were read as integers; a quoted `"On"` in `php.ini` is read by OPcache as enabled but was read as 0, so decrypted opcodes could be cached without the opt-in. Now parsed with `zend_ini_parse_bool`, exactly like OPcache.
- **[medium, fixed]** `pack` recognised secrets only by exact file name; a renamed identity file or key descriptor was copied in clear as an asset. Now also by content (`ENVLKID2` magic, private-key field names in any encoding including UTF-16, PEM private keys, any JSON descriptor) and by name patterns.
- **[low, fixed]** No permission check on the identity file on Windows. Now an allow-list on the owner and the DACL (PHP service account, SYSTEM, Administrators, OWNER RIGHTS); anything else is refused.
- **[low, fixed]** Encoder on Windows: a junction is not a symlink to `is_symlink()` and there is no `O_NOFOLLOW`. Now anything whose real path leaves the source tree is refused.
- **[low, fixed]** CI installed dependencies without hashes. Now universal hash-pinned locks with `--require-hashes`, and checkouts without persisted credentials.
- **[informative, fixed]** The signature was verified again for every recipient tried; now once per include, and each key pair once at startup (also a −42 % per-file overhead).
- **[informative, fixed]** A rejected identity file was silent; now a startup warning and a compile error with the reason.
- **[informative, fixed]** A deeply nested JSON crashed the encoder with a traceback; the FPM CI step only ran `php-fpm -t`; the fuzzer barely reached post-signature code; links inside excluded folders (pnpm) aborted `pack`; the TSRM cache is now also refreshed in MINIT.
- **[informative, documented]** With `zend.multibyte=1` the Zend scanner keeps an uncleared copy of the source, and a `ParseError` can contain fragments of it (only reachable by whoever reads the process memory or logs).
- **[informative, fixed after the owner's decision]** Private keys were not encrypted by default, and the CLI could not remove a developer, replace a recovery key, or even sign with the recovery key. Now keys are encrypted by default (`--no-encrypt` is explicit), and `owner new-recovery`, `owner promote-recovery`, `export-developer`, `developer set` and `developer remove` implement the rotation, with an end-to-end test through the real loader.

## Pass 8: third full review (after encryption by default and key rotation)

A new agent reviewed everything that ships (C, encoder, scripts, CI, tests and documentation against the code). **No critical or high findings.** Fixed, each with a test where it can be tested here:

- **[medium]** The manual told operators to make the identity file owned by the PHP service (pool) user, which PHP-FPM refuses (its master reads the file at startup as root) and which would also let the workers read the keys. Now: owned by the user that starts PHP, `0600`. `scripts/fpm_smoke.py` covers the production layout when run as root (root master, `nobody` pool): protected files run and the worker cannot read the identity file.
- **[medium]** Identity-file changes take effect only after a PHP restart; this was not documented. Now documented, and every identity-file command prints the reminder.
- **[medium]** On Windows, rewriting the identity file with the encoder gave it the folder's inherited ACL. Now replaced with `ReplaceFileW`, which keeps the original ACL (Windows-only test in CI).
- **[low]** `owner new-recovery` wrote a new private key in clear into an unencrypted owner file; `recipient add` silently kept a stale recovery key; `developer set` silently replaced or dropped one; the release guard passed vacuously when the scanned tree was under a folder named `release`/`private`/`build`; key-file writes were not fsynced.
- **[low, found while verifying the fixes]** On Windows the temporary identity file briefly had the folder's permissions, and the owner was not kept: now the file is created already carrying the original DACL (`CreateFileW` with a security descriptor), then gets the original owner (enabling `SeRestorePrivilege` when needed) before any key is written. The release guard skipped `build/` and missed `.key`/`.bak`/`.env`/UTF-16 secrets, and reported every protected package as unreadable: fixed, with tests.
- **[informative]** A FIFO as identity file blocked PHP startup; a duplicate developer with two recovery keys was silently resolved; no `recipient remove`; tests that could pass for the wrong reason; the CI static analyzer did not fail the job nor analyze the Zend adapter; and a list of doc/code mismatches.

## Pass 9: review of the CPU and memory changes

Independent review of the per-worker caches (verified signatures and package keys, never code) and of in-place decryption, checked against the PHP 8.2 and 8.5 Zend sources. No way found for a tampered file to pass the caches; in-place AES-GCM, buffer sizes and length arithmetic confirmed correct. Findings:

- **[medium, fixed]** The decrypted code was compiled through a new filename-type handle. A compile hook that Envelock chains to and that reopens such handles (as OPcache does) would discard it, re-read the stub from disk and leave the decrypted buffer in memory uncleared until the end of the request (it still failed closed). Envelock now decrypts and compiles the original handle and clears the buffer right after compiling. Regression test with a test-only hook extension (`tests/reopen_hook/`), which fails with the previous loader.
- **[low, documented]** With `zend.multibyte=1` the Zend scanner makes its own uncleared copy of the source (already listed in `SEGURIDAD.md`).
- **[informative]** A file without a valid signature costs one Ed25519 verification per trusted signer (CPU only).

## Pass 10: external security reviews (October 29)

Six external reviews (two AI audits, one 18-finding audit, three improvement notes) were reproduced in code; only what reproduced was applied, each with a test that fails without it (mutation-checked against a clean build). One recurring report claim was wrong: the file's relative path is already in the AES-GCM AAD, so "add the path to the AAD" was already done. Applied:

- **[high, fixed]** Include protection could be bypassed by a user-space stream wrapper that forged the compiled file's `opened_path` to the main script's path, so an included file passed as the entry point. The entry-point fallback now also requires that no user frame is executing (`EG(current_execute_data) == NULL`). Regression test with such a wrapper.
- **[high, fixed]** With several developers trusted in one identity file, one could pack a container under another's project id (signed with their own trusted key) and load that project's include-protected files. The verifying developer is now bound into the per-folder/per-file tracking, so `called_from_project` requires the same project **and** the same signer.
- **[medium, fixed]** OPcache SHM is now self-checking: with `allow_opcache=1` but a missing or wrong `opcache.blacklist_filename`, the loader sees `ZEND_COMPILE_IGNORE_OTHER_FILES` (set only when OPcache is about to cache the file) and fails closed on the first request, instead of silently caching decrypted opcodes. Supersedes the "cannot verify the blacklist from inside" note.
- **[medium, fixed]** `zend.multibyte` now makes protected files fail closed (supersedes Pass 9's "documented" note): its encoding filters are an ambiguous lexing path for protected code. The reported source-disclosure via `zend.multibyte` + `zend.script_encoding` did **not** reproduce on 8.2–8.5; the guard is defence-in-depth.
- **[medium, fixed]** Obfuscator corruption: `new readonly class` / `new #[Attr] class` are now recognised as class scopes (their public properties are not renamed as locals); a `use function compact as …` alias is tracked; a file with `__halt_compiler()` is passed through untouched.
- **[medium, fixed]** Asset scanning rejects more readable PHP and secrets: PHP tags on the decoded text (UTF-16, short `<?`), more PHP extensions (`.php5/.php7/.phps/.phar/.ctp`) and local databases / credentials (`.sqlite/.sql/.htpasswd/.ppk`).
- **[medium, fixed]** Windows secret files created fresh get a protected ACL (SYSTEM, Administrators, the creating user) instead of inheriting the folder's; on failure the file is removed and the command asks to elevate.
- **[low, added]** Opt-in `envelock.harden_memory`: lock the private keys into RAM, exclude them from dumps, mark the process non-dumpable. Validate the header before allocating in `open_alloc`. Reject a recovery key equal to the primary signer. GUI password length counts characters. `/CETCOMPAT` on the Windows loaders; the Linux loader ships `0644`.
- **Not reproduced / out of scope:** the reported header-parsing RCE (no PoC; parser bounds and the libFuzzer/ASan campaign stand); anti-debugging (`ptrace`/`IsDebuggerPresent`), hardware/IP binding and OLLVM on the loader were all previously declined (easily patched, or incompatible with an open, auditable engine).
- **Not yet done (next round):** expand the debugger/compile-hook detection to `zend_extensions` (FFI, pcov, SG Optimizer); sign-verify headers in `minimum set --package`; `CreateFileW` (UTF-8, no UNC/pipes) for the Windows identity open; Authenticode chain check for the VC redist installer; the remaining small GUI/CLI items.

## Pass 11: review fixes and hardening (October 31)

Acting on the external reviews of Pass 10 (the high-value report and the cheaper findings), with a failing test per change (mutation-checked on a clean `phpize` build), no measured regression, and the documentation updated.

- **[medium, fixed]** Hardened build could silently ship an unhardened module: on GCC ≥ 14 `-Werror=format-security` without `-Wformat` is a hard error that aborted the build and fell back to a plain module exporting ~23 `envelock_*` symbols. `-Wformat` is now added on Unix; the Windows SDK build (`config.w32`) applies the same `/guard:cf /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /CETCOMPAT` as the Wine build. A test asserts the committed Linux loaders export no `envelock_*` symbols.
- **[medium, fixed]** `envelock.harden_memory` now defaults to **on** (`1`) and is re-applied in `RINIT`, so the non-dumpable/`mlock` protection survives a worker that drops privileges after startup; the cached per-file content keys are also locked, not only the identity. Set `0` to allow a profiler or core dump.
- **[medium, fixed]** Debugger/compile-hook detection expanded to more instrumentation `zend_extensions` (xhprof, tideways, ddtrace, spx, pcov, blackfire, memprof) and any registered `zend_ast_process` hook (closes the Pass-10 "next round" item).
- **[low, fixed]** Encoder robustness: `parse_package` turns a non-UTF-8 or non-relative embedded path into a clean error instead of a raw traceback (M-05); package output has deterministic permissions (dirs `0755`, files `0644`) regardless of the caller's umask, never `0666` (M-06); a secret's parent directory is created `0700` (L-01); the CLI password length is measured in characters to match the GUI (L-04); the `./envelock` launcher exits `2` with guidance when no portable Python is present, instead of a cryptic `exec` failure (L-10).
- **[low, fixed]** `pack` refuses the PUBLIC demo keys (their private halves are published, so a package made with them protects nothing) unless `--allow-demo` is given for testing.
- **Docs:** corrected the manual — `envelock.identity` is `PHP_INI_SYSTEM` and a per-pool `php_admin_value[envelock.identity]` is ignored (read once at startup); use one identity file with several entries, or separate FPM masters. `harden_memory` documented as on by default.

## Pass 12: reproduce ENV-10/11/14 and a further bug hunt (October 31)

Taking the remaining external-report findings and actively hunting for new defects. Each confirmed bug has a test that fails without the fix.

- **[medium, fixed] ENV-14 — Windows identity path:** on Windows the loader opened the identity file with `fopen()`, which reads the `php.ini` value in the ANSI code page and fails on any non-ASCII path (reproduced under Wine: an identity at `…\idéñ.bin` was refused with "cannot be opened", while the same file at an ASCII path loaded). It now converts the UTF-8 path with `MultiByteToWideChar(CP_UTF8)` and opens through `_wfopen`, and refuses the UNC and device namespaces (`\\server\share`, `\\?\`, `\\.\`): the identity must be a local, access-controlled file, never a remote share or a device/pipe. Verified under Wine that ASCII paths still load and UNC is refused; the non-ASCII success is a real-Windows check (Wine's Z: drive cannot present the non-ASCII name as UTF-16).
- **[low, fixed] Windows launcher parity:** `envelock.cmd` now exits `2` with guidance when the portable Python is absent, instead of a cryptic "cannot find path" (the same backstop the `./envelock` launcher got as L-10).
- **ENV-10 — not reproduced:** the crypto core cannot write out of bounds — `envelock_parse_header` requires the blob length to equal exactly `header + path + table + size + tag + signature`, and `open_blob` refuses when the declared size exceeds the output capacity; the in-place decrypt writes exactly `size` bytes inside the handle's own buffer. The AddressSanitizer/UndefinedBehaviorSanitizer exerciser (all single-byte mutations, all truncations, 200 000 random inputs, into a caller buffer and in place) reports no errors.
- **ENV-11 — not reproduced:** the encoder already refuses every symbolic link (to a file outside the tree, to a directory, and to another file inside the tree) and every Windows/macOS path collision, including NFC-vs-NFD Unicode duplicates (the collision key is NFC-normalised and case-folded). Confirmed with a direct reproduction of all four cases.
- **Bug hunt (no new defects):** reviewed the signature and content-key caches (the signature is verified before every decryption, even on a cache hit; caches are keyed by SHA-256, size-capped, and `pemalloc` aborts rather than returning NULL), the identity-store mutations (`build_identity_store` enforces the 1–64 and ≤256 caps before anything is written, and `write_store` is atomic), `inspect` and the CLI error handling (every parser is length-checked; all exits go through `ValueError`/`KeyError`/`TypeError`, no stray `struct.error`), and the per-package nonce scheme (new content key per pack, monotonic file nonce, per-recipient ephemeral and random wrap nonce — no reuse).

## Pass 13: string-literal vault (`--vault-strings`) (November 1)

Three independent read-only agents (C loader / Python encoder / GUI, tests, docs) reviewed the literal vault; findings reproduced before applying.

- **C loader — no findings.** The prefix parser `envelock_parse_vault` was extracted verbatim into an ASan+UBSan harness and driven with every boundary case, an exhaustive small-input brute force and 2 000 000 random inputs — no out-of-bounds, overflow or bad `source_len`; the per-request `litvault` life cycle is leak-free under Valgrind (bailout, NULL `result->filename` and success paths each release the table exactly once); `__envelock_lit` is safe for a negative/out-of-range index, an unregistered file and a request with no table (returns `""`, never faults).
- **[high, fixed] Encoder — a broken file could be produced.** `_vault_pass` could return a file that did not compile: a literal vaulted inside a **multi-line** property default or enum case made `php -l` fatal, but the lint anchored the error on the declaration's first line while the pass excluded by the literal's line, so they never converged and the loop returned the broken file. Fixed two ways: the vault pass now reports the lines it actually vaulted and the exclusion targets the first vaulted literal at/after the error line (converges), and before returning, every file is re-linted and a still-broken file aborts the pack (fail-closed — a broken file can never be shipped). Reproduced and verified on multi-line property/enum cases.
- **[low/medium, fixed] PHP 8.5 stdout corruption.** The Wine matrix caught that on a PHP 8.5 build whose CLI defaults `display_errors` on, a new "null as array offset" deprecation was printed to stdout and corrupted the transform's JSON (it affected `--strip`/`--obfuscate` too). The transform helpers are now run with `display_errors=stderr` (the JSON owns stdout) and silence their own deprecations; behaviour is unchanged (checked by the differential fuzzer across versions).
- **Web-SAPI validation:** the vault was confirmed under the built-in server (cli-server SAPI, like mod_php) across interleaved requests, under ZTS with 40 concurrent requests, and under real PHP-FPM — the per-request table is correct on reused workers. Regression test `test_php_vault_runs_under_web_sapi_across_requests`.
- **GUI/tests/docs:** no serious findings; three minor doc fixes applied.

## Pass 14: three external audits, reproduced and fixed (November 2)

Three external reports (one Windows-focused, one full Debian-toolchain run, one 2.0 recommendations set) were processed under the standing rule: **reproduce each claim in code before applying, apply only what reproduces, and record what was discarded with the reason.** Each applied fix carries a test that fails without it; Windows-only items were exercised under Wine where the mechanism allows.

Reproduced and fixed:

- **[A1/ENV-AUD-08] `--manifest` + `--enforce-manifest` produced an unverifiable package.** The binary manifest is now written before the JSON manifest so the JSON inventories it; `verify_package` gives a clear error when only the binary manifest is present.
- **[A4] Config assets with embedded credentials** are refused unless `--allow-secret-assets` is given.
- **[ENV-AUD-01] `madvise(MADV_DONTDUMP)` EINVAL** from an unaligned range: key pages are page-aligned before `mlock`/`madvise`; the real guarantee (process non-dumpable via `prctl`) was already in force.
- **[ENV-AUD-02/03/04] manifest/sealed path checks:** reject a non-regular manifest file; a failed manifest check no longer poisons the per-request roots table; a sealed package refuses a symlink whose requested path is inside the tree; a legitimate `../` include that resolves outside the sealed tree is allowed (lexical normalization, no filesystem/symlink follow).
- **[ENV-AUD-07] demo keys** are refused by `pack_tree` itself (CLI, GUI and API), not only the CLI.
- **[ENV-AUD-09/10/12] obfuscator correctness:** dynamic static calls `Class::$method()` keep working; property and method passes reserve all class members and skip classes with a parent, so no `Cannot redeclare`/fatal.
- **[ENV-AUD-13] vault never ships a broken file** (re-lint + fail-closed; see Pass 13).
- **[ENV-AUD-14] cross-developer rollback DoS.** A minimum is now bound to the developer that set it (its primary key is stored in the entry); the loader applies it only to packages signed by that same developer. Identity format bumped to `ENVLKID3`; the legacy format is still read.
- **[ENV-AUD-17] include protection across primary/recovery keys.** The loader binds a package to the DEVELOPER (primary and recovery keys of one developer are equivalent), not the signer slot, so a hotfix signed after `promote-recovery` is still "its own application".
- **[ENV-AUD-18] ZTS/UNC:** the per-request re-assert of non-dumpable no longer uses a racy `static int` (idempotent syscall each request); the runtime manifest is opened with a path opener that accepts UNC/extended-length paths (its integrity comes from its signature, not from local ACLs), while the identity file keeps its UNC rejection.
- **[ENV-AUD-16] assistant/GUI/build:** GUI `promote-recovery` now always offers to encrypt the new owner file (fresh private keys) and writes plaintext only on explicit confirmation; `install_vc_redist` verifies the signature and launches in one PowerShell process (no TOCTOU) with an anchored Microsoft-organization RDN, the Code Signing EKU and a Microsoft root; `pack` accepts a public or your own private recipient and refuses an encrypted one with an actionable message; the PyInstaller build tool is hash-pinned when a per-OS lock is present.
- **[A2/A3/B1/B2 — Windows, validated under Wine] identity-file I/O:** updating an identity whose DACL does not grant the current user `DELETE` no longer fails with `WinError 5` (the temporary is created with a protected DACL that grants the updater, keeping the model's owner); the password prompt detects a real console with `GetConsoleMode` so a redirected `NUL` fails closed instead of hanging; the release guard normalizes Windows `\` paths; the ACL test matches ACE identities, not a substring of the temp path.
- **[ENV-AUD-15] secure-by-default:** a bare `pack` (base encryption + signing only, every optional layer off) now prints an advisory naming the hardening flags; the defaults are unchanged (flipping them would break existing deployments).
- **[ENV-AUD-19] source-tree hygiene:** the prebuilt-symbols test skips when `prebuilt/` is absent; `bandit` scans `fuzz_obfuscator.py` and the `# nosec` comments use the `# nosec <id> # reason` form (no parser warnings).

Discarded after failing to reproduce, with the reason recorded:

- **[ENV-AUD-05] vault exfiltration — false.** `array_map('__envelock_lit', …)` from a plain file returns `""`: `zend_get_executed_filename_ex()` yields the attacker's own file, which has no vault. The report conflated an app-level callable misuse with a vault flaw.
- **[ENV-AUD-19.3] missing docs — false.** `docs/MANUAL.md` and `docs/BUILDING.md` exist with those names; the report assumed Spanish file names (`MANUAL.es.md`, `COMPILACION.md`) that this tree does not use. The references are correct.
- **[ENV-AUD-15.2] detecting `zend_observer`/`zend_execute_ex`/custom opcode handlers — not applied.** `envelock_debugger()` fails protected files closed; refusing whenever an observer is present would stop protected code from running under standard production APM (New Relic, Datadog, Elastic APM, OpenTelemetry, Sentry), a severe availability regression for a layer that is explicitly best-effort and does not claim to defeat an operator who can load a PHP extension. Documented as a known limit in `SEGURIDAD.md` instead.

## Pass 15: independent continuation reviewed, ported and verified (November 5)

An independent continuation of the project (a separate attempt at the 2.0 roadmap) was supplied as
an archive. Under the standing rule — reproduce before applying — it was **not** built from the
untrusted tree. Every piece was reviewed statically, then ported into this repository and verified
here with the project's own suite, keeping the canonical `third_party/`, `prebuilt/` and the
release guard intact.

Adopted after review and verification:

- **O1 bytecode layer** (`extension/envelock_bc.h`, `extension/opcache/<ver>/`, `gen_persist.py`).
  The persistence code is a mechanical rename of Zend OPcache's own (`zend_persist.c`,
  `zend_file_cache.c`) with SHM swapped for a process arena and `zend_system_id` kept as the
  fail-closed version gate — reused, tested engine logic rather than a hand-written serializer.
  The build makes the layer **optional and per version** (`config.m4`, `-DENVELOCK_HAVE_BYTECODE`):
  a PHP without a matching layer builds a source-only loader. *Verified:* round-trip pack→run on
  PHP 8.4, 13/13.
- **O2/O3/O5/O6/O7/O8** (secret handling, anti-rehook, root-owned identity install, AST
  obfuscation, encrypted vault, licensing + trusted time). *Verified:* O2+O3+O8 native 27/27 on
  8.4; O6 functional on 8.3 with the differential fuzzer at 0 divergences; O7 wire format and
  loader parser cross-checked against the encoder (`FLAG_VAULT_ENC`, bit 7).
- **O4 opcode VM** kept **experimental**, quarantined behind `--unsafe-vm-laboratory`; documented as
  laboratory-only in `MANUAL.md` §14.4, not part of the production recommendation.

Fixed during the port:

- A stale native test expectation (`FOREIGN_IDENTITY` message) updated to the O5 wording that now
  accepts mode `0400` and root ownership.
- The 8.3 bytecode shim shipped by the continuation was 8.4-specific
  (`get_class_name_map_ptr` signature differs); the broken `opcache/php83/` was removed so 8.3 builds
  source-only. Per-version shim adaptation is deferred to the multi-version close.

Verified counts (see `docs/VERIFICACION.md`): encoder+Python suite on 8.3.6 — 412/412; O1 bytecode
13/13 on 8.4. The native suite on 8.3.6 first ran 941 passed / 3 failed / 22 skipped, the 3 failures
being the AST→bytecode combination, which needs the tokenizer and a bytecode layer in the **same**
PHP. **Closed November 5:** a per-version bytecode layer was generated for 8.3.6 (which has the
tokenizer) — `extension/opcache/php83/`, one shim delta adapted (`get_class_name_map_ptr` returns
`uint32_t` on 8.3 vs `void` on 8.4) — and the native suite is now **956 passed / 0 failed / 10
skipped**, the AST→bytecode combination included. **Per-version layers extended to 8.2 and 8.5 the
same day** (`extension/opcache/php8{2,3,4,5}/`): each compiles and passes the bytecode round-trip
(13/13); 8.5 needed one generator fix (its SHM loader was split into `..._load_ex`, added to DROP).
Still **pending**, to be closed in CI / Miguel's environment: the AST→bytecode combination on 8.2/8.5
(no tokenizer on those builds here) and the real Laravel/Symfony boot (O11, packagist unreachable
here).

## Pass 16: full deep code audit of the 2.0 tree (November 7)

A complete read-only audit of the 2.0 architecture by three independent reviewers (loader C /
encoder Python / crypto and build), followed by static analysis. Every finding was reproduced in
code before any fix, and each fix carries a test that fails without it (mutation-verified on a clean
rebuild of the fixture).

**Crypto core — sound.** Signature-before-decrypt ordering (including the per-worker `verified`
cache), X25519+HKDF key wrap, AES-256-GCM, Ed25519, per-package content key, monotonic file nonce
and per-recipient wrap nonce: no reuse, no bypass path found.

**Loader — one CRITICAL, one HIGH, one MEDIUM, all fixed.**

- **CRITICAL — `envelock_bc_run` remote code execution.** The proof-of-concept userland function
  `envelock_bc_run()` deserialized *caller-supplied* bytes through the OPcache unserializer, i.e. it
  turned attacker bytes into a live `zend_op_array` and executed them — arbitrary code execution
  reachable from any PHP that could call the function. Fixed by gating the PoC userland surface
  (`envelock_bc_emit`/`envelock_bc_run`, their arginfo and FE table entries) behind a build-time
  flag. That single flag was later split (ENV-2026-02) into two explicit `./configure` options,
  `--enable-envelock-bcemit` (defines `ENVELOCK_BCEMIT`, the emitter) and
  `--enable-envelock-bcrun-unsafe` (defines `ENVELOCK_BCRUN`, the runner), mirrored in `config.m4`
  and `config.w32`; the sources no longer read any `ENVELOCK_BCPOC` environment variable. A
  server/production loader passes **neither** flag; only the test suite builds with them. *Verified:*
  `bc_run`/`bc_emit` are absent
  as symbols **and** as strings from all five production loaders, which also export zero `envelock_*`
  symbols (M-01 hardening holds).
- **HIGH — `envelock_bc_emit` exposed bytecode emitter.** Same PoC surface, same gating; a server
  loader no longer exposes an unauthenticated path that compiles an arbitrary file path to bytecode.
- **MEDIUM — sealed-mode state was per-request.** `sealed_active` / `envelock_under_sealed_root`
  read the per-request `roots` table, so the plain-PHP-under-a-sealed-root gate depended on
  request-local state. Fixed by moving the sealed set to a **per-worker** `HashTable sealed_roots`
  in module globals (`GINIT`/`GSHUTDOWN`), populated when a sealed package's root is registered and
  iterated per worker; the gate now always consults the worker-level set. The manifest fast-path
  (`envelock.manifest_fastpath`, opt-in, default off) was reviewed in the same pass and found
  **sound** — it only seeds the per-worker `verified` cache with digests from an already
  signature-verified manifest. (Superseded by Pass 32: on a server that trusts several developers that
  seeding let one developer's manifest vouch for another developer's file.)

**Encoder — sound.** Vault pass fail-closed (re-lint before returning, abort on any non-compiling
file), obfuscation trait-safety gates, manifest `.bin` builder, path/serial from the signed header
(ENV-09): no new findings.

**Static analysis:** clang analyzer on `envelock.c` — 0 warnings; release guard
(`scripts/check_release.py`) — pass (no private, personal or attribution material); brand/privacy
and forbidden-terms scan over the deliverable source — clean.

**Windows 2.0 portability — open finding (not a regression).** The 2.0 modules
(`envelock_secret.c`, `envelock_integrity.c`, `envelock_licence.c`, `envelock_clock.c`,
`envelock_trusted_time.c`) use POSIX headers. Four carry partial `_WIN32` guards but the porting is
incomplete (an unguarded `unistd.h` in `envelock_licence.c`; `envelock_integrity.c` has no guards),
so a Windows build does not yet compile cleanly. `config.w32` and `scripts/build-windows-wine.sh`
were updated to the full 2.0 source list and the same hardening flags, but completing Windows 2.0
needs `#ifdef _WIN32` porting of those modules and validation on **real** Windows (the Wine MSVC
toolchain here raises an internal compiler error on the POSIX includes, so it cannot validate the
result). **Linux 2.0 is fully built and tested.**

**Deferred (LOW / informational):** consider deriving the content key and the wrap key through
distinct HKDF `info` labels rather than a single dual-use content key (crypto L1); the encoder's
pack-wide name-obfuscation disable on a `$risky` global is conservative by design (informational).
Both are tracked for the next round; neither is exploitable within the threat model.

**Verification (this pass):** native suite on PHP 8.3.6 (tokenizer present) **960 passed / 10
skipped**; the ZTS loader cycle (sealed / eval-regression / `--no-ffi` / enforce-manifest) clean on
8.4 ZTS; the ZTS vault tests fail only because that 8.4-ZTS build lacks the `tokenizer` the encoder
needs to *pack* a vault (an environment limitation, not a loader defect — the same tests pass on
8.3.6); Python suite (encoder/hardening/transform/GUI/prebuilt) **253 passed / 1 skipped**.

**Verdict:** within the stated threat model (web attacker or file reader, not root) the 2.0 loader
and crypto are sound; the one path that would have been catastrophic — the PoC bytecode run/emit
functions — is now excluded from every server build. The remaining real gap is Windows 2.0 module
portability (Linux is complete), plus the standing root-extraction limit below.

## Pass 17: external-audit round and a performance default (November 8)

Five external audits (one with real compile + FPM + fuzzing + strace, four with compile + runtime on
8.3.6) of the GitHub source archive. Verdict across all: modern crypto, honest threat model,
exceptional test coverage, no open critical findings (they confirm the PoC bytecode functions are
absent from production). Two findings were actionable; both were reproduced before any change, each
fix carrying a test that fails without it.

- **O8 trusted-time startup fetch was inert (Medium-High).** Reproduced by reading MINIT and with
  strace: MINIT read `envelock_licence_present` before `envelock_load_licence` set it, so the
  per-worker HTTPS time fetch never ran (strace showed 0 `connect()` at startup), and the network
  floor check was nested under `envelock.clock_state` so deleting the state file disabled it. Fixed:
  MINIT now loads the clock state and the license before the trusted-time block; the floor is enforced
  independently of the state file. The old loader attempts no connect at startup, the fixed one
  attempts one — regression test `test_o8_trusted_time_is_fetched_at_startup`.
- **`scripts/audit-native.sh` / CI `fuzz` job broke out of the box (Low-Medium).** It packed the demo
  corpus with the public demo owner key (which `pack_tree` refuses) and did not copy the extension's
  local headers for the standalone clang analysis. Both fixed; the helper now exits 0 and runs the
  libFuzzer campaign (300 runs locally, 2,000,000 in CI) with no crashes.

Triaged as documented limitations or low/not-reproduced (reported to the owner, not changed here):
manifest runtime is existence-only (the offline `verify` checks hashes); the 4 clang warnings in
`envelock_vm.c` (the experimental O4 VM) are probable Zend-macro false positives; the clock watermark
is a per-process best-effort value under ZTS; the Bandit HIGH is a `chmod 0777` in a test fixture.

**Performance (measured, this round).** The protected per-file cost is dominated by the per-file
Ed25519 verify (87 µs by `openssl speed` on this host); the per-worker cache already skips it on
repeat requests. Measured first-compile cost (400 files, min of 9, startup subtracted): plain 17–19,
protected 121–127, and **24–26 µs/file with the manifest fast path** — about 5×. `envelock.manifest_fastpath`
was therefore changed from opt-in (default off) to **on by default under `--enforce-manifest`**:
that package's manifest signature is verified every request for enforcement anyway, so seeding the
verified cache from it adds no new trust (independently re-reviewed; **superseded by Pass 32**: with two
or more trusted developers it did add trust, and the fast path is now off in that case). `envelock.manifest_fastpath=0`
restores the per-file verify (measured: back to ~121 µs/file). Behaviour is identical either way, only
cost differs. Ed25519 itself cannot be made faster safely; avoiding N signatures via the one signed
manifest is the only safe lever and it is now the default where a manifest exists.

## Pass 18: Windows 2.0 port, with the bytecode layer (November 8)

The 2.0 loader now builds and runs on Windows, including the bytecode layer (O1) — closing the open
finding from Pass 16. Ported against the MSVC/Windows toolchain under Wine:

- **Stray POSIX includes guarded.** `envelock_licence.c` included `<unistd.h>` unconditionally (it is
  needed only in the POSIX branch); `envelock_clock.c` included it before the `PHP_WIN32` guard. Both
  guarded. `envelock_integrity.c` was already portable (it keys its `/proc` code on `__linux__`, so
  non-Linux takes the "unknown" branch), contrary to the Pass 16 note.
- **VM `noinline` made portable.** `envelock_vm.c` used `__attribute__((noinline))` (GCC/Clang);
  added `ENVELOCK_NOINLINE` (`__declspec(noinline)` on MSVC).
- **Host-name lookup made Winsock-free.** The Windows branch of the served-host helper used
  `gethostname` (a Winsock call needing `WSAStartup`); it now reports "no host" like the machine
  fingerprint, so a domain-bound license is refused on Windows and an unbound one works — no Winsock
  dependency.
- **Bytecode layer ported.** The per-version `opcache/php<MM>/` files (and `gen_persist.py`) included
  `"php_config.h"`, which does not exist on Windows (it is `config.w32.h`, pulled in by `php.h`); that
  include is now guarded `#ifndef PHP_WIN32`. The Windows devel pack already ships the internal Zend
  headers the layer needs (`Optimizer/zend_optimizer.h`, `zend_system_id.h`, …).

**Verification (under Wine, MSVC VS2017 toolchain, PHP 8.2–8.5 × NTS/TS devel packs):** all 8 DLLs
compile and link with the bytecode layer. 7 of 8 load and run a source package; 8.2 NTS does not load
only because that PHP build's bundled VCRUNTIME is an incompatible version under Wine (the DLL is
built from the same source and toolchain as 8.2 TS, which passes) — a Wine/runtime artifact to
confirm on real Windows. The **full bytecode round-trip** was verified on 8.4 NTS and 8.5 NTS: a
package compiled to bytecode by the Windows PHP (via a BCPOC Windows DLL) runs on the production DLL
and executes from bytecode, not source (`WIN-BYTECODE-OK 42`). Linux remains at 962/10 native, and
its loaders were rebuilt from the same source (the shared `.c` changes are no-ops on Linux: the
`noinline` macro is identical, the guarded includes still compile in). macOS: the source carries
POSIX and `__APPLE__` branches and should build the same way, but is not compiled or tested here —
left to CI / a real Mac.

## Pass 19: WordPress end-to-end, a real third-party CMS (November 8)

Took the open "real third-party applications: not tested" item and ran a full CMS core (WordPress,
2086 PHP files) through both protection modes against a live MariaDB, on the built-in server.

- **Source-cipher mode.** The home page, login page and a database write/read path (`wp_insert_post`
  → `get_post`) were byte-for-byte identical to the unencrypted baseline (home 78474 B).
- **Bytecode mode (`--bytecode`): one real bug, found and fixed.** The first request failed with
  `array_merge(): Argument #2 must be of type array, null given` in `wp_fix_server_vars()`
  (`array_merge($defaults, $_SERVER)`). Root cause: a normally compiled file arms the autoglobals
  (`$_SERVER`, `$_GET`, …) the first time the compiler meets each, so the engine populates them for
  the request; a **deserialized** op_array never passes through that step, so a function whose first
  use of an autoglobal came from bytecode saw it as `null`. `envelock_bc_load_image` now arms the
  standard set on load (all four per-version layers), the same restoration OPcache performs from
  `ping_auto_globals_mask`. Reproduced in isolation, fixed, and covered by a regression test under
  the built-in server (the SAPI that activates autoglobals lazily; the CLI always populates
  `$_SERVER`). After the fix, bytecode output is byte-for-byte identical to the baseline over three
  requests (home 80867 B). The transient short first render seen before the fix was caching warm-up,
  not reproducible.
- **Deployment recipe confirmed** (now `docs/DEPLOYING-APPS.md`): the package must carry the
  encrypted `.php` **plus every unencrypted asset** (css/js/json/images — `pack_tree` encrypts only
  PHP), the config file stays out of the package, the loader runs with OPcache off or blacklisted,
  and bytecode packages are compiled at the deploy path (`deploy_root`).

**Verification:** native suite 963/0/10 on 8.3.6 (the new regression test included). The fixed Linux
`php-8.3-nts` loader was rebuilt and redeployed; the other prebuilt loaders carry the same source
change and are pending a CI rebuild. Apache SAPI, and Joomla/PrestaShop/Drupal, remain to be run.

## Pass 20: three more CMSs — Joomla, PrestaShop, Drupal (November 8)

Continuing the real-application validation beyond WordPress.

- **Joomla 6.2.0 (5902 PHP files): fully validated.** Installed against MariaDB (CLI installer),
  encrypted the core (config excluded, assets carried, OPcache off), and served it in **both**
  source-cipher and bytecode modes. Home page and administrator entry **byte-for-byte identical** to
  the unencrypted baseline (home 7758 B, over repeated requests); no new bugs — the WordPress
  autoglobal fix already covers it.
- **PrestaShop 8.2.8 (16716 PHP files): encrypts and runs, with one real compatibility limit.** The
  package encrypts cleanly and an encrypted class executes correctly (round-trip of `Tools`). Two of
  PrestaShop's mechanisms **read PHP as text**, which encryption defeats:
  1. The autoloader builds a class index with `token_get_all()` over each file's **source**
     (`PrestaShopAutoload::getClassesFromDir`). On encrypted files it finds no `class` tokens →
     `Class "Db" not found`. **Fixed by deploying the pre-generated `class_index.php`** (the same
     principle as shipping a CMS's generated artifacts), after which the autoloader uses the index
     instead of re-parsing.
  2. Doctrine **annotations** (`@ORM\Table`, resolved from the file's `use` statements by a source
     tokenizer) cannot be read from an encrypted entity → `annotation ... was never imported`. This
     is a genuine limit: code that introspects its **own source text** at runtime is incompatible
     with encryption. Mitigations: exclude the annotated ORM entities from encryption, or use a
     version that declares mapping with PHP 8 **attributes** (read via reflection, which survives
     encryption). Separately, PrestaShop 8.2 does not officially support PHP 8.3 (the only PHP here),
     so its own baseline fails in Doctrine during the Symfony cache warm-up — an environment limit,
     not Envelock. A full end-to-end render is therefore left to a matching-PHP environment.
- **Drupal: not installable in this sandbox.** Drupal core needs its Composer `vendor/` tree, and the
  package registry (packagist.org) and drupal.org are both outside the environment's network
  allow-list, with no full-package tarball published on GitHub. Deferred to an environment with
  Composer access.

**Lesson for the deployment guide** (`docs/DEPLOYING-APPS.md`): beyond carrying assets, a protected
application must also account for code that reads its own source at runtime — generated class maps
and caches (ship them pre-generated) and source-tokenizing annotation readers (exclude those classes
or use PHP 8 attributes).

## Pass 21: Doctrine compatibility, validated against the real library (November 8)

Took the PrestaShop finding (Doctrine annotations break under encryption) and settled it against the
real `doctrine/annotations` (2.0.x), with the entity encrypted by the production loader.

- **Reproduced in isolation:** an entity carrying `@Mapping(name=...)` with a `use` import, encrypted,
  read via `AnnotationReader` → `The annotation "@Mapping" ... was never imported`. Doctrine's
  `PhpParser` tokenizes the file's source to resolve the `use`, which the encrypted file no longer
  exposes — identical to the PrestaShop failure.
- **Two fixes verified, neither exposing the source:**
  - **PHP 8 attributes:** the same mapping as `#[Mapping(name: ...)]`, read by reflection
    (`getAttributes()`), reads back correctly from the encrypted class — the metadata lives in the
    compiled op_array.
  - **Pre-generated metadata cache:** `PsrCachedReader` (non-debug) with the cache warmed in a
    cleartext run returns the encrypted entity's annotations without re-opening the file; with the
    cache removed the same encrypted entity fails — confirming the cache, not the source, is what is
    read.
- **Conclusion:** Envelock is already compatible with Doctrine, and the loader stays uncoupled from
  it. The application moves its mapping metadata out of the source — attributes, or the metadata cache
  Symfony/Doctrine already generates for production — and encrypts the code normally. Recipe in
  `docs/DEPLOYING-APPS.md` §7; `preflight` flags the annotations that need it. Leaving docblocks
  readable inside the package was rejected — it would expose source.

## Pass 22: performance-benchmark review and an emitter crash fixed (November 8)

Reviewed two external performance reports and reproduced their one real defect.

- **Bytecode emitter segfault (rc=139), reproduced and fixed.** A class with thousands of methods
  crashed `envelock_bc_emit` at `envelock_persist_op_array_ex` → `envelock_store_interned_string`.
  gdb showed a short stack (not recursion): the emit arena, a fixed bump mapping sized up front, was
  sized `main_op_array.last * 256 + 1 MB` — only the top-level opcodes. A class with few top-level
  opcodes but thousands of method op_arrays under-sizes it, so the bump pointer runs past the mapping
  and writes out of bounds. Now sized from the whole script (main op_array, every global function,
  every method of every user class), 2× margin, all four layers. Reproduced at 2000/3000/5000
  methods (segfault → OK), round-trip of the 2000-method file verified, regression test added. Only
  the pack-side emitter was affected; the server loader does not emit, so the deployed loaders are
  unchanged.
- **Recommendations cross-checked against the current state.** The reports' main levers are already
  in the project: `manifest_fastpath` default-on (−73 % cold), encrypt-only-business + OPcache
  blacklist (−77/−93 %), long-lived FPM workers (−70 %), `--strip-comments` (−7/−10 %). Both reports
  independently confirm bytecode is **slower** than source mode and is an anti-root tool, not a
  speed-up — matching Pass 17's own measurement. Two actionable additions were folded into
  `docs/RENDIMIENTO.md`: bundling own code into fewer protected files (−96 % on 240 methods) and the
  operational note that `opcache.blacklist_filename` must be set on the FPM master, not per-pool.

## Pass 23: Drupal 11 and PrestaShop 9 (November 9)

User-supplied packages.

- **Drupal 11.3.21 (13641 PHP files): validated, source-cipher.** Installed on SQLite (core
  installer), encrypted the whole code tree (`settings.php` and `sites/default/files/` kept clear),
  served through the built-in router. Home and `/user/login` byte-for-byte identical to the baseline
  (home 15646 B, 0 lines differ), no new bugs — Drupal 11 declares plugins with PHP 8 **attributes**,
  so the annotation problem does not arise. `preflight` flagged only a few `token_get_all` and
  self-read sites, none on the normal request path. Bytecode: a single file and 500-file batches emit
  fine; emitting the whole 13641-file tree in one process ran out of memory — an emitter **scale**
  limit, not a Drupal bug. **Fixed (Pass 24): the emitter now batches**, so `--bytecode` works on
  large trees; bytecode end-to-end is already validated on WordPress and Joomla.
- **PrestaShop 9.2.0 (full "basic edition" package, 34138 PHP files): the Doctrine recipe works
  end-to-end; one residual.** PrestaShop 9 still ships Doctrine `@ORM` annotations (484 in 34 entity
  files — `preflight` flags them before packing), not PHP 8 attributes, so without mitigation it has
  the 8.2 annotation limit. Installed on MariaDB (PHP 8.3, which PS9 supports, unlike 8.2), encrypted
  the code tree and applied the recipe from `docs/DEPLOYING-APPS.md` §7: `var/` kept **in the clear**
  (the compiled Symfony container, the Doctrine metadata cache, and PrestaShop's `class_index`), so
  Doctrine reads the warmed metadata and never re-opens the encrypted entities. Result: the encrypted
  shop boots with **no "annotation never imported" error** — the recipe resolves what blocked 8.2 —
  and renders the header, footer, banners and page structure. The featured-products block was then
  traced to the end and **fixed**: instrumenting `getProducts()` showed it fetched the products
  (`raw=4`) but threw, swallowed by the hook, `AnnotationException: @ORM\Entity in
  PrestaShopBundle\Entity\FeatureFlag was never imported` — the presenter reads that entity's
  annotations **at run time**, a path the compiled container cache did not cover. Excluding the 33
  `@ORM` entity files from encryption (keeping them clear — they are columns and getters, not business
  logic) made the **encrypted shop render identical to the baseline: 189 products, same structure**,
  the only diffs being cache hashes and timestamps. So PrestaShop 9 is validated end-to-end with the
  recipe `var/` clear + exclude the `@ORM` entities (both of which `preflight` points at). The lesson
  is folded into `docs/DEPLOYING-APPS.md` §7: the container cache is not guaranteed to cover every
  runtime annotation read, so excluding the annotated entities is the robust option.

## Pass 24: bytecode emit batched for large trees (November 9)

The emitter compiled every file in a single PHP process; a tree of tens of thousands of files (Drupal
13641, PrestaShop 34138) accumulated op_arrays and ran out of memory. `_bytecode_pass` now emits in
batches of `BYTECODE_BATCH` (500) files per process — each frees its memory on exit — and lifts
`memory_limit` for the build step, so peak memory is bounded by the batch size, not the tree. Each
file compiles independently, so the output is identical. Verified by emitting 14000 files in one pack
(a single process OOM'd before) with round-trips across batches, and a regression test that forces a
tiny batch over several batches. This unblocks `--bytecode` on Drupal and PrestaShop (whose
source-cipher runs are already validated; the §7 recipe — exclude the `@ORM` entities — applies to a
bytecode pack just the same).

## Pass 25: emit-arena sizing bug fixed; Drupal and PrestaShop bytecode (November 9)

Batching (Pass 24) unblocked large trees but exposed a deeper, more serious bug. Scanning the whole
Drupal tree file by file, nine files crashed the emitter with `rc=139` (polyfill-iconv charset tables
`from.cp950/cp949/cp936/big5.php`, the `migrate_drupal`/`contact` fixtures, `core/.phpstan-baseline.php`)
— all dominated by a huge literal/constant array.

**Root cause (severity: high).** The arena is a fixed bump mapping sized up front by a heuristic
(`envelock_bc_estimate_arena`), because the layer has no calc pass. The heuristic counted opcode and
literal *counts* but not the *bytes* that dominate real consumption: the contents of large string and
array literals, constant-expression AST (class constants, property/parameter defaults, enum cases,
attribute arguments kept as AST under `NO_CONSTANT_SUBSTITUTION`), and — on PHP 8.4/8.5 — property-hook
op_arrays. When the estimate fell short the writer ran **past** the mapping: on the hash-table paths
(which bump `ZCG(mem)` directly) that was a silent out-of-bounds write into the heap, and the earlier
`envelock_alloc` "grow" made it worse by relocating the arena (mmap new + memcpy + munmap old), leaving
the already-written absolute pointers and the captured `script->mem` base dangling (use-after-munmap on
serialize). Independently confirmed by the deep audit (Pass 26, bytecode-layer agent).

**Fix (fail-closed, not merely "generous").** (1) The arena is floored at `source_size * 32`: every
byte it holds is either a fixed structure (counted) or source-derived (strings, AST, attributes, hooks)
whose serialized size is bounded by the source size times a small constant, so `max(structural,
source*32) * 2` is a sound over-bound; the mapping is virtual (`mmap`), so over-reserving costs only
address space. (2) The relocate-grow is **removed** — an absolute-pointer arena can never be relocated
— and `envelock_alloc` is fail-closed (flags exhaustion, returns NULL → refusal). (3) A trailing
`PROT_NONE` **guard page** turns any residual overrun, including on the direct-bump hash paths, into an
immediate deterministic fault instead of silent heap corruption. Applied identically to all four layers
(`php82/83/84/85`, which are byte-identical). Regression test
`test_bytecode_emitter_handles_large_constant_arrays` (a ~300 KB class-constant array; the structural
estimate alone would size it at ~1 MB).

**Validated.** All **13637 Drupal** and **34138 PrestaShop** PHP files now emit with **zero** emitter
crashes (parallel file-by-file scan); `from.cp950.php` (the worst case) is clean under `gdb`. Full
native suite 966/0/10.

**Drupal 11 in bytecode, end-to-end.** The whole Drupal tree packed with `--bytecode` (sources compiled
at the deploy root; `sites/default` excluded and kept clear; assets rsync'd alongside), served by the
**hardened production loader** (0 exported `envelock_*` symbols, built by `scripts/build-unix.sh`) with
OPcache off. The home page renders **byte-for-byte identical** to the plaintext baseline (the only diff
is the server port in a self-referential absolute URL), and `/user/login` renders its form. So Drupal 11
is now validated end-to-end in **both** source-cipher and bytecode. **PrestaShop 9 bytecode:** the emit
is validated on 100 % of its 34138 files; its *rendered* run stands validated in source-cipher (189
products, Pass 23), and the bytecode execution layer is proven identical on three real applications
(Drupal here, WordPress and Joomla in Passes 19–20). The PrestaShop *bytecode render* was not re-stood-up
this round (its MariaDB-backed runtime from Pass 23 was not persisted); honest status: emit proven,
render inferred from the three validated bytecode sites plus the source-cipher PrestaShop render.

## Pass 26: comprehensive deep code audit, four independent reviewers (November 9)

A full, detailed re-audit, split across four independent reviewers reading the source (not memory):
the native loader + crypto core, the bytecode layer, the Python encoder, and the build/release scripts.
Overall verdict: the core is **solid** — verify-then-decrypt is correct, GCM authenticates before use,
the `ENVLK02` parser is exhaustively bounded, and no exploitable memory-safety or crypto bug was found
in the code paths that run on a server. Findings acted on:

- **Bytecode arena (high) — FIXED** in Pass 25 (above).
- **GCM content-key nonce reuse (medium, encoder-side) — verified safe, hardened.** The loader cannot
  detect encoder nonce reuse, and the content key is shared across a package. Verified the encoder uses
  a **monotonic counter** nonce per file (unique) with a fresh content key per pack — no reuse. Residual:
  that same content key also wraps the per-file vault data key with a *random* nonce, a different nonce
  space under one key. Hardened by forcing the vault wrap nonce into the top-bit-set half (file counter
  nonces always have it clear), so the two spaces are provably disjoint; no loader change, format
  unchanged. Test `test_vault_key_nonce_is_domain_separated`.
- **`--bytecode` temp sources world-readable (low) — FIXED.** The plaintext sources written under the
  deploy root while they compile are now created `0600` and atomically (`O_EXCL`), closing the window in
  which a local user could read them. Test `test_bytecode_temp_sources_are_owner_only`.
- **`build-unix.sh` flag order (medium) — FIXED.** Inherited `CFLAGS`/`LDFLAGS` were appended *after* the
  hardening, so a conflicting inherited value (e.g. `-fvisibility=default`, which would re-export the
  `envelock_*` API) won. Hardening now goes last.
- **No post-build symbol verification (medium) — FIXED.** `build-unix.sh` and `build-static-php.sh` now
  assert the built module/binary exports no `envelock_*`, `bc_emit` or `bc_run` symbols and fail closed
  otherwise (verified: the hardened loader exports only `get_module`; the gate catches the un-hardened
  PoC that exports 98 such symbols).
- **`build-windows.ps1` stale source list (high, Windows CI) — FIXED.** It copied a hand-kept 6-file list
  that had drifted and dropped the 2.0 sources and the `opcache/` layer, so the native Windows build
  could not compile. It now copies the whole `extension/` tree, like the Unix and Wine scripts.
- **`build-static-php.sh` unhardened (medium) — FIXED.** The static appliance now builds with the same
  hardening flags, including `-fvisibility=hidden` (safe for PHP — its public API is `ZEND_API`/`PHPAPI`,
  visibility-default — and it hides the `envelock_*` internals from a loaded extension), plus the symbol
  gate.
- **Documented, not changed (by design or low):** the bytecode **deserializer is a trust boundary** — its
  in-band checks are `ZEND_ASSERT` (compiled out in production), so it relies on the Ed25519 signature
  verified before load (this is the OPcache `file_cache` posture; hardening it with real range checks is
  future work); the manifest **fast-path cross-attribution** (only a *trusted* developer could mislabel a
  file; shown exploitable and fixed in Pass 32); the licence/trusted-time **fail-open** (anti-rollback, not access control — the real perimeter is
  encryption + signature); the always-registered **mini-VM** `__envelock_vm` (its validator is the trust
  boundary; recommend continuous fuzzing); the Wine-build robustness and the `check_release` exemption of
  the git-ignored `CONTEXTO-PROYECTO.md` (both low; a Windows `dumpbin` symbol gate in CI is recommended).

## Pass 27: two external audits of the source ZIP, reproduced and fixed (November 9)

Two external reports (ENV-01..08, then a second pass NU-01..07) against the source ZIP
delivered that day. Each finding was reproduced in code before being fixed; the design limits the
reports raised were confirmed as already-documented, not reclassified. No cryptographic break was
found (X25519/HKDF/AES-256-GCM and Ed25519 sound), consistent with Pass 26. The genuine bugs — one
(ENV-01) that Pass 26 had missed — are fixed with a test that fails without the fix:

- **NU-01 (high) — negative `clock_tolerance` disabled anti-rollback.** `envelock.clock_tolerance` is
  `PHP_INI_SYSTEM` and read as a signed long; `-1` cast to a huge `uint64`, collapsing every floor to
  0 and silently turning off the clock-set-back check. Now clamped (`<0` → the 3600 default, capped at
  one year) before the unsigned cast. Native test `test_o8_negative_tolerance_does_not_disable_rollback`.
- **ENV-01 (high) — anti-rollback watermark never persisted under a long-lived worker.** The persist
  throttle compared the new value against the IN-MEMORY watermark, not the on-disk one; a worker
  advancing in sub-`step` increments never crossed the threshold, so the disk kept its load-time value
  and a restart lost the whole advance. The throttle now measures from a per-worker record of the
  on-disk value. Native C harness `test_o8_watermark_persists_under_a_long_lived_worker` (simulated
  clock via `--wrap=time`).
- **ENV-02 (robustness) — GUI `pack` truncated recipients.** `zip(recipients, passwords)` silently
  dropped recipients on a length mismatch; now refused with an explicit error.
- **ENV-03 — per-project minimum could be overwritten by a second developer.** The encoder stored
  minimums keyed by project alone, so a second developer sharing a project id replaced the first's
  minimum, even though the wire format and loader bind each to its developer. Now keyed by
  `(project, developer)`; the `inspect` `minimum_serials` became a list. Test
  `test_minimum_keeps_each_developer_independently`.
- **ENV-04 — bytecode cleanup deleted a pre-existing `deploy_root`.** The cleanup rmdir'd upward to
  `deploy_root.parent`; it now removes only the directories the pass itself created. Test
  `test_bytecode_pass_keeps_preexisting_deploy_root`.
- **ENV-05 — second-granularity serial.** The default serial is now `time.time_ns()`, so two releases
  in the same second no longer collide for anti-rollback.
- **NU-02 / NU-07 — password-file permission TOCTOU and missing `O_CLOEXEC`.** The 0600 check now runs
  on the OPEN descriptor (`fstat`), not a pre-open `path.stat()` that follows symlinks, and `bounded_read`
  opens with `O_CLOEXEC`. Test `test_bounded_read_private_requires_owner_only`.
- **NU-03 — IP fingerprint diverged between encoder and loader.** The encoder read one address per
  interface (`SIOCGIFADDR`) while the loader reads all (`getifaddrs`), so an IP-bound license issued on
  a multi-IP host was rejected on that same host. The encoder now enumerates with `getifaddrs` (ctypes),
  matching the loader exactly (verified: same hash format and set).
- **NU-04 — secret folder left world-readable if pre-existing.** `secret_write` now forces the parent
  to 0700 whether or not it created it. Test `test_secret_write_hardens_preexisting_parent`.
- **NU-05 — asset credential scan bypassable by extension.** The content scan now runs on every asset's
  text, not only a fixed extension list. Tests add `config.data` / `settings.conf.local`.
- **NU-06 — dead branch in `host_domain()` removed.**
- **ENV-06 / the SSL read / verify-vs-manifest — documented, not coded.** `trusted_time` does not bound
  DNS resolution and reads the response once: both are fail-open hardening items where a resolver
  thread or a non-blocking SSL read loop would add more startup-failure surface than the Baja gap they
  close (reliability is priority #1), so they are documented (a clear code comment plus `MANUAL.md`)
  rather than changed. `verify` checks only the JSON manifest, not the runtime binary one — a doc
  clarification, not a bug.

Rebuilt the 5 Linux loaders from the fixed source (0 exported `envelock_*` symbols); `prebuilt/SHA256SUMS`
and `test_prebuilt` re-verified. Suites: native **968/0/10**, Python **481/5**.

## Pass 28: obfuscation/hardening options vs real CMSs; WordPress FSE pattern fix (November 9)

Measured which optional pack flags keep a real CMS rendering byte-identical to cleartext, by packing the
whole app, serving it through the production loader and diffing the home page. Full matrix for **Drupal
11** and **WordPress** in `docs/DEPLOYING-APPS.md`. Outcome: the safe set (`--strip-comments`,
`--compact`, `--encode-strings`, `--obfuscate`, `--obfuscate-flow`, `--obfuscate-methods`,
`--include-protection`, `--no-ffi`, `--no-prepend`, plus encryption + bytecode + manifest) renders
identically on both; `--obfuscate-properties` breaks Drupal (serialised-object property rename) and is
unsafe site-wide on WordPress; `--sealed` breaks both (cleartext PHP / `eval()` at run time);
`--vault-strings` is impractical on a 13.6 k-file tree and broke the WordPress render. Correction to
earlier reasoning: **`--include-protection` is compatible** — it only blocks a cleartext file including a
protected one, not protected code including the cleartext PHP these CMSs generate.

New finding and fix — **WordPress block (FSE) themes**: an encrypted FSE theme rendered its templates
empty (HTTP 200, no error; Twenty Twenty-Four dropped from 215 blocks to 10). Root cause: WordPress
registers theme block *patterns* by reading each `patterns/*.php` header (`Title:`/`Slug:`) with
`get_file_data()` — from the file TEXT — so encryption hides the header and the patterns never register.
Same class as Doctrine annotations, not a crypto/loader bug. Keeping `wp-content/themes/*/patterns/*`
cleartext restored the render to 215 blocks, byte-identical. `preflight` gained a `wp-file-header`
detector that flags these (and plugin/theme/page-template headers) before packing; test
`test_preflight_flags_wordpress_file_headers`. Recipe documented in `docs/DEPLOYING-APPS.md`.

## Pass 29: four-CMS option matrix measured; PrestaShop docblock finding + preflight fix (November 9)

Completed the option matrix by **measuring Joomla 5.2.2 and PrestaShop 9 empirically** (whole app packed,
served through the production loader, home page diffed byte-for-byte against the cleartext baseline after
normalising per-request tokens — CSRF tokens, asset cache-busters, random widget ids). This replaces the
Pass-28 *prediction* that PrestaShop would mirror Drupal, which was **wrong on two flags**.

Results (byte-identical unless noted):
- **Joomla 5.2.2** — the most compatible: the whole hardening set composes byte-identically, **including
  `--strip-comments`, `--compact` and `--sealed`** (with `envelock.sealed_cleartext` for the config file,
  `cache`, `tmp`, `administrator`). Only `--obfuscate-properties` breaks it (HTTP 500,
  `Class "voku\helper\Bootup" not found` — the Composer `ClassLoader` private-property rename). Joomla's
  only self-introspection (`getDocComment`/`reads-own-source`) is in `symfony/error-handler`, active only
  in debug mode, so the production front path is unaffected.
- **PrestaShop 9** — safe set ✅, but **`--strip-comments` and `--compact` break it** (HTTP 200, the
  featured-products section silently absent). Root cause isolated by bisection: PrestaShop's front-office
  presenters extend `src/Adapter/Presenter/AbstractLazyArray.php`, which reads its **own method docblocks
  at run time** via `getDocComment()` to find the `@arrayAccess` annotation. Stripping/compacting removes
  the docblocks, the annotation vanishes, the presenters expose no data. Same self-introspection class as
  the WordPress file header and the tokenised class map — **not an Envelock bug** (the compactor validates
  its output with `token_get_all`; it produces valid PHP, the loss is semantic). `--obfuscate-properties`
  ❌ 500 (`Class "PrestaShop\PrestaShop\Core\Version" not found`, Composer autoloader) and `--sealed` ❌ 500
  (PrestaShop's autoloader `eval()`s class stubs; the allowlist re-allows cleartext *files* but
  deliberately never `eval()`).

**Envelock fix (gap found, with a failing test):** `preflight` did not detect runtime docblock reading,
so a `pack --strip-comments` on PrestaShop produced a silently broken deployment with no warning. Added:
- COMPAT category **`reads-own-docblock`** matching `getDocComment(` — flags any code reading its own
  docblocks (custom annotations like `@arrayAccess`). Test `test_preflight_flags_reads_own_docblock`.
- An **active `pack`-time WARNING**: when `--strip-comments` or `--compact` is used and the tree contains a
  comment-sensitive pattern (`reads-own-docblock`, `doctrine-annotation`, `wp-file-header`), `pack` prints
  a warning naming the file count and pointing at `preflight`. Scoped to those two flags, so the common
  pack path is unchanged (no performance regression).

**Universal safe set (all four CMSs, byte-identical):** encryption + bytecode + signed manifest +
`--encode-strings` + `--obfuscate` + `--obfuscate-flow` + `--obfuscate-methods` + `--include-protection` +
`--no-ffi` + `--no-prepend`. Drupal/WordPress/Joomla additionally tolerate `--strip-comments`/`--compact`;
PrestaShop does not. Full table in `docs/DEPLOYING-APPS.md`.

## Pass 30: self-audit ("try to break it"); sealed_cleartext prefix-boundary bypass fixed (November 9)

A fresh adversarial pass over the loader and the encoder, concentrating on the code added in the recent
rounds (the newest surface is the likeliest to hold a new bug) plus the crypto order and the parsers.

**Bug found and fixed — sealed_cleartext prefix-boundary bypass (fail-open, self-introduced).**
`envelock_sealed_cleartext_allowed` (the `envelock.sealed_cleartext` allowlist that lets a sealed CMS run
its cleartext cache) matched each allowed entry as a **plain string prefix with no path-boundary check**.
So whitelisting `/app/sites/default` also allowed any sibling whose path merely *starts with* that string
— `/app/sites/default-evil/x.php`, or a file `/app/sites/defaultX.php`. Under `--sealed`, whose whole
point is to refuse injected cleartext `.php` inside the tree, this let an attacker who can write such a
sibling run plain PHP inside the sealed tree — a real weakening of the sealed guarantee. The direction
matters: the existing `envelock_under_sealed_root` uses the same prefix match, but there over-matching is
**fail-safe** (refuses more) and its root keys are stored with a trailing `/` (boundary by construction);
the allowlist entries come straight from the operator's INI string (often no trailing separator), so
over-matching there is **fail-open**. Reproduced (`test_php_sealed_cleartext_allowlist_respects_path_boundary`:
a sibling `subleak.php` ran — `ALEAKC` — with the allowlist set to `.../sub`). Fixed by requiring the match
to end at a path boundary: the whole name equals the prefix, or the prefix ends in a separator, or the next
character in the path is a separator (`/`, or `\` on Windows). The sibling is now refused; the legitimate
`<prefix>/file.php` still runs. The loader C changed, so the five Linux loaders were rebuilt.

**Verified sound (no change needed):**
- **Crypto order.** `envelock_compile_file` parses and bounds-checks the header, then verifies the Ed25519
  signature against the trusted signers, and only *then* decrypts (`envelock_open`, AES-256-GCM, which
  authenticates) and — for a bytecode image — deserializes. So nothing untrusted reaches the bytecode
  deserializer (whose runtime checks are `ZEND_ASSERT`, by design backed by the prior signature) or the
  source compiler. Signature-before-use holds on both paths.
- **Vault parsers** (`envelock_parse_vault`, `_enc`): every length field is bounds-checked against the
  authenticated plaintext with no integer overflow (table_bytes ≤ total−4, count ≤ (table−4)/4, each
  entry's len ≤ remaining); malformed-but-signed tables are rejected cleanly.
- **Other path prefix matches:** the include-protection suffix match checks the `/` boundary (line ~632);
  sealed-root keys carry their `/` boundary. No other fail-open prefix match found.

**Fuzzing / differential (this pass):**
- Container crypto/parser under **libFuzzer + ASan + UBSan + leak detection** (`scripts/audit-native.sh`,
  `ENVELOCK_FUZZ_RUNS=2000000`): no crashes, no leaks, no UB.
- Differential obfuscator fuzzer (`scripts/fuzz_obfuscator.py`, 1426 programs, random flag combinations):
  **0 divergences** between original and transformed output.

**Documentation:** added a decision guide — "Choosing options: trade-offs and when to use each" — to
`docs/DEPLOYING-APPS.md` (per-option advantage / cost / when-to-use / when-to-avoid, plus
maximum/balanced/minimum profiles), built on the four-CMS measurements; cross-referenced from
`docs/MANUAL.md`.

## Pass 31: harder self-audit (stress, all five engines); Windows binaries rebuilt; options recommender (November 9)

A second, harder "try to break it" pass — stress, every engine, adversarial inputs — plus the work
Pass 30 deferred: rebuilding the Windows binaries, and a new **options recommender**.

**Stress and adversarial testing (no new bug found).**
- **Extreme fuzzing:** the container crypto/parser under libFuzzer+ASan+UBSan+leak detection at
  **5,000,000 runs** (max 256 KiB inputs): 0 crashes, 0 leaks, 0 UB; clang static analysis clean.
- **All five PHP engines:** the loader's security subset (tamper-evidence, truncation, byte-flip,
  sealed, manifest, path-binding, include-protection, wrong-installation, untrusted-signer) passes on
  **8.2, 8.4, 8.4-ZTS and 8.5** (35/35 each) as well as 8.3. (Running the whole suite on a
  tokenizer-less PHP "fails" only the transform/encoder tests, which need a tokenizer to *pack* — the
  loader itself is engine-agnostic C and passes everywhere.)
- **New regression tests** (full-loader level, complementing the fuzzed core): a truncation sweep
  (every parse boundary; never leaks, never crashes), a payload byte-flip sweep (every single-byte
  change to the authenticated header/table/ciphertext/tag/signature is caught — end-to-end
  tamper-evidence), the sealed_cleartext boundary with trailing-separator and multi-entry allowlists,
  and a worker-reuse stress (50 requests to a sealed+vaulted package, and 40 to a sealed package on the
  **ZTS** build) that hammers the per-request lifecycle (`sealed_active`, `litvault`, `roots`). All pass.
- **Re-reviewed sound, no change:** `envelock_policy` (path binding, release/project/developer roots
  mixing, manifest-before-register order, no-prepend/no-ffi/include-protection), `envelock_at_packaged_path`
  (root ≤ length, `/` boundary), and the identity/manifest paths.

Net: the only real bug this round of auditing surfaced was the sealed_cleartext prefix-boundary bypass,
found and fixed in Pass 30. This harder pass found none.

**Windows binaries rebuilt (Pass 30 had deferred them).** All **8 DLLs** (8.2/8.3/8.4/8.5 × NTS/TS) were
rebuilt from the current source with the sealed_cleartext boundary fix, via `build-windows-wine.sh`
(MSVC under Wine): each is a valid PE32+/x64 exporting only `get_module` (0 `envelock_*` symbols) and
carries the fix. Runtime Wine validation of the DLLs is still not possible here (this Wine lacks the
VS2017/2022 VC runtime, so even plain Windows PHP does not start — an environment limit, not a defect);
the Windows runtime matrix is validated by CI / real Windows. Both **assistant executables** were rebuilt
too (they now carry the new recommender); the Windows `.exe` **runs under Wine** and its `--selftest`
passes (6 tabs). `prebuilt/SHA256SUMS` regenerated; `tests/test_prebuilt.py` 4/4.

**New feature — `envelock recommend` (and a Recommend tab in the assistant).** Analyses a tree and
recommends the strongest protection that is safe for it, grounded in the four-CMS matrix and the
preflight detectors: it enables the measured-compatible hardening and turns off only what would break
the project (dropping `--strip-comments`/`--compact` when docblocks are read at run time, `--sealed`
when the tree `eval()`s, and never auto-enabling `--obfuscate-properties` or whole-tree `--vault-strings`),
lists the files to keep cleartext, and prints a ready-to-fill `pack` command. Tests:
`test_recommend_options_is_conservative_and_matches_the_cms_matrix` and the two assistant-action tests.

**Suites:** native **975 / 0 / 10**, Python **486 / 5**.

## Pass 32: native Windows validation and a five-part adversarial audit (November 10)

**Native Windows.** The first run on a real Windows (Windows 11 x64; official PHP for Windows 8.2.35,
8.3.36, 8.4.27, 8.5.12, NTS and TS; Visual Studio Build Tools 2022 with MSVC 14.29 and 14.44;
`BuildPhpExtension` 1.9.0). `scripts/build-windows.ps1` had never run natively and needed fixes before
it built anything (`config.w32`: a `;` in an option's help text truncated phpize's generated
`configure.js`; thread-safe builds hit the bytecode layer's NTS-only `#error`). The SEH crash guard was
then exercised for the first time: with the guard, a sweep over every 4-byte word of a bytecode image
caught every injected fault and the process kept running, and a build without the guard died with
`0xC0000005` on the same images. **But that first conclusion — "the SEH guard works" — was
incomplete:** a *later* fatal error in the same process crashed it (`0xC0000409`, sometimes "zend_mm_heap
corrupted"), because the guard left `EG(bailout)` pointing at a dead jump buffer (BC-1 below). It is
fixed; the final sweeps raise a PHP fatal after every rejection and require it to exit cleanly.

**Method.** Five independent hostile reviews, each told to break its area and to confirm by
experiment where possible: the loader core (CORE), the licence/clock/trusted-time policy and the VM
(POL), the bytecode layer (BC), the encoder (ENC) and the tooling (T). Every finding was then fixed by
a separate implementer, with a regression test that fails on the old code where an old binary or file
was available to prove it (the C regressions were run against the pre-fix DLL and fail there). The
fixed sources were rebuilt into the 8 production DLLs and 4 test DLLs (`--enable-envelock-bcrun-unsafe`,
never shipped) and re-tested natively.

| ID | Severity | Finding | Status |
|---|---|---|---|
| CORE-1 | High (confirmed) | Manifest fast path: a trusted developer's manifest could list another developer's file, or one signed by an untrusted key, and have it run as theirs (include-protection bypass) | Fixed: fast path only with one trusted developer; seeding after full validation, never overwriting |
| CORE-2 | Low | Package content key not cleared before the fatal on decrypt/vault failure | Fixed |
| POL-1 | High (design) | Licence enforcement depends on `php.ini`, which the licensee controls | Documented (MANUAL §14.1): not DRM |
| POL-2 | Medium-high | Trusted time discarded in exactly the rollback it exists to catch; TLS validated against the suspect clock | Fixed (in-memory floor, `X509_V_FLAG_NO_CHECK_TIME`); Linux code |
| POL-3 | Medium (confirmed) | VM swallowed `max_execution_time` | Fixed |
| POL-4 | Medium (confirmed) | `__envelock_vm_v2` callable dynamically (`$f()`, `call_user_func`) | Fixed: dynamic calls refused |
| POL-5 | Medium (confirmed) | Compiled code keeps running after the licence expires in long-lived workers | Documented |
| POL-6 | Low-medium | Machine binding described as "strong" | Documented as medium |
| POL-7 | Low | Under FPM the root master could create the clock file 0600 that workers cannot write | Fixed: not created at MINIT |
| POL-8 | Low | Domain binding satisfiable through `SERVER_NAME` (CLI environment; Apache `UseCanonicalName Off`) | Fixed for CLI/phpdbg/embed; Apache documented |
| POL-9 | Low (confirmed) | VM passed PHP references through | Fixed |
| POL-10 | Low | A clock at time ≤ 0 passed every time check | Fixed |
| POL-11 | Low | Loader capped MACs/IPs at 64 in enumeration order; encoder used all | Fixed: all, sorted, ≤ 256, both sides |
| POL-12 | Low | Clock file: links, FIFOs, no ZTS lock | Fixed |
| POL-13 | Low | Documentation contradicting the code (removed function, "not implemented", "never uses the network") | Fixed |
| BC-1 | Critical (confirmed, Windows) | After a caught fault, the next fatal crashed the worker | Fixed |
| BC-2 | High (POSIX) | A fatal during install left the signal guard armed | Fixed (POSIX path not yet compiled, see below) |
| BC-3 | High (confirmed) | The 8.3 layer had none of the element-count checks | Fixed; enforced by `check_bc_layers.py` |
| BC-4 | High | Remaining count-driven loops unbounded | Fixed |
| BC-5 | High | Relocation bound stored inside the image it protects | Fixed |
| BC-6 | High | Early-binding cache slot written at an unchecked offset | Fixed |
| BC-7 | High | Failure mid-install left global tables pointing into the freed buffer | Fixed (entries removed, buffer retained); observers already notified cannot be rolled back |
| BC-8 | High (8.2/8.3) | Class-name cache offset taken from the image | Fixed |
| BC-9 | Medium-high | Hash-table invariants never checked | Fixed (checked, hashes and chains rebuilt) |
| BC-10 | Medium (confirmed) | A valid image crashed when the server lacked an extension the packer had | Fixed |
| BC-11 | Medium | The generator would strip the hand-made hardening | Fixed (checker + refusal) |
| BC-12 | Medium | Opcode-handler index unbounded | Fixed |
| BC-13 | Medium (Windows) | SEH filter caught every exception | Fixed (memory/instruction/arithmetic faults and stack overflow only) |
| BC-14 | Medium (8.5) | Constant-expression paths could reach an unreachable marker | Fixed |
| BC-15 | Medium-low | Only each structure's start offset checked | Fixed; pointers that are only relocated still have only their start checked |
| BC-16 | Medium-low (confirmed) | `zend_system_id` differs between CLI and CGI/FPM, so CLI-packed images failed under FPM | Fixed: Envelock bytecode identity (older images refused) |
| BC-17 | Low-medium | Emit arena did not fail closed | Fixed |
| BC-18 | Low | Image size truncated to 32 bits | Fixed (> 4 GiB refused) |
| ENC-1 … ENC-26 | 1 high, 1 high-medium, 1 medium-high, 5 medium, the rest low | Windows secret ACLs and `server-install`, POSIX symlink race, PHP planted in the current folder, `--vault-strings` with member obfuscation, `verify` blind spots, pattern matching on Windows, recovery key in the same file, small-order keys, credential files, temp files, command-line limit, silently ignored options, licence canonicalisation | All fixed (CHANGELOG lists each) |
| T-1 … T-21 | 2 high, 1 medium-high, 4 medium, the rest low | Release guard on staged trees, virtualizer name resolution and float handling, assistant PHP search and threading, launcher search path, build parity and gates | All fixed except T-10 (extra VM frame in backtraces), documented |

**The options recommender, run end to end.** Its suggested command was packed exactly as printed (through
the CLI) and deployed on the real Laravel and Symfony apps, comparing every web route and a console
command with the unprotected app. Three defects, all fixed with tests that fail on the old recommender:
(1) `--no-ffi` with PHP's built-in `enable_dl = On` refused every request (0/10 Laravel routes) and
nothing said so — the requirement is now part of the recommendation, and the flag is off for projects
that use FFI/`dl()`; (2) `--include-protection` refused `php artisan` because `pack` leaves extensionless
console scripts cleartext — now off when one exists; (3) `vendor/` was analysed and would have been
encrypted, and third-party false positives switched `--bytecode`/`--strip-comments` off — now
`--exclude 'vendor/*'`, the run-time caches and the Blade templates are recommended and only the own code
is analysed. After the fix: Laravel 10/10 web + `artisan route:list` (closure line numbers differ from
`--compact`, as documented), Symfony 7/7 + `bin/console debug:router`, identical, own code and whole app.

**Also found and fixed during the native run.** ENV-14 (non-ASCII paths on Windows) was only half
fixed: its regression test was skipped on every Windows PHP because Wine could not run it, and on real
Windows a non-ASCII identity path given with `php -d` (which arrives in the ANSI code page) failed, while
the clock-state file failed for a UTF-8 `php.ini` path (ANSI `open()`). All configured paths now share
one UTF-8-or-ANSI conversion and the wide file API; both tests run natively. Build-machine paths in the DLLs (`__FILE__` through
`zend_bailout()` and OpenSSL's memory macros, and the absolute PDB path) — now prevented in the sources
and refused by `build-windows.ps1`; the Windows assistant executable lacked hidden imports and stopped at
start; `--e2e` without a folder stalled on an error dialog; the native suite missed Windows crash exit
codes (reported by Python as large positive numbers), deadlocked on a full `php -S` pipe, and set ACLs by
English group names.

**Still open after this pass.**
- The POSIX-only code changed here — trusted time, the bytecode signal guard and its BC-2 disarm, the
  clock-file checks — has to be compiled and run on Linux. *Done in Pass 33* (2026-11-12): compiled into
  the portable Linux loaders and run there (TEST-STATUS.md); the parts WSL1 cannot exercise (ptrace,
  memfd_secret, PHP's execution timer) are left to a normal Linux kernel and the CI.
- Executing a corrupted but validly signed image remains out of scope (a trusted signer can ship
  malicious code directly); BC-7's observer notifications and BC-15's relocated-only pointers are
  residuals.
- POL-1 and POL-5 are design limits of a loader whose policy the server administrator configures.

## Pass 33: server dependencies and hosting compatibility (November 11)

What the loader needs from a server and what each kind of hosting allows, read from the shipped
binaries (`dumpbin /dependents`, `readelf -d -V`), from the loader's source, and measured with the
shipped Windows DLLs on PHP 8.2–8.5; hosting-product facts were checked against their own
documentation. The result is `docs/HOSTING.md`, plus a pre-flight check for a target server
(`scripts/envelock-preflight.php`).

| ID | Finding | Status |
|---|---|---|
| HOST-1 | **OPcache switched off after startup was refused.** With OPcache on in `php.ini` (the default almost everywhere) and switched off per directory, vhost or FPM pool — the only OPcache change a hosting customer can usually make — OPcache's compile hook stays installed above Envelock's, and the integrity check accepted a hook above only when `allow_opcache` was set **and** OPcache's cache was on at that moment. Result: "another extension installed a compile hook above Envelock's", also with `allow_opcache=1` and a blacklist; `docs/DEPLOYING-APPS.md` §3 recommended exactly that per-vhost switch-off. | **Fixed** (2026-11-11). The loader recognises a hook above it as PHP's own when its code lies in the same image as OPcache's (or Phar's, HOST-6) start-up function (`envelock_compile_hook_is_php_own`: `GetModuleHandleExW` on Windows, `dl_iterate_phdr` on Linux, `dladdr` on macOS), not by any setting. So that the exception hides nothing, a post-start-up callback (`envelock_post_startup`, which OPcache calls before it installs its own hook — checked in the 8.2 and 8.5 sources) records whether a foreign hook already sat above Envelock once every extension had started; if one did, it is refused for good. Tests `test_opcache_switched_off_after_startup_runs_and_preflight_agrees` (with and without the opt-in) and `test_opcache_switch_off_does_not_excuse_a_foreign_hook`; the FPM pool case is in `scripts/fpm_smoke.py`. |
| HOST-2 | **The prebuilt Linux loaders needed glibc 2.38**, not 2.33 as `prebuilt/README.md` said (`__isoc23_sscanf`/`__isoc23_strtoll`, from building on Ubuntu 24.04). That rules out Ubuntu 22.04, Debian 12 and the whole RHEL 8/9 family (AlmaLinux, Rocky, CloudLinux), i.e. most hosting systems. The Linux assistant has the same floor (its bundled Python, Tcl/Tk and X11 libraries). | **Fixed** (2026-11-12). The Linux loaders are now portable builds: AlmaLinux 8 (glibc 2.28) with OpenSSL 3.5.9 linked in and hidden (`build-unix.sh`: `ENVELOCK_OPENSSL_STATIC`, `ENVELOCK_MAX_GLIBC`, both enforced as build gates). Each needs only `libc`/`libdl`/`libpthread`, GLIBC_2.25 at most, no system OpenSSL. Trusted time also loads the system CA bundle, since the linked-in OpenSSL has no certificate folder of its own. Results in TEST-STATUS.md. The Linux assistant is rebuilt on the same baseline. |
| HOST-3 | The 11 OPcache tests of `tests/test_native.py` skipped on every Windows PHP 8.2–8.4: under `php -n` an official Windows build looks for modules in `C:\php\ext`, so the helper never found `php_opcache.dll` (8.5 has OPcache built in). They were counted among the "needs what Windows lacks" skips. | **Fixed** (the helper uses the `ext` folder next to `php.exe`). They and the two new pre-flight tests now pass on all eight DLLs (14/14 each). |
| HOST-4 | Coexistence with other encoders' loaders: any compile hook that ends above Envelock's makes it refuse protected files, by design; ionCube Loader is a `zend_extension` (started after every regular extension, so its hook sits above). | Documented (HOSTING.md §3.4); not run with the ionCube or SourceGuardian binaries. |
| HOST-5 | The identity and licence files are opened with `O_NOFOLLOW`, so a Kubernetes secret volume (each key a symlink into `..data/`) is refused. | By design; documented with the workaround (`subPath`, or an init container). |
| HOST-6 | **Phar's compile hook, on Debian and Ubuntu, made the loader refuse every protected file.** There Phar is a separate module loaded from `conf.d/20-phar.ini`, i.e. after an `extension=` line in the main `php.ini` — the installation the manual describes — so its hook sat above Envelock's. Measured on Ubuntu 24.04 with its own PHP 8.3.6 and the previous loader: every protected file refused, with OPcache off. | **Fixed** with HOST-1 (Phar's hook is PHP's own, recognised the same way). |
| PIE | Support for installing the loader with PIE (`composer.json` as `envelock/loader`, `scripts/package-pie-assets.py` naming the Release assets exactly as PIE's source expects, and the hardening moved into `config.m4`, since PIE's source build is a plain `phpize`). | Added; a PIE 1.5.5 source build was checked on AlmaLinux 8 (hardened, loads, no bytecode surface). Downloads from a Release can only be checked once one is published. |

Measured and documented as **not** affecting the loader: `disable_functions` (including `dl`,
`exec`, `proc_open`), `open_basedir` beyond the usual rule that the protected files lie inside it,
`auto_prepend_file` for packages without `--no-prepend`.

## Open risks and necessary work

- Extraction of the decrypted source and instrumentation by the administrator/root: a **known design limit**, not resolved. O1 bytecode stops decrypted *source* from ever being in the package or in process memory, which raises the cost markedly; but root can still dump the deserialized op_array, literals and runtime data, so this limit stands.
- Whole-deployment integrity: files are bound to their relative path and releases cannot be mixed in a package folder, but there is no signed manifest of the whole set (files can be deleted, or a whole package folder replaced by another package for the same server).
- Obfuscation: 2.0 adds global AST renaming and control-flow flattening (O6) and an experimental opcode VM (O4, laboratory-only). A competent analyst can still recover the logic, especially from bytecode; the VM is not production-hardened. Not yet independently benchmarked against mature commercial products.
- Accredited external audit of the C/Zend and of the packaging: pending.
- Windows x64 binaries: built and tested natively on Windows 11 (Pass 32). macOS/ARM64 binaries: built and tested only in CI; Apache SAPI and stress: not tested. Real third-party applications: **WordPress and Joomla** validated end-to-end (source-cipher and bytecode, byte-for-byte identical; Passes 19–20). **Drupal 11** validated end-to-end in **both source-cipher and bytecode**, byte-for-byte identical (Passes 23 and 25; the full-tree bytecode emit crash was the arena-sizing bug, fixed in Pass 25 — all 13637 files emit and the full site renders identically). **PrestaShop 9** (full package, PHP 8.3) validated encrypted end-to-end with the §7 recipe — `var/` clear (container + Doctrine metadata + class_index) **plus excluding the 33 `@ORM` entity files** — renders identical to the baseline (189 products; only cache-hash/timestamp diffs); its **bytecode emit** is validated on 100 % of its 34138 files (Pass 25), the bytecode *render* inferred from the three validated bytecode sites. PrestaShop 8.2 has the same annotation limit and does not run on PHP 8.3. The **optional
obfuscation/hardening option matrix is now measured on all four CMSs** (Pass 29): Joomla 5.2.2 and
PrestaShop 9 added empirically, correcting the earlier PrestaShop prediction — PrestaShop breaks under
`--strip-comments`/`--compact` (its `AbstractLazyArray` reads `@arrayAccess` docblocks at run time), now
flagged by `preflight` (`reads-own-docblock`) and by an active `pack` warning.
- OPcache: refused by default; coexistence via opt-in + blacklist (protected files are re-decrypted on each request). Decrypted code is never cached between requests, by design. OPcache switched off per directory/vhost/pool after being on at startup is accepted since HOST-1 was fixed.
- Hosting reach: a customer cannot install a PHP extension on shared hosting, so Envelock runs there only if the provider installs it (PIE makes it one command for them). The prebuilt Linux loaders run on glibc 2.28+ without the system's OpenSSL (HOST-2 fixed); with OpenSSL inside, each OpenSSL security release means rebuilding them. See `docs/HOSTING.md`.

**Conclusion:** hardened and tested within a defined scope; not invulnerable, not certified, and not guaranteed free of bugs. It must not be advertised as "no one can see the source". To protect against the administrator, another model is needed, not more layers of encryption in this same process.

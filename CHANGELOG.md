# Changelog

## 1.0.0 (unreleased) — 2026-11-09 (first release: anti-root architecture and full obfuscation)

Envelock's first release. On top of the strongest source cipher in its class, it makes the PHP source
itself stop existing in the package and in process memory (the anti-root bytecode layer). The bytecode
layer and every obfuscation pass are **opt-in and off by default**: a base source package still runs
with none of them. This work was developed internally under the "2.0" codename; it ships as part of the
first 1.0.0 release. **Not yet published to GitHub.** The sections dated earlier below are the
pre-release development history of this same 1.0.0.

### Hosting compatibility, portable Linux loaders and PIE (2026-11-11/12)

IDs HOST-1…6 in `docs/AUDITORIA.md`, Pass 33; results in `TEST-STATUS.md`.

**Loader fixes (`extension/`).**
- **OPcache switched off per site was refused (HOST-1).** With OPcache on in `php.ini` and off for
  one directory, vhost or FPM pool — the only OPcache change a hosting customer can usually make —
  OPcache's compile hook stays above the loader's, and the loader took it for a foreign hook ("another
  extension installed a compile hook above Envelock's"), also with `allow_opcache=1`. The loader now
  recognises a hook above it as PHP's own when its code lies in the same image as OPcache's (or
  Phar's) start-up function, and a post-start-up callback records whether a foreign hook already sat
  above it when PHP finished starting, so the exception hides nothing. Tests
  `test_opcache_switched_off_after_startup_runs_and_preflight_agrees`,
  `test_opcache_switch_off_does_not_excuse_a_foreign_hook`; FPM pool case in `scripts/fpm_smoke.py`.
- **Debian/Ubuntu's Phar made every protected file refused (HOST-6).** There Phar is a shared module
  loaded from `conf.d` after an `extension=` line in `php.ini` (the documented installation), so its
  hook sat above the loader's. Measured on Ubuntu 24.04 with its PHP 8.3; fixed by the same change.
- **Trusted time** also loads the system's CA bundle from the usual distribution paths (needed by the
  portable Linux loaders, whose linked-in OpenSSL has no certificate folder).
- **`config.m4`** carries the hardening itself (stack protector, stack-clash protection, CET, full
  RELRO, BIND_NOW, non-executable stack), so a plain `phpize` build — PIE's — is hardened too.

**Portable Linux loaders (HOST-2).** The previous Linux loaders needed glibc 2.38 and the system's
OpenSSL 3, which ruled out Ubuntu 22.04, Debian 12 and the whole RHEL 8/9 family (most hosting).
`scripts/build-unix.sh` gains `ENVELOCK_OPENSSL_STATIC` (OpenSSL linked in, its symbols hidden; the
module must not need `libssl`/`libcrypto` or export anything but `get_module`) and
`ENVELOCK_MAX_GLIBC` (refuses a module that needs a newer glibc). The prebuilt loaders are rebuilt that
way on AlmaLinux 8 with OpenSSL 3.5.9: they need glibc 2.28+ only (GLIBC_2.25 measured) and no
system OpenSSL. Each OpenSSL security release now means rebuilding them (`docs/PLATAFORMAS.md`).

**Windows loaders** rebuilt with the fixes (same toolchain as 2026-11-10).

**Install with PIE.** `composer.json` (`envelock/loader`, `type: php-ext`, build path `extension/`,
prebuilt binary first, source build as fallback, no configure options that could expose the bytecode
emitter or runner); `scripts/package-pie-assets.py` packages the prebuilt loaders as Release assets
with the exact names PIE's source expects (checked against `prebuilt/SHA256SUMS`, compiler read from
each DLL); tests `tests/test_pie_packaging.py`; `docs/HOSTING.md` §4.1–4.2, `docs/BUILDING.md` §8. A
PIE 1.5.5 source build was checked on AlmaLinux 8.

**Documentation and checks.**
- **New `docs/HOSTING.md`**: the loader's native dependencies as measured in the binaries, what the
  server's PHP configuration must allow and who can change it, what makes the loader refuse protected
  files, what each kind of hosting allows (VPS, Docker/Kubernetes, shared hosting by panel, managed
  WordPress and PaaS, Windows), PIE, and a message for a hosting provider.
- **The options recommender explains every option and says when it is unsure.** Every protection
  option of `pack` is now in one of three groups: enable; enable but **check first** — it depends on
  the server (`--no-ffi`, `--no-prepend`), the PHP build and pack-time setup (`--bytecode`), whether the
  whole application is packed (`--include-protection`), names built at run time
  (`--obfuscate-methods`), docblock-reading libraries (`--strip-comments`/`--compact`, naming the one
  found in `vendor/`) or PHP the app writes (`--sealed`), each with why and how to check; or do not
  enable, each with its reason (now also `--obfuscate-flatten`, `--obfuscate-names` and `--virtualize`,
  saying where one *might* work and how to try it). `recommend_options` returns the new `verify` map;
  test `test_recommend_explains_every_option_and_says_when_it_is_unsure`.
- **New `scripts/envelock-preflight.php`**: run on a target server (browser or CLI), it reports what
  would stop the loader there and which loader file to use. Tests
  `test_preflight_accepts_a_configured_loader` and the HOST-1 test above.
- **Corrected:** `prebuilt/README.md` and `docs/PLATAFORMAS.md` said the earlier Linux loaders needed
  glibc 2.33 (they needed 2.38); `README.md` still said the only included loader was Linux PHP 8.4 NTS.
- **Tests:** the OPcache tests of `tests/test_native.py` skipped on every Windows PHP 8.2–8.4 (the
  helper looked for `php_opcache.dll` in `C:\php\ext`, HOST-3); they now run and pass.
- **CI:** the macOS job moved from the retired `macos-14` runner to `macos-15`.
- **First two GitHub CI runs (private repository) — what they found and the fixes.** The first run
  built on every platform and surfaced the lint, macOS-build and Linux/Windows test issues below; the
  second, with those fixed, left only three failures, all environment or platform limits of the test
  harness, not the loader, confirmed by reproducing the loader's behaviour on a kernel that allows
  ptrace:
  - **Anti-debugger test (`test_o3_a_tracer_attached…`), Linux x86-64 and ARM64.** The test attaches
    a real tracer to a *separate* process; GitHub-hosted runners restrict ptrace
    (`kernel.yama.ptrace_scope`, no `CAP_SYS_PTRACE`), so `PTRACE_SEIZE` returns `EPERM` and the
    scenario cannot be set up. It now skips on `EPERM` as it already did on WSL1's `EINVAL`; the
    TracerPid parser itself stays covered by `test_o3_tracer_pid_reads_a_real_status_file`, which
    needs no live tracer.
  - **Startup trusted-time fetch (`test_o8_trusted_time_is_fetched_at_startup`), Linux.** The test
    uses `strace` (which also needs ptrace) to see the loader's `connect()` to the time host at
    startup. Under the runners' restricted ptrace `strace` records nothing and the trace is empty.
    Verified on AlmaLinux 8 that the **published** PHP 8.4 NTS loader (`a8ced333…`) does attempt the
    connection — `connect(…, htons(443), 127.0.0.1) = EINPROGRESS` — and the protected file runs. The
    test now probes once whether `strace` can observe a known `connect()` here and skips when it
    cannot, rather than asserting against an empty trace.
  - **Machine-bound licence on macOS (`test_o8_licence_bound_to_another_machine_is_refused`).** The
    loader's machine fingerprint reads Linux-only sources (`/etc/machine-id`, `/sys/class/net`), so on
    macOS — as on Windows — it reports no identity and every machine-bound licence is refused for want
    of one (fail-closed). The test now expects that message on macOS too. **Machine binding is a
    Linux-only feature; a licence bound to a machine will not run on macOS or Windows.**
  - **macOS:** the loader did not compile. The vendored bytecode layers called
    `madvise(MADV_DONTDUMP)`, which macOS lacks. They now call one `ENVELOCK_DONTDUMP` macro from
    `envelock_accel_shim.h`, a no-op where `MADV_DONTDUMP` does not exist. Each caller keeps its
    line count (`__LINE__` is part of the bailouts). A rebuilt Linux PHP 8.4 NTS loader is
    byte-identical to `prebuilt/` (`a8ced333…`). For Windows the preprocessed code is unchanged
    (that branch never called `madvise`).
  - **Tests that assumed Linux or Windows:**
    - `_identity_check` now sets the owner only. macOS refuses a group the user is not in.
    - The TracerPid parser test runs only on Linux, where the parser exists.
    - The ENC-25 case-collision test probes the file system instead of checking `os.name`.
    - The release-guard test strips the `/private/var/…` temporary root before looking for
      `private/`.
  - **`tests/test_virtualize_resolution.py`** ran `php -n`. On Debian/Ubuntu PHP the tokenizer is a
    shared module, so it was missing (`T_THROW` undefined). The test now loads it when it is not
    built in. The encoder itself never runs with `-n`.
  - **Lint:** Ruff is clean (import order, unused imports, one statement per line). Bandit's
    findings were all intended and are annotated with the reason.
  - **Jobs:**
    - The FPM job runs on `ubuntu-24.04`, where `php8.3-fpm` exists.
    - The bench job builds the loader with the bytecode emitter it needs.
    - The Windows job runs the native suite with a throwaway identity made in the job. The encoder
      refuses the public demo keys by design (ENV-AUD-07).
- **Release tree:** the 55 files that `SHA256SUMS` lists but the previous complete ZIP lacked
  (Makefiles, `configure`, test archives, `.o` files of the portable Pythons, …) were restored from the
  official upstream archives, each matching its listed hash.

### Security — native Windows validation and adversarial audit (2026-11-10)

The first run on a real Windows (Windows 11 x64, official PHP for Windows 8.2–8.5 NTS/TS, Visual Studio
Build Tools 2022, `BuildPhpExtension` 1.9.0), followed by a hostile five-part audit (loader core;
licence/clock/trusted-time policy and the VM; the bytecode layer; the encoder; the tooling) whose
findings were reproduced, fixed and re-tested on native binaries. IDs are those of
`docs/AUDITORIA.md`, Pass 32, which also lists what stays open.

**Loader core, policy and VM (`extension/`).**
- **Manifest fast path let one trusted developer vouch for another's file (CORE-1, high, confirmed).**
  A manifest only proves that its signer hashed the listed bytes. On a server trusting developers A and
  B, B could list the SHA-256 of A's `--include-protection` file (or of a file signed by an untrusted
  key) in B's own signed manifest: the per-worker cache then treated it as verified and attributed to
  B, so B's code loaded A's protected file, and a container no trusted key signed ran. The fast path now
  applies only when `identity.bin` trusts exactly one developer, and digests are seeded only after the
  whole manifest has validated (never overwriting an existing entry). Test
  `test_manifest_fastpath_cannot_reattribute_another_developers_file`.
- **The VM ignored `max_execution_time` (POL-3, medium, confirmed)**: it cleared the VM interrupt
  without checking `EG(timed_out)`, so any script could make itself unkillable by the time limit. It now
  calls `zend_timeout()`. Test `test_vm_honours_max_execution_time`.
- **`__envelock_vm_v2` callable dynamically (POL-4, medium, confirmed)**: `$f(...)` and
  `call_user_func('__envelock_vm_v2', ...)` passed the direct-call gate, turning a one-argument dynamic
  call sink into arbitrary function calls. Dynamic calls are now refused ("Cannot call ...
  dynamically"). Test `test_vm_entry_refuses_dynamic_calls`.
- **The VM passed PHP references through (POL-9, low, confirmed)**: arguments are now dereferenced
  (`ZVAL_COPY_DEREF`). Test `test_vm_does_not_alias_reference_arguments`.
- **Trusted time** (POL-2): a network time more than a day ahead of the local clock is now treated as
  evidence of a clock set back — kept as the in-memory floor (so an expired licence is refused) but not
  persisted — instead of being discarded; the TLS handshake no longer checks certificate dates against
  the suspect local clock (`X509_V_FLAG_NO_CHECK_TIME`; hostname and chain are still verified). Linux
  code only (trusted time is not built on Windows).
- **Licence and clock checks** (POL-7, POL-10, POL-11, POL-12): a clock reporting time ≤ 0 is refused
  when the licence has an expiry; the machine and IP fingerprints use every entry (sorted) up to 256 and
  refuse beyond, exactly like the encoder (they used to stop at 64 in enumeration order); the CLI,
  phpdbg and embed SAPIs ignore `$_SERVER` for the domain binding (an environment variable
  `SERVER_NAME` no longer satisfies it); the clock-state file is refused when it is a hard link, a
  reparse point/symlink, a FIFO or not a regular file, is opened non-blocking, is updated under a lock on
  thread-safe builds, and is no longer created at MINIT (under PHP-FPM the root master created it 0600
  and the workers could never write it). Test `test_o8_clock_state_is_never_written_through_a_hardlink`.
- **Small-order Ed25519 keys** in `identity.bin` are refused at load (also by the encoder, ENC-14).
  Test `test_identity_with_a_small_order_signing_key_is_refused`.
- **Content key cleared on every failure path** (CORE-2, low): `OPENSSL_cleanse` before each fatal
  error in the decrypt and vault-table failure paths.
- **No build-machine paths in the binaries.** `__FILE__` (from `zend_bailout()` and OpenSSL's memory
  macros) and the linker's absolute PDB path put the builder's TEMP folder and user name into the
  DLLs. The sources now call `_zend_bailout("<file>.c", __LINE__)`, `config.w32` builds with
  `OPENSSL_NO_FILENAMES` and `/PDBALTPATH:php_envelock.pdb`, `scripts/build-windows.ps1` refuses a DLL
  that embeds the profile, TEMP, build or source path, and `scripts/check_bc_layers.py` forbids
  `zend_bailout()`/`__FILE__` in the bytecode layers.
- **`config.w32`**: a `;` in an option's help text truncated the generated `configure.js` (phpize's
  option extractor stops there), and a thread-safe build hit the bytecode layer's NTS-only `#error`. TS
  builds now compile without the bytecode layer, as `config.m4` already did.
- **Licence trust model documented, not changed (POL-1, POL-5, POL-6).** Licence enforcement is policy
  set in `php.ini` by the server administrator — the licensee — so it is not DRM; already-compiled code
  keeps running after expiry in long-lived workers; machine binding is "medium", not "strong". MANUAL
  §14 now says so.

**Bytecode layer (`extension/opcache/`, all four versions) — BC-1 … BC-18, all fixed.**
- **BC-1 (critical, found only on native Windows):** after the crash guard caught a fault in the
  deserializer, `EG(bailout)` still pointed at a dead jump buffer, so the *next* fatal error in that
  process crashed it (`0xC0000409`). Every rejection now restores the saved engine state. The earlier
  claim that the guard made any corrupted image a clean rejection was therefore incomplete until this
  fix. Test `test_fatal_error_after_a_rejected_image_does_not_crash`.
- **BC-2:** a PHP fatal during install (for example "Cannot redeclare") left the POSIX guard armed; the
  install now runs in a `zend_try` inside the guard, which is disarmed before the bailout is re-raised.
- **BC-3, BC-4, BC-5, BC-9, BC-15:** the 8.3 layer had lost every element-count check; all count-driven
  loops are now bounded in every version; the relocation bound, base and mode come from the validated
  header, never from the image; hash-table invariants are checked and the hashes and chains rebuilt; the
  full extent of each structure is checked, not just its start.
- **BC-6, BC-8, BC-12, BC-14:** early-binding cache slots, opcode-handler indexes and operand types are
  validated; relocated strings no longer keep flags or a class-name map pointer taken from the image;
  the 8.5 constant-expression paths no longer reach an unreachable marker.
- **BC-7:** a failure part-way through install removes every function and class entry pointing into the
  image, and the buffer is kept (not freed) when something may still reference it.
- **BC-10:** an image that calls a function of an extension the server lacks now raises "Call to undefined
  function" instead of crashing (no frameless or specialised internal calls are emitted).
- **BC-11:** `scripts/check_bc_layers.py` (also in CI) fails if a layer loses a hardening construct or
  the shared files drift between versions; `gen_persist.py` refuses to overwrite a hardened layer.
- **BC-13:** the SEH filter catches only memory, instruction and arithmetic faults and stack overflow
  (re-arming the guard page), not every exception; POSIX also handles SIGFPE and SIGILL; deserializer
  recursion is bounded.
- **BC-16:** the image no longer carries `zend_system_id`, which differs between the CLI and CGI/FPM of
  the same PHP build (the CLI installs an interrupt handler), so a CLI-packed image could not load under
  php-cgi or FPM. It carries an Envelock bytecode identity (PHP version, build id, data model, structure
  sizes, VM kind). **Images emitted by earlier loaders are refused: re-pack `--bytecode` packages.**
- **BC-17, BC-18:** the emit arena fails closed when exhausted; programs over 4 GiB are refused.

**Encoder (`encoder/envelock.py`) — ENC-1 … ENC-26, all fixed.**
- **Secrets on Windows (ENC-1, ENC-4, ENC-5, ENC-6, ENC-13, ENC-24):** every new secret is created with
  its protected ACL in the create call (no create-then-restrict window); `server-install` works on
  Windows and leaves no readable identity behind; `--bytecode` temporary sources are owner-only and a
  link under the deploy root is refused; updating an identity file keeps its explicit ACL and owner; the
  licence keeps the folder's inherited ACL; `ENVELOCK_PASSWORD_FILE` must not be readable by others.
- **POSIX `server-install` (ENC-2, ENC-12):** `O_NOFOLLOW` and `fchown`/`fchmod` on the open file (no
  symlink race); the package root is created traversable (0755).
- **Program resolution (ENC-3):** a bare `--php php` is looked up in absolute `PATH` entries only, never
  in the current folder. **Behaviour change:** a `php.exe` in the current folder is no longer used.
- **Correctness (ENC-7, ENC-8, ENC-10, ENC-25):** `--vault-strings` with member obfuscation keeps
  behaviour; `verify` reports added content behind a link and fails on an unreadable folder;
  `--exclude`/`--asset` accept `\` and are case-insensitive on Windows, and **an excluded folder now
  excludes its contents**; more reserved Windows names and case collisions are refused, and the tree
  walk never follows links.
- **Keys and licences (ENC-11, ENC-14, ENC-17, ENC-18, ENC-19):** new `owner split-recovery` moves the
  recovery key to its own file (used by `promote-recovery --recovery`); small-order Ed25519 public keys
  are refused; the demo-recipient refusal compares key values; licence domains are canonicalised exactly
  like the loader (IDN as punycode); MAC/IP fingerprints match the loader's limits.
- **Leaks and limits (ENC-15, ENC-16, ENC-21, ENC-22, ENC-26):** more credential dotfiles are always
  excluded; `php -l` reads from stdin (no plaintext temp file); the PHP helper programs are passed on
  stdin (the transform was close to the Windows command-line limit); `--virtualize` quotes its compiler
  path correctly and runs with `memory_limit=-1`.
- **Messages (ENC-9, ENC-20, ENC-23):** the default serial is documented as nanoseconds; the vault entry
  layout is documented as `nonce|ciphertext|tag`; options that were silently ignored are refused.

**Tooling — T-1 … T-21 (T-10 documented).** The release guard checks a staged tree that is not a live
git checkout completely (tool folders, top-level `private/`/`build/`/`dist/`, encrypted key files under
any name, UTF-16 files, `.pyc`), rejects a non-directory argument, finds user paths in every spelling,
understands case-insensitive file systems, and with `--require-complete` reports listed files missing
from the tree (T-1, T-4, T-9). The virtualizer resolves `use function`/`use const` imports, keys float
constants by their bits, no longer folds float-to-string conversions with the packer's precision, and
refuses calls to the pack's by-reference functions (T-2, T-5, T-8, T-11; T-10, the extra VM frame in
backtraces, is documented in MANUAL §14.4). The assistant never runs a PHP from a folder other users
can write or from the current folder, checks its busy state before any side effect, asks before closing
mid-operation, keeps the UI thread free, and refuses every non-HTTPS redirect hop (T-3, T-12–T-14, T-19).
`envelock.cmd` can no longer run a `python.exe` planted in the current folder (T-6). Build parity and
gates: no fallback to another minor's bytecode layer, `-fvisibility=hidden` in `config.m4`,
`_FORTIFY_SOURCE=3` when available, fail-closed export checks, the exposure gate on Windows, CI lints
`gui/` and runs `check_bc_layers.py` (T-7, T-15–T-18, T-20); `build-gui.sh` no longer claims that an
unpinned PyInstaller cannot affect the keys (T-21, message only). `framework-smoke.py` takes
`--php`/`--loader`/`--emitter` and runs on Windows.

**Options recommender (`recommend`, the assistant's Recommend tab), checked end to end.** Its
suggested command was packed as printed and deployed on real Laravel and Symfony apps. Fixed:
- With `--no-ffi` and PHP's built-in `enable_dl = On` (no php.ini, or one that does not set it) every
  request was refused (0 of 10 Laravel routes). `--no-ffi` stays recommended, with the php.ini it needs
  (`enable_dl = Off`, FFI not armed — also for the CLI where FFI is loaded); it is turned off for a
  project that uses FFI or `dl()` itself. `--no-prepend` states its requirement too.
- `--include-protection` was recommended for projects whose console script has no `.php` extension
  (`artisan`, `bin/console`), which `pack` leaves cleartext: `php artisan route:list` was refused. It is
  now turned off, with the reason, when such an entry point exists.
- `vendor/` was analysed and would have been encrypted, against the documented layout: third-party
  matches (Blade's compiler tokenizes templates) switched `--bytecode` and `--strip-comments` off. With
  Composer's `vendor/autoload.php` present it now recommends `--exclude 'vendor/*'` and analyses only the
  project's own code; the run-time caches (`bootstrap/cache`, `storage/framework`, `var/cache`) are
  excluded and Blade templates (`*.blade.php`, read as text by Laravel) kept cleartext without
  disabling `--bytecode` for the rest.
- The suggested `--bytecode` command now carries `--bytecode-php` and `--bytecode-loader`, and the
  recommendation says that the server must run a non-thread-safe PHP and that packing needs an emitter
  build (the production loaders have none); `pack`'s own error for a missing emitter says the same.
  `--compact`'s collapsed line numbers are mentioned. The scan uses `pack`'s own walk (no links, no
  `.git`/`node_modules`).
- Result with the new recommendation: Laravel 10/10 web routes and `artisan route:list` (only the
  closures' line numbers differ, from `--compact`), Symfony 7/7 and `bin/console debug:router` identical
  to the unprotected apps, both for the own code and for the whole application folder. Tests
  `test_recommend_leaves_composer_vendor_caches_and_blade_templates_in_the_clear`,
  `test_recommend_turns_include_protection_off_for_a_cleartext_console_entry_point`,
  `test_recommend_no_ffi_states_its_php_ini_requirement_and_respects_ffi_users` (they fail on the
  previous recommender).

**Windows-specific fixes found by the native run.** Non-ASCII paths (ENV-14 was only half fixed: its
test always skipped on Windows, as it could not run under Wine): the identity file opened only when its
path came from a UTF-8 `php.ini`, while `php -d` hands the value over in the ANSI code page and failed
with "cannot be opened"; the clock-state file used the ANSI `open()` and so failed the other way round,
for a UTF-8 `php.ini` path. Every configured path (identity, licence, clock state, manifest) now goes
through one conversion — valid UTF-8 as UTF-8, anything else as ANSI — and the wide file API. Tests
`test_php_identity_path_non_ascii` (now run on real Windows) and
`test_php_non_ascii_identity_and_clock_paths_from_a_utf8_php_ini`. The assistant executable lacked hidden imports
(`shlex`, `calendar`, `ctypes.util`, `socket`, `types`) and stopped at start; the spec lists them and a
test keeps it in sync with what the bundled code imports. `--e2e` without a folder exits with a usage
message instead of stalling on an error dialog. The native test suite now recognises a Windows crash
exit code (Python reports `0xC0000005` as a positive number, which the old checks missed), no longer
deadlocks on a full pipe from `php -S`, and sets ACLs by SID rather than English group names.

### Security — internal hardening audit (Nov 2026)

A fresh in-code audit across the crypto trust boundary, native memory safety, licence/time, the Python
encoder, the release guard and documentation↔code coherence. No exploitable break of the
signature/verify-before-decrypt boundary was found. Fixed, each with a regression test where one
applies:

- **Release guard (`scripts/check_release.py`).** It now **fails on the presence** of the internal
  notes file (`CONTEXTO-PROYECTO.md`) in any tree that is not a live git working copy (a `.gitignore`
  entry ships inside the release and cannot prove absence), **warns** when `forbidden-terms.txt` is
  absent (the term check is then disabled), **scans non-UTF-8 data files** (`.sql`/`.csv`/… are no
  longer skipped on a decode error — Latin-1 fallback), and **refuses compressed archives** outside the
  hash-locked folders (their contents are not scanned).
- **Encoder `__halt_compiler()` honesty.** Files containing `__halt_compiler()` cannot be rebuilt from
  tokens and were passed through untransformed while the manifest still claimed the protections applied.
  The passes now report them and the manifest records them under `files_not_token_transformed`; the
  packer warns when such a file would ship as readable source (without `--bytecode`).
- **Bytecode deserializer — crash-safe against a malformed image.** Two layers. (1) `script->size` is
  re-anchored to the header `mem_size` that was validated and checksummed, so a forged size cannot widen
  the relocation bound into an arbitrary-offset *write*. (2) The whole load (deserialize **and** install
  into the engine) runs under a crash-safety guard — SIGSEGV/SIGBUS on an alternate stack on POSIX, SEH
  on Windows — that turns **any** wild read/write or stack overflow from a corrupted image into a clean
  rejection (`NULL`, reported as "image does not match this build") instead of killing the worker. A
  differential fuzz that forces every field of the serialized struct to a hostile value now produces
  **zero** crashes in the deserializer (regression test `test_bytecode_deserializer_never_crashes_on_a_corrupted_image`,
  via a test-only `envelock_bc_load_check` gated under `ENVELOCK_BCRUN`). The bytecode layer is NTS-only
  (ENV-2026-03), so the process-global handler is safe. Note this hardens the *deserializer*; executing a
  corrupted-but-signed image is a separate, inherent trust-boundary case (a trusted signer could ship
  malicious source directly), unchanged by this.
- **Trusted time.** A wildly future `Date:` from a misconfigured or compromised time source is ignored
  instead of being accepted and **persisted** as a floor, which used to brick the deployment.
- **Smaller items.** `write_public` leaves a directory it creates traversable (a public licence must be
  readable by a non-root service user); the clock-state write refuses a planted hardlink
  (`st_nlink != 1`); `config.w32` mirrors `config.m4`'s split emit/run flags (the dead `ENVELOCK_BCPOC`
  macro is gone); documentation was corrected to match the code (real `prebuilt/` inventory, the
  `--enable-envelock-bc*` flags, the Recommend assistant tab, manifest enforced by default).

**Scope.** The deserializer is now crash-safe against an arbitrary malformed image (the fuzz above).
What remains inherently out of scope is *executing* a corrupted-but-validly-signed image: running
attacker-chosen opcodes cannot be made safe and needs no memory bug to do harm, and a holder of a
trusted signing key can already ship arbitrary PHP source. The Ed25519 signature remains the trust
boundary; the deserializer hardening is defense-in-depth beneath it.

### Security — external audit, second pass (ENV-2026-01..33)

A second independent external audit of the 1.0.0 source reported 33 findings (8 Critical, 12 High, 10
Medium, 3 Low). **All 33 were reproduced in code and fixed**, each with a regression test that fails
without the fix; a few low-impact defence-in-depth items are left as documented residuals. Full detail,
per finding, in `docs/AUDITORIA-EXTERNA-ENV2026.md`. Highlights:

- **Bytecode to production.** The emit/run surface is now split behind explicit `./configure` flags
  (`--enable-envelock-bcemit` for the packer, `--enable-envelock-bcrun-unsafe` for tests), never an
  inherited environment variable, with a runtime `function_exists` gate in the build scripts so a
  server loader can never ship the RCE runner (ENV-02). The bytecode layer refuses to build under ZTS
  (`#error`; `config.m4` builds source-only for a thread-safe engine) (ENV-03). The deserializer's
  pointer/interned bounds fail closed (ENV-04); the decrypted image buffer is cleansed on error and
  kept out of core dumps on success (ENV-09). The recommender offers `--bytecode` again for compatible
  projects.
- **Loader (C).** The encrypted literal vault no longer resolves through internal callbacks
  (`array_map`) (ENV-05), nor corrupts `$_SESSION` at shutdown (ENV-24). A domain-bound licence follows
  `SERVER_NAME`, not a spoofable `Host` header (ENV-06). On a multi-developer host, a manifest is
  accepted only from the package's own developer (ENV-25). `--sealed` refuses plain PHP wherever it
  lives while active, not only under the tree (ENV-28). The mini-VM honours `max_execution_time` and
  its call opcode enforces the frame blocklist (ENV-07). `envelock_trusted_time` is no longer a
  userland network primitive (ENV-08). Machine-fingerprint parity between encoder and loader is unified
  via physical-device detection, and the licence parser fails closed on unknown fields (ENV-30).
- **Encoder / obfuscation.** `--obfuscate-methods` / `--obfuscate-properties` isolate nested anonymous
  classes (ENV-14/15); `--obfuscate-flatten` resolves `use function` aliases and refuses inline HTML
  (ENV-16/29); `--virtualize` passes only declared parameters and preserves line numbers (ENV-26);
  `--vault-strings` fails closed rather than ship secrets in cleartext (ENV-29).
- **GUI / scripts.** The VC++ redistributable install closes its TOCTOU window and bounds zip
  extraction (ENV-27); the release guard can verify the tree is complete (`--require-complete`,
  ENV-01); `audit-native.sh` statically analyses every C unit with the bytecode layer on (ENV-33).

*Earlier `ENV-AUD-01` (the `__envelock_lit` caller check) and `ENV-AUD-16` (the VC redist TOCTOU),
previously reported as closed, are now genuinely closed by ENV-05 and ENV-27 respectively.*

Added (opt-in):

- **Bytecode packaging (O1), `--bytecode`.** Each file ships as a precompiled, serialized
  `zend_op_array` (format bit 6), encrypted and signed like any package. The loader deserializes it
  in place; the compiler never sees source, so there is no decrypted source in the process to
  intercept — closing the main root-reads-memory weakness. The image carries `zend_system_id` (since
  2026-11-10 an Envelock bytecode identity instead, BC-16) and runs only on the exact PHP build that
  produced it (fail-closed). The bytecode layer is vendored
  per PHP minor under `extension/opcache/<ver>/` (adapted OPcache persistence; generator
  `extension/opcache/gen_persist.py`) and is **optional**: a loader built without a layer for its
  version runs source packages and refuses a bytecode file at runtime. Needs `--deploy-root` (paths
  are compile-time constants baked into the image). Incompatible with `--vault-strings`.
  Per-version layers are provided for **PHP 8.2, 8.3, 8.4 and 8.5** (`extension/opcache/php8{2,3,4,5}/`).
  *Verified:* bytecode round-trip compiles and passes on all four (13/13 each); full native suite on
  8.3.6 — the only PHP here with the tokenizer — at 983 passed / 0 failed / 9 skipped, including the
  AST-obfuscation→bytecode combination. Two per-version deltas were handled: `get_class_name_map_ptr`
  returns `uint32_t` on 8.3 but `void` on 8.2/8.4/8.5, and 8.5 split the SHM loader into a
  `_ex` variant (dropped by the generator, like the rest of the SHM path). *Pending:* the
  AST→bytecode combination on 8.2/8.5 (their tokenizer is absent in this environment; verify in CI).
- **Encrypted string-literal vault (O7), via `--vault-strings`.** The literal table is now
  encrypted at rest inside the plaintext (format bit 7, set together with bit 5); each literal is
  decrypted only when read and wiped at end of request, instead of the whole table sitting
  decrypted for the request. Honest limit: a reader who can decrypt the container can still unwrap
  the data key.
- **Global AST obfuscation (O6):** `--obfuscate-names` (classes/interfaces/traits/enums/constants),
  `--obfuscate-names-ast` (namespaced code), `--obfuscate-names-allow KIND:FQN` (white-list, keeps
  frameworks safe), `--obfuscate-methods`, `--obfuscate-properties`, `--obfuscate-flow` (opaque dead
  branch), `--obfuscate-flatten` (experimental, control-flow flattening). Public renaming is opt-in
  only. *Verified:* differential fuzzer, 0 divergences; functional on PHP 8.3.
- **Hardened secret handling (O2):** transient plaintext and keys kept in `memfd_secret`
  (Linux ≥5.14) with an `mlock`+`MADV_DONTDUMP` fallback, out of `/proc/pid/mem` and core dumps.
- **Anti-rehook self-check (O3):** the loader verifies its own `compile_file` hook, watches for a
  foreign `zend_ast_process`/observer and `TracerPid`, with an opt-in paranoid mode that refuses to
  run under observation.
- **Deployment licensing (O8):** `licence issue` (expiry, domain, IP, machine fingerprint),
  `licence machine-id`/`host-id`, anti-clock-rollback, and an optional online trusted-time check
  over TLS with full certificate and hostname verification.
- **Cold-start manifest fast path** (introduced opt-in; **now on by default under `--enforce-manifest`** — see "Fixed and changed" below): `envelock.manifest_fastpath=1`, for
  `--enforce-manifest` packages. The signed manifest's single signature stands in for each file's
  own Ed25519 on first load (the manifest already carries a trusted SHA-256 of every file), seeded
  into the per-worker verified cache. Measured ~130 µs/file removed from first-request latency
  (120-file package: 24.5 ms → 9.0 ms cold). Fail-closed: altered bytes miss the set and take the
  full per-file verify, which then fails; a wrong/missing manifest refuses and seeds nothing. Ships
  default-off; the verification-path change was independently reviewed (verdict: sound).
  See `docs/RENDIMIENTO.md`.
- **Root-owned identity install (O5):** `recipient server-install`/`export-identity` lay the secret
  identity file down `root:root 0400`, so the pool user cannot read the key while the FPM master
  can; the loader accepts `0400` and root ownership.

Experimental / laboratory only:

- **Opcode mini-VM (O4):** `--virtualize FUNCION` + `--virtualize-loader` + `--unsafe-vm-laboratory`.
  A real stack VM for marked top-level functions. Quarantined behind the unsafe flag and documented
  as not production-ready; see `docs/MANUAL.md` §14.4.

Fixed (deep code audit, November 7):

- **CRITICAL — the proof-of-concept bytecode userland functions are no longer built into any server
  loader.** `envelock_bc_emit`/`envelock_bc_run` were PoC helpers from the bytecode work;
  `envelock_bc_run` deserialized caller-supplied bytes through the OPcache unserializer (arbitrary
  code execution from any PHP that could call it). They are now gated behind a build-time
  `ENVELOCK_BCPOC` flag (`config.m4`/`config.w32`): a production loader is built **without** it, and
  only the test suite and the encoder's bytecode pass set it. Verified: all five Linux production
  loaders export zero `envelock_*` symbols and contain neither function as a symbol or a string.
- **MEDIUM — sealed-mode state moved from per-request to per-worker.** The sealed-root set and its
  `eval()`/plain-PHP gate now live in a per-worker `HashTable` in module globals rather than the
  per-request table, so the gate no longer depends on request-local ordering.

Fixed and changed (external-audit round, November 8):

- **O8 trusted-time startup fetch was inert (reproduced).** MINIT read the license-present flag
  before loading the license, so the per-worker HTTPS time fetch never ran and the startup time
  floor was never established; and the floor check was nested under `envelock.clock_state`, so
  deleting the state file disabled it. MINIT now loads the clock state and the license before the
  trusted-time block, and the network floor is enforced whether or not a state file exists.
  Regression test `test_o8_trusted_time_is_fetched_at_startup` (via strace: a connect is attempted at
  startup; none without the fix).
- **`scripts/audit-native.sh` (CI `fuzz` job) failed out of the box.** It packed the demo fuzz corpus
  with the public demo owner key, which `pack_tree` refuses, and it did not copy the extension's local
  headers for the standalone clang analysis. Both fixed; the helper completes and the libFuzzer
  campaign runs.
- **`envelock.manifest_fastpath` is now on by default under `--enforce-manifest`** (was opt-in,
  default off). That package's manifest signature is verified every request for enforcement anyway, so
  seeding the per-worker verified cache from it adds no new trust; it cuts first-request latency ~5×
  (measured ~127 → ~24 µs/file). `envelock.manifest_fastpath=0` forces the per-file verify.
  Independently re-reviewed.
- **Four-CMS option matrix measured; PrestaShop docblock finding + preflight fix (November 9).** The
  optional obfuscation/hardening flags are now measured on all four CMSs (home page packed, served
  through the loader, diffed byte-for-byte against cleartext after normalising per-request tokens).
  **Joomla 5.2.2**: the whole hardening set composes byte-identically, including `--strip-comments`,
  `--compact` and `--sealed` (with the `envelock.sealed_cleartext` allowlist); only
  `--obfuscate-properties` breaks it (Composer autoloader). **PrestaShop 9**: safe set ✅, but
  `--strip-comments`/`--compact` break it — its front-office presenters (`AbstractLazyArray`) read their
  own `@arrayAccess` method docblocks at run time via `getDocComment()`, which those two flags remove
  (silent: HTTP 200, product section absent). Not an Envelock bug (the compactor emits valid PHP; the
  loss is semantic), but `preflight` missed it. **Fixed:** `preflight` gained the `reads-own-docblock`
  category (`getDocComment(`), and `pack` now prints an active WARNING when `--strip-comments`/`--compact`
  is combined with a comment-sensitive tree. Regression test `test_preflight_flags_reads_own_docblock`.
  Full table and the corrected universal safe set in `docs/DEPLOYING-APPS.md`; details in
  `docs/AUDITORIA.md` Pass 29.
- **Self-audit: sealed_cleartext prefix-boundary bypass fixed, options decision guide added (November 9).**
  A fresh "try to break it" pass found one real, self-introduced bug: the `envelock.sealed_cleartext`
  allowlist matched allowed paths as a **plain string prefix with no path-boundary check**, so whitelisting
  `/app/cache` also allowed a sibling `/app/cacheEVIL.php` — under `--sealed`, that let an attacker who can
  write such a sibling run plain PHP inside the sealed tree (fail-open). Fixed to require the prefix to end
  at a path separator; regression test `test_php_sealed_cleartext_allowlist_respects_path_boundary` (a
  sibling ran before the fix). The five Linux loaders were rebuilt. Verified sound with no change:
  signature-before-decrypt/deserialize order on both source and bytecode paths, vault parser bounds, and
  the other path prefix matches (fail-safe or boundary-checked). Re-fuzzed: container crypto under
  libFuzzer+ASan+UBSan (2,000,000 runs, clean) and the differential obfuscator fuzzer (1426 programs, 0
  divergences). Added a decision guide to `docs/DEPLOYING-APPS.md` — per-option advantages, costs and
  when-to-use/avoid, with maximum/balanced/minimum profiles from the four-CMS measurements. See
  `docs/AUDITORIA.md` Pass 30.
- **Options recommender; harder self-audit; Windows binaries rebuilt (November 9).** New command
  **`envelock recommend --source <dir>`** (and a **Recommend** tab in the assistant): it analyses the
  project and recommends the strongest protection that is *safe for it*, enabling the measured-compatible
  hardening and turning off only what would break the project — it drops `--strip-comments`/`--compact`
  when the tree reads its own docblocks, drops `--sealed` when the tree `eval()`s, and never auto-enables
  `--obfuscate-properties` or whole-tree `--vault-strings`; it lists files to keep cleartext and prints a
  ready `pack` command. Conservative by construction (grounded in the four-CMS matrix). A harder audit
  pass (5,000,000-run fuzz, the loader validated on all five engines incl. ZTS, new truncation /
  byte-flip / worker-reuse stress tests) found no new bug. All **8 Windows DLLs** were rebuilt from the
  current source with the sealed_cleartext boundary fix, and both **assistant executables** were rebuilt
  with the recommender (the Windows `.exe` `--selftest` passes under Wine). Native **975/0/10**, Python
  **486/5**. See `docs/AUDITORIA.md` Pass 31.
- **`pack` writes the signed runtime manifest by default** (was opt-in `--enforce-manifest`). Every new
  package now gets deletion detection at load and the ~5× fast path; `--no-manifest` opts out, and the
  GUI checkbox defaults on. The `pack_tree` API default is unchanged (`enforce_manifest=False`); only
  the CLI/GUI default changed.
- **Windows loader, with the bytecode layer (O1).** The native modules were ported to the
  MSVC/Windows toolchain: stray POSIX includes guarded, the VM's `noinline` spelled portably, the
  host-name lookup made Winsock-free, and the per-version bytecode layer's `"php_config.h"` guarded
  (`#ifndef PHP_WIN32`). All 8 DLLs (8.2–8.5 × NTS/TS) build with the bytecode layer; the full
  bytecode round-trip is verified under Wine on 8.4 and 8.5 NTS. See `docs/AUDITORIA.md` Pass 18 and
  `docs/PLATAFORMAS.md`. macOS source is portable (POSIX + `__APPLE__`), validated by CI / a real Mac.
- **Autoglobals armed when a bytecode image loads (real-application fix).** A function whose first use
  of an autoglobal in a request came from a `--bytecode` image saw it as `null`: a normally compiled
  file arms `$_SERVER`/`$_GET`/… the first time the compiler meets each, and a deserialized op_array
  skipped that step. `envelock_bc_load_image` now arms the standard set on load, the same restoration
  OPcache performs from `ping_auto_globals_mask` (all four per-version layers). Found by running
  WordPress end-to-end: `wp_fix_server_vars()` does `array_merge($defaults, $_SERVER)`. Regression test
  under the built-in server; native suite 963/0/10.
- **End-to-end validation on WordPress (full CMS core).** The complete core (2086 PHP files) was
  encrypted and served, both as source-cipher and as bytecode, producing byte-for-byte identical
  output to the unencrypted baseline (home page 80867 B over three requests, login, and a database
  write/read path). This fixed the recipe now in `docs/DEPLOYING-APPS.md`: ship the encrypted `.php`
  **plus every unencrypted asset** (css/js/json/images), keep the config file out of the package, run
  the loader with OPcache off (or blacklisted), and — for bytecode — compile at the deploy path
  (`deploy_root`). Linux `php-8.3-nts` loader rebuilt **hardened** (via `scripts/build-unix.sh`:
  hidden visibility + stripped, zero exported `envelock_*` symbols) with the fix; the other prebuilt
  loaders carry the same source change and are pending a CI rebuild.
- **More CMSs validated end-to-end.** **Joomla 6.2.0** (5902 PHP files) encrypts and serves
  byte-for-byte identical to its baseline in both source-cipher and bytecode modes. **PrestaShop
  8.2.8** (16716 files) encrypts and executes, but surfaced a real limit documented in
  `docs/DEPLOYING-APPS.md`: code that reads its own source at runtime (PrestaShop's tokenizing
  autoloader — fixed by deploying the pre-generated `class_index.php` — and Doctrine annotations —
  exclude those classes or use PHP 8 attributes). **Drupal** needs Composer and is offline in this
  environment, deferred. See `docs/AUDITORIA.md` Pass 20.
- **New `preflight` command: a compatibility check.** `envelock preflight --source <dir>` statically
  scans a tree for code that reads its OWN source at run time — source tokenizers/class maps
  (`token_get_all`), header readers (`get_file_data`), self-reading (`highlight_file`,
  `file_get_contents(__FILE__)`), and Doctrine/Symfony docblock annotations — the patterns that break
  after encryption, and reports each with a fix (exclude the file, ship the pre-generated artifact, or
  use PHP 8 attributes). It is read-only, runs only in the encoder on the developer's machine, never
  executes the scanned code, and never changes what is encrypted or excluded — so it adds nothing to
  the package or the runtime and cannot weaken protection. `--strict` exits non-zero if anything is
  found (for CI); `--json` for machine output. `pack` now points to it for third-party/framework code.
  Validated against the real trees: it flags PrestaShop's tokenizing autoloader and its ORM
  annotations, and WordPress's header readers.
- **Doctrine compatibility validated (no runtime change, no security trade-off).** The PrestaShop
  annotation limit was settled against the real `doctrine/annotations`: an encrypted entity's mapping
  reads correctly either via PHP 8 attributes (reflection) or via a pre-generated metadata cache
  (warmed in the clear, deployed non-debug) — verified, with a cache-removed control proving the
  source is never read. The loader stays uncoupled from Doctrine; the recipe is in
  `docs/DEPLOYING-APPS.md` §7 and `preflight` points to it. See `docs/AUDITORIA.md` Pass 21.

- **Fixed: the bytecode emitter crashed on a class with thousands of methods.** The emit arena is a
  fixed bump mapping sized up front (the layer has no OPcache-style calc pass); it was sized from the
  **main** op_array alone, so a class with few top-level opcodes but thousands of method op_arrays
  (a ~138 KB / 2000-method file) under-sized the arena and the emitter wrote past the mapping and
  segfaulted. The arena is now sized from the whole script — main op_array, every global function and
  every method of every class — with a 2× margin (all four per-version layers). Regression test at
  2000 methods; round-trip of the big file verified. Only the pack-side emitter was affected (the
  server loader does not emit); native suite 964/0/10.
- **Performance recommendations reviewed (two external benchmark reports).** Confirmed the levers
  already in place (manifest fast path default-on, encrypt-only-business + OPcache blacklist, strip
  comments, long-lived FPM workers) and that bytecode is anti-root, not a speed-up (it is slower —
  matches the project's own measurement). Added the two actionable new items to `docs/RENDIMIENTO.md`:
  **bundling** own code into fewer protected files (measured −96 % on 240 methods), and the note that
  `opcache.blacklist_filename` must be set on the **FPM master**, not only per-pool. See
  `docs/AUDITORIA.md` Pass 22.

- **Bytecode emit now scales to large trees (batched).** `_bytecode_pass` emitted every file in one
  PHP process, which accumulated each compiled op_array and ran out of memory on tens of thousands of
  files (a full Drupal or PrestaShop tree). It now emits in batches of `BYTECODE_BATCH` (500) files
  per process — each process frees its memory on exit — and lifts `memory_limit` for the build step so
  a batch is bounded by its size, not the host setting. Each file compiles independently, so the
  output is unchanged. Verified at 14000 files (one process OOM'd before); regression test across
  several batches; native suite 966/0/10. This unblocks `--bytecode` on large third-party trees.

Fixed and changed (deep code audit + bytecode validation, November 9):

- **Bytecode emit arena sizing — high-severity fix.** Nine Drupal files (polyfill-iconv charset tables,
  migrate fixtures, the PHPStan baseline) crashed the emitter (`rc=139`): the fixed bump arena was sized
  by a heuristic that counted literal/op *counts* but not the *bytes* of large literal arrays/strings,
  constant-expression AST or PHP 8.4/8.5 property hooks, so the writer ran past the mapping — a silent
  heap over-write on the hash paths, made worse by a relocate-on-grow that dangled the already-written
  absolute pointers (use-after-munmap). The arena is now floored at `source_size * 32` (a sound bound on
  every source-derived byte), the relocate-grow is removed (fail-closed), and a trailing `PROT_NONE`
  **guard page** turns any residual overrun into a deterministic fault instead of corruption. Applied to
  all four per-version layers (`php82/83/84/85`). All 13637 Drupal and 34138 PrestaShop files now emit
  with zero crashes; regression test `test_bytecode_emitter_handles_large_constant_arrays`. See
  `docs/AUDITORIA.md` Pass 25.
- **Drupal 11 validated end-to-end in bytecode.** The full tree packed with `--bytecode`, served by the
  hardened production loader, renders byte-for-byte identical to the plaintext baseline. PrestaShop 9
  bytecode emit validated on 100 % of its files. Native suite **966/0/10**, Python suite **474/5**.
- **Vault wrap-nonce domain separation (hardening).** The content key encrypts files with counter nonces
  and also wraps each file's vault data key with a random nonce; the wrap nonce is now forced into the
  top-bit-set half so the two nonce spaces under that key are provably disjoint. No loader change, format
  unchanged. Test `test_vault_key_nonce_is_domain_separated`.
- **`--bytecode` temp sources created `0600`/`O_EXCL`.** The plaintext sources on disk during the compile
  step are no longer world-readable. Test `test_bytecode_temp_sources_are_owner_only`.
- **Build/release hardening.** `build-unix.sh`: inherited `CFLAGS`/`LDFLAGS` no longer override the
  hardening (order fixed), and a post-build gate fails if the module exports any `envelock_*`/`bc_emit`/
  `bc_run` symbol. `build-static-php.sh`: now builds with the full hardening set incl. `-fvisibility=
  hidden` and the same symbol gate. `build-windows.ps1`: copies the whole `extension/` tree instead of a
  drifted 6-file list that could not compile the current sources. See `docs/AUDITORIA.md` Pass 26.

Fixed (two external audits of the source ZIP, reproduced and fixed, November 9):

- **Anti-rollback, two real bugs (high).** A negative `envelock.clock_tolerance` (admin-set, signed)
  cast to a huge `uint64` and silently disabled the clock-set-back check — now clamped (NU-01). And the
  watermark persist throttle measured advance from the in-memory value, not the on-disk one, so a
  long-lived worker advancing in small steps never rewrote the file and a restart lost the advance —
  now measured from the on-disk record (ENV-01). Both carry a native regression test.
- **Delivery and storage robustness.** GUI `pack` refuses a recipients/passwords length mismatch
  instead of truncating silently (ENV-02); per-project minimums are keyed by `(project, developer)` so
  one developer cannot overwrite another's for a shared project id (ENV-03); the `--bytecode` cleanup
  deletes only the directories it created, never a pre-existing `deploy_root` (ENV-04); the default
  pack serial is nanoseconds, not whole seconds (ENV-05).
- **Secret and fingerprint hardening.** The password-file 0600 check runs on the open descriptor
  (`fstat`, no symlink TOCTOU) and `bounded_read` uses `O_CLOEXEC` (NU-02/07); `secret_write` forces a
  pre-existing secret folder to 0700 (NU-04); the asset credential scan runs on every asset, not only a
  fixed extension list (NU-05); the encoder's IP fingerprint now enumerates with `getifaddrs`, matching
  the loader on multi-IP hosts (NU-03); a dead `host_domain()` branch removed (NU-06). `trusted_time`
  DNS/read bounds and the verify-vs-binary-manifest distinction are documented (ENV-06 and the second
  pass's operational note). Native 968/0/10, Python 481/5. See `docs/AUDITORIA.md` Pass 27.

Added (CMS option compatibility + WordPress FSE, November 9):

- **Measured which obfuscation/hardening flags keep a real CMS rendering identically** (Drupal 11 and
  WordPress), with a per-option table in `docs/DEPLOYING-APPS.md`. The safe set (strip-comments, compact,
  encode-strings, obfuscate locals, obfuscate-flow, obfuscate-methods, include-protection, no-ffi,
  no-prepend) renders byte-identical on both; `--obfuscate-properties` and `--sealed` break a CMS, and
  `--include-protection` is in fact compatible (earlier guidance corrected).
- **WordPress block (FSE) themes:** an encrypted FSE theme rendered empty because WordPress reads each
  `patterns/*.php` header with `get_file_data()` (file text) to register block patterns. Keep the theme
  patterns cleartext (`--exclude 'wp-content/themes/*/patterns/*'`); `preflight` now flags them
  (`wp-file-header`). Not a crypto/loader bug — same class as Doctrine annotations. See
  `docs/AUDITORIA.md` Pass 28.

This release adopts and verifies an independent continuation of the project; see `docs/AUDITORIA.md`
(Passes 15–28) for the reviews and per-objective verification, and `docs/VERIFICACION.md` for counts.

## 1.0.0 — 2026-11-02 (security-audit fixes)

Fixes from three external audits, each reproduced in code before being applied (see `docs/AUDITORIA.md`, Pass 14). Every fix carries a test that fails without it; Windows items were exercised under Wine.

### Security

- **Anti-rollback bound to the developer (ENV-AUD-14).** A per-project minimum now records the developer that set it and the loader applies it only to packages signed by that same developer, so on a host trusting several developers one cannot brick another's project. Identity format bumped to `ENVLKID3` (56-byte minimum entries, `developer_pub | project | serial`); the legacy `ENVLKID2` file is still read and is rewritten to the new format on the next `minimum set`.
- **Include protection spans a developer's primary and recovery keys (ENV-AUD-17).** A package is bound to the developer, not the individual signer slot, so a hotfix signed after `promote-recovery` is still "its own application".
- **Sealed tree: `../` include fixed, symlink still refused (ENV-AUD-04).** The requested path is lexically normalized (no filesystem access, no symlink follow) so a legitimate `include '../plain.php'` that resolves outside the tree runs, while a symlink inside the tree to external plain PHP is still refused.
- **Runtime manifest on UNC/long paths (ENV-AUD-18).** `--enforce-manifest` applications hosted on a share (`\\server\share\…`) or an extended-length path now work; the identity file keeps its UNC rejection (it holds private keys). The per-request non-dumpable re-assert no longer uses a racy `static int` under ZTS.
- **Windows identity updates (A2/A3, validated under Wine).** Updating an identity whose DACL does not grant the current user `DELETE` no longer fails with `WinError 5`; the key-password prompt uses `GetConsoleMode` so a redirected `NUL` fails closed instead of hanging.
- **Assistant/GUI (ENV-AUD-16).** `promote-recovery` in the GUI always offers to encrypt the new owner file and writes plaintext only on explicit confirmation; the Visual C++ redistributable is verified and launched in one PowerShell process (no TOCTOU) with an anchored Microsoft RDN, the Code Signing EKU and a Microsoft root.

### Encoder / CLI

- `pack --recipient` accepts a public key **or your own `recipient.json`** (its public part is derived); an encrypted recipient is refused with an actionable message (ENV-AUD-16).
- `pack` prints an advisory when every optional hardening layer is off (base encryption + signing only); defaults are unchanged (ENV-AUD-15).
- `inspect` reports each minimum's bound developer.

### Tooling / tests

- The prebuilt-symbols test skips in a source tree without `prebuilt/`; `bandit` scans `fuzz_obfuscator.py`; `# nosec` comments use the `# nosec <id> # reason` form (ENV-AUD-19). The PyInstaller build tool is hash-pinned when a per-OS lock is present.

### Not applied (discarded after not reproducing)

- ENV-AUD-05 (vault exfiltration) — false: a plain file calling `__envelock_lit` gets its own (empty) vault. ENV-AUD-19.3 (missing docs) — false: `docs/MANUAL.md` and `docs/BUILDING.md` exist. ENV-AUD-15.2 (refuse on `zend_observer`/APM) — would stop protected code running under standard production monitoring; documented as a known limit in `docs/SEGURIDAD.md` instead.

## 1.0.0 — 2026-10-24

First public release.

### Cryptography (v2 format `ENVLK02`)

- **Asymmetric per-recipient** model: the content key is wrapped with X25519 + HKDF-SHA256 + AES-256-GCM for each recipient; Ed25519 signs. Only the holder of the X25519 private key decrypts. Having the public engine or someone else's keys does not open packages meant for others.
- A new random 256-bit content key per `pack`; nonces derived by counter within each package (no collisions under a key).
- The KEM derivation (HKDF `info`) and the wrapping AAD authenticate usage domain, version, project, release, the ephemeral key and the recipient's key: an entry is not valid for another recipient or release.
- **Anti-downgrade**: the loader only accepts `ENVLK02`/version 2 and rejects the earlier `ENVLK01`; magic and version are inside the signed region.

- Each file carries its **relative path** (signed, in the AAD): it only runs from a location ending in that path, so files cannot be renamed or swapped inside a package. In one request, all protected files under a package folder must share project and release (no file swapped in from another release).
- Each package carries a signed **serial** (default: the time of `pack` — in nanoseconds since the epoch since ENV-05 — or `--serial`); a per-project **minimum** in the identity file refuses older releases (`minimum set`).
- Header **flags**: `pack --include-protection` (protected files run only as the entry point or when a protected file of the same project is on the call stack; another script cannot load them) and `pack --no-prepend` (refuse `auto_prepend_file`/`auto_append_file`).

### Trust and key management

- **Generic binary**: the loader embeds no secret. The server's identity (X25519 private key + trusted signer) is read from an external identity file pointed to by the `envelock.identity` directive in `php.ini`. On POSIX that file is rejected if it is readable by group/others or not owned by the process user.
- **Multiple identities per host**: the identity file is a bundle (up to 64); a single module serves several projects from different folders with different keys.
- **Per-installation trust store** (`ENVLKID3`; see the 2026-11-02 entry for the format bump): separates recipient keys from trusted developers; `developer_id = SHA256(public key)`; optional **recovery key** (`init-owner --with-recovery`) to rotate a compromised signer without recompiling or updating servers first. Trusted signers are configured separately, never taken from the package; trust is global per installation.

### Encoder CLI

- `init-owner` / `init-recipient` (aliases `keygen owner|recipient`), `export-public`, `export-identity`.
- Key rotation: `owner new-recovery` (add or replace the recovery key), `owner promote-recovery` (stolen primary: the recovery key becomes the primary; its packages already run on every server), `export-developer` (public descriptor), `developer set` / `developer remove` and `recipient remove` on server identity files. Identity-file commands print the trusted developers before and after, refuse to drop the last developer or recipient, keep the file's owner and ACL on Windows (copied before any key is written), and remind you to restart PHP. A trusted recovery key is never changed silently: `developer set` needs `--remove-recovery` to drop one, and `recipient add` refuses an owner whose recovery key differs. `owner new-recovery` keeps the file's password and encrypts an unencrypted file unless `--no-encrypt`. `inspect` shows the trusted recovery public keys.
- `recipient add` to create/extend the server's trust store incrementally and atomically.
- `pack --recipient` (repeatable; personal mode packs for your own key).
- `inspect` shows **non-secret** metadata of a package, identity file or configuration (never private keys).
- Private configurations **encrypted by default** with scrypt + AES-GCM (unencrypted only with an explicit `--no-encrypt`, which warns); `ENVELOCK_PASSWORD_FILE` for non-interactive use; encoder runs under `umask 0077`.

### OPcache coexistence

- Protected files are **refused by default** (fail closed) when OPcache's SHM cache is on. Opting in with `envelock.allow_opcache=1` plus `opcache.blacklist_filename` on the protected tree lets them run without being cached (measured), while the rest of the app benefits from OPcache.
- `opcache.file_cache` / `file_cache_only` / preloading are **always refused** (they persist decrypted opcodes). Measurement showed OPcache re-asserts the outermost compile hook each request, so a loader cannot bypass it; the blacklist is the reliable mechanism.

### Graphical assistant

- A cross-platform window (Tkinter), in Spanish or English, covering the whole flow (keys, server identity, key rotation, per-project minimums, multi-recipient and packing). It reuses the encoder through a thin, separately tested layer and performs no cryptography of its own. Runs from source (`gui/envelock_gui.py`) or as a self-contained executable built with PyInstaller (`scripts/build-gui.sh`), which bundles Python and `cryptography` so the end user installs nothing. The fields show the expected file type and filter the browse dialog, suggest file names, warn when a file is the wrong kind (owner vs recipient, a public key where a private one is expected), suggest the output folder and accept an existing empty one, size the window to its content, and never fall back to a terminal prompt (a windowed app has no console). It finds a PHP 8 CLI for the comment-stripping and obfuscation options (PATH, WampServer, XAMPP, Laragon, ...), lets you browse for `php.exe`, checks it before starting and runs it without a console window. When there is none, on Windows it offers to download the official PHP 8 (NTS x64) from php.net, verifying its SHA-256 against the official index and extracting it safely next to the assistant (or in the user folder if that one is protected), and to install Microsoft's Visual C++ runtime when PHP needs it (run only if its Authenticode signature is valid and from Microsoft); on Linux/macOS it shows the install command for the system. The *Server identity* tab can also remove a recipient (by its public key) or a developer (by id). `docs/ASSISTANT.md` explains every tab and gives the equivalent command for each button.

### Security, build and verification

- Static analysis clean (Clang analyzer, bandit, ruff, strict `-Wconversion`/`-Werror` build); gcc ASan/UBSan exerciser of the C core with no errors.
- Binary hardening: stack-protector-strong, stack-clash-protection, Intel CET, hidden visibility, `_FORTIFY_SOURCE=2`, format-security, RELRO/NOW, noexecstack, separate-code; flags are concatenated, not dropped by an inherited `CFLAGS`.
- Zend buffers reserved before decrypting (no cleartext left uncleared on an OOM bailout); all intermediate key material cleansed with `OPENSSL_cleanse`.
- `scripts/check_release.py`: publication guard that rejects private material (identities, keys, passwords), compiled binaries outside `prebuilt/` (and the hash-locked upstream sources in `third_party/`), personal/server data or attribution marks.
- `docs/reports/` regenerated by running the tools (`scripts/regen-reports.sh`, with `targets.json` source hashes). Measured per-file performance documented in `docs/VERIFICACION.md`.
- Reviewed independently at each major change. A second, independent full audit found no critical/high issues and two medium ones, both fixed with regression tests:
  - OPcache directives are now parsed as booleans exactly like OPcache does: a quoted `"On"` in `php.ini` could previously hide an enabled OPcache and let decrypted opcodes be cached without the opt-in.
  - `pack` now detects secrets by content as well as by name: identity files (`ENVLKID2`), key descriptors and PEM private keys can no longer be copied as assets under another name or extension.
- Windows: the loader now checks the identity file with an allow-list (owner and access entries limited to the PHP service account, SYSTEM, Administrators and OWNER RIGHTS) and refuses anything else, such as Users, Everyone or another IIS pool; see the `icacls` example in the manual.
- A rejected identity file is reported with its reason (startup warning and compile error) instead of a generic "no identity configured".
- Faster loading: the signature is verified once per include and each recipient key pair once at startup (per-file overhead measured −42 %).
- Fixed: with OPcache loaded but not caching in the CLI (`opcache.enable=1`, `opcache.enable_cli=0`, the stock defaults and always the case on PHP 8.5), protected scripts run from the command line (cron jobs, console commands) were refused. The loader now decides exactly as OPcache does.
- Encoder: refuses Windows junctions and anything whose real path leaves the source tree; a deeply nested JSON gives an error instead of a traceback.
- A third full review found no critical/high issues; its medium findings were fixed: the documented identity-file owner (it must be the user that starts PHP, e.g. root for the PHP-FPM master, not the pool user — which is also safer, since workers then cannot read the keys), the missing note that identity changes need a PHP restart, and Windows ACLs lost when the encoder rewrote the identity file. Also: durable (fsync) key-file writes, a FIFO as identity file no longer blocks PHP startup, the release guard no longer passes vacuously on trees staged under `release/` (and scans an application's own `private/` folder; it also detects identity files by content and `recovery_private` values), and several doc/code mismatches.
- Memory measured and documented (`docs/VERIFICACION.md`, *Measured memory*): no extra PHP memory and no leaks from the loader; protected files are not cached by OPcache, so large projects should encrypt only their own code and size `memory_limit`/PHP-FPM accordingly (MANUAL sections 14 and 19).
- Less memory, with no decrypted code kept between requests: each protected file is decrypted in place inside the buffer PHP read it into and handed straight to the compiler, so it is never held twice (peak RSS for an 11.4 MB file 72.6 → 50.8 MB; a plain file needs 46.9 MB). Package keys and verified signatures are cached per worker (keys only, never code).
- Hardening: the decrypted code is compiled through the original file handle (no new filename handle that another compile hook could reopen, discarding the decrypted buffer without clearing it), and the buffer is cleared right after compiling.
- `pack --strip-comments` (`--php`): removes comments and docblocks before encrypting, keeping line numbers and refusing files that no longer parse; PHP no longer keeps those docblocks in memory (−25 % PHP memory on a docblock-heavy project). Not for code that reads docblocks at run time.
- `pack --obfuscate`: local variables inside named functions and methods get short names; parameters, properties, functions, classes and constants keep theirs, and functions that use names at run time or have nested scopes are left untouched.
- `pack --compact`: collapses every whitespace run and comment to a single space before encrypting (removes indentation, blank lines and comments). It never joins two tokens, so behaviour is unchanged, but line numbers are not preserved. Also in the graphical assistant.
- `pack --encode-strings`: re-spells string literals as `\xNN` byte escapes before encrypting (same value, so behaviour and line numbers are unchanged), hiding the readable SQL, messages and paths that survive obfuscation. Interpolated and heredoc strings are left as is. Enlarges string-heavy files (~4× the string bytes). Also in the graphical assistant.
- `pack --obfuscate-methods`: renames private methods that are only reached via `$this->`/`self::`/`static::`. A method is skipped if its name is used dynamically, on another object, as a bare identifier, as a property/constant, or in a string literal; a class with dynamic member access or `__call` is skipped whole. Behaviour and line numbers are unchanged, but a dynamic call the analysis cannot see would break, so test the package. Public, protected and magic methods are never renamed. Also in the graphical assistant.
- `pack --obfuscate` now also renames local variables **inside closures and arrow functions** (previously such functions were skipped); a captured variable is renamed the same way inside and outside, and every parameter keeps its name, so behaviour is unchanged.
- `pack --obfuscate-properties` (**HIGH RISK**, opt-in): renames private instance properties used only as `$this->name`. It breaks objects serialized before obfuscation (`serialize`, sessions, caches), so classes that serialize or use `get_object_vars`/Reflection/magic accessors, and any name used elsewhere or dynamically, are left alone; test the package. Public and protected properties are never renamed. Also in the graphical assistant.
- `pack --manifest` and the new `verify` command: a signed `envelock-manifest` of the whole tree lets a deployed package be checked for a deleted, added, modified or swapped file (`verify --package DIR --developer dev.pub.json`). It is a check you run, not enforced by the loader; it needs only the public developer/owner descriptor and contains no secrets.
- Protected files fail closed when a debugging extension (Xdebug, VLD, uopz, runkit7) or the phpdbg SAPI is in use, unless `envelock.allow_debuggers=1`.
- Dependencies: universal hash-pinned locks (`requirements.lock`, `requirements-dev.lock`) used by CI with `--require-hashes`; checkouts without persisted credentials.

### Platforms and CI

- Declared support: PHP 8.2–8.5 NTS. Verified on Linux x86-64 with PHP 8.2, 8.3, 8.4 and 8.5 (full test suite on each, plus real PHP-FPM requests with and without OPcache) and a local libFuzzer campaign.
- CI workflow: PHP 8.2–8.5 matrix on Linux/macOS/Windows plus Linux ARM64, a libFuzzer campaign, a real PHP-FPM test (`scripts/fpm_smoke.py`), static-analysis and release-guard jobs, and DEMO artifacts with SHA256SUMS. Runs on GitHub.
- Windows, macOS and ARM64 binaries are built and tested only in CI; they have not been executed in the authoring environment (the Windows ACL check was compiled for Windows and partially exercised under Wine).

### Self-contained repository

- `third_party/`: the source code of every external library — cryptography 50.0.2 with its 32 Rust crates vendored (builds offline), cffi 2.1.1, pycparser 3.11/3.12, typing_extensions 4.16.0 and OpenSSL 4.0.3 — from the official archives (SHA-256 recorded), with only files that name AI products removed (listed in `third_party/README.md`).
- `prebuilt/`: Linux x86-64 loaders for PHP 8.2, 8.3, 8.4 (NTS and ZTS) and 8.5; Windows x64 loaders for PHP 8.2–8.5, NTS and TS, built from Linux with Microsoft's compiler under Wine (`scripts/build-windows-wine.sh`); the assistant executables for Linux and Windows; each loader tested with the native suite (the Windows ones with PHP for Windows under Wine); and the official cryptography/cffi/pycparser/typing_extensions wheels for Windows x64, Linux x86-64/ARM64 and macOS Apple silicon (Python 3.10–3.14), all listed in `prebuilt/SHA256SUMS`. No macOS loader (it needs a Mac; `docs/PLATAFORMAS.md` explains building, the Gatekeeper exception and signing/notarizing with a developer account).
- The native tests adapt to the PHP they run (a Windows PHP under Wine from a Linux host): permission messages, OPcache loading by name, Windows paths for `opcache.file_cache`, and the case-insensitive-path test.
- **Portable Python** (`prebuilt/python/`): the official standalone CPython 3.13.15 builds for Windows x64, Linux x86-64/ARM64 (glibc 2.28+) and macOS Apple silicon, checked against their published hashes, with cryptography, cffi and pycparser installed; the `envelock` (Linux/macOS, also Git Bash/MSYS/Cygwin; follows links and explains musl, 32-bit or glibc older than 2.28) and `envelock.cmd` (Windows) launchers at the root run the encoder with it, so the commands work right after cloning. Each folder carries the license texts of the libraries compiled into it (`licenses/`), listed with versions and source links in `prebuilt/README.md`. CPython's source is in `third_party/cpython-3.13.15/`; the libraries compiled into those builds are referenced with versions and links.
- `docs/BUILDING.md`: how to compile the loader, OpenSSL, cryptography/cffi/pycparser and the assistant executables (Linux, macOS, Windows, and Windows under Wine) and how the portable Python is assembled, stating what was run.
- The release guard locks `prebuilt/` and `third_party/` with a `SHA256SUMS` listing every file (unlisted or changed files are refused: build outputs, swaps, end-of-line conversions); detects compiled files by content as well as by name and refuses them outside those folders; in both it still refuses Envelock key/identity files (third_party), private-key values, forbidden terms (whole words, in any text encoding; binary data is not searched) and links to AI sessions, but not upstream authors' emails, test keys or human co-author credits; symbolic links are refused there; in `prebuilt/` each area holds only its kind of file (loaders, wheels) and no key, password, backup or log. Each distinct content is searched once (the portable Pythons share most files). Report and script formats (`.xml`, `.cmd`, `.bat`, `.spec`, `.lock`, `.html`, `.rst`) are now scanned too, and the attribution check names no product (it matches the session-link format).
- `scripts/regen-reports.sh` writes the reports with paths relative to the repository and refuses to finish if any report fails the release guard (an earlier JUnit report carried this machine's absolute paths in skip messages; test ids no longer embed the fake secrets they use).
- `prebuilt/.gitattributes` (`* -text`), like `third_party/`: without it a git round trip altered ~1,250 files of the portable Pythons. Both folders' `.gitignore` re-ignore Envelock key/identity/password files; `CONTEXTO-PROYECTO.md` (internal notes) is git-ignored. `third_party/.gitattributes` keeps git from converting line endings (it would break the vendored crates' checksums). `tests/test_prebuilt.py` checks both lists and runs the loader matching the local PHP.
- `scripts/fetch_wheels.py` downloads the wheels from the lock, evaluating markers per target Python (this added typing_extensions 4.16.0, needed by cryptography on Python 3.10, to `prebuilt/` and `third_party/`).
- Fixed: the Windows assistant executable made the PHP it runs (for *Remove comments* / *Obfuscate*) load the executable's own, older Visual C++ runtime, so a PHP built with a newer one refused to start ("VCRUNTIME140.dll 14.29 is not compatible with this PHP build linked with 14.44"). The executable now restores the system's library search path before starting other programs (`SetDllDirectoryW(NULL)` on Windows, `LD_LIBRARY_PATH` on Linux, as PyInstaller documents), and is built with CPython 3.13.15, which bundles runtime 14.44. `--e2e` can run a given PHP (`ENVELOCK_E2E_PHP`).
- `docs/MANUAL.md` §11: step-by-step Apache on Windows (WampServer, XAMPP).
- `scripts/build-gui.sh` installs cryptography from `prebuilt/` (offline, after checking the hashes; the lock on musl) or from the hash-pinned lock, and a pinned PyInstaller, instead of unpinned latest versions.

### Fixed

- Include protection (`pack --include-protection`) refused even the directly requested entry point under Apache's `mod_php` and the built-in web server. The loader recognized the entry script only through `file_handle->primary_script`, which the CLI and CGI/FPM SAPIs set but `mod_php` and the built-in server do not, so the first protected file of a request was treated as an illegitimate include (`include protection: it can only be loaded by its own application`). The loader now also accepts the file the SAPI is running as the request's main script (`SG(request_info).path_translated`, compared as resolved real paths), so include protection works under every SAPI. A file that is not the request's main script and is not called from protected code of the same project is still refused, so the protection is not weakened. Covered by `test_php_include_protection_entry_under_web_sapi`, which serves the package over the built-in server (a SAPI that, like `mod_php`, does not set `primary_script`) and fails without the fix; verified on the Linux loaders (PHP 8.2–8.5) and the Windows loaders under Wine.

### Security review (independent audits)

An external review of 1.0.0 was reproduced in code; only what reproduced was applied, each with a test that fails without it.

- **Include protection could be bypassed by a user stream wrapper** that forged the compiled file's path to the main script's path, making an included file look like the entry point. The entry-point fallback now also requires that no user frame is executing, so only the real entry qualifies.
- **Include protection across developers:** with several developers trusted in one identity file, one could pack a container under another's project id (signed with their own trusted key) and load that project's protected files. The verifying developer is now bound into the per-file tracking, so a container must share both the project and the signing developer to count as "its own application".
- **OPcache shared-memory cache is now self-checking:** with `envelock.allow_opcache=1` but a missing or wrong `opcache.blacklist_filename`, the loader detects that OPcache is about to cache the file (`ZEND_COMPILE_IGNORE_OTHER_FILES`) and fails closed on the first request, instead of silently caching decrypted opcodes.
- **`zend.multibyte`** (a per-directory / per-user INI) now makes protected files fail closed: its encoding filters are an ambiguous lexing path for protected code.
- **Obfuscator correctness:** `new readonly class` and `new #[Attr] class` are recognized as class scopes (their public properties are no longer renamed as if locals); a `use function compact as …` alias is tracked; and a file using `__halt_compiler()` is passed through untouched (its trailing data was being dropped).
- **Asset scanning** rejects more readable-PHP and secret files: PHP detected on the decoded text too (UTF-16 templates, short `<?` tags), more PHP extensions (`.php5/.php7/.phps/.phar/.ctp`), and local databases / credentials (`.sqlite/.sql/.htpasswd/.ppk`).
- **Windows secret files** created fresh (identity, key descriptors) are given a protected ACL (SYSTEM, Administrators, the creating user) instead of inheriting the folder's permissions; on failure the file is removed and the command asks you to elevate.
- **Opt-in memory hardening** (`envelock.harden_memory=1`): the loaded private keys are locked into RAM and excluded from dumps, and the process is marked non-dumpable.
- Smaller fixes: validate the header before allocating in `open_alloc` (no large allocation for a truncated input); a recovery key equal to the primary signer is refused; the GUI password length counts characters, not UTF-8 bytes; `/CETCOMPAT` on the Windows loaders; the Linux loader ships world-readable (0644).

### Security review (second round)

A further external review was reproduced in code; again only what reproduced was applied, each with a failing test (mutation-checked).

- **Hardened build could silently ship an unhardened module:** on GCC ≥ 14, `-Werror=format-security` without `-Wformat` is a hard error that aborted the hardened build and fell back to a plain module (exporting its internal `envelock_*` API). `-Wformat` is now set on Unix, and the Windows SDK build (`config.w32`) applies the same hardening flags as the Wine build. A test asserts the committed Linux loaders export no `envelock_*` symbols.
- **Memory hardening is now on by default** (`envelock.harden_memory=1`) and is re-applied after startup (`RINIT`), so it survives a worker that drops privileges; the cached per-file content keys are locked too, not only the identity. Set `envelock.harden_memory=0` to allow a profiler or core dump.
- **Debugger/compile-hook detection** expanded to more instrumentation extensions (xhprof, tideways, ddtrace, spx, pcov, blackfire, memprof) and any registered `zend_ast_process` hook.
- **`pack` refuses the PUBLIC demo keys** (their private halves are published) unless `--allow-demo` is given for testing.
- Smaller fixes: `parse_package` gives a clean error for a non-UTF-8 or non-relative embedded path; package output has deterministic permissions (dirs `0755`, files `0644`) regardless of umask; a secret's parent directory is created `0700`; the CLI password length counts characters (matching the GUI); the `./envelock` launcher exits `2` with guidance when no portable Python is present.
- **Docs:** `envelock.identity` is `PHP_INI_SYSTEM`, so a per-pool `php_admin_value[envelock.identity]` is ignored (read once at startup); the manual now says to use one identity file with several entries or separate FPM masters.

### Security review (third round)

A further pass reproduced the remaining external-report findings and hunted for new defects; only reproduced bugs were fixed, each with a failing test.

- **Windows identity path:** the loader opened the identity file with `fopen()`, which reads the `php.ini` value in the ANSI code page and fails on any non-ASCII path (e.g. an accented folder name). It now opens through the wide API (`MultiByteToWideChar(CP_UTF8)` + `_wfopen`) so a UTF-8 identity path works, and it refuses the UNC and device namespaces (`\\server\share`, `\\?\`, `\\.\`): the identity must be a local, access-controlled file.
- `envelock.cmd` exits `2` with guidance when the portable Python is absent, matching the `./envelock` launcher.
- Reviewed and found sound (no change): the crypto core's bounds (no out-of-bounds decrypt; AddressSanitizer/UndefinedBehaviorSanitizer clean), the encoder's symbolic-link and Unicode-collision rejection, the signature and content-key caches (signature verified before every decryption), the identity-store size caps, and the per-package nonce scheme.

### Full code audit (October 31)

An independent review of the whole codebase (C loader, Python encoder, GUI, scripts) was reproduced and fixed. The C loader had no high/medium findings.

- **Obfuscation vs traits (fixed, was behaviour-changing):** `--obfuscate-methods` and `--obfuscate-properties` could rename a private member that a **trait** method of the same class calls (the trait body lives outside the class's tokens, so the call was left dangling — a fatal error, or a silent `null` read, at run time). A class that `use`s a trait is now left untouched by both passes.
- New **differential fuzzer** `scripts/fuzz_obfuscator.py`: it generates many deterministic PHP programs (classes, traits, closures, private members, strings), transforms each with a random flag combination, and runs the original and transformed programs to confirm identical behaviour. Wired into the test suite; it catches behaviour-changing transforms (such as the trait case) automatically.
- The release guard (`check_release.py`) now scans the **content of every non-binary file whatever its extension** (previously only a fixed text-extension list), so a secret, real email, IP or user path in a `.sql`/`.csv`/`.conf`/... is caught too.
- Smaller fixes: the signed manifest/`verify` gained a full test suite; `verify` reads files with the hardened bounded reader (no symlink following, size cap); a PHP transform that times out reports a clean error instead of a traceback; `--obfuscate-properties` leaves multi-property declarations (`private $a = 1, $b = 2;`) entirely alone. The obfuscator's dynamic-call note was corrected (PHP forbids calling `compact`/`extract`/`get_defined_vars` through a variable).

### Block the FFI/`dl()` memory-read path (October 31)

- New header flag and `pack --no-ffi` (also in the graphical assistant): a package built with it refuses to load while FFI or `dl()` is reachable from PHP, closing a path by which code running in the same process could read the decrypted source out of memory. FFI counts as reachable when its extension is loaded and `ffi.enable` is On (or `ffi.enable=preload` under the CLI, which always enables FFI); `dl()` counts when `enable_dl` is on. The check is strictly **opt-in** and per package, so it never affects existing packages; to run a `--no-ffi` package set `ffi.enable=0` and `enable_dl=0` (or remove the `ffi` extension). Enforced by the loader on every platform (verified natively on Linux and under Wine on Windows) with a regression test that fails if the check is removed.

### Sealed tree: refuse plain PHP under it and `eval()` (November 1)

- New header flag and `pack --sealed` (also in the graphical assistant): once a protected file of the package has loaded in a request, the loader refuses to compile any plain (unencrypted) `.php` whose path is under the package folder — so an injected or swapped-in readable script cannot run inside the protected call stack and read the decrypted code — and refuses `eval()` (and any run-time string compile, via a `zend_compile_string` hook) for the rest of the request. Strictly **opt-in** and per package: a package built without it is unaffected, plain PHP outside the sealed folder keeps working, and there is no cost until a sealed package loads. Order-dependent (the tree is marked sealed when the first protected file compiles), so it pairs with `--include-protection` and a protected entry point. Enforced by the loader on every platform (verified natively on Linux and under Wine on all eight Windows DLLs, NTS and TS) with regression tests that fail if either check is removed. The Windows thread-safe (ZTS) run caught a zero-initialization bug (the per-request `sealed_active` state was not cleared by TSRM, spuriously refusing `eval()` and faulting on the TS builds); fixed by initializing it in GINIT and RINIT, with its own regression test. Not for deployments that keep plain `.php` in the tree or that rely on `eval()`.

### `minimum set` trusts the signed header, not package metadata (November 1)

- `minimum set --package DIR` now reads the project and serial from a protected file's **signed header**, verified against the trusted developers already in that identity file, instead of the unsigned `envelock-package.json` (which was informational and could be forged or swapped). A package not signed by a developer the identity file trusts is refused. The manual `--project/--serial` form is unchanged.
- Lowering an existing minimum is now **refused unless `--allow-downgrade`** is given, so the anti-rollback bar is not moved back by accident (e.g. pointing at an older or tampered package). Both the CLI and the graphical assistant honor this (the assistant gained an "allow lowering" checkbox).

### Runtime manifest enforcement (November 1)

- New header flag and `pack --enforce-manifest`: writes a signed **binary** manifest (`envelock-manifest.bin`, a fixed layout the C loader parses without a JSON library) listing every file of the package. On the first protected file loaded from the package in a request, the loader verifies the manifest's Ed25519 signature against the developers trusted in the server's identity file and confirms every listed file still exists under the package folder; a missing or renamed-away file (e.g. a protected authorization check dropped from the deployment) fails the request closed. Content tampering of protected files is already caught by their GCM tag, so the manifest is not re-hashed at runtime. Strictly **opt-in** and per package, checked once per package per request (no cost otherwise). It complements the operator's deploy-time `verify` (which uses the JSON `--manifest`). Enforced on every platform (verified natively on Linux NTS and ZTS and under Wine on all eight Windows DLLs) with a regression test that fails if the check is removed. Also in the graphical assistant.

### Robustness: one operation at a time, and inspect validates its input (November 1)

- The graphical assistant now runs **one operation at a time**: while a pack, key write or rotation is in flight, starting another is refused with a notice instead of racing on the same files. (Safe ZIP extraction of the downloaded PHP — every archive member path checked before extraction — and the Authenticode check of Microsoft's Visual C++ redistributable before it is run were already in place.)
- `inspect` turns any unrecognized input into a clean error instead of a raw `UnicodeDecodeError`/JSON traceback: a binary or wrong-encoding file that is neither a protected package nor an identity store nor a JSON config is reported as "unrecognized file", not an uncaught exception.

### Control-flow obfuscation, conservative (November 1)

- New `pack --obfuscate-flow`: inserts an **always-false opaque-predicate dead branch** at the start of each named function and method (`strlen()` of a path is never negative, `__LINE__ & 0` is never 1, `count()` of a two-element array is never ≠ 2). It raises the effort to follow the code and defeats automated strippers that do not model those built-ins, while never changing behaviour (the branch cannot run) and **preserving line numbers** (emitted on the opening brace's line). Functions using `goto` are skipped. It is deliberately a modest layer — **dead-code insertion, not control-flow flattening**; true flattening needs a full AST/CFG rewrite and is left to a future version. Validated behaviour-neutral by the differential fuzzer (thousands of generated programs, random flag combinations, 0 divergences) plus a dedicated regression test. Encoder/transform only (no loader change); also in the graphical assistant.

### Full code audit, round 2 (November 1)

An independent three-part audit (C loader, Python encoder, GUI/scripts/tests/docs) of everything added in this round. No high-severity findings; the memory safety of the new manifest/sealed C code, the ENV-09 signed-header checks and the `--obfuscate-flow` pass were all confirmed correct. Fixed:

- **Runtime manifest now bound to the loaded release (medium, fixed):** `--enforce-manifest` verified the manifest's signature and that every listed file existed, but did not check that the manifest belonged to *this* package. A trusted-signed manifest from another (e.g. older) release that happened to list a subset of the present files could have been swapped in to hide a deleted file. The loader now rejects a manifest whose project or release differs from the file being loaded. Regression test + mutation-checked.
- **GUI drain loop made exception-proof (medium, fixed):** if a completion callback raised, the status-drain loop could stop rescheduling and leave the window stuck "working". Each item is now dispatched in its own `try/except` and the loop always reschedules.
- **`inspect` of a malformed owner/developer descriptor (low, fixed):** a descriptor missing or with a non-hex `signing_public` now gives a clean error instead of a `KeyError`/low-level traceback.
- **Documented** that `--sealed` is defense in depth: it refuses `eval()` and plain PHP under the package folder, but an include of plain PHP from a path *outside* the tree (an upload, or `data://`/`php://input` when `allow_url_include` is on) is indistinguishable from a legitimate `vendor/` include — combine it with `--no-ffi` and keep `allow_url_include` off.
- Corrected stale test counts in `VERIFICACION.md` and `BUILDING.md`.

### String-literal vault (November 1)

- New `pack --vault-strings`: string literals that sit in a **runtime position** are moved out of the code into a per-file vault that the loader resolves through an internal `\__envelock_lit(idx)` call, so they are **not kept as constants in the compiled op_array** and are not present in the decrypted source the engine compiles. This raises the cost of recovering SQL, messages, endpoints and paths from a dump of the loaded code; the literals ride inside the file's already-encrypted payload (no new cryptography) and the loader wipes them from memory at the end of each request. It is opt-in per package and **backward compatible** (existing packages are unaffected). Honest limit: like the rest of Envelock it does not defeat the server administrator/root, who can read process memory; it defeats recovery from the compiled code and the source text.
- A literal in a **constant expression** (a `const`, a property or parameter default, a `static` initializer, an attribute argument, an `enum` case, a `declare`) cannot become a function call, so it is left inline. The encoder models the common cases and, as a hard safety net, lints every transformed file and leaves inline any literal whose line would not compile — a broken file can never be produced. Identical literals share one slot; 0/1-character literals stay inline. Line numbers are preserved. Adds about one internal function call per vaulted-literal access (an A/B microbenchmark on PHP 8.3 put it around 15 ns per access; negligible outside tight loops). Validated behaviour-neutral by the differential fuzzer (random flag combinations including the vault, 0 divergences) plus unit, native and malformed-table-rejection tests (mutation-checked). Also in the graphical assistant.
- The source transforms now force `display_errors=stderr` for the PHP helper they run, so a PHP notice can never land on the JSON result stream. This fixes `--strip-comments`/`--obfuscate`/`--compact`/`--encode-strings`/`--vault-strings` on PHP 8.5 builds whose CLI defaults `display_errors` to on (a new 8.5 deprecation was corrupting the transform output there); the helpers also silence their own deprecations, which do not change behaviour (the differential fuzzer checks that across versions).

### Known limits

- No protection against the server administrator/root (can read the identity file and in-memory plaintext). No signed manifest of the whole deployment (files can be deleted, or a whole package folder replaced by another package for the same server). Decrypted code is never cached between requests (by design: it would keep the original program in memory). See `docs/SEGURIDAD.md`.

# Native builders: PHP 8.2, 8.3, 8.4, and 8.5

The encrypted format is common, but you must build one loader per **OS + CPU + PHP minor + TS/NTS + toolchain/ABI**. A Linux `.so` does not work on macOS or Windows. The binary is generic: it contains no keys, and the same module serves any identity file.

See `VERIFICACION.md` to separate completed tests from pending recipes. **Linux x86-64 and Windows x64 are built and tested; macOS has NOT been tested on a real Mac** — the authors do not have one, and no macOS binary is shipped. The build, signing and notarization recipe below is our best effort; anyone on macOS can build and use the loader, but build and test it yourself first. **If you hit a problem or a bug on macOS — or on any platform — please open an issue; we'll be glad to receive it and fix it.** The Windows x64 DLLs in `prebuilt/loader/windows-x64/` are built natively on Windows 11 with `scripts/build-windows.ps1` and tested there with the official PHP for Windows builds ([BUILDING.md](BUILDING.md) §2); `docs/WINDOWS-VALIDATION.md` is the checklist to re-run that validation. Building every other component (OpenSSL, cryptography, the assistant executables) is in [BUILDING.md](BUILDING.md).

## Linux

Install the development tools for the chosen PHP version, OpenSSL 3, make, autoconf, and pkg-config. Example of Debian/Ubuntu packages, adapting names/versions:

```bash
sudo apt install php-cli php-dev libssl-dev pkg-config autoconf make gcc
source .venv/bin/activate
php -v
phpize --version
php-config --version
pkg-config --modversion libcrypto
bash scripts/build-unix.sh release/linux-php84/envelock.so
```

`envelock.secret_memory` (objective O2) is Linux-only and needs `memfd_secret(2)`: Linux 5.14 or
newer **with** `CONFIG_SECRETMEM` **and** a kernel that can split its direct map into small pages.
The last condition is the one that usually fails, and a kernel can carry `CONFIG_SECRETMEM=y` and
still not register the syscall — check for `/proc/sys/vm/secretmem_enable`, whose absence means it
is not there. Where it is unavailable the arena degrades to a locked, dump-excluded mapping and
`envelock_secret_memory()` says so; see `SEGURIDAD.md`.

For different versions installed under separate prefixes, select the three tools explicitly:

```bash
PHP=/opt/php-8.5/bin/php PHPIZE=/opt/php-8.5/bin/phpize PHP_CONFIG=/opt/php-8.5/bin/php-config \
  bash scripts/build-unix.sh release/linux-php85/envelock.so
```

Keep the correct Python from the virtual environment; do not prepend `/usr/bin` indiscriminately to the PATH if doing so also changes the Python interpreter.

The module is generic (no keys). The builder compiles with optimization/stack protector/hidden visibility and RELRO/NOW on Linux, strips local symbols if `strip` is available, tests loading with the selected PHP, and copies the result with exclusive creation. The server keys go separately, in the identity file (`envelock.identity`).

The file may end up private due to `umask 077`: afterward assign the minimal owner/group/permissions that allow the PHP service user to read it. Do not publish it in the webroot.

Verify:

```bash
file release/linux-php85/envelock.so
ldd release/linux-php85/envelock.so
php -n -d opcache.enable=0 -d opcache.enable_cli=0 -d extension=/path/envelock.so --ri envelock
```

### Portable build (how the prebuilt Linux loaders are made)

A loader built as above needs the C library and OpenSSL of the machine it was built on, or newer.
The prebuilt loaders are built so that they load on almost any current Linux server
(`docs/HOSTING.md` §2.2): on an **old C library** (AlmaLinux 8, glibc 2.28) and with **OpenSSL 3
linked in** (static, its symbols hidden), so the module needs only `libc`, `libdl` and `libpthread`
and does not care which OpenSSL — 1.1.1 or 3.x — the PHP process itself uses.

1. On AlmaLinux 8 (a VM, a container or WSL — WSL1 was used here):
   `dnf install gcc make autoconf pkgconf-pkg-config perl perl-IPC-Cmd perl-Pod-Html perl-Time-Piece`.
2. OpenSSL 3 (an LTS release; check its SHA-256 against the project's published one), static and
   position-independent, without dynamic modules, engines or automatic config loading:

   ```bash
   ./Configure linux-x86_64 no-shared no-module no-engine no-autoload-config no-tests no-docs -fPIC \
     --prefix=/opt/envelock-openssl --openssldir=/etc/envelock-openssl --libdir=lib
   make -j2 build_libs && make install_dev
   ```

3. A PHP of each target minor version, built on the same system from the php.net tarball (only its
   headers, `phpize`/`php-config` and a `php` to load-test the module are needed; a lean
   `--disable-all --enable-cli` build is enough).
4. The loader, with the two portability gates:

   ```bash
   PHP=/opt/php/8.4-nts/bin/php PHPIZE=/opt/php/8.4-nts/bin/phpize PHP_CONFIG=/opt/php/8.4-nts/bin/php-config \
     ENVELOCK_OPENSSL_STATIC=/opt/envelock-openssl ENVELOCK_MAX_GLIBC=2.28 \
     bash scripts/build-unix.sh release/linux-php84/envelock.so
   ```

   `ENVELOCK_OPENSSL_STATIC` links that OpenSSL in with `--exclude-libs,ALL` and refuses the module
   if it still needs `libssl`/`libcrypto` or exports anything but `get_module`;
   `ENVELOCK_MAX_GLIBC` refuses it if it needs a newer glibc than given.

With OpenSSL inside the module, **each OpenSSL security release means rebuilding and republishing
the Linux loaders**. Trusted time (`envelock.trusted_time`) then cannot use that OpenSSL's own
certificate folder, so the loader also loads the system's CA bundle from where each distribution
family keeps it (`/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`,
`/etc/ssl/ca-bundle.pem`, `/etc/ssl/cert.pem`); `SSL_CERT_FILE` still applies.

The Linux x86-64 loaders in [`prebuilt/loader/`](../prebuilt/README.md) (PHP 8.2, 8.3, 8.4 NTS and ZTS, 8.5) are portable builds made as described above (2026-11-12, AlmaLinux 8.10 under WSL1, gcc 8.5, OpenSSL 3.5.9 static, PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12 built from the php.net tarballs). Each needs only `libc`, `libdl` and `libpthread`, GLIBC_2.25 at most, and exports only `get_module` (measured). The 8.4 ZTS loader is compiled against the normal ZTS headers and was load-tested and tested with a ZTS PHP built without max-execution timers, because WSL1 lacks the `timer_create` those timers use; the option only changes the end of `executor_globals`, which the loader does not touch. Tests: `TEST-STATUS.md`. musl/Alpine and ARM64: build on the target with `scripts/build-unix.sh`.

## macOS

Requires native macOS, Xcode Command Line Tools, development PHP of the chosen version, OpenSSL 3, autoconf, and pkg-config. Indicative Homebrew example, subject to formula availability:

```bash
xcode-select --install
brew install php@8.5 openssl@3 autoconf pkgconf
export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
PHP="$(brew --prefix php@8.5)/bin/php" \
PHPIZE="$(brew --prefix php@8.5)/bin/phpize" \
PHP_CONFIG="$(brew --prefix php@8.5)/bin/php-config" \
bash scripts/build-unix.sh release/macos-php85/envelock.so
```

Repeat with the tools for 8.2, 8.3, and 8.4. The extension usually keeps `.so`. Intel and Apple Silicon require their own builds or a universal process validated explicitly.

Review `file`, `otool -L`, OpenSSL paths, code signing, and execution on a clean Mac. A module linked to your local Homebrew path is not automatically redistributable. These recipes have not been run in this session.

### Signing, quarantine and the Gatekeeper exception

Every program on Apple silicon must carry a signature; the linker gives the module an *ad-hoc*
signature (no identity) automatically. What decides whether macOS loads it is where it came from:

- **Built on the same Mac** (the recipe above, or cloned with git): no quarantine flag, so PHP
  loads the ad-hoc signed module with no warning. This is the simplest and recommended path for
  your own servers.
- **Downloaded with a browser or copied from a ZIP** extracted by the Finder: the file carries the
  `com.apple.quarantine` flag, and Gatekeeper refuses to load an ad-hoc signed (not notarized)
  library ("cannot be opened because Apple cannot check it for malicious software"). That is why
  a module built elsewhere and signed only ad hoc does not work as it is.

**Adding the exception** (only for a module you built or checked yourself):

```bash
shasum -a 256 envelock.so                          # compare with the hash you published
xattr -l envelock.so                               # shows com.apple.quarantine if flagged
xattr -d com.apple.quarantine envelock.so          # remove the flag from this file only
codesign --verify --verbose=2 envelock.so          # the (ad-hoc) signature is still intact
php -d extension="$PWD/envelock.so" --ri envelock
```

Alternatively, after the first refusal, open *System Settings → Privacy & Security* and press
*Allow Anyway* next to the message about `envelock.so`, then load it again. Never disable
Gatekeeper globally (`spctl --master-disable`). The same applies to the assistant executable.

**Signing it properly with a registered developer account** (for modules you distribute to
other people's Macs). It needs a paid membership of the Apple Developer Program and Xcode's
command-line tools:

1. In the developer account create a **Developer ID Application** certificate and install it in
   the login keychain; check it with `security find-identity -v -p codesigning`.
2. Build the module on the Mac (recipe above), then sign it with that identity, the hardened
   runtime and a secure timestamp (both required by notarization):

   ```bash
   codesign --force --timestamp --options runtime \
     --sign "Developer ID Application: Your Name (TEAMID)" envelock.so
   codesign --verify --strict --verbose=2 envelock.so
   codesign -dv --verbose=4 envelock.so             # shows the authority and the team ID
   ```

3. Notarize it: store the credentials once (an app-specific password of the Apple ID), submit a
   ZIP of the file and wait for the result:

   ```bash
   xcrun notarytool store-credentials envelock-notary \
     --apple-id you@example.com --team-id TEAMID --password <app-specific password>
   ditto -c -k --keepParent envelock.so envelock-macos.zip
   xcrun notarytool submit envelock-macos.zip --keychain-profile envelock-notary --wait
   xcrun notarytool log <submission id> --keychain-profile envelock-notary   # if it fails
   ```

4. A bare library cannot be *stapled* (there is nowhere to attach the ticket): Gatekeeper checks
   the notarization online the first time the downloaded file is loaded. To work offline too,
   ship it inside an installer package or disk image that you sign (`productsign` with a
   **Developer ID Installer** certificate for a `.pkg`, `codesign` for a `.dmg`), notarize that
   container and staple it: `xcrun stapler staple Envelock.pkg`.

The PHP that loads the module must accept it as well: Homebrew's and most self-built PHP binaries
do not use library validation, so a module signed by another team (or ad hoc, without quarantine)
loads; a PHP signed with the hardened runtime and library validation only loads modules of its
own team. Not run in this session (no Mac); follow Apple's current notarization documentation.

## Windows

> **Status (2026-11-10):** the eight Windows x64 DLLs (PHP 8.2–8.5 × NTS/TS) are **built natively on
> Windows 11** with `scripts/build-windows.ps1` and validated there with the official PHP for Windows
> builds: the native suite per DLL, the bytecode SEH crash-safety guard (corruption sweeps over the
> whole image, including the fatal error raised after each rejection), a `php -S` round-trip in source
> and bytecode mode, Laravel and Symfony, and the assistant executable. The **NTS** DLLs carry the
> bytecode layer (O1); the **TS** DLLs are source-only, because the bytecode layer is NTS-only
> (ENV-2026-03) — `config.w32` now leaves it out of a TS build instead of failing it. Results:
> `TEST-STATUS.md` and `docs/AUDITORIA.md` (Pass 32). Windows-specific behaviour of the licence
> bindings (machine, domain and IP bindings are refused) is described in MANUAL §14.
> macOS: the source is portable (POSIX plus `__APPLE__` branches); it is not built or tested here and
> is validated by CI / on a real Mac. See `docs/AUDITORIA.md`.

Ready-made DLLs for PHP 8.2–8.5 (NTS and TS) are in `prebuilt/loader/windows-x64/`; they were built natively with `scripts/build-windows.ps1` ([BUILDING.md](BUILDING.md) §2, which also keeps the older Wine cross-build recipe). To build them yourself:

`scripts/build-windows.ps1` runs natively with the **official** `BuildPhpExtension` module from `php/php-windows-builder`. It does not use the former `setup-php-sdk`, archived in its repository.

Requirements:

- Windows and PowerShell compatible with the official builder.
- Visual Studio/toolset required by the target PHP, SDK, and development tools.
- The environment's Python with `requirements.txt`.
- OpenSSL 3 dependencies of the builder and its development/runtime libraries.
- The ability to download and prepare toolchains according to the official documentation.

Reference and source you must review:

- https://github.com/php/php-windows-builder
- The workflow pins a specific revision of that project to avoid blindly following a mutable branch.

Example of preparation with the same revision referenced in the workflow:

```powershell
git clone https://github.com/php/php-windows-builder.git C:\tools\php-windows-builder
git -C C:\tools\php-windows-builder checkout 5f63433eb2bda2ca8d0d970fe487be84f7ab195c
Import-Module C:\tools\php-windows-builder\extension\BuildPhpExtension\BuildPhpExtension.psm1 -Force
```

The same module is published in the PowerShell Gallery; the committed DLLs were built with that
release: `Install-Module BuildPhpExtension -RequiredVersion 1.9.0 -Scope CurrentUser`, then
`Import-Module BuildPhpExtension`.

From the Envelock root:

```powershell
.\scripts\build-windows.ps1 `
  -PhpVersion '8.5' -ThreadSafety nts `
  -OutputDirectory release\windows-php85-nts
```

The Windows module is also generic. The `-Owner` and `-Recipient` parameters are optional and only serve to run the native integration tests after building; they do not inject keys into the binary.

Repeat with `8.2`, `8.3`, `8.4`; use `-ThreadSafety ts` if your target PHP is TS. The script targets x64; no support for other architectures is declared.

The builder uses a temporary copy of the sources, collects the DLL and the relevant runtime libraries, excludes PDB/headers/JSON/logs, locates the SDK's test PHP, checks loading, checks that the production DLL exposes neither `envelock_bc_emit` nor `envelock_bc_run`, and refuses a DLL that embeds a path of the build machine (user profile, TEMP build folder, source folder; `config.w32` builds with `OPENSSL_NO_FILENAMES` and `/PDBALTPATH:php_envelock.pdb` so none is embedded). If `-Owner` and `-Recipient` are provided — both **private** test files (`init-owner`/`init-recipient --no-encrypt`); a `.pub` is refused — it also runs `tests/test_native.py` on the built DLL; on a test failure it keeps the DLL (without its `SHA256SUMS.txt`) and fails. The official `BuildPhpExtension` module adds its temporary build folders to the user's persistent `PATH`; the script saves and restores the user and machine `PATH` around the build. The standalone C core tests can be skipped if their test library is absent; the PHP integration uses that core within the DLL itself.

If the structure of the official builder changes, if it does not find OpenSSL 3, or if the tests fail, it **stops the delivery**; it does not turn a recipe into a certified binary. Read the logs, fix the environment, and validate before distributing. Run natively on Windows 11 x64 on 2026-11-10 (Visual Studio Build Tools 2022 with the v142 and v143 toolsets, `BuildPhpExtension` 1.9.0): all eight DLLs (8.2–8.5, NTS and TS) build; those in `prebuilt/loader/windows-x64/` come from that run (see `prebuilt/README.md`). Two notes from that run: the official builder needs `cmd` to run its relative `task.bat`, which fails in a shell that sets `NoDefaultCurrentDirectoryInExePath=1`; and a flaky network can truncate its downloads (it does not verify them), which shows up as a ZIP extraction error — rerun.

Check dependencies and ABI. Do not deliver `.pdb`, `.obj`, identity files (`identity*.bin`), or the private tree. Install the appropriate VC Runtime. If you distribute OpenSSL or other DLLs, include notices/licenses and verify that they load from a trusted location.

## Demonstration native CI

`.github/workflows/checks.yml` defines:

- Linux/macOS: PHP 8.2–8.5, native NTS build and tests on the selected runner.
- Windows x64: PHP 8.2–8.5, NTS and TS, official builder and external PHP tests.
- `DEMO-*` artifacts, with public deterministic identities, not production.

The workflow is ready to be run in a repository, but **it has not been run remotely from this release**. Its future results must be reviewed before changing the support matrix. The pinned actions also download tools/dependencies: review that supply chain, not just their names.

## Acceptance criteria before announcing a target

1. Correct build with the target headers/toolchain and known dependencies.
2. Loading on the exact PHP and on a clean target machine.
3. Two projects, `include`/`require_once`, autoload, paths, strict types, and errors.
4. Rejection of altered packages and of another installation's.
5. Rejection of active OPcache without the opt-in, and of preload/file_cache.
6. Repeated and concurrent requests in the actual SAPI.
7. Memory/error analysis with the platform's tools.
8. Review of the artifacts: no auxiliary keys, original source, or private symbols.
9. Document version/ABI/TS/CPU/dependencies and do not extrapolate the results to untested targets.

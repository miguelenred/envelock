# Building from source: libraries and executables

**Inventory depends on the distribution.** Envelock's loader, encoder and assistant sources are
always present, as is the vendored PHP parser in `third_party/`. The **complete** distribution also
ships, under `prebuilt/` (all listed in `prebuilt/SHA256SUMS`), the prebuilt loaders for every
supported engine/platform (the five Linux `.so` and eight Windows `.dll` listed further below), the
Linux and Windows assistant executables, the portable Python distributions and the Python wheel
bundle. The **source-only** distribution ships none of those prebuilt artifacts. Neither distribution
ships the upstream source trees for Python, OpenSSL and the Python dependencies.
See [third_party/README.md](../third_party/README.md) and [prebuilt/README.md](../prebuilt/README.md).

Install the build tools and dependencies for the target, including Python 3.10+ and
`python -m pip install --require-hashes -r requirements.lock`. For the PHP loader use the matching
PHP development tools, a C compiler and OpenSSL development libraries (section 2); for the GUI,
Tkinter and PyInstaller are also needed (section 5). `build-gui.sh` falls back to the hash-locked
requirements when no suitable wheel folder exists, but warns when its optional PyInstaller lock is
absent and installs PyInstaller without hash verification.

**Historical recipes below:** sections 3, 4 and 6 refer to source trees and wheel bundles absent
from this checkout; obtain and verify them independently before attempting those recipes. Earlier
claims about artifacts or tests describe historical environments, not the current inventory or a
current cross-platform certification. See [VERIFICACION.md](VERIFICACION.md) and the roadmap for
current, scoped evidence.

## 1. Before you start

Work on a copy: building writes `build/`, `target/` and similar folders next to the sources.

```bash
mkdir -p ~/envelock-build && cd ~/envelock-build
cp -a /path/to/envelock/third_party/. .
```

```powershell
New-Item -ItemType Directory C:\envelock-build | Out-Null; Set-Location C:\envelock-build
Copy-Item -Recurse C:\path\to\envelock\third_party\* .
```

## 2. PHP loader

Built once per **OS + CPU + PHP minor version + thread safety (NTS/ZTS)**; the binary contains no
keys. The full recipes are in [PLATAFORMAS.md](PLATAFORMAS.md); in short:

- **Linux / macOS** — install PHP's development package (`php-dev`), OpenSSL 3 headers
  (`libssl-dev`), `autoconf`, `make`, `pkg-config` and a C compiler, then:

  ```bash
  bash scripts/build-unix.sh release/linux-php84/envelock.so
  # another PHP: select its three tools
  PHP=/opt/php-8.5/bin/php PHPIZE=/opt/php-8.5/bin/phpize PHP_CONFIG=/opt/php-8.5/bin/php-config \
    bash scripts/build-unix.sh release/linux-php85/envelock.so
  ```

  The script compiles with hardening flags, strips symbols and loads the result in that PHP.

  Then run the whole suite against your binary:
  `ENVELOCK_TEST_EXTENSION=$PWD/release/linux-php85/envelock.so ENVELOCK_TEST_OWNER=owner.json ENVELOCK_TEST_RECIPIENT=recipient.json python -m pytest tests/test_native.py`
  (with unencrypted throw-away keys made by `init-owner --no-encrypt` / `init-recipient --no-encrypt`).

  **Security — never enable the bytecode PoC functions for a server build.** They are gated by
  explicit `./configure` flags, not an environment variable (ENV-2026-02): `--enable-envelock-bcemit`
  compiles the emitter `envelock_bc_emit`, and `--enable-envelock-bcrun-unsafe` compiles the runner
  `envelock_bc_run` (which deserializes caller bytes through the OPcache unserializer — an RCE
  surface, hence `-unsafe`). On Windows the same split lives in `config.w32`
  (`--enable-envelock-bcemit` / `--enable-envelock-bcrun-unsafe`). A normal build passes neither flag,
  so production loaders expose neither function; `scripts/build-unix.sh` additionally asserts their
  absence at build time. Only `tests/test_native.py` builds with these flags (it strips any stray
  `ENVELOCK_BCPOC` from the environment, which the sources no longer read); the encoder calls a
  prebuilt emitter and never builds a loader itself.

  The bytecode layer (objective O1) adds one input: `extension/opcache/<phpmm>/` holds Zend
  OPcache's persistence code adapted to Envelock, and `config.m4` picks the directory that matches
  the PHP being built. Layers for 8.2, 8.3, 8.4 and 8.5 are generated today. The files are in the repository, so a normal
  build needs nothing else; to support another PHP version, regenerate them from that version's
  sources — the `-dev` packages do **not** ship `ext/opcache/`, so unpack the matching
  `php-<version>.tar.gz` from php.net first:

  ```bash
  python3 extension/opcache/gen_persist.py /path/to/php-8.5.0 8.5
  ```
- **Windows, on Windows** (how the DLLs in `prebuilt/loader/windows-x64/` are built) — Visual Studio
  with the toolset of your PHP version and the official `php-windows-builder`, then
  `.\scripts\build-windows.ps1 -PhpVersion '8.4' -ThreadSafety nts -OutputDirectory release\windows-php84-nts`
  (details and requirements in PLATAFORMAS.md, *Windows*). The committed DLLs were built this way on
  Windows 11 x64 with Visual Studio Build Tools 2022 17.14 (MSVC 14.29 / v142 for PHP 8.2 and 8.3,
  MSVC 14.44 / v143 for 8.4 and 8.5, Windows SDK 10.0.19041), `BuildPhpExtension` 1.9.0 from the
  PowerShell Gallery and the PHP SDK 2.8.1 it fetches. Give `-Owner`/`-Recipient` (private throw-away
  key files) to run `tests/test_native.py` against the new DLL as part of the build. The script refuses
  a DLL that exposes the bytecode emit/run functions or that embeds a path of the build machine (user
  profile, TEMP build folder, source folder).
- **Windows, from Linux under Wine** (how the DLLs of the earlier 1.0.0 pre-releases were built; kept
  for reference).
  Needs `wine` and `script` (util-linux). Inputs, each checked as noted:
  1. Microsoft's compiler and SDK from nuget.org (signed Microsoft packages; SHA-512 as listed in
     the NuGet catalog): `VisualCppTools.Community.VS2017Layout` 14.11.25547
     (`qCvT3Fqskcj5jmu1M5TLS+fm02lry/Qq3C62/pxlsXHB1z1FNVPHuvcHeuqLNNsapN2VqCtJqOrdObP2PjwwAQ==`),
     `Microsoft.Windows.SDK.CPP` 10.0.22000.196
     (`+oA+2mYGdnMhOD59TBkdGkJMipZSthBGQUUOO8xt27eOk8ZIoGQayqmwthVy0mclLiMwB+1Hne3wUNuaT0AfIg==`)
     and `Microsoft.Windows.SDK.CPP.x64` 10.0.22000.196
     (`1nuJEUSYsj201IdvanA3Bj0KpWWHHIyDwW9vGiAKBy8cBAixzl0wGQZAj86Po0Mi74kamVZpE/L+88iCPPgiNA==`).
     A `.nupkg` is a zip: extract each one.
  2. PHP for Windows and its development pack for each version and thread safety
     (`php-<v>[-nts]-Win32-vs16|vs17-x64.zip`, `php-devel-pack-<v>[-nts]-Win32-…-x64.zip`) from
     php.net, or from a build of the same official sources (1.0.0 used
     github.com/shivammathur/php-builder-windows, whose daily builds change hash; the SHA-256 of
     the 16 files used are recorded in `docs/VERIFICACION.md`). Extract both.
  3. OpenSSL 3.0.22 headers configured for Windows x64: from the official
     `openssl-3.0.22.tar.gz` (SHA-256 `67ebca7e50d17383028045486653492195b83db95f8558709701bb47b5c1ef81`),
     run `perl Configure mingw64 no-asm` (OpenSSL refuses the MSVC target from a Linux Perl; mingw64
     has the same Windows x64 type model), generate the headers with
     `for f in include/openssl/*.h.in; do perl -I. -Mconfigdata util/dofile.pl -oMakefile "$f" > "${f%.in}"; done`
     and set the system macro of the MSVC target:
     `sed -i 's/#  define OPENSSL_SYS_MINGW64 1/#  define OPENSSL_SYS_WIN64A 1/' include/openssl/configuration.h`.

  Then, per DLL:

  ```bash
  export WINEPREFIX="$HOME/.envelock-wine"
  MSVC=<VS2017Layout>/lib/native WINSDK=<SDK.CPP>/c WINSDK64=<SDK.CPP.x64>/c \
  OPENSSL=<openssl-3.0.22>/include PHPDEV=<php-devel-pack folder> PHPZIP=<PHP folder> \
    bash scripts/build-windows-wine.sh nts prebuilt/loader/windows-x64/php-8.4-nts/php_envelock.dll
  ```

  To test it, run the native suite against it with that Windows PHP under Wine: copy a recent
  `vcruntime140.dll`/`vcruntime140_1.dll` from a separately supplied trusted Windows runtime next to
  `php.exe`, create a `php` wrapper that runs
  `WINEDLLOVERRIDES="vcruntime140,vcruntime140_1=n" wine <PHP>/php.exe -d extension_dir=<PHP>/ext "$@"`,
  put it first on `PATH`, and run
  `ENVELOCK_TEST_EXTENSION=<dll> ENVELOCK_TEST_OWNER=owner.json ENVELOCK_TEST_RECIPIENT=recipient.json python -m pytest tests/test_native.py`.
  The tests adapt their expectations (permission messages, paths) to the PHP they run.

*Run for 1.0.0:* the five Linux x86-64 loaders in `prebuilt/` (PHP 8.2, 8.3, 8.4 NTS/ZTS, 8.5)
are portable builds made on 2026-11-12 on AlmaLinux 8 with `build-unix.sh`, `ENVELOCK_OPENSSL_STATIC`
and `ENVELOCK_MAX_GLIBC=2.28` (PLATAFORMAS.md, "Portable build"): glibc 2.28+ and no system OpenSSL
needed; tested there and on Ubuntu 24.04 (`TEST-STATUS.md`). The eight Windows x64 DLLs (8.2–8.5, NTS and TS) are built
natively with `build-windows.ps1` on Windows 11 from the post-audit source (2026-11-10) and pass
`tests/test_native.py` there with 0 failures on each (`TEST-STATUS.md`); the earlier sets were
cross-built with `build-windows-wine.sh`. The assistant executables are built with `build-gui.sh`
(its spec lists the hidden imports the bundled code needs; a test keeps the list complete). *Not run:*
macOS (no Mac; see PLATAFORMAS.md for building, signing and notarizing there).

## 3. OpenSSL 4.0.3

Needed only to compile cryptography yourself (the loader uses the system's OpenSSL 3). It is
built as static libraries, which is how the official cryptography wheels bundle it.

**Linux / macOS** (C compiler, `make`, Perl):

```bash
cd ~/envelock-build/openssl-4.0.3
./Configure --prefix="$HOME/openssl-4.0.3" --libdir=lib no-shared no-tests
make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)"
make install_sw
"$HOME/openssl-4.0.3/bin/openssl" version          # OpenSSL 4.0.3 ...
```

**Windows** (Visual Studio "x64 Native Tools Command Prompt", Strawberry Perl and NASM on PATH):

```bat
cd C:\envelock-build\openssl-4.0.3
perl Configure VC-WIN64A no-shared no-tests --prefix=C:\openssl-4.0.3
nmake
nmake install_sw
```

*Run for 1.0.0:* Linux x86-64 (Ubuntu 24.04, gcc 13.3, Perl 5.38). *Not run:* macOS, Windows.

## 4. cryptography, cffi, pycparser and typing_extensions (offline)

cryptography is Rust + Python. Its 32 Rust crates are already in
`cryptography-50.0.2/vendor/`, and `cryptography-50.0.2/.cargo/config.toml` makes cargo use them
and never touch the network. pip is run with `--no-index`, so nothing is downloaded either.

Requirements: Rust 1.83+ (`rustc --version`), a C compiler, Python 3.10+ with headers
(`python3-dev`), and on Linux `libffi-dev` (Windows uses the libffi bundled in cffi). With
Python 3.10 use `pycparser-3.11` instead of `pycparser-3.12` and also build `typing_extensions-4.16.0`
(cryptography needs it only below 3.11). The build tools are pinned to the versions used for 1.0.0;
`--no-build-isolation` means pip does not install or check them itself.

**Linux / macOS:**

```bash
cd ~/envelock-build
python3 -m venv .venv-build && source .venv-build/bin/activate   # maturin must be on PATH
python -m pip install maturin==1.15.0 setuptools==84.2.1 flit_core==3.12.0   # build tools (PyPI or a mirror)
PYCPARSER=pycparser-3.12          # Python 3.10: pycparser-3.11, and run the two typing_extensions lines
pip wheel --no-index --no-build-isolation --no-deps -w wheels ./$PYCPARSER
pip install --no-index wheels/pycparser-*.whl
# Python 3.10 only:
# pip wheel --no-index --no-build-isolation --no-deps -w wheels ./typing_extensions-4.16.0
# pip install --no-index wheels/typing_extensions-*.whl
pip wheel --no-index --no-build-isolation --no-deps -w wheels ./cffi-2.1.1
pip install --no-index wheels/cffi-*.whl
OPENSSL_DIR="$HOME/openssl-4.0.3" OPENSSL_STATIC=1 \
  pip wheel --no-index --no-build-isolation --no-deps -w wheels ./cryptography-50.0.2
pip install --no-index wheels/cryptography-*.whl
python -c "from cryptography.hazmat.backends.openssl.backend import backend as b; print(b.openssl_version_text())"
```

**Windows (PowerShell):**

```powershell
cd C:\envelock-build
py -3 -m venv .venv-build; .\.venv-build\Scripts\Activate.ps1
python -m pip install maturin==1.15.0 setuptools==84.2.1 flit_core==3.12.0
$pycparser = 'pycparser-3.12'     # Python 3.10: 'pycparser-3.11', and run the two typing_extensions lines
pip wheel --no-index --no-build-isolation --no-deps -w wheels .\$pycparser
pip install --no-index (Get-ChildItem wheels\pycparser-*.whl)
# Python 3.10 only:
# pip wheel --no-index --no-build-isolation --no-deps -w wheels .\typing_extensions-4.16.0
# pip install --no-index (Get-ChildItem wheels\typing_extensions-*.whl)
pip wheel --no-index --no-build-isolation --no-deps -w wheels .\cffi-2.1.1
pip install --no-index (Get-ChildItem wheels\cffi-*.whl)
$env:OPENSSL_DIR = 'C:\openssl-4.0.3'; $env:OPENSSL_STATIC = '1'
pip wheel --no-index --no-build-isolation --no-deps -w wheels .\cryptography-50.0.2
pip install --no-index (Get-ChildItem wheels\cryptography-*.whl)
```

The wheels in `wheels/` can then be installed on other machines of the same system, or used by
the encoder and by the assistant build (section 5).

*Run for 1.0.0:* Linux x86-64 with the network disabled — cryptography compiled in 72 s, reports
`OpenSSL 4.0.3`, and the encoder, hardening and assistant tests passed with it (151 at that October 29 build; the tests added in the October 31 review round run on the standard toolchain, see `VERIFICACION.md`);
typing_extensions also builds offline (with Python 3.12, so the Python 3.10 path itself was not
run). *Not run:*
macOS, Windows. On an Intel Mac this section is the way to get cryptography 50.0.2 (there is no
official wheel for it).

## 5. Assistant executables

One self-contained window executable per OS, with Python and cryptography inside (PyInstaller
does not cross-compile). The recipe is `gui/envelock-assistant.spec`. Use a Python with Tkinter:
the python.org installers on Windows and macOS include it; on Linux install `python3-tk`.

**Linux / macOS:**

```bash
python3 -m venv .venv-gui
bash scripts/build-gui.sh .venv-gui/bin/python
./dist/envelock-assistant --selftest
./dist/envelock-assistant --e2e /tmp/envelock-e2e      # keys, encryption and PHP download, no window
```

`build-gui.sh` installs cryptography from `prebuilt/python-wheels/` when the system has a folder
there (Linux x86-64/ARM64, macOS Apple silicon), otherwise from PyPI checked against
`requirements.lock`, and PyInstaller 6.22.3. To use cryptography you compiled yourself, install
your wheel into `.venv-gui` first.

**Windows (PowerShell, from the repository root):**

```powershell
py -3 -m venv .venv-gui
.\.venv-gui\Scripts\python -m pip install --require-hashes -r requirements.lock
.\.venv-gui\Scripts\python -m pip install pyinstaller==6.22.3
.\.venv-gui\Scripts\python -m PyInstaller --clean --noconfirm --distpath dist gui\envelock-assistant.spec
.\dist\envelock-assistant.exe --selftest
```

**Windows executable from Linux, under Wine** (needs `wine`, plus `xvfb-run` to test without a
screen). The python.org installer does not run well under Wine, so use a portable Windows CPython
with Tkinter, e.g. the `x86_64-pc-windows-msvc-install_only` build of python-build-standalone
(the selected Windows Python and its Visual C++ runtime must be compatible with the target system
and with the PHP executable you run). Supply it separately; no Windows Python or assistant executable
is included in this checkout.

```bash
# from https://github.com/astral-sh/python-build-standalone/releases (tag 20260924)
export WINEPREFIX="$HOME/.envelock-wine"
mkdir -p "$HOME/winpython"
tar xzf cpython-3.13.15+20260924-x86_64-pc-windows-msvc-install_only_stripped.tar.gz -C "$HOME/winpython"
WINPY="$HOME/winpython/python/python.exe"
# "script" gives Wine a terminal; without it Python can fail at start with "Invalid handle".
script -qefc "wine $WINPY -m pip install --require-hashes -r requirements.lock" /dev/null
script -qefc "wine $WINPY -m pip install pyinstaller==6.22.3" /dev/null
script -qefc "wine $WINPY -m PyInstaller --clean --noconfirm --distpath dist/win gui/envelock-assistant.spec" /dev/null
xvfb-run script -qefc "wine dist/win/envelock-assistant.exe --selftest" /dev/null
```

*Run for 1.0.0:* the Windows executable natively on Windows 11 (2026-11-10, CPython 3.12.10,
PyInstaller 6.22.3, from the post-audit source), passing `--selftest` and `--e2e` (also with a real
PHP), rebuilt on 2026-11-12 with the recommender change; the Linux executable with `build-gui.sh`
on AlmaLinux 8 (2026-11-12, CPython 3.12.15, glibc 2.28+), passing `--selftest` under a virtual display
and `--e2e` with PHP 8.4. *Not run:* macOS.

## 6. Portable Python

The **complete** distribution ships a portable Python under `prebuilt/python/` (Windows x64, Linux
x86-64 and ARM64, macOS Apple silicon), which the `envelock` / `envelock.cmd` launchers use. The
**source-only** distribution does not include it, and the launchers then exit with guidance. The
following recipe rebuilds it from scratch; it requires separately obtaining and verifying CPython and
the wheel bundles (`<target>` is e.g.
`x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`aarch64-apple-darwin`):

1. Download `cpython-3.13.15+20260924-<target>-install_only_stripped.tar.gz` and the release's
   `SHA256SUMS` from github.com/astral-sh/python-build-standalone/releases (tag 20260924), and
   check the archive's hash against that list.
2. Extract it; copy its `python/` folder to `prebuilt/python/<system>/`.
3. On Linux/macOS remove the symbolic links outside `share/terminfo` (aliases such as
   `bin/python3`) and replace those in `share/terminfo` with copies of their targets; remove every
   `__pycache__` folder.
4. Install the libraries offline into its site-packages (`Lib/site-packages` on Windows,
   `lib/python3.13/site-packages` elsewhere):
   `pip install --no-index --find-links prebuilt/python-wheels/<folder> --target <site-packages> --no-compile --no-deps --only-binary=:all: --platform <tag> --python-version 3.13 --implementation cp cryptography==50.0.2 cffi==2.1.1 pycparser==3.12`
   (the `<tag>` values are the ones in `scripts/fetch_wheels.py`), then delete the
   `<site-packages>/bin/` folder that pip leaves (a helper script with a path of the build machine).
   Copy the `python/licenses/` folder of the matching *full* build of the same release
   (`cpython-3.13.15+20260924-<target>-pgo[+lto]-full.tar.zst`, also checked against `SHA256SUMS`)
   to `prebuilt/python/<system>/licenses/`.
5. Run `python scripts/check_release.py`; edit or remove what it flags for forbidden terms and
   record it in `prebuilt/README.md`; regenerate `prebuilt/SHA256SUMS` (section 7).

**Compiling CPython yourself.** The `third_party/cpython-3.13.15/` source referred to by this
historical recipe is not included here; if obtained and verified separately, on Linux/macOS
it builds with the standard `./configure --prefix=<folder> && make && make install` (with the
development packages of OpenSSL, zlib, libffi, SQLite, xz, bzip2 and Tk for the matching modules),
and on Windows with `PCbuild\build.bat -p x64` (Visual Studio). That gives a working Python for
that machine; a *relocatable* build like the ones in `prebuilt/python/` additionally links its
libraries statically and fixes paths, which is the job of the python-build-standalone project
(its build scripts are in that repository).

*Run for 1.0.0:* CPython 3.13.15 from `third_party/` with `./configure && make && make install`
on Linux x86-64 (Ubuntu 24.04): it builds and runs, with `ssl`, `sqlite3`, `ctypes`, `lzma`, `bz2`
and `zlib` (`_tkinter` skipped there because Tk's development package was not installed). The
portable folders were assembled with steps 1–5 for the four systems. *Not run:* `PCbuild` on Windows,
macOS.

## 7. Refreshing `prebuilt/` and `third_party/` (maintainers)

Both folders are locked by a `SHA256SUMS` listing every file; the release guard
(`scripts/check_release.py`) refuses any file missing from it or differing from it. Regenerate
the lists after a deliberate change, never to silence an unexpected finding:

```bash
cd prebuilt && find . -type f ! -path ./SHA256SUMS ! -path ./README.md ! -path ./.gitignore \
  ! -path ./.gitattributes ! -path '*/__pycache__/*' -print0 | sort -z | xargs -0 sha256sum | sed 's#  \./#  #' > SHA256SUMS; cd ..
cd third_party && find . -type f ! -path ./SHA256SUMS ! -path ./README.md ! -path ./.gitignore \
  ! -path ./.gitattributes -print0 | sort -z | xargs -0 sha256sum | sed 's#  \./#  #' > SHA256SUMS; cd ..
```

- **New loader binaries:** build them (section 2), run the native suite against each one, copy
  them to `prebuilt/loader/<os-arch>/php-X.Y-<nts|zts>/` and regenerate `prebuilt/SHA256SUMS`.
- **New library version:** update `requirements.lock`; download the official source archive,
  compare its SHA-256 with the lock (or the project's published hash) and extract it into
  `third_party/` (on a system that keeps the bytes; never let an editor or git convert line
  endings — `third_party/.gitattributes` stops git from doing it). For cryptography run
  `cargo vendor --locked vendor` inside it and add `.cargo/config.toml`, `vendor/.gitignore` and
  `vendor/.gitattributes` as in the current copy. Run `python scripts/check_release.py`, remove
  any file it flags for forbidden terms, record every change in `third_party/README.md`, and
  regenerate `third_party/SHA256SUMS`.
- **New wheels:** `python scripts/fetch_wheels.py` downloads, for each system folder and Python
  3.10–3.14, the runtime libraries pinned in `requirements.lock`, evaluating each entry's
  environment marker for the target Python (pip's `--python-version` does not) and checking every
  hash. Then regenerate `prebuilt/SHA256SUMS`.

## 8. Publishing a release for PIE

[PIE](https://github.com/php/pie) installs the loader as the Packagist package `envelock/loader`
(`composer.json` at the repository root: `type: php-ext`, `extension-name: envelock`,
`build-path: extension`). On Windows it can only install a DLL attached to the GitHub Release; on
Linux it prefers a prebuilt `.so` attached to the Release and otherwise builds from source. Users'
side: `docs/HOSTING.md` §4.1.

1. **Tag without a `v`** (`1.0.0`, not `v1.0.0`): PIE puts the package version in the asset names it
   looks for.
2. **Build and test the loaders** (section 2; Linux on the AlmaLinux 8 baseline with
   `ENVELOCK_OPENSSL_STATIC` and `ENVELOCK_MAX_GLIBC=2.28`, see `docs/PLATAFORMAS.md`), copy them to
   `prebuilt/loader/` and regenerate `prebuilt/SHA256SUMS` (section 7).
3. **Package the assets** with their exact PIE names:

   ```bash
   python scripts/package-pie-assets.py --version 1.0.0     # writes dist/pie/
   ```

   It refuses any binary not listed with its hash in `prebuilt/SHA256SUMS`, reads each DLL's
   compiler from its PE header (VS16 for PHP 8.2/8.3, VS17 for 8.4/8.5) and writes
   `php_envelock-1.0.0-8.4-nts-vs17-x86_64.zip` (the DLL inside under the same name) for Windows,
   `php_envelock-1.0.0_php8.4-x86_64-linux-glibc-nts.zip` (`envelock.so` inside) for Linux, LICENSE
   and NOTICE in each, and a `SHA256SUMS` of the assets. The ZIPs are deterministic.
4. **Create the GitHub Release** for the tag and attach the assets:

   ```bash
   gh release create 1.0.0 dist/pie/*.zip dist/pie/SHA256SUMS --title "Envelock 1.0.0" --notes-file CHANGELOG.md
   ```

5. **Packagist, once:** with the repository public, submit its URL at
   <https://packagist.org/packages/submit> (logged in with the maintainer's account) and enable the
   GitHub integration Packagist offers, so every new tag is picked up by itself. The vendor name
   `envelock` was free on Packagist on 2026-11-11.
6. **Check** on a clean server or container: `pie install envelock/loader`, then
   `php --ri envelock` and `scripts/envelock-preflight.php`.

The source build PIE falls back to runs a plain `phpize && ./configure && make`, not
`scripts/build-unix.sh`: `extension/config.m4` therefore carries the hardening itself (stack
protector, stack-clash protection, CET, full RELRO, BIND_NOW, non-executable stack; checked with
PIE 1.5.5 on AlmaLinux 8, PHP 8.4), while `_FORTIFY_SOURCE`, stripping and the post-build gates stay
in `build-unix.sh`. Such a build links the system's OpenSSL 3 dynamically. No `configure-options`
are declared: PIE users cannot switch on the bytecode emitter or the unsafe runner.

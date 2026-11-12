# Prebuilt binaries

Compiled forms of the Envelock loader (Linux and Windows), of the assistant (Linux and Windows),
of the Python libraries the encoder and the assistant use, and a portable Python ready to run the
commands, so nothing has to be compiled, downloaded or
installed. Their source code is in
this repository (`extension/` and [`third_party/`](../third_party/README.md)); how to compile them
yourself: [docs/BUILDING.md](../docs/BUILDING.md).

Every file is listed in [`SHA256SUMS`](SHA256SUMS). Check it before use:

```bash
cd prebuilt && sha256sum -c SHA256SUMS                    # Linux
cd prebuilt && shasum -a 256 -c SHA256SUMS                # macOS
```

```powershell
# Windows PowerShell: compare one file with its line in SHA256SUMS
Get-FileHash prebuilt\python-wheels\win_amd64\cryptography-50.0.2-cp311-abi3-win_amd64.whl -Algorithm SHA256
```

The release guard (`scripts/check_release.py`) refuses any file here that is not listed with the
same hash, and any compiled file elsewhere in the repository (the only exception is the upstream
binaries inside `third_party/`, locked the same way by `third_party/SHA256SUMS`).

## PHP loader (`loader/`)

The loader is **generic**: it contains no keys (they live in each server's identity file), so the
same binary serves every project and client on that PHP version. Choose it by system, PHP version
and thread safety (`php -i | findstr /C:"PHP Extension Build"` on Windows,
`php -i | grep "PHP Extension Build"` elsewhere).

| File | PHP | Module API |
|---|---|---|
| `loader/linux-x86_64/php-8.2-nts/envelock.so` | 8.2, non-thread-safe | API20220829,NTS |
| `loader/linux-x86_64/php-8.3-nts/envelock.so` | 8.3, non-thread-safe | API20230831,NTS |
| `loader/linux-x86_64/php-8.4-nts/envelock.so` | 8.4, non-thread-safe | API20240924,NTS |
| `loader/linux-x86_64/php-8.4-zts/envelock.so` | 8.4, thread-safe | API20240924,TS |
| `loader/linux-x86_64/php-8.5-nts/envelock.so` | 8.5, non-thread-safe | API20250925,NTS |
| `loader/windows-x64/php-8.2-nts/php_envelock.dll` | 8.2, NTS (VS16) | API20220829,NTS,VS16 |
| `loader/windows-x64/php-8.2-ts/php_envelock.dll` | 8.2, TS (VS16) | API20220829,TS,VS16 |
| `loader/windows-x64/php-8.3-nts/php_envelock.dll` | 8.3, NTS (VS16) | API20230831,NTS,VS16 |
| `loader/windows-x64/php-8.3-ts/php_envelock.dll` | 8.3, TS (VS16) | API20230831,TS,VS16 |
| `loader/windows-x64/php-8.4-nts/php_envelock.dll` | 8.4, NTS (VS17) | API20240924,NTS,VS17 |
| `loader/windows-x64/php-8.4-ts/php_envelock.dll` | 8.4, TS (VS17) | API20240924,TS,VS17 |
| `loader/windows-x64/php-8.5-nts/php_envelock.dll` | 8.5, NTS (VS17) | API20250925,NTS,VS17 |
| `loader/windows-x64/php-8.5-ts/php_envelock.dll` | 8.5, TS (VS17) | API20250925,TS,VS17 |

**Linux**

- **Requirements:** Linux x86-64 with **glibc 2.28 or newer** — Ubuntu 20.04+, Debian 11+,
  RHEL/AlmaLinux/Rocky/CloudLinux 8+, Amazon Linux 2023 — and **no OpenSSL from the system**: OpenSSL
  3.5.9 is linked into each loader (static, its symbols hidden), so it coexists with whatever OpenSSL
  PHP uses. Not for musl (Alpine) or ARM64 ([docs/HOSTING.md](../docs/HOSTING.md) §2.2).
- **How they were built (2026-11-12):** portable builds ([PLATAFORMAS](../docs/PLATAFORMAS.md),
  "Portable build"): AlmaLinux 8.10 (glibc 2.28) under WSL1, gcc 8.5, `scripts/build-unix.sh` with
  `ENVELOCK_OPENSSL_STATIC` and `ENVELOCK_MAX_GLIBC=2.28`, against PHP 8.2.35, 8.3.36, 8.4.27 (NTS and
  ZTS) and 8.5.12 built from the php.net tarballs. Measured in each: needs only `libc.so.6`,
  `libdl.so.2`, `libpthread.so.0`, GLIBC_2.25 at most, exports only `get_module` (plus the linker's
  `__bss_start`/`_edata`/`_end` markers). They carry the hosting fixes of 2026-11-11 (HOST-1, HOST-6).
  An earlier set, built on Ubuntu 24.04, needed glibc 2.38 and the system's OpenSSL 3 (HOST-2).
- **How they were tested:** TEST-STATUS.md (AlmaLinux 8 with the system's OpenSSL 1.1.1k in the same
  PHP process; Ubuntu 24.04 with its own PHP 8.3.6 and OpenSSL 3.0.13; real PHP-FPM requests).
  Install: [MANUAL](../docs/MANUAL.md) §10, or `pie install envelock/loader`.

**Windows x64**

- **Requirements:** PHP for Windows x64 of that version and thread safety (the official
  php.net builds, or any built with the same Visual Studio generation, VS16 or VS17). The DLL
  uses only what such a PHP already ships: `php8.dll`/`php8ts.dll`, its `libcrypto-3-x64.dll`
  (OpenSSL 3.x) and the Visual C++ runtime (measured with `dumpbin /dependents`;
  [docs/HOSTING.md](../docs/HOSTING.md) §2.1). Install: [MANUAL](../docs/MANUAL.md) §11.
- **Rebuilt 2026-11-11** from the source with the hosting fixes (HOST-1/HOST-6: OPcache switched off
  per site and Debian/Ubuntu's Phar no longer refused; docs/AUDITORIA.md, Pass 33), same machine and
  toolchain as below. Tested: whole suite on 8.4 NTS (1589 passed, 3 known failures for the 55 files
  missing from this tree), `tests/test_native.py` on 8.2 NTS (946 passed, 0 failed), a targeted
  run on the other six (69 passed, 0 failed each) and the bytecode guard on 8.2–8.5 (TEST-STATUS.md).
  The description below is that of the 2026-11-10 build, which these replace.
- **How they were built (2026-11-10, natively on Windows 11 x64):** with
  `scripts/build-windows.ps1`, i.e. the official `php/php-windows-builder` module
  (`BuildPhpExtension` 1.9.0, PHP SDK 2.8.1) and PHP's own Windows build system (`phpize` +
  `extension/config.w32`), with Visual Studio Build Tools 2022 17.14: MSVC 14.29 (v142) for PHP
  8.2/8.3 (VS16) and MSVC 14.44 (v143) for PHP 8.4/8.5 (VS17), Windows SDK 10.0.19041, against each
  version's php.net development pack and the OpenSSL dependency the builder supplies
  (3.0.22 for 8.2–8.4, 3.5.9 for 8.5). Flags from `config.w32`: `/guard:cf`, `/DYNAMICBASE`,
  `/HIGHENTROPYVA`, `/NXCOMPAT`, `/CETCOMPAT` (the first four checked in each DLL's PE header).
  The TS DLLs are source-only (the bytecode layer is not ZTS-safe, ENV-2026-03). They are built from
  the source after the 2026-11-10 audit (docs/AUDITORIA.md, Pass 32), and contain no path of the build
  machine: sources and `config.w32` embed relative names only, and the builder refuses a DLL that
  embeds the user profile, TEMP, build or source folder. The earlier sets were cross-built under Wine
  with `scripts/build-windows-wine.sh` ([BUILDING](../docs/BUILDING.md) §2).
- **How they were tested (same machine, official php.net PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12, NTS and
  TS, zips checked against windows.php.net's SHA-256):** `tests/test_native.py` against each DLL:
  932 passed / 70 skipped (8.2–8.4) and 943 / 59 (8.5), **0 failed** on all eight; the skips need
  POSIX facilities, a C toolchain or an emitter build. Each DLL exports only `get_module`, the
  production DLLs contain no `envelock_bc_emit`/`envelock_bc_run`/`envelock_trusted_time`, and
  DYNAMICBASE/HIGHENTROPYVA/NXCOMPAT/CFG are set. With the 8.4 NTS DLL, a small app packed as source
  and as bytecode, and real Laravel 13.40 and Symfony 8.1 apps (bytecode), served by `php -S`, gave
  byte-identical responses to the cleartext apps. The deserializer's SEH crash guard was exercised
  with test-only builds of all four versions: corruption sweeps over every word of an image, with a
  PHP fatal raised after each rejection, gave 0 crashes (the first native run had found that the guard
  left the engine unable to raise the next fatal safely — BC-1, fixed). Details: `TEST-STATUS.md`.

**macOS: not included.** A macOS module must be built on a Mac (Apple's toolchain and SDK), and
to run on other people's Macs it must be signed and notarized with a registered Apple developer
account; a module signed only ad hoc and downloaded is blocked by Gatekeeper. How to build it,
how to add the exception for your own module, and how to sign and notarize it:
[docs/PLATAFORMAS.md](../docs/PLATAFORMAS.md#signing-quarantine-and-the-gatekeeper-exception).

## Assistant executables (`assistant/`)

| File | System |
|---|---|
| `assistant/linux-x86_64/envelock-assistant` | Linux x86-64, glibc 2.28+ (measured over everything it bundles), with a desktop session; from the system it needs only glibc and `libxcb.so.1` (present on any X11/XWayland desktop) |
| `assistant/windows-x64/envelock-assistant.exe` | Windows 10/11 x64 |

One self-contained file each (Python, Tkinter and cryptography inside), built with PyInstaller
6.22.3 from `gui/envelock-assistant.spec` (docs/BUILDING.md §5). On Linux make it executable
(`chmod +x`); on Windows double-click it. Usage: [docs/ASSISTANT.md](../docs/ASSISTANT.md).

- **Windows:** rebuilt natively on Windows 11 x64 on 2026-11-12 (the recommender now explains every
  option and says which ones need checking), with the python.org CPython 3.12.10 (the exe bundles its
  Visual C++ runtime). It passed `--selftest` and `--e2e` (keys, encryption, the PHP download path, and
  the vendored PHP parser run by the official PHP 8.4.27 NTS); a scan of every bundled file found no
  path of the build machine (only generic text of the bundled libraries, such as an example path in a
  Python docstring). The 2026-11-10 build had first added the hidden imports the Wine-built exe lacked
  (`shlex`, `calendar`, `ctypes.util`, `socket`, `types`).
- **Linux:** rebuilt on 2026-11-12 on AlmaLinux 8.10 (glibc 2.28) under WSL1 with its CPython 3.12.15
  and Tk 8.6, so it runs on the same systems as the portable loaders. It passed `--selftest` (under a
  virtual X display) and `--e2e` with PHP 8.4.27; no path of the build machine in any bundled file.
  PyInstaller was installed without hash verification (no Linux lock file in `scripts/`; see the
  warning in `scripts/build-gui.sh`). The earlier Linux build (Ubuntu 24.04) needed glibc 2.38 and lacked
  the `shlex` import.

## Python libraries (`python-wheels/`)

Official wheels from PyPI, unmodified; their hashes are the ones pinned in `requirements.lock`.

| Folder | System | Contents |
|---|---|---|
| `win_amd64/` | Windows x64 | cryptography 50.0.2, cffi 2.1.1, pycparser 3.11/3.12, typing_extensions 4.16.0 |
| `linux_x86_64/` | Linux x86-64 (glibc 2.28+) | same |
| `linux_aarch64/` | Linux ARM64 (glibc 2.28+) | same |
| `macos_arm64/` | macOS 11+ on Apple silicon | same |

Each folder covers Python 3.10 to 3.14 (pycparser 3.11 and typing_extensions are the ones Python 3.10 needs). They were downloaded with `scripts/fetch_wheels.py`. Install without network:

```bash
python -m pip install --no-index --find-links prebuilt/python-wheels/linux_x86_64 cryptography==50.0.2
```

The cryptography wheels bundle OpenSSL 4.0.3 (statically linked). There is **no official
cryptography 50.0.2 wheel for Intel Macs (macOS x86-64)**: there, compile it from `third_party/`
(BUILDING §4). Tested here: the Windows and Linux x86-64 folders install offline and run
the encoder (Windows under Wine), and the Linux ARM64 ones run inside the portable Python under
emulation (qemu); macOS was not run.

## Portable Python (`python/`)

A complete Python 3.13.15 per system, with cryptography 50.0.2, cffi 2.1.1 and pycparser 3.12
already installed (from `python-wheels/`), so the commands work right after cloning. The launchers
at the repository root pick the right one:

```bash
./envelock new-project                    # Linux x86-64 / ARM64 (glibc), macOS Apple silicon
```

```bat
envelock new-project                      &rem Windows x64
```

They run `encoder/envelock.py` with `-E -s` (ignoring `PYTHON*` variables and the user's own
site-packages), so only the bundled libraries are used. The same Python also runs the assistant
from source, Tkinter included: `prebuilt\python\windows-x64\pythonw.exe -E -s gui\envelock_gui.py`
(Windows) or `prebuilt/python/<system>/bin/python3.13 -E -s gui/envelock_gui.py`.

| Folder | System | Size |
|---|---|---|
| `python/windows-x64/` | Windows 10/11 x64 | 70 MB |
| `python/linux-x86_64/` | Linux x86-64, glibc 2.28+ (Python needs 2.17, cryptography 2.28) | 124 MB |
| `python/linux-arm64/` | Linux ARM64, glibc 2.28+ | 105 MB |
| `python/macos-arm64/` | macOS 11+ on Apple silicon | 78 MB |

No Intel-Mac build: cryptography 50.0.2 has no compiled form for it. musl-based Linux (Alpine) is
not covered either. On those systems install Python 3.10+ and the requirements (MANUAL §4).

**Origin.** The official "standalone" CPython builds (python-build-standalone, release
20260924, `install_only_stripped` variants), checked against the SHA-256 list published with that
release:

| Archive | SHA-256 |
|---|---|
| `cpython-3.13.15+20260924-x86_64-pc-windows-msvc-install_only_stripped.tar.gz` | `e42fa944748a50e9ff481cbb817ef8a6e3da6fbcf0cf6f29b554e1acb8c7384d` |
| `cpython-3.13.15+20260924-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz` | `d0b640eed27fbdd6f5f2bd33444aee53df2c8863f8b2a96f4094717411e3de9c` |
| `cpython-3.13.15+20260924-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz` | `5ad58156cbec94e5643c13caa792e92df72a23f33d3a6425d4cbff5c4b7a040c` |
| `cpython-3.13.15+20260924-aarch64-apple-darwin-install_only_stripped.tar.gz` | `064afb7c2fc0bbf511d886288adf98696af5105e36c138cdf2c199c0146fcf68` |

**Changes made for Envelock:** cryptography, cffi and pycparser installed into its
site-packages (offline, from `python-wheels/`, without compiled caches; the stray
`site-packages/bin/cffi-gen-src` script that such an install leaves removed); the license texts of
the bundled libraries added in `licenses/`; on Linux and macOS the
convenience aliases that were symbolic links (`bin/python3`, `bin/python`, `bin/python3-config`,
`bin/pydoc3`, `bin/idle3`, `lib/libpython3.13.so`, man-page and pkg-config aliases) removed and
the terminal-database links (`share/terminfo`) replaced by copies, because symbolic links do not
survive git on Windows; the bundled `__pycache__` folders removed (Python writes them again when
it runs; git ignores them); in `idlelib/News3.txt` (IDLE's change log), the name of an AI coding
product replaced by a generic description, as in `third_party/` (Envelock's publication policy).

**Libraries inside it, and where to get their source.** Each folder carries their license texts in
`licenses/` (copied from the matching full build of the same release, also checked against its
published hash). Versions and source archives are those of the build project's download list
for release 20260924 (`pythonbuild/downloads.json` at that tag); the OpenSSL, SQLite, Tcl/Tk,
zlib, expat and mpdecimal versions were also confirmed by running each Python. The Windows build takes
several of them from CPython's own Windows dependency builds; there the libffi, bzip2 and xz
versions were not confirmed.

| Library | Version | License (in `licenses/`) | Official source |
|---|---|---|---|
| OpenSSL | 3.5.8 | `LICENSE.openssl-3.txt` | github.com/openssl/openssl/releases/download/openssl-3.5.8/openssl-3.5.8.tar.gz |
| SQLite | 3.53.1 | `LICENSE.sqlite.txt` | www.sqlite.org/2026/sqlite-autoconf-3530100.tar.gz |
| zlib | 1.3.2 | `LICENSE.zlib.txt` | github.com/madler/zlib/releases/download/v1.3.2/zlib-1.3.2.tar.gz |
| bzip2 | 1.0.8 | `LICENSE.bzip2.txt` | sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz |
| xz (liblzma) | 5.8.4 | `LICENSE.liblzma.txt` | github.com/tukaani-project/xz/releases/download/v5.8.4/xz-5.8.4.tar.gz |
| expat | 2.8.5 (Windows: 2.8.2) | `LICENSE.expat.txt` | github.com/libexpat/libexpat/releases |
| libffi | 3.4.8 | `LICENSE.libffi.txt` | github.com/libffi/libffi/releases/download/v3.4.8/libffi-3.4.8.tar.gz |
| mpdecimal | 4.0.0 | `LICENSE.mpdecimal.txt` | www.bytereef.org/mpdecimal/ |
| Tcl/Tk | 9.0.4 (Windows: 8.6.15) | `LICENSE.tcl.txt` | prdownloads.sourceforge.net/tcl/ (tcl9.0.4-src, tk9.0.4-src) |
| Linux/macOS only: ncurses | 6.5 | `LICENSE.ncurses.txt` | invisible-island.net/ncurses/ |
| Linux/macOS only: libedit | 20240808-3.1 | `LICENSE.libedit.txt` | thrysoee.dk/editline/libedit-20240808-3.1.tar.gz |
| Linux/macOS only: libuuid | 1.0.3 | `LICENSE.libuuid.txt` | sourceforge.net/projects/libuuid/ |
| Linux/macOS only: Berkeley DB | 6.0.19 | `LICENSE.bdb.txt` | ftp.osuosl.org/pub/blfs/conglomeration/db/db-6.0.19.tar.gz |
| Linux only (for Tk): libX11, libXau, libxcb | 1.8.13, 1.0.12, 1.17.0 | `LICENSE.libX11.txt`, `LICENSE.libXau.txt`, `LICENSE.libxcb.txt` | www.x.org/releases/individual/lib/, xcb.freedesktop.org/dist/ |

Berkeley DB is used only by Python's `dbm` module (`_dbm`, which Envelock does not use); its
license asks that its source and that of the software using it be obtainable: Berkeley DB's from
the link above, CPython's in `third_party/cpython-3.13.15/`. The Windows build also contains
Microsoft's Visual C++ runtime (`vcruntime140.dll`, `vcruntime140_1.dll`), redistributable under
Microsoft's terms. It includes pip, whose bundled libraries keep their licenses in
`site-packages/pip-*.dist-info/licenses/`. The build scripts are in the build project's repository
(github.com/astral-sh/python-build-standalone, tag 20260924).

**Tested here:** Linux x86-64 (`./envelock`: keys, encryption and identity file, then the
protected file run by the loader in `loader/`); Windows x64 under Wine (`envelock.cmd`, and the
assistant's `--selftest` with this Python) and natively on Windows 11 (2026-11-10: `envelock.cmd
new-project`, and the bundled Python reports 3.13.15 with cryptography 50.0.2 and OpenSSL 3.5.8);
Linux ARM64 under qemu (keys and encryption). macOS was not run.

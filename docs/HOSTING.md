# Server requirements and hosting compatibility

What a server needs to run Envelock-protected PHP, what the loader depends on, and what can stop it
on each kind of hosting. Written for whoever decides where a protected application will run: the
vendor, the client, or the hosting provider.

How this was established (2026-11-11): the native dependencies were read from the shipped binaries
themselves (`dumpbin /dependents` on the Windows DLLs, `readelf -d -V` on the Linux `.so` files);
the PHP-configuration behaviour comes from the loader's source and was measured with the shipped
Windows DLLs on the official PHP 8.2–8.5 builds; facts about operating systems and hosting
products link to their own documentation. Anything not run here is marked as such.

## Quick answer

| Where | Does it work? | What it takes |
|---|---|---|
| VPS, dedicated or cloud server (root access) | **Yes** | Install the loader for your PHP and set two `php.ini` lines (§4.1). Linux: the prebuilt loaders run on any x86-64 glibc system from 2.28 on (§2.2); elsewhere, build the loader on the server. |
| Docker / Kubernetes | **Yes**, in an image you build | Add the loader and its `.ini` to the image; mount the identity file as a regular file (§4.2). The official `php` images (Debian 13) fit the prebuilt loader; Alpine does not. |
| Windows server (IIS, Apache) | **Yes** | The DLL needs nothing beyond what the official PHP for Windows already ships (§2.1, §4.5). |
| Shared hosting (cPanel, Plesk, DirectAdmin…) | **Only if the provider installs it** | A customer cannot load a PHP extension; the provider has to (§4.3, §6). |
| Managed WordPress hosting, most PaaS | **Usually no** | They do not let customers add compiled PHP extensions (§4.4). |

The fastest way to know for a given server: run the pre-flight check (§1).

## 1. Pre-flight check

`scripts/envelock-preflight.php` reads the server's PHP configuration and says, line by line, what
would stop Envelock (`FAIL`), what needs a change (`WARN`) and what matters only for some package
options (`INFO`). It changes nothing.

1. Upload it to the server, inside the site.
2. Open it in the browser (it reports the PHP that serves the web: PHP-FPM, LiteSpeed, Apache…), and/or
   run `php envelock-preflight.php` over SSH (the command-line PHP often reads another `php.ini`).
3. **Delete it** afterwards: it prints details of the server configuration.

Before the loader is installed it tells you which loader file to use and whether the system has
what that loader needs; after it is installed it confirms that the identity file was accepted and
that OPcache is set up in a way the loader accepts. Tested on Windows: from the command line with
all eight shipped DLLs (PHP 8.2–8.5, NTS and TS, with and without the loader; two tests in
`tests/test_native.py`), and as a web page through `php-cgi` on 8.4 and 8.5. On Linux, run on
Ubuntu 24.04 with its own PHP 8.3 (the glibc check); the musl branch has not been run.

## 2. What the loader depends on

The loader is one file per PHP version: `php_envelock.dll` on Windows, `envelock.so` on Linux. It
needs **no other PHP extension** (not even PHP's own `openssl` extension) and no Internet access.

### Dependencies by operating system

What each part needs on each system, and whether it comes ready or must be installed. "Loader" is
what goes on the server; "encoder" and "assistant" are only for the machine that creates the
packages.

| System | Loader (server) | Encoder (command line) | Assistant (window) |
|---|---|---|---|
| **Windows 10/11, Server 2016+, x64** | Prebuilt DLL. Needs only what the official PHP already has: its `libcrypto-3-x64.dll` and the Visual C++ runtime. **Nothing to install.** | Portable Python included (complete distribution). **Nothing to install.** | Prebuilt `.exe`, self-contained (Python, Tk and the Visual C++ runtime inside). **Nothing to install.** |
| **Linux x86-64, glibc 2.28+** (Ubuntu 20.04+, Debian 11+, RHEL/Alma/Rocky/CloudLinux 8+, Amazon Linux 2023) | Prebuilt portable `.so`: needs only glibc (part of the system); OpenSSL is inside. **Nothing to install.** | Portable Python included (glibc 2.28+). **Nothing to install.** | Prebuilt executable: needs glibc 2.28+, `libxcb.so.1` (on any X11/XWayland desktop) and a graphical desktop; everything else is inside. |
| **Linux ARM64, glibc 2.28+** | No prebuilt loader: build it on the server (below). Not tested. | Portable Python included. | Run it from source with the portable Python (Tkinter included). |
| **Alpine and other musl Linux** | No prebuilt loader: build it on the server (below). Not tested. | Install Python 3.10+ and the locked requirements. | Run it from source (needs Python's Tkinter). |
| **macOS on Apple silicon (11+)** | No prebuilt loader: build it (below). It then needs Homebrew's `openssl@3` on that Mac. Not tested on a real Mac (CI builds and tests it). | Portable Python included. | Run it from source with the portable Python (Tkinter included). |
| **macOS on Intel** | Build it as on Apple silicon. Not tested. | Not supported out of the box: cryptography 50.0.2 publishes no Intel-Mac build (building it needs Rust). | As the encoder. |
| **FreeBSD** | Not supported; the source may build (PHP development files, OpenSSL 3), not tested. | Install Python 3.10+ and the requirements. | — |

**Installing what is missing:**

- **Windows.** Only if PHP itself does not start: the Visual C++ Redistributable 2015–2022 x64,
  <https://aka.ms/vs/17/release/vc_redist.x64.exe>. PHP: <https://windows.php.net/download/>. Python
  (source-only distribution): <https://www.python.org/downloads/windows/>, then
  `py -m pip install --require-hashes -r requirements.lock`.
- **Debian / Ubuntu.** Encoder without the portable Python:
  `sudo apt install python3 python3-venv` and the locked requirements (MANUAL §4); assistant from
  source: `sudo apt install python3-tk`. To build the loader:
  `sudo apt install php8.4-dev libssl-dev pkg-config autoconf make gcc` (adapt the PHP version).
- **RHEL / AlmaLinux / Rocky / CloudLinux / Fedora / Amazon Linux 2023.** Encoder:
  `sudo dnf install python3.12` (and `python3.12-tkinter` for the assistant from source). To build
  the loader: `sudo dnf install php-devel openssl-devel pkgconf-pkg-config autoconf make gcc`; on
  the 8 family OpenSSL 3 comes from EPEL (`openssl3-devel`, after `sudo dnf install epel-release`).
- **Alpine.** Encoder: `apk add python3 py3-pip` and the requirements. To build the loader:
  `apk add php84-dev openssl-dev pkgconf autoconf make gcc musl-dev` (adapt the PHP version).
- **macOS.** Xcode Command Line Tools (`xcode-select --install`) and Homebrew
  (<https://brew.sh>); to build the loader: `brew install php openssl@3 autoconf pkgconf`
  (`docs/PLATAFORMAS.md`, macOS). Python, if not using the portable one:
  <https://www.python.org/downloads/macos/> (includes Tkinter).
- **Any system, building the loader:** `bash scripts/build-unix.sh` (`docs/BUILDING.md` §2), or
  `pie install envelock/loader`, which builds it when no prebuilt one fits (§4.1).

The details per platform follow.

### 2.1 Windows x64

Measured in all eight DLLs (`prebuilt/loader/windows-x64/`):

| Library | What it is | Where it comes from |
|---|---|---|
| `php8.dll` / `php8ts.dll` | PHP itself | The PHP installation. |
| `libcrypto-3-x64.dll` | OpenSSL 3 (encryption) | **Shipped in the folder of every official PHP for Windows build** (measured: 8.2.35, 8.3.36 and 8.4.27 carry OpenSSL 3.0.22, 8.5.12 carries 3.5.9). Any OpenSSL 3.x works. |
| `VCRUNTIME140.dll`, `api-ms-win-crt-*.dll` | Microsoft Visual C++ runtime | The same runtime PHP itself needs. The `api-ms-win-crt-*` part (Universal CRT) is part of Windows 10/11 and Windows Server 2016+. |
| `KERNEL32.dll`, `ADVAPI32.dll` | Windows | Always present. |

**Nothing to install beyond what PHP already needs.** If `php.exe` starts, everything the DLL
needs is there, with one exception: Apache loading PHP as a module (`php8apache2_4.dll`) looks for
`libcrypto-3-x64.dll` on the DLL search path, not in PHP's folder. If PHP's own `openssl`
extension works in that Apache, Envelock will too; if Apache says the module "could not be found",
add PHP's folder to the system `PATH` (or `LoadFile "C:/php/libcrypto-3-x64.dll"` before
`LoadModule php_module` in `httpd.conf`) and restart Apache.

If PHP does not start because the Visual C++ runtime is missing, install the latest supported
**Visual C++ Redistributable for Visual Studio 2015–2022, x64**:
<https://aka.ms/vs/17/release/vc_redist.x64.exe> (Microsoft's list:
<https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist>). PHP for Windows itself:
<https://windows.php.net/download/>.

`libssl-3-x64.dll` is **not** needed: the trusted-time feature, the only one that speaks TLS, is not
implemented on Windows (§3.6).

### 2.2 Linux x86-64

The prebuilt loaders (`prebuilt/loader/linux-x86_64/`) are **portable**: built on AlmaLinux 8
(glibc 2.28) with OpenSSL 3 linked in, so they need nothing but the C library (measured with
`readelf -d -V`):

| Library | Version needed | Notes |
|---|---|---|
| `libc.so.6`, `libdl.so.2`, `libpthread.so.0` (glibc) | **2.28 or newer** | The build refuses a loader that needs a newer glibc than 2.28 (`ENVELOCK_MAX_GLIBC`); the highest symbol version they actually use is GLIBC_2.25. glibc is part of the operating system. |
| OpenSSL | **none from the system** | OpenSSL 3.5.9 is inside the loader (static, its symbols hidden), so it does not matter whether the server has OpenSSL 1.1.1 or 3.x, or which one PHP itself uses. |
| PHP's own symbols | — | Resolved from the running PHP. |

| System | glibc | Prebuilt loader loads? |
|---|---|---|
| Ubuntu 20.04 / 22.04 / 24.04 LTS | 2.31 / 2.35 / 2.39 | Yes |
| Debian 11 / 12 / 13 | 2.31 / 2.36 / 2.41 | Yes |
| RHEL / AlmaLinux / Rocky / CloudLinux 8 | 2.28 | Yes |
| RHEL / AlmaLinux / Rocky / CloudLinux 9, Amazon Linux 2023 | 2.34 | Yes |
| RHEL / AlmaLinux / Rocky 10 | 2.39 | Yes |
| Amazon Linux 2 | 2.26 | No — build on the server |
| Alpine (any) | musl, not glibc | No — build on the server |

Run here: on AlmaLinux 8 (glibc 2.28, system OpenSSL 1.1.1k, which PHP's own `openssl` extension
used in the same process) and on Ubuntu 24.04 (glibc 2.39, OpenSSL 3.0.13, its own PHP 8.3); the
other rows follow from glibc's symbol versioning. Versions: Ubuntu and Debian package archives
(<https://packages.ubuntu.com>, <https://packages.debian.org>,
<https://launchpad.net/ubuntu/focal/+source/glibc>), the AlmaLinux and CloudLinux repositories
(<https://repo.almalinux.org/almalinux/>, <https://repo.cloudlinux.com/cloudlinux/>), Amazon Linux
(<https://docs.aws.amazon.com/linux/al2023/ug/amzn2-al2023-ami.html>); checked 2026-11-11.

Check a server:

```bash
ldd --version | head -1                                # glibc version (first line)
php -n -d extension=/path/envelock.so --ri envelock    # the definitive test: loads it or says why not
```

A loader that cannot load prints the reason, e.g. ``version `GLIBC_2.25' not found`` (system older
than glibc 2.28).

**Building the loader on the server** (another architecture, musl, or a system older than glibc
2.28) needs PHP's development files, OpenSSL 3 headers, `pkg-config` and a compiler — e.g.
`sudo apt install php8.4-dev libssl-dev pkg-config autoconf make gcc` (adapt the PHP version), or
`dnf install php-devel openssl-devel` (RHEL 9+; on RHEL 8, OpenSSL 3 comes from EPEL:
`openssl3-devel`). Then `bash scripts/build-unix.sh` (`docs/BUILDING.md`, `docs/PLATAFORMAS.md`),
or let PIE do it (§4.1). A loader built that way uses the system's OpenSSL 3 dynamically.

**Maintenance:** with OpenSSL inside the loader, each OpenSSL security release means rebuilding
and republishing the Linux loaders (`docs/PLATAFORMAS.md`, "Portable build").

### 2.3 Other systems

There is no prebuilt loader for **ARM64** servers (AWS Graviton, Ampere, Raspberry Pi), **Alpine /
musl**, **macOS** or **FreeBSD**. The loader's source needs only PHP's development files, OpenSSL 3,
`pkg-config` and a C compiler, so it can be built on such a system, but none of these builds has
been tested here (status: `docs/VERIFICACION.md`).

### 2.4 PHP itself

- **PHP 8.2, 8.3, 8.4 or 8.5**, with the loader built for that minor version and the same thread
  safety (NTS or TS/ZTS); on Windows also the same compiler generation (VS16 for 8.2/8.3, VS17 for
  8.4/8.5, which the official builds use). `php -i | grep "PHP Extension Build"` shows it
  (e.g. `API20240924,NTS`).
- **NTS** runs both kinds of package. **TS/ZTS** (e.g. Apache with PHP as a module on Windows) runs
  source packages only; `--bytecode` packages are refused there.
- Any SAPI: PHP-FPM, Apache module, CGI/FastCGI (IIS), LiteSpeed (LSAPI), CLI.

### 2.5 The developer's machine (encoder and assistant)

Not needed on the server — only where packages are created:

- **Encoder (command line):** Python 3.10+ with the hash-locked packages
  (`python -m pip install --require-hashes -r requirements.lock`: `cryptography` 50.0.2 and its
  `cffi`/`pycparser`), or the portable Python shipped in the complete distribution
  (`prebuilt/python/`: Windows x64, Linux x86-64/ARM64 with glibc 2.28+, macOS Apple silicon). Python:
  <https://www.python.org/downloads/>.
- **A PHP command line** for some pack options (the obfuscation passes, and `--bytecode`, which also
  needs a loader built with the emitter: `docs/BUILDING.md`).
- **Assistant executable:** the Windows `.exe` is self-contained (it bundles Python, Tk and its Visual
  C++ runtime). The Linux one bundles Python, Tk and its X11 libraries too and needs glibc 2.28+
  (measured over everything it bundles), `libxcb.so.1` from the system and a desktop session
  (X11 or XWayland).

## 3. What the PHP configuration must allow

### 3.1 Loading the extension

Two lines in the `php.ini` that the serving PHP reads **at startup**, then a restart of PHP:

```ini
extension=/path/private/envelock.so          ; php_envelock.dll on Windows
envelock.identity=/path/private/identity.bin
```

Every `envelock.*` setting is `PHP_INI_SYSTEM`: it cannot be set from `.user.ini`, `.htaccess` or the
application, and with PHP-FPM it cannot be set per pool either (`php_admin_value` in a pool is
ignored: the master reads it before it applies pool settings). Whoever controls the main `php.ini`
and can restart PHP must do it — on shared hosting, that is the provider.

### 3.2 The identity file

The server's private keys (`docs/MANUAL.md` §6, §10, §11). The loader reads it once, at startup:

- **Linux/Unix:** a regular file (not a symlink: it is opened with `O_NOFOLLOW`), owned by the user
  that **starts** PHP (root for PHP-FPM and Apache) and mode `0600` — no group or other bits, or it
  is refused. It does not need to be inside `open_basedir`.
- **Windows:** owner and every access entry must be the account PHP runs as, SYSTEM,
  Administrators or OWNER RIGHTS (`icacls` commands in `docs/MANUAL.md` §11).
- After any change to the file, **restart PHP**.

### 3.3 OPcache

Almost every server has OPcache on, and PHP 8.5 always includes it. By default the loader refuses
protected files while OPcache's shared-memory cache is on (it would keep the decrypted program in
memory between requests). Measured with the shipped Windows DLLs — every row by tests that pass on
all eight (`tests/test_native.py`), the fourth row with `allow_opcache=1` on PHP 8.4 and 8.5:

| OPcache setup | Result |
|---|---|
| Off in `php.ini` (`opcache.enable=0`) or not loaded | **Works** |
| On in `php.ini` + `envelock.allow_opcache=1` + `opcache.blacklist_filename` listing the protected folder | **Works**, and the rest of the server keeps OPcache — **the recommended server setup** |
| On in `php.ini`, nothing else | Refused: "OPcache is enabled; …" |
| On in `php.ini` and **switched off afterwards** for the site (`.user.ini`, `.htaccess`/vhost `php_admin_flag`, FPM pool `php_admin_flag`) | **Works** (loaders built from 2026-11-11 on; earlier ones refused it with "another extension installed a compile hook above Envelock's") |
| `opcache.file_cache`, `opcache.file_cache_only` or `opcache.preload` set | Always refused (they persist decrypted code) |

The fourth row matters on hosting, because switching OPcache off per site is the only OPcache
change a hosting customer can usually make (`opcache.enable` can be switched off at run time but
not on: <https://www.php.net/manual/en/opcache.configuration.php>). OPcache's compile hook stays
installed above Envelock's (it was on when PHP started) and passes every file straight through; the
loader recognises that hook as OPcache's own by the module its code lives in, so it runs the file,
and OPcache does not cache it. A hook from any other module is still refused, and so is one that
was already above Envelock when PHP finished starting, even if OPcache later covers it (HOST-1 in
`docs/AUDITORIA.md`).

The blacklist file holds one path prefix per line, e.g. `/var/www/myapp-protected/` (OPcache
documentation: <https://www.php.net/manual/en/opcache.configuration.php#ini.opcache.blacklist-filename>).
If the protected folder is missing from it, the loader refuses the file instead of letting OPcache
cache it.

### 3.4 Extensions that make the loader refuse protected files

| What is loaded | Effect | Way out |
|---|---|---|
| Debuggers and profilers: `xdebug`, `vld`, `uopz`, `runkit7`, `xhprof`, `tideways`, `tideways_xhprof`, `ddtrace`, `spx`, `pcov`, `blackfire`, `memprof`, or the `phpdbg` SAPI | Refused | Remove them from the serving PHP, or `envelock.allow_debuggers=1` (development machines only). |
| Any extension whose compile hook ends up **above** Envelock's — which is how the loaders of other encoders (**ionCube Loader**, **SourceGuardian**) decode their own files | Refused: "another extension installed a compile hook above Envelock's" (there is no switch for it; the only exceptions are PHP's own OPcache and Phar, recognised by the module their hook lives in) | Do not load them in the same PHP. On panels that let you choose extensions per PHP version or per account (cPanel, CloudLinux PHP Selector), turn ionCube/SourceGuardian off for the PHP that serves the protected site. |
| `zend.multibyte=1` | Refused | `zend.multibyte=0` (the default). |
| APM/monitoring agents that observe execution (e.g. New Relic, OpenTelemetry) | Fine by default; refused only with `envelock.paranoid=1` | Leave `envelock.paranoid` off on such servers. |

The compile-hook refusal is deliberate (a hook above the loader would see what it hands to the
compiler) and is covered by `test_o3_rehook_above_envelock_is_detected` with a test hook module;
it has **not** been run against the ionCube or SourceGuardian binaries themselves. What decides it
is the order: PHP starts every `zend_extension` (ionCube Loader is one, and must be the first of
them: <https://www.ioncube.com/phpd-zo.php>) after every regular extension, so a compile hook
installed there sits above Envelock's, as OPcache's does; a regular
extension (SourceGuardian's loader is loaded with `extension=`) sits above Envelock only if it is
loaded after it. A hook loaded *before* Envelock is fine (Envelock calls it; covered by
`test_php_later_compile_hook_cannot_orphan_the_plaintext`).

**Phar (HOST-6).** On Debian and Ubuntu, PHP's Phar is a separate module loaded from
`conf.d/20-phar.ini`, i.e. *after* an `extension=` line in the main `php.ini`, so its compile hook
sits above Envelock's. Loaders built before 2026-11-11 therefore refused **every** protected file
with the distribution's own configuration when installed as this guide and the manual describe
(measured on Ubuntu 24.04 with its PHP 8.3.6). Current loaders recognise Phar's hook as PHP's own,
like OPcache's.

### 3.5 Settings that make no difference (measured)

- `disable_functions` (including `exec`, `shell_exec`, `proc_open`, `system`, `passthru`, `popen`, `dl`).
- `open_basedir`: respected as for any PHP file — the protected files must be inside it, as the
  application already must be. The identity, licence and clock files are read by the loader
  directly and do not need to be.
- `auto_prepend_file` (unless the package was made with `--no-prepend`, §3.6).
- Outbound network access: none is needed (except the optional trusted time, §3.6).

### 3.6 Settings needed only by some package options

| Package option / feature | Needs on the server |
|---|---|
| `--no-ffi` | `enable_dl=Off` (it is `Off` in PHP's `php.ini-production` and `php.ini-development`, but the built-in default, used when no `php.ini` sets it, is `On`: <https://www.php.net/manual/en/info.configuration.php>) and FFI not enabled (`ffi.enable` not `On`). |
| `--no-prepend` | No `auto_prepend_file`/`auto_append_file` — some security plugins use one (Wordfence's "Extended Protection" firewall mode, for instance: <https://www.wordfence.com/help/firewall/optimizing-the-firewall/>). |
| `--sealed` | Every cleartext PHP file under the tree is refused unless its folder is listed in `envelock.sealed_cleartext` (`php.ini`), and `eval()` is refused while the package is active. |
| `--bytecode` | NTS PHP; the **exact** PHP build the package was made for (a host's PHP patch update, e.g. 8.4.27 → 8.4.28, makes the loader refuse it until it is repacked); the absolute deploy path given at pack time (`--deploy-root`). |
| `--include-protection` | Nothing on the server; protected files can only be included by other protected files of the same project or be the entry script. |
| Licences | `envelock.licence` in `php.ini` pointing to the licence file. |
| Anti clock rollback | `envelock.clock_state`: a file the PHP **worker** can write. |
| Trusted time | `envelock.trusted_time`: outbound HTTPS to that host. Linux only (on Windows it is not implemented and the loader falls back to the local clock); if the host cannot be reached the site still runs. |

## 4. Hosting types

### 4.1 VPS, dedicated or cloud server (root access)

Everything is in your hands; follow `docs/MANUAL.md` §10 (Linux) or §11 (Windows):

1. Check the system (§2.2) or run the pre-flight check (§1).
2. Install the loader for your PHP — with PIE in one command (below), or by copying the right file
   from `prebuilt/loader/` outside the web root — and create the identity file (§3.2).
3. Add the two `php.ini` lines (§3.1) to the `php.ini` of the PHP that serves the site, and set
   OPcache as in §3.3 (recommended: `envelock.allow_opcache=1` + blacklist).
4. Restart PHP (e.g. `sudo systemctl restart php8.4-fpm`) and run the pre-flight check again.

#### Installing the loader with PIE

[PIE](https://github.com/php/pie) (the PHP Installer for Extensions, PECL's official successor)
picks the right loader for the PHP it is pointed at and enables it:

```bash
pie install envelock/loader                                   # the PHP on the PATH
pie install --with-php-config=/usr/bin/php-config8.3 envelock/loader   # a specific one (Linux)
```

```powershell
pie install --with-php-path=C:\php\php.exe envelock/loader     # Windows
```

- **Windows:** PIE downloads the DLL for that PHP version, thread safety and compiler from the
  GitHub Release and installs it as `ext\php_envelock.dll`.
- **Linux x86-64 (glibc):** PIE downloads the portable prebuilt `envelock.so` (§2.2). Where none
  matches (another architecture, musl), it builds the loader from source with `phpize`, which
  needs PHP's development files, OpenSSL 3 headers, `pkg-config` and a compiler
  (`sudo apt install php8.4-dev libssl-dev pkg-config` or the `dnf` equivalent); the build is
  hardened as the prebuilt one is (`extension/config.m4`).
- PIE then adds `extension=envelock` (to a `conf.d` file, through `phpenmod` or
  `docker-php-ext-enable`, or to `php.ini`), using `sudo` if it has to.
- **What PIE does not do:** the identity file and the `envelock.identity` line (§3.1–3.2), the
  OPcache setting (§3.3) and the restart of PHP stay with you. Run the pre-flight check afterwards.

PIE needs administrator rights on the server like any extension install, so it does not change
the picture on shared hosting (§4.3). Install PIE itself from its releases or package
(`sudo dnf install pie` with EPEL, `brew install pie`), as its documentation explains:
<https://github.com/php/pie/blob/main/docs/usage.md>. Checked: PIE 1.5.5 found the package from this
repository's `composer.json`, built the loader from source with the hardening flags, and the
module loaded in PHP 8.4 (AlmaLinux 8); downloading the prebuilt assets can only be checked once
a release is published (docs/BUILDING.md §8).

### 4.2 Docker and Kubernetes

Add the loader to the image and give it a `.ini` in the image's configuration folder. With the
official `php` images:

```dockerfile
FROM php:8.4-fpm
COPY envelock.so /opt/envelock/envelock.so
RUN printf 'extension=/opt/envelock/envelock.so\nenvelock.identity=/run/secrets/envelock-identity\n' \
      > /usr/local/etc/php/conf.d/50-envelock.ini
```

Or with PIE, which picks the loader and enables it (`docker-php-ext-enable`); only the identity
line is left:

```dockerfile
FROM php:8.4-fpm
RUN --mount=type=bind,from=ghcr.io/php/pie:bin,source=/pie,target=/usr/local/bin/pie \
    set -eux; apt-get update; apt-get install -y --no-install-recommends unzip; \
    pie install --no-cache envelock/loader; \
    apt-get purge -y --auto-remove unzip; rm -rf /var/lib/apt/lists/*; \
    echo 'envelock.identity=/run/secrets/envelock-identity' > /usr/local/etc/php/conf.d/50-envelock-identity.ini
```

- The base system decides whether the prebuilt loader fits (§2.2). The official images' plain tags
  (`8.4`, `8.4-fpm`, `8.4-cli`) are Debian 13 "trixie" (glibc 2.41) and the `-bookworm` tags Debian 12
  (glibc 2.36): the prebuilt loader fits both; the `-alpine` variants use musl and need a loader built
  in that image (<https://github.com/docker-library/docs/blob/master/php/README.md>). Check any image with
  `docker run --rm <image> ldd --version`.
- The identity file must arrive as a **regular file**, owned by root (the FPM master starts as root
  in the official images) and mode `0600`. Docker and Compose secrets are regular files. **Kubernetes
  secret volumes present each key as a symbolic link** (into `..data/`), which the loader refuses
  (§3.2): mount the key with `subPath` and `defaultMode: 0400`, or copy it into place with an init
  container. Check the result inside the container with `ls -l`: a regular file, owner root, no
  group or other permissions (`-r--------` or `-rw-------`).
- Configure OPcache as in §3.3 in the same `.ini`.

### 4.3 Shared hosting (cPanel, Plesk, DirectAdmin, CloudLinux)

A hosting **customer** cannot do what the loader needs: load an extension, set `PHP_INI_SYSTEM`
values, place a root-owned identity file or restart PHP. **The provider has to install it**, the
way many install ionCube Loader for their customers. Points to raise with the provider (a ready
message is in §6):

- **The loader file** must fit their system (§2.2): the prebuilt Linux loaders run on every panel's
  usual operating system (AlmaLinux/CloudLinux/Rocky 8–10, Ubuntu 20.04+, Debian 11+).
- **One identity file per PHP master.** With PHP-FPM, one master per PHP version serves every
  account, so every account on that PHP shares one identity file (it can hold several clients'
  entries, `docs/MANUAL.md` §13), and every worker holds those keys in memory: separation between
  accounts then rests on the provider's account isolation (CageFS, per-user file permissions).
  Where PHP is started as the account's own user (LiteSpeed LSAPI, suPHP/CGI), a per-account
  identity file is possible only if the provider lets that account have its own `php.ini`
  directives.
- **OPcache:** the provider sets it as in §3.3 — or leaves it on, and the customer switches it off
  for the protected site with `opcache.enable=0` in a `.user.ini` (current loaders accept that; the
  rest of the account keeps OPcache).
- **ionCube / SourceGuardian** must be off for the PHP that serves the protected site (§3.4).
- **PHP upgrades:** the provider must install the loader for a new PHP minor version **before**
  moving the site to it, and `--bytecode` packages must be repacked after any PHP update (§5).

Where the provider's administrator puts it, per panel (all of them administrator-only; `extension=`
is a `php.ini`-only directive, so `.user.ini`/`.htaccess` cannot do it:
<https://www.php.net/manual/en/ini.list.php>):

| Panel | Where the administrator installs a custom extension | Can the account owner? |
|---|---|---|
| cPanel / WHM (EasyApache 4) | Module in `/opt/cpanel/ea-phpXY/root/usr/lib64/php/modules/`, its `.ini` in `/opt/cpanel/ea-phpXY/root/etc/php.d/` (<https://docs.cpanel.net/ea4/php/the-cpanel-phprc-php-patch-for-easyapache4/>, <https://docs.cpanel.net/whm/software/php-pecl/>) | No documented way |
| CloudLinux PHP Selector (alt-php) | Module in `/opt/alt/phpXY/usr/lib64/php/modules/`, `.ini` in `/opt/alt/phpXY/etc/php.d.all/`, then `cagefsctl --setup-cl-selector`; accounts can then tick it in the Selector, and can change only the `php.ini` options the administrator whitelists in `/etc/cl.selector/php.conf` (<https://docs.cloudlinux.com/cloudlinuxos/cloudlinux_os_components/>) | Only enable it once installed |
| Plesk | `extension=…` in `/opt/plesk/php/X.Y/etc/php.d/<name>.ini`, then `plesk bin php_handler --reread` (<https://www.plesk.com/blog/adding-custom-php-modules-in-plesk/>) | No: "available to the administrator only" (<https://docs.plesk.com/en-US/obsidian/administrator-guide/web-hosting/php-management.70668/>) |

With LiteSpeed (suEXEC, its default on control panels) and CloudLinux `mod_lsapi`, each PHP process
runs as the account's own user
(<https://docs.litespeedtech.com/lsws/extapp/php/configuration/modes/>); that is the case where a
per-account identity file, owned by that user, is possible.

### 4.4 Managed WordPress hosting and PaaS

Envelock needs two things from a platform: loading a custom compiled extension, and a private
identity file that meets §3.2. What each platform documents about the first (checked 2026-11-11;
none of them was tried here):

| Platform | Custom compiled extension? |
|---|---|
| WP Engine | **No**: server modules "cannot be modified, removed, or added" and `php.ini` is not editable (<https://wpengine.com/support/platform-settings/>). |
| Kinsta | A fixed list of modules (plus ionCube on request); for anything else, contact their support (<https://kinsta.com/docs/wordpress-hosting/php/wordpress-php-modules/>). |
| Google App Engine standard (PHP) | Only its documented list of extensions (<https://cloud.google.com/appengine/docs/standard/php-gen2/runtime>). |
| Heroku | Only through a "custom platform repository", which Heroku does not support (<https://github.com/heroku/heroku-buildpack-php/blob/main/support/build/README.md>). |
| Azure App Service (Linux) | **Yes**: the `.so` stored with the app in its persistent `site/wwwroot` folder, an `.ini` in a folder added to `PHP_INI_SCAN_DIR` (<https://learn.microsoft.com/azure/app-service/configure-language-php?pivots=platform-linux>). |
| Upsun / Platform.sh | **Yes**: a `.so` shipped with the app and loaded with `extension:` (<https://developer.upsun.com/docs/languages/php/extensions>). |
| AWS Lambda with Bref | **Yes**: as a custom Lambda layer (<https://bref.sh/docs/environment/php>). |

Where custom extensions are allowed, the second requirement is the one to test: on platforms that
unpack the application with fixed owners and permissions, or keep persistent files on a network
share, the identity file may not be able to be a `0600` file owned by the user that starts PHP, and
the loader then refuses it. Run the pre-flight check there (§1) before relying on it.

### 4.5 Windows hosting (IIS, Apache)

- IIS runs PHP through FastCGI with the **NTS** build → use the `-nts` DLL; source and bytecode
  packages both run.
- Apache with PHP as a module (WampServer, XAMPP, Apache Lounge) uses the **TS** build → `-ts`
  DLL, source packages only. Step by step: `docs/MANUAL.md` §11.
- The identity file's access list must name the account PHP runs as (for IIS, the application pool
  identity, `IIS AppPool\<pool>`), and nothing broader (§3.2).

## 5. Changes on the server that can stop a working site

| Change | Effect | What to do |
|---|---|---|
| PHP minor upgrade (8.3 → 8.4) | The old loader does not load in the new PHP. | Install the loader for the new version first; source packages run unchanged; repack `--bytecode` packages. |
| PHP patch update (8.4.27 → 8.4.28) | Source packages: nothing. `--bytecode` packages: refused (bound to the exact build). | Repack `--bytecode` packages for the new build. |
| Operating-system upgrade | Fine if the new system still meets §2.2 (newer glibc/OpenSSL 3 are fine). | Rebuild the loader if the system changed its OpenSSL major version. |
| Identity file replaced or edited | Ignored until PHP restarts. | Restart PHP. |
| The provider enables Xdebug, ionCube, SourceGuardian… for that PHP | Protected files refused (§3.4). | Turn them off for that PHP/account. |
| OPcache turned on in `php.ini`, or `file_cache`/`preload` set | Protected files refused (§3.3). | Set it up as in §3.3. |

## 6. Message for a hosting provider

> I need to run a PHP application protected with Envelock (an open-source encoder; its loader is a
> PHP extension, like ionCube Loader). Could you, for PHP <version> (NTS) on my account:
> 1. install the loader `envelock.so` that I will send you (or build it on the server from its
>    source with `phpize`; it needs PHP's development files and OpenSSL 3) and add to that PHP's
>    `php.ini`: `extension=<path>/envelock.so` and `envelock.identity=<path>/identity.bin`;
> 2. place the identity file I will send you at that path, owned by the user that starts PHP (root
>    for PHP-FPM) with mode 0600, and restart PHP;
> 3. for OPcache, either let me switch it off for my protected site (`.user.ini` or the pool's
>    `php_admin_flag[opcache.enable] = off`), or set `envelock.allow_opcache=1` with
>    `opcache.blacklist_filename` listing my protected folder;
> 4. make sure ionCube Loader, SourceGuardian and Xdebug are not loaded in that PHP.
>
> Requirements of the loader: PHP 8.2–8.5 on Linux x86-64 with glibc 2.28 or newer (no system
> OpenSSL needed; otherwise it can be built on the server), or on Windows x64 with the official PHP
> build. It can also be installed with PIE: `pie install envelock/loader`.

## 7. Known limitations

- **A customer cannot install it on shared hosting**: loading an extension and editing `php.ini` is
  the provider's job (§4.3). This is the main limit on where Envelock can run, and PIE does not
  change it.
- **Other encoders' loaders in the same PHP** (ionCube, SourceGuardian) make the loader refuse
  protected files, by design (§3.4).
- **Kubernetes secret volumes** need a `subPath` mount or an init container for the identity file
  (§4.2).
- **No prebuilt loader** for ARM64, musl (Alpine) or macOS: build it on the target (§2.3).

Loaders built before 2026-11-11 also refused protected files when OPcache was switched off per site
or when Debian/Ubuntu loaded Phar after them, and the prebuilt Linux ones needed glibc 2.38 and the
system's OpenSSL 3 (HOST-1, HOST-6, HOST-2 in `docs/AUDITORIA.md`). Use the current loaders.

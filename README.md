# Envelock

**Offline encoder and loader extension for PHP 8.2–8.5.**  
Version **1.0.0** · Python + C + OpenSSL 3 · Apache-2.0 license.  
Project page: **[miguelenred.es/envelock](https://miguelenred.es/envelock)** · Source: **[github.com/miguelenred/envelock](https://github.com/miguelenred/envelock)**

Distribute PHP projects without shipping their files in readable text. A **generic** extension (with no embedded keys) verifies each file's signature, unwraps the content key with the recipient's private key, decrypts in memory and hands the result to PHP's normal compiler. The private key and the trusted signer are read from an external identity file pointed to by `envelock.identity` in `php.ini`. A single host can serve several projects from different folders, each encrypted with different keys.

> **It is not a compiler to machine code nor an invulnerable system.** The server owner can instrument PHP or read the identity file and the source in memory during compilation. Confidentiality against root/Administrator is not guaranteed, nor is the absence of bugs. The design aims to prevent the public engine or another developer's keys from decrypting packages intended for others, subject to the cryptographic assumptions and correct implementation.

## Documentation

A window-based **assistant** (Spanish/English) wraps the whole flow for less technical users: `python gui/envelock_gui.py`, or build a standalone executable with `bash scripts/build-gui.sh` (see the [assistant guide](docs/ASSISTANT.md), which also gives the equivalent command for every button).

- **[Quick start: encrypt your PHP project, step by step](docs/QUICKSTART.md)**
- **[Full manual: how it works, usage and installation](docs/MANUAL.md)**
- [Assistant guide, tab by tab, with the equivalent commands](docs/ASSISTANT.md)
- **[Server requirements and hosting compatibility: dependencies, php.ini, what each kind of hosting allows, pre-flight check](docs/HOSTING.md)**
- [Building from source: loader, libraries and assistant executables](docs/BUILDING.md) · [Loader builders per platform](docs/PLATAFORMAS.md)
- [Prebuilt binaries](prebuilt/README.md) · [Third-party sources](third_party/README.md)
- [Security model and limits](docs/SEGURIDAD.md)
- [Binary format and cryptography](docs/FORMATO.md)
- [Reviews performed, findings and fixes](docs/AUDITORIA.md)
- [Results and verification matrix](docs/VERIFICACION.md)
- [Contributing](CONTRIBUTING.md) · [Reporting vulnerabilities](SECURITY.md) · [Changes](CHANGELOG.md)

## Delivery status

The code supports **8.2, 8.3, 8.4 and 8.5**, with different binaries per ABI, system, architecture and TS/NTS. See the verifiable matrix in `docs/VERIFICACION.md` and the manifest that accompanies the binaries.

**Prebuilt binaries depend on the distribution.** The **complete** distribution ships, under `prebuilt/` and all listed in [`prebuilt/SHA256SUMS`](prebuilt/SHA256SUMS): the loader for every supported engine and platform (Linux x86-64 PHP 8.2/8.3/8.4/8.5 NTS plus 8.4 ZTS, and Windows x64 PHP 8.2–8.5 in NTS and TS), the graphical assistant for Linux and Windows, a portable Python (Windows x64, Linux x86-64 and ARM64, macOS Apple silicon) and the offline wheel bundle. The **source-only** distribution ships none of these — build the loader for your ABI/platform as below. macOS and ARM64 need their own build and validation; a macOS distribution also needs signing and notarization ([how](docs/PLATAFORMAS.md#signing-quarantine-and-the-gatekeeper-exception)).

**Platform testing status (honest).** **Linux x86-64** and **Windows x64** are built and tested: Linux at run time across PHP 8.2–8.5 including ZTS, and the Windows x64 DLLs built and tested natively on Windows 11 with the official PHP for Windows builds. **macOS** (Apple silicon) and **Linux ARM64** are built and their test suites run **in CI** on GitHub's runners — macOS 15 for PHP 8.2–8.5, ARM64 for PHP 8.3/8.4 — but no prebuilt loader is shipped for them yet, and the authors have not run Envelock in production on a Mac: build the loader yourself and test it before relying on it. The macOS build, signing and notarization steps are in [docs/PLATAFORMAS.md](docs/PLATAFORMAS.md). Machine-bound licences are Linux-only (macOS and Windows report no machine identity). If you run Envelock on macOS — or anywhere — and hit a problem or a bug, please open an issue; we'll be glad to receive it and fix it.

The Envelock sources and the vendored `nikic/php-parser` are present, but the upstream source trees of Python, OpenSSL and the Python dependencies are **not** included. Install the Python dependencies using the hash-locked requirements below, or use the portable Python shipped under `prebuilt/python/` in the complete distribution. On POSIX, use `sh ./envelock` if your copy did not preserve the executable bit. See [prebuilt/README.md](prebuilt/README.md) and [BUILDING.md](docs/BUILDING.md).

The loader module is **generic**: the same binary (per ABI/OS/architecture/TS) serves any identity. What is not universal is the decryption capability: each server only opens the packages addressed to the keys in its identity file. That file and the private keys are kept **outside this repository**.

## Features

- No calls to external services during execution.
- Content key wrapping **per recipient** with X25519 + HKDF-SHA256 + AES-256-GCM: only the holder of the private key decrypts.
- AES-256-GCM for the source; Ed25519 signature verified **before** decrypting; signing private key only on the maker's machine.
- **Generic binary**: no embedded keys; the server's identity (private key + trusted signer) is configured separately via `php.ini`.
- Multiple identities per host: a single loader serves several projects encrypted with different keys.
- **Per-installation trust store**: trusted signers configured separately (never from the package), identified by `developer_id = SHA256(public key)`, with an optional **recovery key** to rotate without recompiling.
- v2 format with anti-downgrade: the v2 loader rejects the earlier v1 format.
- A new content key per `pack`; unique nonces by counter within each package.
- Packaging private keys encrypted with scrypt and AES-GCM **by default** (unencrypted only with an explicit `--no-encrypt`).
- OPcache coexistence: protected files refused by default when its SHM cache is on, with an explicit opt-in (`envelock.allow_opcache` + `opcache.blacklist_filename`); if the blacklist is missing or wrong the loader fails closed rather than cache decrypted opcodes. `file_cache`/preloading always refused. Tampered files and packages not addressed to the server's identity are rejected. `envelock.harden_memory` (on by default) locks the loaded keys into RAM and marks the process non-dumpable; set it to `0` to allow a profiler or core dump.
- Exclusion of common secrets and rejection of assets with visible PHP, dangerous backups and non-portable paths.
- At loader runtime, explicit source buffers are cleared after compiling and no temporary decrypted PHP files are written. Offline bytecode compilation separately uses temporary source files at the specified deploy path.
- Opt-in AST renaming for closed code can be restricted with a strict per-symbol allowlist; it is **not** suitable for frameworks or PSR-4/classmap applications. See [MANUAL.md §14](docs/MANUAL.md#14-frameworks-composer-and-assets).

## Quick start

On your packaging machine, install Python 3.10+ and the hash-locked dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
python encoder/envelock.py init-owner --out private/owner.enc.json --with-recovery
python encoder/envelock.py init-recipient --out private/cliente.enc.json --label cliente-001
python encoder/envelock.py export-public --recipient private/cliente.enc.json --out release/cliente-001.pub.json
python encoder/envelock.py new-project
```

Private keys are encrypted with a password by default (asked in the terminal, or read from the file named by `ENVELOCK_PASSWORD_FILE`). `init-recipient` creates the recipient's X25519 pair (private). `export-public` extracts its public key, which is all you need to package. Keep the project UUID. A valid packaging example (personal mode: the recipient is yourself):

```bash
python encoder/envelock.py pack \
  --owner private/owner.enc.json \
  --recipient release/cliente-001.pub.json \
  --project 752581f8-d239-44f6-a85e-49a892040ca8 \
  --source examples/project-a --output release/cliente-001/proyecto-a
```

Repeat `--recipient` to encrypt the same package for several recipients.

Create a new UUID for each distinct project. `pack` does not overwrite destinations nor accept nested source/destination trees. By default it encrypts `.php`, `.phtml`, `.inc` and `.php8`; other resources are only copied via `--asset`. The encoder does not transpile syntax: to run a single package on PHP 8.2, your application must be compatible with PHP 8.2.

The complete distribution includes prebuilt loaders (list in [prebuilt/README.md](prebuilt/README.md); what each needs from the server in [docs/HOSTING.md](docs/HOSTING.md)). `pie install envelock/loader` installs and enables the right one for the server's PHP, from the binaries attached to each [GitHub Release](https://github.com/miguelenred/envelock/releases) ([PIE](https://github.com/php/pie); see [docs/HOSTING.md](docs/HOSTING.md) §4.1). To build a matching loader yourself, on Linux/macOS, use development PHP, OpenSSL 3, autoconf, make and pkg-config:

```bash
# The module is generic: it carries no keys.
bash scripts/build-unix.sh release/envelock.so
# On each server, create its (secret) identity file and point to it from php.ini:
python encoder/envelock.py export-identity \
  --recipient private/cliente.enc.json --owner private/owner.enc.json --out private/identity.bin
php -n -d opcache.enable=0 -d opcache.enable_cli=0 \
  -d extension="$PWD/release/envelock.so" -d envelock.identity="$PWD/private/identity.bin" \
  release/cliente-001/proyecto-a/index.php
```

On Windows use `scripts/build-windows.ps1` in a native environment with the official PHP builder. The [platforms manual](docs/PLATAFORMAS.md) details the requirements, version selection and testing.

## Tests and review

```bash
python -m pytest -q tests
ENVELOCK_REQUIRE_NATIVE=1 python -m pytest -q tests
bash scripts/audit-native.sh /absolute/path/new-audit
```

Without `ENVELOCK_REQUIRE_NATIVE=1`, the native tests may be skipped if tools are missing. A result with skips does not demonstrate compatibility on that platform. The dependency analysis is limited to the versions and date of the report.

## CI and public repository

`.github/workflows/checks.yml` defines native builds of PHP 8.2–8.5 on Linux/macOS and Windows x64 NTS/TS. Its artifacts use **demonstration public keys**, reproducible from `scripts/demo_material.py`, and are marked `DEMO_ONLY`. **They are not fit to protect a product.** It runs on every push to the public repository, <https://github.com/miguelenred/envelock> (Linux x86-64 and ARM64, macOS, Windows NTS/TS, FPM, Laravel/Symfony, static PHP, fuzzing, lint); the results recorded for each release are in [TEST-STATUS.md](TEST-STATUS.md).

Do not publish `owner*.json`, `recipient*.json`, identity files `identity*.bin`, passwords, backups, `.pdb` or private sources. Compiled files are accepted only in `prebuilt/` and only when listed in `prebuilt/SHA256SUMS` (`scripts/check_release.py` enforces it). `.gitignore` helps, but does not replace reviewing the commit and the artifacts. To customize production loaders, use a private and trusted build environment.

## Pending scope

The code includes signed licence constraints (including expiry and a machine fingerprint) and a quarantined mini-VM restricted to unsafe laboratory research (not production), but there is no general online revocation or TPM/DPAPI sealing of the server identity. Real control-flow flattening and constant mixing remain unfinished; the AST name pass and strict allowlist do not prove a closed application boundary. See [ROADMAP-PROTECCION.md](ROADMAP-PROTECCION.md) for the remaining objectives and measured limitations.

Optional per-package protections include anti-rollback by serial, path binding, include protection, no-prepend, local-variable / private-method / private-property obfuscation, dead-branch flow obfuscation, string-literal encoding and a C-side string-literal vault, refusal of FFI/`dl()`, a sealed tree, refusal of debugging extensions, and runtime enforcement of a signed file manifest. Even so this is not a full deployment-integrity sandbox: without the signed manifest (enforced by default; opt out with `--no-manifest`) a file can be deleted or a whole package folder swapped, normal PHP is allowed alongside protected files, and none of these layers defeat the server administrator, who can read process memory. OPcache is refused for protected files unless the operator opts in and blacklists the protected tree (`envelock.allow_opcache`); preloading and `opcache.file_cache` are never allowed. PHAR, `__halt_compiler()` in the original source and code that reads its own file have no guaranteed compatibility.

**Before relying on it in production:** an independent review, native tests on each target, an FPM/Apache/ZTS evaluation, stress testing and validation with your real applications.

## Authorship

This project is directed by Miguel Sanchez and assisted by artificial intelligence. The concept, architecture, functional and technical specification, design decisions, priorities, acceptance criteria and review are the author's. The implementation — the source code, the test suites, the benchmarks and the documentation — is produced with the help of several AI models, working from that specification and under the author's direction, and reviewed by him before being kept.

Every design decision and every trade-off was made by a human. No line ships without his review. See [AUTHORS](AUTHORS) and [NOTICE](NOTICE).

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 Miguel Sanchez.

You may use, modify and redistribute this project for any purpose, personal, professional or commercial. The license requires you to keep the copyright notice, to reproduce the contents of the `NOTICE` file in any redistribution, and to state any changes you make to the source files.

Beyond that, and not as a legal condition: if this project is useful to you, a visible credit and a link back to the original repository is appreciated. Something as simple as "powered by Envelock" with a link is enough.

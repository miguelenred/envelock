# Complete Envelock 1.0.0 manual

## Table of contents

1. [What it protects and what it does not](#1-what-it-protects-and-what-it-does-not)
2. [Architecture and identities](#2-architecture-and-identities)
3. [Requirements and versions](#3-requirements-and-versions)
4. [Install the encoder](#4-install-the-encoder)
5. [Safeguarding keys and passwords](#5-safeguarding-keys-and-passwords)
6. [Create owner and recipients](#6-create-owner-and-recipients)
7. [Create and encrypt projects](#7-create-and-encrypt-projects)
8. [Build loaders](#8-build-loaders)
9. [Use this release's binaries](#9-use-the-generic-binaries)
10. [Install on Linux](#10-install-on-linux)
11. [Install on Windows](#11-install-on-windows)
12. [Install on macOS](#12-install-on-macos)
13. [Multiple projects and clients](#13-multiple-projects-and-clients)
14. [Frameworks, Composer and assets](#14-frameworks-composer-and-assets)
15. [Updating and rotating keys](#15-updating-and-rotating-keys)
16. [Diagnostics and errors](#16-diagnostics-and-errors)
17. [Testing and auditing](#17-testing-and-auditing)
18. [Publish the repository and generate artifacts](#18-publish-the-repository-and-generate-artifacts)
19. [Production checklist](#19-production-checklist)
20. [Frequently asked questions](#20-frequently-asked-questions)

## 1. What it protects and what it does not

The goal is that the client never receives your PHP files in readable text. On disk they receive encrypted containers. When these are executed, a native loader checks their signature, recovers the project key, authenticates the content, and compiles it in memory.

The system does not automatically convert PHP to C, assembly, or Zend-independent opcodes. Nor does it prevent an administrator from modifying PHP, debugging the process, or capturing the source after decryption. The loader is generic and contains no keys, but the recipient's private key lives in the server's identity file, and whoever reads it can decrypt. There is no absolute security against the owner of the machine. What is guaranteed: without that private key (having only the public engine or someone else's keys) the packages cannot be decrypted.

The protection does prevent direct reading of the source in the distributed files and can be an additional barrier for users without control of the environment. If another person must not even access the loader or the files, you must also restrict permissions and separate processes. Encryption is not a substitute for isolation.

## 2. Architecture and identities

```text
OWNER'S PRIVATE MACHINE                        CLIENT'S SERVER

Signing identity (Ed25519)                     PHP 8.2–8.5 + GENERIC loader
  private key: do NOT distribute               identity file (secret):
  public key -> identity file                    x25519_priv + trusted signer
        |                                             |
Recipient (X25519)                                    v
  private key -> identity file                 verify signature (Ed25519)
  public key -> for packaging                  locate the matching entry
        |                                      X25519 + HKDF -> content key
        v                                      authenticate and decrypt source
Encoder + original code                        compile and execute
        |
        v
Encrypted and signed files ------------------> application installation
```

**Owner:** Ed25519 identity that signs the packages. It can serve several clients. Its private key is never distributed.

**Recipient:** an X25519 pair. Its **public** key is used to package; its **private** key lives in the identity file of the server that receives it. It is a logical identity, not a lock to a specific computer. "Personal mode" = encrypting for your own key.

**Server identity:** a binary file (secret) that combines the X25519 private key of one or more recipients with the trusted signers. It is pointed to by `envelock.identity` in `php.ini`. A host can have several identities and thus serve several projects with different keys.

**Project:** a stable UUID for a specific application. It is not derived from its folder. You can rename or move the folder without changing its identity.

**Release:** a new UUID and a new content key for each run of `pack`. All PHP files selected in that run share that key, but use different per-file nonces.

**File:** a security stub, an authenticated header, encrypted source, a GCM tag, and an Ed25519 signature. It is self-sufficient for locating its IDs and its wrapped key. It needs neither an external service nor an additional license file.

## 3. Requirements and versions

### Owner's machine

- Python 3.10+ and the hash-locked packages from `requirements.lock` (section 4). This checkout does not include portable Python or offline wheel bundles.
- To build: tools and headers of the target PHP, a C compiler, and OpenSSL 3.x.
- A trusted original source and input tree, with no concurrent modifications.
- A private working folder and destination parent, not shared with hostile users.

### Client's server

- PHP 8.2, 8.3, 8.4, or 8.5 with a loader of the same ABI, architecture, and TS/NTS.
- The binary's native dependencies: on Windows only what the official PHP build already ships (`libcrypto-3-x64.dll` and the Visual C++ runtime); on Linux only glibc 2.28 or newer for the prebuilt loaders (OpenSSL is linked into them); a loader you build yourself uses the system's OpenSSL 3. Exact list, per-system table and install commands: [HOSTING.md](HOSTING.md) §2.
- Permission to load PHP extensions and to edit the `php.ini` read at startup. A shared-hosting customer cannot do either: the provider has to ([HOSTING.md](HOSTING.md) §4.3).
- OPcache: off (in `php.ini`, or just for the protected site per directory, vhost or FPM pool — loaders built from 2026-11-11 on accept that; earlier ones refused it), or on with the opt-in (`envelock.allow_opcache=1` + `opcache.blacklist_filename` on the protected tree). Preloading and `opcache.file_cache` off. No ionCube Loader or SourceGuardian in the same PHP ([HOSTING.md](HOSTING.md) §3.3–3.4).
- To check a server before installing anything: `scripts/envelock-preflight.php` ([HOSTING.md](HOSTING.md) §1).
- Latency and deployment choices (per-request vs resident-worker, with the security trade of each, measured): [RENDIMIENTO.md](RENDIMIENTO.md). Security prevails over speed; a resident-worker SAPI is the fastest but keeps the decrypted program resident.
- It needs neither Python nor the Internet to run the packages.

**There is no single binary for the four versions or the three systems.** Each minor version changes PHP's ABI. The encrypted format is common; the original application must also be compatible with the chosen PHP. Using PHP 8.5 features does not make them compatible with 8.2.

Check the actual status, without assuming that all combinations have been tested: [VERIFICACION.md](VERIFICACION.md).

## 4. Install the encoder

Download or clone the repository and work from its root.

The `envelock` / `envelock.cmd` launchers use the portable interpreter in `prebuilt/python/`, **shipped in the complete distribution** (the source-only distribution does not include it, and the launcher then exits with instructions). On POSIX, if your copy did not preserve the executable bit, invoke it as `sh ./envelock` or restore the bit with `chmod +x envelock`. Use your own Python as follows.

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
python encoder/envelock.py --help
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --require-hashes -r requirements.lock
python encoder\envelock.py --help
```

**Offline installation:** the complete distribution ships Python wheels under `prebuilt/python-wheels/`; the source-only distribution does not, nor the upstream sources of those dependencies. Supply a separately obtained, hash-verified wheelhouse for the target platform, or install from a trusted index using the lock above. See [BUILDING.md](BUILDING.md).

If your PowerShell policy prevents activating the environment, run `.venv\Scripts\python.exe` directly; there is no need to weaken the execution policy globally.

The direct dependencies are pinned. `requirements.lock` (runtime) and `requirements-dev.lock` (tests and analysis tools) pin every dependency with hashes and are resolved universally (Linux, macOS and Windows; Python 3.10+), so the recommended install is `python -m pip install --require-hashes -r requirements.lock` on any platform. CI installs this way. Regenerate them with `uv pip compile --universal --python-version 3.10 --generate-hashes`.

The packages are downloaded during installation/build. Running the encrypted software remains offline. For isolated build environments, prepare and verify a wheelhouse and native dependencies in advance.

### Graphical assistant (optional)

For a less technical user there is a window-based assistant that does everything the `pack`/key commands do, in Spanish or English, without the console. It reuses the encoder, so it has no logic of its own.

- **Run from source:** `python gui/envelock_gui.py` (needs the same `cryptography` as the encoder, plus Tkinter, which the official python.org installers bundle on Windows and macOS; on Linux install `python3-tk`).
- **Standalone executable (nothing to install):** `bash scripts/build-gui.sh` builds one self-contained window executable for the current OS into `dist/`. PyInstaller does not cross-compile: build the Linux executable on Linux, the macOS one on macOS, and the Windows one on Windows — or, from Linux, under Wine with a Windows Python that includes Tkinter:

  ```bash
  # one-off: a Windows CPython with Tcl/Tk and the build tools, inside a Wine prefix
  export WINEPREFIX=~/.envelock-wine
  wine python.exe -m pip install pyinstaller cryptography
  # build the .exe (a pseudo-terminal avoids a Wine stdio quirk):
  script -qefc "wine python.exe -m PyInstaller --clean --distpath dist/win gui/envelock-assistant.spec" /dev/null
  # self-test the result without a real screen:
  xvfb-run script -qefc "wine dist/win/envelock-assistant.exe --selftest" /dev/null
  ```

  The executable bundles Python and `cryptography`, so the end user installs nothing. The assistant has tabs for the whole flow: **Encrypt a project**, **Recommend** (suggests protection options for a project), **Keys**, **Server identity**, **Key rotation** and **Inspect**.

  *Remove comments* and *Obfuscate local variables* run your own PHP 8 CLI (they use PHP's tokenizer so the code is never misparsed). The assistant runs only a PHP it downloaded itself or one found through the absolute folders in `PATH` (never one in the current folder) and fills the *PHP 8* field; PHP installs in the usual folders (WampServer, XAMPP, Laragon, `C:\php`, Homebrew, `/usr/bin`) are only *listed* for you to pick with *Browse*, because folders such as `C:\php*` can be created by any local user. It checks that PHP before starting and says what is wrong (not found, older than 8, no `tokenizer`). If there is no usable PHP, on Windows it offers to download the official PHP 8 from php.net into a `php` folder next to the assistant — over HTTPS only (a redirect away from HTTPS is refused), with its SHA-256 checked against the same official index, which proves the download is complete and unaltered but is not a signature — and to install Microsoft's Visual C++ runtime if PHP needs it (only if Microsoft's signature is valid); on Linux/macOS it shows the install command. You can also choose a `php.exe` with *Browse*, or untick those two options.

  **Step-by-step guide for every tab, with the exact equivalent command for each button: [ASSISTANT.md](ASSISTANT.md).**

## 5. Safeguarding keys and passwords

Private configurations (`init-owner`, `init-recipient`, `keygen`, `owner promote-recovery`, and `owner new-recovery` on a file that was not encrypted) are **encrypted by default** with a password, asked twice in the terminal or read from `ENVELOCK_PASSWORD_FILE`. Without a terminal and without that variable the command refuses and writes nothing. Use a long random password, not a predictable phrase. A minimum of 16 bytes is required, which by itself does not prove sufficient entropy.

The private format uses scrypt with fixed parameters `N=131072, r=8, p=1`, a random salt, and AES-256-GCM. The derivation requires memory; reserve approximately 128 MiB plus overhead per concurrent operation.

When opening an encrypted file, the password is requested in the terminal. To automate without putting it in process arguments:

```bash
# Create this file with a secrets manager or a secure editor, not with a real password in the history.
chmod 600 /path/private/password.txt
export ENVELOCK_PASSWORD_FILE=/path/private/password.txt
```

PowerShell:

```powershell
$env:ENVELOCK_PASSWORD_FILE = 'C:\private\password.txt'
```

The variable contains a **path**, not the password. On Windows, restrict its ACL to the user who builds: the encoder checks it and refuses a file that any other account or group can read (only you, the file's owner, SYSTEM, Administrators and OWNER RIGHTS are accepted). Do not use symbolic links for the configurations or the password file.

Do not store the password alongside the encrypted files in a repository or an unprotected backup. Encrypting both and also publishing the password defeats that defense. Keep encrypted backups offline and verify that they restore.

With `--no-encrypt` (explicit, and it prints a warning) the JSON files contain readable secrets and are created with Unix mode `0600`; it exists for throw-away test material, not for real keys. The encoder cannot guarantee the erasure of all of its Python objects from memory. Use a trusted machine, an encrypted disk, and appropriate swap/dump policies.

## 6. Create owner and recipients

Once per owner:

```bash
python encoder/envelock.py init-owner --out private/owner.enc.json --with-recovery
```

`--with-recovery` additionally generates a **recovery key** (a second Ed25519 signer). It is optional but recommended: if the primary signer is compromised, `owner promote-recovery` turns it into the primary and packages signed with it already run on every server, without recompiling the loader or touching the servers first (section 15). `developer_id = SHA256(primary public key)` identifies this owner in the trust store. Guard the recovery key with the same care as the primary one, ideally offline: `owner split-recovery --owner private/owner.enc.json --out recovery.enc.json` moves the recovery private key into its own file under its own password (the owner file keeps only the recovery *public* key, so every `pack` stops decrypting it), and `owner promote-recovery --recovery recovery.enc.json` uses it when the time comes. (The graphical assistant's recovery promotion still expects a combined owner file.)

Once per recipient/client (a private X25519 pair):

```bash
python encoder/envelock.py init-recipient \
  --out private/cliente-001.enc.json --label cliente-001
python encoder/envelock.py export-public \
  --recipient private/cliente-001.enc.json --out release/cliente-001.pub.json
```

`export-public` extracts the recipient's public key: it is all the owner needs in order to package. Existing key files are not overwritten. Reading validates the types, lengths, and the consistency of each pair. If you lose the signing identity or a recipient's private key there is no recovery by reverse-engineering the binary (the binary is generic and does not contain them).

The **server identity file** combines the recipient's private key with the trusted signer. It is secret, created once per server, and is never distributed or committed:

```bash
python encoder/envelock.py export-identity \
  --recipient private/cliente-001.enc.json --owner private/owner.enc.json \
  --out /private/folder/identity.bin
```

It is consumed by the loader via `envelock.identity` (see sections 10–12). Keep it owned by the user that **starts** PHP, mode `0600` — or `root:root` mode `0400`, which is what `server-install` leaves and the stronger of the two for a preforked server: root for PHP-FPM (the master reads it at startup) and Apache, or the user that runs a CLI script. Not the pool/worker user: the loader would refuse it, and with root ownership the workers cannot read the private keys at all (section 10). On Windows, restrict its ACL (section 11). If the owner has a recovery key, `export-identity` includes it in the trust store, so that a package signed by the recovery key also verifies. On a server, prefer **`server-install`** over copying the file by hand: it writes it as `root:root` mode `0400` and verifies that afterwards rather than assuming it (objective O5). On Windows it creates the file read-only with a protected ACL (SYSTEM, Administrators and the account running the command, nothing inherited) set at creation time and verified from the open file; then grant read to the PHP service account and remove your own entry if PHP runs as another account (section 11). `--owner-user` is POSIX-only.

```
sudo python encoder/envelock.py server-install \
  --recipient recipient.json --owner owner.json \
  --out /etc/envelock/identity.bin
```

  - It **requires root** and refuses otherwise instead of writing a file that only looks installed: a `0400` file owned by whoever ran the command is still readable by that user and by anything sharing the account, which is the exposure this exists to remove.
  - It **refuses to overwrite** an existing file. An identity file decides which projects a host can serve and which developers it trusts; replacing one by accident is not a mistake to make silently. Remove it first if you really mean to replace it.
  - `--recipient` repeats, for a host serving several projects from one identity file.
  - The result is verified by `stat` before the command reports success, and removed if the ownership or the permissions did not take (a `umask`, or a filesystem that ignores mode bits, would otherwise pass silently).
  - Point `envelock.identity` at it in the **shared** `php.ini`, not in a pool: the master reads it at startup, before it applies pool configuration. The file can contain **several recipients and several trusted developers** (a per-installation trust store); trust is global: the host opens any package addressed to one of its keys and signed by any trusted developer.

To build that trust store incrementally (adding projects to a host without regenerating it entirely), use `recipient add`, which creates or extends the identity file atomically:

```bash
python encoder/envelock.py recipient add \
  --identity /private/folder/identity.bin \
  --recipient private/cliente-002.enc.json --owner private/owner.enc.json
```

`keygen owner` and `keygen recipient` are aliases of `init-owner`/`init-recipient` (accepting `--with-recovery` and `--label` respectively). To review what an artifact contains **without exposing secrets**, use `inspect`:

```bash
python encoder/envelock.py inspect release/cliente-001/proyecto-a/index.php   # package: ids, number and public keys of recipients, size
python encoder/envelock.py inspect /private/folder/identity.bin              # trust store: recipients, developer_id, whether there is recovery
python encoder/envelock.py inspect private/owner.enc.json                    # config: public key and developer_id; never the private one
```

## 7. Create and encrypt projects

Generate the ID:

```bash
python encoder/envelock.py new-project
```

Save the UUID that is emitted. To test the example you can use `752581f8-d239-44f6-a85e-49a892040ca8`:

```bash
python encoder/envelock.py pack \
  --owner private/owner.enc.json --recipient release/cliente-001.pub.json \
  --project 752581f8-d239-44f6-a85e-49a892040ca8 \
  --source examples/project-a --output release/cliente-001/proyecto-a
```

Options for `pack`:

| Option | Meaning |
|---|---|
| `--owner` | Private signing identity |
| `--recipient` | A recipient's **public** key (`.pub.json`) or your own private `recipient.json` (its public part is derived); repeatable. Encrypts the package for each one. An encrypted recipient must be exported to a public key first |
| `--project` | The project's stable UUID |
| `--source` | Trusted original tree |
| `--output` | A new folder, outside the source tree and with no reverse nesting |
| `--asset` | File pattern to be copied unencrypted; repeatable. `/` or `\` as separator; case-insensitive on Windows |
| `--exclude` | Relative-path pattern to exclude; repeatable. A folder that matches is excluded with everything inside it (and never walked into); `/` or `\` as separator; case-insensitive on Windows |
| `--php-ext` | An additional extension to be treated as PHP, for example `.module` |
| `--strip-comments` | Remove comments and docblocks before encrypting (less memory per request; see below). Needs a PHP 8+ CLI with the `tokenizer` extension |
| `--obfuscate` | Give local variables short names before encrypting (section 14). Same PHP CLI requirement |
| `--compact` | Collapse whitespace and remove comments before encrypting (one space between tokens; **line numbers are not preserved**). Same PHP CLI requirement. Combine with `--obfuscate`/`--strip-comments` |
| `--encode-strings` | Re-spell string literals as `\xNN` byte escapes before encrypting (same value; hides SQL, messages and paths). Interpolated and heredoc/nowdoc strings are left as is. Same PHP CLI requirement |
| `--obfuscate-methods` | Rename **private** methods that are only called via `$this->`/`self::`/`static::`. Skipped for any method whose name is used dynamically, as a string, or on another object (see section 14). Same PHP CLI requirement. **Test the package.** |
| `--obfuscate-properties` | **HIGH RISK.** Rename **private instance** properties used only as `$this->name`. Breaks objects serialized before obfuscation (`serialize`, sessions, caches). Classes that serialize, use magic `__get`/`__set`, `get_object_vars` or Reflection, or where the name is used elsewhere, are left alone. Same PHP CLI requirement. **Test the package.** |
| `--obfuscate-flow` | Insert an always-false opaque-predicate dead branch at the start of each function/method. Behaviour and line numbers are unchanged; functions using `goto` are skipped. A modest layer (not control-flow flattening). Same PHP CLI requirement. **Test the package.** |
| `--obfuscate-flatten` | Rewrites each named function/method body whose statements are plain code into a dispatch loop (`while(true){switch($__envlk_st){case 0: ...}}`). Statement text and line numbers are kept. Generators, `goto`, nested declarations, `include`/`eval`, dynamic variables, `compact`/`extract`/`get_defined_vars`/`parse_str` and `declare` are left as written and counted in the pack report. Not combinable with `--virtualize`. Same PHP CLI requirement. **Test the package.** |
| `--obfuscate-names` | Opt-in renaming of eligible global classes, interfaces, traits, enums and functions in a **closed** package. External references or dynamic lookup can break. Namespaced packages are declined unless the separate experimental AST option is also given. Never enable it for framework code. **Test the complete package.** (section 14) |
| `--obfuscate-names-ast` | **Experimental, additional opt-in**, requires `--obfuscate-names`. Enables AST-based renaming for a closed namespaced package; **not for frameworks, PSR-4/classmap autoloaders, reflection or externally referenced names**. Heuristics cannot prove safety. (section 14) |
| `--obfuscate-names-allow KIND:FQN` | Optional **strict allowlist** for the experimental AST pass; repeat for each `type:FQN` or `function:FQN`. Requires both name flags. Only listed declarations are renamed; an unknown, unsafe or unrewritable entry aborts the pack. This does not prove the application is closed (section 14). |
| `--vault-strings` | Move string literals that sit in a runtime position into a per-file vault the loader resolves (`\__envelock_lit(idx)`), so they are not kept as constants in the compiled code (hides SQL, messages, paths from a dump of the loaded code). Since O7 the vault table is **encrypted at rest** inside the container and each literal is decrypted only when read. Literals in constant expressions stay inline. Adds about one call per vaulted-literal access. Same PHP CLI requirement. **Test the package.** (section 14) |
| `--bytecode` | Ship each file as **precompiled bytecode** instead of encrypted source: the server never compiles PHP for it, so there is no decrypted source in memory to intercept (section 14). Needs the target server's exact PHP build with the Envelock loader, and `--deploy-root`. Incompatible with `--vault-strings`. **Test the package.** |
| `--deploy-root` | Absolute path the package will be deployed at. **Required with `--bytecode`**: `__DIR__`, `__FILE__` and resolved `include` paths are baked into the bytecode, so the sources are compiled there (and removed again), and the package then only runs from that path |
| `--bytecode-php` | PHP CLI used to compile the bytecode (default: `--php`). It **must** be the same version and build as the PHP that will run the package |
| `--bytecode-loader` | Path of the Envelock loader module to load into that PHP CLI, when its configuration does not already enable it |
| `--manifest` | Write a signed `envelock-manifest` of the whole tree (every file's SHA-256). Check it later with `verify` to detect a deleted, added, modified or swapped file |
| `--php` | PHP CLI used by the source transformations, including `--obfuscate-names` and its AST/allowlist options (default `php`). A bare name is looked up only in the absolute folders of `PATH` — never the current folder, where a project being packed could plant a `php.exe`. `--bytecode` uses `--bytecode-php`, or this one when that is not given |
| `--include-protection` | Protected files run only as the entry point or when loaded from protected code of the same project (section 14) |
| `--no-prepend` | Refuse to run when `auto_prepend_file` or `auto_append_file` is set (section 14) |
| `--no-ffi` | Refuse to run while FFI or `dl()` is reachable; they can read the decrypted code from process memory (section 14) |
| `--sealed` | Sealed tree: refuse any plain (unencrypted) PHP under the package folder and refuse `eval()` while the package is active (section 14) |
| `--enforce-manifest` / `--no-manifest` | The signed binary runtime manifest is written **by default** (deletion detection at load, and the ~5× `manifest_fastpath`, section 14). `--enforce-manifest` is the explicit form; `--no-manifest` opts out |
| `--serial` | Release number, checked against the server's minimum (default: the current time in **nanoseconds** since the Unix epoch, so later packs are higher; section 15) |
| `--allow-demo` | Permit the PUBLIC demo keys (testing only). By default `pack` refuses them, because their private halves are published, so a package made with them protects nothing |

By default `.php`, `.phtml`, `.inc`, and `.php8` are encrypted, case-insensitively. No other files are copied except authorized assets. A PHP file takes priority over an asset pattern: it is not copied in the clear just because of `--asset '*'`.

Example with assets:

```bash
python encoder/envelock.py pack \
  --owner private/owner.enc.json --recipient release/cliente-001.pub.json \
  --project 752581f8-d239-44f6-a85e-49a892040ca8 \
  --source /path/application --output release/client-001/application \
  --asset '*.css' --asset '*.js' --asset '*.png' --asset '*.woff2' \
  --exclude 'tests/*' --exclude 'debug/*'
```

The patterns apply to the full relative path, with `/`, and are case-sensitive. `*` can cross `/`. Always inspect the package; do not use broad patterns over a tree mixed with secrets.

Assets with `<?php`/`<?=` tags, dangerous backups, known key files, and renamed Envelock descriptors are rejected. This is a conservative defense, not a universal detector of sensitive information. Twig, SQL, JavaScript, templates, and business data do not become private by being copied as assets.

`.env*`, repositories, credential files (`.npmrc`, `.netrc`/`_netrc`, `.git-credentials`, `.pgpass`, `.docker/`) and other dangerous directories are excluded case-insensitively, and an asset whose content looks like a credential (tokens, `"auth":` keys, `user:password@` URLs, private keys) is refused. Real environment configurations are provisioned separately. Symbolic links, special files, reserved Windows paths, and case/Unicode-normalization collisions are rejected.

Limits: 16 MiB of source per file and 64 MiB per asset. Reads are bounded and size/mtime changes during reading are detected. That does not create a safe snapshot of a hostile tree: work with a trusted, immovable copy.

Each protected file carries its relative path inside the package (signed): the loader only runs it from a location ending in that path, so files cannot be renamed or swapped inside a package, while the whole package can be moved. On Windows and macOS the comparison ignores ASCII letter case, like their file systems. In one request, all protected files under the same package folder must come from the same project and release: a file copied in from another release is refused.

The destination is reserved exclusively. **Its publication is not an atomic transaction of the deployment:** during the move a partial tree may exist, and an abrupt shutdown can leave it incomplete. Package outside the served directory and deploy only after success and review. `envelock-package.json` is diagnostic information, not a license or a signed global manifest.

## 8. Build loaders

See [PLATAFORMAS.md](PLATAFORMAS.md) and, for everything else that can be compiled (OpenSSL, cryptography, the assistant executables), [BUILDING.md](BUILDING.md). To summarize these rules:

1. The module is **generic**: it embeds no keys. The same binary serves any identity; the keys go in the server identity file.
2. Build each PHP minor, OS, CPU, and TS/NTS separately.
3. Do not mix the `php`, `phpize`, and `php-config` of different versions.
4. Do not copy build objects into the final package.
5. Test loading on the exact runtime and on a clean machine.

The Unix builder lets you select tools via `PHP`, `PHPIZE`, and `PHP_CONFIG`; keep the virtual environment's Python:

```bash
PHP=/path/php-8.5/bin/php \
PHPIZE=/path/php-8.5/bin/phpize \
PHP_CONFIG=/path/php-8.5/bin/php-config \
bash scripts/build-unix.sh release/linux-php85/envelock.so
```

The resulting module carries no keys. On each server, create its identity file with `export-identity` (section 6) and point to it with `envelock.identity`.

The extension has a guard that rejects versions earlier than 8.2 or later than 8.5. Simply removing it is not enough to support another version: you must review Zend and run the tests.
### 8.1 Static single-binary distribution (objective O10)

For an appliance there is no directory of modules to install into: everything ships as one
executable. A statically linked PHP has **no dynamic loader at all** — `phpinfo()` on a static
FrankenPHP build shows no "Dynamic Library Support" row — so `envelock.so` cannot be loaded into
one. The loader has to be **compiled into the engine**.

```bash
bash scripts/build-static-php.sh php-8.4.27.tar.gz release/php-static
ENVELOCK_STATIC_PHP=release/php-static pytest -k o10
```

The script builds a PHP with the extension linked in and checks the result by asking it, with no
`-d extension=` anywhere, whether `envelock` is loaded. Producing the final FrankenPHP binary on
top of that additionally needs Go and FrankenPHP's own static toolchain, which rebuilds PHP with
your extensions through `static-php-cli`; the step above is the Envelock half of it.

Because the script copies the whole `extension/` tree into `ext/envelock`, the static build picks
up the per-version bytecode layer automatically: `config.m4` selects `opcache/php<MM>/` for the PHP
being compiled, so an appliance built on 8.2, 8.3, 8.4 or 8.5 ships the matching bytecode layer with
no extra step (a version without a layer builds a source-only loader). A git checkout rather than a
release tarball also needs `bison` and `re2c` for `./buildconf`.

Three defects only show up in this build shape, and all three were found by building it rather than
by reading the code:

- **`php_envelock.h` did not exist.** When an extension is built in, PHP generates a table of
  built-in extensions that references `phpext_envelock_ptr`, and emits the matching `#include` only
  for extensions that ship a `php_<name>.h`. Without the header the build dies with
  `'phpext_envelock_ptr' undeclared`. A module never notices: its entry point is `get_module()`
  inside one translation unit and nothing else names the module entry.
- **`config.m4` asked pkg-config for `libcrypto` only.** `envelock_trusted_time.c` speaks TLS,
  which lives in `libssl`. A module gets away with it because a shared object may leave symbols
  undefined and the dynamic linker resolves them from the host process at load time — a real but
  invisible dependency that breaks the moment the SAPI does not happen to have `libssl` loaded. The
  shared module now declares both.
- **`config.m4` read the PHP version from `php-config`,** which does not exist yet inside a PHP
  source tree, so the version came out empty and the bytecode-layer check failed with
  `no bytecode layer for PHP .` It now falls back to the version `configure` itself computed. It
  also locates its own sources by trying the candidates, because inside a PHP tree `$srcdir` is the
  PHP root, not the extension directory, and `$ext_srcdir` is not assigned until after the check.

None of this changes how a normal deployment works: `build-unix.sh` still produces the module, and
the module is still what you want unless you are shipping an appliance.

## 9. Use the generic binaries

The loader module is **generic**: the same `envelock.so`/`.dll` (per ABI/OS/architecture/TS) serves any identity. The keys are not in the binary, but in the server identity file.

The complete distribution ships prebuilt loaders for every supported engine and platform — Linux x86-64 PHP 8.2/8.3/8.4/8.5 NTS and 8.4 ZTS, and Windows x64 PHP 8.2–8.5 in NTS and TS — under `prebuilt/loader/`; see [`prebuilt/README.md`](../prebuilt/README.md). The source-only distribution ships none of them. Check the recorded hashes with `cd prebuilt && sha256sum -c SHA256SUMS`. macOS and ARM64 require separately built and tested loaders; for macOS see [PLATAFORMAS.md](PLATAFORMAS.md), including signing and the Gatekeeper exception.

Once a release is published, the loader can also be installed with PIE, which picks the right file for the server's PHP and enables it: `pie install envelock/loader` ([HOSTING.md](HOSTING.md) §4.1; publishing: [BUILDING.md](BUILDING.md) §8). The identity file and its `php.ini` line stay manual.

To deploy:

1. Keep your private identities (`owner`, `recipient`) and the password outside the repository and the server.
2. Create the server identity file with `export-identity` and copy it to the server with `0600` permissions (section 6).
3. Choose the `envelock.so` for the correct PHP version and thread safety (`php -i | grep "PHP Extension Build"`, e.g. `prebuilt/loader/linux-x86_64/php-8.4-nts/envelock.so`); the same binary works for all your clients on that version.
4. Configure `extension` and `envelock.identity` in the `php.ini` of the actual SAPI.
5. Install and test the package following the next section.

If you change the recipient or the signer, update the identity file (`recipient add/remove`, `developer set/remove`) and **restart PHP**: the loader reads it only at startup. There is no need to recompile the module.

The workflow artifacts carry the `DEMO_ONLY` label, with known keys reproducible from code. They serve to validate the build, **not to distribute protected software**.

## 10. Install on Linux

Inspect your runtime and effective configuration:

```bash
php -v
php --ini
php -i | grep -E 'PHP API|Thread Safety|extension_dir'
```

For the CLI, test before modifying `php.ini`:

```bash
php -n -d opcache.enable=0 -d opcache.enable_cli=0 \
  -d extension=/path/private/envelock.so \
  -d envelock.identity=/path/private/identity.bin /path/proyecto-a/index.php
```

`-n` skips the usual configuration: your real application may need other extensions. For production, use its configuration and configure explicitly:

```ini
extension=/path/private/envelock.so
envelock.identity=/path/private/identity.bin
opcache.enable=0
opcache.enable_cli=0
opcache.file_cache_only=0
; opcache.preload must be empty/unset
```

`envelock.identity` is `PHP_INI_SYSTEM` (it is set only in `php.ini`/the command line, not from the script), like `envelock.allow_opcache` and `envelock.allow_debuggers` (default `0`) and `envelock.harden_memory` (default `1`) and `envelock.secret_memory` (default `0`; both in section 14) and `envelock.manifest_fastpath` (default `1`). For `--enforce-manifest` packages it is **on by default, but only when the identity file trusts a single developer**: that package's signed manifest is already verified on every request for enforcement, and letting its one signature stand in for every file's own signature on first load cuts first-request latency about 5× (measured ~127 → ~24 µs/file). With two or more trusted developers it is always off: a manifest only proves that its signer *hashed* the listed bytes, not that they signed them, so one trusted developer could otherwise list another developer's file (or one signed by an untrusted key) and have it run as their own (audit of 2026-11-10, Pass 32 in [AUDITORIA.md](AUDITORIA.md)). The digests are seeded only after the whole manifest has validated. It is fail-closed (altered bytes have a different SHA-256, miss the seeded set and take the full per-file verify, which then fails). Set `envelock.manifest_fastpath=0` to force the per-file verify even under `--enforce-manifest`; it has no effect on packages without a manifest. See [RENDIMIENTO.md](RENDIMIENTO.md). Because it is `PHP_INI_SYSTEM` and read once at startup, a per-pool `php_admin_value[envelock.identity]` in a PHP-FPM pool is **ignored** (the master reads the directive before it applies pool configuration). To serve projects with different identity files, use one identity file with several entries (section 13) in the shared `php.ini`, or run separate FPM master processes each with its own `php.ini`. The file must be owned by the user that **starts** PHP, mode `0600`: root for PHP-FPM (the master reads it at startup) and Apache, or the user that runs a CLI script. Not the pool/worker user: the loader would refuse it, and with root ownership the workers cannot read the private keys at all. On POSIX the loader rejects it if it has any group/other permission bit or a different owner. The loader reads it once, when PHP starts: **after any change, restart PHP** (php-fpm, Apache) for it to take effect.

CLI, FPM, and Apache may read different `.ini` files. Locate the one corresponding to the actual SAPI. Restart its service after installing or changing the binary. The service name depends on your distribution and version, for example `php8.4-fpm`; do not blindly restart unrelated services.

Install the loader outside the document root, owned by the administrator and readable only by the necessary users/groups. The service PHP needs to read it. An indicative example: `root:service-group`, file `0640`, directories traversable by that group. Do not use `chmod 777`. The protected PHP files must also have appropriate minimal permissions.

The web server must send `.php` to PHP and not serve sources, backups, or repositories as static files. A minimal `public/` is preferable to publishing the entire application.

## 11. Install on Windows

Use the DLL for your PHP's version and thread safety: `prebuilt\loader\windows-x64\php-<version>-<nts|ts>\php_envelock.dll` (x64; built natively and tested on Windows 11 with the official PHP for Windows builds, see TEST-STATUS.md; confirm it on your machine with the commands below), or one you build yourself ([BUILDING.md](BUILDING.md) §2, [PLATAFORMAS.md](PLATAFORMAS.md)). A renamed `.so` will not work. `php -i` shows the version and `Thread Safety` (enabled = TS).

Check:

```powershell
php -v
php --ini
php -i | Select-String 'PHP API|Thread Safety|extension_dir'
```

Copy `php_envelock.dll` to a private folder that untrusted users cannot write. It needs only what the official PHP build already ships — `php8.dll`/`php8ts.dll`, `libcrypto-3-x64.dll` (in PHP's folder) and the Visual C++ runtime PHP itself uses — so if PHP starts, the DLL's dependencies are there; under Apache with PHP as a module, PHP's folder must be on the DLL search path, as for PHP's own `openssl` extension ([HOSTING.md](HOSTING.md) §2.1, with the download link for the Visual C++ runtime).

```ini
extension=C:\private\php_envelock.dll
envelock.identity=C:\private\identity.bin
opcache.enable=0
opcache.enable_cli=0
opcache.file_cache_only=0
```

Test:

```powershell
php -n -d opcache.enable=0 -d opcache.enable_cli=0 -d extension=C:\private\php_envelock.dll -d envelock.identity=C:\private\identity.bin C:\apps\proyecto-a\index.php
```

On Windows the loader checks the identity file with an **allow-list**: its owner, and every access entry, must be the account PHP runs as, SYSTEM, Administrators or OWNER RIGHTS. Any other entry (Users, Everyone, Authenticated Users, another IIS pool, another user…) makes it refuse the file. A file created in a normal folder such as `C:\private` inherits access for Users and will be refused until you restrict it: the startup warning and the compile error say `identity file rejected: accessible by other accounts or groups`. Make Administrators the owner, remove inherited permissions, and grant read access only to the account PHP runs as, plus SYSTEM and Administrators (SIDs are used so the commands work on any Windows language):

```powershell
icacls C:\private\identity.bin /setowner "*S-1-5-32-544"
icacls C:\private\identity.bin /inheritance:r /grant:r "<php-service-account>:R" "*S-1-5-18:R" "*S-1-5-32-544:F"
icacls C:\private\identity.bin   # verify: only the service account, SYSTEM and Administrators
```

The encoder's identity-file commands (`recipient add/remove`, `developer set/remove`, `minimum set`) create the new file already carrying the explicit ACL entries of the one they replace (for example the PHP service account's read entry) and the same owner, before writing any key; they do **not** add an entry for you. Keeping an owner that is not you (the service account or SYSTEM) needs an elevated prompt (Run as Administrator): the encoder then enables `SeRestorePrivilege`. With Administrators as owner, as in the commands above, an elevated prompt is enough. If it cannot be done, nothing is changed. A **newly** created identity file (or any other secret the encoder writes) gets a protected ACL at creation — SYSTEM, Administrators and the account that ran the command, nothing inherited: grant the PHP service account read access, and remove your own entry if PHP runs as another account. `<php-service-account>` is, for example, the IIS application pool identity (`IIS AppPool\<pool-name>`) or the account the Apache/PHP-FPM service runs as.

### Apache on Windows (WampServer, XAMPP, Apache Lounge)

Apache usually loads PHP as a module (`php8apache2_4.dll`), which is the **thread-safe (TS)** PHP. Step by step:

1. **Find your PHP.** Put a page with `<?php phpinfo();` in the web root and open it: note *PHP Version*, *Thread Safety* (enabled = TS, disabled = NTS), *Architecture* (x64) and *Loaded Configuration File* (the `php.ini` Apache really uses; WampServer keeps a separate one for Apache). Delete the page afterwards.
2. **Copy the loader** for that version and thread safety, e.g. `prebuilt\loader\windows-x64\php-8.3-ts\php_envelock.dll`, to a private folder outside the web root, e.g. `C:\envelock\`.
3. **Create the server identity** for that server (assistant: *Server identity* tab; or `envelock recipient add --identity C:\envelock\identity-servidor1.bin --recipient servidor1.enc.json --owner owner.enc.json`) and restrict it (elevated PowerShell; the Apache service of WampServer and XAMPP runs as *Local System* unless you changed it):

   ```powershell
   icacls C:\envelock\identity-servidor1.bin /setowner "*S-1-5-32-544"
   icacls C:\envelock\identity-servidor1.bin /inheritance:r /grant:r "*S-1-5-18:R" "*S-1-5-32-544:F"
   icacls C:\envelock\identity-servidor1.bin
   ```

   If Apache runs under another account, grant that account `:R` too.
4. **Edit the `php.ini` from step 1** and add:

   ```ini
   extension=C:\envelock\php_envelock.dll
   envelock.identity=C:\envelock\identity-servidor1.bin
   ```

   If OPcache is on in that file (`opcache.enable=1`, frequent in WampServer), either turn it off with `opcache.enable=0`, or keep it and add `envelock.allow_opcache=1` plus `opcache.blacklist_filename=C:\envelock\opcache-blacklist.txt`, a text file holding the protected folder followed by `*` (e.g. `C:\wamp64\www\myapp-encrypted\*`).
5. **Restart Apache** (WampServer menu → *Restart All Services*, XAMPP panel → *Stop/Start*, or `httpd -k restart`). `phpinfo()` must now show an **envelock** section with the trust store loaded; if the identity file was refused, Apache's `error.log` says why.
6. **Deploy** the encrypted output folder (the whole folder, with its subfolders as `pack` produced them) under the web root and open it in the browser.

The `php -d extension=… --ri envelock` check from a console uses the CLI's `php.ini`, not Apache's: use it to test the DLL, and `phpinfo()` to test Apache.

Restart IIS/FastCGI or Apache according to your deployment. Apply ACLs that allow read access to the service user, not to general users, and that prevent modification of binaries/configuration. The exact ACL syntax depends on the accounts and domain: review the results with `icacls` before serving traffic.

## 12. Install on macOS

Build on macOS for Intel or Apple Silicon according to the target PHP. The PHP extension is normally called `envelock.so`. Verify with `file`, `php -v`, and the dependencies with `otool -L`.

Do not assume that an OpenSSL library linked to a Homebrew path on the build machine exists on the client. Review load paths, dependency distribution, and code signing. Do not force the global removal of system protections in order to load it.

Test and configure the same as on Unix, with macOS-specific paths and OPcache/preload disabled. If there is an FPM service managed by Homebrew or another manager, restart only that service. The macOS builds and tests are still pending native execution in this release.

## 13. Multiple projects and clients

A server supports:

```text
apps/
├── proyecto-a/   UUID A, content key A
└── proyecto-b/   UUID B, content key B
```

They can run in the same process, provided the applications do not collide in their own global names. Having different keys does not separate namespaces or create a sandbox. A project can include files from another if PHP has access and the loader authorizes them cryptographically.

Because the module is **generic**, the same host can serve several projects from different folders encrypted with **different** keys: it is enough to include in the server identity file (up to 64 entries) each recipient's private key and its trusted signer. The loader tries each identity until it finds the one that corresponds to each package. Separating clients into different processes/services/containers remains advisable to isolate permissions and limit the scope if a server is compromised, but a separate compiled module per client is no longer required.

One identity file per host is the model: `envelock.identity` is read once at startup (`PHP_INI_SYSTEM`), so you cannot give each PHP-FPM pool a different identity with `php_admin_value[envelock.identity]` — that per-pool directive is ignored. Put every project's keys in the one identity file, or run a separate FPM master (its own `php.ini`) per identity.

## 14. Frameworks, Composer and assets

The encoder preserves folders and does not transpile or link dependencies. First prepare the normal project, install authorized dependencies, generate the autoload, and run the tests in the clear. Then package a clean copy.

**First, run the compatibility check.** `envelock preflight --source <dir>` statically scans the tree (read-only — it changes nothing and never runs the code) and flags code that reads its own source at run time, the patterns that break after encryption: source tokenizers and class maps (`token_get_all`), header readers (`get_file_data`), self-reading (`file_get_contents(__FILE__)`, `highlight_file`), and Doctrine/Symfony docblock annotations. Each finding comes with a fix — exclude the file, ship the artifact generated from a cleartext build, or use PHP 8 attributes (`#[...]`) instead of annotations. Add `--strict` to fail in CI on any finding, `--json` for tooling. The fixes in context are in [DEPLOYING-APPS.md](DEPLOYING-APPS.md).

**Let the tool choose the options for you.** `envelock recommend --source <dir>` analyses the tree and prints the **strongest protection that is safe for it**: it enables the hardening options that measurement (the four-CMS matrix) shows are compatible and turns **off** only what would break *this* project, with the reason for each; it lists the files to keep cleartext (`--exclude`, from the same scan as `preflight`) and prints a ready-to-fill `pack` command. It is read-only and deliberately conservative — it never recommends an option known to break a project: `--obfuscate-properties` (breaks the Composer autoloader and object serialisation on every CMS measured) and `--vault-strings` (impractical whole-tree) are never auto-enabled, `--strip-comments`/`--compact` are dropped when the tree reads its own docblocks, and `--sealed` is dropped when the tree uses `eval()`/`create_function()`/`assert('…')`. `--json` gives machine-readable output. It is also the **Recommend** tab in the assistant ([ASSISTANT.md](ASSISTANT.md) §4). Always test the packaged app like a real release before deploying.

Review:

- Autoload: preserved paths; the selected PHP `vendor` must be present and compatible.
- Non-PHP files read by Composer/frameworks: authorize them individually as assets.
- Generated caches: those containing sensitive PHP must be encrypted before distribution; caches created at runtime are another matter and may remain readable.
- Templates: if they contain logic you want to hide, copying Twig/Blade as an asset does not protect it. You need a specific strategy and tests.
- Code that uses `file_get_contents(__FILE__)`, PHAR, or `__halt_compiler()` offsets: it has no guaranteed compatibility, because the physical file is encrypted.
- Source lint/analysis tools: run them on the original before packaging. Do not expect them to analyze the encrypted content.
- Third-party licensing: do not hide or distribute third-party code against its terms.

**Large projects: encrypt only your own code.** OPcache cannot cache protected files, so every request decrypts and compiles them, and their compiled code occupies that request's memory instead of OPcache's shared memory (measured in [VERIFICACION.md](VERIFICACION.md#measured-memory): 100 MB per request for 2,000 protected classes, against 6 MB for the same code served by OPcache). Leave the framework and `vendor/` unencrypted so OPcache keeps caching them, and protect only the business logic you need to hide: `pack --exclude 'vendor/*'` leaves `vendor/` out of the protected output (it is neither encrypted nor copied), so deploy it next to the protected tree yourself, for example with `composer install --no-dev --optimize-autoloader` on the server or by copying it from your clean build. Then:

- Raise `memory_limit` for the protected application if needed (PHP's default is 128 MB); measure its real peak with `memory_get_peak_usage(true)`.
- Size PHP-FPM by RAM: each worker keeps the memory of its largest request, so `pm.max_children` ≈ available RAM / memory per worker.
- Use Composer's optimized autoloader so that each request loads only the classes it uses.
- Consider `pack --strip-comments`. PHP keeps every docblock (`/** ... */`) in memory as part of the compiled code; this option removes comments and docblocks before encrypting, keeping line numbers (errors and stack traces point to the same lines) and checking that every file still parses. Measured: −25 % PHP memory on a docblock-heavy project and peak RSS 50.8 → 28.9 MB for one large file ([VERIFICACION.md](VERIFICACION.md#measured-memory)). **Do not use it** if the protected code reads docblocks at run time (`ReflectionMethod::getDocComment()`, Doctrine/Symfony annotations in docblocks); PHP 8 attributes `#[...]` are not comments and are kept.

### Extra protections (optional)

> For a decision guide — the advantages, costs and *when to use / when to avoid* each option, with three
> ready-made profiles (maximum / balanced / minimum) based on the four-CMS measurements — see
> **"Choosing options: trade-offs and when to use each"** in [DEPLOYING-APPS.md](DEPLOYING-APPS.md). The
> descriptions below are the per-option reference.

- **`--include-protection`**: without it, anyone who can place a `.php` file on the server can `require` a protected file and use its classes and functions (or inspect them with Reflection) without seeing the source. With it, a protected file runs only when it is the script being executed (the entry point) or when a protected file of the same project is on the call stack; a plain autoloader called from your protected code (Composer's, for instance) keeps working. The entry point is recognized the same way under every SAPI — the command line, PHP-FPM/CGI and the Apache module (`mod_php`) — so a protected `index.php` served directly by the web server runs normally. Use it when your entry points (`index.php`, console commands) are protected. **It does not fit** a deployment where the entry point and the framework stay unencrypted and call into protected code (the call stack then holds no protected file): those files would be refused. Plain files that your protected code includes (configuration, `vendor/`) run inside that call stack, so they must not be writable by others.
- **`--no-prepend`**: refuses to run when `auto_prepend_file` or `auto_append_file` is set. Those directives can be set by a site user through `.user.ini` (PHP-FPM/CGI) or `.htaccess` (Apache module) and run code before or after yours in the same request, which could then inspect your code; combine it with `--include-protection`. Do not use it if the server relies on a prepended file (some web application firewalls, such as the one in Wordfence, do).
- **`--no-ffi`**: refuses to run while FFI or `dl()` is reachable. Both let PHP code running in the same process read the decrypted source straight out of memory (FFI maps and reads arbitrary addresses; `dl()` can load the FFI extension at run time). FFI is counted reachable when its extension is loaded and `ffi.enable` is On, or `ffi.enable=preload` under the CLI (which always enables FFI); on a web SAPI `preload` only arms FFI during preloading, which Envelock already forbids for protected trees. The check is per package and **opt-in**, so it never affects a package built without it. Use it only when your application needs neither FFI nor `dl()`; to run such a package, set `ffi.enable=0` and `enable_dl=0` (or remove the `ffi` extension).
- **`--sealed`**: seals the package tree. Once a protected file of the package has loaded in a request, the loader (a) refuses to compile any **plain, unencrypted `.php`** whose path is under the package folder, so an attacker cannot drop or swap in a readable script that would run inside the protected call stack and read the decrypted code (reflection, `debug_backtrace`), and (b) refuses **`eval()`** (and any run-time string compile) for the rest of the request, closing the same path through compiled-on-the-fly code. It is per package and **opt-in**: a package built without it is unaffected, and plain PHP outside the sealed folder keeps working. The detection is order-dependent (the tree is marked sealed when the first protected file of the package compiles), so pair it with `--include-protection` and keep the entry point protected. It is **defense in depth, not a complete boundary**: it refuses `eval()` and plain `.php` *under the package folder*, but an `include`/`require` of plain PHP from a path *outside* the tree (an uploaded file, `data://`/`php://input` when `allow_url_include` is on) is not distinguishable from a legitimate `vendor/` include and still runs. Combine it with **`--no-ffi`** (so even plain PHP running in-process cannot read the decrypted source from memory), keep `allow_url_include` off (the default), and treat `--sealed` as one layer, not the only one. **Do not use it** if your deployment keeps plain `.php` inside the package folder or the protected code relies on `eval()` (some template engines and config caches do); every `.php` in the tree must be protected. `vendor/` and the framework left outside the package folder (see below) are not affected.
  - **`envelock.sealed_cleartext` (directive, for running a CMS under `--sealed`).** A CMS legitimately writes plain `.php` under its own tree at run time (a Twig/Smarty template cache, a compiled service container) and sealed would refuse it. Set `envelock.sealed_cleartext` in `php.ini` to a `PATH_SEPARATOR`-separated list of **absolute path prefixes** (`:` on Linux, `;` on Windows) — the config file's directory and the folders the app writes generated PHP into — and plain `.php` under those prefixes is **re-allowed** while every other plain file in the tree stays refused. It is `PHP_INI_SYSTEM` (set only in `php.ini`/the command line). It deliberately does **not** relax the `eval()` refusal: `eval()` is the primary vector sealed exists to block. Consequence (measured on the four CMSs): Drupal and Joomla run sealed with this directive (they only *write* cleartext cache PHP; Drupal `sites/default`, Joomla `cache`/`tmp`/`administrator` plus the config file); PrestaShop and WordPress do **not** (their autoloaders `eval()` at run time, which the allowlist cannot and must not cover). Only list directories the app itself writes, and keep untrusted uploads non-executable at the web server — a `.php` dropped into an allowed prefix would run. See `docs/DEPLOYING-APPS.md`.
- **`--enforce-manifest`**: writes a signed binary manifest (`envelock-manifest.bin`) listing every file of the package, and the loader checks it at runtime. On the first protected file loaded from the package in a request, the loader verifies the manifest's signature against the developers trusted in the server's identity file and confirms **every listed file still exists** under the package folder; if one is missing (deleted or renamed away) the request fails closed. This closes the gap that a deployment could drop a file — for example a protected authorization check — so its code silently stops running; content tampering of protected files is already caught by their per-file authentication tag. It is **on by default** (opt out with `--no-manifest`), checked once per package per request, and it is also what enables the `envelock.manifest_fastpath` cold-start optimization (section on directives). Deploy the package as one unit and restart nothing special. This complements the operator's `verify` command (section 17), which checks the same inventory at deploy time with the JSON `--manifest`.
- **`--obfuscate`**: inside each named function and method, local variables get short names (`$invoiceTotal` becomes `$a`). Parameters keep their names (named arguments depend on them), as do properties, `$this`, superglobals, functions, classes and constants. Local variables are also renamed inside **closures and arrow functions** (a captured variable is renamed the same way inside and outside, and every parameter keeps its name). A function that uses names at run time (`compact`, `extract`, `get_defined_vars` — also when named in a string, as in `call_user_func('compact', ...)` — `$$name`, `eval`, `include`, `global`) or contains an anonymous class is left untouched. A name built at run time (`$f = 'comp' . 'act'`) cannot be detected: test the obfuscated package like any release. Line numbers are kept and every file must still parse. Notices such as "Undefined variable $b" will show the short names. Docblocks such as `@var Type $name` still reveal names: combine it with `--strip-comments`.
- **`--compact`**: collapses every run of whitespace, and each comment, to a single space before encrypting, removing indentation, blank lines and the line structure that aid reading. It never joins two tokens (one space always remains where whitespace was), so behaviour is unchanged, but **line numbers are not preserved** (errors report the collapsed line), so use it when you do not need line numbers in production. Heredoc/nowdoc bodies and string literals keep their content. Combine with `--obfuscate` and `--strip-comments` for the least readable output. **Caveat — code that reads its own docblocks at run time.** Both `--compact` and `--strip-comments` physically remove docblocks, so a framework that reads a `getDocComment()` annotation at run time (for example PrestaShop's `@arrayAccess` on its `AbstractLazyArray` presenters) silently misbehaves after packing — no error, just missing output. Run `envelock preflight` first: it flags this (category `reads-own-docblock`), and `pack` prints a warning when these flags meet such a tree. Drupal, WordPress and Joomla are unaffected; on PrestaShop, drop these two flags (the rest of the safe set still applies) or `--exclude` the presenter files. See `docs/DEPLOYING-APPS.md`.
- **`--obfuscate-methods`**: renames **private** methods to short names. It is deliberately conservative: a private method is only callable from inside its own class (PHP enforces it), and a name is renamed only when **every** use of it in the file is the declaration or a call via `$this->name(`, `self::name(` or `static::name(`. If the name is ever used on another object (`$other->name(`), through another class, as a bare identifier, as a property or class constant (no `(`), or appears in a string literal (a possible `[$this,'name']` callable or Reflection lookup), that method is left untouched. A class with any dynamic member access (`$this->$m()`, `$obj->{...}`, `::$x`) or a `__call`/`__callStatic` is skipped whole. Behaviour and line numbers are unchanged, but because a dynamic call the analysis cannot see would break, **test the obfuscated package like any release**. Public, protected, and magic (`__*`) methods are never renamed.
- **`--obfuscate-properties`** (**HIGH RISK**): renames **private instance** properties used only as `$this->name`. The gain is that property names stop revealing intent; the danger is that a private property name also appears in the **serialized** form of an object (`serialize()`, PHP sessions, caches, queued jobs), which the tokenizer cannot see, so **data serialized before obfuscation will not unserialize after it** (and vice versa) — only enable it where that does not happen, or re-generate such data. It is conservative: the class is skipped if it serializes (`serialize`/`__sleep`/`__wakeup`/`__serialize`/`__unserialize`/`Serializable`), uses `get_object_vars`/`get_class_vars`/`compact`/`extract`, any `Reflection*`, a magic `__get`/`__set`/`__isset`/`__unset`, or dynamic member access; and a property is renamed only when its name is used in the whole package exclusively as `$this->name` (never on another object, never as a string, never a static or promoted property, never a multi-declaration). Public and protected properties are never renamed. **Test the package thoroughly.**
- **`--obfuscate-flow`**: inserts an **always-false opaque-predicate dead branch** at the start of each named function and method — a condition a reader (or a naive automated tool) must evaluate to see the branch never runs (`strlen()` of a path is never negative; `__LINE__ & 0` is never 1; `count()` of a two-element array is never ≠ 2). It raises the effort to follow the code and defeats a stripper that does not model those built-ins. It is honest about its limit: it is **dead-code insertion, not control-flow flattening** (for real flattening see `--obfuscate-flatten` below; closures and generators are still not flattened, see ROADMAP O6). Behaviour never changes (the branch cannot execute) and **line numbers are preserved** (the branch is emitted on the opening brace's line). Functions that use `goto` are skipped. Validated behaviour-neutral by the differential fuzzer (`scripts/fuzz_obfuscator.py`, thousands of generated programs with random flag combinations). Still, **test the package**.
- **`--obfuscate-flatten`** (O6): rewrites each named function and method whose body is plain code into a `while(true){switch($__envlk_st){case 0: …}}` dispatch loop. Each statement keeps its text and its line, so behaviour, line numbers and exception messages do not change (tests in `tests/test_transform.py` and `tests/test_native.py`). A body that observes its own frame or uses constructs the rewrite cannot keep in order is left as written and counted in the pack report: generators (`yield`), `goto`, nested declarations, `include`/`eval`, dynamic variables, `compact`, `extract`, `get_defined_vars`, `parse_str`, `declare`. The dispatch loop is readable: it raises the cost of following the flow, it is not opaque. It cannot be combined with `--virtualize`. Validated by the differential fuzzer (`--flatten`) and by the Laravel and Symfony smokes (`scripts/framework-smoke.py --flatten`), which are integration checks, not O11 closure.
- **`--vault-strings` and the encrypted vault** (objective O7): literals in a runtime position are moved out of the code into a per-file table the loader resolves through `\__envelock_lit(idx)`. Since O7 that table is **encrypted at rest inside the container**: AES-256-GCM under a per-file data key, itself wrapped with the package content key, and each literal is decrypted only when the program reads it (then cached for the rest of the request and wiped at the end of it, like the rest).
  - What that buys: the container is decrypted once, at load, and from then on its plaintext is in memory for the whole request. Before O7 the vault table was part of that plaintext, so every secret string in the file sat in one contiguous, already-decrypted block. Now it holds ciphertext, and a literal exists in the clear only between the call that asks for it and the end of the request.
  - **Honest limit:** the data key is wrapped with the content key, so a reader who can decrypt the container can unwrap it. This does not defeat someone who can run the code or dump the process at the right moment; it removes the attack that cost nothing, which was reading one block and getting everything.
  - A tampered entry is not handed over: its tag fails and the loader returns the empty string, the same as any other vault miss, so a forged or corrupted lookup cannot fatal a request.
  - Cost: one AES-GCM decrypt per distinct literal per request (repeated reads of the same literal hit the cache), plus 28 bytes of nonce and tag per literal and 60 for the wrapped key.
  - Still incompatible with `--bytecode`, which ships no source for the `\__envelock_lit()` calls to live in.

- **`--encode-strings`**: re-spells every complete string literal as a double-quoted run of `\xNN` byte escapes (`"SELECT ..."` becomes `"\x53\x45\x4c..."`). The value is identical, so behaviour and line numbers are unchanged and there is no run-time cost beyond parsing the escapes; it hides the readable text (SQL, messages, paths) that survives obfuscation. Interpolated strings (`"id $x"`) and heredoc/nowdoc are left untouched. Trade-off: it enlarges the source of string-heavy files (about 4× the string bytes), and since protected files are not cached by OPcache that compile cost is paid per request — measure a very string-heavy app before enabling it there. Note `--encode-strings` keeps the (decoded) value as a constant in the compiled op_array; `--vault-strings` goes further and removes it from the compiled code entirely.
- **`--vault-strings`**: moves string literals that sit in a **runtime position** out of the code and into a per-file vault. Each such literal is replaced by an internal `\__envelock_lit(idx)` call; the loader keeps the file's literals in a request-scoped table (carried inside the file's already-encrypted payload, so no new cryptography) and returns them on demand, wiping them from memory when the request ends. The gain over `--encode-strings`: the readable text is **not a constant in the compiled op_array** and is **not in the decrypted source** the engine compiles, so it does not surface in a dump of the loaded code or a capture of the compiled source. A literal in a **constant expression** — a `const`, a class-constant or property default, a function/method parameter default, a `static $v = …` initializer, an attribute argument, an `enum` case backing value, a `declare()` — cannot become a function call and is **left inline**; the encoder models the common cases and, as a hard safety net, compiles (`php -l`) every transformed file and leaves inline any literal whose line would not compile, so a broken file is never produced. Identical literals share one slot; 0/1-character literals stay inline. **Line numbers are preserved.** Cost: about one internal function call per vaulted-literal access — on an A/B microbenchmark (PHP 8.3, a tight loop that does almost nothing but read one literal) roughly 15 ns per access; negligible outside such loops, but since protected files are not OPcache-cached it is paid per request, so measure a literal-access-heavy hot path before enabling it there. It is per package and **opt-in**; packages built without it are byte-for-byte unaffected. **Honest limit:** like every Envelock layer it does **not** defeat the server administrator/root, who can read process memory (including the vault); it defeats recovery of the strings from the compiled code and the source text. **Test the package.**
- **`--bytecode`**: ships each file as a **precompiled `zend_op_array`** instead of encrypted source. On the server the loader deserializes the image and runs it, so the compiler is never invoked for that file: there is no decrypted PHP source in the process for a compilation hook, a modified engine or a memory reader to recover. This is the single biggest step up over source mode, and it is what makes the attack on `zend_compile_file` irrelevant. Three things you must know before using it:
  - **It needs the target server's PHP version and build.** The image carries a bytecode identity of that build (PHP version, Zend extension build id — thread safety, debug, compiler —, data layout and VM kind) and the loader refuses the file if it differs, so a package is per PHP version and build. It does not depend on the SAPI or on extensions loaded: an image packed with the CLI runs under `php-cgi` or PHP-FPM of the same build, and a call to a function of an extension the server lacks fails with PHP's normal "Call to undefined function" error rather than crashing. `--bytecode-php` selects the CLI that compiles (default `--php`); `--bytecode-loader` points at the loader module when that CLI does not already load it. Repack when the server's PHP changes.
  - **It needs `--deploy-root`, and the package then only runs from there.** `__DIR__`, `__FILE__` and the path of a statically resolved `include`/`require` are compile-time values, baked into the image as the absolute path the file had while being compiled. So `pack` compiles each source at its deploy path and removes it again (nothing else in that folder is touched, and a path that already exists is refused rather than overwritten). Running the package from anywhere else fails with a clear error naming the path it wants. This is inherent to precompiled bytecode — OPcache's own file cache is bound to an absolute path the same way.
  - **It cannot be combined with `--vault-strings`**, which rewrites literals into `\__envelock_lit()` calls *in the source*; a bytecode image ships no source to resolve them in. The other source transformations (`--obfuscate`, `--strip-comments`, `--compact`, `--encode-strings`, `--obfuscate-methods`, `--obfuscate-properties`, `--obfuscate-flow`) do combine, and run **before** the compilation, so they land inside the image.
  Cost: the image is about ten times the size of its source (about 7.7× after `zlib -9` on a 5.7 KiB file), and each request decrypts and deserializes it afresh — the decrypted program lives exactly as long as the request, and nothing about it is cached between requests. Performance is at parity with source mode at the container level: `scripts/bench.py` on PHP 8.4.27 measures 179 µs/file in source mode against 174 µs/file in bytecode mode, because the per-file cost is dominated by unwrapping, decrypting and verifying, not by compiling. The engine-level gain from not compiling (94.5 µs to load an image against 534.4 µs to compile one 5.7 KiB source, in process) needs the per-worker cache of objective O9, which is still open. **Test the package.**
- **`envelock.secret_memory`** (off by default, `0`; objective O2): puts the identity private keys in a *secret* memory region instead of the process's ordinary heap. On Linux that region is `memfd_secret(2)`, whose pages are removed from the kernel's direct map: they appear in no `/proc/PID/maps`, no `/proc/PID/pagemap` and no `/proc/kcore`, because the kernel itself has no linear address for them. This closes what `envelock.harden_memory` leaves open — that one defeats a core dump and an ordinary same-user `ptrace`, but a reader holding `CAP_SYS_PTRACE` (root, or a container granted it) can still read a normal mapping through `/proc/PID/mem`.
  - **It is off by default because it is often unavailable.** `memfd_secret` needs `CONFIG_SECRETMEM` *and* a kernel that can split its direct map into small pages; where it cannot, the syscall is not even registered and returns `ENOSYS`. When that happens the arena degrades to an anonymous `mlock`'d, `MADV_DONTDUMP` mapping — the older, weaker protection — and **says so**: call `envelock_secret_memory()` after turning the directive on. It returns `"memfd_secret"`, `"mlock+MADV_DONTDUMP"` or `"none"` (directive off). Read it back on the real server rather than assuming.
  - Linux only. On macOS and Windows the arena is a locked mapping, never secret memory.
  - The keys are placed there at startup, in the PHP-FPM master before it forks, so each worker inherits an already-mapped region — which is what `memfd_secret` requires (its manual asks for the region to be created after the fork, not across it). Restart PHP after changing the directive.
- **`--obfuscate-names`**: opt-in renaming of eligible global classes, interfaces, traits, enums and functions and their static references across the package. It is separate from `--obfuscate` (locals) and `--obfuscate-methods`/`--obfuscate-properties` (private members). It is off by default.
  - **Only for a deliberately closed package.** External code, configuration, classmaps, autoloaders, stored serialized objects and dynamically assembled names can depend on the original spelling. Renaming can break them even when PHP lint succeeds. Do **not** enable public-name renaming for Laravel, Symfony or other framework code. Review the boundary and test the whole deployed application.
  - By default the token pass declines namespaced packages. It also declines known risky constructs, including qualified names, constant declarations, attributes, interpolation, dynamic calls, observable class identities and external inheritance. Names mentioned in string literals or docblocks, builtins and certain collisions are kept. These checks are conservative but **not a proof of closure**.
  - `--obfuscate-names --obfuscate-names-ast` additionally enables the **experimental** AST pass for namespaced code. It resolves class/function imports and static references across the supplied files and patches byte offsets without changing line breaks. It retains classes in PSR-4-style filenames and classes with external ancestors or traits, including transitively; it declines known dynamic, reflection, serialization and attribute cases. It also declines dynamic symbol observers such as `constant`, `defined`, `function_exists`, `method_exists`, `property_exists`, `is_callable` and closure binding/callable creation, as well as dynamically named methods. Because exception messages and traces can expose original names, it declines `try`/`catch`/`finally`, `throw` and known Throwable-observer method names. Without type inference it may also decline unrelated methods named `bind`, `bindTo`, `call`, `fromCallable`, `getTrace`, `getTraceAsString`, `getMessage`, `getPrevious` or `__toString`. These safeguards cannot see an external classmap/autoloader or every external consumer: this mode is **not suitable for PSR-4/classmap applications or frameworks**, and is not enabled by the GUI.
  - For a deliberately closed application, add a **strict allowlist** with repeatable `--obfuscate-names-allow 'type:App\Engine'` and `--obfuscate-names-allow 'function:App\helper'`. `type` means class, interface, trait or enum; `function` means a global or namespaced function. Give the full name **without a leading backslash**. Matching folds ASCII case like PHP; it does not Unicode-casefold names. Only the listed declarations can be renamed by this name pass. If any entry is unknown, duplicated, malformed, blocked by a safety check, or cannot be rewritten and linted, the **entire pack is aborted**; no destination is published. The policy also forces the AST pass for global-namespace code. Other explicitly enabled transforms (private methods/properties, local variables, etc.) have their own scopes. Without the allowlist the earlier experimental behavior remains available; the list is an operator-declared boundary, **not evidence that external consumers do not exist**. Symbols supplied on the command line may appear in shell history or process listings.
  - The `pack` report exposes `names_obfuscated` (generated names, or `false` when the option is off), `names_skipped` (the reason for a whole-package refusal when no strict list was supplied), and `names_allowlist_enforced` (boolean, without the original names). A bad span or lint failure rolls back the **whole** rename, or aborts a strict-list pack. Name analysis runs before `--vault-strings` so the vault cannot hide a literal from its checks; bytecode compilation runs afterwards.
  - Class constants and their references are not renamed by this feature. `--compact` remains a separate option that does **not** preserve line numbers.
- **`envelock.allow_debuggers`** (off by default, `0`): when a debugger or profiler that can dump or trace the decrypted code is loaded (Xdebug, VLD, uopz, runkit7, xhprof, Tideways, ddtrace, SPX, pcov, Blackfire, memprof), when a `zend_ast_process` hook is installed, or PHP runs under phpdbg, protected files fail closed (they can dump or trace the decrypted code). Set `envelock.allow_debuggers=1` in `php.ini` to allow them, for example on a development machine.
- **`zend.multibyte`**: protected files fail closed when it is on. It routes the source through mbstring's encoding filters (a per-directory / per-user INI), an ambiguous path we do not want for protected code. Leave it off (the default).
- **`envelock.harden_memory`** (on by default, `1`): once a server identity is loaded, the process is marked non-dumpable (no core dumps, no `ptrace`/`/proc/self/mem` reads by the same user) and the private keys are locked into RAM and excluded from any dump. It is re-applied after startup so it survives a worker dropping privileges. Set `envelock.harden_memory=0` to turn it off, for example to let a legitimate profiler or a core dump work in a shared pool.
- **`envelock.paranoid`** (off by default, `0`; objective O3): refuses a protected file when the process is being instrumented in a way that shows up at run time rather than as a loaded extension — a tracer attached with `ptrace`, a replacement of `zend_execute_ex`, a replaced `zend_interrupt_function`, or a registered execution observer. Those are what an APM agent or a profiler does on purpose, so the mode is opt-in and will refuse them.
  - Two checks run **always**, with or without the flag, because they cost a pointer comparison and refusing them would leave the objective unmet: that Envelock's own compile hook is still the one it installed at startup (an extension loaded afterwards can install a hook above it and receive the handle Envelock has just decrypted), and that no `zend_ast_process` hook is installed. The one exception is an operator who has set `envelock.allow_opcache`: OPcache re-asserts itself as the outermost compile hook and Envelock cannot sit above it, so that opt-in already accepts a hook above this one.
  - **What the tracer check cannot see, measured:** `PTRACE_ATTACH` stops the target, and a stopped process cannot run the check that would notice it — by the time it runs again the tracer has detached and `TracerPid` reads 0. A tracer that leaves the target running (`PTRACE_SEIZE`, or attach-then-continue to single-step or read memory) *is* detected, and that is the one worth catching. `envelock.harden_memory` already blocks an ordinary same-user attach outright; this covers the tracer that gets through anyway (one with `CAP_SYS_PTRACE`, or one attached before the flag was set).
  - Every check here is advisory by nature: an attacker who owns the process owns the checks. What it buys is that a protected package fails closed in a process that is being traced or instrumented instead of quietly handing over its source.
  - Linux only for the tracer check; elsewhere that one reports "could not determine" and does not refuse.
- **`envelock.licence`** (empty by default; objective O8): path of the signed deployment license issued by the vendor. Empty means the deployment is unlicensed and unrestricted. Once it names a file, that license is mandatory: a missing or unusable file fails closed, so deleting the *file* does not lift its restrictions. Removing the *directive* does: `php.ini` belongs to whoever administers the server (see "What a license is, and is not" in 14.1).

### 14.1 Deployment licenses (objective O8)

A license is a small fixed-size file, signed with the owner's Ed25519 key — the same key that signs packages, so the server already trusts it and no new key material is involved. It can only ever **narrow** what the loader runs; there is no license that widens it, which is why a self-issued one is useless to an attacker and why the loader requires a signature from a key already in the identity file.

Issue one per server:

```bash
envelock.py licence machine-id                       # the customer runs this and sends the value
envelock.py licence issue --owner owner.json --out licence.bin --days 365 \
    --machine 2f0c…                                  # or --machine this on your own host
envelock.py licence inspect licence.bin              # read the constraints back
```

Then on the server, `envelock.licence = /etc/envelock/licence.bin` in the shared `php.ini` (the master reads it at startup, like `envelock.identity`).

The file is **not secret** — its integrity comes from the signature — and `licence issue` writes it `0644` on purpose (on Windows it keeps the folder's inherited permissions): the PHP worker usually runs as the pool user, and a `0600` file owned by root would be unreadable to it and would fail closed in a way that looks like a bad license. It is per-server, so issue one per host rather than sharing a file.

**What a license is, and is not.** Every license control lives in the server's `php.ini` (`envelock.licence`, `envelock.clock_state`, `envelock.clock_tolerance`, `envelock.trusted_time`), and the loader is open source. Whoever administers the server can therefore remove the directive, widen the tolerance, or run a loader built without the check, and no package or license format can prevent that on a machine they control. A license keeps a deployment that is operated as agreed within its terms — it stops a copied deployment, an expired one or one moved to another host from simply working — and it is a contractual tool against a licensee who tampers with it. It is not DRM against the server's own administrator.

Constraints supported today:

| Constraint | Flag | Meaning | Strength |
|---|---|---|---|
| Expiry | `--days N` or `--expires YYYY-MM-DD` | Refuses every protected file compiled from that moment. Checked each time a protected file is compiled — on every request under PHP-FPM, Apache or CGI, where protected files are recompiled per request because OPcache is refused for them. Code already compiled in a long-lived process (a daemon, a queue worker, Swoole/RoadRunner/FrankenPHP worker mode) keeps running past expiry until that process restarts. | Commercial term, not a boundary: see the clock note below |
| Machine | `--machine this` or a 64-hex fingerprint | Binds the license to one host, so it cannot be copied to a second server by accident. | Medium — `/etc/machine-id` and the MACs of physical NICs, both settable by the server administrator; inside a container (only virtual interfaces) it is the image's `/etc/machine-id` alone, which travels with the image |
| Domain | `--domain app.example.com` or `this` | Refuses requests served under a different host name. Compared exactly as the loader sees it: ASCII-lowercased, port removed, a trailing dot kept; an international name is bound in its punycode form. `this` takes the packing machine's host name, while a web server compares its `SERVER_NAME`. | **Weak** — the web server's `SERVER_NAME`, which its administrator configures |
| IP | `--ip this` or a 64-hex fingerprint | Binds the license to the server's own IPv4 addresses. | Medium — not spoofable from outside, but breaks when the addresses change |

Constraints combine: every one present has to hold. On **Windows** the loader has no machine, host-name or IP lookup, so a license bound to any of them is **refused** there (fail closed); an unbound or expiry-only license works.

**The domain binding is the weak one, and it is worth being blunt about it.** For a web request the loader takes the name from `SERVER_NAME` — the name the web server is configured to serve — and not from the client's `Host` header, which any client could set to the licensed name. With Apache's default `UseCanonicalName Off`, however, Apache itself fills `SERVER_NAME` from the client's `Host` header: set `UseCanonicalName On` (with a `ServerName`) for the binding to mean anything there. Either way the server's administrator decides the name. What the check buys is that copying a deployment to another server does not keep working by accident or by habit; it is not access control, and it must not be relied on as such. Two consequences worth knowing:

- A port is ignored, so `app.example.com` and `app.example.com:8443` are the same site.
- On the command-line SAPIs (`cli`, `phpdbg`, `embed`) there is no web server: their `$_SERVER` is built from the environment, so the loader ignores it and uses the machine's own host name (otherwise `SERVER_NAME=licensed.example php app.php` would pass anywhere). `licence host-id` prints that value. A worker also has no request before its first one, which is why the domain is **not** checked at startup — only per protected file, when there is a request to look at.

**The machine fingerprint** is SHA-256 over the host's `/etc/machine-id` (or the D-Bus equivalent) plus the MAC addresses of its non-loopback interfaces, addresses sorted so that enumeration order and interface renames cannot change it. It is derived only from what the machine already reports: a value Envelock stored itself would prove only that the file was copied along with it, which is the very thing the binding exists to catch. Read it back at any time with `envelock.py licence machine-id`, or from PHP with `envelock_machine_fingerprint()`.

Two limits worth stating plainly:

- The fingerprint is computed independently by the encoder (when issuing) and by the loader (when checking). If the two ever disagreed, **every** machine-bound license would be refused, and it would look like a bad license rather than a mismatch — so the pair is compared directly in the test suite on the machine running the tests.
- Expiry is compared against the **local clock**, so on its own it is a commercial term rather than a security boundary. `envelock.clock_state` closes the cheap bypass — see below — but it does not turn expiry into a boundary either.
- On Windows the loader reports no machine identity, so a machine-bound license is refused there. An unbound license works.
- A host with more than 256 MAC addresses (or IPv4 addresses, for `--ip`) cannot be bound: both the encoder and the loader take every entry, sorted, and refuse rather than silently use a subset.
- A clock at or before 1970 (an unsynchronised container, or a shim freezing `time()` at 0) refuses an expiring license instead of passing it.

### 14.2 Anti-clock-rollback (objective O8)

An expiry checked against the local clock is worth nothing if `date -s` can move the clock back and the license lives again. `envelock.clock_state` points at a small file in which the loader records **the highest time this installation has ever been seen running at**. On every protected file it compares the clock against that record and refuses when the clock is behind it:

```ini
envelock.clock_state = /var/lib/envelock/clock     ; the worker must be able to WRITE it
envelock.clock_tolerance = 3600                    ; how much lag is normal drift, not a rollback
```

The tolerance exists so an NTP step or a hand-corrected timezone does not stop a server; the default of an hour absorbs those and still catches a rollback measured in days. Writes are throttled to one per tolerance interval (measured against the value already on disk), because this runs inside request handling. Valid range is `0` to one year of seconds; a negative or absurd value is clamped (negative falls back to the 3600 default) so it cannot accidentally switch the rollback check off.

Two design decisions worth knowing, because both look like bugs and are not:

- **A missing, truncated or garbage state file does not refuse anything.** It costs one rollback detection. Refusing to run because a bookkeeping file is broken would let anyone take the site down by touching a file, and would punish the operator for the vendor's record-keeping.
- **The check only runs when a license is in force**, and only after the license itself has been accepted. An unlicensed deployment has nothing to roll back to, and a refused request cannot push the record forward.

**Honest limit, and it is a real one:** the state is a file on the server, and whoever administers the server can delete or edit it. It is deliberately not signed with a key either, because every key the loader holds is on that same server, so a signature would only stop an attacker who cannot read the disk — and such an attacker cannot delete the file either. What this defeats is setting the clock back, which is the common bypass. It does not defeat a determined administrator, and nothing stored only on the customer's machine ever will. A *trusted* time source (14.3, Linux and macOS) closes the "delete the record and reset the clock" variant; even so, treat expiry as a commercial term.

The file cannot live where the identity file does: `server-install` leaves that `root:root` mode `0400` precisely so the workers cannot read it, and this one needs the opposite. Under PHP-FPM the master (root) never creates it: the first worker that records a time creates it as the worker user, so make its directory writable by the pool user. The loader refuses to read or write it through anything but one ordinary file — not a symlink, hard link, junction, FIFO or device — so a link planted at that path cannot redirect the write.

### 14.3 A trusted time source (objective O8)

The watermark is a file, so an administrator can delete it and set the clock back. What closes that is a floor on the real time the machine cannot invent:

```ini
envelock.trusted_time = www.cloudflare.com     ; any HTTPS host; empty (default) = off
envelock.trusted_time_timeout = 5              ; seconds, for the whole exchange
```

Once per **process start** — at module startup, never per request; under PHP-FPM that is the master, before it forks its workers — and only when a license is in force, the loader opens a TLS connection to that host, sends `HEAD /` and reads the `Date` header. The certificate chain and host name are verified; the certificate's validity dates are deliberately **not** checked against the local clock, because that clock is exactly what is under suspicion (a clock set back past a certificate's start date would otherwise make the check fail silently). The answer is used two ways: as an additional floor to compare the clock against on every protected file, and to push the watermark forward, which is what makes deleting the state file insufficient — the next start re-establishes the floor from the network.

When the network time is more than a day **ahead** of the local clock — the clock was set back, or `envelock.trusted_time` points at a broken source — protected files are refused (with a warning at startup) until the two agree. That floor is kept in memory only and not written to the state file, so a broken source cannot block the deployment beyond its next restart.

**A host that cannot be reached never refuses a site.** Unresolvable name, blocked egress, slow peer, TLS failure: the loader logs nothing, records no observation, and falls back to the local clock and the watermark. An outbound dependency added to a web server must not become an outage, so failure is silent by design. Check reachability before turning it on, e.g. `curl -sI https://www.cloudflare.com | grep -i '^date'` from the server. The timeout bounds the TCP connect and the read, but **not** DNS resolution (POSIX `getaddrinfo` has no timeout and bounding it would risk the worker's startup for a fail-open floor); point `trusted_time` at a host whose DNS is reliable, or pin it in `/etc/hosts`.

There is deliberately **no Envelock licence server** here. Any HTTPS endpoint works, which is why the host is a directive rather than a constant, and why turning this on does not create a new party your deployment depends on.

Honest limits:

- It is a floor, not a ceiling: it proves the real time is *at least* the answer, which is what an expiry needs. It cannot show the clock is not set ahead.
- An administrator who controls the machine's DNS and its trusted CAs can answer with a chosen time. That is a much higher bar than `date -s`, not an impossible one.
- Not implemented on Windows: the loader reports no observation there and the deployment runs on the local clock and the watermark.

### 14.3.1 Real applications: Laravel and Symfony (objective O11)

An integration check for the v2 container format; repeat it as the final O11 closure check after all other
objectives are complete. It uses dedicated **disposable** applications, not production apps.
The builder requires Composer, PHP 8.4+ with the frameworks' extensions, network access and an
empty destination; it refuses to overwrite an existing directory. The fixture source lives under
`tests/fixtures/frameworks/`.

```bash
python3 scripts/create-framework-fixtures.py --root /tmp/envelock-framework-fixtures
ENVELOCK_FW_LARAVEL=/tmp/envelock-framework-fixtures/laravel \
ENVELOCK_FW_SYMFONY=/tmp/envelock-framework-fixtures/symfony \
  python3 -m pytest tests/test_frameworks.py -q
```

The loader that serves the protected app defaults to the committed one matching the running PHP
(version, thread safety, OS, architecture); `--loader` / `ENVELOCK_FW_LOADER` chooses another, and
`--php` / `ENVELOCK_FW_PHP` the PHP. The bytecode pass needs a **pack-time** loader with
`envelock_bc_emit` (`--emitter` / `ENVELOCK_FW_EMITTER`, default: the serving loader). The production
Windows DLLs carry no emitter, so on Windows pass an emitter build (`--enable-envelock-bcemit`) of the
same PHP; images it emits are accepted by the production DLL of that PHP. `create-framework-fixtures.py`
finds Composer on `PATH` or as `composer.phar` (`--composer`, `--php`).

On Laravel 13.40/13.41 and Symfony 8.1.11 with bytecode and the listed obfuscation passes — on Linux,
and on native Windows 11 with the 8.4 NTS production DLL serving and an emitter build packing —
**10/10 and 7/7 responses matched** for status, complete body and response headers, after normalizing
copy paths and local ports. Redirects are not followed, so their original status and `Location` are
compared. The volatile `Date` header is excluded. For the two known Laravel fixture cookies, random
values are masked and `Expires` is masked only when `Max-Age` remains available; names, flags, other
attributes and other cookies remain compared. Separate cookie jars exercise a Laravel file-session
write/read round trip in both apps. The smoke also copies only session files between the disposable
copies and verifies that a pre-deployment cookie works after deployment and a protected-session cookie
works after rollback. Raw random cookie values, other session stores and CSRF flows are not compared.
The script also checks expected statuses and contents: successful routes, service
injection, instantiated attributes, Eloquent's `widgets` table, a create/read cycle, 422 validation
and 404. It runs in production mode. This is not a general guarantee for other applications or debug pages:
`--compact` changes line numbers and protected source snippets differ from plaintext.

Five details decide whether this works, and four of them produce a symptom that points somewhere
else entirely:

- **Pack only the application's own code.** `vendor/` and the run-time caches stay outside the
  packed tree: they are not the asset and they are regenerated anyway.
- **Delete only the files the packer will replace.** Removing a whole directory takes the non-PHP
  files with it — `config/*.yaml`, `.env`, templates — which the packer neither touches nor copies.
  In Symfony that is `config/routes.yaml`, and the symptom is an empty `debug:router`: it looks
  exactly like attribute reflection failing under bytecode, and it is not. Reflection works fine;
  `ReflectionClass::getAttributes()` returns every `#[Route]` from a protected file.
- **`artisan` and `bin/console` have no file extension**, so `extensions` must include the empty
  suffix. Omitted, the packer skips them silently and the application will not start at all. (The
  `pack` command line encrypts only files with an extension: there they stay cleartext entry points,
  which is fine unless the package uses `--include-protection` — then their commands are refused, so
  `envelock recommend` leaves that option off for such projects.)
- **The run-time caches must still exist.** Laravel refuses to boot without a present and writable
  `bootstrap/cache`; emptying it without recreating it reports `PackageManifest.php line 179`, which
  says nothing about the protector.
- **OPcache must be off** (or explicitly allowed): the loader refuses to run with it enabled.

**Public renaming (O6) is explicitly off.** The script passes `obfuscate_names=False` and requires
the real report field `names_obfuscated` to be the boolean `false`; a missing field or an enabled
pass fails the check. Both runs use disposable copies. Laravel is forced to use each copy's own
SQLite database, regardless of an absolute `DB_DATABASE` in `.env`; `LARAVEL_STORAGE_PATH` is also
forced into each disposable copy for file sessions. The smoke script refuses applications without
the fixture marker. The smoke checks that its own PHP server bound the port,
not merely that an HTTP service is listening there; use distinct `--baseline-port` and
`--protected-port` values for concurrent runs. `variables_order=EGPCS` exposes those environment
overrides to PHP/Symfony. Do not point the check at a production app or service.

### 14.4 Mini-VM (O4): quarantined, laboratory only

**Do not deploy virtualized packages.** Differential testing found observable PHP/VM differences,
including exception classes, messages and evaluation priority. Supported syntax is not a guarantee
of semantic equivalence. The compiler checks reachable instruction paths and rejects nested
expressions that can exceed the 4096-slot VM stack; the loader still checks stack bounds at runtime
for untrusted programs. O4 remains open. A pack without `--virtualize` is unaffected by this
quarantine.

For isolated research only, explicitly override the quarantine and probe a compatible rebuilt loader:

```bash
envelock pack --source app --output dist --virtualize calcularPrecio \
  --virtualize-loader /absolute/path/to/rebuilt/envelock.so --unsafe-vm-laboratory
```

Use `--virtualize-loader builtin` only when the PHP executing the probe already contains the V2
loader. The Python API equivalents are `virtualize=[...]`, `virtualize_loader=...` and
`unsafe_vm_laboratory=True`. The override and the V3 program version are recorded in package information.

Behaviour worth knowing (November 2026 audit):

- The VM entry (`__envelock_vm_v2`) runs only when called **directly by name**, as the rewritten body
  does. A variable-function call (`$f(...)`), `call_user_func($name, ...)` with a run-time name, or a
  callback through `array_map` & co. is refused, so an application's one-argument dynamic-call sink
  cannot become "call any function with any arguments" through a crafted program.
- `max_execution_time` ends a virtualized loop like any other (the VM used to swallow the timeout and
  leave the rest of the request unkillable); shutdown functions still run.
- Arguments are copied by value: a reference element in the argument list no longer aliases the
  caller's variable inside the program or in its result.
- The compiler refuses calls to a name the file rebinds with `use function` (any form, including
  group use) and refuses `true`/`false`/`null` rebound with `use const`; it refuses calls to a function
  of the same pack that takes a parameter by reference. Float constants are kept bit-exact, and a
  float-to-string conversion (`.` with a float, a loose comparison of a float with a string) is no
  longer folded at pack time with the packer's `precision`: it runs on the server, as PHP does.
- A call from virtualized code into a user function shows one extra internal frame,
  `__envelock_vm_v2`, in `debug_backtrace()` and exception traces, and a `TypeError` raised there
  loses its "called in <file> on line <n>" suffix; code that inspects its caller through the backtrace
  sees the difference.
The informational `envelock-package.json` also records `vm_compiler_sha256` for new VM packages;
this unsigned field is not authenticated provenance or evidence of correctness. Compare it only to
an independently trusted compiler hash. Packages made before this field existed lack it, and the
loader does not use it. The packer refuses VM together with `--obfuscate-names`; combining VM with other transformations,
including string vault or bytecode, has not established general compatibility. Select only top-level
global functions. Unsupported constructs are refused (nested assignments are accepted since V3), but accepted programs
may still differ from PHP; signatures, calls and defaults are not an equivalence guarantee.

**Compatibility break:** rebuilt loaders refuse legacy V1 and V2 VM programs. The current format is
V3 (`ENVVM3`): plain local operands are read when their operation runs, as PHP does, so
`$a + ($a = 5)` yields 10. Every V2 research program must be repacked from the original source; the
V2 loader accepted programs with eager reads, skipped `else` branches, misordered some operands and
reported undefined-variable warnings late. The loader refuses V2 explicitly. Repacking is currently
only for laboratory use. The header is still `ENVVM3`, but the opcode set grew: a program that uses a dimension chain with a
plain local key (`FETCH_DIM_MIXED`, opcode 0x15) is refused by any V3 loader built before that opcode, as an
unknown opcode. That is the fail-safe direction; rebuild the loader from the same source. Calls to a function use `INIT_CALL` (opcode 0x16, which takes the name, the argument count and the stack width) before the arguments, and `CALL` (0x08) after them; a loader without 0x16 refuses such programs in the same fail-safe way. Only builtins measured to behave the same when called directly are compiled. Refused: the 33 builtins that Zend compiles specially (for example `strlen`, `count`, `gettype`, `is_*`, `intval`, `in_array`, `sprintf`), `min`, `max` and `implode` (their direct call differs from a call through a value, measured on PHP 8.4.27), frame-sensitive functions (`compact`, `extract`, `func_get_args`, `get_defined_vars`, `call_user_func`, `assert`, and others), by-reference parameters, and any call in a file with `strict_types` or a `namespace`. The result of a call is a temporary of rank VAR, so operand order for commutative operators follows PHP. Concatenation with a constant array converts the array where PHP does: `[1, 2] . $undef` warns about the array first, and `$a . [1, 2]` keeps its order. A plain local in the `else` branch of a ternary is copied by an operation of its own in PHP, so a throwing warning stops there; the compiler emits `DUP` and `POP` for it. Constant folding
and operand order follow PHP's rules (checked by the finite deterministic matrix in `scripts/vm_order_matrix.py`: operators, dimension reads and branches, 36 376 cases with no divergence; not a proof) (no folding when PHP would warn or throw; `&`, `|`, `^`, `*` swap their
operands as PHP does). Measured against the previous V3 loader on the same machine: 1.004 on an integer loop and
0.974 on a constant-key dimension read; no measurement exists for the new opcode, which has no earlier baseline.
The bundled prebuilt loader is old, does not support V3, and contains the
unsafe V1 implementation. Do not use it for virtualized packages. Build and deploy the exact
V3-capable loader tested in the laboratory; compatibility with other PHP targets has not been
established.

The VM encodes rather than encrypts logic; execution necessarily exposes it in memory. A single
bounded integer microbenchmark found V2 roughly 23 times slower than native PHP; performance varies
and no universal performance or correctness claim follows. See the roadmap for measurements.

## 15. Updating and rotating keys

For a new version, keep the project UUID and run `pack` to a new destination. The release and content key are renewed. Perform a coherent deployment of the full package, with a controlled operational rollback.

**Refusing old releases.** Each package has a serial (by default the time of `pack` in nanoseconds since the Unix epoch, so later packs are higher; `--serial` sets it). A serial you type yourself must use the same unit: `date +%s` gives *seconds*, about a billion times smaller than a default serial, so a minimum set that way would never refuse anything. After deploying a release, set it as the minimum for its project in the server's identity file and restart PHP; from then on the loader refuses older releases of that project, even well signed (for example an old one with a fixed bug):

```bash
python encoder/envelock.py minimum set --identity /private/folder/identity.bin --package release/client-001/application
# or: --project <project UUID> --serial <number>
```

With `--package`, the project and serial are read from the package's **signed header**, verified against the trusted developers already in that identity file — not from the unsigned `envelock-package.json` — so a tampered or swapped metadata file cannot steer the minimum, and a package signed by a developer the file does not trust is refused. The minimum is then **bound to that developer**: on a host that trusts several developers, it only affects packages signed by the same developer, so one developer cannot set a rollback bar on another's project (a minimum set manually with `--project/--serial` is left unbound and applies to any developer). `inspect` on the identity file shows each minimum with its bound developer, and they are kept by the other identity-file commands. **Lowering an existing minimum is refused** (it would reopen the door to the old releases you meant to block); pass `--allow-downgrade` when you really intend to roll the bar back.

If a recipient's private key is compromised (its identity file):

1. Create a new recipient (`init-recipient`) and its public key (`export-public`).
2. Re-encrypt the projects for the new public key (`pack`).
3. Add the new recipient to the identity file (`recipient add`), deploy the new packages, then remove the exposed one (`recipient remove --recipient <its public or private descriptor>`; the last recipient cannot be removed) and **restart PHP**. **There is no need to recompile** the generic module.
4. Consider what the attacker may have captured as already exposed: rotating does not erase their copies.

If the **primary** signer is compromised (the owner must have been created with `--with-recovery`):

```bash
# 1. The recovery key becomes the primary; a new recovery key is generated.
python encoder/envelock.py owner promote-recovery --owner private/owner.enc.json --out private/owner-2.enc.json
# 2. Sign new releases with owner-2: they already run on every server (the old recovery
#    key was trusted), so packages can be shipped before any server is updated.
# 3. On each server identity file: trust the new developer, then remove the stolen key.
python encoder/envelock.py export-developer --owner private/owner-2.enc.json --out release/developer-2.json
python encoder/envelock.py developer set --identity /private/folder/identity.bin --developer release/developer-2.json
python encoder/envelock.py developer remove --identity /private/folder/identity.bin --developer-id <old developer_id>
```

After step 3 **and a PHP restart**, packages signed with the stolen key are refused. The old owner file still holds the stolen primary key and the new primary (as its recovery key): once `owner-2` works, destroy it or keep it offline with the same care as `owner-2`. `developer remove` refuses to remove the last trusted developer. `inspect` on the identity file lists the `developer_id` of each developer.

To **replace only the recovery key** (lost, or suspected exposed), keeping the primary:

```bash
python encoder/envelock.py owner new-recovery --owner private/owner.enc.json   # in place; same password (an unencrypted file gets encrypted unless --no-encrypt)
python encoder/envelock.py export-developer --owner private/owner.enc.json --out release/developer.json
python encoder/envelock.py developer set --identity /private/folder/identity.bin --developer release/developer.json
```

`developer set` adds the developer, or replaces its recovery key; dropping a trusted recovery key that the descriptor lacks requires `--remove-recovery`. Every identity-file command prints the trusted developers before and after (with their recovery public keys, also shown by `inspect`) and reminds you to **restart PHP**: the change takes effect only then. `recipient add` refuses an owner whose recovery key differs from the trusted one, or that has none while the identity file trusts one (use `developer set`). The developer descriptor is public (no private keys) and can be sent to whoever manages the servers. All of this works without recompiling the loader. There is no online revocation, and no trusted clock to enforce offline expiration against a hostile administrator.

### Deployment integrity: signed manifest and `verify`

`pack --manifest` writes an `envelock-manifest` in the package root: a list of every file with its SHA-256, signed with the owner's key. Later, on the deployed server, check the tree against it:

```bash
envelock verify --package /var/www/myapp-encrypted --developer owner.pub.json
# or: --owner owner.enc.json   (uses its signing public key; no private key is needed to verify)
```

`verify` reports `ok: true` only when the signature is valid and every file is present and unchanged with nothing added; otherwise it lists the `missing`, `added` and `changed` files and exits non-zero. It detects a file deleted, added, modified, or a whole package folder swapped for another. It needs only the **public** developer descriptor (`export-developer`) or the owner file, so you can run it from a deployment script or a scheduled check. This is a check you run; it is not enforced by the loader at run time (an administrator who can write files can also remove the manifest). The manifest contains no secrets.

`verify` reads the JSON `envelock-manifest` written by `pack --manifest`; it does not read the separate **binary** `envelock-manifest.bin` that `--enforce-manifest` writes for the loader (section 14). The two are independent: to get an offline `verify` AND runtime enforcement, pack with both `--manifest` and `--enforce-manifest`. Content tampering of a protected file is always caught at run time by its own authentication tag, with or without either manifest.

## 16. Diagnostics and errors

| Symptom | Probable cause / check |
|---|---|
| `Envelock loader required` | Extension not loaded or file not intercepted. Check `php --ini` and `php --ri envelock`. |
| `no identity configured; set envelock.identity ...` | `envelock.identity` is not set in the `php.ini` of the SAPI actually in use. On PHP-FPM, a per-pool `php_admin_value[envelock.identity]` does not count: it is read once at startup, before pool config applies (section 13). Set it in the shared `php.ini`. |
| `identity file rejected: cannot be opened` | Wrong path, or the user that starts PHP cannot read it (for a CLI script run as an unprivileged user, that user needs its own identity file). On Windows the path may contain non-ASCII characters, from a UTF-8 `php.ini` or from `php -d` (which hands the value over in the system's ANSI code page, so the name must be representable there); the identity, licence and clock-state files are opened through the wide API. A UNC or device path (`\\server\share`, `\\?\…`) is refused — use a local path. |
| `identity file rejected: must be a regular file owned by the PHP user ...` | POSIX: owner = the user that starts PHP (root for PHP-FPM/Apache), mode `0600`. Not the pool user. |
| `identity file rejected: accessible by other accounts or groups ...` / `must be owned by ...` | Windows: set the owner and restrict the ACL with `icacls` (section 11). |
| `identity file rejected: malformed (...)` | Not an Envelock identity file, truncated, or a recipient key pair that does not match. Re-export it with `export-identity`/`recipient add`. |
| `Asset contains private key material` | `pack` refused to copy a key, identity file or private descriptor as an asset (detected by content). Exclude it. |
| `invalid protected file or not addressed to this installation` | File altered/truncated, signature from an untrusted owner, or package addressed to a recipient whose key is not in the identity file. Do not solve it by publishing keys. |
| `invalid protected file size or header` | Container out of bounds, incomplete or of another format version. Repeat the build/transfer and compare hashes. |
| `refused: the file is not at the path it was packaged with` | The file was renamed or moved inside the package, or swapped with another. Deploy the package as produced by `pack`. |
| `refused: files of different releases, projects or developers are mixed in one folder` | Files of two `pack` runs (or two developers) were combined in one package folder. Deploy one release as a whole. |
| `refused: this release is older than the minimum ...` | The identity file sets a higher minimum serial for this project (`minimum set`). Deploy a newer release. |
| `refused: include protection ...` | Package made with `--include-protection` loaded from a script outside it, or from an unencrypted entry point. |
| `refused: auto_prepend_file/auto_append_file are set ...` | Package made with `--no-prepend`; unset those directives (also in `.user.ini`/`.htaccess`). |
| `refuses to load while FFI or dl() is reachable ...` | Package made with `--no-ffi`; set `ffi.enable=0` and `enable_dl=0`, or remove the `ffi` extension. |
| `sealed package: plain PHP under the protected tree is refused` | A plain `.php` under a `--sealed` package folder. Protect every `.php` in the tree (none may be plain), or do not use `--sealed`. |
| `a sealed package is active; eval() is refused` | The protected code (or something it loaded) called `eval()` while a `--sealed` package was active. Remove the `eval()`, or do not use `--sealed`. |
| `manifest enforcement: ... is missing` / `... malformed` / `not signed by a trusted developer` | A `--enforce-manifest` package is incomplete (a listed file was deleted), or `envelock-manifest.bin` is gone, altered or signed by an untrusted key. Redeploy the whole package as one unit. |
| `... is loaded and can dump or trace the decrypted code` | Xdebug, VLD, uopz, runkit7 or phpdbg in use. Remove it, or set `envelock.allow_debuggers=1`. |
| `OPcache is enabled; ...` | OPcache SHM cache on without opt-in. Disable it in `php.ini`, or set `envelock.allow_opcache=1` + `opcache.blacklist_filename` on the protected tree. |
| `another extension installed a compile hook above Envelock's ...` | An extension loaded after Envelock hooks PHP's compiler: typically ionCube Loader or SourceGuardian (remove them from that PHP). Loaders built before 2026-11-11 also gave this for OPcache switched off per directory, vhost or pool, and for Debian/Ubuntu's Phar module (HOST-1, HOST-6): install the current loader. [HOSTING.md](HOSTING.md) §3.3–3.4. |
| `OPcache is about to cache this protected file ...` | `allow_opcache=1` but the protected tree is not in `opcache.blacklist_filename` (or the pattern is wrong). Add its real path to the blacklist, or disable OPcache. |
| `zend.multibyte must be off ...` | `zend.multibyte` is on (perhaps via `.user.ini`/`.htaccess`). Turn it off for the protected app. |
| `disable opcache.file_cache ...` | `opcache.file_cache`/`file_cache_only`/`preload` active; always refused. Unset them in the effective SAPI. |
| `Unable to load dynamic library` | Incorrect ABI/TS/CPU/toolchain, missing dependency, or permissions/path. On Linux, ``version `GLIBC_2.38' not found`` means the system is too old for the prebuilt loader (build it on the server) and `libssl.so.3: cannot open shared object file` means the OpenSSL 3 runtime is missing: [HOSTING.md](HOSTING.md) §2.2. |
| Incorrect password/altered configuration | Different password or modified encrypted JSON. Restore a verified copy. |
| `Asset contains readable PHP` | An asset with code not selected as PHP. Choose the appropriate `--php-ext` or exclude it. |
| Non-portable path/collision | Reserved name, case-only differences, or Unicode. Rename at the source. |
| Destination already exists | Use a new destination; do not delete a live installation to skip the check. |

The stub's message without a loader ends execution, but it currently uses `exit(message)` and may return process code 0. Do not use it as a healthcheck. To check loading, use `php --ri envelock` and a functional test of the project.

Do not enable source dumps, debuggers, or instrumentation extensions in production if your goal is to raise the difficulty of extraction (the known ones make protected files fail closed unless `envelock.allow_debuggers=1`). FFI, `dl()`, and other capabilities should be adjusted to the real needs and the threat model; a package built with `--no-ffi` fails closed while either is reachable, and one built with `--sealed` refuses plain PHP under its tree and `eval()` while it is active. An administrator can re-enable them; it is not an absolute defense.

## 17. Testing and auditing

```bash
python -m pytest -q tests
ENVELOCK_REQUIRE_NATIVE=1 python -m pytest -q tests
python -m ruff check .
python scripts/check_release.py
python -m bandit -r encoder
python -m pip_audit -r requirements.txt
bash scripts/audit-native.sh /absolute/path/new-audit
```

The additional review tools are pinned in `requirements-dev.txt`. The native analysis requires clang with libFuzzer/ASan/UBSan and PHP headers. The included campaign is bounded, not a formal proof or unlimited fuzzing.

To test an already-compiled module, `ENVELOCK_TEST_EXTENSION`, `ENVELOCK_TEST_OWNER`, and `ENVELOCK_TEST_RECIPIENT` are supported. The suite creates the identity file from that owner and recipient. Configure them in a private environment. The tests generate example code and never need your commercial source.

Every file under `third_party/` is checked against `third_party/SHA256SUMS` by `scripts/check_release.py`, so a swapped, edited or re-encoded vendored file fails the release check rather than shipping. `third_party/README.md` records what each vendored package is, its version, its licence, the exact commit it was imported from and how to re-import a newer one.

The vendored parser (`third_party/php-parser`, `nikic/php-parser` 5.9.0, BSD-3-Clause) is used only on the owner's machine at pack time by the experimental AST name pass; it is not part of a protected deployment. It needs PHP's tokenizer. On PHP builds where tokenizer is a shared extension, `php -n` can omit it and the parser can fail with `Undefined constant "T_THROW"`; use a PHP CLI with tokenizer enabled.

The differential fuzzers compare execution output, not just successful parsing. The general fuzzer opts into the experimental pass for namespaced cases and reports how many were actually renamed; `fuzz_ast_names.py` exercises multi-file imports, aliases, casing, constants and identity-related refusals, with `--allowlist` testing random strict subsets. `fuzz_name_observers.py` exercises assembled names passed to known dynamic observers in both global and namespaced code. They are bounded tests, not proof that an arbitrary application is closed.

```bash
python3 scripts/fuzz_obfuscator.py --count 500 --seed 3
python3 scripts/fuzz_ast_names.py --count 200 --seed 73 --allowlist
python3 scripts/fuzz_name_observers.py --count 300 --seed 113
python3 scripts/bench_ast_names.py --samples 30 --iterations 400000 --allowlist
```

The allowlist benchmark compares two arms that both rename the same class; without `--allowlist`, the baseline declines the namespaced pack and therefore is not an equal-work comparison. It is a microbenchmark, not proof of application-wide performance.

For exact results and scope see `AUDITORIA.md` and `VERIFICACION.md`. Do not interpret "no findings from a tool" as "no bugs".

## 18. Publish the repository and generate artifacts

Publish from git (`git push`, or `git archive` for a ZIP), never by compressing your working folder: it holds `private/`, `release/` and other local material that git ignores. Run `python scripts/check_release.py` first. In a live git checkout it skips the working folders that `.gitignore` excludes (and `.git`, virtualenvs and caches); in any other tree — an unpacked archive, a staged release — it scans and reports them, so a stray `private/` or cache folder cannot ship unnoticed. Before the first commit:

```bash
git init
git status --short --ignored
# Review contents and secrets before adding files.
git add envelock envelock.cmd README.md LICENSE NOTICE AUTHORS CHANGELOG.md CONTRIBUTING.md SECURITY.md .gitignore .gitattributes .github docs encoder extension gui scripts tests third_party prebuilt requirements.txt requirements-dev.txt requirements.lock requirements-dev.lock pyproject.toml CMakeLists.txt examples
python scripts/check_release.py   # also checks third_party/ and prebuilt/ against their SHA256SUMS
git diff --cached --stat
# Also review the diff's content, not just its names.
git commit -m "Initial Envelock experimental release"
```

Then add YOUR repository's URL as a remote and publish according to your policy. No remote repository has been published in this session.

The workflow uses pinned action references and builds with **public demonstration keys**. It generates artifacts per OS/PHP/TS. Trigger it from Actions or via a push; download each artifact and examine logs/tests before announcing support. Do not trust a green check if there are omitted combinations or skipped tests.

Do not inject production keys into public pull request jobs or unreviewed code. For production, use private runners or a controlled build environment and restrict access to its artifacts. Do not upload PDBs/private headers/logs indiscriminately. The default workflow does not publish a commercial release or upload secrets in this release.

Review dependencies, actions, and licenses regularly. Edit the copyright/security contact with your real data before publishing. Maintaining a protection project requires ongoing maintenance.

## 19. Production checklist

- [ ] Demonstrated support for each announced OS, PHP minor, CPU, TS/NTS, and SAPI.
- [ ] Original application compatible with the minimum PHP.
- [ ] Tests on the real application, errors, concurrency, stress, and recovery.
- [ ] Independent audit of the C/Zend, cryptography, packaging, and distribution.
- [ ] New identities, never the `DEMO_ONLY` ones.
- [ ] Keys/password outside the repository, webroot, and client package.
- [ ] Verified runtime dependencies and legal redistribution.
- [ ] OPcache off for the protected tree, or opt-in + blacklist verified with `opcache_get_status()`; preload/file_cache off.
- [ ] Minimum serial set for each deployed project (`minimum set`); PHP restarted after the last identity-file change.
- [ ] `--include-protection` and `--no-prepend` used where the entry points are protected; `--no-ffi` where the app needs neither FFI nor `dl()`; `--sealed` where every `.php` in the tree is protected and the app does not use `eval()`; `--enforce-manifest` to detect a missing file at runtime; no debugging extensions loaded.
- [ ] Only your own code encrypted (framework/`vendor` left to OPcache); `memory_limit` and `pm.max_children` sized with the measured memory per request.
- [ ] Verified permissions/ACLs and client separation.
- [ ] No PDBs, backups, repositories, or assets with private logic exposed.
- [ ] Verified binary hashes and provenance; code signing where appropriate.
- [ ] Defined policy for updates, key rotation, and incidents.
- [ ] Clients informed that there is no absolute protection against whoever controls the server.

## 20. Frequently asked questions

**Can it run completely offline?** Yes. Installing the tools may require downloads, but the loader does not contact external services.

**Does an encrypted file work on the three systems?** Its format does. It needs the loader of the same installation compiled for that system and an application compatible with that PHP.

**Can I change the key without recompiling?** Yes. The loader is generic: changing the recipient or the trusted signer only requires updating the server identity file (`recipient add/remove`, `developer set/remove`) and restarting PHP; there is no need to recompile. You can also renew the content key with each `pack`.

**Does it work with OPcache?** By default protected files are refused when OPcache's SHM cache is on (fail closed), because OPcache would cache the decrypted opcodes. You can opt in with `envelock.allow_opcache=1` **and** exclude the protected tree via `opcache.blacklist_filename`: then protected files run with OPcache on and are not cached (verify with `opcache_get_status()`), while the rest of the app benefits from OPcache. `opcache.file_cache` and preloading are always refused (they persist decrypted opcodes). If you set `allow_opcache=1` but the blacklist is missing or wrong, the loader fails closed on the first request (it detects OPcache is about to cache the file) rather than caching decrypted opcodes silently; the blacklist is still what lets the protected tree run with OPcache on. Blacklisted protected files are re-decrypted per request; a per-worker cache is future work.

**How much does the encryption cost?** Measured: about 230–260 µs additional per file compared to PHP without encryption (files of ~2 KB, PHP 8.2–8.5; `scripts/bench.py` reproduces it). Detail and conditions in [VERIFICACION.md](VERIFICACION.md#measured-performance). Measure with your real application; fewer and larger files reduce the cost.

**Does it use more memory?** Envelock itself, almost none (same PHP memory as plain code without OPcache, no leaks). But protected files are not cached by OPcache, so their compiled code is rebuilt in every request's memory: in a large project that can mean tens of MB per request more than with OPcache. Encrypt only your own code and size `memory_limit` and PHP-FPM accordingly (section 14, and [VERIFICACION.md](VERIFICACION.md#measured-memory)).

**Does one client compromise all of them?** Each recipient has its own key. Compromising a server's identity file exposes the projects whose keys it contains, not those of others. But recovering the common source distributed to one client reveals that same common logic; the independence of keys does not change that fact.

**Does publishing the encoder/loader automatically reveal my application's source?** No. The loader is public and generic: it contains no keys. By itself it decrypts nothing; the recipient's private key is required, which you keep outside. No advanced resistance to reverse-engineering of the already-decrypted source in memory is promised.

**Can I ensure that no one sees the source?** Not against the administrator who controls its execution. If that requirement is absolute, this offline PHP-decryption architecture does not satisfy it.

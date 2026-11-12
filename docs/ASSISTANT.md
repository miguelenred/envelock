# Envelock assistant: graphical guide and command-line equivalents

The assistant is a window (Spanish or English) that runs the whole Envelock flow without the
console. It calls the same encoder code as the command line, so **everything it does can also be
done with commands**; this guide gives, for every button, the exact equivalent command.

All file and folder names below are only examples (the assistant suggests them); use your own.

## 1. Start the assistant

| How | Command |
|---|---|
| Standalone executable | Shipped in the complete distribution under `prebuilt/assistant/` (Linux and Windows); the source-only distribution has none, build it first. Run `envelock-assistant` (Linux/macOS) or `envelock-assistant.exe` (Windows) |
| From source | `python gui/envelock_gui.py` (after installing the encoder, see [MANUAL](MANUAL.md) §4; on Linux also `python3-tk`) |
| Build the executable | `bash scripts/build-gui.sh` (one per OS; Windows can be built under Wine, see [BUILDING](BUILDING.md) §5) |

The language selector (*Language* / *Idioma*) is at the top of the window. The executable also accepts `--selftest`
(builds the window and exits) and `--e2e <folder>` (creates test keys and encrypts a small project
in that folder, without a window).

Command-line equivalents below use `python encoder/envelock.py …` from the repository root,
after installing the requirements. The optional launchers use the portable Python in
`prebuilt/python/`, shipped in the complete distribution (not in the source-only one).

### Passwords

Private keys (owner, recipient) are saved **encrypted with a password of at least 16 characters**
unless you untick *Encrypt the file with a password* (command line: `--no-encrypt`, not
recommended). The assistant asks for each password in a dialog. The command line asks in the
terminal, or reads it from the file named by `ENVELOCK_PASSWORD_FILE` (permissions `0600` on
Linux/macOS; the same password is then used for every key, so when your keys have different
passwords, run the commands interactively).

### Which file goes where

When you choose a file with *Browse*, the assistant checks what it is and warns you if it is the
wrong one (for example an owner where a server public key is expected). Each label shows the
expected extension.

| File (example name) | What it is | Where it goes |
|---|---|---|
| `owner.enc.json` | Your signing key (owner), private | Only on your machine, with a backup |
| `servidor1.enc.json` | A server's key (recipient), private | Your machine; used only to build that server's identity file |
| `servidor1.pub.json` | That server's public key | Used when encrypting; may be shared |
| `developer.json` | Your public developer descriptor | Used to trust your signer in identity files |
| `identity-servidor1.bin` | The server identity file, **secret** | Only on that server (see [MANUAL](MANUAL.md) §10–12) |

## 2. Keys tab

Create your keys once. The owner signs; each server has its own recipient key.

| Box | What to fill in | Command equivalent |
|---|---|---|
| **Create signing key (owner)** | *Save to* `owner.enc.json`; *Also create a recovery key* (recommended, ticked) | `python encoder/envelock.py init-owner --out owner.enc.json --with-recovery` |
| **Create server key (recipient)** | *Save to* `servidor1.enc.json`; *Label* `servidor1` (the file name follows the label) | `python encoder/envelock.py init-recipient --out servidor1.enc.json --label servidor1` |
| **Export public key (from a recipient)** | *Recipient file* `servidor1.enc.json`; *Save to* `servidor1.pub.json` | `python encoder/envelock.py export-public --recipient servidor1.enc.json --out servidor1.pub.json` |
| **Export developer descriptor (from owner)** | *Signing key* `owner.enc.json`; *Save to* `developer.json` | `python encoder/envelock.py export-developer --owner owner.enc.json --out developer.json` |

Repeat *Create server key* and *Export public key* for every server (`servidor2`, …).

## 3. Encrypt a project tab

| Field | What to fill in | Command option |
|---|---|---|
| Signing key (owner) | `owner.enc.json` | `--owner owner.enc.json` |
| Server public keys | *Add* every target server's `.pub.json` (not the private `.enc.json`) | one `--recipient servidor1.pub.json` per server |
| Project ID | *New* the first time; **reuse the same ID for later releases** of the project | `--project <UUID>` (get one with `python encoder/envelock.py new-project`) |
| Project folder | your PHP source folder | `--source ./miapp` |
| Output folder (new) | suggested as `"<project> cifrado"`; must not exist, or be empty | `--output "./miapp cifrado"` |
| Remove comments | optional; less memory, breaks code that reads docblocks (annotations) | `--strip-comments` |
| Obfuscate local variables | optional | `--obfuscate` |
| Compact (remove formatting; no line numbers) | optional; collapses whitespace and comments to single spaces, so error line numbers are not preserved | `--compact` |
| Encode string literals (hide SQL, messages, paths) | optional; re-spells string literals as `\xNN` (same value); enlarges string-heavy files | `--encode-strings` |
| Rename private methods (test the package) | optional; renames private methods reached only via `$this->`/`self::`/`static::`; skips anything dynamic or used as a string | `--obfuscate-methods` |
| Rename private properties (HIGH RISK) | optional; renames private instance properties used only as `$this->name`; **breaks data serialized before obfuscation** (sessions/caches); skips classes that serialize or use Reflection | `--obfuscate-properties` |
| Obfuscate control flow | optional; inserts an always-false opaque-predicate dead branch per function/method (modest; behaviour and line numbers unchanged; functions using `goto` skipped) | `--obfuscate-flow` |
| Flatten control flow (O6) | optional; rewrites plain function/method bodies into a dispatch loop (`switch` in `while`); generators, `goto`, nested declarations, dynamic variables, `compact`/`extract`/`get_defined_vars`, `include`/`eval` left as written; not combinable with virtualization | `--obfuscate-flatten` |
| Vault string literals | optional; moves runtime-position string literals into a per-file vault the loader resolves, so they are not kept as constants in the compiled code; literals in constant expressions stay inline | `--vault-strings` |
| Include protection | optional; protected files run only as the entry point or from protected code of the same project | `--include-protection` |
| Refuse auto_prepend/append | optional | `--no-prepend` |
| Refuse FFI/dl() | optional; refuses to run while FFI or `dl()` is reachable (they can read the decrypted code from memory); only for apps that need neither | `--no-ffi` |
| Sealed tree | optional; refuses any plain PHP under the package folder and `eval()` while the package is active; only when every `.php` in the tree is protected and the app does not use `eval()` | `--sealed` |
| Signed manifest at runtime | **on by default** (checkbox checked); writes a signed binary manifest the loader checks on load, refusing to run if any listed file is missing (deletion detection) and enabling the ~5× manifest fast path (on servers that trust a single developer). Uncheck it to opt out | default; `--no-manifest` to opt out (explicit form: `--enforce-manifest`) |
| Exclude | comma-separated patterns, e.g. `vendor/*, tests/*` | one `--exclude 'vendor/*'` per pattern |
| Copy as-is | comma-separated patterns, e.g. `*.css, *.png` | one `--asset '*.css'` per pattern |
| PHP 8 | needed only for the first two options (see §7) | `--php C:\php\php.exe` |

Press **Run**. The release number (serial) is the current time, as in the command line without
`--serial`. Full command equivalent:

```bash
python encoder/envelock.py new-project            # once per project; keep the UUID
python encoder/envelock.py pack --owner owner.enc.json --recipient servidor1.pub.json --recipient servidor2.pub.json \
  --project <UUID> --source ./miapp --output "./miapp cifrado" \
  --exclude 'vendor/*' --exclude 'tests/*' --asset '*.css' --asset '*.png' \
  --strip-comments --obfuscate --compact --encode-strings --obfuscate-methods --php php --include-protection --no-prepend
```

The command line also has `--php-ext .module` (extra PHP extensions) and `--serial <n>`, which the
assistant does not show. Deploy the output folder; leave `vendor/` out of the encryption and
deploy it separately ([MANUAL](MANUAL.md) §14).

Not sure which options to turn on? Use the **Recommend tab** (next section) first.

## 4. Recommend tab

Choose the project's source folder and press **Analyse and recommend**. The assistant analyses the
tree and shows the **strongest protection that is safe for it**, with every protection option of
`pack` in one of three groups:

- **Enable** — safe for this project as far as the analysis can see.
- **Enable, but check first** — recommended, but whether it works depends on something the analysis
  cannot see: the server's `php.ini` (`--no-ffi`, `--no-prepend`), its PHP build and your pack-time
  setup (`--bytecode`), whether the whole application is in the package (`--include-protection`), code
  that dispatches by names built at run time (`--obfuscate-methods`), libraries that read docblocks
  (`--strip-comments`, `--compact`; it names the one it finds in `vendor/`), or PHP the app writes at
  run time (`--sealed`). Each says why it is unsure and how to check (often:
  `scripts/envelock-preflight.php` on the server); drop any you cannot confirm.
- **Do not enable** — with the reason for each, including the options it never recommends on its own
  (`--obfuscate-properties`, `--vault-strings`, `--obfuscate-flatten`, `--obfuscate-names`,
  `--virtualize`), and where an option *might* work it says so and how to try it.

It also lists any files to keep cleartext (`--exclude`) because they read
their own source, and prints a ready-to-fill `pack` command. It is read-only and changes nothing. It
never recommends an option known to break a project (for example `--obfuscate-properties`, which breaks
the Composer autoloader, or `--sealed` when the code uses `eval()`). For a framework application it leaves
`vendor/` (Composer) and the run-time caches out of the encryption, keeps Blade templates cleartext, turns
`--include-protection` off when a console entry point (`artisan`, `bin/console`) would stay unencrypted,
and lists what the server's `php.ini` must allow for `--no-ffi`, `--no-prepend` and `--bytecode`. Its
suggested command was run as printed on real Laravel and Symfony apps (Windows 11, PHP 8.4): every web
route and the console matched the unprotected app. Command equivalent:
`python encoder/envelock.py recommend --source <folder>` (add `--json` for machine-readable output).
Always test the packaged app like a real release before deploying.

## 5. Server identity tab

Builds and maintains the secret `.bin` that goes on each server. The *Identity file* field at the
top (`identity-servidor1.bin`) applies to every box. After any change, copy the `.bin` to the
server and restart PHP there.

| Box | What to fill in | Command equivalent |
|---|---|---|
| **Build the server identity** | *Recipient file* `servidor1.enc.json` (private) and *Signing key* `owner.enc.json`; asks for both passwords; creates the file or adds to it | `python encoder/envelock.py recipient add --identity identity-servidor1.bin --recipient servidor1.enc.json --owner owner.enc.json` |
| **Add/update trusted developer** | *Developer descriptor* `developer.json` (also updates its recovery key after a rotation) | `python encoder/envelock.py developer set --identity identity-servidor1.bin --developer developer.json` |
| **Remove recipient** | *Server public key* `servidor1.pub.json` (the last recipient cannot be removed) | `python encoder/envelock.py recipient remove --identity identity-servidor1.bin --recipient servidor1.pub.json` |
| **Remove developer (by id)** | the `developer_id` shown by *Inspect* on the `.bin` (the last developer cannot be removed) | `python encoder/envelock.py developer remove --identity identity-servidor1.bin --developer-id <id>` |
| **Refuse releases older than a package** | *Packaged folder*: an encrypted output folder; the project and serial are read from its signed header (verified against the identity's trusted developers), and older releases of that project stop running on this server. *Allow lowering an existing minimum*: only when you mean to roll the bar back | `python encoder/envelock.py minimum set --identity identity-servidor1.bin --package "./miapp cifrado"` (or `--project <UUID> --serial <n>`; add `--allow-downgrade` to lower) |

The command line also has `developer set --remove-recovery`, which the assistant does not show.

## 6. Key rotation tab

| Box | When | Command equivalent |
|---|---|---|
| **Replace the recovery key (in place)** | the recovery key was lost or exposed; updates `owner.enc.json` | `python encoder/envelock.py owner new-recovery --owner owner.enc.json` |
| **Primary stolen: promote the recovery key** | the primary key was stolen; *New owner file* `owner-nuevo.enc.json` | `python encoder/envelock.py owner promote-recovery --owner owner.enc.json --out owner-nuevo.enc.json` |

After a rotation, export the new developer descriptor (Keys tab) and update every identity file
(*Add/update trusted developer*). The full procedure is in [MANUAL](MANUAL.md) §15.

## 7. Inspect tab

Choose an encrypted file, an identity file (`.bin`) or a key/descriptor (`.json`) and press
**Inspect**: it shows only non-secret metadata (project, release, recipients, developers,
minimum releases). Command equivalent: `python encoder/envelock.py inspect <file>`.

## 8. When PHP 8 is missing

*Remove comments*, *Obfuscate local variables*, *Compact*, *Encode string literals*, *Rename private methods*, *Rename private properties*, *Obfuscate control flow* and *Vault string literals* run a PHP 8 CLI with the `tokenizer` extension.
At start-up the assistant looks for one — a PHP it downloaded earlier, then the absolute folders of
`PATH` (never the current folder) — and fills the *PHP 8* field. PHP installs in the usual folders
(WampServer, XAMPP, Laragon, `C:\php`, Homebrew, `/usr/bin`) are listed for you to choose with
*Browse*, never run on their own: such folders can be created by any local user.
When you press **Run** with one of those options ticked and no usable PHP:

- **Windows**: it offers to download the official PHP 8 (NTS x64) from php.net. It reads the
  official release index, downloads the ZIP (about 35 MB) over HTTPS only (a redirect away from
  HTTPS is refused), **checks its SHA-256 against that same index** — which proves the file is
  complete and unaltered, not that it is signed — extracts it safely and saves it **next to the
  assistant**, in `php\<version>\`. If that
  folder is protected (for example under `Program Files`), it asks to use
  `%LOCALAPPDATA%\Envelock\php\<version>\` instead. Then it fills the field and continues. Nothing
  is downloaded without your answer.
- **Windows, PHP will not start** because Microsoft's *Visual C++ Redistributable* is missing: it
  offers to download it from Microsoft, **runs it only if its digital signature is valid and
  belongs to Microsoft**, and Windows asks for administrator permission.
- **Linux/macOS**: it shows the install command for your system (for example
  `sudo apt install php-cli`, `sudo dnf install php-cli`, `sudo pacman -S php` or
  `brew install php`); install it and press Run again.

Command-line equivalent: install PHP 8 yourself and pass it with `--php`:

- Windows: download the *VS17 x64 Non Thread Safe* ZIP from the official PHP for Windows
  downloads page, check its SHA-256, extract it (e.g. to `C:\php`) and use
  `--php C:\php\php.exe`. If `php.exe` does not start, install Microsoft's *Visual C++
  Redistributable (x64)*.
- Linux/macOS: install the PHP CLI package with your package manager and use `--php php`.

Check it with `php -r "echo PHP_VERSION, function_exists('token_get_all') ? ' ok' : ' no tokenizer';"`.

## 9. Errors you may see

| Message | Meaning |
|---|---|
| *That file looks like … Here you must choose …* | wrong file in that field (see the table in §1) |
| *… is encrypted: a password is required* | an encrypted key was given where no password is asked; use the `.pub.json` instead |
| *The output folder already exists and is not empty* | choose a new folder, or empty it |
| *Refusing to remove the last recipient/developer* | an identity file always keeps at least one of each |

Other loader and server errors are explained in [MANUAL](MANUAL.md) §16.

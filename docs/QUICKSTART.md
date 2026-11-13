# Quick start: encrypt your PHP project, step by step

This is the shortest path from a normal PHP project to an **encrypted package** that
runs on your server. Every command here is real; the deeper options live in the
[full manual](MANUAL.md).

If you prefer not to use the terminal, the **graphical assistant** does this whole flow
with buttons: `python gui/envelock_gui.py` (see the [assistant guide](ASSISTANT.md), which
shows the equivalent command for every button). This guide is the command-line version.

---

## What you are about to do

Envelock has two sides:

- **Your packaging machine** (your laptop): holds your **private keys** and runs the
  encoder that turns `.php` files into encrypted, signed packages.
- **The server**: runs the **loader** (a generic PHP extension with *no* keys in it) plus a
  small **secret identity file** that lets *only that server* decrypt packages meant for it.

So the plan is: create your keys once, encrypt your project, then put three things on the
server — the loader, the identity file, and the encrypted package.

```
 packaging machine                              server
 ┌───────────────────────────┐                 ┌──────────────────────────────┐
 │ owner key   (you sign)     │   encrypt       │ loader  (generic extension)  │
 │ recipient key (the server) │  ───pack──▶     │ identity.bin (secret)        │
 │ your PHP source            │   copy over     │ encrypted package            │
 └───────────────────────────┘                 └──────────────────────────────┘
```

> **What this protects, and what it does not.** Envelock keeps your source unreadable at rest
> and in transit to the server, and stops a different developer's keys (or the plain PHP engine)
> from opening it. It does **not** hide the code from someone with root/Administrator on the
> server, who can read process memory. See [SEGURIDAD.md](SEGURIDAD.md).

---

## Before you start

On the **packaging machine** you need **Python 3.10 or newer**. On the **server** you need
**PHP 8.2–8.5**. The encoder does not change your PHP syntax: if you pack for PHP 8.2, your
app must already run on PHP 8.2.

Pick a working layout like this and `cd` into your Envelock checkout:

```
private/   # SECRET: your keys never leave the packaging machine
release/   # what you hand out: public keys and encrypted packages
```

---

## Step 1 — Install the encoder (packaging machine)

```bash
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
python -m pip install --require-hashes -r requirements.lock
```

`--require-hashes` pins every dependency to the exact version in `requirements.lock`, so you
install the same audited code every time.

---

## Step 2 — Create your signing identity (the "owner")

This is the key that **signs** your packages so the server can trust they came from you.
It is private — never distribute it.

```bash
python encoder/envelock.py init-owner --out private/owner.enc.json --with-recovery
```

You will be asked for a password; it encrypts the key file on disk. (For an unattended run,
put the password in a file and point `ENVELOCK_PASSWORD_FILE` at it.) `--with-recovery` adds a
spare key so you can rotate the signing key later without rebuilding anything.

---

## Step 3 — Create the recipient and its public key (one per server)

The **recipient** is the identity that will be able to *decrypt* — think of it as "this
server". Create it, then export its **public** key, which is the only part you need to encrypt.

```bash
python encoder/envelock.py init-recipient --out private/server-001.enc.json --label server-001
python encoder/envelock.py export-public  --recipient private/server-001.enc.json \
                                          --out release/server-001.pub.json
```

> **Personal mode:** if the same machine both packs and runs the code, the recipient is just
> *you* — the steps are identical.

---

## Step 4 — Get a project ID

A package is tied to a **project UUID**. Generate one and **keep it**: reuse the same UUID for
every future release of the same project (it is how anti-rollback and "minimum version" work).

```bash
python encoder/envelock.py new-project
# → prints a UUID like 752581f8-d239-44f6-a85e-49a892040ca8
```

---

## Step 5 — Check your project first (optional, recommended)

Two read-only commands that change nothing:

```bash
# Flags code that reads its OWN source at run time (annotations, class maps…) and would break:
python encoder/envelock.py preflight --source path/to/your-app

# Suggests the strongest protection that is still SAFE for this specific project, and why:
python encoder/envelock.py recommend --source path/to/your-app
```

Fix anything `preflight` reports before you encrypt.

---

## Step 6 — Encrypt your project

```bash
python encoder/envelock.py pack \
  --owner     private/owner.enc.json \
  --recipient release/server-001.pub.json \
  --project   752581f8-d239-44f6-a85e-49a892040ca8 \
  --source    path/to/your-app \
  --output    release/server-001/your-app
```

What to know:

- By default `pack` encrypts `.php`, `.phtml`, `.inc` and `.php8`. **Other files are not copied**
  unless you ask: add `--asset "public/**"` (repeatable) for images, CSS, templates, etc.
- `pack` never overwrites an existing `--output`, and source and output cannot be nested.
- Encrypt for several servers at once by repeating `--recipient`.
- A signed **manifest** is written by default (detects a deleted or swapped file); keep the
  packed folder together as one unit.

That is it — `release/server-001/your-app` now contains your project with no readable PHP.

---

## Step 7 — Install the loader on the server

The loader is **generic**: the same binary serves any identity. The easiest install is
[PIE](https://github.com/php/pie), which picks the right prebuilt binary for the server's PHP:

```bash
pie install envelock/loader
```

No PIE, or an unusual platform? Build it from source — see
[HOSTING.md](HOSTING.md) (what each kind of hosting allows) and
[BUILDING.md](BUILDING.md). You can check a server before deploying with
`scripts/envelock-preflight.php`.

---

## Step 8 — Give the server its secret identity file

The server needs one small file that holds its recipient **private** key plus the developer it
trusts (your owner public key). Build it on your trusted machine:

```bash
python encoder/envelock.py export-identity \
  --recipient private/server-001.enc.json \
  --owner     private/owner.enc.json \
  --out       private/identity.bin
```

Then put it on the server, readable only by the PHP process. On the server itself you can
install it safely in one step (root-owned, mode 0400):

```bash
python encoder/envelock.py server-install \
  --recipient private/server-001.enc.json \
  --owner     private/owner.enc.json \
  --out       /etc/envelock/identity.bin
```

Finally, point `php.ini` at the loader and the identity file:

```ini
extension=envelock
envelock.identity=/etc/envelock/identity.bin
```

(If PIE enabled the extension for you, you only need the `envelock.identity` line.)

---

## Step 9 — Deploy and verify

Copy the encrypted folder from Step 6 to the server and run it as you normally would. For a
quick one-off check without touching `php.ini`:

```bash
php -n -d opcache.enable=0 -d opcache.enable_cli=0 \
  -d extension="$PWD/release/envelock.so" \
  -d envelock.identity="$PWD/private/identity.bin" \
  release/server-001/your-app/index.php
```

If the page renders, you are done. A package addressed to a different key, or a tampered file,
is **refused** — that is the point.

---

## Keep these secret — never commit them

`owner*.json`, `recipient*.json`, every `identity*.bin`, your passwords and any private source.
`.gitignore` helps but is not a substitute for reviewing what you commit. The public key
(`*.pub.json`) and the encrypted package are the only things meant to leave the packaging machine.

---

## Going further (stronger protection)

The command in Step 6 is the safe default. When you are ready for more, `recommend` (Step 5)
tells you which of these are safe for *your* code; all are detailed in [MANUAL.md](MANUAL.md):

- `--strip-comments`, `--compact`, `--obfuscate`, `--encode-strings` — shrink and obscure the source.
- `--vault-strings` — keep string literals out of the compiled image.
- `--bytecode` — ship precompiled bytecode so the server never handles PHP source at all
  (requires the server's exact PHP build).
- `--sealed`, `--no-ffi`, `--no-prepend`, `--include-protection` — lock down how the package may run.
- Signed deployment **licences** with expiry or machine binding (`licence issue`), and
  anti-rollback (`minimum set`).

Always test a protected package against your real application before relying on it.

---

## If something goes wrong

| Symptom | Likely cause |
|---|---|
| A file 404s or an asset is missing | It was not `.php` and not copied — add `--asset` for it in Step 6. |
| The loader refuses the package | The server's `identity.bin` does not match the recipient you packed for, or the file was tampered with. |
| `pack` refuses to run | `--output` already exists, or source/output are nested — use a fresh output folder. |
| Something reads its own file and breaks | `preflight` (Step 5) lists these; they are not compatible with encryption. |
| Need more detail on your hosting | See [HOSTING.md](HOSTING.md) and run `scripts/envelock-preflight.php` on the server. |

---

More depth, every option and the security model: **[MANUAL.md](MANUAL.md)** ·
**[HOSTING.md](HOSTING.md)** · **[SEGURIDAD.md](SEGURIDAD.md)**.

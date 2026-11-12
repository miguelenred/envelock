# Deploying a real application protected with Envelock

Envelock protects **PHP code**. A real application (a CMS, a framework) is more than code: it is also
assets (CSS, JS, JSON, images, fonts), a configuration file, and a writable area. A deployable tree
is the encrypted `.php` files **plus** everything else, laid out exactly as the application expects.

This recipe was validated end-to-end on a full WordPress core (2086 PHP files): both as source-cipher
and as bytecode, the protected site produced byte-for-byte identical output to the unencrypted
original. The same five points apply to any application.

## 1. Encrypt the PHP, carry the assets unchanged

`pack_tree` encrypts files it recognises as PHP and **does not copy the rest**. A package built from a
CMS core therefore contains the encrypted `.php` and nothing else — no `.css`, `.js`, `.json`, images
or fonts — and the application renders blank or half-rendered because it cannot find them.

Deploy the encrypted PHP over a full copy of the application, so every non-PHP asset is present and
untouched next to it. For example, after packing into `dist/`:

```sh
# bring every non-PHP file across, unchanged, without touching the encrypted .php
rsync -a --exclude='*.php' app/ dist/
```

`pack_tree(..., assets=[...])` can also copy named asset patterns into the package instead.

## 2. Keep the configuration file out of the package

The configuration file (`wp-config.php`, `.env`, `config/config.php`, …) holds secrets and is written
per server. It must **not** be encrypted or shipped. Pass it to `exclude` so `pack_tree` leaves it out
of the package, and deploy the real one, unencrypted, on the server:

```python
pack_tree(src, dst, recipients, owner, project, exclude=['wp-config.php'])
```

Note `exclude` means *not in the package* (not "copied in cleartext"): place the real config file on
the server yourself.

## 3. Run the loader with OPcache off (or blacklisted)

Protected files are refused under OPcache's shared memory by default — fail-closed, so decrypted code
is never cached between requests. Either disable OPcache — in `php.ini`, or only for the protected
site (vhost or FPM pool `php_admin_flag`, `.user.ini`), which loaders built from 2026-11-11 on accept
(earlier ones refused it: HOST-1, `docs/HOSTING.md` §3.3) — or allow coexistence explicitly.

```ini
; simplest: no OPcache for this site (php.ini, the vhost/pool, or a .user.ini in the site)
opcache.enable = 0

; or: keep OPcache for unprotected code, exclude the protected tree
envelock.allow_opcache = 1
opcache.blacklist_filename = /path/to/envelock-opcache.blacklist
```

## 4. Bytecode packages are bound to their deploy path

With `--bytecode`, `__DIR__`, `__FILE__` and statically resolved include paths are baked into the
compiled op_array, so the package must be **compiled for the path it will run from**. Pass that path
as `deploy_root`:

```python
pack_tree(src, dst, recipients, owner, project,
          exclude=['wp-config.php'],
          bytecode=True, bytecode_loader='/path/to/emit-loader.so',
          deploy_root='/var/www/app')      # the absolute path on the server
```

If the application will live at `/var/www/app`, compile with `deploy_root=/var/www/app` and deploy
there. Compiling a large tree can exceed PHP's default `memory_limit`; raise it for the emit step
(e.g. `php -d memory_limit=2G`).

## 5. Install the server identity

The loader reads its identity file (the server's private keys) once at startup, from
`envelock.identity`. Owned by the user that starts PHP, mode `0600` (root for PHP-FPM/Apache). See
`docs/MANUAL.md` §13 and the `server-install` command.

## 6. Code that reads its own source at runtime

Some applications read their own PHP **as text** at runtime, not just execute it. Encryption replaces
that text with an encrypted stub, so those mechanisms stop working even though the code still runs.
Two patterns seen in real CMSs:

- **Generated class maps / caches** built by tokenizing the source (e.g. PrestaShop's
  `class_index.php`, built with `token_get_all()` over each file). Fix: **generate the artifact from
  the cleartext tree and deploy it** alongside the encrypted code, so the application reads the map
  instead of re-parsing. This is the same idea as shipping any pre-built cache.
- **Annotation readers that parse `use` statements from the source** (e.g. Doctrine ORM annotations
  like `@ORM\Table`). These cannot be read from an encrypted file. Fix: exclude the annotated classes
  from encryption, or use a version that declares metadata with **PHP 8 attributes** (`#[ORM\Table]`),
  which are read via reflection and survive encryption.

More generally: reflection over an encrypted class works (method/property/attribute metadata lives in
the compiled op_array), but anything that re-opens the `.php` file to read its text does not. When an
application depends on the latter, exclude those specific files or pre-generate what they produce.

**Find these automatically:** `envelock preflight --source <dir>` scans the tree (read-only) and lists
every file matching these patterns, each with its fix. Run it before packing any third-party or
framework code; use `--strict` to fail a CI build on any finding.

## 7. Doctrine / Symfony annotations

Doctrine's annotation reader resolves `@ORM\Table` (and the like) by tokenizing the file's `use`
statements, which an encrypted file no longer exposes — hence `The annotation "@..." in class ... was
never imported`. Two ways keep it working, **both validated against `doctrine/annotations` with the
entity encrypted, and neither exposes the source**:

- **PHP 8 attributes (recommended).** Declare the mapping with `#[ORM\Table]` instead of
  `/** @ORM\Table */`. Attributes are read by reflection from the compiled class, which survives
  encryption — and Doctrine itself recommends them ("a native replacement for annotations"). Verified:
  an attribute on an encrypted class reads back correctly.
- **Pre-generated metadata cache (for code you cannot change).** Warm the metadata in a CLEARTEXT
  build (`php bin/console cache:warmup`, or Doctrine's `PsrCachedReader` / ORM metadata cache) and ship
  that cache next to the encrypted code, in **non-debug** mode so the reader does not re-check the file
  against its timestamp. The reader then returns from the cache and never re-opens the `.php`.
  Verified: with the cache pre-populated in the clear, an encrypted entity's annotations read
  correctly; **with the cache removed, the same encrypted entity fails** — proof that the cache, not
  the source, is what is read. This is the standard production setup for Symfony/Doctrine regardless.

What NOT to do: leave the docblocks readable inside the encrypted package so the reader can parse them
— that exposes part of the source and defeats the protection. Always move the metadata OUT of the
source (attributes or cache); never ship half-encrypted source.

**The robust belt-and-braces option: exclude the annotated entity classes from encryption.** The
compiled container's metadata cache may not cover *every* runtime annotation read — an entity read
lazily by a service or presenter can still trigger the reader on the live file. Entity classes are
structure (columns, getters/setters), not business logic, so excluding them costs little protection.
**Validated on PrestaShop 9 (full package, encrypted):** keeping only `var/` clear left the
featured-products block empty — the product presenter reads `@ORM` on `FeatureFlag` at run time, which
the container cache did not cover, and the hook swallowed the exception. Keeping `var/` clear **and**
excluding the 33 `@ORM` entity files (`src/.../Entity/*`) made the encrypted shop render identical to
the baseline (189 products; remaining diffs are only cache hashes and timestamps). `preflight` lists
exactly those files to exclude.

## Drupal in bytecode (validated end-to-end)

The full Drupal 11 tree runs packed with `--bytecode`, rendering byte-for-byte identical to the
cleartext baseline. Two Drupal-specific points:

- **Exclude the writable site directory with a glob, not a bare path.** `--exclude` matches each
  relative path with `fnmatch`, so `--exclude sites/default` matches nothing — use
  `--exclude 'sites/default/*'`. That keeps `settings.php` (config) and `sites/default/files/`
  (the SQLite/MySQL data, the compiled Twig templates and the service container) out of the package,
  so they stay clear and writable.
- **Assets are not copied by the packer.** As in §1, rsync the non-PHP assets (and Drupal's
  `.twig`/`.yml`) into the deploy root yourself, excluding the PHP-bearing extensions so the encrypted
  files are not overwritten: `--exclude='*.php' --exclude='*.module' --exclude='*.inc'
  --exclude='*.install' --exclude='*.theme' --exclude='*.engine' --exclude='*.profile'`. Pass those same
  extensions to the packer with `--php-ext` so they are encrypted. Then copy `sites/default` in the clear.

Drupal declares plugins with PHP 8 attributes and autoloads via Composer PSR-4, so it has none of the
source-tokenizing annotation problem; `include_protection` stays off so the runtime-generated clear PHP
(compiled Twig, the container) loads normally. See `docs/AUDITORIA.md` Pass 25.

## Obfuscation / hardening options vs real CMSs (measured)

Which pack options keep a real CMS rendering identically, verified by packing the whole app, serving
it through the production loader and diffing the rendered home page against the cleartext baseline
(✅ = byte-identical; ❌ = breaks). Encryption + bytecode + the signed manifest are always on and always
pass; this table is only about the OPTIONAL obfuscation/hardening flags.

| Option (flag) | Drupal 11 | WordPress | Joomla 5 | PrestaShop 9 |
|---|---|---|---|---|
| Strip comments `--strip-comments` | ✅ | ✅ | ✅ | ❌ docblocks (see below) |
| Compact `--compact` | ✅ | ✅ | ✅ | ❌ docblocks (see below) |
| Encode strings `--encode-strings` | ✅ | ✅ | ✅ | ✅ |
| Obfuscate local variables `--obfuscate` | ✅ | ✅ | ✅ | ✅ |
| Obfuscate flow `--obfuscate-flow` | ✅ | ✅ | ✅ | ✅ |
| Rename private methods `--obfuscate-methods` | ✅ | ✅ | ✅ | ✅ |
| Include protection `--include-protection` | ✅ | ✅ | ✅ | ✅ |
| Reject FFI/dl `--no-ffi` | ✅ | ✅ | ✅ | ✅ |
| Reject auto_prepend/append `--no-prepend` | ✅ | ✅ | ✅ | ✅ |
| Rename private PROPERTIES `--obfuscate-properties` | ❌ HTTP 500 | ⚠️ home OK, unsafe elsewhere | ❌ HTTP 500 | ❌ HTTP 500 |
| Sealed tree `--sealed` | ✅ with `sealed_cleartext` | ❌ eval at run time | ✅ with `sealed_cleartext` | ❌ eval at run time |
| Vault strings `--vault-strings` | ⏱️ impractical at 13.6 k files | ❌ render breaks | — not measured | — not measured |

All four CMSs were **measured** (whole app packed, served through the production loader, home page
diffed byte-for-byte against the cleartext baseline after normalising per-request tokens — CSRF tokens,
asset cache-busters, random widget ids). The earlier prediction that PrestaShop would mirror Drupal was
**wrong on two flags** and is corrected above: PrestaShop breaks under `--strip-comments`/`--compact`.

Notes from the runs:

- **PrestaShop and `--strip-comments` / `--compact`: incompatible.** PrestaShop's front-office
  presentation layer (`src/Adapter/Presenter/AbstractLazyArray.php`, the base class of the product,
  cart and order presenters) reads its **own method docblocks at run time** via `getDocComment()` to
  find the `@arrayAccess` annotation that marks which methods expose array keys. Plain encryption keeps
  docblocks, so the base pack renders identically — but `--strip-comments` and `--compact` physically
  remove docblocks, so `@arrayAccess` disappears, the presenters expose nothing, and the product data
  silently vanishes (HTTP 200 with the featured-products section simply absent — no error). This is the
  same self-introspection class as a tokenised class map or a WordPress file header. `envelock preflight`
  now detects `getDocComment()` (category `reads-own-docblock`) and `pack` prints an active WARNING when
  `--strip-comments`/`--compact` is combined with a tree that contains it. Fix: drop those two flags on
  PrestaShop (the rest of the safe set still applies), or `--exclude` the presenter files.
- **`--include-protection` is compatible** (this corrects earlier guidance). It only refuses a
  *cleartext* file including a *protected* one; it does NOT refuse protected code including the cleartext
  PHP these CMSs generate at run time (Twig/Smarty cache, the service container).
- **`--sealed` and the `envelock.sealed_cleartext` allowlist.** By default sealed refuses every plain
  `.php` **and** every `eval()` under the tree. The **`envelock.sealed_cleartext`** directive
  (`PATH_SEPARATOR`-separated absolute path prefixes) re-allows plain `.php` under the listed
  directories — the app's config file and the folders it writes generated PHP into — while every other
  plain file is still refused. It deliberately does **not** relax the `eval()` refusal: `eval()` is the
  primary vector sealed exists to block. Consequence, all measured:
  - **Drupal ✅** and **Joomla ✅** under sealed with the allowlist — they only *write cleartext cache
    PHP* (Twig/container; Joomla's `cache/`, `tmp/`), they do not `eval()` in the front path. Drupal:
    `envelock.sealed_cleartext=/var/www/app/sites/default`. Joomla: the config file plus `cache`, `tmp`,
    `administrator`.
  - **PrestaShop ❌** — its Composer/PrestaShop autoloader `eval()`s class stubs
    (`vendor/prestashop/autoload/src/Autoloader.php`), which the allowlist cannot and must not cover.
  - **WordPress ❌** — eval at run time.
  Only list directories the app itself writes, and keep untrusted uploads non-executable at the web
  server, since a `.php` dropped into an allowed directory would run. If you don't need sealed,
  `--include-protection` already gives most of the benefit with none of this.
- **`--obfuscate` (local variables) is safe even on WordPress**, despite WordPress's heavy use of
  `compact()`/`extract()`: the obfuscator detects those (and `get_defined_vars`/`parse_str`/variable
  variables) and leaves those scopes alone.
- **`--obfuscate-properties` stays HIGH RISK — ❌ on every CMS tried.** It breaks the Composer autoloader
  (private `ClassLoader` properties such as `$prefixLengthsPsr4` are accessed by name via `Closure::bind`,
  so renaming them empties the PSR-4 map and classes stop loading: `Class … not found`, HTTP 500 on
  Drupal, Joomla and PrestaShop) and Drupal's unserialise of cached objects. WordPress renders its home
  but is unsafe elsewhere. Leave it off for a CMS.
- **`--vault-strings` is impractical on a very large tree** (it did not finish on Drupal's 13.6 k files
  in >10 min) and broke the WordPress render. Treat it as a per-file, test-it tool, not a whole-CMS flag.

**Universal safe set (all four CMSs, byte-identical):** encryption + bytecode + signed manifest +
`--encode-strings` + `--obfuscate` + `--obfuscate-flow` + `--obfuscate-methods` + `--include-protection`
+ `--no-ffi` + `--no-prepend`. Drupal, WordPress and Joomla additionally tolerate `--strip-comments` +
`--compact`; PrestaShop does not (docblock annotations above). Joomla additionally tolerates `--sealed`
with the allowlist; it composed with the whole set byte-identically. On Laravel and Symfony (own code
packed, `vendor/` cleartext; Windows 11, PHP 8.4, 2026-11-10) the set that works is encryption + bytecode +
`--encode-strings --obfuscate --obfuscate-flow --obfuscate-methods --strip-comments --compact --no-ffi
--no-prepend` — every web route and the console match the unprotected app — but **not**
`--include-protection`, because their console scripts (`artisan`, `bin/console`) have no `.php` extension
and stay cleartext — and, with `vendor/` cleartext, because an exception or shutdown handler registered
from `vendor/` would be refused when it loads one of the protected classes (external audit 2026-11-12,
H-03). `--no-ffi` needs `enable_dl = Off` in php.ini (see the table below).

## Choosing options: trade-offs and when to use each

Every option here is **opt-in and off by default**; encryption, Ed25519 signing and (by default) the
signed manifest are always on. Think along two independent axes:

- **Confidentiality / anti-root** — how hard it is to recover the original once it runs on the server
  (`--bytecode`, `--sealed`, `--no-ffi`, `--include-protection`, `--vault-strings`). None of these defeat
  a determined root on the box — that limit is inherent to running on a machine the adversary controls —
  they raise the cost.
- **Obfuscation / readability** — how unreadable the code is *if* someone does recover it
  (`--strip-comments`, `--compact`, `--encode-strings`, `--obfuscate`, `--obfuscate-flow`,
  `--obfuscate-methods`, `--obfuscate-properties`).

The cost you pay is in **reliability, compatibility and (sometimes) runtime speed**. The golden rule:
**the more aggressive the flag, the more you must test the packaged app like a real release** — a few
of these can break an app silently (HTTP 200, wrong output), not loudly. Run `envelock preflight` first;
it flags the self-introspection patterns that the aggressive flags break.

### Recommended profiles

- **Maximum protection (code you control end-to-end, own servers):** `--bytecode` + the full obfuscation
  set (`--strip-comments --compact --encode-strings --obfuscate --obfuscate-flow --obfuscate-methods`) +
  `--include-protection --no-ffi --no-prepend --sealed` (with `envelock.sealed_cleartext` for the paths
  the app writes). This keeps no source in memory and refuses injected cleartext/eval. Test thoroughly;
  drop `--sealed`/`--strip-comments`/`--compact` per the CMS notes above where they don't apply.
- **Balanced (most apps, including CMSs):** encryption + `--bytecode` + the universal safe set
  (`--encode-strings --obfuscate --obfuscate-flow --obfuscate-methods --include-protection --no-ffi
  --no-prepend`). Byte-identical on all four CMSs. This is the sweet spot: strong, low-risk. For a
  framework app whose console script has no `.php` extension (Laravel, Symfony), leave out
  `--include-protection` — `envelock recommend` does this for you.
- **Minimum / first deploy:** encryption + signed manifest only. Everything still private to your key;
  add the layers above once the bare package is confirmed working.

### Per-option reference

| Option | What it buys you | Cost / risk | Use it when | Avoid it when |
|---|---|---|---|---|
| **`--bytecode`** | Ships compiled op_arrays, not source text: the source never reaches `zend_compile_file`, so there is no decrypted source in memory to dump. The biggest single anti-root win. | ~9 µs/file slower than source (not faster — its value is protection, not speed); image is bound to the exact PHP build and to the deploy path (`--deploy-root`); incompatible with `--vault-strings`. | You want the strongest confidentiality and control the PHP version on the server. | The server's PHP build/version isn't fixed, or you can't compile at the deploy path. |
| **`--include-protection`** | A protected file refuses to run if a *cleartext* file tries to include it — stops a dropped loader script from pulling your code into a readable scope. | Essentially none on the four CMSs (measured compatible). Order-dependent: every entry point must be protected. `pack` encrypts only files with a PHP extension, so a console script without one (`artisan`, `bin/console`) stays cleartext and its commands are refused (measured on Laravel: `php artisan route:list` → "it can only be loaded by its own application"); `recommend` turns it off for such projects. | Every entry point (web and console) is protected. | The app has console entry points without a `.php` extension. |
| **`--no-ffi`** | Fails closed if FFI or `dl()` is reachable, so in-process code can't load a C shim to read decrypted memory. | None on the CMSs, **but a php.ini requirement**: `enable_dl = Off` (PHP's built-in default is On; the `php.ini-production`/`-development` templates set it Off) and FFI not armed (`ffi.enable = 0` or no ffi extension; FFI's default `preload` arms it in the CLI, and Debian/Ubuntu load FFI). Otherwise every protected file refuses to load (measured: 0 of 10 Laravel routes). | The app needs neither FFI nor `dl()` (most don't) and you control the server's php.ini. | The app legitimately uses FFI/`dl()`, or the server's php.ini is not yours to set. |
| **`--no-prepend`** | Refuses `auto_prepend_file`/`auto_append_file`, a classic injection point. | None measured; requires both directives empty on the server. | Almost always. | The deployment relies on an auto-prepend bootstrap (some hosting security/monitoring agents use one). |
| **`--sealed`** (+ `envelock.sealed_cleartext`) | Refuses *all* cleartext `.php` under the tree **and** `eval()` while active — closes "drop a readable script next to the protected code" and run-time string compilation. Strongest injection defense. | Breaks any app that runs cleartext PHP it generates (template/container caches) or uses `eval()`; needs the `sealed_cleartext` allowlist for the dirs the app writes, and it never relaxes the `eval()` refusal. Measured: Drupal/Joomla OK with allowlist; WordPress/PrestaShop ❌ (they `eval()`). | Every `.php` in the tree is protected and the app doesn't `eval()`. | The app ships/writes cleartext PHP or relies on `eval()` (don't force it). |
| **`--enforce-manifest`** (on by default) | Signed inventory of every file; the loader fails closed if a protected file was deleted (e.g. an auth check silently removed). Also enables the ~5× cold-start fast path when the server trusts a single developer. | None; on by default (opt out with `--no-manifest`). | Always — deploy the package as one unit. | Only if you deliberately ship partial packages. |
| **`--strip-comments`** | Removes comments/docblocks — less to read if recovered. | **Removes docblocks that some frameworks read at run time** (`getDocComment()` annotations, WP file headers). Can break silently. Line numbers preserved. | Drupal, WordPress, Joomla, and any app that doesn't read its own docblocks. | PrestaShop and any app with runtime docblock annotations (`preflight` flags it). |
| **`--compact`** | Collapses whitespace/comments to one space — removes indentation and line structure. | Same docblock caveat as `--strip-comments`; **line numbers not preserved** (errors report the collapsed line). | You don't need production line numbers and the app passes the docblock check. | PrestaShop (docblocks), or when you need accurate error line numbers. |
| **`--encode-strings`** | String literals become `\xNN` escapes — hides readable strings (URLs, messages, SQL) from a casual `strings`/grep. | Low; measured byte-identical on all four CMSs. | Almost always — good readability win for little cost. | No strong reason to avoid. |
| **`--obfuscate`** (local vars) | Renames local variables to short names; the single best readability-reduction with the lowest risk. Safe even on WordPress (it skips `compact()`/`extract()`/variable-variable scopes). | Low; byte-identical on all four CMSs. Notices show short names. | Almost always. | No strong reason to avoid. |
| **`--obfuscate-flow`** | Inserts dead branches behind opaque always-false predicates — modest control-flow noise. | Low; byte-identical on all four CMSs. It is *modest* (dead code, not real flattening) — honest about that. | When you want a bit more analysis cost at near-zero risk. | If you expect it to defeat a serious analyst — it won't on its own. |
| **`--obfuscate-methods`** (private) | Renames **private** methods to short names; conservative (skips dynamic dispatch, `__call`, reflection-looking usage). | Low; byte-identical on all four CMSs — but a dynamic call it can't see would break, so test. | Most apps. | A class resolves its own method names dynamically in ways the analysis can't see. |
| **`--obfuscate-properties`** (private) | Renames **private** properties — stops property names revealing intent. | **HIGH RISK. ❌ on every CMS tried (HTTP 500).** Breaks the Composer autoloader (private `ClassLoader` props accessed by name via `Closure::bind`) and anything that serializes objects (sessions, caches, queues) — the serialized form carries the old names. | Only a self-contained app you can test exhaustively and that never serializes the affected objects. | Any CMS or framework using Composer autoload or object serialization — i.e. almost everything. |
| **`--vault-strings`** | Moves string literals out of the op_array into an encrypted table decrypted at use — strings aren't even in the compiled form. | Impractical on very large trees (didn't finish on Drupal's 13.6 k files in >10 min), broke the WordPress render, and is incompatible with `--bytecode`. +~15 ns per literal access. | A small, hot module where a few secrets must not sit in memory as plain op_array constants. | Whole large apps / CMSs, or together with `--bytecode`. |

### WordPress block (FSE) themes: keep the theme patterns unencrypted

A WordPress **block theme** (FSE — the default since Twenty Twenty-Two) registers its block *patterns*
from `wp-content/themes/<theme>/patterns/*.php` by reading each file's header comment (`Title:`, `Slug:`)
with `get_file_data()` — i.e. from the file TEXT, exactly like a Doctrine annotation (§7). Encrypt those
files and the header is gone, so the patterns never register and the FSE templates render **empty** (the
page returns HTTP 200 with almost no content and no PHP error — easy to miss). Measured: an encrypted
Twenty Twenty-Four home page dropped from 215 blocks to 10; excluding the patterns restored it to 215,
byte-identical to cleartext.

Fix: keep the pattern files in the clear. Exclude them from the package and copy them over as assets:

```bash
envelock pack ... --exclude 'wp-content/themes/*/patterns/*'
# then copy the cleartext pattern files into the deploy (they are PHP, so your asset rsync skipped them):
#   cp -a src/wp-content/themes/<theme>/patterns/*.php deploy/wp-content/themes/<theme>/patterns/
```

They carry no business logic worth protecting (just block markup + a header), so leaving them clear costs
nothing. `envelock preflight --source <app>` now flags these as `wp-file-header`. Classic (non-FSE)
themes do not need this.

## Checklist

- [ ] Encrypted `.php` deployed over a full copy of the app (assets present).
- [ ] Config file excluded from the package, real one placed on the server.
- [ ] OPcache disabled or the protected tree blacklisted.
- [ ] Bytecode packages compiled with `deploy_root` = the real server path.
- [ ] `envelock.identity` installed, `0600`, owned by the PHP master user.
- [ ] Writable areas (uploads, cache) left outside the protected tree.
- [ ] Generated class maps/caches pre-generated from cleartext and deployed.
- [ ] Source-tokenizing annotation readers handled (exclude those classes, or use PHP 8 attributes).
- [ ] Doctrine/Symfony: PHP 8 attributes, or the pre-generated metadata cache deployed in non-debug mode.
- [ ] Doctrine with annotations: also exclude the `@ORM` entity classes (`preflight` lists them) — the
      container cache may not cover every runtime read.

See `docs/AUDITORIA.md` Passes 19–25 for the validations behind this guide (WordPress, Joomla and Drupal
end-to-end in both source-cipher and bytecode; PrestaShop 9 encrypted end-to-end with this recipe).

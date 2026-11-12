# Third-party source code

Envelock ships the source code of every external library it uses and of CPython, so the project
can be audited and rebuilt without downloading anything. (The libraries compiled into the portable
Python — OpenSSL 3.5, SQLite, Tcl/Tk… — are referenced, not copied: see
[prebuilt/README.md](../prebuilt/README.md#portable-python-python).) How to compile them: [docs/BUILDING.md](../docs/BUILDING.md).
Their compiled forms are in [`prebuilt/`](../prebuilt/README.md).

| Folder | What it is | Used by | License |
|---|---|---|---|
| `cryptography-50.0.2/` | Python cryptography library (Rust + Python) | encoder, assistant | Apache-2.0 OR BSD-3-Clause |
| `cryptography-50.0.2/vendor/` | the 32 Rust crates cryptography needs (`cargo vendor --locked`) | cryptography build | see below |
| `cffi-2.1.1/` | C foreign-function interface for Python (includes libffi for Windows) | cryptography | MIT-0 (libffi: MIT) |
| `pycparser-3.11/`, `pycparser-3.12/` | C parser used by cffi (3.11 for Python 3.10, 3.12 for 3.11+) | cffi | BSD-3-Clause |
| `typing_extensions-4.16.0/` | backports of typing features (needed only on Python 3.10) | cryptography | PSF-2.0 |
| `openssl-4.0.3/` | OpenSSL, the version bundled in the official cryptography 50.0.2 builds | cryptography (static); the PHP loader links the system OpenSSL 3 | Apache-2.0 |
| `cpython-3.13.15/` | CPython, the interpreter of the portable Python in `prebuilt/python/` (its bundled libraries: see [prebuilt/README.md](../prebuilt/README.md#portable-python-python)) | portable Python | PSF-2.0 |
| `php-parser/` | PHP AST parser (nikic/php-parser, v5 series) for the encoder's name/flow obfuscator | encoder (pack-time, objective O6) | BSD-3-Clause |

The Python libraries are the exact versions pinned in `requirements.lock`. Each library keeps its own license
files in its folder; their copyright notices are summarised in [NOTICE](../NOTICE).

Rust crate licenses (from each crate's `Cargo.toml`): MIT OR Apache-2.0 (23 crates, incl. pyo3,
syn, libc, cc), MIT (openssl-sys, pem), Apache-2.0 (openssl), BSD-3-Clause (asn1, asn1_derive),
Apache-2.0 OR MIT (portable-atomic), Apache-2.0 OR GPL-2.0-only (self_cell, used under
Apache-2.0), Apache-2.0 WITH LLVM-exception (target-lexicon), (MIT OR Apache-2.0) AND
Unicode-3.0 (unicode-ident).

## Origin and integrity

Each folder is the official source archive, extracted. SHA-256 of the original archives:

> `php-parser/` is the upstream nikic/php-parser distribution (github.com/nikic/PHP-Parser),
> `lib/`, `LICENSE`, `composer.json` and `README.md` only; every file is listed byte for byte in
> `SHA256SUMS`. Pin it to a specific upstream tag when preparing a release.

| Archive | SHA-256 | Source |
|---|---|---|
| `cryptography-50.0.2.tar.gz` | `7b46165bb56eb4704e2eaaf86f3c940d19154535d9b0ca7d6d590b04060e00d5` | PyPI |
| `cffi-2.1.1.tar.gz` | `dd31f52ea1086513bb9df30f8fcee9b8918323ae067a3d5b78bc826a000712be` | PyPI |
| `pycparser-3.11.tar.gz` | `d875f09c3507d00e1aba0eecc6dcadc1352f30fff09dc6bff2f1c2935e97c2bc` | PyPI |
| `pycparser-3.12.tar.gz` | `f03387877eab82ce01bbdfd0ba7252ee55a90b1c708d5129e2ce915475cf1db6` | PyPI |
| `typing_extensions-4.16.0.tar.gz` | `dc983d19a509c94dba722ee6abd33940f7c05a89e243c47e907eb4db6f1a43e5` | PyPI |
| `openssl-4.0.3.tar.gz` | `325b5c806167c13b40b1ffeadfe0248197c00eccc4cf123ec1e28d2d2fd216d9` | github.com/openssl/openssl releases (matches its published `.sha256`) |

`cpython-3.13.15/` is the tag `v3.13.15` of github.com/python/cpython (commit
`4061bc4c35f7c26f25264666d4ba083b93d2f6f9`, 2026-08-05), exported with `git archive`.

The PyPI hashes are the same ones pinned in `requirements.lock`. To check a folder, download the
original archive, compare its SHA-256, extract it and compare with `diff -r`: the only differences
must be the ones listed next (git does not keep empty folders, so the empty submodule folders of
the OpenSSL archive, such as `cloudflare-quiche/` or `wycheproof/`, are absent in a clone).

**Byte for byte.** [`SHA256SUMS`](SHA256SUMS) lists every file here with its hash, and the release
guard (`scripts/check_release.py`) refuses any file that is missing from it or differs from it:
build outputs left in these folders, a swapped file, or an end-of-line conversion are caught.
`.gitattributes` (`* -text`) stops git from converting line endings, which would otherwise break
cargo's per-file checksums of the vendored crates. The upstream binaries kept here (libffi
objects for Windows in cffi, test data in the `vcpkg` crate) are covered by the same list.

## Changes made for Envelock

Envelock's publication policy does not name artificial-intelligence products, so files that do,
and that are not needed to build, were removed or edited:

- `cryptography-50.0.2/`: removed two contributor files with instructions for coding agents;
  removed their two names from the `[tool.check-sdist]` list in `pyproject.toml`.
- `cryptography-50.0.2/vendor/pyo3/`: removed `README.md`, and its entry from that crate's
  `.cargo-checksum.json` (so cargo still verifies every remaining file).
- `openssl-4.0.3/`: removed `CHANGES.md` (release notes) and `CONTRIBUTING.md`.
- `cpython-3.13.15/Lib/idlelib/News3.txt` (IDLE's change log): the name of an AI coding product
  replaced by "an AI coding assistant" in 6 credit lines. (Other matches of the same word in
  CPython are people's names in the credits and were kept.)
- `cpython-3.13.15/`: its `.gitattributes` and four `.gitignore` files renamed with an
  `.upstream` suffix (they would make git convert or skip files of this copy), and the three
  symbolic links in `Misc/mypy/` removed (recreated by the `make_symlinks.py` next to them;
  symbolic links do not survive git on Windows).

Added:

- `cryptography-50.0.2/vendor/` (the crates, produced by `cargo vendor --locked` from the
  package's own `Cargo.lock`) and `cryptography-50.0.2/.cargo/config.toml`, which points cargo
  at that folder and builds offline.
- `.gitignore` and `.gitattributes` here and in `cryptography-50.0.2/vendor/` (keep every file,
  convert none), `SHA256SUMS` and this README.

No program code was changed.

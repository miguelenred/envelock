# Envelock v2 format

Experimental format, common to Windows/Linux/macOS. It does not depend on endianness, pointer size or the serialization of Zend's internal structures. Incompatible changes must use a different format/version signature.

In v2 the content key is **wrapped per recipient** with asymmetric cryptography: nobody can decrypt a package without holding the recipient's X25519 private key. The loader is **generic** (it embeds no secret); its private key and the trusted signer are read from an external identity file (see `MANUAL.md`). Having the public engine or another developer's keys does not allow decrypting packages meant for others.

## Byte layout

```text
fixed PHP stub | 70-byte header | relative path | recipient table (N×124) | ciphertext | GCM tag 16 | Ed25519 signature 64
```

The exact stub, terminated with LF, is:

```php
<?php /* Envelock */ exit("Envelock loader required\n"); __halt_compiler();
```

Without the extension, PHP ends with a message, without printing the binary payload. The stub contains `__halt_compiler()` to stop the normal parser; the original source is NOT transformed into a script that uses `eval()`.

The header begins immediately after the stub's LF. All subsequent offsets are relative to the start of that header:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 8 | Magic `ENVLK02` followed by NUL |
| 8 | 1 | Format version (2) |
| 9 | 1 | Flags (opt-in, per package): bit 0 = include protection, bit 1 = refuse `auto_prepend_file`/`auto_append_file`, bit 2 = refuse while FFI/`dl()` is reachable, bit 3 = sealed tree (refuse plain PHP under it and `eval()`), bit 4 = enforce the signed binary manifest at runtime, bit 5 = string-literal vault (the plaintext carries a literal-table prefix, see below), bit 6 = bytecode (the plaintext is a serialized `zend_op_array`, not source, see below), bit 7 = encrypted string-literal vault (objective O7: the literal table is encrypted at rest inside the plaintext; `--vault-strings` sets bits 5 and 7 together and the loader then uses the encrypted table, see below). Known bits = 0..7 (`0xFF`); any other bit set is refused |
| 10 | 2 | Length of the relative path, uint16 big-endian (1..1024) |
| 12 | 16 | Project UUID |
| 28 | 16 | Release UUID |
| 44 | 2 | Number of recipients, uint16 big-endian (1..1024) |
| 46 | 12 | File GCM nonce |
| 58 | 4 | Length of the encrypted plaintext, uint32 big-endian (the original source; with the vault flag, the literal-table prefix plus the source; with the bytecode flag, the bytecode image — see below) |
| 62 | 8 | Release serial, uint64 big-endian (by default the time of `pack` in **nanoseconds** since the Unix epoch) |

The **relative path** follows the header: the file's path inside the package, UTF-8, `/`-separated, with no empty, `.` or `..` parts. The loader only runs the file from a location ending in that path.

The maximum source is 16 MiB per file. No compression is used. File lengths and the tree structure are not hidden.

**String-literal vault (flag bit 5).** When the vault flag is set, the encrypted plaintext is not the source alone but a literal-table prefix followed by the source:

```
u32 table_bytes (BE) | u32 count (BE) | count × ( u32 len (BE) | len bytes ) | PHP source
```

`table_bytes` is the size of the `count`-and-entries block that follows it. Each entry is one string literal that the encoder moved out of a runtime position in the source and replaced with an internal `\__envelock_lit(idx)` call (`idx` is the 0-based entry number; identical literals are stored once). The table travels inside the same AES-256-GCM ciphertext and Ed25519 signature as the source, so it is authenticated and bound to this file; it adds no new cryptography. The loader parses the prefix, keeps the literals in a per-request table keyed by the file, compiles only the source, and returns each literal from the table on demand, wiping them at the end of the request. Literals in constant expressions stay inline. A package without the flag has no prefix: the plaintext is exactly the source.

**Encrypted string-literal vault (flag bit 7, objective O7).** `--vault-strings` sets bits 5 and 7 together; when bit 7 is present the loader ignores the plaintext table above and reads an *encrypted* one instead. The reason: the container is decrypted once at load and its plaintext — the whole literal table with it — then sits in process memory for the rest of the request. With the encrypted table the decrypted container holds ciphertext, and a literal becomes plaintext only when the program actually reads it, one entry at a time, wiped again at end of request. Layout of the plaintext (all lengths big-endian):

```
u32 table_bytes | u32 count | key_nonce 12 | wrapped_key 48 |
  count × ( u32 len | nonce 12 | ciphertext | tag 16 )  | PHP source
```

A per-file 256-bit data key is wrapped with the package content key (`key_nonce` + 48-byte `wrapped_key` = 32 B key + 16 B GCM tag); each literal is sealed with AES-256-GCM under that data key (`len` counts nonce + ciphertext + tag, i.e. every byte after it). Honest limit: a reader who can decrypt the container can unwrap the data key — this does not defeat a reader who can run the code or dump the process at the right moment, and is not meant to. It removes the property that asked for the least effort: every secret string lying in one contiguous, already-decrypted block. A package with bit 5 alone (no bit 7) is the earlier plaintext-table form and is still read for compatibility.

**Bytecode payload (flag bit 6, objective O1).** With this flag the encrypted plaintext is not PHP source at all but a *bytecode image*: the `zend_op_array` of the file, serialized with the persistence code of Zend OPcache adapted to Envelock. The loader deserializes it in place and runs it; the compiler never sees the file, so there is no decrypted source in the process to intercept. Its layout:

```text
0   4   tag "EVB1"
4   8   magic "ENVELBC1"
12  32  bytecode identity of the PHP build that produced it (ASCII hex)
44  4   padding, always 0
48  8   u64be mem_size       size of the serialized program
56  8   u64be str_size       reserved, always 0
64  8   u64be script_offset  offset of the script record inside the program
72  8   u64be timestamp      reserved, always 0
76  4   u32be adler32        over the program bytes
80  …   the serialized program (pointers rewritten as offsets from here)
```

Two bindings follow from what an image is, and both are enforced fail-closed:

- **Build binding.** The identity is an MD5 over the running PHP version, the Zend extension build id (API number, thread safety, debug, compiler), the data model and the size of every structure the image contains, the VM kind and last opcode, and the number of op_array extension slots (plus `zend_system_id` itself for `-dev` builds). The loader compares it before dereferencing anything and refuses the file if it differs, so an image only runs on the PHP version and build that produced it; repack for each target build. It is deliberately **not** `zend_system_id`, which also hashes the hooks the process installed and so differs between the SAPIs of one build (the Windows CLI's Ctrl+C handler, `pcntl` in a Linux CLI): with it, an image packed with the CLI was refused by `php-cgi` or PHP-FPM of the same build. Handlers are re-selected at load time and internal functions resolved at run time, so the server's own hooks apply.
- **Path binding.** `__DIR__`, `__FILE__` and the path of a statically resolved `include`/`require` are *compile-time* values: they are baked into the image as the absolute path the file had while being compiled. `pack --bytecode` therefore compiles each source at its deploy path (`--deploy-root`) and removes it again, and the package only runs from there. This is inherent to precompiled bytecode — OPcache's own file cache is bound to an absolute path the same way — not a property of this container.

The flag is mutually exclusive with the vault (bit 5): the vault rewrites literals into `\__envelock_lit()` calls *in the source*, and a bytecode image ships no source to resolve them in.

Because bit 6 was outside the known-bits mask of a loader predating this format (that older mask was `0x3F`), such a loader sees an unknown bit and refuses the whole file: a bytecode package fails closed on a loader that cannot run it, rather than being misread as source. In the current v2 format bit 6 is a known flag and the known-bits mask is `0xFF` (`ENVELOCK_FLAGS_KNOWN`, see the flags table above).

Each **recipient table** entry occupies 124 bytes:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 32 | Recipient's X25519 public key (identifies the entry) |
| 32 | 32 | Ephemeral X25519 public key of this wrapping |
| 64 | 12 | Wrapping GCM nonce |
| 76 | 48 | Wrapped content key: 32 bytes + 16-byte tag |

The table is created once per package and copied identically to each file.

## Per-recipient key wrapping (X25519 + HKDF + AES-GCM)

For each recipient with public key `R_pub` an ephemeral pair `(E_priv, E_pub)` is generated:

```text
secret       = X25519(E_priv, R_pub)
info         = "Envelock/kem/v2\0" || version(1) || project(16) || release(16) || E_pub(32) || R_pub(32)
wrap_key     = HKDF-SHA256(ikm = secret, salt = "", info = info, L = 32)
wrapped_key  = AES-256-GCM(wrap_key, wrap_nonce, content_key, AAD = info)
```

The `info` binds the wrapping to the version, the project, the release, the ephemeral and the specific recipient, so an entry cannot be reused for another recipient or another release. Decryption recreates `secret = X25519(R_priv, E_pub)`, derives the same `wrap_key` and authenticates the content key. Without `R_priv` it is not possible.

## File encryption and signing

```text
file_AAD = stub || header || relative path || recipient table
payload  = AES-256-GCM(content_key, file_nonce, original_source, file_AAD)
signature = Ed25519(maker_private_key, stub || header || path || table || payload)
```

`payload` includes the 16-byte tag. `pack` uses a new content key per run and 96-bit counters as file nonces: there are no collisions between files of the same package. The maker's signature is common to its packages; the decryption capability depends on holding the recipient's private key.

## Loader validation order

1. Detect the stub through the file buffer that Zend opens; refuse if a debugging extension is loaded (unless `envelock.allow_debuggers=1`).
2. Check magic, version, known flags, path length, number of recipients, size limits and the exact length.
3. **Verify Ed25519 before any key operation or decryption** (magic, version, flags, path and serial are inside the signed region).
4. Policy, still before decrypting: minimum serial of the project (identity file), path binding, one project and release per package folder in the request, and the package flags (no prepend/append, include protection, FFI/`dl()` refusal, sealed tree, manifest enforcement). After decrypting, with the vault flag, the literal-table prefix is parsed off and only the source is compiled.
5. For each configured identity, locate its entry in the table by the X25519 public key (constant-time comparison).
6. Derive the X25519 secret, the wrap key (HKDF) and authenticate/unwrap the content key.
7. Authenticate and decrypt the source in place, in the buffer Zend read the file into.
8. Compile that same file handle with PHP's original file compiler, then clear the buffer.

The original file stays encrypted on disk. Zend's paths and opening mechanisms are honored, including `include_path` and the normal restrictions on inclusions.

## Anti-downgrade

The v2 loader accepts **only** the `ENVLK02` magic and version 2. A v1 package (`ENVLK01`, weaker symmetric model) is rejected. Because the magic and version are inside the signed region, they cannot be altered without invalidating the Ed25519 signature.

## Server identity file

It is consumed by the loader via the `envelock.identity` directive in `php.ini`. It is **secret** (it contains private keys) and is never distributed. It separates the **recipient** keys from the **trust store** of trusted developers (a per-installation trust list, never taken from the package):

```text
magic "ENVLKID3" (8)
recipient_count  uint16 BE (1..64)
developer_count  uint16 BE (1..64)
recipients:  recipient_count × (x25519_priv 32 | x25519_pub 32)
developers:  developer_count × (ed25519_primary 32 | ed25519_recovery 32)
minimums:    optional, until the end of the file:
             n × (developer_primary_pub 32 | project UUID 16 | serial uint64 BE), n ≤ 256
```

An all-zero `ed25519_recovery` means "no recovery key". The loader flattens the developers into a list of trusted signers (primary and, if present, recovery). Trust is **global per installation**: a package is accepted if it is addressed to any of the recipient keys and is signed by **any** trusted signer (primary or recovery). `developer_id = SHA256(primary_Ed25519_public_key)` identifies each developer (for configuring, referencing and auditing; it does not travel in the package). The loader rejects the file if other local users can read it: on POSIX, if it is readable by group or others or does not belong to the process user; on Windows, if its owner or any access entry is not the account PHP runs as, SYSTEM, Administrators or OWNER RIGHTS. Each recipient's public key must be derived from its private key, or the file is rejected.

A **minimum** refuses packages of that project whose serial is lower (no rollback to an older signed release); it is set with `minimum set`. Each minimum is **bound to the developer** that set it: its `developer_primary_pub` field records the primary key of the developer whose signed package justified it (or, for an admin-set `--project/--serial` minimum, all zeros = unbound). The loader applies a minimum to a package only when the minimum is unbound or was set by the **same** developer that signed the package, so on a host trusting several developers one cannot set a rollback bar on another's project (ENV-AUD-14). The legacy `ENVLKID2` layout (24-byte, unbound minimums) is still read; `minimum set` rewrites the file in the current format.

## Metadata and updates

`envelock-package.json` contains IDs, the serial, the options used and counts, without keys. It is informational and is not consulted to decrypt (only `minimum set --package` reads its project and serial). Each file carries its own header, path, table and signature. Within one request the loader refuses files of different projects or releases under the same package folder, so a file from another release cannot be swapped in; it does not enforce an atomic update: replace the package as a coherent whole (for example by switching a symbolic link).

## Encrypted private configurations (encoder)

This wrapping is for safeguarding identities on the maker's machine; it is **not distributed to the client** and does not alter PHP's v2 container.

```text
external JSON: kind=envelock-encrypted, format=1, kdf=scrypt-131072-8-1,
              salt=16 bytes hex, nonce=12 bytes hex, ciphertext=hex
key = scrypt(password, salt, N=131072, r=8, p=1, length=32)
AAD = UTF8("Envelock/private-config/v1")
ciphertext = AES-256-GCM(key, nonce, original private JSON UTF-8, AAD)
```

The KDF parameters are validated against that fixed identifier: arbitrary costs supplied by the file are not accepted. Configurations are read with a 64 KiB limit and integrity is checked before validating their internal schema. The password is not stored in that JSON.

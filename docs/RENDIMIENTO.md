# Performance and deployment

Ground rule for this document, set by the project: **security prevails, speed comes second.** Every
option below is judged first by what it exposes and only then by how fast it is. Nothing here trades
away a protection to go faster; where an option changes the exposure at all, that change is stated
first and left as the operator's decision.

## What a protected file costs (measured)

PHP 8.4/8.3, loader with the bytecode layer, OPcache disabled for the protected tree (as the loader
requires). Microseconds per protected file:

| Case | µs/file | What runs |
|---|---|---|
| Plain PHP (unprotected) | ~4 | compile + execute |
| Protected, **cold** (first request a worker serves) | ~130–180 | Ed25519 signature verify **+** X25519 key agreement **+** AES-GCM decrypt **+** compile |
| Protected, **warm** (later requests, same worker) | ~10 | AES-GCM decrypt **+** SHA-256 **+** compile |
| Bytecode mode vs source mode | ≈ equal (±4) | deserialize instead of compile |

Primitive costs on this hardware: Ed25519 verify ≈ 155 µs, X25519 ≈ 32 µs, AES-256-GCM is hardware
accelerated and negligible by comparison.

Two facts decide everything:

1. **The expensive part is asymmetric crypto, and it is paid once per worker, not once per request.**
   The loader keeps two per-worker caches (module globals, destroyed at worker shutdown, never
   cleared between requests): the SHA-256 of every container whose Ed25519 signature was already
   verified, and the content key of every package (so the X25519 key agreement runs **once per
   package**, not per file). Nothing decrypted is cached — only the verification result and the
   symmetric key (the key is held in locked, non-dumpable memory). So the first request a worker
   serves pays the full ~155 µs/file; every later request that worker serves pays only decrypt +
   compile.

2. **Bytecode mode is not faster than source mode.** It is chosen for the anti-root property
   (objective O1: no decrypted source in the package or in memory), not for speed. Do not expect a
   latency gain from it.

The one cost that is genuinely per-request, and cannot be cached away, is **re-compilation**: the
loader refuses OPcache's shared-memory cache for protected files (it would persist decrypted opcodes
in SHM), so in a non-resident SAPI each request recompiles the files it touches. That refusal is a
deliberate security choice, and the next section is about the one deployment that removes the cost
*without* undoing it.

## Deployment options, ordered security first

### A. Non-resident SAPI (PHP-FPM, mod_php) — maximum isolation

Each request is a fresh execution: op_arrays are built and destroyed within the request, so **no
decrypted code outlives a single request**. This is the strongest posture and the documented
guarantee ("decrypted source or opcodes are never kept between requests") holds literally.

Cost: every request recompiles the files it touches, at the warm ~10 µs/file (the asymmetric crypto
is already cached in the worker after its first request). An app that touches 200 files per request
pays on the order of ~2 ms of loader overhead per request. Bounded and often acceptable.

Make it as fast as this option allows, with no security change:

- Keep workers long-lived so the per-worker caches stay warm: `pm.max_requests = 0` (or a high
  value). A worker recycled after every request pays the ~155 µs/file cold cost every time.
- Leave OPcache on for the *unprotected* parts of the stack (framework `vendor/`, if you did not
  protect it) and blacklist only the protected tree (`opcache.blacklist_filename`), with
  `envelock.allow_opcache=1`. The loader still fails closed if the blacklist does not actually cover
  a protected file. `opcache.file_cache` and `opcache.preload` stay off (they persist decrypted
  opcodes to disk / SHM) — the loader refuses them.
  - **Set `opcache.blacklist_filename` on the FPM master** (`php.ini`, or `-d` on the `php-fpm`
    command line), not only as a per-pool `php_admin_value`. OPcache loads the blacklist at MINIT, in
    the master, before pool configuration applies; a pool-only value is read too late and the
    protected file is refused ("OPcache is about to cache this protected file"). Verified in testing.

### B. Resident-worker SAPI (FrankenPHP worker mode, Laravel Octane, RoadRunner) — fastest

A resident worker boots the application once and then serves many requests in a loop without
re-including the already-loaded classes. So each protected class file is decrypted and compiled
**once per worker**, and its op_array is reused for every later request exactly as it would be under
OPcache. **Per-request loader overhead falls to essentially zero** after warm-up.

The honest security trade — state it before choosing this:

- In a resident worker the decrypted op_arrays of the loaded classes **stay in that worker's memory
  for the worker's lifetime**, reused across requests. This is inherent to how these SAPIs run *any*
  application, not something the loader adds, and the loader cannot prevent it without breaking the
  SAPI. It means the "never kept between requests" property of option A does **not** hold here: the
  decrypted program is resident.
- What still holds, and is the reason this is not a security regression of the loader itself:
  decrypted code never reaches **disk** or **OPcache SHM** (file_cache/preload/SHM stay refused);
  each worker decrypts into its **own private, non-dumpable memory** and **nothing is shared between
  workers**; the memory is wiped when the worker dies. The attacker who can read another process's
  resident memory is `root`, and the threat model already concedes that `root` can read the
  decrypted program during execution — residency lengthens that window from "during a request" to
  "for the worker's life", it does not open a new class of attacker.
- This is the same exposure that objective **O9** (a per-worker opcode cache in FPM) was declined
  for. The difference that makes B acceptable where O9 was not: here the residency is the operator's
  explicit, architecture-level choice of a resident SAPI, not the loader silently caching decrypted
  opcodes inside a SAPI (FPM) whose whole point is per-request isolation.

Choose B when the latency target needs it and the operator accepts a resident decrypted program in
exchange; otherwise A is stronger. Configuration is the same as A regarding OPcache SHM, file_cache
and preload (all still refused/blacklisted for the protected tree); worker mode changes only how
often compilation happens, not what is allowed to persist.

## Manifest-anchored verification (`envelock.manifest_fastpath`, default on under `--enforce-manifest`)

**On by default** for `--enforce-manifest` packages, and **only when the server's identity file trusts
a single developer**. A manifest entry proves that its developer *hashed* those bytes, not that a
trusted key *signed* that container, so a seeded file is attributed to the manifest's developer. With
one trusted developer that is the trust the developer already has (they could sign the same bytes).
With several, an earlier version let developer B list developer A's container (or one signed by a key
the server does not trust at all) in B's own signed manifest and run it as B's, defeating include
protection between applications (found in the November 2026 audit and confirmed by experiment), so
the fast path is now off whenever more than one developer is trusted, and digests are seeded only
after the whole manifest has validated. Set `envelock.manifest_fastpath=0` to force the per-file
verify; it has no effect on packages without a manifest.

**Measured (120-file package, cold first request, this hardware):** off 24.5 ms → on 9.0 ms, i.e.
~130 µs/file removed — the per-file Ed25519 of every file after the first collapses into the
manifest's single signature.

**What it does.** The signed binary manifest already carries a trusted SHA-256 of every packaged
file (one Ed25519 signature over the whole list). With `envelock.manifest_fastpath=1`, once that
manifest has verified (its signature is still checked every request, bound to this release), each
listed digest is seeded into the per-worker verified cache. A later protected file whose own SHA-256
is in that set is then vouched for by the (single) trusted developer who signed the manifest, so
`envelock_signature_ok()` returns without the per-file Ed25519. The per-file signatures **stay in the
package**; the loader just stops re-verifying bytes a stronger, already-verified manifest covers.

**Fail-closed, by construction.** Altered bytes hash differently, miss the seeded set, and take the
full per-file verify (which then fails). A missing or wrongly signed manifest refuses the request and
seeds nothing. A manifest for another release is rejected before any seeding (release binding). With
the flag off, nothing is seeded and the path is byte-for-byte the previous behavior.

**Why this is arguably equal-or-stronger, not weaker:**

- A signed manifest of cryptographic hashes is the standard, sound way to sign a set of files (OS
  package managers, code signing). Forging a file needs either a SHA-256 collision or the developer
  signing key.
- The manifest binds **path → hash**, so it catches intra-package substitution and rollback (an
  older, still-validly-signed version of a file swapped in) that per-file signatures alone do **not**
  catch — which is exactly why `--enforce-manifest` exists as defense in depth.

**Conditions required for it to be safe (all must hold, fail-closed):**

- Only when `--enforce-manifest` is active; a missing or unverified manifest must refuse to run, as
  it does today — never fall back to "no verification".
- The per-file hash must be compared against the manifest **before** decrypt/execute, every request
  (this is cheap and already computed for the verified-cache lookup).
- The manifest signature itself is still verified per worker, and bound to the package release (it
  already is: project and release offsets are checked).

**Review findings (resolved):** per-file verification stays available simply by leaving the flag off
(default). The `signer` identity a seeded file records becomes the manifest's signer; the review
confirmed this is fail-closed, not a weakening — in a correctly packed single-developer package the
manifest and every file share the same developer index, and where they differ the mismatch only
triggers *extra* refusals (the per-package roots check and include-protection tighten, never relax),
never a bypass. The SHA-256 ranges on both sides are the whole on-disk file, so the hash + the signed
manifest leave no gap the per-file signature was closing. Two performance (non-security) notes from
the review were addressed: seeding leaves headroom below the verified-cache cap so inert asset
digests cannot evict warm entries, and a signed-but-malformed manifest that seeds a few entries
before being refused is harmless (every seeded digest is developer-authentic; the request still
fails closed).

## Fewer, larger protected files (bundles)

Each protected file pays a fixed cost (header, Ed25519 verify on a cold worker, X25519 unwrap,
decrypt, compile). Grouping many small classes into fewer files multiplies that fixed cost by a
smaller N. Measured cold, 240 methods: 240 files 37.6 ms → 12 files 2.9 ms → 1 file 1.3 ms (−96 %).
No cryptographic change — each bundle is still signed and encrypted.

- Bundle your OWN closed code by module (e.g. `src/ModuleA/bundle.php` holding the module's classes),
  loaded through a Composer `classmap-authoritative` autoload or a bootstrap that `require_once`s the
  bundles. Do not bundle `vendor/` or the framework — leave those flat for OPcache (above).
- Trade-off: a bundle is decrypted whole even if one class is used, so group by module cohesion, not
  the whole app into one file. Keep one-class-per-file only where a PSR-4 autoloader requires it.

## Safe micro-optimizations (no security change)

- Hoist the INI lookups done per file in the compile hook (`opcache.*`, `envelock.*`) to RINIT,
  reading them once per request instead of once per file. Sub-microsecond per file; pure win.
- `--strip-comments` / `--compact` cut compile time ~7–10 % (PHP keeps docblocks in the compiled
  code); free if you do not read docblocks at run time. See `docs/MANUAL.md` §14.
- These are small next to options A/B, the manifest fast path and bundling, and are listed for
  completeness.

## Measuring in your environment

`python3 scripts/bench.py <envelock.so> <php>` reports plain vs protected vs bytecode µs/file for the
PHP it is given (build the loader for that exact PHP first; a loader without the bytecode layer
cannot measure bytecode mode). Run it on the target hardware: the absolute numbers above are from one
machine and the asymmetric-crypto cost in particular scales with CPU. The project rule "nothing
slower than before" is checked by comparing this output across changes.

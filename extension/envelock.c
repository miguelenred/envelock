/*
 * Envelock -- PHP source protection loader (native extension).
 * Project page: https://miguelenred.es/envelock
 * Apache-2.0. "Powered by Envelock" acknowledgements are appreciated but not required.
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include "php.h"
#include "php_envelock.h"   /* declares the module entry for a build compiled INTO php; see the
                             * header for why a phpize build never needed it */
#include "SAPI.h"
#include "ext/standard/info.h"
#include "Zend/zend_stream.h"
#include <stdio.h>
#include <openssl/crypto.h>
#include "envelock_crypto.h"
#include "envelock_file.h"
/* O1 bytecode layer is per PHP version (extension/opcache/php<MM>/). config.m4 defines
 * ENVELOCK_HAVE_BYTECODE=1 and builds the layer when one exists for the target engine; otherwise it
 * is 0 and this loader runs source packages only, refusing a FLAG_BYTECODE file at runtime. */
#ifndef ENVELOCK_HAVE_BYTECODE
#define ENVELOCK_HAVE_BYTECODE 0
#endif
#if ENVELOCK_HAVE_BYTECODE
#include "envelock_bc.h"
#endif
#include "envelock_secret.h"
#include "envelock_integrity.h"
#include "envelock_licence.h"
#include "envelock_clock.h"
#include "envelock_trusted_time.h"
#include "zend_observer.h"   /* O3: observing an execution is observable */
#include "zend_extensions.h" /* HOST-1: zend_get_extension("Zend OPcache") */
#if defined(__linux__)
# include <sys/mman.h>
# include <sys/prctl.h>
# include <unistd.h>
#elif defined(__APPLE__)
# include <sys/mman.h>
# include <unistd.h>
#endif
#if defined(__APPLE__)
# include <dlfcn.h>      /* dladdr: which image a compile hook lives in (HOST-1) */
#elif !defined(PHP_WIN32)
# include <link.h>       /* dl_iterate_phdr: ditto, and in libc on every glibc/musl/BSD */
# include <stdint.h>
#endif

#if PHP_VERSION_ID < 80200 || PHP_VERSION_ID >= 80600
# error "This prototype targets PHP 8.2-8.5; audit newer Zend versions before enabling them."
#endif

/* Generic binary: no embedded secret. The recipient private keys and the trusted signer
 * public keys come from an external identity/trust-store file named by the envelock.identity
 * php.ini directive. A host may serve several projects with different keys, so recipients and
 * trusted developers are independent lists (a per-installation trust store, never taken from
 * the package). Loaded once at MINIT and kept read-only (safe to share across ZTS threads). */
#define ENVELOCK_MAX_RECIPIENTS_ID 64
#define ENVELOCK_MAX_DEVELOPERS 64
#define ENVELOCK_MAX_SIGNERS (2 * ENVELOCK_MAX_DEVELOPERS) /* primary + optional recovery each */
#define ENVELOCK_MAX_MINIMUMS 256
static struct {
    int recipient_count;
    int signer_count;
    /* O2: the private half is the one thing in this process that decrypts everything addressed to
     * it, so it does not live in .bss with the rest. `x25519_private` points at the secret arena
     * (memfd_secret where the kernel offers it) and `x25519_private_fallback` is the .bss copy
     * used when that arena could not be created; exactly one of the two is ever populated. */
    const unsigned char (*x25519_private)[32];
    unsigned char x25519_private_fallback[ENVELOCK_MAX_RECIPIENTS_ID][32];
    unsigned char x25519_public[ENVELOCK_MAX_RECIPIENTS_ID][32];
    unsigned char signing_public[ENVELOCK_MAX_SIGNERS][32]; /* flattened trusted signers */
    int signer_developer_index[ENVELOCK_MAX_SIGNERS];        /* signer slot -> developer record index */
    int developer_count;                                     /* developers with at least one key */
    int minimum_count;                                       /* anti-rollback, per project */
    unsigned char minimum_project[ENVELOCK_MAX_MINIMUMS][16];
    uint64_t minimum_serial[ENVELOCK_MAX_MINIMUMS];
    int minimum_developer_index[ENVELOCK_MAX_MINIMUMS];      /* developer the minimum is bound to:
                                                              * -1 = unbound/any, -2 = unknown dev */
} envelock_identity;

/* Per-worker caches (per thread in ZTS, so no locking). They hold NO source or opcodes:
 *  - verified: SHA-256 of containers whose signature was already verified. The trust store
 *    is fixed for the process lifetime (read at MINIT), so identical bytes stay valid; the
 *    hash costs a few microseconds against ~120 us for an Ed25519 verification.
 *  - keys: content key of each package (same project, release and recipient table), so the
 *    X25519 + HKDF key agreement runs once per package instead of once per file. Keys are
 *    secrets like the identity file already in memory: cleansed on eviction and shutdown. */
#define ENVELOCK_VERIFIED_MAX 65536
/* Manifest fast-path seeding (envelock.manifest_fastpath) stops this far below the cap, so the
 * inert digests a manifest seeds (it lists every file, assets included) cannot fill the table and
 * make envelock_signature_ok() clean out genuinely verified warm entries. Headroom, not a limit on
 * real files. */
#define ENVELOCK_SEED_RESERVE 8192
#define ENVELOCK_KEYS_MAX 1024
/* Per request (no code either): the project|release of each package folder (no mixed
 * releases), and which protected files were compiled: filename -> pointer to that folder's
 * project|release (include protection; no allocation per file). */
ZEND_BEGIN_MODULE_GLOBALS(envelock)
    HashTable verified;
    HashTable keys;
    HashTable loaded;
    HashTable roots;
    HashTable litvault;          /* filename -> array of this file's vaulted string literals (FLAG_VAULT) */
    HashTable litvault_enc;      /* filename -> envelock_enc_vault (FLAG_VAULT_ENC, objective O7) */
    HashTable sealed_roots;      /* per-WORKER set of every sealed-package root this worker has seen,
                                  * so plain PHP under a sealed tree is refused even on a request that
                                  * has not yet loaded a sealed file (closes an order-dependent gap). */
    zend_bool request_ready;
    int sealed_active;            /* >0 once a sealed package has loaded this request */
ZEND_END_MODULE_GLOBALS(envelock)
ZEND_DECLARE_MODULE_GLOBALS(envelock)
#define ENVELOCK_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(envelock, v)

/* Memory hardening (envelock.harden_memory); defined with the helpers further down. */
static int envelock_harden_enabled = 0;
static void envelock_protect_bytes(void *p, size_t len);
static void envelock_unprotect_bytes(void *p, size_t len);

static void envelock_key_dtor(zval *zv)
{
    unsigned char *key = Z_PTR_P(zv);
    envelock_unprotect_bytes(key, 32);
    OPENSSL_cleanse(key, 32);
    pefree(key, 1);
}

static PHP_GINIT_FUNCTION(envelock)
{
#if defined(COMPILE_DL_ENVELOCK) && defined(ZTS)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    zend_hash_init(&envelock_globals->verified, 64, NULL, NULL, 1);
    zend_hash_init(&envelock_globals->keys, 8, NULL, envelock_key_dtor, 1);
    zend_hash_init(&envelock_globals->sealed_roots, 4, NULL, NULL, 1);
    envelock_globals->request_ready = 0;
    envelock_globals->sealed_active = 0;   /* not zeroed by TSRM on every platform (ZTS) */
}

static PHP_GSHUTDOWN_FUNCTION(envelock)
{
    zend_hash_destroy(&envelock_globals->verified);
    zend_hash_destroy(&envelock_globals->keys);   /* cleanses every cached key */
    zend_hash_destroy(&envelock_globals->sealed_roots);
}

/* True when a 32-byte Ed25519 public key encodes one of the 8 small-order points, in any encoding
 * (sign bit masked, y reduced mod p = 2^255-19). Such a "key" verifies trivially forged signatures
 * for every message, so a trust store that contains one is refused (the encoder refuses to write one;
 * this is the loader's own check). Same y list as encoder.ed25519_small_order(). */
static int envelock_ed25519_small_order(const unsigned char key[32])
{
    static const unsigned char small_y[5][32] = {
        {0},                                                                 /* y = 0 (order 4) */
        {1},                                                                 /* y = 1 (identity) */
        {0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
        {0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
         0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
        {0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
         0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a}};
    unsigned char y[32];
    int i, ge_p = 1;
    memcpy(y, key, 32);
    y[31] &= 0x7f;
    /* y >= p (p = ed ff..ff 7f, little-endian) only for the 19 values p..2^255-1: reduce them. */
    if (y[31] != 0x7f || y[0] < 0xed) ge_p = 0;
    for (i = 1; i < 31 && ge_p; i++) if (y[i] != 0xff) ge_p = 0;
    if (ge_p) {
        unsigned char low = (unsigned char)(y[0] - 0xed);
        memset(y, 0, 32);
        y[0] = low;
    }
    for (i = 0; i < 5; i++) if (memcmp(y, small_y[i], 32) == 0) return 1;
    return 0;
}

/* Verifies the container against the trusted signers and reports WHICH trusted signer (developer)
 * verified it in *signer: that identity is bound into the per-folder/per-file tracking so a
 * developer cannot pass off a container under another developer's project (ENV-04). The signer
 * index is stored in the verified cache (as index+1) so a cache hit still returns it. */
static int envelock_signature_ok(const unsigned char *blob, size_t length, int *signer)
{
    unsigned char digest[32];
    void *cached;
    int s;
    if (!envelock_sha256(blob, length, digest)) return 0;
    cached = zend_hash_str_find_ptr(&ENVELOCK_G(verified), (const char *)digest, sizeof(digest));
    if (cached) { *signer = (int)(uintptr_t)cached - 1; return 1; }
    for (s = 0; s < envelock_identity.signer_count; s++) {
        if (envelock_verify(blob, length, envelock_identity.signing_public[s])) {
            if (zend_hash_num_elements(&ENVELOCK_G(verified)) >= ENVELOCK_VERIFIED_MAX) {
                zend_hash_clean(&ENVELOCK_G(verified));
            }
            zend_hash_str_update_ptr(&ENVELOCK_G(verified), (const char *)digest, sizeof(digest),
                                     (void *)(uintptr_t)(s + 1));
            *signer = s;
            return 1;
        }
    }
    return 0;
}

/* Decrypt a container whose signature is verified straight into out (no second copy of the
 * plaintext), reusing or learning its package key. The key is stored BEFORE any plaintext
 * exists: an out-of-memory bailout in the cache insert cannot strand decrypted bytes. On
 * failure out must be cleared by the caller. */
static int envelock_open(const unsigned char *blob, size_t length,
    unsigned char *out, size_t capacity, size_t *out_length, unsigned char key_out[32])
{
    unsigned char package[32], key[32];
    const unsigned char *cached = NULL;
    int r, found = 0, ok, have_package = envelock_package_digest(blob, length, package);
    if (have_package) {
        cached = zend_hash_str_find_ptr(&ENVELOCK_G(keys), (const char *)package, sizeof(package));
    }
    if (cached) {
        /* O7: the caller may need the content key (to unwrap a vault data key), so hand back a
         * copy of the cached one rather than only using it. */
        if (key_out) memcpy(key_out, cached, 32);
        return envelock_decrypt_with_key_into(blob, length, cached, out, capacity, out_length);
    }
    for (r = 0; r < envelock_identity.recipient_count && !found; r++) {
        found = envelock_unwrap_key(blob, length, envelock_identity.x25519_private[r],
                                    envelock_identity.x25519_public[r], key);
    }
    if (!found) return 0;
    if (have_package) {
        unsigned char *stored;
        if (zend_hash_num_elements(&ENVELOCK_G(keys)) >= ENVELOCK_KEYS_MAX) {
            zend_hash_clean(&ENVELOCK_G(keys));
        }
        stored = pemalloc(32, 1);
        memcpy(stored, key, 32);
        if (envelock_harden_enabled) envelock_protect_bytes(stored, 32);   /* M-02: cache keys too */
        if (!zend_hash_str_add_ptr(&ENVELOCK_G(keys), (const char *)package, sizeof(package), stored)) {
            envelock_unprotect_bytes(stored, 32);
            OPENSSL_cleanse(stored, 32);
            pefree(stored, 1);
        }
    }
    ok = envelock_decrypt_with_key_into(blob, length, key, out, capacity, out_length);
    if (ok && key_out) memcpy(key_out, key, 32);
    OPENSSL_cleanse(key, sizeof(key));
    return ok;
}

/* Why a configured identity file was rejected (static string), or NULL. */
static const char *envelock_identity_error = NULL;

/* Objective O8: the deployment license named by envelock.licence, when one is configured.
 * `envelock_licence_present` is what makes a license mandatory: once the directive names a file,
 * an unusable license fails closed instead of being ignored, so deleting it cannot widen access.
 * A license can only ever narrow what runs, never widen it. */
static envelock_licence envelock_licence_data;
static const char *envelock_licence_error = NULL;   /* why it was refused at load, or NULL */
static int envelock_licence_present = 0;

/* O8 anti-rollback. The watermark only means anything alongside an expiry, so it is only consulted
 * when a license is in force: an unlicensed deployment has nothing to roll back to. The value lives
 * in memory for the worker's lifetime and is only ever advanced, never lowered. */
static uint64_t envelock_clock_watermark = 0;
static const char *envelock_clock_path = NULL;
static uint64_t envelock_trusted_floor = 0;   /* 0 = no observation this worker */

/* Reads and checks the license file. Returns NULL when it is usable, otherwise a static reason.
 * Runs at MINIT, after the identity file, because the trusted developer keys come from there. */
static const char *envelock_load_licence(const char *path)
{
    unsigned char blob[ENVELOCK_LICENCE_SIZE];
    FILE *file;
    size_t got;
    const char *refused;

    if (!path || !*path) {
        return NULL;                       /* no license configured: nothing to enforce */
    }
    envelock_licence_present = 1;
    /* envelock_plain_open, not envelock_identity_open: a license holds no secrets, its integrity
     * comes from the signature, and it may legitimately live on a share next to the app. */
    file = envelock_plain_open(path);
    if (!file) {
        return "the license file cannot be opened";
    }
    got = fread(blob, 1, sizeof(blob), file);
    fclose(file);
    if (got != sizeof(blob)) {
        return "the license file has the wrong size";
    }
    if (!envelock_licence_parse(blob, sizeof(blob), &envelock_licence_data)) {
        memset(&envelock_licence_data, 0, sizeof(envelock_licence_data));
        return "the license is malformed or of an unsupported format";
    }
    if (envelock_identity.signer_count <= 0) {
        memset(&envelock_licence_data, 0, sizeof(envelock_licence_data));
        return "no trusted owner key is loaded to check the license against";
    }
    if (!envelock_licence_signed_by(blob, envelock_identity.signing_public,
            envelock_identity.signer_count)) {
        memset(&envelock_licence_data, 0, sizeof(envelock_licence_data));
        return "the license signature does not verify with any trusted owner key";
    }
    /* Checked here for a clear startup message AND per protected file, because expiry is a
     * property of the clock and a long-lived worker would otherwise keep running past it. */
    /* No request yet at MINIT, so the domain binding is not checked here; see the header. */
    if ((refused = envelock_licence_refusal(&envelock_licence_data, 0)) != NULL) {
        memset(&envelock_licence_data, 0, sizeof(envelock_licence_data));
        return refused;
    }
    return NULL;
}

static zend_op_array *(*envelock_previous_compile_file)(zend_file_handle *, int) = NULL;
static zend_op_array *(*envelock_previous_compile_string)(zend_string *, const char *,
    zend_compile_position) = NULL;
/* O3: what zend_compile_file pointed at once Envelock had installed its own hook, so the loader
 * can tell later whether something installed another hook on top of it. NULL until MINIT. */
static zend_op_array *(*envelock_own_compile_file)(zend_file_handle *, int) = NULL;
/* O3: same idea for zend_interrupt_function, and here it is not optional. PHP 8.4 installs its own
 * interrupt handler before any extension's MINIT (measured: it is non-NULL in a bare
 * `php -n -r`), so testing it against NULL would refuse every process. Only a *change* is news. */
static void (*envelock_own_interrupt_function)(zend_execute_data *) = NULL;

PHP_INI_BEGIN()
    PHP_INI_ENTRY("envelock.identity", "", PHP_INI_SYSTEM, NULL)
    /* Opt-in coexistence with OPcache's SHM cache. Default 0 = fail closed when OPcache is
     * enabled. Setting 1 asserts the operator has excluded the protected tree from OPcache via
     * opcache.blacklist_filename. As a backstop the loader also refuses any protected file that
     * OPcache is about to cache (ZEND_COMPILE_IGNORE_OTHER_FILES), so a missing or wrong blacklist
     * fails closed on the first request instead of silently caching decrypted opcodes. file_cache
     * and preloading are always refused, since they persist decrypted opcodes to disk / SHM. */
    PHP_INI_ENTRY("envelock.allow_opcache", "0", PHP_INI_SYSTEM, NULL)
    /* Paths allowed to run as PLAIN PHP under a --sealed tree: a PATH_SEPARATOR-separated list of
     * absolute path prefixes. A sealed package refuses all cleartext PHP by default; a CMS, however,
     * legitimately runs some cleartext under its tree — its config file and the PHP it GENERATES at
     * run time (Drupal's compiled Twig and service container under sites/default/files, WordPress's
     * cache). List those app-controlled directories here so --sealed can be used with such an app
     * while every other plain file under the tree is still refused. Only list directories the
     * application itself writes; an attacker able to drop a .php into an allowed directory could run
     * it, so keep untrusted uploads non-executable at the web server, as usual. */
    PHP_INI_ENTRY("envelock.sealed_cleartext", "", PHP_INI_SYSTEM, NULL)
    /* Cold-start optimisation (docs/RENDIMIENTO.md). Only has any effect with pack
     * --enforce-manifest, DEFAULT ON there, and only when identity.bin trusts a SINGLE developer.
     * That package's signed manifest is already verified every request for enforcement (its Ed25519
     * signature checked, bound to this release), so the SHA-256 of every file it lists is seeded into
     * the per-worker verified cache and a later protected file whose own SHA-256 is in that set skips
     * its per-file Ed25519 verify (the first-request N*Ed25519 cost, measured ~5x: 127 -> 26 us/file).
     * A manifest entry only proves the developer hashed those bytes, so the seeded file is attributed
     * to the manifest's developer: harmless with one developer (they could sign the same bytes), but
     * with several it would let one developer claim another's container, so then the fast path is off
     * (ENV-04). Fail-closed: altered bytes hash differently, miss the set and take the full per-file
     * verify; a missing, malformed or wrongly signed manifest seeds nothing and refuses the request.
     * Set to 0 to force the per-file verify even under --enforce-manifest. */
    PHP_INI_ENTRY("envelock.manifest_fastpath", "1", PHP_INI_SYSTEM, NULL)
    /* Extensions that can dump or trace the decrypted code (see envelock_debugger) make
     * protected files fail closed unless this is set to 1 (e.g. on a development machine). */
    PHP_INI_ENTRY("envelock.allow_debuggers", "0", PHP_INI_SYSTEM, NULL)
    /* O3, opt-in. Refuses a protected file when the process is being instrumented in a way that
     * only shows up at run time rather than as a loaded extension: a tracer attached with ptrace,
     * a replacement of zend_execute_ex, or an execution observer. Costs one /proc/self/status read
     * and two pointer comparisons per protected file, and it will refuse legitimate profilers and
     * debuggers, so it stays off unless the deployment asks for it. The checks that need no opt-in
     * — our own compile hook still ours, no zend_ast_process — always run. */
    PHP_INI_ENTRY("envelock.paranoid", "0", PHP_INI_SYSTEM, NULL)
    /* Memory hardening, ON by default. Once a server identity is loaded the process is marked
     * non-dumpable (no core dumps, no ptrace/proc-mem reads by the same user — which otherwise lets
     * any PHP in the same pool read the private keys from /proc/self/mem) and the private key
     * material (identity and the per-worker content-key cache) is locked into RAM and excluded from
     * dumps. Set to 0 only where a core dump of the PHP process is needed; sampling profilers that
     * run inside the process are unaffected. Re-applied in RINIT because setuid() (PHP-FPM dropping
     * privileges) resets the dumpable flag. */
    PHP_INI_ENTRY("envelock.harden_memory", "1", PHP_INI_SYSTEM, NULL)
    /* O2. Off by default unlike harden_memory: it can be unavailable on the running kernel and a
     * deployment should opt in knowing that, and read back envelock_secret_memory() to see what
     * it actually got. */
    PHP_INI_ENTRY("envelock.secret_memory", "0", PHP_INI_SYSTEM, NULL)
    /* O8. Path of the signed deployment license issued by the vendor. Empty (the default) means
     * the deployment is unlicensed and unrestricted. Once set, the license is MANDATORY: an
     * unusable one fails closed, so removing the file cannot be a way to lift its restrictions. */
    PHP_INI_ENTRY("envelock.licence", "", PHP_INI_SYSTEM, NULL)
    /* O8 anti-rollback: path of the file recording the highest time this installation has been
     * seen running at. Empty (the default) disables the check. The PHP worker must be able to
     * WRITE it, so it cannot live in the same root-owned 0400 place as the identity file. */
    PHP_INI_ENTRY("envelock.clock_state", "", PHP_INI_SYSTEM, NULL)
    /* How far behind that record the clock may be before it is treated as set back. Absorbs an NTP
     * step and a hand-corrected timezone; anything larger is a rollback. */
    PHP_INI_ENTRY("envelock.clock_tolerance", "3600", PHP_INI_SYSTEM, NULL)
    /* O8: an HTTPS host asked for the time once per worker, to bound the real time from below so
     * that deleting the clock state and resetting the clock is not enough. Empty (the default)
     * means the local clock and the watermark only. Needs outbound HTTPS from the server, and a
     * host that cannot be reached degrades to that — it never refuses a site. */
    PHP_INI_ENTRY("envelock.trusted_time", "", PHP_INI_SYSTEM, NULL)
    PHP_INI_ENTRY("envelock.trusted_time_timeout", "5", PHP_INI_SYSTEM, NULL)
PHP_INI_END()

/* Reads the trust store: magic "ENVLKID3" | recipient_count(u16 BE) | developer_count(u16 BE) |
 * recipients(rc x [x25519_priv 32|x25519_pub 32]) | developers(dc x [primary_pub 32|recovery_pub 32]) |
 * optional minimums until the end (n x [developer_primary_pub 32|project 16|serial u64 BE]).
 * The developer field binds each minimum to the developer that set it; an all-zero developer is
 * unbound (applies to any developer). The legacy "ENVLKID2" format (24-byte minimums, all unbound)
 * is still read. A recovery public of all zeros means none. Refuses a file other local users can
 * read (it holds private keys; see envelock_file.c). Returns NULL if a usable store was loaded. */
#define ENVELOCK_ID_HEADER 12U
#define ENVELOCK_ID_RECIPIENT 64U
#define ENVELOCK_ID_DEVELOPER 64U
#define ENVELOCK_ID_MINIMUM 56U       /* developer_pub 32 | project 16 | serial 8 */
#define ENVELOCK_ID_MINIMUM_V2 24U    /* legacy: project 16 | serial 8 */
#define ENVELOCK_IDENTITY_MAX_FILE (ENVELOCK_ID_HEADER + \
    (unsigned)ENVELOCK_MAX_RECIPIENTS_ID * ENVELOCK_ID_RECIPIENT + \
    (unsigned)ENVELOCK_MAX_DEVELOPERS * ENVELOCK_ID_DEVELOPER + \
    (unsigned)ENVELOCK_MAX_MINIMUMS * ENVELOCK_ID_MINIMUM)
static const char *envelock_load_identity(const char *path)
{
    static const unsigned char magic[8] = {'E', 'N', 'V', 'L', 'K', 'I', 'D', '3'};
    static const unsigned char magic_v2[8] = {'E', 'N', 'V', 'L', 'K', 'I', 'D', '2'};
    static const unsigned char zero32[32] = {0};
    /* One byte larger than the maximum valid file, so an over-long file is detected
     * without reading past the buffer. */
    unsigned char buffer[ENVELOCK_IDENTITY_MAX_FILE + 1];
    const unsigned char *recipients, *developers, *minimums;
    const char *insecure;
    FILE *file;
    size_t got;
    unsigned int rc, dc, mc, i, signers = 0;
    size_t base, min_stride;
    int has_dev;

    envelock_identity.recipient_count = 0;
    envelock_identity.signer_count = 0;
    envelock_identity.minimum_count = 0;
    if (!path || !*path) return NULL; /* not configured: not an error by itself */
    file = envelock_identity_open(path);
    if (!file) return "cannot be opened";
    insecure = envelock_identity_file_check(file);
    if (insecure) {
        fclose(file);
        return insecure;
    }
    got = fread(buffer, 1, sizeof(buffer), file);
    fclose(file);
    if (got < ENVELOCK_ID_HEADER || got > ENVELOCK_IDENTITY_MAX_FILE ||
        (memcmp(buffer, magic, 8) != 0 && memcmp(buffer, magic_v2, 8) != 0)) {
        OPENSSL_cleanse(buffer, sizeof(buffer));
        return "malformed (not an Envelock identity file)";
    }
    has_dev = (memcmp(buffer, magic, 8) == 0);               /* v3 binds minimums to a developer */
    min_stride = has_dev ? ENVELOCK_ID_MINIMUM : ENVELOCK_ID_MINIMUM_V2;
    rc = ((unsigned int)buffer[8] << 8) | (unsigned int)buffer[9];
    dc = ((unsigned int)buffer[10] << 8) | (unsigned int)buffer[11];
    base = ENVELOCK_ID_HEADER + (size_t)rc * ENVELOCK_ID_RECIPIENT + (size_t)dc * ENVELOCK_ID_DEVELOPER;
    if (rc < 1 || rc > ENVELOCK_MAX_RECIPIENTS_ID || dc < 1 || dc > ENVELOCK_MAX_DEVELOPERS ||
        got < base || (got - base) % min_stride != 0 ||
        (got - base) / min_stride > ENVELOCK_MAX_MINIMUMS) {
        OPENSSL_cleanse(buffer, sizeof(buffer));
        return "malformed (inconsistent counts or size)";
    }
    recipients = buffer + ENVELOCK_ID_HEADER;
    developers = recipients + (size_t)rc * ENVELOCK_ID_RECIPIENT;
    minimums = buffer + base;
    mc = (unsigned int)((got - base) / min_stride);
    for (i = 0; i < mc; i++) {
        const unsigned char *e = minimums + (size_t)i * min_stride;
        const unsigned char *dev_pub = has_dev ? e : NULL;        /* 32-byte primary, or unbound */
        const unsigned char *proj = has_dev ? e + 32 : e;
        const unsigned char *ser = has_dev ? e + 48 : e + 16;
        int b, idx = -1;                                          /* -1 unbound (applies to any) */
        memcpy(envelock_identity.minimum_project[i], proj, 16);
        envelock_identity.minimum_serial[i] = 0;
        for (b = 0; b < 8; b++) {
            envelock_identity.minimum_serial[i] = (envelock_identity.minimum_serial[i] << 8) | ser[b];
        }
        if (dev_pub && memcmp(dev_pub, zero32, 32) != 0) {        /* bound: resolve developer index */
            unsigned int j;
            idx = -2;                                             /* -2: developer no longer present */
            for (j = 0; j < dc; j++) {
                if (memcmp(developers + (size_t)j * ENVELOCK_ID_DEVELOPER, dev_pub, 32) == 0) {
                    idx = (int)j; break;
                }
            }
        }
        envelock_identity.minimum_developer_index[i] = idx;
    }
    for (i = 0; i < rc; i++) {
        const unsigned char *e = recipients + (size_t)i * ENVELOCK_ID_RECIPIENT;
        /* Key-pair self-check once here, not on every include. */
        if (!envelock_check_keypair(e, e + 32)) {
            OPENSSL_cleanse(buffer, sizeof(buffer));
            OPENSSL_cleanse(&envelock_identity, sizeof(envelock_identity));
            return "malformed (recipient key pair mismatch)";
        }
        memcpy((void *)envelock_identity.x25519_private[i], e, 32);
        memcpy(envelock_identity.x25519_public[i], e + 32, 32);
    }
    envelock_identity.developer_count = 0;
    for (i = 0; i < dc; i++) {
        const unsigned char *e = developers + (size_t)i * ENVELOCK_ID_DEVELOPER;
        if ((memcmp(e, zero32, 32) != 0 && envelock_ed25519_small_order(e)) ||
            (memcmp(e + 32, zero32, 32) != 0 && envelock_ed25519_small_order(e + 32))) {
            OPENSSL_cleanse(buffer, sizeof(buffer));
            OPENSSL_cleanse(&envelock_identity, sizeof(envelock_identity));
            return "malformed (a trusted signing key is a small-order point that would accept forged signatures)";
        }
        if (memcmp(e, zero32, 32) != 0 || memcmp(e + 32, zero32, 32) != 0) {
            envelock_identity.developer_count++;
        }
        if (memcmp(e, zero32, 32) != 0) {              /* primary (skip an all-zero slot) */
            envelock_identity.signer_developer_index[signers] = (int)i;
            memcpy(envelock_identity.signing_public[signers++], e, 32);
        }
        if (memcmp(e + 32, zero32, 32) != 0) {         /* recovery, if any */
            envelock_identity.signer_developer_index[signers] = (int)i;
            memcpy(envelock_identity.signing_public[signers++], e + 32, 32);
        }
    }
    OPENSSL_cleanse(buffer, sizeof(buffer));
    if (signers == 0) {
        OPENSSL_cleanse(&envelock_identity, sizeof(envelock_identity));
        return "malformed (no trusted signer)";
    }
    envelock_identity.recipient_count = (int)rc;
    envelock_identity.signer_count = (int)signers;
    envelock_identity.minimum_count = (int)mc;
    return NULL;
}

/* Read a boolean directive exactly as OPcache does (zend_ini_parse_bool accepts "on",
 * "yes", "true"). INI_INT would read a quoted "On" as 0 while OPcache treats it as enabled. */
#define ENVELOCK_INI_BOOL(name) envelock_ini_bool(name, sizeof(name) - 1)
static int envelock_ini_bool(const char *name, size_t length)
{
    zend_ini_entry *entry = zend_hash_str_find_ptr(EG(ini_directives), name, length);
    return entry && entry->value && zend_ini_parse_bool(entry->value);
}

/* Persistent plaintext sinks, refused unconditionally: file cache writes decrypted opcodes
 * to disk; preloading keeps them resident in shared memory for the server's lifetime. */
static int envelock_persistent_cache(void)
{
    const char *preload = INI_STR("opcache.preload");
    const char *file_cache = INI_STR("opcache.file_cache");
    return ENVELOCK_INI_BOOL("opcache.file_cache_only") || (file_cache && *file_cache) ||
           (preload && *preload);
}

/* OPcache's in-memory (SHM) cache. Measured behaviour: OPcache re-asserts itself as the
 * outermost compile hook every request, so Envelock cannot sit above it; the only reliable
 * way to keep decrypted opcodes out of SHM is opcache.blacklist_filename on the protected
 * tree. Allowed only when the operator opts in via envelock.allow_opcache (and blacklists). */
static int envelock_shm_cache(void)
{
    /* Same rule as OPcache: it caches only if opcache.enable is on and, for the CLI/phpdbg
     * SAPIs, opcache.enable_cli too (measured). With the stock defaults (enable=1,
     * enable_cli=0, always present on PHP 8.5) the CLI does not cache, so it is allowed. */
    if (!ENVELOCK_INI_BOOL("opcache.enable")) return 0;
    if (sapi_module.name &&
        (strcmp(sapi_module.name, "cli") == 0 || strcmp(sapi_module.name, "phpdbg") == 0)) {
        return ENVELOCK_INI_BOOL("opcache.enable_cli");
    }
    return 1;
}

/* O3: self-verification. Returns a human-readable reason to refuse a protected file, or NULL.
 *
 * envelock_debugger() answers "is a known instrument loaded?". This answers the harder question —
 * "is this process, right now, in a state where the hand-over of decrypted source can be watched?"
 * — which no list of extension names can settle, because the instruments that matter here are
 * installed by setting a pointer rather than by loading something with a name.
 *
 * The first two checks always run: they cost a pointer comparison each, and refusing them would
 * leave the objective unmet by default. The rest are behind envelock.paranoid because they reject
 * legitimate profilers and cost one /proc/self/status read per protected file.
 *
 * Every check is advisory by nature — an attacker who owns the process owns the checks. What it
 * buys is that a protected package fails closed in a process that is being traced or instrumented
 * instead of quietly handing over its source.
 */
/* Whether two code addresses lie in the same loaded image (DLL, shared object or executable).
 * -1 when the platform cannot tell, which callers treat as "not the same". */
#if defined(PHP_WIN32)
static int envelock_same_image(const void *a, const void *b)
{
    HMODULE ma = NULL, mb = NULL;
    const DWORD flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
    if (!GetModuleHandleExW(flags, (LPCWSTR) a, &ma) || !GetModuleHandleExW(flags, (LPCWSTR) b, &mb)) return -1;
    return ma == mb;
}
#elif defined(__APPLE__)
static int envelock_same_image(const void *a, const void *b)
{
    Dl_info ia, ib;
    if (!dladdr(a, &ia) || !dladdr(b, &ib)) return -1;
    return ia.dli_fbase == ib.dli_fbase;
}
#else
struct envelock_image_probe { uintptr_t address; const void *image; };
static int envelock_image_of_cb(struct dl_phdr_info *info, size_t size, void *data)
{
    struct envelock_image_probe *probe = data;
    int i;
    (void) size;
    for (i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        uintptr_t start = (uintptr_t) info->dlpi_addr + (uintptr_t) ph->p_vaddr;
        if (ph->p_type == PT_LOAD && probe->address >= start && probe->address - start < (uintptr_t) ph->p_memsz) {
            probe->image = info->dlpi_phdr;   /* unique per loaded object */
            return 1;
        }
    }
    return 0;
}
static int envelock_same_image(const void *a, const void *b)
{
    struct envelock_image_probe pa = { (uintptr_t) a, NULL }, pb = { (uintptr_t) b, NULL };
    dl_iterate_phdr(envelock_image_of_cb, &pa);
    dl_iterate_phdr(envelock_image_of_cb, &pb);
    if (!pa.image || !pb.image) return -1;
    return pa.image == pb.image;
}
#endif

/* HOST-1: is the compile hook above ours PHP's own — OPcache's, or Phar's? Both are php-src
 * extensions that hook compilation for their own reasons: OPcache always sits above every regular
 * extension (it installs its hook after their MINIT), and Phar does when it is a shared module
 * loaded after Envelock (a distribution's conf.d/20-phar.ini after an extension= line in php.ini).
 * They are recognised by where the hook's code lives — the same image as the module's own
 * start-up function — not by any setting, so a hook from any other image is still refused. This
 * is what lets OPcache be switched off per directory, vhost or FPM pool: its hook stays installed
 * (it was on at start-up) but passes every file straight through, and before this the loader
 * refused the site as if a foreign hook were present. */
static int envelock_compile_hook_is_php_own(void)
{
    const void *hook = (const void *) zend_compile_file;
    zend_extension *opcache = zend_get_extension("Zend OPcache");
    zend_module_entry *phar = zend_hash_str_find_ptr(&module_registry, "phar", sizeof("phar") - 1);
    if (opcache && opcache->startup && envelock_same_image(hook, (const void *) opcache->startup) == 1) {
        return 1;
    }
    if (phar && phar->module_startup_func &&
        envelock_same_image(hook, (const void *) phar->module_startup_func) == 1) {
        return 1;
    }
    return 0;
}

/* HOST-1, and what keeps that exception from hiding anything: once every extension has started
 * (every MINIT and every zend_extension start-up have run; OPcache installs its own hook only after
 * this callback returns), note whether a hook that is not PHP's own already sits above Envelock's.
 * One that does is refused for good, even after OPcache later covers it with its own hook. */
static zend_result (*envelock_previous_post_startup)(void) = NULL;
static int envelock_foreign_hook_at_startup = 0;
static zend_result envelock_post_startup(void)
{
    if (envelock_previous_post_startup) {
        zend_result (*callback)(void) = envelock_previous_post_startup;
        envelock_previous_post_startup = NULL;
        if (callback() != SUCCESS) {
            return FAILURE;
        }
    }
    envelock_foreign_hook_at_startup = envelock_own_compile_file != NULL &&
        zend_compile_file != envelock_own_compile_file && !envelock_compile_hook_is_php_own();
    return SUCCESS;
}

static const char *envelock_integrity_check(void)
{
    /* A compile hook installed above ours receives the handle Envelock has just decrypted, which
     * defeats the whole loader, and there is no name to look for: catching it means noticing that
     * zend_compile_file is no longer the function we put there at MINIT.
     *
     * One legitimate exception, and it is not a compromise so much as the shape of the engine:
     * OPcache re-asserts itself as the outermost compile hook and Envelock cannot sit above it
     * (see envelock_shm_cache). So an operator who has opted into envelock.allow_opcache — which
     * asserts they blacklisted the protected tree, and which the loader separately enforces per
     * file — has already accepted a hook above this one, and refusing here would only contradict
     * that. The other exception is a hook whose code is PHP's own OPcache or Phar
     * (envelock_compile_hook_is_php_own, HOST-1). Anyone else gets the strict answer. */
    if (envelock_own_compile_file != NULL && zend_compile_file != envelock_own_compile_file &&
        !(ENVELOCK_INI_BOOL("envelock.allow_opcache") && envelock_shm_cache()) &&
        (envelock_foreign_hook_at_startup || !envelock_compile_hook_is_php_own())) {
        return "another extension installed a compile hook above Envelock's";
    }
    /* A zend_ast_process hook walks the syntax tree of every file that is compiled. envelock_debugger()
     * already refuses it, but it is cheap enough to state here too, so that turning allow_debuggers
     * on does not silently turn this one off as well. */
    if (zend_ast_process != NULL) return "a zend_ast_process hook is installed";

    if (!ENVELOCK_INI_BOOL("envelock.paranoid")) return NULL;

    /* A tracer attached with ptrace(2) can read the decrypted source out of memory and can stop the
     * process between the decryption and the compilation. envelock.harden_memory blocks a same-uid
     * attach, but not one by a tracer that already has CAP_SYS_PTRACE, and not one that was already
     * attached before the flag was set. -1 means "could not determine" and is not a refusal: on a
     * platform without /proc/self/status there is nothing to answer from, and saying "traced" would
     * break every deployment there. */
    if (envelock_tracer_pid() > 0) return "the process is being traced (ptrace attached)";
    /* A replacement of zend_execute_ex runs for every op_array; the interrupt handler runs at
     * every VM interrupt. Both see the program after Envelock has decrypted it. execute_ex is
     * compared against the engine's own, which is what "not hooked" means; the interrupt handler
     * against the one PHP itself installed, because it always installs one. */
    if (zend_execute_ex != execute_ex) return "zend_execute_ex has been replaced";
    /* zend_execute_internal is NULL on a stock engine (internal functions are called directly). A
     * module that sets it intercepts EVERY internal call and its return value — including the
     * cleartext a vaulted literal (__envelock_lit) or a virtualized function (__envelock_vm) hands
     * back — without touching zend_execute_ex, so it slipped past the check above (ENV-2026-28). In
     * paranoid mode, a non-NULL hook here is refused like the others. */
    if (zend_execute_internal != NULL) return "zend_execute_internal has been replaced";
    if (envelock_own_interrupt_function != NULL &&
        zend_interrupt_function != envelock_own_interrupt_function) {
        return "the zend_interrupt_function has been replaced";
    }
    /* An execution observer. The engine keeps its handler list internal, so what is observable is
     * the slot it allocates for one: -1 while nothing is registered (measured on PHP 8.4), and the
     * slot number once zend_observer_fcall_register() has run. */
    if (zend_observer_fcall_op_array_extension >= 0) return "an execution observer is registered";
    return NULL;
}

/* Extensions, hooks or SAPIs that can dump, trace or rewrite the decrypted code (M-03: profilers
 * and an installed AST hook see the program too, not just the classic debuggers). */
static const char *envelock_debugger(void)
{
    static const char *const names[] = {"xdebug", "vld", "uopz", "runkit7", "xhprof",
        "tideways", "tideways_xhprof", "ddtrace", "spx", "pcov", "blackfire", "memprof"};
    size_t i;
    if (sapi_module.name && strcmp(sapi_module.name, "phpdbg") == 0) return "phpdbg";
    /* An AST process hook receives the full syntax tree of every compiled file. */
    if (zend_ast_process != NULL) return "a zend_ast_process hook";
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (zend_hash_str_exists(&module_registry, names[i], strlen(names[i]))) return names[i];
    }
    return NULL;
}

/* FFI and dl() let PHP running in this process read the decrypted source straight out of memory
 * (FFI maps/reads arbitrary addresses; dl() can load the FFI extension at runtime). A package
 * built with --no-ffi refuses to load while that path is reachable. FFI is reachable when its
 * extension is loaded AND ffi.enable is On, or ffi.enable is "preload" under the CLI SAPI (the
 * CLI enables FFI for every request; on web SAPIs "preload" only arms FFI during preloading,
 * which Envelock already forbids for protected trees via envelock_persistent_cache). */
static int envelock_ffi_usable(void)
{
    if (zend_hash_str_exists(&module_registry, "ffi", sizeof("ffi") - 1)) {
        zend_ini_entry *entry =
            zend_hash_str_find_ptr(EG(ini_directives), "ffi.enable", sizeof("ffi.enable") - 1);
        if (entry && entry->value && ZSTR_LEN(entry->value)) {
            if (zend_ini_parse_bool(entry->value)) return 1;
            if (zend_string_equals_literal_ci(entry->value, "preload") &&
                sapi_module.name && strcmp(sapi_module.name, "cli") == 0) return 1;
        }
    }
    return ENVELOCK_INI_BOOL("enable_dl");
}

/* Path comparison as the file system does it: '\\' is a separator on Windows, and Windows
 * and macOS file systems ignore ASCII case by default. */
static int envelock_path_char(unsigned char c)
{
#ifdef _WIN32
    if (c == '\\') return '/';
#endif
#if defined(_WIN32) || defined(__APPLE__)
    if (c >= 'A' && c <= 'Z') return c + ('a' - 'A');
#endif
    return c;
}

/* 1 iff name ends with the packaged relative path at a directory boundary; *root receives
 * the length of the package folder prefix. */
static int envelock_at_packaged_path(const char *name, size_t length, const unsigned char *rel,
    size_t rel_length, size_t *root)
{
    size_t i;
    if (length < rel_length) return 0;
    for (i = 1; i <= rel_length; i++) {
        if (envelock_path_char((unsigned char)name[length - i]) != envelock_path_char(rel[rel_length - i])) {
            return 0;
        }
    }
    if (length > rel_length && envelock_path_char((unsigned char)name[length - rel_length - 1]) != '/') {
        return 0;
    }
    *root = length - rel_length;
    return 1;
}

/* 1 iff a protected file of this project is on the call stack (include protection). */
static int envelock_called_from_project(const unsigned char *project, int signer)
{
    zend_execute_data *ex;
    /* Compare the DEVELOPER, not the signer slot: a developer's primary and recovery keys sit in
     * different signer slots, so a hotfix signed after promote-recovery must still count as the
     * same application as a module signed with the primary key (ENV-AUD-17). */
    int dev = (signer >= 0 && signer < envelock_identity.signer_count)
                  ? envelock_identity.signer_developer_index[signer] : -2;
    for (ex = EG(current_execute_data); ex; ex = ex->prev_execute_data) {
        if (ex->func && ZEND_USER_CODE(ex->func->type) && ex->func->op_array.filename) {
            const unsigned char *owner = zend_hash_find_ptr(&ENVELOCK_G(loaded), ex->func->op_array.filename);
            /* Same project AND same trusted developer: a container signed by a different developer,
             * even one trusted on this host, is not "its own application" (ENV-04). */
            if (owner && memcmp(owner, project, 16) == 0 &&
                memcmp(owner + 32, &dev, sizeof(int)) == 0) return 1;
        }
    }
    return 0;
}

/* 1 iff this file is the request's entry script. The CLI and CGI/FPM SAPIs set
 * file_handle->primary_script, but the Apache module (mod_php) and the built-in server do not
 * (1.0.0 bug: include protection then refused even the directly requested file under Apache).
 * So also accept the file the SAPI is running as the main script, matched as resolved real
 * paths (opened_path is already Zend's realpath; path_translated is resolved the same way, so
 * symlinks and relative segments agree; envelock_path_char folds Windows/macOS case and slashes).
 * An included file is never the request's main script, so this cannot relax include protection.
 * The fallback also requires that no user frame is executing (EG(current_execute_data) == NULL):
 * the entry script is compiled before execution begins, so a file pulled in during the request
 * (e.g. a user stream wrapper that forges opened_path to the main script's path) is never taken
 * for the entry and cannot slip past include protection (ENV-02). */
static int envelock_is_entry_script(zend_file_handle *file_handle)
{
    const char *requested;
    char resolved[MAXPATHLEN];
    zend_string *name;
    size_t length, i;

    if (file_handle->primary_script) return 1;
    if (EG(current_execute_data) != NULL) return 0;
    requested = SG(request_info).path_translated;
    if (!requested || !*requested) return 0;
    name = file_handle->opened_path ? file_handle->opened_path : file_handle->filename;
    if (!name || !VCWD_REALPATH(requested, resolved)) return 0;
    length = ZSTR_LEN(name);
    if (strlen(resolved) != length) return 0;
    for (i = 0; i < length; i++) {
        if (envelock_path_char((unsigned char)resolved[i]) !=
            envelock_path_char((unsigned char)ZSTR_VAL(name)[i])) return 0;
    }
    return 1;
}

/* Runtime manifest enforcement (pack --enforce-manifest). Read the signed binary manifest at the
 * package root, verify its Ed25519 signature with a trusted developer, and confirm every file it
 * lists still exists under the root — so a deleted file (e.g. a security check removed from the
 * deployed package) fails the request closed. Content tampering of protected files is already
 * caught by their GCM tag, so the manifest is not re-hashed here. Returns NULL on success or a
 * static reason. Called once per package per request (from the first protected file). `name` is
 * the loaded file's path and `root` the length of its package-folder prefix (it ends at a '/'). */
#define ENVELOCK_MANIFEST_NAME "envelock-manifest.bin"
#define ENVELOCK_MANIFEST_MAX (16U * 1024 * 1024)
static const char *envelock_check_manifest(const char *name, size_t root, const envelock_header *h,
                                           int dev)
{
    char *mpath, *entry;
    FILE *file;
    unsigned char *buf = NULL;
    size_t len, off, i;
    unsigned int count;
    int ok = 0, s;
    /* A manifest entry proves its developer HASHED those bytes, not that a trusted key SIGNED that
     * container: seeding it as "verified" attributes any listed bytes to the manifest's developer. With
     * one developer in identity.bin that is the same trust the developer already has; with several it
     * lets developer B list developer A's container and run it as B's, defeating include-protection
     * (ENV-04). So the fast path only runs when this server trusts a single developer. */
    int fastpath = ENVELOCK_INI_BOOL("envelock.manifest_fastpath") && envelock_identity.developer_count == 1;
    const char *reason = NULL;
    zend_stat_t st;

    mpath = (char *)malloc(root + sizeof(ENVELOCK_MANIFEST_NAME));
    if (!mpath) return "manifest enforcement: out of memory";
    memcpy(mpath, name, root);
    memcpy(mpath + root, ENVELOCK_MANIFEST_NAME, sizeof(ENVELOCK_MANIFEST_NAME));  /* incl NUL */
    file = envelock_plain_open(mpath);   /* public, signature-verified: UNC/long paths allowed (ENV-AUD-18) */
    free(mpath);
    if (!file || !envelock_file_is_regular(file)) {
        if (file) fclose(file);
        return "manifest enforcement: " ENVELOCK_MANIFEST_NAME " is missing or not a regular file";
    }
    buf = (unsigned char *)malloc(ENVELOCK_MANIFEST_MAX + 1);
    if (!buf) { fclose(file); return "manifest enforcement: out of memory"; }
    len = fread(buf, 1, ENVELOCK_MANIFEST_MAX + 1, file);
    fclose(file);
    /* magic(8) ver(1) rsv(1) project(16) release(16) serial(8) count(4) [entries] sig(64) */
    if (len == 0 || len > ENVELOCK_MANIFEST_MAX ||
        len < 54 + ENVELOCK_SIG_SIZE || memcmp(buf, "ENVLKMAN", 8) != 0 || buf[8] != 2) {
        reason = "manifest enforcement: the manifest is malformed"; goto done;
    }
    /* The manifest must be signed by the SAME developer that signed the package it governs, not by any
     * trusted developer in identity.bin. On a shared host where identity.bin trusts several independent
     * developers, accepting any signer let developer B forge a manifest for developer A's package and
     * delete A's security files (guard.php, middleware) while passing enforcement (ENV-2026-25). The
     * package's developer is `dev`; accept only signer slots that belong to that developer (its primary
     * and recovery keys are equivalent — same developer index). */
    for (s = 0; s < envelock_identity.signer_count; s++) {
        if (dev >= 0 && envelock_identity.signer_developer_index[s] == dev &&
            envelock_verify(buf, len, envelock_identity.signing_public[s])) { ok = 1; break; }
    }
    if (!ok) { reason = "manifest enforcement: the manifest is not signed by the package's own developer"; goto done; }
    /* Bind the manifest to THIS package's release: project at offset 10, release at 26 (see
     * build_manifest_bin). Without this a trusted-signed manifest of another (e.g. older) release
     * that lists a subset of the present files could be swapped in to hide a deleted file. */
    if (memcmp(buf + 10, h->project, 16) != 0 || memcmp(buf + 26, h->release, 16) != 0) {
        reason = "manifest enforcement: the manifest is for a different release (swapped in)"; goto done;
    }
    count = ((unsigned int)buf[50] << 24) | ((unsigned int)buf[51] << 16) |
            ((unsigned int)buf[52] << 8) | (unsigned int)buf[53];
    off = 54;
    for (i = 0; i < count; i++) {
        unsigned int plen;
        if (off + 2 > len - ENVELOCK_SIG_SIZE) { reason = "manifest enforcement: the manifest is truncated"; goto done; }
        plen = ((unsigned int)buf[off] << 8) | (unsigned int)buf[off + 1];
        off += 2;
        if (plen == 0 || plen > ENVELOCK_MAX_PATH || off + plen + 32 > len - ENVELOCK_SIG_SIZE) {
            reason = "manifest enforcement: the manifest is truncated"; goto done;
        }
        /* The path is relative to the package root and must stay inside it: reject a leading separator
         * (absolute), an embedded NUL, a backslash, or any ".." segment, so a tampered manifest cannot
         * name a file outside the tree (path traversal) (ENV-2026-25). */
        {
            const unsigned char *pp = buf + off;
            unsigned int k;
            int seg_start = 1, bad_path = 0;
            if (pp[0] == '/' || pp[0] == '\\') bad_path = 1;
            for (k = 0; k < plen && !bad_path; k++) {
                unsigned char c = pp[k];
                if (c == '\0' || c == '\\') { bad_path = 1; break; }
                if (seg_start && c == '.' && k + 1 < plen && pp[k + 1] == '.' &&
                    (k + 2 == plen || pp[k + 2] == '/')) { bad_path = 1; break; }   /* ".." segment */
                seg_start = (c == '/');
            }
            if (bad_path) {
                reason = "manifest enforcement: the manifest lists a path outside the package (traversal)";
                goto done;
            }
        }
        entry = (char *)malloc(root + plen + 1);
        if (!entry) { reason = "manifest enforcement: out of memory"; goto done; }
        memcpy(entry, name, root);
        memcpy(entry + root, buf + off, plen);
        entry[root + plen] = '\0';
        /* lstat, not stat: a deleted file replaced by a SYMLINK to any readable regular file elsewhere
         * would otherwise satisfy the "still present and regular" check and hide the deletion. Reject a
         * symlink outright (ENV-2026-25). */
        if (VCWD_LSTAT(entry, &st) != 0 || (st.st_mode & S_IFMT) != S_IFREG) {
            free(entry);
            reason = "manifest enforcement: a file listed in the signed manifest is missing, a symlink, or not a regular file (the package is incomplete or tampered)";
            goto done;
        }
        free(entry);
        off += plen + 32;
    }
    if (off != len - ENVELOCK_SIG_SIZE) {
        reason = "manifest enforcement: the manifest has trailing data";
    } else if (fastpath) {
        /* Cold-start fast path (envelock.manifest_fastpath, default on under --enforce-manifest, single
         * developer only, see above). Seeded only once the WHOLE manifest validated, so a refused
         * manifest leaves nothing behind. Each entry is path (u16 length + bytes) then the 32-byte
         * SHA-256 of the packaged file; a container whose bytes hash to it skips its per-file Ed25519
         * in envelock_signature_ok(). Altered bytes hash differently and take the full verify.
         * add, not update: never overwrite the developer a container was genuinely verified under. */
        size_t o = 54;
        for (i = 0; i < count &&
             zend_hash_num_elements(&ENVELOCK_G(verified)) < ENVELOCK_VERIFIED_MAX - ENVELOCK_SEED_RESERVE; i++) {
            unsigned int plen = ((unsigned int)buf[o] << 8) | (unsigned int)buf[o + 1];
            o += 2;
            zend_hash_str_add_ptr(&ENVELOCK_G(verified), (const char *)(buf + o + plen), 32,
                                  (void *)(uintptr_t)(s + 1));
            o += plen + 32;
        }
    }
done:
    free(buf);
    return reason;
}

/* Objective O7: a vault whose literals stay encrypted until the program reads one.
 *
 * The plaintext vault table is decrypted once, with the container, and then every literal in the
 * file sits in memory in one contiguous block for the whole request. Encrypting the table removes
 * that: the container's plaintext holds ciphertext, and a literal exists in the clear only between
 * the \__envelock_lit() call that asks for it and the end of the request, which wipes it. It does
 * not defeat a reader who can run the code or dump at the right moment — nothing here does — but
 * the cheap attack, reading one decrypted block and getting every secret string in the file, is
 * gone.
 *
 * `values` caches what has already been decrypted this request so a literal read in a loop is not
 * re-decrypted per iteration; those zend_strings are wiped at RSHUTDOWN like the plaintext vault's.
 */
typedef struct {
    unsigned char data_key[32];   /* unwrapped at load; never leaves this struct */
    uint32_t count;
    unsigned char *table;         /* copy of [u32 len | nonce 12 | tag 16 | ciphertext]* */
    size_t table_length;
    size_t *offsets;              /* per entry: byte offset into table (count entries) */
    zend_string **values;         /* per entry: decrypted value or NULL (count entries) */
} envelock_enc_vault;

static void envelock_enc_vault_free(zval *zv)
{
    envelock_enc_vault *v = (envelock_enc_vault *)Z_PTR_P(zv);
    uint32_t i;
    if (!v) return;
    for (i = 0; i < v->count; i++) {
        if (v->values && v->values[i]) {
            if (!ZSTR_IS_INTERNED(v->values[i])) {
                OPENSSL_cleanse(ZSTR_VAL(v->values[i]), ZSTR_LEN(v->values[i]));
            }
            zend_string_release(v->values[i]);
        }
    }
    OPENSSL_cleanse(v->data_key, sizeof(v->data_key));
    if (v->table) {
        OPENSSL_cleanse(v->table, v->table_length);
        efree(v->table);
    }
    efree(v->offsets);
    efree(v->values);
    efree(v);
}

/* Domain string the encrypted vault authenticates against (objective O7). Must match the
 * encoder's VAULT_INFO exactly: GCM folds the AAD into the tag, so a mismatch reads as a tampered
 * table rather than as a configuration error. */
#define ENVELOCK_VAULT_INFO "envelock-vault-1"
#define ENVELOCK_VAULT_INFO_LEN (sizeof(ENVELOCK_VAULT_INFO) - 1)

/* Big-endian u32 reader for the vault table format. */
static uint32_t envelock_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* Parse the FLAG_VAULT plaintext prefix (u32 table_bytes | u32 count | [u32 len | bytes]*) that
 * precedes the PHP source. Builds *vault as an array of zend_strings (copies of the literals) and
 * reports the source offset and length that follow. The plaintext is authenticated (GCM) and from a
 * trusted signer, but every field is still bounds-checked. Returns 1 on success (caller owns
 * *vault), 0 if the prefix is malformed. */
static int envelock_parse_vault(const unsigned char *text, size_t total, zval *vault,
                                size_t *source_off, size_t *source_len)
{
    size_t pos, table_end, i, count;
    uint32_t table_bytes;

    ZVAL_UNDEF(vault);
    if (total < 8) return 0;                          /* table_bytes(4) + count(4) at least */
    table_bytes = envelock_be32(text);
    if (table_bytes < 4 || table_bytes > total - 4) return 0;
    table_end = (size_t)4 + table_bytes;
    pos = 4;
    count = envelock_be32(text + pos);
    pos += 4;
    if (count > (table_bytes - 4) / 4) return 0;      /* each entry is at least a 4-byte length */
    array_init(vault);
    for (i = 0; i < count; i++) {
        uint32_t len;
        if (pos + 4 > table_end) goto bad;
        len = envelock_be32(text + pos);
        pos += 4;
        if (len > table_end - pos) goto bad;
        add_index_stringl(vault, (zend_ulong)i, (const char *)text + pos, len);
        pos += len;
    }
    *source_off = table_end;
    *source_len = total - table_end;
    return 1;
bad:
    zval_ptr_dtor(vault);
    ZVAL_UNDEF(vault);
    return 0;
}

/* Objective O7: parse the encrypted vault prefix (see envelock_enc_vault). Same contract as
 * envelock_parse_vault: bounds-check every field, report where the source starts, and never trust
 * a length read out of the blob. The data key is unwrapped here, at load, so an access later is one
 * AES-GCM decrypt and nothing else. Returns 1 on success (*out owns the vault), 0 if malformed. */
static int envelock_parse_vault_enc(const unsigned char *text, size_t total,
    const unsigned char content_key[32], envelock_enc_vault **out,
    size_t *source_off, size_t *source_len)
{
    size_t pos = 0, table_end, i, count;
    uint32_t table_bytes;
    envelock_enc_vault *v = NULL;

    *out = NULL;
    /* `total` is the container's PLAINTEXT, which carries no signature: the tag was consumed by
     * the container decryption. Only the 4-byte length prefix and the table have to fit in it, so
     * anything past `total - 8` is malformed or truncated. Subtracting the signature size here
     * (as an earlier draft did) rejected every table smaller than 64 bytes of slack. */
    if (total < 8) return 0;
    table_bytes = envelock_be32(text);
    if (table_bytes < 4 + 12 + 48 || table_bytes > total - 8) return 0;
    pos = 4;
    table_end = 4 + (size_t)table_bytes;
    if (table_end > total) return 0;

    count = envelock_be32(text + pos);
    pos += 4;
    /* An absurd count would drive the two arrays below; bound it by what the table can actually
     * hold, since every entry costs at least 4 + 12 + 16 bytes. */
    if (count > (table_bytes - 4 - 12 - 48) / (4 + 12 + 16)) return 0;

    v = ecalloc(1, sizeof(*v));
    if (!v) return 0;
    v->count = (uint32_t)count;
    v->offsets = ecalloc(count ? count : 1, sizeof(*v->offsets));
    v->values = ecalloc(count ? count : 1, sizeof(*v->values));
    if (!v->offsets || !v->values) goto fail;

    /* key_nonce 12 | wrapped_key 48 (32-byte key + 16-byte tag), authenticated by GCM. */
    if (pos + 12 + 48 > table_end) goto fail;
    if (!envelock_gcm_decrypt(content_key, text + pos,
                              (const unsigned char *)ENVELOCK_VAULT_INFO, ENVELOCK_VAULT_INFO_LEN,
                              text + pos + 12, 32,
                              text + pos + 12 + 32, v->data_key)) {
        goto fail;      /* wrong content key or a tampered table: fail closed */
    }
    pos += 12 + 48;

    for (i = 0; i < count; i++) {
        uint32_t len;
        if (pos + 4 > table_end) goto fail;
        len = envelock_be32(text + pos);
        pos += 4;
        /* len covers nonce(12) + tag(16) + ciphertext, so a zero-length literal still costs 28. */
        if (len < 12 + 16 || pos + len > table_end) {
            goto fail; }
        /* Relative to the table body, which starts at text+4 — the part v->table is a copy of,
         * so the offsets stay valid after the copy. Entry 0 lands at 4+12+48 = 64. */
        v->offsets[i] = pos - 4;
        pos += len;
    }
    if (pos != table_end) goto fail;      /* trailing data in the table */

    /* Copy the table out: `text` is the decrypted container, which is wiped when the compile
     * finishes, and the vault has to outlive it for the whole request. */
    v->table_length = (size_t)table_bytes;
    v->table = emalloc(v->table_length);
    if (!v->table) goto fail;
    memcpy(v->table, text + 4, v->table_length);

    *source_off = table_end;
    *source_len = total - table_end;
    *out = v;
    return 1;
fail:
    if (v) {
        zval holder;
        ZVAL_PTR(&holder, v);
        envelock_enc_vault_free(&holder);
    }
    return 0;
}

/* Decrypt entry `idx` of an encrypted vault, caching it. Returns the zend_string (owned by the
 * vault, wiped at RSHUTDOWN) or NULL. */
static zend_string *envelock_enc_vault_get(envelock_enc_vault *v, uint32_t idx)
{
    const unsigned char *entry;
    uint32_t len;
    size_t cipher_len;
    unsigned char *plain;
    zend_string *result;

    if (idx >= v->count) return NULL;
    if (v->values[idx]) return v->values[idx];

    /* offsets[] are relative to the table body, so the entry's length field sits 4 bytes before
     * the nonce. The first entry is at 64, so this never reads before the buffer. */
    if (v->offsets[idx] < 4 || v->offsets[idx] + 4 > v->table_length) return NULL;
    entry = v->table + v->offsets[idx];
    len = envelock_be32(entry - 4);
    if (len < 12 + 16 || v->offsets[idx] + (size_t)len > v->table_length) return NULL;
    cipher_len = (size_t)len - 12 - 16;

    plain = emalloc(cipher_len + 1);
    if (!plain) return NULL;
    if (!envelock_gcm_decrypt(v->data_key, entry,
                              (const unsigned char *)ENVELOCK_VAULT_INFO, ENVELOCK_VAULT_INFO_LEN,
                              entry + 12, cipher_len,
                              entry + 12 + cipher_len, plain)) {
        OPENSSL_cleanse(plain, cipher_len);
        efree(plain);
        return NULL;      /* tampered entry: this one literal is unreadable, the request goes on */
    }
    plain[cipher_len] = '\0';
    result = zend_string_init((const char *)plain, cipher_len, 0);
    OPENSSL_cleanse(plain, cipher_len);      /* the copy we decrypted into is not the one we keep */
    efree(plain);
    if (!result) return NULL;
    v->values[idx] = result;
    return result;
}

/* Checks that need the (already verified) header, made BEFORE any decryption. Returns NULL or
 * the reason for refusing the file; *owner receives the request-lifetime copy of the
 * package's project|release (kept in roots) to record the file under. */
static const char *envelock_policy(const envelock_header *h, zend_file_handle *file_handle,
    const unsigned char **owner, int signer)
{
    zend_string *name = file_handle->opened_path ? file_handle->opened_path : file_handle->filename;
    const char *prepend = INI_STR("auto_prepend_file"), *append = INI_STR("auto_append_file");
    unsigned char identity[32 + sizeof(int) + 1]; /* project | release | developer index | sealed */
    size_t root = 0;
    zend_string *key;
    zval *seen;
    int i;
    int dev = (signer >= 0 && signer < envelock_identity.signer_count)
                  ? envelock_identity.signer_developer_index[signer] : -2;
    for (i = 0; i < envelock_identity.minimum_count; i++) {
        /* ENV-AUD-14: a minimum applies to a package only when it is unbound (-1) or was set by the
         * SAME developer, so one trusted developer cannot brick another's project on a shared host. */
        int mdev = envelock_identity.minimum_developer_index[i];
        if ((mdev == -1 || mdev == dev) &&
            memcmp(envelock_identity.minimum_project[i], h->project, 16) == 0 &&
            h->serial < envelock_identity.minimum_serial[i]) {
            return "this release is older than the minimum set for its project in the identity file";
        }
    }
    if (!name || !envelock_at_packaged_path(ZSTR_VAL(name), ZSTR_LEN(name), h->path, h->path_length, &root)) {
        return "the file is not at the path it was packaged with (moved or swapped)";
    }
    /* One project and release per package folder: no file swapped in from another release.
     * The folder key is spelled the way the path comparison sees it (one key per folder). */
    memcpy(identity, h->project, 16);                    /* project (ENV-16: explicit members, */
    memcpy(identity + 16, h->release, 16);               /* release   not one span across both) */
    memcpy(identity + 32, &dev, sizeof(int));            /* bind the verifying DEVELOPER, not the
                                                          * signer slot: primary and recovery keys of
                                                          * one developer are equivalent (ENV-AUD-17) */
    identity[36] = (h->flags & ENVELOCK_FLAG_SEALED) ? 1 : 0;   /* sealed tree (C9) */
    key = zend_string_init(ZSTR_VAL(name), root, 0);
#if defined(_WIN32) || defined(__APPLE__)
    {
        size_t n;
        for (n = 0; n < root; n++) ZSTR_VAL(key)[n] = (char)envelock_path_char((unsigned char)ZSTR_VAL(key)[n]);
    }
#endif
    seen = zend_hash_find(&ENVELOCK_G(roots), key);
    if (seen && memcmp(Z_STRVAL_P(seen), identity, sizeof(identity)) != 0) {
        zend_string_release(key);
        return "files of different releases, projects or developers are mixed in one folder";
    }
    if (!seen) {
        zval value;
        /* Verify the signed manifest BEFORE registering the package as seen or marking it sealed: a
         * failed check must not leave the root recorded, or a later file of the same package in this
         * request (from a shutdown function or __destruct) would take the !seen branch as already
         * validated and skip the check (ENV-AUD-03). Once per package per request. */
        if (h->flags & ENVELOCK_FLAG_ENFORCE_MANIFEST) {
            const char *bad = envelock_check_manifest(ZSTR_VAL(name), root, h, dev);
            if (bad) { zend_string_release(key); return bad; }
        }
        ZVAL_STRINGL(&value, (const char *)identity, sizeof(identity));
        seen = zend_hash_add_new(&ENVELOCK_G(roots), key, &value);
        if (identity[36]) {
            ENVELOCK_G(sealed_active)++;   /* a sealed package is now active (C9) */
            /* Remember this sealed root for the WORKER's lifetime, so a plain file injected into the
             * tree and requested directly (before any sealed file loads this request) is still
             * refused below. The key is stored with the HT's persistent allocator. */
            zend_hash_str_add_empty_element(&ENVELOCK_G(sealed_roots), ZSTR_VAL(key), ZSTR_LEN(key));
        }
    }
    zend_string_release(key);
    *owner = (const unsigned char *)Z_STRVAL_P(seen);
    if ((h->flags & ENVELOCK_FLAG_NO_PREPEND) && ((prepend && *prepend) || (append && *append))) {
        return "auto_prepend_file/auto_append_file are set and this package refuses them";
    }
    if ((h->flags & ENVELOCK_FLAG_NO_FFI) && envelock_ffi_usable()) {
        return "this package refuses to load while FFI or dl() is reachable "
               "(set ffi.enable=0 and enable_dl=0, or remove the ffi extension)";
    }
    if ((h->flags & ENVELOCK_FLAG_INCLUDE_PROTECTION) && !envelock_is_entry_script(file_handle) &&
        !envelock_called_from_project(h->project, signer)) {
        return "include protection: it can only be loaded by its own application";
    }
    return NULL;
}

/* 1 iff a sealed package's folder (a root key, which ends at its '/' boundary) is a prefix of
 * this plain file's path. Only consulted while a sealed package is active this request, so the
 * roots table is non-empty; the scan is over the few package folders seen so far. */
static int envelock_under_sealed_root(zend_string *name)
{
    zend_string *key;
    if (!name) return 0;
    /* Checked against the per-WORKER sealed-roots set (every key is a sealed-package root by
     * construction), not the per-request roots, so an injected plain file under a sealed tree is
     * refused even on a request that has not itself loaded a sealed file yet. */
    ZEND_HASH_FOREACH_STR_KEY(&ENVELOCK_G(sealed_roots), key) {
        if (key && ZSTR_LEN(key) > 0) {
            size_t klen = ZSTR_LEN(key), i;
            int match = ZSTR_LEN(name) >= klen;
            for (i = 0; match && i < klen; i++) {
                if (envelock_path_char((unsigned char)ZSTR_VAL(name)[i]) !=
                    envelock_path_char((unsigned char)ZSTR_VAL(key)[i])) match = 0;
            }
            if (match) return 1;
        }
    } ZEND_HASH_FOREACH_END();
    return 0;
}

/* 1 iff `name` (a plain file found under a sealed tree) sits under one of the operator's allowed
 * cleartext prefixes (envelock.sealed_cleartext, PATH_SEPARATOR-separated). Lets a sealed CMS run its
 * config and the PHP it generates at run time without dropping the sealed guarantee for the rest of
 * the tree. Prefix match uses envelock_path_char so it is case/sep-folded like the sealed-root test. */
static int envelock_sealed_cleartext_allowed(zend_string *name)
{
    const char *list = INI_STR("envelock.sealed_cleartext");
    const char *p;
    size_t nlen;
    if (!list || !*list || !name) return 0;
    nlen = ZSTR_LEN(name);
    for (p = list; *p; ) {
        const char *end = p;
        size_t plen, i;
        int match;
        while (*end && *end != ZEND_PATHS_SEPARATOR) end++;   /* one entry is [p, end) */
        plen = (size_t) (end - p);
        match = (plen > 0 && nlen >= plen);
        for (i = 0; match && i < plen; i++) {
            if (envelock_path_char((unsigned char) ZSTR_VAL(name)[i]) !=
                envelock_path_char((unsigned char) p[i])) match = 0;
        }
        /* Prefix must end at a path boundary, or '/a/cache' would also allow the sibling
         * '/a/cacheEVIL.php' and let an attacker run plain PHP inside a sealed tree (fail-open).
         * OK iff the whole name is the prefix, the prefix itself ends in a separator, or the next
         * char in `name` is a separator ('/', or '\\' on Windows, matching envelock_path_char). */
        if (match && !(nlen == plen
                       || p[plen - 1] == '/' || ZSTR_VAL(name)[plen] == '/'
#ifdef _WIN32
                       || p[plen - 1] == '\\' || ZSTR_VAL(name)[plen] == '\\'
#endif
                      )) match = 0;
        if (match) return 1;
        p = (*end) ? end + 1 : end;
    }
    return 0;
}

/* Lexically normalize a path (collapse '.', '..' and duplicate separators), without touching the
 * filesystem so it never follows symlinks. Used to decide whether a REQUESTED path lands inside
 * the sealed tree: the raw filename of an include like '<tree>/../plain.php' starts with the tree
 * prefix yet resolves outside it, so a prefix test on the raw name wrongly refused it (ENV-AUD-04).
 * A symlink that lives inside the tree normalizes to an inside path and is still refused. */
static zend_string *envelock_lexical_norm(zend_string *name)
{
    size_t n = ZSTR_LEN(name), i = 0, w = 0, top = 0;
    const char *s = ZSTR_VAL(name);
    char *out = emalloc(n + 2);
    size_t *starts = emalloc((n + 1) * sizeof(size_t));
    int absolute = 0;
    zend_string *res;
    /* '\\' is a path separator only on Windows; on POSIX it is a valid filename character, so
     * (matching envelock_path_char) it must not split a segment there. */
#ifdef _WIN32
#define ENVELOCK_IS_SEP(c) ((c) == '/' || (c) == '\\')
#else
#define ENVELOCK_IS_SEP(c) ((c) == '/')
#endif
    if (n > 0 && ENVELOCK_IS_SEP(s[0])) { out[w++] = '/'; absolute = 1; }
    while (i < n) {
        size_t start = i, seglen;
        while (i < n && !ENVELOCK_IS_SEP(s[i])) i++;
        seglen = i - start;
        while (i < n && ENVELOCK_IS_SEP(s[i])) i++;      /* skip run of separators */
        if (seglen == 0) continue;
        if (seglen == 1 && s[start] == '.') continue;
        if (seglen == 2 && s[start] == '.' && s[start + 1] == '.') {
            if (top > 0) { w = starts[--top]; }          /* pop the last kept segment */
            else if (!absolute) { out[w++] = '.'; out[w++] = '.'; out[w++] = '/'; }
            continue;
        }
        starts[top++] = w;
        memcpy(out + w, s + start, seglen);
        w += seglen;
        out[w++] = '/';
    }
    if (w > 1 && out[w - 1] == '/') w--;                 /* drop the trailing separator */
    else if (w == 0) out[w++] = '.';
    res = zend_string_init(out, w, 0);
    efree(out);
    efree(starts);
    return res;
#undef ENVELOCK_IS_SEP
}

/* eval() (and any other runtime string compile) routes through zend_compile_string. While a
 * sealed package is active, refuse it: injected PHP compiled this way runs inside the protected
 * process and could read the decrypted code. Protected files compile through compile_file, not
 * here, so this never touches them. */
static zend_op_array *envelock_compile_string(zend_string *source, const char *filename,
    zend_compile_position position)
{
    if (ENVELOCK_G(sealed_active) > 0) {
        zend_error_noreturn(E_COMPILE_ERROR,
            "Envelock: a sealed package is active; eval() is refused");
    }
    return envelock_previous_compile_string(source, filename, position);
}

static zend_op_array *envelock_compile_file(zend_file_handle *file_handle, int type)
{
    char *blob = NULL;
    size_t blob_length = 0, source_length = 0;
    zend_op_array *result = NULL;
    envelock_header h;
    const char *refused;
    unsigned char *text;
    /* O7: the package content key, asked for so an encrypted vault's data key can be
     * unwrapped. Cleared before returning, vault or no vault. */
    unsigned char content_key[32];
    const unsigned char *owner = NULL;
    int signer = -1;

    /* Use Zend's original stream: preserves include_path, open_basedir and stream state. */
    if (zend_stream_fixup(file_handle, &blob, &blob_length) == FAILURE) {
        return envelock_previous_compile_file(file_handle, type);
    }
    if (blob_length < sizeof(ENVELOCK_STUB) - 1 ||
        memcmp(blob, ENVELOCK_STUB, sizeof(ENVELOCK_STUB) - 1) != 0) {
        /* Refuse the plain file if EITHER the requested path (filename, lexically normalized so an
         * '<tree>/../plain.php' include that resolves outside the tree is allowed) OR the resolved
         * path (opened_path) is under a sealed root: a symlink placed inside the sealed folder
         * pointing to external plain PHP resolves opened_path outside the tree, but its requested
         * path is inside it, so checking only opened_path let it through (ENV-AUD-04).
         * Checked unconditionally (not gated on sealed_active this request): envelock_under_sealed_root
         * consults the per-worker sealed-roots set, so a plain file requested directly as the entry
         * script inside a sealed tree is refused even before any sealed file has loaded this request,
         * once the worker has seen the sealed package. The set is empty (and this is a cheap no-op)
         * when no sealed package has ever loaded in this worker. */
        {
            int under_root = 0;
            if (file_handle->filename) {
                zend_string *norm = envelock_lexical_norm(file_handle->filename);
                under_root = envelock_under_sealed_root(norm);
                zend_string_release(norm);
            }
            if (!under_root && file_handle->opened_path)
                under_root = envelock_under_sealed_root(file_handle->opened_path);
            /* Refuse this plain PHP if it is under a sealed root (the per-worker set catches even a
             * directly-requested entry script before any sealed file has loaded this request), OR if a
             * sealed package is ALREADY ACTIVE this request. The second case is the important one: while
             * sealed, NO unprotected PHP runs, wherever it lives — so an LFI, an uploaded /tmp/evil.php,
             * or a phar://wrapper include cannot execute plain code merely by sitting OUTSIDE the tree
             * (ENV-2026-28). The operator's sealed_cleartext allowlist is the only exception (its config
             * and the PHP a CMS generates at run time). */
            if (under_root || ENVELOCK_G(sealed_active) > 0) {
                int allowed = 0;
                if (file_handle->filename) {
                    zend_string *norm = envelock_lexical_norm(file_handle->filename);
                    allowed = envelock_sealed_cleartext_allowed(norm);
                    zend_string_release(norm);
                }
                if (!allowed && file_handle->opened_path)
                    allowed = envelock_sealed_cleartext_allowed(file_handle->opened_path);
                if (!allowed) {
                    zend_error_noreturn(E_COMPILE_ERROR,
                        "Envelock: sealed package active: unprotected PHP is refused (allowlist a "
                        "legitimate path via envelock.sealed_cleartext)");
                }
            }
        }
        return envelock_previous_compile_file(file_handle, type);
    }
    if (envelock_persistent_cache()) {
        zend_error_noreturn(E_COMPILE_ERROR,
            "Envelock: disable opcache.file_cache, opcache.file_cache_only and opcache.preload (they persist decrypted opcodes)");
    }
    if (envelock_shm_cache() && !ENVELOCK_INI_BOOL("envelock.allow_opcache")) {
        zend_error_noreturn(E_COMPILE_ERROR,
            "Envelock: OPcache is enabled; either disable it, or set envelock.allow_opcache=1 and exclude the protected tree via opcache.blacklist_filename");
    }
    /* OPcache sets ZEND_COMPILE_IGNORE_OTHER_FILES on CG(compiler_options) only when it is about
     * to persist this file into shared memory (a file excluded by opcache.blacklist_filename is
     * compiled WITHOUT this flag). So even with allow_opcache=1, if the protected tree is not in
     * the blacklist we catch it here and fail closed instead of letting decrypted opcodes reach
     * SHM. This makes the blacklist self-verifying on the first request for each file. */
    if (CG(compiler_options) & ZEND_COMPILE_IGNORE_OTHER_FILES) {
        zend_error_noreturn(E_COMPILE_ERROR,
            "Envelock: OPcache is about to cache this protected file in shared memory; add its real path to opcache.blacklist_filename (or disable OPcache)");
    }
    /* zend.multibyte routes the decrypted source through mbstring's encoding filters (a per-dir /
     * per-user INI), an ambiguous lexing path we do not want for protected code. Fail closed. */
    if (CG(multibyte)) {
        zend_error_noreturn(E_COMPILE_ERROR,
            "Envelock: zend.multibyte must be off for protected files (its encoding filters can reinterpret the decrypted source)");
    }
    if (!ENVELOCK_INI_BOOL("envelock.allow_debuggers") && (refused = envelock_debugger()) != NULL) {
        zend_error_noreturn(E_COMPILE_ERROR,
            "Envelock: %s is loaded and can dump or trace the decrypted code; remove it or set envelock.allow_debuggers=1",
            refused);
    }
    /* O3: a deliberately separate gate from the one above. Setting allow_debuggers says "I accept
     * the named extensions"; it does not say "I accept being traced or rehooked", and one flag
     * must not silently grant both. */
    if ((refused = envelock_integrity_check()) != NULL) {
        zend_error_noreturn(E_COMPILE_ERROR,
            "Envelock: %s; refusing to run protected code in this process", refused);
    }
    if (envelock_identity.recipient_count <= 0 || envelock_identity.signer_count <= 0) {
        if (envelock_identity_error) {
            zend_error_noreturn(E_COMPILE_ERROR, "Envelock: identity file rejected: %s",
                envelock_identity_error);
        }
        zend_error_noreturn(E_COMPILE_ERROR,
            "Envelock: no identity configured; set envelock.identity in php.ini to the server key file");
    }
    /* O8: the license, if this deployment has one. Deliberately after the identity check (the
     * trusted keys come from it) and before anything of the file is decrypted or parsed. */
    if (envelock_licence_present) {
        const char *refusal;
        /* Clamp before the unsigned cast: envelock.clock_tolerance is PHP_INI_SYSTEM and read as a
         * signed long, so a negative value (e.g. -1) would cast to a huge uint64 and make every
         * floor (watermark - tolerance, trusted_floor - tolerance) collapse to 0, silently disabling
         * the whole anti-rollback check (audit NU-01). Negative -> the documented default; an absurd
         * value -> capped at one year. */
        const char *tol_str = INI_STR("envelock.clock_tolerance");   /* NULL-guarded: atol(NULL) is UB (ENV-2026-31) */
        long tol_raw = tol_str ? (long) ZEND_ATOL(tol_str) : -1;     /* missing -> the documented default below */
        uint64_t tolerance = tol_raw < 0 ? 3600U
                           : (tol_raw > 31536000L ? 31536000U : (uint64_t) tol_raw);
        if (envelock_licence_error) {
            zend_error_noreturn(E_COMPILE_ERROR, "Envelock: license rejected: %s",
                envelock_licence_error);
        }
        /* Re-checked per file: expiry moves with the clock, and a worker may outlive the license. */
        if ((refusal = envelock_licence_refusal(&envelock_licence_data, 1)) != NULL) {
            zend_error_noreturn(E_COMPILE_ERROR, "Envelock: license rejected: %s", refusal);
        }
        /* O8 network floor: checked whether or not a state file exists, since it is the time the
         * machine cannot invent — it catches a clock rollback that also deleted the state file.
         * (Fixed Nov 2026: this used to be nested under envelock.clock_state, so removing the state
         * file disabled it.) */
        if (envelock_trusted_floor) {
            uint64_t floor_value = envelock_trusted_floor > tolerance
                ? envelock_trusted_floor - tolerance : 0;
            time_t now = time(NULL);
            if (now > 0 && (uint64_t) now < floor_value) {
                zend_error_noreturn(E_COMPILE_ERROR,
                    "Envelock: license rejected: the system clock is behind the time reported "
                    "by %s (clock set back?)", INI_STR("envelock.trusted_time"));
            }
        }
        /* O8 anti-rollback record. Only with a license in force, and only once the license itself
         * has been accepted, so a refused request cannot push the watermark forward and a
         * deployment with no license is untouched. */
        if (envelock_clock_path) {
            if ((refusal = envelock_clock_refusal(envelock_clock_watermark, tolerance)) != NULL) {
                zend_error_noreturn(E_COMPILE_ERROR, "Envelock: license rejected: %s", refusal);
            }
            envelock_clock_advance(envelock_clock_path, &envelock_clock_watermark,
                                   tolerance > 0 ? tolerance : 3600, 1);
        }
    }
    /* Exact layout (header, path, table and declared length against the real blob) BEFORE
     * anything else, so the in-place plaintext region lies inside the buffer. */
    if (!envelock_parse_header((const unsigned char *)blob, blob_length, &h)) {
        zend_error_noreturn(E_COMPILE_ERROR, "Envelock: invalid protected file size or header");
    }
    /* Per-installation trust store. The signature (independent of the recipient) is verified
     * once against the trusted signers (or found in the per-worker cache of already verified
     * containers); only then are the header's path, release and flags trusted. */
    if (!envelock_signature_ok((const unsigned char *)blob, blob_length, &signer)) {
        zend_error_noreturn(E_COMPILE_ERROR,
            "Envelock: invalid protected file or not addressed to this installation");
    }
    if (!ENVELOCK_G(request_ready)) {
        zend_hash_init(&ENVELOCK_G(loaded), 64, NULL, NULL, 0);
        zend_hash_init(&ENVELOCK_G(roots), 4, NULL, ZVAL_PTR_DTOR, 0);
        zend_hash_init(&ENVELOCK_G(litvault), 8, NULL, ZVAL_PTR_DTOR, 0);
        zend_hash_init(&ENVELOCK_G(litvault_enc), 8, NULL, envelock_enc_vault_free, 0);
        ENVELOCK_G(sealed_active) = 0;
        ENVELOCK_G(request_ready) = 1;
    }
    if ((refused = envelock_policy(&h, file_handle, &owner, signer)) != NULL) {
        zend_error_noreturn(E_COMPILE_ERROR, "Envelock: refused: %s", refused);
    }
    /* The vault resolves \__envelock_lit(idx) calls that exist only in source; a bytecode image
     * was compiled elsewhere and has no source to resolve them in. Refuse the combination rather
     * than let a file claim both. */
    if ((h.flags & (ENVELOCK_FLAG_BYTECODE | ENVELOCK_FLAG_VAULT)) ==
        (ENVELOCK_FLAG_BYTECODE | ENVELOCK_FLAG_VAULT)) {
        zend_error_noreturn(E_COMPILE_ERROR,
            "Envelock: a bytecode file cannot carry a literal vault (pack without --vault-strings)");
    }

    /* FLAG_BYTECODE: the plaintext is a bytecode image, not source.
     *
     * Deserializing CONSUMES its input — the map-pointer slots stop being offsets and become
     * pointers into this request, and the non-interned strings are appended past the program (see
     * envelock_bc_unserialize) — and the op_array it returns, with its opcodes, literals and class
     * entries, points INTO that same buffer. So the buffer has to live exactly as long as the
     * request, which is what request memory does. Allocating it for the process instead leaked one
     * image per file per request in a long-lived worker; measured on a two-file package under the
     * built-in web server, RSS grew about 25 kB per request and was flat once the block moved here.
     * Upstream OPcache does the same for its own file cache. */
    if (h.flags & ENVELOCK_FLAG_BYTECODE) {
#if !ENVELOCK_HAVE_BYTECODE
        zend_error_noreturn(E_COMPILE_ERROR,
            "Envelock: this loader was built without bytecode support for this PHP version; "
            "ship source packages, or rebuild the loader with the bytecode layer for this engine");
#else
        unsigned char *work = (unsigned char *)emalloc(h.size + ENVELOCK_BC_SLACK);
        if (work == NULL) {
            zend_error_noreturn(E_COMPILE_ERROR, "Envelock: out of memory for the bytecode image");
        }
        if (!envelock_open((const unsigned char *)blob, blob_length, work, h.size,
                           &source_length, NULL) || source_length != h.size) {
            OPENSSL_cleanse(work, h.size);
            efree(work);
            zend_error_noreturn(E_COMPILE_ERROR,
                "Envelock: invalid protected file or not addressed to this installation");
        }
        memset(work + h.size, 0, ENVELOCK_BC_SLACK);
        /* The plaintext exists only in `work`. Clear exactly the ciphertext in the request buffer
         * plus Zend's look-ahead padding — NOT "from the ciphertext to the end of the blob": the
         * container is header, path, recipient table and ciphertext, so that span overshoots by
         * the whole file length and scribbles over the heap behind it. */
        OPENSSL_cleanse((void *)h.ciphertext, h.size);
        OPENSSL_cleanse(blob + blob_length, ZEND_MMAP_AHEAD);

        {
            int retain = 0;
            result = envelock_bc_load_image_ex(work, h.size, ENVELOCK_BC_SLACK, &retain);
            if (result == NULL) {
                /* The layer does not free its input on failure. When nothing can reference `work`, the
                 * decrypted image (plaintext opcodes and literals) is scrubbed and freed rather than
                 * left on the heap to be read back or captured in a core dump (ENV-2026-09). When the
                 * install had already started, the layer rolled back what it registered but something
                 * may still point into `work`, so it is left on the request heap, released with it at
                 * the end of the request (freeing it here could leave dangling engine entries). */
                if (!retain) {
                    OPENSSL_cleanse(work, h.size + ENVELOCK_BC_SLACK);
                    efree(work);
                }
                zend_error_noreturn(E_COMPILE_ERROR,
                    "Envelock: the bytecode image does not match this PHP build or is malformed (it is "
                    "bound to the PHP version and build that produced it); repack for this server or "
                    "ship source");
            }
        }
        /* On success the op_array points INTO `work`, so it must stay mapped for the worker's life and
         * cannot be freed or cleansed. Keep it out of core dumps instead (MADV_DONTDUMP), the same
         * marking envelock_bc_adopt applies on its own uncached path (ENV-2026-09). */
        envelock_bc_keep(work, h.size + ENVELOCK_BC_SLACK);
        /* Same bookkeeping as the source path: from now on this file counts as a trusted caller
         * for --include-protection. No literal vault can be attached (refused above). */
        if (result->filename) {
            zend_hash_update_ptr(&ENVELOCK_G(loaded), result->filename, (void *)owner);
        }
        return result;
#endif /* ENVELOCK_HAVE_BYTECODE */
    }

    /* The ciphertext is decrypted IN PLACE in the handle's own buffer (zend_stream_fixup:
     * emalloc'd, blob_length plus ZEND_MMAP_AHEAD bytes), so the file never exists twice in
     * memory; without re-verifying (key pairs were checked at MINIT). Every Zend allocation
     * (caches, request records) happens before decrypting; none from there to compiling. */
    text = (unsigned char *)h.ciphertext;
    /* O7: the content key is needed to unwrap an encrypted vault's data key, so ask for it.
     * Cleared below whether or not the file turns out to have a vault. */
    if (!envelock_open((const unsigned char *)blob, blob_length, text, h.size, &source_length,
                       content_key) ||
        source_length != h.size) {
        OPENSSL_cleanse(text, h.size);              /* unauthenticated bytes, never used */
        OPENSSL_cleanse(content_key, sizeof(content_key));   /* a cached key was copied in first */
        zend_error_noreturn(E_COMPILE_ERROR,
            "Envelock: invalid protected file or not addressed to this installation");
    }
    /* FLAG_VAULT: the plaintext is a literal-table prefix then the source. Parse the table (copies
     * into zend_strings) and compile only the source; the table is attached to the file below so
     * \__envelock_lit(idx) can resolve it, keeping those literals out of the op_array constants. */
    {
        size_t source_off = 0;
        zval vault;
        int have_vault = (h.flags & ENVELOCK_FLAG_VAULT) != 0;
        /* O7: FLAG_VAULT_ENC replaces the plaintext table with an encrypted one, so the two
         * parsers are mutually exclusive even though both flags are set. */
        int have_vault_enc = (h.flags & ENVELOCK_FLAG_VAULT_ENC) != 0;
        envelock_enc_vault *enc_vault = NULL;
        if (have_vault_enc) {
            have_vault = 0;
            if (!envelock_parse_vault_enc(text, h.size, content_key, &enc_vault,
                                          &source_off, &source_length)) {
                OPENSSL_cleanse(text, h.size);
                OPENSSL_cleanse(content_key, sizeof(content_key));
                zend_error_noreturn(E_COMPILE_ERROR,
                    "Envelock: invalid protected file (encrypted vault table)");
            }
        } else if (have_vault &&
                   !envelock_parse_vault(text, h.size, &vault, &source_off, &source_length)) {
            OPENSSL_cleanse(text, h.size);
            OPENSSL_cleanse(content_key, sizeof(content_key));
            zend_error_noreturn(E_COMPILE_ERROR, "Envelock: invalid protected file (vault table)");
        }
        /* The content key has done its job (the vault's data key is unwrapped now); the vault
         * carries its own from here on, so do not leave this one on the stack. */
        OPENSSL_cleanse(content_key, sizeof(content_key));
        /* Move the plaintext source to the start and zero everything after it (table prefix,
         * left-over plaintext and Zend's look-ahead padding). The SAME handle is then compiled as a
         * real file (not eval: paths, returns and strict_types preserved); a new filename-type
         * handle could be reopened, and its buffer orphaned, by a later compile hook. */
        memmove(blob, text + source_off, source_length);
        memset(blob + source_length, 0, blob_length + ZEND_MMAP_AHEAD - source_length);
        file_handle->len = source_length;

        zend_try {
            result = envelock_previous_compile_file(file_handle, type);
        } zend_catch {
            if (have_vault) zval_ptr_dtor(&vault);
            if (enc_vault) {
                zval holder;
                ZVAL_PTR(&holder, enc_vault);
                envelock_enc_vault_free(&holder);
            }
            OPENSSL_cleanse(blob, blob_length + ZEND_MMAP_AHEAD);
            /* zend_bailout() is _zend_bailout(__FILE__, __LINE__): it would embed the absolute
             * path of the build directory (and so the builder's user name) in the shipped module.
             * Same call, relative file name. */
            _zend_bailout("envelock.c", __LINE__);
        } zend_end_try();
        /* The compiled code holds its own copies: clear the source before Zend frees it. */
        OPENSSL_cleanse(blob, blob_length + ZEND_MMAP_AHEAD);
        if (result && result->filename) {                /* a trusted caller from now on */
            zend_hash_update_ptr(&ENVELOCK_G(loaded), result->filename, (void *)owner);
            if (have_vault) zend_hash_update(&ENVELOCK_G(litvault), result->filename, &vault);
            if (enc_vault) {
                zend_hash_update_ptr(&ENVELOCK_G(litvault_enc), result->filename, enc_vault);
                enc_vault = NULL;                        /* the table owns it from here */
            }
        } else if (have_vault) {
            zval_ptr_dtor(&vault);                       /* no op_array to attach the table to */
        }
        if (enc_vault) {                                 /* no op_array to attach the vault to */
            zval holder;
            ZVAL_PTR(&holder, enc_vault);
            envelock_enc_vault_free(&holder);
        }
    }
    return result;
}

/* Lock a key buffer into RAM and keep it out of core dumps. Best effort — a failure (e.g.
 * RLIMIT_MEMLOCK) never blocks anything; the memory just is not locked. */
static void envelock_protect_bytes(void *p, size_t len)
{
#if defined(__linux__)
    /* madvise() rejects an unaligned start with EINVAL (mlock() would round down, but madvise() does
     * not), so align the start down and the length up to whole pages — otherwise MADV_DONTDUMP failed
     * silently for the unaligned identity struct and the heap keys (ENV-AUD-01). MADV_DONTDUMP is
     * belt-and-suspenders over PR_SET_DUMPABLE(0), which already makes the whole process
     * non-dumpable, so marking the rest of a shared page is harmless. */
    long ps = sysconf(_SC_PAGESIZE);
    if (ps > 0) {
        uintptr_t start = (uintptr_t)p & ~((uintptr_t)ps - 1);
        size_t span = (((uintptr_t)p + len) - start + (size_t)ps - 1) & ~((size_t)ps - 1);
        if (mlock((void *)start, span) == 0) (void)madvise((void *)start, span, MADV_DONTDUMP);
    }
#elif defined(_WIN32)
    VirtualLock(p, len);
#elif defined(__APPLE__)
    (void)mlock(p, len);
#endif
}

static void envelock_unprotect_bytes(void *p, size_t len)
{
    /* Deliberately NOT munlock: a 32-byte cache key shares its page with other locked keys, and
     * munlock() clears VM_LOCKED for the WHOLE page, which would let neighbouring keys be swapped
     * (ENV-AUD-01). The locked pages are few (bounded by the key cache) and released at process
     * exit; the bytes are still cleansed by the caller. Windows is the same: VirtualUnlock() works on
     * whole pages and is not counted, so unlocking one key unlocked every key sharing its page; the
     * ENV-AUD-01 fix had only reached the POSIX branch (audit 2026-11-12, H-07). */
    (void)p; (void)len;
}

/* Mark the process non-dumpable (no core dump, no ptrace/proc-mem by the same uid). Separate from
 * the key locking because setuid() (PHP-FPM dropping privileges) resets it, so it is re-applied in
 * RINIT after the worker has changed user. */
static void envelock_set_undumpable(void)
{
#if defined(__linux__)
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
}

static void envelock_harden_memory(void)
{
    envelock_set_undumpable();
    envelock_protect_bytes(&envelock_identity, sizeof(envelock_identity));
}

PHP_MINIT_FUNCTION(envelock)
{
#if defined(ZTS) && defined(COMPILE_DL_ENVELOCK)
    ZEND_TSRMLS_CACHE_UPDATE();   /* ZTS: valid cache before any EG() use, even pre-RINIT */
#endif
    REGISTER_INI_ENTRIES();
    envelock_crypto_init();   /* optional speed-up: without it each call fetches on its own */
#if ENVELOCK_HAVE_BYTECODE
    envelock_bc_startup();    /* O1: persistence state for the bytecode layer (no SHM, no files) */
#endif
    /* O2: the arena must exist before the identity is read into it, and this is the right point
     * for a preforked server (PHP-FPM): MINIT runs in the master before it forks, and a child
     * inherits an already-mapped region, which is exactly what memfd_secret needs — the manual
     * asks for the region to be created after the fork rather than across it. */
    if (ENVELOCK_INI_BOOL("envelock.secret_memory")) {
        if (envelock_secret_init(0)) {
            envelock_identity.x25519_private = envelock_secret_alloc(
                ENVELOCK_MAX_RECIPIENTS_ID * 32);
        }
    }
    if (envelock_identity.x25519_private == NULL) {
        /* No arena, or it was exhausted: keep the keys in .bss, protected the old way below. */
        envelock_identity.x25519_private = envelock_identity.x25519_private_fallback;
    }
    /* A missing or invalid identity does not block module load: plain PHP keeps working
     * and protected files fail closed with a clear message at compile time. */
    envelock_identity_error = envelock_load_identity(INI_STR("envelock.identity"));
    if (envelock_identity_error) {
        zend_error(E_WARNING, "Envelock: identity file rejected: %s; protected files will not run",
            envelock_identity_error);
    } else if (ENVELOCK_INI_BOOL("envelock.harden_memory")) {
        envelock_harden_enabled = 1;      /* keys are in memory now; protect and re-apply in RINIT */
        envelock_harden_memory();
    }
    /* Clock state first: the trusted-time block below records its floor into it, and the per-file
     * license check reads the watermark. */
    envelock_clock_path = INI_STR("envelock.clock_state");
    if (envelock_clock_path && *envelock_clock_path) {
        envelock_clock_load(envelock_clock_path, &envelock_clock_watermark);
    } else {
        envelock_clock_path = NULL;
    }
    /* The license (which sets envelock_licence_present) must load before the trusted-time block,
     * because that block only runs when a license is in force. (Fixed Nov 2026: this block used to
     * sit before the license load, so envelock_licence_present was still 0, the fetch never ran and
     * the startup time floor was inert — reported by an external audit and reproduced.) */
    envelock_licence_error = envelock_load_licence(INI_STR("envelock.licence"));
    if (envelock_licence_error) {
        zend_error(E_WARNING, "Envelock: license rejected: %s; protected files will not run",
            envelock_licence_error);
    }
    /* O8: ask once per worker, not per request — this is a TLS handshake and it must never sit in
     * request handling. Only worth doing when a license is in force, since it exists to bound an
     * expiry; an unlicensed deployment has nothing to bound. */
    if (envelock_licence_present) {
        const char *tt_host = INI_STR("envelock.trusted_time");
        if (tt_host && *tt_host) {
            const char *tt_to_str = INI_STR("envelock.trusted_time_timeout");  /* NULL-guarded (ENV-2026-31) */
            int tt_timeout = tt_to_str ? (int) ZEND_ATOL(tt_to_str) : 0;
            uint64_t observed = 0;
            if (tt_timeout <= 0) {
                tt_timeout = 5;
            }
            if (envelock_trusted_time_fetch(tt_host, 443, tt_timeout, &observed) == 1) {
                /* Sanity window (internal audit, Nov 2026): a trusted-time source that answers with a
                 * wildly FUTURE date (a misconfigured endpoint, or a compromise of that one host) would
                 * set a floor ABOVE the real clock, refuse every protected file, AND persist that floor
                 * to the state file -- bricking the deployment until an admin deletes it. Accept the
                 * floor only when it is not implausibly ahead of the local clock (a generous one-day
                 * skew allowance). A floor at or below the local clock is the normal, useful case: it is
                 * what catches a clock set back. */
                time_t now = time(NULL);
                const uint64_t max_skew = 24 * 60 * 60;
                /* The network time is always the in-memory floor: it is the one time the machine
                 * cannot invent. When it is far AHEAD of the local clock that is either the rollback
                 * this exists to catch or a broken source; both must refuse protected files rather
                 * than be ignored (ignoring it let any rollback over a day pass, the exact case this
                 * defends). Only the persistence differs: a time far ahead is NOT written to the
                 * state file, so a broken source refuses until it is fixed or the next restart, and
                 * cannot brick the deployment permanently. */
                envelock_trusted_floor = observed;
                if (now > 0 && observed > (uint64_t) now + max_skew) {
                    zend_error(E_WARNING, "Envelock: the trusted-time source %s reports a time far "
                        "ahead of the system clock (clock set back, or a wrong envelock.trusted_time); "
                        "protected files will be refused until they agree", tt_host);
                } else if (envelock_clock_path && observed > envelock_clock_watermark) {
                    /* A time this installation demonstrably reached belongs in the record too: this is
                     * what makes deleting the state file insufficient. */
                    envelock_clock_watermark = observed;
                    envelock_clock_advance(envelock_clock_path, &envelock_clock_watermark, 0, 0);
                }
            } else {
                /* Fail-open by design (an unreachable host never refuses a site), but not SILENT: the
                 * administrator configured a control and must be able to see that it is not in force
                 * (audit 2026-11-12, H-06). Written to the error log (error_log, or the SAPI's own
                 * log: the FPM log, Apache's error log, stderr for the CLI) — never into a page. */
                char message[512];
                snprintf(message, sizeof(message),
                    "Envelock: the trusted-time source %s could not be read (unreachable, TLS or "
                    "certificate failure, no usable Date header%s); this process runs on the local "
                    "clock and the watermark only", tt_host,
#ifdef PHP_WIN32
                    ", or Windows, where the loader has no outbound TLS"
#else
                    ""
#endif
                    );
                php_log_err(message);
            }
        }
    }
    envelock_previous_compile_file = zend_compile_file;
    zend_compile_file = envelock_compile_file;
    envelock_own_compile_file = zend_compile_file;   /* O3: what "still ours" means from here on */
    envelock_previous_post_startup = zend_post_startup_cb;   /* HOST-1: see envelock_post_startup */
    zend_post_startup_cb = envelock_post_startup;
    envelock_own_interrupt_function = zend_interrupt_function;   /* O3: ditto, see above */
    envelock_previous_compile_string = zend_compile_string;   /* eval() gate for sealed packages (C9) */
    zend_compile_string = envelock_compile_string;
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(envelock)
{
    if (zend_compile_file == envelock_compile_file) zend_compile_file = envelock_previous_compile_file;
    if (zend_compile_string == envelock_compile_string) zend_compile_string = envelock_previous_compile_string;
    OPENSSL_cleanse(&envelock_identity, sizeof(envelock_identity));
    envelock_secret_shutdown();   /* O2: wipes the arena, private keys included, then unmaps it */
#if ENVELOCK_HAVE_BYTECODE
    envelock_bc_shutdown();
#endif
    envelock_crypto_shutdown();
    UNREGISTER_INI_ENTRIES();
    return SUCCESS;
}

PHP_RINIT_FUNCTION(envelock)
{
#if defined(ZTS) && defined(COMPILE_DL_ENVELOCK)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    /* Per-request records start empty even if a previous request's RSHUTDOWN was skipped
     * (their memory belonged to that request). */
    ENVELOCK_G(request_ready) = 0;
    ENVELOCK_G(sealed_active) = 0;   /* each request starts with no sealed package active (C9) */
    /* Re-assert non-dumpable: PHP-FPM does setuid() to the pool user after MINIT, which resets the
     * dumpable flag to 1. prctl(PR_SET_DUMPABLE) is process-wide and idempotent, so just call it
     * every request rather than gating on a process-wide `static int` that several ZTS threads could
     * race on (C11 data race / UB) (ENV-AUD-18). The cost is one cheap syscall per request. */
    if (envelock_harden_enabled) {
        envelock_set_undumpable();
    }
    /* The authoritative, fail-closed decision is made per file at compile time
     * (envelock_compile_file), which is the only point that distinguishes a protected
     * file from ordinary PHP. A misconfiguration only blocks protected files, never
     * plain PHP, so RINIT does not fail the whole request. */
    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(envelock)
{
    if (ENVELOCK_G(request_ready)) {
        /* The vault holds decrypted source literals: wipe them before freeing, like the source
         * buffer. RSHUTDOWN runs after all user code (shutdown functions and destructors have already
         * run), so a literal still referenced by $GLOBALS or a static property (refcount > 1) is no
         * longer read by anything — only released during the remaining teardown — and wiping its
         * bytes is safe. The earlier refcount==1 guard left exactly those copies uncleansed
         * (ENV-AUD-06); now every non-interned vault string is wiped. */
        zval *list, *item;
        ZEND_HASH_FOREACH_VAL(&ENVELOCK_G(litvault), list) {
            if (Z_TYPE_P(list) != IS_ARRAY) continue;
            ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(list), item) {
                if (Z_TYPE_P(item) == IS_STRING && !ZSTR_IS_INTERNED(Z_STR_P(item))) {
                    OPENSSL_cleanse(ZSTR_VAL(Z_STR_P(item)), ZSTR_LEN(Z_STR_P(item)));
                }
            } ZEND_HASH_FOREACH_END();
        } ZEND_HASH_FOREACH_END();
        zend_hash_destroy(&ENVELOCK_G(loaded));
        zend_hash_destroy(&ENVELOCK_G(roots));
        zend_hash_destroy(&ENVELOCK_G(litvault));
        /* O7: wipes the data key, the still-encrypted table and every literal decrypted during
         * the request (envelock_enc_vault_free does all three). */
        zend_hash_destroy(&ENVELOCK_G(litvault_enc));
        ENVELOCK_G(sealed_active) = 0;
        ENVELOCK_G(request_ready) = 0;
    }
    return SUCCESS;
}

PHP_MINFO_FUNCTION(envelock)
{
    php_info_print_table_start();
    php_info_print_table_row(2, "Envelock", "1.0.0 / offline");
    php_info_print_table_row(2, "Format", "X25519+HKDF-SHA256+AES-256-GCM + Ed25519 / v2");
    php_info_print_table_row(2, "Trust store",
        (envelock_identity.recipient_count > 0 && envelock_identity.signer_count > 0)
            ? "loaded" : "not configured");
    php_info_print_table_row(2, "OPcache (SHM)",
        ENVELOCK_INI_BOOL("envelock.allow_opcache")
            ? "allowed; protected tree MUST be in opcache.blacklist_filename"
            : "refused for protected files (set envelock.allow_opcache=1 to opt in)");
    php_info_print_table_row(2, "OPcache file_cache/preload", "always refused (persist decrypted opcodes)");
    php_info_print_table_end();
    DISPLAY_INI_ENTRIES();
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo___envelock_lit, 0, 1, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, idx, IS_LONG, 0)
ZEND_END_ARG_INFO()

/* Internal function the vault pass emits as \__envelock_lit(idx): returns the idx-th string of the
 * CURRENTLY EXECUTING file's vault table. Reserved name; only vaulted protected files call it.
 * Any miss (no vault for this file, out of range) returns "" rather than failing, so a stray call
 * can never fatal a request. */
static PHP_FUNCTION(__envelock_lit)
{
    zend_long idx;
    zend_string *fn;
    zval *entry, *str;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(idx)
    ZEND_PARSE_PARAMETERS_END();

    /* The index is a zend_long and the vault is addressed with uint32_t: a value past UINT32_MAX
     * used to wrap (2^32 + 3 answered literal 3) instead of being out of range (audit 2026-11-12,
     * H-05). Vault indexes never come near that, so anything above it is refused outright. */
    if (!ENVELOCK_G(request_ready) || idx < 0 || (zend_ulong) idx > (zend_ulong) UINT32_MAX) {
        RETURN_EMPTY_STRING();
    }
    /* Resolve the vault of the file that DIRECTLY made this call, by inspecting the immediate caller
     * frame rather than zend_get_executed_filename_ex(), which walks PAST internal C frames to the
     * nearest user file. That frame-skipping let `array_map('__envelock_lit', range(0, N))` (or
     * preg_replace_callback / ob_start, all internal functions) be attributed to the enclosing file
     * and pull its entire vault in one call, defeating the "one literal, briefly" property of O7. Only
     * a DIRECT call from user code resolves a literal now (ENV-2026-05). */
    {
        zend_execute_data *caller = execute_data->prev_execute_data;
        if (!caller || !caller->func || !ZEND_USER_CODE(caller->func->common.type)) {
            RETURN_EMPTY_STRING();
        }
        fn = caller->func->op_array.filename;
    }
    if (!fn) RETURN_EMPTY_STRING();
    /* O7: an encrypted vault answers by decrypting just this entry, and caches it for the rest
     * of the request. Checked first because FLAG_VAULT_ENC packages set both flags but only ever
     * register here. */
    {
        envelock_enc_vault *enc = zend_hash_find_ptr(&ENVELOCK_G(litvault_enc), fn);
        if (enc) {
            zend_string *value = envelock_enc_vault_get(enc, (uint32_t)idx);
            if (!value) RETURN_EMPTY_STRING();
            /* Return an INDEPENDENT copy, never RETURN_STR_COPY: the vault caches `value` and wipes its
             * buffer IN PLACE at request shutdown (envelock_enc_vault_free). A shared copy kept by the
             * app — in $_SESSION, an output buffer, a shutdown-function closure — would then be
             * serialised to disk as NUL bytes because envelock's RSHUTDOWN can run before the session
             * module's, cleansing a zend_string the engine still considers immutable (ENV-2026-24). */
            RETURN_STRINGL(ZSTR_VAL(value), ZSTR_LEN(value));
        }
    }
    entry = zend_hash_find(&ENVELOCK_G(litvault), fn);
    if (!entry || Z_TYPE_P(entry) != IS_ARRAY) RETURN_EMPTY_STRING();
    str = zend_hash_index_find(Z_ARRVAL_P(entry), (zend_ulong)idx);
    if (!str || Z_TYPE_P(str) != IS_STRING) RETURN_EMPTY_STRING();
    /* An independent copy here too, for the same reason as the encrypted vault above: RSHUTDOWN
     * wipes these vault strings in place, and a shared copy the app kept (session, output buffer)
     * would be read back as NUL bytes. Only the encrypted path had been fixed (ENV-2026-24); this
     * plain-vault path is reached only by older or hand-built containers (audit 2026-11-12, H-05). */
    RETURN_STRINGL(Z_STRVAL_P(str), Z_STRLEN_P(str));
}

/* O1 proof of concept (see envelock_bcpoc.c): the two ends of the bytecode round-trip. These are NOT
 * part of a server loader. envelock_bc_run() deserializes a caller-supplied image through the
 * OPcache-derived unserializer, which does not validate internal offsets at run time, so exposing it
 * to untrusted in-process PHP is a remote-code-execution surface: it is compiled and registered ONLY
 * under ENVELOCK_BCRUN (TEST ONLY). envelock_bc_emit() is the pack-side compile primitive, compiled
 * under ENVELOCK_BCEMIT (a pack-time loader) or ENVELOCK_BCRUN. Each is gated by its OWN flag, set by
 * an explicit configure option, never by an inherited environment variable (ENV-2026-02). A
 * production/server loader defines neither and exposes neither. */
#if ENVELOCK_HAVE_BYTECODE && defined(ENVELOCK_BCEMIT)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_envelock_bc_emit, 0, 1, MAY_BE_STRING | MAY_BE_FALSE)
    ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
ZEND_END_ARG_INFO()
PHP_FUNCTION(envelock_bc_emit);
#endif
#if ENVELOCK_HAVE_BYTECODE && defined(ENVELOCK_BCRUN)
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_envelock_bc_run, 0, 1, _IS_BOOL, 0)
    ZEND_ARG_TYPE_INFO(0, image, IS_STRING, 0)
ZEND_END_ARG_INFO()
PHP_FUNCTION(envelock_bc_run);
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_envelock_bc_load_check, 0, 1, _IS_BOOL, 0)
    ZEND_ARG_TYPE_INFO(0, image, IS_STRING, 0)
ZEND_END_ARG_INFO()
PHP_FUNCTION(envelock_bc_load_check);
#endif
PHP_FUNCTION(__envelock_vm);   /* O4: the mini-VM entry point (envelock_vm.c) */

/* O2: what the secret arena actually is on this kernel. "memfd_secret" means the identity private
 * keys are in pages the kernel cannot read back; "mlock+MADV_DONTDUMP" means memfd_secret was
 * unavailable and they are in the older, weaker protection; "none" means envelock.secret_memory is
 * off. A deployment turns the directive on and reads this back, because the syscall is silently
 * absent on many kernels and assuming otherwise would be a false sense of safety. */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_envelock_secret_memory, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()
PHP_FUNCTION(envelock_secret_memory)
{
    ZEND_PARSE_PARAMETERS_NONE();
    RETURN_STRING(envelock_secret_kind());
}

/* O8: this host's fingerprint as the loader computes it, hex. Not a secret — it is derived from
 * what the machine already reports — and it exists so an operator can read off the value to give
 * the vendor when asking for a machine-bound license, and so the test suite can check this agrees
 * with encoder.machine_fingerprint() on the same host. The two are computed independently in C and
 * in Python; if they ever drift, every machine-bound license fails, so the pair is tested. */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_envelock_machine_fingerprint, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()
PHP_FUNCTION(envelock_machine_fingerprint)
{
    unsigned char fp[32];
    char hex[65];
    int i;
    ZEND_PARSE_PARAMETERS_NONE();
    if (envelock_machine_fingerprint(fp) != 1) {
        RETURN_STRING("");          /* this host reports no machine identity */
    }
    for (i = 0; i < 32; i++) {
        snprintf(hex + i * 2, 3, "%02x", fp[i]);
    }
    hex[64] = '\0';
    RETURN_STRING(hex);
}

/* O8: the host name the loader would bind a domain license to, right now: the request's Host when
 * there is a request, otherwise this machine's own name. Exists so an operator can check that the
 * value they are about to put in --domain is the one the server will actually present, which for a
 * web app is not obvious (it is the client's Host header, not the host name of the box). */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_envelock_host_domain, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()
PHP_FUNCTION(envelock_host_domain)
{
    char buf[ENVELOCK_HOST_MAX];
    size_t len;
    ZEND_PARSE_PARAMETERS_NONE();
    len = envelock_host_domain(buf, sizeof(buf));
    RETURN_STRINGL(buf, len);
}

/* O8: the trusted-time fetch (envelock_trusted_time_fetch) is used INTERNALLY by the network floor
 * only (see MINIT: once per process start, never per request). It is deliberately NOT exposed as a userland PHP function any more: as a
 * global function it was an unrestricted DNS + TCP + TLS primitive that any script could use to reach
 * any host, bypassing disable_functions, allow_url_fopen=0 and open_basedir (ENV-2026-08). An operator
 * checks reachability with ordinary tools (curl/openssl) instead. */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo___envelock_vm, 0, 1, IS_MIXED, 0)
    ZEND_ARG_TYPE_INFO(0, program, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, args, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

static const zend_function_entry envelock_functions[] = {
    PHP_FE(__envelock_lit, arginfo___envelock_lit)
    PHP_FE(envelock_machine_fingerprint, arginfo_envelock_machine_fingerprint)
    PHP_FE(envelock_host_domain, arginfo_envelock_host_domain)
    PHP_FE(__envelock_vm, arginfo___envelock_vm)
    /* v2 is a capability marker as well as an alias: v2 packs never run on legacy loaders. */
    PHP_FALIAS(__envelock_vm_v2, __envelock_vm, arginfo___envelock_vm)
    /* envelock_trusted_time is intentionally NOT registered: it was a userland DNS/TCP/TLS primitive
     * that bypassed php.ini network policy (ENV-2026-08). The floor uses the fetch internally. */
#if ENVELOCK_HAVE_BYTECODE && defined(ENVELOCK_BCEMIT)
    /* Pack side only — see the comment at its arginfo. Never registered in a server loader. */
    PHP_FE(envelock_bc_emit, arginfo_envelock_bc_emit)
#endif
#if ENVELOCK_HAVE_BYTECODE && defined(ENVELOCK_BCRUN)
    /* TEST ONLY — executes a caller-supplied image. Never registered in any distributed loader. */
    PHP_FE(envelock_bc_run, arginfo_envelock_bc_run)
    /* TEST ONLY — deserializes without executing, to exercise the crash-safety guard. */
    PHP_FE(envelock_bc_load_check, arginfo_envelock_bc_load_check)
#endif
    PHP_FE(envelock_secret_memory, arginfo_envelock_secret_memory)
    PHP_FE_END
};

zend_module_entry envelock_module_entry = {
    STANDARD_MODULE_HEADER,
    "envelock",
    envelock_functions,
    PHP_MINIT(envelock),
    PHP_MSHUTDOWN(envelock),
    PHP_RINIT(envelock),
    PHP_RSHUTDOWN(envelock),
    PHP_MINFO(envelock),
    "1.0.0",
    PHP_MODULE_GLOBALS(envelock),
    PHP_GINIT(envelock),
    PHP_GSHUTDOWN(envelock),
    NULL,
    STANDARD_MODULE_PROPERTIES_EX
};

#ifdef COMPILE_DL_ENVELOCK
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(envelock)
#endif

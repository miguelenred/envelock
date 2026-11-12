#include "envelock_crypto.h"
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000L
# error "Envelock requires OpenSSL 3.x"
#endif

/* Domain string bound into every wrapped key (HKDF info and GCM AAD). The trailing
 * NUL is deliberate and part of the 16-byte domain. Must match the encoder. */
static const unsigned char KEM_DOMAIN[16] = "Envelock/kem/v2\0";
#define KEM_INFO_SIZE (16U + 1U + 16U + 16U + 32U + 32U) /* domain|ver|project|release|eph|recip */

/* Algorithms fetched once by envelock_crypto_init() (MINIT, before any thread runs) and then
 * only read: fetched OpenSSL algorithm objects may be shared between threads. Without init
 * (tests, fuzzers) every call falls back to the implicit/per-call fetch, as before. */
static EVP_CIPHER *envelock_aes_gcm = NULL;
static EVP_KDF *envelock_hkdf = NULL;
static EVP_MD *envelock_sha256_md = NULL;

int envelock_crypto_init(void)
{
    if (!envelock_aes_gcm) envelock_aes_gcm = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    if (!envelock_hkdf) envelock_hkdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!envelock_sha256_md) envelock_sha256_md = EVP_MD_fetch(NULL, "SHA256", NULL);
    return envelock_aes_gcm && envelock_hkdf && envelock_sha256_md;
}

void envelock_crypto_shutdown(void)
{
    EVP_CIPHER_free(envelock_aes_gcm);
    EVP_KDF_free(envelock_hkdf);
    EVP_MD_free(envelock_sha256_md);
    envelock_aes_gcm = NULL;
    envelock_hkdf = NULL;
    envelock_sha256_md = NULL;
}

static int decrypt_gcm(const unsigned char key[32], const unsigned char nonce[12],
    const unsigned char *aad, int aad_length, const unsigned char *ciphertext,
    int ciphertext_length, const unsigned char tag[16], unsigned char *output)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0, written = 0, final_length = 0, ok = 0;
    if (!ctx) return 0;
    if (EVP_DecryptInit_ex(ctx, envelock_aes_gcm ? envelock_aes_gcm : EVP_aes_256_gcm(),
                           NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        EVP_DecryptUpdate(ctx, NULL, &n, aad, aad_length) != 1 ||
        EVP_DecryptUpdate(ctx, output, &written, ciphertext, ciphertext_length) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1 ||
        EVP_DecryptFinal_ex(ctx, output + written, &final_length) != 1) goto done;
    ok = written + final_length == ciphertext_length;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int envelock_gcm_decrypt(const unsigned char key[32], const unsigned char nonce[12],
    const unsigned char *aad, size_t aad_length,
    const unsigned char *ciphertext, size_t ciphertext_length, const unsigned char tag[16],
    unsigned char *output)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0, written = 0, final_length = 0, ok = 0;
    if (!ctx) return 0;
    if (ciphertext_length > (size_t)INT_MAX || aad_length > (size_t)INT_MAX) goto done;
    if (EVP_DecryptInit_ex(ctx, envelock_aes_gcm ? envelock_aes_gcm : EVP_aes_256_gcm(),
                           NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    /* The AAD goes through DecryptUpdate with a NULL output buffer: that is the "this is
     * associated data" form. Passing a real buffer here would be the "encrypt this" form instead,
     * which is what an earlier draft did. Skip the call entirely when there is no AAD. */
    if (aad_length > 0 && EVP_DecryptUpdate(ctx, NULL, &n, aad, (int)aad_length) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, output, &written, ciphertext, (int)ciphertext_length) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) goto done;
    /* DecryptFinal_ex is the tag check: 1 iff it verifies. Do not also assert that
     * written + final_length equals ciphertext_length the way decrypt_gcm() does — measured on
     * this OpenSSL, how the bytes split between the two calls depends on whether an AAD was fed,
     * and a good ciphertext can report written = 0. */
    ok = EVP_DecryptFinal_ex(ctx, output + written, &final_length) == 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* shared = X25519(private, peer_public). 32 bytes. */
static int x25519_shared(const unsigned char priv[32], const unsigned char peer[32],
    unsigned char out[32])
{
    EVP_PKEY *p = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    EVP_PKEY *q = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer, 32);
    EVP_PKEY_CTX *ctx = p ? EVP_PKEY_CTX_new(p, NULL) : NULL;
    size_t n = 32;
    int ok = 0;
    if (ctx && q && EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_derive_set_peer(ctx, q) == 1 &&
        EVP_PKEY_derive(ctx, out, &n) == 1 && n == 32)
        ok = 1;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(p);
    EVP_PKEY_free(q);
    return ok;
}

/* public = X25519 base-point * private. Lets the loader verify the identity file
 * is self-consistent instead of trusting the stored public blindly. */
static int x25519_public_from_private(const unsigned char priv[32], unsigned char out[32])
{
    EVP_PKEY *p = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    size_t n = 32;
    int ok = p && EVP_PKEY_get_raw_public_key(p, out, &n) == 1 && n == 32;
    EVP_PKEY_free(p);
    return ok;
}

static int hkdf_sha256(const unsigned char *ikm, size_t ikm_length,
    const unsigned char *info, size_t info_length, unsigned char out[32])
{
    EVP_KDF *kdf = envelock_hkdf ? envelock_hkdf : EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *ctx = kdf ? EVP_KDF_CTX_new(kdf) : NULL;
    char digest[] = "SHA256";
    unsigned char empty_salt[1] = {0};
    OSSL_PARAM params[5];
    int ok = 0;
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)ikm, ikm_length);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, info_length);
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, empty_salt, 0);
    params[4] = OSSL_PARAM_construct_end();
    if (ctx && EVP_KDF_derive(ctx, out, 32, params) == 1) ok = 1;
    EVP_KDF_CTX_free(ctx);
    if (kdf != envelock_hkdf) EVP_KDF_free(kdf);
    return ok;
}

static uint32_t read_u32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int envelock_parse_header(const unsigned char *blob, size_t length, envelock_header *h)
{
    const size_t stub_length = sizeof(ENVELOCK_STUB) - 1;
    const size_t fixed = stub_length + ENVELOCK_HEADER_SIZE;
    const unsigned char *header;
    size_t table_size;
    int i;
    if (!blob || !h || length < fixed || memcmp(blob, ENVELOCK_STUB, stub_length) != 0) return 0;
    header = blob + stub_length;
    /* Anti-downgrade: only exactly this magic and version are accepted. Both live inside the
     * signed region, so flipping them breaks the signature. */
    if (memcmp(header, ENVELOCK_MAGIC, 8) != 0 || header[8] != ENVELOCK_FORMAT_VERSION) return 0;
    h->flags = header[9];
    h->path_length = ((size_t)header[10] << 8) | (size_t)header[11];
    h->project = header + 12;
    h->release = header + 28;
    h->count = ((unsigned int)header[44] << 8) | (unsigned int)header[45];
    h->nonce = header + 46;
    h->size = read_u32(header + 58);
    h->serial = 0;
    for (i = 0; i < 8; i++) h->serial = (h->serial << 8) | header[62 + i];
    if ((h->flags & ~ENVELOCK_FLAGS_KNOWN) != 0 || h->path_length < 1 ||
        h->path_length > ENVELOCK_MAX_PATH || h->count < 1 || h->count > ENVELOCK_MAX_RECIPIENTS ||
        h->size > ENVELOCK_MAX_SOURCE) return 0;
    table_size = (size_t)h->count * ENVELOCK_RECIPIENT_SIZE;
    if (length != fixed + h->path_length + table_size + (size_t)h->size + ENVELOCK_TAG_SIZE +
                  ENVELOCK_SIG_SIZE) return 0;
    h->path = blob + fixed;
    h->table = h->path + h->path_length;
    h->ciphertext = h->table + table_size;
    h->aad_size = fixed + h->path_length + table_size;
    return 1;
}

int envelock_sha256(const unsigned char *data, size_t length, unsigned char out[32])
{
    unsigned int n = 0;
    if (!data || !out) return 0;
    return EVP_Digest(data, length, out, &n,
                      envelock_sha256_md ? envelock_sha256_md : EVP_sha256(), NULL) == 1 && n == 32;
}

int envelock_verify(const unsigned char *blob, size_t length,
    const unsigned char signing_public[32])
{
    EVP_PKEY *key;
    EVP_MD_CTX *ctx;
    int ok = 0;
    if (!blob || !signing_public || length < ENVELOCK_SIG_SIZE) return 0;
    key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, signing_public, 32);
    ctx = EVP_MD_CTX_new();
    if (key && ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
        EVP_DigestVerify(ctx, blob + length - ENVELOCK_SIG_SIZE, ENVELOCK_SIG_SIZE,
                         blob, length - ENVELOCK_SIG_SIZE) == 1)
        ok = 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

/* Verifies a detached Ed25519 signature over an arbitrary byte range. envelock_verify() assumes the
 * package layout (signature appended to the blob it signs) and so cannot check the license body,
 * which the O8 license format lays out as a fixed 176-byte body followed by the signature. */
int envelock_verify_detached(const unsigned char *message, size_t message_length,
    const unsigned char signature[64], const unsigned char signing_public[32])
{
    EVP_PKEY *key;
    EVP_MD_CTX *ctx;
    int ok = 0;
    if (!message || !signature || !signing_public) return 0;
    key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, signing_public, 32);
    ctx = EVP_MD_CTX_new();
    if (key && ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
        EVP_DigestVerify(ctx, signature, ENVELOCK_SIG_SIZE, message, message_length) == 1)
        ok = 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

int envelock_check_keypair(const unsigned char x25519_private[32],
    const unsigned char x25519_public[32])
{
    unsigned char derived[32];
    int ok;
    if (!x25519_private || !x25519_public) return 0;
    ok = x25519_public_from_private(x25519_private, derived) &&
         CRYPTO_memcmp(derived, x25519_public, 32) == 0;
    OPENSSL_cleanse(derived, sizeof(derived));
    return ok;
}

/* Decrypts into out (capacity bytes, at least the declared source length). On failure out
 * may hold unauthenticated bytes: the caller must clear it and never use it. With out ==
 * NULL only the content key is unwrapped into key_out (no file decryption).
 * signing_public == NULL means the caller already verified the signature of this exact
 * buffer and checked the key pair. known_key != NULL skips the key agreement and uses that
 * content key; key_out != NULL receives the content key after a successful decryption. */
static int open_blob(const unsigned char *blob, size_t length,
    const unsigned char *x25519_private, const unsigned char *x25519_public,
    const unsigned char *signing_public, const unsigned char *known_key,
    unsigned char *key_out, unsigned char *out, size_t capacity, size_t *out_length)
{
    envelock_header h;
    const unsigned char *entry;
    unsigned char info[KEM_INFO_SIZE];
    unsigned char shared[32] = {0};
    unsigned char wrap_key[32] = {0};
    unsigned char content_key[32] = {0};
    unsigned int i, matched = ENVELOCK_MAX_RECIPIENTS + 1;
    int ok = 0;

    if (out ? !out_length : !key_out) return 0;
    if (out_length) *out_length = 0;
    if (!known_key && (!x25519_private || !x25519_public)) goto done;
    if (!envelock_parse_header(blob, length, &h) || (out && h.size > capacity)) goto done;

    /* 1) Verify the signature over everything but the trailing 64 bytes BEFORE any
     *    key agreement or decryption, and self-check the identity (unless the caller
     *    already did both once for this buffer). */
    if (signing_public && (!envelock_verify(blob, length, signing_public) ||
                           !envelock_check_keypair(x25519_private, x25519_public))) goto done;

    if (known_key) {
        memcpy(content_key, known_key, 32);
        goto decrypt_file;
    }

    /* 2) Find this recipient's entry by public key. */
    for (i = 0; i < h.count; i++) {
        if (CRYPTO_memcmp(h.table + (size_t)i * ENVELOCK_RECIPIENT_SIZE, x25519_public, 32) == 0) {
            matched = i;
            break;
        }
    }
    if (matched > ENVELOCK_MAX_RECIPIENTS) goto done;
    entry = h.table + (size_t)matched * ENVELOCK_RECIPIENT_SIZE;
    /* entry: recipient_pub 32 | ephemeral_pub 32 | wrap_nonce 12 | wrapped_key 48 */

    /* 3) KEM: shared = X25519(priv, ephemeral_pub); wrap_key = HKDF(shared, info). */
    memcpy(info, KEM_DOMAIN, 16);
    info[16] = ENVELOCK_FORMAT_VERSION;
    memcpy(info + 17, h.project, 16);
    memcpy(info + 33, h.release, 16);
    memcpy(info + 49, entry + 32, 32);                 /* ephemeral_pub */
    memcpy(info + 81, entry, 32);                      /* recipient_pub */
    if (!x25519_shared(x25519_private, entry + 32, shared)) goto done;
    if (!hkdf_sha256(shared, 32, info, sizeof(info), wrap_key)) goto done;
    if (!decrypt_gcm(wrap_key, entry + 64, info, (int)sizeof(info),
                     entry + 76, 32, entry + 76 + 32, content_key)) goto done;

    if (!out) {                                     /* key only */
        memcpy(key_out, content_key, 32);
        ok = 1;
        goto done;
    }

decrypt_file:
    /* 4) Decrypt the file. AAD binds the content to the header, its path and the table. */
    if (!decrypt_gcm(content_key, h.nonce, blob, (int)h.aad_size,
                     h.ciphertext, (int)h.size, h.ciphertext + h.size, out)) goto done;
    *out_length = h.size;
    if (key_out) memcpy(key_out, content_key, 32);
    ok = 1;
done:
    OPENSSL_cleanse(shared, sizeof(shared));
    OPENSSL_cleanse(wrap_key, sizeof(wrap_key));
    OPENSSL_cleanse(content_key, sizeof(content_key));
    return ok;
}

void envelock_clear_source(unsigned char *source, size_t source_length)
{
    if (source) OPENSSL_clear_free(source, source_length + ENVELOCK_PADDING);
}

size_t envelock_source_length(const unsigned char *blob, size_t length)
{
    const size_t stub_length = sizeof(ENVELOCK_STUB) - 1;
    if (!blob || length < stub_length + ENVELOCK_HEADER_SIZE) return 0;
    return read_u32(blob + stub_length + 58);
}

/* Allocating wrapper (tests, fuzzers, tools): same core, plaintext in an OpenSSL buffer. */
static int open_alloc(const unsigned char *blob, size_t length,
    const unsigned char *x25519_private, const unsigned char *x25519_public,
    const unsigned char *signing_public, const unsigned char *known_key,
    unsigned char *key_out, unsigned char **source, size_t *source_length)
{
    envelock_header h;
    size_t size, got = 0;
    unsigned char *buffer;
    if (!source || !source_length) return 0;
    *source = NULL;
    *source_length = 0;
    /* ENV-17: validate the whole layout (declared size vs the real blob length) BEFORE allocating,
     * so a tiny truncated input cannot make us reserve up to the maximum source size. */
    if (!envelock_parse_header(blob, length, &h)) return 0;
    size = h.size;
    if (size > ENVELOCK_MAX_SOURCE) return 0;
    buffer = OPENSSL_zalloc(size + ENVELOCK_PADDING);
    if (!buffer) return 0;
    if (!open_blob(blob, length, x25519_private, x25519_public, signing_public, known_key,
                   key_out, buffer, size, &got)) {
        OPENSSL_clear_free(buffer, size + ENVELOCK_PADDING);
        return 0;
    }
    *source = buffer;
    *source_length = got;
    return 1;
}

int envelock_decrypt(const unsigned char *blob, size_t length,
    const unsigned char x25519_private[32], const unsigned char x25519_public[32],
    const unsigned char signing_public[32], unsigned char **source, size_t *source_length)
{
    if (!signing_public) {
        if (source) *source = NULL;
        if (source_length) *source_length = 0;
        return 0;
    }
    return open_alloc(blob, length, x25519_private, x25519_public, signing_public, NULL, NULL,
                      source, source_length);
}

int envelock_decrypt_verified(const unsigned char *blob, size_t length,
    const unsigned char x25519_private[32], const unsigned char x25519_public[32],
    unsigned char key_out[32], unsigned char **source, size_t *source_length)
{
    return open_alloc(blob, length, x25519_private, x25519_public, NULL, NULL, key_out,
                      source, source_length);
}

int envelock_decrypt_with_key(const unsigned char *blob, size_t length,
    const unsigned char content_key[32], unsigned char **source, size_t *source_length)
{
    if (!content_key) {
        if (source) *source = NULL;
        if (source_length) *source_length = 0;
        return 0;
    }
    return open_alloc(blob, length, NULL, NULL, NULL, content_key, NULL, source, source_length);
}

int envelock_unwrap_key(const unsigned char *blob, size_t length,
    const unsigned char x25519_private[32], const unsigned char x25519_public[32],
    unsigned char key_out[32])
{
    return open_blob(blob, length, x25519_private, x25519_public, NULL, NULL, key_out,
                     NULL, 0, NULL);
}

int envelock_decrypt_with_key_into(const unsigned char *blob, size_t length,
    const unsigned char content_key[32], unsigned char *out, size_t capacity, size_t *out_length)
{
    if (!content_key) {
        if (out_length) *out_length = 0;
        return 0;
    }
    return open_blob(blob, length, NULL, NULL, NULL, content_key, NULL, out, capacity, out_length);
}
int envelock_package_digest(const unsigned char *blob, size_t length, unsigned char out[32])
{
    static const unsigned char domain[16] = "Envelock/pkg/v2\0";
    envelock_header h;
    unsigned char buffer[16 + 32];
    EVP_MD_CTX *ctx;
    unsigned int n = 0;
    int ok = 0;
    if (!out || !envelock_parse_header(blob, length, &h)) return 0;
    memcpy(buffer, domain, 16);
    memcpy(buffer + 16, h.project, 16);               /* project (ENV-16: explicit members) */
    memcpy(buffer + 32, h.release, 16);               /* release */
    ctx = EVP_MD_CTX_new();
    if (ctx && EVP_DigestInit_ex(ctx, envelock_sha256_md ? envelock_sha256_md : EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, buffer, sizeof(buffer)) == 1 &&
        EVP_DigestUpdate(ctx, h.table, (size_t)h.count * ENVELOCK_RECIPIENT_SIZE) == 1 &&
        EVP_DigestFinal_ex(ctx, out, &n) == 1 && n == 32)
        ok = 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

#ifndef ENVELOCK_CRYPTO_H
#define ENVELOCK_CRYPTO_H
#include <stddef.h>
#include <stdint.h>
/* Format v2: per-recipient asymmetric wrapping (X25519 + HKDF-SHA256 + AES-256-GCM),
 * Ed25519 signature. The loader holds no embedded secret: the recipient private key
 * and the trusted signer public key come from an external identity (generic binary). */
#define ENVELOCK_STUB "<?php /* Envelock */ exit(\"Envelock loader required\\n\"); __halt_compiler();\n"
#define ENVELOCK_MAGIC "ENVLK02\0"
#define ENVELOCK_FORMAT_VERSION 2U
#define ENVELOCK_MAX_SOURCE (16U * 1024U * 1024U)
/* Fixed header: magic 8 | version 1 | flags 1 | path_length 2 | project 16 | release 16 |
 *               recipient_count 2 | file_nonce 12 | source_length 4 | serial 8 = 70,
 * followed by the relative path (path_length bytes, UTF-8, '/'-separated), the recipient
 * table, the ciphertext, the GCM tag and the signature. Everything before the signature is
 * signed; stub, header, path and table are the content's AAD.
 *
 * The ciphertext is PHP source, except with FLAG_BYTECODE: then it is a bytecode image (see
 * envelock_bc.h) that the loader deserializes into a zend_op_array instead of handing source to
 * the compiler. The two payload kinds are mutually exclusive: FLAG_VAULT rewrites the literals
 * of the source into vault lookups, and a precompiled image has no source to rewrite. An older
 * loader sees the unknown bit and refuses the file, so a bytecode package fails closed on a
 * loader that cannot run it. */
#define ENVELOCK_HEADER_SIZE 70U
#define ENVELOCK_MAX_PATH 1024U
/* Package flags (unknown bits are refused). */
#define ENVELOCK_FLAG_INCLUDE_PROTECTION 1U   /* only entry point or same-project callers */
#define ENVELOCK_FLAG_NO_PREPEND 2U           /* refuse auto_prepend_file / auto_append_file */
#define ENVELOCK_FLAG_NO_FFI 4U               /* refuse while FFI / dl() can read process memory */
#define ENVELOCK_FLAG_SEALED 8U               /* sealed tree: refuse plain PHP under it and eval() */
#define ENVELOCK_FLAG_ENFORCE_MANIFEST 16U    /* verify the signed binary manifest at runtime */
#define ENVELOCK_FLAG_VAULT 32U               /* string literals moved to a C-side per-file vault */
#define ENVELOCK_FLAG_BYTECODE 64U            /* payload is a serialized zend_op_array, not source */
/* Objective O7: the FLAG_VAULT table is itself encrypted and each literal is decrypted on access.
 * Always accompanies FLAG_VAULT; an older loader sees the unknown bit and refuses the file, so a
 * package cannot silently fall back to a plaintext table. */
#define ENVELOCK_FLAG_VAULT_ENC 128U
#define ENVELOCK_FLAGS_KNOWN 255U
/* Recipient entry: recipient_pub 32 | ephemeral_pub 32 | wrap_nonce 12 | wrapped_key 48 = 124 */
#define ENVELOCK_RECIPIENT_SIZE 124U
#define ENVELOCK_MAX_RECIPIENTS 1024U
#define ENVELOCK_PADDING 32U
#define ENVELOCK_KEY_SIZE 32U
#define ENVELOCK_PUBLIC_SIZE 32U
#define ENVELOCK_SIG_SIZE 64U
#define ENVELOCK_TAG_SIZE 16U
#define ENVELOCK_NONCE_SIZE 12U
/* Parsed view of a container (pointers into blob); not authenticated by itself. */
typedef struct {
    unsigned int flags, count;
    uint32_t size;
    uint64_t serial;
    const unsigned char *project, *release, *nonce, *path, *table, *ciphertext;
    size_t path_length, aad_size;
} envelock_header;
/* Returns 1 iff blob has the exact v2 layout (magic, version, known flags, path and table
 * sizes, total length); fills h. */
int envelock_parse_header(const unsigned char *blob, size_t length, envelock_header *h);
/* Returns 1 on success, 0 on any error. Output must be freed by envelock_clear_source.
 * x25519_public is used to find this recipient's entry; it must match the key derived
 * from x25519_private (checked). signing_public is the trusted signer (not from the package). */
int envelock_decrypt(const unsigned char *blob, size_t length,
    const unsigned char x25519_private[32], const unsigned char x25519_public[32],
    const unsigned char signing_public[32], unsigned char **source, size_t *source_length);
/* Returns 1 iff the Ed25519 signature (last 64 bytes) over blob[:-64] verifies under
 * signing_public. Lets a caller pick the trusted signer once instead of re-verifying the
 * same signature for every recipient; envelock_decrypt still verifies authoritatively. */
int envelock_verify(const unsigned char *blob, size_t length,
    const unsigned char signing_public[32]);
/* Returns 1 iff x25519_public is the public key of x25519_private. */
/* Detached Ed25519 verification over an arbitrary range (objective O8 licenses). */
int envelock_verify_detached(const unsigned char *message, size_t message_length,
    const unsigned char signature[64], const unsigned char signing_public[32]);
int envelock_check_keypair(const unsigned char x25519_private[32],
    const unsigned char x25519_public[32]);
/* Like envelock_decrypt but WITHOUT signature verification or key-pair check. Only for a
 * caller that has already (a) checked the key pair with envelock_check_keypair and (b)
 * verified this exact, unmodified buffer with envelock_verify. Avoids repeating an Ed25519
 * verification and a scalar multiplication on every include. */
int envelock_decrypt_verified(const unsigned char *blob, size_t length,
    const unsigned char x25519_private[32], const unsigned char x25519_public[32],
    unsigned char key_out[32], unsigned char **source, size_t *source_length);
/* key_out (optional) receives the package content key after a successful decryption, so a
 * caller can reuse it for the other files of the same package (envelock_decrypt_with_key). */
/* Decrypts an already verified buffer with a content key obtained before from a file of the
 * same package (same project, release and recipient table: envelock_package_digest). The
 * GCM tag still authenticates this file's content, header and table. */
int envelock_decrypt_with_key(const unsigned char *blob, size_t length,
    const unsigned char content_key[32], unsigned char **source, size_t *source_length);
/* SHA-256 over a domain string, project, release and the recipient table (not the path):
 * equal for every file of one package, so it can key a cache of that package's content key. */
int envelock_package_digest(const unsigned char *blob, size_t length, unsigned char out[32]);
/* Declared source length in the header (0 if the buffer is too short); not authenticated. */
size_t envelock_source_length(const unsigned char *blob, size_t length);
/* For an already verified buffer: unwrap only the package content key (no file decryption),
 * so a caller can store it before any plaintext exists. */
int envelock_unwrap_key(const unsigned char *blob, size_t length,
    const unsigned char x25519_private[32], const unsigned char x25519_public[32],
    unsigned char key_out[32]);
/* Like envelock_decrypt_with_key, but straight into the caller's buffer (capacity >= declared
 * source length), avoiding a second copy of the plaintext. out may be the ciphertext's own
 * position inside blob (in-place decryption) but must not otherwise overlap it. On failure
 * out may hold unauthenticated bytes: clear it and never use it. */
int envelock_decrypt_with_key_into(const unsigned char *blob, size_t length,
    const unsigned char content_key[32], unsigned char *out, size_t capacity, size_t *out_length);
int envelock_sha256(const unsigned char *data, size_t length, unsigned char out[32]);
/* AES-256-GCM decrypt into a caller buffer of at least `ciphertext_length` bytes. Objective O7:
 * the literal vault decrypts one entry per access, so it needs the primitive on its own rather
 * than the whole-container path. `aad`/`aad_length` may be NULL/0. Returns 1 iff the tag
 * verifies; on failure `output` may hold unauthenticated bytes and the caller must clear it.
 *
 * The AAD is not optional decoration: GCM folds it into the tag, so a decrypt that omits an AAD
 * the encrypter used produces the right plaintext (CTR does not depend on the AAD) and still
 * fails the tag. That is exactly the failure this signature exists to prevent. */
int envelock_gcm_decrypt(const unsigned char key[32], const unsigned char nonce[12],
    const unsigned char *aad, size_t aad_length,
    const unsigned char *ciphertext, size_t ciphertext_length, const unsigned char tag[16],
    unsigned char *output);
/* Fetch the algorithms once (call before any thread starts); shutdown frees them. */
int envelock_crypto_init(void);
void envelock_crypto_shutdown(void);
void envelock_clear_source(unsigned char *source, size_t source_length);
#endif

/* libFuzzer entry point. audit_keys.h is generated with PUBLIC DEMO material (v2). */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "envelock_crypto.h"
#include "audit_keys.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    unsigned char *source = NULL;
    size_t length = 0;
    if (envelock_decrypt(data, size, envelock_x25519_private, envelock_x25519_public,
                      envelock_signing_public, &source, &length)) {
        envelock_clear_source(source, length);
    }
    /* Post-signature path: mutated inputs reach the table lookup, KEM and GCM code too. */
    source = NULL;
    length = 0;
    unsigned char key[32] = {0};
    if (envelock_decrypt_verified(data, size, envelock_x25519_private, envelock_x25519_public,
                                  key, &source, &length)) {
        envelock_clear_source(source, length);
    }
    /* Cached-package-key path, on every input (the real key if found, else a fixed one). */
    source = NULL;
    length = 0;
    if (envelock_decrypt_with_key(data, size, key, &source, &length)) {
        envelock_clear_source(source, length);
    }
    (void)envelock_package_digest(data, size, key);
    /* The loader's own path: unwrap the key, then decrypt straight into a caller buffer. */
    {
        size_t declared = envelock_source_length(data, size), got = 0;
        (void)envelock_unwrap_key(data, size, envelock_x25519_private, envelock_x25519_public, key);
        if (declared <= size) {
            unsigned char *out = malloc(declared + 1);
            if (out) {
                (void)envelock_decrypt_with_key_into(data, size, key, out, declared, &got);
                free(out);
            }
        }
        /* In place, as the loader does: the ciphertext region of a copy is the output. */
        if (size >= 80 && declared <= size - 80) {
            unsigned char *copy = malloc(size);
            if (copy) {
                memcpy(copy, data, size);
                (void)envelock_decrypt_with_key_into(copy, size, key, copy + (size - 80 - declared),
                                                     declared, &got);
                free(copy);
            }
        }
    }
    return 0;
}

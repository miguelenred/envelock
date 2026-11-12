#ifndef ENVELOCK_LICENCE_H
#define ENVELOCK_LICENCE_H

#include <stddef.h>
#include <stdint.h>

/* Objective O8: deployment licenses.
 *
 * A license is a fixed-size, Ed25519-signed binary issued by the vendor for one server. It only
 * ever CONSTRAINS: it can make the loader refuse files it would otherwise run, never the other way
 * round. It is a separate file from the identity bundle on purpose — the identity holds this
 * server's private keys and is generated on the server, while a license is a public document.
 *
 * Layout (big-endian), ENVELOCK_LICENCE_SIZE bytes:
 *    0  magic "ENVLKLIC" (8) | format u8 | fields u8
 *   10  expires u64           Unix seconds, 0 = no expiry
 *   18  machine 32            SHA-256 host fingerprint, all-zero = unbound
 *   50  domain 32             SHA-256, all-zero = unbound
 *   82  ip 32                 SHA-256, all-zero = unbound
 *  114  zero padding to 176
 *  176  Ed25519 signature over bytes 0..176
 *
 * Fixed size and no JSON because this loader has no JSON parser. The cost is that a new constraint
 * needs a new magic rather than a new field. */
#define ENVELOCK_LICENCE_MAGIC "ENVLKLIC"
#define ENVELOCK_LICENCE_FORMAT 1U
#define ENVELOCK_LICENCE_SIZE 240U
#define ENVELOCK_LICENCE_BODY 176U
#define ENVELOCK_LICENCE_FIELD_EXPIRY 0x01U
#define ENVELOCK_LICENCE_FIELD_MACHINE 0x02U
#define ENVELOCK_LICENCE_FIELD_DOMAIN 0x04U
#define ENVELOCK_LICENCE_FIELD_IP 0x08U
/* Every field bit this loader understands. A licence that sets any other bit carries a constraint a
 * newer encoder added, which THIS loader cannot enforce: it must be REFUSED, not run with the unknown
 * constraint silently ignored (fail-open) (ENV-2026-30). */
#define ENVELOCK_LICENCE_KNOWN_FIELDS \
    (ENVELOCK_LICENCE_FIELD_EXPIRY | ENVELOCK_LICENCE_FIELD_MACHINE | \
     ENVELOCK_LICENCE_FIELD_DOMAIN | ENVELOCK_LICENCE_FIELD_IP)

typedef struct _envelock_licence {
    uint8_t format;
    uint8_t fields;
    uint64_t expires;                 /* 0 = never */
    unsigned char machine[32];        /* all-zero = unbound */
    unsigned char domain[32];
    unsigned char ip[32];
} envelock_licence;

/* Parses the fixed-size body. Returns 1 on a well-formed license of the supported format. */
int envelock_licence_parse(const unsigned char *blob, size_t length, envelock_licence *out);

/* Checks the Ed25519 signature over bytes 0..176 against the trusted developer keys.
 * `signers` is signer_count x 32 raw public keys. Returns 1 if any of them signed it. */
int envelock_licence_signed_by(const unsigned char *blob,
                               const unsigned char (*signers)[32], int signer_count);

/* SHA-256 fingerprint of this host, matching encoder.machine_fingerprint() byte for byte:
 * SHA256("envelock-machine-1\n" + machine-id + "\n" + each non-loopback MAC, lowercased, sorted).
 * Returns 1 and fills out[32], or 0 when the host reports neither a machine-id nor a MAC. */
int envelock_machine_fingerprint(unsigned char out[32]);

/* The host name this server serves, lowercased and without any port: the SAPI's SERVER_NAME of the
 * current request in a web SAPI (not the client's Host header, ENV-2026-06), otherwise the
 * machine's own host name (CLI/phpdbg/embed, whose $_SERVER comes from the environment, or a worker
 * before any request). Windows reports no host at all (domain-bound licences are refused there).
 * buf must hold at least ENVELOCK_HOST_MAX. Returns the length, or 0 when nothing is available.
 *
 * Honest limit: SERVER_NAME is what the web server is configured to serve, but Apache with
 * UseCanonicalName Off derives it from the client's Host header, and the server administrator
 * controls it either way. What this raises is the cost of moving a deployment to another server and
 * having it work by accident or by copying; it is not an access control. */
#define ENVELOCK_HOST_MAX 256U
size_t envelock_host_domain(char *buf, size_t cap);

/* SHA-256 of this host's own IPv4 addresses (loopback excluded, sorted), matching
 * encoder.host_ips_hash(). Unlike the Host header these are not something a remote caller chooses.
 * Returns 1 and fills out[32], or 0 when the host has no non-loopback IPv4 address. */
int envelock_host_ips_hash(unsigned char out[32]);

/* The reason this license must be refused right now (static, human-readable), or NULL when it is
 * acceptable. Checks expiry against the current clock and the machine binding against this host;
 * the caller has already verified the signature and the format. */
/* The reason this license must be refused right now (static, human-readable), or NULL when it is
 * acceptable. The caller has already verified the signature and the format.
 *
 * `request_active` says whether there is an HTTP request to look at. It matters for the domain
 * binding and nothing else: at startup a worker has served nothing yet, so there is no Host header
 * and the only name available would be the machine's own — checking the domain there would refuse
 * every web deployment whose licensed name is not its host name. Expiry, machine and IP are
 * knowable at startup and are checked either way. */
const char *envelock_licence_refusal(const envelock_licence *licence, int request_active);

#endif /* ENVELOCK_LICENCE_H */

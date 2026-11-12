/*
  +----------------------------------------------------------------------+
  | Envelock — PHP source protection.                                    |
  | Apache License 2.0 (see LICENSE).                                    |
  +----------------------------------------------------------------------+
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_variables.h"          /* PG(http_globals): the request's $_SERVER */
#include "SAPI.h"
#include "envelock_licence.h"
#include "envelock_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
/* <unistd.h> is POSIX-only and not needed here outside the POSIX branch below (which includes it for
 * dirent/ifaddrs); including it unconditionally broke the Windows build. */

#ifdef PHP_WIN32
/* Host identity on Windows comes from the registry (MachineGuid) and GetAdaptersAddresses; neither
 * is wired up here, so envelock_machine_fingerprint() reports "no identity" and a machine-bound
 * license is refused on Windows rather than silently accepted. An unbound license works. */
#else
#include <dirent.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>      /* stat(): only count interfaces backed by a real device (ENV-2026-30) */
#include <net/if.h>
#endif

/* Fingerprint domain separator. Must match encoder.machine_fingerprint() byte for byte.
 * The label carries NO trailing newline: every part, including the machine-id that follows the
 * label, is preceded by the '\n' written before it. Getting this wrong is silent and total — the
 * two sides would compute different fingerprints and every machine-bound license would be refused,
 * so the pair is covered by a test that compares them on the same host. */
#define ENVELOCK_MACHINE_INFO "envelock-machine-1"
#define ENVELOCK_MACHINE_INFO_LEN 18U
#define ENVELOCK_MACHINE_MAX 4096U     /* machine-id + up to ~100 MACs; ample */
#define ENVELOCK_MAC_LEN 17U           /* "aa:bb:cc:dd:ee:ff" */
/* Domain and IP fingerprints carry their own labels, so a host whose name happens to equal its
 * machine-id cannot collide across the two constraints. Neither label ends in a newline: every
 * part is preceded by its separator (this is what the machine fingerprint got wrong once). */
#define ENVELOCK_DOMAIN_INFO "envelock-domain-1"
#define ENVELOCK_DOMAIN_INFO_LEN 17U
#define ENVELOCK_IP_INFO "envelock-ip-1"
#define ENVELOCK_IP_INFO_LEN 13U
/* Most MACs / IPv4 addresses a fingerprint takes. ALL entries are collected and sorted (as the
 * encoder does); a host with more than this refuses binding rather than silently using the first
 * ones in enumeration order, which is not stable. */
#define ENVELOCK_MACS_MAX 256U

int envelock_licence_parse(const unsigned char *blob, size_t length, envelock_licence *out)
{
    size_t i;
    if (!blob || !out || length != ENVELOCK_LICENCE_SIZE) {
        return 0;
    }
    if (memcmp(blob, ENVELOCK_LICENCE_MAGIC, 8) != 0) {
        return 0;
    }
    out->format = blob[8];
    out->fields = blob[9];
    if (out->format != ENVELOCK_LICENCE_FORMAT) {
        return 0;
    }
    /* Fail closed on an unknown constraint bit: a future encoder may add a field this loader cannot
     * enforce, and running the package while ignoring it would be fail-open (ENV-2026-30). */
    if ((out->fields & ~ENVELOCK_LICENCE_KNOWN_FIELDS) != 0) {
        return 0;
    }
    /* The reserved padding (bytes 114..175, before the signature) must be zero: a non-zero byte there
     * means a different layout than this loader knows, so refuse rather than verify a blob it may be
     * misreading (ENV-2026-30). */
    for (i = 114; i < ENVELOCK_LICENCE_BODY; i++) {
        if (blob[i] != 0) {
            return 0;
        }
    }
    out->expires = 0;
    for (i = 0; i < 8; i++) {
        out->expires = (out->expires << 8) | (uint64_t) blob[10 + i];
    }
    memcpy(out->machine, blob + 18, 32);
    memcpy(out->domain, blob + 50, 32);
    memcpy(out->ip, blob + 82, 32);
    /* A constraint flagged absent but non-zero (or vice versa) means the file was edited by hand
     * or by a mismatched encoder. Refuse rather than guess which of the two to believe. */
    {
        unsigned char zero[32];
        memset(zero, 0, sizeof(zero));
        if (((out->fields & ENVELOCK_LICENCE_FIELD_MACHINE) != 0)
                == (memcmp(out->machine, zero, 32) == 0)) {
            return 0;
        }
        if ((out->fields & ENVELOCK_LICENCE_FIELD_EXPIRY) != 0 && out->expires == 0) {
            return 0;
        }
        if ((out->fields & ENVELOCK_LICENCE_FIELD_EXPIRY) == 0 && out->expires != 0) {
            return 0;
        }
    }
    return 1;
}

int envelock_licence_signed_by(const unsigned char *blob,
                               const unsigned char (*signers)[32], int signer_count)
{
    int s;
    if (!blob || !signers) {
        return 0;
    }
    /* envelock_verify signs/verifies the package layout (header + body + trailing signature) and
     * takes the whole blob, so it is not usable for the license body. Verify the raw Ed25519
     * signature over bytes 0..176 directly. */
    for (s = 0; s < signer_count; s++) {
        if (envelock_verify_detached(blob, ENVELOCK_LICENCE_BODY,
                                     blob + ENVELOCK_LICENCE_BODY, signers[s]) == 1) {
            return 1;
        }
    }
    return 0;
}

#ifndef PHP_WIN32
/* Reads a small text file into buf (NUL-terminated), returning its length or -1. */
static long envelock_read_small(const char *path, char *buf, size_t cap)
{
    FILE *f;
    size_t got;
    f = fopen(path, "rb");
    if (!f) {
        return -1;
    }
    got = fread(buf, 1, cap - 1, f);
    fclose(f);
    buf[got] = '\0';
    return (long) got;
}

/* Trim ASCII whitespace in place and return the length. */
static size_t envelock_trim(char *s)
{
    size_t end;
    size_t start = 0;
    while (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
        start++;
    }
    if (start) {
        memmove(s, s + start, strlen(s + start) + 1);
    }
    end = strlen(s);
    while (end > 0 && (s[end - 1] == ' ' || s[end - 1] == '\t'
                       || s[end - 1] == '\n' || s[end - 1] == '\r')) {
        s[--end] = '\0';
    }
    return end;
}
#endif

int envelock_machine_fingerprint(unsigned char out[32])
{
#ifdef PHP_WIN32
    (void) out;
    return 0;
#else
    unsigned char buf[ENVELOCK_MACHINE_MAX];
    size_t used = 0;
    size_t i, j;
    char macs[ENVELOCK_MACS_MAX][ENVELOCK_MAC_LEN + 1];
    size_t mac_count = 0;
    DIR *dir;
    struct dirent *entry;
    char line[256];

    memcpy(buf, ENVELOCK_MACHINE_INFO, ENVELOCK_MACHINE_INFO_LEN);
    used = ENVELOCK_MACHINE_INFO_LEN;

    /* First source that answers wins, in the same order as the encoder. */
    {
        static const char *const ids[] = {"/etc/machine-id", "/var/lib/dbus/machine-id"};
        long got = -1;
        for (i = 0; i < sizeof(ids) / sizeof(ids[0]) && got <= 0; i++) {
            got = envelock_read_small(ids[i], line, sizeof(line));
            if (got > 0) {
                size_t len = envelock_trim(line);
                if (len == 0) {
                    got = -1;
                    continue;
                }
                if (used + len + 1 >= ENVELOCK_MACHINE_MAX) {
                    return 0;
                }
                buf[used++] = '\n';
                memcpy(buf + used, line, len);
                used += len;
            }
        }
    }

    dir = opendir("/sys/class/net");
    if (dir) {
        while ((entry = readdir(dir)) != NULL) {
            char path[512];
            long got;
            struct stat dev_st;
            if (entry->d_name[0] == '.' || strcmp(entry->d_name, "lo") == 0) {
                continue;
            }
            /* Only interfaces backed by a real device: a physical or virtio NIC has
             * /sys/class/net/<name>/device; veth/tun/tap/bridge/bond/tunnel interfaces do NOT. This
             * both unifies the C and Python fingerprints (which diverged on tunnels and on the 64-entry
             * cap applied before sorting) and stops a container's transient veth* interfaces from
             * changing the machine fingerprint when it restarts (ENV-2026-30). */
            snprintf(path, sizeof(path), "/sys/class/net/%s/device", entry->d_name);
            if (stat(path, &dev_st) != 0) {
                continue;
            }
            snprintf(path, sizeof(path), "/sys/class/net/%s/address", entry->d_name);
            got = envelock_read_small(path, line, sizeof(line));
            if (got <= 0) {
                continue;
            }
            if (envelock_trim(line) != ENVELOCK_MAC_LEN) {
                continue;
            }
            for (i = 0; i < ENVELOCK_MAC_LEN; i++) {
                if (line[i] >= 'A' && line[i] <= 'F') {
                    line[i] = (char) (line[i] - 'A' + 'a');   /* lowercase, as the encoder does */
                }
            }
            /* 00:00:00:00:00:00 and ff:ff:ff:ff:ff:ff carry no identity. */
            if (strcmp(line, "00:00:00:00:00:00") == 0
                    || strcmp(line, "ff:ff:ff:ff:ff:ff") == 0) {
                continue;
            }
            if (mac_count == ENVELOCK_MACS_MAX) {    /* more than we can sort: refuse, never truncate */
                closedir(dir);
                return 0;
            }
            memcpy(macs[mac_count], line, ENVELOCK_MAC_LEN);
            macs[mac_count][ENVELOCK_MAC_LEN] = '\0';
            mac_count++;
        }
        closedir(dir);
    }

    /* Sort, so interface enumeration order cannot change the fingerprint. Insertion sort: the
     * count is tiny and this keeps the file free of a qsort comparator. */
    for (i = 1; i < mac_count; i++) {
        for (j = i; j > 0 && strcmp(macs[j - 1], macs[j]) > 0; j--) {
            char tmp[ENVELOCK_MAC_LEN + 1];
            memcpy(tmp, macs[j - 1], sizeof(tmp));
            memcpy(macs[j - 1], macs[j], sizeof(tmp));
            memcpy(macs[j], tmp, sizeof(tmp));
        }
    }
    for (i = 0; i < mac_count; i++) {
        if (used + ENVELOCK_MAC_LEN + 1 >= ENVELOCK_MACHINE_MAX) {
            return 0;
        }
        buf[used++] = '\n';
        memcpy(buf + used, macs[i], ENVELOCK_MAC_LEN);
        used += ENVELOCK_MAC_LEN;
    }

    /* Only the machine-id, with no usable MAC, still identifies the host (a container with a
     * stable machine-id). With neither, there is nothing to bind to. */
    if (used == ENVELOCK_MACHINE_INFO_LEN) {
        return 0;
    }
    return envelock_sha256(buf, used, out);
#endif
}

#ifndef PHP_WIN32
/* One $_SERVER entry as a NUL-terminated lowercase copy, or 0 if absent/not a string. */
static size_t envelock_server_entry(char *buf, size_t cap, const char *name)
{
    zval *server, *value;
    size_t len;
    if (cap == 0) {
        return 0;
    }
    /* $_SERVER is a LAZY auto-global: it is not materialised until userland touches it, and a
     * protected file's compile hook usually runs before anything does. Reading http_globals
     * without asking for it first finds an empty slot and silently falls back to the machine's own
     * name, which would make every domain-bound license fail on a web server. Measured: without
     * this call the entry is not an array even in the middle of a request that has a Host header. */
    zend_is_auto_global_str(ZEND_STRL("_SERVER"));
    server = &PG(http_globals)[TRACK_VARS_SERVER];
    if (Z_TYPE_P(server) != IS_ARRAY) {
        return 0;                       /* CLI, or a worker that has no request yet */
    }
    value = zend_hash_str_find(Z_ARRVAL_P(server), name, strlen(name));
    if (!value || Z_TYPE_P(value) != IS_STRING || Z_STRLEN_P(value) <= 0) {
        return 0;
    }
    len = (size_t) Z_STRLEN_P(value);
    if (len >= cap) {
        len = cap - 1;
    }
    memcpy(buf, Z_STRVAL_P(value), len);
    buf[len] = '\0';
    return envelock_trim(buf);
}
#endif

size_t envelock_host_domain(char *buf, size_t cap)
{
    size_t len = 0;
    char *colon;
    size_t i;
    if (!buf || cap == 0) {
        return 0;
    }
    buf[0] = '\0';
#ifdef PHP_WIN32
    /* No SAPI host or machine-name lookup is wired up on Windows (consistent with the machine
     * fingerprint above, which reports "no identity"): gethostname there is a Winsock call that also
     * needs WSAStartup, so rather than guess a name we report no host. A domain-bound license is thus
     * refused on Windows; an unbound one works. Returns 0 = no served host. */
    (void) buf; (void) cap;
    return 0;
#else
    /* SERVER_NAME, NOT HTTP_HOST (ENV-2026-06): HTTP_HOST is the client's Host header, which any
     * client or reverse-proxy admin can set to the licensed domain to run the package on an
     * unauthorised server. SERVER_NAME is configured by the server (nginx server_name / Apache
     * ServerName / the CLI server), so it reflects the host the deployment actually serves. A
     * domain-bound licence is a NON-cryptographic control (see the encoder's --domain warning); this
     * just stops the trivial header-spoofing bypass.
     * Command-line SAPIs have no configured server name, and their $_SERVER is built from the
     * ENVIRONMENT, so `SERVER_NAME=licensed.example php app.php` would pass anywhere: there only the
     * machine's own host name counts. (Apache with UseCanonicalName Off also fills SERVER_NAME from
     * the client's Host header; that is documented, the server must set UseCanonicalName On.) */
    if (!sapi_module.name || (strcmp(sapi_module.name, "cli") != 0
                              && strcmp(sapi_module.name, "phpdbg") != 0
                              && strcmp(sapi_module.name, "embed") != 0)) {
        len = envelock_server_entry(buf, cap, "SERVER_NAME");
    }
    if (len == 0) {
        if (gethostname(buf, cap - 1) != 0) {
            buf[0] = '\0';
            return 0;
        }
        buf[cap - 1] = '\0';
        len = strlen(buf);
    }
#endif
    /* Strip the port. A bracketed IPv6 literal ("[...]:port" or "[...]") keeps what is inside the
     * brackets. The old code cut at the first ':', turning a bracketed IPv6 literal into "[" (the
     * address lost) (ENV-2026-06). Otherwise a "host:port" / "dotted-quad:port" form: cut at the
     * first colon. */
    if (buf[0] == '[') {
        char *close = strchr(buf, ']');
        if (close) {
            size_t inner = (size_t) (close - (buf + 1));
            memmove(buf, buf + 1, inner);
            buf[inner] = '\0';
            len = inner;
        }
    } else {
        colon = strchr(buf, ':');
        if (colon) {
            *colon = '\0';
            len = strlen(buf);
        }
    }
    for (i = 0; i < len; i++) {
        if (buf[i] >= 'A' && buf[i] <= 'Z') {
            buf[i] = (char) (buf[i] - 'A' + 'a');
        }
    }
    return len;
}

int envelock_host_ips_hash(unsigned char out[32])
{
#ifdef PHP_WIN32
    (void) out;
    return 0;
#else
    /* Sorted dotted-quad IPv4s of the non-loopback interfaces. Same recipe as the encoder, and the
     * same reason for sorting: enumeration order is not stable. */
    char ips[ENVELOCK_MACS_MAX][INET_ADDRSTRLEN];
    size_t count = 0, i, j;
    unsigned char buf[ENVELOCK_MACHINE_MAX];
    size_t used;
    struct ifaddrs *list, *ifa;

    if (getifaddrs(&list) != 0) {
        return 0;
    }
    for (ifa = list; ifa != NULL; ifa = ifa->ifa_next) {
        struct sockaddr_in *sin;
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        if (ifa->ifa_flags & IFF_LOOPBACK) {
            continue;
        }
        if (count == ENVELOCK_MACS_MAX) {            /* more than we can sort: refuse, never truncate */
            freeifaddrs(list);
            return 0;
        }
        sin = (struct sockaddr_in *) (void *) ifa->ifa_addr;
        if (!inet_ntop(AF_INET, &sin->sin_addr, ips[count], INET_ADDRSTRLEN)) {
            continue;
        }
        count++;
    }
    freeifaddrs(list);
    if (count == 0) {
        return 0;
    }
    for (i = 1; i < count; i++) {
        for (j = i; j > 0 && strcmp(ips[j - 1], ips[j]) > 0; j--) {
            char tmp[INET_ADDRSTRLEN];
            memcpy(tmp, ips[j - 1], INET_ADDRSTRLEN);
            memcpy(ips[j - 1], ips[j], INET_ADDRSTRLEN);
            memcpy(ips[j], tmp, INET_ADDRSTRLEN);
        }
    }
    memcpy(buf, ENVELOCK_IP_INFO, ENVELOCK_IP_INFO_LEN);
    used = ENVELOCK_IP_INFO_LEN;
    for (i = 0; i < count; i++) {
        size_t len = strlen(ips[i]);
        if (used + len + 1 >= ENVELOCK_MACHINE_MAX) {
            return 0;
        }
        buf[used++] = '\n';
        memcpy(buf + used, ips[i], len);
        used += len;
    }
    return envelock_sha256(buf, used, out);
#endif
}

/* SHA-256("envelock-domain-1" + "\n" + name). Matches encoder.domain_hash(). */
static int envelock_domain_hash(const char *name, size_t len, unsigned char out[32])
{
    unsigned char buf[ENVELOCK_HOST_MAX + 32];
    if (!name || len == 0 || len > ENVELOCK_HOST_MAX) {
        return 0;
    }
    memcpy(buf, ENVELOCK_DOMAIN_INFO, ENVELOCK_DOMAIN_INFO_LEN);
    buf[ENVELOCK_DOMAIN_INFO_LEN] = '\n';
    memcpy(buf + ENVELOCK_DOMAIN_INFO_LEN + 1, name, len);
    return envelock_sha256(buf, ENVELOCK_DOMAIN_INFO_LEN + 1 + len, out);
}

const char *envelock_licence_refusal(const envelock_licence *licence, int request_active)
{
    if (!licence) {
        return "no license loaded";
    }
    if (licence->fields & ENVELOCK_LICENCE_FIELD_EXPIRY) {
        time_t now = time(NULL);
        /* The clock is not trustworthy (that is objective O8's anti-rollback item, still open), so
         * this compares against the local clock and says so in the message rather than pretending
         * to a guarantee it cannot give. */
        /* A clock at or before the epoch (0, or -1 on error) is no evidence of time at all: an
         * LD_PRELOAD shim freezing time() at 0 must not pass every expiry. */
        if (now <= 0) {
            return "the system clock reports no valid time, and the license has an expiry date";
        }
        if ((uint64_t) now >= licence->expires) {
            return "the license has expired";
        }
    }
    /* Only with a request in flight: before the first one there is no Host to compare, and the
     * fallback name would be the machine's own, which is a different thing than the site's. */
    if (request_active && (licence->fields & ENVELOCK_LICENCE_FIELD_DOMAIN)) {
        char here[ENVELOCK_HOST_MAX];
        unsigned char digest[32];
        size_t len = envelock_host_domain(here, sizeof(here));
        if (len == 0) {
            return "this server reports no host name, and the license is bound to a domain";
        }
        if (envelock_domain_hash(here, len, digest) != 1
                || memcmp(digest, licence->domain, 32) != 0) {
            return "the license is bound to a different domain";
        }
    }
    if (licence->fields & ENVELOCK_LICENCE_FIELD_IP) {
        unsigned char here[32];
        if (envelock_host_ips_hash(here) != 1) {
            return "this server reports no IP address, and the license is bound to one";
        }
        if (memcmp(here, licence->ip, 32) != 0) {
            return "the license is bound to a different IP address";
        }
    }
    if (licence->fields & ENVELOCK_LICENCE_FIELD_MACHINE) {
        unsigned char here[32];
        if (envelock_machine_fingerprint(here) != 1) {
            return "this host reports no machine identity, and the license is bound to one";
        }
        if (memcmp(here, licence->machine, 32) != 0) {
            return "the license is bound to a different machine";
        }
    }
    return NULL;
}

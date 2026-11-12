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
#include "envelock_trusted_time.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#ifdef PHP_WIN32
/* Outbound TLS from the loader is not wired up on Windows. envelock_trusted_time_fetch() reports
 * failure there, and the deployment falls back to the local clock and the watermark, exactly as it
 * does when the host cannot be reached. */
int envelock_trusted_time_fetch(const char *host, int port, int timeout_seconds, uint64_t *out)
{
    (void) host; (void) port; (void) timeout_seconds; (void) out;
    return 0;
}
#else
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define ENVELOCK_TT_RESPONSE 2048U
#define ENVELOCK_TT_REQUEST "HEAD / HTTP/1.0\r\nConnection: close\r\nUser-Agent: envelock\r\n\r\n"

/* "Sun, 06 Nov 1994 08:49:37 GMT" — the only form a server must send (RFC 9110 §5.6.7); the two
 * obsolete ones are not accepted, because accepting more formats means parsing more by hand. */
/* Two ASCII digits at p as a number, or -1. Not isdigit(): that is locale-dependent. */
static int envelock_tt_digits2(const char *p)
{
    if (p[0] < '0' || p[0] > '9' || p[1] < '0' || p[1] > '9') {
        return -1;
    }
    return (p[0] - '0') * 10 + (p[1] - '0');
}

int envelock_http_date_parse(const char *text, uint64_t *out)
{
    static const char *const months[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    static const char *const weekdays[7] = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"};
    static const int month_days[12] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    struct tm when;
    time_t value;
    int day, year, hour, min, sec, century, mon = -1, weekday = -1, i;
    size_t len;
    if (!text || !out) {
        return 0;
    }
    /* Parse the fixed RFC 9110 form "Wdy, DD Mon YYYY HH:MM:SS GMT" BY POSITION, not with strptime:
     * its %a/%b conversions read the weekday and month names through LC_TIME, so on a worker whose
     * locale is not English, strptime fails to parse the (always-English) HTTP date and the time floor
     * silently disables itself — fail-open (ENV-2026-32). This reads the English tables directly.
     *
     * Exactly 29 characters, every one checked. The earlier sscanf("%2d") accepted a sign ("-5" passed
     * `hour > 23`), skipped the weekday and ignored anything after the seconds, and timegm() then
     * normalised an impossible date (31 Feb) into a plausible one (audit 2026-11-12, H-06). Trailing
     * blanks are the only slack: envelock_http_header trims the leading ones. */
    len = strlen(text);
    while (len > 0 && (text[len - 1] == ' ' || text[len - 1] == '\t')) {
        len--;
    }
    if (len != 29 || text[3] != ',' || text[4] != ' ' || text[7] != ' ' || text[11] != ' '
            || text[16] != ' ' || text[19] != ':' || text[22] != ':'
            || memcmp(text + 25, " GMT", 4) != 0) {
        return 0;
    }
    for (i = 0; i < 7; i++) {
        if (memcmp(text, weekdays[i], 3) == 0) { weekday = i; break; }
    }
    for (i = 0; i < 12; i++) {
        if (memcmp(text + 8, months[i], 3) == 0) { mon = i; break; }
    }
    day = envelock_tt_digits2(text + 5);
    century = envelock_tt_digits2(text + 12);
    year = envelock_tt_digits2(text + 14);
    hour = envelock_tt_digits2(text + 17);
    min = envelock_tt_digits2(text + 20);
    sec = envelock_tt_digits2(text + 23);
    if (weekday < 0 || mon < 0 || day < 0 || century < 0 || year < 0 || hour < 0 || min < 0
            || sec < 0) {
        return 0;
    }
    year += century * 100;
    if (day < 1 || day > month_days[mon] || year < 1970 || hour > 23 || min > 59 || sec > 60) {
        return 0;
    }
    if (mon == 1 && day == 29 && !((year % 4 == 0 && year % 100 != 0) || year % 400 == 0)) {
        return 0;                                   /* 29 Feb outside a leap year */
    }
    memset(&when, 0, sizeof(when));
    when.tm_mday = day;
    when.tm_mon = mon;
    when.tm_year = year - 1900;
    when.tm_hour = hour;
    when.tm_min = min;
    when.tm_sec = sec;
    value = timegm(&when);
    if (value <= 0) {
        return 0;
    }
    /* Reject a date that cannot be a real "now": before the epoch, or beyond 2100. A server that
     * answers with its own default of 1970 would otherwise set a floor that is useless, and a
     * corrupt answer would set one that refuses everything. */
    if ((uint64_t) value > (uint64_t) 4102444800LL) {
        return 0;
    }
    *out = (uint64_t) value;
    return 1;
}

/* Finds a header value in a response, case-insensitively on the name. Returns a NUL-terminated copy
 * in out, or 0 if absent. Deliberately small: it only has to find Date. */
static int envelock_http_header(const char *response, const char *name, char *out, size_t cap)
{
    size_t name_len = strlen(name);
    const char *cursor = response;
    while (*cursor) {
        const char *eol = strstr(cursor, "\r\n");
        size_t line_len = eol ? (size_t) (eol - cursor) : strlen(cursor);
        if (line_len > name_len + 1 && strncasecmp(cursor, name, name_len) == 0
                && cursor[name_len] == ':') {
            const char *value = cursor + name_len + 1;
            size_t value_len = line_len - name_len - 1;
            while (value_len > 0 && (*value == ' ' || *value == '\t')) {
                value++;
                value_len--;
            }
            if (value_len == 0 || value_len >= cap) {
                return 0;
            }
            memcpy(out, value, value_len);
            out[value_len] = '\0';
            return 1;
        }
        if (!eol) {
            break;
        }
        cursor = eol + 2;
    }
    return 0;
}

/* Connects with a bounded wait. A blocking connect() has no usable timeout of its own, and this
 * runs while a worker is starting. */
static int envelock_connect_bounded(const char *host, int port, int timeout_seconds)
{
    struct addrinfo hints, *list = NULL, *ai;
    char service[16];
    int fd = -1;
    int flags;
    int connected = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(service, sizeof(service), "%d", port);
    /* timeout_seconds bounds the connect (poll, below) and the read, but NOT this DNS resolution:
     * POSIX getaddrinfo has no timeout of its own, and the ways to add one (a resolver thread, or
     * SIGALRM) would put process-wide threading/signal state at risk during a loader's startup for a
     * best-effort, fail-open floor. A hung resolver therefore degrades to the local clock + watermark
     * like any other trusted_time failure (audit ENV-06); run trusted_time only against a host whose
     * DNS is reliable, or pin it in /etc/hosts. */
    if (getaddrinfo(host, service, &hints, &list) != 0) {
        return -1;
    }
    for (ai = list; ai != NULL && !connected; ai = ai->ai_next) {
        struct pollfd wait;
        int error = 0;
        socklen_t error_len = sizeof(error);
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(fd);
            fd = -1;
            continue;
        }
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
            if (errno != EINPROGRESS) {
                close(fd);
                fd = -1;
                continue;
            }
            wait.fd = fd;
            wait.events = POLLOUT;
            wait.revents = 0;
            if (poll(&wait, 1, timeout_seconds * 1000) <= 0
                    || getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len) < 0 || error != 0) {
                close(fd);
                fd = -1;
                continue;
            }
        }
        /* Connected — after the bounded wait, or at once: a non-blocking connect() may also return 0
         * (loopback and local peers on some systems). BOTH go back to blocking, with a bounded wait.
         * Leaving it non-blocking makes SSL_connect return -1/WANT_READ on its first call — not an
         * error, but it reads exactly like one to a caller that checks `!= 1` once — so the fetch
         * failed and the time floor stayed off in silence. The immediate case used to `break` here
         * with the descriptor still non-blocking (audit 2026-11-12, H-06). Blocking plus SO_*TIMEO
         * keeps the same bound without a retry loop around every OpenSSL call. */
        {
            struct timeval limit;
            limit.tv_sec = timeout_seconds;
            limit.tv_usec = 0;
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit));
            if (fcntl(fd, F_SETFL, flags) < 0) {
                close(fd);
                fd = -1;
                continue;
            }
        }
        connected = 1;
    }
    freeaddrinfo(list);
    return connected ? fd : -1;
}

int envelock_trusted_time_fetch(const char *host, int port, int timeout_seconds, uint64_t *out)
{
    char request[512];
    char response[ENVELOCK_TT_RESPONSE];
    char date[128];
    const SSL_METHOD *method;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int fd = -1;
    int written, received, total = 0;
    struct pollfd wait;
    int ok = 0;

    if (!host || !*host || !out || timeout_seconds <= 0) {
        return 0;
    }
    /* Clamp the timeout: poll() takes milliseconds as int, and `timeout_seconds * 1000` overflows a
     * signed int past ~2.1M seconds, which wraps to a negative (infinite) or tiny wait (ENV-2026-32).
     * No legitimate floor needs more than a minute. */
    if (timeout_seconds > 60) {
        timeout_seconds = 60;
    }
    if (port <= 0) {
        port = 443;
    }
    fd = envelock_connect_bounded(host, port, timeout_seconds);
    if (fd < 0) {
        return 0;
    }
    method = TLS_client_method();
    ctx = method ? SSL_CTX_new(method) : NULL;
    if (!ctx) {
        close(fd);
        return 0;
    }
    /* The CA bundle is loaded, and the host name is checked. Answering with a chosen time is only
     * possible for something that is already the CA or the endpoint; skipping either check would
     * make the whole exercise decorative. */
    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        SSL_CTX_free(ctx);
        close(fd);
        return 0;
    }
    /* The default paths are those of the OpenSSL the loader was linked with. A loader that carries
     * its own OpenSSL (the portable Linux build, HOST-2) has no system directory of its own, so also
     * trust the system's CA bundle at the place each distribution family keeps it: the first one
     * that exists. SSL_CERT_FILE/SSL_CERT_DIR still take effect through the default paths. */
    {
        static const char *const bundles[] = {
            "/etc/ssl/certs/ca-certificates.crt",   /* Debian, Ubuntu, Alpine, Arch */
            "/etc/pki/tls/certs/ca-bundle.crt",     /* RHEL, AlmaLinux, Rocky, CloudLinux, Fedora, Amazon Linux */
            "/etc/ssl/ca-bundle.pem",               /* openSUSE, SLES */
            "/etc/ssl/cert.pem",                    /* macOS, FreeBSD, Alpine */
            NULL
        };
        const char *const *bundle;
        for (bundle = bundles; *bundle; bundle++) {
            if (access(*bundle, R_OK) == 0) {
                (void) SSL_CTX_load_verify_locations(ctx, *bundle, NULL);
                break;
            }
        }
        ERR_clear_error();
    }
    ssl = SSL_new(ctx);
    if (!ssl || SSL_set_fd(ssl, fd) != 1
            || SSL_set_tlsext_host_name(ssl, host) != 1
            || SSL_set1_host(ssl, host) != 1) {
        goto done;
    }
    SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
    /* Verify the chain and the host name, but NOT the validity dates against the local clock: the
     * local clock is exactly what this fetch exists to check. A clock set back past the server
     * certificate's notBefore (often < 90 days) made the handshake fail silently, so the rollback
     * went undetected. The source's identity is still proven by the chain and SSL_set1_host. */
    X509_VERIFY_PARAM_set_flags(SSL_get0_param(ssl), X509_V_FLAG_NO_CHECK_TIME);
    if (SSL_connect(ssl) != 1 || SSL_get_verify_result(ssl) != X509_V_OK) {
        goto done;
    }
    {
        /* Fail rather than send a truncated request: a host longer than the buffer would otherwise go
         * out with a silently cut Host header (ENV-2026-32). */
        int need = snprintf(request, sizeof(request), "HEAD / HTTP/1.0\r\nHost: %s\r\n"
                            "Connection: close\r\nUser-Agent: envelock\r\n\r\n", host);
        if (need < 0 || (size_t) need >= sizeof(request)) {
            goto done;
        }
    }
    written = SSL_write(ssl, request, (int) strlen(request));
    if (written <= 0) {
        goto done;
    }
    /* Bounded read: one poll, then whatever is there. The Date header is in the first packet of any
     * sane response, and waiting for more would put the worker's startup at the mercy of the peer. */
    wait.fd = fd;
    wait.events = POLLIN;
    wait.revents = 0;
    if (poll(&wait, 1, timeout_seconds * 1000) <= 0) {
        goto done;
    }
    received = SSL_read(ssl, response, (int) sizeof(response) - 1);
    if (received <= 0) {
        goto done;
    }
    response[received] = '\0';
    total = received;
    /* Validate the STATUS LINE, not "a recognised code appears somewhere in the response". The old
     * strstr(response, "200") matched a "200" in any header value or body byte, so any reachable HTTP
     * server — or an attacker-controlled one returning "200" in a header — was accepted as a time
     * source. Require "HTTP/1.0 " or "HTTP/1.1 " at the very start, then exactly three digits that are
     * a recognised status code, then a space or CR (ENV-2026-08). */
    {
        const char *sp;
        int code_ok = 0;
        if (strncmp(response, "HTTP/1.0 ", 9) != 0 && strncmp(response, "HTTP/1.1 ", 9) != 0) {
            goto done;
        }
        sp = response + 9;
        if (isdigit((unsigned char) sp[0]) && isdigit((unsigned char) sp[1]) &&
            isdigit((unsigned char) sp[2]) && (sp[3] == ' ' || sp[3] == '\r')) {
            static const char *const accepted[] = {"200", "301", "302", "403", "404"};
            size_t k;
            for (k = 0; k < sizeof(accepted) / sizeof(accepted[0]); k++) {
                if (strncmp(sp, accepted[k], 3) == 0) { code_ok = 1; break; }
            }
        }
        /* A Date header is required on all of the accepted statuses, so one without it is not
         * something this can interpret. */
        if (!code_ok) {
            goto done;
        }
    }
    if (!envelock_http_header(response, "Date", date, sizeof(date))) {
        goto done;
    }
    ok = envelock_http_date_parse(date, out);

done:
    (void) total;
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
    close(fd);
    ERR_clear_error();
    return ok;
}
#endif /* PHP_WIN32 */

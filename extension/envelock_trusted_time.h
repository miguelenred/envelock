#ifndef ENVELOCK_TRUSTED_TIME_H
#define ENVELOCK_TRUSTED_TIME_H

#include <stdint.h>

/* Objective O8: a trusted time source.
 *
 * The anti-rollback watermark defeats `date -s`, but the record is a file on the server and its
 * administrator can delete it. What closes that is a floor on the real time that the machine cannot
 * invent: ask something on the internet what time it is, over TLS, and use the answer. The Date
 * header of an HTTPS response is authenticated by the TLS session, so it cannot be forged by
 * anything that is not already the CA or the endpoint.
 *
 * This deliberately does NOT contact an Envelock server: there is no licence server in this design
 * and adding one would be a new dependency and a new way to break a deployment. Any HTTPS endpoint
 * works, which is also why the host is a directive rather than a constant.
 *
 * Honest limits, all of them real:
 *  - It needs outbound HTTPS from the web server. Many production hosts do not allow that, so it is
 *    opt-in and a failure to reach the host must never break a site (see envelock_trusted_time).
 *  - It is a floor, not a ceiling: it proves the real time is AT LEAST the answer, which is exactly
 *    what an expiry needs. It cannot prove the clock is not ahead.
 *  - An administrator who controls the machine's DNS and root CAs can answer with a chosen time.
 *    That is a much higher bar than `date -s`, not an impossible one.
 */

/* Fetches the time from `host` over TLS and stores it in *out. `port` 0 means 443.
 * `timeout_seconds` bounds the whole exchange, because this runs while a PHP worker is starting and
 * a hung connection would otherwise hang the worker.
 *
 * Returns 1 on success. Returns 0 on any failure — no route, TLS error, timeout, no Date header,
 * implausible value — and the caller must then fall back to the local clock rather than refuse:
 * the point of this is to raise the bar for expiry, not to make the site depend on the internet. */
int envelock_trusted_time_fetch(const char *host, int port, int timeout_seconds, uint64_t *out);

/* Parses an HTTP-date ("Sun, 06 Nov 1994 08:49:37 GMT") into Unix seconds. Returns 1 and fills *out
 * on success. Exposed so the parsing can be tested without a network. */
int envelock_http_date_parse(const char *text, uint64_t *out);

#endif /* ENVELOCK_TRUSTED_TIME_H */

#ifndef ENVELOCK_CLOCK_H
#define ENVELOCK_CLOCK_H

#include <stdint.h>

/* Objective O8: anti-clock-rollback.
 *
 * An expiry checked against the local clock is worth nothing on its own: `date -s` moves it back
 * and the license lives again. A watermark of the highest time this installation has ever been seen
 * running at closes the easy version of that — the clock can be set back, but the record of where
 * it already got to cannot, so a rollback shows up as "the clock is behind what this server has
 * already been".
 *
 * Honest limit, and it is a real one: the state is a file on the server, and whoever administers
 * the server can delete or edit it. What this defeats is setting the clock back, which is the cheap
 * and common bypass; it does not defeat a determined administrator with write access to the state,
 * and nothing stored only on the customer's machine ever will. It is not made tamper-evident with a
 * key either, because every key the loader holds is also on that server.
 *
 * Layout (big-endian), ENVELOCK_CLOCK_SIZE bytes:
 *    0  magic "ENVLKCLK" (8) | version u8 | flags u8 | reserved u16
 *   12  watermark u64         highest Unix time observed
 *   20  check 8               first 8 bytes of SHA-256("envelock-clock-1\n" + bytes 0..20)
 */
#define ENVELOCK_CLOCK_MAGIC "ENVLKCLK"
#define ENVELOCK_CLOCK_FORMAT 1U
#define ENVELOCK_CLOCK_SIZE 28U
#define ENVELOCK_CLOCK_CHECK_OFFSET 20U

/* Reads and validates the state file. Returns 1 and fills *watermark when a usable record was
 * read; returns 0 when there is none (first run, unreadable, or corrupt) and leaves *watermark
 * untouched, which the caller treats as "nothing observed yet" rather than as a failure — refusing
 * to start because a bookkeeping file is missing would be worse than the bypass it prevents. */
int envelock_clock_load(const char *path, uint64_t *watermark);

/* The reason the clock must be refused now (static, human-readable), or NULL when it is
 * acceptable. `tolerance` is how far behind the watermark the clock may legitimately be, so an NTP
 * step or a hand-corrected timezone does not stop a server. */
const char *envelock_clock_refusal(uint64_t watermark, uint64_t tolerance);

/* Records that this installation has now been seen running at the current time, and persists it
 * when that moves the watermark forward by at least `step` seconds. Writes are throttled by `step`
 * because this runs inside request handling: without it, every protected file would mean a
 * write() and an fsync-free rewrite of the state file. *watermark is updated in memory either way,
 * so a worker's view only ever moves forward. `may_create` = 0 only updates an existing file (used at
 * MINIT, where an FPM master running as root must not create a file its workers cannot write).
 * Serialised under ZTS. Returns 1 if the file was written. */
int envelock_clock_advance(const char *path, uint64_t *watermark, uint64_t step, int may_create);

#endif /* ENVELOCK_CLOCK_H */

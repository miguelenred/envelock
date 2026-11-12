/* Envelock - integrity of the process Envelock runs in (objective O3).
 *
 * Envelock protects source by decrypting it in memory and handing it to the engine. That is only
 * as good as the assumption that nothing else in the process can watch the hand-over. Three things
 * break that assumption, and all three are visible from inside the process without privileges:
 *
 *   1. A tracer attached with ptrace(2). It reads the decrypted source out of memory and can stop
 *      the process between the decryption and the compilation. PR_SET_DUMPABLE (envelock.harden_memory)
 *      blocks a same-uid ptrace, but a tracer with CAP_SYS_PTRACE — root, or a container granted
 *      it — attaches anyway, and so does anything already attached before the flag was set.
 *      TracerPid in /proc/self/status is what the kernel reports for it.
 *   2. An execution observer (zend_observer) or a replacement of zend_execute_ex, which sees every
 *      op_array as it starts running.
 *   3. A compile hook installed above Envelock's own, which receives the decrypted source as the
 *      handle Envelock just filled in.
 *
 * (1) is a kernel question and lives here, deliberately free of any PHP dependency so the parsing
 * is testable on its own. (2) and (3) are Zend state and live in envelock.c, which can name the
 * functions it hooked at MINIT.
 *
 * Every check here is advisory by nature: an attacker who controls the process controls the check.
 * The value is in the honest default — a protected package refuses to run in a process that is
 * being traced or instrumented, instead of quietly handing over its source.
 */
#ifndef ENVELOCK_INTEGRITY_H
#define ENVELOCK_INTEGRITY_H

#include <stddef.h>

/* Read the TracerPid of this process out of /proc/self/status.
 *
 * Returns the pid of the tracer (> 0 means the process is being traced, which is what a caller
 * wants to refuse), or 0 when the process is not traced. Returns -1 when the answer could not be
 * determined at all — no /proc, an unreadable status file, no TracerPid line — because "we could
 * not tell" must not be reported as "no tracer": a caller that fails open here fails the whole
 * objective. Linux only; on any other platform this returns -1, and callers treat -1 as unknown
 * rather than as an accusation.
 *
 * `status` is the file to read, so the parsing can be exercised against a captured status file
 * instead of only against the live kernel. Pass NULL for /proc/self/status.
 *
 * What this can and cannot see, measured on Linux 6.1: PTRACE_ATTACH stops the target, and a
 * stopped process cannot run the check that would notice it — by the time it runs again the tracer
 * has detached and TracerPid reads 0. So a tracer that halts its target is invisible here, and no
 * in-process check could ever see it. A tracer that leaves the target running — PTRACE_SEIZE, or
 * ATTACH followed by PTRACE_CONT to single-step or read memory — does show up, and that is the
 * tracer worth catching, because it is the one reading while the program works.
 */
int envelock_tracer_pid_from(const char *status);

/* envelock_tracer_pid_from(NULL), for callers that do not care about the distinction. */
int envelock_tracer_pid(void);

/* Find the TracerPid line in a status-file buffer already in memory.
 *
 * Returns the pid, or 0 when the buffer says the process is not traced, or -1 when the buffer
 * holds no parseable TracerPid line. Exposed because it is the part worth testing: the real file
 * has ~50 lines, the value is followed by a newline that is not always the last thing in the read,
 * and a truncated read must not be mistaken for a zero.
 */
int envelock_parse_tracer_pid(const char *buffer, size_t length);

#endif /* ENVELOCK_INTEGRITY_H */

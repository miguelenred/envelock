/* Envelock - secret memory (objective O2).
 *
 * A region for long-lived secrets that is kept out of every read path the kernel offers to a
 * reader outside the process. On Linux it is backed by memfd_secret(2): the pages are removed
 * from the kernel's direct map, so they are absent from /proc/PID/maps and /proc/PID/pagemap and
 * cannot be reached through /proc/kcore either — the kernel itself has no linear address for
 * them. That closes the window PR_SET_DUMPABLE and MADV_DONTDUMP leave open: those defeat a core
 * dump and an ordinary same-uid ptrace, but a reader with CAP_SYS_PTRACE (root, or a container
 * that was granted it) can still read a normal mapping through /proc/PID/mem.
 *
 * memfd_secret is frequently unavailable in practice — the kernel needs CONFIG_SECRETMEM *and*
 * the ability to split its direct map into small pages, and the syscall is simply not registered
 * when it cannot. Every call here therefore degrades to an anonymous mlock'd, MADV_DONTDUMP
 * mapping, which is what this extension already did, and reports that honestly through
 * envelock_secret_kind(). A deployment can tell the two apart instead of assuming.
 *
 * Deliberately absent: freeing. The arena is bumped and only torn down at MSHUTDOWN, so a block
 * can never be handed out twice and nothing is left behind for a later reader. Callers that need
 * to retire a block must size the arena for it; envelock_secret_alloc() returns NULL when it is
 * exhausted rather than reusing.
 */
#ifndef ENVELOCK_SECRET_H
#define ENVELOCK_SECRET_H

#include <stddef.h>

/* Prepare an arena of at least `size` bytes. Returns 1 when usable, 0 when the secret arena
 * could not be created at all (callers then keep secrets where they were). Idempotent. */
int envelock_secret_init(size_t size);

/* Bump-allocate `size` bytes, aligned to 64. NULL when unavailable or exhausted. */
void *envelock_secret_alloc(size_t size);

/* 1 when the arena is real memfd_secret memory, 0 when it is the mlock'd fallback. */
int envelock_secret_is_secret(void);

/* Where the arena lives, for a human-readable status line. */
const char *envelock_secret_kind(void);

/* Wipe the arena and release it. */
void envelock_secret_shutdown(void);

#endif /* ENVELOCK_SECRET_H */

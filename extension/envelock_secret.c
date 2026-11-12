/* Envelock - secret memory (objective O2). See envelock_secret.h for the reasoning. */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "envelock_secret.h"

#include <openssl/crypto.h>   /* OPENSSL_cleanse */
#include <string.h>

#if defined(__linux__)
# include <errno.h>
# include <fcntl.h>
# include <sys/mman.h>
# include <sys/syscall.h>
# include <unistd.h>
#elif defined(__APPLE__)
# include <sys/mman.h>
# include <unistd.h>
#elif defined(_WIN32)
# include <windows.h>
#endif

/* glibc only started exporting SYS_memfd_secret recently, and a distribution kernel can carry the
 * syscall without its headers doing so. Number it directly where it is missing; 447 is the fixed
 * x86-64/arm64 number and memfd_secret exists nowhere else. */
#if defined(__linux__) && !defined(SYS_memfd_secret)
# if defined(__x86_64__) || defined(__aarch64__)
#  define SYS_memfd_secret 447
# endif
#endif

/* The identity key block is 64 recipients x 32 bytes; 64 KiB leaves room for the key cache
 * without making the fallback (which is locked, and so charged against RLIMIT_MEMLOCK) large. */
#define ENVELOCK_SECRET_ARENA (64 * 1024)

static unsigned char *envelock_secret_base = NULL;
static size_t envelock_secret_size = 0;
static size_t envelock_secret_used = 0;
static int envelock_secret_real = 0;
static int envelock_secret_fd = -1;

int envelock_secret_init(size_t size)
{
    void *p = NULL;
#if defined(__linux__)
    if (size < ENVELOCK_SECRET_ARENA) size = ENVELOCK_SECRET_ARENA;
    /* Round up to whole pages: mmap() and ftruncate() both want that for a file mapping. */
    size = (size + 4095u) & ~(size_t)4095u;

# ifdef SYS_memfd_secret
    {
        int fd = (int)syscall(SYS_memfd_secret, 0);
        if (fd >= 0) {
            /* The fd is the only handle to these pages, so it must not survive an exec: a child
             * process the server spawns would otherwise inherit a readable view of the secrets. */
            (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
            if (ftruncate(fd, (off_t)size) == 0) {
                p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            }
            if (p == MAP_FAILED) {
                p = NULL;
                close(fd);
            } else {
                /* A memfd_secret mapping is never swapped and never core-dumped: it has no
                 * backing file in the usual sense, so neither mlock() nor MADV_DONTDUMP applies
                 * (and mlock() would fail on it). Nothing further to harden here. */
                envelock_secret_fd = fd;
                envelock_secret_real = 1;
            }
        }
    }
# endif
    if (p == NULL) {
        /* memfd_secret unavailable (ENOSYS when the kernel has no small-page direct map, EPERM
         * under a seccomp filter) or unusable. Fall back to what the rest of the extension does:
         * locked, and excluded from dumps. Weaker — a reader with CAP_SYS_PTRACE can still read
         * it through /proc/PID/mem — and envelock_secret_kind() says so. */
        p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) return 0;
        if (mlock(p, size) != 0) {
            /* Not fatal: unlocked is still MADV_DONTDUMP'd below, which is the part that keeps a
             * secret out of a core file on disk. Swapping is the lesser exposure. */
            (void)0;
        }
        (void)madvise(p, size, MADV_DONTDUMP);
    }
#elif defined(__APPLE__)
    if (size < ENVELOCK_SECRET_ARENA) size = ENVELOCK_SECRET_ARENA;
    p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;
    (void)mlock(p, size);
#elif defined(_WIN32)
    if (size < ENVELOCK_SECRET_ARENA) size = ENVELOCK_SECRET_ARENA;
    p = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (p == NULL) return 0;
    VirtualLock(p, size);
#else
    (void)size;
    return 0;
#endif

    envelock_secret_base = (unsigned char *)p;
    envelock_secret_size = size;
    envelock_secret_used = 0;
    return 1;
}

void *envelock_secret_alloc(size_t size)
{
    size_t at;
    if (envelock_secret_base == NULL || size == 0) return NULL;
    size = (size + 63u) & ~(size_t)63u;
    if (size > envelock_secret_size - envelock_secret_used) return NULL;   /* exhausted, no reuse */
    at = envelock_secret_used;
    envelock_secret_used += size;
    return envelock_secret_base + at;
}

int envelock_secret_is_secret(void)
{
    return envelock_secret_real;
}

const char *envelock_secret_kind(void)
{
    if (envelock_secret_base == NULL) return "none";
    return envelock_secret_real ? "memfd_secret" : "mlock+MADV_DONTDUMP";
}

void envelock_secret_shutdown(void)
{
    if (envelock_secret_base == NULL) return;
    /* Wipe before releasing ONLY a mapping that belongs to this process alone. The fallback (and
     * macOS, and Windows) is private: after a fork it is copy-on-write, so wiping it touches this
     * process's copy and nobody else's, and its pages may have been swapped before being locked.
     *
     * The memfd_secret arena is different: memfd_secret only maps MAP_SHARED, and every process
     * forked after MINIT shares those very pages — PHP-FPM's daemonize fork, every FPM worker, every
     * Apache child. MSHUTDOWN runs whenever one of them exits (the pre-daemon process, a worker that
     * reaches pm.max_requests or is scaled down), so wiping here zeroed the private keys of the
     * master and of every live worker, and every protected file failed until PHP was restarted
     * (external audit 2026-11-12, H-01). Nothing is lost by not wiping: the kernel clears secretmem
     * pages itself when it frees them, after the last mapping and descriptor are gone
     * (mm/secretmem.c), and until then no other process and not even the kernel's direct map can
     * read them. So this process only lets go of its own mapping and descriptor. */
    if (!envelock_secret_real) {
        OPENSSL_cleanse(envelock_secret_base, envelock_secret_size);
    }
#if defined(__linux__) || defined(__APPLE__)
    (void)munmap(envelock_secret_base, envelock_secret_size);
#elif defined(_WIN32)
    VirtualUnlock(envelock_secret_base, envelock_secret_size);
    VirtualFree(envelock_secret_base, 0, MEM_RELEASE);
#endif
    if (envelock_secret_fd >= 0) {
        close(envelock_secret_fd);
        envelock_secret_fd = -1;
    }
    envelock_secret_base = NULL;
    envelock_secret_size = 0;
    envelock_secret_used = 0;
    envelock_secret_real = 0;
}

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
#include "envelock_clock.h"
#include "envelock_crypto.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#ifndef PHP_WIN32
#include <unistd.h>   /* POSIX-only; Windows uses <io.h> below */
#include <sys/stat.h> /* fstat() for the hardlink (st_nlink) guard below */
#endif
#include <fcntl.h>
#include <errno.h>
#ifndef O_NOFOLLOW
# define O_NOFOLLOW 0
#endif
#ifndef O_CLOEXEC
# define O_CLOEXEC 0
#endif
#ifndef O_BINARY
# define O_BINARY 0
#endif

#ifndef O_NONBLOCK
# define O_NONBLOCK 0
#endif

#ifdef PHP_WIN32
#include <io.h>
#include <windows.h>
#include <stdlib.h>
#include "envelock_file.h"   /* envelock_path_wide: php.ini (UTF-8) and -d (ANSI) path values */
#endif

/* ZTS: the watermark and the on-disk value are process-wide and every request thread updates them,
 * so the read-modify-write in envelock_clock_advance is serialised. Statically initialised locks, so
 * there is no setup/teardown ordering to get wrong. */
#ifdef ZTS
# ifdef PHP_WIN32
static SRWLOCK envelock_clock_lock = SRWLOCK_INIT;
#  define ENVELOCK_CLOCK_LOCK()   AcquireSRWLockExclusive(&envelock_clock_lock)
#  define ENVELOCK_CLOCK_UNLOCK() ReleaseSRWLockExclusive(&envelock_clock_lock)
# else
#  include <pthread.h>
static pthread_mutex_t envelock_clock_lock = PTHREAD_MUTEX_INITIALIZER;
#  define ENVELOCK_CLOCK_LOCK()   pthread_mutex_lock(&envelock_clock_lock)
#  define ENVELOCK_CLOCK_UNLOCK() pthread_mutex_unlock(&envelock_clock_lock)
# endif
#else
# define ENVELOCK_CLOCK_LOCK()   ((void) 0)
# define ENVELOCK_CLOCK_UNLOCK() ((void) 0)
#endif

/* The state file must be one ordinary file: not a FIFO or device (opening a FIFO would block the
 * worker), not a directory, and not a second name for some other file (a hardlink, or on Windows a
 * symlink/junction, which CRT open() follows) through which the write would land elsewhere. */
static int envelock_clock_fd_ok(int fd)
{
#ifdef PHP_WIN32
    BY_HANDLE_FILE_INFORMATION info;
    HANDLE handle = (HANDLE) _get_osfhandle(fd);
    if (handle == INVALID_HANDLE_VALUE || GetFileType(handle) != FILE_TYPE_DISK
            || !GetFileInformationByHandle(handle, &info)) {
        return 0;
    }
    return info.nNumberOfLinks == 1
        && (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
#else
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 1;
#endif
}

#ifdef PHP_WIN32
/* CRT open() follows a symlink or junction at the final component; refuse one up front (the handle
 * check above then catches a hardlink, and a reparse point swapped in between shows up there too). */
static int envelock_clock_path_ok(const char *path)
{
    DWORD attributes;
    wchar_t *wide = envelock_path_wide(path);
    if (!wide) {
        return 0;
    }
    attributes = GetFileAttributesW(wide);
    free(wide);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return 1;                                   /* does not exist yet */
    }
    return (attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY
                          | FILE_ATTRIBUTE_DEVICE)) == 0;
}

/* The CRT open() reads the path in the ANSI code page, so a UTF-8 php.ini value with a non-ASCII
 * character would name another (missing) file: open through the wide API (ENV-14). */
static int envelock_clock_open(const char *path, int flags, int mode)
{
    int fd;
    wchar_t *wide = envelock_path_wide(path);
    if (!wide) {
        return -1;
    }
    fd = _wopen(wide, flags, mode);
    free(wide);
    return fd;
}
#else
# define envelock_clock_path_ok(path) 1
# define envelock_clock_open(path, flags, mode) open((path), (flags), (mode))
#endif

#define ENVELOCK_CLOCK_INFO "envelock-clock-1\n"
#define ENVELOCK_CLOCK_INFO_LEN 17U

/* The value currently ON DISK for this worker (0 = unknown / no state file loaded yet). The persist
 * throttle in envelock_clock_advance compares against this, not against the in-memory watermark:
 * otherwise a worker that advances in steps smaller than `step` never crosses its own in-memory
 * value + step, never writes, and a restart loses every bit of advance (audit ENV-01). */
static uint64_t envelock_clock_persisted = 0;

/* SHA-256("envelock-clock-1\n" + body), first 8 bytes into out. Not a MAC: it catches a truncated
 * or half-written file, not an administrator, who has the file and every key on the box. */
static void envelock_clock_check(const unsigned char *body, unsigned char out[8])
{
    unsigned char buf[ENVELOCK_CLOCK_CHECK_OFFSET + ENVELOCK_CLOCK_INFO_LEN];
    unsigned char digest[32];
    memcpy(buf, ENVELOCK_CLOCK_INFO, ENVELOCK_CLOCK_INFO_LEN);
    memcpy(buf + ENVELOCK_CLOCK_INFO_LEN, body, ENVELOCK_CLOCK_CHECK_OFFSET);
    if (envelock_sha256(buf, sizeof(buf), digest) != 1) {
        memset(out, 0, 8);
        return;
    }
    memcpy(out, digest, 8);
}

int envelock_clock_load(const char *path, uint64_t *watermark)
{
    unsigned char blob[ENVELOCK_CLOCK_SIZE];
    unsigned char want[8];
    FILE *file;
    size_t got;
    size_t i;
    uint64_t value;

    if (!path || !*path || !watermark) {
        return 0;
    }
    {
        /* O_NOFOLLOW/O_CLOEXEC: the clock-state path must not be read through a symlink an attacker
         * planted, nor leak the descriptor to a child process (ENV-2026-10). */
        int rfd;
        if (!envelock_clock_path_ok(path)) {
            return 0;
        }
        /* O_NONBLOCK: a FIFO planted at the path must not block the worker in open(); the fd check
         * then refuses anything but one ordinary file. */
        rfd = envelock_clock_open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_BINARY | O_NONBLOCK, 0);
        if (rfd < 0) {
            return 0;                               /* first run, removed, or a symlink in its place */
        }
        if (!envelock_clock_fd_ok(rfd)) {
            close(rfd);
            return 0;
        }
        file = fdopen(rfd, "rb");
        if (!file) {
            close(rfd);
            return 0;
        }
    }
    got = fread(blob, 1, sizeof(blob), file);
    fclose(file);
    if (got != sizeof(blob) || memcmp(blob, ENVELOCK_CLOCK_MAGIC, 8) != 0
            || blob[8] != ENVELOCK_CLOCK_FORMAT) {
        return 0;                                   /* truncated, foreign, or a newer format */
    }
    envelock_clock_check(blob, want);
    if (memcmp(want, blob + ENVELOCK_CLOCK_CHECK_OFFSET, 8) != 0) {
        return 0;                                   /* half-written or edited by hand */
    }
    value = 0;
    for (i = 0; i < 8; i++) {
        value = (value << 8) | (uint64_t) blob[12 + i];
    }
    /* A watermark of 0 is indistinguishable from "nothing observed", and a wildly future one is a
     * forged or corrupt record; ignoring either is safer than refusing to run on their account. */
    if (value == 0 || value > (uint64_t) 4294967296LL) {
        return 0;
    }
    *watermark = value;
    envelock_clock_persisted = value;               /* the throttle measures advance from here */
    return 1;
}

const char *envelock_clock_refusal(uint64_t watermark, uint64_t tolerance)
{
    time_t now;
    uint64_t floor_value;

    if (watermark == 0) {
        return NULL;                                /* nothing recorded yet: nothing to compare */
    }
    now = time(NULL);
    if (now <= 0) {
        /* No usable clock at all (an unsynchronised container can return 0 or -1 before NTP).
         * Refusing here would be a guess; the expiry check already refuses an impossible date. */
        return NULL;
    }
    floor_value = watermark > tolerance ? watermark - tolerance : 0;
    if ((uint64_t) now < floor_value) {
        return "the system clock is behind the last time this installation was seen running "
               "(clock set back?)";
    }
    return NULL;
}

static int envelock_clock_advance_locked(const char *path, uint64_t *watermark, uint64_t step,
                                         int may_create);

int envelock_clock_advance(const char *path, uint64_t *watermark, uint64_t step, int may_create)
{
    int result;
    if (!path || !*path || !watermark) {
        return 0;
    }
    ENVELOCK_CLOCK_LOCK();
    result = envelock_clock_advance_locked(path, watermark, step, may_create);
    ENVELOCK_CLOCK_UNLOCK();
    return result;
}

static int envelock_clock_advance_locked(const char *path, uint64_t *watermark, uint64_t step,
                                         int may_create)
{
    unsigned char blob[ENVELOCK_CLOCK_SIZE];
    uint64_t now, previous, value;
    size_t i;
    int fd;

    now = (uint64_t) time(NULL);
    if (now == 0 || now > (uint64_t) 4294967296LL) {
        return 0;                                   /* not a plausible Unix time; record nothing */
    }
    previous = *watermark;
    if (now > previous) {
        *watermark = now;                           /* in memory it always moves forward */
    }
    value = *watermark;
    /* Throttle: only persist once the record has moved by `step` SINCE THE LAST WRITE. A worker that
     * serves thousands of requests would otherwise rewrite the file on each of them for no benefit.
     * The comparison is against the on-disk value (envelock_clock_persisted), not the in-memory
     * `previous`: measuring from `previous` meant a worker advancing in sub-`step` increments never
     * crossed the threshold and never persisted, so the disk kept its load-time value and a restart
     * lost the whole advance (audit ENV-01). */
    if (envelock_clock_persisted != 0 && value < envelock_clock_persisted + step) {
        return 0;
    }
    memcpy(blob, ENVELOCK_CLOCK_MAGIC, 8);
    blob[8] = ENVELOCK_CLOCK_FORMAT;
    blob[9] = 0;
    blob[10] = 0;
    blob[11] = 0;
    for (i = 0; i < 8; i++) {
        blob[12 + i] = (unsigned char) ((value >> (56 - i * 8)) & 0xFF);
    }
    envelock_clock_check(blob, blob + ENVELOCK_CLOCK_CHECK_OFFSET);

    /* Written in place rather than via a temp file + rename: the state is bookkeeping, and a
     * rename would need a writable directory as well as a writable file, which a locked-down
     * deployment may not offer. A torn write is caught by the check on the next load and costs
     * only that one rollback detection, not a refusal to run. */
    /* 0600, not 0644: the watermark is internal bookkeeping, not something other users need to read.
     * O_NOFOLLOW so a symlink planted in its place is not written through; O_CLOEXEC so the descriptor
     * does not leak to a child (ENV-2026-10). */
    /* may_create = 0 at MINIT: under PHP-FPM that is the master, running as root, and a file it
     * created (root, 0600) could never be written by the workers, freezing the on-disk watermark.
     * The first worker that needs the record creates it, as the worker user. */
    if (!envelock_clock_path_ok(path)) {
        return 0;
    }
    fd = envelock_clock_open(path, O_WRONLY | (may_create ? O_CREAT : 0) | O_NOFOLLOW | O_CLOEXEC
                                   | O_BINARY | O_NONBLOCK, 0600);
    if (fd < 0) {
        return 0;
    }
    /* O_NOFOLLOW only refuses a SYMLINK as the final component (and does nothing on Windows); a
     * pre-planted HARDLINK to a victim file is followed and would be overwritten. Refuse to write
     * through anything but one ordinary, singly-linked file (internal audit, Nov 2026). */
    if (!envelock_clock_fd_ok(fd)) {
        close(fd);
        return 0;
    }
    {
        ssize_t written = write(fd, blob, sizeof(blob));
        close(fd);
        if (written == (ssize_t) sizeof(blob)) {
            envelock_clock_persisted = value;        /* disk now holds this; measure the next step from it */
            return 1;
        }
        return 0;
    }
}

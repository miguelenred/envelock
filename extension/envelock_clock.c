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
#include <sys/file.h> /* flock(): serialise the watermark read-modify-write ACROSS FPM processes */
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
/* A symlink or junction at the final component is refused up front, and again on the opened handle
 * (envelock_clock_fd_ok): the open below does NOT follow a reparse point, so a link swapped in after
 * this check is opened AS the link and refused there too. The CRT _wopen() used before followed it,
 * so the handle check saw the TARGET's attributes and a link planted in between went unnoticed: the
 * 28-byte write could be redirected into any file the PHP account can write (audit 2026-11-17). */
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

/* Opens through the wide API (the CRT open() reads the path in the ANSI code page, so a UTF-8 php.ini
 * value with a non-ASCII character would name another, missing, file: ENV-14), never following a
 * reparse point, and hands back a CRT descriptor. Only the flag combinations used here are mapped. */
static int envelock_clock_open(const char *path, int flags, int mode)
{
    HANDLE handle;
    DWORD access = ((flags & O_RDWR) ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_READ);
    DWORD disposition = (flags & O_CREAT) ? OPEN_ALWAYS : OPEN_EXISTING;
    int fd;
    wchar_t *wide = envelock_path_wide(path);
    (void) mode;
    if (!wide) {
        return -1;
    }
    handle = CreateFileW(wide, access, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, disposition,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    free(wide);
    if (handle == INVALID_HANDLE_VALUE) {
        errno = (GetLastError() == ERROR_ACCESS_DENIED) ? EACCES : ENOENT;
        return -1;
    }
    fd = _open_osfhandle((intptr_t) handle, (flags & O_RDWR) ? (_O_RDWR | _O_BINARY) : (_O_RDONLY | _O_BINARY));
    if (fd < 0) {
        CloseHandle(handle);
        return -1;
    }
    return fd;
}

/* Whole-record lock ACROSS PROCESSES (C-10), and positioned reads/writes at offset 0. Windows had no
 * lock at all, so a long-lived process (an IIS FastCGI php-cgi, a CLI daemon) holding a stale value
 * rewrote the record LOWER than one another process had saved: "never lowers" held on POSIX only
 * (audit 2026-11-17). */
static int envelock_clock_try_lock(int fd, int exclusive)
{
    OVERLAPPED overlapped;
    memset(&overlapped, 0, sizeof(overlapped));
    if (LockFileEx((HANDLE) _get_osfhandle(fd),
                   (exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0) | LOCKFILE_FAIL_IMMEDIATELY, 0,
                   MAXDWORD, MAXDWORD, &overlapped)) {
        return 1;
    }
    return GetLastError() == ERROR_LOCK_VIOLATION ? -1 : 0;
}
# define envelock_clock_pause() Sleep(1)
static void envelock_clock_unlock_fd(int fd)
{
    OVERLAPPED overlapped;
    memset(&overlapped, 0, sizeof(overlapped));
    (void) UnlockFileEx((HANDLE) _get_osfhandle(fd), 0, MAXDWORD, MAXDWORD, &overlapped);
}
static long envelock_clock_read_at0(int fd, unsigned char *buf, size_t n)
{
    if (_lseeki64(fd, 0, SEEK_SET) != 0) {
        return -1;
    }
    return (long) _read(fd, buf, (unsigned int) n);
}
static long envelock_clock_write_at0(int fd, const unsigned char *buf, size_t n)
{
    if (_lseeki64(fd, 0, SEEK_SET) != 0) {
        return -1;
    }
    return (long) _write(fd, buf, (unsigned int) n);
}
#else
# define envelock_clock_path_ok(path) 1
# define envelock_clock_open(path, flags, mode) open((path), (flags), (mode))
static int envelock_clock_try_lock(int fd, int exclusive)
{
    if (flock(fd, (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB) == 0) {
        return 1;
    }
    return (errno == EWOULDBLOCK || errno == EAGAIN) ? -1 : 0;
}
# define envelock_clock_pause() usleep(1000)
static void envelock_clock_unlock_fd(int fd)
{
    (void) flock(fd, LOCK_UN);
}
static long envelock_clock_read_at0(int fd, unsigned char *buf, size_t n)
{
    return (long) pread(fd, buf, n, 0);
}
static long envelock_clock_write_at0(int fd, const unsigned char *buf, size_t n)
{
    return (long) pwrite(fd, buf, n, 0);
}
#endif

/* 1 = locked; 0 = the filesystem has no locking (go on without it, best effort); -1 = another process
 * still holds it after about 20 ms. Never a blocking wait: the lock used to be taken with a plain
 * flock(LOCK_EX), under the ZTS mutex too, so any process running as the PHP user that held the
 * record's lock stalled every worker's next save, indefinitely (audit 2026-11-17). A genuine writer
 * holds it for one 28-byte write. */
static int envelock_clock_lock_fd(int fd, int exclusive)
{
    int attempt, state = -1;
    for (attempt = 0; attempt < 20 && state == -1; attempt++) {
        state = envelock_clock_try_lock(fd, exclusive);
        if (state == -1) {
            envelock_clock_pause();
        }
    }
    return state;
}

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

/* Validates a record read from disk: 1 and *value when it is one, 0 otherwise. */
static int envelock_clock_parse(const unsigned char blob[ENVELOCK_CLOCK_SIZE], uint64_t *value)
{
    unsigned char want[8];
    uint64_t v = 0;
    size_t i;
    if (memcmp(blob, ENVELOCK_CLOCK_MAGIC, 8) != 0 || blob[8] != ENVELOCK_CLOCK_FORMAT) {
        return 0;                                   /* foreign, or a newer format */
    }
    envelock_clock_check(blob, want);
    if (memcmp(want, blob + ENVELOCK_CLOCK_CHECK_OFFSET, 8) != 0) {
        return 0;                                   /* half-written or edited by hand */
    }
    for (i = 0; i < 8; i++) {
        v = (v << 8) | (uint64_t) blob[12 + i];
    }
    /* A watermark of 0 is indistinguishable from "nothing observed", and a wildly future one is a
     * forged or corrupt record; ignoring either is safer than refusing to run on their account. */
    if (v == 0 || v > (uint64_t) 4294967296LL) {
        return 0;
    }
    *value = v;
    return 1;
}

/* Reads the record at `path` under a SHARED lock (a writer holds the exclusive one only for its
 * 28-byte rewrite). 1 and *value when a valid record was read. */
static int envelock_clock_read(const char *path, uint64_t *value)
{
    unsigned char blob[ENVELOCK_CLOCK_SIZE];
    int fd, ok = 0;
    if (!envelock_clock_path_ok(path)) {
        return 0;
    }
    /* O_NOFOLLOW/O_CLOEXEC: the clock-state path must not be read through a symlink an attacker
     * planted, nor leak the descriptor to a child process (ENV-2026-10). O_NONBLOCK: a FIFO planted at
     * the path must not block the worker in open(); the fd check then refuses anything but one
     * ordinary file. */
    fd = envelock_clock_open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_BINARY | O_NONBLOCK, 0);
    if (fd < 0) {
        return 0;                                   /* first run, removed, or a symlink in its place */
    }
    if (envelock_clock_fd_ok(fd)) {
        /* Busy or not, the record is read: a half-written one fails its check and counts as
         * no record, which is what an unreadable file means here anyway. */
        int locked = envelock_clock_lock_fd(fd, 0) == 1;
        ok = envelock_clock_read_at0(fd, blob, sizeof(blob)) == (long) sizeof(blob)
             && envelock_clock_parse(blob, value);
        if (locked) {
            envelock_clock_unlock_fd(fd);
        }
    }
    close(fd);
    return ok;
}

int envelock_clock_load(const char *path, uint64_t *watermark)
{
    uint64_t value;
    if (!path || !*path || !watermark) {
        return 0;
    }
    if (!envelock_clock_read(path, &value)) {
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

/* C-10: the rollback check and the advance as ONE locked operation. The refusal used to read the
 * process-wide watermark OUTSIDE the lock that envelock_clock_advance takes, so in ZTS another thread
 * could be advancing it at the same time (a torn 64-bit read on 32-bit builds, or a check against a
 * value already being changed). Holding the lock across both the read and the advance removes that
 * window; the per-process state is also protected across processes by the file lock inside the
 * advance.
 *
 * `resync` (the first protected file of a request): first adopt the record ON DISK when it is higher
 * than this process's value. The record is loaded once, at MINIT -- in the FPM master or Apache parent
 * -- so a worker forked later held the master's start-up value and judged a clock set back against
 * it, ignoring everything other workers had saved since; only its throttled advance re-read the disk,
 * after the refusal had already passed (audit 2026-11-17). */
const char *envelock_clock_guard(const char *path, uint64_t *watermark, uint64_t tolerance,
                                 int resync)
{
    const char *refusal;
    if (!path || !*path || !watermark) {
        return NULL;
    }
    ENVELOCK_CLOCK_LOCK();
    if (resync) {
        uint64_t disk;
        if (envelock_clock_read(path, &disk)) {
            if (disk > *watermark) {
                *watermark = disk;
            }
            if (disk > envelock_clock_persisted) {
                envelock_clock_persisted = disk;
            }
        }
    }
    refusal = envelock_clock_refusal(*watermark, tolerance);   /* watermark read under the lock */
    if (refusal == NULL) {
        envelock_clock_advance_locked(path, watermark, tolerance > 0 ? tolerance : 3600, 1);
    }
    ENVELOCK_CLOCK_UNLOCK();
    return refusal;
}

/* After the record could not be opened for writing (owner/permissions), no new attempt before this
 * time: every protected file used to pay a failed open() for good. */
static uint64_t envelock_clock_retry_at = 0;
static int envelock_clock_warned = 0;

static int envelock_clock_advance_locked(const char *path, uint64_t *watermark, uint64_t step,
                                         int may_create)
{
    unsigned char blob[ENVELOCK_CLOCK_SIZE];
    unsigned char current[ENVELOCK_CLOCK_SIZE];
    uint64_t now, previous, value, disk;
    size_t i;
    int fd, locked;
    long written;

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
    if (envelock_clock_retry_at != 0 && now < envelock_clock_retry_at) {
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
    /* O_RDWR (not O_WRONLY): the record is re-read under the lock below before it is rewritten, so a
     * higher value another process already persisted is never lowered (C-10). */
    fd = envelock_clock_open(path, O_RDWR | (may_create ? O_CREAT : 0) | O_NOFOLLOW | O_CLOEXEC
                                   | O_BINARY | O_NONBLOCK, 0600);
    if (fd < 0) {
        if (errno == EACCES || errno == EPERM) {
            /* The record exists but this process may not write it -- typically created as root, 0600,
             * by a CLI or cron run before the workers -- so the saved rollback floor stops advancing.
             * That used to be silent; say it once per process in the PHP log, and stop retrying on
             * every protected file. */
            envelock_clock_retry_at = now + 60;
            if (!envelock_clock_warned) {
                char message[600];
                envelock_clock_warned = 1;
                snprintf(message, sizeof(message),
                         "Envelock: cannot write the clock state file %.400s (owner or permissions; "
                         "the PHP worker user must own it): the anti-rollback record is not being saved",
                         path);
                php_log_err(message);
            }
        }
        return 0;
    }
    envelock_clock_retry_at = 0;
    /* O_NOFOLLOW only refuses a SYMLINK as the final component (and does nothing on Windows); a
     * pre-planted HARDLINK to a victim file is followed and would be overwritten. Refuse to write
     * through anything but one ordinary, singly-linked file (internal audit, Nov 2026). */
    if (!envelock_clock_fd_ok(fd)) {
        close(fd);
        return 0;
    }
    /* C-10: serialise the read-modify-write ACROSS PROCESSES (flock on POSIX, LockFileEx on Windows,
     * which had none). Every PHP-FPM worker is a separate process, so the ZTS mutex above does not
     * reach them, and a process still holding a stale value could otherwise overwrite a LATER value
     * another one had persisted -- moving the on-disk rollback floor BACKWARDS. Under the lock,
     * re-read the current record and, if it already holds a higher value, adopt it and write nothing
     * (never lower it); otherwise write ours. The lock is advisory and released on unlock, close or
     * process death (no deadlock), and a write happens at most once per `step` (the tolerance, an
     * hour by default), so contention is negligible. Where the filesystem has no locking the same
     * read-then-write still runs, best effort, rather than record nothing. */
    locked = envelock_clock_lock_fd(fd, 1);
    if (locked == -1) {
        close(fd);                                   /* held elsewhere: save at a later file */
        return 0;
    }
    if (envelock_clock_read_at0(fd, current, sizeof(current)) == (long) sizeof(current)
            && envelock_clock_parse(current, &disk) && disk > value) {
        if (disk > *watermark) {
            *watermark = disk;                       /* adopt the higher value in memory too */
        }
        envelock_clock_persisted = disk;
        if (locked) {
            envelock_clock_unlock_fd(fd);
        }
        close(fd);
        return 1;                                    /* nothing lower was written */
    }
    written = envelock_clock_write_at0(fd, blob, sizeof(blob));
    if (locked) {
        envelock_clock_unlock_fd(fd);
    }
    close(fd);
    if (written == (long) sizeof(blob)) {
        envelock_clock_persisted = value;            /* disk now holds this; measure the next step from it */
        return 1;
    }
    return 0;
}

/* Envelock - integrity of the process Envelock runs in (objective O3). See envelock_integrity.h. */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "envelock_integrity.h"

#include <stdint.h>   /* INT32_MAX */
#include <string.h>

#if defined(__linux__)
# include <fcntl.h>
# include <unistd.h>
#endif

/* Largest /proc/self/status we will read. The file is ~1.5 kB in practice and every line we care
 * about sits near the top, but read the whole thing so a future kernel that grows it does not turn
 * a parse into a silent "not traced". */
#define ENVELOCK_STATUS_MAX 16384

int envelock_parse_tracer_pid(const char *buffer, size_t length)
{
    static const char key[] = "TracerPid:";
    const size_t key_length = sizeof(key) - 1;
    size_t i = 0;

    if (buffer == NULL) return -1;
    for (; i + key_length <= length; i++) {
        /* The key starts a line. Requiring that rules out a match inside another field's value,
         * which is the only way this string can legitimately appear elsewhere in the file. */
        if (i != 0 && buffer[i - 1] != '\n') continue;
        if (memcmp(buffer + i, key, key_length) != 0) continue;

        i += key_length;
        while (i < length && (buffer[i] == ' ' || buffer[i] == '\t')) i++;

        /* A truncated read that cut the number in half, or no number at all, is not a zero: the
         * caller asked "is this process traced?" and the honest answer is "could not tell". */
        if (i >= length || buffer[i] < '0' || buffer[i] > '9') return -1;

        unsigned long pid = 0;
        while (i < length && buffer[i] >= '0' && buffer[i] <= '9') {
            /* Saturate rather than overflow: an absurd value still means "traced", and wrapping
             * around to 0 would report the opposite of what the file says. */
            if (pid > (unsigned long)(INT32_MAX - 1) / 10UL) return INT32_MAX;
            pid = pid * 10UL + (unsigned long)(buffer[i] - '0');
            i++;
        }
        return (int)pid;
    }
    return -1;   /* No TracerPid line at all: not a status file we can answer from. */
}

int envelock_tracer_pid_from(const char *status)
{
#if defined(__linux__)
    char buffer[ENVELOCK_STATUS_MAX];
    const char *path = (status != NULL) ? status : "/proc/self/status";
    size_t used = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;

    for (;;) {
        ssize_t got = read(fd, buffer + used, sizeof(buffer) - used);
        if (got < 0) {
            close(fd);
            return -1;   /* EINTR included: retrying is not worth the state, and -1 fails closed. */
        }
        if (got == 0) break;
        used += (size_t)got;
        if (used == sizeof(buffer)) break;
    }
    close(fd);
    return envelock_parse_tracer_pid(buffer, used);
#else
    /* No /proc/self/status. Report unknown, never "not traced": the caller decides what an
     * unknown answer is worth on this platform. */
    (void)status;
    return -1;
#endif
}

int envelock_tracer_pid(void)
{
    return envelock_tracer_pid_from(NULL);
}

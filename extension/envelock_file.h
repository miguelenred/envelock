#ifndef ENVELOCK_FILE_H
#define ENVELOCK_FILE_H

#include <stdio.h>

/* Checks that an already-open identity file (it holds private keys) is protected from other
 * local users. Returns NULL if acceptable, otherwise a static, human-readable reason.
 * POSIX: regular file, no group/other permission bits, owned by the process user or by root
 * (objective O5: root ownership is what lets a PHP-FPM master read the keys at startup while the
 * pool users it forks cannot read them at all).
 * Windows (allow-list): regular file owned by, and with access entries only for, the account
 * the process runs as, SYSTEM, Administrators or OWNER RIGHTS; any other entry is refused. */
const char *envelock_identity_file_check(FILE *file);

/* Opens the identity file for reading without blocking on a FIFO or device (POSIX:
 * O_NONBLOCK, then the checks above reject anything that is not a regular file).
 * Windows: rejects UNC/device paths, because the identity holds private keys and must be a
 * local, ACL-controlled file (anti-SMB-theft). */
FILE *envelock_identity_open(const char *path);

/* Opens a non-secret, signature-verified file (e.g. the runtime manifest) for reading. Unlike
 * envelock_identity_open it accepts UNC and extended-length paths on Windows: a protected app may
 * legitimately be hosted on a share, and the manifest's integrity comes from its Ed25519 signature
 * and release binding, not from local file permissions (ENV-AUD-18). */
FILE *envelock_plain_open(const char *path);

/* 1 iff the open FILE is a regular on-disk file (not a FIFO, device or directory). Used before
 * reading a public package file (the runtime manifest) opened with envelock_identity_open. */
int envelock_file_is_regular(FILE *file);

#ifdef _WIN32
#include <wchar.h>
/* Windows: converts a path setting to UTF-16 for the wide file APIs. A php.ini value is UTF-8, a
 * php.exe -d value is in the ANSI code page: valid UTF-8 is taken as UTF-8, anything else as ANSI.
 * Returns a malloc'd string (free() it) or NULL. */
wchar_t *envelock_path_wide(const char *path);
#endif

#endif

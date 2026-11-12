#include "envelock_file.h"

#ifdef _WIN32
# include <windows.h>
# include <aclapi.h>
# include <io.h>
# include <stdlib.h>
# include <wchar.h>
# ifdef _MSC_VER
#  pragma comment(lib, "advapi32.lib")
# endif

/* Allow-list: besides the account PHP runs as, only these may hold access entries or own
 * the file. Anything else (other users, other IIS pools, broad groups) is refused. */
static int envelock_trusted_sid(PSID sid, PSID process_user)
{
    return EqualSid(sid, process_user) || IsWellKnownSid(sid, WinLocalSystemSid) ||
           IsWellKnownSid(sid, WinBuiltinAdministratorsSid) ||
           IsWellKnownSid(sid, WinCreatorOwnerRightsSid);
}

/* Copies the SID of the user the process runs as into buffer. Returns 0 on failure. */
static int envelock_process_user(BYTE *buffer, DWORD buffer_size)
{
    BYTE info[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    HANDLE token;
    DWORD length = 0;
    int ok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 0;
    ok = GetTokenInformation(token, TokenUser, info, sizeof(info), &length) &&
         CopySid(buffer_size, buffer, ((TOKEN_USER *)info)->User.Sid);
    CloseHandle(token);
    return ok;
}

const char *envelock_identity_file_check(FILE *file)
{
    static const char *const unreadable = "its permissions cannot be read";
    HANDLE handle = (HANDLE)_get_osfhandle(_fileno(file));
    BYTE process_user[SECURITY_MAX_SID_SIZE];
    PSECURITY_DESCRIPTOR descriptor = NULL;
    PSID owner = NULL;
    PACL dacl = NULL;
    ACL_SIZE_INFORMATION size;
    const char *reason = NULL;
    DWORD i;

    if (handle == INVALID_HANDLE_VALUE || GetFileType(handle) != FILE_TYPE_DISK) {
        return "must be a regular file";
    }
    if (!envelock_process_user(process_user, sizeof(process_user))) return unreadable;
    /* Read owner and DACL from the open handle (no check/open race). */
    if (GetSecurityInfo(handle, SE_FILE_OBJECT,
                        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                        &owner, NULL, &dacl, NULL, &descriptor) != ERROR_SUCCESS) {
        return unreadable;
    }
    if (owner == NULL || !envelock_trusted_sid(owner, (PSID)process_user)) {
        reason = "must be owned by the PHP service account, SYSTEM or Administrators "
                 "(icacls /setowner)";
    } else if (dacl == NULL) {
        reason = "has no access list (everyone has full access); restrict it with icacls";
    } else if (!GetAclInformation(dacl, &size, sizeof(size), AclSizeInformation)) {
        reason = unreadable;
    } else {
        for (i = 0; i < size.AceCount && reason == NULL; i++) {
            ACE_HEADER *header = NULL;
            if (!GetAce(dacl, i, (LPVOID *)&header)) {
                reason = unreadable;
            } else if (header->AceFlags & INHERIT_ONLY_ACE) {
                continue;                      /* applies to children only, not this file */
            } else if (header->AceType == ACCESS_DENIED_ACE_TYPE ||
                       header->AceType == ACCESS_DENIED_CALLBACK_ACE_TYPE ||
                       header->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE ||
                       header->AceType == ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE) {
                continue;                      /* deny entries never grant access */
            } else if (header->AceType == ACCESS_ALLOWED_ACE_TYPE ||
                       header->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE) {
                /* Both types start with header, mask and SID. */
                ACCESS_ALLOWED_ACE *ace = (ACCESS_ALLOWED_ACE *)header;
                if (!envelock_trusted_sid((PSID)&ace->SidStart, (PSID)process_user)) {
                    reason = "accessible by other accounts or groups; restrict it with icacls "
                             "to the PHP service account, SYSTEM and Administrators";
                }
            } else {
                reason = "has an access entry of an unsupported type";  /* fail closed */
            }
        }
    }
    LocalFree(descriptor);
    return reason;
}

wchar_t *envelock_path_wide(const char *path)
{
    /* The bytes of a path setting are UTF-8 when they come from php.ini (PHP reads the file as bytes
     * and runs with the UTF-8 code page), but php.exe's -d options arrive in the ANSI code page (its
     * main() takes ANSI argv): measured on Windows 11 with PHP 8.4, "-d envelock.identity=...\idéñ.bin"
     * reaches the module as e9 f1, the same setting in a UTF-8 php.ini as c3 a9 c3 b1. Valid UTF-8 is
     * read as UTF-8; anything else can only be the ANSI form. (fopen()/open() would read every value
     * in the ANSI code page and so fail on a UTF-8 php.ini path: ENV-14.) Free the result with free(). */
    UINT codepage = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
    wchar_t *wide;
    int n;
    if (!path) return NULL;
    n = MultiByteToWideChar(codepage, flags, path, -1, NULL, 0);
    if (n <= 0) {
        codepage = CP_ACP;
        flags = 0;
        n = MultiByteToWideChar(codepage, flags, path, -1, NULL, 0);
        if (n <= 0) return NULL;
    }
    wide = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!wide) return NULL;
    if (MultiByteToWideChar(codepage, flags, path, -1, wide, n) <= 0) {
        free(wide);
        return NULL;
    }
    return wide;
}

FILE *envelock_identity_open(const char *path)
{
    wchar_t *wide;
    FILE *file;
    if (!path) return NULL;
    /* The identity must be a local, access-controlled file. Reject the UNC and device namespaces
     * (\\server\share, \\?\, \\.\, and the forward-slash forms): a remote share cannot be held to
     * the same local ownership/ACL guarantee, and a device/pipe path is never a key file (ENV-14).
     * The regular-file (FILE_TYPE_DISK) check in envelock_identity_file_check is the backstop. */
    if ((path[0] == '\\' || path[0] == '/') && (path[1] == '\\' || path[1] == '/')) return NULL;
    /* Opened through the wide API so a non-ASCII identity path works (ENV-14). */
    wide = envelock_path_wide(path);
    if (!wide) return NULL;
    file = _wfopen(wide, L"rb");
    free(wide);
    return file;
}

FILE *envelock_plain_open(const char *path)
{
    wchar_t *wide;
    FILE *file;
    if (!path) return NULL;
    /* No UNC/device rejection: the manifest is public and signature-verified, and the app may be
     * hosted on a share or an extended-length path (ENV-AUD-18). Still opened through the wide API
     * so non-ASCII and \\?\ long paths work. The regular-file check is the caller's backstop. */
    wide = envelock_path_wide(path);
    if (!wide) return NULL;
    file = _wfopen(wide, L"rb");
    free(wide);
    return file;
}

int envelock_file_is_regular(FILE *file)
{
    HANDLE handle = (HANDLE)_get_osfhandle(_fileno(file));
    return handle != INVALID_HANDLE_VALUE && GetFileType(handle) == FILE_TYPE_DISK;
}

#else
# include <fcntl.h>
# include <sys/stat.h>
# include <unistd.h>
# ifndef O_CLOEXEC
#  define O_CLOEXEC 0
# endif
# ifndef O_NOFOLLOW
#  define O_NOFOLLOW 0
# endif

const char *envelock_identity_file_check(FILE *file)
{
    struct stat info;
    if (fstat(fileno(file), &info) != 0 || !S_ISREG(info.st_mode) ||
        (info.st_mode & 0077) != 0 || (info.st_uid != geteuid() && info.st_uid != 0)) {
        /* Objective O5. The rule itself did not need changing and, measured, did not change
         * behaviour: a PHP-FPM master runs as root, so `st_uid != geteuid()` was already false for
         * a root-owned file, and the group/other test already refused any mode that let a pool
         * user in. What was wrong was the message, which told an operator following the documented
         * root:0400 layout that the file had to be "owned by the PHP user" — the very thing that
         * layout exists to avoid. Root is named as an accepted owner so the answer matches the
         * rule. */
        return "must be a regular file with mode 0600 or 0400 (no group/other access), owned by "
               "the PHP user or by root";
    }
    return NULL;
}
FILE *envelock_identity_open(const char *path)
{
    FILE *file;
    /* O_NOFOLLOW on the final component: the SECRET identity.bin / licence.bin must not be opened
     * through a symlink an attacker planted in its place (ENV-2026-31). O_NONBLOCK so a FIFO left in
     * its place cannot hang worker startup; the caller's fstat(S_ISREG) rejects a non-regular file. */
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return NULL;
    file = fdopen(fd, "rb");
    if (!file) close(fd);
    return file;
}

/* POSIX has no UNC namespace; a plain open is the same as the identity open (the manifest's
 * integrity comes from its signature, not from permissions). */
FILE *envelock_plain_open(const char *path)
{
    FILE *file;
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return NULL;
    file = fdopen(fd, "rb");
    if (!file) close(fd);
    return file;
}

int envelock_file_is_regular(FILE *file)
{
    struct stat info;
    return fstat(fileno(file), &info) == 0 && S_ISREG(info.st_mode);
}
#endif

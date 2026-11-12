#!/usr/bin/env python3
"""Envelock v2: offline packager. Requires Python >=3.10, cryptography >=42.

Envelock -- PHP source protection. Project page: https://miguelenred.es/envelock
Apache-2.0; "Powered by Envelock" acknowledgements are appreciated but not required.

v2 (Oct 2026): per-recipient asymmetric wrapping. The content key is wrapped for each
recipient with X25519 + HKDF-SHA256 + AES-256-GCM; Ed25519 signs for authenticity.
The loader carries no embedded secret (generic binary): it reads the recipient private
key and the trusted signer public key from an external identity file. Owning a public
engine or another developer's keys does not decrypt packages addressed to someone else.
"""

from __future__ import annotations

import argparse
import base64
import calendar
import fnmatch
import getpass
import glob
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import struct
import subprocess  # nosec B404 # only runs the operator's php CLI (--strip-comments/--obfuscate)
import sys
import tempfile
import time
import unicodedata
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

STUB = b'<?php /* Envelock */ exit("Envelock loader required\\n"); __halt_compiler();\n'
MAGIC = b"ENVLK02\0"
FORMAT_VERSION = 2
# magic 8 | version 1 | flags 1 | path_length 2 | project 16 | release 16 | count 2 |
# file_nonce 12 | size 4 | serial 8; then the relative path, the recipient table, the ciphertext,
# the GCM tag and the signature. Stub, header, path and table are the content's AAD.
HEADER = struct.Struct(">8sBBH16s16sH12sIQ")
MAX_PATH = 1024
FLAG_INCLUDE_PROTECTION = 1  # only the entry point or protected callers of the same project
FLAG_NO_PREPEND = 2  # refuse to run with auto_prepend_file / auto_append_file
FLAG_NO_FFI = 4  # refuse while FFI / dl() can read the decrypted code from process memory
FLAG_SEALED = 8  # sealed tree: loader refuses plain PHP under it and eval()
FLAG_ENFORCE_MANIFEST = 16  # loader checks the signed binary manifest at runtime (no deleted files)
FLAG_VAULT = 32  # string literals moved to a C-side per-file vault, kept out of the op_array constants
FLAG_BYTECODE = 64  # payload is a serialized zend_op_array (objective O1), not PHP source
# Objective O7: the vault table itself is encrypted, and each literal is decrypted only when the
# program asks for it. Always accompanies FLAG_VAULT; an older loader sees the unknown bit and
# refuses the file, so a package cannot silently fall back to a plaintext table.
FLAG_VAULT_ENC = 128
FLAGS_KNOWN = (FLAG_INCLUDE_PROTECTION | FLAG_NO_PREPEND | FLAG_NO_FFI | FLAG_SEALED
               | FLAG_ENFORCE_MANIFEST | FLAG_VAULT | FLAG_BYTECODE | FLAG_VAULT_ENC)
RECIPIENT_SIZE = 32 + 32 + 12 + 48  # recipient_pub | ephemeral_pub | wrap_nonce | wrapped_key
MAX_RECIPIENTS = 1024
KEM_DOMAIN = b"Envelock/kem/v2\0"  # 16 bytes, trailing NUL is part of the domain
MAX_SOURCE = 16 * 1024 * 1024
SIGNATURE_SIZE = 64
TAG_SIZE = 16
# Server identity/trust store (consumed by the loader via php.ini). A host may serve
# several projects with different keys, so recipients and trusted developers are two
# independent lists (a per-installation trust store, never taken from the package):
#   magic "ENVLKID3" | recipient_count(u16) | developer_count(u16)
#   recipients:  recipient_count x (x25519_priv 32 | x25519_pub 32)
#   developers:  developer_count x (ed25519_primary_pub 32 | ed25519_recovery_pub 32)
#   minimums:    optional, until the end of the file: n x (developer_primary_pub 32 | project 16 | serial u64)
# A minimum refuses packages of that project with a lower serial (no rollback to an old release).
# The minimum is bound to the developer whose signed package set it (its primary public key); the
# loader applies it only to packages signed by THAT developer, so one trusted developer cannot brick
# another developer's project on a shared server (ENV-AUD-14). An all-zero developer field means
# "unbound" (applies to any developer): legacy v2 minimums and admin-set --project/--serial minimums.
# A recovery public of all zeros means "no recovery key". The loader trusts a package
# signed by any developer's primary OR recovery key. developer_id = SHA256(primary_pub).
IDENTITY_MAGIC = b"ENVLKID3"       # 8 bytes (current)
IDENTITY_MAGIC_V2 = b"ENVLKID2"    # legacy, read-only (24-byte minimums, unbound)
IDENTITY_RECIPIENT = 32 + 32  # 64
IDENTITY_DEVELOPER = 32 + 32  # 64
MAX_IDENTITIES = 64
IDENTITY_MINIMUM = 32 + 16 + 8  # 56 (developer_pub | project | serial)
IDENTITY_MINIMUM_V2 = 16 + 8    # 24 (legacy: project | serial)
MAX_MINIMUMS = 256
IDENTITY_MAX_FILE = 12 + MAX_IDENTITIES * (IDENTITY_RECIPIENT + IDENTITY_DEVELOPER) + MAX_MINIMUMS * IDENTITY_MINIMUM
ZERO32 = b"\x00" * 32
DEFAULT_EXTENSIONS = {".php", ".phtml", ".inc", ".php8"}
DENIED_PARTS = {
    ".git",
    ".svn",
    ".hg",
    ".ssh",
    ".aws",
    ".venv",
    "__pycache__",
    "node_modules",
    # Developer credential stores (ENC-15): npm/yarn tokens, netrc logins, git's credential store,
    # Docker registry auth and PostgreSQL passwords. Never part of a PHP deployment.
    ".npmrc",
    ".netrc",
    "_netrc",
    ".git-credentials",
    ".pgpass",
    ".docker",
}
MAX_ASSET = 64 * 1024 * 1024
CONFIG_AAD = b"Envelock/private-config/v1"
# Device names Windows reserves in every folder, with or without an extension. COM0/LPT0 and the
# superscript-digit forms (COM¹, LPT²...) are reserved too, as are the console devices (ENC-25).
WINDOWS_RESERVED = {"con", "prn", "aux", "nul", "conin$", "conout$"} | {
    f"{prefix}{n}" for prefix in ("com", "lpt") for n in [*range(0, 10), "¹", "²", "³"]
}


def secret_write(path: Path, data: bytes, like: Path | None = None) -> None:
    """Create path exclusively with mode 0600 and write data durably.

    like: a file being replaced. On Windows the new file is created already carrying the explicit
    access entries of like (0600 has no effect there) and like's owner, before any secret is
    written; replace_file() then puts it in place and drops the temporary entry that let you rename
    it. It is never readable through inherited permissions.
    """
    parent_existed = path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)   # L-01: a secret's folder is private
    # mkdir's mode applies only to a folder it CREATES, so a folder we create is 0700. We do NOT chmod
    # a PRE-EXISTING parent: forcing a shared system dir (e.g. /etc/envelock, which may also hold a
    # world-readable licence) to 0700 silently broke other users' access (ENV-2026-17), and it buys
    # little — the secret file itself is created 0600, so it is unreadable by others whatever the
    # directory mode. We only warn if a pre-existing parent is group/other-accessible.
    if os.name != "nt" and parent_existed:
        try:
            mode = stat.S_IMODE(os.stat(path.parent).st_mode)
            if mode & 0o077:
                print(f"Note: {path.parent} is group/other-accessible ({oct(mode)}); the secret file "
                      f"itself is 0600, but consider tightening the directory.", file=sys.stderr)
        except OSError:
            pass
    if os.name == "nt" and like is not None and like.exists():
        try:
            fd = _create_windows_like(path, like)
        except FileExistsError:
            raise
        except OSError as error:
            raise ValueError(
                f"Could not give the new file the owner and permissions of {like.name} "
                f"({error}); run the command as Administrator (elevated). Nothing was changed."
            ) from error
    elif os.name == "nt":
        # 0600 has no effect on Windows: a file made by os.open inherits the folder's ACL (e.g. read
        # for all local users under C:\), and restricting it afterwards left a window in which another
        # account could open a handle that kept its access (ENC-4). Create it ALREADY carrying a
        # protected ACL (SYSTEM, Administrators, you), before a single byte of the secret exists.
        fd = _windows_create_new(path, _windows_secret_sddl())
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())  # durable before any rename that relies on it


def _current_user_sid_string() -> str:
    """SID string of the process user (e.g. 'S-1-5-21-...'). Windows only."""
    import ctypes  # Windows only
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                           wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]

    def win_error():
        return ctypes.WinError(ctypes.get_last_error())

    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):  # TOKEN_QUERY
        raise win_error()
    try:
        size = wintypes.DWORD(0)
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))  # TokenUser = 1
        buf = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, buf, size, ctypes.byref(size)):
            raise win_error()
        psid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]   # TOKEN_USER.User.Sid
        str_sid = wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(psid, ctypes.byref(str_sid)):
            raise win_error()
        try:
            return str_sid.value
        finally:
            kernel.LocalFree(str_sid)
    finally:
        kernel.CloseHandle(token)


_WIN32_API = None


def _win32():
    """advapi32/kernel32 entry points used by the Windows ACL code, with their signatures. Windows
    only; built once."""
    global _WIN32_API
    if _WIN32_API is not None:
        return _WIN32_API
    import ctypes  # Windows only
    import types
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    void_pp = ctypes.POINTER(ctypes.c_void_p)

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", wintypes.BOOL)]

    advapi.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD,
                                             void_pp, void_pp, void_pp, void_pp, void_pp]
    advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
                                       void_pp, void_pp, void_pp, void_pp, void_pp]
    advapi.GetSecurityInfo.restype = wintypes.DWORD
    advapi.SetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
                                       ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.c_void_p]
    advapi.SetSecurityInfo.restype = wintypes.DWORD
    advapi.SetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
                                             ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                             ctypes.c_void_p]
    advapi.SetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, void_pp, ctypes.c_void_p]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR),
        ctypes.c_void_p]
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    advapi.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
                                                 void_pp, ctypes.POINTER(wintypes.BOOL)]
    advapi.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, void_pp]
    advapi.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                   ctypes.POINTER(SecurityAttributes), wintypes.DWORD,
                                   wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                                  wintypes.DWORD]
    kernel.SetFileInformationByHandle.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    _WIN32_API = types.SimpleNamespace(ctypes=ctypes, wintypes=wintypes, advapi=advapi,
                                       kernel=kernel, SecurityAttributes=SecurityAttributes)
    return _WIN32_API


# SECURITY_INFORMATION bits and SE_FILE_OBJECT, for the Windows ACL helpers.
_WIN_OWNER_INFO, _WIN_DACL_INFO = 0x1, 0x4
_WIN_PROTECTED_DACL, _WIN_UNPROTECTED_DACL = 0x80000000, 0x20000000
_WIN_SE_FILE_OBJECT = 1


def _windows_secret_sddl() -> str:
    """The protected DACL every fresh secret gets on Windows: SYSTEM, Administrators and the
    creating user, full control, nothing inherited."""
    return f"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{_current_user_sid_string()})"


def _windows_security_sddl(path: Path | None = None, handle: int | None = None,
                           info: int = _WIN_DACL_INFO) -> str:
    """SDDL text of the owner and/or DACL (info) of a file, read by path or from an open handle (the
    handle form has no check/open race). Windows only."""
    w = _win32()
    ctypes = w.ctypes
    sd = ctypes.c_void_p()
    if handle is not None:
        rc = w.advapi.GetSecurityInfo(handle, _WIN_SE_FILE_OBJECT, info, None, None, None, None,
                                      ctypes.byref(sd))
    else:
        rc = w.advapi.GetNamedSecurityInfoW(str(path), _WIN_SE_FILE_OBJECT, info, None, None, None,
                                            None, ctypes.byref(sd))
    if rc:
        raise ctypes.WinError(rc)
    try:
        text = w.wintypes.LPWSTR()
        if not w.advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd, 1, info, ctypes.byref(text), None):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return text.value or ""
        finally:
            w.kernel.LocalFree(text)
    finally:
        w.kernel.LocalFree(sd)


def _windows_sid_string(token: str) -> str:
    """Canonical 'S-1-...' form of an SDDL SID token, which may be an alias such as SY, BA or LA."""
    if token.upper().startswith("S-"):
        return token.upper()
    w = _win32()
    ctypes = w.ctypes
    sid = ctypes.c_void_p()
    if not w.advapi.ConvertStringSidToSidW(token, ctypes.byref(sid)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        text = w.wintypes.LPWSTR()
        if not w.advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return (text.value or "").upper()
        finally:
            w.kernel.LocalFree(text)
    finally:
        w.kernel.LocalFree(sid)


def _parse_sddl_dacl(sddl: str) -> tuple[str, list[str]]:
    """Split the 'D:' part of SDDL text into its flags ('P', 'AI', ...) and its ACE strings, each
    '(type;flags;rights;object;inherited-object;sid)'. Anything this does not model exactly (a NULL
    DACL, conditional or resource-attribute entries) raises OSError: the callers fail closed."""
    match = re.search(r"D:((?:P|AR|AI|NO_ACCESS_CONTROL)*)((?:\([^()]*\))*)(?=S:|$)", sddl)
    if not match:
        raise OSError("unsupported access list (" + sddl[:120] + ")")
    if "NO_ACCESS_CONTROL" in match.group(1):
        raise OSError("the file has no access list (everyone has full access)")
    return match.group(1), re.findall(r"\([^()]*\)", match.group(2))


def _sddl_ace_flags(ace: str) -> set[str]:
    """The two-letter flags of one ACE string ('CI', 'OI', 'IO', 'ID', ...)."""
    flags = ace[1:-1].split(";")[1]
    return {flags[i:i + 2] for i in range(0, len(flags), 2)}


def _windows_explicit_dacl(model: Path) -> tuple[list[str], bool]:
    """The explicit (not inherited) ACEs of model's DACL and whether that DACL is protected. These
    are what an update must carry over (ENC-6): an identity file's ACL is set by the administrator
    (the PHP service account's read entry, SYSTEM, Administrators), and rebuilding it from scratch
    dropped the service account and added the operator, whom the loader does not accept."""
    flags, aces = _parse_sddl_dacl(_windows_security_sddl(model, info=_WIN_DACL_INFO))
    explicit = [ace for ace in aces if "ID" not in _sddl_ace_flags(ace)]
    if "P" in flags and not explicit:
        raise OSError(f"the access list of {model.name} grants access to no one; fix it with icacls")
    return explicit, "P" in flags


def _windows_create_new(path: Path, sddl: str, owner_of: Path | None = None,
                        readonly: bool = False) -> int:
    """Windows: create path (CREATE_NEW: never an existing file or link) ALREADY carrying the
    security descriptor sddl, so no other account can open it between creation and the first write
    (ENC-4), and return a writable CRT descriptor (its handle also has READ_CONTROL and DELETE).
    owner_of: give the new file that file's owner, enabling SeRestorePrivilege when it is another
    account. readonly sets the read-only attribute (the 0400 analogue). An existing path raises
    FileExistsError; on any later failure the half-made file is deleted through its own handle."""
    import msvcrt  # type: ignore[import-not-found]

    w = _win32()
    ctypes = w.ctypes
    generic_write, write_owner, delete, read_control = 0x40000000, 0x80000, 0x10000, 0x20000
    create_new = 1
    attribute = 0x1 if readonly else 0x80          # FILE_ATTRIBUTE_READONLY / _NORMAL
    file_disposition_info, error_invalid_owner = 4, 1307
    invalid_handle = ctypes.c_void_p(-1).value

    sd = ctypes.c_void_p()
    if not w.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(sd),
                                                                         None):
        raise ctypes.WinError(ctypes.get_last_error())
    owner_sd, owner = ctypes.c_void_p(), ctypes.c_void_p()
    try:
        if owner_of is not None:
            rc = w.advapi.GetNamedSecurityInfoW(str(owner_of), _WIN_SE_FILE_OBJECT, _WIN_OWNER_INFO,
                                                ctypes.byref(owner), None, None, None,
                                                ctypes.byref(owner_sd))
            if rc:
                raise OSError(f"cannot read the owner of {owner_of.name} (error {rc})")
        attributes = w.SecurityAttributes(ctypes.sizeof(w.SecurityAttributes), sd, False)
        handle = w.kernel.CreateFileW(str(path), generic_write | write_owner | delete | read_control,
                                      0, ctypes.byref(attributes), create_new, attribute, None)
        if handle in (None, invalid_handle):
            error = ctypes.WinError(ctypes.get_last_error())   # 80 -> FileExistsError
            error.filename = str(path)
            raise error
        try:
            if owner_of is not None:
                set_info = w.advapi.SetSecurityInfo
                rc = set_info(handle, _WIN_SE_FILE_OBJECT, _WIN_OWNER_INFO, owner, None, None, None)
                if rc == error_invalid_owner and _enable_windows_privilege("SeRestorePrivilege"):
                    rc = set_info(handle, _WIN_SE_FILE_OBJECT, _WIN_OWNER_INFO, owner, None, None,
                                  None)
                if rc:
                    raise OSError(f"cannot set the file owner (error {rc})")
            return msvcrt.open_osfhandle(handle, os.O_WRONLY | getattr(os, "O_BINARY", 0))
        except BaseException:
            delete_file = ctypes.c_ubyte(1)  # FILE_DISPOSITION_INFO.DeleteFile = TRUE
            w.kernel.SetFileInformationByHandle(handle, file_disposition_info,
                                                ctypes.byref(delete_file), 1)
            w.kernel.CloseHandle(handle)
            raise
    finally:
        w.kernel.LocalFree(sd)
        if owner_sd:
            w.kernel.LocalFree(owner_sd)


# Windows: final DACL of a file made by _create_windows_like, applied by replace_file() once it is in
# place. Keyed by the temporary path.
_PENDING_WINDOWS_DACL: dict[str, tuple[list[str], bool]] = {}


def _pending_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(path))


def _create_windows_like(path: Path, model: Path) -> int:
    """Windows: create path (CREATE_NEW) for an in-place update of model and return a writable CRT
    descriptor. The new file gets model's owner and model's EXPLICIT access entries (ENC-6: the
    service account's read entry must survive an update, and the operator must not be added: the
    loader accepts only the PHP service account, SYSTEM and Administrators).

    One temporary entry is added: full control for the current user. os.replace() needs DELETE on
    the source (A2: a verbatim model DACL need not grant the updater DELETE, and identity updates
    failed with WinError 5), and that entry is also what lets replace_file() set the final DACL —
    exactly model's explicit entries, protected or inheriting as model's was — once the file is in
    place. The temporary entry only ever names the user who is writing the secret anyway."""
    explicit, protected = _windows_explicit_dacl(model)
    sddl = "D:P" + "".join(explicit) + f"(A;;FA;;;{_current_user_sid_string()})"
    fd = _windows_create_new(path, sddl, owner_of=model)
    _PENDING_WINDOWS_DACL[_pending_key(path)] = (explicit, protected)
    return fd


def _set_windows_dacl(path: Path, aces: list[str], protected: bool) -> None:
    """Windows: make path's DACL exactly aces, protected (nothing inherited) or inheriting from its
    folder."""
    w = _win32()
    ctypes, wintypes = w.ctypes, w.wintypes
    sd = ctypes.c_void_p()
    if not w.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            "D:" + "".join(aces), 1, ctypes.byref(sd), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        present, dacl, defaulted = wintypes.BOOL(), ctypes.c_void_p(), wintypes.BOOL()
        if not w.advapi.GetSecurityDescriptorDacl(sd, ctypes.byref(present), ctypes.byref(dacl),
                                                  ctypes.byref(defaulted)):
            raise ctypes.WinError(ctypes.get_last_error())
        flags = _WIN_DACL_INFO | (_WIN_PROTECTED_DACL if protected else _WIN_UNPROTECTED_DACL)
        rc = w.advapi.SetNamedSecurityInfoW(str(path), _WIN_SE_FILE_OBJECT, flags, None, None, dacl,
                                            None)
        if rc:
            raise ctypes.WinError(rc)
    finally:
        w.kernel.LocalFree(sd)


def _windows_dacl_problem(handle: int, allowed: set[str]) -> str | None:
    """Why the file behind handle is readable by someone it should not be, or None. allowed: SID
    strings that may hold an allow entry; the file's own owner is always allowed. Deny and
    inherit-only entries grant nothing to the file and are skipped; an entry type this does not
    model fails closed."""
    sddl = _windows_security_sddl(handle=handle, info=_WIN_OWNER_INFO | _WIN_DACL_INFO)
    owner = re.search(r"O:(S-[0-9-]+|[A-Z]{2})", sddl)
    permitted = {_windows_sid_string(s) for s in allowed}
    if owner:
        permitted.add(_windows_sid_string(owner.group(1)))
    try:
        _flags, aces = _parse_sddl_dacl(sddl)
    except OSError as error:
        return str(error)
    for ace in aces:
        fields = ace[1:-1].split(";")
        if len(fields) < 6:
            return "it has an access entry of an unsupported form"
        kind, sid = fields[0], fields[5]
        if "IO" in _sddl_ace_flags(ace) or kind in ("D", "OD", "XD"):
            continue
        if kind not in ("A", "OA"):
            return "it has an access entry of an unsupported type"
        if _windows_sid_string(sid) not in permitted:
            return f"its access list also grants {sid}"
    return None


def _enable_windows_privilege(name: str) -> bool:
    """Enable a privilege the (elevated) process holds, e.g. SeRestorePrivilege, which Windows
    requires to set a file owner other than the current user or its owner-capable groups."""
    import ctypes  # Windows only
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]

    class Luid(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class LuidAndAttributes(ctypes.Structure):
        _fields_ = [("Luid", Luid), ("Attributes", wintypes.DWORD)]

    class TokenPrivileges(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LuidAndAttributes * 1)]

    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(Luid)]
    advapi.LookupPrivilegeValueW.restype = wintypes.BOOL
    advapi.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL,
                                             ctypes.POINTER(TokenPrivileges), wintypes.DWORD,
                                             ctypes.c_void_p, ctypes.c_void_p]
    advapi.AdjustTokenPrivileges.restype = wintypes.BOOL
    token_adjust_privileges, token_query, se_privilege_enabled = 0x20, 0x8, 0x2
    error_not_all_assigned = 1300

    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(),
                                   token_adjust_privileges | token_query, ctypes.byref(token)):
        return False
    try:
        luid = Luid()
        if not advapi.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            return False
        privileges = TokenPrivileges(1, (LuidAndAttributes * 1)(LuidAndAttributes(luid, se_privilege_enabled)))
        ok = advapi.AdjustTokenPrivileges(token, False, ctypes.byref(privileges), 0, None, None)
        return bool(ok) and ctypes.get_last_error() != error_not_all_assigned
    finally:
        kernel.CloseHandle(token)


def replace_file(source: Path, target: Path) -> None:
    """Atomically replace target with source (prepared with secret_write(..., like=target)).
    POSIX: rename, then fsync the directory so the change survives a power cut. Windows: once in
    place, the file gets exactly the explicit access entries of the file it replaced (ENC-6)."""
    pending = _PENDING_WINDOWS_DACL.pop(_pending_key(source), None) if os.name == "nt" else None
    os.replace(source, target)
    if pending is not None:
        try:
            _set_windows_dacl(target, *pending)
        except OSError as error:
            raise ValueError(
                f"{target.name} was updated, but its previous access list could not be restored "
                f"({error}); check it with icacls before restarting PHP") from error
    if os.name != "nt":
        fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def write_public(path: Path, data: bytes) -> None:
    """Write a world-readable (0644) file atomically: a concurrent reader never sees it absent or
    half-written. Used for the licence, whose integrity comes from its signature, not its mode. The
    old unlink-then-write left a window where a running server read a missing licence.bin and failed
    closed as if the licence were invalid (ENV-2026-20).

    Not a secret, so not written like one: on Windows it keeps the folder's inherited ACL (a
    protected owner-only ACL left the PHP service account unable to read it, ENC-13), and on POSIX
    the mode is set on the open descriptor (fchmod), never through a path a symlink could redirect
    (ENC-2)."""
    parent_existed = path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / (path.name + ".tmp-" + secrets.token_hex(4))
    try:
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        fd = os.open(tmp, flags, 0o644)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            if os.name != "nt":
                os.fchmod(f.fileno(), 0o644)      # the umask may have narrowed the create mode
            os.fsync(f.fileno())
        replace_file(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()
    # Internal audit (Nov 2026): a parent created under the CLI's umask 077 is 0700, but this file is
    # deliberately world-readable (a signed licence; its integrity is its signature, not its mode).
    # A 0700 parent a non-root service user cannot traverse would make the loader read a "missing"
    # licence and fail closed -- the exact mis-deploy ENV-2026-20 set out to remove. If WE created
    # the parent, make it traversable (0755). A pre-existing parent is left as the admin set it.
    if os.name != "nt" and not parent_existed:
        try:
            os.chmod(path.parent, 0o755)  # nosec B103 - must be traversable by the PHP user (ENV-2026-20)
        except OSError:
            pass


def bounded_read(path: Path, limit: int, private: bool = False) -> bytes:
    # Trusted source tree still required: NOFOLLOW does not pin ancestor directories.
    # O_CLOEXEC so the descriptor is not inherited by a child `php` started while it is open
    # (audit NU-07); it matches the loader, which opens the identity with O_CLOEXEC.
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    if path.is_symlink():
        raise ValueError(f"Symbolic links are not allowed: {path.name}")
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as f:
        before = os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError(f"File is not regular or too large: {path.name}")
        # Permission check on the OPEN descriptor, not a pre-open path.stat(): the latter follows
        # symlinks and leaves a TOCTOU window in which the checked file and the read file differ
        # (audit NU-02). fstat pins the exact file being read.
        if private and os.name != "nt" and (before.st_mode & 0o077):
            raise ValueError("The password file must have 0600 permissions or stricter")
        if private and os.name == "nt":
            # Mode bits mean nothing on Windows: check the access list of the OPEN handle instead
            # (ENC-24). Only you, the file's owner, SYSTEM and Administrators may hold an entry.
            import msvcrt  # type: ignore[import-not-found]
            try:
                problem = _windows_dacl_problem(
                    msvcrt.get_osfhandle(f.fileno()),
                    {_current_user_sid_string(), "S-1-5-18", "S-1-5-32-544", "S-1-3-4"})
            except OSError as error:
                problem = f"its access list cannot be read ({error})"
            if problem:
                raise ValueError(
                    f"The password file must be readable only by you, SYSTEM and Administrators: "
                    f"{problem}. Restrict it, e.g. icacls <file> /inheritance:r /grant:r "
                    f"\"%USERNAME%:F\" \"*S-1-5-18:F\" \"*S-1-5-32-544:F\"")
        data = f.read(limit + 1)
        after = os.fstat(f.fileno())
        if len(data) > limit or (before.st_size, before.st_mtime_ns) != (
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError(
                f"File too large or modified during read: {path.name}"
            )
        return data


def _stdin_is_console() -> bool:
    """True only when stdin is a real interactive console.

    On Windows ``NUL`` is a character device, so ``isatty()`` returns True for a
    redirected ``stdin=NUL`` and ``getpass`` would then block forever. Query the
    console mode of the stdin handle instead and fail closed if it is not a
    console. On POSIX ``isatty()`` is reliable.
    """
    if os.name != "nt":
        try:
            return sys.stdin.isatty()
        except (ValueError, OSError):
            return False
    import ctypes
    from ctypes import wintypes
    STD_INPUT_HANDLE = -10
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.GetStdHandle(STD_INPUT_HANDLE)
    if handle == 0 or handle == wintypes.HANDLE(-1).value:
        return False
    mode = wintypes.DWORD()
    # GetConsoleMode succeeds only for a genuine console handle.
    return bool(kernel32.GetConsoleMode(handle, ctypes.byref(mode)))


def password_from_user(confirm: bool = False) -> bytes:
    location = os.getenv("ENVELOCK_PASSWORD_FILE")
    if location:
        path = Path(location)
        # private=True enforces 0600-or-stricter via fstat on the opened file (no TOCTOU, NU-02).
        password = bounded_read(path, 4096, private=True).rstrip(b"\r\n")
    else:
        if not _stdin_is_console():
            raise ValueError(
                "The private-key password needs an interactive terminal or ENVELOCK_PASSWORD_FILE "
                "(to create keys without a password, pass --no-encrypt explicitly)"
            )
        password = getpass.getpass("Private key password: ").encode("utf-8")
        if confirm and password != getpass.getpass("Repeat password: ").encode("utf-8"):
            raise ValueError("Passwords do not match")
    if len(password.decode("utf-8", "replace")) < 16:     # characters, to match the GUI (L-04)
        raise ValueError("Use a password of at least 16 characters, preferably random")
    return password


RESTART_NOTE = ("Restart PHP (php-fpm / Apache / the CLI process) for the change to take effect: "
                "the loader reads the identity file at startup.")


def recipient_public_hex(path: Path) -> str:
    """X25519 public key from a recipient descriptor, public or private."""
    raw = json.loads(bounded_read(path, 64 * 1024))
    kind = raw.get("kind") if isinstance(raw, dict) else None
    if kind == "envelock-recipient-public":
        return validate_config(raw, kind)["x25519_public"]
    return read_config(path, "envelock-recipient")["x25519_public"]


def cli_recipient_public(path: Path) -> dict:
    """A public recipient descriptor for packing, from either an exported public key (.pub.json)
    or your own private recipient.json (its public part is derived). An ENCRYPTED private recipient
    is refused with an actionable message: its public key lives inside the encrypted blob, so pack
    cannot read it without the password (ENV-AUD-16) — export the public key once instead."""
    raw = json.loads(bounded_read(path, 64 * 1024))
    kind = raw.get("kind") if isinstance(raw, dict) else None
    if kind == "envelock-recipient-public":
        return validate_config(raw, kind)
    if kind == "envelock-encrypted":
        raise ValueError(
            f"{Path(path).name} is an encrypted private recipient; pack needs only the public key. "
            "Export it once with 'export-public' and pass the resulting .pub.json to pack")
    return recipient_public(read_config(path, "envelock-recipient"))


def new_password(args) -> bytes | None:
    """Private keys are encrypted unless --no-encrypt is given explicitly."""
    if getattr(args, "no_encrypt", False):
        print("WARNING: writing private keys unencrypted (--no-encrypt). Protect the file.",
              file=sys.stderr)
        return None
    return password_from_user(True)


def save_json(path: Path, value: dict, password: bytes | None = None, like: Path | None = None) -> None:
    data = (json.dumps(value, indent=2) + "\n").encode()
    if password is not None:
        if len(password.decode("utf-8", "replace")) < 16:     # characters (L-04)
            raise ValueError("Password too short (at least 16 characters)")
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        key = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(password)
        ciphertext = AESGCM(key).encrypt(nonce, data, CONFIG_AAD)
        data = (
            json.dumps(
                {
                    "kind": "envelock-encrypted",
                    "format": 1,
                    "kdf": "scrypt-131072-8-1",
                    "salt": salt.hex(),
                    "nonce": nonce.hex(),
                    "ciphertext": ciphertext.hex(),
                },
                indent=2,
            )
            + "\n"
        ).encode()
    secret_write(path, data, like)


# kind -> {field: byte length}. All private/public key material is fixed-length hex.
CONFIG_FIELDS = {
    "envelock-owner": {"signing_public": 32, "signing_private": 32},
    "envelock-recipient": {"x25519_public": 32, "x25519_private": 32},
    "envelock-recipient-public": {"x25519_public": 32},
    "envelock-identity": {"x25519_private": 32, "x25519_public": 32, "signing_public": 32},
    "envelock-developer-public": {"signing_public": 32},
}


def validate_config(obj: dict, kind: str) -> dict:
    if not isinstance(obj, dict) or obj.get("kind") != kind or obj.get("format") != FORMAT_VERSION:
        raise ValueError("Incorrect config kind or version")
    fields = CONFIG_FIELDS.get(kind)
    if fields is None:
        raise ValueError("Unknown config kind")
    for field, length in fields.items():
        value = obj.get(field)
        if (
            not isinstance(value, str)
            or len(value) != length * 2
            or len(bytes.fromhex(value)) != length
        ):
            raise ValueError(f"Invalid field: {field}")
    # A small-order Ed25519 key (identity, order 2/4/8, any encoding) accepts forged signatures on
    # every message: never trust one as a signer (ENC-14). Checked for every signing public key a
    # descriptor carries, including the optional recovery key.
    for field in ("signing_public", "recovery_public"):
        value = obj.get(field)
        if field in fields or (field == "recovery_public" and value is not None):
            try:
                weak = isinstance(value, str) and ed25519_small_order(bytes.fromhex(value))
            except ValueError:
                weak = False             # malformed: reported by the field checks below
            if weak:
                raise ValueError(f"Invalid {field}: a small-order Ed25519 point, which would accept "
                                 "forged signatures")
    if kind == "envelock-owner":
        signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(obj["signing_private"]))
        if raw_public(signer.public_key()).hex() != obj["signing_public"]:
            raise ValueError("Inconsistent signing pair")
        # Optional recovery signer: both fields present together and consistent, or only its public
        # half once the private one was moved to its own file (`owner split-recovery`, ENC-11).
        if "recovery_public" in obj and "recovery_private" not in obj:
            value = obj["recovery_public"]
            if not isinstance(value, str) or len(value) != 64 or len(bytes.fromhex(value)) != 32:
                raise ValueError("Invalid recovery field: recovery_public")
            if value == obj["signing_public"]:
                raise ValueError("The recovery key must differ from the primary signing key")
        elif "recovery_private" in obj or "recovery_public" in obj:
            for field in ("recovery_private", "recovery_public"):
                value = obj.get(field)
                if not isinstance(value, str) or len(value) != 64 or len(bytes.fromhex(value)) != 32:
                    raise ValueError(f"Invalid recovery field: {field}")
            recovery = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(obj["recovery_private"]))
            if raw_public(recovery.public_key()).hex() != obj["recovery_public"]:
                raise ValueError("Inconsistent recovery pair")
            if obj["recovery_public"] == obj["signing_public"]:   # ENV-18: a recovery key equal to
                raise ValueError("The recovery key must differ from the primary signing key")
    if kind in ("envelock-recipient", "envelock-identity"):
        priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(obj["x25519_private"]))
        if raw_x_public(priv.public_key()).hex() != obj["x25519_public"]:
            raise ValueError("Inconsistent X25519 pair")
    # Optional recovery signer carried into a server identity (public only).
    if kind in ("envelock-identity", "envelock-developer-public") and obj.get("recovery_public") is not None:
        value = obj["recovery_public"]
        if not isinstance(value, str) or len(value) != 64 or len(bytes.fromhex(value)) != 32:
            raise ValueError("Invalid recovery_public")
        if obj.get("signing_public") is not None and value == obj["signing_public"]:   # ENV-18
            raise ValueError("The recovery key must differ from the primary signing key")
    return obj


def read_config(path: Path, kind: str, password: bytes | None = None) -> dict:
    return read_config_with_password(path, kind, password)[0]


def read_config_with_password(
    path: Path, kind: str, password: bytes | None = None
) -> tuple[dict, bytes | None]:
    """Like read_config, also returning the password used (None for an unencrypted file), so
    a file updated in place can be re-encrypted with the same password."""
    obj = json.loads(bounded_read(path, 64 * 1024))
    if isinstance(obj, dict) and obj.get("kind") == "envelock-encrypted":
        if obj.get("format") != 1 or obj.get("kdf") != "scrypt-131072-8-1":
            raise ValueError("Unknown encrypted key format")
        salt, nonce = bytes.fromhex(obj["salt"]), bytes.fromhex(obj["nonce"])
        if len(salt) != 16 or len(nonce) != 12:
            raise ValueError("Invalid encrypted key header")
        password = password_from_user() if password is None else password
        key = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(password)
        try:
            obj = json.loads(
                AESGCM(key).decrypt(nonce, bytes.fromhex(obj["ciphertext"]), CONFIG_AAD)
            )
        except InvalidTag as error:
            raise ValueError("Wrong password or tampered configuration") from error
    else:
        password = None
    return validate_config(obj, kind), password


def raw_private(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )


def raw_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def raw_x_private(key: X25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )


def raw_x_public(key: X25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def developer_id(signing_public_hex: str) -> str:
    """Stable identifier of a developer/signer: SHA256 of its Ed25519 public key."""
    return hashlib.sha256(bytes.fromhex(signing_public_hex)).hexdigest()


# The PUBLIC, deterministic keys produced by scripts/demo_material.py (reproducible from source,
# used only for fuzzing/tests). Their private halves are published, so a package addressed to a
# demo recipient or signed by the demo owner is readable by anyone: pack refuses them unless
# --allow-demo is given, so a demo key cannot silently reach production. (DEMO rejection.)
DEMO_SIGNING_PUBLIC = "1be7ea2b3083fcfabfff1bbe6b4495bf520ff026a71a1289cdef853ebc6c4f26"
DEMO_X25519_PUBLIC = "487020a3036058b1a5d4bb0d035ded01e0f533fc72837d272bd3aa600400ac43"

_P25519 = 2**255 - 19


def _x25519_canonical_u(public: bytes) -> int:
    """The u-coordinate an X25519 public key actually denotes: bit 255 is ignored and u is taken
    modulo p (RFC 7748), so several byte strings name the same key."""
    return (int.from_bytes(public, "little") & ((1 << 255) - 1)) % _P25519


# y-coordinates of the 8 points of small order on edwards25519: the identity (y=1), the point of
# order 2 (y=-1), the two of order 4 (y=0) and the four of order 8 (two y values, each with both
# signs of x). A signing "public key" equal to one of them verifies forged signatures (ENC-14).
_ED25519_SMALL_ORDER_Y = frozenset({0, 1, _P25519 - 1} | {
    int.from_bytes(bytes.fromhex(h), "little") for h in (
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")})


def ed25519_small_order(public: bytes) -> bool:
    """True when public encodes a small-order point, in ANY encoding: the sign bit is masked and y
    reduced modulo p, so a non-canonical spelling of the same point is caught too."""
    y = int.from_bytes(public, "little") & ((1 << 255) - 1)
    return len(public) == 32 and y % _P25519 in _ED25519_SMALL_ORDER_Y


def make_owner(with_recovery: bool = False) -> dict:
    signer = Ed25519PrivateKey.generate()
    owner = {
        "kind": "envelock-owner",
        "format": FORMAT_VERSION,
        "signing_private": raw_private(signer).hex(),
        "signing_public": raw_public(signer.public_key()).hex(),
    }
    if with_recovery:
        recovery = Ed25519PrivateKey.generate()
        owner["recovery_private"] = raw_private(recovery).hex()
        owner["recovery_public"] = raw_public(recovery.public_key()).hex()
    return owner


def make_recipient(label: str) -> dict:
    key = X25519PrivateKey.generate()
    return {
        "kind": "envelock-recipient",
        "format": FORMAT_VERSION,
        "label": label,
        "x25519_private": raw_x_private(key).hex(),
        "x25519_public": raw_x_public(key.public_key()).hex(),
    }


def recipient_public(recipient: dict) -> dict:
    validate_config(recipient, "envelock-recipient")
    return {
        "kind": "envelock-recipient-public",
        "format": FORMAT_VERSION,
        "label": recipient.get("label", ""),
        "x25519_public": recipient["x25519_public"],
    }


def new_recovery(owner: dict) -> dict:
    """Return a copy of owner with a new recovery key pair (added, or replacing the old one)."""
    validate_config(owner, "envelock-owner")
    recovery = Ed25519PrivateKey.generate()
    rotated = dict(owner)
    rotated["recovery_private"] = raw_private(recovery).hex()
    rotated["recovery_public"] = raw_public(recovery.public_key()).hex()
    return rotated


def promote_recovery(owner: dict, recovery: dict | None = None) -> dict:
    """The recovery key becomes the primary signing key and a fresh recovery key is made.

    For a compromised primary: packages signed with the promoted key already verify on every
    server that trusts the old recovery key, before any server is updated. recovery: the separate
    recovery file made by split_recovery (an envelock-owner whose signing pair is the recovery
    key), needed once the owner file no longer holds the recovery private key.
    """
    validate_config(owner, "envelock-owner")
    if recovery is not None:
        validate_config(recovery, "envelock-owner")
        if recovery["signing_public"] != owner.get("recovery_public"):
            raise ValueError("That recovery file does not hold this owner's recovery key")
        private, public = recovery["signing_private"], recovery["signing_public"]
    elif "recovery_private" in owner:
        private, public = owner["recovery_private"], owner["recovery_public"]
    elif "recovery_public" in owner:
        raise ValueError("This owner's recovery key was moved to its own file (split-recovery); "
                         "pass that file with --recovery")
    else:
        raise ValueError("This owner has no recovery key to promote")
    promoted = {
        "kind": "envelock-owner",
        "format": FORMAT_VERSION,
        "signing_private": private,
        "signing_public": public,
    }
    return new_recovery(promoted)


def split_recovery(owner: dict) -> tuple[dict, dict]:
    """Separate an owner's recovery private key from its primary (ENC-11), so the recovery key can
    be kept offline under its own password as the manual advises. Returns (owner without
    recovery_private — it keeps recovery_public, so identity files still trust the recovery key —,
    the recovery key as its own envelock-owner descriptor). Nothing about the keys changes."""
    validate_config(owner, "envelock-owner")
    if "recovery_private" not in owner:
        raise ValueError("This owner file holds no recovery private key to split off")
    recovery = {"kind": "envelock-owner", "format": FORMAT_VERSION,
                "signing_private": owner["recovery_private"],
                "signing_public": owner["recovery_public"]}
    kept = {k: v for k, v in owner.items() if k != "recovery_private"}
    return validate_config(kept, "envelock-owner"), validate_config(recovery, "envelock-owner")


def developer_public(owner: dict) -> dict:
    """Public descriptor of a developer (primary and optional recovery public keys)."""
    validate_config(owner, "envelock-owner")
    developer = {"kind": "envelock-developer-public", "format": FORMAT_VERSION,
                 "signing_public": owner["signing_public"]}
    if owner.get("recovery_public"):
        developer["recovery_public"] = owner["recovery_public"]
    return developer


def make_identity(recipient: dict, owner: dict) -> dict:
    validate_config(recipient, "envelock-recipient")
    validate_config(owner, "envelock-owner")
    identity = {
        "kind": "envelock-identity",
        "format": FORMAT_VERSION,
        "x25519_private": recipient["x25519_private"],
        "x25519_public": recipient["x25519_public"],
        "signing_public": owner["signing_public"],
        "developer_id": developer_id(owner["signing_public"]),
    }
    if owner.get("recovery_public") is not None:
        identity["recovery_public"] = owner["recovery_public"]
    return identity


def identity_bundle_bytes(identities: list[dict]) -> bytes:
    """Server identity bundle consumed by the loader via php.ini. SECRET.

    One entry per project served by the host. The loader tries each entry until one
    matches the package's recipient table and verifies under that entry's signer.
    """
    if not 1 <= len(identities) <= MAX_IDENTITIES:
        raise ValueError("The identity bundle supports between 1 and 64 projects")
    recipients: list[bytes] = []
    recipients_seen: set[bytes] = set()
    developers: list[bytes] = []
    developers_seen: set[bytes] = set()
    for identity in identities:
        validate_config(identity, "envelock-identity")
        pub = bytes.fromhex(identity["x25519_public"])
        if pub not in recipients_seen:
            recipients_seen.add(pub)
            recipients.append(bytes.fromhex(identity["x25519_private"]) + pub)
        primary = bytes.fromhex(identity["signing_public"])
        recovery = bytes.fromhex(identity["recovery_public"]) if identity.get("recovery_public") else ZERO32
        if primary not in developers_seen:
            developers_seen.add(primary)
            developers.append(primary + recovery)
        elif primary + recovery not in developers:
            raise ValueError("The same developer appears with different recovery keys")
    return build_identity_store(recipients, developers)


def build_identity_store(recipients: list[bytes], developers: list[bytes],
                         minimums: dict[tuple[bytes, bytes], int] | None = None) -> bytes:
    """Pack raw recipient (priv32|pub32) and developer (primary32|recovery32) entries and the
    per-project minimums, keyed by (project id bytes, developer_primary_pub) -> serial. An all-zero
    developer_primary_pub means the minimum is unbound (applies to any developer). Always writes
    the current format (ENVLKID3)."""
    minimums = minimums or {}
    if len(minimums) > MAX_MINIMUMS:
        raise ValueError("At most 256 project minimums per identity file")
    if not 1 <= len(recipients) <= MAX_IDENTITIES or not 1 <= len(developers) <= MAX_IDENTITIES:
        raise ValueError("The trust store supports between 1 and 64 recipients and developers")
    if any(len(r) != IDENTITY_RECIPIENT for r in recipients) or any(
        len(d) != IDENTITY_DEVELOPER for d in developers
    ):
        raise ValueError("Identity entry with incorrect size")
    blocks = []
    for (project, dev_pub), serial in sorted(minimums.items()):
        if len(dev_pub) != 32:
            raise ValueError("Minimum developer key with incorrect size")
        blocks.append(dev_pub + project + struct.pack(">Q", serial))
    return (
        IDENTITY_MAGIC
        + struct.pack(">HH", len(recipients), len(developers))
        + b"".join(recipients)
        + b"".join(developers)
        + b"".join(blocks)
    )


def _identity_minimum_layout(data: bytes) -> tuple[int, int]:
    """(stride, has_developer) for the minimum entries, by magic. Reads both the current format and
    the legacy ENVLKID2 (24-byte, unbound) files; build_* always writes the current one."""
    if data[:8] == IDENTITY_MAGIC:
        return IDENTITY_MINIMUM, True
    if data[:8] == IDENTITY_MAGIC_V2:
        return IDENTITY_MINIMUM_V2, False
    raise ValueError("Unrecognized identity file")


def parse_identity_store(data: bytes) -> tuple[list[bytes], list[bytes]]:
    """Inverse of build_identity_store. Returns (recipients, developers) raw entries. Accepts the
    current and the legacy identity format."""
    stride, _ = _identity_minimum_layout(data)
    if len(data) < 12:
        raise ValueError("Unrecognized identity file")
    rc, dc = struct.unpack(">HH", data[8:12])
    if not (1 <= rc <= MAX_IDENTITIES and 1 <= dc <= MAX_IDENTITIES):
        raise ValueError("Identity count out of range")
    rest = len(data) - 12 - rc * IDENTITY_RECIPIENT - dc * IDENTITY_DEVELOPER
    if rest < 0 or rest % stride or rest // stride > MAX_MINIMUMS:
        raise ValueError("Invalid identity file size")
    off = 12
    recipients = [data[off + i * IDENTITY_RECIPIENT : off + (i + 1) * IDENTITY_RECIPIENT] for i in range(rc)]
    off += rc * IDENTITY_RECIPIENT
    developers = [data[off + i * IDENTITY_DEVELOPER : off + (i + 1) * IDENTITY_DEVELOPER] for i in range(dc)]
    return recipients, developers


def identity_minimums(data: bytes) -> dict[tuple[bytes, bytes], int]:
    """Per-project minimums stored after the developers, keyed by (project id bytes,
    developer_primary_pub) -> serial. developer_primary_pub is all-zero for an unbound (legacy/admin)
    minimum. The key includes the developer so two developers that share a project id keep INDEPENDENT
    minimums: keying by project alone let a second developer's minimum silently replace the first's
    (audit ENV-03), even though the wire format and the loader bind each minimum to its developer."""
    stride, has_dev = _identity_minimum_layout(data)
    recipients, developers = parse_identity_store(data)
    off = 12 + len(recipients) * IDENTITY_RECIPIENT + len(developers) * IDENTITY_DEVELOPER
    out: dict[tuple[bytes, bytes], int] = {}
    for i in range(off, len(data), stride):
        if has_dev:
            dev_pub = data[i : i + 32]
            project = data[i + 32 : i + 48]
            serial = struct.unpack(">Q", data[i + 48 : i + 56])[0]
        else:
            dev_pub = ZERO32
            project = data[i : i + 16]
            serial = struct.unpack(">Q", data[i + 16 : i + 24])[0]
        out[(project, dev_pub)] = serial
    return out


def set_minimum(existing: bytes, project: str, serial: int, developer_pub: bytes = ZERO32,
                allow_downgrade: bool = False) -> bytes:
    """Refuse, from now on, packages of project with a serial lower than serial. developer_pub binds
    the minimum to a developer's primary key (ENV-AUD-14); all-zero leaves it unbound. Lowering an
    existing minimum needs allow_downgrade (ENV-09: the anti-rollback bar is not rolled back by
    accident, e.g. from a tampered or older package)."""
    if not 0 <= serial < 2**64:
        raise ValueError("Invalid serial")
    if len(developer_pub) != 32:
        raise ValueError("Invalid developer key")
    recipients, developers = parse_identity_store(existing)
    minimums = identity_minimums(existing)
    key = (uuid.UUID(project).bytes, developer_pub)   # per (project, developer), not project alone
    current = minimums.get(key)
    if current is not None and serial < current and not allow_downgrade:
        raise ValueError(
            f"refusing to lower the minimum for this project ({current} -> {serial}); "
            "pass --allow-downgrade to do it on purpose"
        )
    minimums[key] = serial
    return build_identity_store(recipients, developers, minimums)


def identity_signers(data: bytes) -> list[bytes]:
    """Trusted signing public keys in an identity store: each developer's primary key and, when
    present, its recovery key. Whose header to trust is decided here, never by the package (ENV-09)."""
    _recipients, developers = parse_identity_store(data)
    signers: list[bytes] = []
    for d in developers:
        signers.append(d[:32])
        if d[32:64] != ZERO32:
            signers.append(d[32:64])
    return signers


def verified_header_and_signer(blob: bytes, signers: list[bytes]) -> tuple[dict, bytes]:
    """Like verified_header but also returns the trusted signer key that verified the signature."""
    if not blob.startswith(STUB) or len(blob) < len(STUB) + HEADER.size + TAG_SIZE + SIGNATURE_SIZE:
        raise ValueError("Invalid protected file")
    signed, signature = blob[:-SIGNATURE_SIZE], blob[-SIGNATURE_SIZE:]
    for signer in signers:
        try:
            Ed25519PublicKey.from_public_bytes(signer).verify(signature, signed)
            return parse_package(blob), signer
        except InvalidSignature:
            continue
    raise ValueError("no trusted developer in the identity file signed this package")


def verified_header(blob: bytes, signers: list[bytes]) -> dict:
    """Verify a protected file's Ed25519 signature against the trusted signers and return its
    layout-checked header. project and serial then come from this SIGNED region, so a tampered
    envelock-package.json cannot influence what minimum is set (ENV-09)."""
    return verified_header_and_signer(blob, signers)[0]


def developer_primary_for_signer(existing: bytes, signer: bytes) -> bytes:
    """Primary signing key of the developer whose primary OR recovery key is signer. Used to bind a
    minimum to the developer that set it (ENV-AUD-14). Returns all-zero if not found (unbound)."""
    _recipients, developers = parse_identity_store(existing)
    for d in developers:
        if d[:32] == signer or (d[32:64] != ZERO32 and d[32:64] == signer):
            return d[:32]
    return ZERO32


def first_protected_file(package_dir: Path) -> bytes:
    """Bytes of a protected file in the package folder (any one: all files of a pack share project,
    release and serial). Used to read the signed project/serial for 'minimum set' (ENV-09)."""
    if not package_dir.is_dir():
        raise ValueError("The package path is not a folder")
    for path in sorted(package_dir.rglob("*")):
        if path.is_file() and not path.is_symlink():
            try:
                with path.open("rb") as handle:
                    head = handle.read(len(STUB))
            except OSError:
                continue
            if head == STUB:
                return bounded_read(path, MAX_SOURCE + 8 * 1024 * 1024)
    raise ValueError("No protected file found in the package folder")


def identity_bytes(identity: dict) -> bytes:
    """One-project identity bundle (convenience). SECRET."""
    return identity_bundle_bytes([identity])


def server_install_identities(recipient_paths: list[Path], owner_path: Path) -> bytes:
    """Build the identity bundle `server-install` writes. SECRET.

    Split out from the command so the bundle itself is testable without root, which the command
    is not: the point of the subcommand is the ownership and the mode it leaves behind.
    """
    owner = read_config(owner_path, "envelock-owner")
    return identity_bundle_bytes(
        [make_identity(read_config(path, "envelock-recipient"), owner) for path in recipient_paths]
    )


def server_install(data: bytes, out: Path, owner_uid: int = 0, owner_gid: int = 0,
                   mode: int = 0o400) -> None:
    """Write the SECRET identity file the way a server should hold it (objective O5).

    Mode 0400 and root ownership, verified afterwards rather than assumed. That combination is
    what makes the PHP-FPM layout safe: the master starts as root and reads the file at startup,
    then forks workers that drop to the pool user — and a pool user cannot read a root-owned 0400
    file at all, so the private keys never become reachable from the user the application runs as.

    Refuses to run as a non-root user instead of quietly writing a file that only looks installed:
    a 0400 file owned by whoever ran the command would still be readable by that user, and by any
    process sharing it, which is exactly the exposure this exists to remove.

    On Windows there is no root or mode: owner_uid/owner_gid are ignored and the file gets a
    protected access list at creation (see _server_install_windows).
    """
    # The destination check comes first and needs no privilege: pointing the command at an
    # identity that is already installed is an operator mistake, and reporting it should not
    # require being root first.
    if out.exists():
        raise ValueError(
            f"{out} already exists; it is not overwritten. Remove it first if you mean to replace "
            "it — an identity file is not something to clobber by accident."
        )
    if os.name != "nt":
        euid = os.geteuid()
        # Root installs the file owned by anyone (the usual root:root 0400 layout). A non-root
        # operator may install it ONLY for themselves (a documented rootless deploy, e.g. a per-user
        # service): the file still ends up 0400 and owned by the intended user, and the 0077 check
        # below proves no group/other can read it. Installing a non-root-owned file as someone else
        # needs root to chown, so it is refused rather than written with the wrong owner (ENV-2026-20).
        if euid != 0 and owner_uid != euid:
            raise ValueError(
                "server-install must run as root, or install the identity for the current user "
                "(--owner-user <you>). As written it would end up owned by the wrong user or with "
                "permissions that expose the keys. Nothing was written."
            )
    out.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        _server_install_windows(data, out)
        return
    # Created with the final mode, not created then chmod'd: there is no window in which the
    # private keys sit in a file other users can open. O_NOFOLLOW and every later step on the OPEN
    # descriptor (fchown/fchmod/fstat): a path-based chown after close followed a symlink the target
    # user could swap in, and got root to chown a file of its choosing (ENC-2).
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_CLOEXEC", 0))
    fd = os.open(out, flags, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fchown(handle.fileno(), owner_uid, owner_gid)
            os.fchmod(handle.fileno(), mode)     # chown can clear setuid bits; re-assert the mode
            os.fsync(handle.fileno())
            # Verify rather than trust: a umask, a chown that did not take, or a filesystem that
            # ignores mode bits would otherwise pass silently and the keys would be exposed.
            info = os.fstat(handle.fileno())
        if info.st_uid != owner_uid or info.st_gid != owner_gid:
            raise ValueError(
                f"{out} ended up owned by uid {info.st_uid}:{info.st_gid}, not "
                f"{owner_uid}:{owner_gid}; removed it rather than leave the keys exposed."
            )
        if info.st_mode & 0o077:
            raise ValueError(
                f"{out} ended up with group or other permissions ({oct(info.st_mode & 0o777)}); "
                "removed it rather than leave the keys exposed."
            )
    except BaseException:
        out.unlink(missing_ok=True)      # never leave a half-written secret behind
        raise


def _unlink_secret(path: Path) -> None:
    """Delete path even when it carries the Windows read-only attribute (os.unlink refuses such a
    file with WinError 5, which used to leave a half-installed identity behind, ENC-1)."""
    try:
        if os.name == "nt":
            os.chmod(path, stat.S_IREAD | stat.S_IWRITE)   # clears FILE_ATTRIBUTE_READONLY
        path.unlink()
    except FileNotFoundError:
        pass


def _server_install_windows(data: bytes, out: Path) -> None:
    """Windows half of server_install (ENC-1). Mode bits do not exist there: the file is created
    ALREADY carrying a protected access list (SYSTEM, Administrators, the installing user) and the
    read-only attribute, never readable through the folder's inherited entries, and the access list
    is read back from the open handle and verified before the command reports success. Any failure
    removes the file (clearing read-only first)."""
    import msvcrt  # type: ignore[import-not-found]

    fd = _windows_create_new(out, _windows_secret_sddl(), readonly=True)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            problem = _windows_dacl_problem(msvcrt.get_osfhandle(handle.fileno()),
                                            {_current_user_sid_string(), "S-1-5-18", "S-1-5-32-544"})
            sddl = _windows_security_sddl(handle=msvcrt.get_osfhandle(handle.fileno()))
        if problem is None and "P" not in _parse_sddl_dacl(sddl)[0]:
            problem = "its access list inherits entries from the folder"
        if problem:
            raise ValueError(f"{out}: {problem}; removed it rather than leave the keys exposed.")
    except BaseException:
        _unlink_secret(out)
        raise


def add_recipient_to_store(existing: bytes | None, recipient: dict, owner: dict) -> bytes:
    """Create or extend a server identity (trust store) with one recipient + its developer."""
    validate_config(recipient, "envelock-recipient")
    validate_config(owner, "envelock-owner")
    recipients, developers = parse_identity_store(existing) if existing else ([], [])
    minimums = identity_minimums(existing) if existing else {}
    entry = bytes.fromhex(recipient["x25519_private"]) + bytes.fromhex(recipient["x25519_public"])
    pub = bytes.fromhex(recipient["x25519_public"])
    if not any(r[32:64] == pub for r in recipients):
        recipients.append(entry)
    primary = bytes.fromhex(owner["signing_public"])
    recovery = bytes.fromhex(owner["recovery_public"]) if owner.get("recovery_public") else ZERO32
    for index, dev in enumerate(developers):
        if dev[:32] == primary:
            if dev[32:64] == ZERO32 and recovery != ZERO32:
                # Fill in a recovery key that was missing, instead of silently dropping it.
                developers[index] = primary + recovery
            elif dev[32:64] != recovery:
                raise ValueError(
                    "The identity file trusts a different recovery key for this developer; "
                    "use 'developer set' to change it explicitly"
                )
            break
    else:
        developers.append(primary + recovery)
    return build_identity_store(recipients, developers, minimums)


def set_developer(existing: bytes, developer: dict, remove_recovery: bool = False) -> bytes:
    """Add a trusted developer to the identity file, or update the recovery key of an existing
    one (same primary key). Dropping an existing recovery key requires remove_recovery."""
    validate_config(developer, "envelock-developer-public")
    recipients, developers = parse_identity_store(existing)
    primary = bytes.fromhex(developer["signing_public"])
    recovery = bytes.fromhex(developer["recovery_public"]) if developer.get("recovery_public") else ZERO32
    for index, dev in enumerate(developers):
        if dev[:32] == primary:
            if recovery == ZERO32 and dev[32:64] != ZERO32 and not remove_recovery:
                raise ValueError(
                    "The descriptor has no recovery key but the identity file trusts one; "
                    "pass --remove-recovery to drop it"
                )
            developers[index] = primary + recovery
            break
    else:
        developers.append(primary + recovery)
    return build_identity_store(recipients, developers, identity_minimums(existing))


def remove_recipient(existing: bytes, x25519_public: str) -> bytes:
    """Remove a recipient (e.g. its private key was exposed) by its X25519 public key."""
    recipients, developers = parse_identity_store(existing)
    kept = [r for r in recipients if r[32:64].hex() != x25519_public.lower()]
    if len(kept) == len(recipients):
        raise ValueError("That recipient is not in the identity file")
    if not kept:
        raise ValueError("Refusing to remove the last recipient (nothing could be decrypted)")
    return build_identity_store(kept, developers, identity_minimums(existing))


def describe_developers(data: bytes) -> list[str]:
    """One line per trusted developer: developer_id and recovery public key (public data)."""
    return [
        f"{developer_id(d[:32].hex())}  recovery: {d[32:].hex() if d[32:] != ZERO32 else 'none'}"
        for d in parse_identity_store(data)[1]
    ]


def remove_developer(existing: bytes, developer: str) -> bytes:
    """Remove a trusted developer by developer_id (e.g. after its primary key was stolen)."""
    recipients, developers = parse_identity_store(existing)
    kept = [d for d in developers if developer_id(d[:32].hex()) != developer.lower()]
    if len(kept) == len(developers):
        raise ValueError("That developer_id is not in the identity file")
    if not kept:
        raise ValueError("Refusing to remove the last trusted developer (nothing would run)")
    # Drop the removed developer's per-project minimums too, so they do not sit as orphans forever
    # consuming MAX_MINIMUMS slots (ENV-2026-33). Minimums are keyed by (project, developer_pub).
    removed_pubs = {d[:32] for d in developers if developer_id(d[:32].hex()) == developer.lower()}
    minimums = {(proj, pub): serial
                for (proj, pub), serial in identity_minimums(existing).items()
                if pub not in removed_pubs}
    return build_identity_store(recipients, kept, minimums)


def write_store(path: Path, data: bytes) -> None:
    """Atomic replace, so updating an identity file cannot leave it half-written."""
    tmp = path.parent / (path.name + ".tmp-" + secrets.token_hex(4))
    try:
        secret_write(tmp, data, like=path)
        replace_file(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def inspect_path(path: Path) -> dict:
    """Return non-secret metadata of a protected package, an identity store or a config.

    Never reveals private keys; encrypted configs are reported without decrypting them.
    """
    data = bounded_read(path, MAX_SOURCE + 8 * 1024 * 1024)
    stub = len(STUB)
    if data[:stub] == STUB:
        package = parse_package(data)
        table = package["table"]
        return {
            "kind": "envelock-package",
            "format": FORMAT_VERSION,
            "project_id": str(uuid.UUID(bytes=package["project"])),
            "release_id": str(uuid.UUID(bytes=package["release"])),
            "serial": package["serial"],
            "path": package["path"],
            "include_protection": bool(package["flags"] & FLAG_INCLUDE_PROTECTION),
            "no_prepend": bool(package["flags"] & FLAG_NO_PREPEND),
            "no_ffi": bool(package["flags"] & FLAG_NO_FFI),
            "sealed": bool(package["flags"] & FLAG_SEALED),
            "enforce_manifest": bool(package["flags"] & FLAG_ENFORCE_MANIFEST),
            "vault": bool(package["flags"] & FLAG_VAULT),
            "recipient_count": package["count"],
            "recipients": [table[i * RECIPIENT_SIZE : i * RECIPIENT_SIZE + 32].hex()
                           for i in range(package["count"])],
            "source_bytes": package["size"],
        }
    if data[:8] in (IDENTITY_MAGIC, IDENTITY_MAGIC_V2):
        recipients, developers = parse_identity_store(data)
        return {
            "kind": "envelock-identity-store",
            "recipients": [r[32:64].hex() for r in recipients],
            "developers": [
                {
                    "developer_id": developer_id(d[:32].hex()),
                    "signing_public": d[:32].hex(),
                    "has_recovery": d[32:64] != ZERO32,
                    "recovery_public": d[32:64].hex() if d[32:64] != ZERO32 else None,
                }
                for d in developers
            ],
            "minimum_serials": [
                {
                    "project": str(uuid.UUID(bytes=project)),
                    "serial": serial,
                    "developer_id": developer_id(dev_pub.hex()) if dev_pub != ZERO32 else None,
                }
                for (project, dev_pub), serial in sorted(identity_minimums(data).items())
            ],
        }
    # Not a protected package or an identity store: the only remaining kind is a JSON config.
    # Any non-JSON input (binary, wrong encoding) becomes a clean error, never a raw
    # UnicodeDecodeError/JSONDecodeError traceback (ENV-18: inspect validates its input).
    try:
        obj = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("Unrecognized file: not an Envelock package, identity file or "
                         "configuration") from error
    if not isinstance(obj, dict):
        raise ValueError("Unrecognized configuration")
    kind = obj.get("kind")
    if kind == "envelock-encrypted":
        return {"kind": "envelock-encrypted", "note": "encrypted; not inspected without a password"}
    if kind in ("envelock-owner", "envelock-developer-public"):
        pub = obj.get("signing_public")
        try:
            if not isinstance(pub, str) or len(bytes.fromhex(pub)) != 32:
                raise ValueError
        except ValueError:
            raise ValueError(f"Malformed {kind}: 'signing_public' must be 32 bytes of hex") from None
        return {
            "kind": kind,
            "signing_public": pub,
            "developer_id": developer_id(pub),
            "has_recovery": "recovery_public" in obj,
        }
    if kind in ("envelock-recipient", "envelock-recipient-public"):
        return {"kind": kind, "label": obj.get("label", ""), "x25519_public": obj.get("x25519_public")}
    if kind == "envelock-identity":
        # The identity descriptor (make_identity). Show only PUBLIC material and the developer id,
        # never x25519_private (ENV-2026-19).
        pub = obj.get("signing_public")
        return {
            "kind": "envelock-identity",
            "signing_public": pub,
            "x25519_public": obj.get("x25519_public"),
            "developer_id": developer_id(pub) if isinstance(pub, str) else None,
            "has_recovery": obj.get("recovery_public") is not None,
        }
    raise ValueError("Unrecognized configuration")


MANIFEST_MAX_FILE = 64 * 1024 * 1024    # a manifest for a very large tree is still well under this


def manifest_signed_bytes(body: dict) -> bytes:
    """Canonical bytes of a manifest body (without its signature) for signing/verifying."""
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_manifest(root: Path, project_id: bytes, release_id: bytes, serial: int,
                   signer: Ed25519PrivateKey) -> bytes:
    """A signed inventory of every file under root (path -> SHA-256), for `verify` (C8). Detects a
    deleted, added, modified or swapped file after deployment. Signed with the owner's key; checked
    with the matching public descriptor. Not a runtime loader check."""
    files = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            files[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    body = {
        "kind": "envelock-manifest",
        "format": FORMAT_VERSION,
        "project_id": str(uuid.UUID(bytes=project_id)),
        "release_id": str(uuid.UUID(bytes=release_id)),
        "serial": serial,
        "files": files,
    }
    body["signature"] = signer.sign(manifest_signed_bytes(body)).hex()
    return (json.dumps(body, indent=2) + "\n").encode("utf-8")


# Binary, loader-readable manifest for runtime enforcement (ENV-09b / C8 runtime). A fixed layout
# the C loader can parse without a JSON library: it verifies the Ed25519 signature over everything
# but the trailing 64 bytes, then checks every listed path still exists under the package folder
# (deletion detection at run time). Content tampering of protected files is already caught by the
# per-file GCM tag, so the loader does not re-hash; the SHA-256 is carried for completeness and for
# the operator `verify` flow.
MANIFEST_BIN_NAME = "envelock-manifest.bin"
MANIFEST_BIN_MAGIC = b"ENVLKMAN"


def build_manifest_bin(root: Path, project_id: bytes, release_id: bytes, serial: int,
                       signer: Ed25519PrivateKey) -> bytes:
    """Signed binary inventory of every file under root (relative path | SHA-256), for the loader's
    runtime check (pack --enforce-manifest). Signed with the owner's key over all but the trailing
    signature; the loader trusts it against the same developers it already trusts for the files."""
    entries = []
    for p in sorted(root.rglob("*")):
        if p.is_file():
            rel = p.relative_to(root).as_posix().encode("utf-8")
            if len(rel) > MAX_PATH:
                raise ValueError("A packaged path is too long for the manifest")
            entries.append((rel, hashlib.sha256(p.read_bytes()).digest()))
    body = (MANIFEST_BIN_MAGIC + bytes([FORMAT_VERSION, 0]) + project_id + release_id
            + struct.pack(">QI", serial, len(entries)))
    body += b"".join(struct.pack(">H", len(rel)) + rel + digest for rel, digest in entries)
    return body + signer.sign(body)


def verify_package(package_dir: Path, signing_public_hex: str) -> dict:
    """Check a deployed package against its signed manifest. Raises ValueError if the manifest is
    missing/invalid or its signature does not verify with signing_public_hex; otherwise returns a
    report whose 'ok' is True only when every file is present and unchanged and none were added."""
    manifest_path = package_dir / "envelock-manifest"
    if not manifest_path.is_file():
        if (package_dir / MANIFEST_BIN_NAME).is_file():
            raise ValueError(
                "This package has only the runtime binary manifest (envelock-manifest.bin); "
                "re-pack with --manifest to use 'verify' (the loader still enforces the binary one)")
        raise ValueError("No signed manifest found (pack with --manifest to create one)")
    raw = bounded_read(manifest_path, MANIFEST_MAX_FILE)
    body = json.loads(raw)
    if not isinstance(body, dict) or body.get("kind") != "envelock-manifest":
        raise ValueError("Not an Envelock manifest")
    if "signature" not in body or not isinstance(body.get("files"), dict):
        raise ValueError("Malformed manifest")
    signature = bytes.fromhex(body.pop("signature"))
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(signing_public_hex)).verify(
            signature, manifest_signed_bytes(body))
    except InvalidSignature:
        raise ValueError("The manifest signature does not verify with that developer/owner key")
    expected = body["files"]
    actual = {}
    # Walk WITHOUT following symlinks and classify every entry with lstat, so an added broken symlink,
    # FIFO, socket or device node is reported as "added" instead of being silently skipped by a
    # plain is_file() check (ENV-2026-19). A folder that cannot be read is an error, not an empty
    # folder, and a symlinked or junction FOLDER is itself an added entry (os.walk lists it among
    # the folders and, for a symlink, never reports it; for a junction it walked into the target):
    # both used to leave `ok` true with content added (ENC-8).
    def walk_error(error: OSError) -> None:
        raise ValueError(f"cannot read {error.filename} while verifying ({error.strerror}); "
                         "the package cannot be checked") from error

    for dirpath, dirnames, filenames in os.walk(package_dir, onerror=walk_error, followlinks=False):
        for name in list(dirnames):
            p = Path(dirpath) / name
            try:
                linked = _is_link_or_reparse(os.lstat(p))
            except OSError as error:
                walk_error(error)
            if linked:
                actual[p.relative_to(package_dir).as_posix()] = "non-regular"
                dirnames.remove(name)            # never walk through it
        for name in filenames:
            p = Path(dirpath) / name
            if p.parent == package_dir and name == "envelock-manifest":
                continue
            rel = p.relative_to(package_dir).as_posix()
            try:
                st = os.lstat(p)
            except OSError:
                actual[rel] = "unreadable"       # present but unstattable -> never matches a hash
                continue
            if not stat.S_ISREG(st.st_mode):     # symlink / FIFO / socket / device: not a plain file
                actual[rel] = "non-regular"      # never equals an expected hash -> changed/added
                continue
            try:                                 # bounded_read refuses symlinks/FIFOs and caps size
                actual[rel] = hashlib.sha256(bounded_read(p, MANIFEST_MAX_FILE)).hexdigest()
            except ValueError:
                actual[rel] = "unreadable"
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    changed = sorted(k for k in expected if k in actual and actual[k] != expected[k])
    return {
        "ok": not (missing or extra or changed),
        "project_id": body["project_id"], "release_id": body["release_id"], "serial": body["serial"],
        "files": len(expected), "missing": missing, "added": extra, "changed": changed,
    }


def kem_info(project_id: bytes, release_id: bytes, ephemeral_pub: bytes, recipient_pub: bytes) -> bytes:
    return (
        KEM_DOMAIN
        + bytes([FORMAT_VERSION])
        + project_id
        + release_id
        + ephemeral_pub
        + recipient_pub
    )


def wrap_for_recipient(
    recipient_pub: bytes, content_key: bytes, project_id: bytes, release_id: bytes
) -> bytes:
    """One recipient-table entry: recipient_pub | ephemeral_pub | wrap_nonce | wrapped_key."""
    ephemeral = X25519PrivateKey.generate()
    ephemeral_pub = raw_x_public(ephemeral.public_key())
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_pub))
    info = kem_info(project_id, release_id, ephemeral_pub, recipient_pub)
    wrap_key = HKDF(algorithm=SHA256(), length=32, salt=b"", info=info).derive(shared)
    nonce = secrets.token_bytes(12)
    wrapped = AESGCM(wrap_key).encrypt(nonce, content_key, info)
    entry = recipient_pub + ephemeral_pub + nonce + wrapped
    if len(entry) != RECIPIENT_SIZE:
        raise ValueError("Incorrect recipient entry size")
    return entry


def build_table(
    recipient_pubs: list[bytes], content_key: bytes, project_id: bytes, release_id: bytes
) -> bytes:
    if not 1 <= len(recipient_pubs) <= MAX_RECIPIENTS:
        raise ValueError("Recipient count out of range")
    if len(set(recipient_pubs)) != len(recipient_pubs):
        raise ValueError("Duplicate recipient")
    return b"".join(
        wrap_for_recipient(pub, content_key, project_id, release_id) for pub in recipient_pubs
    )


def parse_package(data: bytes) -> dict:
    """Parse and validate the layout of a protected file (not its signature)."""
    stub, fixed = len(STUB), len(STUB) + HEADER.size
    if not data.startswith(STUB) or len(data) < fixed:
        raise ValueError("Invalid protected package")
    magic, version, flags, path_length, project, release, count, nonce, size, serial = HEADER.unpack(
        data[stub:fixed]
    )
    if magic != MAGIC or version != FORMAT_VERSION:
        raise ValueError("Incorrect format or version (anti-downgrade)")
    if flags & ~FLAGS_KNOWN or not 1 <= path_length <= MAX_PATH or not 1 <= count <= MAX_RECIPIENTS \
            or size > MAX_SOURCE:
        raise ValueError("Invalid header")
    table_start = fixed + path_length
    ciphertext = table_start + count * RECIPIENT_SIZE
    if len(data) != ciphertext + size + TAG_SIZE + SIGNATURE_SIZE:
        raise ValueError("Truncated or inconsistent package")
    try:                                             # M-05: a clear error, not a raw UnicodeDecodeError
        path = data[fixed:table_start].decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("The packaged path is not valid UTF-8 (corrupt package)") from error
    if not path or any(part in ("", ".", "..") for part in path.split("/")) or path.startswith("/"):
        raise ValueError("The packaged path is not a clean relative path (corrupt package)")
    return {"flags": flags, "project": project, "release": release, "count": count, "nonce": nonce,
            "size": size, "serial": serial, "path": path,
            "table": data[table_start:ciphertext], "aad": data[:ciphertext]}


def protect(
    source: bytes,
    signer: Ed25519PrivateKey,
    project_id: bytes,
    release_id: bytes,
    content_key: bytes,
    table: bytes,
    file_nonce: bytes | None = None,
    *,
    path: str,
    flags: int = 0,
    serial: int = 0,
) -> bytes:
    """path: the file's relative path inside the package ('/'-separated); the loader only runs
    the file from a location ending in that path. flags: FLAG_*; serial: release number checked
    against the minimum set in the server's identity file."""
    if len(source) > MAX_SOURCE:
        raise ValueError("PHP file larger than 16 MiB")
    if source.startswith(STUB):
        raise ValueError("Source is already protected")
    if len(table) % RECIPIENT_SIZE or not table:
        raise ValueError("Invalid recipient table")
    count = len(table) // RECIPIENT_SIZE
    if count > MAX_RECIPIENTS:
        raise ValueError("Too many recipients")
    nonce = secrets.token_bytes(12) if file_nonce is None else file_nonce
    if len(nonce) != 12:
        raise ValueError("Incorrect file nonce")
    encoded_path = path.encode("utf-8")
    if (not 1 <= len(encoded_path) <= MAX_PATH or path.startswith("/") or "\\" in path
            or any(part in ("", ".", "..") for part in path.split("/"))):
        raise ValueError(f"Invalid relative path: {path!r}")
    if flags & ~FLAGS_KNOWN or not 0 <= serial < 2**64:
        raise ValueError("Invalid flags or serial")
    header = HEADER.pack(MAGIC, FORMAT_VERSION, flags, len(encoded_path), project_id, release_id,
                         count, nonce, len(source), serial)
    aad = STUB + header + encoded_path + table
    signed = aad + AESGCM(content_key).encrypt(nonce, source, aad)
    return signed + signer.sign(signed)


def open_protected(blob: bytes, identity) -> bytes:
    """Reference decoder for tests ONLY. Mirrors the loader; not exposed by the CLI.

    `identity` is one envelock-identity dict or a list of them (a host trust store).
    Trust is per-installation and global: the package verifies against ANY trusted
    signer (each developer's primary or recovery key) and is decrypted with whichever
    recipient key it is addressed to. The trusted signers come from the identity, never
    from the package.
    """
    identities = identity if isinstance(identity, list) else [identity]
    recipients: list[tuple[bytes, bytes]] = []
    signers: list[bytes] = []
    for one in identities:
        validate_config(one, "envelock-identity")
        recipients.append(
            (bytes.fromhex(one["x25519_private"]), bytes.fromhex(one["x25519_public"]))
        )
        signers.append(bytes.fromhex(one["signing_public"]))
        if one.get("recovery_public"):
            signers.append(bytes.fromhex(one["recovery_public"]))
    return _open_protected(blob, recipients, signers)


def _open_protected(blob: bytes, recipients: list, signers: list) -> bytes:
    if not blob.startswith(STUB) or len(blob) < len(STUB) + HEADER.size + TAG_SIZE + SIGNATURE_SIZE:
        raise ValueError("Invalid format")
    signed, signature = blob[:-SIGNATURE_SIZE], blob[-SIGNATURE_SIZE:]
    for signer in signers:
        try:
            Ed25519PublicKey.from_public_bytes(signer).verify(signature, signed)
            break
        except InvalidSignature:
            continue
    else:
        raise InvalidSignature("No trusted signer validates the package")
    package = parse_package(blob)
    table, count = package["table"], package["count"]
    for priv_bytes, own_pub in recipients:
        priv = X25519PrivateKey.from_private_bytes(priv_bytes)
        if raw_x_public(priv.public_key()) != own_pub:
            continue  # inconsistent recipient: skip it and try the next, like the loader
        for i in range(count):
            entry = table[i * RECIPIENT_SIZE : (i + 1) * RECIPIENT_SIZE]
            if entry[:32] == own_pub:
                ephemeral_pub, wrap_nonce, wrapped = entry[32:64], entry[64:76], entry[76:124]
                shared = priv.exchange(X25519PublicKey.from_public_bytes(ephemeral_pub))
                info = kem_info(package["project"], package["release"], ephemeral_pub, own_pub)
                wrap_key = HKDF(algorithm=SHA256(), length=32, salt=b"", info=info).derive(shared)
                content_key = AESGCM(wrap_key).decrypt(wrap_nonce, wrapped, info)
                ciphertext = blob[len(package["aad"]) : -SIGNATURE_SIZE]
                return AESGCM(content_key).decrypt(package["nonce"], ciphertext, package["aad"])
    raise ValueError("The package is not addressed to any identity")


def forbidden(path: Path) -> bool:
    return any(p.casefold() in DENIED_PARTS or p.casefold().startswith(".env") for p in path.parts)


def validate_portable_path(path: Path) -> str:
    for part in path.parts:
        if (
            part.rstrip(" .") != part
            or any(c in part for c in '<>:"\\|?*')
            or any(ord(c) < 32 for c in part)              # control characters (ENC-25)
            or part.split(".")[0].rstrip(" ").casefold() in WINDOWS_RESERVED
        ):
            raise ValueError(f"Path not portable to Windows: {path.as_posix()}")
    return unicodedata.normalize("NFC", path.as_posix()).casefold()


def _claim_portable_name(canonical: str, files: set[str], folders: set[str]) -> bool:
    """Record a packed file by its canonical (validate_portable_path) name. True when it collides on
    a case-insensitive file system with an earlier packed file, or with a FOLDER holding one: "Lib"
    next to "lib/x.php" cannot both exist on Windows or macOS (ENC-25)."""
    parents = ["/".join(canonical.split("/")[:i]) for i in range(1, canonical.count("/") + 1)]
    clash = canonical in files or canonical in folders or any(p in files for p in parents)
    files.add(canonical)
    folders.update(parents)
    return clash


def _pattern_matches(name: str, patterns: list[str] | None) -> bool:
    """--exclude / --asset matching on a '/'-separated relative name (ENC-10). A pattern written
    with Windows separators (lib\\*) is normalised to '/', and on Windows, whose file names are
    case-insensitive, the match is too: LIB/* used to match nothing and an excluded folder shipped."""
    for pattern in patterns or []:
        pattern = pattern.replace("\\", "/")
        if os.name == "nt":
            if fnmatch.fnmatchcase(name.casefold(), pattern.casefold()):
                return True
        elif fnmatch.fnmatchcase(name, pattern):
            return True
    return False


def _is_link_or_reparse(st: os.stat_result) -> bool:
    """An lstat() result for a symlink, or for any Windows reparse point (junction, mount point,
    symlink): something a walk must never descend through."""
    return stat.S_ISLNK(st.st_mode) or bool(
        getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _source_entries(source: Path, skip) -> list[Path]:
    """Every entry under source that skip(relative_path) does not exclude, sorted like rglob.

    Pruned walk (ENC-25): an excluded folder is never entered (pnpm's links inside node_modules,
    or a junction loop there, used to be followed by rglob before the filter ran), and no link,
    junction or other reparse point is ever descended into, so a looping junction cannot make the
    walk explode. Such an entry is still RETURNED, so pack_tree refuses it as before."""
    found: list[Path] = []
    stack = [source]
    while stack:
        with os.scandir(stack.pop()) as entries:
            for entry in entries:
                item = Path(entry.path)
                if skip(item.relative_to(source)):
                    continue
                found.append(item)
                if (entry.is_dir(follow_symlinks=False) and not item.is_symlink()
                        and not _is_link_or_reparse(entry.stat(follow_symlinks=False))):
                    stack.append(item)
    return sorted(found)


SECRET_NAMES = ("identity*.bin", "owner*.json", "recipient*.json", "credentials.json",
                # Credential stores under another name (ENC-15); the dot-file forms are DENIED_PARTS.
                "pgpass.conf", "*.npmrc", "*.netrc", "*.git-credentials", "*.pgpass")
# Field names searched without quotes (also in .ini/.env-like files), on the decoded text.
SECRET_MARKERS = ("PRIVATE KEY-----", "signing_private", "x25519_private", "recovery_private",
                  "wrapping_key")


# Other PHP source extensions that must never be copied in clear as an asset (ENV-12). .phar is a
# PHP archive whose compressed bytes do not contain a literal "<?php".
PHP_ASSET_EXTENSIONS = (".php3", ".php4", ".php5", ".php7", ".phps", ".pht", ".phar", ".ctp")
# Local databases and developer credentials that should not ship inside a package (ENV-12).
SENSITIVE_ENDINGS = (".pem", ".key", ".p12", ".pfx", ".ppk", ".bak", ".old", ".orig", ".swp", "~",
                     ".sqlite", ".sqlite3", ".db", ".sql", ".htpasswd")


# Config-like asset extensions whose CONTENT is scanned for credential keys. Assets are copied in
# the clear (the loader protects PHP only), so a config holding a password/token would be exposed.
SECRET_ASSET_EXTENSIONS = (".json", ".env", ".ini", ".yaml", ".yml", ".xml", ".conf", ".cfg",
                           ".config", ".properties", ".toml", ".cnf", ".txt")
# Match a credential key, allowing an underscore/hyphen-joined prefix (DB_PASSWORD, AWS_SECRET...)
# but requiring a word boundary after the keyword so "tokenizer=" or "tokens=" do not match.
SECRET_CONTENT_RE = re.compile(
    r"(?i)(?:^|[^a-z0-9_])(?:[a-z0-9]+[_-])*"
    r"(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|"
    r"client[_-]?secret|aws_secret_access_key|aws_access_key_id|connection[_-]?string|"
    r"database[_-]?url|jwt[_-]?secret|bearer|"
    # npm/yarn registry tokens ("//registry/:_authToken=", "_auth=") and Docker's config.json
    # ("auth": "<base64 user:password>") (ENC-15).
    r"_?auth(?:token)?)"
    r"\b\s*[\"']?\s*[:=]")
# Credential formats without a "key = value" shape (ENC-15): a netrc entry ("machine h login u
# password p", possibly over several lines) and a URL carrying user:password, which is exactly what
# git's credential store holds (https://user:token@host) and what a database URL embeds.
SECRET_FORMATS_RE = re.compile(
    r"(?is)\bmachine\s+\S+\s+(?:login\s+\S+\s+)?password\s+\S"
    r"|\b[a-z][a-z0-9+.-]*://[^\s/:@'\"]+:[^\s/@'\"]+@[^\s/@'\"]")


def validate_asset(path: Path, data: bytes, allow_secret_assets: bool = False) -> None:
    name = path.name.casefold()
    if (
        any(part in DEFAULT_EXTENSIONS for part in Path(name).suffixes)
        or name.endswith(PHP_ASSET_EXTENSIONS)
        or name.endswith(SENSITIVE_ENDINGS)
        or any(fnmatch.fnmatchcase(name, pattern) for pattern in SECRET_NAMES)
    ):
        raise ValueError(f"Potentially private asset: {path.as_posix()}")
    # Secrets are recognised by content too: a renamed identity file or key descriptor must
    # never be copied in clear. Decode like json does (UTF-8/16/32, with or without BOM), so a
    # UTF-16 copy made by Windows PowerShell is caught as well.
    text = data.decode(json.detect_encoding(data), errors="ignore")
    if data[:8] in (IDENTITY_MAGIC, IDENTITY_MAGIC_V2) or any(marker in text for marker in SECRET_MARKERS):
        raise ValueError(f"Asset contains private key material: {path.as_posix()}")
    # PHP tags on the decoded text, not only the raw bytes: a UTF-16 template with <?php is caught,
    # and a short open tag (<? ..., but not <?xml) is readable PHP too (ENV-12).
    lower = text.lower()
    if ("<?php" in lower or "<?=" in lower or re.search(r"<\?(?!php\b|xml\b)", lower)
            or b"<?php" in data.lower() or b"<?=" in data):
        raise ValueError(
            f"Asset contains readable PHP: {path.as_posix()}; use --php-ext or exclude it"
        )
    if len(data) <= 65536 and text.lstrip("\ufeff \t\r\n").startswith("{"):
        try:
            value = json.loads(text.lstrip("\ufeff"))
        except (ValueError, UnicodeError, RecursionError):
            value = None
        if isinstance(value, dict) and str(value.get("kind", "")).startswith("envelock-"):
            raise ValueError(f"Do not distribute private configurations: {path.as_posix()}")
    # Credentials in an asset: assets are NOT encrypted, so a password/token/key would ship in clear.
    # Refuse unless the operator opts in after reviewing it (external audit A4 / ENV-AUD-15). Scanned
    # on EVERY asset's decoded text, not only a fixed extension list: gating on extensions let a
    # secret in a custom name (config.data, settings.conf.local) ship silently (audit NU-05). The
    # text is already decoded above for the marker/PHP checks, so this adds no new I/O; a false
    # positive is cleared with --allow-secret-assets after review.
    if not allow_secret_assets and (SECRET_CONTENT_RE.search(text) or SECRET_FORMATS_RE.search(text)):
        raise ValueError(
            f"Asset looks like it contains credentials: {path.as_posix()}. Assets are NOT encrypted; "
            "keep secrets out of the package (use environment variables or a secret manager), or pass "
            "allow_secret_assets=True / --allow-secret-assets after reviewing the file")


# Runs in the operator's PHP CLI (PHP >= 8.0 with the tokenizer): PHP's own tokenizer is the
# only reliable way to tell comments and variables from strings, heredocs and attributes.
# strip: each comment becomes the same number of newlines (or one space), so line numbers do not
# change. obfuscate: inside each named function or method, local variables get short names;
# parameters (named arguments), properties, $this and superglobals keep theirs, and a function
# that uses names at run time (compact, extract, get_defined_vars, call_user_func(_array), $$, eval,
# include, global) or
# nested scopes (closures, arrow functions, anonymous classes) is left as is. The result must
# still parse.
TRANSFORM_PHP = r"""
if (PHP_VERSION_ID < 80000 || !function_exists("token_get_all")) { fwrite(STDERR, "needs PHP 8+ with tokenizer"); exit(2); }
// This internal, audited program emits only its JSON result; a PHP-version deprecation in it (e.g.
// PHP 8.5 null-array-offset on punctuation token ids) is not actionable by the user and must not be
// raised. Real breakage shows as a fatal (caught) or an output change (caught by the differential fuzzer).
error_reporting(E_ALL & ~E_DEPRECATED);
$in = json_decode(stream_get_contents(STDIN), true, 4, JSON_THROW_ON_ERROR);
// Variables that must keep their name inside a function: $this, superglobals and the local
// that file_get_contents() and friends create by name.
$keep = array_flip(['$this', '$GLOBALS', '$_SERVER', '$_GET', '$_POST', '$_FILES', '$_COOKIE',
    '$_SESSION', '$_REQUEST', '$_ENV', '$http_response_header', '$argc', '$argv']);
// A function using any of these depends on variable names at run time: left as is. Nested
// closures/arrow functions (T_FUNCTION/T_FN) are NOT here: their bodies are obfuscated too, with
// their own parameters collected and kept (see below), so a captured variable is renamed the same
// way in both scopes while every parameter keeps its name (named-argument safety).
$unsafe = array_flip([T_EVAL, T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE,
    T_REQUIRE_ONCE, T_GLOBAL, T_DOLLAR_OPEN_CURLY_BRACES, T_STRING_VARNAME]);
// Functions that read or write the CALLER's local scope by name. A direct call, or a
// call_user_func(_array) call, is detected as a T_STRING token and makes the function unsafe. PHP
// itself forbids calling compact/extract/get_defined_vars through a variable ("cannot be called
// dynamically"), so there is no token-invisible way to reach them that we would miss.
$byName = array_flip(['compact', 'extract', 'get_defined_vars', 'call_user_func', 'call_user_func_array']);
$skip = array_flip([T_WHITESPACE, T_COMMENT, T_DOC_COMMENT]);
$out = []; $halted = [];
foreach ($in["files"] as $name => $b64) {
    $code = base64_decode($b64, true);
    try { $raw = token_get_all($code, TOKEN_PARSE); }
    catch (ParseError $e) { fwrite(STDERR, $name . ": " . $e->getMessage()); exit(3); }
    $t = [];
    foreach ($raw as $x) $t[] = is_array($x) ? [$x[0], $x[1]] : [null, $x];
    $n = count($t);
    $next = function (int $i) use ($t, $n, $skip): int {
        for ($i++; $i < $n && isset($skip[$t[$i][0]]); $i++);
        return $i;
    };
    $prev = function (int $i) use ($t, $skip): int {
        for ($i--; $i >= 0 && isset($skip[$t[$i][0]]); $i--);
        return $i;
    };
    // ENV-2026-14 / ENV-2026-15: the member-renaming passes (methods, properties) work on one class
    // body [$cstart,$cend] at a time, but a NESTED class declared inside it -- named or, typically,
    // an anonymous `new class(...) implements X { ... }` -- is a SEPARATE scope. Its own methods and
    // its own $this->prop belong to it, not to the enclosing class, and must never be renamed with
    // the outer class's maps (doing so corrupts a nested public method, or silently changes a value
    // when $this->x shadows an outer private $x). $nestedRanges returns the [start,end] token ranges
    // of the class bodies nested strictly inside ($cs,$ce); the passes skip any token inside them.
    $nestedRanges = function (int $cs, int $ce) use (&$t, $n, $prev): array {
        $ranges = [];
        for ($k = $cs + 1; $k < $ce; $k++) {
            if ($t[$k][0] !== T_CLASS) continue;
            if ($t[$prev($k)][0] === T_DOUBLE_COLON) continue;   // Foo::class, not a declaration
            // Find this nested class's body brace: the first "{" at paren/bracket depth 0 (so a "{"
            // inside constructor-argument defaults, e.g. a closure, is not mistaken for the body).
            $pdp = 0; $b = $k;
            for (; $b < $ce; $b++) {
                $c = $t[$b][1];
                if ($c === "(" || $c === "[") $pdp++;
                elseif ($c === ")" || $c === "]") $pdp--;
                elseif ($c === "{" && $pdp === 0) break;
                elseif ($c === ";" && $pdp === 0) { $b = $ce; break; }   // no body (defensive)
            }
            if ($b >= $ce) continue;
            $depth = 0;
            for ($e = $b; $e < $n; $e++) {
                $id = $t[$e][0]; $c = $t[$e][1];
                if ($c === "{" || $id === T_CURLY_OPEN || $id === T_DOLLAR_OPEN_CURLY_BRACES) $depth++;
                elseif ($c === "}" && --$depth === 0) break;
            }
            $ranges[] = [$k, $e];
            $k = $e;                                             // inner nesting is covered by this range
        }
        return $ranges;
    };
    $inNested = function (int $idx, array $ranges): bool {
        foreach ($ranges as [$s, $e]) { if ($idx >= $s && $idx <= $e) return true; }
        return false;
    };
    // __halt_compiler() leaves raw data after it that the tokenizer does not return; rebuilding
    // from tokens would drop it. Pass such a file through untouched (ENV-08).
    foreach ($t as [$id, $c]) { if ($id === T_HALT_COMPILER) { $out[$name] = $b64; $halted[$name] = true; continue 2; } }
    // "use function compact as c;" makes c() call compact at run time: track the alias so a
    // function that uses it is left alone, like a direct compact() call (ENV-08).
    $byNameLocal = $byName;
    for ($i = 0; $i + 1 < $n; $i++) {
        if ($t[$i][0] !== T_USE) continue;
        $j = $next($i);
        if ($j >= $n || $t[$j][0] !== T_FUNCTION) continue;           // only "use function ..."
        $last = null;
        for ($j = $next($j); $j < $n && $t[$j][1] !== ";"; $j = $next($j)) {
            $id = $t[$j][0]; $c = $t[$j][1];
            if ($id === T_STRING || $id === T_NAME_QUALIFIED || $id === T_NAME_FULLY_QUALIFIED) {
                $last = strtolower(ltrim(strrchr("\\" . ltrim($c, "\\"), "\\"), "\\"));
            } elseif ($id === T_AS) {
                $j = $next($j);
                if ($j < $n && $t[$j][0] === T_STRING && $last !== null && isset($byName[$last])) {
                    $byNameLocal[strtolower($t[$j][1])] = true;
                }
                $last = null;
            } elseif ($c === ",") {
                $last = null;
            }
        }
    }
    if ($in["obfuscate"]) {
        for ($i = 0; $i < $n; $i++) {
            if ($t[$i][0] !== T_FUNCTION) continue;
            $j = $next($i);
            if ($j < $n && $t[$j][1] === "&") $j = $next($j);
            if ($j >= $n || $t[$j][0] !== T_STRING) continue;            // closure or "use function"
            $j = $next($j);
            if ($j >= $n || $t[$j][1] !== "(") continue;
            $params = [];
            for ($depth = 0; $j < $n; $j++) {                              // parameter list
                $c = $t[$j][1];
                if ($c === "(" || $c === "[" || $t[$j][0] === T_ATTRIBUTE) $depth++;
                elseif ($c === ")" || $c === "]") { if (--$depth === 0) break; }
                elseif ($t[$j][0] === T_VARIABLE) $params[$c] = true;
            }
            for ($j++; $j < $n && $t[$j][1] !== "{" && $t[$j][1] !== ";"; $j++);
            if ($j >= $n || $t[$j][1] === ";") continue;                   // abstract/interface
            $start = $j;
            for ($depth = 0; $j < $n; $j++) {                              // body
                $id = $t[$j][0]; $c = $t[$j][1];
                if ($c === "{" || $id === T_CURLY_OPEN || $id === T_DOLLAR_OPEN_CURLY_BRACES) $depth++;
                elseif ($c === "}" && --$depth === 0) break;
            }
            $end = $j;
            // Parameters of EVERY nested closure/arrow function are kept too (named-argument safety):
            // only the first "(...)" after each function/fn (not its use(...) capture list).
            for ($k = $start + 1; $k < $end; $k++) {
                if ($t[$k][0] !== T_FUNCTION && $t[$k][0] !== T_FN) continue;
                $q = $next($k);
                if ($q < $n && $t[$q][1] === "&") $q = $next($q);
                if ($q < $n && $t[$q][0] === T_STRING) $q = $next($q);   // a name (not expected in a body)
                if ($q >= $n || $t[$q][1] !== "(") continue;
                for ($d2 = 0; $q < $n; $q++) {
                    $cc = $t[$q][1];
                    if ($cc === "(" || $cc === "[" || $t[$q][0] === T_ATTRIBUTE) $d2++;
                    elseif ($cc === ")" || $cc === "]") { if (--$d2 === 0) break; }
                    elseif ($t[$q][0] === T_VARIABLE) $params[$t[$q][1]] = true;
                }
            }
            $safe = true;
            $locals = [];
            for ($k = $start + 1; $k < $end && $safe; $k++) {
                [$id, $c] = $t[$k];
                if (isset($unsafe[$id]) || ($id === null && $c === '$')) $safe = false;
                elseif ($id === T_CLASS && $t[$prev($k)][0] !== T_DOUBLE_COLON) $safe = false; // any class scope (new / new readonly / new #[Attr] / nested), not Foo::class
                elseif (($id === T_STRING || $id === T_NAME_FULLY_QUALIFIED) && isset($byNameLocal[strtolower(ltrim($c, "\\"))])) $safe = false;
                elseif ($id === T_VARIABLE && !isset($keep[$c]) && !isset($params[$c])
                        && !($t[$prev($k)][0] === T_DOUBLE_COLON && $t[$next($k)][1] !== "(")) $locals[$c] = true; // Foo::$static is a property (skip); Foo::$m() uses a local (rename)
            }
            if ($safe && $locals) {
                $map = [];
                $counter = 0;
                foreach (array_keys($locals) as $old) {
                    do {
                        $s = ""; $v = $counter++;
                        do { $s = chr(97 + $v % 26) . $s; $v = intdiv($v, 26) - 1; } while ($v >= 0);
                        $new = '$' . $s;
                    } while (isset($keep[$new]) || isset($params[$new]));
                    $map[$old] = $new;
                }
                for ($k = $start + 1; $k < $end; $k++) {
                    if ($t[$k][0] === T_VARIABLE && isset($map[$t[$k][1]])
                            && !($t[$prev($k)][0] === T_DOUBLE_COLON && $t[$next($k)][1] !== "(")) {
                        $t[$k][1] = $map[$t[$k][1]];
                    }
                }
            }
            $i = $end;
        }
    }
    if ($in["methods"]) {
        // Rename PRIVATE methods of named classes. A private method is callable only from inside its
        // own class (PHP enforces it), so renaming it and its internal call sites cannot affect any
        // other file. We are deliberately conservative: a name is renamed only when EVERY use of it
        // in the whole file is one of {declaration, $this->name(, self::name(, static::name(,
        // <ThisClass>::name(} — a call through any other object/class, a bare identifier, a property
        // or constant access, or the name appearing in a string literal (a possible dynamic callable
        // like [$this,'name'] or a Reflection lookup) disqualifies it. Classes with dynamic member
        // access ($obj->$x, ::$x, ->{...}) or magic methods are skipped whole. Any doubt -> keep the
        // name. Method calls are recognised by the "(" that follows (a property/constant has none),
        // so a property with the same name as a method is never touched.
        for ($ci = 0; $ci < $n; $ci++) {
            if ($t[$ci][0] !== T_CLASS) continue;                       // only `class` (not enum/trait/interface)
            if ($t[$prev($ci)][0] === T_DOUBLE_COLON || $t[$prev($ci)][0] === T_NEW) continue;  // Foo::class / anonymous
            $cn = $next($ci);
            if ($cn >= $n || $t[$cn][0] !== T_STRING) continue;         // must be a named class
            $className = strtolower($t[$cn][1]);
            $j = $cn; $hasParent = false;
            while ($j < $n && $t[$j][1] !== "{" && $t[$j][1] !== ";") {
                if ($t[$j][0] === T_EXTENDS || $t[$j][0] === T_IMPLEMENTS) $hasParent = true;
                $j++;
            }
            if ($j >= $n || $t[$j][1] !== "{") continue;
            // A class that extends/implements something may inherit a FINAL method; renaming a private
            // method to a short name could collide with it ("Cannot override final method"). We cannot
            // see the parent/interface from here, so skip the whole class (ENV-AUD-12). Conservative.
            if ($hasParent) continue;
            $cstart = $j;
            for ($depth = 0; $j < $n; $j++) {
                $id = $t[$j][0]; $c = $t[$j][1];
                if ($c === "{" || $id === T_CURLY_OPEN || $id === T_DOLLAR_OPEN_CURLY_BRACES) $depth++;
                elseif ($c === "}" && --$depth === 0) break;
            }
            $cend = $j;
            // Skip the whole class on any dynamic member access (we cannot see what it targets).
            $skipClass = false;
            for ($k = $cstart + 1; $k < $cend; $k++) {
                $id = $t[$k][0];
                if ($id === T_OBJECT_OPERATOR || $id === T_NULLSAFE_OBJECT_OPERATOR || $id === T_DOUBLE_COLON) {
                    $nx = $next($k);
                    if ($nx < $n && ($t[$nx][0] === T_VARIABLE || $t[$nx][1] === "{" || $t[$nx][0] === T_CURLY_OPEN)) { $skipClass = true; break; }
                } elseif ($id === T_USE && $next($k) < $n && $t[$next($k)][1] !== "(") {
                    // A trait "use" (not a closure "use (...)"): the trait's methods are composed into
                    // this class and may call its private methods, but their bodies live outside this
                    // class's token range, so renaming would leave them dangling. Skip the class (H1).
                    $skipClass = true; break;
                }
            }
            if ($skipClass) continue;
            // Nested class bodies are separate scopes (ENV-2026-14): their methods are not this
            // class's members and their token range is excluded below.
            $nested = $nestedRanges($cstart, $cend);
            // Private method names declared in this class, and ALL method names (to avoid collisions).
            $priv = []; $allMethods = [];
            for ($k = $cstart + 1; $k < $cend; $k++) {
                if ($t[$k][0] !== T_FUNCTION || $inNested($k, $nested)) continue;
                $nm = $next($k); if ($nm < $n && $t[$nm][1] === "&") $nm = $next($nm);
                if ($nm >= $n || $t[$nm][0] !== T_STRING) continue;
                $allMethods[strtolower($t[$nm][1])] = true;
                $isPriv = false; $isPublicOrProtected = false;
                for ($m = $prev($k); $m >= $cstart; $m = $prev($m)) {
                    $mid = $t[$m][0];
                    if ($mid === T_PRIVATE) $isPriv = true;
                    elseif ($mid === T_PUBLIC || $mid === T_PROTECTED) $isPublicOrProtected = true;
                    elseif ($mid === T_STATIC || $mid === T_FINAL || $mid === T_ABSTRACT) continue;
                    else break;
                }
                if ($isPriv && !$isPublicOrProtected && substr($t[$nm][1], 0, 2) !== "__") {
                    $priv[strtolower($t[$nm][1])] = true;
                }
            }
            if (!$priv) continue;
            // Eligibility over the WHOLE file. positions[name] collects token indexes to rename.
            $eligible = $priv; $positions = [];
            foreach (array_keys($priv) as $lm) $positions[$lm] = [];
            for ($k = 0; $k < $n; $k++) {
                if ($inNested($k, $nested)) continue;             // nested-class members are a separate scope
                $id = $t[$k][0]; $c = $t[$k][1];
                if ($id === T_CONSTANT_ENCAPSED_STRING) {
                    $val = eval("return " . $c . ";");
                    if (is_string($val) && isset($eligible[strtolower($val)])) unset($eligible[strtolower($val)]);
                    continue;
                }
                if ($id !== T_STRING) continue;
                $lk = strtolower($c);
                if (!isset($priv[$lk])) continue;
                $p = $prev($k);
                $pid = $t[$p][0];
                if ($pid === T_FUNCTION) { $positions[$lk][] = $k; continue; }   // declaration
                $callLike = ($t[$next($k)][1] === "(");                          // a method call has "("
                if ($pid === T_OBJECT_OPERATOR || $pid === T_NULLSAFE_OBJECT_OPERATOR) {
                    if (!$callLike) continue;                                    // property access: leave it
                    $pp = $prev($p);
                    if ($t[$pp][0] === T_VARIABLE && strtolower($t[$pp][1]) === '$this') { $positions[$lk][] = $k; continue; }
                    unset($eligible[$lk]); continue;                             // $other->name(: ambiguous
                }
                if ($pid === T_DOUBLE_COLON) {
                    if (!$callLike) continue;                                    // class constant: leave it
                    $pp = $prev($p); $recv = strtolower($t[$pp][1]);
                    if ($t[$pp][0] === T_STATIC || $recv === "self" || $recv === "static" || $recv === $className) { $positions[$lk][] = $k; continue; }
                    unset($eligible[$lk]); continue;                             // Other::name(: ambiguous
                }
                unset($eligible[$lk]);                                           // bare identifier: disqualify
            }
            // Rename eligible methods (only token positions inside THIS class body) to short names.
            $used = $allMethods; $counter = 0;
            foreach (array_keys($eligible) as $lm) {
                do {
                    $s = ""; $v = $counter++;
                    do { $s = chr(97 + $v % 26) . $s; $v = intdiv($v, 26) - 1; } while ($v >= 0);
                } while (isset($used[$s]));
                $used[$s] = true;
                foreach ($positions[$lm] as $pos) {
                    if ($pos >= $cstart && $pos <= $cend && !$inNested($pos, $nested)) $t[$pos][1] = $s;  // this class only, not nested
                }
            }
            $ci = $cend;
        }
    }
    if ($in["properties"]) {
        // Rename PRIVATE INSTANCE properties. HIGH RISK, opt-in: a private property name also
        // appears in the SERIALIZED form of an object (serialize(), sessions, caches), which the
        // tokenizer cannot see, so a value serialized before obfuscation would not unserialize
        // after it. We gate hard: the class is skipped if it has dynamic member access, magic
        // __get/__set/etc., get_object_vars, (un)serialize/__sleep/__wakeup, compact/extract or any
        // Reflection*; and a property is renamed only when the bareword appears in the WHOLE FILE
        // exclusively as $this->name used as a property (no "(" after it), never on another object,
        // never as a string literal, never as any other identifier. Static and promoted properties
        // and multi-declarations ("private $a, $b;") are left alone. Property names are
        // case-sensitive. A local variable $name is unrelated (accessed as $name, not $this->name).
        $barred = array_flip(['__get','__set','__isset','__unset','__call','__callstatic','__sleep',
            '__wakeup','__serialize','__unserialize','get_object_vars','get_class_vars','compact',
            'extract','get_defined_vars','serializable','reflectionproperty','reflectionobject',
            'reflectionclass','serialize']);
        for ($ci = 0; $ci < $n; $ci++) {
            if ($t[$ci][0] !== T_CLASS) continue;
            if ($t[$prev($ci)][0] === T_DOUBLE_COLON || $t[$prev($ci)][0] === T_NEW) continue;
            $cn = $next($ci);
            if ($cn >= $n || $t[$cn][0] !== T_STRING) continue;
            $j = $cn; $hasParent = false;
            while ($j < $n && $t[$j][1] !== "{" && $t[$j][1] !== ";") {
                if ($t[$j][0] === T_EXTENDS || $t[$j][0] === T_IMPLEMENTS) $hasParent = true;
                $j++;
            }
            if ($j >= $n || $t[$j][1] !== "{") continue;
            // A child may inherit a property; a renamed private property could collide with it
            // ("Cannot redeclare"). The parent is not visible here, so skip the class (ENV-AUD-10).
            if ($hasParent) continue;
            $cstart = $j;
            for ($depth = 0; $j < $n; $j++) {
                $id = $t[$j][0]; $c = $t[$j][1];
                if ($c === "{" || $id === T_CURLY_OPEN || $id === T_DOLLAR_OPEN_CURLY_BRACES) $depth++;
                elseif ($c === "}" && --$depth === 0) break;
            }
            $cend = $j;
            $skipClass = false;
            for ($k = $cstart + 1; $k < $cend; $k++) {
                $id = $t[$k][0]; $c = $t[$k][1];
                if ($id === T_OBJECT_OPERATOR || $id === T_NULLSAFE_OBJECT_OPERATOR) {
                    $nx = $next($k);
                    if ($nx < $n && ($t[$nx][0] === T_VARIABLE || $t[$nx][1] === "{" || $t[$nx][0] === T_CURLY_OPEN)) { $skipClass = true; break; }
                } elseif ($id === T_STRING && isset($barred[strtolower($c)])) { $skipClass = true; break; }
                elseif ($id === T_USE && $next($k) < $n && $t[$next($k)][1] !== "(") { $skipClass = true; break; }  // trait use (H2)
            }
            if ($skipClass) continue;
            // A nested class's $this->prop is its own, not this class's (ENV-2026-15): exclude nested
            // class bodies from the eligibility scan and the rename below.
            $nested = $nestedRanges($cstart, $cend);
            // Class-level single private instance property declarations: name -> declaration index.
            $props = []; $bd = 0; $pd = 0;
            for ($k = $cstart + 1; $k < $cend; $k++) {
                $id = $t[$k][0]; $c = $t[$k][1];
                if ($c === "(" || $c === "[") { $pd++; continue; }
                if ($c === ")" || $c === "]") { $pd--; continue; }
                if ($c === "{" || $id === T_CURLY_OPEN || $id === T_DOLLAR_OPEN_CURLY_BRACES) { $bd++; continue; }
                if ($c === "}") { $bd--; continue; }
                if ($id !== T_PRIVATE || $bd !== 0 || $pd !== 0) continue;
                $isStatic = false; $isPP = false; $m = $next($k);
                while ($m < $n) {
                    $mid = $t[$m][0]; $mc = $t[$m][1];
                    if ($mid === T_VARIABLE || $mid === T_FUNCTION) break;
                    if ($mc === ";" || $mc === "{" || $mc === "}" || $mc === "(") break;
                    if ($mid === T_STATIC || strtolower($mc) === "static") $isStatic = true;
                    if ($mid === T_PUBLIC || $mid === T_PROTECTED) $isPP = true;
                    $m = $next($m);
                }
                if ($m < $n && $t[$m][0] === T_VARIABLE && !$isStatic && !$isPP) {
                    $after = $next($m);
                    // Single declaration only: "private $x;" or "private $x = <expr>;". A comma at
                    // depth 0 before the ";" means a multi-declaration ("private $a = 1, $b = 2;"),
                    // which we leave entirely alone (H7).
                    $single = false;
                    if ($after < $n && $t[$after][1] === ";") {
                        $single = true;
                    } elseif ($after < $n && $t[$after][1] === "=") {
                        $dd = 0;
                        for ($w = $after + 1; $w < $cend; $w++) {
                            $wc = $t[$w][1];
                            if ($wc === "(" || $wc === "[") $dd++;
                            elseif ($wc === ")" || $wc === "]") $dd--;
                            elseif ($dd === 0 && $wc === ";") { $single = true; break; }
                            elseif ($dd === 0 && $wc === ",") break;   // multi-declaration
                        }
                    }
                    if ($single) $props[ltrim($t[$m][1], '$')] = $m;
                }
            }
            if (!$props) continue;
            $elig = $props;
            for ($k = 0; $k < $n; $k++) {
                if ($inNested($k, $nested)) continue;             // nested-class $this->prop is a separate scope
                $id = $t[$k][0]; $c = $t[$k][1];
                if ($id === T_CONSTANT_ENCAPSED_STRING) {
                    $val = eval("return " . $c . ";");
                    if (is_string($val) && isset($elig[$val])) unset($elig[$val]);
                    continue;
                }
                if ($id !== T_STRING || !isset($props[$c])) continue;
                $p = $prev($k);
                if ($t[$p][0] === T_OBJECT_OPERATOR || $t[$p][0] === T_NULLSAFE_OBJECT_OPERATOR) {
                    if ($t[$next($k)][1] === "(") { unset($elig[$c]); continue; }   // a method, not a property
                    $pp = $prev($p);
                    if ($t[$pp][0] === T_VARIABLE && strtolower($t[$pp][1]) === '$this') continue;  // $this->name: ok
                    unset($elig[$c]); continue;                                     // $other->name: ambiguous
                }
                unset($elig[$c]);                                                   // any other use: disqualify
            }
            if (!$elig) continue;
            $reserved = $keep;
            foreach ($props as $pn => $idx) $reserved['$' . $pn] = true;
            // Reserve EVERY variable name that appears in the class body (property declarations of any
            // visibility, constructor-promoted properties, statics, locals, $this). Over-reserving is
            // harmless (the generator just skips those names) and prevents a renamed private property
            // from colliding with a public/protected/promoted/multi-declared property of the same
            // class ("Cannot redeclare") (ENV-AUD-10).
            for ($k = $cstart + 1; $k < $cend; $k++) {
                if ($t[$k][0] === T_VARIABLE) $reserved[$t[$k][1]] = true;
            }
            $counter = 0;
            foreach (array_keys($elig) as $pn) {
                do {
                    $s = ""; $v = $counter++;
                    do { $s = chr(97 + $v % 26) . $s; $v = intdiv($v, 26) - 1; } while ($v >= 0);
                    $nv = '$' . $s;
                } while (isset($reserved[$nv]));
                $reserved[$nv] = true;
                $t[$props[$pn]][1] = $nv;                                           // declaration: $name -> $s
                for ($k = $cstart + 1; $k < $cend; $k++) {                          // $this->name -> $this->s
                    if ($inNested($k, $nested)) continue;                           // never a nested class's $this->prop
                    if ($t[$k][0] === T_STRING && $t[$k][1] === $pn) {
                        $p = $prev($k);
                        if (($t[$p][0] === T_OBJECT_OPERATOR || $t[$p][0] === T_NULLSAFE_OBJECT_OPERATOR)
                                && $t[$next($k)][1] !== "(") {
                            $pp = $prev($p);
                            if ($t[$pp][0] === T_VARIABLE && strtolower($t[$pp][1]) === '$this') $t[$k][1] = $s;
                        }
                    }
                }
            }
            $ci = $cend;
        }
    }
    if ($in["encode_strings"]) {
        // Re-spell every complete string literal as a double-quoted run of \xNN byte escapes. The
        // VALUE is identical (the compiler produces the same bytes), so behaviour never changes and
        // there is no run-time cost beyond parsing the escapes; it is still a constant literal, so
        // it is valid anywhere (const, default values, attributes, array keys). Only
        // T_CONSTANT_ENCAPSED_STRING is touched: interpolated "$x" strings and heredoc/nowdoc are a
        // sequence of other tokens and are left as they are. Hides SQL, messages, paths, etc.
        for ($i = 0; $i < $n; $i++) {
            if ($t[$i][0] !== T_CONSTANT_ENCAPSED_STRING) continue;
            $val = eval("return " . $t[$i][1] . ";");   // a pure literal: no side effects
            if (!is_string($val) || $val === "") continue;
            $hex = "";
            for ($b = 0, $len = strlen($val); $b < $len; $b++) $hex .= sprintf("\\x%02x", ord($val[$b]));
            $t[$i][1] = '"' . $hex . '"';
        }
    }
    if ($in["obfuscate_flow"]) {
        // Opaque-predicate dead-code insertion (modest control-flow obfuscation; NOT flattening).
        // At the start of each NAMED function/method body, insert an always-false branch: strlen of
        // a path is never < 0, __LINE__ & 0 is never 1, count of a 2-element array is never != 2. The
        // branch never runs, so behaviour is unchanged; it is emitted on the opening brace's line, so
        // line numbers are preserved; and an automated stripper must model strlen/count to prove it
        // dead. Functions using goto are skipped (ultra-safe). The final TOKEN_PARSE check below
        // rejects the file if any insertion ever broke the syntax.
        $preds = ['if(\\strlen(__FILE__)<0){throw new \\Exception();}',
                  'if((__LINE__&0)===1){throw new \\Exception();}',
                  'if(\\count([__FILE__,__LINE__])!==2){throw new \\Exception();}'];
        $inserts = [];
        for ($i = 0; $i < $n; $i++) {
            if ($t[$i][0] !== T_FUNCTION) continue;
            $j = $next($i);
            if ($j < $n && $t[$j][1] === "&") $j = $next($j);
            if ($j >= $n || $t[$j][0] !== T_STRING) continue;             // named function/method only
            $j = $next($j);
            if ($j >= $n || $t[$j][1] !== "(") continue;
            for ($depth = 0; $j < $n; $j++) {
                $c = $t[$j][1];
                if ($c === "(" || $c === "[" || $t[$j][0] === T_ATTRIBUTE) $depth++;
                elseif ($c === ")" || $c === "]") { if (--$depth === 0) break; }
            }
            for ($j++; $j < $n && $t[$j][1] !== "{" && $t[$j][1] !== ";"; $j++);
            if ($j >= $n || $t[$j][1] === ";") continue;                   // abstract/interface: no body
            $brace = $j;
            $hasGoto = false;
            for ($depth = 0, $k = $brace; $k < $n; $k++) {
                $id = $t[$k][0]; $c = $t[$k][1];
                if ($c === "{" || $id === T_CURLY_OPEN || $id === T_DOLLAR_OPEN_CURLY_BRACES) $depth++;
                elseif ($c === "}" && --$depth === 0) break;
                elseif ($id === T_GOTO) $hasGoto = true;
            }
            if (!$hasGoto) $inserts[$brace] = $preds[count($inserts) % count($preds)];
        }
        krsort($inserts);                                                  // splice high→low: indices stay valid
        foreach ($inserts as $pos => $code) array_splice($t, $pos + 1, 0, [[null, $code]]);
    }
    $result = "";
    foreach ($t as [$id, $c]) {
        if ($in["compact"] && ($id === T_WHITESPACE || $id === T_COMMENT || $id === T_DOC_COMMENT)) {
            // Collapse each whitespace run (and each comment) to a SINGLE space: never zero, so two
            // tokens can never merge into a different one (PHP tolerated whitespace there, one space
            // is always a valid separator). Removes indentation, blank lines and comments; line
            // numbers are NOT preserved. Heredoc/nowdoc bodies and strings are their own tokens, so
            // their newlines are untouched. The open tag keeps its own trailing whitespace.
            $result .= " ";
        } elseif ($in["strip"] && ($id === T_COMMENT || $id === T_DOC_COMMENT)) {
            // Same number of newlines (or one space): line numbers do not change.
            $lines = substr_count($c, "\n");
            $result .= $lines ? str_repeat("\n", $lines) : " ";
        } else {
            $result .= $c;
        }
    }
    try { token_get_all($result, TOKEN_PARSE); }
    catch (ParseError $e) { fwrite(STDERR, $name . ": the transformation broke the file: " . $e->getMessage()); exit(3); }
    $out[$name] = base64_encode($result);
}
echo json_encode(["files" => $out, "halted" => array_keys($halted)], JSON_THROW_ON_ERROR);
"""


_PROGRAM_CACHE: dict[tuple[str, str, str], str] = {}


def resolve_program(name: str) -> str:
    """Absolute path of the program to run for name (e.g. the default --php "php").

    A name with a directory part is the operator's explicit choice and is only made absolute. A
    BARE name is looked up in the PATH entries ONLY (ENC-3): handing it to CreateProcess, or to
    shutil.which, on Windows searches the application folder and the CURRENT folder first, so a
    php.exe planted in the project being packed would run and receive the plaintext sources. Empty,
    '.' and relative PATH entries are skipped for the same reason (they also mean "the current
    folder"). Raises ValueError when nothing is found."""
    if not name:
        raise ValueError("no program name given")
    if os.path.dirname(name) or (os.altsep and os.altsep in name):
        return os.path.abspath(name)
    key = (name, os.environ.get("PATH", ""), os.name)
    if key in _PROGRAM_CACHE:
        return _PROGRAM_CACHE[key]
    # Windows: like CreateProcess, append only ".exe" to a name without an extension. Resolving to
    # a .bat/.cmd would hand the fixed PHP arguments to cmd.exe for re-parsing.
    candidates = [name if os.name != "nt" or os.path.splitext(name)[1] else name + ".exe"]
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        entry = entry.strip().strip('"')
        if not entry or entry == "." or not os.path.isabs(entry):
            continue
        for candidate in candidates:
            full = os.path.join(entry, candidate)
            if os.path.isfile(full) and (os.name == "nt" or os.access(full, os.X_OK)):
                _PROGRAM_CACHE[key] = full
                return full
    raise ValueError(f"'{name}' was not found in the PATH folders (the current folder is never "
                     f"searched); pass its full path (e.g. --php C:\\php\\php.exe or /usr/bin/php)")


# A php program travels on STDIN, not on the command line: TRANSFORM_PHP alone is ~32,000
# characters, at the 32,767 limit of a Windows command line (ENC-21), and a non-ASCII byte in a
# -r argument is re-encoded through the ANSI code page there. This bootstrap reads one decimal
# length line, then that many bytes of program, and evaluates it; the program then reads its JSON
# payload from the rest of STDIN, exactly as before.
_PHP_BOOTSTRAP = ('$n=(int)fgets(STDIN);$c=$n>0?stream_get_contents(STDIN,$n):"";'
                  'if(!is_string($c)||strlen($c)!==$n){fwrite(STDERR,"envelock: truncated program");'
                  'exit(2);}eval($c);')


def _run_php(php: str, code: str, payload: dict, what: str, extra_args: list[str] | None = None) -> dict:
    """Run a php CLI program that reads a JSON payload on STDIN and writes JSON to STDOUT. Shared by
    the transform and the literal-vault passes (PHP 8+ with tokenizer). extra_args are inserted
    before -r: the bytecode pass uses them to load the Envelock loader itself. The program itself is
    sent on STDIN ahead of the payload (see _PHP_BOOTSTRAP)."""
    try:
        exe = resolve_program(php)
    except ValueError as error:
        raise ValueError(f"{what} need a php CLI (PHP 8+ with tokenizer): {error}") from None
    program = code.encode("utf-8")
    try:
        result = subprocess.run(  # nosec B603 # fixed argument list, no shell
            # display_errors=stderr: the JSON protocol owns STDOUT, so a PHP notice (e.g. a PHP 8.5
            # deprecation) must never land there and corrupt it; our own errors already use STDERR.
            [exe, *(extra_args or []), "-d", "display_errors=stderr", "-r", _PHP_BOOTSTRAP],
            input=str(len(program)).encode() + b"\n" + program + json.dumps(payload).encode(),
            capture_output=True, timeout=600,
            # No console window flashing when called from the windowed assistant (Windows only).
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as error:
        raise ValueError(f"the php CLI took too long ({what}, >{error.timeout:.0f}s)") from error
    except OSError as error:
        raise ValueError(f"{what} need a php CLI (PHP 8+ with tokenizer): {error}") from error
    if result.returncode != 0:
        raise ValueError(f"{what} failed: " + result.stderr.decode(errors="replace")[-500:])
    return json.loads(result.stdout)


# Objective O6, first slice: rename the GLOBAL names the package declares — classes, interfaces,
# traits, enums and functions — and every reference to them, across every file of the pack at once.
# What it deliberately does not touch: class constants, and any name it cannot prove is closed
# inside the package. A name is renamed only when it never appears inside a string literal anywhere
# in the pack (a string is how PHP spells a dynamic class_exists/Reflection/serialisation target)
# and the pack contains no dynamic construction the tokenizer cannot see through. The builtin
# whitelist is asked of the running PHP rather than written down, so it cannot drift.
NAMES_PHP = r"""
if (PHP_VERSION_ID < 80000 || !function_exists("token_get_all")) { fwrite(STDERR, "needs PHP 8+ with tokenizer"); exit(2); }
error_reporting(E_ALL & ~E_DEPRECATED);
$in = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$WS = array_flip([T_WHITESPACE, T_COMMENT, T_DOC_COMMENT]);

/* One normalised token list per file: [id|null, text, line]. */
$T = []; $N = [];
foreach ($in["files"] as $name => $b64) {
    try { $raw = token_get_all(base64_decode($b64, true), TOKEN_PARSE); }
    catch (ParseError $e) { fwrite(STDERR, $name . ": " . $e->getMessage()); exit(3); }
    $t = [];
    foreach ($raw as $x) $t[] = is_array($x) ? [$x[0], $x[1], $x[2]] : [null, $x, 0];
    $T[$name] = $t; $N[$name] = count($t);
}

/* Single exit: always one JSON object, with the ORIGINAL files whenever nothing was renamed, so
 * the caller can never mistake "skipped" for "rewritten". */
$finish = function (array $files, array $renamed, string $skipped) use ($in): void {
    if ($skipped !== "" || !$renamed) {
        $o = [];
        foreach ($in["files"] as $name => $b64) $o[$name] = $b64;
        echo json_encode(["files" => $o, "renamed" => [], "skipped" => $skipped]);
        return;
    }
    echo json_encode(["files" => $files, "renamed" => $renamed, "skipped" => ""]);
};

/* The whitelist is the running PHP's own symbol table: a name the engine already owns is never
 * renamed, so this cannot shadow a builtin, and the list cannot drift with the PHP version. */
$builtin = [];
$known = array_merge(get_declared_classes(), get_declared_interfaces(), get_declared_traits(),
                     get_defined_functions()["internal"]);
if (function_exists("get_declared_enums")) $known = array_merge($known, get_declared_enums());
foreach ($known as $nm) $builtin[strtolower($nm)] = true;

$declared = [];   /* "ty:lower"|"fn:lower" -> original spelling */
$at = [];         /* same key -> [file => [token index, ...]] */
$memberNames = [];/* lowercase name of every method and class constant: a collision disqualifies */
$literals = [];   /* every string-literal text in the pack, lowercased */
$risky = false;
$identityCalls = array_flip(["spl_autoload_register", "spl_autoload_call", "class_exists", "interface_exists",
    "trait_exists", "enum_exists", "class_alias", "function_exists", "method_exists", "property_exists",
    "is_callable", "constant", "defined", "fromcallable", "bind", "bindto", "call",
    "gettrace", "gettraceasstring", "getmessage", "getprevious", "__tostring",
    "get_class", "get_called_class", "get_parent_class",
    "get_debug_type", "get_declared_classes", "get_declared_interfaces", "get_declared_traits",
    "get_defined_functions", "get_class_methods", "get_class_vars", "class_implements", "class_parents",
    "class_uses", "is_a", "is_subclass_of", "serialize", "unserialize", "var_dump", "var_export", "print_r",
    "debug_backtrace", "debug_print_backtrace", "call_user_func", "call_user_func_array", "forward_static_call",
    "forward_static_call_array", "array_map", "array_filter", "array_reduce", "array_walk", "array_walk_recursive",
    "array_udiff", "array_udiff_assoc", "array_udiff_uassoc", "array_diff_uassoc", "array_diff_ukey",
    "array_uintersect", "array_uintersect_assoc", "array_uintersect_uassoc", "array_intersect_uassoc",
    "array_intersect_ukey", "array_find", "array_find_key", "array_any", "array_all", "iterator_apply",
    "callbackfilteriterator", "recursivecallbackfilteriterator", "fiber", "stream_wrapper_register",
    "stream_register_wrapper", "stream_filter_register", "header_register_callback", "session_set_save_handler",
    "usort", "uasort", "uksort", "preg_replace_callback", "preg_replace_callback_array", "register_shutdown_function",
    "register_tick_function", "set_error_handler", "set_exception_handler", "ob_start"]);

/* Class/interface/trait/enum bodies FIRST: whether a T_FUNCTION is a global function or a method
 * depends on it, and getting that wrong renames a call site without its declaration. */
$bodies = [];
foreach ($T as $name => $t) {
    $n = $N[$name];
    for ($i = 0; $i < $n; $i++) {
        $id = $t[$i][0];
        if ($id !== T_CLASS && $id !== T_INTERFACE && $id !== T_TRAIT && $id !== T_ENUM) continue;
        $j = $i;
        while ($j < $n && $t[$j][1] !== "{" && $t[$j][1] !== ";") $j++;
        if ($j >= $n || $t[$j][1] !== "{") continue;
        $start = $j;
        for ($d = 0; $j < $n; $j++) {
            $cj = $t[$j][1]; $ij = $t[$j][0];
            if ($cj === "{" || $ij === T_CURLY_OPEN || $ij === T_DOLLAR_OPEN_CURLY_BRACES) $d++;
            elseif ($cj === "}" && --$d === 0) break;
        }
        $bodies[$name][] = [$start, $j];
    }
}
$inBody = function (string $file, int $idx) use ($bodies): bool {
    foreach ($bodies[$file] ?? [] as [$s, $e]) { if ($idx > $s && $idx < $e) return true; }
    return false;
};

foreach ($T as $name => $t) {
    $n = $N[$name];
    $next = function (int $i) use ($t, $n, $WS): int {
        for ($i++; $i < $n && $t[$i][0] !== null && isset($WS[$t[$i][0]]); $i++);
        return $i;
    };
    for ($i = 0; $i < $n; $i++) {
        $id = $t[$i][0]; $c = $t[$i][1];
        if ($id === T_NAMESPACE) { $finish([], [], "namespaced"); return; }
        // The token rewriter cannot distinguish all qualified names or separate constant symbols
        // from class/function symbols. Do not guess: a wrong rename can pass php -l and then fatal.
        if (in_array($id, [T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED, T_NAME_RELATIVE, T_CONST,
                           T_CLASS_C, T_TRAIT_C, T_METHOD_C, T_FUNC_C, T_ATTRIBUTE, T_HALT_COMPILER,
                           T_ENCAPSED_AND_WHITESPACE, T_TRY, T_CATCH, T_FINALLY, T_THROW], true)) $risky = true;
        if ($id === T_STRING && (isset($identityCalls[strtolower($c)])
                                 || str_starts_with(strtolower($c), "reflection"))) $risky = true;
        // A dynamically named member could invoke an identity observer even when the target
        // spelling is assembled from pieces. The token pass cannot resolve that safely.
        if (in_array($id, [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON], true)) {
            $nx = $next($i);
            if ($nx < $n && ($t[$nx][0] === T_VARIABLE || $t[$nx][1] === "{")) $risky = true;
        }
        // TOKEN_PARSE reports the keyword in Foo::class as T_STRING on supported PHP versions.
        if ($id === T_CLASS || ($id === T_STRING && strtolower($c) === "class")) {
            for ($k = $i - 1; $k >= 0; $k--) {
                if ($t[$k][0] === null || !isset($WS[$t[$k][0]])) {
                    if ($t[$k][0] === T_DOUBLE_COLON) $risky = true; // Foo::class observes identity
                    break;
                }
            }
        }
        if ($id === T_CONSTANT_ENCAPSED_STRING || $id === T_ENCAPSED_AND_WHITESPACE || $id === T_DOC_COMMENT) {
            $literals[] = strtolower($c);
        } elseif ($id === T_CLASS || $id === T_INTERFACE || $id === T_TRAIT || $id === T_ENUM
                  || $id === T_FUNCTION) {
            $j = $next($i);
            if ($j < $n && $t[$j][1] === "&") $j = $next($j);
            if ($j >= $n || $t[$j][0] !== T_STRING) continue;   /* `new class`, closure: no name */
            if ($id === T_FUNCTION) {
                /* A method belongs to the private-method pass, not here. Renaming a global function
                 * whose name a method also uses would rewrite the method's declaration too (the
                 * rewrite cannot tell them apart), so the collision is recorded and disqualifies. */
                if ($inBody($name, $i)) { $memberNames[strtolower($t[$j][1])] = true; continue; }
                $key = "fn:" . strtolower($t[$j][1]);
            } else {
                $p = null;
                for ($k = $i - 1; $k >= 0; $k--) {
                    if ($t[$k][0] === null || !isset($WS[$t[$k][0]])) { $p = $t[$k][0]; break; }
                }
                if ($p === T_DOUBLE_COLON || $p === T_NEW) continue;    /* Foo::class, `new class` */
                $key = "ty:" . strtolower($t[$j][1]);
            }
            $declared[$key] = $t[$j][1];
            $at[$key][$name][] = $j;
        } elseif ($id === T_CONST && $inBody($name, $i)) {
            $j = $next($i);
            if ($j < $n && $t[$j][0] === T_STRING) $memberNames[strtolower($t[$j][1])] = true;
        } elseif ($id === T_STRING_VARNAME || $id === T_DOLLAR_OPEN_CURLY_BRACES || $id === T_EVAL
                  || $id === T_GLOBAL) {
            /* "${x}" / "{$x}" interpolation, eval(), global: each can reach a name that never
             * appears as a T_STRING, so the rename cannot see every reference. */
            $risky = true;
        } elseif ($id === T_VARIABLE) {
            $nx = $next($i);
            if ($nx < $n && ($t[$nx][1] === "(" || $t[$nx][0] === T_DOUBLE_COLON)) $risky = true;
            for ($k = $i - 1; $k >= 0; $k--) {
                if ($t[$k][0] === null || !isset($WS[$t[$k][0]])) {
                    if ($t[$k][0] === T_NEW || $t[$k][0] === T_INSTANCEOF) $risky = true;
                    break;
                }
            }
        }
    }
}
// An external parent or trait can observe the subclass name. Since this pass cannot resolve one,
// decline the whole package if any inheritance/trait target is absent from the declarations.
foreach ($T as $name => $t) {
    $n = $N[$name];
    for ($i = 0; $i < $n; $i++) {
        $id = $t[$i][0];
        if ($id !== T_EXTENDS && $id !== T_IMPLEMENTS && !($id === T_USE && $inBody($name, $i))) continue;
        for ($j = $i + 1; $j < $n && $t[$j][1] !== "{" && $t[$j][1] !== ";"; $j++) {
            if ($t[$j][0] === T_STRING && !isset($declared["ty:" . strtolower($t[$j][1])])) $risky = true;
        }
    }
}
if ($risky) { $finish([], [], "dynamic"); return; }

/* The rename map. A name survives only if the engine does not own it, it is not magic-by-name, it
 * is long enough to be worth the churn, and it appears in NO string literal in the pack — a string
 * is how PHP spells a class_exists(), a Reflection lookup or a serialised class name, and none of
 * those show up as a T_STRING this pass would rewrite. */
$map = [];
$alphabet = "abcdefghijklmnopqrstuvwxyz";
foreach ($declared as $key => $orig) {
    $lower = strtolower($orig);
    if (isset($builtin[$lower]) || str_starts_with($lower, "__") || strlen($lower) < 3) continue;
    // The token rewrite cannot distinguish separate type/function symbol tables of the same name.
    if (isset($declared["ty:" . $lower]) && isset($declared["fn:" . $lower])) continue;
    if (str_starts_with($key, "ty:")) {
        // An external autoloader may map this original basename; source paths are not rewritten.
        foreach (array_keys($at[$key] ?? []) as $file) {
            if (strtolower(basename(str_replace('\\', '/', $file))) === $lower . ".php") continue 2;
        }
    }
    /* A method or class constant elsewhere in the pack already spells this name. The rewrite
     * decides what to rename from the preceding token, and a T_STRING that is a member of an object
     * whose class we cannot resolve would be rewritten by mistake, so the name stays. */
    if (isset($memberNames[$lower])) continue;
    foreach ($literals as $lit) { if (str_contains($lit, $lower)) continue 2; }
    do { $short = "e" . substr(str_shuffle("0123456789" . $alphabet), 0, 5); }
    while (isset($builtin[$short]) || in_array($short, $map, true) || isset($declared["ty:" . $short])
           || isset($declared["fn:" . $short]));
    $map[$key] = $short;
}
if (!$map) { $finish([], [], ""); return; }

$out = [];
foreach ($T as $name => $t) {
    $n = $N[$name];
    for ($i = 0; $i < $n; $i++) {
        if ($t[$i][0] !== T_STRING) continue;
        $p = null;
        for ($k = $i - 1; $k >= 0; $k--) {
            if ($t[$k][0] === null || !isset($WS[$t[$k][0]])) { $p = $t[$k][0]; break; }
        }
        $after = $i + 1;
        while ($after < $n && $t[$after][0] !== null && isset($WS[$t[$after][0]])) $after++;
        // `Widget:` is a named argument or label, except in `enum Widget: string`, where it is
        // the declaration itself. Do not rename a reference while accidentally skipping that enum.
        if ($after < $n && $t[$after][1] === ":" && $p !== T_ENUM) continue;
        /* Not a global name: a member after -> or ?->, a constant being declared, a goto label, a
         * foreach alias, a named argument (`name:`), a case label, a variable's name.
         * T_FUNCTION is deliberately NOT here: the T_STRING after `function` IS the declaration this
         * pass has to rename, and a closure or arrow function has no T_STRING there to misrename. */
        if ($p === T_OBJECT_OPERATOR || $p === T_NULLSAFE_OBJECT_OPERATOR || $p === T_DOUBLE_COLON
            || $p === T_CONST || $p === T_GOTO || $p === T_AS || $p === T_CASE
            || $p === T_VARIABLE) continue;
        $ty = $map["ty:" . strtolower($t[$i][1])] ?? null;
        $fn = $ty === null ? ($map["fn:" . strtolower($t[$i][1])] ?? null) : null;
        if ($ty !== null) $t[$i][1] = $ty;
        elseif ($fn !== null) $t[$i][1] = $fn;
    }
    $s = "";
    foreach ($t as [, $c,]) $s .= $c;
    $out[$name] = base64_encode($s);
}
$renamed = [];
foreach ($map as $key => $short) $renamed[$declared[$key]] = $short;
$finish($out, $renamed, "");
"""


def _virtualize_php_path() -> Path:
    """The mini-VM compiler ships beside this module. Under a frozen build it is unpacked under
    _MEIPASS/encoder, which is where gui/envelock-assistant.spec places it."""
    candidates = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / "encoder" / "virtualize.php")
    candidates.append(Path(__file__).resolve().with_name("virtualize.php"))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise ValueError("--virtualize needs encoder/virtualize.php beside the packer")


def _require_vm_v2_loader(php: str, loader: str | Path | None) -> None:
    """Require and probe the intended host loader; v1 had silently wrong VM operator semantics.

    This verifies a local binary, not the loader actually installed on a remote deployment. The
    operator must deploy the same compatible build and run end-to-end tests there.
    """
    if loader is None or not str(loader):
        raise ValueError("--virtualize requires --virtualize-loader (v2-capable loader or 'builtin')")
    options = []
    if str(loader) != "builtin":
        path = Path(loader).resolve()
        if not path.is_file():
            raise ValueError(f"--virtualize loader does not exist: {path}")
        options = ["-d", f"extension={path}"]
    # One v2 program, NAN <= 1. Checking the alias alone would accept an incorrectly implemented
    # marker. This remains a compatibility smoke test, not a proof of the whole interpreter.
    code = b"\x02\x00\x00\x01\x00\x00\x04\x0c\x09"
    program = (b"ENVVM3" + struct.pack(">HH", 1, 1) + b"\x02" + struct.pack(">q", 1)
               + struct.pack(">I", len(code)) + code)
    probe = ("if (!function_exists('__envelock_vm_v2')) exit(2); "
             + "if (__envelock_vm_v2('" + base64.b64encode(program).decode() + "', [NAN]) !== false) exit(3); "
             + "echo 'envelock-vm-v2-ok';")
    try:
        exe = resolve_program(php)
    except ValueError as error:
        raise ValueError(f"--virtualize loader probe failed: {error}") from None
    try:
        result = subprocess.run(  # nosec B603 - explicit operator-supplied local PHP and extension
            [exe, "-n", *options, "-d", "display_errors=stderr", "-r", probe],
            capture_output=True, timeout=60, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"--virtualize loader probe failed: {error}") from error
    if result.returncode or result.stdout != b"envelock-vm-v2-ok":
        detail = result.stderr.decode(errors="replace").strip()[-300:]
        raise ValueError(f"--virtualize loader is not a compatible v2 build: {detail}")


def _php_single_quoted(text: str) -> str:
    """text as a PHP single-quoted string literal: only \\ and ' are special there."""
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"


def virtualize_sources(files: dict[str, bytes], names: list[str],
                       php: str = "php") -> tuple[dict[str, bytes], dict[str, str]]:
    """Compile selected top-level global functions into experimental v2 mini-VM programs.

    The compiler refuses unsupported syntax; that is not a proof of semantic equivalence. The
    packer separately probes the intended v2 loader before staging and forbids name obfuscation.
    """
    program = _virtualize_php_path()
    # A single-quoted PHP literal (ENC-22): json.dumps made a double-quoted one, in which a non-ASCII
    # character became a literal é and a "$NAME" in the folder name was interpolated. The
    # compile is a build step like --bytecode: lift memory_limit, or a large function exhausts the
    # host's 128M default inside virtualize.php (ENC-26).
    res = _run_php(php, "require " + _php_single_quoted(str(program)) + ";",
                   {"files": {name: base64.b64encode(data).decode() for name, data in files.items()},
                    "marked": list(names), "rewrite": True},
                   "--virtualize", extra_args=["-d", "memory_limit=-1"])
    return ({name: base64.b64decode(data) for name, data in res["files"].items()},
            res["programs"])


# PHP's class and function lookups fold ASCII case only (not Unicode casefold).
_PHP_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def _php_name_key(name: str) -> str:
    return name.translate(_PHP_ASCII_LOWER)


# PHP identifiers are byte-oriented; a UTF-8 identifier can contain bytes above 0x7f. Only ASCII
# letters are folded by class/function lookup, so do not use Unicode casefold or str.lower here.
_PHP_IDENT = rb"[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*"
_PHP_FQN = re.compile(_PHP_IDENT + rb"(?:\\" + _PHP_IDENT + rb")*")


def _parse_names_allowlist(entries: list[str]) -> dict[tuple[str, str], str]:
    """Validate explicit KIND:FQN entries; keys match PHP's ASCII class/function name rules."""
    if not isinstance(entries, (list, tuple)) or not 1 <= len(entries) <= 4096:
        raise ValueError("name allowlist must contain 1..4096 entries")
    parsed: dict[tuple[str, str], str] = {}
    for item in entries:
        if not isinstance(item, str):
            raise ValueError("name allowlist entries must be strings of the form type:FQN or function:FQN")
        kind, sep, fqn = item.partition(":")
        try:
            encoded = fqn.encode("utf-8")
        except UnicodeError as error:
            raise ValueError("name allowlist contains an invalid UTF-8 identifier") from error
        if not sep or kind not in ("type", "function") or len(encoded) > 1024 or not _PHP_FQN.fullmatch(encoded):
            raise ValueError(f"invalid name allowlist entry: {item!r}; use type:FQN or function:FQN")
        key = (kind, _php_name_key(fqn))
        if key in parsed:
            raise ValueError(f"duplicate name allowlist entry: {item!r}")
        parsed[key] = item
    return parsed


def _ast_rename_names(
    files: dict[str, bytes], php: str = "php", *, allowlist: list[str] | None = None
) -> tuple[dict[str, bytes], dict[str, str], str]:
    r"""Experimental closed-world rename, decided by the AST and applied using byte offsets.

    All callers must explicitly opt in. This pass cannot see external code, generated caches or an
    autoloader installed outside the pack; it is NOT safe for a framework or a PSR-4/classmap app.
    Known dynamic/identity-observing constructs cause the whole pass to decline. A class with an
    external ancestor or trait (including transitively) and a class in its PSR-4-style filename is
    kept; these are safeguards, not a proof that a package is closed.

    Class and function names are matched with PHP's ASCII case rules, and references are classified
    separately from constants. Every rewritten reference is fully qualified; imported aliases remain
    bound to their original spelling. When an allowlist is supplied, ONLY its exact type/function
    declarations may be renamed, and every requested declaration must be eligible or the pack fails.
    The list is an operator-declared boundary, not proof that external consumers do not exist.
    No line breaks are changed. Any suspect span or lint failure rolls back the entire pack. Returns
    (files, {original FQN: new short name}, refusal reason) when no strict allowlist is supplied.
    """
    selected = _parse_names_allowlist(allowlist) if allowlist is not None else None

    def refuse(reason: str) -> tuple[dict[str, bytes], dict[str, str], str]:
        if selected is not None:
            raise ValueError(f"name allowlist refused ({reason}); no package was produced")
        return dict(files), {}, reason

    if not files:
        return refuse("no-source-declarations") if selected is not None else ({}, {}, "")
    info, builtin = _ast_names(files, php)
    if set(info) != set(files) or any(entry["error"] for entry in info.values()):
        return refuse("ast-unparsable")
    if any(entry["dynamic"] for entry in info.values()):
        return refuse("dynamic")

    # PHP permits a class and function of the same FQN, but this report has just one key per FQN.
    # Refuse ambiguous/duplicate declarations instead of conflating their independent symbol tables.
    declared: dict[str, dict] = {}
    for name, entry in info.items():
        for decl in entry["decls"]:
            key = _php_name_key(decl["fqn"])
            if key in declared:
                return refuse("duplicate-name")
            declared[key] = {**decl, "file": name}

    if selected is not None:
        for (kind, key), item in selected.items():
            decl = declared.get(key)
            actual = "function" if decl and decl["kind"] == "function" else "type"
            if decl is None or kind != actual:
                raise ValueError(f"name allowlist symbol not declared with that kind: {item}")

    # A superclass or trait outside the pack can derive behaviour from the subclass's name. This is
    # also true for engine types (Exception::__toString, for example), and propagates to descendants.
    blocked: set[str] = set()
    for key, decl in declared.items():
        if decl["kind"] == "function":
            continue
        basename = decl["file"].replace("\\", "/").rsplit("/", 1)[-1]
        if _php_name_key(basename) == _php_name_key(decl["short"] + ".php"):
            blocked.add(key)  # PSR-4 convention; cannot prove there is no external autoloader
        for parent in decl.get("parents") or []:
            parent_decl = declared.get(_php_name_key(parent))
            if parent_decl is None or parent_decl["kind"] == "function":
                blocked.add(key)
    changed = True
    while changed:
        changed = False
        for key, decl in declared.items():
            if key not in blocked and any(_php_name_key(p) in blocked for p in (decl.get("parents") or [])):
                blocked.add(key)
                changed = True

    literals = [value.lower() for entry in info.values() for value in entry["strings"]]
    unresolved = {_php_name_key(u) for entry in info.values() for u in entry["unresolved"]}
    taken = {_php_name_key(d["short"]) for d in declared.values()}
    taken.update(_php_name_key(n.rsplit("\\", 1)[-1]) for n in builtin)
    for entry in info.values():
        taken.update(_php_name_key(u["alias"]) for u in entry["uses"])
        taken.update(_php_name_key(r["fqn"].rsplit("\\", 1)[-1]) for r in entry["refs"])
        taken.update(_php_name_key(u) for u in entry["unresolved"])

    renames: dict[str, str] = {}
    by_key: dict[str, str] = {}
    pool = "abcdefghijklmnopqrstuvwxyz0123456789"
    for key, decl in sorted(declared.items()):
        kind = "function" if decl["kind"] == "function" else "type"
        if selected is not None and (kind, key) not in selected:
            continue
        low = _php_name_key(decl["short"])
        if key in blocked or key in builtin or len(low) < 3 or low.startswith("__"):
            continue
        if decl["kind"] == "function" and low in unresolved:
            continue
        # bytes.lower folds only ASCII, matching PHP even for arbitrary bytes in a literal.
        if any(low.encode() in lit or key.encode() in lit for lit in literals):
            continue
        while True:
            short = "e" + "".join(secrets.choice(pool) for _ in range(5))
            if short not in taken:
                break
        taken.add(short)
        by_key[key] = short
        renames[decl["fqn"]] = short
    if selected is not None:
        skipped = [item for (_kind, key), item in selected.items() if key not in by_key]
        if skipped:
            raise ValueError("name allowlist symbol not eligible for safe renaming: " + ", ".join(skipped))
    if not renames:
        return dict(files), {}, ""

    out: dict[str, bytes] = {}
    for name, data in files.items():
        entry = info[name]
        patches: list[tuple[int, int, bytes]] = []

        def add_patch(item: dict, expected: str, replacement: bytes) -> bool:
            start, end = item["start"], item["end"]
            if (not isinstance(start, int) or not isinstance(end, int) or start < 0 or end <= start
                    or end > len(data) or data[start:end] != expected.encode()):
                return False
            patches.append((start, end, replacement))
            return True

        for decl in entry["decls"]:
            key = _php_name_key(decl["fqn"])
            if key in by_key and not add_patch(decl, decl["short"], by_key[key].encode()):
                return refuse("span-mismatch")

        for ref in entry["refs"]:
            key = _php_name_key(ref["fqn"])
            if key not in by_key:
                continue
            decl = declared[key]
            expected_kind = "function" if decl["kind"] == "function" else "type"
            if ref["kind"] != expected_kind:
                continue  # e.g. a constant with the same FQN as a class
            # A fully qualified replacement is independent of spelling, casing and use aliases.
            namespace, _, _ = decl["fqn"].rpartition("\\")
            new_fqn = "\\" + (namespace + "\\" if namespace else "") + by_key[key]
            if not add_patch(ref, ref["code"], new_fqn.encode()):
                return refuse("span-mismatch")

        for use in entry["uses"]:
            key = _php_name_key(use["fqn"])
            if key not in by_key or use["type"] == 3:
                continue  # a constant import is never an import of the similarly named class
            decl = declared[key]
            expected_type = 2 if decl["kind"] == "function" else 1
            if use["type"] != expected_type:
                continue
            # A class import may simultaneously serve as a prefix for a namespace (X\\Other).
            # Keep that import unchanged when it might be used that way; direct refs above are FQ.
            if any(_php_name_key(r["fqn"]).startswith(key + "\\") for r in entry["refs"]):
                continue
            code = use["code"]
            prefix = code.rpartition("\\")[0]
            replacement = ((prefix + "\\") if prefix else "") + by_key[key]
            if not use["explicit"]:
                replacement += " as " + use["alias"]  # preserve PHP's implicit alias
            if not add_patch(use, code, replacement.encode()):
                return refuse("span-mismatch")

        patches.sort()
        if any(patches[i][0] < patches[i - 1][1] for i in range(1, len(patches))):
            return refuse("overlapping")
        buf = bytearray(data)
        for start, end, replacement in reversed(patches):
            buf[start:end] = replacement
        candidate = bytes(buf)
        if candidate.count(b"\n") != data.count(b"\n"):
            return refuse("span-mismatch")
        if candidate != data and _php_lint_error_line(php, candidate) is not None:
            return refuse("lint")
        out[name] = candidate
    return out, renames, ""


def _names_pass(files: dict[str, bytes], php: str = "php", *, ast_names: bool = False,
                allowlist: list[str] | None = None) -> tuple[dict[str, bytes], dict[str, str], str]:
    """Rename eligible names across the pack; the experimental AST pass is opt-in.

    Without ``ast_names`` the legacy token pass declines namespaced packs. An explicit allowlist
    requires AST and bypasses the token pass even for global-namespace files, so it cannot be ignored.
    A lint failure rolls back the entire pack, never just an individual file.
    """
    if allowlist is not None:
        if not ast_names:
            raise ValueError("name allowlist requires --obfuscate-names-ast")
        return _ast_rename_names(files, php, allowlist=allowlist)
    res = _run_php(php, NAMES_PHP,
                   {"files": {name: base64.b64encode(data).decode() for name, data in files.items()}},
                   "--obfuscate-names")
    renamed = res.get("renamed") or {}
    if not renamed or "files" not in res:
        skipped = res.get("skipped") or ""
        if skipped == "namespaced" and ast_names:
            return _ast_rename_names(files, php)
        return files, {}, skipped
    out = {}
    for name, data in files.items():
        candidate = base64.b64decode(res["files"][name])
        if candidate == data:
            out[name] = data
            continue
        if _php_lint_error_line(php, candidate) is not None:
            # A single bad file invalidates the map for every file, including those already checked.
            return dict(files), {}, "lint"
        out[name] = candidate
    return out, renamed, ""



# Vendored nikic/php-parser (third_party/php-parser, BSD-3-Clause; third_party/README.md records the
# version, the commit it came from and how the manifest is verified). The token-stream passes cannot
# resolve a name across files: inside `namespace App\Model;` a bare `Widget` does not say WHICH
# Widget it is, and a `use App\Service\Thing;` makes `Thing` mean something else entirely. The
# default token pass therefore declines namespaced packages. Only with an additional explicit,
# experimental opt-in does the AST pass resolve names and apply replacements by byte offset.
# Offset patching preserves lines; reprinting the AST would move them and break stack-trace mapping.
# Static resolution cannot prove a closed world, detect every external consumer or update autoload
# maps: this experimental option must not be used on a framework/PSR-4/classmap application.
PHP_PARSER_LIB = Path(__file__).resolve().parent.parent / "third_party" / "php-parser" / "lib"

AST_PHP = r"""
if (PHP_VERSION_ID < 80000 || !function_exists("token_get_all")) { fwrite(STDERR, "needs PHP 8+ with tokenizer"); exit(2); }
$in = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$lib = $in["lib"] ?? "";
if (!is_dir($lib . "/PhpParser")) { fwrite(STDERR, "vendored php-parser missing under " . $lib); exit(2); }
spl_autoload_register(function ($class) use ($lib) {
    if (strncmp($class, 'PhpParser\\', 10) !== 0) return;
    $f = $lib . "/" . str_replace('\\', '/', $class) . ".php";
    if (is_file($f)) require $f;
});
error_reporting(E_ALL & ~E_DEPRECATED);
$parser = (new PhpParser\ParserFactory)->createForNewestSupportedVersion();
// Preserve the written Name node and its exact byte span. NameResolver attaches resolvedName rather
// than replacing the node, so the collector can distinguish a function, constant and class even
// when PHP permits all three to have the same fully-qualified spelling.
$resolver = new PhpParser\NodeVisitor\NameResolver(null, ["replaceNodes" => false]);
$collector = new class extends PhpParser\NodeVisitorAbstract {
    public array $decls = [];
    public array $refs = [];
    public array $uses = [];
    public array $strings = [];  // base64, because PHP strings may contain arbitrary non-UTF-8 bytes
    public bool $dynamic = false;
    public array $unresolved = [];
    public array $stack = [];
    public array $declIndex = [];
    private function resolved(PhpParser\Node\Name $name): string {
        $r = $name->getAttribute("resolvedName");
        return $r instanceof PhpParser\Node\Name ? $r->toString() : $name->toString();
    }
    public function enterNode(PhpParser\Node $node) {
        $parent = $this->stack ? $this->stack[count($this->stack) - 1] : null;
        if (($node instanceof PhpParser\Node\Stmt\ClassLike || $node instanceof PhpParser\Node\Stmt\Function_)
                && $node->name !== null) {
            $kind = $node instanceof PhpParser\Node\Stmt\Class_ ? "class"
                  : ($node instanceof PhpParser\Node\Stmt\Interface_ ? "interface"
                  : ($node instanceof PhpParser\Node\Stmt\Trait_ ? "trait"
                  : ($node instanceof PhpParser\Node\Stmt\Enum_ ? "enum" : "function")));
            $fqn = isset($node->namespacedName) ? $node->namespacedName->toString() : (string)$node->name;
            $parents = [];
            if (isset($node->extends)) {
                foreach (is_array($node->extends) ? $node->extends : [$node->extends] as $e) {
                    $parents[] = $this->resolved($e);
                }
            }
            if (isset($node->implements)) {
                foreach ($node->implements as $i) $parents[] = $this->resolved($i);
            }
            $this->declIndex[spl_object_id($node)] = count($this->decls);
            $this->decls[] = ["kind" => $kind, "short" => (string)$node->name, "fqn" => $fqn,
                              "start" => $node->name->getStartFilePos(),
                              "end" => $node->name->getEndFilePos() + 1, "parents" => $parents];
        }
        if ($node instanceof PhpParser\Node\Stmt\TraitUse) {
            // A trait outside the pack may depend on the using class's name, just like a parent.
            foreach (array_reverse($this->stack) as $owner) {
                if ($owner instanceof PhpParser\Node\Stmt\ClassLike) {
                    $index = $this->declIndex[spl_object_id($owner)] ?? null;
                    if ($index !== null) {
                        foreach ($node->traits as $trait) $this->decls[$index]["parents"][] = $this->resolved($trait);
                    }
                    break;
                }
            }
        }
        if ($node instanceof PhpParser\Node\Stmt\Use_ || $node instanceof PhpParser\Node\Stmt\GroupUse) {
            $group = $node instanceof PhpParser\Node\Stmt\GroupUse ? $node->prefix->toString() . "\\" : "";
            foreach ($node->uses as $u) {
                $this->uses[] = ["type" => $u->type ?: $node->type,
                                 "fqn" => $group . $u->name->toString(),
                                 "alias" => (string)$u->getAlias(), "explicit" => $u->alias !== null,
                                 "code" => $u->name->toCodeString(),
                                 "start" => $u->name->getStartFilePos(),
                                 "end" => $u->name->getEndFilePos() + 1];
            }
        }
        if ($node instanceof PhpParser\Node\Scalar\String_) $this->strings[] = base64_encode($node->value);
        if (($node instanceof PhpParser\Node\Expr\FuncCall || $node instanceof PhpParser\Node\Expr\ConstFetch)
                && $node->name instanceof PhpParser\Node\Name && $node->name->isUnqualified()
                && !($node->name->getAttribute("resolvedName") instanceof PhpParser\Node\Name)) {
            // PHP may fall back to the global function/constant. The name cannot be safely resolved.
            $this->unresolved[] = (string)$node->name;
        }
        // Names can be observed or reached without a static reference. These checks are conservative
        // and intentionally decline the entire experimental pass; they do not prove a closed world.
        if ($node instanceof PhpParser\Node\Scalar\InterpolatedString
                || $node instanceof PhpParser\Node\Expr\Eval_
                || $node instanceof PhpParser\Node\Expr\Throw_
                || $node instanceof PhpParser\Node\Stmt\TryCatch
                || $node instanceof PhpParser\Node\Stmt\Global_
                || $node instanceof PhpParser\Node\Stmt\HaltCompiler
                || $node instanceof PhpParser\Node\Attribute
                || $node instanceof PhpParser\Node\Scalar\MagicConst\Class_
                || $node instanceof PhpParser\Node\Scalar\MagicConst\Trait_
                || $node instanceof PhpParser\Node\Scalar\MagicConst\Method
                || $node instanceof PhpParser\Node\Scalar\MagicConst\Function_
                || ($node instanceof PhpParser\Node\Expr\FuncCall && !($node->name instanceof PhpParser\Node\Name))
                || (($node instanceof PhpParser\Node\Expr\StaticCall || $node instanceof PhpParser\Node\Expr\MethodCall
                     || $node instanceof PhpParser\Node\Expr\NullsafeMethodCall)
                    && !($node->name instanceof PhpParser\Node\Identifier))
                || (($node instanceof PhpParser\Node\Expr\New_ || $node instanceof PhpParser\Node\Expr\Instanceof_
                     || $node instanceof PhpParser\Node\Expr\StaticCall || $node instanceof PhpParser\Node\Expr\StaticPropertyFetch
                     || $node instanceof PhpParser\Node\Expr\ClassConstFetch) && !($node->class instanceof PhpParser\Node\Name))
                || ($node instanceof PhpParser\Node\Expr\ClassConstFetch && $node->name instanceof PhpParser\Node\Identifier
                     && strtolower((string)$node->name) === "class")) $this->dynamic = true;
        if ($node instanceof PhpParser\Node\Expr\New_ && $node->class instanceof PhpParser\Node\Name) {
            // These constructors consume a callback assembled from otherwise harmless fragments.
            $callbackTypes = ["fiber", "callbackfilteriterator", "recursivecallbackfilteriterator"];
            if (in_array(strtolower($node->class->getLast()), $callbackTypes, true)
                    || in_array(strtolower(basename(str_replace('\\', '/', $this->resolved($node->class)))),
                                $callbackTypes, true)) $this->dynamic = true;
        }
        if ($node instanceof PhpParser\Node\Expr\FuncCall && $node->name instanceof PhpParser\Node\Name) {
            $sensitive = ["spl_autoload_register", "spl_autoload_call", "class_exists", "interface_exists",
                "trait_exists", "enum_exists", "class_alias", "function_exists", "method_exists", "property_exists",
                "is_callable", "constant", "defined", "get_class", "get_called_class", "get_parent_class",
                "get_debug_type", "get_declared_classes", "get_declared_interfaces", "get_declared_traits",
                "get_defined_functions", "get_class_methods", "get_class_vars", "class_implements", "class_parents",
                "class_uses", "is_a", "is_subclass_of", "serialize", "unserialize", "var_dump", "var_export",
                "print_r", "debug_backtrace", "debug_print_backtrace", "call_user_func", "call_user_func_array",
                "forward_static_call", "forward_static_call_array", "array_map", "array_filter", "array_reduce",
                "array_walk", "array_walk_recursive", "array_udiff", "array_udiff_assoc", "array_udiff_uassoc",
                "array_diff_uassoc", "array_diff_ukey", "array_uintersect", "array_uintersect_assoc",
                "array_uintersect_uassoc", "array_intersect_uassoc", "array_intersect_ukey", "array_find",
                "array_find_key", "array_any", "array_all", "iterator_apply", "stream_wrapper_register",
                "stream_register_wrapper", "stream_filter_register", "header_register_callback",
                "session_set_save_handler", "usort", "uasort", "uksort", "preg_replace_callback",
                "preg_replace_callback_array", "register_shutdown_function", "register_tick_function",
                "set_error_handler", "set_exception_handler", "ob_start"];
            if (in_array(strtolower($node->name->getLast()), $sensitive, true)
                    || in_array(strtolower(basename(str_replace('\\', '/', $this->resolved($node->name)))), $sensitive, true)) {
                $this->dynamic = true;
            }
        }
        // Closure binding/callable creation can consume assembled names. Throwable methods can
        // expose original function/class names via messages and traces, including exceptions passed
        // in from outside this file. Without type inference we reject these names on any receiver.
        if (($node instanceof PhpParser\Node\Expr\StaticCall || $node instanceof PhpParser\Node\Expr\MethodCall
             || $node instanceof PhpParser\Node\Expr\NullsafeMethodCall)
                && $node->name instanceof PhpParser\Node\Identifier
                && in_array(strtolower((string)$node->name), ["fromcallable", "bind", "bindto", "call",
                    "gettrace", "gettraceasstring", "getmessage", "getprevious", "__tostring"], true)) {
            $this->dynamic = true;
        }
        if (($node instanceof PhpParser\Node\Expr\New_ || $node instanceof PhpParser\Node\Expr\StaticCall)
                && $node->class instanceof PhpParser\Node\Name) {
            $class = strtolower(basename(str_replace('\\', '/', $this->resolved($node->class))));
            if (str_starts_with($class, "reflection")) $this->dynamic = true;
        }
        if ($node instanceof PhpParser\Node\Name
                && !($parent instanceof PhpParser\Node\UseItem)
                && !($parent instanceof PhpParser\Node\Stmt\GroupUse)
                && !($parent instanceof PhpParser\Node\Stmt\Namespace_)) {
            $resolved = $node->getAttribute("resolvedName");
            if ($resolved instanceof PhpParser\Node\Name) {
                $kind = ($parent instanceof PhpParser\Node\Expr\FuncCall && $parent->name === $node) ? "function"
                      : (($parent instanceof PhpParser\Node\Expr\ConstFetch && $parent->name === $node) ? "constant" : "type");
                $this->refs[] = ["kind" => $kind, "fqn" => $resolved->toString(), "code" => $node->toCodeString(),
                                 "start" => $node->getStartFilePos(), "end" => $node->getEndFilePos() + 1];
            }
        }
        $this->stack[] = $node;
        return null;
    }
    public function leaveNode(PhpParser\Node $node) { array_pop($this->stack); return null; }
};
$traverser = new PhpParser\NodeTraverser($resolver, $collector);
$out = [];
foreach ($in["files"] as $name => $b64) {
    $code = base64_decode($b64, true);
    $collector->decls = []; $collector->refs = []; $collector->uses = []; $collector->strings = [];
    $collector->dynamic = false; $collector->unresolved = []; $collector->stack = []; $collector->declIndex = [];
    try {
        $ast = $parser->parse($code);
        if ($ast === null) { $out[$name] = ["error" => "parser returned no statements"]; continue; }
        $traverser->traverse($ast);
        // Framework annotations and external consumers can read docblocks. Protect names mentioned
        // in them just as conservatively as names in string literals.
        foreach (token_get_all($code) as $token) {
            if (is_array($token) && $token[0] === T_DOC_COMMENT) $collector->strings[] = base64_encode($token[1]);
        }
        $entry = ["decls" => $collector->decls, "refs" => $collector->refs, "uses" => $collector->uses,
                  "strings" => $collector->strings, "dynamic" => $collector->dynamic, "unresolved" => $collector->unresolved];
        // Non-UTF-8 identifiers are legal in PHP, but not representable in this JSON name protocol.
        // Fail closed per file rather than replacing their bytes and trusting the wrong spans.
        json_encode($entry, JSON_THROW_ON_ERROR);
        $out[$name] = $entry;
    } catch (PhpParser\Error $e) {
        $out[$name] = ["error" => "parse or name-resolution error"];
    } catch (JsonException $e) {
        $out[$name] = ["error" => "non-UTF-8 identifier in AST metadata"];
    }
}
$builtin = [];
$groups = [get_declared_classes(), get_declared_interfaces(), get_declared_traits()];
if (function_exists("get_declared_enums")) $groups[] = get_declared_enums();
foreach ($groups as $group) { foreach ($group as $c) $builtin[strtolower($c)] = true; }
foreach (get_defined_functions()["internal"] as $f) $builtin[strtolower($f)] = true;
foreach (get_defined_constants() as $k => $v) $builtin[strtolower($k)] = true;
echo json_encode(["files" => $out, "builtin" => array_keys($builtin)], JSON_THROW_ON_ERROR);
"""


def _ast_names(files: dict[str, bytes], php: str = "php") -> tuple[dict[str, dict], set[str]]:
    """Per-file name map from the vendored parser, plus the running PHP's own names (lowercase).

    The map is {file: {"decls", "refs", "uses", "strings", "unresolved", "dynamic", "error"}}.

    Declarations and typed references carry byte spans into their own source file; string and
    docblock values are returned as bytes because PHP strings need not be valid UTF-8. Parsing or
    name-resolution failures are reported on the corresponding file rather than partly applying a
    rename. The separate set contains names already present in the running PHP symbol table.
    """
    res = _run_php(php, AST_PHP,
                   {"lib": str(PHP_PARSER_LIB),
                    "files": {n: base64.b64encode(d).decode() for n, d in files.items()}},
                   "--ast-names")
    out: dict[str, dict] = {}
    for name, entry in (res.get("files") or {}).items():
        out[name] = {"decls": entry.get("decls") or [], "refs": entry.get("refs") or [],
                     "uses": entry.get("uses") or [],
                     "strings": [base64.b64decode(s) for s in (entry.get("strings") or [])],
                     "unresolved": entry.get("unresolved") or [],
                     "dynamic": bool(entry.get("dynamic")), "error": entry.get("error")}
    return out, {n.lower() for n in (res.get("builtin") or [])}


# Moves runtime string literals into a per-file vault resolved by \__envelock_lit(idx). Literals
# in constant expressions remain inline; _vault_pass retries lines that would fail php -l, keeping
# the source and line numbers intact. Name analysis runs first so the vault cannot hide a name.
VAULT_PHP = r"""
if (PHP_VERSION_ID < 80000 || !function_exists("token_get_all")) { fwrite(STDERR, "needs PHP 8+ with tokenizer"); exit(2); }
error_reporting(E_ALL & ~E_DEPRECATED);   // our own JSON-only program; see TRANSFORM_PHP note
$in = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$skip = array_flip([T_WHITESPACE, T_COMMENT, T_DOC_COMMENT]);
$out = []; $lits = []; $lines = []; $halted = [];
foreach ($in["files"] as $name => $b64) {
    $code = base64_decode($b64, true);
    try { $raw = token_get_all($code, TOKEN_PARSE); }
    catch (ParseError $e) { fwrite(STDERR, $name . ": " . $e->getMessage()); exit(3); }
    $t = [];
    foreach ($raw as $x) $t[] = is_array($x) ? [$x[0], $x[1], $x[2]] : [null, $x, 0];
    $n = count($t);
    // __halt_compiler() leaves raw trailing data the tokenizer drops: never rewrite such a file.
    foreach ($t as [$id,,]) { if ($id === T_HALT_COMPILER) { $out[$name] = $b64; $lits[$name] = []; $lines[$name] = []; $halted[$name] = true; continue 2; } }
    $next = function (int $i) use ($t, $n, $skip): int {
        for ($i++; $i < $n && $t[$i][0] !== null && isset($skip[$t[$i][0]]); $i++);
        return $i;
    };
    $excl = array_flip($in["exclude"][$name] ?? []);
    $unsafe = array_fill(0, $n, false);
    $markTo = function (int $from, int $to) use (&$unsafe) { for ($k = $from; $k <= $to; $k++) $unsafe[$k] = true; };
    for ($i = 0; $i < $n; $i++) {
        $id = $t[$i][0]; $c = $t[$i][1];
        if ($id === T_ATTRIBUTE) {                                   // #[ ... ] : constant args
            for ($d = 0, $j = $i; $j < $n; $j++) {
                $cj = $t[$j][1];
                if ($t[$j][0] === T_ATTRIBUTE || $cj === "[") $d++;
                elseif ($cj === "]" && --$d === 0) break;
            }
            $markTo($i, min($j, $n - 1)); $i = $j;
        } elseif ($id === T_DECLARE) {                               // declare( ... ) : constant
            for ($j = $i; $j < $n && $t[$j][1] !== "("; $j++);
            for ($d = 0; $j < $n; $j++) { $cj = $t[$j][1]; if ($cj === "(") $d++; elseif ($cj === ")" && --$d === 0) break; }
            $markTo($i, min($j, $n - 1)); $i = $j;
        } elseif ($id === T_CONST) {                                 // const NAME = <const expr> ;
            for ($j = $i; $j < $n && $t[$j][1] !== ";"; $j++);
            $markTo($i, min($j, $n - 1)); $i = $j;
        } elseif ($id === T_FUNCTION || $id === T_FN) {              // signature (...) : default values
            $j = $next($i);
            if ($j < $n && $t[$j][1] === "&") $j = $next($j);
            if ($j < $n && $t[$j][0] === T_STRING) $j = $next($j);
            if ($j < $n && $t[$j][1] === "(") {
                for ($d = 0; $j < $n; $j++) { $cj = $t[$j][1]; if ($cj === "(") $d++; elseif ($cj === ")" && --$d === 0) break; }
                $markTo($i, min($j, $n - 1)); $i = $j;
            }
        } elseif ($id === T_STATIC) {                                // static $v = <const expr> ; (local)
            $j = $next($i);
            if ($j < $n && $t[$j][0] === T_VARIABLE) {
                for ($k = $j; $k < $n && $t[$k][1] !== ";"; $k++);
                $markTo($i, min($k, $n - 1)); $i = $k;
            }
        }
    }
    $vals = []; $seen = []; $vlines = [];
    for ($i = 0; $i < $n; $i++) {
        if ($t[$i][0] !== T_CONSTANT_ENCAPSED_STRING || $unsafe[$i] || isset($excl[$t[$i][2]])) continue;
        $val = eval("return " . $t[$i][1] . ";");                    // a pure literal: no side effects
        if (!is_string($val) || strlen($val) < 2) continue;          // keep empty/1-char inline (cheap, low value)
        $key = "\0" . $val;                                          // force a string key (binary-safe, no int cast)
        if (isset($seen[$key])) { $idx = $seen[$key]; }              // one entry per distinct value (dedup)
        else { $idx = count($vals); $vals[] = base64_encode($val); $seen[$key] = $idx; }
        $vlines[$t[$i][2]] = true;                                   // line this literal was vaulted on
        $t[$i][1] = '\\__envelock_lit(' . $idx . ')' . str_repeat("\n", substr_count($t[$i][1], "\n"));
    }
    $result = "";
    foreach ($t as [, $c,]) $result .= $c;
    try { token_get_all($result, TOKEN_PARSE); }
    catch (ParseError $e) { fwrite(STDERR, $name . ": vault broke the file: " . $e->getMessage()); exit(3); }
    $out[$name] = base64_encode($result); $lits[$name] = $vals;
    $ln = array_keys($vlines); sort($ln); $lines[$name] = $ln;      // ascending lines with a vaulted literal
}
echo json_encode(["files" => $out, "lits" => $lits, "lines" => $lines, "halted" => array_keys($halted)], JSON_THROW_ON_ERROR);
"""


def _vault_pass(files: dict[str, bytes], php: str = "php"
                ) -> tuple[dict[str, bytes], dict[str, list[bytes]], list[str]]:
    """Replace runtime-position string literals with \\__envelock_lit(idx) calls and return the
    rewritten sources plus each file's ordered literal table (raw bytes). A literal that lands in a
    constant-expression context the state machine does not model (a property default, an enum case)
    makes `php -l` fatal; that file's failing line is excluded and the pass re-runs, so a broken
    file can never be produced. Line numbers are preserved (the call carries the literal's newlines),
    which keeps the re-run's line exclusions valid."""
    exclude: dict[str, list[int]] = {name: [] for name in files}
    halted_names: set[str] = set()    # files with __halt_compiler(): passed through unvaulted (ENV-08)
    done: set[str] = set()            # files that lint clean (their excludes no longer change)
    inline: set[str] = set()          # files left entirely unvaulted (see GIVE_UP)
    GIVE_UP = 64                      # a file needing more exclusions than this has pathologically
    # many constant-expression literals: leave it entirely inline (safe, bounded) instead of
    # relinting it O(N) times. This avoids the quadratic re-lint and the old "fails with >1000
    # literals" determinism bug (external audit ENV-AUD-13); clean files are not relinted either.
    for _ in range(len(files) * (GIVE_UP + 1) + 2):
        active = {name: base64.b64encode(files[name]).decode() for name in files if name not in inline}
        exc = {name: exclude[name] for name in active}
        res = _run_php(php, VAULT_PHP, {"files": active, "exclude": exc}, "--vault-strings") if active else {"files": {}, "lits": {}, "lines": {}, "halted": []}
        halted_names.update(res.get("halted", []))
        vaulted = {name: (files[name] if name in inline else base64.b64decode(res["files"][name]))
                   for name in files}
        progressed = False
        for name in files:
            if name in done:
                continue
            line = _php_lint_error_line(php, vaulted[name])
            if line is None:
                done.add(name)
                continue
            if len(exclude[name]) >= GIVE_UP:
                # Pathological file (very many constant-expression literals, e.g. typed properties).
                # FAIL CLOSED: the operator asked to vault strings, so silently shipping this file's
                # secrets inline while reporting success would be a hidden downgrade (ENV-2026-29).
                raise ValueError(
                    f"--vault-strings could not vault all literals in {name} (too many constant-"
                    f"expression literals, e.g. typed/static properties). Refusing to leave its "
                    f"strings in cleartext: --exclude this file from --vault-strings, or move its "
                    f"literals out of property/constant initialisers.")
            # `php -l` anchors a constant-expression fatal at the START of the declaration (the
            # `public`/`case`/... line), while the offending literal is at or below it. Exclude the
            # first vaulted literal line >= the error line (the offender); fall back to the error
            # line. Converges even for multi-line property/enum declarations.
            after = [ln for ln in res["lines"][name] if ln >= line and ln not in exclude[name]]
            target = min(after) if after else line
            if target not in exclude[name]:
                exclude[name].append(target)
                progressed = True
            else:
                raise ValueError(f"--vault-strings could not produce a file that compiles: {name}")
        if len(done) == len(files):
            # Fail-closed re-lint: a broken file must never be produced.
            for name in files:
                if _php_lint_error_line(php, vaulted[name]) is not None:
                    raise ValueError(f"--vault-strings could not produce a file that compiles: {name}")
            lits = {name: ([] if name in inline else [base64.b64decode(v) for v in res["lits"][name]])
                    for name in files}
            return vaulted, lits, sorted(halted_names)
        if not progressed:
            raise ValueError("--vault-strings could not produce a file that compiles")
    raise ValueError("--vault-strings could not produce a file that compiles")


# Compiles each file's source into a serialized zend_op_array (objective O1), so a protected file
# carries bytecode and no PHP source at all: on the server nothing is ever handed to the compiler,
# which closes the attack on zend_compile_file.
#
# The catch that dictates the whole design: __DIR__, __FILE__ and the path of a statically resolved
# include are COMPILE-TIME values. They are baked into the image as the absolute path the file had
# while being compiled, so an image compiled anywhere else runs with the packer's paths — a
# require() of a sibling file simply does not find it. This is inherent to precompiled bytecode
# (OPcache's own file cache is bound to an absolute path the same way), not a flaw of this format.
# So the sources are compiled AT their deploy path, which --deploy-root states, and the resulting
# package only runs from there. It needs the target server's PHP version and build, with a pack-time
# Envelock loader (envelock_bc_emit) loaded: the image is bound to that build's bytecode identity
# (version, Zend extension build id, data layout, VM kind; not zend_system_id, so it does not depend
# on the SAPI) and any other build refuses it.
BYTECODE_PHP = r"""
if (!function_exists("envelock_bc_emit")) { fwrite(STDERR, "envelock_bc_emit missing: --bytecode needs a pack-time build of the Envelock loader with the emitter (--enable-envelock-bcemit, docs/BUILDING.md), given with --bytecode-loader; the production loaders, the prebuilt ones included, have none"); exit(2); }
$in = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$out = [];
foreach ($in["files"] as $name => $path) {
    $image = @envelock_bc_emit($path);
    if (!is_string($image)) { fwrite(STDERR, $name . ": the PHP build refused to compile this file to bytecode"); exit(3); }
    $out[$name] = base64_encode($image);
}
echo json_encode($out);
"""


# Files emitted per PHP process in _bytecode_pass. Bounds the emitter's peak memory on large trees
# (a single process emitting the whole tree runs out of memory); each process exits and frees between
# batches. 500 emits fine within PHP's default memory on the CMSs tested.
BYTECODE_BATCH = 500


def _bytecode_pass(files: dict[str, bytes], deploy_root: Path, php: str = "php",
                   loader: str | None = None) -> dict[str, bytes]:
    """Compile every source into its bytecode image, at its deploy path (see the note above).

    The sources are written under deploy_root, compiled there and removed again; nothing that was
    already there is touched, and a path that exists is refused rather than overwritten. loader:
    path of the Envelock loader module to load into that php CLI when its configuration does not
    already enable it."""
    if not deploy_root.is_absolute():
        raise ValueError("--deploy-root must be an absolute path: __DIR__ and __FILE__ are baked "
                         "into the bytecode as absolute paths")
    created: list[Path] = []
    created_dirs: set[Path] = set()
    try:
        paths: dict[str, str] = {}
        # Record the directories THIS pass creates (deploy_root itself if missing, and folders below
        # it). The cleanup removes only these, never a directory that was already there — a
        # pre-existing deploy_root must survive a pass that fails or finds it empty (audit ENV-04).
        if not deploy_root.exists():
            deploy_root.mkdir(parents=True)
            created_dirs.add(deploy_root)
        for name, data in files.items():
            target = deploy_root / name
            # Below the deploy root, never write THROUGH a link or junction (ENC-5): a folder that
            # is one would put the plaintext wherever it points. Missing folders are created here,
            # owner-only on POSIX.
            probe = deploy_root
            for part in Path(name).parts[:-1]:
                probe = probe / part
                try:
                    info = os.lstat(probe)
                except FileNotFoundError:
                    probe.mkdir(mode=0o700)
                    created_dirs.add(probe)
                    continue
                if _is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
                    raise ValueError(f"--bytecode refuses to write {name} through {probe}: it is a "
                                     "link, junction or file, not a plain folder under the deploy root")
            # These are the plaintext sources, on disk only while they compile. Create each one
            # read/write for the owner alone and atomically (O_EXCL / CREATE_NEW): that closes the
            # window in which another local user could read the source, and refuses to overwrite
            # anything already at the deploy path. On Windows 0600 means nothing: the file is made
            # with an owner-only protected ACL instead of the deploy folder's inherited one (e.g.
            # inetpub\wwwroot, readable and servable while it compiles, ENC-5).
            try:
                if os.name == "nt":
                    fd = _windows_create_new(target, f"D:P(A;;FA;;;{_current_user_sid_string()})")
                else:
                    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
            except FileExistsError:
                raise ValueError(f"--bytecode needs to compile {name} at its deploy path, but "
                                 f"{target} already exists; pack from a clean deploy root") from None
            created.append(target)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            paths[name] = str(target)
        # A build step, not runtime: lift memory_limit so a batch is not capped by the host's PHP
        # setting (the batch size, not memory_limit, is what bounds peak memory here).
        extra = ["-d", "memory_limit=-1"]
        if loader:
            extra = ["-n", "-d", "memory_limit=-1", "-d", f"extension={loader}"]
        # Emit in batches, one PHP process per batch. Emitting every file in a single process
        # accumulates each compiled op_array in that process and runs out of memory on large trees
        # (tens of thousands of files, e.g. a full CMS); a batch releases its memory when the
        # process exits. Each file compiles independently, so batching changes nothing in the output.
        images: dict[str, str] = {}
        items = list(paths.items())
        for start in range(0, len(items), BYTECODE_BATCH):
            batch = dict(items[start:start + BYTECODE_BATCH])
            images.update(_run_php(php, BYTECODE_PHP, {"files": batch}, "--bytecode", extra_args=extra))
        return {name: base64.b64decode(data) for name, data in images.items()}
    finally:
        # Remove what this pass wrote, deepest first: the source files, then ONLY the directories it
        # created (never a pre-existing one), and those only if empty. A pack must not leave sources
        # behind at the deploy path, nor delete anything it did not create (audit ENV-04).
        for target in sorted(created, key=lambda p: len(p.parts), reverse=True):
            target.unlink(missing_ok=True)
        for directory in sorted(created_dirs, key=lambda p: len(p.parts), reverse=True):
            try:
                directory.rmdir()
            except OSError:
                pass            # not empty (something else is there) or already gone: leave it


VAULT_INFO = b"envelock-vault-1"


def _vault_plaintext_encrypted(table: list[bytes], source: bytes, content_key: bytes) -> bytes:
    """Plaintext of a vaulted file with the table encrypted (objective O7).

    u32 table_bytes | u32 count | key_nonce 12 | wrapped_key 48 | [u32 len | nonce 12 | tag 16 |
    ciphertext len]* | source — all big-endian, `len` counting nonce+tag+ciphertext.

    Why encrypt a table that already sits inside an encrypted container: the container is decrypted
    once, at load, and from then on its plaintext is in memory for the whole request — the vault
    table included, every literal at once. Encrypting the table means the decrypted container holds
    ciphertext, and a literal becomes plaintext only when the program actually reads it, one entry
    at a time, wiped again at the end of the request like the rest. It does not survive a reader
    who can run the code or dump the process at the right moment, and it is not meant to; it
    removes the property that asked for the least effort to exploit, which was that every secret
    string in the file was lying in one contiguous, already-decrypted block.

    The data key is wrapped with the package content key, so a new one per file and per pack: a
    reader who can decrypt the container can unwrap it, which is the honest limit, but nothing is
    left in the clear for a reader who cannot.
    """
    data_key = secrets.token_bytes(32)
    # The content key also encrypts each file with a counter nonce (protect(), top bit of byte 0
    # always clear). This wrap shares that key, so its nonce is forced into the disjoint half with
    # the top bit set: a content-key nonce can never be reused across the two domains. The loader
    # reads the nonce verbatim, so this needs no loader change and does not alter the format.
    key_nonce = bytes([secrets.token_bytes(1)[0] | 0x80]) + secrets.token_bytes(11)
    wrapped = AESGCM(content_key).encrypt(key_nonce, data_key, VAULT_INFO)   # 32 + 16 = 48
    cipher = AESGCM(data_key)
    body = len(table).to_bytes(4, "big") + key_nonce + wrapped
    for value in table:
        nonce = secrets.token_bytes(12)
        sealed = cipher.encrypt(nonce, value, VAULT_INFO)        # ciphertext + 16-byte tag
        # `length` covers nonce + ciphertext + tag, which is every byte that follows it. Writing
        # len(sealed) here — as a first draft did — leaves the reader unable to tell where the
        # nonce stops, and its "at least 12 + 16" sanity bound rejects the whole table.
        body += (12 + len(sealed)).to_bytes(4, "big") + nonce + sealed
    return len(body).to_bytes(4, "big") + body + source


def _vault_plaintext(table: list[bytes], source: bytes) -> bytes:
    """Plaintext of a vaulted file: u32 table_bytes | table | source, where
    table = u32 count | [u32 len | bytes]* (all big-endian). The loader strips this prefix, registers
    the table under the file and compiles only the source."""
    body = len(table).to_bytes(4, "big")
    for value in table:
        body += len(value).to_bytes(4, "big") + value
    return len(body).to_bytes(4, "big") + body + source


def _php_lint_error_line(php: str, source: bytes) -> int | None:
    """Return the 1-based line of the first `php -l` error for this source, or None if it lints
    clean. `php -l` catches the constant-expression fatals a vaulted literal can cause.

    The source goes to `php -l` on STDIN ("Standard input code"): it is transformed PLAINTEXT, and
    a named temporary file left it on disk in the shared temp folder, with the folder's ACL on
    Windows and behind if the process was killed (ENC-16)."""
    try:
        exe = resolve_program(php)
    except ValueError as error:
        raise ValueError(f"--vault-strings could not lint a transformed file: {error}") from None
    try:
        result = subprocess.run(  # nosec B603 # fixed argument list, no shell
            [exe, "-n", "-d", "display_errors=stderr", "-l"], input=source, capture_output=True,
            timeout=120, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"--vault-strings could not lint a transformed file: {error}") from error
    if result.returncode == 0:
        return None
    text = (result.stderr + result.stdout).decode(errors="replace")
    match = re.search(r" on line (\d+)", text)
    if match:
        return int(match.group(1))
    raise ValueError("--vault-strings: a transformed file failed to compile: " + text.strip()[-300:])


def transform_sources(files: dict[str, bytes], php: str = "php", strip: bool = False,
                      obfuscate: bool = False, compact: bool = False,
                      encode_strings: bool = False, methods: bool = False,
                      properties: bool = False, obfuscate_flow: bool = False
                      ) -> tuple[dict[str, bytes], list[str]]:
    """Strip comments/docblocks, obfuscate local variable names, rename private methods/properties,
    compact whitespace and/or encode string literals as \\xNN escapes with the given php CLI (PHP 8+
    with tokenizer). strip/obfuscate/methods/properties/encode_strings keep behaviour and line
    numbers; compact collapses whitespace (line numbers not preserved). properties is HIGH RISK
    (serialized objects). Invalid files are refused. The literal vault is a separate pass
    (_vault_pass), run by pack_tree before these, because it needs each file's literal table."""
    res = _run_php(php, TRANSFORM_PHP,
                   {"strip": strip, "obfuscate": obfuscate, "compact": compact,
                    "encode_strings": encode_strings, "methods": methods, "properties": properties,
                    "obfuscate_flow": obfuscate_flow,
                    "files": {name: base64.b64encode(data).decode() for name, data in files.items()}},
                   "--strip-comments/--obfuscate")
    # "halted": files containing __halt_compiler() that the token rewriter cannot rebuild and so
    # passed through UNTRANSFORMED (ENV-08). Returned so the caller records it honestly instead of
    # the manifest claiming a protection that was not applied to those files.
    return ({name: base64.b64decode(data) for name, data in res["files"].items()},
            list(res.get("halted", [])))



# O6, control-flow flattening (opt-in, --obfuscate-flatten). Each named function or method body whose
# top-level statements are plain code becomes a dispatch loop: `while(true){switch($state){case 0: ...}}`.
# The statements keep their own text and order; only the labels and state assignments are added, on
# the same lines, so line numbers do not change. The parser supplies the statement byte spans and the
# PHP side re-parses the result, so a wrong edit is refused instead of shipped. A function is left as
# it is when a statement could depend on the dispatcher: yield (generators), goto or labels, nested
# declarations, include/eval, dynamic variable names, compact/extract/get_defined_vars/parse_str, or a
# declare. Those are the constructs that observe or reshape the frame, so the state variable would be
# visible to them.
FLATTEN_PHP = r"""
if (PHP_VERSION_ID < 80000) { fwrite(STDERR, "needs PHP 8+"); exit(2); }
$in = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$lib = $in["lib"] ?? "";
if (!is_dir($lib . "/PhpParser")) { fwrite(STDERR, "vendored php-parser missing under " . $lib); exit(2); }
spl_autoload_register(function ($class) use ($lib) {
    if (strncmp($class, 'PhpParser\\', 10) !== 0) return;
    $f = $lib . "/" . str_replace('\\', '/', $class) . ".php";
    if (is_file($f)) require $f;
});
error_reporting(E_ALL & ~E_DEPRECATED);
$parser = (new PhpParser\ParserFactory)->createForNewestSupportedVersion();
$frame = ['compact', 'extract', 'get_defined_vars', 'parse_str', 'mb_parse_str'];
$state = '$__envlk_st';
class EnvFlattenEligibility extends PhpParser\NodeVisitorAbstract {
    public $reason = '';
    public function __construct(private array $frame) {}
    private function bad(string $why): void { if ($this->reason === '') $this->reason = $why; }
    public function enterNode(PhpParser\Node $node) {
        if ($node instanceof PhpParser\Node\Expr\Yield_ || $node instanceof PhpParser\Node\Expr\YieldFrom) $this->bad('generator');
        elseif ($node instanceof PhpParser\Node\Stmt\Goto_ || $node instanceof PhpParser\Node\Stmt\Label) $this->bad('goto');
        elseif ($node instanceof PhpParser\Node\Stmt\Function_ || $node instanceof PhpParser\Node\Stmt\ClassLike) $this->bad('declaration');
        elseif ($node instanceof PhpParser\Node\Stmt\Const_ || $node instanceof PhpParser\Node\Stmt\Namespace_
                || $node instanceof PhpParser\Node\Stmt\Use_ || $node instanceof PhpParser\Node\Stmt\GroupUse
                || $node instanceof PhpParser\Node\Stmt\Declare_ || $node instanceof PhpParser\Node\Stmt\HaltCompiler) $this->bad('declaration');
        elseif ($node instanceof PhpParser\Node\Expr\Include_ || $node instanceof PhpParser\Node\Expr\Eval_) $this->bad('include/eval');
        // Inline HTML (a close-tag then raw output then an open-tag) is text OUTSIDE the PHP tags, not
        // a statement the dispatch loop can wrap. Its text may end in '}' or ';', which slipped past the
        // span guard, so the flattener injected "case N:" / "state=..;break;" into the raw HTML, breaking
        // the switch and the function at run time (ENV-2026-29). Never flatten a body with inline HTML.
        elseif ($node instanceof PhpParser\Node\Stmt\InlineHTML) $this->bad('inline html');
        elseif ($node instanceof PhpParser\Node\Expr\Variable && !is_string($node->name)) $this->bad('dynamic variable');
        elseif ($node instanceof PhpParser\Node\Expr\FuncCall && $node->name instanceof PhpParser\Node\Name) {
            // A function that can observe the caller's locals (get_defined_vars/compact/extract/...)
            // must never be flattened, or it would see the injected state variable $__envlk_st. The
            // call may reach a frame function under an alias ("use function get_defined_vars as snap;
            // snap();"), so check the NameResolver-resolved name, not only the written one (ENV-2026-16).
            $nm = strtolower($node->name->toString());
            $rn = $node->name->getAttribute('resolvedName');
            $rn = ($rn instanceof PhpParser\Node\Name) ? strtolower($rn->toString()) : null;
            if (in_array($nm, $this->frame, true) || ($rn !== null && in_array($rn, $this->frame, true))) $this->bad('frame function');
        }
        elseif ($node instanceof PhpParser\Node\Scalar\String_ && in_array(strtolower($node->value), $this->frame, true)) $this->bad('frame function');
    }
}
class EnvFlattenCollector extends PhpParser\NodeVisitorAbstract {
    public $functions = [];
    public function enterNode(PhpParser\Node $node) {
        if (($node instanceof PhpParser\Node\Stmt\Function_ || $node instanceof PhpParser\Node\Stmt\ClassMethod)
                && is_array($node->stmts) && count($node->stmts) > 0) {
            $this->functions[] = $node;
        }
    }
}
$out = [];
foreach ($in["files"] as $name => $b64) {
    $code = base64_decode($b64, true);
    $res = ["code" => "", "error" => "", "flattened" => 0, "skipped" => []];
    if ($code === false) { $res["error"] = "not base64"; $out[$name] = $res; continue; }
    if (strpos($code, '__envlk_st') !== false) { $res["error"] = "the state variable name is already used"; $out[$name] = $res; continue; }
    try { $ast = $parser->parse($code); } catch (Throwable $e) { $res["error"] = "does not parse: " . $e->getMessage(); $out[$name] = $res; continue; }
    // Resolve names first (attributes only, nodes/spans preserved) so the eligibility visitor sees the
    // real target of every call, including "use function ... as ..." aliases (ENV-2026-16).
    $nr = new PhpParser\NodeTraverser();
    $nr->addVisitor(new PhpParser\NodeVisitor\NameResolver(null, ["replaceNodes" => false]));
    $ast = $nr->traverse($ast);
    $collector = new EnvFlattenCollector();
    $t = new PhpParser\NodeTraverser(); $t->addVisitor($collector); $t->traverse($ast);
    $edits = []; $seq = 0;
    foreach ($collector->functions as $fn) {
        $fnName = $fn instanceof PhpParser\Node\Stmt\ClassMethod ? 'method' : 'function';
        $elig = new EnvFlattenEligibility($frame);
        $tt = new PhpParser\NodeTraverser(); $tt->addVisitor($elig); $tt->traverse($fn->stmts);
        if ($elig->reason !== '') { $res["skipped"][$elig->reason] = ($res["skipped"][$elig->reason] ?? 0) + 1; continue; }
        $spans = [];
        $ok = true;
        foreach ($fn->stmts as $st) {
            $s = $st->getStartFilePos(); $e = $st->getEndFilePos() + 1;
            $text = substr($code, $s, $e - $s);
            if ($s < 0 || $e <= $s || !in_array(substr($text, -1), [';', '}'], true)) { $ok = false; break; }
            $spans[] = [$s, $e];
        }
        if (!$ok) { $res["skipped"]['unexpected statement span'] = ($res["skipped"]['unexpected statement span'] ?? 0) + 1; continue; }
        $n = count($spans);
        for ($i = 0; $i < $n; $i++) {
            [$s, $e] = $spans[$i];
            $label = ($i === 0 ? "$state=0;while(true){switch($state){" : "") . "case $i:";
            $edits[] = [$s, 1, $seq++, $label];
            # The last segment leaves the whole dispatch loop: a plain `break` only leaves the switch and the
            # while would run the segment again (O6 regression, see test_obfuscate_flatten_function_that_falls_off_the_end_terminates).
            $tail = $i === $n - 1 ? "break 2;default:break 2;}}" : "$state=" . ($i + 1) . ";break;";
            $edits[] = [$e, 0, $seq++, $tail];
        }
        $res["flattened"]++;
    }
    usort($edits, fn($a, $b) => [$a[0], $a[1], $a[2]] <=> [$b[0], $b[1], $b[2]]);
    $o = ""; $last = 0;
    foreach ($edits as [$pos, $rank, $sq, $text]) { $o .= substr($code, $last, $pos - $last) . $text; $last = $pos; }
    $o .= substr($code, $last);
    if (substr_count($o, "\n") !== substr_count($code, "\n")) { $res["error"] = "line count changed"; $out[$name] = $res; continue; }
    try { $parser->parse($o); } catch (Throwable $e) { $res["error"] = "the flattened result does not parse: " . $e->getMessage(); $out[$name] = $res; continue; }
    $res["code"] = base64_encode($o);
    $out[$name] = $res;
}
echo json_encode(["files" => $out], JSON_THROW_ON_ERROR);
"""


def _flatten_pass(files: dict[str, bytes], php: str = "php") -> tuple[dict[str, bytes], dict]:
    """Flatten eligible function and method bodies. Returns (files, stats). Any file the pass cannot
    prove well-formed is refused rather than shipped unflattened (the caller stops the pack)."""
    res = _run_php(php, FLATTEN_PHP,
                   {"lib": str(PHP_PARSER_LIB),
                    "files": {n: base64.b64encode(d).decode() for n, d in files.items()}},
                   "--flatten")
    out: dict[str, bytes] = {}
    stats = {"flattened": 0, "skipped": {}}
    for name, entry in (res.get("files") or {}).items():
        if entry.get("error"):
            raise ValueError(f"--obfuscate-flatten refused {name}: {entry['error']}")
        out[name] = base64.b64decode(entry["code"])
        stats["flattened"] += int(entry.get("flattened") or 0)
        for reason, count in (entry.get("skipped") or {}).items():
            stats["skipped"][reason] = stats["skipped"].get(reason, 0) + int(count)
    if set(out) != set(files):
        raise ValueError("--obfuscate-flatten: the parser returned a different file set")
    return out, stats


def pack_tree(
    source: Path,
    destination: Path,
    recipients: list[dict],
    owner: dict,
    project: str,
    extensions: set[str] | None = None,
    assets: list[str] | None = None,
    exclude: list[str] | None = None,
    php: str = "php",
    strip_comments: bool = False,
    obfuscate: bool = False,
    include_protection: bool = False,
    no_prepend: bool = False,
    serial: int | None = None,
    compact: bool = False,
    encode_strings: bool = False,
    obfuscate_methods: bool = False,
    manifest: bool = False,
    obfuscate_properties: bool = False,
    no_ffi: bool = False,
    sealed: bool = False,
    enforce_manifest: bool = False,
    obfuscate_flow: bool = False,
    vault_strings: bool = False,
    allow_demo: bool = False,
    allow_secret_assets: bool = False,
    obfuscate_names: bool = False,   # O6: keyword-only in practice; the positional order above is
                                     # already fixed by callers, so a new flag joins it by name
    virtualize: list[str] | None = None,   # O4: functions to run through the mini-VM
    bytecode: bool = False,
    bytecode_php: str | None = None,
    bytecode_loader: str | None = None,
    deploy_root: Path | None = None,
    obfuscate_names_ast: bool = False,
    obfuscate_names_allowlist: list[str] | None = None,
    virtualize_loader: str | Path | None = None,
    unsafe_vm_laboratory: bool = False,
    obfuscate_flatten: bool = False,   # O6: control-flow flattening of function bodies (keyword)
) -> dict:
    """php: CLI used by strip_comments/obfuscate. include_protection: protected files only run as
    the entry point or when called from protected code of the same project. no_prepend: refuse
    to run with auto_prepend_file/auto_append_file. serial: release number for the server's
    minimum (default: the current time in NANOSECONDS since the Unix epoch, so later packs have
    higher serials). allow_demo:
    permit the PUBLIC demo keys (testing only; a package made with them protects nothing)."""
    if obfuscate_flatten and virtualize:
        raise ValueError("--obfuscate-flatten cannot be combined with --virtualize: the mini-VM replaces "
                         "function bodies, so the flattener would act on stubs it did not write; no package "
                         "was produced")
    if virtualize and obfuscate_names:
        raise ValueError("--virtualize cannot be combined with --obfuscate-names: virtualized bodies "
                         "hide references and literals from the name analysis; no package was produced")
    if virtualize:
        if not unsafe_vm_laboratory:
            raise ValueError("--virtualize is quarantined: known PHP semantic divergences remain. "
                             "Only --unsafe-vm-laboratory permits research packages; never use in production")
        _require_vm_v2_loader(php, virtualize_loader)
    elif virtualize_loader is not None or unsafe_vm_laboratory:
        raise ValueError("--virtualize-loader and --unsafe-vm-laboratory require --virtualize")
    if obfuscate_names_ast and not obfuscate_names:
        raise ValueError("--obfuscate-names-ast requires --obfuscate-names")
    if obfuscate_names_allowlist is not None:
        if not obfuscate_names or not obfuscate_names_ast:
            raise ValueError("--obfuscate-names-allow requires --obfuscate-names and --obfuscate-names-ast")
        _parse_names_allowlist(obfuscate_names_allowlist)  # reject malformed policies before staging
    if not bytecode and (deploy_root is not None or bytecode_php is not None
                         or bytecode_loader is not None):
        # Silently ignoring them shipped encrypted SOURCE to an operator who believed the package
        # was compiled to bytecode for that deploy path (ENC-23).
        raise ValueError("--deploy-root, --bytecode-php and --bytecode-loader only apply with "
                         "--bytecode; no package was produced")
    validate_config(owner, "envelock-owner")
    recipient_pubs = []
    for recipient in recipients:
        validate_config(recipient, "envelock-recipient-public")
        recipient_pubs.append(bytes.fromhex(recipient["x25519_public"]))
    # Refuse the PUBLIC demo keys HERE, at the single chokepoint, not only in the CLI handler: the
    # GUI and any API caller go straight through pack_tree and would otherwise ship a package made
    # with published private halves, i.e. protecting nothing (external audit ENV-AUD-07).
    if not allow_demo:
        if owner["signing_public"] == DEMO_SIGNING_PUBLIC:
            raise ValueError("refusing the PUBLIC demo owner key (its private half is published): "
                             "use a real owner, or allow_demo=True for testing")
        # Compare the KEY, not its spelling (ENC-17): uppercase hex, or the unused top bit set, is
        # the same X25519 public key (the exchange ignores bit 255 and works modulo p).
        demo_u = _x25519_canonical_u(bytes.fromhex(DEMO_X25519_PUBLIC))
        for recipient in recipients:
            if _x25519_canonical_u(bytes.fromhex(recipient["x25519_public"])) == demo_u:
                raise ValueError("refusing the PUBLIC demo recipient key (its private half is "
                                 "published): use a real recipient, or allow_demo=True for testing")
    if not 1 <= len(recipient_pubs) <= MAX_RECIPIENTS:
        raise ValueError("Specify between 1 and 1024 recipients")
    if len(set(recipient_pubs)) != len(recipient_pubs):
        raise ValueError("Duplicate recipient")
    source, destination = source.resolve(), destination.resolve()
    if not source.is_dir():
        raise ValueError("The source folder does not exist")
    if (
        destination == source
        or destination.is_relative_to(source)
        or source.is_relative_to(destination)
    ):
        raise ValueError("Source and destination must be separate trees, not nested")
    if destination.exists():
        raise ValueError("Destination already exists; it is not overwritten")
    signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(owner["signing_private"]))
    if raw_public(signer.public_key()).hex() != owner["signing_public"]:
        raise ValueError("Inconsistent signing pair")
    project_id = uuid.UUID(project).bytes
    release_id = uuid.uuid4().bytes
    # Nanosecond wall clock, not whole seconds: two releases packed within the same second would
    # otherwise share a serial, so an anti-rollback minimum could not tell the old one from the new
    # (audit ENV-05). Pass --serial explicitly for a controlled monotonic counter in a pipeline.
    serial = time.time_ns() if serial is None else serial
    if not 0 <= serial < 2**64:
        raise ValueError("Invalid serial")
    flags = (
        (FLAG_INCLUDE_PROTECTION if include_protection else 0)
        | (FLAG_NO_PREPEND if no_prepend else 0)
        | (FLAG_NO_FFI if no_ffi else 0)
        | (FLAG_SEALED if sealed else 0)
        | (FLAG_ENFORCE_MANIFEST if enforce_manifest else 0)
        | (FLAG_VAULT if vault_strings else 0)
        | (FLAG_VAULT_ENC if vault_strings else 0)
        | (FLAG_BYTECODE if bytecode else 0)
    )
    content_key = secrets.token_bytes(32)
    # Build the recipient table once per pack and copy it identically to each file.
    table = build_table(recipient_pubs, content_key, project_id, release_id)
    extensions = DEFAULT_EXTENSIONS if extensions is None else extensions
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".envelock-pack-", dir=destination.parent))
    protected, copied = 0, 0
    published = False
    portable_names = set()
    portable_dirs = set()                     # folders of packed files, for file/folder collisions
    sources: dict[str, bytes] = {}            # PHP to encrypt, in tree order
    assets_used: set[str] = set()             # --asset patterns that copied at least one file
    assets_not_copied: list[dict[str, str]] = []
    try:
        # Excluded entries (and everything under an excluded folder) are skipped before the link
        # checks: they are never read, and tools such as pnpm create links/junctions inside
        # node_modules. The walk never descends through a link or junction (ENC-25).
        for item in _source_entries(
                source, lambda rel: forbidden(rel) or _pattern_matches(rel.as_posix(), exclude)):
            rel = item.relative_to(source)
            name = rel.as_posix()
            if item.is_symlink():
                raise ValueError(f"Symbolic link not allowed: {name}")
            # Windows junctions are not symlinks to is_symlink(), and Windows has no
            # O_NOFOLLOW: refuse anything whose real location is outside the source tree.
            if getattr(item, "is_junction", lambda: False)() or not item.resolve().is_relative_to(source):
                raise ValueError(f"Link or junction leaves the source tree: {name}")
            if item.is_dir():
                continue
            if not item.is_file():
                raise ValueError(f"Special file not allowed: {name}")
            is_php = item.suffix.lower() in extensions
            is_asset = _pattern_matches(name, assets)
            if not is_php and not is_asset:
                continue
            if _claim_portable_name(validate_portable_path(rel), portable_names, portable_dirs):
                raise ValueError(f"Path collision on Windows/macOS: {name}")
            target = staging / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if is_php:
                sources[name] = bounded_read(item, MAX_SOURCE)
            else:
                data = bounded_read(item, MAX_ASSET)
                validate_asset(rel, data, allow_secret_assets)
                target.write_bytes(data)
                copied += 1
                for pattern in assets or []:
                    if _pattern_matches(name, [pattern]):
                        assets_used.add(pattern)
        if not sources:
            raise ValueError("No PHP files found to protect")
        # An --asset that copied nothing used to vanish in silence (copied_assets 0, exit 0): an
        # operator who asked for `.netrc` or `.env` shipped a package without it and no word why
        # (audit 2026-11-12, H-08). Report every such pattern with the reason, for the CLI to warn.
        for pattern in assets or []:
            if pattern in assets_used:
                continue
            literal = None if any(c in pattern for c in "*?[") else source / pattern.replace("\\", "/")
            if literal is not None and literal.is_file():
                rel = literal.relative_to(source)
                if forbidden(rel):
                    reason = ("it is a path pack never copies (.env*, .git, .ssh, .netrc and the other "
                              "secret or tooling locations)")
                elif _pattern_matches(rel.as_posix(), exclude):
                    reason = "it is also excluded by --exclude"
                elif rel.suffix.lower() in extensions:
                    reason = "it is PHP, so it was encrypted as code rather than copied as an asset"
                else:
                    reason = "it was not copied"
            else:
                reason = "no file in the source tree matches it"
            assets_not_copied.append({"asset": pattern, "reason": reason})
        # O4 runs before every other pass: once the body is gone, the passes that follow see a
        # one-line function and cannot undo it, and the program blob is then just another string
        # literal, which --vault-strings will encrypt like the rest.
        virtualized: dict[str, str] = {}
        vm_compiler_sha256 = None
        if virtualize:
            # Informational provenance only, not a signature or runtime attestation. Reject normal
            # concurrent compiler changes rather than publishing a misleading fingerprint.
            compiler_path = _virtualize_php_path()
            vm_compiler_sha256 = hashlib.sha256(compiler_path.read_bytes()).hexdigest()
            sources, virtualized = virtualize_sources(sources, virtualize, php)
            if (_virtualize_php_path() != compiler_path
                    or hashlib.sha256(compiler_path.read_bytes()).hexdigest() != vm_compiler_sha256):
                raise ValueError("--virtualize compiler changed during packaging; no package was produced")
        # Name analysis MUST see original literals: vaulting them first would hide dynamic class
        # and function names from its safety checks and silently break the combined flags.
        renamed_names: dict[str, str] = {}
        names_skipped = ""
        if obfuscate_names:
            sources, renamed_names, names_skipped = _names_pass(
                sources, php, ast_names=obfuscate_names_ast, allowlist=obfuscate_names_allowlist)
        # The vault and the other source passes follow the package-wide rename. Both the name and
        # vault passes preserve line numbers; the per-file vault tables are still built afterwards.
        vault_tables: dict[str, list[bytes]] = {}
        # Files containing __halt_compiler() cannot be rebuilt from tokens, so the vault and the
        # token rewriters pass them through UNTRANSFORMED (ENV-08). Collect them so the manifest
        # reports the truth per file instead of claiming a protection that was not applied, and so
        # the operator is warned when such a file would otherwise ship as readable source.
        not_token_transformed: set[str] = set()
        rename_methods, rename_properties = obfuscate_methods, obfuscate_properties
        if vault_strings and (rename_methods or rename_properties):
            # Like the name pass, the private method/property renamers MUST see the original string
            # literals: a name that appears in one ([$this, 'helper'], property_exists($o, 'x')) is
            # used dynamically and keeps its spelling. Run after the vault, they saw only
            # \__envelock_lit(n) calls, renamed the member and broke the program silently (ENC-7).
            sources, rename_halted = transform_sources(sources, php, methods=rename_methods,
                                                       properties=rename_properties)
            not_token_transformed.update(rename_halted)
            rename_methods = rename_properties = False
        if vault_strings:
            sources, vault_tables, vault_halted = _vault_pass(sources, php)
            not_token_transformed.update(vault_halted)
        if (strip_comments or obfuscate or compact or encode_strings or rename_methods
                or rename_properties or obfuscate_flow):
            sources, transform_halted = transform_sources(sources, php, strip_comments, obfuscate,
                                        compact, encode_strings, rename_methods,
                                        rename_properties, obfuscate_flow)
            not_token_transformed.update(transform_halted)
        flatten_stats = {"flattened": 0, "skipped": {}}
        if obfuscate_flatten:
            # After every other source pass, so the dispatcher wraps the final statement text. Refused
            # files stop the pack (see _flatten_pass); bytecode, if any, is compiled from the result.
            sources, flatten_stats = _flatten_pass(sources, php)
        # Bytecode last: it compiles whatever the previous passes produced, so obfuscation and the
        # literal rewrites land inside the image and the source itself is never shipped.
        if bytecode:
            if vault_strings:
                raise ValueError("--bytecode and --vault-strings are mutually exclusive: the vault "
                                 "rewrites literals into __envelock_lit() calls in the source, and a "
                                 "bytecode image ships no source to resolve them in")
            if deploy_root is None:
                raise ValueError("--bytecode needs --deploy-root: __DIR__, __FILE__ and statically "
                                 "resolved include paths are baked into the bytecode, so the sources "
                                 "have to be compiled at the path the package will run from")
            sources = _bytecode_pass(sources, Path(deploy_root), bytecode_php or php,
                                     bytecode_loader)
        # Warn when a token-level protection was requested but some files could not receive it and are
        # NOT protected by bytecode either: those ship as readable source inside the container. With
        # --bytecode on, the same files are compiled to bytecode (no source shipped), so no warning.
        if not_token_transformed and not bytecode:
            listed = ", ".join(sorted(not_token_transformed))
            print(f"WARNING: {len(not_token_transformed)} file(s) contain __halt_compiler() and could "
                  f"not be obfuscated/vaulted (their trailing data cannot be rebuilt from tokens); they "
                  f"ship as readable source: {listed}. Use --bytecode for these files, or --exclude "
                  f"them. See envelock-package.json -> files_not_token_transformed.", file=sys.stderr)
        for name, data in sources.items():
            # With the vault flag the plaintext is the table section then the source; the loader
            # registers the table and compiles only the source. count==0 files still carry the
            # (empty) prefix so the loader strips uniformly.
            plaintext = (_vault_plaintext_encrypted(vault_tables[name], data, content_key)
                         if vault_strings else data)
            # New content key every pack + monotonic nonce: no per-file collisions.
            (staging / name).write_bytes(
                protect(plaintext, signer, project_id, release_id, content_key, table,
                        protected.to_bytes(12, "big"), path=name, flags=flags, serial=serial)
            )
            protected += 1
        info = {
            "format": FORMAT_VERSION,
            "project_id": str(uuid.UUID(bytes=project_id)),
            "release_id": str(uuid.UUID(bytes=release_id)),
            "recipients": len(recipient_pubs),
            "protected_files": protected,
            "copied_assets": copied,
            "serial": serial,
            "virtualized_functions": sorted(virtualized),
            "unsafe_vm_laboratory": bool(virtualized and unsafe_vm_laboratory),
            "vm_program_version": 3 if virtualized else None,
            "vm_compiler_sha256": vm_compiler_sha256,
            "comments_stripped": strip_comments,
            "obfuscated": obfuscate,
            "compacted": compact,
            "strings_encoded": encode_strings,
            "private_methods_obfuscated": obfuscate_methods,
            "private_properties_obfuscated": obfuscate_properties,
            "flow_obfuscated": obfuscate_flow,
            "flow_flattened": bool(obfuscate_flatten),
            "functions_flattened": flatten_stats["flattened"],
            "functions_not_flattened": flatten_stats["skipped"],
            "names_obfuscated": sorted(renamed_names.values()) if obfuscate_names else False,
            "names_skipped": names_skipped if obfuscate_names else "",
            "names_allowlist_enforced": obfuscate_names_allowlist is not None,
            "strings_vaulted": vault_strings,
            # Files that contain __halt_compiler() and so were passed through without the token-level
            # protections (strip/encode/methods/properties/flow/vault). Honest per-file record: with
            # --bytecode they are still protected (compiled, no source shipped); without it they ship
            # as readable source. Empty when every file could be transformed.
            "files_not_token_transformed": sorted(not_token_transformed),
            "bytecode": bytecode,
            "include_protection": include_protection,
            "no_prepend": no_prepend,
            "no_ffi": no_ffi,
            "sealed": sealed,
            "manifest": manifest,
            "enforce_manifest": enforce_manifest,
        }
        # Metadata is informational, not an authorization input. No secrets here.
        if (staging / "envelock-package.json").exists():
            raise ValueError("Reserved name: envelock-package.json")
        (staging / "envelock-package.json").write_text(
            json.dumps(info, indent=2) + "\n", encoding="utf-8"
        )
        # Binary manifest for the loader's runtime check (pack --enforce-manifest). Written BEFORE
        # the JSON manifest so the JSON inventories it too (A1 fix: otherwise `verify` reported
        # envelock-manifest.bin as an added file and failed every time). It inventories everything
        # present now except itself; the loader fails closed if it is gone.
        if enforce_manifest:
            if (staging / MANIFEST_BIN_NAME).exists():
                raise ValueError(f"Reserved name: {MANIFEST_BIN_NAME}")
            (staging / MANIFEST_BIN_NAME).write_bytes(
                build_manifest_bin(staging, project_id, release_id, serial, signer))
        # Signed JSON manifest of the WHOLE tree (every file's SHA-256), so a deployed package can be
        # checked with `verify`: a deleted, added, modified or swapped file is detected (C8). Written
        # last so it covers envelock-package.json AND the binary manifest; it hashes everything
        # except itself.
        if manifest:
            if (staging / "envelock-manifest").exists():
                raise ValueError("Reserved name: envelock-manifest")
            (staging / "envelock-manifest").write_bytes(
                build_manifest(staging, project_id, release_id, serial, signer))
        # Deterministic permissions, independent of the caller's umask (M-06: with umask 000 the
        # files would otherwise be 0666). The package content is encrypted, so world-readable is
        # fine; it is never world-writable.
        for item in staging.rglob("*"):
            os.chmod(item, 0o755 if item.is_dir() else 0o644)
        # mkdir is an exclusive reservation; rename alone can overwrite an empty directory on POSIX.
        destination.mkdir(mode=0o755)
        published = True
        if os.name != "nt":
            # mkdir's mode is filtered by the umask, and the CLI runs under umask 077 (main), which
            # left the package root 0700: the web server user could not enter it (ENC-12).
            os.chmod(destination, 0o755)  # nosec B103 - the web server must enter the encrypted package (ENC-12)
        for child in staging.iterdir():
            child.rename(destination / child.name)
        staging.rmdir()
        # For the caller only, never inside the package's envelock-package.json: the names of files
        # the operator asked for and did not get (".netrc", ".env.production") are not for the server.
        info["assets_not_copied"] = assets_not_copied
        return info
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        if published:
            shutil.rmtree(destination, ignore_errors=True)
        raise


# ---------------------------------------------------------------------------
# Objective O8: signed deployment licenses (expiry, machine binding).
# ---------------------------------------------------------------------------
#
# A license is a fixed-size binary the vendor issues for one server, signed with the owner's
# Ed25519 key (the same key that signs packages, so the loader already trusts it). It is a
# separate file from the identity bundle on purpose: the identity holds this server's PRIVATE keys
# and is generated here, while a license is a public, vendor-issued document that only constrains.
#
# Layout (all integers big-endian), total LICENCE_SIZE bytes:
#   0   magic "ENVLKLIC" (8) | version u8 | fields u8
#   10  expires u64 BE          Unix seconds; 0 = never
#   18  machine fingerprint 32  0 = unbound
#   50  domain sha256 32        0 = unbound
#   82  ip sha256 32            0 = unbound
#   114 padding to 176, zero
#   176 Ed25519 signature over bytes 0..176
#
# Fixed size and no JSON because the loader has no JSON parser; the cost is that a new field means
# a new magic. `fields` says which of the three constraints are present, so an all-zero slot is
# never mistaken for a constraint on nothing.
LICENCE_BIN_MAGIC = b"ENVLKLIC"
LICENCE_FORMAT = 1
LICENCE_SIZE = 176 + 64
LICENCE_FIELD_EXPIRY = 0x01
LICENCE_FIELD_MACHINE = 0x02
LICENCE_FIELD_DOMAIN = 0x04
LICENCE_FIELD_IP = 0x08


def licence_body(expires: int, machine: bytes, domain: bytes, ip: bytes) -> bytes:
    """The signed part of a license. Every slot is fixed-width so the loader can parse it without
    any framing, and absent constraints are all-zero (the `fields` byte says which are real)."""
    if not 0 <= expires < (1 << 63):
        raise ValueError("expires must be a non-negative Unix timestamp")
    for name, slot in (("machine", machine), ("domain", domain), ("ip", ip)):
        if len(slot) != 32:
            raise ValueError(f"the {name} slot must be 32 bytes")
    fields = 0
    if expires:
        fields |= LICENCE_FIELD_EXPIRY
    if machine != ZERO32:
        fields |= LICENCE_FIELD_MACHINE
    if domain != ZERO32:
        fields |= LICENCE_FIELD_DOMAIN
    if ip != ZERO32:
        fields |= LICENCE_FIELD_IP
    body = (LICENCE_BIN_MAGIC + bytes([LICENCE_FORMAT, fields])
            + struct.pack(">Q", expires) + machine + domain + ip)
    return body + b"\x00" * (176 - len(body))


def issue_licence(owner: dict, expires: int = 0, machine: bytes = ZERO32,
                  domain: bytes = ZERO32, ip: bytes = ZERO32) -> bytes:
    """Sign a license with the owner key. The issuer is not stored: the loader accepts a license
    whose signature verifies under ANY trusted developer, so rotating the owner key keeps old
    licenses working exactly as it keeps old packages working."""
    validate_config(owner, "envelock-owner")
    signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(owner["signing_private"]))
    body = licence_body(expires, machine, domain, ip)
    return body + signer.sign(body)


def parse_licence(blob: bytes) -> dict:
    """Split a license into its fields, verifying nothing. Raises ValueError on a wrong size or
    magic; use verify_licence for the real checks."""
    if len(blob) != LICENCE_SIZE:
        raise ValueError(f"a license is {LICENCE_SIZE} bytes, got {len(blob)}")
    if blob[:8] != LICENCE_BIN_MAGIC:
        raise ValueError("not an Envelock license")
    fields = blob[9]
    return {"format": blob[8], "fields": fields,
            "expires": int.from_bytes(blob[10:18], "big"),
            "machine": blob[18:50], "domain": blob[50:82], "ip": blob[82:114],
            "signature": blob[176:]}


def verify_licence(blob: bytes, trusted_public_hex: list[str]) -> dict:
    """Check a license against the owner keys a server trusts. Returns the parsed license; raises
    ValueError naming the reason otherwise. Expiry is checked here too so the CLI reports the same
    verdict the loader will reach, but the loader re-checks it at run time — the clock moves."""
    licence = parse_licence(blob)
    if licence["format"] != LICENCE_FORMAT:
        raise ValueError(f"unsupported license format {licence['format']}")
    body, signature = blob[:176], licence["signature"]
    keys = [k for k in trusted_public_hex if k]
    if any(ed25519_small_order(bytes.fromhex(k)) for k in keys):   # ENC-14: accepts forgeries
        raise ValueError("a trusted owner key is a small-order Ed25519 point; refusing to trust it")
    if not keys:
        raise ValueError("no trusted owner key to check the license against")

    def signed_by(public_hex: str) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(signature, body)
            return True
        except Exception:
            return False

    if not any(signed_by(k) for k in keys):
        raise ValueError("the license signature does not verify with any trusted owner key")
    if (licence["fields"] & LICENCE_FIELD_EXPIRY) and licence["expires"] <= time.time():
        raise ValueError("the license expired on "
                         + time.strftime("%Y-%m-%d %H:%M:%S UTC",
                                         time.gmtime(licence["expires"])))
    return licence


# Limits of the loader's fingerprint buffers (envelock_licence.c): ENVELOCK_MACHINE_MAX bytes for
# label + "\n"-separated parts, ENVELOCK_MACS_MAX MACs or IPv4 addresses. A host beyond either is
# REFUSED by the loader (it never fingerprints a truncated list), so the encoder refuses too rather
# than issue a licence that host can never satisfy (ENC-19).
_FINGERPRINT_MAX = 4096
_FINGERPRINT_ENTRIES_MAX = 256
_TOO_MANY_NET = "too many network interfaces/addresses to bind a licence to this host"
_ASCII_LOWER_BYTES = bytes.maketrans(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"abcdefghijklmnopqrstuvwxyz")


def _fingerprint(label: bytes, parts: list[bytes]) -> bytes:
    """SHA-256 of label + ("\\n" + part)..., refusing a buffer the loader could not hold."""
    buffer = label + b"".join(b"\n" + part for part in parts)
    if len(buffer) >= _FINGERPRINT_MAX:
        raise ValueError(_TOO_MANY_NET)
    return hashlib.sha256(buffer).digest()


def _read_small(path: str) -> bytes | None:
    """First 255 bytes of a small text file, up to any NUL and trimmed of ASCII whitespace, as the
    loader's envelock_read_small + envelock_trim read it; None if unreadable."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read(255)
    except OSError:
        return None
    return raw.split(b"\0", 1)[0].strip(b" \t\r\n")


def machine_fingerprint() -> bytes:
    """Fingerprint of THIS host, so a license can be bound to one machine.

    Deliberately derived from what the machine already reports — /etc/machine-id (or the D-Bus
    equivalent) plus the MAC addresses of the physical interfaces — rather than from anything
    Envelock writes. A value Envelock stored itself would prove only that the file was copied along
    with it, which is exactly what the binding is meant to catch. Computed byte for byte like the
    loader's envelock_machine_fingerprint(): ALL qualifying MACs, lowercased and sorted, so interface
    enumeration order cannot change the result; more than 256 of them, or a buffer of 4096 bytes or
    more, is refused on both sides (ENC-19).
    """
    parts: list[bytes] = []
    for candidate in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        value = _read_small(candidate)
        if value:
            parts.append(value)
            break
    try:
        entries = os.listdir("/sys/class/net")
    except OSError:
        entries = []
    macs: list[bytes] = []
    for name in entries:
        if name.startswith(".") or name == "lo":
            continue
        # Only interfaces backed by a REAL device: a physical or virtio NIC has
        # /sys/class/net/<name>/device; veth/tun/tap/bridge/bond/tunnel interfaces do not. This matches
        # the loader (envelock_machine_fingerprint) exactly — the two used to diverge on tunnels and on
        # a 64-entry cap applied before sorting — and stops a container's transient veth* interfaces
        # from changing the machine fingerprint when it restarts (ENV-2026-30).
        if not os.path.exists(f"/sys/class/net/{name}/device"):
            continue
        mac = _read_small(f"/sys/class/net/{name}/address")
        # Exactly a "xx:xx:xx:xx:xx:xx" MAC (17 chars), the same length the loader requires; all-zero
        # and all-ff carry no identity. The loader lowercases A-F only; so does this.
        if mac is None or len(mac) != 17:
            continue
        mac = mac.translate(bytes.maketrans(b"ABCDEF", b"abcdef"))
        if mac not in (b"00:00:00:00:00:00", b"ff:ff:ff:ff:ff:ff"):
            macs.append(mac)
    if len(macs) > _FINGERPRINT_ENTRIES_MAX:
        raise ValueError(_TOO_MANY_NET)
    # Sort the ADDRESSES (bytewise, like strcmp), not the interface names: name order and address
    # order disagree on some hosts, and interface names are not stable across reboots anyway.
    parts.extend(sorted(macs))
    if not parts:
        raise ValueError("this host reports neither a machine-id nor a MAC address; a license "
                         "cannot be bound to it (issue an unbound one instead)")
    # The label carries no trailing newline: every part is preceded by a separator, so the
    # machine-id gets one too. The C side (envelock_machine_fingerprint) does the same.
    return _fingerprint(b"envelock-machine-1", parts)


def _strip_port(name: str) -> str:
    """Drop a trailing :port exactly as the loader does (envelock_host_domain). A bracketed IPv6
    literal keeps its address: "[::1]:8443" -> "::1" (splitting on the first ':' truncated it to
    "[", ENV-2026-06). An unclosed bracket is kept whole, as the loader keeps it: "[::1" stays
    "[::1" (ENC-18). Only ASCII whitespace is trimmed, like envelock_trim."""
    s = name.strip(" \t\r\n")
    if s.startswith("["):
        end = s.find("]")
        return s[1:end] if end != -1 else s
    return s.split(":", 1)[0]


ENVELOCK_HOST_MAX = 256          # envelock_licence.h: the loader holds at most 255 bytes of host


def canonical_domain(name: str) -> str:
    """The host name exactly as the loader will hash it (ENC-18): ASCII whitespace trimmed, the port
    stripped the loader's way, ASCII-only lowercasing (the loader does not fold Unicode), and an
    internationalised name in its IDNA/punycode form, which is what a server's SERVER_NAME holds.
    A trailing dot is NOT removed: the loader keeps it, so "example.com." and "example.com" are
    different bindings."""
    clean = _strip_port(name)
    if not clean.isascii():
        try:
            clean = clean.encode("idna").decode("ascii")
        except UnicodeError as error:
            raise ValueError(f"{name!r} is not a valid internationalised host name ({error})") from None
    clean = clean.encode("ascii").translate(_ASCII_LOWER_BYTES).decode("ascii")
    if not clean:
        raise ValueError("an empty host name cannot be bound")
    if len(clean) >= ENVELOCK_HOST_MAX:
        raise ValueError("that host name is longer than the loader can compare (255 bytes)")
    return clean


def domain_hash(name: str) -> bytes:
    """Fingerprint of a served host name, matching envelock_domain_hash() in the loader.

    Canonicalised exactly like the loader (canonical_domain). Honest limit: the loader reads this
    from SERVER_NAME (the host the server is configured to serve), not the client's Host header, so
    it is no longer trivially spoofed (ENV-2026-06) — but a domain binding is still a
    NON-cryptographic control. What it buys is that copying a deployment to another server does not
    keep working; it is not an access control, and is documented as such. Bind with --machine or
    --ip for anything stronger. Windows builds of the loader refuse domain-bound licences.
    """
    return hashlib.sha256(b"envelock-domain-1\n" + canonical_domain(name).encode("ascii")).digest()


def host_domain() -> str:
    """The host name this machine would report to the loader when there is no HTTP request: its own
    name. That is what `licence host-id` prints, so an operator can check it against the value a
    web server will actually present (the request's Host)."""
    import socket
    # The loader (envelock_licence.c) hashes the raw gethostname(), so the encoder must too — the
    # full name as the OS reports it, not a short-name variant (audit NU-06: a dead `if False`
    # branch used to imply a short-name option that never ran).
    return socket.gethostname()


def host_ipv4_addresses() -> list[str]:
    """This host's non-loopback IPv4 addresses, dotted-quad, sorted.

    Enumerated with getifaddrs, exactly as the loader's envelock_host_ips_hash() does: EVERY AF_INET
    address of every non-loopback interface, not just the primary one. Reading one address per
    interface (SIOCGIFADDR) used to miss secondary addresses (eth0 with an alias), so a host with a
    secondary IP produced an encoder fingerprint that the loader — which sees all of them — then
    rejected on that same host (audit NU-03). On platforms without getifaddrs (e.g. Windows, where
    the loader's hash is also a stub) there is no IP binding, as before.
    """
    import sys
    if not sys.platform.startswith("linux"):
        return []
    import ctypes
    import ctypes.util
    import socket

    class _sockaddr(ctypes.Structure):
        _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", ctypes.c_char * 14)]

    class _sockaddr_in(ctypes.Structure):
        _fields_ = [("sin_family", ctypes.c_ushort), ("sin_port", ctypes.c_ushort),
                    ("sin_addr", ctypes.c_ubyte * 4)]

    class _ifaddrs(ctypes.Structure):
        pass

    _ifaddrs._fields_ = [
        ("ifa_next", ctypes.POINTER(_ifaddrs)),
        ("ifa_name", ctypes.c_char_p),
        ("ifa_flags", ctypes.c_uint),
        ("ifa_addr", ctypes.POINTER(_sockaddr)),
        ("ifa_netmask", ctypes.POINTER(_sockaddr)),
        ("ifa_ifu", ctypes.POINTER(_sockaddr)),
        ("ifa_data", ctypes.c_void_p),
    ]
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        getifaddrs = libc.getifaddrs
        freeifaddrs = libc.freeifaddrs
    except (OSError, AttributeError):
        return []
    IFF_LOOPBACK = 0x8
    head = ctypes.POINTER(_ifaddrs)()
    if getifaddrs(ctypes.byref(head)) != 0:
        return []
    out: list[str] = []
    try:
        node = head
        while node:
            ifa = node.contents
            if ifa.ifa_addr and ifa.ifa_addr.contents.sa_family == socket.AF_INET \
                    and not (ifa.ifa_flags & IFF_LOOPBACK):
                sin = ctypes.cast(ifa.ifa_addr, ctypes.POINTER(_sockaddr_in)).contents
                out.append(".".join(str(b) for b in sin.sin_addr))
            node = ifa.ifa_next
    finally:
        freeifaddrs(head)
    return sorted(out)


def host_ips_hash() -> bytes:
    """Fingerprint of this host's IPv4 addresses, matching envelock_host_ips_hash() in the loader.
    Raises ValueError when the host has none, since an IP-bound license would then be unusable."""
    addresses = host_ipv4_addresses()
    if not addresses:
        raise ValueError("this host has no non-loopback IPv4 address; a license cannot be bound "
                         "to one (issue an unbound or domain-bound license instead)")
    # ALL addresses, sorted, as the loader's envelock_host_ips_hash(); more than 256, or a buffer of
    # 4096 bytes or more, is refused there, so it is refused here too (ENC-19).
    if len(addresses) > _FINGERPRINT_ENTRIES_MAX:
        raise ValueError(_TOO_MANY_NET)
    return _fingerprint(b"envelock-ip-1", [a.encode("ascii") for a in sorted(addresses)])


# ---------------------------------------------------------------- compatibility preflight
# Encryption replaces each .php with an encrypted stub, so any mechanism that re-opens a file to read
# its TEXT at run time (rather than executing it) stops working: source tokenizers that build class
# maps, header readers, and annotation readers that parse `use` statements from the source. This scan
# flags those patterns BEFORE packing. It is a static, read-only pass on the developer's machine: it
# never runs the scanned code, never changes what is encrypted, and never excludes anything on its own
# — it only reports, so the decision (and the protection) stays entirely with the developer. It adds
# nothing to the package or to the runtime loader and therefore cannot weaken the protection.
COMPAT_PATTERNS = [
    ("source-tokenizer", re.compile(r"\btoken_get_all\s*\(", re.IGNORECASE),
     "tokenizes PHP source at run time (e.g. to build a class map). Ship the map/cache generated "
     "from a cleartext build, or exclude this file from encryption."),
    ("file-header-reader", re.compile(r"\bget_file_data\s*\(", re.IGNORECASE),
     "reads header comments from the file text (e.g. plugin/theme headers). Keep the file that "
     "carries the header unencrypted (--exclude it)."),
    ("reads-own-source", re.compile(
        r"\b(?:php_strip_whitespace|highlight_file|show_source)\s*\(|"
        r"\bfile(?:_get_contents)?\s*\(\s*__FILE__", re.IGNORECASE),
     "reads its own source text at run time. Exclude the file if that path is actually used."),
    ("doctrine-annotation", re.compile(
        r"^\s*(?:/\*\*|\*)\s*@(?:ORM|Route|Assert|Serializer|ApiResource|Groups|Embedded)\b"),
     "mapping declared as a docblock ANNOTATION: the reader tokenizes the file's use-statements from "
     "source, which an encrypted file no longer exposes. Use PHP 8 ATTRIBUTES (#[...], read via "
     "reflection, unaffected by encryption), or ship a pre-generated metadata cache (warm it in the "
     "clear, deploy it non-debug). Both are validated in docs/DEPLOYING-APPS.md."),
    ("wp-file-header", re.compile(
        r"^\s*(?:\*\s*)?(?:Plugin Name|Theme Name|Template Name|Slug)\s*:", re.IGNORECASE),
     "a WordPress file header read from the file TEXT via get_file_data (a block pattern's 'Slug:', "
     "or a plugin/theme/page-template header). Encryption hides the header, so WordPress stops "
     "registering the pattern / recognising the plugin or template — on a block (FSE) theme the "
     "templates then render empty. Keep these files unencrypted, e.g. "
     "--exclude 'wp-content/themes/*/patterns/*'. Validated in docs/DEPLOYING-APPS.md."),
    ("reads-own-docblock", re.compile(r"\bgetDocComment\s*\(", re.IGNORECASE),
     "reads its own docblock comments at run time via Reflection getDocComment() (e.g. a custom "
     "annotation such as PrestaShop's @arrayAccess on a LazyArray presenter). Plain encryption KEEPS "
     "docblocks, so this is safe on a base pack — but --strip-comments and --compact REMOVE them, so "
     "the annotation vanishes and the code silently misbehaves (on PrestaShop the front-office product "
     "data stops rendering, HTTP 200 with the section simply absent). Do not use --strip-comments / "
     "--compact on a tree that contains this, or --exclude the affected files. "
     "Validated in docs/DEPLOYING-APPS.md."),
]

# Categories whose findings are destroyed specifically by --strip-comments / --compact (they remove
# the docblocks/comments those patterns rely on). Used for the active pack-time warning.
_COMMENT_SENSITIVE_CATEGORIES = frozenset({"doctrine-annotation", "wp-file-header", "reads-own-docblock"})


def _scanned_files(source: Path, extensions: set, skip_top: frozenset = frozenset()) -> list[Path]:
    """The files pack would read: the same pruned, link-free walk (ENC-25), never entering the
    folders pack never ships (DENIED_PARTS) or the top-level folders in skip_top."""
    def skip(rel: Path) -> bool:
        return any(part in DENIED_PARTS for part in rel.parts) or (len(rel.parts) and rel.parts[0] in skip_top)
    return [p for p in _source_entries(source, skip)
            if p.suffix.lower() in extensions and p.is_file() and not p.is_symlink()]


def compatibility_findings(source: Path, extensions: set, skip_top: frozenset = frozenset()) -> dict:
    """Static read-only scan: category -> {'hint', 'hits':[(relpath, line)]}. Never executes code.
    Fails closed on a bad --source: a non-existent path or a single file would otherwise rglob to
    nothing and look like a clean project, so preflight/recommend would silently approve it (ENV-2026-11)."""
    if not source.is_dir():
        raise ValueError(f"--source must be a project directory (got: {source})")
    findings: dict = {}
    for path in _scanned_files(source, extensions, skip_top):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(source).as_posix()
        for lineno, line in enumerate(text.splitlines(), 1):
            for category, pattern, hint in COMPAT_PATTERNS:
                if pattern.search(line):
                    findings.setdefault(category, {"hint": hint, "hits": []})["hits"].append((rel, lineno))
    return findings


def format_compatibility_report(findings: dict, max_examples: int = 6) -> str:
    if not findings:
        return ("Compatibility preflight: no self-introspection patterns found. "
                "Encrypting this tree should not break source-reading code.")
    out = ["Compatibility preflight — code that reads its OWN source may break after encryption:"]
    for category, data in findings.items():
        hits = data["hits"]
        files = len({h[0] for h in hits})
        out.append(f"\n[{category}] {len(hits)} occurrence(s) in {files} file(s)")
        out.append(f"  -> {data['hint']}")
        for rel, ln in hits[:max_examples]:
            out.append(f"     {rel}:{ln}")
        if len(hits) > max_examples:
            out.append(f"     ... and {len(hits) - max_examples} more")
    out.append("\nAdvisory only: encryption is unchanged. Decide per file whether to --exclude it or "
               "ship a pre-generated artifact. See docs/DEPLOYING-APPS.md.")
    return "\n".join(out)


# Categories whose files break under ANY encryption (the code reads its own SOURCE TEXT at run time),
# so the file must stay cleartext (--exclude) or be re-architected (PHP 8 attributes / a warmed cache).
_ENCRYPTION_BREAKING_CATEGORIES = frozenset({
    "source-tokenizer", "file-header-reader", "reads-own-source",
    "doctrine-annotation", "wp-file-header"})
# Run-time string compilation --sealed refuses while active: recommending --sealed over such a tree
# would break it. assert('string') compiles its argument; create_function() is an eval() wrapper.
# Case-insensitive (PHP keywords/functions are), and DOTALL so `eval\n(...)` split across lines is
# still caught (ENV-2026-13): the whitespace class spans newlines.
_EVAL_RE = re.compile(r"\beval\s*\(|\bcreate_function\s*\(|\bassert\s*\(\s*['\"]",
                      re.IGNORECASE | re.DOTALL)


def _tree_uses_runtime_compile(source: Path, extensions: set, skip_top: frozenset = frozenset()) -> list:
    """Files that eval()/create_function()/assert('...') — what --sealed refuses at run time. Returns a
    few 'relpath:line' examples (bounded), used to gate the --sealed recommendation."""
    return _tree_matches(source, extensions, _EVAL_RE, skip_top)


# FFI or dl() used by the project itself: --no-ffi refuses to load while either is reachable, so a
# project that needs them cannot use it. `\FFI::cdef`, `FFI\CData`, `dl('x.so')`; not `->dl(`/`::dl(`.
_FFI_RE = re.compile(r"\bFFI\s*(?:::|\\)|(?<![\w$>:])\\?dl\s*\(", re.IGNORECASE)
# Laravel Blade templates: .php files the framework READS AS TEXT and compiles into its view cache.
# Encrypted, the compiler gets the container instead of the template (and bytecode has no text at all).
_TEMPLATE_SUFFIXES = (".blade.php",)
# Run-time caches of the common frameworks: regenerated on the server, never part of the asset
# (MANUAL §14). Each is recommended for exclusion only when it exists in the tree.
_RUNTIME_CACHE_DIRS = ("bootstrap/cache", "storage/framework", "var/cache")


def _tree_matches(source: Path, extensions: set, pattern, skip_top: frozenset = frozenset()) -> list:
    hits: list[str] = []
    for path in _scanned_files(source, extensions, skip_top):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Scan the whole file text (not line by line) so `eval` and its `(` on different lines match;
        # report the line of the match start.
        for m in pattern.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            hits.append(f"{path.relative_to(source).as_posix()}:{line}")
            if len(hits) >= 8:
                return hits
    return hits


def recommend_options(source: Path, extensions: set) -> dict:
    """Analyse the tree and recommend the STRONGEST protection that measurement shows is SAFE for it,
    turning OFF only what would break THIS project. Grounded in the four-CMS matrix and the preflight
    detectors (docs/DEPLOYING-APPS.md): it never recommends an option known to break the project.
    Every pack option is accounted for: in `on` (and also in `verify` when it may or may not work here
    — it depends on the server or on code the static analysis cannot see — with why and how to check),
    or in `off` with the reason it is not recommended.
    Returns {on: [flags], verify: {flag: why/how to check}, off: {flag: reason},
    exclude: {category: [files]}, exclude_patterns: [patterns], notes: [str]}."""
    if not source.is_dir():
        raise ValueError(f"--source must be a project directory (got: {source})")
    notes: list[str] = []
    exclude_patterns: list[str] = []
    # Composer dependencies: the documented layout is to encrypt only the application's own code and
    # deploy vendor/ separately (MANUAL §14: OPcache keeps caching it, and a protected file costs a
    # decrypt + compile per request). Third-party code also trips the source-reading detectors
    # (Blade's compiler tokenizes TEMPLATES, not itself) and would wrongly switch options off.
    skip_top: frozenset = frozenset()
    if (source / "vendor" / "autoload.php").is_file():
        skip_top = frozenset({"vendor"})
        exclude_patterns.append("vendor/*")
        notes.append("vendor/ (Composer dependencies) is left out of the encryption and of this analysis: "
                     "deploy it next to the package yourself (composer install --no-dev "
                     "--optimize-autoloader on the server, or a copy from your clean build). Encrypting it "
                     "would cost a decrypt and compile per request for code that is not yours to hide.")
    for cache in _RUNTIME_CACHE_DIRS:
        if (source / cache).is_dir():
            exclude_patterns.append(cache + "/*")
    if any(p.endswith("/*") and p != "vendor/*" for p in exclude_patterns):
        notes.append("Run-time cache folders (" + ", ".join(p[:-2] for p in exclude_patterns
                                                           if p != "vendor/*") +
                     ") are regenerated on the server and are not packed; they must still exist and be "
                     "writable there.")
    findings = compatibility_findings(source, extensions, skip_top)
    for cache in _RUNTIME_CACHE_DIRS:
        for data in findings.values():
            data["hits"] = [h for h in data["hits"] if not h[0].startswith(cache + "/")]
    findings = {c: d for c, d in findings.items() if d["hits"]}
    comment_sensitive = {c: d for c, d in findings.items() if c in _COMMENT_SENSITIVE_CATEGORIES}
    encryption_breaking = {c: d for c, d in findings.items() if c in _ENCRYPTION_BREAKING_CATEGORIES}
    eval_hits = _tree_uses_runtime_compile(source, extensions, skip_top)
    ffi_hits = _tree_matches(source, extensions, _FFI_RE, skip_top)
    scanned = [p.relative_to(source).as_posix() for p in _scanned_files(source, extensions, skip_top)]
    scanned = [p for p in scanned if not any(p.startswith(c + "/") for c in _RUNTIME_CACHE_DIRS)]
    templates = sorted(p for p in scanned if p.lower().endswith(_TEMPLATE_SUFFIXES))
    entry_scripts = _cleartext_php_entry_points(source, skip_top)

    on: list[str] = []
    off: dict[str, str] = {}
    verify: dict[str, str] = {}
    exclude = {c: sorted({h[0] for h in d["hits"]}) for c, d in encryption_breaking.items()}
    # Composer libraries that read TYPE information from @var/@param docblocks of the application's
    # classes at run time (Symfony's PropertyInfo/Serializer through phpDocumentor): the docblock
    # detectors look only at the application's own code, so they cannot see this use.
    docblock_readers = [name for name in ("phpdocumentor/reflection-docblock", "symfony/property-info")
                        if (source / "vendor" / name).is_dir()]
    if templates:
        # Templates are not code to hide (markup plus echo); they are kept cleartext and do NOT stop
        # --bytecode for the rest, unlike the files below that read their own source.
        exclude["template-source"] = templates
        notes.append("Blade templates (*.blade.php) are read as TEXT and compiled by Laravel into its "
                     "view cache: keep them cleartext (they are in the cleartext list and must be deployed "
                     "as they are).")
    # Byte-identical on all four CMSs measured — the balanced hardening core.
    on += ["--encode-strings", "--obfuscate", "--obfuscate-flow", "--obfuscate-methods"]
    verify["--obfuscate-methods"] = (
        "very probably fine (it skips every dynamic call it can see, and was byte-identical on four "
        "CMSs), but a private method reached through a name built at run time (e.g. "
        "[$this, 'on' . $event] or a string handed to a callback) would break. Check: test the parts of "
        "the app that dispatch by name; if one breaks, drop this option")
    # include protection: a protected file refuses to load unless a protected file of the same project
    # is already on the call stack or it is the entry script. An extensionless PHP entry point
    # (artisan, bin/console) is never encrypted by pack, so the console would refuse the protected code
    # it loads: measured on Laravel, `php artisan route:list` -> "include protection: it can only be
    # loaded by its own application" while the web routes ran.
    if entry_scripts:
        off["--include-protection"] = (
            "this project has a PHP entry point that pack leaves in the clear (" + ", ".join(entry_scripts[:3]) +
            ": no .php extension); with include protection the protected code it loads refuses to run, "
            "so its console commands (migrations, queues, the scheduler) would fail. Use it only if every "
            "entry point is protected")
    elif "vendor/*" in exclude_patterns:
        # This recommendation itself leaves vendor/ out (above), and the two do not mix: PHP calls some
        # library code back with no protected file on the call stack — an exception or error handler,
        # a shutdown function, a session or output handler registered from vendor/ — and when that
        # code autoloads one of the project's protected classes (through vendor/'s autoloader),
        # include protection refuses it and the request dies, usually on its error path. Measured by
        # the external audit of 2026-11-12 (H-03): an exception handler in vendor/ loading a protected
        # formatter -> "include protection: it can only be loaded by its own application".
        off["--include-protection"] = (
            "vendor/ (Composer) is left out of the package, and library code that PHP calls back with no "
            "protected file on the call stack — an exception or error handler, a shutdown function, a "
            "session or output handler registered from vendor/ — refuses to load your protected classes "
            "under include protection, so the request dies, often on its error page. Use it only if "
            "vendor/ is packed with the application too, and then test the error pages")
    else:
        on.append("--include-protection")
        verify["--include-protection"] = (
            "it works only if every PHP file that loads these files is in this package or is the entry "
            "script itself. If --source is only part of an application (a plugin, theme or module that an "
            "unprotected CMS or framework loads), the protected files refuse to load: leave it off then. "
            "Check: pack the whole application, then open the site and run every console command and cron "
            "job once")
    if ffi_hits:
        off["--no-ffi"] = ("the project itself uses FFI or dl() (e.g. " + ffi_hits[0] + "), and a --no-ffi "
                           "package refuses to load while either is reachable")
    else:
        on.append("--no-ffi")
        verify["--no-ffi"] = (
            "depends on the server, which this analysis cannot see: its php.ini must set enable_dl = Off "
            "(PHP's built-in default is On; the php.ini-production and php.ini-development templates set it "
            "Off) and must not arm FFI (ffi.enable = 0, or no ffi extension; FFI's default 'preload' arms it "
            "in the command-line PHP, which Debian/Ubuntu load, so set ffi.enable = 0 there too if the app "
            "runs console commands). Otherwise every protected file refuses to load. Check: run "
            "scripts/envelock-preflight.php on the server; drop this option if you cannot change php.ini")
    on.append("--no-prepend")
    verify["--no-prepend"] = (
        "depends on the server: auto_prepend_file and auto_append_file must be empty there, and some "
        "hosting security or monitoring agents set one (Wordfence's firewall, for instance); otherwise the "
        "package refuses to load. Check: run scripts/envelock-preflight.php on the server")
    # strip-comments / compact: only when nothing reads its own docblocks/comments at run time
    # (PrestaShop's AbstractLazyArray did, so these broke it — four-CMS matrix).
    if comment_sensitive:
        files = sorted({h[0] for d in comment_sensitive.values() for h in d["hits"]})
        reason = ("the tree reads its own docblocks/comments at run time (" +
                  ", ".join(sorted(comment_sensitive)) + f"; e.g. {files[0]}); removing them would "
                  "silently break it")
        off["--strip-comments"] = reason
        off["--compact"] = reason
    else:
        on += ["--strip-comments", "--compact"]
        why = ("no code here reads its own docblocks in a way the analysis knows (annotations, "
               "getDocComment(), file headers), but a library can read the application's @var/@param "
               "docblocks for type information at run time")
        if docblock_readers:
            why += (" — and this project has one (" + ", ".join("vendor/" + n for n in docblock_readers) +
                    ", used e.g. by Symfony's serializer and forms): with the comments gone it can "
                    "silently change how data is (de)serialised")
        why += (". Check: test the paths that serialise, deserialise or validate objects; if anything "
                "changes, drop both options")
        verify["--strip-comments"] = why
        verify["--compact"] = why
        notes.append("--compact collapses each file's lines: error messages, stack traces and listings "
                     "that show source positions (e.g. `artisan route:list`) report the collapsed line "
                     "numbers. Leave it off if you need production line numbers.")
    # sealed: only when the tree does not compile strings at run time (eval/create_function/assert) AND
    # there are no .php files we have to keep cleartext (sealed would refuse those unless allowlisted —
    # recommending --sealed together with --exclude of .php was ENV-2026-12).
    cleartext_php = sorted({f for files in exclude.values() for f in files if f.lower().endswith(".php")})
    if "vendor/*" in exclude_patterns:
        cleartext_php.insert(0, "vendor/")
    if eval_hits:
        off["--sealed"] = ("the tree uses eval()/create_function()/assert('...') (e.g. " + eval_hits[0] +
                           "), which --sealed refuses while active (this is why it broke WordPress and "
                           "PrestaShop)")
    elif cleartext_php:
        off["--sealed"] = ("this project keeps some .php cleartext under the tree (e.g. " + cleartext_php[0] +
                           "), and --sealed refuses cleartext .php under the tree. Use it only if you can "
                           "allowlist those exact paths with envelock.sealed_cleartext, then test.")
    else:
        on.append("--sealed")
        verify["--sealed"] = (
            "no eval() or cleartext .php was found in the tree, but many applications WRITE cleartext PHP "
            "at run time (compiled templates, a service container, config caches), which --sealed then "
            "refuses. Check: set the envelock.sealed_cleartext INI directive to the folders the app writes "
            "PHP into, then test every page and command; if the app ships or writes cleartext .php you "
            "cannot allowlist, drop --sealed")
    # --bytecode ships NO PHP source at all — the strongest protection, and measured byte-identical on
    # all four CMSs. It is now part of the production toolchain: the shipped server loaders include the
    # bytecode layer, and the packer emits with a bc-emit build. Recommend it when the project is
    # compatible — i.e. no file needs to keep its own SOURCE, because a bytecode image has no source for
    # such a file to read (the source-reading part of the `exclude` set; templates kept cleartext do not
    # count). It binds the package to its exact deploy path and PHP build, so it also needs --deploy-root
    # (ENV-2026-12, re-enabled after integration).
    if encryption_breaking:
        off["--bytecode"] = ("some files here must keep their SOURCE (see the cleartext list below, e.g. "
                             + sorted({f for c in encryption_breaking for f in exclude[c]})[0] + "); a "
                             "bytecode image ships no source for them to read. Use --bytecode only if you "
                             "exclude those exact files and test, or re-architect them (PHP 8 attributes / "
                             "a pre-generated cache).")
    else:
        on.append("--bytecode")
        # Bytecode ships no source, so --sealed (which only governs cleartext .php on disk) is redundant
        # with it; recommend the stronger one alone rather than an un-measured --sealed + --bytecode combo.
        if "--sealed" in on:
            on.remove("--sealed")
            verify.pop("--sealed", None)
            off["--sealed"] = ("redundant with --bytecode, which ships no PHP source at all; enabling both "
                               "is an untested combination. Use --sealed instead of --bytecode only if you "
                               "need cleartext source on disk for some reason.")
        verify["--bytecode"] = (
            "the code is compatible (nothing here needs its own source), but whether it can be used depends "
            "on the server and on your build setup, which this analysis cannot see: (1) the server runs a "
            "NON-thread-safe PHP (NTS) — the thread-safe loaders (Windows TS, Linux ZTS) refuse bytecode; "
            "(2) --bytecode-php is a php CLI of EXACTLY the server's version and build, and a PHP update on "
            "the server (even 8.4.27 -> 8.4.28) means repacking; (3) --bytecode-loader is a pack-time loader "
            "built with the emitter (--enable-envelock-bcemit, docs/BUILDING.md §2; the loaders in prebuilt/ "
            "have none); (4) --deploy-root is the absolute path the app will run from. Check: "
            "scripts/envelock-preflight.php on the server shows its PHP version and thread safety. If any "
            "of these does not hold, drop --bytecode (and consider --sealed instead)")
    # Never auto-recommend: HIGH-RISK or whole-tree-impractical options (they broke CMSs when measured).
    off["--obfuscate-properties"] = ("HIGH RISK: renaming private properties breaks the Composer "
                                     "autoloader and object serialisation (sessions/caches) — it broke "
                                     "every CMS measured (HTTP 500). Only for a self-contained app you "
                                     "can test exhaustively and that never serialises those objects.")
    off["--vault-strings"] = ("impractical on a whole large tree (did not finish on 13.6 k files) and "
                              "incompatible with --bytecode; use it per-file on a small hot module.")
    off["--obfuscate-flatten"] = (
        "experimental and not part of the four-CMS measurement: it MAY well work here (statement text and "
        "line numbers are kept, unsafe bodies are left alone), but it adds a dispatch loop to every call. "
        "Try it yourself and compare the packaged app with the original, pages and timings.")
    off["--obfuscate-names"] = (
        ("not for this project: it renames classes and functions across files, and Composer/PSR-4 "
         "autoloading finds classes by their names, so renamed ones are no longer found."
         if (source / "vendor" / "autoload.php").is_file() or (source / "composer.json").is_file() else
         "uncertain: it renames classes and functions across files, which is safe only for a closed "
         "codebase that nothing outside references by name (no autoloader, reflection, serialised "
         "objects or external callers) — the analysis cannot prove that. Try it with "
         "--obfuscate-names-allow listing only the symbols you know are internal, and test everything.") +
        " (--obfuscate-names-ast and --obfuscate-names-allow go with it.)")
    off["--virtualize"] = (
        "laboratory only: the mini-VM is quarantined (known semantic differences, needs "
        "--unsafe-vm-laboratory); never for production.")

    if encryption_breaking:
        notes.append("Keep the files below CLEARTEXT (--exclude) or re-architect them (PHP 8 attributes "
                     "/ a pre-generated cache): they read their own source TEXT and break even with base "
                     "encryption. See docs/DEPLOYING-APPS.md.")
    if exclude or exclude_patterns:
        notes.append("pack neither encrypts nor copies what --exclude names (nor non-PHP files unless "
                     "given with --asset): deploy the package over a copy of the application so those "
                     "files stay in place, removing first only the files the package replaces.")
    return {"on": on, "verify": verify, "off": off, "exclude": exclude, "exclude_patterns": exclude_patterns,
            "notes": notes}


def _cleartext_php_entry_points(source: Path, skip_top: frozenset = frozenset()) -> list[str]:
    """Extensionless PHP scripts (artisan, bin/console, cron scripts with a php shebang): pack only
    encrypts files with a PHP extension, so these stay cleartext entry points."""
    found: list[str] = []
    def skip(rel: Path) -> bool:
        return any(part in DENIED_PARTS for part in rel.parts) or (len(rel.parts) and rel.parts[0] in skip_top)
    for path in _source_entries(source, skip):
        if path.suffix or not path.is_file() or path.is_symlink():
            continue
        try:
            with open(path, "rb") as handle:
                head = handle.read(256)
        except OSError:
            continue
        first = head.split(b"\n", 1)[0]
        if head.startswith(b"<?php") or (first.startswith(b"#!") and b"php" in first):
            found.append(path.relative_to(source).as_posix())
    return sorted(found)


def format_recommendation(rec: dict) -> str:
    verify = rec.get("verify", {})
    out = ["Recommended protection for this project (strongest options that measurement shows are safe "
           "for it; see docs/DEPLOYING-APPS.md):", ""]
    out.append("Always on: encryption, signatures and the enforced manifest (the default; do not add "
               "--no-manifest).")
    out.append("")
    out.append("ENABLE — safe for this project as far as the analysis can see:")
    for flag in rec["on"]:
        if flag not in verify:
            out.append(f"  {flag}")
    if verify:
        out.append("")
        out.append("ENABLE, BUT CHECK FIRST — these may or may not work here (they are in the suggested "
                   "command; drop any you cannot confirm):")
        for flag in rec["on"]:
            if flag in verify:
                out.append(f"  {flag} — {verify[flag]}")
    out.append("")
    out.append("DO NOT enable for this project (and why):")
    for flag, reason in rec["off"].items():
        out.append(f"  {flag} — {reason}")
    patterns = rec.get("exclude_patterns", [])
    if rec["exclude"] or patterns:
        out.append("")
        out.append("Keep CLEARTEXT (not encrypted, deployed as they are):")
        for pattern in patterns:
            out.append(f"  {pattern}")
        for category, files in rec["exclude"].items():
            shown = files[:6]
            out.append(f"  [{category}] " + ", ".join(shown) + (" ..." if len(files) > 6 else ""))
    excl_files = sorted({f for files in rec["exclude"].values() for f in files})
    # glob.escape() so a literal path like 'routes/[id].php' is matched as-is by pack's fnmatch (not as a
    # character class), and shlex.quote() so a path with a quote/space cannot break the shell command.
    # The folder patterns (vendor/*, caches) are real globs: quoted, not escaped.
    excl_flags = " ".join(["--exclude " + shlex.quote(p) for p in patterns] +
                          ["--exclude " + shlex.quote(glob.escape(f)) for f in excl_files])
    cmd = ("envelock pack --owner owner.json --recipient recipient.pub --project <uuid> "
           "--source <dir> --output <out> " + " ".join(rec["on"]) +
           (" --deploy-root <absolute deploy path> --bytecode-php <php of the server's version and build> "
            "--bytecode-loader <pack-time loader build with the emitter>" if "--bytecode" in rec["on"] else "") +
           (" " + excl_flags if excl_flags else ""))
    out += ["", "Suggested command (fill in the keys, project UUID and paths):", "  " + cmd]
    if rec["notes"]:
        out.append("")
        out.append("Notes:")
        for note in rec["notes"]:
            out.append(f"  - {note}")
    out.append("")
    out.append("This is a conservative recommendation: it never enables an option known to break your "
               "project, and it says which ones depend on things it cannot see. Always test the packaged "
               "app like a real release before deploying.")
    return "\n".join(out)


def main() -> int:
    # Private key material and its parent directories must not inherit a lax umask.
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Envelock: offline encoder (prototype)")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init-owner", help="Create a private signing identity; DO NOT distribute")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--no-encrypt", action="store_true",
                   help="Store private keys UNENCRYPTED (not recommended)")
    p.add_argument("--with-recovery", action="store_true", help="Also generate a recovery key")
    p = sub.add_parser("init-recipient", help="Create a recipient X25519 pair; private")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--label", required=True)
    p.add_argument("--no-encrypt", action="store_true",
                   help="Store private keys UNENCRYPTED (not recommended)")
    p = sub.add_parser("export-public", help="Extract the recipient public key (for packing)")
    p.add_argument("--recipient", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p = sub.add_parser("export-identity", help="Create the SECRET server identity file")
    p.add_argument("--recipient", type=Path, required=True)
    p.add_argument("--owner", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p = sub.add_parser("server-install",
                       help="Install the SECRET identity file as root:root mode 0400 (O5)")
    p.add_argument("--recipient", type=Path, action="append", required=True,
                   help="Recipient private descriptor; repeat for a host serving several projects")
    p.add_argument("--owner", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True,
                   help="Where to install it, e.g. /etc/envelock/identity.bin")
    p.add_argument("--owner-user",
                   help="Install owned by this user instead of root, mode 0400, for a documented "
                        "rootless deploy (e.g. a per-user service). Without root you can only "
                        "install for yourself.")
    p = sub.add_parser("keygen", help="Generate keys (owner or recipient); alias of init-*")
    p.add_argument("kind", choices=["owner", "recipient"])
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--label", help="Recipient label (recipient only)")
    p.add_argument("--no-encrypt", action="store_true",
                   help="Store private keys UNENCRYPTED (not recommended)")
    p.add_argument("--with-recovery", action="store_true", help="Recovery key (owner only)")
    p = sub.add_parser("recipient", help="Manage the server identity file (trust store)")
    rsub = p.add_subparsers(dest="subcommand", required=True)
    pa = rsub.add_parser("add", help="Add a recipient and its developer to the identity file")
    pa.add_argument("--identity", type=Path, required=True, help="Identity file to create or extend")
    pa.add_argument("--recipient", type=Path, required=True, help="Recipient private descriptor")
    pa.add_argument("--owner", type=Path, required=True, help="Signing identity (trusted developer)")
    pr = rsub.add_parser("remove", help="Remove a recipient from the identity file")
    pr.add_argument("--identity", type=Path, required=True)
    pr.add_argument("--recipient", type=Path, required=True,
                    help="Recipient descriptor, public (export-public) or private")
    p = sub.add_parser("owner", help="Rotate the keys of a signing identity")
    osub = p.add_subparsers(dest="subcommand", required=True)
    po = osub.add_parser("new-recovery", help="Add or replace the recovery key (file updated in place)")
    po.add_argument("--owner", type=Path, required=True)
    po.add_argument("--no-encrypt", action="store_true",
                    help="Keep an unencrypted owner file unencrypted (not recommended)")
    po = osub.add_parser("promote-recovery",
                         help="Primary key compromised: the recovery key becomes the primary")
    po.add_argument("--owner", type=Path, required=True)
    po.add_argument("--out", type=Path, required=True, help="New signing identity")
    po.add_argument("--recovery", type=Path,
                    help="The separate recovery file made by 'owner split-recovery', when the "
                         "owner file no longer holds the recovery private key")
    po.add_argument("--no-encrypt", action="store_true",
                    help="Store private keys UNENCRYPTED (not recommended)")
    po = osub.add_parser("split-recovery",
                         help="Move the recovery private key to its own file (to keep it offline); "
                              "the owner file keeps only its public half")
    po.add_argument("--owner", type=Path, required=True)
    po.add_argument("--out", type=Path, required=True,
                    help="New file for the recovery key (asks for its own password)")
    po.add_argument("--no-encrypt", action="store_true",
                    help="Store the recovery key UNENCRYPTED (not recommended)")
    p = sub.add_parser("export-developer", help="Public developer descriptor (for identity files)")
    p.add_argument("--owner", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p = sub.add_parser("developer", help="Manage trusted developers in a server identity file")
    dsub = p.add_subparsers(dest="subcommand", required=True)
    pd = dsub.add_parser("set", help="Add a developer, or update its recovery key")
    pd.add_argument("--identity", type=Path, required=True)
    pd.add_argument("--developer", type=Path, required=True, help="From export-developer")
    pd.add_argument("--remove-recovery", action="store_true",
                    help="Allow dropping a trusted recovery key the descriptor does not have")
    pd = dsub.add_parser("remove", help="Remove a trusted developer")
    pd.add_argument("--identity", type=Path, required=True)
    pd.add_argument("--developer-id", required=True)
    p = sub.add_parser("minimum", help="Refuse old releases of a project on a server")
    msub = p.add_subparsers(dest="subcommand", required=True)
    pm = msub.add_parser("set", help="Set the minimum serial of a project in an identity file")
    pm.add_argument("--identity", type=Path, required=True)
    group = pm.add_mutually_exclusive_group(required=True)
    group.add_argument("--package", type=Path, help="A packed folder: uses its project and serial")
    group.add_argument("--project", help="Project UUID (with --serial)")
    pm.add_argument("--serial", type=int, help="Minimum serial (with --project)")
    pm.add_argument("--allow-downgrade", action="store_true",
                    help="Permit lowering an existing minimum (otherwise refused, to keep the "
                         "anti-rollback bar from being moved back by a tampered or older package)")
    p = sub.add_parser("licence", help="Issue or inspect a signed deployment license (O8)")
    lsub = p.add_subparsers(dest="subcommand", required=True)
    pl = lsub.add_parser("issue", help="Sign a license for one server with the owner key")
    pl.add_argument("--owner", type=Path, required=True, help="Private signing identity; DO NOT distribute")
    pl.add_argument("--out", type=Path, required=True, help="Where to write the license")
    pl.add_argument("--days", type=int, help="Expire this many days from now (omit for no expiry)")
    pl.add_argument("--expires", help="Expire at this UTC date, YYYY-MM-DD (omit for no expiry)")
    pl.add_argument("--machine", help="Bind to a host fingerprint: 'this' for the local host, "
                                      "or a 64-hex fingerprint the customer reported")
    pl.add_argument("--domain", help="Bind to a served host name, as the loader reads it from "
                                     "SERVER_NAME (nginx server_name / Apache ServerName; the machine's "
                                     "own name only for the CLI): e.g. app.example.com. 'this' hashes "
                                     "THIS machine's own name (gethostname), which is usually NOT a "
                                     "site's SERVER_NAME. IDNs are bound in punycode. Windows loaders "
                                     "refuse domain-bound licences")
    pl.add_argument("--ip", help="Bind to the server's own IPv4 addresses: 'this' for the local "
                                 "host, or a 64-hex fingerprint the customer reported")
    pl.add_argument("--force", action="store_true",
                    help="Overwrite --out (refused by default: a license names a deployment)")
    lsub.add_parser("machine-id", help="Print this host's fingerprint, to bind a license to it")
    lsub.add_parser("host-id", help="Print this host's domain and IP fingerprints")
    pc = lsub.add_parser("inspect", help="Show a license's constraints without checking its signature")
    pc.add_argument("path", type=Path)
    p = sub.add_parser("inspect", help="Show NON-secret metadata of a package, identity or config")
    p.add_argument("path", type=Path)
    p = sub.add_parser("verify", help="Check a packed folder against its signed manifest (pack --manifest)")
    p.add_argument("--package", type=Path, required=True)
    vg = p.add_mutually_exclusive_group(required=True)
    vg.add_argument("--developer", type=Path, help="Trusted developer public descriptor")
    vg.add_argument("--owner", type=Path, help="Owner descriptor (uses its signing public key)")
    p = sub.add_parser("new-project", help="Generate project UUID; keep it across releases")
    p = sub.add_parser("preflight",
                       help="Scan a source tree for code that reads its OWN source at run time "
                            "(annotations, class maps, header readers) and would break after "
                            "encryption. Read-only; changes nothing")
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--php-ext", action="append", default=[], help="Additional PHP extension, e.g. .module")
    p.add_argument("--json", action="store_true", help="Machine-readable output")
    p.add_argument("--strict", action="store_true", help="Exit non-zero if any issue is found")

    p = sub.add_parser("recommend",
                       help="Analyse a source tree and recommend the STRONGEST protection that is safe "
                            "for it: it enables the hardening options measurement shows are compatible "
                            "and turns off only what would break THIS project. Read-only")
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--php-ext", action="append", default=[], help="Additional PHP extension, e.g. .module")
    p.add_argument("--json", action="store_true", help="Machine-readable output")

    p = sub.add_parser("pack", help="Encrypt PHP per recipient and copy ONLY explicit assets")
    p.add_argument("--owner", type=Path, required=True)
    p.add_argument(
        "--recipient", type=Path, action="append", required=True,
        help="A recipient public key (.pub.json) or your own recipient.json (repeatable). "
             "Personal mode: your own recipient. An encrypted recipient must be exported first.",
    )
    p.add_argument("--project", required=True, help="UUID issued by new-project")
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--asset", action="append", default=[], help="Pattern of assets to copy without encrypting")
    p.add_argument("--exclude", action="append", default=[], help="Relative path pattern to exclude")
    p.add_argument("--php-ext", action="append", default=[], help="Additional PHP extension, e.g. .module")
    p.add_argument("--strip-comments", action="store_true",
                   help="Remove comments/docblocks before encrypting (less memory; breaks code that "
                        "reads docblocks via reflection, e.g. annotations)")
    p.add_argument("--obfuscate", action="store_true",
                   help="Give local variables short names (parameters, properties and functions "
                        "that use names at run time are kept)")
    p.add_argument("--compact", action="store_true",
                   help="Collapse whitespace and remove comments (one space between tokens; line "
                        "numbers are NOT preserved). Combine with --obfuscate/--strip-comments")
    p.add_argument("--encode-strings", action="store_true",
                   help="Re-spell string literals as \\xNN byte escapes (same value, hides SQL, "
                        "messages and paths). Interpolated and heredoc strings are left as is")
    p.add_argument("--obfuscate-methods", action="store_true",
                   help="Rename PRIVATE methods that are only called via $this->/self::/static:: "
                        "(skipped if the name is used dynamically or as a string; test the package)")
    p.add_argument("--obfuscate-properties", action="store_true",
                   help="HIGH RISK: rename PRIVATE instance properties used only as $this->name. "
                        "Breaks data serialized before obfuscation (serialize/sessions/caches); test")
    p.add_argument("--obfuscate-flatten", action="store_true",
                   help="O6, experimental: rewrite each named function/method body whose statements are plain "
                        "code into a dispatch loop (while/switch on a state variable). Statement text and line "
                        "numbers are kept; generators, goto, nested declarations, include/eval, dynamic variables, "
                        "compact/extract/get_defined_vars/parse_str and declare are left alone. Not combinable "
                        "with --virtualize. Test the package against the unprotected app")
    p.add_argument("--obfuscate-flow", action="store_true",
                   help="Insert an always-false opaque-predicate dead branch at the start of each "
                        "function/method (modest control-flow obfuscation; behaviour and line numbers "
                        "unchanged; functions using goto are skipped). Test the package")
    p.add_argument("--obfuscate-names", action="store_true",
                   help="Rename eligible classes, interfaces, traits, enums and functions and their "
                        "static references in a closed package (objective O6). External references, "
                        "autoloading or reflection can break. Literal and dynamic cases are skipped; "
                        "namespaced code additionally requires --obfuscate-names-ast. Test the package")
    p.add_argument("--obfuscate-names-ast", action="store_true",
                   help="EXPERIMENTAL: permit AST-based renaming in a closed namespaced package. "
                        "Requires --obfuscate-names. Not for frameworks, PSR-4/classmap autoloaders, "
                        "reflection or externally used symbols; test the complete deployed app")
    p.add_argument("--obfuscate-names-allow", action="append", metavar="KIND:FQN",
                   help="EXPERIMENTAL strict allowlist: rename ONLY each listed type:FQN or "
                        "function:FQN (repeatable; no leading backslash). Requires both name flags; "
                        "an unknown or ineligible entry aborts the pack. Not proof of a closed world")
    p.add_argument("--virtualize", action="append", metavar="FUNCION",
                   help="Experimental: run this top-level global function through the mini-VM "
                        "(repeatable); requires --virtualize-loader and rejects --obfuscate-names")
    p.add_argument("--virtualize-loader", metavar="LOADER|builtin",
                   help="Required with --virtualize: local v2-capable extension to probe, or 'builtin' "
                        "for a statically linked loader. Deploy and test the same compatible build")
    p.add_argument("--unsafe-vm-laboratory", action="store_true",
                   help="UNSAFE, LABORATORY ONLY: bypass the VM quarantine despite known semantic "
                        "divergences. Never deploy such packages to production")
    p.add_argument("--vault-strings", action="store_true",
                   help="Move string literals that sit in a runtime position into a per-file vault "
                        "the loader resolves, so they are not kept as op_array constants (hides SQL, "
                        "messages, paths from a dump of the compiled code). Adds a call per literal "
                        "access; literals in constant expressions stay inline. Test the package")
    p.add_argument("--bytecode", action="store_true",
                   help="Ship each file as precompiled bytecode instead of encrypted source: the "
                        "server never compiles PHP, so there is no source in the package or in "
                        "memory to intercept. Needs the target server's exact PHP build with the "
                        "Envelock loader; the image is refused by any other build. Incompatible "
                        "with --vault-strings")
    p.add_argument("--bytecode-php", default=None,
                   help="php CLI used to compile the bytecode (default: --php). It MUST be the same "
                        "version and build as the PHP that will run the package")
    p.add_argument("--bytecode-loader", default=None,
                   help="Path of the Envelock loader module to load into that php CLI, when it is "
                        "not enabled in its configuration")
    p.add_argument("--deploy-root", type=Path, default=None,
                   help="Absolute path the package will be deployed at (required with --bytecode). "
                        "The sources are compiled there and removed again, so __DIR__, __FILE__ and "
                        "resolved include paths are the server's; the package then only runs from "
                        "that path. The folder is created if needed and only the packed files are "
                        "written into it")
    p.add_argument("--manifest", action="store_true",
                   help="Write a signed envelock-manifest of the whole tree; check it later with "
                        "'verify' to detect a deleted, added, modified or swapped file")
    p.add_argument("--php", default="php",
                   help="php CLI used by --strip-comments/--obfuscate/--compact (PHP 8+ with tokenizer)")
    p.add_argument("--include-protection", action="store_true",
                   help="Protected files run only as the entry point or when called from "
                        "protected code of the same project (not from other scripts)")
    p.add_argument("--no-prepend", action="store_true",
                   help="Refuse to run when auto_prepend_file/auto_append_file are set")
    p.add_argument("--no-ffi", action="store_true",
                   help="Refuse to run while FFI or dl() is reachable (they can read the "
                        "decrypted code from process memory); enable only if the app needs neither")
    p.add_argument("--sealed", action="store_true",
                   help="Sealed tree: the loader refuses any plain (unencrypted) PHP under the "
                        "package folder and refuses eval() while the package is active; enable only "
                        "if every .php in the tree is protected and the app does not use eval()")
    # The runtime manifest is ON BY DEFAULT: it adds deletion detection and, with the loader's
    # envelock.manifest_fastpath (default on), removes the first-request per-file Ed25519 cost
    # (measured ~5x). --no-manifest opts out. --enforce-manifest is kept as the (now redundant)
    # explicit form. Deploy the whole package as one unit; removing a listed file refuses the package.
    p.add_argument("--enforce-manifest", dest="enforce_manifest", action="store_true",
                   help="(default) write a signed binary manifest the loader checks at run time: it "
                        "refuses to run if any listed file is missing (deletion detection)")
    p.add_argument("--no-manifest", dest="enforce_manifest", action="store_false",
                   help="Do not write the runtime manifest (opt out of the default integrity check "
                        "and the manifest fast path)")
    p.set_defaults(enforce_manifest=True)
    p.add_argument("--serial", type=int,
                   help="Release number (default: the current time in NANOSECONDS since the Unix "
                        "epoch, e.g. 1789000000000000000); see 'minimum set'")
    p.add_argument("--allow-demo", action="store_true",
                   help="Permit the PUBLIC demo keys (their private halves are published, so the "
                        "package would be readable by anyone); for testing only")
    p.add_argument("--allow-secret-assets", action="store_true",
                   help="Permit config assets (.json/.env/.ini/...) whose content looks like "
                        "credentials. Assets are NOT encrypted; only use this after reviewing them")
    args = parser.parse_args()
    try:
        if args.command == "init-owner":
            save_json(args.out, make_owner(with_recovery=args.with_recovery), new_password(args))
        elif args.command == "init-recipient":
            save_json(args.out, make_recipient(args.label), new_password(args))
        elif args.command == "export-public":
            save_json(args.out, recipient_public(read_config(args.recipient, "envelock-recipient")))
        elif args.command == "export-identity":
            identity = make_identity(
                read_config(args.recipient, "envelock-recipient"),
                read_config(args.owner, "envelock-owner"),
            )
            secret_write(args.out, identity_bytes(identity))
            print(RESTART_NOTE)
        elif args.command == "server-install":
            owner_uid, owner_gid, owner_name = 0, 0, "root"
            if args.owner_user and os.name == "nt":
                raise ValueError("--owner-user is for POSIX servers (a user to own the 0400 file). "
                                 "On Windows the file is created with a protected access list "
                                 "(SYSTEM, Administrators, you); grant the PHP service account read "
                                 "access with icacls instead. Nothing was written.")
            if args.owner_user:
                import pwd
                try:
                    pw = pwd.getpwnam(args.owner_user)
                except KeyError:
                    raise ValueError(f"unknown user for --owner-user: {args.owner_user}")
                owner_uid, owner_gid, owner_name = pw.pw_uid, pw.pw_gid, pw.pw_name
            server_install(
                server_install_identities(args.recipient, args.owner), args.out,
                owner_uid=owner_uid, owner_gid=owner_gid)
            if os.name == "nt":
                print(f"Installed {args.out}, read-only, readable only by SYSTEM, Administrators "
                      "and you (protected access list).")
                print("The loader accepts only the PHP service account, SYSTEM and Administrators: "
                      "if PHP does not run as you, grant its account read access and remove yours, "
                      "e.g. icacls <file> /grant:r \"<php-service-account>:R\" /remove:g %USERNAME%")
            else:
                print(f"Installed {args.out} as {owner_name} mode 0400.")
            print("Point envelock.identity at it in the shared php.ini, not in a pool:")
            print("  envelock.identity = " + str(args.out))
            print(RESTART_NOTE)
        elif args.command == "keygen":
            if args.kind == "owner":
                save_json(args.out, make_owner(with_recovery=args.with_recovery), new_password(args))
            else:
                if not args.label:
                    raise ValueError("keygen recipient requires --label")
                save_json(args.out, make_recipient(args.label), new_password(args))
        elif args.command == "recipient":
            existing = (
                bounded_read(args.identity, IDENTITY_MAX_FILE) if args.identity.exists() else None
            )
            if args.subcommand == "add":
                data = add_recipient_to_store(
                    existing,
                    read_config(args.recipient, "envelock-recipient"),
                    read_config(args.owner, "envelock-owner"),
                )
            else:
                if existing is None:
                    raise ValueError("The identity file does not exist")
                data = remove_recipient(existing, recipient_public_hex(args.recipient))
            write_store(args.identity, data)
            print(RESTART_NOTE)
        elif args.command == "owner":
            owner, password = read_config_with_password(args.owner, "envelock-owner")
            if args.subcommand == "new-recovery":
                # Re-encrypt with the same password; an unencrypted file gets encrypted now
                # unless --no-encrypt says otherwise. Replaced atomically.
                if password is None:
                    password = new_password(args)
                data = new_recovery(owner)
                tmp = args.owner.parent / (args.owner.name + ".tmp-" + secrets.token_hex(4))
                try:
                    save_json(tmp, data, password, like=args.owner)
                    replace_file(tmp, args.owner)
                finally:
                    if tmp.exists():
                        tmp.unlink()
            elif args.subcommand == "split-recovery":
                # ENC-11: write the recovery key's own file FIRST (exclusive create), then rewrite
                # the owner without it, keeping its password. A failure in between leaves both keys
                # in the owner file and a recovery copy: nothing is ever lost.
                kept, recovery = split_recovery(owner)
                save_json(args.out, recovery, new_password(args))
                tmp = args.owner.parent / (args.owner.name + ".tmp-" + secrets.token_hex(4))
                try:
                    save_json(tmp, kept, password, like=args.owner)
                    replace_file(tmp, args.owner)
                finally:
                    if tmp.exists():
                        tmp.unlink()
                print(f"Recovery key moved to {args.out}; {args.owner} keeps only its public half. "
                      "Keep the recovery file offline; promote it with 'owner promote-recovery "
                      "--recovery' if the primary key is ever compromised.")
            else:
                recovery = read_config(args.recovery, "envelock-owner") if args.recovery else None
                save_json(args.out, promote_recovery(owner, recovery), new_password(args))
        elif args.command == "export-developer":
            save_json(args.out, developer_public(read_config(args.owner, "envelock-owner")))
        elif args.command == "developer":
            existing = bounded_read(args.identity, IDENTITY_MAX_FILE)
            if args.subcommand == "set":
                data = set_developer(existing, read_config(args.developer, "envelock-developer-public"),
                                     args.remove_recovery)
            else:
                data = remove_developer(existing, args.developer_id)
            write_store(args.identity, data)
            print("Trusted developers before:", *describe_developers(existing), sep="\n  ")
            print("Trusted developers now:", *describe_developers(data), sep="\n  ")
            print(RESTART_NOTE)
        elif args.command == "minimum":
            if args.package and args.serial is not None:
                # The serial comes from the package's SIGNED header; a --serial given alongside was
                # silently ignored, so the operator believed a different minimum was set (ENC-23).
                raise ValueError("--serial goes with --project; with --package the serial is read "
                                 "from the package's signed header")
            existing = bounded_read(args.identity, IDENTITY_MAX_FILE)
            if args.package:
                # ENV-09: read project/serial from a SIGNED, trusted header, not from the
                # unsigned envelock-package.json (which a tampered package could forge).
                header, signer = verified_header_and_signer(
                    first_protected_file(args.package), identity_signers(existing))
                project, serial = str(uuid.UUID(bytes=header["project"])), header["serial"]
                # ENV-AUD-14: bind the minimum to the developer who signed the package, so it cannot
                # affect another developer's project on a shared server.
                developer_pub = developer_primary_for_signer(existing, signer)
            elif args.serial is None:
                raise ValueError("--project needs --serial")
            else:
                project, serial = args.project, args.serial
                developer_pub = ZERO32   # admin-set: unbound (applies to any developer)
            data = set_minimum(existing, project, serial, developer_pub, args.allow_downgrade)
            write_store(args.identity, data)
            print(f"Project {uuid.UUID(project)}: releases with a serial below {serial} are refused")
            print(RESTART_NOTE)
        elif args.command == "licence":
            if args.subcommand == "machine-id":
                print(machine_fingerprint().hex())
            elif args.subcommand == "host-id":
                name = host_domain()
                print("domain  :", name)
                print("  hash  :", domain_hash(name).hex())
                try:
                    print("ipv4    :", ", ".join(host_ipv4_addresses()) or "none")
                    print("  hash  :", host_ips_hash().hex())
                except ValueError as error:
                    print("ipv4    :", error)
                print("note: on a web server the loader compares SERVER_NAME (the configured server "
                      "name), which is usually the site name rather than this machine's own name; "
                      "bind --domain to that one")
            elif args.subcommand == "inspect":
                info = parse_licence(bounded_read(args.path, LICENCE_SIZE + 1))
                shown = {"format": info["format"],
                         "expires": (time.strftime("%Y-%m-%d %H:%M:%S UTC",
                                                   time.gmtime(info["expires"]))
                                     if info["expires"] else "never"),
                         "machine": (info["machine"].hex()
                                     if info["machine"] != ZERO32 else "any"),
                         "domain": info["domain"].hex() if info["domain"] != ZERO32 else "any",
                         "ip": info["ip"].hex() if info["ip"] != ZERO32 else "any"}
                print(json.dumps(shown, indent=2))
                print("note: this does NOT verify the signature; the loader does that")
            else:
                owner = read_config(args.owner, "envelock-owner")
                expires = 0
                if args.days is not None and args.expires:
                    raise ValueError("--days and --expires are alternatives")
                if args.days is not None:
                    if not 0 < args.days <= 36500:
                        raise ValueError("--days must be between 1 and 36500")
                    expires = int(time.time()) + args.days * 86400
                elif args.expires:
                    # Interpret the date as end-of-day UTC with calendar.timegm: unambiguous and free of
                    # the daylight-saving double-correction that time.mktime()-time.timezone produced on
                    # DST dates (ENV-2026-18). strptime validates the format before anything is written.
                    expires = calendar.timegm(time.strptime(args.expires + " 23:59:59",
                                                            "%Y-%m-%d %H:%M:%S"))
                    if expires <= time.time():
                        # An already-expired licence is refused by every loader (ENC-23).
                        raise ValueError(f"--expires {args.expires} is in the past; the licence "
                                         "would be expired on issue")
                domain = ip = ZERO32
                if args.domain:
                    domain = (domain_hash(host_domain()) if args.domain == "this"
                              else domain_hash(args.domain))
                if args.ip:
                    if args.ip == "this":
                        ip = host_ips_hash()
                    else:
                        ip = bytes.fromhex(args.ip)
                        if len(ip) != 32:
                            raise ValueError("--ip takes 'this' or 64 hex characters")
                machine = ZERO32
                if args.machine:
                    if args.machine == "this":
                        machine = machine_fingerprint()
                    else:
                        machine = bytes.fromhex(args.machine)
                        if len(machine) != 32:
                            raise ValueError("--machine takes 'this' or 64 hex characters")
                if args.out.exists() and not args.force:
                    raise ValueError(f"refusing to overwrite {args.out} (use --force)")
                if args.domain == "this":
                    print("WARNING: --domain this binds THIS machine's own name ("
                          + host_domain() + "); on a web server the loader compares SERVER_NAME "
                          "(the configured server name), which is usually different. Bind the "
                          "site's name instead unless the package only runs from the CLI.",
                          file=sys.stderr)
                if machine != ZERO32 or domain != ZERO32 or ip != ZERO32:
                    # The Windows loader has no machine, domain or IP fingerprint: it REFUSES such a
                    # licence (fail closed) rather than ignore the binding (ENC-18).
                    print("WARNING: this licence is bound to a machine, domain or IP address. "
                          "Loaders on Windows servers cannot check those bindings and REFUSE it: "
                          "it will not run on a Windows server. Issue an unbound (expiry-only) "
                          "licence for Windows hosts.", file=sys.stderr)
                blob = issue_licence(owner, expires=expires, machine=machine,
                                     domain=domain, ip=ip)
                # A license is NOT secret — its integrity comes from the signature — so it is
                # written world-readable. That matters: the PHP worker usually runs as the pool
                # user, and a 0600 file owned by root would be unreadable to it and would fail
                # closed in a way that looks like a bad license.
                # Atomic replace (ENV-2026-20): a running server never sees licence.bin missing.
                write_public(args.out, blob)
                print(f"License written to {args.out}")
                print("  expires : "
                      + (time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(expires))
                         if expires else "never"))
                print(f"  machine : {machine.hex() if machine != ZERO32 else 'any'}")
                print(f"  domain  : {args.domain if domain != ZERO32 else 'any'}")
                print(f"  ip      : {args.ip if ip != ZERO32 else 'any'}")
                print("Point envelock.licence at it in php.ini. It is not secret, but it is "
                      "per-server: issue one per host.")
        elif args.command == "inspect":
            print(json.dumps(inspect_path(args.path), indent=2))
        elif args.command == "verify":
            kind = "envelock-developer-public" if args.developer else "envelock-owner"
            pub = read_config(args.developer or args.owner, kind)["signing_public"]
            report = verify_package(args.package, pub)
            print(json.dumps(report, indent=2))
            return 0 if report["ok"] else 1
        elif args.command == "new-project":
            print(uuid.uuid4())
        elif args.command == "preflight":
            extensions = DEFAULT_EXTENSIONS | {"." + x.lower().lstrip(".") for x in args.php_ext}
            findings = compatibility_findings(args.source, extensions)
            if args.json:
                print(json.dumps({c: {"hint": d["hint"], "hits": d["hits"]}
                                  for c, d in findings.items()}, indent=2))
            else:
                print(format_compatibility_report(findings))
            return 1 if (args.strict and findings) else 0
        elif args.command == "recommend":
            extensions = DEFAULT_EXTENSIONS | {"." + x.lower().lstrip(".") for x in args.php_ext}
            rec = recommend_options(args.source, extensions)
            if args.json:
                print(json.dumps(rec, indent=2))
            else:
                print(format_recommendation(rec))
            return 0
        elif args.command == "pack":
            if args.virtualize and args.unsafe_vm_laboratory:
                print("WARNING: virtualized packages remain unsafe and are for laboratory use only; "
                      "PHP semantic divergences are known.", file=sys.stderr)
            extensions = DEFAULT_EXTENSIONS | {"." + x.lower().lstrip(".") for x in args.php_ext}
            recipients = [cli_recipient_public(r) for r in args.recipient]
            owner = read_config(args.owner, "envelock-owner")
            # The demo-key refusal lives in pack_tree now (so the GUI and API are covered too,
            # ENV-AUD-07); the CLI just forwards the opt-in flag.
            info = pack_tree(
                args.source,
                args.output,
                recipients,
                owner,
                args.project,
                extensions,
                args.asset,
                args.exclude,
                args.php,
                args.strip_comments,
                args.obfuscate,
                args.include_protection,
                args.no_prepend,
                args.serial,
                args.compact,
                args.encode_strings,
                args.obfuscate_methods,
                args.manifest,
                args.obfuscate_properties,
                args.no_ffi,
                args.sealed,
                args.enforce_manifest,
                args.obfuscate_flow,
                args.vault_strings,
                args.allow_demo,
                args.allow_secret_assets,
                obfuscate_names=args.obfuscate_names,
                obfuscate_names_ast=args.obfuscate_names_ast,
                obfuscate_names_allowlist=args.obfuscate_names_allow,
                virtualize=args.virtualize,
                virtualize_loader=args.virtualize_loader,
                unsafe_vm_laboratory=args.unsafe_vm_laboratory,
                obfuscate_flatten=args.obfuscate_flatten,
                bytecode=args.bytecode,
                bytecode_php=args.bytecode_php,
                bytecode_loader=args.bytecode_loader,
                deploy_root=args.deploy_root,
            )
            # ENV-AUD-15: the base protection (per-file AES-256-GCM encryption + Ed25519 signing) is
            # always on, and the runtime manifest is on by default, but the confidentiality hardening
            # layers are opt-in. Advise when a bare pack leaves them all off. enforce_manifest is NOT
            # in this check: it is integrity, not code confidentiality, and it is on by default — so a
            # default pack still earns the advisory about the confidentiality layers.
            if not any((args.include_protection, args.sealed, args.no_ffi,
                        args.vault_strings, args.no_prepend, args.obfuscate, args.obfuscate_methods,
                        args.obfuscate_properties, args.strip_comments, args.encode_strings,
                        args.bytecode)):
                print("Note: base protection only (encryption + signing). For stronger protection "
                      "add --include-protection, --no-ffi, --vault-strings and --sealed "
                      "(see docs/SEGURIDAD.md).", file=sys.stderr)
            # H-08 (audit 2026-11-12): an --asset that copied nothing is no longer silent.
            for missing in info.get("assets_not_copied", []):
                print(f"WARNING: --asset {missing['asset']} was not copied: {missing['reason']}.",
                      file=sys.stderr)
            # H-02 (audit 2026-11-12): what --sealed does NOT cover, said where the choice is made.
            if args.sealed:
                print("Note: --sealed refuses plain PHP under the package folder only once a protected "
                      "file of the package has loaded in that PHP process. A plain file run in a fresh "
                      "process (every CLI run, the first request of a new worker), or one OPcache "
                      "already holds in shared memory, is not checked. Put the whole package FOLDER in "
                      "opcache.blacklist_filename (or disable OPcache), keep the entry point protected "
                      "and keep the folder unwritable by the web server (docs/SEGURIDAD.md).",
                      file=sys.stderr)
            # --strip-comments / --compact physically REMOVE docblocks. Code that reads its own
            # docblocks at run time (custom annotations such as PrestaShop's @arrayAccess, Doctrine
            # @ORM, WP file headers) then silently misbehaves with no pack-time error. This is the one
            # flag combination that can corrupt a tree invisibly, so actively scan and warn for it.
            if args.strip_comments or args.compact:
                sensitive = {c: d for c, d in
                             compatibility_findings(args.source, extensions).items()
                             if c in _COMMENT_SENSITIVE_CATEGORIES}
                if sensitive:
                    files = len({h[0] for d in sensitive.values() for h in d["hits"]})
                    print("WARNING: --strip-comments/--compact removes docblocks, and " +
                          str(files) + " file(s) in this tree read their own docblocks at run time "
                          "(annotations). They will silently misbehave after this pack. Run 'envelock "
                          "preflight --source " + str(args.source) + "' for the list, then --exclude "
                          "those files or drop --strip-comments/--compact.", file=sys.stderr)
            print("Tip: for third-party or framework code, run 'envelock preflight --source " +
                  str(args.source) + "' first to flag code that reads its own source "
                  "(annotations, class maps) and would break after encryption.", file=sys.stderr)
            print(json.dumps(info, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, EOFError, RecursionError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

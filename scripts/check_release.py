#!/usr/bin/env python3
"""Release guard: refuse to publish if private, personal or attribution material is present.

Scans a directory tree (default: repo root) and fails (exit 1) when it finds anything
that must never ship: installation identities, keys, passwords, compiled loaders with
embedded keys, real personal/server data, or AI-attribution markers.

Portable (Python stdlib only). Run before every commit, archive or release:

    python scripts/check_release.py            # scan repo root
    python scripts/check_release.py some/dir   # scan a staged release tree

Exit status: 0 clean, 1 findings, 2 usage error (e.g. the argument is not a directory).

Extra literal terms to block (e.g. vendor or internal app names) can be listed, one per
line, in scripts/forbidden-terms.txt; that file is git-ignored so the terms never ship.
"""
from __future__ import annotations

import codecs
import hashlib
import json
import os
import re
import sys
from pathlib import Path

# Files that must never be published, matched case-insensitively against the name. Envelock's own
# key/identity files are refused everywhere, third_party/ included; the generic patterns (other
# people's certificates, backups) do not apply to upstream sources, whose test keys are theirs.
ENVELOCK_SECRET_NAMES = [
    re.compile(p, re.I)
    for p in (
        r".*\.enc\.json$",
        r"owner.*\.json$",
        r"recipient.*\.json$",
        r"installation.*\.json$",
        r"identity.*\.bin$",
        r"generated_keys\.h$",
        r"audit_keys\.h$",
    )
]
# Secrets and leftovers refused in the portable Python too (where CA bundles, .pem, are legitimate).
SECRET_NAMES = ENVELOCK_SECRET_NAMES + [
    re.compile(p, re.I)
    for p in (
        r"credentials.*",
        r".*password.*\.txt$",
        r".*\.(?:key|p12|pfx|bak|old|orig|swp|log)$",  # keys, editor backups, build logs
        r".*~$",
        r"\.env.*",                                     # environment files with secrets
    )
]
FORBIDDEN_NAMES = SECRET_NAMES + [re.compile(r".*\.pem$", re.I)]
# What each prebuilt/ area may hold (beyond being listed in prebuilt/SHA256SUMS).
PREBUILT_AREAS = {"loader": re.compile(r"(?:envelock\.so|php_envelock\.dll)$"),
                  "python-wheels": re.compile(r".*\.whl$"),
                  "assistant": re.compile(r"envelock-assistant(?:\.exe)?$")}

# Compiled artifacts (may embed per-installation keys) and debug symbols, by name or by content.
# Python bytecode too: a .pyc embeds the absolute path of its source (a user/home folder).
FORBIDDEN_EXT = {".so", ".dll", ".dylib", ".pdb", ".obj", ".lib", ".a", ".o", ".lo", ".whl", ".exe",
                 ".pyd", ".rlib", ".pyc", ".pyo"}
BINARY_MAGIC = (b"\x7fELF", b"MZ", b"!<arch>\n", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
# Data formats that are never text: upstream files starting like this are not searched for terms
# (their random bytes would give false matches).
DATA_MAGIC = BINARY_MAGIC + (b"\x89PNG", b"GIF8", b"\xff\xd8\xff", b"icns", b"\x00\x00\x01\x00",
                             b"PK\x03\x04", b"\x1f\x8b", b"BZh", b"\xfd7zXZ", b"%PDF", b"wOF", b"\x00\x01\x00\x00")
# Repository folders whose every file must be listed, with the same hash, in <folder>/SHA256SUMS:
# prebuilt/ (the only compiled files allowed) and third_party/ (upstream sources byte for byte, so
# build outputs, swapped files or end-of-line conversions are caught). Upstream authors' emails,
# test keys and binaries are theirs: in third_party/ only Envelock's own secrets, forbidden terms
# and attribution markers are searched.
MANIFEST_DIRS = ("prebuilt", "third_party")
MANIFEST_EXEMPT = {"SHA256SUMS", "README.md", ".gitignore", ".gitattributes"}
SUM_LINE = re.compile(r"^([0-9a-fA-F]{64}) [ *](.+?)\s*$")

# Text files worth scanning for content leaks.
TEXT_EXT = {
    ".py", ".c", ".h", ".m4", ".w32", ".sh", ".ps1", ".md", ".txt", ".yml",
    ".yaml", ".json", ".toml", ".cfg", ".ini", ".php", ".cmake", ".xml", ".cmd", ".bat", ".spec",
    ".lock", ".html", ".rst", ".in", "",
}

# Tool/cache directories, not scanned wherever they are -- but only inside a live git working tree
# (a real ".git" directory at the root), where git keeps them out of commits and archives. In any
# other tree (a copy, a staged or extracted release) they would ship, so their presence is reported.
SKIP_ANYWHERE = {".git", "__pycache__", ".pytest_cache", ".ruff_cache", ".venv"}
SKIP_PREFIX = ".venv-"   # extra virtual environments (.venv-gui, .venv-build), as git-ignored
# Local working folders of the Envelock repository itself: skipped only at its top level when
# the scanned tree IS a live git checkout of the repository and git ignores them. A tree that
# merely looks like the repository (extension/envelock.c, a shipped .gitignore) but has no live
# ".git" is a copy or a release: these folders are reported there AND scanned. An application's
# own private/ or build/ folder inside a staged release tree is always scanned.
SKIP_TOP = {"private", "release", "build", "dist", "cmake-work", "_builder"}

# Files whose CONTENT is not scanned: this guard (holds the patterns themselves) and the two
# internal files that legitimately contain the forbidden terms (scanning them would always match).
CONTENT_SKIP = {"scripts/check_release.py", "scripts/forbidden-terms.txt",
                "CONTEXTO-PROYECTO.md"}
# Internal files that must NEVER be published. Skipping only their content is not enough: their mere
# PRESENCE in a shipped tree is the leak, and because the tree also ships .gitignore, a .gitignore
# listing cannot prove the file is absent from a release. They are tolerated only inside a live git
# working tree (a real ".git" directory is present), where git actually keeps an ignored file out of
# commits and archives; in any other tree (a naive copy, an extracted release) their presence fails.
NEVER_SHIP = {"CONTEXTO-PROYECTO.md"}

# Compressed archives hide their contents from the content scan. Outside the hash-locked folders
# (prebuilt/ wheels are handled there) an archive in a release tree is refused.
ARCHIVE_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b", b"BZh", b"\xfd7zXZ",
                 b"7z\xbc\xaf\x27\x1c", b"Rar!")
ARCHIVE_EXT = {".zip", ".gz", ".tgz", ".xz", ".bz2", ".tar", ".7z", ".rar"}

# Documentation / private IP ranges allowed in examples (RFC 5737 / RFC 1918 / RFC 3849).
ALLOWED_IP = re.compile(
    r"^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|192\.168\.|10\.|127\.|0\.0\.0\.0|255\.)"
)

# Structural content patterns (do not hardcode any brand name here).
PEM = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
# Session links that attribution tools append (".../code/session_<id>", ".../chat/<uuid>").
SESSION_LINK = r"/code/session_\w|/chat/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
ATTRIB = re.compile(r"Co-Authored-By|" + SESSION_LINK + r"|\U0001F916", re.I)
# The project's own attribution page: an intentional, author-approved reference the author asked to
# ship (README/NOTICE/AUTHORS, source headers, the assistant). A "miguelenred" term match lying
# entirely inside this exact URL is allowed; any other "miguelenred..." reference is still a finding.
PROJECT_URL = re.compile(r"miguelenred\.es/envelock\b", re.I)
# Upstream projects credit human co-authors: there only session links are markers.
UPSTREAM_ATTRIB = re.compile(SESSION_LINK, re.I)
# Email: domain must end in a real alphabetic TLD (excludes Homebrew's php@8.5, openssl@3).
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b")
# A 4-octet group NOT embedded in a longer dotted chain, so OIDs and version strings
# (e.g. the code-signing OID 1.3.6.1.5.5.7.3.3) are not mistaken for an IPv4 address.
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# Real user paths only: the segment must start a path (not "word/root" like Administrador/root).
# Windows profiles with "\", escaped "\\" (any number) or "/" separators (C:\Users\x, C:\\Users\\x,
# C:/Users/x, Git Bash/WSL /c/Users/x, /mnt/c/Users/x), Linux /home/x and /root, macOS /Users/x.
# A placeholder segment (<you>, %USERNAME%, $USER) is not a real user.
USERPATH = re.compile(
    r"[A-Za-z]:(?:\\+|/)(?i:Users)(?:\\+|/)(?![%$])[^\\/\s\"'<>]+"
    r"|(?<![\w.])(?:/mnt)?/[A-Za-z]/(?i:Users)/(?![%$])[^/\s\"'<>]+"
    r"|(?<![\w.])/Users/(?![%$])[^/\s\"'<>]+"
    r"|(?<!\w)/home/(?!account\b)[^/\s\"']+|(?<!\w)/root\b"
)
# A private-key value actually present (hex 64 chars assigned to a known secret field).
SECRET_VALUE = re.compile(
    r"(?:signing_private|x25519_private|recovery_private|wrapping_key)[\"']?\s*[:=]\s*[\"']?[0-9a-fA-F]{64}"
)
# A password-encrypted private key file (owner/recipient, `save_json` with a password), whatever its
# name: the kind marker plus an actual hex ciphertext (also when embedded, JSON-escaped, in another
# file). Source code naming the kind has no hex ciphertext literal next to it.
ENCRYPTED_KIND = re.compile(r"\\*[\"']kind\\*[\"']\s*:\s*\\*[\"']envelock-encrypted\\*[\"']")
ENCRYPTED_BLOB = re.compile(r"\\*[\"']ciphertext\\*[\"']\s*:\s*\\*[\"'][0-9a-fA-F]{32,}")
# Byte-order marks of UTF-16/32 text (which holds NUL bytes, e.g. PowerShell 5.1's `>` output).
UTF_BOMS = (codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE, codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)

# Start of every Envelock-protected file (encrypted, signed; never contains private keys).
PROTECTED_STUB = b'<?php /* Envelock */ exit("Envelock loader required\\n"); __halt_compiler();\n'

ALLOWED_EMAIL = re.compile(r"@(?:example\.(?:com|org|net)|localhost)$", re.I)

# The bytecode layer (objective O1) vendors three Zend OPcache files under extension/opcache/.
# Their upstream PHP license header names its authors, and PHP 3.01 attribution requires keeping
# it. Only that block is exempt, and only for email addresses: every other pattern — Envelock
# secrets, real IPs, user paths, attribution markers — is still searched in those files, and an
# address anywhere past the header is still a finding.
UPSTREAM_HEADER_PARTS = ("extension", "opcache")
UPSTREAM_HEADER_EMAIL_LINES = 80
UPSTREAM_HEADER_MARKERS = ("| Zend OPcache ", "PHP License 3.01", "Copyright (c) The PHP Group")


def upstream_email_allowed(relp, n: int, line: str, text: str) -> bool:
    """True only for an author address inside the PHP license header of a vendored OPcache file.

    Narrow on purpose: the file must live under extension/opcache/, the address must sit on one of
    the header's own framed lines within the first lines of the file, and the file must actually
    carry the upstream attribution block. An address anywhere else is still a finding.
    """
    if relp.parts[:2] != UPSTREAM_HEADER_PARTS or n > UPSTREAM_HEADER_EMAIL_LINES:
        return False
    if not line.lstrip(" ").startswith("| ") or "@" not in line:
        return False
    head = text[:4096]
    return all(marker in head for marker in UPSTREAM_HEADER_MARKERS)


def load_terms(root: Path) -> tuple[list[str], list[str]]:
    """(forbidden terms, allowed phrases). A line starting with "!" is a phrase that contains a
    term but is not a finding in upstream files (e.g. a person's name in their credits): a term
    match lying entirely inside such a phrase is ignored there. Envelock's own files get none."""
    f = root / "scripts" / "forbidden-terms.txt"
    if not f.exists():
        return [], []
    lines = [t.strip() for t in f.read_text(encoding="utf-8").splitlines()
             if t.strip() and not t.startswith("#")]
    allowed = [t[1:].strip() for t in lines if t.startswith("!")]
    return [t for t in lines if not t.startswith("!")], [t for t in allowed if t]


def load_sums(root: Path, folder: str) -> dict[str, str]:
    """<folder>/SHA256SUMS (sha256sum format, text or *binary marker) as {repo path: sha256}.
    Paths that leave the folder are ignored, so they whitelist nothing."""
    sums = root / folder / "SHA256SUMS"
    if not sums.is_file():
        return {}
    listed = {}
    for line in sums.read_text(encoding="utf-8").splitlines():
        m = SUM_LINE.match(line)
        if not m:
            continue
        name = m.group(2).removeprefix("./")
        if name.startswith("/") or ".." in Path(name).parts:
            continue
        listed[f"{folder}/{name}"] = m.group(1).lower()
    return listed


def case_insensitive(path: Path) -> bool:
    """True when the directory holding `path` (an existing entry with letters in its name) finds
    names regardless of case, as NTFS and default APFS do. Probed on the real filesystem (a
    case-swapped name reaching the same file), never guessed from the operating system."""
    other = path.with_name(path.name.swapcase())
    if other.name == path.name:
        return False
    try:
        return other.exists() and os.path.samefile(path, other)
    except OSError:
        return False


def case_variants(listed: dict[str, str]) -> dict[str, tuple[str, ...]]:
    """{lower-cased path: the listed paths spelled that way but for case}. Upstream trees may hold
    names that differ only by case (terminfo's 2/2621A and 2/2621a, P/ and p/ folders): on a
    case-insensitive filesystem they cannot coexist, so one file on disk stands for all of them."""
    groups: dict[str, list[str]] = {}
    for name in listed:
        groups.setdefault(name.lower(), []).append(name)
    return {key: tuple(sorted(names)) for key, names in groups.items()}


def match_listed(rel: str, digest: str, listed: dict[str, str],
                 variants: dict[str, tuple[str, ...]] | None) -> tuple[str, tuple[str, ...]]:
    """("ok" | "not listed" | "differs", the listed paths the file at `rel` stands for).

    `variants` is None on a case-sensitive filesystem: the file must be listed under its exact
    path with its exact hash. On a case-insensitive one (case_variants of the listing) a listed path
    is present if it exists in any case, and the file must carry the hash of one of the listed paths
    that differ from it only by case -- an unlisted name or other content is still a finding."""
    if variants is None:
        names = (rel,) if rel in listed else ()
    else:
        names = variants.get(rel.lower(), ())
    if not names:
        return "not listed", ()
    if any(listed[n] == digest for n in names):
        return "ok", names
    return "differs", names


def upstream_text(raw: bytes) -> str:
    """Text for the term search: UTF-8/16/32 (BOM or NUL layout, as json detects it), BOM-less
    UTF-16 with any characters, else Latin-1, so no text escapes because of its encoding."""
    try:
        return raw.decode(json.detect_encoding(raw))
    except UnicodeDecodeError:
        pass
    codec = utf16_layout(raw)
    return raw.decode(codec, errors="replace") if codec else raw.decode("latin-1")


def nul_text(raw: bytes) -> bool:
    """True when data holding NUL bytes is nevertheless text: a UTF-16/32 byte-order mark, or the
    BOM-less UTF-16 layout (e.g. a config written by PowerShell 5.1's `>`)."""
    return raw.startswith(UTF_BOMS) or utf16_layout(raw) is not None


def encrypted_key_lines(text: str) -> list[int]:
    """Line numbers of an envelock-encrypted private key (marker + hex ciphertext) in `text`."""
    if "envelock-encrypted" not in text or not ENCRYPTED_BLOB.search(text):
        return []
    return [n for n, line in enumerate(text.splitlines(), 1) if ENCRYPTED_KIND.search(line)]


def utf16_layout(raw: bytes) -> str | None:
    """"utf-16-le"/"utf-16-be" when the data looks like BOM-less UTF-16 (a NUL in nearly every
    other byte of its start, as ASCII-range text has), else None."""
    head = raw[:4096]
    for offset, codec in ((1, "utf-16-le"), (0, "utf-16-be")):
        half = head[offset::2]
        if half and half.count(0) > 0.9 * len(half):
            return codec
    return None


def ascii_needle(fragment: str) -> bytes:
    """Lower-case ASCII bytes that any occurrence of `fragment` contains, for a byte-level
    prefilter: the fragment itself, or its longest ASCII run when it has other characters."""
    runs = re.findall(r"[\x00-\x7f]+", fragment.lower())
    return max(runs, key=len).encode() if runs else b""


def scan_upstream(raw: bytes, word_hit, needles: tuple[bytes, ...], fragments: tuple[str, ...]) -> list[str]:
    """Findings as ":<line>: <reason>" suffixes, to be prefixed with the file's path."""
    if raw.startswith(DATA_MAGIC):
        return []            # images, archives, libraries: never text
    if b"\x00" in raw:
        # NUL bytes: UTF-16/32 text, or data with a stray NUL; decode before searching.
        text = upstream_text(raw)
        low = text.casefold()
        if not any(f in low for f in fragments):
            return []
    else:
        # Most upstream files: byte-level substring pass first (fast), decoding only on a hit.
        low = raw.lower()
        if not any(needle in low for needle in needles):
            return []
        text = upstream_text(raw)
    found = [f":{n}: encrypted private key (envelock-encrypted)" for n in encrypted_key_lines(text)]
    for n, line in enumerate(text.splitlines(), 1):
        if SECRET_VALUE.search(line):
            found.append(f":{n}: embedded private-key value")
        if UPSTREAM_ATTRIB.search(line):
            found.append(f":{n}: AI-attribution marker")
        if word_hit(line):
            found.append(f":{n}: forbidden term")
    return found


def scan(root: Path, notes: list[str] | None = None, require_complete: bool = False) -> list[str]:
    """Findings (each one fails the check). Informational lines that are not failures (case-only
    name collisions a case-insensitive filesystem cannot hold) are appended to `notes`. With
    `require_complete`, a file listed in a SHA256SUMS but absent from the tree is a finding too."""
    if notes is None:
        notes = []
    # Fail-open guard: if the terms file is absent (e.g. a staged release or a published ZIP, where
    # it is git-ignored) the forbidden-term check cannot run. Say so loudly instead of passing
    # silently, so a green result is never mistaken for "no internal terms present".
    if not (root / "scripts" / "forbidden-terms.txt").is_file():
        print("WARNING: scripts/forbidden-terms.txt is absent -- forbidden-term checking is "
              "DISABLED for this scan (a pass does not prove no internal terms are present).",
              file=sys.stderr)
    terms, allowed = load_terms(root)
    allowed_re = re.compile("|".join(re.escape(t) for t in allowed), re.I) if allowed else None
    alternatives = "|".join(re.escape(t) for t in terms)
    # Envelock's own files: any occurrence. Upstream sources: whole words only, so an upstream
    # identifier that merely contains a term (e.g. inside "UnicodeXID") is not a finding.
    term_re = re.compile(alternatives, re.I) if terms else None
    word_re = re.compile(r"\b(?:" + alternatives + r")\b", re.I) if terms else None

    def upstream_hit(line: str) -> bool:
        """A whole-word term match not lying entirely inside an allowed phrase."""
        if word_re is None:
            return False
        spans = [m.span() for m in allowed_re.finditer(line)] if allowed_re else []
        return any(not any(a <= m.start() and m.end() <= b for a, b in spans)
                   for m in word_re.finditer(line))
    findings: list[str] = []

    is_repository = (root / "extension" / "envelock.c").is_file()
    searched: dict[str, list[str]] = {}   # sha256 -> findings of scan_upstream (without the path)
    listed = {}
    # Per hash-locked folder: None on a case-sensitive filesystem, else its case_variants.
    variants: dict[str, dict[str, tuple[str, ...]] | None] = {}
    noted: set[tuple[str, ...]] = set()
    accounted: set[str] = set()           # listed paths found on disk (in any case where it is folded)
    if is_repository:
        for folder in MANIFEST_DIRS:
            sums = load_sums(root, folder)
            listed.update(sums)
            ci = bool(sums) and case_insensitive(root / folder / "SHA256SUMS")
            variants[folder] = case_variants(sums) if ci else None
    # Fragments that any match in scan_upstream contains (prefilter), as text and as ASCII bytes.
    fragments = ("/code/session_", "/chat/", "signing_private", "x25519_private",
                 "recovery_private", "wrapping_key", "envelock-encrypted",
                 *(t.casefold() for t in terms))
    needles = tuple(n for n in (ascii_needle(f) for f in fragments) if n)
    for folder in MANIFEST_DIRS:
        if is_repository and (root / folder).is_symlink():
            findings.append(f"{folder}: symbolic link (the hash-locked folder must be real)")
    # A real git working tree keeps its ignored files out of commits and archives; a mere ".gitignore"
    # text file (which ships inside every release) does not. So an internal NEVER_SHIP file is tolerated
    # only when a real ".git" directory is present AND git ignores it.
    live_git = (root / ".git").is_dir()
    # A local working folder is skipped only if git ignores it (so it cannot be committed).
    ignored: set[str] = set()
    if (root / ".gitignore").is_file():
        ignored = {line.strip().strip("/") for line in
                   (root / ".gitignore").read_text(encoding="utf-8").splitlines()}
    for path in sorted(root.rglob("*")):
        relp = path.relative_to(root)
        # Report paths POSIX-style ("/"), never with Windows "\" (B1): the guard runs on Windows too
        # and the tests/messages expect "/". relp keeps the Path for part-wise logic below.
        rel = relp.as_posix()
        # Only names INSIDE the scanned tree count: a tree staged under release/ or private/
        # must still be scanned.
        tool = next((i for i, part in enumerate(relp.parts)
                     if part in SKIP_ANYWHERE or part.startswith(SKIP_PREFIX)), None)
        if live_git:
            # A live git working tree: git keeps these out of commits and archives.
            if tool is not None or (is_repository and relp.parts[0] in SKIP_TOP
                                    and relp.parts[0] in ignored and len(relp.parts) > 1):
                continue
        elif tool is not None:
            # Any other tree (a copy, a staged or extracted release; its .gitignore proves nothing)
            # would ship them: report the folder once instead of skipping it silently.
            if tool == len(relp.parts) - 1:
                findings.append(f"{rel}: VCS/tool/cache folder in a tree that is not a live git "
                                f"checkout (it would be published; remove it -- not scanned)")
            continue
        elif is_repository and len(relp.parts) == 1 and rel in SKIP_TOP:
            findings.append(f"{rel}: local working folder of the repository in a tree that is not a "
                            f"live git checkout (it would be published; remove it -- scanned below)")
        # In the hash-locked folders a link is refused (git on Windows turns it into a text file,
        # and a link to a folder or outside would escape the list), whatever it points to.
        if is_repository and len(relp.parts) > 1 and relp.parts[0] in MANIFEST_DIRS and path.is_symlink():
            findings.append(f"{rel}: symbolic link (not portable across systems; store a real file)")
            continue
        if not path.is_file():
            continue
        name = path.name
        # Internal files that must never ship: flag their PRESENCE (unless this is a live git tree
        # that ignores them), then skip their content below like the rest of CONTENT_SKIP.
        if rel in NEVER_SHIP and not (live_git and (rel in ignored or name in ignored)):
            findings.append(f"{rel}: internal file that must never be published is present "
                            f"(allowed only as a git-ignored file inside a live repository)")
            continue
        if rel in CONTENT_SKIP:
            continue
        try:
            with path.open("rb") as f:
                head = f.read(8)
        except OSError:
            head = b""
        if head in (b"ENVLKID2", b"ENVLKID3"):
            findings.append(f"{rel}: server identity file (private keys), whatever its name")
            continue

        managed = is_repository and len(relp.parts) > 1 and relp.parts[0] in MANIFEST_DIRS
        if managed and not (len(relp.parts) == 2 and name in MANIFEST_EXEMPT):
            sums = f"{relp.parts[0]}/SHA256SUMS"
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            status, names = match_listed(rel, digest, listed, variants.get(relp.parts[0]))
            accounted.update(names)
            if status == "not listed":
                findings.append(f"{rel}: not listed in {sums}")
            elif status == "differs":
                findings.append(f"{rel}: differs from its hash in {sums}")
            if len(names) > 1 and names not in noted:
                noted.add(names)
                notes.append(f"{' | '.join(names)}: listed in {sums} with names that differ only "
                             f"by case, which cannot coexist on this case-insensitive filesystem; "
                             f"the one present ({rel}) is checked against their hashes")
            if any(rx.match(name) for rx in ENVELOCK_SECRET_NAMES):
                findings.append(f"{rel}: forbidden file (private identity/key)")
            elif relp.parts[0] == "prebuilt":
                area = PREBUILT_AREAS.get(relp.parts[1])
                if area is not None and not area.match(name):
                    findings.append(f"{rel}: not a file this prebuilt/{relp.parts[1]}/ area holds")
                elif any(rx.match(name) for rx in SECRET_NAMES):
                    findings.append(f"{rel}: forbidden file (key, password, backup or log)")
            # Upstream content in both folders (sources, portable Python): terms and markers too.
            # The four portable Pythons share most files: each distinct content is searched once.
            if digest not in searched:
                searched[digest] = scan_upstream(raw, upstream_hit, needles, fragments)
            findings += [f"{rel}{finding}" for finding in searched[digest]]
            continue
        if any(rx.match(name) for rx in FORBIDDEN_NAMES):
            findings.append(f"{rel}: forbidden file (private identity/key/password)")
            continue
        if path.suffix.lower() in FORBIDDEN_EXT or head.startswith(BINARY_MAGIC):
            where = " (compiled files belong in prebuilt/, listed in its SHA256SUMS)" if is_repository else ""
            findings.append(f"{rel}: forbidden binary/compiled artifact{where}")
            continue
        if path.suffix.lower() in ARCHIVE_EXT or head.startswith(ARCHIVE_MAGIC):
            findings.append(f"{rel}: archive in the release tree (its contents are not scanned; "
                            f"list it under a hash-locked folder or remove it)")
            continue
        # Scan the CONTENT of every file that is not a known binary/data blob, WHATEVER its
        # extension — not only TEXT_EXT — so a secret, email, real IP or user path inside a
        # .sql/.csv/.conf/.crt/... is caught too. Known data (images, archives, PDFs, fonts) and
        # files with NUL bytes and no text extension are treated as binary and skipped.
        is_text_ext = path.suffix.lower() in TEXT_EXT
        try:
            raw = path.read_bytes()
        except OSError:
            findings.append(f"{rel}: file that cannot be read (not checked)")
            continue
        if raw.startswith(PROTECTED_STUB) or raw.startswith(DATA_MAGIC):
            continue  # Envelock container or a known binary/data format: holds no readable secret
        if not is_text_ext and b"\x00" in raw[:8192] and not nul_text(raw):
            continue  # binary blob without a known magic (no text extension): not scannable text
        # UTF-8/16/32 (BOM or NUL layout, as json detects it), BOM-less UTF-16, else Latin-1: a
        # single non-UTF-8 byte (e.g. a Latin-1 accented name inside a .sql/.csv/.conf dump) or a
        # UTF-16 config (PowerShell 5.1's `>`) must not make the whole file escape the content scan.
        text = upstream_text(raw)

        for n in encrypted_key_lines(text):
            findings.append(f"{rel}:{n}: encrypted private key (envelock-encrypted), whatever the "
                            f"file's name")
        for n, line in enumerate(text.splitlines(), 1):
            if PEM.search(line):
                findings.append(f"{rel}:{n}: PEM private key")
            if SECRET_VALUE.search(line):
                findings.append(f"{rel}:{n}: embedded private-key value")
            if ATTRIB.search(line):
                findings.append(f"{rel}:{n}: AI-attribution marker")
            if term_re is not None:
                proj_spans = [m.span() for m in PROJECT_URL.finditer(line)]
                if any(not any(a <= m.start() and m.end() <= b for a, b in proj_spans)
                       for m in term_re.finditer(line)):
                    findings.append(f"{rel}:{n}: forbidden term")
            for m in EMAIL.finditer(line):
                if not ALLOWED_EMAIL.search(m.group(0)) and not upstream_email_allowed(relp, n, line, text):
                    findings.append(f"{rel}:{n}: real email address")
            for m in IPV4.finditer(line):
                if not ALLOWED_IP.match(m.group(0)):
                    findings.append(f"{rel}:{n}: non-documentation IP address")
            if USERPATH.search(line):
                findings.append(f"{rel}:{n}: real user/home/root path")

    if require_complete:
        # A packaging step that drops files by name (Makefile, *.zip, ...) leaves the hash-locked
        # upstream trees incomplete while every file still present matches its hash.
        for name in sorted(set(listed) - accounted):
            findings.append(f"{name}: listed in {name.split('/', 1)[0]}/SHA256SUMS but missing from "
                            f"the tree (an incomplete archive)")
    return findings


# Files a usable source release MUST contain. A release ZIP once shipped WITHOUT
# third_party/php-parser, which the AST / --obfuscate-flatten / --virtualize passes require at run
# time: the toolchain broke on first use while the privacy guard still reported success. The privacy
# scan above runs on arbitrary synthetic trees in the tests, so this COMPLETENESS check is a separate,
# opt-in pass (--require-complete) that the release packaging runs on the assembled tree (ENV-2026-01).
REQUIRED_FILES = (
    "encoder/envelock.py",
    "encoder/virtualize.php",
    "third_party/php-parser/lib/PhpParser/ParserFactory.php",
)


def missing_required(root: Path) -> list[str]:
    return [f"required file missing from the release tree: {rel} (an incomplete archive)"
            for rel in REQUIRED_FILES if not (root / rel).is_file()]


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--require-complete"]
    require_complete = "--require-complete" in sys.argv[1:]
    if len(args) > 1:
        print("usage: check_release.py [--require-complete] [directory]", file=sys.stderr)
        return 2
    # A typo, a mistyped option or a .zip must not "pass" by scanning nothing.
    if args and not Path(args[0]).is_dir():
        print(f"ERROR: {args[0]} is not a directory (pass the unpacked tree to check, not an "
              f"archive or a file)", file=sys.stderr)
        return 2
    root = Path(args[0]).resolve() if args else Path(__file__).resolve().parents[1]
    notes: list[str] = []
    findings = scan(root, notes, require_complete)
    if require_complete:
        findings += missing_required(root)
    for note in notes:
        print("NOTE: " + note)
    if findings:
        print(f"RELEASE CHECK FAILED: {len(findings)} issue(s) in {root}\n")
        for f in findings:
            print("  " + f)
        print("\nRemove or redact the items above before committing or releasing.")
        return 1
    print(f"Release check passed: no private, personal or attribution material in {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

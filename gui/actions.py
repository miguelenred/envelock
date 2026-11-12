"""Non-GUI layer for the Envelock assistant: thin, testable wrappers over the encoder.

Project page: https://miguelenred.es/envelock (Apache-2.0; "Powered by Envelock" appreciated).

It performs no cryptography of its own; it orchestrates the functions in encoder/envelock.py
and turns their results into plain values. The GUI (envelock_gui.py) decides when to ask for a
password and only draws widgets. Keeping this apart lets the whole flow be tested without a
display.
"""

from __future__ import annotations

import glob
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess  # nosec B404 # only runs the user's own php CLI with a fixed argument list
import sys
import tempfile
import urllib.parse
import urllib.request
import uuid
import zipfile
from pathlib import Path

# Import the encoder as a module, from the repo layout or from a frozen bundle (PyInstaller
# unpacks data next to sys._MEIPASS).
if getattr(sys, "frozen", False):
    _BASE = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
else:
    _BASE = Path(__file__).resolve().parent.parent
_ENCODER = _BASE / "encoder" / "envelock.py"
_spec = importlib.util.spec_from_file_location("envelock_encoder", _ENCODER)
a = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(a)

IDENTITY_LIMIT = a.IDENTITY_MAX_FILE
MIN_PASSWORD = 16


_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)   # no console flash on Windows


def release_bundle_search_paths() -> None:
    """In the standalone executable, let the programs it starts (the user's PHP, PowerShell) find
    their own libraries. PyInstaller points the library search at its own unpacked runtime and
    child processes inherit that, so a PHP built with a newer Visual C++ runtime loaded the
    bundled older one and refused to start (1.0.0: "VCRUNTIME140.dll 14.29 is not compatible
    with this PHP build linked with 14.44"). Restores the system's search path, as PyInstaller's
    documentation recommends; the running assistant is not affected (it is already loaded)."""
    if not getattr(sys, "frozen", False):
        return
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.kernel32.SetDllDirectoryW(None)
    elif "LD_LIBRARY_PATH_ORIG" in os.environ:
        os.environ["LD_LIBRARY_PATH"] = os.environ["LD_LIBRARY_PATH_ORIG"]
    else:
        os.environ.pop("LD_LIBRARY_PATH", None)
_PHP_PROBE = "echo PHP_VERSION, ' ', PHP_VERSION_ID, ' ', function_exists('token_get_all') ? 1 : 0;"
# Usual places of a PHP CLI when it is not in PATH, per OS (WampServer, XAMPP, Laragon and manual
# installs on Windows; Homebrew and packages elsewhere). Newest first within each pattern. Only the
# current OS's list is searched (a POSIX path on Windows would resolve on the current drive).
# These are only LISTED for the user to choose (known_php_locations), never run automatically:
# any local user can create C:\wamp64, C:\xampp or C:\php8 on a default C:\ ACL, and the PHP the
# assistant picks receives the project's plaintext sources.
_PHP_PLACES = (
    (r"C:\wamp64\bin\php\php*\php.exe", r"C:\wamp\bin\php\php*\php.exe", r"C:\xampp\php\php.exe",
     r"C:\laragon\bin\php\*\php.exe", r"C:\php*\php.exe", r"C:\Program Files\PHP\*\php.exe")
    if sys.platform == "win32" else
    ("/opt/homebrew/bin/php", "/usr/local/bin/php", "/usr/bin/php")
)


# Official PHP for Windows: the release index lists each build with its SHA-256 (two official
# addresses of the same files; the second is tried if the first fails).
PHP_INDEX_URLS = (
    "https://windows.php.net/downloads/releases/releases.json",
    "https://www.php.net/~windows/releases/releases.json",
)
VC_REDIST_URL = "https://aka.ms/vs/17/release/vc_redist.x64.exe"   # Microsoft, Visual C++ 2015-2022
_STATUS_DLL_NOT_FOUND = (0xC0000135, -1073741515)   # exit code of php.exe without the VC++ runtime
_VC_OK = (0, 1638, 3010)        # installed / a newer one already present / installed, reboot needed


def check_php(cmd: str) -> tuple[str, str]:
    """Can cmd strip comments / obfuscate? ('ok', version) for PHP 8+ with the tokenizer; else
    (reason, detail) with reason not_found | no_vcruntime | old | no_tokenizer | error."""
    try:
        out = subprocess.run([cmd, "-r", _PHP_PROBE], capture_output=True, text=True,  # nosec B603
                             timeout=30, stdin=subprocess.DEVNULL, creationflags=_NO_WINDOW)
    except (OSError, subprocess.SubprocessError) as error:
        return "not_found", str(error)
    if out.returncode in _STATUS_DLL_NOT_FOUND:
        return "no_vcruntime", ""
    parts = out.stdout.split()
    if out.returncode != 0 or len(parts) < 3 or not parts[-2].isdigit():
        return "error", (out.stderr or out.stdout).strip()[:200]
    version = " ".join(parts[:-2])
    if int(parts[-2]) < 80000:
        return "old", version
    if parts[-1] != "1":
        return "no_tokenizer", version
    return "ok", version


def php_home() -> Path:
    """Folder next to the assistant where a downloaded PHP lives (php/<version>/php.exe)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "php"
    return Path(__file__).resolve().parent / "php"


def user_php_home() -> Path:
    """Fallback when the assistant's own folder is read-only (e.g. under Program Files)."""
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local" / "share")
    return Path(base) / "Envelock" / "php"


def is_writable(folder: Path) -> bool:
    try:
        Path(folder).mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryFile(dir=folder):
            return True
    except OSError:
        return False


def _downloaded_phps() -> list[str]:
    """php.exe files previously downloaded by the assistant, newest version first."""
    found = []
    for home in (php_home(), user_php_home()):
        for exe in home.glob("*/php.exe"):
            if re.fullmatch(r"\d+\.\d+\.\d+", exe.parent.name):
                found.append((tuple(int(n) for n in exe.parent.name.split(".")), str(exe)))
    return [path for _, path in sorted(found, reverse=True)]


def _php_on_path() -> str | None:
    """The first PHP CLI in the PATH entries themselves. Not shutil.which: on Windows it searches
    the current directory first, which is not part of PATH and may be any folder."""
    names = ("php.exe",) if sys.platform == "win32" else ("php",)
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        entry = entry.strip().strip('"')
        if not entry or not os.path.isabs(entry):
            continue
        for name in names:
            candidate = os.path.join(entry, name)
            if os.path.isfile(candidate) and (sys.platform == "win32" or os.access(candidate, os.X_OK)):
                return candidate
    return None


def known_php_locations() -> list[str]:
    """PHP CLIs in the usual install folders (WampServer, XAMPP, Laragon, C:\\php...), newest first
    within each pattern. Only listed, never run: the user chooses one explicitly (Browse)."""
    found: list[str] = []
    for pattern in _PHP_PLACES:
        for path in sorted(glob.glob(pattern), reverse=True):
            if path not in found and os.path.isfile(path):
                found.append(path)
    return found


def find_php() -> str | None:
    """A usable PHP 8 CLI with the tokenizer that may be run without asking: one downloaded by
    the assistant (its own folder or the user's), else the one in PATH. PHPs in other folders
    are only listed (known_php_locations) for the user to choose."""
    candidates = _downloaded_phps() + [_php_on_path()]
    seen = set()
    for candidate in candidates:
        if candidate and candidate not in seen:
            seen.add(candidate)
            if check_php(candidate)[0] == "ok":
                return candidate
    return None


def _allowed_url(address: str) -> bool:
    """HTTPS, or plain HTTP to this machine only (the tests' local mirror)."""
    parsed = urllib.parse.urlparse(address)
    return parsed.scheme == "https" or (
        parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost"))


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only to an allowed URL. Checking the final URL alone let a chain
    https -> http -> https pass, with the middle hop readable and alterable on the network."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _allowed_url(newurl):
            # urllib.request re-exports urllib.error's HTTPError (an OSError: download_php reports it).
            raise urllib.request.HTTPError(newurl, code, f"Refusing a redirect away from HTTPS: {newurl}",
                                           headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch(url: str, limit: int) -> bytes:
    """Download url (HTTPS only; plain HTTP is accepted only from this machine, for tests),
    refusing any redirect hop away from HTTPS and anything larger than limit bytes."""
    if not _allowed_url(url):
        raise ValueError(f"Refusing a non-HTTPS download: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "Envelock-assistant"})
    opener = urllib.request.build_opener(_HttpsOnlyRedirects)
    with opener.open(request, timeout=120) as response:  # nosec B310 # scheme checked on every hop
        if not _allowed_url(response.geturl()):
            raise ValueError(f"Refusing a redirect away from HTTPS: {response.geturl()}")
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"Download larger than expected: {url}")
    return data


def latest_php_release(index: dict) -> tuple[str, str, str]:
    """(version, zip name, sha256) of the newest PHP 8 non-thread-safe x64 build listed in the
    official releases.json."""
    best = None
    for key, entry in index.items():
        if not re.fullmatch(r"8\.\d+", str(key)) or not isinstance(entry, dict):
            continue
        build = entry.get("nts-vs17-x64") or entry.get("nts-vs16-x64")
        archive = build.get("zip") if isinstance(build, dict) else None
        if isinstance(archive, dict) and (best is None or int(key.split(".")[1]) > best[0]):
            best = (int(key.split(".")[1]), str(entry.get("version", "")),
                    str(archive.get("path", "")), str(archive.get("sha256", "")).lower())
    if best is None:
        raise ValueError("No PHP 8 Windows x64 build in the release index")
    _, version, name, sha = best
    if (not re.fullmatch(r"8\.\d+\.\d+", version) or not re.fullmatch(r"[0-9a-f]{64}", sha)
            or not re.fullmatch(r"[A-Za-z0-9._-]+\.zip", name)):
        raise ValueError("Unexpected entry in the release index")
    return version, name, sha


_EXTRACT_LIMIT = 1024 * 1024 * 1024   # max uncompressed bytes _extract_zip will write (zip-bomb guard)


def _extract_zip(data: bytes, target: Path) -> None:
    """Extract a zip into target, refusing absolute paths, drive letters and '..' components;
    built in a temporary sibling and renamed, so a failure leaves nothing half-extracted."""
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=".php-", dir=target.parent))
    # Bound the UNCOMPRESSED total before extracting: _fetch caps the download at a few hundred MiB,
    # but a zip bomb packs far more than that into those bytes, and extractall() would fill the disk
    # (ENV-2026-27). An official PHP/VC distribution is well under this cap.
    extract_limit = _EXTRACT_LIMIT
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            total = 0
            for member in archive.infolist():
                name = member.filename.replace("\\", "/")
                parts = name.split("/")
                if name.startswith("/") or ".." in parts or ":" in parts[0]:
                    raise ValueError(f"Unsafe path in the archive: {member.filename}")
                total += member.file_size
                if total > extract_limit:
                    raise ValueError("The archive expands to more than 1 GiB; refusing to extract it")
            archive.extractall(tmp)  # nosec B202 # every member path and the total size were checked above
        tmp.rename(target)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def download_php(dest: Path, index_urls=PHP_INDEX_URLS) -> Path:
    """Windows: download the newest official PHP 8 (NTS x64) over HTTPS, check it against the
    SHA-256 listed in the same official index and extract it to dest/<version>/. Returns the path
    of php.exe. The hash comes from the same origin as the file: it proves the download is complete
    and unaltered since the index was served, not a separate signature (authenticity rests on
    HTTPS to php.net)."""
    errors = []
    for index_url in index_urls:
        try:
            version, name, sha = latest_php_release(json.loads(_fetch(index_url, 4 * 1024 * 1024)))
            exe = Path(dest) / version / "php.exe"
            if exe.exists():
                return exe
            data = _fetch(index_url.rsplit("/", 1)[0] + "/" + name, 256 * 1024 * 1024)
            if hashlib.sha256(data).hexdigest() != sha:
                raise ValueError(f"{name}: SHA-256 does not match the official index")
            _extract_zip(data, exe.parent)
            if not exe.exists():
                raise ValueError(f"{name} contains no php.exe")
            return exe
        except (OSError, ValueError, KeyError) as error:          # try the other address
            errors.append(f"{index_url}: {error}")
    raise ValueError("Could not download PHP.\n" + "\n".join(errors))


def _powershell_path() -> str:
    """Absolute path to Windows PowerShell, never the bare name 'powershell' resolved through PATH: a
    writable directory earlier in PATH could otherwise shadow it with a trojan (ENV-2026-27)."""
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


def _powershell(script: str, path: Path) -> subprocess.CompletedProcess:
    """Run a fixed PowerShell script on Windows; the file path goes through an environment
    variable, never into the command text."""
    return subprocess.run(  # nosec B603 B607 # fixed script, Windows' own PowerShell at an absolute path
        [_powershell_path(), "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=1800, stdin=subprocess.DEVNULL,
        creationflags=_NO_WINDOW, env=dict(os.environ, ENVELOCK_FILE=str(path)))


def install_vc_redist(work: Path, url: str = VC_REDIST_URL) -> int:
    """Windows: download Microsoft's Visual C++ Redistributable, run it only if it carries a valid
    Microsoft Authenticode signature, and install it (Windows asks for administrator permission).
    Returns the installer's exit code (0, 1638 or 3010 mean it is in place)."""
    installer = Path(work) / "vc_redist.x64.exe"
    installer.write_bytes(_fetch(url, 128 * 1024 * 1024))
    try:
        # Verify the Authenticode signature AND launch the installer in ONE PowerShell process, so
        # no other process of the same user can swap the file in %TEMP% between the check and the
        # elevated run (ENV-AUD-16 TOCTOU). The signer must chain to a valid Microsoft signature,
        # carry the Code Signing EKU, and have organization EXACTLY "Microsoft Corporation" matched
        # as a whole RDN (anchored), so a crafted subject like "O=Microsoft Corporation Evil" fails.
        run = _powershell(
            "$ErrorActionPreference='Stop';"
            "$f=$env:ENVELOCK_FILE;"
            # Hold the file open with share mode 'Read' (others may READ, but NOT write or delete) for
            # the WHOLE verify-then-elevate window, so no other process of this user can swap or
            # overwrite the file in %TEMP% between the signature check and the elevated run while the UAC
            # dialog waits (ENV-2026-27 TOCTOU). Read sharing still lets Start-Process open and execute
            # the very bytes that were verified; write/delete sharing is denied.
            "$lock=[System.IO.File]::Open($f,[System.IO.FileMode]::Open,"
            "[System.IO.FileAccess]::Read,[System.IO.FileShare]::Read);"
            "try {"
            "  $s=Get-AuthenticodeSignature -LiteralPath $f;"
            "  $c=$s.SignerCertificate;"
            "  $subjectOk=$c -and ($c.Subject -match '(?:^|,\\s*)O=Microsoft Corporation(?:,\\s|$)');"
            "  $ekuOk=$c -and ($c.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.3' });"
            "  $rootOk=$false;"
            "  if ($c) {"
            "    $chain=New-Object System.Security.Cryptography.X509Certificates.X509Chain;"
            # Online revocation, and the chain-build RESULT is checked, not discarded (ENV-2026-27).
            "    $chain.ChainPolicy.RevocationMode='Online';"
            "    $chain.ChainPolicy.RevocationFlag='EntireChain';"
            "    $built=$chain.Build($c);"
            "    $root=$chain.ChainElements[$chain.ChainElements.Count-1].Certificate;"
            "    $rootOk=$built -and ($root.Subject -match '(?:^|,\\s*)O=Microsoft Corporation(?:,\\s|$)')"
            "      -and ($root.Subject -match 'Microsoft Root')"
            "  }"
            "  if ($s.Status -ne 'Valid' -or -not $subjectOk -or -not $ekuOk -or -not $rootOk) { exit 2001 }"
            "  $p=Start-Process -FilePath $f -ArgumentList '/install','/passive','/norestart' "
            "  -Verb RunAs -Wait -PassThru; exit $p.ExitCode"
            "} finally { $lock.Close() }",
            installer)
        if run.returncode == 2001:
            raise ValueError("The downloaded installer is not validly signed by Microsoft; it was not run")
        return run.returncode
    finally:
        installer.unlink(missing_ok=True)


def vc_redist_installed(code: int) -> bool:
    return code in _VC_OK


def php_install_hint(os_release: str | None = None) -> str:
    """Linux/macOS: the command that installs a PHP 8 CLI with the tokenizer."""
    if sys.platform == "darwin":
        return "brew install php"
    if os_release is None:
        try:
            os_release = Path("/etc/os-release").read_text()
        except OSError:
            os_release = ""
    ids = " ".join(re.findall(r'^(?:ID|ID_LIKE)="?([^"\n]*)"?', os_release, re.M)).split()
    for names, command in ((("debian", "ubuntu"), "sudo apt install php-cli"),
                           (("fedora", "rhel", "centos"), "sudo dnf install php-cli"),
                           (("arch",), "sudo pacman -S php")):
        if any(name in ids for name in names):
            return command
    return "your package manager's PHP 8 CLI package (with the tokenizer extension)"


def is_encrypted(path: Path) -> bool:
    """True if path is an Envelock encrypted private configuration (needs a password)."""
    try:
        obj = json.loads(a.bounded_read(Path(path), 64 * 1024))
    except (ValueError, OSError):
        return False
    return isinstance(obj, dict) and obj.get("kind") == "envelock-encrypted"


def _password(value: bytes | None, encrypt: bool) -> bytes | None:
    """Validate a password for writing: None means 'store unencrypted'."""
    if not encrypt:
        return None
    # Count characters, not UTF-8 bytes, so the limit matches the message (ENV-18): otherwise a
    # few non-ASCII characters (each several bytes) would pass as if they were 16.
    if value is None or len(value.decode("utf-8", "replace")) < MIN_PASSWORD:
        raise ValueError(f"The password must have at least {MIN_PASSWORD} characters")
    return value


KIND_NAME = {
    "envelock-owner": "a signing key (owner)",
    "envelock-recipient": "a server key (recipient)",
    "envelock-recipient-public": "a public key (.pub.json)",
    "envelock-developer-public": "a developer descriptor",
}


def file_kind(path: Path) -> str | None:
    """The 'kind' declared in a config file, or None if it is not a readable Envelock JSON.
    An encrypted file reports 'envelock-encrypted' (its real kind is hidden until decrypted)."""
    try:
        obj = json.loads(a.bounded_read(Path(path), 64 * 1024))
    except (ValueError, OSError):
        return None
    return obj.get("kind") if isinstance(obj, dict) else None


def _read_config(path: Path, kind: str, password: bytes | None):
    """Read a private configuration, never falling back to a terminal prompt (a windowed app
    has no console): an encrypted file without a password is a clear error, not a crash. A wrong
    file kind (e.g. an owner where a recipient is expected) is reported in plain words."""
    if is_encrypted(path) and password is None:
        raise ValueError(f"{Path(path).name} is encrypted: a password is required")
    try:
        return a.read_config(Path(path), kind, password)
    except ValueError as error:
        if "Incorrect config kind" in str(error):
            raise ValueError(f"{Path(path).name} is not {KIND_NAME.get(kind, kind)}") from error
        raise


def recipient_public_descriptor(path: Path, password: bytes | None = None) -> dict:
    """A public recipient descriptor from either an exported public key (.pub.json) or a private
    recipient file (in which case its public part is derived; a password is needed if encrypted)."""
    obj = json.loads(a.bounded_read(Path(path), 64 * 1024))
    if isinstance(obj, dict) and obj.get("kind") == "envelock-recipient-public":
        return a.validate_config(obj, "envelock-recipient-public")
    return a.recipient_public(_read_config(path, "envelock-recipient", password))


# --- keys -----------------------------------------------------------------------------------

def create_owner(out: Path, with_recovery: bool, password: bytes | None, encrypt: bool = True) -> None:
    a.save_json(Path(out), a.make_owner(with_recovery=with_recovery), _password(password, encrypt))


def create_recipient(out: Path, label: str, password: bytes | None, encrypt: bool = True) -> None:
    if not label.strip():
        raise ValueError("The recipient needs a label")
    a.save_json(Path(out), a.make_recipient(label.strip()), _password(password, encrypt))


def export_public(recipient: Path, recipient_password: bytes | None, out: Path) -> None:
    config = _read_config(Path(recipient), "envelock-recipient", recipient_password)
    a.save_json(Path(out), a.recipient_public(config))


def export_developer(owner: Path, owner_password: bytes | None, out: Path) -> None:
    config = _read_config(Path(owner), "envelock-owner", owner_password)
    a.save_json(Path(out), a.developer_public(config))


def new_project() -> str:
    return str(uuid.uuid4())


# --- server identity (trust store) ----------------------------------------------------------

def _read_store(identity: Path) -> bytes | None:
    path = Path(identity)
    return a.bounded_read(path, IDENTITY_LIMIT) if path.exists() else None


def identity_add_recipient(identity: Path, recipient: Path, recipient_password: bytes | None,
                           owner: Path, owner_password: bytes | None) -> None:
    data = a.add_recipient_to_store(
        _read_store(identity),
        _read_config(Path(recipient), "envelock-recipient", recipient_password),
        _read_config(Path(owner), "envelock-owner", owner_password),
    )
    a.write_store(Path(identity), data)


def identity_remove_recipient(identity: Path, recipient: Path) -> None:
    data = a.remove_recipient(_require_store(identity),
                              recipient_public_descriptor(recipient)["x25519_public"])
    a.write_store(Path(identity), data)


def identity_set_developer(identity: Path, developer: Path, remove_recovery: bool = False) -> None:
    data = a.set_developer(_require_store(identity),
                           a.read_config(Path(developer), "envelock-developer-public"),
                           remove_recovery)
    a.write_store(Path(identity), data)


def identity_remove_developer(identity: Path, developer_id: str) -> None:
    data = a.remove_developer(_require_store(identity), developer_id.strip())
    a.write_store(Path(identity), data)


def identity_set_minimum(identity: Path, package: Path | None = None,
                         project: str | None = None, serial: int | None = None,
                         allow_downgrade: bool = False) -> tuple[str, int]:
    store = _require_store(identity)
    developer_pub = a.ZERO32   # admin-set minimum: unbound (applies to any developer)
    if package is not None:
        # ENV-09: take project/serial from the SIGNED header verified against the identity's
        # trusted developers, not from the unsigned envelock-package.json.
        header, signer = a.verified_header_and_signer(
            a.first_protected_file(Path(package)), a.identity_signers(store))
        project, serial = str(uuid.UUID(bytes=header["project"])), header["serial"]
        # ENV-AUD-14: bind the minimum to the developer that signed the package.
        developer_pub = a.developer_primary_for_signer(store, signer)
    elif project is None or serial is None:
        raise ValueError("Give a package folder, or a project and a serial")
    data = a.set_minimum(store, project, int(serial), developer_pub, allow_downgrade=allow_downgrade)
    a.write_store(Path(identity), data)
    return project, int(serial)


def describe_identity(identity: Path) -> dict:
    return a.inspect_path(Path(identity))


def _require_store(identity: Path) -> bytes:
    data = _read_store(identity)
    if data is None:
        raise ValueError("The identity file does not exist yet")
    return data


# --- key rotation -----------------------------------------------------------------------------

def rotate_new_recovery(owner: Path, password: bytes | None, encrypt: bool = True) -> None:
    owner = Path(owner)
    config, stored = a.read_config_with_password(owner, "envelock-owner", password)
    use = stored if stored is not None else _password(password, encrypt)
    import secrets
    tmp = owner.parent / (owner.name + ".tmp-" + secrets.token_hex(4))
    try:
        a.save_json(tmp, a.new_recovery(config), use, like=owner)  # atomic in-place replace
        a.replace_file(tmp, owner)
    finally:
        if tmp.exists():
            tmp.unlink()


def rotate_promote_recovery(owner: Path, owner_password: bytes | None,
                            out: Path, out_password: bytes | None, encrypt: bool = True) -> None:
    config = _read_config(Path(owner), "envelock-owner", owner_password)
    a.save_json(Path(out), a.promote_recovery(config), _password(out_password, encrypt))


# --- inspect ----------------------------------------------------------------------------------

def inspect(path: Path) -> dict:
    return a.inspect_path(Path(path))


# --- pack -------------------------------------------------------------------------------------

def pack(owner: Path, owner_password: bytes | None, recipients: list[Path], project: str,
         source: Path, output: Path, *, recipient_passwords: list | None = None,
         assets: list[str] | None = None, exclude: list[str] | None = None,
         php_ext: list[str] | None = None, strip_comments: bool = False, obfuscate: bool = False,
         include_protection: bool = False, no_prepend: bool = False,
         serial: int | None = None, php: str = "php", compact: bool = False,
         encode_strings: bool = False, obfuscate_methods: bool = False,
         obfuscate_properties: bool = False, no_ffi: bool = False,
         sealed: bool = False, enforce_manifest: bool = False,
         obfuscate_flow: bool = False, vault_strings: bool = False,
         allow_secret_assets: bool = False) -> dict:
    owner_config = _read_config(Path(owner), "envelock-owner", owner_password)
    # Explicit length check: zip() would otherwise truncate silently to the shorter list, packing
    # for fewer recipients than asked with no error (audit ENV-02).
    if recipient_passwords is not None and len(recipient_passwords) != len(recipients):
        raise ValueError(
            f"Give one password per recipient (got {len(recipient_passwords)} for "
            f"{len(recipients)} recipients), or none at all.")
    pws = recipient_passwords or [None] * len(recipients)
    recipient_configs = [recipient_public_descriptor(r, pw) for r, pw in zip(recipients, pws)]
    extensions = a.DEFAULT_EXTENSIONS | {"." + x.lower().lstrip(".") for x in (php_ext or [])}
    return a.pack_tree(
        Path(source), Path(output), recipient_configs, owner_config, project,
        extensions, assets or [], exclude or [], php,
        strip_comments=strip_comments, obfuscate=obfuscate,
        include_protection=include_protection, no_prepend=no_prepend, serial=serial,
        compact=compact, encode_strings=encode_strings, obfuscate_methods=obfuscate_methods,
        obfuscate_properties=obfuscate_properties, no_ffi=no_ffi, sealed=sealed,
        enforce_manifest=enforce_manifest, obfuscate_flow=obfuscate_flow,
        vault_strings=vault_strings, allow_secret_assets=allow_secret_assets,
    )


def recommend(source: Path, php_ext: list[str] | None = None) -> dict:
    """Analyse a project tree and return the recommended protection: the strongest options that
    measurement shows are safe for it, with what to turn off and why, plus a human-readable report.
    Thin wrapper over the encoder's recommend_options/format_recommendation (no cryptography here)."""
    source = Path(source)
    if not source.is_dir():
        raise ValueError("Choose the project's source folder to analyse.")
    extensions = a.DEFAULT_EXTENSIONS | {"." + x.lower().lstrip(".") for x in (php_ext or [])}
    rec = a.recommend_options(source, extensions)
    return {"recommendation": rec, "report": a.format_recommendation(rec)}

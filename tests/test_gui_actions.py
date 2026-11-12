"""The assistant's non-GUI layer drives the encoder end to end without a display."""

import hashlib
import http.server
import importlib.util
import io
import json
import os
import shutil
import subprocess as _subprocess
import sys
import threading
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("envelock_gui_actions", ROOT / "gui" / "actions.py")
actions = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(actions)

PASSWORD = b"a-long-enough-password"
PHP = shutil.which("php")


def _has_tokenizer():
    if not PHP:
        return False
    import subprocess
    out = subprocess.run([PHP, "-r", 'echo function_exists("token_get_all") && PHP_VERSION_ID >= 80000 ? "1":"0";'],
                         capture_output=True, text=True)
    return out.stdout == "1"


def test_encrypted_keys_roundtrip_and_detection(tmp_path):
    owner, rcpt = tmp_path / "owner.enc.json", tmp_path / "rcpt.enc.json"
    actions.create_owner(owner, with_recovery=True, password=PASSWORD)
    actions.create_recipient(rcpt, "client-1", password=PASSWORD)
    assert actions.is_encrypted(owner) and actions.is_encrypted(rcpt)
    pub = tmp_path / "rcpt.pub.json"
    actions.export_public(rcpt, PASSWORD, pub)
    assert not actions.is_encrypted(pub)
    assert json.loads(pub.read_text())["kind"] == "envelock-recipient-public"
    with pytest.raises(Exception):
        actions.export_public(rcpt, b"wrong-password-xxx", tmp_path / "x.json")


def test_short_password_refused(tmp_path):
    with pytest.raises(ValueError, match="at least"):
        actions.create_owner(tmp_path / "o.json", with_recovery=False, password=b"short")


def test_unencrypted_when_not_asked(tmp_path):
    owner = tmp_path / "owner.json"
    actions.create_owner(owner, with_recovery=False, password=None, encrypt=False)
    assert not actions.is_encrypted(owner)


def test_identity_build_minimum_and_inspect(tmp_path):
    owner, rcpt = tmp_path / "owner.enc.json", tmp_path / "rcpt.enc.json"
    actions.create_owner(owner, True, PASSWORD)
    actions.create_recipient(rcpt, "srv", PASSWORD)
    identity = tmp_path / "identity.bin"
    actions.identity_add_recipient(identity, rcpt, PASSWORD, owner, PASSWORD)
    assert identity.exists()
    meta = actions.describe_identity(identity)
    assert meta["kind"] == "envelock-identity-store" and len(meta["recipients"]) == 1
    project = actions.new_project()
    actions.identity_set_minimum(identity, project=project, serial=42)
    mins = actions.describe_identity(identity)["minimum_serials"]
    assert next(m for m in mins if m["project"] == project)["serial"] == 42


def test_identity_remove_recipient_and_developer_without_prompt(tmp_path, monkeypatch):
    """Removal takes the server's public key; an encrypted private recipient is a clear error,
    never a terminal prompt (a windowed app has no console)."""
    o1, o2, r1, r2 = (tmp_path / n for n in ("o1.enc.json", "o2.enc.json", "r1.enc.json", "r2.enc.json"))
    pub = tmp_path / "r1.pub.json"
    for owner in (o1, o2):
        actions.create_owner(owner, False, PASSWORD)
    for rcpt in (r1, r2):
        actions.create_recipient(rcpt, rcpt.stem, PASSWORD)
    actions.export_public(r1, PASSWORD, pub)
    identity = tmp_path / "identity.bin"
    actions.identity_add_recipient(identity, r1, PASSWORD, o1, PASSWORD)
    actions.identity_add_recipient(identity, r2, PASSWORD, o2, PASSWORD)
    monkeypatch.delenv("ENVELOCK_PASSWORD_FILE", raising=False)
    monkeypatch.setattr(sys, "stdin", None)      # as in the windowed executable: no console
    with pytest.raises(ValueError, match="password is required"):
        actions.identity_remove_recipient(identity, r1)
    actions.identity_remove_recipient(identity, pub)
    meta = actions.describe_identity(identity)
    assert len(meta["recipients"]) == 1 and len(meta["developers"]) == 2
    actions.identity_remove_developer(identity, meta["developers"][0]["developer_id"])
    assert len(actions.describe_identity(identity)["developers"]) == 1


def test_identity_set_minimum_from_package(tmp_path):
    owner, rcpt, pub = tmp_path / "o.enc.json", tmp_path / "r.enc.json", tmp_path / "r.pub.json"
    actions.create_owner(owner, False, PASSWORD)
    actions.create_recipient(rcpt, "srv", PASSWORD)
    actions.export_public(rcpt, PASSWORD, pub)
    identity = tmp_path / "id.bin"
    actions.identity_add_recipient(identity, rcpt, PASSWORD, owner, PASSWORD)
    src = tmp_path / "src"
    src.mkdir()
    (src / "i.php").write_text("<?php echo 1;")
    project = actions.new_project()
    actions.pack(owner, PASSWORD, [pub], project, src, tmp_path / "out", serial=55)
    got_project, got_serial = actions.identity_set_minimum(identity, package=tmp_path / "out")
    assert got_project == project and got_serial == 55
    mins = actions.describe_identity(identity)["minimum_serials"]
    assert next(m for m in mins if m["project"] == project)["serial"] == 55


def test_rotation_new_and_promote_recovery(tmp_path):
    owner = tmp_path / "owner.enc.json"
    actions.create_owner(owner, with_recovery=True, password=PASSWORD)
    def read(path):
        return actions.a.read_config(path, "envelock-owner", PASSWORD)
    first = read(owner)
    actions.rotate_new_recovery(owner, PASSWORD)          # in place, same password
    assert actions.is_encrypted(owner)                    # still encrypted, nothing in the clear
    rotated = read(owner)
    assert rotated["signing_public"] == first["signing_public"]          # primary unchanged
    assert rotated["recovery_public"] != first["recovery_public"]        # recovery replaced
    promoted = tmp_path / "owner-2.enc.json"
    actions.rotate_promote_recovery(owner, PASSWORD, promoted, PASSWORD)
    assert read(promoted)["signing_public"] == rotated["recovery_public"]  # recovery is now primary


def test_promote_recovery_encrypts_new_owner_even_from_a_plaintext_source(tmp_path):
    """ENV-AUD-16: the new owner file holds fresh private signing keys. When a password is given
    (the GUI now always offers one), the output is encrypted even if the source was plaintext;
    without a password it is plaintext (the GUI requires an explicit confirmation for that)."""
    source = tmp_path / "owner.json"
    actions.create_owner(source, with_recovery=True, password=None, encrypt=False)   # unencrypted source
    assert not actions.is_encrypted(source)
    enc = tmp_path / "owner-new.enc.json"
    actions.rotate_promote_recovery(source, None, enc, PASSWORD, encrypt=True)
    assert actions.is_encrypted(enc)                                  # fresh keys protected
    clear = tmp_path / "owner-new.json"
    actions.rotate_promote_recovery(source, None, clear, None, encrypt=False)
    assert not actions.is_encrypted(clear)                            # plaintext only when asked


def test_pack_runs_and_is_addressed(tmp_path):
    owner, rcpt, pub = tmp_path / "o.enc.json", tmp_path / "r.enc.json", tmp_path / "r.pub.json"
    actions.create_owner(owner, False, PASSWORD)
    actions.create_recipient(rcpt, "srv", PASSWORD)
    actions.export_public(rcpt, PASSWORD, pub)
    src = tmp_path / "app"
    (src / "lib").mkdir(parents=True)
    (src / "index.php").write_text("<?php require __DIR__.'/lib/x.php'; echo v();")
    (src / "lib" / "x.php").write_text("<?php function v(){ return 7; }")
    (src / "logo.png").write_bytes(b"\x89PNG demo")
    out = tmp_path / "out"
    info = actions.pack(owner, PASSWORD, [pub], actions.new_project(), src, out,
                        assets=["*.png"], include_protection=True, no_prepend=True)
    assert info["protected_files"] == 2 and info["copied_assets"] == 1
    assert info["include_protection"] and info["no_prepend"]
    assert (out / "logo.png").read_bytes() == b"\x89PNG demo"      # asset copied verbatim
    identity = actions.a.make_identity(
        actions.a.read_config(rcpt, "envelock-recipient", PASSWORD),
        actions.a.read_config(owner, "envelock-owner", PASSWORD))
    plain = actions.a.open_protected((out / "index.php").read_bytes(), identity)
    assert b"require" in plain


def test_pack_rejects_mismatched_recipient_passwords(tmp_path):
    """zip(recipients, passwords) would truncate to the shorter list, silently packing for fewer
    recipients than asked (audit ENV-02). pack must refuse a length mismatch outright."""
    owner = tmp_path / "o.enc.json"
    r1, p1 = tmp_path / "r1.enc.json", tmp_path / "r1.pub.json"
    r2, p2 = tmp_path / "r2.enc.json", tmp_path / "r2.pub.json"
    actions.create_owner(owner, False, PASSWORD)
    for r, p, label in ((r1, p1, "a"), (r2, p2, "b")):
        actions.create_recipient(r, label, PASSWORD)
        actions.export_public(r, PASSWORD, p)
    src = tmp_path / "app"
    src.mkdir()
    (src / "index.php").write_text("<?php echo 1;")
    with pytest.raises(ValueError, match="one password per recipient"):
        actions.pack(owner, PASSWORD, [p1, p2], actions.new_project(), src, tmp_path / "out",
                     recipient_passwords=[None])              # 1 password for 2 recipients


@pytest.mark.skipif(not _has_tokenizer(), reason="php CLI with tokenizer required")
def test_pack_with_transform_options(tmp_path):
    owner, pub = tmp_path / "o.enc.json", tmp_path / "r.pub.json"
    rcpt = tmp_path / "r.enc.json"
    actions.create_owner(owner, False, PASSWORD)
    actions.create_recipient(rcpt, "srv", PASSWORD)
    actions.export_public(rcpt, PASSWORD, pub)
    src = tmp_path / "app"
    src.mkdir()
    (src / "a.php").write_text("<?php\n/** doc */\nfunction f(){ $longName = 1; return $longName; }\n")
    out = tmp_path / "out"
    info = actions.pack(owner, PASSWORD, [pub], actions.new_project(), src, out,
                        strip_comments=True, obfuscate=True, compact=True, encode_strings=True, obfuscate_methods=True, obfuscate_properties=True, php=PHP)
    assert info["comments_stripped"] and info["obfuscated"] and info["compacted"] and info["strings_encoded"] and info["private_methods_obfuscated"] and info["private_properties_obfuscated"]
    identity = actions.a.make_identity(
        actions.a.read_config(rcpt, "envelock-recipient", PASSWORD),
        actions.a.read_config(owner, "envelock-owner", PASSWORD))
    plain = actions.a.open_protected((out / "a.php").read_bytes(), identity)
    assert b"doc" not in plain and b"$longName" not in plain


def test_pack_accepts_public_or_encrypted_recipient(tmp_path):
    owner, rcpt, pub = tmp_path / "o.enc.json", tmp_path / "r.enc.json", tmp_path / "r.pub.json"
    actions.create_owner(owner, False, PASSWORD)
    actions.create_recipient(rcpt, "srv", PASSWORD)
    actions.export_public(rcpt, PASSWORD, pub)
    src = tmp_path / "app"
    src.mkdir()
    (src / "i.php").write_text("<?php echo 1;")
    project = actions.new_project()
    # public key: no password needed
    info = actions.pack(owner, PASSWORD, [pub], project, src, tmp_path / "o1")
    assert info["protected_files"] == 1
    # the encrypted private recipient, by mistake, works when its password is given
    info = actions.pack(owner, PASSWORD, [rcpt], project, src, tmp_path / "o2",
                        recipient_passwords=[PASSWORD])
    assert info["protected_files"] == 1
    # without the password it is a clear error, never a terminal prompt / isatty crash
    with pytest.raises(ValueError, match="encrypted"):
        actions.pack(owner, PASSWORD, [rcpt], project, src, tmp_path / "o3")


def test_file_kind_and_friendly_wrong_kind(tmp_path):
    owner, rcpt, pub = tmp_path / "o.enc.json", tmp_path / "r.enc.json", tmp_path / "r.pub.json"
    actions.create_owner(owner, False, PASSWORD)
    actions.create_recipient(rcpt, "srv", PASSWORD)
    actions.export_public(rcpt, PASSWORD, pub)
    assert actions.file_kind(owner) == "envelock-encrypted"      # encrypted hides the real kind
    assert actions.file_kind(pub) == "envelock-recipient-public"
    assert actions.file_kind(tmp_path / "nope.json") is None
    # passing the owner where a recipient is expected gives a plain-words error, not a raw one
    with pytest.raises(ValueError, match="is not a server key"):
        actions._read_config(owner, "envelock-recipient", PASSWORD)


def _fake_php(tmp_path, name, output, code=0):
    script = tmp_path / name
    script.write_text(f"#!/bin/sh\nprintf '%s' '{output}'\nexit {code}\n")
    script.chmod(0o755)
    return str(script)


def test_check_php_reports_why_it_cannot_be_used(tmp_path):
    assert actions.check_php(str(tmp_path / "no-such-php"))[0] == "not_found"
    if os.name == "nt":
        return                                   # the fake interpreters below are shell scripts
    assert actions.check_php(_fake_php(tmp_path, "old", "7.4.33 70433 1")) == ("old", "7.4.33")
    assert actions.check_php(_fake_php(tmp_path, "notok", "8.3.0 80300 0")) == ("no_tokenizer", "8.3.0")
    assert actions.check_php(_fake_php(tmp_path, "good", "8.3.0 80300 1")) == ("ok", "8.3.0")
    assert actions.check_php(_fake_php(tmp_path, "junk", "Parse error", 255))[0] == "error"


def test_find_php_returns_a_usable_php_or_none():
    found = actions.find_php()
    assert found is None or actions.check_php(found)[0] == "ok"
    if PHP and _has_tokenizer():
        assert found is not None                 # this machine has one in PATH


def test_php_search_places_belong_to_the_current_os():
    """A POSIX path searched on Windows resolves on the current drive (and vice versa)."""
    places = actions._PHP_PLACES
    if sys.platform == "win32":
        assert places and all(p.startswith("C:") for p in places)
    else:
        assert places and all(p.startswith("/") for p in places)


def _php_name():
    return "php.exe" if sys.platform == "win32" else "php"


def _plant_php(folder):
    folder.mkdir(parents=True, exist_ok=True)
    exe = folder / _php_name()
    exe.write_bytes(b"#!/bin/sh\nexit 0\n")
    exe.chmod(0o755)
    return exe


def test_php_in_usual_folders_is_listed_but_never_run(tmp_path, monkeypatch):
    """T-3: C:\\wamp64, C:\\xampp, C:\\php* ... can be created by any local user on a default C:\\
    ACL, and the PHP the assistant picks receives the plaintext sources. Such PHPs are only listed
    for the user to choose; find_php runs only the assistant's own download or the one in PATH."""
    planted = _plant_php(tmp_path / "wamp64" / "bin" / "php" / "php8.3.0")
    monkeypatch.setattr(actions, "_PHP_PLACES", (str(tmp_path / "wamp64" / "bin" / "php" / "php*" / _php_name()),))
    monkeypatch.setattr(actions, "_downloaded_phps", lambda: [])
    empty = tmp_path / "empty-path"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    probed = []
    monkeypatch.setattr(actions, "check_php", lambda cmd: probed.append(cmd) or ("ok", "8.3.0"))
    assert actions.find_php() is None
    assert str(planted) not in probed
    assert actions.known_php_locations() == [str(planted)]
    on_path = _plant_php(tmp_path / "bin")
    monkeypatch.setenv("PATH", os.pathsep.join([str(empty), str(tmp_path / "bin")]))
    assert actions.find_php() == str(on_path) and probed == [str(on_path)]


def test_php_in_the_current_directory_is_not_taken_for_the_one_in_path(tmp_path, monkeypatch):
    """shutil.which (and Windows' own search) look in the current directory first; that folder is
    not part of PATH and may be anywhere, so a php there is not "the PHP in PATH"."""
    _plant_php(tmp_path / "cwd")
    monkeypatch.chdir(tmp_path / "cwd")
    monkeypatch.setenv("PATH", os.pathsep.join(["", ".", str(tmp_path / "nothing")]))
    assert actions._php_on_path() is None


def _redirecting_server(location):
    """A local server whose every GET answers 302 to `location`; returns (server, base URL)."""
    class Redirect(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", location(self.path))
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def test_fetch_refuses_every_redirect_hop_away_from_https(php_mirror):
    """T-19: urllib followed https -> http -> https and only the final URL was checked; the plain
    middle hop could be read or altered on the network. Each hop is checked now, before it is
    followed (192.0.2.1 is a documentation address: never contacted)."""
    root, base = php_mirror
    (root / "file.bin").write_bytes(b"payload")
    server, start = _redirecting_server(lambda path: "http://192.0.2.1/hop?next=https://x" + path)
    try:
        with pytest.raises(OSError, match="away from HTTPS"):
            actions._fetch(start + "/file.bin", 1024)
    finally:
        server.shutdown()
        server.server_close()
    # An allowed hop (here the local test mirror) is still followed.
    server, start = _redirecting_server(lambda path: base + path)
    try:
        assert actions._fetch(start + "/file.bin", 1024) == b"payload"
    finally:
        server.shutdown()
        server.server_close()


# --- PHP download (official index + SHA-256) and VC++ redistributable ---------------------------


def _zip(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_extract_zip_refuses_a_zip_bomb(tmp_path, monkeypatch):
    """ENV-2026-27: _extract_zip bounds the UNCOMPRESSED total before writing anything. A member that
    expands past the cap is refused and nothing is extracted (no half-written temp left behind)."""
    monkeypatch.setattr(actions, "_EXTRACT_LIMIT", 1024)          # tiny cap for the test
    data = _zip({"big.txt": b"A" * 4096})                         # 4 KiB uncompressed > 1 KiB cap
    target = tmp_path / "out"
    with pytest.raises(ValueError, match="refusing to extract"):
        actions._extract_zip(data, target)
    assert not target.exists()                                   # nothing extracted
    assert list(tmp_path.glob(".php-*")) == []                   # and no temp dir left behind


def test_extract_zip_refuses_path_traversal(tmp_path):
    """ENV-2026-27 / defense in depth: a member with a '..' component or an absolute path is refused."""
    for bad in ({"../evil.txt": b"x"}, {"/abs.txt": b"x"}):
        with pytest.raises(ValueError, match="Unsafe path"):
            actions._extract_zip(_zip(bad), tmp_path / "o")


def _index(version, name, sha):
    minor = version.rsplit(".", 1)[0]
    return {"7.4": {"version": "7.4.33"},
            minor: {"version": version, "nts-vs17-x64": {"zip": {"path": name, "sha256": sha}},
                    "ts-vs17-x64": {"zip": {"path": "ts.zip", "sha256": "0" * 64}}}}


@pytest.fixture
def php_mirror(tmp_path):
    """A local stand-in for php.net: serves files from a folder over HTTP on 127.0.0.1."""
    root = tmp_path / "mirror"
    root.mkdir()

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(root), **kwargs)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield root, f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_latest_php_release_picks_newest_php8_nts_x64():
    index = _index("8.4.27", "php-8.4.27-nts-Win32-vs17-x64.zip", "a" * 64)
    index["8.5"] = {"version": "8.5.12", "nts-vs17-x64": {"zip": {
        "path": "php-8.5.12-nts-Win32-vs17-x64.zip", "sha256": "B" * 64}}}
    assert actions.latest_php_release(index) == ("8.5.12", "php-8.5.12-nts-Win32-vs17-x64.zip", "b" * 64)
    with pytest.raises(ValueError, match="Unexpected"):
        actions.latest_php_release(_index("8.4.27", "../evil.zip", "a" * 64))
    with pytest.raises(ValueError, match="No PHP 8"):
        actions.latest_php_release({"7.4": {"version": "7.4.33"}})


def test_fetch_refuses_plain_http_to_other_hosts():
    with pytest.raises(ValueError, match="non-HTTPS"):
        actions._fetch("http://example.com/releases.json", 10)


def test_download_php_verifies_and_extracts(tmp_path, php_mirror):
    root, base = php_mirror
    archive = _zip({"php.exe": b"MZ fake php", "ext/php_tokenizer.dll": b"dll"})
    name = "php-8.4.27-nts-Win32-vs17-x64.zip"
    (root / name).write_bytes(archive)
    (root / "releases.json").write_text(json.dumps(_index("8.4.27", name, hashlib.sha256(archive).hexdigest())))
    dest = tmp_path / "php"
    exe = actions.download_php(dest, (f"{base}/releases.json",))
    assert exe == dest / "8.4.27" / "php.exe" and exe.read_bytes() == b"MZ fake php"
    assert (dest / "8.4.27" / "ext" / "php_tokenizer.dll").exists()
    assert actions.download_php(dest, (f"{base}/releases.json",)) == exe     # already there


def test_download_php_rejects_wrong_checksum_and_unsafe_zip(tmp_path, php_mirror):
    root, base = php_mirror
    good = _zip({"php.exe": b"MZ"})
    (root / "good.zip").write_bytes(good)
    (root / "releases.json").write_text(json.dumps(_index("8.4.27", "good.zip", "f" * 64)))
    with pytest.raises(ValueError, match="SHA-256 does not match"):
        actions.download_php(tmp_path / "a", (f"{base}/releases.json",))
    assert not (tmp_path / "a" / "8.4.27").exists()                       # nothing left behind
    evil = _zip({"../../escape.txt": b"x", "php.exe": b"MZ"})
    (root / "evil.zip").write_bytes(evil)
    (root / "releases.json").write_text(json.dumps(_index("8.4.27", "evil.zip", hashlib.sha256(evil).hexdigest())))
    with pytest.raises(ValueError, match="Unsafe path"):
        actions.download_php(tmp_path / "b", (f"{base}/releases.json",))
    assert not (tmp_path / "escape.txt").exists() and not (tmp_path / "b" / "8.4.27").exists()


def test_download_php_falls_back_to_the_second_official_address(tmp_path, php_mirror):
    root, base = php_mirror
    archive = _zip({"php.exe": b"MZ"})
    (root / "p.zip").write_bytes(archive)
    (root / "releases.json").write_text(json.dumps(_index("8.3.9", "p.zip", hashlib.sha256(archive).hexdigest())))
    exe = actions.download_php(tmp_path / "php", (f"{base}/missing/releases.json", f"{base}/releases.json"))
    assert exe.parent.name == "8.3.9"


def test_downloaded_php_is_found_first(tmp_path, monkeypatch):
    home = tmp_path / "home"
    for version in ("8.3.9", "8.10.1", "8.4.27"):
        (home / version).mkdir(parents=True)
        (home / version / "php.exe").write_bytes(b"MZ")
    monkeypatch.setattr(actions, "php_home", lambda: home)
    monkeypatch.setattr(actions, "user_php_home", lambda: tmp_path / "none")
    assert [Path(p).parent.name for p in actions._downloaded_phps()] == ["8.10.1", "8.4.27", "8.3.9"]


def test_check_php_detects_missing_vc_runtime(monkeypatch):
    fake = _subprocess.CompletedProcess([], 0xC0000135, "", "")
    monkeypatch.setattr(actions.subprocess, "run", lambda *a, **k: fake)
    assert actions.check_php("php.exe")[0] == "no_vcruntime"


def test_vc_redist_runs_only_if_signed_by_microsoft(tmp_path, monkeypatch):
    """ENV-AUD-16: verification and the elevated run happen in ONE PowerShell process (no TOCTOU
    gap), which exits 2001 when the Microsoft signature is not valid and the installer's exit code
    otherwise. The signer check is anchored (whole O= RDN), requires the Code Signing EKU and a
    Microsoft root."""
    calls = []
    monkeypatch.setattr(actions, "_fetch", lambda url, limit: b"MZ installer")

    def fake_powershell(script, path):
        calls.append(script)
        # The single script both verifies and launches; model it by its exit code.
        return _subprocess.CompletedProcess([], 3010 if fake_powershell.signed else 2001, "", "")
    fake_powershell.signed = False
    monkeypatch.setattr(actions, "_powershell", fake_powershell)
    with pytest.raises(ValueError, match="not validly signed"):
        actions.install_vc_redist(tmp_path)
    assert len(calls) == 1 and not (tmp_path / "vc_redist.x64.exe").exists()   # never kept
    # The script is one process that both checks the signature (anchored RDN) and runs with RunAs.
    assert "RunAs" in calls[0] and "O=Microsoft Corporation(?:,\\s|$)" in calls[0]
    calls.clear()
    fake_powershell.signed = True
    code = actions.install_vc_redist(tmp_path)
    assert code == 3010 and actions.vc_redist_installed(code) and len(calls) == 1
    assert not (tmp_path / "vc_redist.x64.exe").exists()


@pytest.mark.parametrize("os_release,command", [
    ('ID=ubuntu\nID_LIKE=debian\n', "sudo apt install php-cli"),
    ('ID="fedora"\n', "sudo dnf install php-cli"),
    ('ID=arch\n', "sudo pacman -S php"),
    ('ID=gentoo\n', "your package manager"),
])
def test_php_install_hint(os_release, command, monkeypatch):
    monkeypatch.setattr(actions.sys, "platform", "linux")
    assert actions.php_install_hint(os_release).startswith(command)


def test_executable_releases_its_library_search_path_for_child_programs(monkeypatch):
    """Frozen executable: the user's PHP must not inherit the bundled runtime's search path
    (1.0.0 bug: PHP refused the bundled older VCRUNTIME140.dll)."""
    calls = []

    class Kernel32:
        def SetDllDirectoryW(self, value):
            calls.append(value)

    fake_ctypes = type(sys)("ctypes")
    fake_ctypes.windll = type("W", (), {"kernel32": Kernel32()})()
    monkeypatch.setitem(sys.modules, "ctypes", fake_ctypes)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "platform", "win32")
    actions.release_bundle_search_paths()
    assert calls == [None]
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("LD_LIBRARY_PATH", "/tmp/_MEIabc")
    monkeypatch.setenv("LD_LIBRARY_PATH_ORIG", "/opt/lib")
    actions.release_bundle_search_paths()
    assert os.environ["LD_LIBRARY_PATH"] == "/opt/lib"
    monkeypatch.delenv("LD_LIBRARY_PATH_ORIG")
    monkeypatch.setenv("LD_LIBRARY_PATH", "/tmp/_MEIabc")
    actions.release_bundle_search_paths()
    assert "LD_LIBRARY_PATH" not in os.environ
    monkeypatch.delattr(sys, "frozen")
    monkeypatch.setenv("LD_LIBRARY_PATH", "/kept")             # running from source: untouched
    actions.release_bundle_search_paths()
    assert os.environ["LD_LIBRARY_PATH"] == "/kept"


def _frozen_bundle_spec(monkeypatch):
    """Run gui/envelock-assistant.spec with PyInstaller stubbed out; return the Analysis(...) kwargs."""
    import runpy
    import types

    hooks = types.ModuleType("PyInstaller.utils.hooks")
    hooks.collect_all = lambda _package: ([], [], [])
    monkeypatch.setitem(sys.modules, "PyInstaller", types.ModuleType("PyInstaller"))
    monkeypatch.setitem(sys.modules, "PyInstaller.utils", types.ModuleType("PyInstaller.utils"))
    monkeypatch.setitem(sys.modules, "PyInstaller.utils.hooks", hooks)
    monkeypatch.chdir(ROOT)
    captured = {}

    def analysis(_scripts, **kwargs):
        captured.update(kwargs)
        return types.SimpleNamespace(pure=[], scripts=[], binaries=[], datas=[])

    runpy.run_path(str(ROOT / "gui" / "envelock-assistant.spec"), init_globals={
        "Analysis": analysis, "PYZ": lambda *args, **kwargs: None, "EXE": lambda *args, **kwargs: None,
    })
    return captured


def test_frozen_bundle_spec_includes_vendored_php_parser(monkeypatch):
    """A frozen encoder resolves third_party relative to its bundled encoder/ directory."""
    captured = _frozen_bundle_spec(monkeypatch)
    assert (str(ROOT / "third_party" / "php-parser"), "third_party/php-parser") in captured["datas"]
    assert (ROOT / "third_party" / "php-parser" / "lib" / "PhpParser" / "ParserFactory.php").is_file()
    assert (ROOT / "third_party" / "php-parser" / "LICENSE").is_file()


def test_frozen_bundle_spec_lists_every_module_the_dynamic_files_import(monkeypatch):
    """encoder/envelock.py, gui/actions.py and gui/_e2e.py travel as DATA and are executed by path
    inside the frozen exe, so PyInstaller never analyses their imports: every standard-library module
    they import must be in the spec's hidden imports, or the exe dies at start (on Windows it did:
    "No module named 'shlex'" on --selftest). Exempt: modules built into this interpreter, modules the
    entry script imports itself (analysed normally) and modules absent on this platform (msvcrt on
    POSIX, pwd on Windows: only imported on the other system's code path)."""
    import ast

    hidden = set(_frozen_bundle_spec(monkeypatch)["hiddenimports"])

    def imports(path):
        names = set()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module)
        return names

    entry = imports(ROOT / "gui" / "envelock_gui.py")
    missing = []
    for relative in ("encoder/envelock.py", "gui/actions.py", "gui/_e2e.py"):
        for name in sorted(imports(ROOT / relative)):
            if name == "__future__" or name.split(".")[0] not in sys.stdlib_module_names:
                continue
            if name in hidden or name in entry or name in sys.builtin_module_names:
                continue
            if importlib.util.find_spec(name) is None:
                continue
            missing.append(f"{name} ({relative})")
    assert not missing, "add to `hidden` in gui/envelock-assistant.spec: " + ", ".join(missing)


@pytest.mark.skipif(not _has_tokenizer(), reason="php CLI with tokenizer required")
def test_headless_gui_e2e_exercises_vendored_parser(tmp_path):
    environment = os.environ.copy()
    environment["ENVELOCK_E2E_PHP"] = PHP
    result = _subprocess.run([sys.executable, str(ROOT / "gui" / "_e2e.py"), "--e2e", str(tmp_path / "e2e")],
                             env=environment, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "php-ast=ok" in result.stdout


@pytest.mark.parametrize("tail", [[], ["--selftest"]])
def test_e2e_without_a_work_folder_is_a_usage_error_not_an_exception(tail):
    """A windowed (frozen) build has no console: an IndexError there sits on PyInstaller's error dialog
    instead of exiting. A missing folder must be a plain usage exit."""
    pytest.importorskip("tkinter")
    result = _subprocess.run([sys.executable, str(ROOT / "gui" / "envelock_gui.py"), "--e2e", *tail],
                             capture_output=True, text=True, timeout=120)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "usage: envelock-assistant --e2e <workdir>" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.skipif(sys.platform != "linux", reason="Linux build-script fallback")
def test_gui_builder_falls_back_to_hashed_requirements_when_wheels_are_absent(tmp_path):
    """A source checkout without prebuilt wheels must not attempt a nonexistent offline install."""
    root = tmp_path / "project"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(ROOT / "scripts" / "build-gui.sh", scripts / "build-gui.sh")
    (root / "requirements.lock").write_text("")
    shim = tmp_path / "python-shim"
    shim.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$GUI_BUILD_LOG"\nexit 0\n')
    shim.chmod(0o755)
    environment = os.environ.copy()
    environment["GUI_BUILD_LOG"] = str(tmp_path / "calls.txt")
    result = _subprocess.run(["bash", str(scripts / "build-gui.sh"), str(shim)],
                             cwd=root, env=environment, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    calls = (tmp_path / "calls.txt").read_text()
    assert "--require-hashes -r " in calls and "requirements.lock" in calls
    assert "--no-index --find-links" not in calls


def test_actions_recommend_returns_report_and_is_conservative(tmp_path):
    """The assistant's recommend action returns a human report plus the structured recommendation, and
    stays conservative: a clean tree gets the full safe set; the high-risk options are never enabled."""
    (tmp_path / "a.php").write_text("<?php class A { function f(){ return 1; } }\n")
    result = actions.recommend(tmp_path)
    assert "report" in result and "recommendation" in result
    assert "Recommended protection" in result["report"]
    rec = result["recommendation"]
    assert "--obfuscate" in rec["on"] and "--include-protection" in rec["on"]
    assert "--obfuscate-properties" not in rec["on"] and "--vault-strings" not in rec["on"]


def test_actions_recommend_rejects_a_file_path(tmp_path):
    """recommend analyses a project FOLDER; pointing it at a file is a clear error, not a traceback."""
    f = tmp_path / "x.php"
    f.write_text("<?php\n")
    try:
        actions.recommend(f)
    except ValueError as e:
        assert "folder" in str(e).lower()
    else:
        raise AssertionError("expected a ValueError for a file path")

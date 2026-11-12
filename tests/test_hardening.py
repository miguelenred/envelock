"""Regression tests for review findings and the v2 redesign (1.0.0)."""

import concurrent.futures
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from test_encoder import a, dir_link, symlink_or_skip

ENCODER = Path(__file__).resolve().parent.parent / "encoder" / "envelock.py"
LAUNCHER = Path(__file__).resolve().parent.parent / "envelock"


@pytest.fixture
def material():
    owner = a.make_owner()
    recipient = a.make_recipient("hardening")
    return owner, recipient, a.make_identity(recipient, owner)


def recipients(material):
    return [a.recipient_public(material[1])]


def tree(tmp_path):
    src = tmp_path / "source"
    src.mkdir()
    (src / "main.php").write_text('<?php echo "protected";', encoding="utf-8")
    return src


def test_encrypted_private_config_roundtrip(tmp_path, material):
    path = tmp_path / "encrypted.json"
    password = os.urandom(32)
    a.save_json(path, material[0], password)
    raw = path.read_text()
    assert material[0]["signing_private"] not in raw
    assert a.read_config(path, "envelock-owner", password) == material[0]
    with pytest.raises(ValueError, match="Wrong password"):
        a.read_config(path, "envelock-owner", b"not-the-correct-password")


def test_encrypted_recipient_config_roundtrip(tmp_path, material):
    path = tmp_path / "rcpt.json"
    password = os.urandom(32)
    a.save_json(path, material[1], password)
    assert material[1]["x25519_private"] not in path.read_text()
    assert a.read_config(path, "envelock-recipient", password) == material[1]


def test_encrypted_config_fixed_kdf_and_authentication(tmp_path, material):
    password = os.urandom(32)
    path = tmp_path / "encrypted.json"
    a.save_json(path, material[1], password)
    obj = json.loads(path.read_text())
    obj["kdf"] = "scrypt-huge-attacker-controlled"
    path.write_text(json.dumps(obj))
    with pytest.raises(ValueError):
        a.read_config(path, "envelock-recipient", password)
    obj["kdf"] = "scrypt-131072-8-1"
    damaged = bytearray.fromhex(obj["ciphertext"])
    damaged[0] ^= 1
    obj["ciphertext"] = damaged.hex()
    path.write_text(json.dumps(obj))
    with pytest.raises(ValueError):
        a.read_config(path, "envelock-recipient", password)


@pytest.mark.parametrize("value", [[], None, 1, {}, {"kind": "envelock-owner", "format": 1}])
def test_config_schema_rejects_non_objects(tmp_path, value):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        a.read_config(path, "envelock-owner")


@pytest.mark.parametrize("value", [None, 12, "ff", "g" * 64, "00" * 33])
def test_private_key_schema(material, value):
    broken = dict(material[0], signing_private=value)
    with pytest.raises(ValueError):
        a.validate_config(broken, "envelock-owner")


@pytest.mark.parametrize("value", [None, 12, "ff", "g" * 64, "00" * 33])
def test_x25519_key_schema(material, value):
    broken = dict(material[1], x25519_private=value)
    with pytest.raises(ValueError):
        a.validate_config(broken, "envelock-recipient")


def test_inconsistent_x25519_pair_rejected(material):
    broken = dict(material[1], x25519_public=a.make_recipient("x")["x25519_public"])
    with pytest.raises(ValueError, match="Inconsistent"):
        a.validate_config(broken, "envelock-recipient")


def test_recovery_key_equal_to_primary_rejected():
    """ENV-18: a recovery key identical to the primary signer gives no protection if the primary is
    compromised, so it is refused (owner and the public developer descriptor)."""
    owner = a.make_owner(with_recovery=True)
    broken = dict(owner, recovery_private=owner["signing_private"], recovery_public=owner["signing_public"])
    with pytest.raises(ValueError, match="recovery key must differ"):
        a.validate_config(broken, "envelock-owner")
    public = {"kind": "envelock-developer-public", "format": a.FORMAT_VERSION,
              "signing_public": owner["signing_public"], "recovery_public": owner["signing_public"]}
    with pytest.raises(ValueError, match="recovery key must differ"):
        a.validate_config(public, "envelock-developer-public")


@pytest.mark.parametrize("count", [0, a.MAX_IDENTITIES + 1])
def test_identity_bundle_bounds(material, count):
    with pytest.raises(ValueError):
        a.identity_bundle_bytes([material[2]] * count)


@pytest.mark.parametrize("name", [".ENV", ".Env.production", ".SSH/key.json", ".GIT/config"])
def test_case_insensitive_secret_exclusion(name):
    assert a.forbidden(Path(name))


@pytest.mark.parametrize(
    "name", ["index.php.bak", "source.phtml.txt", "server.key", "key.pem", "owner.json", "identity.bin",
             "legacy.php5", "old.php7", "listing.phps", "archive.phar", "data.sqlite", "dump.sql",
             "users.htpasswd", "server.ppk"]      # ENV-12: more PHP sources, local DBs, credentials
)
def test_dangerous_assets_rejected(tmp_path, material, name):
    src = tree(tmp_path)
    (src / name).write_text("secret")
    with pytest.raises(ValueError, match="private asset"):
        a.pack_tree(src, tmp_path / "out", recipients(material), material[0], str(uuid.uuid4()), assets=["*"])
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("content", [
    b"<?PHP echo 1;", b"<?= $secret ?>",
    b"<? $secret = 1; ?>",                              # ENV-12: short open tag is readable PHP
    "<?php echo 'x';".encode("utf-16"),                # ENV-12: UTF-16 template with <?php
])
def test_php_disguised_as_asset_rejected(tmp_path, material, content):
    src = tree(tmp_path)
    (src / "readme.txt").write_bytes(content)
    with pytest.raises(ValueError, match="readable PHP"):
        a.pack_tree(src, tmp_path / "out", recipients(material), material[0], str(uuid.uuid4()), assets=["*"])


def test_renamed_secret_descriptor_not_copied(tmp_path, material):
    src = tree(tmp_path)
    (src / "innocent.json").write_text(json.dumps(material[1]))
    with pytest.raises(ValueError, match="private (key material|configurations)"):
        a.pack_tree(src, tmp_path / "out", recipients(material), material[0], str(uuid.uuid4()), assets=["*.json"])


@pytest.mark.parametrize("case", ["identity", "recipient_cfg", "owner_txt", "pem", "named_identity",
                                  "utf16_bom", "utf16_nobom", "ini_unquoted"])
def test_disguised_secrets_not_copied_as_assets(tmp_path, material, case):
    """Secrets must be detected by content, not only by exact file name or .json suffix."""
    src = tree(tmp_path)
    (src / "conf").mkdir()
    payload = {
        "identity": ("conf/server-data.dat", a.identity_bytes(material[2])),
        "recipient_cfg": ("conf/client.cfg", json.dumps(material[1]).encode()),
        "owner_txt": ("conf/owner-prod.json.txt", json.dumps(material[0]).encode()),
        # Built in pieces so this fake key does not trip the release guard itself.
        "pem": ("conf/tls.txt", b"-----BEGIN " + b"PRIVATE KEY-----\nAAAA\n-----END " + b"PRIVATE KEY-----\n"),
        "named_identity": ("conf/identity-prod.bin", b"anything"),
        # Windows PowerShell 5.1 "Get-Content r.json > file" writes UTF-16LE with a BOM.
        "utf16_bom": ("conf/client.cfg", json.dumps(material[1]).encode("utf-16")),
        "utf16_nobom": ("conf/client.dat", json.dumps(material[1]).encode("utf-16-le")),
        "ini_unquoted": ("conf/keys.ini", ("x25519_private=" + material[1]["x25519_private"]).encode()),
    }[case]
    (src / payload[0]).write_bytes(payload[1])
    with pytest.raises(ValueError, match="private"):
        a.pack_tree(src, tmp_path / "out", recipients(material), material[0], str(uuid.uuid4()), assets=["conf/*"])
    assert not (tmp_path / "out").exists()


def test_link_not_reported_as_symlink_cannot_leave_tree(tmp_path, material, monkeypatch):
    """Simulates Windows: a junction is not reported by is_symlink() and there is no
    O_NOFOLLOW. A file reached through it from outside the source must not be packed."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.php").write_text('<?php echo "outside";')
    src = tree(tmp_path)
    symlink_or_skip(src / "link.php", outside / "secret.php")
    monkeypatch.setattr(Path, "is_symlink", lambda self: False)
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    with pytest.raises(ValueError, match="leaves the source tree"):
        a.pack_tree(src, tmp_path / "out", recipients(material), material[0], str(uuid.uuid4()))
    assert not (tmp_path / "out").exists()


def test_links_inside_excluded_dirs_are_skipped(tmp_path, material):
    """pnpm creates links/junctions inside node_modules; an excluded directory is skipped,
    so its links must not abort the pack (links elsewhere are still refused)."""
    outside = tmp_path / "outside"
    outside.mkdir()
    src = tree(tmp_path)
    (src / "node_modules").mkdir()
    dir_link(src / "node_modules" / "pkg", outside)     # a junction on Windows, as pnpm makes
    result = a.pack_tree(src, tmp_path / "out", recipients(material), material[0], str(uuid.uuid4()))
    assert result["protected_files"] == 1
    assert not (tmp_path / "out" / "node_modules").exists()


def test_cli_deeply_nested_json_is_a_clean_error(tmp_path):
    """A hostile, deeply nested JSON must give an error message, not a Python traceback."""
    import subprocess
    import sys
    nested = tmp_path / "nested.json"
    nested.write_text("[" * 60000 + "]" * 60000)
    script = Path(__file__).resolve().parent.parent / "encoder" / "envelock.py"
    result = subprocess.run([sys.executable, str(script), "inspect", str(nested)],
                            capture_output=True, text=True)
    assert result.returncode == 1
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("name", ["CON.php", "nul", "com9.json", "dir/trailing.", "dir/file ",
                                  # ENC-25: also reserved by Windows, and control characters
                                  "COM0.php", "lpt0", "COM¹.php", "lpt³.txt", "CONIN$",
                                  "conout$.php", "CON .php", "dir/a\x01b.php", "tab\there.php"])
def test_nonportable_paths_rejected(name):
    with pytest.raises(ValueError, match="portable"):
        a.validate_portable_path(Path(name))


def test_case_and_unicode_collisions():
    assert a.validate_portable_path(Path("Lib/Service.php")) == a.validate_portable_path(
        Path("lib/service.php")
    )
    assert a.validate_portable_path(Path("café.php")) == a.validate_portable_path(
        Path("café.php")
    )


def test_bounded_read_rejects_large_input(tmp_path):
    p = tmp_path / "large"
    p.write_bytes(b"12345")
    with pytest.raises(ValueError):
        a.bounded_read(p, 4)


def test_fifo_read_is_nonblocking_and_rejected(tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("POSIX FIFO test")
    p = tmp_path / "pipe"
    os.mkfifo(p)
    with pytest.raises(ValueError):
        a.bounded_read(p, 100)


def test_password_file_permissions(tmp_path, monkeypatch):
    p = tmp_path / "password"
    a.secret_write(p, b"a-long-random-password-for-testing\n")
    monkeypatch.setenv("ENVELOCK_PASSWORD_FILE", str(p))
    assert a.password_from_user() == b"a-long-random-password-for-testing"
    if os.name != "nt":
        p.chmod(0o644)
        with pytest.raises(ValueError, match="0600"):
            a.password_from_user()
    else:
        # ENC-24: the Windows equivalent of a 0644 password file is an ACL entry for another
        # principal (here BUILTIN\Users, by SID so it works on any display language).
        subprocess.run(["icacls", str(p), "/grant", "*S-1-5-32-545:R"], check=True, capture_output=True)
        with pytest.raises(ValueError, match="readable only by you"):
            a.password_from_user()


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL check")
@pytest.mark.parametrize("sid", ["S-1-1-0", "S-1-5-11", "S-1-5-20"])   # Everyone, Auth. Users, NS
def test_password_file_windows_acl_refuses_other_principals(tmp_path, monkeypatch, sid):
    """ENC-24: the ENVELOCK_PASSWORD_FILE permission check used to be skipped on Windows entirely;
    any entry for a principal other than you, SYSTEM and Administrators is now refused."""
    p = tmp_path / "password"
    a.secret_write(p, b"a-long-random-password-for-testing\n")
    subprocess.run(["icacls", str(p), "/grant", f"*{sid}:R"], check=True, capture_output=True)
    monkeypatch.setenv("ENVELOCK_PASSWORD_FILE", str(p))
    with pytest.raises(ValueError, match="readable only by you"):
        a.password_from_user()


def test_identity_file_written_0600(tmp_path, material):
    path = tmp_path / "identity.bin"
    a.secret_write(path, a.identity_bytes(material[2]))
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    else:
        sid = a._current_user_sid_string()
        assert a._windows_security_sddl(path) == f"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{sid})"


def test_simultaneous_pack_does_not_overwrite(tmp_path, material):
    src = tree(tmp_path)
    destination = tmp_path / "output"

    def pack_once(_):
        try:
            a.pack_tree(src, destination, recipients(material), material[0], str(uuid.uuid4()))
            return True
        except (ValueError, FileExistsError):
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(pack_once, range(2)))
    assert results.count(True) == 1
    assert a.open_protected((destination / "main.php").read_bytes(), material[2]).startswith(b"<?php")


def test_php_in_private_directory_is_not_silently_omitted(tmp_path, material):
    src = tree(tmp_path)
    (src / "private").mkdir()
    original = b'<?php return "private-application-logic";'
    (src / "private/engine.php").write_bytes(original)
    a.pack_tree(src, tmp_path / "output", recipients(material), material[0], str(uuid.uuid4()))
    blob = (tmp_path / "output/private/engine.php").read_bytes()
    assert original not in blob
    assert a.open_protected(blob, material[2]) == original


# --- M-05: a corrupt package gives a clean error, never a raw traceback -------------------------

def _valid_package(tmp_path, material):
    src = tree(tmp_path)
    a.pack_tree(src, tmp_path / "pkg", recipients(material), material[0], str(uuid.uuid4()))
    return bytearray((tmp_path / "pkg/main.php").read_bytes())


def test_parse_package_rejects_non_utf8_path(tmp_path, material):
    """A package whose path bytes are not UTF-8 must raise ValueError (M-05), not let a raw
    UnicodeDecodeError escape. 'main.php' is 8 bytes; overwrite them in place (length unchanged)."""
    blob = _valid_package(tmp_path, material)
    fixed = len(a.STUB) + a.HEADER.size
    blob[fixed:fixed + len("main.php")] = b"\xff" * len("main.php")
    with pytest.raises(ValueError, match="UTF-8"):
        a.parse_package(bytes(blob))


def test_parse_package_rejects_traversal_path(tmp_path, material):
    """A package whose embedded path is not a clean relative path is refused (M-05)."""
    blob = _valid_package(tmp_path, material)
    fixed = len(a.STUB) + a.HEADER.size
    blob[fixed:fixed + len("main.php")] = b"../../ab"     # same length as 'main.php'
    with pytest.raises(ValueError, match="clean relative path"):
        a.parse_package(bytes(blob))


# --- M-06: package permissions are deterministic, not the caller's umask ------------------------

def test_pack_tree_permissions_independent_of_umask(tmp_path, material):
    """Under a permissive umask the files inside the package must still be 0644, never 0666, and
    the top directory 0755 (M-06). Without the normalisation they would inherit umask 000."""
    if os.name == "nt":
        pytest.skip("POSIX permission test")
    src = tree(tmp_path)
    (src / "sub").mkdir()
    (src / "sub/more.php").write_text("<?php echo 1;", encoding="utf-8")
    out = tmp_path / "out"
    old = os.umask(0)
    try:
        a.pack_tree(src, out, recipients(material), material[0], str(uuid.uuid4()))
    finally:
        os.umask(old)
    assert out.stat().st_mode & 0o777 == 0o755
    assert (out / "main.php").stat().st_mode & 0o777 == 0o644
    assert (out / "sub").stat().st_mode & 0o777 == 0o755
    assert (out / "sub/more.php").stat().st_mode & 0o777 == 0o644


# --- L-01: a secret's parent directory is created private (0700) --------------------------------

def test_secret_write_creates_private_parent(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX permission test")
    old = os.umask(0)
    try:
        target = tmp_path / "keys" / "identity.bin"
        a.secret_write(target, b"x" * 64)
    finally:
        os.umask(old)
    assert target.parent.stat().st_mode & 0o777 == 0o700


def test_secret_write_does_not_clamp_preexisting_parent(tmp_path):
    """mkdir's mode applies only to a folder secret_write CREATES. A PRE-EXISTING folder is left as the
    operator set it: forcing a shared system dir (e.g. /etc/envelock, which may also hold a
    world-readable licence) to 0700 silently broke other users' access (ENV-2026-17, which revises the
    earlier NU-04 behaviour). The secret file itself is still created 0600, so it stays private
    regardless of the directory mode."""
    if os.name == "nt":
        pytest.skip("POSIX permission test")
    old = os.umask(0)
    try:
        parent = tmp_path / "keys"
        parent.mkdir(mode=0o755)                         # pre-existing, operator's choice
        assert parent.stat().st_mode & 0o777 == 0o755
        a.secret_write(parent / "identity.bin", b"x" * 64)
    finally:
        os.umask(old)
    assert parent.stat().st_mode & 0o777 == 0o755        # parent left untouched
    assert (parent / "identity.bin").stat().st_mode & 0o777 == 0o600   # file still private


def test_bounded_read_private_requires_owner_only(tmp_path):
    """private=True enforces 0600-or-stricter via fstat on the OPEN descriptor (no pre-open path.stat
    that follows symlinks and leaves a TOCTOU window, audit NU-02)."""
    if os.name == "nt":
        pytest.skip("POSIX permission test")
    p = tmp_path / "secret"
    p.write_bytes(b"value")
    p.chmod(0o640)
    with pytest.raises(ValueError, match="0600"):
        a.bounded_read(p, 100, private=True)
    p.chmod(0o600)
    assert a.bounded_read(p, 100, private=True) == b"value"


# --- L-04: the private-key password is measured in characters, not bytes ------------------------

def test_password_length_is_characters_not_bytes(tmp_path, monkeypatch):
    """Ten two-byte characters are 20 bytes but only 10 characters: a byte-based check would let
    this weak password through. password_from_user must reject it (L-04)."""

    def password_file(name, text):
        path = tmp_path / name
        if os.name == "nt":       # owner-only ACL: the Windows password-file check (ENC-24)
            a.secret_write(path, text.encode("utf-8"))
            return path
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)
        return path

    weak = password_file("weak", "ñ" * 10 + "\n")              # 20 bytes, 10 characters
    monkeypatch.setenv("ENVELOCK_PASSWORD_FILE", str(weak))
    with pytest.raises(ValueError, match="16 characters"):
        a.password_from_user()
    ok = password_file("ok", "ñ" * 16 + "\n")                  # 16 characters: accepted
    monkeypatch.setenv("ENVELOCK_PASSWORD_FILE", str(ok))
    assert a.password_from_user() == ("ñ" * 16).encode("utf-8")


# --- DEMO rejection: the published demo keys cannot silently reach a real pack -------------------

def _demo_keyfiles(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "demo_material", ENCODER.parent.parent / "scripts" / "demo_material.py")
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    owner, recipient = demo.get_material()
    (tmp_path / "owner.json").write_text(json.dumps(owner), encoding="utf-8")
    (tmp_path / "recipient.json").write_text(json.dumps(a.recipient_public(recipient)), encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.php").write_text("<?php echo 1;", encoding="utf-8")
    return src


def _run_pack(tmp_path, src, extra):
    return subprocess.run(
        [sys.executable, str(ENCODER), "pack", "--owner", str(tmp_path / "owner.json"),
         "--recipient", str(tmp_path / "recipient.json"), "--project", str(uuid.uuid4()),
         "--source", str(src), "--output", str(tmp_path / "out"), *extra],
        capture_output=True, text=True)


def test_pack_refuses_demo_keys(tmp_path):
    src = _demo_keyfiles(tmp_path)
    result = _run_pack(tmp_path, src, [])
    assert result.returncode == 1
    assert "demo" in result.stderr.lower() and not (tmp_path / "out").exists()


def test_pack_allows_demo_keys_with_flag(tmp_path):
    src = _demo_keyfiles(tmp_path)
    result = _run_pack(tmp_path, src, ["--allow-demo"])
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "out" / "main.php").exists()


# --- L-10: the launcher exits 2 with guidance when no portable Python is present ----------------

def test_launcher_exits_2_when_bundle_missing(tmp_path):
    if os.name == "nt" or not LAUNCHER.exists():
        pytest.skip("POSIX launcher test")
    stub = tmp_path / "envelock"
    stub.write_bytes(LAUNCHER.read_bytes())
    stub.chmod(0o755)
    (tmp_path / "encoder").mkdir()
    (tmp_path / "encoder" / "envelock.py").write_text("print('x')\n", encoding="utf-8")
    (tmp_path / "prebuilt" / "python").mkdir(parents=True)     # present but empty: no interpreter
    result = subprocess.run([str(stub), "new-project"], capture_output=True, text=True)
    assert result.returncode == 2
    assert "portable Python" in result.stderr


# --- C8: signed manifest and `verify` detect tampering -----------------------------------------

def _packed_with_manifest(tmp_path, material):
    tmp_path.mkdir(parents=True, exist_ok=True)
    src = tree(tmp_path)
    (src / "lib.php").write_text("<?php echo 2;", encoding="utf-8")
    out = tmp_path / "out"
    a.pack_tree(src, out, recipients(material), material[0], str(uuid.uuid4()), manifest=True)
    return out


def test_manifest_verify_clean_package(tmp_path, material):
    out = _packed_with_manifest(tmp_path, material)
    assert (out / "envelock-manifest").is_file()
    pub = a.developer_public(material[0])["signing_public"]
    report = a.verify_package(out, pub)
    assert report["ok"] and not report["missing"] and not report["added"] and not report["changed"]


def test_manifest_verify_detects_tampering(tmp_path, material):
    pub = a.developer_public(material[0])["signing_public"]
    out = _packed_with_manifest(tmp_path, material)
    (out / "main.php").write_bytes((out / "main.php").read_bytes() + b"x")   # modify
    assert a.verify_package(out, pub)["changed"] == ["main.php"]
    out2 = _packed_with_manifest(tmp_path / "b", material)
    (out2 / "lib.php").unlink()                                              # delete
    assert a.verify_package(out2, pub)["missing"] == ["lib.php"]
    out3 = _packed_with_manifest(tmp_path / "c", material)
    (out3 / "evil.php").write_text("<?php", encoding="utf-8")                # add
    r = a.verify_package(out3, pub)
    assert r["added"] == ["evil.php"] and not r["ok"]


def test_manifest_verify_rejects_wrong_signer(tmp_path, material):
    out = _packed_with_manifest(tmp_path, material)
    other = a.developer_public(a.make_owner())["signing_public"]
    with pytest.raises(ValueError, match="signature"):
        a.verify_package(out, other)


def test_manifest_verify_rejects_malformed(tmp_path, material):
    out = _packed_with_manifest(tmp_path, material)
    pub = a.developer_public(material[0])["signing_public"]
    (out / "envelock-manifest").write_text('{"kind":"envelock-manifest"}', encoding="utf-8")
    with pytest.raises(ValueError):
        a.verify_package(out, pub)


def test_verify_cli_exit_codes(tmp_path, material):
    out = _packed_with_manifest(tmp_path, material)
    ownerfile = tmp_path / "owner.json"
    ownerfile.write_text(json.dumps(material[0]), encoding="utf-8")
    base = [sys.executable, str(ENCODER), "verify", "--package", str(out), "--owner", str(ownerfile)]
    assert subprocess.run(base, capture_output=True).returncode == 0
    (out / "main.php").write_bytes(b"tampered")
    assert subprocess.run(base, capture_output=True).returncode == 1


def _flags_byte(blob):
    """Package flags are a single byte at STUB + 9 (see test_tamper offsets)."""
    return blob[len(a.STUB) + 9]


def test_no_ffi_flag_set_in_header(tmp_path, material):
    """pack --no-ffi sets FLAG_NO_FFI in the signed header; default packs leave it clear."""
    src = tree(tmp_path)
    on = a.pack_tree(src, tmp_path / "on", recipients(material), material[0], str(uuid.uuid4()), no_ffi=True)
    off = a.pack_tree(src, tmp_path / "off", recipients(material), material[0], str(uuid.uuid4()))
    assert on["no_ffi"] is True and off["no_ffi"] is False
    assert _flags_byte((tmp_path / "on" / "main.php").read_bytes()) & a.FLAG_NO_FFI
    assert not _flags_byte((tmp_path / "off" / "main.php").read_bytes()) & a.FLAG_NO_FFI


def test_sealed_flag_set_in_header(tmp_path, material):
    """pack --sealed sets FLAG_SEALED in the signed header; default packs leave it clear."""
    src = tree(tmp_path)
    on = a.pack_tree(src, tmp_path / "s_on", recipients(material), material[0], str(uuid.uuid4()), sealed=True)
    off = a.pack_tree(src, tmp_path / "s_off", recipients(material), material[0], str(uuid.uuid4()))
    assert on["sealed"] is True and off["sealed"] is False
    assert _flags_byte((tmp_path / "s_on" / "main.php").read_bytes()) & a.FLAG_SEALED
    assert not _flags_byte((tmp_path / "s_off" / "main.php").read_bytes()) & a.FLAG_SEALED


@pytest.mark.skipif(shutil.which("php") is None, reason="php CLI required for --vault-strings")
def test_vault_flag_set_in_header(tmp_path, material):
    """pack --vault-strings sets FLAG_VAULT in the signed header and reports strings_vaulted;
    default packs leave it clear. The echoed literal moves out of the compiled source."""
    src = tree(tmp_path)
    on = a.pack_tree(src, tmp_path / "v_on", recipients(material), material[0], str(uuid.uuid4()), vault_strings=True)
    off = a.pack_tree(src, tmp_path / "v_off", recipients(material), material[0], str(uuid.uuid4()))
    assert on["strings_vaulted"] is True and off["strings_vaulted"] is False
    assert _flags_byte((tmp_path / "v_on" / "main.php").read_bytes()) & a.FLAG_VAULT
    assert not _flags_byte((tmp_path / "v_off" / "main.php").read_bytes()) & a.FLAG_VAULT
    # The runtime literal "protected" is no longer in the plaintext source the loader compiles.
    plain = a.open_protected((tmp_path / "v_on" / "main.php").read_bytes(), material[2])
    table_bytes = int.from_bytes(plain[:4], "big")
    assert b"protected" not in plain[4 + table_bytes:]        # not in the source
    assert b"__envelock_lit(" in plain[4 + table_bytes:]      # replaced by a vault call


# --- ENV-09: minimum set from the signed header, anti-rollback of the minimum ---

def test_minimum_reads_signed_header_not_unsigned_metadata(tmp_path, material):
    """minimum set --package must take project/serial from the SIGNED header, so a tampered
    envelock-package.json (unsigned, informational) cannot steer the minimum."""
    owner, recipient, _ = material
    out = tmp_path / "pkg"
    a.pack_tree(tree(tmp_path), out, recipients(material), owner, str(uuid.uuid4()), serial=500)
    meta = out / "envelock-package.json"
    info = json.loads(meta.read_text(encoding="utf-8"))
    info["serial"] = 999999
    info["project_id"] = str(uuid.uuid4())           # a different project, too
    meta.write_text(json.dumps(info), encoding="utf-8")
    store = a.add_recipient_to_store(None, recipient, owner)
    header = a.verified_header(a.first_protected_file(out), a.identity_signers(store))
    assert header["serial"] == 500                   # the signed serial, not the tampered 999999


def test_minimum_rejects_package_from_untrusted_signer(tmp_path, material):
    """A package whose signer is not a trusted developer in the identity file is refused."""
    owner, recipient, _ = material
    out = tmp_path / "pkg"
    a.pack_tree(tree(tmp_path), out, recipients(material), owner, str(uuid.uuid4()), serial=7)
    other = a.make_owner()                            # a different, untrusted signer
    store = a.add_recipient_to_store(None, recipient, other)
    with pytest.raises(ValueError, match="no trusted developer"):
        a.verified_header(a.first_protected_file(out), a.identity_signers(store))


def test_set_minimum_refuses_downgrade(material):
    """Lowering an existing minimum needs allow_downgrade; raising it is always fine."""
    owner, recipient, _ = material
    project = str(uuid.uuid4())
    store = a.set_minimum(a.add_recipient_to_store(None, recipient, owner), project, 100)
    assert a.identity_minimums(a.set_minimum(store, project, 200))[(uuid.UUID(project).bytes, a.ZERO32)] == 200
    with pytest.raises(ValueError, match="lower the minimum"):
        a.set_minimum(store, project, 50)
    lowered = a.set_minimum(store, project, 50, allow_downgrade=True)
    assert a.identity_minimums(lowered)[(uuid.UUID(project).bytes, a.ZERO32)] == 50


def test_minimum_keeps_each_developer_independently(material):
    """Two developers that share a project id must keep INDEPENDENT minimums. Keying the store by
    project alone let the second developer's minimum silently replace the first's (audit ENV-03),
    even though the wire format and the loader bind each minimum to its developer."""
    owner_a, recipient, _ = material
    owner_b = a.make_owner()
    store = a.add_recipient_to_store(None, recipient, owner_a)
    store = a.set_developer(store, a.developer_public(owner_b))
    project = str(uuid.uuid4())
    pa = bytes.fromhex(owner_a["signing_public"])
    pb = bytes.fromhex(owner_b["signing_public"])
    store = a.set_minimum(store, project, 100, pa)
    store = a.set_minimum(store, project, 50, pb)        # same project, different developer
    mins = a.identity_minimums(store)
    pid = uuid.UUID(project).bytes
    assert mins[(pid, pa)] == 100 and mins[(pid, pb)] == 50   # both survive (one entry before the fix)


def test_enforce_manifest_flag_and_signed_binary(tmp_path, material):
    """pack --enforce-manifest sets FLAG_ENFORCE_MANIFEST and writes a signed binary manifest."""
    owner, recipient, _ = material
    out = tmp_path / "pkg"
    a.pack_tree(tree(tmp_path), out, recipients(material), owner, str(uuid.uuid4()),
                enforce_manifest=True)
    assert _flags_byte((out / "main.php").read_bytes()) & a.FLAG_ENFORCE_MANIFEST
    man = (out / a.MANIFEST_BIN_NAME).read_bytes()
    assert man[:8] == a.MANIFEST_BIN_MAGIC and man[8] == a.FORMAT_VERSION
    # the signature covers everything but the trailing 64 bytes
    a.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(owner["signing_public"])).verify(man[-64:], man[:-64])
    # default packs write no binary manifest and leave the flag clear
    off = tmp_path / "off"
    (tmp_path / "b").mkdir()
    a.pack_tree(tree(tmp_path / "b"), off, recipients(material), owner, str(uuid.uuid4()))
    assert not (off / a.MANIFEST_BIN_NAME).exists()
    assert not _flags_byte((off / "main.php").read_bytes()) & a.FLAG_ENFORCE_MANIFEST


@pytest.mark.parametrize("data", [b"\x00\x01\x02not json", b"", b"\xff\xfe\x00\x01", b"<html></html>"])
def test_inspect_rejects_garbage_cleanly(tmp_path, data):
    """inspect turns any unrecognized input into a clean ValueError, never a raw decode/JSON
    traceback the CLI would not catch (ENV-18: inspect validates its input)."""
    p = tmp_path / "x.bin"
    p.write_bytes(data)
    with pytest.raises(ValueError):
        a.inspect_path(p)


def test_inspect_owner_without_signing_public_is_clean_error(tmp_path):
    """ENV-18: an owner/developer descriptor missing or with a bad signing_public gives a clean
    ValueError, not a KeyError or a low-level 'non-hexadecimal' traceback."""
    bad = tmp_path / "o.json"
    bad.write_text(json.dumps({"kind": "envelock-owner", "format": 2}), encoding="utf-8")
    with pytest.raises(ValueError, match="signing_public"):
        a.inspect_path(bad)
    bad.write_text(json.dumps({"kind": "envelock-developer-public", "signing_public": "zz"}), encoding="utf-8")
    with pytest.raises(ValueError, match="signing_public"):
        a.inspect_path(bad)


def test_manifest_and_enforce_manifest_verify_clean(tmp_path, material):
    """pack --manifest --enforce-manifest must produce a package that `verify` accepts: the binary
    manifest is written before the JSON one so the JSON inventories it (external audit A1)."""
    src = tree(tmp_path)
    (src / "config.json").write_text('{"k": 1}', encoding="utf-8")
    out = tmp_path / "pkg"
    a.pack_tree(src, out, recipients(material), material[0], str(uuid.uuid4()),
                assets=["*.json"], manifest=True, enforce_manifest=True)
    report = a.verify_package(out, material[0]["signing_public"])
    assert report["ok"] is True and report["added"] == [] and report["missing"] == []


def test_verify_package_clear_error_when_only_binary_manifest(tmp_path, material):
    """verify_package must raise a clear ValueError (not FileNotFoundError) when a package has only
    the runtime binary manifest (external audit B3)."""
    out = tmp_path / "pkg"
    a.pack_tree(tree(tmp_path), out, recipients(material), material[0], str(uuid.uuid4()),
                enforce_manifest=True)
    with pytest.raises(ValueError, match="binary manifest"):
        a.verify_package(out, material[0]["signing_public"])


def test_pack_tree_refuses_demo_keys_via_api_and_gui(tmp_path):
    """The demo-key refusal must live in pack_tree, so the GUI (gui/actions.pack) and any API caller
    are covered, not only the CLI handler (external audit ENV-AUD-07)."""
    import importlib.util as _ilu
    src = _demo_keyfiles(tmp_path)
    owner = a.read_config(tmp_path / "owner.json", "envelock-owner")
    recipient = a.read_config(tmp_path / "recipient.json", "envelock-recipient-public")
    with pytest.raises(ValueError, match="demo"):
        a.pack_tree(src, tmp_path / "out_api", [recipient], owner, str(uuid.uuid4()))
    # Through the GUI action layer too (it forwards to pack_tree with allow_demo defaulting off).
    spec = _ilu.spec_from_file_location("gui_actions", Path(__file__).resolve().parent.parent / "gui" / "actions.py")
    actions = _ilu.module_from_spec(spec)
    spec.loader.exec_module(actions)
    with pytest.raises(ValueError, match="demo"):
        actions.pack(tmp_path / "owner.json", None, [tmp_path / "recipient.json"], str(uuid.uuid4()),
                     src, tmp_path / "out_gui")


@pytest.mark.parametrize("name,data", [
    ("config.json", b'{"password": "s3cret"}'),
    ("app.env", b"DB_PASSWORD=hunter2\n"),
    ("aws.ini", b"aws_secret_access_key = AKIA\n"),
    ("config.data", b'password = "supersecret"'),       # NU-05: custom extension must not bypass
    ("settings.conf.local", b"api_key: 0123456789abcdef"),
])
def test_asset_with_credentials_refused_unless_opted_in(tmp_path, material, name, data):
    """A config asset whose content looks like credentials is refused (assets are not encrypted),
    unless allow_secret_assets is set (external audit A4 / ENV-AUD-15). The content scan runs on
    EVERY asset, not only a fixed extension list, so a custom name cannot smuggle a secret (NU-05)."""
    src = tree(tmp_path)
    (src / name).write_bytes(data)
    with pytest.raises(ValueError, match="credential"):
        a.pack_tree(src, tmp_path / "o1", recipients(material), material[0], str(uuid.uuid4()), assets=[name])
    a.pack_tree(src, tmp_path / "o2", recipients(material), material[0], str(uuid.uuid4()),
                assets=[name], allow_secret_assets=True)       # opt-in packs it
    assert (tmp_path / "o2" / name).is_file()


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell invocation")
def test_launcher_can_be_invoked_via_sh_when_archive_loses_execute_bit(tmp_path):
    stub = tmp_path / "envelock"
    stub.write_bytes(LAUNCHER.read_bytes())
    stub.chmod(0o644)
    (tmp_path / "encoder").mkdir()
    (tmp_path / "encoder" / "envelock.py").write_text("print('x')\n", encoding="utf-8")
    result = subprocess.run(["sh", str(stub), "new-project"], capture_output=True, text=True)
    assert result.returncode == 2 and "portable Python" in result.stderr

"""Regression tests for the encoder audit findings ENC-1 .. ENC-26 (Nov 2026).

Each test names the finding it covers and was written to FAIL on the code before the fix."""

import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from test_encoder import ROOT, a, dir_link, symlink_or_skip, windows_dacl
from test_transform import PHP, needs_php

ENCODER = str(ROOT / "encoder" / "envelock.py")
windows_only = pytest.mark.skipif(os.name != "nt", reason="Windows ACL behaviour")
posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX permission behaviour")


@pytest.fixture
def material():
    owner = a.make_owner()
    recipient = a.make_recipient("audit")
    return owner, recipient, a.make_identity(recipient, owner)


def run_cli(*argv, env=None):
    return subprocess.run([sys.executable, ENCODER, *map(str, argv)], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, env=env)


def keyfiles(tmp_path, material):
    owner, recipient, _ = material
    (tmp_path / "owner.json").write_text(json.dumps(owner), encoding="utf-8")
    (tmp_path / "rcpt.json").write_text(json.dumps(recipient), encoding="utf-8")
    (tmp_path / "rcpt.pub.json").write_text(json.dumps(a.recipient_public(recipient)), encoding="utf-8")
    return tmp_path / "owner.json", tmp_path / "rcpt.json", tmp_path / "rcpt.pub.json"


def source_tree(tmp_path, files):
    src = tmp_path / "src"
    for name, data in files.items():
        (src / name).parent.mkdir(parents=True, exist_ok=True)
        (src / name).write_bytes(data)
    return src


def pack(material, src, out, **options):
    return a.pack_tree(src, out, [a.recipient_public(material[1])], material[0], str(uuid.uuid4()),
                       **options)


# --- ENC-1: server-install on Windows ---------------------------------------------------------------

@windows_only
def test_enc1_server_install_windows_protected_at_creation(tmp_path):
    """The identity is created with a protected ACL (no inherited entries), read-only, and the
    command succeeds. Before: created with the folder's inherited ACL, the POSIX 0o077 mode check
    always tripped and the cleanup unlink failed on the read-only file (WinError 5)."""
    out = tmp_path / "etc" / "identity.bin"
    a.server_install(b"SECRET-IDENTITY", out)
    assert out.read_bytes() == b"SECRET-IDENTITY"
    sid = a._current_user_sid_string()
    assert windows_dacl(out) == f"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{sid})"
    assert os.stat(out).st_file_attributes & stat.FILE_ATTRIBUTE_READONLY
    a._unlink_secret(out)                       # clears read-only first
    assert not out.exists()


@windows_only
def test_enc1_server_install_windows_failure_removes_readonly_file(tmp_path, monkeypatch):
    """A failed verification must remove the half-installed, read-only identity."""
    monkeypatch.setattr(a, "_windows_dacl_problem", lambda handle, allowed: "simulated exposure")
    out = tmp_path / "identity.bin"
    with pytest.raises(ValueError, match="simulated exposure"):
        a.server_install(b"SECRET", out)
    assert not out.exists()


@windows_only
def test_enc1_server_install_owner_user_on_windows_is_a_clean_error(tmp_path, material):
    owner, recipient, _ = keyfiles(tmp_path, material)
    result = run_cli("server-install", "--recipient", recipient, "--owner", owner,
                     "--out", tmp_path / "id.bin", "--owner-user", "someone")
    assert result.returncode == 1, result.stderr
    assert "POSIX" in result.stderr and "Traceback" not in result.stderr
    assert not (tmp_path / "id.bin").exists()


@windows_only
def test_enc1_server_install_cli_windows(tmp_path, material):
    owner, recipient, _ = keyfiles(tmp_path, material)
    result = run_cli("server-install", "--recipient", recipient, "--owner", owner,
                     "--out", tmp_path / "id.bin")
    assert result.returncode == 0, result.stderr
    assert "protected access list" in result.stdout
    a._unlink_secret(tmp_path / "id.bin")


# --- ENC-2: no path-based chown/chmod after the descriptor is closed (POSIX) --------------------

@posix_only
def test_enc2_server_install_never_chowns_or_chmods_by_path(tmp_path, monkeypatch):
    """chown/chmod by PATH after close followed a symlink the target user could swap in. Every step
    must use the open descriptor (fchown/fchmod/fstat)."""
    def refuse(*args, **kwargs):
        raise AssertionError(f"path-based call {args!r}")
    monkeypatch.setattr(a.os, "chown", refuse)
    monkeypatch.setattr(a.os, "chmod", refuse)
    out = tmp_path / "identity.bin"
    a.server_install(b"SECRET", out, owner_uid=os.geteuid(), owner_gid=os.getegid())
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o400


@posix_only
def test_enc2_write_public_never_chmods_by_path(tmp_path, monkeypatch):
    target = tmp_path / "licence.bin"                 # parent exists: no chmod of a created parent
    monkeypatch.setattr(a.os, "chmod", lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError(f"path-based chmod {args!r}")))
    a.write_public(target, b"LICENCE")
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o644


# --- ENC-3: a bare program name is resolved through PATH only ------------------------------------

def _plant_fake_php(folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        # Any real executable will do; if it ran instead of PHP the transform would fail.
        shutil.copy(Path(os.environ["SystemRoot"]) / "System32" / "whoami.exe", folder / "php.exe")
    else:
        (folder / "php").write_text("#!/bin/sh\necho planted >&2\nexit 7\n")
        (folder / "php").chmod(0o755)


@needs_php
def test_enc3_planted_php_in_current_folder_never_runs(tmp_path, monkeypatch):
    """A php(.exe) planted in the current folder (the project being packed) must not run: before,
    CreateProcess searched the current folder before PATH (and on POSIX an empty PATH entry meant
    the current folder), and the planted program received the plaintext sources."""
    planted = tmp_path / "project"
    _plant_fake_php(planted)
    monkeypatch.chdir(planted)
    php_dir = os.path.dirname(PHP)
    monkeypatch.setenv("PATH", php_dir if os.name == "nt" else os.pathsep + php_dir)
    monkeypatch.setattr(a, "_PROGRAM_CACHE", {})
    out, _ = a.transform_sources({"x.php": b"<?php\n// comment\necho 1;\n"}, "php", strip=True)
    assert b"comment" not in out["x.php"]
    assert os.path.normcase(a.resolve_program("php")).startswith(os.path.normcase(php_dir))


def test_enc3_resolve_program_skips_current_and_relative_path_entries(tmp_path, monkeypatch):
    _plant_fake_php(tmp_path / "cwd")
    monkeypatch.chdir(tmp_path / "cwd")
    monkeypatch.setattr(a, "_PROGRAM_CACHE", {})
    monkeypatch.setenv("PATH", os.pathsep.join(["", ".", "relative", str(tmp_path / "empty")]))
    with pytest.raises(ValueError, match="not found in the PATH folders"):
        a.resolve_program("php")
    with pytest.raises(ValueError, match="need a php CLI"):
        a.transform_sources({"x.php": b"<?php echo 1;"}, "php", strip=True)
    # A name with a folder part is the operator's explicit choice, made absolute.
    explicit = os.path.join("tools", "php")
    assert a.resolve_program(explicit) == os.path.abspath(explicit)
    # Found in a real PATH folder; on Windows only php.exe, never a php.bat (cmd.exe re-parsing).
    good = tmp_path / "bin"
    _plant_fake_php(good)
    if os.name == "nt":
        (good / "php.exe").rename(good / "php.bat")
        monkeypatch.setenv("PATH", str(good))
        with pytest.raises(ValueError, match="not found"):
            a.resolve_program("php")
        (good / "php.bat").rename(good / "php.exe")
    monkeypatch.setenv("PATH", os.pathsep.join(["", str(good)]))
    found = a.resolve_program("php")
    assert os.path.dirname(found) == str(good) and os.path.isabs(found)


# --- ENC-4: Windows secrets are created already restricted ------------------------------------------

@windows_only
def test_enc4_secret_is_never_created_with_an_inherited_acl(tmp_path, monkeypatch):
    """Before: os.open created the file with the folder's ACL and the ACL was restricted AFTER, so a
    handle opened in between kept its access. Now the protected ACL is in the CreateFileW call: the
    file never exists without it."""
    real_open, real_create = os.open, a._windows_create_new
    seen = []

    def no_create_open(path, flags, *args, **kwargs):
        if flags & os.O_CREAT and str(path).startswith(str(tmp_path)):
            raise AssertionError(f"secret created through os.open (inherited ACL): {path}")
        return real_open(path, flags, *args, **kwargs)

    def create_and_look(path, sddl, *args, **kwargs):
        fd = real_create(path, sddl, *args, **kwargs)
        seen.append(windows_dacl(path))            # the ACL at the very first moment, still empty
        return fd

    monkeypatch.setattr(a.os, "open", no_create_open)
    monkeypatch.setattr(a, "_windows_create_new", create_and_look)
    a.save_json(tmp_path / "owner.json", a.make_owner())
    sid = a._current_user_sid_string()
    assert seen == [f"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{sid})"]
    assert windows_dacl(tmp_path / "owner.json") == seen[0]


# --- ENC-5: bytecode staging sources -----------------------------------------------------------------

def test_enc5_bytecode_refuses_to_write_through_a_link_under_the_deploy_root(tmp_path, monkeypatch):
    """A folder under the deploy root that is a junction/symlink would receive the plaintext
    sources wherever it points."""
    deploy, outside = tmp_path / "deploy", tmp_path / "outside"
    deploy.mkdir()
    outside.mkdir()
    dir_link(deploy / "sub", outside)
    monkeypatch.setattr(a, "_run_php", lambda *args, **kwargs: {})
    with pytest.raises(ValueError, match="link, junction"):
        a._bytecode_pass({"sub/a.php": b"<?php echo 'plaintext';"}, deploy, "php")
    assert list(outside.iterdir()) == []                 # nothing written through the link


# --- ENC-6: identity updates keep the replaced file's explicit ACL -----------------------------------

@windows_only
def test_enc6_write_store_keeps_explicit_aces_and_adds_no_operator(tmp_path):
    identity = tmp_path / "id.bin"
    owner = a.make_owner()
    a.secret_write(identity, a.add_recipient_to_store(None, a.make_recipient("r"), owner))
    me = a._current_user_sid_string()
    subprocess.run(["icacls", str(identity), "/inheritance:r", "/grant:r", "*S-1-5-18:F",
                    "/grant:r", "*S-1-5-32-544:F", "/grant:r", "*S-1-5-19:R", "/grant:r", f"*{me}:R"],
                   check=True, capture_output=True)
    before = windows_dacl(identity)
    data = a.set_developer(a.bounded_read(identity, a.IDENTITY_MAX_FILE),
                           a.developer_public(a.make_owner()))
    a.write_store(identity, data)
    assert windows_dacl(identity) == before              # LOCAL SERVICE kept, no operator FA added
    assert "(A;;FR;;;LS)" in before
    assert a.bounded_read(identity, a.IDENTITY_MAX_FILE) == data
    assert list(tmp_path.glob("*.tmp-*")) == []


# --- ENC-7: --vault-strings with member renaming -----------------------------------------------------

MEMBERS_BY_NAME = b'''<?php
class Report {
    private $label = 'L';
    private function helper(): string { return 'H'; }
    private function inner(): string { return 'I'; }
    public function run(): string {
        $cb = [$this, 'helper'];
        $seen = property_exists($this, 'label') ? $this->label : 'none';
        return $cb() . '|' . $seen . '|' . $this->inner();
    }
}
echo (new Report)->run();
'''


def _vaulted_plaintext(plain: bytes) -> tuple[list[bytes], bytes]:
    """Split the unencrypted vault layout (_vault_plaintext) into (table, source)."""
    size = int.from_bytes(plain[:4], "big")
    body, source = plain[4:4 + size], plain[4 + size:]
    count, off, table = int.from_bytes(body[:4], "big"), 4, []
    for _ in range(count):
        n = int.from_bytes(body[off:off + 4], "big")
        table.append(body[off + 4:off + 4 + n])
        off += 4 + n
    return table, source


@needs_php
def test_enc7_vault_with_obfuscated_members_keeps_behaviour(tmp_path, material, monkeypatch):
    """The renamers ran AFTER the vault, saw \\__envelock_lit(n) instead of 'helper'/'label', renamed
    members still used by name and broke the program. They must see the original literals."""
    monkeypatch.setattr(a, "_vault_plaintext_encrypted",
                        lambda table, source, key: a._vault_plaintext(table, source))
    src = source_tree(tmp_path, {"app.php": MEMBERS_BY_NAME})
    pack(material, src, tmp_path / "out", php=PHP, vault_strings=True, obfuscate_methods=True,
         obfuscate_properties=True)
    plain = a.open_protected((tmp_path / "out" / "app.php").read_bytes(), material[2])
    table, source = _vaulted_plaintext(plain)
    assert b"function inner" not in source               # renaming still happens where safe
    (tmp_path / "vaulted.php").write_bytes(source)
    boot = tmp_path / "boot.php"
    boot.write_bytes(b"<?php function __envelock_lit($i){ static $t=["
                     + b",".join(b'"' + base64.b64encode(s) + b'"' for s in table)
                     + b"]; return base64_decode($t[$i]); }\nrequire __DIR__ . '/vaulted.php';\n")
    run = subprocess.run([PHP, "-n", str(boot)], capture_output=True, text=True, timeout=60)
    assert (run.returncode, run.stdout) == (0, "H|L|I"), run.stdout + run.stderr


# --- ENC-8: verify reports linked folders and fails on unreadable ones -------------------------------

def _signed_manifest(pkg: Path, owner: dict) -> None:
    files = {"index.php": hashlib.sha256((pkg / "index.php").read_bytes()).hexdigest()}
    body = {"kind": "envelock-manifest", "project_id": str(uuid.uuid4()),
            "release_id": str(uuid.uuid4()), "serial": 1, "files": files}
    signer = a.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(owner["signing_private"]))
    body["signature"] = signer.sign(a.manifest_signed_bytes(body)).hex()
    (pkg / "envelock-manifest").write_text(json.dumps(body))


def test_enc8_verify_reports_a_linked_folder_as_added(tmp_path):
    owner = a.make_owner()
    pkg, elsewhere = tmp_path / "pkg", tmp_path / "elsewhere"
    pkg.mkdir()
    elsewhere.mkdir()                                     # empty: walking into it reports nothing
    (pkg / "index.php").write_text("<?php echo 1;")
    _signed_manifest(pkg, owner)
    assert a.verify_package(pkg, owner["signing_public"])["ok"] is True
    dir_link(pkg / "plugins", elsewhere)
    report = a.verify_package(pkg, owner["signing_public"])
    assert report["ok"] is False and "plugins" in report["added"], report


def test_enc8_verify_fails_on_an_unreadable_folder(tmp_path):
    owner = a.make_owner()
    pkg = tmp_path / "pkg"
    (pkg / "hidden").mkdir(parents=True)
    (pkg / "index.php").write_text("<?php echo 1;")
    (pkg / "hidden" / "added.php").write_text("<?php echo 2;")
    _signed_manifest(pkg, owner)
    if os.name == "nt":
        sid = a._current_user_sid_string()
        subprocess.run(["icacls", str(pkg / "hidden"), "/deny", f"*{sid}:(RD)"], check=True,
                       capture_output=True)
        undo = ["icacls", str(pkg / "hidden"), "/remove:d", f"*{sid}"]
    else:
        if os.geteuid() == 0:
            pytest.skip("root reads any folder")
        (pkg / "hidden").chmod(0)
        undo = None
    try:
        with pytest.raises(ValueError, match="cannot read"):
            a.verify_package(pkg, owner["signing_public"])
    finally:
        if undo:
            subprocess.run(undo, check=True, capture_output=True)
        else:
            (pkg / "hidden").chmod(0o755)


# --- ENC-9: the default serial is documented as nanoseconds ------------------------------------------

def test_enc9_serial_help_says_nanoseconds():
    result = run_cli("pack", "--help")
    assert result.returncode == 0
    assert "NANOSECONDS" in " ".join(result.stdout.split())


# --- ENC-10: --exclude/--asset patterns ----------------------------------------------------------------

@pytest.mark.parametrize("pattern", ["lib\\*", "lib\\secret.php"] + (["LIB/*"] if os.name == "nt" else []))
def test_enc10_exclude_patterns_with_backslashes_and_case(tmp_path, material, pattern):
    src = source_tree(tmp_path, {"main.php": b"<?php echo 1;", "lib/secret.php": b"<?php echo 2;"})
    info = pack(material, src, tmp_path / "out", exclude=[pattern])
    assert info["protected_files"] == 1
    assert not (tmp_path / "out" / "lib" / "secret.php").exists()


def test_enc10_asset_pattern_with_backslash(tmp_path, material):
    src = source_tree(tmp_path, {"main.php": b"<?php echo 1;", "css/site.css": b"body{}"})
    info = pack(material, src, tmp_path / "out", assets=["css\\*.css"])
    assert info["copied_assets"] == 1 and (tmp_path / "out" / "css" / "site.css").exists()


# --- ENC-11: the recovery key can live in its own file --------------------------------------------

def test_enc11_split_recovery_and_promote_from_the_separate_file():
    owner = a.make_owner(with_recovery=True)
    kept, recovery = a.split_recovery(owner)
    assert "recovery_private" not in kept and kept["recovery_public"] == owner["recovery_public"]
    assert recovery["signing_private"] == owner["recovery_private"]
    assert a.validate_config(kept, "envelock-owner") is kept
    # Servers still trust the recovery key: it stays in the public descriptor and the identity.
    assert a.developer_public(kept)["recovery_public"] == owner["recovery_public"]
    assert a.make_identity(a.make_recipient("r"), kept)["recovery_public"] == owner["recovery_public"]
    with pytest.raises(ValueError, match="--recovery"):
        a.promote_recovery(kept)
    with pytest.raises(ValueError, match="does not hold"):
        a.promote_recovery(kept, a.make_owner())
    promoted = a.promote_recovery(kept, recovery)
    assert promoted["signing_public"] == owner["recovery_public"]
    with pytest.raises(ValueError, match="no recovery private key"):
        a.split_recovery(kept)


def test_enc11_split_recovery_cli(tmp_path):
    owner, rec, promoted = tmp_path / "owner.json", tmp_path / "recovery.json", tmp_path / "o2.json"
    assert run_cli("keygen", "owner", "--out", owner, "--with-recovery", "--no-encrypt").returncode == 0
    before = json.loads(owner.read_text())
    result = run_cli("owner", "split-recovery", "--owner", owner, "--out", rec, "--no-encrypt")
    assert result.returncode == 0, result.stderr
    after = json.loads(owner.read_text())
    assert "recovery_private" not in after and after["recovery_public"] == before["recovery_public"]
    assert json.loads(rec.read_text())["signing_private"] == before["recovery_private"]
    result = run_cli("owner", "promote-recovery", "--owner", owner, "--recovery", rec, "--out",
                     promoted, "--no-encrypt")
    assert result.returncode == 0, result.stderr
    assert json.loads(promoted.read_text())["signing_public"] == before["recovery_public"]


# --- ENC-12: the package root is 0755 under the CLI's umask -------------------------------------------

@posix_only
def test_enc12_package_root_traversable_under_umask_077(tmp_path, material):
    src = source_tree(tmp_path, {"main.php": b"<?php echo 1;"})
    old = os.umask(0o077)
    try:
        pack(material, src, tmp_path / "out")
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(tmp_path / "out").st_mode) == 0o755


# --- ENC-14: small-order Ed25519 keys are never trusted ------------------------------------------------

SMALL_ORDER = [
    "01" + "00" * 31,                                                    # identity
    "ec" + "ff" * 30 + "7f",                                             # order 2 (y = -1)
    "00" * 32,                                                           # order 4 (y = 0)
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",  # order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",  # order 8
    # non-canonical spellings of the same points: sign bit set, y + p
    "01" + "00" * 30 + "80",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "ed" + "ff" * 30 + "7f",                                             # p     == 0
    "ee" + "ff" * 30 + "7f",                                             # p + 1 == 1
]


@pytest.mark.parametrize("weak", SMALL_ORDER)
def test_enc14_small_order_signing_keys_refused(weak):
    assert a.ed25519_small_order(bytes.fromhex(weak))
    developer = {"kind": "envelock-developer-public", "format": a.FORMAT_VERSION, "signing_public": weak}
    with pytest.raises(ValueError, match="small-order"):
        a.validate_config(developer, "envelock-developer-public")
    store = a.add_recipient_to_store(None, a.make_recipient("r"), a.make_owner())
    with pytest.raises(ValueError, match="small-order"):
        a.set_developer(store, developer)
    real = a.developer_public(a.make_owner())
    with pytest.raises(ValueError, match="small-order"):
        a.validate_config(dict(real, recovery_public=weak), "envelock-developer-public")
    owner = a.make_owner()
    with pytest.raises(ValueError, match="small-order"):
        a.validate_config(dict(owner, recovery_public=weak), "envelock-owner")
    identity = a.make_identity(a.make_recipient("r"), owner)
    with pytest.raises(ValueError, match="small-order"):
        a.validate_config(dict(identity, signing_public=weak), "envelock-identity")


def test_enc14_real_keys_are_not_small_order():
    for _ in range(20):
        assert not a.ed25519_small_order(bytes.fromhex(a.make_owner()["signing_public"]))


# --- ENC-15: developer credential stores never ship -----------------------------------------------

def test_enc15_credential_dotfiles_are_excluded(tmp_path, material):
    src = source_tree(tmp_path, {
        "main.php": b"<?php echo 1;",
        ".npmrc": b"//registry.npmjs.org/:_authToken=npm_secret\n",
        ".netrc": b"machine example.com login u password p\n",
        ".git-credentials": b"https://user:token@example.com\n",
        ".pgpass": b"localhost:5432:db:user:secret\n",
        ".docker/config.json": b'{"auths": {"r.example": {"auth": "dXNlcjpwYXNz"}}}',
    })
    pack(material, src, tmp_path / "out", assets=["*", ".docker/*"])
    shipped = {p.relative_to(tmp_path / "out").as_posix() for p in (tmp_path / "out").rglob("*")}
    assert not {".npmrc", ".netrc", ".git-credentials", ".pgpass", ".docker"} & shipped, shipped


@pytest.mark.parametrize("name,data", [
    ("npm.cfg", b"//registry.npmjs.org/:_authToken=npm_0123456789\n"),
    ("legacy.cfg", b"_auth=dXNlcjpwYXNz\n"),
    ("registry.json", b'{"auths": {"r.example": {"auth": "dXNlcjpwYXNz"}}}'),
    ("logins.txt", b"machine example.com\n  login u\n  password p\n"),
    ("creds.txt", b"https://user:ghp_token@example.com\n"),
    ("db.txt", b"mysql://app:hunter2@example.com/prod\n"),
])
def test_enc15_renamed_credentials_detected_by_content(tmp_path, material, name, data):
    src = source_tree(tmp_path, {"main.php": b"<?php echo 1;", name: data})
    with pytest.raises(ValueError, match="credential"):
        pack(material, src, tmp_path / "out", assets=[name])


def test_enc15_pgpass_conf_name_refused(tmp_path, material):
    src = source_tree(tmp_path, {"main.php": b"<?php echo 1;", "pgpass.conf": b"h:1:d:u:p\n"})
    with pytest.raises(ValueError, match="private asset"):
        pack(material, src, tmp_path / "out", assets=["*.conf"])


# --- ENC-16: php -l reads the transformed source from STDIN -----------------------------------------

@needs_php
def test_enc16_lint_writes_no_temporary_file(monkeypatch):
    def no_temp(*args, **kwargs):
        raise AssertionError("plaintext written to a temporary file")
    monkeypatch.setattr(a.tempfile, "NamedTemporaryFile", no_temp)
    monkeypatch.setattr(a.tempfile, "mkstemp", no_temp)
    assert a._php_lint_error_line(PHP, b"<?php echo 1;\n") is None
    assert a._php_lint_error_line(PHP, b"<?php\n\nfunction f() { return 1 }\n") == 3
    assert a._php_lint_error_line(PHP, b"<?php\nclass A { public $x = \\strlen('ab'); }\n") == 2


# --- ENC-17: demo recipient refused in any spelling ---------------------------------------------------

@pytest.mark.parametrize("spelling", ["upper", "top-bit"])
def test_enc17_demo_recipient_refused_in_any_encoding(tmp_path, material, spelling):
    raw = bytearray.fromhex(a.DEMO_X25519_PUBLIC)
    if spelling == "upper":
        key = a.DEMO_X25519_PUBLIC.upper()
    else:
        raw[31] |= 0x80                                  # bit 255: ignored by X25519
        key = raw.hex()
    recipient = {"kind": "envelock-recipient-public", "format": a.FORMAT_VERSION, "label": "x",
                 "x25519_public": key}
    src = source_tree(tmp_path, {"main.php": b"<?php echo 1;"})
    with pytest.raises(ValueError, match="demo recipient"):
        a.pack_tree(src, tmp_path / "out", [recipient], material[0], str(uuid.uuid4()))


# --- ENC-18: licence domain canonicalised exactly like the loader -----------------------------------

def _loader_domain_hash(name: bytes) -> bytes:
    return hashlib.sha256(b"envelock-domain-1\n" + name).digest()


@pytest.mark.parametrize("given,loader_sees", [
    ("[::1", b"[::1"),                          # unclosed bracket: kept whole (was "[")
    ("[::1]:8443", b"::1"),
    (" \tExample.COM:8080\r\n", b"example.com"),
    ("example.com.", b"example.com."),          # the loader keeps a trailing dot
    ("Bücher.Example", b"xn--bcher-kva.example"),   # IDN -> punycode (what SERVER_NAME holds)
])
def test_enc18_domain_hash_matches_the_loader(given, loader_sees):
    assert a.domain_hash(given) == _loader_domain_hash(loader_sees)


def test_enc18_domain_edge_cases():
    # ASCII-only lowercasing and trimming, like the C side: no Unicode case folding of ASCII text.
    assert a.domain_hash("example.com") != a.domain_hash("example.com.")
    with pytest.raises(ValueError):
        a.domain_hash("   ")
    with pytest.raises(ValueError, match="longer"):
        a.domain_hash("a" * 300)


def test_enc18_bound_licence_warns_about_windows_and_this(tmp_path, material):
    owner, _, _ = keyfiles(tmp_path, material)
    result = run_cli("licence", "issue", "--owner", owner, "--out", tmp_path / "l.bin",
                     "--domain", "app.example.com")
    assert result.returncode == 0, result.stderr
    assert "Windows" in result.stderr and "REFUSE" in result.stderr
    result = run_cli("licence", "issue", "--owner", owner, "--out", tmp_path / "l2.bin", "--domain", "this")
    assert result.returncode == 0, result.stderr
    assert "SERVER_NAME" in result.stderr
    plain = run_cli("licence", "issue", "--owner", owner, "--out", tmp_path / "l3.bin", "--days", "5")
    assert plain.returncode == 0 and "Windows" not in plain.stderr


# --- ENC-19: fingerprints use ALL entries, sorted, with the loader's limits -------------------------

def _fake_net(monkeypatch, machine_id, macs):
    """Fake /sys/class/net with one device-backed interface per MAC, enumerated in reverse order."""
    names = [f"eth{i}" for i in range(len(macs))]
    files = {f"/sys/class/net/{n}/address": m.encode() for n, m in zip(names, macs)}
    files["/etc/machine-id"] = machine_id
    real_listdir, real_exists = os.listdir, os.path.exists
    monkeypatch.setattr(a.os, "listdir", lambda path: list(reversed(names))
                        if path == "/sys/class/net" else real_listdir(path))
    monkeypatch.setattr(a.os.path, "exists", lambda path: str(path).endswith("/device")
                        if str(path).startswith("/sys/class/net/") else real_exists(path))
    monkeypatch.setattr(a, "_read_small", lambda path: files.get(path))


def test_enc19_machine_fingerprint_all_sorted_and_limits(monkeypatch):
    mid = b"0123456789abcdef0123456789abcdef"
    macs = [f"02:00:00:00:{i // 256:02x}:{i % 256:02X}" for i in range(224)]   # A-F uppercase too
    _fake_net(monkeypatch, mid, macs)
    expected = hashlib.sha256(b"envelock-machine-1\n" + mid + b"".join(
        b"\n" + m.lower().encode() for m in sorted(m.lower() for m in macs))).digest()
    assert a.machine_fingerprint() == expected            # 18 + 33 + 224*18 = 4083 < 4096
    _fake_net(monkeypatch, mid, macs + ["02:00:00:00:ff:ff"])
    with pytest.raises(ValueError, match="too many network interfaces/addresses"):
        a.machine_fingerprint()                           # 4101 >= 4096: the loader refuses
    _fake_net(monkeypatch, b"", [f"02:00:00:01:{i // 256:02x}:{i % 256:02x}" for i in range(257)])
    with pytest.raises(ValueError, match="too many network interfaces/addresses"):
        a.machine_fingerprint()                           # more than 256 MACs


def test_enc19_ip_fingerprint_all_sorted_and_limits(monkeypatch):
    ips = [f"10.0.{i // 250}.{i % 250 + 1}" for i in range(40)]
    monkeypatch.setattr(a, "host_ipv4_addresses", lambda: list(reversed(ips)))
    expected = hashlib.sha256(b"envelock-ip-1" + b"".join(
        b"\n" + ip.encode() for ip in sorted(ips))).digest()
    assert a.host_ips_hash() == expected
    wide = [f"255.255.{200 + i // 150}.{100 + i % 150}" for i in range(255)]    # 15 chars each
    assert {len(ip) for ip in wide} == {15} and len(set(wide)) == 255
    monkeypatch.setattr(a, "host_ipv4_addresses", lambda: wide)
    assert len(a.host_ips_hash()) == 32                    # 13 + 255*16 = 4093 < 4096
    monkeypatch.setattr(a, "host_ipv4_addresses", lambda: wide + ["255.255.254.254"])
    with pytest.raises(ValueError, match="too many network interfaces/addresses"):
        a.host_ips_hash()                                  # 4109 >= 4096
    monkeypatch.setattr(a, "host_ipv4_addresses", lambda: [f"10.{i // 250}.0.{i % 250}" for i in range(257)])
    with pytest.raises(ValueError, match="too many network interfaces/addresses"):
        a.host_ips_hash()


# --- ENC-21: the php programs travel on STDIN, not the command line ---------------------------------

@needs_php
def test_enc21_program_not_on_the_command_line(monkeypatch):
    real_run, seen = subprocess.run, []

    def spy(args, **kwargs):
        seen.append((args, kwargs.get("input")))
        return real_run(args, **kwargs)

    monkeypatch.setattr(a.subprocess, "run", spy)
    out, _ = a.transform_sources({"x.php": b"<?php\n$a = 1; // c\necho $a;\n"}, PHP, strip=True,
                                 obfuscate=True)
    assert b"// c" not in out["x.php"]
    args, stdin = seen[0]
    assert sum(len(arg) for arg in args) < 2000, "the program is on the command line"
    assert a.TRANSFORM_PHP.encode() in stdin


# --- ENC-22/26: --virtualize compiler path quoting and memory limit -------------------------------

@needs_php
def test_enc22_virtualize_path_with_dollar_quote_and_accent(tmp_path, monkeypatch):
    folder = tmp_path / "dir $HOME é'q"
    folder.mkdir()
    compiler = folder / "virtualize.php"
    compiler.write_text('<?php\n$in = json_decode(stream_get_contents(STDIN), true);\n'
                        'echo json_encode(["files" => $in["files"], "programs" => '
                        '["memory_limit" => ini_get("memory_limit"), "file" => __FILE__]]);\n',
                        encoding="utf-8")
    monkeypatch.setattr(a, "_virtualize_php_path", lambda: compiler)
    files, programs = a.virtualize_sources({"x.php": b"<?php echo 1;"}, ["f"], PHP)
    assert files == {"x.php": b"<?php echo 1;"}
    assert os.path.normcase(programs["file"]) == os.path.normcase(str(compiler))
    assert programs["memory_limit"] == "-1"               # ENC-26: a build step, no 128M cap


# --- ENC-23: options that used to be ignored --------------------------------------------------------

def test_enc23_bytecode_options_without_bytecode_refused(tmp_path, material):
    src = source_tree(tmp_path, {"main.php": b"<?php echo 1;"})
    for option in ({"deploy_root": tmp_path / "deploy"}, {"bytecode_php": "php"},
                   {"bytecode_loader": "envelock.so"}):
        with pytest.raises(ValueError, match="only apply with --bytecode"):
            pack(material, src, tmp_path / "out", **option)
    assert not (tmp_path / "out").exists()


def test_enc23_cli_refuses_ignored_or_contradictory_options(tmp_path, material):
    owner, recipient, public = keyfiles(tmp_path, material)
    src = source_tree(tmp_path, {"main.php": b"<?php echo 1;"})
    result = run_cli("pack", "--owner", owner, "--recipient", public, "--project", uuid.uuid4(),
                     "--source", src, "--output", tmp_path / "out", "--deploy-root", tmp_path / "d")
    assert result.returncode == 1 and "only apply with --bytecode" in result.stderr
    identity = tmp_path / "id.bin"
    identity.write_bytes(a.add_recipient_to_store(None, material[1], material[0]))
    pack(material, src, tmp_path / "pkg", serial=10)
    result = run_cli("minimum", "set", "--identity", identity, "--package", tmp_path / "pkg",
                     "--serial", "99")
    assert result.returncode == 1 and "--serial goes with --project" in result.stderr
    result = run_cli("licence", "issue", "--owner", owner, "--out", tmp_path / "l.bin",
                     "--expires", "2001-01-01")
    assert result.returncode == 1 and "in the past" in result.stderr
    assert not (tmp_path / "l.bin").exists()


# --- ENC-25: pruned walk, collisions ----------------------------------------------------------------

def test_enc25_excluded_folders_are_never_walked(tmp_path, material, monkeypatch):
    """rglob walked node_modules (and followed the junctions inside) before the filter ran; a looping
    junction there made the walk explode. Excluded folders are pruned now."""
    src = source_tree(tmp_path, {"main.php": b"<?php echo 1;", "node_modules/pkg/x.js": b"x"})
    dir_link(src / "node_modules" / "loop1", src)
    dir_link(src / "node_modules" / "loop2", src)
    real_scandir, scanned = os.scandir, []

    def spy(path="."):
        scanned.append(Path(os.fspath(path)))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", spy)
    info = pack(material, src, tmp_path / "out")
    assert info["protected_files"] == 1
    assert not any("node_modules" in p.parts for p in scanned), scanned


def test_enc25_link_loop_outside_excluded_folders_is_refused(tmp_path, material):
    src = source_tree(tmp_path, {"main.php": b"<?php echo 1;"})
    (src / "lib").mkdir()
    dir_link(src / "lib" / "again", src)
    with pytest.raises(ValueError, match="(Link or junction|Symbolic link)"):
        pack(material, src, tmp_path / "out")


def test_enc25_excluded_folder_pattern_prunes_its_content(tmp_path, material):
    src = source_tree(tmp_path, {"main.php": b"<?php echo 1;", "private/x.php": b"<?php echo 2;"})
    info = pack(material, src, tmp_path / "out", exclude=["private"])
    assert info["protected_files"] == 1 and not (tmp_path / "out" / "private").exists()


def test_enc25_file_versus_folder_case_collision(tmp_path, material):
    files = {"main.php": b"<?php echo 1;", "lib/x.php": b"<?php echo 2;"}
    if os.name == "nt":
        pytest.skip("this file system cannot hold both 'Lib' and 'lib'")
    src = source_tree(tmp_path, files)
    (src / "LIB").write_text("not a folder")
    with pytest.raises(ValueError, match="collision"):
        pack(material, src, tmp_path / "out", assets=["LIB"])


@pytest.mark.parametrize("first,second", [("lib/x.php", "LIB"), ("Lib", "lib/x.php"),
                                          ("a/B/c.php", "a/b"), ("x.php", "X.PHP")])
def test_enc25_file_versus_folder_collision(first, second):
    """pack_tree's check, independent of the file system (this one may not hold both names)."""
    names, folders = set(), set()
    assert not a._claim_portable_name(a.validate_portable_path(Path(first)), names, folders)
    assert a._claim_portable_name(a.validate_portable_path(Path(second)), names, folders)
    names, folders = set(), set()
    assert not a._claim_portable_name(a.validate_portable_path(Path("lib/x.php")), names, folders)
    assert not a._claim_portable_name(a.validate_portable_path(Path("lib/y.php")), names, folders)

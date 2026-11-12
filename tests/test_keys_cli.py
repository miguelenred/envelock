"""Private keys encrypted by default, and key rotation (recovery key, trusted developers)."""

import json
import os
import subprocess
import sys
import uuid

import pytest
from test_encoder import ROOT, a

ENCODER = str(ROOT / "encoder/envelock.py")


@pytest.fixture
def cli(tmp_path):
    """Run the encoder CLI non-interactively, with a 0600 password file."""
    password = tmp_path / "password.txt"
    # secret_write: 0600 on POSIX, an owner-only protected ACL on Windows, where the encoder now
    # checks the password file's ACL (ENC-24) and an inherited temp-folder ACL may not pass.
    a.secret_write(password, os.urandom(24).hex().encode())

    def run(*argv, use_password=True):
        env = dict(os.environ)
        env.pop("ENVELOCK_PASSWORD_FILE", None)
        if use_password:
            env["ENVELOCK_PASSWORD_FILE"] = str(password)
        return subprocess.run([sys.executable, ENCODER, *map(str, argv)], capture_output=True,
                              text=True, stdin=subprocess.DEVNULL, env=env)

    run.password = password.read_text().encode()
    return run


# --- Private keys encrypted by default ---

@pytest.mark.parametrize("argv", [["init-owner"], ["init-recipient", "--label", "c1"],
                                  ["keygen", "owner"], ["keygen", "recipient", "--label", "c1"]])
def test_private_keys_encrypted_by_default(cli, tmp_path, argv):
    out = tmp_path / "key.json"
    result = cli(*argv, "--out", out)
    assert result.returncode == 0, result.stderr
    stored = json.loads(out.read_text())
    assert stored["kind"] == "envelock-encrypted"
    assert "private" not in out.read_text()
    kind = "envelock-owner" if any("owner" in x for x in argv) else "envelock-recipient"
    assert a.read_config(out, kind, cli.password)["kind"] == kind


def test_no_encrypt_is_explicit_and_warns(cli, tmp_path):
    out = tmp_path / "plain.json"
    result = cli("keygen", "owner", "--out", out, "--no-encrypt", use_password=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(out.read_text())["kind"] == "envelock-owner"
    assert "WARNING" in result.stderr and "unencrypted" in result.stderr


def test_keygen_without_password_source_fails_closed(cli, tmp_path):
    """No terminal, no ENVELOCK_PASSWORD_FILE and no --no-encrypt: refuse, write nothing."""
    out = tmp_path / "never.json"
    result = cli("keygen", "owner", "--out", out, use_password=False)
    assert result.returncode == 1
    assert not out.exists()


def test_stdin_is_console_treats_errors_as_no_console(monkeypatch):
    """A2/A3 fail-closed: if the console check raises it must report no console,
    never let the password prompt run on a non-interactive handle."""
    class _Bad:
        def isatty(self):
            raise OSError("not a real tty")
    monkeypatch.setattr(a.sys, "stdin", _Bad())
    monkeypatch.setattr(a.os, "name", "posix")
    assert a._stdin_is_console() is False


# --- Rotation: functions ---

def test_new_recovery_replaces_only_the_recovery_key():
    owner = a.make_owner(with_recovery=True)
    rotated = a.new_recovery(owner)
    assert rotated["signing_private"] == owner["signing_private"]
    assert rotated["recovery_public"] != owner["recovery_public"]
    a.validate_config(rotated, "envelock-owner")
    assert "recovery_public" in a.new_recovery(a.make_owner())  # adds one when missing


def test_promote_recovery_makes_recovery_the_primary():
    owner = a.make_owner(with_recovery=True)
    promoted = a.promote_recovery(owner)
    assert promoted["signing_private"] == owner["recovery_private"]
    assert promoted["signing_public"] == owner["recovery_public"]
    assert promoted["recovery_public"] not in (owner["recovery_public"], owner["signing_public"])
    a.validate_config(promoted, "envelock-owner")
    with pytest.raises(ValueError, match="no recovery key"):
        a.promote_recovery(a.make_owner())


def test_developer_public_has_no_private_material():
    owner = a.make_owner(with_recovery=True)
    developer = a.developer_public(owner)
    assert developer["kind"] == "envelock-developer-public"
    assert "private" not in json.dumps(developer)
    assert a.validate_config(developer, "envelock-developer-public") == developer


def _store_with(owner):
    return a.add_recipient_to_store(None, a.make_recipient("r"), owner)


def test_developer_set_updates_recovery_and_adds_new_developers():
    owner = a.make_owner(with_recovery=True)
    store = _store_with(owner)
    rotated = a.new_recovery(owner)
    _, developers = a.parse_identity_store(a.set_developer(store, a.developer_public(rotated)))
    assert len(developers) == 1
    assert developers[0][32:].hex() == rotated["recovery_public"]   # replaced, not appended
    other = a.make_owner()
    _, developers = a.parse_identity_store(a.set_developer(store, a.developer_public(other)))
    assert len(developers) == 2 and developers[1][32:] == a.ZERO32


def test_developer_remove():
    first, second = a.make_owner(), a.make_owner()
    store = a.set_developer(_store_with(first), a.developer_public(second))
    remaining = a.remove_developer(store, a.developer_id(first["signing_public"]))
    _, developers = a.parse_identity_store(remaining)
    assert [d[:32].hex() for d in developers] == [second["signing_public"]]
    with pytest.raises(ValueError, match="not in the identity file"):
        a.remove_developer(remaining, a.developer_id(first["signing_public"]))
    with pytest.raises(ValueError, match="last trusted developer"):
        a.remove_developer(remaining, a.developer_id(second["signing_public"]))


def test_developer_remove_purges_that_developers_minimums(tmp_path):
    """Removing a developer must drop its per-project minimums too (ENV-2026-33): left behind they sit
    as orphans forever consuming MAX_MINIMUMS slots and bind nobody. A co-developer's minimum on the
    same project must survive untouched."""
    import uuid
    first, second = a.make_owner(), a.make_owner()
    store = a.set_developer(_store_with(first), a.developer_public(second))
    first_pub = bytes.fromhex(first["signing_public"])
    second_pub = bytes.fromhex(second["signing_public"])
    project = str(uuid.uuid4())
    store = a.set_minimum(store, project, 5, developer_pub=first_pub)
    store = a.set_minimum(store, project, 7, developer_pub=second_pub)   # same project, other dev
    assert len(a.identity_minimums(store)) == 2

    pruned = a.remove_developer(store, a.developer_id(first["signing_public"]))
    mins = a.identity_minimums(pruned)
    assert (uuid.UUID(project).bytes, first_pub) not in mins             # orphan purged
    assert mins == {(uuid.UUID(project).bytes, second_pub): 7}          # co-developer's survives


# --- Rotation: CLI end to end ---

def test_cli_rotation_flow(cli, tmp_path):
    owner, recipient, identity = tmp_path / "owner.json", tmp_path / "r.json", tmp_path / "id.bin"
    assert cli("keygen", "owner", "--out", owner, "--with-recovery").returncode == 0
    assert cli("keygen", "recipient", "--out", recipient, "--label", "c1").returncode == 0
    assert cli("recipient", "add", "--identity", identity, "--recipient", recipient,
               "--owner", owner).returncode == 0
    before = a.read_config(owner, "envelock-owner", cli.password)

    # Replace the recovery key in place: the file stays encrypted with the same password.
    result = cli("owner", "new-recovery", "--owner", owner)
    assert result.returncode == 0, result.stderr
    assert json.loads(owner.read_text())["kind"] == "envelock-encrypted"
    after = a.read_config(owner, "envelock-owner", cli.password)
    assert after["signing_public"] == before["signing_public"]
    assert after["recovery_public"] != before["recovery_public"]

    developer = tmp_path / "developer.json"
    assert cli("export-developer", "--owner", owner, "--out", developer).returncode == 0
    assert "private" not in developer.read_text()
    result = cli("developer", "set", "--identity", identity, "--developer", developer)
    assert result.returncode == 0, result.stderr
    _, developers = a.parse_identity_store(identity.read_bytes())
    assert developers[0][32:].hex() == after["recovery_public"]
    if os.name != "nt":
        assert identity.stat().st_mode & 0o777 == 0o600

    # Promote the recovery key (primary compromised).
    promoted = tmp_path / "owner-2.json"
    result = cli("owner", "promote-recovery", "--owner", owner, "--out", promoted)
    assert result.returncode == 0, result.stderr
    new = a.read_config(promoted, "envelock-owner", cli.password)
    assert new["signing_public"] == after["recovery_public"]

    # Remove the old developer; removing the last one is refused.
    old_id = a.developer_id(before["signing_public"])
    result = cli("developer", "remove", "--identity", identity, "--developer-id", old_id)
    assert result.returncode == 1 and "last trusted developer" in result.stderr
    developer2 = tmp_path / "developer-2.json"
    assert cli("export-developer", "--owner", promoted, "--out", developer2).returncode == 0
    assert cli("developer", "set", "--identity", identity, "--developer", developer2).returncode == 0
    result = cli("developer", "remove", "--identity", identity, "--developer-id", old_id)
    assert result.returncode == 0, result.stderr
    info = json.loads(cli("inspect", identity).stdout)
    assert [d["developer_id"] for d in info["developers"]] == [a.developer_id(new["signing_public"])]


# --- Review fixes ---

def test_new_recovery_on_plain_owner_encrypts_unless_no_encrypt(cli, tmp_path):
    """An unencrypted owner must not get a new private key written in clear silently."""
    owner = tmp_path / "plain-owner.json"
    assert cli("keygen", "owner", "--out", owner, "--no-encrypt", use_password=False).returncode == 0
    result = cli("owner", "new-recovery", "--owner", owner)
    assert result.returncode == 0, result.stderr
    assert json.loads(owner.read_text())["kind"] == "envelock-encrypted"
    assert "recovery_private" in a.read_config(owner, "envelock-owner", cli.password)
    plain = tmp_path / "plain-owner-2.json"
    assert cli("keygen", "owner", "--out", plain, "--no-encrypt", use_password=False).returncode == 0
    result = cli("owner", "new-recovery", "--owner", plain, "--no-encrypt", use_password=False)
    assert result.returncode == 0 and "WARNING" in result.stderr
    assert json.loads(plain.read_text())["kind"] == "envelock-owner"


def test_recipient_add_refuses_a_different_recovery_key():
    owner = a.make_owner(with_recovery=True)
    store = a.add_recipient_to_store(None, a.make_recipient("r1"), owner)
    with pytest.raises(ValueError, match="different recovery key"):
        a.add_recipient_to_store(store, a.make_recipient("r2"), a.new_recovery(owner))


def test_developer_set_needs_explicit_flag_to_remove_a_recovery():
    owner = a.make_owner(with_recovery=True)
    store = a.add_recipient_to_store(None, a.make_recipient("r"), owner)
    without = dict(a.developer_public(owner))
    without.pop("recovery_public")
    with pytest.raises(ValueError, match="--remove-recovery"):
        a.set_developer(store, without)
    _, developers = a.parse_identity_store(a.set_developer(store, without, remove_recovery=True))
    assert developers[0][32:] == a.ZERO32


def test_inspect_shows_trusted_recovery_public(tmp_path):
    owner = a.make_owner(with_recovery=True)
    identity = tmp_path / "id.bin"
    identity.write_bytes(a.add_recipient_to_store(None, a.make_recipient("r"), owner))
    info = a.inspect_path(identity)
    assert info["developers"][0]["recovery_public"] == owner["recovery_public"]


def test_bundle_refuses_same_developer_with_two_recovery_keys():
    owner = a.make_owner(with_recovery=True)
    first = a.make_identity(a.make_recipient("r1"), owner)
    second = a.make_identity(a.make_recipient("r2"), a.new_recovery(owner))
    with pytest.raises(ValueError, match="different recovery keys"):
        a.identity_bundle_bytes([first, second])


def test_recipient_remove():
    owner = a.make_owner()
    r1, r2 = a.make_recipient("r1"), a.make_recipient("r2")
    store = a.add_recipient_to_store(a.add_recipient_to_store(None, r1, owner), r2, owner)
    remaining = a.remove_recipient(store, r1["x25519_public"])
    recipients, _ = a.parse_identity_store(remaining)
    assert [r[32:].hex() for r in recipients] == [r2["x25519_public"]]
    with pytest.raises(ValueError, match="not in the identity file"):
        a.remove_recipient(remaining, r1["x25519_public"])
    with pytest.raises(ValueError, match="last recipient"):
        a.remove_recipient(remaining, r2["x25519_public"])


def test_cli_identity_changes_remind_to_restart_php(cli, tmp_path):
    """The loader reads the identity file at startup: every change needs a PHP restart."""
    owner, r1, r2 = tmp_path / "o.json", tmp_path / "r1.json", tmp_path / "r2.json"
    identity, public = tmp_path / "id.bin", tmp_path / "r1.pub.json"
    for argv in (["keygen", "owner", "--out", owner, "--with-recovery"],
                 ["keygen", "recipient", "--out", r1, "--label", "a"],
                 ["keygen", "recipient", "--out", r2, "--label", "b"],
                 ["export-public", "--recipient", r1, "--out", public]):
        assert cli(*argv).returncode == 0
    developer = tmp_path / "dev.json"
    assert cli("export-developer", "--owner", owner, "--out", developer).returncode == 0
    for argv in (["export-identity", "--recipient", r1, "--owner", owner, "--out", tmp_path / "x.bin"],
                 ["recipient", "add", "--identity", identity, "--recipient", r1, "--owner", owner],
                 ["recipient", "add", "--identity", identity, "--recipient", r2, "--owner", owner],
                 ["developer", "set", "--identity", identity, "--developer", developer],
                 ["recipient", "remove", "--identity", identity, "--recipient", public]):
        result = cli(*argv)
        assert result.returncode == 0, (argv, result.stderr)
        assert "Restart PHP" in result.stdout, argv
    recipients, _ = a.parse_identity_store(identity.read_bytes())
    assert len(recipients) == 1


def _get_acl(path, field):
    """Owner or Sddl of path through PowerShell's Get-Acl: an ACL reader independent of the
    encoder's own ctypes code. SIDs, not account names, so it works in any display language."""
    return subprocess.check_output(
        ["powershell", "-NoProfile", "-Command", f"(Get-Acl -LiteralPath '{path}').{field}"],
        text=True).strip()


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL preservation")
def test_cli_identity_update_keeps_windows_acl(cli, tmp_path):
    """A2 + ENC-6: updating an identity whose DACL does NOT grant the current user DELETE must still
    succeed (os.replace needs DELETE on the source), keep the owner, and end with EXACTLY the explicit
    access entries the administrator gave it: the PHP service account's read entry (here NETWORK
    SERVICE) survives, nothing is inherited, and the operator is NOT added (the loader accepts only
    the service account, SYSTEM and Administrators). Before ENC-6 the DACL was rebuilt as SY:F BA:F
    <operator>:F, dropping the service account and adding the operator."""
    owner, r1, identity = tmp_path / "o.json", tmp_path / "r1.json", tmp_path / "id.bin"
    assert cli("keygen", "owner", "--out", owner).returncode == 0
    assert cli("keygen", "recipient", "--out", r1, "--label", "a").returncode == 0
    assert cli("recipient", "add", "--identity", identity, "--recipient", r1, "--owner", owner).returncode == 0
    # The documented server layout (MANUAL section 11), by SID: SYSTEM and Administrators full, the
    # service account (S-1-5-20) read. The current user keeps READ only (it must read the file to
    # update it) and so has no DELETE on it. Set as the file's owner, which keeps WRITE_DAC.
    me = a._current_user_sid_string()
    subprocess.run(["icacls", str(identity), "/inheritance:r", "/grant:r", "*S-1-5-18:F",
                    "/grant:r", "*S-1-5-32-544:F", "/grant:r", "*S-1-5-20:R", "/grant:r", f"*{me}:R"],
                   check=True, capture_output=True)
    owner_before, sddl_before = _get_acl(identity, "Owner"), _get_acl(identity, "Sddl")
    developer = tmp_path / "dev.json"
    assert cli("export-developer", "--owner", owner, "--out", developer).returncode == 0
    result = cli("developer", "set", "--identity", identity, "--developer", developer)
    assert result.returncode == 0, result.stderr   # A2: no WinError 5
    sddl = _get_acl(identity, "Sddl")
    dacl = sddl[sddl.index("D:"):]
    assert dacl.startswith("D:P"), dacl                       # protected, nothing inherited
    assert ";ID;" not in dacl, dacl
    assert "(A;;FR;;;NS)" in dacl, dacl                       # the service account's read survives
    assert f"(A;;FR;;;{me})" in dacl and f"(A;;FA;;;{me})" not in dacl, dacl   # operator NOT added
    assert dacl == sddl_before[sddl_before.index("D:"):]      # exactly the previous explicit entries
    assert _get_acl(identity, "Owner") == owner_before
    assert list(tmp_path.glob("id.bin.tmp-*")) == []           # no temporary left behind
    _, developers = a.parse_identity_store(identity.read_bytes())   # still readable, still valid
    assert len(developers) == 1


def test_minimum_set_from_signed_package_and_downgrade_guard(cli, tmp_path):
    """ENV-09 end to end: 'minimum set --package' sets the serial from the signed header, and
    lowering a minimum is refused unless --allow-downgrade is given."""
    owner = a.make_owner()
    recipient = a.make_recipient("r")
    store = tmp_path / "identity.store"
    store.write_bytes(a.add_recipient_to_store(None, recipient, owner))
    project = str(uuid.uuid4())
    src = tmp_path / "src"
    src.mkdir()
    (src / "index.php").write_text("<?php echo 1;", encoding="utf-8")
    a.pack_tree(src, tmp_path / "pkg", [a.recipient_public(recipient)], owner, project, serial=300)

    ok = cli("minimum", "set", "--identity", store, "--package", tmp_path / "pkg", use_password=False)
    assert ok.returncode == 0, ok.stderr
    dev = bytes.fromhex(owner["signing_public"])
    pid = uuid.UUID(project).bytes
    assert a.identity_minimums(store.read_bytes())[(pid, dev)] == 300   # bound to the signer (ENV-AUD-14)

    # An unbound admin minimum for the same project is an INDEPENDENT entry (ENV-03): it neither
    # touches the developer-bound one nor trips the downgrade guard when first created.
    up = cli("minimum", "set", "--identity", store, "--project", project, "--serial", "400",
             use_password=False)
    assert up.returncode == 0, up.stderr
    mins = a.identity_minimums(store.read_bytes())
    assert mins[(pid, dev)] == 300 and mins[(pid, a.ZERO32)] == 400     # both kept, independent

    # Lowering the SAME (unbound) entry is refused unless --allow-downgrade; the bound one is untouched.
    low = cli("minimum", "set", "--identity", store, "--project", project, "--serial", "100",
              use_password=False)
    assert low.returncode != 0 and "lower the minimum" in low.stderr
    forced = cli("minimum", "set", "--identity", store, "--project", project, "--serial", "100",
                 "--allow-downgrade", use_password=False)
    assert forced.returncode == 0, forced.stderr
    mins = a.identity_minimums(store.read_bytes())
    assert mins[(pid, a.ZERO32)] == 100 and mins[(pid, dev)] == 300

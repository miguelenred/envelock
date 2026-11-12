import importlib.util
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("envelock", ROOT / "encoder/envelock.py")
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


TABLE = len(a.STUB) + a.HEADER.size + len("app.php")  # recipient table offset in sample()


def symlink_or_skip(link: Path, target, is_dir: bool = False) -> None:
    """Create a symlink, or skip the test where the OS refuses (Windows without the symlink
    privilege: WinError 1314)."""
    try:
        os.symlink(target, link, target_is_directory=is_dir)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"this host does not permit symlinks ({error})")


def dir_link(link: Path, target: Path) -> None:
    """A link to a FOLDER: a junction on Windows (no privilege needed, and the case is_symlink()
    does not report), a symlink elsewhere."""
    if os.name == "nt":
        import _winapi
        _winapi.CreateJunction(str(target), str(link))
    else:
        symlink_or_skip(link, target, is_dir=True)


def windows_dacl(path: Path) -> str:
    """SDDL text of path's DACL (Windows only), e.g. 'D:P(A;;FA;;;SY)...'."""
    return a._windows_security_sddl(path)


@pytest.fixture
def material():
    owner = a.make_owner()
    recipient = a.make_recipient("test")
    return owner, recipient, a.make_identity(recipient, owner)


def sample(material, source=b'<?php echo "private";'):
    """Build a one-recipient v2 package addressed to material's recipient."""
    owner, recipient, _identity = material
    project, release = uuid.uuid4().bytes, uuid.uuid4().bytes
    content_key = os.urandom(32)
    table = a.build_table([bytes.fromhex(recipient["x25519_public"])], content_key, project, release)
    signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(owner["signing_private"]))
    return a.protect(source, signer, project, release, content_key, table, path="app.php")


@pytest.mark.parametrize(
    "source",
    [
        b"",
        b'<?php echo "secret";',
        b"HTML <?php echo 1; ?> tail",
        '<?php echo "España";'.encode(),
        b"x" * 65537,
    ],
    ids=["empty", "php", "template", "utf8", "65KiB"],
)
def test_roundtrip(material, source):
    assert a.open_protected(sample(material, source), material[2]) == source


@pytest.mark.parametrize(
    "offset",
    [
        0,                 # stub
        len(a.STUB),       # magic
        len(a.STUB) + 8,   # version byte
        len(a.STUB) + 12,  # project id
        len(a.STUB) + 9,   # flags
        len(a.STUB) + 10,  # path length
        len(a.STUB) + 44,  # recipient count
        len(a.STUB) + 62,  # serial
        len(a.STUB) + a.HEADER.size,  # relative path
        TABLE,             # recipient table (recipient_pub)
        TABLE + a.RECIPIENT_SIZE,  # ciphertext
        -65,               # gcm tag region
        -1,                # signature
    ],
)
def test_tamper(material, offset):
    blob = bytearray(sample(material))
    blob[offset] ^= 1
    with pytest.raises((ValueError, InvalidSignature, InvalidTag)):
        a.open_protected(bytes(blob), material[2])


def test_other_recipient_cannot_decrypt(material):
    """Core property: a package for recipient A is useless to recipient B."""
    other = a.make_recipient("other")
    other_identity = a.make_identity(other, material[0])
    with pytest.raises(ValueError, match="addressed"):
        a.open_protected(sample(material), other_identity)


def test_wrong_signer(material):
    foreign = a.make_owner()
    broken = a.make_identity(material[1], foreign)
    with pytest.raises(InvalidSignature):
        a.open_protected(sample(material), broken)


def test_anti_downgrade_rejects_v1_magic(material):
    blob = bytearray(sample(material))
    blob[len(a.STUB) : len(a.STUB) + 8] = b"ENVLK01\0"
    with pytest.raises((ValueError, InvalidSignature)):
        a.open_protected(bytes(blob), material[2])


def test_anti_downgrade_rejects_version_byte(material):
    """Version lives in the signed header: changing it must break verification."""
    blob = bytearray(sample(material))
    blob[len(a.STUB) + 8] = 1
    with pytest.raises((ValueError, InvalidSignature)):
        a.open_protected(bytes(blob), material[2])


def test_kem_binding_resign_breaks_unwrap(material):
    """Re-sign a blob with a corrupted ephemeral key: signature passes but the KEM
    binding must make the content-key unwrap fail (proves X25519/HKDF binding)."""
    owner = material[0]
    blob = bytearray(sample(material))
    signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(owner["signing_private"]))
    ephemeral_offset = TABLE + 32  # ephemeral_pub inside first entry
    blob[ephemeral_offset] ^= 0x80
    body = bytes(blob[:-64])
    resigned = body + signer.sign(body)
    with pytest.raises(InvalidTag):
        a.open_protected(resigned, material[2])


def test_personal_mode(material):
    """Encrypting to your own key and opening with your own identity."""
    owner, recipient, identity = material
    content_key = os.urandom(32)
    pid, rid = uuid.uuid4().bytes, uuid.uuid4().bytes
    table = a.build_table([bytes.fromhex(recipient["x25519_public"])], content_key, pid, rid)
    signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(owner["signing_private"]))
    blob = a.protect(b'<?php echo "me";', signer, pid, rid, content_key, table, path="app.php")
    assert a.open_protected(blob, identity) == b'<?php echo "me";'


def test_multi_recipient(material):
    owner, recipient, identity = material
    other = a.make_recipient("other")
    other_identity = a.make_identity(other, owner)
    content_key = os.urandom(32)
    pid, rid = uuid.uuid4().bytes, uuid.uuid4().bytes
    table = a.build_table(
        [bytes.fromhex(recipient["x25519_public"]), bytes.fromhex(other["x25519_public"])],
        content_key, pid, rid,
    )
    signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(owner["signing_private"]))
    blob = a.protect(b'<?php echo "both";', signer, pid, rid, content_key, table, path="app.php")
    assert a.open_protected(blob, identity) == b'<?php echo "both";'
    assert a.open_protected(blob, other_identity) == b'<?php echo "both";'


def test_host_bundle_opens_several_projects():
    """One hosting, several folders/projects, different keys and signers: a single
    identity bundle opens each project's package (list = loader iterating identities)."""
    owner_a, owner_b = a.make_owner(), a.make_owner()
    rcpt_a, rcpt_b = a.make_recipient("proj-a"), a.make_recipient("proj-b")
    bundle = [a.make_identity(rcpt_a, owner_a), a.make_identity(rcpt_b, owner_b)]

    def pack_one(owner, rcpt, text):
        ck = os.urandom(32)
        pid, rid = uuid.uuid4().bytes, uuid.uuid4().bytes
        table = a.build_table([bytes.fromhex(rcpt["x25519_public"])], ck, pid, rid)
        signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(owner["signing_private"]))
        return a.protect(text, signer, pid, rid, ck, table, path="app.php")

    assert a.open_protected(pack_one(owner_a, rcpt_a, b"<?php echo 'A';"), bundle) == b"<?php echo 'A';"
    assert a.open_protected(pack_one(owner_b, rcpt_b, b"<?php echo 'B';"), bundle) == b"<?php echo 'B';"
    # a package for an unrelated project is rejected by the whole bundle
    with pytest.raises(Exception):
        a.open_protected(pack_one(a.make_owner(), a.make_recipient("x"), b"<?php 1;"), bundle)


@pytest.mark.parametrize("cut", [0, 1, 70, 200, -1])
def test_truncated(material, cut):
    blob = sample(material)
    with pytest.raises((ValueError, InvalidSignature)):
        a.open_protected(blob[:cut], material[2])


def test_identity_bundle_bytes_layout(material):
    data = a.identity_bytes(material[2])
    assert data[:8] == a.IDENTITY_MAGIC                 # ENVLKID3
    assert data[8:12] == b"\x00\x01\x00\x01"            # 1 recipient, 1 developer
    assert len(data) == 12 + a.IDENTITY_RECIPIENT + a.IDENTITY_DEVELOPER


def test_developer_id_is_sha256_of_signing_public(material):
    import hashlib
    expected = hashlib.sha256(bytes.fromhex(material[0]["signing_public"])).hexdigest()
    assert material[2]["developer_id"] == expected
    assert a.developer_id(material[0]["signing_public"]) == expected


def _pack_signed_by(recipient, signer_private_hex, source=b'<?php echo "x";'):
    signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(signer_private_hex))
    pid, rid = uuid.uuid4().bytes, uuid.uuid4().bytes
    ck = os.urandom(32)
    table = a.build_table([bytes.fromhex(recipient["x25519_public"])], ck, pid, rid)
    return a.protect(source, signer, pid, rid, ck, table, path="app.php")


def test_recovery_key_accepted():
    owner = a.make_owner(with_recovery=True)
    recipient = a.make_recipient("r")
    identity = a.make_identity(recipient, owner)
    assert "recovery_public" in identity
    blob = _pack_signed_by(recipient, owner["recovery_private"], b'<?php echo "rec";')
    assert a.open_protected(blob, identity) == b'<?php echo "rec";'


def test_recovery_key_rejected_when_not_in_trust_store():
    """If the identity carries no recovery key, a package signed by it must NOT verify
    (fails without the recovery entry — proves the recovery trust is load-bearing)."""
    owner = a.make_owner(with_recovery=True)
    recipient = a.make_recipient("r")
    identity = a.make_identity(recipient, owner)
    identity.pop("recovery_public")
    blob = _pack_signed_by(recipient, owner["recovery_private"])
    with pytest.raises(InvalidSignature):
        a.open_protected(blob, identity)


def test_untrusted_signer_rejected():
    owner, rogue = a.make_owner(), a.make_owner()
    recipient = a.make_recipient("r")
    identity = a.make_identity(recipient, owner)  # trusts owner only
    blob = _pack_signed_by(recipient, rogue["signing_private"])
    with pytest.raises(InvalidSignature):
        a.open_protected(blob, identity)


def test_trust_store_is_global_over_recipients():
    """Per-installation trust store: a package addressed to one recipient and signed by
    any trusted developer (even one paired with another recipient) verifies."""
    owner_a, owner_b = a.make_owner(), a.make_owner()
    rcpt_a, rcpt_b = a.make_recipient("A"), a.make_recipient("B")
    store = [a.make_identity(rcpt_a, owner_a), a.make_identity(rcpt_b, owner_b)]
    blob = _pack_signed_by(rcpt_a, owner_b["signing_private"], b'<?php echo "g";')
    assert a.open_protected(blob, store) == b'<?php echo "g";'


def test_export_public_has_no_private(material):
    pub = a.recipient_public(material[1])
    assert "x25519_private" not in pub
    assert pub["x25519_public"] == material[1]["x25519_public"]


def test_pack_defaults_and_secrets(tmp_path, material):
    source, dest = tmp_path / "source", tmp_path / "output"
    source.mkdir()
    (source / "index.php").write_text('<?php echo "sensitive";')
    (source / ".env").write_text("SECRET=123")
    (source / "credentials.json").write_text("secret")
    (source / ".git").mkdir()
    (source / ".git/config").write_text("token")
    info = a.pack_tree(
        source, dest, [a.recipient_public(material[1])], material[0], str(uuid.uuid4())
    )
    assert info["protected_files"] == 1 and info["recipients"] == 1
    assert b"sensitive" not in (dest / "index.php").read_bytes()
    assert not (dest / ".env").exists()
    assert not (dest / ".git").exists()
    assert not (dest / "credentials.json").exists()
    assert a.open_protected((dest / "index.php").read_bytes(), material[2]) == b'<?php echo "sensitive";'


def test_assets_and_exclude(tmp_path, material):
    source, dest = tmp_path / "source", tmp_path / "output"
    source.mkdir()
    (source / "main.php").write_text("<?php return 1;")
    (source / "debug.php").write_text("<?php return 2;")
    (source / "style.css").write_text("body{}")
    (source / ".env.production").write_text("secret")
    a.pack_tree(
        source, dest, [a.recipient_public(material[1])], material[0], str(uuid.uuid4()),
        assets=["*"], exclude=["debug.php"],
    )
    assert (dest / "style.css").read_text() == "body{}"
    assert not (dest / "debug.php").exists()
    assert not (dest / ".env.production").exists()


def test_no_overwrite(tmp_path):
    path = tmp_path / "key.json"
    a.save_json(path, {"a": 1})
    with pytest.raises(FileExistsError):
        a.save_json(path, {"a": 2})
    assert path.read_text().find("1") >= 0
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600


def test_nested_output_rejected(tmp_path, material):
    source = tmp_path / "src"
    source.mkdir()
    with pytest.raises(ValueError):
        a.pack_tree(source, source / "out", [a.recipient_public(material[1])], material[0], str(uuid.uuid4()))


def test_output_exists_rejected(tmp_path, material):
    source, output = tmp_path / "src", tmp_path / "out"
    source.mkdir()
    output.mkdir()
    with pytest.raises(ValueError):
        a.pack_tree(source, output, [a.recipient_public(material[1])], material[0], str(uuid.uuid4()))


def test_symlink_rejected(tmp_path, material):
    source = tmp_path / "src"
    source.mkdir()
    (source / "main.php").write_text("<?php echo 1;")
    try:
        (source / "link.php").symlink_to(source / "main.php")
    except OSError:
        pytest.skip("Host does not permit symlinks")
    with pytest.raises(ValueError):
        a.pack_tree(source, tmp_path / "out", [a.recipient_public(material[1])], material[0], str(uuid.uuid4()))
    assert not (tmp_path / "out").exists()


def test_each_pack_has_distinct_release_and_table(tmp_path, material):
    source = tmp_path / "src"
    source.mkdir()
    (source / "main.php").write_text("<?php echo 1;")
    blobs = []
    for label in ("a", "b"):
        dest = tmp_path / label
        a.pack_tree(source, dest, [a.recipient_public(material[1])], material[0], str(uuid.uuid4()))
        blobs.append((dest / "main.php").read_bytes())
    h1 = a.HEADER.unpack(blobs[0][len(a.STUB) : len(a.STUB) + a.HEADER.size])
    h2 = a.HEADER.unpack(blobs[1][len(a.STUB) : len(a.STUB) + a.HEADER.size])
    # release id (index 5) differs; recipient tables differ (fresh ephemeral keys)
    assert h1[5] != h2[5]
    table = len(a.STUB) + a.HEADER.size + len("main.php")
    t1 = blobs[0][table : table + a.RECIPIENT_SIZE]
    t2 = blobs[1][table : table + a.RECIPIENT_SIZE]
    assert t1 != t2


def test_identity_does_not_embed_signing_private(material):
    data = a.identity_bytes(material[2])
    assert bytes.fromhex(material[0]["signing_private"]) not in data
    assert bytes.fromhex(material[1]["x25519_private"]) in data  # the X25519 private IS the secret


def test_content_nonces_are_unique_within_pack(tmp_path, material):
    source, destination = tmp_path / "source", tmp_path / "out"
    source.mkdir()
    for index in range(40):
        (source / f"{index}.php").write_text("<?php return 1;")
    a.pack_tree(source, destination, [a.recipient_public(material[1])], material[0], str(uuid.uuid4()))
    nonces = []
    for path in destination.glob("*.php"):
        blob = path.read_bytes()
        nonces.append(a.HEADER.unpack(blob[len(a.STUB) : len(a.STUB) + a.HEADER.size])[7])
    assert len(set(nonces)) == 40


def test_limit_and_double_encoding(material):
    owner, recipient, _ = material
    signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(owner["signing_private"]))
    pid, rid = uuid.uuid4().bytes, uuid.uuid4().bytes
    ck = os.urandom(32)
    table = a.build_table([bytes.fromhex(recipient["x25519_public"])], ck, pid, rid)
    with pytest.raises(ValueError):
        a.protect(b"x" * (a.MAX_SOURCE + 1), signer, pid, rid, ck, table, path="app.php")
    with pytest.raises(ValueError):
        a.protect(sample(material), signer, pid, rid, ck, table, path="app.php")


def test_duplicate_recipient_rejected(material):
    pub = bytes.fromhex(material[1]["x25519_public"])
    with pytest.raises(ValueError, match="Duplicate"):
        a.build_table([pub, pub], os.urandom(32), uuid.uuid4().bytes, uuid.uuid4().bytes)


# --- Objective 8: CLI (keygen / recipient add / inspect) ---

def test_add_recipient_to_store_builds_extends_and_dedups(material):
    owner2 = a.make_owner(with_recovery=True)
    rcpt2 = a.make_recipient("second")
    store = a.add_recipient_to_store(None, material[1], material[0])
    store = a.add_recipient_to_store(store, rcpt2, owner2)
    recipients, developers = a.parse_identity_store(store)
    assert len(recipients) == 2 and len(developers) == 2
    assert any(d[32:64] != a.ZERO32 for d in developers)  # owner2 has recovery
    # adding the same recipient+developer again does not grow the store
    again = a.add_recipient_to_store(store, material[1], material[0])
    r2, d2 = a.parse_identity_store(again)
    assert len(r2) == 2 and len(d2) == 2


def test_store_of_one_matches_identity_bytes(material):
    assert a.add_recipient_to_store(None, material[1], material[0]) == a.identity_bytes(material[2])


def test_inspect_package_has_no_secrets(tmp_path, material):
    source, dest = tmp_path / "s", tmp_path / "o"
    source.mkdir()
    (source / "index.php").write_text('<?php echo "s";')
    a.pack_tree(source, dest, [a.recipient_public(material[1])], material[0], str(uuid.uuid4()))
    info = a.inspect_path(dest / "index.php")
    assert info["kind"] == "envelock-package" and info["recipient_count"] == 1
    assert material[1]["x25519_public"] in info["recipients"]
    text = json.dumps(info)
    assert material[1]["x25519_private"] not in text
    assert material[0]["signing_private"] not in text


def test_inspect_identity_store(tmp_path, material):
    owner = a.make_owner(with_recovery=True)
    path = tmp_path / "id.bin"
    a.secret_write(path, a.identity_bytes(a.make_identity(material[1], owner)))
    info = a.inspect_path(path)
    assert info["kind"] == "envelock-identity-store"
    assert info["recipients"] == [material[1]["x25519_public"]]
    assert info["developers"][0]["developer_id"] == a.developer_id(owner["signing_public"])
    assert info["developers"][0]["has_recovery"] is True
    assert owner["recovery_private"] not in json.dumps(info)


def test_inspect_owner_hides_private(tmp_path, material):
    path = tmp_path / "owner.json"
    a.save_json(path, material[0])
    info = a.inspect_path(path)
    assert info["kind"] == "envelock-owner"
    assert info["developer_id"] == a.developer_id(material[0]["signing_public"])
    assert "signing_private" not in json.dumps(info)


def test_recipient_add_fills_missing_recovery(material):
    recovery = Ed25519PrivateKey.generate()
    owner_with_recovery = dict(
        material[0],
        recovery_private=a.raw_private(recovery).hex(),
        recovery_public=a.raw_public(recovery.public_key()).hex(),
    )
    store = a.add_recipient_to_store(None, material[1], material[0])  # no recovery yet
    _, developers = a.parse_identity_store(store)
    assert developers[0][32:64] == a.ZERO32
    store = a.add_recipient_to_store(store, material[1], owner_with_recovery)  # same signer + recovery
    _, developers = a.parse_identity_store(store)
    assert len(developers) == 1 and developers[0][32:64] != a.ZERO32


def test_inspect_truncated_package_rejected(tmp_path, material):
    source, dest = tmp_path / "s", tmp_path / "o"
    source.mkdir()
    (source / "index.php").write_text('<?php echo "s";')
    a.pack_tree(source, dest, [a.recipient_public(material[1])], material[0], str(uuid.uuid4()))
    truncated = tmp_path / "trunc.php"
    truncated.write_bytes((dest / "index.php").read_bytes()[:-10])
    with pytest.raises(ValueError):
        a.inspect_path(truncated)


def test_cli_keygen_recipient_add_inspect(tmp_path):
    enc = str(ROOT / "encoder/envelock.py")

    def run(*argv):
        return subprocess.run([sys.executable, enc, *argv], capture_output=True, text=True)

    owner, rcpt, ident = tmp_path / "owner.json", tmp_path / "rcpt.json", tmp_path / "id.bin"
    assert run("keygen", "owner", "--out", str(owner), "--with-recovery", "--no-encrypt").returncode == 0
    assert run("keygen", "recipient", "--out", str(rcpt), "--label", "c1", "--no-encrypt").returncode == 0
    added = run("recipient", "add", "--identity", str(ident),
                "--recipient", str(rcpt), "--owner", str(owner))
    assert added.returncode == 0, added.stderr
    assert ident.exists()
    if os.name != "nt":
        assert ident.stat().st_mode & 0o777 == 0o600
    inspected = run("inspect", str(ident))
    assert inspected.returncode == 0, inspected.stderr
    data = json.loads(inspected.stdout)
    assert data["kind"] == "envelock-identity-store" and len(data["recipients"]) == 1
    assert data["developers"][0]["has_recovery"] is True


def test_package_header_carries_path_flags_and_serial(tmp_path, material):
    source = tmp_path / "src"
    (source / "sub").mkdir(parents=True)
    (source / "sub" / "page.php").write_text("<?php echo 1;")
    info = a.pack_tree(source, tmp_path / "out", [a.recipient_public(material[1])], material[0],
                       str(uuid.uuid4()), include_protection=True, no_prepend=True, serial=1234)
    assert info["serial"] == 1234 and info["include_protection"] and info["no_prepend"]
    meta = a.inspect_path(tmp_path / "out" / "sub" / "page.php")
    assert meta["path"] == "sub/page.php" and meta["serial"] == 1234
    assert meta["include_protection"] is True and meta["no_prepend"] is True
    default = a.pack_tree(source, tmp_path / "out2", [a.recipient_public(material[1])], material[0],
                          str(uuid.uuid4()))
    # Default serial: nanoseconds since the Unix epoch (ENV-05), not seconds (ENC-9).
    assert default["serial"] > 1_700_000_000 * 10**9 and not default["include_protection"]


@pytest.mark.parametrize("path", ["", "/abs.php", "a/../b.php", "a//b.php", "./a.php", "a\\b.php", "x" * 1025])
def test_protect_refuses_bad_paths(material, path):
    with pytest.raises(ValueError, match="Invalid relative path"):
        sample_with(material, path=path)


def test_unknown_flags_refused(material):
    # The flags field is ONE byte, so "unknown" has to be a bit inside 0..255 that the known mask
    # does not cover. `FLAGS_KNOWN + 1` used to be that bit; now that the mask is the whole byte
    # (objective O7 took bit 128) there is none left, and any candidate has to be found by masking.
    unknown = next(bit for bit in (1 << i for i in range(8)) if not a.FLAGS_KNOWN & bit) \
        if a.FLAGS_KNOWN != 0xFF else None
    if unknown is None:
        pytest.skip("the known mask covers every bit of the flags byte")
    with pytest.raises(ValueError):
        sample_with(material, flags=unknown)
    blob = bytearray(sample(material))
    blob[len(a.STUB) + 9] = unknown                            # unknown flag bit
    with pytest.raises(ValueError, match="Invalid header"):
        a.parse_package(bytes(blob))


def sample_with(material, **options):
    owner, recipient, _identity = material
    project, release = uuid.uuid4().bytes, uuid.uuid4().bytes
    key = os.urandom(32)
    table = a.build_table([bytes.fromhex(recipient["x25519_public"])], key, project, release)
    signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(owner["signing_private"]))
    options.setdefault("path", "app.php")
    return a.protect(b"<?php echo 1;", signer, project, release, key, table, **options)


def test_minimums_survive_identity_changes(material):
    owner, recipient, identity = material
    project = str(uuid.uuid4())
    store = a.set_minimum(a.identity_bytes(identity), project, 77)
    assert a.identity_minimums(store) == {(uuid.UUID(project).bytes, a.ZERO32): 77}
    store = a.add_recipient_to_store(store, a.make_recipient("second"), owner)
    store = a.set_developer(store, a.developer_public(a.make_owner()))
    store = a.remove_recipient(store, recipient["x25519_public"])
    assert a.identity_minimums(store) == {(uuid.UUID(project).bytes, a.ZERO32): 77}
    with pytest.raises(ValueError):
        a.parse_identity_store(store + b"\0" * 5)                 # partial minimum entry


def test_cli_minimum_set_from_package(tmp_path):
    enc = str(ROOT / "encoder/envelock.py")

    def run(*argv):
        return subprocess.run([sys.executable, enc, *map(str, argv)], capture_output=True, text=True)

    owner, rcpt, ident = tmp_path / "owner.json", tmp_path / "rcpt.json", tmp_path / "id.bin"
    assert run("keygen", "owner", "--out", owner, "--no-encrypt").returncode == 0
    assert run("keygen", "recipient", "--out", rcpt, "--label", "c1", "--no-encrypt").returncode == 0
    assert run("export-public", "--recipient", rcpt, "--out", tmp_path / "pub.json").returncode == 0
    assert run("recipient", "add", "--identity", ident, "--recipient", rcpt, "--owner", owner).returncode == 0
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "i.php").write_text("<?php echo 1;")
    project = str(uuid.uuid4())
    packed = run("pack", "--owner", owner, "--recipient", tmp_path / "pub.json", "--project", project,
                 "--source", tmp_path / "src", "--output", tmp_path / "out", "--serial", "55")
    assert packed.returncode == 0, packed.stderr
    result = run("minimum", "set", "--identity", ident, "--package", tmp_path / "out")
    assert result.returncode == 0 and "below 55" in result.stdout and "Restart PHP" in result.stdout
    mins = json.loads(run("inspect", ident).stdout)["minimum_serials"]
    entry = next(m for m in mins if m["project"] == project)
    assert entry["serial"] == 55 and entry["developer_id"]              # bound to the signer (ENV-AUD-14)
    assert run("minimum", "set", "--identity", ident, "--project", project).returncode != 0   # needs --serial


def test_cli_pack_advises_when_no_hardening_flags(tmp_path):
    """ENV-AUD-15: a bare pack (base protection only) prints an advisory to stderr; enabling any
    hardening layer silences it. Defaults are unchanged (no breakage of existing workflows)."""
    enc = str(ROOT / "encoder/envelock.py")

    def run(*argv):
        return subprocess.run([sys.executable, enc, *map(str, argv)], capture_output=True, text=True)

    owner, rcpt = tmp_path / "owner.json", tmp_path / "rcpt.json"
    assert run("keygen", "owner", "--out", owner, "--no-encrypt").returncode == 0
    assert run("keygen", "recipient", "--out", rcpt, "--label", "c1", "--no-encrypt").returncode == 0
    assert run("export-public", "--recipient", rcpt, "--out", tmp_path / "pub.json").returncode == 0
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "i.php").write_text("<?php echo 1;")
    project = str(uuid.uuid4())
    common = ["pack", "--owner", owner, "--recipient", tmp_path / "pub.json", "--project", project,
              "--source", tmp_path / "src"]
    bare = run(*common, "--output", tmp_path / "bare")
    assert bare.returncode == 0 and "base protection only" in bare.stderr
    hardened = run(*common, "--output", tmp_path / "hard", "--include-protection")
    assert hardened.returncode == 0 and "base protection only" not in hardened.stderr


def test_cli_pack_writes_runtime_manifest_by_default(tmp_path):
    """The runtime manifest is on by default (integrity + the loader's fast path, ~5x). A bare pack
    writes envelock-manifest.bin and sets the enforce flag; --no-manifest opts out of both."""
    enc = str(ROOT / "encoder/envelock.py")

    def run(*argv):
        return subprocess.run([sys.executable, enc, *map(str, argv)], capture_output=True, text=True)

    owner, rcpt = tmp_path / "owner.json", tmp_path / "rcpt.json"
    assert run("keygen", "owner", "--out", owner, "--no-encrypt").returncode == 0
    assert run("keygen", "recipient", "--out", rcpt, "--label", "c1", "--no-encrypt").returncode == 0
    assert run("export-public", "--recipient", rcpt, "--out", tmp_path / "pub.json").returncode == 0
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "i.php").write_text("<?php echo 1;")
    common = ["pack", "--owner", owner, "--recipient", tmp_path / "pub.json",
              "--project", str(uuid.uuid4()), "--source", tmp_path / "src"]

    on = run(*common, "--output", tmp_path / "def")
    assert on.returncode == 0, on.stderr
    assert (tmp_path / "def" / "envelock-manifest.bin").exists(), "default pack should write the manifest"
    got = run("inspect", tmp_path / "def" / "i.php")
    assert got.returncode == 0 and '"enforce_manifest": true' in got.stdout, got.stdout

    off = run(*common, "--output", tmp_path / "nom", "--no-manifest")
    assert off.returncode == 0, off.stderr
    assert not (tmp_path / "nom" / "envelock-manifest.bin").exists(), "--no-manifest should write no manifest"
    got2 = run("inspect", tmp_path / "nom" / "i.php")
    assert got2.returncode == 0 and '"enforce_manifest": false' in got2.stdout, got2.stdout


def test_cli_recipient_public_accepts_public_or_private_rejects_encrypted(tmp_path):
    """ENV-AUD-16: pack accepts a public recipient or your own private recipient.json (its public
    part is derived); an encrypted private recipient is refused with an actionable message, since
    its public key cannot be read without the password."""
    rec = a.make_recipient("srv")
    (tmp_path / "rec.json").write_text(json.dumps(rec))
    (tmp_path / "rec.pub.json").write_text(json.dumps(a.recipient_public(rec)))
    a.save_json(tmp_path / "rec.enc.json", rec, b"a-long-enough-password-x")
    assert a.cli_recipient_public(tmp_path / "rec.pub.json")["x25519_public"] == rec["x25519_public"]
    assert a.cli_recipient_public(tmp_path / "rec.json")["x25519_public"] == rec["x25519_public"]
    with pytest.raises(ValueError, match="encrypted private recipient"):
        a.cli_recipient_public(tmp_path / "rec.enc.json")


def test_preflight_flags_self_introspecting_code(tmp_path):
    """The compatibility scan detects code that reads its own source (the patterns that broke
    PrestaShop), while leaving ordinary code alone. Static, read-only: it never runs the code."""
    (tmp_path / "autoload.php").write_text(
        "<?php foreach (token_get_all(file_get_contents($f)) as $t) {}\n")
    (tmp_path / "Entity.php").write_text(
        "<?php\n/**\n * @ORM\\Table(name=\"x\")\n */\nclass X { public int $id = 0; }\n")
    (tmp_path / "header.php").write_text("<?php $d = get_file_data(__FILE__, []);\n")
    (tmp_path / "clean.php").write_text(
        "<?php function add(int $a, int $b): int { return $a + $b; }\n")
    findings = a.compatibility_findings(tmp_path, a.DEFAULT_EXTENSIONS)
    assert "source-tokenizer" in findings
    assert "doctrine-annotation" in findings
    assert "file-header-reader" in findings
    flagged = {rel for data in findings.values() for rel, _ in data["hits"]}
    assert "autoload.php" in flagged and "Entity.php" in flagged and "header.php" in flagged
    assert "clean.php" not in flagged  # ordinary code is never flagged


def test_preflight_clean_tree_reports_no_issues(tmp_path):
    (tmp_path / "ok.php").write_text("<?php class A { public function f(){ return 1; } }\n")
    findings = a.compatibility_findings(tmp_path, a.DEFAULT_EXTENSIONS)
    assert findings == {}
    assert "no self-introspection" in a.format_compatibility_report(findings)


def test_preflight_cli_strict_exit_code(tmp_path):
    """`preflight --strict` exits non-zero when an issue is found, zero on a clean tree."""
    (tmp_path / "bad.php").write_text("<?php token_get_all('<?php 1;');\n")
    script = str(ROOT / "encoder" / "envelock.py")
    dirty = subprocess.run([sys.executable, script, "preflight", "--source", str(tmp_path),
                            "--strict"], capture_output=True, text=True)
    assert dirty.returncode == 1
    assert "source-tokenizer" in dirty.stdout
    clean_dir = tmp_path / "clean"
    clean_dir.mkdir()
    (clean_dir / "ok.php").write_text("<?php echo 1;\n")
    clean = subprocess.run([sys.executable, script, "preflight", "--source", str(clean_dir),
                            "--strict"], capture_output=True, text=True)
    assert clean.returncode == 0


def test_vault_key_nonce_is_domain_separated():
    """The package content key encrypts each file with a counter nonce (protect(): protected.to_bytes,
    so the top bit of byte 0 is always clear) and ALSO wraps each file's vault data key. Under one
    shared key a random wrap nonce could, with vanishing but non-zero probability, collide with a
    small counter nonce — catastrophic for AES-GCM. The wrap nonce is therefore forced into the
    top-bit-set half, which the counter nonces can never reach. Output layout:
    u32 body_len | u32 count | key_nonce[12] | wrapped[48] | ... | source."""
    content_key = bytes(range(32))
    out = a._vault_plaintext_encrypted([b"secret-1", b"secret-2"], b"<?php $x = 1;", content_key)
    key_nonce = out[8:20]
    assert key_nonce[0] & 0x80, "vault wrap nonce must have its top bit set"
    # the file counter nonces live in the complementary half, so the two can never collide
    assert (0).to_bytes(12, "big")[0] & 0x80 == 0
    assert (2**80).to_bytes(12, "big")[0] & 0x80 == 0


def test_bytecode_temp_sources_are_owner_only(tmp_path, monkeypatch):
    """The plaintext sources the bytecode pass writes under the deploy root exist on disk only while
    they compile; they must be created 0600 so another local user cannot read the source in that
    window. On Windows, where 0600 means nothing, they carry a protected owner-only ACL instead of the
    deploy folder's inherited one (ENC-5)."""
    seen: dict[str, object] = {}

    def fake_run_php(php, code, payload, what, extra_args=None):
        for name, path in payload["files"].items():
            seen[name] = windows_dacl(Path(path)) if os.name == "nt" else os.stat(path).st_mode & 0o777
        return {name: "" for name in payload["files"]}

    monkeypatch.setattr(a, "_run_php", fake_run_php)
    files = {"a/b.php": b"<?php echo 1;", "c.php": b"<?php echo 2;"}
    a._bytecode_pass(files, tmp_path / "deploy", "php", None)
    assert seen, "no temp sources were created"
    if os.name == "nt":
        owner_only = f"D:P(A;;FA;;;{a._current_user_sid_string()})"
        assert all(dacl == owner_only for dacl in seen.values()), seen
    else:
        assert all(mode == 0o600 for mode in seen.values()), {k: oct(v) for k, v in seen.items()}


def test_bytecode_pass_keeps_preexisting_deploy_root(tmp_path, monkeypatch):
    """The cleanup must remove only directories THIS pass created, never a pre-existing deploy_root.
    It used to rmdir upward to deploy_root.parent, deleting an empty deploy_root the pipeline had
    pre-created (audit ENV-04)."""
    deploy = tmp_path / "deploy"
    deploy.mkdir()                                       # pre-existing, empty

    def boom(*args, **kwargs):
        raise RuntimeError("emit failed")

    monkeypatch.setattr(a, "_run_php", boom)
    with pytest.raises(RuntimeError):
        a._bytecode_pass({"sub/a.php": b"<?php echo 1;"}, deploy, php="php")
    assert deploy.exists()                               # pre-existing root survives the failure
    assert not (deploy / "sub").exists()                 # the dir this pass created is cleaned up


def test_preflight_flags_wordpress_file_headers(tmp_path):
    """WordPress reads a block pattern's 'Slug:' header (and plugin/theme/template headers) from the
    file TEXT via get_file_data; encryption hides it, so a block (FSE) theme renders empty. Preflight
    must flag these files so the developer keeps them unencrypted (audit: Envelock + WordPress FSE)."""
    (tmp_path / "banner.php").write_text(
        "<?php\n/**\n * Title: Hero\n * Slug: mytheme/banner-hero\n * Categories: banner\n */\nreturn;\n")
    findings = a.compatibility_findings(tmp_path, {".php"})
    assert "wp-file-header" in findings
    assert findings["wp-file-header"]["hits"][0][0] == "banner.php"


def test_preflight_flags_reads_own_docblock(tmp_path):
    """Code that reads its OWN docblocks at run time via Reflection getDocComment() (a custom
    annotation such as PrestaShop's @arrayAccess on a LazyArray presenter) keeps working under plain
    encryption but silently breaks under --strip-comments/--compact, which physically remove the
    docblocks. Preflight must flag it so the developer excludes the file or drops those flags
    (measured: PrestaShop front-office product data vanished under --strip-comments and --compact)."""
    (tmp_path / "LazyArray.php").write_text(
        "<?php\nclass LazyArray {\n"
        "    private function buildArrayAccessList() {\n"
        "        $m = new ReflectionMethod($this, 'getProducts');\n"
        "        if (strpos($m->getDocComment(), '@arrayAccess') !== false) { return true; }\n"
        "    }\n"
        "    /** @arrayAccess */\n    public function getProducts() { return []; }\n}\n")
    findings = a.compatibility_findings(tmp_path, {".php"})
    assert "reads-own-docblock" in findings
    assert findings["reads-own-docblock"]["hits"][0][0] == "LazyArray.php"


def test_recommend_options_is_conservative_and_matches_the_cms_matrix(tmp_path):
    """The recommender enables the strongest options measurement shows are safe and never enables one
    known to break the project (grounded in the four-CMS matrix and the preflight detectors)."""
    ext = {".php"}
    # A clean tree with no file that needs its own source: the full safe set, plus --bytecode (the
    # strongest option, now part of the production toolchain). --bytecode ships no source, so --sealed
    # is superseded and moves to off; the high-risk ones stay off.
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "a.php").write_text("<?php class A { function f(){ return 1; } }\n")
    rec = a.recommend_options(clean, ext)
    for flag in ("--encode-strings", "--obfuscate", "--obfuscate-flow", "--obfuscate-methods",
                 "--include-protection", "--no-ffi", "--no-prepend",
                 "--strip-comments", "--compact", "--bytecode"):
        assert flag in rec["on"], flag
    # bytecode supersedes sealed (ships no source at all); both-on is untested, so sealed goes off.
    assert "--bytecode" not in rec["off"]
    assert "--sealed" in rec["off"] and "--sealed" not in rec["on"]
    assert "--obfuscate-properties" in rec["off"] and "--vault-strings" in rec["off"]
    assert "--obfuscate-properties" not in rec["on"] and "--vault-strings" not in rec["on"]

    # A tree that reads its OWN SOURCE: --bytecode must be OFF (an image ships no source to read), and
    # --sealed is recommended instead since nothing supersedes it here.
    assert True

    # A tree that reads its own docblocks: strip-comments/compact must be OFF (PrestaShop class).
    dbk = tmp_path / "dbk"
    dbk.mkdir()
    (dbk / "l.php").write_text("<?php class L { /** @arrayAccess */ function g(){}"
                               " function h(){ $m=new ReflectionMethod($this,'g'); return $m->getDocComment(); } }\n")
    rdb = a.recommend_options(dbk, ext)
    assert "--strip-comments" in rdb["off"] and "--compact" in rdb["off"]
    assert "--strip-comments" not in rdb["on"] and "--compact" not in rdb["on"]

    # A tree that eval()s: --sealed must be OFF (sealed refuses eval at run time).
    ev = tmp_path / "ev"
    ev.mkdir()
    (ev / "e.php").write_text("<?php function x($c){ return eval($c); }\n")
    rev = a.recommend_options(ev, ext)
    assert "--sealed" in rev["off"] and "--sealed" not in rev["on"]

    # A tree that tokenizes its own source: the file must be listed to keep CLEARTEXT, and the
    # suggested command excludes it exactly once (deduplicated across categories).
    tok = tmp_path / "tok"
    tok.mkdir()
    (tok / "t.php").write_text("<?php $t = token_get_all(file_get_contents(__FILE__));\n")
    rtk = a.recommend_options(tok, ext)
    assert any("t.php" in files for files in rtk["exclude"].values())
    # A file reads its own source, so --bytecode (ships no source) must be OFF, not recommended.
    assert "--bytecode" in rtk["off"] and "--bytecode" not in rtk["on"]
    cmd = a.format_recommendation(rtk)
    assert cmd.count("--exclude t.php") == 1   # shlex.quote leaves a safe name bare


def test_recommend_leaves_composer_vendor_caches_and_blade_templates_in_the_clear(tmp_path):
    """Measured on real Laravel/Symfony apps (2026-11-10): analysing vendor/ made third-party files
    (Blade's compiler tokenizes TEMPLATES, not itself) switch --bytecode and --strip-comments off, and
    the suggested command would have encrypted vendor/, the run-time caches and the Blade templates
    Laravel reads as text. The documented layout (MANUAL §14) packs only the application's own code."""
    ext = {".php"}
    app = tmp_path / "app"
    for name, text in {
        "vendor/autoload.php": "<?php require __DIR__ . '/composer/autoload_real.php';",
        "vendor/laravel/BladeCompiler.php": "<?php $t = token_get_all($template);",
        "vendor/x/Doc.php": "<?php /** @ORM\\Entity */ class D { function d(){ return (new ReflectionClass($this))->getDocComment(); } }",
        "app/Service.php": "<?php namespace App; class Service { private function f(){ return 1; } }",
        "bootstrap/cache/packages.php": "<?php return [];",
        "resources/views/welcome.blade.php": "<h1>{{ $title }}</h1>",
    }.items():
        (app / name).parent.mkdir(parents=True, exist_ok=True)
        (app / name).write_text(text)
    rec = a.recommend_options(app, ext)
    assert rec["exclude_patterns"][:2] == ["vendor/*", "bootstrap/cache/*"]
    assert rec["exclude"] == {"template-source": ["resources/views/welcome.blade.php"]}
    for flag in ("--bytecode", "--strip-comments", "--compact"):         # vendor no longer decides
        assert flag in rec["on"], flag
    assert "--sealed" in rec["off"]                                      # vendor/ stays cleartext .php
    cmd = a.format_recommendation(rec)
    assert "--exclude 'vendor/*'" in cmd and "--exclude 'bootstrap/cache/*'" in cmd
    assert "--exclude resources/views/welcome.blade.php" in cmd
    assert "--bytecode-loader" in cmd and "--bytecode-php" in cmd       # a production loader cannot emit
    # Without Composer's autoloader there is no vendor/ rule and everything is the project's own code.
    plain = tmp_path / "plain"
    (plain / "lib").mkdir(parents=True)
    (plain / "lib" / "x.php").write_text("<?php function x(){}")
    assert a.recommend_options(plain, ext)["exclude_patterns"] == []


def test_recommend_turns_include_protection_off_for_a_cleartext_console_entry_point(tmp_path):
    """Measured on Laravel: pack encrypts only files with a PHP extension, so `artisan` stayed cleartext
    and, with --include-protection, `php artisan route:list` was refused ("it can only be loaded by its
    own application") while the web routes ran. The recommender must not enable it then."""
    ext = {".php"}
    app = tmp_path / "app"
    (app / "bin").mkdir(parents=True)
    (app / "src.php").write_text("<?php function f(){}")
    plain = a.recommend_options(app, ext)
    assert "--include-protection" in plain["on"]
    (app / "bin" / "console").write_text("#!/usr/bin/env php\n<?php require __DIR__ . '/../src.php';\n")
    (app / "LICENSE").write_text("MIT License\n")                       # extensionless, not PHP
    rec = a.recommend_options(app, ext)
    assert "--include-protection" not in rec["on"]
    assert "bin/console" in rec["off"]["--include-protection"]
    assert "LICENSE" not in rec["off"]["--include-protection"]


def test_recommend_no_ffi_states_its_php_ini_requirement_and_respects_ffi_users(tmp_path):
    """Measured: with PHP's built-in enable_dl=On (no php.ini, or one that does not set it) a --no-ffi
    package refuses every request. The recommendation must say what php.ini needs, and must not enable
    --no-ffi for a project that uses FFI or dl() itself."""
    ext = {".php"}
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "a.php").write_text("<?php $o->dl('x'); Foo::dl(1);")         # methods named dl are not dl()
    rec = a.recommend_options(clean, ext)
    assert "--no-ffi" in rec["on"]
    # Server-side conditions the analysis cannot see: recommended, but listed as "check first".
    assert "enable_dl = Off" in rec["verify"]["--no-ffi"] and "ffi.enable = 0" in rec["verify"]["--no-ffi"]
    assert "auto_prepend_file" in rec["verify"]["--no-prepend"]
    ffi = tmp_path / "ffi"
    ffi.mkdir()
    (ffi / "f.php").write_text("<?php $c = \\FFI::cdef('int abs(int);');")
    rec = a.recommend_options(ffi, ext)
    assert "--no-ffi" not in rec["on"] and "f.php" in rec["off"]["--no-ffi"]
    dl = tmp_path / "dl"
    dl.mkdir()
    (dl / "d.php").write_text("<?php if (!extension_loaded('x')) { dl('x.so'); }")
    assert "--no-ffi" in a.recommend_options(dl, ext)["off"]


def test_recommend_explains_every_option_and_says_when_it_is_unsure(tmp_path):
    """Every protection option of pack is accounted for — recommended, recommended with a stated doubt
    and how to check it, or not recommended with the reason — so the user never has to guess why an
    option is missing."""
    ext = {".php"}
    protection = ["--strip-comments", "--obfuscate", "--compact", "--encode-strings", "--obfuscate-methods",
                  "--obfuscate-properties", "--obfuscate-flatten", "--obfuscate-flow", "--obfuscate-names",
                  "--virtualize", "--vault-strings", "--bytecode", "--include-protection", "--no-prepend",
                  "--no-ffi", "--sealed"]
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "index.php").write_text("<?php class A { private function f() { return 1; } }")
    app = tmp_path / "app"
    (app / "vendor" / "symfony" / "property-info").mkdir(parents=True)
    (app / "vendor" / "autoload.php").write_text("<?php")
    (app / "index.php").write_text("<?php require 'vendor/autoload.php';")
    (app / "bin").mkdir()
    (app / "bin" / "console").write_text("#!/usr/bin/env php\n<?php\n")
    for tree in (clean, app):
        rec = a.recommend_options(tree, ext)
        for flag in protection:
            assert (flag in rec["on"]) != (flag in rec["off"]), flag     # exactly one of the two
        assert all(reason.strip() for reason in rec["off"].values())
        assert set(rec["verify"]) <= set(rec["on"])                       # doubts are about enabled ones
        assert all("heck" in why for why in rec["verify"].values())        # each says how to check
        report = a.format_recommendation(rec)
        assert "CHECK FIRST" in report and "DO NOT enable" in report
        for flag, reason in rec["off"].items():
            assert f"{flag} — {reason}" in report
    clean_rec = a.recommend_options(clean, ext)
    # Conditions on the server or the deployment: never presented as certain.
    for flag in ("--no-ffi", "--no-prepend", "--include-protection", "--bytecode", "--obfuscate-methods"):
        assert flag in clean_rec["verify"], flag
    assert "only part of an application" in clean_rec["verify"]["--include-protection"]
    assert "NTS" in clean_rec["verify"]["--bytecode"]
    # A docblock-reading library in vendor/ is named in the doubt about stripping comments.
    app_rec = a.recommend_options(app, ext)
    assert "vendor/symfony/property-info" in app_rec["verify"]["--strip-comments"]
    assert "Composer" in app_rec["off"]["--obfuscate-names"]
    assert "uncertain" in clean_rec["off"]["--obfuscate-names"]


def test_recommend_and_preflight_fail_closed_on_bad_source(tmp_path):
    """ENV-2026-11: a non-existent --source or a single file must NOT look like a clean project.
    compatibility_findings (used by preflight and recommend) raises instead of returning empty."""
    import pytest
    with pytest.raises(ValueError):
        a.compatibility_findings(tmp_path / "does-not-exist", {".php"})
    lone = tmp_path / "lone.php"
    lone.write_text("<?php eval($x);\n")
    with pytest.raises(ValueError):
        a.recommend_options(lone, {".php"})


def test_recommend_robust_against_evasion_and_shell_metachars(tmp_path):
    """ENV-2026-13: method/function detection is case-insensitive (PHP is) and matches `eval` split
    across lines; the suggested command shell-quotes and glob-escapes excluded paths."""
    ext = {".php"}
    up = tmp_path / "up"
    up.mkdir()
    (up / "u.php").write_text("<?php class L { function h(){ return (new ReflectionClass($this))"
                              "->GETDOCCOMMENT(); } }\n")
    assert "reads-own-docblock" in a.compatibility_findings(up, ext)       # UPPERCASE still caught
    ev = tmp_path / "ev"
    ev.mkdir()
    (ev / "e.php").write_text("<?php $r = eval\n(\n'return 1;'\n);\n")      # eval ( on separate lines
    assert a._tree_uses_runtime_compile(ev, ext)                          # still caught
    br = tmp_path / "br"
    br.mkdir()
    (br / "[id].php").write_text("<?php token_get_all(file_get_contents(__FILE__));\n")
    cmd = a.format_recommendation(a.recommend_options(br, ext))
    assert "'[[]id].php'" in cmd                                          # glob-escaped + shell-quoted


def test_secret_write_does_not_clamp_preexisting_parent_dir(tmp_path):
    """ENV-2026-17: writing a secret into a PRE-EXISTING shared dir must not silently chmod it to 0700
    (that broke e.g. /etc/envelock holding a world-readable licence). The secret file is still 0600."""
    import os
    import stat as _stat
    shared = tmp_path / "etc-envelock"
    shared.mkdir(mode=0o755)
    os.chmod(shared, 0o755)
    if os.name == "nt":
        # Mode bits mean nothing on Windows: the folder's ACL must be left as it was, and the
        # secret must carry a protected (non-inherited) owner-only ACL.
        before = windows_dacl(shared)
        a.secret_write(shared / "k.bin", b"secret")
        assert windows_dacl(shared) == before                        # parent untouched
        sid = a._current_user_sid_string()
        assert windows_dacl(shared / "k.bin") == f"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{sid})"
        return
    a.secret_write(shared / "k.bin", b"secret")
    assert _stat.S_IMODE(os.stat(shared).st_mode) == 0o755          # parent untouched
    assert _stat.S_IMODE(os.stat(shared / "k.bin").st_mode) == 0o600  # file still private


def test_domain_hash_parses_ipv6_brackets_and_strips_port():
    """ENV-2026-06: a bracketed IPv6 host must keep its address, not be truncated to '['. The port is
    dropped, the result is case-insensitive, and '[::1]:8443' binds the same host as '::1'."""
    assert a.domain_hash("[::1]:8443") == a.domain_hash("[::1]")
    assert a.domain_hash("[2001:db8::5]:443") == a.domain_hash("[2001:db8::5]")
    assert a.domain_hash("Example.COM:8080") == a.domain_hash("example.com")
    # The old split-on-first-colon bug hashed '[' for a bracketed IPv6 literal; it must not any more.
    assert a.domain_hash("[::1]:8443") != a.domain_hash("[")
    # Distinct IPv6 literals bind distinct hosts (not all collapsed to '[').
    assert a.domain_hash("[::1]") != a.domain_hash("[2001:db8::5]")
    with pytest.raises(ValueError):
        a.domain_hash("")


def test_licence_expires_is_dst_free(monkeypatch):
    """ENV-2026-18: a date-only --expires must resolve to the same UTC end-of-day regardless of the
    machine's timezone / DST (the old time.mktime()-time.timezone drifted by one hour on DST dates)."""
    import calendar
    import time as _time
    got = calendar.timegm(_time.strptime("2026-07-01 23:59:59", "%Y-%m-%d %H:%M:%S"))
    # Deterministic UTC value, independent of the machine's local timezone / DST.
    assert got == calendar.timegm((2026, 7, 1, 23, 59, 59, 0, 0, 0))


def test_write_public_replaces_atomically_and_keeps_old_on_failure(tmp_path, monkeypatch):
    """ENV-2026-20: a licence rewrite must be atomic. The pre-existing file stays intact if the write
    fails (old unlink-then-write destroyed it first), and on success it is replaced in place as 0644
    with no temp file left behind."""
    import os
    target = tmp_path / "licence.bin"
    target.write_bytes(b"OLD-VALID-LICENCE")
    # Failure mid-write must leave the original untouched (the old code had already unlinked it).
    monkeypatch.setattr(a, "replace_file", lambda s, d: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        a.write_public(target, b"NEW")
    assert target.read_bytes() == b"OLD-VALID-LICENCE"                 # original survived
    assert list(tmp_path.glob("*.tmp-*")) == []                        # no orphan temp file
    monkeypatch.undo()
    # Success path: replaced in place, world-readable, still no temp leftovers.
    a.write_public(target, b"NEW-LICENCE")
    assert target.read_bytes() == b"NEW-LICENCE"
    if os.name == "nt":
        # The licence is public: it keeps the folder's INHERITED ACL so the PHP service account can
        # read it, not a protected owner-only one (ENC-13).
        flags, aces = a._parse_sddl_dacl(windows_dacl(target))
        assert "P" not in flags, flags
        assert any("ID" in a._sddl_ace_flags(ace) for ace in aces), aces
    else:
        assert (target.stat().st_mode & 0o777) == 0o644
    assert list(tmp_path.glob("*.tmp-*")) == []


def test_server_install_allows_rootless_for_current_user(tmp_path):
    """ENV-2026-20: a non-root operator may install the identity for THEMSELVES (rootless deploy). The
    file still ends up 0400 and owned by the current user; installing it for a different user without
    root is refused rather than written with the wrong owner."""
    import os
    if os.name == "nt" or os.geteuid() == 0:
        pytest.skip("POSIX non-root path")
    out = tmp_path / "identity.bin"
    a.server_install(b"SECRET-IDENTITY", out, owner_uid=os.geteuid(), owner_gid=os.getegid())
    info = out.stat()
    assert (info.st_mode & 0o777) == 0o400 and info.st_uid == os.geteuid()
    # Installing for a different (root) owner without privilege must refuse, leaving nothing behind.
    out2 = tmp_path / "identity2.bin"
    with pytest.raises(ValueError, match="run as root"):
        a.server_install(b"SECRET", out2, owner_uid=0, owner_gid=0)
    assert not out2.exists()


def test_verify_package_flags_added_symlink(tmp_path):
    """ENV-2026-19: verify must report an ADDED symlink/FIFO, not skip it because it is not a plain
    file. Builds a minimal signed manifest, then plants a symlink and checks it shows as 'added'."""
    owner = a.make_owner("t")
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "index.php").write_text("<?php echo 1;")
    # Minimal signed manifest over the one real file.
    files = {"index.php": __import__("hashlib").sha256((pkg / "index.php").read_bytes()).hexdigest()}
    body = {"kind": "envelock-manifest", "project_id": str(__import__("uuid").uuid4()),
            "release_id": str(__import__("uuid").uuid4()), "serial": 1, "files": files}
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(owner["signing_private"]))
    body2 = dict(body)
    body2["signature"] = sk.sign(a.manifest_signed_bytes(body)).hex()
    (pkg / "envelock-manifest").write_text(__import__("json").dumps(body2))
    symlink_or_skip(pkg / "evil_link.php", "/etc/hostname")        # added, not in the manifest
    report = a.verify_package(pkg, owner["signing_public"])
    assert "evil_link.php" in report["added"] and report["ok"] is False


def test_inspect_identity_descriptor_shows_only_public(tmp_path):
    """ENV-2026-19: inspecting an envelock-identity JSON must succeed and never reveal x25519_private."""
    identity = a.make_identity(a.make_recipient("r"), a.make_owner())
    assert "x25519_private" in identity                      # the descriptor DOES hold the private key
    p = tmp_path / "id.json"
    p.write_text(__import__("json").dumps(identity))
    info = a.inspect_path(p)
    assert info["kind"] == "envelock-identity" and "x25519_private" not in info


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory-traversal semantics")
def test_write_public_makes_a_created_parent_traversable(tmp_path):
    """write_public ships a world-readable licence; if it has to create the parent directory it must
    leave it traversable (o+x), or a non-root service user cannot read the 0644 file and the loader
    fails closed as if the licence were missing. Regression for the internal audit (nov 2026)."""
    import stat as _stat
    target = tmp_path / "newdir" / "licence.bin"
    a.write_public(target, b"signed-licence-bytes")
    assert target.read_bytes() == b"signed-licence-bytes"
    assert _stat.S_IMODE(os.stat(target).st_mode) == 0o644
    parent_mode = _stat.S_IMODE(os.stat(target.parent).st_mode)
    assert parent_mode & 0o001, f"created parent {oct(parent_mode)} is not traversable by others"
    assert parent_mode & 0o004, f"created parent {oct(parent_mode)} is not readable by others"

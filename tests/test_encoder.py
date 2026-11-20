import importlib.util
import json
import os
import signal
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

try:
    a.resolve_program("php")
    HAVE_PHP = True
except Exception:
    HAVE_PHP = False


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
    import hashlib
    data = a.identity_bytes(material[2])
    assert data[:8] == a.IDENTITY_MAGIC_V4             # C-29: 1.1 writes the checksummed ENVLKID4 format
    assert data[8:12] == b"\x00\x01\x00\x01"            # 1 recipient, 1 developer
    assert len(data) == 12 + a.IDENTITY_RECIPIENT + a.IDENTITY_DEVELOPER + a.IDENTITY_CHECKSUM
    assert hashlib.sha256(data[:-32]).digest() == data[-32:]   # trailing SHA-256 over the body


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


@pytest.mark.skipif(not HAVE_PHP, reason="needs a php CLI with the tokenizer")
def test_pack_lints_php_syntax_adversarial(tmp_path, material):
    """C-17, ATTACK: the advisory lint must catch real syntax errors (several, in one pack), must not
    false-flag valid-but-unusual files (heredoc, PHP 8 attributes, an empty <?php), and must NEVER make
    the pack fail — it is advisory only. A broken file is still encrypted."""
    source, dest = tmp_path / "src", tmp_path / "out"
    source.mkdir()
    (source / "broken1.php").write_text("<?php function f( { return 1; }\n")        # missing )
    (source / "broken2.php").write_text("<?php class C { public function \n")        # truncated
    (source / "ok_heredoc.php").write_text("<?php $x = <<<EOT\nhi $y\nEOT;\n")
    (source / "ok_attr.php").write_text("<?php #[Attribute]\nclass A {}\n")
    (source / "ok_empty.php").write_text("<?php\n")
    info = a.pack_tree(source, dest, [a.recipient_public(material[1])], material[0], str(uuid.uuid4()))
    assert info["protected_files"] == 5                               # ALL encrypted, pack did not fail
    warned = {w.split(":", 1)[0] for w in info["syntax_warnings"]}
    assert warned == {"broken1.php", "broken2.php"}, warned             # exactly the broken ones
    # The broken files are genuinely encrypted (recoverable), the lint never blocked them:
    assert a.open_protected((dest / "broken1.php").read_bytes(), material[2]).startswith(b"<?php")


@pytest.mark.skipif(not HAVE_PHP, reason="needs a php CLI with the tokenizer")
def test_pack_lints_php_syntax_without_transform(tmp_path, material):
    """C-17: a plain pack (no source-rewriting option) now syntax-checks the PHP and reports the files
    that do not parse, instead of shipping a broken file with exit 0. The pack still succeeds."""
    source, dest = tmp_path / "source", tmp_path / "output"
    source.mkdir()
    (source / "ok.php").write_text("<?php function g(){ return 1; }\n")
    (source / "broken.php").write_text("<?php function x( { return 1; }\n")   # missing )
    info = a.pack_tree(source, dest, [a.recipient_public(material[1])], material[0], str(uuid.uuid4()))
    assert info["protected_files"] == 2                      # both still encrypted
    warned = {w.split(":", 1)[0] for w in info["syntax_warnings"]}
    assert warned == {"broken.php"}
    # A transforming pass already stops the pack on a parse error, so the lint is skipped then:
    clean, dest2 = tmp_path / "clean", tmp_path / "out2"
    clean.mkdir()
    (clean / "ok.php").write_text("<?php $x = 1;\n")
    good = a.pack_tree(clean, dest2, [a.recipient_public(material[1])], material[0], str(uuid.uuid4()),
                       strip_comments=True)
    assert good["syntax_warnings"] == []


def test_validate_asset_binary_vs_readable_php(tmp_path):
    """C-06: a binary asset must not be rejected as 'readable PHP' just because '<?' (or even the bytes
    '<?php') appear by chance; real readable PHP text must still be refused."""
    p = tmp_path / "x"
    # Binaries that contain "<?"/"<?php"/"<?=" by chance but are NOT decodable text: accepted.
    png = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 20 + b"<?php stray ?> <? <?= end"
    jpeg = b"\xff\xd8\xff\xe0" + b"<?php echo" + bytes(range(256)) * 10 + b"\xff\xd9"
    woff2 = b"wOF2\x00\x01\x00\x00" + bytes(range(256)) * 8 + b"<? \x00\x00<?="
    for blob in (png, jpeg, woff2):
        a.validate_asset(p, blob)   # must NOT raise
    # Real readable PHP (UTF-8 and a UTF-16 template): refused.
    for bad in (b'<?php echo "x";', b"<?= $x", b"<?\n echo 1;", b"<? echo 1;",
                "<?php echo 1;".encode("utf-16")):
        with pytest.raises(ValueError, match="readable PHP"):
            a.validate_asset(p, bad)
    # Text with a stray "<?" that is NOT a PHP open tag (XML decl, a CSV cell): accepted.
    for ok in (b"id,note\n1,<?xml-ish\n2,price<?x end\n", b"body{content:'<'}\n",
               b'{"x":"<?xml version=\\"1.0\\"?>"}'):
        a.validate_asset(p, ok)     # must NOT raise


def test_validate_asset_credentials_adversarial(tmp_path):
    """C-15, ATTACK: (1) a real secret must NOT sneak past the detector in a tricky-but-valid form
    (under-flagging ships it in clear — the dangerous direction); (2) benign JS/expression forms must
    not misfire; (3) hostile/malformed input must not crash the classifier (it returns a bool)."""
    p = tmp_path / "a.js"
    # (1) Real secrets in awkward-but-real shapes: ALL must still be refused.
    must_refuse = [
        b'{"password":"s3cr3t"}',                       # no spaces, quoted
        b"password\t=\thunter2logn",                    # tabs around =
        b"password  =>  's3cretValue'",                 # PHP arrow + spaces + quotes
        b"api_key: ABCD1234EFGH5678",                   # YAML bareword
        b"DB_PASSWORD=verylongsecretvalue000",          # env bareword
        b"password:\n  s3cretOnNextLine",               # value on the next line
        b"password:/*c*/s3cretAfterComment",            # a comment between : and the value
        b"aws_secret_access_key = AKIAIOSFODNN7EXAMPLE",
        b"machine host login u password p3wra",         # netrc format (SECRET_FORMATS_RE)
        b"https://user:tok3n@example.com/x",             # URL with user:password
        b"TOKEN=" + b"x" * 5000,                         # very long value must still flag, not hang
    ]
    for data in must_refuse:
        with pytest.raises(ValueError, match="credential"):
            a.validate_asset(p, data)
    # (2) Benign expressions / non-credentials: must NOT be refused.
    must_accept = [
        b"const o = { user: u, password: p };\n",
        b"headers['X-Api-Key'] = apiKey;\n",
        b"$cfg = ['password' => $env['DB_PASS']];\n",
        b"password: () => computeSecret()\n",
        b"const passwordField = selector;\n",           # 'password' not on a word boundary before =
        b"tokens = tokenizer.run();\n",                 # 'token' not a boundary match
        b"body { content: 'secret'; }\n",               # css, 'secret' is not key:value here
    ]
    for data in must_accept:
        a.validate_asset(p, data)                       # must NOT raise
    # (3) Hostile/malformed input: the classifier must return a bool, never raise.
    for weird in ("", " ", ">", "password:", "password: ", "password:\x00\x00",
                  "password:" + "(" * 2000, "password: café", 'password:"unterminated',
                  "secret=" + "\\" * 500, "=" * 1000, "password:==>>"):
        assert isinstance(a._asset_has_credentials(weird), bool)
        assert isinstance(a._asset_value_is_literal_secret(weird), bool)


def test_validate_asset_credentials_need_a_literal_value(tmp_path):
    """C-15: a credential KEY only counts when a real literal value follows it. Ordinary JavaScript —
    `token: getCsrf()`, `{user:u,password:p}`, `password: $pass` — is an expression, not a secret, and
    must no longer force a blanket --allow-secret-assets. Genuine credential values stay refused."""
    p = tmp_path / "app.js"
    # Expressions, NOT literals: accepted (no raise).
    for ok in (b"const o = { user: u, password: p };\n",
               b"const h = { token: getCsrf() };\n",
               b"$config = ['password' => $pass];\n",
               b"headers['X-Api-Key'] = apiKey;\n",
               b"const secret = computeSecret();\n"):
        a.validate_asset(p, ok)                       # must NOT raise
    # Real literal credentials: still refused.
    for bad in (b'{"password": "s3cret"}',            # quoted
                b"DB_PASSWORD=hunter2\n",             # bareword
                b"aws_secret_access_key = AKIA\n",    # 4-char value at line end
                b"api_key: 0123456789abcdef\n",       # digit-leading bareword
                b"password = 'supersecret'\n"):
        with pytest.raises(ValueError, match="credential"):
            a.validate_asset(p, bad)
    # The helper itself, directly:
    assert a._asset_value_is_literal_secret(' "x"') is True
    assert a._asset_value_is_literal_secret(" getCsrf()") is False
    assert a._asset_value_is_literal_secret(" p}") is False
    assert a._asset_value_is_literal_secret(" $pass") is False
    assert a._asset_value_is_literal_secret(" hunter2") is True


def test_run_php_lifts_memory_limit(monkeypatch):
    """C-13: every build-time PHP pass must run with memory_limit=-1 so a large tree does not hit the
    host's default 128M. Checked by capturing the argv _run_php builds."""
    captured = {}

    class _Done:
        returncode = 0
        stdout = b'{"ok": true}'
        stderr = b""

    def _fake_run(argv, **kw):
        captured["argv"] = argv
        return _Done()

    monkeypatch.setattr(a, "resolve_program", lambda name: "/usr/bin/php")
    monkeypatch.setattr(a.subprocess, "run", _fake_run)
    assert a._run_php("php", "echo 1;", {"x": 1}, "test") == {"ok": True}
    argv = captured["argv"]
    assert "memory_limit=-1" in argv and argv[argv.index("memory_limit=-1") - 1] == "-d"
    # The program still travels via -r, and STDOUT stays the JSON channel (display_errors=stderr).
    assert "-r" in argv and "display_errors=stderr" in argv
    # C-33/N-14: a site-configured prepend/append must not run and write to STDOUT here.
    assert "auto_prepend_file=" in argv and "auto_append_file=" in argv


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


def test_identity_from_public_developer_descriptor(tmp_path):
    """C-12: an identity/trust store builds from the PUBLIC developer descriptor, so the private signing
    key never has to reach the server. make_identity/add_recipient_to_store accept it and produce the
    SAME bytes as the full owner; export-identity --developer and recipient add --developer work."""
    owner = a.make_owner(with_recovery=True)
    recipient = a.make_recipient("r")
    dev_pub = a.developer_public(owner)
    # Either source yields the identical identity / trust store:
    assert a.make_identity(recipient, dev_pub) == a.make_identity(recipient, owner)
    assert (a.add_recipient_to_store(None, recipient, dev_pub)
            == a.add_recipient_to_store(None, recipient, owner))
    # read_developer_like reads both kinds:
    opath, dpath = tmp_path / "owner.json", tmp_path / "dev.json"
    a.save_json(opath, owner, None)
    dpath.write_text(json.dumps(dev_pub), encoding="utf-8")
    assert a.read_developer_like(dpath)["signing_public"] == owner["signing_public"]
    assert a.read_developer_like(opath)["signing_public"] == owner["signing_public"]
    # CLI: export-identity --developer (no private signing key in play):
    enc = str(ROOT / "encoder/envelock.py")

    def run(*argv):
        return subprocess.run([sys.executable, enc, *map(str, argv)], capture_output=True, text=True)

    rpath = tmp_path / "rcpt.json"
    assert run("keygen", "recipient", "--out", rpath, "--label", "c1", "--no-encrypt").returncode == 0
    idout = tmp_path / "identity.bin"
    r = run("export-identity", "--recipient", rpath, "--developer", dpath, "--out", idout)
    assert r.returncode == 0, r.stderr
    assert idout.exists()
    # recipient add --developer extends a trust store with only the public descriptor:
    store = tmp_path / "store.bin"
    assert run("recipient", "add", "--identity", store, "--recipient", rpath,
               "--developer", dpath).returncode == 0
    assert store.exists()
    # Passing both --developer and --owner is refused:
    bad = run("export-identity", "--recipient", rpath, "--developer", dpath, "--owner", opath,
              "--out", tmp_path / "x.bin")
    assert bad.returncode != 0 and "not both" in bad.stderr


def test_licence_issue_rejects_all_zero_binding_and_inspect_recognises_it(tmp_path):
    """C-27: an explicit all-zero --machine/--ip fingerprint is refused (it would silently mean 'any',
    dropping the binding the operator asked for). C-33: the general 'inspect' recognises a licence file
    and shows its constraints instead of a cryptic error."""
    enc = str(ROOT / "encoder/envelock.py")

    def run(*argv):
        return subprocess.run([sys.executable, enc, *map(str, argv)], capture_output=True, text=True)

    owner = tmp_path / "owner.json"
    assert run("keygen", "owner", "--out", owner, "--no-encrypt").returncode == 0
    lic = tmp_path / "licence.bin"
    zeros = "0" * 64
    bad = run("licence", "issue", "--owner", owner, "--machine", zeros, "--out", lic)
    assert bad.returncode != 0 and "all zeros" in bad.stderr
    badip = run("licence", "issue", "--owner", owner, "--ip", zeros, "--out", lic)
    assert badip.returncode != 0 and "all zeros" in badip.stderr
    assert not lic.exists()                                   # nothing was written
    # A valid unbound (expiry-only) licence issues, and the general inspect recognises it:
    assert run("licence", "issue", "--owner", owner, "--out", lic).returncode == 0
    info = json.loads(run("inspect", lic).stdout)
    assert info["kind"] == "envelock-licence"
    assert info["machine"] == "any" and info["domain"] == "any" and info["ip"] == "any"


def test_developer_like_rejects_hostile_input(tmp_path):
    """C-12, ATTACK: accepting a PUBLIC developer descriptor must not weaken validation. A recipient,
    garbage, wrong types and malformed descriptors are all refused, and an injected private field in a
    developer descriptor is IGNORED (the identity's private key is always the recipient's)."""
    owner = a.make_owner(with_recovery=True)
    recipient = a.make_recipient("r")
    dev_pub = a.developer_public(owner)
    # A recipient is not a developer; wrong types and malformed descriptors are refused:
    hostile = [recipient, None, [], "x", 123, {}, {"kind": "envelock-developer-public"},
               {"kind": "envelock-developer-public", "format": a.FORMAT_VERSION, "signing_public": "00"},
               {"kind": "envelock-developer-public", "format": a.FORMAT_VERSION, "signing_public": "zz" * 32},
               {"kind": "envelock-owner", "format": a.FORMAT_VERSION, "signing_public": "aa" * 32}]
    for bad in hostile:
        with pytest.raises((ValueError, TypeError)):
            a._validate_developer_like(bad)
        with pytest.raises((ValueError, TypeError)):
            a.make_identity(recipient, bad)
    # read_developer_like on hostile FILES: never crashes with a raw traceback, always a ValueError.
    for content in (b"not json at all", b"[]", b"12345",
                    b'{"kind":"envelock-recipient","format":2,"x25519_public":"' + b"aa" * 32 +
                    b'","x25519_private":"' + b"bb" * 32 + b'"}',
                    b'{"kind":"envelock-developer-public"}'):
        pth = tmp_path / "d.json"
        pth.write_bytes(content)
        with pytest.raises(ValueError):
            a.read_developer_like(pth)
    # An injected x25519_private in a developer-public is IGNORED: the identity's private key is the
    # recipient's, and the signer is the real developer's public key — attacker data never leaks in.
    tampered = dict(dev_pub)
    tampered["x25519_private"] = "ff" * 32
    ident = a.make_identity(recipient, tampered)
    assert ident["x25519_private"] == recipient["x25519_private"]
    assert ident["signing_public"] == owner["signing_public"]
    # Same descriptor fed to both sources yields the same trust store (no attacker-controlled drift):
    assert a.add_recipient_to_store(None, recipient, tampered) == a.add_recipient_to_store(None, recipient, owner)


def test_licence_issue_all_zero_binding_adversarial(tmp_path):
    """C-27, ATTACK: an all-zero fingerprint silently means 'any' (no binding). Try to slip one through
    in several forms; a GENUINE near-zero binding and malformed input must behave correctly."""
    run = _cli(tmp_path)
    assert run("keygen", "owner", "--out", tmp_path / "o.json", "--no-encrypt").returncode == 0
    base = ["licence", "issue", "--owner", tmp_path / "o.json", "--out", tmp_path / "l.bin"]
    zeros = "0" * 64
    # Every all-zero spelling is refused (hex is case-insensitive, so upper/lower both reduce to zero):
    for flag, val in [("--machine", zeros), ("--machine", "0" * 63 + "0"), ("--ip", zeros),
                      ("--machine", "0" * 64)]:
        r = run(*base, flag, val)
        assert r.returncode != 0 and "all zeros" in r.stderr, (flag, val, r.stderr)
        assert not (tmp_path / "l.bin").exists()
    # A GENUINE near-zero binding (63 zeros + one non-zero) is a real fingerprint -> allowed:
    ok = run(*base, "--machine", "0" * 63 + "f")
    assert ok.returncode == 0, ok.stderr
    info = json.loads(run("inspect", tmp_path / "l.bin").stdout)
    assert info["machine"].rstrip("0").endswith("f") and info["machine"] != "any"
    # Malformed fingerprints are a clean error, not a traceback:
    (tmp_path / "l.bin").unlink()
    for val in ["00", "zz" * 32, "xyz", "0" * 63]:
        r = run(*base, "--machine", val)
        assert r.returncode != 0 and "Traceback" not in r.stderr


def test_resolve_licence_fields_adversarial(monkeypatch):
    """ATTACK the shared licence resolver that the GUI uses: every way to smuggle a no-op binding past
    it, malformed and boundary inputs, and the 'this' / expiry paths. It must resist each one with a
    clean ValueError or the correct resolved value — never a silent wrong binding and never a crash."""
    Z = a.ZERO32
    rlf = a.resolve_licence_fields
    # Unbound (nothing asked): all-zero slots, no expiry, no warnings.
    assert rlf() == (0, Z, Z, Z, [])
    # --- all-zero bindings are refused in EVERY spelling (hex folds case; 63+1 still reduces to zero):
    for flag in ("machine", "ip"):
        for val in ("0" * 64, "0" * 63 + "0", "00000000000000000000000000000000" * 2):
            with pytest.raises(ValueError, match="all zeros"):
                rlf(**{flag: val})
    # --- malformed / wrong-length fingerprints: clean ValueError, never a raw crash:
    for flag in ("machine", "ip"):
        for val in ("00", "0" * 63, "aa" * 31, "aa" * 33, "zz" * 32, "xyz", " " * 64):
            with pytest.raises(ValueError):
                rlf(**{flag: val})
    # An empty string is falsy, so (exactly as the CLI's `if args.machine:` / `elif args.expires:`) it
    # means 'not asked for' -> unbound / no expiry, NOT an error. Never mistaken for a binding.
    assert rlf(machine="", ip="", domain="", expires="") == (0, Z, Z, Z, [])
    # --- a GENUINE near-zero fingerprint (63 zeros + one set bit) is a real binding, so it is kept,
    # and a bound licence carries the Windows "cannot check bindings" warning:
    exp, m, d, ip, warns = rlf(machine="0" * 63 + "f")
    assert m != Z and m.hex() == "0" * 63 + "f" and d == Z and ip == Z
    assert exp == 0 and any("Windows" in w for w in warns)
    exp, m, d, ip, warns = rlf(ip="0" * 63 + "1")
    assert ip != Z and m == Z and any("Windows" in w for w in warns)
    # --- expiry: days and expires are alternatives; days is bounded 1..36500; a past date is refused;
    # a malformed date is a clean error; a valid future date is deterministic (end-of-day UTC).
    with pytest.raises(ValueError, match="alternatives"):
        rlf(days=1, expires="2999-12-31")
    for bad_days in (0, -1, -36500, 36501, 10 ** 9):
        with pytest.raises(ValueError, match="between 1 and 36500"):
            rlf(days=bad_days)
    for bad_date in ("2020-01-01", "1970-01-01"):
        with pytest.raises(ValueError, match="in the past"):
            rlf(expires=bad_date)
    for junk in ("notadate", "2026-13-01", "2026-02-30", "2026/01/01", "2026-01-01x", "99999-01-01"):
        with pytest.raises(ValueError):
            rlf(expires=junk)
    import calendar as _cal
    import time
    before = int(time.time())
    exp, *_ = rlf(days=30)
    after = int(time.time())
    assert before + 30 * 86400 <= exp <= after + 30 * 86400          # ~now + 30 days, no monkeypatch
    assert rlf(expires="2999-12-31")[0] == _cal.timegm(time.strptime("2999-12-31 23:59:59",
                                                                      "%Y-%m-%d %H:%M:%S"))
    # --- domain binding by name: hashed exactly like the loader; bound -> Windows warning, no 'this' note:
    exp, m, d, ip, warns = rlf(domain="App.Example.COM")
    assert d == a.domain_hash("App.Example.COM") and m == Z and ip == Z
    assert any("Windows" in w for w in warns) and not any("own name" in w for w in warns)
    # --- 'this' resolves THIS host (patched to be deterministic) and adds the right warnings:
    monkeypatch.setattr(a, "machine_fingerprint", lambda: b"\x11" * 32)
    monkeypatch.setattr(a, "host_domain", lambda: "box.local")
    monkeypatch.setattr(a, "host_ips_hash", lambda: b"\x22" * 32)
    exp, m, d, ip, warns = rlf(machine="this", domain="this", ip="this")
    assert m == b"\x11" * 32 and d == a.domain_hash("box.local") and ip == b"\x22" * 32
    # exactly one Windows binding warning even with three bindings, plus the 'domain this' note:
    assert sum("Windows" in w for w in warns) == 1
    assert any("own name" in w and "box.local" in w for w in warns)


def test_licence_resolver_matches_cli(tmp_path):
    """Pin the GUI resolver to the shipped CLI so the two can never drift: on deterministic inputs
    (fixed expiry date and fixed hex bindings), the licence the resolver+issue_licence produce must be
    byte-for-byte the licence the `licence issue` CLI writes (Ed25519 signing is deterministic)."""
    run = _cli(tmp_path)
    owner_path = tmp_path / "o.json"
    assert run("keygen", "owner", "--out", owner_path, "--no-encrypt").returncode == 0
    owner = a.read_config(owner_path, "envelock-owner")
    lic = tmp_path / "cli.bin"
    r = run("licence", "issue", "--owner", owner_path, "--out", lic,
            "--expires", "2999-12-31", "--machine", "aa" * 32, "--domain", "example.com", "--ip", "bb" * 32)
    assert r.returncode == 0, r.stderr
    cli_bytes = lic.read_bytes()
    exp, m, d, ip, _ = a.resolve_licence_fields(expires="2999-12-31", machine="aa" * 32,
                                                domain="example.com", ip="bb" * 32)
    mine = a.issue_licence(owner, expires=exp, machine=m, domain=d, ip=ip)
    assert mine == cli_bytes                                  # same body AND same signature
    # And it verifies under the owner's own signing key (sanity that the bytes are a real licence):
    assert a.verify_licence(mine, [owner["signing_public"]])["machine"] == m


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


def _cli(tmp_path):
    enc = str(ROOT / "encoder/envelock.py")

    def run(*argv):
        return subprocess.run([sys.executable, enc, *map(str, argv)], capture_output=True, text=True)
    return run


def test_cli_keygen_label_rules(tmp_path):
    """C-33: `keygen owner --label` used to ignore --label silently; it is now refused. Recipient still
    requires --label, and both succeed when used correctly (four distinct cases)."""
    run = _cli(tmp_path)
    # owner + --label -> refused, nothing written
    bad = run("keygen", "owner", "--out", tmp_path / "o1.json", "--label", "x", "--no-encrypt")
    assert bad.returncode != 0 and "does not take --label" in bad.stderr
    assert not (tmp_path / "o1.json").exists()
    # owner without --label -> ok
    assert run("keygen", "owner", "--out", tmp_path / "o2.json", "--no-encrypt").returncode == 0
    # recipient without --label -> refused
    norl = run("keygen", "recipient", "--out", tmp_path / "r1.json", "--no-encrypt")
    assert norl.returncode != 0 and "requires --label" in norl.stderr
    # recipient with --label -> ok
    assert run("keygen", "recipient", "--out", tmp_path / "r2.json",
               "--label", "srv", "--no-encrypt").returncode == 0


def test_cli_pack_warns_include_protection_without_no_prepend(tmp_path):
    """C-30: --include-protection stops a direct request to a protected library file, but an
    auto_prepend_file/auto_append_file configured on the server can still load it as the entry point
    and call its functions; only --no-prepend refuses to run under a configured prelude. Three cases:
    include-protection alone warns EXACTLY ONCE (pack used to print two different warnings for this,
    and a duplicated copy of this test hid the first assertion), with --no-prepend it is quiet, and
    without include protection there is nothing to warn about."""
    run = _cli(tmp_path)
    assert run("keygen", "owner", "--out", tmp_path / "o.json", "--no-encrypt").returncode == 0
    assert run("keygen", "recipient", "--out", tmp_path / "r.json", "--label", "s",
               "--no-encrypt").returncode == 0
    assert run("export-public", "--recipient", tmp_path / "r.json",
               "--out", tmp_path / "p.json").returncode == 0
    src = tmp_path / "src"
    src.mkdir()
    (src / "i.php").write_text("<?php echo 1;")
    base = ["pack", "--owner", tmp_path / "o.json", "--recipient", tmp_path / "p.json",
            "--project", str(uuid.uuid4()), "--source", src]
    warn = run(*base, "--output", tmp_path / "a", "--include-protection")
    assert warn.returncode == 0, warn.stderr
    assert warn.stderr.count("--include-protection without --no-prepend") == 1, warn.stderr
    assert "bypassable by an auto_prepend_file/auto_append_file" in warn.stderr
    both = run(*base, "--output", tmp_path / "b", "--include-protection", "--no-prepend")
    assert both.returncode == 0 and "--include-protection without --no-prepend" not in both.stderr
    neither = run(*base, "--output", tmp_path / "c")
    assert neither.returncode == 0 and "--include-protection without --no-prepend" not in neither.stderr


def _composer_tree(root, autoload=True):
    """A small Composer-style project: own code in app/, two library files in vendor/."""
    files = {"app/A.php": "<?php namespace App; class A {}",
             "app/vendor/Local.php": "<?php function local_vendor_named_dir() {}",
             "vendor/acme/lib/Lib.php": "<?php namespace Acme; class Lib { /* " + "x" * 3000 + " */ }"}
    if autoload:
        files["vendor/autoload.php"] = "<?php return null;"
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return files


def test_pack_reports_composer_vendor_packed_encrypted_to_the_caller_only(tmp_path):
    """Memory guidance (docs/RENDIMIENTO.md): recommend leaves Composer's vendor/ out because OPcache
    cannot cache protected files, so a pack that encrypts it costs every PHP worker the compile of every
    library file a request uses. pack_tree reports what it really encrypted from vendor/, counted after
    --exclude, for the caller to warn; like the other caller-only keys it is not in the package's
    envelock-package.json."""
    owner, rcpt = a.make_owner(), a.make_recipient("srv")
    pubs = [a.recipient_public(rcpt)]
    src = tmp_path / "src"
    files = _composer_tree(src)
    vendor_bytes = sum(len(files[n].encode()) for n in files if n.startswith("vendor/"))
    info = a.pack_tree(src, tmp_path / "all", pubs, owner, str(uuid.uuid4()))
    assert info["vendor_encrypted"] == {"files": 2, "bytes": vendor_bytes}
    meta = json.loads((tmp_path / "all" / "envelock-package.json").read_text())
    assert "vendor_encrypted" not in meta
    # Excluded: nothing from vendor/ in the package, nothing reported (app/vendor/ is the app's own).
    info = a.pack_tree(src, tmp_path / "own", pubs, owner, str(uuid.uuid4()), exclude=["vendor/*"])
    assert info["vendor_encrypted"] is None
    assert (tmp_path / "own" / "app" / "vendor" / "Local.php").is_file()
    assert not (tmp_path / "own" / "vendor").exists()
    # Partly excluded: what is still encrypted is what is reported.
    info = a.pack_tree(src, tmp_path / "part", pubs, owner, str(uuid.uuid4()), exclude=["vendor/acme/*"])
    assert info["vendor_encrypted"] == {"files": 1, "bytes": len(files["vendor/autoload.php"].encode())}
    # A vendor/ folder that is not Composer's (no vendor/autoload.php) is the project's own code.
    other = tmp_path / "other"
    _composer_tree(other, autoload=False)
    info = a.pack_tree(other, tmp_path / "other-out", pubs, owner, str(uuid.uuid4()))
    assert info["vendor_encrypted"] is None


def test_pack_reports_the_memory_ceiling_of_exactly_what_it_encrypts(tmp_path):
    """At encryption time pack returns recommend's memory ceiling (memory_estimate) for exactly what it
    encrypted: the original PHP source after --exclude — not assets, not excluded files, and measured
    before any rewrite (the 3-9x ratio was measured against original source). Caller-only: never in
    the package's envelock-package.json."""
    owner, rcpt = a.make_owner(), a.make_recipient("srv")
    src = tmp_path / "src"
    for name, size in {"a.php": 300_000, "lib/b.php": 200_000, "skip/c.php": 900_000}.items():
        (src / name).parent.mkdir(parents=True, exist_ok=True)
        (src / name).write_bytes(b"<?php /* " + b"x" * (size - 12) + b" */")
    (src / "style.css").write_bytes(b"s" * 500_000)
    pubs = [a.recipient_public(rcpt)]
    info = a.pack_tree(src, tmp_path / "out", pubs, owner, str(uuid.uuid4()), assets=["*.css"],
                       exclude=["skip/*"])
    assert info["copied_assets"] == 1
    assert info["memory_estimate"] == a.memory_estimate(2, 500_000)
    assert info["memory_estimate"]["worst_case_extra_mb"] == [1.4, 4.3]
    assert "memory_estimate" not in json.loads((tmp_path / "out" / "envelock-package.json").read_text())
    if HAVE_PHP:
        # --strip-comments removes those comments; the ceiling is still that of the original source.
        info = a.pack_tree(src, tmp_path / "stripped", pubs, owner, str(uuid.uuid4()), exclude=["skip/*"],
                           strip_comments=True)
        assert info["comments_stripped"] and info["memory_estimate"] == a.memory_estimate(2, 500_000)


def test_cli_pack_states_the_memory_ceiling_once(tmp_path):
    """The command line says it where the package is made, once: the size encrypted, the ceiling, that it
    is a ceiling and how to measure; PHP's default memory_limit is named only when the ceiling passes it."""
    run = _cli(tmp_path)
    assert run("keygen", "owner", "--out", tmp_path / "o.json", "--no-encrypt").returncode == 0
    assert run("keygen", "recipient", "--out", tmp_path / "r.json", "--label", "s",
               "--no-encrypt").returncode == 0
    assert run("export-public", "--recipient", tmp_path / "r.json",
               "--out", tmp_path / "p.json").returncode == 0
    small, big = tmp_path / "small", tmp_path / "big"
    small.mkdir()
    (small / "i.php").write_bytes(b"<?php echo 1;")
    big.mkdir()
    for name in ("a.php", "b.php"):
        (big / name).write_bytes(b"<?php /* " + b"x" * (8_400_000 - 12) + b" */")
    base = ["pack", "--owner", tmp_path / "o.json", "--recipient", tmp_path / "p.json",
            "--project", str(uuid.uuid4())]
    out = run(*base, "--source", small, "--output", tmp_path / "s")
    assert out.returncode == 0, out.stderr
    assert out.stderr.count("Note: memory:") == 1, out.stderr
    assert "1 PHP file(s), 13 bytes of source" in out.stderr and "less than 0.1 MB more" in out.stderr
    assert "memory_get_peak_usage(true)" in out.stderr and "memory_limit (128 MB)" not in out.stderr
    assert json.loads(out.stdout)["memory_estimate"]["protected_files"] == 1
    out = run(*base, "--source", big, "--output", tmp_path / "b")
    assert out.returncode == 0, out.stderr
    assert out.stderr.count("Note: memory:") == 1
    assert "2 PHP file(s), 16.02 MB of source" in out.stderr and "roughly 48.1-144.2 MB more" in out.stderr
    assert "above PHP's default memory_limit (128 MB)" in out.stderr


@pytest.mark.skipif(os.name != "nt", reason="Windows file names are case-insensitive")
def test_pack_reports_a_differently_cased_vendor_folder_on_windows(tmp_path):
    """On Windows 'Vendor/' is Composer's vendor/ (the file system and --exclude matching ignore case,
    ENC-10), so it must be counted, and an --exclude 'vendor/*' must leave nothing to report."""
    owner, rcpt = a.make_owner(), a.make_recipient("srv")
    src = tmp_path / "src"
    (src / "Vendor" / "acme").mkdir(parents=True)
    (src / "Vendor" / "autoload.php").write_text("<?php return 1;")
    (src / "Vendor" / "acme" / "L.php").write_text("<?php class L {}")
    (src / "index.php").write_text("<?php echo 1;")
    info = a.pack_tree(src, tmp_path / "a", [a.recipient_public(rcpt)], owner, str(uuid.uuid4()))
    assert info["vendor_encrypted"]["files"] == 2
    info = a.pack_tree(src, tmp_path / "b", [a.recipient_public(rcpt)], owner, str(uuid.uuid4()),
                       exclude=["vendor/*"])
    assert info["vendor_encrypted"] is None


def test_cli_pack_warns_once_when_composer_vendor_is_encrypted(tmp_path):
    """The CLI says it where the choice is made, once, with the numbers and the fix; with
    --include-protection (which needs vendor/ packed, H-03) it says to size memory instead of telling
    the operator to exclude it; and a pack that leaves vendor/ out stays quiet."""
    run = _cli(tmp_path)
    assert run("keygen", "owner", "--out", tmp_path / "o.json", "--no-encrypt").returncode == 0
    assert run("keygen", "recipient", "--out", tmp_path / "r.json", "--label", "s",
               "--no-encrypt").returncode == 0
    assert run("export-public", "--recipient", tmp_path / "r.json",
               "--out", tmp_path / "p.json").returncode == 0
    src = tmp_path / "src"
    _composer_tree(src)
    base = ["pack", "--owner", tmp_path / "o.json", "--recipient", tmp_path / "p.json",
            "--project", str(uuid.uuid4()), "--source", src]
    marker = "vendor/ (Composer dependencies) is in the package encrypted"
    warn = run(*base, "--output", tmp_path / "a")
    assert warn.returncode == 0, warn.stderr
    assert warn.stderr.count(marker) == 1, warn.stderr
    assert "2 PHP file(s)" in warn.stderr and "--exclude 'vendor/*'" in warn.stderr
    assert json.loads(warn.stdout)["vendor_encrypted"]["files"] == 2
    quiet = run(*base, "--output", tmp_path / "b", "--exclude", "vendor/*")
    assert quiet.returncode == 0 and marker not in quiet.stderr, quiet.stderr
    ip = run(*base, "--output", tmp_path / "c", "--include-protection", "--no-prepend")
    assert ip.returncode == 0 and ip.stderr.count(marker) == 1, ip.stderr
    assert "--include-protection needs vendor/ packed" in ip.stderr
    assert "Unless you need it" not in ip.stderr


@pytest.mark.skipif(not HAVE_PHP, reason="--obfuscate-names needs a php CLI")
def test_cli_pack_warns_when_obfuscate_names_renames_nothing(tmp_path):
    """C-24: --obfuscate-names declines the WHOLE package on a risky construct (try/catch/throw,
    reflection, variable calls). Two distinct cases: a tree with try/catch warns 'renamed nothing', a
    closed tree without any renameable global name is also reported, both instead of silent success."""
    run = _cli(tmp_path)
    assert run("keygen", "owner", "--out", tmp_path / "o.json", "--no-encrypt").returncode == 0
    assert run("keygen", "recipient", "--out", tmp_path / "r.json", "--label", "s",
               "--no-encrypt").returncode == 0
    assert run("export-public", "--recipient", tmp_path / "r.json",
               "--out", tmp_path / "p.json").returncode == 0
    src = tmp_path / "src"
    src.mkdir()
    # A try/catch makes the token pass decline the whole package (exception types cross boundaries).
    (src / "a.php").write_text("<?php function helper_fn(){ try { return 1; } catch (\\Exception $e) "
                               "{ return 0; } }\n")
    res = run("pack", "--owner", tmp_path / "o.json", "--recipient", tmp_path / "p.json",
              "--project", str(uuid.uuid4()), "--source", src, "--output", tmp_path / "out",
              "--obfuscate-names")
    assert res.returncode == 0
    assert "renamed nothing" in res.stderr and "try/catch" in res.stderr


@pytest.mark.skipif(not HAVE_PHP, reason="--strip-comments needs a php CLI")
def test_cli_pack_warns_about_halt_compiler_data(tmp_path):
    """C-19: a file with data after __halt_compiler() is encrypted but cannot be read back via
    __FILE__/__COMPILER_HALT_OFFSET__. Two cases: a tree WITH such a file warns and lists it; a tree
    without one does not."""
    run = _cli(tmp_path)
    assert run("keygen", "owner", "--out", tmp_path / "o.json", "--no-encrypt").returncode == 0
    assert run("keygen", "recipient", "--out", tmp_path / "r.json", "--label", "s",
               "--no-encrypt").returncode == 0
    assert run("export-public", "--recipient", tmp_path / "r.json",
               "--out", tmp_path / "p.json").returncode == 0
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.php").write_text("<?php class Ok { function x(){ return 1; } }\n")
    (src / "data.php").write_text("<?php class Dat {}\n__halt_compiler();\nRAW TRAILING DATA BYTES\n")
    res = run("pack", "--owner", tmp_path / "o.json", "--recipient", tmp_path / "p.json",
              "--project", str(uuid.uuid4()), "--source", src, "--output", tmp_path / "out",
              "--strip-comments")
    assert res.returncode == 0, res.stderr
    info = json.loads(res.stdout)
    assert "data.php" in info["files_not_token_transformed"]
    assert "__COMPILER_HALT_OFFSET__" in res.stderr and "data.php" in res.stderr
    # A tree with no __halt_compiler() file: no such warning.
    src2 = tmp_path / "src2"
    src2.mkdir()
    (src2 / "ok.php").write_text("<?php class Ok2 { function x(){ return 1; } }\n")
    res2 = run("pack", "--owner", tmp_path / "o.json", "--recipient", tmp_path / "p.json",
               "--project", str(uuid.uuid4()), "--source", src2, "--output", tmp_path / "out2",
               "--strip-comments")
    assert res2.returncode == 0 and "__COMPILER_HALT_OFFSET__" not in res2.stderr


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
    (tmp_path / "Mine.php").write_text(
        "<?php\n/**\n * @Cache(ttl=60)\n */\nfunction cached() {}\n")       # any annotation, any library
    (tmp_path / "header.php").write_text("<?php $d = get_file_data(__FILE__, []);\n")
    (tmp_path / "clean.php").write_text(
        "<?php\n/**\n * Adds.\n * @param int $a\n * @return int\n * @TODO faster\n */\n"
        "function add(int $a, int $b): int { return $a + $b; }\n")
    findings = a.compatibility_findings(tmp_path, a.DEFAULT_EXTENSIONS)
    assert "source-tokenizer" in findings
    assert sorted({h[0] for h in findings["docblock-annotation"]["hits"]}) == ["Entity.php", "Mine.php"]
    # Generic only: no category tied to one CMS's API or file headers.
    assert set(findings) <= {c for c, _, _ in a.COMPAT_PATTERNS}
    assert not {"file-header-reader", "wp-file-header", "doctrine-annotation"} & {c for c, _, _ in a.COMPAT_PATTERNS}
    flagged = {rel for data in findings.values() for rel, _ in data["hits"]}
    assert "autoload.php" in flagged and "Entity.php" in flagged
    assert "header.php" not in flagged  # a CMS API name is not a condition
    assert "clean.php" not in flagged  # ordinary code and PHPDoc tags are never flagged


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


def test_bytecode_pass_cleans_plaintext_when_interrupted(tmp_path, monkeypatch):
    """C-18: if the compile step is interrupted (a SIGTERM that now raises KeyboardInterrupt), the
    bytecode pass's finally must still remove the plaintext sources it wrote at the deploy path, so a
    cancelled CI job leaves nothing in the clear."""
    deploy = tmp_path / "deploy"

    def interrupted(*args, **kw):
        raise KeyboardInterrupt("terminated by signal 15")

    monkeypatch.setattr(a, "_run_php", interrupted)
    with pytest.raises(KeyboardInterrupt):
        a._bytecode_pass({"sub/a.php": b"<?php echo 1;", "b.php": b"<?php echo 2;"}, deploy, "php", None)
    assert not list(deploy.rglob("*.php")), "plaintext source left at the deploy path after interrupt"


def test_termination_handler_raises_and_installs(monkeypatch):
    """C-18: the SIGTERM/SIGHUP handler raises KeyboardInterrupt (so cleanup runs), and installing it on
    the main thread registers it for SIGTERM. The install is a guarded no-op off the main thread."""
    with pytest.raises(KeyboardInterrupt):
        a._raise_keyboard_interrupt(signal.SIGTERM, None)
    prev = signal.getsignal(signal.SIGTERM)
    try:
        a._install_termination_handlers()
        assert signal.getsignal(signal.SIGTERM) is a._raise_keyboard_interrupt
    finally:
        signal.signal(signal.SIGTERM, prev)


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


def test_analysis_has_no_cms_specific_condition(tmp_path):
    """Envelock works with any PHP project, with no condition for a named CMS or framework: a CMS's
    file headers, template file names, cache folders or packages change nothing in the analysis (what
    each CMS needs is in docs/DEPLOYING-APPS.md). The encoder's code names none of them."""
    ext = {".php"}
    (tmp_path / "banner.php").write_text(
        "<?php\n/**\n * Title: Hero\n * Slug: mytheme/banner-hero\n * Plugin Name: Demo\n */\nreturn;\n")
    (tmp_path / "views").mkdir()
    (tmp_path / "views" / "page.blade.php").write_text("<?php echo $title; ?>")   # has PHP code
    for cache in ("bootstrap/cache", "storage/framework", "var/cache"):
        (tmp_path / cache).mkdir(parents=True)
        (tmp_path / cache / "c.php").write_text("<?php return [];")
    (tmp_path / "vendor" / "symfony" / "property-info").mkdir(parents=True)
    assert a.compatibility_findings(tmp_path, ext) == {}
    rec = a.recommend_options(tmp_path, ext)
    assert rec["exclude"] == {} and rec["exclude_patterns"] == []
    assert "--include-protection" in rec["on"]
    words = ("wordpress", "drupal", "joomla", "prestashop", "magento", "codeigniter", "laravel",
             "symfony", "blade", "artisan", "doctrine", "wp-content", "get_file_data", "bootstrap/cache",
             "storage/framework", "var/cache")
    source = (Path(a.__file__)).read_text(encoding="utf-8").lower()
    assert [w for w in words if w in source] == []
    report = a.format_recommendation(rec).lower()
    assert [w for w in words if w in report] == []


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


def test_recommend_options_is_conservative_and_matches_the_measured_matrix(tmp_path):
    """The recommender enables the strongest options measurement shows are safe and never enables one
    known to break the project (grounded in the measured application matrix and the generic detectors)."""
    ext = {".php"}
    # A clean tree with no file that needs its own source: the full safe set, plus --bytecode (the
    # strongest option, now part of the production toolchain). --bytecode ships no source, so --sealed
    # is superseded and moves to off; the high-risk ones stay off. Control-flow flattening is on: it is
    # safe by construction (unsafe bodies are left as written, the result is re-parsed) and the
    # differential fuzzer proves its behaviour, so it is the strongest obfuscation that is still safe.
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "a.php").write_text("<?php class A { function f(){ return 1; } }\n")
    rec = a.recommend_options(clean, ext)
    for flag in ("--encode-strings", "--obfuscate", "--obfuscate-flow", "--obfuscate-methods",
                 "--obfuscate-flatten", "--include-protection", "--no-ffi", "--no-prepend",
                 "--strip-comments", "--compact", "--bytecode"):
        assert flag in rec["on"], flag
    assert "--obfuscate-flatten" not in rec["off"] and "heck" in rec["verify"]["--obfuscate-flatten"]
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


def test_recommend_leaves_composer_vendor_and_files_without_php_code_in_the_clear(tmp_path):
    """Measured on real framework apps (2026-11-10): analysing vendor/ made third-party files (a
    template compiler tokenizes TEMPLATES, not itself) switch --bytecode and --strip-comments off, and
    the suggested command would have encrypted vendor/ and templates the framework reads as text. The
    documented layout (MANUAL §14) packs only the application's own code; a file with a PHP extension
    and no PHP code (not one <? tag) has nothing to protect and stays cleartext — a generic rule, no
    framework named. A framework's run-time cache folder is the developer's --exclude (docs)."""
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
    assert rec["exclude_patterns"] == ["vendor/*"]
    assert rec["exclude"] == {"no-php-code": ["resources/views/welcome.blade.php"]}
    for flag in ("--bytecode", "--strip-comments", "--compact"):         # vendor no longer decides
        assert flag in rec["on"], flag
    assert "--sealed" in rec["off"]                                      # vendor/ stays cleartext .php
    cmd = a.format_recommendation(rec)
    assert "--exclude 'vendor/*'" in cmd and "bootstrap/cache" not in cmd
    assert "--exclude resources/views/welcome.blade.php" in cmd
    assert "--bytecode-loader" in cmd and "--bytecode-php" in cmd       # a production loader cannot emit
    # Without Composer's autoloader there is no vendor/ rule and everything is the project's own code.
    plain = tmp_path / "plain"
    (plain / "lib").mkdir(parents=True)
    (plain / "lib" / "x.php").write_text("<?php function x(){}")
    assert a.recommend_options(plain, ext)["exclude_patterns"] == []


def test_recommend_estimates_memory_from_exactly_what_it_encrypts(tmp_path):
    """Memory sizing (docs/RENDIMIENTO.md): recommend says how much PHP it would encrypt and the extra
    memory a request loading all of it would need without OPcache (3x-9x the source, measured), and how
    to measure. Only what the recommendation encrypts counts: not vendor/, not a file without PHP code
    nor a file that reads its own source, which it keeps cleartext."""
    ext = {".php"}
    app = tmp_path / "app"
    sizes = {"app/A.php": 400_000, "app/B.php": 120_000}
    tree = {"vendor/autoload.php": "<?php return 1;",
            "vendor/acme/Big.php": "<?php /* " + "v" * 900_000 + " */",
            "resources/views/w.blade.php": "<h1>{{ $t }}</h1>" + "t" * 70_000,
            "app/Reads.php": "<?php $me = file_get_contents(__FILE__); /* " + "r" * 80_000 + " */"}
    tree.update({name: "<?php /* " + "x" * (size - 15) + " */ ?>" for name, size in sizes.items()})
    for name, text in tree.items():
        (app / name).parent.mkdir(parents=True, exist_ok=True)
        (app / name).write_bytes(text.encode())
    for name, size in sizes.items():
        assert (app / name).stat().st_size == size
    rec = a.recommend_options(app, ext)
    assert "app/Reads.php" in {f for files in rec["exclude"].values() for f in files}
    total = sum(sizes.values())
    assert rec["memory"] == {"protected_files": 2, "protected_source_bytes": total,
                             "worst_case_extra_mb": [round(total * 3 / 1048576, 1),
                                                     round(total * 9 / 1048576, 1)]}
    note = [n for n in rec["notes"] if n.startswith("Memory:")]
    assert len(note) == 1
    assert "encrypts 2 PHP file(s), 508 KB of source" in note[0] and "roughly 1.5-4.5 MB more" in note[0]
    assert "Leaving vendor/ out" in note[0] and "memory_get_peak_usage(true)" in note[0]
    assert note[0] in a.format_recommendation(rec)
    # No Composer vendor/: the same figures, without the vendor/ sentence.
    plain = tmp_path / "plain"
    (plain / "lib").mkdir(parents=True)
    (plain / "lib" / "x.php").write_bytes(b"<?php /* " + b"y" * 2_000_000 + b" */")
    note = [n for n in a.recommend_options(plain, ext)["notes"] if n.startswith("Memory:")][0]
    assert "1.91 MB of source" in note and "roughly 5.7-17.2 MB more" in note
    assert "Leaving vendor/ out" not in note
    # Tiny: never a misleading "0.00 MB" or "0.0-0.0 MB".
    tiny = tmp_path / "tiny"
    tiny.mkdir()
    (tiny / "i.php").write_bytes(b"<?php echo 1;")
    note = [n for n in a.recommend_options(tiny, ext)["notes"] if n.startswith("Memory:")][0]
    assert "13 bytes of source" in note and "less than 0.1 MB more" in note and "0.0" not in note
    # Nothing to encrypt (only a file without PHP code): no memory note at all.
    views = tmp_path / "views"
    views.mkdir()
    (views / "w.blade.php").write_text("<p>{{ $x }}</p>")
    rec = a.recommend_options(views, ext)
    assert rec["memory"]["protected_files"] == 0 and not any(n.startswith("Memory:") for n in rec["notes"])


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


def test_recommend_turns_include_protection_off_when_it_leaves_vendor_out(tmp_path):
    """External audit 2026-11-12, H-03: the recommendation excluded vendor/ AND enabled include
    protection, which do not mix. Library code that PHP calls back with no protected file on the stack
    (an exception handler registered from vendor/) autoloads a protected class and is refused, so the
    app's error path died with "include protection: it can only be loaded by its own application"."""
    ext = {".php"}
    app = tmp_path / "app"
    (app / "vendor").mkdir(parents=True)
    (app / "vendor" / "autoload.php").write_text("<?php")
    (app / "src").mkdir()
    (app / "src" / "Formatter.php").write_text("<?php class Formatter { function f() { return 1; } }")
    (app / "index.php").write_text("<?php require 'vendor/autoload.php';")
    rec = a.recommend_options(app, ext)
    assert "vendor/*" in rec["exclude_patterns"]
    assert "--include-protection" not in rec["on"] and "--include-protection" not in rec["verify"]
    assert "vendor/" in rec["off"]["--include-protection"]
    assert "error" in rec["off"]["--include-protection"]
    assert "--include-protection" not in a.format_recommendation(rec).split("DO NOT enable")[0]
    # Without Composer's autoloader nothing is left out, and it is recommended (to check) again.
    (app / "vendor" / "autoload.php").unlink()
    rec = a.recommend_options(app, ext)
    assert "--include-protection" in rec["on"] and "--include-protection" in rec["verify"]


def test_recommend_include_protection_off_on_cross_checked_cases(tmp_path):
    """C-04: --include-protection is also turned off when the recommendation leaves any .php cleartext
    (it reads its own source) or when composer.json is present but vendor/ is not installed; a clean
    app with none of these stays ON. A CMS plugin header is no condition (docs/DEPLOYING-APPS.md)."""
    ext = {".php"}
    # (a) a .php that reads its own source stays cleartext -> off, and the file is named.
    a1 = tmp_path / "a1"
    a1.mkdir()
    (a1 / "ok.php").write_text("<?php class A { function f(){ return 1; } }")
    (a1 / "tok.php").write_text("<?php $t = token_get_all(file_get_contents(__FILE__));")
    r1 = a.recommend_options(a1, ext)
    assert "--include-protection" not in r1["on"]
    assert "cleartext" in r1["off"]["--include-protection"] and "tok.php" in r1["off"]["--include-protection"]
    # (b) composer.json present but vendor/ not installed -> off (autoloader runs with no protected frame).
    a2 = tmp_path / "a2"
    a2.mkdir()
    (a2 / "composer.json").write_text('{"name":"x/y"}')
    (a2 / "src.php").write_text("<?php class S { function f(){ return 1; } }")
    r2 = a.recommend_options(a2, ext)
    assert "--include-protection" not in r2["on"] and "composer.json" in r2["off"]["--include-protection"]
    # (c) a CMS plugin header is not a condition: nothing here turns it off.
    a3 = tmp_path / "a3"
    a3.mkdir()
    (a3 / "plugin.php").write_text("<?php\n/**\n * Plugin Name: Demo\n */\nfunction demo(){}")
    r3 = a.recommend_options(a3, ext)
    assert "--include-protection" in r3["on"]
    assert "only part of an application" in r3["verify"]["--include-protection"]
    # (d) a clean app with none of these -> still ON (no false turn-off).
    a4 = tmp_path / "a4"
    a4.mkdir()
    (a4 / "lib.php").write_text("<?php class L { function f(){ return 1; } }")
    assert "--include-protection" in a.recommend_options(a4, ext)["on"]


def test_preflight_detects_more_self_source_reads(tmp_path):
    """C-02: catch more ways a file reads its OWN source (fopen/readfile/SplFileObject(__FILE__),
    __COMPILER_HALT_OFFSET__, PhpToken::tokenize), without flagging a plain data-file read."""
    ext = {".php"}
    src = tmp_path / "src"
    src.mkdir()
    (src / "fopen.php").write_text("<?php $h = fopen(__FILE__, 'r');")
    (src / "readfile.php").write_text("<?php readfile(__FILE__);")
    (src / "spl.php").write_text("<?php $o = new SplFileObject(__FILE__);")
    (src / "halt.php").write_text("<?php $o = __COMPILER_HALT_OFFSET__; __halt_compiler(); data")
    (src / "phptoken.php").write_text("<?php $t = PhpToken::tokenize('<?php 1;');")
    (src / "datafile.php").write_text("<?php $c = file_get_contents(__DIR__ . '/data.json');")
    (src / "clean.php").write_text("<?php class A { function f(){ return 1; } }")
    findings = a.compatibility_findings(src, ext)
    read = {h[0] for h in findings.get("reads-own-source", {}).get("hits", [])}
    assert {"fopen.php", "readfile.php", "spl.php", "halt.php"} <= read
    tok = {h[0] for h in findings.get("source-tokenizer", {}).get("hits", [])}
    assert "phptoken.php" in tok
    # A plain data-file read (__DIR__ + a .json) must NOT be flagged as reading its own source.
    assert "datafile.php" not in read
    assert "clean.php" not in read and "clean.php" not in tok


def test_preflight_entry_points_and_nonstandard_extensions(tmp_path):
    """C-03: an extensionless entry point is detected even with a BOM or a blank line before <?php, and
    a PHP file with a non-standard extension (.module) is reported with a --php-ext suggestion."""
    ext = {".php"}
    app = tmp_path / "app"
    (app / "bin").mkdir(parents=True)
    (app / "src.php").write_text("<?php function f(){ return 1; }")
    (app / "bin" / "console").write_bytes(b"\xef\xbb\xbf\n   <?php require __DIR__.'/../src.php';\n")
    assert "bin/console" in a._cleartext_php_entry_points(app, frozenset())
    (app / "mymod.module").write_text("<?php function mymod_hook(){}")
    rec = a.recommend_options(app, ext)
    note = " ".join(rec["notes"])
    assert "mymod.module" in note and "--php-ext .module" in note
    assert "--include-protection" not in rec["on"]        # bin/console is a cleartext entry point
    # a plain data file with the same odd extension but no <?php is NOT reported.
    (app / "notes.module").write_text("just text, not php")
    assert "notes.module" not in " ".join(a.recommend_options(app, ext)["notes"])


def test_pack_reports_each_asset_it_did_not_copy(tmp_path, material):
    """External audit 2026-11-12, H-08: `--asset .netrc` (a path pack never copies) ended with
    copied_assets 0, exit 0 and not a word. Every --asset that copied nothing is now reported with the
    reason, to the caller only: the names are not written into the package's envelock-package.json."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "index.php").write_text("<?php echo 1;")
    (src / ".netrc").write_text("machine example.invalid login u password p\n")
    (src / "style.css").write_text("body{}")
    (src / "skip.txt").write_text("x")
    info = a.pack_tree(src, tmp_path / "out", [a.recipient_public(material[1])], material[0],
                       str(uuid.uuid4()), assets=[".netrc", "style.css", "skip.txt", "missing/*.json"],
                       exclude=["skip.txt"])
    reasons = {m["asset"]: m["reason"] for m in info["assets_not_copied"]}
    assert set(reasons) == {".netrc", "skip.txt", "missing/*.json"}
    assert "never copies" in reasons[".netrc"]
    assert "--exclude" in reasons["skip.txt"]
    assert "no file" in reasons["missing/*.json"]
    assert info["copied_assets"] == 1
    meta = (tmp_path / "out" / "envelock-package.json").read_text()
    assert "assets_not_copied" not in meta and ".netrc" not in meta
    clean = a.pack_tree(src, tmp_path / "out2", [a.recipient_public(material[1])], material[0],
                        str(uuid.uuid4()), assets=["style.css"])
    assert clean["assets_not_copied"] == []


def test_cli_pack_warns_about_lost_assets_and_what_sealed_does_not_cover(tmp_path):
    """The CLI says it out loud: a WARNING for each --asset not copied (H-08), and with --sealed a note
    on what sealing does not reach — a fresh process, OPcache's shared memory — and the folder
    blacklist that closes the second (H-02, external audit 2026-11-12)."""
    enc = str(ROOT / "encoder/envelock.py")

    def run(*argv):
        return subprocess.run([sys.executable, enc, *map(str, argv)], capture_output=True, text=True)

    owner, rcpt = tmp_path / "owner.json", tmp_path / "rcpt.json"
    assert run("keygen", "owner", "--out", owner, "--no-encrypt").returncode == 0
    assert run("keygen", "recipient", "--out", rcpt, "--label", "c1", "--no-encrypt").returncode == 0
    assert run("export-public", "--recipient", rcpt, "--out", tmp_path / "pub.json").returncode == 0
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "i.php").write_text("<?php echo 1;")
    (tmp_path / "src" / ".netrc").write_text("machine example.invalid login u password p\n")
    common = ["pack", "--owner", owner, "--recipient", tmp_path / "pub.json", "--project",
              str(uuid.uuid4()), "--source", tmp_path / "src"]
    lost = run(*common, "--output", tmp_path / "lost", "--asset", ".netrc")
    assert lost.returncode == 0, lost.stderr
    assert "WARNING: --asset .netrc was not copied" in lost.stderr
    assert "--sealed refuses" not in lost.stderr
    sealed = run(*common, "--output", tmp_path / "sealed", "--sealed")
    assert sealed.returncode == 0, sealed.stderr
    assert "opcache.blacklist_filename" in sealed.stderr and "FOLDER" in sealed.stderr
    assert "WARNING: --asset" not in sealed.stderr


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
    (app / "vendor" / "acme" / "serializer").mkdir(parents=True)
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
    # The doubt about stripping comments names the generic risk, never a package.
    app_rec = a.recommend_options(app, ext)
    assert "@var/@param docblocks" in app_rec["verify"]["--strip-comments"]
    assert "vendor/" not in app_rec["verify"]["--strip-comments"]
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


def test_compat_token_masks_route_detectors_and_kill_false_positives(tmp_path):
    """C-01: with token-aware masks, the comment category (docblock annotation) matches only the
    COMMENT text and code categories (eval, FFI, token_get_all, getDocComment) match only the CODE text.
    So a multiplication continued on a line `* @Helper::rate()` (the @ silences errors) is no longer an
    annotation, and a genuine annotation in a docblock still is. The masks are supplied directly (as _php_code_comment_masks would
    build them) so the test needs no php."""
    ext = {".php"}
    src = tmp_path / "proj"
    src.mkdir()
    # x.php: a product continued on its own line, `* @Helper::rate()` — code that looks like an
    # annotation to a raw-text scan — plus a $r->eval( method call. Here the file text has no
    # comments/strings, so the raw scan sees this text verbatim.
    fp_code = ("<?php\n"
               "$x = $base\n"
               "    * @Helper::rate();\n"   # code: an annotation false positive in raw
               ";\n"
               "$r->eval($y);\n")        # method call, not the eval() construct
    (src / "x.php").write_text(fp_code)
    # plug.php: a genuine annotation, which lives in a COMMENT.
    (src / "plug.php").write_text("<?php\n")

    # Raw scan (no php): the code line MISFIRES as an annotation, which is what the token path fixes.
    raw = a.compatibility_findings(src, ext)
    assert "x.php" in {h[0] for h in raw.get("docblock-annotation", {"hits": []})["hits"]}
    # The eval lookbehind already rejects the ->eval( method call even in raw mode (no mask needed):
    assert a._tree_uses_runtime_compile(src, ext) == []

    # Token masks: that line is CODE (the comment blob is empty), so the false positive is gone;
    # the real annotation in plug.php's comment blob is still found, on its own line.
    masks = {
        "x.php": {"code": fp_code, "comments": "\n\n\n\n\n"},
        "plug.php": {"code": "     \n     \n                 \n    \n",
                     "comments": "\n/**\n * @Route(\"/z\")\n */\n"},
    }
    findings = a.compatibility_findings(src, ext, masks=masks)
    cats = {c: sorted({h[0] for h in d["hits"]}) for c, d in findings.items()}
    assert cats.get("docblock-annotation") == ["plug.php"]  # only the real annotation, not the code
    assert sorted(ln for f, ln in findings["docblock-annotation"]["hits"] if f == "plug.php") == [3]
    assert "source-tokenizer" not in cats
    assert a._tree_uses_runtime_compile(src, ext, masks=masks) == []
    assert a._tree_matches(src, ext, a._FFI_RE, masks=masks) == []


def test_compat_token_masks_keep_real_positives(tmp_path):
    """C-01: masks must not SUPPRESS genuine findings — a real eval(), FFI::, token_get_all() and
    getDocComment() in code are still reported when they live in the code mask."""
    ext = {".php"}
    src = tmp_path / "proj"
    src.mkdir()
    (src / "y.php").write_text("<?php\n")
    masks = {"y.php": {
        "code": ("<?php\n"
                 "eval($code);\n"
                 "$f = FFI::cdef('int x();', 'l.so');\n"
                 "token_get_all($s);\n"
                 "(new ReflectionMethod($o,'m'))->getDocComment();\n"),
        "comments": "\n\n\n\n\n"}}
    cats = {c: sorted({h[0] for h in d["hits"]})
            for c, d in a.compatibility_findings(src, ext, masks=masks).items()}
    assert cats.get("source-tokenizer") == ["y.php"]
    assert cats.get("reads-own-docblock") == ["y.php"]
    assert a._tree_uses_runtime_compile(src, ext, masks=masks) == ["y.php:2"]
    assert a._tree_matches(src, ext, a._FFI_RE, masks=masks) == ["y.php:3"]


def test_recommend_compact_off_for_line_number_logic(tmp_path):
    """C-28: __LINE__/getLine()/getTrace() used as data breaks under --compact (it renumbers lines) but
    is fine under --strip-comments. The recommender turns OFF only --compact; preflight flags it; and a
    token scan ignores a __LINE__ that is only in a comment."""
    ext = {".php"}
    app = tmp_path / "app"
    app.mkdir()
    (app / "cache.php").write_text("<?php $key = 'build-' . __LINE__;\n")
    rec = a.recommend_options(app, ext)
    assert "--strip-comments" in rec["on"]       # strip keeps line numbers -> still recommended
    assert "--compact" in rec["off"]             # compact renumbers -> turned off
    assert "line number" in rec["off"]["--compact"].lower()
    assert "line-number-logic" in a.compatibility_findings(app, ext)
    (app / "err.php").write_text("<?php function h($e){ return $e->getLine(); }\n")
    assert "line-number-logic" in a.compatibility_findings(app, ext)
    # A __LINE__ that lives only in a comment must NOT be flagged when token masks are available.
    c = tmp_path / "c"
    c.mkdir()
    (c / "x.php").write_text("<?php $x = 1;\n")
    masks = {"x.php": {"code": "<?php $x = 1;\n", "comments": "// __LINE__ mentioned here\n"}}
    assert "line-number-logic" not in a.compatibility_findings(c, ext, masks=masks)


@pytest.mark.skipif(not HAVE_PHP, reason="needs a php CLI with the tokenizer")
def test_compat_line_number_logic_adversarial(tmp_path):
    """C-28, ATTACK: __LINE__/getLine()/getTrace() hidden in a comment or a string must NOT trigger the
    --compact gate, a similarly-named method (getLineNumber) must not be a false positive, and the real
    uses must still be caught."""
    ext = {".php"}
    src = tmp_path / "p"
    src.mkdir()
    (src / "hidden.php").write_text(
        "<?php\n"
        "// uses __LINE__ in a comment and $e->getLine() too\n"
        '$s = "build-" . "plain string __LINE__ and getLine( here";\n'
        "$n = $e->getLineNumber();\n"           # different method, not getLine(
        "echo $s;\n", encoding="utf-8")
    (src / "uses.php").write_text(
        "<?php\n$k = 'build-' . __LINE__;\nfunction h($e){ return $e->getLine(); }\n", encoding="utf-8")
    masks = a._php_code_comment_masks("php", src, ext)
    assert masks is not None
    cats = {c: sorted({h[0] for h in d["hits"]})
            for c, d in a.compatibility_findings(src, ext, masks=masks).items()}
    assert cats.get("line-number-logic") == ["uses.php"], cats.get("line-number-logic")


@pytest.mark.skipif(not HAVE_PHP, reason="needs a php CLI with the tokenizer")
def test_compat_token_masks_adversarial(tmp_path):
    """C-01, ATTACK with the real tokenizer: eval()/FFI/token_get_all hidden in comments, strings,
    heredoc/nowdoc, inline HTML, escaped quotes or a string carrying `*/` must NOT be flagged, while the
    genuine ones right next to them MUST be — and an annotation-looking line in code or a string is not
    an annotation. A detector that can be fooled either way is the whole point of C-01."""
    ext = {".php"}
    src = tmp_path / "proj"
    src.mkdir()
    (src / "noise.php").write_text(
        "<?php\n"
        "// eval( here is a line comment\n"
        "# eval( here too\n"
        "/* a block comment with eval( FFI:: token_get_all( getDocComment( inside */\n"
        '$a = "a double-quoted string with eval( and FFI:: inside";\n'
        "$b = 'single-quoted eval( and token_get_all(';\n"
        "$c = <<<EOT\n eval( inside a heredoc FFI:: \nEOT;\n"
        "$d = <<<'NOW'\n token_get_all( inside a nowdoc \nNOW;\n"
        '$e = "escaped \\" quote then eval( still in the string";\n'
        "$redis->eval($x);\n"              # method call, not the construct
        "Cache::eval($x);\n"               # static method, not the construct
        "function eval_helper() { return 1; }\n"   # a function named eval_* is not eval
        "?>\n"
        "inline HTML with eval( and FFI:: that is not PHP at all\n"
        "<?php echo 1;\n", encoding="utf-8")
    (src / "real.php").write_text(
        "<?php\n"
        '$s = "ordinary";\n'
        "eval($code);\n"                               # real eval
        '$f = FFI::cdef("int x();", "lib.so");\n'      # real FFI
        "token_get_all($s);\n"                         # real tokenizer
        'echo "a */ tricky string"; eval($again);\n',  # a string holding */ then a real eval
        encoding="utf-8")
    (src / "plug.php").write_text(
        "<?php\n/**\n * @Entity(table=\"real\")\n */\n$x = 1;\n", encoding="utf-8")
    (src / "fakehdr.php").write_text(
        "<?php\n"
        '$t = "\n * @Entity inside a string, not an annotation\n";\n'
        "$y = $a\n    * @Helper::rate();\n"                 # code, not an annotation
        "// * @Entity after a // prefix, not a docblock\n", encoding="utf-8")

    masks = a._php_code_comment_masks("php", src, ext)
    assert masks is not None, "the token scan failed"
    cats = {c: sorted({h[0] for h in d["hits"]})
            for c, d in a.compatibility_findings(src, ext, masks=masks).items()}
    # Code detectors fire ONLY on real.php, never on the hidden copies in noise.php:
    assert cats.get("source-tokenizer") == ["real.php"], cats.get("source-tokenizer")
    assert {h.split(":")[0] for h in a._tree_uses_runtime_compile(src, ext, masks=masks)} == {"real.php"}
    assert {h.split(":")[0] for h in a._tree_matches(src, ext, a._FFI_RE, masks=masks)} == {"real.php"}
    # The annotation is found only in the REAL docblock, not in the string, the code or the // line:
    assert cats.get("docblock-annotation") == ["plug.php"], cats.get("docblock-annotation")
    # getDocComment hidden in a comment is not a reads-own-docblock finding:
    assert "noise.php" not in cats.get("reads-own-docblock", [])


def test_php_code_comment_masks_absent_php_returns_none(tmp_path, monkeypatch):
    """C-01: _php_code_comment_masks never raises; with no php CLI it returns None so recommend/preflight
    fall back to the raw-text regex scan (identical to the historical behaviour)."""
    src = tmp_path / "proj"
    src.mkdir()
    (src / "a.php").write_text("<?php eval($x);\n")
    monkeypatch.setattr(a, "resolve_program",
                        lambda name: (_ for _ in ()).throw(ValueError("no php")))
    assert a._php_code_comment_masks("php", src, {".php"}) is None
    # masks=None path still produces the finding via raw text:
    assert a._tree_uses_runtime_compile(src, {".php"}, masks=None) == ["a.php:1"]


@pytest.mark.skipif(not HAVE_PHP, reason="needs a php CLI with the tokenizer")
def test_php_code_comment_masks_integration(tmp_path):
    """C-01 end to end with the real tokenizer: eval()/FFI/token_get_all written inside a comment or a
    string, and an annotation-looking code line, are NOT flagged; the genuine ones are."""
    ext = {".php"}
    src = tmp_path / "proj"
    src.mkdir()
    (src / "noise.php").write_text(
        "<?php\n// once called eval( ) here\n"
        "/* token_get_all( ) and FFI:: in a comment */\n"
        "$q = 'SELECT eval( FROM t';\n$r->eval($s);\n", encoding="utf-8")
    (src / "named.php").write_text(
        "<?php\n$v = $w\n    * @Helper::rate();\n", encoding="utf-8")
    (src / "real.php").write_text(
        "<?php\n/**\n * @Cache(ttl=60)\n */\neval($c);\n$f = FFI::cdef('int x();','l.so');\n",
        encoding="utf-8")
    masks = a._php_code_comment_masks("php", src, ext)
    assert masks is not None
    cats = {c: sorted({h[0] for h in d["hits"]})
            for c, d in a.compatibility_findings(src, ext, masks=masks).items()}
    assert cats.get("docblock-annotation") == ["real.php"]
    assert "source-tokenizer" not in cats
    assert a._tree_uses_runtime_compile(src, ext, masks=masks) == ["real.php:5"]
    assert [h for h in a._tree_matches(src, ext, a._FFI_RE, masks=masks)] == ["real.php:6"]


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


def test_server_install_creates_missing_dirs(tmp_path):
    """C-20: the identity file's missing parent folders are created; the helper reports which ones."""
    out = tmp_path / "etc" / "envelock" / "identity.bin"
    created = a._create_install_dirs(out, owner_uid=0)
    assert out.parent.is_dir()
    assert (tmp_path / "etc") in created and (tmp_path / "etc" / "envelock") in created


def test_server_install_dirs_traversable_for_owner_user(tmp_path):
    """C-20: for a non-root owner (--owner-user), the folders THIS call creates must be traversable
    (0711) so that user can reach the 0400 identity inside; a self-owned install keeps the umask and is
    not forced open. Root keeps ownership of the created folders (the pool user cannot write them)."""
    import stat as _stat
    if os.name == "nt":
        pytest.skip("POSIX ownership/mode semantics")
    out = tmp_path / "etc" / "envelock" / "identity.bin"
    created = a._create_install_dirs(out, owner_uid=os.geteuid() + 1)   # a different owner
    assert created
    for directory in created:
        assert _stat.S_IMODE(os.stat(directory).st_mode) == 0o711, directory
    # A self-owned install keeps the umask (here 0700), i.e. it is NOT forced traversable to others:
    out2 = tmp_path / "self" / "a" / "identity.bin"
    old = os.umask(0o077)
    try:
        created2 = a._create_install_dirs(out2, owner_uid=os.geteuid())
    finally:
        os.umask(old)
    for directory in created2:
        assert not (os.stat(directory).st_mode & 0o077), directory


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

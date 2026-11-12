"""scripts/check_release.py must catch private material wherever the scanned tree lives."""

import json
import subprocess
import sys

import pytest
from test_encoder import ROOT, a

GUARD = str(ROOT / "scripts/check_release.py")


def guard(path, *extra):
    return subprocess.run([sys.executable, GUARD, *extra, str(path)], capture_output=True, text=True)


def test_require_complete_flags_an_incomplete_release(tmp_path):
    """ENV-2026-01: --require-complete fails when a required entry point (here the vendored PHP-Parser)
    is missing from the assembled tree, so an incomplete release ZIP is caught; without the flag the
    privacy guard ignores completeness, and with every required file present it passes."""
    _fake_repository(tmp_path, [])
    # Default privacy scan ignores completeness: an incomplete tree still passes the privacy guard.
    assert guard(tmp_path).returncode == 0
    # With the flag, the missing required entry points (the vendored PHP-Parser among them) are reported.
    missing = guard(tmp_path, "--require-complete")
    assert missing.returncode == 1
    assert "php-parser" in missing.stdout and "incomplete archive" in missing.stdout
    # A file listed in a hash-locked folder's SHA256SUMS but dropped from the tree (a packager that
    # skips Makefiles or *.zip by name) makes the archive incomplete too.
    lib = tmp_path / "third_party" / "lib-1.0"
    lib.mkdir(parents=True)
    (lib / "Makefile").write_text("all:\n")
    (lib / "README").write_text("upstream\n")
    _manifest(tmp_path / "third_party")
    (lib / "Makefile").unlink()
    assert guard(tmp_path).returncode == 0
    dropped = guard(tmp_path, "--require-complete").stdout
    assert "third_party/lib-1.0/Makefile: listed in third_party/SHA256SUMS but missing" in dropped
    assert "lib-1.0/README" not in dropped
    # The real repository, which HAS every required file, passes the completeness check -- on a
    # case-insensitive filesystem (NTFS) too, where prebuilt/'s case-only name pairs cannot coexist.
    real = guard(ROOT, "--require-complete")
    assert "not listed in" not in real.stdout and "differs from its hash" not in real.stdout, real.stdout
    missing = [line for line in real.stdout.splitlines() if "incomplete archive" in line]
    assert not missing, f"{len(missing)} required/listed file(s) missing, e.g. {missing[:3]}"
    if (ROOT / ".git").is_dir():
        assert real.returncode == 0, real.stdout
    else:
        # A copy of the repository without a live .git (e.g. an extracted source archive): the only
        # findings allowed are tool/cache folders it would publish (e.g. a .ruff_cache).
        reported = [line for line in real.stdout.splitlines() if line.startswith("  ")]
        assert all("not a live git checkout" in line for line in reported), real.stdout


def test_clean_tree_passes(tmp_path):
    (tmp_path / "README.md").write_text("Nothing private here.\n")
    assert guard(tmp_path).returncode == 0


@pytest.mark.parametrize("parent", ["release", "private", "build"])
def test_scanned_root_inside_a_skipped_name_is_still_scanned(tmp_path, parent):
    """Checking a staged tree such as release/client-001 must not pass vacuously."""
    staged = tmp_path / parent / "client-001"
    staged.mkdir(parents=True)
    (staged / "owner.json").write_text(json.dumps(a.make_owner()))
    result = guard(staged)
    assert result.returncode == 1 and "owner.json" in result.stdout


def test_project_url_allowed_but_other_personal_refs_flagged(tmp_path):
    """The author asked to ship his Envelock project page as attribution: that exact project URL is
    allowed everywhere, but any OTHER reference to his personal domain (another site/project path under
    it) is still a finding. The domain is assembled at run time so this file carries no literal term."""
    # Split the term so this test file itself does not carry the literal personal reference the guard
    # (which scans tests/ too) would flag; it is only assembled at run time, into the staged files.
    mig = "miguel" + "enred"
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "forbidden-terms.txt").write_text(mig + "\n")
    (tmp_path / "ok.md").write_text(f"Powered by Envelock -- https://{mig}.es/envelock\n")
    assert guard(tmp_path).returncode == 0
    (tmp_path / "bad.md").write_text(f"see also https://{mig}.es/otherproject\n")
    r = guard(tmp_path)
    assert r.returncode == 1 and "bad.md" in r.stdout and "forbidden term" in r.stdout


def test_oid_and_version_strings_are_not_mistaken_for_ip(tmp_path):
    """A dotted OID/version embedded in a longer chain (e.g. the code-signing OID
    1.3.6.1.5.5.7.3.3) must not be flagged as an IP address, but a real one still is."""
    (tmp_path / "a.txt").write_text("EKU 1.3.6.1.5.5.7.3.3 and version 10.20.30.40.50\n")
    assert guard(tmp_path).returncode == 0
    # Build the IP at runtime so this test file carries no literal IPv4 that the guard,
    # which scans the repo (including tests/), would itself flag.
    real_ip = ".".join(["45", "33", "22", "11"])
    (tmp_path / "b.txt").write_text(f"connect to {real_ip} now\n")
    assert guard(tmp_path).returncode == 1


def test_recovery_private_value_detected(tmp_path):
    owner = a.make_owner(with_recovery=True)
    leak = {"note": "copied by mistake", "recovery_private": owner["recovery_private"]}
    (tmp_path / "notes.json").write_text(json.dumps(leak))
    result = guard(tmp_path)
    assert result.returncode == 1 and "private-key value" in result.stdout


@pytest.mark.parametrize("name", ["app.conf", "seed.sql", "data.csv", "server.properties", "x.dist"])
def test_secret_in_non_text_extension_detected(tmp_path, name):
    """A private-key value inside a file whose extension is not in TEXT_EXT (.conf/.sql/.csv/...)
    must still be caught: content is scanned for every non-binary file, not only known text ones."""
    owner = a.make_owner()
    (tmp_path / name).write_text(f"setting=1\nsigning_private={owner['signing_private']}\n")
    result = guard(tmp_path)
    assert result.returncode == 1 and "private-key value" in result.stdout


def test_binary_blob_without_text_extension_is_skipped(tmp_path):
    """A binary file with NUL bytes and no text extension is treated as binary, not flagged."""
    (tmp_path / "blob.dat").write_bytes(b"\x00\x01\x02binary\x00data")
    assert guard(tmp_path).returncode == 0


def test_renamed_identity_file_detected_by_content(tmp_path):
    identity = a.identity_bytes(a.make_identity(a.make_recipient("r"), a.make_owner()))
    (tmp_path / "server-data.dat").write_bytes(identity)
    result = guard(tmp_path)
    assert result.returncode == 1 and "identity file" in result.stdout


def test_nested_private_folder_of_a_staged_app_is_scanned(tmp_path):
    """An application may have its own private/ folder: inside a staged tree it is scanned."""
    staged = tmp_path / "release" / "c1"
    (staged / "private").mkdir(parents=True)
    leak = {"signing_private": a.make_owner()["signing_private"]}
    (staged / "private" / "x.json").write_text(json.dumps(leak))
    result = guard(staged)
    assert result.returncode == 1 and "private-key value" in result.stdout


def _fake_repository(root, ignored):
    (root / "extension").mkdir(parents=True)
    (root / "extension" / "envelock.c").write_text("/* repository marker */\n")
    (root / ".gitignore").write_text("".join(f"{d}/\n" for d in ignored))


def _symlink_or_skip(target, link):
    """Windows grants symbolic links only to administrators or in Developer Mode."""
    import os
    try:
        os.symlink(target, link, target_is_directory=os.path.isdir(target))
    except OSError as e:
        pytest.skip(f"symbolic links are not permitted here ({e.strerror})")


def test_repository_scans_working_folders_not_in_gitignore(tmp_path):
    """build/ is not ignored by git, so a key left there would be committed."""
    _fake_repository(tmp_path, ["private", "release"])
    (tmp_path / ".git").mkdir()                      # a live working tree: git applies .gitignore
    (tmp_path / "private").mkdir()
    (tmp_path / "private" / "owner.json").write_text(json.dumps(a.make_owner()))
    assert guard(tmp_path).returncode == 0           # private/ is git-ignored
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "keys.json").write_text(json.dumps(a.make_owner()))
    result = guard(tmp_path)
    assert result.returncode == 1 and "build" in result.stdout


@pytest.mark.parametrize("name,content", [
    ("tls.key", b"-----BEGIN " + b"PRIVATE KEY-----\nAAAA\n"),
    ("owner.json.bak", json.dumps({"kind": "x"}).encode()),
    (".env", b"APP=1\n"),
    ("notes.txt", json.dumps({"signing_private": "ab" * 32}).encode("utf-16")),
    ("settings.ini", ("signing_private = " + "cd" * 32 + "\n").encode()),
], ids=["pem-key", "backup", "env", "utf16-secret", "ini-secret"])   # ids: no fake secret in reports
def test_staged_tree_common_secret_formats(tmp_path, name, content):
    (tmp_path / name).write_bytes(content)
    assert guard(tmp_path).returncode == 1


def test_clean_protected_package_passes(tmp_path):
    """The guard's main use: a freshly packed tree must pass (protected .php are binary)."""
    import uuid
    source = tmp_path / "src"
    source.mkdir()
    (source / "index.php").write_text('<?php echo "ok";')
    recipient = a.make_recipient("r")
    a.pack_tree(source, tmp_path / "out", [a.recipient_public(recipient)], a.make_owner(),
                str(uuid.uuid4()))
    result = guard(tmp_path / "out")
    assert result.returncode == 0, result.stdout


def _manifest(folder):
    """Write <folder>/SHA256SUMS for every file in it (sha256sum format)."""
    import hashlib
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(folder).as_posix()}"
             for p in sorted(folder.rglob("*")) if p.is_file() and p.name != "SHA256SUMS"]
    (folder / "SHA256SUMS").write_text("\n".join(lines) + "\n")


def test_prebuilt_binaries_only_when_listed_with_their_hash(tmp_path):
    """Compiled files are accepted only under prebuilt/ and only as listed in prebuilt/SHA256SUMS."""
    _fake_repository(tmp_path, [])
    module = tmp_path / "prebuilt" / "loader" / "envelock.so"
    module.parent.mkdir(parents=True)
    module.write_bytes(b"\x7fELF generic loader")
    _manifest(tmp_path / "prebuilt")
    assert guard(tmp_path).returncode == 0
    module.write_bytes(b"\x7fELF swapped")                      # same name, other content
    result = guard(tmp_path)
    assert result.returncode == 1 and "differs from its hash" in result.stdout
    module.unlink()
    stray = tmp_path / "prebuilt" / "loader" / "other.whl"        # not listed
    stray.write_bytes(b"PK")
    result = guard(tmp_path)
    assert result.returncode == 1 and "not listed" in result.stdout
    stray.unlink()
    (tmp_path / "extension" / "envelock.so").write_bytes(b"\x7fELF")  # outside prebuilt/
    assert guard(tmp_path).returncode == 1


@pytest.mark.parametrize("name", ["envelock.so.1", "envelock.bin", "module.pyd"])
def test_compiled_file_detected_by_content_or_name(tmp_path, name):
    (tmp_path / name).write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 32)
    result = guard(tmp_path)
    assert result.returncode == 1 and "compiled" in result.stdout


def test_sums_format_variants_and_escapes(tmp_path):
    """sha256sum's binary marker and ./ prefixes are accepted; a path leaving the folder
    whitelists nothing."""
    import hashlib
    _fake_repository(tmp_path, [])
    module = tmp_path / "prebuilt" / "a.so"
    module.parent.mkdir()
    module.write_bytes(b"\x7fELF a")
    outside = tmp_path / "extension" / "x.so"
    outside.write_bytes(b"\x7fELF x")
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()  # noqa: E731
    (tmp_path / "prebuilt" / "SHA256SUMS").write_text(
        f"{digest(module).upper()} *./a.so\r\n{digest(outside)}  ../extension/x.so\n")
    result = guard(tmp_path)
    assert result.returncode == 1 and "extension/x.so" in result.stdout
    assert "prebuilt/a.so" not in result.stdout


def test_third_party_is_byte_for_byte_and_still_guarded(tmp_path):
    """Upstream sources may hold their authors' emails, test keys and binaries; but every file must
    match third_party/SHA256SUMS (build outputs, swaps and end-of-line conversions are caught),
    Envelock secrets are refused there, and forbidden terms (whole words) are found in any
    encoding."""
    _fake_repository(tmp_path, [])
    lib = tmp_path / "third_party" / "lib-1.0"
    lib.mkdir(parents=True)
    # Built in pieces so this test file itself does not trip the guard.
    (lib / "AUTHORS").write_text("Jane Developer <jane.developer" + "@" + "upstream-project.org>\n")
    (lib / "test.key").write_text("-----BEGIN " + "PRIVATE KEY-----\n")
    (lib / "libffi.lib").write_bytes(b"\x00\x01binary")
    (lib / "ident.rs").write_bytes(b"unicode::FoobarXID::is_start(c)\n")   # term inside an identifier
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "forbidden-terms.txt").write_text("Foobar\n")
    _manifest(tmp_path / "third_party")
    assert guard(tmp_path).returncode == 0

    (lib / "ident.rs").write_bytes(b"unicode::FoobarXID::is_start(c)\r\n")  # CRLF conversion
    result = guard(tmp_path)
    assert result.returncode == 1 and "ident.rs: differs from its hash" in result.stdout
    (lib / "ident.rs").write_bytes(b"unicode::FoobarXID::is_start(c)\n")

    (lib / "build").mkdir()
    (lib / "build" / "_backend.so").write_bytes(b"\x7fELF")             # a build output
    (lib / "owner.json").write_text(json.dumps({"signing_private": a.make_owner()["signing_private"]}))
    (lib / "notes-utf16.txt").write_bytes("Written with Foobar.\n".encode("utf-16"))
    (lib / "notes-latin1.txt").write_bytes("Écrit avec Foobar.\n".encode("latin-1"))
    assert "_backend.so: not listed in third_party/SHA256SUMS" in guard(tmp_path).stdout
    _manifest(tmp_path / "third_party")                                  # even if listed
    result = guard(tmp_path).stdout
    assert "owner.json: forbidden file" in result and "owner.json:1: embedded private-key value" in result
    assert "notes-utf16.txt:1: forbidden term" in result and "notes-latin1.txt:1: forbidden term" in result
    (lib / "owner.json").unlink()
    for f in ("notes-utf16.txt", "notes-latin1.txt"):
        (lib / f).unlink()
    _manifest(tmp_path / "third_party")
    (lib / "build" / "_backend.so").write_bytes(b"\x7fELF rebuilt")
    assert "_backend.so: differs" in guard(tmp_path).stdout


def test_own_files_match_terms_anywhere_and_extra_venvs_are_skipped(tmp_path):
    """Outside third_party/ a term counts even inside an identifier; .venv-* folders (git-ignored
    build environments) are not scanned inside a live git checkout, but reported anywhere else
    (a copy or a release would publish them)."""
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "forbidden-terms.txt").write_text("Foobar\n")
    (tmp_path / "client.py").write_text("client = FoobarClient()\n")
    assert "client.py:1: forbidden term" in guard(tmp_path).stdout
    (tmp_path / "client.py").unlink()
    venv = tmp_path / ".venv-gui" / "lib"
    venv.mkdir(parents=True)
    (venv / "_cffi_backend.so").write_bytes(b"\x7fELF")
    result = guard(tmp_path)
    assert result.returncode == 1 and ".venv-gui: VCS/tool/cache folder" in result.stdout
    assert "_cffi_backend.so" not in result.stdout               # reported once, as a folder
    (tmp_path / ".git").mkdir()
    assert guard(tmp_path).returncode == 0


def test_upstream_rules_human_coauthors_binaries_links_and_allowed_phrases(tmp_path):
    """In hash-locked upstream folders: a human co-author line is not a marker, random bytes of a
    binary are not searched, BOM-less UTF-16 text is, a symbolic link is refused, and a "!"
    phrase in forbidden-terms.txt (e.g. a person's name) is not a finding."""
    import os
    _fake_repository(tmp_path, [])
    lib = tmp_path / "third_party" / "lib-1.0"
    lib.mkdir(parents=True)
    (lib / "NEWS").write_text("Co-" + "authored-by: Jane Developer\nPatch by Foobar Smith.\n")
    (lib / "icon.icns").write_bytes(b"\x00\x01\x02 xFOOBARx \x00 FooBar \x00\xff" * 4)
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "forbidden-terms.txt").write_text("Foobar\n!Foobar Smith\n")
    _manifest(tmp_path / "third_party")
    assert guard(tmp_path).returncode == 0
    (lib / "notes.txt").write_bytes("Made with Foobar.\n".encode("utf-16-le"))   # no BOM
    _manifest(tmp_path / "third_party")
    assert "notes.txt:1: forbidden term" in guard(tmp_path).stdout
    (lib / "notes.txt").unlink()
    _symlink_or_skip("NEWS", lib / "NEWS.link")
    _manifest(tmp_path / "third_party")
    result = guard(tmp_path)
    assert result.returncode == 1 and "NEWS.link: symbolic link" in result.stdout


def test_allowed_phrases_are_narrow_and_upstream_only(tmp_path):
    """A "!" phrase hides a term only inside upstream files and only when the match lies inside
    it; an empty "!" line disables nothing."""
    _fake_repository(tmp_path, [])
    lib = tmp_path / "third_party" / "lib-1.0"
    lib.mkdir(parents=True)
    (lib / "CREDITS").write_text("Patch by Foobar Smith.\n")
    (tmp_path / "scripts").mkdir()
    terms = tmp_path / "scripts" / "forbidden-terms.txt"
    terms.write_text("Foobar\nSmithson\n!Foobar Smith\n!\n")
    _manifest(tmp_path / "third_party")
    assert guard(tmp_path).returncode == 0
    (lib / "CREDITS").write_text("Patch by Foobar Smithson.\n")       # overlaps a longer term
    _manifest(tmp_path / "third_party")
    assert "CREDITS:1: forbidden term" in guard(tmp_path).stdout
    (lib / "CREDITS").write_text("Patch by Foobar Smith.\n")
    _manifest(tmp_path / "third_party")
    (tmp_path / "README.md").write_text("Thanks to Foobar Smith.\n")  # Envelock's own file
    assert "README.md:1: forbidden term" in guard(tmp_path).stdout


def test_text_with_a_stray_nul_or_in_utf32_is_still_searched(tmp_path):
    _fake_repository(tmp_path, [])
    lib = tmp_path / "third_party" / "lib-1.0"
    lib.mkdir(parents=True)
    (lib / "NEWS").write_bytes(b"Made with Foobar.\n\x00\n")
    (lib / "notes32.txt").write_bytes("Made with Foobar.\n".encode("utf-32"))
    (lib / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n Foobar \x00")      # data: not searched
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "forbidden-terms.txt").write_text("Foobar\n")
    _manifest(tmp_path / "third_party")
    result = guard(tmp_path).stdout
    assert "NEWS:1: forbidden term" in result and "notes32.txt:1: forbidden term" in result
    assert "logo.png" not in result


def test_prebuilt_areas_secrets_reports_and_linked_folders(tmp_path):
    """prebuilt/: each area holds only its kind of file and no key, password, backup or log even
    when listed; report formats (.xml, .cmd) are scanned; a linked top folder is refused."""
    import os
    _fake_repository(tmp_path, [])
    for rel in ("loader/linux/envelock.so", "loader/linux/notes.txt", "python/x/tls.key",
                "python/x/owner.enc.json", "python/x/build.log", "python/x/cacert.pem"):
        (tmp_path / "prebuilt" / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "prebuilt" / rel).write_bytes(b"\x7fELF" if rel.endswith(".so") else b"x\n")
    _manifest(tmp_path / "prebuilt")
    result = guard(tmp_path).stdout
    assert "loader/linux/notes.txt: not a file this prebuilt/loader/ area holds" in result
    assert "tls.key: forbidden file" in result and "build.log: forbidden file" in result
    assert "owner.enc.json: forbidden file" in result and "cacert.pem" not in result
    assert "envelock.so" not in result
    report = tmp_path / "docs" / "junit.xml"
    report.parent.mkdir()
    report.write_text('<skipped message="/home/' + 'builder/project/tests/x.py"/>\n')
    assert "junit.xml:1: real user/home/root path" in guard(tmp_path).stdout
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.mkdir()
    _symlink_or_skip(outside, tmp_path / "third_party")
    assert "third_party: symbolic link" in guard(tmp_path).stdout


def _vendored(address, *, in_header):
    """A minimal stand-in for a vendored OPcache file, with one address in or out of the header."""
    header = """/*
  +----------------------------------------------------------------------+
  | Zend OPcache                                                         |
  +----------------------------------------------------------------------+
  | Copyright (c) The PHP Group                                          |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | PHP License 3.01 text: https://www.php.net/license/3_01.txt          |
  +----------------------------------------------------------------------+
"""
    if in_header:
        header += f"   | Authors: Someone <{address}>                                    |\n"
    body = "*/\n\nint main(void) { return 0; }\n"
    if not in_header:
        body += f"/* contact {address} */\n"
    return header + body


@pytest.mark.parametrize("in_header", [True, False])
def test_vendored_opcache_attribution_email(tmp_path, in_header):
    """The upstream PHP license header of a vendored OPcache file keeps its authors' addresses;
    an address anywhere else in the same file is still a finding."""
    vendored = tmp_path / "extension" / "opcache" / "php84"
    vendored.mkdir(parents=True)
    address = "author" + chr(64) + "php.net"
    (vendored / "envelock_persist.c").write_text(_vendored(address, in_header=in_header))
    result = guard(tmp_path)
    if in_header:
        assert result.returncode == 0, result.stdout
    else:
        assert result.returncode == 1 and "real email address" in result.stdout


def test_attribution_email_outside_the_vendored_folder_is_a_finding(tmp_path):
    """The exemption is bound to extension/opcache/: the same header anywhere else still fails."""
    (tmp_path / "extension").mkdir()
    address = "author" + chr(64) + "php.net"
    (tmp_path / "extension" / "envelock.c").write_text(_vendored(address, in_header=True))
    result = guard(tmp_path)
    assert result.returncode == 1 and "real email address" in result.stdout


def test_internal_notes_file_presence_is_a_finding_outside_a_live_repo(tmp_path):
    """CONTEXTO-PROYECTO.md must never be published. Skipping only its content is not enough: its
    presence in a tree with no live ".git" (a naive copy, an extracted release) is a finding even
    though .gitignore lists it; inside a live repository (a real .git) it is tolerated."""
    _fake_repository(tmp_path, ["CONTEXTO-PROYECTO.md"])      # .gitignore lists it
    (tmp_path / "CONTEXTO-PROYECTO.md").write_text("internal notes\n")
    r = guard(tmp_path)                                       # no .git: a copy that would ship it
    assert r.returncode == 1 and "CONTEXTO-PROYECTO.md" in r.stdout
    assert "must never be published" in r.stdout
    (tmp_path / ".git").mkdir()                               # a live working tree ignores it
    assert guard(tmp_path).returncode == 0


def test_non_utf8_non_text_extension_is_still_scanned(tmp_path):
    """A .sql/.csv dump with a non-UTF-8 byte (a Latin-1 accented name) plus a secret must still be
    scanned, not silently skipped for failing a UTF-8 decode."""
    owner = a.make_owner()
    content = ("-- caf\xe9 export\nsigning_private=" + owner["signing_private"] + "\n").encode("latin-1")
    (tmp_path / "dump.sql").write_bytes(content)
    r = guard(tmp_path)
    assert r.returncode == 1 and "private-key value" in r.stdout


def test_archive_in_release_tree_is_flagged(tmp_path):
    """A compressed archive outside the hash-locked folders hides its contents from the scan and is
    refused rather than skipped."""
    (tmp_path / "data.tar.gz").write_bytes(b"\x1f\x8b\x08" + b"\x00" * 24)  # gzip magic
    r = guard(tmp_path)
    assert r.returncode == 1 and "archive" in r.stdout


def test_terms_file_absent_warns_on_stderr(tmp_path):
    """When forbidden-terms.txt is absent the term check cannot run; the guard says so on stderr
    instead of passing silently."""
    (tmp_path / "README.md").write_text("Nothing private here.\n")
    r = guard(tmp_path)
    assert r.returncode == 0
    assert "forbidden-term checking is" in r.stderr.lower() and "disabled" in r.stderr.lower()


def _encrypted_key_json():
    """The layout `save_json` writes for a password-protected private key (random bytes stand in
    for the scrypt/AES-GCM output; the guard looks at the structure, not at the cipher)."""
    import os
    return json.dumps({"kind": "envelock-encrypted", "format": 1, "kdf": "scrypt-131072-8-1",
                       "salt": os.urandom(16).hex(), "nonce": os.urandom(12).hex(),
                       "ciphertext": os.urandom(96).hex()}, indent=2) + "\n"


def _staged_repository_copy(root):
    """A staged release tree that LOOKS like the repository (extension/envelock.c and the shipped
    .gitignore, which lists private/, dist/, .venv/...) but has no live .git."""
    (root / "extension").mkdir(parents=True)
    (root / "extension" / "envelock.c").write_text("/* repository marker */\n")
    (root / ".gitignore").write_bytes((ROOT / ".gitignore").read_bytes())
    owner = a.make_owner()
    files = {
        "private/owner.enc.json": _encrypted_key_json().encode(),
        "private/identity.bin": a.identity_bytes(a.make_identity(a.make_recipient("r"), owner)),
        "dist/keys.json": json.dumps(owner).encode(),
        ".venv/x.json": json.dumps(owner).encode(),
        "app/.git/leak.txt": json.dumps(owner).encode(),
        "app/__pycache__/m.cpython-312.pyc": b"\xcb\r\r\n" + b"\x00" * 12,
        "app/stray.pyc": b"\xcb\r\r\n" + b"\x00" * 12,
        # PowerShell 5.1's `>` writes UTF-16 LE with a BOM: NUL bytes, no text extension.
        "conf/server.conf": f"x25519_private={'ab' * 32}\n".encode("utf-16"),
        "conf/prod.json": _encrypted_key_json().encode(),          # neutral name, encrypted key
    }
    for rel, data in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(data)


def test_staged_tree_that_looks_like_the_repository_is_fully_checked(tmp_path):
    """T-1: a tree is "the repository" only when it is a live git checkout. A copy with
    extension/envelock.c and the shipped .gitignore must report its private/, dist/, .venv/, .git
    and __pycache__ folders, decode UTF-16 configs, flag .pyc files and encrypted private keys
    under any name; in a live git checkout the ignored folders are skipped again, the rest is not."""
    _staged_repository_copy(tmp_path)
    result = guard(tmp_path)
    out = result.stdout
    assert result.returncode == 1
    for expected in ("private: local working folder", "dist: local working folder",
                     "private/owner.enc.json: forbidden file", "private/identity.bin: server identity",
                     "dist/keys.json:1: embedded private-key value",
                     ".venv: VCS/tool/cache folder", "app/.git: VCS/tool/cache folder",
                     "app/__pycache__: VCS/tool/cache folder",
                     "app/stray.pyc: forbidden binary/compiled artifact",
                     "conf/server.conf:1: embedded private-key value",
                     "conf/prod.json:2: encrypted private key"):
        assert expected in out, (expected, out)
    assert "leak.txt" not in out and ".venv/x.json" not in out   # reported as folders
    (tmp_path / ".git").mkdir()                                    # now a live working tree
    out = guard(tmp_path).stdout
    for skipped in ("private/", "private:", "dist/", "dist:", ".venv", "app/.git", "__pycache__"):
        assert skipped not in out, (skipped, out)
    for expected in ("app/stray.pyc", "conf/server.conf:1", "conf/prod.json:2: encrypted private key"):
        assert expected in out, (expected, out)


def test_encrypted_key_embedded_or_utf16_is_found_but_source_naming_the_kind_is_not(tmp_path):
    """The encrypted-key check needs the marker AND a hex ciphertext: code that merely names the
    kind (the encoder, the assistant) passes; the blob escaped inside another JSON is found."""
    (tmp_path / "loader.py").write_text('if obj.get("kind") == "envelock-encrypted":\n'
                                        '    blob = {"kind": "envelock-encrypted", "ciphertext": ct.hex()}\n')
    assert guard(tmp_path).returncode == 0
    (tmp_path / "wrapped.json").write_text(json.dumps({"backup": _encrypted_key_json()}))
    (tmp_path / "key.txt").write_bytes(_encrypted_key_json().encode("utf-16"))
    out = guard(tmp_path).stdout
    assert "wrapped.json:1: encrypted private key" in out and "key.txt:2: encrypted private key" in out


@pytest.mark.parametrize("arg", ["missing-dir", "release.zip"])
def test_argument_that_is_not_a_directory_is_an_error(tmp_path, arg):
    """T-4: a typo or an archive must not pass by scanning nothing."""
    (tmp_path / "release.zip").write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    result = guard(tmp_path / arg)
    assert result.returncode == 2 and "not a directory" in result.stderr
    assert "passed" not in result.stdout


# Built at run time so this file, which the guard scans, carries none of these paths.
_USER = "jdoe"
_BS = chr(92)        # a backslash


@pytest.mark.parametrize("path", [
    (_BS * 2).join(["C:", "Users", _USER, "proj"]),         # as JSON-escaped text
    _BS.join(["C:", "Users", _USER, "proj"]),
    "/".join(["C:", "Users", _USER, "proj"]),
    "/".join(["", "Users", _USER, "src"]),                  # macOS
    "/".join(["", "c", "Users", _USER, "src"]),             # Git Bash
    "/".join(["", "mnt", "c", "users", _USER]),             # WSL
], ids=["json-escaped", "windows", "windows-slash", "macos", "git-bash", "wsl"])
def test_user_paths_in_every_spelling_are_found(tmp_path, path):
    """T-9: user profile paths are found however they are spelled."""
    (tmp_path / "settings.conf").write_text(f"cwd = {path}\n")
    (tmp_path / "settings.json").write_text(json.dumps({"cwd": path}) + "\n")
    out = guard(tmp_path).stdout
    assert "settings.conf:1: real user/home/root path" in out
    assert "settings.json:1: real user/home/root path" in out


@pytest.mark.parametrize("text", [
    _BS.join(["C:", "Users", "<you>", "proj"]),
    _BS.join(["C:", "Users", "%USERNAME%", "proj"]),
    "/".join(["", "Users", "$USER", "src"]),
    "GET https://api.example.com" + "/".join(["", "Users", "42"]),
    "/".join(["", "api", "users", "42"]),
], ids=["placeholder", "env-var", "shell-var", "url", "route"])
def test_generic_user_path_examples_are_not_findings(tmp_path, text):
    (tmp_path / "README.md").write_text(f"Example: {text}\n")
    result = guard(tmp_path)
    assert result.returncode == 0, result.stdout


def _load_guard():
    import importlib.util
    spec = importlib.util.spec_from_file_location("check_release", GUARD)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_case_only_variants_match_as_on_a_case_insensitive_filesystem():
    """NTFS: listed paths that differ only by case cannot coexist; the one file present stands
    for its group if it carries one of their hashes, and nothing unlisted or tampered passes."""
    g = _load_guard()
    listed = {"prebuilt/t/2/2621A": "aa", "prebuilt/t/2/2621a": "bb", "prebuilt/t/p/putty": "cc"}
    ci = g.case_variants(listed)
    assert g.match_listed("prebuilt/t/2/2621A", "bb", listed, ci)[0] == "ok"      # sibling's content
    assert g.match_listed("prebuilt/t/2/2621A", "aa", listed, ci) == (
        "ok", ("prebuilt/t/2/2621A", "prebuilt/t/2/2621a"))
    assert g.match_listed("prebuilt/t/P/putty", "cc", listed, ci) == ("ok", ("prebuilt/t/p/putty",))
    assert g.match_listed("prebuilt/t/2/2621A", "ee", listed, ci)[0] == "differs"
    assert g.match_listed("prebuilt/t/P/putty", "ee", listed, ci)[0] == "differs"
    assert g.match_listed("prebuilt/t/P/evil", "cc", listed, ci)[0] == "not listed"
    # Case-sensitive filesystem: exact names and exact hashes only.
    assert g.match_listed("prebuilt/t/2/2621A", "bb", listed, None)[0] == "differs"
    assert g.match_listed("prebuilt/t/P/putty", "cc", listed, None)[0] == "not listed"


def test_case_only_variants_on_this_filesystem(tmp_path):
    """End to end on the real filesystem, whichever kind it is (probed, not guessed)."""
    import hashlib
    g = _load_guard()
    _fake_repository(tmp_path, [])
    base = tmp_path / "prebuilt" / "python" / "x" / "share" / "terminfo"
    (base / "P").mkdir(parents=True)
    (base / "P" / "P12").write_bytes(b"upper\n")
    (base / "P" / "putty").write_bytes(b"putty\n")       # listed under p/: one folder on NTFS

    def digest(data):
        return hashlib.sha256(data).hexdigest()
    sums = tmp_path / "prebuilt" / "SHA256SUMS"
    sums.write_text(f"{digest(b'upper' + bytes([10]))}  python/x/share/terminfo/P/P12\n"
                    f"{digest(b'lower' + bytes([10]))}  python/x/share/terminfo/p/p12\n"
                    f"{digest(b'putty' + bytes([10]))}  python/x/share/terminfo/p/putty\n")
    insensitive = g.case_insensitive(sums)
    assert insensitive == (tmp_path / "prebuilt" / "sha256sums").exists()
    result = guard(tmp_path)
    if insensitive:
        assert result.returncode == 0, result.stdout
        assert result.stdout.count("NOTE:") == 1 and "differ only by case" in result.stdout
        (base / "P" / "P12").write_bytes(b"tampered\n")
        (base / "P" / "evil").write_bytes(b"putty\n")
        out = guard(tmp_path).stdout
        assert "P/P12: differs from its hash" in out and "P/evil: not listed" in out
    else:
        assert "P/putty: not listed" in result.stdout and "NOTE:" not in result.stdout

"""Native integration tests. Linux/macOS auto-build; Windows core can use ENVELOCK_CRYPTO_LIB.

The loader is a generic binary: keys are not embedded. Each test configures identities
through the envelock.identity php.ini directive pointing at a server identity bundle.
"""

import base64
import ctypes
import hashlib
import http.client
import json
import os
import random
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
import zlib
from pathlib import Path

import pytest
from test_encoder import a, sample

ROOT = Path(__file__).resolve().parents[1]

# Wire header of a bytecode image (see extension/envelock_bc.h): tag, magic, system_id, sizes,
# script offset, timestamp and the adler32 that covers the program bytes.
ENVELOCK_BC_HEADER_SIZE = 80


def _php_os_family():
    """PHP_OS_FAMILY of the `php` under test (it may be a Windows PHP run under Wine from a Linux
    host), or "" when there is none: the expectations follow the PHP, not the host."""
    try:
        return subprocess.run(["php", "-n", "-r", "echo PHP_OS_FAMILY;"], capture_output=True,
                              text=True, check=False, timeout=60).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


PHP_WINDOWS = _php_os_family() == "Windows"
# macOS, like Windows, has no machine-fingerprint source wired up in the loader (envelock_licence.c
# reads Linux-only paths: /etc/machine-id and /sys/class/net). There a machine-bound licence is
# refused for want of any identity, not for a mismatch — fail-closed, the same as Windows.
PHP_MACOS = _php_os_family() == "Darwin"
# The identity-file refusal is worded after each system's permission model.
LAX_IDENTITY = ("accessible by other accounts or groups" if PHP_WINDOWS
                else "identity file rejected: must be a regular file with mode 0600 or 0400")
# A Windows PHP run under Wine sees the host's files on drive Z:; directives that demand a full
# Windows path (opcache.file_cache) get it in that form.
PHP_PATH_PREFIX = "Z:" if PHP_WINDOWS and os.name != "nt" else ""
FOREIGN_IDENTITY = ("must be owned by the PHP service account" if PHP_WINDOWS
                    else "owned by the PHP user or by root")


def write_identity(path, identities):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(a.identity_bundle_bytes(identities))


@pytest.fixture(scope="session")
def native(tmp_path_factory):
    external = os.getenv("ENVELOCK_TEST_EXTENSION")
    if external:
        root = tmp_path_factory.mktemp("external-native")
        owner = a.read_config(Path(os.environ["ENVELOCK_TEST_OWNER"]), "envelock-owner")
        recipient = a.read_config(Path(os.environ["ENVELOCK_TEST_RECIPIENT"]), "envelock-recipient")
    else:
        needed = ["php", "phpize", "php-config", "make", "cc", "pkg-config"]
        missing = [tool for tool in needed if not shutil.which(tool)]
        if os.name == "nt" or missing:
            message = "Native PHP build unavailable: " + ", ".join(missing)
            if os.getenv("ENVELOCK_REQUIRE_NATIVE") == "1":
                pytest.fail(message)
            pytest.skip(message)
        root = tmp_path_factory.mktemp("native")
        ext = root / "extension"
        ext.mkdir()
        for name in EXTENSION_SOURCES:
            shutil.copyfile(ROOT / "extension" / name, ext / name)
        # O1 bytecode layer: vendored per PHP version, config.m4 selects the matching directory.
        shutil.copytree(ROOT / "extension" / "opcache", ext / "opcache")
        log = ""
        # The round-trip tests need both bytecode PoC functions (emit + run). They are now gated by
        # explicit configure flags, not an environment variable (ENV-2026-02): --enable-envelock-bcrun-unsafe
        # pulls in the emitter too. A server loader is built with neither flag.
        build_env = {k: v for k, v in os.environ.items() if k != "ENVELOCK_BCPOC"}
        for command in [["phpize"],
                        ["./configure", "--enable-envelock", "--enable-envelock-bcrun-unsafe"],
                        ["make", "-j2"]]:
            result = subprocess.run(command, cwd=ext, text=True, capture_output=True, check=False, env=build_env)
            log += result.stdout + result.stderr
            if result.returncode:
                pytest.fail("Native build failed:\n" + log[-12000:])
        external = ext / "modules/envelock.so"
        owner = a.make_owner()
        recipient = a.make_recipient("integration-test")
    identity = a.make_identity(recipient, owner)
    identity_path = root / "identity.bin"
    write_identity(identity_path, [identity])
    return root, Path(external).resolve(), owner, recipient, identity_path


def php_environment():
    env = os.environ.copy()
    if os.getenv("ENVELOCK_PHP_PRELOAD"):
        env["LD_PRELOAD"] = os.environ["ENVELOCK_PHP_PRELOAD"]
        env["USE_ZEND_ALLOC"] = "0"
        env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1"
        env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    return env


def php_literal(value):
    return 'base64_decode("' + base64.b64encode(value.encode()).decode() + '")'


# Every top-level source of the extension, mirroring PHP_NEW_EXTENSION in config.m4. One list on
# purpose: a second copy drifted once already and left a build copying stale sources.
# php_envelock.h is not optional: envelock.c includes it, and it is what lets the extension be
# compiled INTO php (the static build a single-binary distribution needs) rather than only loaded.
EXTENSION_SOURCES = ["config.m4", "php_envelock.h", "envelock.c", "envelock_crypto.c", "envelock_crypto.h",
                     "envelock_file.c", "envelock_file.h", "envelock_bc.h", "envelock_bcpoc.c",
                     "envelock_secret.c", "envelock_secret.h",
                     "envelock_integrity.c", "envelock_integrity.h",
                     "envelock_licence.c", "envelock_licence.h",
                     "envelock_clock.c", "envelock_clock.h",
                     "envelock_trusted_time.c", "envelock_trusted_time.h",
                     "envelock_vm.c"]


def php(native, *arguments, extra_ini=(), identity=None, timeout=None):
    identity_path = native[4] if identity is None else identity
    return subprocess.run(
        [
            "php", "-n",
            "-d", f"extension={native[1]}",
            "-d", f"envelock.identity={identity_path}",
            "-d", "display_errors=stderr",
            "-d", "opcache.enable=0",
            "-d", "opcache.enable_cli=0",
            "-d", "opcache.file_cache_only=0",
            "-d", "opcache.preload=",
            *extra_ini,
            *map(str, arguments),
        ],
        capture_output=True, text=True, check=False, env=php_environment(), timeout=timeout,
    )


def popen_server(args, **kwargs):
    """Start a long-running php process (the built-in server) with its output going to a temporary
    FILE, never a pipe: nobody reads a pipe while the requests run, and once its buffer fills (about
    4 KiB on Windows, 64 KiB on Linux) the server blocks writing its access log and every later request
    times out. Read the output with server_output(); close it with stop_server()."""
    log = tempfile.TemporaryFile()
    proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, env=php_environment(), **kwargs)
    proc.envelock_log = log
    return proc


def server_output(proc):
    log = proc.envelock_log
    log.flush()
    log.seek(0)
    return log.read().decode(errors="replace")


def stop_server(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    proc.envelock_log.close()


def crashed(returncode):
    """True when the process under test died instead of exiting, on either family of systems: killed
    by a signal on POSIX (a NEGATIVE return code, e.g. -11 for SIGSEGV), or ended by an unhandled
    structured exception on Windows (an NTSTATUS error code, 0xC0000000 and above: 0xC0000005 access
    violation, 0xC00000FD stack overflow, 0xC0000409 fail-fast). Python reports the Windows code as a
    POSITIVE integer (0xC0000005 is 3221225477), so `returncode >= 0` alone never sees a crash there."""
    return returncode is not None and (returncode < 0 or (returncode & 0xFFFFFFFF) >= 0xC0000000)


def describe_rc(returncode):
    return f"rc={returncode} ({returncode & 0xFFFFFFFF:#010x})"


def test_crash_detector_sees_a_real_crash_on_this_platform():
    """The no-crash assertions in this file rely on crashed(): it must recognise a genuine wild-pointer
    crash of a child process on THIS system (SIGSEGV on POSIX, 0xC0000005 on Windows) and must not flag
    a clean exit or a PHP fatal error (exit status 255)."""
    import faulthandler
    if not hasattr(faulthandler, "_read_null"):
        pytest.skip("this Python has no faulthandler._read_null to provoke a crash")
    r = subprocess.run([sys.executable, "-I", "-c", "import faulthandler; faulthandler._read_null()"],
                       capture_output=True, check=False, timeout=60)
    assert crashed(r.returncode), describe_rc(r.returncode)
    assert not any(crashed(code) for code in (0, 1, 2, 255))


def package(native, tmp_path, contents, recipients=None, owner=None, project=None, **options):
    source = tmp_path / ("source-" + uuid.uuid4().hex)
    output = tmp_path / ("protected-" + uuid.uuid4().hex)
    source.mkdir()
    for name, data in contents.items():
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data.encode() if isinstance(data, str) else data)
    recipients = [a.recipient_public(native[3])] if recipients is None else recipients
    owner = native[2] if owner is None else owner
    if options.get("virtualize"):
        options.setdefault("virtualize_loader", native[1])
        options.setdefault("unsafe_vm_laboratory", True)  # tests exercise the quarantined research VM
    a.pack_tree(source, output, recipients, owner, project or str(uuid.uuid4()), **options)
    return output


def skip_without_posix_build_tools(purpose):
    """Tests that compile their own module use phpize/configure/make (the POSIX build); on Windows,
    or without those tools, they skip instead of erroring out with a missing executable."""
    missing = [t for t in ("phpize", "php-config", "make", "cc") if not shutil.which(t)]
    if os.name == "nt" or missing:
        pytest.skip(f"needs the POSIX PHP build tools to {purpose}"
                    + (f" (missing: {', '.join(missing)})" if missing else " (Windows)"))


def build_hook(tmp_path, name="reopen_hook", source_dir="reopen_hook", cflags=""):
    """Test-only extension built under the given module name.

    source_dir picks which of the test hooks to build: tests/reopen_hook (a compile hook loaded
    before Envelock) or tests/rehook (an instrument loaded after it, objective O3). cflags carries
    the -D switches that hook takes, e.g. -DREHOOK_MODE=REHOOK_AST.
    """
    skip_without_posix_build_tools("build a test hook extension")
    hook = tmp_path / ("hook-" + name)
    shutil.copytree(ROOT / "tests" / source_dir, hook)
    name_macro = "REOPEN_HOOK_NAME" if source_dir == "reopen_hook" else "REHOOK_NAME"
    flags = f'-D{name_macro}=\\"{name}\\"'
    env = dict(os.environ, CFLAGS=(flags + " " + cflags).strip())
    enable = "--enable-reopen-hook" if source_dir == "reopen_hook" else "--enable-rehook"
    for command in [["phpize"], ["./configure", enable], ["make"]]:
        built = subprocess.run(command, cwd=hook, text=True, capture_output=True, check=False, env=env)
        assert built.returncode == 0, built.stdout[-4000:] + built.stderr[-4000:]
    return hook / "modules" / (source_dir + ".so")


def test_php_two_projects_same_process(native, tmp_path):
    paths = []
    for project in ("project-a", "project-b"):
        path = tmp_path / project
        a.pack_tree(ROOT / "examples" / project, path, [a.recipient_public(native[3])], native[2], str(uuid.uuid4()))
        paths.append(path / "index.php")
    command = ";".join("require " + php_literal(str(p)) for p in paths) + ";"
    result = php(native, "-r", command)
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    first = json.loads(lines[0])
    assert first["total"] == 121
    assert first["first_include"] == "library-loaded"
    assert first["second_include"] is True
    assert first["included_files"] == 2
    assert "Proyecto B" in lines[1]


def test_php_multiple_projects_different_keys_one_host(native, tmp_path):
    """Two folders, two owners, two recipient keys, one identity bundle: both run."""
    owner_a, owner_b = a.make_owner(), a.make_owner()
    rcpt_a, rcpt_b = a.make_recipient("A"), a.make_recipient("B")
    bundle = tmp_path / "bundle.bin"
    write_identity(bundle, [a.make_identity(rcpt_a, owner_a), a.make_identity(rcpt_b, owner_b)])
    out_a = package(native, tmp_path, {"index.php": '<?php echo "AAA";'},
                    recipients=[a.recipient_public(rcpt_a)], owner=owner_a)
    out_b = package(native, tmp_path, {"index.php": '<?php echo "BBB";'},
                    recipients=[a.recipient_public(rcpt_b)], owner=owner_b)
    command = "require %s; require %s;" % (php_literal(str(out_a / "index.php")),
                                           php_literal(str(out_b / "index.php")))
    result = php(native, "-r", command, identity=bundle)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "AAABBB"


def test_php_recovery_key_accepted(native, tmp_path):
    """Trust store: a package signed by the developer's recovery key verifies in the loader."""
    owner = a.make_owner(with_recovery=True)
    recipient = a.make_recipient("rec")
    identity_file = tmp_path / "rec-identity.bin"
    write_identity(identity_file, [a.make_identity(recipient, owner)])
    recovery_owner = {
        "kind": "envelock-owner", "format": a.FORMAT_VERSION,
        "signing_private": owner["recovery_private"], "signing_public": owner["recovery_public"],
    }
    out = package(native, tmp_path, {"index.php": '<?php echo "rec-ok";'},
                  recipients=[a.recipient_public(recipient)], owner=recovery_owner)
    result = php(native, out / "index.php", identity=identity_file)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "rec-ok"


def test_php_malformed_identity_ignored(native, tmp_path):
    """A corrupt/garbage identity file loads nothing; protected files fail closed."""
    bad = tmp_path / "garbage-identity.bin"
    fd = os.open(bad, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(b"ENVLKID2" + b"\xff" * 200)  # right magic, inconsistent counts/size
    output = package(native, tmp_path, {"index.php": '<?php echo "secret-output";'})
    result = php(native, output / "index.php", identity=bad)
    assert result.returncode != 0
    assert "identity file rejected: malformed" in result.stderr
    assert "secret-output" not in result.stdout


def test_php_untrusted_signer_rejected(native, tmp_path):
    """A package signed by a developer not in the trust store fails closed."""
    rogue = a.make_owner()
    recipient = a.make_recipient("rogue-target")
    identity_file = tmp_path / "rogue-identity.bin"
    # trust store pairs this recipient with the session owner, NOT with rogue
    write_identity(identity_file, [a.make_identity(recipient, native[2])])
    out = package(native, tmp_path, {"index.php": '<?php echo "never";'},
                  recipients=[a.recipient_public(recipient)], owner=rogue)
    result = php(native, out / "index.php", identity=identity_file)
    assert result.returncode != 0 and "invalid protected file" in result.stderr
    assert "never" not in result.stdout


def test_php_plain_files_still_work(native, tmp_path):
    p = tmp_path / "plain.php"
    p.write_text('<?php echo "plain-ok";')
    result = php(native, p)
    assert result.returncode == 0 and result.stdout == "plain-ok"


def test_php_without_loader_fails_closed(native, tmp_path):
    output = package(native, tmp_path, {"index.php": '<?php echo "secret-output";'})
    result = subprocess.run(["php", "-n", str(output / "index.php")], capture_output=True, text=True)
    assert result.stdout == "Envelock loader required\n"
    assert "secret-output" not in result.stdout


def test_php_no_identity_configured_fails_closed(native, tmp_path):
    output = package(native, tmp_path, {"index.php": '<?php echo "secret-output";'})
    result = php(native, output / "index.php", identity="")
    assert result.returncode != 0
    assert "no identity configured" in result.stderr
    assert "secret-output" not in result.stdout


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission check")
def test_php_identity_bad_permissions_ignored(native, tmp_path):
    loose = tmp_path / "loose-identity.bin"
    write_identity(loose, [a.make_identity(native[3], native[2])])
    loose.chmod(0o644)
    output = package(native, tmp_path, {"index.php": '<?php echo "secret-output";'})
    result = php(native, output / "index.php", identity=loose)
    assert result.returncode != 0
    assert LAX_IDENTITY in result.stderr
    assert "Warning" in result.stderr  # also reported once at startup, not silently dropped
    assert "secret-output" not in result.stdout


@pytest.mark.skipif(os.name == "nt" or not hasattr(os, "mkfifo"), reason="POSIX FIFO")
def test_php_identity_fifo_does_not_hang(native, tmp_path):
    """envelock.identity pointing to a FIFO must be refused at startup, not block PHP."""
    fifo = tmp_path / "identity-fifo"
    os.mkfifo(fifo, 0o600)
    output = package(native, tmp_path, {"index.php": '<?php echo "never";'})
    result = subprocess.run(
        ["php", "-n", "-d", f"extension={native[1]}", "-d", f"envelock.identity={fifo}",
         "-d", "display_errors=stderr", "-d", "opcache.enable=0", str(output / "index.php")],
        capture_output=True, text=True, timeout=20, env=php_environment())
    assert result.returncode != 0 and "never" not in result.stdout
    assert "identity file rejected: must be a regular file" in result.stderr


def test_php_strip_comments_runs_and_saves_memory(native, tmp_path):
    """--strip-comments through the real loader: same output and line numbers, docblocks gone,
    and less PHP memory than the same package with its comments."""
    from test_transform import PHP as STRIP_PHP
    from test_transform import SAMPLE
    if STRIP_PHP is None:
        pytest.skip("php CLI with the tokenizer extension required to strip comments")
    doc = "    /**\n" + "     * Documentation line that PHP keeps in memory.\n" * 20 + "     */\n"
    big = "<?php\nclass Big {\n" + "".join(f"{doc}    public function m{i}() {{ return {i}; }}\n" for i in range(300)) + "}\n"
    probe = "<?php require __DIR__ . '/big.php'; echo memory_get_usage();"
    outputs = {}
    for strip in (None, STRIP_PHP):
        source = tmp_path / ("src-" + uuid.uuid4().hex)
        source.mkdir()
        (source / "app.php").write_bytes(SAMPLE)
        (source / "big.php").write_text(big)
        (source / "probe.php").write_text(probe)
        out = tmp_path / ("out-" + uuid.uuid4().hex)
        a.pack_tree(source, out, [a.recipient_public(native[3])], native[2], str(uuid.uuid4()),
                    php=strip or "php", strip_comments=bool(strip))
        app, mem = php(native, out / "app.php"), php(native, out / "probe.php")
        assert app.returncode == 0 and mem.returncode == 0, app.stderr + mem.stderr
        outputs[bool(strip)] = (app.stdout, int(mem.stdout))
    (kept, mem_kept), (stripped, mem_stripped) = outputs[False], outputs[True]
    assert kept.replace("|doc|", "|nodoc|") == stripped and "|nodoc|" in stripped
    assert mem_stripped < mem_kept


def test_php_later_compile_hook_cannot_orphan_the_plaintext(native, tmp_path):
    """A compile hook that Envelock chains to (loaded before it) and that reopens filename-type
    handles, as OPcache does, must get the decrypted code, not a fresh read of the stub (which
    would also orphan the plaintext buffer)."""
    if os.getenv("ENVELOCK_TEST_EXTENSION"):
        pytest.skip("needs the local PHP build tools")
    hook = build_hook(tmp_path)
    source = tmp_path / "src"
    source.mkdir()
    (source / "lib.php").write_text("<?php function f() { return 'lib'; }")
    (source / "main.php").write_text("<?php require __DIR__ . '/lib.php'; echo f(), '|main';")
    out = tmp_path / "out"
    a.pack_tree(source, out, [a.recipient_public(native[3])], native[2], str(uuid.uuid4()))
    run = subprocess.run(
        ["php", "-n", "-d", f"extension={hook}", "-d", f"extension={native[1]}",
         "-d", f"envelock.identity={native[4]}", "-d", "opcache.enable_cli=0", str(out / "main.php")],
        capture_output=True, text=True, check=False, env=php_environment())
    assert run.returncode == 0 and run.stdout == "lib|main", run.stdout + run.stderr


def test_php_protected_file_is_not_held_twice_in_memory(native, tmp_path):
    """In-place decryption: PHP's peak memory for a protected file stays close to the plain
    file's, instead of adding a second full copy (ciphertext + plaintext) while compiling."""
    body = "".join(f"    public function m{i}() {{ $a = str_repeat('x', {i}); return strlen($a) + {i}; }}\n"
                   for i in range(4000))
    source = tmp_path / "src"
    source.mkdir()
    (source / "big.php").write_text("<?php\nclass Big {\n" + body + "}\n")
    probe = "<?php require __DIR__ . '/big.php'; echo memory_get_peak_usage();"
    (source / "probe.php").write_text(probe)
    out = tmp_path / "out"
    a.pack_tree(source, out, [a.recipient_public(native[3])], native[2], str(uuid.uuid4()))
    peaks = []
    for tree in (source, out):
        run = php(native, tree / "probe.php", extra_ini=("-d", "memory_limit=-1"))
        assert run.returncode == 0, run.stderr
        peaks.append(int(run.stdout))
    size = (source / "big.php").stat().st_size
    assert peaks[1] - peaks[0] < size // 4, (peaks, size)


def test_php_worker_caches_do_not_accept_tampering(native, tmp_path):
    """Per-worker caches (verified containers, package content keys): after a valid file of a
    package has been loaded, a tampered file of the SAME package (same recipient table, same
    content key) must still be refused in that process, and an untouched sibling must run."""
    output = package(native, tmp_path, {"a.php": '<?php return "A";', "b.php": '<?php return "B";'})
    tampered = output / "b-tampered.php"
    blob = bytearray((output / "b.php").read_bytes())
    blob[-90] ^= 1                                  # inside the ciphertext
    tampered.write_bytes(bytes(blob))
    # Only the signature corrupted: GCM still authenticates the content, so only the signature
    # check (not skipped through the caches) can refuse it.
    bad_signature = output / "b-signature.php"
    blob = bytearray((output / "b.php").read_bytes())
    blob[-1] ^= 1
    bad_signature.write_bytes(bytes(blob))
    for target in (tampered, bad_signature):
        script = tmp_path / f"caches-{target.stem}.php"
        script.write_text(
            "<?php\n"
            f"echo include {php_literal(str(output / 'a.php'))};\n"
            f"echo include {php_literal(str(output / 'a.php'))};\n"      # verified-cache hit
            f"echo include {php_literal(str(output / 'b.php'))};\n"      # package-key hit
            f"echo include {php_literal(str(target))};\n"
        )
        result = php(native, script)
        assert result.stdout == "AAB", (target.name, result.stderr)
        assert result.returncode != 0 and "invalid protected file" in result.stderr, target.name


def test_php_two_packages_in_one_worker(native, tmp_path):
    """Two packages (different content keys) addressed to the same server, in one process."""
    first = package(native, tmp_path, {"x.php": '<?php return "one";'})
    second = package(native, tmp_path, {"x.php": '<?php return "two";'})
    script = tmp_path / "two.php"
    script.write_text(
        "<?php\n"
        f"echo include {php_literal(str(first / 'x.php'))}, '|';\n"
        f"echo include {php_literal(str(second / 'x.php'))}, '|';\n"
        f"echo include {php_literal(str(first / 'x.php'))};\n"
    )
    result = php(native, script)
    assert result.returncode == 0 and result.stdout == "one|two|one", result.stderr


def test_php_key_rotation_with_recovery(native, tmp_path):
    """Primary key stolen: promote the recovery key. New packages run on a server whose
    identity file was not touched; after removing the old developer, packages signed with
    the stolen key are refused while the new ones keep running."""
    old = a.make_owner(with_recovery=True)
    recipient = a.make_recipient("rotation")
    store = a.add_recipient_to_store(None, recipient, old)
    new = a.promote_recovery(old)
    target = [a.recipient_public(recipient)]
    by_old = package(native, tmp_path, {"index.php": '<?php echo "old";'}, recipients=target, owner=old)
    by_new = package(native, tmp_path, {"index.php": '<?php echo "new";'}, recipients=target, owner=new)

    def run(store_bytes, output):
        identity = tmp_path / f"identity-{uuid.uuid4().hex}.bin"
        fd = os.open(identity, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(store_bytes)
        return php(native, output / "index.php", identity=identity)

    assert run(store, by_new).stdout == "new"          # server not updated yet
    updated = a.set_developer(store, a.developer_public(new))
    updated = a.remove_developer(updated, a.developer_id(old["signing_public"]))
    assert run(updated, by_new).stdout == "new"
    refused = run(updated, by_old)
    assert refused.returncode != 0 and "old" not in refused.stdout
    assert "invalid protected file" in refused.stderr


def test_php_identity_keypair_mismatch_rejected(native, tmp_path):
    """A recipient entry whose public key is not derived from its private key is refused at
    load (the per-include self-check was moved to MINIT). The package is addressed to that
    public key, so only the load-time check stands between it and an attempted decryption."""
    victim = a.make_recipient("victim")
    other = a.make_recipient("other")
    entry = bytes.fromhex(other["x25519_private"]) + bytes.fromhex(victim["x25519_public"])
    developer = bytes.fromhex(native[2]["signing_public"]) + bytes(32)
    bad = tmp_path / "mismatch-identity.bin"
    fd = os.open(bad, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(a.build_identity_store([entry], [developer]))
    output = package(native, tmp_path, {"index.php": '<?php echo "never";'},
                     recipients=[a.recipient_public(victim)])
    result = php(native, output / "index.php", identity=bad)
    assert result.returncode != 0 and "never" not in result.stdout
    assert "identity file rejected: malformed (recipient key pair mismatch)" in result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL check")
def test_php_identity_broad_acl_rejected(native, tmp_path):
    """Windows allow-list: an entry for Users is refused; restricted to the user, it runs."""
    identity = tmp_path / "acl-identity.bin"
    write_identity(identity, [a.make_identity(native[3], native[2])])
    output = package(native, tmp_path, {"index.php": '<?php echo "acl-ok";'})
    user = subprocess.check_output(["whoami"], text=True).strip()
    subprocess.run(["icacls", str(identity), "/inheritance:r", "/grant:r", f"{user}:F",
                    "*S-1-5-32-545:R"], check=True, capture_output=True)  # Users: read
    result = php(native, output / "index.php", identity=identity)
    assert result.returncode != 0 and "acl-ok" not in result.stdout
    assert "identity file rejected: accessible by other accounts or groups" in result.stderr
    # /grant:r only replaces the grants for the named account; the explicit Users ACE added above has
    # to be removed explicitly or the file stays (correctly) refused.
    subprocess.run(["icacls", str(identity), "/inheritance:r", "/remove:g", "*S-1-5-32-545",
                    "/grant:r", f"{user}:F"], check=True, capture_output=True)
    result = php(native, output / "index.php", identity=identity)
    assert result.returncode == 0 and result.stdout == "acl-ok", result.stderr


def test_php_tampering(native, tmp_path):
    output = package(native, tmp_path, {"index.php": '<?php echo "never";'})
    p = output / "index.php"
    blob = bytearray(p.read_bytes())
    blob[-70] ^= 1
    p.write_bytes(blob)
    result = php(native, p)
    assert result.returncode != 0
    assert "invalid protected file" in result.stderr
    assert "never" not in result.stdout


def test_php_inflated_size_rejected(native, tmp_path):
    """A small file that lies about its source size is rejected before any large
    allocation (header length cross-checked against the real blob)."""
    output = package(native, tmp_path, {"index.php": '<?php echo "never";'})
    p = output / "index.php"
    blob = bytearray(p.read_bytes())
    off = len(a.STUB) + 58  # source_length field (uint32 BE)
    blob[off : off + 4] = (16 * 1024 * 1024 - 1).to_bytes(4, "big")
    p.write_bytes(blob)
    result = php(native, p)
    assert result.returncode != 0
    assert "invalid protected file size" in result.stderr
    assert "never" not in result.stdout


def test_php_wrong_installation(native, tmp_path):
    """Package addressed to a recipient the host does not hold: fail closed."""
    other = a.make_recipient("other")
    output = package(native, tmp_path, {"index.php": '<?php echo "never";'},
                     recipients=[a.recipient_public(other)])
    result = php(native, output / "index.php")
    assert result.returncode != 0 and "invalid protected file" in result.stderr
    assert "never" not in result.stdout


def test_php_include_path_autoload_and_default_return(native, tmp_path):
    output = package(
        native, tmp_path,
        {
            "lib/thing.php": "<?php class Thing { public function value() { return 42; } }",
            "empty.php": "<?php /* default include return must be 1 */",
            "index.php": """<?php
set_include_path(__DIR__ . '/lib');
spl_autoload_register(function($c) { require 'thing.php'; });
echo (new Thing)->value(), ':', require __DIR__ . '/empty.php';
""",
        },
    )
    result = php(native, output / "index.php")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "42:1"


def test_php_template_and_line_numbers(native, tmp_path):
    output = package(native, tmp_path, {"index.php": "HTML\n<?php echo __LINE__; ?> tail"})
    result = php(native, output / "index.php")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "HTML\n2 tail"


def test_php_syntax_error_cleans_up(native, tmp_path):
    output = package(native, tmp_path, {"index.php": "<?php function broken( {"})
    result = php(native, output / "index.php")
    assert result.returncode not in (0, -11, -6)
    assert "Parse error" in result.stderr


def test_php_catch_parse_error_and_continue(native, tmp_path):
    output = package(
        native, tmp_path,
        {
            "broken.php": "<?php function broken( {",
            "index.php": """<?php
try { include __DIR__ . '/broken.php'; } catch (ParseError $e) { echo 'caught'; }
echo ':alive';
""",
        },
    )
    result = php(native, output / "index.php")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "caught:alive"


def _opcache_settings():
    """Return the -d flags to enable OPcache's SHM cache, or skip if unavailable."""
    extension_dir = subprocess.check_output(
        ["php", "-n", "-r", 'echo ini_get("extension_dir");'], text=True
    ).strip()
    cache = Path(extension_dir) / ("php_opcache.dll" if os.name == "nt" or PHP_WINDOWS else "opcache.so")
    located = ()
    if not cache.exists() and os.name == "nt" and shutil.which("php"):
        # The official Windows builds compile in C:\php\ext as the default extension_dir, so under
        # -n a PHP unpacked anywhere else did not find OPcache and every test here skipped on PHP
        # 8.2-8.4 (8.5 has it built in). Its modules are in the ext folder next to php.exe.
        beside = Path(shutil.which("php")).resolve().parent / "ext"
        if (beside / cache.name).exists():
            cache, located = beside / cache.name, ("-d", f"extension_dir={beside}")
    builtin = (
        subprocess.check_output(
            ["php", "-n", "-r", 'echo function_exists("opcache_get_status") ? "1" : "0";'], text=True
        ).strip() == "1"
    )
    if not builtin and not cache.exists():
        pytest.skip("OPcache unavailable")
    # A Windows PHP resolves a bare name in its extension_dir (a host path would not be absolute there).
    base = () if builtin else (*located, "-d", f"zend_extension={'opcache' if PHP_WINDOWS else cache}")
    # file_update_protection=0: OPcache otherwise skips files modified in the last 2 s, which
    # would make every "not cached" assertion on freshly packed files pass vacuously.
    return (*base, "-d", "opcache.enable=1", "-d", "opcache.enable_cli=1",
            "-d", "opcache.file_update_protection=0")


def test_php_opcache_rejected_by_default(native, tmp_path):
    """With OPcache's SHM cache on and no opt-in, protected files fail closed; plain PHP is
    unaffected (the decision is per protected file, not the whole request)."""
    output = package(native, tmp_path, {"index.php": '<?php echo "secret-output";'})
    result = php(native, output / "index.php", extra_ini=_opcache_settings())
    assert result.returncode != 0
    assert "secret-output" not in result.stdout
    assert "OPcache is enabled" in result.stderr


@pytest.mark.parametrize("directive", ["opcache.enable", "opcache.enable_cli"])
@pytest.mark.parametrize("value", ['"On"', '"yes"', '"true"'])
def test_php_opcache_quoted_boolean_rejected(native, tmp_path, directive, value):
    """A quoted boolean ("On") is not converted to "1" by the ini parser, but OPcache still
    reads it as true. Envelock must parse it the same way, or decrypted opcodes are cached."""
    output = package(native, tmp_path, {"index.php": '<?php echo "secret-output";'})
    loader = _opcache_settings()[:-6]  # only the zend_extension part, if any
    other = "opcache.enable_cli" if directive == "opcache.enable" else "opcache.enable"
    result = php(native, output / "index.php",
                 extra_ini=(*loader, "-d", f"{other}=1", "-d", f"{directive}={value}"))
    assert result.returncode != 0
    assert "secret-output" not in result.stdout
    assert "OPcache is enabled" in result.stderr


def test_php_cli_with_opcache_loaded_but_inactive_runs(native, tmp_path):
    """CLI with OPcache loaded and the stock defaults (opcache.enable=1, enable_cli=0): OPcache
    does not cache in CLI, so protected files must run (cron jobs, console commands). PHP 8.5
    always ships OPcache with these defaults."""
    output = package(native, tmp_path, {"index.php": '<?php echo "cli-ok";'})
    loader = _opcache_settings()[:-6]
    result = php(native, output / "index.php",
                 extra_ini=(*loader, "-d", "opcache.enable=1", "-d", "opcache.enable_cli=0"))
    assert result.returncode == 0, result.stderr
    assert result.stdout == "cli-ok"


def test_php_opcache_allowed_with_blacklist(native, tmp_path):
    """Opt-in + blacklist: the protected file runs with OPcache on and is NOT cached in SHM, while
    a plain file in the same run IS cached. The plain control keeps PROTCACHED=0 from passing
    vacuously: it proves OPcache is active and that the blacklist is what excludes the protected
    tree (the old control for this relied on the un-blacklisted file being cached, which now fails
    closed — see test_php_opcache_without_blacklist_fails_closed)."""
    output = package(native, tmp_path, {"index.php": '<?php echo "runs-uncached";'})
    plain = tmp_path / "plain.php"
    plain.write_text("<?php return 1;")
    blacklist = tmp_path / "bl.txt"
    blacklist.write_text(str(output) + "\n")
    probe = (
        'require $argv[1]; require $argv[2]; $s = opcache_get_status(true)["scripts"] ?? [];'
        '$prot = $plain = 0;'
        'foreach (array_keys($s) as $k) { if (str_contains($k, "index.php")) $prot++;'
        ' if (str_contains($k, "plain.php")) $plain++; }'
        'fwrite(STDERR, "PROTCACHED=$prot PLAINCACHED=$plain");'
    )
    result = php(
        native, "-r", probe, str(output / "index.php"), str(plain),
        extra_ini=(*_opcache_settings(), "-d", f"opcache.blacklist_filename={blacklist}",
                   "-d", "envelock.allow_opcache=1"),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "runs-uncached"
    assert "PROTCACHED=0" in result.stderr      # protected file not cached in SHM
    assert "PLAINCACHED=1" in result.stderr     # OPcache is active; only the protected tree is excluded


def test_php_opcache_without_blacklist_fails_closed(native, tmp_path):
    """ENV-05: opt-in but WITHOUT the blacklist (an operator mistake). OPcache sets
    ZEND_COMPILE_IGNORE_OTHER_FILES on CG(compiler_options) only when it is about to persist this
    file to SHM; the loader sees it and fails closed, so decrypted opcodes never reach shared
    memory. Without the guard OPcache would cache and serve the file (returncode 0, output shown)."""
    output = package(native, tmp_path, {"index.php": '<?php echo "secret-output";'})
    result = php(native, output / "index.php",
                 extra_ini=(*_opcache_settings(), "-d", "envelock.allow_opcache=1"))
    assert result.returncode != 0
    assert "secret-output" not in result.stdout
    assert "cache this protected file in shared memory" in result.stderr


def test_php_harden_memory_locks_keys(native, tmp_path):
    """envelock.harden_memory (ON by default) locks the loaded private keys into RAM and marks the
    process non-dumpable. Measured here by VmLck in /proc/self/status; the protected file still
    runs, and harden_memory=0 turns it off."""
    if PHP_WINDOWS:
        pytest.skip("Windows PHP locks via VirtualLock; no /proc to measure here")
    try:
        status = open("/proc/self/status").read()
    except OSError:
        pytest.skip("no /proc/self/status")
    if "VmLck" not in status:
        pytest.skip("kernel does not report VmLck")
    libc = ctypes.CDLL(None)
    page = ctypes.create_string_buffer(65536)
    if libc.mlock(page, 65536) == 0:
        locked = [line for line in open("/proc/self/status") if line.startswith("VmLck:")]
        libc.munlock(page, 65536)
        if locked and locked[0].split()[1] == "0":
            pytest.skip("this kernel grants mlock but does not report it in VmLck (e.g. WSL1)")
    probe = ('<?php preg_match("/^VmLck:\\\\s*(\\\\d+)/m", file_get_contents("/proc/self/status"), $m);'
             ' echo "ok:" . ($m[1] ?? "?");')
    output = package(native, tmp_path, {"index.php": probe})
    on = php(native, output / "index.php")                                         # default: on
    off = php(native, output / "index.php", extra_ini=("-d", "envelock.harden_memory=0"))
    assert on.returncode == 0 and on.stdout.startswith("ok:"), on.stdout + on.stderr
    assert int(on.stdout.split(":")[1]) > 0, "keys not locked by default"
    assert off.stdout == "ok:0", off.stdout + off.stderr                           # off: not locked


def test_php_rejects_zend_multibyte(native, tmp_path):
    """ENV-01: zend.multibyte (a per-dir / per-user INI) routes the decrypted source through
    mbstring's encoding filters. The loader fails closed rather than compile a protected file on
    that ambiguous path. Fails without the guard (the file runs)."""
    output = package(native, tmp_path, {"index.php": '<?php echo "mb-output";'})
    result = php(native, output / "index.php", extra_ini=("-d", "zend.multibyte=1"))
    assert result.returncode != 0
    assert "mb-output" not in result.stdout
    assert "zend.multibyte must be off" in result.stderr


def test_php_opcache_file_cache_always_refused(native, tmp_path):
    """opcache.file_cache (disk) is refused even with the opt-in: it would persist opcodes."""
    file_cache = tmp_path / "fc"
    file_cache.mkdir()
    output = package(native, tmp_path, {"index.php": '<?php echo "never";'})
    result = php(
        native, output / "index.php",
        extra_ini=(*_opcache_settings(), "-d", f"opcache.file_cache={PHP_PATH_PREFIX}{file_cache}",
                   "-d", "envelock.allow_opcache=1"),
    )
    assert result.returncode != 0
    assert "never" not in result.stdout
    assert "persist decrypted opcodes" in result.stderr


PREFLIGHT = ROOT / "scripts" / "envelock-preflight.php"


def test_preflight_accepts_a_configured_loader(native, tmp_path):
    """scripts/envelock-preflight.php (docs/HOSTING.md) run by the PHP that loads Envelock with a
    valid identity file and OPcache off: it reports the loader and its identity as accepted, and no
    OPcache problem."""
    result = php(native, PREFLIGHT)
    assert "identity file accepted" in result.stdout, result.stdout + result.stderr
    opcache = [line for line in result.stdout.splitlines() if line.split()[1:2] == ["OPcache"]]
    assert opcache and opcache[0].startswith("OK"), result.stdout


@pytest.mark.parametrize("opt_in", [False, True])
def test_opcache_switched_off_after_startup_runs_and_preflight_agrees(native, tmp_path, opt_in):
    """HOST-1. OPcache on in php.ini and switched off later — what a host's per-directory .user.ini,
    vhost or FPM pool override does; here an auto_prepend_file calling ini_set — leaves OPcache's
    compile hook installed above Envelock's, passing every file straight through. The loader used
    to take it for a foreign hook and refuse the site (with or without allow_opcache); it now
    recognises OPcache's own code and runs the file, which OPcache does not cache. The pre-flight
    check must agree with the loader, or it misleads the people it is meant to help."""
    off = tmp_path / "off.php"
    off.write_text('<?php ini_set("opcache.enable", "0");')
    settings = (*_opcache_settings(), "-d", f"auto_prepend_file={off}")
    output = package(native, tmp_path, {"index.php": '<?php echo "runs-uncached";'})
    if opt_in:
        blacklist = tmp_path / "bl.txt"
        blacklist.write_text(str(output) + "\n")
        settings += ("-d", "envelock.allow_opcache=1", "-d", f"opcache.blacklist_filename={blacklist}")
    report = php(native, PREFLIGHT, extra_ini=settings)
    opcache = [line for line in report.stdout.splitlines() if line.split()[1:2] == ["OPcache"]]
    assert opcache and opcache[0].startswith("OK") and "switched off" in opcache[0], report.stdout
    ran = php(native, output / "index.php", extra_ini=settings)
    assert ran.returncode == 0, ran.stderr
    assert ran.stdout == "runs-uncached"


def test_opcache_switch_off_does_not_excuse_a_foreign_hook(native, tmp_path):
    """HOST-1's exception is for OPcache's and Phar's own code, recognised by the image it lives in.
    A test module that installs its compile hook above Envelock is still refused when OPcache is
    loaded and switched off at run time, exactly as without OPcache."""
    path = o3_package(native, tmp_path)
    hook = build_hook(tmp_path, "rehook_compile", source_dir="rehook",
                      cflags="-DREHOOK_MODE=REHOOK_COMPILE_FILE")
    off = tmp_path / "off.php"
    off.write_text('<?php ini_set("opcache.enable", "0");')
    result = o3_run(native, path, extra_extension=hook,
                    extra_ini=(*_opcache_settings(), "-d", f"auto_prepend_file={off}"))
    assert result.returncode != 0
    assert "compile hook above Envelock" in result.stderr, result.stderr


def test_php_open_basedir_respected(native, tmp_path):
    output = package(native, tmp_path, {"index.php": '<?php echo "never";'})
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    result = php(
        native, "-r", "require " + php_literal(str(output / "index.php")) + ";",
        extra_ini=("-d", f"open_basedir={allowed}"),
    )
    assert result.returncode != 0
    assert "never" not in result.stdout
    assert "open_basedir restriction in effect" in result.stderr  # refused for that reason


@pytest.mark.skipif(os.name == "nt" or os.geteuid() != 0, reason="needs root to chown")
def test_php_identity_foreign_owner_rejected(native, tmp_path):
    """POSIX: a 0600 identity file owned by another user is refused (owner must be the user
    that starts PHP, e.g. root for the PHP-FPM master)."""
    foreign = tmp_path / "foreign-identity.bin"
    write_identity(foreign, [a.make_identity(native[3], native[2])])
    os.chown(foreign, 65534, -1)
    output = package(native, tmp_path, {"index.php": '<?php echo "never";'})
    result = php(native, output / "index.php", identity=foreign)
    assert result.returncode != 0 and "never" not in result.stdout
    assert FOREIGN_IDENTITY in result.stderr


@pytest.fixture(scope="session")
def core(tmp_path_factory):
    lib = os.getenv("ENVELOCK_CRYPTO_LIB")
    if not lib:
        if os.name == "nt" or not shutil.which("cc") or not shutil.which("pkg-config"):
            pytest.skip("Set ENVELOCK_CRYPTO_LIB to a native crypto test library")
        path = tmp_path_factory.mktemp("core") / "libenvelock_crypto.so"
        flags = shlex.split(
            subprocess.check_output(["pkg-config", "--cflags", "--libs", "libcrypto"], text=True)
        )
        subprocess.run(
            ["cc", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror", "-O2",
             str(ROOT / "extension/envelock_crypto.c"), "-o", str(path), *flags],
            check=True,
        )
        lib = str(path)
    dll_directory = None
    if os.name == "nt" and os.getenv("ENVELOCK_DLL_DIR"):
        dll_directory = os.add_dll_directory(os.environ["ENVELOCK_DLL_DIR"])
    try:
        loaded = ctypes.CDLL(lib)
    finally:
        if dll_directory:
            dll_directory.close()
    loaded.envelock_decrypt.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t),
    ]
    loaded.envelock_decrypt.restype = ctypes.c_int
    loaded.envelock_clear_source.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    loaded.envelock_clear_source.restype = None
    return loaded


def decode(core, blob, identity):
    output = ctypes.c_void_p()
    length = ctypes.c_size_t()
    buffers = [
        ctypes.create_string_buffer(value)
        for value in [
            blob,
            bytes.fromhex(identity["x25519_private"]),
            bytes.fromhex(identity["x25519_public"]),
            bytes.fromhex(identity["signing_public"]),
        ]
    ]
    result = core.envelock_decrypt(
        buffers[0], len(blob), *buffers[1:], ctypes.byref(output), ctypes.byref(length)
    )
    if result:
        try:
            return ctypes.string_at(output, length.value)
        finally:
            core.envelock_clear_source(output, length.value)
    assert output.value is None and length.value == 0
    return None


def fresh_material():
    owner = a.make_owner()
    recipient = a.make_recipient("core")
    return owner, recipient, a.make_identity(recipient, owner)


@pytest.mark.parametrize("source", [b"", b"<?php echo 1;", b"x" * 100000], ids=["empty", "php", "100KiB"])
def test_core_python_interoperability(core, source):
    material = fresh_material()
    assert decode(core, sample(material, source), material[2]) == source


def test_core_cross_recipient_rejected(core):
    material = fresh_material()
    stranger = fresh_material()
    assert decode(core, sample(material), stranger[2]) is None


def test_core_mutations_and_truncations(core):
    material = fresh_material()
    blob = sample(material)
    for offset in range(len(blob)):
        damaged = bytearray(blob)
        damaged[offset] ^= 0x80
        assert decode(core, bytes(damaged), material[2]) is None
    for cut in range(len(blob)):
        assert decode(core, blob[:cut], material[2]) is None
    assert decode(core, blob + b"x", material[2]) is None


def test_core_signed_but_invalid_gcm_and_sizes(core):
    material = fresh_material()
    signer = a.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(material[0]["signing_private"]))
    blob = sample(material)
    stub, header_end = len(a.STUB), len(a.STUB) + a.HEADER.size
    # Re-sign corrupt envelopes/payloads: exercise the KEM/GCM, not just the signature.
    table = header_end + len("app.php")   # sample() packages its file as app.php
    for offset in (
        stub + 8,                      # version byte
        stub + 9,                      # flags (an unknown bit)
        stub + 44,                     # recipient count
        header_end,                    # relative path (AAD)
        table + 32,                    # ephemeral_pub inside entry (KEM binding)
        table + 64,                    # wrap_nonce
        table + 76,                    # wrapped key
        table + a.RECIPIENT_SIZE,      # ciphertext
    ):
        body = bytearray(blob[:-64])
        body[offset] ^= 0x80
        altered = bytes(body) + signer.sign(bytes(body))
        assert decode(core, altered, material[2]) is None


def test_core_anti_downgrade_v1(core):
    material = fresh_material()
    signer = a.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(material[0]["signing_private"]))
    body = bytearray(sample(material)[:-64])
    body[len(a.STUB) : len(a.STUB) + 8] = b"ENVLK01\0"
    altered = bytes(body) + signer.sign(bytes(body))  # validly signed, wrong magic
    assert decode(core, altered, material[2]) is None


def test_core_random_garbage(core):
    material = fresh_material()
    randomizer = random.Random(83212)
    for _ in range(1000):
        value = randomizer.randbytes(randomizer.randrange(0, 512))
        assert decode(core, value, material[2]) is None


def test_php_repeated_include_and_strict_types(native, tmp_path):
    output = package(
        native, tmp_path,
        {
            "piece.php": "<?php return 42;",
            "index.php": """<?php
declare(strict_types=1);
function needsInt(int $n): int { return $n; }
try { needsInt('1'); } catch (TypeError $e) { echo 'strict:'; }
for ($i = 0; $i < 2000; $i++) {
    if ((include __DIR__ . '/piece.php') !== 42) { throw new Exception('bad include'); }
}
echo 'ok';
""",
        },
    )
    result = php(native, output / "index.php")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "strict:ok"


def refused(result, reason):
    return result.returncode != 0 and f"Envelock: refused: {reason}" in result.stderr


def test_php_file_bound_to_its_packaged_path(native, tmp_path):
    """A protected file only runs at the relative path it was packaged with: no renaming or
    swapping files inside a package; the whole package can still move."""
    out = package(native, tmp_path, {"a.php": "<?php echo 'A';", "sub/b.php": "<?php echo 'B';"})
    assert php(native, out / "sub" / "b.php").stdout == "B"
    moved = tmp_path / "elsewhere"
    shutil.copytree(out, moved)
    assert php(native, moved / "a.php").stdout == "A"                      # package moved: fine
    (moved / "b.php").write_bytes((moved / "sub" / "b.php").read_bytes())  # file moved
    assert refused(php(native, moved / "b.php"), "the file is not at the path")
    a_blob, b_blob = (moved / "a.php").read_bytes(), (moved / "sub" / "b.php").read_bytes()
    (moved / "a.php").write_bytes(b_blob)                                  # files swapped
    (moved / "sub" / "b.php").write_bytes(a_blob)
    assert refused(php(native, moved / "a.php"), "the file is not at the path")
    assert refused(php(native, moved / "sub" / "b.php"), "the file is not at the path")


def test_php_no_mixed_releases_in_one_folder(native, tmp_path):
    """A file from another release (or project) dropped into a package folder is refused."""
    project = str(uuid.uuid4())
    files = {"main.php": "<?php require __DIR__ . '/lib.php'; echo v();",
             "lib.php": "<?php function v() { return 'new'; }"}
    new = package(native, tmp_path, files, project=project)
    old = package(native, tmp_path, dict(files, **{"lib.php": "<?php function v() { return 'old'; }"}),
                  project=project)
    assert php(native, new / "main.php").stdout == "new"
    (new / "lib.php").write_bytes((old / "lib.php").read_bytes())
    assert refused(php(native, new / "main.php"), "files of different releases")


def test_php_minimum_serial_refuses_old_releases(native, tmp_path):
    project = str(uuid.uuid4())
    old = package(native, tmp_path, {"index.php": "<?php echo 'old';"}, project=project, serial=100)
    new = package(native, tmp_path, {"index.php": "<?php echo 'new';"}, project=project, serial=200)
    identity = tmp_path / "minimum-identity.bin"
    write_identity(identity, [a.make_identity(native[3], native[2])])
    store = a.set_minimum(identity.read_bytes(), project, 200)
    identity.unlink()
    fd = os.open(identity, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(store)
    assert php(native, old / "index.php").stdout == "old"                 # default identity: no minimum
    assert refused(php(native, old / "index.php", identity=identity), "this release is older")
    assert php(native, new / "index.php", identity=identity).stdout == "new"
    other = package(native, tmp_path, {"index.php": "<?php echo 'other';"}, serial=1)
    assert php(native, other / "index.php", identity=identity).stdout == "other"   # other project


INCLUDE_FILES = {
    "main.php": "<?php require __DIR__ . '/loader.php'; echo (new Secret\\Lib())->name(), '|';"
                " require __DIR__ . '/lib/helper.php'; echo helper();",
    "lib/Lib.php": "<?php namespace Secret; class Lib { function name() { return 'lib'; } }",
    "lib/helper.php": "<?php function helper() { return 'helper'; }",
}
LOADER = ("<?php spl_autoload_register(function ($c) { $f = __DIR__ . '/lib/' . basename(str_replace('\\\\', '/', $c)) . '.php';"
          " if (is_file($f)) require $f; });")


def serve_over_http(native, docroot, paths):
    """Serve docroot with the built-in web server (the cli-server SAPI, which — like Apache's
    mod_php — does NOT set file_handle->primary_script) and GET each path. Returns the response
    bodies. Skips if the server cannot bind (e.g. a Windows PHP under Wine with no network)."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    proc = popen_server(
        ["php", "-n", "-d", f"extension={native[1]}", "-d", f"envelock.identity={native[4]}",
         "-d", "opcache.enable=0", "-d", "opcache.enable_cli=0", "-d", "display_errors=1",
         "-S", f"127.0.0.1:{port}", "-t", str(docroot)])
    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            if proc.poll() is not None:
                pytest.skip("built-in server did not start: " + server_output(proc)[-400:])
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                conn.request("GET", "/__ping")
                conn.getresponse().read()
                conn.close()
                break
            except OSError:
                time.sleep(0.2)
        else:
            pytest.skip("built-in server never became ready")
        bodies = []
        for path in paths:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request("GET", path)
            bodies.append(conn.getresponse().read().decode(errors="replace"))
            conn.close()
        return bodies
    finally:
        stop_server(proc)


def test_php_include_protection_entry_under_web_sapi(native, tmp_path):
    """Under a SAPI that does not set primary_script (the built-in server, like Apache's mod_php),
    the directly requested protected entry point must still run (1.0.0 bug: include protection
    refused even the entry under mod_php because it relied only on primary_script). An unprotected
    script that pulls a protected file in is still refused, so the protection is not weakened."""
    out = package(native, tmp_path, INCLUDE_FILES, include_protection=True)
    (out / "loader.php").write_text(LOADER)
    (out / "attacker.php").write_text("<?php require __DIR__ . '/lib/helper.php'; echo helper();")
    entry, attacker = serve_over_http(native, out, ["/main.php", "/attacker.php"])
    assert entry == "lib|helper", entry                                   # entry runs under mod_php
    assert "include protection" in attacker, attacker                     # foreign script still refused


def test_php_include_protection_survives_userspace_stream_wrapper(native, tmp_path):
    """ENV-02: a user-space stream wrapper can feed a protected container's bytes while faking the
    reported opened_path (even to the main script's own path). Path binding and include protection
    must still refuse it: neither the forged location nor a forged "entry" lets an unprotected
    script load protected code."""
    output = package(native, tmp_path, {"index.php": "<?php function secret(){ return 'LOGIC'; }"},
                     include_protection=True)
    container = str((output / "index.php"))
    attacker = tmp_path / "index.php"               # same basename as the container's packaged path
    attacker.write_text(
        "<?php class W { public $context; private $d; private $p = 0;"
        " function stream_open($path,$m,$o,&$opened){"
        "  $this->d = file_get_contents(substr($path, strpos($path,'://')+3)); $opened = __FILE__; return true; }"
        " function stream_read($n){ $r = substr($this->d,$this->p,$n); $this->p += strlen($r); return $r; }"
        " function stream_eof(){ return $this->p >= strlen($this->d); }"
        " function stream_set_option($a,$b,$c){ return true; }"
        " function stream_stat(){ return array(); } function url_stat($p,$f){ return array(); } }"
        " stream_wrapper_register('ev','W',0);"
        " try { include 'ev://'.$argv[1]; echo function_exists('secret') ? 'LEAK' : 'no-func'; }"
        " catch (\\Throwable $e) { echo 'REFUSED'; }")
    result = php(native, str(attacker), container)
    assert "LEAK" not in result.stdout, result.stdout + result.stderr
    assert "LOGIC" not in result.stdout


def test_php_include_protection_not_bypassed_by_another_developer(native, tmp_path):
    """ENV-04: two developers trusted in one identity bundle. Developer B packs a container that
    claims developer A's project id (signed with B's own key, which the host trusts). It must NOT
    satisfy A's include protection: a protected file runs only when a file of the same project AND
    the same signing developer is on the stack. Without the signer binding, B's file loads A's
    protected code."""
    owner_a, owner_b = a.make_owner(), a.make_owner()
    recipient = a.make_recipient("shared")
    bundle = tmp_path / "bundle.bin"
    write_identity(bundle, [a.make_identity(recipient, owner_a), a.make_identity(recipient, owner_b)])
    project = str(uuid.uuid4())
    pub = [a.recipient_public(recipient)]

    src_a = tmp_path / "src-a"
    (src_a / "lib").mkdir(parents=True)
    (src_a / "lib" / "secret.php").write_text("<?php function secret(){ return 'A-LOGIC'; }")
    out_a = tmp_path / "out-a"
    a.pack_tree(src_a, out_a, pub, owner_a, project, include_protection=True)

    src_b = tmp_path / "src-b"
    src_b.mkdir()
    (src_b / "evil.php").write_text(
        "<?php require %r; echo function_exists('secret') ? 'LEAK' : 'no';"
        % str(out_a / "lib" / "secret.php"))
    out_b = tmp_path / "out-b"
    a.pack_tree(src_b, out_b, pub, owner_b, project, include_protection=True)  # B signs, A's project id

    result = php(native, out_b / "evil.php", identity=bundle)
    assert refused(result, "include protection"), result.stdout + result.stderr
    assert "LEAK" not in result.stdout


def test_php_include_protection(native, tmp_path):
    """With --include-protection, protected files run only as the entry point or when loaded from
    protected code of the same project (a plain autoloader it calls is fine); another script
    cannot load them. Without the flag (control), it can."""
    guarded = None
    for protected in (True, False):
        out = package(native, tmp_path, INCLUDE_FILES, include_protection=protected)
        guarded = guarded or out
        (out / "loader.php").write_text(LOADER)                          # plain, like Composer's
        assert php(native, out / "main.php").stdout == "lib|helper"
        (out / "attacker.php").write_text("<?php require __DIR__ . '/lib/helper.php'; echo helper();")
        (out / "autoload-attacker.php").write_text(
            "<?php require __DIR__ . '/loader.php'; echo (new Secret\\Lib())->name();")
        for script, expected in (("attacker.php", "helper"), ("autoload-attacker.php", "lib")):
            result = php(native, out / script)
            if protected:
                assert refused(result, "include protection"), result.stdout + result.stderr
            else:
                assert result.returncode == 0 and result.stdout == expected, result.stderr
    other = package(native, tmp_path, {"other.php": "<?php require $argv[1]; echo helper();"},
                    include_protection=True)
    result = php(native, other / "other.php", guarded / "lib" / "helper.php")
    assert refused(result, "include protection")                          # other project's code


def test_php_no_prepend(native, tmp_path):
    prepend = tmp_path / "prepend.php"
    prepend.write_text("<?php echo 'injected|';")
    for flag in (True, False):
        out = package(native, tmp_path, {"index.php": "<?php echo 'app';"}, no_prepend=flag)
        assert php(native, out / "index.php").stdout == "app"
        for directive in ("auto_prepend_file", "auto_append_file"):
            result = php(native, out / "index.php", extra_ini=("-d", f"{directive}={prepend}"))
            if flag:
                assert refused(result, "auto_prepend_file/auto_append_file are set"), result.stdout
            else:
                assert result.returncode == 0 and "app" in result.stdout


@pytest.mark.parametrize("module", ["vld", "pcov"])     # pcov stands in for the M-03 profiler list
def test_php_refuses_debugging_extensions(native, tmp_path, module):
    """A loaded extension that can dump or trace the decrypted code (stood in for by a test-only
    module) makes protected files fail closed unless envelock.allow_debuggers=1. Covers a classic
    debugger (vld) and one of the profilers added in M-03 (pcov)."""
    if os.getenv("ENVELOCK_TEST_EXTENSION"):
        pytest.skip("needs the local PHP build tools")
    hook = build_hook(tmp_path, module)
    out = package(native, tmp_path, {"index.php": "<?php echo 'app';"})
    plain = tmp_path / "plain.php"
    plain.write_text("<?php echo 'plain';")
    base = ["php", "-n", "-d", f"extension={hook}", "-d", f"extension={native[1]}",
            "-d", f"envelock.identity={native[4]}", "-d", "opcache.enable_cli=0", "-d", "display_errors=stderr"]
    run = lambda *extra: subprocess.run([*base, *extra], capture_output=True, text=True, check=False,  # noqa: E731
                                        env=php_environment())
    result = run(str(out / "index.php"))
    assert result.returncode != 0 and f"Envelock: {module} is loaded" in result.stderr, result.stdout
    assert run(str(plain)).stdout == "plain"                              # plain PHP unaffected
    assert run("-d", "envelock.allow_debuggers=1", str(out / "index.php")).stdout == "app"


def test_php_refuses_phpdbg(native, tmp_path):
    phpdbg = shutil.which("phpdbg")
    if not phpdbg or Path(phpdbg).parent != Path(shutil.which("php")).parent:
        pytest.skip("phpdbg of the same PHP build required")
    out = package(native, tmp_path, {"index.php": "<?php echo 'app';"})
    base = [phpdbg, "-n", "-q", "-d", f"extension={native[1]}", "-d", f"envelock.identity={native[4]}",
            "-d", "opcache.enable_cli=0", "-rr"]
    result = subprocess.run([*base, str(out / "index.php")], capture_output=True, text=True,
                            check=False, timeout=30)
    assert "app" not in result.stdout and "Envelock: phpdbg is loaded" in result.stdout + result.stderr


@pytest.mark.skipif(not (sys.platform.startswith(("win", "darwin")) or PHP_WINDOWS),
                    reason="case-insensitive file systems")
def test_php_mixed_releases_detected_whatever_the_folder_case(native, tmp_path):
    """On Windows/macOS one folder spelled with another letter case is still one package folder."""
    project = str(uuid.uuid4())
    swap = "$alt = str_replace('protected-', 'PROTECTED-', __DIR__);"   # package() folder names
    files = {"main.php": f"<?php require __DIR__ . '/lib.php'; {swap} require $alt . '/other.php'; echo 'mixed';",
             "lib.php": "<?php", "other.php": "<?php"}
    new = package(native, tmp_path, files, project=project)
    old = package(native, tmp_path, files, project=project)
    (new / "other.php").write_bytes((old / "other.php").read_bytes())
    assert refused(php(native, new / "main.php"), "files of different releases")


@pytest.mark.skipif(PHP_WINDOWS and sys.platform != "win32",
                    reason="Wine's Z: drive does not present a non-ASCII Linux filename as the UTF-16 "
                    "name the Windows loader looks up; runs on real Windows")
def test_php_identity_path_non_ascii(native, tmp_path):
    """ENV-14: the identity file opens even when its path has non-ASCII characters. On Windows the
    loader used fopen(), which reads the php.ini value in the ANSI code page and fails on a UTF-8
    path (e.g. an accented folder name); it now opens through the wide API (MultiByteToWideChar +
    _wfopen). Runs on POSIX (open handles UTF-8) and on real Windows; skipped only for a Windows PHP
    driven from Linux under Wine, which cannot model the non-ASCII file system."""
    weird = tmp_path / "idéñ.bin"
    write_identity(weird, [a.make_identity(native[3], native[2])])
    out = package(native, tmp_path, {"index.php": "<?php echo 'OK', 42;"})
    result = php(native, out / "index.php", identity=weird)
    assert result.returncode == 0 and result.stdout == "OK42", result.stderr


def php_with_ini(native, tmp_path, script, settings):
    """Runs php with its settings in a UTF-8 php.ini (-c) instead of -d options: how a server is
    configured, and on Windows the route where a path reaches the module as UTF-8 (php.exe hands a -d
    value over in the ANSI code page instead)."""
    values = {"extension": native[1], "envelock.identity": native[4], "display_errors": "stderr",
              "opcache.enable": "0", "opcache.enable_cli": "0"}
    values.update(settings)
    ini = tmp_path / ("php-" + uuid.uuid4().hex + ".ini")
    ini.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")
    environment = php_environment()
    environment.pop("PHP_INI_SCAN_DIR", None)
    return subprocess.run(["php", "-c", str(ini), str(script)], capture_output=True, text=True,
                          check=False, env=environment)


@pytest.mark.skipif(PHP_WINDOWS and sys.platform != "win32",
                    reason="Wine's Z: drive cannot present a non-ASCII Linux filename to a Windows PHP")
def test_php_non_ascii_identity_and_clock_paths_from_a_utf8_php_ini(native, tmp_path):
    """ENV-14, both encodings: a non-ASCII identity, licence and clock-state path works when it comes
    from a UTF-8 php.ini (on Windows the CRT open()/fopen() would read those bytes in the ANSI code page
    and name a missing file) as well as from -d (ANSI on Windows); the clock state is written to the
    file that was named, not to a mangled name beside it."""
    folder = tmp_path / "carpeta-ñandú"
    folder.mkdir()
    identity = folder / "idéñ.bin"
    write_identity(identity, [a.make_identity(native[3], native[2])])
    out = package(native, tmp_path, {"index.php": "<?php echo 'UTF', 8;"})
    licence = folder / "licencia-é.bin"
    licence.write_bytes(a.issue_licence(native[2], expires=int(time.time()) + 3600))
    state = folder / "reloj-ü.state"
    run = php_with_ini(native, tmp_path, out / "index.php",
                       {"envelock.identity": identity, "envelock.licence": licence, "envelock.clock_state": state})
    assert run.returncode == 0 and run.stdout == "UTF8", run.stderr
    assert state.is_file() and state.stat().st_size > 0, sorted(p.name for p in folder.iterdir())
    second = folder / "reloj-ø.state"
    if sys.platform == "win32":
        import ctypes
        try:   # php.exe receives -d values in the ANSI code page: only a representable name can work
            str(second).encode(f"cp{ctypes.windll.kernel32.GetACP()}")
        except (UnicodeEncodeError, LookupError):
            return
    run = php(native, out / "index.php", identity=identity,
              extra_ini=("-d", f"envelock.licence={licence}", "-d", f"envelock.clock_state={second}"))
    assert run.returncode == 0 and run.stdout == "UTF8", run.stderr
    assert second.is_file() and second.stat().st_size > 0, sorted(p.name for p in folder.iterdir())
    assert sorted(p.name for p in folder.iterdir()) == sorted(
        [identity.name, licence.name, state.name, second.name])


def _ffi_loaded():
    """True iff this PHP can load the FFI extension (only then can the refusal be exercised)."""
    probe = subprocess.run(
        ["php", "-n", "-d", "extension=ffi", "-r", "echo extension_loaded('ffi')?'1':'0';"],
        capture_output=True, text=True, check=False,
    )
    return probe.stdout.strip() == "1"


@pytest.mark.skipif(not _ffi_loaded(), reason="PHP build without a loadable FFI extension")
def test_php_no_ffi_refuses_only_when_ffi_reachable(native, tmp_path):
    """A --no-ffi package refuses while FFI or dl() can read the decrypted code from memory, runs
    when neither is reachable, and is unaffected by them when the flag is off (opt-in).
    (The CLI's compiled enable_dl default is On, so every allowed run disables dl() explicitly.)"""
    body = "<?php echo 'OK';"
    sealed = package(native, tmp_path, {"index.php": body}, no_ffi=True)
    plain = package(native, tmp_path, {"index.php": body})
    ffi_usable = ("-d", "extension=ffi", "-d", "ffi.enable=1", "-d", "enable_dl=0")
    ffi_disabled = ("-d", "extension=ffi", "-d", "ffi.enable=0", "-d", "enable_dl=0")
    dl_usable = ("-d", "enable_dl=1")
    nothing = ("-d", "enable_dl=0",)

    # Refused while FFI itself is usable...
    by_ffi = php(native, sealed / "index.php", extra_ini=ffi_usable)
    assert by_ffi.returncode != 0 and "FFI or dl()" in by_ffi.stderr and "OK" not in by_ffi.stdout
    # ...and while dl() could load the FFI extension at runtime.
    by_dl = php(native, sealed / "index.php", extra_ini=dl_usable)
    assert by_dl.returncode != 0 and "FFI or dl()" in by_dl.stderr

    # Allowed when FFI is loaded but disabled, and when neither path is reachable.
    assert php(native, sealed / "index.php", extra_ini=ffi_disabled).stdout == "OK"
    assert php(native, sealed / "index.php", extra_ini=nothing).stdout == "OK"

    # A package without the flag is unaffected by FFI/dl (strictly opt-in).
    unflagged = php(native, plain / "index.php", extra_ini=ffi_usable)
    assert unflagged.returncode == 0 and unflagged.stdout == "OK", unflagged.stderr


def test_php_sealed_refuses_plain_php_under_tree(native, tmp_path):
    """A sealed package refuses a plain .php injected under its folder. The protected entry
    compiles first (marking the tree sealed), so the later plain include is refused."""
    out = package(native, tmp_path,
                  {"index.php": "<?php echo 'A'; include __DIR__.'/evil.php'; echo 'B';"}, sealed=True)
    (out / "evil.php").write_text("<?php echo 'LEAK';", encoding="utf-8")  # injected plain file
    result = php(native, out / "index.php")
    assert result.returncode != 0
    assert "unprotected PHP is refused" in result.stderr
    assert "LEAK" not in result.stdout


def test_php_sealed_refuses_eval(native, tmp_path):
    """While a sealed package is active, eval() is refused (it could compile code that reads
    the decrypted source from the same process)."""
    out = package(native, tmp_path,
                  {"index.php": "<?php echo 'A'; eval('echo 42;'); echo 'B';"}, sealed=True)
    result = php(native, out / "index.php")
    assert result.returncode != 0
    assert "eval() is refused" in result.stderr
    assert "42" not in result.stdout


def test_php_unsealed_allows_plain_and_eval(native, tmp_path):
    """Without --sealed the feature is off: a plain sibling and eval() both work (opt-in)."""
    out = package(native, tmp_path,
                  {"index.php": "<?php include __DIR__.'/plain.php'; eval('echo 9;');"})
    (out / "plain.php").write_text("<?php echo 'P';", encoding="utf-8")
    result = php(native, out / "index.php")
    assert result.returncode == 0 and result.stdout == "P9", result.stderr


def test_php_truncation_sweep_refuses_and_never_leaks(native, tmp_path):
    """Hard audit: a protected file truncated at ANY length must never emit the secret and never crash
    the worker (a segfault returns a negative signal code on POSIX and an NTSTATUS exception code on
    Windows, see crashed(); an ASan build would abort). A truncation
    that still looks protected (>= the stub length) must be refused; a truncation below that becomes a
    plain/empty file the loader does not own. Covers every parse boundary at the real-loader level."""
    out = package(native, tmp_path, {"index.php": '<?php echo "SECRET42";'})
    p = out / "index.php"
    full = p.read_bytes()
    stub_len = len(b"<?php /* Envelock */ exit(\"Envelock loader required\\n\"); __halt_compiler();\n")
    lengths = sorted(set(list(range(0, min(260, len(full)))) + list(range(260, len(full), 97))))
    for n in lengths:
        p.write_bytes(full[:n])
        r = php(native, p)
        assert not crashed(r.returncode), f"worker crashed on truncation to {n} bytes: {describe_rc(r.returncode)}"
        assert "SECRET42" not in r.stdout, f"leaked at {n} bytes"
        if n >= stub_len:                       # still recognised as a protected file: must be refused
            assert r.returncode != 0, f"truncation to {n} bytes (still protected) was accepted"


def test_php_byteflip_sweep_in_payload_is_refused(native, tmp_path):
    """Hard audit: flipping any single byte of the AUTHENTICATED payload (everything after the stub:
    header, recipient table, ciphertext, GCM tag, Ed25519 signature) must be caught — the file stays
    recognised as protected, verification fails, it is refused, nothing runs, no crash. This is the
    end-to-end tamper-evidence property at the real-loader level (the crypto core itself is fuzzed with
    ASan separately). Flips inside the stub turn it into a plain file, a path covered elsewhere."""
    out = package(native, tmp_path, {"index.php": '<?php echo "SECRET42";'})
    p = out / "index.php"
    full = p.read_bytes()
    stub_len = len(b"<?php /* Envelock */ exit(\"Envelock loader required\\n\"); __halt_compiler();\n")
    positions = sorted(set([stub_len, stub_len + 1, stub_len + 16, stub_len + 40,
                            len(full) // 2, 3 * len(full) // 4] +
                           list(range(len(full) - 72, len(full)))))   # GCM tag + signature tail
    for pos in positions:
        if pos < stub_len or pos >= len(full):
            continue
        b = bytearray(full)
        b[pos] ^= 0x01
        p.write_bytes(bytes(b))
        r = php(native, p)
        assert r.returncode != 0, f"payload byte flip at {pos} was accepted"
        assert not crashed(r.returncode), f"worker crashed on flip at {pos}: {describe_rc(r.returncode)}"
        assert "SECRET42" not in r.stdout, f"leaked with byte {pos} flipped"


def test_php_sealed_cleartext_trailing_slash_and_multiple_entries(native, tmp_path):
    """Hard audit of the allowlist: a prefix WITH a trailing separator still matches files under it; a
    PATH_SEPARATOR list of several prefixes all work; and a sibling sharing the prefix string is still
    refused (boundary holds for the trailing-slash form too)."""
    out = package(native, tmp_path,
                  {"index.php": "<?php echo 'A'; include __DIR__.'/a/x.php'; include __DIR__.'/b/y.php';"
                                " echo 'Z';"}, sealed=True)
    (out / "a").mkdir()
    (out / "b").mkdir()
    (out / "a" / "x.php").write_text("<?php echo 'X';", encoding="utf-8")
    (out / "b" / "y.php").write_text("<?php echo 'Y';", encoding="utf-8")
    sep = ";" if PHP_WINDOWS else ":"                    # PHP's PATH_SEPARATOR
    allow = f"{out / 'a'}{os.sep}{sep}{out / 'b'}"       # first entry has a trailing separator
    # ';' starts a comment in an INI value: a Windows list must be quoted (as in php.ini).
    value = f'"{allow}"' if sep == ";" else allow
    r = php(native, out / "index.php", extra_ini=("-d", f"envelock.sealed_cleartext={value}"))
    assert r.stdout == "AXYZ", (r.stdout, r.stderr)      # both allowed dirs ran, nothing refused
    # And a sibling that merely shares the 'a' prefix is still refused (boundary with trailing slash).
    second = tmp_path / "second"
    second.mkdir()
    out2 = package(native, second,
                   {"index.php": "<?php echo 'A'; include __DIR__.'/aleak.php'; echo 'Z';"}, sealed=True)
    (out2 / "a").mkdir()
    (out2 / "aleak.php").write_text("<?php echo 'LEAK';", encoding="utf-8")
    r2 = php(native, out2 / "index.php", extra_ini=("-d", f"envelock.sealed_cleartext={out2 / 'a'}{os.sep}"))
    assert "LEAK" not in r2.stdout and r2.returncode != 0, (r2.stdout, r2.stderr)


def test_php_sealed_cleartext_allowlist(native, tmp_path):
    """envelock.sealed_cleartext whitelists paths that may run as cleartext under a sealed tree — a
    CMS's config and the PHP it generates at run time — so --sealed becomes usable with such an app
    while every OTHER plain file under the tree is still refused."""
    out = package(native, tmp_path,
                  {"index.php": "<?php echo 'A'; include __DIR__.'/sub/conf.php'; echo 'B'; "
                                "include __DIR__.'/evil.php'; echo 'C';"}, sealed=True)
    (out / "sub").mkdir()
    (out / "sub" / "conf.php").write_text("<?php echo 'CONF';", encoding="utf-8")   # app config, whitelisted
    (out / "evil.php").write_text("<?php echo 'LEAK';", encoding="utf-8")            # injected, NOT whitelisted
    res = php(native, out / "index.php", extra_ini=("-d", f"envelock.sealed_cleartext={out / 'sub'}"))
    assert "CONF" in res.stdout                 # the whitelisted cleartext file ran
    assert res.returncode != 0                  # but evil.php outside the allowlist is still refused
    assert "LEAK" not in res.stdout
    assert "unprotected PHP is refused" in res.stderr


def test_php_sealed_cleartext_allowlist_respects_path_boundary(native, tmp_path):
    """The sealed_cleartext prefix match must stop at a path separator: whitelisting '<out>/sub' must
    NOT also allow a sibling whose name merely STARTS with that string ('<out>/subleak.php'), or an
    attacker who can write such a sibling would run plain PHP inside a sealed tree. Regression for the
    prefix-boundary hole in envelock_sealed_cleartext_allowed (self-audit)."""
    out = package(native, tmp_path,
                  {"index.php": "<?php echo 'A'; include __DIR__.'/subleak.php'; echo 'C';"}, sealed=True)
    (out / "sub").mkdir()
    (out / "subleak.php").write_text("<?php echo 'LEAK';", encoding="utf-8")   # sibling, shares the 'sub' prefix
    res = php(native, out / "index.php", extra_ini=("-d", f"envelock.sealed_cleartext={out / 'sub'}"))
    assert "LEAK" not in res.stdout                                            # boundary: sibling is NOT allowed
    assert res.returncode != 0
    assert "unprotected PHP is refused" in res.stderr


def test_php_sealed_refuses_plain_php_outside_tree(native, tmp_path):
    """ENV-2026-28: while a sealed package is active, plain PHP must be refused WHEREVER it lives, not
    only under the sealed folder. A sealed app with an LFI vulnerability (or an attacker who can drop a
    file in /tmp) could otherwise `include '/tmp/evil.php'` and run plain code from OUTSIDE the tree —
    exactly the bypass the old 'under-root only' check allowed. The sealed_cleartext allowlist remains
    the single escape hatch."""
    out = package(native, tmp_path,
                  {"index.php": "<?php echo 'A'; include __DIR__.'/../ext_plain.php'; echo 'B';"},
                  sealed=True)
    (out.parent / "ext_plain.php").write_text("<?php echo 'LEAK';", encoding="utf-8")  # outside the tree
    result = php(native, out / "index.php")
    assert result.returncode != 0
    assert "unprotected PHP is refused" in result.stderr
    assert "LEAK" not in result.stdout
    # The allowlist still lets a legitimate outside-tree path through.
    ok = php(native, out / "index.php",
             extra_ini=("-d", f"envelock.sealed_cleartext={out.parent / 'ext_plain.php'}"))
    assert ok.returncode == 0 and ok.stdout == "ALEAKB", ok.stderr


def test_php_eval_runs_without_any_protected_file(native, tmp_path):
    """eval() must work when the loader is present but no protected (sealed) file is in play.
    Regression: on a ZTS build the per-request `sealed_active` was not zero-initialized, so a
    worker that compiled no protected file would spuriously refuse eval() and then fault when a
    plain include scanned the uninitialized roots table."""
    script = tmp_path / "plain.php"
    script.write_text("<?php eval('echo 7;'); echo 'E';", encoding="utf-8")
    result = php(native, script)
    assert result.returncode == 0 and result.stdout == "7E", result.stderr


def test_php_enforce_manifest_runs_when_intact(native, tmp_path):
    """A --enforce-manifest package runs when every listed file is present."""
    out = package(native, tmp_path,
                  {"index.php": "<?php echo 'OK';", "lib.php": "<?php function f(){}"},
                  enforce_manifest=True)
    assert (out / "envelock-manifest.bin").is_file()
    result = php(native, out / "index.php")
    assert result.returncode == 0 and result.stdout == "OK", result.stderr


def test_php_enforce_manifest_detects_missing_file(native, tmp_path):
    """Deleting any file listed in the signed manifest fails the request closed (deletion
    detection: e.g. a security check removed from the deployed package)."""
    out = package(native, tmp_path,
                  {"index.php": "<?php echo 'OK';", "lib.php": "<?php function f(){}"},
                  enforce_manifest=True)
    (out / "lib.php").unlink()
    result = php(native, out / "index.php")
    assert result.returncode != 0
    assert "listed in the signed manifest is missing" in result.stderr and "OK" not in result.stdout


def test_php_enforce_manifest_refuses_tampered_manifest(native, tmp_path):
    """A manifest whose signed bytes were altered no longer verifies and is refused."""
    out = package(native, tmp_path, {"index.php": "<?php echo 'OK';"}, enforce_manifest=True)
    man = out / "envelock-manifest.bin"
    blob = bytearray(man.read_bytes())
    blob[12] ^= 1                                        # flip a byte inside the signed region
    man.write_bytes(blob)
    result = php(native, out / "index.php")
    assert result.returncode != 0 and "not signed by the package's own developer" in result.stderr


def test_php_enforce_manifest_rejects_another_developers_manifest(native, tmp_path):
    """ENV-2026-25: on a host whose identity.bin trusts several INDEPENDENT developers, the manifest
    must be accepted only from the SAME developer that signed the package. Developer B re-signing
    developer A's manifest — to hide a deleted security file on A's deployment — must be refused, even
    though B is a trusted developer on the host. Before the fix the manifest check accepted any trusted
    signer; now it requires signer_developer_index == the package's developer."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    owner_a, owner_b = a.make_owner(), a.make_owner()
    # One recipient (the loader's), two independent developers → one ENVLKID3 store, signer_count == 2.
    id_a = a.make_identity(native[3], owner_a)
    id_b = a.make_identity(native[3], owner_b)
    identity_path = tmp_path / "identity_two_devs.bin"
    write_identity(identity_path, [id_a, id_b])
    out = package(native, tmp_path,
                  {"index.php": "<?php echo 'OK';", "guard.php": "<?php /* security check */"},
                  owner=owner_a, enforce_manifest=True)
    # Control: developer A's own manifest runs under the two-developer identity.
    ok = php(native, out / "index.php", identity=identity_path)
    assert ok.returncode == 0 and ok.stdout == "OK", ok.stderr[-800:]
    # Developer B re-signs the SAME manifest body with B's key (B has no access to A's key).
    man = out / "envelock-manifest.bin"
    body = man.read_bytes()[:-64]
    sk_b = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(owner_b["signing_private"]))
    man.write_bytes(body + sk_b.sign(body))
    forged = php(native, out / "index.php", identity=identity_path)
    assert forged.returncode != 0 and "not signed by the package's own developer" in forged.stderr


def test_php_enforce_manifest_refuses_missing_manifest(native, tmp_path):
    """If the package declares enforcement but the manifest file is gone, fail closed."""
    out = package(native, tmp_path, {"index.php": "<?php echo 'OK';"}, enforce_manifest=True)
    (out / "envelock-manifest.bin").unlink()
    result = php(native, out / "index.php")
    assert result.returncode != 0 and "is missing or not a regular file" in result.stderr


def test_php_without_enforce_manifest_unaffected_by_missing_file(native, tmp_path):
    """A package built without --enforce-manifest is not affected by a missing sibling (opt-in)."""
    out = package(native, tmp_path,
                  {"index.php": "<?php echo 'OK';", "lib.php": "<?php function f(){}"})
    (out / "lib.php").unlink()
    result = php(native, out / "index.php")
    assert result.returncode == 0 and result.stdout == "OK", result.stderr


def test_php_enforce_manifest_bound_to_release(native, tmp_path):
    """A signed manifest from a DIFFERENT release (same signer/files) cannot be swapped in to hide
    a deletion: the loader binds the manifest to the loaded package's project and release."""
    project = str(uuid.uuid4())
    body = {"index.php": "<?php echo 'OK';", "lib.php": "<?php function f(){}"}
    p1 = package(native, tmp_path, body, enforce_manifest=True, project=project)
    p2 = package(native, tmp_path, body, enforce_manifest=True, project=project)  # different release id
    shutil.copy(p2 / "envelock-manifest.bin", p1 / "envelock-manifest.bin")       # swap in the other manifest
    result = php(native, p1 / "index.php")
    assert result.returncode != 0 and "different release" in result.stderr and "OK" not in result.stdout


def test_php_vault_runs_and_keeps_literals_out_of_the_source(native, tmp_path):
    """--vault-strings: a protected file runs identically, its runtime string literals resolve
    through the loader's per-file vault, and they no longer appear in the compiled source. Output
    correctness is itself the end-to-end proof: without the loader parsing the table and the
    __envelock_lit resolver, the strings would be missing."""
    code = ("<?php $sql = 'SELECT secret FROM vault_table WHERE id = ?';"
            " $msg = 'access-granted-message'; echo $sql, '|', $msg, '|', strlen($sql);")
    out = package(native, tmp_path, {"index.php": code}, vault_strings=True)
    result = php(native, out / "index.php")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "SELECT secret FROM vault_table WHERE id = ?|access-granted-message|43"
    # The literal is gone from the plaintext source the loader compiles (only in the encrypted table).
    plain = a.open_protected((out / "index.php").read_bytes(), a.make_identity(native[3], native[2]))
    table_bytes = int.from_bytes(plain[:4], "big")
    assert b"SELECT secret FROM vault_table" not in plain[4 + table_bytes:]
    assert b"__envelock_lit(" in plain[4 + table_bytes:]


def test_php_vault_lit_resolves_only_for_a_direct_call(native, tmp_path):
    """ENV-2026-05: __envelock_lit must resolve a literal ONLY when called DIRECTLY from the file's own
    code, never when routed through an internal function such as array_map/call_user_func. The old
    filename attribution walked past the internal frame to the enclosing file and would hand back the
    whole vault, so `array_map('__envelock_lit', range(0, N))` dumped every secret at once. The file's
    own direct literal still resolves; the array_map enumeration comes back empty."""
    code = ("<?php $secret = 'ZZSECRETVALUEZZ';"
            " $fn = '__envelock_lit';"
            " $dump = @array_map($fn, range(0, 15));"
            " echo $secret, '|', implode('', $dump);")
    out = package(native, tmp_path, {"index.php": code}, vault_strings=True)
    result = php(native, out / "index.php")
    assert result.returncode == 0, result.stderr
    # The direct literal resolved (appears once); the array_map enumeration leaked nothing.
    assert result.stdout.startswith("ZZSECRETVALUEZZ|")
    assert result.stdout.count("ZZSECRETVALUEZZ") == 1
    assert result.stdout == "ZZSECRETVALUEZZ|"          # the dump is all empty strings


def test_php_vault_per_file_tables_do_not_cross(native, tmp_path):
    """Each file resolves \\__envelock_lit against its OWN table (keyed by the executing file), so a
    shared index returns each file's own literal, never another file's."""
    files = {
        "index.php": "<?php require __DIR__.'/lib.php'; $a='alpha-from-index'; echo $a, '|', libword();",
        "lib.php": "<?php function libword(){ $b='beta-from-lib'; return $b; }",
    }
    out = package(native, tmp_path, files, vault_strings=True)
    result = php(native, out / "index.php")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "alpha-from-index|beta-from-lib"


def test_php_without_vault_flag_has_no_vault_function_effect(native, tmp_path):
    """A normal (non-vaulted) package keeps its literals inline and runs as before; the reserved
    __envelock_lit function existing in the process does not change anything."""
    out = package(native, tmp_path, {"index.php": "<?php echo 'plain-inline-literal';"})
    result = php(native, out / "index.php")
    assert result.returncode == 0 and result.stdout == "plain-inline-literal"
    plain = a.open_protected((out / "index.php").read_bytes(), a.make_identity(native[3], native[2]))
    assert b"plain-inline-literal" in plain and b"__envelock_lit(" not in plain


def test_php_vault_rejects_malformed_table(native, tmp_path, monkeypatch):
    """A malformed vault prefix (table_bytes larger than the plaintext) in a properly SIGNED file
    must be rejected cleanly by the loader's bounds checks, never crash. The signature is valid, so
    this exercises the parser, not the signature path."""
    # vault_strings now emits the ENCRYPTED table (objective O7), so this has to corrupt that
    # format: a table_bytes that claims more than the plaintext holds. Patching _vault_plaintext,
    # as this test did, no longer reaches anything the packer calls.
    bad = (12345).to_bytes(4, "big") + (0).to_bytes(4, "big") + b"<?php echo 'x';"
    monkeypatch.setattr(a, "_vault_plaintext_encrypted", lambda table, source, key: bad)
    out = package(native, tmp_path, {"index.php": "<?php echo 'x';"}, vault_strings=True)
    result = php(native, out / "index.php")
    assert result.returncode != 0 and "vault table" in result.stderr


def test_php_vault_runs_under_web_sapi_across_requests(native, tmp_path):
    """The literal vault must work under a web SAPI (the built-in cli-server, like Apache's mod_php)
    and stay correct across several requests on the SAME reused worker: the per-request `litvault`
    table is set up and torn down each request, so a stale or missing table would surface here (as
    the ZTS `sealed_active` zero-init bug did). Each request must resolve this file's own literals."""
    files = {
        "index.php": ("<?php require __DIR__.'/lib.php'; header('Content-Type: text/plain');"
                      " echo 'WEB-SECRET-SQL-SELECT','|',libword();"),
        "lib.php": "<?php function libword(){ return 'web-sapi-vault-literal'; }",
    }
    out = package(native, tmp_path, files, vault_strings=True)
    bodies = serve_over_http(native, out, ["/index.php", "/index.php", "/index.php"])
    for body in bodies:                                   # identical and correct on every request
        assert body == "WEB-SECRET-SQL-SELECT|web-sapi-vault-literal", body


def test_php_sealed_vault_worker_reuse_stress(native, tmp_path):
    """Hard audit, per-request lifecycle under a reused worker: 50 requests to a SEALED + vaulted
    package on one built-in-server worker. Each request must set up and tear down the per-request state
    (sealed_active, litvault, roots, loaded) cleanly — a leak or a missed reset would make a later
    request spuriously refuse (the ZTS sealed_active zero-init class of bug) or resolve a stale literal.
    Every response must be byte-identical and correct, and the worker must not crash."""
    files = {
        "index.php": ("<?php header('Content-Type: text/plain');"
                      " echo 'STRESS','|','secret-literal-7';"),
    }
    try:
        out = package(native, tmp_path, files, vault_strings=True, sealed=True)
    except ValueError as e:
        if "tokenizer" in str(e):
            pytest.skip("this PHP CLI has no tokenizer, so a vaulted package cannot be built here")
        raise
    bodies = serve_over_http(native, out, ["/index.php"] * 50)
    assert len(bodies) == 50
    for i, body in enumerate(bodies):
        assert body == "STRESS|secret-literal-7", f"request {i}: {body!r}"


def test_php_sealed_worker_reuse_stress_no_tokenizer_needed(native, tmp_path):
    """Hard audit on EVERY engine (needs no tokenizer, so it runs on the thread-safe ZTS build too):
    40 requests to a SEALED package on one reused built-in-server worker. Each request must re-arm and
    reset `sealed_active` in RINIT; a missed reset would make request N spuriously refuse its own
    protected entry. Stresses the per-request sealed lifecycle under worker reuse on NTS and ZTS."""
    out = package(native, tmp_path,
                  {"index.php": "<?php header('Content-Type: text/plain'); echo 'OK-', 7*6;"},
                  sealed=True)
    bodies = serve_over_http(native, out, ["/index.php"] * 40)
    assert len(bodies) == 40
    for i, body in enumerate(bodies):
        assert body == "OK-42", f"request {i}: {body!r}"


def test_php_enforce_manifest_refuses_non_regular_file(native, tmp_path):
    """enforce-manifest must refuse if a listed path was replaced by a directory (stat alone would
    pass; the loader now requires a regular file) (external audit ENV-AUD-02)."""
    out = package(native, tmp_path, {"index.php": "<?php echo 'OK';", "lib.php": "<?php function f(){}"},
                  enforce_manifest=True)
    (out / "lib.php").unlink()
    (out / "lib.php").mkdir()                       # a directory now stands where the file was
    result = php(native, out / "index.php")
    assert result.returncode != 0 and "not a regular file" in result.stderr and "OK" not in result.stdout


def test_php_enforce_manifest_failure_does_not_poison_roots(native, tmp_path):
    """A failed manifest check must not register the package as seen, or a later protected file of
    the same package in the same request (from a shutdown function) would skip the check and run an
    incomplete package (external audit ENV-AUD-03)."""
    files = {
        "index.php": ("<?php register_shutdown_function(function(){ "
                      "@include __DIR__.'/lib.php'; echo function_exists('leaked') ? 'LEAK:'.leaked() : 'NOLEAK'; });"
                      " echo 'START;';"),
        "lib.php": "<?php function leaked(){ return 'SECRET'; }",
        "gone.php": "<?php function g(){}",
    }
    out = package(native, tmp_path, files, enforce_manifest=True)
    (out / "gone.php").unlink()                     # make the manifest check fail for the package
    result = php(native, out / "index.php")
    assert result.returncode != 0
    assert "LEAK" not in result.stdout              # the shutdown include must not load the package


def test_php_sealed_refuses_symlink_to_external_plain_php(native, tmp_path):
    """A symlink inside the sealed folder pointing to external plain PHP must be refused: the loader
    checks the requested path (filename), not only the resolved opened_path (external audit
    ENV-AUD-04). Skipped where the OS cannot create symlinks."""
    out = package(native, tmp_path, {"index.php": "<?php echo 'ENTRY;'; include __DIR__.'/evil.php'; echo 'AFTER;';"},
                  sealed=True)
    external = tmp_path / "external.php"
    external.write_text("<?php echo 'PLAINLEAK';")
    try:
        (out / "evil.php").symlink_to(external)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create a symlink on this platform")
    result = php(native, out / "index.php")
    assert "PLAINLEAK" not in result.stdout and result.returncode != 0


def test_php_minimum_is_bound_to_the_setting_developer(native, tmp_path):
    """ENV-AUD-14: on a host trusting two developers, a minimum set from developer B's signed
    package must NOT brick developer A's own project that happens to share the project id. Before
    the fix the minimum was keyed by project id alone and applied to every developer."""
    owner_a, owner_b = native[2], a.make_owner()
    recipient = native[3]
    project = str(uuid.uuid4())
    out_a = package(native, tmp_path, {"index.php": "<?php echo 'A-OK';"},
                    owner=owner_a, project=project, serial=1000)
    # Build a two-developer bundle and let B set a huge minimum for A's project (bound to B).
    store = a.identity_bundle_bytes([a.make_identity(recipient, owner_a),
                                     a.make_identity(recipient, owner_b)])
    store = a.set_minimum(store, project, 2**64 - 1,
                          developer_pub=bytes.fromhex(owner_b["signing_public"]))
    bundle = tmp_path / "two-dev-identity.bin"
    fd = os.open(bundle, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(store)
    result = php(native, out_a / "index.php", identity=bundle)
    assert result.returncode == 0 and result.stdout == "A-OK", result.stderr   # A survives B's minimum
    # Sanity: a minimum bound to A does gate A's project (mechanism still works).
    store2 = a.set_minimum(store, project, 2**64 - 1,
                           developer_pub=bytes.fromhex(owner_a["signing_public"]))
    bundle2 = tmp_path / "two-dev-identity-2.bin"
    fd = os.open(bundle2, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(store2)
    blocked = php(native, out_a / "index.php", identity=bundle2)
    assert blocked.returncode != 0 and "older than the minimum" in blocked.stderr


def test_php_include_protection_spans_primary_and_recovery_of_one_developer(native, tmp_path):
    """ENV-AUD-17: a module signed with a developer's recovery key must count as the SAME
    application as a main package signed with that developer's primary key (same project and
    developer), so include protection does not break a hotfix shipped after promote-recovery."""
    owner = a.make_owner(with_recovery=True)
    owner_recovery = {
        "kind": "envelock-owner", "format": a.FORMAT_VERSION,
        "signing_private": owner["recovery_private"], "signing_public": owner["recovery_public"],
    }
    recipient = native[3]
    bundle = tmp_path / "rec-identity.bin"
    write_identity(bundle, [a.make_identity(recipient, owner)])      # developer (primary, recovery)
    project = str(uuid.uuid4())
    pub = [a.recipient_public(recipient)]

    module = package(native, tmp_path, {"lib/mod.php": "<?php function mod_ok(){ return 'MOD-OK'; }"},
                     recipients=pub, owner=owner_recovery, project=project, include_protection=True)
    main = package(native, tmp_path,
                   {"index.php": "<?php require %r; echo mod_ok();" % str(module / "lib" / "mod.php")},
                   recipients=pub, owner=owner, project=project, include_protection=True)
    result = php(native, main / "index.php", identity=bundle)
    assert result.returncode == 0 and "MOD-OK" in result.stdout, result.stdout + result.stderr


# --------------------------------------------------------------------------- objective O1 (PoC)
# The bytecode layer compiles a file offline into a serialized zend_op_array image and a worker
# deserializes and executes it, so no PHP source ever reaches the compiler. These tests are the
# round-trip of the layer itself; the loader integration (flag bit 6) is covered further down.

# Deliberately exercises the constructs whose persistence is easy to get subtly wrong: constants,
# a trait and an interface, an enum, promoted and readonly properties, static and instance methods,
# default arguments, and Reflection over the result.
BYTECODE_SOURCE = """<?php
const POC_NAME = "envelock-poc";
function poc_sum(int $a, int $b): int { return $a + $b; }
function poc_join(array $parts, string $glue = "-"): string { return implode($glue, $parts); }
class Poc_Calc {
    private int $base;
    public function __construct(int $base) { $this->base = $base; }
    public function add(int $n): int { return $this->base + $n; }
    public static function describe(): string { return self::class . "/" . POC_NAME; }
}
trait Poc_T { public function tag(): string { return "trait"; } }
interface Poc_I { public function tag(): string; }
enum Poc_E: string { case On = "on"; case Off = "off"; }
final class Poc_Svc implements Poc_I {
    use Poc_T;
    public function __construct(private readonly Poc_Calc $c) {}
    public function run(int $n): string {
        return $this->tag() . ":" . $this->c->add($n) . ":" . Poc_E::On->value;
    }
}
"""

BYTECODE_ASSERTIONS = """
echo poc_sum(2, 40), "\\n";
echo poc_join(["a","b","c"]), "\\n";
echo (new Poc_Calc(10))->add(5), "\\n";
echo Poc_Calc::describe(), "\\n";
echo (new Poc_Svc(new Poc_Calc(1)))->run(41), "\\n";
echo Poc_E::Off->value, "\\n";
echo (new ReflectionClass(Poc_Svc::class))->getMethod("run")->getNumberOfParameters(), "\\n";
"""


def _bytecode_available(native):
    # php(native, "-r", code): "-r" must be its own argument, or PHP reads the code as a filename.
    return php(native, "-r",
               "echo function_exists('envelock_bc_emit') ? 'yes' : 'no';").stdout.strip()


def test_bytecode_roundtrip_matches_source(native, tmp_path):
    """A program run from its serialized op_array behaves exactly like the same program's source."""
    if _bytecode_available(native) != "yes":
        pytest.skip("no bytecode layer for this PHP version")
    source = tmp_path / "app.php"
    source.write_text(BYTECODE_SOURCE)
    image = tmp_path / "app.bin"

    emit = php(native, "-r",
               "$i = envelock_bc_emit($argv[1]);"
               "if ($i === false) { exit(3); }"
               "file_put_contents($argv[2], $i);",
               str(source), str(image))
    assert emit.returncode == 0, emit.stderr[-2000:]
    assert image.stat().st_size > ENVELOCK_BC_HEADER_SIZE

    plain = subprocess.run(["php", "-n", "-r",
                            "require $argv[1];" + BYTECODE_ASSERTIONS, str(source)],
                           capture_output=True, text=True, check=False, env=php_environment())
    assert plain.returncode == 0, plain.stderr[-2000:]

    # A separate process: the image is loaded cold, with no source anywhere near it.
    run = php(native, "-r",
              "$b = file_get_contents($argv[1]);"
              "if (!envelock_bc_run($b)) { exit(4); }" + BYTECODE_ASSERTIONS, str(image))
    assert run.returncode == 0, run.stderr[-2000:]
    assert run.stdout == plain.stdout


def test_bytecode_image_carries_no_source_text(native, tmp_path):
    """The image holds the program's identifiers but none of its PHP source."""
    if _bytecode_available(native) != "yes":
        pytest.skip("no bytecode layer for this PHP version")
    source = tmp_path / "app.php"
    source.write_text(BYTECODE_SOURCE)
    image = tmp_path / "app.bin"
    assert php(native, "-r",
               "$i = envelock_bc_emit($argv[1]);"
               "if ($i === false) { exit(3); }"
               "file_put_contents($argv[2], $i);",
               str(source), str(image)).returncode == 0

    blob = image.read_bytes()
    for fragment in ("function ", "class ", "interface ", "trait ", "enum ",
                     "return ", "implode(", "=> ", "public ", "private "):
        assert fragment.encode() not in blob, f"source text {fragment!r} found in the image"
    # Identifiers and string literals are still there: they are the program. Hiding them is
    # objective O6, which runs before the bytecode is produced.
    assert b"poc_sum" in blob


def test_bytecode_image_header_matches_documented_layout(native, tmp_path):
    """The wire header is parsed field by field the way envelock_bc.h documents it."""
    if _bytecode_available(native) != "yes":
        pytest.skip("no bytecode layer for this PHP version")
    source = tmp_path / "app.php"
    source.write_text(BYTECODE_SOURCE)
    image = tmp_path / "app.bin"
    assert php(native, "-r",
               "$i = envelock_bc_emit($argv[1]);"
               "if ($i === false) { exit(3); }"
               "file_put_contents($argv[2], $i);",
               str(source), str(image)).returncode == 0

    blob = image.read_bytes()
    assert len(blob) > ENVELOCK_BC_HEADER_SIZE
    assert blob[0:4] == b"EVB1"
    assert blob[4:12] == b"ENVELBC1"
    # zend_system_id: ASCII hex, NUL padded to 32 bytes. PHP exposes no userland getter, so this
    # checks the wire format; the tampering test covers the fact that the loader acts on it.
    system_id = blob[12:44].rstrip(b"\x00")
    assert len(system_id) == 32 and system_id == bytes.fromhex(system_id.decode("ascii")).hex().encode()
    assert blob[44:48] == b"\x00" * 4, "padding must stay zero"

    def field(offset, width):
        return int.from_bytes(blob[offset:offset + width], "big")

    mem_size = field(48, 8)
    assert mem_size == len(blob) - ENVELOCK_BC_HEADER_SIZE
    assert field(56, 8) == 0, "str_size is reserved"
    assert field(64, 8) < mem_size, "script_offset points inside the program"
    # 4 bytes, not 8: 4 + 8 + 32 + 8 + 8 + 8 + 8 + 4 is exactly the 80-byte header.
    assert field(72, 4) == 0, "timestamp is reserved"
    assert field(76, 4) == zlib.adler32(
        blob[ENVELOCK_BC_HEADER_SIZE:ENVELOCK_BC_HEADER_SIZE + mem_size], 1)


@pytest.mark.parametrize("byte", [12, ENVELOCK_BC_HEADER_SIZE - 1])
def test_bytecode_refuses_a_tampered_image(native, tmp_path, byte):
    """Fail closed: a wrong system_id (byte 12) or a wrong checksum is refused, not deserialized."""
    if _bytecode_available(native) != "yes":
        pytest.skip("no bytecode layer for this PHP version")
    source = tmp_path / "app.php"
    source.write_text(BYTECODE_SOURCE)
    image = tmp_path / "app.bin"
    assert php(native, "-r",
               "$i = envelock_bc_emit($argv[1]);"
               "if ($i === false) { exit(3); }"
               "file_put_contents($argv[2], $i);",
               str(source), str(image)).returncode == 0

    blob = bytearray(image.read_bytes())
    blob[byte] ^= 0xFF
    tampered = tmp_path / "tampered.bin"
    tampered.write_bytes(bytes(blob))
    run = php(native, "-r",
              "var_dump(envelock_bc_run(file_get_contents($argv[1])));", str(tampered))
    assert run.returncode == 0, run.stderr[-2000:]
    assert run.stdout.strip() == "bool(false)"


def test_bytecode_loader_requires_empty_interned_region(native, tmp_path):
    """ENV-2026-04: a shippable image carries NO interned strings — the serializer counts every
    interned string into str_size, and the loader requires str_size == 0. That invariant is what makes
    the interned-string deserialization path unreachable for any accepted image, so an interned-tagged
    pointer (which would otherwise resolve to an unbounded offset) is treated as corruption and fails
    closed rather than being dereferenced. Here: an image whose str_size field is forced non-zero and
    re-checksummed is refused cleanly (bool(false)), never deserialized.

    NOTE ON SCOPE: a bytecode image reaches this loader only after its signed container passes an
    Ed25519 verify-before-decrypt, so only a trusted developer's key can produce a loadable image —
    and such a holder can already ship arbitrary PHP source. The signature is the trust boundary (the
    same posture as upstream OPcache's file cache); the active pointer/interned/arena bounds checks are
    defense-in-depth against a malformed image from a rogue co-signer, not a claim that the deserializer
    is hardened against every forged-but-signed image."""
    if _bytecode_available(native) != "yes":
        pytest.skip("no bytecode layer for this PHP version")
    source = tmp_path / "app.php"
    source.write_text(BYTECODE_SOURCE)
    image = tmp_path / "app.bin"
    assert php(native, "-r",
               "$i = envelock_bc_emit($argv[1]);"
               "if ($i === false) { exit(3); }"
               "file_put_contents($argv[2], $i);",
               str(source), str(image)).returncode == 0
    base = bytearray(image.read_bytes())
    mem_size = int.from_bytes(base[48:56], "big")
    body0, body1 = ENVELOCK_BC_HEADER_SIZE, ENVELOCK_BC_HEADER_SIZE + mem_size
    blob = bytearray(base)
    blob[56:64] = (64).to_bytes(8, "big")                   # str_size != 0: interned region claimed
    blob[76:80] = zlib.adler32(bytes(blob[body0:body1]), 1).to_bytes(4, "big")   # re-checksum: header is valid
    forged = tmp_path / "forged.bin"
    forged.write_bytes(bytes(blob))
    run = php(native, "-r",
              "var_dump(envelock_bc_run(file_get_contents($argv[1])));", str(forged))
    assert run.returncode == 0, run.stderr[-2000:]          # clean refusal, no crash
    assert run.stdout.strip() == "bool(false)"              # rejected, not deserialized


def test_bytecode_loader_reanchors_a_corrupted_script_size(native, tmp_path):
    """Internal audit (nov 2026): the deserializer bounds every pointer/string relocation against the
    image's embedded persistent_script.size field. The loader must NOT trust that field: it re-anchors
    it to the header mem_size, which was validated and checksummed. Here the embedded size is corrupted
    to a tiny value and the image re-checksummed; without the clamp the loader would reject every legit
    relocation (a fatal), so a VALID image would stop working. With the clamp the bound is restored and
    the image runs identically to its source. (Defense-in-depth behind the Ed25519 signature; the same
    corruption with a huge value would otherwise widen the bound into an arbitrary-offset primitive.)"""
    if _bytecode_available(native) != "yes":
        pytest.skip("no bytecode layer for this PHP version")
    source = tmp_path / "app.php"
    source.write_text(BYTECODE_SOURCE)
    image = tmp_path / "app.bin"
    assert php(native, "-r",
               "$i = envelock_bc_emit($argv[1]);"
               "if ($i === false) { exit(3); }"
               "file_put_contents($argv[2], $i);",
               str(source), str(image)).returncode == 0
    plain = subprocess.run(["php", "-n", "-r", "require $argv[1];" + BYTECODE_ASSERTIONS, str(source)],
                           capture_output=True, text=True, check=False, env=php_environment())
    assert plain.returncode == 0, plain.stderr[-2000:]

    blob = bytearray(image.read_bytes())
    H = ENVELOCK_BC_HEADER_SIZE
    mem_size = int.from_bytes(blob[48:56], "big")
    script_offset = int.from_bytes(blob[64:72], "big")
    # The embedded persistent_script.size equals the arena size (== mem_size). Find that 8-byte,
    # host-endian field inside the struct and corrupt it to a tiny value.
    needle = mem_size.to_bytes(8, sys.byteorder)
    try:
        pos = blob.index(needle, H + script_offset, H + mem_size)
    except ValueError:                                       # layout did not expose it as expected
        pytest.skip("could not locate the embedded script->size field for this build")
    blob[pos:pos + 8] = (8).to_bytes(8, sys.byteorder)       # corrupt the relocation bound -> tiny
    blob[76:80] = zlib.adler32(bytes(blob[H:H + mem_size]), 1).to_bytes(4, "big")   # header stays valid
    tampered = tmp_path / "tampered.bin"
    tampered.write_bytes(bytes(blob))

    run = php(native, "-r",
              "$b = file_get_contents($argv[1]);"
              "if (!envelock_bc_run($b)) { exit(4); }" + BYTECODE_ASSERTIONS, str(tampered))
    # With the clamp: the bound is re-anchored to mem_size, the image runs and matches source.
    # Without it: the tiny size rejects every legit relocation (fatal), so this would fail.
    assert run.returncode == 0, run.stderr[-2000:]
    assert run.stdout == plain.stdout


def test_bytecode_deserializer_never_crashes_on_a_corrupted_image(native, tmp_path):
    """Internal audit (nov 2026): the deserializer that turns an image into an op_array must NEVER
    crash the worker on a malformed image — it must reject it. The whole load runs under a crash-safety
    guard (SIGSEGV/SIGBUS on POSIX, SEH on Windows) that converts any wild access into a clean NULL.
    Differential fuzz via envelock_bc_load_check (deserialize + install, WITHOUT executing): force each
    4-byte word of the struct region to a large value, re-checksum so the header stays valid, and load
    it. Every case must exit cleanly (bool(true)/bool(false)); a crash (a negative signal code on POSIX,
    an NTSTATUS exception code such as 0xC0000005 on Windows, see crashed()) is what the guard must
    prevent. Without the guard, dozens of these corruptions crash.
    (Executing a corrupted-but-signed image is the trust-boundary case and is out of scope here.)"""
    if _bytecode_available(native) != "yes":
        pytest.skip("no bytecode layer for this PHP version")
    if php(native, "-r", "echo function_exists('envelock_bc_load_check')?'y':'n';").stdout.strip() != "y":
        pytest.skip("loader built without the deserialize-only test entry")
    source = tmp_path / "app.php"
    source.write_text(BYTECODE_SOURCE)
    image = tmp_path / "app.bin"
    assert php(native, "-r",
               "$i = envelock_bc_emit($argv[1]);"
               "if ($i === false) { exit(3); }"
               "file_put_contents($argv[2], $i);",
               str(source), str(image)).returncode == 0
    base = image.read_bytes()
    H = ENVELOCK_BC_HEADER_SIZE
    mem_size = int.from_bytes(base[48:56], "big")
    script_offset = int.from_bytes(base[64:72], "big")
    tampered = tmp_path / "c.bin"
    region_start = H + script_offset
    # Bounded sweep over the struct region (where the crashy count/handler/type fields live).
    for off in range(region_start, min(H + mem_size - 4, region_start + 900), 4):
        blob = bytearray(base)
        blob[off:off + 4] = (0x7fffffff).to_bytes(4, sys.byteorder)
        blob[76:80] = zlib.adler32(bytes(blob[H:H + mem_size]), 1).to_bytes(4, "big")
        tampered.write_bytes(bytes(blob))
        r = php(native, "-r", "var_dump(envelock_bc_load_check(file_get_contents($argv[1])));",
                str(tampered))
        assert not crashed(r.returncode), (
            f"deserializer crashed on a corrupted image at offset {off}: {describe_rc(r.returncode)}")


# ------------------------------------------------------- objective O1: loader integration (bit 6)
# A protected file whose payload is a bytecode image rather than source: the loader deserializes it
# into a zend_op_array and never hands PHP text to the compiler.

BYTECODE_APP = {
    "app.php": """<?php
const BC_NAME = "envelock-bc";
interface BC_Shape { public function area(): float; }
trait BC_Tag { public function tag(): string { return static::class . "/" . BC_NAME; } }
enum BC_Mode: string { case Fast = "fast"; case Safe = "safe";
    public function label(): string { return match ($this) { self::Fast => "rapido", self::Safe => "seguro" }; } }
final class BC_Square implements BC_Shape {
    use BC_Tag;
    public function __construct(public readonly float $side) {}
    public function area(): float { return $this->side * $this->side; }
}
function bc_sum(int ...$n): int { return array_sum($n); }
""",
    # __DIR__ is a compile-time value: it is baked into the image, which is why a bytecode package
    # is compiled at, and bound to, its deploy path.
    "use.php": """<?php
require __DIR__ . "/app.php";
echo bc_sum(2, 40), "\\n";
echo (new BC_Square(3.0))->area(), "\\n";
echo (new BC_Square(3.0))->tag(), "\\n";
echo BC_Mode::Safe->label(), "\\n";
echo (new ReflectionClass(BC_Square::class))->getMethod("area")->getNumberOfParameters(), "\\n";
""",
}

BYTECODE_EXPECTED = "42\n9\nBC_Square/envelock-bc\nseguro\n0\n"


def bytecode_pack(native, tmp_path, name, **options):
    """Pack BYTECODE_APP as a bytecode package and return (package, deploy_root)."""
    source = tmp_path / (name + "-src")
    output = tmp_path / (name + "-out")
    deploy = tmp_path / (name + "-deploy")
    source.mkdir()
    for file, text in BYTECODE_APP.items():
        (source / file).write_text(text)
    a.pack_tree(source, output, [a.recipient_public(native[3])], native[2], str(uuid.uuid4()),
                bytecode=True, bytecode_loader=str(native[1]), deploy_root=deploy, **options)
    return output, deploy


def test_bytecode_package_runs_identically_to_source(native, tmp_path):
    """A package carrying bytecode instead of source behaves exactly like the plain sources."""
    if _bytecode_available(native) != "yes":
        pytest.skip("no bytecode layer for this PHP version")
    output, deploy = bytecode_pack(native, tmp_path, "run")
    deploy.mkdir(parents=True, exist_ok=True)
    for file in BYTECODE_APP:
        shutil.copyfile(output / file, deploy / file)
    result = php(native, str(deploy / "use.php"))
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout == BYTECODE_EXPECTED


def test_bytecode_package_ships_no_php_source(native, tmp_path):
    """No PHP text in the package: neither syntax nor the program's own identifiers."""
    if _bytecode_available(native) != "yes":
        pytest.skip("no bytecode layer for this PHP version")
    output, _ = bytecode_pack(native, tmp_path, "nosrc")
    for file in BYTECODE_APP:
        blob = (output / file).read_bytes()
        for fragment in ("function ", "class ", "interface ", "trait ", "enum ", "return ",
                         "=> ", "public ", "readonly ", "BC_Square", "bc_sum", "__DIR__"):
            assert fragment.encode() not in blob, f"{file}: source text {fragment!r} in the package"


def test_bytecode_pack_leaves_no_source_at_the_deploy_root(native, tmp_path):
    """The pass compiles at the deploy path and cleans up after itself."""
    if _bytecode_available(native) != "yes":
        pytest.skip("no bytecode layer for this PHP version")
    _, deploy = bytecode_pack(native, tmp_path, "clean")
    assert not deploy.exists() or list(deploy.rglob("*")) == []


def test_bytecode_refuses_the_literal_vault(native, tmp_path):
    """The vault rewrites literals in the source; a bytecode image ships no source to rewrite."""
    if _bytecode_available(native) != "yes":
        pytest.skip("no bytecode layer for this PHP version")
    with pytest.raises(ValueError, match="mutually exclusive"):
        bytecode_pack(native, tmp_path, "vault", vault_strings=True)


def test_bytecode_requires_a_deploy_root(native, tmp_path):
    """__DIR__ and resolved include paths are baked in, so the deploy path is not optional."""
    if _bytecode_available(native) != "yes":
        pytest.skip("no bytecode layer for this PHP version")
    source = tmp_path / "noroot-src"
    source.mkdir()
    for file, text in BYTECODE_APP.items():
        (source / file).write_text(text)
    with pytest.raises(ValueError, match="deploy-root"):
        a.pack_tree(source, tmp_path / "noroot-out", [a.recipient_public(native[3])], native[2],
                    str(uuid.uuid4()), bytecode=True, bytecode_loader=str(native[1]))


def test_bytecode_arms_autoglobals_for_a_functions_first_use(native, tmp_path):
    """A function whose FIRST use of an autoglobal in the request comes from bytecode must still
    see it populated. A normally compiled file arms $_SERVER/$_GET/... the first time the compiler
    meets each; a deserialized op_array skips that step, so without arming them on load $_SERVER
    reads as null inside the function. That is the failure that broke a real CMS's
    wp_fix_server_vars(): array_merge($defaults, $_SERVER). The bug only shows under a SAPI that
    activates autoglobals lazily (the CLI always populates $_SERVER), so this drives the built-in
    web server."""
    if _bytecode_available(native) != "yes":
        pytest.skip("no bytecode layer for this PHP version")
    import http.client
    import socket
    import time

    source = tmp_path / "ag-src"
    source.mkdir()
    (source / "index.php").write_text("<?php require __DIR__ . '/lib.php'; go();\n")
    (source / "lib.php").write_text(
        "<?php function go(){ $m = array_merge(['A' => 1], $_SERVER);"
        " header('Content-Type: text/plain'); echo 'COUNT=' . count($m); }\n")
    output = tmp_path / "ag-out"
    deploy = tmp_path / "ag-deploy"
    a.pack_tree(source, output, [a.recipient_public(native[3])], native[2], str(uuid.uuid4()),
                bytecode=True, bytecode_loader=str(native[1]), deploy_root=deploy)
    deploy.mkdir(parents=True, exist_ok=True)
    for name in ("index.php", "lib.php"):
        shutil.copyfile(output / name, deploy / name)

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    server = subprocess.Popen(
        ["php", "-n", "-d", f"extension={native[1]}", "-d", f"envelock.identity={native[4]}",
         "-d", "opcache.enable=0", "-d", "opcache.enable_cli=0",
         "-S", f"127.0.0.1:{port}"],
        cwd=str(deploy), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=php_environment())
    try:
        status = body = None
        for _ in range(50):
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                conn.request("GET", "/")
                response = conn.getresponse()
                status, body = response.status, response.read().decode()
                conn.close()
                break
            except OSError:
                time.sleep(0.1)
        assert body is not None, "the built-in server never answered"
        # Without the fix the request is a 500: array_merge(..., null) is an uncaught TypeError.
        assert status == 200, f"status {status}: {body[:300]}"
        assert "COUNT=" in body, body[:300]
    finally:
        server.terminate()
        server.wait()


def test_bytecode_emitter_handles_a_class_with_many_methods(native, tmp_path):
    """A class with thousands of methods has few top-level opcodes but thousands of method
    op_arrays. The emit arena is a fixed bump mapping sized up front; sizing it from the main
    op_array alone under-sized it and the emitter wrote past the mapping and segfaulted (rc=139,
    reported for a ~138 KB / 2000-method file). The arena is now sized from the whole script."""
    if _bytecode_available(native) != "yes":
        pytest.skip("no bytecode layer for this PHP version")
    big = tmp_path / "Big.php"
    methods = "\n".join(
        f"    public function m{i}(int $a, int $b): int {{ $x = $a + $b; return $x * {i} - $a; }}"
        for i in range(2000))
    big.write_text("<?php\nclass Big {\n" + methods + "\n}\n")
    result = php(native, "-r",
                 "$img = envelock_bc_emit($argv[1]); echo $img === false ? 'FALSE' : strlen($img);",
                 str(big))
    assert result.returncode == 0, f"emitter crashed rc={result.returncode}: {result.stderr[-500:]}"
    assert result.stdout.strip().isdigit() and int(result.stdout) > 0, result.stdout


def test_bytecode_emitter_handles_large_constant_arrays(native, tmp_path):
    """A file whose weight is a huge constant array (e.g. the polyfill-iconv charset tables, or any
    big embedded data table) under-sized the emit arena: the structural estimate counts opcode and
    literal counts, but a class constant kept as a constant-expression AST (compilation runs with
    NO_CONSTANT_SUBSTITUTION) is not a literal zval, so none of its bytes were counted. The writer
    then ran past the fixed mapping (rc=139 on from.cp950.php and 8 other Drupal files). The arena is
    now floored at the source size, which bounds every source-derived byte, and a trailing guard page
    makes any residual overrun fault instead of corrupting the heap. This file reproduces that: a
    ~300 KB class constant array with no methods, which the structural estimate alone sizes at ~1 MB."""
    if _bytecode_available(native) != "yes":
        pytest.skip("no bytecode layer for this PHP version")
    big = tmp_path / "Table.php"
    entries = ",\n".join(f"    {i} => 'glyph_{i}_\\u{{{(0x4e00 + (i % 8000)):04x}}}'" for i in range(12000))
    big.write_text("<?php\nclass Table {\n  const MAP = [\n" + entries + "\n  ];\n}\n")
    assert big.stat().st_size > 300_000  # large enough that the source-size floor, not the struct estimate, sizes the arena
    result = php(native, "-r",
                 "$img = envelock_bc_emit($argv[1]); echo $img === false ? 'FALSE' : strlen($img);",
                 str(big))
    assert result.returncode == 0, f"emitter crashed rc={result.returncode}: {result.stderr[-500:]}"
    assert result.stdout.strip().isdigit() and int(result.stdout) > 0, result.stdout


def test_bytecode_emits_in_batches(native, tmp_path, monkeypatch):
    """Large trees are emitted a batch of files per PHP process so the emitter does not run out of
    memory on tens of thousands of files; batching must not change the output. Force a tiny batch and
    pack more files than it, spanning several batches, then run files from different batches."""
    if _bytecode_available(native) != "yes":
        pytest.skip("no bytecode layer for this PHP version")
    monkeypatch.setattr(a, "BYTECODE_BATCH", 3)
    source = tmp_path / "src"
    source.mkdir()
    for i in range(10):
        (source / f"C{i}.php").write_text(f"<?php class C{i} {{ public function v(): int {{ return {i} * 7; }} }}\n")
    output = tmp_path / "out"
    deploy = tmp_path / "deploy"
    a.pack_tree(source, output, [a.recipient_public(native[3])], native[2], str(uuid.uuid4()),
                bytecode=True, bytecode_loader=str(native[1]), deploy_root=deploy)
    assert len(list(output.glob("*.php"))) == 10  # every file emitted across the batches
    deploy.mkdir(parents=True, exist_ok=True)
    for i in range(10):
        shutil.copyfile(output / f"C{i}.php", deploy / f"C{i}.php")
    # run one class from the first, a middle and the last batch
    program = "".join(f"require '{deploy / f'C{i}.php'}'; echo (new C{i})->v(), ',';" for i in (0, 5, 9))
    result = php(native, "-r", program)
    assert result.returncode == 0, result.stderr[-400:]
    assert result.stdout.strip().strip(",") == "0,35,63", result.stdout


def test_bytecode_layer_refuses_to_build_under_zts():
    """ENV-2026-03: the bytecode layer keeps per-process state (page arena, ZCG/ZCSG shim globals)
    without thread-local storage, so it is not thread-safe. Every per-version opcache shim header
    carries a hard #error under ZTS as the compile-time backstop; config.m4 and the build scripts also
    drop the layer for a thread-safe engine so a ZTS build still succeeds (source-only)."""
    shim_dirs = sorted((ROOT / "extension" / "opcache").glob("php*"))
    assert shim_dirs, "no per-version bytecode layers found"
    for d in shim_dirs:
        header = (d / "envelock_accel_shim.h").read_text()
        assert "#ifdef ZTS" in header and "ENV-2026-03" in header and "# error" in header, d.name


def _build_loader_variant(tmp_path, subdir, configure_flags):
    """Build the extension with the given extra ./configure flags, returning the module path (or
    skipping if the toolchain is unavailable here)."""
    needed = ["php", "phpize", "php-config", "make", "cc", "pkg-config"]
    if os.name == "nt" or any(not shutil.which(t) for t in needed):
        pytest.skip("native PHP build unavailable")
    ext = tmp_path / subdir
    ext.mkdir()
    for name in EXTENSION_SOURCES:
        shutil.copyfile(ROOT / "extension" / name, ext / name)
    shutil.copytree(ROOT / "extension" / "opcache", ext / "opcache")
    # The env var is deliberately NOT how the PoC is enabled any more (ENV-2026-02); clear it so an
    # inherited value cannot change what this variant builds.
    build_env = {k: v for k, v in os.environ.items() if k != "ENVELOCK_BCPOC"}
    log = ""
    for command in [["phpize"], ["./configure", "--enable-envelock", *configure_flags], ["make", "-j2"]]:
        result = subprocess.run(command, cwd=ext, text=True, capture_output=True, check=False, env=build_env)
        log += result.stdout + result.stderr
        if result.returncode:
            pytest.skip(f"cannot build loader variant {configure_flags} here:\n{log[-3000:]}")
    return ext / "modules" / "envelock.so"


def _exposes(module, func):
    r = subprocess.run(["php", "-n", "-d", f"extension={module}", "-r",
                        f"echo function_exists('{func}') ? '1' : '0';"],
                       text=True, capture_output=True, check=False)
    return r.stdout.strip() == "1"


def test_server_loader_exposes_no_bytecode_emit_or_run_surface(tmp_path):
    """ENV-2026-02: the bytecode emit/run userland functions must be gated by EXPLICIT configure flags,
    never by an inherited ENVELOCK_BCPOC environment variable, and -fvisibility=hidden (which hides them
    from nm -D) must not be mistaken for them being absent. A server loader (no bc flags) exposes
    NEITHER; the pack-side build (--enable-envelock-bcemit) exposes the emitter but NOT the runner (the
    RCE surface); only the test build (--enable-envelock-bcrun-unsafe) exposes the runner."""
    server = _build_loader_variant(tmp_path, "srv", [])
    assert not _exposes(server, "envelock_bc_emit"), "server loader must not expose the emitter"
    assert not _exposes(server, "envelock_bc_run"), "server loader must not expose the runner"

    packer = _build_loader_variant(tmp_path, "packer", ["--enable-envelock-bcemit"])
    assert _exposes(packer, "envelock_bc_emit"), "pack build must expose the emitter"
    assert not _exposes(packer, "envelock_bc_run"), "pack build must NOT expose the RCE runner"


def build_unstripped_extension(tmp_path):
    """The released module is stripped, so a test that reads its symbols needs its own build."""
    skip_without_posix_build_tools("build an unstripped module")
    ext = tmp_path / "unstripped"
    ext.mkdir()
    for name in EXTENSION_SOURCES:
        shutil.copyfile(ROOT / "extension" / name, ext / name)
    shutil.copytree(ROOT / "extension" / "opcache", ext / "opcache")
    log = ""
    # This helper's callers exercise the pack/test-only envelock_bc_emit/run, gated by explicit
    # configure flags (ENV-2026-02); a server loader is built with neither.
    build_env = {k: v for k, v in os.environ.items() if k != "ENVELOCK_BCPOC"}
    for command in [["phpize"],
                    ["./configure", "--enable-envelock", "--enable-envelock-bcrun-unsafe"],
                    ["make", "-j2"]]:
        result = subprocess.run(command, cwd=ext, text=True, capture_output=True, check=False, env=build_env)
        log += result.stdout + result.stderr
        if result.returncode:
            pytest.skip(f"cannot build an unstripped module here:\n{log[-4000:]}")
    return ext / "modules" / "envelock.so"


def test_bytecode_emitter_destroys_its_translation_table_inside_the_request(tmp_path):
    """Regression: the emitter used to create its translation table at module start and destroy it
    at module shutdown. zend_hash_init() allocates on the current request heap, and MSHUTDOWN runs
    outside any request, so the php process died with a segmentation fault on the way out — after
    emitting a perfectly good image, which made it easy to miss.

    The crash itself is not testable: freeing a request-heap table after the heap is gone is
    undefined behaviour whose outcome depends on the heap layout. What IS testable is the invariant
    that was broken — the table must be destroyed by the emitter, inside the request."""
    if shutil.which("gdb") is None:
        pytest.skip("gdb is needed to read the call stack")
    module = build_unstripped_extension(tmp_path)
    source = tmp_path / "app.php"
    source.write_text(BYTECODE_APP["app.php"])
    # Run to completion and print EVERY call: with the bug there is a second one, from shutdown.
    script = tmp_path / "order.cmd"
    script.write_text("set breakpoint pending on\nset pagination off\n"
                      "break envelock_xlat_destroy\ncommands\nbt 4\ncontinue\nend\n"
                      "run\nquit\n")
    result = subprocess.run(
        ["gdb", "-batch", "-x", str(script), "--args", "php", "-n",
         "-d", f"extension={module}", "-r",
         "$i = envelock_bc_emit($argv[1]); if ($i === false) { exit(3); } echo strlen($i);",
         str(source)],
        text=True, capture_output=True, check=False)
    frames = [line for line in result.stdout.splitlines() if line.startswith("#")]
    assert any("envelock_bc_emit_file" in frame for frame in frames), (
        "the emitter never destroys its translation table:\n"
        + result.stdout[-3000:] + result.stderr[-2000:])
    assert not any("envelock_bc_shutdown" in frame for frame in frames), (
        "the translation table is also destroyed at module shutdown, outside any request heap:\n"
        + "\n".join(frames))


def test_bytecode_emitter_survives_its_own_exit_branch(native, tmp_path):
    """Smoke test of the emit path, including the `exit()` branch next to it."""
    if _bytecode_available(native) != "yes":
        pytest.skip("no bytecode layer for this PHP version")
    source = tmp_path / "app.php"
    source.write_text(BYTECODE_APP["app.php"])
    result = php(native, "-r",
                 "$i = envelock_bc_emit($argv[1]);"
                 "if ($i === false) { exit(3); }"
                 "echo strlen($i);", str(source))
    assert result.returncode == 0, f"rc={result.returncode} stderr={result.stderr[-2000:]}"
    assert int(result.stdout) > ENVELOCK_BC_HEADER_SIZE


def test_bytecode_flag_sits_outside_the_v2_mask():
    """A bytecode file fails closed on a loader that cannot run it: the flag is a bit the v2 mask
    (0x3F) does not know, and an unknown bit makes envelock_parse_header refuse the whole file.
    This asserts the arithmetic of that guarantee on both sides of the format."""
    assert a.FLAG_BYTECODE == 64
    assert a.FLAG_BYTECODE & 0x3F == 0, "a v2 loader would not see it as an unknown bit"
    # Objective O7 took bit 128 (FLAG_VAULT_ENC), so the known mask is now the whole flags byte.
    # That is the end of the road for this trick: with no spare bit left, a FUTURE format change
    # cannot be signalled by an unknown bit and will need a format version bump instead.
    assert a.FLAG_VAULT_ENC == 128
    assert a.FLAGS_KNOWN == 0xFF, "this side must know its own bits, or it would refuse its packages"
    # The C loader carries the same mask; envelock_parse_header is what refuses the file.
    header = (ROOT / "extension" / "envelock_crypto.h").read_text()
    assert "#define ENVELOCK_FLAG_BYTECODE 64U" in header
    assert "#define ENVELOCK_FLAG_VAULT_ENC 128U" in header
    assert "#define ENVELOCK_FLAGS_KNOWN 255U" in header


# ---------------------------------------------------------------------------
# Objective O2: secret memory for the identity private keys.
# ---------------------------------------------------------------------------

SECRET_MOCK_C = r"""
/* Mock harness for the PRIMARY (memfd_secret) path of envelock_secret.c, for kernels that do not
 * offer the syscall.
 *
 * HOW IT SUBSTITUTES, stated plainly: the build links with -Wl,--wrap=syscall, so the extension's
 * call to syscall(SYS_memfd_secret, 0) lands in __wrap_syscall below and is answered with
 * memfd_create(2). Every line of the primary path around the syscall then really runs — the
 * ftruncate, the MAP_SHARED mapping, the FD_CLOEXEC on the fd, allocation, exhaustion, wipe,
 * teardown — against a real anonymous file descriptor. The two syscalls do not share a signature
 * (memfd_create takes a name and rejects NULL with EINVAL, memfd_secret takes flags), which is why
 * the number alone cannot simply be swapped.
 *
 * WHAT IT DOES NOT SHOW: the secrecy itself. A memfd_create mapping is ordinary memory, present in
 * /proc/self/maps and readable by a CAP_SYS_PTRACE reader through /proc/PID/mem. Only a kernel with
 * CONFIG_SECRETMEM and a small-page direct map removes those pages from the direct map. So this
 * harness asserts the arena IS listed in /proc/self/maps, and says so out loud.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#ifndef SYS_memfd_secret
# define SYS_memfd_secret 447   /* as envelock_secret.c does where the headers predate it */
#endif

extern long __real_syscall(long number, ...);

long __wrap_syscall(long number, ...)
{
    if (number == SYS_memfd_secret) return (long)memfd_create("envelock-secret-mock", 0);
    return __real_syscall(number);
}

#include "envelock_secret.c"

int main(void)
{
    unsigned char *keys, *more;
    FILE *f;
    char line[512];
    int listed = 0, nulls = 0, i;
    unsigned long a, b;

    if (!envelock_secret_init(0)) { printf("FAIL init\n"); return 1; }
    if (!envelock_secret_is_secret()) { printf("FAIL primary path not taken\n"); return 1; }

    keys = envelock_secret_alloc(64 * 32);
    if (!keys) { printf("FAIL alloc\n"); return 1; }
    memset(keys, 0xAB, 64 * 32);
    if (keys[0] != 0xAB || keys[64 * 32 - 1] != 0xAB) { printf("FAIL readback\n"); return 1; }

    more = envelock_secret_alloc(1);
    if (!more || more < keys + 64 * 32) { printf("FAIL overlap\n"); return 1; }

    for (i = 0; i < 4096; i++) if (envelock_secret_alloc(4096) == NULL) nulls++;
    if (nulls == 0) { printf("FAIL arena never exhausted\n"); return 1; }

    f = fopen("/proc/self/maps", "r");
    while (f && fgets(line, sizeof line, f)) {
        if (sscanf(line, "%lx-%lx", &a, &b) == 2 &&
            (unsigned long)keys >= a && (unsigned long)keys < b) listed = 1;
    }
    if (f) fclose(f);
    if (!listed) { printf("FAIL arena not in /proc/self/maps even under the mock\n"); return 1; }

    envelock_secret_shutdown();
    if (envelock_secret_alloc(32) != NULL) { printf("FAIL alloc after shutdown\n"); return 1; }
    printf("ok\n");
    return 0;
}
"""


def test_secret_memory_reports_what_the_kernel_actually_gave(native):
    """The directive must not silently claim a guarantee the kernel does not provide: with it off
    the arena is absent, with it on the answer names whichever mechanism is really in use."""
    off = php(native, "-r", "echo envelock_secret_memory();")
    assert off.returncode == 0
    assert off.stdout.strip() == "none"

    on = php(native, "-r", "echo envelock_secret_memory();",
             extra_ini=("-d", "envelock.secret_memory=1"))
    assert on.returncode == 0
    kind = on.stdout.strip()
    # memfd_secret needs CONFIG_SECRETMEM *and* a small-page direct map; where the syscall is not
    # registered the arena degrades to the locked mapping, and must say so rather than pass.
    assert kind in ("memfd_secret", "mlock+MADV_DONTDUMP"), kind


def test_secret_memory_keeps_decrypting_packages(native, tmp_path):
    """The private keys move behind the arena, so the whole decrypt path runs through it. A
    package that still opens proves the keys are read from where they were put."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.php").write_text('<?php\necho "secret-memory-ok\\n";\n')
    out = tmp_path / "out"
    a.pack_tree(src, out, [a.recipient_public(native[3])], native[2], str(uuid.uuid4()))
    for ini in ((), ("-d", "envelock.secret_memory=1")):
        result = php(native, str(out / "app.php"), extra_ini=ini)
        assert result.returncode == 0, result.stderr[-2000:]
        assert result.stdout == "secret-memory-ok\n", result.stdout


def test_secret_memory_primary_path_behaves(tmp_path):
    """Exercise the memfd_secret branch on a kernel that does not offer the syscall, by answering
    it with memfd_create at link time. This checks the code around the syscall, not the secrecy;
    see the harness header for the boundary."""
    if not sys.platform.startswith("linux") or not shutil.which("cc"):
        pytest.skip("needs a Linux C toolchain")
    try:  # the harness answers memfd_secret with memfd_create(2)
        os.close(os.memfd_create("envelock-probe", 0))
    except OSError:
        pytest.skip("this kernel lacks memfd_create, which the harness stands in for memfd_secret (e.g. WSL1)")
    work = tmp_path / "secret"
    work.mkdir()
    for name in ("envelock_secret.c", "envelock_secret.h"):
        shutil.copyfile(ROOT / "extension" / name, work / name)
    (work / "mock.c").write_text(SECRET_MOCK_C)
    built = work / "mock"
    result = subprocess.run(
        ["cc", "-I.", "-o", "mock", "mock.c", "-lcrypto", "-Wl,--wrap=syscall"],
        cwd=work, text=True, capture_output=True, check=False)
    if result.returncode:
        pytest.fail("cannot build the secret-memory harness:\n" + result.stderr[-4000:])
    run = subprocess.run([str(built)], cwd=work, text=True, capture_output=True, check=False)
    assert run.returncode == 0, run.stdout + run.stderr
    assert run.stdout.strip() == "ok"


# ---------------------------------------------------------------------------
# Objective O9: per-worker image cache.
# ---------------------------------------------------------------------------

def _rss_kb(pid):
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return -1


def serve_and_watch(native, docroot, path, requests, extra_ini=()):
    """Serve one path `requests` times on a single worker and return (bodies, rss_first, rss_last).

    The built-in cli-server keeps one process for every request, which is what makes a per-request
    leak visible: it shows up as RSS growth instead of as a crash.
    """
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    proc = popen_server(
        ["php", "-n", "-d", f"extension={native[1]}", "-d", f"envelock.identity={native[4]}",
         "-d", "opcache.enable=0", "-d", "opcache.enable_cli=0", "-d", "display_errors=1",
         *extra_ini, "-S", f"127.0.0.1:{port}", "-t", str(docroot)])
    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            if proc.poll() is not None:
                pytest.skip("built-in server did not start: " + server_output(proc)[-400:])
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                conn.request("GET", path)
                conn.getresponse().read()
                conn.close()
                break
            except OSError:
                time.sleep(0.2)
        else:
            pytest.skip("built-in server never became ready")
        first = last = -1
        bodies = []
        for index in range(requests):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request("GET", path)
            bodies.append(conn.getresponse().read().decode(errors="replace"))
            conn.close()
            if index == 0:
                first = _rss_kb(proc.pid)
            if index == requests - 1:
                last = _rss_kb(proc.pid)
        return bodies, first, last
    finally:
        stop_server(proc)


def _bytecode_serve(native, tmp_path, name, requests):
    """Pack BYTECODE_APP for a deploy root and serve its use.php repeatedly on one worker."""
    if _bytecode_available(native) != "yes":
        pytest.skip("no bytecode layer for this PHP version")
    # bytecode_pack derives the deploy root from `name` and packs into it; it is returned.
    output, deploy = bytecode_pack(native, tmp_path, name)
    deploy.mkdir(parents=True, exist_ok=True)
    for file in BYTECODE_APP:
        shutil.copyfile(output / file, deploy / file)
    return serve_and_watch(native, deploy, "/use.php", requests)


def test_bytecode_worker_does_not_leak_an_image_per_request(native, tmp_path):
    """Regression: the block an image is deserialized into was malloc'd for the process and never
    freed. It cannot be freed — the op_array, its opcodes, its literals and its class entries all
    point into it — so a long-lived worker leaked one copy of every protected file on every
    request. Measured on this package under the built-in web server: about 25 kB per request, so a
    worker serving a few thousand requests would have grown by tens of MB.

    The fix is that the block lives in the REQUEST heap, which is torn down when the request ends,
    exactly as upstream OPcache does for its own file cache. Nothing is cached: an image is
    decrypted and deserialized on every request, and a per-worker cache of reusable opcodes (the
    original objective O9) is still open — it needs a deserialized script that survives its
    request, which this persistence code does not produce."""
    if os.name == "nt" or not Path("/proc/self/status").exists():
        pytest.skip("measures the worker's RSS through /proc (Linux)")
    bodies, first, last = _bytecode_serve(native, tmp_path, "leak", 30)
    assert set(bodies) == {BYTECODE_EXPECTED}, sorted(set(bodies))[:2]
    growth = last - first
    # With the leak this is hundreds of kB over 29 requests; flat, it is within a few tens.
    assert growth < 400, f"worker RSS grew {growth} kB over 29 requests ({first} -> {last} kB)"


# ---------------------------------------------------------------------------
# Objective O3: anti-rehook self-verification and the opt-in paranoid mode.
# ---------------------------------------------------------------------------

O3_APP = "<?php\nfunction envelock_o3_secret(): int { return 4242; }\n"


def o3_package(native, tmp_path):
    return package(native, tmp_path, {
        "app.php": O3_APP,
        "index.php": "<?php\nrequire __DIR__ . '/app.php';\necho envelock_o3_secret(), \"\\n\";\n",
    })


def o3_run(native, package_path, extra_extension=(), paranoid=False, extra_ini=()):
    ini = ["-d", "envelock.paranoid=1"] if paranoid else []
    ini += list(extra_ini)
    if extra_extension:
        ini += ["-d", f"extension={extra_extension}"]
    return php(native, package_path / "index.php", extra_ini=ini)


def test_o3_package_runs_and_paranoia_does_not_break_it(native, tmp_path):
    """The control case, and the one that a too-eager check breaks first: a protected package must
    still run in a clean process, with the paranoid mode on. An earlier draft of this objective
    failed exactly here, because PHP 8.4 installs its own zend_interrupt_function before any
    extension's MINIT, so testing that pointer against NULL refused every process."""
    path = o3_package(native, tmp_path)
    for paranoid in (False, True):
        result = o3_run(native, path, paranoid=paranoid)
        assert result.returncode == 0, (paranoid, result.stderr)
        assert result.stdout == "4242\n"


def test_o3_rehook_above_envelock_is_detected(native, tmp_path):
    """Acceptance for the objective. An extension loaded after Envelock installs its own compile
    hook on top, and from there it receives the handle Envelock has just decrypted — the whole
    loader, defeated by one assignment. There is no name to look for, so the only way to catch it
    is to notice that zend_compile_file is no longer ours. This test is what proves we do."""
    path = o3_package(native, tmp_path)
    hook = build_hook(tmp_path, "rehook_compile", source_dir="rehook",
                      cflags="-DREHOOK_MODE=REHOOK_COMPILE_FILE")
    result = o3_run(native, path, extra_extension=hook)
    assert result.returncode != 0
    assert "compile hook above Envelock" in result.stderr, result.stderr


def test_o3_paranoia_rejects_execution_instruments(native, tmp_path):
    """A replacement of zend_execute_ex and an execution observer both see every op_array once it
    runs, decrypted. Neither is a loaded extension with a recognisable name, so neither is caught
    by the debugger list; they are exactly what the paranoid mode exists for."""
    path = o3_package(native, tmp_path)
    for mode, message in (("REHOOK_EXECUTE_EX", "zend_execute_ex has been replaced"),
                          ("REHOOK_OBSERVER", "an execution observer is registered")):
        hook = build_hook(tmp_path, "rehook_" + mode.lower(), source_dir="rehook",
                          cflags="-DREHOOK_MODE=" + mode)
        result = o3_run(native, path, extra_extension=hook, paranoid=True)
        assert result.returncode != 0, mode
        assert message in result.stderr, (mode, result.stderr)


def test_o3_execution_instruments_are_allowed_without_paranoia(native, tmp_path):
    """The paranoid mode is opt-in and must stay that way: a profiler or an APM agent replaces
    zend_execute_ex on purpose, and refusing one by default would break deployments that never
    asked for this. Without the flag the package still runs — the checks that need no opt-in are
    the hook-integrity ones, covered above."""
    path = o3_package(native, tmp_path)
    hook = build_hook(tmp_path, "rehook_plain", source_dir="rehook",
                      cflags="-DREHOOK_MODE=REHOOK_EXECUTE_EX")
    result = o3_run(native, path, extra_extension=hook)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "4242\n"


@pytest.fixture(scope="session")
def integrity_lib(tmp_path_factory):
    """envelock_integrity.c on its own. It has no PHP dependency on purpose, so the part worth
    testing — reading TracerPid out of a status file — is testable without an engine."""
    if os.name == "nt" or not shutil.which("cc"):
        pytest.skip("No C compiler for the integrity unit test")
    path = tmp_path_factory.mktemp("integrity") / "libenvelock_integrity.so"
    subprocess.run(["cc", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror", "-O2",
                    str(ROOT / "extension/envelock_integrity.c"), "-o", str(path)], check=True)
    loaded = ctypes.CDLL(str(path))
    loaded.envelock_parse_tracer_pid.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    loaded.envelock_parse_tracer_pid.restype = ctypes.c_int
    loaded.envelock_tracer_pid_from.argtypes = [ctypes.c_char_p]
    loaded.envelock_tracer_pid_from.restype = ctypes.c_int
    return loaded


def _parse_tracer_pid(lib, text):
    data = text.encode()
    return lib.envelock_parse_tracer_pid(data, len(data))


def test_o3_tracer_pid_parsing(integrity_lib, tmp_path):
    """A wrong answer here is worse than no answer. "Could not tell" (-1) must never be reported
    as "not traced" (0), and a truncated read must not read as a zero either."""
    real = ("Name:\tphp\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t1234\nPid:\t1234\nPPid:\t1\n"
            "TracerPid:\t0\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\nVmPeak:\t 12345 kB\n")
    assert _parse_tracer_pid(integrity_lib, real) == 0
    assert _parse_tracer_pid(integrity_lib, real.replace("TracerPid:\t0", "TracerPid:\t5678")) == 5678
    assert _parse_tracer_pid(integrity_lib, "TracerPid:\t4242\n") == 4242
    assert _parse_tracer_pid(integrity_lib, "TracerPid:\t77") == 77          # no trailing newline
    assert _parse_tracer_pid(integrity_lib, "TracerPid:   31\n") == 31        # spaces, not a tab
    # Not answerable, and must say so rather than claim "not traced".
    for undecidable in ("TracerPid:\t", "TracerPid:\txyz\n", "Name:\tphp\nPid:\t1\n", "",
                        "Foo TracerPid:\t9\n", "Seccomp:\tTracerPid:\t5\n"):
        assert _parse_tracer_pid(integrity_lib, undecidable) == -1, undecidable
    # Saturates instead of overflowing: an absurd value still means traced, and wrapping to 0
    # would report the opposite of what the file says.
    assert _parse_tracer_pid(integrity_lib, "TracerPid:\t" + "9" * 40 + "\n") == 2147483647


def test_o3_tracer_pid_reads_a_real_status_file(integrity_lib, tmp_path):
    """The parser against a file on disk rather than a buffer, including the "not a status file"
    case, which must come back as unknown and not as clean."""
    if not sys.platform.startswith("linux"):
        pytest.skip("TracerPid is a Linux /proc field; elsewhere the parser is compiled out")
    captured = tmp_path / "status"
    captured.write_text("Name:\tphp\nTracerPid:\t999\nUid:\t1000\n")
    assert integrity_lib.envelock_tracer_pid_from(str(captured).encode()) == 999
    other = tmp_path / "not-a-status"
    other.write_text("nothing to see here\n")
    assert integrity_lib.envelock_tracer_pid_from(str(other).encode()) == -1
    assert integrity_lib.envelock_tracer_pid_from(b"/nonexistent/envelock/status") == -1


@pytest.fixture(scope="session")
def ptrace_tracer(tmp_path_factory):
    """Attaches to a running process with PTRACE_SEIZE, holds it, then lets go.

    SEIZE rather than ATTACH because ATTACH stops the target, and a stopped process cannot run the
    check that would notice it — measured: the target sees TracerPid 0 before and after, never
    during. SEIZE leaves the target running while the tracer is attached, which is both the case a
    self-check can see and the case worth seeing, since that tracer is reading memory while the
    program works.
    """
    if not sys.platform.startswith("linux") or not shutil.which("cc"):
        pytest.skip("Needs Linux and a C compiler")
    directory = tmp_path_factory.mktemp("tracer")
    source = directory / "tracer.c"
    source.write_text(r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr, "uso: tracer <pid> <segundos>\n"); return 2; }
    pid_t target = (pid_t)atoi(argv[1]);
    if (ptrace(PTRACE_SEIZE, target, NULL, NULL) != 0) { perror("PTRACE_SEIZE"); return 1; }
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", (int)target);
    FILE *f = fopen(path, "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) { printf("%s", line); fflush(stdout); break; }
        }
        fclose(f);
    }
    usleep((useconds_t)(atof(argv[2]) * 1e6));
    ptrace(PTRACE_DETACH, target, NULL, NULL);
    return 0;
}
''')
    binary = directory / "tracer"
    built = subprocess.run(["cc", "-Wall", "-Wextra", "-O2", str(source), "-o", str(binary)],
                           text=True, capture_output=True, check=False)
    assert built.returncode == 0, built.stderr
    return binary


def test_o3_a_tracer_attached_while_a_protected_file_loads_is_refused(
        native, tmp_path, ptrace_tracer):
    """The TracerPid check against a real tracer, not a captured file.

    envelock.harden_memory is off here on purpose: PR_SET_DUMPABLE makes PTRACE_SEIZE fail, which
    is the protection working and would leave this test with nothing to detect. The point of the
    check is the tracer that gets through anyway — one with CAP_SYS_PTRACE, or one already attached
    before the flag was set.
    """
    path = o3_package(native, tmp_path)
    probe = tmp_path / "probe.php"
    pid_file = tmp_path / "probe.pid"
    probe.write_text(
        "<?php\nfile_put_contents(" + php_literal(str(pid_file)) + ", (string)getmypid());\n"
        "usleep(2000000);\nrequire " + php_literal(str(path / "index.php")) + ";\n")
    process = subprocess.Popen(
        ["php", "-n", "-d", f"extension={native[1]}", "-d", f"envelock.identity={native[4]}",
         "-d", "envelock.paranoid=1", "-d", "envelock.harden_memory=0", "-d", "display_errors=stderr",
         str(probe)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=php_environment())
    deadline = time.time() + 10
    while not pid_file.exists() and time.time() < deadline:
        time.sleep(0.05)
    assert pid_file.exists(), "the probe never reported its pid"
    tracer = subprocess.run([str(ptrace_tracer), pid_file.read_text().strip(), "3"],
                            text=True, capture_output=True, check=False)
    stdout, stderr = process.communicate(timeout=60)
    if tracer.returncode != 0 and "PTRACE_SEIZE: Invalid argument" in tracer.stderr:
        pytest.skip("this kernel does not support PTRACE_SEIZE (e.g. WSL1)")
    # A restricted environment (kernel.yama.ptrace_scope >= 1, no CAP_SYS_PTRACE — the default on
    # GitHub-hosted runners) forbids attaching to a process that is not our own child. The scenario
    # this test needs then cannot be set up; the TracerPid parser itself is covered by
    # test_o3_tracer_pid_reads_a_real_status_file, which needs no live tracer.
    if tracer.returncode != 0 and "PTRACE_SEIZE: Operation not permitted" in tracer.stderr:
        pytest.skip("this environment forbids ptrace of a non-child (ptrace_scope / no CAP_SYS_PTRACE)")
    assert "TracerPid:" in tracer.stdout, (tracer.stdout, tracer.stderr)
    assert tracer.stdout.split(":")[1].strip() != "0", "the tracer never attached"
    assert process.returncode != 0
    assert "being traced" in stderr, stderr
    assert "4242" not in stdout, "the protected code ran under a tracer"


# ---------------------------------------------------------------------------
# Objective O5: identity.bin as root:root mode 0400, and `server-install`.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def identity_file_lib(tmp_path_factory):
    """envelock_file.c on its own: the permission rule for the identity file, testable without
    an engine and without root."""
    if os.name == "nt" or not shutil.which("cc"):
        pytest.skip("No C compiler for the identity permission test")
    path = tmp_path_factory.mktemp("idfile") / "libenvelock_file.so"
    subprocess.run(["cc", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror", "-O2",
                    str(ROOT / "extension/envelock_file.c"), "-o", str(path)], check=True)
    loaded = ctypes.CDLL(str(path))
    loaded.envelock_identity_file_check.argtypes = [ctypes.c_void_p]
    loaded.envelock_identity_file_check.restype = ctypes.c_char_p
    return loaded


def _identity_check(lib, path, mode, uid=None):
    """Run the loader's own permission check over a file with the given mode (and owner)."""
    handle = open(path, "rb")
    try:
        if mode is not None:
            os.chmod(path, mode)
        if uid is not None:
            os.chown(path, uid, -1)
        libc = ctypes.CDLL(None)
        libc.fdopen.restype = ctypes.c_void_p
        libc.fdopen.argtypes = [ctypes.c_int, ctypes.c_char_p]
        stream = libc.fdopen(os.dup(handle.fileno()), b"rb")
        assert stream, "fdopen failed"
        try:
            return lib.envelock_identity_file_check(stream)
        finally:
            ctypes.CDLL(None).fclose(ctypes.c_void_p(stream))
    finally:
        handle.close()


def test_o5_identity_permission_rule(identity_file_lib, tmp_path):
    """The rule the root:0400 layout depends on, pinned so a later change cannot quietly drop it.

    A PHP-FPM master starts as root, reads the keys at startup, then forks workers that drop to
    the pool user; root ownership with mode 0400 is the layout where the pool user cannot read the
    keys at all. Note this rule already allowed it before objective O5 — a root process reading a
    root-owned file satisfies `st_uid == geteuid()` — so what O5 added is `server-install` and the
    message, not the permission. These assertions exist to keep it that way."""
    path = tmp_path / "identity.bin"
    path.write_bytes(b"x" * 64)
    me = os.getuid()
    # Accepted: mine with 0600 (the CLI layout), mine read-only, and root-owned read-only.
    assert _identity_check(identity_file_lib, path, 0o600, me) is None
    assert _identity_check(identity_file_lib, path, 0o400, me) is None
    if me == 0:
        assert _identity_check(identity_file_lib, path, 0o400, 0) is None
    # Refused: any group or other bit, whatever the owner.
    for mode in (0o640, 0o604, 0o644, 0o666, 0o440):
        assert _identity_check(identity_file_lib, path, mode, me) is not None, oct(mode)


def test_o5_identity_permission_rule_accepts_root_owner(tmp_path):
    """The half of the rule that needs root to observe, so it is asserted rather than assumed:
    with the file owned by root and mode 0400, the loader accepts it and a non-root user cannot
    even open it. Skipped where sudo is not available passwordless."""
    if os.name == "nt" or os.geteuid() == 0:
        pytest.skip("needs to run as a non-root user")
    probe = subprocess.run(["sudo", "-n", "true"], capture_output=True, check=False)
    if probe.returncode != 0:
        pytest.skip("passwordless sudo unavailable")
    path = tmp_path / "identity.bin"
    path.write_bytes(b"x" * 64)
    os.chmod(path, 0o644)          # so root can chown it, then tighten
    subprocess.run(["sudo", "-n", "chown", "0:0", str(path)], check=True)
    subprocess.run(["sudo", "-n", "chmod", "400", str(path)], check=True)
    try:
        info = path.stat()
        assert info.st_uid == 0 and info.st_mode & 0o777 == 0o400
        with pytest.raises(PermissionError):
            path.read_bytes()      # the pool user's answer
        # The master's answer: root can open and read it.
        read = subprocess.run(["sudo", "-n", "cat", str(path)], capture_output=True, check=False)
        assert read.returncode == 0 and read.stdout == b"x" * 64
    finally:
        subprocess.run(["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", str(path)],
                       check=False)


def test_o5_server_install_refuses_to_run_as_a_non_root_user(native, tmp_path):
    """The subcommand must not quietly write a file that only looks installed. A 0400 file owned
    by whoever ran it is still readable by that user and by anything sharing the account, which is
    exactly the exposure O5 removes — so it refuses, and writes nothing."""
    if os.name == "nt" or os.geteuid() == 0:
        pytest.skip("needs to run as a non-root user")
    recipient = tmp_path / "recipient.json"
    owner = tmp_path / "owner.json"
    a.save_json(recipient, a.make_recipient("o5"))
    a.save_json(owner, a.make_owner())
    out = tmp_path / "identity.bin"
    with pytest.raises(ValueError, match="must run as root"):
        a.server_install(a.server_install_identities([recipient], owner), out)
    assert not out.exists(), "it wrote the file anyway"


def test_o5_server_install_refuses_to_overwrite_an_existing_identity(native, tmp_path):
    """An identity file is not something to clobber by accident: replacing one silently changes
    which projects a host can serve, and the old keys are gone. Refuse and make the operator say
    so explicitly. This half is testable without root, since the check comes first."""
    if os.name == "nt" or os.geteuid() == 0:
        pytest.skip("needs to run as a non-root user")
    recipient = tmp_path / "recipient.json"
    owner = tmp_path / "owner.json"
    a.save_json(recipient, a.make_recipient("o5"))
    a.save_json(owner, a.make_owner())
    out = tmp_path / "identity.bin"
    out.write_bytes(b"the identity already installed on this host")
    before = out.read_bytes()
    with pytest.raises(ValueError, match="not overwritten"):
        a.server_install(a.server_install_identities([recipient], owner), out)
    assert out.read_bytes() == before, "it modified the installed identity"


def test_o5_server_install_leaves_root_readonly(native, tmp_path):
    """What the subcommand is for: the file ends up root:root mode 0400, verified by stat rather
    than assumed, and a second install over an existing file is refused instead of clobbered."""
    if os.name == "nt" or os.geteuid() == 0:
        pytest.skip("needs to run as a non-root user")
    probe = subprocess.run(["sudo", "-n", "true"], capture_output=True, check=False)
    if probe.returncode != 0:
        pytest.skip("passwordless sudo unavailable")
    recipient = tmp_path / "recipient.json"
    owner = tmp_path / "owner.json"
    a.save_json(recipient, a.make_recipient("o5"))
    a.save_json(owner, a.make_owner())
    out = tmp_path / "identity.bin"
    os.chmod(tmp_path, 0o777)      # root has to be able to create the file here
    bundle = a.server_install_identities([recipient], owner)
    try:
        run = subprocess.run(
            ["sudo", "-n", sys.executable, "-c",
             "import sys; sys.path.insert(0, " + repr(str(ROOT)) + ");"
             "from encoder import envelock as a;"
             "a.server_install(sys.stdin.buffer.read(), __import__('pathlib').Path(" +
             repr(str(out)) + "))"],
            input=bundle, capture_output=True, check=False)
        assert run.returncode == 0, run.stdout.decode() + run.stderr.decode()
        info = out.stat()
        assert info.st_uid == 0 and info.st_gid == 0
        assert info.st_mode & 0o777 == 0o400
        assert out.read_bytes() != bundle       # PermissionError for us, in practice
    except PermissionError:
        pass
    finally:
        subprocess.run(["sudo", "-n", "rm", "-f", str(out)], check=False)


def test_o5_protected_package_runs_as_root_and_not_as_the_pool_user(native, tmp_path):
    """The acceptance criterion end to end: with the identity installed root:root 0400, the
    process that starts as root can run the protected package, and a non-root process cannot read
    the keys at all. This is the PHP-FPM shape without needing an FPM master."""
    if os.name == "nt" or os.geteuid() == 0:
        pytest.skip("needs to run as a non-root user")
    probe = subprocess.run(["sudo", "-n", "true"], capture_output=True, check=False)
    if probe.returncode != 0:
        pytest.skip("passwordless sudo unavailable")
    path = package(native, tmp_path, {
        "app.php": "<?php\nfunction o5_secret(): int { return 4242; }\n",
        "index.php": "<?php\nrequire __DIR__ . '/app.php';\necho o5_secret(), \"\\n\";\n",
    })
    installed = tmp_path / "installed-identity.bin"
    shutil.copyfile(native[4], installed)
    os.chmod(installed, 0o644)
    subprocess.run(["sudo", "-n", "chown", "0:0", str(installed)], check=True)
    subprocess.run(["sudo", "-n", "chmod", "400", str(installed)], check=True)
    try:
        for target in (path, native[1]):
            subprocess.run(["sudo", "-n", "chmod", "a+rX", str(target)], check=False)
        as_root = subprocess.run(
            ["sudo", "-n", "php", "-n", "-d", f"extension={native[1]}",
             "-d", f"envelock.identity={installed}", "-d", "display_errors=stderr",
             str(path / "index.php")],
            capture_output=True, text=True, check=False)
        assert as_root.returncode == 0, as_root.stderr
        assert as_root.stdout == "4242\n"
        as_pool = php(native, path / "index.php", identity=installed)
        assert as_pool.returncode != 0
        assert "identity file rejected" in as_pool.stderr, as_pool.stderr
        assert "4242" not in as_pool.stdout
    finally:
        subprocess.run(["sudo", "-n", "rm", "-f", str(installed)], check=False)


# ---------------------------------------------------------------------------
# Objective O7: the vault table is encrypted at rest and decrypted per access.
# ---------------------------------------------------------------------------

O7_LITERAL = "SELECT secret FROM vault_table WHERE id = ?"


def test_o7_vault_table_holds_no_plaintext_literal(native, tmp_path):
    """What O7 adds over the original vault. The container was already encrypted, so "the literal
    is not in the file" was true before and proves nothing here. The point is the layer inside:
    once the container is decrypted — which the loader does once, at load, and which is exactly
    what a memory reader waits for — the vault table must still be ciphertext. Before O7 every
    secret string in the file lay in one contiguous, already-decrypted block at that moment."""
    code = ("<?php $sql = '" + O7_LITERAL + "';"
            " $msg = 'access-granted-message'; echo $sql, '|', $msg;")
    out = package(native, tmp_path, {"index.php": code}, vault_strings=True)
    blob = (out / "index.php").read_bytes()
    assert a.parse_package(blob)["flags"] & a.FLAG_VAULT_ENC, "the package is not using the encrypted vault"

    plain = a.open_protected(blob, a.make_identity(native[3], native[2]))
    table_bytes = int.from_bytes(plain[:4], "big")
    table, source = plain[4:4 + table_bytes], plain[4 + table_bytes:]
    # Not in the table, and not anywhere in the decrypted container at all.
    assert O7_LITERAL.encode() not in table
    assert O7_LITERAL.encode() not in plain
    assert b"access-granted-message" not in plain
    # The program still runs, so the literals are really there and really resolve.
    result = php(native, out / "index.php")
    assert result.returncode == 0, result.stderr
    assert result.stdout == O7_LITERAL + "|access-granted-message"
    # And the source the engine compiles asks the loader for them rather than carrying them.
    assert b"__envelock_lit(" in source
    assert O7_LITERAL.encode() not in source


def test_o7_tampered_vault_entry_is_not_handed_over(native, tmp_path, monkeypatch):
    """Each entry is AES-GCM under a per-file data key, so a flipped byte must cost the attacker
    that literal rather than reveal it. The loader's answer for an entry whose tag does not verify
    is the empty string — the same as any other vault miss — so a stray or forged lookup can never
    fatal a request either.

    The tampering is done on the plaintext table and the file is then packed normally, so the
    container's own signature and tag stay valid: what this exercises is the vault parser and the
    per-entry tag, not the container. Patching the encoder is the only way to get a well-formed
    container around a corrupted table, since flipping a byte of the blob would break the
    container's tag first and prove nothing about the vault."""
    code = "<?php $sql = '" + O7_LITERAL + "'; echo '[', $sql, ']';"
    real = a._vault_plaintext_encrypted
    holder = {}

    def corrupt_one_byte(table, source, content_key):
        good = bytearray(real(table, source, content_key))
        table_bytes = int.from_bytes(good[:4], "big")
        entry_length = int.from_bytes(good[68:72], "big")
        assert 68 + 4 + entry_length <= 4 + table_bytes, "the probe is outside the table"
        target = 68 + 4 + 12 + 1        # inside the first entry's ciphertext, past its nonce
        good[target] ^= 0x01
        holder["patched"] = bytes(good)
        return bytes(good)

    monkeypatch.setattr(a, "_vault_plaintext_encrypted", corrupt_one_byte)
    out = package(native, tmp_path, {"index.php": code}, vault_strings=True)
    assert "patched" in holder, "the packer never called the encrypted-vault encoder"

    result = php(native, out / "index.php")
    assert result.returncode == 0, result.stderr
    assert O7_LITERAL not in result.stdout, "a tampered entry was handed over"
    assert result.stdout == "[]", result.stdout


# ---------------------------------------------------------------------------
# Objective O8: signed deployment licenses (expiry, machine binding).
# ---------------------------------------------------------------------------

def _licence_php(native, out, blob):
    """Run one packaged file under a license, written to a temp path next to the package."""
    path = out.parent / "licence.bin"
    path.write_bytes(blob)
    return php(native, out / "index.php", extra_ini=(f"-denvelock.licence={path}",))


def test_o8_machine_fingerprint_agrees_between_encoder_and_loader(native):
    """The one property everything else here rests on. The fingerprint is computed twice, once in
    Python when the vendor issues the license and once in C when the loader checks it, from two
    independent implementations of the same recipe. If they disagree by a single byte every
    machine-bound license is refused, and the failure would look like a bad license rather than a
    mismatch — so the pair is compared directly, on this host, instead of being assumed."""
    got = php(native, "-r", "echo envelock_machine_fingerprint();")
    assert got.returncode == 0, got.stderr
    if PHP_WINDOWS:
        # Machine binding is not implemented by the Windows loader: it reports no identity, so a
        # machine-bound licence is refused there (fail closed; see the refusal test below).
        assert got.stdout == "", got.stdout
        return
    try:
        expected = a.machine_fingerprint().hex()
    except ValueError:
        expected = ""
    if not expected:
        pytest.skip("this host reports no machine identity")
    assert got.stdout == expected, (
        "the loader and the encoder fingerprint this host differently; every machine-bound "
        f"license would be refused (loader {got.stdout}, encoder {expected})")


def test_o8_licence_with_an_unknown_field_bit_is_refused(native, tmp_path):
    """ENV-2026-30: a licence that sets a field bit this loader does not understand (a constraint a
    newer encoder would add) must be REFUSED, not run with the unknown constraint silently ignored
    (fail-open). The bit is set and the body re-signed so the signature itself is valid — only the
    unknown field makes it fail."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    out = package(native, tmp_path, {"index.php": "<?php echo 'X';"})
    blob = bytearray(a.issue_licence(native[2], expires=int(time.time()) + 3600))
    assert len(blob) == 240
    blob[9] |= 0x10                                              # a field bit this loader does not know
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(native[2]["signing_private"]))
    blob[176:240] = sk.sign(bytes(blob[:176]))                  # re-sign the body so the signature is valid
    bad = _licence_php(native, out, bytes(blob))
    assert bad.returncode != 0, bad.stdout                      # refused, not run with the bit ignored


def test_o8_valid_licence_lets_the_package_run(native, tmp_path):
    """A license signed by the owner and still in date changes nothing: the file runs."""
    out = package(native, tmp_path, {"index.php": "<?php echo 'O8-OK';"})
    result = _licence_php(native, out,
                          a.issue_licence(native[2], expires=int(time.time()) + 3600))
    assert result.returncode == 0, result.stderr
    assert result.stdout == "O8-OK"


def test_o8_trusted_time_is_fetched_at_startup(native, tmp_path):
    """The trusted-time floor (O8) is fetched once per worker at startup, but only when a license is
    in force. Regression for an external-audit finding (reproduced): MINIT read the license-present
    flag before loading the license, so the flag was still 0 and the TLS fetch never ran — the
    startup time floor was inert and a rolled-back clock could revive an expired license. We point
    trusted_time at 127.0.0.1 (nothing listens on 443) and confirm with strace that the loader
    attempts the connection at startup. Without the fix there is no connect() at all."""
    if shutil.which("strace") is None:
        pytest.skip("strace not available")
    # envelock.harden_memory is off here ON PURPOSE, for the same reason as the O3 tracer test: the
    # hardening calls prctl(PR_SET_DUMPABLE, 0) at MINIT, BEFORE the trusted-time block. On a kernel
    # that enforces that flag (GitHub-hosted runners), a strace whose process lacks CAP_SYS_PTRACE
    # loses visibility of every syscall once the traced process turns non-dumpable — so the connect(),
    # which happens after the prctl, was recorded on a permissive kernel (WSL1) yet invisible on the
    # runners, and the test failed for the observer, not the loader. With hardening off the process
    # stays dumpable and strace sees the connect. The MINIT ordering under test is independent of
    # memory hardening. Verified on AlmaLinux 8 that the published loader does make this connect.
    # A probe still guards the fully-restricted case (strace cannot trace even a plain child).
    probe = tmp_path / "strace-probe.txt"
    probe_php = tmp_path / "probe.php"
    probe_php.write_text('<?php @fsockopen("127.0.0.1", 443, $e, $s, 1); echo "P";')
    probe_run = subprocess.run(
        ["strace", "-f", "-e", "trace=connect", "-o", str(probe), "php", "-n", str(probe_php)],
        capture_output=True, text=True, env=php_environment(), timeout=30, check=False)
    if not probe.exists() or "htons(443)" not in probe.read_text(errors="replace"):
        pytest.skip("strace cannot observe connect() syscalls here (restricted ptrace): "
                    f"probe stderr {probe_run.stderr[:200]!r}")
    out = package(native, tmp_path, {"index.php": "<?php echo 'TT';"})
    licence = out.parent / "licence.bin"
    licence.write_bytes(a.issue_licence(native[2], expires=int(time.time()) + 3600))
    trace = out.parent / "connect-trace.txt"
    result = subprocess.run(
        ["strace", "-f", "-e", "trace=connect", "-o", str(trace),
         "php", "-n",
         "-d", f"extension={native[1]}",
         "-d", f"envelock.identity={native[4]}",
         "-d", f"envelock.licence={licence}",
         "-d", "envelock.trusted_time=127.0.0.1",
         "-d", "envelock.trusted_time_timeout=1",
         "-d", "envelock.harden_memory=0",
         "-d", "opcache.enable=0", "-d", "opcache.enable_cli=0",
         str(out / "index.php")],
        capture_output=True, text=True, env=php_environment(), timeout=30, check=False,
    )
    if not trace.exists():
        pytest.skip("strace could not attach in this environment")
    assert result.returncode == 0, result.stderr
    assert "TT" in result.stdout
    assert "htons(443)" in trace.read_text(errors="replace"), (
        "the loader did not attempt the trusted-time fetch at startup: MINIT is not loading the "
        "license before the trusted-time block")


def test_o8_expired_licence_refuses_the_package(native, tmp_path):
    """Expiry is enforced by the loader, not by the packer: a package that ran yesterday refuses to
    run today on the same server, with nothing repacked."""
    out = package(native, tmp_path, {"index.php": "<?php echo 'O8-OK';"})
    result = _licence_php(native, out,
                          a.issue_licence(native[2], expires=int(time.time()) - 3600))
    assert result.returncode != 0
    assert "expired" in result.stderr, result.stderr


def test_o8_licence_bound_to_another_machine_is_refused(native, tmp_path):
    """The binding that stops a license (and with it the deployment) being copied to a second
    server. The fingerprint here is a constant that is not this host's, so this passes on any
    machine and does not depend on what the test host happens to report."""
    out = package(native, tmp_path, {"index.php": "<?php echo 'O8-OK';"})
    result = _licence_php(native, out,
                          a.issue_licence(native[2], machine=b"\x11" * 32))
    assert result.returncode != 0
    # Windows and macOS loaders: no machine identity at all (the fingerprint reads Linux-only
    # sources), so every machine-bound licence is refused for want of an identity, not a mismatch.
    expected = "reports no machine identity" if (PHP_WINDOWS or PHP_MACOS) else "different machine"
    assert expected in result.stderr, result.stderr


def test_o8_licence_bound_to_this_machine_is_accepted(native, tmp_path):
    """The other half of the binding: the host's OWN fingerprint must be accepted, or the check
    would be refusing everything and the test above would pass for the wrong reason."""
    try:
        here = a.machine_fingerprint()
    except ValueError:
        pytest.skip("this host reports no machine identity")
    out = package(native, tmp_path, {"index.php": "<?php echo 'O8-OK';"})
    result = _licence_php(native, out, a.issue_licence(native[2], machine=here))
    assert result.returncode == 0, result.stderr
    assert result.stdout == "O8-OK"


def test_o8_licence_from_another_owner_is_refused(native, tmp_path):
    """Only a key the server already trusts can issue a license — the same developer keys that sign
    packages. Anyone could otherwise mint their own license, and since a license only ever
    constrains, a self-issued one is how an attacker would lift a restriction."""
    out = package(native, tmp_path, {"index.php": "<?php echo 'O8-OK';"})
    stranger = a.make_owner()
    result = _licence_php(native, out,
                          a.issue_licence(stranger, expires=int(time.time()) + 3600))
    assert result.returncode != 0
    assert "does not verify" in result.stderr, result.stderr


def test_o8_edited_licence_body_is_refused(native, tmp_path):
    """Flipping a byte of the signed body — here the expiry — must cost the whole license. The
    signature is over the body, so this is the check that makes the fields mean anything."""
    out = package(native, tmp_path, {"index.php": "<?php echo 'O8-OK';"})
    tampered = bytearray(a.issue_licence(native[2], expires=int(time.time()) + 3600))
    tampered[12] ^= 0xFF                      # inside the u64 expiry
    result = _licence_php(native, out, bytes(tampered))
    assert result.returncode != 0
    assert "does not verify" in result.stderr, result.stderr


def test_o8_missing_licence_fails_closed(native, tmp_path):
    """Once envelock.licence names a file, that license is mandatory. Deleting it must not lift its
    restrictions, or removing the file would be the cheapest way to bypass them."""
    out = package(native, tmp_path, {"index.php": "<?php echo 'O8-OK';"})
    result = php(native, out / "index.php",
                 extra_ini=("-denvelock.licence=" + str(out.parent / "absent.bin"),))
    assert result.returncode != 0
    assert "cannot be opened" in result.stderr, result.stderr


def _serve_with_licence(native, docroot, licence, hosts):
    """Serve docroot under a license and GET /index.php once per (label, Host header) pair.

    Its own helper rather than serve_over_http because a domain binding is about the Host header,
    which that helper does not let a test set. Returns {label: body}.
    """
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    path = docroot.parent / "licence-domain.bin"
    path.write_bytes(licence)
    proc = popen_server(
        ["php", "-n", "-d", f"extension={native[1]}", "-d", f"envelock.identity={native[4]}",
         "-d", f"envelock.licence={path}", "-d", "opcache.enable=0",
         "-d", "opcache.enable_cli=0", "-d", "display_errors=1",
         "-S", f"127.0.0.1:{port}", "-t", str(docroot)])
    bodies = {}
    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            if proc.poll() is not None:
                pytest.skip("built-in server did not start: " + server_output(proc)[-400:])
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                conn.request("GET", "/__ping")
                conn.getresponse().read()
                conn.close()
                break
            except OSError:
                time.sleep(0.2)
        else:
            pytest.skip("built-in server did not answer")
        for label, host in hosts:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request("GET", "/index.php", headers={"Host": host})
            bodies[label] = conn.getresponse().read().decode("utf-8", "replace")
            conn.close()
    finally:
        stop_server(proc)
    return bodies


def test_o8_domain_binding_follows_server_name_not_a_spoofed_host_header(native, tmp_path):
    """ENV-2026-06: a domain-bound licence must follow SERVER_NAME — the host the SERVER is configured
    to serve — not the client's Host header, which any client or proxy admin can set to the licensed
    domain to run the package on an unauthorised server. The built-in server reports SERVER_NAME = the
    bind host (127.0.0.1) whatever Host a client sends, so a licence bound to 127.0.0.1 runs for ANY
    Host header (the spoof is ignored), and a licence bound to a different domain is refused whatever
    Host is sent.

    It also covers a trap worth keeping pinned down: $_SERVER is a LAZY auto-global, so a compile hook
    that reads it without materialising it first finds nothing and silently falls back to the machine's
    own host name — which would refuse every domain-bound licence on a web server while looking exactly
    like a wrong licence."""
    out = package(native, tmp_path, {"index.php": "<?php echo 'O8-DOMAIN-OK';"})
    if PHP_WINDOWS:
        # The Windows loader has no host lookup: a domain-bound licence is refused whatever the server
        # name or Host header (fail closed), including for the name it actually serves.
        refused = _serve_with_licence(
            native, out, a.issue_licence(native[2], domain=a.domain_hash("127.0.0.1")),
            [("honest", "127.0.0.1"), ("spoof", "app.example.com")])
        for label, body in refused.items():
            assert "reports no host name" in body, (label, body)
        return
    # Bound to the host the server actually serves (SERVER_NAME = the bind host). A forged Host header
    # must NOT change the verdict: every request runs.
    served = _serve_with_licence(
        native, out, a.issue_licence(native[2], domain=a.domain_hash("127.0.0.1")),
        [("honest", "127.0.0.1"), ("spoof_a", "app.example.com"), ("spoof_b", "other.example:8443")])
    assert served["honest"] == "O8-DOMAIN-OK", served["honest"]
    assert served["spoof_a"] == "O8-DOMAIN-OK", served["spoof_a"]
    assert served["spoof_b"] == "O8-DOMAIN-OK", served["spoof_b"]
    # Bound to a domain the server does NOT serve: refused whatever Host is sent — a spoofed Host that
    # matches the licensed name can no longer satisfy the binding.
    denied = _serve_with_licence(
        native, out, a.issue_licence(native[2], domain=a.domain_hash("licensed.example.com")),
        [("spoof_licensed", "licensed.example.com"), ("other", "127.0.0.1")])
    assert "different domain" in denied["spoof_licensed"], denied["spoof_licensed"]
    assert "different domain" in denied["other"], denied["other"]


def test_o8_ip_binding_accepts_this_host_and_refuses_another(native, tmp_path):
    """The server's own IPv4 addresses. Unlike the Host header these are not something a remote
    caller chooses, so this one is not spoofable from outside — at the cost of being brittle on a
    host whose addresses change, which is why it is offered as a separate constraint."""
    try:
        here = a.host_ips_hash()
    except ValueError:
        pytest.skip("this host has no non-loopback IPv4 address")
    out = package(native, tmp_path, {"index.php": "<?php echo 'O8-IP-OK';"})
    good = _licence_php(native, out, a.issue_licence(native[2], ip=here))
    assert good.returncode == 0, good.stderr
    assert good.stdout == "O8-IP-OK"
    bad = _licence_php(native, out, a.issue_licence(native[2], ip=b"\x33" * 32))
    assert bad.returncode != 0
    assert "different IP address" in bad.stderr, bad.stderr


def test_o8_constraints_can_be_combined(native, tmp_path):
    """A license may bind several constraints at once, and every one of them has to hold: a
    per-field check that short-circuited on the first match would let a license through on the
    strength of the one constraint that happened to fit."""
    try:
        here = a.machine_fingerprint()
    except ValueError:
        pytest.skip("this host reports no machine identity")
    out = package(native, tmp_path, {"index.php": "<?php echo 'O8-BOTH-OK';"})
    everything = a.issue_licence(native[2], expires=int(time.time()) + 3600, machine=here,
                                 domain=a.domain_hash("cli.example"))
    # Under the CLI SAPI there is no request, so the loader compares the machine's own name.
    good = _licence_php(native, out, a.issue_licence(
        native[2], expires=int(time.time()) + 3600, machine=here,
        domain=a.domain_hash(socket.gethostname())))
    assert good.returncode == 0, good.stderr
    assert good.stdout == "O8-BOTH-OK"
    # Machine and expiry both fine, domain wrong: still refused.
    wrong = _licence_php(native, out, everything)
    if socket.gethostname() != "cli.example":
        assert wrong.returncode != 0
        assert "different domain" in wrong.stderr, wrong.stderr


# ---------------------------------------------------------------------------
# Objective O8: anti-clock-rollback. An expiry checked against the local clock
# is worth nothing if `date -s` can move it back; the watermark is what makes
# setting the clock back show up instead of extending the license.
# ---------------------------------------------------------------------------

def _write_clock_state(path, watermark):
    """Write a clock state file the loader will accept, in its own format."""
    body = b"ENVLKCLK" + bytes([1, 0, 0, 0]) + watermark.to_bytes(8, "big")
    check = hashlib.sha256(b"envelock-clock-1\n" + body[:20]).digest()[:8]
    path.write_bytes(body + check)


def _clock_php(native, out, state, tolerance="3600", licence=None):
    """Run one packaged file under a license plus a clock state file."""
    blob = licence if licence is not None else a.issue_licence(
        native[2], expires=int(time.time()) + 3600)
    lic = out.parent / "licence-clock.bin"
    lic.write_bytes(blob)
    return php(native, out / "index.php", extra_ini=(
        f"-denvelock.licence={lic}", f"-denvelock.clock_state={state}",
        f"-denvelock.clock_tolerance={tolerance}"))


def test_o8_clock_set_back_is_refused(native, tmp_path):
    """The bypass this exists for. The license is still in date and the clock says so — but the
    installation has already been seen running a month from now, so the clock is lying."""
    out = package(native, tmp_path, {"index.php": "<?php echo 'O8-CLOCK-OK';"})
    state = out.parent / "clock.bin"
    _write_clock_state(state, int(time.time()) + 86400 * 30)
    result = _clock_php(native, out, state)
    assert result.returncode != 0
    assert "clock is behind" in result.stderr, result.stderr


def test_o8_clock_within_tolerance_is_accepted(native, tmp_path):
    """The other half: an NTP step or a corrected timezone must not stop a server. A watermark ten
    minutes ahead is normal drift, not a rollback, and refusing it would make the feature
    undeployable."""
    out = package(native, tmp_path, {"index.php": "<?php echo 'O8-CLOCK-OK';"})
    state = out.parent / "clock.bin"
    _write_clock_state(state, int(time.time()) + 600)
    result = _clock_php(native, out, state, tolerance="3600")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "O8-CLOCK-OK"


def test_o8_negative_tolerance_does_not_disable_rollback(native, tmp_path):
    """envelock.clock_tolerance is admin-set (PHP_INI_SYSTEM) and read as a signed long; a negative
    value (e.g. -1) used to cast to a huge uint64, collapse every floor to 0 and silently disable the
    whole rollback check (audit NU-01). It is now clamped, so a set-back is still refused."""
    out = package(native, tmp_path, {"index.php": "<?php echo 'O8-CLOCK-OK';"})
    state = out.parent / "clock.bin"
    _write_clock_state(state, int(time.time()) + 86400 * 30)
    result = _clock_php(native, out, state, tolerance="-1")
    assert result.returncode != 0, result.stdout                 # before the fix: accepted (rc 0)
    assert "clock is behind" in result.stderr, result.stderr


def test_o8_watermark_persists_under_a_long_lived_worker(tmp_path):
    """ENV-01: the persist throttle must measure advance from the ON-DISK value, not the in-memory
    watermark. A worker advancing in sub-`step` increments otherwise never crossed its own value +
    step, never rewrote the file, and a restart lost the whole advance. A C harness compiles
    envelock_clock.c with a simulated clock (--wrap=time) and drives 200 one-minute advances."""
    import shutil
    cc = shutil.which("cc") or shutil.which("gcc")
    phpcfg = shutil.which("php-config")
    if not cc or not phpcfg:
        pytest.skip("no C compiler / php-config for the clock harness")
    ext = Path(__file__).resolve().parent.parent / "extension"
    harness = tmp_path / "clk_harness.c"
    harness.write_text(
        "#include <stdint.h>\n#include <stdio.h>\n#include <time.h>\n#include <openssl/sha.h>\n"
        '#include "envelock_clock.h"\n'
        "static time_t g_now = 1700000000;\n"
        "time_t __wrap_time(time_t *t){ if(t)*t=g_now; return g_now; }\n"
        "int envelock_sha256(const unsigned char *b, size_t n, unsigned char o[32]){ return SHA256(b,n,o)!=NULL; }\n"
        "int main(int argc, char **argv){\n"
        "  uint64_t live=0, disk=0; const char *p=argv[1]; remove(p);\n"
        "  envelock_clock_advance(p,&live,3600,1);\n"
        "  for(int i=0;i<200;i++){ g_now+=60; envelock_clock_advance(p,&live,3600,1); }\n"
        "  envelock_clock_load(p,&disk);\n"
        "  return (live>=disk && (live-disk)<=3600) ? 0 : 1;\n}\n")
    includes = subprocess.run([phpcfg, "--includes"], capture_output=True, text=True).stdout.split()
    binp = tmp_path / "clk_harness"
    build = subprocess.run([cc, "-O2", "-I", str(ext), *includes, str(harness),
                            str(ext / "envelock_clock.c"), "-Wl,--wrap=time", "-lcrypto", "-o", str(binp)],
                           capture_output=True, text=True)
    if build.returncode != 0:
        # Only a missing OpenSSL header is the environment's fault. Anything else is this harness
        # or envelock_clock.c: it once called envelock_clock_advance with 3 of its 4 arguments and
        # skipped silently everywhere, so this regression test never ran.
        if "openssl/sha.h" in build.stderr:
            pytest.skip("OpenSSL headers are not installed")
        pytest.fail("clock harness did not build: " + build.stderr[-2000:])
    run = subprocess.run([str(binp), str(tmp_path / "clk.state")], capture_output=True, text=True)
    assert run.returncode == 0, "the on-disk watermark did not follow the advance (ENV-01)"


def test_o8_running_records_the_time(native, tmp_path):
    """A clean run has to leave a record behind, or the next one has nothing to compare against and
    the whole check is inert. The state file is created by the worker itself."""
    out = package(native, tmp_path, {"index.php": "<?php echo 'O8-CLOCK-OK';"})
    state = out.parent / "clock.bin"
    assert not state.exists()
    before = int(time.time())
    result = _clock_php(native, out, state)
    assert result.returncode == 0, result.stderr
    assert state.is_file(), "a clean run left no clock state behind"
    blob = state.read_bytes()
    assert blob[:8] == b"ENVLKCLK" and len(blob) == 28
    recorded = int.from_bytes(blob[12:20], "big")
    assert before - 60 <= recorded <= int(time.time()) + 60, recorded


def test_o8_unreadable_clock_state_does_not_refuse(native, tmp_path):
    """Bookkeeping must not become an outage. A state file that is missing, truncated or garbage
    costs one rollback detection; refusing to run on its account would let anyone take the site
    down by touching a file, and would punish the operator for the vendor's bookkeeping."""
    out = package(native, tmp_path, {"index.php": "<?php echo 'O8-CLOCK-OK';"})
    state = out.parent / "clock.bin"
    state.write_bytes(os.urandom(28))
    result = _clock_php(native, out, state)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "O8-CLOCK-OK"


def test_o8_clock_state_is_ignored_without_a_licence(native, tmp_path):
    """The watermark only means anything next to an expiry. An unlicensed deployment has nothing to
    roll back to, so a stale or forged state file must not stop it."""
    out = package(native, tmp_path, {"index.php": "<?php echo 'O8-CLOCK-OK';"})
    state = out.parent / "clock.bin"
    _write_clock_state(state, int(time.time()) + 86400 * 30)
    result = php(native, out / "index.php",
                 extra_ini=(f"-denvelock.clock_state={state}",))
    assert result.returncode == 0, result.stderr
    assert result.stdout == "O8-CLOCK-OK"


# ---------------------------------------------------------------------------
# Objective O8: trusted time. The watermark defeats `date -s`, but the record is
# a file the administrator can delete; a floor fetched over TLS is not.
# ---------------------------------------------------------------------------

def test_o8_unreachable_trusted_time_does_not_break_the_site(native, tmp_path):
    """The failure mode that matters most. A trusted time source is an outbound dependency added to
    a web server, and the moment it is configured the site must not depend on the internet: an
    unresolvable host, a blocked egress port or a slow peer has to degrade to the local clock and
    the watermark, not to an outage. Needs no network to test, which is the point."""
    out = package(native, tmp_path, {"index.php": "<?php echo 'O8-TT-OK';"})
    blob = a.issue_licence(native[2], expires=int(time.time()) + 3600)
    lic = out.parent / "licence-tt.bin"
    lic.write_bytes(blob)
    result = php(native, out / "index.php", extra_ini=(
        f"-denvelock.licence={lic}",
        "-denvelock.trusted_time=envelock-no-existe.invalid",
        "-denvelock.trusted_time_timeout=3"))
    assert result.returncode == 0, result.stderr
    assert result.stdout == "O8-TT-OK"


def test_o8_trusted_time_is_not_a_userland_function(native):
    """ENV-2026-08: envelock_trusted_time must NOT be exposed as a userland PHP function. As a global
    function it was an unrestricted DNS + TCP + TLS primitive that any script could point at any host,
    bypassing disable_functions, allow_url_fopen=0 and open_basedir. The time floor still uses the
    fetch INTERNALLY (test_o8_trusted_time_is_fetched_at_startup covers that path); it just is not a
    callable function any more."""
    got = php(native, "-r", "echo function_exists('envelock_trusted_time') ? 'EXPOSED' : 'ok';")
    assert got.returncode == 0, got.stderr
    assert got.stdout == "ok"


# ---------------------------------------------------------------------------
# Objective O4: the mini-VM. A marked function ships as this instruction stream
# instead of as standard PHP opcodes.
# ---------------------------------------------------------------------------

def _virtualize(name, source):
    """Compile one marked function to a mini-VM program. Returns (base64, None) or (None, reason)."""
    result = subprocess.run(
        # memory_limit lifted as for any build step: the u16-header tests compile functions with tens of
        # thousands of constants/locals, which exceed the stock 128M with some official PHP builds.
        ["php", "-d", "display_errors=stderr", "-d", "memory_limit=-1",
         str(ROOT / "encoder" / "virtualize.php")],
        input=json.dumps({"files": {"a.php": base64.b64encode(source.encode()).decode()},
                          "marked": [name]}).encode(),
        capture_output=True, timeout=120, check=False)
    if result.returncode != 0:
        return None, result.stderr.decode(errors="replace").strip()
    return json.loads(result.stdout)["programs"][name], None


def _vm_run(native, program, args):
    """Run a program through the loader's VM and return (ok, json_text, stderr)."""
    result = php(native, "-r",
                 "echo json_encode(__envelock_vm(" + repr(program) + ", " + json.dumps(args) + "));")
    return result.returncode == 0, result.stdout, result.stderr


O4_CASES = [
    # (function source, [(args, ...), ...]) — each is compared against PHP itself, which is the
    # only oracle that can say whether a mini-VM agrees with the language.
    ("function f($n) { $t = 0; for ($i = 1; $i <= $n; $i = $i + 1) { if ($i % 2 == 0) { $t = $t + $i; } } return $t; }",
     "f", [[10], [7], [0], [1]]),
    ("function f($a, $b) { $s = 'x' . $a . $b; if ($a > 0 && $b != 0) { $s = $s . '!'; } "
     "elseif ($a < 0 || $b == 0) { $s = $s . '?'; } $i = 0; "
     "while ($i < 3) { $s = $s . (string) $i; $i = $i + 1; } return $s; }",
     "f", [[5, 3], [-1, 0], [0, 0], [0, 5]]),
    ("function f($x) { $t = [1, 2, 3]; $r = $t[1] * 2 + $x ** 2 - 7 % 4; $r = $r / 2; "
     "if (!($x >= 0)) { $r = -$r; } return $r; }",
     "f", [[3], [-2], [0]]),
]


@pytest.mark.parametrize("source,name,cases", O4_CASES, ids=["loop", "branches", "arithmetic"])
def test_o4_virtualized_function_matches_php(native, source, name, cases):
    """The acceptance criterion for O4: the marked function runs, and it computes what PHP computes.

    PHP itself is the oracle, run in a separate process on the same inputs. That matters more than
    it looks: a mini-VM that returns a plausible answer is not the same as one that agrees with the
    language on `==`, on `**`, on int/float promotion and on short-circuit evaluation, and those are
    exactly the places a re-implementation drifts. Four separate bugs were found this way."""
    program, error = _virtualize(name, "<?php\n" + source + "\n")
    assert program is not None, f"the compiler refused: {error}"
    for args in cases:
        expected = subprocess.run(
            ["php", "-n", "-d", "display_errors=stderr", "-r", source + f"\necho json_encode({name}("
             + ", ".join(repr(a) for a in args) + "));"],
            capture_output=True, text=True, check=False)
        assert expected.returncode == 0, expected.stderr
        ok, got, stderr = _vm_run(native, program, args)
        assert ok, f"{name}{tuple(args)}: the VM refused to run it: {stderr.strip()[:200]}"
        assert got == expected.stdout, f"{name}{tuple(args)}: php={expected.stdout} vm={got}"


def test_vm_runs_only_for_a_direct_call(native):
    """ENV-2026-07: __envelock_vm runs a program only on a DIRECT call from user code. Routed through
    an internal function (array_map with '__envelock_vm' as the callback), the immediate caller frame
    is array_map, not user code, so the call is refused (returns null) — it cannot be used as a gadget
    to run an attacker-supplied program from a callback context."""
    program, reason = _virtualize("f", "<?php\nfunction f(int $a): int { return $a + 100; }\n")
    assert program, reason
    direct = php(native, "-r", "echo json_encode(__envelock_vm(" + repr(program) + ", [41]));")
    assert direct.returncode == 0, direct.stderr
    assert direct.stdout == "141"                               # the direct call runs the program
    via = php(native, "-r", "var_dump(array_map('__envelock_vm', [" + repr(program) + "]));")
    assert via.returncode == 0, via.stderr
    assert "NULL" in via.stdout and "141" not in via.stdout     # refused through array_map


# Function calls (O4). Each case states what PHP does; the VM must match it or refuse at compile time.
# A call the VM cannot reproduce exactly (by-reference parameters, frame-dependent builtins, strict
# types, namespaces, named or spread arguments) must be refused, never silently run.
O4_CALL_CASES = [
    ("function f($s) { return abs($s) + floor($s / 2); }", "f", [[-3], [0], [7]]),
    ("function f($s) { return STRTOUPPER($s) . str_repeat('-', 2); }", "f", [["ab"]]),
    ("function f($a, $b) { return intdiv($a, $b) + abs($a - $b); }", "f", [[7, 2], [-9, 4]]),
    ("function f($a) { return str_repeat('-', 2) . intdiv($a, 2); }", "f", [[3], [-7]]),
    ("function f($a) { return array_map('abs', $a); }", "f", [[[-1, 2, -3]]]),
    ("function f($a) { return str_repeat(strtoupper('x' . $a), 2) . intdiv(9, 2); }", "f", [["yz"], [""]]),
]


@pytest.mark.parametrize("source,name,cases", O4_CALL_CASES, ids=[f"call{i}" for i in range(len(O4_CALL_CASES))])
def test_o4_function_calls_match_php(native, source, name, cases):
    program, error = _virtualize(name, "<?php\n" + source + "\n")
    assert program is not None, f"the compiler refused a plain builtin call: {error}"
    for args in cases:
        expected = subprocess.run(
            ["php", "-n", "-d", "display_errors=stderr", "-r", source + f"\necho json_encode({name}(" + ", ".join(repr(a) for a in args) + "));"],
            capture_output=True, text=True, check=False)
        assert expected.returncode == 0, expected.stderr
        ok, got, stderr = _vm_run(native, program, args)
        assert ok, f"{name}{tuple(args)}: {stderr.strip()[:200]}"
        assert got == expected.stdout, f"{name}{tuple(args)}: php={expected.stdout} vm={got}"


def test_o4_call_result_is_a_var_for_operand_order(native):
    """Zend ranks a call's result as a VAR (4): `(TMP) | f()` swaps, so PHP reports the TypeError as
    `string | int`. The loader must reproduce that message, not the unswapped one."""
    source = "function f($a, $b) { return (($a += 1) | str_repeat(-3, $b)); }"
    program, error = _virtualize("f", "<?php\n" + source + "\n")
    assert program is not None, error
    php_run = subprocess.run(["php", "-n", "-d", "display_errors=stderr", "-r", source + "\necho f(0, 0);"], capture_output=True, text=True, check=False)
    assert "Unsupported operand types: string | int" in php_run.stderr, php_run.stderr
    ok, got, stderr = _vm_run(native, program, [0, 0])
    assert not ok and "Unsupported operand types: string | int" in stderr, stderr


@pytest.mark.parametrize("source,call_args", [
    ("function f($a, $b) { return $a . [1, 2]; }", "$obj, 0"),
    ("function f($a, $b) { return $undef . [1, 2]; }", "$obj, 0"),
    ("function f($a, $b) { return $b . [1, 2]; }", "5, 0"),
    ("function f($a, $b) { return $a . $b; }", "$obj, [1]"),
])
def test_o4_concat_array_conversion_order_matches_php(native, source, call_args):
    """PHP converts a constant array on the right before it reads a plain local on the left. Both
    sides run under the same handler that turns the first warning into an exception, so the test
    compares the first diagnostic the program raises, exactly."""
    program, error = _virtualize("f", "<?php\n" + source + "\n")
    assert program is not None, error
    handler = "set_error_handler(function($n,$s){throw new ErrorException($s,0,$n);}); $obj = (object)['x' => 1]; "
    tail = "try { echo serialize(%s); } catch (Throwable $e) { echo get_class($e), ': ', $e->getMessage(); }"
    expected = subprocess.run(["php", "-n", "-d", "display_errors=stderr", "-r", handler + source + "\n" + tail % ("f(" + call_args + ")")],
                              capture_output=True, text=True, check=False)
    got = php(native, "-r", handler + tail % ("__envelock_vm(" + repr(program) + ", [" + call_args + "])"))
    assert got.returncode == 0 and got.stdout == expected.stdout, (expected.stdout, got.stdout, got.stderr)


def test_o4_branch_order_matrix_matches_php(native):
    """Runs the branch section of scripts/vm_order_matrix.py (ternary branches and boolean operators
    that copy a plain local) against PHP. The operator and dimension sections are long; run them with
    `python3 scripts/vm_order_matrix.py --loader <v3 loader> --section ops|dims`."""
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "vm_order_matrix.py"),
                             "--loader", native[1], "--section", "branch"],
                            capture_output=True, text=True, errors="replace", timeout=900, check=False)
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-2000:]
    assert "section=branch total=126 divergences=0 refused=0" in result.stdout, result.stdout[-2000:]


@pytest.mark.parametrize("source,call_args", [
    ("function f($a, $b) { return [1, 2] . $undef; }", "$obj, 0"),
    ("function f($a, $b) { return (~(($a -= 1.5) ? 2 : $undef)); }", "1.5, -2"),
    ("function f($a, $b) { return (~(($a -= 1.5) ? $undef : 2)); }", "1.5, -2"),
    ("function f($a, $b) { return (~(($a -= 1.5) ? 2 : $b)); }", "1.5, -2"),
])
def test_o4_warning_before_an_operation_matches_php(native, source, call_args):
    """A warning that throws must stop the program where PHP stops it: a constant array on the left of
    `.` is converted before a local on the right is read, and a plain local in a ternary branch is
    copied by an operation of its own, so the operation after the ternary does not run."""
    program, error = _virtualize("f", "<?php\n" + source + "\n")
    assert program is not None, error
    handler = "set_error_handler(function($n,$s){throw new ErrorException($s,0,$n);}); $obj = (object)['x' => 1]; "
    tail = "try { echo serialize(%s); } catch (Throwable $e) { echo get_class($e), ': ', $e->getMessage(); }"
    expected = subprocess.run(["php", "-n", "-d", "display_errors=stderr", "-r", handler + source + "\n" + tail % ("f(" + call_args + ")")],
                              capture_output=True, text=True, check=False)
    got = php(native, "-r", handler + tail % ("__envelock_vm(" + repr(program) + ", [" + call_args + "])"))
    assert got.returncode == 0 and got.stdout == expected.stdout, (source, expected.stdout, got.stdout, got.stderr)


def test_o4_call_to_missing_function_reports_before_arguments(native):
    """PHP raises `Call to undefined function` before it evaluates the arguments: an undefined
    variable inside the arguments must not warn first. Measured with PHP 8.4."""
    source = "function f($a) { return nope_fn($undef); }"
    program, error = _virtualize("f", "<?php\n" + source + "\n")
    assert program is not None, error
    php_run = subprocess.run(["php", "-n", "-d", "display_errors=stderr", "-r", source + "\necho f(1);"], capture_output=True, text=True, check=False)
    assert "Call to undefined function nope_fn()" in php_run.stderr
    ok, got, stderr = _vm_run(native, program, [1])
    assert not ok and "Call to undefined function nope_fn()" in stderr, stderr
    assert "Undefined variable" not in stderr, stderr


def test_o4_exception_from_a_called_builtin_propagates(native):
    source = "function f($a) { return intdiv($a, 0); }"
    program, error = _virtualize("f", "<?php\n" + source + "\n")
    assert program is not None, error
    php_run = subprocess.run(["php", "-n", "-d", "display_errors=stderr", "-r", source + "\necho f(5);"], capture_output=True, text=True, check=False)
    assert "DivisionByZeroError: Division by zero" in php_run.stderr
    ok, got, stderr = _vm_run(native, program, [5])
    assert not ok and "DivisionByZeroError: Division by zero" in stderr, stderr
    assert "could not run" not in stderr, stderr


@pytest.mark.parametrize("source,why", [
    ("function f($a) { sort($a); return $a; }", "by-reference"),
    ("function f($a) { return compact('a'); }", "frame"),
    ("function f($a) { return extract($a); }", "frame"),
    ("function f($a) { return func_get_args(); }", "frame"),
    ("function f($a) { return f(name: $a); }", "named"),
    ("function f($a) { return strlen(...$a); }", "spread"),
    ("function f($a) { return \\strlen($a); }", "qualified"),
    ("function f($a) { return isset($a); }", "language"),
    ("function f($a) { return strlen($a, 2); }", "arguments"),
    ("function f($a) { return min($a, true); }", "direct min compares differently"),
])
def test_o4_refuses_calls_it_cannot_reproduce(source, why):
    program, error = _virtualize("f", "<?php\n" + source + "\n")
    assert program is None, f"accepted a call that must be refused ({why}): {source}"


def test_o4_calls_user_functions_by_value_like_php(native):
    """A user function is not known at compile time, so the compiler cannot check its parameters.
    By-value user functions must run and agree with PHP."""
    source = "function f($a) { return twice($a) + 1; }"
    program, error = _virtualize("f", "<?php\n" + source + "\n")
    assert program is not None, error
    defs = "function twice($x) { return $x * 2; }"
    expected = subprocess.run(["php", "-n", "-d", "display_errors=stderr", "-r", defs + "\n" + source + "\necho json_encode(f(5));"],
                              capture_output=True, text=True, check=False)
    assert expected.returncode == 0, expected.stderr
    run = php(native, "-r", defs + "\necho json_encode(__envelock_vm(" + repr(program) + ", [5]));")
    assert run.returncode == 0 and run.stdout == expected.stdout, (run.stderr, run.stdout, expected.stdout)


def test_o4_refuses_user_function_with_by_reference_parameter_at_run_time(native):
    """Unknown at compile time, so the loader checks at INIT_CALL: it must refuse, never copy."""
    source = "function f($a) { return bump($a); }"
    program, error = _virtualize("f", "<?php\n" + source + "\n")
    assert program is not None, error
    defs = "function bump(&$x) { $x = $x + 1; return $x; }"
    run = php(native, "-r", defs + "\nset_error_handler(function($n,$s){throw new ErrorException($s);});"
              "try { echo json_encode(__envelock_vm(" + repr(program) + ", [1])); } catch (Throwable $e) { echo 'REFUSED:', $e->getMessage(); }")
    assert run.returncode == 0, run.stderr
    assert "REFUSED:" in run.stdout and "by-reference" in run.stdout, run.stdout


def test_o4_refuses_calls_in_strict_types_and_namespaces():
    strict = "<?php\ndeclare(strict_types=1);\nfunction f($a) { return strlen($a); }\n"
    program, error = _virtualize("f", strict)
    assert program is None, "strict_types callers have different coercion; refuse them"
    namespaced = "<?php\nnamespace App;\nfunction f($a) { return strlen($a); }\n"
    program, error = _virtualize("f", namespaced)
    assert program is None, "unqualified calls in a namespace resolve differently; refuse them"


def test_o4_program_is_not_standard_opcodes(native):
    """The point of the objective: what ships is the mini-VM's own instruction stream, not a
    zend_op_array, so the logic is not present as standard PHP opcodes. Checked structurally —
    the stream carries this format's header and none of the shapes a compiled PHP function has."""
    program, error = _virtualize(
        "f", "<?php\nfunction f($n) { $t = 0; for ($i = 0; $i < $n; $i = $i + 1) { $t = $t + $i; } return $t; }\n")
    assert program is not None, error
    blob = base64.b64_decode(program) if hasattr(base64, "b64_decode") else base64.b64decode(program)
    assert blob[:6] == b"ENVVM3", "the program does not carry the v2 mini-VM header"
    constant_count = int.from_bytes(blob[6:8], "big")
    local_count = int.from_bytes(blob[8:10], "big")
    assert constant_count > 0 and local_count > 0
    # Every opcode must be one this loader defines; a zend_op_array would not decode as such.
    known = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
             0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11}
    cursor = 10
    for _ in range(constant_count):
        kind = blob[cursor]
        cursor += {0: 1, 1: 2, 2: 9, 3: 9}[kind] if kind != 4 else 4 + int.from_bytes(blob[cursor + 1:cursor + 4], "big")
    code_length = int.from_bytes(blob[cursor:cursor + 4], "big")
    code = blob[cursor + 4:cursor + 4 + code_length]
    widths = {0x01: 2, 0x02: 2, 0x03: 2, 0x04: 1, 0x05: 1, 0x06: 4, 0x07: 4, 0x08: 3,
              0x09: 0, 0x0A: 0, 0x0B: 2, 0x0C: 0, 0x0D: 0, 0x0E: 0, 0x0F: 4, 0x10: 4, 0x11: 4}
    index = 0
    seen = 0
    while index < len(code):
        assert code[index] in known, f"opcode {code[index]:#04x} at {index} is not in the mini-VM set"
        index += 1 + widths[code[index]]
        seen += 1
    assert index == len(code), "the instruction stream does not decode to its declared length"
    assert seen > 5, "a real function should be more than a handful of instructions"


def test_o4_unsupported_construct_is_refused_by_name(native):
    """The subset is the safety property. A construct the mini-VM does not implement must be
    refused, naming the construct — never approximated. A protector that quietly changed what a
    function does would be worse than no protector at all."""
    for construct, source in [
        ("object member", "function f($o) { return $o->x; }"),
        ("static call", "function f() { return DateTime::createFromFormat('Y', '2020'); }"),
        ("foreach", "function f($a) { $t = 0; foreach ($a as $v) { $t = $t + $v; } return $t; }"),
        ("try/catch", "function f() { try { return 1; } catch (Exception $e) { return 0; } }"),
        ("closure", "function f() { $g = function () { return 1; }; return $g(); }"),
        ("increment", "function f($n) { $i = 0; while ($i < $n) { $i++; } return $i; }"),
        ("heredoc", "function f() { return <<<EOT\ntext\nEOT;\n}"),
        ("interpolated string", 'function f($a) { return "value: $a"; }'),
    ]:
        program, error = _virtualize("f", "<?php\n" + source + "\n")
        assert program is None, f"{construct} was compiled but should have been refused"
        assert "outside the virtualized subset" in error, f"{construct}: {error}"


def test_o4_vm_refuses_a_program_it_does_not_understand(native):
    """A program is data, so the loader has to treat it as hostile: a bad header, a truncated
    constant pool or an unknown opcode must fail with a message, not read past the end."""
    for label, blob in [
        ("wrong header", b"XXXXXX" + b"\x00" * 40),
        ("truncated", b"ENVVM1" + b"\x00" * 4),
        ("pool past the end", b"ENVVM1" + (2).to_bytes(2, "big") + (0).to_bytes(2, "big")
                              + b"\x02" + b"\x00" * 4),
        ("unknown opcode", b"ENVVM1" + (0).to_bytes(2, "big") + (0).to_bytes(2, "big")
                           + (1).to_bytes(4, "big") + b"\xEE"),
    ]:
        result = php(native, "-r", "echo __envelock_vm(" + repr(base64.b64encode(blob).decode()) + ");")
        assert result.returncode != 0, f"{label}: accepted a program it should refuse"
        assert "Envelock" in result.stderr, f"{label}: {result.stderr[:200]}"


O4_FUNCTION = ("<?php\n"
               "function total($n) { $t = 0; for ($i = 1; $i <= $n; $i = $i + 1) "
               "{ if ($i % 2 == 0) { $t = $t + $i; } } return $t; }\n"
               "echo total(10), '|', total(7), '|', total(0);\n")


def test_o4_packed_function_runs_through_the_mini_vm(native, tmp_path):
    """The end-to-end acceptance for O4: from `pack --virtualize` to a working site, with the
    marked function's logic gone from what ships.

    Three things have to hold at once, and the first two on their own would not be enough. The
    program still computes the right answer — a pack that ran and returned 0 would pass a
    'does it load' check. The source PHP compiles and ships no longer contains the loop, which is
    the actual claim of the objective. And the loader, not PHP, is what evaluates it."""
    out = package(native, tmp_path, {"index.php": O4_FUNCTION}, virtualize=["total"])
    result = php(native, out / "index.php")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "30|12|0", f"the virtualized function computed: {result.stdout}"

    blob = (out / "index.php").read_bytes()
    # No --vault-strings here, so the decrypted container is the source itself with no table
    # prefix; slicing off a prefix would read past the end and test an empty string.
    source = a.open_protected(blob, a.make_identity(native[3], native[2]))
    assert source.strip(), "the decrypted container came back empty"
    assert b"__envelock_vm_v2(" in source, "the shipped source does not call the v2 mini-VM"
    # What must be gone is the logic, not the name: the signature stays so callers keep working.
    for fragment in (b"for ($i", b"% 2 == 0", b"$t = $t + $i"):
        assert fragment not in source, f"the function body is still in the source: {fragment!r}"


def test_o4_manifest_records_what_was_virtualized(native, tmp_path):
    """A pack has to say what it did. `--virtualize` names functions, and a typo would otherwise
    be silent: the pack would succeed and simply ship that function as ordinary PHP, which is the
    one outcome the flag exists to prevent."""
    source = tmp_path / "src"
    source.mkdir()
    (source / "index.php").write_bytes(O4_FUNCTION.encode())
    out = tmp_path / "out"
    info = a.pack_tree(source, out, [a.recipient_public(native[3])], native[2], str(uuid.uuid4()),
                       virtualize=["total"], virtualize_loader=native[1], unsafe_vm_laboratory=True)
    assert info["virtualized_functions"] == ["total"]
    assert info["unsafe_vm_laboratory"] is True and info["vm_program_version"] == 3
    expected_sha = hashlib.sha256((ROOT / 'encoder/virtualize.php').read_bytes()).hexdigest()
    assert info["vm_compiler_sha256"] == expected_sha
    saved = json.loads((out / 'envelock-package.json').read_text())
    assert saved["vm_compiler_sha256"] == expected_sha


def test_o4_pack_is_refused_when_a_marked_function_is_outside_the_subset(native, tmp_path):
    """The refusal must stop the pack, naming the construct. Shipping that function unvirtualized
    would be the silent failure: the user asked for the logic to leave the file and it did not."""
    code = "<?php\nfunction total($xs) { $t = 0; foreach ($xs as $v) { $t = $t + $v; } return $t; }\n"
    with pytest.raises(ValueError) as failure:
        package(native, tmp_path, {"index.php": code}, virtualize=["total"])
    message = str(failure.value)
    assert "outside the virtualized subset" in message or "foreach" in message, message


def test_o4_pack_is_refused_when_a_marked_name_is_not_a_function(native, tmp_path):
    """`--virtualize` takes names the packer cannot check against the user's intent, so a name that
    matches nothing has to be an error rather than a no-op."""
    with pytest.raises(ValueError) as failure:
        package(native, tmp_path, {"index.php": O4_FUNCTION}, virtualize=["does_not_exist"])
    assert "was not found" in str(failure.value)


# ---------------------------------------------------------------------------
# Objective O10: the loader compiled INTO the engine.
# ---------------------------------------------------------------------------

def test_o10_loader_works_when_compiled_into_php(native, tmp_path):
    """A single-binary distribution has no module to load: a statically linked PHP has no dynamic
    loader at all (FrankenPHP's static builds show no "Dynamic Library Support" row in phpinfo), so
    the loader has to be linked into the engine. That build shape exercises paths a module never
    does, and three real defects only appear in it — see scripts/build-static-php.sh.

    Gated on ENVELOCK_STATIC_PHP because building such a PHP takes minutes and needs autoconf; the
    rest of the suite must not depend on it. Build one with:
        bash scripts/build-static-php.sh php-8.4.27.tar.gz /tmp/php-static
        ENVELOCK_STATIC_PHP=/tmp/php-static pytest -k o10
    """
    binary = os.getenv("ENVELOCK_STATIC_PHP")
    if not binary:
        pytest.skip("set ENVELOCK_STATIC_PHP to a php built by scripts/build-static-php.sh")
    if not Path(binary).is_file():
        pytest.fail(f"ENVELOCK_STATIC_PHP does not exist: {binary}")

    def run(*arguments):
        return subprocess.run([binary, "-n", "-d", "display_errors=stderr", *map(str, arguments)],
                              capture_output=True, text=True, check=False, env=php_environment())

    # No -d extension=: the point is that nothing is being loaded from disk.
    probe = run("-r", 'echo (int) extension_loaded("envelock"), (int) function_exists("__envelock_vm");')
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout == "11", "the loader is not compiled into this php binary"

    code = ("<?php\nfunction total($n) { $t = 0; for ($i = 1; $i <= $n; $i = $i + 1) "
            "{ if ($i % 2 == 0) { $t = $t + $i; } } return $t; }\necho 'ok ', total(10);\n")
    out = package(native, tmp_path, {"index.php": code}, virtualize=["total"])
    result = subprocess.run(
        [binary, "-n", "-d", f"envelock.identity={native[4]}", "-d", "display_errors=stderr",
         "-d", "opcache.enable=0", str(out / "index.php")],
        capture_output=True, text=True, check=False, env=php_environment())
    assert result.returncode == 0, result.stderr
    assert result.stdout == "ok 30", result.stdout


def test_o10_module_declares_both_openssl_libraries():
    """config.m4 must ask pkg-config for libssl as well as libcrypto. envelock_trusted_time.c
    speaks TLS, which lives in libssl; a module gets away with declaring only libcrypto because a
    shared object may leave symbols undefined and the dynamic linker resolves them from the host
    process — so the dependency is real but invisible until something links the extension where
    there is no host to borrow from. Checked in the build description rather than at run time,
    because the failure is a link error, not a behaviour."""
    text = (ROOT / "extension" / "config.m4").read_text()
    assert "libssl" in text, "config.m4 does not require libssl; a static build will not link"
    # And the extension has to be buildable as a built-in, not only as a module.
    header = ROOT / "extension" / "php_envelock.h"
    assert header.is_file(), "php_envelock.h is missing; php cannot compile the extension in"
    assert "phpext_envelock_ptr" in header.read_text()
    assert '"php_envelock.h"' in (ROOT / "extension" / "envelock.c").read_text(), \
        "envelock.c does not include the header, so a mismatch would go uncaught"


def test_names_and_vault_preserve_dynamic_class_lookup(native, tmp_path):
    """The vault must not hide a literal before the package-wide name safety check sees it."""
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.php").write_bytes(
        b"<?php class Widget {} echo class_exists('Widget') ? 'YES' : 'NO';")
    info = a.pack_tree(source, tmp_path / "packed", [a.recipient_public(native[3])], native[2],
                       str(uuid.uuid4()), obfuscate_names=True, vault_strings=True)
    assert info["names_obfuscated"] == []
    result = php(native, tmp_path / "packed" / "main.php")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "YES"


@pytest.mark.parametrize("allowlist", [False, True], ids=["all-eligible", "strict-allowlist"])
def test_namespaced_ast_then_bytecode_executes_closed_pack(native, tmp_path, allowlist):
    """Exercise the actual loader: AST rename first, compile bytecode second, identical runtime."""
    if _bytecode_available(native) != "yes":
        pytest.skip("no bytecode emitter in this loader (a production build has none)")
    source = tmp_path / "source"
    source.mkdir()
    (source / "types.php").write_bytes(
        b"<?php namespace App\\Model; class Widget { public static function answer(){ return 42; } }")
    (source / "main.php").write_bytes(
        b"<?php namespace App; require __DIR__ . '/types.php'; "
        b"use App\\Model\\Widget as Item; echo Item::answer();")
    original = subprocess.run(["php", "-n", str(source / "main.php")], capture_output=True, text=True,
                              timeout=60, check=False)
    assert original.returncode == 0 and original.stdout == "42", original.stderr
    destination, deploy = tmp_path / "packed", tmp_path / "deploy"
    deploy.mkdir()
    policy = ["type:App\\Model\\Widget"] if allowlist else None
    info = a.pack_tree(source, destination, [a.recipient_public(native[3])], native[2], str(uuid.uuid4()),
                       obfuscate_names=True, obfuscate_names_ast=True, obfuscate_names_allowlist=policy,
                       bytecode=True, deploy_root=deploy, bytecode_loader=str(native[1]))
    assert info["names_obfuscated"] and not info["names_skipped"]
    assert info["names_allowlist_enforced"] is allowlist
    shutil.copytree(destination, deploy, dirs_exist_ok=True)
    protected = php(native, deploy / "main.php")
    assert protected.returncode == 0, protected.stderr
    assert protected.stdout == original.stdout


def test_assembled_dynamic_name_guard_runs_before_vault(native, tmp_path):
    """A real loader run: vaulting cannot hide the parts of a dynamic constant lookup."""
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.php").write_bytes(
        b"<?php namespace App; class Widget { const VALUE=42; } "
        b"$n='App\\\\' . 'Wid' . 'get::VALUE'; echo constant($n);")
    info = a.pack_tree(source, tmp_path / "packed", [a.recipient_public(native[3])], native[2],
                       str(uuid.uuid4()), obfuscate_names=True, obfuscate_names_ast=True,
                       vault_strings=True)
    assert info["names_obfuscated"] == [] and info["names_skipped"] == "dynamic"
    result = php(native, tmp_path / "packed" / "main.php")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "42"


@pytest.mark.parametrize("expression", [
    "false", "TRUE", "Null", "0123", "0o17", "1_000", "0b10_01", "0xFA_10", "1_2.3_4",
    r'"a\q"', r'"\u{1F600}"', 'b"binary"',
    '"x" . 1 + 2', '1 . 2 << 1', '-2 ** 2', '(int) 1.5 ** 2',
], ids=["false", "true", "null", "octal", "explicit-octal", "integer-separator", "binary-separator",
        "hex-separator", "float-separator", "unknown-string-escape", "unicode-escape", "binary-string",
        "concat-add", "concat-shift", "negative-exponent", "cast-exponent"])
def test_vm_literals_and_precedence_match_php(native, expression):
    """Literal spelling and operator precedence must not alter the VM result or its PHP type."""
    function = f"function f() {{ return {expression}; }}"
    original = subprocess.run(["php", "-n", "-r", function + " echo json_encode(f());"],
                              capture_output=True, text=True, check=False)
    assert original.returncode == 0, original.stderr
    program, error = _virtualize("f", "<?php " + function)
    assert program is not None, error
    ok, value, stderr = _vm_run(native, program, [])
    assert ok, stderr
    assert value == original.stdout, (expression, value, original.stdout)


@pytest.mark.parametrize("operator", ["&&", "||"])
@pytest.mark.parametrize("args", [[0, 7], [2, 7], [2, 0], ["0", "x"], [None, True]])
def test_vm_short_circuit_returns_php_boolean(native, operator, args):
    source = f"function f($a, $b) {{ return $a {operator} $b; }}"
    original = subprocess.run(["php", "-n", "-r", source + " echo json_encode(f(...json_decode($argv[1], true)));",
                               json.dumps(args)], capture_output=True, text=True, check=False)
    assert original.returncode == 0, original.stderr
    program, error = _virtualize("f", "<?php " + source)
    assert program is not None, error
    ok, value, stderr = _vm_run(native, program, args)
    assert ok, stderr
    assert value == original.stdout, (operator, args, value, original.stdout)


@pytest.mark.parametrize("operator", ["&&", "||"])
@pytest.mark.parametrize("arg", [0, 1])
def test_vm_short_circuit_preserves_side_effects(native, operator, arg):
    source = f"function f($a) {{ $x=0; $v=$a {operator} (($x=9)>0); return [$v, $x]; }}"
    original = subprocess.run(["php", "-n", "-r", source + f" echo json_encode(f({arg}));"],
                              capture_output=True, text=True, check=False)
    assert original.returncode == 0, original.stderr
    program, error = _virtualize("f", "<?php " + source)
    assert program is not None, error
    ok, value, stderr = _vm_run(native, program, [arg])
    assert ok, stderr
    assert value == original.stdout, (operator, arg, value, original.stdout)


def test_vm_bare_user_constant_is_refused_instead_of_becoming_a_string():
    program, error = _virtualize("f", "<?php const SECRET=42; function f(){return SECRET;}")
    assert program is None and "outside the virtualized subset" in error, (program, error)


def test_vm_function_call_policy_refuses_measured_special_cases_only():
    """Calls are compiled only for builtins measured to behave the same directly and through a value.
    Zend's special-cased builtins (strlen) and min/max are refused with the measured reason; a plain
    builtin (abs) compiles. Replaces the old blanket refusal, which predated the measurements."""
    program, error = _virtualize("f", '<?php function f(){return strlen("abc");}')
    assert program is None and "compares differently" in error and "outside the virtualized subset" in error, error
    program, error = _virtualize("f", '<?php function f($a){return abs($a);}')
    assert program is not None, error


def test_vm_packed_literals_and_boolean_result_match_php(native, tmp_path):
    """End-to-end test: a successful pack must not silently change these values or types."""
    src = tmp_path / "src"
    src.mkdir()
    data = (b"<?php function choose($n){return ($n && true) ? 0o17 : 1_000;} "
            b"echo json_encode([choose(2), choose(0)]);")
    (src / "main.php").write_bytes(data)
    expected = subprocess.run(["php", "-n", str(src / "main.php")], capture_output=True, text=True)
    assert expected.returncode == 0 and expected.stdout == "[15,1000]"
    info = a.pack_tree(src, tmp_path / "packed", [a.recipient_public(native[3])], native[2],
                       str(uuid.uuid4()), virtualize=["choose"], virtualize_loader=native[1],
                       unsafe_vm_laboratory=True)
    assert info["virtualized_functions"] == ["choose"]
    result = php(native, tmp_path / "packed" / "main.php")
    assert result.returncode == 0 and result.stdout == expected.stdout, (result.stderr, result.stdout)


@pytest.mark.parametrize("expression", ['+"12"', '~"ab"', '(array) null', '(array) [1,2]'],
                         ids=["unary-plus-numeric-string", "bitwise-not-string", "cast-null", "cast-array"])
def test_vm_unary_operations_match_php_types_and_values(native, expression):
    function = f"function f() {{ return {expression}; }}"
    expected = subprocess.run(["php", "-n", "-r", function + " echo base64_encode(serialize(f()));"],
                               text=True, capture_output=True, check=False)
    assert expected.returncode == 0, expected.stderr
    program, error = _virtualize("f", "<?php " + function)
    assert program is not None, error
    actual = php(native, "-r", "echo base64_encode(serialize(__envelock_vm(" + repr(program) + ", [])));" )
    assert actual.returncode == 0 and actual.stdout == expected.stdout, (expression, actual.stdout, expected.stdout)


@pytest.mark.parametrize("operator", ["<=", ">="])
def test_vm_nan_comparisons_match_php(native, operator):
    function = f"function f($x) {{ return $x {operator} 1; }}"
    expected = subprocess.run(["php", "-n", "-r", function + " echo json_encode(f(NAN));"],
                               text=True, capture_output=True, check=False)
    assert expected.returncode == 0 and expected.stdout == "false"
    program, error = _virtualize("f", "<?php " + function)
    assert program is not None, error
    actual = php(native, "-r", "echo json_encode(__envelock_vm(" + repr(program) + ", [NAN]));")
    assert actual.returncode == 0 and actual.stdout == expected.stdout, (operator, actual.stdout, actual.stderr)


@pytest.mark.parametrize("variable", ["$_SERVER", "$_GET", "$_POST", "$_COOKIE", "$_FILES", "$_ENV", "$_REQUEST", "$_SESSION", "$GLOBALS", "$this"])
def test_vm_refuses_superglobals_and_this(variable):
    program, error = _virtualize("f", f"<?php function f(){{return {variable};}}")
    assert program is None and "outside the virtualized subset" in error, (variable, program, error)


def test_vm_refuses_void_return_type_before_publishing(native, tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.php").write_text("<?php function f(): void { return; } f();")
    destination = tmp_path / "packed"
    with pytest.raises(ValueError, match="void|return type"):
        a.pack_tree(src, destination, [a.recipient_public(native[3])], native[2], str(uuid.uuid4()),
                    virtualize=["f"], virtualize_loader=native[1], unsafe_vm_laboratory=True)
    assert not destination.exists()


@pytest.mark.parametrize("source", [
    "<?php namespace A; function f(){return 1;}",
    "<?php class A { public function f(){return 1;} }",
    "<?php if (true) { function f(){return 1;} }",
], ids=["namespace", "method", "conditional-function"])
def test_vm_rejects_non_top_level_global_functions(source):
    program, error = _virtualize("f", source)
    assert program is None, (source, program, error)


def test_vm_ignores_fake_function_inside_comment_and_virtualizes_real_one(native, tmp_path):
    source = ("<?php /* function f(){return 7;} */ "
              "function f(){return 42;} echo f();")
    out = package(native, tmp_path, {"index.php": source}, virtualize=["f"])
    actual = php(native, out / "index.php")
    assert actual.returncode == 0 and actual.stdout == "42", actual.stderr
    clear = a.open_protected((out / "index.php").read_bytes(), a.make_identity(native[3], native[2]))
    assert b"function f(){return 42;}" not in clear, clear
    assert clear.count(b"__envelock_vm_v2(") == 1, clear


def test_vm_pack_keeps_php_files_without_marked_functions(native, tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.php").write_text("<?php function f(){return 42;} require __DIR__.'/other.php'; echo f();")
    (src / "other.php").write_text("<?php echo 'other:';")
    out = tmp_path / "packed"
    a.pack_tree(src, out, [a.recipient_public(native[3])], native[2], str(uuid.uuid4()),
                virtualize=["f"], virtualize_loader=native[1], unsafe_vm_laboratory=True)
    assert (out / "other.php").exists(), "the VM pass dropped an unmarked PHP file"
    actual = php(native, out / "main.php")
    assert actual.returncode == 0 and actual.stdout == "other:42", actual.stderr


def test_vm_negative_float_zero_matches_php(native):
    function = "function f($x) { return -$x; }"
    expected = subprocess.run(["php", "-n", "-r", function + " echo serialize(f(0.0));"],
                               capture_output=True, text=True, check=False)
    assert expected.returncode == 0 and expected.stdout == "d:-0;"
    program, error = _virtualize("f", "<?php " + function)
    assert program is not None, error
    actual = php(native, "-r", "echo serialize(__envelock_vm(" + repr(program) + ", [0.0]));")
    assert actual.returncode == 0 and actual.stdout == expected.stdout


@pytest.mark.parametrize("loader", [None, "prebuilt", "missing"])
def test_vm_pack_requires_a_verified_v2_loader_and_rejects_atomically(native, tmp_path, loader):
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.php").write_text("<?php function f(){return 1;} echo f();")
    destination = tmp_path / "packed"
    selected = (ROOT / "prebuilt/loader/linux-x86_64/php-8.4-nts/envelock.so" if loader == "prebuilt"
                else tmp_path / "missing.so" if loader == "missing" else None)
    with pytest.raises(ValueError, match="virtualize.*loader|loader.*virtualize"):
        a.pack_tree(src, destination, [a.recipient_public(native[3])], native[2], str(uuid.uuid4()),
                    virtualize=["f"], virtualize_loader=selected, unsafe_vm_laboratory=True)
    assert not destination.exists()


def test_vm_v2_program_refuses_legacy_prebuilt_loader(native):
    legacy = ROOT / "prebuilt/loader/linux-x86_64/php-8.4-nts/envelock.so"
    program, error = _virtualize("f", "<?php function f(){return 1;}")
    assert program is not None, error
    assert base64.b64decode(program).startswith(b"ENVVM3")
    run = subprocess.run(["php", "-n", "-d", f"extension={legacy}", "-d", "display_errors=stderr",
                          "-r", "__envelock_vm(" + repr(program) + ", []);"],
                         capture_output=True, text=True, check=False)
    assert run.returncode != 0, "a legacy loader must never silently execute a v2 VM program"


def test_vm_v2_entrypoint_exists_in_rebuilt_loader(native):
    run = php(native, "-r", 'echo function_exists("__envelock_vm_v2") ? "yes" : "no";')
    assert run.returncode == 0 and run.stdout == "yes", run.stderr


@pytest.mark.parametrize("mode", ["tokens", "ast", "allowlist"])
def test_vm_and_name_obfuscation_cannot_hide_original_names(native, tmp_path, mode):
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.php").write_text("<?php function marker(){return 'helper';} function helper(){return 42;} echo marker();")
    kwargs = {"obfuscate_names": True}
    if mode != "tokens":
        kwargs["obfuscate_names_ast"] = True
    if mode == "allowlist":
        kwargs["obfuscate_names_allowlist"] = ["function:helper"]
    destination = tmp_path / "packed"
    with pytest.raises(ValueError, match="virtualiz.*name|name.*virtualiz"):
        a.pack_tree(src, destination, [a.recipient_public(native[3])], native[2], str(uuid.uuid4()),
                    virtualize=["marker"], **kwargs)
    assert not destination.exists()


@pytest.mark.parametrize("mode", ["tokens", "ast", "allowlist"])
def test_vm_names_callback_hidden_in_blob_never_breaks_runtime(native, tmp_path, mode):
    source = ("<?php function marker(){return 'helper';} "
              "function helper(){echo 'OK';return true;} "
              "iterator_apply(new ArrayIterator([1]), marker());")
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.php").write_text(source)
    baseline = subprocess.run(["php", "-n", str(src / "main.php")], text=True, capture_output=True, check=False)
    assert baseline.returncode == 0 and baseline.stdout == "OK", baseline.stderr
    options = {"obfuscate_names": True, "obfuscate_names_ast": mode != "tokens"}
    if mode == "allowlist":
        options["obfuscate_names_allowlist"] = ["function:helper"]
    dest = tmp_path / "packed"
    try:
        a.pack_tree(src, dest, [a.recipient_public(native[3])], native[2], str(uuid.uuid4()),
                    virtualize=["marker"], **options)
    except ValueError as error:
        assert "virtualiz" in str(error) and "name" in str(error)
        assert not dest.exists()
        return
    actual = php(native, dest / "main.php")
    assert actual.returncode == 0 and actual.stdout == baseline.stdout, (actual.stderr, actual.stdout)


@pytest.mark.parametrize("mode", ["tokens", "ast", "allowlist"])
def test_names_alone_refuses_unlisted_callback_builtin(native, tmp_path, mode):
    source = ("<?php function helper(){echo 'OK';return true;} "
              "iterator_apply(new ArrayIterator([1]), 'hel'.'per');")
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.php").write_text(source)
    baseline = subprocess.run(["php", "-n", str(src / "main.php")], text=True, capture_output=True, check=False)
    assert baseline.returncode == 0 and baseline.stdout == "OK", baseline.stderr
    options = {"obfuscate_names": True, "obfuscate_names_ast": mode != "tokens"}
    if mode == "allowlist":
        options["obfuscate_names_allowlist"] = ["function:helper"]
    dest = tmp_path / "packed"
    try:
        a.pack_tree(src, dest, [a.recipient_public(native[3])], native[2], str(uuid.uuid4()), **options)
    except ValueError as error:
        assert mode == "allowlist" and "name allowlist refused" in str(error)
        assert not dest.exists()
        return
    actual = php(native, dest / "main.php")
    assert actual.returncode == 0 and actual.stdout == baseline.stdout, (actual.stderr, actual.stdout)


def test_vm_uninitialized_variable_does_not_suppress_php_warning(native):
    function = "function f($flag) { if ($flag) { $x=5; } return $x; }"
    original = subprocess.run(["php", "-n", "-d", "display_errors=stderr", "-r",
                               function + " set_error_handler(function($n,$s){throw new ErrorException($s);}); "
                               "try { f(false); echo 'no-warning'; } catch (ErrorException $e) { echo $e->getMessage(); }"],
                              text=True, capture_output=True, check=False)
    assert original.returncode == 0 and original.stdout == "Undefined variable $x"
    program, error = _virtualize("f", "<?php " + function)
    if program is None:  # conservative refusal is acceptable; silently omitting the warning is not
        assert "outside the virtualized subset" in error
        return
    vm = php(native, "-r", "set_error_handler(function($n,$s){throw new ErrorException($s);}); "
             + "try { __envelock_vm_v2(" + repr(program) + ", [false]); echo 'no-warning'; } "
             + "catch (ErrorException $e) { echo $e->getMessage(); }")
    assert vm.returncode == 0 and vm.stdout == original.stdout, (vm.stderr, vm.stdout)


def test_vm_missing_array_key_does_not_suppress_php_warning(native):
    function = "function f($a) { return $a[2]; }"
    original = subprocess.run(["php", "-n", "-d", "display_errors=stderr", "-r",
                               function + " set_error_handler(function($n,$s){throw new ErrorException($s);}); "
                               "try { f([]); echo 'no-warning'; } catch (ErrorException $e) { echo $e->getMessage(); }"],
                              text=True, capture_output=True, check=False)
    assert original.returncode == 0 and original.stdout == "Undefined array key 2"
    program, error = _virtualize("f", "<?php " + function)
    if program is None:
        assert "outside the virtualized subset" in error
        return
    vm = php(native, "-r", "set_error_handler(function($n,$s){throw new ErrorException($s);}); "
             + "try { __envelock_vm_v2(" + repr(program) + ", [[]]); echo 'no-warning'; } "
             + "catch (ErrorException $e) { echo $e->getMessage(); }")
    assert vm.returncode == 0 and vm.stdout == original.stdout, (vm.stderr, vm.stdout)


@pytest.mark.parametrize("opcode", [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0F, 0x10, 0x11])
def test_vm_rejects_truncated_instruction_before_reading_operand(native, opcode):
    blob = b"ENVVM3" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x01" + bytes([opcode])
    run = php(native, "-r", "__envelock_vm_v2(" + repr(base64.b64encode(blob).decode()) + ", []);")
    assert run.returncode != 0 and "truncated instruction" in run.stderr.lower(), (opcode, run.returncode, run.stderr)


@pytest.mark.parametrize("code,expected", [
    (b"\x15\x01\x00\x07", "unknown kind"),            # one key whose kind byte is not 0 or 1
    (b"\x15\x02\x00\x00", "truncated instruction"),   # two keys announced, one entry present
    (b"\x15\x00\x00", "malformed"),                     # zero keys is not a dimension fetch
    (b"\x15\x01\x02\x00", "malformed"),                # flags beyond bit 0 are unknown
])
def test_vm_rejects_malformed_dimension_fetch_descriptor(native, code, expected):
    blob = b"ENVVM3" + b"\x00\x00\x00\x00" + len(code).to_bytes(4, "big") + code
    run = php(native, "-r", "__envelock_vm_v2(" + repr(base64.b64encode(blob).decode()) + ", []);")
    assert run.returncode != 0 and expected in run.stderr.lower(), (code, run.returncode, run.stderr)


def test_vm_rejects_constant_index_past_pool(native):
    code = b"\x01\x00\x00\x09"
    blob = b"ENVVM3" + b"\x00\x00\x00\x00" + len(code).to_bytes(4, "big") + code
    run = php(native, "-r", "__envelock_vm_v2(" + repr(base64.b64encode(blob).decode()) + ", []);")
    assert run.returncode != 0 and "constant" in run.stderr.lower(), (run.returncode, run.stdout, run.stderr)


@pytest.mark.parametrize("expression,args", [
    ("$a + ($a=5)", [1]),
    ("$a . ($a=5)", ["x"]),
    ("$a - ($a=5)", [1]),
    ("$a == ($a=5)", [1]),
    ("$a + ($b=5) + $b", [1, 2]),
])
def test_vm_mixed_reads_and_assignments_never_silently_diverge(native, expression, args):
    """PHP may defer loading a variable until another operand has assigned it."""
    function = "function f($a,$b=2) { return " + expression + "; }"
    # Defaults are refused by the VM; use only required parameters in the tested source.
    function = function.replace("$b=2", "$b")
    if len(args) == 1:
        args.append(2)
    expected = subprocess.run(["php", "-n", "-r", function + " echo json_encode(f(...json_decode($argv[1], true)));",
                              json.dumps(args)], text=True, capture_output=True, check=False)
    assert expected.returncode == 0, expected.stderr
    program, error = _virtualize("f", "<?php " + function)
    assert program is not None, error
    actual = php(native, "-r", "echo json_encode(__envelock_vm_v2(" + repr(program)
                 + ", json_decode(" + repr(json.dumps(args)) + ", true)));")
    assert actual.returncode == 0 and actual.stdout == expected.stdout, (expression, expected.stdout, actual.stdout)


def test_vm_constant_count_never_wraps_the_u16_header():
    # One reserved constant plus 65,535 distinct numeric literals cannot fit in the u16 count.
    literals = ";".join(map(str, range(65535)))
    program, error = _virtualize("f", "<?php function f(){" + literals + ";}")
    assert program is None and "too many constants" in error, (error, None if program is None else len(program))


def test_vm_local_count_never_wraps_the_u16_header():
    variables = ";".join(f"$v{i}" for i in range(65536))
    program, error = _virtualize("f", "<?php function f(){" + variables + ";}")
    assert program is None and "too many locals" in error, error


def test_vm_refuses_array_larger_than_interpreter_stack(native):
    function = "function f(){return [" + ",".join(["0"] * 4097) + "]; }"
    program, error = _virtualize("f", "<?php " + function)
    if program is None:
        assert "array" in error and "outside the virtualized subset" in error
        return
    run = php(native, "-r", "echo count(__envelock_vm_v2(" + repr(program) + ", []));")
    assert run.returncode == 0 and run.stdout == "4097", run.stderr


def test_vm_pack_is_quarantined_without_explicit_laboratory_override(native, tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.php").write_text("<?php function f($a){return $a+1;} echo f(1);")
    destination = tmp_path / "packed"
    with pytest.raises(ValueError, match="virtualiz.*laborator|virtualiz.*quarantin"):
        a.pack_tree(src, destination, [a.recipient_public(native[3])], native[2], str(uuid.uuid4()),
                    virtualize=["f"], virtualize_loader=native[1])
    assert not destination.exists()


def test_vm_undefined_variable_warning_yields_to_operation_exception(native):
    function = "function f(){return 0/$undef;}"
    capture = ("set_error_handler(function($n,$s){throw new ErrorException($s);}); "
               "try { CALL; echo 'no error'; } catch (Throwable $e) { echo get_class($e),':',$e->getMessage(); }")
    expected = subprocess.run(["php", "-n", "-r", function + capture.replace("CALL", "f()")],
                              text=True, capture_output=True, check=False)
    assert expected.returncode == 0 and expected.stdout.startswith("DivisionByZeroError:")
    program, error = _virtualize("f", "<?php " + function)
    assert program is not None, error
    actual = php(native, "-r", capture.replace("CALL", "__envelock_vm_v2(" + repr(program) + ", [])"))
    assert actual.returncode == 0 and actual.stdout == expected.stdout


def test_vm_commutative_typeerror_message_matches_php(native):
    function = "function f($x){return 0 | $x;}"
    capture = "try { CALL; } catch (Throwable $e) { echo get_class($e),':',$e->getMessage(); }"
    expected = subprocess.run(["php", "-n", "-r", function + capture.replace("CALL", "f('x')")],
                              text=True, capture_output=True, check=False)
    assert expected.returncode == 0 and "string | int" in expected.stdout
    program, error = _virtualize("f", "<?php " + function)
    assert program is not None, error
    actual = php(native, "-r", capture.replace("CALL", "__envelock_vm_v2(" + repr(program) + ", ['x'])"))
    assert actual.returncode == 0 and actual.stdout == expected.stdout


def test_vm_known_dimension_evaluation_order(native):
    function = "function f($a,$b){return ($a[$b])[(0)[1]];}"
    capture = ("set_error_handler(function($n,$s){throw new ErrorException($s);}); "
               "try { CALL; } catch (Throwable $e) { echo get_class($e),':',$e->getMessage(); }")
    expected = subprocess.run(["php", "-n", "-r", function + capture.replace("CALL", "f('hello',1.5)")],
                              text=True, capture_output=True, check=False)
    # PHP 8.3 shortened the wording ("...on value of type int" in 8.2).
    assert expected.returncode == 0 and ("offset on int" in expected.stdout
                                         or "offset on value of type int" in expected.stdout)
    program, error = _virtualize("f", "<?php " + function)
    assert program is not None, error
    actual = php(native, "-r", capture.replace("CALL", "__envelock_vm_v2(" + repr(program) + ", ['hello',1.5])"))
    assert actual.returncode == 0 and actual.stdout == expected.stdout


@pytest.mark.parametrize("laboratory", [False, True], ids=["quarantined", "explicit-lab"])
def test_vm_cli_quarantine_and_explicit_laboratory_warning(native, tmp_path, laboratory):
    src, out = tmp_path / "src", tmp_path / "packed"
    src.mkdir()
    (src / "main.php").write_text("<?php function f($x){return $x+2;} echo f(40);")
    owner, recipient = tmp_path / "owner.json", tmp_path / "recipient.json"
    owner.write_text(json.dumps(native[2]))
    recipient.write_text(json.dumps(a.recipient_public(native[3])))
    command = [sys.executable, str(ROOT / "encoder/envelock.py"), "pack", "--source", str(src),
               "--output", str(out), "--owner", str(owner), "--recipient", str(recipient),
               "--project", str(uuid.uuid4()), "--virtualize", "f", "--virtualize-loader", str(native[1])]
    if laboratory:
        command.append("--unsafe-vm-laboratory")
    run = subprocess.run(command, text=True, capture_output=True, check=False, timeout=60)
    if not laboratory:
        assert run.returncode != 0 and "quarantined" in run.stderr and not out.exists()
    else:
        assert run.returncode == 0 and "WARNING" in run.stderr and "laboratory" in run.stderr, run.stderr
        info = json.loads(run.stdout)
        assert info["unsafe_vm_laboratory"] is True and info["vm_program_version"] == 3
        actual = php(native, out / "main.php")
        assert actual.returncode == 0 and actual.stdout == "42", actual.stderr


def test_rebuilt_loader_rejects_legacy_v1_vm_programs(native):
    program, error = _virtualize("f", "<?php function f(){return 42;}")
    assert program is not None, error
    blob = base64.b64decode(program)
    legacy = base64.b64encode(b"ENVVM1" + blob[6:]).decode()
    actual = php(native, "-r", "echo __envelock_vm(" + repr(legacy) + ", []);")
    assert actual.returncode != 0 and "legacy" in actual.stderr.lower(), (actual.returncode, actual.stdout, actual.stderr)


def test_vm_rejects_jump_into_an_operand_boundary(native):
    # The jump at byte 0 targets byte 2, the middle of its own four-byte operand.
    code = b"\x06" + (-3).to_bytes(4, "big", signed=True) + b"\x0e"
    blob = b"ENVVM3" + b"\x00\x00\x00\x00" + len(code).to_bytes(4, "big") + code
    actual = php(native, "-r", "__envelock_vm_v2(" + repr(base64.b64encode(blob).decode()) + ", []);")
    assert actual.returncode != 0 and "instruction boundary" in actual.stderr.lower(), actual.stderr


def test_vm_rejects_truncated_unreachable_instruction(native):
    # A malformed trailer must not be accepted merely because an earlier RETURN happens to skip it.
    code = b"\x0e\x01"
    blob = b"ENVVM3" + b"\x00\x00\x00\x00" + len(code).to_bytes(4, "big") + code
    actual = php(native, "-r", "__envelock_vm_v2(" + repr(base64.b64encode(blob).decode()) + ", []);")
    assert actual.returncode != 0 and "truncated instruction" in actual.stderr.lower(), actual.stderr


def test_vm_stack_overflow_releases_rejected_value(native, tmp_path):
    """A rejected owned string must not leak on every caught stack overflow."""
    payload = b'x' * 50_000
    pool = b'\x00' + b'\x04' + len(payload).to_bytes(3, 'big') + payload
    code = b'\x01\x00\x00' * 4096 + b'\x01\x00\x01' + b'\x0e'
    blob = b'ENVVM3' + (2).to_bytes(2, 'big') + b'\x00\x00' + pool + len(code).to_bytes(4, 'big') + code
    program = base64.b64encode(blob).decode()
    script = ("$p=" + repr(program) + "; $before=memory_get_usage(); "
              "for($i=0;$i<12;$i++){try{__envelock_vm_v2($p,[]);}catch(Throwable $e){"
              "if(!str_contains($e->getMessage(),'ran out of stack')) throw $e;}} "
              "echo memory_get_usage()-$before;")
    # From a file, not -r: the ~67 KB program exceeds Windows' 32,767-character command line.
    script_file = tmp_path / "vm.php"
    script_file.write_text("<?php " + script, encoding="utf-8")
    run = php(native, script_file)
    assert run.returncode == 0, run.stderr
    assert int(run.stdout) < 200_000, run.stdout


@pytest.mark.parametrize('pool', [b'\x01', b'\x02\x00', b'\x03\x00', b'\x04\x00\x00',
                                  b'\x04\x00\x00\x10short'])
def test_vm_rejects_truncated_constant_payload(native, pool):
    blob = b'ENVVM3' + b'\x00\x01\x00\x00' + pool
    run = php(native, '-r', '__envelock_vm_v2(' + repr(base64.b64encode(blob).decode()) + ', []);')
    assert run.returncode != 0 and ('constant' in run.stderr.lower()), run.stderr


@pytest.mark.parametrize('outer_count,accepted', [(4094, True), (4095, False)])
def test_vm_nested_array_respects_total_stack_limit(native, outer_count, accepted):
    # The inner list is evaluated while all previous outer elements remain on the stack.
    source = '<?php function f(){return [' + ','.join(['0'] * outer_count + ['[1,2]']) + '];}'
    program, error = _virtualize('f', source)
    if not accepted:
        assert program is None and 'stack' in error.lower(), error
        return
    assert program is not None, error
    run = php(native, '-r', 'echo count(__envelock_vm_v2(' + repr(program) + ', []));')
    assert run.returncode == 0 and run.stdout == str(outer_count + 1), run.stderr


@pytest.mark.parametrize('expression', ['$a ? [1,2] : 0', '$a && [1,2]', '$a || [1,2]'])
def test_vm_stack_analysis_examines_each_conditional_path(native, expression):
    source = ('<?php function f($a){return [' + ','.join(['0'] * 4095 + ['(' + expression + ')']) + '];}')
    program, error = _virtualize('f', source)
    assert program is None and 'stack' in error.lower(), error


def test_vm_oversized_nested_stack_refuses_pack_atomically(native, tmp_path):
    source = tmp_path / 'src'
    source.mkdir()
    (source / 'index.php').write_text(
        '<?php function f(){return [' + ','.join(['0'] * 4095 + ['[1,2]']) + '];}')
    destination = tmp_path / 'out'
    with pytest.raises(ValueError, match='stack'):
        a.pack_tree(source, destination, [a.recipient_public(native[3])], native[2], str(uuid.uuid4()),
                    virtualize=['f'], virtualize_loader=native[1], unsafe_vm_laboratory=True)
    assert not destination.exists()


@pytest.mark.parametrize(('code', 'expected'), [
    (b'\x0c\x0e', 'underflow'),
    (b'\x01\x00\x00\x07\x00\x00\x00\x03\x01\x00\x00\x0e', 'inconsistent stack depth'),
    (b'\x01\x00\x00\x06\xff\xff\xff\xf8', 'inconsistent stack depth'),
    (b'\x06\xff\xff\xff\xfc\x0e', 'outside an instruction'),
    (b'\x01\x00', 'truncated instruction'),
    (b'\xff', 'invalid or truncated instruction'),
])
def test_vm_compiler_stack_analyzer_rejects_invalid_internal_code(code, expected):
    """Defend against accidental emitter bugs, not only currently reachable PHP syntax."""
    path = ROOT / 'encoder' / 'virtualize.php'
    script = ("function envelock_fail($s){throw new Exception($s);} "
              "$s=file_get_contents(" + json.dumps(str(path)) + "); "
              "$a=strpos($s,'final class VmProgram'); $b=strpos($s,'/* Operator tables', $a); "
              "eval(substr($s,$a,$b-$a)); $p=new VmProgram(); $p->code=base64_decode("
              + repr(base64.b64encode(code).decode()) + "); "
              "try {$p->bytes(); echo 'accepted';} catch (Throwable $e) {echo $e->getMessage();}")
    run = subprocess.run(['php', '-n', '-r', script], capture_output=True, text=True, check=False, timeout=30)
    assert run.returncode == 0 and expected in run.stdout.lower(), (run.stdout, run.stderr)


@pytest.mark.parametrize(('body', 'inputs'), [
    ('if($x){return 10;} else {return 20;}', [False, True]),
    ('if($x===1){return 10;} elseif($x===2){return 20;} else {return 30;}', [1, 2, 3]),
    ('if($x===1){return 10;} elseif($x===2){return 20;} return 30;', [1, 2, 3]),
    ('$n=0; while($n<3){if($n===$x){return 10;} else {$n=$n+1;}} return 20;', [0, 1, 2, 3]),
    ('if($x){if($x===2){return 10;} else{return 20;}} else{return 30;}', [0, 1, 2]),
])
def test_vm_if_elseif_else_matches_all_php_branches(native, body, inputs):
    function = 'function f($x){' + body + '}'
    program, error = _virtualize('f', '<?php ' + function)
    assert program is not None, error
    for value in inputs:
        parameter = json.dumps([value])
        original = subprocess.run(['php', '-n', '-r', function + 'echo json_encode(f(...json_decode($argv[1],true)));',
                                   parameter], text=True, capture_output=True, check=False, timeout=30)
        try:
            virtual = php(native, '-r', 'echo json_encode(__envelock_vm_v2(' + repr(program)
                          + ', json_decode(' + repr(parameter) + ',true)));', timeout=3)
        except subprocess.TimeoutExpired:
            pytest.fail(f'virtualized branch failed to terminate: {body!r}, input={value!r}')
        assert original.returncode == virtual.returncode == 0, (body, value, original.stderr, virtual.stderr)
        assert original.stdout == virtual.stdout, (body, value, original.stdout, virtual.stdout)


def test_vm_if_else_survives_research_pack_end_to_end(native, tmp_path):
    source = ('<?php function decision($x){if($x>0){return 10;}else{return 20;}} '
              'echo decision(1),"|",decision(0);')
    out = package(native, tmp_path, {'index.php': source}, virtualize=['decision'])
    result = php(native, out / 'index.php', timeout=10)
    assert result.returncode == 0 and result.stdout == '10|20', result.stderr


def test_vm_compiler_change_aborts_pack_before_publication(native, tmp_path, monkeypatch):
    source = tmp_path / 'src'
    source.mkdir()
    (source / 'index.php').write_text('<?php function f(){return 1;}')
    compiler = tmp_path / 'compiler.php'
    compiler.write_bytes(b'first compiler')
    monkeypatch.setattr(a, '_virtualize_php_path', lambda: compiler)

    def changed(files, names, php='php'):
        compiler.write_bytes(b'second compiler')
        return files, {names[0]: 'laboratory-placeholder'}

    monkeypatch.setattr(a, 'virtualize_sources', changed)
    destination = tmp_path / 'out'
    with pytest.raises(ValueError, match='compiler changed'):
        a.pack_tree(source, destination, [a.recipient_public(native[3])], native[2], str(uuid.uuid4()),
                    virtualize=['f'], virtualize_loader=native[1], unsafe_vm_laboratory=True)
    assert not destination.exists()


def test_non_vm_package_does_not_claim_vm_compiler(native, tmp_path):
    out = package(native, tmp_path, {'index.php': '<?php echo 1;'})
    info = json.loads((out / 'envelock-package.json').read_text())
    assert info['vm_program_version'] is None and info['vm_compiler_sha256'] is None


@pytest.mark.parametrize('op', ['*', '&', '|', '^'])
@pytest.mark.parametrize('literal', ['0', '1.5', "'abc'"])
@pytest.mark.parametrize('value', ["'x'", '[1]', 'new stdClass', '2.5', '-0.0', 'NAN', 'INF',
                                   'null', 'true', '-2', "'12'"])
def test_vm_commutative_literal_left_matches_php_errors_and_values(native, op, literal, value):
    function = f'function f($x){{return {literal} {op} $x;}}'
    capture = ("set_error_handler(function($n,$s){throw new ErrorException($s);}); "
               "try {echo 'value:',base64_encode(serialize(CALL));} "
               "catch(Throwable $e){echo 'error:',get_class($e),':',$e->getMessage();}")
    program, error = _virtualize('f', '<?php ' + function)
    assert program is not None, error
    expected = subprocess.run(['php', '-n', '-r', function + capture.replace('CALL', f'f({value})')],
                              capture_output=True, text=True, check=False, timeout=30)
    actual = php(native, '-r', capture.replace('CALL', f'__envelock_vm_v2({program!r}, [{value}])'), timeout=10)
    assert expected.returncode == actual.returncode == 0, (expected.stderr, actual.stderr)
    assert expected.stdout == actual.stdout, (function, value, expected.stdout, actual.stdout)


@pytest.mark.parametrize('op', ['&', '|', '^'])
@pytest.mark.parametrize('left', ['"a"', '("a" ? "a" : 0)', '("a" . $a)', '$c[0]', '(true ? "a" : $a)', '$b',
                                  '"abc"[0]', '["x"][0]', '("ab")[1]'])
@pytest.mark.parametrize('right', ['$a', '(2+$a)', '$c[0]', '1'])
def test_vm_bitwise_operand_order_matches_php(native, op, left, right):
    """Zend swaps a bitwise operand pair in TypeError messages only when the left one is a constant,
    or when it is a temporary or VAR and the right one is a plain CV. A ternary is not a constant."""
    body = f"$b = 'a'; $c = ['x']; return {left} {op} {right};"
    function = f'function f($a){{{body}}}'
    capture = ("set_error_handler(function($n,$s){throw new ErrorException($s);}); "
               "try {echo 'value:',base64_encode(serialize(CALL));} "
               "catch(Throwable $e){echo 'error:',get_class($e),':',$e->getMessage();}")
    program, error = _virtualize('f', '<?php ' + function)
    assert program is not None, error
    expected = subprocess.run(['php', '-n', '-r', function + capture.replace('CALL', 'f(0)')],
                              capture_output=True, text=True, check=False, timeout=30)
    actual = php(native, '-r', capture.replace('CALL', f'__envelock_vm_v2({program!r}, [0])'), timeout=10)
    assert expected.returncode == actual.returncode == 0, (expected.stderr, actual.stderr)
    assert expected.stdout == actual.stdout, (function, expected.stdout, actual.stdout)


@pytest.mark.parametrize("op", ["|", "&", "^", "*"])
@pytest.mark.parametrize("right", ["$a", "(2+$a)", "(array)('x')", "(false % 1)", "(1 ? 2 : 3)", "$c[0]", "(!$a)"])
@pytest.mark.parametrize("left", ["'a'", "(string)('x')", "(false % 1)", "(1 ? 'a' : 0)", "(true && 'a')",
                                  "(!0)", "(~'a')", "('a' . 'b')", "(-1)", "[1][0]"])
def test_vm_operand_rank_matches_php_error_order(native, op, left, right):
    """Zend orders a commutative pair by operand type: CONST < TMP < CV. A cast, a ternary, a logical
    operator and a dimension read are temporaries, never constants; % and / fold when they cannot throw."""
    body = f"$c = [0]; return {left} {op} {right};"
    function = f"function f($a){{{body}}}"
    capture = ("set_error_handler(function($n,$s){throw new ErrorException($s);}); "
               "try {echo 'value:',base64_encode(serialize(CALL));} "
               "catch(Throwable $e){echo 'error:',get_class($e),':',$e->getMessage();}")
    program, error = _virtualize("f", "<?php " + function)
    assert program is not None, error
    expected = subprocess.run(["php", "-n", "-r", function + capture.replace("CALL", "f(0)")],
                              capture_output=True, text=True, check=False, timeout=30)
    actual = php(native, "-r", capture.replace("CALL", f"__envelock_vm_v2({program!r}, [0])"), timeout=10)
    assert expected.returncode == actual.returncode == 0, (expected.stderr, actual.stderr)
    assert expected.stdout == actual.stdout, (function, expected.stdout, actual.stdout)


def test_vm_call_underflow_releases_already_popped_arguments(native, tmp_path):
    """Hostile raw programs must not leak values when CALL has fewer stack items than argc."""
    payload = b'x' * 50_000
    name = b'strlen'
    pool = (b'\x04' + len(name).to_bytes(3, 'big') + name
            + b'\x04' + len(payload).to_bytes(3, 'big') + payload)
    code = b'\x01\x00\x01' * 2 + b'\x08\x00\x00\x03\x0e'
    blob = b'ENVVM3' + b'\x00\x02\x00\x00' + pool + len(code).to_bytes(4, 'big') + code
    encoded = base64.b64encode(blob).decode()
    script = ("$p=" + repr(encoded) + "; $before=memory_get_usage(); "
              "for($i=0;$i<12;$i++){try{__envelock_vm_v2($p,[]);}catch(Throwable $e){"
              "if(!str_contains($e->getMessage(),'underflowed')) throw $e;}} "
              "echo memory_get_usage()-$before;")
    # From a file, not -r: the ~67 KB program exceeds Windows' 32,767-character command line.
    script_file = tmp_path / "vm.php"
    script_file.write_text("<?php " + script, encoding="utf-8")
    run = php(native, script_file, timeout=30)
    assert run.returncode == 0, run.stderr
    assert int(run.stdout) < 200_000, run.stdout


@pytest.mark.parametrize('expression', [
    "null - '0' | $x",             # folded constant left, COMMUTATIVE swap
    "'a' ^ (2 + $x)",              # constant left, computed right
    "(1.5 ? 1000 : '0') ^ $x",     # ternary folded to a constant left
    "[1, 2] & 'x'",                # constant array literal on the left, both constant
    "'x' * ($x ? true : -3)",      # right block contains a jump
    "-0.0 | ($x ? 'a' : 1)",       # signed constant left with jump on the right
])
@pytest.mark.parametrize('value', ["'x'", '9', '0', '[1]', "'12'"])
def test_vm_commutative_folded_operands_match_php(native, expression, value):
    function = 'function f($x){return ' + expression + ';}'
    capture = ("set_error_handler(function($n,$s){throw new ErrorException($s);}); "
               "try {echo 'value:',base64_encode(serialize(CALL));} "
               "catch(Throwable $e){echo 'error:',get_class($e),':',$e->getMessage();}")
    program, error = _virtualize('f', '<?php ' + function)
    assert program is not None, error
    expected = subprocess.run(['php', '-n', '-r', function + capture.replace('CALL', f'f({value})')],
                              capture_output=True, text=True, check=False, timeout=30)
    actual = php(native, '-r', capture.replace('CALL', f'__envelock_vm_v2({program!r}, [{value}])'), timeout=10)
    assert expected.returncode == actual.returncode == 0, (expected.stderr, actual.stderr)
    assert expected.stdout == actual.stdout, (function, value, expected.stdout, actual.stdout)


def _undefined_operand_cases():
    for operator in ['+', '/', '%', '.', '&', '<<']:
        for side in ['L', 'R']:
            for other in ['0', '1', "'x'", '[1]', 'null', '-1']:
                # Concatenation with an array used to be a strict xfail here (the VM reported the undefined
                # operand first). Fixed: the array is converted where PHP converts it, so it now runs as a case.
                yield pytest.param(operator, side, other, id=f'{operator}-{side}-{other}')


@pytest.mark.parametrize('operator,side,other', list(_undefined_operand_cases()))
def test_vm_undefined_operand_matches_php_exception_chaining(native, operator, side, other):
    """A throwing error handler: the operation's own exception replaces the warning's one, and the
    warning's exception is the outcome when the operation completes. Compared with real PHP."""
    body = f'return $undef {operator} {other};' if side == 'L' else f'return {other} {operator} $undef;'
    function = 'function f(){' + body + '}'
    capture = ("set_error_handler(function($n,$s){throw new ErrorException($s);}); "
               "try { CALL; echo 'no error'; } catch (Throwable $e) { echo get_class($e),':',$e->getMessage(); }")
    expected = subprocess.run(['php', '-n', '-r', function + capture.replace('CALL', 'f()')],
                              text=True, capture_output=True, check=False, timeout=30)
    program, error = _virtualize('f', '<?php ' + function)
    assert program is not None, error
    actual = php(native, '-r', capture.replace('CALL', '__envelock_vm_v2(' + repr(program) + ', [])'), timeout=10)
    assert expected.returncode == actual.returncode == 0, (expected.stderr, actual.stderr)
    assert actual.stdout == expected.stdout, (function, expected.stdout, actual.stdout)


@pytest.mark.parametrize("source,args", [
    ("function f($a) { $a += ($a = 5); return $a; }", [1]),
    ("function f($a) { $a -= ($a = 5); return $a; }", [1]),
    ("function f($a) { $a .= ($a = 'y'); return $a; }", ["x"]),
    ("function f($a) { $i = 0; return $a[$i = 1]; }", [[7, 8]]),
    ("function f($a) { $i = 0; $r = $a[$i] + ($i = 1); return [$r, $i]; }", [[7, 8]]),
    ("function f($a) { return ($a = 3) + $a; }", [1]),
    ("function f($a) { $x = $a = 4; return [$x, $a]; }", [1]),
    ("function f($a) { return $a + ($a = $a + 1) * 2; }", [1]),
])
def test_vm_lazy_local_reads_match_php(native, source, args):
    """Zend reads a plain local operand when its operation runs, after the other side is evaluated."""
    original = subprocess.run(["php", "-n", "-r", source + " echo json_encode(f(...json_decode($argv[1], true)));",
                               json.dumps(args)], capture_output=True, text=True, check=False)
    assert original.returncode == 0, original.stderr
    program, error = _virtualize("f", "<?php " + source)
    assert program is not None, error
    ok, value, stderr = _vm_run(native, program, args)
    assert ok, stderr
    assert value == original.stdout, (source, value, original.stdout)


def test_vm_lazy_read_warning_order_matches_php_when_handler_throws(native):
    """The undefined read happens during the addition, after the right side ran."""
    function = "function f(){ return $u + ($v = 3); }"
    capture = ("set_error_handler(function($n,$s){throw new ErrorException($s);}); "
               "try { CALL; echo 'no error'; } catch (Throwable $e) { echo get_class($e),':',$e->getMessage(); }")
    expected = subprocess.run(["php", "-n", "-r", function + capture.replace("CALL", "f()")],
                              text=True, capture_output=True, check=False)
    assert expected.returncode == 0, expected.stderr
    program, error = _virtualize("f", "<?php " + function)
    assert program is not None, error
    actual = php(native, "-r", capture.replace("CALL", "__envelock_vm_v2(" + repr(program) + ", [])"))
    assert actual.returncode == 0 and actual.stdout == expected.stdout, (expected.stdout, actual.stdout)


@pytest.mark.parametrize("source,args", [
    ("function f($n,$arr){ return $n[$arr['x']][$arr['y']]; }", [1, [7, 8]]),
    ("function f($n,$arr){ return $arr[$arr['x']][0]; }", [1, [7, 8]]),
    ("function f($arr){ return $arr[1][$arr['y']]; }", [[[1, 2], [3, 4]]]),
    ("function f($arr){ return $arr[1][$arr['y']][$arr['z']]; }", [[[1, 2], [3, 4]]]),
    ("function f($arr){ return $undef[$arr['x']][$arr['y']]; }", [[1]]),
    ("function f($arr){ return $undef[$undef2]; }", [[1]]),
    ("function f($arr){ return (1)[$arr['x']][$arr['y']]; }", [[1]]),
    ("function f($arr){ return (1)[$arr['x']]; }", [[1]]),
    ("function f($arr){ $i = 0; return $arr[$i = 1][$i]; }", [[[1, 2], [3, 4]]]),
    ("function f($arr){ return $arr[(1 ? 0 : 1)][(0 ? 0 : 1)]; }", [[[1, 2], [3, 4]]]),
    # A parenthesised dimension chain is the same AST as the unparenthesised one (PHP delays it).
    ("function f($arr){ return ((false)[2])[$arr['x']]; }", [[1]]),
    ("function f($arr){ return ((1.5)[0])[$arr['y']]; }", [[1]]),
    ("function f($arr){ return (($arr)[0])[$arr['x']][$arr['y']]; }", [[[1, 2]]]),
    ("function f($arr){ return ($arr[1])[$arr['x']]; }", [[[1, 2]]]),
    ("function f($arr){ return ((\"abc\")[0])[$arr['x']]; }", [[1]]),
    ("function f($arr){ return (('x')[1])[$undef]; }", [[1]]),
    ("function f($arr){ return $arr[$undef][$arr['x']]; }", [[1]]),
    ("function f($arr){ $k = 0; return $arr[$k][$k = 1]; }", [[[1, 2], [3, 4]]]),
    ("function f($a,$b){ return ((((($b)[-0.0])[(0 <= 0123)])[((0.0 % 0o17))[((string)('12'))]])); }", [0.0, -0.0]),
    ("function f($arr){ return (($arr)[0])[$arr['x']]; }", [[[1]]]),
])
def test_vm_dimension_chains_match_php_warning_order(native, source, args):
    """Zend evaluates every key of B[K1][K2]... before the fetches; an undefined base warns at its
    fetch. The full ordered event log of a non-throwing handler is compared with PHP."""
    capture = ("$log=[]; set_error_handler(function($n,$s) use (&$log){ $log[] = $s; return true; }); "
               "try { $v = CALL; $log[] = 'VALUE:' . json_encode($v); } "
               "catch (Throwable $e) { $log[] = get_class($e) . ':' . $e->getMessage(); } "
               "echo json_encode($log);")
    expected = subprocess.run(["php", "-n", "-r", source + " " + capture.replace("CALL", "f(...json_decode($argv[1], true))"),
                               json.dumps(args)], text=True, capture_output=True, check=False)
    assert expected.returncode == 0, expected.stderr
    program, error = _virtualize("f", "<?php " + source)
    assert program is not None, error
    actual = php(native, "-r", capture.replace("CALL", "__envelock_vm_v2(" + repr(program) + ", " + json.dumps(args) + ")"),
                 timeout=10)
    assert actual.returncode == 0, actual.stderr
    assert actual.stdout == expected.stdout, (source, expected.stdout, actual.stdout)


def test_plain_app_with_flattened_functions_matches_unprotected_php(native, tmp_path):
    """O6 criterion, app without a framework: a multi-file application packed with --obfuscate-flatten
    (plus the default bytecode path) prints the same as the unprotected sources. A generator and a
    function that calls compact() are left as written, and the app still runs them."""
    files = {
        "index.php": ("<?php\n"
                      "require __DIR__ . '/lib/Cart.php';\n"
                      "require __DIR__ . '/lib/helpers.php';\n"
                      "$cart = new Cart();\n"
                      "foreach ([3, 8, 15] as $qty) { $cart->add($qty); }\n"
                      "echo $cart->report(), '|', total_label(40), '|', implode(',', iterator_to_array(iter_squares(4))), \"\\n\";\n"),
        "lib/Cart.php": ("<?php\n"
                         "class Cart {\n"
                         "    private array $lines = [];\n"
                         "    public function add(int $qty): void {\n"
                         "        if ($qty <= 0) { return; }\n"
                         "        $this->lines[] = $qty * 2;\n"
                         "    }\n"
                         "    public function report(): string {\n"
                         "        $sum = 0;\n"
                         "        foreach ($this->lines as $line) { $sum += $line; }\n"
                         "        try { if ($sum > 40) { throw new RuntimeException('big:' . $sum); } }\n"
                         "        catch (RuntimeException $e) { return $e->getMessage() . '@' . $e->getLine(); }\n"
                         "        return 'sum=' . $sum;\n"
                         "    }\n"
                         "}\n"),
        "lib/helpers.php": ("<?php\n"
                            "function total_label($n) {\n"
                            "    $label = 'total';\n"
                            "    $n = $n + 2;\n"
                            "    return $label . ':' . $n;\n"
                            "}\n"
                            "function iter_squares($k) { for ($i = 1; $i <= $k; $i++) { yield $i * $i; } }\n"
                            "function frame_bound($x) { $y = $x + 1; return compact('x', 'y'); }\n"
                            "echo '', json_encode(frame_bound(1)), \"\\n\";\n"),
    }
    plain = tmp_path / "plain"
    for name, data in files.items():
        (plain / name).parent.mkdir(parents=True, exist_ok=True)
        (plain / name).write_text(data)
    original = subprocess.run(["php", "-n", str(plain / "index.php")], capture_output=True, text=True,
                              cwd=plain, check=False)
    assert original.returncode == 0, original.stderr
    out = package(native, tmp_path, files, obfuscate_flatten=True, strip_comments=True, obfuscate=True)
    info = json.loads((out / "envelock-package.json").read_text())
    assert info["functions_flattened"] >= 3, info
    assert info["functions_not_flattened"].get("generator") == 1, info
    assert info["functions_not_flattened"].get("frame function") == 1, info
    protected = php(native, out / "index.php")
    assert protected.returncode == 0, protected.stderr
    assert protected.stdout == original.stdout, (protected.stdout, original.stdout)


# --- envelock.manifest_fastpath (cold-start optimisation, default ON under --enforce-manifest) ----
# The manifest already carries a trusted-signed SHA-256 of every file and is verified every request
# for enforcement, so its digests seed the per-worker verified cache and a matching file skips its
# per-file Ed25519 (measured ~5x on first compile). These tests assert it stays fail-closed —
# equivalent integrity, never a way in for altered bytes — and that it is on by default but can be
# turned off with envelock.manifest_fastpath=0.
FASTPATH_ON = ("-d", "envelock.manifest_fastpath=1")
FASTPATH_OFF = ("-d", "envelock.manifest_fastpath=0")


def test_manifest_fastpath_runs_multi_file(native, tmp_path):
    """With the fast path on, a multi-file --enforce-manifest package runs identically."""
    out = package(native, tmp_path,
                  {"index.php": "<?php require __DIR__.'/lib.php'; echo f().g();",
                   "lib.php": "<?php function f(){return 'A';} function g(){return 'B';}"},
                  enforce_manifest=True)
    result = php(native, out / "index.php", extra_ini=FASTPATH_ON)
    assert result.returncode == 0 and result.stdout == "AB", result.stderr


def test_manifest_fastpath_still_refuses_tampered_file(native, tmp_path):
    """Fail-closed: a protected container whose bytes were altered has a different SHA-256, is not in
    the seeded set, falls back to the per-file verify and is refused even with the fast path on."""
    out = package(native, tmp_path,
                  {"index.php": "<?php require __DIR__.'/lib.php'; echo 'OK';",
                   "lib.php": "<?php function f(){}"},
                  enforce_manifest=True)
    lib = out / "lib.php"
    blob = bytearray(lib.read_bytes())
    blob[-1] ^= 1                                        # flip a ciphertext byte of the container
    lib.write_bytes(blob)
    result = php(native, out / "index.php", extra_ini=FASTPATH_ON)
    assert result.returncode != 0 and "OK" not in result.stdout, result.stdout


def test_manifest_fastpath_still_refuses_untrusted_manifest(native, tmp_path):
    """Fail-closed: if the manifest signature does not verify, nothing is seeded and the request is
    refused — the fast path can never run a file the manifest did not legitimately vouch for."""
    out = package(native, tmp_path, {"index.php": "<?php echo 'OK';"}, enforce_manifest=True)
    man = out / "envelock-manifest.bin"
    blob = bytearray(man.read_bytes())
    blob[12] ^= 1                                        # corrupt a byte inside the signed region
    man.write_bytes(blob)
    result = php(native, out / "index.php", extra_ini=FASTPATH_ON)
    assert result.returncode != 0 and "not signed by the package's own developer" in result.stderr


def test_manifest_fastpath_is_on_by_default(native):
    """The fast path is now ON by default (it only acts under --enforce-manifest, whose manifest is
    verified every request anyway, so seeding adds no new trust). Regression lock on the default so
    it cannot be silently reverted."""
    got = php(native, "-r", "echo ini_get('envelock.manifest_fastpath');")
    assert got.returncode == 0, got.stderr
    assert got.stdout == "1", f"manifest_fastpath default should be 1, got {got.stdout!r}"


def test_manifest_fastpath_opt_out_matches(native, tmp_path):
    """Default (on) and an explicit opt-out (=0, the full per-file verify) produce the same result:
    the optimisation never changes behaviour, only cost."""
    out = package(native, tmp_path,
                  {"index.php": "<?php require __DIR__.'/lib.php'; echo f();",
                   "lib.php": "<?php function f(){return 'Z';}"},
                  enforce_manifest=True)
    on = php(native, out / "index.php")                       # default: fast path on
    off = php(native, out / "index.php", extra_ini=FASTPATH_OFF)
    assert off.returncode == 0 and on.returncode == 0
    assert off.stdout == on.stdout == "Z", (off.stderr, on.stderr)


# ------------------------------------------------------------------ audit regressions (Nov 2026)

def _resign_manifest(path, owner, extra_entries):
    """Append (relative path, sha256) entries to envelock-manifest.bin and re-sign it with owner."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    data = path.read_bytes()
    body = data[:-64]
    count = int.from_bytes(body[50:54], "big")
    entries = body[54:]
    for rel, digest in extra_entries:
        entries += len(rel).to_bytes(2, "big") + rel + digest
        count += 1
    body = body[:50] + count.to_bytes(4, "big") + entries
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(owner["signing_private"]))
    path.write_bytes(body + key.sign(body))


def test_manifest_fastpath_cannot_reattribute_another_developers_file(native, tmp_path):
    """A manifest entry only proves its developer HASHED some bytes. With two developers trusted on the
    server, developer B listing developer A's include-protected container in B's own signed manifest
    used to make the fast path attribute A's file to B, so B's code could load A's protected code, and
    likewise run a container signed by a key the server does not trust at all. The fast path now only
    runs with a single trusted developer, so both stay refused."""
    owner_a, owner_b, owner_c = a.make_owner(), a.make_owner(), a.make_owner()
    identity = tmp_path / "two-developers.bin"
    write_identity(identity, [a.make_identity(native[3], owner_a), a.make_identity(native[3], owner_b)])
    project = str(uuid.uuid4())
    recipients = [a.recipient_public(native[3])]
    src_a, out_a = tmp_path / "src-a", tmp_path / "app-a"
    (src_a / "lib").mkdir(parents=True)
    (src_a / "index.php").write_text('<?php require __DIR__ . "/lib/secret.php"; echo secret_fn();')
    (src_a / "lib" / "secret.php").write_text('<?php function secret_fn() { return "A-SECRET"; }')
    a.pack_tree(src_a, out_a, recipients, owner_a, project, include_protection=True)
    secret = out_a / "lib" / "secret.php"
    src_c, out_c = tmp_path / "src-c", tmp_path / "app-c"
    src_c.mkdir()
    (src_c / "c.php").write_text('<?php echo "UNTRUSTED-C-RAN";')
    a.pack_tree(src_c, out_c, recipients, owner_c, str(uuid.uuid4()))
    untrusted = out_c / "c.php"
    src_b, out_b = tmp_path / "src-b", tmp_path / "app-b"
    src_b.mkdir()
    (src_b / "b.php").write_text("<?php require " + php_literal(str(secret)) + "; echo 'B:', secret_fn(); "
                                 "require " + php_literal(str(untrusted)) + ";")
    a.pack_tree(src_b, out_b, recipients, owner_b, project, enforce_manifest=True)
    _resign_manifest(out_b / "envelock-manifest.bin", owner_b,
                     [(b"b.php", hashlib.sha256(secret.read_bytes()).digest()),
                      (b"b.php", hashlib.sha256(untrusted.read_bytes()).digest())])
    result = php(native, out_b / "b.php", identity=identity)
    assert "A-SECRET" not in result.stdout and "UNTRUSTED-C-RAN" not in result.stdout, result.stdout
    assert result.returncode != 0
    assert "include protection" in result.stderr, result.stderr


def _vm_loop_program():
    """A one-instruction infinite loop: JMP -5 (opcode 0x06, signed 32-bit relative offset)."""
    code = b"\x06" + ((-5) & 0xFFFFFFFF).to_bytes(4, "big")
    blob = b"ENVVM3" + (0).to_bytes(2, "big") + (0).to_bytes(2, "big") + len(code).to_bytes(4, "big") + code
    return base64.b64encode(blob).decode()


def test_vm_honours_max_execution_time(native):
    """The VM loop cleared the engine's interrupt flag without checking timed_out, so a virtualized
    loop swallowed max_execution_time and left the rest of the request unkillable. It must now end the
    request with the normal timeout error, and shutdown functions must still run."""
    try:  # PHP's own timer, without Envelock: some kernels (WSL1) never deliver its signal.
        subprocess.run(["php", "-n", "-d", "max_execution_time=1", "-r", "while (true) {}"],
                       capture_output=True, text=True, check=False, timeout=15)
    except subprocess.TimeoutExpired:
        pytest.skip("this kernel does not deliver PHP's max_execution_time timer (e.g. WSL1)")
    start = time.time()
    run = php(native, "-d", "max_execution_time=1", "-r",
              "register_shutdown_function(function () { echo 'SHUTDOWN-RAN'; });"
              " __envelock_vm_v2(" + repr(_vm_loop_program()) + ", []);", timeout=60)
    assert time.time() - start < 30
    assert "Maximum execution time" in run.stderr, run.stderr
    assert "SHUTDOWN-RAN" in run.stdout, run.stdout


def test_vm_entry_refuses_dynamic_calls(native):
    """The rewritten body calls the VM by its literal name; a variable-function call or
    call_user_func() would turn a one-argument dynamic-call sink in an application into "call any
    function with any arguments", so dynamic calls are refused like compact()/extract()."""
    program, error = _virtualize("f", "<?php function f($x) { return $x + 1; }")
    assert program is not None, error
    direct = php(native, "-r", "echo __envelock_vm_v2(" + repr(program) + ", [41]);")
    assert direct.returncode == 0 and direct.stdout == "42", direct.stderr
    # A name that arrives at run time is the gadget. (A LITERAL call_user_func('__envelock_vm_v2', ...)
    # is compiled by Zend into an ordinary direct call, the same as writing the call itself.)
    for call in ("$f = '__envelock_vm_v2'; echo $f(%s, [41]);",
                 "$f = '__envelock_vm_v2'; echo call_user_func($f, %s, [41]);"):
        run = php(native, "-r", call % repr(program))
        assert "42" not in run.stdout, (call, run.stdout)
        assert "dynamically" in run.stderr, (call, run.stderr)
    mapped = php(native, "-r", "var_dump(array_map('__envelock_vm_v2', [%s], [[41]]));" % repr(program))
    assert "int(42)" not in mapped.stdout, mapped.stdout


def test_vm_does_not_alias_reference_arguments(native):
    """A reference element in $args used to be copied into the program as a reference, so the value
    the VM returned aliased the caller's variable."""
    program, error = _virtualize("f", "<?php function f($v) { return [$v]; }")
    assert program is not None, error
    run = php(native, "-r", "$x = 'original'; $args = [&$x]; $r = __envelock_vm_v2(" + repr(program)
              + ", $args); $r[0] = 'changed'; echo $x;")
    assert run.returncode == 0, run.stderr
    assert run.stdout == "original", run.stdout


def test_o8_clock_state_is_never_written_through_a_hardlink(native, tmp_path):
    """The clock-state write must land only in its own file: not through a hard link to another file
    (O_NOFOLLOW does not cover hard links, and on Windows it does not exist at all)."""
    out = package(native, tmp_path, {"index.php": "<?php echo 'CLK';"})
    licence = out.parent / "licence.bin"
    licence.write_bytes(a.issue_licence(native[2], expires=int(time.time()) + 3600))
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"VICTIM-CONTENT")
    state = tmp_path / "clock-linked.state"
    try:
        os.link(victim, state)
    except OSError as error:
        pytest.skip(f"cannot create a hard link here: {error}")
    run = php(native, out / "index.php",
              extra_ini=("-d", f"envelock.licence={licence}", "-d", f"envelock.clock_state={state}"))
    assert run.returncode == 0 and run.stdout == "CLK", run.stderr
    assert victim.read_bytes() == b"VICTIM-CONTENT"
    fresh = tmp_path / "clock-fresh.state"
    run = php(native, out / "index.php",
              extra_ini=("-d", f"envelock.licence={licence}", "-d", f"envelock.clock_state={fresh}"))
    assert run.returncode == 0 and run.stdout == "CLK", run.stderr
    assert fresh.is_file() and fresh.stat().st_size > 0    # a normal path is still recorded


def test_identity_with_a_small_order_signing_key_is_refused(native, tmp_path):
    """A trusted signing key equal to a small-order point (here the identity point, y = 1) verifies
    forged signatures for every message. The encoder refuses to write one; the loader refuses to load
    a trust store containing one, whoever wrote it."""
    blob = bytearray(a.identity_bundle_bytes([a.make_identity(native[3], native[2])]))
    public = bytes.fromhex(native[2]["signing_public"])
    at = blob.find(public)
    assert at > 0
    blob[at:at + 32] = (1).to_bytes(32, "little")
    identity = tmp_path / "small-order.bin"
    fd = os.open(identity, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(bytes(blob))
    out = package(native, tmp_path, {"index.php": "<?php echo 'SMALL-ORDER-RAN';"})
    run = php(native, out / "index.php", identity=identity)
    assert "SMALL-ORDER-RAN" not in run.stdout
    assert run.returncode != 0 and "small-order" in run.stderr, run.stderr

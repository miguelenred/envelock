"""Real PHP-FPM smoke test: start php-fpm, send FastCGI requests, check the results.

Usage: python scripts/fpm_smoke.py /path/to/php-fpm /path/to/envelock.so [opcache.so|builtin]

Requires `cgi-fcgi` (package libfcgi-bin). Uses a throw-away identity in a temporary
directory that is removed afterwards. Exit code 0 only if every check passes.
"""

import os
import pwd
import re
import subprocess  # nosec B404 # test harness: runs php-fpm and cgi-fcgi with argument lists
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "encoder"))
import envelock as a  # noqa: E402


def request(sock, script):
    env = {"SCRIPT_FILENAME": str(script), "REQUEST_METHOD": "GET", "QUERY_STRING": "",
           "PATH": os.environ.get("PATH", "")}
    out = subprocess.run(["cgi-fcgi", "-bind", "-connect", str(sock)], env=env,  # nosec B603 B607
                         capture_output=True, text=True, timeout=20)
    return re.split(r"\r?\n\r?\n", out.stdout, maxsplit=1)[-1]


def serve(fpm, tmp, ini, pool_user=None, pool_lines=""):
    sock = tmp / f"fpm-{uuid.uuid4().hex[:8]}.sock"
    conf = tmp / "fpm.conf"
    conf.write_text(
        f"[global]\nerror_log = {tmp / 'fpm.log'}\ndaemonize = no\n"
        f"[www]\nlisten = {sock}\npm = static\npm.max_children = 2\n"
        + (f"user = {pool_user}\n" if pool_user else "")
        + pool_lines
        + "catch_workers_output = yes\nphp_admin_value[display_errors] = stdout\n")
    args = [fpm, "-n", "-F", "-y", str(conf)]
    if os.geteuid() == 0 and not pool_user:
        args.append("-R")
    for key, value in ini.items():
        args += ["-d", f"{key}={value}"]
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # nosec B603
    for _ in range(100):
        if sock.exists():
            return proc, sock
        time.sleep(0.05)
    proc.terminate()
    raise RuntimeError("php-fpm did not start: " + (tmp / "fpm.log").read_text(errors="replace"))


def main():
    fpm, extension = sys.argv[1], str(Path(sys.argv[2]).resolve())
    opcache = sys.argv[3] if len(sys.argv) > 3 else None
    failures = []

    def check(label, condition, detail=""):
        print(f"{'PASS' if condition else 'FAIL'}  {label}" + ("" if condition else f"  [{detail!r}]"))
        if not condition:
            failures.append(label)

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        source = tmp / "source"
        source.mkdir()
        (source / "lib.php").write_text('<?php function greet($n) { return "hello $n"; }')
        (source / "index.php").write_text(
            "<?php require_once __DIR__ . '/lib.php'; echo greet('fpm'), ':', PHP_SAPI;")
        owner, recipient = a.make_owner(), a.make_recipient("fpm")
        identity = tmp / "identity.bin"
        fd = os.open(identity, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(a.identity_bundle_bytes([a.make_identity(recipient, owner)]))
        protected = tmp / "protected"
        a.pack_tree(source, protected, [a.recipient_public(recipient)], owner, str(uuid.uuid4()))
        tampered = tmp / "tampered.php"
        blob = bytearray((protected / "index.php").read_bytes())
        blob[-100] ^= 1
        tampered.write_bytes(bytes(blob))
        plain = tmp / "plain.php"
        plain.write_text('<?php echo "plain-ok";')
        base = {"extension": extension, "envelock.identity": str(identity)}

        proc, sock = serve(fpm, tmp, {**base, "opcache.enable": "0"})
        try:
            outputs = [request(sock, protected / "index.php") for _ in range(6)]
            check("protected file runs under FPM (6 requests, 2 workers)",
                  all(o == "hello fpm:fpm-fcgi" for o in outputs), outputs[0])
            check("plain PHP unaffected", request(sock, plain) == "plain-ok")
            out = request(sock, tampered)
            check("tampered file refused", "invalid protected file" in out and "hello" not in out, out)
            check("still serving after a refused file",
                  request(sock, protected / "index.php") == "hello fpm:fpm-fcgi")
        finally:
            proc.terminate()
            proc.wait(timeout=10)

        if os.geteuid() == 0:
            # Production layout: master as root reads the identity at startup, workers run
            # unprivileged. The identity must be owned by root (0600), and then the workers
            # cannot read it at all.
            os.chmod(tmp, 0o755)  # nosec B103 # the unprivileged pool must traverse it; identity.bin stays 0600
            for item in [protected, *protected.rglob("*"), plain]:
                os.chmod(item, 0o755 if item.is_dir() else 0o644)
            probe = tmp / "read-identity.php"
            probe.write_text(f'<?php var_dump(@file_get_contents("{identity}") !== false);')
            os.chmod(probe, 0o644)
            proc, sock = serve(fpm, tmp, {**base, "opcache.enable": "0"}, pool_user="nobody")
            try:
                check("root master + 'nobody' pool, identity root:0600: protected file runs",
                      request(sock, protected / "index.php") == "hello fpm:fpm-fcgi")
                out = request(sock, probe)
                check("the unprivileged worker cannot read the identity file", "bool(false)" in out, out)
            finally:
                proc.terminate()
                proc.wait(timeout=10)
            pool_owned = tmp / "identity-nobody.bin"
            fd = os.open(pool_owned, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(identity.read_bytes())
            os.chown(pool_owned, pwd.getpwnam("nobody").pw_uid, -1)
            proc, sock = serve(fpm, tmp, {**base, "envelock.identity": str(pool_owned),
                                          "opcache.enable": "0"}, pool_user="nobody")
            try:
                out = request(sock, protected / "index.php")
                check("identity owned by the pool user is refused by the root master",
                      "identity file rejected" in out, out)
            finally:
                proc.terminate()
                proc.wait(timeout=10)

        if opcache:
            blacklist = tmp / "blacklist.txt"
            blacklist.write_text(f"{protected}\n")
            probe = tmp / "probe.php"
            probe.write_text(
                f'<?php $s = opcache_get_status(true)["scripts"] ?? []; $n = 0;'
                f' foreach (array_keys($s) as $k) if (str_starts_with($k, "{protected}")) $n++;'
                ' echo "cached=$n";')
            ini = {**base, "opcache.enable": "1", "opcache.file_update_protection": "0"}
            if opcache != "builtin":
                ini = {"zend_extension": opcache, **ini}
            proc, sock = serve(fpm, tmp, ini)
            try:
                out = request(sock, protected / "index.php")
                check("OPcache on, no opt-in: protected file refused", "OPcache is enabled" in out, out)
            finally:
                proc.terminate()
                proc.wait(timeout=10)
            # HOST-1: OPcache on in the master's php.ini, switched off for the pool (what a hosting
            # panel does per site). Its compile hook stays installed above Envelock's; the loader
            # must recognise it as OPcache's own and run the file, which OPcache does not cache.
            proc, sock = serve(fpm, tmp, ini, pool_lines="php_admin_flag[opcache.enable] = off\n")
            try:
                outputs = [request(sock, protected / "index.php") for _ in range(4)]
                check("OPcache on in the master, off in the pool: protected file runs",
                      all(o == "hello fpm:fpm-fcgi" for o in outputs), outputs[0])
            finally:
                proc.terminate()
                proc.wait(timeout=10)
            ini.update({"envelock.allow_opcache": "1", "opcache.blacklist_filename": str(blacklist)})
            proc, sock = serve(fpm, tmp, ini)
            try:
                outputs = [request(sock, protected / "index.php") for _ in range(6)]
                check("OPcache on + opt-in + blacklist: protected file runs",
                      all(o == "hello fpm:fpm-fcgi" for o in outputs), outputs[0])
                out = request(sock, probe)
                check("protected files NOT in OPcache shared memory", out == "cached=0", out)
            finally:
                proc.terminate()
                proc.wait(timeout=10)
            # Opt-in WITHOUT a blacklist (the documented operator mistake): the loader must
            # fail closed on the first request (it detects OPcache is about to cache the file,
            # ZEND_COMPILE_IGNORE_OTHER_FILES) instead of letting decrypted opcodes reach SHM.
            # This is the self-verifying backstop; the probe must never see it cached.
            del ini["opcache.blacklist_filename"]
            proc, sock = serve(fpm, tmp, ini)
            try:
                out = request(sock, protected / "index.php")
                check("opt-in without blacklist: fail closed, not cached",
                      "OPcache is about to cache" in out, out)
                out = request(sock, probe)
                check("opt-in without blacklist: nothing reached OPcache shared memory",
                      out == "cached=0", out)
            finally:
                proc.terminate()
                proc.wait(timeout=10)

    print("ALL PASS" if not failures else f"{len(failures)} FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

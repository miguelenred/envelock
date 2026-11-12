"""Headless end-to-end of the assistant's actions layer, also runnable from the frozen
executable with `--e2e <workdir>`: create keys, pack a tiny project, and reopen it. Used to
test the packaged executable (including the Windows build under Wine) without a display."""

import importlib.util
import os
import sys
from pathlib import Path


def run(work):
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS")) / "gui"
    else:
        base = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location("actions", base / "actions.py")
    actions = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(actions)

    pw = b"a-long-enough-password"
    owner, rcpt, pub = work / "owner.enc.json", work / "rcpt.enc.json", work / "rcpt.pub.json"
    actions.create_owner(owner, True, pw)
    actions.create_recipient(rcpt, "srv", pw)
    actions.export_public(rcpt, pw, pub)

    src = work / "app"
    (src / "lib").mkdir(parents=True)
    (src / "index.php").write_text("<?php require __DIR__.'/lib/x.php'; echo v();")
    (src / "lib" / "x.php").write_text("<?php function v(){ return 7; }")
    out = work / "out"
    info = actions.pack(owner, pw, [pub], actions.new_project(), src, out,
                        include_protection=True, no_prepend=True)
    identity = actions.a.make_identity(
        actions.a.read_config(rcpt, "envelock-recipient", pw),
        actions.a.read_config(owner, "envelock-owner", pw))
    plain = actions.a.open_protected((out / "index.php").read_bytes(), identity)
    if b"require" not in plain or info["protected_files"] != 2:
        raise SystemExit("E2E failed: %r" % (info,))

    # Reproduce the windowed-app bug: reading an encrypted file without a password must be a clear
    # error, never a terminal prompt (no console in a frozen windowed exe -> 'NoneType'.isatty).
    try:
        actions.pack(owner, pw, [rcpt], actions.new_project(), src, work / "out2")
    except ValueError:
        pass
    else:
        raise SystemExit("E2E failed: encrypted recipient without password did not error cleanly")

    # A missing PHP (needed only for strip/obfuscate) is reported, not a crash (WinError 2 path).
    if actions.check_php("definitely-not-a-php-binary")[0] != "not_found":
        raise SystemExit("E2E failed: missing php not reported as not_found")

    # A real PHP given in ENVELOCK_E2E_PHP must run from the executable (1.0.0 bug: on Windows it
    # inherited the executable's library search path and loaded its older Visual C++ runtime).
    php = os.environ.get("ENVELOCK_E2E_PHP")
    ast_status = "not-tested"
    if php:
        if actions.check_php(php)[0] != "ok":
            raise SystemExit("E2E failed: %s could not be run: %s" % (php, actions.check_php(php)[1]))
        # Exercise the parser from the frozen data layout too; merely importing the encoder does not
        # show whether third_party/php-parser was actually bundled beside it.
        import subprocess  # nosec B404 - fixed local PHP executable, no shell
        sources = {
            "types.php": b"<?php namespace BundleCheck\\Model; class Widget { static function go(){return 7;} }",
            "main.php": (b"<?php namespace BundleCheck; use BundleCheck\\Model\\Widget as Item; "
                         b"require __DIR__ . '/types.php'; echo Item::go();"),
        }
        transformed, renamed, reason = actions.a._names_pass(sources, php, ast_names=True)
        if "BundleCheck\\Model\\Widget" not in renamed or reason:
            raise SystemExit("E2E failed: bundled AST parser did not rename the closed test pack")
        tree = work / "ast"
        tree.mkdir()
        for name, data in transformed.items():
            (tree / name).write_bytes(data)
        result = subprocess.run([php, "-n", str(tree / "main.php")], capture_output=True, timeout=60)  # nosec B603
        if result.returncode != 0 or result.stdout != b"7":
            raise SystemExit("E2E failed: AST-transformed pack did not execute")
        ast_status = "ok"

    # The PHP download path (index -> zip -> SHA-256 -> safe extraction) against a local mirror,
    # so the packaged executable proves it bundles everything the real download needs.
    exe = _download_from_mirror(actions, work)
    if exe.read_bytes() != b"fake php" or exe.parent.name != "8.4.27":
        raise SystemExit("E2E failed: PHP download/extraction")

    print("E2E OK files=%d assets=%d serial=%d php-download=ok php-ast=%s"
          % (info["protected_files"], info["copied_assets"], info["serial"], ast_status))


def _download_from_mirror(actions, work):
    import hashlib
    import http.server
    import io
    import json
    import threading
    import zipfile

    mirror = work / "mirror"
    mirror.mkdir()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("php.exe", b"fake php")
    name = "php-8.4.27-nts-Win32-vs17-x64.zip"
    (mirror / name).write_bytes(buf.getvalue())
    (mirror / "releases.json").write_text(json.dumps({"8.4": {"version": "8.4.27", "nts-vs17-x64": {
        "zip": {"path": name, "sha256": hashlib.sha256(buf.getvalue()).hexdigest()}}}}))

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(mirror), **kwargs)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/releases.json"
        return actions.download_php(work / "php", (url,))
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    run(sys.argv[sys.argv.index("--e2e") + 1] if "--e2e" in sys.argv else "e2e-work")

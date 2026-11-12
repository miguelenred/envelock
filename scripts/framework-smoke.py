#!/usr/bin/env python3
"""Objective O11: compare selected routes of disposable real framework applications.

This is an intermediate integration check, not proof of general equivalence or O11 closure. It
is not a unit test: it needs two real applications and
a network to install them, so it is a script you run, and tests/test_frameworks.py runs it when the
apps are present and skips when they are not.

    # 1. Create dedicated disposable fixtures (needs composer and network):
    python3 scripts/create-framework-fixtures.py --root /tmp/envelock-framework-fixtures

    # 2. Run the checks:
    python3 scripts/framework-smoke.py --app /tmp/envelock-framework-fixtures/laravel --kind laravel
    python3 scripts/framework-smoke.py --app /tmp/envelock-framework-fixtures/symfony --kind symfony

    # A production loader has no envelock_bc_emit (always so on Windows): name the served loader
    # and a pack-time emitter build (--enable-envelock-bcemit) of the same PHP:
    python scripts/framework-smoke.py --app C:/fw/laravel --kind laravel \
        --loader C:/loaders/php_envelock.dll --emitter C:/loaders/emitter/php_envelock.dll

What it does, and why each step is shaped the way it is:

- Both runs use disposable copies. Laravel is forced to use each copy's own SQLite fixture rather
  than a DB_DATABASE from the environment or .env; the supplied application is not reset or served.
- Only the application's OWN code is packed. `vendor/` and the caches generated at run time
  (Laravel `bootstrap/cache`, Symfony `var/cache`, compiled templates) stay outside the packed tree:
  they are not the asset, and packing them would mean shipping a cache that has to be regenerated
  anyway.
- Only the files the packer will actually replace are removed from the working copy. Removing the
  whole directory takes the non-PHP files with it — `config/*.yaml`, `.env`, templates — which the
  packer neither touches nor copies. In Symfony that is `config/routes.yaml`, and the symptom is an
  empty `debug:router` that looks exactly like an attribute-reflection failure and is not one.
- `extensions` includes the empty suffix, because `artisan` and `bin/console` are own code with no
  file extension. Without it the packer skips them silently and the app will not start at all.
- Public renaming (O6) is explicitly off. The pack report's `names_obfuscated` field must be the
  boolean False; the script fails if the field is missing or the feature was enabled.
- OPcache must be off (or explicitly allowed). The loader refuses to run with OPcache enabled unless
  you opt in, because the cache would hold opcodes it is supposed to be the only one producing.

Exit 0 only when the expected fixture behaviour is exercised and status, full body and response
headers match after normalizing copy paths and local ports. Redirects are not followed. Date is
excluded; the two known Laravel fixture cookie nonces and clock-based Expires are masked as
specified in _normalise_fixture_cookie. A separate cookie jar for each app checks a Laravel
file-session write/read round trip and transfers the cookie and copied session files through deploy
and rollback. Raw random cookie values, other session stores and CSRF flows are not compared.
This is an intermediate check, not a general equivalence proof or O11 closure.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess  # nosec B404 - runs the local php CLI with fixed argument lists, no shell
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "encoder"))
import envelock as a  # noqa: E402

_PHP_INFO = 'echo PHP_MAJOR_VERSION, ".", PHP_MINOR_VERSION, " ", (int) PHP_ZTS, " ", PHP_OS_FAMILY;'


def default_loader(php: str = "php") -> pathlib.Path:
    """The committed loader matching the given PHP CLI: its version, thread safety, OS and machine
    (prebuilt/loader/<os-arch>/php-X.Y-<nts|ts|zts>/<envelock.so|php_envelock.dll>)."""
    try:
        info = subprocess.run([php, "-n", "-r", _PHP_INFO], capture_output=True, text=True,  # nosec B603
                              timeout=60, check=True).stdout.split()
    except (OSError, subprocess.SubprocessError) as error:
        raise SystemExit(f"cannot run {php} to choose the matching loader ({error}); pass --loader") from error
    version, zts, family = info[0], info[1] == "1", info[2]
    arch = "arm64" if platform.machine().lower() in ("aarch64", "arm64") else "x86_64"
    if family == "Windows":
        folder, name, thread = "windows-x64", "php_envelock.dll", "ts" if zts else "nts"
    else:
        folder = f"{'macos' if family == 'Darwin' else 'linux'}-{arch}"
        name, thread = "envelock.so", "zts" if zts else "nts"
    return ROOT / "prebuilt" / "loader" / folder / f"php-{version}-{thread}" / name


def has_function(php: str, module: pathlib.Path, name: str) -> bool:
    """Whether `module`, loaded into the given PHP CLI, defines the userland function `name`."""
    code = f"echo function_exists('{name}') ? 'yes' : 'no';"
    result = subprocess.run([php, "-n", "-d", f"extension={module}", "-r", code],  # nosec B603
                            capture_output=True, text=True, timeout=60, check=False)
    return result.stdout.strip() == "yes"


def pack_framework_code(own, destination, recipient_public, owner, project, protected, flatten=False,
                        emitter=None, php="php"):
    """Keep public names off in framework code; fail closed on an absent or enabled report field.
    emitter: the pack-time loader that compiles the bytecode (it needs envelock_bc_emit); by
    default the committed loader matching `php`."""
    info = a.pack_tree(
        own, destination, [recipient_public], owner, project,
        extensions={".php", ""}, strip_comments=True, obfuscate=True, compact=True,
        encode_strings=True, obfuscate_names=False, obfuscate_flatten=flatten, php=php,
        bytecode=True, deploy_root=protected, bytecode_loader=str(emitter or default_loader(php)))
    if info.get("names_obfuscated") is not False:
        raise SystemExit("public name obfuscation must be explicitly disabled for framework code")
    return info


# Own code, per framework. Everything else — vendor/, storage/, var/, caches — stays put.
OWN_CODE = {
    "laravel": ["app", "config", "routes", "database/migrations",
                "bootstrap/app.php", "bootstrap/providers.php", "public/index.php", "artisan"],
    "symfony": ["src", "config", "public/index.php", "bin/console"],
}

ROUTES = {
    "laravel": [("GET", "/ping", None), ("GET", "/widgets", None), ("GET", "/reflect", None),
                ("POST", "/widgets", b'{"name":"tornillo"}'), ("GET", "/widgets", None),
                ("POST", "/widgets", b'{"name":"' + b"x" * 64 + b'"}'),
                ("GET", "/up", None), ("GET", "/no-existe", None),
                ("GET", "/session/write", None), ("GET", "/session/read", None)],
    "symfony": [("GET", "/ping", None), ("GET", "/items", None), ("GET", "/reflect", None),
                ("POST", "/items", b"tornillo"), ("GET", "/items", None),
                ("POST", "/items", b"x" * 64), ("GET", "/no-existe", None)],
}

EXPECTED_CODES = {"laravel": [200, 200, 200, 201, 200, 422, 200, 404, 200, 200],
                  "symfony": [200, 200, 200, 201, 200, 422, 404]}


def assert_probe_exercises_fixture(kind: str, responses: dict) -> None:
    """Identical errors are not a successful framework test: check status and fixture semantics."""
    def response(index: int):
        method, path, _body = ROUTES[kind][index]
        return responses.get(f"{index:02d} {method} {path}")

    for index, code in enumerate(EXPECTED_CODES[kind]):
        item = response(index)
        if not item or item[0] != code:
            detail = (item[0], item[1][:200]) if item else None
            raise SystemExit(f"{kind}: expected HTTP {code} at route {index}, got {detail!r}")

    def body(index: int) -> dict:
        try:
            obj = json.loads(response(index)[1])
        except (TypeError, ValueError) as error:
            raise SystemExit(f"{kind}: expected JSON at route {index}") from error
        if not isinstance(obj, dict):
            raise SystemExit(f"{kind}: expected JSON object at route {index}")
        return obj

    ping, first, reflection, created, second, rejected = (body(i) for i in range(6))
    item_key = "widgets" if kind == "laravel" else "items"
    expected_service = r"App\Services\ProbeService" if kind == "laravel" else r"App\Service\Catalogue"
    items_after = second.get(item_key)
    if (ping.get("pong") is not True or first.get(item_key) != []
            or created.get("name") != "tornillo" or not isinstance(items_after, list)
            or not any(item.get("name") == "tornillo" for item in items_after if isinstance(item, dict))
            or not rejected.get("errors") or reflection.get("service") != expected_service
            or not isinstance(reflection.get("attributes"), int) or reflection["attributes"] < 1
            or (kind == "laravel" and (reflection.get("table") != "widgets"
                                       or reflection.get("attribute_name") != "reflection"))
            or (kind == "symfony" and reflection.get("path") != "/ping")):
        raise SystemExit(f"{kind}: expected fixture results (injection, attributes, state and validation)")
    if kind == "laravel" and (body(8).get("session") != "stored" or body(9).get("session") != "envelock-probe"):
        raise SystemExit("laravel: expected a cookie-backed session round trip")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None  # compare the original 3xx status and Location; never hide it behind a 200


def _open_no_redirect(opener, request, timeout):
    return opener.open(request, timeout=timeout)


def _normalise_fixture_cookie(kind: str, value: str) -> str:
    """Mask the two Laravel fixture nonce values, never arbitrary application cookies.

    Preserve cookie name, presence, attributes and Max-Age. Expires is only masked when an
    explicit Max-Age remains available for TTL comparison. This does NOT verify cookie contents,
    equality or cryptographic properties of cookie contents. The separate session route verifies
    that a cookie returned by each app can be used in that app's subsequent request.
    """
    parts = value.split(";")
    name, separator, token = parts[0].partition("=")
    if kind != "laravel" or name.strip().lower() not in {"xsrf-token", "laravel-session"} \
            or not separator or not token or token.lower() == "deleted":
        return value
    parts[0] = name + "=<fixture-random-value>"
    if any(part.strip().lower().startswith("max-age=") for part in parts[1:]):
        parts[1:] = [(part.split("=", 1)[0] + "=<clock>") if part.strip().lower().startswith("expires=")
                     else part for part in parts[1:]]
    return ";".join(parts)


def probe(port: int, kind: str, roots: list[str], jar: http.cookiejar.CookieJar | None = None) -> dict:
    """Return status, full body and headers; mask Date and known fixture-only cookie nonces."""
    out = {}
    # Each app run has an independent browser-like cookie jar; requests within the run share it.
    if jar is None:
        jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPCookieProcessor(jar))
    # Keyed by position, not by "METHOD path": the list deliberately requests the same path twice
    # (before and after the POST) and a dict keyed by route would let the second hide the first.
    for index, (method, path, body) in enumerate(ROUTES[kind]):
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}{path}", data=body, method=method,
            headers={"Content-Type": "application/json", "Accept": "application/json"})
        headers = None
        try:
            with _open_no_redirect(opener, request, timeout=60) as response:
                status, payload, headers = response.status, response.read(), response.headers
        except urllib.error.HTTPError as error:
            status, payload, headers = error.code, error.read(), error.headers
        except Exception as error:  # noqa: BLE001 - a connection failure is a result, not a crash
            status, payload = -1, repr(error).encode("utf-8", errors="backslashreplace")
        # Both copies live at different paths and listen on different ports, and framework error
        # pages embed absolute file paths and the full request URL. Left in, those would be the
        # only differences and would mask any real one.
        for root in roots:
            payload = payload.replace(root.encode(), b"<APP>")
        payload = payload.replace(f"127.0.0.1:{port}".encode(), b"<HOST>")
        # Header names are case-insensitive; preserve duplicate values and ordering. Comparing only
        # the body misses cache, redirect or security policies. Date is volatile; the two fixture
        # cookie nonces and their clock-based expiry need the narrowly scoped treatment below.
        canonical_headers: dict[str, list[str]] = {}
        if headers is not None:
            for name, value in headers.items():
                key = name.lower()
                if key == "date":
                    continue
                for root in roots:
                    value = value.replace(root, "<APP>")
                value = value.replace(f"127.0.0.1:{port}", "<HOST>")
                if key == "set-cookie":
                    value = _normalise_fixture_cookie(kind, value)
                canonical_headers.setdefault(key, []).append(value)
        # Compare the complete body as bytes. Truncating at 600 or decoding with replacement can
        # silently hide a real divergence, including one after a long HTML error-page header.
        out[f"{index:02d} {method} {path}"] = [status, payload, canonical_headers]
    return out


def assert_session_handoff(port: int, jar: http.cookiejar.CookieJar, phase: str) -> None:
    """Verify that an existing cookie accesses the copied session after deploy or rollback."""
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPCookieProcessor(jar))
    request = urllib.request.Request(f"http://127.0.0.1:{port}/session/read",
                                     headers={"Accept": "application/json"})
    try:
        with opener.open(request, timeout=60) as response:
            status, payload = response.status, json.loads(response.read())
    except Exception as error:  # noqa: BLE001 - any failure must abort the deployment check
        raise SystemExit(f"{phase}: session handoff request failed: {type(error).__name__}") from error
    if status != 200 or not isinstance(payload, dict) or payload.get("session") != "envelock-probe":
        raise SystemExit(f"{phase}: session handoff did not preserve the stored session")


def copy_fixture_sessions(source: pathlib.Path, target: pathlib.Path) -> None:
    """Copy only disposable Laravel file sessions, not arbitrary storage or external paths."""
    src = source / "storage/framework/sessions"
    dst = target / "storage/framework/sessions"
    if not src.resolve().is_relative_to(source.resolve()) or not dst.resolve().is_relative_to(target.resolve()):
        raise SystemExit("refusing an external session storage path")
    if not src.is_dir() or not dst.is_dir():
        raise SystemExit("fixture session directory is missing")
    copied = 0
    for item in src.iterdir():
        # Laravel file session IDs are forty alphanumeric ASCII characters. No symlinks or
        # arbitrary fixture files are followed or copied; both roots are already disposable copies.
        if re.fullmatch(r"[A-Za-z0-9]{40}", item.name) and item.is_file() and not item.is_symlink():
            if (dst / item.name).is_symlink():
                raise SystemExit("refusing a symlink in fixture session storage")
            shutil.copy2(item, dst / item.name)
            copied += 1
    if not copied:
        raise SystemExit("no fixture file sessions available for deployment handoff")


def serve(directory: pathlib.Path, port: int, ini_dir: pathlib.Path | None, kind: str,
          php: str = "php") -> subprocess.Popen:
    """Serve a disposable copy; for Laravel, force the copy's own SQLite database."""
    environment = dict(os.environ)
    environment.update({"APP_ENV": "production" if kind == "laravel" else "prod", "APP_DEBUG": "0"})
    if kind == "laravel":
        # Never trust an absolute DB_DATABASE inherited from the source .env or the caller's shell.
        # The test routes write data, so both apps must use isolated copies of the fixture database.
        environment.update({"DB_CONNECTION": "sqlite", "DB_DATABASE": str(directory / "database" / "database.sqlite"),
                            "LARAVEL_STORAGE_PATH": str(directory / "storage"),
                            "CACHE_STORE": "array", "SESSION_DRIVER": "file", "QUEUE_CONNECTION": "sync"})
    if ini_dir is not None:
        # The leading separator (':' on POSIX, ';' on Windows) keeps PHP's default ini locations,
        # including the framework's extensions.
        environment["PHP_INI_SCAN_DIR"] = f"{os.pathsep}{ini_dir}"
    # Symfony's dotenv reads $_ENV/$_SERVER, not getenv(); Debian's default GPCS omits E and can
    # otherwise override our isolation and APP_ENV settings with values from the copied .env.
    command = [php, "-d", "variables_order=EGPCS", "-S", f"127.0.0.1:{port}",
               "-t", "public", "public/index.php"]
    # stderr goes to a file, not a pipe: nobody reads a pipe here, so once the 64 KiB buffer fills
    # the server blocks mid-request and the app silently stops answering. The file also gives the
    # failure something to show.
    log = directory / ".envelock-smoke.log"
    # Do not reuse a copied or previous log: readiness must come from THIS process.
    with open(log, "wb") as handle:
        process = subprocess.Popen(command, cwd=directory, env=environment,  # nosec B603
                                   stdout=handle, stderr=handle, text=True)
    process.envelock_log = log          # type: ignore[attr-defined]
    return process


def wait_for(port: int, process: subprocess.Popen, seconds: int = 60) -> None:
    """Require this PHP process to have bound the port, not merely any HTTP listener."""
    deadline = time.monotonic() + seconds
    marker = f"Development Server (http://127.0.0.1:{port}) started"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"the app server exited before starting on port {port}")
        log = process.envelock_log.read_text(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        if marker in log:
            if process.poll() is not None:
                raise RuntimeError(f"the app server exited after starting on port {port}")
            return
        time.sleep(0.1)
    raise TimeoutError(f"the app server did not start on port {port}")


def reset_state(directory: pathlib.Path, kind: str) -> None:
    """Reset ONLY the disposable copy's fixture state, never a database named by its .env."""
    if kind == "symfony":
        (directory / "var" / "items.json").unlink(missing_ok=True)
        return
    import sqlite3
    database = directory / "database" / "database.sqlite"
    if not database.is_file():
        raise SystemExit("the Laravel fixture needs its own database/database.sqlite")
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM widgets")
        connection.execute("DELETE FROM sqlite_sequence WHERE name = 'widgets'")


def _tail(path: pathlib.Path, lines: int = 25) -> str:
    if not path.is_file():
        return "(the server wrote no log)"
    return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--app", type=pathlib.Path, required=True)
    parser.add_argument("--kind", choices=sorted(OWN_CODE), required=True)
    parser.add_argument("--baseline-port", type=int, default=8123)
    parser.add_argument("--protected-port", type=int, default=8124)
    parser.add_argument("--keep", action="store_true", help="Keep the working copies for inspection")
    parser.add_argument("--flatten", action="store_true",
                        help="Also apply control-flow flattening (--obfuscate-flatten, O6) to the own code")
    parser.add_argument("--php", default="php", help="PHP CLI that packs and serves (default: php on PATH)")
    parser.add_argument("--loader", type=pathlib.Path,
                        help="Loader module the protected app is served with (default: the committed "
                             "prebuilt loader matching --php's version, thread safety and OS)")
    parser.add_argument("--emitter", type=pathlib.Path,
                        help="Pack-time loader that compiles the bytecode (a build with "
                             "--enable-envelock-bcemit of the same PHP; default: --loader). A production "
                             "loader has no envelock_bc_emit")
    arguments = parser.parse_args()

    app = arguments.app.resolve()
    if not app.is_dir():
        raise SystemExit(f"no such app: {app}")
    marker = app / ".envelock-smoke-fixture"
    if not marker.is_file() or marker.read_text(encoding="utf-8").strip() != arguments.kind:
        raise SystemExit("fixture marker missing or wrong; create a disposable app with "
                         "scripts/create-framework-fixtures.py")
    php = arguments.php
    loader = (arguments.loader or default_loader(php)).resolve()
    emitter = (arguments.emitter or loader).resolve()
    for role, module in (("loader", loader), ("emitter", emitter)):
        if not module.is_file():
            raise SystemExit(f"no {role} module at {module}")
    if not has_function(php, emitter, "envelock_bc_emit"):
        raise SystemExit(f"the emitter {emitter} has no envelock_bc_emit (a production loader never "
                         "has it): pass --emitter with a pack-time build (--enable-envelock-bcemit) "
                         f"of the same PHP as {php}")
    work = pathlib.Path(tempfile.mkdtemp(prefix="envelock-fw-"))
    baseline_app = work / "baseline"
    protected = work / "protected"
    keys = work / "keys"
    try:
        # Run both sides in copies. The routes write state; the supplied application and its .env,
        # database, logs and caches must never be modified by this test.
        shutil.copytree(app, baseline_app)
        shutil.copytree(app, protected)
        # The protected copy starts WITHOUT its own PHP code because bytecode compiles each file at
        # its deploy path and refuses to overwrite anything already there.
        own = work / "own"
        packed_paths = []
        for relative in OWN_CODE[arguments.kind]:
            source = app / relative
            if source.is_dir():
                packed_paths += [f.relative_to(app) for f in sorted(source.rglob("*"))
                                 if f.is_file() and f.suffix.lower() in (".php", "")]
            else:
                packed_paths.append(pathlib.Path(relative))
        for relative in packed_paths:
            (protected / relative).unlink(missing_ok=True)
            target = own / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(app / relative, target)

        owner = a.make_owner()
        recipient = a.make_recipient("framework-smoke")
        keys.mkdir(parents=True)
        (keys / "identity.bin").write_bytes(
            a.identity_bundle_bytes([a.make_identity(recipient, owner)]))
        os.chmod(keys / "identity.bin", 0o600)

        info = pack_framework_code(own, work / "packed", a.recipient_public(recipient), owner,
                                   str(uuid.uuid4()), protected, flatten=arguments.flatten,
                                   emitter=emitter, php=php)
        print(f"  empaquetados: {info['protected_files']}  (renombrado publico desactivado)")

        for source in (work / "packed").rglob("*"):
            if source.is_file():
                target = protected / source.relative_to(work / "packed")
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
        # The run-time caches stay out of the packed tree, but they must still EXIST: Laravel
        # refuses to boot without a present and writable bootstrap/cache, and deleting it without
        # recreating it is a confusing "PackageManifest.php line 179" rather than anything that
        # points at the protector.
        for tree in (baseline_app, protected):
            for cache in ("var/cache", "bootstrap/cache"):
                target = tree / cache
                shutil.rmtree(target, ignore_errors=True)
                if (tree / cache.split("/")[0]).is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    os.chmod(target, 0o700)    # writable by the user that serves the copy (bandit B103)

        ini = work / "ini"
        ini.mkdir()
        # Forward slashes: PHP takes them on Windows too, and an INI value then holds no backslash.
        (ini / "zz-envelock.ini").write_text(
            f"extension={loader.as_posix()}\nenvelock.identity={(keys / 'identity.bin').as_posix()}\n"
            "opcache.enable=0\nopcache.enable_cli=0\n", encoding="utf-8")

        roots = [str(protected), str(baseline_app), str(app)]
        baseline_jar, protected_jar = http.cookiejar.CookieJar(), http.cookiejar.CookieJar()
        reset_state(baseline_app, arguments.kind)
        baseline = serve(baseline_app, arguments.baseline_port, None, arguments.kind, php)
        try:
            try:
                wait_for(arguments.baseline_port, baseline)
            except (TimeoutError, RuntimeError) as error:
                raise SystemExit(f"{error}\n--- log ---\n{_tail(baseline_app / '.envelock-smoke.log')}")
            expected = probe(arguments.baseline_port, arguments.kind, roots, baseline_jar)
            if baseline.poll() is not None:
                raise SystemExit("baseline app server exited during the probe")
            assert_probe_exercises_fixture(arguments.kind, expected)
        finally:
            baseline.terminate()
            baseline.wait(timeout=30)

        reset_state(protected, arguments.kind)
        if arguments.kind == "laravel":
            # Simulate deployment with the pre-existing cookie and its file-session store intact.
            copy_fixture_sessions(baseline_app, protected)
        guarded = serve(protected, arguments.protected_port, ini, arguments.kind, php)
        try:
            try:
                wait_for(arguments.protected_port, guarded)
            except (TimeoutError, RuntimeError) as error:
                raise SystemExit(
                    f"{error}\n--- log ---\n{_tail(protected / '.envelock-smoke.log')}")
            actual = probe(arguments.protected_port, arguments.kind, roots, protected_jar)
            if guarded.poll() is not None:
                raise SystemExit("protected app server exited during the probe")
            assert_probe_exercises_fixture(arguments.kind, actual)
            if arguments.kind == "laravel":
                assert_session_handoff(arguments.protected_port, baseline_jar, "deploy")
                if guarded.poll() is not None:
                    raise SystemExit("protected app server exited during session handoff")
        finally:
            guarded.terminate()
            guarded.wait(timeout=30)

        if arguments.kind == "laravel":
            # A rollback must also accept a session created by the protected deployment.
            copy_fixture_sessions(protected, baseline_app)
            rollback = serve(baseline_app, arguments.baseline_port, None, arguments.kind, php)
            try:
                try:
                    wait_for(arguments.baseline_port, rollback)
                except (TimeoutError, RuntimeError) as error:
                    raise SystemExit(f"{error}\n--- log ---\n{_tail(baseline_app / '.envelock-smoke.log')}")
                assert_session_handoff(arguments.baseline_port, protected_jar, "rollback")
                if rollback.poll() is not None:
                    raise SystemExit("rollback app server exited during session handoff")
            finally:
                rollback.terminate()
                rollback.wait(timeout=30)
            print("  OK   Laravel session survives deployment and rollback")

        differing = [k for k in sorted(expected) if expected.get(k) != actual.get(k)]
        for key in sorted(expected):
            print(("  OK   " if key not in differing else "  DIF  ") + key
                  + f"  ->  {actual.get(key, [None])[0]}")
            if key in differing:
                print(f"     sin proteger: {str(expected.get(key))[:200]}")
                print(f"     protegido   : {str(actual.get(key))[:200]}")
        verdict = "IDENTICAS" if not differing else f"DIFIEREN en {len(differing)}"
        print(f"{arguments.kind}: {len(expected) - len(differing)}/{len(expected)} respuestas "
              f"identicas — {verdict}")
        return 0 if not differing else 1
    finally:
        if arguments.keep:
            print(f"copias conservadas en {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())

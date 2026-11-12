"""Objective O11: real Laravel and Symfony applications, protected and unprotected.

This is an intermediate check for format 2.0, not final O11 closure: its real-app tests need two
applications with their `vendor/` trees installed, which means composer and a network. They run
when the applications are present and skip otherwise, exactly like the static-PHP
check in test_native.py.

    python3 scripts/create-framework-fixtures.py --root /tmp/envelock-framework-fixtures
    ENVELOCK_FW_LARAVEL=/tmp/envelock-framework-fixtures/laravel \\
    ENVELOCK_FW_SYMFONY=/tmp/envelock-framework-fixtures/symfony pytest tests/test_frameworks.py

Optional: ENVELOCK_FW_LOADER (served module), ENVELOCK_FW_EMITTER (pack-time build with
envelock_bc_emit; required with any production loader, so on Windows) and ENVELOCK_FW_PHP.
"""

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "framework-smoke.py"


def _symlink_or_skip(link, target, directory=False):
    """Windows grants symbolic links only to administrators or in Developer Mode."""
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as error:
        pytest.skip(f"symbolic links are not permitted here ({error.strerror})")


@pytest.mark.parametrize("variable,kind", [("ENVELOCK_FW_LARAVEL", "laravel"),
                                           ("ENVELOCK_FW_SYMFONY", "symfony")])
def test_framework_app_behaves_identically_protected(variable, kind):
    """The whole point of the check: same routes, same status codes, same bodies, byte for byte.

    What that exercises, and why each piece matters: PSR-4 autoloading of classes whose source is no
    longer in the file; reflection over constructor parameters, which is how the container decides
    what to inject; PHP 8 attributes read back off methods, which is how both frameworks discover
    routes; Eloquent resolving a table name from a class; and the validation and error paths, where
    a protector that changed behaviour would show up as a different status rather than a crash.
    """
    application = os.getenv(variable)
    if not application:
        pytest.skip(f"set {variable} to a real {kind} application")
    if not Path(application).is_dir():
        pytest.fail(f"{variable} does not exist: {application}")
    # Optional: the served loader, the pack-time emitter (a production loader, and so every Windows
    # DLL, has no envelock_bc_emit) and the PHP CLI; by default the committed loader matching php.
    extra = []
    for option, name in (("--loader", "ENVELOCK_FW_LOADER"), ("--emitter", "ENVELOCK_FW_EMITTER"),
                         ("--php", "ENVELOCK_FW_PHP")):
        if os.getenv(name):
            extra += [option, os.environ[name]]
    result = subprocess.run([sys.executable, str(SCRIPT), "--app", application, "--kind", kind, *extra],
                            capture_output=True, text=True, timeout=1800, check=False)
    assert result.returncode == 0, f"{kind} differs protected vs unprotected:\n{result.stdout}\n{result.stderr}"
    assert "respuestas identicas — IDENTICAS" in result.stdout, result.stdout


def _load_smoke_script():
    spec = importlib.util.spec_from_file_location("framework_smoke", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_obfuscator_does_not_rename_public_names_in_framework_code(monkeypatch, tmp_path):
    """The framework pack must explicitly turn off public renaming and check the real report key."""
    smoke = _load_smoke_script()
    observed = {}

    def fake_pack(*args, **kwargs):
        observed.update(kwargs)
        return {"names_obfuscated": False, "protected_files": 1}

    monkeypatch.setattr(smoke.a, "pack_tree", fake_pack)
    emitter = tmp_path / "emitter" / "envelock.so"
    result = smoke.pack_framework_code(tmp_path, tmp_path / "out", {}, {}, "project", tmp_path / "deployed",
                                       emitter=emitter)
    assert observed["obfuscate_names"] is False
    assert observed["bytecode_loader"] == str(emitter)          # the pack-time emitter, not the server loader
    assert result["names_obfuscated"] is False
    for report in ({}, {"names_obfuscated": []}, {"names_obfuscated": ["e12345"]}):
        monkeypatch.setattr(smoke.a, "pack_tree", lambda *args, report=report, **kwargs: report)
        with pytest.raises(SystemExit, match="public"):
            smoke.pack_framework_code(tmp_path, tmp_path / "out", {}, {}, "project", tmp_path / "deployed",
                                      emitter=emitter)


def test_framework_probe_compares_full_binary_body(monkeypatch):
    """A difference after byte 600, including non-UTF-8 bytes, must not be silently discarded."""
    smoke = _load_smoke_script()
    monkeypatch.setitem(smoke.ROUTES, "test", [("GET", "/probe", None)])
    payload = [b"x" * 600 + b"\xfffirst"]

    class Response:
        status = 200
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return payload[0]

    monkeypatch.setattr(smoke, "_open_no_redirect", lambda *args, **kwargs: Response())
    before = smoke.probe(8123, "test", [])
    payload[0] = b"x" * 600 + b"\xfefirst"
    after = smoke.probe(8123, "test", [])
    assert before != after
    assert before["00 GET /probe"][1] == b"x" * 600 + b"\xfffirst"


def test_reset_framework_state_never_touches_external_database(tmp_path):
    """The copied app's .env may point at a real database: never clear that external path."""
    import sqlite3

    smoke = _load_smoke_script()
    external = tmp_path / "external.sqlite"
    copied = tmp_path / "copy"
    local = copied / "database" / "database.sqlite"
    local.parent.mkdir(parents=True)
    for db in (external, local):
        with sqlite3.connect(db) as connection:
            connection.execute("CREATE TABLE widgets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)")
            connection.execute("INSERT INTO widgets (name) VALUES ('keep')")
    (copied / ".env").write_text(f"DB_CONNECTION=sqlite\nDB_DATABASE={external}\n")
    smoke.reset_state(copied, "laravel")
    with sqlite3.connect(external) as connection:
        assert connection.execute("SELECT name FROM widgets").fetchall() == [("keep",)]
    with sqlite3.connect(local) as connection:
        assert connection.execute("SELECT name FROM widgets").fetchall() == []


def test_framework_smoke_rejects_matching_404s_instead_of_exercising_routes():
    smoke = _load_smoke_script()
    fake = {f"{i:02d} {method} {path}": [404, b"not found"]
            for i, (method, path, _body) in enumerate(smoke.ROUTES["laravel"])}
    with pytest.raises(SystemExit, match="expected"):
        smoke.assert_probe_exercises_fixture("laravel", fake)


@pytest.mark.parametrize("kind,collection,service,reflection", [
    ("laravel", "widgets", r"App\Services\ProbeService", {"table": "widgets", "attribute_name": "reflection"}),
    ("symfony", "items", r"App\Service\Catalogue", {"path": "/ping"}),
])
def test_framework_smoke_checks_the_fixture_results(kind, collection, service, reflection):
    import json

    smoke = _load_smoke_script()
    bodies = [{"pong": True}, {collection: []}, {"service": service, "attributes": 1, **reflection},
              {"id": 1, "name": "tornillo"}, {collection: [{"id": 1, "name": "tornillo"}]},
              {"errors": {"name": ["invalid"]}}]
    while len(bodies) < len(smoke.ROUTES[kind]):
        bodies.append({})
    if kind == "laravel":
        bodies[8], bodies[9] = {"session": "stored"}, {"session": "envelock-probe"}
    responses = {f"{i:02d} {method} {path}": [smoke.EXPECTED_CODES[kind][i], json.dumps(bodies[i]).encode()]
                 for i, (method, path, _body) in enumerate(smoke.ROUTES[kind])}
    smoke.assert_probe_exercises_fixture(kind, responses)
    key = "02 GET /reflect"
    responses[key][1] = json.dumps({"service": "wrong", "attributes": 1, **reflection}).encode()
    with pytest.raises(SystemExit, match="expected fixture"):
        smoke.assert_probe_exercises_fixture(kind, responses)


def test_fixture_builder_refuses_nonempty_target(tmp_path):
    sentinel = tmp_path / "do-not-overwrite.txt"
    sentinel.write_text("original")
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "create-framework-fixtures.py"),
                             "--root", str(tmp_path)], capture_output=True, text=True, timeout=30)
    assert result.returncode != 0 and "refusing to overwrite" in result.stderr
    assert sentinel.read_text() == "original"


def test_server_uses_copy_database_and_exposes_environment_to_php(monkeypatch, tmp_path):
    smoke = _load_smoke_script()
    observed = {}

    def fake_popen(command, **kwargs):
        observed.update(command=command, **kwargs)
        return type("Process", (), {})()

    monkeypatch.setenv("DB_DATABASE", "/outside/real-database.sqlite")
    monkeypatch.setenv("LARAVEL_STORAGE_PATH", "/outside/real-storage")
    monkeypatch.setattr(smoke.subprocess, "Popen", fake_popen)
    smoke.serve(tmp_path, 8123, None, "laravel")
    assert observed["env"]["DB_DATABASE"] == str(tmp_path / "database" / "database.sqlite")
    assert observed["env"]["DB_CONNECTION"] == "sqlite"
    assert observed["env"]["SESSION_DRIVER"] == "file"
    assert observed["env"]["LARAVEL_STORAGE_PATH"] == str(tmp_path / "storage")
    assert "variables_order=EGPCS" in observed["command"]
    # The extra ini folder is appended with the OS's own list separator (';' on Windows), after an
    # empty entry that keeps PHP's default scan directory.
    smoke.serve(tmp_path, 8123, tmp_path / "ini", "symfony", php="/opt/php/bin/php")
    assert observed["env"]["PHP_INI_SCAN_DIR"] == os.pathsep + str(tmp_path / "ini")
    assert observed["command"][0] == "/opt/php/bin/php"


@pytest.mark.parametrize("info,machine,expected", [
    ("8.4 0 Linux", "x86_64", "linux-x86_64/php-8.4-nts/envelock.so"),
    ("8.4 1 Linux", "x86_64", "linux-x86_64/php-8.4-zts/envelock.so"),
    ("8.3 0 Linux", "aarch64", "linux-arm64/php-8.3-nts/envelock.so"),
    ("8.4 0 Windows", "AMD64", "windows-x64/php-8.4-nts/php_envelock.dll"),
    ("8.3 1 Windows", "AMD64", "windows-x64/php-8.3-ts/php_envelock.dll"),
])
def test_default_loader_matches_the_running_php(monkeypatch, info, machine, expected):
    """FW: the served loader defaults to the committed one for the PHP in use (version, thread
    safety, OS), not to a hard-coded Linux 8.4 NTS module."""
    smoke = _load_smoke_script()
    monkeypatch.setattr(smoke.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, info, ""))
    monkeypatch.setattr(smoke.platform, "machine", lambda: machine)
    assert smoke.default_loader("php") == ROOT / "prebuilt" / "loader" / Path(expected)


def test_smoke_refuses_an_emitter_without_bc_emit(tmp_path):
    """A production loader (every committed one, and every Windows DLL) cannot compile bytecode:
    the script says to pass --emitter instead of failing deep inside the pack."""
    import shutil

    php = shutil.which("php")
    if not php:
        pytest.skip("php is needed")
    smoke = _load_smoke_script()
    loader = smoke.default_loader(php)
    if not loader.is_file():
        pytest.skip(f"no committed loader for this PHP ({loader.name})")
    app = tmp_path / "app"
    app.mkdir()
    (app / ".envelock-smoke-fixture").write_text("symfony\n", encoding="utf-8")
    result = subprocess.run([sys.executable, str(SCRIPT), "--app", str(app), "--kind", "symfony"],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode != 0 and "--emitter" in result.stderr, result.stderr
    result = subprocess.run([sys.executable, str(SCRIPT), "--app", str(app), "--kind", "symfony",
                             "--loader", str(loader), "--emitter", str(tmp_path / "missing.dll")],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode != 0 and "no emitter module" in result.stderr, result.stderr


def _load_fixture_builder():
    spec = importlib.util.spec_from_file_location("create_fixtures", ROOT / "scripts" / "create-framework-fixtures.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fixture_builder_finds_composer_on_windows(monkeypatch, tmp_path):
    """FW: subprocess cannot start a bare "composer" on Windows: composer.phar runs through PHP,
    a lone .bat wrapper by its full path."""
    builder = _load_fixture_builder()
    bin_dir = tmp_path / "ComposerSetup" / "bin"
    bin_dir.mkdir(parents=True)
    bat, phar = bin_dir / "composer.bat", bin_dir / "composer.phar"
    bat.write_text("@php composer.phar %*\n")
    phar.write_text("<?php\n")
    monkeypatch.setattr(builder.sys, "platform", "win32")
    monkeypatch.setattr(builder.shutil, "which", lambda name: str(bat) if name == "composer" else None)
    assert builder.composer_command("C:/php/php.exe") == ["C:/php/php.exe", str(phar.resolve())]
    phar.unlink()
    assert builder.composer_command("C:/php/php.exe") == [str(bat.resolve())]
    assert builder.composer_command("php", str(tmp_path / "x" / "composer.phar"))[0] == "php"
    monkeypatch.setattr(builder.shutil, "which", lambda name: None)
    with pytest.raises(SystemExit, match="composer not found"):
        builder.composer_command("php")


def test_fixture_builder_reads_composer_lock_as_utf8(tmp_path):
    """FW: composer.lock is UTF-8 (authors' names...); the locale codec (cp1252) failed on it."""
    builder = _load_fixture_builder()
    lock = {"packages": [{"name": "laravel/framework", "version": "v12.0.0",
                          "authors": [{"name": "Taylor Otwell", "note": "caf\u00e9 \u2603 \u65e5\u672c"}]}]}
    (tmp_path / "composer.lock").write_bytes(json.dumps(lock, ensure_ascii=False).encode("utf-8"))
    assert builder.installed_version(tmp_path, "laravel/framework") == "v12.0.0"


def test_framework_smoke_refuses_unmarked_real_app(tmp_path):
    """The smoke test issues write requests; only explicit disposable fixtures are allowed."""
    app = tmp_path / "app"
    app.mkdir()
    sentinel = app / "keep.txt"
    sentinel.write_text("untouched")
    result = subprocess.run([sys.executable, str(SCRIPT), "--app", str(app), "--kind", "laravel"],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode != 0 and "fixture marker" in result.stderr
    assert sentinel.read_text() == "untouched"


def test_smoke_does_not_probe_an_unrelated_server_on_occupied_port(tmp_path):
    """An occupied port must not make two probes compare an unrelated app to itself."""
    import shutil
    import socket

    if not shutil.which('php'):
        pytest.skip('PHP is needed to test the development server')
    smoke = _load_smoke_script()
    (tmp_path / 'public').mkdir()
    (tmp_path / 'public' / 'index.php').write_text('<?php echo "fixture";')
    with socket.socket() as occupied:
        occupied.bind(('127.0.0.1', 0))
        occupied.listen()
        port = occupied.getsockname()[1]
        process = smoke.serve(tmp_path, port, None, 'symfony')
        try:
            with pytest.raises(RuntimeError, match='server.*(exit|start)'):
                smoke.wait_for(port, process, seconds=3)
        finally:
            process.terminate()
            process.wait(timeout=10)


def test_framework_probe_compares_http_headers_and_preserves_duplicates(monkeypatch):
    """Identical bodies do not make different Content-Type or cookie headers equivalent."""
    from email.message import Message

    smoke = _load_smoke_script()
    monkeypatch.setitem(smoke.ROUTES, 'test', [('GET', '/probe', None)])
    headers = Message()
    headers.add_header('Content-Type', 'application/json')
    headers.add_header('Set-Cookie', 'one=first; HttpOnly')
    headers.add_header('Set-Cookie', 'two=second; Secure')
    headers.add_header('Date', 'Mon, 01 Jan 2024 00:00:00 GMT')

    class Response:
        status = 200

        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def read(self): return b'{}'

        @property
        def headers(self): return headers

    monkeypatch.setattr(smoke, '_open_no_redirect', lambda *args, **kwargs: Response())
    original = smoke.probe(8123, 'test', [])
    headers.replace_header('Date', 'Tue, 02 Jan 2024 00:00:00 GMT')
    assert smoke.probe(8123, 'test', []) == original  # volatile clock header alone is irrelevant
    headers.replace_header('Content-Type', 'text/plain')
    assert smoke.probe(8123, 'test', []) != original
    headers.replace_header('Content-Type', 'application/json')
    headers.replace_header('Set-Cookie', 'one=changed; HttpOnly')
    assert smoke.probe(8123, 'test', []) != original


def test_framework_probe_normalizes_only_fixture_nondeterministic_cookies(monkeypatch):
    from email.message import Message

    smoke = _load_smoke_script()
    monkeypatch.setitem(smoke.ROUTES, 'laravel', [('GET', '/probe', None)])
    headers = Message()
    headers.add_header('Set-Cookie', 'XSRF-TOKEN=random1; expires=Wed, 04 Nov 2026 12:00:00 GMT; Max-Age=7200; path=/')
    headers.add_header('Set-Cookie', 'laravel-session=random2; Max-Age=7200; path=/; HttpOnly; SameSite=Lax')

    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def read(self): return b'{}'
        @property
        def headers(self): return headers

    monkeypatch.setattr(smoke, '_open_no_redirect', lambda *args, **kwargs: Response())
    baseline = smoke.probe(8123, 'laravel', [])
    headers.replace_header('Set-Cookie', 'XSRF-TOKEN=different; expires=Wed, 04 Nov 2026 12:01:00 GMT; Max-Age=7200; path=/')
    assert smoke.probe(8123, 'laravel', []) == baseline
    headers.replace_header('Set-Cookie', 'XSRF-TOKEN=different; expires=Wed, 04 Nov 2026 12:01:00 GMT; Max-Age=7200; path=/; Secure')
    assert smoke.probe(8123, 'laravel', []) != baseline


def test_framework_probe_compares_redirect_response_instead_of_following(monkeypatch):
    """A 302 can otherwise be hidden by the common 200 destination response."""
    import http.server
    import threading

    smoke = _load_smoke_script()
    monkeypatch.setitem(smoke.ROUTES, 'test', [('GET', '/redirect', None)])

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/redirect':
                self.send_response(302)
                self.send_header('Location', '/landing')
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'landing')

        def log_message(self, *_args):
            pass

    server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = smoke.probe(server.server_port, 'test', [])['00 GET /redirect']
        assert response[0] == 302
        assert response[2]['location'] == ['/landing']
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_framework_probe_keeps_cookies_within_each_run(monkeypatch):
    """A returned session cookie must be sent to the next request, but not across probes."""
    import http.server
    import threading

    smoke = _load_smoke_script()
    monkeypatch.setitem(smoke.ROUTES, 'test', [('GET', '/set', None), ('GET', '/read', None)])

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            if self.path == '/set':
                self.send_header('Set-Cookie', 'probe=token; Path=/; HttpOnly')
            self.end_headers()
            self.wfile.write(self.headers.get('Cookie', '').encode())

        def log_message(self, *_args):
            pass

    server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = smoke.probe(server.server_port, 'test', [])
        assert response['00 GET /set'][1] == b''
        assert response['01 GET /read'][1] == b'probe=token'
        second = smoke.probe(server.server_port, 'test', [])
        assert second['00 GET /set'][1] == b''  # the next app/run gets a fresh cookie jar
        assert second['01 GET /read'][1] == b'probe=token'
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_laravel_fixture_requires_actual_session_round_trip():
    """A fixture that emits cookies but loses the server session must fail."""
    import json

    smoke = _load_smoke_script()
    assert [('GET', '/session/write', None), ('GET', '/session/read', None)] == smoke.ROUTES['laravel'][-2:]
    contents = [
        {'pong': True}, {'widgets': []},
        {'service': r'App\Services\ProbeService', 'attributes': 1, 'table': 'widgets', 'attribute_name': 'reflection'},
        {'name': 'tornillo'}, {'widgets': [{'name': 'tornillo'}]}, {'errors': {'name': ['invalid']}}, {}, {},
        {'session': 'stored'}, {'session': 'envelock-probe'},
    ]
    responses = {f'{i:02d} {method} {path}': [smoke.EXPECTED_CODES['laravel'][i], json.dumps(contents[i]).encode()]
                 for i, (method, path, _data) in enumerate(smoke.ROUTES['laravel'])}
    smoke.assert_probe_exercises_fixture('laravel', responses)
    responses['09 GET /session/read'][1] = b'{"session":null}'
    with pytest.raises(SystemExit, match='session'):
        smoke.assert_probe_exercises_fixture('laravel', responses)


def test_session_handoff_requires_cookie_from_previous_run(monkeypatch):
    """The deployment check must use the prior app's cookie, not a new anonymous request."""
    import http.cookiejar
    import http.server
    import threading
    import urllib.request

    smoke = _load_smoke_script()
    monkeypatch.setitem(smoke.ROUTES, 'test', [('GET', '/set', None)])

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            if self.path == '/set':
                self.send_header('Set-Cookie', 'proof=123; Path=/')
            self.end_headers()
            if self.path == '/session/read':
                valid = 'proof=123' in self.headers.get('Cookie', '')
                self.wfile.write(b'{"session":"envelock-probe"}' if valid else b'{"session":null}')
            else:
                self.wfile.write(b'{}')

        def log_message(self, *_args):
            pass

    server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        opener.open(f'http://127.0.0.1:{server.server_port}/set').close()
        smoke.assert_session_handoff(server.server_port, jar, 'deploy')
        with pytest.raises(SystemExit, match='session.*handoff'):
            smoke.assert_session_handoff(server.server_port, http.cookiejar.CookieJar(), 'deploy')
    finally:
        server.shutdown()
        worker.join(timeout=5)
        server.server_close()


def test_session_handoff_copies_only_safe_fixture_files(tmp_path):
    smoke = _load_smoke_script()
    source, target, outside = tmp_path / 'before', tmp_path / 'after', tmp_path / 'outside'
    source_sessions = source / 'storage/framework/sessions'
    target_sessions = target / 'storage/framework/sessions'
    source_sessions.mkdir(parents=True)
    target_sessions.mkdir(parents=True)
    outside.write_text('unchanged')
    valid = 'A' * 40
    (source_sessions / valid).write_text('fixture session')
    (source_sessions / '.gitignore').write_text('not a session')
    _symlink_or_skip(source_sessions / ('B' * 40), outside)
    smoke.copy_fixture_sessions(source, target)
    assert (target_sessions / valid).read_text() == 'fixture session'
    assert not (target_sessions / '.gitignore').exists()
    assert not (target_sessions / ('B' * 40)).exists()
    (target_sessions / valid).unlink()
    _symlink_or_skip(target_sessions / valid, outside)
    with pytest.raises(SystemExit, match='symlink'):
        smoke.copy_fixture_sessions(source, target)
    assert outside.read_text() == 'unchanged'


def test_session_handoff_refuses_an_external_storage_path(tmp_path):
    smoke = _load_smoke_script()
    source, target, outside = tmp_path / 'before', tmp_path / 'after', tmp_path / 'external'
    (source / 'storage/framework').mkdir(parents=True)
    (target / 'storage/framework/sessions').mkdir(parents=True)
    outside.mkdir()
    (outside / ('A' * 40)).write_text('untouched')
    _symlink_or_skip(source / 'storage/framework/sessions', outside, directory=True)
    with pytest.raises(SystemExit, match='external session'):
        smoke.copy_fixture_sessions(source, target)
    assert (outside / ('A' * 40)).read_text() == 'untouched'

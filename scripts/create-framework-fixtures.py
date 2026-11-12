#!/usr/bin/env python3
"""Create disposable Laravel and Symfony fixtures for scripts/framework-smoke.py.

Requires Composer, PHP 8.4+, tokenizer, sqlite, mbstring and the frameworks' usual extensions.
The target directory must be empty: this tool never overwrites an existing application. Composer is
`composer` on PATH (on Windows also composer.bat / composer.phar, run through PHP), or --composer.

    python3 scripts/create-framework-fixtures.py --root /tmp/envelock-framework-fixtures
    ENVELOCK_FW_LARAVEL=/tmp/envelock-framework-fixtures/laravel \
    ENVELOCK_FW_SYMFONY=/tmp/envelock-framework-fixtures/symfony \
        python3 -m pytest tests/test_frameworks.py -q
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess  # nosec B404 - runs composer and php with fixed argument lists, no shell
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "frameworks"


def run(command: list[str], cwd: Path) -> None:
    env = dict(os.environ)
    env["COMPOSER_NO_INTERACTION"] = "1"
    subprocess.run(command, cwd=cwd, env=env, check=True, timeout=1200)  # nosec B603 - fixed local tools, no shell


def composer_command(php: str, explicit: str | None = None) -> list[str]:
    """How to run Composer here. subprocess cannot start a bare "composer" on Windows, where it is
    a composer.bat beside composer.phar (or only the .phar): the .phar is run through PHP, which
    also keeps the arguments away from cmd.exe; a lone .bat/.cmd wrapper is started by its path."""
    found = explicit or shutil.which("composer") or shutil.which("composer.phar")
    if not found:
        raise SystemExit("composer not found: put composer (composer.bat / composer.phar on Windows) "
                         "on PATH, or pass --composer")
    path = Path(found).resolve()
    if path.suffix.lower() == ".phar":
        return [php, str(path)]
    if sys.platform == "win32" and path.suffix.lower() not in (".exe", ".com"):
        phar = path.with_name("composer.phar")
        if phar.is_file():
            return [php, str(phar)]
        if path.suffix.lower() not in (".bat", ".cmd"):
            raise SystemExit(f"{path} cannot be run on Windows; pass --composer with composer.phar or composer.bat")
    return [str(path)]


def copy_fixture(kind: str, app: Path) -> None:
    for source in (FIXTURES / kind).rglob("*"):
        if source.is_file():
            target = app / source.relative_to(FIXTURES / kind)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)


def installed_version(app: Path, name: str) -> str:
    lock = json.loads((app / "composer.lock").read_text(encoding="utf-8"))
    return next((p["version"] for p in lock["packages"] if p["name"] == name), "unknown")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, required=True, help="An empty folder for the two disposable apps")
    parser.add_argument("--php", default=None, help="PHP CLI to use (default: php on PATH)")
    parser.add_argument("--composer", default=None,
                        help="Composer to use: composer, composer.bat or composer.phar (default: from PATH)")
    args = parser.parse_args()
    root = args.root.expanduser().resolve()
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise SystemExit(f"refusing to overwrite nonempty target: {root}")
    php = args.php or shutil.which("php")
    if not php:
        raise SystemExit("php not found: put a PHP 8.4+ CLI on PATH, or pass --php")
    composer = composer_command(php, args.composer)
    root.mkdir(parents=True, exist_ok=True)
    for kind, project in (("laravel", "laravel/laravel"), ("symfony", "symfony/skeleton")):
        app = root / kind
        command = [*composer, "create-project", project, str(app), "--no-interaction", "--prefer-dist"]
        if kind == "laravel":
            # The fresh skeleton's scripts expect .env before it exists. Set it up explicitly below.
            command.append("--no-scripts")
        run(command, root)
        copy_fixture(kind, app)
        if kind == "laravel":
            shutil.copy2(app / ".env.example", app / ".env")
            run([php, "artisan", "key:generate", "--force", "--no-interaction"], app)
            database = app / "database" / "database.sqlite"
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE widgets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)")
        # The smoke script issues write requests and therefore refuses unmarked applications.
        (app / ".envelock-smoke-fixture").write_text(kind + "\n", encoding="utf-8")
        package = "laravel/framework" if kind == "laravel" else "symfony/framework-bundle"
        print(f"{kind}: {installed_version(app, package)} -> {app}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

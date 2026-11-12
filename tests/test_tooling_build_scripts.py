"""Build scripts and CI: the guarantees they promise, checked without compiling anything.

Behavioural where a check can run on its own (a refusal that happens before any build step, a
security gate fed a fake `nm`), static otherwise. Nothing here compiles or downloads.
"""

import os
import re
import shutil
import subprocess
import sys

import pytest
from test_encoder import ROOT

SCRIPTS = ROOT / "scripts"
BASH = shutil.which("bash")
if BASH and "system32" in BASH.lower():      # the WSL launcher: not a bash for these paths
    BASH = None


def _text(relative):
    return (ROOT / relative).read_text(encoding="utf-8")


# ----------------------------------------------------------------- extension/config.m4

def test_config_m4_has_no_previous_minor_fallback_for_the_bytecode_layer():
    """T-7: PHP 8.6 must not compile opcache/php85 against 8.6 headers; like config.w32 and the
    Wine builder, a PHP without its exact layer builds source-only (with a warning)."""
    text = _text("extension/config.m4")
    assert "$2 - 1" not in text and "($2-1)" not in text
    assert text.count('ENVELOCK_PHP_MM=`') == 1
    assert "no bytecode layer for PHP" in text                       # the source-only warning stays


def test_config_m4_hides_the_extension_symbols_in_a_plain_phpize_build():
    """T-17: -fvisibility=hidden is part of the extension's own flags, not only build-unix.sh's."""
    text = _text("extension/config.m4")
    call = text[text.index("PHP_NEW_EXTENSION([envelock]"):]
    extra = call.split("[$ext_shared], [],", 1)[1].split("]", 1)[0]
    assert "-fvisibility=hidden" in extra


# ------------------------------------------------------------- _FORTIFY_SOURCE (T-18)

@pytest.mark.parametrize("script", ["build-unix.sh", "build-static-php.sh"])
def test_fortify_level_is_never_lowered(script):
    """-D_FORTIFY_SOURCE=2 appended last lowered a toolchain default of 3: level 3 where the
    compiler supports it, else 2, always after -U_FORTIFY_SOURCE."""
    text = (SCRIPTS / script).read_text(encoding="utf-8")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "-D_FORTIFY_SOURCE=2" not in code
    assert "-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=$fortify" in text
    assert "-D_FORTIFY_SOURCE=3 -Werror" in text and "fortify=3" in text and "fortify=2" in text


@pytest.mark.skipif(BASH is None, reason="bash is needed")
@pytest.mark.parametrize("cc,expected", [("false", "2"), ("true", "3")])
def test_fortify_probe_picks_the_level_the_compiler_accepts(tmp_path, cc, expected):
    """The probe itself, with a compiler stand-in that refuses (false) or accepts (true) level 3."""
    text = (SCRIPTS / "build-unix.sh").read_text(encoding="utf-8")
    probe = text[text.index("fortify=2\n"):text.index("base_cflags=")]
    result = subprocess.run([BASH, "-c", probe + 'printf %s "$fortify"'], env=dict(os.environ, CC=cc),
                            capture_output=True, text=True, timeout=60)
    assert result.stdout == expected, result.stderr


# ------------------------------------------------- build-static-php.sh export gate (T-15)

def _static_gate():
    text = (SCRIPTS / "build-static-php.sh").read_text(encoding="utf-8")
    return text[text.index("command -v nm >/dev/null"):text.index("# Load-test with no -d extension=")]


def _run_gate(tmp_path, nm_body, uname="Linux"):
    """Run the gate alone with stand-ins for nm and uname on PATH (no binary is built)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    for name, body in (("nm", nm_body), ("uname", f"echo {uname}")):
        if body is None:
            continue
        tool = bin_dir / name
        tool.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8", newline="\n")
        tool.chmod(0o755)
    for name in ("awk", "grep"):             # the only other programs the gate runs
        real = shutil.which(name)
        if real:
            (bin_dir / name).write_text(f'#!/bin/sh\nexec "{_posix(real)}" "$@"\n', encoding="utf-8",
                                        newline="\n")
            (bin_dir / name).chmod(0o755)
    script = "set -euo pipefail\nbinary=/nonexistent/php\n" + _static_gate() + "echo GATE-PASSED\n"
    return subprocess.run([BASH, "--noprofile", "--norc", "-c", f'PATH="$1"; {script}', "gate",
                           _posix(str(bin_dir))], capture_output=True, text=True, timeout=60)


def _posix(path):
    """A path for bash's PATH: Git Bash on Windows wants /c/... rather than C:\\..."""
    if sys.platform != "win32":
        return path
    drive, rest = os.path.splitdrive(path)
    return "/" + drive.rstrip(":").lower() + rest.replace("\\", "/")


@pytest.mark.skipif(BASH is None, reason="bash is needed")
@pytest.mark.parametrize("nm_body,uname,passes,message", [
    ("echo '0000000000001000 T zend_execute'", "Linux", True, ""),
    ("echo '0000000000001000 T envelock_decrypt'", "Linux", False, "SECURITY"),
    ("echo 'nm: cannot read' >&2; exit 1", "Linux", False, "could not list"),
    (None, "Linux", False, "Missing tool: nm"),
    ('[ "$1" = -gU ] || exit 9; echo "0000000100001000 T _envelock_unwrap_key"', "Darwin", False, "SECURITY"),
    ('[ "$1" = -gU ] || exit 9; echo "0000000100001000 T _main"', "Darwin", True, ""),
], ids=["clean", "exported", "nm-fails", "no-nm", "macos-exported", "macos-clean"])
def test_static_build_export_gate_fails_closed(tmp_path, nm_body, uname, passes, message):
    """T-15: `if nm ... | awk | grep -q` PASSED when nm was missing or failed (and on macOS, which
    has no `nm -D`). The gate now fails unless nm actually listed the exports and none is ours."""
    result = _run_gate(tmp_path, nm_body, uname)
    assert ("GATE-PASSED" in result.stdout) is passes, (result.stdout, result.stderr)
    if not passes:
        assert result.returncode == 1 and message in result.stderr, result.stderr


# ------------------------------------------------------------ Windows builders (T-16)

@pytest.mark.skipif(BASH is None, reason="bash is needed")
@pytest.mark.parametrize("asked,lib,dll", [("ts", "php8.lib", "php8.dll"), ("nts", "php8ts.lib", "php8ts.dll"),
                                           ("ts", "php8ts.lib", "php8.dll")])
def test_wine_builder_refuses_a_thread_safety_mismatch_before_building(tmp_path, asked, lib, dll):
    """A ts DLL compiled against an nts devel pack (or zip) builds and then fails to load; the
    builder now stops first. Nothing is compiled: the refusal comes before any tool runs."""
    folders = {}
    for name in ("MSVC", "WINSDK", "WINSDK64", "OPENSSL", "PHPDEV", "PHPZIP"):
        folders[name] = tmp_path / name.lower()
        folders[name].mkdir()
    (folders["PHPDEV"] / "lib").mkdir()
    (folders["PHPDEV"] / "lib" / lib).write_bytes(b"")
    (folders["PHPZIP"] / dll).write_bytes(b"")
    env = dict(os.environ, **{name: _posix(str(path)) for name, path in folders.items()})
    result = subprocess.run([BASH, _posix(str(SCRIPTS / "build-windows-wine.sh")), asked,
                             _posix(str(tmp_path / "out.dll"))],
                            env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 2 and "Thread-safety mismatch" in result.stderr, result.stderr
    assert not (tmp_path / "out.dll").exists()


def test_windows_builder_gates_exposure_runs_the_native_suite_and_restores_path():
    """T-16 and the native-run findings: the production DLL is asked whether it exposes
    envelock_bc_emit / envelock_bc_run; -Owner/-Recipient run tests/test_native.py (not the whole
    tree) and a failure keeps the DLL; the persistent PATH the official module edits is restored."""
    text = (SCRIPTS / "build-windows.ps1").read_text(encoding="utf-8")
    assert "function_exists('envelock_bc_run') || function_exists('envelock_bc_emit')" in text
    assert "python -m pytest -q tests/test_native.py" in text
    assert not re.search(r"pytest -q tests\s*$", text, re.M)
    assert "$keepOutput = $true" in text and "-not $keepOutput" in text
    assert "GetEnvironmentVariable('Path', $scope)" in text
    assert "SetEnvironmentVariable('Path', $persistentPath[$scope], $scope)" in text
    assert "envelock-recipient-public" in text and "PRIVATE recipient" in text


@pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell")
def test_windows_builder_refuses_a_public_recipient_before_building(tmp_path):
    """The docs passed test_recip.pub, which the native suite cannot read ("Incorrect config
    kind") only after a full build; the builder now refuses it up front. Nothing is built: the
    check comes before the module and the SDK are even looked for."""
    import json
    owner, pub = tmp_path / "test_owner.json", tmp_path / "test_recip.pub"
    owner.write_text(json.dumps({"kind": "envelock-owner", "format": 2}), encoding="utf-8")
    pub.write_text(json.dumps({"kind": "envelock-recipient-public", "format": 2}), encoding="utf-8")
    powershell = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32",
                              "WindowsPowerShell", "v1.0", "powershell.exe")
    result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                             "-File", str(SCRIPTS / "build-windows.ps1"), "-PhpVersion", "8.4",
                             "-OutputDirectory", str(tmp_path / "out"), "-Owner", str(owner),
                             "-Recipient", str(pub)],
                            capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
    assert result.returncode != 0
    assert "PRIVATE recipient" in result.stdout + result.stderr, result.stdout + result.stderr
    assert not (tmp_path / "out").exists()


# ----------------------------------------------------------------------- build-gui.sh (T-21)

def test_gui_builder_does_not_play_down_an_unpinned_pyinstaller():
    text = (SCRIPTS / "build-gui.sh").read_text(encoding="utf-8")
    assert "shipped keys are unaffected" not in text
    assert "private keys" in text and "WITHOUT hash verification" in text


# ------------------------------------------------------------------------------ CI (T-20)

def test_ci_lints_and_audits_the_assistant_and_every_script():
    text = _text(".github/workflows/checks.yml")
    ruff = next(line.strip() for line in text.splitlines() if line.strip().startswith("ruff check"))
    bandit = next(line.strip() for line in text.splitlines() if line.strip().startswith("bandit "))
    for command in (ruff, bandit):
        words = command.split()
        assert "gui" in words and "scripts" in words and "encoder" in words, command

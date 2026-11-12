"""The command launchers run the portable Python next to them, never one from the current folder."""

import os
import shutil
import subprocess
import sys

import pytest
from test_encoder import ROOT

PORTABLE = ROOT / "prebuilt" / "python" / "windows-x64" / "python.exe"


@pytest.mark.skipif(sys.platform != "win32", reason="envelock.cmd is the Windows launcher")
def test_cmd_launcher_found_through_path_ignores_a_python_planted_in_the_current_folder(tmp_path):
    """T-6: run through PATH under a quoted name (`call "envelock"`), %~dp0 at the top level of a
    batch file expands to the CURRENT folder, so CWD\\prebuilt\\python\\windows-x64\\python.exe ran
    instead of the launcher's own. The decoy here is a harmless copy of whoami.exe: if it ran, the
    encoder's usage text would be missing."""
    if not PORTABLE.is_file():
        pytest.skip("no portable Python in prebuilt/python/windows-x64")
    system32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    decoy = tmp_path / "prebuilt" / "python" / "windows-x64" / "python.exe"
    decoy.parent.mkdir(parents=True)
    shutil.copy2(os.path.join(system32, "whoami.exe"), decoy)
    env = dict(os.environ, PATH=f"{ROOT};{system32}")
    env.pop("ROOT", None)
    for command in ('call "envelock" --help', "call envelock --help", '"envelock" --help'):
        # A string command line: the quotes must reach cmd.exe exactly as a user types them.
        result = subprocess.run(f"cmd /d /c {command}", cwd=tmp_path, env=env, capture_output=True,
                                text=True, stdin=subprocess.DEVNULL, timeout=300)
        assert result.returncode == 0 and "usage" in result.stdout.lower(), (command, result.stdout, result.stderr)
    # The exit status still passes through, and the launcher leaves no ROOT variable behind in the
    # calling cmd session (setlocal).
    result = subprocess.run('cmd /d /c "call envelock definitely-not-a-command & set ROOT"', cwd=tmp_path,
                            env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=300)
    assert "ROOT=" not in result.stdout, result.stdout
    result = subprocess.run('cmd /d /c call "envelock" definitely-not-a-command', cwd=tmp_path, env=env,
                            capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=300)
    assert result.returncode == 2, (result.stdout, result.stderr)


def test_cmd_launcher_resolves_its_folder_inside_a_called_label():
    """The fix itself, checked on any OS: the launcher's folder is read in a subroutine."""
    raw = (ROOT / "envelock.cmd").read_bytes()
    assert raw.endswith(b"\r\n") and b"\n" not in raw.replace(b"\r\n", b"")   # CRLF throughout
    text = raw.decode("ascii")
    assert "\r\ncall :root\r\n" in text and '\r\n:root\r\nset "ROOT=%~dp0"\r\n' in text
    top_level = text.split("\r\n:root\r\n", 1)[0]
    code = [line for line in top_level.split("\r\n") if not line.lower().startswith("rem ")]
    assert not any("%~dp0" in line for line in code), "a top-level %~dp0 can resolve to the CWD"

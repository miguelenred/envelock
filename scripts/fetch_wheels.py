#!/usr/bin/env python3
"""Download the official wheels of Envelock's runtime libraries into prebuilt/python-wheels/.

For every system folder and Python version it takes, from requirements.lock, the packages the
encoder and the assistant need at run time (cryptography and its dependencies), evaluates each
lock entry's environment marker for THAT Python version (pip's --python-version does not), and
runs `pip download --require-hashes`, so every file matches the pinned hashes. Maintainers only;
afterwards regenerate prebuilt/SHA256SUMS (docs/BUILDING.md, section 7).

    python scripts/fetch_wheels.py [destination]
"""
from __future__ import annotations

import os
import re
import subprocess  # nosec B404 # runs this interpreter's own pip with fixed arguments
import sys
import tempfile
from pathlib import Path

from pip._vendor.packaging.markers import Marker

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ("cryptography", "cffi", "pycparser", "typing-extensions")
PYTHONS = ("3.10", "3.11", "3.12", "3.13", "3.14")
SYSTEMS = {
    "win_amd64": ("win_amd64",),
    "linux_x86_64": ("manylinux_2_28_x86_64", "manylinux_2_17_x86_64", "manylinux2014_x86_64"),
    "linux_aarch64": ("manylinux_2_28_aarch64", "manylinux_2_17_aarch64", "manylinux2014_aarch64"),
    "macos_arm64": ("macosx_11_0_arm64",),
}


def requirements_for(python: str) -> str:
    """The RUNTIME entries of requirements.lock that apply to CPython `python`, markers removed."""
    env = {"python_version": python, "python_full_version": python + ".0",
           "implementation_name": "cpython", "platform_python_implementation": "CPython"}
    chosen = []
    for block in re.split(r"\n(?=[a-z])", (ROOT / "requirements.lock").read_text(encoding="utf-8")):
        head = block.split("\\", 1)[0]
        name, _, marker = head.partition(";")
        if name.split("==")[0].strip() not in RUNTIME:
            continue
        if marker.strip() and not Marker(marker.strip()).evaluate(env):
            continue
        chosen.append(name.strip() + " \\" + block.split("\\", 1)[1])
    return "\n".join(chosen) + "\n"


def main() -> int:
    dest = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "prebuilt" / "python-wheels"
    for python in PYTHONS:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as req:
            req.write(requirements_for(python))
        try:
            for folder, tags in SYSTEMS.items():
                platforms = [arg for tag in tags for arg in ("--platform", tag)]
                subprocess.run(  # nosec B603 # fixed command, hash-pinned requirements
                    [sys.executable, "-m", "pip", "download", "--quiet", "--no-deps",
                     "--only-binary=:all:", *platforms, "--python-version", python,
                     "--implementation", "cp", "--require-hashes", "-r", req.name,
                     "-d", str(dest / folder)], check=True)
        finally:
            os.unlink(req.name)
    print(f"Wheels in {dest}. Now regenerate prebuilt/SHA256SUMS (docs/BUILDING.md, section 7).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

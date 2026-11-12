"""PIE support: composer.json and the Release assets PIE downloads (scripts/package-pie-assets.py).

PIE looks for assets by exact name, so a wrong name is a silent "no binary found" for users: these
tests pin the names against PIE's own scheme (src/Platform/WindowsExtensionAssetName.php and
PrePackagedBinaryAssetName.php in php/pie) and check what the ZIPs contain.
"""

import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "package-pie-assets.py"
spec = importlib.util.spec_from_file_location("package_pie_assets", SCRIPT)
pie = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pie)


def test_composer_json_describes_the_loader_for_pie():
    data = json.loads((ROOT / "composer.json").read_text(encoding="utf-8"))
    assert data["type"] == "php-ext"
    assert re.fullmatch(r"[a-z0-9-]+/[a-z0-9-]+", data["name"])
    ext = data["php-ext"]
    assert ext["extension-name"] == "envelock"
    build = ROOT / ext["build-path"]
    assert (build / "config.m4").is_file() and (build / "config.w32").is_file()
    assert 'PHP_ARG_ENABLE([envelock]' in (build / "config.m4").read_text(encoding="utf-8")
    assert ext["download-url-method"] == ["pre-packaged-binary", "composer-default"]
    # Supported engines only: the range must admit 8.2-8.5 and nothing outside them.
    assert data["require"]["php"] == ">=8.2.0 <8.6.0"
    # No configure option may expose the bytecode emitter or the unsafe runner (ENV-2026-02).
    assert not any("bc" in option.get("name", "") for option in ext.get("configure-options", []))


def test_asset_names_follow_pies_scheme():
    assert pie.windows_asset("1.0.0", "8.4", "nts", "vs17") == "php_envelock-1.0.0-8.4-nts-vs17-x86_64"
    assert pie.windows_asset("1.0.0", "8.2", "ts", "vs16") == "php_envelock-1.0.0-8.2-ts-vs16-x86_64"
    assert pie.linux_asset("1.0.0", "8.4", "zts") == "php_envelock-1.0.0_php8.4-x86_64-linux-glibc-zts"
    assert pie.linux_asset("1.0.0", "8.5", "nts") == "php_envelock-1.0.0_php8.5-x86_64-linux-glibc-nts"


def _run(*args):
    return subprocess.run([sys.executable, "-B", str(SCRIPT), *map(str, args)],
                          capture_output=True, text=True, check=False)


def test_rejects_a_v_prefixed_version(tmp_path):
    result = _run("--version", "v1.0.0", "--out", tmp_path / "out")
    assert result.returncode != 0 and "bare tag" in result.stderr
    assert not (tmp_path / "out").exists()


@pytest.mark.skipif(not (ROOT / "prebuilt" / "loader").is_dir(), reason="source-only tree: no prebuilt loaders")
def test_packages_every_prebuilt_loader(tmp_path):
    out = tmp_path / "pie"
    result = _run("--version", "1.0.0", "--out", out)
    assert result.returncode == 0, result.stderr
    names = sorted(p.name for p in out.glob("*.zip"))
    windows = [n for n in names if "-linux-" not in n]
    linux = [n for n in names if "-linux-" in n]
    assert len(windows) == len(list((ROOT / "prebuilt/loader/windows-x64").glob("*/php_envelock.dll")))
    assert len(linux) == len(list((ROOT / "prebuilt/loader/linux-x86_64").glob("*/envelock.so")))
    for name in windows:
        members = zipfile.ZipFile(out / name).namelist()
        assert members[0] == name[:-4] + ".dll" and {"LICENSE", "NOTICE"} <= set(members)
    for name in linux:
        members = zipfile.ZipFile(out / name).namelist()
        assert members[0] == "envelock.so" and {"LICENSE", "NOTICE"} <= set(members)
    listed = dict(reversed(line.split("  ", 1)) for line in (out / "SHA256SUMS").read_text().splitlines())
    assert sorted(listed) == names
    for name in names:
        assert listed[name] == hashlib.sha256((out / name).read_bytes()).hexdigest()
    # Deterministic: the same input gives byte-identical assets.
    again = tmp_path / "again"
    assert _run("--version", "1.0.0", "--out", again).returncode == 0
    assert (again / "SHA256SUMS").read_text() == (out / "SHA256SUMS").read_text()


@pytest.mark.skipif(not (ROOT / "prebuilt" / "loader" / "windows-x64").is_dir(), reason="no prebuilt Windows loaders")
def test_refuses_a_binary_that_is_not_the_listed_one(tmp_path):
    fake = tmp_path / "prebuilt"
    rel = "loader/windows-x64/php-8.4-nts/php_envelock.dll"
    (fake / rel).parent.mkdir(parents=True)
    data = bytearray((ROOT / "prebuilt" / rel).read_bytes())
    (fake / "SHA256SUMS").write_text(f"{hashlib.sha256(data).hexdigest()}  {rel}\n")
    data[-1] ^= 1
    (fake / rel).write_bytes(bytes(data))
    result = _run("--version", "1.0.0", "--prebuilt", fake, "--out", tmp_path / "out")
    assert result.returncode != 0 and "SHA256SUMS" in result.stderr
    assert not (tmp_path / "out").exists()
    shutil.rmtree(fake)

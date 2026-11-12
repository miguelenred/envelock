"""The committed binaries in prebuilt/: every file matches SHA256SUMS, and the loader built for
the local PHP really decrypts and runs a protected file (skipped where none matches)."""

import hashlib
import importlib.util
import platform
import shutil
import subprocess
import sys

import pytest
from test_encoder import ROOT, a
from test_native import package, php, write_identity

PREBUILT = ROOT / "prebuilt"
_spec = importlib.util.spec_from_file_location("check_release", ROOT / "scripts" / "check_release.py")
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)


@pytest.mark.parametrize("folder", guard.MANIFEST_DIRS)
def test_every_file_is_listed_with_its_hash(folder):
    """prebuilt/ and third_party/ match their SHA256SUMS exactly (same parser and matching as the
    guard). On a case-insensitive filesystem (NTFS; probed, not assumed from the OS) listed names
    that differ only by case cannot coexist: the one file present stands for its group and must
    carry one of their hashes; an unlisted, altered or missing file still fails."""
    sums = guard.load_sums(ROOT, folder)
    base = ROOT / folder
    variants = guard.case_variants(sums) if guard.case_insensitive(base / "SHA256SUMS") else None
    present = {p.relative_to(ROOT).as_posix(): p for p in base.rglob("*") if p.is_file()
               and not (p.parent == base and p.name in guard.MANIFEST_EXEMPT)
               and not guard.SKIP_ANYWHERE.intersection(p.relative_to(base).parts)}  # runtime caches
    accounted = set()
    for rel, path in sorted(present.items()):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        status, names = guard.match_listed(rel, digest, sums, variants)
        assert status == "ok", f"{rel}: {status}"
        accounted.update(names)
    missing = sorted(set(sums) - accounted)
    assert not missing, f"{len(missing)} listed file(s) missing from {folder}/, e.g. {missing[:5]}"


def local_loader():
    """prebuilt/loader/<os-arch>/php-X.Y-<nts|zts>/envelock.so for the `php` on PATH, if any."""
    libc, version = platform.libc_ver()
    if (not shutil.which("php") or sys.platform != "linux" or platform.machine() != "x86_64"
            or libc != "glibc" or tuple(map(int, version.split(".")[:2])) < (2, 33)):
        return None                       # the committed loaders need Linux x86-64, glibc 2.33+
    info = subprocess.run(["php", "-n", "-r", 'echo PHP_MAJOR_VERSION, ".", PHP_MINOR_VERSION, " ",'
                           ' (int) PHP_ZTS, " ", (int) PHP_DEBUG;'],
                          capture_output=True, text=True, check=True).stdout.split()
    if info[2] == "1":
        return None                       # debug builds of PHP have their own module ABI
    module = PREBUILT / "loader" / "linux-x86_64" / f"php-{info[0]}-{'zts' if info[1] == '1' else 'nts'}" / "envelock.so"
    return module if module.is_file() else None


def test_committed_linux_loaders_export_no_envelock_symbols():
    """The committed Linux loaders must export none of their own symbols (M-01): the hardened
    build strips them, so another extension cannot dlsym the decryption API. A loader built with
    plain `phpize` would export ~23 (envelock_decrypt, envelock_unwrap_key, …)."""
    if not (PREBUILT / "SHA256SUMS").is_file():
        pytest.skip("no prebuilt/ in this source tree (ENV-AUD-19)")
    if not shutil.which("nm"):
        pytest.skip("nm not available")
    loaders = sorted((PREBUILT / "loader" / "linux-x86_64").glob("php-*/envelock.so"))
    assert loaders, "no committed Linux loaders found"
    for so in loaders:
        out = subprocess.run(["nm", "-D", "--defined-only", str(so)],
                             capture_output=True, text=True, check=True).stdout
        exported = [line for line in out.splitlines() if "envelock_" in line]
        assert not exported, f"{so.name} exports Envelock symbols: {exported[:3]}"


def test_prebuilt_loader_runs_a_protected_file(tmp_path):
    module = local_loader()
    if module is None:
        pytest.skip("no prebuilt loader for this system/PHP")
    owner, recipient = a.make_owner(), a.make_recipient("prebuilt-test")
    identity = tmp_path / "identity.bin"
    write_identity(identity, [a.make_identity(recipient, owner)])
    native = (tmp_path, module, owner, recipient, identity)
    out = package(native, tmp_path, {"index.php": "<?php echo 'prebuilt ', 6 * 7;"})
    result = php(native, out / "index.php")
    assert result.returncode == 0 and result.stdout == "prebuilt 42", result.stderr

"""Package the prebuilt loaders as the GitHub Release assets that PIE downloads.

Usage:
    python scripts/package-pie-assets.py --version 1.0.0 [--prebuilt prebuilt] [--out dist/pie]

PIE (the PHP Installer for Extensions, https://github.com/php/pie) installs `envelock/loader` from
Packagist and, for each server, looks in the GitHub Release of that version for an asset with an
exact name (docs/BUILDING.md, "Publishing a release for PIE"):

  Windows  php_envelock-{version}-{8.x}-{nts|ts}-{vs16|vs17}-x86_64.zip
           holding the DLL under the same base name (PIE installs it as ext\\php_envelock.dll),
           plus LICENSE and NOTICE (PIE puts other files in php\\extras\\envelock\\).
  Linux    php_envelock-{version}_php{8.x}-x86_64-linux-glibc-{nts|zts}.zip
           holding envelock.so at the top level (plus LICENSE and NOTICE).

Every binary must be listed with its hash in prebuilt/SHA256SUMS (the tested build, nothing else).
Each DLL's compiler tag is read from its PE header (linker 14.2x = vs16, 14.3x/14.4x = vs17) and must
match the compiler of the official PHP build for that minor. The ZIPs are deterministic, and a
SHA256SUMS of the assets is written next to them. An existing output folder is never overwritten.
"""

import argparse
import hashlib
import re
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXTENSION = "envelock"
PHP_MINORS = ("8.2", "8.3", "8.4", "8.5")
OFFICIAL_COMPILER = {"8.2": "vs16", "8.3": "vs16", "8.4": "vs17", "8.5": "vs17"}
ZIP_DATE = (2026, 1, 1, 0, 0, 0)
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-?(?:alpha|beta|RC|rc)[0-9]*)?$")


def windows_asset(version, minor, ts, compiler):
    return f"php_{EXTENSION}-{version}-{minor}-{ts}-{compiler}-x86_64"


def linux_asset(version, minor, ts):
    return f"php_{EXTENSION}-{version}_php{minor}-x86_64-linux-glibc-{ts}"


def pe_compiler(data):
    """vs16/vs17 from the linker version of an x64 PE image, or raise ValueError."""
    if data[:2] != b"MZ":
        raise ValueError("not a PE image")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE image")
    machine = struct.unpack_from("<H", data, pe + 4)[0]
    if machine != 0x8664:
        raise ValueError(f"not an x64 image (machine 0x{machine:04x})")
    optional = pe + 24
    major, minor = data[optional + 2], data[optional + 3]
    if major == 14 and 20 <= minor <= 29:
        return "vs16"
    if major == 14 and minor >= 30:
        return "vs17"
    raise ValueError(f"unexpected linker version {major}.{minor}")


def is_elf_x86_64(data):
    return data[:4] == b"\x7fELF" and data[4] == 2 and struct.unpack_from("<H", data, 18)[0] == 62


def deterministic_zip(path, members):
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in members:
            info = zipfile.ZipInfo(name, date_time=ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True, help="release version = the git tag, without a leading 'v'")
    parser.add_argument("--prebuilt", default=str(ROOT / "prebuilt"))
    parser.add_argument("--out", default=str(ROOT / "dist" / "pie"))
    args = parser.parse_args(argv)
    if not VERSION_RE.match(args.version):
        sys.exit(f"version {args.version!r}: use the bare tag, e.g. 1.0.0 (PIE matches asset names on it)")
    prebuilt, out = Path(args.prebuilt), Path(args.out)
    sums = {}
    for line in (prebuilt / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        if "  " in line:
            digest, name = line.split("  ", 1)
            sums[name.lstrip("*")] = digest
    extras = [(name, (ROOT / name).read_bytes()) for name in ("LICENSE", "NOTICE")]

    plan = []
    for minor in PHP_MINORS:
        for ts in ("nts", "ts"):
            rel = f"loader/windows-x64/php-{minor}-{ts}/php_{EXTENSION}.dll"
            if (prebuilt / rel).is_file():
                plan.append(("windows", minor, ts, rel))
        for ts in ("nts", "zts"):
            rel = f"loader/linux-x86_64/php-{minor}-{ts}/{EXTENSION}.so"
            if (prebuilt / rel).is_file():
                plan.append(("linux", minor, ts, rel))
    if not plan:
        sys.exit(f"no loaders under {prebuilt / 'loader'}")
    if out.exists():
        sys.exit(f"refusing to overwrite {out}")

    built = []
    errors = []
    for system, minor, ts, rel in plan:
        data = (prebuilt / rel).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if sums.get(rel) != digest:
            errors.append(f"{rel}: not listed in prebuilt/SHA256SUMS with this hash")
            continue
        if system == "windows":
            try:
                compiler = pe_compiler(data)
            except ValueError as error:
                errors.append(f"{rel}: {error}")
                continue
            if compiler != OFFICIAL_COMPILER[minor]:
                errors.append(f"{rel}: built with {compiler}, but PHP {minor} for Windows uses {OFFICIAL_COMPILER[minor]}")
                continue
            base = windows_asset(args.version, minor, ts, compiler)
            members = [(base + ".dll", data)] + extras
        else:
            if not is_elf_x86_64(data):
                errors.append(f"{rel}: not an x86-64 ELF object")
                continue
            base = linux_asset(args.version, minor, ts)
            members = [(f"{EXTENSION}.so", data)] + extras
        built.append((base + ".zip", members))
    if errors:
        sys.exit("nothing written:\n  " + "\n  ".join(errors))

    out.mkdir(parents=True)
    lines = []
    for name, members in built:
        deterministic_zip(out / name, members)
        lines.append(f"{hashlib.sha256((out / name).read_bytes()).hexdigest()}  {name}")
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{len(built)} PIE assets in {out}:")
    for name, _ in built:
        print("  " + name)
    return 0


if __name__ == "__main__":
    sys.exit(main())

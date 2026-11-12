"""Measure the per-file cost of protected PHP versus plain PHP.

Usage: python scripts/bench.py /path/to/envelock.so [php-binary]

Generates N small PHP files (~1.9 KB), packs them for a throw-away identity, and times
including all of them inside one PHP process (OPcache off). Reports the minimum of several
runs in microseconds per file. Keys and files live in a temporary directory that is removed.

It also packs the same tree in bytecode mode (objective O1) and reports it, because the two
modes have opposite cost profiles: source mode pays compilation per request, bytecode mode pays
deserialization of a much larger payload instead. Timing them in one process, as here, is what
makes the comparison meaningful — a cold `php` process drowns both in start-up noise.
"""

import os
import subprocess  # nosec B404 # runs the local php binary with an argument list
import sys
import tempfile
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "encoder"))
import envelock as a  # noqa: E402

FILES, RUNS = 300, 7
LOOP = '$t=hrtime(true); foreach (glob($argv[1]."/f*.php") as $f) require $f; echo hrtime(true)-$t;'



def run(php, extension, identity, directory):
    args = [php, "-n", "-d", "opcache.enable_cli=0"]
    if extension:
        args += ["-d", f"extension={extension}", "-d", f"envelock.identity={identity}"]
    best = None
    for _ in range(RUNS):
        out = subprocess.run([*args, "-r", LOOP, str(directory)], capture_output=True,  # nosec B603
                             text=True, check=True).stdout
        best = int(out) if best is None else min(best, int(out))
    return best / 1000 / FILES


def main():
    extension = Path(sys.argv[1]).resolve()
    php = sys.argv[2] if len(sys.argv) > 2 else "php"
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        plain = tmp / "plain"
        plain.mkdir()
        body = "".join(f"    $v[] = 'line {j} of a typical application file';\n" for j in range(40))
        for i in range(FILES):
            (plain / f"f{i:04d}.php").write_text(
                f"<?php\nfunction f{i}() {{\n    $v = [];\n{body}    return $v;\n}}\n")
        owner, recipient = a.make_owner(), a.make_recipient("bench")
        identity = tmp / "identity.bin"
        fd = os.open(identity, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(a.identity_bundle_bytes([a.make_identity(recipient, owner)]))
        protected = tmp / "protected"
        a.pack_tree(plain, protected, [a.recipient_public(recipient)], owner, str(uuid.uuid4()))
        # Bytecode mode compiles each source at its deploy path, so the deploy root must be a
        # sibling of the sources (pack refuses a destination nested in the source tree).
        deploy = tmp / "deploy"
        bytecode = tmp / "bytecode"
        a.pack_tree(plain, bytecode, [a.recipient_public(recipient)], owner, str(uuid.uuid4()),
                    bytecode=True, bytecode_loader=str(extension), deploy_root=deploy)
        deployed = tmp / "deployed"
        deployed.mkdir()
        for item in sorted(bytecode.rglob("f*.php")):
            (deployed / item.name).write_bytes(item.read_bytes())
        version = subprocess.run([php, "-n", "-r", "echo PHP_VERSION;"], capture_output=True,  # nosec B603
                                 text=True, check=True).stdout
        base = run(php, None, None, plain)
        prot = run(php, extension, identity, protected)
        code = run(php, extension, identity, deployed)
        print(f"PHP {version}: plain {base:.0f} us/file, protected {prot:.0f} us/file, "
              f"overhead {prot - base:.0f} us/file ({FILES} files, min of {RUNS} runs)")
        print(f"  bytecode mode: {code:.0f} us/file "
              f"({code - prot:+.0f} us/file against source mode, {code - base:+.0f} against plain)")



if __name__ == "__main__":
    main()

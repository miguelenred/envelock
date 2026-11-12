#!/usr/bin/env python3
"""A/B lab-VM packaging with and without the compiler fingerprint checks.

The baseline temporarily removes only the new fingerprint/check lines in an isolated module; both
arms compile the same function with the same real V2 compiler and loader. This measures packing, not
request runtime, and neither arm makes the quarantined mini-VM safe for production.
"""
from __future__ import annotations

import argparse
import importlib.util
import random
import statistics
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # The temporary baseline module has a different __file__; use the exact same compiler.
    module._virtualize_php_path = lambda: ROOT / "encoder/virtualize.php"
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--loader", required=True, type=Path)
    parser.add_argument("--pairs", type=int, default=30)
    args = parser.parse_args()
    if not args.loader.is_file() or not 1 <= args.pairs <= 100:
        parser.error("loader must exist and pairs must be 1..100")
    path = ROOT / "encoder/envelock.py"
    code = path.read_text()
    block = '''        vm_compiler_sha256 = None
        if virtualize:
            # Informational provenance only, not a signature or runtime attestation. Reject normal
            # concurrent compiler changes rather than publishing a misleading fingerprint.
            compiler_path = _virtualize_php_path()
            vm_compiler_sha256 = hashlib.sha256(compiler_path.read_bytes()).hexdigest()
            sources, virtualized = virtualize_sources(sources, virtualize, php)
            if (_virtualize_php_path() != compiler_path
                    or hashlib.sha256(compiler_path.read_bytes()).hexdigest() != vm_compiler_sha256):
                raise ValueError("--virtualize compiler changed during packaging; no package was produced")'''
    prior = '''        if virtualize:
            sources, virtualized = virtualize_sources(sources, virtualize, php)'''
    field = '            "vm_compiler_sha256": vm_compiler_sha256,\n'
    if code.count(block) != 1 or code.count(field) != 1:
        raise RuntimeError("packer layout changed; cannot isolate fingerprint checks reliably")
    rng = random.Random(7319)  # nosec B311 - deterministic benchmark order
    with tempfile.TemporaryDirectory(prefix="envelock-vm-pack-bench-") as directory:
        root = Path(directory)
        old_path = root / "baseline.py"
        old_path.write_text(code.replace(block, prior).replace(field, ""))
        old, new = load_module(old_path, "vm_pack_bench_old"), load_module(path, "vm_pack_bench_new")
        source = root / "src"
        source.mkdir()
        (source / "index.php").write_text("<?php function f($x){if($x>0){return 1;}else{return 2;}}")
        owner, recipient = new.make_owner(), new.make_recipient("lab-bench")
        recipients = [new.recipient_public(recipient)]
        measurements = {"baseline": [], "fingerprint": []}
        for pair in range(args.pairs + 1):
            order = [("baseline", old), ("fingerprint", new)]
            rng.shuffle(order)
            for name, module in order:
                destination = root / f"{pair}-{name}"
                start = time.perf_counter_ns()
                info = module.pack_tree(source, destination, recipients, owner, str(uuid.uuid4()),
                                        virtualize=["f"], virtualize_loader=args.loader.resolve(),
                                        unsafe_vm_laboratory=True)
                elapsed = (time.perf_counter_ns() - start) / 1_000_000
                if info["virtualized_functions"] != ["f"]:
                    raise RuntimeError("unexpected packaging result")
                if pair:
                    measurements[name].append(elapsed)
        base, new_ms = (statistics.median(measurements[key]) for key in ("baseline", "fingerprint"))
        print(f"pairs={args.pairs} baseline_ms={base:.3f} fingerprint_ms={new_ms:.3f} ratio={new_ms/base:.3f}")
        print("Same lab-VM source and loader; measures pack time, not application runtime.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

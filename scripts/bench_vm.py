#!/usr/bin/env python3
"""A/B the repaired experimental VM against the old prebuilt on an integer-only loop.

The old loader is unsafe and must not be deployed because of known VM defects. This benchmark
only uses it in a disposable PHP process for one valid integer program. Programs are byte-for-byte
identical except for the ENVVM1/ENVVM3 header; this isolates loader differences and does not prove
semantic parity. The native-PHP arm measures the same loop without virtualization.

    python3 scripts/bench_vm.py --old-loader prebuilt/loader/linux-x86_64/php-8.4-nts/envelock.so \
        --new-loader /tmp/build/modules/envelock.so --pairs 30 --calls 10000
"""
from __future__ import annotations

import argparse
import base64
import json
import random
import statistics
import subprocess  # nosec B404 - fixed local commands without a shell
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FUNCTION = ("function total($n){$t=0;for($i=1;$i<=$n;$i=$i+1)"
            "{if($i%2==0){$t=$t+$i;}}return $t;}")


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(command, capture_output=True, check=False, timeout=120, **kwargs)  # nosec B603
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(str(error)) from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old-loader", required=True, type=Path)
    parser.add_argument("--new-loader", required=True, type=Path)
    parser.add_argument("--php", default="php")
    parser.add_argument("--pairs", type=int, default=30)
    parser.add_argument("--calls", type=int, default=10000)
    args = parser.parse_args()
    if not 1 <= args.pairs <= 200 or not 1 <= args.calls <= 1000000:
        parser.error("pairs must be 1..200 and calls 1..1000000")
    if not args.old_loader.is_file() or not args.new_loader.is_file():
        parser.error("both loader paths must exist")
    payload = {"files": {"loop.php": base64.b64encode(("<?php " + FUNCTION).encode()).decode()},
               "marked": ["total"]}
    compiled = run([args.php, "-d", "display_errors=stderr", str(ROOT / "encoder/virtualize.php")],
                   input=json.dumps(payload).encode())
    if compiled.returncode:
        print(compiled.stderr.decode(errors="replace"), file=sys.stderr)
        return 1
    blob = base64.b64decode(json.loads(compiled.stdout)["programs"]["total"])
    if not blob.startswith(b"ENVVM3"):
        raise RuntimeError("compiler did not generate a v2 program")
    v1 = base64.b64encode(b"ENVVM1" + blob[6:]).decode()
    v2 = base64.b64encode(blob).decode()
    calls = {
        "php": "total(50)",
        "old-v1": "__envelock_vm('" + v1 + "',[50])",
        "new-v2": "__envelock_vm_v2('" + v2 + "',[50])",
    }
    loaders = {"php": None, "old-v1": args.old_loader.resolve(), "new-v2": args.new_loader.resolve()}
    results: dict[str, list[float]] = {name: [] for name in calls}
    rng = random.Random(7319)  # nosec B311 - fixed seed for a reproducible benchmark order, not crypto
    for pair in range(args.pairs + 1):  # one warm-up triplet, excluded
        order = list(calls)
        rng.shuffle(order)
        for name in order:
            call = calls[name]
            code = (FUNCTION + f" $sum=0;$t=hrtime(true);for($j=0;$j<{args.calls};$j++){{$sum+={call};}}"
                    + "echo $sum,'|',hrtime(true)-$t;")
            extra = ["-d", f"extension={loaders[name]}"] if loaders[name] is not None else []
            result = run([args.php, "-n", *extra, "-d", "display_errors=stderr", "-r", code])
            if result.returncode:
                print(f"{name} failed: {result.stderr.decode(errors='replace')[-1000:]}", file=sys.stderr)
                return 1
            try:
                computed, nanos = result.stdout.decode().split("|")
                if int(computed) != args.calls * 650:
                    raise ValueError(f"unexpected result {computed}")
                if pair:
                    results[name].append(int(nanos) / 1e6)
            except ValueError as error:
                print(f"{name}: invalid benchmark result: {error}", file=sys.stderr)
                return 1
    medians = {name: statistics.median(values) for name, values in results.items()}
    print(f"pairs={args.pairs} calls={args.calls} n=50 result={args.calls * 650}")
    print("median_ms: " + " ".join(f"{name}={median:.3f}" for name, median in medians.items()))
    print(f"ratios: new/old={medians['new-v2']/medians['old-v1']:.3f} "
          f"new/php={medians['new-v2']/medians['php']:.3f}")
    print("Caveat: identical bounded integer program; no claim of general parity, security or production readiness.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

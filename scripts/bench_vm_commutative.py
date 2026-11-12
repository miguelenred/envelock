#!/usr/bin/env python3
"""A/B the repaired VM compiler's constant/local operand ordering.

Both arms execute the same correct integer case. The old ordering is known to produce different
exceptions for other types; this benchmark does not endorse it or establish general performance.
"""
from __future__ import annotations

import argparse
import random
import shutil
import statistics
import tempfile
from pathlib import Path

import bench_vm_else as bench


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--loader", type=Path, required=True)
    parser.add_argument("--php", default="php")
    parser.add_argument("--pairs", type=int, default=40)
    parser.add_argument("--calls", type=int, default=30000)
    args = parser.parse_args()
    if not args.loader.is_file() or not 1 <= args.pairs <= 200 or not 1 <= args.calls <= 1_000_000:
        parser.error("loader must exist, pairs must be 1..200 and calls must be 1..1000000")
    current = bench.ROOT / "encoder/virtualize.php"
    code = current.read_text()
    marker = "            /* Zend's specialized commutative MUL and bitwise handlers"
    end_marker = "            $this->program->emit(0x04, chr($opcode));"
    if code.count(marker) != 1:
        raise RuntimeError("compiler layout changed; cannot reproduce old operand ordering")
    start = code.index(marker)
    end = code.index(end_marker, start)
    bench.FUNCTION = "function f($x){return 2*$x;}"
    with tempfile.TemporaryDirectory(prefix="envelock-vm-commutative-bench-") as temp:
        root = Path(temp)
        (root / "encoder").mkdir()
        (root / "third_party").mkdir()
        shutil.copytree(bench.ROOT / "third_party/php-parser", root / "third_party/php-parser")
        old = root / "encoder/virtualize.php"
        old.write_text(code[:start] + code[end:])
        programs = {"old": bench.compile_program(args.php, old),
                    "repaired": bench.compile_program(args.php, current)}
    rng = random.Random(7319)  # nosec B311 - deterministic measurement order
    timings: dict[str, list[float]] = {name: [] for name in programs}
    for pair in range(args.pairs + 1):
        order = list(programs)
        rng.shuffle(order)
        for name in order:
            script = (f"$p='{programs[name]}'; $t=hrtime(true);$sum=0;"
                      f"for($i=0;$i<{args.calls};$i++){{$sum+=__envelock_vm_v2($p,[1]);}}"
                      "echo $sum,'|',hrtime(true)-$t;")
            process = bench.run([args.php, "-n", "-d", f"extension={args.loader.resolve()}", "-r", script])
            if process.returncode:
                raise RuntimeError(process.stderr.decode(errors="replace")[-2000:])
            total, nanos = process.stdout.decode().split("|")
            if int(total) != args.calls * 2:
                raise RuntimeError(f"unexpected result from {name}: {total}")
            if pair:
                timings[name].append(int(nanos) / 1e6)
    old_ms, repaired_ms = (statistics.median(timings[name]) for name in ("old", "repaired"))
    print(f"pairs={args.pairs} calls={args.calls} old_ms={old_ms:.3f} repaired_ms={repaired_ms:.3f} "
          f"repaired/old={repaired_ms/old_ms:.3f}")
    print("Only a common integer case is measured. Old error semantics are wrong; VM is quarantined.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

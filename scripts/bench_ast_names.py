#!/usr/bin/env python3
"""Small A/B benchmark of closed-world AST renaming: pack-time and PHP runtime separately.

This is not a production-workload benchmark. By default the baseline declines namespaced name
renaming and the AST arm opts in. With --allowlist, both arms actually rename the same class: the
baseline is AST without a list and the second arm uses a strict one-entry allowlist. Runtime measures
only repeated static method calls using PHP's monotonic clock; PHP startup is intentionally excluded.

    python3 scripts/bench_ast_names.py --samples 25 --iterations 200000
    python3 scripts/bench_ast_names.py --samples 25 --iterations 200000 --allowlist
"""

from __future__ import annotations

import argparse
import importlib.util
import shutil
import statistics
import subprocess  # nosec B404 - runs the local PHP CLI with fixed argument lists
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("envelock", ROOT / "encoder" / "envelock.py")
a = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(a)


def write_tree(root: Path, files: dict[str, bytes]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (root / name).write_bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--samples", type=int, default=25)
    parser.add_argument("--iterations", type=int, default=200000)
    parser.add_argument("--php", default="php")
    parser.add_argument("--allowlist", action="store_true", help="Compare AST against AST + strict allowlist")
    args = parser.parse_args()
    if args.samples < 2 or args.iterations < 1:
        parser.error("--samples must be at least 2; --iterations must be positive")
    php = shutil.which(args.php)
    if not php:
        parser.error("PHP CLI not found")
    files = {
        "types.php": (b"<?php namespace Bench; class Widget { "
                      b"public static function calc(int $n): int { return ($n * 3 + 5) % 97; } }"),
        "main.php": (b"<?php namespace Bench; require __DIR__ . '/types.php'; "
                     b"$sum=0; $start=hrtime(true); "
                     + f"for($i=0;$i<{args.iterations};$i++) $sum+=Widget::calc($i); ".encode()
                     + b"echo $sum, ',', hrtime(true)-$start;"),
    }
    left, right = ("ast", "allowlist") if args.allowlist else ("default", "ast")
    pack_ms: dict[str, list[float]] = {left: [], right: []}
    runtime_ms: dict[str, list[float]] = {left: [], right: []}
    with tempfile.TemporaryDirectory(prefix="envelock-ast-bench-") as temp:
        root = Path(temp)
        sums = set()
        for i in range(args.samples):
            arms = (left, right) if i % 2 == 0 else (right, left)
            for arm in arms:
                allow = ["type:Bench\\Widget"] if arm == "allowlist" else None
                start = time.perf_counter_ns()
                out, mapping, reason = a._names_pass(files, php, ast_names=(arm != "default"), allowlist=allow)
                pack_ms[arm].append((time.perf_counter_ns() - start) / 1e6)
                if arm == "default" and (mapping or reason != "namespaced" or out != files):
                    raise RuntimeError("the baseline did not decline unchanged")
                if arm != "default" and (set(mapping) != {"Bench\\Widget"} or reason):
                    raise RuntimeError(f"{arm} did not rename exactly the class: {mapping}, {reason}")
                write_tree(root / arm, out)
                result = subprocess.run([php, "-n", str(root / arm / "main.php")],  # nosec B603
                                        capture_output=True, text=True, timeout=60, check=True)
                total, elapsed = result.stdout.split(",")
                sums.add(total)
                runtime_ms[arm].append(int(elapsed) / 1e6)
        if len(sums) != 1:
            raise RuntimeError(f"the two programs returned different sums: {sums}")
    print(f"{args.samples} paired samples, {args.iterations} calls/sample, identical result={sums.pop()}")
    for label, values in (("name-pass wall time (ms/pack)", pack_ms), ("PHP loop time (ms)", runtime_ms)):
        baseline = statistics.median(values[left])
        candidate = statistics.median(values[right])
        print(f"{label}: {left}={baseline:.3f}, {right}={candidate:.3f}, ratio={candidate / baseline:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

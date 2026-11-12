#!/usr/bin/env python3
"""Compare the repaired compiler with a temporary reproduction of its old else-jump bug.

Both programs execute ONLY the true branch, where the old and repaired results agree. This does
not endorse the old program: it is observably wrong on the false path. Measures VM execution, not
whole-application performance. The loader and VM remain quarantined for laboratory use.
"""
from __future__ import annotations

import argparse
import base64
import json
import random
import shutil
import statistics
import subprocess  # nosec B404 - fixed local PHP commands
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FUNCTION = "function f($x){if($x>0){return $x*2;}else{return -1;}}"


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, check=False, timeout=120, **kwargs)  # nosec B603


def compile_program(php: str, compiler: Path) -> str:
    payload = {"files": {"case.php": base64.b64encode(("<?php " + FUNCTION).encode()).decode()}, "marked": ["f"]}
    result = run([php, str(compiler)], input=json.dumps(payload).encode())
    if result.returncode:
        raise RuntimeError("compiler failed: " + result.stderr.decode(errors="replace")[-2000:])
    return json.loads(result.stdout)["programs"]["f"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--loader", required=True, type=Path)
    parser.add_argument("--php", default="php")
    parser.add_argument("--pairs", type=int, default=40)
    parser.add_argument("--calls", type=int, default=30000)
    args = parser.parse_args()
    if not args.loader.is_file() or not 1 <= args.pairs <= 200 or not 1 <= args.calls <= 1_000_000:
        parser.error("loader must exist, pairs must be 1..200, calls must be 1..1000000")
    current = ROOT / "encoder/virtualize.php"
    fix = "            $jumpFalse = null; // already points to else; do not overwrite it with end below\n"
    correct = "        if ($jumpFalse !== null) $this->program->patch($jumpFalse, $end);"
    source = current.read_text()
    if source.count(fix) != 1 or source.count(correct) != 1:
        raise RuntimeError("compiler layout changed; cannot reproduce the old bug reliably")
    with tempfile.TemporaryDirectory(prefix="envelock-vm-else-bench-") as temp:
        root = Path(temp)
        (root / "encoder").mkdir()
        (root / "third_party").mkdir()
        shutil.copytree(ROOT / "third_party/php-parser", root / "third_party/php-parser")
        old = root / "encoder/virtualize.php"
        old.write_text(source.replace(fix, "").replace(correct, "        $this->program->patch($jumpFalse, $end);"))
        programs = {"old_bug": compile_program(args.php, old), "repaired": compile_program(args.php, current)}
    rng = random.Random(7319)  # nosec B311 - deterministic measurement order
    timings: dict[str, list[float]] = {name: [] for name in programs}
    for pair in range(args.pairs + 1):  # warm-up excluded
        order = list(programs)
        rng.shuffle(order)
        for name in order:
            script = (f"$p='{programs[name]}'; $t=hrtime(true);$sum=0;"
                      f"for($i=0;$i<{args.calls};$i++){{$sum+=__envelock_vm_v2($p,[1]);}}"
                      "echo $sum,'|',hrtime(true)-$t;")
            process = run([args.php, "-n", "-d", f"extension={args.loader.resolve()}", "-r", script])
            if process.returncode:
                raise RuntimeError(process.stderr.decode(errors="replace")[-2000:])
            total, nanos = process.stdout.decode().split("|")
            if int(total) != args.calls * 2:
                raise RuntimeError(f"unexpected true-path result from {name}: {total}")
            if pair:
                timings[name].append(int(nanos) / 1e6)
    old_ms, repaired_ms = (statistics.median(timings[name]) for name in ("old_bug", "repaired"))
    print(f"pairs={args.pairs} calls={args.calls} old_ms={old_ms:.3f} repaired_ms={repaired_ms:.3f} "
          f"repaired/old={repaired_ms/old_ms:.3f}")
    print("Only the common true path is measured. Old false branches are wrong; VM remains quarantined.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

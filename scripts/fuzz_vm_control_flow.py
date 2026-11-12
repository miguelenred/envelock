#!/usr/bin/env python3
"""Differentially test VM statement control flow on bounded integer programs.

Compares real PHP against the reconstructed V2 loader for many if/elseif/else combinations,
nested branches, while/for loops and ternaries. A compiler refusal, timeout or mismatch is failure.
This is a bounded campaign, not a proof of general PHP/VM equivalence or production readiness.
"""
from __future__ import annotations

import argparse
import base64
import json
import random
import subprocess  # nosec B404 - explicit local PHP commands
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INPUTS = (-3, -1, 0, 1, 2, 4, 7)


def body(rng: random.Random) -> str:
    a, b, c, d = (rng.randint(-6, 6) for _ in range(4))
    kind = rng.randrange(6)
    if kind == 0:
        return f"if($x<{a}){{return {b};}} else {{return {c};}}"
    if kind == 1:
        return f"if($x<{a}){{return {b};}} elseif($x==={c}){{return {d};}} else {{return {a};}}"
    if kind == 2:
        return (f"if($x<{a}){{if($x==={b}){{return {c};}} else {{return {d};}}}} "
                f"else {{if($x>{c}){{return {a};}} else {{return {b};}}}}")
    if kind == 3:
        return (f"$s=0;for($i=0;$i<4;$i=$i+1){{if($x>$i){{$s=$s+({a});}} "
                f"else {{$s=$s+({b});}}}} return $s;")
    if kind == 4:
        return (f"$s=0;$i=0;while($i<4){{if($x==$i){{$s=$s+({a});}} "
                f"elseif($x<$i){{$s=$s+({b});}} else {{$s=$s+({c});}} $i=$i+1;}} return $s;")
    return (f"$s=($x>{a})?({b}):({c}); if($s==={b}){{$s=$s+({c});}} "
            f"else {{$s=$s+({d});}} return $s;")


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, timeout=120, check=False, **kwargs)  # nosec B603


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--loader", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, default=ROOT / "encoder/virtualize.php")
    parser.add_argument("--php", default="php")
    parser.add_argument("--count", type=int, default=500)
    parser.add_argument("--seed", type=int, default=73)
    args = parser.parse_args()
    if not 1 <= args.count <= 3000 or not args.loader.is_file() or not args.compiler.is_file():
        parser.error("count must be 1..3000 and loader and compiler must be existing files")
    rng = random.Random(args.seed)  # nosec B311 - deterministic corpus, not cryptography
    cases = [body(rng) for _ in range(args.count)]
    names = [f"flow{i:05d}" for i in range(args.count)]
    source = "<?php\n" + "\n".join(f"function {name}($x){{{stmt}}}" for name, stmt in zip(names, cases, strict=True))
    payload = {"files": {"fuzz.php": base64.b64encode(source.encode()).decode()}, "marked": names}
    started = time.monotonic()
    try:
        compiled = run([args.php, "-d", "display_errors=stderr", str(args.compiler.resolve())],
                       input=json.dumps(payload).encode())
        if compiled.returncode:
            print("COMPILER REFUSED OR FAILED: " + compiled.stderr.decode(errors="replace")[-2000:], file=sys.stderr)
            return 1
        programs = json.loads(compiled.stdout)["programs"]
        if set(programs) != set(names):
            raise ValueError("compiler omitted or added function names")
        encoded = base64.b64encode(json.dumps(programs).encode()).decode()
        harness = r'''
$programs=json_decode(base64_decode('PROGRAMS'),true,512,JSON_THROW_ON_ERROR);
$inputs=INPUTS; $failures=[]; $checked=0;
foreach($programs as $name=>$program) {
    foreach($inputs as $x) {
        $expected=$name($x); $actual=__envelock_vm_v2($program,[$x]); $checked++;
        if($expected!==$actual) $failures[]=[$name,$x,$expected,$actual];
    }
}
echo json_encode(['checked'=>$checked,'failures'=>$failures],JSON_THROW_ON_ERROR);
'''.replace("PROGRAMS", encoded).replace("INPUTS", json.dumps(INPUTS))
        with tempfile.TemporaryDirectory(prefix="envelock-vm-flow-fuzz-") as tmp:
            path = Path(tmp) / "cases.php"
            path.write_text(source + "\n" + harness)
            result = run([args.php, "-n", "-d", f"extension={args.loader.resolve()}",
                          "-d", "display_errors=stderr", str(path)])
        if result.returncode:
            print("RUNNER FAILED: " + result.stderr.decode(errors="replace")[-2000:], file=sys.stderr)
            return 1
        report = json.loads(result.stdout)
        failures = report["failures"]
        for name, x, expected, actual in failures[:20]:
            print(f"DIVERGENCE {name} input={x} source={cases[int(name[4:])]} expected={expected} actual={actual}")
        print(f"seed={args.seed} programs={args.count} inputs={report['checked']} "
              f"divergences={len(failures)} elapsed={time.monotonic()-started:.2f}s")
        return 1 if failures or report["checked"] != args.count * len(INPUTS) else 0
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
        print(f"control-flow fuzz failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

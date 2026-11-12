#!/usr/bin/env python3
"""Differentially exercise mini-VM v2 expressions against the running PHP engine.

Generated programs use only a deliberately bounded expression grammar. For each input, compare
serialized PHP values (including types and signed zero), or the class/message of a caught exception
or a warning converted into an exception. A refusal, timeout, empty corpus, or mismatch is failure,
not a silently skipped case. This is not an exhaustive proof or a test of stack traces/line numbers.

    python3 scripts/fuzz_vm_semantics.py --loader /tmp/build/modules/envelock.so --count 200 --seed 73
"""
from __future__ import annotations

import argparse
import base64
import json
import random
import subprocess  # nosec B404 - fixed local PHP commands, no shell
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEAVES = ("$a", "$b", "$undef", "0", "1", "2", "-3", "0.0", "-0.0", "1.5", "0123", "0o17",
          "1_000", "true", "false", "null", "'12'", "'0'", "'x'", r'"a\q"', "[1,2]")
UNARY = ("+", "-", "!", "~", "(int)", "(float)", "(string)", "(bool)", "(array)")
BINARY = ("+", "-", "*", "/", "%", "**", ".", "==", "!=", "===", "!==", "<", "<=", ">", ">=",
          "<=>", "<<", ">>", "&", "|", "^", "&&", "||")
# Only operators that PHP permits in an unparenthesized chain; comparison operators are
# intentionally excluded because PHP 8 rejects e.g. `1 < 2 < 3` at parse time.
CHAIN = ("+", "-", "*", ".", "<<", ">>", "&", "|", "^", "&&", "||")
# Builtins that compile as ordinary calls (not the direct-call special cases the compiler refuses).
CALLS = {"abs": 1, "intdiv": 2, "str_repeat": 2, "strtoupper": 1, "floor": 1, "array_sum": 1}
INPUTS = r"""[
    [0,0], [1,2], [-3,2], [1.5,-2], [0.0,-0.0], [true,false], [null,5],
    ['12','2'], ['-0.0','0'], ['x',1], [[1,2],0], [[1,2],true], ['abc',1],
    [INF,NAN], [NAN,1], [(object)['x'=>1],0]
]"""


def generate(rng: random.Random, depth: int) -> str:
    if depth <= 0 or rng.random() < 0.26:
        return rng.choice(LEAVES)
    choice = rng.randrange(7)
    if choice == 6:
        name = rng.choice(sorted(CALLS))
        return name + "(" + ", ".join(generate(rng, depth - 1) for _ in range(CALLS[name])) + ")"
    if choice == 5:
        # Nested assignments: PHP reads a plain local operand when its operation runs, so these
        # exercise the lazy local reads of the VM rather than only the pure expression subset.
        target = rng.choice(("$a", "$b"))
        return "(" + target + " " + rng.choice(("=", "+=", "-=", ".=")) + " " + generate(rng, depth - 1) + ")"
    if choice == 0:
        return "(" + rng.choice(UNARY) + "(" + generate(rng, depth - 1) + "))"
    if choice == 1:
        return "(" + generate(rng, depth - 1) + ")[" + generate(rng, depth - 1) + "]"
    if choice == 2:
        return "(" + generate(rng, depth - 1) + " ? " + generate(rng, depth - 1) + " : " + generate(rng, depth - 1) + ")"
    return "(" + generate(rng, depth - 1) + " " + rng.choice(BINARY) + " " + generate(rng, depth - 1) + ")"


def execute(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(command, capture_output=True, check=False, timeout=120, **kwargs)  # nosec B603
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"PHP process failed or timed out: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--loader", required=True, type=Path, help="v2-capable loader built for this PHP")
    parser.add_argument("--php", default="php")
    parser.add_argument("--count", type=int, default=200)
    parser.add_argument("--seed", type=int, default=73)
    args = parser.parse_args()
    if not 1 <= args.count <= 3000 or not args.loader.is_file():
        parser.error("--count must be 1..3000 and --loader must be an existing extension")
    rng = random.Random(args.seed)
    expressions = []
    for i in range(args.count):
        if i % 7 == 0:
            expressions.append(" ".join([rng.choice(LEAVES), rng.choice(CHAIN), rng.choice(LEAVES),
                                         rng.choice(CHAIN), rng.choice(LEAVES)]))
        else:
            # Nested assignments are deliberately rejected by the compiler; targeted regression
            # tests cover that refusal. This corpus exercises expressions it currently accepts.
            expressions.append(generate(rng, rng.randrange(1, 4)))
    names = [f"probe{i:05d}" for i in range(args.count)]
    source = "<?php\n" + "\n".join(f"function {name}($a,$b){{return {expr};}}"
                                   for name, expr in zip(names, expressions, strict=True))
    payload = {"files": {"fuzz.php": base64.b64encode(source.encode()).decode()}, "marked": names}
    started = time.monotonic()
    compile_result = execute([args.php, "-d", "display_errors=stderr", str(ROOT / "encoder/virtualize.php")],
                             input=json.dumps(payload).encode())
    if compile_result.returncode:
        print("COMPILER REFUSED OR FAILED: " + compile_result.stderr.decode(errors="replace")[-2000:], file=sys.stderr)
        return 1
    try:
        programs = json.loads(compile_result.stdout)["programs"]
    except (ValueError, KeyError) as error:
        print(f"invalid compiler output: {error}", file=sys.stderr)
        return 1
    if set(programs) != set(names):
        print("compiler did not return every requested program", file=sys.stderr)
        return 1
    programs_json = base64.b64encode(json.dumps(programs).encode()).decode()
    # Suppress warning output but preserve its exact message and severity through ErrorException.
    harness = r'''
function fuzz_snap($callback) {
    set_error_handler(function($severity, $message) { throw new ErrorException($message, 0, $severity); });
    try { return ['value', base64_encode(serialize($callback()))]; }
    catch (Throwable $e) { return ['exception', get_class($e), $e->getMessage(), $e->getCode()]; }
    finally { restore_error_handler(); }
}
$programs = json_decode(base64_decode('PROGRAMS'), true, 512, JSON_THROW_ON_ERROR);
$inputs = INPUTS;
$failures = []; $total = 0;
foreach ($programs as $name => $program) {
    foreach ($inputs as $case => $values) {
        $expected = fuzz_snap(fn() => $name(...$values));
        $actual = fuzz_snap(fn() => __envelock_vm_v2($program, $values));
        $total++;
        if ($expected !== $actual) $failures[] = [$name, $case, $expected, $actual];
    }
}
echo json_encode(['checked' => $total, 'failures' => $failures], JSON_THROW_ON_ERROR);
'''.replace("PROGRAMS", programs_json).replace("INPUTS", INPUTS)
    with tempfile.TemporaryDirectory(prefix="envelock-vm-fuzz-") as folder:
        path = Path(folder) / "fuzz.php"
        path.write_text(source + "\n" + harness)
        result = execute([args.php, "-n", "-d", f"extension={args.loader.resolve()}",
                          "-d", "display_errors=stderr", str(path)])
    if result.returncode:
        print("RUNNER FAILED: " + result.stderr.decode(errors="replace")[-2000:], file=sys.stderr)
        return 1
    try:
        report = json.loads(result.stdout)
    except ValueError as error:
        print(f"invalid runner output: {error}; {result.stdout[:300]!r}", file=sys.stderr)
        return 1
    failures = report["failures"]
    reported = set()
    for name, case, expected, actual in failures:
        if name in reported:
            continue
        reported.add(name)
        if len(reported) <= 20:
            print(f"DIVERGENCE {name} input={case} expr={expressions[int(name[5:])]} expected={expected} actual={actual}")
    values = sum(expected[0] == "value" or actual[0] == "value" for _, _, expected, actual in failures)
    print(f"seed={args.seed} programs={args.count} inputs={report['checked']} refusals=0 "
          f"divergences={len(failures)} affected_programs={len(reported)} value_or_exception={values} "
          f"elapsed={time.monotonic()-started:.2f}s")
    return 1 if failures or report["checked"] != args.count * 16 else 0


if __name__ == "__main__":
    raise SystemExit(main())

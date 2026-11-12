#!/usr/bin/env python3
"""Exhaustive, deterministic differential matrices for mini-VM operand order and warning order.

Three sections, each compared against the running PHP engine (no sampling):

  ops     binary operators x operand shapes (CV, CONST, TMP, undefined CV) x value pairs
  dims    dimension reads with undefined or mistyped bases and keys
  branch  ternary branches and boolean operators that copy a plain local

Every case runs the same PHP with an error handler that turns every diagnostic into an exception,
then compares the serialized value, or the class and message of the exception, with the VM's result.
A refused program, a mismatch, or a crash counts as a failure. Nothing is skipped silently: refusals
are printed and counted. Object-literal bases are kept out of the dimension matrix on purpose, because
the compiler refuses `(object)` casts by design (a refusal is safe, but it is not a comparison).

    python3 scripts/vm_order_matrix.py --loader /tmp/envelock-calls3.so --section ops
"""
from __future__ import annotations

import argparse
import base64
import json
import subprocess  # nosec B404 - fixed local PHP commands, no shell
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VIRTUALIZE = ROOT / "encoder" / "virtualize.php"
HANDLER = "set_error_handler(function($n,$s){throw new ErrorException($s,0,$n);}); "
TAIL = ('try { $r = %s; echo "V:", serialize($r); } catch (Throwable $e) '
        '{ echo "E:", get_class($e), ":", $e->getMessage(); }')

OPS = ("|", "&", "^", "<<", ">>", "%", "+", "-", "*", "/")
SHAPES = {
    "CVCV": "$a {op} $b",
    "CVC": "$a {op} 1.5",
    "CCV": "1.5 {op} $a",
    "CVC2": "$a {op} 2",
    "TMPCV": "($a + 0) {op} $b",
    "CVTMP": "$a {op} ($b + 0)",
    "CVF": "$a {op} 2.0",
    "FCV": "2.0 {op} $a",
    "UNDEF": "$undef {op} $b",
}
OPERAND_VALUES = ("1.5", "2.0", "-0.0", "1e20", "NAN", "INF", "3", "0", '"1.5"', '"3"', "null", "true",
                  "[1]", '(object)["x"=>1]', '"x"')

DIM_BASES = ("$a", "$undef", "($a + 0)", "$a[0]", "[1, 2]", '"abc"', "null")
DIM_KEYS = ("$b", "$undef", "1", '"x"', "1.5", "null", "true", "[1]", "($b + 0)", "$a[0]")
DIM_VALUES = ("[1, [2]]", '"abc"', "null", "1", "5", "[]", '"1.5"', "0", "false", '(object)["x"=>1]')

BRANCH_EXPRS = (
    "(~(($a -= 1.5) ? $undef : 2))", "(~(($a -= 1.5) ? 2 : $undef))", "(~(($a -= 1.5) ? $b : $undef))",
    "(~(($a -= 1.5) ? $undef : $b))", "($undef ? $a : $b)", "(~($undef ? $a : $b))", "(~($b ? $undef : $a))",
    "(~(($a ? $undef : 2) ? 3 : 4))", "(~(($a ? 2 : $undef) ? 3 : 4))",
    "(~(($a -= 1.5) ? ($b ? $undef : 2) : $undef))", "($a && $undef) | 2", "(~($a && $undef))",
    "(~($a || $undef))", "(~($undef || $a))", "(~(($a -= 1.5) && $undef))", "(~(!$undef))",
    "(~((int)$undef))", "(~((string)$undef))", "(~(-$undef))", "(~($undef ? 1 : 2))",
    "(~(($a = 2) ? $undef : 1))",
)
BRANCH_INPUTS = ((0.0, 0), (1.5, -2), (3, 1), (0, None), (None, [1]), ("0", "x"))


def _virtualize(source: str) -> tuple[str | None, str]:
    result = subprocess.run(  # nosec B603 B607 - fixed command, the developer's php, no shell
        ["php", "-d", "display_errors=stderr", str(VIRTUALIZE)],
        input=json.dumps({"files": {"a.php": base64.b64encode(source.encode()).decode()},
                          "marked": ["f"]}).encode(),
        capture_output=True, timeout=120, check=False)
    if result.returncode != 0:
        return None, result.stderr.decode(errors="replace").strip()
    return json.loads(result.stdout)["programs"]["f"], ""


def _run_php(code: str) -> subprocess.CompletedProcess:
    return subprocess.run(["php", "-n", "-r", code],  # nosec B603 B607 - fixed command, the developer's php
                          capture_output=True, text=True, errors="replace", timeout=60, check=False)


def _run_vm(loader: Path, program: str, args: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # nosec B603 B607 - fixed command, the developer's php, no shell
        ["php", "-n", "-d", f"extension={loader}", "-r",
         HANDLER + TAIL % f"__envelock_vm({program!r}, [{args}])"],
        capture_output=True, text=True, errors="replace", timeout=60, check=False)


class Counter:
    def __init__(self) -> None:
        self.total = 0
        self.divergences = 0
        self.refused = 0
        self.shown = 0

    def compare(self, label: str, php_code: str, source: str, loader: Path, args: str) -> None:
        self.total += 1
        php_result = _run_php(HANDLER + source + " " + TAIL % php_code)
        vm_result = _run_vm(loader, self.program, args)
        if php_result.stdout == vm_result.stdout and php_result.returncode == vm_result.returncode == 0:
            return
        self.divergences += 1
        if self.shown < 25:
            self.shown += 1
            print("DIFF", label, args, "| PHP:", php_result.stdout[:120], "| VM:",
                  (vm_result.stdout or vm_result.stderr)[:120])


def run_cases(loader: Path, expressions, arguments, kind: str) -> Counter:
    counter = Counter()
    for expression in expressions:
        source = "function f($a, $b) { return " + expression + "; }"
        program, error = _virtualize("<?php " + source)
        if program is None:
            counter.refused += 1
            print("REFUSED", kind, expression, error[-120:])
            continue
        counter.program = program
        for args in arguments:
            php_args, vm_args = args
            counter.compare(f"{kind} {expression}", f"f({php_args})", source, loader, vm_args)
    return counter


def section_ops(loader: Path) -> Counter:
    # Each operator/shape pair is compiled once; the value pairs are the arguments.
    counter = Counter()
    for op in OPS:
        for name, shape in SHAPES.items():
            expression = shape.replace("{op}", op)
            source = "function f($a, $b) { return " + expression + "; }"
            program, error = _virtualize("<?php " + source)
            if program is None:
                counter.refused += 1
                print("REFUSED", op, name, error[-120:])
                continue
            counter.program = program
            for x in OPERAND_VALUES:
                for y in OPERAND_VALUES:
                    counter.compare(f"{name} {op}", f"f({x}, {y})", source, loader, f"{x}, {y}")
    return counter


def section_dims(loader: Path) -> Counter:
    expressions = []
    for base in DIM_BASES:
        for key in DIM_KEYS:
            expressions.append(f"{base}[{key}]")
            expressions.append(f"{base}[{key}][{key}]")
    for key in DIM_KEYS:
        expressions.append(f"$a[{key}][$b]")
        expressions.append(f"$a[$b][{key}]")
    arguments = [(f"{x}, {y}", f"{x}, {y}") for x in DIM_VALUES for y in DIM_VALUES]
    return run_cases(loader, expressions, arguments, "dims")


def section_branch(loader: Path) -> Counter:
    arguments = []
    for x, y in BRANCH_INPUTS:
        text_x = "null" if x is None else repr(x) if isinstance(x, str) else str(x)
        text_y = "null" if y is None else repr(y) if isinstance(y, str) else str(y)
        if isinstance(y, list):
            text_y = "[1]"
        arguments.append((f"{text_x}, {text_y}", f"{text_x}, {text_y}"))
    return run_cases(loader, BRANCH_EXPRS, arguments, "branch")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--loader", required=True, type=Path, help="V3 loader built for this PHP")
    parser.add_argument("--section", choices=("ops", "dims", "branch", "all"), default="all")
    options = parser.parse_args()
    sections = ("ops", "dims", "branch") if options.section == "all" else (options.section,)
    failures = 0
    for name in sections:
        if name == "ops":
            counter = section_ops(options.loader)
        elif name == "dims":
            counter = section_dims(options.loader)
        else:
            counter = section_branch(options.loader)
        print(f"section={name} total={counter.total} divergences={counter.divergences} refused={counter.refused}")
        failures += counter.divergences + counter.refused + (1 if counter.total == 0 else 0)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

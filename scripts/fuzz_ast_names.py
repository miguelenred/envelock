#!/usr/bin/env python3
"""Differentially test the experimental name pass on closed, multi-file PHP packages.

Every generated package runs both before and after transformation. Safe cases must actually rename
all three declarations (or exactly a random subset with --allowlist); observable class-identity
cases must decline without altering any bytes. Imports cover explicit/default aliases, mixed group
imports, same short names in two namespaces, case-insensitive class/function references and a
constant sharing the class's spelling.

    python3 scripts/fuzz_ast_names.py --count 300 --seed 73
    python3 scripts/fuzz_ast_names.py --count 300 --seed 73 --allowlist
"""

from __future__ import annotations

import argparse
import importlib.util
import random
import shutil
import subprocess  # nosec B404 - runs the local PHP CLI with fixed argument lists
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("envelock", ROOT / "encoder" / "envelock.py")
a = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(a)


def generate(rng: random.Random) -> tuple[dict[str, bytes], bool, list[str]]:
    cls1 = f"Widget{rng.randrange(10000, 99999)}"
    cls2 = cls1 if rng.randrange(2) else f"Box{rng.randrange(10000, 99999)}"
    fn = f"helper{rng.randrange(10000, 99999)}"
    n1, n2, n3 = (rng.randrange(1, 100) for _ in range(3))
    a_src = (f"<?php\nnamespace Lab\\Alpha;\n"
             f"class {cls1} {{ public static function go($n) {{ return $n + {n1}; }} }}\n"
             f"const {cls1}={n2};\nfunction {fn}($n) {{ return $n + {n3}; }}\n")
    b_src = (f"<?php\nnamespace Lab\\Beta;\n"
             f"class {cls2} {{ public static function go($n) {{ return $n + {n2}; }} }}\n")
    mode = rng.randrange(5)
    if mode == 0:
        imports = (f"use Lab\\Alpha\\{cls1} as {cls1}; use Lab\\Beta\\{cls2} as Other; "
                   f"use function Lab\\Alpha\\{fn} as {fn}; use const Lab\\Alpha\\{cls1} as NUMBER;")
        expression = f"{cls1}::go(1), '|', Other::go(2), '|', {fn}(3), '|', NUMBER"
    elif mode == 1:
        imports = (f"use Lab\\Alpha\\{cls1}; use Lab\\Beta\\{cls2} as Other; "
                   f"use function Lab\\Alpha\\{fn}; use const Lab\\Alpha\\{cls1} as NUMBER;")
        expression = f"{cls1.swapcase()}::go(1), '|', Other::go(2), '|', {fn.swapcase()}(3), '|', NUMBER"
    elif mode == 2:
        imports = (f"use Lab\\Alpha\\{{{cls1} as {cls1}, function {fn} as {fn}, const {cls1} as NUMBER}}; "
                   f"use Lab\\Beta\\{cls2} as Other;")
        expression = f"{cls1}::go(1), '|', Other::go(2), '|', {fn}(3), '|', NUMBER"
    elif mode == 3:
        imports = ""
        expression = (f"\\lab\\aLPHA\\{cls1.swapcase()}::go(1), '|', "
                      f"\\lab\\bETA\\{cls2.swapcase()}::go(2), '|', "
                      f"\\lab\\aLPHA\\{fn.swapcase()}(3), '|', \\Lab\\Alpha\\{cls1}")
    else:
        imports = f"use Lab\\Alpha\\{cls1};"
        expression = f"{cls1}::class"  # observable identity: this case must be rejected
    main = (f"<?php\nnamespace Runner;\n{imports}\n"
            f"require __DIR__ . '/a.php'; require __DIR__ . '/b.php';\necho {expression};\n")
    candidates = [f"type:Lab\\Alpha\\{cls1}", f"type:Lab\\Beta\\{cls2}",
                  f"function:Lab\\Alpha\\{fn}"]
    return {"a.php": a_src.encode(), "b.php": b_src.encode(), "main.php": main.encode()}, mode == 4, candidates


def run(php: str, root: Path, files: dict[str, bytes]) -> tuple[int, bytes, bytes]:
    root.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (root / name).write_bytes(data)
    result = subprocess.run([php, "-n", str(root / "main.php")], capture_output=True, timeout=30)  # nosec B603
    return result.returncode, result.stdout, result.stderr


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--count", type=int, default=300)
    parser.add_argument("--seed", type=int, default=73)
    parser.add_argument("--php", default="php")
    parser.add_argument("--allowlist", action="store_true", help="Test strict random subsets of declarations")
    args = parser.parse_args()
    if args.count < 1:
        parser.error("--count must be positive")
    php = shutil.which(args.php)
    if not php:
        parser.error("PHP CLI not found")
    rng = random.Random(args.seed)  # nosec B311 - deterministic fuzz inputs, not security
    renamed = declined = 0
    with tempfile.TemporaryDirectory(prefix="envelock-ast-fuzz-") as work:
        root = Path(work)
        for i in range(args.count):
            files, observable, candidates = generate(rng)
            allowed = rng.sample(candidates, rng.randint(1, len(candidates))) if args.allowlist else None
            before = run(php, root / "before", files)
            if before[0] != 0:
                print(f"generator error at case {i}: {before}", file=sys.stderr)
                return 2
            try:
                transformed, mapping, reason = a._names_pass(files, php, ast_names=True, allowlist=allowed)
            except ValueError as error:
                if not (args.allowlist and observable and "dynamic" in str(error)):
                    print(f"transform failed at case {i}: {error}", file=sys.stderr)
                    return 1
                transformed, mapping, reason = files, {}, "dynamic"
            if observable:
                if mapping or transformed != files or reason != "dynamic":
                    print(f"unsafe identity case was not declined at {i}: {mapping}, {reason}", file=sys.stderr)
                    return 1
                declined += 1
            else:
                expected = {entry.split(":", 1)[1] for entry in (allowed or candidates)}
                if set(mapping) != expected or reason:
                    print(f"safe case did not honor its boundary at {i}: {mapping}, {reason}, {allowed}",
                          file=sys.stderr)
                    return 1
                renamed += 1
            if any(files[name].count(b"\n") != transformed[name].count(b"\n") for name in files):
                print(f"line counts changed at case {i}", file=sys.stderr)
                return 1
            after = run(php, root / "after", transformed)
            if before != after:
                print(f"divergence at case {i}: map={mapping}, reason={reason}\n"
                      f"original={before!r}\ntransformed={after!r}\n"
                      f"sources={files!r}", file=sys.stderr)
                return 1
    if not renamed:
        print("no real rename was exercised", file=sys.stderr)
        return 1
    mode = "strict allowlist" if args.allowlist else "whole eligible set"
    print(f"seed {args.seed}: {args.count} multi-file packages, {renamed} renamed, "
          f"{declined} identity refusals, 0 divergences ({mode})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

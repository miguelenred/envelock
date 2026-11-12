#!/usr/bin/env python3
"""Differentially fuzz PHP identity observers and assembled class/function names.

Runs real programs before and after both the legacy global and experimental AST name passes.
Every case must decline without changing any bytes; strict allowlists must abort, never silently
weaken the requested transformation. Dynamic-lookup names are split into separately randomized
fragments; exception cases inspect names in actual traces/messages. This campaign tests known
observers, not all PHP behavior.

    python3 scripts/fuzz_name_observers.py --count 400 --seed 113
"""
from __future__ import annotations

import argparse
import importlib.util
import random
import shutil
import subprocess  # nosec B404 - fixed local PHP CLI invocation
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("envelock", ROOT / "encoder" / "envelock.py")
a = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(a)

OBSERVERS = ("constant", "defined", "function_exists", "method_exists", "property_exists",
             "is_callable", "from_callable", "bind", "bind_to", "dynamic_static",
             "dynamic_method", "dynamic_nullsafe", "trace_array", "trace_string",
             "exception_string", "error_message", "iterator_apply", "array_udiff", "callback_filter")


def generate(rng: random.Random) -> tuple[dict[str, bytes], bool, str, list[str], str]:
    namespaced = bool(rng.randrange(2))
    namespace = f"Lab{rng.randrange(100, 999)}" if namespaced else ""
    cls = f"Widget{rng.randrange(10000, 99999)}"
    fn = f"helper{rng.randrange(10000, 99999)}"
    op = rng.choice(OBSERVERS)
    # PHP single-quoted strings use two backslashes for one backslash in the value.
    scope = "'" + (namespace + "\\\\" if namespace else "") + "'"

    def fragments(name: str) -> str:
        cut = rng.randrange(1, len(name))
        return f"{scope} . '{name[:cut]}' . '{name[cut:]}'"

    class_expr, function_expr = fragments(cls), fragments(fn)
    namespace_stmt = f"namespace {namespace}; " if namespaced else ""
    closure = r"\Closure" if namespaced else "Closure"
    constant = "const VALUE=42;" if op in ("constant", "defined") else ""
    exception = r"\Exception" if namespaced else "Exception"
    throwable = r"\Throwable" if namespaced else "Throwable"
    type_error = r"\TypeError" if namespaced else "TypeError"
    std_class = r"\stdClass" if namespaced else "stdClass"
    throw_ops = ("trace_array", "trace_string", "exception_string")
    fn_body = f"throw new {exception}('x');" if op in throw_ops else "return 8;"
    arg = f"{cls} $x" if op == "error_message" else ""
    declarations = (f"class {cls} {{{constant} public $prop=7; static function go(){{return 9;}}}} "
                    f"function {fn}({arg}) {{{fn_body}}} ")
    prefix = f"$n={class_expr}; "
    if op == "constant":
        body = prefix + "echo constant($n . '::VALUE');"
        expected = "42"
    elif op == "defined":
        body = prefix + "echo defined($n . '::VALUE')?'yes':'no';"
        expected = "yes"
    elif op == "function_exists":
        body = f"$n={function_expr}; echo function_exists($n)?'yes':'no';"
        expected = "yes"
    elif op == "method_exists":
        body = prefix + "echo method_exists($n,'go')?'yes':'no';"
        expected = "yes"
    elif op == "property_exists":
        body = prefix + "echo property_exists($n,'prop')?'yes':'no';"
        expected = "yes"
    elif op == "is_callable":
        body = prefix + "echo is_callable([$n,'go'])?'yes':'no';"
        expected = "yes"
    elif op == "from_callable":
        body = prefix + f"{closure}::fromCallable([$n,'go']); echo 'yes';"
        expected = "yes"
    elif op == "bind":
        body = prefix + f"$c={closure}::bind(function(){{}},null,$n); echo $c?'yes':'no';"
        expected = "yes"
    elif op == "bind_to":
        body = prefix + "$c=function(){}; $b=$c->bindTo(null,$n); echo $b?'yes':'no';"
        expected = "yes"
    elif op == "dynamic_static":
        body = prefix + f"$m='from'.'Callable'; {closure}::$m([$n,'go']); echo 'yes';"
        expected = "yes"
    elif op == "dynamic_method":
        body = prefix + "$c=function(){}; $b=$c->{'bind'.'To'}(null,$n); echo $b?'yes':'no';"
        expected = "yes"
    elif op == "dynamic_nullsafe":
        body = prefix + "$c=function(){}; $m='bind'.'To'; $b=$c?->$m(null,$n); echo $b?'yes':'no';"
        expected = "yes"
    elif op == "iterator_apply":
        body = f"$cb={function_expr}; \\iterator_apply(new \\ArrayIterator([1]),$cb); echo 'yes';"
        expected = "yes"
    elif op == "array_udiff":
        body = f"$cb={function_expr}; \\array_udiff([1],[2],$cb); echo 'yes';"
        expected = "yes"
    elif op == "callback_filter":
        body = (f"$cb={function_expr}; $it=new \\CallbackFilterIterator(new \\ArrayIterator([8]),$cb); "
                "foreach ($it as $item) echo $item;")
        expected = "8"
    else:
        target = ("\\" + namespace + "\\" if namespaced else "") + fn
        if op == "error_message":
            body = (f"try {{{target}(new {std_class});}} catch({type_error} $e){{ "
                    "echo rtrim(explode(' ',explode('type ',$e->getMessage())[1])[0],','); }")
            expected = (namespace + "\\" if namespaced else "") + cls
        else:
            if op == "trace_array":
                observe = "echo $e->getTrace()[0]['function'];"
            elif op == "trace_string":
                observe = "echo explode('(',explode(': ',$e->getTraceAsString())[1])[0];"
            else:
                observe = "$s=(string)$e; preg_match('/#0.*: ([^(]+)/',$s,$m); echo $m[1];"
            body = f"try {{{target}();}} catch({throwable} $e){{ {observe} }}"
            expected = (namespace + "\\" if namespaced else "") + fn
    code = ("<?php " + namespace_stmt + declarations + body).encode()
    fqn = (namespace + "\\" if namespace else "")
    allowlist = [f"type:{fqn}{cls}", f"function:{fqn}{fn}"]
    return {"main.php": code}, namespaced, expected, allowlist, op


def run(php: str, root: Path, files: dict[str, bytes]) -> tuple[int, bytes, bytes]:
    root.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (root / name).write_bytes(data)
    p = subprocess.run([php, "-n", str(root / "main.php")], capture_output=True, timeout=30)  # nosec B603
    return p.returncode, p.stdout, p.stderr


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--count", type=int, default=400)
    parser.add_argument("--seed", type=int, default=113)
    parser.add_argument("--php", default="php")
    args = parser.parse_args()
    if args.count < 1:
        parser.error("--count must be positive")
    php = shutil.which(args.php)
    if not php:
        parser.error("PHP CLI not found")
    rng = random.Random(args.seed)  # nosec B311 - reproducible inputs, not cryptography
    counts: Counter[str] = Counter()
    with tempfile.TemporaryDirectory(prefix="envelock-observers-fuzz-") as temp:
        root = Path(temp)
        for i in range(args.count):
            files, namespaced, expected, allowlist, op = generate(rng)
            before = run(php, root / "before", files)
            if before != (0, expected.encode(), b""):
                print(f"invalid generated program {i}: {before!r}, {files!r}", file=sys.stderr)
                return 2
            try:
                after_files, mapping, reason = a._names_pass(files, php, ast_names=namespaced)
            except ValueError as error:
                print(f"unexpected transform error at {i}: {error}", file=sys.stderr)
                return 1
            after = run(php, root / "after", after_files)
            if after != before or after_files != files or mapping or reason != "dynamic":
                print(f"observer divergence at {i}: before={before!r}, after={after!r}, "
                      f"mapping={mapping}, reason={reason}, source={files!r}", file=sys.stderr)
                return 1
            # Strict boundaries always use the AST, including for global namespace code.
            try:
                a._names_pass(files, php, ast_names=True, allowlist=allowlist)
            except ValueError as error:
                if "dynamic" not in str(error):
                    print(f"unexpected strict refusal at {i}: {error}", file=sys.stderr)
                    return 1
            else:
                print(f"strict policy did not refuse dynamic observer at {i}: {files!r}", file=sys.stderr)
                return 1
            counts["namespaced" if namespaced else "global"] += 1
            counts["observer:" + op] += 1
    variants = sum(counts["observer:" + op] > 0 for op in OBSERVERS)
    print(f"seed {args.seed}: {args.count} observer programs, {counts['global']} global, "
          f"{counts['namespaced']} namespaced, {args.count} strict refusals, "
          f"{variants}/{len(OBSERVERS)} observer variants, 0 divergences")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

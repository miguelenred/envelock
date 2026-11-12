#!/usr/bin/env python3
"""Differential fuzzer for the PHP source transformer (--strip-comments/--obfuscate/--compact/
--encode-strings/--obfuscate-methods/--obfuscate-properties/--obfuscate-flow).

It builds many small, deterministic PHP programs from templates that stress every transform pass
(local variables, closures and arrow functions with captures, private methods and properties,
traits, string literals, whitespace), transforms each with a RANDOM combination of flags, runs the
original and the transformed program with the PHP CLI, and compares stdout and exit status. The
transform must never change behaviour, so ANY difference is a bug. This is how a divergence such as
the trait breakage (a trait method calling a renamed private member) is caught automatically,
without hand-writing a case for it.

Usage:
  python scripts/fuzz_obfuscator.py --count 500 --seed 1 [--php php] [--keep-going] [--quiet]
Exit 0 if no divergence, 1 if any (prints minimal counterexamples), 2 on setup error.
"""
from __future__ import annotations

import argparse
import base64
import importlib.util
import random
import shutil
import subprocess  # nosec B404 # local fuzzer: runs the php binary with fixed argument lists
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("envelock", ROOT / "encoder" / "envelock.py")
a = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(a)

FLAGS = ["strip", "obfuscate", "compact", "encode_strings", "methods", "properties", "obfuscate_flow",
         "vault_strings", "names", "flatten"]


def _name(rng: random.Random, used: set[str], first: str = "abcdefghijkmnp") -> str:
    while True:
        # Keep generated names out of PHP's builtin symbol table (a random `md5` once made the
        # original program fatal, reducing the corpus before the transform even ran).
        n = "fz_gen_" + rng.choice(first) + "".join(
            rng.choice("abcdefghijklmnopqrstuvwxyz0123456789_") for _ in range(rng.randint(2, 8)))
        if n not in used:
            used.add(n)
            return n


def _str_literal(rng: random.Random) -> str:
    # Content that looks like real code (SQL, messages, paths) and survives round-tripping.
    sqlish = "SELECT col_%d FROM t_%d WHERE a = 1" % (rng.randint(0, 99), rng.randint(0, 99))  # nosec B608 # a PHP string literal generated as obfuscator fuzz input, not a SQL query
    body = rng.choice([
        sqlish,
        "error number %d for user" % rng.randint(0, 99),
        "/var/www/app/%d/config" % rng.randint(0, 99),
        "key: value; other // not a comment /* nor this */",
        "",
    ])
    return "'" + body.replace("\\", "").replace("'", "") + "'"


def _func(rng: random.Random, used: set[str]) -> tuple[str, str]:
    """A function with locals, a closure (use) and an arrow function; returns an int."""
    fn = _name(rng, used)
    a1, b1, c1 = (_name(rng, used, "xyzuvw") for _ in range(3))
    k1, k2 = rng.randint(1, 9), rng.randint(1, 9)
    code = (
        f"function {fn}(int ${a1}): int {{\n"
        f"    ${b1} = ${a1} + {k1};\n"
        f"    ${c1} = {k2};\n"
        f"    $add = function (int $p) use (${c1}): int {{ $q = $p + ${c1}; return $q; }};\n"
        f"    $arrow = fn($r) => $r + ${b1};\n"
        f"    $sum = array_sum(array_map(fn($s) => $s * 2, [1, 2, 3]));\n"
        f"    return ${b1} + $add(3) + $arrow(4) + $sum;\n"
        f"}}\n"
    )
    return code, f"{fn}(5)"


def _plain_class(rng: random.Random, used: set[str]) -> tuple[str, str]:
    """A class with private method(s) and private/public properties accessed via $this."""
    cls = _name(rng, used, "ABCDEFGHJKLMNP")
    prop, spub = _name(rng, used), _name(rng, used)
    m1, m2 = _name(rng, used), _name(rng, used)
    s1 = _str_literal(rng)
    code = (
        f"class {cls} {{\n"
        f"    private int ${prop} = {rng.randint(1, 9)};\n"
        f"    public int ${spub} = {rng.randint(1, 9)};\n"
        f"    public function run(): string {{ return $this->{m1}() . ':' . self::{m2}() . ':' . $this->{prop} . ':' . $this->{spub} . ':' . {s1}; }}\n"
        f"    private function {m1}(): int {{ return $this->{prop} + {rng.randint(1, 9)}; }}\n"
        f"    private static function {m2}(): int {{ return {rng.randint(1, 9)}; }}\n"
        f"}}\n"
    )
    return code, f"(new {cls}())->run()"


def _trait_class(rng: random.Random, used: set[str]) -> tuple[str, str]:
    """A trait whose method calls a private method and reads a private property of the using class
    (the pattern that must NOT be broken by method/property renaming)."""
    tr, cls = _name(rng, used, "ABCDEFGHJ"), _name(rng, used, "ABCDEFGHJ")
    prop, meth = _name(rng, used), _name(rng, used)
    code = (
        f"trait {tr} {{ public function viaTrait(): int {{ return $this->{meth}() + $this->{prop}; }} }}\n"
        f"class {cls} {{\n"
        f"    use {tr};\n"
        f"    private int ${prop} = {rng.randint(1, 9)};\n"
        f"    private function {meth}(): int {{ return $this->{prop} * 2; }}\n"
        f"}}\n"
    )
    return code, f"(new {cls}())->viaTrait()"


def _flow_func(rng: random.Random, used: set[str]) -> tuple[str, str]:
    """Loops with continue/break, an early return, a try/catch and a switch: the statement shapes
    control-flow flattening has to keep in order. Line numbers are not echoed here: --compact
    documents that it does not preserve them, so the line check lives in the unit tests."""
    fn = _name(rng, used)
    a1, acc = (_name(rng, used, "xyzuvw") for _ in range(2))
    k = rng.randint(2, 6)
    # Half of the bodies fall off the end (void, echo last): the last dispatch segment must leave the
    # whole loop, not just the switch (O6 regression, see test_obfuscate_flatten_function_that_falls_off_the_end_terminates).
    void = rng.random() < 0.5
    code = (
        f"function {fn}(int ${a1}): {'void' if void else 'string'} {{\n"
        f"    ${acc} = '';\n"
        f"    for ($i = 0; $i < ${a1}; $i++) {{\n"
        f"        if ($i % {k} === 0) {{ continue; }}\n"
        f"        ${acc} .= $i;\n"
        f"        if ($i > {k + 3}) {{ break; }}\n"
        f"    }}\n"
        f"    try {{ if (${a1} > {k}) {{ throw new RuntimeException('r' . ${a1}); }} ${acc} .= 'n'; }}\n"
        f"    catch (RuntimeException $e) {{ ${acc} .= '[' . $e->getMessage() . ']'; }}\n"
        f"    switch (${a1} % 3) {{ case 0: ${acc} .= 'z'; break; default: ${acc} .= 'd'; }}\n"
        + (f"    if (${acc} === '') {{ echo 'empty'; return; }}\n" if void
           else f"    if (${acc} === '') {{ return 'empty'; }}\n")
        + (f"    echo ${acc};\n" if void else f"    return ${acc};\n")
        + "}\n"
    )
    return code, f"{fn}({rng.randint(0, 9)})"


def _string_fn(rng: random.Random, used: set[str]) -> tuple[str, str]:
    """A function returning concatenated string literals (stresses --encode-strings)."""
    fn = _name(rng, used)
    s1, s2 = _str_literal(rng), _str_literal(rng)
    code = f"function {fn}(): string {{ return {s1} . '|' . {s2}; }}\n"
    return code, f"{fn}()"


TEMPLATES = [_func, _plain_class, _trait_class, _string_fn, _flow_func]


def _namespace_alias_program(rng: random.Random) -> str:
    """Exercise aliases, case folding and PHP's separate type/function/constant name tables."""
    used: set[str] = set()
    cls = _name(rng, used, "ABCDEFGHJKLMNP")
    fn = _name(rng, used)
    namespace = "Pkg" + str(rng.randint(100, 999))
    value = rng.randint(1, 99)
    definition = (f"namespace Fz\\{namespace} {{ class {cls} {{ static function go() {{ return {value}; }} }} "
                  f"const {cls} = 13; function {fn}() {{ return 29; }} }}\n")
    mode = rng.randrange(3)
    if mode == 0:
        # An explicit alias identical to the original short name is not the same as no alias.
        use = f"use Fz\\{namespace}\\{cls} as {cls}; use function Fz\\{namespace}\\{fn} as {fn}; "
        use += f"use const Fz\\{namespace}\\{cls} as VALUE; "
        expression = f"{cls}::go(), ':', {fn}(), ':', VALUE"
    elif mode == 1:
        use = (f"use Fz\\{namespace}\\{{{cls} as {cls}, function {fn} as {fn}, "
               f"const {cls} as VALUE}}; ")
        expression = f"{cls}::go(), ':', {fn}(), ':', VALUE"
    else:
        use = ""
        # Class/function names are case-insensitive; constants are not.
        expression = (f"\\fZ\\{namespace.swapcase()}\\{cls.swapcase()}::go(), ':', "
                      f"\\fZ\\{namespace.swapcase()}\\{fn.swapcase()}(), ':', \\Fz\\{namespace}\\{cls}")
    return "<?php\n" + definition + f"namespace Fz\\Runner {{ {use}echo {expression}; }}\n"


def generate(rng: random.Random) -> str:
    used: set[str] = set()
    defs, echoes = [], []
    for _ in range(rng.randint(2, 5)):
        code, expr = rng.choice(TEMPLATES)(rng, used)
        defs.append(code)
        echoes.append(expr)
    body = "".join(defs)
    out = " . '#' . ".join(f"({e})" for e in echoes)
    # A third of the corpus is namespaced; half of those use the more adversarial multi-namespace
    # template with imports, aliases, casing and a constant that shares a class name.
    if rng.random() < 1 / 3:
        if rng.random() < 0.5:
            return _namespace_alias_program(rng)
        head = "namespace Fz\\Gen;\n"
    else:
        head = ""
    return "<?php\n" + head + body + f"echo {out};\n"


def run_php(php: str, path: Path) -> tuple[int, str]:
    r = subprocess.run([php, "-n", str(path)], capture_output=True, text=True, timeout=30)  # nosec B603 # fixed command (php -n <path>), no shell, no untrusted input
    return r.returncode, r.stdout + ("\n[stderr]\n" + r.stderr if r.stderr else "")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--count", type=int, default=500)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--php", default="php")
    p.add_argument("--keep-going", action="store_true", help="report all divergences, not just the first")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()

    php = shutil.which(args.php)
    if not php:
        print(f"php CLI not found: {args.php}", file=sys.stderr)
        return 2
    probe = subprocess.run([php, "-r", 'echo function_exists("token_get_all") && PHP_VERSION_ID >= 80000 ? "1" : "0";'],  # nosec B603 # fixed probe command, no shell
                           capture_output=True, text=True)
    if probe.stdout != "1":
        print("php CLI needs the tokenizer extension (PHP 8+)", file=sys.stderr)
        return 2

    rng = random.Random(args.seed)  # nosec B311 # fuzz seed, not for security; reproducible corpus
    failures = 0
    skipped = 0
    generated = 0
    name_attempts = namespaced_attempts = namespaced_renamed = 0
    flattened_total = 0
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        orig, xfrm = tmp / "orig.php", tmp / "xfrm.php"
        for i in range(args.count):
            generated += 1
            src = generate(rng).encode("utf-8")
            orig.write_bytes(src)
            base_rc, base_out = run_php(php, orig)
            if base_rc != 0:
                skipped += 1            # a generated program that does not run cleanly is not a target
                continue
            opts = {f: rng.random() < 0.5 for f in FLAGS}
            if not any(opts.values()):
                opts["obfuscate"] = True
            # The vault follows name analysis and precedes the per-file transforms. Its calls need
            # a bootstrap __envelock_lit resolver (mirroring the C loader).
            flatten = opts.pop("flatten")
            vault = opts.pop("vault_strings")
            # The global rename runs before the vault, as in pack_tree. Deliberately opt into the
            # experimental AST path here: otherwise every namespaced program would merely be skipped.
            names = opts.pop("names")
            run_target, src_for_rest = xfrm, src
            try:
                if names:
                    name_attempts += 1
                    is_namespaced = b"namespace " in src_for_rest
                    namespaced_attempts += int(is_namespaced)
                    renamed_files, mapping, declined = a._names_pass({"x.php": src_for_rest}, php, ast_names=True)
                    namespaced_renamed += int(is_namespaced and bool(mapping))
                    if not mapping and renamed_files["x.php"] != src_for_rest:
                        # The pass declined, so it must hand back the file byte for byte. A decline
                        # that changed anything would leave references pointing at names that no
                        # longer exist, which is worse than not renaming at all.
                        print(f"[{i}] names pass declined ({declined or 'no candidates'}) but altered "
                              "the source", file=sys.stderr)
                        failures += 1
                        if not args.keep_going:
                            break
                        continue
                    # [0] is the {name: bytes} dict, so index it back down to the one file.
                    src_for_rest = renamed_files["x.php"]
                if vault:
                    vaulted, lits, _ = a._vault_pass({"x.php": src_for_rest}, php)
                    src_for_rest = vaulted["x.php"]
                out = a.transform_sources({"x.php": src_for_rest}, php, **opts)[0]["x.php"]
                if flatten:
                    flat_files, flat_stats = a._flatten_pass({"x.php": out}, php)
                    out = flat_files["x.php"]
                    flattened_total += flat_stats["flattened"]
            except ValueError as error:
                print(f"[{i}] transform error with "
                      f"{opts | {'vault_strings': vault, 'names': names}}: {error}", file=sys.stderr)
                failures += 1
                if not args.keep_going:
                    break
                continue
            xfrm.write_bytes(out)
            if vault:
                stub = (b"<?php function __envelock_lit($i){ static $t=["
                        + b",".join(b'"' + base64.b64encode(s) + b'"' for s in lits["x.php"])
                        + b"]; return base64_decode($t[$i]); }\nrequire " + repr(str(xfrm)).encode() + b";\n")
                run_target = tmp / "boot.php"
                run_target.write_bytes(stub)
            got_rc, got_out = run_php(php, run_target)
            if (got_rc, got_out) != (base_rc, base_out):
                failures += 1
                flags = ",".join(f for f, v in opts.items() if v)
                print(f"\n=== DIVERGENCE #{i} (seed {args.seed}, flags: {flags}, "
                      f"names={names}, vault_strings={vault}, flatten={flatten}) ===")
                print("--- original output ---\n" + base_out)
                print("--- transformed output ---\n" + got_out)
                print("--- program ---\n" + src.decode("utf-8", "replace"))
                if not args.keep_going:
                    break
    if not args.quiet:
        print(f"\nseed {args.seed}: fuzzed {generated - skipped} programs ({skipped} skipped), "
              f"{failures} divergence(s)",
              file=sys.stderr)
        print(f"flatten: {flattened_total} function bodies flattened", file=sys.stderr)
        print(f"names attempts: {name_attempts}; namespaced: {namespaced_attempts}; "
              f"namespaced actually renamed: {namespaced_renamed}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

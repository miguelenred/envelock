"""encoder/virtualize.php: name resolution, by-reference user functions and constant handling.

The compiler runs in the packer's PHP, the program in the server's: anything resolved or converted
at pack time must give what PHP itself gives on the server. These tests run the compiler through
the `php` on PATH (as tests/test_native.py does) and, where a committed loader matches that PHP,
run the program too.
"""

import base64
import json
import platform
import shutil
import struct
import subprocess

import pytest
from test_encoder import ROOT

PHP = shutil.which("php")
# php-parser needs ext/tokenizer; under -n a distribution PHP (tokenizer as a shared module, as on
# Debian/Ubuntu) loads none, so load it explicitly when it is not built in.
TOKENIZER = ([] if PHP is None or subprocess.run(
    [PHP, "-n", "-r", "echo defined('T_THROW') ? 1 : 0;"], capture_output=True, text=True,
    timeout=30).stdout.strip() == "1" else ["-d", "extension=tokenizer"])
pytestmark = pytest.mark.skipif(PHP is None, reason="no php on PATH")
COMPILER = ROOT / "encoder" / "virtualize.php"


def compile_files(files, marked, *ini):
    """Run the compiler on {path: source}. Returns (programs, None) or (None, refusal)."""
    payload = {"files": {p: base64.b64encode(s.encode()).decode() for p, s in files.items()},
               "marked": marked}
    result = subprocess.run([PHP, "-n", *TOKENIZER, "-d", "display_errors=stderr", "-d", "memory_limit=-1",
                             *ini, str(COMPILER)],
                            input=json.dumps(payload).encode(), capture_output=True, timeout=120)
    if result.returncode != 0:
        return None, result.stderr.decode(errors="replace").strip()
    return json.loads(result.stdout)["programs"], None


def compile_one(source, *ini):
    programs, error = compile_files({"a.php": source}, ["f"], *ini)
    return (programs["f"] if programs else None), error


def constants_and_code(program):
    """Decode an ENVVM3 program: ([(type, value), ...], code bytes)."""
    raw = base64.b64decode(program)
    assert raw[:6] == b"ENVVM3"
    count, _locals = struct.unpack(">HH", raw[6:10])
    pos, constants = 10, []
    for _ in range(count):
        kind = raw[pos]
        pos += 1
        if kind == 0:
            constants.append(("null", None))
        elif kind == 1:
            constants.append(("bool", bool(raw[pos])))
            pos += 1
        elif kind == 2:
            constants.append(("int", struct.unpack(">q", raw[pos:pos + 8])[0]))
            pos += 8
        elif kind == 3:
            constants.append(("float", raw[pos:pos + 8]))      # exact IEEE-754 bits
            pos += 8
        elif kind == 4:
            size = int.from_bytes(raw[pos:pos + 3], "big")
            constants.append(("string", raw[pos + 3:pos + 3 + size]))
            pos += 3 + size
        else:
            raise AssertionError(f"unknown constant type {kind}")
    size = struct.unpack(">I", raw[pos:pos + 4])[0]
    return constants, raw[pos + 4:pos + 4 + size]


# Operand bytes after each opcode (VmProgram::validateStack); 21 has a variable width, unused here.
WIDTHS = {1: 2, 2: 2, 3: 2, 4: 1, 5: 1, 6: 4, 7: 4, 8: 3, 9: 0, 10: 0, 11: 2, 12: 0, 13: 0, 14: 0,
          15: 4, 16: 4, 17: 4, 18: 0, 19: 1, 20: 3, 22: 3}


def binary_ops(code):
    """The operator ids of the BINARY (0x04) instructions in a program's code."""
    ops, at = [], 0
    while at < len(code):
        op = code[at]
        assert op in WIDTHS, f"unexpected opcode {op} in {code.hex()}"
        if op == 0x04:
            ops.append(code[at + 1])
        at += 1 + WIDTHS[op]
    return ops


def bits(value):
    return struct.pack("<d", value)


def local_loader():
    """The committed loader for the `php` on PATH (version, thread safety, OS), if it loads."""
    info = subprocess.run([PHP, "-n", "-r", 'echo PHP_MAJOR_VERSION, ".", PHP_MINOR_VERSION, " ",'
                           ' (int) PHP_ZTS, " ", (int) PHP_DEBUG, " ", PHP_OS_FAMILY;'],
                          capture_output=True, text=True, check=True).stdout.split()
    version, zts, debug, family = info
    if debug == "1" or platform.machine().lower() not in ("amd64", "x86_64"):
        return None
    if family == "Windows":
        module = ROOT / "prebuilt/loader/windows-x64" / f"php-{version}-{'ts' if zts == '1' else 'nts'}" / "php_envelock.dll"
    elif family == "Linux":
        module = ROOT / "prebuilt/loader/linux-x86_64" / f"php-{version}-{'zts' if zts == '1' else 'nts'}" / "envelock.so"
    else:
        return None
    if not module.is_file():
        return None
    probe = subprocess.run([PHP, "-n", "-d", f"extension={module}", "-r",
                            "echo function_exists('__envelock_vm') ? 'yes' : 'no';"],
                           capture_output=True, text=True)
    return module if probe.stdout.strip() == "yes" else None


def run_program(module, program, args, *ini):
    code = f"var_export(__envelock_vm({program!r}, {json.dumps(args)}));"
    return subprocess.run([PHP, "-n", "-d", f"extension={module}", *ini, "-r", code],
                          capture_output=True, text=True, timeout=60)


def run_php(code, *ini):
    return subprocess.run([PHP, "-n", *ini, "-r", code], capture_output=True, text=True, timeout=60)


# --------------------------------------------------------------- T-2: imported names

@pytest.mark.parametrize("imports", [
    "use function Lib\\shout as strtoupper;",
    "use function Lib\\strtoupper;",
    "use function Lib\\{shout as strtoupper, other};",
    "use Lib\\{Foo, function shout as strtoupper};",
    "use function Lib\\a, Lib\\shout as STRTOUPPER;",
], ids=["aliased", "plain", "group-function", "mixed-group", "list-case"])
def test_call_to_a_name_imported_with_use_function_is_refused(imports):
    """`use function Lib\\shout as strtoupper;` makes strtoupper() call Lib\\shout in PHP, while
    the VM resolves the name globally: compiling it was a silent miscompile ("HI" for "hi!!!")."""
    program, error = compile_one(f"<?php\n{imports}\nfunction f($a) {{ return strtoupper($a); }}\n")
    assert program is None and "use function" in error, error


def test_imports_of_other_names_do_not_block_calls():
    source = ("<?php\nuse Lib\\Foo;\nuse function Lib\\shout;\nuse const Lib\\X;\n"
              "function f($a) { return strtoupper($a) . (true ? 'y' : 'n'); }\n")
    program, error = compile_one(source)
    assert program is not None, error


def test_true_false_null_imported_with_use_const_are_refused():
    """PHP lets `use const Lib\\X as true;` rebind true in the importing file."""
    program, error = compile_one("<?php\nuse const Lib\\X as TRUE;\nfunction f($a) { return true; }\n")
    assert program is None and "use const" in error, error


# --------------------------------------------------- T-11: the pack's by-ref functions

@pytest.mark.parametrize("files", [
    {"b.php": "<?php\nfunction bump(&$x) { return ++$x; }\n"},
    {"b.php": "<?php\nif (!function_exists('bump')) {\n    function BUMP($y, &...$x) { return 1; }\n}\n"},
    {"b.php": "<?php\nnamespace {\n    function bump(int &$x) { return ++$x; }\n}\n"},
    {"a2.php": "<?php\nfunction outer() { function bump(array &$x) { return 1; } }\n"},
], ids=["other-file", "conditional-variadic", "global-namespace-block", "nested-declaration"])
def test_call_to_a_by_reference_function_of_the_pack_is_refused_at_compile_time(files):
    """The VM passes values only, so such a call failed on every run; the pack's files are all
    given to the compiler, which now refuses it instead."""
    files = {"a.php": "<?php\nfunction f($a) { return bump($a); }\n", **files}
    programs, error = compile_files(files, ["f"])
    assert programs is None and "by-reference" in error and "bump" in error, error


@pytest.mark.parametrize("files", [
    {"b.php": "<?php\nfunction bump($x, ...$rest) { return $x & 1; }\n"},
    {"b.php": "<?php\nnamespace App;\nfunction bump(&$x) { return ++$x; }\n"},
    {"b.php": "<?php\nclass C { function bump(&$x) { return 1; } }\n$g = function (&$x) { return 1; };\n"},
], ids=["by-value", "namespaced", "method-and-closure"])
def test_by_value_or_unreachable_declarations_still_compile(files):
    files = {"a.php": "<?php\nfunction f($a) { return bump($a); }\n", **files}
    programs, error = compile_files(files, ["f"])
    assert programs is not None, error


# ------------------------------------------------------ T-5: float constants by their bits

def test_float_constants_are_merged_by_bits_not_by_printed_text():
    """With serialize_precision=14 in the packer, var_export printed 0.1 + 0.2 and 0.3 alike and
    the program returned 0.30000000000000004 for both. -0.0 and 0.0 stay apart too."""
    source = "<?php\nfunction f($a) { return [0.1 + 0.2, 0.3, -0.0, 0.0, 0.3]; }\n"
    program, error = compile_one(source, "-d", "serialize_precision=14", "-d", "precision=10")
    assert program is not None, error
    floats = [value for kind, value in constants_and_code(program)[0] if kind == "float"]
    for value in (0.1 + 0.2, 0.3, -0.0, 0.0):
        assert floats.count(bits(value)) == 1, (value, floats)
    module = local_loader()
    if module is None:
        return                       # structure checked; no committed loader for this PHP to run it
    run = run_program(module, program, [1], "-d", "serialize_precision=-1")
    expected = run_php("var_export([0.1 + 0.2, 0.3, -0.0, 0.0, 0.3]);", "-d", "serialize_precision=-1")
    assert run.returncode == 0 and run.stdout == expected.stdout, (run.stdout, run.stderr)


# --------------------------------------- T-8: float-to-string stays a server-side operation

@pytest.mark.parametrize("expression,opcode", [
    ("1.23456 . 'x'", 6),
    ("'x' . (0.1 + 0.2)", 6),
    ("1.23456 == 'abc'", 7),
    ("1.23456 <=> '1.23x'", 23),
    ("[1.23456] == ['1.23']", 7),
])
def test_float_to_string_is_not_folded_with_the_packers_precision(expression, opcode):
    """PHP converts a float to text with the `precision` INI of the server that compiles the file;
    the compiler folded it with the packer's. The operation must stay in the program."""
    program, error = compile_one(f"<?php\nfunction f($a) {{ return {expression}; }}\n", "-d", "precision=3")
    assert program is not None, error
    constants, code = constants_and_code(program)
    assert opcode in binary_ops(code), code.hex()
    strings = [value for kind, value in constants if kind == "string"]
    assert b"1.23x" not in strings or expression.endswith("'1.23x'"), strings
    module = local_loader()
    if module is None:
        return
    for precision in ("3", "14"):        # whatever the server uses, the VM agrees with PHP there
        run = run_program(module, program, [1], "-d", f"precision={precision}")
        expected = run_php(f"var_export({expression});", "-d", f"precision={precision}")
        assert run.returncode == 0 and run.stdout == expected.stdout, (precision, run.stdout, run.stderr)


def test_float_arithmetic_and_strict_comparison_are_still_folded():
    """Only the precision-dependent conversions changed: arithmetic and === still fold."""
    program, error = compile_one("<?php\nfunction f($a) { return [0.5 + 1, 1.5 === '1.5', 2.5 > 1]; }\n")
    assert program is not None, error
    constants, code = constants_and_code(program)
    assert binary_ops(code) == [], code.hex()
    assert ("float", bits(1.5)) in constants and ("bool", False) in constants and ("bool", True) in constants

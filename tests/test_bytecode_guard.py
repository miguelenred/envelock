"""Regression tests for the bytecode-layer hardening (internal audit, Nov 2026, BC-1..BC-18).

The native tests reuse tests/test_native.py's `native` fixture and helpers: they run against the
loader under test (ENVELOCK_TEST_EXTENSION, or a POSIX build) and need the test-only bytecode entry
points (envelock_bc_emit / envelock_bc_run / envelock_bc_load_check, --enable-envelock-bcrun-unsafe).
The layer-checker tests need nothing but Python.
"""

import os
import shutil
import struct
import subprocess
import sys
import zlib
from pathlib import Path

import pytest

from test_native import (  # noqa: F401  (native is a pytest fixture)
    BYTECODE_ASSERTIONS,
    BYTECODE_SOURCE,
    ENVELOCK_BC_HEADER_SIZE as H,
    _bytecode_available,
    crashed,
    describe_rc,
    native,
    php,
    php_environment,
)

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check_bc_layers.py"
GENERATOR = ROOT / "extension" / "opcache" / "gen_persist.py"

EMIT = "$i = envelock_bc_emit($argv[1]); if ($i === false) { exit(3); } file_put_contents($argv[2], $i);"
LOAD = "var_dump(envelock_bc_load_check(file_get_contents($argv[1])));"


# ------------------------------------------------------------------------------- helpers
def _need_load_check(native):
    if _bytecode_available(native) != "yes":
        pytest.skip("no bytecode layer for this PHP version")
    if php(native, "-r", "echo function_exists('envelock_bc_load_check') ? 'y' : 'n';").stdout.strip() != "y":
        pytest.skip("loader built without the deserialize-only test entry")


def _emit(native, tmp_path, source_text, name="app", extra_ini=()):
    source = tmp_path / f"{name}.php"
    source.write_text(source_text, encoding="utf-8")
    image = tmp_path / f"{name}.bin"
    r = php(native, "-r", EMIT, str(source), str(image), extra_ini=extra_ini)
    assert r.returncode == 0, describe_rc(r.returncode) + r.stderr[-2000:]
    return source, image


def _rechecksum(blob):
    mem_size = int.from_bytes(blob[48:56], "big")
    blob[76:80] = zlib.adler32(bytes(blob[H:H + mem_size]), 1).to_bytes(4, "big")
    return blob


def _string_offset(blob, text):
    """Offset (from the program start) of the zend_string holding `text` (64-bit layout)."""
    needle = text.encode() + b"\x00"
    found = []
    start = H
    while True:
        v = blob.find(needle, start)
        if v < 0:
            break
        if int.from_bytes(blob[v - 8:v], sys.byteorder) == len(text):
            found.append(v - 24 - H)
        start = v + 1
    return found


# ------------------------------------------------------------------- BC-11: layer checker
def test_layer_checker_passes_on_the_shipped_layers():
    r = subprocess.run([sys.executable, str(CHECKER)], capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stdout + r.stderr


def test_layer_checker_flags_a_layer_that_lost_its_bounds(tmp_path):
    """A layer regenerated (or edited) without the hardening must fail the gate, naming what is gone."""
    copy = tmp_path / "opcache"
    shutil.copytree(ROOT / "extension" / "opcache", copy)
    target = copy / "php83" / "envelock_file_cache.c"
    text = target.read_text(encoding="utf-8")
    assert "ENVELOCK_BOUND_COUNT(p, op_array->last_literal);" in text
    text = text.replace("\t\tENVELOCK_BOUND_COUNT(p, op_array->last_literal);\n", "")
    text = text.replace("envelock_fc_set_handlers(op_array);", "zend_deserialize_opcode_handler(opline);")
    target.write_text(text, encoding="utf-8")
    r = subprocess.run([sys.executable, str(CHECKER), "--root", str(copy)],
                       capture_output=True, text=True, check=False)
    assert r.returncode == 1, r.stdout
    assert "php83/envelock_file_cache.c: missing 'ENVELOCK_BOUND_COUNT(p, op_array->last_literal);'" in r.stdout
    assert "zend_deserialize_opcode_handler(" in r.stdout


def test_layer_checker_flags_drift_between_version_copies(tmp_path):
    copy = tmp_path / "opcache"
    shutil.copytree(ROOT / "extension" / "opcache", copy)
    bc = copy / "php85" / "envelock_bc.c"
    bc.write_text(bc.read_text(encoding="utf-8") + "\n/* drift */\n", encoding="utf-8")
    r = subprocess.run([sys.executable, str(CHECKER), "--root", str(copy)],
                       capture_output=True, text=True, check=False)
    assert r.returncode == 1 and "envelock_bc.c differs between layers" in r.stdout, r.stdout


def test_generator_refuses_to_overwrite_a_hardened_layer(tmp_path):
    """gen_persist.py emits the upstream (unhardened) traversal: it must not silently replace a
    shipped layer."""
    before = (ROOT / "extension" / "opcache" / "php84" / "envelock_file_cache.c").read_bytes()
    r = subprocess.run([sys.executable, str(GENERATOR), str(tmp_path / "no-php-src"), "8.4"],
                       capture_output=True, text=True, check=False)
    assert r.returncode == 3, r.stdout + r.stderr
    assert "REFUSED" in r.stderr and "check_bc_layers.py" in r.stderr
    assert (ROOT / "extension" / "opcache" / "php84" / "envelock_file_cache.c").read_bytes() == before


# --------------------------------------------------------- BC-1: a fatal after a rejection
def test_fatal_error_after_a_rejected_image_does_not_crash(native, tmp_path):
    """A rejected load must leave the engine as it found it. A fault caught by the guard used to leave
    EG(bailout) pointing into a dead frame, so the NEXT fatal error longjmp'ed into it (0xC0000409 on
    Windows); in production a rejection is always followed by a fatal. Each corrupted image is loaded
    and then a fatal is raised: the process must end with that fatal, not a crash."""
    _need_load_check(native)
    _, image = _emit(native, tmp_path, BYTECODE_SOURCE)
    base = image.read_bytes()
    mem_size = int.from_bytes(base[48:56], "big")
    script_offset = int.from_bytes(base[64:72], "big")
    tampered = tmp_path / "t.bin"
    probe = LOAD + " trigger_error('probe', E_USER_ERROR);"
    cases = list(range(H + script_offset, min(H + mem_size - 4, H + script_offset + 520), 8))
    cases.append(76)                                       # a header-level rejection (bad checksum)
    for off in cases:
        blob = bytearray(base)
        blob[off:off + 4] = (0x7FFFFFFF).to_bytes(4, sys.byteorder)
        if off != 76:
            _rechecksum(blob)
        tampered.write_bytes(bytes(blob))
        r = php(native, "-r", probe, str(tampered))
        assert not crashed(r.returncode), f"offset {off - H}: {describe_rc(r.returncode)} {r.stderr[-300:]}"
        assert "probe" in r.stderr, f"offset {off - H}: the fatal after the load never ran: {r.stderr[-300:]}"


# ------------------------------------------------- BC-3/4/9/12/15: corrupted counts and fields
def test_corrupted_counts_and_fields_are_rejected_without_a_crash(native, tmp_path):
    """Every word of the script record, then a stride across the whole program, forced to a hostile
    count (0x7fffffff / 0xffffffff), re-checksummed: each load must be a clean accept or a clean
    rejection. At least some must be caught by the validation itself (not merely survive)."""
    _need_load_check(native)
    _, image = _emit(native, tmp_path, BYTECODE_SOURCE)
    base = image.read_bytes()
    mem_size = int.from_bytes(base[48:56], "big")
    script_offset = int.from_bytes(base[64:72], "big")
    tampered = tmp_path / "t.bin"
    record = range(H + script_offset, min(H + mem_size - 4, H + script_offset + 400), 4)
    spread = range(H, H + mem_size - 4, 96)
    validated = 0
    for index, off in enumerate(sorted(set(record) | set(spread))):
        value = 0x7FFFFFFF if index % 2 == 0 else 0xFFFFFFFF
        blob = bytearray(base)
        blob[off:off + 4] = value.to_bytes(4, sys.byteorder)
        tampered.write_bytes(bytes(_rechecksum(blob)))
        r = php(native, "-r", LOAD, str(tampered))
        assert not crashed(r.returncode), f"offset {off - H}: {describe_rc(r.returncode)} {r.stderr[-300:]}"
        clean_fatal = r.returncode == 255 and "Fatal error" in r.stderr   # e.g. a forged redeclaration
        assert r.stdout.strip() in ("bool(true)", "bool(false)") or clean_fatal, (
            f"offset {off - H}: {r.stdout!r} {r.stderr[-300:]}")
        if "corrupt bytecode image" in r.stderr:
            validated += 1
    assert validated > 0, "no corruption was caught by the deserializer's own checks"


def test_a_deeply_nested_constant_still_loads(native, tmp_path):
    """The recursion budget (BC-13) must not refuse a legitimately nested literal."""
    _need_load_check(native)
    depth = 300
    source_text = "<?php const DEEP = " + "[" * depth + "1" + "]" * depth + ";\n" \
                  "$d = DEEP; $n = 0; while (is_array($d)) { $d = $d[0]; $n++; } echo $n, \"\\n\";\n"
    _, image = _emit(native, tmp_path, source_text)
    r = php(native, "-r", "var_dump(envelock_bc_run(file_get_contents($argv[1])));", str(image))
    assert r.returncode == 0, describe_rc(r.returncode) + r.stderr[-1000:]
    assert r.stdout.strip().splitlines() == [str(depth), "bool(true)"]


# ----------------------------------------------------------------- BC-6: early-binding slot
EARLY_BINDING_SOURCE = """<?php
class EnvChildX extends EnvBaseX {}
echo "ok\\n";
"""


@pytest.mark.parametrize("slot", [0x7FFFFFF8, 0x00000003])
def test_early_binding_cache_slot_out_of_range_is_rejected(native, tmp_path, slot):
    """The install step stores the bound class at run_time_cache + cache_slot, a value read from the
    image: a slot outside the cache (or misaligned) must be refused, never written."""
    _need_load_check(native)
    _, image = _emit(native, tmp_path, EARLY_BINDING_SOURCE)
    blob = bytearray(image.read_bytes())
    child = _string_offset(blob, "envchildx")
    parent = _string_offset(blob, "envbasex")
    if not child or not parent:
        pytest.skip("could not locate the early-binding names in this build's image")
    records = []
    for c in child:
        for p in parent:
            pattern_c, pattern_p = struct.pack("<Q", c), struct.pack("<Q", p)
            pos = H
            while True:
                pos = blob.find(pattern_c, pos)
                if pos < 0:
                    break
                if (pos - H) % 8 == 0 and blob[pos + 16:pos + 24] == pattern_p:
                    records.append(pos)
                pos += 1
    if len(records) != 1:
        pytest.skip(f"expected one early-binding record, found {len(records)}")
    untouched = php(native, "-r", LOAD, str(image))
    assert untouched.stdout.strip() == "bool(true)", untouched.stderr[-1000:]
    slot_at = records[0] + 24
    blob[slot_at:slot_at + 4] = struct.pack("<I", slot)
    tampered = tmp_path / "slot.bin"
    tampered.write_bytes(bytes(_rechecksum(blob)))
    r = php(native, "-r", LOAD, str(tampered))
    assert not crashed(r.returncode), describe_rc(r.returncode)
    assert r.stdout.strip() == "bool(false)", r.stdout + r.stderr[-1000:]
    assert "early binding cache slot out of range" in r.stderr


# ------------------------------------------------------- BC-10: extension missing at run time
def _ext_dir_ini():
    php_bin = shutil.which("php")
    if not php_bin:
        return ()
    ext = Path(php_bin).resolve().parent / "ext"
    return ("-d", f"extension_dir={ext}") if ext.is_dir() else ()


def test_an_image_calling_a_missing_extension_does_not_crash(native, tmp_path):
    """Packed where mbstring was loaded, run where it is not: the call must fail as PHP does
    ('Call to undefined function'), not crash the worker. Before the fix the emitter compiled the call
    to INIT_FCALL, which assumes the function exists, and the run segfaulted."""
    _need_load_check(native)
    probe = subprocess.run(["php", "-n", *_ext_dir_ini(), "-d", "extension=mbstring", "-r",
                            "echo extension_loaded('mbstring') ? 1 : 0;"],
                           capture_output=True, text=True, check=False, env=php_environment())
    bare = subprocess.run(["php", "-n", "-r", "echo extension_loaded('mbstring') ? 1 : 0;"],
                          capture_output=True, text=True, check=False, env=php_environment())
    if probe.stdout.strip() != "1" or bare.stdout.strip() != "0":
        pytest.skip("mbstring is not available as a loadable shared extension here")
    source_text = "<?php\necho \"start\\n\";\necho mb_strlen(\"abc\"), \"\\n\";\n"
    _, image = _emit(native, tmp_path, source_text, extra_ini=(*_ext_dir_ini(), "-d", "extension=mbstring"))
    r = php(native, "-r", "envelock_bc_run(file_get_contents($argv[1]));", str(image))
    assert not crashed(r.returncode), describe_rc(r.returncode)
    assert "start" in r.stdout
    assert "Call to undefined function mb_strlen()" in (r.stdout + r.stderr)
    ok = php(native, "-r", "envelock_bc_run(file_get_contents($argv[1]));", str(image),
             extra_ini=(*_ext_dir_ini(), "-d", "extension=mbstring"))
    assert ok.returncode == 0 and ok.stdout.splitlines() == ["start", "3"], ok.stderr[-1000:]


def test_namespaced_calls_to_internal_functions_roundtrip(native, tmp_path):
    """Unqualified calls in a namespace used to compile to frameless calls even with internal
    functions ignored; the image must not carry them (the loader refuses them) and must still behave
    like its source."""
    _need_load_check(native)
    source_text = """<?php
namespace App\\Util;
function check(array $a, string $s): string {
    return (in_array(3, $a) ? "yes" : "no") . ":" . strlen($s) . ":" . substr($s, 1, 2) . ":"
        . (str_contains($s, "b") ? "b" : "-") . ":" . implode(",", $a) . ":" . max(1, 7) . ":" . \\strlen("xyz");
}
echo check([1, 2, 3], "abcd"), "\\n";
"""
    source, image = _emit(native, tmp_path, source_text)
    plain = subprocess.run(["php", "-n", str(source)], capture_output=True, text=True, check=False,
                           env=php_environment())
    r = php(native, "-r", "envelock_bc_run(file_get_contents($argv[1]));", str(image))
    assert r.returncode == 0, describe_rc(r.returncode) + r.stderr[-1000:]
    assert r.stdout == plain.stdout


# ------------------------------------------------------ BC-16: SAPI-independent image identity
def _php_cgi():
    php_bin = shutil.which("php")
    candidates = [shutil.which("php-cgi")]
    if php_bin:
        candidates.append(str(Path(php_bin).resolve().parent / ("php-cgi.exe" if os.name == "nt" else "php-cgi")))
    for c in candidates:
        if c and Path(c).exists():
            return c
    return None


def test_a_cli_packed_image_loads_under_php_cgi(native, tmp_path):
    """The image used to carry zend_system_id, which also hashes the SAPI's engine hooks (the Windows
    CLI's Ctrl+C interrupt handler, pcntl on Linux), so a CLI-packed image was refused by php-cgi/FPM of
    the same build. It must load there, and PHP_SAPI/PHP_BINARY must be the RUNNING process', not the
    packer's (they used to be folded into the image at pack time)."""
    _need_load_check(native)
    cgi = _php_cgi()
    if cgi is None:
        pytest.skip("no php-cgi next to the php under test")
    _, image = _emit(native, tmp_path, "<?php echo PHP_SAPI, '|', php_sapi_name(), '|', basename(PHP_BINARY), \"\\n\";\n",
                     name="sapi")
    runner = tmp_path / "run.php"
    runner.write_text("<?php var_dump(envelock_bc_run(file_get_contents($argv[1] ?? getenv('ENVELOCK_IMAGE'))));\n",
                      encoding="utf-8")
    env = php_environment()
    env["ENVELOCK_IMAGE"] = str(image)
    r = subprocess.run([cgi, "-n", "-q", "-d", f"extension={native[1]}", "-d", "display_errors=1",
                        "-d", "opcache.enable=0", str(runner)],
                       capture_output=True, text=True, check=False, env=env, timeout=120)
    assert not crashed(r.returncode), describe_rc(r.returncode)
    out = r.stdout.replace("\r", "")
    assert "bool(true)" in out, out + r.stderr
    assert out.splitlines()[0].startswith("cgi-fcgi|cgi-fcgi|php-cgi"), out


# ------------------------------------------- BC-14: PHP 8.5 constant-expression closures, attributes
PHP85_SOURCE = """<?php
#[Attribute(Attribute::TARGET_ALL)]
final class EnvAttr { public function __construct(public string $v) {} }
#[EnvAttr("on-a-constant")]
const ENV_ATTRIBUTED = 5;
final class EnvK {
    public const F = static function (int $x): int { return $x * 7; };
    public const G = strlen(...);
}
$attrs = (new ReflectionConstant('ENV_ATTRIBUTED'))->getAttributes();
echo ENV_ATTRIBUTED, "|", (EnvK::F)(3), "|", (EnvK::G)("abcd"), "|", $attrs[0]->newInstance()->v, "\\n";
"""


def test_php85_constant_expression_closures_and_attributed_constants_roundtrip(native, tmp_path):
    """The 8.5-only paths of the deserializer (ZEND_AST_OP_ARRAY, ZEND_AST_CALLABLE_CONVERT whose cached
    function pointer is now always reset, ZEND_DECLARE_ATTRIBUTED_CONST whose OP_DATA literal is now
    checked) must still reproduce the program exactly."""
    _need_load_check(native)
    version = php(native, "-r", "echo PHP_VERSION_ID;").stdout.strip()
    if not version.isdigit() or int(version) < 80500:
        pytest.skip("PHP 8.5 feature")
    source, image = _emit(native, tmp_path, PHP85_SOURCE)
    plain = subprocess.run(["php", "-n", str(source)], capture_output=True, text=True, check=False,
                           env=php_environment())
    assert plain.returncode == 0, plain.stderr[-1000:]
    r = php(native, "-r", "envelock_bc_run(file_get_contents($argv[1]));", str(image))
    assert r.returncode == 0, describe_rc(r.returncode) + r.stderr[-1000:]
    assert r.stdout == plain.stdout == "5|21|4|on-a-constant\n"

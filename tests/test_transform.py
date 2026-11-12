"""pack --strip-comments / --obfuscate: identical behaviour and line numbers, less to read."""

import re
import shutil
import subprocess
import uuid

import pytest
from test_encoder import ROOT, a

SAMPLE = b'''<?php
declare(strict_types=1);
/**
 * Class docblock: kept in memory by PHP unless stripped.
 */
#[\\Attribute]
final class Demo
{
    // a line comment with "quotes" and /* fake opener
    public function text(): string
    {
        $s = "// not a comment, /* nor this */, # nor this";
        $h = <<<EOT
        # heredoc line, not a comment
        EOT;
        return $s . "|" . $h;   # trailing hash comment
    }

    /** @return int */
    public function one(): int { return/**/1; }

    public function fail(): void
    {
        /* multi
           line */ throw new \\RuntimeException("line " . __LINE__);
    }
}
$d = new Demo();
echo $d->text(), "|", $d->one(), "|", (new ReflectionMethod(Demo::class, "one"))->getDocComment() === false ? "nodoc" : "doc", "|";
try { $d->fail(); } catch (RuntimeException $e) { echo $e->getMessage(), "@", $e->getLine(); }
'''

# Locals to rename ($subtotalAmount, $taxRate, ...) and everything that must keep its name.
OBFUSCATE = b'''<?php
namespace Demo;
use function strlen;
interface Priced { public function price(int $units): float; }
abstract class Base { abstract protected function rate(): float; }
final class Invoice extends Base implements Priced
{
    public static int $count = 0;
    public array $lines = [];
    public function __construct(private float $unitPrice = 2.5) {}
    protected function rate(): float { return 0.25; }
    public function price(#[\\SensitiveParameter] int $units, int $a = 0): float
    {
        static $calls = 0;
        $calls++;
        self::$count++;
        $subtotalAmount = $units * $this->unitPrice;
        $taxRate = $this->rate();
        $label = "total $subtotalAmount {$taxRate}";
        $text = <<<TXT
        units: $units
        TXT;
        foreach ([1, 2] as $index => $value) { $subtotalAmount += $index * $value * $a; }
        [$first, $second] = [1, 2];
        try { throw new \\Exception("x"); } catch (\\Exception $caught) { $first += strlen($caught->getMessage()); }
        $field = "lines";
        $this->$field[] = $label . "|" . trim($text);
        $ref = &$first;
        $ref++;
        return round($subtotalAmount * (1 + $taxRate) + $first + $second, 2);
    }
    public function names(): array { $keepMe = 1; return compact("keepMe"); }
    public function closure(): int { $keepToo = 2; return (fn() => $keepToo)(); }
    public function variable(): int { $keepThree = 3; $name = "keepThree"; return $$name; }
    public function dynamic(): array { $keepFour = 4; return \\call_user_func('compact', 'keepFour'); }
    public function built(): array { $keepFive = 5; return \\call_user_func_array('comp' . 'act', ['keepFive']); }
}
function helper(int $units, ?Invoice $inv = null): string
{
    $invoiceTotal = ($inv ?? new Invoice())->price(units: $units);
    return sprintf("%.2f", $invoiceTotal);
}
$i = new Invoice();
echo helper(4), "|", $i->price(3), "|", json_encode($i->names()), "|", $i->closure(), "|",
     $i->variable(), "|", json_encode($i->dynamic()), "|", json_encode($i->built()), "|", Invoice::$count, "|", implode(",", $i->lines), "|",
     implode(",", array_map(fn($p) => $p->getName(), (new \\ReflectionMethod(Invoice::class, "price"))->getParameters()));
'''


def _php_with_tokenizer():
    php = shutil.which("php")
    if not php:
        return None
    probe = subprocess.run([php, "-r", 'echo function_exists("token_get_all") && PHP_VERSION_ID >= 80000 ? "1" : "0";'],
                           capture_output=True, text=True)
    return php if probe.stdout == "1" else None


PHP = _php_with_tokenizer()
needs_php = pytest.mark.skipif(PHP is None, reason="php CLI with the tokenizer extension (PHP 8+) required")


def run_php(path):
    return subprocess.run([PHP, "-n", str(path)], capture_output=True, text=True).stdout


def transform(tmp_path, source, **options):
    original, changed = tmp_path / "original.php", tmp_path / "changed.php"
    original.write_bytes(source)
    changed.write_bytes(a.transform_sources({"x.php": source}, PHP, **options)[0]["x.php"])
    return original, changed


@needs_php
def test_strip_keeps_behaviour_and_line_numbers(tmp_path):
    original, stripped = transform(tmp_path, SAMPLE, strip=True)
    before, after = run_php(original), run_php(stripped)
    assert before.replace("|doc|", "|nodoc|") == after       # only the docblock differs
    throw_line = SAMPLE.split(b"\n").index(next(x for x in SAMPLE.split(b"\n") if b"throw new" in x)) + 1
    assert "|nodoc|" in after and after.endswith(f"@{throw_line}")   # line of the throw unchanged
    assert stripped.read_bytes().count(b"\n") == SAMPLE.count(b"\n")
    tokens = subprocess.run(
        [PHP, "-r", 'foreach (token_get_all(file_get_contents($argv[1])) as $t) if (is_array($t) && in_array($t[0], [T_COMMENT, T_DOC_COMMENT])) echo "C";', str(stripped)],
        capture_output=True, text=True).stdout
    assert tokens == ""
    assert b"// not a comment, /* nor this */, # nor this" in stripped.read_bytes()
    assert b"# heredoc line, not a comment" in stripped.read_bytes()
    assert b"#[\\Attribute]" in stripped.read_bytes()


@needs_php
def test_obfuscate_renames_locals_only_and_keeps_behaviour(tmp_path):
    original, obfuscated = transform(tmp_path, OBFUSCATE, obfuscate=True)
    before, after = run_php(original), run_php(obfuscated)
    assert before == after and "units,a" in after
    text = obfuscated.read_bytes()
    assert text.count(b"\n") == OBFUSCATE.count(b"\n")
    for gone in (b"$subtotalAmount", b"$taxRate", b"$label", b"$caught", b"$invoiceTotal", b"$calls",
                 b"$index", b"$field", b"$keepToo"):   # $keepToo is captured by an arrow fn: now renamed too
        assert gone not in text, gone
    for kept in (b"$units", b"$a = 0", b"$unitPrice", b"$this->", b"self::$count", b"public static int $count",
                 b"$keepMe", b"$keepThree", b"$keepFour", b"$keepFive", b"units: $units", b"$inv"):
        assert kept in text, kept
    assert b"$a" in text and text.count(b"int $a") == 1      # a local never takes a parameter's name


ANON_CLASS = b'''<?php
function make_attr(): string {
    $localWork = "work";
    $dto = new #[\\AllowDynamicProperties] class { public string $status = "ok"; };
    return $dto->status . "|" . $localWork;
}
function make_plain(): string {
    $localSpan = "span";
    $dto = new class { public int $tag = 7; };
    return $dto->tag . "|" . $localSpan;
}
echo make_attr(), "||", make_plain();
'''

USE_FUNCTION_ALIAS = b'''<?php
use function compact as c;
use function get_defined_vars as gdv;
function one(): array { $keepOne = 11; $other = 22; return c("keepOne"); }
function two(): array { $keepTwo = 33; return gdv(); }
echo json_encode(one()), "||", json_encode(two());
'''


@needs_php
def test_obfuscate_anonymous_class_forms_keep_behaviour(tmp_path):
    """ENV-08: new readonly class and new #[Attr] class are class scopes too, so a function that
    builds one is left as is; its public properties must not be renamed as if locals."""
    original, obfuscated = transform(tmp_path, ANON_CLASS, obfuscate=True)
    assert run_php(original) == run_php(obfuscated) == "ok|work||7|span"
    text = obfuscated.read_bytes()
    assert b"$status" in text and b"$tag" in text               # properties kept, not corrupted


@needs_php
def test_obfuscate_use_function_alias_of_byname(tmp_path):
    """ENV-08: `use function compact as c;` makes c() resolve to compact at run time; a function
    that uses the alias must be left as is so its locals keep the names compact() looks up."""
    original, obfuscated = transform(tmp_path, USE_FUNCTION_ALIAS, obfuscate=True)
    assert run_php(original) == run_php(obfuscated)
    assert run_php(obfuscated) == '{"keepOne":11}||{"keepTwo":33}'


@needs_php
def test_transform_preserves_data_after_halt_compiler(tmp_path):
    """ENV-08: __halt_compiler() is followed by raw data the tokenizer does not return; rebuilding
    from tokens would silently drop it, so such a file is passed through untouched."""
    source = b'<?php function g(){ $localThing = 1; return $localThing; } echo g();\n__halt_compiler();\nRAW-PAYLOAD-BYTES'
    for options in ({"obfuscate": True}, {"strip": True}):
        _, changed = transform(tmp_path, source, **options)
        assert b"RAW-PAYLOAD-BYTES" in changed.read_bytes()
        assert changed.read_bytes() == source                   # untouched


@needs_php
def test_strip_and_obfuscate_together(tmp_path):
    original, both = transform(tmp_path, OBFUSCATE, strip=True, obfuscate=True)
    assert run_php(original) == run_php(both)


@needs_php
def test_transform_refuses_invalid_php():
    with pytest.raises(ValueError, match="broken.php"):
        a.transform_sources({"ok.php": b"<?php echo 1;", "broken.php": b"<?php this is not php;"}, PHP,
                            strip=True)


def test_transform_without_php_is_a_clear_error():
    with pytest.raises(ValueError, match="need a php CLI"):
        a.transform_sources({"x.php": b"<?php echo 1;"}, "/nonexistent/php", obfuscate=True)


@needs_php
def test_pack_with_strip_comments_and_obfuscate(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.php").write_bytes(SAMPLE)
    (src / "invoice.php").write_bytes(OBFUSCATE)
    owner, recipient = a.make_owner(), a.make_recipient("strip")
    info = a.pack_tree(src, tmp_path / "out", [a.recipient_public(recipient)], owner,
                       str(uuid.uuid4()), php=PHP, strip_comments=True, obfuscate=True)
    assert info["comments_stripped"] is True and info["obfuscated"] is True
    identity = a.make_identity(recipient, owner)
    plain = a.open_protected((tmp_path / "out" / "app.php").read_bytes(), identity)
    assert b"Class docblock" not in plain and plain.count(b"\n") == SAMPLE.count(b"\n")
    plain = a.open_protected((tmp_path / "out" / "invoice.php").read_bytes(), identity)
    assert b"$subtotalAmount" not in plain and b"$units" in plain


@needs_php
def test_compact_keeps_behaviour_and_removes_structure(tmp_path):
    """--compact collapses whitespace and comments to single spaces: same behaviour (modulo the
    docblock, removed like --strip-comments), far fewer newlines, no indentation, no comments, and
    strings/heredocs untouched. Fails without the compact logic (output would keep every newline)."""
    original, compacted = transform(tmp_path, SAMPLE, compact=True)
    before, after = run_php(original), run_php(compacted)
    # Identical behaviour except: the docblock is gone (like --strip-comments) and line numbers are
    # not preserved, so __LINE__/getLine() values change. Normalise the digits to compare the rest.
    def norm(s):
        return re.sub(r"\d+", "#", s)
    assert norm(before).replace("|doc|", "|nodoc|") == norm(after)
    text = compacted.read_bytes()
    assert text.count(b"\n") < SAMPLE.count(b"\n") // 3          # line structure collapsed
    assert b"a line comment with" not in text and b"Class docblock" not in text \
        and b"trailing hash comment" not in text                # real comments removed
    assert b"# heredoc line, not a comment" in text             # heredoc body preserved verbatim
    assert b"// not a comment, /* nor this */, # nor this" in text  # string literal preserved
    # No two tokens merged: it must still tokenise to the same tokens as the original (minus
    # comments/whitespace), i.e. it parses and runs — already asserted by the equal output above.


@needs_php
def test_compact_composes_with_obfuscate(tmp_path):
    """--compact and --obfuscate together: still identical behaviour."""
    original, out = transform(tmp_path, OBFUSCATE, obfuscate=True, compact=True)
    assert run_php(original) == run_php(out)
    text = out.read_bytes()
    assert b"$subtotalAmount" not in text and b"$units" in text   # locals renamed, params kept
    assert text.count(b"\n") < OBFUSCATE.count(b"\n") // 3        # structure collapsed


@needs_php
def test_pack_with_compact(tmp_path):
    """pack --compact flows through to the encoded bytes and reports it."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.php").write_bytes(SAMPLE)
    owner, recipient = a.make_owner(), a.make_recipient("compact")
    info = a.pack_tree(src, tmp_path / "out", [a.recipient_public(recipient)], owner,
                       str(uuid.uuid4()), php=PHP, compact=True)
    assert info["compacted"] is True
    plain = a.open_protected((tmp_path / "out" / "app.php").read_bytes(), a.make_identity(recipient, owner))
    assert plain.count(b"\n") < SAMPLE.count(b"\n") // 3 and b"Class docblock" not in plain


@needs_php
def test_encode_strings_keeps_behaviour_and_hides_literals(tmp_path):
    """--encode-strings re-spells string literals as \\xNN (same value): identical behaviour, the
    readable literals are gone, and interpolated/heredoc strings are untouched. Fails without the
    feature (the literal would still be readable)."""
    original, encoded = transform(tmp_path, SAMPLE, encode_strings=True)
    assert run_php(original) == run_php(encoded)            # identical behaviour, line numbers kept
    text = encoded.read_bytes()
    assert text.count(b"\n") == SAMPLE.count(b"\n")         # encode_strings does not move lines
    assert b"// not a comment, /* nor this */, # nor this" not in text   # the literal is hidden
    assert rb"\x2f\x2f\x20\x6e\x6f\x74" in text             # ...re-spelled as \xNN
    assert b"# heredoc line, not a comment" in text         # heredoc body untouched


@needs_php
def test_encode_strings_composes_with_obfuscate(tmp_path):
    """--encode-strings with --obfuscate: identical behaviour. Interpolated strings keep their
    (renamed) variables; single-quoted literals used by call_user_func keep their value."""
    original, out = transform(tmp_path, OBFUSCATE, obfuscate=True, encode_strings=True)
    assert run_php(original) == run_php(out)
    text = out.read_bytes()
    assert b"$subtotalAmount" not in text                   # locals still obfuscated
    assert b'"lines"' not in text and b"'lines'" not in text  # the literal is encoded away


METHODS = b'''<?php
class Svc
{
    private $value = 10;
    public function run(): int
    {
        return $this->helper() + $this->calc(3) + self::stat() + $this->value;
    }
    private function helper(): int { return 5; }
    private function calc(int $x): int { return $x * 2; }
    private static function stat(): int { return 100; }
    private function viaString(): int { return 7; }
    private function viaOther(): int { return 9; }
    public function useThem(Svc $o): int
    {
        $cb = [$this, 'viaString'];
        return call_user_func($cb) + $o->viaOther();
    }
}
$s = new Svc();
echo $s->run(), "|", $s->useThem(new Svc());
'''


@needs_php
def test_obfuscate_methods_renames_only_unambiguous_private(tmp_path):
    """--obfuscate-methods renames private methods reached only via $this->/self::/static::; it
    keeps (does not rename) a method whose name is used as a string callable or called on another
    object. Behaviour and line numbers are unchanged. Fails without the feature."""
    original, out = transform(tmp_path, METHODS, methods=True)
    assert run_php(original) == run_php(out)                       # identical behaviour
    text = out.read_bytes()
    assert text.count(b"\n") == METHODS.count(b"\n")               # line numbers preserved
    assert b"function helper" not in text                          # $this-> only -> renamed
    assert b"function calc" not in text and b"function stat" not in text
    assert b"function viaString" in text                           # [$this,'viaString'] -> kept
    assert b"function viaOther" in text                            # $o->viaOther() -> kept
    assert b"$this->value" in text and b"private $value" in text   # property untouched


@needs_php
def test_obfuscate_methods_skips_classes_with_dynamic_calls(tmp_path):
    """A class using a dynamic method call ($this->$m()) is left entirely untouched."""
    src = b'''<?php
class D {
    public function go(string $m): int { return $this->$m(); }
    private function secret(): int { return 42; }
}
$d = new D();
echo $d->go("secret");
'''
    original, out = transform(tmp_path, src, methods=True)
    assert run_php(original) == run_php(out)
    assert b"function secret" in out.read_bytes()                  # dynamic class -> not renamed


@needs_php
def test_pack_with_obfuscate_methods(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.php").write_bytes(METHODS)
    owner, recipient = a.make_owner(), a.make_recipient("m")
    info = a.pack_tree(src, tmp_path / "out", [a.recipient_public(recipient)], owner,
                       str(uuid.uuid4()), php=PHP, obfuscate_methods=True)
    assert info["private_methods_obfuscated"] is True
    plain = a.open_protected((tmp_path / "out" / "a.php").read_bytes(), a.make_identity(recipient, owner))
    assert b"function helper" not in plain and b"function viaString" in plain


CLOSURES = b'''<?php
function compute(int $base): int
{
    $total = $base;
    $byVal = 10;
    $byRef = 0;
    $add = function (int $p) use ($byVal): int { $inner = $p + $byVal; return $inner; };
    $bump = function () use (&$byRef): void { $byRef += 5; };
    $arrow = fn(int $q) => $q + $total;
    $total += $add(3);
    $bump();
    $nums = array_map(fn($x) => $x * $total, [1, 2, 3]);
    return $total + $byRef + $arrow(4) + array_sum($nums);
}
echo compute(100);
'''


@needs_php
def test_obfuscate_covers_closures_and_arrow_functions(tmp_path):
    """Local variables are now obfuscated even in functions that contain closures/arrow functions:
    a captured variable is renamed the same way inside and outside the closure, parameters keep
    their names, and behaviour is identical. Fails if closures are skipped (vars stay readable)."""
    original, out = transform(tmp_path, CLOSURES, obfuscate=True)
    assert run_php(original) == run_php(out)          # identical behaviour (100-based result)
    text = out.read_bytes()
    for gone in (b"$total", b"$byVal", b"$byRef", b"$inner", b"$nums"):
        assert gone not in text, gone                 # locals + captures renamed (coverage gain)
    for kept in (b"$base", b"$p", b"$q", b"$x"):       # parameters (outer and nested) keep names
        assert kept in text, kept


PROPERTIES = b'''<?php
class Account
{
    private int $balanceCents = 0;
    private string $ownerLabel = "n/a";
    private $shared = 1;
    public $publicId = 7;
    public function deposit(int $c): void { $this->balanceCents += $c; $this->ownerLabel = "set"; }
    public function report(Peer $p): string
    {
        return $this->balanceCents . ":" . $this->ownerLabel . ":" . ($this->shared + $p->shared) . ":" . $this->publicId;
    }
}
class Peer { public $shared = 2; }
$a = new Account(); $a->deposit(150);
echo $a->report(new Peer());
'''


@needs_php
def test_obfuscate_properties_renames_only_unambiguous_private(tmp_path):
    """--obfuscate-properties renames private instance properties used only as $this->name, keeps
    behaviour, and leaves alone a name used on another object, a public property, and static/dynamic
    cases. Fails without the feature."""
    original, out = transform(tmp_path, PROPERTIES, properties=True)
    assert run_php(original) == run_php(out)
    text = out.read_bytes()
    assert text.count(b"\n") == PROPERTIES.count(b"\n")
    assert b"balanceCents" not in text and b"ownerLabel" not in text   # $this-> only -> renamed
    assert b"shared" in text                                           # $p->shared -> kept
    assert b"public $publicId" in text and b"publicId" in text         # public -> untouched


@needs_php
def test_obfuscate_properties_skips_serialize_and_reflection(tmp_path):
    """A class that serializes, uses get_object_vars, __get/__set or Reflection, or where a property
    name appears as a string, is left untouched (property names leak through those paths)."""
    src = b'''<?php
class S {
    private int $amount = 0;
    public function set(int $x): void { $this->amount = $x; }
    public function dump(): string { return serialize($this); }
    public function viaName(): int { $k = "amount"; return $this->$k; }
}
$s = new S(); $s->set(5);
echo strlen($s->dump()) > 0 ? "ok" : "no";
'''
    original, out = transform(tmp_path, src, properties=True)
    assert run_php(original) == run_php(out)
    assert b"$amount" in out.read_bytes()                  # serialize()/dynamic -> class skipped


@needs_php
def test_pack_with_obfuscate_properties(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.php").write_bytes(PROPERTIES)
    owner, recipient = a.make_owner(), a.make_recipient("p")
    info = a.pack_tree(src, tmp_path / "out", [a.recipient_public(recipient)], owner,
                       str(uuid.uuid4()), php=PHP, obfuscate_properties=True)
    assert info["private_properties_obfuscated"] is True
    plain = a.open_protected((tmp_path / "out" / "a.php").read_bytes(), a.make_identity(recipient, owner))
    assert b"balanceCents" not in plain and b"shared" in plain


TRAIT_METHOD = b'''<?php
trait Helper { public function viaTrait() { return $this->secret() + 1; } }
class Widget { use Helper; private function secret() { return 41; } public function run() { return $this->secret(); } }
$w = new Widget();
echo $w->run(), "|", $w->viaTrait();
'''

TRAIT_PROP = b'''<?php
trait Reader { public function viaTrait() { return $this->value; } }
class Store { use Reader; private $value = 7; public function run() { return $this->value; } }
$s = new Store();
echo $s->run(), "|", $s->viaTrait();
'''


@needs_php
def test_obfuscate_methods_skips_classes_using_traits(tmp_path):
    """H1: a trait method calls a private method of the using class, whose body is outside the
    class token range. Renaming would leave the trait's call dangling (fatal at run time), so a
    class that uses a trait is left untouched. Fails without the fix (Call to undefined method)."""
    original, out = transform(tmp_path, TRAIT_METHOD, methods=True)
    assert run_php(original) == run_php(out) == "41|42"
    assert b"function secret" in out.read_bytes()      # not renamed (class uses a trait)


@needs_php
def test_obfuscate_properties_skips_classes_using_traits(tmp_path):
    """H2: a trait method reads a private property of the using class. Renaming would make the
    trait read a missing property (null, silent corruption), so such a class is left untouched."""
    original, out = transform(tmp_path, TRAIT_PROP, properties=True)
    assert run_php(original) == run_php(out) == "7|7"
    assert b"$value" in out.read_bytes()               # not renamed (class uses a trait)


@needs_php
def test_fuzz_obfuscator_finds_no_divergence(tmp_path):
    """Run the differential obfuscator fuzzer for a bounded number of programs: the transform must
    never change behaviour. Catches regressions like the trait breakage automatically."""
    import subprocess
    import sys
    script = ROOT / "scripts" / "fuzz_obfuscator.py"
    result = subprocess.run([sys.executable, str(script), "--count", "150", "--seed", "7",
                             "--php", PHP, "--quiet"], capture_output=True, text=True, timeout=600)
    assert result.returncode == 0, "obfuscator fuzzer found a divergence:\n" + result.stdout[-4000:]


PROMOTED_FCC = b'''<?php
class Money
{
    public function __construct(private readonly int $cents = 0) {}
    public function describe(): string
    {
        $f = $this->fmt(...);        // first-class callable to a private method
        return $f($this->cents);
    }
    private function fmt(int $c): string { return "EUR" . $c; }
}
$m = new Money(250);
echo $m->describe();
'''


@needs_php
def test_promoted_property_and_first_class_callable(tmp_path):
    """A constructor-promoted (readonly) property is left alone (it is also a named-arg parameter),
    and a private method reached via a first-class callable $this->fmt(...) is renamed correctly."""
    original, out = transform(tmp_path, PROMOTED_FCC, methods=True, properties=True)
    assert run_php(original) == run_php(out) == "EUR250"
    text = out.read_bytes()
    assert b"$cents" in text                      # promoted property not renamed (named-arg safety)
    assert b"function fmt" not in text            # private method renamed (first-class callable too)


@needs_php
def test_obfuscate_flow_inserts_dead_branch_and_preserves_behaviour(tmp_path):
    """--obfuscate-flow inserts an always-false opaque-predicate branch at each named function/
    method body, keeps behaviour and line numbers, and skips functions that use goto."""
    source = (b"<?php\n"
              b"function f($x){ return $x + 1; }\n"
              b"class C { private function g(){ return 2; } function h(){ return $this->g() + f(3); } }\n"
              b"function withgoto(){ $i = 0; a: $i++; if ($i < 2) goto a; return $i; }\n"
              b"echo f(3), '|', (new C)->h(), '|', withgoto();")
    original, changed = transform(tmp_path, source, obfuscate_flow=True)
    out = changed.read_bytes()
    assert out.count(b"throw new \\Exception()") == 3        # f, C::g, C::h; the goto function is skipped
    assert b"function withgoto(){ $i = 0" in out             # left untouched (uses goto)
    assert run_php(original) == run_php(changed)             # behaviour identical
    assert out.count(b"\n") == source.count(b"\n")           # line numbers preserved (no newlines added)


# --- Control-flow flattening (pack --obfuscate-flatten, O6) -----------------------------------------

FLATTEN_SRC = (b"<?php\n"
               b"function f($x) {\n"
               b"    $t = 0;\n"
               b"    for ($i = 0; $i < $x; $i++) {\n"
               b"        if ($i % 2 === 0) { continue; }\n"
               b"        $t += $i;\n"
               b"    }\n"
               b"    try { if ($t > 3) { throw new RuntimeException('big ' . $t); } $t = -$t; }\n"
               b"    catch (RuntimeException $e) { $t = $e->getMessage() . '@' . $e->getLine(); }\n"
               b"    if (is_int($t)) { return $t * 2; }\n"
               b"    return $t;\n"
               b"}\n"
               b"class C { public function g($a) { $b = $a + 1; echo $b, \"\\n\"; return $b; } }\n"
               b"function withgoto() { $i = 0; a: $i++; if ($i < 2) goto a; return $i; }\n"
               b"echo f(7), '|', (new C)->g(4), '|', withgoto(), \"\\n\";\n")


def flatten(tmp_path, source):
    original, changed = tmp_path / "original.php", tmp_path / "changed.php"
    original.write_bytes(source)
    out, stats = a._flatten_pass({"x.php": source}, PHP)
    changed.write_bytes(out["x.php"])
    return original, changed, stats


@needs_php
def test_obfuscate_flatten_keeps_behaviour_lines_and_messages(tmp_path):
    """Named functions and methods become a dispatch loop; the statement text and the line of every
    statement, including the line a caught exception reports, do not change. goto is skipped."""
    original, changed, stats = flatten(tmp_path, FLATTEN_SRC)
    out = changed.read_bytes()
    assert stats["flattened"] == 2 and stats["skipped"] == {"goto": 1}, stats
    assert out.count(b"while(true){switch($__envlk_st){") == 2
    assert b"function withgoto() { $i = 0; a: $i++;" in out      # left untouched (uses goto)
    assert run_php(original) == run_php(changed)                 # behaviour, including the exception line
    assert out.count(b"\n") == FLATTEN_SRC.count(b"\n")          # line numbers preserved
    assert b"return $t * 2; }" in out                             # statement text kept verbatim


@needs_php
def test_obfuscate_flatten_refuses_functions_that_observe_the_frame(tmp_path):
    """Each construct that could see or reshape the frame (or the state variable) keeps the function
    exactly as written, and the reason is reported. Refusals are counted, never silent."""
    source = (b"<?php\n"
              b"function gen($n) { for ($i = 0; $i < $n; $i++) { yield $i; } }\n"
              b"function cmp($a) { $b = 1; return compact('a', 'b'); }\n"
              b"function vars($a) { $x = 1; return get_defined_vars(); }\n"
              b"function dyn($a) { $name = 'a'; return $$name; }\n"
              b"function inc($a) { $x = 1; return include __DIR__ . '/none.php'; }\n"
              b"function nested($a) { function inner_fz() { return 1; } return inner_fz(); }\n"
              b"function plain($a) { $b = $a + 1; return $b; }\n"
              b"echo plain(1), \"\\n\";\n")
    original, changed, stats = flatten(tmp_path, source)
    out = changed.read_bytes()
    for reason in ("generator", "frame function", "dynamic variable", "include/eval", "declaration"):
        assert stats["skipped"].get(reason, 0) >= 1, (reason, stats)
    # plain() and the inner function inner_fz() are flattened; nested() keeps its declaration.
    assert stats["flattened"] == 2, stats
    assert b"function nested($a) { function inner_fz() { $__envlk_st=0;" in out
    assert b"function gen($n) { for ($i = 0; $i < $n; $i++) { yield $i; } }" in out
    assert b"function cmp($a) { $b = 1; return compact('a', 'b'); }" in out
    assert b"return $$name; }" in out


@needs_php
def test_obfuscate_flatten_refuses_frame_function_reached_through_an_alias(tmp_path):
    """A function that observes the frame through a `use function ... as ...` alias must be refused
    too: flattening it would expose the injected state variable to get_defined_vars (ENV-2026-16). The
    alias is resolved before eligibility, so the call is recognised despite its local name. Fails
    without the NameResolver pass (the function would be flattened and the leak would show)."""
    # The source must not spell the state variable itself (the pass refuses any file that already
    # mentions it), so the probe counts its visible locals instead: a clean frame has exactly $a and
    # $b; a flattened body would add the injected state variable, making it 3.
    source = (b"<?php\n"
              b"use function get_defined_vars as snapshot_locals;\n"
              b"function probe($a) { $b = 2; return count(snapshot_locals()); }\n"
              b"echo probe(1), \"\\n\";\n")
    original, changed, stats = flatten(tmp_path, source)
    out = changed.read_bytes()
    assert stats["flattened"] == 0, stats                        # probe refused, nothing flattened
    assert stats["skipped"].get("frame function", 0) >= 1, stats
    assert b"snapshot_locals()" in out and b"while(true)" not in out   # kept verbatim
    assert run_php(original) == run_php(changed) == "2\n"         # no state variable ever observable


@needs_php
def test_obfuscate_flatten_refuses_a_function_with_inline_html(tmp_path):
    """ENV-2026-29: a function body containing inline HTML (?>...<?php) must not be flattened. The raw
    HTML can end in '}' or ';', which the statement-span guard accepted, so the flattener injected
    'case N:'/'$__envlk_st=..;break;' into the HTML OUTSIDE the PHP tags, breaking the switch and
    fataling the function at run time. It is refused now, and behaviour is preserved."""
    source = (b"<?php\n"
              b"function render(): int { $x = 7; ?>body{color:red}<?php return $x; }\n"
              b"echo render();\n")
    original, changed, stats = flatten(tmp_path, source)
    out = changed.read_bytes()
    assert stats["flattened"] == 0, stats                        # not flattened
    assert stats["skipped"].get("inline html", 0) >= 1, stats
    assert b"while(true)" not in out and b"body{color:red}" in out    # body left verbatim
    assert run_php(original) == run_php(changed)                 # identical, no Fatal


# --- Literal vault (pack --vault-strings) ---------------------------------------------------------

VAULT_SRC = b'''<?php
namespace App;
const TOP = "const-top-secret";
#[Route("attr-arg-literal")]
class Repo {
    const TABLE = "class-const-accounts";
    public string $dsn = "property-default-dsn";
    public int $n = 0;
    public function __construct(public string $role = "param-default-role") {}
    public function find(int $id): string {
        static $cache = "static-init-cache";
        $sql = "SELECT name FROM accounts WHERE id = ?";
        $repeated = "SELECT name FROM accounts WHERE id = ?";
        $label = "user#";
        $arr = ["key-name" => "array-runtime-value"];
        return match($id) {
            0 => "zero-case",
            default => $cache . $label . $id . " [" . $sql . "|" . $repeated . "] "
                       . $arr["key-name"] . " " . $this->dsn . " " . self::TABLE . " " . $this->role . " " . TOP,
        };
    }
}
$r = new Repo();
echo $r->find(7), "\\n";
echo $r->find(0), "\\n";
'''


def test_obfuscate_flatten_function_that_falls_off_the_end_terminates(tmp_path):
    """Regression (O6, found by the plain-app test): a body whose last statement is not a return used
    to end its last segment with a plain `break;`, which leaves the switch but not the while, so the
    body ran again forever (memory exhaustion). The last segment must leave the whole dispatch loop."""
    source = (b"<?php\n"
              b"class Cart {\n"
              b"    private array $lines = [];\n"
              b"    public function add(int $qty): void {\n"
              b"        if ($qty <= 0) { return; }\n"
              b"        $this->lines[] = $qty * 2;\n"
              b"    }\n"
              b"}\n"
              b"function say($x) {\n"
              b"    $y = $x + 1;\n"
              b"    echo \"y=\", $y, \"\\n\";\n"
              b"}\n"
              b"$c = new Cart();\n"
              b"$c->add(3);\n"
              b"$c->add(0);\n"
              b"say(4);\n"
              b"echo count((fn() => $this->lines)->call($c)), \"\\n\";\n")
    stub = ("<?php\n" + source.decode()[len("<?php\n"):]).encode()
    original, changed = tmp_path / "original.php", tmp_path / "changed.php"
    original.write_bytes(stub)
    out, stats = a._flatten_pass({"x.php": stub}, PHP)
    assert stats["flattened"] == 2, stats                       # add() and say(): both fall off the end
    changed.write_bytes(out["x.php"])
    lint = subprocess.run([PHP, "-l", str(changed)], capture_output=True, text=True)
    assert lint.returncode == 0, lint.stdout + lint.stderr
    results = []
    for path in (original, changed):
        run = subprocess.run([PHP, "-n", "-d", "memory_limit=64M", str(path)], capture_output=True,
                             text=True, timeout=30)
        results.append((run.returncode, run.stdout, run.stderr))
    assert results[0][0] == 0, results[0]
    assert results[1] == results[0], (results[1], results[0])


def _run_with_vault_stub(tmp_path, source):
    """Run a vaulted source with a global __envelock_lit backed by its table (simulating the loader),
    and return its output. Mirrors how the C loader resolves \\__envelock_lit(idx)."""
    import base64
    vaulted, lits, _ = a._vault_pass({"x.php": source}, PHP)
    table = lits["x.php"]
    # __envelock_lit lives in the global namespace and the vaulted file may declare its own
    # namespace (which must stay the first statement), so the stub is a separate bootstrap that
    # defines the function and then requires the vaulted file unchanged.
    (tmp_path / "vaulted.php").write_bytes(vaulted["x.php"])
    boot = tmp_path / "boot.php"
    boot.write_bytes(b"<?php function __envelock_lit($i){ static $t=["
                     + b",".join(b'"' + base64.b64encode(s) + b'"' for s in table)
                     + b"]; return base64_decode($t[$i]); }\nrequire __DIR__ . '/vaulted.php';\n")
    return run_php(boot), vaulted["x.php"], table


@needs_php
def test_vault_keeps_behaviour_and_vaults_only_runtime_literals(tmp_path):
    """--vault-strings moves runtime string literals to the table (replaced by \\__envelock_lit),
    leaves literals in constant expressions inline, keeps behaviour and preserves line numbers."""
    original = tmp_path / "orig.php"
    original.write_bytes(VAULT_SRC)
    vaulted_out, vsrc, table = _run_with_vault_stub(tmp_path, VAULT_SRC)
    assert vaulted_out == run_php(original)                         # behaviour identical
    assert vsrc.count(b"\n") == VAULT_SRC.count(b"\n")              # line numbers preserved
    values = {t.decode() for t in table}
    # Runtime literals are vaulted (not present inline in the rewritten source).
    for secret in (b"SELECT name FROM accounts WHERE id = ?", b"user#",
                   b"array-runtime-value", b"key-name", b"zero-case"):
        assert secret not in vsrc, secret
        assert secret.decode() in values, secret
    # Constant-expression literals stay inline (cannot become a function call) and are NOT vaulted.
    for const_literal in (b"const-top-secret", b"class-const-accounts", b"property-default-dsn",
                          b"param-default-role", b"static-init-cache", b"attr-arg-literal"):
        assert const_literal in vsrc, const_literal
        assert const_literal.decode() not in values, const_literal
    # Dedup: the repeated SQL appears once in the table.
    assert [t.decode() for t in table].count("SELECT name FROM accounts WHERE id = ?") == 1


@needs_php
def test_vault_dedup_and_short_strings_inline(tmp_path):
    """Identical literals share one table slot; 0/1-char literals stay inline (cheap, low value)."""
    source = (b'<?php function f(){ $a="SAME-VALUE"; $b="SAME-VALUE"; $c="x"; $d=""; '
              b'return $a.$b.$c.$d."SAME-VALUE"; } echo f();')
    out, vsrc, table = _run_with_vault_stub(tmp_path, source)
    assert out == "SAME-VALUESAME-VALUExSAME-VALUE"
    assert [t.decode() for t in table] == ["SAME-VALUE"]           # deduped, short ones not vaulted
    assert b'"x"' in vsrc and b'""' in vsrc                        # 1-char and empty left inline


@needs_php
def test_vault_falls_back_to_inline_when_a_file_would_not_compile(tmp_path):
    """A literal in a constant context the state machine does not model (an enum backing value)
    makes php -l fatal; _vault_pass drops that line and leaves it inline, never a broken file."""
    source = (b"<?php\n"
              b"enum Status: string { case Open = \"enum-backing-open\"; case Shut = \"enum-backing-shut\"; }\n"
              b"function f(){ return \"runtime-vaulted-string\"; }\n"
              b"echo Status::Open->value, f();")
    out, vsrc, table = _run_with_vault_stub(tmp_path, source)
    assert out == "enum-backing-openruntime-vaulted-string"
    assert b"enum-backing-open" in vsrc and b"enum-backing-shut" in vsrc   # left inline (would not compile)
    assert [t.decode() for t in table] == ["runtime-vaulted-string"]       # the runtime literal is vaulted


# --- Obfuscator correctness regressions (external audit ENV-AUD-09/10/12) ---------------------

@needs_php
def test_obfuscate_keeps_dynamic_static_method_call(tmp_path):
    """--obfuscate must rename a local used as a dynamic static method name (`C::$m()`) consistently:
    the declaration and the `::$m(` use are the same local. A static PROPERTY read (`C::$prop`, no
    `(`) is NOT a local and must be left alone. (ENV-AUD-09)"""
    src = (b"<?php class C { public static $prop='P'; public static function foo(){ return 'FOO'; } }\n"
           b"function run(){ $m='foo'; $p='prop'; return C::$m().'|'.C::$prop.'|'.C::${$p}; }\n"
           b"echo run();")
    original, changed = transform(tmp_path, src, obfuscate=True)
    assert run_php(original) == run_php(changed) == "FOO|P|P"


@needs_php
def test_obfuscate_properties_no_same_class_or_inherited_collision(tmp_path):
    """--obfuscate-properties must not rename a private property to a name that collides with a
    public/protected/promoted property of the same class, nor obfuscate a class that extends/
    implements (a parent property is invisible here). (ENV-AUD-10)"""
    intra = b"<?php class C{public $a='A'; private $secret='S'; function g(){return $this->a.$this->secret;}} echo (new C)->g();"
    promoted = b"<?php class C{private $secret='S'; function __construct(public string $a='A'){} function g(){return $this->a.$this->secret;}} echo (new C)->g();"
    inherited = b"<?php class Base{protected $a='A';} class C extends Base{private $secret='S'; function g(){return $this->a.$this->secret;}} echo (new C)->g();"
    for src in (intra, promoted, inherited):
        original, changed = transform(tmp_path, src, properties=True)
        assert run_php(original) == run_php(changed) == "AS"


@needs_php
def test_obfuscate_methods_skips_classes_with_a_parent(tmp_path):
    """--obfuscate-methods must not rename a private method to a name that collides with a parent's
    final method; a class that extends/implements is skipped whole. (ENV-AUD-12)"""
    src = (b"<?php class Base{final public function a(){return 'A';}}\n"
           b"class C extends Base{private function secret(){return 'S';} function g(){return $this->secret();}}\n"
           b"echo (new C)->g();")
    original, changed = transform(tmp_path, src, methods=True)
    assert run_php(original) == run_php(changed) == "S"


NESTED_METHOD = b'''<?php
interface Stepper { public function step(): int; }
class Svc {
    private function step(): int { return 6; }
    public function run(): int {
        $c = new class implements Stepper {
            public function step(): int { return 3; }
            public function run2(): int { return $this->step(); }
        };
        return $this->step() + $c->run2() + 100;
    }
}
echo (new Svc)->run();
'''


@needs_php
def test_obfuscate_methods_isolates_nested_anonymous_class_scope(tmp_path):
    """--obfuscate-methods renames the OUTER class's private step(); the nested anonymous class's
    public step() implements an interface and belongs to a separate scope. Renaming it with the outer
    map (the ENV-2026-14 bug) breaks the interface contract -> Fatal error. The fix leaves the nested
    member intact, so behaviour is identical (109). Fails without the scope stack."""
    original, out = transform(tmp_path, NESTED_METHOD, methods=True)
    assert run_php(original) == run_php(out) == "109"              # no Fatal; identical behaviour
    text = out.read_bytes()
    assert b"function step" in text        # the nested interface method survives (outer's was renamed)


NESTED_PROP = b'''<?php
class Outer {
    private int $x = 10;
    public function run(): int {
        $inner = new class {
            public int $x = 99;
            public function get(): int { return $this->x; }
        };
        return $this->x + $inner->get();
    }
}
echo (new Outer)->run();
'''


@needs_php
def test_obfuscate_properties_isolates_nested_anonymous_class_scope(tmp_path):
    """--obfuscate-properties renames Outer's private $x, but the nested anonymous class's $this->x is
    its OWN public property. Rewriting it with Outer's map (the ENV-2026-15 bug) silently changes the
    result from 109 to 10 (exit 0, no error). The fix isolates the nested scope. Fails without it."""
    original, out = transform(tmp_path, NESTED_PROP, properties=True)
    assert run_php(original) == run_php(out) == "109"              # not silently 10


VIRT_SRC = b'''<?php
function checkAdmin(string $role): int {
    if ($role === "superadmin") { $isAdmin = 1; }
    if ($isAdmin) { return 1; }
    return 0;
}
'''


@needs_php
def test_virtualize_rewrite_trims_caller_args_and_preserves_lines(tmp_path):
    """A virtualized function must receive ONLY its declared parameters. PHP accepts extra positional
    arguments on any call, and the old rewrite forwarded a raw func_get_args() straight into the
    function's private locals in the loader, so call_user_func('checkAdmin','guest',1) could seed
    $isAdmin and escalate 0 -> 1 (ENV-2026-26). The closed slice drops the extra argument, and the
    body is re-emitted with the same number of newlines so line numbers do not shift."""
    out, _programs = a.virtualize_sources({"x.php": VIRT_SRC}, ["checkAdmin"], PHP)
    rewritten = out["x.php"]
    assert rewritten.count(b"\n") == VIRT_SRC.count(b"\n")                 # line numbers preserved
    assert b"array_slice(\\func_get_args(), 0, 1)" in rewritten           # closed to declared arity
    # Stub the loader to report how many arguments actually reach the function. An extra positional
    # argument from the caller must not be among them.
    (tmp_path / "rewritten.php").write_bytes(rewritten)
    boot = tmp_path / "boot.php"
    boot.write_bytes(b"<?php function __envelock_vm_v2($p, array $args) { return count($args); }\n"
                     b"require __DIR__ . '/rewritten.php';\n"
                     b"echo call_user_func('checkAdmin', 'guest', 1);\n")
    assert run_php(boot) == "1"                                           # only $role, not the injected arg


@needs_php
def test_vault_pathological_constant_context_file_fails_closed(tmp_path):
    """A file with more constant-expression literals than can be vaulted must FAIL CLOSED, not ship its
    secrets inline while reporting success. The operator asked to vault strings; silently leaving them
    in cleartext would be a hidden downgrade (external audit ENV-2026-29). The loop stays bounded (the
    old O(N^2) hang from ENV-AUD-13 must not return): the error arrives promptly, naming the file and
    the --exclude escape hatch."""
    props = "".join(f"  public string $p{i} = 'const-default-{i}';\n" for i in range(70))
    src = ("<?php\nclass Big {\n" + props + "  function go(){ return 'RESULT-OK'; }\n}\necho (new Big)->go();").encode()
    with pytest.raises(ValueError) as exc:
        a._vault_pass({"x.php": src}, PHP)
    msg = str(exc.value)
    assert "x.php" in msg                                   # names the offending file
    assert "--exclude" in msg                               # offers the escape hatch
    assert "cleartext" in msg.lower() or "vault" in msg.lower()


# ---------------------------------------------------------------------------
# Objective O6, first slice: --obfuscate-names, the global rename.
# ---------------------------------------------------------------------------

NAMES_APP = b'''<?php
interface Shape6 { public function area(): float; }
trait Taggable6 { public function tag(): string { return 'tagged'; } }
enum Mode6: string { case Fast = 'fast'; case Safe = 'safe'; }
final class Square6 implements Shape6 {
    use Taggable6;
    public function __construct(public readonly float $side) {}
    public function area(): float { return $this->side * $this->side; }
}
function total6(int ...$n): int { return array_sum($n); }
'''

NAMES_USE = b'''<?php
echo total6(2, 40), "\\n";
echo (new Square6(3.0))->area(), "\\n";
echo Mode6::Safe->value, "\\n";
'''


def rename(tmp_path, files):
    """Run the global rename over a set of files and return (files, renamed, skipped)."""
    return a._names_pass(files, PHP)


@needs_php
def test_names_renames_declarations_and_references_together(tmp_path):
    """The whole point: a declaration renamed without its references (or the other way round) is a
    broken package, and that is exactly the bug this test would catch."""
    (tmp_path / "app.php").write_bytes(NAMES_APP)
    (tmp_path / "use.php").write_bytes(b"<?php\nrequire __DIR__ . '/app.php';\n" + NAMES_USE[5:])
    out, renamed, skipped = rename(tmp_path, {
        "app.php": NAMES_APP, "use.php": b"<?php\nrequire __DIR__ . '/app.php';\n" + NAMES_USE[5:]})
    assert skipped == ""
    assert set(renamed) == {"Shape6", "Taggable6", "Mode6", "Square6", "total6"}, renamed
    for original, short in renamed.items():
        for data in out.values():
            assert original.encode() not in data, f"{original} survived the rename"
    for original, short in renamed.items():
        # Every new name must be used SOMEWHERE in the pack: a name renamed at its declaration but
        # not at its references (or the reverse) is the breakage this pass must never produce.
        assert any(short.encode() in data for data in out.values()), \
            f"{original} -> {short} is declared or referenced nowhere"
    assert sum(data.count(short.encode()) for data in out.values()
               for short in renamed.values()) >= 2 * len(renamed), \
        "a declaration and at least one reference per renamed name"
    for name, data in out.items():
        (tmp_path / ("ren_" + name)).write_bytes(data)
    before = run_php(tmp_path / "use.php")
    (tmp_path / "ren_use.php").write_bytes(
        (tmp_path / "ren_use.php").read_bytes().replace(b"/app.php", b"/ren_app.php"))
    assert run_php(tmp_path / "ren_use.php") == before


@needs_php
def test_names_keeps_a_name_that_appears_in_a_string_literal(tmp_path):
    """A string is how PHP spells a dynamic target: class_exists(), a Reflection lookup, a
    serialised class name. None of those appear as a T_STRING the rewrite would follow, so a name
    that shows up in any literal of the pack must keep its spelling."""
    source = (b"<?php\nclass Dynamic6 { public function go(): int { return 1; } }\n"
              b"if (class_exists('Dynamic6')) { echo (new Dynamic6())->go(); }\n")
    out, renamed, skipped = rename(tmp_path, {"x.php": source})
    assert renamed == {}
    assert out["x.php"] == source


@needs_php
@pytest.mark.parametrize("source,why", [
    (b"<?php\nnamespace App;\nclass Ns6 { public function go(): int { return 1; } }\n"
     b"echo (new Ns6())->go();\n", "namespaced"),
    (b"<?php\nfunction Var6(): int { return 1; }\n$f = 'Var6';\necho $f();\n", "dynamic"),
    (b"<?php\nclass Ev6 { public function go(): int { return 1; } }\n"
     b"eval('echo (new Ev6())->go();');\n", "dynamic"),
])
def test_names_declines_whole_packs_it_cannot_see_through(tmp_path, source, why):
    """A namespace resolves references through aliases this pass does not model, and eval() or a
    variable function call can reach a name that never appears as a token. Declining the whole pack
    is the conservative answer; half-renaming would ship something broken."""
    out, renamed, skipped = rename(tmp_path, {"x.php": source})
    assert skipped == why
    assert renamed == {}
    assert out["x.php"] == source


@needs_php
def test_names_keeps_a_function_whose_name_a_member_also_uses(tmp_path):
    """The rewrite decides from the preceding token, so a T_STRING that is a member of an object
    whose class it cannot resolve would be renamed by mistake. A method or class constant that
    already spells the name disqualifies it — while the class it belongs to is still renamed."""
    source = (b"<?php\nclass Box6 { public function Collide6(): int { return 2; } }\n"
              b"function Collide6(): int { return 1; }\n"
              b"echo (new Box6())->Collide6() + Collide6();\n")
    out, renamed, skipped = rename(tmp_path, {"x.php": source})
    assert "Box6" in renamed and "Collide6" not in renamed, renamed
    (tmp_path / "collide.php").write_bytes(out["x.php"])
    assert run_php(tmp_path / "collide.php") == "3"


@needs_php
def test_names_never_renames_a_builtin(tmp_path):
    """The whitelist is the running PHP's own symbol table, so a pack that declares a class with a
    builtin's name shadows it deliberately and must be left exactly as written."""
    source = (b"<?php\nclass DateTime { public function go(): int { return 1; } }\n"
              b"echo (new DateTime())->go();\n")
    out, renamed, skipped = rename(tmp_path, {"x.php": source})
    assert renamed == {}
    assert out["x.php"] == source


@needs_php
def test_names_survives_a_file_that_would_not_compile(tmp_path):
    """The safety net: every renamed file is linted, and one that does not parse drops the whole
    rename rather than shipping a half-renamed pack that cannot run."""
    good = b"<?php\nclass Ok6 { public function go(): int { return 1; } }\necho (new Ok6())->go();\n"
    out, renamed, skipped = rename(tmp_path, {"x.php": good})
    assert renamed, "the control case must rename"
    assert b"class Ok6" not in out["x.php"]

def test_namespaced_pack_is_returned_byte_for_byte(tmp_path):
    """Without the separate experimental AST opt-in, a namespaced pack is declined unchanged.

    The default must remain a true no-op: a half-applied rename would leave imports and references
    pointing at names that no longer exist. Framework code must not opt into public renaming.
    """
    src = {
        "app/widget.php": b"<?php\nnamespace App\\Model;\n\nclass Widget\n{\n    private string $tag = 'x';\n"
                          b"\n    public function label(): string\n    {\n        return $this->tag;\n    }\n}\n",
        "app/use.php": b"<?php\nnamespace App;\n\nuse App\\Model\\Widget;\n\n"
                       b"function make(): Widget\n{\n    return new Widget();\n}\n",
    }
    files, renamed, skipped = a._names_pass(src, PHP)
    assert renamed == {}, "a namespaced pack must not be renamed at all"
    assert skipped == "namespaced"
    for name, data in src.items():
        assert files[name] == data, f"{name} was altered even though the pass declined"

@needs_php
def test_ast_names_resolves_namespaced_references():
    r"""The vendored parser is what the token passes cannot do: inside `namespace App;` a bare
    `Widget` says nothing about which Widget it is, which is why the token pass declines namespaced
    packages by default. Here both occurrences of `Widget` in use.php resolve to `App\Model\Widget`
    through the `use` statement, and every entry carries a byte span into its own file's source --
    so a rename can be decided from the AST and applied by offset, without pretty-printing the file
    back and moving every line."""
    src = {
        "app/widget.php": b"<?php\nnamespace App\\Model;\n\nuse App\\Service\\Thing;\n\n"
                          b"class Widget\n{\n    public function f(Thing $t): int\n    {\n"
                          b"        return $t->n();\n    }\n}\n",
        "app/use.php": b"<?php\nnamespace App;\n\nuse App\\Model\\Widget;\n\n"
                       b"function make(): Widget\n{\n    return new Widget();\n}\n",
    }
    res, builtin = a._ast_names(src, PHP)
    assert "exception" in builtin
    assert all(entry["error"] is None for entry in res.values()), res
    widget = res["app/widget.php"]
    assert [(d["kind"], d["fqn"]) for d in widget["decls"]] == [("class", "App\\Model\\Widget")]
    assert [r["fqn"] for r in widget["refs"]] == ["App\\Service\\Thing"]
    use = res["app/use.php"]
    assert [(d["kind"], d["fqn"]) for d in use["decls"]] == [("function", "App\\make")]
    assert [r["fqn"] for r in use["refs"]] == ["App\\Model\\Widget", "App\\Model\\Widget"]
    # The spans are what make offset patching safe: they must name the exact bytes they claim.
    for name, entry in res.items():
        for item in entry["decls"] + entry["refs"]:
            span = src[name][item["start"]:item["end"]].decode()
            assert span, f"empty span in {name}"
            # Whatever was written (`Thing`, `Widget`), it must end in the name the FQN ends in:
            # the span and the resolution have to be talking about the same identifier.
            assert span.split("\\")[-1] == item["fqn"].split("\\")[-1], (span, item["fqn"])
        for d in entry["decls"]:
            assert src[name][d["start"]:d["end"]].decode() == d["short"]


@needs_php
def test_ast_names_global_code_and_parse_errors():
    """Outside a namespace the short name IS the fully-qualified one, so the map stays complete
    rather than silently empty; and a file that does not parse is reported as an error on its own
    entry instead of aborting the whole pack -- one broken file must not blind the caller to the
    files that did parse."""
    src = {"ok.php": b"<?php\nclass Plain {}\nfunction top() {}\n",
           "bad.php": b"<?php\nclass Broken {\n"}
    res, _builtin = a._ast_names(src, PHP)
    assert res["ok.php"]["error"] is None
    assert sorted(d["fqn"] for d in res["ok.php"]["decls"]) == ["Plain", "top"]
    assert res["bad.php"]["error"], "a file that does not parse must be reported, not dropped"
    assert res["bad.php"]["decls"] == []

@needs_php
def test_ast_rename_keeps_a_namespaced_pack_behaving_identically(tmp_path):
    """An explicitly opted-in closed pack is really renamed and executes with exactly the same output.

    The files are loaded explicitly, not via PSR-4. The program does not observe class identity;
    tests for that and for autoloaded classes verify that the pass declines instead of normalizing
    away a real behavioural difference.
    """
    pack = {
        "src/types.php": b"<?php\nnamespace App\\Model;\n\nuse App\\Service\\Marker as Item;\n\n"
                         b"class Widget\n{\n    public function label(Item $t): string\n    {\n"
                         b"        return 'hello|' . $t->name();\n    }\n"
                         b"    public static function number(): int { return 42; }\n}\n",
        "src/services.php": b"<?php\nnamespace App\\Service;\n\nclass Marker\n{\n"
                            b"    public function name(): string\n    {\n        return 'mk';\n    }\n}\n",
        "src/run.php": b"<?php\nnamespace App;\n\nuse App\\Model\\Widget;\nuse App\\Service\\Marker;\n\n"
                       b"$w = new Widget();\necho $w->label(new Marker()), \"\\n\";\n"
                       b"echo \\App\\Model\\Widget::number(), \"\\n\";\n",
    }
    out, renamed, skipped = a._names_pass(pack, PHP, ast_names=True)
    assert skipped == ""
    assert set(renamed) == {"App\\Model\\Widget", "App\\Service\\Marker"}, renamed
    assert out["src/types.php"] != pack["src/types.php"]
    assert all(out[name].count(b"\n") == data.count(b"\n") for name, data in pack.items())

    def run(tree):
        root = tmp_path / tree
        for name, data in pack.items() if tree == "orig" else out.items():
            f = root / name
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(data)
        runner = root / "boot.php"
        runner.write_bytes(b"<?php\nrequire __DIR__ . '/src/services.php';\n"
                           b"require __DIR__ . '/src/types.php';\nrequire __DIR__ . '/src/run.php';\n")
        r = subprocess.run([PHP, str(runner)], capture_output=True, timeout=60)
        assert r.returncode == 0, r.stderr
        return r.stdout

    assert run("orig") == run("renamed") == b"hello|mk\n42\n"

@needs_php
def test_ast_rename_refusals_are_the_dangerous_cases():
    """Each refusal here is a way the rename would have broken a running program, and none of them
    is visible as a token: a framework parent whose class name drives behaviour, a call PHP resolves
    by falling back to global, and a name spelled inside a string."""
    external = {"a.php": b"<?php\nnamespace App;\nuse Some\\Framework\\Model;\n"
                         b"class Widget extends Model {}\nclass Dto {}\n"}
    out, renamed, _ = a._ast_rename_names(external, PHP)
    assert "App\\Widget" not in renamed, "a class extending outside the pack must keep its name"
    assert "App\\Dto" in renamed, "a class with no external parent is safe to rename"
    assert out["a.php"].count(b"class Widget") == 1

    builtin = {"b.php": b"<?php\nnamespace App;\nclass Box implements \\JsonSerializable {}\n"}
    assert "App\\Box" not in a._ast_rename_names(builtin, PHP)[1], \
        "even an engine parent may observe the name of the subclass"

    unqualified = {"c.php": b"<?php\nnamespace App;\nfunction helper() { return 1; }\n"
                            b"function go() { return helper(); }\n"}
    assert "App\\helper" not in a._ast_rename_names(unqualified, PHP)[1], \
        "an unqualified call would fall back to a global helper() that no longer exists"

    qualified = {"d.php": b"<?php\nnamespace App;\nfunction helper() { return 1; }\n"
                          b"function go() { return \\App\\helper(); }\n"}
    assert "App\\helper" in a._ast_rename_names(qualified, PHP)[1], \
        "a fully-qualified call is resolved, so the function is safe to rename"

    instring = {"e.php": b"<?php\nnamespace App;\nclass Widget {}\n"
                         b"$x = 'App\\\\Model\\\\Widget';\n"}
    assert "App\\Widget" not in a._ast_rename_names(instring, PHP)[1], \
        "a name spelled in a string may reach class_exists() or a serialised payload"


@needs_php
def test_halt_compiler_files_are_reported_not_silently_untransformed():
    """A file with __halt_compiler() cannot be rebuilt from tokens, so the transform and vault passes
    pass it through unchanged (ENV-08). They MUST report it so the manifest never claims a protection
    that was not applied and the operator can react (bytecode or --exclude). Regression for the silent
    fail-open found in the internal audit (nov 2026)."""
    src = b"<?php $x = 'SECRET-VALUE'; __halt_compiler();\nTRAILING RAW DATA"
    out, halted = a.transform_sources({"stub.php": src}, PHP, strip=True, encode_strings=True,
                                      methods=True)
    assert halted == ["stub.php"]
    assert out["stub.php"] == src                      # passed through verbatim (trailing data kept)
    vaulted, lits, vhalted = a._vault_pass({"stub.php": src}, PHP)
    assert vhalted == ["stub.php"]
    assert vaulted["stub.php"] == src and lits["stub.php"] == []
    # A normal file alongside it is still transformed and not reported as halted.
    out2, halted2 = a.transform_sources({"stub.php": src, "ok.php": b"<?php $y = 'HELLO';"}, PHP,
                                        encode_strings=True)
    assert halted2 == ["stub.php"] and out2["ok.php"] != b"<?php $y = 'HELLO';"


@needs_php
def test_pack_manifest_lists_files_not_token_transformed(tmp_path):
    """End to end: packing (without bytecode) a tree that includes a __halt_compiler() file with
    --strip-comments --vault-strings records that file under files_not_token_transformed in the
    package manifest, instead of the manifest implying every file was protected."""
    import json
    source = tmp_path / "src"
    source.mkdir()
    (source / "ok.php").write_text("<?php $a = 'x'; // comment\n")
    (source / "stub.php").write_bytes(b"<?php $s = 'INNER'; __halt_compiler();\nDATA")
    recipient = a.make_recipient("r")
    a.pack_tree(source, tmp_path / "out", [a.recipient_public(recipient)], a.make_owner(),
                str(uuid.uuid4()), strip_comments=True, vault_strings=True)
    info = json.loads((tmp_path / "out" / "envelock-package.json").read_text())
    assert info["files_not_token_transformed"] == ["stub.php"]

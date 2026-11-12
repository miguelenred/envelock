"""Runtime regressions for the experimental, closed-world AST name pass.

Compare actual PHP executions, not merely syntactically valid output or normalized class names.
"""

import base64
import subprocess
import sys
import uuid

import pytest
from test_encoder import ROOT, a
from test_transform import PHP, needs_php


def run_tree(root, files, entry="main.php"):
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    result = subprocess.run([PHP, "-n", str(root / entry)], capture_output=True, timeout=30)
    return result.returncode, result.stdout, result.stderr


def compare_tree(tmp_path, files, entry="main.php"):
    before = run_tree(tmp_path / "before", files, entry)
    out, mapping, reason = a._ast_rename_names(files, PHP)
    after = run_tree(tmp_path / "after", out, entry)
    assert before[0] == 0, before
    assert after[0] == 0, (mapping, reason, after)
    assert after[1] == before[1], (mapping, reason, before, after)
    return out, mapping, reason


@needs_php
@pytest.mark.parametrize("source,expected_name", [
    (b"<?php namespace Pkg\\Model { class Widget { static function go(){ return 42; } } } "
     b"namespace Client { use Pkg\\Model\\Widget as Widget; echo Widget::go(); }", "Pkg\\Model\\Widget"),
    (b"<?php namespace App; class Widget { function go(){ return 42; } } "
     b"echo (new wIDgET)->go();", "App\\Widget"),
    (b"<?php namespace App; class Widget {} const Widget=42; echo \\App\\Widget;", "App\\Widget"),
    (b"<?php namespace App; function helper(){ return 42; } echo \\app\\HELPER();", "App\\helper"),
    (b"<?php namespace Pkg { function helper(){ return 42; } } "
     b"namespace Client { use function Pkg\\helper as helper; echo helper(); }", "Pkg\\helper"),
    (b"<?php namespace Pkg\\Model { class Widget { static function go(){ return 42; } } } "
     b"namespace Client { use Pkg\\Model\\{Widget as Widget}; echo Widget::go(); }", "Pkg\\Model\\Widget"),
    (b"<?php namespace Pkg { class Widget {} const Widget=42; } "
     b"namespace Client { use const Pkg\\Widget; echo Widget; }", "Pkg\\Widget"),
])
def test_resolved_names_preserve_runtime_semantics(tmp_path, source, expected_name):
    """Aliases, PHP's case-insensitivity and the separate type/function/constant namespaces matter."""
    _, mapping, _ = compare_tree(tmp_path, {"main.php": source})
    assert expected_name in mapping, "the test must exercise a real rename, not just a no-op"


@needs_php
def test_two_namespaces_with_same_short_name_are_distinct(tmp_path):
    source = (b"<?php namespace Left { class Widget { static function go(){return 2;} } } "
              b"namespace Right { class Widget { static function go(){return 3;} } } "
              b"namespace Run { use Left\\Widget as First; use Right\\Widget as Second; "
              b"echo First::go() + Second::go(); }")
    _, mapping, _ = compare_tree(tmp_path, {"main.php": source})
    assert set(mapping) == {"Left\\Widget", "Right\\Widget"}
    assert len(set(mapping.values())) == 2


@needs_php
@pytest.mark.parametrize("source", [
    b"<?php namespace App; class Widget {} echo Widget::class;",
    b"<?php namespace App; class Widget { static function go(){return self::class;} } echo Widget::go();",
    b"<?php namespace App; class Widget { static function go(){return __CLASS__;} } echo Widget::go();",
    b"<?php namespace App; class Widget { static function go(){return __METHOD__;} } echo Widget::go();",
    b"<?php namespace App; class Widget {} var_dump(new Widget);",
    b"<?php namespace App; class Widget {} echo get_class(new Widget);",
    b"<?php namespace App; class Widget {} echo serialize(new Widget);",
    (b"<?php namespace App; class Widget { function go(){return 42;} } "
     b"$n='App\\\\' . 'Wid' . 'get'; echo (new $n)->go();"),
])
def test_observable_class_identity_is_not_changed(tmp_path, source):
    """Unlike a normalized comparison, this catches names leaking into output and serialization."""
    _, mapping, _ = compare_tree(tmp_path, {"main.php": source})
    assert "App\\Widget" not in mapping


@needs_php
def test_psr4_autoloader_is_not_broken(tmp_path):
    pack = {
        "src/Widget.php": b"<?php namespace App; class Widget { function go(){ return 42; } }",
        "main.php": (b"<?php namespace App; spl_autoload_register(function($n){ "
                     b"require __DIR__ . '/src/' . substr(strrchr($n, '\\\\'), 1) . '.php'; }); "
                     b"echo (new Widget)->go();"),
    }
    _, mapping, _ = compare_tree(tmp_path, pack)
    assert "App\\Widget" not in mapping


@needs_php
def test_psr4_filename_is_not_renamed_even_if_autoloader_is_outside_pack(tmp_path):
    """An autoloader may be installed outside the package, where the AST cannot see it."""
    pack = {
        "src/Widget.php": b"<?php namespace App; class Widget { static function go(){return 42;} }",
        "main.php": (b"<?php namespace App; foreach (glob(__DIR__ . '/src/*.php') as $f) "
                     b"require $f; echo Widget::go();"),
    }
    _, mapping, _ = compare_tree(tmp_path, pack)
    assert "App\\Widget" not in mapping


@needs_php
def test_inheriting_external_parent_is_transitive():
    pack = {"app.php": b"<?php namespace App; class Base extends \\External\\Model {} "
                       b"class Widget extends Base {} class Dto {}"}
    _, mapping, _ = a._ast_rename_names(pack, PHP)
    assert "App\\Base" not in mapping and "App\\Widget" not in mapping
    assert "App\\Dto" in mapping


@needs_php
def test_builtin_parent_can_also_observe_the_subclass_name(tmp_path):
    source = (b"<?php namespace App; class Problem extends \\Exception {} "
              b"echo explode(':', (string) new Problem('oops'))[0];")
    _, mapping, _ = compare_tree(tmp_path, {"main.php": source})
    assert "App\\Problem" not in mapping


@needs_php
def test_binary_php_strings_do_not_corrupt_ast_protocol(tmp_path):
    source = (b'<?php namespace App; class Widget { static function go(){return 7;} } '
              b'echo bin2hex("\xff"), "|", Widget::go();')
    _, mapping, _ = compare_tree(tmp_path, {"main.php": source})
    assert "App\\Widget" in mapping


@needs_php
def test_names_lint_refusal_is_atomic(monkeypatch):
    """A bad later file must roll back the already-transformed earlier files too."""
    original = {"first.php": b"<?php class First {}", "last.php": b"<?php class Last {}"}
    candidate = {"first.php": b"<?php class efirst {}", "last.php": b"<?php BAD;"}
    result = {"files": {n: base64.b64encode(d).decode() for n, d in candidate.items()},
              "renamed": {"First": "efirst", "Last": "elast"}}
    monkeypatch.setattr(a, "_run_php", lambda *args, **kwargs: result)
    monkeypatch.setattr(a, "_php_lint_error_line", lambda php, data: 1 if b"BAD" in data else None)
    out, mapping, reason = a._names_pass(original, PHP)
    assert (out, mapping, reason) == (original, {}, "lint")


@needs_php
def test_pack_checks_name_literals_before_vaulting_them(tmp_path):
    """The vault must not hide class names from the subsequent global-name safety analysis."""
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.php").write_bytes(
        b"<?php class Widget {} echo class_exists('Widget') ? 'YES' : 'NO';")
    owner, recipient = a.make_owner(), a.make_recipient("names-vault-test")
    info = a.pack_tree(source, tmp_path / "out", [a.recipient_public(recipient)], owner,
                       str(uuid.uuid4()), php=PHP, obfuscate_names=True, vault_strings=True)
    assert info["names_obfuscated"] == [], info


@needs_php
def test_namespaced_ast_requires_explicit_opt_in():
    pack = {"types.php": b"<?php namespace App; class Widget { static function go(){return 42;} } "
                         b"echo Widget::go();"}
    out, mapping, reason = a._names_pass(pack, PHP)
    assert (out, mapping, reason) == (pack, {}, "namespaced")
    out, mapping, reason = a._names_pass(pack, PHP, ast_names=True)
    assert "App\\Widget" in mapping and not reason
    assert out != pack


@needs_php
def test_pack_ast_opt_in_works_and_is_not_default(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    files = {
        "types.php": b"<?php namespace App; class Widget { static function go(){return 42;} }",
        "main.php": b"<?php namespace App; require __DIR__ . '/types.php'; echo Widget::go();",
    }
    for name, data in files.items():
        (source / name).write_bytes(data)
    owner, recipient = a.make_owner(), a.make_recipient("closed-ast-test")
    identity = a.make_identity(recipient, owner)
    kwargs = {"php": PHP, "obfuscate_names": True}
    plain = a.pack_tree(source, tmp_path / "legacy", [a.recipient_public(recipient)], owner,
                        str(uuid.uuid4()), **kwargs)
    assert plain["names_obfuscated"] == [] and plain["names_skipped"] == "namespaced"
    protected = a.pack_tree(source, tmp_path / "ast", [a.recipient_public(recipient)], owner,
                            str(uuid.uuid4()), obfuscate_names_ast=True, **kwargs)
    assert protected["names_obfuscated"] and not protected["names_skipped"]
    decoded = {name: a.open_protected((tmp_path / "ast" / name).read_bytes(), identity)
               for name in files}
    assert run_tree(tmp_path / "orig-exec", files)[:2] == run_tree(tmp_path / "ast-exec", decoded)[:2]


@needs_php
def test_pack_rejects_ast_modifier_without_public_name_opt_in(tmp_path):
    owner, recipient = a.make_owner(), a.make_recipient("modifier-test")
    with pytest.raises(ValueError, match="requires --obfuscate-names"):
        a.pack_tree(tmp_path, tmp_path / "out", [a.recipient_public(recipient)], owner,
                    str(uuid.uuid4()), php=PHP, obfuscate_names_ast=True)


@needs_php
@pytest.mark.parametrize("source,expected", [
    (b"<?php namespace Lib { interface Contract {} "
     b"class Widget implements Contract { function go(){ return 42; } } } "
     b"namespace Run { use Lib\\{Widget as Item, Contract as Result}; "
     b"function wrap(?Item $x): Result { return $x; } echo wrap(new Item)->go(); }",
     {"Lib\\Contract", "Lib\\Widget"}),
    (b"<?php namespace Lib { trait Marker { function go(){ return 42; } } "
     b"class Widget { use Marker; } } namespace Run { use Lib\\Widget as Item; echo (new Item)->go(); }",
     {"Lib\\Marker", "Lib\\Widget"}),
    (b"<?php namespace Lib { enum Status { case Ready; } } "
     b"namespace Run { use Lib\\Status; echo Status::Ready->name; }", {"Lib\\Status"}),
    (b"<?php namespace Lib { class Widget { static function go(){return 40;} } } "
     b"namespace Lib\\Widget { class Other { static function go(){return 2;} } } "
     b"namespace Run { use Lib\\Widget; echo Widget::go() + Widget\\Other::go(); }",
     {"Lib\\Widget", "Lib\\Widget\\Other"}),
    (b"<?php namespace App; class Widget { static function go(){return 42;} } "
     b"echo namespace\\Widget::go();", {"App\\Widget"}),
])
def test_ast_type_contexts_and_namespace_prefixes(tmp_path, source, expected):
    _, mapping, _ = compare_tree(tmp_path, {"main.php": source})
    assert expected <= set(mapping), mapping


@needs_php
def test_external_trait_and_its_descendant_keep_names():
    pack = {"main.php": b"<?php namespace App; class Base { use \\External\\FrameworkTrait; } "
                        b"class Widget extends Base {} class Dto {}"}
    _, mapping, _ = a._ast_rename_names(pack, PHP)
    assert "App\\Base" not in mapping and "App\\Widget" not in mapping
    assert "App\\Dto" in mapping


@needs_php
def test_attributes_cause_a_safe_decline():
    pack = {"main.php": b"<?php namespace App; #[\\Attribute] class Widget {} echo 42;"}
    out, mapping, reason = a._ast_rename_names(pack, PHP)
    assert (out, mapping, reason) == (pack, {}, "dynamic")


@needs_php
def test_invalid_utf8_identifier_declines_instead_of_corrupting_json():
    pack = {"main.php": b"<?php namespace App; class \xe9clair {}"}
    out, mapping, reason = a._ast_rename_names(pack, PHP)
    assert (out, mapping, reason) == (pack, {}, "ast-unparsable")


@needs_php
def test_generated_name_avoids_existing_reference_and_import_alias(monkeypatch):
    """Force the normally unlikely random collisions, then verify a different short name is used."""
    pack = {"main.php": b"<?php namespace App; use External\\Thing as eaaaaa; "
                        b"class Widget {} function go(\\External\\ebbbbb $x) {}"}
    choices = iter("aaaaa" + "bbbbb" + "ccccc")
    monkeypatch.setattr(a.secrets, "choice", lambda _pool: next(choices))
    _, mapping, reason = a._ast_rename_names(pack, PHP)
    assert reason == ""
    assert mapping == {"App\\Widget": "eccccc"}


@needs_php
def test_same_fqn_declared_in_separate_symbol_tables_declines():
    pack = {"main.php": b"<?php namespace App; class Widget {} function Widget() {return 42;} "
                        b"echo Widget();"}
    out, mapping, reason = a._ast_rename_names(pack, PHP)
    assert (out, mapping, reason) == (pack, {}, "duplicate-name")


@needs_php
@pytest.mark.parametrize("source", [
    b"<?php class Widget {} echo Widget::class;",
    b"<?php class Widget { static function label(){return __CLASS__;} } echo Widget::label();",
    b"<?php class Widget { static function go(){return 42;} } echo \\Widget::go();",
    b"<?php function helper(){return 42;} echo \\helper();",
    b"<?php class Widget {} const Widget=42; echo Widget;",
    (b"<?php class Widget { function go(){return 42;} } "
     b"$name='Wid' . 'get'; echo (new $name)->go();"),
    b"<?php class Widget {} echo get_class(new Widget);",
    b"<?php class Widget {} echo serialize(new Widget);",
])
def test_legacy_global_pass_never_partially_breaks_unsafe_code(tmp_path, source):
    pack = {"main.php": source}
    before = run_tree(tmp_path / "before", pack)
    out, mapping, reason = a._names_pass(pack, PHP)
    after = run_tree(tmp_path / "after", out)
    assert before[0] == after[0] == 0, (mapping, reason, before, after)
    assert before[1] == after[1], (mapping, reason, before, after)


@needs_php
@pytest.mark.parametrize("namespace,ast", [(b"", False), (b"namespace App; ", True)])
def test_callback_consumers_with_assembled_class_name_decline(tmp_path, namespace, ast):
    prefix = b"'App\\\\' . " if namespace else b""
    source = (b"<?php " + namespace + b"class Widget { static function go($n){return $n+1;} } "
              b"$callback=[" + prefix + b"'Wid' . 'get', 'go']; echo array_map($callback, [41])[0];")
    files = {"main.php": source}
    before = run_tree(tmp_path / "before", files)
    out, mapping, reason = a._names_pass(files, PHP, ast_names=ast)
    after = run_tree(tmp_path / "after", out)
    assert before[0] == after[0] == 0, (mapping, reason, before, after)
    assert before[1] == after[1] == b"42", (mapping, reason, before, after)


@needs_php
def test_legacy_global_reflection_cannot_observe_changed_name(tmp_path):
    source = b"<?php class Widget {} $r=new ReflectionObject(new Widget); echo $r->getName();"
    files = {"main.php": source}
    before = run_tree(tmp_path / "before", files)
    out, mapping, reason = a._names_pass(files, PHP)
    after = run_tree(tmp_path / "after", out)
    assert before[0] == after[0] == 0, (mapping, reason, before, after)
    assert before[1] == after[1] == b"Widget", (mapping, reason, before, after)


@needs_php
def test_legacy_global_named_argument_is_not_renamed_as_a_class(tmp_path):
    source = (b"<?php class Widget {} function capture($Widget){return $Widget;} "
              b"echo capture(Widget:42);")
    pack = {"main.php": source}
    before = run_tree(tmp_path / "before", pack)
    out, mapping, reason = a._names_pass(pack, PHP)
    after = run_tree(tmp_path / "after", out)
    assert before[0] == after[0] == 0, (mapping, reason, before, after)
    assert before[1] == after[1] == b"42"
    assert "Widget" in mapping, "a safe named-argument token should not disqualify the class"


@needs_php
def test_legacy_global_external_static_member_is_not_a_class_reference(tmp_path):
    main = (b"<?php require __DIR__ . '/external.php'; class Widget {} "
            b"echo External::Widget();")
    external = b"<?php class External { static function Widget(){return 42;} }"
    before = run_tree(tmp_path / "before", {"main.php": main, "external.php": external})
    out, mapping, reason = a._names_pass({"main.php": main}, PHP)
    after = run_tree(tmp_path / "after", {**out, "external.php": external})
    assert before[0] == after[0] == 0, (mapping, reason, before, after)
    assert before[1] == after[1] == b"42"
    assert "Widget" in mapping


@needs_php
def test_legacy_global_external_parent_cannot_change_child_identity(tmp_path):
    main = (b"<?php require __DIR__ . '/external.php'; class Middle extends Foreign {} "
            b"class Widget extends Middle {} echo (new Widget)->label();")
    external = b"<?php class Foreign { function label(){ return get_class($this); } }"
    before = run_tree(tmp_path / "before", {"main.php": main, "external.php": external})
    out, mapping, reason = a._names_pass({"main.php": main}, PHP)
    after = run_tree(tmp_path / "after", {**out, "external.php": external})
    assert before[0] == after[0] == 0, (mapping, reason, before, after)
    assert before[1] == after[1] == b"Widget"
    assert mapping == {} and reason == "dynamic"


@needs_php
def test_legacy_global_goto_label_is_not_renamed(tmp_path):
    source = b"<?php class Widget { static function go(){return 42;} } goto Widget; echo 0; Widget: echo Widget::go();"
    pack = {"main.php": source}
    before = run_tree(tmp_path / "before", pack)
    out, mapping, reason = a._names_pass(pack, PHP)
    after = run_tree(tmp_path / "after", out)
    assert before[0] == after[0] == 0, (mapping, reason, before, after)
    assert before[1] == after[1] == b"42"
    assert "Widget" in mapping


@needs_php
@pytest.mark.parametrize("allowlist", [False, True], ids=["all-eligible", "strict-allowlist"])
def test_multifile_fuzzer_smoke(allowlist):
    command = [sys.executable, str(ROOT / "scripts" / "fuzz_ast_names.py"), "--count", "8", "--seed", "73"]
    if allowlist:
        command.append("--allowlist")
    # 8 packages, each run through PHP several times: ~1 minute on a fast machine, several on a
    # small shared VM. The work (and so the coverage) is unchanged; only the wall-clock cap is lifted.
    result = subprocess.run(command, capture_output=True, text=True, timeout=600)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "8 multi-file packages" in result.stdout and "0 divergences" in result.stdout
    assert ("strict allowlist" in result.stdout) is allowlist


@needs_php
@pytest.mark.parametrize("allowlist", [False, True], ids=["default-vs-ast", "ast-vs-allowlist"])
def test_ast_benchmark_exercises_both_arms(allowlist):
    command = [sys.executable, str(ROOT / "scripts" / "bench_ast_names.py"), "--samples", "2", "--iterations", "1000"]
    if allowlist:
        command.append("--allowlist")
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "identical result=" in result.stdout
    assert "name-pass wall time" in result.stdout and "PHP loop time" in result.stdout
    assert ("allowlist=" in result.stdout) is allowlist


@needs_php
@pytest.mark.parametrize("namespaced", [False, True], ids=["legacy-global", "experimental-ast"])
@pytest.mark.parametrize("source", [
    b"class Widget { const VALUE=42; } $n=__WIDGET__; echo constant($n . '::VALUE');",
    b"class Widget { const VALUE=42; } $n=__WIDGET__; echo defined($n . '::VALUE') ? 'yes' : 'no';",
    b"function helper() {} $n=__HELPER__; echo function_exists($n) ? 'yes' : 'no';",
    b"class Widget { static function go(){} } $n=__WIDGET__; echo method_exists($n, 'go') ? 'yes' : 'no';",
    b"class Widget { public $value=1; } $n=__WIDGET__; echo property_exists($n, 'value') ? 'yes' : 'no';",
    b"class Widget { static function go(){} } $n=__WIDGET__; echo is_callable([$n, 'go']) ? 'yes' : 'no';",
    b"class Widget { static function go(){} } $n=__WIDGET__; \\Closure::fromCallable([$n, 'go']); echo 'yes';",
    b"class Widget {} $n=__WIDGET__; $c=\\Closure::bind(function(){}, null, $n); echo $c ? 'yes' : 'no';",
    b"class Widget {} $n=__WIDGET__; $c=function(){}; $bound=$c->bindTo(null, $n); echo $bound ? 'yes' : 'no';",
], ids=["constant", "defined", "function-exists", "method-exists", "property-exists", "is-callable",
        "closure-from-callable", "closure-bind", "closure-bind-to"])
def test_assembled_names_in_dynamic_observers_are_not_renamed(tmp_path, namespaced, source):
    """Observers can reconstruct names without any literal containing the target identifier."""
    prefix = b"namespace App; " if namespaced else b""
    widget = b"'App\\\\' . 'Wid' . 'get'" if namespaced else b"'Wid' . 'get'"
    helper = b"'App\\\\' . 'hel' . 'per'" if namespaced else b"'hel' . 'per'"
    program = b"<?php " + prefix + source.replace(b"__WIDGET__", widget).replace(b"__HELPER__", helper)
    files = {"main.php": program}
    before = run_tree(tmp_path / "before", files)
    assert before[0] == 0, before
    transformed, mapping, reason = a._names_pass(files, PHP, ast_names=namespaced)
    after = run_tree(tmp_path / "after", transformed)
    assert after[:2] == before[:2], (mapping, reason, before, after)
    assert (transformed, mapping, reason) == (files, {}, "dynamic")


@needs_php
@pytest.mark.parametrize("source", [
    b"<?php namespace App; use function \\function_exists as probe; function helper(){} "
    b"$n='App\\\\'.'hel'.'per'; echo probe($n) ? 'yes':'no';",
    b"<?php namespace App; use \\Closure as Factory; class Widget {static function go(){}} "
    b"$n='App\\\\'.'Wid'.'get'; Factory::fromCallable([$n,'go']); echo 'yes';",
], ids=["function-import-alias", "closure-class-import-alias"])
def test_aliased_dynamic_observers_decline_globally(tmp_path, source):
    files = {"main.php": source}
    before = run_tree(tmp_path / "before", files)
    assert before[0] == 0, before
    transformed, mapping, reason = a._names_pass(files, PHP, ast_names=True)
    after = run_tree(tmp_path / "after", transformed)
    assert after[:2] == before[:2], (mapping, reason, before, after)
    assert (transformed, mapping, reason) == (files, {}, "dynamic")


@needs_php
@pytest.mark.parametrize("source", [
    b"<?php namespace App; class Widget {static function go(){}} $n='App\\\\'.'Wid'.'get'; "
    b"$m='from'.'Callable'; \\Closure::$m([$n,'go']); echo 'yes';",
    b"<?php namespace App; class Widget {} $n='App\\\\'.'Wid'.'get'; $c=function(){}; "
    b"$b=$c->{'bind'.'To'}(null, $n); echo $b ? 'yes' : 'no';",
    b"<?php namespace App; class Widget {} $n='App\\\\'.'Wid'.'get'; $c=function(){}; "
    b"$m='bind'.'To'; $b=$c?->$m(null, $n); echo $b ? 'yes' : 'no';",
], ids=["dynamic-static-method", "dynamic-instance-method", "dynamic-nullsafe-method"])
def test_assembled_member_name_declines_ast_rename(tmp_path, source):
    files = {"main.php": source}
    before = run_tree(tmp_path / "before", files)
    assert before[0] == 0, before
    transformed, mapping, reason = a._names_pass(files, PHP, ast_names=True)
    after = run_tree(tmp_path / "after", transformed)
    assert after[:2] == before[:2], (mapping, reason, before, after)
    assert (transformed, mapping, reason) == (files, {}, "dynamic")


@needs_php
def test_dynamic_name_observer_fuzzer_smoke():
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "fuzz_name_observers.py"),
                             "--count", "12", "--seed", "113"],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "12 observer programs" in result.stdout and "12 strict refusals" in result.stdout
    assert "0 divergences" in result.stdout


@needs_php
@pytest.mark.parametrize("namespaced", [False, True], ids=["legacy-global", "experimental-ast"])
@pytest.mark.parametrize("observer", ["trace-array", "trace-string", "exception-to-string", "message"])
def test_exceptions_do_not_observe_renamed_symbols(tmp_path, namespaced, observer):
    ns = b"namespace App; " if namespaced else b""
    exception = b"\\Exception" if namespaced else b"Exception"
    throwable = b"\\Throwable" if namespaced else b"Throwable"
    type_error = b"\\TypeError" if namespaced else b"TypeError"
    std_class = b"\\stdClass" if namespaced else b"stdClass"
    invoke = b"\\App\\invoke" if namespaced else b"invoke"
    helper = b"\\App\\helper" if namespaced else b"helper"
    if observer == "message":
        source = (b"class Widget {} function invoke(Widget $x){} try { " + invoke + b"(new " + std_class
                  + b"); } catch(" + type_error + b" $e){ echo preg_replace('~ in .*~','',$e->getMessage()); }")
    else:
        source = b"function helper(){throw new " + exception + b"('x');} try { " + helper + b"(); } catch(" \
                 + throwable + b" $e){ "
        if observer == "trace-array":
            source += b"echo $e->getTrace()[0]['function'];"
        elif observer == "trace-string":
            source += b"echo explode('(',explode(': ',$e->getTraceAsString())[1])[0];"
        else:
            source += b"$s=(string)$e; preg_match('/#0.*: ([^(]+)/',$s,$m); echo $m[1];"
        source += b" }"
    files = {"main.php": b"<?php " + ns + source}
    before = run_tree(tmp_path / "before", files)
    assert before[0] == 0 and before[1], before
    transformed, mapping, reason = a._names_pass(files, PHP, ast_names=namespaced)
    after = run_tree(tmp_path / "after", transformed)
    assert after[:2] == before[:2], (mapping, reason, before, after)
    assert (transformed, mapping, reason) == (files, {}, "dynamic")


@needs_php
@pytest.mark.parametrize("namespaced", [False, True], ids=["legacy-global", "experimental-ast"])
@pytest.mark.parametrize("method", ["getTrace", "getTraceAsString", "getMessage", "getPrevious", "__toString"])
def test_unknown_throwable_observer_declines_without_local_catch(namespaced, method):
    ns = b"namespace App; " if namespaced else b""
    program = (b"<?php " + ns + b"function helper(){return 1;} "
               + f"function inspect($e){{return $e->{method}();}} ".encode() + b"echo 42;")
    files = {"main.php": program}
    transformed, mapping, reason = a._names_pass(files, PHP, ast_names=namespaced)
    assert (transformed, mapping, reason) == (files, {}, "dynamic")


@needs_php
@pytest.mark.parametrize("namespaced", [False, True], ids=["legacy-global", "experimental-ast"])
@pytest.mark.parametrize("code", [
    b"function helper(){return 1;} if(false) throw new Exception('never'); echo 42;",
    b"function helper(){return 1;} try {echo 42;} finally {$x=1;}",
], ids=["throw-expression", "try-finally"])
def test_exception_constructs_decline_names_even_without_visible_observer(namespaced, code):
    files = {"main.php": b"<?php " + (b"namespace App; " if namespaced else b"") + code}
    transformed, mapping, reason = a._names_pass(files, PHP, ast_names=namespaced)
    assert (transformed, mapping, reason) == (files, {}, "dynamic")


@needs_php
@pytest.mark.parametrize("body", [
    b"iterator_apply(new ArrayIterator([1]), 'hel'.'per');",
    b"array_udiff([1], [2], 'hel'.'per');",
    b"array_uintersect([1], [2], 'hel'.'per');",
    b"array_diff_ukey([1], [2], 'hel'.'per');",
    b"$f=new CallbackFilterIterator(new ArrayIterator([1]), 'hel'.'per'); foreach($f as $v){}",
    b"$f=new Fiber('hel'.'per'); $f->start();",
], ids=["iterator-apply", "array-udiff", "array-uintersect", "array-diff-ukey", "callback-filter", "fiber"])
@pytest.mark.parametrize("ast", [False, True], ids=["tokens", "ast"])
def test_extra_callback_consumers_block_renaming(tmp_path, body, ast):
    files = {"main.php": b"<?php function helper(...$args){return 1;} " + body + b" echo 'OK';"}
    before = run_tree(tmp_path / "before", files)
    assert before[0] == 0 and before[1] == b"OK", before
    transformed, mapping, reason = a._names_pass(files, PHP, ast_names=ast)
    after = run_tree(tmp_path / "after", transformed)
    assert after[:2] == before[:2], (mapping, reason, before, after)
    assert (transformed, mapping, reason) == (files, {}, "dynamic")
    if ast:
        with pytest.raises(ValueError, match="name allowlist refused.*dynamic"):
            a._names_pass(files, PHP, ast_names=True, allowlist=["function:helper"])


@needs_php
def test_aliased_callback_constructor_blocks_ast_renaming(tmp_path):
    source = (b"<?php namespace App; use \\Fiber as Runner; function helper(){return 8;} "
              b"$f=new Runner('App\\\\'.'hel'.'per'); $f->start(); echo $f->getReturn();")
    files = {"main.php": source}
    before = run_tree(tmp_path / "before", files)
    assert before[0] == 0 and before[1] == b"8", before
    transformed, mapping, reason = a._names_pass(files, PHP, ast_names=True)
    assert (transformed, mapping, reason) == (files, {}, "dynamic")

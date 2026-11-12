"""A fail-closed, explicit symbol allowlist for the experimental AST name pass."""

import json
import subprocess
import sys
import uuid

import pytest
from test_ast_rename import run_tree
from test_encoder import ROOT, a
from test_transform import PHP, needs_php


def program(namespaced=True):
    namespace = b"namespace App; " if namespaced else b""
    call = b"\\App\\helper()" if namespaced else b"\\helper()"
    return (b"<?php " + namespace
            + b"class First {static function value(){return 11;}} "
              b"class Second {static function value(){return 13;}} "
              b"function helper(){return First::value()+Second::value();} echo " + call + b";")


@needs_php
@pytest.mark.parametrize("namespaced", [False, True], ids=["global", "namespace"])
def test_allowlist_renames_only_explicit_declarations_and_their_references(tmp_path, namespaced):
    files = {"main.php": program(namespaced)}
    prefix = "App\\" if namespaced else ""
    allowed = [f"type:{prefix}First", f"function:{prefix}helper"]
    before = run_tree(tmp_path / "before", files)
    assert before[0:2] == (0, b"24")
    transformed, mapping, reason = a._names_pass(files, PHP, ast_names=True, allowlist=allowed)
    assert set(mapping) == {f"{prefix}First", f"{prefix}helper"}
    assert not reason and b"class Second" in transformed["main.php"]
    assert b"class First" not in transformed["main.php"]
    assert run_tree(tmp_path / "after", transformed)[0:2] == before[0:2]


@needs_php
def test_allowlist_php_ascii_case_and_non_ascii_are_distinct(tmp_path):
    source = ("<?php namespace App; class ÄWidget {static function go(){return 2;}} "
              "class äWidget {static function go(){return 3;}} echo ÄWidget::go()+äWidget::go();").encode()
    files = {"main.php": source}
    before = run_tree(tmp_path / "before", files)
    assert before[0:2] == (0, b"5")
    transformed, mapping, reason = a._names_pass(files, PHP, ast_names=True,
                                                  allowlist=["type:APP\\ÄWIDGET"])
    assert set(mapping) == {"App\\ÄWidget"} and not reason
    assert "class äWidget".encode() in transformed["main.php"]
    assert run_tree(tmp_path / "after", transformed)[0:2] == before[0:2]


@needs_php
@pytest.mark.parametrize("allowed", [
    [], [""], ["App\\First"], ["class:App\\First"], ["type:\\App\\First"],
    ["type:App\\"], ["type:App\\7bad"], ["type:App\\First thing"],
    ["type:App\\First", "type:app\\fIRST"], ["type:App/First"], [42],
], ids=["empty", "blank", "no-kind", "wrong-kind", "leading-slash", "trailing-slash", "digit",
        "space", "duplicate-case", "slash", "not-string"])
def test_invalid_allowlist_is_refused(allowed):
    with pytest.raises(ValueError, match="allowlist"):
        a._names_pass({"main.php": program()}, PHP, ast_names=True, allowlist=allowed)


@needs_php
@pytest.mark.parametrize("allowed,source,reason", [
    (["type:App\\Missing"], program(), "Missing"),
    (["function:App\\First"], program(), "First"),
    (["type:App\\First"], b"<?php namespace App; class First {} echo First::class;", "dynamic"),
], ids=["unknown", "wrong-symbol-kind", "dynamic"])
def test_allowlist_never_silently_skips_requested_symbols(allowed, source, reason):
    with pytest.raises(ValueError, match=reason):
        a._names_pass({"main.php": source}, PHP, ast_names=True, allowlist=allowed)


@needs_php
def test_allowlist_rejects_psr4_filename_without_publishing_partial_package(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "First.php").write_bytes(b"<?php namespace App; class First {}")
    owner, recipient = a.make_owner(), a.make_recipient("allowlist-test")
    with pytest.raises(ValueError, match="First"):
        a.pack_tree(source, tmp_path / "out", [a.recipient_public(recipient)], owner,
                    str(uuid.uuid4()), php=PHP, obfuscate_names=True, obfuscate_names_ast=True,
                    obfuscate_names_allowlist=["type:App\\First"])
    assert not (tmp_path / "out").exists()


@needs_php
@pytest.mark.parametrize("names,ast", [(False, False), (True, False), (False, True)])
def test_allowlist_requires_both_explicit_name_flags(tmp_path, names, ast):
    owner, recipient = a.make_owner(), a.make_recipient("allowlist-test")
    with pytest.raises(ValueError, match="requires"):
        a.pack_tree(tmp_path, tmp_path / "out", [a.recipient_public(recipient)], owner,
                    str(uuid.uuid4()), php=PHP, obfuscate_names=names, obfuscate_names_ast=ast,
                    obfuscate_names_allowlist=["type:App\\First"])


@needs_php
def test_pack_allowlist_preserves_unlisted_symbols_and_does_not_publish_policy(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.php").write_bytes(program())
    owner, recipient = a.make_owner(), a.make_recipient("allowlist-test")
    info = a.pack_tree(source, tmp_path / "out", [a.recipient_public(recipient)], owner,
                       str(uuid.uuid4()), php=PHP, obfuscate_names=True, obfuscate_names_ast=True,
                       obfuscate_names_allowlist=["type:App\\First"])
    assert len(info["names_obfuscated"]) == 1 and info["names_allowlist_enforced"] is True
    identity = a.make_identity(recipient, owner)
    decoded = a.open_protected((tmp_path / "out" / "main.php").read_bytes(), identity)
    assert b"class First" not in decoded and b"class Second" in decoded
    assert run_tree(tmp_path / "decoded", {"main.php": decoded})[0:2] == (0, b"24")
    assert "App\\First" not in (tmp_path / "out" / "envelock-package.json").read_text()


@needs_php
def test_cli_allowlist_forwards_policy_to_pack(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.php").write_bytes(program())
    owner, recipient = a.make_owner(), a.make_recipient("allowlist-cli")
    owner_file, recipient_file = tmp_path / "owner.json", tmp_path / "public.json"
    owner_file.write_text(json.dumps(owner))
    recipient_file.write_text(json.dumps(a.recipient_public(recipient)))
    result = subprocess.run([sys.executable, str(ROOT / "encoder" / "envelock.py"), "pack",
                             "--source", str(source), "--output", str(tmp_path / "out"),
                             "--project", str(uuid.uuid4()), "--owner", str(owner_file),
                             "--recipient", str(recipient_file), "--obfuscate-names",
                             "--obfuscate-names-ast", "--obfuscate-names-allow", "type:App\\First"],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    info = json.loads(result.stdout)
    assert info["names_allowlist_enforced"] is True and len(info["names_obfuscated"]) == 1


@needs_php
def test_allowlist_refuses_lint_failure_without_publishing(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.php").write_bytes(program())
    owner, recipient = a.make_owner(), a.make_recipient("allowlist-lint")
    monkeypatch.setattr(a, "_php_lint_error_line", lambda php, data: 1)
    with pytest.raises(ValueError, match="allowlist.*lint"):
        a.pack_tree(source, tmp_path / "out", [a.recipient_public(recipient)], owner, str(uuid.uuid4()),
                    php=PHP, obfuscate_names=True, obfuscate_names_ast=True,
                    obfuscate_names_allowlist=["type:App\\First"])
    assert not (tmp_path / "out").exists()
    assert not list(tmp_path.glob(".envelock-pack-*"))


@needs_php
def test_allowlist_refuses_suspect_spans(monkeypatch):
    files = {"main.php": program()}
    info, builtin = a._ast_names(files, PHP)
    info["main.php"]["decls"][0]["start"] += 1
    monkeypatch.setattr(a, "_ast_names", lambda *args: (info, builtin))
    with pytest.raises(ValueError, match="allowlist.*span-mismatch"):
        a._names_pass(files, PHP, ast_names=True, allowlist=["type:App\\First"])


@needs_php
def test_allowlist_risky_other_file_aborts_whole_pack():
    files = {
        "type.php": b"<?php namespace App; class First {}",
        "other.php": (b"<?php namespace App; $n='App\\\\' . 'Fir' . 'st'; "
                      b"echo class_exists($n) ? 'yes' : 'no';"),
    }
    with pytest.raises(ValueError, match="allowlist.*dynamic"):
        a._names_pass(files, PHP, ast_names=True, allowlist=["type:App\\First"])


@needs_php
def test_allowlist_rejects_ambiguous_same_fqn_in_symbol_tables():
    files = {"main.php": b"<?php namespace App; class First {} function First() {}"}
    with pytest.raises(ValueError, match="allowlist.*duplicate-name"):
        a._names_pass(files, PHP, ast_names=True, allowlist=["type:App\\First"])

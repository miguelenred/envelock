#!/usr/bin/env python3
"""Verify that every vendored bytecode layer (extension/opcache/php<MM>/) still carries the
deserializer hardening (internal audit Nov 2026, BC-1..BC-18).

extension/opcache/gen_persist.py regenerates a layer mechanically from upstream OPcache and does NOT
emit any of that hardening: regenerating a layer silently dropped every defence once already (php83
shipped without a single ENVELOCK_BOUND_COUNT). This checker is the gate: it lists, per layer, every
required construct that is missing (and every forbidden one that is back), and exits non-zero.

Usage: python3 scripts/check_bc_layers.py [--root extension/opcache] [--quiet]
"""

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "extension" / "opcache"
HARDEN = "envelock_bc_harden.h"

# The shared header: every helper a layer calls must exist there.
HEADER_REQUIRED = [
    "static const char *envelock_fc_base;",
    "static size_t envelock_fc_size;",
    "#define ENVELOCK_BOUND_COUNT(p, count)",
    "#define ENVELOCK_FC_EXTENT(p, bytes)",
    "static zend_never_inline void envelock_fc_check_stack(void)",
    "zend_call_stack_overflowed(EG(stack_limit))",
    "static zend_always_inline void envelock_fc_check_string(zend_string *s)",
    "GC_TYPE_INFO(s) = GC_STRING | (IS_STR_INTERNED << GC_FLAGS_SHIFT);",
    "ZSTR_H(s) = zend_inline_hash_func(",
    "static void envelock_fc_check_table(HashTable *ht)",
    "static void envelock_fc_rehash(HashTable *ht)",
    "static zend_always_inline void envelock_fc_check_uninitialized(HashTable *ht)",
    "static zend_always_inline void envelock_fc_check_table_seen(HashTable *ht)",
    "static zend_always_inline void envelock_fc_check_opline(",
    "opline->opcode > ZEND_VM_LAST_OPCODE",
    "envelock_fc_optype_ok(opline->op1_type)",
    "static void envelock_fc_set_handlers(zend_op_array *op_array)",
    "ZEND_VM_SET_OPCODE_HANDLER(",
    "static zend_always_inline void envelock_fc_note_opline(zend_op *opline)",
    "Z_EXTRA_P(fname) = 0;",
    "static zend_always_inline void envelock_fc_check_arg_info(",
    "static void envelock_fc_check_op_array_arrays(",
    "static zend_always_inline void envelock_fc_check_prop(",
    "static zend_always_inline void envelock_fc_fix_class(",
    "static zend_always_inline void envelock_fc_fix_array(zval *zv)",
    "static zend_always_inline void envelock_fc_check_zval_type(",
    "static void envelock_fc_finish(envelock_persistent_script *script)",
    "void envelock_file_cache_unserialize_cleanup(void)",
    "void envelock_file_cache_unserialize_abandon(void)",
]

# Required in every layer's envelock_file_cache.c. (needle, minimum count)
FILE_CACHE_REQUIRED = [
    ('#include "../envelock_bc_harden.h"', 1),
    ("#define IS_SERIALIZED(ptr) \\\n\t((size_t)(ptr) <= envelock_fc_size)", 1),
    ("(const char*)(ptr) >= envelock_fc_base", 1),
    ('"Envelock: corrupt bytecode image (pointer out of range)"', 1),
    ('"Envelock: corrupt bytecode image (string out of range)"', 1),
    ("envelock_fc_check_string((zend_string*)(ptr));", 1),
    ("GC_DEL_FLAGS(ptr, IS_STR_CLASS_NAME_MAP_PTR);", 1),            # BC-8
    ('"Envelock: corrupt bytecode image (interned string not allowed)"', 1),
    ("envelock_fc_begin(buf, size,", 1),                             # BC-5
    ("envelock_fc_finish(script);", 1),
    # BC-3/BC-4: every count-driven walk
    ("ENVELOCK_BOUND_COUNT(p, ht->nNumUsed);", 2),
    ("ENVELOCK_BOUND_COUNT(p, op_array->last_literal);", 1),
    ("ENVELOCK_BOUND_COUNT(opline, op_array->last);", 1),
    ("envelock_fc_check_arg_info(op_array);", 1),                    # BC-15
    ("ENVELOCK_BOUND_COUNT(p, op_array->last_var);", 1),
    ("ENVELOCK_BOUND_COUNT(op_array->dynamic_func_defs, op_array->num_dynamic_func_defs);", 1),
    ("ENVELOCK_BOUND_COUNT(p, ce->default_properties_count);", 1),
    ("ENVELOCK_BOUND_COUNT(p, ce->default_static_members_count);", 1),
    ("ENVELOCK_BOUND_COUNT(ce->properties_info_table, ce->default_properties_count);", 1),
    ("ENVELOCK_BOUND_COUNT(ce->interface_names, ce->num_interfaces);", 1),
    ("ENVELOCK_BOUND_COUNT(ce->trait_names, ce->num_traits);", 1),
    ("ENVELOCK_BOUND_COUNT(q->exclude_class_names, q->num_excludes);", 1),
    ("ENVELOCK_BOUND_COUNT(p, 1);", 4),
    ("ENVELOCK_BOUND_COUNT(attr->args, attr->argc);", 1),
    ("ENVELOCK_BOUND_COUNT(list->types, list->num_types);", 1),
    ("ENVELOCK_BOUND_COUNT(script->warnings, script->num_warnings);", 1),
    ("ENVELOCK_BOUND_COUNT(script->early_bindings, script->num_early_bindings);", 1),
    ('"early binding cache slot out of range"', 1),                  # BC-6
    # BC-13: recursion budget in every recursive unserializer
    ("envelock_fc_check_stack();", 5),
    ("envelock_fc_check_ast(ast);", 1),
    # BC-9: tables
    ("envelock_fc_check_uninitialized(ht);", 1),
    ("envelock_fc_check_table_seen(ht);", 1),
    ("envelock_fc_check_table(ht);", 1),
    ("envelock_fc_rehash(ht);", 1),
    ('"packed symbol table"', 1),
    # BC-12: opcodes
    ("envelock_fc_check_opline(op_array, opline);", 1),
    ("envelock_fc_note_opline(opline);", 1),
    ("envelock_fc_set_handlers(op_array);", 1),
    ("envelock_fc_own_op_array(op_array);", 1),
    ("envelock_fc_share_op_array(op_array);", 1),
    ("envelock_fc_check_op_array_seen(op_array);", 1),
    ("envelock_fc_check_op_array_arrays(op_array);", 1),
    # values and classes
    ("envelock_fc_check_zval_type(zv,", 1),
    ("envelock_fc_fix_array(zv);", 1),
    ("envelock_fc_fix_ast_ref(zv);", 2),
    ("envelock_fc_fix_class(ce);", 1),
    ("envelock_fc_check_prop(Z_PTR_P(zv));", 1),
    ("ENVELOCK_FC_EXTENT(ce, sizeof(zend_class_entry));", 1),
    ("ENVELOCK_FC_EXTENT(func, sizeof(zend_op_array));", 1),
    ("ENVELOCK_FC_EXTENT(op_array, sizeof(zend_op_array));", 1),
    ("ENVELOCK_FC_EXTENT(script, sizeof(*script));", 1),
    ("envelock_fc_base = (const char *) script->mem;", 1),           # pack side bound
]

# PHP 8.4+: property hooks. PHP 8.5: constant-expression closures and attributed constants (BC-14).
FILE_CACHE_REQUIRED_84 = [
    ("ENVELOCK_BOUND_COUNT(prop->hooks, ZEND_PROPERTY_HOOK_COUNT);", 1),
]
FILE_CACHE_REQUIRED_85 = [
    ("ZEND_MAP_PTR_INIT(fcc->fptr, NULL);", 1),
    ('"declaration in a constant expression"', 1),
    ("&& opline > op_array->opcodes", 1),
    ('"attributed constant without its attributes"', 2),
    ("ENVELOCK_FC_EXTENT(ast, sizeof(zend_ast_op_array));", 1),
]

# Never allowed on the deserialization side (from the unserialize_hash definition to the end).
UNSERIALIZE_FORBIDDEN = [
    ("zend_deserialize_opcode_handler(", "unchecked handler index from the image (BC-12)"),
    ("script->corrupted", "control state read back from the image (BC-5)"),
    ("script->size", "bound read back from the image (BC-5)"),
    ("ZEND_UNREACHABLE()", "undefined behaviour in a release build (BC-14)"),
    ("#define ENVELOCK_BOUND_COUNT", "a local copy of the bound macro that ignores the captured bound"),
]
FILE_FORBIDDEN = [
    ("ZCG(mem) + ((size_t)(str) & ~Z_UL(1))", "unbounded interned-string offset (ENV-2026-04)"),
    ("(char*)script->size", "IS_SERIALIZED bound read from the image (BC-5)"),
]

BC_REQUIRED = [
    ("envelock_bc_save_state(&state);", 2),                          # BC-1 (load + emit)
    ("envelock_bc_restore_state(&state);", 2),
    ("EG(bailout) = state->bailout;", 1),
    ("static zend_op_array *envelock_bc_guarded(", 1),               # BC-2
    ('_zend_bailout("envelock_bc.c", __LINE__);', 1),
    ("static int envelock_bc_seh_filter(unsigned long code)", 1),    # BC-13
    ("_resetstkoflw();", 1),
    ("SIGFPE", 1),
    ("envelock_bc_rollback(image, length + slack);", 1),             # BC-7
    ("*retain = 1;", 1),
    ("ZEND_COMPILE_IGNORE_INTERNAL_FUNCTIONS", 1),                   # BC-10
    ("ZEND_COMPILE_WITH_FILE_CACHE", 1),                             # BC-16
    ("zend_execute_internal = execute_internal;", 1),                # no frameless/specialised calls
    ("envelock_bc_identity()", 3),
    ("mem_size > UINT32_MAX", 1),                                    # BC-18
    ("(uint64_t) script->size > UINT32_MAX", 1),
    ("script_offset > mem_size - sizeof(envelock_persistent_script)", 1),   # BC-15
    ("slack < ENVELOCK_BC_SLACK", 1),
    ("envelock_arena_ok()", 1),                                      # BC-17
    ("envelock_file_cache_unserialize(script, image + ENVELOCK_BC_WIRE_SIZE, (size_t) mem_size);", 1),
]
BC_FORBIDDEN = [
    ("__except (EXCEPTION_EXECUTE_HANDLER)", "catches every exception, stack overflow included (BC-13)"),
    ("memcmp(image + ENVELOCK_BC_OFF_SYSTEM_ID, zend_system_id", "SAPI-dependent gate (BC-16)"),
]
# Never allowed in any layer source: both expand __FILE__, i.e. the absolute path of the build
# directory (and with it the builder's user name), into the shipped module.
EVERY_FILE_FORBIDDEN = [
    ("zend_bailout();", "use _zend_bailout(\"<file>.c\", __LINE__): zend_bailout() embeds __FILE__"),
    ("__FILE__", "embeds the absolute build path in the binary"),
]
ARENA_REQUIRED = [
    ("static ZEND_COLD ZEND_NORETURN void envelock_arena_fail(void)", 1),
    ('_zend_bailout("envelock_arena.c", __LINE__);', 1),
    ("bool envelock_arena_ok(void)", 1),
    ("void envelock_arena_check(void)", 1),
    ("PAGE_NOACCESS", 1),
]
PERSIST_REQUIRED = [
    ("HT_SET_DATA_ADDR(ht, envelock_alloc((hash_size * sizeof(uint32_t)) + (ht->nNumUsed * sizeof(Bucket))));", 1),
    ("data = envelock_alloc(HT_USED_SIZE(ht));", 1),
    ("envelock_arena_check();", 3),
]
SCRIPT_REQUIRED = [
    ("early_binding->cache_slot <= op_array->cache_size - sizeof(void *)", 1),
]
SHIM_REQUIRED = [
    ("void envelock_file_cache_unserialize(envelock_persistent_script *script, void *buf, size_t size);", 1),
    ("void envelock_file_cache_unserialize_cleanup(void);", 1),
    ("bool  envelock_arena_ok(void);", 1),
]


def check_counts(text, required, label, problems):
    for needle, minimum in required:
        found = text.count(needle)
        if found < minimum:
            problems.append(f"{label}: missing {needle!r} (found {found}, need >= {minimum})")


def check_layer(layer):
    problems = []
    version = layer.name                      # php82 ...
    minor = int(version[3:]) if version[3:].isdigit() else 0

    fc = layer / "envelock_file_cache.c"
    if not fc.exists():
        return [f"{version}: envelock_file_cache.c missing"]
    text = fc.read_text(encoding="utf-8", errors="replace")
    check_counts(text, FILE_CACHE_REQUIRED, f"{version}/envelock_file_cache.c", problems)
    if minor >= 84:
        check_counts(text, FILE_CACHE_REQUIRED_84, f"{version}/envelock_file_cache.c", problems)
    if minor >= 85:
        check_counts(text, FILE_CACHE_REQUIRED_85, f"{version}/envelock_file_cache.c", problems)
    for needle, why in FILE_FORBIDDEN + EVERY_FILE_FORBIDDEN:
        if needle in text:
            problems.append(f"{version}/envelock_file_cache.c: forbidden {needle!r}: {why}")
    marker = text.find("static void envelock_file_cache_unserialize_hash(")
    if marker < 0:
        problems.append(f"{version}/envelock_file_cache.c: unserialize_hash definition not found")
    else:
        rest = text[marker:]
        for needle, why in UNSERIALIZE_FORBIDDEN:
            if needle in rest:
                problems.append(f"{version}/envelock_file_cache.c: forbidden on the unserialize side "
                                f"{needle!r}: {why}")
        # every interned-string reference must go through the refusing helper
        interned = re.search(r"void \*envelock_file_cache_unserialize_interned\(zend_string \*str\)\s*\{(.*?)\n\}",
                             text, re.S)
        if not interned or "zend_error_noreturn" not in interned.group(1):
            problems.append(f"{version}/envelock_file_cache.c: unserialize_interned does not fail closed")

    for name, required, forbidden in (("envelock_bc.c", BC_REQUIRED, BC_FORBIDDEN),
                                      ("envelock_arena.c", ARENA_REQUIRED, []),
                                      ("envelock_persist.c", PERSIST_REQUIRED, []),
                                      ("envelock_script.c", SCRIPT_REQUIRED, []),
                                      ("envelock_accel_shim.h", SHIM_REQUIRED, [])):
        path = layer / name
        if not path.exists():
            problems.append(f"{version}: {name} missing")
            continue
        body = path.read_text(encoding="utf-8", errors="replace")
        check_counts(body, required, f"{version}/{name}", problems)
        for needle, why in list(forbidden) + EVERY_FILE_FORBIDDEN:
            if needle in body:
                problems.append(f"{version}/{name}: forbidden {needle!r}: {why}")
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT, help="the extension/opcache directory")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    problems = []

    header = root / HARDEN
    if not header.exists():
        problems.append(f"{HARDEN} missing")
    else:
        check_counts(header.read_text(encoding="utf-8", errors="replace"),
                     [(n, 1) for n in HEADER_REQUIRED], HARDEN, problems)

    layers = sorted(p for p in root.glob("php8*") if p.is_dir())
    if not layers:
        problems.append(f"no php<MM> layer under {root}")
    for layer in layers:
        problems.extend(check_layer(layer))

    # The version-independent files must stay identical across layers: a fix applied to one copy
    # and not the others is exactly the drift this checker exists for.
    for name in ("envelock_bc.c", "envelock_arena.c"):
        copies = {layer.name: (layer / name).read_bytes() for layer in layers if (layer / name).exists()}
        if len(set(copies.values())) > 1:
            problems.append(f"{name} differs between layers: {', '.join(sorted(copies))} must be identical")

    if problems:
        print("check_bc_layers: FAILED - the bytecode layer lost hardening (see scripts/check_bc_layers.py):")
        for problem in problems:
            print("  -", problem)
        return 1
    if not args.quiet:
        print(f"check_bc_layers: OK ({', '.join(layer.name for layer in layers)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

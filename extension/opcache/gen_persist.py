#!/usr/bin/env python3
"""Regenerate extension/opcache/php<major><minor>/envelock_{persist,file_cache,script}.c from a
PHP source tree.

The three files are OPcache's persistence and script-plumbing code, transformed mechanically:
symbols renamed with a `zend_` -> `envelock_` prefix, the shared-memory allocator replaced by the
process-memory arena, and the file/SHM I/O (which Envelock never does) removed. Doing it as a
transformation keeps every change auditable with `diff -u` against the upstream file, which matters
more here than saving a few lines: this is the code that reconstructs a program from bytes.

Why the file is edited line by line instead of being run through cpp: the renaming works on the
written source (ZCG(...) must survive, because the shim redefines it), and cpp would expand every
macro it can see. So only the conditionals that are platform noise (ZEND_WIN32, __APPLE__, the
sanitizer probes, HAVE_JIT) are resolved here, and the ones that depend on the real engine
(ZEND_USE_ABS_CONST_ADDR, ZEND_USE_ABS_JMP_ADDR) are left in place for the compiler — they are
defined in the installed Zend headers, exactly as upstream expects.

How the edits are located: functions are found by line range (a `static`-or-typed definition line
at column 0 whose braces balance), never by matching a body as text — the renaming has already
rewritten the symbols inside it, so an exact-text match would fail silently. Anything that needs a
whole function replaced goes through replace_function(), which refuses to guess: it is a no-op when
the function is absent and an error when the name appears twice. Directives are only recognised at
column 0, which is how all three upstream files write them.

SECURITY WARNING (internal audit, Nov 2026, BC-11). The output is the UPSTREAM traversal, which
trusts the image completely. The shipped layers are hardened by hand on top of it: the shared
../envelock_bc_harden.h and its call sites in envelock_file_cache.c (bounds, counts, tables,
opcodes, strings, recursion), plus the fail-closed arena bumps in envelock_persist.c, the cache-slot
check in envelock_script.c and the guarded envelock_bc.c. Regenerating a layer silently drops all of
that (php83 once shipped without a single bound check). So this script REFUSES to overwrite a layer
that exists unless --force is given, and after writing it runs scripts/check_bc_layers.py, which
lists every defence the new files lack. A regenerated layer must not ship until that check passes.

Usage: python3 extension/opcache/gen_persist.py /path/to/php-8.4.27 8.4 [--windows] [--force]
"""

import re
import sys
from pathlib import Path

# ---------------------------------------------------------------- renaming
PREFIX_MAP = [
    ("zend_persistent_script", "envelock_persistent_script"),
    ("zend_accel_script_persist", "envelock_script_persist"),
    ("zend_accel_store_string", "envelock_store_string"),
    ("zend_accel_store_interned_string", "envelock_store_interned_string"),
    ("zend_accel_memdup_string", "envelock_memdup_string"),
    ("zend_accel_memdup_interned_string", "envelock_memdup_interned_string"),
    ("zend_accel_in_shm", "envelock_in_shm"),
    ("zend_accel_get_class_name_map_ptr", "envelock_get_class_name_map_ptr"),
    ("zend_accel_pending_ce_cache_begin", "envelock_pending_ce_cache_begin"),
    ("zend_accel_pending_ce_cache_commit", "envelock_pending_ce_cache_commit"),
    ("zend_accel_pending_ce_cache_discard", "envelock_pending_ce_cache_discard"),
    ("zend_accel_persist_jit_op_array", "envelock_persist_jit_op_array"),
    ("zend_accel_persist_link_func_info", "envelock_persist_link_func_info"),
    ("zend_accel_persist_class_table", "envelock_persist_class_table"),
    ("zend_accel_error_noreturn", "envelock_accel_error"),
    ("zend_accel_error", "envelock_accel_error"),
    ("zend_shared_alloc_get_shared_mem", "envelock_arena_base"),
    ("zend_shared_alloc_aligned", "envelock_alloc_aligned"),
    ("zend_shared_alloc_get_xlat_entry", "envelock_xlat_get"),
    ("zend_shared_alloc_register_xlat_entry", "envelock_xlat_register"),
    ("zend_shared_alloc", "envelock_alloc"),
    ("zend_shared_memdup_get_put_free", "envelock_memdup_get_put_free"),
    ("zend_shared_memdup_put_free", "envelock_memdup_put_free"),
    ("zend_shared_memdup_free", "envelock_memdup_free"),
    ("zend_shared_memdup_put", "envelock_memdup_put"),
    ("zend_shared_memdup", "envelock_memdup"),
    ("accel_time_t", "envelock_accel_time_t"),
    # OPcache's own types and tables. Deliberately a closed list: Zend's own types (zend_string,
    # zend_ast, zend_op_array, ...) must keep their names, they are the engine's ABI.
    ("zend_persist_zval", "envelock_persist_zval"),
    ("zend_persist_op_array_ex", "envelock_persist_op_array_ex"),
    ("zend_persist_op_array", "envelock_persist_op_array"),
    ("zend_persist_func_t", "envelock_persist_func_t"),
    ("zend_hash_persist", "envelock_hash_persist"),
    ("zend_persist_ast", "envelock_persist_ast"),
    ("zend_persist_attributes", "envelock_persist_attributes"),
    ("zend_persist_type", "envelock_persist_type"),
    ("zend_persist_class_method", "envelock_persist_class_method"),
    ("zend_persist_property_info", "envelock_persist_property_info"),
    ("zend_persist_class_constant", "envelock_persist_class_constant"),
    ("zend_persist_class_entry", "envelock_persist_class_entry"),
    ("zend_persist_warnings", "envelock_persist_warnings"),
    ("zend_persist_early_bindings", "envelock_persist_early_bindings"),
    ("zend_update_parent_ce", "envelock_update_parent_ce"),
    ("zend_file_cache_metainfo", "envelock_file_cache_metainfo"),
    ("zend_file_cache_serialize_interned", "envelock_file_cache_serialize_interned"),
    ("zend_file_cache_unserialize_interned", "envelock_file_cache_unserialize_interned"),
    ("zend_file_cache_serialize_hash", "envelock_file_cache_serialize_hash"),
    ("zend_file_cache_unserialize_hash", "envelock_file_cache_unserialize_hash"),
    ("zend_file_cache_serialize_ast", "envelock_file_cache_serialize_ast"),
    ("zend_file_cache_unserialize_ast", "envelock_file_cache_unserialize_ast"),
    ("zend_file_cache_serialize_zval", "envelock_file_cache_serialize_zval"),
    ("zend_file_cache_unserialize_zval", "envelock_file_cache_unserialize_zval"),
    ("zend_file_cache_serialize_attribute", "envelock_file_cache_serialize_attribute"),
    ("zend_file_cache_unserialize_attribute", "envelock_file_cache_unserialize_attribute"),
    ("zend_file_cache_serialize_type", "envelock_file_cache_serialize_type"),
    ("zend_file_cache_unserialize_type", "envelock_file_cache_unserialize_type"),
    ("zend_file_cache_serialize_op_array", "envelock_file_cache_serialize_op_array"),
    ("zend_file_cache_unserialize_op_array", "envelock_file_cache_unserialize_op_array"),
    ("zend_file_cache_serialize_func", "envelock_file_cache_serialize_func"),
    ("zend_file_cache_unserialize_func", "envelock_file_cache_unserialize_func"),
    ("zend_file_cache_serialize_prop_info", "envelock_file_cache_serialize_prop_info"),
    ("zend_file_cache_unserialize_prop_info", "envelock_file_cache_unserialize_prop_info"),
    ("zend_file_cache_serialize_class_constant", "envelock_file_cache_serialize_class_constant"),
    ("zend_file_cache_unserialize_class_constant", "envelock_file_cache_unserialize_class_constant"),
    ("zend_file_cache_serialize_class", "envelock_file_cache_serialize_class"),
    ("zend_file_cache_unserialize_class", "envelock_file_cache_unserialize_class"),
    ("zend_file_cache_serialize_warnings", "envelock_file_cache_serialize_warnings"),
    ("zend_file_cache_unserialize_warnings", "envelock_file_cache_unserialize_warnings"),
    ("zend_file_cache_serialize_early_bindings", "envelock_file_cache_serialize_early_bindings"),
    ("zend_file_cache_unserialize_early_bindings", "envelock_file_cache_unserialize_early_bindings"),
    ("zend_file_cache_serialize", "envelock_file_cache_serialize"),
    ("zend_file_cache_unserialize", "envelock_file_cache_unserialize"),
    ("create_persistent_script", "envelock_create_script"),
    ("free_persistent_script", "envelock_free_script"),
    ("zend_accel_move_user_functions", "envelock_move_user_functions"),
    ("zend_accel_move_user_classes", "envelock_move_user_classes"),
    ("_zend_accel_function_hash_copy", "_envelock_function_hash_copy"),
    ("zend_accel_function_hash_copy_notify", "envelock_function_hash_copy_notify"),
    ("zend_accel_function_hash_copy", "envelock_function_hash_copy"),
    ("_zend_accel_class_hash_copy", "_envelock_class_hash_copy"),
    ("zend_accel_class_hash_copy_notify", "envelock_class_hash_copy_notify"),
    ("zend_accel_class_hash_copy", "envelock_class_hash_copy"),
    ("zend_accel_build_delayed_early_binding_list", "envelock_build_delayed_early_binding_list"),
    ("zend_accel_finalize_delayed_early_binding_list",
     "envelock_finalize_delayed_early_binding_list"),
    ("zend_accel_free_delayed_early_binding_list", "envelock_free_delayed_early_binding_list"),
    ("zend_accel_do_delayed_early_binding", "envelock_do_delayed_early_binding"),
    ("zend_accel_load_script", "envelock_load_script"),
    ("zend_accel_script_checksum", "envelock_script_checksum"),
    # zend_adler32 keeps its name: the comment block above it is zlib's copyright notice and the
    # rename would detach the attribution from the code it covers.
]

# Not renamed: these are the engine's own symbols, exported by the PHP binary itself
# (verified with `nm -D` on the target build): zend_serialize_opcode_handler,
# zend_deserialize_opcode_handler, zend_extensions_op_array_persist, zend_map_ptr_extend,
# zend_alloc_ce_cache, zend_try_early_bind, zend_bind_class_in_slot, zend_map_ptr_static_last.

# ------------------------------------------------------- functions to drop
# File and SHM I/O: Envelock serializes to a buffer and deserializes in place, it never opens a
# cache file and never touches shared memory.
DROP = {
    "zend_file_cache_mkdir",
    "zend_file_cache_flock",
    "zend_file_cache_get_bin_file_path",
    "zend_file_cache_script_write",
    "zend_file_cache_script_store",
    "zend_file_cache_script_load",
    "zend_file_cache_script_load_ex",  # 8.5 split the loader into a _ex variant + a thin wrapper;
                                       # both are the SHM load path Envelock never takes
    "zend_file_cache_invalidate",
    "zend_accel_in_shm",
    "accel_new_interned_string",
    "zend_accel_get_auto_globals",
}

# Macros that only the dropped file/SHM I/O used.
DROP_DEFINES = re.compile(r"^#\s*define\s+(zend_file_cache_|LOCK_|O_BINARY)")

# Conditionals that are platform noise: resolved here so the generated copy carries only the code
# path this platform takes. Anything not listed is left untouched for the compiler.
# Keys are the NORMALISED condition: #ifdef X becomes "defined(X)", #ifndef X becomes
# "!defined(X)", #if X keeps its text. Listing a bare macro name would silently never match an
# #ifdef, which is how the Windows-only flock kept surviving.
RESOLVE = {
    "defined(ZEND_WIN32)": False,
    "defined(__APPLE__)": False,
    "defined(HAVE_JIT)": False,  # the image carries no JIT state (see the #undef in the header)
    "__has_feature(memory_sanitizer)": False,
    "__has_feature(address_sanitizer)": False,
}

HEADER = """/*
  +----------------------------------------------------------------------+
  | Envelock — bytecode layer (objective O1)                             |
  +----------------------------------------------------------------------+
  | GENERATED, THEN HARDENED BY HAND (audit Nov 2026): regenerating      |
  | with gen_persist.py drops the hardening (../envelock_bc_harden.h     |
  | and its call sites); scripts/check_bc_layers.py must pass.           |
  | Regenerate with: python3 extension/opcache/gen_persist.py PHP_SRC VER|
  |                                                                      |
  | Adapted from Zend OPcache's ext/opcache/{upstream}                   |
  | (c) The PHP Group, PHP License 3.01 — see NOTICE for provenance.     |
  |                                                                      |
  | Changes from upstream: symbols renamed zend_* -> envelock_*, the     |
  | shared-memory allocator replaced by the process-memory arena in      |
  | envelock_arena.c, and the file/SHM I/O removed. The traversal of     |
  | Zend's structures is deliberately untouched: it is the part that has |
  | to keep matching the engine exactly.                                 |
  +----------------------------------------------------------------------+
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#ifndef PHP_WIN32
#include "php_config.h"
#endif
#include <stdlib.h>

#include "envelock_accel_shim.h"
#include "zend_compile.h"
#include "zend_vm.h"
#include "zend_interfaces.h"
#include "zend_attributes.h"
#include "zend_system_id.h"
#include "zend_enum.h"
#include "zend_constants.h"
#include "zend_operators.h"
#include "zend_extensions.h"
#include "ext/standard/php_filestat.h"

#include <string.h>

/* The image Envelock ships carries no JIT structures, so the JIT branches of the persistence
 * code are compiled out. This is a deliberate constraint of objective O1: bytecode blobs run on
 * the VM executor, exactly as an OPcache file-cache script does. */
#undef HAVE_JIT

"""

# Column 0 only: an indented # directive belongs to a function body and must stay inside it, not be
# mistaken for a top-level one (verified: none of the three upstream files indents a directive).
DIRECTIVE = re.compile(r"#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)$")
# A top-level definition starts at column 0 and its opening brace is at column 0 too. Anything
# indented is inside a body, which is what keeps struct members and prototypes from being read as
# functions.
# Deliberately NOT allowing newlines in the parameter list (no re.S, no [^;]*?): a typedef like
#
#   typedef int (*serialize_callback_t)(zval *zv,
#                                       ...
#
# otherwise matches all the way to the opening brace of the next real function, and everything in
# between — the SERIALIZE_PTR/IS_SERIALIZED macro block, the other typedefs — disappears from the
# generated copy. The opening brace must also sit on the signature's own line.

# The metainfo record is declared in the shim header (the Envelock surface needs it too), so the
# copy must not declare it a second time.
# The typedef name is renamed by rename(); the struct tag is not (it is not in the symbol list).
METAINFO = re.compile(
    r"typedef struct _zend_file_cache_metainfo \{.*?\} envelock_file_cache_metainfo;\s*", re.S)


# ------------------------------------------------------------------ line-range rewriting
# The transformation is a sequence of line-range deletions on the original file, repeated until
# nothing more can go. It is deliberately dumb: no C parsing, no nesting tree. Each step is easy to
# check against the upstream file with diff, which is the point of keeping this a transformation.

DIRECTIVE = re.compile(r"#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)$")
# A top-level definition starts at column 0 and its opening brace is on the same line. Anything
# indented is inside a body. The parameter list must stay on one line, otherwise a typedef like
#   typedef int (*serialize_callback_t)(zval *zv,
# matches through to the next function's opening brace and swallows the macro block in between.
# "Is this line the start of a top-level definition?" — the name is taken separately, because a
# lazy (\w+...) capture grabs the RETURN type of "zend_persistent_script *zend_file_cache_...("
# and then finds no "(" after it, so the whole definition stopped matching.
# The opening brace may sit on the signature's line or on the next one (upstream does both); the
# caller checks `brace_here or next_line_is_brace`.
# The signature itself may continue on the next line; only its first line is matched here.
# Return type + name, then "(". The return type is one or more words possibly starred
# ("static zend_always_inline void *"), which a single lazy word group cannot span — with it the
# pattern matched nothing at all and every function was invisible to the transformation.
DEFINITION_HEAD = re.compile(
    r"^(?!#)(?!typedef\b)(?!return\b)(?:\w+\**[ \t]+)+\*?[ \t]*\w+[ \t]*\**[ \t]*\(?")
# The function name is the last identifier before the "(" — the only reliable way to read it off a
# declaration whose return type may itself contain spaces and stars.
# The "(" is optional: the caller cuts the signature at its first paren before searching.
DEF_NAME = re.compile(r"(\w+)[ \t]*\(?")


def function_ranges(lines):
    """(name, start, end) for each top-level function; end exclusive, brace-matched at column 0.

    The signature may span several lines (upstream does this for the callback-taking serializers),
    so the closing paren is found by scanning, and the opening brace must be the next thing after
    it. Missing a definition here is not cosmetic: the function stops existing as a unit, so it can
    neither be dropped nor be found again by name.
    """
    ranges = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if line[:1].isspace() or line.startswith("#") or line.startswith("//"):
            index += 1
            continue
        match = DEFINITION_HEAD.match(line)
        if match is None:
            index += 1
            continue
        close = line.find(")")
        cursor = index
        while close < 0 and cursor + 1 < len(lines):
            cursor += 1
            close = lines[cursor].find(")")
        if close < 0:
            index += 1
            continue
        rest = lines[cursor][close + 1:].strip()
        brace_here = rest.startswith("{")
        brace_next = lines[cursor + 1:cursor + 2] == ["{\n"]
        if not (brace_here or brace_next):
            index += 1
            continue
        # The name is the last identifier before the "(" of the whole signature, which for a
        # multi-line one is not on the first line at all:
        #     static void zend_file_cache_serialize_zval(zval *zv,
        #                                                zend_persistent_script *script, ...)
        head = "".join(lines[index:cursor + 1])
        names = DEF_NAME.findall(head.split("(")[0])
        if not names:
            index += 1
            continue
        name = names[-1]
        start = index
        while start > 0:
            previous = lines[start - 1].strip()
            if not previous or previous.startswith("*") or previous.startswith("/*") \
                    or previous.startswith("//"):
                start -= 1
            else:
                break
        # Start at -1: the body's opening brace is what brings the counter to 0, and the closing
        # one takes it back to -1. Starting at 0 instead ended the "function" at the next
        # column-0 closing brace — usually the one belonging to the following function — which
        # swallowed the rest of the file into a single bogus range.
        depth = -1
        end = cursor
        closed = False
        while end < len(lines):
            depth += lines[end].count("{") - lines[end].count("}")
            end += 1
            if depth <= -1 and lines[end - 1].lstrip().startswith("}"):
                closed = True
                break
        if not closed:
            # Unbalanced in the raw text (a platform #ifdef with braces in both branches, before
            # the conditional was resolved). Treat it as "not a function" rather than letting one
            # bogus range cover the rest of the file.
            index += 1
            continue
        ranges.append((name, start, end))
        index = end
    return ranges


def conditional_ranges(lines):
    """(open, [(branch_start, branch_end), ...], close) for each top-level conditional, innermost
    first. open/close are the #if/#endif line indices, close exclusive."""
    found = []
    stack = []
    for index, line in enumerate(lines):
        if line[:1].isspace() or not line.lstrip().startswith("#"):
            continue
        directive = DIRECTIVE.match(line.lstrip())
        if directive is None:
            continue
        kind, rest = directive.group(1), directive.group(2).strip()
        if kind in ("if", "ifdef", "ifndef"):
            condition = rest if kind == "if" else (
                ("!defined(%s)" % rest) if kind == "ifndef" else ("defined(%s)" % rest))
            stack.append({"open": index, "condition": condition,
                          "branches": [(index, index + 1, kind)]})
        elif kind in ("elif", "else") and stack:
            entry = stack[-1]
            previous = entry["branches"][-1]
            entry["branches"][-1] = (previous[0], index, previous[2])
            entry["branches"].append((index, index + 1, kind))
            if kind == "elif":
                entry["branches"][-1] = (index, index + 1, "elif")
                entry.setdefault("elif_conditions", []).append(rest)
        elif kind == "endif" and stack:
            entry = stack.pop()
            previous = entry["branches"][-1]
            entry["branches"][-1] = (previous[0], index, previous[2])
            found.append(entry | {"close": index})
    # Innermost first: they were closed in that order.
    return found


def strip_pass(lines, windows):
    """One round of deletions. Returns (new_lines, changed).

    Includes and conditionals are removed BEFORE functions are located, and the caller repeats
    until stable. The order matters: upstream guards the two platform variants of a helper with
    #ifdef/#else, so the raw text of such a function has unbalanced braces (both branches' opening
    braces, one closing). Counting braces before the conditional is resolved makes the function run
    to the end of the file and hides every function after it.
    """
    drop = set()

    for index, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith("#include") or stripped.startswith("# include"):
            drop.add(index)
        elif DROP_DEFINES.match(stripped):
            drop.add(index)

    for entry in conditional_ranges(lines):
        values = []
        resolvable = True
        for position, branch in enumerate(entry["branches"]):
            if branch[2] == "else":
                values.append(None)
                continue
            condition = entry["condition"] if position == 0 else \
                entry.get("elif_conditions", [None] * position)[position - 1]
            value = condition_value(condition, windows)
            if value is None:
                resolvable = False
                break
            values.append(value)
        if not resolvable:
            continue
        chosen = None
        settled = False
        for position, value in enumerate(values):
            if value is None:            # the #else branch
                if chosen is None and settled:
                    chosen = position
                break
            settled = True
            if value and chosen is None:
                chosen = position
        if chosen is None:
            drop.update(range(entry["open"], entry["close"] + 1))
            continue
        for position, (start, end, _kind) in enumerate(entry["branches"]):
            if position == chosen:
                drop.add(start)                           # the #if/#elif/#else line itself
                continue
            drop.update(range(start, end))
        drop.add(entry["close"])                          # and the #endif

    # A conditional whose body is now only comments, blanks and directives goes too, so that
    # removing an include never leaves a dangling #endif.
    for entry in conditional_ranges(lines):
        body = [index for index in range(entry["open"] + 1, entry["close"])
                if index not in drop]
        if body and all(
                not lines[index].strip()
                or lines[index].lstrip().startswith(("*", "/*", "//"))
                or (lines[index].lstrip().startswith("#")
                    and not DIRECTIVE.match(lines[index].lstrip()))
                for index in body):
            drop.update(range(entry["open"], entry["close"] + 1))

    if drop:
        lines = [line for index, line in enumerate(lines) if index not in drop]

    # Functions come last, on text whose preprocessor structure is already settled.
    drop = set()
    for name, start, end in function_ranges(lines):
        if name in DROP or rename(name) in DROP:
            drop.update(range(start, end))
    if not drop:
        return lines, False
    return [line for index, line in enumerate(lines) if index not in drop], True


def rewrite(source_text, windows):
    lines = source_text.splitlines(keepends=True)
    for _ in range(50):
        lines, changed = strip_pass(lines, windows)
        if not changed:
            break
    return "".join(lines)


# Conditions that mean "this is Linux", resolved from the target platform rather than a table.
LINUX_ONLY = ("defined(__linux__)", "__linux__", "defined(HAVE_MEMFD_CREATE)")


def condition_value(condition, windows):
    """True/False when the condition is platform noise resolved here; None to leave it alone.

    None is the safe answer: the conditional stays in the generated copy and the real compiler
    resolves it against the real Zend headers, exactly as upstream expects.
    """
    condition = (condition or "").strip()
    if condition in LINUX_ONLY:
        return not windows
    if condition in RESOLVE:
        value = RESOLVE[condition]
        return (not value) if (windows and "WIN32" in condition) else value
    return None


# The two functions Envelock calls from outside the copy must have external linkage; upstream
# declares them static because nothing outside zend_file_cache.c used them.
EXPORTED = ("envelock_file_cache_serialize", "envelock_file_cache_unserialize",
            "envelock_file_cache_serialize_interned", "envelock_file_cache_unserialize_interned")


def unstatic(text):
    for name in EXPORTED:
        text = text.replace("static void %s(" % name, "void %s(" % name)
        text = text.replace("static void *%s(" % name, "void *%s(" % name)
    return text


# Fail closed (ENV-2026-04): a shippable image carries NO interned strings (the loader refuses
# str_size != 0), so an interned-tagged pointer can only come from a malformed image. Resolving it
# as ZCG(mem) + offset (what this used to emit) is an unbounded, attacker-chosen read.
INTERNED_NEW = """void *envelock_file_cache_unserialize_interned(zend_string *str)
{
\t/* A shippable Envelock image carries NO interned strings (the loader refuses str_size != 0), so
\t * an interned-tagged pointer can only come from a malformed image: refuse it rather than resolve
\t * an unbounded, attacker-chosen offset from ZCG(mem) (ENV-2026-04). */
\t(void) str;
\tzend_error_noreturn(E_ERROR, "Envelock: corrupt bytecode image (interned string not allowed)");
\treturn NULL;   /* unreachable: zend_error_noreturn does not return */
}"""


def globals_fixups(text):
    """The few places where an OPcache global has no Envelock counterpart.

    ZCSG(uninitialized_bucket) is OPcache's SHM-resident empty bucket pair. The copy already has
    its own file-static one (upstream declares it in this very file), and the branch that reads it
    is compiled out anyway because the image is never shared.

    The SHM-interning path of zend_file_cache_unserialize_interned goes too: an Envelock image is
    deserialized into one worker's private mapping, so an "interned" string is simply a string in
    that mapping. Keeping the parameter would keep a branch that calls OPcache's interned-string
    allocator and its restart machinery, neither of which means anything here.
    """
    text = text.replace("&ZCSG(uninitialized_bucket)", "uninitialized_bucket")
    text = replace_function(text, "envelock_file_cache_unserialize_interned", INTERNED_NEW)
    text = text.replace("(zend_string*)(ptr), !script->corrupted)", "(zend_string*)(ptr))")
    return text


def replace_function(text, name, replacement):
    """Swap a whole top-level function body. No-op when this file has no such function (the fixups
    run over all three copies); a hard error when it has several, which would mean the detection
    went wrong and the wrong body is about to be replaced."""
    if name not in text:
        return text
    lines = text.splitlines(keepends=True)
    found = [entry for entry in function_ranges(lines) if entry[0] == name]
    if len(found) != 1:
        raise SystemExit(
            "gen_persist: expected exactly one definition of %s, found %d; re-read the upstream "
            "file before regenerating" % (name, len(found)))
    _name, start, end = found[0]
    return "".join(lines[:start]) + replacement + "\n\n" + "".join(lines[end:])




def magic(text):
    return text.replace('memcpy(info->magic, "OPCACHE", 8)',
                        'memcpy(info->magic, "ENVELBC1", 8)') \
               .replace('memcmp(info.magic, "OPCACHE", 8)',
                        'memcmp(info.magic, "ENVELBC1", 8)')


def rename(text):
    for old, new in PREFIX_MAP:
        text = re.sub(r"\b%s\b" % re.escape(old), new, text)
    return text


def transform(source_text, upstream_name, windows):
    body = rewrite(source_text, windows)
    # Order: rename first (so the fixups below can match the Envelock names), then the text-level
    # fixups, then METAINFO on the upstream typedef name, then drop `static` from the entry points.
    body = magic(rename(body))
    body = globals_fixups(body)
    body = unstatic(METAINFO.sub("", body))
    # The preamble ends at the first definition; drop the trailing blank run it leaves behind.
    body = re.sub(r"\n{3,}", "\n\n", body).strip() + "\n"
    return HEADER.format(upstream=upstream_name) + body


TARGETS = (("zend_persist.c", "envelock_persist.c"),
           ("zend_file_cache.c", "envelock_file_cache.c"),
           ("zend_accelerator_util_funcs.c", "envelock_script.c"))

LOUD = """
*************************************************************************************************
* gen_persist.py emits the UPSTREAM deserializer: none of Envelock's hardening (bounds, counts,  *
* tables, opcodes, strings, recursion; audit BC-1..BC-18) is generated. A regenerated layer MUST *
* be re-hardened by hand and pass scripts/check_bc_layers.py before it ships.                    *
*************************************************************************************************
"""


def main():
    args = [argument for argument in sys.argv[1:] if not argument.startswith("--")]
    windows = "--windows" in sys.argv
    force = "--force" in sys.argv
    if len(args) != 2:
        print(__doc__)
        return 2
    php_root = Path(args[0]).resolve()
    version = args[1]
    # The directory name must not contain a dot: PHP's build system derives the object file name
    # from the source path and truncates at the first one ("opcache/8.4/x.c" -> "opcache/8.lo",
    # which collides for every file in the directory). Hence php84, not 8.4.
    out_dir = Path(__file__).resolve().parent / ("php" + version.replace(".", ""))
    print(LOUD, file=sys.stderr)
    existing = [out_dir / target for _upstream, target in TARGETS if (out_dir / target).exists()]
    if existing and not force:
        print("gen_persist: REFUSED: %s already has a layer (%s). Overwriting it would drop its "
              "hand-applied hardening. Re-run with --force only to start a new hardening pass, and "
              "do not ship the result until scripts/check_bc_layers.py passes."
              % (out_dir, ", ".join(p.name for p in existing)), file=sys.stderr)
        return 3
    out_dir.mkdir(parents=True, exist_ok=True)
    for upstream, target in TARGETS:
        source = php_root / "ext" / "opcache" / upstream
        text = source.read_text(encoding="utf-8", errors="replace")
        (out_dir / target).write_text(transform(text, upstream, windows), encoding="utf-8")
        print("wrote", out_dir / target)
    checker = Path(__file__).resolve().parents[2] / "scripts" / "check_bc_layers.py"
    if checker.exists():
        import subprocess
        result = subprocess.run([sys.executable, str(checker)], check=False)
        if result.returncode != 0:
            print("gen_persist: the regenerated layer lacks the hardening listed above; it must not "
                  "ship as is.", file=sys.stderr)
            return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())

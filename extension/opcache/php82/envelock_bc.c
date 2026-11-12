/*
  +----------------------------------------------------------------------+
  | Envelock — bytecode layer (objective O1): public surface             |
  +----------------------------------------------------------------------+
  | Apache License 2.0 (see LICENSE).                                      |
  +----------------------------------------------------------------------+

  Everything the rest of Envelock needs from the persistence layer, in one place:

    envelock_bc_startup/shutdown   module lifetime
    envelock_bc_emit_file          compile a real PHP file and return its image (pack side)
    envelock_bc_load_image[_ex]    turn an image back into a runnable op_array (server side)

  The image is a flat, self-contained buffer: a metainfo record followed by the serialized
  program, where every internal pointer has been rewritten as an offset from the start of the
  buffer. That property is what makes it shippable — no pointers, no shared memory, no file.

  Fail-closed rules, all enforced here:
    * the image carries the Envelock bytecode identity of the build that produced it (PHP version,
      Zend extension build id, data layout, VM kind, op_array extension slots); a mismatch is
      refused before any pointer is rewritten;
    * the image carries an adler32 over its own bytes, checked before deserialization;
    * the deserialized program is marked process-local (script->corrupted = 1), so nothing about
      it ever pretends to live in shared memory;
    * the image carries no JIT state, so the resulting op_array runs on the VM executor.
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#ifndef PHP_WIN32
#include "php_config.h"
#endif
#include <stdlib.h>
#include <stdint.h>

#include "envelock_accel_shim.h"
#include "../../envelock_bc.h"           /* ENVELOCK_BC_SLACK and the public prototypes */

/* Crash-safety guard (internal audit, Nov 2026). The deserializer below validates the image (bounds,
 * counts, tables, opcodes: see ../envelock_bc_harden.h), but it is Zend-internal code and so is the
 * install step that follows. As hard defence in depth the whole load runs under a guard that turns a
 * wild read/write (SIGSEGV/SIGBUS/SIGFPE/SIGILL on POSIX, the matching structured exceptions on
 * Windows) into a clean rejection (return NULL), which the loader reports as "the image does not match
 * this PHP build". The bytecode layer is NTS-only (ENV-2026-03), so a process-global signal handler
 * here is safe: no other thread shares it. */
#ifdef PHP_WIN32
# include <malloc.h>                     /* _resetstkoflw */
#else
# include <signal.h>
# include <setjmp.h>
# define ENVELOCK_BC_ALTSTACK_SIZE (64 * 1024)
static sigjmp_buf envelock_bc_fault_jmp;
static volatile sig_atomic_t envelock_bc_fault_armed;
/* An alternate signal stack, so the handler still runs when the fault IS a main-stack overflow
 * (a corrupted pointer cycle recursing without bound), which is otherwise unrecoverable. */
static char envelock_bc_altstack[ENVELOCK_BC_ALTSTACK_SIZE];
static void envelock_bc_fault_handler(int sig)
{
    if (envelock_bc_fault_armed) {
        envelock_bc_fault_armed = 0;
        siglongjmp(envelock_bc_fault_jmp, 1);
    }
    /* Not from our deserialize window: restore the default disposition and re-raise so the normal
     * crash path runs instead of looping in this handler. */
    signal(sig, SIG_DFL);
    raise(sig);
}
#endif

#include "zend_compile.h"
#include "zend_stream.h"
#include "zend_system_id.h"
#include "zend_extensions.h"
#include "zend_observer.h"
#include "zend_vm.h"
#include "zend_vm_opcodes.h"
#include "zend_gc.h"
#include "zend_constants.h"
#include "zend_execute.h"
#include "ext/standard/php_filestat.h"
#include "ext/standard/md5.h"

#include <string.h>
#if defined(__linux__) || defined(__APPLE__)
# include <sys/mman.h>
# include <unistd.h>
#endif

/* The adapted copy of zend_accelerator_util_funcs.c provides the checksum (and keeps zlib's
 * attribution comment attached to it). */
extern unsigned int zend_adler32(unsigned int checksum, unsigned char *buf, uint32_t len);

/* The metainfo record as it travels. The in-memory struct uses size_t, which is not portable;
 * on the wire every field is a fixed-width big-endian integer, so an image is never ambiguous
 * about the layout it was written with — even though the identity check already refuses any
 * build other than the one that produced it. */
#define ENVELOCK_BC_MAGIC      "ENVELBC1"
#define ENVELOCK_BC_WIRE_SIZE  80
#define ENVELOCK_BC_TAG_SIZE   4
#define ENVELOCK_BC_TAG        "EVB1"

/* Absolute offsets of the wire header. Single source of truth for the layout documented in
 * envelock_bc.h — the reader and the writer must never be allowed to drift apart. */
#define ENVELOCK_BC_OFF_MAGIC          4
#define ENVELOCK_BC_OFF_SYSTEM_ID      12
#define ENVELOCK_BC_SYSTEM_ID_SIZE     32
#define ENVELOCK_BC_OFF_MEM_SIZE       48
#define ENVELOCK_BC_OFF_STR_SIZE       56
#define ENVELOCK_BC_OFF_SCRIPT_OFFSET  64
#define ENVELOCK_BC_OFF_TIMESTAMP      72
#define ENVELOCK_BC_OFF_CHECKSUM       (ENVELOCK_BC_WIRE_SIZE - 4)

#define ENVELOCK_BC_PUT64(p, val) do { \
        uint64_t (v) = (uint64_t) (val); \
        (p)[0] = (unsigned char) (((v) >> 56) & 0xff); \
        (p)[1] = (unsigned char) (((v) >> 48) & 0xff); \
        (p)[2] = (unsigned char) (((v) >> 40) & 0xff); \
        (p)[3] = (unsigned char) (((v) >> 32) & 0xff); \
        (p)[4] = (unsigned char) (((v) >> 24) & 0xff); \
        (p)[5] = (unsigned char) (((v) >> 16) & 0xff); \
        (p)[6] = (unsigned char) (((v) >> 8) & 0xff); \
        (p)[7] = (unsigned char) ((v) & 0xff); \
    } while (0)

#define ENVELOCK_BC_GET64(p) \
    (((uint64_t) (p)[0] << 56) | ((uint64_t) (p)[1] << 48) | ((uint64_t) (p)[2] << 40) | \
     ((uint64_t) (p)[3] << 32) | ((uint64_t) (p)[4] << 24) | ((uint64_t) (p)[5] << 16) | \
     ((uint64_t) (p)[6] << 8) | ((uint64_t) (p)[7]))

#define ENVELOCK_BC_PUT32(p, v) do { \
        (p)[0] = (unsigned char) (((v) >> 24) & 0xff); \
        (p)[1] = (unsigned char) (((v) >> 16) & 0xff); \
        (p)[2] = (unsigned char) (((v) >> 8) & 0xff); \
        (p)[3] = (unsigned char) ((v) & 0xff); \
    } while (0)

#define ENVELOCK_BC_GET32(p) \
    (((uint32_t) (p)[0] << 24) | ((uint32_t) (p)[1] << 16) | \
     ((uint32_t) (p)[2] << 8) | ((uint32_t) (p)[3]))

/* Load stages, for the failure path: a failure while deserializing leaves nothing that points into
 * the buffer; one during install may have published functions and classes that do. */
#define ENVELOCK_BC_STAGE_DESERIALIZE 0
#define ENVELOCK_BC_STAGE_INSTALL     1

void envelock_bc_startup(void)
{
    memset(&envelock_ag, 0, sizeof(envelock_ag));
    memset(&envelock_sag, 0, sizeof(envelock_sag));
    /* Pinned configuration: the persistence code sees "no SHM, no second-level file cache,
     * keep comments, always checksum". These are not INI entries on purpose — an Envelock image
     * must deserialize identically whatever the host has configured for OPcache. */
    ZCG(accel_directives).save_comments = 1;
    ZCG(accel_directives).file_cache = NULL;
    ZCG(accel_directives).file_cache_consistency_checks = 1;
    ZCG(accel_directives).validate_timestamps = 0;
    ZCG(accel_directives).ignore_dups = 0;
    /* The translation table is NOT created here: a non-persistent zend_hash_init() allocates it on
     * the current request heap, and MINIT/MSHUTDOWN run outside any request. Upstream OPcache brackets each
     * persist with init/destroy for exactly this reason, and envelock_bc_emit_file does the same.
     * The arena, by contrast, is a mapping of its own and does belong to the module lifetime. */
}

void envelock_bc_shutdown(void)
{
    envelock_arena_destroy();
}

/* ------------------------------------------------------------------ engine state (BC-1)
 * A rejection must leave the engine exactly as it found it. Two things can unwind out of the middle
 * of a load: a zend_error_noreturn() raised by the deserializer's checks (a bailout, caught below),
 * and a fault caught by the guard (a longjmp/SEH unwind that skips every zend_end_try() in between).
 * The second used to leave EG(bailout) pointing into a dead stack frame, so the NEXT fatal error of
 * the request longjmp'ed into it (0xC0000409 on Windows). Snapshot what either can change and put
 * it back on every rejection. Scalars of engine-defined types are copied as bytes, so the snapshot
 * does not depend on the exact integer type a PHP version gives them. */
typedef struct _envelock_bc_engine_state {
    JMP_BUF *bailout;
    zend_execute_data *current_execute_data;
    zend_string *compiled_filename;
    zend_class_entry *active_class_entry;
    zend_class_entry *current_linking_class;
    unsigned char zend_lineno[8];
    unsigned char in_compilation[8];
    unsigned char unclean_shutdown[8];
    unsigned char memoize_mode[8];
    bool gc_protected;
} envelock_bc_engine_state;

#define ENVELOCK_BC_STASH(buf, lvalue)   memcpy((buf), &(lvalue), sizeof(lvalue))
#define ENVELOCK_BC_UNSTASH(lvalue, buf) memcpy(&(lvalue), (buf), sizeof(lvalue))

static void envelock_bc_save_state(envelock_bc_engine_state *state)
{
    state->bailout = EG(bailout);
    state->current_execute_data = EG(current_execute_data);
    state->compiled_filename = CG(compiled_filename);
    state->active_class_entry = CG(active_class_entry);
    state->current_linking_class = CG(current_linking_class);
    ENVELOCK_BC_STASH(state->zend_lineno, CG(zend_lineno));
    ENVELOCK_BC_STASH(state->in_compilation, CG(in_compilation));
    ENVELOCK_BC_STASH(state->unclean_shutdown, CG(unclean_shutdown));
    ENVELOCK_BC_STASH(state->memoize_mode, CG(memoize_mode));
    state->gc_protected = gc_protected();
}

static void envelock_bc_restore_state(const envelock_bc_engine_state *state)
{
    EG(bailout) = state->bailout;
    EG(current_execute_data) = state->current_execute_data;
    CG(compiled_filename) = state->compiled_filename;
    CG(active_class_entry) = state->active_class_entry;
    CG(current_linking_class) = state->current_linking_class;
    ENVELOCK_BC_UNSTASH(CG(zend_lineno), state->zend_lineno);
    ENVELOCK_BC_UNSTASH(CG(in_compilation), state->in_compilation);
    ENVELOCK_BC_UNSTASH(CG(unclean_shutdown), state->unclean_shutdown);
    ENVELOCK_BC_UNSTASH(CG(memoize_mode), state->memoize_mode);
    gc_protect(state->gc_protected);
}

/* ------------------------------------------------------------------ identity (BC-16)
 * The image used to carry zend_system_id. That id hashes, besides the build, which engine HOOKS the
 * process has installed (zend_ast_process, zend_compile_file, zend_execute_ex, zend_execute_internal,
 * zend_interrupt_function, user opcode handlers) — and the hooks differ between SAPIs of one and the
 * same build: the Windows CLI installs zend_interrupt_function for its Ctrl+C handler
 * (sapi_windows_set_ctrl_handler), php-cgi does not; on Linux a CLI with pcntl does, FPM does not. A
 * CLI-packed image could therefore NEVER load under php-cgi/FPM, the SAPIs it is packed for.
 *
 * None of those hooks changes how a deserialized program is laid out or dispatched: the handler of
 * every opline is re-selected by THIS process' VM (envelock_fc_set_handlers, which also applies this
 * process' user opcode handlers and observer state), internal functions are resolved at run time
 * (ZEND_COMPILE_IGNORE_INTERNAL_FUNCTIONS) and internal classes too (_IGNORE_INTERNAL_CLASSES). What
 * the layout DOES depend on is hashed here instead: the exact running PHP version, the Zend extension
 * build id (API number, NTS/TS, debug, compiler), the data model and the sizes of every structure the
 * image is made of, the VM kind and opcode range, and the number of op_array extension slots (each
 * op_array's run-time cache starts with one slot per handle; a different count would alias them). A
 * development (-dev) engine also gets its zend_system_id, which carries its build date. */
#define ENVELOCK_BC_IDENTITY_TAG "envelock-bytecode-identity/1"

static char envelock_bc_identity_hex[ENVELOCK_BC_SYSTEM_ID_SIZE];
static bool envelock_bc_identity_ready;

static const char *envelock_bc_identity(void)
{
    if (!envelock_bc_identity_ready) {
        static const char hex[] = "0123456789abcdef";
        PHP_MD5_CTX context;
        unsigned char digest[16];
        const char *version = PHP_VERSION;
        zval *runtime = zend_get_constant_str("PHP_VERSION", sizeof("PHP_VERSION") - 1);
        uint32_t facts[] = {
            (uint32_t) sizeof(int), (uint32_t) sizeof(long), (uint32_t) sizeof(size_t),
            (uint32_t) sizeof(zend_long), (uint32_t) ZEND_MM_ALIGNMENT, (uint32_t) sizeof(void *),
            (uint32_t) sizeof(zval), (uint32_t) sizeof(Bucket), (uint32_t) sizeof(HashTable),
            (uint32_t) sizeof(zend_string), (uint32_t) sizeof(zend_op), (uint32_t) sizeof(zend_op_array),
            (uint32_t) sizeof(zend_class_entry), (uint32_t) sizeof(zend_property_info),
            (uint32_t) sizeof(zend_class_constant), (uint32_t) sizeof(zend_arg_info),
            (uint32_t) sizeof(envelock_persistent_script), (uint32_t) ZEND_VM_LAST_OPCODE,
            (uint32_t) zend_vm_kind(), (uint32_t) zend_op_array_extension_handles,
        };
        size_t i;

        if (runtime != NULL && Z_TYPE_P(runtime) == IS_STRING) {
            version = Z_STRVAL_P(runtime);
        }
        PHP_MD5Init(&context);
        PHP_MD5Update(&context, ENVELOCK_BC_IDENTITY_TAG, sizeof(ENVELOCK_BC_IDENTITY_TAG));
        PHP_MD5Update(&context, version, strlen(version) + 1);
        PHP_MD5Update(&context, ZEND_EXTENSION_BUILD_ID, sizeof(ZEND_EXTENSION_BUILD_ID));
        PHP_MD5Update(&context, facts, sizeof(facts));
        if (strstr(version, "-dev") != NULL) {
            PHP_MD5Update(&context, zend_system_id, sizeof(zend_system_id));
        }
        PHP_MD5Final(digest, &context);
        for (i = 0; i < sizeof(digest); i++) {
            envelock_bc_identity_hex[2 * i] = hex[digest[i] >> 4];
            envelock_bc_identity_hex[2 * i + 1] = hex[digest[i] & 0x0f];
        }
        envelock_bc_identity_ready = true;
    }
    return envelock_bc_identity_hex;
}

/* For the test-only diagnostics in envelock_bcpoc.c. */
void envelock_bc_identity_copy(char out[33])
{
    memcpy(out, envelock_bc_identity(), ENVELOCK_BC_SYSTEM_ID_SIZE);
    out[ENVELOCK_BC_SYSTEM_ID_SIZE] = '\0';
}

/* ------------------------------------------------------------------ serialization */

/* Serialize a persisted script into a freshly malloc'd image. Returns its size, or 0 on failure
 * (the caller must then refuse the file rather than fall back to shipping source silently). */
size_t envelock_bc_serialize(envelock_persistent_script *script, unsigned char **out)
{
    envelock_file_cache_metainfo info;
    unsigned char *image;

    if (script == NULL || script->mem == NULL || script->size == 0) {
        return 0;
    }
    /* The checksum covers the program with a 32-bit length (BC-18), and the loader refuses more. */
    if ((uint64_t) script->size > UINT32_MAX || script->size > SIZE_MAX - ENVELOCK_BC_WIRE_SIZE) {
        return 0;
    }
    memset(&info, 0, sizeof(info));
    image = (unsigned char *) malloc(ENVELOCK_BC_WIRE_SIZE + script->size);
    if (image == NULL) {
        return 0;
    }
    envelock_file_cache_serialize(script, &info, image + ENVELOCK_BC_WIRE_SIZE);

    memcpy(image, ENVELOCK_BC_TAG, ENVELOCK_BC_TAG_SIZE);
    memcpy(image + ENVELOCK_BC_OFF_MAGIC, info.magic, 8);
    /* The Envelock identity, not the SAPI-dependent zend_system_id the copy filled in (BC-16). */
    memcpy(image + ENVELOCK_BC_OFF_SYSTEM_ID, envelock_bc_identity(), ENVELOCK_BC_SYSTEM_ID_SIZE);
    memset(image + ENVELOCK_BC_OFF_SYSTEM_ID + ENVELOCK_BC_SYSTEM_ID_SIZE, 0,
           ENVELOCK_BC_OFF_MEM_SIZE - ENVELOCK_BC_OFF_SYSTEM_ID - ENVELOCK_BC_SYSTEM_ID_SIZE);
    ENVELOCK_BC_PUT64(image + ENVELOCK_BC_OFF_MEM_SIZE, (uint64_t) info.mem_size);
    ENVELOCK_BC_PUT64(image + ENVELOCK_BC_OFF_STR_SIZE, (uint64_t) info.str_size);
    ENVELOCK_BC_PUT64(image + ENVELOCK_BC_OFF_SCRIPT_OFFSET, (uint64_t) info.script_offset);
    /* Reserved, and zero on the wire: envelock_bc_emit_file zeroes script->timestamp, so no
     * source mtime ever travels inside an artifact. */
    ENVELOCK_BC_PUT64(image + ENVELOCK_BC_OFF_TIMESTAMP, (uint64_t) info.timestamp);
    /* The checksum covers the image bytes only; the wire header is authenticated by the
     * Ed25519 signature of the container it travels in. */
    ENVELOCK_BC_PUT32(image + ENVELOCK_BC_OFF_CHECKSUM,
                      zend_adler32(1, image + ENVELOCK_BC_WIRE_SIZE, (uint32_t) info.mem_size));
    *out = image;
    return ENVELOCK_BC_WIRE_SIZE + script->size;
}

/* Deserialize an image IN PLACE: the buffer becomes the program's memory. The caller owns the
 * buffer and must keep it alive for as long as the returned script (and everything it points at)
 * is used — in Envelock that is the per-worker cache of objective O9. */
/* CONSUMES ITS INPUT: deserializing rewrites the image in place — the map-ptr slots stop being
 * offsets and become pointers into this request, and the string flags and hashes are reset. An
 * image can therefore be deserialized ONCE. Measured, not inferred: the adler32 stored in the header
 * no longer matches the bytes after a first deserialize. Anything that wants to run the same image
 * again has to start from a pristine copy of it, which is what the O9 cache hands out. */
envelock_persistent_script *envelock_bc_unserialize(unsigned char *image, size_t length)
{
    envelock_persistent_script *script;
    uint64_t mem_size, str_size, script_offset;
    uint32_t checksum;
    volatile bool ok = true;

    if (image == NULL || length <= ENVELOCK_BC_WIRE_SIZE) {
        return NULL;
    }
    if (memcmp(image, ENVELOCK_BC_TAG, ENVELOCK_BC_TAG_SIZE) != 0 ||
        memcmp(image + ENVELOCK_BC_OFF_MAGIC, ENVELOCK_BC_MAGIC, 8) != 0) {
        return NULL;
    }
    /* Version binding, before anything is dereferenced: a bytecode image is only valid for the
     * exact PHP build (and data layout) that produced it, whatever the SAPI (see the identity). */
    if (memcmp(image + ENVELOCK_BC_OFF_SYSTEM_ID, envelock_bc_identity(), ENVELOCK_BC_SYSTEM_ID_SIZE) != 0) {
        return NULL;
    }
    mem_size = ENVELOCK_BC_GET64(image + ENVELOCK_BC_OFF_MEM_SIZE);
    str_size = ENVELOCK_BC_GET64(image + ENVELOCK_BC_OFF_STR_SIZE);
    script_offset = ENVELOCK_BC_GET64(image + ENVELOCK_BC_OFF_SCRIPT_OFFSET);
    checksum = ENVELOCK_BC_GET32(image + ENVELOCK_BC_OFF_CHECKSUM);
    /* mem_size: inside the buffer and representable in the 32-bit checksum length (BC-18).
     * script_offset: the WHOLE script record fits, at its natural alignment (BC-15). */
    if (mem_size == 0 || str_size != 0 ||
        mem_size > (uint64_t) (length - ENVELOCK_BC_WIRE_SIZE) ||
        mem_size > UINT32_MAX ||
        mem_size < sizeof(envelock_persistent_script) ||
        script_offset > mem_size - sizeof(envelock_persistent_script) ||
        script_offset % sizeof(void *) != 0) {
        return NULL;
    }
    if (zend_adler32(1, image + ENVELOCK_BC_WIRE_SIZE, (uint32_t) mem_size) != checksum) {
        return NULL;
    }

    script = (envelock_persistent_script *) (image + ENVELOCK_BC_WIRE_SIZE + script_offset);
    /* Process memory, not SHM: this flag drives the string GC rules in the deserializer. */
    script->corrupted = true;
    /* Internal audit (Nov 2026): the walk's bound is the header mem_size, validated and checksummed
     * above, passed in as a parameter and kept outside the image (BC-5); the record's own field is
     * re-anchored too, for whatever reads it after the walk. */
    script->size = (size_t) mem_size;
    /* Nothing is appended past the image any more (interned strings are refused), but ZCG(mem) keeps
     * pointing at its end, as in OPcache's own process-memory path. */
    ZCG(mem) = (void *) (image + ENVELOCK_BC_WIRE_SIZE + mem_size);

    zend_try {
        envelock_file_cache_unserialize(script, image + ENVELOCK_BC_WIRE_SIZE, (size_t) mem_size);
    } zend_catch {
        ok = false;
    } zend_end_try();
    envelock_file_cache_unserialize_cleanup();
    if (!ok) {
        return NULL;
    }
    /* The record is part of the buffer the walk rewrote: re-assert what the install step reads. */
    script->corrupted = true;
    script->mem = image + ENVELOCK_BC_WIRE_SIZE;
    script->size = (size_t) mem_size;
    return script;
}

/* ------------------------------------------------------------------ pack side */

/* Compile a real file and return its image. Mirrors opcache_compile_file(): the file is compiled
 * with the options a persistable script needs (no constant substitution, delayed binding, no
 * observers), the functions and classes it declares are moved out of the compiler's tables into
 * the script, and the resulting script is persisted into the arena and serialized.
 *
 * The source is compiled here and nowhere else: on the server this path never runs. */
/* Approximate bytes the arena needs to persist ONE op_array. The arena is a fixed bump mapping
 * (OPcache pre-computes the exact size in a calc pass; the layer has no calc pass), so it must be
 * sized up front for everything persisted, not just the top-level op_array — a class with many
 * methods has few top-level opcodes but thousands of method op_arrays. Deliberately generous. */
/* Bytes a literal zval serializes to, counting the CONTENTS of strings and (recursively) arrays.
 * A constant array literal (e.g. a charset table with tens of thousands of entries) or a long string
 * serializes to far more than one zval, so counting it as sizeof(zval) under-sizes the arena and the
 * writer runs past it. */
static size_t envelock_bc_zval_cost(const zval *z)
{
    size_t cost = sizeof(zval) + 32;

    if (Z_TYPE_P(z) == IS_STRING) {
        cost += ZSTR_LEN(Z_STR_P(z)) + 32;
    } else if (Z_TYPE_P(z) == IS_ARRAY) {
        zend_array *ht = Z_ARRVAL_P(z);       /* not const: 8.2's FOREACH macro drops the qualifier */
        zend_string *key;
        zval *val;

        cost += 256 + (size_t) zend_hash_num_elements(ht) * (sizeof(Bucket) + 48);
        ZEND_HASH_FOREACH_STR_KEY_VAL(ht, key, val) {
            if (key != NULL) {
                cost += ZSTR_LEN(key) + 24;
            }
            cost += envelock_bc_zval_cost(val);
        } ZEND_HASH_FOREACH_END();
    }
    return cost;
}

static size_t envelock_bc_op_array_cost(const zend_op_array *op)
{
    size_t cost = 2048;                                           /* struct, name, arg_info, misc */
    uint32_t i;

    cost += (size_t) op->last * (sizeof(zend_op) + 32);           /* opcodes */
    cost += (size_t) op->last_var * 48;                           /* CV names */
    for (i = 0; i < op->last_literal; i++) {                      /* literals, with their contents */
        cost += envelock_bc_zval_cost(&op->literals[i]);
    }
    return cost;
}

/* Size the arena from the whole script: the main op_array, every global user function, and every
 * method of every user class. Iterated with the same bucket walk envelock_script_persist uses.
 *
 * The structural walk below counts opcodes, CV names and literal contents, but NOT every byte the
 * persist writes (constant-expression AST, attribute arguments, type lists, doc comments, and the
 * property-hook op_arrays of PHP 8.4/8.5). Every one of those is source-derived, so its serialized
 * size is bounded by the source size times a small constant. `source_size` is therefore taken as a
 * floor: max(structural, source_size * 32) covers the cases the structural walk under-counts without
 * a version-specific traversal. The mapping is virtual (mmap / VirtualAlloc), so a generous bound
 * costs only address space; the arena refuses to overrun (BC-17) and a trailing guard page backs that
 * up, so a residual under-size fails the emit cleanly instead of shipping stray bytes. */
static size_t envelock_bc_estimate_arena(envelock_persistent_script *script, size_t source_size)
{
    size_t total = envelock_bc_op_array_cost(&script->script.main_op_array);
    size_t floor = source_size * 32;
    Bucket *p;

    ZEND_HASH_MAP_FOREACH_BUCKET(&script->script.function_table, p) {
        zend_function *fn = Z_PTR(p->val);
        if (fn != NULL && fn->type == ZEND_USER_FUNCTION) {
            total += envelock_bc_op_array_cost(&fn->op_array);
        }
    } ZEND_HASH_FOREACH_END();

    ZEND_HASH_MAP_FOREACH_BUCKET(&script->script.class_table, p) {
        zend_class_entry *ce;
        Bucket *m;

        if (Z_TYPE(p->val) == IS_ALIAS_PTR) {
            continue;
        }
        ce = Z_CE(p->val);
        if (ce == NULL || ce->type != ZEND_USER_CLASS) {
            continue;
        }
        total += 8192;                                           /* class: name, props, constants */
        ZEND_HASH_MAP_FOREACH_BUCKET(&ce->function_table, m) {
            zend_function *fn = Z_PTR(m->val);
            if (fn != NULL && fn->type == ZEND_USER_FUNCTION) {
                total += envelock_bc_op_array_cost(&fn->op_array);
            }
        } ZEND_HASH_FOREACH_END();
    } ZEND_HASH_FOREACH_END();

    if (total < floor) {
        total = floor;                                           /* source-derived bytes dominate */
    }
    return total * 2 + (4u << 20);                               /* 2x margin + 4 MB floor */
}

int envelock_bc_emit_file(zend_file_handle *file_handle, unsigned char **image_out,
                          size_t *image_length, const char **error)
{
    envelock_persistent_script *script;
    zend_op_array *volatile op_array = NULL;
    uint32_t orig_functions_count, orig_class_count;
    zend_op_array *orig_active_op_array;
    uint32_t orig_compiler_options;
    void (*orig_execute_internal)(zend_execute_data *execute_data, zval *return_value);
    volatile bool compile_bailed = false;
    size_t length;

    *image_out = NULL;
    *image_length = 0;

    if (file_handle->type == ZEND_HANDLE_FILENAME &&
        zend_stream_open_function(file_handle) != SUCCESS) {
        *error = "cannot open the file";
        return FAILURE;
    }

    orig_active_op_array = CG(active_op_array);
    orig_functions_count = CG(function_table)->nNumUsed;
    orig_class_count = CG(class_table)->nNumUsed;

    orig_compiler_options = CG(compiler_options);
    CG(compiler_options) |= ZEND_COMPILE_HANDLE_OP_ARRAY;
    CG(compiler_options) |= ZEND_COMPILE_DELAYED_BINDING;
    CG(compiler_options) |= ZEND_COMPILE_NO_CONSTANT_SUBSTITUTION;
    CG(compiler_options) |= ZEND_COMPILE_IGNORE_OTHER_FILES;
    CG(compiler_options) |= ZEND_COMPILE_IGNORE_OBSERVER;
    /* The image must not depend on any extension being loaded later: a class baked into the
     * inheritance chain by pointer would dangle on a host without that extension. */
    CG(compiler_options) |= ZEND_COMPILE_IGNORE_INTERNAL_CLASSES;
    /* Same for functions (BC-10): without this a call to an internal function is compiled to
     * INIT_FCALL (or a frameless call, or a specialised opcode), which assumes the function exists
     * because it did at compile time. An image packed where mbstring was loaded then crashed a server
     * without it on the first mb_strlen(). Resolved by name at run time instead, it is a clean
     * "Call to undefined function" there. */
    CG(compiler_options) |= ZEND_COMPILE_IGNORE_INTERNAL_FUNCTIONS;
    /* Constants the engine marks CONST_NO_FILE_CACHE (PHP_SAPI, PHP_BINARY) describe the PROCESS,
     * not the build: never fold the packer's values into the image (BC-16). */
    CG(compiler_options) |= ZEND_COMPILE_WITH_FILE_CACHE;
    /* Compile as if an execute_internal hook were installed. The compiler then emits no frameless
     * calls (ZEND_FRAMELESS_ICALL_*: an index into a process table the deserializer cannot bound,
     * produced for unqualified calls in a namespace even under IGNORE_INTERNAL_FUNCTIONS) and the
     * generic ZEND_DO_FCALL instead of DO_UCALL/DO_ICALL, which skip whatever execute hooks the
     * SERVER has. The image therefore does not depend on the packer's hooks (BC-16), and the loader
     * can refuse frameless opcodes outright (BC-12). execute_internal is the engine's own default,
     * so anything run while compiling behaves exactly as without the hook. */
    orig_execute_internal = zend_execute_internal;
    if (zend_execute_internal == NULL) {
        zend_execute_internal = execute_internal;
    }
    zend_try {
        op_array = zend_compile_file(file_handle, ZEND_INCLUDE);
    } zend_catch {
        compile_bailed = true;
    } zend_end_try();
    zend_execute_internal = orig_execute_internal;
    CG(compiler_options) = orig_compiler_options;
    CG(active_op_array) = orig_active_op_array;
    if (compile_bailed) {
        /* A compile-time fatal: let it end the request, with the engine's options put back. */
        _zend_bailout("envelock_bc.c", __LINE__);
    }

    if (op_array == NULL) {
        *error = "compilation failed";
        return FAILURE;
    }

    script = envelock_create_script();
    if (script == NULL) {
        destroy_op_array(op_array);
        efree(op_array);
        *error = "out of memory";
        return FAILURE;
    }
    script->script.main_op_array = *op_array;
    envelock_move_user_functions(CG(function_table),
                                 CG(function_table)->nNumUsed - orig_functions_count,
                                 &script->script);
    envelock_move_user_classes(CG(class_table),
                               CG(class_table)->nNumUsed - orig_class_count, &script->script);
    envelock_build_delayed_early_binding_list(script);
    script->num_warnings = 0;
    script->warnings = NULL;
    script->timestamp = 0;
    script->script.filename = file_handle->opened_path
        ? zend_string_copy(file_handle->opened_path)
        : zend_string_copy(file_handle->filename);
    zend_string_hash_val(script->script.filename);
    efree(op_array);

    /* Persist into the arena (for_shm = 0: process memory), then serialize out of it. The
     * translation table lives exactly as long as the persist: it is allocated on this request's
     * heap, so it must be destroyed here and not at module shutdown. */
    size_t source_size = 0;
    {
        /* Floor the arena at the source size (see envelock_bc_estimate_arena): bounds the
         * source-derived bytes the structural walk does not count. Best-effort — if the stat fails
         * the structural estimate and the arena's own refusal still apply. */
        zend_stat_t st;
        zend_string *src_path = file_handle->opened_path
            ? file_handle->opened_path : file_handle->filename;
        if (src_path != NULL && zend_stat(ZSTR_VAL(src_path), &st) == 0 && st.st_size > 0) {
            source_size = (size_t) st.st_size;
        }
    }
    envelock_xlat_init();
    envelock_arena_init(envelock_bc_estimate_arena(script, source_size));
    if (envelock_arena_base() == NULL) {
        envelock_xlat_destroy();
        *error = "out of memory for the persistence arena";
        return FAILURE;
    }
    ZCSG(map_ptr_last) = CG(map_ptr_last);
    {
        /* The arena is fail-closed (BC-17): when the estimate is too small it does not return NULL
         * into code that dereferences it, it bails out of the persist. Catch that here and refuse the
         * file. The script is then half moved into the arena; its request-heap leftovers are reclaimed
         * at the end of the request, so nothing of it is touched again. */
        envelock_bc_engine_state state;
        envelock_persistent_script *volatile persisted = NULL;
        volatile bool persist_failed = false;

        envelock_bc_save_state(&state);
        zend_try {
            persisted = envelock_script_persist(script, 0);
        } zend_catch {
            persist_failed = true;
        } zend_end_try();
        if (persist_failed || persisted == NULL) {
            if (persist_failed) {
                envelock_bc_restore_state(&state);
            }
            ZCG(current_persistent_script) = NULL;
            envelock_xlat_destroy();
            envelock_arena_reset();
            *error = envelock_arena_exhausted()
                ? "the persistence arena is too small for this file (refused rather than truncated)"
                : "persistence failed";
            return FAILURE;
        }
        script = persisted;
    }
    /* Never serialize past what the arena really holds: on a host without a guard page an overrun
     * would otherwise copy unrelated heap bytes into the shipped image. */
    if (!envelock_arena_ok()) {
        envelock_xlat_destroy();
        envelock_arena_reset();
        *error = "the persistence arena overflowed (refused rather than shipped)";
        return FAILURE;
    }
    script->size = envelock_arena_used();
    length = envelock_bc_serialize(script, image_out);
    envelock_xlat_destroy();
    envelock_arena_reset();
    if (length == 0) {
        *error = "serialization failed";
        return FAILURE;
    }
    *image_length = length;
    return SUCCESS;
}

/* ------------------------------------------------------------------ server side */

/* Turn an image into a runnable op_array. The image buffer must stay alive for the life of the
 * returned op_array (it holds every structure the program points at), which is why the caller
 * keeps it in the per-worker cache rather than on the stack. */
static zend_op_array *envelock_bc_load_image_inner(unsigned char *image, size_t length,
                                                   volatile int *stage)
{
    envelock_persistent_script *script = envelock_bc_unserialize(image, length);

    if (script == NULL) {
        return NULL;
    }
    /* From here on, functions and classes are published into the engine's tables. */
    *stage = ENVELOCK_BC_STAGE_INSTALL;
    ZCSG(map_ptr_last) = CG(map_ptr_last);
    /* from_shared_memory = 1: the script outlives the call, so the loader must NOT free it. The
     * other value makes envelock_load_script() call envelock_free_script(), which efrees a struct
     * that lives in the image mapping — a guaranteed heap corruption. The flag also registers
     * __COMPILER_HALT_OFFSET__ and grows the map-ptr table, both of which we want. */
    {
        /* A normally-compiled file arms the auto-globals ($_SERVER, $_GET, ...) the first time the
         * compiler sees each one, so the engine populates them for the request. A deserialized
         * op_array never passes through that step: if the first use of an auto-global in a request
         * comes from bytecode inside a function, it would read as null (e.g. WordPress's
         * wp_fix_server_vars(): array_merge($defaults, $_SERVER)). Arm the standard set here, the
         * same restoration OPcache performs from ping_auto_globals_mask when it loads a script. */
        zend_op_array *envelock_loaded = envelock_load_script(script, 1);

        if (envelock_loaded != NULL) {
            zend_is_auto_global_str(ZEND_STRL("_SERVER"));
            zend_is_auto_global_str(ZEND_STRL("_GET"));
            zend_is_auto_global_str(ZEND_STRL("_POST"));
            zend_is_auto_global_str(ZEND_STRL("_COOKIE"));
            zend_is_auto_global_str(ZEND_STRL("_FILES"));
            zend_is_auto_global_str(ZEND_STRL("_ENV"));
            zend_is_auto_global_str(ZEND_STRL("_REQUEST"));
            zend_is_auto_global_str(ZEND_STRL("_SESSION"));
        }
        return envelock_loaded;
    }
}

/* Inside the guard: a bailout (zend_error_noreturn) is caught here, so it can never unwind through
 * the guard with the signal handlers still armed (BC-2). Deserializer rejections are bailouts that
 * envelock_bc_unserialize has already turned into NULL; what reaches this catch is a genuine fatal of
 * the install step (a redeclared class, an inheritance error, memory_limit, an autoloader's fatal),
 * which the caller re-raises once the guard is down. */
static zend_op_array *envelock_bc_guarded(unsigned char *image, size_t length, volatile int *stage,
                                          volatile int *bailed)
{
    zend_op_array *volatile result = NULL;

    zend_try {
        result = envelock_bc_load_image_inner(image, length, stage);
    } zend_catch {
        *bailed = 1;
        result = NULL;
    } zend_end_try();
    return result;
}

#ifdef PHP_WIN32
/* Only the exceptions a wild access or a runaway recursion raise (BC-13). Anything else (a C++
 * exception, a breakpoint, a fail-fast) is not ours to swallow. */
static int envelock_bc_seh_filter(unsigned long code)
{
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:
        case EXCEPTION_IN_PAGE_ERROR:
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        case EXCEPTION_DATATYPE_MISALIGNMENT:
        case EXCEPTION_ILLEGAL_INSTRUCTION:
        case EXCEPTION_PRIV_INSTRUCTION:
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
        case EXCEPTION_INT_OVERFLOW:
        case EXCEPTION_STACK_OVERFLOW:
            return EXCEPTION_EXECUTE_HANDLER;
        default:
            return EXCEPTION_CONTINUE_SEARCH;
    }
}
#endif

/* ---------------------------------------------------------------- failed install (BC-7)
 * A failure after functions and classes were published leaves entries in the engine's tables that
 * point into the buffer the caller is about to give back. Drop every entry that references it: a
 * function whose struct or opcodes live there, a class whose entry or (for a lazily bound copy) whose
 * file name does. The buckets are emptied in place and the hash index rebuilt WITHOUT compaction,
 * because compiled code elsewhere may cache bucket positions of the function table. */
static zend_always_inline bool envelock_bc_in(const void *p, const unsigned char *lo, size_t span)
{
    return (const unsigned char *) p >= lo && (const unsigned char *) p < lo + span;
}

static void envelock_bc_drop_entries(HashTable *ht, const unsigned char *lo, size_t span, bool classes)
{
    uint32_t i;
    bool dropped = false;

    for (i = 0; i < ht->nNumUsed; i++) {
        Bucket *p = ht->arData + i;
        void *ptr;
        bool ours;

        if (Z_TYPE(p->val) != IS_PTR && Z_TYPE(p->val) != IS_ALIAS_PTR) {
            continue;
        }
        ptr = Z_PTR(p->val);
        if (ptr == NULL) {
            continue;
        }
        if (envelock_bc_in(ptr, lo, span)) {
            ours = true;
        } else if (classes) {
            zend_class_entry *ce = (zend_class_entry *) ptr;
            ours = ce->type == ZEND_USER_CLASS && envelock_bc_in(ce->info.user.filename, lo, span);
        } else {
            zend_function *fn = (zend_function *) ptr;
            ours = fn->type == ZEND_USER_FUNCTION && envelock_bc_in(fn->op_array.opcodes, lo, span);
        }
        if (ours) {
            ZVAL_UNDEF(&p->val);
            ht->nNumOfElements--;
            dropped = true;
        }
    }
    if (!dropped) {
        return;
    }
    while (ht->nNumUsed > 0 && Z_TYPE(ht->arData[ht->nNumUsed - 1].val) == IS_UNDEF) {
        ht->nNumUsed--;
    }
    if (ht->nInternalPointer > ht->nNumUsed) {
        ht->nInternalPointer = ht->nNumUsed;
    }
    memset(&HT_HASH(ht, ht->nTableMask), 0xff, HT_HASH_SIZE(ht->nTableMask));
    for (i = 0; i < ht->nNumUsed; i++) {
        Bucket *p = ht->arData + i;
        uint32_t nIndex;

        if (Z_TYPE(p->val) == IS_UNDEF) {
            continue;
        }
        nIndex = (uint32_t) p->h | ht->nTableMask;
        Z_NEXT(p->val) = HT_HASH(ht, nIndex);
        HT_HASH(ht, nIndex) = HT_IDX_TO_HASH(i);
    }
}

static void envelock_bc_rollback(const unsigned char *buffer, size_t span)
{
    envelock_bc_drop_entries(EG(function_table), buffer, span, false);
    envelock_bc_drop_entries(EG(class_table), buffer, span, true);
}

/* Public entry: turn an image into a runnable op_array, under the crash-safety guard, so ANY wild
 * access while deserializing OR installing the program becomes a clean NULL (which the loader reports
 * as "image does not match this build") instead of killing the worker.
 *
 *   image/length  the image; the buffer is length + slack bytes, the slack zero-filled.
 *   slack         CHECKED (BC-15): below ENVELOCK_BC_SLACK the image is refused. The deserializer
 *                 no longer reads past `length` at all; the margin is kept as a contract.
 *   retain        out, may be NULL: on failure, 1 when the install step had started. Then the
 *                 caller must NOT free or scrub the buffer before the end of the request: the
 *                 entries published so far are rolled back, but an observer extension, the CE
 *                 cache of a lazily bound class or a failed autoload may still hold a pointer into
 *                 it. 0: nothing references the buffer, cleanse and free it at will.
 *
 * A genuine PHP fatal raised while installing (redeclared class, inheritance error, memory_limit)
 * is NOT turned into a rejection: once the guard is down it continues as the bailout it is. */
zend_op_array *envelock_bc_load_image_ex(unsigned char *image, size_t length, size_t slack,
                                         int *retain)
{
    envelock_bc_engine_state state;
    zend_op_array *volatile result = NULL;
    volatile int stage = ENVELOCK_BC_STAGE_DESERIALIZE;
    volatile int bailed = 0;
    volatile int faulted = 0;

    if (retain != NULL) {
        *retain = 0;
    }
    if (image == NULL || slack < ENVELOCK_BC_SLACK || length > SIZE_MAX - slack) {
        return NULL;
    }
    envelock_bc_save_state(&state);
#ifdef PHP_WIN32
    {
        volatile unsigned long code = 0;

        __try {
            result = envelock_bc_guarded(image, length, &stage, &bailed);
        } __except (envelock_bc_seh_filter(code = GetExceptionCode())) {
            result = NULL;
            faulted = 1;
        }
        if (faulted && code == EXCEPTION_STACK_OVERFLOW) {
            /* Re-arm the guard page the overflow consumed, or the next one kills the process. */
            _resetstkoflw();
        }
    }
#else
    {
        /* A load can nest (an autoloader run by the install step includes another bytecode file):
         * the inner one keeps the outer's handlers and alternate stack and swaps in its own jump
         * buffer, so a fault is always caught by the innermost load, as SEH does on Windows. */
        int nested = envelock_bc_fault_armed;
        sigjmp_buf outer_jmp;
        struct sigaction sa, old_segv, old_bus, old_fpe, old_ill;
        stack_t ss, old_ss;

        memset(&old_segv, 0, sizeof(old_segv));
        memset(&old_bus, 0, sizeof(old_bus));
        memset(&old_fpe, 0, sizeof(old_fpe));
        memset(&old_ill, 0, sizeof(old_ill));
        memset(&old_ss, 0, sizeof(old_ss));
        if (nested) {
            memcpy(&outer_jmp, &envelock_bc_fault_jmp, sizeof(sigjmp_buf));
        } else {
            ss.ss_sp = envelock_bc_altstack;
            ss.ss_size = sizeof(envelock_bc_altstack);
            ss.ss_flags = 0;
            sigaltstack(&ss, &old_ss);
            sa.sa_handler = envelock_bc_fault_handler;
            sigemptyset(&sa.sa_mask);
            sa.sa_flags = SA_NODEFER | SA_ONSTACK;
            sigaction(SIGSEGV, &sa, &old_segv);
            sigaction(SIGBUS, &sa, &old_bus);
            sigaction(SIGFPE, &sa, &old_fpe);
            sigaction(SIGILL, &sa, &old_ill);
        }
        if (sigsetjmp(envelock_bc_fault_jmp, 1) == 0) {
            envelock_bc_fault_armed = 1;
            result = envelock_bc_guarded(image, length, &stage, &bailed);
        } else {
            result = NULL;              /* a wild read/write (or stack overflow) faulted: reject */
            faulted = 1;
        }
        if (nested) {
            memcpy(&envelock_bc_fault_jmp, &outer_jmp, sizeof(sigjmp_buf));
            envelock_bc_fault_armed = 1;
        } else {
            envelock_bc_fault_armed = 0;
            sigaction(SIGSEGV, &old_segv, NULL);
            sigaction(SIGBUS, &old_bus, NULL);
            sigaction(SIGFPE, &old_fpe, NULL);
            sigaction(SIGILL, &old_ill, NULL);
            sigaltstack(&old_ss, NULL);
        }
    }
#endif
    if (bailed) {
        /* The guard is down and EG(bailout) is the caller's again (zend_end_try restored it). */
        _zend_bailout("envelock_bc.c", __LINE__);
    }
    if (result == NULL) {
        if (faulted) {
            /* the walk's bookkeeping may be half-built: forget it, the request heap reclaims it */
            envelock_file_cache_unserialize_abandon();
        } else {
            envelock_file_cache_unserialize_cleanup();
        }
        envelock_bc_restore_state(&state);
        if (stage == ENVELOCK_BC_STAGE_INSTALL) {
            envelock_bc_rollback(image, length + slack);
            if (retain != NULL) {
                *retain = 1;
            }
        }
    }
    return result;
}

/* Compatible entry for callers that allocate the documented ENVELOCK_BC_SLACK past the image and do
 * not ask whether the buffer may still be referenced. Prefer envelock_bc_load_image_ex(). */
zend_op_array *envelock_bc_load_image(unsigned char *image, size_t length)
{
    return envelock_bc_load_image_ex(image, length, ENVELOCK_BC_SLACK, NULL);
}

/* Keep a deserialized image out of core dumps. The op_array the caller receives points into it,
 * so the mapping lives for the whole process and is never freed. Exported because the loader has
 * one uncached path of its own that needs the same marking. */
void envelock_bc_keep(unsigned char *image, size_t length)
{
#if defined(__linux__) || defined(__APPLE__)
    long page = sysconf(_SC_PAGESIZE);
    size_t span;

    if (page <= 0) {
        return;
    }
    /* Round the start down and the length up: madvise() rejects an unaligned start with EINVAL. */
    span = (((uintptr_t) image & ((uintptr_t) page - 1)) + length + (size_t) page - 1)
        & ~((size_t) page - 1);
    (void) madvise((void *) ((uintptr_t) image & ~((uintptr_t) page - 1)), span, MADV_DONTDUMP);
#else
    (void) image;
    (void) length;
#endif
}

zend_op_array *envelock_bc_adopt(unsigned char *buffer, size_t length, size_t slack)
{
    zend_op_array *op_array;
    int retain = 0;

    if (buffer == NULL) {
        return NULL;
    }
    op_array = envelock_bc_load_image_ex(buffer, length, slack, &retain);
    if (op_array == NULL) {
        if (retain) {
            /* The install had started: something may still point into the buffer (BC-7). It is
             * malloc'd for the process, so leaking it is the safe answer. */
            envelock_bc_keep(buffer, length + slack);
        } else {
            free(buffer);
        }
        return NULL;
    }
    envelock_bc_keep(buffer, length + slack);
    return op_array;
}

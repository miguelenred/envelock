/*
  +----------------------------------------------------------------------+
  | Envelock — bytecode layer (objective O1)                             |
  +----------------------------------------------------------------------+
  | Apache License 2.0 (see LICENSE). Portions of the code that includes |
  | this header are adapted from Zend OPcache, (c) The PHP Group,        |
  | PHP License 3.01 — see NOTICE for the exact provenance.              |
  +----------------------------------------------------------------------+

  Shim over the OPcache internals that the persistence code expects.

  OPcache persists a compiled file into SHARED memory (SHM) and, as a second
  level, into a file (opcache.file_cache). Envelock needs the same persistence
  but into PROCESS memory: the image is serialized, encrypted, shipped, and
  deserialized in place in the worker that runs it. Nothing is ever shared
  between processes and nothing is ever written to disk, so this shim provides
  the handful of globals OPcache reads (ZCG/ZCSG/ZSMMG) backed by Envelock's
  own state instead of by the accelerator's.

  Everything is fail-closed: any state the persistence code would have taken
  from a running OPcache defaults to the "no SHM, process memory only" value,
  which is exactly the mode OPcache itself uses for opcache.file_cache_only.
*/

#ifndef ENVELOCK_ACCEL_SHIM_H
#define ENVELOCK_ACCEL_SHIM_H

#include "php.h"
#include "zend.h"
#include "zend_API.h"

/* ENV-2026-03: the bytecode layer keeps per-process state (the page arena and the ZCG/ZCSG shim
 * globals) in plain process globals, NOT thread-local storage. Two threads in a ZTS SAPI would race on
 * the arena and one could munmap it while another is still reading an op_array out of it. Until that
 * state is made thread-local, refuse to build the layer for a thread-safe engine. A ZTS build must be
 * source-only (config.m4 and the build scripts drop the layer under ZTS; this is the compile backstop). */
#ifdef ZTS
# error "Envelock bytecode layer is not thread-safe (ENV-2026-03): build a non-ZTS (NTS) loader, or build the loader without the bytecode layer for a ZTS SAPI."
#endif
#include "zend_compile.h"
#include "zend_hash.h"
#include "zend_string.h"
#include "zend_types.h"
#include "zend_alloc.h"      /* ZEND_ALIGNED_SIZE */
#include "zend_stream.h"
#include "zend_inheritance.h"
#include "zend_observer.h"
#include "Optimizer/zend_optimizer.h"   /* zend_script: the unit the persistence code works on */

/* zend_early_binding is OPcache's own record (upstream ZendAccelerator.h). It travels inside the
 * serialized image, so its layout is part of Envelock's wire format for a given PHP version. */
typedef struct _zend_early_binding {
    zend_string *lcname;
    zend_string *rtd_key;
    zend_string *lc_parent_name;
    uint32_t cache_slot;
} zend_early_binding;

/* The persisted script: the exact layout OPcache serializes, minus nothing. Keeping the layout
 * identical is what lets the adapted zend_persist/zend_file_cache code stay a faithful copy. */
typedef time_t envelock_accel_time_t;

typedef struct _envelock_persistent_script {
    zend_script    script;
    zend_long      compiler_halt_offset;   /* position of __HALT_COMPILER or -1 */
    int            ping_auto_globals_mask; /* which autoglobals are used by the script */
    envelock_accel_time_t timestamp;       /* the script modification time */
    bool           corrupted;              /* 1 = restored into process memory, not SHM */
    bool           is_phar;
    bool           empty;
    uint32_t       num_warnings;
    uint32_t       num_early_bindings;
    zend_error_info **warnings;
    zend_early_binding *early_bindings;

    void          *mem;                    /* process memory area used by script structures */
    size_t         size;                   /* size of the used area */

    struct envelock_persistent_script_dynamic_members {
        time_t       last_used;
        zend_ulong   hits;
        unsigned int memory_consumption;
        time_t       revalidate;
    } dynamic_members;
} envelock_persistent_script;

/* The persistence code is written against OPcache's globals. These aliases keep the adapted
 * source a near-verbatim copy (auditable line by line against the upstream file) while every
 * access lands on Envelock state. Only the members the code actually reads are provided; the
 * build fails loudly if a future PHP version touches another one. */
typedef struct _envelock_accel_globals {
    /* Arena cursor. During persistence it walks forward inside the arena; during deserialization
     * it points just past the image, where non-interned strings are appended (OPcache does the
     * same: ZCG(mem) = mem + mem_size). */
    void *mem;
    envelock_persistent_script *current_persistent_script;
    /* Deduplication table for persistence: source pointer -> arena pointer. */
    HashTable xlat_table;
    /* Class-inheritance-cache slots reserved during a persist window. Only ever used on the
     * for_shm path, which Envelock never takes; kept because the persistence code reads it. */
    HashTable *pending_ce_cache;
    /* The subset of opcache.* directives the persistence code reads, pinned to the values of the
     * "no SHM, no file cache" configuration. They are constants, not INI entries: Envelock must
     * behave identically whatever the host has configured for OPcache. */
    struct {
        int save_comments;                 /* 1: comments survive into the image */
        char *file_cache;                  /* NULL: no second-level file cache, ever */
        int file_cache_consistency_checks; /* 1: adler32 over the deserialized image */
        int validate_timestamps;           /* 0: the signature covers freshness, not mtime */
        int ignore_dups;                   /* 0: a redeclared class is an error, as in PHP */
    } accel_directives;
    time_t request_time;
    int locked;                            /* OPcache's SHM reentrancy guard; unused here */
} envelock_accel_globals;

typedef struct _envelock_accel_shared_globals {
    /* Inheritance-cache slot watermark. With no SHM there is no cross-process slot table, so the
     * "shared" watermark is simply kept in step with this process's CG(map_ptr_last). */
    uint32_t map_ptr_last;
    uint32_t map_ptr_static_last;
} envelock_accel_shared_globals;

/* The image header, as the adapted serializer writes it (upstream zend_file_cache.c). It lives
 * here because both the serializer and the Envelock surface that ships it need the layout. */
typedef struct _envelock_file_cache_metainfo {
    char           magic[8];
    char           system_id[32];
    size_t         mem_size;
    size_t         str_size;
    size_t         script_offset;
    envelock_accel_time_t timestamp;
    uint32_t       checksum;
} envelock_file_cache_metainfo;

/* Provided by the adapted copy (upstream declares them static; the generator removes it for these
 * two). Declared here because the SERIALIZE_STR/UNSERIALIZE_STR macros in the copy reference them
 * before their definitions. */
void *envelock_file_cache_serialize_interned(zend_string *str,
                                             envelock_file_cache_metainfo *info);
void *envelock_file_cache_unserialize_interned(zend_string *str);

/* Provided by the adapted copy; both are static there, as upstream. */
void envelock_file_cache_serialize(envelock_persistent_script *script,
                                   envelock_file_cache_metainfo *info, void *buf);
/* `size` is the validated header mem_size: the walk is bounded by it, never by script->size
 * (audit BC-5). The walk's bookkeeping is released by _cleanup(), or forgotten by _abandon()
 * after a fault interrupted it. */
void envelock_file_cache_unserialize(envelock_persistent_script *script, void *buf, size_t size);
void envelock_file_cache_unserialize_cleanup(void);
void envelock_file_cache_unserialize_abandon(void);

/* ZEND_ALIGNED_SIZE is OPcache's own macro (upstream zend_shared_alloc.h): the persistence code
 * lays structures out at the platform's natural alignment, and the image must reproduce that
 * layout exactly, so the definition is copied verbatim rather than approximated. */
typedef union _envelock_align_test {
    void *ptr;
    double dbl;
    zend_long lng;
} envelock_align_test;

#if ZEND_GCC_VERSION >= 2000
# define ENVELOCK_PLATFORM_ALIGNMENT \
    (__alignof__(envelock_align_test) < 8 ? 8 : __alignof__(envelock_align_test))
#else
# define ENVELOCK_PLATFORM_ALIGNMENT (sizeof(envelock_align_test))
#endif
#define ZEND_ALIGNED_SIZE(size) ZEND_MM_ALIGNED_SIZE_EX(size, ENVELOCK_PLATFORM_ALIGNMENT)

extern envelock_accel_globals envelock_ag;
extern envelock_accel_shared_globals envelock_sag;

#define ZCG(v)  (envelock_ag.v)
#define ZCSG(v) (envelock_sag.v)
/* OPcache's SHM metrics. There is no shared memory, so nothing is ever "exhausted". */
#define ZSMMG(v) (envelock_smm_shim_##v)
extern int envelock_smm_shim_memory_exhausted;

/* OPcache's own interned-string arena does not exist here. IS_ACCEL_INTERNED therefore answers
 * "no" for every string: all of them go through the serialization string table, which is the safe
 * direction (a false negative costs bytes, a false positive would corrupt the image). */
#define IS_ACCEL_INTERNED(str) (0)

/* The persistence code branches on this global to take the process-memory path. Envelock is
 * always in that path: nothing is shared, so string GC flags and bucket tables follow the
 * process-local rules. */
#define file_cache_only (1)

/* Allocator: a bump arena in process memory, plus the memdup/dedup helpers the persistence code
 * uses. Signatures match OPcache's so the adapted source is unchanged. */
void  envelock_arena_init(size_t size_hint);
void  envelock_arena_reset(void);
void  envelock_arena_destroy(void);
size_t envelock_arena_used(void);
void *envelock_arena_base(void);
/* Fail-closed arena (audit BC-17): exhaustion bails out of the persist (never a NULL handed to
 * code that dereferences it); _check() catches a direct bump past the end, _ok() is asked
 * before anything is serialized out of it. */
bool  envelock_arena_exhausted(void);
bool  envelock_arena_ok(void);
void  envelock_arena_check(void);

void *envelock_alloc(size_t size);
static inline void *envelock_alloc_aligned(size_t size)
{
#if defined(__AVX__) || defined(__SSE2__)
    void *p = envelock_alloc(size + 64);
    if (!p) {
        return NULL;
    }
    return (void *) ((((uintptr_t) p) + 63L) & ~63L);
#else
    return envelock_alloc(size);
#endif
}
void *envelock_memdup_get_put_free(void *source, size_t size);
void *envelock_memdup_put_free(void *source, size_t size);
void *envelock_memdup_free(void *source, size_t size);
void *envelock_memdup_put(void *source, size_t size);
void *envelock_memdup(void *source, size_t size);
int   envelock_memdup_size(void *p, size_t size);

void     envelock_xlat_init(void);
void     envelock_xlat_destroy(void);
void     envelock_xlat_clear(void);
uint32_t envelock_xlat_checkpoint(void);
void     envelock_xlat_restore(uint32_t checkpoint);
void     envelock_xlat_register(const void *key, const void *value);
void    *envelock_xlat_get(const void *key);

/* Is this pointer inside the persistence arena? OPcache asks the shared-memory allocator the same
 * question about its SHM segments. Two call sites matter (a type list and an op_array's static
 * variables): for those, "already persisted" must mean "already in the arena", otherwise the
 * persistence pass would copy a structure it has already copied. The other call sites are
 * short-circuited by the script being process-local. */
bool envelock_in_shm(void *ptr);

/* Replacements for the OPcache helpers the persistence code calls. */
void envelock_accel_error(int level, const char *format, ...);
#define ADLER32_INIT 1     /* initial Adler-32 value (upstream zend_accelerator_util_funcs.h) */
#define ACCEL_LOG_WARNING 3
#define ACCEL_LOG_NOTICE  4
#define ACCEL_LOG_INFO    5
#define ACCEL_LOG_DEBUG   6

/* Process-local script bookkeeping. OPcache keeps restored file-cache scripts in a per-process
 * map so a second request does not deserialize them again; Envelock keeps the same idea in the
 * per-worker cache of objective O9, with the mapping keyed by the blob's SHA-256. */
typedef struct _envelock_script_entry {
    envelock_persistent_script *script;
    void *region;      /* mapping that owns script->mem; never freed while cached */
    size_t region_size;
} envelock_script_entry;

void envelock_bc_startup(void);
void envelock_bc_shutdown(void);

envelock_persistent_script *envelock_create_script(void);
void envelock_free_script(envelock_persistent_script *script, int destroy_elements);
void envelock_move_user_functions(HashTable *src, uint32_t count, zend_script *script);
void envelock_move_user_classes(HashTable *src, uint32_t count, zend_script *script);
envelock_persistent_script *envelock_script_persist(envelock_persistent_script *script,
                                                    int for_shm);
size_t envelock_script_serialize(envelock_persistent_script *script, char **buf_out);
envelock_persistent_script *envelock_script_unserialize(void *buf, size_t buf_size,
                                                        uint32_t script_offset);
zend_op_array *envelock_load_script(envelock_persistent_script *script, int from_shared_memory);
void envelock_build_delayed_early_binding_list(envelock_persistent_script *script);
void envelock_finalize_delayed_early_binding_list(envelock_persistent_script *script);
void envelock_free_delayed_early_binding_list(envelock_persistent_script *script);

/* Pending class-inheritance-cache slots. With no SHM there is no shared slot table to reserve, so
 * these are the no-OPcache equivalents: begin/commit do nothing and a type never gets a map ptr. */
void envelock_pending_ce_cache_begin(void);
void envelock_pending_ce_cache_commit(void);
void envelock_pending_ce_cache_discard(void);
void envelock_get_class_name_map_ptr(zend_string *type_name);

/* Keep a mapping out of core dumps where the system can: Linux has MADV_DONTDUMP; macOS has no
 * equivalent, and there the process-wide hardening (no core dumps, no tracing) still applies. A
 * macro, so its callers keep their line count (__LINE__ is part of their bailouts). */
#if defined(__linux__) || defined(__APPLE__)
# include <sys/mman.h>
#endif
#ifdef MADV_DONTDUMP
# define ENVELOCK_DONTDUMP(addr, len) ((void) madvise((addr), (len), MADV_DONTDUMP))
#else
# define ENVELOCK_DONTDUMP(addr, len) ((void) (addr), (void) (len))
#endif

#endif /* ENVELOCK_ACCEL_SHIM_H */

/*
  +----------------------------------------------------------------------+
  | Envelock — bytecode layer (objective O1): process-memory arena       |
  +----------------------------------------------------------------------+
  | Apache License 2.0 (see LICENSE). The memdup/dedup semantics mirror   |
  | Zend OPcache's zend_shared_alloc.c, (c) The PHP Group, PHP License    |
  | 3.01 — see NOTICE for provenance.                                    |
  +----------------------------------------------------------------------+

  OPcache's persistence code allocates every structure it persists from the shared-memory
  allocator, because the point of OPcache is that N workers share one copy. Envelock has the
  opposite requirement: the persisted image must be private to one worker and must never be
  shared or dumped. So the allocator is replaced by a bump arena in process memory.

  A bump arena is the right shape for this workload (thousands of small, individually-unfreed
  allocations built in one pass, then either serialized or kept for the process lifetime) and it
  keeps the adapted persistence source unchanged: it only ever calls the same five entry points.
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "envelock_accel_shim.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#if defined(__linux__) || defined(__APPLE__)
# include <sys/mman.h>
# include <unistd.h>
#elif defined(PHP_WIN32)
# include <windows.h>
#endif

envelock_accel_globals envelock_ag;
envelock_accel_shared_globals envelock_sag;
int envelock_smm_shim_memory_exhausted = 0;

#define ENVELOCK_ARENA_MIN (1u << 16)

static char *arena_base = NULL;
static size_t arena_capacity = 0;   /* bytes usable by the bump pointer */
static size_t arena_mapped = 0;     /* total mapping length (usable + guard page); 0 = malloc fallback */

void envelock_arena_init(size_t size_hint)
{
    size_t want = size_hint > ENVELOCK_ARENA_MIN ? size_hint : ENVELOCK_ARENA_MIN;

    envelock_smm_shim_memory_exhausted = 0;
    if (arena_base != NULL && arena_capacity >= want) {
        ZCG(mem) = arena_base;
        return;
    }
    envelock_arena_destroy();
#if defined(__linux__) || defined(__APPLE__)
    {
        long pg = sysconf(_SC_PAGESIZE);
        size_t page = (pg > 0) ? (size_t) pg : 4096u;
        size_t usable = (want + page - 1) & ~(page - 1);   /* round up to a page */
        size_t mapped = usable + page;                     /* one PROT_NONE guard page at the end */

        /* A private anonymous mapping rather than the emalloc heap: the image holds the whole program
         * and must stay out of core dumps (MADV_DONTDUMP), which madvise can only do per mapping. */
        arena_base = (char *) mmap(NULL, mapped, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (arena_base == MAP_FAILED) {
            arena_base = NULL;
        } else if (mprotect(arena_base + usable, page, PROT_NONE) != 0) {
            /* Without the guard the arena is unsafe (a mis-sized write would corrupt the heap
             * silently instead of faulting), so refuse the mapping rather than run without it. */
            (void) munmap((void *) arena_base, mapped);
            arena_base = NULL;
        } else {
            (void) madvise((void *) arena_base, usable, MADV_DONTDUMP);
            arena_capacity = usable;
            arena_mapped = mapped;
            ZCG(mem) = arena_base;
            return;
        }
    }
#elif defined(PHP_WIN32)
    {
        /* Same shape on Windows (audit BC-17): a private reservation with one PAGE_NOACCESS guard page
         * at the end, so a direct bump the capacity checks miss faults at pack time instead of
         * writing into the heap behind a malloc'ed block (whose bytes would then be serialized). */
        SYSTEM_INFO si;
        size_t page, usable, mapped;
        DWORD old_protect;

        GetSystemInfo(&si);
        page = si.dwPageSize ? (size_t) si.dwPageSize : 4096u;
        usable = (want + page - 1) & ~(page - 1);
        mapped = usable + page;
        arena_base = (char *) VirtualAlloc(NULL, mapped, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (arena_base != NULL) {
            if (!VirtualProtect(arena_base + usable, page, PAGE_NOACCESS, &old_protect)) {
                (void) VirtualFree(arena_base, 0, MEM_RELEASE);
                arena_base = NULL;
            } else {
                arena_capacity = usable;
                arena_mapped = mapped;
                ZCG(mem) = arena_base;
                return;
            }
        }
    }
#endif
    /* Fallback (no mapping, or the guard page could not be set): plain heap, no guard page. The bump
     * pointer is still bounded by arena_capacity in envelock_alloc and envelock_arena_check. */
    arena_base = (char *) malloc(want);
    if (arena_base == NULL) {
        arena_capacity = 0;
        arena_mapped = 0;
        ZCG(mem) = NULL;
        return;
    }
    arena_capacity = want;
    arena_mapped = 0;
    ZCG(mem) = arena_base;
}

size_t envelock_arena_used(void)
{
    if (arena_base == NULL || ZCG(mem) == NULL) {
        return 0;
    }
    return (size_t) ((char *) ZCG(mem) - arena_base);
}

void *envelock_arena_base(void)
{
    return arena_base;
}

void envelock_arena_destroy(void)
{
    if (arena_base == NULL) {
        return;
    }
#if defined(__linux__) || defined(__APPLE__)
    /* Only munmap what we mmap'ed (usable + guard page): a malloc fallback (arena_mapped == 0) must
     * be freed, not unmapped. The mapping is ours alone; no persisted structure outlives the request
     * that built it. */
    if (arena_mapped != 0) {
        /* arena_base came from mmap, never malloc: calling free() on it corrupts the heap. If munmap
         * fails (practically impossible for a mapping we own), leak the mapping rather than free a
         * pointer the allocator never owned (ENV-2026-04). */
        (void) munmap((void *) arena_base, arena_mapped);
    } else {
        free(arena_base);
    }
#elif defined(PHP_WIN32)
    if (arena_mapped != 0) {
        (void) VirtualFree(arena_base, 0, MEM_RELEASE);
    } else {
        free(arena_base);
    }
#else
    free(arena_base);
#endif
    arena_base = NULL;
    arena_capacity = 0;
    arena_mapped = 0;
    ZCG(mem) = NULL;
}

void envelock_arena_reset(void)
{
    if (arena_base != NULL) {
        ZCG(mem) = arena_base;
    }
}

/* The shared-memory allocator's contract, on the arena. The arena holds ABSOLUTE pointers and the
 * image records offsets from a base captured at the start of persist, so it can NEVER be relocated:
 * growing it (mmap new + memcpy + munmap old) would leave every already-written pointer and the
 * captured base dangling (use-after-munmap on serialize). So the arena is sized up front
 * (envelock_bc_estimate_arena, bounded by the source size) and this allocator is fail-closed: on
 * exhaustion it flags the condition and bails out of the persist, which envelock_bc_emit_file turns
 * into a refusal (audit BC-17: the vendored persistence code dereferences what it gets without a
 * NULL check). The persist's hash-table bumps go through it too; the trailing guard page
 * (PROT_NONE / PAGE_NOACCESS) remains as the last net. */
static ZEND_COLD ZEND_NORETURN void envelock_arena_fail(void)
{
    envelock_smm_shim_memory_exhausted = 1;
    /* Only ever reached from inside envelock_bc_emit_file's zend_try. */
    _zend_bailout("envelock_arena.c", __LINE__);
}

bool envelock_arena_exhausted(void)
{
    return envelock_smm_shim_memory_exhausted != 0;
}

/* A direct bump of ZCG(mem) (alignment, a Zend extension's op_array persist hook) is checked after
 * the fact; the guard page has already stopped any write past the mapping. */
void envelock_arena_check(void)
{
    if (arena_base == NULL || ZCG(mem) == NULL || (char *) ZCG(mem) < arena_base
        || (size_t) ((char *) ZCG(mem) - arena_base) > arena_capacity) {
        envelock_arena_fail();
    }
}

/* Asked before anything is serialized out of the arena: never ship bytes it does not hold. */
bool envelock_arena_ok(void)
{
    return arena_base != NULL && ZCG(mem) != NULL && envelock_smm_shim_memory_exhausted == 0
        && (char *) ZCG(mem) >= arena_base
        && (size_t) ((char *) ZCG(mem) - arena_base) <= arena_capacity;
}

void *envelock_alloc(size_t size)
{
    size_t aligned, used;

    if (arena_base == NULL || ZCG(mem) == NULL) {
        envelock_arena_fail();
    }
    aligned = ZEND_ALIGNED_SIZE(size);
    used = (size_t) ((char *) ZCG(mem) - arena_base);
    /* Overflow-safe fit check (ENV-2026-04): a size near SIZE_MAX makes ZEND_ALIGNED_SIZE wrap to a
     * small value (aligned < size), which the old `ZCG(mem) + aligned` arithmetic would have accepted
     * and then written past the arena. Reject a wrapped alignment, and test the fit by subtraction so
     * no pointer arithmetic can overflow. */
    if (aligned < size || used > arena_capacity || aligned > arena_capacity - used) {
        envelock_arena_fail();
    }
    ZCG(mem) = (void *) (arena_base + used + aligned);
    return (void *) (arena_base + used);
}

bool envelock_in_shm(void *ptr)
{
    return arena_base != NULL
        && (char *) ptr >= arena_base
        && (char *) ptr < arena_base + arena_capacity;
}

static zend_always_inline zend_ulong envelock_rotr3(zend_ulong key)
{
    return (key >> 3) | (key << ((sizeof(key) * 8) - 3));
}

int envelock_memdup_size(void *source, size_t size)
{
    void *old_p;
    zend_ulong key = envelock_rotr3((zend_ulong) source);

    if ((old_p = zend_hash_index_find_ptr(&ZCG(xlat_table), key)) != NULL) {
        return 0; /* already duplicated this pointer */
    }
    zend_hash_index_add_new_ptr(&ZCG(xlat_table), key, source);
    return ZEND_ALIGNED_SIZE(size);
}

static zend_always_inline void *envelock_memdup_ex(void *source, size_t size, bool get_xlat,
                                                   bool set_xlat, bool free_source)
{
    void *old_p, *retval;
    zend_ulong key = 0;

    if (get_xlat) {
        key = envelock_rotr3((zend_ulong) source);
        if ((old_p = zend_hash_index_find_ptr(&ZCG(xlat_table), key)) != NULL) {
            return old_p;
        }
    }
    retval = envelock_alloc(size);
    if (retval == NULL) {
        return NULL;
    }
    memcpy(retval, source, size);
    if (set_xlat) {
        if (!get_xlat) {
            key = envelock_rotr3((zend_ulong) source);
        }
        zend_hash_index_add_new_ptr(&ZCG(xlat_table), key, retval);
    }
    if (free_source) {
        efree(source);
    }
    return retval;
}

void *envelock_memdup_get_put_free(void *source, size_t size)
{
    return envelock_memdup_ex(source, size, true, true, true);
}

void *envelock_memdup_put_free(void *source, size_t size)
{
    return envelock_memdup_ex(source, size, false, true, true);
}

void *envelock_memdup_free(void *source, size_t size)
{
    return envelock_memdup_ex(source, size, false, false, true);
}

void *envelock_memdup_put(void *source, size_t size)
{
    return envelock_memdup_ex(source, size, false, true, false);
}

void *envelock_memdup(void *source, size_t size)
{
    return envelock_memdup_ex(source, size, false, false, false);
}

void envelock_xlat_init(void)
{
    zend_hash_init(&ZCG(xlat_table), 128, NULL, NULL, 0);
}

void envelock_xlat_destroy(void)
{
    zend_hash_destroy(&ZCG(xlat_table));
}

void envelock_xlat_clear(void)
{
    zend_hash_clean(&ZCG(xlat_table));
}

uint32_t envelock_xlat_checkpoint(void)
{
    return ZCG(xlat_table).nNumUsed;
}

void envelock_xlat_restore(uint32_t checkpoint)
{
    zend_hash_discard(&ZCG(xlat_table), checkpoint);
}

void envelock_xlat_register(const void *key_pointer, const void *value)
{
    zend_ulong key = envelock_rotr3((zend_ulong) key_pointer);

    zend_hash_index_add_new_ptr(&ZCG(xlat_table), key, (void *) value);
}

void *envelock_xlat_get(const void *key_pointer)
{
    zend_ulong key = envelock_rotr3((zend_ulong) key_pointer);

    return zend_hash_index_find_ptr(&ZCG(xlat_table), key);
}

/* envelock_pending_ce_cache_* and envelock_get_class_name_map_ptr come from the vendored copy of
 * zend_persist.c, exactly as upstream: they are the class-inheritance-cache slot bookkeeping, and
 * the persistence code only reaches them on the for_shm path, which Envelock never takes. */

/* OPcache logs through its own error_log. Envelock has no log of its own and must not spam the
 * application log from a loader, so persistence warnings are dropped; every condition that must
 * reach the operator is a refusal returned to the caller instead. */
void envelock_accel_error(int level, const char *format, ...)
{
    (void) level;
    (void) format;
}

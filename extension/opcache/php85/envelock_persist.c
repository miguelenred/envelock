/*
  +----------------------------------------------------------------------+
  | Envelock — bytecode layer (objective O1)                             |
  +----------------------------------------------------------------------+
  | GENERATED, THEN HARDENED BY HAND (audit Nov 2026): regenerating      |
  | with gen_persist.py drops the hardening (../envelock_bc_harden.h     |
  | and its call sites); scripts/check_bc_layers.py must pass.           |
  | Regenerate with: python3 extension/opcache/gen_persist.py PHP_SRC VER|
  |                                                                      |
  | Adapted from Zend OPcache's ext/opcache/zend_persist.c                   |
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

/*
   +----------------------------------------------------------------------+
   | Zend OPcache                                                         |
   +----------------------------------------------------------------------+
   | Copyright (c) The PHP Group                                          |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | https://www.php.net/license/3_01.txt                                 |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Authors: Andi Gutmans <andi@php.net>                                 |
   |          Zeev Suraski <zeev@php.net>                                 |
   |          Stanislav Malyshev <stas@zend.com>                          |
   |          Dmitry Stogov <dmitry@php.net>                              |
   +----------------------------------------------------------------------+
*/

#define zend_set_str_gc_flags(str) do { \
	GC_SET_REFCOUNT(str, 2); \
	uint32_t flags = GC_STRING | (ZSTR_IS_VALID_UTF8(str) ? IS_STR_VALID_UTF8 : 0); \
	if (file_cache_only \
	 || (ZCG(current_persistent_script) && ZCG(current_persistent_script)->corrupted)) { \
		GC_TYPE_INFO(str) = GC_STRING | (IS_STR_INTERNED << GC_FLAGS_SHIFT); \
		flags |= (IS_STR_INTERNED << GC_FLAGS_SHIFT); \
	} else { \
		flags |= ((IS_STR_INTERNED | IS_STR_PERMANENT) << GC_FLAGS_SHIFT); \
	} \
	GC_TYPE_INFO(str) = flags; \
} while (0)

#define envelock_store_string(str) do { \
		zend_string *new_str = envelock_xlat_get(str); \
		if (new_str) { \
			zend_string_release_ex(str, 0); \
			str = new_str; \
		} else { \
			new_str = envelock_memdup_put((void*)str, _ZSTR_STRUCT_SIZE(ZSTR_LEN(str))); \
			zend_string_release_ex(str, 0); \
			str = new_str; \
			zend_string_hash_val(str); \
			zend_set_str_gc_flags(str); \
		} \
	} while (0)
#define envelock_memdup_string(str) do { \
		zend_string *new_str = envelock_xlat_get(str); \
		if (new_str) { \
			str = new_str; \
		} else { \
			new_str = envelock_memdup_put((void*)str, _ZSTR_STRUCT_SIZE(ZSTR_LEN(str))); \
			str = new_str; \
			zend_string_hash_val(str); \
			zend_set_str_gc_flags(str); \
		} \
	} while (0)
#define envelock_store_interned_string(str) do { \
		if (!IS_ACCEL_INTERNED(str)) { \
			envelock_store_string(str); \
		} \
	} while (0)
#define envelock_memdup_interned_string(str) do { \
		if (!IS_ACCEL_INTERNED(str)) { \
			envelock_memdup_string(str); \
		} \
	} while (0)

typedef void (*envelock_persist_func_t)(zval*);

static void envelock_persist_zval(zval *z);
static void envelock_persist_op_array(zval *zv);

static const uint32_t uninitialized_bucket[-HT_MIN_MASK] =
	{HT_INVALID_IDX, HT_INVALID_IDX};

static void envelock_hash_persist(HashTable *ht)
{
	uint32_t idx, nIndex;
	Bucket *p;

	HT_FLAGS(ht) |= HASH_FLAG_STATIC_KEYS;
	ht->pDestructor = NULL;
	ht->nInternalPointer = 0;

	if (HT_FLAGS(ht) & HASH_FLAG_UNINITIALIZED) {
		if (EXPECTED(!ZCG(current_persistent_script)->corrupted)) {
			HT_SET_DATA_ADDR(ht, uninitialized_bucket);
		} else {
			HT_SET_DATA_ADDR(ht, &uninitialized_bucket);
		}
		return;
	}
	if (ht->nNumUsed == 0) {
		efree(HT_GET_DATA_ADDR(ht));
		ht->nTableMask = HT_MIN_MASK;
		if (EXPECTED(!ZCG(current_persistent_script)->corrupted)) {
			HT_SET_DATA_ADDR(ht, uninitialized_bucket);
		} else {
			HT_SET_DATA_ADDR(ht, &uninitialized_bucket);
		}
		HT_FLAGS(ht) |= HASH_FLAG_UNINITIALIZED;
		return;
	}
	if (HT_IS_PACKED(ht)) {
		void *data = HT_GET_DATA_ADDR(ht);
		if (GC_FLAGS(ht) & IS_ARRAY_IMMUTABLE) {
			data = envelock_memdup(data, HT_PACKED_USED_SIZE(ht));
		} else {
			data = envelock_memdup_free(data, HT_PACKED_USED_SIZE(ht));
		}
		HT_SET_DATA_ADDR(ht, data);
	} else if (ht->nNumUsed > HT_MIN_SIZE && ht->nNumUsed < (uint32_t)(-(int32_t)ht->nTableMask) / 4) {
		/* compact table */
		void *old_data = HT_GET_DATA_ADDR(ht);
		Bucket *old_buckets = ht->arData;
		uint32_t hash_size;

		hash_size = (uint32_t)(-(int32_t)ht->nTableMask);
		while (hash_size >> 2 > ht->nNumUsed) {
			hash_size >>= 1;
		}
		ht->nTableMask = (uint32_t)(-(int32_t)hash_size);
		ZEND_ASSERT(((uintptr_t)ZCG(mem) & 0x7) == 0); /* should be 8 byte aligned */
		/* Envelock: through the fail-closed allocator, never a raw bump past the arena (BC-17) */
		HT_SET_DATA_ADDR(ht, envelock_alloc((hash_size * sizeof(uint32_t)) + (ht->nNumUsed * sizeof(Bucket))));
		HT_HASH_RESET(ht);
		memcpy(ht->arData, old_buckets, ht->nNumUsed * sizeof(Bucket));
		if (!(GC_FLAGS(ht) & IS_ARRAY_IMMUTABLE)) {
			efree(old_data);
		}

		/* rehash */
		for (idx = 0; idx < ht->nNumUsed; idx++) {
			p = ht->arData + idx;
			if (Z_TYPE(p->val) == IS_UNDEF) continue;
			nIndex = p->h | ht->nTableMask;
			Z_NEXT(p->val) = HT_HASH(ht, nIndex);
			HT_HASH(ht, nIndex) = HT_IDX_TO_HASH(idx);
		}
	} else {
		void *old_data = HT_GET_DATA_ADDR(ht);
		void *data;

		ZEND_ASSERT(((uintptr_t)ZCG(mem) & 0x7) == 0); /* should be 8 byte aligned */
		/* Envelock: through the fail-closed allocator, never a raw bump past the arena (BC-17) */
		data = envelock_alloc(HT_USED_SIZE(ht));
		memcpy(data, old_data, HT_USED_SIZE(ht));
		if (!(GC_FLAGS(ht) & IS_ARRAY_IMMUTABLE)) {
			efree(old_data);
		}
		HT_SET_DATA_ADDR(ht, data);
	}
}

static zend_ast *envelock_persist_ast(zend_ast *ast)
{
	uint32_t i;
	zend_ast *node;

	if (ast->kind == ZEND_AST_ZVAL || ast->kind == ZEND_AST_CONSTANT) {
		zend_ast_zval *copy = envelock_memdup(ast, sizeof(zend_ast_zval));
		envelock_persist_zval(&copy->val);
		node = (zend_ast *) copy;
	} else if (zend_ast_is_list(ast)) {
		zend_ast_list *list = zend_ast_get_list(ast);
		zend_ast_list *copy = envelock_memdup(ast,
			sizeof(zend_ast_list) - sizeof(zend_ast *) + sizeof(zend_ast *) * list->children);
		for (i = 0; i < list->children; i++) {
			if (copy->child[i]) {
				copy->child[i] = envelock_persist_ast(copy->child[i]);
			}
		}
		node = (zend_ast *) copy;
	} else if (ast->kind == ZEND_AST_OP_ARRAY) {
		zend_ast_op_array *copy = envelock_memdup(ast, sizeof(zend_ast_op_array));
		zval z;
		ZVAL_PTR(&z, copy->op_array);
		envelock_persist_op_array(&z);
		copy->op_array = Z_PTR(z);
		node = (zend_ast *) copy;
	} else if (ast->kind == ZEND_AST_CALLABLE_CONVERT) {
		zend_ast_fcc *copy = envelock_memdup(ast, sizeof(zend_ast_fcc));
		if (!ZCG(current_persistent_script)->corrupted) {
			ZEND_MAP_PTR_NEW(copy->fptr);
		}
		node = (zend_ast *) copy;
	} else if (zend_ast_is_decl(ast)) {
		/* Not implemented. */
		ZEND_UNREACHABLE();
	} else {
		uint32_t children = zend_ast_get_num_children(ast);
		node = envelock_memdup(ast, zend_ast_size(children));
		for (i = 0; i < children; i++) {
			if (node->child[i]) {
				node->child[i] = envelock_persist_ast(node->child[i]);
			}
		}
	}

	return node;
}

static void envelock_persist_zval(zval *z)
{
	void *new_ptr;

	switch (Z_TYPE_P(z)) {
		case IS_STRING:
			envelock_store_interned_string(Z_STR_P(z));
			Z_TYPE_FLAGS_P(z) = 0;
			break;
		case IS_ARRAY:
			new_ptr = envelock_xlat_get(Z_ARR_P(z));
			if (new_ptr) {
				Z_ARR_P(z) = new_ptr;
				Z_TYPE_FLAGS_P(z) = 0;
			} else if (!ZCG(current_persistent_script)->corrupted
			 && envelock_in_shm(Z_ARR_P(z))) {
				/* pass */
			} else {
				HashTable *ht;

				if (!Z_REFCOUNTED_P(z)) {
					ht = envelock_memdup_put(Z_ARR_P(z), sizeof(zend_array));
				} else {
					GC_REMOVE_FROM_BUFFER(Z_ARR_P(z));
					ht = envelock_memdup_put_free(Z_ARR_P(z), sizeof(zend_array));
				}
				Z_ARR_P(z) = ht;
				envelock_hash_persist(ht);
				if (HT_IS_PACKED(ht)) {
					zval *zv;

					ZEND_HASH_PACKED_FOREACH_VAL(ht, zv) {
						envelock_persist_zval(zv);
					} ZEND_HASH_FOREACH_END();
				} else {
					Bucket *p;

					ZEND_HASH_MAP_FOREACH_BUCKET(ht, p) {
						if (p->key) {
							envelock_store_interned_string(p->key);
						}
						envelock_persist_zval(&p->val);
					} ZEND_HASH_FOREACH_END();
				}
				/* make immutable array */
				Z_TYPE_FLAGS_P(z) = 0;
				GC_SET_REFCOUNT(Z_COUNTED_P(z), 2);
				GC_ADD_FLAGS(Z_COUNTED_P(z), IS_ARRAY_IMMUTABLE);
			}
			break;
		case IS_CONSTANT_AST:
			new_ptr = envelock_xlat_get(Z_AST_P(z));
			if (new_ptr) {
				Z_AST_P(z) = new_ptr;
				Z_TYPE_FLAGS_P(z) = 0;
			} else if (ZCG(current_persistent_script)->corrupted
			 || !envelock_in_shm(Z_AST_P(z))) {
				zend_ast_ref *old_ref = Z_AST_P(z);
				Z_AST_P(z) = envelock_memdup_put(Z_AST_P(z), sizeof(zend_ast_ref));
				envelock_persist_ast(GC_AST(old_ref));
				Z_TYPE_FLAGS_P(z) = 0;
				GC_SET_REFCOUNT(Z_COUNTED_P(z), 1);
				GC_ADD_FLAGS(Z_COUNTED_P(z), GC_IMMUTABLE);
				efree(old_ref);
			}
			break;
		case IS_PTR:
			break;
		default:
			ZEND_ASSERT(Z_TYPE_P(z) < IS_STRING);
			break;
	}
}

static HashTable *envelock_persist_attributes(HashTable *attributes)
{
	uint32_t i;
	zval *v;

	if (!ZCG(current_persistent_script)->corrupted && envelock_in_shm(attributes)) {
		return attributes;
	}

	/* Attributes for trait properties may be shared if preloading is used. */
	HashTable *xlat = envelock_xlat_get(attributes);
	if (xlat) {
		return xlat;
	}

	envelock_hash_persist(attributes);

	ZEND_HASH_PACKED_FOREACH_VAL(attributes, v) {
		zend_attribute *attr = Z_PTR_P(v);
		zend_attribute *copy = envelock_memdup_put_free(attr, ZEND_ATTRIBUTE_SIZE(attr->argc));

		envelock_store_interned_string(copy->name);
		envelock_store_interned_string(copy->lcname);
		if (copy->validation_error) {
			envelock_store_interned_string(copy->validation_error);
		}

		for (i = 0; i < copy->argc; i++) {
			if (copy->args[i].name) {
				envelock_store_interned_string(copy->args[i].name);
			}
			envelock_persist_zval(&copy->args[i].value);
		}

		ZVAL_PTR(v, copy);
	} ZEND_HASH_FOREACH_END();

	HashTable *ptr = envelock_memdup_put_free(attributes, sizeof(HashTable));
	GC_SET_REFCOUNT(ptr, 2);
	GC_TYPE_INFO(ptr) = GC_ARRAY | ((IS_ARRAY_IMMUTABLE|GC_NOT_COLLECTABLE) << GC_FLAGS_SHIFT);

	return ptr;
}

/* We delay the publishing of CE cache slots until after ZCSG(map_ptr_last) is
 * published.
 * CE cache slots stored in interned strings are immediately visible to other
 * processes, so if we fail to update ZCSG(map_ptr_last) after publishing a
 * slot (due to a bailout/exit), that slot may be re-allocated for something
 * else by other processes. */
void envelock_pending_ce_cache_begin(void)
{
	ZEND_ASSERT(ZCG(locked));

	/* A persist window left through a bailout caught by the caller (e.g.
	 * opcache_compile_file()) never published its slots. Drop them. */
	envelock_pending_ce_cache_discard();

	ZCG(pending_ce_cache) = emalloc(sizeof(HashTable));
	zend_hash_init(ZCG(pending_ce_cache), 8, NULL, NULL, 0);
}

void envelock_pending_ce_cache_commit(void)
{
	ZEND_ASSERT(ZCG(pending_ce_cache));
	/* Every pending slot must be covered by ZCSG(map_ptr_last) */
	ZEND_ASSERT(ZCSG(map_ptr_last) == CG(map_ptr_last));

	ZEND_HASH_FOREACH_NUM_KEY_VAL(ZCG(pending_ce_cache), zend_ulong h, zval *zv) {
		zend_string *type_name = (zend_string*)(uintptr_t)h;

		ZEND_ASSERT(!ZSTR_HAS_CE_CACHE(type_name));
		GC_SET_REFCOUNT(type_name, (uint32_t)Z_LVAL_P(zv));
		GC_ADD_FLAGS(type_name, IS_STR_CLASS_NAME_MAP_PTR);
	} ZEND_HASH_FOREACH_END();

	envelock_pending_ce_cache_discard();
}

void envelock_pending_ce_cache_discard(void)
{
	if (ZCG(pending_ce_cache)) {
		zend_hash_destroy(ZCG(pending_ce_cache));
		efree(ZCG(pending_ce_cache));
		ZCG(pending_ce_cache) = NULL;
	}
}

void envelock_get_class_name_map_ptr(zend_string *type_name)
{
	uint32_t ret;
	zval *slot;

	if (zend_string_equals_ci(type_name, ZSTR_KNOWN(ZEND_STR_SELF)) ||
			zend_string_equals_ci(type_name, ZSTR_KNOWN(ZEND_STR_PARENT))) {
		return;
	}

	/* We use type.name.gc.refcount to keep map_ptr of corresponding type */
	if (ZSTR_HAS_CE_CACHE(type_name)) {
		return;
	}

	if ((GC_FLAGS(type_name) & GC_IMMUTABLE)
	 && (GC_FLAGS(type_name) & IS_STR_PERMANENT)) {
		ZEND_ASSERT(ZCG(pending_ce_cache) && "Must be called inside a persist window");
		slot = zend_hash_index_lookup(ZCG(pending_ce_cache), (zend_ulong)(uintptr_t)type_name);
		if (Z_TYPE_P(slot) != IS_NULL) {
			/* Already allocated earlier in this window */
			return;
		}
		do {
			ret = ZEND_MAP_PTR_NEW_OFFSET();
		} while (ret <= 2);
		ZVAL_LONG(slot, ret);
	}
}

static void envelock_persist_type(zend_type *type) {
	if (ZEND_TYPE_HAS_LIST(*type)) {
		zend_type_list *list = ZEND_TYPE_LIST(*type);
		if (ZEND_TYPE_USES_ARENA(*type) || envelock_in_shm(list)) {
			list = envelock_memdup_put(list, ZEND_TYPE_LIST_SIZE(list->num_types));
			ZEND_TYPE_FULL_MASK(*type) &= ~_ZEND_TYPE_ARENA_BIT;
		} else {
			list = envelock_memdup_put_free(list, ZEND_TYPE_LIST_SIZE(list->num_types));
		}
		ZEND_TYPE_SET_PTR(*type, list);
	}

	zend_type *single_type;
	ZEND_TYPE_FOREACH_MUTABLE(*type, single_type) {
		if (ZEND_TYPE_HAS_LIST(*single_type)) {
			envelock_persist_type(single_type);
			continue;
		}
		if (ZEND_TYPE_HAS_NAME(*single_type)) {
			zend_string *type_name = ZEND_TYPE_NAME(*single_type);
			envelock_store_interned_string(type_name);
			ZEND_TYPE_SET_PTR(*single_type, type_name);
			if (!ZCG(current_persistent_script)->corrupted) {
				envelock_get_class_name_map_ptr(type_name);
			}
		}
	} ZEND_TYPE_FOREACH_END();
}

static void envelock_persist_op_array_ex(zend_op_array *op_array, envelock_persistent_script* main_persistent_script)
{
	zend_op *persist_ptr;
	zval *orig_literals = NULL;

	if (op_array->refcount && --(*op_array->refcount) == 0) {
		efree(op_array->refcount);
	}
	op_array->refcount = NULL;

	if (main_persistent_script) {
		zend_execute_data *orig_execute_data = EG(current_execute_data);
		zend_execute_data fake_execute_data;
		zval *offset;

		memset(&fake_execute_data, 0, sizeof(fake_execute_data));
		fake_execute_data.func = (zend_function*)op_array;
		EG(current_execute_data) = &fake_execute_data;
		if ((offset = zend_get_constant_str("__COMPILER_HALT_OFFSET__", sizeof("__COMPILER_HALT_OFFSET__") - 1)) != NULL) {
			main_persistent_script->compiler_halt_offset = Z_LVAL_P(offset);
		}
		EG(current_execute_data) = orig_execute_data;
	}

	if (op_array->function_name) {
		zend_string *old_name = op_array->function_name;
		envelock_store_interned_string(op_array->function_name);
		/* Remember old function name, so it can be released multiple times if shared. */
		if (op_array->function_name != old_name
				&& !envelock_xlat_get(&op_array->function_name)) {
			envelock_xlat_register(&op_array->function_name, old_name);
		}
	}

	if (op_array->scope) {
		zend_class_entry *scope = envelock_xlat_get(op_array->scope);

		if (scope) {
			op_array->scope = scope;
		}

		if (op_array->prototype) {
			zend_function *ptr = envelock_xlat_get(op_array->prototype);

			if (ptr) {
				op_array->prototype = ptr;
			}
		}

		persist_ptr = envelock_xlat_get(op_array->opcodes);
		if (persist_ptr) {
			op_array->opcodes = persist_ptr;
			if (op_array->static_variables) {
				op_array->static_variables = envelock_xlat_get(op_array->static_variables);
				ZEND_ASSERT(op_array->static_variables != NULL);
			}
			if (op_array->literals) {
				op_array->literals = envelock_xlat_get(op_array->literals);
				ZEND_ASSERT(op_array->literals != NULL);
			}
			if (op_array->filename) {
				op_array->filename = envelock_xlat_get(op_array->filename);
				ZEND_ASSERT(op_array->filename != NULL);
			}
			if (op_array->arg_info) {
				zend_arg_info *arg_info = op_array->arg_info;
				if (op_array->fn_flags & ZEND_ACC_HAS_RETURN_TYPE) {
					arg_info--;
				}
				arg_info = envelock_xlat_get(arg_info);
				ZEND_ASSERT(arg_info != NULL);
				if (op_array->fn_flags & ZEND_ACC_HAS_RETURN_TYPE) {
					arg_info++;
				}
				op_array->arg_info = arg_info;
			}
			if (op_array->live_range) {
				op_array->live_range = envelock_xlat_get(op_array->live_range);
				ZEND_ASSERT(op_array->live_range != NULL);
			}
			if (op_array->doc_comment) {
				if (ZCG(accel_directives).save_comments) {
					op_array->doc_comment = envelock_xlat_get(op_array->doc_comment);
					ZEND_ASSERT(op_array->doc_comment != NULL);
				} else {
					op_array->doc_comment = NULL;
				}
			}
			if (op_array->attributes) {
				op_array->attributes = envelock_xlat_get(op_array->attributes);
				ZEND_ASSERT(op_array->attributes != NULL);
			}

			if (op_array->try_catch_array) {
				op_array->try_catch_array = envelock_xlat_get(op_array->try_catch_array);
				ZEND_ASSERT(op_array->try_catch_array != NULL);
			}
			if (op_array->vars) {
				op_array->vars = envelock_xlat_get(op_array->vars);
				ZEND_ASSERT(op_array->vars != NULL);
			}
			if (op_array->dynamic_func_defs) {
				op_array->dynamic_func_defs = envelock_xlat_get(op_array->dynamic_func_defs);
				ZEND_ASSERT(op_array->dynamic_func_defs != NULL);
			}
			ZCG(mem) = (void*)((char*)ZCG(mem) + ZEND_ALIGNED_SIZE(zend_extensions_op_array_persist(op_array, ZCG(mem))));
			envelock_arena_check();
			return;
		}
	} else {
		/* "prototype" may be undefined if "scope" isn't set */
		op_array->prototype = NULL;
	}

	if (op_array->scope
	 && !(op_array->fn_flags & ZEND_ACC_CLOSURE)
	 && (op_array->scope->ce_flags & ZEND_ACC_CACHED)) {
		return;
	}

	if (op_array->static_variables && !envelock_in_shm(op_array->static_variables)) {
		Bucket *p;

		envelock_hash_persist(op_array->static_variables);
		ZEND_HASH_MAP_FOREACH_BUCKET(op_array->static_variables, p) {
			ZEND_ASSERT(p->key != NULL);
			envelock_store_interned_string(p->key);
			envelock_persist_zval(&p->val);
		} ZEND_HASH_FOREACH_END();
		op_array->static_variables = envelock_memdup_put_free(op_array->static_variables, sizeof(HashTable));
		/* make immutable array */
		GC_SET_REFCOUNT(op_array->static_variables, 2);
		GC_TYPE_INFO(op_array->static_variables) = GC_ARRAY | ((IS_ARRAY_IMMUTABLE|GC_NOT_COLLECTABLE) << GC_FLAGS_SHIFT);
	}

	if (op_array->literals) {
		zval *p, *end;

		orig_literals = op_array->literals;
#if ZEND_USE_ABS_CONST_ADDR
		p = envelock_memdup_put_free(op_array->literals, sizeof(zval) * op_array->last_literal);
#else
		p = envelock_memdup_put(op_array->literals, sizeof(zval) * op_array->last_literal);
#endif
		end = p + op_array->last_literal;
		op_array->literals = p;
		while (p < end) {
			envelock_persist_zval(p);
			p++;
		}
	}

	{
		zend_op *new_opcodes = envelock_memdup_put(op_array->opcodes, sizeof(zend_op) * op_array->last);
		zend_op *opline = new_opcodes;
		zend_op *end = new_opcodes + op_array->last;

		for (; opline < end ; opline++) {
#if ZEND_USE_ABS_CONST_ADDR
			if (opline->op1_type == IS_CONST) {
				opline->op1.zv = (zval*)((char*)opline->op1.zv + ((char*)op_array->literals - (char*)orig_literals));
				if (opline->opcode == ZEND_SEND_VAL
				 || opline->opcode == ZEND_SEND_VAL_EX
				 || opline->opcode == ZEND_QM_ASSIGN) {
					/* Update handlers to eliminate REFCOUNTED check */
					zend_vm_set_opcode_handler_ex(opline, 1 << Z_TYPE_P(opline->op1.zv), 0, 0);
				}
			}
			if (opline->op2_type == IS_CONST) {
				opline->op2.zv = (zval*)((char*)opline->op2.zv + ((char*)op_array->literals - (char*)orig_literals));
			}
#else
			if (opline->op1_type == IS_CONST) {
				opline->op1.constant =
					(char*)(op_array->literals +
						((zval*)((char*)(op_array->opcodes + (opline - new_opcodes)) +
						(int32_t)opline->op1.constant) - orig_literals)) -
					(char*)opline;
				if (opline->opcode == ZEND_SEND_VAL
				 || opline->opcode == ZEND_SEND_VAL_EX
				 || opline->opcode == ZEND_QM_ASSIGN) {
					zend_vm_set_opcode_handler_ex(opline, 0, 0, 0);
				}
			}
			if (opline->op2_type == IS_CONST) {
				opline->op2.constant =
					(char*)(op_array->literals +
						((zval*)((char*)(op_array->opcodes + (opline - new_opcodes)) +
						(int32_t)opline->op2.constant) - orig_literals)) -
					(char*)opline;
			}
#endif
#if ZEND_USE_ABS_JMP_ADDR
			if (op_array->fn_flags & ZEND_ACC_DONE_PASS_TWO) {
				/* fix jumps to point to new array */
				switch (opline->opcode) {
					case ZEND_JMP:
					case ZEND_FAST_CALL:
						opline->op1.jmp_addr = &new_opcodes[opline->op1.jmp_addr - op_array->opcodes];
						break;
					case ZEND_JMPZ:
					case ZEND_JMPNZ:
					case ZEND_JMPZ_EX:
					case ZEND_JMPNZ_EX:
					case ZEND_JMP_SET:
					case ZEND_COALESCE:
					case ZEND_FE_RESET_R:
					case ZEND_FE_RESET_RW:
					case ZEND_ASSERT_CHECK:
					case ZEND_JMP_NULL:
					case ZEND_BIND_INIT_STATIC_OR_JMP:
					case ZEND_JMP_FRAMELESS:
						opline->op2.jmp_addr = &new_opcodes[opline->op2.jmp_addr - op_array->opcodes];
						break;
					case ZEND_CATCH:
						if (!(opline->extended_value & ZEND_LAST_CATCH)) {
							opline->op2.jmp_addr = &new_opcodes[opline->op2.jmp_addr - op_array->opcodes];
						}
						break;
					case ZEND_FE_FETCH_R:
					case ZEND_FE_FETCH_RW:
					case ZEND_SWITCH_LONG:
					case ZEND_SWITCH_STRING:
					case ZEND_MATCH:
						/* relative extended_value don't have to be changed */
						break;
				}
			}
#endif
			if (opline->opcode == ZEND_OP_DATA && (opline-1)->opcode == ZEND_DECLARE_ATTRIBUTED_CONST) {
				zval *literal = RT_CONSTANT(opline, opline->op1);
				HashTable *attributes = Z_PTR_P(literal);
				attributes = envelock_persist_attributes(attributes);
				ZVAL_PTR(literal, attributes);
			}
		}

		efree(op_array->opcodes);
		op_array->opcodes = new_opcodes;
	}

	if (op_array->filename) {
		envelock_store_string(op_array->filename);
	}

	if (op_array->arg_info) {
		zend_arg_info *arg_info = op_array->arg_info;
		uint32_t num_args = op_array->num_args;
		uint32_t i;

		if (op_array->fn_flags & ZEND_ACC_HAS_RETURN_TYPE) {
			arg_info--;
			num_args++;
		}
		if (op_array->fn_flags & ZEND_ACC_VARIADIC) {
			num_args++;
		}
		arg_info = envelock_memdup_put_free(arg_info, sizeof(zend_arg_info) * num_args);
		for (i = 0; i < num_args; i++) {
			if (arg_info[i].name) {
				envelock_store_interned_string(arg_info[i].name);
			}
			envelock_persist_type(&arg_info[i].type);
		}
		if (op_array->fn_flags & ZEND_ACC_HAS_RETURN_TYPE) {
			arg_info++;
		}
		op_array->arg_info = arg_info;
	}

	if (op_array->live_range) {
		op_array->live_range = envelock_memdup_put_free(op_array->live_range, sizeof(zend_live_range) * op_array->last_live_range);
	}

	if (op_array->doc_comment) {
		if (ZCG(accel_directives).save_comments) {
			envelock_store_interned_string(op_array->doc_comment);
		} else {
			zend_string_release_ex(op_array->doc_comment, 0);
			op_array->doc_comment = NULL;
		}
	}

	if (op_array->attributes) {
		op_array->attributes = envelock_persist_attributes(op_array->attributes);
	}

	if (op_array->try_catch_array) {
		op_array->try_catch_array = envelock_memdup_put_free(op_array->try_catch_array, sizeof(zend_try_catch_element) * op_array->last_try_catch);
	}

	if (op_array->vars) {
		int i;
		op_array->vars = envelock_memdup_put_free(op_array->vars, sizeof(zend_string*) * op_array->last_var);
		for (i = 0; i < op_array->last_var; i++) {
			envelock_store_interned_string(op_array->vars[i]);
		}
	}

	if (op_array->num_dynamic_func_defs) {
		op_array->dynamic_func_defs = envelock_memdup_put_free(
			op_array->dynamic_func_defs, sizeof(zend_function *) * op_array->num_dynamic_func_defs);
		for (uint32_t i = 0; i < op_array->num_dynamic_func_defs; i++) {
			zval tmp;
			ZVAL_PTR(&tmp, op_array->dynamic_func_defs[i]);
			envelock_persist_op_array(&tmp);
			op_array->dynamic_func_defs[i] = Z_PTR(tmp);
		}
	}

	ZCG(mem) = (void*)((char*)ZCG(mem) + ZEND_ALIGNED_SIZE(zend_extensions_op_array_persist(op_array, ZCG(mem))));
	envelock_arena_check();
}

static void envelock_persist_op_array(zval *zv)
{
	zend_op_array *op_array = Z_PTR_P(zv);
	zend_op_array *old_op_array;
	ZEND_ASSERT(op_array->type == ZEND_USER_FUNCTION);

	old_op_array = envelock_xlat_get(op_array);
	if (!old_op_array) {
		op_array = Z_PTR_P(zv) = envelock_memdup_put(Z_PTR_P(zv), sizeof(zend_op_array));
		envelock_persist_op_array_ex(op_array, NULL);
		if (!ZCG(current_persistent_script)->corrupted) {
			op_array->fn_flags |= ZEND_ACC_IMMUTABLE;
			ZEND_MAP_PTR_NEW(op_array->run_time_cache);
			if (op_array->static_variables) {
				ZEND_MAP_PTR_NEW(op_array->static_variables_ptr);
			}
		}
	} else {
		/* This can happen during preloading, if a dynamic function definition is declared. */
		Z_PTR_P(zv) = old_op_array;
	}
}

static zend_op_array *envelock_persist_class_method(zend_op_array *op_array, zend_class_entry *ce)
{
	zend_op_array *old_op_array;

	if (op_array->type != ZEND_USER_FUNCTION) {
		ZEND_ASSERT(op_array->type == ZEND_INTERNAL_FUNCTION);
		if (op_array->fn_flags & ZEND_ACC_ARENA_ALLOCATED) {
			old_op_array = envelock_xlat_get(op_array);
			if (old_op_array) {
				return old_op_array;
			} else {
				op_array = envelock_memdup_put(op_array, sizeof(zend_internal_function));
				if (op_array->scope) {
					void *persist_ptr;

					if ((persist_ptr = envelock_xlat_get(op_array->scope))) {
						op_array->scope = (zend_class_entry*)persist_ptr;
					}
					if (op_array->prototype) {
						if ((persist_ptr = envelock_xlat_get(op_array->prototype))) {
							op_array->prototype = (zend_function*)persist_ptr;
						}
					}
				}
				// Real dynamically created internal functions like enum methods must have their own run_time_cache pointer. They're always on the same scope as their defining class.
				// However, copies - as caused by inheritance of internal methods - must retain the original run_time_cache pointer, shared with the source function.
				if (!op_array->scope || (op_array->scope == ce && !(op_array->fn_flags & ZEND_ACC_TRAIT_CLONE))) {
					if (op_array->fn_flags & ZEND_ACC_PRELOADED) {
						ZEND_MAP_PTR_NEW_STATIC(op_array->run_time_cache);
					} else {
						ZEND_MAP_PTR_NEW(op_array->run_time_cache);
					}
				}
			}
		}
		return op_array;
	}

	if ((op_array->fn_flags & ZEND_ACC_IMMUTABLE)
	 && !ZCG(current_persistent_script)->corrupted
	 && envelock_in_shm(op_array)) {
		envelock_xlat_register(op_array, op_array);
		return op_array;
	}

	old_op_array = envelock_xlat_get(op_array);
	if (old_op_array) {
		if (op_array->refcount && --(*op_array->refcount) == 0) {
			efree(op_array->refcount);
		}

		/* If op_array is shared, the function name refcount is still incremented for each use,
		 * so we need to release it here. We remembered the original function name in xlat. */
		zend_string *old_function_name =
			envelock_xlat_get(&old_op_array->function_name);
		if (old_function_name) {
			zend_string_release_ex(old_function_name, 0);
		}
		return old_op_array;
	}

	op_array = envelock_memdup_put(op_array, sizeof(zend_op_array));
	envelock_persist_op_array_ex(op_array, NULL);
	if (ce->ce_flags & ZEND_ACC_IMMUTABLE) {
		op_array->fn_flags |= ZEND_ACC_IMMUTABLE;
		if (ce->ce_flags & ZEND_ACC_LINKED) {
			ZEND_MAP_PTR_NEW(op_array->run_time_cache);
			if (op_array->static_variables) {
				ZEND_MAP_PTR_NEW(op_array->static_variables_ptr);
			}
		} else {
			ZEND_MAP_PTR_INIT(op_array->run_time_cache, NULL);
			ZEND_MAP_PTR_INIT(op_array->static_variables_ptr, NULL);
		}
	}
	return op_array;
}

static zend_property_info *envelock_persist_property_info(zend_property_info *prop)
{
	zend_class_entry *ce;
	prop = envelock_memdup_put(prop, sizeof(zend_property_info));
	ce = envelock_xlat_get(prop->ce);
	if (ce) {
		prop->ce = ce;
	}
	envelock_store_interned_string(prop->name);
	if (prop->doc_comment) {
		if (ZCG(accel_directives).save_comments) {
			envelock_store_interned_string(prop->doc_comment);
		} else {
			if (!envelock_xlat_get(prop->doc_comment)) {
				envelock_xlat_register(prop->doc_comment, prop->doc_comment);
			}
			zend_string_release_ex(prop->doc_comment, 0);
			prop->doc_comment = NULL;
		}
	}
	if (prop->attributes) {
		prop->attributes = envelock_persist_attributes(prop->attributes);
	}
	if (prop->prototype) {
		zend_property_info *new_prototype = (zend_property_info *) envelock_xlat_get(prop->prototype);
		if (new_prototype) {
			prop->prototype = new_prototype;
		}
	}
	if (prop->hooks) {
		prop->hooks = envelock_memdup_put(prop->hooks, ZEND_PROPERTY_HOOK_STRUCT_SIZE);
		for (uint32_t i = 0; i < ZEND_PROPERTY_HOOK_COUNT; i++) {
			if (prop->hooks[i]) {
				zend_op_array *hook = envelock_persist_class_method(&prop->hooks[i]->op_array, ce);
				zend_property_info *new_prop_info = (zend_property_info *) envelock_xlat_get(hook->prop_info);
				if (new_prop_info) {
					hook->prop_info = new_prop_info;
				}
				prop->hooks[i] = (zend_function *) hook;
			}
		}
	}
	envelock_persist_type(&prop->type);
	return prop;
}

static void envelock_persist_class_constant(zval *zv)
{
	zend_class_constant *orig_c = Z_PTR_P(zv);
	zend_class_constant *c = envelock_xlat_get(orig_c);
	zend_class_entry *ce;

	if (c) {
		Z_PTR_P(zv) = c;
		return;
	} else if (((orig_c->ce->ce_flags & ZEND_ACC_IMMUTABLE) && !(Z_CONSTANT_FLAGS(orig_c->value) & CONST_OWNED))
	 || orig_c->ce->type == ZEND_INTERNAL_CLASS) {
		/* Class constant comes from a different file in shm or internal class, keep existing pointer. */
		return;
	} else if (!ZCG(current_persistent_script)->corrupted
	 && envelock_in_shm(Z_PTR_P(zv))) {
		return;
	}
	c = Z_PTR_P(zv) = envelock_memdup_put(Z_PTR_P(zv), sizeof(zend_class_constant));
	envelock_persist_zval(&c->value);
	ce = envelock_xlat_get(c->ce);
	if (ce) {
		c->ce = ce;
	}
	if (c->doc_comment) {
		if (ZCG(accel_directives).save_comments) {
			zend_string *doc_comment = envelock_xlat_get(c->doc_comment);
			if (doc_comment) {
				c->doc_comment = doc_comment;
			} else {
				envelock_store_interned_string(c->doc_comment);
			}
		} else {
			zend_string *doc_comment = envelock_xlat_get(c->doc_comment);
			if (!doc_comment) {
				envelock_xlat_register(c->doc_comment, c->doc_comment);
				zend_string_release_ex(c->doc_comment, 0);
			}
			c->doc_comment = NULL;
		}
	}
	if (c->attributes) {
		c->attributes = envelock_persist_attributes(c->attributes);
	}
	envelock_persist_type(&c->type);
}

zend_class_entry *envelock_persist_class_entry(zend_class_entry *orig_ce)
{
	Bucket *p;
	zend_class_entry *ce = orig_ce;

	if (ce->type == ZEND_USER_CLASS) {
		/* The same zend_class_entry may be reused by class_alias */
		zend_class_entry *new_ce = envelock_xlat_get(ce);
		if (new_ce) {
			return new_ce;
		}
		ce = envelock_memdup_put(ce, sizeof(zend_class_entry));
		if (EXPECTED(!ZCG(current_persistent_script)->corrupted)) {
			ce->ce_flags |= ZEND_ACC_IMMUTABLE;
			if ((ce->ce_flags & ZEND_ACC_LINKED)
			 && !(ce->ce_flags & ZEND_ACC_CONSTANTS_UPDATED)) {
				ZEND_MAP_PTR_NEW(ce->mutable_data);
			} else {
				ZEND_MAP_PTR_INIT(ce->mutable_data, NULL);
			}
		} else {
			ce->ce_flags |= ZEND_ACC_FILE_CACHED;
		}
		ce->inheritance_cache = NULL;

		if (!(ce->ce_flags & ZEND_ACC_CACHED)) {
			if (ZSTR_HAS_CE_CACHE(ce->name)) {
				ZSTR_SET_CE_CACHE_EX(ce->name, NULL, 0);
			}
			envelock_store_interned_string(ce->name);
			if (!(ce->ce_flags & ZEND_ACC_ANON_CLASS)
			 && !ZCG(current_persistent_script)->corrupted) {
				envelock_get_class_name_map_ptr(ce->name);
			}
			if (ce->parent_name && !(ce->ce_flags & ZEND_ACC_LINKED)) {
				envelock_store_interned_string(ce->parent_name);
			}
		}

		envelock_hash_persist(&ce->function_table);
		ZEND_HASH_MAP_FOREACH_BUCKET(&ce->function_table, p) {
			ZEND_ASSERT(p->key != NULL);
			envelock_store_interned_string(p->key);
			Z_PTR(p->val) = envelock_persist_class_method(Z_PTR(p->val), ce);
		} ZEND_HASH_FOREACH_END();
		HT_FLAGS(&ce->function_table) &= (HASH_FLAG_UNINITIALIZED | HASH_FLAG_STATIC_KEYS);
		if (ce->default_properties_table) {
		    int i;

			ce->default_properties_table = envelock_memdup_free(ce->default_properties_table, sizeof(zval) * ce->default_properties_count);
			for (i = 0; i < ce->default_properties_count; i++) {
				envelock_persist_zval(&ce->default_properties_table[i]);
			}
		}
		if (ce->default_static_members_table) {
			int i;
			ce->default_static_members_table = envelock_memdup_free(ce->default_static_members_table, sizeof(zval) * ce->default_static_members_count);

			/* Persist only static properties in this class.
			 * Static properties from parent classes will be handled in class_copy_ctor and are marked with IS_INDIRECT */
			for (i = 0; i < ce->default_static_members_count; i++) {
				if (Z_TYPE(ce->default_static_members_table[i]) != IS_INDIRECT) {
					envelock_persist_zval(&ce->default_static_members_table[i]);
				}
			}
			if (ce->ce_flags & ZEND_ACC_IMMUTABLE) {
				if (ce->ce_flags & ZEND_ACC_LINKED) {
					ZEND_MAP_PTR_NEW(ce->static_members_table);
				} else {
					ZEND_MAP_PTR_INIT(ce->static_members_table, NULL);
				}
			}
		}

		envelock_hash_persist(&ce->constants_table);
		ZEND_HASH_MAP_FOREACH_BUCKET(&ce->constants_table, p) {
			ZEND_ASSERT(p->key != NULL);
			envelock_store_interned_string(p->key);
			envelock_persist_class_constant(&p->val);
		} ZEND_HASH_FOREACH_END();
		HT_FLAGS(&ce->constants_table) &= (HASH_FLAG_UNINITIALIZED | HASH_FLAG_STATIC_KEYS);

		envelock_hash_persist(&ce->properties_info);
		ZEND_HASH_MAP_FOREACH_BUCKET(&ce->properties_info, p) {
			zend_property_info *prop = Z_PTR(p->val);
			ZEND_ASSERT(p->key != NULL);
			envelock_store_interned_string(p->key);
			if (prop->ce == orig_ce) {
				Z_PTR(p->val) = envelock_persist_property_info(prop);
			} else {
				prop = envelock_xlat_get(prop);
				if (prop) {
					Z_PTR(p->val) = prop;
				} else {
					/* This can happen if preloading is used and we inherit a property from an
					 * internal class. In that case we should keep pointing to the internal
					 * property, without any adjustments. */
				}
			}
		} ZEND_HASH_FOREACH_END();
		HT_FLAGS(&ce->properties_info) &= (HASH_FLAG_UNINITIALIZED | HASH_FLAG_STATIC_KEYS);

		if (ce->properties_info_table) {
			int i;

			size_t size = sizeof(zend_property_info *) * ce->default_properties_count;
			ZEND_ASSERT(ce->ce_flags & ZEND_ACC_LINKED);
			ce->properties_info_table = envelock_memdup(
				ce->properties_info_table, size);

			for (i = 0; i < ce->default_properties_count; i++) {
				if (ce->properties_info_table[i]) {
					zend_property_info *prop_info = envelock_xlat_get(
						ce->properties_info_table[i]);
					if (prop_info) {
						ce->properties_info_table[i] = prop_info;
					}
				}
			}
		}

		if (ce->iterator_funcs_ptr) {
			ce->iterator_funcs_ptr = envelock_memdup(ce->iterator_funcs_ptr, sizeof(zend_class_iterator_funcs));
		}
		if (ce->arrayaccess_funcs_ptr) {
			ce->arrayaccess_funcs_ptr = envelock_memdup(ce->arrayaccess_funcs_ptr, sizeof(zend_class_arrayaccess_funcs));
		}

		if (ce->ce_flags & ZEND_ACC_CACHED) {
			return ce;
		}

		ce->ce_flags |= ZEND_ACC_CACHED;

		if (ce->info.user.filename) {
			envelock_store_string(ce->info.user.filename);
		}

		if (ce->doc_comment) {
			if (ZCG(accel_directives).save_comments) {
				envelock_store_interned_string(ce->doc_comment);
			} else {
				if (!envelock_xlat_get(ce->doc_comment)) {
					envelock_xlat_register(ce->doc_comment, ce->doc_comment);
					zend_string_release_ex(ce->doc_comment, 0);
				}
				ce->doc_comment = NULL;
			}
		}

		if (ce->attributes) {
			ce->attributes = envelock_persist_attributes(ce->attributes);
		}

		if (ce->num_interfaces && !(ce->ce_flags & ZEND_ACC_LINKED)) {
			uint32_t i = 0;

			for (i = 0; i < ce->num_interfaces; i++) {
				envelock_store_interned_string(ce->interface_names[i].name);
				envelock_store_interned_string(ce->interface_names[i].lc_name);
			}
			ce->interface_names = envelock_memdup_free(ce->interface_names, sizeof(zend_class_name) * ce->num_interfaces);
		}

		if (ce->num_traits) {
			uint32_t i = 0;

			for (i = 0; i < ce->num_traits; i++) {
				envelock_store_interned_string(ce->trait_names[i].name);
				envelock_store_interned_string(ce->trait_names[i].lc_name);
			}
			ce->trait_names = envelock_memdup_free(ce->trait_names, sizeof(zend_class_name) * ce->num_traits);

			i = 0;
			if (ce->trait_aliases) {
				while (ce->trait_aliases[i]) {
					if (ce->trait_aliases[i]->trait_method.method_name) {
						envelock_store_interned_string(ce->trait_aliases[i]->trait_method.method_name);
					}
					if (ce->trait_aliases[i]->trait_method.class_name) {
						envelock_store_interned_string(ce->trait_aliases[i]->trait_method.class_name);
					}

					if (ce->trait_aliases[i]->alias) {
						envelock_store_interned_string(ce->trait_aliases[i]->alias);
					}

					ce->trait_aliases[i] = envelock_memdup_free(ce->trait_aliases[i], sizeof(zend_trait_alias));
					i++;
				}

				ce->trait_aliases = envelock_memdup_free(ce->trait_aliases, sizeof(zend_trait_alias*) * (i + 1));
			}

			if (ce->trait_precedences) {
				uint32_t j;

				i = 0;
				while (ce->trait_precedences[i]) {
					envelock_store_interned_string(ce->trait_precedences[i]->trait_method.method_name);
					envelock_store_interned_string(ce->trait_precedences[i]->trait_method.class_name);

					for (j = 0; j < ce->trait_precedences[i]->num_excludes; j++) {
						envelock_store_interned_string(ce->trait_precedences[i]->exclude_class_names[j]);
					}

					ce->trait_precedences[i] = envelock_memdup_free(ce->trait_precedences[i], sizeof(zend_trait_precedence) + (ce->trait_precedences[i]->num_excludes - 1) * sizeof(zend_string*));
					i++;
				}
				ce->trait_precedences = envelock_memdup_free(
					ce->trait_precedences, sizeof(zend_trait_precedence*) * (i + 1));
			}
		}

		ZEND_ASSERT(ce->backed_enum_table == NULL);
	}

	return ce;
}

void envelock_update_parent_ce(zend_class_entry *ce)
{
	if (ce->ce_flags & ZEND_ACC_LINKED) {
		if (ce->parent) {
			int i, end;
			zend_class_entry *parent = ce->parent;

			if (parent->type == ZEND_USER_CLASS) {
				zend_class_entry *p = envelock_xlat_get(parent);

				if (p) {
					ce->parent = parent = p;
				}
			}

			/* Create indirections to static properties from parent classes */
			i = parent->default_static_members_count - 1;
			while (parent && parent->default_static_members_table) {
				end = parent->parent ? parent->parent->default_static_members_count : 0;
				for (; i >= end; i--) {
					zval *p = &ce->default_static_members_table[i];
					/* The static property may have been overridden by a trait
					 * during inheritance. In that case, the property default
					 * value is replaced by zend_declare_typed_property() at the
					 * property index of the parent property. Make sure we only
					 * point to the parent property value if the child value was
					 * already indirect. */
					if (Z_TYPE_P(p) == IS_INDIRECT) {
						ZVAL_INDIRECT(p, &parent->default_static_members_table[i]);
					}
				}

				parent = parent->parent;
			}
		}

		if (ce->num_interfaces) {
			uint32_t i = 0;

			ce->interfaces = envelock_memdup_free(ce->interfaces, sizeof(zend_class_entry*) * ce->num_interfaces);
			for (i = 0; i < ce->num_interfaces; i++) {
				if (ce->interfaces[i]->type == ZEND_USER_CLASS) {
					zend_class_entry *tmp = envelock_xlat_get(ce->interfaces[i]);
					if (tmp != NULL) {
						ce->interfaces[i] = tmp;
					}
				}
			}
		}

		if (ce->iterator_funcs_ptr) {
			memset(ce->iterator_funcs_ptr, 0, sizeof(zend_class_iterator_funcs));
			if (zend_class_implements_interface(ce, zend_ce_aggregate)) {
				ce->iterator_funcs_ptr->zf_new_iterator = zend_hash_str_find_ptr(&ce->function_table, "getiterator", sizeof("getiterator") - 1);
			}
			if (zend_class_implements_interface(ce, zend_ce_iterator)) {
				ce->iterator_funcs_ptr->zf_rewind = zend_hash_str_find_ptr(&ce->function_table, "rewind", sizeof("rewind") - 1);
				ce->iterator_funcs_ptr->zf_valid = zend_hash_str_find_ptr(&ce->function_table, "valid", sizeof("valid") - 1);
				ce->iterator_funcs_ptr->zf_key = zend_hash_find_ptr(&ce->function_table, ZSTR_KNOWN(ZEND_STR_KEY));
				ce->iterator_funcs_ptr->zf_current = zend_hash_str_find_ptr(&ce->function_table, "current", sizeof("current") - 1);
				ce->iterator_funcs_ptr->zf_next = zend_hash_str_find_ptr(&ce->function_table, "next", sizeof("next") - 1);
			}
		}

		if (ce->arrayaccess_funcs_ptr) {
			ZEND_ASSERT(zend_class_implements_interface(ce, zend_ce_arrayaccess));
			ce->arrayaccess_funcs_ptr->zf_offsetget = zend_hash_str_find_ptr(&ce->function_table, "offsetget", sizeof("offsetget") - 1);
			ce->arrayaccess_funcs_ptr->zf_offsetexists = zend_hash_str_find_ptr(&ce->function_table, "offsetexists", sizeof("offsetexists") - 1);
			ce->arrayaccess_funcs_ptr->zf_offsetset = zend_hash_str_find_ptr(&ce->function_table, "offsetset", sizeof("offsetset") - 1);
			ce->arrayaccess_funcs_ptr->zf_offsetunset = zend_hash_str_find_ptr(&ce->function_table, "offsetunset", sizeof("offsetunset") - 1);
		}
	}

	/* update methods */
	if (ce->constructor) {
		zend_function *tmp = envelock_xlat_get(ce->constructor);
		if (tmp != NULL) {
			ce->constructor = tmp;
		}
	}
	if (ce->destructor) {
		zend_function *tmp = envelock_xlat_get(ce->destructor);
		if (tmp != NULL) {
			ce->destructor = tmp;
		}
	}
	if (ce->clone) {
		zend_function *tmp = envelock_xlat_get(ce->clone);
		if (tmp != NULL) {
			ce->clone = tmp;
		}
	}
	if (ce->__get) {
		zend_function *tmp = envelock_xlat_get(ce->__get);
		if (tmp != NULL) {
			ce->__get = tmp;
		}
	}
	if (ce->__set) {
		zend_function *tmp = envelock_xlat_get(ce->__set);
		if (tmp != NULL) {
			ce->__set = tmp;
		}
	}
	if (ce->__call) {
		zend_function *tmp = envelock_xlat_get(ce->__call);
		if (tmp != NULL) {
			ce->__call = tmp;
		}
	}
	if (ce->__serialize) {
		zend_function *tmp = envelock_xlat_get(ce->__serialize);
		if (tmp != NULL) {
			ce->__serialize = tmp;
		}
	}
	if (ce->__unserialize) {
		zend_function *tmp = envelock_xlat_get(ce->__unserialize);
		if (tmp != NULL) {
			ce->__unserialize = tmp;
		}
	}
	if (ce->__isset) {
		zend_function *tmp = envelock_xlat_get(ce->__isset);
		if (tmp != NULL) {
			ce->__isset = tmp;
		}
	}
	if (ce->__unset) {
		zend_function *tmp = envelock_xlat_get(ce->__unset);
		if (tmp != NULL) {
			ce->__unset = tmp;
		}
	}
	if (ce->__tostring) {
		zend_function *tmp = envelock_xlat_get(ce->__tostring);
		if (tmp != NULL) {
			ce->__tostring = tmp;
		}
	}
	if (ce->__callstatic) {
		zend_function *tmp = envelock_xlat_get(ce->__callstatic);
		if (tmp != NULL) {
			ce->__callstatic = tmp;
		}
	}
	if (ce->__debugInfo) {
		zend_function *tmp = envelock_xlat_get(ce->__debugInfo);
		if (tmp != NULL) {
			ce->__debugInfo = tmp;
		}
	}
}

static void envelock_persist_class_table(HashTable *class_table)
{
	Bucket *p;
	zend_class_entry *ce;
	envelock_hash_persist(class_table);
	ZEND_HASH_MAP_FOREACH_BUCKET(class_table, p) {
		ZEND_ASSERT(p->key != NULL);
		envelock_store_interned_string(p->key);
		Z_CE(p->val) = envelock_persist_class_entry(Z_CE(p->val));
	} ZEND_HASH_FOREACH_END();
	ZEND_HASH_MAP_FOREACH_BUCKET(class_table, p) {
		if (EXPECTED(Z_TYPE(p->val) != IS_ALIAS_PTR)) {
			ce = Z_PTR(p->val);
			envelock_update_parent_ce(ce);
		}
	} ZEND_HASH_FOREACH_END();
}

zend_error_info **envelock_persist_warnings(uint32_t num_warnings, zend_error_info **warnings) {
	if (warnings) {
		warnings = envelock_memdup(warnings, num_warnings * sizeof(zend_error_info *));
		for (uint32_t i = 0; i < num_warnings; i++) {
			envelock_store_string(warnings[i]->filename);
			envelock_store_string(warnings[i]->message);
			warnings[i] = envelock_memdup(warnings[i], sizeof(zend_error_info));
		}
	}
	return warnings;
}

static zend_early_binding *envelock_persist_early_bindings(
		uint32_t num_early_bindings, zend_early_binding *early_bindings) {
	if (early_bindings) {
		early_bindings = envelock_memdup_free(
			early_bindings, num_early_bindings * sizeof(zend_early_binding));
		for (uint32_t i = 0; i < num_early_bindings; i++) {
			envelock_store_interned_string(early_bindings[i].lcname);
			envelock_store_interned_string(early_bindings[i].rtd_key);
			envelock_store_interned_string(early_bindings[i].lc_parent_name);
		}
	}
	return early_bindings;
}

envelock_persistent_script *envelock_script_persist(envelock_persistent_script *script, int for_shm)
{
	Bucket *p;

	script->mem = ZCG(mem);

	ZEND_ASSERT(((uintptr_t)ZCG(mem) & 0x7) == 0); /* should be 8 byte aligned */

	script = envelock_memdup_free(script, sizeof(envelock_persistent_script));
	script->corrupted = false;
	ZCG(current_persistent_script) = script;

	if (!for_shm) {
		/* script is not going to be saved in SHM */
		script->corrupted = true;
	}

	envelock_store_interned_string(script->script.filename);

#if defined(__AVX__) || defined(__SSE2__)
	/* Align to 64-byte boundary */
	ZCG(mem) = (void*)(((uintptr_t)ZCG(mem) + 63L) & ~63L);
	envelock_arena_check();
#else
	ZEND_ASSERT(((uintptr_t)ZCG(mem) & 0x7) == 0); /* should be 8 byte aligned */
#endif

	zend_map_ptr_extend(ZCSG(map_ptr_last));
	if (for_shm) {
		envelock_pending_ce_cache_begin();
	}

	envelock_persist_class_table(&script->script.class_table);
	envelock_hash_persist(&script->script.function_table);
	ZEND_HASH_MAP_FOREACH_BUCKET(&script->script.function_table, p) {
		ZEND_ASSERT(p->key != NULL);
		envelock_store_interned_string(p->key);
		envelock_persist_op_array(&p->val);
	} ZEND_HASH_FOREACH_END();
	envelock_persist_op_array_ex(&script->script.main_op_array, script);
	if (!script->corrupted) {
		ZEND_MAP_PTR_INIT(script->script.main_op_array.run_time_cache, NULL);
		if (script->script.main_op_array.static_variables) {
			ZEND_MAP_PTR_NEW(script->script.main_op_array.static_variables_ptr);
		}
	}
	script->warnings = envelock_persist_warnings(script->num_warnings, script->warnings);
	script->early_bindings = envelock_persist_early_bindings(
		script->num_early_bindings, script->early_bindings);

	if (for_shm) {
		ZCSG(map_ptr_last) = CG(map_ptr_last);
		ZCSG(map_ptr_static_last) = zend_map_ptr_static_last;
		envelock_pending_ce_cache_commit();
	}

	script->corrupted = false;
	ZCG(current_persistent_script) = NULL;

	return script;
}

/*
  +----------------------------------------------------------------------+
  | Envelock — PHP source protection.                                    |
  | Apache License 2.0 (see LICENSE).                                    |
  +----------------------------------------------------------------------+
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "ext/standard/base64.h"
#include "zend_exceptions.h"
#include "zend_API.h"

#include <string.h>

/* "do not inline this" — portable: GCC/Clang spell it with __attribute__, MSVC with __declspec. */
#if defined(_MSC_VER)
# define ENVELOCK_NOINLINE __declspec(noinline)
#else
# define ENVELOCK_NOINLINE __attribute__((noinline))
#endif

/* Objective O4: the mini-VM.
 *
 * A function marked for virtualization ships as this instruction stream instead of as a
 * zend_op_array, so its logic is not present in the process as standard PHP opcodes and does not
 * appear as such in a dump of the compiled code.
 *
 * THE DESIGN CHOICE THAT MAKES THIS SAFE: every operation is delegated to Zend's own operator
 * function (add_function, is_equal_function, concat_function, ...). The VM decides WHAT to compute
 * and in what order; PHP decides what `+` or `==` mean. Re-implementing PHP's arithmetic here —
 * its string-to-number coercion, its loose comparison, its int-to-float promotion — would be where
 * a mini-VM quietly started disagreeing with the language, and a protector that changes behaviour
 * is worse than no protector.
 *
 * The instruction set is closed and small; the encoder refuses to compile anything outside it
 * rather than approximating it. See encoder/virtualize.php for the subset.
 */

/* Opcodes. Shared with encoder/virtualize.php; both sides must agree. */
#define ENVELOCK_VM_PUSH_CONST   0x01   /* u16 constant index */
#define ENVELOCK_VM_PUSH_LOCAL   0x02   /* u16 local index */
#define ENVELOCK_VM_STORE_LOCAL  0x03   /* u16 local index (pops) */
#define ENVELOCK_VM_BINARY       0x04   /* u8 operator id */
#define ENVELOCK_VM_UNARY        0x05   /* u8 operator id */
#define ENVELOCK_VM_JMP          0x06   /* i32 relative */
#define ENVELOCK_VM_JMP_FALSE    0x07   /* i32 relative (pops) */
#define ENVELOCK_VM_CALL         0x08   /* u16 name index, u8 argc */
#define ENVELOCK_VM_INIT_CALL    0x16   /* u16 name index, u8 argc: checks the callee before its arguments run */
#define ENVELOCK_VM_RETURN       0x09
#define ENVELOCK_VM_FETCH_DIM_R  0x0A   /* pops index then array, pushes the element */
#define ENVELOCK_VM_ARRAY        0x0B   /* u16 count: pops count values, pushes a list */
#define ENVELOCK_VM_POP          0x0C
#define ENVELOCK_VM_DUP          0x0D
#define ENVELOCK_VM_RETURN_NULL  0x0E
#define ENVELOCK_VM_SWAP         0x12   /* exchanges the two top values: lazy local reads */
#define ENVELOCK_VM_FETCH_DIM_N  0x13   /* u8 n: container below n keys, reads them in order */
#define ENVELOCK_VM_FETCH_DIM_LOCAL 0x14 /* u16 local, u8 n: keys on the stack, container read as a
                                          * local at the fetch, as Zend's CV operands are */
#define ENVELOCK_VM_FETCH_DIM_MIXED 0x15 /* variable length: u8 count, u8 flags (bit 0: u16 local container),
                                          * then per key u8 tag: 0 = key on the stack, 1 = u16 local read at its fetch */
#define ENVELOCK_VM_JMP_TRUE     0x0F   /* i32 relative (pops) — the right side of || */
/* Short-circuit expressions leave a boolean result on the stack; `if` merely tests and discards
 * its condition. The encoder casts each selected operand to bool before retaining it. Two families
 * of jumps are needed because a jump that pops cannot serve both. */
#define ENVELOCK_VM_JZ_KEEP      0x10   /* i32 relative: jumps when false, leaves the value */
#define ENVELOCK_VM_JNZ_KEEP     0x11   /* i32 relative: jumps when true,  leaves the value */

/* Binary operator ids, matching VM_BINARY in the encoder. 20 and 21 (&& and ||) never reach here:
 * they short-circuit, so the encoder compiles them to jumps. */
#define ENVELOCK_VM_STACK_MAX 4096

typedef struct _envelock_vm {
    const unsigned char **constant_offsets; /* validated entry pointers, avoiding a scan on each read */
    size_t constant_count;
    zval *stack;
    size_t stack_size;
    size_t stack_top;
    zval *locals;
    size_t local_count;
    const unsigned char *code;
    size_t code_length;
    size_t ip;
    int failed;
    const char *error;
} envelock_vm;

static void envelock_vm_fail(envelock_vm *vm, const char *why)
{
    if (!vm->failed) {
        vm->failed = 1;
        vm->error = why;
    }
}

static int envelock_vm_push(envelock_vm *vm, zval *value)
{
    if (vm->stack_top >= vm->stack_size) {
        /* push consumes ownership even on failure; otherwise overflow leaks strings, arrays,
         * objects or references that were materialized for the rejected slot. */
        zval_ptr_dtor(value);
        envelock_vm_fail(vm, "the virtualized function ran out of stack");
        return 0;
    }
    vm->stack[vm->stack_top++] = *value;
    return 1;
}

static zval *envelock_vm_pop(envelock_vm *vm)
{
    if (vm->stack_top == 0) {
        envelock_vm_fail(vm, "the virtualized function underflowed its stack");
        return NULL;
    }
    return &vm->stack[--vm->stack_top];
}

static const unsigned char *envelock_vm_constant_at(const envelock_vm *vm, size_t index)
{
    if (index >= vm->constant_count) {
        return NULL;
    }
    /* Filled once from the validated pool before execution; no repeated linear pool scan. */
    return vm->constant_offsets[index];
}

/* Materialises constant #index into *out. Returns 0 on a malformed pool. */
static int envelock_vm_load_constant(const envelock_vm *vm, size_t index, zval *out)
{
    const unsigned char *entry = envelock_vm_constant_at(vm, index);
    uint32_t length;
    if (!entry) {
        return 0;
    }
    switch (*entry) {
        case 0: ZVAL_NULL(out); return 1;
        case 1: ZVAL_BOOL(out, entry[1] != 0); return 1;
        case 2: {
            uint64_t raw = 0;
            size_t i;
            for (i = 0; i < 8; i++) {
                raw = (raw << 8) | (uint64_t) entry[1 + i];
            }
            ZVAL_LONG(out, (zend_long) raw);
            return 1;
        }
        case 3: {
            /* VM floats are IEEE-754 binary64 in little-endian order (PHP pack('e')). Build the
             * numeric bit pattern first, then copy its native representation to the double; copying
             * the serialized bytes directly only works on little-endian hosts. */
            uint64_t raw = 0;
            double value;
            size_t i;
            if (sizeof(value) != sizeof(raw)) {
                return 0;
            }
            for (i = 0; i < 8; i++) {
                raw |= (uint64_t) entry[1 + i] << (8 * i);
            }
            memcpy(&value, &raw, sizeof(value));
            ZVAL_DOUBLE(out, value);
            return 1;
        }
        case 4:
            length = ((uint32_t) entry[1] << 16) | ((uint32_t) entry[2] << 8) | (uint32_t) entry[3];
            ZVAL_STRINGL(out, (const char *) (entry + 4), length);
            return 1;
        default:
            return 0;
    }
}

static uint16_t envelock_vm_u16(const envelock_vm *vm, size_t at)
{
    return (uint16_t) (((uint16_t) vm->code[at] << 8) | (uint16_t) vm->code[at + 1]);
}

static int32_t envelock_vm_i32(const envelock_vm *vm, size_t at)
{
    uint32_t raw = ((uint32_t) vm->code[at] << 24) | ((uint32_t) vm->code[at + 1] << 16)
                 | ((uint32_t) vm->code[at + 2] << 8) | (uint32_t) vm->code[at + 3];
    return (int32_t) raw;
}

/* The code and jump destinations are immutable during an invocation. Validate every instruction,
 * including unreachable trailers, once before execution; mark boundaries so a jump cannot make an
 * operand byte become a new instruction. This removes repeated length checks from hot loops. */
/* Width of a FETCH_DIM_MIXED instruction whose opcode is at $at. Bounds are checked as it is walked. */
static int envelock_vm_mixed_width(const envelock_vm *vm, size_t at, size_t *width, const char **error)
{
    size_t p = at + 1;
    unsigned int i;
    unsigned int count;
    unsigned int flags;
    if (p + 2 > vm->code_length) {
        *error = "the program has a truncated instruction";
        return 0;
    }
    count = vm->code[p];
    flags = vm->code[p + 1];
    p += 2;
    if (count == 0 || (flags & ~1u)) {
        *error = "a dimension fetch is malformed";
        return 0;
    }
    if (flags & 1u) {
        if (p + 2 > vm->code_length) {
            *error = "the program has a truncated instruction";
            return 0;
        }
        p += 2;
    }
    for (i = 0; i < count; i++) {
        if (p >= vm->code_length) {
            *error = "the program has a truncated instruction";
            return 0;
        }
        if (vm->code[p] == 0) {
            p += 1;
        } else if (vm->code[p] == 1) {
            if (p + 3 > vm->code_length) {
                *error = "the program has a truncated instruction";
                return 0;
            }
            p += 3;
        } else {
            *error = "a dimension fetch key has an unknown kind";
            return 0;
        }
    }
    *width = p - at - 1;
    return 1;
}

static int envelock_vm_validate_code(const envelock_vm *vm, const char **error)
{
    static const unsigned char widths[] = {255, 2, 2, 2, 1, 1, 4, 4, 3, 0, 0, 2, 0, 0, 0, 4, 4, 4, 0, 1, 3, 0, 3};
    unsigned char *boundaries = (unsigned char *) ecalloc(vm->code_length + 1, 1);
    size_t at = 0;
    int valid = 0;
    while (at < vm->code_length) {
        unsigned int opcode = vm->code[at];
        size_t width;
        if (opcode >= sizeof(widths) || widths[opcode] == 255) {
            *error = "the program holds an opcode this loader does not know";
            goto done;
        }
        width = widths[opcode];
        if (opcode == ENVELOCK_VM_FETCH_DIM_MIXED && !envelock_vm_mixed_width(vm, at, &width, error)) {
            goto done;
        }
        if (width > vm->code_length - at - 1) {
            *error = "the program has a truncated instruction";
            goto done;
        }
        boundaries[at] = 1;
        at += 1 + width;
    }
    boundaries[vm->code_length] = 1;
    for (at = 0; at < vm->code_length;) {
        unsigned int opcode = vm->code[at];
        size_t width = widths[opcode];
        if (opcode == ENVELOCK_VM_FETCH_DIM_MIXED) {
            /* Already validated by the walk above: the width cannot fail here. */
            (void) envelock_vm_mixed_width(vm, at, &width, error);
        }
        if (opcode == ENVELOCK_VM_JMP || opcode == ENVELOCK_VM_JMP_FALSE
                || opcode == ENVELOCK_VM_JMP_TRUE || opcode == ENVELOCK_VM_JZ_KEEP
                || opcode == ENVELOCK_VM_JNZ_KEEP) {
            int64_t target = (int64_t) at + 1 + (int64_t) width + envelock_vm_i32(vm, at + 1);
            if (target < 0 || (uint64_t) target > vm->code_length || !boundaries[(size_t) target]) {
                *error = "a jump does not land on an instruction boundary";
                goto done;
            }
        }
        at += 1 + width;
    }
    valid = 1;
done:
    efree(boundaries);
    return valid;
}

static void envelock_vm_binary(envelock_vm *vm, uint8_t op)
{
    zval *right = envelock_vm_pop(vm);
    zval *left;
    zval result;
    int status = 0;
    int negate = 0;
    if (!right) {
        return;
    }
    left = envelock_vm_pop(vm);
    if (!left) {
        zval_ptr_dtor(right);
        return;
    }
    ZVAL_UNDEF(&result);
    switch (op) {
        case 1:  status = add_function(&result, left, right); break;
        case 2:  status = sub_function(&result, left, right); break;
        case 3:  status = mul_function(&result, left, right); break;
        case 4:  status = div_function(&result, left, right); break;
        case 5:  status = mod_function(&result, left, right); break;
        case 6:  status = concat_function(&result, left, right); break;
        /* PHP's ordered <= and >= are not the negation of > and <: NAN makes both false. Use
         * Zend's actual smaller-or-equal primitive instead of complementing a strict comparison. */
        case 7: case 8:
            status = is_equal_function(&result, left, right);
            negate = (op == 8);
            break;
        case 9: case 10:
            status = is_identical_function(&result, left, right);
            negate = (op == 10);
            break;
        case 11: status = is_smaller_function(&result, left, right); break;
        case 12: status = is_smaller_or_equal_function(&result, left, right); break;
        case 13: status = is_smaller_function(&result, right, left); break;
        case 14: status = is_smaller_or_equal_function(&result, right, left); break;
        case 15: status = bitwise_and_function(&result, left, right); break;
        case 16: status = bitwise_or_function(&result, left, right); break;
        case 17: status = bitwise_xor_function(&result, left, right); break;
        case 18: status = shift_left_function(&result, left, right); break;
        case 19: status = shift_right_function(&result, left, right); break;
        case 22: status = pow_function(&result, left, right); break;
        case 23: status = compare_function(&result, left, right); break;
        default:
            envelock_vm_fail(vm, "the program uses a binary operator this loader does not know");
            zval_ptr_dtor(left);
            zval_ptr_dtor(right);
            return;
    }
    zval_ptr_dtor(left);
    zval_ptr_dtor(right);
    if (negate && Z_TYPE(result) == IS_TRUE) {
        ZVAL_FALSE(&result);
    } else if (negate && Z_TYPE(result) == IS_FALSE) {
        ZVAL_TRUE(&result);
    }
    if (status != SUCCESS || Z_TYPE(result) == IS_UNDEF) {
        envelock_vm_fail(vm, "a virtualized operation failed the way it would fail in PHP");
        zval_ptr_dtor(&result);
        return;
    }
    envelock_vm_push(vm, &result);
}

/* Reads a local for an operation that consumes it. An undefined local warns and yields NULL, as
 * Zend does for a CV operand. Returns 0 only after a malformed program has been recorded. */
static int envelock_vm_read_local(envelock_vm *vm, uint16_t index, zval *copy)
{
    if (index >= vm->local_count) {
        envelock_vm_fail(vm, "the program reads a local that is not there");
        return 0;
    }
    if (Z_ISUNDEF(vm->locals[index])) {
        zval name;
        if (!envelock_vm_load_constant(vm, (size_t) index + 1, &name)) {
            envelock_vm_fail(vm, "an undefined local has no valid name");
            return 0;
        }
        if (Z_TYPE(name) != IS_STRING || Z_STRLEN(name) < 2 || Z_STRVAL(name)[0] != '$') {
            zval_ptr_dtor(&name);
            envelock_vm_fail(vm, "an undefined local has an invalid name");
            return 0;
        }
        zend_error(E_WARNING, "Undefined variable %s", Z_STRVAL(name));
        zval_ptr_dtor(&name);
        ZVAL_NULL(copy);
        return 1;
    }
    ZVAL_COPY(copy, &vm->locals[index]);
    return 1;
}

/* Performs the chain container[keys[0]][keys[1]]... in order, as separate Zend reads. A fetch
 * that raises an exception ends the chain, because the engine stops after that operation too.
 * Takes ownership of container and of every key. */
static int envelock_vm_fetch_chain(envelock_vm *vm, zval *current, zval *keys, uint8_t count, zval *result)
{
    uint8_t i;
    int ok = 1;
    for (i = 0; i < count; i++) {
        if (ok) {
            zval next;
            ZVAL_UNDEF(&next);
            zend_fetch_dimension_const(&next, current, &keys[i], BP_VAR_R);
            zval_ptr_dtor(current);
            if (EG(exception)) {
                ok = 0;
                ZVAL_NULL(current);
                if (!Z_ISUNDEF(next)) {
                    zval_ptr_dtor(&next);
                }
                envelock_vm_fail(vm, "a virtualized dimension read threw");
            } else if (Z_ISUNDEF(next)) {
                ok = 0;
                ZVAL_NULL(current);
                envelock_vm_fail(vm, "a virtualized dimension read failed");
            } else {
                ZVAL_COPY_VALUE(current, &next);
            }
        }
        zval_ptr_dtor(&keys[i]);
    }
    if (ok) {
        ZVAL_COPY_VALUE(result, current);
        return 1;
    }
    zval_ptr_dtor(current);
    ZVAL_NULL(result);
    return 0;
}

/* FETCH_DIM_MIXED: the container and the keys that are not locals are on the stack, in PHP's order.
 * A local key or local container is read at its own fetch, after the fetch before it, as Zend's CV
 * operands are: $a[$k][$k = 1] reads $k after the assignment. */
static int envelock_vm_fetch_mixed(envelock_vm *vm, zval *result)
{
    size_t spec = vm->ip;
    unsigned int count = vm->code[spec];
    unsigned int flags = vm->code[spec + 1];
    size_t at = spec + 2;
    uint16_t base_index = 0;
    unsigned int stack_keys = 0;
    unsigned int i;
    unsigned int next = 0;
    zval pushed[255];
    zval current;
    zval *value;
    int ok = 1;
    if (flags & 1u) {
        base_index = envelock_vm_u16(vm, at);
        at += 2;
    }
    for (i = 0; i < count; i++) {
        if (vm->code[at] == 0) {
            stack_keys++;
            at += 1;
        } else {
            at += 3;
        }
    }
    vm->ip = at;
    if (stack_keys + ((flags & 1u) ? 0u : 1u) > vm->stack_top) {
        envelock_vm_fail(vm, "the program fetches from fewer values than it pushed");
        return 0;
    }
    for (i = stack_keys; i > 0; i--) {
        value = envelock_vm_pop(vm);
        pushed[i - 1] = *value;
    }
    ZVAL_UNDEF(&current);
    if (flags & 1u) {
        if (!envelock_vm_read_local(vm, base_index, &current)) {
            for (i = 0; i < stack_keys; i++) {
                zval_ptr_dtor(&pushed[i]);
            }
            return 0;
        }
    } else {
        value = envelock_vm_pop(vm);
        current = *value;
    }
    at = spec + 2 + ((flags & 1u) ? 2 : 0);
    for (i = 0; i < count && ok; i++) {
        zval key;
        zval fetched;
        if (vm->code[at] == 0) {
            key = pushed[next++];
            at += 1;
        } else {
            uint16_t index = envelock_vm_u16(vm, at + 1);
            at += 3;
            if (!envelock_vm_read_local(vm, index, &key)) {
                ok = 0;
                break;
            }
        }
        if (!envelock_vm_fetch_chain(vm, &current, &key, 1, &fetched)) {
            /* The chain released the container and the key. */
            ok = 0;
            break;
        }
        current = fetched;
    }
    if (!ok) {
        zval_ptr_dtor(&current);
        for (i = next; i < stack_keys; i++) {
            zval_ptr_dtor(&pushed[i]);
        }
        return 0;
    }
    ZVAL_COPY_VALUE(result, &current);
    return 1;
}

static void envelock_vm_unary(envelock_vm *vm, uint8_t op)
{
    zval *value = envelock_vm_pop(vm);
    zval result;
    if (!value) {
        return;
    }
    ZVAL_UNDEF(&result);
    switch (op) {
        case 1: case 2: {                           /* unary minus / plus */
            zval factor;
            /* Zend implements unary arithmetic by multiplication: unlike 0-value, this preserves
             * the sign of floating zero, and unlike a no-op it converts numeric strings. */
            ZVAL_LONG(&factor, op == 1 ? -1 : 1);
            if (mul_function(&result, value, &factor) != SUCCESS) {
                envelock_vm_fail(vm, "a virtualized unary arithmetic operation failed");
            }
            break;
        }
        case 3: ZVAL_BOOL(&result, !zend_is_true(value)); break;
        case 4:
            if (bitwise_not_function(&result, value) != SUCCESS) {
                envelock_vm_fail(vm, "a virtualized bitwise negation failed");
            }
            break;
        case 5: ZVAL_LONG(&result, zval_get_long(value)); break;
        case 6: ZVAL_DOUBLE(&result, zval_get_double(value)); break;
        case 7: {
            zend_string *text = zval_get_string(value);
            ZVAL_STR(&result, text);
            break;
        }
        case 8: ZVAL_BOOL(&result, zend_is_true(value)); break;
        case 9:
            /* Zend handles arrays, null and objects differently; wrapping every input in a list
             * silently changed all three. Convert a copy exactly as the engine does. */
            ZVAL_COPY(&result, value);
            convert_to_array(&result);
            break;
        default:
            envelock_vm_fail(vm, "the program uses a unary operator this loader does not know");
            zval_ptr_dtor(value);
            return;
    }
    zval_ptr_dtor(value);
    envelock_vm_push(vm, &result);
}

/* Functions whose result depends on the frame that calls them. The loader's own frame is not the
 * virtualized function's, so these are refused at run time as well as at compile time. */
static const char *const envelock_vm_frame_functions[] = {
    "compact", "extract", "func_get_args", "func_get_arg", "func_num_args", "get_defined_vars",
    "get_called_class", "debug_backtrace", "debug_print_backtrace", "call_user_func",
    "call_user_func_array", "assert", NULL
};

/* INIT_CALL runs before the arguments, as PHP's INIT_FCALL does. An undefined function is an Error
 * raised here, so an undefined variable inside the arguments cannot warn first. A by-reference
 * parameter would receive a copy here, so the program is refused instead of running differently. */
/* Kept out of line: inlining it into the dispatch switch changed the hot loop's code layout (measured
 * 1.6-2.8% slower on a call-free loop with identical bytecode). */
static ENVELOCK_NOINLINE void envelock_vm_init_call(envelock_vm *vm, uint16_t name_index, uint8_t argc)
{
    zval name_value;
    zend_string *lower_name;
    zend_function *function_entry;
    const char *const *frame;
    unsigned int i;

    if (argc > 64) {
        envelock_vm_fail(vm, "the program calls a function with too many arguments");
        return;
    }
    if (!envelock_vm_load_constant(vm, name_index, &name_value)) {
        envelock_vm_fail(vm, "the program calls a function whose name is malformed");
        return;
    }
    if (Z_TYPE(name_value) != IS_STRING) {
        envelock_vm_fail(vm, "the program calls something that is not a name");
        zval_ptr_dtor(&name_value);
        return;
    }
    lower_name = zend_string_tolower(Z_STR(name_value));
    for (frame = envelock_vm_frame_functions; *frame; frame++) {
        if (strcmp(ZSTR_VAL(lower_name), *frame) == 0) {
            envelock_vm_fail(vm, "the program calls a function that depends on its own frame");
            goto done;
        }
    }
    function_entry = zend_hash_find_ptr(EG(function_table), lower_name);
    if (!function_entry) {
        zend_throw_error(NULL, "Call to undefined function %s()", ZSTR_VAL(Z_STR(name_value)));
        envelock_vm_fail(vm, "a virtualized operation threw");
        goto done;
    }
    for (i = 1; i <= argc; i++) {
        if (ARG_SHOULD_BE_SENT_BY_REF(function_entry, i)) {
            envelock_vm_fail(vm, "the program calls a function with a by-reference parameter");
            goto done;
        }
    }
done:
    zend_string_release(lower_name);
    zval_ptr_dtor(&name_value);
}

static void envelock_vm_call(envelock_vm *vm, uint16_t name_index, uint8_t argc)
{
    zval name_value, function, retval;
    zval params[64];
    uint8_t i;
    zend_string *name, *lower_name;
    zend_function *function_entry;

    if (argc > 64) {
        envelock_vm_fail(vm, "the program calls a function with too many arguments");
        return;
    }
    if (!envelock_vm_load_constant(vm, name_index, &name_value)) {
        envelock_vm_fail(vm, "the program calls a function whose name is malformed");
        return;
    }
    if (Z_TYPE(name_value) != IS_STRING) {
        envelock_vm_fail(vm, "the program calls something that is not a name");
        zval_ptr_dtor(&name_value);
        return;
    }
    /* Arguments were pushed left to right, so they come off right to left. */
    for (i = argc; i > 0; i--) {
        zval *argument = envelock_vm_pop(vm);
        if (!argument) {
            uint8_t j;
            /* The rightmost arguments already moved out of the VM stack. They are not part of
             * its cleanup anymore, so release them here if a malformed CALL underflows. */
            for (j = i; j < argc; j++) {
                zval_ptr_dtor(&params[j]);
            }
            zval_ptr_dtor(&name_value);
            return;
        }
        params[i - 1] = *argument;
    }
    name = Z_STR(name_value);
    lower_name = zend_string_tolower(name);
    /* OP_CALL must enforce the SAME restrictions as INIT_CALL (envelock_vm_init_call): a crafted
     * program that emits CALL (0x08) WITHOUT a preceding INIT would otherwise skip the frame-function
     * blocklist and the by-reference check, reaching call_user_func / assert / extract / get_defined_vars
     * from inside the VM (ENV-2026-07). Apply the blocklist here too. */
    {
        const char *const *frame;
        for (frame = envelock_vm_frame_functions; *frame; frame++) {
            if (strcmp(ZSTR_VAL(lower_name), *frame) == 0) {
                zend_string_release(lower_name);
                envelock_vm_fail(vm, "the program calls a function that depends on its own frame");
                for (i = 0; i < argc; i++) {
                    zval_ptr_dtor(&params[i]);
                }
                zval_ptr_dtor(&name_value);
                return;
            }
        }
    }
    function_entry = zend_hash_find_ptr(EG(function_table), lower_name);
    zend_string_release(lower_name);
    if (!function_entry) {
        envelock_vm_fail(vm, "the program calls a function that does not exist");
        for (i = 0; i < argc; i++) {
            zval_ptr_dtor(&params[i]);
        }
        zval_ptr_dtor(&name_value);
        return;
    }
    /* A by-reference parameter would receive a copy from the VM's stack, silently changing behaviour;
     * refuse, exactly as INIT_CALL does (ENV-2026-07). */
    for (i = 1; i <= argc; i++) {
        if (ARG_SHOULD_BE_SENT_BY_REF(function_entry, i)) {
            envelock_vm_fail(vm, "the program calls a function with a by-reference parameter");
            for (i = 0; i < argc; i++) {
                zval_ptr_dtor(&params[i]);
            }
            zval_ptr_dtor(&name_value);
            return;
        }
    }
    ZVAL_STR_COPY(&function, name);
    ZVAL_UNDEF(&retval);
    if (call_user_function(NULL, NULL, &function, &retval, argc, params) != SUCCESS) {
        envelock_vm_fail(vm, "a call made by the virtualized function failed");
    }
    zval_ptr_dtor(&function);
    for (i = 0; i < argc; i++) {
        zval_ptr_dtor(&params[i]);
    }
    zval_ptr_dtor(&name_value);
    if (Z_TYPE(retval) == IS_UNDEF) {
        ZVAL_NULL(&retval);
    }
    envelock_vm_push(vm, &retval);
}

/* Runs one program. `args` are the function's parameters, positionally. Returns 1 and fills *out
 * with the return value, or 0 with a static reason in *error. */
static int envelock_vm_execute(const unsigned char *program, size_t program_length,
                               HashTable *args, zval *out, const char **error)
{
    envelock_vm vm;
    size_t cursor, i;
    uint16_t constant_count, local_count;
    uint32_t code_length;
    int returned = 0;

    *error = NULL;
    /* v1's encoder and interpreter silently miscomputed valid PHP programs. Never run an old
     * virtualized package under the repaired loader as though it were compatible: repack it. */
    if (program_length >= 6 && memcmp(program, "ENVVM1", 6) == 0) {
        *error = "legacy v1 mini-VM programs are refused; repack from the original source";
        return 0;
    }
    /* v2 programs were compiled with eager local reads and the earlier warning order. The header
     * cannot tell which compiler produced them, so v2 is refused and every package is repacked. */
    if (program_length >= 6 && memcmp(program, "ENVVM2", 6) == 0) {
        *error = "legacy v2 mini-VM programs are refused; repack from the original source";
        return 0;
    }
    if (program_length < 10 || memcmp(program, "ENVVM3", 6) != 0) {
        *error = "not an Envelock mini-VM v3 program";
        return 0;
    }
    constant_count = (uint16_t) (((uint16_t) program[6] << 8) | program[7]);
    local_count = (uint16_t) (((uint16_t) program[8] << 8) | program[9]);
    cursor = 10;
    for (i = 0; i < constant_count; i++) {
        if (cursor >= program_length) {
            *error = "the constant pool runs past the end of the program";
            return 0;
        }
        {
            size_t entry_length;
            switch (program[cursor]) {
                case 0: entry_length = 1; break;
                case 1: entry_length = 2; break;
                case 2: case 3: entry_length = 9; break;
                case 4: {
                    uint32_t length;
                    if (program_length - cursor < 4) {
                        *error = "a string constant is truncated";
                        return 0;
                    }
                    length = ((uint32_t) program[cursor + 1] << 16)
                           | ((uint32_t) program[cursor + 2] << 8) | program[cursor + 3];
                    entry_length = 4 + (size_t) length;
                    break;
                }
                default:
                    *error = "the constant pool holds a type this loader does not know";
                    return 0;
            }
            if (entry_length > program_length - cursor) {
                *error = "the constant pool runs past the end of the program";
                return 0;
            }
            cursor += entry_length;
        }
    }
    if (program_length - cursor < 4) {
        *error = "the program has no code section";
        return 0;
    }
    code_length = ((uint32_t) program[cursor] << 24) | ((uint32_t) program[cursor + 1] << 16)
                | ((uint32_t) program[cursor + 2] << 8) | program[cursor + 3];
    cursor += 4;
    if ((size_t) code_length > program_length - cursor) {
        *error = "the code section runs past the end of the program";
        return 0;
    }

    memset(&vm, 0, sizeof(vm));
    vm.constant_count = constant_count;
    vm.code = program + cursor;
    vm.code_length = code_length;
    if (!envelock_vm_validate_code(&vm, error)) {
        return 0;
    }
    /* The pool has already been checked above. Index it once instead of scanning from the start
     * on every PUSH_CONST or CALL. The table points into the immutable decoded program. */
    vm.constant_offsets = (const unsigned char **) ecalloc(constant_count ? constant_count : 1,
                                                             sizeof(*vm.constant_offsets));
    cursor = 10;
    for (i = 0; i < constant_count; i++) {
        const unsigned char *entry = program + cursor;
        vm.constant_offsets[i] = entry;
        switch (*entry) {
            case 0: cursor += 1; break;
            case 1: cursor += 2; break;
            case 2: case 3: cursor += 9; break;
            case 4: cursor += 4 + (((uint32_t) entry[1] << 16)
                                  | ((uint32_t) entry[2] << 8) | entry[3]); break;
        }
    }
    vm.stack_size = ENVELOCK_VM_STACK_MAX;
    vm.stack = (zval *) ecalloc(vm.stack_size, sizeof(zval));
    vm.local_count = local_count;
    vm.locals = (zval *) ecalloc(local_count ? local_count : 1, sizeof(zval));
    /* The encoder lays parameters out as locals 0..n-1 in declaration order; constant 0 is
     * reserved separately. The rewritten function passes arguments positionally as a list. */
    for (i = 0; i < local_count; i++) {
        zval *argument = args ? zend_hash_index_find(args, (zend_ulong) i) : NULL;
        if (argument) {
            /* DEREF: an IS_REFERENCE element of $args must not alias the caller's variable inside
             * the program (nor leak a reference out as the internal function's return value). */
            ZVAL_COPY_DEREF(&vm.locals[i], argument);
        } else {
            ZVAL_UNDEF(&vm.locals[i]);
        }
    }
    ZVAL_NULL(out);

    while (!vm.failed && !returned && vm.ip < vm.code_length) {
        uint8_t opcode;
        /* Honour an engine interrupt (max_execution_time, a pcntl signal): without this a virtualized
         * loop spins at 100% CPU immune to the time limit, since the VM never returns to the Zend
         * executor that would otherwise notice (ENV-2026-07). Checked every instruction, which bounds
         * any loop — a back-jump cannot iterate without passing through here. */
        if (UNEXPECTED(zend_atomic_bool_load_ex(&EG(vm_interrupt)))) {
            zend_atomic_bool_store_ex(&EG(vm_interrupt), false);
            /* Exactly what Zend's own interrupt helper does: a pending max_execution_time ends the
             * request here (zend_timeout() does not return). Clearing vm_interrupt without this
             * swallowed the timeout and left the rest of the request unkillable. */
            if (zend_atomic_bool_load_ex(&EG(timed_out))) {
                zend_timeout();
            } else if (zend_interrupt_function) {
                zend_interrupt_function(EG(current_execute_data));
            }
            if (EG(exception)) {
                envelock_vm_fail(&vm, "execution was interrupted");
                break;
            }
        }
        opcode = vm.code[vm.ip++];
        /* All widths and jump targets were verified before entering the loop. */
        switch (opcode) {
            case ENVELOCK_VM_PUSH_CONST: {
                zval value;
                uint16_t index = envelock_vm_u16(&vm, vm.ip);
                vm.ip += 2;
                if (!envelock_vm_load_constant(&vm, index, &value)) {
                    envelock_vm_fail(&vm, "the program reads a constant that is not there");
                    break;
                }
                envelock_vm_push(&vm, &value);
                break;
            }
            case ENVELOCK_VM_PUSH_LOCAL: {
                uint16_t index = envelock_vm_u16(&vm, vm.ip);
                vm.ip += 2;
                if (index >= vm.local_count) {
                    envelock_vm_fail(&vm, "the program reads a local that is not there");
                    break;
                }
                {
                    zval copy;
                    if (Z_ISUNDEF(vm.locals[index])) {
                        zval name;
                        if (!envelock_vm_load_constant(&vm, (size_t) index + 1, &name)) {
                            envelock_vm_fail(&vm, "an undefined local has no valid name");
                            break;
                        }
                        if (Z_TYPE(name) != IS_STRING || Z_STRLEN(name) < 2 || Z_STRVAL(name)[0] != '$') {
                            zval_ptr_dtor(&name);
                            envelock_vm_fail(&vm, "an undefined local has an invalid name");
                            break;
                        }
                        /* Zend reads a variable operand inside the consuming operation, not at the
                         * fetch, and an exception from the warning is only raised after that
                         * operation has run. The read therefore continues with NULL, and the loop
                         * below stops after the next non-fetch opcode if an exception is pending. */
                        zend_error(E_WARNING, "Undefined variable %s", Z_STRVAL(name));
                        zval_ptr_dtor(&name);
                        ZVAL_NULL(&copy);
                    } else {
                        ZVAL_COPY(&copy, &vm.locals[index]);
                    }
                    envelock_vm_push(&vm, &copy);
                }
                break;
            }
            case ENVELOCK_VM_STORE_LOCAL: {
                uint16_t index = envelock_vm_u16(&vm, vm.ip);
                zval *value;
                vm.ip += 2;
                value = envelock_vm_pop(&vm);
                if (!value) {
                    break;
                }
                if (index >= vm.local_count) {
                    envelock_vm_fail(&vm, "the program writes a local that is not there");
                    zval_ptr_dtor(value);
                    break;
                }
                zval_ptr_dtor(&vm.locals[index]);
                ZVAL_COPY_VALUE(&vm.locals[index], value);
                break;
            }
            case ENVELOCK_VM_BINARY:
                envelock_vm_binary(&vm, vm.code[vm.ip++]);
                break;
            case ENVELOCK_VM_UNARY:
                envelock_vm_unary(&vm, vm.code[vm.ip++]);
                break;
            case ENVELOCK_VM_JMP: {
                int32_t offset = envelock_vm_i32(&vm, vm.ip);
                /* The displacement is relative to the END of the instruction, as the encoder
                 * measures it. Skipping this advance lands every jump four bytes short, inside
                 * another instruction — which surfaces as an unknown opcode or a stack underflow
                 * rather than as a wrong branch, so it is easy to chase in the wrong place. */
                vm.ip += 4;
                if ((int64_t) vm.ip + offset < 0
                        || (size_t) ((int64_t) vm.ip + offset) > vm.code_length) {
                    envelock_vm_fail(&vm, "the program jumps outside its own code");
                    break;
                }
                vm.ip = (size_t) ((int64_t) vm.ip + offset);
                break;
            }
            case ENVELOCK_VM_JZ_KEEP:
            case ENVELOCK_VM_JNZ_KEEP: {
                /* Peek, do not pop: the caller's next instruction is the POP that discards the
                 * left operand on the path that continues. */
                int32_t offset = envelock_vm_i32(&vm, vm.ip);
                zval *condition;
                int take;
                vm.ip += 4;
                if (vm.stack_top == 0) {
                    envelock_vm_fail(&vm, "the virtualized function underflowed its stack");
                    break;
                }
                condition = &vm.stack[vm.stack_top - 1];
                take = zend_is_true(condition);
                if (opcode == ENVELOCK_VM_JZ_KEEP) {
                    take = !take;
                }
                if (!take) {
                    break;
                }
                if ((int64_t) vm.ip + offset < 0
                        || (size_t) ((int64_t) vm.ip + offset) > vm.code_length) {
                    envelock_vm_fail(&vm, "the program jumps outside its own code");
                    break;
                }
                vm.ip = (size_t) ((int64_t) vm.ip + offset);
                break;
            }
            case ENVELOCK_VM_JMP_FALSE:
            case ENVELOCK_VM_JMP_TRUE: {
                int32_t offset = envelock_vm_i32(&vm, vm.ip);
                zval *condition;
                int take;
                vm.ip += 4;
                condition = envelock_vm_pop(&vm);
                if (!condition) {
                    break;
                }
                /* JMP_FALSE jumps when the value is false (that is how `if` skips its body, and
                 * how && skips its right side); JMP_TRUE jumps when it is true (how || does).
                 * Getting this the wrong way round does not crash — it quietly inverts every
                 * branch, which is the worst failure a mini-VM can have. */
                take = zend_is_true(condition);
                zval_ptr_dtor(condition);
                if (opcode == ENVELOCK_VM_JMP_FALSE) {
                    take = !take;
                }
                if (!take) {
                    break;
                }
                if ((int64_t) vm.ip + offset < 0
                        || (size_t) ((int64_t) vm.ip + offset) > vm.code_length) {
                    envelock_vm_fail(&vm, "the program jumps outside its own code");
                    break;
                }
                vm.ip = (size_t) ((int64_t) vm.ip + offset);
                break;
            }
            case ENVELOCK_VM_CALL: {
                uint16_t name_index = envelock_vm_u16(&vm, vm.ip);
                uint8_t call_argc = vm.code[vm.ip + 2];
                vm.ip += 3;
                envelock_vm_call(&vm, name_index, call_argc);
                break;
            }
            case ENVELOCK_VM_FETCH_DIM_R: {
                zval *offset = envelock_vm_pop(&vm);
                zval *container;
                zval result;
                if (!offset) {
                    break;
                }
                container = envelock_vm_pop(&vm);
                if (!container) {
                    zval_ptr_dtor(offset);
                    break;
                }
                /* Use Zend's own read helper: it handles array key conversions, strings,
                 * ArrayAccess, and the warnings/exceptions for missing or illegal offsets. */
                ZVAL_UNDEF(&result);
                zend_fetch_dimension_const(&result, container, offset, BP_VAR_R);
                zval_ptr_dtor(container);
                zval_ptr_dtor(offset);
                if (EG(exception)) {
                    zval_ptr_dtor(&result);
                    envelock_vm_fail(&vm, "a virtualized dimension read threw");
                    break;
                }
                if (Z_ISUNDEF(result)) {
                    envelock_vm_fail(&vm, "a virtualized dimension read failed");
                    break;
                }
                envelock_vm_push(&vm, &result);
                break;
            }
            case ENVELOCK_VM_FETCH_DIM_N: {
                uint8_t count = vm.code[vm.ip++];
                zval keys[255];
                zval container, result;
                uint8_t i;
                if (count == 0 || count + 1 > vm.stack_top) {
                    envelock_vm_fail(&vm, "the program fetches from fewer values than it pushed");
                    break;
                }
                for (i = count; i > 0; i--) {
                    zval *key = envelock_vm_pop(&vm);
                    keys[i - 1] = *key;
                }
                {
                    zval *value = envelock_vm_pop(&vm);
                    container = *value;
                }
                if (!envelock_vm_fetch_chain(&vm, &container, keys, count, &result)) {
                    break;
                }
                envelock_vm_push(&vm, &result);
                break;
            }
            case ENVELOCK_VM_FETCH_DIM_LOCAL: {
                uint16_t index = envelock_vm_u16(&vm, vm.ip);
                uint8_t count = vm.code[vm.ip + 2];
                zval keys[255];
                zval container, result;
                uint8_t i;
                vm.ip += 3;
                if (count == 0 || count > vm.stack_top) {
                    envelock_vm_fail(&vm, "the program fetches from fewer values than it pushed");
                    break;
                }
                for (i = count; i > 0; i--) {
                    zval *key = envelock_vm_pop(&vm);
                    keys[i - 1] = *key;
                }
                /* The local is read here, after the keys: Zend's CV container is fetched during
                 * the fetch itself, so its undefined-variable warning follows the key warnings. */
                if (!envelock_vm_read_local(&vm, index, &container)) {
                    for (i = 0; i < count; i++) {
                        zval_ptr_dtor(&keys[i]);
                    }
                    break;
                }
                if (!envelock_vm_fetch_chain(&vm, &container, keys, count, &result)) {
                    break;
                }
                envelock_vm_push(&vm, &result);
                break;
            }
            case ENVELOCK_VM_FETCH_DIM_MIXED: {
                zval result;
                if (!envelock_vm_fetch_mixed(&vm, &result)) {
                    break;
                }
                envelock_vm_push(&vm, &result);
                break;
            }
            case ENVELOCK_VM_ARRAY: {
                uint16_t count = envelock_vm_u16(&vm, vm.ip);
                uint16_t index;
                zval *values;
                zval array;
                vm.ip += 2;
                if (count > vm.stack_top) {
                    envelock_vm_fail(&vm, "the program builds an array from values it never pushed");
                    break;
                }
                values = &vm.stack[vm.stack_top - count];
                array_init_size(&array, count);
                for (index = 0; index < count; index++) {
                    zend_hash_next_index_insert(Z_ARRVAL(array), &values[index]);
                }
                vm.stack_top -= count;
                envelock_vm_push(&vm, &array);
                break;
            }
            case ENVELOCK_VM_POP: {
                zval *value = envelock_vm_pop(&vm);
                if (value) {
                    zval_ptr_dtor(value);
                }
                break;
            }
            case ENVELOCK_VM_DUP: {
                zval *value = envelock_vm_pop(&vm);
                zval copy;
                if (!value) {
                    break;
                }
                ZVAL_COPY(&copy, value);
                envelock_vm_push(&vm, value);
                envelock_vm_push(&vm, &copy);
                break;
            }
            case ENVELOCK_VM_RETURN: {
                zval *value = envelock_vm_pop(&vm);
                if (!value) {
                    break;
                }
                ZVAL_COPY_VALUE(out, value);
                returned = 1;
                break;
            }
            case ENVELOCK_VM_SWAP: {
                /* Only the values move: each pop hands out a stack slot, and both are pushed back
                 * in reverse order, so ownership of each zval travels with it. */
                zval *top = envelock_vm_pop(&vm);
                zval first, second;
                if (!top) {
                    break;
                }
                first = *top;
                {
                    zval *below = envelock_vm_pop(&vm);
                    if (!below) {
                        zval_ptr_dtor(&first);
                        break;
                    }
                    second = *below;
                }
                envelock_vm_push(&vm, &first);
                envelock_vm_push(&vm, &second);
                break;
            }
            case ENVELOCK_VM_RETURN_NULL:
                ZVAL_NULL(out);
                returned = 1;
                break;
            default:
                /* INIT_CALL is handled here rather than in its own case: a new case in the dispatch switch
                 * moved the hot loop's code (measured about 1% slower on a call-free loop), and this path
                 * is never taken by the other opcodes. */
                if (opcode == ENVELOCK_VM_INIT_CALL) {
                    uint16_t name_index = envelock_vm_u16(&vm, vm.ip);
                    uint8_t call_argc = vm.code[vm.ip + 2];
                    vm.ip += 3;
                    envelock_vm_init_call(&vm, name_index, call_argc);
                    break;
                }
                envelock_vm_fail(&vm, "the program holds an opcode this loader does not know");
                break;
        }
        /* A pending exception stops the program after the operation that consumed it. Pushing a
         * constant or a local, and building a literal list, are not operations in PHP: they cannot
         * raise anything, so they leave a warning's exception pending for the operation after
         * them, which may supersede it, exactly as the engine chains them. */
        if (EG(exception) && opcode != ENVELOCK_VM_PUSH_CONST && opcode != ENVELOCK_VM_PUSH_LOCAL
                && opcode != ENVELOCK_VM_ARRAY && opcode != ENVELOCK_VM_SWAP) {
            envelock_vm_fail(&vm, "a virtualized operation threw");
        }
    }
    if (!returned && !vm.failed) {
        envelock_vm_fail(&vm, "the program ended without returning");
    }
    for (i = 0; i < vm.local_count; i++) {
        zval_ptr_dtor(&vm.locals[i]);
    }
    for (i = 0; i < vm.stack_top; i++) {
        zval_ptr_dtor(&vm.stack[i]);
    }
    efree(vm.locals);
    efree(vm.stack);
    efree(vm.constant_offsets);
    if (vm.failed) {
        zval_ptr_dtor(out);
        ZVAL_NULL(out);
        *error = vm.error;
        return 0;
    }
    return 1;
}

/* __envelock_vm(string $program, array $args = []): mixed. The arginfo lives in envelock.c next
 * to the function table, because ZEND_BEGIN_ARG_* emits a static array per translation unit. */
PHP_FUNCTION(__envelock_vm)
{
    char *encoded;
    size_t encoded_length;
    zval *args = NULL;
    zend_string *program;
    const char *error = NULL;
    zval result;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_STRING(encoded, encoded_length)
        Z_PARAM_OPTIONAL
        Z_PARAM_ARRAY(args)
    ZEND_PARSE_PARAMETERS_END();

    /* Only a DIRECT call from user code runs a program, inspecting the immediate caller frame rather
     * than walking past internal C frames (the same hardening as __envelock_lit): the rewritten
     * virtualized body calls this directly, so routing it through array_map/call_user_func — a gadget
     * to run an attacker-supplied program — is refused (ENV-2026-07). */
    {
        zend_execute_data *caller = execute_data->prev_execute_data;
        if (!caller || !caller->func || !ZEND_USER_CODE(caller->func->common.type)) {
            RETURN_NULL();
        }
    }
    /* A variable-function call ($f($x)) or call_user_func() also has a user-code caller frame, so the
     * check above lets them through. The rewritten virtualized body always calls this function by its
     * literal name, so refuse any DYNAMIC call, as PHP does for compact()/extract(): otherwise a
     * one-argument dynamic-call sink in an application becomes "call any functions with any
     * arguments" via a crafted program. */
    if (ZEND_CALL_INFO(execute_data) & ZEND_CALL_DYNAMIC) {
        zend_throw_error(NULL, "Cannot call %s() dynamically",
                         ZSTR_VAL(execute_data->func->common.function_name));
        RETURN_THROWS();
    }

    /* The program travels as base64 inside the protected source, which keeps it out of the way of
     * anything that expects printable text and lets --vault-strings treat it as one more literal. */
    program = php_base64_decode((const unsigned char *) encoded, encoded_length);
    if (!program) {
        zend_throw_error(NULL, "Envelock: the virtualized program is not valid base64");
        RETURN_THROWS();
    }
    ZVAL_NULL(&result);
    if (!envelock_vm_execute((const unsigned char *) ZSTR_VAL(program), ZSTR_LEN(program),
            args ? Z_ARRVAL_P(args) : NULL, &result, &error)) {
        zend_string_release(program);
        /* Preserve an exception raised by the PHP operation or its error handler; replacing it
         * with a generic VM error silently changes catch behavior. */
        if (!EG(exception)) {
            zend_throw_error(NULL, "Envelock: the virtualized function could not run: %s",
                             error ? error : "unknown reason");
        }
        RETURN_THROWS();
    }
    zend_string_release(program);
    RETURN_ZVAL(&result, 0, 0);
}

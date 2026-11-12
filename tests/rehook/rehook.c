/* Test-only extension (objective O3): stands in for something that instruments the process
 * Envelock is running in, and lets a test check that Envelock notices instead of quietly handing
 * over decrypted source.
 *
 * It must be loaded AFTER Envelock (php loads extension= in order) so that it sits above
 * Envelock's hook. That ordering is the whole attack: Envelock decrypts, and the hook installed
 * on top receives the filled-in handle.
 *
 * Pick one instrument at build time:
 *   CFLAGS=-DREHOOK_MODE=REHOOK_COMPILE_FILE   a compile hook above Envelock's
 *   CFLAGS=-DREHOOK_MODE=REHOOK_AST            a zend_ast_process hook (whole syntax tree)
 *   CFLAGS=-DREHOOK_MODE=REHOOK_EXECUTE_EX     a replacement of zend_execute_ex
 *   CFLAGS=-DREHOOK_MODE=REHOOK_OBSERVER       a zend_observer fcall init handler
 *
 * The module name can be changed too (CFLAGS=-DREHOOK_NAME='"name"'), as the other test hook does.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "php.h"
#include "zend_observer.h"

#define REHOOK_NONE         0
#define REHOOK_COMPILE_FILE 1
#define REHOOK_AST          2
#define REHOOK_EXECUTE_EX   3
#define REHOOK_OBSERVER     4

#ifndef REHOOK_MODE
# define REHOOK_MODE REHOOK_COMPILE_FILE
#endif

#ifndef REHOOK_NAME
# define REHOOK_NAME "rehook"
#endif

#if REHOOK_MODE == REHOOK_COMPILE_FILE
static zend_op_array *(*rehook_previous_compile_file)(zend_file_handle *, int);
static zend_op_array *rehook_compile_file(zend_file_handle *handle, int type)
{
    /* The handle Envelock has just decrypted is right here. Reading it is the point. */
    return rehook_previous_compile_file(handle, type);
}
#elif REHOOK_MODE == REHOOK_AST
static void rehook_ast_process(zend_ast *ast)
{
    (void)ast;   /* A real instrument would walk the tree; installing one is already fatal. */
}
#elif REHOOK_MODE == REHOOK_EXECUTE_EX
static void (*rehook_previous_execute_ex)(zend_execute_data *execute_data);
static void rehook_execute_ex(zend_execute_data *execute_data)
{
    /* Every op_array as it starts running, decrypted and all. */
    rehook_previous_execute_ex(execute_data);
}
#elif REHOOK_MODE == REHOOK_OBSERVER
/* PHP 8.4's API: register an init handler during MINIT. The engine then allocates a slot for it,
 * which is exactly what makes an observer visible to a process that wants to refuse one. */
static zend_observer_fcall_handlers rehook_observer_init(zend_execute_data *execute_data)
{
    zend_observer_fcall_handlers handlers = {NULL, NULL};
    (void)execute_data;
    return handlers;
}
#endif

static PHP_MINIT_FUNCTION(rehook)
{
#if REHOOK_MODE == REHOOK_COMPILE_FILE
    rehook_previous_compile_file = zend_compile_file;
    zend_compile_file = rehook_compile_file;
#elif REHOOK_MODE == REHOOK_AST
    zend_ast_process = rehook_ast_process;
#elif REHOOK_MODE == REHOOK_EXECUTE_EX
    rehook_previous_execute_ex = zend_execute_ex;
    zend_execute_ex = rehook_execute_ex;
#elif REHOOK_MODE == REHOOK_OBSERVER
    zend_observer_fcall_register(rehook_observer_init);
#endif
    return SUCCESS;
}

zend_module_entry rehook_module_entry = {
    STANDARD_MODULE_HEADER, REHOOK_NAME, NULL, PHP_MINIT(rehook), NULL, NULL, NULL,
    NULL, "1.0", STANDARD_MODULE_PROPERTIES
};
ZEND_GET_MODULE(rehook)

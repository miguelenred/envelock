/* Test-only extension: a compile hook loaded BEFORE Envelock (so Envelock chains to it) that
 * reopens filename-type handles, as OPcache and other hooks do (zend_stream_open clears the
 * handle first). */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "php.h"

/* The module name can be changed at build time (CFLAGS=-DREOPEN_HOOK_NAME='"name"') to stand in
 * for an extension Envelock refuses to run with. */
#ifndef REOPEN_HOOK_NAME
# define REOPEN_HOOK_NAME "reopen_hook"
#endif

static zend_op_array *(*reopen_previous)(zend_file_handle *, int);

static zend_op_array *reopen_compile_file(zend_file_handle *handle, int type)
{
    if (handle->type == ZEND_HANDLE_FILENAME && zend_stream_open(handle) == FAILURE) {
        return NULL;
    }
    return reopen_previous(handle, type);
}

static PHP_MINIT_FUNCTION(reopen_hook)
{
    reopen_previous = zend_compile_file;
    zend_compile_file = reopen_compile_file;
    return SUCCESS;
}

zend_module_entry reopen_hook_module_entry = {
    STANDARD_MODULE_HEADER, REOPEN_HOOK_NAME, NULL, PHP_MINIT(reopen_hook), NULL, NULL, NULL,
    NULL, "1.0", STANDARD_MODULE_PROPERTIES
};
ZEND_GET_MODULE(reopen_hook)

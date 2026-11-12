/*
  +----------------------------------------------------------------------+
  | Envelock — bytecode layer (objective O1): proof-of-concept surface   |
  +----------------------------------------------------------------------+
  | Apache License 2.0 (see LICENSE).                                    |
  +----------------------------------------------------------------------+

  Two userland functions that exercise the whole bytecode path end to end, and nothing else.
  They exist so the round-trip can be tested before the loader is wired to it (step 2 of O1),
  and they stay as the narrowest possible regression test afterwards:

    envelock_bc_emit(string $path): string|false
        Compile $path and return its bytecode image. This is the pack side; it is the only place
        in the loader where PHP source is compiled, and on a server it never runs.

    envelock_bc_run(string $image): bool
        Deserialize an image and execute it, returning whether it deserialized at all. The image
        is copied into a mapping that outlives the call, because the program it becomes points
        into it.

  The point of envelock_bc_run is what it does NOT do: it never receives source, and it frees
  nothing the program still points at. If the two functions agree with running the file normally,
  the persistence layer is faithful.
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "zend_stream.h"
#include "zend_exceptions.h"

#include <stdlib.h>
#include <string.h>

#include "envelock_bc.h"

/* These are pack/test-only (see the registration guard in envelock.c). A server loader is built with
 * neither ENVELOCK_BCEMIT nor ENVELOCK_BCRUN, so the functions do not exist there. envelock_bc_emit
 * (the pack-side compiler) is compiled under ENVELOCK_BCEMIT; envelock_bc_run (executes a
 * caller-supplied image — an RCE surface) only under ENVELOCK_BCRUN, which is TEST ONLY (ENV-2026-02). */
#if defined(ENVELOCK_BCEMIT)

/* envelock_bc_emit(string $path): string|false */
PHP_FUNCTION(envelock_bc_emit)
{
    char *path;
    size_t path_length;
    zend_file_handle file_handle;
    unsigned char *image = NULL;
    size_t image_length = 0;
    const char *error = NULL;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_PATH(path, path_length)
    ZEND_PARSE_PARAMETERS_END();

    zend_stream_init_filename_ex(&file_handle, zend_string_init(path, path_length, 0));
    if (envelock_bc_emit_file(&file_handle, &image, &image_length, &error) != SUCCESS) {
        zend_destroy_file_handle(&file_handle);
        php_error_docref(NULL, E_WARNING, "Envelock bytecode: %s", error ? error : "failed");
        RETURN_FALSE;
    }
    zend_destroy_file_handle(&file_handle);
    RETVAL_STRINGL((char *) image, image_length);
    free(image);
}

#endif /* ENVELOCK_BCEMIT */

#if defined(ENVELOCK_BCRUN)

/* envelock_bc_run(string $image): bool */
PHP_FUNCTION(envelock_bc_run)
{
    char *image;
    size_t image_length;
    unsigned char *copy;
    zend_op_array *op_array;
    zval retval;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(image, image_length)
    ZEND_PARSE_PARAMETERS_END();

    /* The program points into this buffer, so the layer takes it over and keeps it mapped. */
    copy = (unsigned char *) malloc(image_length + ENVELOCK_BC_SLACK);
    if (copy == NULL) {
        RETURN_FALSE;
    }
    memcpy(copy, image, image_length);
    memset(copy + image_length, 0, ENVELOCK_BC_SLACK);

    op_array = envelock_bc_adopt(copy, image_length, ENVELOCK_BC_SLACK);
    if (op_array == NULL) {
        RETURN_FALSE;
    }

    ZVAL_UNDEF(&retval);
    /* zend_execute takes ownership of the op_array: it destroys and frees it on the way out.
     * Freeing it here as well was a double free and corrupted the emalloc heap. */
    zend_execute(op_array, &retval);
    zval_ptr_dtor(&retval);
    RETURN_TRUE;
}

/* envelock_bc_load_check(string $image): bool — TEST ONLY. Deserialize and install an image and
 * report whether it loaded, WITHOUT executing it, so the deserializer's crash-safety guard can be
 * exercised in isolation (executing a corrupted-but-signed image is the trust-boundary case and is
 * inherently unsafe, so it is not what this checks). Gated under ENVELOCK_BCRUN. */
PHP_FUNCTION(envelock_bc_load_check)
{
    char *image;
    size_t image_length;
    unsigned char *copy;
    zend_op_array *op_array;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(image, image_length)
    ZEND_PARSE_PARAMETERS_END();

    copy = (unsigned char *) malloc(image_length + ENVELOCK_BC_SLACK);
    if (copy == NULL) {
        RETURN_FALSE;
    }
    memcpy(copy, image, image_length);
    memset(copy + image_length, 0, ENVELOCK_BC_SLACK);

    /* envelock_bc_adopt -> envelock_bc_load_image runs under the crash-safety guard and frees the
     * buffer on rejection; on success the op_array is intentionally left mapped (never executed). */
    op_array = envelock_bc_adopt(copy, image_length, ENVELOCK_BC_SLACK);
    RETURN_BOOL(op_array != NULL);
}

#endif /* ENVELOCK_BCRUN */

/* Public header of the Envelock loader extension.
 *
 * This file exists for one reason, and the reason only shows up in one build shape. When the
 * extension is compiled INTO PHP rather than as a loadable module, the build generates
 * main/internal_functions.c (and internal_functions_cli.c), which lists every built-in extension
 * as `phpext_<name>_ptr`. configure emits the matching `#include "ext/<name>/php_<name>.h"` only
 * for extensions that actually ship such a header, so without this file the generated table refers
 * to a symbol nobody declared and the build dies with:
 *
 *   internal_functions_cli.c: error: 'phpext_envelock_ptr' undeclared here
 *
 * A module built with phpize never notices, because its entry point is get_module() inside
 * envelock.c and nothing outside that translation unit names the module entry. Compiling the
 * loader into the engine is what a statically embedded distribution needs — a static PHP has no
 * dynamic loader, so the loader has to be linked in rather than dlopen'ed — which makes this
 * header part of the supported build, not an optional extra.
 *
 * It is included as "ext/envelock/php_envelock.h" from outside the extension directory, so it must
 * not assume anything about the include path beyond PHP's own headers.
 */

#ifndef PHP_ENVELOCK_H
#define PHP_ENVELOCK_H

#include "php.h"

/* The entry itself lives in envelock.c. Declaring it here is what lets the generated built-in
 * extension table take its address. */
extern zend_module_entry envelock_module_entry;
#define phpext_envelock_ptr &envelock_module_entry

#define PHP_ENVELOCK_EXTNAME "envelock"

#endif /* PHP_ENVELOCK_H */

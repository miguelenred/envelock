/*
  +----------------------------------------------------------------------+
  | Envelock — bytecode layer (objective O1): API for the loader         |
  +----------------------------------------------------------------------+
  | Apache License 2.0 (see LICENSE).                                    |
  +----------------------------------------------------------------------+

  The loader talks to the bytecode layer through this header only. It never sees the adapted
  OPcache structures, which keeps the vendored code contained in extension/opcache/<version>/.

  Version support: the layer is per PHP version (extension/opcache/8.2, /8.3, /8.4, /8.5) because
  it adapts Zend-internal files that are not part of the stable extension API. The build selects
  the directory that matches the engine it is being compiled against.
*/

#ifndef ENVELOCK_BC_H
#define ENVELOCK_BC_H

#include "php.h"

/* Wire layout of a bytecode image:
 *
 *  off  len  field
 *    0    4   tag "EVB1"
 *    4    8   magic "ENVELBC1"
 *   12   32   bytecode identity of the PHP build that produced the image (ASCII hex)
 *   44    4   padding, always 0
 *   48    8   u64be mem_size      size of the serialized program
 *   56    8   u64be str_size      reserved, always 0
 *   64    8   u64be script_offset offset of the script record inside the program
 *   72    8   u64be timestamp     reserved, always 0
 *   76    4   u32be adler32       over the program bytes
 *   80    …   the serialized program (pointers rewritten as offsets from here)
 *
 * Offsets are absolute from the start of the image, i.e. they include the 4-byte tag. The
 * ENVELOCK_BC_OFF_* macros below are the single source of truth for them.
 *
 * Every field is fixed-width big-endian: the image is shipped inside an encrypted container and
 * must never depend on the host that reads its header. The identity is the real version gate — a
 * bytecode image is valid only for the exact PHP build that produced it. It is NOT zend_system_id
 * (audit BC-16): that one also hashes which engine hooks the process installed, which differ between
 * the SAPIs of one build (the Windows CLI's Ctrl+C handler, pcntl in a Linux CLI), so a CLI-packed
 * image was refused by php-cgi/FPM. The identity hashes the running PHP version, the Zend extension
 * build id, the data layout, the VM kind and the op_array extension slots instead (see
 * envelock_bc_identity() in opcache/php<MM>/envelock_bc.c); handlers are re-selected at load time.
 */
#define ENVELOCK_BC_HEADER_SIZE 80
#define ENVELOCK_BC_MAGIC       "ENVELBC1"

void envelock_bc_startup(void);
void envelock_bc_shutdown(void);

/* Pack side: compile a real PHP file and return its image (malloc'd; the caller frees it).
 * Returns SUCCESS and sets *image_out/*image_length, or FAILURE and *error. */
int envelock_bc_emit_file(zend_file_handle *file_handle, unsigned char **image_out,
                          size_t *image_length, const char **error);

/* Server side: deserialize an image in place and return a runnable op_array. The image buffer
 * must outlive the op_array — it holds every structure the program points at. Returns NULL when
 * the image is not valid for this PHP build, is truncated, fails its checksum or is malformed.
 *
 * The buffer is length + slack bytes, the slack zero-filled; slack is CHECKED (below
 * ENVELOCK_BC_SLACK the image is refused). On failure *retain (may be NULL) says what the caller may
 * do with the buffer: 0 = nothing references it, cleanse and free it; 1 = the install step had
 * started, entries published so far were rolled back but something may still point into it, so keep
 * it (unscrubbed) until the end of the request. A PHP fatal raised while installing (a redeclared
 * class, an inheritance error, memory_limit) is not a rejection: it propagates as the bailout it is,
 * after the crash guard is disarmed. */
zend_op_array *envelock_bc_load_image_ex(unsigned char *image, size_t length, size_t slack,
                                         int *retain);

/* Compatible form: assumes the caller allocated ENVELOCK_BC_SLACK zeroed bytes past the image and
 * does not report *retain. New callers should use envelock_bc_load_image_ex(). */
zend_op_array *envelock_bc_load_image(unsigned char *image, size_t length);

/* Same, but the layer TAKES OWNERSHIP of a buffer the caller allocated with malloc() and never
 * frees it again: the returned op_array, its opcodes, literals and class entries all point into
 * it, so its lifetime is the process'. On failure the buffer is freed and NULL returned — unless the
 * install step had started, in which case it is kept (leaked) for the same reason as *retain above.
 *
 * length is the image size; slack is extra zero-filled room past it. The deserializer is in place
 * — measured: it consumes none — but it is Zend-internal code being reused, so a bounded margin is
 * kept rather than relying on that. malloc (not emalloc) on purpose: the engine tears down its
 * request heap, and this buffer must not be in it. */
zend_op_array *envelock_bc_adopt(unsigned char *buffer, size_t length, size_t slack);

/* Room every caller keeps past the image, zero-filled. The deserializer never reads past the image
 * (the last opline's handler is selected on a copy); the margin is a checked part of the contract,
 * not something the layer silently relies on. */
#define ENVELOCK_BC_SLACK 4096U

/* TEST/diagnostics: the identity this process stamps into (and requires from) an image, as 32 hex
 * characters plus a NUL. */
void envelock_bc_identity_copy(char out[33]);

/* Keep an image the CALLER keeps out of core dumps. For the loader's uncached fallback, where the
 * buffer is not in the cache but the op_array still points into it. */
void envelock_bc_keep(unsigned char *image, size_t length);

#endif /* ENVELOCK_BC_H */

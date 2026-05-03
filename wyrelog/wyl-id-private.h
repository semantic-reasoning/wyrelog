/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

/*
 * Time-ordered identifier used by long-lived persistent records.
 *
 * Backed by a vendored generator that emits an RFC 9562 UUIDv7-shaped
 * 16-byte value: a 48-bit big-endian millisecond timestamp prefix
 * followed by version and variant nibbles and 74 random bits. Bytewise
 * lexicographic order on the 16-byte representation tracks creation
 * order at millisecond granularity, so sorting an array of ids yields
 * coarse chronological order without a separate timestamp field.
 *
 * Ordering contract: best-effort coarse-time. Two ids minted within
 * the same millisecond (or across a backward wall-clock step) are NOT
 * guaranteed to compare in mint order. Callers that need strict per-
 * call monotonic sequencing must layer a separate sequence number on
 * top of this id rather than rely on the embedded timestamp.
 *
 * Thread-safety: wyl_id_new is callable from any thread. The backing
 * generator uses a per-thread CSPRNG and does not require external
 * synchronisation. Re-entrant calls from within a single thread (e.g.
 * from a signal handler) are not supported.
 *
 * Value type by design: 16 bytes, no padding, safe to embed by value,
 * copy with assignment, and compare with memcmp. There is no heap
 * ownership to free, so this type intentionally has no autoptr
 * cleanup function.
 */

#define WYL_ID_BYTES        16
#define WYL_ID_STRING_LEN   36
#define WYL_ID_STRING_BUF   37

typedef struct wyl_id_t
{
  guint8 bytes[WYL_ID_BYTES];
} wyl_id_t;

G_STATIC_ASSERT (sizeof (wyl_id_t) == WYL_ID_BYTES);

extern const wyl_id_t WYL_ID_NIL;

/*
 * Generate a fresh time-ordered id stamped with the current wall-
 * clock time. On entropy failure returns WYRELOG_E_CRYPTO and leaves
 * |*out| untouched. On wall-clock-out-of-range (a year >= 10889 or
 * a clock pre-1970) returns WYRELOG_E_INTERNAL and leaves |*out|
 * untouched. NULL |out| returns WYRELOG_E_INVALID.
 *
 * Fail-closed: callers MUST NOT proceed with a zero-initialised id
 * on error. The all-zero sentinel WYL_ID_NIL is reserved for "no id
 * present" slots and would collapse uniqueness if returned by mint.
 */
wyrelog_error_t wyl_id_new (wyl_id_t * out);

/*
 * Render |id| into |buf| as the 36-character canonical hyphenated
 * lowercase form, NUL-terminated. |buf_len| must be at least
 * WYL_ID_STRING_BUF (37). Returns WYRELOG_E_INVALID for NULL inputs
 * or undersized buffer; on error |buf| is left untouched.
 */
wyrelog_error_t wyl_id_format (const wyl_id_t * id, gchar * buf, gsize buf_len);

/*
 * Parse the 36-character canonical form at |str| (NUL-terminated)
 * into |out|. Accepts upper- or lower-case hex. Returns
 * WYRELOG_E_INVALID for any format violation (length, hex, hyphen
 * placement, version != 7, variant != 10xx) or NULL inputs; on
 * error |*out| is left untouched. The wrapper enforces the RFC 9562
 * version and variant nibbles in addition to whatever structural
 * checks the backing parser performs, so accepted bytes are
 * guaranteed to round-trip through wyl_id_format.
 */
wyrelog_error_t wyl_id_parse (const gchar * str, wyl_id_t * out);

/*
 * Bytewise equality. NULL on either side returns FALSE.
 */
gboolean wyl_id_equal (const wyl_id_t * a, const wyl_id_t * b);

/*
 * Bytewise total order: returns <0, 0, >0 in memcmp fashion. NULL
 * arguments are substituted with WYL_ID_NIL for ordering purposes.
 */
gint wyl_id_compare (const wyl_id_t * a, const wyl_id_t * b);

G_END_DECLS;

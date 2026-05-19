/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

/*
 * RFC 6238 TOTP core (HMAC-SHA-1, 6 digits, 30-second step, T0=0).
 *
 * This header is intentionally narrow: it carries the cryptographic
 * primitives and nothing else.  Persistence, audit emission, replay
 * defense, and lockout policy live in higher layers that compose
 * this module.  Constants are locked at the spec defaults; no knobs.
 *
 * Secret material handed to these entry points is treated as
 * sensitive: all intermediate state inside the implementation is
 * cleared with sodium_memzero on every return path.  Callers are
 * responsible for zeroing their own copies of the seed.
 */

/*
 * Canonical RFC 6238 SHA-1 seed length.  The module rejects any
 * other length to keep callers from feeding partial or oversized
 * material that would silently change the security level.
 */
#define WYL_TOTP_SEED_BYTES 20

/* Digits, step, T0 — locked to RFC 6238 defaults. */
#define WYL_TOTP_DIGITS 6
#define WYL_TOTP_STEP_SECONDS 30
#define WYL_TOTP_T0_SECONDS 0

/*
 * Generate a 20-byte seed from the platform CSPRNG (libsodium
 * randombytes_buf).  out_seed MUST point to a writable buffer of
 * exactly WYL_TOTP_SEED_BYTES bytes; seed_len carries that size for
 * defensive checks.
 *
 * On error, out_seed is zeroed before return.  On success, the
 * caller owns the secret material and is responsible for zeroing
 * it once consumed.
 */
wyrelog_error_t wyl_totp_generate_seed (guint8 * out_seed,
    gsize seed_len, GError ** error);

/*
 * Compute the 6-digit TOTP code for the given counter step.  step
 * is the integer counter T (i.e. unix_time / WYL_TOTP_STEP_SECONDS),
 * not the wall-clock time — callers convert.  out_code receives the
 * integer in the range [0, 999999].
 *
 * Returns WYRELOG_E_INVALID for NULL inputs or seed_len that does
 * not match WYL_TOTP_SEED_BYTES.  Returns WYRELOG_E_CRYPTO if the
 * underlying HMAC primitive fails.
 */
wyrelog_error_t wyl_totp_code_at_step (const guint8 * seed,
    gsize seed_len, guint64 step, guint * out_code, GError ** error);

/*
 * Verify a 6-digit code against the three skew windows {-1, 0, +1}
 * centred on the step that contains unix_time.  All three windows
 * are evaluated unconditionally with constant-time equality (no
 * early return on first match) to defeat timing oracles.
 *
 * Returns TRUE on match; out_matched_step (optional) receives the
 * absolute step that matched, intended for the caller's replay
 * defense (persist this value, refuse codes at steps <= the last
 * verified one).
 *
 * Returns FALSE on no-match or on any argument validation failure;
 * use the GError to distinguish if needed.  out_matched_step is
 * untouched on no-match.
 */
gboolean wyl_totp_code_matches (const guint8 * seed,
    gsize seed_len, gint64 unix_time, guint code,
    guint64 * out_matched_step, GError ** error);

/*
 * RFC 4648 base32 encode.  Output is uppercase A-Z / 2-7 with '='
 * padding to a multiple of 8 characters.  *out is owned by the
 * caller and must be released with g_free.
 */
wyrelog_error_t wyl_totp_base32_encode (const guint8 * in,
    gsize in_len, gchar ** out, GError ** error);

/*
 * RFC 4648 base32 decode.  Accepts uppercase and lowercase letters;
 * tolerates trailing '=' padding even when the input length already
 * fits an exact 8-character boundary.  Rejects any other character
 * (including internal whitespace, internal '=', or characters
 * outside the alphabet) with WYRELOG_E_INVALID.
 *
 * On success, *out is a fresh allocation owned by the caller; free
 * with g_free.  *out_len receives the decoded length (may be 0 for
 * an empty input).  Both *out and *out_len are zeroed on error
 * before return.
 */
wyrelog_error_t wyl_totp_base32_decode (const gchar * in,
    guint8 ** out, gsize * out_len, GError ** error);

G_END_DECLS;

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/totp.h"

#include <sodium.h>
#include <string.h>

/*
 * RFC 6238 TOTP core (SHA-1) — minimal in-tree implementation.
 *
 * Design notes that callers and reviewers should hold in mind:
 *
 *   - HMAC-SHA-1 is performed via GLib's g_compute_hmac_for_data so
 *     we do not carry a hand-rolled SHA-1 implementation.  GLib
 *     returns the digest as a lowercase hex string; we decode that
 *     into 20 raw bytes for the dynamic-truncation step described
 *     in RFC 4226 section 5.3.  Both buffers are zeroed before
 *     release.
 *
 *   - Random seed bytes come from libsodium's randombytes_buf; the
 *     caller chose libsodium for every other secret-bearing path in
 *     the project and we follow that lead.  No /dev/urandom direct
 *     reads, no glibc rand().
 *
 *   - The verifier evaluates all three skew windows {-1, 0, +1}
 *     unconditionally and compares with sodium_memcmp on the
 *     6-character decimal form of the code so the path length is
 *     independent of which window (if any) matched.  This forecloses
 *     timing oracles that could otherwise leak which step a code
 *     belongs to.
 *
 *   - Replay defense is NOT implemented here.  This module returns
 *     the matched step number; persistence and "refuse anything <=
 *     last verified step" live in the caller (commit 5 of the issue
 *     roll-out).  Keeping the core stateless makes unit testing
 *     against published RFC vectors straightforward.
 *
 * Constants (step=30s, digits=6, T0=0) match RFC 6238 and are not
 * exposed as runtime knobs.  Operators do not benefit from being
 * able to weaken these.
 */

#define WYL_TOTP_HMAC_SHA1_LEN 20

/* 10^WYL_TOTP_DIGITS — the modulus that trims the dynamic-truncation
 * 31-bit integer down to a 6-digit code.  Encoded as a literal to
 * keep the expression visible to a reader scanning for the RFC
 * derivation rather than buried behind a power-of computation. */
#define WYL_TOTP_DIGIT_MODULUS 1000000u

static gboolean
hex_nibble (gchar c, guint8 *out)
{
  if (c >= '0' && c <= '9') {
    *out = (guint8) (c - '0');
    return TRUE;
  }
  if (c >= 'a' && c <= 'f') {
    *out = (guint8) (c - 'a' + 10);
    return TRUE;
  }
  if (c >= 'A' && c <= 'F') {
    *out = (guint8) (c - 'A' + 10);
    return TRUE;
  }
  return FALSE;
}

/*
 * Decode the lowercase hex string GLib produces (40 characters for
 * SHA-1) into 20 raw bytes.  The intermediate hex string is zeroed
 * by the caller via sodium_memzero after we return — the digest
 * itself is sensitive enough that we treat it the same as a key.
 */
static gboolean
decode_hex_digest (const gchar *hex, guint8 *out, gsize out_len)
{
  if (hex == NULL || out == NULL || out_len == 0)
    return FALSE;
  gsize hex_len = strlen (hex);
  if (hex_len != out_len * 2)
    return FALSE;
  for (gsize i = 0; i < out_len; i++) {
    guint8 hi, lo;
    if (!hex_nibble (hex[i * 2], &hi) || !hex_nibble (hex[i * 2 + 1], &lo))
      return FALSE;
    out[i] = (guint8) ((hi << 4) | lo);
  }
  return TRUE;
}

/*
 * RFC 4226 section 5.3 dynamic truncation.  digest is the 20-byte
 * HMAC-SHA-1 output; returns the 31-bit integer P (modulus applied
 * by the caller).
 */
static guint32
dynamic_truncate (const guint8 digest[WYL_TOTP_HMAC_SHA1_LEN])
{
  guint offset = digest[WYL_TOTP_HMAC_SHA1_LEN - 1] & 0x0Fu;
  guint32 bin = ((guint32) (digest[offset] & 0x7Fu) << 24)
      | ((guint32) digest[offset + 1] << 16)
      | ((guint32) digest[offset + 2] << 8)
      | ((guint32) digest[offset + 3]);
  return bin;
}

static wyrelog_error_t
hmac_sha1 (const guint8 *key, gsize key_len,
    const guint8 *data, gsize data_len,
    guint8 out_digest[WYL_TOTP_HMAC_SHA1_LEN])
{
  /* GLib's g_compute_hmac_for_data only emits a hex-encoded digest;
   * the project standardises on this entry point per the implementer
   * brief (no hand-rolled SHA-1, no OpenSSL).  We zero the
   * intermediate hex buffer before release because it carries the
   * full digest in printable form. */
  gchar *hex = g_compute_hmac_for_data (G_CHECKSUM_SHA1, key, key_len,
      data, data_len);
  if (hex == NULL)
    return WYRELOG_E_CRYPTO;
  gboolean ok = decode_hex_digest (hex, out_digest, WYL_TOTP_HMAC_SHA1_LEN);
  sodium_memzero (hex, strlen (hex));
  g_free (hex);
  return ok ? WYRELOG_E_OK : WYRELOG_E_CRYPTO;
}

static wyrelog_error_t
compute_code_for_step (const guint8 *seed, gsize seed_len, guint64 step,
    guint *out_code)
{
  if (seed == NULL || seed_len != WYL_TOTP_SEED_BYTES || out_code == NULL)
    return WYRELOG_E_INVALID;

  /* Counter is an 8-byte big-endian step number, per RFC 4226. */
  guint8 counter[8];
  for (gint i = 7; i >= 0; i--) {
    counter[i] = (guint8) (step & 0xFFu);
    step >>= 8;
  }

  guint8 digest[WYL_TOTP_HMAC_SHA1_LEN];
  wyrelog_error_t rc = hmac_sha1 (seed, seed_len, counter, sizeof counter,
      digest);
  /* Zero the counter even on the success path: it doesn't carry
   * secret material per se, but keeping the discipline uniform
   * means no one has to reason about which return path forgot. */
  sodium_memzero (counter, sizeof counter);
  if (rc != WYRELOG_E_OK) {
    sodium_memzero (digest, sizeof digest);
    return rc;
  }

  guint32 bin = dynamic_truncate (digest);
  sodium_memzero (digest, sizeof digest);
  *out_code = (guint) (bin % WYL_TOTP_DIGIT_MODULUS);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_totp_generate_seed (guint8 *out_seed, gsize seed_len, GError **error)
{
  (void) error;
  if (out_seed == NULL || seed_len != WYL_TOTP_SEED_BYTES)
    return WYRELOG_E_INVALID;
  if (sodium_init () < 0) {
    sodium_memzero (out_seed, seed_len);
    return WYRELOG_E_CRYPTO;
  }
  randombytes_buf (out_seed, seed_len);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_totp_code_at_step (const guint8 *seed, gsize seed_len, guint64 step,
    guint *out_code, GError **error)
{
  (void) error;
  return compute_code_for_step (seed, seed_len, step, out_code);
}

static void
format_code_6 (guint code, gchar out[7])
{
  /* Zero-padded 6-digit decimal.  We compare on the string form so
   * the constant-time comparison length is fixed regardless of how
   * many leading zeros the integer happened to have. */
  out[0] = (gchar) ('0' + (code / 100000u) % 10u);
  out[1] = (gchar) ('0' + (code / 10000u) % 10u);
  out[2] = (gchar) ('0' + (code / 1000u) % 10u);
  out[3] = (gchar) ('0' + (code / 100u) % 10u);
  out[4] = (gchar) ('0' + (code / 10u) % 10u);
  out[5] = (gchar) ('0' + code % 10u);
  out[6] = '\0';
}

gboolean
wyl_totp_code_matches (const guint8 *seed, gsize seed_len, gint64 unix_time,
    guint code, guint64 *out_matched_step, GError **error)
{
  (void) error;
  if (seed == NULL || seed_len != WYL_TOTP_SEED_BYTES)
    return FALSE;
  if (code >= WYL_TOTP_DIGIT_MODULUS)
    return FALSE;

  /* Integer-divide unix_time by the step length, biased so negative
   * times round toward minus infinity.  This keeps step boundaries
   * symmetric across the epoch — important for the test vectors at
   * T close to zero that the unit tests use. */
  gint64 step_centre;
  if (unix_time >= 0) {
    step_centre = unix_time / WYL_TOTP_STEP_SECONDS;
  } else {
    /* Floor division for negatives without invoking implementation-
     * defined behaviour on signed-integer division. */
    step_centre = -(((-unix_time) + WYL_TOTP_STEP_SECONDS - 1)
        / WYL_TOTP_STEP_SECONDS);
  }

  gchar candidate[7];
  format_code_6 (code, candidate);

  /* Compare against {-1, 0, +1} unconditionally.  We use accumulator
   * variables instead of an early-return loop so the function
   * executes the same amount of HMAC and comparison work for every
   * call regardless of which window (if any) matched. */
  guint matched_mask = 0;
  guint64 matched_step = 0;
  wyrelog_error_t worst_rc = WYRELOG_E_OK;

  for (gint delta = -1; delta <= 1; delta++) {
    gint64 step = step_centre + delta;
    if (step < 0) {
      /* Treat negative absolute steps as never-matching without
       * shortening the work: still run the HMAC at step 0 and
       * discard.  This keeps the timing flat for pre-epoch
       * inputs that show up in tests. */
      guint discard = 0;
      wyrelog_error_t rc = compute_code_for_step (seed, seed_len, 0,
          &discard);
      if (rc != WYRELOG_E_OK)
        worst_rc = rc;
      continue;
    }
    guint window_code = 0;
    wyrelog_error_t rc = compute_code_for_step (seed, seed_len,
        (guint64) step, &window_code);
    if (rc != WYRELOG_E_OK) {
      worst_rc = rc;
      continue;
    }
    gchar window_str[7];
    format_code_6 (window_code, window_str);
    /* sodium_memcmp returns 0 iff the buffers are byte-equal and
     * does so in constant time relative to buffer length. */
    if (sodium_memcmp (window_str, candidate, 6) == 0) {
      matched_mask = 1;
      matched_step = (guint64) step;
    }
    sodium_memzero (window_str, sizeof window_str);
  }

  sodium_memzero (candidate, sizeof candidate);

  if (worst_rc != WYRELOG_E_OK)
    return FALSE;
  if (matched_mask == 0)
    return FALSE;
  if (out_matched_step != NULL)
    *out_matched_step = matched_step;
  return TRUE;
}

/* RFC 4648 base32 alphabet (uppercase). */
static const gchar B32_ALPHA[33] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

wyrelog_error_t
wyl_totp_base32_encode (const guint8 *in, gsize in_len, gchar **out,
    GError **error)
{
  (void) error;
  if (out == NULL)
    return WYRELOG_E_INVALID;
  *out = NULL;
  if (in == NULL && in_len > 0)
    return WYRELOG_E_INVALID;

  /* Each 5-byte group produces 8 characters; pad partial groups
   * with '=' to a multiple of 8 per RFC 4648. */
  gsize groups = (in_len + 4) / 5;
  gsize out_len = groups * 8;
  gchar *buf = g_malloc (out_len + 1);
  buf[out_len] = '\0';

  gsize oi = 0;
  for (gsize i = 0; i < in_len; i += 5) {
    guint8 b[5] = { 0 };
    gsize remaining = in_len - i;
    gsize take = remaining < 5 ? remaining : 5;
    memcpy (b, in + i, take);

    /* Build the 8 5-bit groups across the 5-byte window. */
    guint8 idx[8];
    idx[0] = (b[0] >> 3) & 0x1Fu;
    idx[1] = (guint8) (((b[0] << 2) | (b[1] >> 6)) & 0x1Fu);
    idx[2] = (b[1] >> 1) & 0x1Fu;
    idx[3] = (guint8) (((b[1] << 4) | (b[2] >> 4)) & 0x1Fu);
    idx[4] = (guint8) (((b[2] << 1) | (b[3] >> 7)) & 0x1Fu);
    idx[5] = (b[3] >> 2) & 0x1Fu;
    idx[6] = (guint8) (((b[3] << 3) | (b[4] >> 5)) & 0x1Fu);
    idx[7] = b[4] & 0x1Fu;

    /* RFC 4648: emit alphabet for the bytes we had, pad '=' for the
     * trailing groups whose source bytes do not exist.  The lookup
     * table maps each 5-bit residue to {2,4,5,7,8}-byte windows. */
    gsize emit;
    switch (take) {
      case 1:
        emit = 2;
        break;
      case 2:
        emit = 4;
        break;
      case 3:
        emit = 5;
        break;
      case 4:
        emit = 7;
        break;
      default:
        emit = 8;
        break;
    }
    for (gsize k = 0; k < emit; k++)
      buf[oi + k] = B32_ALPHA[idx[k]];
    for (gsize k = emit; k < 8; k++)
      buf[oi + k] = '=';
    oi += 8;
    sodium_memzero (b, sizeof b);
    sodium_memzero (idx, sizeof idx);
  }

  *out = buf;
  return WYRELOG_E_OK;
}

static gboolean
b32_char_value (gchar c, guint8 *out)
{
  if (c >= 'A' && c <= 'Z') {
    *out = (guint8) (c - 'A');
    return TRUE;
  }
  if (c >= 'a' && c <= 'z') {
    *out = (guint8) (c - 'a');
    return TRUE;
  }
  if (c >= '2' && c <= '7') {
    *out = (guint8) (c - '2' + 26);
    return TRUE;
  }
  return FALSE;
}

wyrelog_error_t
wyl_totp_base32_decode (const gchar *in, guint8 **out, gsize *out_len,
    GError **error)
{
  (void) error;
  if (in == NULL || out == NULL || out_len == NULL)
    return WYRELOG_E_INVALID;
  *out = NULL;
  *out_len = 0;

  gsize len = strlen (in);

  /* Strip trailing '=' padding before validating the data run.  We
   * accept padding regardless of whether it lines up to a multiple
   * of 8 — the RFC requires it but real-world Base32 emitters
   * (including some authenticator apps) leave it off, and operators
   * tend to paste secrets from clipboards that did or did not
   * preserve it. */
  gsize data_len = len;
  while (data_len > 0 && in[data_len - 1] == '=')
    data_len--;

  /* Reject any non-alphabet character in the data run.  '=' inside
   * the data run, whitespace, dashes, etc. all land here. */
  for (gsize i = 0; i < data_len; i++) {
    guint8 ignored;
    if (!b32_char_value (in[i], &ignored))
      return WYRELOG_E_INVALID;
  }

  /* The data run length must be one of {0, 2, 4, 5, 7} modulo 8 —
   * the only group sizes RFC 4648 permits.  1, 3, 6 modulo 8 are
   * unrepresentable and indicate truncation. */
  gsize tail = data_len % 8;
  if (tail == 1 || tail == 3 || tail == 6)
    return WYRELOG_E_INVALID;

  gsize full_groups = data_len / 8;
  gsize tail_bytes = 0;
  switch (tail) {
    case 0:
      tail_bytes = 0;
      break;
    case 2:
      tail_bytes = 1;
      break;
    case 4:
      tail_bytes = 2;
      break;
    case 5:
      tail_bytes = 3;
      break;
    case 7:
      tail_bytes = 4;
      break;
    default:
      g_assert_not_reached ();
  }

  gsize decoded_len = full_groups * 5 + tail_bytes;
  guint8 *buf = (decoded_len == 0) ? g_malloc0 (1) : g_malloc (decoded_len);

  gsize oi = 0;
  for (gsize gi = 0; gi < full_groups; gi++) {
    guint8 v[8];
    for (gsize k = 0; k < 8; k++)
      (void) b32_char_value (in[gi * 8 + k], &v[k]);
    buf[oi + 0] = (guint8) ((v[0] << 3) | (v[1] >> 2));
    buf[oi + 1] = (guint8) ((v[1] << 6) | (v[2] << 1) | (v[3] >> 4));
    buf[oi + 2] = (guint8) ((v[3] << 4) | (v[4] >> 1));
    buf[oi + 3] = (guint8) ((v[4] << 7) | (v[5] << 2) | (v[6] >> 3));
    buf[oi + 4] = (guint8) ((v[6] << 5) | v[7]);
    oi += 5;
    sodium_memzero (v, sizeof v);
  }

  if (tail > 0) {
    guint8 v[8] = { 0 };
    for (gsize k = 0; k < tail; k++)
      (void) b32_char_value (in[full_groups * 8 + k], &v[k]);
    if (tail_bytes >= 1)
      buf[oi + 0] = (guint8) ((v[0] << 3) | (v[1] >> 2));
    if (tail_bytes >= 2)
      buf[oi + 1] = (guint8) ((v[1] << 6) | (v[2] << 1) | (v[3] >> 4));
    if (tail_bytes >= 3)
      buf[oi + 2] = (guint8) ((v[3] << 4) | (v[4] >> 1));
    if (tail_bytes >= 4)
      buf[oi + 3] = (guint8) ((v[4] << 7) | (v[5] << 2) | (v[6] >> 3));
    sodium_memzero (v, sizeof v);
  }

  *out = buf;
  *out_len = decoded_len;
  return WYRELOG_E_OK;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Unit tests for the RFC 6238 TOTP core (wyrelog/auth/totp.{c,h}).
 *
 * Vectors come from RFC 6238 Appendix B, restricted to the SHA-1
 * variant.  Appendix B prints 8-digit codes; this module is locked to
 * 6 digits, so each expected value is the published 8-digit code
 * taken modulo 1_000_000.  The seed used by Appendix B for SHA-1 is
 * the 20-byte ASCII string "12345678901234567890".
 */

#include "auth/totp.h"

#include <glib.h>
#include <sodium.h>
#include <string.h>

/* RFC 6238 SHA-1 canonical 20-byte seed (ASCII "12345678901234567890"). */
static const guint8 RFC6238_SEED[20] = {
  0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
  0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
  0x37, 0x38, 0x39, 0x30,
};

typedef struct
{
  gint64 unix_time;
  guint expected_code;          /* 8-digit RFC value mod 1_000_000 */
} rfc6238_vector_t;

static const rfc6238_vector_t RFC6238_VECTORS[] = {
  /* T=59          -> 94287082 -> 287082 */
  {59, 287082},
  /* T=1111111109  -> 07081804 -> 081804 */
  {1111111109, 81804},
  /* T=1111111111  -> 14050471 -> 050471 */
  {1111111111, 50471},
  /* T=1234567890  -> 89005924 -> 005924 */
  {1234567890, 5924},
  /* T=2000000000  -> 69279037 -> 279037 */
  {2000000000, 279037},
  /* T=20000000000 -> 65353130 -> 353130 */
  {20000000000LL, 353130},
};

static gint
check_rfc6238_vectors (void)
{
  for (gsize i = 0; i < G_N_ELEMENTS (RFC6238_VECTORS); i++) {
    const rfc6238_vector_t *v = &RFC6238_VECTORS[i];
    guint64 step = (guint64) (v->unix_time / 30);
    guint code = 999999;
    if (wyl_totp_code_at_step (RFC6238_SEED, sizeof RFC6238_SEED, step, &code,
            NULL) != WYRELOG_E_OK)
      return 100 + (gint) i;
    if (code != v->expected_code)
      return 200 + (gint) i;
  }
  return 0;
}

static gint
check_code_at_step_validates_args (void)
{
  guint code = 0;
  if (wyl_totp_code_at_step (NULL, sizeof RFC6238_SEED, 0, &code, NULL)
      != WYRELOG_E_INVALID)
    return 10;
  if (wyl_totp_code_at_step (RFC6238_SEED, 0, 0, &code, NULL)
      != WYRELOG_E_INVALID)
    return 11;
  if (wyl_totp_code_at_step (RFC6238_SEED, sizeof RFC6238_SEED, 0, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 12;
  return 0;
}

static gint
check_matches_within_skew_window (void)
{
  /* For T=59 (step 1 under T0=0, step=30), accept current step 1
   * and the {-1, +1} skew neighbours (steps 0 and 2).  T=59 ± 30s
   * keeps us inside the ±1 window.  T=59 ± 60s lands two steps
   * away and must be rejected. */
  guint code_step1 = 0;
  if (wyl_totp_code_at_step (RFC6238_SEED, sizeof RFC6238_SEED, 1, &code_step1,
          NULL) != WYRELOG_E_OK)
    return 20;

  /* The code at step 1 must be accepted at T=59 (step 1), T=29 (step 0)
   * via +1 skew, and T=89 (step 2) via -1 skew. */
  guint64 matched_step = 0;
  GError *error = NULL;
  if (!wyl_totp_code_matches (RFC6238_SEED, sizeof RFC6238_SEED, 59,
          code_step1, &matched_step, &error))
    return 21;
  if (matched_step != 1)
    return 22;
  matched_step = 0;
  if (!wyl_totp_code_matches (RFC6238_SEED, sizeof RFC6238_SEED, 29,
          code_step1, &matched_step, &error))
    return 23;
  if (matched_step != 1)
    return 24;
  matched_step = 0;
  if (!wyl_totp_code_matches (RFC6238_SEED, sizeof RFC6238_SEED, 89,
          code_step1, &matched_step, &error))
    return 25;
  if (matched_step != 1)
    return 26;

  /* T = -1 (i.e. shift one step earlier) — code_step1 must NOT
   * match because the verifier is centred on step -1, not step 1. */
  if (wyl_totp_code_matches (RFC6238_SEED, sizeof RFC6238_SEED, -1,
          code_step1, NULL, &error))
    return 27;

  /* T=119 lands on step 3 (code_step1 is two steps away). */
  if (wyl_totp_code_matches (RFC6238_SEED, sizeof RFC6238_SEED, 119,
          code_step1, NULL, &error))
    return 28;
  /* T=-31 lands on step -2 (verifier centre -2: covers -3, -2, -1). */
  if (wyl_totp_code_matches (RFC6238_SEED, sizeof RFC6238_SEED, -31,
          code_step1, NULL, &error))
    return 29;
  return 0;
}

static gint
check_matches_rejects_wrong_code (void)
{
  guint code_step1 = 0;
  if (wyl_totp_code_at_step (RFC6238_SEED, sizeof RFC6238_SEED, 1, &code_step1,
          NULL) != WYRELOG_E_OK)
    return 30;
  /* Use a code that is mathematically off-by-one from the valid
   * 6-digit code at step 1; very unlikely to collide with the
   * codes at steps 0 or 2 as well.  If it does, this test
   * still passes only because *all three* skew codes coincide,
   * which would be a separate (severe) bug. */
  guint bad = (code_step1 == 0) ? 1 : code_step1 - 1;
  if (wyl_totp_code_matches (RFC6238_SEED, sizeof RFC6238_SEED, 59, bad,
          NULL, NULL))
    return 31;

  /* Codes outside the 0..999999 6-digit range must be rejected. */
  if (wyl_totp_code_matches (RFC6238_SEED, sizeof RFC6238_SEED, 59, 1000000,
          NULL, NULL))
    return 32;
  return 0;
}

static gint
check_generate_seed_basic (void)
{
  guint8 seed1[20] = { 0 };
  guint8 seed2[20] = { 0 };

  if (wyl_totp_generate_seed (seed1, sizeof seed1, NULL) != WYRELOG_E_OK)
    return 40;
  if (wyl_totp_generate_seed (seed2, sizeof seed2, NULL) != WYRELOG_E_OK)
    return 41;
  /* Two independently-generated seeds should not collide.  P(collision)
   * for 20 random bytes is negligible; this is a smoke check that the
   * generator is wired to randombytes_buf and not, say, all zeros. */
  if (memcmp (seed1, seed2, sizeof seed1) == 0)
    return 42;

  /* The function MUST refuse buffer sizes other than the canonical 20. */
  if (wyl_totp_generate_seed (seed1, 16, NULL) != WYRELOG_E_INVALID)
    return 43;
  if (wyl_totp_generate_seed (seed1, 32, NULL) != WYRELOG_E_INVALID)
    return 44;
  if (wyl_totp_generate_seed (NULL, sizeof seed1, NULL) != WYRELOG_E_INVALID)
    return 45;
  return 0;
}

static gboolean
bytes_equal (const guint8 *a, gsize a_len, const guint8 *b, gsize b_len)
{
  return a_len == b_len && memcmp (a, b, a_len) == 0;
}

static gint
check_base32_roundtrip (void)
{
  static const gsize sizes[] = { 10, 16, 20, 32 };
  for (gsize i = 0; i < G_N_ELEMENTS (sizes); i++) {
    gsize len = sizes[i];
    g_autofree guint8 *buf = g_malloc (len);
    randombytes_buf (buf, len);
    g_autofree gchar *encoded = NULL;
    if (wyl_totp_base32_encode (buf, len, &encoded, NULL) != WYRELOG_E_OK)
      return 50 + (gint) i;
    if (encoded == NULL || encoded[0] == '\0')
      return 60 + (gint) i;
    /* Encoded output must be uppercase A-Z / 2-7 with optional
     * trailing '=' padding.  Reject anything else outright. */
    for (const gchar * p = encoded; *p != '\0'; p++) {
      gboolean ok = (*p >= 'A' && *p <= 'Z')
          || (*p >= '2' && *p <= '7') || *p == '=';
      if (!ok)
        return 70 + (gint) i;
    }
    g_autofree guint8 *decoded = NULL;
    gsize decoded_len = 0;
    if (wyl_totp_base32_decode (encoded, &decoded, &decoded_len, NULL)
        != WYRELOG_E_OK)
      return 80 + (gint) i;
    if (!bytes_equal (buf, len, decoded, decoded_len))
      return 90 + (gint) i;
  }
  return 0;
}

static gint
check_base32_known_vectors (void)
{
  /* "Hello!\xDE\xAD\xBE\xEF" — well-known sanity vector.
   *   ASCII "Hello!" = 48 65 6C 6C 6F 21
   *   + DE AD BE EF
   * Base32 = "JBSWY3DPEHPK3PXP" (no padding, 10 bytes). */
  static const guint8 raw[] = {
    0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF,
  };
  g_autofree gchar *encoded = NULL;
  if (wyl_totp_base32_encode (raw, sizeof raw, &encoded, NULL) != WYRELOG_E_OK)
    return 100;
  if (g_strcmp0 (encoded, "JBSWY3DPEHPK3PXP") != 0)
    return 101;

  /* Decode must accept upper-case, lower-case, and tolerate trailing
   * '=' padding even though the canonical encoded form omits it. */
  static const gchar *accept[] = {
    "JBSWY3DPEHPK3PXP",
    "jbswy3dpehpk3pxp",
    "JBSWY3DPEHPK3PXP=",
    "JBSWY3DPEHPK3PXP==",
    "JBSWY3DPEHPK3PXP======",
    "JbSwY3dPeHpK3pXp",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (accept); i++) {
    g_autofree guint8 *decoded = NULL;
    gsize decoded_len = 0;
    if (wyl_totp_base32_decode (accept[i], &decoded, &decoded_len, NULL)
        != WYRELOG_E_OK)
      return 110 + (gint) i;
    if (!bytes_equal (raw, sizeof raw, decoded, decoded_len))
      return 120 + (gint) i;
  }
  return 0;
}

static gint
check_base32_rejects_invalid (void)
{
  static const gchar *reject[] = {
    "JBSWY3DPEHPK3PX!",         /* '!' is not in the alphabet */
    "0BSWY3DPEHPK3PXP",         /* '0' is not in the alphabet */
    "8BSWY3DPEHPK3PXP",         /* '8' is not in the alphabet */
    "1BSWY3DPEHPK3PXP",         /* '1' is not in the alphabet */
    "JBSWY3DPEHPK3PXP ",        /* trailing space */
    "JBSWY 3DPEHPK3PXP",        /* internal space */
    "JBSWY-3DPEHPK3PXP",        /* internal dash */
    "=JBSWY3DPEHPK3PXP",        /* leading '=' is not padding */
    "JBSWY3DPEHPK3P=P",         /* '=' in the middle of data */
  };
  for (gsize i = 0; i < G_N_ELEMENTS (reject); i++) {
    g_autofree guint8 *decoded = NULL;
    gsize decoded_len = 0;
    if (wyl_totp_base32_decode (reject[i], &decoded, &decoded_len, NULL)
        != WYRELOG_E_INVALID)
      return 200 + (gint) i;
    if (decoded != NULL)
      return 250 + (gint) i;
  }

  /* Empty string decodes to a 0-length buffer (valid base32). */
  g_autofree guint8 *empty_decoded = NULL;
  gsize empty_len = 999;
  if (wyl_totp_base32_decode ("", &empty_decoded, &empty_len, NULL)
      != WYRELOG_E_OK)
    return 280;
  if (empty_len != 0)
    return 281;
  return 0;
}

int
main (void)
{
  if (sodium_init () < 0)
    return 1;

  gint rc;
  if ((rc = check_rfc6238_vectors ()) != 0)
    return rc;
  if ((rc = check_code_at_step_validates_args ()) != 0)
    return rc;
  if ((rc = check_matches_within_skew_window ()) != 0)
    return rc;
  if ((rc = check_matches_rejects_wrong_code ()) != 0)
    return rc;
  if ((rc = check_generate_seed_basic ()) != 0)
    return rc;
  if ((rc = check_base32_roundtrip ()) != 0)
    return rc;
  if ((rc = check_base32_known_vectors ()) != 0)
    return rc;
  if ((rc = check_base32_rejects_invalid ()) != 0)
    return rc;
  return 0;
}

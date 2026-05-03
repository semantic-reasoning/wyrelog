/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include <chronoid/ksuid.h>

#include "wyrelog/wyl-id-private.h"

static gint
failing_rng (void *ctx, uint8_t *buf, size_t n)
{
  (void) ctx;
  (void) buf;
  (void) n;
  return -1;
}

static gint
check_nil_sentinel (void)
{
  for (gsize i = 0; i < WYL_ID_BYTES; i++) {
    if (WYL_ID_NIL.bytes[i] != 0)
      return 10;
  }
  if (!wyl_id_equal (&WYL_ID_NIL, &WYL_ID_NIL))
    return 11;
  return 0;
}

static gint
check_generation_succeeds (void)
{
  wyl_id_t id;
  if (wyl_id_new (&id) != WYRELOG_E_OK)
    return 20;
  if (wyl_id_equal (&id, &WYL_ID_NIL))
    return 21;
  return 0;
}

static gint
check_generation_null (void)
{
  if (wyl_id_new (NULL) != WYRELOG_E_INVALID)
    return 30;
  return 0;
}

static gint
check_generation_uniqueness (void)
{
  GHashTable *seen = g_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, NULL);
  for (guint i = 0; i < 1000; i++) {
    wyl_id_t id;
    gchar buf[WYL_ID_STRING_BUF];
    if (wyl_id_new (&id) != WYRELOG_E_OK) {
      g_hash_table_destroy (seen);
      return 40;
    }
    if (wyl_id_format (&id, buf, sizeof buf) != WYRELOG_E_OK) {
      g_hash_table_destroy (seen);
      return 41;
    }
    if (g_hash_table_contains (seen, buf)) {
      g_hash_table_destroy (seen);
      return 42;
    }
    g_hash_table_add (seen, g_strdup (buf));
  }
  g_hash_table_destroy (seen);
  return 0;
}

static gint
check_monotonicity (void)
{
  wyl_id_t a, b;
  if (wyl_id_new (&a) != WYRELOG_E_OK)
    return 50;
  g_usleep (2000);
  if (wyl_id_new (&b) != WYRELOG_E_OK)
    return 51;
  if (wyl_id_compare (&a, &b) >= 0)
    return 52;
  return 0;
}

static gint
check_format_length (void)
{
  wyl_id_t id;
  gchar buf[WYL_ID_STRING_BUF];
  if (wyl_id_new (&id) != WYRELOG_E_OK)
    return 60;
  if (wyl_id_format (&id, buf, sizeof buf) != WYRELOG_E_OK)
    return 61;
  if (strlen (buf) != WYL_ID_STRING_LEN)
    return 62;
  if (buf[WYL_ID_STRING_LEN] != '\0')
    return 63;
  return 0;
}

static gint
check_format_canonical_shape (void)
{
  wyl_id_t id;
  gchar buf[WYL_ID_STRING_BUF];
  if (wyl_id_new (&id) != WYRELOG_E_OK)
    return 70;
  if (wyl_id_format (&id, buf, sizeof buf) != WYRELOG_E_OK)
    return 71;
  if (buf[8] != '-' || buf[13] != '-' || buf[18] != '-' || buf[23] != '-')
    return 72;
  for (gsize i = 0; i < WYL_ID_STRING_LEN; i++) {
    gchar c = buf[i];
    if (i == 8 || i == 13 || i == 18 || i == 23)
      continue;
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
      return 73;
  }
  if (buf[14] != '7')
    return 74;
  if (buf[19] != '8' && buf[19] != '9' && buf[19] != 'a' && buf[19] != 'b')
    return 75;
  return 0;
}

static gint
check_format_buffer_too_small (void)
{
  wyl_id_t id;
  gchar buf[WYL_ID_STRING_BUF];
  if (wyl_id_new (&id) != WYRELOG_E_OK)
    return 80;
  buf[0] = '!';
  if (wyl_id_format (&id, buf, WYL_ID_STRING_LEN) != WYRELOG_E_INVALID)
    return 81;
  if (buf[0] != '!')
    return 82;
  return 0;
}

static gint
check_format_null_inputs (void)
{
  wyl_id_t id;
  gchar buf[WYL_ID_STRING_BUF];
  if (wyl_id_new (&id) != WYRELOG_E_OK)
    return 90;
  if (wyl_id_format (NULL, buf, sizeof buf) != WYRELOG_E_INVALID)
    return 91;
  if (wyl_id_format (&id, NULL, sizeof buf) != WYRELOG_E_INVALID)
    return 92;
  return 0;
}

static gint
check_round_trip (void)
{
  for (guint i = 0; i < 100; i++) {
    wyl_id_t original, parsed;
    gchar buf[WYL_ID_STRING_BUF];
    if (wyl_id_new (&original) != WYRELOG_E_OK)
      return 100;
    if (wyl_id_format (&original, buf, sizeof buf) != WYRELOG_E_OK)
      return 101;
    if (wyl_id_parse (buf, &parsed) != WYRELOG_E_OK)
      return 102;
    if (!wyl_id_equal (&original, &parsed))
      return 103;
  }
  return 0;
}

static gint
check_parse_fixed_vector (void)
{
  static const gchar *canonical = "01890c10-2e3f-7000-8000-000000000001";
  wyl_id_t parsed;
  gchar buf[WYL_ID_STRING_BUF];

  if (wyl_id_parse (canonical, &parsed) != WYRELOG_E_OK)
    return 110;
  if (wyl_id_format (&parsed, buf, sizeof buf) != WYRELOG_E_OK)
    return 111;
  if (strcmp (buf, canonical) != 0)
    return 112;
  return 0;
}

static gint
check_parse_rejects_short (void)
{
  wyl_id_t out;
  if (wyl_id_parse ("00000000-0000-0000-0000-00000000000", &out)
      != WYRELOG_E_INVALID)
    return 120;
  return 0;
}

static gint
check_parse_rejects_long (void)
{
  wyl_id_t out;
  if (wyl_id_parse ("00000000-0000-0000-0000-0000000000000", &out)
      != WYRELOG_E_INVALID)
    return 130;
  return 0;
}

static gint
check_parse_rejects_non_hex (void)
{
  wyl_id_t out;
  if (wyl_id_parse ("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz", &out)
      != WYRELOG_E_INVALID)
    return 140;
  return 0;
}

static gint
check_parse_rejects_misplaced_hyphens (void)
{
  wyl_id_t out;
  if (wyl_id_parse ("000000000-000-0000-0000-000000000000", &out)
      != WYRELOG_E_INVALID)
    return 150;
  return 0;
}

static gint
check_parse_preserves_out_on_error (void)
{
  wyl_id_t out;
  memset (out.bytes, 0xab, WYL_ID_BYTES);
  if (wyl_id_parse ("not-a-uuid", &out) != WYRELOG_E_INVALID)
    return 160;
  for (gsize i = 0; i < WYL_ID_BYTES; i++) {
    if (out.bytes[i] != 0xab)
      return 161;
  }
  return 0;
}

static gint
check_parse_accepts_uppercase (void)
{
  static const gchar *upper = "01890C10-2E3F-7000-8000-00000000000A";
  wyl_id_t parsed;
  gchar buf[WYL_ID_STRING_BUF];
  if (wyl_id_parse (upper, &parsed) != WYRELOG_E_OK)
    return 170;
  if (wyl_id_format (&parsed, buf, sizeof buf) != WYRELOG_E_OK)
    return 171;
  if (strcmp (buf, "01890c10-2e3f-7000-8000-00000000000a") != 0)
    return 172;
  return 0;
}

static gint
check_parse_null_inputs (void)
{
  wyl_id_t out;
  if (wyl_id_parse (NULL, &out) != WYRELOG_E_INVALID)
    return 180;
  if (wyl_id_parse ("01890c10-2e3f-7000-8000-000000000000", NULL)
      != WYRELOG_E_INVALID)
    return 181;
  return 0;
}

static gint
check_equal_null_handling (void)
{
  wyl_id_t id;
  if (wyl_id_new (&id) != WYRELOG_E_OK)
    return 190;
  if (wyl_id_equal (NULL, &id))
    return 191;
  if (wyl_id_equal (&id, NULL))
    return 192;
  if (wyl_id_equal (NULL, NULL))
    return 193;
  return 0;
}

static gint
check_compare_total_order (void)
{
  enum
  { COUNT = 16 };
  wyl_id_t ids[COUNT];
  for (guint i = 0; i < COUNT; i++) {
    if (wyl_id_new (&ids[i]) != WYRELOG_E_OK)
      return 200;
    g_usleep (2000);
  }
  for (guint i = 1; i < COUNT; i++) {
    if (wyl_id_compare (&ids[i - 1], &ids[i]) >= 0)
      return 201;
  }
  return 0;
}

static gint
check_parse_rejects_bad_version (void)
{
  wyl_id_t out;
  /* Version nibble at offset 14 set to '6' (UUIDv6, not v7). */
  if (wyl_id_parse ("01890c10-2e3f-6000-8000-000000000000", &out)
      != WYRELOG_E_INVALID)
    return 210;
  return 0;
}

static gint
check_parse_rejects_bad_variant (void)
{
  wyl_id_t out;
  /* Variant nibble at offset 19 set to 'c' (RFC 4122 variant 11x,
   * reserved). RFC 9562 requires '8'..'b' (variant 10xx). */
  if (wyl_id_parse ("01890c10-2e3f-7000-c000-000000000000", &out)
      != WYRELOG_E_INVALID)
    return 220;
  return 0;
}

static gint
check_compare_null_handling (void)
{
  wyl_id_t id;
  if (wyl_id_new (&id) != WYRELOG_E_OK)
    return 230;
  if (wyl_id_compare (NULL, NULL) != 0)
    return 231;
  if (wyl_id_compare (&WYL_ID_NIL, NULL) != 0)
    return 232;
  if (wyl_id_compare (NULL, &WYL_ID_NIL) != 0)
    return 233;
  if (wyl_id_compare (NULL, &id) >= 0)
    return 234;
  if (wyl_id_compare (&id, NULL) <= 0)
    return 235;
  return 0;
}

static gint
check_rng_failure_fail_closed (void)
{
  wyl_id_t out;
  wyrelog_error_t rc;

  memset (out.bytes, 0xab, WYL_ID_BYTES);
  chronoid_set_rand (failing_rng, NULL);
  rc = wyl_id_new (&out);
  chronoid_set_rand (NULL, NULL);

  if (rc != WYRELOG_E_CRYPTO)
    return 240;
  /* Fail-closed contract: |*out| must remain untouched on entropy
   * failure so a caller cannot accidentally proceed with a half-
   * written or zero-initialised id. */
  for (gsize i = 0; i < WYL_ID_BYTES; i++) {
    if (out.bytes[i] != 0xab)
      return 241;
  }
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_nil_sentinel ()) != 0)
    return rc;
  if ((rc = check_generation_succeeds ()) != 0)
    return rc;
  if ((rc = check_generation_null ()) != 0)
    return rc;
  if ((rc = check_generation_uniqueness ()) != 0)
    return rc;
  if ((rc = check_monotonicity ()) != 0)
    return rc;
  if ((rc = check_format_length ()) != 0)
    return rc;
  if ((rc = check_format_canonical_shape ()) != 0)
    return rc;
  if ((rc = check_format_buffer_too_small ()) != 0)
    return rc;
  if ((rc = check_format_null_inputs ()) != 0)
    return rc;
  if ((rc = check_round_trip ()) != 0)
    return rc;
  if ((rc = check_parse_fixed_vector ()) != 0)
    return rc;
  if ((rc = check_parse_rejects_short ()) != 0)
    return rc;
  if ((rc = check_parse_rejects_long ()) != 0)
    return rc;
  if ((rc = check_parse_rejects_non_hex ()) != 0)
    return rc;
  if ((rc = check_parse_rejects_misplaced_hyphens ()) != 0)
    return rc;
  if ((rc = check_parse_preserves_out_on_error ()) != 0)
    return rc;
  if ((rc = check_parse_accepts_uppercase ()) != 0)
    return rc;
  if ((rc = check_parse_null_inputs ()) != 0)
    return rc;
  if ((rc = check_equal_null_handling ()) != 0)
    return rc;
  if ((rc = check_compare_total_order ()) != 0)
    return rc;
  if ((rc = check_parse_rejects_bad_version ()) != 0)
    return rc;
  if ((rc = check_parse_rejects_bad_variant ()) != 0)
    return rc;
  if ((rc = check_compare_null_handling ()) != 0)
    return rc;
  if ((rc = check_rng_failure_fail_closed ()) != 0)
    return rc;

  return 0;
}

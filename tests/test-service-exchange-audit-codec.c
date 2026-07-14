/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <sodium.h>
#include <string.h>

#include "auth/service-exchange-audit-private.h"

#define SESSION_ID "01890f47-3c4b-7cc2-98c4-dc0c0c07398f"
#define JTI "01890f47-3c4b-7cc2-a8c4-dc0c0c073990"
#define INTENTION_ID "01890f47-3c4b-7cc2-b8c4-dc0c0c073991"
#define REQUEST_ID "000000000000000000000000000"
#define CREDENTIAL_ID "wlc_000000000000000000000000000"

static const gchar transcript_one_hex[] =
    "777972656c6f672e736572766963652d65786368616e67652e696e74656e74696f"
    "6e2d7061796c6f616400000000010000002430313839306634372d336334622d37"
    "6363322d623863342d6463306330633037333939310000001b736572766963652e"
    "63726564656e7469616c2e65786368616e676500000007616c6c6f776564000615"
    "5e8bec6ff20000001b303030303030303030303030303030303030303030303030"
    "3030300000001f776c635f30303030303030303030303030303030303030303030"
    "30303030300102030405060708000000127376633a62696c6c696e673a726561"
    "6465720000000874656e616e742d6100000001000000200da4415c0595bc92941d"
    "bb76d6efc38fda8ca71da515c59ed28dc461d076737a000000202f21c5654459ac"
    "b3315b999dbdf891a63f19a36f91a1ebefeb88c05bd310a724";

static const gchar transcript_two_hex[] =
    "777972656c6f672e736572766963652d65786368616e67652e696e74656e74696f"
    "6e2d7061796c6f616400000000010000002466666666666666662d666666662d37"
    "6666662d626666662d6666666666666666666666660000001b736572766963652e"
    "63726564656e7469616c2e65786368616e676500000007616c6c6f776564000000"
    "00000000010000001b30756a74735963677653546c385041754164715759534d6e"
    "4c4f760000001f776c635f30756a74735963677653546c38504175416471575953"
    "4d6e4c4f767fffffffffffffff000000057376633a78000000017a000000010000"
    "00200da4415c0595bc92941dbb76d6efc38fda8ca71da515c59ed28dc461d0767"
    "37a000000202f21c5654459acb3315b999dbdf891a63f19a36f91a1ebefeb88c05"
    "bd310a724";

static const gchar transcript_three_hex[] =
    "777972656c6f672e736572766963652d65786368616e67652e696e74656e74696f"
    "6e2d7061796c6f616400000000010000002430313839306634372d336334622d37"
    "6363322d623863342d6463306330633037333939330000001b736572766963652e"
    "63726564656e7469616c2e65786368616e676500000007616c6c6f776564000000"
    "00000000020000001b303030303030303030303030303030303030303030303030"
    "3030320000001f776c635f30303030303030303030303030303030303030303030"
    "30303030320000000000000002000000087376633a7574663800000009ed858c"
    "eb848ced8ab800000001000000200da4415c0595bc92941dbb76d6efc38fda8ca7"
    "1da515c59ed28dc461d076737a000000202f21c5654459acb3315b999dbdf891a6"
    "3f19a36f91a1ebefeb88c05bd310a724";

static wyl_service_exchange_text_t
text (const gchar *value)
{
  return (wyl_service_exchange_text_t) {
  value, strlen (value)};
}

static wyl_service_exchange_audit_input_t
input_one (void)
{
  wyl_service_exchange_audit_input_t input = {
    .request_id = {REQUEST_ID, 27},
    .credential_id = {CREDENTIAL_ID, 31},
    .credential_generation = G_GUINT64_CONSTANT (0x0102030405060708),
    .service_principal = {"svc:billing:reader", 18},
    .tenant_id = {"tenant-a", 8},
    .session_id = {SESSION_ID, 36},
    .jti = {JTI, 36},
    .created_at_us = G_GINT64_CONSTANT (1712345678901234),
  };
  g_assert_cmpint (wyl_id_parse (INTENTION_ID, &input.intention_id), ==,
      WYRELOG_E_OK);
  return input;
}

static wyl_service_exchange_audit_input_t
input_two (void)
{
  wyl_service_exchange_audit_input_t input = {
    .request_id = {"0ujtsYcgvSTl8PAuAdqWYSMnLOv", 27},
    .credential_id = {"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", 31},
    .credential_generation = G_MAXINT64,
    .service_principal = {"svc:x", 5},
    .tenant_id = {"z", 1},
    .session_id = {SESSION_ID, 36},
    .jti = {JTI, 36},
    .created_at_us = 1,
  };
  g_assert_cmpint (wyl_id_parse ("ffffffff-ffff-7fff-bfff-ffffffffffff",
          &input.intention_id), ==, WYRELOG_E_OK);
  return input;
}

static wyl_service_exchange_audit_input_t
input_three (void)
{
  static const gchar tenant[] = "테넌트";
  wyl_service_exchange_audit_input_t input = {
    .request_id = {"000000000000000000000000002", 27},
    .credential_id = {"wlc_000000000000000000000000002", 31},
    .credential_generation = 2,
    .service_principal = {"svc:utf8", 8},
    .tenant_id = {tenant, sizeof tenant - 1},
    .session_id = {SESSION_ID, 36},
    .jti = {JTI, 36},
    .created_at_us = 2,
  };
  g_assert_cmpint (wyl_id_parse ("01890f47-3c4b-7cc2-b8c4-dc0c0c073993",
          &input.intention_id), ==, WYRELOG_E_OK);
  return input;
}

static gsize
count_bytes (const guint8 *haystack, gsize haystack_len,
    const guint8 *needle, gsize needle_len)
{
  if (needle == NULL || needle_len == 0 || haystack_len < needle_len)
    return 0;
  gsize count = 0;
  for (gsize i = 0; i <= haystack_len - needle_len; i++)
    if (memcmp (haystack + i, needle, needle_len) == 0)
      count++;
  return count;
}

static gboolean
contains_bytes (const guint8 *haystack, gsize haystack_len,
    const guint8 *needle, gsize needle_len)
{
  return count_bytes (haystack, haystack_len, needle, needle_len) != 0;
}

static void
assert_vector (wyl_service_exchange_audit_input_t input,
    const gchar *expected_hex, const gchar *expected_digest)
{
  wyl_service_exchange_audit_material_t material =
      WYL_SERVICE_EXCHANGE_AUDIT_MATERIAL_INIT;
  g_assert_cmpint (wyl_service_exchange_audit_encode (&input, &material), ==,
      WYRELOG_E_OK);
  gsize expected_len = strlen (expected_hex) / 2;
  g_autofree guint8 *expected = g_malloc (expected_len);
  gsize decoded_len = 0;
  g_assert_cmpint (sodium_hex2bin (expected, expected_len, expected_hex,
          strlen (expected_hex), NULL, &decoded_len, NULL), ==, 0);
  g_assert_cmpuint (decoded_len, ==, expected_len);
  gsize actual_len = 0;
  const guint8 *actual = g_bytes_get_data (material.canonical_payload,
      &actual_len);
  g_assert_cmpuint (actual_len, ==, expected_len);
  g_assert_cmpmem (actual, actual_len, expected, expected_len);
  g_assert_cmpstr (material.payload_digest, ==, expected_digest);
  g_assert_cmpstr (material.session_fingerprint, ==,
      "0da4415c0595bc92941dbb76d6efc38fda8ca71da515c59ed28dc461d076737a");
  g_assert_cmpstr (material.jti_fingerprint, ==,
      "2f21c5654459acb3315b999dbdf891a63f19a36f91a1ebefeb88c05bd310a724");
  g_assert_cmpuint (count_bytes (actual, actual_len,
          (const guint8 *) SESSION_ID, strlen (SESSION_ID)), ==, 0);
  g_assert_cmpuint (count_bytes (actual, actual_len, (const guint8 *) JTI,
          strlen (JTI)), ==, 0);
  const gchar *forbidden[] = { "Authorization", "Bearer", "JWT", "secret",
    "salt", "verifier", "CVK"
  };
  for (guint i = 0; i < G_N_ELEMENTS (forbidden); i++)
    g_assert_false (contains_bytes (actual, actual_len,
            (const guint8 *) forbidden[i], strlen (forbidden[i])));

  static const guint8 post_nul_marker[] = { 0, 'p', 'o', 's', 't' };
  g_assert_true (contains_bytes (post_nul_marker, sizeof post_nul_marker,
          post_nul_marker + 1, sizeof post_nul_marker - 1));
  GByteArray *mutant = g_byte_array_sized_new (actual_len + 72);
  g_byte_array_append (mutant, actual, actual_len);
  g_byte_array_append (mutant, (const guint8 *) SESSION_ID,
      strlen (SESSION_ID));
  g_assert_cmpuint (count_bytes (mutant->data, mutant->len,
          (const guint8 *) SESSION_ID, strlen (SESSION_ID)), ==, 1);
  const guint8 *domain_nul = memchr (mutant->data, '\0', mutant->len);
  g_assert_nonnull (domain_nul);
  gsize after_nul = (gsize) (domain_nul - mutant->data) + 1;
  GByteArray *post_nul_mutant = g_byte_array_sized_new (mutant->len + 36);
  g_byte_array_append (post_nul_mutant, mutant->data, after_nul);
  g_byte_array_append (post_nul_mutant, (const guint8 *) JTI, strlen (JTI));
  g_byte_array_append (post_nul_mutant, mutant->data + after_nul,
      mutant->len - after_nul);
  g_assert_cmpuint (count_bytes (post_nul_mutant->data, post_nul_mutant->len,
          (const guint8 *) JTI, strlen (JTI)), ==, 1);
  g_byte_array_unref (post_nul_mutant);
  g_byte_array_unref (mutant);
  wyl_service_exchange_audit_material_clear (&material);
}

static void
test_literal_vectors (void)
{
  assert_vector (input_one (), transcript_one_hex,
      "b6448d2d41708cd15a391ac8812fcbc0b7d4d6898d8ffe02f80a01a0539877a5");
  assert_vector (input_two (), transcript_two_hex,
      "d6aa950d795193fba20c37825584b3d7673b314ceb8d45e895f0f64d7b4642fb");
  assert_vector (input_three (), transcript_three_hex,
      "2182e3fdba829b86b0be0249c72b9939e2a7fb2f6fdbaf45d932149eb8135013");
}

static void
assert_invalid (wyl_service_exchange_audit_input_t input)
{
  wyl_service_exchange_audit_material_t material =
      WYL_SERVICE_EXCHANGE_AUDIT_MATERIAL_INIT;
  g_assert_cmpint (wyl_service_exchange_audit_encode (&input, &material), ==,
      WYRELOG_E_INVALID);
  g_assert_null (material.canonical_payload);
}

static void
test_identifier_rejections (void)
{
  wyl_service_exchange_audit_input_t input = input_one ();
  input.intention_id = WYL_ID_NIL;
  assert_invalid (input);
  input = input_one ();
  input.intention_id.bytes[6] = 0x60;
  assert_invalid (input);
  input = input_one ();
  input.intention_id.bytes[8] = 0x40;
  assert_invalid (input);

  const gchar *bad_uuids[] = {
    "01890F47-3C4B-7CC2-98C4-DC0C0C07398F",
    "01890f47-3c4b-6cc2-98c4-dc0c0c07398f",
    "01890f47-3c4b-7cc2-58c4-dc0c0c07398f",
    "01890f47-3c4b-7cc2-98c4-dc0c0c07398",
    "01890f47-3c4b-7cc2-98c4-dc0c0c07398ff",
  };
  for (guint i = 0; i < G_N_ELEMENTS (bad_uuids); i++) {
    input = input_one ();
    input.session_id = text (bad_uuids[i]);
    assert_invalid (input);
  }
  const gchar nul_uuid[36] = "01890f47-3c4b-7cc2-98c4-dc0c0c07398";
  input = input_one ();
  input.jti = (wyl_service_exchange_text_t) {
  nul_uuid, sizeof nul_uuid};
  assert_invalid (input);

  const gchar *bad_ksuids[] = {
    "00000000000000000000000000", "0000000000000000000000000000",
    "00000000000000000000000000!", "aWgEPTl1tmebfsQzFP4bxwgy80W",
  };
  for (guint i = 0; i < G_N_ELEMENTS (bad_ksuids); i++) {
    input = input_one ();
    input.request_id = text (bad_ksuids[i]);
    assert_invalid (input);
  }
  const gchar nul_ksuid[27] = "00000000000000000000000000";
  input = input_one ();
  input.request_id = (wyl_service_exchange_text_t) {
  nul_ksuid, sizeof nul_ksuid};
  assert_invalid (input);
}

typedef struct
{
  const guint8 *bytes;
  gsize len;
} InvalidUtf8;

static gchar *digest_for (wyl_service_exchange_audit_input_t input);

static void
test_binding_utf8_and_byte_bounds (void)
{
  static const guint8 isolated[] = { 0x80 };
  static const guint8 overlong[] = { 0xc0, 0xaf };
  static const guint8 truncated[] = { 0xe2, 0x82 };
  static const guint8 surrogate[] = { 0xed, 0xa0, 0x80 };
  static const guint8 above_max[] = { 0xf4, 0x90, 0x80, 0x80 };
  static const guint8 embedded_nul[] = { 'a', 0, 'b' };
  static const guint8 trailing_nul[] = { 'a', 0 };
  static const InvalidUtf8 invalid[] = {
    {isolated, sizeof isolated}, {overlong, sizeof overlong},
    {truncated, sizeof truncated}, {surrogate, sizeof surrogate},
    {above_max, sizeof above_max},
    {embedded_nul, sizeof embedded_nul},
    {trailing_nul, sizeof trailing_nul},
  };
  for (guint i = 0; i < G_N_ELEMENTS (invalid); i++) {
    wyl_service_exchange_audit_input_t input = input_one ();
    input.tenant_id = (wyl_service_exchange_text_t) {
    (const gchar *) invalid[i].bytes, invalid[i].len};
    assert_invalid (input);

    guint8 principal[4 + sizeof above_max];
    memcpy (principal, "svc:", 4);
    memcpy (principal + 4, invalid[i].bytes, invalid[i].len);
    input = input_one ();
    input.service_principal = (wyl_service_exchange_text_t) {
    (const gchar *) principal, 4 + invalid[i].len};
    assert_invalid (input);
  }

  static const gchar multibyte_principal[] = "svc:테";
  wyl_service_exchange_audit_input_t input = input_one ();
  input.service_principal = (wyl_service_exchange_text_t) {
  multibyte_principal, sizeof multibyte_principal - 1};
  assert_invalid (input);

  gchar principal_128[128];
  memcpy (principal_128, "svc:", 4);
  memset (principal_128 + 4, 'a', sizeof principal_128 - 4);
  input = input_one ();
  input.service_principal = (wyl_service_exchange_text_t) {
  principal_128, sizeof principal_128};
  g_autofree gchar *digest = digest_for (input);
  g_assert_nonnull (digest);
  gchar principal_129[129];
  memcpy (principal_129, principal_128, sizeof principal_128);
  principal_129[128] = 'a';
  input.service_principal = (wyl_service_exchange_text_t) {
  principal_129, sizeof principal_129};
  assert_invalid (input);

  gchar tenant_128[128];
  memset (tenant_128, 't', sizeof tenant_128);
  input = input_one ();
  input.tenant_id = (wyl_service_exchange_text_t) {
  tenant_128, sizeof tenant_128};
  g_clear_pointer (&digest, g_free);
  digest = digest_for (input);
  g_assert_nonnull (digest);
  gchar tenant_129[129];
  memset (tenant_129, 't', sizeof tenant_129);
  input.tenant_id = (wyl_service_exchange_text_t) {
  tenant_129, sizeof tenant_129};
  assert_invalid (input);
}

static gchar *
digest_for (wyl_service_exchange_audit_input_t input)
{
  wyl_service_exchange_audit_material_t material =
      WYL_SERVICE_EXCHANGE_AUDIT_MATERIAL_INIT;
  g_assert_cmpint (wyl_service_exchange_audit_encode (&input, &material), ==,
      WYRELOG_E_OK);
  gchar *digest = g_strdup (material.payload_digest);
  wyl_service_exchange_audit_material_clear (&material);
  return digest;
}

static void
assert_digest_changed (const gchar *baseline,
    wyl_service_exchange_audit_input_t changed)
{
  g_autofree gchar *digest = digest_for (changed);
  g_assert_cmpstr (digest, !=, baseline);
}

static void
test_every_input_is_bound (void)
{
  wyl_service_exchange_audit_input_t input = input_one ();
  g_autofree gchar *baseline = digest_for (input);
  wyl_id_parse ("01890f47-3c4b-7cc2-b8c4-dc0c0c073992", &input.intention_id);
  assert_digest_changed (baseline, input);
  input = input_one ();
  input.request_id = text ("000000000000000000000000001");
  assert_digest_changed (baseline, input);
  input = input_one ();
  input.credential_id = text ("wlc_000000000000000000000000001");
  assert_digest_changed (baseline, input);
  input = input_one ();
  input.credential_generation++;
  assert_digest_changed (baseline, input);
  input = input_one ();
  input.service_principal = text ("svc:billing:write");
  assert_digest_changed (baseline, input);
  input = input_one ();
  input.tenant_id = text ("tenant-b");
  assert_digest_changed (baseline, input);
  input = input_one ();
  input.session_id = (wyl_service_exchange_text_t) {
  JTI, 36};
  assert_digest_changed (baseline, input);
  input = input_one ();
  input.jti = (wyl_service_exchange_text_t) {
  SESSION_ID, 36};
  assert_digest_changed (baseline, input);
  input = input_one ();
  input.created_at_us++;
  assert_digest_changed (baseline, input);
}

static void
test_numeric_and_output_contract (void)
{
  wyl_service_exchange_audit_input_t input = input_one ();
  input.credential_generation = 0;
  assert_invalid (input);
  input = input_one ();
  input.credential_generation = G_MAXUINT64;
  assert_invalid (input);
  input = input_one ();
  input.created_at_us = 0;
  assert_invalid (input);
  input = input_one ();
  input.created_at_us = -1;
  assert_invalid (input);

  wyl_service_exchange_audit_material_t material =
      WYL_SERVICE_EXCHANGE_AUDIT_MATERIAL_INIT;
  material.canonical_payload = g_bytes_new_static ("x", 1);
  input = input_one ();
  g_assert_cmpint (wyl_service_exchange_audit_encode (&input, &material), ==,
      WYRELOG_E_INVALID);
  g_bytes_unref (material.canonical_payload);
  material = (wyl_service_exchange_audit_material_t)
      WYL_SERVICE_EXCHANGE_AUDIT_MATERIAL_INIT;
  material.session_fingerprint[1] = 'x';
  g_assert_cmpint (wyl_service_exchange_audit_encode (&input, &material), ==,
      WYRELOG_E_INVALID);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/service-exchange-audit/literal-vectors",
      test_literal_vectors);
  g_test_add_func ("/service-exchange-audit/identifiers",
      test_identifier_rejections);
  g_test_add_func ("/service-exchange-audit/input-binding",
      test_every_input_is_bound);
  g_test_add_func ("/service-exchange-audit/binding-utf8-bounds",
      test_binding_utf8_and_byte_bounds);
  g_test_add_func ("/service-exchange-audit/numeric-output",
      test_numeric_and_output_contract);
  return g_test_run ();
}

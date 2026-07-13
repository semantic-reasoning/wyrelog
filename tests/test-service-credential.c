/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <sodium.h>
#include <string.h>

#include "auth/service-credential-private.h"

#define FIXTURE_ID "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv"
#define FIXTURE_SECRET "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"

static const guint8 fixture_digest[WYL_SERVICE_CREDENTIAL_VERIFIER_BYTES] = {
  0x7f, 0x91, 0xc6, 0x7a, 0x1a, 0x7b, 0x27, 0xad,
  0xc0, 0xb3, 0xb5, 0xcc, 0x7b, 0x40, 0x31, 0xed,
  0xa2, 0xf3, 0x48, 0x2b, 0xe8, 0xbe, 0x71, 0x2d,
  0x37, 0x7d, 0xfa, 0x17, 0x23, 0x84, 0x24, 0x0b,
};

static void
fill_fixture (guint8 cvk[WYL_SERVICE_CREDENTIAL_CVK_BYTES],
    guint8 salt[WYL_SERVICE_CREDENTIAL_SALT_BYTES])
{
  for (guint i = 0; i < WYL_SERVICE_CREDENTIAL_CVK_BYTES; i++)
    cvk[i] = (guint8) i;
  for (guint i = 0; i < WYL_SERVICE_CREDENTIAL_SALT_BYTES; i++)
    salt[i] = (guint8) (0x10 + i);
}

static wyl_service_credential_secret_t *
parse_fixture_secret (void)
{
  wyl_service_credential_secret_t *secret = NULL;
  g_assert_cmpint (wyl_service_credential_secret_parse
      (WYL_SERVICE_CREDENTIAL_FORMAT_VERSION, FIXTURE_SECRET,
          strlen (FIXTURE_SECRET), &secret), ==, WYRELOG_E_OK);
  return secret;
}

static void
test_kat_and_verify (void)
{
  guint8 cvk[WYL_SERVICE_CREDENTIAL_CVK_BYTES];
  guint8 salt[WYL_SERVICE_CREDENTIAL_SALT_BYTES];
  fill_fixture (cvk, salt);
  wyl_service_credential_secret_t *secret = parse_fixture_secret ();

  guint8 actual[WYL_SERVICE_CREDENTIAL_VERIFIER_BYTES];
  memset (actual, 0xa5, sizeof actual);
  g_assert_cmpint (wyl_service_credential_verifier_compute
      (WYL_SERVICE_CREDENTIAL_VERIFIER_VERSION, cvk, sizeof cvk, FIXTURE_ID,
          strlen (FIXTURE_ID), "tenant-a", 8, "svc:tenant-a:worker", 19, salt,
          sizeof salt, secret, actual, sizeof actual), ==, WYRELOG_E_OK);
  g_assert_cmpmem (actual, sizeof actual, fixture_digest,
      sizeof fixture_digest);

  gboolean match = FALSE;
  g_assert_cmpint (wyl_service_credential_verify
      (WYL_SERVICE_CREDENTIAL_FORMAT_VERSION,
          WYL_SERVICE_CREDENTIAL_VERIFIER_VERSION, cvk, sizeof cvk, FIXTURE_ID,
          strlen (FIXTURE_ID), "tenant-a", 8, "svc:tenant-a:worker", 19, salt,
          sizeof salt, fixture_digest, sizeof fixture_digest, FIXTURE_SECRET,
          strlen (FIXTURE_SECRET), &match), ==, WYRELOG_E_OK);
  g_assert_true (match);

  guint8 wrong[sizeof fixture_digest];
  memcpy (wrong, fixture_digest, sizeof wrong);
  wrong[9] ^= 1;
  match = TRUE;
  g_assert_cmpint (wyl_service_credential_verify
      (WYL_SERVICE_CREDENTIAL_FORMAT_VERSION,
          WYL_SERVICE_CREDENTIAL_VERIFIER_VERSION, cvk, sizeof cvk, FIXTURE_ID,
          strlen (FIXTURE_ID), "tenant-a", 8, "svc:tenant-a:worker", 19, salt,
          sizeof salt, wrong, sizeof wrong, FIXTURE_SECRET,
          strlen (FIXTURE_SECRET), &match), ==, WYRELOG_E_OK);
  g_assert_false (match);

  match = TRUE;
  const gchar *wrong_secret = "ASEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";
  g_assert_cmpint (wyl_service_credential_verify
      (WYL_SERVICE_CREDENTIAL_FORMAT_VERSION,
          WYL_SERVICE_CREDENTIAL_VERIFIER_VERSION, cvk, sizeof cvk, FIXTURE_ID,
          strlen (FIXTURE_ID), "tenant-a", 8, "svc:tenant-a:worker", 19, salt,
          sizeof salt, fixture_digest, sizeof fixture_digest, wrong_secret,
          strlen (wrong_secret), &match), ==, WYRELOG_E_OK);
  g_assert_false (match);
  wyl_service_credential_secret_clear (&secret);
  g_assert_null (secret);
}

static void
assert_verifier_changed (const guint8 *cvk, const gchar *id,
    const gchar *tenant, const gchar *subject, const guint8 *salt,
    const wyl_service_credential_secret_t *secret)
{
  guint8 digest[WYL_SERVICE_CREDENTIAL_VERIFIER_BYTES];
  g_assert_cmpint (wyl_service_credential_verifier_compute
      (WYL_SERVICE_CREDENTIAL_VERIFIER_VERSION, cvk,
          WYL_SERVICE_CREDENTIAL_CVK_BYTES, id, strlen (id), tenant,
          strlen (tenant), subject, strlen (subject), salt,
          WYL_SERVICE_CREDENTIAL_SALT_BYTES, secret, digest, sizeof digest), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (sodium_memcmp (digest, fixture_digest, sizeof digest), !=,
      0);
}

static void
test_transcript_field_binding (void)
{
  guint8 cvk[WYL_SERVICE_CREDENTIAL_CVK_BYTES];
  guint8 salt[WYL_SERVICE_CREDENTIAL_SALT_BYTES];
  fill_fixture (cvk, salt);
  wyl_service_credential_secret_t *secret = parse_fixture_secret ();

  cvk[0] ^= 1;
  assert_verifier_changed (cvk, FIXTURE_ID, "tenant-a",
      "svc:tenant-a:worker", salt, secret);
  cvk[0] ^= 1;

  gchar other_id[WYL_SERVICE_CREDENTIAL_ID_BUF];
  g_assert_cmpint (wyl_service_credential_id_new (other_id, sizeof other_id),
      ==, WYRELOG_E_OK);
  assert_verifier_changed (cvk, other_id, "tenant-a",
      "svc:tenant-a:worker", salt, secret);
  assert_verifier_changed (cvk, FIXTURE_ID, "tenant-b",
      "svc:tenant-a:worker", salt, secret);
  assert_verifier_changed (cvk, FIXTURE_ID, "tenant-a",
      "svc:tenant-a:worker2", salt, secret);

  salt[7] ^= 1;
  assert_verifier_changed (cvk, FIXTURE_ID, "tenant-a",
      "svc:tenant-a:worker", salt, secret);
  salt[7] ^= 1;

  wyl_service_credential_secret_t *other_secret = NULL;
  const gchar *other_text = "ASEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";
  g_assert_cmpint (wyl_service_credential_secret_parse
      (WYL_SERVICE_CREDENTIAL_FORMAT_VERSION, other_text, strlen (other_text),
          &other_secret), ==, WYRELOG_E_OK);
  assert_verifier_changed (cvk, FIXTURE_ID, "tenant-a", "svc:tenant-a:worker",
      salt, other_secret);
  wyl_service_credential_secret_clear (&other_secret);

  /* Length framing separates otherwise identical concatenations. */
  guint8 first[WYL_SERVICE_CREDENTIAL_VERIFIER_BYTES];
  guint8 second[WYL_SERVICE_CREDENTIAL_VERIFIER_BYTES];
  g_assert_cmpint (wyl_service_credential_verifier_compute (1, cvk,
          sizeof cvk, FIXTURE_ID, strlen (FIXTURE_ID), "ab", 2, "svc:c", 5,
          salt, sizeof salt, secret, first, sizeof first), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_verifier_compute (1, cvk,
          sizeof cvk, FIXTURE_ID, strlen (FIXTURE_ID), "a", 1, "bsvc:c", 6,
          salt, sizeof salt, secret, second, sizeof second), ==, WYRELOG_E_OK);
  g_assert_cmpint (sodium_memcmp (first, second, sizeof first), !=, 0);
  wyl_service_credential_secret_clear (&secret);
}

static void
test_id_contract (void)
{
  g_assert_true (wyl_service_credential_id_is_canonical (FIXTURE_ID,
          strlen (FIXTURE_ID)));
  g_assert_false (wyl_service_credential_id_is_canonical
      ("WLC_0ujtsYcgvSTl8PAuAdqWYSMnLOv", WYL_SERVICE_CREDENTIAL_ID_LEN));
  g_assert_false (wyl_service_credential_id_is_canonical (FIXTURE_ID,
          WYL_SERVICE_CREDENTIAL_ID_LEN - 1));
  g_assert_true (wyl_service_credential_id_is_canonical
      ("wlc_000000000000000000000000000", WYL_SERVICE_CREDENTIAL_ID_LEN));
  g_assert_false (wyl_service_credential_id_is_canonical
      ("wlc_0ujtsYcgvSTl8PAuAdqWYSMnLO!", WYL_SERVICE_CREDENTIAL_ID_LEN));

  gchar id[WYL_SERVICE_CREDENTIAL_ID_BUF];
  g_assert_cmpint (wyl_service_credential_id_new (id, sizeof id), ==,
      WYRELOG_E_OK);
  g_assert_true (wyl_service_credential_id_is_canonical (id, strlen (id)));

  gchar canary[WYL_SERVICE_CREDENTIAL_ID_BUF];
  memset (canary, 0x5a, sizeof canary);
  g_assert_cmpint (wyl_service_credential_id_new (canary,
          WYL_SERVICE_CREDENTIAL_ID_BUF - 1), ==, WYRELOG_E_INVALID);
  for (guint i = 0; i < sizeof canary; i++)
    g_assert_cmpuint ((guint8) canary[i], ==, 0x5a);
}

static void
test_secret_codec_contract (void)
{
  wyl_service_credential_secret_t *secret = parse_fixture_secret ();
  gsize len = 0;
  const gchar *encoded = wyl_service_credential_secret_peek_encoded (secret,
      &len);
  g_assert_cmpuint (len, ==, WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN);
  g_assert_cmpmem (encoded, len, FIXTURE_SECRET, strlen (FIXTURE_SECRET));
  wyl_service_credential_secret_clear (&secret);

  const gchar *bad[] = {
    "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj=",
    "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj+",
    "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj/",
    "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj ",
    "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9",
  };
  for (guint i = 0; i < G_N_ELEMENTS (bad); i++) {
    secret = NULL;
    g_assert_cmpint (wyl_service_credential_secret_parse
        (WYL_SERVICE_CREDENTIAL_FORMAT_VERSION, bad[i], strlen (bad[i]),
            &secret), ==, WYRELOG_E_INVALID);
    g_assert_null (secret);
  }
  secret = NULL;
  g_assert_cmpint (wyl_service_credential_secret_parse (2, FIXTURE_SECRET,
          strlen (FIXTURE_SECRET), &secret), ==, WYRELOG_E_INVALID);
  g_assert_null (secret);
}

typedef struct
{
  guint allocs;
  guint locks;
  guint wipes;
  guint unlocks;
  guint frees;
  guint id_calls;
  guint rng_calls;
  guint fail_alloc_at;
  guint fail_lock_at;
  gboolean fail_id;
  gboolean invalid_id;
  gboolean fail_rng;
  gchar events[128];
  guint n_events;
} TestRuntime;

static void
record_event (TestRuntime *t, gchar event)
{
  g_assert_cmpuint (t->n_events, <, G_N_ELEMENTS (t->events));
  t->events[t->n_events++] = event;
}

static gpointer
test_alloc (gpointer data, gsize size)
{
  TestRuntime *t = data;
  t->allocs++;
  record_event (t, 'A');
  if (t->fail_alloc_at == t->allocs)
    return NULL;
  return g_malloc (size);
}

static int
test_lock (gpointer data, gpointer ptr, gsize size)
{
  TestRuntime *t = data;
  (void) ptr;
  (void) size;
  t->locks++;
  record_event (t, 'L');
  return t->fail_lock_at == t->locks ? -1 : 0;
}

static void
test_wipe (gpointer data, gpointer ptr, gsize size)
{
  TestRuntime *t = data;
  t->wipes++;
  record_event (t, 'W');
  sodium_memzero (ptr, size);
}

static int
test_unlock (gpointer data, gpointer ptr, gsize size)
{
  TestRuntime *t = data;
  (void) ptr;
  (void) size;
  t->unlocks++;
  record_event (t, 'U');
  return 0;
}

static void
test_free (gpointer data, gpointer ptr)
{
  TestRuntime *t = data;
  t->frees++;
  record_event (t, 'F');
  g_free (ptr);
}

static wyrelog_error_t
test_new_id (gpointer data, gchar out[WYL_SERVICE_CREDENTIAL_ID_BUF])
{
  TestRuntime *t = data;
  t->id_calls++;
  record_event (t, 'I');
  if (t->fail_id)
    return WYRELOG_E_INTERNAL;
  if (t->invalid_id) {
    memset (out, 'x', WYL_SERVICE_CREDENTIAL_ID_LEN);
    out[WYL_SERVICE_CREDENTIAL_ID_LEN] = '\0';
    return WYRELOG_E_OK;
  }
  memcpy (out, FIXTURE_ID, sizeof FIXTURE_ID);
  return WYRELOG_E_OK;
}

static int
test_random (gpointer data, guint8 *out, gsize len)
{
  TestRuntime *t = data;
  t->rng_calls++;
  record_event (t, 'R');
  if (t->fail_rng)
    return -1;
  for (gsize i = 0; i < len; i++)
    out[i] = i < WYL_SERVICE_CREDENTIAL_SECRET_BYTES ? (guint8) (0x20 + i)
        : (guint8) (0x10 + i - WYL_SERVICE_CREDENTIAL_SECRET_BYTES);
  return 0;
}

static wyl_service_credential_runtime_t
make_runtime (TestRuntime *state)
{
  return (wyl_service_credential_runtime_t) {
  .secure_alloc = test_alloc,.secure_lock = test_lock,.secure_wipe =
        test_wipe,.secure_unlock = test_unlock,.secure_free =
        test_free,.new_id = test_new_id,.fill_random = test_random,.data =
        state,};
}

static void
assert_last_events (const TestRuntime *state, const gchar *expected)
{
  gsize len = strlen (expected);
  g_assert_cmpuint (state->n_events, >=, len);
  g_assert_cmpmem (state->events + state->n_events - len, len, expected, len);
}

static void
test_deterministic_generate_and_snapshot (void)
{
  TestRuntime state = { 0 };
  wyl_service_credential_runtime_t runtime = make_runtime (&state);
  guint8 cvk[WYL_SERVICE_CREDENTIAL_CVK_BYTES];
  guint8 salt[WYL_SERVICE_CREDENTIAL_SALT_BYTES];
  fill_fixture (cvk, salt);
  wyl_service_credential_material_t material;
  memset (&material, 0xa5, sizeof material);
  wyl_service_credential_secret_t *secret = NULL;
  g_assert_cmpint (wyl_service_credential_generate_with_runtime (cvk,
          sizeof cvk, "tenant-a", 8, "svc:tenant-a:worker", 19, &runtime,
          &material, &secret), ==, WYRELOG_E_OK);
  g_assert_cmpuint (state.id_calls, ==, 1);
  g_assert_cmpuint (state.rng_calls, ==, 1);
  g_assert_cmpmem (material.salt, sizeof material.salt, salt, sizeof salt);
  g_assert_cmpmem (material.verifier, sizeof material.verifier,
      fixture_digest, sizeof fixture_digest);
  gsize text_len = 0;
  g_assert_cmpstr (wyl_service_credential_secret_peek_encoded (secret,
          &text_len), ==, FIXTURE_SECRET);
  g_assert_cmpuint (text_len, ==, strlen (FIXTURE_SECRET));

  /* The object owns a callback snapshot; changing the caller's table must not
   * affect destruction. */
  memset (&runtime, 0, sizeof runtime);
  guint frees_before = state.frees;
  guint unlocks_before = state.unlocks;
  wyl_service_credential_secret_clear (&secret);
  g_assert_cmpuint (state.frees, ==, frees_before + 1);
  g_assert_cmpuint (state.unlocks, ==, unlocks_before + 1);
  assert_last_events (&state, "WUF");
  wyl_service_credential_material_clear (&material);
  g_assert_true (sodium_is_zero ((const guint8 *) &material, sizeof material));
}

static void
assert_generate_failure (TestRuntime *state, wyrelog_error_t expected)
{
  wyl_service_credential_runtime_t runtime = make_runtime (state);
  guint8 cvk[WYL_SERVICE_CREDENTIAL_CVK_BYTES] = { 0 };
  wyl_service_credential_material_t material;
  memset (&material, 0xa5, sizeof material);
  wyl_service_credential_material_t before = material;
  wyl_service_credential_secret_t *secret = NULL;
  g_assert_cmpint (wyl_service_credential_generate_with_runtime (cvk,
          sizeof cvk, "tenant-a", 8, "svc:tenant-a:worker", 19, &runtime,
          &material, &secret), ==, expected);
  g_assert_cmpmem (&material, sizeof material, &before, sizeof before);
  g_assert_null (secret);
}

static void
test_failure_cleanup_and_transactionality (void)
{
  TestRuntime alloc_failure = {.fail_alloc_at = 1 };
  assert_generate_failure (&alloc_failure, WYRELOG_E_NOMEM);
  g_assert_cmpuint (alloc_failure.frees, ==, 0);

  TestRuntime lock_failure = {.fail_lock_at = 1 };
  assert_generate_failure (&lock_failure, WYRELOG_E_NOMEM);
  g_assert_cmpuint (lock_failure.wipes, ==, 1);
  g_assert_cmpuint (lock_failure.unlocks, ==, 0);
  g_assert_cmpuint (lock_failure.frees, ==, 1);

  TestRuntime second_alloc_failure = {.fail_alloc_at = 2 };
  assert_generate_failure (&second_alloc_failure, WYRELOG_E_NOMEM);
  g_assert_cmpuint (second_alloc_failure.allocs, ==, 2);
  g_assert_cmpuint (second_alloc_failure.unlocks, ==, 1);
  g_assert_cmpuint (second_alloc_failure.frees, ==, 1);
  assert_last_events (&second_alloc_failure, "WUF");

  TestRuntime second_lock_failure = {.fail_lock_at = 2 };
  assert_generate_failure (&second_lock_failure, WYRELOG_E_NOMEM);
  g_assert_cmpuint (second_lock_failure.locks, ==, 2);
  g_assert_cmpuint (second_lock_failure.unlocks, ==, 1);
  g_assert_cmpuint (second_lock_failure.frees, ==, 2);
  assert_last_events (&second_lock_failure, "WUF");

  TestRuntime third_alloc_failure = {.fail_alloc_at = 3 };
  assert_generate_failure (&third_alloc_failure, WYRELOG_E_NOMEM);
  g_assert_cmpuint (third_alloc_failure.allocs, ==, 3);
  g_assert_cmpuint (third_alloc_failure.unlocks, ==, 2);
  g_assert_cmpuint (third_alloc_failure.frees, ==, 2);
  assert_last_events (&third_alloc_failure, "WUF");

  TestRuntime third_lock_failure = {.fail_lock_at = 3 };
  assert_generate_failure (&third_lock_failure, WYRELOG_E_NOMEM);
  g_assert_cmpuint (third_lock_failure.locks, ==, 3);
  g_assert_cmpuint (third_lock_failure.unlocks, ==, 2);
  g_assert_cmpuint (third_lock_failure.frees, ==, 3);
  assert_last_events (&third_lock_failure, "WUF");

  TestRuntime rng_failure = {.fail_rng = TRUE };
  assert_generate_failure (&rng_failure, WYRELOG_E_CRYPTO);
  g_assert_cmpuint (rng_failure.rng_calls, ==, 1);
  g_assert_cmpuint (rng_failure.unlocks, ==, 1);
  g_assert_cmpuint (rng_failure.frees, ==, 1);

  TestRuntime id_failure = {.fail_id = TRUE };
  assert_generate_failure (&id_failure, WYRELOG_E_INTERNAL);
  g_assert_cmpuint (id_failure.allocs, ==, 0);

  TestRuntime invalid_id = {.invalid_id = TRUE };
  assert_generate_failure (&invalid_id, WYRELOG_E_INVALID);
  g_assert_cmpuint (invalid_id.id_calls, ==, 1);
  g_assert_cmpuint (invalid_id.allocs, ==, 0);

  TestRuntime incomplete_state = { 0 };
  wyl_service_credential_runtime_t incomplete =
      make_runtime (&incomplete_state);
  incomplete.secure_unlock = NULL;
  wyl_service_credential_secret_t *secret = NULL;
  g_assert_cmpint (wyl_service_credential_secret_parse_with_runtime
      (WYL_SERVICE_CREDENTIAL_FORMAT_VERSION, FIXTURE_SECRET,
          strlen (FIXTURE_SECRET), &incomplete, &secret), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpuint (incomplete_state.allocs, ==, 0);

  TestRuntime prevalidation = { 0 };
  wyl_service_credential_runtime_t runtime = make_runtime (&prevalidation);
  guint8 short_cvk[WYL_SERVICE_CREDENTIAL_CVK_BYTES - 1] = { 0 };
  wyl_service_credential_material_t material = { 0 };
  secret = NULL;
  g_assert_cmpint (wyl_service_credential_generate_with_runtime (short_cvk,
          sizeof short_cvk, "tenant-a", 8, "svc:tenant-a:worker", 19,
          &runtime, &material, &secret), ==, WYRELOG_E_INVALID);
  g_assert_cmpuint (prevalidation.id_calls, ==, 0);
  g_assert_cmpuint (prevalidation.rng_calls, ==, 0);
  g_assert_cmpuint (prevalidation.allocs, ==, 0);

  gboolean match = TRUE;
  guint8 salt[WYL_SERVICE_CREDENTIAL_SALT_BYTES] = { 0 };
  guint8 expected[WYL_SERVICE_CREDENTIAL_VERIFIER_BYTES] = { 0 };
  g_assert_cmpint (wyl_service_credential_verify_with_runtime (2, 1,
          expected, sizeof expected, FIXTURE_ID, strlen (FIXTURE_ID),
          "tenant-a", 8, "svc:tenant-a:worker", 19, salt, sizeof salt,
          expected, sizeof expected, FIXTURE_SECRET, strlen (FIXTURE_SECRET),
          &runtime, &match), ==, WYRELOG_E_INVALID);
  g_assert_true (match);
  g_assert_cmpuint (prevalidation.allocs, ==, 0);

  match = TRUE;
  g_assert_cmpint (wyl_service_credential_verify_with_runtime (1, 2,
          expected, sizeof expected, FIXTURE_ID, strlen (FIXTURE_ID),
          "tenant-a", 8, "svc:tenant-a:worker", 19, salt, sizeof salt,
          expected, sizeof expected, FIXTURE_SECRET, strlen (FIXTURE_SECRET),
          &runtime, &match), ==, WYRELOG_E_INVALID);
  g_assert_true (match);
  g_assert_cmpuint (prevalidation.n_events, ==, 0);

  TestRuntime malformed_state = { 0 };
  wyl_service_credential_runtime_t malformed_runtime =
      make_runtime (&malformed_state);
  const gchar *noncanonical = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9";
  match = TRUE;
  g_assert_cmpint (wyl_service_credential_verify_with_runtime (1, 1,
          expected, sizeof expected, FIXTURE_ID, strlen (FIXTURE_ID),
          "tenant-a", 8, "svc:tenant-a:worker", 19, salt, sizeof salt,
          expected, sizeof expected, noncanonical, strlen (noncanonical),
          &malformed_runtime, &match), ==, WYRELOG_E_INVALID);
  g_assert_true (match);
  assert_last_events (&malformed_state, "WUF");
}

static void
test_version_bounds_and_unchanged_outputs (void)
{
  guint8 cvk[WYL_SERVICE_CREDENTIAL_CVK_BYTES];
  guint8 salt[WYL_SERVICE_CREDENTIAL_SALT_BYTES];
  fill_fixture (cvk, salt);
  wyl_service_credential_secret_t *secret = parse_fixture_secret ();
  guint8 out[WYL_SERVICE_CREDENTIAL_VERIFIER_BYTES];
  memset (out, 0xa5, sizeof out);
  guint8 before[sizeof out];
  memcpy (before, out, sizeof out);
  g_assert_cmpint (wyl_service_credential_verifier_compute (2, cvk,
          sizeof cvk, FIXTURE_ID, strlen (FIXTURE_ID), "tenant-a", 8,
          "svc:tenant-a:worker", 19, salt, sizeof salt, secret, out,
          sizeof out), ==, WYRELOG_E_INVALID);
  g_assert_cmpmem (out, sizeof out, before, sizeof before);

  g_assert_cmpint (wyl_service_credential_verifier_compute (1, cvk,
          sizeof cvk, FIXTURE_ID, strlen (FIXTURE_ID), "a", 1, "svc:a", 5,
          salt, sizeof salt, secret, out, sizeof out), ==, WYRELOG_E_OK);

  const gchar embedded_nul[] = { 'a', '\0', 'b' };
  const gchar invalid_utf8[] = { (gchar) 0xc3, '(' };
  memset (out, 0xa5, sizeof out);
  memcpy (before, out, sizeof out);
  g_assert_cmpint (wyl_service_credential_verifier_compute (1, cvk,
          sizeof cvk, FIXTURE_ID, strlen (FIXTURE_ID), embedded_nul,
          sizeof embedded_nul, "svc:a", 5, salt, sizeof salt, secret, out,
          sizeof out), ==, WYRELOG_E_INVALID);
  g_assert_cmpmem (out, sizeof out, before, sizeof before);
  g_assert_cmpint (wyl_service_credential_verifier_compute (1, cvk,
          sizeof cvk, FIXTURE_ID, strlen (FIXTURE_ID), invalid_utf8,
          sizeof invalid_utf8, "svc:a", 5, salt, sizeof salt, secret, out,
          sizeof out), ==, WYRELOG_E_INVALID);
  g_assert_cmpmem (out, sizeof out, before, sizeof before);
  g_assert_cmpint (wyl_service_credential_verifier_compute (1, cvk,
          sizeof cvk, FIXTURE_ID, strlen (FIXTURE_ID), "", 0, "svc:a", 5,
          salt, sizeof salt, secret, out, sizeof out), ==, WYRELOG_E_INVALID);
  g_assert_cmpmem (out, sizeof out, before, sizeof before);
  g_assert_cmpint (wyl_service_credential_verifier_compute (1, cvk,
          sizeof cvk, FIXTURE_ID, strlen (FIXTURE_ID), "a", 1, "svc:", 4,
          salt, sizeof salt, secret, out, sizeof out), ==, WYRELOG_E_INVALID);
  g_assert_cmpmem (out, sizeof out, before, sizeof before);

  gboolean match = TRUE;
  g_assert_cmpint (wyl_service_credential_verify (2,
          WYL_SERVICE_CREDENTIAL_VERIFIER_VERSION, cvk, sizeof cvk,
          FIXTURE_ID, strlen (FIXTURE_ID), "tenant-a", 8,
          "svc:tenant-a:worker", 19, salt, sizeof salt, fixture_digest,
          sizeof fixture_digest, FIXTURE_SECRET, strlen (FIXTURE_SECRET),
          &match), ==, WYRELOG_E_INVALID);
  g_assert_true (match);

  gchar too_long[WYL_SERVICE_CREDENTIAL_BINDING_MAX_BYTES + 1];
  memset (too_long, 'x', sizeof too_long);
  g_assert_cmpint (wyl_service_credential_verifier_compute
      (WYL_SERVICE_CREDENTIAL_VERIFIER_VERSION, cvk, sizeof cvk, FIXTURE_ID,
          strlen (FIXTURE_ID), too_long, sizeof too_long, "svc:tenant-a:worker",
          19, salt, sizeof salt, secret, out, sizeof out), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpmem (out, sizeof out, before, sizeof before);
  wyl_service_credential_secret_clear (&secret);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_assert_cmpint (sodium_init (), >=, 0);
  g_test_add_func ("/service-credential/kat-and-verify", test_kat_and_verify);
  g_test_add_func ("/service-credential/transcript-binding",
      test_transcript_field_binding);
  g_test_add_func ("/service-credential/id-contract", test_id_contract);
  g_test_add_func ("/service-credential/secret-codec",
      test_secret_codec_contract);
  g_test_add_func ("/service-credential/generate-snapshot",
      test_deterministic_generate_and_snapshot);
  g_test_add_func ("/service-credential/failure-cleanup",
      test_failure_cleanup_and_transactionality);
  g_test_add_func ("/service-credential/version-bounds",
      test_version_bounds_and_unchanged_outputs);
  return g_test_run ();
}

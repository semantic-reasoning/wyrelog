/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef G_OS_WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif
#include <glib.h>
#include <glib/gstdio.h>
#include <sodium.h>
#include <sqlite3.h>
#include <string.h>
#ifndef G_OS_WIN32
#include <unistd.h>
#endif

#include "auth/service-credential-private.h"
#include "policy/store-private.h"

#define ENVELOPE_BYTES 124u
#define CVK_OFFSET 92u
#define FIXTURE_ID "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv"
#define FIXTURE_SECRET "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"

typedef struct
{
  gchar events[512];
  guint n_events;
} SharedTrace;

typedef struct
{
  guint8 seed;
  guint probes;
  guint derives;
  guint seals;
  guint unseals;
  guint clears;
  guint wipes;
  guint binding_derives;
  guint store_derives;
  gboolean fail_binding_derive;
  gboolean fail_store_derive;
  gboolean fail_probe;
  gboolean fail_seal;
  gboolean fail_unseal;
  gssize unseal_written_override;
  SharedTrace *trace;
} TestProvider;

static void
trace_event (SharedTrace *trace, gchar value)
{
  if (trace == NULL)
    return;
  g_assert_cmpuint (trace->n_events, <, G_N_ELEMENTS (trace->events));
  trace->events[trace->n_events++] = value;
}

static wyrelog_error_t
provider_probe (gpointer data)
{
  TestProvider *p = data;
  p->probes++;
  return p->fail_probe ? WYRELOG_E_CRYPTO : WYRELOG_E_OK;
}

static wyrelog_error_t
provider_derive (gpointer data, const gchar *label, guint8 *out, gsize len)
{
  TestProvider *p = data;
  p->derives++;
  g_assert_cmpuint (len, ==, 32);
  if (g_str_equal (label, "wyrelog.service-credential.cvk.provider-binding.v1")) {
    p->binding_derives++;
    if (p->fail_binding_derive)
      return WYRELOG_E_CRYPTO;
    for (gsize i = 0; i < len; i++)
      out[i] = (guint8) (p->seed + i);
  } else {
    p->store_derives++;
    g_assert_cmpstr (label, ==, "policy_store_v1");
    if (p->fail_store_derive)
      return WYRELOG_E_CRYPTO;
    for (gsize i = 0; i < len; i++)
      out[i] = (guint8) (0x40 + p->seed + i);
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
provider_seal (gpointer data, const guint8 *plaintext, gsize len,
    wyl_sealed_blob_t *out)
{
  TestProvider *p = data;
  p->seals++;
  *out = (wyl_sealed_blob_t) {
  0};
  if (p->fail_seal)
    return WYRELOG_E_CRYPTO;
  out->bytes = g_malloc (len);
  out->len = len;
  for (gsize i = 0; i < len; i++)
    out->bytes[i] = plaintext[i] ^ 0xa5;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
provider_unseal (gpointer data, const wyl_sealed_blob_t *blob, guint8 *out,
    gsize capacity, gsize *written)
{
  TestProvider *p = data;
  p->unseals++;
  if (p->fail_unseal)
    return WYRELOG_E_CRYPTO;
  if (capacity < blob->len)
    return WYRELOG_E_INVALID;
  for (gsize i = 0; i < blob->len; i++)
    out[i] = blob->bytes[i] ^ 0xa5;
  *written = p->unseal_written_override > 0
      ? (gsize) p->unseal_written_override : blob->len;
  return WYRELOG_E_OK;
}

static void
provider_wipe (gpointer data)
{
  TestProvider *p = data;
  p->wipes++;
  trace_event (p->trace, 'P');
}

static void
provider_clear (gpointer data, wyl_sealed_blob_t *blob)
{
  TestProvider *p = data;
  p->clears++;
  if (blob != NULL && blob->bytes != NULL) {
    sodium_memzero (blob->bytes, blob->len);
    g_free (blob->bytes);
  }
  if (blob != NULL)
    *blob = (wyl_sealed_blob_t) {
    0};
}

static const wyl_keyprovider_vtable_t provider_vtable = {
  .probe = provider_probe,
  .seal = provider_seal,
  .unseal = provider_unseal,
  .derive = provider_derive,
  .wipe = provider_wipe,
  .clear_sealed_blob = provider_clear,
};

typedef struct
{
  guint allocs;
  guint locks;
  guint wipes;
  guint unlocks;
  guint frees;
  guint rng_calls;
  guint clock_calls;
  guint fail_alloc_at;
  guint fail_lock_at;
  gboolean fail_rng;
  gchar events[256];
  guint n_events;
  SharedTrace *trace;
} TestRuntime;

static void
event (TestRuntime *r, gchar value)
{
  g_assert_cmpuint (r->n_events, <, G_N_ELEMENTS (r->events));
  r->events[r->n_events++] = value;
  trace_event (r->trace, value);
}

static gpointer
runtime_alloc (gpointer data, gsize size)
{
  TestRuntime *r = data;
  r->allocs++;
  event (r, 'A');
  return r->fail_alloc_at == r->allocs ? NULL : g_malloc (size);
}

static int
runtime_lock (gpointer data, gpointer ptr, gsize size)
{
  TestRuntime *r = data;
  (void) ptr;
  (void) size;
  r->locks++;
  event (r, 'L');
  return r->fail_lock_at == r->locks ? -1 : 0;
}

static void
runtime_wipe (gpointer data, gpointer ptr, gsize size)
{
  TestRuntime *r = data;
  r->wipes++;
  event (r, 'W');
  sodium_memzero (ptr, size);
}

static int
runtime_unlock (gpointer data, gpointer ptr, gsize size)
{
  TestRuntime *r = data;
  (void) ptr;
  (void) size;
  r->unlocks++;
  event (r, 'U');
  return 0;
}

static void
runtime_free (gpointer data, gpointer ptr)
{
  TestRuntime *r = data;
  r->frees++;
  event (r, 'F');
  g_free (ptr);
}

static int
runtime_random (gpointer data, guint8 *out, gsize len)
{
  TestRuntime *r = data;
  r->rng_calls++;
  event (r, 'R');
  if (r->fail_rng)
    return -1;
  g_assert_cmpuint (len, ==, 32);
  for (gsize i = 0; i < len; i++)
    out[i] = (guint8) (0x80 + i);
  return 0;
}

static gint64
runtime_now (gpointer data)
{
  TestRuntime *r = data;
  r->clock_calls++;
  event (r, 'T');
  return 123456789;
}

static wyl_policy_store_cvk_runtime_t
make_runtime (TestRuntime *state)
{
  return (wyl_policy_store_cvk_runtime_t) {
  .secure_alloc = runtime_alloc,.secure_lock = runtime_lock,.secure_wipe =
        runtime_wipe,.secure_unlock = runtime_unlock,.secure_free =
        runtime_free,.fill_random = runtime_random,.now_us =
        runtime_now,.data = state,};
}

static wyrelog_error_t
open_store (const gchar *path, TestProvider *provider, TestRuntime *state,
    wyl_policy_store_t **out)
{
  wyl_policy_store_cvk_runtime_t runtime = make_runtime (state);
  wyl_policy_store_open_options_t opts = {
    .path = path,
    .keyprovider_vtable = &provider_vtable,
    .keyprovider_state = provider,
    .require_encrypted = path != NULL,
    .service_cvk_runtime = &runtime,
  };
  return wyl_policy_store_open_with_options (&opts, out);
}

static void
expected_binding (guint8 out[32])
{
  guint8 key[32];
  for (guint i = 0; i < sizeof key; i++)
    key[i] = (guint8) i;
  crypto_generichash_state state;
  g_assert_cmpint (crypto_generichash_init (&state, key, sizeof key, 32), ==,
      0);
  const gchar *domain = "wyrelog.service-credential.cvk.provider-binding";
  g_assert_cmpint (crypto_generichash_update (&state,
          (const guint8 *) domain, strlen (domain)), ==, 0);
  const guint8 suffix[] = { 0, 1 };
  g_assert_cmpint (crypto_generichash_update (&state, suffix, sizeof suffix),
      ==, 0);
  g_assert_cmpint (crypto_generichash_final (&state, out, 32), ==, 0);
  sodium_memzero (&state, sizeof state);
  sodium_memzero (key, sizeof key);
}

static void
expected_envelope (guint8 out[ENVELOPE_BYTES])
{
  memset (out, 0, ENVELOPE_BYTES);
  memcpy (out, "WYLCVK1\0", 8);
  memcpy (out + 8, "wyrelog.service-credential.cvk-envelope", 40);
  out[48] = 1;
  out[49] = 1;
  out[57] = 1;
  expected_binding (out + 58);
  out[90] = 0;
  out[91] = 32;
  for (guint i = 0; i < 32; i++)
    out[CVK_OFFSET + i] = (guint8) (0x80 + i);
}

typedef struct
{
  wyl_policy_store_t *store;
  GMutex *mutex;
  GCond *cond;
  guint *ready;
  gboolean *go;
  wyrelog_error_t rc;
  const guint8 *cvk;
  gsize len;
} EnsureThread;

static gpointer
ensure_thread (gpointer data)
{
  EnsureThread *t = data;
  g_mutex_lock (t->mutex);
  (*t->ready)++;
  g_cond_broadcast (t->cond);
  while (!*t->go)
    g_cond_wait (t->cond, t->mutex);
  g_mutex_unlock (t->mutex);
  t->rc = wyl_policy_store_ensure_service_cvk_for_issuance (t->store,
      &t->cvk, &t->len);
  return NULL;
}

static gboolean
contains_bytes (const guint8 *haystack, gsize haystack_len,
    const guint8 *needle, gsize needle_len)
{
  if (needle_len > haystack_len)
    return FALSE;
  for (gsize i = 0; i <= haystack_len - needle_len; i++)
    if (memcmp (haystack + i, needle, needle_len) == 0)
      return TRUE;
  return FALSE;
}

static void
assert_file_omits (const gchar *path, const guint8 *needle, gsize needle_len)
{
  g_autofree gchar *contents = NULL;
  gsize len = 0;
  g_assert_true (g_file_get_contents (path, &contents, &len, NULL));
  g_assert_false (contains_bytes ((const guint8 *) contents, len, needle,
          needle_len));
}

static void
test_fixture_concurrency_and_reopen (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-cvk-XXXXXX", NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
  TestProvider provider = { 0 };
  TestRuntime runtime = { 0 };
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (open_store (path, &provider, &runtime, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  const guint8 *missing = (const guint8 *) 0x1;
  gsize missing_len = 99;
  g_assert_cmpint (wyl_policy_store_materialize_service_cvk_existing (store,
          &missing, &missing_len), ==, WYRELOG_E_NOT_FOUND);
  g_assert_null (missing);
  g_assert_cmpuint (missing_len, ==, 0);

  GMutex mutex;
  GCond cond;
  g_mutex_init (&mutex);
  g_cond_init (&cond);
  guint ready = 0;
  gboolean go = FALSE;
  EnsureThread calls[8];
  GThread *threads[8];
  for (guint i = 0; i < G_N_ELEMENTS (calls); i++) {
    calls[i] = (EnsureThread) {
    .store = store,.mutex = &mutex,.cond = &cond,.ready = &ready,.go = &go,};
    threads[i] = g_thread_new ("cvk-ensure", ensure_thread, &calls[i]);
  }
  g_mutex_lock (&mutex);
  while (ready != G_N_ELEMENTS (calls))
    g_cond_wait (&cond, &mutex);
  go = TRUE;
  g_cond_broadcast (&cond);
  g_mutex_unlock (&mutex);
  for (guint i = 0; i < G_N_ELEMENTS (calls); i++) {
    g_thread_join (threads[i]);
    g_assert_cmpint (calls[i].rc, ==, WYRELOG_E_OK);
    g_assert_cmpuint (calls[i].len, ==, 32);
    g_assert_true (calls[i].cvk == calls[0].cvk);
  }
  g_mutex_clear (&mutex);
  g_cond_clear (&cond);
  g_assert_cmpuint (runtime.rng_calls, ==, 1);
  g_assert_cmpuint (provider.seals, ==, 1);

  wyl_policy_service_cvk_info_t info = { 0 };
  g_assert_cmpint (wyl_policy_store_load_service_cvk (store, &info), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (info.sealed_cvk_len, ==, ENVELOPE_BYTES);
  guint8 decoded[ENVELOPE_BYTES];
  for (guint i = 0; i < sizeof decoded; i++)
    decoded[i] = info.sealed_cvk[i] ^ 0xa5;
  guint8 expected[ENVELOPE_BYTES];
  expected_envelope (expected);
  g_assert_cmpmem (decoded, sizeof decoded, expected, sizeof expected);
  g_assert_false (contains_bytes (info.sealed_cvk, info.sealed_cvk_len,
          expected + CVK_OFFSET, 32));
  wyl_policy_service_cvk_info_clear (&info);
  g_autofree gchar *work_path = g_strdup_printf ("%s.wyrelog-clear", path);
  g_assert_false (g_file_test (work_path, G_FILE_TEST_EXISTS));

  g_assert_cmpint (wyl_policy_store_begin_mutation (store), ==, WYRELOG_E_OK);
  missing = (const guint8 *) 0x1;
  missing_len = 99;
  g_assert_cmpint (wyl_policy_store_ensure_service_cvk_for_issuance (store,
          &missing, &missing_len), ==, WYRELOG_E_BUSY);
  g_assert_null (missing);
  g_assert_cmpuint (missing_len, ==, 0);
  wyl_policy_store_rollback_mutation (store);
  wyl_policy_store_close (store);
  assert_file_omits (path, expected + CVK_OFFSET, 32);

  TestProvider reopened_provider = { 0 };
  TestRuntime reopened_runtime = { 0 };
  SharedTrace close_trace = { 0 };
  reopened_provider.trace = &close_trace;
  reopened_runtime.trace = &close_trace;
  store = NULL;
  g_assert_cmpint (open_store (path, &reopened_provider, &reopened_runtime,
          &store), ==, WYRELOG_E_OK);
  g_mutex_init (&mutex);
  g_cond_init (&cond);
  ready = 0;
  go = FALSE;
  for (guint i = 0; i < G_N_ELEMENTS (calls); i++) {
    calls[i] = (EnsureThread) {
    .store = store,.mutex = &mutex,.cond = &cond,.ready = &ready,.go = &go,};
    threads[i] = g_thread_new ("cvk-reopen", ensure_thread, &calls[i]);
  }
  g_mutex_lock (&mutex);
  while (ready != G_N_ELEMENTS (calls))
    g_cond_wait (&cond, &mutex);
  go = TRUE;
  g_cond_broadcast (&cond);
  g_mutex_unlock (&mutex);
  for (guint i = 0; i < G_N_ELEMENTS (calls); i++) {
    g_thread_join (threads[i]);
    g_assert_cmpint (calls[i].rc, ==, WYRELOG_E_OK);
    g_assert_true (calls[i].cvk == calls[0].cvk);
  }
  g_mutex_clear (&mutex);
  g_cond_clear (&cond);
  const guint8 *reopened_cvk = calls[0].cvk;
  gsize reopened_len = calls[0].len;
  g_assert_cmpuint (reopened_runtime.rng_calls, ==, 0);
  g_assert_cmpuint (reopened_provider.binding_derives, ==, 1);
  g_assert_cmpuint (reopened_provider.unseals, ==, 1);
  g_assert_cmpmem (reopened_cvk, reopened_len, expected + CVK_OFFSET, 32);

  wyl_service_credential_secret_t *parsed = NULL;
  g_assert_cmpint (wyl_service_credential_secret_parse (1, FIXTURE_SECRET,
          strlen (FIXTURE_SECRET), &parsed), ==, WYRELOG_E_OK);
  wyl_policy_service_credential_info_t credential = {
    .credential_id = (gchar *) FIXTURE_ID,
    .credential_format_version = 1,
    .subject_id = (gchar *) "svc:tenant-a:worker",
    .tenant_id = (gchar *) "tenant-a",
    .verifier_version = 1,
  };
  for (guint i = 0; i < sizeof credential.salt; i++)
    credential.salt[i] = (guint8) (0x10 + i);
  g_assert_cmpint (wyl_service_credential_verifier_compute (1, reopened_cvk,
          reopened_len, credential.credential_id,
          strlen (credential.credential_id), credential.tenant_id,
          strlen (credential.tenant_id), credential.subject_id,
          strlen (credential.subject_id), credential.salt,
          sizeof credential.salt, parsed, credential.verifier,
          sizeof credential.verifier), ==, WYRELOG_E_OK);
  wyl_service_credential_secret_clear (&parsed);
  gboolean match = FALSE;
  g_assert_cmpint (wyl_policy_store_verify_service_credential_secret (store,
          &credential, FIXTURE_SECRET, strlen (FIXTURE_SECRET), &match), ==,
      WYRELOG_E_OK);
  g_assert_true (match);
  credential.verifier_version = 2;
  match = TRUE;
  g_assert_cmpint (wyl_policy_store_verify_service_credential_secret (store,
          &credential, FIXTURE_SECRET, strlen (FIXTURE_SECRET), &match), ==,
      WYRELOG_E_POLICY);
  g_assert_true (match);
  g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (store),
          "UPDATE service_credential_cvk SET envelope_format_version=2;",
          NULL, NULL, NULL), ==, SQLITE_OK);
  close_trace.n_events = 0;
  wyl_policy_store_close (store);
  g_assert_cmpuint (close_trace.n_events, >=, 4);
  g_assert_cmpmem (close_trace.events + close_trace.n_events - 4, 4, "WUFP", 4);

  TestProvider version_provider = { 0 };
  TestRuntime version_runtime = { 0 };
  store = NULL;
  g_assert_cmpint (open_store (path, &version_provider, &version_runtime,
          &store), ==, WYRELOG_E_OK);
  const guint8 *bad_version_cvk = (const guint8 *) 0x1;
  gsize bad_version_len = 99;
  g_assert_cmpint (wyl_policy_store_materialize_service_cvk_existing (store,
          &bad_version_cvk, &bad_version_len), ==, WYRELOG_E_POLICY);
  g_assert_null (bad_version_cvk);
  g_assert_cmpuint (bad_version_len, ==, 0);
  g_assert_cmpuint (version_provider.unseals, ==, 0);
  wyl_policy_store_close (store);
  g_assert_cmpint (g_remove (path), ==, 0);
  g_autofree gchar *lock_path = g_strdup_printf ("%s.wyrelog-lock", path);
  (void) g_remove (lock_path);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

static void
test_absent_with_credentials_is_policy (void)
{
  TestProvider provider = { 0 };
  TestRuntime runtime = { 0 };
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (open_store (NULL, &provider, &runtime, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  const gchar *sql =
      "INSERT INTO tenants VALUES('tenant-a',0,1,1);"
      "INSERT INTO service_principals"
      "(subject_id,display_name,state,generation,created_by,created_at_us,"
      "updated_at_us) VALUES('svc:tenant-a:worker','worker','active',1,"
      "'admin',1,1);"
      "INSERT INTO service_credentials"
      "(credential_id,credential_format_version,subject_id,tenant_id,"
      "generation,state,verifier_version,salt,verifier,created_by,"
      "created_at_us,updated_at_us) VALUES('" FIXTURE_ID
      "',1,'svc:tenant-a:worker','tenant-a',1,'active',1,zeroblob(16),"
      "zeroblob(32),'admin',1,1);";
  g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (store), sql, NULL,
          NULL, NULL), ==, SQLITE_OK);
  const guint8 *cvk = (const guint8 *) 0x1;
  gsize len = 99;
  g_assert_cmpint (wyl_policy_store_ensure_service_cvk_for_issuance (store,
          &cvk, &len), ==, WYRELOG_E_POLICY);
  g_assert_null (cvk);
  g_assert_cmpuint (len, ==, 0);
  g_assert_cmpuint (runtime.rng_calls, ==, 0);
  g_assert_cmpuint (provider.seals, ==, 0);
  wyl_policy_store_close (store);
}

static void
assert_ensure_failure (TestRuntime *runtime, TestProvider *provider,
    wyrelog_error_t expected)
{
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (open_store (NULL, provider, runtime, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  const guint8 *cvk = (const guint8 *) 0x1;
  gsize len = 99;
  g_assert_cmpint (wyl_policy_store_ensure_service_cvk_for_issuance (store,
          &cvk, &len), ==, expected);
  g_assert_null (cvk);
  g_assert_cmpuint (len, ==, 0);
  wyl_policy_store_close (store);
}

static void
test_fault_cleanup (void)
{
  TestProvider provider = { 0 };
  TestRuntime alloc = {.fail_alloc_at = 1 };
  assert_ensure_failure (&alloc, &provider, WYRELOG_E_NOMEM);

  provider = (TestProvider) {
  0};
  TestRuntime lock = {.fail_lock_at = 1 };
  assert_ensure_failure (&lock, &provider, WYRELOG_E_NOMEM);
  g_assert_cmpuint (lock.unlocks, ==, 0);
  g_assert_cmpuint (lock.frees, ==, 1);

  provider = (TestProvider) {
  0};
  TestRuntime second_alloc = {.fail_alloc_at = 2 };
  assert_ensure_failure (&second_alloc, &provider, WYRELOG_E_NOMEM);
  g_assert_cmpuint (second_alloc.allocs, ==, 2);
  g_assert_cmpuint (second_alloc.unlocks, ==, 1);
  g_assert_cmpuint (second_alloc.frees, ==, 1);

  provider = (TestProvider) {
  0};
  TestRuntime second_lock = {.fail_lock_at = 2 };
  assert_ensure_failure (&second_lock, &provider, WYRELOG_E_NOMEM);
  g_assert_cmpuint (second_lock.locks, ==, 2);
  g_assert_cmpuint (second_lock.unlocks, ==, 1);
  g_assert_cmpuint (second_lock.frees, ==, 2);

  provider = (TestProvider) {
  0};
  TestRuntime third_alloc = {.fail_alloc_at = 3 };
  assert_ensure_failure (&third_alloc, &provider, WYRELOG_E_NOMEM);
  g_assert_cmpuint (third_alloc.allocs, ==, 3);
  g_assert_cmpuint (third_alloc.unlocks, ==, 2);
  g_assert_cmpuint (third_alloc.frees, ==, 2);

  provider = (TestProvider) {
  0};
  TestRuntime third_lock = {.fail_lock_at = 3 };
  assert_ensure_failure (&third_lock, &provider, WYRELOG_E_NOMEM);
  g_assert_cmpuint (third_lock.locks, ==, 3);
  g_assert_cmpuint (third_lock.unlocks, ==, 2);
  g_assert_cmpuint (third_lock.frees, ==, 3);

  provider = (TestProvider) {
  0};
  TestRuntime rng = {.fail_rng = TRUE };
  assert_ensure_failure (&rng, &provider, WYRELOG_E_CRYPTO);
  g_assert_cmpuint (rng.rng_calls, ==, 1);
  g_assert_cmpuint (provider.seals, ==, 0);
  g_assert_cmpuint (rng.unlocks, ==, rng.frees);

  provider = (TestProvider) {
  .fail_seal = TRUE};
  TestRuntime seal = { 0 };
  assert_ensure_failure (&seal, &provider, WYRELOG_E_CRYPTO);
  g_assert_cmpuint (provider.clears, ==, 1);
  g_assert_cmpuint (seal.unlocks, ==, seal.frees);
  g_assert_cmpuint (seal.n_events, >=, 3);
  g_assert_cmpmem (seal.events + seal.n_events - 3, 3, "WUF", 3);
}

static int
deny_commit (gpointer data, int action, const char *arg1, const char *arg2,
    const char *db_name, const char *trigger)
{
  (void) data;
  (void) arg2;
  (void) db_name;
  (void) trigger;
  return action == SQLITE_TRANSACTION && g_strcmp0 (arg1, "COMMIT") == 0
      ? SQLITE_DENY : SQLITE_OK;
}

static void
test_commit_before_cache (void)
{
  TestProvider provider = { 0 };
  TestRuntime runtime = { 0 };
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (open_store (NULL, &provider, &runtime, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  g_assert_cmpint (sqlite3_set_authorizer (db, deny_commit, NULL), ==,
      SQLITE_OK);
  const guint8 *cvk = (const guint8 *) 0x1;
  gsize len = 99;
  g_assert_cmpint (wyl_policy_store_ensure_service_cvk_for_issuance (store,
          &cvk, &len), ==, WYRELOG_E_IO);
  g_assert_null (cvk);
  g_assert_cmpuint (len, ==, 0);
  g_assert_cmpint (sqlite3_set_authorizer (db, NULL, NULL), ==, SQLITE_OK);
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db,
          "SELECT count(*) FROM service_credential_cvk;", -1, &stmt, NULL),
      ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  g_assert_cmpint (sqlite3_column_int (stmt, 0), ==, 0);
  sqlite3_finalize (stmt);
  g_assert_cmpuint (runtime.rng_calls, ==, 1);
  g_assert_cmpint (wyl_policy_store_ensure_service_cvk_for_issuance (store,
          &cvk, &len), ==, WYRELOG_E_OK);
  g_assert_cmpuint (runtime.rng_calls, ==, 2);
  g_assert_cmpuint (provider.seals, ==, 2);
  g_assert_cmpuint (provider.clears, ==, 2);
  wyl_policy_store_close (store);
}

static void
test_unseal_failure_is_closed (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-cvk-unseal-XXXXXX", NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
  TestProvider provider = { 0 };
  TestRuntime runtime = { 0 };
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (open_store (path, &provider, &runtime, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  const guint8 *cvk = NULL;
  gsize len = 0;
  g_assert_cmpint (wyl_policy_store_ensure_service_cvk_for_issuance (store,
          &cvk, &len), ==, WYRELOG_E_OK);
  wyl_policy_store_close (store);

  TestProvider failing = {.fail_unseal = TRUE };
  TestRuntime reopened_runtime = { 0 };
  store = NULL;
  g_assert_cmpint (open_store (path, &failing, &reopened_runtime, &store), ==,
      WYRELOG_E_OK);
  cvk = (const guint8 *) 0x1;
  len = 99;
  g_assert_cmpint (wyl_policy_store_materialize_service_cvk_existing (store,
          &cvk, &len), ==, WYRELOG_E_CRYPTO);
  g_assert_null (cvk);
  g_assert_cmpuint (len, ==, 0);
  g_assert_cmpuint (failing.unseals, ==, 1);
  wyl_policy_store_close (store);
  g_assert_cmpint (g_remove (path), ==, 0);
  g_autofree gchar *lock_path = g_strdup_printf ("%s.wyrelog-lock", path);
  (void) g_remove (lock_path);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

static void
assert_authenticated_inner_tamper_is_policy (gsize offset, guint8 mask)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-cvk-inner-XXXXXX", NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
  TestProvider provider = { 0 };
  TestRuntime runtime = { 0 };
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (open_store (path, &provider, &runtime, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  const guint8 *cvk = NULL;
  gsize len = 0;
  g_assert_cmpint (wyl_policy_store_ensure_service_cvk_for_issuance (store,
          &cvk, &len), ==, WYRELOG_E_OK);

  wyl_policy_service_cvk_info_t info = { 0 };
  g_assert_cmpint (wyl_policy_store_load_service_cvk (store, &info), ==,
      WYRELOG_E_OK);
  guint8 envelope[ENVELOPE_BYTES];
  gsize written = 0;
  wyl_sealed_blob_t original = {
    .bytes = info.sealed_cvk,
    .len = info.sealed_cvk_len,
  };
  g_assert_cmpint (provider_unseal (&provider, &original, envelope,
          sizeof envelope, &written), ==, WYRELOG_E_OK);
  g_assert_cmpuint (written, ==, sizeof envelope);
  envelope[offset] ^= mask;
  wyl_sealed_blob_t resealed = { 0 };
  g_assert_cmpint (provider_seal (&provider, envelope, sizeof envelope,
          &resealed), ==, WYRELOG_E_OK);
  sodium_memzero (envelope, sizeof envelope);
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db (store),
          "UPDATE service_credential_cvk SET sealed_cvk=? WHERE slot=1;", -1,
          &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_blob (stmt, 1, resealed.bytes,
          (int) resealed.len, SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_DONE);
  sqlite3_finalize (stmt);
  provider_clear (&provider, &resealed);
  wyl_policy_service_cvk_info_clear (&info);
  wyl_policy_store_close (store);

  TestProvider reopened_provider = { 0 };
  TestRuntime reopened_runtime = { 0 };
  store = NULL;
  g_assert_cmpint (open_store (path, &reopened_provider, &reopened_runtime,
          &store), ==, WYRELOG_E_OK);
  cvk = (const guint8 *) 0x1;
  len = 99;
  g_assert_cmpint (wyl_policy_store_materialize_service_cvk_existing (store,
          &cvk, &len), ==, WYRELOG_E_POLICY);
  g_assert_null (cvk);
  g_assert_cmpuint (len, ==, 0);
  g_assert_cmpuint (reopened_provider.unseals, ==, 1);
  wyl_policy_store_close (store);
  g_assert_cmpint (g_remove (path), ==, 0);
  g_autofree gchar *lock_path = g_strdup_printf ("%s.wyrelog-lock", path);
  (void) g_remove (lock_path);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

static void
test_authenticated_inner_tamper_is_policy (void)
{
  assert_authenticated_inner_tamper_is_policy (58, 1);
  assert_authenticated_inner_tamper_is_policy (57, 3);
  assert_authenticated_inner_tamper_is_policy (91, 1);
}

static void
test_providerless_is_policy (void)
{
  TestRuntime runtime = { 0 };
  wyl_policy_store_cvk_runtime_t cvk_runtime = make_runtime (&runtime);
  wyl_policy_store_open_options_t opts = {
    .service_cvk_runtime = &cvk_runtime,
  };
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (wyl_policy_store_open_with_options (&opts, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  const guint8 *cvk = (const guint8 *) 0x1;
  gsize len = 99;
  g_assert_cmpint (wyl_policy_store_materialize_service_cvk_existing (store,
          &cvk, &len), ==, WYRELOG_E_POLICY);
  g_assert_null (cvk);
  g_assert_cmpuint (len, ==, 0);
  cvk = (const guint8 *) 0x1;
  len = 99;
  g_assert_cmpint (wyl_policy_store_ensure_service_cvk_for_issuance (store,
          &cvk, &len), ==, WYRELOG_E_POLICY);
  g_assert_null (cvk);
  g_assert_cmpuint (len, ==, 0);
  g_assert_cmpuint (runtime.allocs, ==, 0);
  g_assert_cmpuint (runtime.rng_calls, ==, 0);
  g_assert_true (sqlite3_get_autocommit (wyl_policy_store_get_db (store)));
  wyl_policy_store_close (store);
}

static void
assert_schema_gate (const gchar *mutation)
{
  TestProvider provider = { 0 };
  TestRuntime runtime = { 0 };
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (open_store (NULL, &provider, &runtime, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (store), mutation,
          NULL, NULL, NULL), ==, SQLITE_OK);
  const guint8 *cvk = (const guint8 *) 0x1;
  gsize len = 99;
  g_assert_cmpint (wyl_policy_store_ensure_service_cvk_for_issuance (store,
          &cvk, &len), ==, WYRELOG_E_POLICY);
  g_assert_null (cvk);
  g_assert_cmpuint (len, ==, 0);
  g_assert_cmpuint (provider.binding_derives, ==, 0);
  g_assert_cmpuint (provider.unseals, ==, 0);
  g_assert_cmpuint (provider.seals, ==, 0);
  g_assert_cmpuint (runtime.rng_calls, ==, 0);
  g_assert_true (sqlite3_get_autocommit (wyl_policy_store_get_db (store)));
  wyl_policy_store_close (store);
}

static void
test_schema_gate_precedes_crypto (void)
{
  assert_schema_gate ("DROP TRIGGER trg_service_credential_events_no_delete;");
  assert_schema_gate ("DROP INDEX idx_service_credentials_tenant_state_expiry;"
      "CREATE INDEX idx_service_credentials_tenant_state_expiry"
      " ON service_credentials(state,tenant_id,expires_at_us);");
  assert_schema_gate
      ("CREATE TRIGGER trg_service_extra BEFORE INSERT ON service_principals"
      " BEGIN SELECT 1; END;");
}

static void
create_persisted_cvk (const gchar *path)
{
  TestProvider provider = { 0 };
  TestRuntime runtime = { 0 };
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (open_store (path, &provider, &runtime, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  const guint8 *cvk = NULL;
  gsize len = 0;
  g_assert_cmpint (wyl_policy_store_ensure_service_cvk_for_issuance (store,
          &cvk, &len), ==, WYRELOG_E_OK);
  wyl_policy_store_close (store);
}

static void
test_binding_and_unseal_boundaries (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-cvk-boundary-XXXXXX", NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
  create_persisted_cvk (path);

  TestProvider provider = {.fail_binding_derive = TRUE };
  TestRuntime runtime = { 0 };
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (open_store (path, &provider, &runtime, &store), ==,
      WYRELOG_E_OK);
  const guint8 *cvk = (const guint8 *) 0x1;
  gsize len = 99;
  g_assert_cmpint (wyl_policy_store_materialize_service_cvk_existing (store,
          &cvk, &len), ==, WYRELOG_E_CRYPTO);
  g_assert_cmpuint (provider.binding_derives, ==, 1);
  g_assert_cmpuint (provider.unseals, ==, 0);
  wyl_policy_store_close (store);

  for (guint i = 0; i < 2; i++) {
    provider = (TestProvider) {
    .unseal_written_override = i == 0 ? 123 : 125};
    runtime = (TestRuntime) {
    0};
    store = NULL;
    g_assert_cmpint (open_store (path, &provider, &runtime, &store), ==,
        WYRELOG_E_OK);
    cvk = (const guint8 *) 0x1;
    len = 99;
    g_assert_cmpint (wyl_policy_store_materialize_service_cvk_existing (store,
            &cvk, &len), ==, WYRELOG_E_CRYPTO);
    g_assert_null (cvk);
    g_assert_cmpuint (provider.unseals, ==, 1);
    wyl_policy_store_close (store);
  }

  provider = (TestProvider) {
  0};
  runtime = (TestRuntime) {
  0};
  store = NULL;
  g_assert_cmpint (open_store (path, &provider, &runtime, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (store),
          "UPDATE service_credential_cvk SET provider_binding=zeroblob(32);",
          NULL, NULL, NULL), ==, SQLITE_OK);
  wyl_policy_store_close (store);
  provider = (TestProvider) {
  0};
  runtime = (TestRuntime) {
  0};
  store = NULL;
  g_assert_cmpint (open_store (path, &provider, &runtime, &store), ==,
      WYRELOG_E_OK);
  cvk = (const guint8 *) 0x1;
  len = 99;
  g_assert_cmpint (wyl_policy_store_materialize_service_cvk_existing (store,
          &cvk, &len), ==, WYRELOG_E_CRYPTO);
  g_assert_cmpuint (provider.unseals, ==, 0);
  wyl_policy_store_close (store);

  g_assert_cmpint (g_remove (path), ==, 0);
  g_autofree gchar *lock_path = g_strdup_printf ("%s.wyrelog-lock", path);
  (void) g_remove (lock_path);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

typedef struct
{
  wyl_policy_store_rotation_stage_t fail_stage;
  guint calls[4];
} RotationFault;

static int
rotation_checkpoint (gpointer data, wyl_policy_store_rotation_stage_t stage)
{
  RotationFault *fault = data;
  fault->calls[stage]++;
  return fault->fail_stage == stage ? -1 : 0;
}

static wyrelog_error_t
rotate_store (const gchar *path, TestProvider *old_provider,
    TestProvider *new_provider, TestRuntime *runtime, RotationFault *fault)
{
  wyl_policy_store_cvk_runtime_t cvk_runtime = make_runtime (runtime);
  wyl_policy_store_rotation_runtime_t rotation_runtime = {
    .checkpoint = rotation_checkpoint,
    .data = fault,
  };
  wyl_policy_store_open_options_t old_opts = {
    .keyprovider_vtable = &provider_vtable,
    .keyprovider_state = old_provider,
    .require_encrypted = TRUE,
    .service_cvk_runtime = &cvk_runtime,
    .rotation_runtime = fault != NULL ? &rotation_runtime : NULL,
  };
  wyl_policy_store_open_options_t new_opts = {
    .keyprovider_vtable = &provider_vtable,
    .keyprovider_state = new_provider,
    .require_encrypted = TRUE,
  };
  return wyl_policy_store_rotate_keyprovider (path, &old_opts, &new_opts);
}

static void
remove_rotation_sidecar (const gchar *path)
{
  g_autofree gchar *sidecar = g_strconcat (path,
      ".wyrelog-rotation-intent", NULL);
  (void) g_remove (sidecar);
}

static void
insert_golden_credential (wyl_policy_store_t *store, const guint8 *cvk,
    gsize cvk_len, guint8 out_salt[16], guint8 out_verifier[32])
{
  for (guint i = 0; i < 16; i++)
    out_salt[i] = (guint8) (0x10 + i);
  wyl_service_credential_secret_t *parsed = NULL;
  g_assert_cmpint (wyl_service_credential_secret_parse (1, FIXTURE_SECRET,
          strlen (FIXTURE_SECRET), &parsed), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_verifier_compute (1, cvk, cvk_len,
          FIXTURE_ID, strlen (FIXTURE_ID), "tenant-a", 8,
          "svc:tenant-a:worker", 19, out_salt, 16, parsed, out_verifier, 32),
      ==, WYRELOG_E_OK);
  wyl_service_credential_secret_clear (&parsed);
  sqlite3 *db = wyl_policy_store_get_db (store);
  g_assert_cmpint (sqlite3_exec (db,
          "INSERT INTO tenants VALUES('tenant-a',0,1,1);"
          "INSERT INTO service_principals(subject_id,display_name,state,"
          "generation,created_by,created_at_us,updated_at_us) VALUES("
          "'svc:tenant-a:worker','worker','active',1,'admin',1,1);",
          NULL, NULL, NULL), ==, SQLITE_OK);
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db,
          "INSERT INTO service_credentials(credential_id,"
          "credential_format_version,subject_id,tenant_id,generation,state,"
          "verifier_version,salt,verifier,created_by,created_at_us,"
          "updated_at_us) VALUES(?,1,'svc:tenant-a:worker','tenant-a',1,"
          "'active',1,?,?,'admin',1,1);", -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, FIXTURE_ID, -1,
          SQLITE_STATIC), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_blob (stmt, 2, out_salt, 16,
          SQLITE_STATIC), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_blob (stmt, 3, out_verifier, 32,
          SQLITE_STATIC), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_DONE);
  sqlite3_finalize (stmt);
  g_assert_cmpint (sqlite3_exec (db,
          "INSERT INTO service_domain_requests "
          "(request_id,operation,resource_id,input_fingerprint,created_at_us) "
          "VALUES('rotation-request','credential_issue',"
          "'svc:tenant-a:worker',zeroblob(32),1);", NULL, NULL, NULL), ==,
      SQLITE_OK);
}

static void
assert_golden_verifies (wyl_policy_store_t *store, const guint8 salt[16],
    const guint8 verifier[32])
{
  sqlite3_stmt *request_stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM service_domain_requests "
          "WHERE request_id='rotation-request' "
          "AND operation='credential_issue';", -1, &request_stmt, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_step (request_stmt), ==, SQLITE_ROW);
  g_assert_cmpint (sqlite3_column_int64 (request_stmt, 0), ==, 1);
  sqlite3_finalize (request_stmt);

  wyl_policy_service_credential_info_t info = { 0 };
  g_assert_cmpint (wyl_policy_store_lookup_service_credential (store,
          FIXTURE_ID, "svc:tenant-a:worker", "tenant-a", &info), ==,
      WYRELOG_E_OK);
  g_assert_cmpmem (info.salt, sizeof info.salt, salt, 16);
  g_assert_cmpmem (info.verifier, sizeof info.verifier, verifier, 32);
  gboolean match = FALSE;
  g_assert_cmpint (wyl_policy_store_verify_service_credential_secret (store,
          &info, FIXTURE_SECRET, strlen (FIXTURE_SECRET), &match), ==,
      WYRELOG_E_OK);
  g_assert_true (match);
  match = TRUE;
  g_assert_cmpint (wyl_policy_store_verify_service_credential_secret (store,
          &info, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 43, &match),
      ==, WYRELOG_E_OK);
  g_assert_false (match);
  wyl_policy_service_credential_info_clear (&info);
}

static void
create_golden_store (const gchar *path, guint8 salt[16], guint8 verifier[32],
    guint8 cvk[32])
{
  TestProvider provider = { 0 };
  TestRuntime runtime = { 0 };
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (open_store (path, &provider, &runtime, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  const guint8 *materialized = NULL;
  gsize len = 0;
  g_assert_cmpint (wyl_policy_store_ensure_service_cvk_for_issuance (store,
          &materialized, &len), ==, WYRELOG_E_OK);
  memcpy (cvk, materialized, 32);
  insert_golden_credential (store, materialized, len, salt, verifier);
  assert_golden_verifies (store, salt, verifier);
  wyl_policy_store_close (store);
}

static void
test_rotation_preserves_golden_credential (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-cvk-rotate-XXXXXX", NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
  guint8 salt[16], verifier[32], original_cvk[32];
  create_golden_store (path, salt, verifier, original_cvk);
  guint8 old_binding[32];
  guint8 old_auth_key[crypto_generichash_KEYBYTES];
  g_autofree guint8 *old_sealed = NULL;
  gsize old_sealed_len = 0;
  {
    TestProvider inspect_provider = { 0 };
    TestRuntime inspect_runtime = { 0 };
    wyl_policy_store_t *inspect_store = NULL;
    g_assert_cmpint (open_store (path, &inspect_provider, &inspect_runtime,
            &inspect_store), ==, WYRELOG_E_OK);
    wyl_policy_service_cvk_info_t inspect_info = { 0 };
    g_assert_cmpint (wyl_policy_store_load_service_cvk (inspect_store,
            &inspect_info), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_rotation_intent_derive_auth_key (inspect_store,
            old_auth_key, sizeof old_auth_key), ==, WYRELOG_E_OK);
    memcpy (old_binding, inspect_info.provider_binding, sizeof old_binding);
    old_sealed = g_memdup2 (inspect_info.sealed_cvk,
        inspect_info.sealed_cvk_len);
    old_sealed_len = inspect_info.sealed_cvk_len;
    wyl_policy_service_cvk_info_clear (&inspect_info);
    wyl_policy_store_close (inspect_store);
  }
  g_autofree gchar *old_canonical = NULL;
  gsize old_canonical_len = 0;
  g_assert_true (g_file_get_contents (path, &old_canonical,
          &old_canonical_len, NULL));

  TestProvider old_provider = { 0 };
  TestProvider new_provider = {.seed = 0x20 };
  TestRuntime runtime = { 0 };
  SharedTrace rotation_trace = { 0 };
  old_provider.trace = &rotation_trace;
  new_provider.trace = &rotation_trace;
  runtime.trace = &rotation_trace;
  RotationFault fault = { 0 };
  g_assert_cmpint (rotate_store (path, &old_provider, &new_provider, &runtime,
          &fault), ==, WYRELOG_E_OK);
  g_assert_cmpuint (old_provider.unseals, ==, 1);
  g_assert_cmpuint (new_provider.seals, ==, 1);
  g_assert_cmpuint (new_provider.clears, ==, 1);
  g_assert_cmpuint (old_provider.wipes, ==, 1);
  g_assert_cmpuint (new_provider.wipes, ==, 1);
  g_assert_cmpuint (runtime.rng_calls, ==, 0);
  g_assert_cmpuint (rotation_trace.n_events, >=, 5);
  g_assert_cmpmem (rotation_trace.events + rotation_trace.n_events - 5, 5,
      "WUFPP", 5);
  g_assert_cmpuint (fault.calls[WYL_POLICY_ROTATION_BEFORE_CANONICAL_RENAME],
      ==, 1);

  TestProvider wrong_old = { 0 };
  TestRuntime wrong_runtime = { 0 };
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (open_store (path, &wrong_old, &wrong_runtime, &store), !=,
      WYRELOG_E_OK);
  g_assert_null (store);

  TestProvider reopened = {.seed = 0x20 };
  TestRuntime reopened_runtime = { 0 };
  g_assert_cmpint (open_store (path, &reopened, &reopened_runtime, &store), ==,
      WYRELOG_E_OK);
  WylPolicyRotationIntent pending = { 0 };
  g_assert_cmpint (wyl_policy_rotation_intent_read_sidecar (store,
          old_auth_key, sizeof old_auth_key, &pending), ==, WYRELOG_E_OK);
  guint8 expected_digest[crypto_generichash_BYTES];
  g_assert_cmpint (crypto_generichash (expected_digest,
          sizeof expected_digest, (const guint8 *) old_canonical,
          old_canonical_len, NULL, 0), ==, 0);
  g_assert_cmpmem (pending.canonical_digest, sizeof pending.canonical_digest,
      expected_digest, sizeof expected_digest);
  g_assert_cmpint (pending.state, ==, WYL_POLICY_ROTATION_INTENT_PENDING);
  g_assert_cmpuint (pending.old_generation, ==, 1);
  g_assert_cmpuint (pending.expected_new_generation, ==, 2);
  g_assert_false (sodium_is_zero (pending.canonical_digest,
          sizeof pending.canonical_digest));
  g_assert_false (sodium_is_zero (pending.old_provider_id,
          sizeof pending.old_provider_id));
  g_assert_false (sodium_is_zero (pending.new_provider_id,
          sizeof pending.new_provider_id));
  g_assert_cmpint (memcmp (pending.old_provider_id, pending.new_provider_id,
          sizeof pending.old_provider_id), !=, 0);
  g_autofree gchar *pending_path = g_strconcat (path,
      ".wyrelog-rotation-intent", NULL);
  assert_file_omits (pending_path, original_cvk, sizeof original_cvk);
  const guint8 *cvk = NULL;
  gsize cvk_len = 0;
  g_assert_cmpint (wyl_policy_store_materialize_service_cvk_existing (store,
          &cvk, &cvk_len), ==, WYRELOG_E_OK);
  g_assert_cmpmem (cvk, cvk_len, original_cvk, sizeof original_cvk);
  assert_golden_verifies (store, salt, verifier);
  wyl_policy_service_cvk_info_t info = { 0 };
  g_assert_cmpint (wyl_policy_store_load_service_cvk (store, &info), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (info.generation, ==, 2);
  g_assert_cmpint (sodium_memcmp (info.provider_binding, old_binding,
          sizeof old_binding), !=, 0);
  g_assert_false (info.sealed_cvk_len == old_sealed_len
      && memcmp (info.sealed_cvk, old_sealed, old_sealed_len) == 0);
  g_assert_false (contains_bytes (info.sealed_cvk, info.sealed_cvk_len,
          original_cvk, sizeof original_cvk));
  g_assert_false (contains_bytes ((const guint8 *) old_canonical,
          old_canonical_len, original_cvk, sizeof original_cvk));
  wyl_policy_service_cvk_info_clear (&info);
  wyl_policy_store_close (store);

  TestProvider retry_old = {.seed = 0x20 };
  TestProvider retry_new = {.seed = 0x40 };
  TestRuntime retry_runtime = { 0 };
  RotationFault retry_fault = { 0 };
  g_assert_cmpint (rotate_store (path, &retry_old, &retry_new, &retry_runtime,
          &retry_fault), ==, WYRELOG_E_POLICY);

  /* The pending marker remains until the post-commit recovery child clears it. */
  {
    TestProvider cleanup_provider = {.seed = 0x20 };
    TestRuntime cleanup_runtime = { 0 };
    wyl_policy_store_t *cleanup_store = NULL;
    g_assert_cmpint (open_store (path, &cleanup_provider, &cleanup_runtime,
            &cleanup_store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_rotation_intent_clear_sidecar (cleanup_store),
        ==, WYRELOG_E_OK);
    wyl_policy_store_close (cleanup_store);
  }
  sodium_memzero (expected_digest, sizeof expected_digest);
  sodium_memzero (old_auth_key, sizeof old_auth_key);

  TestProvider second = {.seed = 0x20 };
  TestProvider third = {.seed = 0x40 };
  runtime = (TestRuntime) {
  0};
  fault = (RotationFault) {
  0};
  g_assert_cmpint (rotate_store (path, &second, &third, &runtime, &fault), ==,
      WYRELOG_E_OK);
  TestProvider third_reopen = {.seed = 0x40 };
  reopened_runtime = (TestRuntime) {
  0};
  store = NULL;
  g_assert_cmpint (open_store (path, &third_reopen, &reopened_runtime, &store),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_load_service_cvk (store, &info), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (info.generation, ==, 3);
  wyl_policy_service_cvk_info_clear (&info);
  assert_golden_verifies (store, salt, verifier);
  wyl_policy_store_close (store);
  assert_file_omits (path, original_cvk, sizeof original_cvk);

  g_assert_cmpint (g_remove (path), ==, 0);
  remove_rotation_sidecar (path);
  g_autofree gchar *lock_path = g_strdup_printf ("%s.wyrelog-lock", path);
  (void) g_remove (lock_path);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

static void
test_rotation_publish_failpoints (void)
{
  for (guint iteration = 0; iteration < 2; iteration++) {
    g_autofree gchar *dir = g_dir_make_tmp ("wyl-cvk-rotate-fail-XXXXXX",
        NULL);
    g_assert_nonnull (dir);
    g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
    guint8 salt[16], verifier[32], cvk[32];
    create_golden_store (path, salt, verifier, cvk);
    g_autofree gchar *before = NULL;
    gsize before_len = 0;
    g_assert_true (g_file_get_contents (path, &before, &before_len, NULL));
    TestProvider old_provider = { 0 };
    TestProvider new_provider = {.seed = 0x20 };
    TestRuntime runtime = { 0 };
    RotationFault fault = {
      .fail_stage = iteration == 0 ? WYL_POLICY_ROTATION_BEFORE_CVK_CAS :
          WYL_POLICY_ROTATION_BEFORE_CANONICAL_RENAME,
    };
    g_assert_cmpint (rotate_store (path, &old_provider, &new_provider,
            &runtime, &fault), ==,
        iteration == 0 ? WYRELOG_E_POLICY : WYRELOG_E_IO);
    g_autofree gchar *after = NULL;
    gsize after_len = 0;
    g_assert_true (g_file_get_contents (path, &after, &after_len, NULL));
    g_assert_cmpmem (after, after_len, before, before_len);
    TestProvider reopened = { 0 };
    TestRuntime reopened_runtime = { 0 };
    wyl_policy_store_t *store = NULL;
    g_assert_cmpint (open_store (path, &reopened, &reopened_runtime, &store),
        ==, WYRELOG_E_OK);
    assert_golden_verifies (store, salt, verifier);
    wyl_policy_store_close (store);
    TestProvider wrong_new = {.seed = 0x20 };
    reopened_runtime = (TestRuntime) {
    0};
    store = NULL;
    g_assert_cmpint (open_store (path, &wrong_new, &reopened_runtime, &store),
        !=, WYRELOG_E_OK);
    g_assert_null (store);
    g_assert_cmpint (g_remove (path), ==, 0);
    remove_rotation_sidecar (path);
    g_autofree gchar *lock_path = g_strdup_printf ("%s.wyrelog-lock", path);
    (void) g_remove (lock_path);
    g_assert_cmpint (g_rmdir (dir), ==, 0);
  }
}

static void
test_rotation_intent_codec (void)
{
  WylPolicyRotationIntent intent = { 0 };
  g_assert_cmpint (wyl_id_new (&intent.transaction_id), ==, WYRELOG_E_OK);
  memset (intent.canonical_digest, 0x11, sizeof intent.canonical_digest);
  memset (intent.old_provider_id, 0x22, sizeof intent.old_provider_id);
  memset (intent.new_provider_id, 0x33, sizeof intent.new_provider_id);
  intent.old_generation = 7;
  intent.expected_new_generation = 8;
  intent.state = WYL_POLICY_ROTATION_INTENT_PENDING;
  guint8 auth_key[crypto_generichash_KEYBYTES];
  memset (auth_key, 0x5a, sizeof auth_key);

  guint8 *encoded = NULL;
  gsize encoded_len = 0;
  g_assert_cmpint (wyl_policy_rotation_intent_encode (&intent, auth_key,
          sizeof auth_key, &encoded, &encoded_len), ==, WYRELOG_E_OK);
  g_assert_nonnull (encoded);
  g_assert_cmpuint (encoded_len, >, sizeof auth_key);

  WylPolicyRotationIntent decoded = { 0 };
  g_assert_cmpint (wyl_policy_rotation_intent_decode (encoded, encoded_len,
          auth_key, sizeof auth_key, &decoded), ==, WYRELOG_E_OK);
  g_assert_cmpmem (&decoded, sizeof decoded, &intent, sizeof intent);

  encoded[encoded_len / 2] ^= 0x01;
  g_assert_cmpint (wyl_policy_rotation_intent_decode (encoded, encoded_len,
          auth_key, sizeof auth_key, &decoded), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_policy_rotation_intent_decode (encoded,
          encoded_len - 1, auth_key, sizeof auth_key, &decoded), ==,
      WYRELOG_E_POLICY);
  sodium_memzero (encoded, encoded_len);
  g_free (encoded);
  sodium_memzero (auth_key, sizeof auth_key);
}

static void
test_rotation_intent_auth_key_derivation (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-rotation-auth-XXXXXX", NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
  TestProvider provider = { 0 };
  TestRuntime runtime = { 0 };
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (open_store (path, &provider, &runtime, &store), ==,
      WYRELOG_E_OK);

  guint8 first[crypto_generichash_KEYBYTES];
  guint8 second[crypto_generichash_KEYBYTES];
  g_assert_cmpint (wyl_policy_rotation_intent_derive_auth_key (store, first,
          sizeof first), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_rotation_intent_derive_auth_key (store, second,
          sizeof second), ==, WYRELOG_E_OK);
  g_assert_cmpmem (first, sizeof first, second, sizeof second);
  g_assert_false (sodium_is_zero (first, sizeof first));
  guint8 store_key[crypto_generichash_KEYBYTES];
  guint8 expected[crypto_generichash_KEYBYTES];
  for (gsize i = 0; i < sizeof store_key; i++)
    store_key[i] = (guint8) (0x40 + i);
  g_assert_cmpint (crypto_generichash (expected, sizeof expected,
          (const guint8 *) "wyrelog.policy.rotation-intent.auth.v1",
          strlen ("wyrelog.policy.rotation-intent.auth.v1"), store_key,
          sizeof store_key), ==, 0);
  g_assert_cmpmem (first, sizeof first, expected, sizeof expected);
  g_assert_false (sodium_is_zero (store_key, sizeof store_key));
  sodium_memzero (store_key, sizeof store_key);
  sodium_memzero (expected, sizeof expected);
  sodium_memzero (first, sizeof first);
  sodium_memzero (second, sizeof second);
  wyl_policy_store_close (store);

  guint8 short_key[16];
  memset (short_key, 0xa5, sizeof short_key);
  g_assert_cmpint (wyl_policy_rotation_intent_derive_auth_key (NULL,
          short_key, sizeof short_key), ==, WYRELOG_E_INVALID);
  g_assert_true (sodium_is_zero (short_key, sizeof short_key));

  wyl_policy_store_t *providerless = NULL;
  wyl_policy_store_open_options_t providerless_options = {
    .path = ":memory:",
  };
  g_assert_cmpint (wyl_policy_store_open_with_options (&providerless_options,
          &providerless), ==, WYRELOG_E_OK);
  guint8 rejected[crypto_generichash_KEYBYTES];
  memset (rejected, 0xa5, sizeof rejected);
  g_assert_cmpint (wyl_policy_rotation_intent_derive_auth_key (providerless,
          rejected, sizeof rejected), ==, WYRELOG_E_POLICY);
  g_assert_true (sodium_is_zero (rejected, sizeof rejected));
  sodium_memzero (rejected, sizeof rejected);
  wyl_policy_store_close (providerless);

  g_assert_cmpint (g_remove (path), ==, 0);
  remove_rotation_sidecar (path);
  g_autofree gchar *lock_path = g_strdup_printf ("%s.wyrelog-lock", path);
  (void) g_remove (lock_path);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

static void
test_rotation_intent_sidecar_lifecycle (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-rotation-intent-XXXXXX", NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
  TestProvider provider = { 0 };
  TestRuntime runtime = { 0 };
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (open_store (path, &provider, &runtime, &store), ==,
      WYRELOG_E_OK);

  WylPolicyRotationIntent intent = { 0 };
  g_assert_cmpint (wyl_id_new (&intent.transaction_id), ==, WYRELOG_E_OK);
  memset (intent.canonical_digest, 0x41, sizeof intent.canonical_digest);
  memset (intent.old_provider_id, 0x42, sizeof intent.old_provider_id);
  memset (intent.new_provider_id, 0x43, sizeof intent.new_provider_id);
  intent.old_generation = 11;
  intent.expected_new_generation = 12;
  intent.state = WYL_POLICY_ROTATION_INTENT_PENDING;
  guint8 auth_key[crypto_generichash_KEYBYTES];
  memset (auth_key, 0x5c, sizeof auth_key);

  WylPolicyRotationIntent loaded = { 0 };
  g_assert_cmpint (wyl_policy_rotation_intent_read_sidecar (store, auth_key,
          sizeof auth_key, &loaded), ==, WYRELOG_E_NOT_FOUND);
  g_assert_cmpint (wyl_policy_rotation_intent_write_sidecar (store, &intent,
          auth_key, sizeof auth_key), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_rotation_intent_read_sidecar (store, auth_key,
          sizeof auth_key, &loaded), ==, WYRELOG_E_OK);
  g_assert_cmpmem (&loaded, sizeof loaded, &intent, sizeof intent);
  guint8 wrong_key[crypto_generichash_KEYBYTES];
  memset (wrong_key, 0x5d, sizeof wrong_key);
  g_assert_cmpint (wyl_policy_rotation_intent_read_sidecar (store, wrong_key,
          sizeof wrong_key, &loaded), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_policy_rotation_intent_read_sidecar (store, auth_key,
          1, &loaded), ==, WYRELOG_E_INVALID);

  g_autofree gchar *sidecar_path = g_strconcat (path,
      ".wyrelog-rotation-intent", NULL);
  const guint8 malformed[] = { 0x57, 0x59, 0x4c };
  g_assert_true (g_file_set_contents (sidecar_path,
          (const gchar *) malformed, sizeof malformed, NULL));
  g_assert_cmpint (wyl_policy_rotation_intent_read_sidecar (store, auth_key,
          sizeof auth_key, &loaded), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_policy_rotation_intent_write_sidecar (store, &intent,
          auth_key, sizeof auth_key), ==, WYRELOG_E_OK);
  gchar *tampered = NULL;
  gsize tampered_len = 0;
  g_assert_true (g_file_get_contents (sidecar_path, &tampered, &tampered_len,
          NULL));
  g_assert_cmpuint (tampered_len, >, 0);
  tampered[tampered_len / 2] ^= 0x01;
  g_assert_true (g_file_set_contents (sidecar_path, tampered, tampered_len,
          NULL));
  g_free (tampered);
  g_assert_cmpint (wyl_policy_rotation_intent_read_sidecar (store, auth_key,
          sizeof auth_key, &loaded), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_policy_rotation_intent_write_sidecar (store, &intent,
          auth_key, sizeof auth_key), ==, WYRELOG_E_OK);
#ifndef G_OS_WIN32
  g_assert_cmpint (g_remove (sidecar_path), ==, 0);
  g_autofree gchar *symlink_target = g_build_filename (dir, "target", NULL);
  g_assert_cmpint (symlink (symlink_target, sidecar_path), ==, 0);
  g_assert_cmpint (wyl_policy_rotation_intent_read_sidecar (store, auth_key,
          sizeof auth_key, &loaded), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (g_remove (sidecar_path), ==, 0);
  g_assert_cmpint (wyl_policy_rotation_intent_write_sidecar (store, &intent,
          auth_key, sizeof auth_key), ==, WYRELOG_E_OK);
#endif
  g_assert_cmpint (wyl_policy_rotation_intent_clear_sidecar (store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_rotation_intent_clear_sidecar (store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_rotation_intent_read_sidecar (store, auth_key,
          sizeof auth_key, &loaded), ==, WYRELOG_E_NOT_FOUND);
  sodium_memzero (auth_key, sizeof auth_key);
  wyl_policy_store_close (store);
  g_assert_cmpint (g_remove (path), ==, 0);
  g_autofree gchar *lock_path = g_strdup_printf ("%s.wyrelog-lock", path);
  (void) g_remove (lock_path);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

static void
test_rotation_recovery_classifier (void)
{
  WylPolicyRotationRecoveryProbe probe = {
    .old_root_authenticated = TRUE,
    .old_generation_matches = TRUE,
    .old_binding_matches = TRUE,
    .old_inner_invariants_match = TRUE,
  };
  WylPolicyRotationRecoveryState state = 0;
  g_assert_cmpint (wyl_policy_rotation_recovery_classify (&probe, &state), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (state, ==, WYL_POLICY_ROTATION_RECOVERY_OLD);

  probe.old_root_authenticated = FALSE;
  probe.new_root_authenticated = TRUE;
  probe.new_generation_matches = TRUE;
  probe.new_binding_matches = TRUE;
  probe.new_inner_invariants_match = TRUE;
  g_assert_cmpint (wyl_policy_rotation_recovery_classify (&probe, &state), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (state, ==, WYL_POLICY_ROTATION_RECOVERY_NEW);

  probe.old_root_authenticated = TRUE;
  g_assert_cmpint (wyl_policy_rotation_recovery_classify (&probe, &state), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (state, ==, WYL_POLICY_ROTATION_RECOVERY_AMBIGUOUS);
  probe.new_root_authenticated = FALSE;
  probe.old_root_authenticated = FALSE;
  g_assert_cmpint (wyl_policy_rotation_recovery_classify (&probe, &state), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (state, ==, WYL_POLICY_ROTATION_RECOVERY_AMBIGUOUS);
  g_assert_cmpint (wyl_policy_rotation_recovery_classify (NULL, &state), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_policy_rotation_recovery_classify (&probe, NULL), ==,
      WYRELOG_E_INVALID);
}

static void
test_rotation_recovery_plan (void)
{
  WylPolicyRotationIntent intent = { 0 };
  g_assert_cmpint (wyl_id_new (&intent.transaction_id), ==, WYRELOG_E_OK);
  memset (intent.canonical_digest, 0x11, sizeof intent.canonical_digest);
  memset (intent.old_provider_id, 0x22, sizeof intent.old_provider_id);
  memset (intent.new_provider_id, 0x33, sizeof intent.new_provider_id);
  intent.old_generation = 7;
  intent.expected_new_generation = 8;
  intent.state = WYL_POLICY_ROTATION_INTENT_PENDING;
  WylPolicyRotationRecoveryProbe probe = {
    .old_root_authenticated = TRUE,
    .old_generation_matches = TRUE,
    .old_binding_matches = TRUE,
    .old_inner_invariants_match = TRUE,
  };
  WylPolicyRotationRecoveryState state = 0;
  WylPolicyRotationRecoveryAction action = 0;
  g_assert_cmpint (wyl_policy_rotation_recovery_plan (&intent, &probe, &state,
          &action), ==, WYRELOG_E_OK);
  g_assert_cmpint (state, ==, WYL_POLICY_ROTATION_RECOVERY_OLD);
  g_assert_cmpint (action, ==, WYL_POLICY_ROTATION_RECOVERY_RESUME_OLD);

  memset (&probe, 0, sizeof probe);
  probe.new_root_authenticated = TRUE;
  probe.new_generation_matches = TRUE;
  probe.new_binding_matches = TRUE;
  probe.new_inner_invariants_match = TRUE;
  g_assert_cmpint (wyl_policy_rotation_recovery_plan (&intent, &probe, &state,
          &action), ==, WYRELOG_E_OK);
  g_assert_cmpint (state, ==, WYL_POLICY_ROTATION_RECOVERY_NEW);
  g_assert_cmpint (action, ==, WYL_POLICY_ROTATION_RECOVERY_FINALIZE_NEW);

  intent.state = WYL_POLICY_ROTATION_INTENT_COMMITTED;
  g_assert_cmpint (wyl_policy_rotation_recovery_plan (&intent, &probe, &state,
          &action), ==, WYRELOG_E_OK);
  g_assert_cmpint (action, ==, WYL_POLICY_ROTATION_RECOVERY_FINALIZE_NEW);

  probe.old_root_authenticated = TRUE;
  probe.old_generation_matches = TRUE;
  probe.old_binding_matches = TRUE;
  probe.old_inner_invariants_match = TRUE;
  probe.new_root_authenticated = FALSE;
  g_assert_cmpint (wyl_policy_rotation_recovery_plan (&intent, &probe, &state,
          &action), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (action, ==, WYL_POLICY_ROTATION_RECOVERY_FAIL_CLOSED);

  memset (&probe, 0, sizeof probe);
  g_assert_cmpint (wyl_policy_rotation_recovery_plan (&intent, &probe, &state,
          &action), ==, WYRELOG_E_OK);
  g_assert_cmpint (state, ==, WYL_POLICY_ROTATION_RECOVERY_AMBIGUOUS);
  g_assert_cmpint (action, ==, WYL_POLICY_ROTATION_RECOVERY_FAIL_CLOSED);

  intent.expected_new_generation = 99;
  g_assert_cmpint (wyl_policy_rotation_recovery_plan (&intent, &probe, &state,
          &action), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_policy_rotation_recovery_plan (NULL, &probe, &state,
          &action), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_policy_rotation_recovery_plan (&intent, &probe, NULL,
          &action), ==, WYRELOG_E_INVALID);
}

static void
test_rotation_post_rename_warning_commits (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-cvk-rotate-post-XXXXXX", NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
  guint8 salt[16], verifier[32], cvk[32];
  create_golden_store (path, salt, verifier, cvk);
  TestProvider old_provider = { 0 };
  TestProvider new_provider = {.seed = 0x20 };
  TestRuntime runtime = { 0 };
  RotationFault fault = {
    .fail_stage = WYL_POLICY_ROTATION_AFTER_CANONICAL_RENAME,
  };
  g_assert_cmpint (rotate_store (path, &old_provider, &new_provider, &runtime,
          &fault), ==, WYRELOG_E_OK);
  TestProvider reopened = {.seed = 0x20 };
  TestRuntime reopened_runtime = { 0 };
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (open_store (path, &reopened, &reopened_runtime, &store), ==,
      WYRELOG_E_OK);
  assert_golden_verifies (store, salt, verifier);
  wyl_policy_store_close (store);
  g_assert_cmpint (g_remove (path), ==, 0);
  remove_rotation_sidecar (path);
  g_autofree gchar *lock_path = g_strdup_printf ("%s.wyrelog-lock", path);
  (void) g_remove (lock_path);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

static void
test_rotation_provider_failures_preserve_old (void)
{
  for (guint scenario = 0; scenario < 6; scenario++) {
    g_autofree gchar *dir = g_dir_make_tmp ("wyl-cvk-provider-fail-XXXXXX",
        NULL);
    g_assert_nonnull (dir);
    g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
    guint8 salt[16], verifier[32], cvk[32];
    create_golden_store (path, salt, verifier, cvk);
    g_autofree gchar *before = NULL;
    gsize before_len = 0;
    g_assert_true (g_file_get_contents (path, &before, &before_len, NULL));
    TestProvider old_provider = { 0 };
    TestProvider new_provider = {.seed = 0x20 };
    if (scenario == 0)
      old_provider.fail_binding_derive = TRUE;
    else if (scenario == 1)
      old_provider.fail_unseal = TRUE;
    else if (scenario == 2)
      new_provider.fail_probe = TRUE;
    else if (scenario == 3)
      new_provider.fail_binding_derive = TRUE;
    else if (scenario == 4)
      new_provider.fail_seal = TRUE;
    else
      new_provider.fail_store_derive = TRUE;
    TestRuntime runtime = { 0 };
    RotationFault fault = { 0 };
    g_assert_cmpint (rotate_store (path, &old_provider, &new_provider,
            &runtime, &fault), ==, WYRELOG_E_CRYPTO);
    g_autofree gchar *after = NULL;
    gsize after_len = 0;
    g_assert_true (g_file_get_contents (path, &after, &after_len, NULL));
    g_assert_cmpmem (after, after_len, before, before_len);
    g_assert_cmpuint (runtime.rng_calls, ==, 0);
    g_assert_cmpuint (new_provider.clears, ==, scenario >= 4 ? 1 : 0);
    TestProvider reopened = { 0 };
    TestRuntime reopened_runtime = { 0 };
    wyl_policy_store_t *store = NULL;
    g_assert_cmpint (open_store (path, &reopened, &reopened_runtime, &store),
        ==, WYRELOG_E_OK);
    assert_golden_verifies (store, salt, verifier);
    wyl_policy_store_close (store);
    g_assert_cmpint (g_remove (path), ==, 0);
    remove_rotation_sidecar (path);
    g_autofree gchar *lock_path = g_strdup_printf ("%s.wyrelog-lock", path);
    (void) g_remove (lock_path);
    g_assert_cmpint (g_rmdir (dir), ==, 0);
  }
}

static void
test_rotation_secure_memory_failures_preserve_old (void)
{
  for (guint scenario = 0; scenario < 10; scenario++) {
    g_autofree gchar *dir = g_dir_make_tmp ("wyl-cvk-memory-fail-XXXXXX",
        NULL);
    g_assert_nonnull (dir);
    g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
    guint8 salt[16], verifier[32], cvk[32];
    create_golden_store (path, salt, verifier, cvk);
    g_autofree gchar *before = NULL;
    gsize before_len = 0;
    g_assert_true (g_file_get_contents (path, &before, &before_len, NULL));
    TestProvider old_provider = { 0 };
    TestProvider new_provider = {.seed = 0x20 };
    TestRuntime runtime = { 0 };
    if (scenario < 5)
      runtime.fail_alloc_at = scenario + 1;
    else
      runtime.fail_lock_at = scenario - 4;
    RotationFault fault = { 0 };
    g_assert_cmpint (rotate_store (path, &old_provider, &new_provider,
            &runtime, &fault), ==, WYRELOG_E_NOMEM);
    g_autofree gchar *after = NULL;
    gsize after_len = 0;
    g_assert_true (g_file_get_contents (path, &after, &after_len, NULL));
    g_assert_cmpmem (after, after_len, before, before_len);
    g_assert_cmpuint (runtime.rng_calls, ==, 0);
    g_assert_cmpint (g_remove (path), ==, 0);
    remove_rotation_sidecar (path);
    g_autofree gchar *lock_path = g_strdup_printf ("%s.wyrelog-lock", path);
    (void) g_remove (lock_path);
    g_assert_cmpint (g_rmdir (dir), ==, 0);
  }
}

static void
test_rotation_policy_edges (void)
{
  for (guint scenario = 0; scenario < 4; scenario++) {
    g_autofree gchar *dir = g_dir_make_tmp ("wyl-cvk-policy-edge-XXXXXX",
        NULL);
    g_assert_nonnull (dir);
    g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
    guint8 salt[16], verifier[32], cvk[32];
    create_golden_store (path, salt, verifier, cvk);
    if (scenario != 0) {
      TestProvider provider = { 0 };
      TestRuntime runtime = { 0 };
      wyl_policy_store_t *store = NULL;
      g_assert_cmpint (open_store (path, &provider, &runtime, &store), ==,
          WYRELOG_E_OK);
      const gchar *sql = scenario == 1 ?
          "UPDATE service_credential_cvk SET generation=9223372036854775807;" :
          scenario == 2 ? "DELETE FROM service_credential_cvk;" :
          "DROP TRIGGER trg_service_credential_events_no_delete;"
          "CREATE TRIGGER trg_service_credential_events_no_delete BEFORE "
          "DELETE ON service_credential_events BEGIN SELECT 1; END;";
      g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (store), sql,
              NULL, NULL, NULL), ==, SQLITE_OK);
      wyl_policy_store_close (store);
    }
    g_autofree gchar *before = NULL;
    gsize before_len = 0;
    g_assert_true (g_file_get_contents (path, &before, &before_len, NULL));
    TestProvider old_provider = { 0 };
    TestProvider new_provider = {.seed = scenario == 0 ? 0 : 0x20 };
    TestRuntime runtime = { 0 };
    RotationFault fault = { 0 };
    g_assert_cmpint (rotate_store (path, &old_provider, &new_provider,
            &runtime, &fault), ==, WYRELOG_E_POLICY);
    g_autofree gchar *after = NULL;
    gsize after_len = 0;
    g_assert_true (g_file_get_contents (path, &after, &after_len, NULL));
    g_assert_cmpmem (after, after_len, before, before_len);
    if (scenario == 0) {
      g_assert_cmpuint (new_provider.unseals, ==, 0);
      g_assert_cmpuint (new_provider.seals, ==, 0);
    }
    if (scenario >= 2)
      g_assert_cmpuint (new_provider.probes, ==, 0);
    if (scenario == 3) {
      g_assert_cmpuint (old_provider.binding_derives, ==, 0);
      g_assert_cmpuint (old_provider.unseals, ==, 0);
    }
    g_assert_cmpint (g_remove (path), ==, 0);
    remove_rotation_sidecar (path);
    g_autofree gchar *lock_path = g_strdup_printf ("%s.wyrelog-lock", path);
    (void) g_remove (lock_path);
    g_assert_cmpint (g_rmdir (dir), ==, 0);
  }

  g_autofree gchar *dir = g_dir_make_tmp ("wyl-cvk-legacy-XXXXXX", NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
  TestProvider initial = { 0 };
  TestRuntime initial_runtime = { 0 };
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (open_store (path, &initial, &initial_runtime, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  guint8 legacy_auth_key[crypto_generichash_KEYBYTES];
  g_assert_cmpint (wyl_policy_rotation_intent_derive_auth_key (store,
          legacy_auth_key, sizeof legacy_auth_key), ==, WYRELOG_E_OK);
  wyl_policy_store_close (store);
  TestProvider old_provider = { 0 };
  TestProvider new_provider = {.seed = 0x20 };
  TestRuntime runtime = { 0 };
  RotationFault fault = { 0 };
  g_assert_cmpint (rotate_store (path, &old_provider, &new_provider, &runtime,
          &fault), ==, WYRELOG_E_OK);
  g_assert_cmpuint (old_provider.binding_derives, ==, 0);
  g_assert_cmpuint (old_provider.unseals, ==, 0);
  g_assert_cmpuint (new_provider.binding_derives, ==, 0);
  g_assert_cmpuint (new_provider.seals, ==, 0);
  g_assert_cmpuint (runtime.rng_calls, ==, 0);
  TestProvider reopened = {.seed = 0x20 };
  TestRuntime reopened_runtime = { 0 };
  store = NULL;
  g_assert_cmpint (open_store (path, &reopened, &reopened_runtime, &store), ==,
      WYRELOG_E_OK);
  WylPolicyRotationIntent legacy_pending = { 0 };
  g_assert_cmpint (wyl_policy_rotation_intent_read_sidecar (store,
          legacy_auth_key, sizeof legacy_auth_key, &legacy_pending), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (legacy_pending.old_generation, ==, 0);
  g_assert_cmpuint (legacy_pending.expected_new_generation, ==, 1);
  sodium_memzero (legacy_auth_key, sizeof legacy_auth_key);
  const guint8 *missing = NULL;
  gsize missing_len = 0;
  g_assert_cmpint (wyl_policy_store_materialize_service_cvk_existing (store,
          &missing, &missing_len), ==, WYRELOG_E_NOT_FOUND);
  wyl_policy_store_close (store);
  g_assert_cmpint (g_remove (path), ==, 0);
  remove_rotation_sidecar (path);
  g_autofree gchar *lock_path = g_strdup_printf ("%s.wyrelog-lock", path);
  (void) g_remove (lock_path);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_assert_cmpint (sodium_init (), >=, 0);
  g_test_add_func ("/policy-store-service-cvk/fixture-concurrency-reopen",
      test_fixture_concurrency_and_reopen);
  g_test_add_func ("/policy-store-service-cvk/fault-cleanup",
      test_fault_cleanup);
  g_test_add_func ("/policy-store-service-cvk/absent-with-credentials",
      test_absent_with_credentials_is_policy);
  g_test_add_func ("/policy-store-service-cvk/commit-before-cache",
      test_commit_before_cache);
  g_test_add_func ("/policy-store-service-cvk/unseal-failure",
      test_unseal_failure_is_closed);
  g_test_add_func ("/policy-store-service-cvk/inner-binding-tamper",
      test_authenticated_inner_tamper_is_policy);
  g_test_add_func ("/policy-store-service-cvk/providerless",
      test_providerless_is_policy);
  g_test_add_func ("/policy-store-service-cvk/schema-gate",
      test_schema_gate_precedes_crypto);
  g_test_add_func ("/policy-store-service-cvk/crypto-boundaries",
      test_binding_and_unseal_boundaries);
  g_test_add_func ("/policy-store-service-cvk/rotation-golden",
      test_rotation_preserves_golden_credential);
  g_test_add_func ("/policy-store-service-cvk/rotation-intent-codec",
      test_rotation_intent_codec);
  g_test_add_func ("/policy-store-service-cvk/rotation-intent-auth-key",
      test_rotation_intent_auth_key_derivation);
  g_test_add_func ("/policy-store-service-cvk/rotation-intent-sidecar",
      test_rotation_intent_sidecar_lifecycle);
  g_test_add_func ("/policy-store-service-cvk/rotation-recovery-classifier",
      test_rotation_recovery_classifier);
  g_test_add_func ("/policy-store-service-cvk/rotation-recovery-plan",
      test_rotation_recovery_plan);
  g_test_add_func ("/policy-store-service-cvk/rotation-failpoints",
      test_rotation_publish_failpoints);
  g_test_add_func ("/policy-store-service-cvk/rotation-post-rename",
      test_rotation_post_rename_warning_commits);
  g_test_add_func ("/policy-store-service-cvk/rotation-provider-failures",
      test_rotation_provider_failures_preserve_old);
  g_test_add_func ("/policy-store-service-cvk/rotation-memory-failures",
      test_rotation_secure_memory_failures_preserve_old);
  g_test_add_func ("/policy-store-service-cvk/rotation-policy-edges",
      test_rotation_policy_edges);
  return g_test_run ();
}

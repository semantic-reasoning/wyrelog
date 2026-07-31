/* SPDX-License-Identifier: GPL-3.0-or-later */
#if defined(__unix__) || defined(__APPLE__)
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#endif

#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>
#include <string.h>

#include "wyrelog/policy/service-permission-maintenance-private.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-keyprovider-file-private.h"
#include "wyrelog/wyl-request-id-private.h"

/* Durable encrypted store fixture: a maintenance-exclusive lease requires the
 * store file to already exist as an owner-only regular file, so the closure is
 * seeded through a first, non-maintenance open and every later phase reopens
 * the persisted image maintenance-exclusive. */
typedef struct
{
  gchar *dir;
  gchar *store_path;
  gchar *key_path;
} StoreEnv;

static void
store_env_init (StoreEnv *env)
{
  GError *error = NULL;
  env->dir = g_dir_make_tmp ("wyl-spm-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (env->dir);
  env->store_path = g_build_filename (env->dir, "policy.store", NULL);
  env->key_path = g_build_filename (env->dir, "policy.key", NULL);
  guint8 key[32];
  for (gsize i = 0; i < sizeof key; i++)
    key[i] = (guint8) (0x40 + i);
  g_assert_true (g_file_set_contents (env->key_path, (const gchar *) key,
          sizeof key, NULL));
}

static void
store_env_clear (StoreEnv *env)
{
  (void) g_remove (env->store_path);
  (void) g_remove (env->key_path);
  (void) g_rmdir (env->dir);
  g_clear_pointer (&env->store_path, g_free);
  g_clear_pointer (&env->key_path, g_free);
  g_clear_pointer (&env->dir, g_free);
}

static wyl_policy_store_t *
open_store (const StoreEnv *env, gboolean maintenance)
{
  wyl_keyprovider_file_t *keyprovider =
      wyl_keyprovider_file_new (env->key_path);
  g_assert_nonnull (keyprovider);
  wyl_policy_store_open_options_t opts = {
    .path = env->store_path,
    .keyprovider_vtable = wyl_keyprovider_file_get_vtable (),
    .keyprovider_state = keyprovider,
    .keyprovider_state_free = (void (*)(gpointer)) wyl_keyprovider_file_free,
    .require_encrypted = TRUE,
    .maintenance_exclusive = maintenance,
  };
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (wyl_policy_store_open_with_options (&opts, &store), ==,
      WYRELOG_E_OK);
  g_assert_nonnull (store);
  return store;
}

/* Insert unsafe service grants directly, bypassing the mutation guard. An
 * unregistered "svc:" subject holding direct permissions is a dangling-subject
 * closure violation; each grant is one REVOKE_DIRECT removal. */
static void
seed_unsafe_closure (wyl_policy_store_t *store)
{
  sqlite3 *db = wyl_policy_store_get_db (store);
  g_assert_nonnull (db);
  g_assert_cmpint (sqlite3_exec (db,
          "INSERT INTO permissions(perm_id,perm_name,class) VALUES"
          " ('wr.stream.write','stream write','basic'),"
          " ('wr.stream.admin','stream admin','basic');"
          "INSERT INTO direct_permissions(subject_id,perm_id,scope) VALUES"
          " ('svc:tenant-a:worker','wr.stream.write','*'),"
          " ('svc:tenant-a:worker','wr.stream.admin','*');", NULL, NULL,
          NULL), ==, SQLITE_OK);
}

static void
add_extra_unsafe_grant (wyl_policy_store_t *store)
{
  sqlite3 *db = wyl_policy_store_get_db (store);
  g_assert_nonnull (db);
  g_assert_cmpint (sqlite3_exec (db,
          "INSERT INTO permissions(perm_id,perm_name,class) VALUES"
          " ('wr.stream.exec','stream exec','basic');"
          "INSERT INTO direct_permissions(subject_id,perm_id,scope) VALUES"
          " ('svc:tenant-a:worker','wr.stream.exec','*');", NULL, NULL,
          NULL), ==, SQLITE_OK);
}

static guint
removal_count (wyl_policy_store_t *store)
{
  WylPolicyPermissionClosureAnalysis analysis = { 0 };
  g_assert_cmpint (wyl_policy_store_analyze_service_permission_closure (store,
          &analysis), ==, WYRELOG_E_OK);
  guint n = analysis.removals->len;
  wyl_policy_permission_closure_analysis_clear (&analysis);
  return n;
}

static gint64
count_receipts (wyl_policy_store_t *store)
{
  sqlite3 *db = wyl_policy_store_get_db (store);
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db,
          "SELECT count(*) FROM service_permission_remediation_receipts;", -1,
          &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 n = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return n;
}

static guint64
remediation_generation (wyl_policy_store_t *store)
{
  guint64 generation = 0;
  g_assert_cmpint (wyl_policy_store_service_permission_remediation_generation
      (store, &generation), ==, WYRELOG_E_OK);
  return generation;
}

/* Seed the unsafe closure and capture a canonical full-removal manifest bound
 * to that state, then persist and release the store so callers can reopen it
 * maintenance-exclusive. */
static void
seed_and_build_manifest (const StoreEnv *env, const gchar *request_id,
    WylServicePermissionManifest *out_manifest)
{
  wyl_policy_store_t *store = open_store (env, FALSE);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_cmpuint (removal_count (store), ==, 0);
  seed_unsafe_closure (store);
  g_assert_cmpuint (removal_count (store), ==, 2);

  WylPolicyPermissionClosureAnalysis analysis = { 0 };
  g_assert_cmpint (wyl_policy_store_analyze_service_permission_closure (store,
          &analysis), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_permission_manifest_from_analysis (&analysis,
          request_id, out_manifest), ==, WYRELOG_E_OK);
  wyl_policy_permission_closure_analysis_clear (&analysis);
  wyl_policy_store_close (store);
}

/* A one-operation manifest that reuses a request id and pre-state binding but
 * carries a different fingerprint than the full manifest. */
static void
build_single_op_manifest (const WylServicePermissionManifest *full,
    WylServicePermissionManifest *out)
{
  memset (out, 0, sizeof *out);
  out->version = 1;
  out->request_id = g_strdup (full->request_id);
  out->store_generation = full->store_generation;
  memcpy (out->store_digest, full->store_digest, 32);
  out->operations = g_ptr_array_new_with_free_func
      ((GDestroyNotify) wyl_policy_permission_closure_removal_free);
  const WylPolicyPermissionClosureRemoval *src =
      g_ptr_array_index (full->operations, 0);
  WylPolicyPermissionClosureRemoval *copy =
      g_new0 (WylPolicyPermissionClosureRemoval, 1);
  copy->action = src->action;
  copy->reason = src->reason;
  copy->subject_id = g_strdup (src->subject_id);
  copy->right_id = g_strdup (src->right_id);
  copy->scope = g_strdup (src->scope);
  g_ptr_array_add (out->operations, copy);
}

static void
fresh_request_id (gchar buf[WYL_REQUEST_ID_STRING_BUF])
{
  g_assert_cmpint (wyl_request_id_new (buf, WYL_REQUEST_ID_STRING_BUF), ==,
      WYRELOG_E_OK);
}

/* A valid dry-run reports OK and leaves the store byte-for-byte unchanged: the
 * reopened image still shows the unsafe grants and holds no receipt. */
static void
test_dry_run_is_read_only (void)
{
  StoreEnv env;
  store_env_init (&env);
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  WylServicePermissionManifest manifest;
  seed_and_build_manifest (&env, request_id, &manifest);

  wyl_policy_store_t *store = open_store (&env, TRUE);
  g_assert_cmpuint (removal_count (store), ==, 2);
  g_assert_cmpint (wyl_service_permission_maintenance_dry_run (store,
          &manifest), ==, WYRELOG_E_OK);
  /* dry_run consumed and closed the store; reopen to confirm no change. */

  store = open_store (&env, TRUE);
  g_assert_cmpuint (removal_count (store), ==, 2);
  g_assert_cmpint (count_receipts (store), ==, 0);
  g_assert_cmpuint (remediation_generation (store), ==, 0);
  wyl_policy_store_close (store);

  wyl_service_permission_manifest_clear (&manifest);
  store_env_clear (&env);
}

/* Apply removes exactly the manifest operations, the reopened closure is
 * clean, and a receipt is produced and persisted. This also exercises the
 * bare maintenance handle end to end with no resolver/exchange/engine pair. */
static void
test_apply_cleans_closure (void)
{
  StoreEnv env;
  store_env_init (&env);
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  WylServicePermissionManifest manifest;
  seed_and_build_manifest (&env, request_id, &manifest);

  wyl_policy_store_t *store = open_store (&env, TRUE);
  g_assert_cmpuint (removal_count (store), ==, 2);
  wyl_policy_service_permission_receipt_t receipt = { 0 };
  g_assert_cmpint (wyl_service_permission_maintenance_apply (store, &manifest,
          &receipt), ==, WYRELOG_E_OK);
  g_assert_cmpstr (receipt.request_id, ==, request_id);
  g_assert_cmpuint (receipt.operation_count, ==, 2);
  g_assert_nonnull (receipt.audit_id);
  g_assert_nonnull (receipt.actor_identity);
  g_assert_cmpuint (strlen (receipt.manifest_fingerprint), ==, 64);
  g_assert_cmpuint (receipt.pre_generation, ==, manifest.store_generation);
  g_assert_cmpuint (receipt.post_generation, !=, 0);
  g_assert_cmpuint (receipt.post_generation, !=, receipt.pre_generation);
  wyl_policy_service_permission_receipt_clear (&receipt);

  store = open_store (&env, TRUE);
  g_assert_cmpuint (removal_count (store), ==, 0);
  g_assert_cmpint (count_receipts (store), ==, 1);
  g_assert_cmpuint (remediation_generation (store), ==, 1);
  gboolean found = FALSE;
  wyl_policy_service_permission_receipt_t stored = { 0 };
  g_assert_cmpint (wyl_policy_store_service_permission_receipt_lookup (store,
          request_id, &found, &stored), ==, WYRELOG_E_OK);
  g_assert_true (found);
  wyl_policy_service_permission_receipt_clear (&stored);
  wyl_policy_store_close (store);

  wyl_service_permission_manifest_clear (&manifest);
  store_env_clear (&env);
}

/* A manifest whose pre-state no longer matches the live snapshot is rejected
 * before any mutation, by both dry-run and apply. */
static void
test_stale_manifest_rejected (void)
{
  StoreEnv env;
  store_env_init (&env);
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  WylServicePermissionManifest manifest;
  seed_and_build_manifest (&env, request_id, &manifest);

  /* Move the store out from under the manifest's captured snapshot. */
  wyl_policy_store_t *store = open_store (&env, TRUE);
  add_extra_unsafe_grant (store);
  g_assert_cmpuint (removal_count (store), ==, 3);
  wyl_policy_store_close (store);

  store = open_store (&env, TRUE);
  g_assert_cmpint (wyl_service_permission_maintenance_dry_run (store,
          &manifest), ==, WYRELOG_E_POLICY);

  store = open_store (&env, TRUE);
  wyl_policy_service_permission_receipt_t receipt = { 0 };
  g_assert_cmpint (wyl_service_permission_maintenance_apply (store, &manifest,
          &receipt), ==, WYRELOG_E_POLICY);
  g_assert_null (receipt.request_id);
  wyl_policy_service_permission_receipt_clear (&receipt);

  /* No mutation, no receipt: all three unsafe grants remain. */
  store = open_store (&env, TRUE);
  g_assert_cmpuint (removal_count (store), ==, 3);
  g_assert_cmpint (count_receipts (store), ==, 0);
  wyl_policy_store_close (store);

  wyl_service_permission_manifest_clear (&manifest);
  store_env_clear (&env);
}

/* A second apply of the same request id and fingerprint replays the frozen
 * receipt verbatim and applies nothing: row counts do not move. */
static void
test_idempotent_replay (void)
{
  StoreEnv env;
  store_env_init (&env);
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  WylServicePermissionManifest manifest;
  seed_and_build_manifest (&env, request_id, &manifest);

  wyl_policy_store_t *store = open_store (&env, TRUE);
  wyl_policy_service_permission_receipt_t first = { 0 };
  g_assert_cmpint (wyl_service_permission_maintenance_apply (store, &manifest,
          &first), ==, WYRELOG_E_OK);

  store = open_store (&env, TRUE);
  g_assert_cmpint (count_receipts (store), ==, 1);
  g_assert_cmpuint (remediation_generation (store), ==, 1);
  wyl_policy_service_permission_receipt_t replay = { 0 };
  g_assert_cmpint (wyl_service_permission_maintenance_apply (store, &manifest,
          &replay), ==, WYRELOG_E_OK);
  g_assert_cmpstr (replay.request_id, ==, first.request_id);
  g_assert_cmpstr (replay.manifest_fingerprint, ==, first.manifest_fingerprint);
  g_assert_cmpstr (replay.audit_id, ==, first.audit_id);
  g_assert_cmpuint (replay.operation_count, ==, first.operation_count);
  g_assert_cmpuint (replay.pre_generation, ==, first.pre_generation);
  g_assert_cmpuint (replay.post_generation, ==, first.post_generation);

  /* The replay applied nothing: exactly one receipt, generation unmoved. */
  store = open_store (&env, TRUE);
  g_assert_cmpint (count_receipts (store), ==, 1);
  g_assert_cmpuint (remediation_generation (store), ==, 1);
  g_assert_cmpuint (removal_count (store), ==, 0);
  wyl_policy_store_close (store);

  wyl_policy_service_permission_receipt_clear (&replay);
  wyl_policy_service_permission_receipt_clear (&first);
  wyl_service_permission_manifest_clear (&manifest);
  store_env_clear (&env);
}

/* A different manifest under an already-recorded request id is a conflict and
 * mutates nothing. */
static void
test_idempotent_conflict (void)
{
  StoreEnv env;
  store_env_init (&env);
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  WylServicePermissionManifest manifest;
  seed_and_build_manifest (&env, request_id, &manifest);

  wyl_policy_store_t *store = open_store (&env, TRUE);
  wyl_policy_service_permission_receipt_t first = { 0 };
  g_assert_cmpint (wyl_service_permission_maintenance_apply (store, &manifest,
          &first), ==, WYRELOG_E_OK);
  wyl_policy_service_permission_receipt_clear (&first);

  /* Same request id, different (single-op) manifest -> hard conflict. */
  WylServicePermissionManifest conflicting;
  build_single_op_manifest (&manifest, &conflicting);

  store = open_store (&env, TRUE);
  wyl_policy_service_permission_receipt_t receipt = { 0 };
  g_assert_cmpint (wyl_service_permission_maintenance_apply (store,
          &conflicting, &receipt), ==, WYRELOG_E_POLICY);
  g_assert_null (receipt.request_id);
  wyl_policy_service_permission_receipt_clear (&receipt);

  store = open_store (&env, TRUE);
  g_assert_cmpint (count_receipts (store), ==, 1);
  g_assert_cmpuint (remediation_generation (store), ==, 1);
  g_assert_cmpuint (removal_count (store), ==, 0);
  wyl_policy_store_close (store);

  wyl_service_permission_manifest_clear (&conflicting);
  wyl_service_permission_manifest_clear (&manifest);
  store_env_clear (&env);
}

/* A partial manifest that removes only one of two unsafe grants passes the
 * pre-state check but fails the #614 closure validation at commit, so the
 * whole apply rolls back: no receipt, store unchanged. */
static void
test_partial_manifest_rolls_back (void)
{
  StoreEnv env;
  store_env_init (&env);
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (request_id);
  WylServicePermissionManifest full;
  seed_and_build_manifest (&env, request_id, &full);

  WylServicePermissionManifest partial;
  build_single_op_manifest (&full, &partial);
  /* Give the partial manifest its own request id so it is not mistaken for a
   * replay/conflict of the full one. */
  gchar partial_request_id[WYL_REQUEST_ID_STRING_BUF];
  fresh_request_id (partial_request_id);
  g_free (partial.request_id);
  partial.request_id = g_strdup (partial_request_id);

  wyl_policy_store_t *store = open_store (&env, TRUE);
  wyl_policy_service_permission_receipt_t receipt = { 0 };
  g_assert_cmpint (wyl_service_permission_maintenance_apply (store, &partial,
          &receipt), ==, WYRELOG_E_POLICY);
  g_assert_null (receipt.request_id);
  wyl_policy_service_permission_receipt_clear (&receipt);

  /* Commit-time validation rolled everything back: both grants remain, no
   * receipt was written, and the generation counter did not advance. */
  store = open_store (&env, TRUE);
  g_assert_cmpuint (removal_count (store), ==, 2);
  g_assert_cmpint (count_receipts (store), ==, 0);
  g_assert_cmpuint (remediation_generation (store), ==, 0);
  wyl_policy_store_close (store);

  wyl_service_permission_manifest_clear (&partial);
  wyl_service_permission_manifest_clear (&full);
  store_env_clear (&env);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/service-permission-maintenance/dry-run-read-only",
      test_dry_run_is_read_only);
  g_test_add_func ("/service-permission-maintenance/apply-cleans-closure",
      test_apply_cleans_closure);
  g_test_add_func ("/service-permission-maintenance/stale-rejected",
      test_stale_manifest_rejected);
  g_test_add_func ("/service-permission-maintenance/idempotent-replay",
      test_idempotent_replay);
  g_test_add_func ("/service-permission-maintenance/idempotent-conflict",
      test_idempotent_conflict);
  g_test_add_func ("/service-permission-maintenance/partial-rolls-back",
      test_partial_manifest_rolls_back);
  return g_test_run ();
}

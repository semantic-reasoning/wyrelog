/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include "human-user-test-support.h"
#include "test-exit-status.h"
#include "wyrelog/wyl-keyprovider-file-private.h"
#include <glib/gstdio.h>
#include "wyrelog/policy/store-private.h"

/* Registration is explicit; a grant or login must never invent a human. */
static void
check_human_registry_contract (void)
{
  gchar requests[4][WYL_REQUEST_ID_STRING_BUF];
  for (guint i = 0; i < 4; i++)
    g_assert_cmpint (wyl_request_id_new (requests[i], sizeof requests[i]), ==, WYRELOG_E_OK);
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (wyl_policy_store_open (":memory:", &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_false (wyl_policy_human_subject_is_valid ("svc:agent"));
  g_assert_false (wyl_policy_human_subject_is_valid ("wr.system"));
  g_assert_false (wyl_policy_human_subject_is_valid (".."));
  g_assert_true (wyl_policy_human_subject_is_valid ("alice"));
  g_assert_cmpint (wyl_policy_store_user_require (store, "alice", TRUE), !=, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_grant_role_membership (store, "alice", "wr.system_admin", "__wr_default"), !=, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_begin_mutation (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_user_register (store, "alice"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_commit_mutation (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_user_require (store, "alice", TRUE), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_grant_role_membership (store, "alice", "wr.system_admin", "__wr_default"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_revoke_role_membership (store, "alice", "wr.system_admin", "__wr_default"), !=, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_revoke_role_membership (store, "unknown", "wr.system_admin", "__wr_default"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_begin_mutation (store), ==, WYRELOG_E_OK);
  g_auto (WylUserOperation) created = {0};
  g_assert_cmpint (wyl_policy_store_user_operation_commit (store, "bob", "alice", "create",
      requests[0], NULL, NULL, &created), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_commit_mutation (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_grant_role_membership (store, "bob", "wr.system_admin", "__wr_default"), ==, WYRELOG_E_OK);
  gboolean tenant_created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (store,"alice-a","alice",&tenant_created), ==, WYRELOG_E_OK);
  g_assert_true (tenant_created);
  g_assert_cmpint (wyl_policy_store_create_tenant (store,"alice-b","alice",&tenant_created), ==, WYRELOG_E_OK);
  g_assert_true (tenant_created);
  g_auto (WylUserOperation) disabled = {0};
  g_assert_cmpint (wyl_policy_store_begin_mutation (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_user_operation_commit (store, "alice", "bob", "disable",
      requests[1], NULL, NULL, &disabled), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_commit_mutation (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_user_require (store, "alice", TRUE), !=, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_user_require (store, "alice", FALSE), ==, WYRELOG_E_OK);
  g_auto (WylUserOperation) refused = {0};
  g_assert_cmpint (wyl_policy_store_begin_mutation (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_user_operation_commit (store, "bob", "bob", "disable",
      requests[2], NULL, NULL, &refused), !=, WYRELOG_E_OK);
  g_assert_cmpstr (refused.error_code, ==, "last_system_admin");
  wyl_policy_store_rollback_mutation (store);
  g_auto (WylUserDeletePreview) preview = {0};
  g_assert_cmpint (wyl_policy_store_user_preview (store, "alice", &preview), ==, WYRELOG_E_OK);
  g_assert_nonnull (strstr (preview.unsealed,"alice-a"));
  g_assert_nonnull (strstr (preview.unsealed,"alice-b"));
  WylPolicyAuthorityMutationResult transition;
  g_assert_cmpint (wyl_policy_store_reconcile_tenant_authority (store,"alice-a",WYL_POLICY_TENANT_LIFECYCLE_SEALED,0,0,&transition), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_reconcile_tenant_authority (store,"alice-b",WYL_POLICY_TENANT_LIFECYCLE_SEALED,0,0,&transition), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_grant_role_membership (store,"bob","wr.system_admin","alice-b"), ==, WYRELOG_E_OK);
  wyl_user_delete_preview_clear (&preview);
  g_assert_cmpint (wyl_policy_store_user_preview (store,"alice",&preview), ==, WYRELOG_E_OK);
  g_assert_nonnull (strstr (preview.blockers,"alice-b:bob:role:wr.system_admin"));
  g_assert_cmpint (wyl_policy_store_revoke_role_membership (store,"bob","wr.system_admin","alice-b"), ==, WYRELOG_E_OK);
  wyl_user_delete_preview_clear (&preview);
  g_assert_cmpint (wyl_policy_store_user_preview (store,"alice",&preview), ==, WYRELOG_E_OK);
  g_auto (WylUserOperation) deleted = {0};
  g_autoptr (GPtrArray) children = g_ptr_array_new_with_free_func (wyl_user_child_free);
  for (gsize i=0; i<preview.tenants->len; i++) {
    WylTenantDeleteRecord *child = g_new0 (WylTenantDeleteRecord,1);
    gchar request[WYL_REQUEST_ID_STRING_BUF];
    g_assert_cmpint (wyl_request_id_new (request,sizeof request), ==, WYRELOG_E_OK);
    child->tenant = g_strdup (g_ptr_array_index (preview.tenants,i));
    child->request_id = g_strdup (request); child->manifest = g_strdup ("none");
    g_ptr_array_add (children,child);
  }
  sqlite3 *db = wyl_policy_store_get_db (store);
  g_assert_cmpint (sqlite3_exec (db,"CREATE TRIGGER fail_second_user_child BEFORE DELETE ON tenants WHEN OLD.tenant_id='alice-b' BEGIN SELECT RAISE(ABORT,'injected'); END",NULL,NULL,NULL), ==, SQLITE_OK);
  g_assert_cmpint (wyl_policy_store_begin_mutation (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_user_operation_commit (store,"alice","bob","delete",requests[3],preview.fingerprint,children,&deleted), !=, WYRELOG_E_OK);
  wyl_policy_store_rollback_mutation (store);
  wyl_user_operation_clear (&deleted);
  g_assert_cmpint (wyl_policy_store_user_require (store,"alice",FALSE), ==, WYRELOG_E_OK);
  g_auto (WylTenantDeleteRecord) absent_child = {0};
  g_assert_cmpint (wyl_policy_store_tenant_delete_read (store,"alice-a",&absent_child), ==, WYRELOG_E_NOT_FOUND);
  g_assert_cmpint (sqlite3_exec (db,"DROP TRIGGER fail_second_user_child",NULL,NULL,NULL), ==, SQLITE_OK);
  g_assert_cmpint (wyl_policy_store_begin_mutation (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_user_operation_commit (store, "alice", "bob", "delete",
      requests[3], preview.fingerprint, children, &deleted), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_commit_mutation (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_user_require (store, "alice", FALSE), !=, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_user_require (store, "alice", FALSE), !=, WYRELOG_E_OK);
  wyl_policy_store_close (store);
}

static gint64
count_rows (wyl_policy_store_t *store, const gchar *sql)
{
  sqlite3_stmt *statement = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db (store),sql,-1,&statement,NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (statement), ==, SQLITE_ROW);
  gint64 value = sqlite3_column_int64 (statement,0);
  sqlite3_finalize (statement);
  return value;
}

static void
check_predecessor_migration (void)
{
  g_autofree gchar *directory = g_dir_make_tmp ("human-migration-XXXXXX",NULL);
  g_assert_nonnull (directory);
  g_autofree gchar *path = g_build_filename (directory,"policy.sqlite",NULL);
  g_autofree gchar *schema = NULL;
  g_assert_true (g_file_get_contents (WYL_HUMAN_PREDECESSOR_SCHEMA,&schema,NULL,NULL));
  sqlite3 *db = NULL;
  g_assert_cmpint (sqlite3_open (path,&db), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_exec (db,schema,NULL,NULL,NULL), ==, SQLITE_OK);
  const gchar *seed =
      "INSERT INTO roles(role_id,role_name) VALUES('site.legacy','legacy');"
      "INSERT INTO permissions(perm_id,perm_name,class) VALUES('site.legacy.read','legacy','basic');"
      "INSERT INTO role_memberships(subject_id,role_id,scope) VALUES"
      "('migrated-role','site.legacy','scope'),('duplicate','site.legacy','scope'),"
      "('typo-holder','site.legacy','scope'),('wr.system','site.legacy','scope'),('bad subject','site.legacy','scope');"
      "INSERT INTO direct_permissions(subject_id,perm_id,scope) VALUES('migrated-direct','site.legacy.read','scope'),('duplicate','site.legacy.read','scope');"
      "INSERT INTO totp_enrollments VALUES('migrated-totp',zeroblob(32),0,1,'legacy-id');"
      "INSERT INTO principal_states(subject_id,state) VALUES('login-only','unverified'),('svc:legacy','unverified');"
      "INSERT INTO permission_states(subject_id,perm_id,scope,state) VALUES('state-only','site.legacy.read','scope','armed');";
  g_assert_cmpint (sqlite3_exec (db,seed,NULL,NULL,NULL), ==, SQLITE_OK);
  sqlite3_close (db);
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (wyl_policy_store_open (path,&store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (count_rows (store,"SELECT COUNT(*) FROM human_users"), ==, 5);
  g_assert_cmpint (count_rows (store,"SELECT COUNT(*) FROM human_user_migration_report WHERE outcome='registered'"), ==, 5);
  g_assert_cmpint (count_rows (store,"SELECT COUNT(*) FROM human_user_migration_report WHERE outcome='skipped'"), ==, 5);
  g_assert_cmpint (wyl_policy_store_user_require (store,"login-only",TRUE), ==, WYRELOG_E_SUBJECT_NOT_REGISTERED);
  g_assert_cmpint (wyl_policy_store_user_require (store,"state-only",TRUE), ==, WYRELOG_E_SUBJECT_NOT_REGISTERED);
  g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (store),
      "UPDATE human_users SET state='deleted',generation=generation+1 WHERE subject_id='migrated-role';"
      "UPDATE human_users SET state='disabled',generation=generation+1 WHERE subject_id='migrated-direct';",NULL,NULL,NULL), ==, SQLITE_OK);
  wyl_policy_store_close (store); store = NULL;
  g_assert_cmpint (wyl_policy_store_open (path,&store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (count_rows (store,"SELECT COUNT(*) FROM human_users WHERE state='deleted'"), ==, 1);
  g_assert_cmpint (count_rows (store,"SELECT COUNT(*) FROM human_users WHERE state='disabled'"), ==, 1);
  g_assert_cmpint (count_rows (store,"SELECT COUNT(*) FROM human_user_migration_report"), ==, 10);
  wyl_policy_store_close (store);
  g_remove (path); g_rmdir (directory);
}

typedef struct
{
  wyl_policy_store_t *store;
  const gchar *actor;
  const gchar *subject;
  GMutex *mutex;
  GCond *condition;
  guint *arrived;
  wyrelog_error_t result;
} AdminRace;

static gpointer
retire_other_admin (gpointer data)
{
  AdminRace *race = data;
  wyl_policy_store_t *store = race->store;
  gchar request[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (request, sizeof request), ==, WYRELOG_E_OK);
  g_auto (WylUserDeletePreview) preview = {0};
  g_assert_cmpint (wyl_policy_store_user_preview (store, race->subject, &preview), ==, WYRELOG_E_OK);
  g_mutex_lock (race->mutex);
  (*race->arrived)++;
  g_cond_broadcast (race->condition);
  while (*race->arrived < 2) g_cond_wait (race->condition, race->mutex);
  g_mutex_unlock (race->mutex);
  race->result = wyl_policy_store_begin_mutation (store);
  if (race->result == WYRELOG_E_OK) {
    g_auto (WylUserOperation) operation = {0};
    g_autoptr (GPtrArray) children = g_ptr_array_new ();
    race->result = wyl_policy_store_user_operation_commit (store, race->subject,
            race->actor, "delete", request, preview.fingerprint, children, &operation);
    if (race->result == WYRELOG_E_OK)
      race->result = wyl_policy_store_commit_mutation (store);
    if (race->result != WYRELOG_E_OK) wyl_policy_store_rollback_mutation (store);
  }
  return NULL;
}

static void
check_last_admin_race (void)
{
  g_autofree gchar *directory = g_dir_make_tmp ("human-admin-race-XXXXXX", NULL);
  g_autofree gchar *path = g_build_filename (directory, "policy.sqlite", NULL);
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (wyl_policy_store_open (path, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_begin_mutation (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_user_register (store, "alpha"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_user_register (store, "beta"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_grant_role_membership (store, "alpha", "wr.system_admin", "__wr_default"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_grant_role_membership (store, "beta", "wr.system_admin", "__wr_default"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_commit_mutation (store), ==, WYRELOG_E_OK);
  GMutex mutex;
  GCond condition;
  g_mutex_init (&mutex);
  g_cond_init (&condition);
  guint arrived = 0;
  AdminRace first = {store, "alpha", "beta", &mutex, &condition, &arrived, WYRELOG_E_INTERNAL};
  AdminRace second = {store, "beta", "alpha", &mutex, &condition, &arrived, WYRELOG_E_INTERNAL};
  GThread *a = g_thread_new ("delete-beta", retire_other_admin, &first);
  GThread *b = g_thread_new ("delete-alpha", retire_other_admin, &second);
  g_thread_join (a);
  g_thread_join (b);
  g_test_message ("Concurrent administrator deletions returned %d and %d", first.result, second.result);
  g_assert_cmpint ((first.result == WYRELOG_E_OK) + (second.result == WYRELOG_E_OK), ==, 1);
  g_assert_cmpint (count_rows (store, "SELECT COUNT(*) FROM human_users u JOIN role_memberships r USING(subject_id) WHERE u.state='active' AND r.role_id='wr.system_admin' AND r.scope='__wr_default'"), ==, 1);
  g_cond_clear (&condition);
  g_mutex_clear (&mutex);
  wyl_policy_store_close (store);
  g_remove (path);
  g_rmdir (directory);
}

static void
check_delete_uses_current_ownership (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  register_test_human (store, "alice");
  register_test_human (store, "bob");
  g_assert_cmpint (wyl_policy_store_grant_role_membership (store, "bob", "wr.system_admin", "__wr_default"), ==, WYRELOG_E_OK);
  gboolean changed = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (store, "away", "alice", &changed), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_tenant (store, "incoming", "bob", &changed), ==, WYRELOG_E_OK);
  g_auto (WylUserDeletePreview) before = {0};
  g_assert_cmpint (wyl_policy_store_user_preview (store, "alice", &before), ==, WYRELOG_E_OK);
  gchar request[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_policy_store_begin_mutation (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (request, sizeof request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_transfer_tenant_owner (store, "away", "alice", "bob", request, FALSE, &changed), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_request_id_new (request, sizeof request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_transfer_tenant_owner (store, "incoming", "bob", "alice", request, FALSE, &changed), ==, WYRELOG_E_OK);
  WylPolicyAuthorityMutationResult transition;
  g_assert_cmpint (wyl_policy_store_reconcile_tenant_authority (store, "incoming", WYL_POLICY_TENANT_LIFECYCLE_SEALED, 0, 0, &transition), ==, WYRELOG_E_OK);
  g_assert_cmpint (transition, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_commit_mutation (store), ==, WYRELOG_E_OK);
  g_auto (WylUserDeletePreview) after = {0};
  g_assert_cmpint (wyl_policy_store_user_preview (store, "alice", &after), ==, WYRELOG_E_OK);
  g_assert_cmpuint (after.tenants->len, ==, 1);
  g_assert_cmpstr (g_ptr_array_index (after.tenants, 0), ==, "incoming");
  g_assert_cmpstr (before.fingerprint, !=, after.fingerprint);
  g_autoptr (GPtrArray) children = g_ptr_array_new_with_free_func (wyl_user_child_free);
  WylTenantDeleteRecord *child = g_new0 (WylTenantDeleteRecord, 1);
  g_assert_cmpint (wyl_request_id_new (request, sizeof request), ==, WYRELOG_E_OK);
  child->tenant = g_strdup ("incoming"); child->request_id = g_strdup (request); child->manifest = g_strdup ("none");
  g_ptr_array_add (children, child);
  g_assert_cmpint (wyl_request_id_new (request, sizeof request), ==, WYRELOG_E_OK);
  g_auto (WylUserOperation) operation = {0};
  g_assert_cmpint (wyl_policy_store_begin_mutation (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_user_operation_commit (store, "alice", "bob", "delete", request, before.fingerprint, children, &operation), ==, WYRELOG_E_CONFLICT);
  wyl_policy_store_rollback_mutation (store);
  g_assert_cmpint (wyl_policy_store_begin_mutation (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_user_operation_commit (store, "alice", "bob", "delete", request, after.fingerprint, children, &operation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_commit_mutation (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (count_rows (store, "SELECT COUNT(*) FROM tenants WHERE tenant_id='away' AND owner_subject_id='bob'"), ==, 1);
  g_assert_cmpint (count_rows (store, "SELECT COUNT(*) FROM tenants WHERE tenant_id='incoming'"), ==, 0);
  g_assert_cmpint (count_rows (store, "SELECT COUNT(*) FROM tenant_ownership_events"), ==, 1);
}

typedef struct
{
  wyl_policy_store_t *store;
  GMutex mutex;
  GCond condition;
  gboolean grant_first;
  gboolean first_done;
  const gchar *fingerprint;
  GPtrArray *children;
  wyrelog_error_t grant_result;
  wyrelog_error_t delete_result;
} GrantDeleteRace;

static gpointer
grant_during_delete (gpointer data)
{
  GrantDeleteRace *race = data;
  g_mutex_lock (&race->mutex);
  while (!race->grant_first && !race->first_done)
    g_cond_wait (&race->condition, &race->mutex);
  g_mutex_unlock (&race->mutex);
  race->grant_result = wyl_policy_store_grant_role_membership (race->store,
          "admin", "wr.system_admin", "owned");
  g_mutex_lock (&race->mutex);
  race->first_done = TRUE;
  g_cond_broadcast (&race->condition);
  g_mutex_unlock (&race->mutex);
  return NULL;
}

static gpointer
delete_during_grant (gpointer data)
{
  GrantDeleteRace *race = data;
  g_mutex_lock (&race->mutex);
  while (race->grant_first && !race->first_done)
    g_cond_wait (&race->condition, &race->mutex);
  g_mutex_unlock (&race->mutex);
  gchar request[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (request, sizeof request), ==, WYRELOG_E_OK);
  g_auto (WylUserOperation) operation = {0};
  g_assert_cmpint (wyl_policy_store_begin_mutation (race->store), ==, WYRELOG_E_OK);
  race->delete_result = wyl_policy_store_user_operation_commit (race->store,
          "owner", "admin", "delete", request, race->fingerprint,
          race->children, &operation);
  if (race->delete_result == WYRELOG_E_OK)
    g_assert_cmpint (wyl_policy_store_commit_mutation (race->store), ==, WYRELOG_E_OK);
  else
    wyl_policy_store_rollback_mutation (race->store);
  g_mutex_lock (&race->mutex);
  race->first_done = TRUE;
  g_cond_broadcast (&race->condition);
  g_mutex_unlock (&race->mutex);
  return NULL;
}

static void
check_grant_delete_interleavings (void)
{
  for (guint grant_first = 0; grant_first < 2; grant_first++) {
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_assert_cmpint (wyl_policy_store_open (":memory:", &store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
    register_test_human (store, "owner");
    register_test_human (store, "admin");
    g_assert_cmpint (wyl_policy_store_grant_role_membership (store, "admin", "wr.system_admin", "__wr_default"), ==, WYRELOG_E_OK);
    gboolean created;
    g_assert_cmpint (wyl_policy_store_create_tenant (store, "owned", "owner", &created), ==, WYRELOG_E_OK);
    WylPolicyAuthorityMutationResult transition;
    g_assert_cmpint (wyl_policy_store_reconcile_tenant_authority (store, "owned", WYL_POLICY_TENANT_LIFECYCLE_SEALED, 0, 0, &transition), ==, WYRELOG_E_OK);
    g_auto (WylUserDeletePreview) preview = {0};
    g_assert_cmpint (wyl_policy_store_user_preview (store, "owner", &preview), ==, WYRELOG_E_OK);
    g_autoptr (GPtrArray) children = g_ptr_array_new_with_free_func (wyl_user_child_free);
    WylTenantDeleteRecord *child = g_new0 (WylTenantDeleteRecord, 1);
    gchar request[WYL_REQUEST_ID_STRING_BUF];
    g_assert_cmpint (wyl_request_id_new (request, sizeof request), ==, WYRELOG_E_OK);
    child->tenant = g_strdup ("owned");
    child->request_id = g_strdup (request);
    child->manifest = g_strdup ("none");
    g_ptr_array_add (children, child);
    GrantDeleteRace race = {.store = store, .grant_first = grant_first,
                            .fingerprint = preview.fingerprint, .children = children};
    g_mutex_init (&race.mutex);
    g_cond_init (&race.condition);
    GThread *grant = g_thread_new ("grant", grant_during_delete, &race);
    GThread *deletion = g_thread_new ("delete", delete_during_grant, &race);
    g_thread_join (grant);
    g_thread_join (deletion);
    if (grant_first) {
      g_assert_cmpint (race.grant_result, ==, WYRELOG_E_OK);
      g_assert_cmpint (race.delete_result, !=, WYRELOG_E_OK);
      g_assert_cmpint (wyl_policy_store_user_require (store, "owner", TRUE), ==, WYRELOG_E_OK);
    } else {
      g_assert_cmpint (race.delete_result, ==, WYRELOG_E_OK);
      g_assert_cmpint (race.grant_result, !=, WYRELOG_E_OK);
      g_assert_cmpint (count_rows (store, "SELECT COUNT(*) FROM role_memberships WHERE scope='owned'"), ==, 0);
    }
    g_cond_clear (&race.condition);
    g_mutex_clear (&race.mutex);
  }
}

/* Offline assertion for the real daemon E2E, after its exclusive lease ends. */
static void
inspect_deleted_user (const gchar *path, const gchar *key, const gchar *subject)
{
  wyl_keyprovider_file_t *provider = wyl_keyprovider_file_new (key);
  g_assert_nonnull (provider);
  wyl_policy_store_open_options_t options = {
    .path = path, .keyprovider_vtable = wyl_keyprovider_file_get_vtable (),
    .keyprovider_state = provider,
    .keyprovider_state_free = (void (*)(gpointer)) wyl_keyprovider_file_free,
    .require_encrypted = TRUE
  };
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open_with_options (&options, &store), ==, WYRELOG_E_OK);
  const gchar *tables[] = {"role_memberships", "direct_permissions", "permission_states",
                           "principal_states", "totp_enrollments", "human_user_sessions"};
  for (guint i = 0; i < G_N_ELEMENTS (tables); i++) {
    g_autofree gchar *sql = g_strdup_printf ("SELECT COUNT(*) FROM %s WHERE subject_id=?", tables[i]);
    sqlite3_stmt *statement = NULL;
    g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), sql, -1, &statement, NULL), ==, SQLITE_OK);
    g_assert_cmpint (sqlite3_bind_text (statement, 1, subject, -1, SQLITE_TRANSIENT), ==, SQLITE_OK);
    g_assert_cmpint (sqlite3_step (statement), ==, SQLITE_ROW);
    g_assert_cmpint (sqlite3_column_int64 (statement, 0), ==, 0);
    sqlite3_finalize (statement);
  }
  g_assert_cmpint (count_rows (store, "SELECT COUNT(*) FROM human_users WHERE subject_id='alice' AND state='deleted'"), ==, 1);
  g_assert_cmpint (count_rows (store, "SELECT COUNT(*) FROM audit_events WHERE action='user_delete'"), ==, 1);
  g_assert_cmpint (count_rows (store, "SELECT COUNT(*) FROM audit_events WHERE subject_id='alice'"), >, 0);
  g_assert_cmpint (count_rows (store, "SELECT COUNT(*) FROM tenants WHERE tenant_id='alice-data'"), ==, 0);
}

int
main (int argc, char **argv)
{
  if (argc == 5 && g_str_equal (argv[1], "--inspect-deleted")) {
    inspect_deleted_user (argv[2], argv[3], argv[4]);
    return wyl_test_normalize_exit_status (0);
  }
  g_assert_cmpint (argc, ==, 1);
  check_predecessor_migration ();
  check_human_registry_contract ();
  check_last_admin_race ();
  check_grant_delete_interleavings ();
  check_delete_uses_current_ownership ();
  return wyl_test_normalize_exit_status (0);
}

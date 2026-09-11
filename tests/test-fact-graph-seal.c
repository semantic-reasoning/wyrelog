/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <errno.h>
#include <duckdb.h>
#include <glib.h>
#include <glib/gstdio.h>
#ifdef G_OS_WIN32
#include <windows.h>
#endif
#include <sqlite3.h>
#include <string.h>

#include "fact-test-support.h"
#include "wyrelog/fact/graph-seal-private.h"
#include "wyrelog/fact/provisioning-run-private.h"
#include "wyrelog/fact/store-private.h"
#include "wyrelog/fact/store-test-seams-private.h"
#include "wyrelog/fact/replay-private.h"
#include "wyrelog/fact/runtime-private.h"
#include "wyrelog/fact/publication-lock-event-private.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/auth/service-auth-coordination-private.h"
#ifdef WYL_HAS_SECURE_DUCKDB_BRIDGE
#include "fact/secure-duckdb-bridge-private.h"
#include "wyrelog/fact/store-open-private.h"
G_GNUC_INTERNAL wyrelog_error_t
wyl_fact_artifact_namespace_open_provisioned_pair_internal
  (WylFactGraphProvisionedPair *, WylFactArtifactNamespace **);
#endif

typedef struct
{
  guint64 device;
  guint64 file;
} FactGraphFileIdentity;

static gboolean
fact_graph_file_get_identity (const gchar *path, FactGraphFileIdentity *out)
{
#ifdef G_OS_WIN32
  g_autofree gunichar2 *path_utf16 = g_utf8_to_utf16 (path, -1,
          NULL, NULL, NULL);
  if (path_utf16 == NULL)
    return FALSE;
  HANDLE handle = CreateFileW ((LPCWSTR) path_utf16, 0,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (handle == INVALID_HANDLE_VALUE)
    return FALSE;
  BY_HANDLE_FILE_INFORMATION info = { 0 };
  gboolean ok = GetFileInformationByHandle (handle, &info);
  CloseHandle (handle);
  if (!ok)
    return FALSE;
  out->device = info.dwVolumeSerialNumber;
  out->file = ((guint64) info.nFileIndexHigh << 32) | info.nFileIndexLow;
  return TRUE;
#else
  GStatBuf stat_buf = { 0 };
  if (g_stat (path, &stat_buf) != 0)
    return FALSE;
  out->device = stat_buf.st_dev;
  out->file = stat_buf.st_ino;
  return TRUE;
#endif
}

typedef struct
{
  GMutex mutex;
  GArray *events;
} PublicationLockTrace;

static void
publication_lock_trace_event (const WylFactPublicationLockEvent *event,
    gpointer user_data)
{
  PublicationLockTrace *trace = user_data;
  g_mutex_lock (&trace->mutex);
  g_array_append_val (trace->events, *event);
  g_mutex_unlock (&trace->mutex);
}

#ifdef WYL_HAS_SECURE_DUCKDB_BRIDGE
#include "wyrelog/fact/provisioning-run-private.h"
#include "wyrelog/fact/store-open-private.h"
#endif

#if defined(WYL_HAS_SECURE_DUCKDB_BRIDGE) && !defined(G_OS_WIN32)
static const gchar policy_seal_helper_arg[] = "--policy-seal-helper";
#endif
static gchar *test_self_path;

/* The graph fixture is duplicated from tests/test-fact-replay.c rather than
 * shared.  Extracting it would mean deleting it there, and two open pull
 * requests rewrite that file; a third conflict in it would cost more than
 * these forty lines.  Dedupe once those land. */
static wyl_policy_fact_relation_schema_options_t
make_schema (const gchar *tenant_id, const gchar *graph_id,
    const wyl_policy_fact_relation_schema_column_t *columns, gsize n_columns)
{
  wyl_policy_fact_relation_schema_options_t schema = {
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .namespace_id = "shop.ns",
    .relation_name = "orders-rel",
    .schema_version = 1,
    .relation_visible = TRUE,
    .columns = columns,
    .n_columns = n_columns,
  };
  return schema;
}

static void
create_graph_with_schema (wyl_policy_store_t *store, const gchar *root,
    const gchar *tenant_id, const gchar *graph_id)
{
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (store, tenant_id, &created),
      ==, WYRELOG_E_OK);
  const wyl_policy_fact_graph_column_t graph_columns[] = {
    {"order_id", "symbol"},
    {"amount", "int64"},
    {"expedited", "bool"},
  };
  const wyl_policy_fact_graph_relation_t graph_relations[] = {
    {"orders-rel", graph_columns, G_N_ELEMENTS (graph_columns)},
  };
  const wyl_policy_fact_graph_create_options_t graph_opts = {
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .fact_root = root,
    .schema_version = 1,
    .owner_scope = tenant_id,
    .relations = graph_relations,
    .n_relations = G_N_ELEMENTS (graph_relations),
  };
  g_assert_cmpint (wyl_policy_store_create_fact_graph (store, &graph_opts,
      NULL), ==, WYRELOG_E_OK);
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
    {"expedited", "bool", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (tenant_id,
          graph_id, columns, G_N_ELEMENTS (columns));
  g_assert_cmpint (wyl_policy_store_register_fact_relation_schema (store,
      &schema), ==, WYRELOG_E_OK);
}

static void
create_authority_graph_with_schema (wyl_policy_store_t *store,
    const gchar *root, const gchar *tenant_id, const gchar *graph_id)
{
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (store, tenant_id, &created),
      ==, WYRELOG_E_OK);
  const wyl_policy_fact_graph_column_t graph_columns[] = {
    {"order_id", "symbol"},
    {"amount", "int64"},
    {"expedited", "bool"},
  };
  const wyl_policy_fact_graph_relation_t graph_relations[] = {
    {"orders-rel", graph_columns, G_N_ELEMENTS (graph_columns)},
  };
  const wyl_policy_fact_graph_create_options_t graph_opts = {
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .fact_root = root,
    .schema_version = 1,
    .owner_scope = tenant_id,
    .relations = graph_relations,
    .n_relations = G_N_ELEMENTS (graph_relations),
  };
  gchar op_uuid[WYL_ID_STRING_BUF] = { 0 };
  g_assert_cmpint (wyl_policy_store_create_fact_graph_provisioning (store,
      &graph_opts, NULL, op_uuid), ==, WYRELOG_E_OK);
#ifdef WYL_HAS_SECURE_DUCKDB_BRIDGE
  /* Complete both sides of the provisioning state machine.  Moving only the
   * authority row to ACTIVE leaves the operation RESERVED, which is an
   * invalid production state and is rejected by the secure store opener. */
  g_assert_cmpint (wyl_fact_graph_provisioning_recover (store, op_uuid, root,
      NULL), ==, WYRELOG_E_OK);
#else
  WylPolicyAuthorityMutationResult mutation =
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
      tenant_id, graph_id, WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING,
      WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE, WYL_POLICY_GRAPH_ERROR_NONE, 1, 0,
      &mutation), ==, WYRELOG_E_OK);
  g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
#endif
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
    {"expedited", "bool", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (tenant_id,
          graph_id, columns, G_N_ELEMENTS (columns));
  g_assert_cmpint (wyl_policy_store_register_fact_relation_schema (store,
      &schema), ==, WYRELOG_E_OK);
}

/* Proves the pinned generation is still live after the seal detached the
 * entry's reference.  What it computes is beside the point; that it runs at
 * all is the assertion. */
static wyrelog_error_t
engine_is_reachable (WylEngine *engine, gpointer user_data)
{
  gboolean *reached = user_data;
  *reached = engine != NULL;
  return WYRELOG_E_OK;
}

typedef struct
{
  const gchar *tenant_id;
  const gchar *graph_id;
  gchar *storage_path;
} GraphPathProbe;

static wyrelog_error_t
capture_graph_path_cb (const wyl_policy_fact_graph_info_t *info,
    gpointer user_data)
{
  GraphPathProbe *probe = user_data;
  if (g_strcmp0 (probe->tenant_id, info->tenant_id) == 0
      && g_strcmp0 (probe->graph_id, info->graph_id) == 0)
    probe->storage_path = g_strdup (info->storage_path);
  return WYRELOG_E_OK;
}

/* Give the graph a real store so its engine builds and a seal has something
 * to evict.  Three of these four steps are obvious; the fourth is not, and it
 * is the one that blocks: open_graph_store refuses facts.duckdb unless it is
 * mode 0600, so without the chmod the build fails at its first step with
 * WYRELOG_E_POLICY and every later ingredient is irrelevant. */
static void
materialize_graph_engine (wyl_policy_store_t *policy,
    const gchar *root G_GNUC_UNUSED, const gchar *tenant_id,
    const gchar *graph_id)
{
  GraphPathProbe probe = { tenant_id, graph_id, NULL };
  g_assert_cmpint (wyl_policy_store_foreach_fact_graph (policy, tenant_id,
      capture_graph_path_cb, &probe), ==, WYRELOG_E_OK);
  g_assert_nonnull (probe.storage_path);
  g_autofree gchar *storage_path = probe.storage_path;
  g_autofree gchar *fact_path = g_build_filename (storage_path,
          "facts.duckdb", NULL);

  {
    g_autoptr (wyl_fact_store_t) store = NULL;
#ifdef WYL_HAS_SECURE_DUCKDB_BRIDGE
    WylPolicyGraphAuthorityRecord *authority = NULL;
    g_assert_cmpint (wyl_policy_store_read_graph_authority (policy,
        tenant_id, graph_id, &authority), ==, WYRELOG_E_OK);
    g_assert_nonnull (authority);
    gboolean legacy = authority->lifecycle_state
        == WYL_POLICY_GRAPH_LIFECYCLE_LEGACY_UNCLASSIFIED;
    wyl_policy_graph_authority_record_free (authority);
    if (!legacy)
      g_assert_cmpint (wyl_fact_store_open_provisioned_graph (policy, root,
          tenant_id, graph_id, TRUE, &store), ==, WYRELOG_E_OK);
    else
#endif
    g_assert_cmpint (wyl_fact_store_open (fact_path, &store), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_store_create_schema (store), ==, WYRELOG_E_OK);
    const wyl_policy_fact_relation_schema_column_t columns[] = {
      {"order_id", "symbol", FALSE, TRUE},
      {"amount", "int64", FALSE, TRUE},
      {"expedited", "bool", FALSE, TRUE},
    };
    wyl_policy_fact_relation_schema_options_t schema = make_schema (tenant_id,
            graph_id, columns, G_N_ELEMENTS (columns));
    wyl_fact_value_t values[] = {
      {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "order-a"},
      {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 11},
      {.type = WYL_FACT_VALUE_BOOL,.as.bool_value = TRUE},
    };
    wyl_fact_row_t rows[] = { {values, 3} };
    const wyl_fact_store_batch_t batch = {
      .batch_id = "batch-1",
      .tenant_id = tenant_id,
      .graph_id = graph_id,
      .namespace_id = "shop.ns",
      .relation_name = "orders-rel",
      .schema_version = 1,
      .source = "test",
      .idempotency_key = "key-1",
      .op = WYL_FACT_STORE_OP_ASSERT,
      .rows = rows,
      .n_rows = G_N_ELEMENTS (rows),
    };
    gboolean inserted = FALSE;
    g_assert_cmpint (wyl_fact_store_append_batch (store, &schema, &batch,
        &inserted), ==, WYRELOG_E_OK);
    g_assert_true (inserted);
  }

  g_autoptr (GError) error = NULL;
  g_assert_true (wyl_test_secure_regular_file (fact_path, &error));
}

static void
remove_tree (const gchar *path)
{
  if (path == NULL)
    return;
  g_autoptr (GDir) dir = g_dir_open (path, 0, NULL);
  if (dir != NULL) {
    const gchar *name = NULL;
    while ((name = g_dir_read_name (dir)) != NULL) {
      g_autofree gchar *child = g_build_filename (path, name, NULL);
      if (g_file_test (child, G_FILE_TEST_IS_DIR))
        remove_tree (child);
      else
        (void) g_remove (child);
    }
  }
  (void) g_rmdir (path);
}

static void
count_live_order (WylEngine *engine, const gchar *relation, const gint64 *row,
    guint ncols, gpointer data)
{
  (void) engine;
  (void) relation;
  g_assert_cmpuint (ncols, ==, 3);
  g_assert_cmpint (row[1], ==, 11);
  g_assert_cmpint (row[2], ==, 1);
  (*(guint *) data)++;
}

typedef enum
{
  LEGACY_DIRECT_POLICY,
  LEGACY_HANDLE_NO_ROOT,
  LEGACY_HANDLE_OTHER_ROOT,
} LegacyCompetitor;

static void
test_legacy_live_owner_case (LegacyCompetitor competitor)
{
  if (!g_test_subprocess ()) {
    g_test_trap_subprocess (NULL, 30 * G_TIME_SPAN_SECOND, 0);
    g_test_trap_assert_passed ();
    return;
  }
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-policy-ownership-legacy-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *other_root = NULL;
  if (competitor == LEGACY_HANDLE_OTHER_ROOT) {
    other_root = wyl_test_make_secure_fact_root
          ("wyl-policy-ownership-other-XXXXXX", &error);
    g_assert_no_error (error);
  }
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite", NULL);
  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==,
        WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "graph-a");
    materialize_graph_engine (policy, root, "tenant-a", "graph-a");
  }

  WylHandleOpenOptions a_options = {
    .policy_store_path = policy_path,
    .fact_root = root,
  };
  g_autoptr (WylHandle) handle_a = NULL;
  g_assert_cmpint (wyl_handle_open_with_options (&a_options, &handle_a), ==,
      WYRELOG_E_OK);
  guint initial_rows = 0;
  g_autofree gchar *relation = wyl_fact_replay_wirelog_relation_name
        ("shop.ns", "orders-rel");
  g_autofree gchar *observed = g_strdup_printf ("%s_observed", relation);
  g_assert_cmpint (wyl_handle_snapshot_fact_graph_relation (handle_a,
      "tenant-a", "graph-a", observed, count_live_order, &initial_rows), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (initial_rows, ==, 1);

  wyrelog_error_t seal_rc = WYRELOG_E_INTERNAL;
  if (competitor == LEGACY_DIRECT_POLICY) {
    g_autoptr (wyl_policy_store_t) policy_b = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy_b), ==,
        WYRELOG_E_OK);
    seal_rc = wyl_policy_store_seal_fact_graph (policy_b, "tenant-a",
            "graph-a");
  } else {
    WylHandleOpenOptions b_options = {
      .policy_store_path = policy_path,
      .fact_root = competitor == LEGACY_HANDLE_OTHER_ROOT ? other_root : NULL,
    };
    g_autoptr (WylHandle) handle_b = NULL;
    g_assert_cmpint (wyl_handle_open_with_options (&b_options, &handle_b), ==,
        WYRELOG_E_OK);
    g_autoptr (WylServiceAuthWriteLease) lease = NULL;
    g_assert_cmpint (wyl_service_auth_authority_acquire_write
          (wyl_handle_get_service_auth_authority (handle_b), handle_b, NULL,
        &lease), ==, WYRELOG_E_OK);
    wyl_policy_fact_graph_info_t info = {
      .tenant_id = "tenant-a",
      .graph_id = "graph-a",
    };
    WylFactGraphSealOutcome outcome = { 0 };
    seal_rc = wyl_handle_seal_fact_graph (handle_b, lease, &info,
            G_TIME_SPAN_SECOND,
            &outcome);
    wyl_fact_graph_seal_outcome_clear (&outcome);
    g_assert_cmpint (wyl_service_auth_write_lease_release_terminal (&lease),
        ==, WYRELOG_E_OK);
  }

  gboolean durable_sealed = FALSE;
  {
    g_autoptr (wyl_policy_store_t) policy_c = NULL;
    WylPolicyGraphAuthorityRecord *authority = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy_c), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_read_graph_authority (policy_c,
        "tenant-a", "graph-a", &authority), ==, WYRELOG_E_OK);
    g_assert_nonnull (authority);
    durable_sealed = authority->sealed_compatibility;
    wyl_policy_graph_authority_record_free (authority);
  }
  guint fresh_rows = 0;
  wyrelog_error_t fresh_snapshot_rc =
      wyl_handle_snapshot_fact_graph_relation (handle_a, "tenant-a", "graph-a",
          observed, count_live_order, &fresh_rows);

  /* The diagnostic values are captured before teardown.  Teardown must not be
   * skipped when the ownership assertion below catches the known regression. */
  gboolean unsafe = seal_rc == WYRELOG_E_OK && durable_sealed
      && fresh_snapshot_rc == WYRELOG_E_OK && fresh_rows == 1;
  g_printerr ("contender=%d seal=%d durable-sealed=%d fresh-snapshot=%d rows=%u\n",
      competitor, seal_rc, durable_sealed, fresh_snapshot_rc, fresh_rows);
  g_clear_object (&handle_a);
  remove_tree (root);
  if (other_root != NULL)
    remove_tree (other_root);
  g_assert_cmpint (seal_rc, ==, WYRELOG_E_BUSY);
  g_assert_true (fresh_snapshot_rc == WYRELOG_E_OK
      || fresh_snapshot_rc == WYRELOG_E_BUSY);
  if (seal_rc == WYRELOG_E_OK)
    g_assert_true (durable_sealed);
  if (fresh_snapshot_rc == WYRELOG_E_OK)
    g_assert_cmpuint (fresh_rows, ==, 1);
  g_assert_false (unsafe);
}

static void
test_legacy_direct_policy_live_owner (void)
{
  test_legacy_live_owner_case (LEGACY_DIRECT_POLICY);
}

static void
test_legacy_handle_live_owner_without_root (void)
{
  test_legacy_live_owner_case (LEGACY_HANDLE_NO_ROOT);
}

static void
test_legacy_handle_live_owner_with_other_root (void)
{
  test_legacy_live_owner_case (LEGACY_HANDLE_OTHER_ROOT);
}

#if defined(WYL_HAS_SECURE_DUCKDB_BRIDGE) && !defined(G_OS_WIN32)

static void
create_provisioned_graph_fixture (wyl_policy_store_t *policy,
    const gchar *root, const gchar *tenant_id, const gchar *graph_id)
{
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (policy, tenant_id, &created),
      ==, WYRELOG_E_OK);
  const wyl_policy_fact_graph_column_t graph_columns[] = {
    {"order_id", "symbol"}, {"amount", "int64"}, {"expedited", "bool"},
  };
  const wyl_policy_fact_graph_relation_t graph_relations[] = {
    {"orders-rel", graph_columns, G_N_ELEMENTS (graph_columns)},
  };
  const wyl_policy_fact_graph_create_options_t graph_opts = {
    .tenant_id = tenant_id, .graph_id = graph_id, .fact_root = root,
    .schema_version = 1, .owner_scope = tenant_id,
    .relations = graph_relations, .n_relations = G_N_ELEMENTS (graph_relations),
  };
  gchar op_uuid[WYL_ID_STRING_BUF] = { 0 };
  g_assert_cmpint (wyl_policy_store_create_fact_graph_provisioning (policy,
      &graph_opts, NULL, op_uuid), ==, WYRELOG_E_OK);
  g_assert_cmpstr (op_uuid, !=, "");
  g_assert_cmpint (wyl_fact_graph_provisioning_recover (policy, op_uuid, root,
      NULL), ==, WYRELOG_E_OK);
  WylPolicyGraphProvisioningRecord *operation = NULL;
  WylPolicyGraphAuthorityRecord *authority = NULL;
  g_assert_cmpint (wyl_policy_store_graph_provisioning_read (policy, op_uuid,
      &operation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_read_graph_authority (policy, tenant_id,
      graph_id, &authority), ==, WYRELOG_E_OK);
  g_assert_nonnull (operation);
  g_assert_nonnull (authority);
  g_assert_cmpint (operation->phase, ==, WYL_POLICY_GRAPH_PROVISIONING_ACTIVE);
  g_assert_cmpint (authority->lifecycle_state, ==,
      WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE);
  g_assert_cmpstr (operation->tenant_id, ==, tenant_id);
  g_assert_cmpstr (operation->graph_id, ==, graph_id);
  g_assert_cmpstr (authority->tenant_id, ==, tenant_id);
  g_assert_cmpstr (authority->graph_id, ==, graph_id);
  g_assert_nonnull (operation->store_uuid);
  g_assert_true (authority->has_store_identity);
  g_assert_nonnull (authority->store_uuid);
  g_assert_cmpstr (operation->store_uuid, ==, authority->store_uuid);
  wyl_policy_graph_provisioning_record_free (operation);
  wyl_policy_graph_authority_record_free (authority);
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE}, {"amount", "int64", FALSE, TRUE},
    {"expedited", "bool", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (tenant_id,
          graph_id, columns, G_N_ELEMENTS (columns));
  g_assert_cmpint (wyl_policy_store_register_fact_relation_schema (policy,
      &schema), ==, WYRELOG_E_OK);
}

static void
append_provisioned_batch (wyl_policy_store_t *policy, const gchar *root,
    const gchar *tenant_id, const gchar *graph_id)
{
  wyl_fact_store_t *store = NULL;
  g_assert_cmpint (wyl_fact_store_open_provisioned_graph (policy, root,
      tenant_id, graph_id, TRUE, &store), ==, WYRELOG_E_OK);
  g_assert_nonnull (store);
  g_assert_cmpint (wyl_fact_store_create_schema (store), ==, WYRELOG_E_OK);
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE}, {"amount", "int64", FALSE, TRUE},
    {"expedited", "bool", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = make_schema (tenant_id,
          graph_id, columns, G_N_ELEMENTS (columns));
  wyl_fact_value_t values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = "order-a"},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = 11},
    {.type = WYL_FACT_VALUE_BOOL,.as.bool_value = TRUE},
  };
  wyl_fact_row_t rows[] = { {values, G_N_ELEMENTS (values)} };
  const wyl_fact_store_batch_t batch = {
    .batch_id = "provisioned-live-owner", .tenant_id = tenant_id,
    .graph_id = graph_id, .namespace_id = "shop.ns",
    .relation_name = "orders-rel", .schema_version = 1, .source = "test",
    .idempotency_key = "provisioned-live-owner:1", .op = WYL_FACT_STORE_OP_ASSERT,
    .rows = rows, .n_rows = G_N_ELEMENTS (rows),
  };
  gboolean inserted = FALSE;
  g_assert_cmpint (wyl_fact_store_append_batch (store, &schema, &batch,
      &inserted), ==, WYRELOG_E_OK);
  g_assert_true (inserted);
  wyl_fact_store_close (store);
}

typedef struct
{
  GMainLoop *loop;
  GSubprocess *process;
  gchar *stdout_text;
  gchar *stderr_text;
  GError *error;
  gboolean communicate_ok;
  gboolean timed_out;
  gboolean successful;
  GSource *timeout_source;
} PolicySealChild;

static void
policy_seal_child_communicated (GObject *source_object, GAsyncResult *result,
    gpointer user_data)
{
  PolicySealChild *child = user_data;
  child->communicate_ok = g_subprocess_communicate_utf8_finish
        (G_SUBPROCESS (source_object), result, &child->stdout_text,
          &child->stderr_text, &child->error);
  g_source_destroy (child->timeout_source);
  g_main_loop_quit (child->loop);
}

static gboolean
policy_seal_child_timeout (gpointer user_data)
{
  PolicySealChild *child = user_data;
  child->timed_out = TRUE;
  g_subprocess_force_exit (child->process);
  return G_SOURCE_REMOVE;
}

static gboolean
parse_policy_seal_result (const gchar *text, gint *out_startup, gint *out_seal)
{
  if (text == NULL
      || !g_regex_match_simple ("^STARTUP=-?[0-9]+ SEAL=-?[0-9]+\\n$",
      text, 0, 0))
    return FALSE;
  gchar *end = NULL;
  gint64 startup = g_ascii_strtoll (text + strlen ("STARTUP="), &end, 10);
  const gchar *seal_text = strstr (text, " SEAL=");
  if (seal_text == NULL)
    return FALSE;
  seal_text += strlen (" SEAL=");
  gint64 seal = g_ascii_strtoll (seal_text, &end, 10);
  if (end == NULL || g_strcmp0 (end, "\n") != 0
      || startup < G_MININT || startup > G_MAXINT
      || seal < G_MININT || seal > G_MAXINT)
    return FALSE;
  *out_startup = (gint) startup;
  *out_seal = (gint) seal;
  return TRUE;
}

static void
run_policy_seal_child (const gchar *policy_path, PolicySealChild *child)
{
  const gchar *argv[] = {test_self_path, policy_seal_helper_arg, policy_path,
                         "tenant-a", "orders", NULL};
  g_autoptr (GMainContext) context = g_main_context_new ();
  g_main_context_push_thread_default (context);
  child->process = g_subprocess_newv (argv,
          G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE,
          &child->error);
  if (child->process != NULL) {
    child->loop = g_main_loop_new (context, FALSE);
    child->timeout_source = g_timeout_source_new (5000);
    g_source_set_callback (child->timeout_source, policy_seal_child_timeout,
        child, NULL);
    g_source_attach (child->timeout_source, context);
    g_subprocess_communicate_utf8_async (child->process, NULL, NULL,
        policy_seal_child_communicated, child);
    g_main_loop_run (child->loop);
    child->successful = child->communicate_ok
        && g_subprocess_get_successful (child->process);
    g_source_destroy (child->timeout_source);
    g_clear_pointer (&child->timeout_source, g_source_unref);
    g_clear_pointer (&child->loop, g_main_loop_unref);
    g_clear_object (&child->process);
  }
  g_main_context_pop_thread_default (context);
}

typedef struct
{
  const gchar *policy_path;
  PolicySealChild *child;
  guint calls;
} BeforeAdmissionProbe;

static wyrelog_error_t
seal_before_admission_hook (const gchar *phase, gpointer user_data)
{
  BeforeAdmissionProbe *probe = user_data;
  if (g_strcmp0 (phase,
      WYL_FACT_GRAPH_SEAL_PHASE_UNSEAL_BEFORE_ADMISSION_OPEN) == 0) {
    probe->calls++;
    if (probe->calls == 1)
      run_policy_seal_child (probe->policy_path, probe->child);
  }
  return WYRELOG_E_OK;
}

static gint
policy_seal_helper_main (int argc, char **argv)
{
  if (argc != 5)
    return 2;
  wyl_policy_store_t *policy = NULL;
  wyrelog_error_t startup = wyl_policy_store_open (argv[2], &policy);
  wyrelog_error_t seal = WYRELOG_E_INVALID;
  if (startup == WYRELOG_E_OK) {
    seal = wyl_policy_store_seal_fact_graph (policy, argv[3], argv[4]);
    wyl_policy_store_close (policy);
  }
  g_print ("STARTUP=%d SEAL=%d\n", startup, seal);
  return 0;
}
#endif

static void
test_independent_policy_seal_with_live_handle (gconstpointer data)
{
#if !defined(WYL_HAS_SECURE_DUCKDB_BRIDGE) || defined(G_OS_WIN32)
  (void) data;
  g_test_skip ("the provisioned live-handle case requires POSIX secure fact storage");
  return;
#else
  if (!g_test_subprocess ()) {
    g_test_trap_subprocess (NULL, 30 * G_TIME_SPAN_SECOND, 0);
    g_test_trap_assert_passed ();
    return;
  }
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-policy-live-owner-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite", NULL);
  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==,
        WYRELOG_E_OK);
    create_provisioned_graph_fixture (policy, root, "tenant-a", "orders");
    append_provisioned_batch (policy, root, "tenant-a", "orders");
  }
  g_autoptr (WylHandle) handle = NULL;
  WylHandleOpenOptions options = {.policy_store_path = policy_path,
                                  .fact_root = root};
  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);
  g_autofree gchar *relation = wyl_fact_replay_wirelog_relation_name
        ("shop.ns", "orders-rel");
  g_autofree gchar *observed = g_strdup_printf ("%s_observed", relation);
  guint rows = 0;
  g_assert_cmpint (wyl_handle_snapshot_fact_graph_relation (handle, "tenant-a",
      "orders", observed, count_live_order, &rows), ==, WYRELOG_E_OK);
  g_assert_cmpuint (rows, ==, 1);
  gboolean before_open = GPOINTER_TO_INT (data) != 0;
  PolicySealChild child = { 0 };
  BeforeAdmissionProbe probe = {policy_path, &child, 0};
  wyrelog_error_t unseal_rc = WYRELOG_E_OK;
  wyrelog_error_t release_rc = WYRELOG_E_OK;
  if (before_open) {
    g_autoptr (WylServiceAuthWriteLease) lease = NULL;
    g_assert_cmpint (wyl_service_auth_authority_acquire_write
          (wyl_handle_get_service_auth_authority (handle), handle, NULL,
        &lease), ==, WYRELOG_E_OK);
    wyl_policy_fact_graph_info_t info = {
      .tenant_id = "tenant-a", .graph_id = "orders",
    };
    WylFactGraphSealOutcome sealed_outcome = { 0 };
    wyrelog_error_t initial_seal = wyl_handle_seal_fact_graph (handle, lease,
            &info, G_TIME_SPAN_SECOND, &sealed_outcome);
    wyl_fact_graph_seal_outcome_clear (&sealed_outcome);
    if (initial_seal != WYRELOG_E_OK) {
      (void) wyl_service_auth_write_lease_release_terminal (&lease);
      g_assert_cmpint (initial_seal, ==, WYRELOG_E_OK);
    }
    WylFactGraphUnsealOutcome outcome = { 0 };
    wyl_fact_graph_seal_set_test_hook (seal_before_admission_hook, &probe);
    unseal_rc = wyl_handle_unseal_fact_graph (handle, lease, &info,
            G_TIME_SPAN_SECOND, &outcome);
    wyl_fact_graph_seal_set_test_hook (NULL, NULL);
    wyl_fact_graph_unseal_outcome_clear (&outcome);
    release_rc = wyl_service_auth_write_lease_release_terminal (&lease);
  } else {
    run_policy_seal_child (policy_path, &child);
  }
  gint startup = WYRELOG_E_INTERNAL;
  gint seal = WYRELOG_E_INTERNAL;
  gboolean protocol_ok = !child.timed_out && child.communicate_ok
      && child.successful && child.error == NULL
      && (child.stderr_text == NULL || child.stderr_text[0] == '\0')
      && parse_policy_seal_result (child.stdout_text, &startup, &seal);
  WylPolicyGraphAuthorityRecord *authority = NULL;
  {
    g_autoptr (wyl_policy_store_t) observer = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &observer), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_read_graph_authority (observer,
        "tenant-a", "orders", &authority), ==, WYRELOG_E_OK);
  }
  guint fresh_rows = 0;
  wyrelog_error_t snapshot_rc = wyl_handle_snapshot_fact_graph_relation
        (handle, "tenant-a", "orders", observed, count_live_order, &fresh_rows);
  gboolean sealed = authority->sealed_compatibility;
  g_printerr ("before-open=%d checkpoints=%u protocol=%d timeout=%d "
      "startup=%d seal=%d unseal=%d authority-sealed=%d lifecycle=%d "
      "generation=%" G_GUINT64_FORMAT " fresh-snapshot=%d rows=%u\n",
      before_open, probe.calls, protocol_ok, child.timed_out, startup, seal,
      unseal_rc, sealed, authority->lifecycle_state,
      authority->lifecycle_generation, snapshot_rc, fresh_rows);
  gboolean unsafe = seal == WYRELOG_E_OK && sealed
      && snapshot_rc == WYRELOG_E_OK && fresh_rows == 1;
  wyl_policy_graph_authority_record_free (authority);
  g_clear_pointer (&child.stdout_text, g_free);
  g_clear_pointer (&child.stderr_text, g_free);
  g_clear_error (&child.error);
  g_clear_object (&handle);
  remove_tree (root);
  g_assert_true (protocol_ok);
  g_assert_cmpint (release_rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (startup, ==, WYRELOG_E_OK);
  g_assert_cmpint (seal, ==, WYRELOG_E_BUSY);
  if (before_open) {
    g_assert_cmpuint (probe.calls, ==, 1);
    g_assert_cmpint (unseal_rc, ==, WYRELOG_E_OK);
  }
  g_assert_true (snapshot_rc == WYRELOG_E_OK || snapshot_rc == WYRELOG_E_BUSY);
  g_assert_false (sealed);
  if (snapshot_rc == WYRELOG_E_OK)
    g_assert_cmpuint (fresh_rows, ==, 1);
  g_assert_false (unsafe);
#endif
}

static WylFactGraphRuntimeStatus
status_of (WylFactGraphRuntimeManager *manager, const gchar *tenant_id,
    const gchar *graph_id)
{
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, tenant_id, graph_id), ==,
      WYRELOG_E_OK);
  WylFactGraphRuntimeStatus status = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (manager, &key,
      &status), ==, WYRELOG_E_OK);
  wyl_fact_graph_key_clear (&key);
  return status;
}

/* A seal is durable in the policy store and was not durable in the runtime:
 * before the boot hook, a restart reopened every graph the policy store still
 * called sealed.  The hook writes the axis in both directions, because
 * closing the sealed ones and leaving the rest alone would strand any graph
 * unsealed out of band while the daemon was down. */
static void
test_boot_reestablishes_admission_from_the_durable_seal (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-graph-seal-XXXXXX", &error);
  g_assert_nonnull (root);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.db", NULL);

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==,
        WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "sealed-graph");
    create_graph_with_schema (policy, root, "tenant-a", "open-graph");
    g_assert_cmpint (wyl_policy_store_seal_fact_graph (policy, "tenant-a",
        "sealed-graph"), ==, WYRELOG_E_OK);
  }

  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactGraphRuntimeManager) manager = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&manager), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t summary = { 0 };
  (void) wyl_fact_replay_policy_graphs (policy, root, manager, &summary);

  /* Sealing is a decision, not a fault.  Before this the sealed graph landed
   * in graphs_degraded and reported schema_mismatch to an operator.
   *
   * degraded is 1, and it is the OTHER graph: this fixture writes no fact
   * store to disk, so an unsealed graph's engine build legitimately fails.
   * That is what makes the pair discriminating -- without the hook both
   * graphs land in degraded and graphs_sealed stays zero. */
  g_assert_cmpuint (summary.graphs_sealed, ==, 1);
  g_assert_cmpuint (summary.graphs_degraded, ==, 1);

  WylFactGraphRuntimeStatus sealed = status_of (manager, "tenant-a",
          "sealed-graph");
  g_assert_cmpint (sealed.admission, ==, WYL_FACT_GRAPH_ADMISSION_CLOSED);
  /* DEGRADED, not EVICTED: boot closes admission and leaves the state alone.
   * Evicting here would only move it to EVICTED, which the status reader
   * skips -- the graph would vanish from an operator's listing rather than
   * merely being misclassified.  The live seal owns the eviction, together
   * with the surface change that makes a sealed graph reportable. */
  g_assert_cmpint (sealed.state, ==, WYL_FACT_GRAPH_RUNTIME_DEGRADED);
  g_assert_false (sealed.queryable);
  wyl_fact_graph_runtime_status_clear (&sealed);

  /* The other direction, and it is the half that is easy to omit. */
  WylFactGraphRuntimeStatus open = status_of (manager, "tenant-a",
          "open-graph");
  g_assert_cmpint (open.admission, ==, WYL_FACT_GRAPH_ADMISSION_OPEN);
  wyl_fact_graph_runtime_status_clear (&open);

  /* The open direction is not a no-op, and this is the case that shows it.
   * Close the unsealed graph by hand -- standing in for a previous boot that
   * closed it while it was sealed -- and run the pass again.  The hook has to
   * be a function of the durable bit, so it must reopen; a hook that only
   * closes would leave a graph unsealed out of band permanently barred. */
  WylFactGraphKey open_key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&open_key, "tenant-a",
      "open-graph"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission (manager,
      &open_key), ==, WYRELOG_E_OK);
  WylFactGraphRuntimeStatus barred = status_of (manager, "tenant-a",
          "open-graph");
  g_assert_cmpint (barred.admission, ==, WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_runtime_status_clear (&barred);

  wyl_fact_replay_summary_t again = { 0 };
  (void) wyl_fact_replay_policy_graphs (policy, root, manager, &again);
  WylFactGraphRuntimeStatus reopened = status_of (manager, "tenant-a",
          "open-graph");
  g_assert_cmpint (reopened.admission, ==, WYL_FACT_GRAPH_ADMISSION_OPEN);
  /* The axis is restored; the graph is not.  The reopen runs after the
   * refresh in the same pass, so the refresh that would have rebuilt the
   * engine was still refused -- recovery takes a second pass.  Latent today
   * because there is no unseal route at all, but it is the half the stated
   * motivation actually needs, so it is pinned rather than assumed. */
  g_assert_false (reopened.queryable);
  wyl_fact_graph_runtime_status_clear (&reopened);
  /* And the sealed one is still closed after a second pass. */
  WylFactGraphRuntimeStatus still = status_of (manager, "tenant-a",
          "sealed-graph");
  g_assert_cmpint (still.admission, ==, WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_runtime_status_clear (&still);
  wyl_fact_graph_key_clear (&open_key);

  /* The barrier really holds: no new snapshot on the sealed graph. */
  WylFactGraphKey sealed_key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&sealed_key, "tenant-a",
      "sealed-graph"), ==, WYRELOG_E_OK);
  WylFactGraphSnapshot *snapshot = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
      &sealed_key, &snapshot), ==, WYRELOG_E_BUSY);
  g_assert_null (snapshot);
  wyl_fact_graph_key_clear (&sealed_key);
  remove_tree (root);
}

/* Closing admission does not disturb the erasure verdict.  That is all this
 * proves, and it is worth proving because the two writes sit next to each
 * other in the boot loop.
 *
 * It does NOT prove the ordering between them.  set_forget_state refuses an
 * EVICTED entry, so once the live seal starts evicting, an admission write
 * placed ahead of it would leave the axis at its default CONVERGED over an
 * erasure that is still owed.  The boot path does not evict, so swapping the
 * two blocks today changes nothing and no test can tell -- verified by doing
 * it.  Whoever adds the eviction owns making that ordering falsifiable. */
static void
test_boot_admission_write_does_not_clobber_the_forget_verdict (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-graph-seal-forget-XXXXXX", &error);
  g_assert_nonnull (root);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.db", NULL);

  {
    g_autoptr (wyl_policy_store_t) policy = NULL;
    g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (policy), ==,
        WYRELOG_E_OK);
    create_graph_with_schema (policy, root, "tenant-a", "sealed-graph");
    g_assert_cmpint (wyl_policy_store_seal_fact_graph (policy, "tenant-a",
        "sealed-graph"), ==, WYRELOG_E_OK);
  }

  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactGraphRuntimeManager) manager = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&manager), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t summary = { 0 };
  (void) wyl_fact_replay_policy_graphs (policy, root, manager, &summary);

  /* Write the verdict the way the loop does for a graph with a pending
   * intent, then read it back through the same surface the loop wrote the
   * admission axis on. */
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "sealed-graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_set_forget_state (manager,
      &key, WYL_FACT_GRAPH_FORGET_INCOMPLETE), ==, WYRELOG_E_OK);

  WylFactGraphRuntimeStatus after = status_of (manager, "tenant-a",
          "sealed-graph");
  g_assert_cmpint (after.forget_state, ==, WYL_FACT_GRAPH_FORGET_INCOMPLETE);
  g_assert_cmpint (after.admission, ==, WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_runtime_status_clear (&after);

  wyl_fact_graph_key_clear (&key);
  remove_tree (root);
}

/* A live seal denies new work, waits for admitted work, commits the durable
 * bit, and only then takes the engine away.  Success means all four. */
/* Fail a named phase of the seal, and count every phase reached.
 *
 * The counts are what make the two tests below evidence rather than
 * description.  A seam that never fires leaves the seal succeeding, and the
 * assertions would then be pinning the ordinary path while claiming to pin the
 * ambiguous one.  #945 records exactly that mistake being made once already:
 * the first version of this seam let the write run and replaced its result
 * afterwards, so the compensating re-read found the graph genuinely sealed and
 * control took the recovery arm -- measuring identically to the unhooked code,
 * which reads as "no difference" rather than "the branch was never reached". */
typedef struct
{
  gboolean fail_write;
  gboolean fail_probe;
  gboolean shutdown_at_write;
  WylFactGraphRuntimeManager *manager;
  guint write_seen;
  guint probe_seen;
  gboolean fail_unseal_reseal;
  const gchar *replace_path;
  const gchar *replacement_path;
  const gchar *foreign_path;
  gboolean replacement_attempted;
  gboolean replacement_blocked;
  gboolean replacement_setup_failed;
  gint replacement_errno;
} SealPhaseFault;

static wyrelog_error_t
seal_phase_fault (const gchar *phase, gpointer user_data)
{
  SealPhaseFault *fault = user_data;
  if (g_strcmp0 (phase, WYL_FACT_GRAPH_SEAL_PHASE_DURABLE_WRITE) == 0) {
    fault->write_seen++;
    /* Shutting the manager down here is what makes the compensating reopen
     * intended but ineffective: open_admission refuses a shut-down manager.
     * It happens at the write phase because that is the last point before
     * the branch under test decides what to report. */
    if (fault->shutdown_at_write)
      wyl_fact_graph_runtime_manager_shutdown (fault->manager);
    return fault->fail_write ? WYRELOG_E_IO : WYRELOG_E_OK;
  }
  if (g_strcmp0 (phase, WYL_FACT_GRAPH_SEAL_PHASE_RESEAL_PROBE) == 0) {
    fault->probe_seen++;
    return fault->fail_probe ? WYRELOG_E_IO : WYRELOG_E_OK;
  }
  if (g_strcmp0 (phase, WYL_FACT_GRAPH_SEAL_PHASE_UNSEAL_RESEAL) == 0)
    return fault->fail_unseal_reseal ? WYRELOG_E_IO : WYRELOG_E_OK;
  if (g_strcmp0 (phase,
      WYL_FACT_GRAPH_SEAL_PHASE_UNSEAL_BEFORE_PUBLICATION) == 0) {
    fault->replacement_attempted = TRUE;
    if (g_rename (fault->replace_path, fault->replacement_path) != 0) {
      fault->replacement_errno = errno;
      if (!g_file_test (fault->replace_path, G_FILE_TEST_IS_REGULAR))
        fault->replacement_setup_failed = TRUE;
      else
        fault->replacement_blocked = TRUE;
      return fault->replacement_setup_failed ? WYRELOG_E_IO : WYRELOG_E_OK;
    }
    if (g_rename (fault->foreign_path, fault->replace_path) != 0) {
      (void) g_remove (fault->replace_path);
      (void) g_rename (fault->replacement_path, fault->replace_path);
      fault->replacement_setup_failed = TRUE;
      return WYRELOG_E_IO;
    }
    return WYRELOG_E_OK;
  }
  return WYRELOG_E_OK;
}

typedef struct
{
  const gchar *tenant_id;
  const gchar *graph_id;
  gboolean found;
  gboolean sealed;
} SealedBitProbe;

static wyrelog_error_t
capture_sealed_bit_cb (const wyl_policy_fact_graph_info_t *info,
    gpointer user_data)
{
  SealedBitProbe *probe = user_data;
  if (g_strcmp0 (probe->tenant_id, info->tenant_id) == 0
      && g_strcmp0 (probe->graph_id, info->graph_id) == 0) {
    probe->found = TRUE;
    probe->sealed = info->sealed;
  }
  return WYRELOG_E_OK;
}

/* A live, replayed, sealable graph: the same fixture the barrier test builds,
 * factored out because the two ambiguous-write cases need it twice more. */
typedef struct
{
  gchar *root;
  wyl_policy_store_t *policy;
  WylFactGraphRuntimeManager *manager;
} SealFixture;

static void
seal_fixture_init (SealFixture *fixture, const gchar *template_name)
{
  g_autoptr (GError) error = NULL;
  fixture->root = wyl_test_make_secure_fact_root (template_name, &error);
  g_assert_nonnull (fixture->root);
  g_autofree gchar *policy_path = g_build_filename (fixture->root,
          "policy.db", NULL);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &fixture->policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (fixture->policy), ==,
      WYRELOG_E_OK);
  create_graph_with_schema (fixture->policy, fixture->root, "tenant-a",
      "orders");
  materialize_graph_engine (fixture->policy, fixture->root, "tenant-a", "orders");
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&fixture->manager), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t summary = { 0 };
  (void) wyl_fact_replay_policy_graphs (fixture->policy, fixture->root,
      fixture->manager, &summary);
  g_assert_cmpuint (summary.graphs_loaded, ==, 1);
}

static void
seal_fixture_clear (SealFixture *fixture)
{
  wyl_fact_graph_seal_set_test_hook (NULL, NULL);
  g_clear_pointer (&fixture->manager, wyl_fact_graph_runtime_manager_unref);
  g_clear_pointer (&fixture->policy, wyl_policy_store_close);
  g_clear_pointer (&fixture->root, g_free);
}

static void
authority_seal_fixture_init (SealFixture *fixture, const gchar *template_name)
{
  g_autoptr (GError) error = NULL;
  fixture->root = wyl_test_make_secure_fact_root (template_name, &error);
  g_assert_nonnull (fixture->root);
  g_autofree gchar *policy_path = g_build_filename (fixture->root,
          "policy.db", NULL);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &fixture->policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (fixture->policy), ==,
      WYRELOG_E_OK);
  create_authority_graph_with_schema (fixture->policy, fixture->root,
      "tenant-a", "orders");
  materialize_graph_engine (fixture->policy, fixture->root, "tenant-a", "orders");
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&fixture->manager), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t summary = { 0 };
  (void) wyl_fact_replay_policy_graphs (fixture->policy, fixture->root,
      fixture->manager, &summary);
  g_assert_cmpuint (summary.graphs_loaded, ==, 1);
}

static void
test_unseal_rebuilds_before_reopening (void)
{
  SealFixture fixture = { 0 };
  g_autoptr (GError) error = NULL;
  fixture.root = wyl_test_make_secure_fact_root
        ("wyl-graph-unseal-success-XXXXXX", &error);
  g_assert_nonnull (fixture.root);
  g_autofree gchar *policy_path = g_build_filename (fixture.root, "policy.db",
          NULL);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &fixture.policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (fixture.policy), ==,
      WYRELOG_E_OK);
  create_authority_graph_with_schema (fixture.policy, fixture.root, "tenant-a",
      "orders");
  materialize_graph_engine (fixture.policy, fixture.root, "tenant-a", "orders");
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&fixture.manager), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t summary = { 0 };
  (void) wyl_fact_replay_policy_graphs (fixture.policy, fixture.root,
      fixture.manager, &summary);
  g_assert_cmpuint (summary.graphs_loaded, ==, 1);

  PublicationLockTrace trace = { 0 };
  g_mutex_init (&trace.mutex);
  trace.events = g_array_new (FALSE, FALSE,
          sizeof (WylFactPublicationLockEvent));

  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome sealed = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (fixture.policy, &info, fixture.manager,
      -1, &sealed), ==, WYRELOG_E_OK);
  g_assert_true (sealed.engine_evicted);
  wyl_fact_graph_seal_outcome_clear (&sealed);

  WylFactGraphUnsealOutcome unsealed = { 0 };
  wyl_fact_publication_lock_event_set_hook (publication_lock_trace_event,
      &trace);
  g_assert_cmpint (wyl_fact_graph_unseal_for_test (fixture.policy, fixture.root, &info,
      fixture.manager, -1, &unsealed), ==, WYRELOG_E_OK);
  wyl_fact_publication_lock_event_set_hook (NULL, NULL);
  g_assert_true (unsealed.durable_unseal_applied);
  g_assert_true (unsealed.engine_published);
  g_assert_true (unsealed.runtime_admission_open);
  g_assert_cmpint (unsealed.policy_result,
      ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (unsealed.status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_OPEN);
  g_assert_cmpint (unsealed.status.state, ==, WYL_FACT_GRAPH_RUNTIME_READY);
  g_assert_true (unsealed.status.queryable);

#ifdef WYL_HAS_SECURE_DUCKDB_BRIDGE
  guint artifact_acquired = G_MAXUINT;
#endif
  guint runtime_writer_acquired = G_MAXUINT;
  guint runtime_state_acquired = G_MAXUINT;
  guint policy_acquired = G_MAXUINT;
  for (guint i = 0; i < trace.events->len; i++) {
    WylFactPublicationLockEvent event =
        g_array_index (trace.events, WylFactPublicationLockEvent, i);
    if (event.phase != WYL_FACT_PUBLICATION_LOCK_ACQUIRED)
      continue;
#ifdef WYL_HAS_SECURE_DUCKDB_BRIDGE
    if (event.domain == WYL_FACT_PUBLICATION_LOCK_ARTIFACT_LEASE
        && artifact_acquired == G_MAXUINT)
      artifact_acquired = i;
    else if (event.domain == WYL_FACT_PUBLICATION_LOCK_RUNTIME_WRITER
#else
    if (event.domain == WYL_FACT_PUBLICATION_LOCK_RUNTIME_WRITER
#endif
        && runtime_writer_acquired == G_MAXUINT)
      runtime_writer_acquired = i;
    else if (event.domain == WYL_FACT_PUBLICATION_LOCK_RUNTIME_STATE
        && runtime_writer_acquired != G_MAXUINT
        && i > runtime_writer_acquired
        && runtime_state_acquired == G_MAXUINT)
      runtime_state_acquired = i;
    else if (event.domain == WYL_FACT_PUBLICATION_LOCK_POLICY_FENCE
        && runtime_state_acquired != G_MAXUINT
        && i > runtime_state_acquired
        && policy_acquired == G_MAXUINT)
      policy_acquired = i;
  }
#ifdef WYL_HAS_SECURE_DUCKDB_BRIDGE
  g_assert_cmpuint (artifact_acquired, !=, G_MAXUINT);
#endif
  g_assert_cmpuint (runtime_writer_acquired, !=, G_MAXUINT);
  g_assert_cmpuint (runtime_state_acquired, !=, G_MAXUINT);
  g_assert_cmpuint (policy_acquired, !=, G_MAXUINT);
#ifdef WYL_HAS_SECURE_DUCKDB_BRIDGE
  g_assert_cmpuint (artifact_acquired, <, runtime_writer_acquired);
#endif
  g_assert_cmpuint (runtime_writer_acquired, <, runtime_state_acquired);
  g_assert_cmpuint (runtime_state_acquired, <, policy_acquired);
  g_array_free (trace.events, TRUE);
  g_mutex_clear (&trace.mutex);

  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  g_autoptr (WylFactGraphSnapshot) snapshot = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot
        (fixture.manager, &key, &snapshot), ==, WYRELOG_E_OK);
  g_assert_nonnull (snapshot);
  wyl_fact_graph_key_clear (&key);
  wyl_fact_graph_unseal_outcome_clear (&unsealed);
  g_autofree gchar *root = g_strdup (fixture.root);
  seal_fixture_clear (&fixture);
  remove_tree (root);
}

typedef struct
{
  GMutex mutex;
  GCond changed;
  guint ready;
  gboolean release;
} ConcurrentUnsealStart;

typedef struct
{
  GMutex mutex;
  GCond changed;
  gboolean held;
  gboolean release;
  gboolean timed_out;
} ConcurrentUnsealHold;

typedef struct
{
  wyl_policy_store_t *policy;
  const gchar *root;
  WylFactGraphRuntimeManager *manager;
  ConcurrentUnsealStart *start;
  GMutex mutex;
  GCond changed;
  wyrelog_error_t result;
  WylFactGraphUnsealOutcome outcome;
  gboolean completed;
} ConcurrentUnsealCall;

static gpointer
concurrent_unseal_call_thread (gpointer user_data)
{
  ConcurrentUnsealCall *call = user_data;
  g_mutex_lock (&call->start->mutex);
  call->start->ready++;
  g_cond_broadcast (&call->start->changed);
  while (!call->start->release)
    g_cond_wait (&call->start->changed, &call->start->mutex);
  g_mutex_unlock (&call->start->mutex);
  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  call->result = wyl_fact_graph_unseal_for_test (call->policy, call->root,
          &info, call->manager, -1, &call->outcome);
  g_mutex_lock (&call->mutex);
  call->completed = TRUE;
  g_cond_broadcast (&call->changed);
  g_mutex_unlock (&call->mutex);
  return NULL;
}

static wyrelog_error_t
concurrent_unseal_hold_before_publication (const gchar *phase,
    gpointer user_data)
{
  ConcurrentUnsealHold *hold = user_data;
  if (g_strcmp0 (phase, WYL_FACT_GRAPH_SEAL_PHASE_UNSEAL_BEFORE_PUBLICATION)
      != 0)
    return WYRELOG_E_OK;
  g_mutex_lock (&hold->mutex);
  hold->held = TRUE;
  g_cond_broadcast (&hold->changed);
  gint64 deadline = g_get_monotonic_time () + 15 * G_TIME_SPAN_SECOND;
  while (!hold->release) {
    if (!g_cond_wait_until (&hold->changed, &hold->mutex, deadline)) {
      hold->timed_out = TRUE;
      break;
    }
  }
  gboolean released = hold->release;
  g_mutex_unlock (&hold->mutex);
  return released ? WYRELOG_E_OK : WYRELOG_E_BUSY;
}

static void
test_concurrent_unseal_converges_after_loser_abort (void)
{
  SealFixture fixture = { 0 };
  ConcurrentUnsealStart start = { 0 };
  ConcurrentUnsealHold hold = { 0 };
  g_mutex_init (&start.mutex);
  g_cond_init (&start.changed);
  g_mutex_init (&hold.mutex);
  g_cond_init (&hold.changed);
  authority_seal_fixture_init (&fixture, "wyl-unseal-concurrent-XXXXXX");
  WylFactGraphSealOutcome sealed = { 0 };
  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  g_assert_cmpint (wyl_fact_graph_seal (fixture.policy, &info, fixture.manager,
      -1, &sealed), ==, WYRELOG_E_OK);
  wyl_fact_graph_seal_outcome_clear (&sealed);

  ConcurrentUnsealCall first = {
    .policy = fixture.policy, .root = fixture.root, .manager = fixture.manager,
    .start = &start, .result = WYRELOG_E_INTERNAL,
  };
  ConcurrentUnsealCall second = first;
  g_mutex_init (&first.mutex);
  g_cond_init (&first.changed);
  g_mutex_init (&second.mutex);
  g_cond_init (&second.changed);
  wyl_fact_graph_seal_set_test_hook
    (concurrent_unseal_hold_before_publication, &hold);
  GThread *first_thread = g_thread_new ("unseal-first",
          concurrent_unseal_call_thread, &first);
  GThread *second_thread = g_thread_new ("unseal-second",
          concurrent_unseal_call_thread, &second);

  g_mutex_lock (&start.mutex);
  gint64 start_deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  while (start.ready < 2) {
    if (!g_cond_wait_until (&start.changed, &start.mutex, start_deadline))
      break;
  }
  g_assert_cmpuint (start.ready, ==, 2);
  start.release = TRUE;
  g_cond_broadcast (&start.changed);
  g_mutex_unlock (&start.mutex);

  g_mutex_lock (&hold.mutex);
  gint64 hold_deadline = g_get_monotonic_time () + 15 * G_TIME_SPAN_SECOND;
  while (!hold.held) {
    if (!g_cond_wait_until (&hold.changed, &hold.mutex, hold_deadline))
      break;
  }
  g_assert_true (hold.held);
  g_assert_false (hold.timed_out);
  hold.release = TRUE;
  g_cond_broadcast (&hold.changed);
  g_mutex_unlock (&hold.mutex);

  gint64 completion_deadline = g_get_monotonic_time ()
      + 15 * G_TIME_SPAN_SECOND;
  g_mutex_lock (&first.mutex);
  while (!first.completed)
    if (!g_cond_wait_until (&first.changed, &first.mutex,
        completion_deadline))
      break;
  gboolean first_completed = first.completed;
  g_mutex_unlock (&first.mutex);
  g_mutex_lock (&second.mutex);
  while (!second.completed)
    if (!g_cond_wait_until (&second.changed, &second.mutex,
        completion_deadline))
      break;
  gboolean second_completed = second.completed;
  g_mutex_unlock (&second.mutex);
  g_assert_true (first_completed);
  g_assert_true (second_completed);
  g_thread_join (first_thread);
  g_thread_join (second_thread);
  guint successes = (first.result == WYRELOG_E_OK)
      + (second.result == WYRELOG_E_OK);
  g_assert_cmpuint (successes, ==, 1);
  ConcurrentUnsealCall *loser = first.result == WYRELOG_E_OK
      ? &second : &first;
  g_test_message ("concurrent unseal results: winner=%d loser=%d",
      (first.result == WYRELOG_E_OK ? first.result : second.result),
      loser->result);
  g_assert_cmpint (loser->result, !=, WYRELOG_E_OK);
  WylFactGraphRuntimeStatus final = status_of (fixture.manager, "tenant-a",
          "orders");
  g_assert_cmpint (final.state, ==, WYL_FACT_GRAPH_RUNTIME_READY);
  g_assert_cmpint (final.admission, ==, WYL_FACT_GRAPH_ADMISSION_OPEN);
  g_assert_true (final.queryable);
  g_assert_false (final.operation_active);
  g_assert_cmpuint (final.active_engine_calls, ==, 0);
  g_assert_cmpuint (final.waiting_engine_calls, ==, 0);
  g_assert_cmpuint (final.waiting_drains, ==, 0);
  wyl_fact_graph_runtime_status_clear (&final);
  wyl_fact_graph_unseal_outcome_clear (&first.outcome);
  wyl_fact_graph_unseal_outcome_clear (&second.outcome);
  wyl_fact_graph_seal_set_test_hook (NULL, NULL);
  g_cond_clear (&first.changed);
  g_mutex_clear (&first.mutex);
  g_cond_clear (&second.changed);
  g_mutex_clear (&second.mutex);
  g_cond_clear (&hold.changed);
  g_mutex_clear (&hold.mutex);
  g_cond_clear (&start.changed);
  g_mutex_clear (&start.mutex);
  g_autofree gchar *root = g_strdup (fixture.root);
  seal_fixture_clear (&fixture);
  remove_tree (root);
}

typedef struct
{
  wyrelog_error_t open_rc;
} PublicationOpenProbe;

static void
probe_publication_open (WylFactGraphRuntimeManager *manager,
    const WylFactGraphKey *key, gpointer user_data)
{
  PublicationOpenProbe *probe = user_data;
  probe->open_rc = wyl_fact_graph_runtime_manager_open_admission (manager,
          key);
}

static void
test_publication_blocks_external_open (void)
{
  SealFixture fixture = { 0 };
  authority_seal_fixture_init (&fixture,
      "wyl-graph-publication-open-XXXXXX");
  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome sealed = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (fixture.policy, &info, fixture.manager,
      -1, &sealed), ==, WYRELOG_E_OK);
  wyl_fact_graph_seal_outcome_clear (&sealed);

  PublicationOpenProbe probe = { WYRELOG_E_INTERNAL };
  wyl_fact_graph_runtime_set_publication_test_hook (probe_publication_open,
      &probe);
  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (wyl_fact_graph_unseal_for_test (fixture.policy,
      fixture.root, &info, fixture.manager, -1, &outcome), ==, WYRELOG_E_OK);
  wyl_fact_graph_runtime_set_publication_test_hook (NULL, NULL);
  g_assert_cmpint (probe.open_rc, ==, WYRELOG_E_BUSY);
  g_assert_true (outcome.runtime_admission_open);
  wyl_fact_graph_unseal_outcome_clear (&outcome);
  seal_fixture_clear (&fixture);
}

static void
test_unseal_build_failure_reseals_and_stays_closed (void)
{
  SealFixture fixture = { 0 };
  g_autoptr (GError) error = NULL;
  fixture.root = wyl_test_make_secure_fact_root
        ("wyl-graph-unseal-failure-XXXXXX", &error);
  g_assert_nonnull (fixture.root);
  g_autofree gchar *policy_path = g_build_filename (fixture.root, "policy.db",
          NULL);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &fixture.policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (fixture.policy), ==,
      WYRELOG_E_OK);
  create_authority_graph_with_schema (fixture.policy, fixture.root, "tenant-a",
      "orders");
  materialize_graph_engine (fixture.policy, fixture.root, "tenant-a", "orders");
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&fixture.manager), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t summary = { 0 };
  (void) wyl_fact_replay_policy_graphs (fixture.policy, fixture.root,
      fixture.manager, &summary);
  g_assert_cmpuint (summary.graphs_loaded, ==, 1);
  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome sealed = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (fixture.policy, &info, fixture.manager,
      -1, &sealed), ==, WYRELOG_E_OK);
  wyl_fact_graph_seal_outcome_clear (&sealed);

  GraphPathProbe path = { "tenant-a", "orders", NULL };
  g_assert_cmpint (wyl_policy_store_foreach_fact_graph (fixture.policy,
      "tenant-a", capture_graph_path_cb, &path), ==, WYRELOG_E_OK);
  g_assert_nonnull (path.storage_path);
  g_autofree gchar *fact_path = g_build_filename (path.storage_path,
          "facts.duckdb", NULL);
  g_assert_cmpint (g_remove (fact_path), ==, 0);

  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (wyl_fact_graph_unseal_for_test (fixture.policy, fixture.root, &info,
      fixture.manager, -1, &outcome), !=, WYRELOG_E_OK);
  g_assert_true (outcome.durable_unseal_applied);
  g_assert_true (outcome.durable_reseal_applied);
  g_assert_false (outcome.engine_published);
  g_assert_false (outcome.runtime_admission_open);
  g_assert_cmpint (outcome.status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_unseal_outcome_clear (&outcome);

  WylPolicyGraphAuthorityRecord *authority = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (fixture.policy,
      "tenant-a", "orders", &authority), ==, WYRELOG_E_OK);
  g_assert_nonnull (authority);
  g_assert_cmpint (authority->lifecycle_state, ==,
      WYL_POLICY_GRAPH_LIFECYCLE_SEALED);
  g_assert_true (authority->sealed_compatibility);
  wyl_policy_graph_authority_record_free (authority);
  g_autofree gchar *root = g_strdup (fixture.root);
  seal_fixture_clear (&fixture);
  remove_tree (root);
}

static void
test_unseal_requires_handle_write_lease (void)
{
  SealFixture fixture = { 0 };
  authority_seal_fixture_init (&fixture, "wyl-unseal-lease-XXXXXX");
  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  g_assert_cmpint (wyl_fact_graph_unseal (fixture.policy, NULL, NULL, NULL,
      &info, fixture.manager, -1, NULL), ==, WYRELOG_E_INVALID);
  seal_fixture_clear (&fixture);
}

#ifdef WYL_HAS_SECURE_DUCKDB_BRIDGE
/* Test-only access deliberately bypasses identity validation for corruption
 * and restoration, while retaining the bounded filesystem and artifact lease. */
static void
open_metadata_test_bridge (SealFixture *fixture, WylSecureDuckdbBridge **bridge,
    duckdb_database *db, duckdb_connection *conn)
{
  GPtrArray *records = NULL;
  g_assert_cmpint (wyl_policy_store_graph_provisioning_list (fixture->policy,
      "tenant-a", &records), ==, WYRELOG_E_OK);
  g_assert_cmpuint (records->len, ==, 1);
  WylPolicyGraphProvisioningRecord *record = g_ptr_array_index (records, 0);
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_assert_cmpint (wyl_policy_store_open_fact_graph_directory (fixture->policy,
      fixture->root, "tenant-a", "orders", FALSE, &directory), ==,
      WYRELOG_E_OK);
  WylFactGraphProvisionedPair *pair = NULL;
#ifdef __APPLE__
  WylFactGraphDarwinOperationEvidence evidence = { 0 };
  gsize length = 0;
  const guint8 *bytes = g_bytes_get_data (record->darwin_operation_evidence,
          &length);
  g_assert_cmpint (wyl_fact_graph_darwin_evidence_decode (bytes, length,
      record->op_uuid, &evidence), ==, WYRELOG_E_OK);
  g_assert_cmpint
    (wyl_fact_graph_directory_open_darwin_provisioned_pair_exact_with_evidence
        (&directory, record->op_uuid, &evidence, &pair), ==, WYRELOG_E_OK);
#else
  g_assert_cmpint (wyl_fact_graph_directory_open_provisioned_pair_exact
        (&directory, record->op_uuid, &pair), ==, WYRELOG_E_OK);
#endif
  WylFactArtifactNamespace *namespace_ = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_open_provisioned_pair_internal
        (pair, &namespace_), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_secure_duckdb_bridge_open_live_pair (namespace_, TRUE,
      bridge, db, conn), ==, WYRELOG_E_OK);
  wyl_fact_artifact_namespace_free (namespace_);
  wyl_fact_graph_provisioned_pair_free (pair);
  wyl_fact_graph_directory_clear (&directory);
  g_ptr_array_unref (records);
}

static void
metadata_query_ok (duckdb_connection conn, const gchar *sql)
{
  duckdb_result result;
  g_assert_cmpint (duckdb_query (conn, sql, &result), ==, DuckDBSuccess);
  duckdb_destroy_result (&result);
}

static void
test_unseal_rejects_persisted_metadata (gconstpointer data)
{
  const gchar *key_name = data;
  SealFixture fixture = { 0 };
  authority_seal_fixture_init (&fixture, "wyl-unseal-metadata-XXXXXX");
  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a", .graph_id = "orders",
  };
  WylFactGraphSealOutcome sealed = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (fixture.policy, &info, fixture.manager,
      -1, &sealed), ==, WYRELOG_E_OK);
  wyl_fact_graph_seal_outcome_clear (&sealed);
  GraphPathProbe path = { "tenant-a", "orders", NULL };
  g_assert_cmpint (wyl_policy_store_foreach_fact_graph (fixture.policy,
      "tenant-a", capture_graph_path_cb, &path), ==, WYRELOG_E_OK);
  g_autofree gchar *fact_path = g_build_filename (path.storage_path,
          "facts.duckdb", NULL);
  g_free (path.storage_path);
  FactGraphFileIdentity before = { 0 }, after = { 0 };
  g_assert_true (fact_graph_file_get_identity (fact_path, &before));
  WylSecureDuckdbBridge *bridge = NULL;
  duckdb_database db = NULL;
  duckdb_connection conn = NULL;
  open_metadata_test_bridge (&fixture, &bridge, &db, &conn);
  metadata_query_ok (conn,
      "ALTER TABLE fact_store_metadata RENAME TO saved_metadata;");
  if (g_strcmp0 (key_name, "missing") != 0) {
    metadata_query_ok (conn,
        "CREATE TABLE fact_store_metadata(key VARCHAR PRIMARY KEY,"
        "value VARCHAR NOT NULL);"
        "INSERT INTO fact_store_metadata SELECT * FROM saved_metadata;");
    if (g_strcmp0 (key_name, "schema") == 0)
      metadata_query_ok (conn, "DROP TABLE fact_store_metadata;"
          "CREATE TABLE fact_store_metadata AS SELECT * FROM saved_metadata;");
    else {
      g_autofree gchar *sql = g_strdup_printf
            ("UPDATE fact_store_metadata SET value='%s' WHERE key='%s';",
              g_strcmp0 (key_name, "store_uuid") == 0
            ? "01890f47-3c4b-7cc2-b8c4-dc0c0c079999" : "2", key_name);
      metadata_query_ok (conn, sql);
    }
  }
  duckdb_disconnect (&conn);
  duckdb_close (&db);
  g_assert_cmpint (wyl_secure_duckdb_bridge_release_live (bridge), ==,
      WYRELOG_E_OK);
  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (wyl_fact_graph_unseal_for_test (fixture.policy,
      fixture.root, &info, fixture.manager, -1, &outcome), ==, WYRELOG_E_POLICY);
  g_assert_false (outcome.engine_published);
  g_assert_false (outcome.runtime_admission_open);
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  WylFactGraphRuntimeStatus status = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_get_status (fixture.manager,
      &key, &status), ==, WYRELOG_E_OK);
  g_assert_false (status.queryable);
  g_assert_cmpint (status.admission, ==, WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_runtime_status_clear (&status);
  WylFactGraphSnapshot *snapshot = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot
        (fixture.manager, &key, &snapshot), !=, WYRELOG_E_OK);
  g_assert_null (snapshot);
  g_assert_true (fact_graph_file_get_identity (fact_path, &after));
  g_assert_cmpuint (before.device, ==, after.device);
  g_assert_cmpuint (before.file, ==, after.file);
  wyl_fact_graph_unseal_outcome_clear (&outcome);
  open_metadata_test_bridge (&fixture, &bridge, &db, &conn);
  metadata_query_ok (conn, "DROP TABLE IF EXISTS fact_store_metadata;"
      "ALTER TABLE saved_metadata RENAME TO fact_store_metadata;");
  duckdb_disconnect (&conn);
  duckdb_close (&db);
  g_assert_cmpint (wyl_secure_duckdb_bridge_release_live (bridge), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_unseal_for_test (fixture.policy,
      fixture.root, &info, fixture.manager, -1, &outcome), ==, WYRELOG_E_OK);
  g_assert_true (outcome.status.queryable);
  g_assert_true (outcome.runtime_admission_open);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot
        (fixture.manager, &key, &snapshot), ==, WYRELOG_E_OK);
  wyl_fact_graph_snapshot_unref (snapshot);
  wyl_fact_graph_key_clear (&key);
  wyl_fact_graph_unseal_outcome_clear (&outcome);
  g_autofree gchar *root = g_strdup (fixture.root);
  seal_fixture_clear (&fixture);
  remove_tree (root);
}

static void
test_unseal_rejects_provisioning_mismatch (gconstpointer data)
{
  SealFixture fixture = { 0 };
  authority_seal_fixture_init (&fixture, "wyl-unseal-record-mismatch-XXXXXX");
  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a", .graph_id = "orders",
  };
  WylFactGraphSealOutcome sealed = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (fixture.policy, &info, fixture.manager,
      -1, &sealed), ==, WYRELOG_E_OK);
  wyl_fact_graph_seal_outcome_clear (&sealed);
  sqlite3 *db = wyl_policy_store_get_db (fixture.policy);
  /* Model an inconsistent persisted record, bypassing only the fixture's
   * immutable-record guard so the read-side validation is exercised. */
  g_assert_cmpint (sqlite3_exec (db,
      "DROP TRIGGER fact_graph_provisioning_immutable;"
      "DROP TRIGGER fact_graph_provisioning_update_guard;", NULL, NULL, NULL),
      ==, SQLITE_OK);
  const gchar *sql = GPOINTER_TO_INT (data) == 0
      ? "UPDATE fact_graph_provisioning SET "
      "store_uuid='01890f47-3c4b-7cc2-b8c4-dc0c0c079999';"
      : GPOINTER_TO_INT (data) == 1
      ? "UPDATE fact_graph_provisioning SET darwin_operation_evidence=NULL;"
      : "UPDATE fact_graph_provisioning SET "
      "darwin_operation_evidence=zeroblob(length(darwin_operation_evidence));";
  g_assert_cmpint (sqlite3_exec (db, sql, NULL, NULL, NULL), ==, SQLITE_OK);
  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (wyl_fact_graph_unseal_for_test (fixture.policy,
      fixture.root, &info, fixture.manager, -1, &outcome), ==, WYRELOG_E_POLICY);
  g_assert_false (outcome.runtime_admission_open);
  g_assert_false (outcome.status.queryable);
  WylPolicyGraphAuthorityRecord *authority = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (fixture.policy,
      info.tenant_id, info.graph_id, &authority), ==, WYRELOG_E_OK);
  g_assert_cmpint (authority->lifecycle_state, ==,
      WYL_POLICY_GRAPH_LIFECYCLE_SEALED);
  wyl_policy_graph_authority_record_free (authority);
  wyl_fact_graph_unseal_outcome_clear (&outcome);
  g_autofree gchar *root = g_strdup (fixture.root);
  seal_fixture_clear (&fixture);
  remove_tree (root);
}
#endif

typedef struct
{
  sqlite3 *db;
  gboolean veto;
  guint installed;
  guint rejected;
} UnsealCommitFault;

static int
deny_unseal_commit (void *data, int action, const char *arg1,
    const char *arg2, const char *database, const char *trigger)
{
  (void) arg2;
  (void) database;
  (void) trigger;
  UnsealCommitFault *fault = data;
  if (action == SQLITE_TRANSACTION && g_strcmp0 (arg1, "COMMIT") == 0) {
    fault->rejected++;
    return SQLITE_DENY;
  }
  return SQLITE_OK;
}

static int
veto_unseal_commit (void *data)
{
  UnsealCommitFault *fault = data;
  fault->rejected++;
  return 1;
}

static wyrelog_error_t
arm_unseal_commit_fault (const gchar *phase, gpointer data)
{
  UnsealCommitFault *fault = data;
  if (g_strcmp0 (phase,
      WYL_FACT_GRAPH_SEAL_PHASE_UNSEAL_BEFORE_PUBLICATION) == 0) {
    fault->installed++;
    if (fault->veto)
      sqlite3_commit_hook (fault->db, veto_unseal_commit, fault);
    else
      g_assert_cmpint (sqlite3_set_authorizer (fault->db, deny_unseal_commit,
          fault), ==, SQLITE_OK);
  }
  return WYRELOG_E_OK;
}

static void
test_unseal_commit_failure_stays_closed (gconstpointer data)
{
  SealFixture fixture = { 0 };
  authority_seal_fixture_init (&fixture, "wyl-unseal-commit-failure-XXXXXX");
  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a", .graph_id = "orders",
  };
  WylFactGraphSealOutcome sealed = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (fixture.policy, &info, fixture.manager,
      -1, &sealed), ==, WYRELOG_E_OK);
  wyl_fact_graph_seal_outcome_clear (&sealed);
  WylPolicyGraphAuthorityRecord *authority = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (fixture.policy,
      info.tenant_id, info.graph_id, &authority), ==, WYRELOG_E_OK);
  guint64 generation = authority->lifecycle_generation;
  wyl_policy_graph_authority_record_free (authority);
  g_autoptr (WylFactRootWriterLease) lease = NULL;
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (fixture.root, &lease),
      ==, WYRELOG_E_OK);
  UnsealCommitFault fault = {
    .db = wyl_policy_store_get_db (fixture.policy),
    .veto = GPOINTER_TO_INT (data),
  };
  wyl_fact_graph_seal_set_test_hook (arm_unseal_commit_fault, &fault);
  WylFactGraphUnsealOutcome outcome = { 0 };
  wyrelog_error_t rc = wyl_fact_graph_unseal_with_root_lease (fixture.policy,
          fixture.root, lease, &info, fixture.manager, -1, &outcome);
  wyl_fact_graph_seal_set_test_hook (NULL, NULL);
  sqlite3_set_authorizer (fault.db, NULL, NULL);
  sqlite3_commit_hook (fault.db, NULL, NULL);
  g_test_message ("commit rejection rc=%d admission_open=%d queryable=%d",
      rc, outcome.runtime_admission_open, outcome.status.queryable);
  g_assert_cmpuint (fault.installed, ==, 1);
  g_assert_cmpuint (fault.rejected, ==, 1);
  g_assert_cmpint (rc, ==, WYRELOG_E_IO);
  g_assert_false (outcome.runtime_admission_open);
  g_assert_false (outcome.status.queryable);
  g_assert_cmpint (outcome.status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);
  g_assert_true (sqlite3_get_autocommit (fault.db));
  WylFactGraphSnapshot *snapshot = NULL;
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, info.tenant_id,
      info.graph_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot
        (fixture.manager, &key, &snapshot), !=, WYRELOG_E_OK);
  g_assert_null (snapshot);
  wyl_fact_graph_key_clear (&key);
  g_autofree gchar *path = g_build_filename (fixture.root, "policy.db", NULL);
  g_autoptr (wyl_policy_store_t) observer = NULL;
  g_assert_cmpint (wyl_policy_store_open (path, &observer), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_read_graph_authority (observer,
      info.tenant_id, info.graph_id, &authority), ==, WYRELOG_E_OK);
  g_assert_cmpint (authority->lifecycle_state, ==,
      WYL_POLICY_GRAPH_LIFECYCLE_SEALED);
  g_assert_cmpuint (authority->lifecycle_generation, ==, generation);
  wyl_policy_graph_authority_record_free (authority);
  g_clear_pointer (&observer, wyl_policy_store_close);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  wyl_fact_graph_unseal_outcome_clear (&outcome);
  g_autofree gchar *root = g_strdup (fixture.root);
  seal_fixture_clear (&fixture);
  remove_tree (root);
}

static void
test_unseal_reseal_failure_is_reported_and_stays_closed (void)
{
  SealFixture fixture = { 0 };
  authority_seal_fixture_init (&fixture,
      "wyl-graph-unseal-reseal-failure-XXXXXX");

  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome sealed = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (fixture.policy, &info, fixture.manager,
      -1, &sealed), ==, WYRELOG_E_OK);
  wyl_fact_graph_seal_outcome_clear (&sealed);

  GraphPathProbe path = { "tenant-a", "orders", NULL };
  g_assert_cmpint (wyl_policy_store_foreach_fact_graph (fixture.policy,
      "tenant-a", capture_graph_path_cb, &path), ==, WYRELOG_E_OK);
  g_assert_nonnull (path.storage_path);
  g_autofree gchar *fact_path = g_build_filename (path.storage_path,
          "facts.duckdb", NULL);
  g_assert_cmpint (g_remove (fact_path), ==, 0);

  SealPhaseFault fault = { 0 };
  fault.fail_unseal_reseal = TRUE;
  wyl_fact_graph_seal_set_test_hook (seal_phase_fault, &fault);
  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (wyl_fact_graph_unseal_for_test (fixture.policy, fixture.root, &info,
      fixture.manager, -1, &outcome), ==, WYRELOG_E_IO);
  wyl_fact_graph_seal_set_test_hook (NULL, NULL);

  g_assert_true (outcome.durable_unseal_applied);
  g_assert_false (outcome.durable_reseal_applied);
  g_assert_true (outcome.compensation_failed);
  g_assert_cmpint (outcome.compensation_error, ==, WYRELOG_E_IO);
  g_assert_false (outcome.runtime_admission_open);
  g_assert_cmpint (outcome.status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);

  WylPolicyGraphAuthorityRecord *authority = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (fixture.policy,
      "tenant-a", "orders", &authority), ==, WYRELOG_E_OK);
  g_assert_nonnull (authority);
  g_assert_cmpint (authority->lifecycle_state, ==,
      WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE);
  g_assert_false (authority->sealed_compatibility);
  wyl_policy_graph_authority_record_free (authority);

  wyl_fact_graph_unseal_outcome_clear (&outcome);
  g_autofree gchar *root = g_strdup (fixture.root);
  seal_fixture_clear (&fixture);
  remove_tree (root);
}

static void
test_unseal_rejects_graph_schema_mismatch (void)
{
  SealFixture fixture = { 0 };
  g_autoptr (GError) error = NULL;
  fixture.root = wyl_test_make_secure_fact_root
        ("wyl-graph-unseal-schema-mismatch-XXXXXX", &error);
  g_assert_nonnull (fixture.root);
  g_autofree gchar *policy_path = g_build_filename (fixture.root, "policy.db",
          NULL);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &fixture.policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (fixture.policy), ==,
      WYRELOG_E_OK);
  create_authority_graph_with_schema (fixture.policy, fixture.root, "tenant-a",
      "orders");
  materialize_graph_engine (fixture.policy, fixture.root, "tenant-a", "orders");
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&fixture.manager), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t summary = { 0 };
  (void) wyl_fact_replay_policy_graphs (fixture.policy, fixture.root,
      fixture.manager, &summary);
  g_assert_cmpuint (summary.graphs_loaded, ==, 1);

  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome sealed = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (fixture.policy, &info, fixture.manager,
      -1, &sealed), ==, WYRELOG_E_OK);
  wyl_fact_graph_seal_outcome_clear (&sealed);

  /* Remove the policy-owned schema columns while leaving the authority row
   * sealed and otherwise valid.  A preflight that only checks
   * lifecycle/sealed would incorrectly proceed to publication. */
  g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (fixture.policy),
      "PRAGMA foreign_keys=OFF;"
      "DELETE FROM fact_relation_schema_columns "
      "WHERE tenant_id='tenant-a' AND graph_id='orders';", NULL, NULL, NULL),
      ==, SQLITE_OK);

  WylFactGraphUnsealOutcome outcome = { 0 };
  g_assert_cmpint (wyl_fact_graph_unseal_for_test (fixture.policy, fixture.root, &info,
      fixture.manager, -1, &outcome), !=, WYRELOG_E_OK);
  g_assert_true (outcome.durable_unseal_applied);
  g_assert_true (outcome.durable_reseal_applied);
  g_assert_false (outcome.engine_published);
  g_assert_false (outcome.runtime_admission_open);
  g_assert_cmpint (outcome.status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_unseal_outcome_clear (&outcome);

  WylPolicyGraphAuthorityRecord *authority = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (fixture.policy,
      "tenant-a", "orders", &authority), ==, WYRELOG_E_OK);
  g_assert_cmpint (authority->lifecycle_state, ==,
      WYL_POLICY_GRAPH_LIFECYCLE_SEALED);
  wyl_policy_graph_authority_record_free (authority);
  g_autofree gchar *root = g_strdup (fixture.root);
  seal_fixture_clear (&fixture);
  remove_tree (root);
}

static void
test_unseal_replacement_after_validation_and_retry (void)
{
  SealFixture fixture = { 0 };
  authority_seal_fixture_init (&fixture,
      "wyl-graph-unseal-replacement-XXXXXX");
  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome sealed = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (fixture.policy, &info, fixture.manager,
      -1, &sealed), ==, WYRELOG_E_OK);
  wyl_fact_graph_seal_outcome_clear (&sealed);

  GraphPathProbe path = { "tenant-a", "orders", NULL };
  g_assert_cmpint (wyl_policy_store_foreach_fact_graph (fixture.policy,
      "tenant-a", capture_graph_path_cb, &path), ==, WYRELOG_E_OK);
  g_assert_nonnull (path.storage_path);
  g_autofree gchar *fact_path = g_build_filename (path.storage_path,
          "facts.duckdb", NULL);
  g_autofree gchar *replacement_path = g_build_filename (path.storage_path,
          "facts.duckdb.validated", NULL);
  g_autofree gchar *foreign_path = g_build_filename (path.storage_path,
          "facts.duckdb.foreign", NULL);
  FactGraphFileIdentity original_identity = { 0 };
  g_assert_true (fact_graph_file_get_identity (fact_path, &original_identity));
  WylPolicyGraphAuthorityRecord *original_authority = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (fixture.policy,
      "tenant-a", "orders", &original_authority), ==, WYRELOG_E_OK);
  g_assert_nonnull (original_authority);
  g_assert_nonnull (original_authority->store_uuid);
  g_autofree gchar *original_uuid = g_strdup (original_authority->store_uuid);
  wyl_policy_graph_authority_record_free (original_authority);
  g_autofree gchar *foreign_bytes = NULL;
  gsize foreign_length = 0;
  g_autoptr (GError) error = NULL;
  g_assert_true (g_file_get_contents (fact_path, &foreign_bytes,
      &foreign_length, &error));
  g_assert_true (g_file_set_contents (foreign_path, foreign_bytes,
      (gssize) foreign_length, &error));
  FactGraphFileIdentity foreign_identity = { 0 };
  g_assert_true (fact_graph_file_get_identity (foreign_path, &foreign_identity));
  g_assert_cmpuint (foreign_identity.device, ==, original_identity.device);
  g_assert_cmpuint (foreign_identity.file, !=, original_identity.file);
  duckdb_database foreign_db = NULL;
  duckdb_connection foreign_connection = NULL;
  duckdb_result foreign_result = { 0 };
  g_assert_cmpint (duckdb_open (foreign_path, &foreign_db), ==, DuckDBSuccess);
  g_assert_cmpint (duckdb_connect (foreign_db, &foreign_connection), ==,
      DuckDBSuccess);
  g_assert_cmpint (duckdb_query (foreign_connection,
      "DELETE FROM fact_store_metadata WHERE key='store_uuid';"
      "INSERT INTO fact_store_metadata(key,value) VALUES "
      "('store_uuid','01890f47-3c4b-6cc2-b8c4-dc0c0c073988');",
      &foreign_result), ==, DuckDBSuccess);
  duckdb_destroy_result (&foreign_result);
  g_assert_cmpint (duckdb_query (foreign_connection,
      "SELECT value FROM fact_store_metadata WHERE key='store_uuid';",
      &foreign_result), ==, DuckDBSuccess);
  g_assert_cmpuint (duckdb_row_count (&foreign_result), ==, 1);
  gchar *foreign_uuid = duckdb_value_varchar (&foreign_result, 0, 0);
  g_assert_cmpstr (foreign_uuid, ==,
      "01890f47-3c4b-6cc2-b8c4-dc0c0c073988");
  g_assert_cmpstr (foreign_uuid, !=, original_uuid);
  duckdb_free (foreign_uuid);
  duckdb_destroy_result (&foreign_result);
  duckdb_disconnect (&foreign_connection);
  duckdb_close (&foreign_db);
  foreign_db = NULL;
  foreign_connection = NULL;
  g_assert_cmpint (duckdb_open (foreign_path, &foreign_db), ==, DuckDBSuccess);
  g_assert_cmpint (duckdb_connect (foreign_db, &foreign_connection), ==,
      DuckDBSuccess);
  g_assert_cmpint (duckdb_query (foreign_connection,
      "SELECT value FROM fact_store_metadata WHERE key='store_uuid';",
      &foreign_result), ==, DuckDBSuccess);
  g_assert_cmpuint (duckdb_row_count (&foreign_result), ==, 1);
  foreign_uuid = duckdb_value_varchar (&foreign_result, 0, 0);
  g_assert_cmpstr (foreign_uuid, ==,
      "01890f47-3c4b-6cc2-b8c4-dc0c0c073988");
  duckdb_free (foreign_uuid);
  duckdb_destroy_result (&foreign_result);
  duckdb_disconnect (&foreign_connection);
  duckdb_close (&foreign_db);

  SealPhaseFault fault = {
    .replace_path = fact_path,
    .replacement_path = replacement_path,
    .foreign_path = foreign_path,
  };
  wyl_fact_graph_seal_set_test_hook (seal_phase_fault, &fault);
  WylFactGraphUnsealOutcome outcome = { 0 };
  wyrelog_error_t rc = wyl_fact_graph_unseal_for_test (fixture.policy,
          fixture.root, &info, fixture.manager, -1, &outcome);
  wyl_fact_graph_seal_set_test_hook (NULL, NULL);
  g_assert_true (fault.replacement_attempted);

  g_assert_false (fault.replacement_setup_failed);
  if (fault.replacement_blocked) {
    /* A blocked replacement is only valid evidence when the original target
     * is still present, the substitute was not created, and its physical
     * identity is unchanged. */
    FactGraphFileIdentity blocked_identity = { 0 };
    g_assert_true (g_file_test (fact_path, G_FILE_TEST_IS_REGULAR));
    g_assert_false (g_file_test (replacement_path, G_FILE_TEST_EXISTS));
    g_assert_true (fact_graph_file_get_identity (fact_path, &blocked_identity));
    g_assert_cmpuint (blocked_identity.device, ==, original_identity.device);
    g_assert_cmpuint (blocked_identity.file, ==, original_identity.file);
    g_assert_true (fault.replacement_errno == EACCES
        || fault.replacement_errno == EBUSY
        || fault.replacement_errno == EPERM);
    g_assert_cmpint (rc, ==, WYRELOG_E_OK);
    g_assert_true (outcome.engine_published);
    g_assert_true (outcome.runtime_admission_open);
    g_assert_true (outcome.status.queryable);
    g_assert_cmpint (outcome.policy_result,
        ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  } else {
    g_assert_cmpint (rc, !=, WYRELOG_E_OK);
    g_assert_cmpint (rc, ==, WYRELOG_E_POLICY);
    g_assert_true (outcome.durable_unseal_applied);
    g_assert_true (outcome.durable_reseal_applied);
    g_assert_false (outcome.engine_published);
    g_assert_false (outcome.runtime_admission_open);
    g_assert_false (outcome.status.queryable);
    g_assert_false (outcome.status.operation_active);
    g_assert_cmpuint (outcome.status.active_engine_calls, ==, 0);
    g_assert_cmpuint (outcome.status.waiting_engine_calls, ==, 0);
    g_assert_cmpint (outcome.status.admission, ==,
        WYL_FACT_GRAPH_ADMISSION_CLOSED);
    WylPolicyGraphAuthorityRecord *authority = NULL;
    g_assert_cmpint (wyl_policy_store_read_graph_authority (fixture.policy,
        "tenant-a", "orders", &authority), ==, WYRELOG_E_OK);
    g_assert_nonnull (authority);
    g_assert_cmpint (authority->lifecycle_state, ==,
        WYL_POLICY_GRAPH_LIFECYCLE_SEALED);
    g_assert_cmpstr (authority->store_uuid, ==, original_uuid);
    wyl_policy_graph_authority_record_free (authority);
    g_assert_cmpint (g_remove (fact_path), ==, 0);
    g_assert_cmpint (g_rename (replacement_path, fact_path), ==, 0);
  }
  wyl_fact_graph_unseal_outcome_clear (&outcome);

  if (!fault.replacement_blocked && !fault.replacement_setup_failed) {
    WylFactGraphUnsealOutcome retry = { 0 };
    g_assert_cmpint (wyl_fact_graph_unseal_for_test (fixture.policy,
        fixture.root, &info, fixture.manager, -1, &retry), ==, WYRELOG_E_OK);
    g_assert_true (retry.engine_published);
    g_assert_true (retry.runtime_admission_open);
    g_assert_true (retry.status.queryable);
    g_assert_cmpint (retry.policy_result,
        ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
    g_assert_cmpint (retry.status.admission, ==,
        WYL_FACT_GRAPH_ADMISSION_OPEN);
    wyl_fact_graph_unseal_outcome_clear (&retry);
  }

  g_autofree gchar *root = g_strdup (fixture.root);
  seal_fixture_clear (&fixture);
  remove_tree (root);
}

/* S4's ambiguous durable write, sub-case one: the write fails and the
 * compensating re-read succeeds, reporting the graph unsealed.
 *
 * The write never committed, so the close is rolled back and there is no
 * barrier left to report.
 *
 * Kills: `reopened = FALSE` (the close is never rolled back, so admission
 * stays CLOSED) and `runtime_barrier_established = TRUE`.  No pre-existing
 * test in this file kills either -- both survive the whole suite without
 * these two cases. */
static void
test_seal_ambiguous_write_rolls_back_when_the_reread_says_unsealed (void)
{
  SealFixture fixture = { 0 };
  seal_fixture_init (&fixture, "wyl-graph-seal-ambig-a-XXXXXX");

  SealPhaseFault fault = {
    .fail_write = TRUE,
    .fail_probe = FALSE,
  };
  wyl_fact_graph_seal_set_test_hook (seal_phase_fault, &fault);

  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome outcome = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (fixture.policy, &info,
      fixture.manager, -1, &outcome), ==, WYRELOG_E_IO);

  /* The seam fired and the probe ran, so this really is the ambiguous-write
   * branch and really is its re-read-succeeded arm. */
  g_assert_cmpuint (fault.write_seen, ==, 1);
  g_assert_cmpuint (fault.probe_seen, ==, 1);

  g_assert_false (outcome.sealed_committed);
  g_assert_false (outcome.runtime_barrier_established);
  g_assert_cmpint (outcome.status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_OPEN);

  /* The durable bit really is clear: the write was skipped, not run and
   * relabelled.  Without this the seam could be masking a committed seal,
   * which is the failure mode #945 warns about. */
  SealedBitProbe probe = {"tenant-a", "orders", FALSE, TRUE};
  g_assert_cmpint (wyl_policy_store_foreach_fact_graph (fixture.policy,
      "tenant-a", capture_sealed_bit_cb, &probe), ==, WYRELOG_E_OK);
  g_assert_true (probe.found);
  g_assert_false (probe.sealed);

  wyl_fact_graph_seal_outcome_clear (&outcome);
  seal_fixture_clear (&fixture);
}

/* Sub-case two: the write fails and the re-read fails too, so the durable
 * state is unknown.
 *
 * The close deliberately stands -- leaving a possibly-sealed graph admitting
 * is the one unsafe direction -- and the barrier is reported TRUE because the
 * graph really is offline.
 *
 * Kills: dropping the `probe_rc == WYRELOG_E_OK` term from the reopen guard,
 * `reopened = TRUE`, and `runtime_barrier_established = FALSE`.
 *
 * Two mutations of these lines survive both cases, and saying so is the point
 * of listing the ones that do not:
 *
 *   - dropping `&& barrier` from the reopen guard.  Both fixtures replay the
 *     graph first, so S2 always establishes a barrier and the term is never
 *     the deciding one.  A fixture without an entry would make it FALSE, but
 *     reopening a graph that was never closed is a no-op, so the reported
 *     values would not move either.  The term guards a pointless call rather
 *     than a wrong report.
 *   - deriving the barrier from the intent (`= !reopened`) instead of from
 *     the admission observed afterwards.  The two agree whenever the reopen
 *     takes effect, and the only way to make an intended reopen fail is to
 *     shut the manager down -- which also makes the status read fail, so the
 *     derived form degrades to FALSE and the case proves nothing.  That line
 *     keeps its "argued, not proved" marker for this reason. */
static void
test_seal_ambiguous_write_stands_when_the_reread_fails (void)
{
  SealFixture fixture = { 0 };
  seal_fixture_init (&fixture, "wyl-graph-seal-ambig-b-XXXXXX");

  SealPhaseFault fault = {
    .fail_write = TRUE,
    .fail_probe = TRUE,
  };
  wyl_fact_graph_seal_set_test_hook (seal_phase_fault, &fault);

  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome outcome = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (fixture.policy, &info,
      fixture.manager, -1, &outcome), ==, WYRELOG_E_IO);

  g_assert_cmpuint (fault.write_seen, ==, 1);
  g_assert_cmpuint (fault.probe_seen, ==, 1);

  g_assert_false (outcome.sealed_committed);
  g_assert_true (outcome.runtime_barrier_established);
  g_assert_cmpint (outcome.status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);

  wyl_fact_graph_seal_outcome_clear (&outcome);
  seal_fixture_clear (&fixture);
}

static void
test_seal_establishes_the_barrier_and_the_durable_bit (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-graph-seal-live-XXXXXX", &error);
  g_assert_nonnull (root);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.db", NULL);

  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
  create_graph_with_schema (policy, root, "tenant-a", "orders");
  materialize_graph_engine (policy, root, "tenant-a", "orders");

  g_autoptr (WylFactGraphRuntimeManager) manager = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&manager), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t summary = { 0 };
  (void) wyl_fact_replay_policy_graphs (policy, root, manager, &summary);
  /* Without a published engine the eviction assertions below pin the call and
   * not its effect: evict_closed reports out_evicted TRUE whether or not
   * there was a generation to detach. */
  g_assert_cmpuint (summary.graphs_loaded, ==, 1);

  /* Pinned before the seal.  The eviction detaches the entry's reference
   * while this one keeps the generation alive -- the carve-out that lets a
   * seal use evict_closed where try_evict refuses. */
  WylFactGraphKey pinned_key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&pinned_key, "tenant-a",
      "orders"), ==, WYRELOG_E_OK);
  g_autoptr (WylFactGraphSnapshot) pinned = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
      &pinned_key, &pinned), ==, WYRELOG_E_OK);

  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome outcome = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (policy, &info, manager, -1, &outcome),
      ==, WYRELOG_E_OK);
  g_assert_true (outcome.sealed_committed);
  g_assert_true (outcome.runtime_barrier_established);
  g_assert_cmpint (outcome.status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);
  /* The fourth postcondition, and the one an admission assertion cannot
   * stand in for: acquire_snapshot is refused by the barrier whether or not
   * the engine went away, so without this the eviction can be deleted
   * outright and nothing notices.
   *
   * These are only meaningful because the fixture publishes a real engine.
   * Without one, entry->current is already NULL and evict_closed reports
   * out_evicted TRUE regardless, so queryable would read FALSE whether or not
   * the eviction did anything. */
  g_assert_true (outcome.engine_evicted);
  g_assert_cmpint (outcome.status.state, ==, WYL_FACT_GRAPH_RUNTIME_EVICTED);
  g_assert_false (outcome.status.queryable);
  /* And the distinguishing promise: the generation pinned before the close
   * is still alive and still usable after the seal detached the entry's
   * reference. */
  g_assert_cmpuint (outcome.status.active_snapshots, ==, 1);
  gboolean reached = FALSE;
  g_assert_cmpint (wyl_fact_graph_snapshot_use (pinned, engine_is_reachable,
      &reached), ==, WYRELOG_E_OK);
  g_assert_true (reached);
  wyl_fact_graph_seal_outcome_clear (&outcome);
  wyl_fact_graph_key_clear (&pinned_key);

  /* Durable, and the barrier holds against new work. */
  gboolean active = TRUE;
  g_assert_cmpint (wyl_policy_store_fact_graph_is_active (policy, "tenant-a",
      "orders", &active), ==, WYRELOG_E_OK);
  g_assert_false (active);
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);
  WylFactGraphSnapshot *snapshot = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_acquire_snapshot (manager,
      &key, &snapshot), ==, WYRELOG_E_BUSY);
  g_assert_null (snapshot);

  /* Idempotent: a repeat commits nothing and still converges the runtime. */
  WylFactGraphSealOutcome again = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (policy, &info, manager, -1, &again),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (again.status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_seal_outcome_clear (&again);

  wyl_fact_graph_key_clear (&key);
  remove_tree (root);
}

typedef struct
{
  GMutex mutex;
  GCond changed;
  gboolean entered;
  gboolean released;
} BuildGate;

typedef struct
{
  WylFactGraphRuntimeManager *manager;
  const WylFactGraphKey *key;
  BuildGate *gate;
  wyrelog_error_t result;
} GatedRefresh;

static wyrelog_error_t
gated_build (const WylFactGraphKey *key, WylEngine **out_engine,
    gpointer user_data)
{
  BuildGate *gate = user_data;
  (void) key;
  *out_engine = NULL;
  g_mutex_lock (&gate->mutex);
  gate->entered = TRUE;
  g_cond_broadcast (&gate->changed);
  while (!gate->released)
    g_cond_wait (&gate->changed, &gate->mutex);
  g_mutex_unlock (&gate->mutex);
  /* Fail the build rather than open an engine: this test is about the seal's
   * drain, and an engine would drag the whole wirelog fixture in for nothing.
   * A failed build still consumes and releases operation_active, which is the
   * admitted work the drain has to wait for. */
  return WYRELOG_E_IO;
}

static gpointer
gated_refresh_thread (gpointer user_data)
{
  GatedRefresh *r = user_data;
  r->result = wyl_fact_graph_runtime_manager_refresh (r->manager, r->key,
          gated_build, r->gate, NULL);
  return NULL;
}

/* The compensation rule.  A seal that aborts before the durable commit must
 * leave the graph admitting again -- otherwise a failed seal bars the graph
 * with nothing recorded anywhere to say why, and only a restart clears it. */
static void
test_seal_aborted_by_a_drain_timeout_reopens_admission (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-graph-seal-abort-XXXXXX", &error);
  g_assert_nonnull (root);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.db", NULL);

  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
  create_graph_with_schema (policy, root, "tenant-a", "orders");

  g_autoptr (WylFactGraphRuntimeManager) manager = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&manager), ==,
      WYRELOG_E_OK);
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);

  /* Admitted work, held open.  A build in flight is what the seal's drain has
   * to wait for, and it needs no engine to be one. */
  BuildGate gate = { 0 };
  g_mutex_init (&gate.mutex);
  g_cond_init (&gate.changed);
  GatedRefresh refresh = {.manager = manager,.key = &key,.gate = &gate,
                          .result = WYRELOG_E_OK };
  GThread *worker = g_thread_new ("gated-build", gated_refresh_thread,
          &refresh);
  g_mutex_lock (&gate.mutex);
  while (!gate.entered)
    g_cond_wait (&gate.changed, &gate.mutex);
  g_mutex_unlock (&gate.mutex);

  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome aborted = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (policy, &info, manager, 50 * 1000,
      &aborted), ==, WYRELOG_E_BUSY);
  g_assert_false (aborted.sealed_committed);
  g_assert_true (aborted.status.operation_active);
  /* The abort rolled the close back, so the graph is admitting.  This field
   * has been wrong on two of three return paths across two rounds, each time
   * because nothing held it. */
  g_assert_false (aborted.runtime_barrier_established);
  wyl_fact_graph_seal_outcome_clear (&aborted);

  /* Nothing durable happened, and the graph admits again -- this is the
   * assertion the compensation rule exists for. */
  gboolean active = FALSE;
  g_assert_cmpint (wyl_policy_store_fact_graph_is_active (policy, "tenant-a",
      "orders", &active), ==, WYRELOG_E_OK);
  g_assert_true (active);
  WylFactGraphRuntimeStatus after = status_of (manager, "tenant-a", "orders");
  g_assert_cmpint (after.admission, ==, WYL_FACT_GRAPH_ADMISSION_OPEN);
  wyl_fact_graph_runtime_status_clear (&after);

  g_mutex_lock (&gate.mutex);
  gate.released = TRUE;
  g_cond_broadcast (&gate.changed);
  g_mutex_unlock (&gate.mutex);
  g_thread_join (worker);

  /* With the build finished the same seal succeeds, which proves the abort
   * was the drain and not something permanent. */
  WylFactGraphSealOutcome retried = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (policy, &info, manager, -1, &retried),
      ==, WYRELOG_E_OK);
  g_assert_true (retried.sealed_committed);
  wyl_fact_graph_seal_outcome_clear (&retried);

  g_cond_clear (&gate.changed);
  g_mutex_clear (&gate.mutex);
  wyl_fact_graph_key_clear (&key);
  remove_tree (root);
}

/* The three conditions wyl_policy_store_fact_graph_is_active folds together,
 * each of which needs a different answer.  Reading it instead of the graph's
 * own seal made all three silently wrong. */
static void
test_seal_refuses_an_absent_graph_and_seals_a_real_one (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-graph-seal-states-XXXXXX", &error);
  g_assert_nonnull (root);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.db", NULL);

  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
  create_graph_with_schema (policy, root, "tenant-a", "orders");

  g_autoptr (WylFactGraphRuntimeManager) manager = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&manager), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t summary = { 0 };
  (void) wyl_fact_replay_policy_graphs (policy, root, manager, &summary);

  /* A graph the store has never heard of is NOT_FOUND, not a successful
   * seal.  Reading is_active reported it inactive, so the durable write was
   * skipped and the call returned OK with sealed_committed set. */
  wyl_policy_fact_graph_info_t absent = {
    .tenant_id = "tenant-a",
    .graph_id = "no-such-graph",
  };
  WylFactGraphSealOutcome missing = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (policy, &absent, manager, -1,
      &missing), ==, WYRELOG_E_NOT_FOUND);
  g_assert_false (missing.sealed_committed);
  wyl_fact_graph_seal_outcome_clear (&missing);

  /* A real graph seals, and the durable bit really lands. */
  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome sealed = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (policy, &info, manager, -1, &sealed),
      ==, WYRELOG_E_OK);
  g_assert_true (sealed.sealed_committed);
  wyl_fact_graph_seal_outcome_clear (&sealed);

  /* Durable enough to survive a fresh manager, which is what "the seal
   * evaporated" means concretely. */
  g_autoptr (WylFactGraphRuntimeManager) rebooted = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&rebooted), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t after_boot = { 0 };
  (void) wyl_fact_replay_policy_graphs (policy, root, rebooted, &after_boot);
  g_assert_cmpuint (after_boot.graphs_sealed, ==, 1);
  WylFactGraphRuntimeStatus rebooted_status = status_of (rebooted, "tenant-a",
          "orders");
  g_assert_cmpint (rebooted_status.admission, ==,
      WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_runtime_status_clear (&rebooted_status);

  remove_tree (root);
}

/* An aborted seal must not reopen a graph that is ALREADY durably sealed.
 * The pre-existing endpoint writes the durable bit with no runtime
 * involvement, so "durably sealed with an open runtime entry" exists in the
 * shipped daemon -- and an aborted seal against one used to reopen it. */
static void
test_aborted_seal_does_not_reopen_an_already_sealed_graph (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-graph-seal-resealed-XXXXXX", &error);
  g_assert_nonnull (root);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.db", NULL);

  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
  create_graph_with_schema (policy, root, "tenant-a", "orders");

  g_autoptr (WylFactGraphRuntimeManager) manager = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&manager), ==,
      WYRELOG_E_OK);
  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "orders"), ==,
      WYRELOG_E_OK);

  /* Seal durably the way the old endpoint does -- no runtime involvement --
   * so the entry is open while the graph is sealed. */
  g_assert_cmpint (wyl_policy_store_seal_fact_graph (policy, "tenant-a",
      "orders"), ==, WYRELOG_E_OK);

  BuildGate gate = { 0 };
  g_mutex_init (&gate.mutex);
  g_cond_init (&gate.changed);
  GatedRefresh refresh = {.manager = manager,.key = &key,.gate = &gate,
                          .result = WYRELOG_E_OK };
  GThread *worker = g_thread_new ("gated-build", gated_refresh_thread,
          &refresh);
  g_mutex_lock (&gate.mutex);
  while (!gate.entered)
    g_cond_wait (&gate.changed, &gate.mutex);
  g_mutex_unlock (&gate.mutex);

  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome aborted = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (policy, &info, manager, 50 * 1000,
      &aborted), ==, WYRELOG_E_BUSY);
  /* The other direction: an already-sealed graph stays closed, so the field
   * must report the barrier that is really there. */
  g_assert_true (aborted.runtime_barrier_established);
  wyl_fact_graph_seal_outcome_clear (&aborted);

  /* The abort must leave it CLOSED.  Reopening here produces "durably sealed
   * and admitting", which is the state the compensation rule exists to make
   * unrepresentable. */
  WylFactGraphRuntimeStatus after = status_of (manager, "tenant-a", "orders");
  g_assert_cmpint (after.admission, ==, WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_runtime_status_clear (&after);

  g_mutex_lock (&gate.mutex);
  gate.released = TRUE;
  g_cond_broadcast (&gate.changed);
  g_mutex_unlock (&gate.mutex);
  g_thread_join (worker);

  g_cond_clear (&gate.changed);
  g_mutex_clear (&gate.mutex);
  wyl_fact_graph_key_clear (&key);
  remove_tree (root);
}

/* The condition that separates the graph's own seal from "is this graph
 * active": a SEALED TENANT holding an UNSEALED graph.  Sourcing the flag from
 * wyl_policy_store_fact_graph_is_active makes those indistinguishable, so the
 * durable write was skipped and the call reported success having written
 * nothing -- the seal then evaporated at the next boot.
 *
 * Every other fixture here has an active tenant, so without this test the
 * regression is invisible: collapsing S1 back into the one-call helper, which
 * is exactly the tidy-up a later reader would make, leaves the suite green. */
static void
test_seal_writes_durably_inside_a_sealed_tenant (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-graph-seal-tenant-XXXXXX", &error);
  g_assert_nonnull (root);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.db", NULL);

  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy), ==, WYRELOG_E_OK);
  create_graph_with_schema (policy, root, "tenant-a", "orders");

  g_autoptr (WylFactGraphRuntimeManager) manager = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&manager), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t summary = { 0 };
  (void) wyl_fact_replay_policy_graphs (policy, root, manager, &summary);

  /* Seal the tenant.  The graph's own bit stays unset, which is the whole
   * point: is_active now reports FALSE for a graph that is not sealed. */
  g_assert_cmpint (wyl_policy_store_set_tenant_sealed (policy, "tenant-a",
      TRUE), ==, WYRELOG_E_OK);

  wyl_policy_fact_graph_info_t info = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
  };
  WylFactGraphSealOutcome outcome = { 0 };
  g_assert_cmpint (wyl_fact_graph_seal (policy, &info, manager, -1, &outcome),
      ==, WYRELOG_E_OK);
  g_assert_true (outcome.sealed_committed);
  wyl_fact_graph_seal_outcome_clear (&outcome);

  /* The durable write really happened.  Unseal the tenant so nothing but the
   * graph's own bit can be keeping it sealed, then boot a fresh manager:
   * before the fix this reported graphs_sealed == 0 and an open graph. */
  g_assert_cmpint (wyl_policy_store_set_tenant_sealed (policy, "tenant-a",
      FALSE), ==, WYRELOG_E_OK);
  g_autoptr (WylFactGraphRuntimeManager) rebooted = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&rebooted), ==,
      WYRELOG_E_OK);
  wyl_fact_replay_summary_t after_boot = { 0 };
  (void) wyl_fact_replay_policy_graphs (policy, root, rebooted, &after_boot);
  g_assert_cmpuint (after_boot.graphs_sealed, ==, 1);
  WylFactGraphRuntimeStatus status = status_of (rebooted, "tenant-a",
          "orders");
  g_assert_cmpint (status.admission, ==, WYL_FACT_GRAPH_ADMISSION_CLOSED);
  wyl_fact_graph_runtime_status_clear (&status);

  remove_tree (root);
}

int
main (int argc, char **argv)
{
#if defined(WYL_HAS_SECURE_DUCKDB_BRIDGE) && !defined(G_OS_WIN32)
  if (argc >= 2 && g_strcmp0 (argv[1], policy_seal_helper_arg) == 0)
    return policy_seal_helper_main (argc, argv);
#endif
  test_self_path = g_canonicalize_filename (argv[0], NULL);
  g_assert_nonnull (test_self_path);
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact-graph-seal/independent-policy-live-handle",
      test_legacy_direct_policy_live_owner);
  g_test_add_func ("/fact-graph-seal/independent-handle-no-root",
      test_legacy_handle_live_owner_without_root);
  g_test_add_func ("/fact-graph-seal/independent-handle-other-root",
      test_legacy_handle_live_owner_with_other_root);
  g_test_add_data_func ("/fact-graph-seal/provisioned-independent-policy-exec",
      GINT_TO_POINTER (0), test_independent_policy_seal_with_live_handle);
  g_test_add_data_func ("/fact-graph-seal/provisioned-before-admission-policy-exec",
      GINT_TO_POINTER (1), test_independent_policy_seal_with_live_handle);
  g_test_add_func ("/fact-graph-seal/boot-reestablishes-admission",
      test_boot_reestablishes_admission_from_the_durable_seal);
  g_test_add_func ("/fact-graph-seal/boot-preserves-forget-verdict",
      test_boot_admission_write_does_not_clobber_the_forget_verdict);
  g_test_add_func ("/fact-graph-seal/ambiguous-write-rolls-back",
      test_seal_ambiguous_write_rolls_back_when_the_reread_says_unsealed);
  g_test_add_func ("/fact-graph-seal/ambiguous-write-stands",
      test_seal_ambiguous_write_stands_when_the_reread_fails);
  g_test_add_func ("/fact-graph-seal/seal-establishes-barrier",
      test_seal_establishes_the_barrier_and_the_durable_bit);
  g_test_add_func ("/fact-graph-seal/seal-abort-reopens",
      test_seal_aborted_by_a_drain_timeout_reopens_admission);
  g_test_add_func ("/fact-graph-seal/seal-distinguishes-graph-states",
      test_seal_refuses_an_absent_graph_and_seals_a_real_one);
  g_test_add_func ("/fact-graph-seal/seal-writes-inside-a-sealed-tenant",
      test_seal_writes_durably_inside_a_sealed_tenant);
  g_test_add_func ("/fact-graph-seal/abort-keeps-a-sealed-graph-closed",
      test_aborted_seal_does_not_reopen_an_already_sealed_graph);
  g_test_add_func ("/fact-graph-seal/unseal-rebuilds-before-reopening",
      test_unseal_rebuilds_before_reopening);
  g_test_add_func ("/fact-graph-seal/concurrent-unseal-converges",
      test_concurrent_unseal_converges_after_loser_abort);
  g_test_add_func ("/fact-graph-seal/publication-blocks-external-open",
      test_publication_blocks_external_open);
  g_test_add_func ("/fact-graph-seal/unseal-requires-handle-write-lease",
      test_unseal_requires_handle_write_lease);
  g_test_add_data_func ("/fact-graph-seal/unseal-commit-denied",
      GINT_TO_POINTER (FALSE), test_unseal_commit_failure_stays_closed);
  g_test_add_data_func ("/fact-graph-seal/unseal-commit-vetoed",
      GINT_TO_POINTER (TRUE), test_unseal_commit_failure_stays_closed);
#ifdef WYL_HAS_SECURE_DUCKDB_BRIDGE
  static const gchar *metadata_keys[] = {
    "store_uuid", "format_version", "path_encoding_version", "missing", "schema"
  };
  for (gsize i = 0; i < G_N_ELEMENTS (metadata_keys); i++) {
    g_autofree gchar *name = g_strdup_printf
          ("/fact-graph-seal/unseal-persisted-metadata-%s", metadata_keys[i]);
    g_test_add_data_func (name, metadata_keys[i],
        test_unseal_rejects_persisted_metadata);
  }
  g_test_add_data_func ("/fact-graph-seal/unseal-provisioning-uuid-mismatch",
      GINT_TO_POINTER (0), test_unseal_rejects_provisioning_mismatch);
#ifdef __APPLE__
  g_test_add_data_func ("/fact-graph-seal/unseal-missing-darwin-evidence",
      GINT_TO_POINTER (1), test_unseal_rejects_provisioning_mismatch);
  g_test_add_data_func ("/fact-graph-seal/unseal-invalid-darwin-evidence",
      GINT_TO_POINTER (2), test_unseal_rejects_provisioning_mismatch);
#endif
#endif
  g_test_add_func ("/fact-graph-seal/unseal-build-failure-reseals",
      test_unseal_build_failure_reseals_and_stays_closed);
  g_test_add_func ("/fact-graph-seal/unseal-reseal-failure-reported",
      test_unseal_reseal_failure_is_reported_and_stays_closed);
  g_test_add_func ("/fact-graph-seal/unseal-schema-mismatch",
      test_unseal_rejects_graph_schema_mismatch);
  g_test_add_func ("/fact-graph-seal/unseal-replacement-after-validation-and-retry",
      test_unseal_replacement_after_validation_and_retry);
  return g_test_run ();
}

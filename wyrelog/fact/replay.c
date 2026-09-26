/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "replay-private.h"

#include <string.h>

#include "compound-private.h"
#include "graph-artifact-namespace-private.h"
#include "graph-locator-private.h"
#include "replay-scheduler-private.h"
#include "wyrelog/wyl-engine-private.h"
#include "wyrelog/wyl-log-private.h"
#define WYL_FACT_STORE_CONNECTION_ROLE 1
#include "store-connection-private.h"
#undef WYL_FACT_STORE_CONNECTION_ROLE
#include "fact/store-open-private.h"

#ifdef G_OS_WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#define WYL_FACT_REPLAY_MAX_ROWS G_MAXUINT32

#if defined(WYL_TEST_HANDLE_SEAMS)
static gint fact_replay_test_fault = WYL_FACT_REPLAY_TEST_FAULT_NONE;
static WylFactReplayScheduledStartTestHook scheduled_start_test_hook;
static gpointer scheduled_start_test_hook_data;
G_LOCK_DEFINE_STATIC (scheduled_start_test_hook);
static WylFactReplayValidationConnectedTestHook
    validation_connected_test_hook;
static gpointer validation_connected_test_hook_data;
G_LOCK_DEFINE_STATIC (validation_connected_test_hook);

void
wyl_fact_replay_set_test_fault (WylFactReplayTestFault fault)
{
  g_return_if_fail (fault >= WYL_FACT_REPLAY_TEST_FAULT_NONE
      && fault <= WYL_FACT_REPLAY_TEST_FAULT_OPEN_GRAPH_ENGINE);
  g_atomic_int_set (&fact_replay_test_fault, fault);
}

void
wyl_fact_replay_set_scheduled_start_test_hook
  (WylFactReplayScheduledStartTestHook hook, gpointer user_data)
{
  G_LOCK (scheduled_start_test_hook);
  scheduled_start_test_hook = hook;
  scheduled_start_test_hook_data = user_data;
  G_UNLOCK (scheduled_start_test_hook);
}

static void
scheduled_start_test_hook_invoke (const gchar *tenant_id,
    const gchar *graph_id)
{
  G_LOCK (scheduled_start_test_hook);
  WylFactReplayScheduledStartTestHook hook = scheduled_start_test_hook;
  gpointer user_data = scheduled_start_test_hook_data;
  G_UNLOCK (scheduled_start_test_hook);
  if (hook != NULL)
    hook (tenant_id, graph_id, user_data);
}

void
wyl_fact_replay_set_validation_connected_test_hook
  (WylFactReplayValidationConnectedTestHook hook, gpointer user_data)
{
  G_LOCK (validation_connected_test_hook);
  validation_connected_test_hook = hook;
  validation_connected_test_hook_data = user_data;
  G_UNLOCK (validation_connected_test_hook);
}

static void
validation_connected_test_hook_invoke (WylFactReplayJobContext *job_context)
{
  G_LOCK (validation_connected_test_hook);
  WylFactReplayValidationConnectedTestHook hook =
      validation_connected_test_hook;
  gpointer user_data = validation_connected_test_hook_data;
  G_UNLOCK (validation_connected_test_hook);
  if (hook != NULL)
    hook (job_context, user_data);
}

static gboolean
take_fact_replay_test_fault (WylFactReplayTestFault fault)
{
  return g_atomic_int_compare_and_exchange (&fact_replay_test_fault, fault,
             WYL_FACT_REPLAY_TEST_FAULT_NONE);
}
#endif

typedef struct
{
  gchar *namespace_id;
  gchar *relation_name;
  guint32 schema_version;
  gboolean relation_visible;
  gboolean has_durable_batches;
  wyl_policy_fact_relation_schema_column_t *columns;
  gsize n_columns;
  gchar *projection_table;
  gchar *wirelog_relation;
} ReplayRelation;

typedef struct
{
  gchar *namespace_id;
  gchar *relation_name;
  guint32 schema_version;
} ReplayActiveRelation;

static void replay_relation_free (gpointer data);
static void replay_active_relation_free (gpointer data);
static WylPolicyGraphMaterializationState
graph_materialization_state_or_unknown (wyl_policy_store_t *policy,
    const wyl_policy_fact_graph_info_t *graph_info);

typedef struct
{
  wyl_policy_fact_graph_info_t info;
  gboolean info_valid;
  GPtrArray *schemas;
  GPtrArray *active;
  gchar *active_schema_digest;
  WylPolicyGraphMaterializationState materialization_state;
} ReplayPolicyGraphSnapshot;

static void
replay_policy_graph_snapshot_init (ReplayPolicyGraphSnapshot *snapshot)
{
  memset (snapshot, 0, sizeof *snapshot);
  snapshot->schemas = g_ptr_array_new_with_free_func (replay_relation_free);
  snapshot->active =
      g_ptr_array_new_with_free_func (replay_active_relation_free);
  snapshot->materialization_state =
      WYL_POLICY_GRAPH_MATERIALIZATION_UNKNOWN;
}

static void
replay_policy_graph_snapshot_clear (ReplayPolicyGraphSnapshot *snapshot)
{
  if (snapshot == NULL)
    return;
  g_free ((gchar *) snapshot->info.tenant_id);
  g_free ((gchar *) snapshot->info.graph_id);
  g_free ((gchar *) snapshot->info.storage_uri);
  g_free ((gchar *) snapshot->info.storage_path);
  g_free ((gchar *) snapshot->info.owner_scope);
  memset (&snapshot->info, 0, sizeof snapshot->info);
  snapshot->info_valid = FALSE;
  g_clear_pointer (&snapshot->schemas, g_ptr_array_unref);
  g_clear_pointer (&snapshot->active, g_ptr_array_unref);
  g_clear_pointer (&snapshot->active_schema_digest, g_free);
  snapshot->materialization_state =
      WYL_POLICY_GRAPH_MATERIALIZATION_UNKNOWN;
}

typedef struct
{
  const gchar *graph_id;
  ReplayPolicyGraphSnapshot *snapshot;
} ReplayGraphInfoSnapshotCtx;

static wyrelog_error_t
capture_replay_graph_info (const wyl_policy_fact_graph_info_t *info,
    gpointer user_data)
{
  ReplayGraphInfoSnapshotCtx *ctx = user_data;
  if (ctx->snapshot->info_valid || g_strcmp0 (info->graph_id,
      ctx->graph_id) != 0)
    return WYRELOG_E_OK;
  ctx->snapshot->info.tenant_id = g_strdup (info->tenant_id);
  ctx->snapshot->info.graph_id = g_strdup (info->graph_id);
  ctx->snapshot->info.storage_uri = g_strdup (info->storage_uri);
  ctx->snapshot->info.storage_path = g_strdup (info->storage_path);
  ctx->snapshot->info.schema_version = info->schema_version;
  ctx->snapshot->info.owner_scope = g_strdup (info->owner_scope);
  ctx->snapshot->info.sealed = info->sealed;
  ctx->snapshot->info_valid = TRUE;
  return WYRELOG_E_OK;
}

static wyrelog_error_t capture_replay_policy_graph_snapshot
  (wyl_policy_store_t *policy,
    const wyl_policy_fact_graph_info_t *info,
    WylFactReplayJobContext *job_context,
    ReplayPolicyGraphSnapshot *snapshot);

typedef struct
{
  WylEngine *engine;
  const gchar *tenant_id;
  const gchar *graph_id;
  const gchar *namespace_id;
  wyl_fact_store_t *store;
  GHashTable *compound_handles;
  WylFactReplayJobContext *job_context;
} ReplayMaterializeCtx;

typedef struct
{
  gchar *namespace_id;
  gchar *relation_name;
  guint32 schema_version;
} ReplayRelationKey;

typedef struct
{
  gchar *text;
  gint64 integer;
  gboolean boolean;
} ReplayOwnedCell;

typedef struct
{
  ReplayOwnedCell *cells;
  gsize n_cells;
  gboolean valid;
} ReplayOwnedRow;

static void
replay_relation_key_free (gpointer data)
{
  ReplayRelationKey *key = data;
  if (key == NULL)
    return;
  g_free (key->namespace_id);
  g_free (key->relation_name);
  g_free (key);
}

static void
replay_owned_row_free (gpointer data)
{
  ReplayOwnedRow *row = data;
  if (row == NULL)
    return;
  for (gsize i = 0; i < row->n_cells; i++)
    g_free (row->cells[i].text);
  g_free (row->cells);
  g_free (row);
}

const gchar *
wyl_fact_graph_state_name (wyl_fact_graph_state_t state)
{
  switch (state) {
    case WYL_FACT_GRAPH_STATE_READY:
      return "ready";
    case WYL_FACT_GRAPH_STATE_DEGRADED:
      return "degraded";
    case WYL_FACT_GRAPH_STATE_SCHEMA_MISMATCH:
      return "schema_mismatch";
    case WYL_FACT_GRAPH_STATE_REPLAY_FAILED:
      return "replay_failed";
    case WYL_FACT_GRAPH_STATE_STORE_UNAVAILABLE:
      return "store_unavailable";
    case WYL_FACT_GRAPH_STATE_FORGET_INCOMPLETE:
      return "forget_incomplete";
    case WYL_FACT_GRAPH_STATE_SEALED:
      return "sealed";
    case WYL_FACT_GRAPH_STATE_EMPTY:
      return "empty";
  }
  /* No default arm: -Wswitch then names a state added without a string.  It
   * is a warning rather than an error here (werror is off), so it does not
   * stop a build -- the test asserting the literal name is what does.  This
   * return covers a value outside the enum, and says so rather than
   * rendering it as a plausible state. */
  return "unknown";
}

void
wyl_fact_graph_status_free (gpointer data)
{
  wyl_fact_graph_status_t *status = data;
  if (status == NULL)
    return;
  g_free (status->tenant_id);
  g_free (status->graph_id);
  g_free (status->last_error_class);
  g_free (status);
}

static void
append_wirelog_identifier (GString *out, const gchar *identifier)
{
  if (identifier == NULL || identifier[0] == '\0') {
    g_string_append_c (out, 'w');
    return;
  }

  g_string_append_c (out, 'w');
  for (const gchar * p = identifier; *p != '\0'; p++)
    g_string_append_printf (out, "_%02x", (guchar) * p);
}

gchar *
wyl_fact_replay_wirelog_relation_name (const gchar *namespace_id,
    const gchar *relation_name)
{
  if (namespace_id == NULL || relation_name == NULL)
    return NULL;

  g_autoptr (GString) out = g_string_new (NULL);
  append_wirelog_identifier (out, namespace_id);
  g_string_append_c (out, '_');
  append_wirelog_identifier (out, relation_name);
  return g_string_free (g_steal_pointer (&out), FALSE);
}

static void
append_duckdb_identifier (GString *out, const gchar *identifier)
{
  g_string_append_c (out, '"');
  for (const gchar * p = identifier; p != NULL && *p != '\0'; p++) {
    if (*p == '"')
      g_string_append_c (out, '"');
    g_string_append_c (out, *p);
  }
  g_string_append_c (out, '"');
}

static void
replay_relation_free (gpointer data)
{
  ReplayRelation *rel = data;
  if (rel == NULL)
    return;
  g_free (rel->namespace_id);
  g_free (rel->relation_name);
  for (gsize i = 0; i < rel->n_columns; i++) {
    g_free ((gchar *) rel->columns[i].column_name);
    g_free ((gchar *) rel->columns[i].column_type);
  }
  g_free (rel->columns);
  g_free (rel->projection_table);
  g_free (rel->wirelog_relation);
  g_free (rel);
}

static void
replay_active_relation_free (gpointer data)
{
  ReplayActiveRelation *active = data;
  if (active == NULL)
    return;
  g_free (active->namespace_id);
  g_free (active->relation_name);
  g_free (active);
}

static ReplayRelation *
replay_relation_clone (const ReplayRelation *source)
{
  if (source == NULL)
    return NULL;
  ReplayRelation *copy = g_new0 (ReplayRelation, 1);
  copy->namespace_id = g_strdup (source->namespace_id);
  copy->relation_name = g_strdup (source->relation_name);
  copy->schema_version = source->schema_version;
  copy->relation_visible = source->relation_visible;
  copy->has_durable_batches = source->has_durable_batches;
  copy->n_columns = source->n_columns;
  copy->projection_table = g_strdup (source->projection_table);
  copy->wirelog_relation = g_strdup (source->wirelog_relation);
  copy->columns = g_new0 (wyl_policy_fact_relation_schema_column_t,
          source->n_columns);
  for (gsize i = 0; i < source->n_columns; i++) {
    copy->columns[i].column_name = g_strdup (source->columns[i].column_name);
    copy->columns[i].column_type = g_strdup (source->columns[i].column_type);
    copy->columns[i].nullable = source->columns[i].nullable;
    copy->columns[i].visible = source->columns[i].visible;
  }
  return copy;
}

static ReplayRelation *
replay_snapshot_find_schema (const ReplayPolicyGraphSnapshot *snapshot,
    const gchar *namespace_id, const gchar *relation_name,
    guint32 schema_version)
{
  for (guint i = 0; snapshot != NULL && snapshot->schemas != NULL
      && i < snapshot->schemas->len; i++) {
    ReplayRelation *schema = g_ptr_array_index (snapshot->schemas, i);
    if (schema->schema_version == schema_version
        && g_str_equal (schema->namespace_id, namespace_id)
        && g_str_equal (schema->relation_name, relation_name))
      return schema;
  }
  return NULL;
}

static wyrelog_error_t
copy_schema_columns (const wyl_policy_fact_relation_schema_column_info_t *in,
    gsize n_columns, wyl_policy_fact_relation_schema_column_t **out)
{
  *out = NULL;
  if (in == NULL || n_columns == 0)
    return WYRELOG_E_INVALID;

  wyl_policy_fact_relation_schema_column_t *copy =
      g_new0 (wyl_policy_fact_relation_schema_column_t, n_columns);
  for (gsize i = 0; i < n_columns; i++) {
    copy[i].column_name = g_strdup (in[i].column_name);
    copy[i].column_type = g_strdup (in[i].column_type);
    copy[i].nullable = in[i].nullable;
    copy[i].visible = in[i].visible;
    if (copy[i].column_name == NULL || copy[i].column_type == NULL) {
      for (gsize j = 0; j <= i; j++) {
        g_free ((gchar *) copy[j].column_name);
        g_free ((gchar *) copy[j].column_type);
      }
      g_free (copy);
      return WYRELOG_E_NOMEM;
    }
  }
  *out = copy;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
load_relation_schema (wyl_policy_store_t *policy,
    const wyl_policy_fact_graph_info_t *graph, const gchar *namespace_id,
    const gchar *relation_name, guint32 schema_version,
    ReplayRelation **out_relation)
{
  *out_relation = NULL;

  gboolean relation_visible = FALSE;
  wyl_policy_fact_relation_schema_column_info_t *columns = NULL;
  gsize n_columns = 0;
  wyrelog_error_t rc = wyl_policy_store_load_fact_relation_schema_columns
        (policy, graph->tenant_id, graph->graph_id, namespace_id, relation_name,
          schema_version, &relation_visible, &columns, &n_columns);
  if (rc != WYRELOG_E_OK)
    return rc;

  ReplayRelation *rel = g_new0 (ReplayRelation, 1);
  rel->namespace_id = g_strdup (namespace_id);
  rel->relation_name = g_strdup (relation_name);
  rel->schema_version = schema_version;
  rel->relation_visible = relation_visible;
  rc = copy_schema_columns (columns, n_columns, &rel->columns);
  rel->n_columns = n_columns;
  wyl_policy_fact_relation_schema_columns_free (columns, n_columns);
  if (rc != WYRELOG_E_OK) {
    replay_relation_free (rel);
    return rc;
  }

  const wyl_policy_fact_relation_schema_options_t opts = {
    .tenant_id = graph->tenant_id,
    .graph_id = graph->graph_id,
    .namespace_id = rel->namespace_id,
    .relation_name = rel->relation_name,
    .schema_version = rel->schema_version,
    .relation_visible = rel->relation_visible,
    .columns = rel->columns,
    .n_columns = rel->n_columns,
  };
  rel->projection_table = wyl_fact_store_projection_table_name (&opts);
  rel->wirelog_relation =
      wyl_fact_replay_wirelog_relation_name (rel->namespace_id,
          rel->relation_name);
  if (rel->namespace_id == NULL || rel->relation_name == NULL
      || rel->projection_table == NULL || rel->wirelog_relation == NULL) {
    replay_relation_free (rel);
    return WYRELOG_E_NOMEM;
  }

  *out_relation = rel;
  return WYRELOG_E_OK;
}

static gchar *
replay_relation_seen_key (const gchar *namespace_id, const gchar *relation_name)
{
  return g_strconcat (namespace_id, "\x1f", relation_name, NULL);
}

static gchar *
replay_relation_version_key (const gchar *namespace_id,
    const gchar *relation_name, guint32 schema_version)
{
  return g_strdup_printf ("%s\x1f%s\x1f%u", namespace_id, relation_name,
             schema_version);
}

typedef struct
{
  wyl_policy_store_t *policy;
  const wyl_policy_fact_graph_info_t *graph;
  WylFactReplayJobContext *job_context;
  GPtrArray *schemas;
} ReplayRegisteredSchemaCollectCtx;

static wyrelog_error_t
collect_replay_registered_schema (const gchar *namespace_id,
    const gchar *relation_name, guint32 schema_version, gpointer user_data)
{
  ReplayRegisteredSchemaCollectCtx *ctx = user_data;
  if (ctx->job_context != NULL) {
    wyrelog_error_t rc = wyl_fact_replay_job_context_checkpoint
          (ctx->job_context);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  ReplayRelation *schema = NULL;
  wyrelog_error_t rc = load_relation_schema (ctx->policy, ctx->graph,
          namespace_id, relation_name, schema_version, &schema);
  if (rc == WYRELOG_E_OK)
    g_ptr_array_add (ctx->schemas, schema);
  return rc;
}

static void replay_interrupt_cancelled (GCancellable *cancellable,
    gpointer user_data);

/* Active versions take precedence. Batch-backed versions retain their
 * historical enumeration; a uniquely registered visible schema with no
 * batches is also declared so its empty relation survives replay. */
static wyrelog_error_t
list_replay_relations (wyl_policy_store_t *policy, wyl_fact_store_t *store,
    const wyl_policy_fact_graph_info_t *graph,
    const ReplayPolicyGraphSnapshot *policy_snapshot,
    WylFactReplayJobContext *job_context, GPtrArray **out_relations)
{
  *out_relations = NULL;
  if (policy == NULL || graph == NULL)
    return WYRELOG_E_INVALID;

  g_autoptr (GPtrArray) relations =
      g_ptr_array_new_with_free_func (replay_relation_free);
  g_autoptr (GHashTable) seen =
      g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  g_autoptr (GHashTable) batch_names =
      g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  g_autoptr (GHashTable) batch_versions =
      g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  wyrelog_error_t rc = job_context == NULL ? WYRELOG_E_OK
      : wyl_fact_replay_job_context_checkpoint (job_context);
  if (policy_snapshot != NULL) {
    for (guint i = 0; rc == WYRELOG_E_OK
        && i < policy_snapshot->active->len; i++) {
      ReplayActiveRelation *active = g_ptr_array_index
            (policy_snapshot->active, i);
      ReplayRelation *schema = replay_snapshot_find_schema (policy_snapshot,
              active->namespace_id, active->relation_name,
              active->schema_version);
      if (schema == NULL) {
        rc = WYRELOG_E_POLICY;
        break;
      }
      g_ptr_array_add (relations, replay_relation_clone (schema));
      g_hash_table_add (seen, replay_relation_seen_key (active->namespace_id,
          active->relation_name));
    }
  } else {
    g_autoptr (GPtrArray) active = NULL;
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_list_active_fact_relations (policy,
              graph->tenant_id, graph->graph_id, &active);
    for (guint i = 0; rc == WYRELOG_E_OK && active != NULL
        && i < active->len; i++) {
      if (job_context != NULL) {
        rc = wyl_fact_replay_job_context_checkpoint (job_context);
        if (rc != WYRELOG_E_OK)
          break;
      }
      const WylPolicyRelationActivationRecord *record =
          g_ptr_array_index (active, i);
      if (!record->has_active_schema_version
          || record->active_schema_version == 0
          || record->active_schema_version > G_MAXUINT32) {
        rc = WYRELOG_E_POLICY;
        break;
      }
      ReplayRelation *rel = NULL;
      rc = load_relation_schema (policy, graph, record->namespace_id,
              record->relation_name, (guint32) record->active_schema_version,
              &rel);
      if (rc == WYRELOG_E_OK) {
        g_ptr_array_add (relations, rel);
        g_hash_table_add (seen, replay_relation_seen_key (record->namespace_id,
            record->relation_name));
      }
    }
  }
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autoptr (GPtrArray) stored_keys =
      g_ptr_array_new_with_free_func (replay_relation_key_free);
  if (store != NULL) {
    WylFactStoreConnectionSession session = { 0 };
    rc = wyl_fact_store_connection_session_begin (store, &session);
    if (rc != WYRELOG_E_OK)
      return rc;
    duckdb_connection conn = wyl_fact_store_connection_session_get (&session);
    GCancellable *cancellable = job_context == NULL ? NULL
      : wyl_fact_replay_job_context_get_cancellable (job_context);
    gulong interrupt_handler = cancellable == NULL ? 0
      : g_cancellable_connect (cancellable,
            G_CALLBACK (replay_interrupt_cancelled), conn, NULL);
#if defined(WYL_TEST_HANDLE_SEAMS)
    validation_connected_test_hook_invoke (job_context);
#endif
    duckdb_prepared_statement stmt = NULL;
    duckdb_result result = { 0 };
    static const gchar *sql =
        "SELECT DISTINCT namespace_id, relation_name, schema_version "
        "FROM fact_batches WHERE tenant_id = ? AND graph_id = ? "
        "ORDER BY namespace_id, relation_name, schema_version;";
    if (job_context != NULL)
      rc = wyl_fact_replay_job_context_checkpoint (job_context);
    if (rc == WYRELOG_E_OK
        && duckdb_prepare (conn, sql, &stmt) != DuckDBSuccess) {
      duckdb_destroy_prepare (&stmt);
      rc = WYRELOG_E_IO;
    }
    if (rc == WYRELOG_E_OK
        && (duckdb_bind_varchar (stmt, 1, graph->tenant_id) != DuckDBSuccess
        || duckdb_bind_varchar (stmt, 2, graph->graph_id) != DuckDBSuccess)) {
      rc = WYRELOG_E_IO;
    }
    if (rc == WYRELOG_E_OK
        && duckdb_execute_prepared (stmt, &result) != DuckDBSuccess) {
      rc = job_context == NULL ? WYRELOG_E_IO
        : wyl_fact_replay_job_context_checkpoint (job_context);
      if (rc == WYRELOG_E_OK)
        rc = WYRELOG_E_IO;
    }

    for (idx_t row = 0; rc == WYRELOG_E_OK && row < duckdb_row_count (&result);
        row++) {
      if (job_context != NULL) {
        rc = wyl_fact_replay_job_context_checkpoint (job_context);
        if (rc != WYRELOG_E_OK)
          break;
      }
      if (duckdb_value_is_null (&result, 0, row)
          || duckdb_value_is_null (&result, 1, row)
          || duckdb_value_is_null (&result, 2, row)) {
        rc = WYRELOG_E_POLICY;
        break;
      }
      gchar *namespace_id = duckdb_value_varchar (&result, 0, row);
      gchar *relation_name = duckdb_value_varchar (&result, 1, row);
      gint64 schema_version = duckdb_value_int64 (&result, 2, row);
      if (namespace_id == NULL || relation_name == NULL || schema_version <= 0
          || schema_version > G_MAXUINT32) {
        rc = WYRELOG_E_POLICY;
      } else {
        ReplayRelationKey *key = g_new0 (ReplayRelationKey, 1);
        key->namespace_id = g_strdup (namespace_id);
        key->relation_name = g_strdup (relation_name);
        key->schema_version = (guint32) schema_version;
        if (key->namespace_id == NULL || key->relation_name == NULL) {
          replay_relation_key_free (key);
          rc = WYRELOG_E_NOMEM;
        } else {
          g_ptr_array_add (stored_keys, key);
        }
      }
      duckdb_free (namespace_id);
      duckdb_free (relation_name);
    }
    if (interrupt_handler != 0)
      g_cancellable_disconnect (cancellable, interrupt_handler);
    duckdb_destroy_prepare (&stmt);
    duckdb_destroy_result (&result);
    wyl_fact_store_connection_session_end (&session);
  }
  if (rc != WYRELOG_E_OK)
    return rc;

  for (guint i = 0; i < stored_keys->len; i++) {
    ReplayRelationKey *stored = g_ptr_array_index (stored_keys, i);
    g_hash_table_add (batch_names, replay_relation_seen_key (
          stored->namespace_id, stored->relation_name));
    g_hash_table_add (batch_versions, replay_relation_version_key (
          stored->namespace_id, stored->relation_name, stored->schema_version));
  }

  for (guint i = 0; rc == WYRELOG_E_OK && i < stored_keys->len; i++) {
    if (job_context != NULL) {
      rc = wyl_fact_replay_job_context_checkpoint (job_context);
      if (rc != WYRELOG_E_OK)
        break;
    }
    ReplayRelationKey *stored = g_ptr_array_index (stored_keys, i);
    g_autofree gchar *key = replay_relation_seen_key (stored->namespace_id,
            stored->relation_name);
    if (!g_hash_table_contains (seen, key)) {
      ReplayRelation *rel = NULL;
      if (policy_snapshot != NULL) {
        ReplayRelation *schema = replay_snapshot_find_schema (policy_snapshot,
                stored->namespace_id, stored->relation_name,
                stored->schema_version);
        if (schema == NULL)
          rc = WYRELOG_E_NOT_FOUND;
        else
          rel = replay_relation_clone (schema);
      } else {
        rc = load_relation_schema (policy, graph, stored->namespace_id,
                stored->relation_name, stored->schema_version, &rel);
      }
      if (rc == WYRELOG_E_OK) {
        rel->has_durable_batches = TRUE;
        g_ptr_array_add (relations, rel);
      }
    }
  }
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autoptr (GPtrArray) registered = NULL;
  if (policy_snapshot != NULL) {
    registered = g_ptr_array_new_with_free_func (replay_relation_free);
    for (guint i = 0; i < policy_snapshot->schemas->len; i++) {
      if (job_context != NULL) {
        rc = wyl_fact_replay_job_context_checkpoint (job_context);
        if (rc != WYRELOG_E_OK)
          return rc;
      }
      g_ptr_array_add (registered, replay_relation_clone (
            g_ptr_array_index (policy_snapshot->schemas, i)));
    }
  } else {
    registered = g_ptr_array_new_with_free_func (replay_relation_free);
    ReplayRegisteredSchemaCollectCtx collect = {
      .policy = policy,
      .graph = graph,
      .job_context = job_context,
      .schemas = registered,
    };
    rc = wyl_policy_store_foreach_fact_relation_schema_key (policy,
            graph->tenant_id, graph->graph_id,
            collect_replay_registered_schema, &collect);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  g_autoptr (GHashTable) candidate_names =
      g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
          (GDestroyNotify) g_ptr_array_unref);
  for (guint i = 0; rc == WYRELOG_E_OK && i < registered->len; i++) {
    if (job_context != NULL)
      rc = wyl_fact_replay_job_context_checkpoint (job_context);
    if (rc != WYRELOG_E_OK)
      break;
    ReplayRelation *schema = g_ptr_array_index (registered, i);
    if (!schema->relation_visible)
      continue;
    g_autofree gchar *logical = replay_relation_seen_key (schema->namespace_id,
            schema->relation_name);
    if (g_hash_table_contains (seen, logical)
        || g_hash_table_contains (batch_names, logical)) {
      continue;
    }
    GPtrArray *versions = g_hash_table_lookup (candidate_names, logical);
    if (versions == NULL) {
      versions = g_ptr_array_new ();
      g_hash_table_insert (candidate_names, g_strdup (logical), versions);
    }
    g_ptr_array_add (versions, schema);
  }
  if (rc != WYRELOG_E_OK)
    return rc;
  GHashTableIter candidate_iter;
  gpointer candidate_key = NULL;
  gpointer candidate_value = NULL;
  g_hash_table_iter_init (&candidate_iter, candidate_names);
  while (rc == WYRELOG_E_OK
      && g_hash_table_iter_next (&candidate_iter, &candidate_key,
      &candidate_value)) {
    GPtrArray *versions = candidate_value;
    if (versions->len != 1) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    g_ptr_array_add (relations, replay_relation_clone (
          g_ptr_array_index (versions, 0)));
  }
  if (rc != WYRELOG_E_OK)
    return rc;
  for (guint i = 0; i < relations->len; i++) {
    ReplayRelation *rel = g_ptr_array_index (relations, i);
    g_autofree gchar *version = replay_relation_version_key (rel->namespace_id,
            rel->relation_name, rel->schema_version);
    rel->has_durable_batches = g_hash_table_contains (batch_versions, version);
  }

  *out_relations = g_steal_pointer (&relations);
  return WYRELOG_E_OK;
}

static gchar *
build_graph_program (GPtrArray *relations)
{
  g_autoptr (GString) program = g_string_new (NULL);
  for (guint i = 0; relations != NULL && i < relations->len; i++) {
    ReplayRelation *rel = g_ptr_array_index (relations, i);
    const gchar *relation_names[2] = { rel->wirelog_relation, NULL };
    g_autofree gchar *observed_relation = g_strdup_printf ("%s_observed",
            rel->wirelog_relation);
    relation_names[1] = observed_relation;

    for (guint decl_idx = 0; decl_idx < G_N_ELEMENTS (relation_names);
        decl_idx++) {
      g_string_append (program, ".decl ");
      g_string_append (program, relation_names[decl_idx]);
      g_string_append_c (program, '(');
      for (gsize col = 0; col < rel->n_columns; col++) {
        const gchar *column_type = rel->columns[col].column_type;
        const gchar *wire_type = NULL;
        if (g_strcmp0 (column_type, "symbol") == 0
            || g_strcmp0 (column_type, "string") == 0)
          wire_type = "symbol";
        else if (g_strcmp0 (column_type, "int64") == 0
            || g_strcmp0 (column_type, "bool") == 0
            || g_strcmp0 (column_type, "compound_ref") == 0)
          wire_type = "int64";
        else
          return NULL;
        if (col > 0)
          g_string_append (program, ", ");
        append_wirelog_identifier (program, rel->columns[col].column_name);
        g_string_append_printf (program, ": %s", wire_type);
      }
      g_string_append (program, ")\n");
    }

    g_string_append (program, observed_relation);
    g_string_append_c (program, '(');
    for (gsize col = 0; col < rel->n_columns; col++) {
      if (col > 0)
        g_string_append (program, ", ");
      g_string_append_printf (program, "V%" G_GSIZE_FORMAT, col);
    }
    g_string_append (program, ") :- ");
    g_string_append (program, rel->wirelog_relation);
    g_string_append_c (program, '(');
    for (gsize col = 0; col < rel->n_columns; col++) {
      if (col > 0)
        g_string_append (program, ", ");
      g_string_append_printf (program, "V%" G_GSIZE_FORMAT, col);
    }
    g_string_append (program, ").\n");
  }
  return g_string_free (g_steal_pointer (&program), FALSE);
}

static wyrelog_error_t
materialize_owned_cell (ReplayMaterializeCtx *ctx,
    const wyl_policy_fact_relation_schema_column_t *column,
    const ReplayOwnedCell *cell, gint64 *out)
{
  if (g_strcmp0 (column->column_type, "symbol") == 0
      || g_strcmp0 (column->column_type, "string") == 0) {
    if (cell->text == NULL)
      return WYRELOG_E_POLICY;
    return wyl_engine_owned_intern_symbol (ctx->engine, cell->text, out);
  }
  if (g_strcmp0 (column->column_type, "int64") == 0) {
    *out = cell->integer;
    return WYRELOG_E_OK;
  }
  if (g_strcmp0 (column->column_type, "bool") == 0) {
    *out = cell->boolean ? 1 : 0;
    return WYRELOG_E_OK;
  }
  if (g_strcmp0 (column->column_type, "compound_ref") == 0) {
    wyrelog_error_t rc = ctx->job_context == NULL
        ? wyl_fact_compound_replay_cached (ctx->store, ctx->engine,
            ctx->tenant_id, ctx->graph_id, ctx->namespace_id, cell->integer,
            ctx->compound_handles, out)
        : wyl_fact_compound_replay_cached_bounded (ctx->store, ctx->engine,
            ctx->tenant_id, ctx->graph_id, ctx->namespace_id, cell->integer,
            ctx->compound_handles, ctx->job_context, out);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (*out <= 0)
      return WYRELOG_E_INTERNAL;
    return WYRELOG_E_OK;
  }
  return WYRELOG_E_POLICY;
}

static gchar *
row_key (const gint64 *row, gsize ncols)
{
  return g_base64_encode ((const guchar *) row, sizeof (gint64) * ncols);
}

static void
insert_or_replace_row (GHashTable *rows, const gint64 *row, gsize ncols)
{
  g_autofree gchar *key = row_key (row, ncols);
  gint64 *copy = g_memdup2 (row, sizeof (gint64) * ncols);
  g_hash_table_replace (rows, g_steal_pointer (&key), copy);
}

static void
remove_row (GHashTable *rows, const gint64 *row, gsize ncols)
{
  g_autofree gchar *key = row_key (row, ncols);
  g_hash_table_remove (rows, key);
}

static void
replay_interrupt_cancelled (GCancellable *cancellable, gpointer user_data)
{
  (void) cancellable;
  duckdb_interrupt ((duckdb_connection) user_data);
}

static wyrelog_error_t
replay_relation_into_engine (wyl_fact_store_t *store,
    const wyl_policy_fact_graph_info_t *graph, ReplayRelation *rel,
    WylEngine *engine, GHashTable *compound_handles,
    WylFactReplayJobContext *job_context)
{
  if (store == NULL || graph == NULL || rel == NULL || engine == NULL
      || compound_handles == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = job_context == NULL ? WYRELOG_E_OK
      : wyl_fact_replay_job_context_checkpoint (job_context);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!rel->has_durable_batches)
    return WYRELOG_E_OK;
  g_autoptr (GString) sql = g_string_new ("SELECT ");
  for (gsize i = 0; i < rel->n_columns; i++) {
    if (i > 0)
      g_string_append (sql, ", ");
    append_duckdb_identifier (sql, rel->columns[i].column_name);
  }
  g_string_append (sql, ", __wyl_valid FROM ");
  append_duckdb_identifier (sql, rel->projection_table);
  g_string_append (sql,
      " WHERE __wyl_tenant_id = ? AND __wyl_graph_id = ? "
      "ORDER BY __wyl_seq, __wyl_row_index;");

  g_autoptr (GPtrArray) owned_rows =
      g_ptr_array_new_with_free_func (replay_owned_row_free);
  WylFactStoreConnectionSession session = { 0 };
  rc = wyl_fact_store_connection_session_begin (store,
          &session);
  if (rc != WYRELOG_E_OK)
    return rc;
  duckdb_connection conn = wyl_fact_store_connection_session_get (&session);
  GCancellable *cancellable = job_context == NULL ? NULL
      : wyl_fact_replay_job_context_get_cancellable (job_context);
  gulong interrupt_handler = cancellable == NULL ? 0
      : g_cancellable_connect (cancellable,
          G_CALLBACK (replay_interrupt_cancelled), conn, NULL);
  duckdb_prepared_statement stmt = NULL;
  duckdb_result result = { 0 };
  if (job_context != NULL)
    rc = wyl_fact_replay_job_context_checkpoint (job_context);
  if (rc == WYRELOG_E_OK
      && duckdb_prepare (conn, sql->str, &stmt) != DuckDBSuccess) {
    duckdb_destroy_prepare (&stmt);
    rc = WYRELOG_E_IO;
  }
  if (rc == WYRELOG_E_OK
      && (duckdb_bind_varchar (stmt, 1, graph->tenant_id) != DuckDBSuccess
      || duckdb_bind_varchar (stmt, 2, graph->graph_id) != DuckDBSuccess))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK
      && duckdb_execute_prepared (stmt, &result) != DuckDBSuccess) {
    rc = job_context == NULL ? WYRELOG_E_IO
        : wyl_fact_replay_job_context_checkpoint (job_context);
    if (rc == WYRELOG_E_OK)
      rc = WYRELOG_E_IO;
  }
  if (rc == WYRELOG_E_OK
      && duckdb_row_count (&result) > WYL_FACT_REPLAY_MAX_ROWS)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && job_context != NULL)
    rc = wyl_fact_replay_job_context_charge_rows (job_context,
            duckdb_row_count (&result));

  for (idx_t r = 0; rc == WYRELOG_E_OK && r < duckdb_row_count (&result); r++) {
    if (job_context != NULL)
      rc = wyl_fact_replay_job_context_checkpoint (job_context);
    if (rc != WYRELOG_E_OK)
      break;
    if (duckdb_value_is_null (&result, rel->n_columns, r)) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    ReplayOwnedRow *owned = g_new0 (ReplayOwnedRow, 1);
    owned->n_cells = rel->n_columns;
    owned->cells = g_new0 (ReplayOwnedCell, rel->n_columns);
    owned->valid = duckdb_value_boolean (&result, rel->n_columns, r);
    for (gsize c = 0; rc == WYRELOG_E_OK && c < rel->n_columns; c++) {
      if (duckdb_value_is_null (&result, c, r)) {
        rc = WYRELOG_E_POLICY;
        break;
      }
      const gchar *type = rel->columns[c].column_type;
      if (g_strcmp0 (type, "symbol") == 0
          || g_strcmp0 (type, "string") == 0) {
        gchar *value = duckdb_value_varchar (&result, c, r);
        if (value == NULL) {
          rc = WYRELOG_E_POLICY;
        } else {
          owned->cells[c].text = g_strdup (value);
          duckdb_free (value);
          if (owned->cells[c].text == NULL)
            rc = WYRELOG_E_NOMEM;
        }
      } else if (g_strcmp0 (type, "int64") == 0
          || g_strcmp0 (type, "compound_ref") == 0) {
        owned->cells[c].integer = duckdb_value_int64 (&result, c, r);
      } else if (g_strcmp0 (type, "bool") == 0) {
        owned->cells[c].boolean = duckdb_value_boolean (&result, c, r);
      } else {
        rc = WYRELOG_E_POLICY;
      }
    }
    if (rc == WYRELOG_E_OK)
      g_ptr_array_add (owned_rows, owned);
    else
      replay_owned_row_free (owned);
  }
  if (interrupt_handler != 0)
    g_cancellable_disconnect (cancellable, interrupt_handler);
  duckdb_destroy_prepare (&stmt);
  duckdb_destroy_result (&result);
  wyl_fact_store_connection_session_end (&session);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autoptr (GHashTable) current_rows =
      g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  ReplayMaterializeCtx mat = {
    .engine = engine,
    .tenant_id = graph->tenant_id,
    .graph_id = graph->graph_id,
    .namespace_id = rel->namespace_id,
    .store = store,
    .compound_handles = compound_handles,
    .job_context = job_context,
  };

  for (guint r = 0; rc == WYRELOG_E_OK && r < owned_rows->len; r++) {
    if (job_context != NULL)
      rc = wyl_fact_replay_job_context_checkpoint (job_context);
    if (rc != WYRELOG_E_OK)
      break;
    ReplayOwnedRow *owned = g_ptr_array_index (owned_rows, r);
    g_autofree gint64 *wire_row = g_new0 (gint64, rel->n_columns);
    for (gsize c = 0; rc == WYRELOG_E_OK && c < rel->n_columns; c++)
      rc = materialize_owned_cell (&mat, &rel->columns[c], &owned->cells[c],
              &wire_row[c]);
    if (rc != WYRELOG_E_OK)
      break;
    if (owned->valid)
      insert_or_replace_row (current_rows, wire_row, rel->n_columns);
    else
      remove_row (current_rows, wire_row, rel->n_columns);
  }
  if (rc != WYRELOG_E_OK)
    return rc;

  GHashTableIter iter;
  gpointer key = NULL;
  gpointer value = NULL;
  g_hash_table_iter_init (&iter, current_rows);
  while (g_hash_table_iter_next (&iter, &key, &value)) {
    (void) key;
    if (job_context != NULL) {
      rc = wyl_fact_replay_job_context_checkpoint (job_context);
      if (rc != WYRELOG_E_OK)
        return rc;
    }
    rc = wyl_engine_owned_insert (engine, rel->wirelog_relation,
            (const gint64 *) value, rel->n_columns);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
replay_relations_into_engine (wyl_fact_store_t *store,
    const wyl_policy_fact_graph_info_t *graph, GPtrArray *relations,
    WylEngine *engine, WylFactReplayJobContext *job_context)
{
  g_autoptr (GHashTable) compound_handles =
      g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  for (guint i = 0; relations != NULL && i < relations->len; i++) {
    wyrelog_error_t rc = replay_relation_into_engine (store, graph,
            g_ptr_array_index (relations, i), engine, compound_handles,
            job_context);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
resolve_fact_db_path (wyl_policy_store_t *policy, const gchar *fact_root,
    const wyl_policy_fact_graph_info_t *graph_info, gchar **out_path)
{
  *out_path = NULL;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  wyrelog_error_t rc = wyl_policy_store_open_fact_graph_directory (policy,
          fact_root, graph_info->tenant_id, graph_info->graph_id, FALSE,
          &directory);
  /* A graph directory is durable provisioning evidence.  A missing directory
   * means storage is unavailable; only a present directory with no database
   * file is the expected lazy, pre-first-append state. */
  if (rc == WYRELOG_E_NOT_FOUND)
    rc = WYRELOG_E_IO;
  gint fd = -1;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_open_file (&directory, "facts.duckdb",
            FALSE, &fd);
  if (rc == WYRELOG_E_OK) {
    *out_path = wyl_fact_graph_directory_descriptive_file (&directory,
            "facts.duckdb");
    if (*out_path == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  if (fd >= 0)
#ifdef G_OS_WIN32
    _close (fd);
#else
    close (fd);
#endif
  wyl_fact_graph_directory_clear (&directory);
  return rc;
}

/* Open one graph's fact store, choosing the same provisioned/legacy path the
 * engine builder chooses.  Extracted so the two callers cannot drift: they
 * differ only in whether they need to write. */
static wyrelog_error_t
open_graph_store (wyl_policy_store_t *policy, const gchar *fact_root,
    const wyl_policy_fact_graph_info_t *graph_info, gboolean writable,
    WylFactArtifactNamespace *artifact_namespace,
    WylFactArtifactMutationLease *artifact_lease,
    WylFactResourceRecorder *resource_recorder,
    wyl_fact_store_t **out_store)
{
  g_assert (out_store != NULL);
  *out_store = NULL;
#if defined(WYL_HAS_SECURE_DUCKDB_BRIDGE)
  gboolean provisioned = FALSE;
  {
    WylPolicyGraphAuthorityRecord *authority = NULL;
    if (wyl_policy_store_read_graph_authority (policy, graph_info->tenant_id,
        graph_info->graph_id, &authority) == WYRELOG_E_OK
        && authority != NULL && authority->lifecycle_state
        != WYL_POLICY_GRAPH_LIFECYCLE_LEGACY_UNCLASSIFIED)
      provisioned = TRUE;
    if (provisioned && artifact_namespace != NULL && artifact_lease != NULL) {
      WylFactStoreIdentity identity = { 0 };
      identity.tenant_id = authority->tenant_id;
      identity.graph_id = authority->graph_id;
      identity.store_uuid = authority->store_uuid;
      identity.format_version = authority->format_version;
      identity.path_encoding_version = authority->path_encoding_version;
      wyrelog_error_t lease_rc =
          wyl_fact_store_open_provisioned_namespace_with_lease (
        artifact_namespace, artifact_lease, &identity,
        writable || artifact_lease != NULL,
        out_store);
      if (lease_rc == WYRELOG_E_OK)
        wyl_fact_store_attach_physical_quota_context (*out_store, policy,
            artifact_namespace, artifact_lease);
      if (lease_rc == WYRELOG_E_OK)
        wyl_fact_store_observe_open (*out_store, resource_recorder);
      wyl_policy_graph_authority_record_free (authority);
      return lease_rc;
    }
    wyl_policy_graph_authority_record_free (authority);
  }
  if (provisioned)
    return wyl_fact_store_open_provisioned_graph_observed (policy, fact_root,
               graph_info->tenant_id, graph_info->graph_id, writable,
               resource_recorder, NULL, out_store);
#else
  (void) writable;
  (void) artifact_namespace;
  (void) artifact_lease;
#endif
  g_autofree gchar *fact_db_path = NULL;
  wyrelog_error_t rc = resolve_fact_db_path (policy, fact_root, graph_info,
          &fact_db_path);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_fact_store_open_legacy_graph_observed (policy, fact_db_path,
             fact_root, graph_info->tenant_id, graph_info->graph_id, writable,
             resource_recorder, NULL, out_store);
}

static wyrelog_error_t
replay_store_with_snapshot (wyl_policy_store_t *policy,
    wyl_fact_store_t *store,
    const wyl_policy_fact_graph_info_t *graph_info,
    const ReplayPolicyGraphSnapshot *policy_snapshot,
    WylFactReplayJobContext *job_context, WylEngine **out_engine)
{
  if (out_engine != NULL)
    *out_engine = NULL;
  if (policy == NULL || graph_info == NULL || out_engine == NULL)
    return WYRELOG_E_INVALID;
  if (job_context != NULL) {
    wyrelog_error_t checkpoint_rc =
        wyl_fact_replay_job_context_checkpoint (job_context);
    if (checkpoint_rc != WYRELOG_E_OK)
      return checkpoint_rc;
  }
#if defined(WYL_TEST_HANDLE_SEAMS)
  if (take_fact_replay_test_fault (
        WYL_FACT_REPLAY_TEST_FAULT_OPEN_GRAPH_ENGINE))
    return WYRELOG_E_IO;
#endif

  /* A restore preflight supplies a read-only store opened from its retained
   * stage reader. Existing empty-graph replay may still have no store at all.
   * When supplied, reject a poisoned store and verify its persisted scope
   * before policy enumeration or any row replay. */
  wyrelog_error_t rc = WYRELOG_E_OK;
  if (store != NULL) {
    WylFactStoreConnectionSession admission = { 0 };
    rc = wyl_fact_store_connection_session_begin (store, &admission);
    if (rc != WYRELOG_E_OK)
      return rc;
    wyl_fact_store_connection_session_end (&admission);
    rc = wyl_fact_store_validate_scope (store, graph_info->tenant_id,
            graph_info->graph_id);
    if (rc != WYRELOG_E_OK)
      return rc;
  }

  g_autoptr (GPtrArray) relations = NULL;
  rc = list_replay_relations (policy, store, graph_info, policy_snapshot,
          job_context,
          &relations);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (relations->len == 0)
    return WYRELOG_E_NOT_FOUND;

  g_autofree gchar *program = build_graph_program (relations);
  if (program == NULL)
    return WYRELOG_E_NOMEM;

  WylEngine *engine = NULL;
  rc = wyl_engine_open_source (program, 1, &engine);
  if (rc != WYRELOG_E_OK)
    return rc;
  wyl_engine_set_owner (engine, WYL_ENGINE_OWNER_READ);

  if (store != NULL)
    rc = replay_relations_into_engine (store, graph_info, relations, engine,
            job_context);
  if (rc != WYRELOG_E_OK) {
    g_object_unref (engine);
    return rc;
  }

  *out_engine = engine;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
open_graph_engine_with_store (wyl_policy_store_t *policy,
    wyl_fact_store_t *store,
    const wyl_policy_fact_graph_info_t *graph_info,
    const ReplayPolicyGraphSnapshot *policy_snapshot,
    WylFactReplayJobContext *job_context, WylEngine **out_engine)
{
  if (out_engine != NULL)
    *out_engine = NULL;
  if (policy == NULL || graph_info == NULL || out_engine == NULL)
    return WYRELOG_E_INVALID;
  if (graph_info->sealed)
    return WYRELOG_E_POLICY;
  return replay_store_with_snapshot (policy, store, graph_info,
             policy_snapshot, job_context, out_engine);
}

static wyrelog_error_t
open_graph_engine_with_artifact_lease (wyl_policy_store_t *policy,
    const gchar *fact_root, const wyl_policy_fact_graph_info_t *graph_info,
    const ReplayPolicyGraphSnapshot *policy_snapshot,
    WylFactArtifactNamespace *artifact_namespace,
    WylFactArtifactMutationLease *artifact_lease,
    WylFactReplayJobContext *job_context, WylEngine **out_engine)
{
  if (out_engine != NULL)
    *out_engine = NULL;
  if (policy == NULL || fact_root == NULL || graph_info == NULL
      || out_engine == NULL)
    return WYRELOG_E_INVALID;
  if (graph_info->sealed)
    return WYRELOG_E_POLICY;
#if defined(WYL_TEST_HANDLE_SEAMS)
  /* Taken here rather than in wyl_fact_replay_open_graph_engine, which is no
   * longer the only way in: build_graph_engine needs the artifact namespace
   * and lease, so it calls this function directly.  Checking in the public
   * entry point alone would leave the runtime's engine builder -- the path a
   * mutation actually takes -- unable to be faulted, and a graph whose engine
   * failed to open would be reported committed_ready. */
  if (take_fact_replay_test_fault (
        WYL_FACT_REPLAY_TEST_FAULT_OPEN_GRAPH_ENGINE))
    return WYRELOG_E_IO;
#endif
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (job_context != NULL) {
    wyrelog_error_t checkpoint_rc =
        wyl_fact_replay_job_context_checkpoint (job_context);
    if (checkpoint_rc != WYRELOG_E_OK)
      return checkpoint_rc;
  }
  wyrelog_error_t rc = open_graph_store (policy, fact_root, graph_info, FALSE,
          artifact_namespace, artifact_lease,
          wyl_fact_replay_job_context_get_resource_recorder (job_context),
          &store);
  if (rc == WYRELOG_E_NOT_FOUND) {
    WylPolicyGraphMaterializationState state = policy_snapshot == NULL
        ? graph_materialization_state_or_unknown (policy, graph_info)
        : policy_snapshot->materialization_state;
    if (state == WYL_POLICY_GRAPH_MATERIALIZATION_NEVER) {
      WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
      rc = wyl_policy_store_open_fact_graph_directory (policy, fact_root,
              graph_info->tenant_id, graph_info->graph_id, FALSE, &directory);
      wyl_fact_graph_directory_clear (&directory);
      if (rc == WYRELOG_E_OK)
        return open_graph_engine_with_store (policy, NULL, graph_info,
                   policy_snapshot, job_context, out_engine);
      if (rc == WYRELOG_E_NOT_FOUND)
        rc = WYRELOG_E_IO;
    }
  }
  if (rc != WYRELOG_E_OK) {
    if (job_context != NULL && rc == WYRELOG_E_RESOURCE_LIMIT)
      wyl_fact_replay_job_context_record_quota_rejection (job_context);
    return rc;
  }
  rc = open_graph_engine_with_store (policy, store, graph_info,
          policy_snapshot, job_context, out_engine);
  g_clear_pointer (&store, wyl_fact_store_close);
  return rc;
}

static wyrelog_error_t
validate_graph_internal (wyl_policy_store_t *policy,
    const gchar *fact_root, const wyl_policy_fact_graph_info_t *graph_info,
    const ReplayPolicyGraphSnapshot *policy_snapshot,
    WylFactArtifactNamespace *artifact_namespace,
    WylFactArtifactMutationLease *artifact_lease,
    WylFactReplayJobContext *job_context)
{
  if (policy == NULL || graph_info == NULL || graph_info->tenant_id == NULL
      || graph_info->graph_id == NULL)
    return WYRELOG_E_INVALID;

  g_autoptr (wyl_fact_store_t) store = NULL;
  wyrelog_error_t rc = job_context == NULL ? WYRELOG_E_OK
      : wyl_fact_replay_job_context_checkpoint (job_context);
  if (rc == WYRELOG_E_OK)
    rc = open_graph_store (policy, fact_root, graph_info, FALSE,
            artifact_namespace, artifact_lease,
            wyl_fact_replay_job_context_get_resource_recorder (job_context),
            &store);
  if (rc != WYRELOG_E_OK) {
    if (job_context != NULL && rc == WYRELOG_E_RESOURCE_LIMIT)
      wyl_fact_replay_job_context_record_quota_rejection (job_context);
    return rc;
  }

  rc = wyl_fact_store_validate_scope (store, graph_info->tenant_id,
          graph_info->graph_id);
  if (rc == WYRELOG_E_OK) {
    /* Opening the provisioned store performs the physical identity and
     * metadata-schema validation. Enumerating replay relations then checks
     * that durable policy schema is complete and type-valid before the
     * caller asks the runtime to publish anything. */
    g_autoptr (GPtrArray) relations = NULL;
    rc = list_replay_relations (policy, store, graph_info, policy_snapshot,
            job_context, &relations);
  }
  g_clear_pointer (&store, wyl_fact_store_close);
  return rc;
}

wyrelog_error_t
wyl_fact_replay_validate_graph (wyl_policy_store_t *policy,
    const gchar *fact_root, const wyl_policy_fact_graph_info_t *graph_info)
{
  return validate_graph_internal (policy, fact_root, graph_info, NULL, NULL,
             NULL, NULL);
}

wyrelog_error_t
wyl_fact_replay_validate_graph_bounded (wyl_policy_store_t *policy,
    const gchar *fact_root, const wyl_policy_fact_graph_info_t *graph_info,
    WylFactReplayJobContext *job_context)
{
  if (job_context == NULL)
    return WYRELOG_E_INVALID;
  ReplayPolicyGraphSnapshot snapshot;
  wyrelog_error_t rc = capture_replay_policy_graph_snapshot (policy,
          graph_info, job_context, &snapshot);
  if (rc == WYRELOG_E_OK)
    rc = validate_graph_internal (policy, fact_root, &snapshot.info,
            &snapshot, NULL, NULL, job_context);
  replay_policy_graph_snapshot_clear (&snapshot);
  return rc;
}

wyrelog_error_t
wyl_fact_replay_validate_graph_with_artifact_lease
  (wyl_policy_store_t *policy, const gchar *fact_root,
    const wyl_policy_fact_graph_info_t *graph_info,
    WylFactArtifactNamespace *artifact_namespace,
    WylFactArtifactMutationLease *artifact_lease)
{
  if (artifact_namespace == NULL || artifact_lease == NULL)
    return WYRELOG_E_INVALID;
  return validate_graph_internal (policy, fact_root, graph_info,
             NULL, artifact_namespace, artifact_lease, NULL);
}

wyrelog_error_t
wyl_fact_replay_validate_graph_with_artifact_lease_bounded
  (wyl_policy_store_t *policy, const gchar *fact_root,
    const wyl_policy_fact_graph_info_t *graph_info,
    WylFactArtifactNamespace *artifact_namespace,
    WylFactArtifactMutationLease *artifact_lease,
    WylFactReplayJobContext *job_context)
{
  if (artifact_namespace == NULL || artifact_lease == NULL
      || job_context == NULL)
    return WYRELOG_E_INVALID;
  ReplayPolicyGraphSnapshot snapshot;
  wyrelog_error_t rc = capture_replay_policy_graph_snapshot (policy,
          graph_info, job_context, &snapshot);
  if (rc == WYRELOG_E_OK)
    rc = validate_graph_internal (policy, fact_root, &snapshot.info,
            &snapshot, artifact_namespace, artifact_lease, job_context);
  replay_policy_graph_snapshot_clear (&snapshot);
  return rc;
}

#if defined(WYL_TEST_HANDLE_SEAMS)
wyrelog_error_t
wyl_fact_replay_open_graph_engine_with_store_for_test
  (wyl_policy_store_t *policy, wyl_fact_store_t *store,
    const wyl_policy_fact_graph_info_t *graph_info, WylEngine **out_engine)
{
  return open_graph_engine_with_store (policy, store, graph_info, NULL, NULL,
             out_engine);
}
#endif

wyrelog_error_t
wyl_fact_replay_open_graph_engine (wyl_policy_store_t *policy,
    const gchar *fact_root, const wyl_policy_fact_graph_info_t *graph_info,
    WylEngine **out_engine)
{
  if (out_engine != NULL)
    *out_engine = NULL;
  if (policy == NULL || fact_root == NULL || fact_root[0] == '\0'
      || graph_info == NULL || out_engine == NULL)
    return WYRELOG_E_INVALID;
  if (graph_info->sealed)
    return WYRELOG_E_POLICY;
  return open_graph_engine_with_artifact_lease (policy, fact_root, graph_info,
             NULL, NULL, NULL, NULL, out_engine);
}

typedef struct
{
  wyl_policy_fact_graph_info_t info;
  WylFactGraphKey key;
  gboolean key_valid;
  ReplayPolicyGraphSnapshot policy_snapshot;
} OwnedGraphSpec;

static void
owned_graph_spec_free (gpointer data)
{
  OwnedGraphSpec *spec = data;
  if (spec == NULL)
    return;
  g_free ((gchar *) spec->info.tenant_id);
  g_free ((gchar *) spec->info.graph_id);
  g_free ((gchar *) spec->info.storage_uri);
  g_free ((gchar *) spec->info.storage_path);
  g_free ((gchar *) spec->info.owner_scope);
  replay_policy_graph_snapshot_clear (&spec->policy_snapshot);
  wyl_fact_graph_key_clear (&spec->key);
  g_free (spec);
}

static wyrelog_error_t
collect_graph_spec (const wyl_policy_fact_graph_info_t *info,
    gpointer user_data)
{
  GPtrArray *specs = user_data;
  OwnedGraphSpec *spec = g_new0 (OwnedGraphSpec, 1);
  spec->info.tenant_id = g_strdup (info->tenant_id);
  spec->info.graph_id = g_strdup (info->graph_id);
  spec->info.storage_uri = g_strdup (info->storage_uri);
  spec->info.storage_path = g_strdup (info->storage_path);
  spec->info.schema_version = info->schema_version;
  spec->info.owner_scope = g_strdup (info->owner_scope);
  spec->info.sealed = info->sealed;
  replay_policy_graph_snapshot_init (&spec->policy_snapshot);
  wyrelog_error_t rc = wyl_fact_graph_key_init (&spec->key, info->tenant_id,
          info->graph_id);
  if (rc != WYRELOG_E_OK && rc != WYRELOG_E_INVALID) {
    owned_graph_spec_free (spec);
    return rc;
  }
  spec->key_valid = rc == WYRELOG_E_OK;
  g_ptr_array_add (specs, spec);
  return WYRELOG_E_OK;
}

typedef struct
{
  wyl_policy_store_t *policy;
  const wyl_policy_fact_graph_info_t *info;
  ReplayPolicyGraphSnapshot *snapshot;
} ReplaySchemaSnapshotCtx;

static wyrelog_error_t
collect_replay_schema_snapshot (const gchar *namespace_id,
    const gchar *relation_name, guint32 schema_version, gpointer user_data)
{
  ReplaySchemaSnapshotCtx *ctx = user_data;
  ReplayRelation *relation = NULL;
  wyrelog_error_t rc = load_relation_schema (ctx->policy, ctx->info,
          namespace_id, relation_name, schema_version, &relation);
  if (rc == WYRELOG_E_OK)
    g_ptr_array_add (ctx->snapshot->schemas, relation);
  return rc;
}

static wyrelog_error_t
capture_replay_policy_graph_snapshot_locked (wyl_policy_store_t *policy,
    const wyl_policy_fact_graph_info_t *info,
    ReplayPolicyGraphSnapshot *snapshot)
{
  ReplayGraphInfoSnapshotCtx graph_ctx = { info->graph_id, snapshot };
  wyrelog_error_t rc = wyl_policy_store_foreach_fact_graph (policy,
          info->tenant_id, capture_replay_graph_info, &graph_ctx);
  if (rc == WYRELOG_E_OK && !snapshot->info_valid)
    rc = WYRELOG_E_NOT_FOUND;
  const wyl_policy_fact_graph_info_t *owned_info = &snapshot->info;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_fact_graph_active_schema_digest_in_replay_snapshot
          (policy, owned_info->tenant_id, owned_info->graph_id,
            &snapshot->active_schema_digest);
  if (rc == WYRELOG_E_OK) {
    wyrelog_error_t materialization_rc =
        wyl_policy_store_read_fact_graph_materialization
          (policy, owned_info->tenant_id, owned_info->graph_id,
            &snapshot->materialization_state);
    if (materialization_rc == WYRELOG_E_NOT_FOUND) {
      snapshot->materialization_state =
          WYL_POLICY_GRAPH_MATERIALIZATION_UNKNOWN;
    } else {
      rc = materialization_rc;
    }
  }
  g_autoptr (GPtrArray) active = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_list_active_fact_relations (policy,
            owned_info->tenant_id, owned_info->graph_id, &active);
  for (guint i = 0; rc == WYRELOG_E_OK && active != NULL
      && i < active->len; i++) {
    const WylPolicyRelationActivationRecord *record =
        g_ptr_array_index (active, i);
    if (!record->has_active_schema_version
        || record->active_schema_version == 0
        || record->active_schema_version > G_MAXUINT32) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    ReplayActiveRelation *copy = g_new0 (ReplayActiveRelation, 1);
    copy->namespace_id = g_strdup (record->namespace_id);
    copy->relation_name = g_strdup (record->relation_name);
    copy->schema_version = (guint32) record->active_schema_version;
    g_ptr_array_add (snapshot->active, copy);
  }
  ReplaySchemaSnapshotCtx schema_ctx = { policy, owned_info, snapshot };
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_foreach_fact_relation_schema_key (policy,
            owned_info->tenant_id, owned_info->graph_id,
            collect_replay_schema_snapshot, &schema_ctx);
  return rc;
}

static wyrelog_error_t
capture_replay_policy_graph_snapshot (wyl_policy_store_t *policy,
    const wyl_policy_fact_graph_info_t *info,
    WylFactReplayJobContext *job_context,
    ReplayPolicyGraphSnapshot *snapshot)
{
  replay_policy_graph_snapshot_init (snapshot);
  wyrelog_error_t rc = job_context == NULL ? WYRELOG_E_OK
      : wyl_fact_replay_job_context_checkpoint (job_context);
  gboolean begun = FALSE;
  gboolean current = rc == WYRELOG_E_OK
      && wyl_policy_store_fact_replay_snapshot_is_current (policy);
  if (rc == WYRELOG_E_OK && !current) {
    rc = wyl_policy_store_fact_replay_snapshot_begin (policy);
    begun = rc == WYRELOG_E_OK;
  }
  if (rc == WYRELOG_E_OK)
    rc = capture_replay_policy_graph_snapshot_locked (policy, info, snapshot);
  if (begun) {
    wyrelog_error_t end_rc =
        wyl_policy_store_fact_replay_snapshot_end (policy);
    if (rc == WYRELOG_E_OK)
      rc = end_rc;
  }
  if (rc == WYRELOG_E_OK && job_context != NULL)
    rc = wyl_fact_replay_job_context_checkpoint (job_context);
  if (rc != WYRELOG_E_OK)
    replay_policy_graph_snapshot_clear (snapshot);
  return rc;
}

static gboolean
canonical_sha256_text (const gchar *text)
{
  if (text == NULL || strlen (text) != 71
      || !g_str_has_prefix (text, "sha256:"))
    return FALSE;
  for (guint i = 7; i < 71; i++)
    if (!g_ascii_isdigit (text[i])
        && !(text[i] >= 'a' && text[i] <= 'f'))
      return FALSE;
  return TRUE;
}

wyrelog_error_t
wyl_fact_replay_validate_store_for_restore (wyl_policy_store_t *policy,
    wyl_fact_store_t *store,
    const wyl_policy_fact_graph_info_t *graph_info,
    const gchar *expected_schema_digest,
    WylFactReplayJobContext *job_context, gchar **out_schema_digest)
{
  if (out_schema_digest != NULL)
    *out_schema_digest = NULL;
  if (policy == NULL || store == NULL || graph_info == NULL
      || graph_info->tenant_id == NULL || graph_info->graph_id == NULL
      || !canonical_sha256_text (expected_schema_digest)
      || job_context == NULL || out_schema_digest == NULL)
    return WYRELOG_E_INVALID;

  ReplayPolicyGraphSnapshot snapshot;
  wyrelog_error_t rc = capture_replay_policy_graph_snapshot (policy,
          graph_info, job_context, &snapshot);
  if (rc != WYRELOG_E_OK)
    return rc;

  /* Restore is permitted to preflight only an already sealed graph. The
   * captured copy, not a later policy read, supplies both the digest and all
   * schema inputs used to replay the supplied store. */
  if (!snapshot.info.sealed
      || g_strcmp0 (snapshot.info.tenant_id, graph_info->tenant_id) != 0
      || g_strcmp0 (snapshot.info.graph_id, graph_info->graph_id) != 0
      || !canonical_sha256_text (snapshot.active_schema_digest)
      || g_strcmp0 (snapshot.active_schema_digest,
      expected_schema_digest) != 0) {
    replay_policy_graph_snapshot_clear (&snapshot);
    return WYRELOG_E_POLICY;
  }

  WylEngine *engine = NULL;
  rc = replay_store_with_snapshot (policy, store, &snapshot.info, &snapshot,
          job_context, &engine);
  if (engine != NULL)
    g_object_unref (engine);
  if (rc == WYRELOG_E_OK)
    *out_schema_digest = g_strdup (snapshot.active_schema_digest);
  if (rc == WYRELOG_E_OK && *out_schema_digest == NULL)
    rc = WYRELOG_E_NOMEM;
  if (rc != WYRELOG_E_OK)
    g_clear_pointer (out_schema_digest, g_free);
  replay_policy_graph_snapshot_clear (&snapshot);
  return rc;
}

static wyrelog_error_t
capture_replay_policy_snapshot (wyl_policy_store_t *policy,
    GPtrArray *specs)
{
  wyrelog_error_t rc = wyl_policy_store_fact_replay_snapshot_begin (policy);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_foreach_fact_graph (policy, NULL,
          collect_graph_spec, specs);
  wyrelog_error_t end_rc =
      wyl_policy_store_fact_replay_snapshot_end (policy);
  return rc == WYRELOG_E_OK ? end_rc : rc;
}

typedef struct
{
  wyl_policy_store_t *policy;
  const gchar *fact_root;
  const wyl_policy_fact_graph_info_t *info;
  const ReplayPolicyGraphSnapshot *policy_snapshot;
  WylPolicyGraphMaterializationState materialization_state;
  WylFactArtifactNamespace *artifact_namespace;
  WylFactArtifactMutationLease *artifact_lease;
  WylFactReplayJobContext *job_context;
} GraphBuildCtx;

static wyrelog_error_t
job_publish_check (gpointer user_data)
{
  return wyl_fact_replay_job_context_commit (user_data);
}

static WylPolicyGraphMaterializationState
graph_materialization_state_or_unknown (wyl_policy_store_t *policy,
    const wyl_policy_fact_graph_info_t *graph_info)
{
  WylPolicyGraphMaterializationState state =
      WYL_POLICY_GRAPH_MATERIALIZATION_UNKNOWN;
  if (wyl_policy_store_read_fact_graph_materialization (policy,
      graph_info->tenant_id, graph_info->graph_id, &state) != WYRELOG_E_OK)
    return WYL_POLICY_GRAPH_MATERIALIZATION_UNKNOWN;
  return state;
}

static wyrelog_error_t
build_graph_engine (const WylFactGraphKey *key, WylEngine **out_engine,
    gpointer user_data)
{
  GraphBuildCtx *ctx = user_data;
  if (g_strcmp0 (key->tenant_id, ctx->info->tenant_id) != 0
      || g_strcmp0 (key->graph_id, ctx->info->graph_id) != 0)
    return WYRELOG_E_INTERNAL;
  /* A crash can leave policy at PENDING after DuckDB committed.  Reconcile
   * only when the durable batch ledger proves the mutation happened; a
   * schema-only store remains degraded and is never promoted by boot. */
  if (ctx->materialization_state == WYL_POLICY_GRAPH_MATERIALIZATION_PENDING) {
    g_autoptr (wyl_fact_store_t) pending_store = NULL;
    wyrelog_error_t pending_rc = open_graph_store (ctx->policy,
            ctx->fact_root, ctx->info, FALSE, ctx->artifact_namespace,
            ctx->artifact_lease,
            wyl_fact_replay_job_context_get_resource_recorder
              (ctx->job_context),
            &pending_store);
    if (pending_rc != WYRELOG_E_OK)
      return pending_rc == WYRELOG_E_NOT_FOUND ? WYRELOG_E_IO : pending_rc;
    gboolean has_batches = FALSE;
    if (wyl_fact_store_has_durable_batches (pending_store, &has_batches)
        != WYRELOG_E_OK || !has_batches)
      return WYRELOG_E_IO;
    WylPolicyAuthorityMutationResult result;
    (void) wyl_policy_store_transition_fact_graph_materialization (
      ctx->policy, ctx->info->tenant_id, ctx->info->graph_id,
      WYL_POLICY_GRAPH_MATERIALIZATION_PENDING,
      WYL_POLICY_GRAPH_MATERIALIZATION_MATERIALIZED, &result);
  }
  wyrelog_error_t rc = open_graph_engine_with_artifact_lease (ctx->policy,
          ctx->fact_root, ctx->info, ctx->policy_snapshot,
          ctx->artifact_namespace, ctx->artifact_lease, ctx->job_context,
          out_engine);
  /* A missing store is empty only before the first successful materialization.
   * Existing graphs and UNKNOWN legacy graphs must remain degraded. */
  if (rc == WYRELOG_E_NOT_FOUND
      && ctx->materialization_state
      != WYL_POLICY_GRAPH_MATERIALIZATION_NEVER)
    return WYRELOG_E_IO;
  return rc;
}

/* Ask whether a graph has any pending forget intention without asking for
 * write access.  "Only a read lease" is the bridge case: off-bridge, and for
 * a LEGACY_UNCLASSIFIED graph under the bridge, open_graph_store discards
 * |writable| and this takes the same read-write DuckDB handle the engine
 * builder takes.
 *
 * The store handle lives and dies inside this function and the count
 * is returned by value, so no probe handle is in scope where the caller
 * escalates to a writable open.  That makes "the probe contends with the
 * escalation it decided on" unrepresentable rather than something a test has
 * to police -- which matters because off-bridge the two opens are the same
 * call and no off-bridge test could catch it.
 *
 * *out_opened reports whether the store was examined at all: TRUE means the
 * open succeeded, FALSE that it did not.  Do not read more into a failure
 * than that.  TRUE with a non-OK rc means only that we opened the store --
 * the survey can still fail with E_IO out of table_exists_unlocked or
 * load_pending_forget_intents_unlocked, which is a store examined and nothing
 * learned.  Today the caller cannot tell that from a genuinely unconverged
 * erasure and reports both as incomplete; separating them is what U2's
 * loaded/executed/refused/failed counts are for. */
static wyrelog_error_t
probe_graph_forgets (wyl_policy_store_t *policy, const gchar *fact_root,
    const wyl_policy_fact_graph_info_t *graph_info, gboolean *out_opened,
    gsize *out_pending, WylFactReplayJobContext *job_context)
{
  g_assert (out_opened != NULL);
  g_assert (out_pending != NULL);
  *out_opened = FALSE;
  *out_pending = 0;

  g_autoptr (wyl_fact_store_t) probe = NULL;
  wyrelog_error_t rc = job_context == NULL ? WYRELOG_E_OK
      : wyl_fact_replay_job_context_checkpoint (job_context);
  if (rc == WYRELOG_E_OK)
    rc = open_graph_store (policy, fact_root, graph_info, FALSE, NULL, NULL,
            wyl_fact_replay_job_context_get_resource_recorder (job_context),
            &probe);
  /* A graph whose store has never been written has nothing to converge.  The
   * resolver reports that as NOT_FOUND. */
  if (rc == WYRELOG_E_NOT_FOUND)
    return WYRELOG_E_OK;
  if (rc != WYRELOG_E_OK)
    return rc;
  *out_opened = TRUE;
  rc = wyl_fact_store_forget_pending_count (probe, graph_info->tenant_id,
          graph_info->graph_id, out_pending);
  return rc == WYRELOG_E_OK && job_context != NULL
      ? wyl_fact_replay_job_context_checkpoint (job_context) : rc;
}

/* Converge any forget interrupted by a crash, before the engine for this graph
 * is built.  A forget is durable in two steps -- a PENDING intent, then the
 * deletion and its completion -- and nothing in the request path resumes the
 * second step, so an interrupted forget stays pending until something drives
 * it.  Since a sealed graph refuses forget at the request boundary and there
 * is no unseal route, startup is its only remedy.
 *
 * Sealed graphs are therefore included deliberately: sealing blocks admission
 * of new data, not erasure of existing data, and the store opener serves a
 * sealed graph for exactly this reason.  That is a different question from
 * whether a sealed graph gets a query engine, which it does not.
 *
 * Returns non-OK only to be counted and logged by the caller.  It must never
 * reach the handle open, which destroys the handle on any replay failure.
 *
 * The line lengths of this comment are constrained by #872: some block shapes
 * make uncrustify rewrite the continuation stars.  Re-run ./tools/format-c
 * after editing it.
 *
 * A graph whose key does not validate is skipped by the caller before this
 * runs, so it is never probed and produces neither log line.  That is
 * deliberate: such a graph has no usable identity to name in a message.
 *
 * out_opened reports whether the store was opened at all, because the caller
 * cannot say the same thing about both outcomes.  A store that would not open
 * has told us nothing about any erasure: the graph may be DEGRADED or still
 * PROVISIONING, in which case no forget was ever recorded for it, and the
 * engine build about to run reports that state through its own channel.  Only
 * a store that opened has a ledger the reconciler could read. */
static wyrelog_error_t
reconcile_graph_forgets (wyl_policy_store_t *policy, const gchar *fact_root,
    const wyl_policy_fact_graph_info_t *graph_info, gboolean *out_opened,
    WylFactReplayJobContext *job_context)
{
  g_assert (out_opened != NULL);
  *out_opened = FALSE;
  if (policy == NULL || fact_root == NULL || fact_root[0] == '\0'
      || graph_info == NULL)
    return WYRELOG_E_INVALID;

  gsize pending = 0;
  wyrelog_error_t rc = probe_graph_forgets (policy, fact_root, graph_info,
          out_opened, &pending, job_context);
  /* Nothing pending, or we could not find out.  Either way no write lease is
   * taken: the overwhelmingly common boot has no outstanding erasure, and
   * taking an exclusive lease on every graph to discover that is what this
   * probe exists to avoid. */
  if (rc != WYRELOG_E_OK || pending == 0)
    return rc;

  /* Something is pending, so escalate.  The probe's store handle is already
   * closed -- it never leaves probe_graph_forgets -- so this open cannot
   * contend with it. */
  g_autoptr (wyl_fact_store_t) store = NULL;
  rc = job_context == NULL ? WYRELOG_E_OK
      : wyl_fact_replay_job_context_checkpoint (job_context);
  if (rc == WYRELOG_E_OK)
    rc = open_graph_store (policy, fact_root, graph_info, TRUE, NULL, NULL,
            wyl_fact_replay_job_context_get_resource_recorder (job_context),
            &store);
  /* NOT_FOUND is not benign here.  The probe just read this store, so a
   * resolver that now reports it missing is an anomaly, not a graph that was
   * never written, and reporting it as convergence would claim an erasure
   * completed that did not. */
  if (rc != WYRELOG_E_OK)
    return rc;
  /* No schema creation here: this runs for every graph at every boot.  A
   * store with no forget ledger has nothing pending, and the reconciler
   * reports that as success rather than as a missing-table error. */
  /* U2-1 threads the outcome out of the reconciler; U2-2 carries it into the
   * replay summary.  Discarded here so this unit stays one behavioural
   * change. */
  wyl_fact_forget_outcome_t outcome = { 0 };
  return wyl_fact_store_forget_reconcile (store, graph_info->tenant_id,
             graph_info->graph_id, NULL, NULL, &outcome);
}

wyrelog_error_t
wyl_fact_replay_policy_graphs (wyl_policy_store_t *policy,
    const gchar *fact_root, WylFactGraphRuntimeManager *runtime_manager,
    wyl_fact_replay_summary_t *out_summary)
{
  if (out_summary != NULL)
    memset (out_summary, 0, sizeof (*out_summary));
  if (policy == NULL || runtime_manager == NULL)
    return WYRELOG_E_INVALID;

  if (fact_root != NULL && fact_root[0] != '\0') {
    wyrelog_error_t rc = wyl_policy_store_bind_fact_root (policy, fact_root);
    if (rc != WYRELOG_E_OK)
      return rc;
  }

  g_autoptr (GPtrArray) specs =
      g_ptr_array_new_with_free_func (owned_graph_spec_free);
  wyrelog_error_t rc = wyl_policy_store_foreach_fact_graph (policy, NULL,
          collect_graph_spec, specs);
  if (rc != WYRELOG_E_OK)
    return rc;

  wyl_fact_replay_summary_t summary = { 0 };
  g_autoptr (GPtrArray) seen_keys = g_ptr_array_new ();
  for (guint i = 0; i < specs->len; i++) {
    OwnedGraphSpec *spec = g_ptr_array_index (specs, i);
    summary.graphs_seen++;
    if (!spec->key_valid) {
      summary.graphs_degraded++;
      continue;
    }
    /* CONVERGED, INCOMPLETE, or no verdict at all -- see the write below. */
    gboolean forget_probed = FALSE;
    gboolean forget_incomplete = FALSE;
    gboolean forget_attempted = FALSE;
    /* Hoisted so the tripwire below can report it: the rc is what separates a
     * lost lease race from a transient resource failure at probe time, and
     * those two produce an identical signal. */
    wyrelog_error_t forget_rc = WYRELOG_E_OK;
    if (fact_root != NULL && fact_root[0] != '\0') {
      forget_attempted = TRUE;
      gboolean opened = FALSE;
      forget_rc = reconcile_graph_forgets (policy, fact_root,
              &spec->info, &opened, NULL);
      forget_probed = forget_rc == WYRELOG_E_OK || opened;
      forget_incomplete = forget_rc != WYRELOG_E_OK && opened;
      if (forget_rc != WYRELOG_E_OK) {
        if (opened)
          summary.graphs_forget_reconcile_failed++;
        else
          summary.graphs_forget_probe_unavailable++;
        const gchar *tenant = spec->info.tenant_id != NULL
              ? spec->info.tenant_id : "(unset)";
        const gchar *graph = spec->info.graph_id != NULL
              ? spec->info.graph_id : "(unset)";
        /* The counter alone is not observable: the only in-product caller
         * passes a NULL summary.  An erasure that could not be converged must
         * not be silent, or the daemon comes up reporting ready with data it
         * promised to delete.  Say only what the outcome supports: a store
         * that never opened is not evidence that an erasure is outstanding,
         * and claiming otherwise on every boot of an unopenable graph would
         * bury the case that is. */
        if (opened)
          WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
              "a pending fact forget recorded for tenant %s graph %s could "
              "not be converged: rc=%d; that erasure is still incomplete",
              tenant, graph, (int) forget_rc);
        else
          WYL_LOG_WARN (WYL_LOG_SECTION_BOOT,
              "could not open the fact store of tenant %s graph %s to look "
              "for a pending forget: rc=%d", tenant, graph, (int) forget_rc);
      }
    }
    GraphBuildCtx build = {
      .policy = policy,
      .fact_root = fact_root,
      .info = &spec->info,
      .materialization_state =
          graph_materialization_state_or_unknown (policy, &spec->info),
    };
    wyrelog_error_t graph_rc = wyl_fact_graph_runtime_manager_refresh
          (runtime_manager, &spec->key, build_graph_engine, &build, NULL);
    if (graph_rc == WYRELOG_E_OK)
      summary.graphs_loaded++;
    else if (spec->info.sealed)
      /* The refusal is the point, not a failure.  build_graph_engine declines
       * a sealed graph before it opens anything, so this arm costs a hash
       * lookup and no file open -- and the refresh still runs because it is
       * the only thing that materializes the entry, which the admission write
       * below needs and which foreach_status needs to report the graph at
       * all. */
      summary.graphs_sealed++;
    else if (graph_rc == WYRELOG_E_NOT_FOUND)
      /* A provisioned graph with no materialized store is expected during
       * lazy startup; it is represented as EMPTY, not replay degradation. */
      ;
    else
      summary.graphs_degraded++;
    /* The forget probe and the engine builder open the same store with
     * byte-identical arguments, so a probe that could not open it while the
     * engine built fine is two identical opens disagreeing.  The bridge makes
     * that possible -- the reader guard takes LOCK_SH|LOCK_NB and can lose to
     * transient contention, the residual shape #870 left behind -- but a lost
     * lease is NOT the only cause.  Any transient resource failure that clears
     * between the two opens produces the identical signal, and EMFILE at probe
     * time is neither bridge-specific nor rare.  That is why the rc is
     * reported: a reader of this counter must be able to tell an exhausted
     * descriptor table from a lost race, because only one of the two is
     * evidence that the population #550 asks about exists.  Report it here,
     * where both outcomes are in hand.
     *
     * Not an assertion: boot must never abort on a graph.  And no status
     * verdict, because we do not know whether an erasure is outstanding --
     * the two opens disagreeing is itself the anomaly worth naming.
     *
     * This line is also the instrument that settles whether the racy window
     * is a population worth its own WylFactGraphForgetState value in #550.
     * If it is ever observed in the field, that population exists; until
     * then, nothing shows it does.
     *
     * forget_attempted is half of the condition, not padding around it.  The
     * state being reported is "the probe ran and was refused, while the engine
     * built", and forget_probed cannot express that on its own: it is FALSE
     * both when a probe was refused and when no probe was ever attempted,
     * which is the same conflation this issue removes one layer up.  Without
     * this term the line would read "the forget block established no verdict",
     * a weaker and different claim than the one above.  (It happens to be
     * inert today -- with no fact root the engine build fails for the same
     * missing root, so graph_rc is not OK either: seen=1 loaded=0 degraded=1.
     * That is why no test discriminates it, not a reason to drop it.) */
    if (forget_attempted && !forget_probed && graph_rc == WYRELOG_E_OK) {
      summary.graphs_forget_probe_disagreed++;
      WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
          "the fact store of tenant %s graph %s refused the forget probe "
          "with rc=%d but served the engine build moments later; the "
          "pending-erasure state of that graph was not established",
          spec->info.tenant_id != NULL ? spec->info.tenant_id : "(unset)",
          spec->info.graph_id != NULL ? spec->info.graph_id : "(unset)",
          (int) forget_rc);
    }
    /* After the refresh, never before it.  The setter does not create an
     * entry and refuses a tombstone, so a verdict written earlier is dropped
     * -- NOT_FOUND on a graph the runtime has not built yet, which is every
     * graph of a fresh daemon, or BUSY on one retired by an earlier replay --
     * and the refresh then publishes CONVERGED over it.  Either return from
     * this call means it has been moved to the wrong place.
     *
     * Written on both outcomes, because the CONVERGED zero is only honest if
     * success asserts it: a graph that converges on a later replay must clear
     * itself.  Not written when the store never opened, which is neither
     * outcome -- nothing was learned, and claiming convergence there would be
     * the over-report that #547 removed from the boot log.  Worse, it would
     * erase a standing verdict: a graph already INCOMPLETE whose store then
     * fails to open would be reported converged, which is this issue's own
     * defect arriving through the failure path.
     *
     * Argued, not proved, and the whole choice is unpinned rather than just
     * its reasoning: flipping this to write INCOMPLETE for an unprobed graph
     * passes the entire suite unchanged.  The reason is now stronger than it
     * was when this was written.  Since #869 U1 the forget probe and the
     * engine builder BOTH open read-only (probe_graph_forgets and
     * open_graph_engine_with_artifact_lease, which the builder reaches
     * directly), so they are the same call in every
     * configuration, not only off-bridge: a graph that could not be probed
     * also failed to build and is never mapped through the forget axis.  The
     * write-lease refusal that used to be the one observable state no longer
     * reaches this decision at all, because no write lease is taken unless
     * something is pending.  What remains is the LOCK_SH race the tripwire
     * above counts.  Do not read the green suite as agreement with this
     * decision.
     *
     * The residual this used to leave -- a bridge graph refused a write lease
     * keeping the CONVERGED zero and reporting ready over an unreconciled
     * ledger -- is closed by #869 U1 and no longer applies.  A write lease is
     * requested only after the read-only probe has counted a pending intent,
     * so a refusal now lands with the store opened: graphs_forget_reconcile_
     * failed, an ERROR that survives wyrelog_log_max_level=error, and
     * FORGET_INCOMPLETE.  Do not re-open #870 or #550 on the strength of the
     * older wording. */
    if (forget_probed)
      (void) wyl_fact_graph_runtime_manager_set_forget_state (runtime_manager,
          &spec->key, forget_incomplete ? WYL_FACT_GRAPH_FORGET_INCOMPLETE
          : WYL_FACT_GRAPH_FORGET_CONVERGED);
    /* Re-establish the runtime barrier from the durable bit.  Admission is
     * runtime-only state, so without this a restart reopens every graph the
     * policy store still calls sealed -- a seal survives a crash in policy and
     * not in the runtime.
     *
     * Written in BOTH directions on purpose.  Closing the sealed ones and
     * leaving the rest alone would strand, as permanently closed, any graph
     * unsealed out of band while the daemon was down; the axis has to be a
     * function of the durable bit, not a latch.
     *
         * One ordering is forced and proved: this must follow the refresh,
     * because close_admission deliberately mints no entry and would answer
     * NOT_FOUND for every graph on a fresh manager.  Deleting the refresh
     * fails the suite.
     *
     * A second is argued, not proved.  It must also follow set_forget_state,
     * which refuses an EVICTED entry -- so once the live seal evicts here, an
     * admission write placed ahead of it would leave the axis at its default
     * CONVERGED over an erasure that is still owed.  This loop does not evict,
     * so swapping the two blocks today changes nothing and the suite stays
     * green; verified by doing it.  Whoever adds the eviction owns making
     * that ordering falsifiable.
     *
     * A third an earlier draft claimed is not an ordering at all.  Being
     * before retire_unseen buys nothing: every key here is added to
     * seen_keys, so retirement skips it.
     *
     * The rc is discarded the way set_forget_state's is: NOT_FOUND cannot
     * happen because the refresh above created the entry, and BUSY means
     * shutdown raced the boot pass, which the caller learns from
     * retire_unseen. */
    if (spec->info.sealed) {
      (void) wyl_fact_graph_runtime_manager_close_admission (runtime_manager,
          &spec->key);
      /* Deliberately NOT evicted here.  At boot the sealed graph's refresh
       * already failed, so there is no engine to detach and the only thing an
       * eviction would change is DEGRADED -> EVICTED -- and EVICTED is the
       * one state fact_graph_runtime_status_cb skips, so the graph would
       * disappear from an operator's listing entirely and a query against it
       * would answer NOT_FOUND where it used to answer POLICY.  Trading a
       * wrong entry for a missing one is not an improvement.
       *
       * Eviction belongs to the live seal, where a published engine actually
       * exists to take away, and the sealed state has to arrive on the
       * reporting surface in the same change that starts producing it. */
    } else {
      (void) wyl_fact_graph_runtime_manager_open_admission (runtime_manager,
          &spec->key);
    }
    g_ptr_array_add (seen_keys, &spec->key);
  }
  rc = wyl_fact_graph_runtime_manager_retire_unseen (runtime_manager,
          (const WylFactGraphKey * const *) seen_keys->pdata, seen_keys->len);
  if (out_summary != NULL)
    *out_summary = summary;
  return rc;
}

typedef struct
{
  wyl_policy_store_t *policy;
  WylFactReplayPolicyProvider provider;
  const gchar *fact_root;
  WylFactGraphRuntimeManager *runtime_manager;
  OwnedGraphSpec *spec;
  wyl_fact_replay_summary_t summary;
} ScheduledPolicyGraphReplay;

static wyrelog_error_t
scheduled_policy_graph_replay (WylFactReplayJobContext *job_context,
    gpointer user_data)
{
  ScheduledPolicyGraphReplay *job = user_data;
  OwnedGraphSpec *spec = job->spec;
  job->summary.graphs_seen = 1;
  wyl_policy_store_t *policy = job->policy;
  wyrelog_error_t rc = WYRELOG_E_OK;
  if (job->provider.pin != NULL)
    rc = job->provider.pin (job->provider.user_data, &policy);
  if (rc != WYRELOG_E_OK) {
    job->summary.graphs_degraded = 1;
    return rc == WYRELOG_E_CANCELLED || rc == WYRELOG_E_TIMED_OUT
           || rc == WYRELOG_E_RESOURCE_LIMIT ? rc : WYRELOG_E_OK;
  }
#if defined(WYL_TEST_HANDLE_SEAMS)
  scheduled_start_test_hook_invoke (spec->info.tenant_id,
      spec->info.graph_id);
#endif

  /* Admission and the per-job deadline exist before this read transaction.
   * Copy one coherent graph policy view, then release SQLite before opening
   * DuckDB or entering runtime publication. */
  replay_policy_graph_snapshot_clear (&spec->policy_snapshot);
  rc = capture_replay_policy_graph_snapshot (policy, &spec->info,
          job_context, &spec->policy_snapshot);
  const wyl_policy_fact_graph_info_t *replay_info =
      spec->policy_snapshot.info_valid ? &spec->policy_snapshot.info : NULL;

  gboolean forget_probed = FALSE;
  gboolean forget_incomplete = FALSE;
  gboolean forget_attempted = FALSE;
  wyrelog_error_t forget_rc = WYRELOG_E_OK;
  if (rc == WYRELOG_E_OK && job->fact_root != NULL
      && job->fact_root[0] != '\0') {
    forget_attempted = TRUE;
    gboolean opened = FALSE;
    forget_rc = reconcile_graph_forgets (policy, job->fact_root,
            replay_info, &opened, job_context);
    forget_probed = forget_rc == WYRELOG_E_OK || opened;
    forget_incomplete = forget_rc != WYRELOG_E_OK && opened;
    if (forget_rc != WYRELOG_E_OK) {
      if (opened)
        job->summary.graphs_forget_reconcile_failed++;
      else
        job->summary.graphs_forget_probe_unavailable++;
      if (opened)
        WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
            "a pending fact forget recorded for tenant %s graph %s could "
            "not be converged: rc=%d; that erasure is still incomplete",
            replay_info->tenant_id, replay_info->graph_id, (int) forget_rc);
      else
        WYL_LOG_WARN (WYL_LOG_SECTION_BOOT,
            "could not open the fact store of tenant %s graph %s to look "
            "for a pending forget: rc=%d", spec->info.tenant_id,
            replay_info->graph_id, (int) forget_rc);
    }
  }

  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_replay_job_context_checkpoint (job_context);
  GraphBuildCtx build = {
    .policy = policy,
    .fact_root = job->fact_root,
    .info = replay_info,
    .policy_snapshot = &spec->policy_snapshot,
    .materialization_state = spec->policy_snapshot.materialization_state,
    .job_context = job_context,
  };
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_runtime_manager_refresh_checked
          (job->runtime_manager, &spec->key, build_graph_engine, &build,
            job_publish_check, job_context, NULL);

  if (rc == WYRELOG_E_OK)
    job->summary.graphs_loaded++;
  else if (replay_info != NULL && replay_info->sealed)
    job->summary.graphs_sealed++;
  else if (rc != WYRELOG_E_NOT_FOUND)
    job->summary.graphs_degraded++;

  if (forget_attempted && !forget_probed && rc == WYRELOG_E_OK) {
    job->summary.graphs_forget_probe_disagreed++;
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "the fact store of tenant %s graph %s refused the forget probe "
        "with rc=%d but served the engine build moments later; the "
        "pending-erasure state of that graph was not established",
        replay_info->tenant_id, replay_info->graph_id, (int) forget_rc);
  }
  if (forget_probed)
    (void) wyl_fact_graph_runtime_manager_set_forget_state
      (job->runtime_manager, &spec->key,
        forget_incomplete ? WYL_FACT_GRAPH_FORGET_INCOMPLETE
            : WYL_FACT_GRAPH_FORGET_CONVERGED);
  if (replay_info != NULL && replay_info->sealed)
    (void) wyl_fact_graph_runtime_manager_close_admission
      (job->runtime_manager, &spec->key);
  else if (replay_info != NULL)
    (void) wyl_fact_graph_runtime_manager_open_admission
      (job->runtime_manager, &spec->key);

  if (job->provider.unpin != NULL)
    job->provider.unpin (job->provider.user_data, policy);

  /* Per-graph replay failure is represented in runtime status and the boot
   * summary, just as the legacy startup loop did. Return budget outcomes so
   * scheduler metrics retain their exact cause; normalize other graph-local
   * degradation so one graph cannot abort daemon startup. */
  return rc == WYRELOG_E_CANCELLED || rc == WYRELOG_E_TIMED_OUT
         || rc == WYRELOG_E_RESOURCE_LIMIT ? rc : WYRELOG_E_OK;
}

static void
replay_summary_add (wyl_fact_replay_summary_t *total,
    const wyl_fact_replay_summary_t *part)
{
  total->graphs_seen += part->graphs_seen;
  total->graphs_loaded += part->graphs_loaded;
  total->graphs_degraded += part->graphs_degraded;
  total->graphs_sealed += part->graphs_sealed;
  total->graphs_forget_reconcile_failed +=
      part->graphs_forget_reconcile_failed;
  total->graphs_forget_probe_unavailable +=
      part->graphs_forget_probe_unavailable;
  total->graphs_forget_probe_disagreed +=
      part->graphs_forget_probe_disagreed;
}

static wyrelog_error_t
rejected_startup_replay (const WylFactGraphKey *key, WylEngine **out_engine,
    gpointer user_data)
{
  (void) key;
  (void) user_data;
  *out_engine = NULL;
  return WYRELOG_E_BUSY;
}

static void
complete_pending_startup_replay (GPtrArray *jobs, GPtrArray *futures,
    wyl_fact_replay_summary_t *summary)
{
  g_assert (jobs->len > 0 && jobs->len == futures->len);
  ScheduledPolicyGraphReplay *job = g_ptr_array_index (jobs, 0);
  (void) wyl_fact_replay_future_wait (g_ptr_array_index (futures, 0));
  replay_summary_add (summary, &job->summary);
  g_ptr_array_remove_index (futures, 0);
  g_ptr_array_remove_index (jobs, 0);
}

wyrelog_error_t
wyl_fact_replay_policy_graphs_scheduled (wyl_policy_store_t *policy,
    const gchar *fact_root, WylFactGraphRuntimeManager *runtime_manager,
    WylFactReplayScheduler *scheduler,
    const WylFactReplaySchedulerConfig *config,
    wyl_fact_replay_summary_t *out_summary)
{
  return wyl_fact_replay_policy_graphs_scheduled_with_provider (policy,
             fact_root, runtime_manager, scheduler, config, NULL,
             out_summary);
}

wyrelog_error_t
wyl_fact_replay_policy_graphs_scheduled_with_provider
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager,
    WylFactReplayScheduler *scheduler,
    const WylFactReplaySchedulerConfig *config,
    const WylFactReplayPolicyProvider *provider,
    wyl_fact_replay_summary_t *out_summary)
{
  if (out_summary != NULL)
    memset (out_summary, 0, sizeof *out_summary);
  if (policy == NULL || runtime_manager == NULL || scheduler == NULL
      || wyl_fact_replay_scheduler_config_validate (config) != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;

  if (fact_root != NULL && fact_root[0] != '\0') {
    wyrelog_error_t rc = wyl_policy_store_bind_fact_root (policy, fact_root);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  g_autoptr (GPtrArray) specs =
      g_ptr_array_new_with_free_func (owned_graph_spec_free);
  wyrelog_error_t rc = capture_replay_policy_snapshot (policy, specs);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (provider != NULL && provider->snapshot_complete != NULL)
    provider->snapshot_complete (provider->user_data);

  wyl_fact_replay_summary_t summary = { 0 };
  g_autoptr (GHashTable) tenant_queues = g_hash_table_new_full (g_str_hash,
          g_str_equal, NULL, (GDestroyNotify) g_queue_free);
  g_autoptr (GPtrArray) tenant_order = g_ptr_array_new ();
  for (guint i = 0; i < specs->len; i++) {
    OwnedGraphSpec *spec = g_ptr_array_index (specs, i);
    if (!spec->key_valid) {
      summary.graphs_seen++;
      summary.graphs_degraded++;
      continue;
    }
    GQueue *queue = g_hash_table_lookup (tenant_queues,
            spec->info.tenant_id);
    if (queue == NULL) {
      queue = g_queue_new ();
      g_hash_table_insert (tenant_queues, (gpointer) spec->info.tenant_id,
          queue);
      g_ptr_array_add (tenant_order, queue);
    }
    g_queue_push_tail (queue, spec);
  }
  g_autoptr (GPtrArray) seen_keys = g_ptr_array_new ();
  g_autoptr (GPtrArray) jobs = g_ptr_array_new_with_free_func (g_free);
  g_autoptr (GPtrArray) futures = g_ptr_array_new_with_free_func
        ((GDestroyNotify) wyl_fact_replay_future_unref);
  guint remaining = 0;
  for (guint i = 0; i < tenant_order->len; i++)
    remaining += ((GQueue *) g_ptr_array_index (tenant_order, i))->length;
  while (remaining > 0) {
    guint64 change_serial = wyl_fact_replay_scheduler_change_serial
          (scheduler);
    gboolean submitted = FALSE;
    for (guint i = 0; i < tenant_order->len; i++) {
      GQueue *queue = g_ptr_array_index (tenant_order, i);
      OwnedGraphSpec *spec = g_queue_peek_head (queue);
      if (spec == NULL)
        continue;
      ScheduledPolicyGraphReplay *job =
          g_new0 (ScheduledPolicyGraphReplay, 1);
      job->policy = policy;
      if (provider != NULL)
        job->provider = *provider;
      job->fact_root = fact_root;
      job->runtime_manager = runtime_manager;
      job->spec = spec;
      WylFactReplayFuture *future = NULL;
      rc = wyl_fact_replay_scheduler_submit (scheduler,
              spec->info.tenant_id, spec->info.graph_id, NULL,
              scheduled_policy_graph_replay, job, NULL, &future);
      if (rc == WYRELOG_E_BUSY) {
        g_free (job);
        continue;
      }
      g_assert_true (g_queue_pop_head (queue) == spec);
      remaining--;
      submitted = TRUE;
      if (rc != WYRELOG_E_OK) {
        summary.graphs_seen++;
        summary.graphs_degraded++;
        (void) wyl_fact_graph_runtime_manager_refresh (runtime_manager,
            &spec->key, rejected_startup_replay, NULL, NULL);
        g_ptr_array_add (seen_keys, &spec->key);
        g_free (job);
        rc = WYRELOG_E_OK;
        continue;
      }
      g_ptr_array_add (jobs, job);
      g_ptr_array_add (futures, future);
      g_ptr_array_add (seen_keys, &spec->key);
    }
    if (remaining > 0 && !submitted) {
      rc = wyl_fact_replay_scheduler_wait_for_change (scheduler,
              change_serial);
      if (rc != WYRELOG_E_OK) {
        for (guint i = 0; i < tenant_order->len; i++) {
          GQueue *queue = g_ptr_array_index (tenant_order, i);
          OwnedGraphSpec *spec = NULL;
          while ((spec = g_queue_pop_head (queue)) != NULL) {
            summary.graphs_seen++;
            summary.graphs_degraded++;
            (void) wyl_fact_graph_runtime_manager_refresh (runtime_manager,
                &spec->key, rejected_startup_replay, NULL, NULL);
            g_ptr_array_add (seen_keys, &spec->key);
            remaining--;
          }
        }
        rc = WYRELOG_E_OK;
      }
    }
  }
  while (futures->len > 0)
    complete_pending_startup_replay (jobs, futures, &summary);
  rc = wyl_fact_graph_runtime_manager_retire_unseen (runtime_manager,
          (const WylFactGraphKey * const *) seen_keys->pdata, seen_keys->len);
  if (out_summary != NULL)
    *out_summary = summary;
  return rc;
}

static wyrelog_error_t
refresh_graph_bounded_internal (wyl_policy_store_t *policy,
    const gchar *fact_root, const wyl_policy_fact_graph_info_t *graph_info,
    WylFactGraphRuntimeManager *runtime_manager,
    WylFactReplayJobContext *job_context,
    WylFactGraphRuntimeStatus *out_status)
{
  if (out_status != NULL)
    memset (out_status, 0, sizeof (*out_status));
  if (policy == NULL || graph_info == NULL || graph_info->tenant_id == NULL
      || graph_info->graph_id == NULL || runtime_manager == NULL)
    return WYRELOG_E_INVALID;

  if (fact_root != NULL && fact_root[0] != '\0') {
    wyrelog_error_t rc = wyl_policy_store_bind_fact_root (policy, fact_root);
    if (rc != WYRELOG_E_OK)
      return rc;
  }

  WylFactGraphKey key = { 0 };
  wyrelog_error_t rc = wyl_fact_graph_key_init (&key, graph_info->tenant_id,
          graph_info->graph_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  ReplayPolicyGraphSnapshot snapshot = { 0 };
  if (job_context != NULL) {
    rc = capture_replay_policy_graph_snapshot (policy, graph_info,
            job_context, &snapshot);
    if (rc != WYRELOG_E_OK) {
      wyl_fact_graph_key_clear (&key);
      return rc;
    }
  }

  /* Refresh ONLY this one key.  This deliberately never calls
   * retire_unseen or foreach-refresh: a targeted post-mutation refresh must
   * leave every sibling graph's runtime entry and generation untouched
   * (issue #546 isolation), and retiring on a one-element seen set would
   * detach all other entries. */
  GraphBuildCtx build = {
    .policy = policy,
    .fact_root = fact_root,
    .info = job_context == NULL ? graph_info : &snapshot.info,
    .policy_snapshot = job_context == NULL ? NULL : &snapshot,
    .materialization_state = job_context == NULL
        ? graph_materialization_state_or_unknown (policy, graph_info)
        : snapshot.materialization_state,
    .job_context = job_context,
  };
  rc = job_context == NULL
      ? wyl_fact_graph_runtime_manager_refresh (runtime_manager, &key,
          build_graph_engine, &build, out_status)
      : wyl_fact_graph_runtime_manager_refresh_checked (runtime_manager,
          &key, build_graph_engine, &build, job_publish_check, job_context,
          out_status);
  replay_policy_graph_snapshot_clear (&snapshot);
  wyl_fact_graph_key_clear (&key);
  return rc;
}

wyrelog_error_t
wyl_fact_replay_refresh_graph (wyl_policy_store_t *policy,
    const gchar *fact_root, const wyl_policy_fact_graph_info_t *graph_info,
    WylFactGraphRuntimeManager *runtime_manager,
    WylFactGraphRuntimeStatus *out_status)
{
  return refresh_graph_bounded_internal (policy, fact_root, graph_info,
             runtime_manager, NULL, out_status);
}

wyrelog_error_t
wyl_fact_replay_refresh_graph_bounded (wyl_policy_store_t *policy,
    const gchar *fact_root, const wyl_policy_fact_graph_info_t *graph_info,
    WylFactGraphRuntimeManager *runtime_manager,
    WylFactReplayJobContext *job_context,
    WylFactGraphRuntimeStatus *out_status)
{
  if (job_context == NULL)
    return WYRELOG_E_INVALID;
  return refresh_graph_bounded_internal (policy, fact_root, graph_info,
             runtime_manager, job_context, out_status);
}

static wyrelog_error_t
refresh_graph_publication_internal
  (wyl_policy_store_t *policy, const gchar *fact_root,
    const wyl_policy_fact_graph_info_t *graph_info,
    WylFactGraphRuntimePublication *publication,
    WylFactArtifactNamespace *artifact_namespace,
    WylFactArtifactMutationLease *artifact_lease,
    WylFactReplayJobContext *job_context,
    WylFactGraphRuntimeStatus *out_status)
{
  if (out_status != NULL)
    memset (out_status, 0, sizeof *out_status);
  if (policy == NULL || graph_info == NULL || graph_info->tenant_id == NULL
      || graph_info->graph_id == NULL || publication == NULL)
    return WYRELOG_E_INVALID;
  if (fact_root != NULL && fact_root[0] != '\0') {
    wyrelog_error_t rc = wyl_policy_store_bind_fact_root (policy, fact_root);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  ReplayPolicyGraphSnapshot snapshot = { 0 };
  wyrelog_error_t rc = WYRELOG_E_OK;
  if (job_context != NULL) {
    rc = capture_replay_policy_graph_snapshot (policy, graph_info,
            job_context, &snapshot);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  GraphBuildCtx build = {
    .policy = policy,
    .fact_root = fact_root,
    .info = job_context == NULL ? graph_info : &snapshot.info,
    .policy_snapshot = job_context == NULL ? NULL : &snapshot,
    .materialization_state = job_context == NULL
        ? graph_materialization_state_or_unknown (policy, graph_info)
        : snapshot.materialization_state,
    .artifact_namespace = artifact_namespace,
    .artifact_lease = artifact_lease,
    .job_context = job_context,
  };
  rc = job_context == NULL
      ? wyl_fact_graph_runtime_publication_refresh
        (publication, build_graph_engine, &build, out_status)
      : wyl_fact_graph_runtime_publication_refresh_checked
        (publication, build_graph_engine, &build, job_publish_check,
          job_context, out_status);
  replay_policy_graph_snapshot_clear (&snapshot);
  return rc;
}

wyrelog_error_t
wyl_fact_replay_refresh_graph_publication
  (wyl_policy_store_t *policy, const gchar *fact_root,
    const wyl_policy_fact_graph_info_t *graph_info,
    WylFactGraphRuntimePublication *publication,
    WylFactArtifactNamespace *artifact_namespace,
    WylFactArtifactMutationLease *artifact_lease,
    WylFactGraphRuntimeStatus *out_status)
{
  return refresh_graph_publication_internal (policy, fact_root, graph_info,
             publication, artifact_namespace, artifact_lease, NULL,
             out_status);
}

wyrelog_error_t
wyl_fact_replay_refresh_graph_publication_bounded
  (wyl_policy_store_t *policy, const gchar *fact_root,
    const wyl_policy_fact_graph_info_t *graph_info,
    WylFactGraphRuntimePublication *publication,
    WylFactArtifactNamespace *artifact_namespace,
    WylFactArtifactMutationLease *artifact_lease,
    WylFactReplayJobContext *job_context,
    WylFactGraphRuntimeStatus *out_status)
{
  if (job_context == NULL)
    return WYRELOG_E_INVALID;
  return refresh_graph_publication_internal (policy, fact_root, graph_info,
             publication, artifact_namespace, artifact_lease, job_context,
             out_status);
}

static wyrelog_error_t
refresh_graph_closed_internal (wyl_policy_store_t *policy,
    const gchar *fact_root, const wyl_policy_fact_graph_info_t *graph_info,
    WylFactGraphRuntimeManager *runtime_manager,
    WylFactArtifactNamespace *artifact_namespace,
    WylFactArtifactMutationLease *artifact_lease,
    WylFactGraphRuntimeStatus *out_status)
{
  if (out_status != NULL)
    memset (out_status, 0, sizeof *out_status);
  if (policy == NULL || graph_info == NULL || graph_info->tenant_id == NULL
      || graph_info->graph_id == NULL || runtime_manager == NULL)
    return WYRELOG_E_INVALID;

  if (fact_root != NULL && fact_root[0] != '\0') {
    wyrelog_error_t rc = wyl_policy_store_bind_fact_root (policy, fact_root);
    if (rc != WYRELOG_E_OK)
      return rc;
  }

  WylFactGraphKey key = { 0 };
  wyrelog_error_t rc = wyl_fact_graph_key_init (&key, graph_info->tenant_id,
          graph_info->graph_id);
  if (rc != WYRELOG_E_OK)
    return rc;
  GraphBuildCtx build = {
    .policy = policy,
    .fact_root = fact_root,
    .info = graph_info,
    .materialization_state =
        graph_materialization_state_or_unknown (policy, graph_info),
    .artifact_namespace = artifact_namespace,
    .artifact_lease = artifact_lease,
  };
  rc = wyl_fact_graph_runtime_manager_refresh_closed (runtime_manager, &key,
          build_graph_engine, &build, out_status);
  wyl_fact_graph_key_clear (&key);
  return rc;
}

wyrelog_error_t
wyl_fact_replay_publish_graph_closed_and_open
  (wyl_policy_store_t *policy, const gchar *fact_root,
    const wyl_policy_fact_graph_info_t *graph_info,
    WylFactGraphRuntimeManager *runtime_manager,
    WylFactGraphRuntimeStatus *out_status)
{
  if (out_status != NULL)
    memset (out_status, 0, sizeof *out_status);
  if (policy == NULL || graph_info == NULL || graph_info->tenant_id == NULL
      || graph_info->graph_id == NULL || runtime_manager == NULL)
    return WYRELOG_E_INVALID;
  if (fact_root != NULL && fact_root[0] != '\0') {
    wyrelog_error_t rc = wyl_policy_store_bind_fact_root (policy, fact_root);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  WylFactGraphKey key = { 0 };
  wyrelog_error_t rc = wyl_fact_graph_key_init (&key, graph_info->tenant_id,
          graph_info->graph_id);
  if (rc != WYRELOG_E_OK)
    return rc;
  GraphBuildCtx build = {
    .policy = policy,
    .fact_root = fact_root,
    .info = graph_info,
    .materialization_state =
        graph_materialization_state_or_unknown (policy, graph_info),
  };
  rc = wyl_fact_graph_runtime_manager_publish_closed_and_open
        (runtime_manager, &key, build_graph_engine, &build, out_status);
  wyl_fact_graph_key_clear (&key);
  return rc;
}

wyrelog_error_t
wyl_fact_replay_refresh_graph_closed (wyl_policy_store_t *policy,
    const gchar *fact_root, const wyl_policy_fact_graph_info_t *graph_info,
    WylFactGraphRuntimeManager *runtime_manager,
    WylFactGraphRuntimeStatus *out_status)
{
  return refresh_graph_closed_internal (policy, fact_root, graph_info,
             runtime_manager, NULL, NULL, out_status);
}

wyrelog_error_t
wyl_fact_replay_refresh_graph_closed_with_artifact_lease
  (wyl_policy_store_t *policy, const gchar *fact_root,
    const wyl_policy_fact_graph_info_t *graph_info,
    WylFactGraphRuntimeManager *runtime_manager,
    WylFactArtifactNamespace *artifact_namespace,
    WylFactArtifactMutationLease *artifact_lease,
    WylFactGraphRuntimeStatus *out_status)
{
  if (artifact_namespace == NULL || artifact_lease == NULL)
    return WYRELOG_E_INVALID;
  return refresh_graph_closed_internal (policy, fact_root, graph_info,
             runtime_manager, artifact_namespace, artifact_lease, out_status);
}

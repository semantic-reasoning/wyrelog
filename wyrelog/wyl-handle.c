/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

#include <string.h>

#include "wyrelog/engine.h"
#include "wyl-fsm-principal-private.h"
#include "wyl-fsm-session-private.h"
#include "wyl-handle-private.h"
#include "wyl-id-private.h"
#include "wyl-log-private.h"
#include "wyl-permission-scope-private.h"
#include "policy/store-private.h"

#ifdef WYL_HAS_AUDIT
#include "audit/conn-private.h"
#endif

struct _WylHandle
{
  GObject parent_instance;
  wyl_id_t id;
  gint64 created_at_us;
  WylEngine *read_engine;
  WylEngine *delta_engine;
  GHashTable *engine_symbols_by_id;
  gchar *template_dir;
  WylDeltaCallback delta_callback;
  gpointer delta_callback_user_data;
  wyl_policy_store_t *policy_store;
  gboolean login_skip_mfa_allowed;
#ifdef WYL_HAS_AUDIT
  wyl_audit_conn_t *audit_conn;
#endif
};

G_DEFINE_FINAL_TYPE (WylHandle, wyl_handle, G_TYPE_OBJECT);

static void
wyl_handle_finalize (GObject *object)
{
  WylHandle *self = WYL_HANDLE (object);

  g_clear_object (&self->read_engine);
  g_clear_object (&self->delta_engine);
  g_clear_pointer (&self->engine_symbols_by_id, g_hash_table_unref);
  g_clear_pointer (&self->template_dir, g_free);
  g_clear_pointer (&self->policy_store, wyl_policy_store_close);
#ifdef WYL_HAS_AUDIT
  /* NULL-safe: if wyl_shutdown already closed the conn the pointer
   * was reset to NULL there; otherwise this is the only close site
   * and the audit log file (if any) is released here. */
  g_clear_pointer (&self->audit_conn, wyl_audit_conn_close);
#endif

  G_OBJECT_CLASS (wyl_handle_parent_class)->finalize (object);
}

static void
wyl_handle_class_init (WylHandleClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = wyl_handle_finalize;
}

static void
wyl_handle_init (WylHandle *self)
{
  /* Stamp the handle with a fresh id and timestamp at construct time
   * so log lines, audit events, and metrics emitted by the daemon can
   * be correlated back to a specific embedding instance even when a
   * process holds multiple handles. Failure to mint an id is fatal:
   * a zero-id handle would collapse correlation, so abort rather than
   * ship a partially-initialised object. */
  if (wyl_id_new (&self->id) != WYRELOG_E_OK)
    g_error ("wyl_handle_init: failed to mint identifier");
  self->created_at_us = g_get_real_time ();
  self->engine_symbols_by_id =
      g_hash_table_new_full (g_int64_hash, g_int64_equal, g_free, g_free);
}

static wyrelog_error_t
wyl_handle_seed_perm_arm_rules (WylHandle *self)
{
  for (gsize i = 0; i < wyl_perm_arm_rule_count (); i++) {
    gint64 row[2];
    wyrelog_error_t rc = wyl_handle_intern_engine_symbol (self,
        wyl_perm_arm_rule_perm_id (i), &row[0]);
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyl_handle_intern_engine_symbol (self, "_v0_deferred", &row[1]);
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyl_handle_engine_insert (self, "perm_arm_rule", row, 2);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
wyl_handle_seed_session_active_states (WylHandle *self)
{
  static const gchar *states[] = {
    "active",
    "elevated",
  };

  for (gsize i = 0; i < G_N_ELEMENTS (states); i++) {
    gint64 row[1];
    wyrelog_error_t rc =
        wyl_handle_intern_engine_symbol (self, states[i], &row[0]);
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyl_handle_engine_insert (self, "session_active", row, 1);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
wyl_handle_seed_principal_transitions (WylHandle *self)
{
  gsize n = 0;
  const wyl_principal_transition_t *table = wyl_fsm_principal_table (&n);

  /* The .dl facts keep the source catalogue readable; this runtime seed makes
   * the same catalogue available to wirelog snapshots and derived facts. */
  for (gsize i = 0; i < n; i++) {
    gint64 row[3];
    const gchar *from_name = wyl_principal_state_name (table[i].from);
    const gchar *event_name = wyl_principal_event_name (table[i].event);
    const gchar *to_name = wyl_principal_state_name (table[i].to);
    if (from_name == NULL || event_name == NULL || to_name == NULL)
      return WYRELOG_E_INTERNAL;

    wyrelog_error_t rc =
        wyl_handle_intern_engine_symbol (self, from_name, &row[0]);
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyl_handle_intern_engine_symbol (self, event_name, &row[1]);
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyl_handle_intern_engine_symbol (self, to_name, &row[2]);
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyl_handle_engine_insert (self, "principal_transition", row, 3);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
wyl_handle_seed_session_transitions (WylHandle *self)
{
  gsize n = 0;
  const wyl_session_transition_t *table = wyl_fsm_session_table (&n);

  for (gsize i = 0; i < n; i++) {
    gint64 row[3];
    const gchar *from_name = wyl_session_state_name (table[i].from);
    const gchar *event_name = wyl_session_event_name (table[i].event);
    const gchar *to_name = wyl_session_state_name (table[i].to);
    if (from_name == NULL || event_name == NULL || to_name == NULL)
      return WYRELOG_E_INTERNAL;

    wyrelog_error_t rc =
        wyl_handle_intern_engine_symbol (self, from_name, &row[0]);
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyl_handle_intern_engine_symbol (self, event_name, &row[1]);
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyl_handle_intern_engine_symbol (self, to_name, &row[2]);
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyl_handle_engine_insert (self, "session_transition", row, 3);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_init (const gchar *config_path, WylHandle **out_handle)
{
  /* Eagerly initialise the log subsystem before any other library code
   * runs so that log sites in boot phases see the correct thresholds
   * and file sink from the very first message. */
  wyl_log_internal_reconfigure ();

  if (out_handle == NULL)
    return WYRELOG_E_INVALID;
  *out_handle = NULL;

  WylHandle *self = g_object_new (WYL_TYPE_HANDLE, NULL);

  wyrelog_error_t rc = wyl_policy_store_open (NULL, &self->policy_store);
  if (rc != WYRELOG_E_OK) {
    g_object_unref (self);
    return rc;
  }
  rc = wyl_policy_store_create_schema (self->policy_store);
  if (rc != WYRELOG_E_OK) {
    g_object_unref (self);
    return rc;
  }

  if (config_path != NULL) {
    rc = wyl_handle_open_engine_pair (self, config_path);
    if (rc != WYRELOG_E_OK) {
      g_object_unref (self);
      return rc;
    }
  }
#ifdef WYL_HAS_AUDIT
  /* Open an in-memory audit database and create the audit_events
   * schema. Audit persistence is not wired to config_path yet. */
  rc = wyl_audit_conn_open (NULL, &self->audit_conn);
  if (rc != WYRELOG_E_OK) {
    g_object_unref (self);
    return rc;
  }
  rc = wyl_audit_conn_create_schema (self->audit_conn);
  if (rc != WYRELOG_E_OK) {
    g_object_unref (self);
    return rc;
  }
  rc = wyl_handle_load_policy_store_audit_events (self);
  if (rc != WYRELOG_E_OK) {
    g_object_unref (self);
    return rc;
  }
#endif

  *out_handle = self;
  return WYRELOG_E_OK;
}

void
wyl_shutdown (WylHandle *handle)
{
  if (handle == NULL)
    return;

#ifdef WYL_HAS_AUDIT
  /* Close the audit log before tearing down so any pending writers
   * see the close in deterministic order. finalize is NULL-safe and
   * will not double-close. */
  g_clear_pointer (&handle->audit_conn, wyl_audit_conn_close);
#endif
  g_clear_pointer (&handle->policy_store, wyl_policy_store_close);
  g_clear_object (&handle->read_engine);
  g_clear_object (&handle->delta_engine);
  g_clear_pointer (&handle->template_dir, g_free);
  g_object_set_qdata (G_OBJECT (handle),
      wyl_handle_engine_remove_fault_once_quark (), NULL);
  g_hash_table_remove_all (handle->engine_symbols_by_id);
}

gchar *
wyl_handle_dup_id_string (const WylHandle *self)
{
  gchar buf[WYL_ID_STRING_BUF];

  g_return_val_if_fail (WYL_IS_HANDLE (self), NULL);

  if (wyl_id_format (&self->id, buf, sizeof buf) != WYRELOG_E_OK)
    return NULL;
  return g_strdup (buf);
}

gint64
wyl_handle_get_created_at_us (const WylHandle *self)
{
  g_return_val_if_fail (WYL_IS_HANDLE (self), -1);
  return self->created_at_us;
}

#ifdef WYL_HAS_AUDIT
wyl_audit_conn_t *
wyl_handle_get_audit_conn (WylHandle *self)
{
  g_return_val_if_fail (WYL_IS_HANDLE (self), NULL);
  return self->audit_conn;
}

static wyrelog_error_t
insert_policy_store_audit_event (const gchar *id, gint64 created_at_us,
    const gchar *subject_id, const gchar *action, const gchar *resource_id,
    const gchar *deny_reason, const gchar *deny_origin,
    wyl_decision_t decision, gpointer user_data)
{
  WylHandle *self = user_data;

  return wyl_audit_conn_insert_event (self->audit_conn, id, created_at_us,
      subject_id, action, resource_id, deny_reason, deny_origin, decision);
}

wyrelog_error_t
wyl_handle_load_policy_store_audit_events (WylHandle *self)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (self->policy_store == NULL || self->audit_conn == NULL)
    return WYRELOG_E_INVALID;

  duckdb_connection conn = wyl_audit_conn_get_connection (self->audit_conn);
  duckdb_result result;
  memset (&result, 0, sizeof (result));

  if (duckdb_query (conn, "BEGIN TRANSACTION;", &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_result (&result);

  wyrelog_error_t rc = wyl_policy_store_foreach_audit_event (self->policy_store,
      insert_policy_store_audit_event, self);
  if (rc != WYRELOG_E_OK) {
    memset (&result, 0, sizeof (result));
    duckdb_query (conn, "ROLLBACK;", &result);
    duckdb_destroy_result (&result);
    return rc;
  }

  memset (&result, 0, sizeof (result));
  if (duckdb_query (conn, "COMMIT;", &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    memset (&result, 0, sizeof (result));
    duckdb_query (conn, "ROLLBACK;", &result);
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}
#endif

wyl_policy_store_t *
wyl_handle_get_policy_store (WylHandle *self)
{
  g_return_val_if_fail (WYL_IS_HANDLE (self), NULL);
  return self->policy_store;
}

void
wyl_handle_set_login_skip_mfa_allowed (WylHandle *self, gboolean allowed)
{
  g_return_if_fail (WYL_IS_HANDLE (self));
  self->login_skip_mfa_allowed = allowed;
}

gboolean
wyl_handle_get_login_skip_mfa_allowed (WylHandle *self)
{
  g_return_val_if_fail (WYL_IS_HANDLE (self), FALSE);
  if (self->login_skip_mfa_allowed)
    return TRUE;

  g_autofree gchar *deployment_mode = NULL;
  if (wyl_policy_store_get_deployment_mode (self->policy_store,
          &deployment_mode) != WYRELOG_E_OK)
    return FALSE;
  return g_strcmp0 (deployment_mode, "production") != 0;
}

static GHashTable *
new_engine_symbol_map (void)
{
  return g_hash_table_new_full (g_int64_hash, g_int64_equal, g_free, g_free);
}

static wyrelog_error_t
load_current_engine_pair (WylHandle *self)
{
  wyrelog_error_t rc = wyl_handle_seed_perm_arm_rules (self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_seed_session_active_states (self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_seed_principal_transitions (self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_seed_session_transitions (self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_load_policy_store_role_permissions (self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_load_policy_store_role_memberships (self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_load_policy_store_direct_permissions (self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_load_policy_store_principal_states (self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_load_policy_store_principal_events (self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_load_policy_store_session_states (self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_load_policy_store_session_events (self);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_load_policy_store_audit_facts (self);
}

static wyrelog_error_t
replace_engine_pair (WylHandle *self, const gchar *template_dir)
{
  WylEngine *old_read_engine = self->read_engine;
  WylEngine *old_delta_engine = self->delta_engine;
  GHashTable *old_symbols = self->engine_symbols_by_id;
  gchar *old_template_dir = self->template_dir;

  WylEngine *new_read_engine = NULL;
  wyrelog_error_t rc = wyl_engine_open (template_dir, 1, &new_read_engine);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylEngine *new_delta_engine = NULL;
  rc = wyl_engine_open (template_dir, 1, &new_delta_engine);
  if (rc != WYRELOG_E_OK) {
    g_object_unref (new_read_engine);
    return rc;
  }

  self->read_engine = new_read_engine;
  self->delta_engine = new_delta_engine;
  self->engine_symbols_by_id = new_engine_symbol_map ();
  self->template_dir = g_strdup (template_dir);

  rc = load_current_engine_pair (self);
  if (rc != WYRELOG_E_OK) {
    g_clear_object (&self->read_engine);
    g_clear_object (&self->delta_engine);
    g_clear_pointer (&self->engine_symbols_by_id, g_hash_table_unref);
    g_clear_pointer (&self->template_dir, g_free);
    self->read_engine = old_read_engine;
    self->delta_engine = old_delta_engine;
    self->engine_symbols_by_id = old_symbols;
    self->template_dir = old_template_dir;
    return rc;
  }
  if (self->delta_callback != NULL) {
    rc = wyl_engine_set_delta_callback (self->delta_engine,
        self->delta_callback, self->delta_callback_user_data);
    if (rc != WYRELOG_E_OK) {
      g_clear_object (&self->read_engine);
      g_clear_object (&self->delta_engine);
      g_clear_pointer (&self->engine_symbols_by_id, g_hash_table_unref);
      g_clear_pointer (&self->template_dir, g_free);
      self->read_engine = old_read_engine;
      self->delta_engine = old_delta_engine;
      self->engine_symbols_by_id = old_symbols;
      self->template_dir = old_template_dir;
      return rc;
    }
  }

  g_clear_object (&old_read_engine);
  g_clear_object (&old_delta_engine);
  if (old_symbols != NULL)
    g_hash_table_unref (old_symbols);
  g_free (old_template_dir);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_handle_open_engine_pair (WylHandle *self, const gchar *template_dir)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (template_dir == NULL)
    return WYRELOG_E_INVALID;
  if (self->read_engine != NULL || self->delta_engine != NULL)
    return WYRELOG_E_INVALID;

  return replace_engine_pair (self, template_dir);
}

wyrelog_error_t
wyl_handle_reload_engine_pair (WylHandle *self)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (self->template_dir == NULL)
    return WYRELOG_E_INVALID;

  g_autofree gchar *template_dir = g_strdup (self->template_dir);
  return replace_engine_pair (self, template_dir);
}

wyrelog_error_t
wyl_handle_intern_engine_symbol (WylHandle *self, const gchar *symbol,
    gint64 *out_id)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (symbol == NULL || out_id == NULL)
    return WYRELOG_E_INVALID;
  if (self->read_engine == NULL || self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  gint64 read_id = -1;
  wyrelog_error_t rc =
      wyl_engine_intern_symbol (self->read_engine, symbol, &read_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  gint64 delta_id = -1;
  rc = wyl_engine_intern_symbol (self->delta_engine, symbol, &delta_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  if (read_id != delta_id)
    return WYRELOG_E_INTERNAL;

  gint64 *key = g_new (gint64, 1);
  *key = read_id;
  g_hash_table_replace (self->engine_symbols_by_id, key, g_strdup (symbol));

  *out_id = read_id;
  return WYRELOG_E_OK;
}

gchar *
wyl_handle_dup_engine_symbol (WylHandle *self, gint64 id)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return NULL;
  if (self->engine_symbols_by_id == NULL)
    return NULL;

  const gchar *symbol = g_hash_table_lookup (self->engine_symbols_by_id, &id);
  if (symbol == NULL)
    return NULL;
  return g_strdup (symbol);
}

static gboolean
relation_fans_out_to_delta (const gchar *relation)
{
  return g_strcmp0 (relation, "member_of") == 0
      || g_strcmp0 (relation, "principal_transition") == 0
      || g_strcmp0 (relation, "session_transition") == 0
      || g_strcmp0 (relation, "principal_event") == 0
      || g_strcmp0 (relation, "session_event") == 0;
}

wyrelog_error_t
wyl_handle_engine_insert (WylHandle *self, const gchar *relation,
    const gint64 *row, gsize ncols)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (self->read_engine == NULL || self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  WylHandleEngineInsertFaultOnce *fault = g_object_get_qdata (G_OBJECT (self),
      wyl_handle_engine_insert_fault_once_quark ());
  if (fault != NULL && g_strcmp0 (fault->relation, relation) == 0) {
    wyrelog_error_t fault_rc = fault->rc;
    g_object_steal_qdata (G_OBJECT (self),
        wyl_handle_engine_insert_fault_once_quark ());
    wyl_handle_engine_fault_once_free (fault);
    return fault_rc;
  }

  wyrelog_error_t rc =
      wyl_engine_insert (self->read_engine, relation, row, ncols);
  if (rc != WYRELOG_E_OK)
    return rc;

  if (!relation_fans_out_to_delta (relation))
    return WYRELOG_E_OK;
  rc = wyl_engine_insert (self->delta_engine, relation, row, ncols);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_engine_step (self->delta_engine);
}

wyrelog_error_t
wyl_handle_engine_remove (WylHandle *self, const gchar *relation,
    const gint64 *row, gsize ncols)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (self->read_engine == NULL || self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  WylHandleEngineRemoveFaultOnce *fault = g_object_get_qdata (G_OBJECT (self),
      wyl_handle_engine_remove_fault_once_quark ());
  gboolean fault_matches =
      fault != NULL && g_strcmp0 (fault->relation, relation) == 0;
  wyrelog_error_t fault_rc = fault != NULL ? fault->rc : WYRELOG_E_OK;
  if (fault_matches) {
    g_object_steal_qdata (G_OBJECT (self),
        wyl_handle_engine_remove_fault_once_quark ());
    wyl_handle_engine_remove_fault_once_free (fault);
  }

  wyrelog_error_t rc =
      wyl_engine_remove (self->read_engine, relation, row, ncols);
  if (rc != WYRELOG_E_OK)
    return rc;

  if (!relation_fans_out_to_delta (relation))
    return fault_matches ? fault_rc : WYRELOG_E_OK;
  rc = wyl_engine_remove (self->delta_engine, relation, row, ncols);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_engine_step (self->delta_engine);
  if (rc != WYRELOG_E_OK)
    return rc;
  return fault_matches ? fault_rc : WYRELOG_E_OK;
}

wyrelog_error_t
wyl_handle_engine_step_delta (WylHandle *self)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  return wyl_engine_step (self->delta_engine);
}

wyrelog_error_t
wyl_handle_engine_set_delta_callback (WylHandle *self, WylDeltaCallback cb,
    gpointer user_data)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc =
      wyl_engine_set_delta_callback (self->delta_engine, cb, user_data);
  if (rc != WYRELOG_E_OK)
    return rc;

  self->delta_callback = cb;
  self->delta_callback_user_data = user_data;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
insert_policy_store_role_permission (const gchar *role_id,
    const gchar *perm_id, gpointer user_data)
{
  WylHandle *self = user_data;
  gint64 row[2];

  wyrelog_error_t rc = wyl_handle_intern_engine_symbol (self, role_id, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (self, perm_id, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (self, "role_permission", row, 2);
}

wyrelog_error_t
wyl_handle_load_policy_store_role_permissions (WylHandle *self)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (self->policy_store == NULL || self->read_engine == NULL
      || self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  return wyl_policy_store_foreach_role_permission (self->policy_store,
      insert_policy_store_role_permission, self);
}

static wyrelog_error_t
insert_policy_store_role_membership (const gchar *subject_id,
    const gchar *role_id, const gchar *scope, gpointer user_data)
{
  WylHandle *self = user_data;
  gint64 row[3];

  wyrelog_error_t rc =
      wyl_handle_intern_engine_symbol (self, subject_id, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (self, role_id, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (self, scope, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (self, "member_of", row, 3);
}

wyrelog_error_t
wyl_handle_load_policy_store_role_memberships (WylHandle *self)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (self->policy_store == NULL || self->read_engine == NULL
      || self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  return wyl_policy_store_foreach_role_membership (self->policy_store,
      insert_policy_store_role_membership, self);
}

static wyrelog_error_t
insert_policy_store_direct_permission (const gchar *subject_id,
    const gchar *perm_id, const gchar *scope, gpointer user_data)
{
  WylHandle *self = user_data;
  gint64 row[3];
  gint64 state_row[4];

  wyrelog_error_t rc =
      wyl_handle_intern_engine_symbol (self, subject_id, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (self, perm_id, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (self, scope, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;

  state_row[0] = row[0];
  state_row[1] = row[1];
  state_row[2] = row[2];
  rc = wyl_handle_intern_engine_symbol (self, "armed", &state_row[3]);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = wyl_handle_engine_insert (self, "direct_permission", row, 3);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (self, "perm_state", state_row, 4);
}

wyrelog_error_t
wyl_handle_load_policy_store_direct_permissions (WylHandle *self)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (self->policy_store == NULL || self->read_engine == NULL
      || self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  return wyl_policy_store_foreach_direct_permission (self->policy_store,
      insert_policy_store_direct_permission, self);
}

static wyrelog_error_t
insert_policy_store_principal_state (const gchar *subject_id,
    const gchar *state, gpointer user_data)
{
  WylHandle *self = user_data;
  gint64 row[2];

  wyrelog_error_t rc =
      wyl_handle_intern_engine_symbol (self, subject_id, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (self, state, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (self, "principal_state", row, 2);
}

wyrelog_error_t
wyl_handle_load_policy_store_principal_states (WylHandle *self)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (self->policy_store == NULL || self->read_engine == NULL
      || self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  return wyl_policy_store_foreach_principal_state (self->policy_store,
      insert_policy_store_principal_state, self);
}

static wyrelog_error_t
insert_policy_store_principal_event (gint64 event_id, const gchar *subject_id,
    const gchar *event, const gchar *from_state, const gchar *to_state,
    gpointer user_data)
{
  WylHandle *self = user_data;
  gint64 row[5];
  wyl_principal_state_t from = wyl_principal_state_from_name (from_state);
  wyl_principal_event_t ev = wyl_principal_event_from_name (event);
  wyl_principal_state_t to = wyl_principal_state_from_name (to_state);

  if (from == WYL_PRINCIPAL_STATE_LAST_ || ev == WYL_PRINCIPAL_EVENT_LAST_
      || to == WYL_PRINCIPAL_STATE_LAST_)
    return WYRELOG_E_POLICY;
  wyl_principal_state_t validated = WYL_PRINCIPAL_STATE_LAST_;
  wyrelog_error_t rc = wyl_fsm_principal_step (from, ev, &validated);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (validated != to)
    return WYRELOG_E_POLICY;

  row[0] = event_id;
  rc = wyl_handle_intern_engine_symbol (self, subject_id, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (self, event, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (self, from_state, &row[3]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (self, to_state, &row[4]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (self, "principal_event", row, 5);
}

wyrelog_error_t
wyl_handle_load_policy_store_principal_events (WylHandle *self)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (self->policy_store == NULL || self->read_engine == NULL
      || self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  return wyl_policy_store_foreach_principal_event (self->policy_store,
      insert_policy_store_principal_event, self);
}

static wyrelog_error_t
insert_policy_store_session_state (const gchar *session_id,
    const gchar *state, gpointer user_data)
{
  WylHandle *self = user_data;
  gint64 row[2];

  wyrelog_error_t rc =
      wyl_handle_intern_engine_symbol (self, session_id, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (self, state, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (self, "session_state", row, 2);
}

wyrelog_error_t
wyl_handle_load_policy_store_session_states (WylHandle *self)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (self->policy_store == NULL || self->read_engine == NULL
      || self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  return wyl_policy_store_foreach_session_state (self->policy_store,
      insert_policy_store_session_state, self);
}

static wyrelog_error_t
insert_policy_store_session_event (gint64 event_id, const gchar *session_id,
    const gchar *event, const gchar *from_state, const gchar *to_state,
    gpointer user_data)
{
  WylHandle *self = user_data;
  gint64 row[5];
  wyl_session_state_t from = wyl_session_state_from_name (from_state);
  wyl_session_event_t ev = wyl_session_event_from_name (event);
  wyl_session_state_t to = wyl_session_state_from_name (to_state);

  if (from == WYL_SESSION_STATE_LAST_ || ev == WYL_SESSION_EVENT_LAST_
      || to == WYL_SESSION_STATE_LAST_)
    return WYRELOG_E_POLICY;
  wyl_session_state_t validated = WYL_SESSION_STATE_LAST_;
  wyrelog_error_t rc = wyl_fsm_session_step (from, ev, &validated);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (validated != to)
    return WYRELOG_E_POLICY;

  row[0] = event_id;
  rc = wyl_handle_intern_engine_symbol (self, session_id, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (self, event, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (self, from_state, &row[3]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (self, to_state, &row[4]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (self, "session_event", row, 5);
}

wyrelog_error_t
wyl_handle_load_policy_store_session_events (WylHandle *self)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (self->policy_store == NULL || self->read_engine == NULL
      || self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  return wyl_policy_store_foreach_session_event (self->policy_store,
      insert_policy_store_session_event, self);
}

static const gchar *
decision_symbol (wyl_decision_t decision)
{
  switch (decision) {
    case WYL_DECISION_DENY:
      return "deny";
    case WYL_DECISION_ALLOW:
      return "allow";
    default:
      return NULL;
  }
}

typedef struct
{
  const gchar *relation;
  gint64 row[2];
  gboolean inserted;
} WylAuditAttrFact;

static void
rollback_audit_fact_inputs (WylHandle *self, const gint64 audit_event[3],
    gboolean audit_event_inserted, WylAuditAttrFact *attrs, gsize n_attrs)
{
  for (gsize i = n_attrs; i > 0; i--) {
    WylAuditAttrFact *attr = &attrs[i - 1];
    if (attr->inserted)
      (void) wyl_handle_engine_remove (self, attr->relation, attr->row, 2);
  }
  if (audit_event_inserted)
    (void) wyl_handle_engine_remove (self, "audit_event_input", audit_event, 3);
}

static wyrelog_error_t
insert_audit_attr_fact (WylHandle *self, WylAuditAttrFact *attr,
    gint64 audit_id, const gchar *value)
{
  if (value == NULL)
    return WYRELOG_E_OK;

  attr->row[0] = audit_id;
  wyrelog_error_t rc =
      wyl_handle_intern_engine_symbol (self, value, &attr->row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_engine_insert (self, attr->relation, attr->row, 2);
  if (rc == WYRELOG_E_OK)
    attr->inserted = TRUE;
  return rc;
}

static wyrelog_error_t
insert_policy_store_audit_fact (const gchar *id, gint64 created_at_us,
    const gchar *subject_id, const gchar *action, const gchar *resource_id,
    const gchar *deny_reason, const gchar *deny_origin,
    wyl_decision_t decision, gpointer user_data)
{
  WylHandle *self = user_data;
  return wyl_handle_insert_audit_fact (self, id, created_at_us, subject_id,
      action, resource_id, deny_reason, deny_origin, decision);
}

wyrelog_error_t
wyl_handle_insert_audit_fact (WylHandle *self, const gchar *id,
    gint64 created_at_us, const gchar *subject_id, const gchar *action,
    const gchar *resource_id, const gchar *deny_reason,
    const gchar *deny_origin, wyl_decision_t decision)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (id == NULL || created_at_us < 0)
    return WYRELOG_E_INVALID;
  if (self->read_engine == NULL || self->delta_engine == NULL)
    return WYRELOG_E_OK;

  const gchar *decision_name = decision_symbol (decision);
  if (decision_name == NULL)
    return WYRELOG_E_POLICY;

  gint64 audit_event[3];
  gboolean audit_event_inserted = FALSE;
  WylAuditAttrFact attrs[] = {
    {.relation = "audit_event_subject_input"},
    {.relation = "audit_event_action_input"},
    {.relation = "audit_event_resource_input"},
    {.relation = "audit_event_deny_reason_input"},
    {.relation = "audit_event_deny_origin_input"},
  };

  wyrelog_error_t rc =
      wyl_handle_intern_engine_symbol (self, id, &audit_event[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  audit_event[1] = created_at_us;
  rc = wyl_handle_intern_engine_symbol (self, decision_name, &audit_event[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_engine_insert (self, "audit_event_input", audit_event, 3);
  if (rc != WYRELOG_E_OK)
    return rc;
  audit_event_inserted = TRUE;

  const gchar *values[] = {
    subject_id,
    action,
    resource_id,
    deny_reason,
    deny_origin,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (attrs); i++) {
    rc = insert_audit_attr_fact (self, &attrs[i], audit_event[0], values[i]);
    if (rc != WYRELOG_E_OK) {
      rollback_audit_fact_inputs (self, audit_event, audit_event_inserted,
          attrs, G_N_ELEMENTS (attrs));
      return rc;
    }
  }

  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_handle_load_policy_store_audit_facts (WylHandle *self)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (self->policy_store == NULL || self->read_engine == NULL
      || self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  return wyl_policy_store_foreach_audit_event (self->policy_store,
      insert_policy_store_audit_fact, self);
}

typedef struct
{
  const gchar *relation;
  const gint64 *row;
  gsize ncols;
  gboolean matched;
} WylRowProbe;

static void
wyl_handle_row_snapshot_cb (const gchar *relation, const gint64 *row,
    guint ncols, gpointer user_data)
{
  WylRowProbe *probe = user_data;

  if (g_strcmp0 (relation, probe->relation) != 0)
    return;
  if (ncols != probe->ncols)
    return;
  for (gsize i = 0; i < probe->ncols; i++) {
    if (row[i] != probe->row[i])
      return;
  }
  probe->matched = TRUE;
}

wyrelog_error_t
wyl_handle_engine_contains (WylHandle *self, const gchar *relation,
    const gint64 *row, gsize ncols, gboolean *out_contains)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (relation == NULL || row == NULL || ncols == 0 || out_contains == NULL)
    return WYRELOG_E_INVALID;
  if (self->read_engine == NULL || self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  WylRowProbe probe = { relation, row, ncols, FALSE };
  wyrelog_error_t rc = wyl_engine_snapshot (self->read_engine,
      relation, wyl_handle_row_snapshot_cb, &probe);
  if (rc != WYRELOG_E_OK)
    return rc;

  *out_contains = probe.matched;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_handle_engine_decide (WylHandle *self, const gint64 row[3],
    gboolean *out_allowed)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (row == NULL || out_allowed == NULL)
    return WYRELOG_E_INVALID;
  if (self->read_engine == NULL || self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  return wyl_handle_engine_contains (self, "allow_bool", row, 3, out_allowed);
}

WylEngine *
wyl_handle_get_read_engine (WylHandle *self)
{
  g_return_val_if_fail (WYL_IS_HANDLE (self), NULL);
  return self->read_engine;
}

WylEngine *
wyl_handle_get_delta_engine (WylHandle *self)
{
  g_return_val_if_fail (WYL_IS_HANDLE (self), NULL);
  return self->delta_engine;
}

wyrelog_error_t
wyl_handle_replay_delta_insert (WylHandle *self, const gchar *relation,
    const gint64 *row, gsize ncols)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (relation == NULL || row == NULL || ncols == 0)
    return WYRELOG_E_INVALID;
  if (self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  if (self->delta_callback == NULL)
    return WYRELOG_E_OK;

  self->delta_callback (relation, row, (guint) ncols, WYL_DELTA_INSERT,
      self->delta_callback_user_data);
  return WYRELOG_E_OK;
}

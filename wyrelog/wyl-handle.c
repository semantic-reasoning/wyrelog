/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

#include <string.h>

#include "access/decision-private.h"
#include "wyrelog/engine.h"
#include "wyl-fsm-permission-scope-private.h"
#include "wyl-fsm-principal-private.h"
#include "wyl-fsm-session-private.h"
#include "wyl-handle-compound-private.h"
#include "wyl-handle-private.h"
#include "wyl-id-private.h"
#include "wyl-log-private.h"
#include "wyl-permission-scope-private.h"
#include "policy/store-private.h"

#define WYL_LOGIN_SKIP_MFA_PERMISSION "wr.login.skip_mfa"
#define WYL_LOGIN_SKIP_MFA_SCOPE "login"

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

static wyrelog_error_t wyl_handle_make_guard_expr_node_compound (WylHandle *
    self, WylEngine * engine, const wyl_guard_expr_t * expr, gint64 * out_id);

static wyrelog_error_t
wyl_handle_intern_symbol_on_engine (WylHandle *self, WylEngine *engine,
    const gchar *symbol, gboolean cache_symbol, gint64 *out_id)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (engine == NULL || symbol == NULL || out_id == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = wyl_engine_intern_symbol (engine, symbol, out_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  if (cache_symbol) {
    gint64 *key = g_new (gint64, 1);
    *key = *out_id;
    g_hash_table_replace (self->engine_symbols_by_id, key, g_strdup (symbol));
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
wyl_handle_intern_guard_symbol (WylHandle *self, const gchar *symbol,
    WylEngine *engine, gint64 *out_id)
{
  if (symbol == NULL)
    return WYRELOG_E_INVALID;
  return wyl_handle_intern_symbol_on_engine (self, engine, symbol,
      engine == self->read_engine, out_id);
}

static wyrelog_error_t
wyl_handle_make_guard_cmp_compound (WylHandle *self,
    WylEngine *engine, const wyl_guard_expr_t *expr, gint64 *out_id)
{
  gint64 field_id = 0;
  wyrelog_error_t rc = wyl_handle_intern_guard_symbol (self,
      wyl_guard_field_name (expr->u.cmp.field), engine, &field_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  gint64 op_id = 0;
  rc = wyl_handle_intern_guard_symbol (self,
      wyl_guard_op_name (expr->u.cmp.op), engine, &op_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  gint64 value_id = 0;
  rc = wyl_handle_intern_guard_symbol (self, expr->u.cmp.value, engine,
      &value_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  wirelog_compound_arg_t args[3] = {
    {WIRELOG_TYPE_STRING, field_id},
    {WIRELOG_TYPE_STRING, op_id},
    {WIRELOG_TYPE_STRING, value_id},
  };
  return wyl_engine_make_compound (engine, "guard_cmp", args,
      G_N_ELEMENTS (args), out_id);
}

static wyrelog_error_t
wyl_handle_make_guard_tag_compound (WylHandle *self,
    WylEngine *engine, const wyl_guard_expr_t *expr, gint64 *out_id)
{
  gint64 atom_id = 0;
  wyrelog_error_t rc = wyl_handle_intern_guard_symbol (self,
      expr->u.tag.atom, engine, &atom_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  wirelog_compound_arg_t args[1] = {
    {WIRELOG_TYPE_STRING, atom_id},
  };
  return wyl_engine_make_compound (engine, "guard_tag", args,
      G_N_ELEMENTS (args), out_id);
}

static wyrelog_error_t
wyl_handle_make_guard_unary_compound (WylHandle *self, WylEngine *engine,
    const gchar *functor, const wyl_guard_expr_t *child, gint64 *out_id)
{
  gint64 child_id = 0;
  wyrelog_error_t rc =
      wyl_handle_make_guard_expr_node_compound (self, engine, child,
      &child_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  wirelog_compound_arg_t args[1] = {
    {WIRELOG_TYPE_INT64, child_id},
  };
  return wyl_engine_make_compound (engine, functor, args, G_N_ELEMENTS (args),
      out_id);
}

static wyrelog_error_t
wyl_handle_make_guard_binary_compound (WylHandle *self, WylEngine *engine,
    const gchar *functor, const wyl_guard_expr_t *left,
    const wyl_guard_expr_t *right, gint64 *out_id)
{
  gint64 left_id = 0;
  wyrelog_error_t rc =
      wyl_handle_make_guard_expr_node_compound (self, engine, left, &left_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  gint64 right_id = 0;
  rc = wyl_handle_make_guard_expr_node_compound (self, engine, right,
      &right_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  wirelog_compound_arg_t args[2] = {
    {WIRELOG_TYPE_INT64, left_id},
    {WIRELOG_TYPE_INT64, right_id},
  };
  return wyl_engine_make_compound (engine, functor, args, G_N_ELEMENTS (args),
      out_id);
}

static wyrelog_error_t
wyl_handle_make_guard_expr_node_compound (WylHandle *self, WylEngine *engine,
    const wyl_guard_expr_t *expr, gint64 *out_id)
{
  if (out_id != NULL)
    *out_id = (gint64) WIRELOG_COMPOUND_HANDLE_NULL;
  if (expr == NULL || out_id == NULL)
    return WYRELOG_E_INVALID;

  switch (expr->kind) {
    case WYL_GUARD_KIND_CMP:
      return wyl_handle_make_guard_cmp_compound (self, engine, expr, out_id);
    case WYL_GUARD_KIND_TAG:
      return wyl_handle_make_guard_tag_compound (self, engine, expr, out_id);
    case WYL_GUARD_KIND_NOT:
      return wyl_handle_make_guard_unary_compound (self, engine, "guard_not",
          expr->u.unary.child, out_id);
    case WYL_GUARD_KIND_AND:
      return wyl_handle_make_guard_binary_compound (self, engine, "guard_and",
          expr->u.binop.left, expr->u.binop.right, out_id);
    case WYL_GUARD_KIND_OR:
      return wyl_handle_make_guard_binary_compound (self, engine, "guard_or",
          expr->u.binop.left, expr->u.binop.right, out_id);
    case WYL_GUARD_KIND_LAST_:
    default:
      return WYRELOG_E_INVALID;
  }
}

static wyrelog_error_t
wyl_handle_make_guard_expr_compound (WylHandle *self, WylEngine *engine,
    const wyl_guard_expr_t *expr, gint64 *out_id)
{
  gint64 root_id = 0;
  wyrelog_error_t rc =
      wyl_handle_make_guard_expr_node_compound (self, engine, expr, &root_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  wirelog_compound_arg_t args[1] = {
    {WIRELOG_TYPE_INT64, root_id},
  };
  return wyl_engine_make_compound (engine, "guard", args, G_N_ELEMENTS (args),
      out_id);
}

static wyrelog_error_t
wyl_handle_seed_perm_arm_rule_on_engine (WylHandle *self, WylEngine *engine,
    const gchar *perm_id, const wyl_guard_expr_t *guard)
{
  gint64 row[2];
  wyrelog_error_t rc = wyl_handle_intern_symbol_on_engine (self, engine,
      perm_id, engine == self->read_engine, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = wyl_handle_make_guard_expr_compound (self, engine, guard, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = wyl_engine_insert (engine, "perm_arm_rule", row, 2);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (engine == self->delta_engine)
    return wyl_engine_step (engine);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
wyl_handle_seed_perm_arm_rules (WylHandle *self)
{
  for (gsize i = 0; i < wyl_perm_arm_rule_count (); i++) {
    const wyl_guard_expr_t *guard = wyl_perm_arm_rule_expr (i);
    const gchar *perm_id = wyl_perm_arm_rule_perm_id (i);
    wyrelog_error_t rc = wyl_handle_seed_perm_arm_rule_on_engine (self,
        self->read_engine, perm_id, guard);
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyl_handle_seed_perm_arm_rule_on_engine (self, self->delta_engine,
        perm_id, guard);
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

wyrelog_error_t
wyl_init (const gchar *config_path, WylHandle **out_handle)
{
  WylHandleOpenOptions opts = {
    .template_dir = config_path,
  };

  return wyl_handle_open_with_options (&opts, out_handle);
}

wyrelog_error_t
wyl_handle_open_with_options (const WylHandleOpenOptions *opts,
    WylHandle **out_handle)
{
  /* Eagerly initialise the log subsystem before any other library code
   * runs so that log sites in boot phases see the correct thresholds
   * and file sink from the very first message. */
  wyl_log_internal_reconfigure ();

  if (out_handle == NULL)
    return WYRELOG_E_INVALID;
  *out_handle = NULL;

  if (opts == NULL)
    return WYRELOG_E_INVALID;

  WylHandle *self = g_object_new (WYL_TYPE_HANDLE, NULL);

  wyrelog_error_t rc =
      wyl_policy_store_open (opts->policy_store_path, &self->policy_store);
  if (rc != WYRELOG_E_OK) {
    g_object_unref (self);
    return rc;
  }
  rc = wyl_policy_store_create_schema (self->policy_store);
  if (rc != WYRELOG_E_OK) {
    g_object_unref (self);
    return rc;
  }

  if (opts->template_dir != NULL) {
    rc = wyl_handle_open_engine_pair (self, opts->template_dir);
    if (rc != WYRELOG_E_OK) {
      g_object_unref (self);
      return rc;
    }
  }
#ifdef WYL_HAS_AUDIT
  /* Open the runtime audit sink and replay durable Policy DB audit rows into
   * it. Public wyl_init() passes NULL and therefore keeps the sink in-memory;
   * private daemon/test callers may pass a file path through opts. */
  rc = wyl_audit_conn_open (opts->audit_store_path, &self->audit_conn);
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
    const gchar *deny_reason, const gchar *deny_origin, const gchar *request_id,
    wyl_decision_t decision, gpointer user_data)
{
  WylHandle *self = user_data;
  gboolean inserted = FALSE;

  return wyl_audit_conn_insert_event_full (self->audit_conn, id, created_at_us,
      subject_id, action, resource_id, deny_reason, deny_origin, request_id,
      decision, &inserted);
}

wyrelog_error_t
wyl_handle_load_policy_store_audit_events (WylHandle *self)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (self->policy_store == NULL || self->audit_conn == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = wyl_audit_conn_create_schema (self->audit_conn);
  if (rc != WYRELOG_E_OK)
    return rc;

  duckdb_connection conn = wyl_audit_conn_get_connection (self->audit_conn);
  duckdb_result result;
  memset (&result, 0, sizeof (result));

  if (duckdb_query (conn, "BEGIN TRANSACTION;", &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }
  duckdb_destroy_result (&result);

  rc = wyl_policy_store_foreach_audit_event (self->policy_store,
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
wyl_handle_get_login_skip_mfa_override_allowed (WylHandle *self)
{
  g_return_val_if_fail (WYL_IS_HANDLE (self), FALSE);
  return self->login_skip_mfa_allowed;
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
preintern_policy_store_symbol (WylHandle *self, const gchar *symbol)
{
  gint64 ignored = 0;
  return wyl_handle_intern_engine_symbol (self, symbol, &ignored);
}

static wyrelog_error_t
preintern_policy_store_role_permission_symbols (const gchar *role_id,
    const gchar *perm_id, gpointer user_data)
{
  WylHandle *self = user_data;

  wyrelog_error_t rc = preintern_policy_store_symbol (self, role_id);
  if (rc != WYRELOG_E_OK)
    return rc;
  return preintern_policy_store_symbol (self, perm_id);
}

static wyrelog_error_t
preintern_policy_store_role_membership_symbols (const gchar *subject_id,
    const gchar *role_id, const gchar *scope, gpointer user_data)
{
  WylHandle *self = user_data;

  wyrelog_error_t rc = preintern_policy_store_symbol (self, subject_id);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = preintern_policy_store_symbol (self, role_id);
  if (rc != WYRELOG_E_OK)
    return rc;
  return preintern_policy_store_symbol (self, scope);
}

static wyrelog_error_t
preintern_policy_store_direct_permission_symbols (const gchar *subject_id,
    const gchar *perm_id, const gchar *scope, gpointer user_data)
{
  WylHandle *self = user_data;

  wyrelog_error_t rc = preintern_policy_store_symbol (self, subject_id);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = preintern_policy_store_symbol (self, perm_id);
  if (rc != WYRELOG_E_OK)
    return rc;
  return preintern_policy_store_symbol (self, scope);
}

static wyrelog_error_t
preintern_policy_store_permission_state_symbols (const gchar *subject_id,
    const gchar *perm_id, const gchar *scope, const gchar *state,
    gpointer user_data)
{
  WylHandle *self = user_data;

  wyrelog_error_t rc = preintern_policy_store_direct_permission_symbols
      (subject_id, perm_id, scope, user_data);
  if (rc != WYRELOG_E_OK)
    return rc;
  return preintern_policy_store_symbol (self, state);
}

static wyrelog_error_t
preintern_policy_store_permission_event_symbols (gint64 event_id,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope,
    const gchar *event, const gchar *from_state, const gchar *to_state,
    gpointer user_data)
{
  WylHandle *self = user_data;
  (void) event_id;

  wyrelog_error_t rc = preintern_policy_store_direct_permission_symbols
      (subject_id, perm_id, scope, user_data);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = preintern_policy_store_symbol (self, event);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = preintern_policy_store_symbol (self, from_state);
  if (rc != WYRELOG_E_OK)
    return rc;
  return preintern_policy_store_symbol (self, to_state);
}

static wyrelog_error_t
preintern_policy_store_principal_state_symbols (const gchar *subject_id,
    const gchar *state, gpointer user_data)
{
  WylHandle *self = user_data;

  wyrelog_error_t rc = preintern_policy_store_symbol (self, subject_id);
  if (rc != WYRELOG_E_OK)
    return rc;
  return preintern_policy_store_symbol (self, state);
}

static wyrelog_error_t
preintern_policy_store_principal_event_symbols (gint64 event_id,
    const gchar *subject_id, const gchar *event, const gchar *from_state,
    const gchar *to_state, gpointer user_data)
{
  WylHandle *self = user_data;
  (void) event_id;

  wyrelog_error_t rc = preintern_policy_store_symbol (self, subject_id);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = preintern_policy_store_symbol (self, event);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = preintern_policy_store_symbol (self, from_state);
  if (rc != WYRELOG_E_OK)
    return rc;
  return preintern_policy_store_symbol (self, to_state);
}

static wyrelog_error_t
preintern_policy_store_session_state_symbols (const gchar *session_id,
    const gchar *state, gpointer user_data)
{
  WylHandle *self = user_data;

  wyrelog_error_t rc = preintern_policy_store_symbol (self, session_id);
  if (rc != WYRELOG_E_OK)
    return rc;
  return preintern_policy_store_symbol (self, state);
}

static wyrelog_error_t
preintern_policy_store_session_event_symbols (gint64 event_id,
    const gchar *session_id, const gchar *event, const gchar *from_state,
    const gchar *to_state, gpointer user_data)
{
  WylHandle *self = user_data;
  (void) event_id;

  wyrelog_error_t rc = preintern_policy_store_symbol (self, session_id);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = preintern_policy_store_symbol (self, event);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = preintern_policy_store_symbol (self, from_state);
  if (rc != WYRELOG_E_OK)
    return rc;
  return preintern_policy_store_symbol (self, to_state);
}

static wyrelog_error_t
preintern_deny_reason_catalog_symbols (WylHandle *self)
{
  for (guint i = 0; i < wyl_deny_reason_count (); i++) {
    const gchar *name = wyl_deny_reason_name ((wyl_deny_reason_code_t) i);
    const gchar *origin = wyl_deny_reason_origin ((wyl_deny_reason_code_t) i);
    if (name == NULL || origin == NULL)
      return WYRELOG_E_INTERNAL;

    wyrelog_error_t rc = preintern_policy_store_symbol (self, name);
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = preintern_policy_store_symbol (self, origin);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
preintern_policy_store_symbols (WylHandle *self)
{
  wyrelog_error_t rc = preintern_deny_reason_catalog_symbols (self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_foreach_role_permission
      (self->policy_store, preintern_policy_store_role_permission_symbols,
      self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_foreach_role_membership (self->policy_store,
      preintern_policy_store_role_membership_symbols, self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_foreach_direct_permission (self->policy_store,
      preintern_policy_store_direct_permission_symbols, self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_foreach_permission_state (self->policy_store,
      preintern_policy_store_permission_state_symbols, self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_foreach_permission_state_event (self->policy_store,
      preintern_policy_store_permission_event_symbols, self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_foreach_principal_state (self->policy_store,
      preintern_policy_store_principal_state_symbols, self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_foreach_principal_event (self->policy_store,
      preintern_policy_store_principal_event_symbols, self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_foreach_session_state (self->policy_store,
      preintern_policy_store_session_state_symbols, self);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_policy_store_foreach_session_event (self->policy_store,
      preintern_policy_store_session_event_symbols, self);
}

static wyrelog_error_t
load_current_engine_pair (WylHandle *self)
{
  wyrelog_error_t rc = preintern_policy_store_symbols (self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_load_policy_store_audit_facts (self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_seed_perm_arm_rules (self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_seed_session_active_states (self);
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
  rc = wyl_handle_load_policy_store_permission_states (self);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_load_policy_store_permission_state_events (self);
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
  return WYRELOG_E_OK;
}

static wyrelog_error_t
replace_engine_pair (WylHandle *self, const gchar *template_dir)
{
  wyrelog_error_t rc = wyl_policy_store_validate_snapshot (self->policy_store);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylEngine *old_read_engine = self->read_engine;
  WylEngine *old_delta_engine = self->delta_engine;
  GHashTable *old_symbols = self->engine_symbols_by_id;
  gchar *old_template_dir = self->template_dir;

  WylEngine *new_read_engine = NULL;
  rc = wyl_engine_open (template_dir, 1, &new_read_engine);
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

wyrelog_error_t
wyl_handle_make_engine_compound (WylHandle *self, const gchar *functor,
    const wirelog_compound_arg_t *args, gsize nargs, gint64 *out_id)
{
  if (out_id != NULL)
    *out_id = (gint64) WIRELOG_COMPOUND_HANDLE_NULL;

  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (functor == NULL || functor[0] == '\0' || args == NULL || out_id == NULL)
    return WYRELOG_E_INVALID;
  if (nargs == 0 || nargs > G_MAXUINT32)
    return WYRELOG_E_INVALID;
  if (self->read_engine == NULL || self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  gint64 read_id = 0;
  wyrelog_error_t rc = wyl_engine_make_compound (self->read_engine,
      functor, args, nargs, &read_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  gint64 delta_id = 0;
  rc = wyl_engine_make_compound (self->delta_engine, functor, args, nargs,
      &delta_id);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (read_id != delta_id)
    return WYRELOG_E_INTERNAL;

  *out_id = read_id;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_handle_make_read_engine_compound (WylHandle *self, const gchar *functor,
    const wirelog_compound_arg_t *args, gsize nargs, gint64 *out_id)
{
  if (out_id != NULL)
    *out_id = (gint64) WIRELOG_COMPOUND_HANDLE_NULL;

  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (functor == NULL || functor[0] == '\0' || args == NULL || out_id == NULL)
    return WYRELOG_E_INVALID;
  if (nargs == 0 || nargs > G_MAXUINT32)
    return WYRELOG_E_INVALID;
  if (self->read_engine == NULL || self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  gint64 functor_id = 0;
  wyrelog_error_t rc = wyl_handle_intern_engine_symbol (self, functor,
      &functor_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = wyl_engine_make_compound (self->read_engine, functor, args, nargs,
      out_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  /* Keep the handle-owned engines' intern and side-arena streams aligned.
   * The returned handle remains read-engine-local and request-scoped. */
  gint64 delta_id = 0;
  return wyl_engine_make_compound (self->delta_engine, functor, args, nargs,
      &delta_id);
}

wyrelog_error_t
wyl_handle_make_guard_context_compound (WylHandle *self, gint64 timestamp,
    gint64 loc_class_id, gint64 risk, gint64 scope_id, gint64 *out_id)
{
  if (out_id != NULL)
    *out_id = (gint64) WIRELOG_COMPOUND_HANDLE_NULL;

  if (self == NULL || !WYL_IS_HANDLE (self) || out_id == NULL)
    return WYRELOG_E_INVALID;
  if (self->read_engine == NULL || self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  wirelog_compound_arg_t metadata_args[3] = {
    {WIRELOG_TYPE_INT64, timestamp},
    {WIRELOG_TYPE_STRING, loc_class_id},
    {WIRELOG_TYPE_INT64, risk},
  };
  gint64 ignored = 0;
  wyrelog_error_t rc =
      wyl_handle_intern_engine_symbol (self, "metadata", &ignored);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (self, "scope", &ignored);
  if (rc != WYRELOG_E_OK)
    return rc;

  gint64 read_metadata_id = 0;
  rc = wyl_engine_make_compound (self->read_engine, "metadata",
      metadata_args, G_N_ELEMENTS (metadata_args), &read_metadata_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  gint64 delta_metadata_id = 0;
  rc = wyl_engine_make_compound (self->delta_engine, "metadata",
      metadata_args, G_N_ELEMENTS (metadata_args), &delta_metadata_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  wirelog_compound_arg_t read_scope_args[2] = {
    {WIRELOG_TYPE_INT64, read_metadata_id},
    {WIRELOG_TYPE_STRING, scope_id},
  };
  rc = wyl_engine_make_compound (self->read_engine, "scope",
      read_scope_args, G_N_ELEMENTS (read_scope_args), out_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  wirelog_compound_arg_t delta_scope_args[2] = {
    {WIRELOG_TYPE_INT64, delta_metadata_id},
    {WIRELOG_TYPE_STRING, scope_id},
  };
  gint64 delta_scope_id = 0;
  return wyl_engine_make_compound (self->delta_engine, "scope",
      delta_scope_args, G_N_ELEMENTS (delta_scope_args), &delta_scope_id);
}

static gboolean
relation_fans_out_to_delta (const gchar *relation)
{
  return g_strcmp0 (relation, "member_of") == 0
      || g_strcmp0 (relation, "principal_transition") == 0
      || g_strcmp0 (relation, "session_transition") == 0
      || g_strcmp0 (relation, "perm_state_transition") == 0
      || g_strcmp0 (relation, "perm_state_event") == 0
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
insert_login_skip_mfa_authz_if_allowed (WylHandle *self,
    const gchar *subject_id, const gchar *scope)
{
  if (g_strcmp0 (scope, WYL_LOGIN_SKIP_MFA_SCOPE) != 0)
    return WYRELOG_E_OK;

  gboolean allowed = FALSE;
  wyrelog_error_t rc = wyl_policy_store_subject_has_permission
      (self->policy_store, subject_id, WYL_LOGIN_SKIP_MFA_PERMISSION,
      WYL_LOGIN_SKIP_MFA_SCOPE, &allowed);
  if (rc != WYRELOG_E_OK || !allowed)
    return rc;

  gint64 row[1];
  rc = wyl_handle_intern_engine_symbol (self, subject_id, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (self, "login_skip_mfa_authz", row, 1);
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
  rc = wyl_handle_engine_insert (self, "member_of", row, 3);
  if (rc != WYRELOG_E_OK)
    return rc;
  return insert_login_skip_mfa_authz_if_allowed (self, subject_id, scope);
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

  rc = wyl_handle_engine_insert (self, "direct_permission", row, 3);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = insert_login_skip_mfa_authz_if_allowed (self, subject_id, scope);
  if (rc != WYRELOG_E_OK)
    return rc;

  /* Guarded permissions are granted membership only. Their armed state
   * comes from request-local guard evaluation, not persisted perm_state. */
  if (wyl_perm_arm_rule_lookup (perm_id) != NULL)
    return WYRELOG_E_OK;

  gboolean has_durable_state = FALSE;
  rc = wyl_policy_store_permission_state_exists (self->policy_store, subject_id,
      perm_id, scope, &has_durable_state);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (has_durable_state)
    return WYRELOG_E_OK;

  gint64 state_row[4];
  state_row[0] = row[0];
  state_row[1] = row[1];
  state_row[2] = row[2];
  rc = wyl_handle_intern_engine_symbol (self, "armed", &state_row[3]);
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
insert_policy_store_permission_state (const gchar *subject_id,
    const gchar *perm_id, const gchar *scope, const gchar *state,
    gpointer user_data)
{
  WylHandle *self = user_data;
  gint64 row[4];

  if (wyl_perm_state_from_name (state) == WYL_PERM_STATE_LAST_)
    return WYRELOG_E_POLICY;

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
  rc = wyl_handle_intern_engine_symbol (self, state, &row[3]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (self, "perm_state", row, 4);
}

wyrelog_error_t
wyl_handle_load_policy_store_permission_states (WylHandle *self)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (self->policy_store == NULL || self->read_engine == NULL
      || self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  return wyl_policy_store_foreach_permission_state (self->policy_store,
      insert_policy_store_permission_state, self);
}

static wyrelog_error_t
insert_policy_store_permission_state_event (gint64 event_id,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope,
    const gchar *event, const gchar *from_state, const gchar *to_state,
    gpointer user_data)
{
  WylHandle *self = user_data;
  gint64 row[7];
  wyl_perm_state_t from = wyl_perm_state_from_name (from_state);
  wyl_perm_event_t ev = wyl_perm_event_from_name (event);
  wyl_perm_state_t to = wyl_perm_state_from_name (to_state);

  if (event_id <= 0)
    return WYRELOG_E_POLICY;
  if (from == WYL_PERM_STATE_LAST_ || ev == WYL_PERM_EVENT_LAST_
      || to == WYL_PERM_STATE_LAST_)
    return WYRELOG_E_POLICY;
  wyl_perm_state_t validated = WYL_PERM_STATE_LAST_;
  wyrelog_error_t rc = wyl_fsm_permission_scope_step (from, ev, &validated);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (validated != to)
    return WYRELOG_E_POLICY;

  row[0] = event_id;
  rc = wyl_handle_intern_engine_symbol (self, subject_id, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (self, perm_id, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (self, scope, &row[3]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (self, event, &row[4]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (self, from_state, &row[5]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (self, to_state, &row[6]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (self, "perm_state_event", row, 7);
}

wyrelog_error_t
wyl_handle_load_policy_store_permission_state_events (WylHandle *self)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (self->policy_store == NULL || self->read_engine == NULL
      || self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  return wyl_policy_store_foreach_permission_state_event (self->policy_store,
      insert_policy_store_permission_state_event, self);
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
    const gchar *deny_reason, const gchar *deny_origin, const gchar *request_id,
    wyl_decision_t decision, gpointer user_data)
{
  WylHandle *self = user_data;
  return wyl_handle_insert_audit_fact (self, id, created_at_us, subject_id,
      action, resource_id, deny_reason, deny_origin, request_id, decision);
}

wyrelog_error_t
wyl_handle_insert_audit_fact (WylHandle *self, const gchar *id,
    gint64 created_at_us, const gchar *subject_id, const gchar *action,
    const gchar *resource_id, const gchar *deny_reason,
    const gchar *deny_origin, const gchar *request_id, wyl_decision_t decision)
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
    {.relation = "audit_event_request_id_input"},
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
    request_id,
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
  const gchar *snapshot_relation;
  const gint64 *row;
  gsize ncols;
  gboolean matched;
} WylRowProbe;

static void
wyl_handle_row_snapshot_cb (const gchar *relation, const gint64 *row,
    guint ncols, gpointer user_data)
{
  WylRowProbe *probe = user_data;

  if (g_strcmp0 (relation, probe->snapshot_relation) != 0)
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

  const gchar *snapshot_relation = relation;
  /* The engine snapshots derived outputs, so principal_state probes use
   * the template mirror while preserving the handle-level relation name. */
  if (g_strcmp0 (relation, "principal_state") == 0)
    snapshot_relation = "principal_state_observed";
  else if (g_strcmp0 (relation, "login_skip_mfa_authz") == 0)
    snapshot_relation = "login_skip_mfa_authz_observed";

  WylRowProbe probe = { relation, snapshot_relation, row, ncols, FALSE };
  wyrelog_error_t rc = wyl_engine_snapshot (self->read_engine,
      snapshot_relation, wyl_handle_row_snapshot_cb, &probe);
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

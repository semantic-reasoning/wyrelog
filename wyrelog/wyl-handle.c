/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

#include "wyrelog/engine.h"
#include "wyl-handle-private.h"
#include "wyl-id-private.h"
#include "wyl-log-private.h"
#include "wyl-permission-scope-private.h"

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

  if (config_path != NULL) {
    wyrelog_error_t rc = wyl_handle_open_engine_pair (self, config_path);
    if (rc != WYRELOG_E_OK) {
      g_object_unref (self);
      return rc;
    }
  }
#ifdef WYL_HAS_AUDIT
  /* Open an in-memory audit database and create the audit_events
   * schema. Audit persistence is not wired to config_path yet. */
  wyrelog_error_t rc = wyl_audit_conn_open (NULL, &self->audit_conn);
  if (rc != WYRELOG_E_OK) {
    g_object_unref (self);
    return rc;
  }
  rc = wyl_audit_conn_create_schema (self->audit_conn);
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
  g_clear_object (&handle->read_engine);
  g_clear_object (&handle->delta_engine);
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
#endif

wyrelog_error_t
wyl_handle_open_engine_pair (WylHandle *self, const gchar *template_dir)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (template_dir == NULL)
    return WYRELOG_E_INVALID;
  if (self->read_engine != NULL || self->delta_engine != NULL)
    return WYRELOG_E_INVALID;

  WylEngine *read_engine = NULL;
  wyrelog_error_t rc = wyl_engine_open (template_dir, 1, &read_engine);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylEngine *delta_engine = NULL;
  rc = wyl_engine_open (template_dir, 1, &delta_engine);
  if (rc != WYRELOG_E_OK) {
    g_object_unref (read_engine);
    return rc;
  }

  self->read_engine = read_engine;
  self->delta_engine = delta_engine;
  rc = wyl_handle_seed_perm_arm_rules (self);
  if (rc != WYRELOG_E_OK) {
    g_clear_object (&self->read_engine);
    g_clear_object (&self->delta_engine);
    return rc;
  }
  return WYRELOG_E_OK;
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

  *out_id = read_id;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_handle_engine_insert (WylHandle *self, const gchar *relation,
    const gint64 *row, gsize ncols)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (self->read_engine == NULL || self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc =
      wyl_engine_insert (self->read_engine, relation, row, ncols);
  if (rc != WYRELOG_E_OK)
    return rc;

  return wyl_engine_insert (self->delta_engine, relation, row, ncols);
}

wyrelog_error_t
wyl_handle_engine_remove (WylHandle *self, const gchar *relation,
    const gint64 *row, gsize ncols)
{
  if (self == NULL || !WYL_IS_HANDLE (self))
    return WYRELOG_E_INVALID;
  if (self->read_engine == NULL || self->delta_engine == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc =
      wyl_engine_remove (self->read_engine, relation, row, ncols);
  if (rc != WYRELOG_E_OK)
    return rc;

  return wyl_engine_remove (self->delta_engine, relation, row, ncols);
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

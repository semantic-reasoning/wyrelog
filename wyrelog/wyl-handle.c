/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

#include "wyl-id-private.h"

#ifdef WYL_HAS_AUDIT
#include "audit/conn-private.h"
#endif

struct _WylHandle
{
  GObject parent_instance;
  wyl_id_t id;
  gint64 created_at_us;
#ifdef WYL_HAS_AUDIT
  wyl_audit_conn_t *audit_conn;
#endif
};

G_DEFINE_FINAL_TYPE (WylHandle, wyl_handle, G_TYPE_OBJECT);

static void
wyl_handle_finalize (GObject *object)
{
#ifdef WYL_HAS_AUDIT
  WylHandle *self = WYL_HANDLE (object);
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

wyrelog_error_t
wyl_init (const gchar *config_path, WylHandle **out_handle)
{
  (void) config_path;

  if (out_handle == NULL)
    return WYRELOG_E_INVALID;

  WylHandle *self = g_object_new (WYL_TYPE_HANDLE, NULL);

#ifdef WYL_HAS_AUDIT
  /* Open an in-memory audit database and create the audit_events
   * schema. config_path will eventually direct this at a persistent
   * location; for now the in-memory store is enough to exercise the
   * full lifecycle. */
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

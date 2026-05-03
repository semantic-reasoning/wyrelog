/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

#include "wyl-id-private.h"

struct _WylHandle
{
  GObject parent_instance;
  wyl_id_t id;
  gint64 created_at_us;
};

G_DEFINE_FINAL_TYPE (WylHandle, wyl_handle, G_TYPE_OBJECT);

static void
wyl_handle_class_init (WylHandleClass *klass)
{
  (void) klass;
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

  *out_handle = g_object_new (WYL_TYPE_HANDLE, NULL);
  return WYRELOG_E_OK;
}

void
wyl_shutdown (WylHandle *handle)
{
  (void) handle;
  /* Real implementation drains queues, closes DBs, finalizes TPM. */
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

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

struct _WylHandle
{
  GObject parent_instance;
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
  (void) self;
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

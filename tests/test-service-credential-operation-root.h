/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

static gchar *
service_credential_operation_root_for_test (const gchar *fallback_parent,
    const gchar *stem)
{
#ifdef G_OS_WIN32
  const gchar *local = g_getenv ("LOCALAPPDATA");
  g_assert_nonnull (local);
  g_autofree gchar *uuid = g_uuid_string_random ();
  g_autofree gchar *name = g_strdup_printf ("wyrelog-%s-%s", stem, uuid);
  return g_build_filename (local, name, NULL);
#else
  return g_build_filename (fallback_parent, stem, NULL);
#endif
}

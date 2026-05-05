/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

static gboolean
template_tree_has_backup (const gchar *dir_path)
{
  g_autoptr (GDir) dir = g_dir_open (dir_path, 0, NULL);
  if (dir == NULL)
    return TRUE;

  const gchar *name = NULL;
  while ((name = g_dir_read_name (dir)) != NULL) {
    g_autofree gchar *path = g_build_filename (dir_path, name, NULL);

    if (g_str_has_suffix (name, "~") || g_str_has_suffix (name, ".bak")
        || g_str_has_suffix (name, ".orig"))
      return TRUE;
    if (g_file_test (path, G_FILE_TEST_IS_DIR)
        && template_tree_has_backup (path))
      return TRUE;
  }
  return FALSE;
}

int
main (void)
{
  return template_tree_has_backup (WYL_TEST_TEMPLATE_DIR) ? 1 : 0;
}

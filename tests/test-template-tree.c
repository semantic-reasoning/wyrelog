/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/policy/store-private.h"

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

static gint
collect_template_facts (const gchar *contents, const gchar *prefix,
    GHashTable *out)
{
  g_auto (GStrv) lines = g_strsplit (contents, "\n", -1);

  for (gsize i = 0; lines[i] != NULL; i++) {
    g_autofree gchar *line = g_strdup (lines[i]);
    g_strstrip (line);
    if (!g_str_has_prefix (line, prefix))
      continue;

    const gchar *start = strchr (line, '"');
    if (start == NULL)
      return 10;
    const gchar *end = strchr (start + 1, '"');
    if (end == NULL || end == start + 1)
      return 11;

    g_hash_table_add (out, g_strndup (start + 1, (gsize) (end - start - 1)));
  }

  return 0;
}

static gint
check_seed_list (GHashTable *template_ids, gsize count,
    const gchar *(*id_at) (gsize))
{
  if (g_hash_table_size (template_ids) != count)
    return 20;

  for (gsize i = 0; i < count; i++) {
    const gchar *id = id_at (i);
    if (id == NULL)
      return 21;
    if (!g_hash_table_contains (template_ids, id))
      return 22;
  }

  return 0;
}

static gint
check_bootstrap_seed_consistency (void)
{
  g_autofree gchar *path =
      g_build_filename (WYL_TEST_TEMPLATE_DIR, "bootstrap.dl", NULL);
  g_autofree gchar *contents = NULL;
  gsize len = 0;
  g_autoptr (GError) error = NULL;

  if (!g_file_get_contents (path, &contents, &len, &error))
    return 30;

  g_autoptr (GHashTable) roles = g_hash_table_new_full (g_str_hash,
      g_str_equal, g_free, NULL);
  g_autoptr (GHashTable) permissions = g_hash_table_new_full (g_str_hash,
      g_str_equal, g_free, NULL);

  gint rc = collect_template_facts (contents, "role(", roles);
  if (rc != 0)
    return 31;
  rc = collect_template_facts (contents, "permission(", permissions);
  if (rc != 0)
    return 32;

  rc = check_seed_list (roles, wyl_policy_store_builtin_role_count (),
      wyl_policy_store_builtin_role_id);
  if (rc != 0)
    return 40 + rc;
  rc = check_seed_list (permissions,
      wyl_policy_store_builtin_permission_count (),
      wyl_policy_store_builtin_permission_id);
  if (rc != 0)
    return 60 + rc;

  return 0;
}

int
main (void)
{
  if (template_tree_has_backup (WYL_TEST_TEMPLATE_DIR))
    return 1;
  return check_bootstrap_seed_consistency ();
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/wyl-engine-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

static guint32
next_u32 (guint32 *state)
{
  *state = *state * 1664525u + 1013904223u;
  return *state;
}

static void
record_seed (guint32 seed)
{
  const gchar *dir = g_getenv ("WYL_FUZZ_ARTIFACT_DIR");
  if (dir == NULL || dir[0] == '\0')
    return;
  g_mkdir_with_parents (dir, 0755);
  g_autofree gchar *path = g_build_filename (dir, "last-seed.txt", NULL);
  g_autofree gchar *body = g_strdup_printf ("%u\n", seed);
  (void) g_file_set_contents (path, body, -1, NULL);
}

static gchar *
make_payload (guint32 *state, guint max_len)
{
  guint len = next_u32 (state) % (max_len + 1);
  gchar *payload = g_malloc0 (len + 1);
  for (guint i = 0; i < len; i++) {
    guint32 v = next_u32 (state);
    payload[i] = (gchar) (32 + (v % 95));
  }
  return payload;
}

static gint
fuzz_decide_inputs (guint32 seed)
{
  guint32 state = seed;
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 10;

  for (guint i = 0; i < 256; i++) {
    record_seed (seed + i);
    g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
    g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
    g_autofree gchar *subject = make_payload (&state, 64);
    g_autofree gchar *action = make_payload (&state, 64);
    g_autofree gchar *resource = make_payload (&state, 64);
    g_autofree gchar *loc = make_payload (&state, 32);

    if ((next_u32 (&state) & 1) != 0)
      wyl_decide_req_set_subject_id (req, subject);
    if ((next_u32 (&state) & 1) != 0)
      wyl_decide_req_set_action (req, action);
    if ((next_u32 (&state) & 1) != 0)
      wyl_decide_req_set_resource_id (req, resource);
    if ((next_u32 (&state) & 1) != 0)
      wyl_decide_req_set_guard_context (req, (gint64) next_u32 (&state) - 100,
          loc, (gint64) (next_u32 (&state) % 140) - 20);

    wyrelog_error_t rc = wyl_decide (handle, req, resp);
    if (rc != WYRELOG_E_OK && rc != WYRELOG_E_INVALID)
      return 11;
  }
  return 0;
}

static gboolean
write_template_file (const gchar *dir, const gchar *rel, const gchar *body)
{
  g_autofree gchar *path = g_build_filename (dir, rel, NULL);
  g_autofree gchar *parent = g_path_get_dirname (path);
  if (g_mkdir_with_parents (parent, 0755) != 0)
    return FALSE;
  return g_file_set_contents (path, body, -1, NULL);
}

static gint
fuzz_template_loading (guint32 seed)
{
  guint32 state = seed ^ 0x9e3779b9u;
  for (guint i = 0; i < 64; i++) {
    record_seed (seed + 1000 + i);
    g_autoptr (GError) err = NULL;
    gchar *tmp = g_dir_make_tmp ("wyl-fuzz-template-XXXXXX", &err);
    if (tmp == NULL)
      return 20;
    g_autofree gchar *bootstrap = make_payload (&state, 192);
    g_autofree gchar *principal = make_payload (&state, 192);
    g_autofree gchar *session = make_payload (&state, 192);
    g_autofree gchar *perm = make_payload (&state, 192);
    g_autofree gchar *decision = make_payload (&state, 192);

    gboolean ok = write_template_file (tmp, "bootstrap.dl", bootstrap)
        && write_template_file (tmp, "fsm/principal.dl", principal)
        && write_template_file (tmp, "fsm/session.dl", session)
        && write_template_file (tmp, "fsm/permission_scope.dl", perm)
        && write_template_file (tmp, "lobac/decision.dl", decision);

    gchar *dl_src = NULL;
    gsize dl_src_len = 0;
    if (ok) {
      wyrelog_error_t rc = wyl_engine_load_templates (tmp, &dl_src,
          &dl_src_len);
      if (rc == WYRELOG_E_OK && dl_src_len == 0) {
        g_free (dl_src);
        g_remove (tmp);
        return 21;
      }
    }
    if (dl_src != NULL) {
      memset (dl_src, 0, dl_src_len);
      g_free (dl_src);
    }

    g_autofree gchar *bootstrap_path = g_build_filename (tmp, "bootstrap.dl",
        NULL);
    g_autofree gchar *principal_path = g_build_filename (tmp, "fsm",
        "principal.dl", NULL);
    g_autofree gchar *session_path = g_build_filename (tmp, "fsm",
        "session.dl", NULL);
    g_autofree gchar *perm_path = g_build_filename (tmp, "fsm",
        "permission_scope.dl", NULL);
    g_autofree gchar *decision_path = g_build_filename (tmp, "lobac",
        "decision.dl", NULL);
    g_unlink (bootstrap_path);
    g_unlink (principal_path);
    g_unlink (session_path);
    g_unlink (perm_path);
    g_unlink (decision_path);
    g_autofree gchar *fsm_dir = g_build_filename (tmp, "fsm", NULL);
    g_autofree gchar *lobac_dir = g_build_filename (tmp, "lobac", NULL);
    g_rmdir (fsm_dir);
    g_rmdir (lobac_dir);
    g_rmdir (tmp);
  }
  return 0;
}

int
main (void)
{
  guint32 seed = 0x57594c46u;
  const gchar *seed_env = g_getenv ("WYL_FUZZ_SEED");
  if (seed_env != NULL && seed_env[0] != '\0')
    seed = (guint32) g_ascii_strtoull (seed_env, NULL, 10);

  gint rc = fuzz_decide_inputs (seed);
  if (rc != 0)
    return rc;
  return fuzz_template_loading (seed);
}

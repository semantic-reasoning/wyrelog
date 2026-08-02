/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/auth/service-auth-coordination-private.h"
#include "wyrelog/auth/service-credential-domain-private.h"
#include "wyrelog/wyl-handle-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

static void
remove_tree (const gchar *path)
{
  g_autoptr (GDir) dir = g_dir_open (path, 0, NULL);

  if (dir == NULL) {
    g_remove (path);
    return;
  }
  const gchar *name = NULL;
  while ((name = g_dir_read_name (dir)) != NULL) {
    g_autofree gchar *child = g_build_filename (path, name, NULL);
    if (g_file_test (child, G_FILE_TEST_IS_DIR))
      remove_tree (child);
    else
      g_remove (child);
  }
  g_rmdir (path);
}

static gchar *
copy_unsigned_template_tree (void)
{
  static const gchar *const files[] = {
    "bootstrap.dl",
    "fsm/principal.dl",
    "fsm/session.dl",
    "fsm/permission_scope.dl",
    "lobac/decision.dl",
  };
  g_autofree gchar *dir =
      g_dir_make_tmp ("wyl-service-decision-template-XXXXXX", NULL);
  if (dir == NULL)
    return NULL;
  g_autofree gchar *fsm = g_build_filename (dir, "fsm", NULL);
  g_autofree gchar *lobac = g_build_filename (dir, "lobac", NULL);
  if (g_mkdir (fsm, 0700) != 0 || g_mkdir (lobac, 0700) != 0) {
    remove_tree (dir);
    return NULL;
  }

  for (gsize i = 0; i < G_N_ELEMENTS (files); i++) {
    g_autofree gchar *source =
        g_build_filename (WYL_TEST_TEMPLATE_DIR, files[i], NULL);
    g_autofree gchar *target = g_build_filename (dir, files[i], NULL);
    g_autofree gchar *contents = NULL;
    gsize len = 0;
    if (!g_file_get_contents (source, &contents, &len, NULL)
        || !g_file_set_contents (target, contents, (gssize) len, NULL)) {
      remove_tree (dir);
      return NULL;
    }
  }
  return g_steal_pointer (&dir);
}

static void
remove_store_files (const gchar *path)
{
  g_autofree gchar *wal = g_strconcat (path, "-wal", NULL);
  g_autofree gchar *shm = g_strconcat (path, "-shm", NULL);
  g_remove (wal);
  g_remove (shm);
  g_remove (path);
}

static gboolean
contains_state (WylHandle *handle, const gchar *relation,
    const gchar *subject, const gchar *state)
{
  gint64 row[2];
  gboolean contains = FALSE;

  g_assert_cmpint (wyl_handle_intern_engine_symbol (handle, subject, &row[0]),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_intern_engine_symbol (handle, state, &row[1]),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_engine_contains (handle, relation, row, 2,
          &contains), ==, WYRELOG_E_OK);
  return contains;
}

static void
test_service_lifecycle_projection (void)
{
  g_autofree gchar *templates = copy_unsigned_template_tree ();
  g_assert_nonnull (templates);
  WylHandleOpenOptions options = {
    .template_dir = templates,
    .require_template_manifest = FALSE,
  };
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);

  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle, "svc:projection",
          "projection", "admin", "projection-create", &principal), ==,
      WYRELOG_E_OK);
  g_assert_true (contains_state (handle, "service_principal_state",
          principal.subject_id, "active"));
  g_assert_false (contains_state (handle, "principal_state",
          principal.subject_id, "authenticated"));
  wyl_service_principal_clear (&principal);

  g_assert_cmpint (wyl_service_principal_disable (handle, "svc:projection",
          "admin", "00000000000000000000000725A", &principal), ==,
      WYRELOG_E_OK);
  g_assert_false (contains_state (handle, "service_principal_state",
          principal.subject_id, "active"));
  g_assert_true (contains_state (handle, "service_principal_state",
          principal.subject_id, "disabled"));
  g_assert_false (contains_state (handle, "principal_state",
          principal.subject_id, "authenticated"));
  wyl_service_principal_clear (&principal);

  g_clear_object (&handle);
  remove_tree (templates);
}

static void
test_service_lifecycle_restart_projection (void)
{
  g_autofree gchar *templates = copy_unsigned_template_tree ();
  g_autofree gchar *dir =
      g_dir_make_tmp ("wyl-service-decision-store-XXXXXX", NULL);
  g_assert_nonnull (templates);
  g_assert_nonnull (dir);
  g_autofree gchar *store = g_build_filename (dir, "policy.db", NULL);
  WylHandleOpenOptions options = {
    .template_dir = templates,
    .policy_store_path = store,
    .require_template_manifest = FALSE,
  };
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle, "svc:restart:725",
          "restart", "admin", "restart-create", &principal), ==, WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);
  g_assert_cmpint (wyl_service_principal_disable (handle, "svc:restart:725",
          "admin", "00000000000000000000000725B", &principal), ==,
      WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);
  g_clear_object (&handle);

  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);
  g_assert_true (contains_state (handle, "service_principal_state",
          "svc:restart:725", "disabled"));
  g_assert_false (contains_state (handle, "principal_state",
          "svc:restart:725", "authenticated"));
  g_clear_object (&handle);

  remove_store_files (store);
  g_rmdir (dir);
  remove_tree (templates);
}

static void
test_service_lifecycle_projection_failure_latches (void)
{
  g_autofree gchar *templates = copy_unsigned_template_tree ();
  g_assert_nonnull (templates);
  WylHandleOpenOptions options = {
    .template_dir = templates,
    .require_template_manifest = FALSE,
  };
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);

  wyl_handle_set_engine_insert_fault_once (handle,
      "service_principal_state", WYRELOG_E_IO);
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle,
          "svc:projection:fault", "fault", "admin", "projection-fault",
          &principal), ==, WYRELOG_E_BUSY);
  g_assert_null (principal.subject_id);
  WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
  g_assert_cmpint (wyl_service_auth_authority_validate_available
      (wyl_handle_get_service_auth_authority (handle), handle, &reason), ==,
      WYRELOG_E_BUSY);
  g_assert_cmpint (reason, ==,
      WYL_SERVICE_AUTH_UNAVAILABLE_COORDINATION_INVARIANT);
  g_assert_false (contains_state (handle, "service_principal_state",
          "svc:projection:fault", "active"));

  g_clear_object (&handle);
  remove_tree (templates);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/service-decision/lifecycle/live",
      test_service_lifecycle_projection);
  g_test_add_func ("/service-decision/lifecycle/restart",
      test_service_lifecycle_restart_projection);
  g_test_add_func ("/service-decision/lifecycle/projection-failure",
      test_service_lifecycle_projection_failure_latches);
  return g_test_run ();
}

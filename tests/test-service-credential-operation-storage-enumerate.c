/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <glib.h>
#include <glib/gstdio.h>

#include "auth/service-credential-operation-storage-private.h"
#include "wyl-request-id-private.h"

static void
test_enumerate_rejects_null_arguments (void)
{
  GPtrArray *out = (GPtrArray *) 0x1;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  /* NULL out_request_ids is rejected before anything is touched. */
  g_assert_cmpint
      (wyl_service_credential_operation_storage_enumerate_request_ids (NULL,
          &anchor, NULL, NULL), ==, WYRELOG_E_INVALID);
  /* NULL storage with a live out pointer must leave it untouched. */
  g_assert_cmpint
      (wyl_service_credential_operation_storage_enumerate_request_ids (NULL,
          &anchor, NULL, &out), ==, WYRELOG_E_INVALID);
  g_assert_true (out == (GPtrArray *) 0x1);
}

#ifndef G_OS_WIN32
static void
make_op_record (WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const gchar *request_id)
{
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  g_autofree gchar *raw = g_strdup_printf ("op-%s", request_id);
  g_autoptr (GBytes) empty = g_bytes_new_static ("", 0);
  g_assert_cmpint (wyl_service_credential_operation_child_name_validate (raw,
          &name), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_child_create (storage,
          anchor, &name, empty), ==, WYRELOG_E_OK);
  wyl_service_credential_operation_child_name_clear (&name);
}

static void
make_foreign_file (const gchar *root, const gchar *name)
{
  g_autofree gchar *path = g_build_filename (root, name, NULL);
  g_assert_true (g_file_set_contents (path, "x", 1, NULL));
}

static void
purge_root (const gchar *root)
{
  g_autoptr (GDir) dir = g_dir_open (root, 0, NULL);
  const gchar *entry;
  while (dir != NULL && (entry = g_dir_read_name (dir)) != NULL) {
    g_autofree gchar *path = g_build_filename (root, entry, NULL);
    g_remove (path);
  }
}

static void
test_posix_enumerate_backend (void)
{
  g_autofree gchar *base = g_dir_make_tmp ("wyl-enumerate-XXXXXX", NULL);
  g_autofree gchar *root = g_build_filename (base, "state", NULL);
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  gchar ids[3][WYL_REQUEST_ID_STRING_BUF];
  gchar lifecycle_id[WYL_REQUEST_ID_STRING_BUF];
  g_assert_nonnull (base);
  g_assert_cmpint (wyl_service_credential_operation_storage_open (root,
          &storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&storage, &anchor), ==, WYRELOG_E_OK);

  /* (1) An empty root yields success and an empty array. */
  {
    GPtrArray *out = NULL;
    g_assert_cmpint
        (wyl_service_credential_operation_storage_enumerate_request_ids
        (&storage, &anchor, NULL, &out), ==, WYRELOG_E_OK);
    g_assert_nonnull (out);
    g_assert_cmpuint (out->len, ==, 0);
    g_ptr_array_unref (out);
  }

  /* (2) Exactly the created op records are returned, order independent. */
  for (gsize i = 0; i < G_N_ELEMENTS (ids); i++) {
    g_assert_cmpint (wyl_request_id_new (ids[i], sizeof ids[i]), ==,
        WYRELOG_E_OK);
    make_op_record (&storage, &anchor, ids[i]);
  }
  {
    GHashTable *expected = g_hash_table_new (g_str_hash, g_str_equal);
    GPtrArray *out = NULL;
    for (gsize i = 0; i < G_N_ELEMENTS (ids); i++)
      g_hash_table_add (expected, ids[i]);
    g_assert_cmpint
        (wyl_service_credential_operation_storage_enumerate_request_ids
        (&storage, &anchor, NULL, &out), ==, WYRELOG_E_OK);
    g_assert_cmpuint (out->len, ==, G_N_ELEMENTS (ids));
    for (guint i = 0; i < out->len; i++) {
      const gchar *got = g_ptr_array_index (out, i);
      g_assert_true (g_hash_table_remove (expected, got));
    }
    g_assert_cmpuint (g_hash_table_size (expected), ==, 0);
    g_hash_table_unref (expected);
    g_ptr_array_unref (out);
  }

  /* (3) Foreign namespace objects are ignored: lifecycle-*, .lock-*, an
   * invalid "op-" suffix and an unrelated file. */
  g_assert_cmpint (wyl_request_id_new (lifecycle_id, sizeof lifecycle_id), ==,
      WYRELOG_E_OK);
  {
    g_autofree gchar *lifecycle = g_strdup_printf ("lifecycle-%s",
        lifecycle_id);
    make_foreign_file (storage.root_path, lifecycle);
  }
  make_foreign_file (storage.root_path, ".lock-deadbeef");
  make_foreign_file (storage.root_path, "op-notvalid!");
  make_foreign_file (storage.root_path, "garbage");
  {
    GPtrArray *out = NULL;
    g_assert_cmpint
        (wyl_service_credential_operation_storage_enumerate_request_ids
        (&storage, &anchor, NULL, &out), ==, WYRELOG_E_OK);
    g_assert_cmpuint (out->len, ==, G_N_ELEMENTS (ids));
    g_ptr_array_unref (out);
  }

  /* (4) A cancelled operation returns CANCELLED and never writes *out. */
  {
    GCancellable *cancellable = g_cancellable_new ();
    GPtrArray *out = (GPtrArray *) 0x1;
    g_cancellable_cancel (cancellable);
    g_assert_cmpint
        (wyl_service_credential_operation_storage_enumerate_request_ids
        (&storage, &anchor, cancellable, &out), ==, WYRELOG_E_CANCELLED);
    g_assert_true (out == (GPtrArray *) 0x1);
    g_object_unref (cancellable);
  }

  /* (5) NULL out / NULL storage are invalid arguments. */
  {
    GPtrArray *out = NULL;
    g_assert_cmpint
        (wyl_service_credential_operation_storage_enumerate_request_ids
        (&storage, &anchor, NULL, NULL), ==, WYRELOG_E_INVALID);
    g_assert_cmpint
        (wyl_service_credential_operation_storage_enumerate_request_ids
        (NULL, &anchor, NULL, &out), ==, WYRELOG_E_INVALID);
    g_assert_null (out);
  }

  purge_root (root);
  wyl_service_credential_operation_root_anchor_clear (&anchor);
  wyl_service_credential_operation_storage_clear (&storage);
  g_assert_cmpint (g_rmdir (root), ==, 0);
  g_assert_cmpint (g_rmdir (base), ==, 0);
}
#endif

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/operation-storage/enumerate/null-arguments",
      test_enumerate_rejects_null_arguments);
#ifndef G_OS_WIN32
  g_test_add_func ("/operation-storage/enumerate/posix-backend",
      test_posix_enumerate_backend);
#endif
  return g_test_run ();
}

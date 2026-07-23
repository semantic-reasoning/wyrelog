/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>

#include "auth/service-credential-operation-coordinator-status-private.h"
#include "auth/service-credential-operation-coordinator-storage-private.h"
#include "auth/service-credential-operation-storage-private.h"
#ifdef G_OS_WIN32
#include "auth/service-credential-operation-storage-windows-private.h"
#endif
#include "wyl-request-id-private.h"

static const gchar *const SUCCESSOR_CREDENTIAL_ID =
    "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";

static void
begin_prepared_issue (WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const gchar *request_id)
{
  WylServiceCredentialOperationCoordinatorRequest request =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  WylServiceCredentialOperationRecord begun =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  request.kind = WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE;
  request.request_id = (gchar *) request_id;
  request.subject_id = (gchar *) "svc:status:subject";
  request.tenant_id = (gchar *) "tenant-a";
  request.destination = (gchar *) "credential";
  request.parent_identity = (gchar *) "parent";
  request.actor_subject_id = (gchar *) "admin";
  request.escrow_id = (gchar *) "01890f47-3c4b-7cc2-b8c4-dc0c0c073991";
  memset (request.escrow_binding_digest, 0x31,
      sizeof request.escrow_binding_digest);
  request.expires_at_us = 1;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_begin_or_replay_for_test
      (storage, anchor, &request, 1, NULL, &begun), ==, WYRELOG_E_OK);
  g_assert_cmpint (begun.state, ==, WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED);
  wyl_service_credential_operation_record_clear (&begun);
}

static void
checkpoint_committed (WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const gchar *request_id)
{
  WylServiceCredentialOperationRecord committed =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  gboolean replayed = TRUE;
  g_assert_cmpint
      (wyl_service_credential_operation_coordinator_checkpoint_server_committed
      (storage, anchor, request_id, SUCCESSOR_CREDENTIAL_ID, 1, 2, &replayed,
          &committed), ==, WYRELOG_E_OK);
  g_assert_false (replayed);
  g_assert_cmpint (committed.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED);
  wyl_service_credential_operation_record_clear (&committed);
}

static GBytes *
snapshot_record_bytes (WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const gchar *request_id)
{
  WylServiceCredentialOperationRecord record =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  GBytes *bytes = NULL;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_load (storage,
          anchor, request_id, &record), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&record,
          &bytes), ==, WYRELOG_E_OK);
  wyl_service_credential_operation_record_clear (&record);
  return bytes;
}

static void
test_status_null_arguments (void)
{
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  WylServiceCredentialOperationStatusList out = {
    .entries = (WylServiceCredentialOperationStatusEntry *) 0x1,
    .n_entries = 99,
  };
  g_assert_cmpint (wyl_service_credential_operation_coordinator_status_list
      (NULL, &anchor, NULL, &out), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_status_list
      (&storage, NULL, NULL, &out), ==, WYRELOG_E_INVALID);
  /* out is left untouched by every rejected argument shape. */
  g_assert_true (out.entries == (WylServiceCredentialOperationStatusEntry *)
      0x1);
  g_assert_cmpuint (out.n_entries, ==, 99);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_status_list
      (&storage, &anchor, NULL, NULL), ==, WYRELOG_E_INVALID);
}

#ifndef G_OS_WIN32
static void
test_status_backend (void)
{
  g_autofree gchar *base = g_dir_make_tmp ("wyl-status-XXXXXX", NULL);
  g_autofree gchar *root = g_build_filename (base, "state", NULL);
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  gchar ids[3][WYL_REQUEST_ID_STRING_BUF];
  GHashTable *expected_state;
  g_assert_nonnull (base);
  g_assert_cmpint (wyl_service_credential_operation_storage_open (root,
          &storage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_storage_capture_anchor
      (&storage, &anchor), ==, WYRELOG_E_OK);

  /* (1) Empty root -> success and an empty listing. */
  {
    WylServiceCredentialOperationStatusList list = { 0 };
    g_assert_cmpint (wyl_service_credential_operation_coordinator_status_list
        (&storage, &anchor, NULL, &list), ==, WYRELOG_E_OK);
    g_assert_cmpuint (list.n_entries, ==, 0);
    wyl_service_credential_operation_status_list_clear (&list);
  }

  /* Create three PREPARED issue operations, then checkpoint the last one to
   * SERVER_COMMITTED so more than one durable .state value is exercised. */
  expected_state = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
      NULL);
  for (gsize i = 0; i < G_N_ELEMENTS (ids); i++) {
    g_assert_cmpint (wyl_request_id_new (ids[i], sizeof ids[i]), ==,
        WYRELOG_E_OK);
    begin_prepared_issue (&storage, &anchor, ids[i]);
    g_hash_table_insert (expected_state, g_strdup (ids[i]),
        GINT_TO_POINTER (WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED));
  }
  checkpoint_committed (&storage, &anchor, ids[G_N_ELEMENTS (ids) - 1]);
  g_hash_table_insert (expected_state,
      g_strdup (ids[G_N_ELEMENTS (ids) - 1]),
      GINT_TO_POINTER (WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED));

  /* (2) Exactly the created operations are returned, order independent, and
   * each entry's record.state matches what was durably written. */
  {
    GHashTable *seen = g_hash_table_new (g_str_hash, g_str_equal);
    WylServiceCredentialOperationStatusList list = { 0 };
    g_assert_cmpint (wyl_service_credential_operation_coordinator_status_list
        (&storage, &anchor, NULL, &list), ==, WYRELOG_E_OK);
    g_assert_cmpuint (list.n_entries, ==, G_N_ELEMENTS (ids));
    for (gsize i = 0; i < list.n_entries; i++) {
      const WylServiceCredentialOperationRecord *record =
          &list.entries[i].record;
      gpointer want;
      g_assert_nonnull (record->request_id);
      g_assert_true (g_hash_table_lookup_extended (expected_state,
              record->request_id, NULL, &want));
      g_assert_cmpint (record->state, ==, GPOINTER_TO_INT (want));
      /* No duplicate request ids in the listing. */
      g_assert_true (g_hash_table_add (seen, (gpointer) record->request_id));
    }
    g_assert_cmpuint (g_hash_table_size (seen), ==, G_N_ELEMENTS (ids));
    wyl_service_credential_operation_status_list_clear (&list);
    g_hash_table_unref (seen);
  }

  /* (3) READ-ONLY proof: durable bytes for a sampled operation are byte-for-
   * byte identical before and after a listing pass. */
  {
    g_autoptr (GBytes) before = snapshot_record_bytes (&storage, &anchor,
        ids[0]);
    WylServiceCredentialOperationStatusList list = { 0 };
    g_assert_cmpint (wyl_service_credential_operation_coordinator_status_list
        (&storage, &anchor, NULL, &list), ==, WYRELOG_E_OK);
    wyl_service_credential_operation_status_list_clear (&list);
    g_autoptr (GBytes) after = snapshot_record_bytes (&storage, &anchor,
        ids[0]);
    g_assert_true (g_bytes_equal (before, after));
  }

  /* (4) A foreign, non-operation child is ignored (inherited from the
   * enumeration primitive). */
  {
    g_autofree gchar *garbage = g_build_filename (storage.root_path,
        "garbage", NULL);
    WylServiceCredentialOperationStatusList list = { 0 };
    g_assert_true (g_file_set_contents (garbage, "x", 1, NULL));
    g_assert_cmpint (wyl_service_credential_operation_coordinator_status_list
        (&storage, &anchor, NULL, &list), ==, WYRELOG_E_OK);
    g_assert_cmpuint (list.n_entries, ==, G_N_ELEMENTS (ids));
    wyl_service_credential_operation_status_list_clear (&list);
    g_assert_cmpint (g_remove (garbage), ==, 0);
  }

  /* (5) Cancellation -> WYRELOG_E_CANCELLED and *out is untouched. */
  {
    GCancellable *cancellable = g_cancellable_new ();
    WylServiceCredentialOperationStatusList out = {
      .entries = (WylServiceCredentialOperationStatusEntry *) 0x1,
      .n_entries = 99,
    };
    g_cancellable_cancel (cancellable);
    g_assert_cmpint (wyl_service_credential_operation_coordinator_status_list
        (&storage, &anchor, cancellable, &out), ==, WYRELOG_E_CANCELLED);
    g_assert_true (out.entries ==
        (WylServiceCredentialOperationStatusEntry *) 0x1);
    g_assert_cmpuint (out.n_entries, ==, 99);
    g_object_unref (cancellable);
  }

  g_hash_table_unref (expected_state);
  wyl_service_credential_operation_root_anchor_clear (&anchor);
  wyl_service_credential_operation_storage_clear (&storage);
}
#endif

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/operation-status/null-arguments",
      test_status_null_arguments);
#ifndef G_OS_WIN32
  g_test_add_func ("/operation-status/backend", test_status_backend);
#endif
  return g_test_run ();
}

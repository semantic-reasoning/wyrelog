/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>
#include "wyrelog/auth/service-credential-operation-coordinator-journal-private.h"
#include "wyl-request-id-private.h"
static WylServiceCredentialOperationCoordinatorRequest
request (void)
{
  WylServiceCredentialOperationCoordinatorRequest r =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  r.kind = WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE;
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (request_id, sizeof request_id), ==,
      WYRELOG_E_OK);
  r.request_id = g_strdup (request_id);
  r.subject_id = g_strdup ("subject");
  r.tenant_id = g_strdup ("tenant");
  r.destination = g_strdup ("record");
  r.parent_identity = g_strdup ("parent");
  r.expires_at_us = 1;
  return r;
}

static void
test_builder (void)
{
  WylServiceCredentialOperationCoordinatorRequest r = request ();
  WylServiceCredentialOperationRecord out =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&r, "operation", 1, &out), ==, WYRELOG_E_OK);
  g_assert_cmpint (out.state, ==, WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED);
  g_assert_cmpstr (out.request_id, ==, r.request_id);
  g_assert_cmpint (out.created_at_us, ==, 1);
  g_autofree gchar *saved_operation = g_strdup (out.operation_id);
  g_autofree gchar *saved_request = g_strdup (out.request_id);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&r, "", 1, &out), ==, WYRELOG_E_INVALID);
  g_assert_cmpstr (out.operation_id, ==, saved_operation);
  g_assert_cmpstr (out.request_id, ==, saved_request);
  g_autofree gchar *too_long = g_malloc0 (4098);
  memset (too_long, 'x', 4097);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&r, too_long, 1, &out), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&r, "operation", 0, &out), ==, WYRELOG_E_INVALID);
  r.kind = WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE;
  g_clear_pointer (&r.tenant_id, g_free);
  r.old_credential_id = g_strdup ("wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv");
  r.expected_generation = 1;
  g_clear_pointer (&r.subject_id, g_free);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&r, "operation", 1, &out), ==, WYRELOG_E_INVALID);
  r.subject_id = g_strdup ("subject");
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&r, "operation", 1, &out), ==, WYRELOG_E_OK);
  g_assert_cmpint (out.kind, ==, WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE);
  g_assert_null (out.tenant_id);
  g_assert_cmpstr (out.old_credential_id, ==,
      "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv");
  g_assert_cmpuint (out.successor_generation, ==, 1);
  g_assert_cmpint (out.created_at_us, ==, 1);
  g_assert_cmpint (out.updated_at_us, ==, 1);
  g_autofree gchar *rotate_operation = g_strdup (out.operation_id);
  g_clear_pointer (&r.subject_id, g_free);
  g_assert_cmpint (wyl_service_credential_operation_coordinator_build_prepared
      (&r, "operation", 1, &out), ==, WYRELOG_E_INVALID);
  g_assert_cmpstr (out.operation_id, ==, rotate_operation);
  r.subject_id = g_strdup ("subject");
  wyl_service_credential_operation_record_clear (&out);
  wyl_service_credential_operation_coordinator_request_clear (&r);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/coordinator/journal/builder", test_builder);
  return g_test_run ();
}

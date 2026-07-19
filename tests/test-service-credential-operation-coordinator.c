/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include "wyrelog/auth/service-credential-operation-destination-private.h"
#include "wyrelog/auth/service-credential-operation-coordinator-private.h"

static void
test_destination_validator (void)
{
  static const gchar *invalid[] = {
    "", ".", "..", "nested/file", "../file", "/absolute", "\\absolute",
    "bad\\path", "C:relative", "CON", "con.json", "PRN", "aux.log",
    "NUL", "COM1", "com9.json", "LPT1", "lpt9.txt", "trailing.",
    "trailing ", "bad<name", "bad>name", "bad\"name", "bad|name",
    "bad?name", "bad*name", "bad\037name",
  };
  static const gchar *valid[] = {
    "credentials.json", "COM0", "COM10", "LPT0.txt", "LPT10.txt",
    "console.txt", "자격증명.json",
  };
  gchar malformed[] = { 'b', 'a', 'd', (gchar) 0xff, '\0' };
  g_autofree gchar *max_leaf = g_strnfill (255, 'a');
  g_autofree gchar *too_long = g_strnfill (256, 'a');

  g_assert_false (wyl_service_credential_operation_destination_is_valid (NULL));
  g_assert_false
      (wyl_service_credential_operation_destination_is_valid (malformed));
  g_assert_true
      (wyl_service_credential_operation_destination_is_valid (max_leaf));
  g_assert_false
      (wyl_service_credential_operation_destination_is_valid (too_long));
  for (gsize i = 0; i < G_N_ELEMENTS (invalid); i++)
    g_assert_false
        (wyl_service_credential_operation_destination_is_valid (invalid[i]));
  for (gsize i = 0; i < G_N_ELEMENTS (valid); i++)
    g_assert_true
        (wyl_service_credential_operation_destination_is_valid (valid[i]));
}

static void
test_request (void)
{
  WylServiceCredentialOperationCoordinatorRequest r =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  g_assert_false (wyl_service_credential_operation_coordinator_request_is_valid
      (&r));
  r.kind = WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE;
  r.request_id = g_strdup ("000000000000000000000000000");
  r.subject_id = g_strdup ("subject");
  r.tenant_id = g_strdup ("tenant");
  r.destination = g_strdup ("record");
  r.parent_identity = g_strdup ("parent");
  r.actor_subject_id = g_strdup ("admin");
  r.escrow_id = g_strdup ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991");
  for (guint i = 0; i < sizeof r.escrow_binding_digest; i++)
    r.escrow_binding_digest[i] = (guint8) (i + 1);
  r.expires_at_us = 1;
  r.expires_at_us = 1;
  r.parent_identity = g_strdup ("parent");
  g_free (r.actor_subject_id);
  r.actor_subject_id = NULL;
  g_assert_false (wyl_service_credential_operation_coordinator_request_is_valid
      (&r));
  r.actor_subject_id = g_strdup ("admin");
  g_free (r.actor_subject_id);
  r.actor_subject_id = g_strdup ("");
  g_assert_false (wyl_service_credential_operation_coordinator_request_is_valid
      (&r));
  g_free (r.actor_subject_id);
  r.actor_subject_id = g_strnfill (129, 'a');
  g_assert_false (wyl_service_credential_operation_coordinator_request_is_valid
      (&r));
  g_free (r.actor_subject_id);
  r.actor_subject_id = g_strdup ("admin");
  r.actor_subject_id[0] = (gchar) 0xff;
  g_assert_false (wyl_service_credential_operation_coordinator_request_is_valid
      (&r));
  r.actor_subject_id[0] = 'a';
  r.destination = g_strdup ("record");
  g_assert_true (wyl_service_credential_operation_coordinator_request_is_valid
      (&r));
  g_assert_cmpuint (r.expected_generation, ==, 0);
  r.expected_generation = 1;
  g_assert_false (wyl_service_credential_operation_coordinator_request_is_valid
      (&r));
  r.expected_generation = 0;
  r.request_id[0] = 'x';
  g_assert_false (wyl_service_credential_operation_coordinator_request_is_valid
      (&r));
  r.request_id[0] = '0';
  r.expires_at_us = 0;
  g_assert_false (wyl_service_credential_operation_coordinator_request_is_valid
      (&r));
  r.expires_at_us = 1;
  g_free (r.tenant_id);
  r.tenant_id = NULL;
  r.old_credential_id = g_strdup ("wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv");
  r.expected_generation = 1;
  r.kind = WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE;
  g_assert_true (wyl_service_credential_operation_coordinator_request_is_valid
      (&r));
  g_free (r.parent_identity);
  r.parent_identity = NULL;
  g_assert_false (wyl_service_credential_operation_coordinator_request_is_valid
      (&r));
  r.parent_identity = g_strdup ("parent");
  r.tenant_id = g_strdup ("forbidden");
  g_assert_false (wyl_service_credential_operation_coordinator_request_is_valid
      (&r));
  g_free (r.tenant_id);
  r.tenant_id = NULL;
  g_free (r.destination);
  r.destination = g_strdup ("../escape");
  g_assert_false (wyl_service_credential_operation_coordinator_request_is_valid
      (&r));
  g_free (r.destination);
  r.destination = g_strdup ("bad\\path");
  g_assert_false (wyl_service_credential_operation_coordinator_request_is_valid
      (&r));
  wyl_service_credential_operation_coordinator_request_clear (&r);
  g_assert_null (r.request_id);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/coordinator/destination-validator",
      test_destination_validator);
  g_test_add_func ("/coordinator/request", test_request);
  return g_test_run ();
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "wyrelog/policy/store-private.h"

#define DIGEST64 \
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define DIGEST64_ALT \
  "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

static wyl_policy_store_t *
open_store (void)
{
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_nonnull (store);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  return store;
}

static wyl_policy_service_permission_receipt_t
sample_receipt (const gchar *request_id, const gchar *audit_id,
    guint64 pre_generation, guint64 post_generation)
{
  wyl_policy_service_permission_receipt_t receipt = { 0 };
  receipt.request_id = (gchar *) request_id;
  receipt.actor_identity = (gchar *) "svc:tenant-a:remediator";
  receipt.audit_id = (gchar *) audit_id;
  receipt.manifest_fingerprint = (gchar *) DIGEST64;
  receipt.operation_count = 3;
  receipt.applied_at_us = 1700000000000000;
  receipt.pre_generation = pre_generation;
  receipt.pre_digest = (gchar *) DIGEST64;
  receipt.post_generation = post_generation;
  receipt.post_digest = (gchar *) DIGEST64_ALT;
  return receipt;
}

/* Insert one receipt, then look it up: every field round-trips and the schema
 * validator still accepts the store with the new table populated. */
static void
test_insert_then_lookup (void)
{
  g_autoptr (wyl_policy_store_t) store = open_store ();

  wyl_policy_service_permission_receipt_t in =
      sample_receipt ("req-lookup-1", "audit-abc", 7, 42);
  g_assert_cmpint (wyl_policy_store_service_permission_receipt_insert (store,
          &in), ==, WYRELOG_E_OK);

  gboolean found = FALSE;
  wyl_policy_service_permission_receipt_t out = { 0 };
  g_assert_cmpint (wyl_policy_store_service_permission_receipt_lookup (store,
          "req-lookup-1", &found, &out), ==, WYRELOG_E_OK);
  g_assert_true (found);
  g_assert_cmpstr (out.request_id, ==, "req-lookup-1");
  g_assert_cmpstr (out.actor_identity, ==, "svc:tenant-a:remediator");
  g_assert_cmpstr (out.audit_id, ==, "audit-abc");
  g_assert_cmpstr (out.manifest_fingerprint, ==, DIGEST64);
  g_assert_cmpuint (out.operation_count, ==, 3);
  g_assert_cmpint (out.applied_at_us, ==, 1700000000000000);
  g_assert_cmpuint (out.pre_generation, ==, 7);
  g_assert_cmpstr (out.pre_digest, ==, DIGEST64);
  g_assert_cmpuint (out.post_generation, ==, 42);
  g_assert_cmpstr (out.post_digest, ==, DIGEST64_ALT);
  wyl_policy_service_permission_receipt_clear (&out);

  /* A NULL audit_id round-trips as absent. */
  wyl_policy_service_permission_receipt_t in_null =
      sample_receipt ("req-lookup-2", NULL, 1, 2);
  g_assert_cmpint (wyl_policy_store_service_permission_receipt_insert (store,
          &in_null), ==, WYRELOG_E_OK);
  found = FALSE;
  memset (&out, 0, sizeof out);
  g_assert_cmpint (wyl_policy_store_service_permission_receipt_lookup (store,
          "req-lookup-2", &found, &out), ==, WYRELOG_E_OK);
  g_assert_true (found);
  g_assert_null (out.audit_id);
  wyl_policy_service_permission_receipt_clear (&out);

  g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
      WYRELOG_E_OK);
}

/* A miss reports not-found and leaves the out receipt zeroed. */
static void
test_lookup_missing (void)
{
  g_autoptr (wyl_policy_store_t) store = open_store ();

  gboolean found = TRUE;
  wyl_policy_service_permission_receipt_t out = { 0 };
  g_assert_cmpint (wyl_policy_store_service_permission_receipt_lookup (store,
          "absent", &found, &out), ==, WYRELOG_E_OK);
  g_assert_false (found);
  g_assert_null (out.request_id);
  wyl_policy_service_permission_receipt_clear (&out);
}

/* A second insert with the same request id is a primary-key conflict: the
 * helper reports it and the stored row is unchanged. */
static void
test_duplicate_request_id_conflicts (void)
{
  g_autoptr (wyl_policy_store_t) store = open_store ();
  sqlite3 *db = wyl_policy_store_get_db (store);
  g_assert_nonnull (db);

  wyl_policy_service_permission_receipt_t first =
      sample_receipt ("req-dup", "audit-1", 1, 2);
  g_assert_cmpint (wyl_policy_store_service_permission_receipt_insert (store,
          &first), ==, WYRELOG_E_OK);

  wyl_policy_service_permission_receipt_t second =
      sample_receipt ("req-dup", "audit-2", 9, 10);
  g_assert_cmpint (wyl_policy_store_service_permission_receipt_insert (store,
          &second), ==, WYRELOG_E_POLICY);

  /* Direct duplicate insert surfaces SQLITE_CONSTRAINT at the SQL layer. */
  int rc = sqlite3_exec (db,
      "INSERT INTO service_permission_remediation_receipts ("
      " request_id, actor_identity, manifest_fingerprint, operation_count,"
      " applied_at_us, pre_generation, pre_digest, post_generation,"
      " post_digest) VALUES ('req-dup','svc:x','" DIGEST64 "',0,1,0,'" DIGEST64
      "',0,'" DIGEST64 "');", NULL, NULL, NULL);
  g_assert_cmpint (rc & 0xff, ==, SQLITE_CONSTRAINT);

  gboolean found = FALSE;
  wyl_policy_service_permission_receipt_t out = { 0 };
  g_assert_cmpint (wyl_policy_store_service_permission_receipt_lookup (store,
          "req-dup", &found, &out), ==, WYRELOG_E_OK);
  g_assert_true (found);
  g_assert_cmpstr (out.audit_id, ==, "audit-1");
  g_assert_cmpuint (out.pre_generation, ==, 1);
  wyl_policy_service_permission_receipt_clear (&out);
}

/* UPDATE and DELETE on the table are blocked by the immutability triggers, and
 * validate_service_schema still accepts the store afterwards. */
static void
test_immutability_triggers (void)
{
  g_autoptr (wyl_policy_store_t) store = open_store ();
  sqlite3 *db = wyl_policy_store_get_db (store);
  g_assert_nonnull (db);

  wyl_policy_service_permission_receipt_t in =
      sample_receipt ("req-immutable", "audit-x", 5, 6);
  g_assert_cmpint (wyl_policy_store_service_permission_receipt_insert (store,
          &in), ==, WYRELOG_E_OK);

  int rc = sqlite3_exec (db,
      "UPDATE service_permission_remediation_receipts"
      " SET operation_count = 99 WHERE request_id = 'req-immutable';",
      NULL, NULL, NULL);
  g_assert_cmpint (rc & 0xff, ==, SQLITE_CONSTRAINT);

  rc = sqlite3_exec (db,
      "DELETE FROM service_permission_remediation_receipts"
      " WHERE request_id = 'req-immutable';", NULL, NULL, NULL);
  g_assert_cmpint (rc & 0xff, ==, SQLITE_CONSTRAINT);

  /* The row is intact and the schema is still valid. */
  gboolean found = FALSE;
  wyl_policy_service_permission_receipt_t out = { 0 };
  g_assert_cmpint (wyl_policy_store_service_permission_receipt_lookup (store,
          "req-immutable", &found, &out), ==, WYRELOG_E_OK);
  g_assert_true (found);
  g_assert_cmpuint (out.operation_count, ==, 3);
  wyl_policy_service_permission_receipt_clear (&out);

  g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
      WYRELOG_E_OK);
}

/* The persisted generation counter starts at zero and advances by one per
 * inserted receipt. */
static void
test_generation_counter (void)
{
  g_autoptr (wyl_policy_store_t) store = open_store ();

  guint64 generation = 123;
  g_assert_cmpint (wyl_policy_store_service_permission_remediation_generation
      (store, &generation), ==, WYRELOG_E_OK);
  g_assert_cmpuint (generation, ==, 0);

  wyl_policy_service_permission_receipt_t first =
      sample_receipt ("req-gen-1", NULL, 1, 2);
  g_assert_cmpint (wyl_policy_store_service_permission_receipt_insert (store,
          &first), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_permission_remediation_generation
      (store, &generation), ==, WYRELOG_E_OK);
  g_assert_cmpuint (generation, ==, 1);

  wyl_policy_service_permission_receipt_t second =
      sample_receipt ("req-gen-2", NULL, 2, 3);
  g_assert_cmpint (wyl_policy_store_service_permission_receipt_insert (store,
          &second), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_permission_remediation_generation
      (store, &generation), ==, WYRELOG_E_OK);
  g_assert_cmpuint (generation, ==, 2);

  /* A conflicting insert does not advance the counter. */
  wyl_policy_service_permission_receipt_t dup =
      sample_receipt ("req-gen-2", NULL, 2, 3);
  g_assert_cmpint (wyl_policy_store_service_permission_receipt_insert (store,
          &dup), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_policy_store_service_permission_remediation_generation
      (store, &generation), ==, WYRELOG_E_OK);
  g_assert_cmpuint (generation, ==, 2);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/service-permission-receipt/insert-then-lookup",
      test_insert_then_lookup);
  g_test_add_func ("/service-permission-receipt/lookup-missing",
      test_lookup_missing);
  g_test_add_func ("/service-permission-receipt/duplicate-conflicts",
      test_duplicate_request_id_conflicts);
  g_test_add_func ("/service-permission-receipt/immutability-triggers",
      test_immutability_triggers);
  g_test_add_func ("/service-permission-receipt/generation-counter",
      test_generation_counter);
  return g_test_run ();
}

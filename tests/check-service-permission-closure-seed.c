/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Test helper for check-service-permission-closure.sh. The offline
 * service-permission-closure CLI operates on an encrypted policy store, so the
 * shell harness cannot seed or inspect store rows with sqlite3 directly. This
 * helper opens the store under its owner-only KeyProvider and provides the few
 * primitives the script needs:
 *
 *   seed <store> <key>       create the store, install the schema, and inject
 *                            an unsafe service permission closure, then persist.
 *   removals <store> <key>   print "removals=N" for the current closure.
 *   receipts <store> <key>   print "receipts=N" durable remediation receipts.
 *
 * All opens are non-maintenance: the harness runs these while the daemon is
 * stopped and never contends with a maintenance-exclusive lease.
 */
#if defined(__unix__) || defined(__APPLE__)
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#endif

#include <glib.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-keyprovider-file-private.h"

static wyl_policy_store_t *
open_store (const gchar *store_path, const gchar *key_path)
{
  wyl_keyprovider_file_t *keyprovider = wyl_keyprovider_file_new (key_path);
  if (keyprovider == NULL) {
    g_printerr ("seed-helper: cannot mint keyprovider from %s\n", key_path);
    return NULL;
  }
  wyl_policy_store_open_options_t opts = {
    .path = store_path,
    .keyprovider_vtable = wyl_keyprovider_file_get_vtable (),
    .keyprovider_state = keyprovider,
    .keyprovider_state_free = (void (*)(gpointer)) wyl_keyprovider_file_free,
    .require_encrypted = TRUE,
  };
  wyl_policy_store_t *store = NULL;
  wyrelog_error_t rc = wyl_policy_store_open_with_options (&opts, &store);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("seed-helper: open %s failed: %s\n", store_path,
        wyrelog_error_string (rc));
    return NULL;
  }
  return store;
}

static guint
removal_count (wyl_policy_store_t *store)
{
  WylPolicyPermissionClosureAnalysis analysis = { 0 };
  if (wyl_policy_store_analyze_service_permission_closure (store, &analysis)
      != WYRELOG_E_OK) {
    wyl_policy_permission_closure_analysis_clear (&analysis);
    return G_MAXUINT;
  }
  guint n = analysis.removals->len;
  wyl_policy_permission_closure_analysis_clear (&analysis);
  return n;
}

static int
cmd_seed (const gchar *store_path, const gchar *key_path)
{
  wyl_policy_store_t *store = open_store (store_path, key_path);
  if (store == NULL)
    return 1;
  int rc = 0;
  /* A bare seeder-created store needs the schema installed; a store already
   * provisioned by wyrelogd from templates must NOT be re-created, which would
   * disturb the shape the daemon expects on its next boot. */
  gboolean has_schema = FALSE;
  if (wyl_policy_store_table_exists (store, "direct_permissions", &has_schema)
      != WYRELOG_E_OK) {
    g_printerr ("seed-helper: schema probe failed\n");
    rc = 1;
  }
  if (rc == 0 && !has_schema
      && wyl_policy_store_create_schema (store) != WYRELOG_E_OK) {
    g_printerr ("seed-helper: create_schema failed\n");
    rc = 1;
  }
  sqlite3 *db = wyl_policy_store_get_db (store);
  /* An unregistered "svc:" subject holding direct, non-allowlisted permissions
   * is a dangling-subject closure violation; each grant is one removal. */
  if (rc == 0 && sqlite3_exec (db,
          "INSERT INTO permissions(perm_id,perm_name,class) VALUES"
          " ('wr.stream.write','stream write','basic'),"
          " ('wr.stream.admin','stream admin','basic');"
          "INSERT INTO direct_permissions(subject_id,perm_id,scope) VALUES"
          " ('svc:tenant-a:worker','wr.stream.write','*'),"
          " ('svc:tenant-a:worker','wr.stream.admin','*');", NULL, NULL,
          NULL) != SQLITE_OK) {
    g_printerr ("seed-helper: seeding grants failed: %s\n",
        sqlite3_errmsg (db));
    rc = 1;
  }
  if (rc == 0 && removal_count (store) != 2) {
    g_printerr ("seed-helper: seeded closure did not yield 2 removals\n");
    rc = 1;
  }
  wyl_policy_store_close (store);
  return rc;
}

static int
cmd_removals (const gchar *store_path, const gchar *key_path)
{
  wyl_policy_store_t *store = open_store (store_path, key_path);
  if (store == NULL)
    return 1;
  guint n = removal_count (store);
  wyl_policy_store_close (store);
  if (n == G_MAXUINT) {
    g_printerr ("seed-helper: analyze failed\n");
    return 1;
  }
  g_print ("removals=%u\n", n);
  return 0;
}

static int
cmd_receipts (const gchar *store_path, const gchar *key_path)
{
  wyl_policy_store_t *store = open_store (store_path, key_path);
  if (store == NULL)
    return 1;
  sqlite3 *db = wyl_policy_store_get_db (store);
  sqlite3_stmt *stmt = NULL;
  int rc = 0;
  if (sqlite3_prepare_v2 (db,
          "SELECT count(*) FROM service_permission_remediation_receipts;", -1,
          &stmt, NULL) != SQLITE_OK || sqlite3_step (stmt) != SQLITE_ROW) {
    g_printerr ("seed-helper: receipt count failed\n");
    rc = 1;
  } else {
    g_print ("receipts=%lld\n", (long long) sqlite3_column_int64 (stmt, 0));
  }
  sqlite3_finalize (stmt);
  wyl_policy_store_close (store);
  return rc;
}

int
main (int argc, char **argv)
{
  if (argc != 4) {
    g_printerr ("usage: %s seed|removals|receipts <store> <key>\n", argv[0]);
    return 2;
  }
  if (g_strcmp0 (argv[1], "seed") == 0)
    return cmd_seed (argv[2], argv[3]);
  if (g_strcmp0 (argv[1], "removals") == 0)
    return cmd_removals (argv[2], argv[3]);
  if (g_strcmp0 (argv[1], "receipts") == 0)
    return cmd_receipts (argv[2], argv[3]);
  g_printerr ("%s: unknown command %s\n", argv[0], argv[1]);
  return 2;
}

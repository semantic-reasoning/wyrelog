/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"

#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <stdlib.h>
#ifdef G_OS_WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include "wyrelog/policy/store-private.h"

static int
run_child (int argc, char **argv)
{
  if (argc == 5 && g_strcmp0 (argv[1], "--crash-child") == 0){
    wyl_policy_store_open_options_t options = { .path = argv[2] };
    g_autoptr (wyl_policy_store_t) store = NULL;
    if (wyl_policy_store_open_with_options (&options, &store)
        != WYRELOG_E_OK)
      return 20;
    g_autofree gchar *operation_uuid = NULL;
    if (wyl_policy_store_reserve_fact_open (store, argv[4], argv[3],
        "crash-tenant", "crash-graph", "crash-root", "crash-token",
        &operation_uuid) != WYRELOG_E_OK)
      return 21;
    /* Model a process crash after the durable reservation commit. */
    WYL_TEST_EXIT (0);
  }
  if (argc != 6 || g_strcmp0 (argv[1], "--child") != 0)
    return -1;
  const gchar *path = argv[2];
  const gchar *owner = argv[3];
  const gchar *reservation_id = argv[4];
  const gchar *gate = argv[5];
  g_autofree gchar *marker = g_build_filename (gate, owner, NULL);
  g_autoptr (GError) error = NULL;
  if (!g_file_set_contents (marker, "ready\n", -1, &error))
    return 10;

  g_autofree gchar *other = g_build_filename (gate,
          g_strcmp0 (owner, "race-owner-a") == 0
        ? "race-owner-b" : "race-owner-a", NULL);
  gint64 deadline = g_get_monotonic_time () + 10 * G_USEC_PER_SEC;
  while (!g_file_test (other, G_FILE_TEST_EXISTS)
      && g_get_monotonic_time () < deadline)
    g_usleep (1000);
  if (!g_file_test (other, G_FILE_TEST_EXISTS))
    return 11;

  wyl_policy_store_open_options_t options = { .path = path };
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_autofree gchar *operation_uuid = NULL;
  wyrelog_error_t rc = WYRELOG_E_BUSY;
  gboolean opened = FALSE;
  for (guint retry = 0; retry < 5000 && rc == WYRELOG_E_BUSY; retry++){
    if (store == NULL){
      /* Reopening races the other process for the same file, so the open
       * reports the contention this test exists to create: BUSY for the
       * non-blocking lease, IO for a lock the driver could not take.  Both
       * rejoin the retry budget; treating either as fatal fails the run
       * whenever the peer happens to hold the file at reopen time. */
      wyrelog_error_t open_rc = wyl_policy_store_open_with_options (&options,
              &store);
      if (open_rc == WYRELOG_E_BUSY || open_rc == WYRELOG_E_IO){
        g_clear_pointer (&store, wyl_policy_store_close);
        g_usleep (g_strcmp0 (owner, "race-owner-a") == 0 ? 1000 : 7000);
        continue;
      }
      if (open_rc != WYRELOG_E_OK){
        g_printerr ("child %s store open failed rc=%d\n", owner, open_rc);
        return 12;
      }
      opened = TRUE;
    }
    rc = wyl_policy_store_reserve_fact_open (store, reservation_id, owner,
            "race-tenant", "race-graph", "race-root", "race-token",
            &operation_uuid);
    if (rc == WYRELOG_E_BUSY){
      /* A failed nonblocking lease upgrade retains a shared lease. Drop
       * it before retrying so two simultaneous upgraders cannot keep one
       * another permanently out of the exclusive writer slot. */
      g_clear_pointer (&store, wyl_policy_store_close);
      /* Keep retries from remaining phase-aligned after both processes
       * observe the same initial contention. */
      g_usleep (g_strcmp0 (owner, "race-owner-a") == 0 ? 1000 : 7000);
    }
  }
  if (!opened){
    g_printerr ("child %s never opened the store within the retry budget\n",
        owner);
    return 12;
  }
  if (rc == WYRELOG_E_OK)
    g_print ("OK\n");
  else if (rc == WYRELOG_E_POLICY)
    g_print ("POLICY\n");
  else if (rc == WYRELOG_E_BUSY)
    g_print ("BUSY\n");
  else
    g_print ("ERROR:%d\n", rc);
  return 0;
}

static gboolean
spawn_attempt (const gchar *program, const gchar *path, const gchar *owner,
    const gchar *reservation_id, const gchar *gate, GSubprocess **out)
{
  const gchar *argv[] = {
    program, "--child", path, owner, reservation_id, gate, NULL,
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (GSubprocessLauncher) launcher = g_subprocess_launcher_new (
    G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE);
  *out = g_subprocess_launcher_spawnv (launcher, argv, &error);
  if (*out == NULL){
    g_printerr ("failed to spawn %s: %s\n", owner, error->message);
    return FALSE;
  }
  return TRUE;
}

static gboolean
spawn_crash_attempt (const gchar *program, const gchar *path,
    const gchar *owner, const gchar *reservation_id, GSubprocess **out)
{
  const gchar *argv[] = {
    program, "--crash-child", path, owner, reservation_id, NULL,
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (GSubprocessLauncher) launcher = g_subprocess_launcher_new (
    G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE);
  *out = g_subprocess_launcher_spawnv (launcher, argv, &error);
  if (*out == NULL){
    g_printerr ("failed to spawn crash child: %s\n", error->message);
    return FALSE;
  }
  return TRUE;
}

static gboolean
child_output_is (GSubprocess *child, const gchar *expected,
    gchar **out_output)
{
  g_autoptr (GError) error = NULL;
  gchar *stdout_text = NULL;
  gchar *stderr_text = NULL;
  if (!g_subprocess_communicate_utf8 (child, NULL, NULL, &stdout_text,
      &stderr_text, &error)){
    g_printerr ("child communication failed: %s\n", error->message);
    g_free (stdout_text);
    g_free (stderr_text);
    return FALSE;
  }
  if (stderr_text != NULL && *stderr_text != '\0')
    g_printerr ("child diagnostics: %s", stderr_text);
  g_free (stderr_text);
  g_strstrip (stdout_text);
  if (out_output != NULL)
    *out_output = stdout_text;
  else
    g_free (stdout_text);
  return g_strcmp0 (stdout_text, expected) == 0;
}

static gboolean
run_crash_recovery (const gchar *program, const gchar *root)
{
  g_autofree gchar *path = g_build_filename (root, "crash.sqlite", NULL);
  wyl_policy_store_open_options_t options = { .path = path };
  g_autoptr (wyl_policy_store_t) setup = NULL;
  if (wyl_policy_store_open_with_options (&options, &setup) != WYRELOG_E_OK
      || wyl_policy_store_create_schema (setup) != WYRELOG_E_OK)
    return FALSE;
  gboolean created = FALSE;
  if (wyl_policy_store_create_tenant (setup, "crash-tenant", &created)
      != WYRELOG_E_OK || !created
      || wyl_policy_store_register_fact_open_owner (setup, "crash-owner")
      != WYRELOG_E_OK
      || wyl_policy_store_set_fact_concurrent_open_quota (setup,
      "crash-tenant", 1) != WYRELOG_E_OK)
    return FALSE;
  g_clear_pointer (&setup, wyl_policy_store_close);

  g_autoptr (GSubprocess) crashed = NULL;
  if (!spawn_crash_attempt (program, path, "crash-owner", "crash-reservation",
      &crashed))
    return FALSE;
  g_autoptr (GError) error = NULL;
  if (!g_subprocess_communicate_utf8 (crashed, NULL, NULL, NULL, NULL,
      &error) || !g_subprocess_get_successful (crashed))
    return FALSE;

  g_autoptr (wyl_policy_store_t) recovery = NULL;
  if (wyl_policy_store_open_with_options (&options, &recovery) != WYRELOG_E_OK
      || wyl_policy_store_register_fact_open_owner (recovery,
      "recovery-owner") != WYRELOG_E_OK
      || wyl_policy_store_retire_fact_open_owner (recovery, "crash-owner")
      != WYRELOG_E_OK
      || wyl_policy_store_claim_fact_open_recovery (recovery,
      "crash-reservation", "crash-owner", NULL, "recovery-owner",
      "recovery-claim") != WYRELOG_E_OK
      || wyl_policy_store_transition_fact_open (recovery, "crash-reservation",
      "recovery-owner", "recovery-claim", WYL_POLICY_FACT_OPEN_PENDING,
      WYL_POLICY_FACT_OPEN_CLEANUP_PENDING) != WYRELOG_E_OK
      || wyl_policy_store_settle_fact_open (recovery, "crash-reservation",
      "recovery-owner", "recovery-claim", TRUE) != WYRELOG_E_OK)
    return FALSE;

  WylPolicyFactConcurrentOpenQuotaStatus status = { 0 };
  if (wyl_policy_store_get_fact_concurrent_open_quota (recovery,
      "crash-tenant", &status) != WYRELOG_E_OK || status.charged != 0)
    return FALSE;
  g_clear_pointer (&recovery, wyl_policy_store_close);
  g_remove (path);
  return TRUE;
}

static int
run_parent (const gchar *program)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = g_dir_make_tmp ("wyrelog-fact-open-race-XXXXXX",
          &error);
  if (root == NULL){
    g_printerr ("temporary root failed: %s\n", error->message);
    return 1;
  }
  g_autofree gchar *path = g_build_filename (root, "policy.sqlite", NULL);
  g_autofree gchar *gate = g_build_filename (root, "gate", NULL);
  if (g_mkdir (gate, 0700) != 0)
    return 1;

  wyl_policy_store_open_options_t options = { .path = path };
  g_autoptr (wyl_policy_store_t) setup = NULL;
  if (wyl_policy_store_open_with_options (&options, &setup) != WYRELOG_E_OK
      || wyl_policy_store_create_schema (setup) != WYRELOG_E_OK)
    return 1;
  gboolean created = FALSE;
  if (wyl_policy_store_create_tenant (setup, "race-tenant", &created)
      != WYRELOG_E_OK || !created
      || wyl_policy_store_register_fact_open_owner (setup, "race-owner-a")
      != WYRELOG_E_OK
      || wyl_policy_store_register_fact_open_owner (setup, "race-owner-b")
      != WYRELOG_E_OK
      || wyl_policy_store_set_fact_concurrent_open_quota (setup,
      "race-tenant", 1) != WYRELOG_E_OK)
    return 1;
  g_clear_pointer (&setup, wyl_policy_store_close);

  g_autoptr (GSubprocess) first = NULL;
  g_autoptr (GSubprocess) second = NULL;
  if (!spawn_attempt (program, path, "race-owner-a", "race-reservation-a",
      gate, &first)
      || !spawn_attempt (program, path, "race-owner-b", "race-reservation-b",
      gate, &second))
    return 1;
  g_autofree gchar *first_output = NULL;
  g_autofree gchar *second_output = NULL;
  if (!child_output_is (first, "OK", &first_output)
      && g_strcmp0 (first_output, "POLICY") != 0
      && g_strcmp0 (first_output, "BUSY") != 0){
    g_printerr ("unexpected first child outcome '%s'\n",
        first_output != NULL ? first_output : "(null)");
    return 1;
  }
  if (!child_output_is (second, "OK", &second_output)
      && g_strcmp0 (second_output, "POLICY") != 0
      && g_strcmp0 (second_output, "BUSY") != 0){
    g_printerr ("unexpected second child outcome '%s'\n",
        second_output != NULL ? second_output : "(null)");
    return 1;
  }
  guint successes = (g_strcmp0 (first_output, "OK") == 0)
      + (g_strcmp0 (second_output, "OK") == 0);
  if (successes != 1){
    g_printerr ("expected one admitted process, got %s and %s\n",
        first_output, second_output);
    return 1;
  }

  if (!run_crash_recovery (program, root))
    return 1;

  g_autoptr (wyl_policy_store_t) verify = NULL;
  WylPolicyFactConcurrentOpenQuotaStatus status = { 0 };
  if (wyl_policy_store_open_with_options (&options, &verify) != WYRELOG_E_OK
      || wyl_policy_store_get_fact_concurrent_open_quota (verify,
      "race-tenant", &status) != WYRELOG_E_OK
      || status.charged != 1)
    return 1;
  g_remove (path);
  g_rmdir (gate);
  g_rmdir (root);
  return 0;
}

int
main (int argc, char **argv)
{
  int child_rc = run_child (argc, argv);
  if (child_rc >= 0)
    return wyl_test_normalize_exit_status (child_rc);
  return wyl_test_normalize_exit_status (run_parent (argv[0]));
}

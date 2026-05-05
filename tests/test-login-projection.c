/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <sqlite3.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/policy/store-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

static gboolean
policy_count_rows (wyl_policy_store_t *store, const gchar *sql,
    gint64 *out_count)
{
  sqlite3_stmt *stmt = NULL;

  if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), sql, -1, &stmt,
          NULL) != SQLITE_OK)
    return FALSE;

  gboolean ok = sqlite3_step (stmt) == SQLITE_ROW;
  if (ok)
    *out_count = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return ok;
}

static gint
check_login_reload_failure_keeps_durable_state_repairable (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 10;

  wyl_handle_set_engine_insert_fault_once (handle, "principal_state",
      WYRELOG_E_INTERNAL);

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "projection-reload-fail-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_INTERNAL)
    return 11;
  if (session != NULL)
    return 12;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gint64 count = -1;
  if (!policy_count_rows (store,
          "SELECT COUNT(*) FROM principal_states "
          "WHERE subject_id = 'projection-reload-fail-user' "
          "AND state = 'mfa_required';", &count))
    return 13;
  if (count != 1)
    return 14;
  if (!policy_count_rows (store,
          "SELECT COUNT(*) FROM session_states WHERE state = 'active';",
          &count))
    return 15;
  if (count != 1)
    return 16;
  if (!policy_count_rows (store,
          "SELECT COUNT(*) FROM audit_events "
          "WHERE action IN ('principal_state', 'session_state');", &count))
    return 17;
  if (count != 2)
    return 18;

  gboolean contains = FALSE;
  gint64 mfa_required[2];
  if (wyl_handle_intern_engine_symbol (handle, "projection-reload-fail-user",
          &mfa_required[0]) != WYRELOG_E_OK)
    return 19;
  if (wyl_handle_intern_engine_symbol (handle, "mfa_required",
          &mfa_required[1]) != WYRELOG_E_OK)
    return 20;
  if (wyl_handle_engine_contains (handle, "principal_state", mfa_required, 2,
          &contains) != WYRELOG_E_OK)
    return 21;
  if (contains)
    return 22;

  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 23;
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_login_reload_failure_keeps_durable_state_repairable ()) != 0)
    return rc;
  return 0;
}

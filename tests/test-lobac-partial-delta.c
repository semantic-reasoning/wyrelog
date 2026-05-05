/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/wyl-handle-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

static wyrelog_error_t
intern2 (WylHandle *handle, const gchar *a, const gchar *b, gint64 row[2])
{
  wyrelog_error_t rc = wyl_handle_intern_engine_symbol (handle, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_intern_engine_symbol (handle, b, &row[1]);
}

static gint
expect_partial_exec (WylHandle *handle, const gchar *relation,
    const gint64 *row, gsize ncols, gint insert_code, gint step_code)
{
  WylEngine *delta = wyl_handle_get_delta_engine (handle);
  if (delta == NULL)
    return insert_code + 1;
  if (wyl_engine_insert (delta, relation, row, ncols) != WYRELOG_E_OK)
    return insert_code + 2;
  if (wyl_engine_step (delta) != WYRELOG_E_EXEC)
    return step_code;
  return 0;
}

static gint
check_role_permission_partial_exec (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 row[2];

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 10;
  if (intern2 (handle, "wr.partial-role", "wr.partial-perm", row)
      != WYRELOG_E_OK)
    return 11;
  return expect_partial_exec (handle, "role_permission", row, 2, 12, 13);
}

int
main (void)
{
  gint rc;

  if (g_getenv ("WYL_TEST_LOBAC_PARTIAL_DELTA") == NULL)
    return 77;

  if ((rc = check_role_permission_partial_exec ()) != 0)
    return rc;
  return 0;
}

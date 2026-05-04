/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-handle-private.h"

static gint
check_store_creates_authority_schema (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 10;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 11;

  const gchar *tables[] = {
    "roles",
    "permissions",
    "role_permissions",
    "policy_signatures",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (tables); i++) {
    gboolean exists = FALSE;
    if (wyl_policy_store_table_exists (store, tables[i], &exists)
        != WYRELOG_E_OK)
      return 12;
    if (!exists)
      return 13;
  }

  return 0;
}

static gint
check_store_rejects_invalid_args (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 20;
  gboolean exists = FALSE;
  if (wyl_policy_store_create_schema (NULL) != WYRELOG_E_INVALID)
    return 21;
  if (wyl_policy_store_table_exists (NULL, "roles", &exists)
      != WYRELOG_E_INVALID)
    return 22;
  if (wyl_policy_store_table_exists (store, NULL, &exists)
      != WYRELOG_E_INVALID)
    return 23;
  if (wyl_policy_store_table_exists (store, "roles", NULL)
      != WYRELOG_E_INVALID)
    return 24;
  return 0;
}

static gint
check_handle_owns_policy_store (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 30;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (store == NULL)
    return 31;
  if (wyl_policy_store_get_db (store) == NULL)
    return 32;

  gboolean exists = FALSE;
  if (wyl_policy_store_table_exists (store, "role_permissions", &exists)
      != WYRELOG_E_OK)
    return 33;
  if (!exists)
    return 34;
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_store_creates_authority_schema ()) != 0)
    return rc;
  if ((rc = check_store_rejects_invalid_args ()) != 0)
    return rc;
  if ((rc = check_handle_owns_policy_store ()) != 0)
    return rc;
  return 0;
}

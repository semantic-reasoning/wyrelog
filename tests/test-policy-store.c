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
    "direct_permissions",
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

typedef struct
{
  const gchar *role_id;
  const gchar *perm_id;
  guint matches;
} RolePermissionExpect;

static wyrelog_error_t
role_permission_expect_cb (const gchar *role_id, const gchar *perm_id,
    gpointer user_data)
{
  RolePermissionExpect *expect = user_data;

  if (g_strcmp0 (role_id, expect->role_id) == 0
      && g_strcmp0 (perm_id, expect->perm_id) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static gint
check_store_grants_role_permission (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 40;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 41;
  if (wyl_policy_store_upsert_role (store, "wr.test-role", "test role")
      != WYRELOG_E_OK)
    return 42;
  if (wyl_policy_store_upsert_permission (store, "wr.test.read", "test read",
          "basic") != WYRELOG_E_OK)
    return 43;
  if (wyl_policy_store_grant_role_permission (store, "wr.test-role",
          "wr.test.read") != WYRELOG_E_OK)
    return 44;
  if (wyl_policy_store_grant_role_permission (store, "wr.test-role",
          "wr.test.read") != WYRELOG_E_OK)
    return 45;

  RolePermissionExpect expect = {
    .role_id = "wr.test-role",
    .perm_id = "wr.test.read",
  };
  if (wyl_policy_store_foreach_role_permission (store,
          role_permission_expect_cb, &expect) != WYRELOG_E_OK)
    return 46;
  if (expect.matches != 1)
    return 47;
  return 0;
}

static gint
check_store_grants_direct_permission (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 60;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 61;
  if (wyl_policy_store_upsert_permission (store, "wr.direct.read",
          "direct read", "basic") != WYRELOG_E_OK)
    return 62;
  if (wyl_policy_store_grant_direct_permission (store, "direct-user",
          "wr.direct.read", "direct-scope") != WYRELOG_E_OK)
    return 63;
  if (wyl_policy_store_grant_direct_permission (store, "direct-user",
          "wr.direct.read", "direct-scope") != WYRELOG_E_OK)
    return 64;

  gboolean exists = FALSE;
  if (wyl_policy_store_direct_permission_exists (store, "direct-user",
          "wr.direct.read", "direct-scope", &exists) != WYRELOG_E_OK)
    return 65;
  if (!exists)
    return 66;
  if (wyl_policy_store_revoke_direct_permission (store, "direct-user",
          "wr.direct.read", "direct-scope") != WYRELOG_E_OK)
    return 67;
  if (wyl_policy_store_direct_permission_exists (store, "direct-user",
          "wr.direct.read", "direct-scope", &exists) != WYRELOG_E_OK)
    return 68;
  if (exists)
    return 69;
  return 0;
}

static gint
check_store_rejects_bad_direct_permission (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  gboolean exists = FALSE;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 70;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 71;
  if (wyl_policy_store_grant_direct_permission (store, "direct-user",
          "missing-perm", "direct-scope") != WYRELOG_E_IO)
    return 72;
  if (wyl_policy_store_grant_direct_permission (NULL, "direct-user",
          "missing-perm", "direct-scope") != WYRELOG_E_INVALID)
    return 73;
  if (wyl_policy_store_revoke_direct_permission (store, NULL,
          "missing-perm", "direct-scope") != WYRELOG_E_INVALID)
    return 74;
  if (wyl_policy_store_direct_permission_exists (store, "direct-user",
          "missing-perm", "direct-scope", NULL) != WYRELOG_E_INVALID)
    return 75;
  if (wyl_policy_store_direct_permission_exists (store, "direct-user",
          "missing-perm", "direct-scope", &exists) != WYRELOG_E_OK)
    return 76;
  if (exists)
    return 77;
  return 0;
}

static gint
check_store_rejects_bad_role_permission (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 50;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 51;
  if (wyl_policy_store_grant_role_permission (store, "missing-role",
          "missing-perm") != WYRELOG_E_IO)
    return 52;
  if (wyl_policy_store_upsert_role (NULL, "role", "role") != WYRELOG_E_INVALID)
    return 53;
  if (wyl_policy_store_upsert_permission (store, "perm", "perm", "unknown")
      != WYRELOG_E_IO)
    return 54;
  if (wyl_policy_store_foreach_role_permission (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 55;
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
  if ((rc = check_store_grants_role_permission ()) != 0)
    return rc;
  if ((rc = check_store_grants_direct_permission ()) != 0)
    return rc;
  if ((rc = check_store_rejects_bad_direct_permission ()) != 0)
    return rc;
  if ((rc = check_store_rejects_bad_role_permission ()) != 0)
    return rc;
  return 0;
}

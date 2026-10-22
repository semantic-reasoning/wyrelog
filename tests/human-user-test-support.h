/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once
#include "wyrelog/policy/store-private.h"

/* Explicit fixture identities only. Never wrap grants/login with registration:
 * unknown-subject and migration tests must exercise the real boundary. */
static inline void
register_test_human (wyl_policy_store_t *store, const gchar *subject)
{
  if (wyl_policy_store_user_require (store, subject, TRUE) == WYRELOG_E_OK) return;
  gboolean owned = wyl_policy_store_transaction_owned_by_caller (store);
  if (!owned) g_assert_cmpint (wyl_policy_store_begin_mutation (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_user_register (store, subject), ==, WYRELOG_E_OK);
  if (!owned) g_assert_cmpint (wyl_policy_store_commit_mutation (store), ==, WYRELOG_E_OK);
}

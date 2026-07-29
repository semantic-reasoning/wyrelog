/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

#ifdef G_OS_WIN32
#include <windows.h>

G_BEGIN_DECLS
/* Private owner-only ACL material.  Call clear after a successful or partial
 * initialization; it owns both allocated members and no HANDLE. */
    typedef struct
{
  PSID user;
  PACL acl;
  SECURITY_DESCRIPTOR descriptor;
} WylFactGraphWinOwnerOnlySecurity;

/* Captured process-token identity for the narrowly permitted upgrade path. */
typedef struct
{
  PSID user;
  PSID owner;
} WylFactGraphWinTokenIdentity;

void wyl_fact_graph_win_token_identity_clear (WylFactGraphWinTokenIdentity *
    identity);
wyrelog_error_t
wyl_fact_graph_win_token_identity_init (WylFactGraphWinTokenIdentity *
    identity);

void
wyl_fact_graph_win_owner_only_security_clear (WylFactGraphWinOwnerOnlySecurity *
    security);
wyrelog_error_t
wyl_fact_graph_win_owner_only_security_init (WylFactGraphWinOwnerOnlySecurity *
    security, BYTE ace_flags);
wyrelog_error_t
    wyl_fact_graph_win_owner_only_security_init_for_user
    (WylFactGraphWinOwnerOnlySecurity * security, PSID user, BYTE ace_flags);

wyrelog_error_t wyl_fact_graph_win_validate_protected_owner_acl (HANDLE handle,
    BYTE ace_flags);
wyrelog_error_t wyl_fact_graph_win_validate_protected_owner_acl_for_user (HANDLE
    handle, PSID token_user, BYTE ace_flags);
wyrelog_error_t wyl_fact_graph_win_validate_owner_only_acl (HANDLE handle);
wyrelog_error_t wyl_fact_graph_win_validate_upgradeable_file_acl (HANDLE handle,
    const WylFactGraphWinTokenIdentity * identity);

G_END_DECLS
#endif

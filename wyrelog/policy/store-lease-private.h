/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

typedef struct wyl_policy_store_lease_t wyl_policy_store_lease_t;

typedef struct
{
  gboolean valid;
  guint64 device;
  guint64 file;
  guint64 owner;
  guint32 mode;
  guint32 nlink;
} WylPolicyStoreFileIdentity;

wyrelog_error_t wyl_policy_store_lease_acquire (const gchar * path,
    wyl_policy_store_lease_t ** out_lease);
wyrelog_error_t wyl_policy_store_lease_acquire_maintenance (const gchar * path,
    wyl_policy_store_lease_t ** out_lease);
wyrelog_error_t wyl_policy_store_lease_verify_store_identity (const
    wyl_policy_store_lease_t * lease);
/* Drop the pinned store-file handle once its identity has been verified so a
 * platform whose atomic replace cannot rename over an open target name (Windows
 * MoveFileExW) can persist; a no-op where an open handle does not block the
 * replace (POSIX renameat). Must be called only after
 * wyl_policy_store_lease_verify_store_identity has succeeded. */
void wyl_policy_store_lease_release_store_pin (wyl_policy_store_lease_t *
    lease);
/* Re-pin the canonical file after an in-lifetime atomic replacement and
 * replace the remembered identity with the newly published inode. */
wyrelog_error_t wyl_policy_store_lease_refresh_store_pin
  (wyl_policy_store_lease_t * lease,
    const WylPolicyStoreFileIdentity * expected_identity);
void wyl_policy_store_lease_release (wyl_policy_store_lease_t * lease);

const gchar *wyl_policy_store_lease_resolved_path (const
    wyl_policy_store_lease_t * lease);
wyrelog_error_t wyl_policy_store_lease_verify_parent (const
    wyl_policy_store_lease_t * lease);

#ifndef G_OS_WIN32
int wyl_policy_store_lease_parent_dirfd (const
    wyl_policy_store_lease_t * lease);
const gchar *wyl_policy_store_lease_basename (const
    wyl_policy_store_lease_t * lease);
#endif

/*
 * Raw-fork policy: no pthread_atfork handlers are installed. A child forked
 * while any live Wyrelog state exists must call exec* or _exit immediately.
 * It must not call any Wyrelog API, close/free inherited Wyrelog state, log,
 * format an error, or call C exit(). All lease descriptors are CLOEXEC and
 * Windows lease handles are non-inheritable.
 */

G_END_DECLS;

/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

typedef struct wyl_policy_store_lease_t wyl_policy_store_lease_t;

wyrelog_error_t wyl_policy_store_lease_acquire (const gchar * path,
    wyl_policy_store_lease_t ** out_lease);
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

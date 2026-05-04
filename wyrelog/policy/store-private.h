/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <sqlite3.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

typedef struct wyl_policy_store_t wyl_policy_store_t;

/*
 * Policy authority store lifecycle wrapper.
 *
 * v0 uses SQLite directly so the handle owns a real ACID policy DB before
 * SQLCipher key negotiation is wired in. The private boundary keeps callers
 * out of the raw sqlite3 handle except for tests and future migrator code.
 */
wyrelog_error_t wyl_policy_store_open (const gchar * path,
    wyl_policy_store_t ** out_store);
void wyl_policy_store_close (wyl_policy_store_t * store);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (wyl_policy_store_t, wyl_policy_store_close);

sqlite3 *wyl_policy_store_get_db (wyl_policy_store_t * store);

wyrelog_error_t wyl_policy_store_create_schema (wyl_policy_store_t * store);
wyrelog_error_t wyl_policy_store_table_exists (wyl_policy_store_t * store,
    const gchar * table_name, gboolean * out_exists);

G_END_DECLS;

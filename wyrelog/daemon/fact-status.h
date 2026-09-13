/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/wyrelog.h"

G_BEGIN_DECLS;

/* Render fact-subsystem status as JSON.
 *
 * include_graphs selects whether the per-graph rows are emitted at all;
 * tenant_filter selects whose rows they are.  NULL means every tenant, and a
 * tenant id restricts both the rows and the counts to that tenant (#1031) --
 * the counts too, because how many graphs another tenant holds is itself
 * theirs and not the caller's. */
gchar *wyl_daemon_fact_status_json (WylHandle * handle,
    gboolean include_graphs, const gchar * tenant_filter);

G_END_DECLS;

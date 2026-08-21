/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "policy/store-private.h"
#include "fact/store-private.h"

G_BEGIN_DECLS;

/* Open the live secure store handle for a provisioning or active graph.  Reads
 * the graph authority: a provisioning graph is first driven to active by the
 * crash-safe coordinator (idempotent recovery), then the retained pair is
 * opened through the bounded secure filesystem with the authority's exact
 * identity.  A legacy, sealed, or degraded graph is not served here and returns
 * WYRELOG_E_POLICY -- callers keep the legacy path for legacy graphs. */
wyrelog_error_t wyl_fact_store_open_provisioned_graph
  (wyl_policy_store_t * policy_store, const gchar * fact_root,
    const gchar * tenant_id, const gchar * graph_id, gboolean writable,
    wyl_fact_store_t ** out_store);

G_END_DECLS;

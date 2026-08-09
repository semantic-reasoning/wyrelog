/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "fact/provisioning-private.h"
#include "policy/store-private.h"

G_BEGIN_DECLS;

#ifndef G_OS_WIN32
/* Crash-safe staged construction of a new per-graph DuckDB store from a durable
 * provisioning record and its authority.  Stages an exact provisioning file,
 * fsyncs it, atomically publishes it as the retained facts.duckdb pair (one
 * inode under both names at nlink 2), then initializes and validates the exact
 * store identity through the secure DuckDB filesystem bridge.  The pair is kept
 * at nlink 2: the secure open path revalidates that both names still bind the
 * same inode (an anti-swap invariant), so the staged name is never retired.  A
 * crash at any seam leaves the store recoverable by the record's operation UUID.
 * This is the fresh happy-path FS primitive; crash recovery and resume of an
 * already-published pair are owned by the provisioning coordinator, not here.
 * POSIX-only for now: the secure handoff consumes the exact retained pair. */
wyrelog_error_t wyl_fact_graph_provisioning_construct (const gchar * fact_root,
    const WylPolicyGraphProvisioningRecord * record,
    const WylPolicyGraphAuthorityRecord * authority);
#endif

G_END_DECLS;

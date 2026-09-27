/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "fact/offline-restore-stage-private.h"
#include "fact/replay-scheduler-private.h"
#include "fact/store-identity-types-private.h"
#include "policy/store-private.h"

G_BEGIN_DECLS

/* Validate the reader-bound main-file bytes against persisted identity and a
 * sealed policy/schema snapshot, then replay all rows into a disposable
 * engine. The allocated digest is returned only after checked close and final
 * reader/content validation succeed; every failure clears the output.
 *
 * Run on one replay worker. The caller retains the reader and all its borrowed
 * root/directory authority through return. This function acquires no lifecycle
 * authority, validates no complete directory inventory, and authorizes no
 * journal or publication transition. Reader authority checks include known
 * operation-sidecar refusal; downstream publication still needs complete
 * inventory and fresh held-authority validation. Snapshot and content checks
 * are observations, not protection from external writers.
 * Windows fails closed. Requires the secure DuckDB bridge build feature. */
wyrelog_error_t wyl_fact_offline_restore_stage_replay_validate
  (wyl_policy_store_t *policy, WylFactOfflineRestoreStageReader *reader,
    guint64 expected_bytes, const gchar *expected_checksum,
    const WylFactStoreIdentity *expected_identity,
    const wyl_policy_fact_graph_info_t *graph_info,
    const gchar *expected_schema_digest,
    WylFactReplayJobContext *job_context, gchar **out_schema_digest);

G_END_DECLS

/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "fact/graph-locator-private.h"
#include "fact/runtime-private.h"
#include "policy/store-private.h"

G_BEGIN_DECLS

/* Callback-scoped, copied observation. It grants no publication or policy
 * authority and cannot be used as evidence for a later filesystem effect. */
typedef struct
{
  gchar *operation_uuid;
  gchar *tenant_id;
  gchar *graph_id;
  gchar *store_uuid;
  gchar *old_provisioning_uuid;
  gchar *replacement_uuid;
  gchar *replacement_phase;
  guint64 journal_revision;
  WylFactArtifactInventoryIdentity old_main;
  WylFactArtifactInventoryIdentity new_main;
  WylFactGraphRestorePostPublishLayout layout;
} WylFactGraphCommitInspection;

typedef wyrelog_error_t (*WylFactGraphCommitInspectionFunc)
  (const WylFactGraphCommitInspection *inspection, gpointer user_data);

/* Linux-only, read-only inspection of an imported durable graph mode-A COMMIT
 * state. All lease, resolver, directory, runtime and witness handles remain
 * private and are released on return. Normal mode-A COMMIT admission and
 * recovery remain closed. The callback must not retain inspection pointers;
 * its result is a historical observation, never a mutation permit. */
wyrelog_error_t wyl_fact_offline_restore_graph_commit_inspect
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactGraphCommitInspectionFunc callback, gpointer user_data);

G_END_DECLS

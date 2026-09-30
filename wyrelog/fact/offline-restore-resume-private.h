/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "fact/offline-restore-journal-private.h"
#include "fact/runtime-private.h"
#include "policy/store-private.h"

G_BEGIN_DECLS

/* Advances at most one durable v5 tenant COMMIT filesystem step. Each call
 * selects work from the freshly loaded journal, passes its exact revision to
 * the existing authority-holding driver, and returns only that driver's
 * committed journal. An error leaves output empty; a new call must reload
 * durable state. All graphs already PUBLISHED_DURABLE returns the current
 * journal unchanged for the separate v6 replacement phase. No v1 decision,
 * policy publication, cleanup, or unseal occurs here. Linux only. */
wyrelog_error_t wyl_fact_offline_restore_tenant_commit_resume_one
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime, const gchar *operation_uuid,
    guint64 expected_revision, gint64 drain_timeout_us,
    WylFactOfflineRestoreJournal *out_committed);

G_END_DECLS

/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/offline-restore-journal-private.h"
#include "policy/store-private.h"

G_BEGIN_DECLS

typedef enum
{
  WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED = 1,
  WYL_FACT_OFFLINE_RESTORE_STORE_UNCHANGED_REPLAY,
  WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT,
  WYL_FACT_OFFLINE_RESTORE_STORE_STALE,
  WYL_FACT_OFFLINE_RESTORE_STORE_NOT_FOUND,
} WylFactOfflineRestoreStoreResult;

wyrelog_error_t wyl_fact_offline_restore_journal_store_create
  (wyl_policy_store_t *store, const WylFactOfflineRestoreJournal *journal,
    WylFactOfflineRestoreStoreResult *out_result,
    WylFactOfflineRestoreJournal *out_committed);
wyrelog_error_t wyl_fact_offline_restore_journal_store_load
  (wyl_policy_store_t *store, const gchar *operation_uuid,
    WylFactOfflineRestoreJournal *out_journal);
wyrelog_error_t wyl_fact_offline_restore_journal_store_cas
  (wyl_policy_store_t *store, guint64 expected_revision,
    const WylFactOfflineRestoreJournal *desired,
    WylFactOfflineRestoreStoreResult *out_result,
    WylFactOfflineRestoreJournal *out_committed);
wyrelog_error_t wyl_fact_offline_restore_journal_store_release
  (wyl_policy_store_t *store, guint64 expected_revision,
    const gchar *operation_uuid,
    WylFactOfflineRestoreStoreResult *out_result);
wyrelog_error_t wyl_fact_offline_restore_journal_store_list
  (wyl_policy_store_t *store, const gchar *tenant_id, guint limit,
    GPtrArray **out_journals);
/* Fact-aware integrity pass for startup/recovery admission. */
wyrelog_error_t wyl_fact_offline_restore_journal_store_validate
  (wyl_policy_store_t *store);

G_END_DECLS

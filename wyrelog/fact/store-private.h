/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <duckdb.h>

#include "wyrelog/error.h"
#include "wyrelog/fact/schema-private.h"
#include "wyrelog/fact/store-identity-types-private.h"

#include "mutation-outcome-private.h"

G_BEGIN_DECLS;

typedef struct wyl_fact_store_t wyl_fact_store_t;

typedef void (*WylFactStoreIdentityValidationTestHook) (duckdb_database db,
    gpointer user_data);

#if defined(WYL_TEST_HANDLE_SEAMS)
typedef enum
{
  WYL_FACT_STORE_FORGET_TRANSACTION_AFTER_BEGIN = 0,
  WYL_FACT_STORE_FORGET_TRANSACTION_BEFORE_COMMIT,
  WYL_FACT_STORE_FORGET_TRANSACTION_BEFORE_ROLLBACK,
} WylFactStoreForgetTransactionTestPhase;

typedef wyrelog_error_t (*WylFactStoreForgetTransactionTestHook)
  (WylFactStoreForgetTransactionTestPhase phase, gpointer user_data);
#endif

typedef enum
{
  WYL_FACT_STORE_OP_ASSERT = 0,
  WYL_FACT_STORE_OP_RETRACT,
} wyl_fact_store_op_t;

typedef struct
{
  const gchar *batch_id;
  const gchar *tenant_id;
  const gchar *graph_id;
  const gchar *namespace_id;
  const gchar *relation_name;
  guint32 schema_version;
  const gchar *source;
  const gchar *request_id;
  const gchar *idempotency_key;
  wyl_fact_store_op_t op;
  const wyl_fact_row_t *rows;
  gsize n_rows;
} wyl_fact_store_batch_t;

wyrelog_error_t wyl_fact_store_open (const gchar * path,
    wyl_fact_store_t ** out_store);
wyrelog_error_t wyl_fact_store_open_identified (const gchar * path,
    const WylFactStoreIdentity * identity,
    WylFactStoreIdentityOpenMode mode,
    WylFactStoreIdentityResult * out_result, wyl_fact_store_t ** out_store);
/* Pathnames are not authority; this legacy handle-returning API is unsuitable
 * for security-sensitive provisioning. */
#if defined(WYL_HAS_SECURE_DUCKDB_BRIDGE)
typedef struct WylFactGraphProvisionedPair WylFactGraphProvisionedPair;
/* Open a live, secure handle on a retained provisioning pair.  Unlike the raw
 * path open, this binds by descriptor through the bounded secure filesystem, so
 * it serves the nlink-2 pair the regular open path refuses.  The returned handle
 * owns the bounded instance; close it with wyl_fact_store_close.  Identity is
 * bound from |identity| after the store's kind is revalidated. */
wyrelog_error_t wyl_fact_store_open_provisioned_pair
  (WylFactGraphProvisionedPair * pair, const WylFactStoreIdentity * identity,
    gboolean writable, wyl_fact_store_t ** out_store);
#endif
void wyl_fact_store_identity_set_test_fault (WylFactStoreIdentityTestFault
    fault);
void wyl_fact_store_identity_set_validation_test_hook
  (WylFactStoreIdentityValidationTestHook hook, gpointer user_data);
#if defined(WYL_TEST_HANDLE_SEAMS)
void wyl_fact_store_set_forget_transaction_test_hook
  (wyl_fact_store_t * store, WylFactStoreForgetTransactionTestHook hook,
    gpointer user_data);
#endif
void wyl_fact_store_close (wyl_fact_store_t * store);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (wyl_fact_store_t, wyl_fact_store_close);

duckdb_connection wyl_fact_store_get_connection (wyl_fact_store_t * store);
void wyl_fact_store_lock (wyl_fact_store_t * store);
void wyl_fact_store_unlock (wyl_fact_store_t * store);
wyrelog_error_t wyl_fact_store_create_schema (wyl_fact_store_t * store);
wyrelog_error_t wyl_fact_store_table_exists (wyl_fact_store_t * store,
    const gchar * table_name, gboolean * out_exists);
gchar *wyl_fact_store_projection_table_name (const
    wyl_policy_fact_relation_schema_options_t * schema);
wyrelog_error_t wyl_fact_store_ensure_projection (wyl_fact_store_t * store,
    const wyl_policy_fact_relation_schema_options_t * schema,
    gchar ** out_table_name);
/* Read-only projection preflight.  A missing projection is reported as
 * WYRELOG_E_OK with |out_exists| FALSE; an existing malformed projection is
 * rejected with WYRELOG_E_POLICY and |out_exists| TRUE. */
wyrelog_error_t wyl_fact_store_validate_projection (wyl_fact_store_t * store,
    const wyl_policy_fact_relation_schema_options_t * schema,
    gboolean * out_exists);
wyrelog_error_t wyl_fact_store_append_batch (wyl_fact_store_t * store,
    const wyl_policy_fact_relation_schema_options_t * schema,
    const wyl_fact_store_batch_t * batch, gboolean * out_inserted);
wyrelog_error_t wyl_fact_store_retract_batch (wyl_fact_store_t * store,
    const wyl_policy_fact_relation_schema_options_t * schema,
    const wyl_fact_store_batch_t * batch, gboolean * out_inserted);
/* Delta-reporting variants (issue #546).  Identical to the plain append/retract
 * but additionally fill |out_delta| with the committed resource deltas for
 * quota accounting.  On an idempotent no-op the delta is the zero state.  The
 * plain functions above delegate here with a NULL |out_delta|. */
wyrelog_error_t wyl_fact_store_append_batch_delta (wyl_fact_store_t * store,
    const wyl_policy_fact_relation_schema_options_t * schema,
    const wyl_fact_store_batch_t * batch, gboolean * out_inserted,
    wyl_fact_commit_delta_t * out_delta);
wyrelog_error_t wyl_fact_store_retract_batch_delta (wyl_fact_store_t * store,
    const wyl_policy_fact_relation_schema_options_t * schema,
    const wyl_fact_store_batch_t * batch, gboolean * out_inserted,
    wyl_fact_commit_delta_t * out_delta);
wyrelog_error_t wyl_fact_store_retract_by_batch_id (wyl_fact_store_t * store,
    const wyl_policy_fact_relation_schema_options_t * schema,
    const gchar * trigger_batch_id, const gchar * new_batch_id,
    const gchar * source, const gchar * request_id,
    const gchar * idempotency_key, gboolean * out_inserted,
    gint64 * out_row_count);

#define WYL_FACT_STORE_RETRACT_BY_BATCH_MAX_ROWS 10000

typedef struct
{
  /*
   * Optional caller-supplied operation identity.  When NULL the store mints a
   * fresh one; a caller that wants to correlate or retry an exact forget can
   * pass a stable value.  It is NOT the batch_id: batch_id is a reusable
   * primary key, so it cannot safely identify a destructive operation across a
   * crash+reuse.
   */
  const gchar *op_uuid;
  const gchar *batch_id;
  const gchar *operator_id;
  const gchar *reason;
  /*
   * Test-only fault-injection seam; NULL in production.  Invoked at each named
   * durable boundary of the forget protocol ("after_intent",
   * "before_delete_projection", "before_delete_events", "before_delete_batch",
   * "before_completion").  Returning non-OK aborts the call at that boundary,
   * leaving the exact durable state a real crash would, so a subsequent
   * wyl_fact_store_forget_reconcile can prove convergence.
   */
  wyrelog_error_t (*checkpoint) (const gchar * point, gpointer user_data);
  gpointer checkpoint_data;
} wyl_fact_store_forget_options_t;

wyrelog_error_t wyl_fact_store_forget (wyl_fact_store_t * store,
    const wyl_policy_fact_relation_schema_options_t * schema,
    const wyl_fact_store_forget_options_t * opts, gsize * out_rows_purged);

/*
 * Drive every durable forget intention that did not reach its COMPLETED record
 * to convergence: a batch that is fully forgotten (data rows gone, audit +
 * intent COMPLETED written) or, when its identifier has since been reused, a
 * no-op completion that never touches the new batch.  Idempotent; safe to run
 * at startup or targeted reconciliation.  checkpoint is a test-only seam as
 * above (NULL in production).
 *
 * expected_tenant_id/expected_graph_id are the scope the caller believes this
 * store serves; both are required.  The store's own identity is checked
 * against them, and every intent is then checked against the store's identity,
 * so a store reached through a mis-pointed path is refused rather than deleted
 * through.
 */
wyrelog_error_t wyl_fact_store_forget_reconcile (wyl_fact_store_t * store,
    const gchar * expected_tenant_id, const gchar * expected_graph_id,
    wyrelog_error_t (*checkpoint) (const gchar * point, gpointer user_data),
    gpointer checkpoint_data);

G_END_DECLS;

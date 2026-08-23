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

#ifdef WYL_TEST_HANDLE_SEAMS
/* Fault the batch transaction of the next append/retract (issue #546), so a
 * test can prove that a mutation which fails at or just before its DuckDB
 * commit leaves nothing durable and moves no graph's engine generation.
 *
 * BEFORE_COMMIT faults immediately after BEGIN TRANSACTION, before any row is
 * appended; AT_COMMIT faults after the rows are staged but before COMMIT.  The
 * two are distinct injection points, not two names for the same one.  Both
 * take the existing rollback path.
 *
 * One-shot: the armed fault is consumed by the next append/retract that
 * reaches BEGIN TRANSACTION.  A batch that fails validation, or is an
 * idempotent no-op, returns before that point and leaves the fault armed for
 * a later batch on the same store; the tier-2 retract-by-batch-id and
 * forget-intent transactions never consume it at all.  This is deliberately
 * NOT modelled on wyl_fact_store_identity_set_test_fault, which is unguarded
 * and ships in libwyrelog. */
typedef enum
{
  WYL_FACT_STORE_BATCH_FAULT_NONE = 0,
  WYL_FACT_STORE_BATCH_FAULT_BEFORE_COMMIT,
  WYL_FACT_STORE_BATCH_FAULT_AT_COMMIT,
} WylFactStoreBatchFault;
void wyl_fact_store_set_batch_fault_once_for_test (wyl_fact_store_t * store,
    WylFactStoreBatchFault fault);
#endif

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
 * What a reconciliation pass did with the intents it loaded (#869 U2).
 *
 * |loaded| is the number of rows MATERIALIZED as a ForgetIntent -- fingerprint,
 * projection table, the fields the executor deletes through -- not the number
 * of rows in the ledger.  It is set unconditionally from the survey's array,
 * whatever the survey returned, so a store-scope refusal reports the intents it
 * loaded rather than pretending it loaded none.
 *
 * The postcondition is an equality, not a bound, over the four dispositions a
 * materialized intent can reach.  (#869's acceptance criteria originally put
 * |quarantined| in this sum.  It cannot be: the same bullet defines a
 * quarantined row as never materialized, so it is never in |loaded|, and the
 * two-predicate bullet asserts loaded == 0 on a second boot over a
 * quarantined-only store -- which with quarantined in the sum would force
 * quarantined == 0.  The AC has since been corrected to these four terms.  Do
 * not restore the fifth: it was accidentally true only while nothing wrote the
 * field, and would have broken on the first boot after U3 made it non-zero.)
 *
 *     executed + refused + failed + abandoned == loaded
 *
 * A <= bound would pass identically if a row vanished between load and
 * disposition, which is the likeliest defect in this code.  |failed| is
 * therefore always 0 or 1: the pass stops attempting after the first failure
 * -- whether that failure came from the executor or from a scope check that
 * could not be answered -- and everything it then skips is |abandoned|.
 *
 * |abandoned| OUTRANKS |refused|.  An intent that is both out of scope and
 * reached after a failure counts as abandoned; the scope check never runs for
 * it.
 *
 * This IS a deviation from #869's acceptance criteria, and the deviation is
 * mechanical rather than numerical.  The AC defines abandoned as "never
 * attempted because an earlier intent failed AND THE EXECUTOR BROKE OUT OF THE
 * LOOP".  The second conjunct is exactly what this unit removes: the loop no
 * longer breaks, it sets a sticky flag and keeps visiting so every intent is
 * tallied.  The count the AC asks for is preserved; the mechanism it names is
 * not.  Do not read the first conjunct alone as authority for the current
 * shape -- an earlier revision of this comment did, by quoting it without the
 * second, which made a deviation look like compliance.
 *
 * Do not reorder the scope check ahead of the post-failure skip.  It would
 * re-enter the same store reads that may be what is failing, and it is pinned:
 * check_fact_forget_reconcile_abandoned_outranks_refused fails at 2464.
 *
 * (The reachability of that branch was asserted three times before it was
 * checked, so it is recorded in four parts:
 *
 *  1. UNREACHABLE BY ARGUMENT VARIATION -- established.  The non-OK,
 *     non-POLICY outcomes of validate_store_scope_unlocked come from
 *     table_exists_unlocked and metadata_value_unlocked, neither of which
 *     takes anything from the intent.
 *  2. REACHABLE whenever the metadata read's ANSWER changes between the
 *     survey and a later iteration.  Argument-independence gives the same
 *     SQL, not the same result.  An earlier revision said "dead today",
 *     generalising part 1 into a universal it does not support.
 *  3. IN PRODUCTION two mechanisms are known.  Allocation: duckdb_prepare and
 *     duckdb_execute_prepared allocate, and metadata_value_unlocked returns
 *     E_NOMEM when duckdb_value_varchar returns NULL, so memory pressure can
 *     fail the loop call on a store that answered the survey.  And a poisoned
 *     connection (#918, measured in #900): an aborted DuckDB transaction makes
 *     every later statement on that connection fail -- reads included -- until
 *     a COMMIT or ROLLBACK clears it, and the BEGIN TRANSACTION at the head of
 *     complete_forget_intent_unlocked returns without issuing either.  Note
 *     the precise shape, because an earlier revision of this comment got it
 *     backwards twice: the tail COMMIT is safe (COMMIT resolves an aborted
 *     transaction), and it is the early return that strands one.  Concurrent
 *     DDL is not a mechanism: it is not a supported configuration, so the test
 *     seam below is not the field story.
 *  4. DRIVABLE IN TEST via the executor's before_completion seam, which is
 *     NULL in production -- pinned by
 *     check_fact_forget_reconcile_loop_scope_failure_is_not_a_refusal.  An
 *     earlier revision said "not drivable" after looking for a seam on
 *     table_exists_unlocked and finding none; the seam is one layer up.
 *
 * The branch is kept because it is the only thing between a transient E_IO or
 * E_NOMEM on a scope read and a false "refused as out of scope" verdict with
 * a count behind it -- the same hazard this unit fixed one level up in the
 * survey.)
 *
 * |quarantined| is NOT a term of that equality.  A quarantined intent is never
 * materialized, so it is never in |loaded|.  In THIS revision nothing writes
 * it: there is no producer, no caller may branch on it, and no test can tell a
 * correct count from the constant zero it always holds.  It exists only so #869
 * U3 can add a producer without changing this signature or any caller.
 */
typedef struct
{
  gsize loaded;
  gsize executed;
  gsize refused;
  gsize failed;
  gsize quarantined;
  gsize abandoned;
} wyl_fact_forget_outcome_t;

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
 *
 * out_outcome is REQUIRED (NULL returns WYRELOG_E_INVALID) and is zeroed
 * before the remaining argument checks, so a caller that ignores the return
 * value cannot read a stale count as work done.
 *
 * Read the counts on EVERY return except WYRELOG_E_INVALID (all zero, by
 * contract) and WYRELOG_E_INTERNAL (inconsistent, by definition).  That rule
 * is the contract; the shapes below are illustrations of it, not an
 * enumeration.
 *
 * One limit, because store.c and this header must not disagree about it: the
 * postcondition guard only fires when rc is already OK, so a count
 * inconsistency on a NON-OK return is not reported and E_INTERNAL stays unset.
 * The counts are still readable there; they are simply not machine-checked.
 * MAINTENANCE INVARIANT, and it is what makes that trade safe: every non-OK
 * return shape of this function must have a test asserting its counts,
 * because the guard cannot cover them.  The B1 defect in #869 U2-1 arrived
 * exactly here -- a new non-OK early return with neither a guard nor a test.
 * WYRELOG_E_INTERNAL is the one exemption: it is the guard's own output, not
 * a shape the function reaches on its own, and the paragraph above already
 * tells callers not to read counts on it.  Every other non-OK shape has one
 * -- do not add a test for E_INTERNAL, and do not weaken the invariant to
 * accommodate its absence.
 *
 * Two shapes arise in the SURVEY, before any intent is attempted, and are
 * worth spelling out because they are the counter-intuitive ones:
 *
 *   - a store-scope refusal returns POLICY with loaded == refused == N,
 *     because the survey materializes the intents before it checks scope;
 *   - any other survey failure returns that failure's rc with
 *     loaded == abandoned == N and failed == 0 -- the intents were loaded and
 *     the pass could not proceed, so nothing was decided about any of them.
 *
 * The second shape is why |failed| stays 0 or 1 even though N intents went
 * undone: a survey that could not finish attempted nothing.
 *
 * Do NOT infer from the first that POLICY always means loaded == refused.  The
 * loop promotes to POLICY too, after executing some intents, so a POLICY
 * return can carry executed > 0 with loaded == executed + refused (pinned at
 * 2413).  A loop-level failure likewise returns its own rc with failed == 1
 * and the remainder abandoned (pinned at 2444-2448).  Read the counts; do not
 * derive them from the return code.
 *
 * This is NOT the convention of wyl_fact_store_forget_pending_count below,
 * whose *out_pending is meaningful only on OK -- do not generalize from it.
 *
 * WYRELOG_E_INTERNAL is a return value of this function and means the counts
 * did not satisfy the postcondition above.  Treat the outcome as untrustworthy
 * and the pass as having reported nothing.
 */
wyrelog_error_t wyl_fact_store_forget_reconcile (wyl_fact_store_t * store,
    const gchar * expected_tenant_id, const gchar * expected_graph_id,
    wyrelog_error_t (*checkpoint) (const gchar * point, gpointer user_data),
    gpointer checkpoint_data, wyl_fact_forget_outcome_t * out_outcome);

/*
 * Report how many forget intentions are pending, without executing any of
 * them and without writing anything at all.  This is the read-only prefix of
 * wyl_fact_store_forget_reconcile and shares its predicate, so a caller can
 * decide whether convergence work exists before paying for a write lease.
 *
 * expected_tenant_id/expected_graph_id carry the same meaning and the same
 * requirement as in the reconciler, and a store reached through a mis-pointed
 * path is refused here with WYRELOG_E_POLICY once anything is pending -- so
 * it is never escalated to a writable open that would refuse it in turn.  The
 * guard runs only when the count is non-zero, deliberately: see the ordering
 * note on the survey in store.c.  A mis-pointed store with nothing pending
 * therefore reports OK/0 rather than POLICY, which is the same answer the
 * reconciler gives it.
 *
 * *out_pending is meaningful only on WYRELOG_E_OK; it is set to 0 on every
 * other outcome so a caller that ignores the return value cannot read a stale
 * count as convergence work.
 */
wyrelog_error_t wyl_fact_store_forget_pending_count (wyl_fact_store_t * store,
    const gchar * expected_tenant_id, const gchar * expected_graph_id,
    gsize * out_pending);

G_END_DECLS;

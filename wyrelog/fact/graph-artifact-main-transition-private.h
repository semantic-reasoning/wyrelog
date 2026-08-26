/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/graph-artifact-inventory-private.h"
#include "wyrelog/error.h"

G_BEGIN_DECLS

/*
 * Restore-specific bounded main artifact transition authority (#623, unit 1).
 *
 * This authority owns no descriptor, HANDLE, or path, and no caller-chosen
 * name.  It DOES export two derived single-component basenames, via
 * dup_stage_name and dup_rollback_name, for the unit-2/3 backends that must
 * open them relative to the held directory.  Those two functions are not for
 * #552: a driver that opens either name by hand has bypassed the
 * authorize/record interlock.  The structural guard enforcing that lands in
 * unit 4.
 *
 * The three operation-scoped names are derived from one canonical UUIDv7
 * string and nothing else:
 *
 *   final    = "facts.duckdb"
 *   stage    = "restore-<canonical>.duckdb"
 *   rollback = "restore-<canonical>.duckdb.superseded"
 *
 * Two modes exist and they are not symmetric.  rollback_required is DERIVED as
 * !expected_main_absent, is exposed read-only, and is set by no Request field,
 * so the two incoherent boolean combinations are unrepresentable rather than
 * merely refused.
 */

typedef struct WylFactArtifactMainTransition WylFactArtifactMainTransition;

typedef enum
{
  /* INVALID is an input-validation value and cannot be driven into. */
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_INVALID = 0,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_READY,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_RETAINED_STAGE_LOST,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_PUBLISHED_DURABLE,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_FINALIZED,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ROLLED_BACK,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_ABANDONED,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_STATE_COUNT,
} WylFactArtifactMainTransitionState;

/*
 * NONE is an output value only and INSPECT is its own entry point; passing
 * either to authorize returns WYRELOG_E_INVALID.  The remaining nine are the
 * authorizable ops.
 */
typedef enum
{
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_NONE = 0,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_INSPECT,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_ROLLBACK,
  /*
   * RETIRE_STAGE and FINALIZE are the only two unlink ops and each touches
   * exactly one operation-owned, identity-verified name.  They rest on the
   * same argument and must be read together, so they are kept adjacent here
   * and in the tests.
   */
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_COUNT,
} WylFactArtifactMainTransitionOp;

typedef enum
{
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NONE = 0,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_GRAPH_NOT_SEALED,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_LIVE_MAIN_BINDING,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_DIRECTORY_AUTHORITY,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_LEASE_AUTHORITY,
  /* Wiring-consistency family: these compare two CALLER-supplied values and
   * detect a driver wiring bug rather than a state of the namespace. */
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_STALE_OPERATION,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_SEAM_NOT_APPLICABLE,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_EXPECTED_MAIN_MISSING,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_FOREIGN_MAIN,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_FOREIGN_STAGE,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_STAGE_IS_MAIN,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_ROLLBACK_NAME_OCCUPIED,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_LOCK_MISSING,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NO_MAIN_ARTIFACT,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_COLLISION_AMBIGUOUS,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_INVENTORY_UNSTABLE,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_INVENTORY_ANOMALOUS,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_INVENTORY_UNBOUND,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_SIDECAR_UNCONVERGED,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_CROSS_DEVICE,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_DURABILITY_UNPROVEN,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_DURABILITY_UNSUPPORTED,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_DURABILITY_ACK_REQUIRED,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_ILLEGAL_TRANSITION,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_PENDING_MUTATION,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_NO_PENDING_MUTATION,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_TERMINAL,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_CANCELLED,
  /* Detection-deferred family: unit 1 proves the REFUSAL WIRING only.  The
   * evidence behind each is produced by the unit-2/3 backends and must be
   * implemented there -- an out-of-band capability probe taken before any
   * mutation, O_NOFOLLOW / FILE_OPEN_REPARSE_POINT, fstat on POSIX and
   * protected owner-only ACL validation on Windows, and the FileId/nlink
   * pair.  A backend that supplies these inputs without implementing their
   * detection satisfies this contract and proves nothing. */
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_PRIMITIVE_UNSUPPORTED,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_REPARSE,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_OWNERSHIP,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_LINK_SUBSTITUTION,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_REFUSAL_COUNT,
} WylFactArtifactMainTransitionRefusal;

/* UNKNOWN = 0: a zero-filled entry fails closed. */
typedef enum
{
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_UNKNOWN = 0,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_CONFORMING,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_WRONG_PRINCIPAL,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_WRONG_MODE,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_UNPROTECTED_ACL,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_INHERITED_ACE,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_STATE_COUNT,
} WylFactArtifactMainTransitionOwnerState;

/*
 * A backend that cannot tell whether its mutation landed MUST report UNKNOWN
 * rather than guessing an effect.  NOT_APPLIED asserts the kernel REJECTED the
 * operation.
 */
typedef enum
{
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_NOT_APPLIED = 0,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN,
} WylFactArtifactMainTransitionEffect;

/*
 * PROVEN is absorbing WITHIN A DIRECTORY EPOCH; UNSUPPORTED is not absorbing
 * at all.  A seam latched UNSUPPORTED may later latch PROVEN, because
 * capability is an observation and not a fact about the operation.  UNPROVEN
 * is the unset state and is overwritten by either.
 *
 * THE EPOCH RULE, WITHOUT WHICH THE ABSORBING RULE READS AS UNCONDITIONAL AND
 * IS WRONG: a successful record of any RENAME or UNLINK op -- RETAIN,
 * PUBLISH, ROLLBACK, RETIRE_STAGE, FINALIZE -- ends the directory epoch and
 * CLEARS BOTH DIRECTORY-SEAM LATCHES regardless of their value, because the
 * receipt no longer describes the directory it attested and must be
 * re-earned.  That is not a regression, it is a new epoch.  FILE-seam latches
 * are NOT cleared: they attest inode data, which a rename does not change.
 */
typedef enum
{
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_UNPROVEN = 0,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_PROVEN,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_UNSUPPORTED,
} WylFactArtifactMainTransitionDurability;

typedef enum
{
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_MAIN = 0,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_STAGE,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_ROLLBACK,
  WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_COUNT,
} WylFactArtifactMainTransitionSlot;

/* Value-only evidence for one of the three operation-scoped names.  It carries
 * no entry name, path, descriptor, HANDLE, or reopen token. */
typedef struct
{
  gboolean present;
  WylFactArtifactInventoryIdentity identity;
  guint link_count;
  gboolean reparse;
  WylFactArtifactMainTransitionOwnerState owner_state;
} WylFactArtifactMainTransitionEntryEvidence;

/*
 * Four durability seams, four recording ops.  File seams map to fsync(fd) /
 * wyl_fact_artifact_win_entry_flush; directory seams to fsync(dirfd) /
 * wyl_fact_artifact_win_locator_flush_directory.  ONLY DIRECTORY SEAMS MAY
 * REPORT UNSUPPORTED: that is where the documented capability gap lives.  A
 * FILE seam reporting UNSUPPORTED is itself a refusal.
 *
 * rollback_file is kept rather than deleted.  On POSIX the retained old main
 * is the same inode and its data was already durable in a sealed, drained
 * graph, so a POSIX backend MAY satisfy it by assertion without a syscall.  On
 * Windows the entry-level flush is separate from the directory flush and a
 * rename updates file metadata the directory flush does not cover, so a
 * Windows backend MUST NOT report PROVEN without an actual entry flush.  Unit
 * 3 proves that obligation; unit 1 proves only that the dependent op refuses
 * when the latch is unset.
 */
typedef struct
{
  WylFactArtifactMainTransitionDurability staged_file;
  WylFactArtifactMainTransitionDurability rollback_file;
  WylFactArtifactMainTransitionDurability directory_after_retain;
  WylFactArtifactMainTransitionDurability directory_after_publish;
} WylFactArtifactMainTransitionDurabilityEvidence;

/*
 * A receipt is HISTORICAL, not observable.  The DurabilityEvidence fields
 * below are INPUTS TO record ONLY: authorize never reads them, it reads the
 * latches held in the transition object.  A fresh admit after a restart starts
 * with all four latches clear.
 */
typedef struct
{
  WylFactArtifactInventoryIdentity directory_identity;
  WylFactArtifactInventoryIdentity lease_identity;
  guint8 operation_uuid[16];
  gboolean sealed;
  gboolean main_binding_live;
  WylFactArtifactMainTransitionEntryEvidence entries
  [WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_COUNT];
  WylFactArtifactMainTransitionDurabilityEvidence durability;
  /*
   * MUST come from an out-of-band capability probe performed before any
   * mutation.  It MUST NOT be inferred from a failed rename: the POSIX
   * rename_no_replace helper collapses EEXIST, EINVAL, ENOSYS and ENOENT onto
   * one return, so inferring capability from it misclassifies a foreign-file
   * collision as a missing primitive and the reverse.
   */
  gboolean no_replace_supported;
} WylFactArtifactMainTransitionObservation;

typedef struct
{
  /* The canonical 36-character lowercase UUIDv7 form, and nothing else.  No
   * path, name or basename parameter appears anywhere in this surface. */
  const gchar *operation_uuid;
  WylFactArtifactInventoryIdentity directory_identity;
  WylFactArtifactInventoryIdentity lease_identity;
  gboolean expected_main_absent;
  WylFactArtifactInventoryIdentity expected_main_identity;
  WylFactArtifactInventoryIdentity staged_main_identity;
  /*
   * A READY classification is not evidence that no prior attempt occurred:
   * ROLLED_BACK's triple is byte-identical to READY's, so a driver must never
   * treat READY as proof of freshness.  Set this from #552's journal when the
   * UUID already reached a terminal state.  Admit then SUCCEEDS and AT MOST
   * TWO ops are permitted -- mode-B PUBLISHED deliberately has none, and
   * ROLLBACK is scoped to the three mode-A classifications named below.
   * RETAIN, PUBLISH, FINALIZE, every SYNC op and every other forward op are
   * ILLEGAL_TRANSITION, and it does NOT make admit refuse.
   *
   *   RETIRE_STAGE -- the cleanup, and THE DESTRUCTIVE ONE: it UNLINKS this
   *     operation's own stage artifact, after verifying the stage is present
   *     and still holds the staged identity.  A #552 bug that sets this flag
   *     spuriously turns a legitimate fresh restore into a cleanup.  It fails
   *     safe, because the worst outcome is a stage that must be re-staged,
   *     but it is a way for a caller error to destroy work.
   *   ROLLBACK -- the EXIT, and non-destructive: one rename at a time, never
   *     an unlink.  It is what reaches a retirable state from RETAINED,
   *     RETAINED_STAGE_LOST and mode-A PUBLISHED, where facts.duckdb is
   *     absent or superseded and only the rollback link can restore it.
   *     Without it those three classifications have ZERO legal ops.
   */
  gboolean resume_forbidden;
  /*
   * Set by #552 only, after its own operator-authorization step, to accept a
   * FINALIZE whose directory durability the platform cannot prove.  It has no
   * effect unless directory_after_publish is UNSUPPORTED, and it can never
   * satisfy an UNPROVEN seam: that case is recoverable and must be retried.
   */
  gboolean durability_unprovable_acknowledged;
} WylFactArtifactMainTransitionRequest;

typedef struct
{
  WylFactArtifactMainTransitionState state;
  WylFactArtifactMainTransitionRefusal refusal;
  WylFactArtifactMainTransitionOp next_op;
  gboolean terminal;
  /* The latched value of the seam that gated this decision, or UNPROVEN when
   * the decision consulted no seam. */
  WylFactArtifactMainTransitionDurability durability;
} WylFactArtifactMainTransitionResult;

/*
 * Admission takes the #622 snapshot as a precondition and does not re-take it
 * per authorize: a foreign file can only harm this transition at one of the
 * three operation-scoped names, all three of which the per-authorize triple
 * check covers.
 *
 * Every entry point writes *out_result on every path, including the
 * WYRELOG_E_INVALID argument-validation paths.
 */
wyrelog_error_t wyl_fact_artifact_main_transition_admit
  (const WylFactArtifactMainTransitionRequest *request,
    const WylFactArtifactInventorySnapshot *snapshot,
    const WylFactArtifactMainTransitionObservation *observation,
    WylFactArtifactMainTransitionResult *out_result,
    WylFactArtifactMainTransition **out_transition);

void wyl_fact_artifact_main_transition_free
  (WylFactArtifactMainTransition *transition);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylFactArtifactMainTransition,
    wyl_fact_artifact_main_transition_free)

/*
 * Every inspect and every authorize re-validates the complete admission
 * invariant against the supplied observation before any state classification
 * runs, refusing with the same enumerator admission would use and setting
 * next_op = OP_NONE.  A RE-VALIDATION REFUSAL BLOCKS; IT IS NOT TERMINAL: the
 * transition keeps its state and its terminal flag, and a later call with a
 * conforming observation proceeds normally.  The refusals that ARE terminal
 * are exactly the record reconciliations that say so.
 */
wyrelog_error_t wyl_fact_artifact_main_transition_inspect
  (WylFactArtifactMainTransition *transition,
    const WylFactArtifactMainTransitionObservation *observation,
    WylFactArtifactMainTransitionResult *out_result);

/*
 * directory_after_retain gates PUBLISH in mode A ONLY.  Mode B has no retain
 * rename, requires that seam to be UNPROVEN, and must never consult it at
 * PUBLISH: doing both deadlocks mode B by construction.
 */
wyrelog_error_t wyl_fact_artifact_main_transition_authorize
  (WylFactArtifactMainTransition *transition,
    WylFactArtifactMainTransitionOp op,
    const WylFactArtifactMainTransitionObservation *observation,
    WylFactArtifactMainTransitionResult *out_result);

/*
 * |observation| describes the namespace AFTER the attempted mutation.  The
 * reconciliation of effect against shape is asymmetric: NOT_APPLIED paired
 * with the post-shape is a terminal COLLISION_AMBIGUOUS, because either the
 * backend owed us UNKNOWN or a third party produced that shape, and adopting
 * the second as our own success is the substitution attack arriving through
 * the effect argument instead of an absence check.
 */
wyrelog_error_t wyl_fact_artifact_main_transition_record
  (WylFactArtifactMainTransition *transition,
    WylFactArtifactMainTransitionOp applied,
    WylFactArtifactMainTransitionEffect effect,
    const WylFactArtifactMainTransitionObservation *observation,
    WylFactArtifactMainTransitionResult *out_result);

wyrelog_error_t wyl_fact_artifact_main_transition_cancel
  (WylFactArtifactMainTransition *transition);

/*
 * The no-observation status path.  These take no observation, perform no
 * re-validation, and remain readable for the whole lifetime of the object
 * including after any terminal result and after cancel.  In particular
 * rollback_required is DERIVED FROM THE REQUEST FIELD expected_main_absent,
 * fixed at admission, and therefore returns the same value in both modes
 * regardless of any later re-validation refusal.
 */
WylFactArtifactMainTransitionState wyl_fact_artifact_main_transition_state
  (const WylFactArtifactMainTransition *transition);
WylFactArtifactMainTransitionRefusal wyl_fact_artifact_main_transition_refusal
  (const WylFactArtifactMainTransition *transition);
gboolean wyl_fact_artifact_main_transition_is_terminal
  (const WylFactArtifactMainTransition *transition);
gboolean wyl_fact_artifact_main_transition_rollback_required
  (const WylFactArtifactMainTransition *transition);

/*
 * Returning NULL after a terminal result is deliberate and is safe alongside
 * RETIRE_STAGE, because ROLLED_BACK is NOT terminal and the stage name is
 * still available there, and because READY under resume_forbidden is not
 * terminal either.  Every state in which RETIRE_STAGE is legal can still
 * obtain the name.
 */
gchar *wyl_fact_artifact_main_transition_dup_stage_name
  (const WylFactArtifactMainTransition *transition);
gchar *wyl_fact_artifact_main_transition_dup_rollback_name
  (const WylFactArtifactMainTransition *transition);

G_END_DECLS

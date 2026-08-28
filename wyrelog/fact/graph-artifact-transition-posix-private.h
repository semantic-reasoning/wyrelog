/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/graph-artifact-main-transition-private.h"
#include "fact/graph-locator-private.h"
#include "fact/root-writer-lease-private.h"
#include "wyrelog/error.h"

G_BEGIN_DECLS

/*
 * The POSIX observation provider for the bounded main artifact transition
 * (#623, unit 2a).  It BUILDS the evidence the contract consumes and executes
 * none of it: the mutation executor is unit 2b.
 *
 * This surface is portable C even though its implementation is POSIX-only, so
 * that a Windows build can parse the header without the platform arm ever
 * compiling the syscalls.  wyrelog/meson.build registers the implementation
 * inside the non-Windows arm of its platform guard.
 *
 * The provider exports NO name, path, or descriptor.  It derives the three
 * operation-scoped names internally from the operation UUID through the
 * shared graph-artifact-transition-names-private.h, and it holds the graph
 * directory's descriptor and the writer lease as BORROWED references that it
 * neither closes nor releases.
 *
 * It does not touch the #609 namespace authority at all.  The #606 locator
 * already exposes a validated graph_fd and #612 already exposes lease
 * verification, and between them they supply everything an observation needs,
 * so #609's unconditional main-replacement prohibition stays untouched for
 * the strongest possible reason: this code never calls it.
 *
 * WHAT IT IS NOT: read-only.  observe () reads, but probe_capability creates,
 * renames and unlinks its own two probe artifacts.  It cannot DESTROY data --
 * it never touches facts.duckdb, the stage, or the rollback link -- but it
 * can deny a restore if it leaves probe debris behind, which is why the probe
 * retires both names on every exit path including every failure path.
 */

typedef struct WylFactArtifactTransitionPosix WylFactArtifactTransitionPosix;

/*
 * Filesystem capability, probed ONCE before any observation is published and
 * therefore before any mutation can be authorized.  Fixed for the provider's
 * lifetime.
 *
 * This must come from the out-of-band probe and must never be inferred from a
 * failed real rename: the POSIX no-replace primitive collapses several errnos
 * onto one return, so inferring capability from it misclassifies a
 * foreign-file collision as a missing primitive and the reverse.
 */
typedef struct
{
  /*
   * FALSE means the filesystem genuinely lacks a no-replace rename, which the
   * probe establishes from the syscall's own errno rather than from a
   * collapsed return value.  A probe that cannot classify unambiguously fails
   * instead of guessing, so this is never a fallback reading of an
   * unexplained error.
   */
  gboolean no_replace_supported;
  /*
   * PROVEN means a directory flush is provable on this filesystem;
   * UNSUPPORTED means it is not.  Never a claimed success -- unit 2b maps
   * UNSUPPORTED straight through to the contract's directory seams, which is
   * what makes the bounded exit reachable only on a filesystem that genuinely
   * cannot answer.
   */
  WylFactArtifactMainTransitionDurability directory_flush;
} WylFactArtifactTransitionPosixCapability;

/*
 * #552 lifecycle assertions.  These are NOT filesystem facts and cannot be
 * observed from a directory, so the caller supplies them and the provider
 * copies them through unchanged.
 */
typedef struct
{
  gboolean sealed;
  gboolean main_binding_live;
} WylFactArtifactTransitionPosixLifecycle;

/*
 * Deterministic fault seams, in the shape the artifact namespace already
 * uses: a process-global one-shot armed by set_test_fault and consumed by the
 * seam, with was_consumed for a test to prove it fired.
 *
 * THESE SHIP UNGATED, following the local POSIX convention rather than the
 * Windows one, and that is acceptable for one reason worth stating: AN
 * UNARMED SEAM IS INERT.  Each is a compare against a process-global that
 * only a test ever sets, so nothing outside a test can arm one and the
 * shipped cost is a predictable branch rather than a behaviour.
 */
typedef enum
{
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_NONE = 0,
  /*
   * Step 0, the crash-recovery unlink.  THE RULE: a step-0 unlink failure
   * other than ENOENT FAILS THE PROBE, and open () fails with it.
   * Fail-closed, because a directory we cannot clear is one we cannot prove
   * anything about -- and proceeding would surface it as a confusing EEXIST
   * from the O_EXCL create at step 1 instead.
   */
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_PROBE_PRECLEAN,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_PROBE_CREATE,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_PROBE_RENAME,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_PROBE_DIRECTORY_FSYNC,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_PROBE_RETIRE,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_OBSERVE_DIRECTORY_FSTAT,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_OBSERVE_LEASE_FSTAT,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_OBSERVE_SLOT_OPEN,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_OBSERVE_SLOT_SUBSTITUTE,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_LEASE_VERIFY,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_SYNC_STAGED_OPEN,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_SYNC_STAGED_FSYNC,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_RETAIN_RENAME,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_SYNC_ROLLBACK_OPEN,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_SYNC_ROLLBACK_FSYNC,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_SYNC_RETAIN_DIR_FSYNC,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_PUBLISH_RENAME,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_SYNC_PUBLISH_DIR_FSYNC,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_ROLLBACK_RENAME,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_RETIRE_STAGE_VERIFY,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_RETIRE_STAGE_UNLINK,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_FINALIZE_VERIFY,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_FINALIZE_UNLINK,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_EXECUTE_ENTRY_SUBSTITUTE,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_CAPTURE_PRE_FINALIZE_MUTATE_STAGE,
  WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_COUNT,
} WylFactArtifactTransitionPosixTestFault;

typedef void (*WylFactArtifactTransitionPosixTestPostOpenHook)
  (gint directory_fd, const gchar *name, gpointer user_data);

/*
 * Runs the out-of-band capability experiment against |directory| using two
 * probe names derived from |operation_uuid|.  Both probe names are retired
 * and the directory is flushed before this returns, on EVERY path.
 *
 * A probe that cannot answer unambiguously FAILS rather than guessing: a
 * failure yields no capability and the caller must not proceed.
 */
wyrelog_error_t wyl_fact_artifact_transition_posix_probe_capability
  (const WylFactGraphDirectory *directory, const gchar *operation_uuid,
    WylFactArtifactTransitionPosixCapability *out_capability);

/*
 * |resolver|, |directory|, and |lease| are BORROWED and must outlive the
 * provider.  The resolver must be the exact resolver authorized by the lease
 * and from which |directory| was opened.
 * capability must have come from probe_capability above; passing an invented
 * one is the misclassification the probe exists to prevent.
 */
wyrelog_error_t wyl_fact_artifact_transition_posix_open
  (WylFactGraphResolver *resolver, const WylFactGraphDirectory *directory,
    WylFactRootWriterLease *lease,
    const gchar *operation_uuid,
    const WylFactArtifactTransitionPosixCapability *capability,
    WylFactArtifactTransitionPosix **out_provider);

/*
 * Publishes one observation of the three operation-scoped names.
 *
 * The four durability fields are set to UNPROVEN unconditionally.  They are
 * INPUTS TO record ONLY in the contract, so a provider that invented values
 * for them would be claiming receipts it never took -- and would reintroduce
 * exactly the Observation-read design the contract's latch model exists to
 * remove.  Unit 2b fills them at record time.
 *
 * A slot that cannot be read is NEVER reported as absent: the whole
 * observation fails instead, because reporting absence for an unreadable name
 * is inferring success from absence one layer below where the contract
 * forbids it.
 */
wyrelog_error_t wyl_fact_artifact_transition_posix_observe
  (WylFactArtifactTransitionPosix *provider,
    const WylFactArtifactTransitionPosixLifecycle *lifecycle,
    WylFactArtifactMainTransitionObservation *out_observation);

/* Publishes a #622 snapshot and its transition observation from one correlated
 * begin/end directory epoch.  On every failure both outputs remain empty. */
wyrelog_error_t wyl_fact_artifact_transition_posix_capture
  (WylFactArtifactTransitionPosix *provider,
    const WylFactArtifactTransitionPosixLifecycle *lifecycle,
    WylFactArtifactInventorySnapshot **out_snapshot,
    WylFactArtifactMainTransitionObservation *out_observation);

/*
 * Executes one authorized mutation operation against the held graph directory.
 *
 * This performs the actual POSIX filesystem syscalls (renameat2 / renameatx_np,
 * fsync, unlinkat) for the op authorized by the contract.  It reports the
 * empirical outcome as an Effect (APPLIED, NOT_APPLIED, or UNKNOWN) and earns
 * durability evidence for flush operations.
 *
 * The caller supplies the returned Effect and DurabilityEvidence to
 * wyl_fact_artifact_main_transition_record.
 *
 * |authorized| is the observation accepted by authorize immediately before
 * this call.  It binds every file operation to the exact operation UUID,
 * directory, lease, and entry identity that was authorized; the executor does
 * not re-derive which operation is legal.
 */
wyrelog_error_t wyl_fact_artifact_transition_posix_execute
  (WylFactArtifactTransitionPosix *provider,
    const WylFactArtifactMainTransitionObservation *authorized,
    WylFactArtifactMainTransitionOp op,
    WylFactArtifactMainTransitionEffect *out_effect,
    WylFactArtifactMainTransitionDurabilityEvidence *out_durability);

void wyl_fact_artifact_transition_posix_free
  (WylFactArtifactTransitionPosix *provider);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylFactArtifactTransitionPosix,
    wyl_fact_artifact_transition_posix_free)

void wyl_fact_artifact_transition_posix_set_test_fault
  (WylFactArtifactTransitionPosixTestFault fault);
/*
 * Chooses the errno the PROBE_RENAME seam reports, so a test can drive each
 * row of the probe's classification without a filesystem that actually
 * returns it.  Zero means "unset" and the seam then reports ENOSYS, which is
 * the capability-gap row.
 *
 * TAKE-AND-DISARM, like the one-shot fault it accompanies -- BUT ONLY ONCE
 * CONSUMED.  The seam clears the value when it fires, so a level cannot leak
 * past a seam that DID fire.  A level set for a seam that never fires
 * survives, so a test must still reset it; do not delete the fixture's resets
 * on the strength of the word "disarm".
 */
void wyl_fact_artifact_transition_posix_set_test_rename_errno
  (gint errno_value);
/* The same, for the PROBE_DIRECTORY_FSYNC seam.  Zero means "unset" and the
 * seam then reports EIO, which is the probe-fails row. */
void wyl_fact_artifact_transition_posix_set_test_flush_errno
  (gint errno_value);
gboolean wyl_fact_artifact_transition_posix_test_fault_was_consumed
  (WylFactArtifactTransitionPosixTestFault fault);

void wyl_fact_artifact_transition_posix_set_test_post_open_hook
  (WylFactArtifactTransitionPosixTestPostOpenHook hook, gpointer user_data);

G_END_DECLS

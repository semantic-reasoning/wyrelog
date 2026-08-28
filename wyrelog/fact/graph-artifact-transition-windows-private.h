/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/graph-artifact-main-transition-private.h"
#include "fact/graph-locator-private.h"
#include "fact/root-writer-lease-private.h"
#include "wyrelog/error.h"

#ifdef G_OS_WIN32
#include <windows.h>
#endif

G_BEGIN_DECLS

/*
 * The native Windows observation provider and mutation executor for the
 * bounded main artifact transition (#623, unit 3).
 *
 * This surface is portable C even though its implementation is Windows-only,
 * so that non-Windows builds can parse the header without the platform arm
 * compiling Win32/NT calls.  wyrelog/meson.build registers the implementation
 * inside the Windows arm of its platform guard.
 *
 * The provider exports NO name, path, or raw HANDLE.  It derives the three
 * operation-scoped names internally from the operation UUID through the
 * shared graph-artifact-transition-names-private.h, and it holds the graph
 * directory's handle and the writer lease as BORROWED references that it
 * neither closes nor releases.
 *
 * All opens are handle-relative to directory->graph_handle using NtCreateFile
 * with FILE_OPEN_REPARSE_POINT and non-inheritable handles.
 */

typedef struct WylFactArtifactTransitionWindows
    WylFactArtifactTransitionWindows;

/*
 * Filesystem capability, probed ONCE before any observation is published and
 * therefore before any mutation can be authorized.  Fixed for the provider's
 * lifetime.
 */
typedef struct
{
  gboolean no_replace_supported;
  WylFactArtifactMainTransitionDurability directory_flush;
} WylFactArtifactTransitionWindowsCapability;

/*
 * #552 lifecycle assertions.  These are NOT filesystem facts and cannot be
 * observed from a directory, so the caller supplies them and the provider
 * copies them through unchanged.
 */
typedef struct
{
  gboolean sealed;
  gboolean main_binding_live;
} WylFactArtifactTransitionWindowsLifecycle;

/*
 * Deterministic fault seams, following the project-wide convention: a
 * process-global atomic one-shot armed by set_test_fault and consumed by the
 * seam, with was_consumed for a test to prove it fired.
 */
typedef enum
{
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_NONE = 0,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_PROBE_PRECLEAN,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_PROBE_CREATE,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_PROBE_RENAME,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_PROBE_DIRECTORY_FSYNC,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_PROBE_RETIRE,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_OBSERVE_DIRECTORY_FSTAT,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_OBSERVE_LEASE_FSTAT,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_OBSERVE_SLOT_OPEN,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_OBSERVE_SLOT_SUBSTITUTE,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_LEASE_VERIFY,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_SYNC_STAGED_OPEN,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_SYNC_STAGED_FSYNC,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_RETAIN_RENAME,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_SYNC_ROLLBACK_OPEN,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_SYNC_ROLLBACK_FSYNC,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_SYNC_RETAIN_DIR_FSYNC,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_PUBLISH_RENAME,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_SYNC_PUBLISH_DIR_FSYNC,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_ROLLBACK_RENAME,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_RETIRE_STAGE_VERIFY,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_RETIRE_STAGE_UNLINK,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_FINALIZE_VERIFY,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_FINALIZE_UNLINK,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_ENTRY_SUBSTITUTE,
  WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_COUNT,
} WylFactArtifactTransitionWindowsTestFault;

#ifdef G_OS_WIN32
typedef void (*WylFactArtifactTransitionWindowsTestPostOpenHook)
  (HANDLE directory_handle, const gchar *name, gpointer user_data);
#endif

/*
 * Runs the out-of-band capability experiment against |directory| using two
 * probe names derived from |operation_uuid|.  Both probe names are retired
 * and the directory is flushed before this returns, on EVERY path.
 */
wyrelog_error_t wyl_fact_artifact_transition_windows_probe_capability
  (const WylFactGraphDirectory *directory, const gchar *operation_uuid,
    WylFactArtifactTransitionWindowsCapability *out_capability);

/*
 * |directory| and |lease| are BORROWED and must outlive the provider.  The
 * capability must have come from probe_capability above.
 */
wyrelog_error_t wyl_fact_artifact_transition_windows_open
  (const WylFactGraphDirectory *directory, WylFactRootWriterLease *lease,
    const gchar *operation_uuid,
    const WylFactArtifactTransitionWindowsCapability *capability,
    WylFactArtifactTransitionWindows **out_provider);

/*
 * Publishes one observation of the three operation-scoped names.
 */
wyrelog_error_t wyl_fact_artifact_transition_windows_observe
  (WylFactArtifactTransitionWindows *provider,
    const WylFactArtifactTransitionWindowsLifecycle *lifecycle,
    WylFactArtifactMainTransitionObservation *out_observation);

/*
 * Executes one authorized mutation operation against the held graph directory.
 */
wyrelog_error_t wyl_fact_artifact_transition_windows_execute
  (WylFactArtifactTransitionWindows *provider,
    const WylFactArtifactMainTransitionObservation *authorized,
    WylFactArtifactMainTransitionOp op,
    WylFactArtifactMainTransitionEffect *out_effect,
    WylFactArtifactMainTransitionDurabilityEvidence *out_durability);

void wyl_fact_artifact_transition_windows_free
  (WylFactArtifactTransitionWindows *provider);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylFactArtifactTransitionWindows,
    wyl_fact_artifact_transition_windows_free)

void wyl_fact_artifact_transition_windows_set_test_fault
  (WylFactArtifactTransitionWindowsTestFault fault);
void wyl_fact_artifact_transition_windows_set_test_rename_status
  (gint status_value);
void wyl_fact_artifact_transition_windows_set_test_flush_error
  (guint error_value);
gboolean wyl_fact_artifact_transition_windows_test_fault_was_consumed
  (WylFactArtifactTransitionWindowsTestFault fault);

#ifdef G_OS_WIN32
void wyl_fact_artifact_transition_windows_set_test_post_open_hook
  (WylFactArtifactTransitionWindowsTestPostOpenHook hook, gpointer user_data);
#endif

G_END_DECLS

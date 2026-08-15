/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/graph-artifact-namespace-private.h"
#include "fact/graph-artifact-windows-locator-private.h"
#include "wyrelog/error.h"

#ifdef G_OS_WIN32
#include <windows.h>

G_BEGIN_DECLS
/* Windows never exposes the native artifact authority through a CRT gint.
 * This parallel private surface is the only usable Windows substrate; the
 * historical gint namespace APIs remain POLICY on Windows.  It accepts only
 * closed fixed artifact names and owns every native HANDLE it mints. */
typedef struct WylFactArtifactWinNamespace WylFactArtifactWinNamespace;
typedef struct WylFactArtifactWinBinding WylFactArtifactWinBinding;
typedef struct WylFactArtifactWinLease WylFactArtifactWinLease;
typedef struct WylFactArtifactWinMainBinding WylFactArtifactWinMainBinding;
typedef struct WylFactArtifactWinSidecarBinding
    WylFactArtifactWinSidecarBinding;
typedef struct WylFactArtifactWinTempRoot WylFactArtifactWinTempRoot;
typedef struct WylFactArtifactWinTempChild WylFactArtifactWinTempChild;
typedef struct WylFactArtifactWinTempChildBinding
    WylFactArtifactWinTempChildBinding;
typedef struct WylFactArtifactWinTempBinding WylFactArtifactWinTempBinding;
typedef struct WylFactArtifactWinTempToken WylFactArtifactWinTempToken;
typedef struct WylFactArtifactWinTempRecoveryEvidence
    WylFactArtifactWinTempRecoveryEvidence;
typedef struct WylFactArtifactWinIoSession WylFactArtifactWinIoSession;

typedef enum
{
  WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_NOT_REPLACED = 0,
  WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_REPLACED,
  WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_RECONCILE_REQUIRED,
} WylFactArtifactWinSidecarReplaceResult;

#ifdef WYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS
/* Compiled only under enable_windows_artifact_test_hooks.  A shipped library
 * declares neither this fault vocabulary nor the hook pair below, and its
 * sidecar-replacement path holds no armable state. */
typedef enum
{
  WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_NONE = 0,
  WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_REPLACE_PRE_FINAL_DESTINATION_SUBSTITUTE,
  WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_REPLACE_POST_RENAME_UNCERTAIN,
} WylFactArtifactWinNamespaceTestFault;

void wyl_fact_artifact_win_namespace_set_test_fault
  (WylFactArtifactWinNamespaceTestFault);
/* Disarms the hook above and reports what was armed, ..._FAULT_NONE when
 * nothing was.  An armed fault is consumed only when the replacement step it
 * names is actually reached, so a caller that arms it and then never reaches
 * that step leaves it armed for every later operation in the process; a test
 * binary uses this to disarm unconditionally between cases and to prove that
 * nothing leaked out of one.  Read and disarm are a single atomic exchange,
 * so this never races an arming caller into a partially updated state.  It
 * can only establish a clean-run property: a caller that aborts never reaches
 * its own disarm. */
WylFactArtifactWinNamespaceTestFault
wyl_fact_artifact_win_namespace_take_test_fault (void);
#endif /* WYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS */

/* Opens only an already-provisioned main and lock pair.  It never creates
 * either artifact; callers that need initial main provisioning must use the
 * #615 evidence import below. */
wyrelog_error_t wyl_fact_artifact_win_namespace_new
  (const WylFactGraphDirectory * directory,
    WylFactArtifactWinNamespace ** out_namespace);
/* Import the already-provisioned #615 facts.duckdb handle.  The imported
 * handle is never exposed or consumed here: construction requires its FileId
 * to match the same protected-ACL fixed entry reached through the retained
 * graph directory. */
wyrelog_error_t wyl_fact_artifact_win_namespace_new_with_main
  (const WylFactGraphDirectory * directory,
    const WylFactGraphRegularFile * main_file,
    WylFactArtifactWinNamespace ** out_namespace);
wyrelog_error_t wyl_fact_artifact_win_namespace_revalidate
  (WylFactArtifactWinNamespace * namespace_);
void wyl_fact_artifact_win_namespace_free
  (WylFactArtifactWinNamespace * namespace_);

/* Reader-open one existing exact sidecar relative to the retained graph
 * HANDLE.  This legacy-shaped convenience never creates entries, never opens
 * MAIN, and requires GENERIC_READ.  It acquires and retains a native reader
 * lease first, so a live session participates in the exact lock domain and
 * cannot bypass an exclusive mutation from another namespace instance. TEMP
 * is not represented here. */
wyrelog_error_t wyl_fact_artifact_win_namespace_open_fixed
  (WylFactArtifactWinNamespace * namespace_, WylFactArtifactName name,
    ACCESS_MASK access, gboolean create_new,
    WylFactArtifactWinBinding ** out_binding);

/* I/O is available only through *_open_io_session and opaque session
 * operations; this namespace never exports a raw HANDLE. */
void wyl_fact_artifact_win_binding_free (WylFactArtifactWinBinding * binding);
wyrelog_error_t wyl_fact_artifact_win_binding_open_io_session
  (WylFactArtifactWinBinding *, WylFactArtifactWinIoSession **);

/* A lease retains the namespace and its exact native lock-domain lease.
 * Reader leases never mint mutation bindings.  Mutation leases serialize
 * cooperative namespace changes without converting HANDLEs to CRT fds. */
wyrelog_error_t wyl_fact_artifact_win_namespace_acquire_reader
  (WylFactArtifactWinNamespace *, WylFactArtifactWinLease **);
wyrelog_error_t wyl_fact_artifact_win_namespace_acquire_mutation
  (WylFactArtifactWinNamespace *, WylFactArtifactWinLease **);
wyrelog_error_t wyl_fact_artifact_win_lease_revalidate
  (WylFactArtifactWinLease *);
void wyl_fact_artifact_win_lease_free (WylFactArtifactWinLease *);

/* Main is imported authority only; in-place I/O uses the opaque session
 * surface.
 *
 * Two openers, split the way POSIX splits mutation_lease_open_main_binding
 * from reader_guard_open_main_binding.  The writable one demands an exclusive
 * lease, because a writable main session must be serialised.  The reader one
 * takes either kind and its sessions refuse write and truncate: the lock
 * domain already refuses an exclusive lease while a reader guard is live, so
 * read-only access needs no exclusion of its own. */
wyrelog_error_t wyl_fact_artifact_win_lease_open_main
  (WylFactArtifactWinLease *, WylFactArtifactWinMainBinding **);
wyrelog_error_t wyl_fact_artifact_win_lease_open_main_reader
  (WylFactArtifactWinLease *, WylFactArtifactWinMainBinding **);
void wyl_fact_artifact_win_main_binding_free (WylFactArtifactWinMainBinding *);
wyrelog_error_t wyl_fact_artifact_win_main_binding_open_io_session
  (WylFactArtifactWinMainBinding *, WylFactArtifactWinIoSession **);

/* Sidecar I/O is an opaque session. */
wyrelog_error_t wyl_fact_artifact_win_lease_open_sidecar
  (WylFactArtifactWinLease *, WylFactArtifactName sidecar,
    gboolean create_new, gboolean writable, WylFactArtifactWinSidecarBinding **);
/* |out_effect| is always initialized.  APPLIED is terminal evidence that the
 * rename/delete linearized even if later flushing/revalidation fails; callers
 * must reconcile rather than retry that mutation. */
wyrelog_error_t wyl_fact_artifact_win_sidecar_binding_publish_no_replace
  (WylFactArtifactWinSidecarBinding *, WylFactArtifactName destination,
    WylFactArtifactWinMutationEffect * out_effect);
wyrelog_error_t wyl_fact_artifact_win_sidecar_binding_retire
  (WylFactArtifactWinSidecarBinding *, WylFactArtifactSidecarRetireResult *);
void wyl_fact_artifact_win_sidecar_binding_free
  (WylFactArtifactWinSidecarBinding *);
wyrelog_error_t wyl_fact_artifact_win_sidecar_binding_open_io_session
  (WylFactArtifactWinSidecarBinding *, WylFactArtifactWinIoSession **);

/* A fixed-namespace staging artifact is an owner-only source for #609
 * replacement.  The closed token maps solely to tmp-<token>; it has no path
 * or CRT descriptor escape hatch. I/O is an opaque session; raw compatibility
 * calls below are POLICY. */
wyrelog_error_t wyl_fact_artifact_win_lease_create_temp_binding
  (WylFactArtifactWinLease *, const gchar * token,
    WylFactArtifactWinTempBinding **);
/* Replaces an existing verified sidecar under the shared exclusive cooperative
 * lease.  This is not a target-FileId CAS against a same-authority bypass
 * writer.  The output is initialized on all entries. RECONCILE_REQUIRED is
 * terminal and means the rename linearized but durability/postcondition proof
 * did not complete; retry is forbidden. */
wyrelog_error_t wyl_fact_artifact_win_temp_binding_replace_sidecar
  (WylFactArtifactWinTempBinding *, WylFactArtifactWinSidecarBinding *,
    WylFactArtifactWinSidecarReplaceResult *);
void wyl_fact_artifact_win_temp_binding_free (WylFactArtifactWinTempBinding *);
wyrelog_error_t wyl_fact_artifact_win_temp_binding_open_io_session
  (WylFactArtifactWinTempBinding *, WylFactArtifactWinIoSession **);

/* #608-equivalent temporary-token authority.  A token maps only to the
 * closed spelling tmp-<token>; it has neither a host path nor a CRT fd escape
 * hatch.  An owner can create, move without replacement, unlink, and export
 * immutable identity evidence. I/O is an opaque session. A non-owner is
 * intentionally not exposed by
 * this Windows surface: reopening a token would turn recovery evidence into
 * ambient namespace authority. */
wyrelog_error_t wyl_fact_artifact_win_lease_create_temp_token
  (WylFactArtifactWinLease *, const gchar * token,
    WylFactArtifactWinTempToken **);
/* Both mutation APIs initialize |out_effect|.  A successful no-replace rename
 * remains live authority for its new token (including an APPLIED effect);
 * successful unlink and every UNKNOWN effect are terminal.  UNKNOWN requires
 * recovery evidence and reconciliation, never a retry. */
wyrelog_error_t wyl_fact_artifact_win_temp_token_rename_no_replace
  (WylFactArtifactWinTempToken *, const gchar * destination_token,
    WylFactArtifactWinMutationEffect * out_effect);
wyrelog_error_t wyl_fact_artifact_win_temp_token_unlink
  (WylFactArtifactWinTempToken *, WylFactArtifactWinMutationEffect *);
wyrelog_error_t wyl_fact_artifact_win_temp_token_export_recovery_evidence
  (WylFactArtifactWinTempToken *, WylFactArtifactWinTempRecoveryEvidence **);
void wyl_fact_artifact_win_temp_recovery_evidence_free
  (WylFactArtifactWinTempRecoveryEvidence *);
/* Durable evidence is an explicitly versioned byte record.  Decode performs
 * only structural validation; recovery still requires matching graph, lock,
 * artifact identities under a fresh exclusive lease. */
wyrelog_error_t wyl_fact_artifact_win_temp_recovery_evidence_encode
  (const WylFactArtifactWinTempRecoveryEvidence *, GBytes **);
wyrelog_error_t wyl_fact_artifact_win_temp_recovery_evidence_decode
  (GBytes *, WylFactArtifactWinTempRecoveryEvidence **);
/* Recovery has no token pathname authority of its own: it needs a matching
 * exclusive lease and the immutable entry FileId evidence.  A missing entry
 * is idempotently recovered; mismatch/replacement is POLICY and untouched. */
wyrelog_error_t wyl_fact_artifact_win_lease_recover_temp_token
  (WylFactArtifactWinLease *, const WylFactArtifactWinTempRecoveryEvidence *,
    WylFactArtifactWinMutationEffect *);
void wyl_fact_artifact_win_temp_token_free (WylFactArtifactWinTempToken *);
wyrelog_error_t wyl_fact_artifact_win_temp_token_open_io_session
  (WylFactArtifactWinTempToken *, WylFactArtifactWinIoSession **);

/* Opaque, lease-bound DuckDB 1.5.5 spill authority.  It accepts no host path
 * or CRT descriptor: the root is minted here and a child uses only the
 * source-pinned logical spelling. Child I/O is an opaque session. */
wyrelog_error_t wyl_fact_artifact_win_lease_create_temp_root
  (WylFactArtifactWinLease *, WylFactArtifactWinTempRoot **);
gchar *wyl_fact_artifact_win_temp_root_dup_logical_name
  (WylFactArtifactWinTempRoot *);
void wyl_fact_artifact_win_temp_root_free (WylFactArtifactWinTempRoot *);
wyrelog_error_t wyl_fact_artifact_win_temp_root_create_child
  (WylFactArtifactWinTempRoot *, const gchar *,
    WylFactArtifactWinTempChild **);
wyrelog_error_t
wyl_fact_artifact_win_temp_child_open (WylFactArtifactWinTempChild *,
    gboolean writable, WylFactArtifactWinTempChildBinding **);
wyrelog_error_t wyl_fact_artifact_win_temp_root_child_exists
  (WylFactArtifactWinTempRoot *, const gchar * name, gboolean * out_exists);
wyrelog_error_t wyl_fact_artifact_win_temp_root_snapshot_children
  (WylFactArtifactWinTempRoot *, GPtrArray ** out_children_names);
wyrelog_error_t wyl_fact_artifact_win_temp_root_create_child_binding
  (WylFactArtifactWinTempRoot *, const gchar * name, gboolean writable,
    WylFactArtifactWinTempChildBinding ** out_binding);

typedef struct WylFactArtifactWinTempOrphanEvidence WylFactArtifactWinTempOrphanEvidence;

wyrelog_error_t wyl_fact_artifact_win_temp_root_create_with_orphan_evidence
  (WylFactArtifactWinLease *, WylFactArtifactWinTempRoot ** out_root,
    WylFactArtifactWinTempOrphanEvidence ** out_evidence);
wyrelog_error_t wyl_fact_artifact_win_temp_root_create_child_with_orphan_evidence
  (WylFactArtifactWinTempRoot *, const gchar * name, gboolean writable,
    WylFactArtifactWinTempChildBinding ** out_binding,
    WylFactArtifactWinTempOrphanEvidence ** out_evidence);
void wyl_fact_artifact_win_temp_orphan_evidence_free
  (WylFactArtifactWinTempOrphanEvidence *);
GBytes *wyl_fact_artifact_win_temp_orphan_evidence_bytes
  (const WylFactArtifactWinTempOrphanEvidence *);

wyrelog_error_t wyl_fact_artifact_win_namespace_adopt_entries_for_test
  (WylFactArtifactWinLocator *, WylFactArtifactWinEntry * main_entry,
    WylFactArtifactWinEntry * lock_entry,
    WylFactArtifactWinNamespace ** out_namespace);

void wyl_fact_artifact_win_temp_child_binding_free
  (WylFactArtifactWinTempChildBinding *);
wyrelog_error_t wyl_fact_artifact_win_temp_child_binding_open_io_session
  (WylFactArtifactWinTempChildBinding *, WylFactArtifactWinIoSession **);
wyrelog_error_t
wyl_fact_artifact_win_temp_child_retire (WylFactArtifactWinTempChild *,
    WylFactDuckdbTempRetireResult *);
void wyl_fact_artifact_win_temp_child_free (WylFactArtifactWinTempChild *);
wyrelog_error_t wyl_fact_artifact_win_temp_root_retire
  (WylFactArtifactWinTempRoot *, WylFactDuckdbTempRetireResult *);

G_END_DECLS
#endif

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

typedef enum
{
  WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_NOT_REPLACED = 0,
  WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_REPLACED,
  WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_RECONCILE_REQUIRED,
} WylFactArtifactWinSidecarReplaceResult;

typedef enum
{
  WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_NONE = 0,
  WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_REPLACE_PRE_FINAL_DESTINATION_SUBSTITUTE,
  WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_REPLACE_POST_RENAME_UNCERTAIN,
} WylFactArtifactWinNamespaceTestFault;

void wyl_fact_artifact_win_namespace_set_test_fault
    (WylFactArtifactWinNamespaceTestFault);

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

/* Open one exact fixed artifact relative to the retained graph HANDLE.
 * |create_new| is strict FILE_CREATE; it stamps a captured-owner protected
 * DACL.  Existing entries are accepted only after the same captured owner and
 * protected DACL revalidate.  TEMP is not represented here.  A successful
 * binding retains the namespace locator, so callers may release their
 * namespace reference before closing/freeing the binding. */
wyrelog_error_t wyl_fact_artifact_win_namespace_open_fixed
    (WylFactArtifactWinNamespace * namespace_, WylFactArtifactName name,
    ACCESS_MASK access, gboolean create_new,
    WylFactArtifactWinBinding ** out_binding);

/* Borrow only the exact native HANDLE owned by a live binding.  Revalidate at
 * every raw I/O boundary; any failure terminally revokes the binding without
 * closing a potentially reused foreign HANDLE. */
wyrelog_error_t wyl_fact_artifact_win_binding_borrow
    (WylFactArtifactWinBinding * binding, HANDLE * out_handle);
wyrelog_error_t wyl_fact_artifact_win_binding_revalidate
    (WylFactArtifactWinBinding * binding);
wyrelog_error_t wyl_fact_artifact_win_binding_close
    (WylFactArtifactWinBinding * binding, HANDLE * inout_handle);
void wyl_fact_artifact_win_binding_free (WylFactArtifactWinBinding * binding);

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

/* Main is imported authority only: it can be issued for in-place I/O by an
 * exclusive lease, never created, renamed, or deleted. */
wyrelog_error_t wyl_fact_artifact_win_lease_open_main
    (WylFactArtifactWinLease *, WylFactArtifactWinMainBinding **);
wyrelog_error_t wyl_fact_artifact_win_main_binding_borrow
    (WylFactArtifactWinMainBinding *, HANDLE *);
wyrelog_error_t wyl_fact_artifact_win_main_binding_revalidate
    (WylFactArtifactWinMainBinding *);
wyrelog_error_t wyl_fact_artifact_win_main_binding_close
    (WylFactArtifactWinMainBinding *, HANDLE *);
void wyl_fact_artifact_win_main_binding_free (WylFactArtifactWinMainBinding *);

/* Sidecar working HANDLE close consumes only I/O authority.  Successful close
 * retains the lifecycle binding for later no-replace publication or retirement.
 * Any raw-close/reuse or identity failure terminally revokes it and never
 * closes a possibly reused foreign HANDLE. */
wyrelog_error_t wyl_fact_artifact_win_lease_open_sidecar
    (WylFactArtifactWinLease *, WylFactArtifactName sidecar,
    gboolean create_new, WylFactArtifactWinSidecarBinding **);
wyrelog_error_t wyl_fact_artifact_win_sidecar_binding_borrow
    (WylFactArtifactWinSidecarBinding *, HANDLE *);
wyrelog_error_t wyl_fact_artifact_win_sidecar_binding_revalidate
    (WylFactArtifactWinSidecarBinding *);
wyrelog_error_t wyl_fact_artifact_win_sidecar_binding_revalidate_handle
    (WylFactArtifactWinSidecarBinding *, HANDLE);
wyrelog_error_t wyl_fact_artifact_win_sidecar_binding_close
    (WylFactArtifactWinSidecarBinding *, HANDLE *);
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

/* A fixed-namespace staging artifact is an owner-only source for #609
 * replacement.  The closed token maps solely to tmp-<token>; it has no path
 * or CRT descriptor escape hatch.  Its working HANDLE must be checked-closed
 * before replacement. */
wyrelog_error_t wyl_fact_artifact_win_lease_create_temp_binding
    (WylFactArtifactWinLease *, const gchar * token,
    WylFactArtifactWinTempBinding **);
wyrelog_error_t wyl_fact_artifact_win_temp_binding_borrow
    (WylFactArtifactWinTempBinding *, HANDLE *);
wyrelog_error_t wyl_fact_artifact_win_temp_binding_close
    (WylFactArtifactWinTempBinding *, HANDLE *);
/* Replaces an existing verified sidecar under the shared exclusive cooperative
 * lease.  This is not a target-FileId CAS against a same-authority bypass
 * writer.  The output is initialized on all entries. RECONCILE_REQUIRED is
 * terminal and means the rename linearized but durability/postcondition proof
 * did not complete; retry is forbidden. */
wyrelog_error_t wyl_fact_artifact_win_temp_binding_replace_sidecar
    (WylFactArtifactWinTempBinding *, WylFactArtifactWinSidecarBinding *,
    WylFactArtifactWinSidecarReplaceResult *);
void wyl_fact_artifact_win_temp_binding_free (WylFactArtifactWinTempBinding *);

/* #608-equivalent temporary-token authority.  A token maps only to the
 * closed spelling tmp-<token>; it has neither a host path nor a CRT fd escape
 * hatch.  An owner can create, move without replacement, unlink, and export
 * immutable identity evidence.  A non-owner is intentionally not exposed by
 * this Windows surface: reopening a token would turn recovery evidence into
 * ambient namespace authority. */
wyrelog_error_t wyl_fact_artifact_win_lease_create_temp_token
    (WylFactArtifactWinLease *, const gchar * token,
    WylFactArtifactWinTempToken **);
wyrelog_error_t wyl_fact_artifact_win_temp_token_borrow
    (WylFactArtifactWinTempToken *, HANDLE *);
wyrelog_error_t wyl_fact_artifact_win_temp_token_revalidate
    (WylFactArtifactWinTempToken *);
wyrelog_error_t wyl_fact_artifact_win_temp_token_close
    (WylFactArtifactWinTempToken *, HANDLE *);
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

/* Opaque, lease-bound DuckDB 1.5.5 spill authority.  It accepts no host path
 * or CRT descriptor: the root is minted here and a child uses only the
 * source-pinned logical spelling. */
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
    WylFactArtifactWinTempChildBinding **);
wyrelog_error_t
    wyl_fact_artifact_win_temp_child_binding_borrow
    (WylFactArtifactWinTempChildBinding *, HANDLE *);
wyrelog_error_t
    wyl_fact_artifact_win_temp_child_binding_revalidate
    (WylFactArtifactWinTempChildBinding *);
wyrelog_error_t
    wyl_fact_artifact_win_temp_child_binding_revalidate_handle
    (WylFactArtifactWinTempChildBinding *, HANDLE);
wyrelog_error_t
    wyl_fact_artifact_win_temp_child_binding_close
    (WylFactArtifactWinTempChildBinding *, HANDLE *);
void wyl_fact_artifact_win_temp_child_binding_free
    (WylFactArtifactWinTempChildBinding *);
wyrelog_error_t
wyl_fact_artifact_win_temp_child_retire (WylFactArtifactWinTempChild *,
    WylFactDuckdbTempRetireResult *);
void wyl_fact_artifact_win_temp_child_free (WylFactArtifactWinTempChild *);
wyrelog_error_t wyl_fact_artifact_win_temp_root_retire
    (WylFactArtifactWinTempRoot *, WylFactDuckdbTempRetireResult *);

G_END_DECLS
#endif

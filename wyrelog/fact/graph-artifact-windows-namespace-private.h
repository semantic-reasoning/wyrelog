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

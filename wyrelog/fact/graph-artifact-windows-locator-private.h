/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/graph-locator-private.h"
#include "wyrelog/error.h"

#ifdef G_OS_WIN32
#include <windows.h>

G_BEGIN_DECLS
/* This is physical transport only.  It deliberately knows nothing about
 * artifact names, leases, publication policy, or recovery.  The namespace
 * supplies one already-pinned graph directory and decides which closed names
 * it may use. */
typedef struct WylFactArtifactWinLocator WylFactArtifactWinLocator;
typedef struct WylFactArtifactWinEntry WylFactArtifactWinEntry;
typedef struct WylFactArtifactWinDirectory WylFactArtifactWinDirectory;

typedef enum
{
  WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED = 0,
  WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED,
  WYL_FACT_ARTIFACT_WIN_MUTATION_UNKNOWN,
} WylFactArtifactWinMutationEffect;

wyrelog_error_t wyl_fact_artifact_win_locator_new (const WylFactGraphDirectory *
    directory, WylFactArtifactWinLocator ** out_locator);
wyrelog_error_t
wyl_fact_artifact_win_locator_revalidate (WylFactArtifactWinLocator * locator);
/* Identity evidence only; this never exposes a directory HANDLE or spelling. */
const WylFactGraphWinIdentity *wyl_fact_artifact_win_locator_identity
  (const WylFactArtifactWinLocator *);
void wyl_fact_artifact_win_locator_free (WylFactArtifactWinLocator * locator);

/* Open one exact, single-component child relative to the held graph HANDLE.
 * create_new uses FILE_CREATE and therefore returns BUSY on collision. */
wyrelog_error_t wyl_fact_artifact_win_locator_open (WylFactArtifactWinLocator *
    locator, const gchar * name, ACCESS_MASK access, gboolean create_new,
    WylFactArtifactWinEntry ** out_entry);
/* Revalidate the exact locator/name/FileId association, then issue a
 * non-inheritable duplicate.  The caller owns it; this transport does not
 * retain or close an issued working HANDLE. */
wyrelog_error_t
wyl_fact_artifact_win_entry_issue_working_handle (WylFactArtifactWinLocator *
    locator, WylFactArtifactWinEntry * entry, HANDLE * out_handle);
wyrelog_error_t
wyl_fact_artifact_win_entry_revalidate (WylFactArtifactWinLocator * locator,
    WylFactArtifactWinEntry * entry);
/* Flushes the exact retained entry after revalidation.  This is intentionally
 * not a caller-borrowed HANDLE operation, so lifecycle publication can flush
 * a closed working capability without reopening by pathname. */
wyrelog_error_t wyl_fact_artifact_win_entry_flush
  (WylFactArtifactWinLocator * locator, WylFactArtifactWinEntry * entry);
/* Both operations initialize |out_effect|.  APPLIED means the kernel accepted
 * the linearization operation; a subsequent directory flush may still fail
 * and must be reported separately by the namespace. */
wyrelog_error_t
wyl_fact_artifact_win_entry_rename_no_replace (WylFactArtifactWinLocator *
    locator, WylFactArtifactWinEntry * entry, const gchar * destination,
    WylFactArtifactWinMutationEffect * out_effect);
/* Replaces a caller-verified named destination with this entry.  Windows has
 * no target-FileId CAS here: this is serialized by the caller's cooperative
 * exclusive lease, and same-authority nonparticipants are outside that
 * contract.  Transport reports the kernel's linearization separately from
 * post-mutation durability/reconciliation.
 *
 * Replacement uses POSIX rename semantics, so the replaced target link is
 * removed in the same operation even while its file is still open.  Any
 * HANDLE the caller still holds to the replaced object stays valid against a
 * now nameless file and must be closed through that object's terminal
 * destructor.  A kernel or filesystem without the class fails closed as
 * POLICY with NOT_APPLIED and never degrades to a non-atomic path; that
 * capability gap is labelled in the log so it remains distinguishable from
 * an authority violation, which reports the same code. */
wyrelog_error_t
wyl_fact_artifact_win_entry_rename_replace_verified (WylFactArtifactWinLocator *
    locator, WylFactArtifactWinEntry * entry, const gchar * destination,
    WylFactArtifactWinMutationEffect * out_effect);
wyrelog_error_t
wyl_fact_artifact_win_entry_delete_exact (WylFactArtifactWinLocator * locator,
    WylFactArtifactWinEntry * entry,
    WylFactArtifactWinMutationEffect * out_effect);
wyrelog_error_t
wyl_fact_artifact_win_locator_flush_directory (WylFactArtifactWinLocator *
    locator);
/* Directory metadata durability is a capability, not a best-effort hint.
 * ERROR_NOT_SUPPORTED/ERROR_INVALID_FUNCTION mean the backing filesystem
 * cannot prove a flush and map to POLICY; all other FlushFileBuffers failures
 * map to IO.  In both cases callers must reconcile rather than claim durable
 * publication. */
#ifdef WYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS
/* Substitutes the next native directory-flush result.  Compiled only under
 * enable_windows_artifact_test_hooks: a shipped library declares neither this
 * hook nor its disarm below, and its flush path holds no armable state. */
void wyl_fact_artifact_win_locator_fail_next_directory_flush_for_test
  (DWORD error);
/* Disarms the hook above and reports what was armed, ERROR_SUCCESS when
 * nothing was.  The substitution is consumed only when a directory flush is
 * actually reached, so a caller that arms it and then never flushes leaves it
 * armed for every later operation in the process; a test binary uses this to
 * disarm unconditionally between cases and to prove that nothing leaked out
 * of one.  Read and disarm are a single atomic exchange, so this never races
 * an arming caller into a partially updated state.  It can only establish a
 * clean-run property: a caller that aborts never reaches its own disarm. */
DWORD wyl_fact_artifact_win_locator_take_next_directory_flush_error_for_test
  (void);
void wyl_fact_artifact_win_locator_fail_next_rename_status_for_test
  (NTSTATUS status);
NTSTATUS wyl_fact_artifact_win_locator_take_next_rename_status_for_test (void);
#endif /* WYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS */
const WylFactGraphWinIdentity *wyl_fact_artifact_win_entry_identity (const
    WylFactArtifactWinEntry * entry);
const gchar *wyl_fact_artifact_win_entry_name (const WylFactArtifactWinEntry *);
void wyl_fact_artifact_win_entry_free (WylFactArtifactWinEntry * entry);

/* A deliberately narrow nested-directory capability used only by the
 * DuckDB spill authority.  It is still locator-relative: callers receive no
 * host spelling or CRT descriptor and can create/open only single-component
 * regular children below the exact protected directory identity. */
wyrelog_error_t wyl_fact_artifact_win_locator_create_directory
  (WylFactArtifactWinLocator *, const gchar * name,
    WylFactArtifactWinDirectory **);
wyrelog_error_t wyl_fact_artifact_win_directory_revalidate
  (WylFactArtifactWinLocator *, WylFactArtifactWinDirectory *);
wyrelog_error_t wyl_fact_artifact_win_directory_open_file
  (WylFactArtifactWinLocator *, WylFactArtifactWinDirectory *,
    const gchar * name, ACCESS_MASK, gboolean create_new,
    WylFactArtifactWinEntry **);
wyrelog_error_t wyl_fact_artifact_win_directory_entry_revalidate
  (WylFactArtifactWinLocator *, WylFactArtifactWinDirectory *,
    WylFactArtifactWinEntry *);
wyrelog_error_t wyl_fact_artifact_win_directory_entry_issue_working_handle
  (WylFactArtifactWinLocator *, WylFactArtifactWinDirectory *,
    WylFactArtifactWinEntry *, HANDLE *);
wyrelog_error_t wyl_fact_artifact_win_directory_entry_delete_exact
  (WylFactArtifactWinLocator *, WylFactArtifactWinDirectory *,
    WylFactArtifactWinEntry *, WylFactArtifactWinMutationEffect *);
wyrelog_error_t wyl_fact_artifact_win_directory_delete_empty
  (WylFactArtifactWinLocator *, WylFactArtifactWinDirectory *,
    WylFactArtifactWinMutationEffect *);
void wyl_fact_artifact_win_directory_free (WylFactArtifactWinDirectory *);

G_END_DECLS
#endif

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
wyrelog_error_t
wyl_fact_artifact_win_entry_delete_exact (WylFactArtifactWinLocator * locator,
    WylFactArtifactWinEntry * entry,
    WylFactArtifactWinMutationEffect * out_effect);
wyrelog_error_t
wyl_fact_artifact_win_locator_flush_directory (WylFactArtifactWinLocator *
    locator);
const WylFactGraphWinIdentity *wyl_fact_artifact_win_entry_identity (const
    WylFactArtifactWinEntry * entry);
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

/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/graph-artifact-namespace-private.h"
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

wyrelog_error_t wyl_fact_artifact_win_namespace_new
    (const WylFactGraphDirectory * directory,
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

G_END_DECLS
#endif

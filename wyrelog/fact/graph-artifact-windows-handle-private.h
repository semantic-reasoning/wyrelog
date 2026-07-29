/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "fact/graph-locator-private.h"

#ifdef G_OS_WIN32
#include <windows.h>

G_BEGIN_DECLS
/* This is deliberately a private opaque capability rather than a CRT file
 * descriptor.  The native namespace hands its exact issued HANDLE to the
 * binding, which owns it until _close or _free.  Callers may borrow the
 * HANDLE for a native I/O boundary, but cannot turn it into a gint. */
typedef struct WylFactArtifactWinWorkingHandle WylFactArtifactWinWorkingHandle;

/* Adopt one already-open regular-file HANDLE.  The binding records the exact
 * FILE_ID_INFO identity, clears inheritance before publishing it, and takes
 * ownership on success.  |expected| is mandatory and ties this capability to
 * the directory-relative entry that minted it.  Every failure leaves
 * *out_binding NULL and never closes a handle it did not adopt. */
wyrelog_error_t wyl_fact_artifact_win_working_handle_adopt (HANDLE
    issued_handle, const WylFactGraphWinIdentity * expected,
    WylFactArtifactWinWorkingHandle ** out_binding);

/* Return the native handle for one immediate I/O boundary.  The result is a
 * borrowed HANDLE, valid only until the next failed revalidation, _close, or
 * _free.  It is intentionally HANDLE-typed: no descriptor-number conversion
 * is available from this interface. */
wyrelog_error_t
wyl_fact_artifact_win_working_handle_borrow (WylFactArtifactWinWorkingHandle *
    binding, HANDLE * out_handle);

/* Check that the exact still-owned HANDLE is non-inheritable and continues to
 * identify the recorded regular single-link object.  A failure terminally
 * revokes the binding without closing a possibly externally-closed/reused
 * HANDLE value. */
wyrelog_error_t
wyl_fact_artifact_win_working_handle_revalidate (WylFactArtifactWinWorkingHandle
    * binding);

/* Revalidate then close exactly the owned HANDLE.  Success consumes the
 * binding and sets *inout_handle to INVALID_HANDLE_VALUE.  Validation failure
 * leaves the caller's value untouched and does not call CloseHandle. */
wyrelog_error_t
wyl_fact_artifact_win_working_handle_close (WylFactArtifactWinWorkingHandle *
    binding, HANDLE * inout_handle);
void wyl_fact_artifact_win_working_handle_free (WylFactArtifactWinWorkingHandle
    * binding);

G_END_DECLS
#endif

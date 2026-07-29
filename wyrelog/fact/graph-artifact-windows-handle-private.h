/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "fact/graph-locator-private.h"

#ifdef G_OS_WIN32
#include <windows.h>

G_BEGIN_DECLS
/* This is deliberately a private opaque capability rather than a CRT file
 * descriptor.  The binding owns a guardian HANDLE which is never handed to a
 * caller.  Each I/O borrow is a non-inheritable DuplicateHandle copy.  Thus a
 * raw CloseHandle/reuse of an I/O value can never make the namespace close or
 * validate a foreign object. */
typedef struct WylFactArtifactWinWorkingHandle WylFactArtifactWinWorkingHandle;

/* Adopt one already-open regular-file HANDLE.  The binding records the exact
 * FILE_ID_INFO identity, clears inheritance before publishing it, and takes
 * ownership on success.  |expected| is mandatory and ties this capability to
 * the directory-relative entry that minted it.  Every failure leaves
 * *out_binding NULL and never closes a handle it did not adopt. */
wyrelog_error_t wyl_fact_artifact_win_working_handle_adopt (HANDLE
    issued_handle, const WylFactGraphWinIdentity * expected,
    WylFactArtifactWinWorkingHandle ** out_binding);

/* Mint a caller-owned native I/O duplicate.  The caller must CloseHandle it
 * when I/O is complete, then pass INVALID_HANDLE_VALUE to _close to end the
 * capability I/O phase.  No raw value is accepted as authority evidence. */
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

/* End I/O by closing the private guardian.  Callers should first close their
 * own duplicate; a supplied value is cleared but is never closed, inspected,
 * or used as ownership proof. */
wyrelog_error_t
wyl_fact_artifact_win_working_handle_close (WylFactArtifactWinWorkingHandle *
    binding, HANDLE * inout_handle);
void wyl_fact_artifact_win_working_handle_free (WylFactArtifactWinWorkingHandle
    * binding);

G_END_DECLS
#endif

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
typedef struct WylFactArtifactWinIoState WylFactArtifactWinIoState;
typedef struct WylFactArtifactWinIoSession WylFactArtifactWinIoSession;
typedef wyrelog_error_t (*WylFactArtifactWinIoValidator) (gpointer);

/* A WinIoSession is the only Windows artifact I/O surface.  It deliberately
 * contains the private duplicate itself: neither the guardian nor a session
 * handle is ever returned to a caller.  One state admits at most one live
 * session.  The state retains the guardian until both its binding and its
 * session have released it, which makes binding/lease teardown safe while an
 * operation is in flight. */
wyrelog_error_t wyl_fact_artifact_win_io_state_new
    (WylFactArtifactWinWorkingHandle *, WylFactArtifactWinIoState **);
/* Attach one already-retained owner reference (normally binding→lease or
 * binding→namespace).  The state consumes that reference exactly once, only
 * after the binding and every session reference have gone away. */
void wyl_fact_artifact_win_io_state_retain_lifetime
    (WylFactArtifactWinIoState *, gpointer owner, GDestroyNotify owner_unref);
/* Installs one construction-time association validator.  It owns |context|
 * until state teardown and is run at every typed I/O boundary in addition to
 * guardian FileId validation. */
void wyl_fact_artifact_win_io_state_set_validator (WylFactArtifactWinIoState *,
    WylFactArtifactWinIoValidator, gpointer context, GDestroyNotify);
void wyl_fact_artifact_win_io_state_free (WylFactArtifactWinIoState *);
gboolean wyl_fact_artifact_win_io_state_has_session
    (WylFactArtifactWinIoState *);
gboolean wyl_fact_artifact_win_io_state_is_aborted
    (WylFactArtifactWinIoState *);
wyrelog_error_t wyl_fact_artifact_win_io_session_open
    (WylFactArtifactWinIoState *, WylFactArtifactWinIoSession **);
wyrelog_error_t wyl_fact_artifact_win_io_session_read
    (WylFactArtifactWinIoSession *, guint64, gpointer, gsize, gsize *);
wyrelog_error_t wyl_fact_artifact_win_io_session_write
    (WylFactArtifactWinIoSession *, guint64, gconstpointer, gsize, gsize *);
wyrelog_error_t wyl_fact_artifact_win_io_session_seek
    (WylFactArtifactWinIoSession *, gint64, DWORD, guint64 *);
wyrelog_error_t wyl_fact_artifact_win_io_session_size
    (WylFactArtifactWinIoSession *, guint64 *);
wyrelog_error_t wyl_fact_artifact_win_io_session_truncate
    (WylFactArtifactWinIoSession *, guint64);
wyrelog_error_t wyl_fact_artifact_win_io_session_flush
    (WylFactArtifactWinIoSession *);
/* finish and abort both close only the private session duplicate.  They never
 * inspect, validate, or close a caller-supplied numeric HANDLE. */
wyrelog_error_t wyl_fact_artifact_win_io_session_finish
    (WylFactArtifactWinIoSession *);
void wyl_fact_artifact_win_io_session_abort (WylFactArtifactWinIoSession *);

/* Adopt one already-open regular-file HANDLE.  The binding records the exact
 * FILE_ID_INFO identity, clears inheritance before publishing it, and takes
 * ownership on success.  |expected| is mandatory and ties this capability to
 * the directory-relative entry that minted it.  Every failure leaves
 * *out_binding NULL and never closes a handle it did not adopt. */
wyrelog_error_t wyl_fact_artifact_win_working_handle_adopt (HANDLE
    issued_handle, const WylFactGraphWinIdentity * expected,
    WylFactArtifactWinWorkingHandle ** out_binding);

/* Check that the exact still-owned HANDLE is non-inheritable and continues to
 * identify the recorded regular single-link object.  A failure terminally
 * revokes the binding without closing a possibly externally-closed/reused
 * HANDLE value. */
wyrelog_error_t
wyl_fact_artifact_win_working_handle_revalidate (WylFactArtifactWinWorkingHandle
    * binding);

/* End I/O by closing the private guardian.  The caller must first close its
 * own duplicate and pass INVALID_HANDLE_VALUE; a live raw value is rejected,
 * never closed, inspected, or used as ownership proof. */
void wyl_fact_artifact_win_working_handle_free (WylFactArtifactWinWorkingHandle
    * binding);

G_END_DECLS
#endif

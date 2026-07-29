/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/graph-artifact-windows-handle-private.h"

#include <string.h>

#ifdef G_OS_WIN32

struct WylFactArtifactWinWorkingHandle
{
  /* Never expose this owning duplicate.  Identity equality is deliberately
   * insufficient to establish ownership after numeric HANDLE reuse. */
  HANDLE guardian;
  WylFactGraphWinIdentity identity;
  gboolean active;
};

struct WylFactArtifactWinIoState
{
  WylFactArtifactWinWorkingHandle *working;
  GMutex mutex;
  gint references;
  gboolean session_live;
  gboolean aborted;
  gpointer lifetime_owner;
  GDestroyNotify lifetime_unref;
  WylFactArtifactWinIoValidator validator;
  gpointer validator_context;
  GDestroyNotify validator_free;
};

struct WylFactArtifactWinIoSession
{
  WylFactArtifactWinIoState *state;
  HANDLE handle;
  gboolean active;
};

static wyrelog_error_t win_error (DWORD error);

static void
io_state_unref (WylFactArtifactWinIoState *state)
{
  if (state == NULL || !g_atomic_int_dec_and_test (&state->references))
    return;
  wyl_fact_artifact_win_working_handle_free (state->working);
  if (state->validator_free != NULL)
    state->validator_free (state->validator_context);
  if (state->lifetime_unref != NULL)
    state->lifetime_unref (state->lifetime_owner);
  g_mutex_clear (&state->mutex);
  g_free (state);
}

void
wyl_fact_artifact_win_io_state_retain_lifetime (WylFactArtifactWinIoState
    *state, gpointer owner, GDestroyNotify owner_unref)
{
  if (state == NULL || owner == NULL || owner_unref == NULL)
    return;
  g_mutex_lock (&state->mutex);
  /* This is construction-only.  A second owner would make lifetime ordering
   * ambiguous and is therefore ignored rather than replacing authority. */
  if (state->lifetime_unref == NULL) {
    state->lifetime_owner = owner;
    state->lifetime_unref = owner_unref;
  }
  g_mutex_unlock (&state->mutex);
}

void
wyl_fact_artifact_win_io_state_set_validator (WylFactArtifactWinIoState *state,
    WylFactArtifactWinIoValidator validator, gpointer context,
    GDestroyNotify context_free)
{
  if (state == NULL || validator == NULL || context == NULL
      || context_free == NULL)
    return;
  g_mutex_lock (&state->mutex);
  if (state->validator == NULL) {
    state->validator = validator;
    state->validator_context = context;
    state->validator_free = context_free;
    context = NULL;
  }
  g_mutex_unlock (&state->mutex);
  if (context != NULL)
    context_free (context);
}

static wyrelog_error_t
session_check (WylFactArtifactWinIoSession *session)
{
  wyrelog_error_t rc;
  if (session == NULL || !session->active
      || session->handle == INVALID_HANDLE_VALUE)
    return WYRELOG_E_POLICY;
  /* aborted is a one-way session revocation bit.  Guard both observation and
   * the failure transition below: restoring a substituted association must
   * never make this session usable again. */
  g_mutex_lock (&session->state->mutex);
  if (session->state->aborted) {
    g_mutex_unlock (&session->state->mutex);
    return WYRELOG_E_POLICY;
  }
  g_mutex_unlock (&session->state->mutex);
  rc = wyl_fact_artifact_win_working_handle_revalidate (session->
      state->working);
  if (rc == WYRELOG_E_OK && session->state->validator != NULL)
    rc = session->state->validator (session->state->validator_context);
  if (rc != WYRELOG_E_OK) {
    /* Association loss is terminal for this private session.  Do not expose
     * the lower-level result as INVALID or allow a later typed operation to
     * resume after a replacement. */
    g_mutex_lock (&session->state->mutex);
    session->state->aborted = TRUE;
    g_mutex_unlock (&session->state->mutex);
    return WYRELOG_E_POLICY;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_io_state_new (WylFactArtifactWinWorkingHandle *working,
    WylFactArtifactWinIoState **out_state)
{
  WylFactArtifactWinIoState *state;
  if (out_state != NULL)
    *out_state = NULL;
  if (working == NULL || out_state == NULL)
    return WYRELOG_E_INVALID;
  state = g_try_new0 (WylFactArtifactWinIoState, 1);
  if (state == NULL)
    return WYRELOG_E_NOMEM;
  state->working = working;     /* ownership transfers from the binding creator */
  g_mutex_init (&state->mutex);
  g_atomic_int_set (&state->references, 1);
  *out_state = state;
  return WYRELOG_E_OK;
}

void
wyl_fact_artifact_win_io_state_free (WylFactArtifactWinIoState *state)
{
  io_state_unref (state);
}

gboolean
wyl_fact_artifact_win_io_state_has_session (WylFactArtifactWinIoState *state)
{
  gboolean result = FALSE;
  if (state == NULL)
    return FALSE;
  g_mutex_lock (&state->mutex);
  result = state->session_live;
  g_mutex_unlock (&state->mutex);
  return result;
}

gboolean
wyl_fact_artifact_win_io_state_is_aborted (WylFactArtifactWinIoState *state)
{
  gboolean result = TRUE;
  if (state == NULL)
    return TRUE;
  g_mutex_lock (&state->mutex);
  result = state->aborted;
  g_mutex_unlock (&state->mutex);
  return result;
}

wyrelog_error_t
wyl_fact_artifact_win_io_session_open (WylFactArtifactWinIoState *state,
    WylFactArtifactWinIoSession **out_session)
{
  WylFactArtifactWinIoSession *session;
  wyrelog_error_t rc;
  if (out_session != NULL)
    *out_session = NULL;
  if (state == NULL || out_session == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&state->mutex);
  if (state->session_live || state->aborted) {
    g_mutex_unlock (&state->mutex);
    return WYRELOG_E_BUSY;
  }
  if ((rc = wyl_fact_artifact_win_working_handle_revalidate (state->working))
      != WYRELOG_E_OK) {
    g_mutex_unlock (&state->mutex);
    return rc;
  }
  session = g_try_new0 (WylFactArtifactWinIoSession, 1);
  if (session == NULL) {
    g_mutex_unlock (&state->mutex);
    return WYRELOG_E_NOMEM;
  }
  if (!DuplicateHandle (GetCurrentProcess (), state->working->guardian,
          GetCurrentProcess (), &session->handle, 0, FALSE,
          DUPLICATE_SAME_ACCESS)
      || !SetHandleInformation (session->handle, HANDLE_FLAG_INHERIT, 0)) {
    DWORD error = GetLastError ();
    if (session->handle != INVALID_HANDLE_VALUE)
      CloseHandle (session->handle);
    g_free (session);
    g_mutex_unlock (&state->mutex);
    return win_error (error);
  }
  state->session_live = TRUE;
  g_atomic_int_inc (&state->references);
  session->state = state;
  session->active = TRUE;
  *out_session = session;
  g_mutex_unlock (&state->mutex);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
session_finish (WylFactArtifactWinIoSession *session, gboolean abort)
{
  wyrelog_error_t rc = WYRELOG_E_OK;
  if (session == NULL)
    return WYRELOG_E_INVALID;
  if (session->active && session->handle != INVALID_HANDLE_VALUE
      && !CloseHandle (session->handle))
    rc = win_error (GetLastError ());
  session->handle = INVALID_HANDLE_VALUE;
  g_mutex_lock (&session->state->mutex);
  session->state->session_live = FALSE;
  if (abort)
    session->state->aborted = TRUE;
  g_mutex_unlock (&session->state->mutex);
  session->active = FALSE;
  io_state_unref (session->state);
  g_free (session);
  return rc;
}

wyrelog_error_t
wyl_fact_artifact_win_io_session_finish (WylFactArtifactWinIoSession *session)
{
  return session_finish (session, FALSE);
}

void
wyl_fact_artifact_win_io_session_abort (WylFactArtifactWinIoSession *session)
{
  (void) session_finish (session, TRUE);
}

wyrelog_error_t
wyl_fact_artifact_win_io_session_read (WylFactArtifactWinIoSession *session,
    guint64 offset, gpointer buffer, gsize length, gsize *out_read)
{
  OVERLAPPED ov = { 0 };
  DWORD done = 0;
  wyrelog_error_t rc;
  if (out_read != NULL)
    *out_read = 0;
  if (session == NULL || buffer == NULL || out_read == NULL
      || length > G_MAXUINT32)
    return WYRELOG_E_INVALID;
  if ((rc = session_check (session)) != WYRELOG_E_OK)
    return rc;
  ov.Offset = (DWORD) offset;
  ov.OffsetHigh = (DWORD) (offset >> 32);
  if (!ReadFile (session->handle, buffer, (DWORD) length, &done, &ov))
    return win_error (GetLastError ());
  *out_read = done;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_io_session_write (WylFactArtifactWinIoSession *session,
    guint64 offset, gconstpointer buffer, gsize length, gsize *out_written)
{
  OVERLAPPED ov = { 0 };
  DWORD done = 0;
  wyrelog_error_t rc;
  if (out_written != NULL)
    *out_written = 0;
  if (session == NULL || buffer == NULL || out_written == NULL
      || length > G_MAXUINT32)
    return WYRELOG_E_INVALID;
  if ((rc = session_check (session)) != WYRELOG_E_OK)
    return rc;
  ov.Offset = (DWORD) offset;
  ov.OffsetHigh = (DWORD) (offset >> 32);
  if (!WriteFile (session->handle, buffer, (DWORD) length, &done, &ov))
    return win_error (GetLastError ());
  *out_written = done;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_io_session_seek (WylFactArtifactWinIoSession *session,
    gint64 offset, DWORD method, guint64 *out_position)
{
  LARGE_INTEGER move = {.QuadPart = offset }, result;
  wyrelog_error_t rc;
  if (out_position != NULL)
    *out_position = 0;
  if (session == NULL || out_position == NULL || (method != FILE_BEGIN
          && method != FILE_CURRENT && method != FILE_END))
    return WYRELOG_E_INVALID;
  if ((rc = session_check (session)) != WYRELOG_E_OK)
    return rc;
  if (!SetFilePointerEx (session->handle, move, &result, method))
    return win_error (GetLastError ());
  *out_position = result.QuadPart;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_io_session_size (WylFactArtifactWinIoSession *session,
    guint64 *out_size)
{
  LARGE_INTEGER size;
  wyrelog_error_t rc;
  if (out_size != NULL)
    *out_size = 0;
  if (session == NULL || out_size == NULL)
    return WYRELOG_E_INVALID;
  if ((rc = session_check (session)) != WYRELOG_E_OK)
    return rc;
  if (!GetFileSizeEx (session->handle, &size))
    return win_error (GetLastError ());
  *out_size = size.QuadPart;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_io_session_truncate (WylFactArtifactWinIoSession *session,
    guint64 size)
{
  LARGE_INTEGER move = {.QuadPart = (LONGLONG) size };
  wyrelog_error_t rc;
  if (session == NULL)
    return WYRELOG_E_INVALID;
  if ((rc = session_check (session)) != WYRELOG_E_OK)
    return rc;
  if (!SetFilePointerEx (session->handle, move, NULL, FILE_BEGIN)
      || !SetEndOfFile (session->handle))
    return win_error (GetLastError ());
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_io_session_flush (WylFactArtifactWinIoSession *session)
{
  wyrelog_error_t rc;
  if (session == NULL)
    return WYRELOG_E_INVALID;
  if ((rc = session_check (session)) != WYRELOG_E_OK)
    return rc;
  return FlushFileBuffers (session->handle) ? WYRELOG_E_OK :
      win_error (GetLastError ());
}

static wyrelog_error_t
win_error (DWORD error)
{
  switch (error) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
      return WYRELOG_E_NOT_FOUND;
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
    case ERROR_FILE_EXISTS:
    case ERROR_ALREADY_EXISTS:
      return WYRELOG_E_BUSY;
    case ERROR_ACCESS_DENIED:
    case ERROR_INVALID_HANDLE:
    case ERROR_CANT_ACCESS_FILE:
    case ERROR_REPARSE_TAG_INVALID:
    case ERROR_REPARSE_TAG_MISMATCH:
    case ERROR_NOT_SUPPORTED:
      return WYRELOG_E_POLICY;
    default:
      return WYRELOG_E_IO;
  }
}

static gboolean
identity_equal (const WylFactGraphWinIdentity *a,
    const WylFactGraphWinIdentity *b)
{
  return a->volume_serial == b->volume_serial
      && memcmp (a->file_id, b->file_id, sizeof a->file_id) == 0;
}

static wyrelog_error_t
read_identity (HANDLE handle, WylFactGraphWinIdentity *out_identity)
{
  FILE_ID_INFO info = { 0 };
  BY_HANDLE_FILE_INFORMATION basic = { 0 };

  if (!GetFileInformationByHandleEx (handle, FileIdInfo, &info, sizeof info))
    return win_error (GetLastError ());
  if (!GetFileInformationByHandle (handle, &basic))
    return win_error (GetLastError ());
  if ((basic.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY
              | FILE_ATTRIBUTE_REPARSE_POINT)) != 0
      || basic.nNumberOfLinks != 1)
    return WYRELOG_E_POLICY;
  out_identity->volume_serial = info.VolumeSerialNumber;
  memcpy (out_identity->file_id, info.FileId.Identifier,
      sizeof out_identity->file_id);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
revalidate_exact_handle (WylFactArtifactWinWorkingHandle *binding)
{
  WylFactGraphWinIdentity observed = { 0 };
  DWORD flags = 0;
  wyrelog_error_t rc;

  if (binding == NULL || binding->guardian == INVALID_HANDLE_VALUE)
    return WYRELOG_E_POLICY;
  if (!GetHandleInformation (binding->guardian, &flags))
    rc = win_error (GetLastError ());
  else if ((flags & HANDLE_FLAG_INHERIT) != 0)
    rc = WYRELOG_E_POLICY;
  else if ((rc = read_identity (binding->guardian, &observed)) == WYRELOG_E_OK
      && !identity_equal (&binding->identity, &observed))
    rc = WYRELOG_E_POLICY;
  return rc;
}

static wyrelog_error_t
revalidate (WylFactArtifactWinWorkingHandle *binding, gboolean revoke)
{
  wyrelog_error_t rc;

  if (binding == NULL || !binding->active)
    return WYRELOG_E_POLICY;
  rc = revalidate_exact_handle (binding);
  if (rc != WYRELOG_E_OK && revoke)
    binding->active = FALSE;
  return rc;
}

wyrelog_error_t
wyl_fact_artifact_win_working_handle_adopt (HANDLE issued_handle,
    const WylFactGraphWinIdentity *expected,
    WylFactArtifactWinWorkingHandle **out_binding)
{
  WylFactGraphWinIdentity observed = { 0 };
  WylFactArtifactWinWorkingHandle *binding;
  HANDLE guardian = INVALID_HANDLE_VALUE;
  wyrelog_error_t rc;

  if (out_binding != NULL)
    *out_binding = NULL;
  if (out_binding == NULL || expected == NULL
      || issued_handle == NULL || issued_handle == INVALID_HANDLE_VALUE)
    return WYRELOG_E_INVALID;
  /* Never retain the numeric source supplied by a caller/locator.  The
   * guardian is an independently duplicated kernel handle, so raw close or
   * reuse of the source cannot affect namespace ownership. */
  if (!DuplicateHandle (GetCurrentProcess (), issued_handle,
          GetCurrentProcess (), &guardian, 0, FALSE, DUPLICATE_SAME_ACCESS))
    return win_error (GetLastError ());
  if (!SetHandleInformation (guardian, HANDLE_FLAG_INHERIT, 0)) {
    DWORD error = GetLastError ();
    CloseHandle (guardian);
    return win_error (error);
  }
  if (!SetHandleInformation (issued_handle, HANDLE_FLAG_INHERIT, 0)) {
    CloseHandle (guardian);
    return win_error (GetLastError ());
  }
  if ((rc = read_identity (guardian, &observed)) != WYRELOG_E_OK) {
    CloseHandle (guardian);
    return rc;
  }
  if (!identity_equal (&observed, expected)) {
    CloseHandle (guardian);
    return WYRELOG_E_POLICY;
  }
  binding = g_try_new0 (WylFactArtifactWinWorkingHandle, 1);
  if (binding == NULL) {
    CloseHandle (guardian);
    return WYRELOG_E_NOMEM;
  }
  /* Adoption consumes only the source we were explicitly handed, never a
   * future raw value.  It is now safe to discard it before publication. */
  if (!CloseHandle (issued_handle)) {
    DWORD error = GetLastError ();
    CloseHandle (guardian);
    g_free (binding);
    return win_error (error);
  }
  binding->guardian = guardian;
  binding->identity = observed;
  binding->active = TRUE;
  *out_binding = binding;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_working_handle_revalidate (WylFactArtifactWinWorkingHandle
    *binding)
{
  return revalidate (binding, TRUE);
}

void
wyl_fact_artifact_win_working_handle_free (WylFactArtifactWinWorkingHandle
    *binding)
{
  if (binding == NULL)
    return;
  /* A raw CloseHandle followed by native HANDLE value reuse must never cause
   * this destructor to close the new foreign object.  Do not predicate this
   * check on |active|: a caller-handle mismatch revokes the capability but
   * can still leave its owned HANDLE safely closeable. */
  if (binding->guardian != INVALID_HANDLE_VALUE
      && revalidate_exact_handle (binding) == WYRELOG_E_OK)
    CloseHandle (binding->guardian);
  binding->active = FALSE;
  binding->guardian = INVALID_HANDLE_VALUE;
  g_free (binding);
}

#endif

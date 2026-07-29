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
wyl_fact_artifact_win_working_handle_borrow (WylFactArtifactWinWorkingHandle
    *binding, HANDLE *out_handle)
{
  wyrelog_error_t rc;

  if (out_handle != NULL)
    *out_handle = INVALID_HANDLE_VALUE;
  if (binding == NULL || out_handle == NULL)
    return WYRELOG_E_INVALID;
  if ((rc = revalidate (binding, TRUE)) != WYRELOG_E_OK)
    return rc;
  if (!DuplicateHandle (GetCurrentProcess (), binding->guardian,
          GetCurrentProcess (), out_handle, 0, FALSE, DUPLICATE_SAME_ACCESS))
    return win_error (GetLastError ());
  if (!SetHandleInformation (*out_handle, HANDLE_FLAG_INHERIT, 0)) {
    DWORD error = GetLastError ();
    CloseHandle (*out_handle);
    *out_handle = INVALID_HANDLE_VALUE;
    return win_error (error);
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_working_handle_revalidate (WylFactArtifactWinWorkingHandle
    *binding)
{
  return revalidate (binding, TRUE);
}

wyrelog_error_t
wyl_fact_artifact_win_working_handle_close (WylFactArtifactWinWorkingHandle
    *binding, HANDLE *inout_handle)
{
  wyrelog_error_t rc;

  if (binding == NULL || inout_handle == NULL)
    return WYRELOG_E_INVALID;
  /* The caller-owned I/O duplicate must be closed before lifecycle can end.
   * Never inspect or close a live raw value: it may already be a numerically
   * reused foreign HANDLE. */
  if (*inout_handle != INVALID_HANDLE_VALUE)
    return WYRELOG_E_POLICY;
  if ((rc = revalidate (binding, TRUE)) != WYRELOG_E_OK)
    return rc;
  if (!CloseHandle (binding->guardian)) {
    binding->active = FALSE;
    return win_error (GetLastError ());
  }
  binding->guardian = INVALID_HANDLE_VALUE;
  binding->active = FALSE;
  *inout_handle = INVALID_HANDLE_VALUE;
  return WYRELOG_E_OK;
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

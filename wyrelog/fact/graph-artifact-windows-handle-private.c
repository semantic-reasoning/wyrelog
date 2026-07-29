/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/graph-artifact-windows-handle-private.h"

#include <string.h>

#ifdef G_OS_WIN32

struct WylFactArtifactWinWorkingHandle
{
  HANDLE handle;
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
revalidate (WylFactArtifactWinWorkingHandle *binding, gboolean revoke)
{
  WylFactGraphWinIdentity observed = { 0 };
  DWORD flags = 0;
  wyrelog_error_t rc;

  if (binding == NULL || !binding->active
      || binding->handle == INVALID_HANDLE_VALUE)
    return WYRELOG_E_POLICY;
  if (!GetHandleInformation (binding->handle, &flags))
    rc = win_error (GetLastError ());
  else if ((flags & HANDLE_FLAG_INHERIT) != 0)
    rc = WYRELOG_E_POLICY;
  else if ((rc = read_identity (binding->handle, &observed)) == WYRELOG_E_OK
      && !identity_equal (&binding->identity, &observed))
    rc = WYRELOG_E_POLICY;
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
  wyrelog_error_t rc;

  if (out_binding != NULL)
    *out_binding = NULL;
  if (out_binding == NULL || expected == NULL
      || issued_handle == NULL || issued_handle == INVALID_HANDLE_VALUE)
    return WYRELOG_E_INVALID;
  if (!SetHandleInformation (issued_handle, HANDLE_FLAG_INHERIT, 0))
    return win_error (GetLastError ());
  if ((rc = read_identity (issued_handle, &observed)) != WYRELOG_E_OK)
    return rc;
  if (!identity_equal (&observed, expected))
    return WYRELOG_E_POLICY;
  binding = g_try_new0 (WylFactArtifactWinWorkingHandle, 1);
  if (binding == NULL)
    return WYRELOG_E_NOMEM;
  binding->handle = issued_handle;
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
  *out_handle = binding->handle;
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
  if (*inout_handle != binding->handle)
    return WYRELOG_E_POLICY;
  if ((rc = revalidate (binding, TRUE)) != WYRELOG_E_OK)
    return rc;
  if (!CloseHandle (binding->handle)) {
    binding->active = FALSE;
    return win_error (GetLastError ());
  }
  binding->handle = INVALID_HANDLE_VALUE;
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
  if (binding->active && binding->handle != INVALID_HANDLE_VALUE)
    CloseHandle (binding->handle);
  binding->active = FALSE;
  binding->handle = INVALID_HANDLE_VALUE;
  g_free (binding);
}

#endif

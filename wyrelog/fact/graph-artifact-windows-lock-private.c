/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/graph-artifact-windows-lock-private.h"

#include <string.h>

#ifdef G_OS_WIN32

struct WylFactArtifactWinLockDomain
{
  WylFactGraphWinIdentity directory_identity;
  WylFactGraphWinIdentity lock_identity;
  HANDLE pin;
  GMutex mutex;
  guint references;
  guint readers;
  gboolean writer;
};

struct WylFactArtifactWinLockLease
{
  WylFactArtifactWinLockDomain *domain;
  HANDLE handle;
  gboolean exclusive;
  gboolean active;
};

static GMutex domains_mutex;
static GPtrArray *domains;

static gboolean
identity_equal (const WylFactGraphWinIdentity *a,
    const WylFactGraphWinIdentity *b)
{
  return a->volume_serial == b->volume_serial
      && memcmp (a->file_id, b->file_id, sizeof a->file_id) == 0;
}

static wyrelog_error_t
win_error (DWORD error)
{
  if (error == ERROR_SHARING_VIOLATION || error == ERROR_LOCK_VIOLATION)
    return WYRELOG_E_BUSY;
  if (error == ERROR_INVALID_HANDLE || error == ERROR_ACCESS_DENIED
      || error == ERROR_CANT_ACCESS_FILE || error == ERROR_NOT_SUPPORTED)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_IO;
}

static wyrelog_error_t
validate_handle (HANDLE handle, const WylFactGraphWinIdentity *expected)
{
  FILE_BASIC_INFO basic = { 0 };
  FILE_STANDARD_INFO standard = { 0 };
  FILE_ID_INFO info = { 0 };
  WylFactGraphWinIdentity observed = { 0 };
  DWORD flags = 0;

  if (handle == NULL || handle == INVALID_HANDLE_VALUE || expected == NULL)
    return WYRELOG_E_INVALID;
  if (!GetHandleInformation (handle, &flags))
    return win_error (GetLastError ());
  if ((flags & HANDLE_FLAG_INHERIT) != 0)
    return WYRELOG_E_POLICY;
  if (!GetFileInformationByHandleEx (handle, FileBasicInfo, &basic,
          sizeof basic)
      || !GetFileInformationByHandleEx (handle, FileStandardInfo, &standard,
          sizeof standard)
      || !GetFileInformationByHandleEx (handle, FileIdInfo, &info, sizeof info))
    return win_error (GetLastError ());
  if ((basic.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY
              | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 || standard.Directory
      || standard.DeletePending || standard.NumberOfLinks != 1)
    return WYRELOG_E_POLICY;
  observed.volume_serial = info.VolumeSerialNumber;
  memcpy (observed.file_id, info.FileId.Identifier, sizeof observed.file_id);
  return identity_equal (&observed, expected) ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static WylFactArtifactWinLockDomain *
find_domain (const WylFactGraphWinIdentity *directory_identity)
{
  if (domains == NULL)
    return NULL;
  for (guint i = 0; i < domains->len; i++) {
    WylFactArtifactWinLockDomain *domain = g_ptr_array_index (domains, i);
    if (identity_equal (&domain->directory_identity, directory_identity))
      return domain;
  }
  return NULL;
}

static void
domain_unref (WylFactArtifactWinLockDomain *domain)
{
  gboolean destroy = FALSE;

  g_mutex_lock (&domains_mutex);
  g_assert_cmpuint (domain->references, >, 0);
  if (--domain->references == 0) {
    g_assert_cmpuint (domain->readers, ==, 0);
    g_assert_false (domain->writer);
    for (guint i = 0; i < domains->len; i++)
      if (g_ptr_array_index (domains, i) == domain) {
        g_ptr_array_remove_index_fast (domains, i);
        break;
      }
    destroy = TRUE;
  }
  g_mutex_unlock (&domains_mutex);
  if (!destroy)
    return;
  /* The final pin close gets the same exact-identity check as every lease;
   * raw close/reuse therefore cannot close a foreign native object. */
  if (validate_handle (domain->pin, &domain->lock_identity) == WYRELOG_E_OK)
    CloseHandle (domain->pin);
  g_mutex_clear (&domain->mutex);
  g_free (domain);
}

wyrelog_error_t
wyl_fact_artifact_win_lock_domain_open (const WylFactGraphWinIdentity
    *directory_identity, const WylFactGraphWinIdentity *lock_identity,
    HANDLE lock_handle, WylFactArtifactWinLockDomain **out_domain)
{
  WylFactArtifactWinLockDomain *domain;
  wyrelog_error_t rc;

  if (out_domain != NULL)
    *out_domain = NULL;
  if (directory_identity == NULL || lock_identity == NULL || out_domain == NULL
      || lock_handle == NULL || lock_handle == INVALID_HANDLE_VALUE)
    return WYRELOG_E_INVALID;
  if (!SetHandleInformation (lock_handle, HANDLE_FLAG_INHERIT, 0))
    return win_error (GetLastError ());
  if ((rc = validate_handle (lock_handle, lock_identity)) != WYRELOG_E_OK)
    return rc;
  g_mutex_lock (&domains_mutex);
  domain = find_domain (directory_identity);
  if (domain != NULL) {
    if (!identity_equal (&domain->lock_identity, lock_identity)
        || validate_handle (domain->pin, &domain->lock_identity)
        != WYRELOG_E_OK) {
      g_mutex_unlock (&domains_mutex);
      return WYRELOG_E_POLICY;
    }
    domain->references++;
    g_mutex_unlock (&domains_mutex);
    CloseHandle (lock_handle);
    *out_domain = domain;
    return WYRELOG_E_OK;
  }
  domain = g_try_new0 (WylFactArtifactWinLockDomain, 1);
  if (domain == NULL) {
    g_mutex_unlock (&domains_mutex);
    return WYRELOG_E_NOMEM;
  }
  domain->directory_identity = *directory_identity;
  domain->lock_identity = *lock_identity;
  domain->pin = lock_handle;
  domain->references = 1;
  if (domains == NULL)
    domains = g_ptr_array_new ();
  g_ptr_array_add (domains, domain);
  g_mutex_unlock (&domains_mutex);
  *out_domain = domain;
  return WYRELOG_E_OK;
}

void
wyl_fact_artifact_win_lock_domain_free (WylFactArtifactWinLockDomain *domain)
{
  if (domain != NULL)
    domain_unref (domain);
}

wyrelog_error_t
wyl_fact_artifact_win_lock_domain_acquire (WylFactArtifactWinLockDomain *domain,
    HANDLE lock_handle, gboolean exclusive,
    WylFactArtifactWinLockLease **out_lease)
{
  WylFactArtifactWinLockLease *lease;
  OVERLAPPED overlapped = { 0 };
  DWORD flags = LOCKFILE_FAIL_IMMEDIATELY;
  gboolean locally_busy;
  wyrelog_error_t rc;

  if (out_lease != NULL)
    *out_lease = NULL;
  if (domain == NULL || out_lease == NULL || lock_handle == NULL
      || lock_handle == INVALID_HANDLE_VALUE)
    return WYRELOG_E_INVALID;
  if (!SetHandleInformation (lock_handle, HANDLE_FLAG_INHERIT, 0))
    return win_error (GetLastError ());
  if ((rc = validate_handle (lock_handle, &domain->lock_identity))
      != WYRELOG_E_OK)
    return rc;
  g_mutex_lock (&domain->mutex);
  locally_busy = domain->writer || (exclusive && domain->readers != 0);
  if (validate_handle (domain->pin, &domain->lock_identity) != WYRELOG_E_OK
      || locally_busy) {
    g_mutex_unlock (&domain->mutex);
    return locally_busy ? WYRELOG_E_BUSY : WYRELOG_E_POLICY;
  }
  if (exclusive)
    flags |= LOCKFILE_EXCLUSIVE_LOCK;
  if (!LockFileEx (lock_handle, flags, 0, 1, 0, &overlapped)) {
    rc = win_error (GetLastError ());
    g_mutex_unlock (&domain->mutex);
    return rc;
  }
  lease = g_try_new0 (WylFactArtifactWinLockLease, 1);
  if (lease == NULL) {
    UnlockFileEx (lock_handle, 0, 1, 0, &overlapped);
    g_mutex_unlock (&domain->mutex);
    return WYRELOG_E_NOMEM;
  }
  if (exclusive)
    domain->writer = TRUE;
  else
    domain->readers++;
  /* Reference count and final removal are both guarded by domains_mutex.
   * Lock order is domain->mutex then domains_mutex; no code takes the
   * inverse order, so a concurrent release cannot free this domain between
   * lease publication and its destructor. */
  g_mutex_lock (&domains_mutex);
  domain->references++;
  g_mutex_unlock (&domains_mutex);
  lease->domain = domain;
  lease->handle = lock_handle;
  lease->exclusive = exclusive;
  lease->active = TRUE;
  g_mutex_unlock (&domain->mutex);
  *out_lease = lease;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_lock_lease_revalidate (WylFactArtifactWinLockLease *lease)
{
  wyrelog_error_t rc;

  if (lease == NULL || !lease->active)
    return WYRELOG_E_POLICY;
  g_mutex_lock (&lease->domain->mutex);
  rc = validate_handle (lease->domain->pin, &lease->domain->lock_identity);
  if (rc == WYRELOG_E_OK)
    rc = validate_handle (lease->handle, &lease->domain->lock_identity);
  if (rc != WYRELOG_E_OK)
    lease->active = FALSE;
  g_mutex_unlock (&lease->domain->mutex);
  return rc;
}

void
wyl_fact_artifact_win_lock_lease_free (WylFactArtifactWinLockLease *lease)
{
  OVERLAPPED overlapped = { 0 };
  gboolean exact;

  if (lease == NULL)
    return;
  g_mutex_lock (&lease->domain->mutex);
  exact = validate_handle (lease->handle, &lease->domain->lock_identity)
      == WYRELOG_E_OK;
  if (lease->exclusive)
    lease->domain->writer = FALSE;
  else if (lease->domain->readers > 0)
    lease->domain->readers--;
  if (exact) {
    UnlockFileEx (lease->handle, 0, 1, 0, &overlapped);
    CloseHandle (lease->handle);
  }
  lease->active = FALSE;
  g_mutex_unlock (&lease->domain->mutex);
  domain_unref (lease->domain);
  g_free (lease);
}

#endif

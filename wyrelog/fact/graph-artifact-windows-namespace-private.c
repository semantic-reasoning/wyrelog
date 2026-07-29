/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/graph-artifact-windows-namespace-private.h"

#ifdef G_OS_WIN32
#include "fact/graph-artifact-windows-handle-private.h"
#include "fact/graph-artifact-windows-lock-private.h"
#include "fact/graph-artifact-windows-locator-private.h"

#include <string.h>

struct WylFactArtifactWinNamespace
{
  WylFactArtifactWinLocator *locator;
  WylFactArtifactWinEntry *main_entry;
  WylFactArtifactWinEntry *lock_entry;
  WylFactArtifactWinLockDomain *lock_domain;
  gboolean active;
  gint references;
};

static void
namespace_unref (WylFactArtifactWinNamespace *namespace_)
{
  if (namespace_ == NULL)
    return;
  g_assert_cmpint (g_atomic_int_get (&namespace_->references), >, 0);
  if (!g_atomic_int_dec_and_test (&namespace_->references))
    return;
  namespace_->active = FALSE;
  wyl_fact_artifact_win_lock_domain_free (namespace_->lock_domain);
  wyl_fact_artifact_win_entry_free (namespace_->lock_entry);
  wyl_fact_artifact_win_entry_free (namespace_->main_entry);
  wyl_fact_artifact_win_locator_free (namespace_->locator);
  g_free (namespace_);
}

static gboolean
identity_equal (const WylFactGraphWinIdentity *a,
    const WylFactGraphWinIdentity *b)
{
  return a != NULL && b != NULL && a->volume_serial == b->volume_serial
      && memcmp (a->file_id, b->file_id, sizeof a->file_id) == 0;
}

static gboolean
handle_matches_identity (HANDLE handle, const WylFactGraphWinIdentity *expected)
{
  FILE_ID_INFO info = { 0 };
  FILE_BASIC_INFO basic = { 0 };
  FILE_STANDARD_INFO standard = { 0 };
  WylFactGraphWinIdentity observed = { 0 };
  DWORD flags = 0;
  if (handle == NULL || handle == INVALID_HANDLE_VALUE || expected == NULL
      || !GetHandleInformation (handle, &flags) || (flags & HANDLE_FLAG_INHERIT)
      || !GetFileInformationByHandleEx (handle, FileBasicInfo, &basic,
          sizeof basic) || !GetFileInformationByHandleEx (handle,
          FileStandardInfo, &standard, sizeof standard)
      || !GetFileInformationByHandleEx (handle, FileIdInfo, &info,
          sizeof info) || (basic.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY
              | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 || standard.Directory
      || standard.DeletePending || standard.NumberOfLinks != 1)
    return FALSE;
  observed.volume_serial = info.VolumeSerialNumber;
  memcpy (observed.file_id, info.FileId.Identifier, sizeof observed.file_id);
  return identity_equal (&observed, expected);
}

static gboolean
sidecar_name (WylFactArtifactName name)
{
  return name == WYL_FACT_ARTIFACT_WAL || name == WYL_FACT_ARTIFACT_CHECKPOINT
      || name == WYL_FACT_ARTIFACT_RECOVERY;
}

struct WylFactArtifactWinBinding
{
  WylFactArtifactWinNamespace *namespace_;
  WylFactArtifactWinEntry *entry;
  WylFactArtifactWinWorkingHandle *working;
  gboolean active;
};

static const gchar *
name_for (WylFactArtifactName name)
{
  static const gchar *const names[] = {
    "facts.duckdb", "facts.duckdb.wal", "facts.duckdb.wal.checkpoint",
    "facts.duckdb.wal.recovery", "facts.duckdb.lock",
  };
  return name >= WYL_FACT_ARTIFACT_MAIN && name <= WYL_FACT_ARTIFACT_LOCK
      ? names[name] : NULL;
}

wyrelog_error_t
wyl_fact_artifact_win_namespace_new (const WylFactGraphDirectory *directory,
    WylFactArtifactWinNamespace **out_namespace)
{
  WylFactArtifactWinNamespace *namespace_;
  wyrelog_error_t rc;

  if (out_namespace != NULL)
    *out_namespace = NULL;
  if (directory == NULL || out_namespace == NULL)
    return WYRELOG_E_INVALID;
  namespace_ = g_try_new0 (WylFactArtifactWinNamespace, 1);
  if (namespace_ == NULL)
    return WYRELOG_E_NOMEM;
  rc = wyl_fact_artifact_win_locator_new (directory, &namespace_->locator);
  if (rc != WYRELOG_E_OK) {
    g_free (namespace_);
    return rc;
  }
  namespace_->active = TRUE;
  g_atomic_int_set (&namespace_->references, 1);
  *out_namespace = namespace_;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_namespace_new_with_main (const WylFactGraphDirectory
    *directory, const WylFactGraphRegularFile *main_file,
    WylFactArtifactWinNamespace **out_namespace)
{
  WylFactArtifactWinNamespace *namespace_ = NULL;
  WylFactArtifactWinEntry *main_entry = NULL;
  WylFactArtifactWinEntry *lock_entry = NULL;
  HANDLE lock_handle = INVALID_HANDLE_VALUE;
  wyrelog_error_t rc;

  if (out_namespace != NULL)
    *out_namespace = NULL;
  if (directory == NULL || main_file == NULL || out_namespace == NULL
      || main_file->handle == NULL)
    return WYRELOG_E_INVALID;
  if (!handle_matches_identity ((HANDLE) main_file->handle,
          &main_file->identity))
    return WYRELOG_E_POLICY;
  rc = wyl_fact_artifact_win_namespace_new (directory, &namespace_);
  if (rc != WYRELOG_E_OK)
    return rc;
  /* #615 already minted this handle from durable operation evidence.  The
   * native namespace imports it only if the retained graph-relative fixed
   * name independently proves the identical FileId and protected ACL. */
  rc = wyl_fact_artifact_win_locator_open (namespace_->locator,
      name_for (WYL_FACT_ARTIFACT_MAIN), GENERIC_READ | GENERIC_WRITE, FALSE,
      &main_entry);
  if (rc != WYRELOG_E_OK
      || !identity_equal (wyl_fact_artifact_win_entry_identity (main_entry),
          &main_file->identity)) {
    if (rc == WYRELOG_E_OK)
      rc = WYRELOG_E_POLICY;
    wyl_fact_artifact_win_entry_free (main_entry);
    wyl_fact_artifact_win_namespace_free (namespace_);
    return rc;
  }
  /* Lock creation is strict; a concurrent creator is reopened only through
   * the same protected-ACL locator. */
  rc = wyl_fact_artifact_win_locator_open (namespace_->locator,
      name_for (WYL_FACT_ARTIFACT_LOCK), GENERIC_READ | GENERIC_WRITE,
      TRUE, &lock_entry);
  if (rc == WYRELOG_E_BUSY)
    rc = wyl_fact_artifact_win_locator_open (namespace_->locator,
        name_for (WYL_FACT_ARTIFACT_LOCK), GENERIC_READ | GENERIC_WRITE,
        FALSE, &lock_entry);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_entry_issue_working_handle (namespace_->locator,
        lock_entry, &lock_handle);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_lock_domain_open (&directory->graph_identity,
        wyl_fact_artifact_win_entry_identity (lock_entry), lock_handle,
        &namespace_->lock_domain);
  if (rc != WYRELOG_E_OK) {
    if (lock_handle != INVALID_HANDLE_VALUE)
      CloseHandle (lock_handle);
    wyl_fact_artifact_win_entry_free (lock_entry);
    wyl_fact_artifact_win_entry_free (main_entry);
    wyl_fact_artifact_win_namespace_free (namespace_);
    return rc;
  }
  namespace_->main_entry = main_entry;
  namespace_->lock_entry = lock_entry;
  *out_namespace = namespace_;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_namespace_revalidate (WylFactArtifactWinNamespace
    *namespace_)
{
  wyrelog_error_t rc;
  if (namespace_ == NULL || !namespace_->active)
    return WYRELOG_E_POLICY;
  rc = wyl_fact_artifact_win_locator_revalidate (namespace_->locator);
  if (rc != WYRELOG_E_OK)
    namespace_->active = FALSE;
  return rc;
}

void
wyl_fact_artifact_win_namespace_free (WylFactArtifactWinNamespace *namespace_)
{
  if (namespace_ == NULL)
    return;
  /* A live binding retains the namespace locator.  Releasing the caller's
   * namespace reference therefore cannot turn its native HANDLE validation
   * into a use-after-free. */
  namespace_unref (namespace_);
}

wyrelog_error_t
wyl_fact_artifact_win_namespace_open_fixed (WylFactArtifactWinNamespace
    *namespace_, WylFactArtifactName name, ACCESS_MASK access,
    gboolean create_new, WylFactArtifactWinBinding **out_binding)
{
  WylFactArtifactWinEntry *entry = NULL;
  WylFactArtifactWinWorkingHandle *working = NULL;
  WylFactArtifactWinBinding *binding = NULL;
  HANDLE issued = INVALID_HANDLE_VALUE;
  const gchar *fixed_name = name_for (name);
  wyrelog_error_t rc;

  if (out_binding != NULL)
    *out_binding = NULL;
  if (namespace_ == NULL || out_binding == NULL || fixed_name == NULL)
    return WYRELOG_E_INVALID;
  if ((rc = wyl_fact_artifact_win_namespace_revalidate (namespace_))
      != WYRELOG_E_OK)
    return rc;
  rc = wyl_fact_artifact_win_locator_open (namespace_->locator, fixed_name,
      access, create_new, &entry);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_fact_artifact_win_entry_issue_working_handle (namespace_->locator,
      entry, &issued);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_working_handle_adopt (issued,
        wyl_fact_artifact_win_entry_identity (entry), &working);
  if (rc != WYRELOG_E_OK) {
    /* The issued duplicate is not published until adoption succeeds. */
    if (issued != INVALID_HANDLE_VALUE)
      CloseHandle (issued);
    wyl_fact_artifact_win_entry_free (entry);
    return rc;
  }
  binding = g_try_new0 (WylFactArtifactWinBinding, 1);
  if (binding == NULL) {
    wyl_fact_artifact_win_working_handle_free (working);
    wyl_fact_artifact_win_entry_free (entry);
    return WYRELOG_E_NOMEM;
  }
  binding->namespace_ = namespace_;
  g_atomic_int_inc (&namespace_->references);
  binding->entry = entry;
  binding->working = working;
  binding->active = TRUE;
  *out_binding = binding;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_binding_revalidate (WylFactArtifactWinBinding *binding)
{
  wyrelog_error_t rc;
  if (binding == NULL || !binding->active)
    return WYRELOG_E_POLICY;
  rc = wyl_fact_artifact_win_namespace_revalidate (binding->namespace_);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_entry_revalidate (binding->namespace_->locator,
        binding->entry);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_working_handle_revalidate (binding->working);
  if (rc != WYRELOG_E_OK)
    binding->active = FALSE;
  return rc;
}

wyrelog_error_t
wyl_fact_artifact_win_binding_borrow (WylFactArtifactWinBinding *binding,
    HANDLE *out_handle)
{
  wyrelog_error_t rc;
  if (out_handle != NULL)
    *out_handle = INVALID_HANDLE_VALUE;
  if (binding == NULL || out_handle == NULL)
    return WYRELOG_E_INVALID;
  rc = wyl_fact_artifact_win_binding_revalidate (binding);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_fact_artifact_win_working_handle_borrow (binding->working,
      out_handle);
  if (rc != WYRELOG_E_OK)
    binding->active = FALSE;
  return rc;
}

wyrelog_error_t
wyl_fact_artifact_win_binding_close (WylFactArtifactWinBinding *binding,
    HANDLE *inout_handle)
{
  wyrelog_error_t rc;
  if (binding == NULL || inout_handle == NULL)
    return WYRELOG_E_INVALID;
  rc = wyl_fact_artifact_win_binding_revalidate (binding);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_fact_artifact_win_working_handle_close (binding->working,
      inout_handle);
  /* A failed close may mean the raw numeric HANDLE was closed or reused just
   * after the outer validation.  The inner binding has already failed closed;
   * revoke this wrapper as well so it cannot be treated as lifecycle-live. */
  binding->active = FALSE;
  return rc;
}

void
wyl_fact_artifact_win_binding_free (WylFactArtifactWinBinding *binding)
{
  if (binding == NULL)
    return;
  binding->active = FALSE;
  wyl_fact_artifact_win_working_handle_free (binding->working);
  wyl_fact_artifact_win_entry_free (binding->entry);
  namespace_unref (binding->namespace_);
  g_free (binding);
}

struct WylFactArtifactWinLease
{
  WylFactArtifactWinNamespace *namespace_;
  WylFactArtifactWinLockLease *lock;
  gboolean exclusive;
  gboolean active;
  gint references;
};

struct WylFactArtifactWinMainBinding
{
  WylFactArtifactWinLease *lease;
  WylFactArtifactWinWorkingHandle *working;
  gboolean active;
};

struct WylFactArtifactWinSidecarBinding
{
  WylFactArtifactWinLease *lease;
  WylFactArtifactWinEntry *entry;
  WylFactArtifactWinWorkingHandle *working;
  WylFactArtifactName name;
  gboolean creator;
  gboolean active;
  gboolean io_open;
  GMutex mutex;
};

static WylFactArtifactWinLease *
lease_ref (WylFactArtifactWinLease *lease)
{
  /* A binding owns the only lease reference it receives.  Lease itself holds
   * the namespace reference; concurrent binding methods are serialized by the
   * per-binding mutex and the native kernel lock. */
  if (lease != NULL)
    g_atomic_int_inc (&lease->references);
  return lease;
}

static wyrelog_error_t
lease_revalidate (WylFactArtifactWinLease *lease)
{
  wyrelog_error_t rc;
  if (lease == NULL || !lease->active || lease->namespace_ == NULL)
    return WYRELOG_E_POLICY;
  rc = wyl_fact_artifact_win_namespace_revalidate (lease->namespace_);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_lock_lease_revalidate (lease->lock);
  if (rc != WYRELOG_E_OK)
    lease->active = FALSE;
  return rc;
}

static wyrelog_error_t
namespace_acquire (WylFactArtifactWinNamespace *namespace_, gboolean exclusive,
    WylFactArtifactWinLease **out_lease)
{
  WylFactArtifactWinLease *lease = NULL;
  HANDLE handle = INVALID_HANDLE_VALUE;
  wyrelog_error_t rc;
  if (out_lease != NULL)
    *out_lease = NULL;
  if (namespace_ == NULL || out_lease == NULL || namespace_->main_entry == NULL
      || namespace_->lock_entry == NULL || namespace_->lock_domain == NULL)
    return WYRELOG_E_POLICY;
  if ((rc = wyl_fact_artifact_win_namespace_revalidate (namespace_))
      != WYRELOG_E_OK)
    return rc;
  if ((rc = wyl_fact_artifact_win_entry_revalidate (namespace_->locator,
              namespace_->main_entry)) != WYRELOG_E_OK
      || (rc = wyl_fact_artifact_win_entry_revalidate (namespace_->locator,
              namespace_->lock_entry)) != WYRELOG_E_OK)
    return rc;
  rc = wyl_fact_artifact_win_entry_issue_working_handle (namespace_->locator,
      namespace_->lock_entry, &handle);
  if (rc != WYRELOG_E_OK)
    return rc;
  lease = g_try_new0 (WylFactArtifactWinLease, 1);
  if (lease == NULL) {
    CloseHandle (handle);
    return WYRELOG_E_NOMEM;
  }
  rc = wyl_fact_artifact_win_lock_domain_acquire (namespace_->lock_domain,
      handle, exclusive, &lease->lock);
  if (rc != WYRELOG_E_OK) {
    CloseHandle (handle);
    g_free (lease);
    return rc;
  }
  lease->namespace_ = namespace_;
  g_atomic_int_inc (&namespace_->references);
  lease->exclusive = exclusive;
  lease->active = TRUE;
  g_atomic_int_set (&lease->references, 1);
  *out_lease = lease;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_namespace_acquire_reader (WylFactArtifactWinNamespace
    *namespace_, WylFactArtifactWinLease **out_lease)
{
  return namespace_acquire (namespace_, FALSE, out_lease);
}

wyrelog_error_t
wyl_fact_artifact_win_namespace_acquire_mutation (WylFactArtifactWinNamespace
    *namespace_, WylFactArtifactWinLease **out_lease)
{
  return namespace_acquire (namespace_, TRUE, out_lease);
}

wyrelog_error_t
wyl_fact_artifact_win_lease_revalidate (WylFactArtifactWinLease *lease)
{
  return lease_revalidate (lease);
}

void
wyl_fact_artifact_win_lease_free (WylFactArtifactWinLease *lease)
{
  if (lease == NULL)
    return;
  if (!g_atomic_int_dec_and_test (&lease->references))
    return;
  lease->active = FALSE;
  wyl_fact_artifact_win_lock_lease_free (lease->lock);
  namespace_unref (lease->namespace_);
  g_free (lease);
}

static wyrelog_error_t
binding_working_new (WylFactArtifactWinNamespace *namespace_,
    WylFactArtifactWinEntry *entry, WylFactArtifactWinWorkingHandle **out)
{
  HANDLE issued = INVALID_HANDLE_VALUE;
  wyrelog_error_t rc =
      wyl_fact_artifact_win_entry_issue_working_handle (namespace_->locator,
      entry, &issued);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_working_handle_adopt (issued,
        wyl_fact_artifact_win_entry_identity (entry), out);
  if (rc != WYRELOG_E_OK && issued != INVALID_HANDLE_VALUE)
    CloseHandle (issued);
  return rc;
}

wyrelog_error_t
wyl_fact_artifact_win_lease_open_main (WylFactArtifactWinLease *lease,
    WylFactArtifactWinMainBinding **out_binding)
{
  WylFactArtifactWinMainBinding *binding;
  wyrelog_error_t rc;
  if (out_binding != NULL)
    *out_binding = NULL;
  if (lease == NULL || out_binding == NULL || !lease->exclusive)
    return WYRELOG_E_POLICY;
  if ((rc = lease_revalidate (lease)) != WYRELOG_E_OK)
    return rc;
  binding = g_try_new0 (WylFactArtifactWinMainBinding, 1);
  if (binding == NULL)
    return WYRELOG_E_NOMEM;
  rc = binding_working_new (lease->namespace_, lease->namespace_->main_entry,
      &binding->working);
  if (rc != WYRELOG_E_OK) {
    g_free (binding);
    return rc;
  }
  binding->lease = lease_ref (lease);
  binding->active = TRUE;
  *out_binding = binding;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_main_binding_revalidate (WylFactArtifactWinMainBinding
    *binding)
{
  wyrelog_error_t rc;
  if (binding == NULL || !binding->active)
    return WYRELOG_E_POLICY;
  rc = lease_revalidate (binding->lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_entry_revalidate (binding->lease->
        namespace_->locator, binding->lease->namespace_->main_entry);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_working_handle_revalidate (binding->working);
  if (rc != WYRELOG_E_OK)
    binding->active = FALSE;
  return rc;
}

wyrelog_error_t
wyl_fact_artifact_win_main_binding_borrow (WylFactArtifactWinMainBinding
    *binding, HANDLE *out_handle)
{
  wyrelog_error_t rc = wyl_fact_artifact_win_main_binding_revalidate (binding);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_fact_artifact_win_working_handle_borrow (binding->working,
      out_handle);
  if (rc != WYRELOG_E_OK)
    binding->active = FALSE;
  return rc;
}

wyrelog_error_t
wyl_fact_artifact_win_main_binding_close (WylFactArtifactWinMainBinding
    *binding, HANDLE *inout_handle)
{
  wyrelog_error_t rc = wyl_fact_artifact_win_main_binding_revalidate (binding);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_fact_artifact_win_working_handle_close (binding->working,
      inout_handle);
  binding->active = FALSE;
  return rc;
}

void
wyl_fact_artifact_win_main_binding_free (WylFactArtifactWinMainBinding *binding)
{
  if (binding == NULL)
    return;
  binding->active = FALSE;
  wyl_fact_artifact_win_working_handle_free (binding->working);
  /* Main bindings never outlive their exclusive lease in the native API. */
  wyl_fact_artifact_win_lease_free (binding->lease);
  g_free (binding);
}

static void
sidecar_revoke (WylFactArtifactWinSidecarBinding *binding)
{
  binding->active = FALSE;
  binding->io_open = FALSE;
}

static wyrelog_error_t
sidecar_revalidate_locked (WylFactArtifactWinSidecarBinding *binding,
    gboolean require_working, HANDLE supplied)
{
  wyrelog_error_t rc;
  if (binding == NULL || !binding->active || !binding->lease->exclusive)
    return WYRELOG_E_POLICY;
  rc = lease_revalidate (binding->lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_entry_revalidate (binding->lease->
        namespace_->locator, binding->entry);
  if (rc == WYRELOG_E_OK && require_working) {
    HANDLE borrowed = INVALID_HANDLE_VALUE;
    rc = !binding->io_open ? WYRELOG_E_POLICY
        : wyl_fact_artifact_win_working_handle_revalidate (binding->working);
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_artifact_win_working_handle_borrow (binding->working,
          &borrowed);
    if (rc == WYRELOG_E_OK && borrowed != supplied)
      rc = WYRELOG_E_POLICY;
  }
  if (rc != WYRELOG_E_OK)
    sidecar_revoke (binding);
  return rc;
}

wyrelog_error_t
wyl_fact_artifact_win_lease_open_sidecar (WylFactArtifactWinLease *lease,
    WylFactArtifactName sidecar, gboolean create_new,
    WylFactArtifactWinSidecarBinding **out_binding)
{
  WylFactArtifactWinSidecarBinding *binding;
  WylFactArtifactWinEntry *entry = NULL;
  wyrelog_error_t rc;
  if (out_binding != NULL)
    *out_binding = NULL;
  if (lease == NULL || out_binding == NULL || !lease->exclusive
      || !sidecar_name (sidecar))
    return WYRELOG_E_POLICY;
  if ((rc = lease_revalidate (lease)) != WYRELOG_E_OK)
    return rc;
  rc = wyl_fact_artifact_win_locator_open (lease->namespace_->locator,
      name_for (sidecar), GENERIC_READ | GENERIC_WRITE | DELETE, create_new,
      &entry);
  if (rc != WYRELOG_E_OK)
    return rc;
  binding = g_try_new0 (WylFactArtifactWinSidecarBinding, 1);
  if (binding == NULL) {
    wyl_fact_artifact_win_entry_free (entry);
    return WYRELOG_E_NOMEM;
  }
  binding->lease = lease_ref (lease);
  binding->entry = entry;
  binding->name = sidecar;
  binding->creator = create_new;
  binding->active = TRUE;
  binding->io_open = TRUE;
  g_mutex_init (&binding->mutex);
  rc = binding_working_new (lease->namespace_, entry, &binding->working);
  if (rc == WYRELOG_E_OK)
    rc = sidecar_revalidate_locked (binding, FALSE, INVALID_HANDLE_VALUE);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_artifact_win_sidecar_binding_free (binding);
    return rc;
  }
  *out_binding = binding;
  return WYRELOG_E_OK;
}

wyrelog_error_t
    wyl_fact_artifact_win_sidecar_binding_revalidate
    (WylFactArtifactWinSidecarBinding * binding) {
  wyrelog_error_t rc;
  if (binding == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&binding->mutex);
  rc = sidecar_revalidate_locked (binding, FALSE, INVALID_HANDLE_VALUE);
  g_mutex_unlock (&binding->mutex);
  return rc;
}

wyrelog_error_t
    wyl_fact_artifact_win_sidecar_binding_revalidate_handle
    (WylFactArtifactWinSidecarBinding * binding, HANDLE handle) {
  wyrelog_error_t rc;
  if (binding == NULL || handle == INVALID_HANDLE_VALUE || handle == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&binding->mutex);
  rc = sidecar_revalidate_locked (binding, TRUE, handle);
  g_mutex_unlock (&binding->mutex);
  return rc;
}

wyrelog_error_t
    wyl_fact_artifact_win_sidecar_binding_borrow
    (WylFactArtifactWinSidecarBinding * binding, HANDLE * out_handle) {
  wyrelog_error_t rc;
  if (out_handle != NULL)
    *out_handle = INVALID_HANDLE_VALUE;
  if (binding == NULL || out_handle == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&binding->mutex);
  rc = sidecar_revalidate_locked (binding, FALSE, INVALID_HANDLE_VALUE);
  if (rc == WYRELOG_E_OK && !binding->io_open)
    rc = WYRELOG_E_POLICY;
  else if (rc == WYRELOG_E_OK) {
    rc = wyl_fact_artifact_win_working_handle_revalidate (binding->working);
    if (rc != WYRELOG_E_OK)
      sidecar_revoke (binding);
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_working_handle_borrow (binding->working,
        out_handle);
  if (rc == WYRELOG_E_OK)
    rc = sidecar_revalidate_locked (binding, TRUE, *out_handle);
  if (rc != WYRELOG_E_OK)
    *out_handle = INVALID_HANDLE_VALUE;
  g_mutex_unlock (&binding->mutex);
  return rc;
}

wyrelog_error_t
    wyl_fact_artifact_win_sidecar_binding_close
    (WylFactArtifactWinSidecarBinding * binding, HANDLE * inout_handle) {
  wyrelog_error_t rc;
  if (binding == NULL || inout_handle == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&binding->mutex);
  rc = sidecar_revalidate_locked (binding, TRUE, *inout_handle);
  if (rc == WYRELOG_E_OK) {
    rc = wyl_fact_artifact_win_working_handle_close (binding->working,
        inout_handle);
    if (rc == WYRELOG_E_OK)
      binding->io_open = FALSE;
    else
      sidecar_revoke (binding);
  }
  g_mutex_unlock (&binding->mutex);
  return rc;
}

wyrelog_error_t
    wyl_fact_artifact_win_sidecar_binding_publish_no_replace
    (WylFactArtifactWinSidecarBinding * binding,
    WylFactArtifactName destination,
    WylFactArtifactWinMutationEffect * out_effect) {
  wyrelog_error_t rc;
  if (out_effect != NULL)
    *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED;
  if (binding == NULL || out_effect == NULL || !sidecar_name (destination))
    return WYRELOG_E_INVALID;
  g_mutex_lock (&binding->mutex);
  if (!binding->active || !binding->creator || binding->name == destination
      || binding->io_open) {
    if (binding->io_open
        && wyl_fact_artifact_win_working_handle_revalidate (binding->working)
        != WYRELOG_E_OK)
      sidecar_revoke (binding);
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  if ((rc = sidecar_revalidate_locked (binding, FALSE, INVALID_HANDLE_VALUE))
      != WYRELOG_E_OK)
    goto out;
  if ((rc =
          wyl_fact_artifact_win_entry_flush (binding->lease->
              namespace_->locator, binding->entry)) != WYRELOG_E_OK)
    goto out;
  rc = wyl_fact_artifact_win_entry_rename_no_replace (binding->
      lease->namespace_->locator, binding->entry, name_for (destination),
      out_effect);
  if (*out_effect == WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED) {
    binding->name = destination;
    /* Once linearized, any durability or postcondition failure is terminal
     * reconciliation evidence, never an invitation to retry the rename. */
    wyrelog_error_t post =
        wyl_fact_artifact_win_locator_flush_directory (binding->
        lease->namespace_->locator);
    if (post == WYRELOG_E_OK)
      post = sidecar_revalidate_locked (binding, FALSE, INVALID_HANDLE_VALUE);
    if (post != WYRELOG_E_OK) {
      sidecar_revoke (binding);
      if (rc == WYRELOG_E_OK)
        rc = post;
    }
  }
out:
  g_mutex_unlock (&binding->mutex);
  return rc;
}

wyrelog_error_t
    wyl_fact_artifact_win_sidecar_binding_retire
    (WylFactArtifactWinSidecarBinding * binding,
    WylFactArtifactSidecarRetireResult * out_result) {
  WylFactArtifactWinMutationEffect effect =
      WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED;
  wyrelog_error_t rc;
  if (out_result != NULL)
    *out_result = WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED;
  if (binding == NULL || out_result == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&binding->mutex);
  if (!binding->active || binding->io_open) {
    if (binding->io_open
        && wyl_fact_artifact_win_working_handle_revalidate (binding->working)
        != WYRELOG_E_OK)
      sidecar_revoke (binding);
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  if ((rc = sidecar_revalidate_locked (binding, FALSE, INVALID_HANDLE_VALUE))
      != WYRELOG_E_OK)
    goto out;
  rc = wyl_fact_artifact_win_entry_delete_exact (binding->lease->
      namespace_->locator, binding->entry, &effect);
  if (effect == WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED) {
    sidecar_revoke (binding);
    wyrelog_error_t flush =
        wyl_fact_artifact_win_locator_flush_directory (binding->
        lease->namespace_->locator);
    if (rc == WYRELOG_E_OK && flush == WYRELOG_E_OK)
      *out_result = WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RETIRED;
    else
      *out_result = WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RECONCILE_REQUIRED;
    if (rc == WYRELOG_E_OK)
      rc = flush;
  } else if (effect == WYL_FACT_ARTIFACT_WIN_MUTATION_UNKNOWN) {
    sidecar_revoke (binding);
    *out_result = WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RECONCILE_REQUIRED;
  }
out:
  g_mutex_unlock (&binding->mutex);
  return rc;
}

void wyl_fact_artifact_win_sidecar_binding_free
    (WylFactArtifactWinSidecarBinding * binding)
{
  if (binding == NULL)
    return;
  g_mutex_lock (&binding->mutex);
  sidecar_revoke (binding);
  wyl_fact_artifact_win_working_handle_free (binding->working);
  wyl_fact_artifact_win_entry_free (binding->entry);
  g_mutex_unlock (&binding->mutex);
  g_mutex_clear (&binding->mutex);
  wyl_fact_artifact_win_lease_free (binding->lease);
  g_free (binding);
}
#endif

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/graph-artifact-windows-namespace-private.h"

#ifdef G_OS_WIN32
#include "fact/graph-artifact-windows-handle-private.h"
#include "fact/graph-artifact-windows-lock-private.h"
#include "fact/graph-artifact-windows-locator-private.h"

#include <string.h>

static gint win_namespace_test_fault;

void wyl_fact_artifact_win_namespace_set_test_fault
    (WylFactArtifactWinNamespaceTestFault fault)
{
  g_atomic_int_set (&win_namespace_test_fault, fault);
}

static gboolean
win_namespace_fault_take (WylFactArtifactWinNamespaceTestFault fault)
{
  return g_atomic_int_compare_and_exchange (&win_namespace_test_fault, fault,
      WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_NONE);
}

struct WylFactArtifactWinNamespace
{
  WylFactArtifactWinLocator *locator;
  WylFactArtifactWinEntry *main_entry;
  WylFactArtifactWinEntry *lock_entry;
  WylFactArtifactWinLockDomain *lock_domain;
  gboolean active;
  gint references;
};

static wyrelog_error_t namespace_acquire (WylFactArtifactWinNamespace *,
    gboolean, WylFactArtifactWinLease **);
static wyrelog_error_t lease_revalidate (WylFactArtifactWinLease *);
static WylFactArtifactWinLease *lease_ref (WylFactArtifactWinLease *);
static void binding_retain_lease_lifetime (WylFactArtifactWinBinding *);
static wyrelog_error_t io_state_attach_entry_validator
    (WylFactArtifactWinIoState *, WylFactArtifactWinLease *,
    WylFactArtifactWinEntry *);

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
  /* Generic fixed-entry access is reader-authorized.  The binding and every
   * live I/O session retain this lease, so it participates in the same native
   * lock domain as an exclusive mutation from another namespace instance. */
  WylFactArtifactWinLease *lease;
  WylFactArtifactWinEntry *entry;
  WylFactArtifactWinWorkingHandle *working;
  WylFactArtifactWinIoState *io_state;
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

static wyrelog_error_t
namespace_new_empty (const WylFactGraphDirectory *directory,
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

static wyrelog_error_t
namespace_attach_existing_main (WylFactArtifactWinNamespace *namespace_,
    const WylFactGraphWinIdentity *expected_main, gboolean create_lock)
{
  WylFactArtifactWinEntry *main_entry = NULL;
  WylFactArtifactWinEntry *lock_entry = NULL;
  HANDLE lock_handle = INVALID_HANDLE_VALUE;
  wyrelog_error_t rc;

  /* A reader-capable namespace is meaningful only when it has joined the
   * exact facts.duckdb.lock domain.  It never creates facts.duckdb; #615 is
   * still the sole provisioning path. */
  rc = wyl_fact_artifact_win_locator_open (namespace_->locator,
      name_for (WYL_FACT_ARTIFACT_MAIN), GENERIC_READ | GENERIC_WRITE, FALSE,
      &main_entry);
  if (rc == WYRELOG_E_OK && expected_main != NULL
      && !identity_equal (wyl_fact_artifact_win_entry_identity (main_entry),
          expected_main))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && create_lock)
    rc = wyl_fact_artifact_win_locator_open (namespace_->locator,
        name_for (WYL_FACT_ARTIFACT_LOCK), GENERIC_READ | GENERIC_WRITE,
        TRUE, &lock_entry);
  if (rc == WYRELOG_E_OK && !create_lock)
    rc = wyl_fact_artifact_win_locator_open (namespace_->locator,
        name_for (WYL_FACT_ARTIFACT_LOCK), GENERIC_READ | GENERIC_WRITE,
        FALSE, &lock_entry);
  if (rc == WYRELOG_E_BUSY && create_lock)
    rc = wyl_fact_artifact_win_locator_open (namespace_->locator,
        name_for (WYL_FACT_ARTIFACT_LOCK), GENERIC_READ | GENERIC_WRITE,
        FALSE, &lock_entry);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_entry_issue_working_handle (namespace_->locator,
        lock_entry, &lock_handle);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_lock_domain_open
        (wyl_fact_artifact_win_locator_identity (namespace_->locator),
        wyl_fact_artifact_win_entry_identity (lock_entry), lock_handle,
        &namespace_->lock_domain);
  if (rc != WYRELOG_E_OK) {
    if (lock_handle != INVALID_HANDLE_VALUE)
      CloseHandle (lock_handle);
    wyl_fact_artifact_win_entry_free (lock_entry);
    wyl_fact_artifact_win_entry_free (main_entry);
    return rc;
  }
  namespace_->main_entry = main_entry;
  namespace_->lock_entry = lock_entry;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_namespace_new (const WylFactGraphDirectory *directory,
    WylFactArtifactWinNamespace **out_namespace)
{
  WylFactArtifactWinNamespace *namespace_ = NULL;
  wyrelog_error_t rc;
  if (out_namespace != NULL)
    *out_namespace = NULL;
  rc = namespace_new_empty (directory, &namespace_);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = namespace_attach_existing_main (namespace_, NULL, FALSE);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_artifact_win_namespace_free (namespace_);
    return rc;
  }
  *out_namespace = namespace_;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_namespace_new_with_main (const WylFactGraphDirectory
    *directory, const WylFactGraphRegularFile *main_file,
    WylFactArtifactWinNamespace **out_namespace)
{
  WylFactArtifactWinNamespace *namespace_ = NULL;
  wyrelog_error_t rc;

  if (out_namespace != NULL)
    *out_namespace = NULL;
  if (directory == NULL || main_file == NULL || out_namespace == NULL
      || main_file->handle == NULL)
    return WYRELOG_E_INVALID;
  if (!handle_matches_identity ((HANDLE) main_file->handle,
          &main_file->identity))
    return WYRELOG_E_POLICY;
  rc = namespace_new_empty (directory, &namespace_);
  if (rc != WYRELOG_E_OK)
    return rc;
  /* #615 already minted this handle from durable operation evidence.  The
   * native namespace imports it only if the retained graph-relative fixed
   * name independently proves the identical FileId and protected ACL. */
  rc = namespace_attach_existing_main (namespace_, &main_file->identity, TRUE);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_artifact_win_namespace_free (namespace_);
    return rc;
  }
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
  WylFactArtifactWinLease *lease = NULL;
  wyrelog_error_t rc;

  if (out_binding != NULL)
    *out_binding = NULL;
  if (namespace_ == NULL || out_binding == NULL || fixed_name == NULL)
    return WYRELOG_E_INVALID;
  /* This compatibility-shaped fixed reader is deliberately unable to create
   * or mutate.  Crucially, it first joins the same facts.duckdb.lock reader
   * domain as every other namespace instance, so its session blocks an
   * exclusive mutation lease rather than bypassing it. */
  if (!sidecar_name (name) || create_new || access != GENERIC_READ)
    return WYRELOG_E_POLICY;
  if ((rc = namespace_acquire (namespace_, FALSE, &lease)) != WYRELOG_E_OK)
    return rc;
  rc = wyl_fact_artifact_win_locator_open (namespace_->locator, fixed_name,
      access, create_new, &entry);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_artifact_win_lease_free (lease);
    return rc;
  }
  rc = wyl_fact_artifact_win_entry_issue_working_handle (namespace_->locator,
      entry, &issued);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_working_handle_adopt (issued,
        wyl_fact_artifact_win_entry_identity (entry), &working);
  if (rc == WYRELOG_E_OK)
    issued = INVALID_HANDLE_VALUE;      /* adoption consumed this source exactly */
  if (rc == WYRELOG_E_OK)
    binding = g_try_new0 (WylFactArtifactWinBinding, 1);
  if (rc == WYRELOG_E_OK && binding == NULL)
    rc = WYRELOG_E_NOMEM;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_io_state_new (working, &binding->io_state);
  if (rc == WYRELOG_E_OK)
    rc = io_state_attach_entry_validator (binding->io_state, lease, entry);
  if (rc != WYRELOG_E_OK) {
    /* The issued duplicate is not published until adoption succeeds. */
    if (issued != INVALID_HANDLE_VALUE)
      CloseHandle (issued);
    if (binding != NULL) {
      if (binding->io_state != NULL)
        wyl_fact_artifact_win_io_state_free (binding->io_state);
      else
        wyl_fact_artifact_win_working_handle_free (working);
      g_free (binding);
    } else
      wyl_fact_artifact_win_working_handle_free (working);
    wyl_fact_artifact_win_entry_free (entry);
    wyl_fact_artifact_win_lease_free (lease);
    return rc;
  }
  binding->namespace_ = namespace_;
  binding->lease = lease;
  g_atomic_int_inc (&namespace_->references);
  binding_retain_lease_lifetime (binding);
  binding->entry = entry;
  binding->working = working;
  binding->active = TRUE;
  *out_binding = binding;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_binding_open_io_session (WylFactArtifactWinBinding
    *binding, WylFactArtifactWinIoSession **out_session)
{
  wyrelog_error_t rc;
  if (binding == NULL || !binding->active)
    return WYRELOG_E_POLICY;
  rc = lease_revalidate (binding->lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_entry_revalidate (binding->namespace_->locator,
        binding->entry);
  return rc ==
      WYRELOG_E_OK ? wyl_fact_artifact_win_io_session_open (binding->io_state,
      out_session) : rc;
}

void
wyl_fact_artifact_win_binding_free (WylFactArtifactWinBinding *binding)
{
  if (binding == NULL)
    return;
  binding->active = FALSE;
  wyl_fact_artifact_win_io_state_free (binding->io_state);
  wyl_fact_artifact_win_entry_free (binding->entry);
  wyl_fact_artifact_win_lease_free (binding->lease);
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
  WylFactArtifactWinIoState *io_state;
  gboolean active;
};

struct WylFactArtifactWinSidecarBinding
{
  WylFactArtifactWinLease *lease;
  WylFactArtifactWinEntry *entry;
  WylFactArtifactWinWorkingHandle *working;
  WylFactArtifactWinIoState *io_state;
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
    rc = wyl_fact_artifact_win_entry_revalidate (lease->namespace_->locator,
        lease->namespace_->lock_entry);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_lock_lease_revalidate (lease->lock);
  /* The lock lease proves its retained HANDLE.  Recheck the graph-relative
   * fixed lock name after that check too: rename/replacement must revoke an
   * already-issued lease before it can open main or create a sidecar. */
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_entry_revalidate (lease->namespace_->locator,
        lease->namespace_->lock_entry);
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

static void
binding_retain_lease_lifetime (WylFactArtifactWinBinding *binding)
{
  g_assert_nonnull (binding);
  g_assert_nonnull (binding->io_state);
  g_assert_nonnull (binding->lease);
  /* A session may outlive its public reader binding.  Its extra lease ref is
   * consumed by io_state only after the private duplicate closes. */
  wyl_fact_artifact_win_io_state_retain_lifetime (binding->io_state,
      lease_ref (binding->lease),
      (GDestroyNotify) wyl_fact_artifact_win_lease_free);
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
  if (rc == WYRELOG_E_OK)
    issued = INVALID_HANDLE_VALUE;
  if (rc != WYRELOG_E_OK && issued != INVALID_HANDLE_VALUE)
    CloseHandle (issued);
  return rc;
}

/* The state consumes the binding's private guardian reference.  Keep the raw
 * pointer only as an implementation detail for existing revalidation code;
 * destruction is owned by io_state so a live session can outlast its public
 * binding object safely. */
static wyrelog_error_t
binding_io_new (WylFactArtifactWinNamespace *namespace_,
    WylFactArtifactWinEntry *entry, WylFactArtifactWinWorkingHandle **working,
    WylFactArtifactWinIoState **state)
{
  wyrelog_error_t rc;
  if (working != NULL)
    *working = NULL;
  if (state != NULL)
    *state = NULL;
  if (working == NULL || state == NULL)
    return WYRELOG_E_INVALID;
  rc = binding_working_new (namespace_, entry, working);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_io_state_new (*working, state);
  if (rc != WYRELOG_E_OK && *working != NULL) {
    wyl_fact_artifact_win_working_handle_free (*working);
    *working = NULL;
  }
  return rc;
}

typedef struct
{
  WylFactArtifactWinLease *lease;
  gchar *name;
  WylFactGraphWinIdentity identity;
} WylFactArtifactWinEntryValidator;

static void
entry_validator_free (WylFactArtifactWinEntryValidator *validator)
{
  if (validator == NULL)
    return;
  wyl_fact_artifact_win_lease_free (validator->lease);
  g_free (validator->name);
  g_free (validator);
}

static wyrelog_error_t
entry_validator_check (gpointer user_data)
{
  WylFactArtifactWinEntryValidator *validator = user_data;
  WylFactArtifactWinEntry *observed = NULL;
  wyrelog_error_t rc;

  if (validator == NULL || validator->lease == NULL || validator->name == NULL)
    return WYRELOG_E_POLICY;
  if ((rc = lease_revalidate (validator->lease)) != WYRELOG_E_OK)
    return rc;
  rc = wyl_fact_artifact_win_locator_open (validator->lease->
      namespace_->locator, validator->name, GENERIC_READ, FALSE, &observed);
  if (rc == WYRELOG_E_OK
      && !identity_equal (wyl_fact_artifact_win_entry_identity (observed),
          &validator->identity))
    rc = WYRELOG_E_POLICY;
  wyl_fact_artifact_win_entry_free (observed);
  return rc;
}

static wyrelog_error_t
io_state_attach_entry_validator (WylFactArtifactWinIoState *state,
    WylFactArtifactWinLease *lease, WylFactArtifactWinEntry *entry)
{
  WylFactArtifactWinEntryValidator *validator;
  const gchar *name;

  if (state == NULL || lease == NULL || entry == NULL
      || (name = wyl_fact_artifact_win_entry_name (entry)) == NULL)
    return WYRELOG_E_INVALID;
  validator = g_try_new0 (WylFactArtifactWinEntryValidator, 1);
  if (validator == NULL)
    return WYRELOG_E_NOMEM;
  validator->name = g_strdup (name);
  if (validator->name == NULL) {
    g_free (validator);
    return WYRELOG_E_NOMEM;
  }
  validator->lease = lease_ref (lease);
  validator->identity = *wyl_fact_artifact_win_entry_identity (entry);
  wyl_fact_artifact_win_io_state_set_validator (state, entry_validator_check,
      validator, (GDestroyNotify) entry_validator_free);
  return WYRELOG_E_OK;
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
  rc = binding_io_new (lease->namespace_, lease->namespace_->main_entry,
      &binding->working, &binding->io_state);
  if (rc == WYRELOG_E_OK)
    rc = io_state_attach_entry_validator (binding->io_state, lease,
        lease->namespace_->main_entry);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_artifact_win_io_state_free (binding->io_state);
    g_free (binding);
    return rc;
  }
  binding->lease = lease_ref (lease);
  wyl_fact_artifact_win_io_state_retain_lifetime (binding->io_state,
      lease_ref (lease), (GDestroyNotify) wyl_fact_artifact_win_lease_free);
  binding->active = TRUE;
  *out_binding = binding;
  return WYRELOG_E_OK;
}

wyrelog_error_t
    wyl_fact_artifact_win_main_binding_open_io_session
    (WylFactArtifactWinMainBinding * binding,
    WylFactArtifactWinIoSession ** out_session) {
  wyrelog_error_t rc;
  if (binding == NULL || !binding->active)
    return WYRELOG_E_POLICY;
  rc = lease_revalidate (binding->lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_entry_revalidate (binding->lease->
        namespace_->locator, binding->lease->namespace_->main_entry);
  return rc ==
      WYRELOG_E_OK ? wyl_fact_artifact_win_io_session_open (binding->io_state,
      out_session) : rc;
}

void
wyl_fact_artifact_win_main_binding_free (WylFactArtifactWinMainBinding *binding)
{
  if (binding == NULL)
    return;
  binding->active = FALSE;
  wyl_fact_artifact_win_io_state_free (binding->io_state);
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
    rc = !binding->io_open ? WYRELOG_E_POLICY
        : wyl_fact_artifact_win_working_handle_revalidate (binding->working);
    /* |supplied| is intentionally not authority evidence.  It is a caller
     * I/O duplicate and may have been raw-closed then numerically reused. */
    (void) supplied;
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
  binding->io_open = FALSE;     /* session state, not a raw HANDLE, gates mutation */
  g_mutex_init (&binding->mutex);
  rc = binding_io_new (lease->namespace_, entry, &binding->working,
      &binding->io_state);
  if (rc == WYRELOG_E_OK)
    rc = io_state_attach_entry_validator (binding->io_state, lease, entry);
  if (rc == WYRELOG_E_OK)
    wyl_fact_artifact_win_io_state_retain_lifetime (binding->io_state,
        lease_ref (lease), (GDestroyNotify) wyl_fact_artifact_win_lease_free);
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
    wyl_fact_artifact_win_sidecar_binding_open_io_session
    (WylFactArtifactWinSidecarBinding * binding,
    WylFactArtifactWinIoSession ** out_session) {
  wyrelog_error_t rc;
  if (binding == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&binding->mutex);
  rc = sidecar_revalidate_locked (binding, FALSE, INVALID_HANDLE_VALUE);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_io_session_open (binding->io_state, out_session);
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
      || wyl_fact_artifact_win_io_state_has_session (binding->io_state)
      || wyl_fact_artifact_win_io_state_is_aborted (binding->io_state)) {
    if (wyl_fact_artifact_win_io_state_has_session (binding->io_state)
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
  if (!binding->active
      || wyl_fact_artifact_win_io_state_has_session (binding->io_state)
      || wyl_fact_artifact_win_io_state_is_aborted (binding->io_state)) {
    if (wyl_fact_artifact_win_io_state_has_session (binding->io_state)
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
  wyl_fact_artifact_win_io_state_free (binding->io_state);
  wyl_fact_artifact_win_entry_free (binding->entry);
  g_mutex_unlock (&binding->mutex);
  g_mutex_clear (&binding->mutex);
  wyl_fact_artifact_win_lease_free (binding->lease);
  g_free (binding);
}

/* #609 staging is deliberately separate from DuckDB's spill children.  A
 * spill child is governed by its bounded-root grammar; a replacement source
 * is one fixed namespace entry and cannot be smuggled through that authority.
 */
struct WylFactArtifactWinTempBinding
{
  WylFactArtifactWinLease *lease;
  WylFactArtifactWinEntry *entry;
  WylFactArtifactWinWorkingHandle *working;
  WylFactArtifactWinIoState *io_state;
  gboolean active;
  gboolean io_open;
  GMutex mutex;
};

static gboolean
replacement_token_valid (const gchar *token)
{
  const gchar *p;
  if (token == NULL || token[0] == '\0' || strpbrk (token, "/\\\\") != NULL)
    return FALSE;
  for (p = token; *p != '\0'; p++)
    if (!g_ascii_isalnum (*p) && *p != '-' && *p != '_')
      return FALSE;
  return strlen (token) <= 128;
}

static void
replacement_temp_revoke (WylFactArtifactWinTempBinding *binding)
{
  binding->active = FALSE;
  binding->io_open = FALSE;
}

static wyrelog_error_t
replacement_temp_check_locked (WylFactArtifactWinTempBinding *binding,
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
    rc = !binding->io_open ? WYRELOG_E_POLICY
        : wyl_fact_artifact_win_working_handle_revalidate (binding->working);
    (void) supplied;
  }
  if (rc != WYRELOG_E_OK)
    replacement_temp_revoke (binding);
  return rc;
}

wyrelog_error_t
wyl_fact_artifact_win_lease_create_temp_binding (WylFactArtifactWinLease *lease,
    const gchar *token, WylFactArtifactWinTempBinding **out_binding)
{
  WylFactArtifactWinTempBinding *binding = NULL;
  g_autofree gchar *name = NULL;
  wyrelog_error_t rc;
  if (out_binding != NULL)
    *out_binding = NULL;
  if (lease == NULL || out_binding == NULL || !lease->exclusive)
    return WYRELOG_E_POLICY;
  if (!replacement_token_valid (token))
    return WYRELOG_E_INVALID;
  if ((rc = lease_revalidate (lease)) != WYRELOG_E_OK)
    return rc;
  name = g_strdup_printf ("tmp-%s", token);
  if (name == NULL)
    return WYRELOG_E_NOMEM;
  binding = g_try_new0 (WylFactArtifactWinTempBinding, 1);
  if (binding == NULL)
    return WYRELOG_E_NOMEM;
  rc = wyl_fact_artifact_win_locator_open (lease->namespace_->locator, name,
      GENERIC_READ | GENERIC_WRITE | DELETE, TRUE, &binding->entry);
  if (rc == WYRELOG_E_OK)
    rc = binding_io_new (lease->namespace_, binding->entry,
        &binding->working, &binding->io_state);
  if (rc == WYRELOG_E_OK)
    rc = io_state_attach_entry_validator (binding->io_state, lease,
        binding->entry);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_artifact_win_io_state_free (binding->io_state);
    wyl_fact_artifact_win_entry_free (binding->entry);
    g_free (binding);
    return rc;
  }
  binding->lease = lease_ref (lease);
  wyl_fact_artifact_win_io_state_retain_lifetime (binding->io_state,
      lease_ref (lease), (GDestroyNotify) wyl_fact_artifact_win_lease_free);
  binding->active = TRUE;
  binding->io_open = FALSE;
  g_mutex_init (&binding->mutex);
  *out_binding = binding;
  return WYRELOG_E_OK;
}

wyrelog_error_t
    wyl_fact_artifact_win_temp_binding_open_io_session
    (WylFactArtifactWinTempBinding * binding,
    WylFactArtifactWinIoSession ** out_session) {
  wyrelog_error_t rc;
  if (out_session != NULL)
    *out_session = NULL;
  if (binding == NULL || out_session == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&binding->mutex);
  rc = replacement_temp_check_locked (binding, FALSE, INVALID_HANDLE_VALUE);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_io_session_open (binding->io_state, out_session);
  g_mutex_unlock (&binding->mutex);
  return rc;
}

wyrelog_error_t
    wyl_fact_artifact_win_temp_binding_replace_sidecar
    (WylFactArtifactWinTempBinding * source,
    WylFactArtifactWinSidecarBinding * destination,
    WylFactArtifactWinSidecarReplaceResult * out_result) {
  WylFactArtifactWinMutationEffect effect =
      WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED;
  WylFactArtifactWinEntry *replaced_entry;
  WylFactArtifactWinIoState *old_source_state;
  WylFactArtifactWinIoState *old_destination_state;
  wyrelog_error_t rc;
  if (out_result != NULL)
    *out_result = WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_NOT_REPLACED;
  if (source == NULL || destination == NULL || out_result == NULL
      || source->lease != destination->lease)
    return WYRELOG_E_POLICY;
  /* Lock order is source before destination.  That holds only because the
   * two bindings are distinct types and this is the only function taking
   * both, so no caller can transpose the arguments.  A sidecar-to-sidecar
   * replacement would break the argument and the pair would then have to be
   * ordered canonically by mutex address. */
  g_mutex_lock (&source->mutex);
  g_mutex_lock (&destination->mutex);
  if (!source->active
      || wyl_fact_artifact_win_io_state_has_session (source->io_state)
      || wyl_fact_artifact_win_io_state_is_aborted (source->io_state)
      || !destination->active
      || wyl_fact_artifact_win_io_state_has_session (destination->io_state)
      || wyl_fact_artifact_win_io_state_is_aborted (destination->io_state)
      || !destination->lease->exclusive) {
    if (wyl_fact_artifact_win_io_state_has_session (source->io_state)
        && wyl_fact_artifact_win_working_handle_revalidate (source->working) !=
        WYRELOG_E_OK)
      replacement_temp_revoke (source);
    if (wyl_fact_artifact_win_io_state_has_session (destination->io_state)
        &&
        wyl_fact_artifact_win_working_handle_revalidate (destination->working)
        != WYRELOG_E_OK)
      sidecar_revoke (destination);
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  rc = replacement_temp_check_locked (source, FALSE, INVALID_HANDLE_VALUE);
  if (rc == WYRELOG_E_OK)
    rc = sidecar_revalidate_locked (destination, FALSE, INVALID_HANDLE_VALUE);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_entry_flush (source->lease->namespace_->locator,
        source->entry);
  /* Revalidate both associations after source durability and immediately
   * before rename.  A stale destination is never overwritten. */
  if (rc == WYRELOG_E_OK)
    rc = replacement_temp_check_locked (source, FALSE, INVALID_HANDLE_VALUE);
  if (rc == WYRELOG_E_OK)
    rc = sidecar_revalidate_locked (destination, FALSE, INVALID_HANDLE_VALUE);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (win_namespace_fault_take
      (WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_REPLACE_PRE_FINAL_DESTINATION_SUBSTITUTE))
  {
    WylFactArtifactWinEntry *substitute = NULL;
    rc = wyl_fact_artifact_win_locator_open (source->lease->namespace_->locator,
        "tmp-native-replace-substitute", GENERIC_READ | GENERIC_WRITE | DELETE,
        TRUE, &substitute);
    if (rc == WYRELOG_E_OK) {
      WylFactArtifactWinMutationEffect substitute_effect =
          WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED;
      rc = wyl_fact_artifact_win_entry_rename_replace_verified
          (source->lease->namespace_->locator, substitute,
          name_for (destination->name), &substitute_effect);
      wyl_fact_artifact_win_entry_free (substitute);
      if (substitute_effect != WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED
          && rc == WYRELOG_E_OK)
        rc = WYRELOG_E_POLICY;
    }
  }
  if (rc == WYRELOG_E_OK)
    rc = sidecar_revalidate_locked (destination, FALSE, INVALID_HANDLE_VALUE);
  if (rc != WYRELOG_E_OK)
    goto out;
  /* Native replacement serializes sanctioned writers through the shared
   * exclusive lease.  It is deliberately not advertised as a target FileId
   * compare-and-swap against an authority-bypassing writer. */
  rc = wyl_fact_artifact_win_entry_rename_replace_verified
      (source->lease->namespace_->locator, source->entry,
      name_for (destination->name), &effect);
  if (effect != WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED) {
    if (effect == WYL_FACT_ARTIFACT_WIN_MUTATION_UNKNOWN) {
      replacement_temp_revoke (source);
      sidecar_revoke (destination);
      *out_result = WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_RECONCILE_REQUIRED;
    }
    goto out;
  }
  /* Rename is the linearization point.  Retire both pre-rename guardian
   * states before publishing the destination binding: source's validator is
   * still tied to tmp-<token>, while destination's guardian still addresses
   * the unlinked old sidecar -- the POSIX rename removes that link as part
   * of the same operation, which is why the superseded object survives here
   * with no name at all.  A fresh destination state is minted from the
   * transferred entry, so no post-replace session can reach stale content. */
  replaced_entry = destination->entry;
  old_source_state = source->io_state;
  old_destination_state = destination->io_state;
  source->io_state = NULL;
  source->working = NULL;
  destination->io_state = NULL;
  destination->working = NULL;
  destination->entry = source->entry;
  source->entry = NULL;
  source->active = FALSE;
  destination->creator = FALSE;
  wyl_fact_artifact_win_io_state_free (old_source_state);
  wyl_fact_artifact_win_io_state_free (old_destination_state);
  wyl_fact_artifact_win_entry_free (replaced_entry);
  {
    /* |rc| can already carry the allocation failure the transport reported
     * alongside an APPLIED rename.  Overwriting it here would launder that
     * into whatever the follow-on state minting happens to report, so keep
     * the first evidence and only fold in a later failure. */
    wyrelog_error_t minted = binding_io_new (destination->lease->namespace_,
        destination->entry, &destination->working, &destination->io_state);
    if (minted == WYRELOG_E_OK)
      minted = io_state_attach_entry_validator (destination->io_state,
          destination->lease, destination->entry);
    if (rc == WYRELOG_E_OK)
      rc = minted;
    if (minted != WYRELOG_E_OK) {
      sidecar_revoke (destination);
      *out_result = WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_RECONCILE_REQUIRED;
      goto out;
    }
  }
  {
    wyrelog_error_t post = win_namespace_fault_take
        (WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_REPLACE_POST_RENAME_UNCERTAIN)
        ? WYRELOG_E_IO : wyl_fact_artifact_win_locator_flush_directory
        (destination->lease->namespace_->locator);
    if (post == WYRELOG_E_OK)
      post = sidecar_revalidate_locked (destination, FALSE,
          INVALID_HANDLE_VALUE);
    if (post == WYRELOG_E_OK && rc == WYRELOG_E_OK)
      *out_result = WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_REPLACED;
    else {
      replacement_temp_revoke (source);
      sidecar_revoke (destination);
      *out_result = WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_RECONCILE_REQUIRED;
      if (rc == WYRELOG_E_OK)
        rc = post;
    }
  }
out:
  g_mutex_unlock (&destination->mutex);
  g_mutex_unlock (&source->mutex);
  return rc;
}

void
wyl_fact_artifact_win_temp_binding_free (WylFactArtifactWinTempBinding *binding)
{
  if (binding == NULL)
    return;
  g_mutex_lock (&binding->mutex);
  replacement_temp_revoke (binding);
  wyl_fact_artifact_win_io_state_free (binding->io_state);
  wyl_fact_artifact_win_entry_free (binding->entry);
  g_mutex_unlock (&binding->mutex);
  g_mutex_clear (&binding->mutex);
  wyl_fact_artifact_win_lease_free (binding->lease);
  g_free (binding);
}

/* Temporary-token lifecycle is deliberately separate from #609 staging.
 * Staging is consumed by sidecar replacement; a token is an independently
 * recoverable owner artifact.  Keeping the types distinct prevents a caller
 * from accidentally converting spill/replacement authority into recovery
 * deletion authority. */
struct WylFactArtifactWinTempToken
{
  WylFactArtifactWinLease *lease;
  WylFactArtifactWinEntry *entry;
  WylFactArtifactWinWorkingHandle *working;
  WylFactArtifactWinIoState *io_state;
  gchar *token;
  gboolean active;
  gboolean io_open;
  GMutex mutex;
};

struct WylFactArtifactWinTempRecoveryEvidence
{
  gchar *token;
  WylFactGraphWinIdentity directory_identity;
  WylFactGraphWinIdentity lock_identity;
  WylFactGraphWinIdentity identity;
};

static gboolean
temp_token_valid (const gchar *token)
{
  const gchar *p;
  if (token == NULL || token[0] == '\0' || strlen (token) > 48
      || strpbrk (token, "/\\\\") != NULL)
    return FALSE;
  for (p = token; *p != '\0'; p++)
    if (!g_ascii_isalnum (*p) && *p != '-')
      return FALSE;
  return TRUE;
}

static gchar *
temp_token_name (const gchar *token)
{
  return temp_token_valid (token) ? g_strdup_printf ("tmp-%s", token) : NULL;
}

static void
temp_token_revoke (WylFactArtifactWinTempToken *token)
{
  token->active = FALSE;
  token->io_open = FALSE;
}

static wyrelog_error_t
temp_token_check_locked (WylFactArtifactWinTempToken *token,
    gboolean require_working, HANDLE supplied)
{
  wyrelog_error_t rc;
  if (token == NULL || !token->active || token->lease == NULL
      || !token->lease->exclusive || !temp_token_valid (token->token))
    return WYRELOG_E_POLICY;
  rc = lease_revalidate (token->lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_entry_revalidate (token->lease->
        namespace_->locator, token->entry);
  if (rc == WYRELOG_E_OK && require_working) {
    rc = !token->io_open ? WYRELOG_E_POLICY
        : wyl_fact_artifact_win_working_handle_revalidate (token->working);
    (void) supplied;
  }
  if (rc != WYRELOG_E_OK)
    temp_token_revoke (token);
  return rc;
}

wyrelog_error_t
wyl_fact_artifact_win_lease_create_temp_token (WylFactArtifactWinLease *lease,
    const gchar *token_name, WylFactArtifactWinTempToken **out_token)
{
  WylFactArtifactWinTempToken *token = NULL;
  g_autofree gchar *name = NULL;
  wyrelog_error_t rc;
  if (out_token != NULL)
    *out_token = NULL;
  if (lease == NULL || out_token == NULL || !lease->exclusive)
    return WYRELOG_E_POLICY;
  name = temp_token_name (token_name);
  if (name == NULL)
    return WYRELOG_E_INVALID;
  if ((rc = lease_revalidate (lease)) != WYRELOG_E_OK)
    return rc;
  token = g_try_new0 (WylFactArtifactWinTempToken, 1);
  if (token == NULL)
    return WYRELOG_E_NOMEM;
  rc = wyl_fact_artifact_win_locator_open (lease->namespace_->locator, name,
      GENERIC_READ | GENERIC_WRITE | DELETE, TRUE, &token->entry);
  if (rc == WYRELOG_E_OK)
    rc = binding_io_new (lease->namespace_, token->entry, &token->working,
        &token->io_state);
  if (rc == WYRELOG_E_OK)
    rc = io_state_attach_entry_validator (token->io_state, lease, token->entry);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_artifact_win_io_state_free (token->io_state);
    wyl_fact_artifact_win_entry_free (token->entry);
    g_free (token);
    return rc;
  }
  token->token = g_strdup (token_name);
  if (token->token == NULL) {
    wyl_fact_artifact_win_io_state_free (token->io_state);
    wyl_fact_artifact_win_entry_free (token->entry);
    g_free (token);
    return WYRELOG_E_NOMEM;
  }
  token->lease = lease_ref (lease);
  wyl_fact_artifact_win_io_state_retain_lifetime (token->io_state,
      lease_ref (lease), (GDestroyNotify) wyl_fact_artifact_win_lease_free);
  token->active = TRUE;
  token->io_open = FALSE;
  g_mutex_init (&token->mutex);
  *out_token = token;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_temp_token_open_io_session (WylFactArtifactWinTempToken
    *token, WylFactArtifactWinIoSession **out_session)
{
  wyrelog_error_t rc;
  if (token == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&token->mutex);
  rc = temp_token_check_locked (token, FALSE, INVALID_HANDLE_VALUE);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_io_session_open (token->io_state, out_session);
  g_mutex_unlock (&token->mutex);
  return rc;
}

wyrelog_error_t
    wyl_fact_artifact_win_temp_token_rename_no_replace
    (WylFactArtifactWinTempToken * token, const gchar * destination_token,
    WylFactArtifactWinMutationEffect * out_effect)
{
  g_autofree gchar *destination = NULL;
  wyrelog_error_t rc;
  if (out_effect != NULL)
    *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED;
  if (token == NULL || out_effect == NULL)
    return WYRELOG_E_INVALID;
  destination = temp_token_name (destination_token);
  if (destination == NULL || g_strcmp0 (token->token, destination_token) == 0)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&token->mutex);
  if (wyl_fact_artifact_win_io_state_has_session (token->io_state)
      || wyl_fact_artifact_win_io_state_is_aborted (token->io_state)) {
    if (wyl_fact_artifact_win_working_handle_revalidate (token->working)
        != WYRELOG_E_OK)
      temp_token_revoke (token);
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  rc = temp_token_check_locked (token, FALSE, INVALID_HANDLE_VALUE);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_entry_flush (token->lease->namespace_->locator,
        token->entry);
  if (rc == WYRELOG_E_OK)
    rc = temp_token_check_locked (token, FALSE, INVALID_HANDLE_VALUE);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_entry_rename_no_replace
        (token->lease->namespace_->locator, token->entry, destination,
        out_effect);
  if (*out_effect == WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED) {
    g_free (token->token);
    token->token = g_strdup (destination_token);
    if (token->token == NULL) {
      temp_token_revoke (token);
      rc = WYRELOG_E_NOMEM;
    } else {
      wyrelog_error_t post = wyl_fact_artifact_win_locator_flush_directory
          (token->lease->namespace_->locator);
      if (post == WYRELOG_E_OK)
        post = temp_token_check_locked (token, FALSE, INVALID_HANDLE_VALUE);
      if (post != WYRELOG_E_OK) {
        temp_token_revoke (token);
        if (rc == WYRELOG_E_OK)
          rc = post;
      }
    }
  } else if (*out_effect == WYL_FACT_ARTIFACT_WIN_MUTATION_UNKNOWN)
    temp_token_revoke (token);
out:
  g_mutex_unlock (&token->mutex);
  return rc;
}

wyrelog_error_t
wyl_fact_artifact_win_temp_token_unlink (WylFactArtifactWinTempToken *token,
    WylFactArtifactWinMutationEffect *out_effect)
{
  wyrelog_error_t rc;
  if (out_effect != NULL)
    *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED;
  if (token == NULL || out_effect == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&token->mutex);
  if (wyl_fact_artifact_win_io_state_has_session (token->io_state)
      || wyl_fact_artifact_win_io_state_is_aborted (token->io_state)) {
    if (wyl_fact_artifact_win_working_handle_revalidate (token->working)
        != WYRELOG_E_OK)
      temp_token_revoke (token);
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  rc = temp_token_check_locked (token, FALSE, INVALID_HANDLE_VALUE);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_entry_delete_exact (token->lease->
        namespace_->locator, token->entry, out_effect);
  if (*out_effect == WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED) {
    /* Delete is linearized.  Revoke before durability reporting so a failed
     * flush cannot leave deletion authority live. */
    temp_token_revoke (token);
    {
      wyrelog_error_t post = wyl_fact_artifact_win_locator_flush_directory
          (token->lease->namespace_->locator);
      if (rc == WYRELOG_E_OK)
        rc = post;
    }
  } else if (*out_effect == WYL_FACT_ARTIFACT_WIN_MUTATION_UNKNOWN)
    temp_token_revoke (token);
out:
  g_mutex_unlock (&token->mutex);
  return rc;
}

wyrelog_error_t
    wyl_fact_artifact_win_temp_token_export_recovery_evidence
    (WylFactArtifactWinTempToken * token,
    WylFactArtifactWinTempRecoveryEvidence ** out_evidence) {
  WylFactArtifactWinTempRecoveryEvidence *evidence;
  wyrelog_error_t rc;
  if (out_evidence != NULL)
    *out_evidence = NULL;
  if (token == NULL || out_evidence == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&token->mutex);
  rc = temp_token_check_locked (token, FALSE, INVALID_HANDLE_VALUE);
  if (rc == WYRELOG_E_OK) {
    evidence = g_try_new0 (WylFactArtifactWinTempRecoveryEvidence, 1);
    if (evidence == NULL)
      rc = WYRELOG_E_NOMEM;
    else {
      evidence->token = g_strdup (token->token);
      if (evidence->token == NULL) {
        g_free (evidence);
        rc = WYRELOG_E_NOMEM;
      } else {
        evidence->identity =
            *wyl_fact_artifact_win_entry_identity (token->entry);
        evidence->directory_identity = *wyl_fact_artifact_win_locator_identity
            (token->lease->namespace_->locator);
        evidence->lock_identity = *wyl_fact_artifact_win_entry_identity
            (token->lease->namespace_->lock_entry);
        *out_evidence = evidence;
      }
    }
  }
  g_mutex_unlock (&token->mutex);
  return rc;
}

void wyl_fact_artifact_win_temp_recovery_evidence_free
    (WylFactArtifactWinTempRecoveryEvidence * evidence)
{
  if (evidence != NULL) {
    g_free (evidence->token);
    g_free (evidence);
  }
}

#define WIN_TEMP_EVIDENCE_MAGIC "WTE1"
#define WIN_TEMP_EVIDENCE_HEADER_SIZE 77

static void
win_temp_evidence_write_identity (guint8 *data,
    const WylFactGraphWinIdentity *identity)
{
  guint64 volume = GUINT64_TO_BE ((guint64) identity->volume_serial);
  memcpy (data, &volume, sizeof volume);
  memcpy (data + sizeof volume, identity->file_id, sizeof identity->file_id);
}

static void
win_temp_evidence_read_identity (const guint8 *data,
    WylFactGraphWinIdentity *identity)
{
  guint64 volume;
  memcpy (&volume, data, sizeof volume);
  /* The encoder writes all 64 bits and observed identities carry
   * FILE_ID_INFO's full width, so truncating here decoded less than was
   * written.  Nothing past the magic and token is authenticated, so
   * tampering confined to the discarded high half decoded to the live
   * identity and the gate below accepted it; the mismatch[5] and mismatch[29]
   * flips in test_native_namespace_main_sidecar_lifecycle keep that refused.
   * Truncation also denied valid evidence on a volume whose high half is set,
   * which no test reaches: NTFS normally leaves that half zero. */
  identity->volume_serial = GUINT64_FROM_BE (volume);
  memcpy (identity->file_id, data + sizeof volume, sizeof identity->file_id);
}

wyrelog_error_t
    wyl_fact_artifact_win_temp_recovery_evidence_encode
    (const WylFactArtifactWinTempRecoveryEvidence * evidence,
    GBytes ** out_bytes)
{
  guint8 *data;
  gsize length;
  if (out_bytes != NULL)
    *out_bytes = NULL;
  if (evidence == NULL || out_bytes == NULL || !temp_token_valid
      (evidence->token))
    return WYRELOG_E_INVALID;
  length = strlen (evidence->token);
  data = g_try_malloc (WIN_TEMP_EVIDENCE_HEADER_SIZE + length);
  if (data == NULL)
    return WYRELOG_E_NOMEM;
  memcpy (data, WIN_TEMP_EVIDENCE_MAGIC, 4);
  data[4] = (guint8) length;
  win_temp_evidence_write_identity (data + 5, &evidence->directory_identity);
  win_temp_evidence_write_identity (data + 29, &evidence->lock_identity);
  win_temp_evidence_write_identity (data + 53, &evidence->identity);
  memcpy (data + WIN_TEMP_EVIDENCE_HEADER_SIZE, evidence->token, length);
  *out_bytes = g_bytes_new_take (data, WIN_TEMP_EVIDENCE_HEADER_SIZE + length);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_temp_recovery_evidence_decode (GBytes *bytes,
    WylFactArtifactWinTempRecoveryEvidence **out_evidence)
{
  const guint8 *data;
  WylFactArtifactWinTempRecoveryEvidence *evidence;
  gsize size = 0;
  if (out_evidence != NULL)
    *out_evidence = NULL;
  if (bytes == NULL || out_evidence == NULL)
    return WYRELOG_E_INVALID;
  data = g_bytes_get_data (bytes, &size);
  if (size < WIN_TEMP_EVIDENCE_HEADER_SIZE
      || memcmp (data, WIN_TEMP_EVIDENCE_MAGIC, 4) != 0
      || size != WIN_TEMP_EVIDENCE_HEADER_SIZE + (gsize) data[4])
    return WYRELOG_E_INVALID;
  evidence = g_try_new0 (WylFactArtifactWinTempRecoveryEvidence, 1);
  if (evidence == NULL)
    return WYRELOG_E_NOMEM;
  evidence->token = g_strndup ((const gchar *) data +
      WIN_TEMP_EVIDENCE_HEADER_SIZE, data[4]);
  if (!temp_token_valid (evidence->token)) {
    wyl_fact_artifact_win_temp_recovery_evidence_free (evidence);
    return WYRELOG_E_INVALID;
  }
  win_temp_evidence_read_identity (data + 5, &evidence->directory_identity);
  win_temp_evidence_read_identity (data + 29, &evidence->lock_identity);
  win_temp_evidence_read_identity (data + 53, &evidence->identity);
  *out_evidence = evidence;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_lease_recover_temp_token (WylFactArtifactWinLease *lease,
    const WylFactArtifactWinTempRecoveryEvidence *evidence,
    WylFactArtifactWinMutationEffect *out_effect)
{
  g_autofree gchar *name = NULL;
  WylFactArtifactWinEntry *entry = NULL;
  wyrelog_error_t rc;
  if (out_effect != NULL)
    *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED;
  if (lease == NULL || evidence == NULL || out_effect == NULL
      || !lease->exclusive)
    return WYRELOG_E_INVALID;
  name = temp_token_name (evidence->token);
  if (name == NULL)
    return WYRELOG_E_INVALID;
  if ((rc = lease_revalidate (lease)) != WYRELOG_E_OK)
    return rc;
  if (!identity_equal (wyl_fact_artifact_win_locator_identity
          (lease->namespace_->locator), &evidence->directory_identity)
      || !identity_equal (wyl_fact_artifact_win_entry_identity
          (lease->namespace_->lock_entry), &evidence->lock_identity))
    return WYRELOG_E_POLICY;
  rc = wyl_fact_artifact_win_locator_open (lease->namespace_->locator, name,
      GENERIC_READ | GENERIC_WRITE | DELETE, FALSE, &entry);
  if (rc == WYRELOG_E_NOT_FOUND)
    return WYRELOG_E_OK;        /* idempotent abandoned-artifact recovery */
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!identity_equal (wyl_fact_artifact_win_entry_identity (entry),
          &evidence->identity)) {
    wyl_fact_artifact_win_entry_free (entry);
    return WYRELOG_E_POLICY;
  }
  if ((rc = lease_revalidate (lease)) == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_entry_revalidate (lease->namespace_->locator,
        entry);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_entry_delete_exact (lease->namespace_->locator,
        entry, out_effect);
  if (*out_effect == WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED) {
    wyrelog_error_t post = wyl_fact_artifact_win_locator_flush_directory
        (lease->namespace_->locator);
    if (rc == WYRELOG_E_OK)
      rc = post;
  }
  wyl_fact_artifact_win_entry_free (entry);
  return rc;
}

void
wyl_fact_artifact_win_temp_token_free (WylFactArtifactWinTempToken *token)
{
  if (token == NULL)
    return;
  g_mutex_lock (&token->mutex);
  temp_token_revoke (token);
  wyl_fact_artifact_win_io_state_free (token->io_state);
  wyl_fact_artifact_win_entry_free (token->entry);
  g_mutex_unlock (&token->mutex);
  g_mutex_clear (&token->mutex);
  wyl_fact_artifact_win_lease_free (token->lease);
  g_free (token->token);
  g_free (token);
}

struct WylFactArtifactWinTempRoot
{
  WylFactArtifactWinLease *lease;
  WylFactArtifactWinDirectory *directory;
  gchar *logical_name;
  gboolean active;
  gint references;
  GMutex mutex;
};
struct WylFactArtifactWinTempChild
{
  WylFactArtifactWinTempRoot *root;
  WylFactArtifactWinEntry *entry;
  gboolean active;
  gboolean io_terminal;
  guint io_open;
  gint references;
  GPtrArray *bindings;
  GMutex mutex;
};
struct WylFactArtifactWinTempChildBinding
{
  WylFactArtifactWinTempChild *child;
  WylFactArtifactWinWorkingHandle *working;
  WylFactArtifactWinIoState *io_state;
  gboolean active;
  gboolean io_open;
};

static gboolean
temp_child_name (const gchar *name)
{
  const gchar *p;
  if (name == NULL || strpbrk (name, "/\\\\") != NULL)
    return FALSE;
  if (g_str_has_prefix (name, "duckdb_temp_storage_")) {
    p = name + strlen ("duckdb_temp_storage_");
    if (g_str_has_prefix (p, "DEFAULT"))
      p += strlen ("DEFAULT");
    else {
      static const gchar *const classes[] = { "S32K", "S64K", "S96K",
        "S128K", "S160K", "S192K", "S224K"
      };
      gboolean matched = FALSE;
      for (guint i = 0; i < G_N_ELEMENTS (classes); i++)
        if (g_str_has_prefix (p, classes[i])) {
          p += strlen (classes[i]);
          matched = TRUE;
          break;
        }
      if (!matched)
        return FALSE;
    }
    if (*p++ != '-')
      return FALSE;
    const gchar *digits = p;
    while (g_ascii_isdigit (*p))
      p++;
    return p != digits && (digits[0] == '0' ? p == digits + 1
        : (p - digits) <= 20) && g_strcmp0 (p, ".tmp") == 0;
  }
  if (!g_str_has_prefix (name, "duckdb_temp_block-"))
    return FALSE;
  p = name + strlen ("duckdb_temp_block-");
  const gchar *digits = p;
  while (g_ascii_isdigit (*p))
    p++;
  return p != digits && (digits[0] == '0' ? p == digits + 1
      : (p - digits) <= 20) && g_strcmp0 (p, ".block") == 0;
}

static WylFactArtifactWinTempRoot *temp_root_ref
    (WylFactArtifactWinTempRoot * root)
{
  if (root != NULL)
    g_atomic_int_inc (&root->references);
  return root;
}

static WylFactArtifactWinTempChild *temp_child_ref
    (WylFactArtifactWinTempChild * child)
{
  if (child != NULL)
    g_atomic_int_inc (&child->references);
  return child;
}

static void temp_root_unref (WylFactArtifactWinTempRoot *);
static void temp_child_unref (WylFactArtifactWinTempChild *);

static wyrelog_error_t
temp_root_check (WylFactArtifactWinTempRoot *root)
{
  wyrelog_error_t rc;
  if (root == NULL || !root->active)
    return WYRELOG_E_POLICY;
  rc = lease_revalidate (root->lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_directory_revalidate
        (root->lease->namespace_->locator, root->directory);
  if (rc != WYRELOG_E_OK)
    root->active = FALSE;
  return rc;
}

static wyrelog_error_t
temp_child_check (WylFactArtifactWinTempChild *child)
{
  wyrelog_error_t rc;
  if (child == NULL || !child->active)
    return WYRELOG_E_POLICY;
  g_mutex_lock (&child->root->mutex);
  rc = temp_root_check (child->root);
  g_mutex_unlock (&child->root->mutex);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_directory_entry_revalidate
        (child->root->lease->namespace_->locator, child->root->directory,
        child->entry);
  if (rc != WYRELOG_E_OK)
    child->active = FALSE;
  return rc;
}

static wyrelog_error_t
temp_child_session_validate (gpointer user_data)
{
  return temp_child_check (user_data);
}

static void
temp_binding_revoke (WylFactArtifactWinTempChildBinding *binding)
{
  if (binding->io_open && binding->child->io_open > 0)
    binding->child->io_open--;
  binding->active = FALSE;
  binding->io_open = FALSE;
  binding->child->io_terminal = TRUE;
}

static wyrelog_error_t
temp_binding_check (WylFactArtifactWinTempChildBinding *binding,
    gboolean require_handle, HANDLE supplied)
{
  wyrelog_error_t rc;
  if (binding == NULL || !binding->active)
    return WYRELOG_E_POLICY;
  g_mutex_lock (&binding->child->mutex);
  rc = temp_child_check (binding->child);
  if (rc == WYRELOG_E_OK && require_handle) {
    rc = !binding->io_open ? WYRELOG_E_POLICY
        : wyl_fact_artifact_win_working_handle_revalidate (binding->working);
    (void) supplied;
  }
  if (rc != WYRELOG_E_OK && rc != WYRELOG_E_BUSY)
    temp_binding_revoke (binding);
  g_mutex_unlock (&binding->child->mutex);
  return rc;
}

wyrelog_error_t
wyl_fact_artifact_win_lease_create_temp_root (WylFactArtifactWinLease *lease,
    WylFactArtifactWinTempRoot **out_root)
{
  WylFactArtifactWinTempRoot *root;
  g_autofree gchar *uuid = NULL;
  g_autofree gchar *name = NULL;
  wyrelog_error_t rc;
  if (out_root != NULL)
    *out_root = NULL;
  if (lease == NULL || out_root == NULL || !lease->exclusive)
    return WYRELOG_E_POLICY;
  if ((rc = lease_revalidate (lease)) != WYRELOG_E_OK)
    return rc;
  uuid = g_uuid_string_random ();
  name = uuid == NULL ? NULL : g_strdup_printf ("wyrelog-duckdb-temp-%s", uuid);
  if (name == NULL)
    return WYRELOG_E_NOMEM;
  root = g_try_new0 (WylFactArtifactWinTempRoot, 1);
  if (root == NULL)
    return WYRELOG_E_NOMEM;
  rc = wyl_fact_artifact_win_locator_create_directory
      (lease->namespace_->locator, name, &root->directory);
  if (rc != WYRELOG_E_OK) {
    g_free (root);
    return rc;
  }
  root->logical_name = g_strdup_printf ("/wyrelog-duckdb-temp/%s", name);
  if (root->logical_name == NULL) {
    wyl_fact_artifact_win_directory_free (root->directory);
    g_free (root);
    return WYRELOG_E_NOMEM;
  }
  root->lease = lease_ref (lease);
  root->active = TRUE;
  g_atomic_int_set (&root->references, 1);
  g_mutex_init (&root->mutex);
  rc = wyl_fact_artifact_win_locator_flush_directory (lease->
      namespace_->locator);
  if (rc != WYRELOG_E_OK) {
    temp_root_unref (root);
    return rc;
  }
  *out_root = root;
  return WYRELOG_E_OK;
}

gchar *
wyl_fact_artifact_win_temp_root_dup_logical_name (WylFactArtifactWinTempRoot
    *root)
{
  gchar *result;
  if (root == NULL)
    return NULL;
  g_mutex_lock (&root->mutex);
  result = root->active ? g_strdup (root->logical_name) : NULL;
  g_mutex_unlock (&root->mutex);
  return result;
}

wyrelog_error_t
wyl_fact_artifact_win_temp_root_create_child (WylFactArtifactWinTempRoot *root,
    const gchar *name, WylFactArtifactWinTempChild **out_child)
{
  WylFactArtifactWinTempChild *child;
  wyrelog_error_t rc;
  if (out_child != NULL)
    *out_child = NULL;
  if (root == NULL || out_child == NULL || !temp_child_name (name))
    return WYRELOG_E_INVALID;
  g_mutex_lock (&root->mutex);
  rc = temp_root_check (root);
  if (rc != WYRELOG_E_OK) {
    g_mutex_unlock (&root->mutex);
    return rc;
  }
  child = g_try_new0 (WylFactArtifactWinTempChild, 1);
  if (child == NULL) {
    g_mutex_unlock (&root->mutex);
    return WYRELOG_E_NOMEM;
  }
  rc = wyl_fact_artifact_win_directory_open_file
      (root->lease->namespace_->locator, root->directory, name,
      GENERIC_READ | GENERIC_WRITE | DELETE, TRUE, &child->entry);
  if (rc != WYRELOG_E_OK) {
    g_free (child);
    g_mutex_unlock (&root->mutex);
    return rc;
  }
  child->root = temp_root_ref (root);
  child->active = TRUE;
  child->bindings = g_ptr_array_new ();
  if (child->bindings == NULL) {
    wyl_fact_artifact_win_entry_free (child->entry);
    temp_root_unref (child->root);
    g_free (child);
    g_mutex_unlock (&root->mutex);
    return WYRELOG_E_NOMEM;
  }
  g_atomic_int_set (&child->references, 1);
  g_mutex_init (&child->mutex);
  *out_child = child;
  g_mutex_unlock (&root->mutex);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_temp_child_open (WylFactArtifactWinTempChild *child,
    WylFactArtifactWinTempChildBinding **out_binding)
{
  WylFactArtifactWinTempChildBinding *binding;
  HANDLE issued = INVALID_HANDLE_VALUE;
  wyrelog_error_t rc;
  if (out_binding != NULL)
    *out_binding = NULL;
  if (child == NULL || out_binding == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&child->mutex);
  rc = temp_child_check (child);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_directory_entry_issue_working_handle
        (child->root->lease->namespace_->locator, child->root->directory,
        child->entry, &issued);
  if (rc != WYRELOG_E_OK) {
    g_mutex_unlock (&child->mutex);
    return rc;
  }
  binding = g_try_new0 (WylFactArtifactWinTempChildBinding, 1);
  if (binding == NULL) {
    CloseHandle (issued);
    g_mutex_unlock (&child->mutex);
    return WYRELOG_E_NOMEM;
  }
  rc = wyl_fact_artifact_win_working_handle_adopt (issued,
      wyl_fact_artifact_win_entry_identity (child->entry), &binding->working);
  if (rc == WYRELOG_E_OK)
    issued = INVALID_HANDLE_VALUE;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_io_state_new (binding->working,
        &binding->io_state);
  if (rc == WYRELOG_E_OK)
    wyl_fact_artifact_win_io_state_set_validator (binding->io_state,
        temp_child_session_validate, temp_child_ref (child),
        (GDestroyNotify) temp_child_unref);
  if (rc != WYRELOG_E_OK) {
    if (binding->io_state != NULL)
      wyl_fact_artifact_win_io_state_free (binding->io_state);
    else if (binding->working != NULL)
      wyl_fact_artifact_win_working_handle_free (binding->working);
    else if (issued != INVALID_HANDLE_VALUE)
      CloseHandle (issued);
    g_free (binding);
    g_mutex_unlock (&child->mutex);
    return rc;
  }
  binding->child = temp_child_ref (child);
  wyl_fact_artifact_win_io_state_retain_lifetime (binding->io_state,
      temp_child_ref (child), (GDestroyNotify) temp_child_unref);
  binding->active = TRUE;
  binding->io_open = FALSE;
  g_ptr_array_add (child->bindings, binding);
  *out_binding = binding;
  g_mutex_unlock (&child->mutex);
  return WYRELOG_E_OK;
}

wyrelog_error_t
    wyl_fact_artifact_win_temp_child_binding_open_io_session
    (WylFactArtifactWinTempChildBinding * binding,
    WylFactArtifactWinIoSession ** out_session) {
  wyrelog_error_t rc;
  if (out_session != NULL)
    *out_session = NULL;
  if (binding == NULL || out_session == NULL || !binding->active)
    return WYRELOG_E_INVALID;
  /* The child mutex linearizes both session admission and retirement.  Do not
   * validate then reopen a race window in which retire deletes the entry. */
  g_mutex_lock (&binding->child->mutex);
  rc = temp_child_check (binding->child);
  if (rc == WYRELOG_E_OK && binding->active)
    rc = wyl_fact_artifact_win_io_session_open (binding->io_state, out_session);
  /* A second session is ordinary contention, not evidence that the binding
   * or child has been substituted.  Preserve the first session and let it
   * finish; only integrity/transport failures revoke this authority. */
  if (rc != WYRELOG_E_OK && rc != WYRELOG_E_BUSY)
    temp_binding_revoke (binding);
  g_mutex_unlock (&binding->child->mutex);
  return rc;
}

void wyl_fact_artifact_win_temp_child_binding_free
    (WylFactArtifactWinTempChildBinding * binding)
{
  WylFactArtifactWinTempChild *child;
  if (binding == NULL)
    return;
  child = binding->child;
  g_mutex_lock (&child->mutex);
  if (wyl_fact_artifact_win_io_state_has_session (binding->io_state))
    temp_binding_revoke (binding);
  g_ptr_array_remove (child->bindings, binding);
  wyl_fact_artifact_win_io_state_free (binding->io_state);
  g_mutex_unlock (&child->mutex);
  temp_child_unref (child);
  g_free (binding);
}

wyrelog_error_t
wyl_fact_artifact_win_temp_child_retire (WylFactArtifactWinTempChild *child,
    WylFactDuckdbTempRetireResult *out_result)
{
  WylFactArtifactWinMutationEffect effect =
      WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED;
  wyrelog_error_t rc;
  if (out_result != NULL)
    *out_result = WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED;
  if (child == NULL || out_result == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&child->mutex);
  if (child->io_terminal) {
    /* A raw close/reuse is observable before mutation.  Do not delete and do
     * not risk a close on its caller-owned, now foreign HANDLE. */
    for (guint i = 0; i < child->bindings->len; i++) {
      WylFactArtifactWinTempChildBinding *binding = g_ptr_array_index
          (child->bindings, i);
      if (wyl_fact_artifact_win_io_state_has_session (binding->io_state)
          && wyl_fact_artifact_win_working_handle_revalidate (binding->working)
          != WYRELOG_E_OK)
        temp_binding_revoke (binding);
    }
    rc = WYRELOG_E_POLICY;
    g_mutex_unlock (&child->mutex);
    return rc;
  }
  for (guint i = 0; i < child->bindings->len; i++) {
    WylFactArtifactWinTempChildBinding *binding = g_ptr_array_index
        (child->bindings, i);
    if (wyl_fact_artifact_win_io_state_has_session (binding->io_state)
        || wyl_fact_artifact_win_io_state_is_aborted (binding->io_state)) {
      g_mutex_unlock (&child->mutex);
      return WYRELOG_E_POLICY;
    }
  }
  rc = temp_child_check (child);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_directory_entry_delete_exact
        (child->root->lease->namespace_->locator, child->root->directory,
        child->entry, &effect);
  if (effect == WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED) {
    wyrelog_error_t flush = wyl_fact_artifact_win_locator_flush_directory
        (child->root->lease->namespace_->locator);
    child->active = FALSE;
    *out_result = rc == WYRELOG_E_OK && flush == WYRELOG_E_OK
        ? WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED
        : WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RECONCILE_REQUIRED;
    if (rc == WYRELOG_E_OK)
      rc = flush;
  } else if (effect == WYL_FACT_ARTIFACT_WIN_MUTATION_UNKNOWN) {
    child->active = FALSE;
    *out_result = WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RECONCILE_REQUIRED;
  }
  g_mutex_unlock (&child->mutex);
  return rc;
}

void
wyl_fact_artifact_win_temp_child_free (WylFactArtifactWinTempChild *child)
{
  temp_child_unref (child);
}

wyrelog_error_t
wyl_fact_artifact_win_temp_root_retire (WylFactArtifactWinTempRoot *root,
    WylFactDuckdbTempRetireResult *out_result)
{
  WylFactArtifactWinMutationEffect effect =
      WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED;
  wyrelog_error_t rc;
  if (out_result != NULL)
    *out_result = WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED;
  if (root == NULL || out_result == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&root->mutex);
  /* Every child and every child working binding owns a root reference.  A
   * root can be deleted only after all of that authority was released. */
  if (g_atomic_int_get (&root->references) != 1) {
    g_mutex_unlock (&root->mutex);
    return WYRELOG_E_POLICY;
  }
  rc = temp_root_check (root);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_artifact_win_directory_delete_empty
        (root->lease->namespace_->locator, root->directory, &effect);
  if (effect == WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED) {
    wyrelog_error_t flush = wyl_fact_artifact_win_locator_flush_directory
        (root->lease->namespace_->locator);
    root->active = FALSE;
    *out_result = rc == WYRELOG_E_OK && flush == WYRELOG_E_OK
        ? WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED
        : WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RECONCILE_REQUIRED;
    if (rc == WYRELOG_E_OK)
      rc = flush;
  } else if (effect == WYL_FACT_ARTIFACT_WIN_MUTATION_UNKNOWN) {
    root->active = FALSE;
    *out_result = WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RECONCILE_REQUIRED;
  }
  g_mutex_unlock (&root->mutex);
  return rc;
}

static void
temp_child_unref (WylFactArtifactWinTempChild *child)
{
  if (child == NULL || !g_atomic_int_dec_and_test (&child->references))
    return;
  child->active = FALSE;
  wyl_fact_artifact_win_entry_free (child->entry);
  g_clear_pointer (&child->bindings, g_ptr_array_unref);
  g_mutex_clear (&child->mutex);
  temp_root_unref (child->root);
  g_free (child);
}

static void
temp_root_unref (WylFactArtifactWinTempRoot *root)
{
  if (root == NULL || !g_atomic_int_dec_and_test (&root->references))
    return;
  root->active = FALSE;
  wyl_fact_artifact_win_directory_free (root->directory);
  g_free (root->logical_name);
  g_mutex_clear (&root->mutex);
  wyl_fact_artifact_win_lease_free (root->lease);
  g_free (root);
}

void
wyl_fact_artifact_win_temp_root_free (WylFactArtifactWinTempRoot *root)
{
  temp_root_unref (root);
}
#endif

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/graph-artifact-windows-namespace-private.h"

#ifdef G_OS_WIN32
#include "fact/graph-artifact-windows-handle-private.h"
#include "fact/graph-artifact-windows-locator-private.h"

struct WylFactArtifactWinNamespace
{
  WylFactArtifactWinLocator *locator;
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
  wyl_fact_artifact_win_locator_free (namespace_->locator);
  g_free (namespace_);
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
#endif

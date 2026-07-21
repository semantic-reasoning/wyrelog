/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "wyctl-publication-backend-private.h"

/* Bind the portable adapter to exactly one concrete backend per platform. Only
 * the selected family's symbols exist at link time, so the shims below are
 * compiled against a single family and never reference the other. */
#ifdef G_OS_WIN32
typedef WyctlPublicationWindowsBackend WyctlPublicationConcreteBackend;
#define WYCTL_PUB_CONCRETE(op) wyctl_publication_windows_##op
#else
typedef WyctlPublicationPosixBackend WyctlPublicationConcreteBackend;
#define WYCTL_PUB_CONCRETE(op) wyctl_publication_posix_##op
#endif

/* Borrow the receipt's plan-fields into a stack plan for a synchronous
 * conformance-path call. The concrete inspect/resync/cleanup/commit functions
 * take a `const WyctlPublicationPlan *` and never take ownership, so pointing
 * the plan at the receipt's owned strings is correct and allocation-free. Never
 * clear a plan built this way; the strings belong to the receipt. */
static void
plan_borrow_from_receipt (const WyctlPublicationReceipt *receipt,
    WyctlPublicationPlan *plan)
{
  plan->version = WYCTL_PUBLICATION_PLAN_VERSION;
  plan->destination = receipt->destination;
  plan->reservation_id = receipt->reservation_id;
  plan->parent_identity = receipt->parent_identity;
  plan->stage_basename = receipt->stage_basename;
}

/* Executor-path shims: identical signatures to the concrete free functions,
 * so each is a thin self-cast forward. */
static wyrelog_error_t
adapter_plan (gpointer self, const WyctlPublicationPlan *request,
    WyctlPublicationPlan *out_plan)
{
  return WYCTL_PUB_CONCRETE (plan) ((const WyctlPublicationConcreteBackend *)
      self, request, out_plan);
}

static wyrelog_error_t
adapter_prepare (gpointer self, const WyctlPublicationPlan *plan,
    WyctlPublicationReceipt *out_receipt)
{
  return WYCTL_PUB_CONCRETE (prepare) ((const WyctlPublicationConcreteBackend *)
      self, plan, out_receipt);
}

static wyrelog_error_t
adapter_stage_exact (gpointer self, const WyctlPublicationPlan *plan,
    const gchar *credential_id,
    const WyctlSensitiveText *credential_secret,
    WyctlPublicationReceipt *out_receipt,
    WyctlPublicationResult *out_result, gboolean *out_replayed)
{
  return WYCTL_PUB_CONCRETE (stage_exact) ((const
          WyctlPublicationConcreteBackend *) self, plan, credential_id,
      credential_secret, out_receipt, out_result, out_replayed);
}

static wyrelog_error_t
adapter_receipt_target_acquire (gpointer self,
    const WyctlPublicationPlan *plan,
    const WyctlPublicationReceipt *receipt, gboolean require_destination,
    WyctlPublicationReceiptTargetLease **out_lease,
    WyctlPublicationReceiptTargetKind *out_kind)
{
  return WYCTL_PUB_CONCRETE (receipt_target_acquire) ((const
          WyctlPublicationConcreteBackend *) self, plan, receipt,
      require_destination, out_lease, out_kind);
}

static wyrelog_error_t
adapter_receipt_target_inspect (gpointer self,
    WyctlPublicationReceiptTargetLease *lease,
    const gchar *expected_credential_id,
    const WyctlSensitiveText *expected_credential_secret,
    WyctlPublicationResult *out_result)
{
  return WYCTL_PUB_CONCRETE (receipt_target_inspect) ((const
          WyctlPublicationConcreteBackend *) self, lease,
      expected_credential_id, expected_credential_secret, out_result);
}

static wyrelog_error_t
adapter_receipt_target_commit (gpointer self,
    WyctlPublicationReceiptTargetLease *lease,
    const gchar *expected_credential_id,
    const WyctlSensitiveText *expected_credential_secret,
    WyctlPublicationResult *out_result)
{
  return WYCTL_PUB_CONCRETE (receipt_target_commit) ((const
          WyctlPublicationConcreteBackend *) self, lease,
      expected_credential_id, expected_credential_secret, out_result);
}

static void
adapter_receipt_target_release (gpointer self,
    WyctlPublicationReceiptTargetLease *lease)
{
  WYCTL_PUB_CONCRETE (receipt_target_release) ((const
          WyctlPublicationConcreteBackend *) self, lease);
}

/* Conformance-path shims: the concrete functions take an extra plan the vtable
 * does not supply, so each reconstructs a borrowing plan from the receipt.
 * commit additionally unwraps the sensitive secret to the NUL-terminated
 * C-string the concrete commit expects. */
static wyrelog_error_t
adapter_commit (gpointer self, WyctlPublicationReceipt *receipt,
    const gchar *credential_id,
    const WyctlSensitiveText *credential_secret,
    WyctlPublicationResult *out_result)
{
  WyctlPublicationPlan plan = { 0 };

  plan_borrow_from_receipt (receipt, &plan);
  return WYCTL_PUB_CONCRETE (commit) ((const WyctlPublicationConcreteBackend *)
      self, &plan, receipt, credential_id,
      credential_secret != NULL ? credential_secret->text : NULL, out_result);
}

static wyrelog_error_t
adapter_inspect (gpointer self, const WyctlPublicationReceipt *receipt,
    const gchar *expected_credential_id,
    const WyctlSensitiveText *expected_credential_secret,
    WyctlPublicationResult *out_result)
{
  WyctlPublicationPlan plan = { 0 };

  plan_borrow_from_receipt (receipt, &plan);
  return WYCTL_PUB_CONCRETE (inspect) ((const WyctlPublicationConcreteBackend *)
      self, &plan, receipt, expected_credential_id, expected_credential_secret,
      out_result);
}

static wyrelog_error_t
adapter_resync (gpointer self, const WyctlPublicationReceipt *receipt,
    const gchar *expected_credential_id,
    const WyctlSensitiveText *expected_credential_secret,
    WyctlPublicationResult *out_result)
{
  WyctlPublicationPlan plan = { 0 };

  plan_borrow_from_receipt (receipt, &plan);
  return WYCTL_PUB_CONCRETE (resync) ((const WyctlPublicationConcreteBackend *)
      self, &plan, receipt, expected_credential_id, expected_credential_secret,
      out_result);
}

static wyrelog_error_t
adapter_cleanup (gpointer self, const WyctlPublicationReceipt *receipt,
    const gchar *expected_credential_id,
    const WyctlSensitiveText *expected_credential_secret,
    WyctlPublicationResult *out_result)
{
  WyctlPublicationPlan plan = { 0 };

  plan_borrow_from_receipt (receipt, &plan);
  return WYCTL_PUB_CONCRETE (cleanup) ((const WyctlPublicationConcreteBackend *)
      self, &plan, receipt, expected_credential_id, expected_credential_secret,
      out_result);
}

/* Read-only accessor shim: identical signature to the concrete free function,
 * a thin self-cast forward. */
static wyrelog_error_t
adapter_root_identity (gpointer self, gchar **out_identity)
{
  return WYCTL_PUB_CONCRETE (root_identity) ((const
          WyctlPublicationConcreteBackend *) self, out_identity);
}

static const WyctlPublicationBackendVTable adapter_vtable = {
  .plan = adapter_plan,
  .prepare = adapter_prepare,
  .stage_exact = adapter_stage_exact,
  .receipt_target_acquire = adapter_receipt_target_acquire,
  .receipt_target_inspect = adapter_receipt_target_inspect,
  .receipt_target_commit = adapter_receipt_target_commit,
  .receipt_target_release = adapter_receipt_target_release,
  .commit = adapter_commit,
  .inspect = adapter_inspect,
  .resync = adapter_resync,
  .cleanup = adapter_cleanup,
  .root_identity = adapter_root_identity,
};

wyrelog_error_t
wyctl_publication_backend_open (WyctlPublicationBackend *backend,
    const gchar *root_dir)
{
  if (backend == NULL || root_dir == NULL || *root_dir == '\0')
    return WYRELOG_E_INVALID;
  WYCTL_PUB_CONCRETE (backend_init) (&backend->concrete, root_dir);
  return WYRELOG_E_OK;
}

void
wyctl_publication_backend_close (WyctlPublicationBackend *backend)
{
  if (backend == NULL)
    return;
  WYCTL_PUB_CONCRETE (backend_clear) (&backend->concrete);
}

const WyctlPublicationBackendVTable *
wyctl_publication_backend_vtable (void)
{
  return &adapter_vtable;
}

gpointer
wyctl_publication_backend_self (WyctlPublicationBackend *backend)
{
  return backend != NULL ? &backend->concrete : NULL;
}

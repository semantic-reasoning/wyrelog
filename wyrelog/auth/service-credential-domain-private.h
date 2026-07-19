/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "wyrelog/handle.h"
#include "wyrelog/error.h"
#include "wyrelog/auth/service-credential-private.h"

G_BEGIN_DECLS typedef struct
{
  gchar *subject_id;
  gchar *display_name;
  gchar *state;
  guint64 generation;
  gchar *created_by;
  gint64 created_at_us;
  gint64 updated_at_us;
  gchar *disabled_by;
  gint64 disabled_at_us;
} wyl_service_principal_t;

typedef struct
{
  gchar *credential_id;
  guint32 credential_format_version;
  gchar *subject_id;
  gchar *tenant_id;
  guint64 generation;
  gchar *state;
  gchar *created_by;
  gint64 created_at_us;
  gint64 updated_at_us;
  gint64 expires_at_us;
  gint64 last_used_at_us;
  gchar *revoked_by;
  gint64 revoked_at_us;
  gchar *rotated_from_id;
} wyl_service_credential_t;

typedef struct
{
  wyl_service_credential_t credential;
  wyl_service_credential_secret_t *secret;
} wyl_service_credential_issue_result_t;

typedef struct
{
  void (*before_gate) (gpointer data);
    gint64 (*now_us) (gpointer data);
  const wyl_service_credential_runtime_t *credential_runtime;
  gpointer data;
} wyl_service_credential_verify_runtime_t;

typedef wyrelog_error_t (*wyl_service_credential_mutation_authorize_fn)
  (gpointer data, const gchar * actor_subject_id);

/* Optional execution-boundary authorization, borrowed for one mutation call.
 * authorize runs exactly once after the service WRITE lease is acquired and
 * before fence lookup, CVK access, transaction start or credential RNG. It
 * MUST be non-reentrant and MUST NOT call service mutation APIs on handle. */
typedef struct
{
  wyl_service_credential_mutation_authorize_fn authorize;
  gpointer data;
} wyl_service_credential_mutation_authorization_t;

typedef struct
{
  const wyl_service_credential_mutation_authorization_t *authorization;
  /* Borrowed for the call; callback lifetime rules match the returned secret
   * contract documented for rotation below. */
  const wyl_service_credential_runtime_t *credential_runtime;
} wyl_service_credential_issue_runtime_t;

typedef struct
{
  gint64 (*now_us) (gpointer data);
  const wyl_service_credential_runtime_t *credential_runtime;
  gpointer data;
  /* Invoked after the authority commit and before lease release. */
    wyrelog_error_t (*invalidate_credential) (gpointer data,
      const gchar * credential_id, guint64 generation);
  gpointer invalidation_data;
  /* The observed active generation used by the authoritative rotate CAS.
   * Zero preserves callers that have no externally observed generation. */
  guint64 old_credential_generation;
  const wyl_service_credential_mutation_authorization_t *authorization;
} wyl_service_credential_rotate_runtime_t;

typedef struct
{
  /* Invoked after the authority commit and before lease release. */
  wyrelog_error_t (*invalidate_credential) (gpointer data,
      const gchar * credential_id, guint64 generation);
  gpointer invalidation_data;
} wyl_service_credential_revoke_runtime_t;

typedef wyrelog_error_t (*wyl_service_principal_cb) (const
    wyl_service_principal_t * principal, gpointer user_data);
typedef wyrelog_error_t (*wyl_service_credential_cb) (const
    wyl_service_credential_t * credential, gpointer user_data);

/* Owned-output contract for create/get/disable:
 * - On first use, out MUST be initialized to { 0 }.
 * - A later call may reuse an object previously populated or cleared by one
 *   of these APIs; the API clears it before validating other arguments.
 * - Input strings MUST NOT alias strings currently owned by out.
 * - On success, all non-NULL strings in out are caller-owned and released by
 *   wyl_service_principal_clear(). Every failure leaves out cleared.
 *
 * The principal and all of its strings passed to a foreach callback are
 * borrowed only for the duration of that callback. Callers that retain any
 * value after returning MUST make a deep copy.
 */
void wyl_service_principal_clear (wyl_service_principal_t * principal);
wyrelog_error_t wyl_service_principal_create (WylHandle * handle,
    const gchar * subject_id, const gchar * display_name,
    const gchar * actor_subject_id, const gchar * request_id,
    wyl_service_principal_t * out);
wyrelog_error_t wyl_service_principal_get (WylHandle * handle,
    const gchar * subject_id, wyl_service_principal_t * out);
wyrelog_error_t wyl_service_principal_foreach (WylHandle * handle,
    wyl_service_principal_cb cb, gpointer user_data);
wyrelog_error_t wyl_service_principal_disable (WylHandle * handle,
    const gchar * subject_id, const gchar * actor_subject_id,
    const gchar * request_id, wyl_service_principal_t * out);

/* Credential outputs follow the same zero-init, non-aliasing, caller-owned,
 * reuse and failure-clears contract above. Issue or rotation success transfers
 * the opaque locked secret; clear the result to wipe and release it. Credential
 * DTOs deliberately contain no salt, verifier or CVK. Foreach DTOs and their
 * strings are borrowed only during the callback and require a deep copy to
 * retain. A successful issue or rotation is the only opportunity to obtain
 * the corresponding new secret. */
void wyl_service_credential_clear (wyl_service_credential_t * credential);
void wyl_service_credential_issue_result_clear
    (wyl_service_credential_issue_result_t * result);
wyrelog_error_t wyl_service_credential_issue (WylHandle * handle,
    const gchar * subject_id, const gchar * tenant_id,
    const gchar * actor_subject_id, const gchar * request_id,
    gint64 expires_at_us, wyl_service_credential_issue_result_t * out);
wyrelog_error_t wyl_service_credential_issue_with_runtime
    (WylHandle * handle, const gchar * subject_id, const gchar * tenant_id,
    const gchar * actor_subject_id, const gchar * request_id,
    gint64 expires_at_us,
    const wyl_service_credential_issue_runtime_t * runtime,
    wyl_service_credential_issue_result_t * out);
wyrelog_error_t wyl_service_credential_get (WylHandle * handle,
    const gchar * credential_id, wyl_service_credential_t * out);
wyrelog_error_t wyl_service_credential_foreach (WylHandle * handle,
    const gchar * subject_id, const gchar * tenant_id,
    wyl_service_credential_cb cb, gpointer user_data);
/* Named authoritative to avoid colliding with the lower-level codec symbol.
 * This API derives subject and tenant solely from the canonical credential ID.
 * It is read-only: no last-used, audit, session or token state is mutated.
 *
 * The optional runtime, its credential callback table and data are borrowed
 * only until the call returns. before_gate is a deterministic private test
 * checkpoint immediately before gate acquisition. Clock and credential
 * callbacks execute while the service-domain gate is held. All callbacks MUST
 * be non-reentrant and MUST NOT call APIs on the same handle, policy store or
 * service domain. */
wyrelog_error_t wyl_service_credential_verify_authoritative
    (WylHandle * handle, const gchar * credential_id,
    const gchar * presented_secret, gsize presented_secret_len,
    gboolean * out_authenticated);
wyrelog_error_t wyl_service_credential_verify_authoritative_with_runtime
    (WylHandle * handle, const gchar * credential_id,
    const gchar * presented_secret, gsize presented_secret_len,
    const wyl_service_credential_verify_runtime_t * runtime,
    gboolean * out_authenticated);
wyrelog_error_t wyl_service_credential_revoke (WylHandle * handle,
    const gchar * credential_id, const gchar * actor_subject_id,
    const gchar * request_id, wyl_service_credential_t * out);
wyrelog_error_t wyl_service_credential_revoke_with_runtime
    (WylHandle * handle, const gchar * credential_id,
    const gchar * actor_subject_id, const gchar * request_id,
    const wyl_service_credential_revoke_runtime_t * runtime,
    wyl_service_credential_t * out);
/* Rotation derives subject and tenant from old_credential_id and returns the
 * successor secret exactly once, only after the local savepoint is released.
 *
 * The rotate runtime object, now_us callback and runtime->data are borrowed
 * and need remain valid only until this call returns. The nested
 * credential_runtime pointer is likewise borrowed only for the call, but its
 * callback table (including its own data pointer value) is copied into a
 * successfully returned secret. Consequently, credential callback code,
 * targets and credential_runtime->data MUST remain valid until that secret is
 * cleared. On failure or when no secret is returned, those lifetimes need only
 * extend through this call. rotate runtime has no before-gate/checkpoint
 * callback; the store-scoped fault seam owns no callback or data lifetime.
 *
 * Clock and credential callbacks may run under the domain gate, and credential
 * callbacks may also run under the lifecycle mutex. They MUST be non-reentrant
 * and MUST NOT call APIs on the same handle, store or service domain. The
 * optional authorization descriptor is borrowed only for the call and follows
 * the execution-boundary contract above. */
wyrelog_error_t wyl_service_credential_rotate (WylHandle * handle,
    const gchar * old_credential_id, const gchar * actor_subject_id,
    const gchar * request_id, gint64 new_expires_at_us,
    wyl_service_credential_issue_result_t * out);
wyrelog_error_t wyl_service_credential_rotate_with_runtime
    (WylHandle * handle, const gchar * old_credential_id,
    const gchar * actor_subject_id, const gchar * request_id,
    gint64 new_expires_at_us,
    const wyl_service_credential_rotate_runtime_t * runtime,
    wyl_service_credential_issue_result_t * out);

G_END_DECLS

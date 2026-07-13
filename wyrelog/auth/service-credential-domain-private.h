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
 * reuse and failure-clears contract above. Issue success alone transfers the
 * opaque locked secret; clear the result to wipe and release it. Credential
 * DTOs deliberately contain no salt, verifier or CVK. Foreach DTOs and their
 * strings are borrowed only during the callback and require a deep copy to
 * retain. A successful issue is the only opportunity to obtain its secret. */
void wyl_service_credential_clear (wyl_service_credential_t * credential);
void wyl_service_credential_issue_result_clear
    (wyl_service_credential_issue_result_t * result);
wyrelog_error_t wyl_service_credential_issue (WylHandle * handle,
    const gchar * subject_id, const gchar * tenant_id,
    const gchar * actor_subject_id, const gchar * request_id,
    gint64 expires_at_us, wyl_service_credential_issue_result_t * out);
wyrelog_error_t wyl_service_credential_get (WylHandle * handle,
    const gchar * credential_id, wyl_service_credential_t * out);
wyrelog_error_t wyl_service_credential_foreach (WylHandle * handle,
    const gchar * subject_id, const gchar * tenant_id,
    wyl_service_credential_cb cb, gpointer user_data);

G_END_DECLS

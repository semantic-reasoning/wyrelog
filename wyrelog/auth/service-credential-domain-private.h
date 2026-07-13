/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "wyrelog/handle.h"
#include "wyrelog/error.h"

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

typedef wyrelog_error_t (*wyl_service_principal_cb) (const
    wyl_service_principal_t * principal, gpointer user_data);

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

G_END_DECLS

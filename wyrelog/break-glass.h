/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyrelog/handle.h"

G_BEGIN_DECLS;

/*
 * Operator-supplied reason carried into the audit row when a
 * break-glass override is activated and emitted again on each
 * override decision. The vocabulary is closed; passing a value
 * outside the listed set returns WYRELOG_E_INVALID. Stable string
 * names accompanying each enumerator are the durable identifier
 * downstream audit consumers should pivot on.
 *
 *   - WYL_BREAK_GLASS_REASON_INCIDENT_RESPONSE: active outage or
 *     attack that the standard policy-write surface cannot
 *     remediate because the legitimate operators are locked out.
 *   - WYL_BREAK_GLASS_REASON_POLICY_CORRUPTION: the policy store
 *     has been seeded with a bad grant set and the security
 *     officer must rebuild it.
 *   - WYL_BREAK_GLASS_REASON_SECURITY_OFFICER_LOCKOUT: the
 *     principal who normally holds wr.security_officer is locked
 *     out and a break-glass holder must re-establish the SoD
 *     counterweight.
 *   - WYL_BREAK_GLASS_REASON_SERVICE_UNFREEZE: the service-side
 *     freeze guard has trapped a tenant in a frozen state that no
 *     normal grant can release.
 *   - WYL_BREAK_GLASS_REASON_OTHER: reserved final fallback so
 *     operators are not forced to misclassify; the textual reason
 *     belongs in the operator's incident docket, not the audit
 *     row's stable code.
 */
typedef enum
{
  WYL_BREAK_GLASS_REASON_INCIDENT_RESPONSE = 0,
  WYL_BREAK_GLASS_REASON_POLICY_CORRUPTION = 1,
  WYL_BREAK_GLASS_REASON_SECURITY_OFFICER_LOCKOUT = 2,
  WYL_BREAK_GLASS_REASON_SERVICE_UNFREEZE = 3,
  WYL_BREAK_GLASS_REASON_OTHER = 4,
  WYL_BREAK_GLASS_REASON_LAST_,
} wyl_break_glass_reason_code_t;

/*
 * Activate the break-glass override on |handle| with the given
 * |reason| and a TTL of |ttl_seconds|. The TTL is capped at the
 * compile-time ceiling that matches the bootstrap policy template;
 * passing a larger value or a non-positive value returns
 * WYRELOG_E_INVALID. A reason outside the closed enumeration
 * returns WYRELOG_E_INVALID. A second call before
 * wyl_handle_break_glass_disarm returns WYRELOG_E_INVALID so an
 * operator cannot extend the wall-clock window by re-arming.
 *
 * Builds without -Denable_break_glass=true return
 * WYRELOG_E_BREAK_GLASS_DISABLED so callers can detect that the
 * override path is absent rather than receive a false positive.
 *
 * The activation is handle-scoped: a second WylHandle in the same
 * process or in a separate process is unaffected. The activation
 * does not survive process restart by design; an operator must
 * present a fresh activation request after restart.
 */
wyrelog_error_t wyl_handle_break_glass_arm (WylHandle * handle,
    wyl_break_glass_reason_code_t reason, gint64 ttl_seconds);

/*
 * Cancels an in-progress activation on |handle|. Returns
 * WYRELOG_E_OK whether or not the handle was active so callers can
 * use it idempotently from a teardown path. Builds without
 * -Denable_break_glass=true return WYRELOG_E_BREAK_GLASS_DISABLED.
 */
wyrelog_error_t wyl_handle_break_glass_disarm (WylHandle * handle);

/*
 * Returns TRUE iff the break-glass override is currently active on
 * |handle| and its TTL has not elapsed. Returns FALSE for a NULL
 * handle, an inactive handle, an expired activation, or a build
 * without the override path. Strictly read-only; does not advance
 * the activation's used flag or otherwise mutate state.
 */
gboolean wyl_handle_break_glass_is_active (WylHandle * handle);

G_END_DECLS;

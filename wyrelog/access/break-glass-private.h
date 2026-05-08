/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

/*
 * Closed enumeration of operator-supplied reason codes carried into
 * the audit row when a break-glass override is armed or fired. The
 * vocabulary is deliberately small so audit consumers can pivot
 * dashboards on a stable string set; free-form reasons are rejected
 * at the API boundary because they drift across releases and invite
 * downstream-consumer breakage as well as audit-row injection.
 *
 * Adding a new code is a coordinated change: append a new
 * enumerator BEFORE WYL_BREAK_GLASS_REASON_LAST_, extend the
 * name table in access/break-glass.c, and document the addition in
 * release notes so audit consumers can update their filters.
 */
typedef enum
{
  /* Active incident response — a host-side outage or attack that
   * cannot be remediated through the standard policy-write surface
   * because the legitimate operators have lost their access. */
  WYL_BREAK_GLASS_REASON_INCIDENT_RESPONSE = 0,
  /* The policy store has been corrupted or seeded with a bad
   * grant set and the security officer must rebuild it. */
  WYL_BREAK_GLASS_REASON_POLICY_CORRUPTION = 1,
  /* The principal who normally holds wr.security_officer is
   * locked out (lost MFA, departed, etc.) and a break-glass
   * holder must re-establish the SoD counterweight. */
  WYL_BREAK_GLASS_REASON_SECURITY_OFFICER_LOCKOUT = 2,
  /* The service-side freeze guard has trapped a tenant in a
   * frozen state that no normal grant can release. */
  WYL_BREAK_GLASS_REASON_SERVICE_UNFREEZE = 3,
  /* Reason is captured in the operator's incident docket rather
   * than the audit-row reason code; reserved as a final fallback
   * so the vocabulary can stay small without forcing the operator
   * to misclassify. */
  WYL_BREAK_GLASS_REASON_OTHER = 4,
  WYL_BREAK_GLASS_REASON_LAST_,
} wyl_break_glass_reason_code_t;

/*
 * Returns a stable, never-NULL human-readable name for |code|, or
 * "unknown" when |code| is out of range. The string lives in static
 * storage and must not be freed.
 */
const gchar *wyl_break_glass_reason_name (wyl_break_glass_reason_code_t code);

/*
 * Inverse of wyl_break_glass_reason_name: maps a stable name to its
 * enumerator. Returns WYRELOG_E_OK and writes the resolved code on
 * success, or WYRELOG_E_NOT_FOUND when |name| does not match any
 * known reason. NULL or empty |name| returns WYRELOG_E_INVALID.
 */
wyrelog_error_t wyl_break_glass_reason_from_name (const gchar * name,
    wyl_break_glass_reason_code_t * out_code);

/*
 * Compile-time ceiling on the per-arming TTL. Mirrors the
 * ttl("break_glass", 900) row in templates/access/bootstrap.dl so
 * the host-side TTL gate cannot exceed the DL self-disable horizon
 * that templates/access/bootstrap.dl:223-227 enforces.
 */
#define WYL_BREAK_GLASS_DEFAULT_TTL_SECONDS 900

G_END_DECLS;

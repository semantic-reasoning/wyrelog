/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

/*
 * Access decision rule set support code.
 *
 * The Datalog source of truth lives at
 * <datadir>/wyrelog/access/decision.dl. This module exposes the
 * deny-reason taxonomy on the C side: the six v0 codes, their
 * matching origin tags, and a fixed priority that the engine uses
 * to pick a single representative reason for the H1 result struct
 * when multiple deny_reason rows fire for the same (user, perm,
 * scope) tuple. The full row set still goes to the audit log; the
 * priority only collapses the user-visible single-reason field.
 *
 * Code uniqueness contract: the v0 catalogue keys by code alone.
 * Every code maps to exactly one origin tag. A future row that
 * reused a code with a different origin would force this enum to
 * become a (code, origin) composite; until then the simple keying
 * is correct and the test harness pins it.
 *
 * Lower ordinal = higher priority. Tests assert the ordinal
 * ordering is monotonic with the spec priority.
 */

typedef enum wyl_deny_reason_code_t
{
  WYL_DENY_REASON_FROZEN = 0,
  WYL_DENY_REASON_DISABLED_ROLE,
  WYL_DENY_REASON_SOD,
  WYL_DENY_REASON_NOT_AUTHENTICATED,
  WYL_DENY_REASON_SESSION_INACTIVE,
  WYL_DENY_REASON_NOT_ARMED,
  WYL_DENY_REASON_LAST_,
} wyl_deny_reason_code_t;

/*
 * Lexical names. The `name` is the string that appears as the
 * fourth argument of the deny_reason/5 fact in decision.dl; the
 * `origin` is the fifth argument. NULL on out-of-range input;
 * callers must not free the returned strings.
 */
const gchar *wyl_deny_reason_name (wyl_deny_reason_code_t code);
const gchar *wyl_deny_reason_origin (wyl_deny_reason_code_t code);

/*
 * Priority ordering used when multiple deny_reason rows fire for
 * the same tuple and the H1 result must surface a single code.
 * Lower values are higher priority. The current implementation
 * returns the enum ordinal directly; callers must NOT rely on the
 * absolute value, only on relative ordering.
 */
guint wyl_deny_reason_priority (wyl_deny_reason_code_t code);

/*
 * Resolves a name string back to its code. Returns
 * WYL_DENY_REASON_LAST_ when the name does not match any v0 code.
 */
wyl_deny_reason_code_t wyl_deny_reason_from_name (const gchar * name);

/*
 * Catalogue accessors used by the test harness to round-trip the
 * .dl source against the C mirror. Ordering matches the deny_reason
 * row order in the .dl file.
 */
gsize wyl_deny_reason_count (void);

G_END_DECLS;

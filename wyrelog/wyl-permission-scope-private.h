/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyl-guard-expr-private.h"

G_BEGIN_DECLS;

/*
 * Permission scope evaluator and perm_arm_rule baseline catalogue.
 *
 * The Datalog source of truth lives at
 * <datadir>/wyrelog/access/fsm/permission_scope.dl. This module
 * mirrors the catalogue rows on the C side and provides a guard
 * evaluator the engine can call to resolve eval_guard/2 against a
 * request scope.
 *
 * scope/4 in the .dl is laid out as (user, timestamp, loc_class,
 * risk). The fourth slot is `risk` rather than `tenant` because
 * the version-0 catalogue exercises `risk` heavily and `tenant`
 * not at all; the tenant slot is reserved for tenant-scoped policy
 * wiring in a follow-up commit.
 *
 * Evaluation contract: every uncertain or undefined branch
 * returns FALSE (fail-closed). This includes a NULL expression, a
 * NULL scope, an unknown enum value, a malformed comparison value,
 * a tag node (the tag predicate has no v0 binding and is reserved
 * for future site policy), and an undefined window name when a
 * caller-installed in_window matcher is missing.
 */

/*
 * Request-time context delivered to the guard evaluator. Owned by
 * the caller for the duration of one wyl_eval_guard invocation;
 * the evaluator does not retain pointers across the call.
 *
 *   user      : opaque principal identifier; not interpreted by
 *               the evaluator. May be NULL.
 *   timestamp : monotonic nanoseconds since the wyrelog epoch;
 *               passed verbatim to the in_window matcher.
 *   loc_class : one of "trusted", "semi_trusted", "public",
 *               "untrusted"; compared by string equality. NULL is
 *               treated as a non-matching value.
 *   risk      : numeric risk score in [0, 100], host-attested;
 *               compared against the cmp value parsed as a signed
 *               integer.
 *   in_window : caller-installed matcher invoked for the
 *               cmp(timestamp, in, "<window>") path. May be NULL,
 *               in which case every timestamp-in test fails
 *               closed. The matcher receives the exact timestamp
 *               from this struct and the window name from the
 *               cmp value.
 */
typedef struct wyl_scope_t
{
  const gchar *user;
  gint64 timestamp;
  const gchar *loc_class;
  gint64 risk;
    gboolean (*in_window) (gint64 ts, const gchar * window_name,
      gpointer user_data);
  gpointer in_window_user_data;
} wyl_scope_t;

/*
 * Evaluates `e` against `s`. Returns TRUE iff the guard is
 * satisfied. Fail-closed on every failure mode (see header
 * comment).
 */
gboolean wyl_eval_guard (const wyl_guard_expr_t * e, const wyl_scope_t * s);

/*
 * Looks up the guard expression registered for `perm_id`. Returns
 * a borrowed pointer to a module-owned expression tree on hit, or
 * NULL when the permission has no entry in the baseline
 * catalogue. Callers MUST NOT free the returned pointer; the
 * catalogue retains ownership for process lifetime.
 *
 * The first call into the catalogue performs a one-time lazy
 * build of all entries via the guard expression builder API. The
 * build is thread-safe through g_once and validates every entry
 * with wyl_guard_validate; a validation failure aborts the
 * process because the catalogue text is part of the binary and a
 * validation failure means the source of truth was corrupted.
 */
const wyl_guard_expr_t *wyl_perm_arm_rule_lookup (const gchar * perm_id);

/* Read-only accessors for the in-memory catalogue, used by the
 * test harness to round-trip the .dl source against the C
 * mirror. The accessors are stable across calls; ordering matches
 * the catalogue row order in the .dl file. */
gsize wyl_perm_arm_rule_count (void);
const gchar *wyl_perm_arm_rule_perm_id (gsize idx);
const wyl_guard_expr_t *wyl_perm_arm_rule_expr (gsize idx);

G_END_DECLS;

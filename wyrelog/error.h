/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

G_BEGIN_DECLS;

typedef enum wyrelog_error_t
{
  WYRELOG_E_OK = 0,
  WYRELOG_E_INVALID = -1,
  WYRELOG_E_NOMEM = -2,
  WYRELOG_E_IO = -3,
  WYRELOG_E_CRYPTO = -4,
  WYRELOG_E_POLICY = -5,
  WYRELOG_E_AUTH = -6,
  WYRELOG_E_INTERNAL = -7,
  /*
   * Runtime fault inside the embedded Datalog evaluator after a
   * successful policy load: e.g. recursion/aggregate overflow,
   * dynamic negation cycle, or a fact-shape mismatch surfaced at
   * evaluation time. Distinct from WYRELOG_E_POLICY (load-time
   * shape error) and WYRELOG_E_INTERNAL (wyrelog-side invariant
   * violation) so operators can route incidents correctly.
   */
  WYRELOG_E_EXEC = -8,
  /*
   * Caller-supplied identifier resolved past argument validation but
   * names no entity the callee currently tracks. Distinct from
   * WYRELOG_E_INVALID (argument-shape failure: NULL handle, NULL
   * out-pointer, or otherwise malformed input) so callers can
   * distinguish "you asked for something that no longer exists" from
   * "you handed me junk." Used today by wyl_session_logout to flag a
   * sid the handle has never registered.
   */
  WYRELOG_E_NOT_FOUND = -9,
  /*
   * Break-glass override surface is not available in this build or
   * has not been activated for the current handle. Returned by the
   * override-aware paths when WYL_HAS_BREAK_GLASS was not set at
   * compile time, when the operator-supplied reason is missing or
   * out of vocabulary, when the requested TTL exceeds the
   * compile-time ceiling, or when the calling code attempts to use
   * an override that the runtime activation state does not
   * authorise. Distinct from WYRELOG_E_POLICY (load-time policy
   * fault) and WYRELOG_E_INVALID (argument-shape failure) so
   * operators can triage "build does not ship the override path"
   * from genuine misuse.
   */
  WYRELOG_E_BREAK_GLASS_DISABLED = -10,
  /*
   * A non-blocking exclusive resource lease is already held by another
   * store handle or process. Callers may retry after the current owner
   * closes; other filesystem and locking failures remain WYRELOG_E_IO.
   */
  WYRELOG_E_BUSY = -11,
  /*
   * A cooperatively cancellable operation observed its GCancellable in the
   * cancelled state and stopped before completing. No output is produced and
   * any partially built result is discarded. Distinct from WYRELOG_E_IO
   * (genuine device or filesystem failure) and WYRELOG_E_INVALID
   * (argument-shape failure) so callers can treat caller-requested
   * cancellation as an expected, retryable outcome.
   */
  WYRELOG_E_CANCELLED = -12,
} wyrelog_error_t;

const gchar *wyrelog_error_string (wyrelog_error_t err);

G_END_DECLS;

/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "wyl-fsm-session-private.h"
#include "wyl-session-private.h"

/* Single non-installed layout authority shared only by the core GType
 * implementation and the uninstalled service-session companion archive. */
struct _WylSession
{
  GObject parent_instance;
  wyl_id_t id;
  wyl_session_id_t sid;
  gint64 created_at_us;
  gchar *username;
  gchar *tenant;
  /* The session lifecycle word.  It is a plain atomic gint (not the bare
   * enum) so that logout's store and every management liveness load share a
   * single sequentially consistent modification order; the sanctioned
   * accessors below are the ONLY code permitted to touch it. */
  volatile gint state;
  /* Monotonic live-session proof provenance.  This is deliberately private:
   * neither public session ABI nor JWT claims may synthesize it. */
  volatile gint mfa_assured;
  /* Issue #752: the subject-global authentication epoch this session is
   * BOUND to.  Normally that is the principal_events rowid of the
   * authenticating transition (login_skip_mfa or the MFA_OK commit) that THIS
   * session drove to 'authenticated'.  A login that observed an already-
   * authenticated principal drives no transition, so it binds instead to the
   * watermark it observed inside its own publication transaction; it is still
   * non-authoritative (mfa_assured stays 0) but its tokens are checkable.
   * It stays 0 only for a session that is bound to no epoch at all - a loser
   * that attached to an in-flight MFA ceremony, whose subject is not
   * authenticated yet.  It is write-once: set once on the commit that binds
   * it and never rewritten to a different value (the TOTP reauth path
   * re-stores the same observed epoch); a superseded session is rejected,
   * not re-stamped.  Mint stamps it into the human JWT so authorization can
   * reject a token whose epoch the durable watermark has since moved past.
   * The gate this feeds compares epochs only: it does not re-read the live
   * principal state, so it detects supersession by a LATER authenticating
   * transition, not de-authentication that leaves the watermark where it is.
   */
  volatile gint64 authn_epoch;
  volatile gint reauth_pending;
  volatile gint64 reauth_expected_epoch;
  GMutex reauth_mutex;
  wyl_session_auth_method_t auth_method;
  gchar *service_jti;
  gchar *service_subject_id;
  gchar *service_credential_id;
  guint64 service_credential_generation;
  gint64 service_issued_at_seconds;
  gint64 service_expires_at_seconds;
};

/* Sole sanctioned accessors for the atomic lifecycle word.  Every reader
 * (liveness checks, the session FSM, the coordinator authorize gates) and
 * every writer (login, logout/transition, detached construction, the test
 * seams) must route through these so the load/store participate in one
 * coherent modification order.  g_atomic_int_get/set are sequentially
 * consistent; the load is the linearization point for management mutation. */
static inline wyl_session_state_t
wyl_session_state_load_private (const WylSession *session)
{
  return (wyl_session_state_t) g_atomic_int_get ((gint *) &session->state);
}

static inline void
wyl_session_state_store_private (WylSession *session, wyl_session_state_t state)
{
  g_atomic_int_set ((gint *) &session->state, (gint) state);
}

/* Issue #752 authentication-epoch accessors are declared in
* wyl-session-private.h and implemented in wyl-session.c (which owns this
* layout), because non-test daemon code that mints tokens must read the
* epoch without including this uninstalled layout header. */

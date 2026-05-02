/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>

#include "wyrelog/wyl-access-decision-private.h"
#include "wyrelog/wyl-dl-static-private.h"

#ifndef WYL_TEST_ACCESS_DECISION_DL_PATH
#error "WYL_TEST_ACCESS_DECISION_DL_PATH must be defined by the build."
#endif

/* --- Stratification self-check ---------------------------------- */

/*
 * Lifts the eight rule heads introduced by decision.dl into
 * wyl_dl_rule_t form and asserts the program is stratified. Every
 * negation edge from these rules lands on either an EDB predicate
 * (frozen, disabled_role_for, policy_violation, principal_state,
 * session_active) or on `armed` -- which is itself an IDB defined
 * elsewhere but does not depend on any of the heads introduced
 * here, so the negation does not close a cycle.
 */
static gint
check_stratification (void)
{
  static const wyl_dl_body_atom_t allow_body[] = {
    {.predicate = "has_permission",.negated = FALSE},
    {.predicate = "principal_state",.negated = FALSE},
    {.predicate = "session_state",.negated = FALSE},
    {.predicate = "session_active",.negated = FALSE},
    {.predicate = "armed",.negated = FALSE},
    {.predicate = "frozen",.negated = TRUE},
    {.predicate = "disabled_role_for",.negated = TRUE},
    {.predicate = "policy_violation",.negated = TRUE},
  };
  static const wyl_dl_body_atom_t allow_bool_body[] = {
    {.predicate = "allow",.negated = FALSE},
  };
  static const wyl_dl_body_atom_t dr_frozen_body[] = {
    {.predicate = "has_permission",.negated = FALSE},
    {.predicate = "frozen",.negated = FALSE},
  };
  static const wyl_dl_body_atom_t dr_disabled_role_body[] = {
    {.predicate = "has_permission",.negated = FALSE},
    {.predicate = "disabled_role_for",.negated = FALSE},
  };
  static const wyl_dl_body_atom_t dr_sod_body[] = {
    {.predicate = "has_permission",.negated = FALSE},
    {.predicate = "policy_violation",.negated = FALSE},
  };
  static const wyl_dl_body_atom_t dr_not_auth_body[] = {
    {.predicate = "has_permission",.negated = FALSE},
    {.predicate = "principal_state",.negated = TRUE},
  };
  static const wyl_dl_body_atom_t dr_session_inactive_body[] = {
    {.predicate = "has_permission",.negated = FALSE},
    {.predicate = "principal_state",.negated = FALSE},
    {.predicate = "session_state",.negated = FALSE},
    {.predicate = "session_active",.negated = TRUE},
  };
  static const wyl_dl_body_atom_t dr_not_armed_body[] = {
    {.predicate = "has_permission",.negated = FALSE},
    {.predicate = "principal_state",.negated = FALSE},
    {.predicate = "session_state",.negated = FALSE},
    {.predicate = "session_active",.negated = FALSE},
    {.predicate = "armed",.negated = TRUE},
  };
  wyl_dl_rule_t rules[] = {
    {.head = "allow",.body = allow_body,.body_len = G_N_ELEMENTS (allow_body)},
    {.head = "allow_bool",.body = allow_bool_body,
        .body_len = G_N_ELEMENTS (allow_bool_body)},
    {.head = "deny_reason",.body = dr_frozen_body,
        .body_len = G_N_ELEMENTS (dr_frozen_body)},
    {.head = "deny_reason",.body = dr_disabled_role_body,
        .body_len = G_N_ELEMENTS (dr_disabled_role_body)},
    {.head = "deny_reason",.body = dr_sod_body,
        .body_len = G_N_ELEMENTS (dr_sod_body)},
    {.head = "deny_reason",.body = dr_not_auth_body,
        .body_len = G_N_ELEMENTS (dr_not_auth_body)},
    {.head = "deny_reason",.body = dr_session_inactive_body,
        .body_len = G_N_ELEMENTS (dr_session_inactive_body)},
    {.head = "deny_reason",.body = dr_not_armed_body,
        .body_len = G_N_ELEMENTS (dr_not_armed_body)},
  };

  if (wyl_dl_static_check (rules, G_N_ELEMENTS (rules)) != WYRELOG_E_OK)
    return 1;
  return 0;
}

/* --- Code <-> name round-trip ----------------------------------- */

static gint
check_code_name_roundtrip (void)
{
  if (wyl_deny_reason_count () != 6)
    return 10;
  for (guint c = 0; c < WYL_DENY_REASON_LAST_; c++) {
    const gchar *name = wyl_deny_reason_name ((wyl_deny_reason_code_t) c);
    if (name == NULL)
      return (gint) (11 + c);
    if (wyl_deny_reason_from_name (name) != (wyl_deny_reason_code_t) c)
      return (gint) (20 + c);
    const gchar *origin = wyl_deny_reason_origin ((wyl_deny_reason_code_t) c);
    if (origin == NULL)
      return (gint) (30 + c);
  }
  if (wyl_deny_reason_name (WYL_DENY_REASON_LAST_) != NULL)
    return 40;
  if (wyl_deny_reason_origin (WYL_DENY_REASON_LAST_) != NULL)
    return 41;
  if (wyl_deny_reason_from_name (NULL) != WYL_DENY_REASON_LAST_)
    return 42;
  if (wyl_deny_reason_from_name ("does-not-exist") != WYL_DENY_REASON_LAST_)
    return 43;
  return 0;
}

/* --- Priority ordering ------------------------------------------ */

/*
 * Spec priority (high -> low):
 *   frozen > disabled_role > sod > not_authenticated >
 *   session_inactive > not_armed
 *
 * Lower returned value = higher priority.
 */
static gint
check_priority_ordering (void)
{
  guint p_frozen = wyl_deny_reason_priority (WYL_DENY_REASON_FROZEN);
  guint p_disabled = wyl_deny_reason_priority (WYL_DENY_REASON_DISABLED_ROLE);
  guint p_sod = wyl_deny_reason_priority (WYL_DENY_REASON_SOD);
  guint p_na = wyl_deny_reason_priority (WYL_DENY_REASON_NOT_AUTHENTICATED);
  guint p_si = wyl_deny_reason_priority (WYL_DENY_REASON_SESSION_INACTIVE);
  guint p_nar = wyl_deny_reason_priority (WYL_DENY_REASON_NOT_ARMED);

  if (!(p_frozen < p_disabled))
    return 50;
  if (!(p_disabled < p_sod))
    return 51;
  if (!(p_sod < p_na))
    return 52;
  if (!(p_na < p_si))
    return 53;
  if (!(p_si < p_nar))
    return 54;

  if (wyl_deny_reason_priority (WYL_DENY_REASON_LAST_) != G_MAXUINT)
    return 55;
  return 0;
}

/* --- Origin tags align with spec -------------------------------- */

static gint
check_origin_tags (void)
{
  static const struct
  {
    wyl_deny_reason_code_t code;
    const gchar *expected_name;
    const gchar *expected_origin;
  } expectations[] = {
    {WYL_DENY_REASON_FROZEN, "frozen", "frozen"},
    {WYL_DENY_REASON_DISABLED_ROLE, "disabled_role", "disabled_role_for"},
    {WYL_DENY_REASON_SOD, "sod", "policy_violation"},
    {WYL_DENY_REASON_NOT_AUTHENTICATED, "not_authenticated",
        "principal_state"},
    {WYL_DENY_REASON_SESSION_INACTIVE, "session_inactive", "session_state"},
    {WYL_DENY_REASON_NOT_ARMED, "not_armed", "perm_state"},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (expectations); i++) {
    const gchar *name = wyl_deny_reason_name (expectations[i].code);
    const gchar *origin = wyl_deny_reason_origin (expectations[i].code);
    if (g_strcmp0 (name, expectations[i].expected_name) != 0)
      return (gint) (60 + i);
    if (g_strcmp0 (origin, expectations[i].expected_origin) != 0)
      return (gint) (70 + i);
  }
  return 0;
}

/* --- .dl head-signature mirror oracle --------------------------- */

/*
 * Confirms that decision.dl declares exactly one allow/3 head, one
 * allow_bool/3 head, and the six deny_reason/5 heads with literal
 * (code, origin) string pairs identical to the C catalogue. Body
 * compound terms are not parsed; the structural body equality is
 * deferred to a future bisimulation oracle.
 */
static gboolean
extract_deny_reason_pair (const gchar *line, gchar **out_name,
    gchar **out_origin)
{
  /* Matches: deny_reason(U, P, S, "<code>", "<origin>") :- ...
   * The first three positional args are variables; we skip them and
   * pull the two quoted literals at positions 4 and 5. */
  const gchar *prefix = "deny_reason(";
  if (!g_str_has_prefix (line, prefix))
    return FALSE;
  const gchar *p = line + strlen (prefix);

  /* Skip 3 comma-separated args. */
  for (guint i = 0; i < 3; i++) {
    while (*p != ',' && *p != '\0')
      p++;
    if (*p != ',')
      return FALSE;
    p++;
    while (*p == ' ' || *p == '\t')
      p++;
  }

  if (*p != '"')
    return FALSE;
  p++;
  const gchar *end = strchr (p, '"');
  if (end == NULL)
    return FALSE;
  gchar *name = g_strndup (p, (gsize) (end - p));
  p = end + 1;
  while (*p == ' ' || *p == '\t' || *p == ',')
    p++;
  if (*p != '"') {
    g_free (name);
    return FALSE;
  }
  p++;
  end = strchr (p, '"');
  if (end == NULL) {
    g_free (name);
    return FALSE;
  }
  *out_name = name;
  *out_origin = g_strndup (p, (gsize) (end - p));
  return TRUE;
}

static gint
check_head_mirror (void)
{
  g_autofree gchar *contents = NULL;
  gsize len = 0;
  g_autoptr (GError) err = NULL;
  if (!g_file_get_contents (WYL_TEST_ACCESS_DECISION_DL_PATH, &contents,
          &len, &err)) {
    g_printerr ("cannot read %s: %s\n", WYL_TEST_ACCESS_DECISION_DL_PATH,
        err ? err->message : "?");
    return 100;
  }
  g_auto (GStrv) lines = g_strsplit (contents, "\n", -1);
  guint allow_count = 0;
  guint allow_bool_count = 0;
  gsize dr_parsed = 0;
  for (gsize i = 0; lines[i] != NULL; i++) {
    g_autofree gchar *trimmed = g_strdup (g_strchug (lines[i]));
    if (trimmed[0] == '%' || trimmed[0] == '\0')
      continue;
    if (g_str_has_prefix (trimmed, "allow_bool(")) {
      allow_bool_count++;
      continue;
    }
    if (g_str_has_prefix (trimmed, "allow(")) {
      allow_count++;
      continue;
    }
    if (g_str_has_prefix (trimmed, "deny_reason(")) {
      g_autofree gchar *name = NULL;
      g_autofree gchar *origin = NULL;
      if (!extract_deny_reason_pair (trimmed, &name, &origin))
        return (gint) (110 + dr_parsed);
      if (dr_parsed >= wyl_deny_reason_count ())
        return 130;
      const gchar *expect_name =
          wyl_deny_reason_name ((wyl_deny_reason_code_t) dr_parsed);
      const gchar *expect_origin =
          wyl_deny_reason_origin ((wyl_deny_reason_code_t) dr_parsed);
      if (g_strcmp0 (name, expect_name) != 0)
        return (gint) (140 + dr_parsed);
      if (g_strcmp0 (origin, expect_origin) != 0)
        return (gint) (150 + dr_parsed);
      dr_parsed++;
    }
  }
  if (allow_count != 1)
    return 160;
  if (allow_bool_count != 1)
    return 161;
  if (dr_parsed != wyl_deny_reason_count ())
    return 162;
  return 0;
}

int
main (void)
{
  gint rc;
  if ((rc = check_stratification ()) != 0)
    return rc;
  if ((rc = check_code_name_roundtrip ()) != 0)
    return rc;
  if ((rc = check_priority_ordering ()) != 0)
    return rc;
  if ((rc = check_origin_tags ()) != 0)
    return rc;
  if ((rc = check_head_mirror ()) != 0)
    return rc;
  return 0;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>

#include "wyrelog/wyl-fsm-principal-private.h"
#include "wyrelog/wyl-dl-static-private.h"

#ifndef WYL_TEST_FSM_PRINCIPAL_DL_PATH
#error "WYL_TEST_FSM_PRINCIPAL_DL_PATH must be defined by the build."
#endif

/* --- Stratification self-check ---------------------------------- */

/*
 * Lifts the .dl transition table into wyl_dl_rule_t[] form so the
 * existing F0 stratification checker can verify the program is
 * trivially stratified (single non-recursive IDB rule, no negation).
 */
static gint
check_stratification (void)
{
  gsize n = 0;
  (void) wyl_fsm_principal_table (&n);

  /* One rule per transition: head = "principal_transition",
   * body = (state_name, event_name, state_name) literals. The
   * stratification checker only cares about predicate names and
   * negation flags; the literal arguments do not feed the SCC. */
  g_autofree wyl_dl_rule_t *rules = g_new0 (wyl_dl_rule_t, n + 1);
  for (gsize i = 0; i < n; i++) {
    rules[i].head = "principal_transition";
    rules[i].body = NULL;
    rules[i].body_len = 0;
  }

  /* The IDB rule:
   *   principal_step(From, Ev, To) :- principal_transition(From, Ev, To). */
  static const wyl_dl_body_atom_t step_body[] = {
    {.predicate = "principal_transition",.negated = FALSE},
  };
  rules[n].head = "principal_step";
  rules[n].body = step_body;
  rules[n].body_len = G_N_ELEMENTS (step_body);

  if (wyl_dl_static_check (rules, n + 1) != WYRELOG_E_OK)
    return 1;
  return 0;
}

/* --- Golden trace ----------------------------------------------- */

typedef struct
{
  wyl_principal_state_t from;
  wyl_principal_event_t event;
  wyrelog_error_t expected_rc;
  wyl_principal_state_t expected_to;
} step_case_t;

static gint
check_golden_trace (void)
{
  /* Drives the canonical login-through-revocation path plus every
   * defined transition row at least once, plus one undefined
   * transition for the negative path. */
  static const step_case_t cases[] = {
    /* canonical: unverified -> mfa_required -> authenticated -> revoked */
    {WYL_PRINCIPAL_STATE_UNVERIFIED, WYL_PRINCIPAL_EVENT_LOGIN_OK,
        WYRELOG_E_OK, WYL_PRINCIPAL_STATE_MFA_REQUIRED},
    {WYL_PRINCIPAL_STATE_MFA_REQUIRED, WYL_PRINCIPAL_EVENT_MFA_OK,
        WYRELOG_E_OK, WYL_PRINCIPAL_STATE_AUTHENTICATED},
    {WYL_PRINCIPAL_STATE_AUTHENTICATED, WYL_PRINCIPAL_EVENT_REVOKE,
        WYRELOG_E_OK, WYL_PRINCIPAL_STATE_REVOKED},
    /* coverage of remaining defined transitions */
    {WYL_PRINCIPAL_STATE_UNVERIFIED, WYL_PRINCIPAL_EVENT_LOGIN_SKIP_MFA,
        WYRELOG_E_OK, WYL_PRINCIPAL_STATE_AUTHENTICATED},
    {WYL_PRINCIPAL_STATE_MFA_REQUIRED, WYL_PRINCIPAL_EVENT_FAILED_ATTEMPT,
        WYRELOG_E_OK, WYL_PRINCIPAL_STATE_MFA_REQUIRED},
    {WYL_PRINCIPAL_STATE_MFA_REQUIRED, WYL_PRINCIPAL_EVENT_LOCK,
        WYRELOG_E_OK, WYL_PRINCIPAL_STATE_LOCKED},
    {WYL_PRINCIPAL_STATE_AUTHENTICATED, WYL_PRINCIPAL_EVENT_LOCK,
        WYRELOG_E_OK, WYL_PRINCIPAL_STATE_LOCKED},
    {WYL_PRINCIPAL_STATE_LOCKED, WYL_PRINCIPAL_EVENT_UNLOCK,
        WYRELOG_E_OK, WYL_PRINCIPAL_STATE_UNVERIFIED},
    /* negative: revoked is terminal, login_ok has no out-edge */
    {WYL_PRINCIPAL_STATE_REVOKED, WYL_PRINCIPAL_EVENT_LOGIN_OK,
        WYRELOG_E_POLICY, WYL_PRINCIPAL_STATE_REVOKED /* unused */ },
  };

  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++) {
    wyl_principal_state_t to = WYL_PRINCIPAL_STATE_LAST_;
    wyrelog_error_t rc =
        wyl_fsm_principal_step (cases[i].from, cases[i].event, &to);
    if (rc != cases[i].expected_rc)
      return (gint) (10 + i);
    if (rc == WYRELOG_E_OK && to != cases[i].expected_to)
      return (gint) (20 + i);
  }
  return 0;
}

/* --- Argument validation ---------------------------------------- */

static gint
check_argument_validation (void)
{
  wyl_principal_state_t to = WYL_PRINCIPAL_STATE_LAST_;
  /* NULL out_to */
  if (wyl_fsm_principal_step (WYL_PRINCIPAL_STATE_UNVERIFIED,
          WYL_PRINCIPAL_EVENT_LOGIN_OK, NULL) != WYRELOG_E_INVALID)
    return 31;
  /* out-of-range state */
  if (wyl_fsm_principal_step (WYL_PRINCIPAL_STATE_LAST_,
          WYL_PRINCIPAL_EVENT_LOGIN_OK, &to) != WYRELOG_E_INVALID)
    return 32;
  /* out-of-range event */
  if (wyl_fsm_principal_step (WYL_PRINCIPAL_STATE_UNVERIFIED,
          WYL_PRINCIPAL_EVENT_LAST_, &to) != WYRELOG_E_INVALID)
    return 33;
  return 0;
}

/* --- Text mirror oracle ----------------------------------------- */

/*
 * Parses every `principal_transition(...)` line from the .dl file
 * and asserts row-for-row equality with the C table. Mutating
 * either side fails this test, which is the synchronization gate
 * between the two artifacts.
 */
static gboolean
parse_one_row (const gchar *line, gchar **out_from, gchar **out_event,
    gchar **out_to)
{
  /* Expected shape (whitespace-tolerant inside parens):
   *   principal_transition(<from>, <event>, <to>). */
  const gchar *prefix = "principal_transition";
  if (!g_str_has_prefix (line, prefix))
    return FALSE;
  const gchar *p = line + strlen (prefix);
  while (*p == ' ' || *p == '\t')
    p++;
  if (*p != '(')
    return FALSE;
  p++;

  g_auto (GStrv) fields = NULL;
  const gchar *close = strchr (p, ')');
  if (close == NULL)
    return FALSE;
  g_autofree gchar *inner = g_strndup (p, (gsize) (close - p));
  fields = g_strsplit (inner, ",", -1);
  if (g_strv_length (fields) != 3)
    return FALSE;

  *out_from = g_strstrip (g_strdup (fields[0]));
  *out_event = g_strstrip (g_strdup (fields[1]));
  *out_to = g_strstrip (g_strdup (fields[2]));
  return TRUE;
}

static gint
check_text_mirror (void)
{
  g_autofree gchar *contents = NULL;
  gsize len = 0;
  g_autoptr (GError) err = NULL;
  if (!g_file_get_contents (WYL_TEST_FSM_PRINCIPAL_DL_PATH, &contents,
          &len, &err)) {
    g_printerr ("cannot read %s: %s\n", WYL_TEST_FSM_PRINCIPAL_DL_PATH,
        err ? err->message : "?");
    return 41;
  }

  g_auto (GStrv) lines = g_strsplit (contents, "\n", -1);
  gsize parsed_n = 0;
  gsize table_n = 0;
  const wyl_principal_transition_t *table = wyl_fsm_principal_table (&table_n);

  for (gsize i = 0; lines[i] != NULL; i++) {
    g_autofree gchar *trimmed = g_strdup (g_strchug (lines[i]));
    if (trimmed[0] == '%' || trimmed[0] == '\0')
      continue;
    if (!g_str_has_prefix (trimmed, "principal_transition"))
      continue;

    g_autofree gchar *from = NULL;
    g_autofree gchar *event = NULL;
    g_autofree gchar *to = NULL;
    if (!parse_one_row (trimmed, &from, &event, &to))
      return (gint) (50 + parsed_n);

    if (parsed_n >= table_n)
      return 60;

    const gchar *expect_from = wyl_principal_state_name (table[parsed_n].from);
    const gchar *expect_event =
        wyl_principal_event_name (table[parsed_n].event);
    const gchar *expect_to = wyl_principal_state_name (table[parsed_n].to);
    if (g_strcmp0 (from, expect_from) != 0)
      return (gint) (70 + parsed_n);
    if (g_strcmp0 (event, expect_event) != 0)
      return (gint) (80 + parsed_n);
    if (g_strcmp0 (to, expect_to) != 0)
      return (gint) (90 + parsed_n);

    parsed_n++;
  }

  if (parsed_n != table_n)
    return 100;
  return 0;
}

int
main (void)
{
  gint rc;
  if ((rc = check_stratification ()) != 0)
    return rc;
  if ((rc = check_golden_trace ()) != 0)
    return rc;
  if ((rc = check_argument_validation ()) != 0)
    return rc;
  if ((rc = check_text_mirror ()) != 0)
    return rc;
  return 0;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>

#include "wyrelog/wyl-fsm-session-private.h"
#include "wyrelog/wyl-dl-static-private.h"

#ifndef WYL_TEST_FSM_SESSION_DL_PATH
#error "WYL_TEST_FSM_SESSION_DL_PATH must be defined by the build."
#endif

/* --- Stratification self-check ---------------------------------- */

/*
 * Lifts the .dl transition table into wyl_dl_rule_t[] form so the
 * existing static stratification checker can verify the program is
 * trivially stratified (single non-recursive IDB rule, no negation).
 */
static gint
check_stratification (void)
{
  gsize n = 0;
  (void) wyl_fsm_session_table (&n);

  g_autofree wyl_dl_rule_t *rules = g_new0 (wyl_dl_rule_t, n + 1);
  for (gsize i = 0; i < n; i++) {
    rules[i].head = "session_transition";
    rules[i].body = NULL;
    rules[i].body_len = 0;
  }

  /* The IDB rule:
   *   session_step(From, Ev, To) :- session_transition(From, Ev, To). */
  static const wyl_dl_body_atom_t step_body[] = {
    {.predicate = "session_transition",.negated = FALSE},
  };
  rules[n].head = "session_step";
  rules[n].body = step_body;
  rules[n].body_len = G_N_ELEMENTS (step_body);

  if (wyl_dl_static_check (rules, n + 1) != WYRELOG_E_OK)
    return 1;
  return 0;
}

/* --- Functional integrity constraint check ---------------------- */

/*
 * No two table rows may share the same (from, event) pair. If they
 * do, wyl_fsm_session_step picks the first match silently, hiding a
 * spec mistake. With 13 rows this is past the eyeball threshold,
 * so the test enforces uniqueness directly.
 */
static gint
check_functional_ic (void)
{
  gsize n = 0;
  const wyl_session_transition_t *table = wyl_fsm_session_table (&n);

  for (gsize i = 0; i < n; i++) {
    for (gsize j = i + 1; j < n; j++) {
      if (table[i].from == table[j].from && table[i].event == table[j].event)
        return 2;
    }
  }
  return 0;
}

/* --- Name lookup round-trip ------------------------------------- */

/*
 * Catches a swap-two-rows bug in state_names / event_names that
 * the G_STATIC_ASSERT length check cannot see: every enum ordinal
 * must produce a non-NULL name, and the LAST_ sentinel must produce
 * NULL. Concrete identity of the strings is asserted by the text
 * mirror oracle below.
 */
static gint
check_name_roundtrip (void)
{
  for (guint s = 0; s < WYL_SESSION_STATE_LAST_; s++) {
    if (wyl_session_state_name ((wyl_session_state_t) s) == NULL)
      return 3;
  }
  if (wyl_session_state_name (WYL_SESSION_STATE_LAST_) != NULL)
    return 4;

  for (guint e = 0; e < WYL_SESSION_EVENT_LAST_; e++) {
    if (wyl_session_event_name ((wyl_session_event_t) e) == NULL)
      return 5;
  }
  if (wyl_session_event_name (WYL_SESSION_EVENT_LAST_) != NULL)
    return 6;
  return 0;
}

/* --- Golden trace ----------------------------------------------- */

typedef struct
{
  wyl_session_state_t from;
  wyl_session_event_t event;
  wyrelog_error_t expected_rc;
  wyl_session_state_t expected_to;
} step_case_t;

static gint
check_golden_trace (void)
{
  /* Drives the canonical session lifecycle plus every defined
   * transition row at least once, plus three negative cases:
   *   - terminal state attempt (closed has no out-edge),
   *   - intentional omission #1 (expiring -> request, no silent
   *     renewal),
   *   - intentional omission #2 (expiring -> idle_timeout, no
   *     implicit collection of expiring sessions). */
  static const step_case_t cases[] = {
    /* canonical: idle -> active -> elevated -> active -> expiring -> closed */
    {WYL_SESSION_STATE_IDLE, WYL_SESSION_EVENT_REQUEST,
        WYRELOG_E_OK, WYL_SESSION_STATE_ACTIVE},
    {WYL_SESSION_STATE_ACTIVE, WYL_SESSION_EVENT_ELEVATE_GRANT,
        WYRELOG_E_OK, WYL_SESSION_STATE_ELEVATED},
    {WYL_SESSION_STATE_ELEVATED, WYL_SESSION_EVENT_ELEVATE_DROP,
        WYRELOG_E_OK, WYL_SESSION_STATE_ACTIVE},
    {WYL_SESSION_STATE_ACTIVE, WYL_SESSION_EVENT_EXPIRY,
        WYRELOG_E_OK, WYL_SESSION_STATE_EXPIRING},
    {WYL_SESSION_STATE_EXPIRING, WYL_SESSION_EVENT_LOGOUT,
        WYRELOG_E_OK, WYL_SESSION_STATE_CLOSED},
    /* coverage of the remaining defined transitions */
    {WYL_SESSION_STATE_IDLE, WYL_SESSION_EVENT_EXPIRY,
        WYRELOG_E_OK, WYL_SESSION_STATE_CLOSED},
    {WYL_SESSION_STATE_IDLE, WYL_SESSION_EVENT_LOGOUT,
        WYRELOG_E_OK, WYL_SESSION_STATE_CLOSED},
    {WYL_SESSION_STATE_ACTIVE, WYL_SESSION_EVENT_IDLE_TIMEOUT,
        WYRELOG_E_OK, WYL_SESSION_STATE_IDLE},
    {WYL_SESSION_STATE_ACTIVE, WYL_SESSION_EVENT_LOGOUT,
        WYRELOG_E_OK, WYL_SESSION_STATE_CLOSED},
    {WYL_SESSION_STATE_ELEVATED, WYL_SESSION_EVENT_IDLE_TIMEOUT,
        WYRELOG_E_OK, WYL_SESSION_STATE_IDLE},
    {WYL_SESSION_STATE_ELEVATED, WYL_SESSION_EVENT_EXPIRY,
        WYRELOG_E_OK, WYL_SESSION_STATE_EXPIRING},
    {WYL_SESSION_STATE_ELEVATED, WYL_SESSION_EVENT_LOGOUT,
        WYRELOG_E_OK, WYL_SESSION_STATE_CLOSED},
    {WYL_SESSION_STATE_EXPIRING, WYL_SESSION_EVENT_EXPIRY,
        WYRELOG_E_OK, WYL_SESSION_STATE_CLOSED},
    /* negatives — terminal state */
    {WYL_SESSION_STATE_CLOSED, WYL_SESSION_EVENT_REQUEST,
        WYRELOG_E_POLICY, WYL_SESSION_STATE_CLOSED /* unused */ },
    /* negatives — intentional omissions on `expiring` */
    {WYL_SESSION_STATE_EXPIRING, WYL_SESSION_EVENT_REQUEST,
        WYRELOG_E_POLICY, WYL_SESSION_STATE_EXPIRING /* unused */ },
    {WYL_SESSION_STATE_EXPIRING, WYL_SESSION_EVENT_IDLE_TIMEOUT,
        WYRELOG_E_POLICY, WYL_SESSION_STATE_EXPIRING /* unused */ },
  };

  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++) {
    wyl_session_state_t to = WYL_SESSION_STATE_LAST_;
    wyrelog_error_t rc =
        wyl_fsm_session_step (cases[i].from, cases[i].event, &to);
    if (rc != cases[i].expected_rc)
      return (gint) (10 + i);
    if (rc == WYRELOG_E_OK && to != cases[i].expected_to)
      return (gint) (40 + i);
  }
  return 0;
}

/* --- Argument validation ---------------------------------------- */

static gint
check_argument_validation (void)
{
  wyl_session_state_t to = WYL_SESSION_STATE_LAST_;
  if (wyl_fsm_session_step (WYL_SESSION_STATE_IDLE,
          WYL_SESSION_EVENT_REQUEST, NULL) != WYRELOG_E_INVALID)
    return 71;
  if (wyl_fsm_session_step (WYL_SESSION_STATE_LAST_,
          WYL_SESSION_EVENT_REQUEST, &to) != WYRELOG_E_INVALID)
    return 72;
  if (wyl_fsm_session_step (WYL_SESSION_STATE_IDLE,
          WYL_SESSION_EVENT_LAST_, &to) != WYRELOG_E_INVALID)
    return 73;
  return 0;
}

/* --- Text mirror oracle ----------------------------------------- */

/*
 * Parses every `session_transition(...)` line from the .dl file
 * and asserts row-for-row equality with the C table. Mutating
 * either side fails this test, which is the synchronization gate
 * between the two artifacts.
 */
static gboolean
parse_one_row (const gchar *line, gchar **out_from, gchar **out_event,
    gchar **out_to)
{
  const gchar *prefix = "session_transition";
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
  /* Reject embedded parens so a future event name with a `)` in it
   * cannot silently truncate the field span. */
  if (strchr (inner, '(') != NULL)
    return FALSE;
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
  if (!g_file_get_contents (WYL_TEST_FSM_SESSION_DL_PATH, &contents,
          &len, &err)) {
    g_printerr ("cannot read %s: %s\n", WYL_TEST_FSM_SESSION_DL_PATH,
        err ? err->message : "?");
    return 81;
  }

  g_auto (GStrv) lines = g_strsplit (contents, "\n", -1);
  gsize parsed_n = 0;
  gsize table_n = 0;
  const wyl_session_transition_t *table = wyl_fsm_session_table (&table_n);

  for (gsize i = 0; lines[i] != NULL; i++) {
    g_autofree gchar *trimmed = g_strdup (g_strchug (lines[i]));
    if (trimmed[0] == '%' || trimmed[0] == '\0')
      continue;
    if (!g_str_has_prefix (trimmed, "session_transition"))
      continue;

    g_autofree gchar *from = NULL;
    g_autofree gchar *event = NULL;
    g_autofree gchar *to = NULL;
    if (!parse_one_row (trimmed, &from, &event, &to))
      return (gint) (90 + parsed_n);

    if (parsed_n >= table_n)
      return 110;

    const gchar *expect_from = wyl_session_state_name (table[parsed_n].from);
    const gchar *expect_event = wyl_session_event_name (table[parsed_n].event);
    const gchar *expect_to = wyl_session_state_name (table[parsed_n].to);
    if (g_strcmp0 (from, expect_from) != 0)
      return (gint) (120 + parsed_n);
    if (g_strcmp0 (event, expect_event) != 0)
      return (gint) (140 + parsed_n);
    if (g_strcmp0 (to, expect_to) != 0)
      return (gint) (160 + parsed_n);

    parsed_n++;
  }

  if (parsed_n != table_n)
    return 180;
  return 0;
}

int
main (void)
{
  gint rc;
  if ((rc = check_stratification ()) != 0)
    return rc;
  if ((rc = check_functional_ic ()) != 0)
    return rc;
  if ((rc = check_name_roundtrip ()) != 0)
    return rc;
  if ((rc = check_golden_trace ()) != 0)
    return rc;
  if ((rc = check_argument_validation ()) != 0)
    return rc;
  if ((rc = check_text_mirror ()) != 0)
    return rc;
  return 0;
}

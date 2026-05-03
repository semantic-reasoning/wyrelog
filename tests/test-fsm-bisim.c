/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * FSM bisimulation oracle.
 *
 * Cross-checks the principal and session transition tables
 * against their Datalog source files. The text side parses the
 * .dl into a (from, event) -> to map keyed on a separator-joined
 * string, so row ordering and literal duplicates are normalised
 * away. The C side calls wyl_fsm_*_step at runtime. The
 * Cartesian product over the full state-times-event space asserts
 * that both walkers agree on every cell: defined transitions
 * agree on the destination, undefined transitions agree on the
 * rejection.
 *
 * permission_scope is intentionally NOT bisimulated: the v0
 * permission scope is stateless armed/3 derivation, not a
 * Mealy-style transition table. The guard expression depth/atom
 * limits and the perm_arm_rule mirror oracle already cover its
 * semantics in earlier test files.
 */
#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>

#include "wyrelog/wyl-fsm-principal-private.h"
#include "wyrelog/wyl-fsm-session-private.h"

#ifndef WYL_TEST_FSM_PRINCIPAL_DL_PATH
#error "WYL_TEST_FSM_PRINCIPAL_DL_PATH must be defined by the build."
#endif
#ifndef WYL_TEST_FSM_SESSION_DL_PATH
#error "WYL_TEST_FSM_SESSION_DL_PATH must be defined by the build."
#endif

/* --- Text-side parser ------------------------------------------- */

static gchar *
make_key (const gchar *from, const gchar *event)
{
  return g_strdup_printf ("%s|%s", from, event);
}

/*
 * Strip surrounding whitespace and a single pair of double-quotes
 * from a Datalog field token. wirelog requires symbol literals in
 * fact position to be quoted; this oracle compares against unquoted
 * state/event names from the C catalogue, so we unwrap here.
 */
static gchar *
strip_dl_symbol (const gchar *raw)
{
  g_autofree gchar *s = g_strstrip (g_strdup (raw));
  gsize n = strlen (s);
  if (n >= 2 && s[0] == '"' && s[n - 1] == '"') {
    s[n - 1] = '\0';
    return g_strdup (s + 1);
  }
  return g_steal_pointer (&s);
}

/*
 * Parses lines of the shape `<predicate>(<from>, <event>, <to>).` and
 * inserts them into a GHashTable keyed on "from|event" with values
 * g_strdup'd to-state names. A literal duplicate (same key, same
 * value) is silently coalesced; a duplicate key with a different
 * value is treated as a parser-detected divergence and surfaced via
 * *out_dup_collision = TRUE so the caller can fail closed.
 */
static GHashTable *
parse_text_table (const gchar *path, const gchar *predicate,
    gboolean *out_dup_collision)
{
  *out_dup_collision = FALSE;
  g_autofree gchar *contents = NULL;
  gsize len = 0;
  g_autoptr (GError) err = NULL;
  if (!g_file_get_contents (path, &contents, &len, &err)) {
    g_printerr ("cannot read %s: %s\n", path, err ? err->message : "?");
    return NULL;
  }

  GHashTable *table = g_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, g_free);
  g_autofree gchar *prefix = g_strdup_printf ("%s(", predicate);

  g_auto (GStrv) lines = g_strsplit (contents, "\n", -1);
  for (gsize i = 0; lines[i] != NULL; i++) {
    g_autofree gchar *trimmed = g_strdup (g_strchug (lines[i]));
    if (trimmed[0] == '%' || trimmed[0] == '\0'
        || g_str_has_prefix (trimmed, "//")
        || g_str_has_prefix (trimmed, ".decl"))
      continue;
    if (!g_str_has_prefix (trimmed, prefix))
      continue;
    const gchar *p = trimmed + strlen (prefix);
    g_auto (GStrv) fields = NULL;
    const gchar *close = strchr (p, ')');
    if (close == NULL)
      continue;
    g_autofree gchar *inner = g_strndup (p, (gsize) (close - p));
    fields = g_strsplit (inner, ",", -1);
    if (g_strv_length (fields) != 3)
      continue;
    g_autofree gchar *from = strip_dl_symbol (fields[0]);
    g_autofree gchar *event = strip_dl_symbol (fields[1]);
    g_autofree gchar *to = strip_dl_symbol (fields[2]);
    gchar *key = make_key (from, event);
    gpointer existing = g_hash_table_lookup (table, key);
    if (existing != NULL) {
      if (g_strcmp0 ((const gchar *) existing, to) != 0) {
        *out_dup_collision = TRUE;
        g_free (key);
        g_hash_table_unref (table);
        return NULL;
      }
      g_free (key);
      continue;
    }
    g_hash_table_insert (table, key, g_strdup (to));
  }
  return table;
}

/* --- Reverse name lookup helpers (local) ------------------------- */

static gint
principal_state_index_from_name (const gchar *name)
{
  for (guint i = 0; i < WYL_PRINCIPAL_STATE_LAST_; i++) {
    if (g_strcmp0 (name, wyl_principal_state_name (i)) == 0)
      return (gint) i;
  }
  return -1;
}

static gint
session_state_index_from_name (const gchar *name)
{
  for (guint i = 0; i < WYL_SESSION_STATE_LAST_; i++) {
    if (g_strcmp0 (name, wyl_session_state_name (i)) == 0)
      return (gint) i;
  }
  return -1;
}

/* --- Bisim core (principal) ------------------------------------- */

static gint
bisim_principal_against_table (GHashTable *text_table)
{
  for (guint s = 0; s < WYL_PRINCIPAL_STATE_LAST_; s++) {
    for (guint e = 0; e < WYL_PRINCIPAL_EVENT_LAST_; e++) {
      const gchar *from_name = wyl_principal_state_name (s);
      const gchar *event_name = wyl_principal_event_name (e);
      g_autofree gchar *key = make_key (from_name, event_name);
      const gchar *text_to = g_hash_table_lookup (text_table, key);

      wyl_principal_state_t to_c = WYL_PRINCIPAL_STATE_LAST_;
      wyrelog_error_t rc = wyl_fsm_principal_step (
          (wyl_principal_state_t) s, (wyl_principal_event_t) e, &to_c);

      if (text_to == NULL) {
        /* .dl has no transition; C must reject. */
        if (rc != WYRELOG_E_POLICY)
          return (gint) (10 + s * WYL_PRINCIPAL_EVENT_LAST_ + e);
      } else {
        /* .dl has a transition; C must accept and agree on to. */
        if (rc != WYRELOG_E_OK)
          return (gint) (50 + s * WYL_PRINCIPAL_EVENT_LAST_ + e);
        gint to_text_idx = principal_state_index_from_name (text_to);
        if (to_text_idx < 0)
          return (gint) (90 + s);
        if ((gint) to_c != to_text_idx)
          return (gint) (100 + s * WYL_PRINCIPAL_EVENT_LAST_ + e);
      }
    }
  }
  return 0;
}

static gint
check_principal_bisim (void)
{
  gboolean dup = FALSE;
  g_autoptr (GHashTable) text_table =
      parse_text_table (WYL_TEST_FSM_PRINCIPAL_DL_PATH, "principal_transition",
      &dup);
  if (text_table == NULL || dup)
    return 1;
  return bisim_principal_against_table (text_table);
}

/* --- Bisim core (session) --------------------------------------- */

static gint
bisim_session_against_table (GHashTable *text_table)
{
  for (guint s = 0; s < WYL_SESSION_STATE_LAST_; s++) {
    for (guint e = 0; e < WYL_SESSION_EVENT_LAST_; e++) {
      const gchar *from_name = wyl_session_state_name (s);
      const gchar *event_name = wyl_session_event_name (e);
      g_autofree gchar *key = make_key (from_name, event_name);
      const gchar *text_to = g_hash_table_lookup (text_table, key);

      wyl_session_state_t to_c = WYL_SESSION_STATE_LAST_;
      wyrelog_error_t rc = wyl_fsm_session_step (
          (wyl_session_state_t) s, (wyl_session_event_t) e, &to_c);

      if (text_to == NULL) {
        if (rc != WYRELOG_E_POLICY)
          return (gint) (210 + s * WYL_SESSION_EVENT_LAST_ + e);
      } else {
        if (rc != WYRELOG_E_OK)
          return (gint) (260 + s * WYL_SESSION_EVENT_LAST_ + e);
        gint to_text_idx = session_state_index_from_name (text_to);
        if (to_text_idx < 0)
          return (gint) (300 + s);
        if ((gint) to_c != to_text_idx)
          return (gint) (310 + s * WYL_SESSION_EVENT_LAST_ + e);
      }
    }
  }
  return 0;
}

static gint
check_session_bisim (void)
{
  gboolean dup = FALSE;
  g_autoptr (GHashTable) text_table =
      parse_text_table (WYL_TEST_FSM_SESSION_DL_PATH, "session_transition",
      &dup);
  if (text_table == NULL || dup)
    return 200;
  return bisim_session_against_table (text_table);
}

/* --- Cardinality bridge ---------------------------------------- */

/*
 * Confirms the parsed text tables have the same row count as the
 * C tables. Combined with the bisim Cartesian walk above, this
 * detects a row added on either side: a missing-from-C row would
 * fail the bisim with `text_to non-NULL but rc=POLICY`; a
 * missing-from-.dl row would fail with `text_to NULL but rc=OK`;
 * a *duplicate* row in either side would fail this cardinality
 * check.
 */
static gint
check_table_cardinality (void)
{
  gboolean dup = FALSE;
  g_autoptr (GHashTable) p_table =
      parse_text_table (WYL_TEST_FSM_PRINCIPAL_DL_PATH, "principal_transition",
      &dup);
  if (p_table == NULL || dup)
    return 400;
  gsize p_c_len = 0;
  (void) wyl_fsm_principal_table (&p_c_len);
  if ((gsize) g_hash_table_size (p_table) != p_c_len)
    return 401;

  g_autoptr (GHashTable) s_table =
      parse_text_table (WYL_TEST_FSM_SESSION_DL_PATH, "session_transition",
      &dup);
  if (s_table == NULL || dup)
    return 402;
  gsize s_c_len = 0;
  (void) wyl_fsm_session_table (&s_c_len);
  if ((gsize) g_hash_table_size (s_table) != s_c_len)
    return 403;
  return 0;
}

/* --- Synthetic divergence detector ----------------------------- */

/*
 * Builds an in-memory text table identical to the principal .dl
 * EXCEPT one row's destination is mutated. The bisim core must
 * reject this fabricated table; passing it would mean the oracle
 * is structurally incapable of catching divergence (always-OK
 * trivial implementation).
 */
static gint
check_divergence_detector (void)
{
  /* Build a baseline table by parsing the real .dl. */
  gboolean dup = FALSE;
  g_autoptr (GHashTable) baseline =
      parse_text_table (WYL_TEST_FSM_PRINCIPAL_DL_PATH, "principal_transition",
      &dup);
  if (baseline == NULL || dup)
    return 500;
  /* Confirm the baseline passes the bisim. */
  if (bisim_principal_against_table (baseline) != 0)
    return 501;

  /* Mutate one entry: flip (mfa_required, mfa_ok) target to "locked". */
  g_autofree gchar *mutated_key = make_key ("mfa_required", "mfa_ok");
  if (!g_hash_table_contains (baseline, mutated_key))
    return 502;
  g_hash_table_replace (baseline, g_strdup (mutated_key), g_strdup ("locked"));

  /* Now the bisim must fire. */
  gint rc = bisim_principal_against_table (baseline);
  if (rc == 0)
    return 503;

  /* Negative test of removal: drop the row entirely. */
  g_autoptr (GHashTable) reduced =
      parse_text_table (WYL_TEST_FSM_PRINCIPAL_DL_PATH, "principal_transition",
      &dup);
  if (reduced == NULL || dup)
    return 504;
  if (!g_hash_table_remove (reduced, mutated_key))
    return 505;
  rc = bisim_principal_against_table (reduced);
  if (rc == 0)
    return 506;
  return 0;
}

int
main (void)
{
  gint rc;
  if ((rc = check_table_cardinality ()) != 0)
    return rc;
  if ((rc = check_principal_bisim ()) != 0)
    return rc;
  if ((rc = check_session_bisim ()) != 0)
    return rc;
  if ((rc = check_divergence_detector ()) != 0)
    return rc;
  return 0;
}

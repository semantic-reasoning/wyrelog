/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "wyrelog/policy/store-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

static gboolean
template_tree_has_backup (const gchar *dir_path)
{
  g_autoptr (GDir) dir = g_dir_open (dir_path, 0, NULL);
  if (dir == NULL)
    return TRUE;

  const gchar *name = NULL;
  while ((name = g_dir_read_name (dir)) != NULL) {
    g_autofree gchar *path = g_build_filename (dir_path, name, NULL);

    if (g_str_has_suffix (name, "~") || g_str_has_suffix (name, ".bak")
        || g_str_has_suffix (name, ".orig"))
      return TRUE;
    if (g_file_test (path, G_FILE_TEST_IS_DIR)
        && template_tree_has_backup (path))
      return TRUE;
  }
  return FALSE;
}

static gint
collect_template_facts (const gchar *contents, const gchar *prefix,
    GHashTable *out)
{
  g_auto (GStrv) lines = g_strsplit (contents, "\n", -1);

  for (gsize i = 0; lines[i] != NULL; i++) {
    g_autofree gchar *line = g_strdup (lines[i]);
    g_strstrip (line);
    if (!g_str_has_prefix (line, prefix))
      continue;

    const gchar *start = strchr (line, '"');
    if (start == NULL)
      return 10;
    const gchar *end = strchr (start + 1, '"');
    if (end == NULL || end == start + 1)
      return 11;

    g_hash_table_add (out, g_strndup (start + 1, (gsize) (end - start - 1)));
  }

  return 0;
}

static guint
count_substring (const gchar *haystack, const gchar *needle)
{
  guint count = 0;
  const gchar *p = haystack;

  while ((p = strstr (p, needle)) != NULL) {
    count++;
    p += strlen (needle);
  }
  return count;
}

static gint
check_seed_list (GHashTable *template_ids, gsize count,
    const gchar *(*id_at) (gsize))
{
  if (g_hash_table_size (template_ids) != count)
    return 20;

  for (gsize i = 0; i < count; i++) {
    const gchar *id = id_at (i);
    if (id == NULL)
      return 21;
    if (!g_hash_table_contains (template_ids, id))
      return 22;
  }

  return 0;
}

static gint
check_bootstrap_seed_contract (const gchar *contents, gsize len)
{
  static const gchar *const snippets[] = {
    ".decl role(name: symbol)",
    ".decl permission(name: symbol)",
    ".decl role_permission(role: symbol, perm: symbol)",
    ".decl inherits(child: symbol, parent: symbol)",
    ".decl direct_permission(user: symbol, perm: symbol, scope: symbol)",
    ".decl member_of(user: symbol, role: symbol, scope: symbol)",
    ".decl effective_member(user: symbol, role: symbol, scope: symbol)",
    ".decl effective_permission(role: symbol, perm: symbol)",
    ".decl has_permission(user: symbol, perm: symbol, scope: symbol)",
    ".decl login_skip_mfa_authz(user: symbol)",
    "permission(\"wr.policy.read\").",
    "permission(\"wr.policy.write\").",
    "permission(\"wr.policy.grant_role\").",
    "permission(\"wr.audit.read\").",
    "permission(\"wr.audit.write\").",
    "role_permission(\"wr.system_admin\", \"wr.policy.write\").",
    "role_permission(\"wr.service_admin\", \"wr.policy.write\").",
    "role_permission(\"wr.auditor\", \"wr.audit.read\").",
    "role_permission(\"wr.system_agent\", \"wr.audit.write\").",
    "effective_permission(R, P) :- role_permission(R, P).",
    "effective_permission(R, P) :- inherits(R, R2), role_permission(R2, P).",
    "has_permission(U, P, S) :- effective_member(U, R, S), effective_permission(R, P).",
    "has_permission(U, P, S) :- direct_permission(U, P, S).",
    "can_read_audit(U) :- has_permission(U, \"wr.audit.read\", _).",
  };

  for (gsize i = 0; i < G_N_ELEMENTS (snippets); i++) {
    if (g_strstr_len (contents, (gssize) len, snippets[i]) == NULL)
      return (gint) (80 + i);
  }
  if (count_substring (contents, "permission(\"wr.login.skip_mfa\").") != 1)
    return 103;
  if (count_substring (contents, "role_permission(\"wr.login.skip_mfa\"") != 0)
    return 104;
  if (count_substring (contents, ", \"wr.login.skip_mfa\")") != 0)
    return 105;
  return 0;
}

static gint
check_bootstrap_seed_consistency (void)
{
  g_autofree gchar *path =
      g_build_filename (WYL_TEST_TEMPLATE_DIR, "bootstrap.dl", NULL);
  g_autofree gchar *contents = NULL;
  gsize len = 0;
  g_autoptr (GError) error = NULL;

  if (!g_file_get_contents (path, &contents, &len, &error))
    return 30;
  if (count_substring (contents, "\"wr.login.skip_mfa\"") != 1)
    return 33;
  gint rc = check_bootstrap_seed_contract (contents, len);
  if (rc != 0)
    return rc;

  g_autoptr (GHashTable) roles = g_hash_table_new_full (g_str_hash,
      g_str_equal, g_free, NULL);
  g_autoptr (GHashTable) permissions = g_hash_table_new_full (g_str_hash,
      g_str_equal, g_free, NULL);

  rc = collect_template_facts (contents, "role(", roles);
  if (rc != 0)
    return 31;
  rc = collect_template_facts (contents, "permission(", permissions);
  if (rc != 0)
    return 32;

  rc = check_seed_list (roles, wyl_policy_store_builtin_role_count (),
      wyl_policy_store_builtin_role_id);
  if (rc != 0)
    return 40 + rc;
  rc = check_seed_list (permissions,
      wyl_policy_store_builtin_permission_count (),
      wyl_policy_store_builtin_permission_id);
  if (rc != 0)
    return 60 + rc;

  return 0;
}

static gint
read_template_file (const gchar *relative_path, gchar **out_contents,
    gsize *out_len)
{
  g_autofree gchar *path =
      g_build_filename (WYL_TEST_TEMPLATE_DIR, relative_path, NULL);
  g_autoptr (GError) error = NULL;
  g_autofree gchar *raw = NULL;
  gsize raw_len = 0;

  if (!g_file_get_contents (path, &raw, &raw_len, &error))
    return 90;
  g_autoptr (GString) normalized = g_string_sized_new (raw_len);
  for (const gchar * p = raw; *p != '\0'; p++) {
    if (*p != '\r')
      g_string_append_c (normalized, *p);
  }
  *out_contents = g_string_free (g_steal_pointer (&normalized), FALSE);
  *out_len = strlen (*out_contents);
  return 0;
}

static gint
check_required_snippets (const gchar *contents, gsize len,
    const gchar *const *snippets, gsize n_snippets, gint error_base)
{
  for (gsize i = 0; i < n_snippets; i++) {
    if (g_strstr_len (contents, (gssize) len, snippets[i]) == NULL)
      return (gint) (error_base + i);
  }
  return 0;
}

static gint
check_decision_template_relation_contract (void)
{
  static const gchar *const snippets[] = {
    ".decl audit_event_input(id: symbol, created_at_us: int64, decision: symbol)",
    ".decl audit_event_subject_input(id: symbol, subject: symbol)",
    ".decl audit_event_action_input(id: symbol, action: symbol)",
    ".decl audit_event_resource_input(id: symbol, resource: symbol)",
    ".decl audit_event_deny_reason_input(id: symbol, reason: symbol)",
    ".decl audit_event_deny_origin_input(id: symbol, origin: symbol)",
    ".decl audit_event_request_id_input(id: symbol, request_id: symbol)",
    ".decl audit_event(id: symbol, created_at_us: int64, decision: symbol)",
    ".decl audit_event_subject(id: symbol, subject: symbol)",
    ".decl audit_event_action(id: symbol, action: symbol)",
    ".decl audit_event_resource(id: symbol, resource: symbol)",
    ".decl audit_event_deny_reason(id: symbol, reason: symbol)",
    ".decl audit_event_deny_origin(id: symbol, origin: symbol)",
    ".decl audit_event_request_id(id: symbol, request_id: symbol)",
    ".decl login_skip_mfa_authz_observed(user: symbol)",
    ".decl allow_bool(user: symbol, perm: symbol, scope: symbol)",
    ".decl deny_reason(user: symbol, perm: symbol, scope: symbol,\n"
        "    code: symbol, origin: symbol)",
    "audit_event_request_id(ID, RequestID) :-\n"
        "    audit_event_request_id_input(ID, RequestID).",
    "login_skip_mfa_authz_observed(U) :-\n" "    login_skip_mfa_authz(U).",
  };
  g_autofree gchar *contents = NULL;
  gsize len = 0;
  gint rc = read_template_file ("lobac/decision.dl", &contents, &len);
  if (rc != 0)
    return rc;
  return check_required_snippets (contents, len, snippets,
      G_N_ELEMENTS (snippets), 100);
}

static gint
check_permission_scope_relation_contract (void)
{
  static const gchar *const snippets[] = {
    ".decl perm_state_transition(from: symbol, event: symbol, to: symbol)",
    ".decl perm_state_event(event_id: int64, user: symbol, perm: symbol,\n"
        "    scope: symbol, event: symbol, from_state: symbol, to_state: symbol)",
    ".decl perm_state_fired(event_id: int64, user: symbol, perm: symbol,\n"
        "    scope: symbol, from_state: symbol, event: symbol, to_state: symbol)",
    ".decl perm_arm_rule_observed(perm: symbol, guard_handle: int64)",
    ".decl perm_window_guard_observed(perm: symbol, window: symbol)",
    ".decl guard_context_timestamp(user: symbol, scope: symbol, timestamp: int64)",
    ".decl guard_context_loc_class(user: symbol, scope: symbol, loc_class: symbol)",
    ".decl guard_context_risk(user: symbol, scope: symbol, risk: int64)",
    ".decl guard_context_in_window(user: symbol, scope: symbol, timestamp: int64,\n"
        "    window: symbol)",
    ".decl loc_class(loc_id: symbol, class: symbol)",
    ".decl in_window(timestamp: int64, window: symbol)",
    "perm_arm_rule_observed(P, G) :- perm_arm_rule(P, G).",
    "perm_window_guard_observed(P, W) :- perm_window_guard(P, W).",
  };
  g_autofree gchar *contents = NULL;
  gsize len = 0;
  gint rc = read_template_file ("fsm/permission_scope.dl", &contents, &len);
  if (rc != 0)
    return rc;
  return check_required_snippets (contents, len, snippets,
      G_N_ELEMENTS (snippets), 130);
}

static gint
check_audit_schema_contract (const gchar *relative_path, gint error_base)
{
  static const gchar *const snippets[] = {
    "CREATE TABLE IF NOT EXISTS audit_events (",
    "id            ",
    "created_at_us ",
    "subject_id    ",
    "action        ",
    "resource_id   ",
    "deny_reason   ",
    "deny_origin   ",
    "request_id    ",
    "decision      ",
    "CREATE INDEX IF NOT EXISTS idx_audit_events_created_at_us\n"
        "    ON audit_events (created_at_us);",
    "CREATE INDEX IF NOT EXISTS idx_audit_events_subject_id\n"
        "    ON audit_events (subject_id);",
    "CREATE INDEX IF NOT EXISTS idx_audit_events_action\n"
        "    ON audit_events (action);",
    "CREATE INDEX IF NOT EXISTS idx_audit_events_decision\n"
        "    ON audit_events (decision);",
    "CREATE INDEX IF NOT EXISTS idx_audit_events_deny_reason\n"
        "    ON audit_events (deny_reason);",
    "CREATE INDEX IF NOT EXISTS idx_audit_events_deny_origin\n"
        "    ON audit_events (deny_origin);",
    "CREATE INDEX IF NOT EXISTS idx_audit_events_request_id\n"
        "    ON audit_events (request_id);",
  };
  g_autofree gchar *contents = NULL;
  gsize len = 0;
  gint rc = read_template_file (relative_path, &contents, &len);
  if (rc != 0)
    return rc;
  return check_required_snippets (contents, len, snippets,
      G_N_ELEMENTS (snippets), error_base);
}

static gint
check_audit_schema_contracts (void)
{
  gint rc = check_audit_schema_contract ("sqlite-schema.sql", 150);
  if (rc != 0)
    return rc;
  return check_audit_schema_contract ("duckdb-schema.sql", 180);
}

int
main (void)
{
  if (template_tree_has_backup (WYL_TEST_TEMPLATE_DIR))
    return 1;
  gint rc = check_bootstrap_seed_consistency ();
  if (rc != 0)
    return rc;
  rc = check_decision_template_relation_contract ();
  if (rc != 0)
    return rc;
  rc = check_permission_scope_relation_contract ();
  if (rc != 0)
    return rc;
  return check_audit_schema_contracts ();
}

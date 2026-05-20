/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <sqlite3.h>
#include <string.h>

#include "daemon/options.h"
#include "daemon/runtime.h"
#include "wyrelog/wyrelog.h"
#include "wyl-engine-private.h"

#ifndef WYL_DEFAULT_TEMPLATE_DIR
#error "WYL_DEFAULT_TEMPLATE_DIR must be defined by the build."
#endif

/* Tri-state result of the read-only bootstrap-store probe.
 *
 * EMPTY         - probe succeeded and the store has no real subject
 *                 row. Caller stays silent (no WARN).
 * NONEMPTY      - probe succeeded and at least one subject row exists.
 *                 Caller emits the "stale-key" WARN.
 * INDETERMINATE - the probe could not authoritatively answer (file
 *                 unreadable, encrypted, schema missing, sqlite error,
 *                 path unset). Caller emits a separate "indeterminate"
 *                 WARN so a hostile actor who can write the conf file
 *                 cannot silence the staleness signal by also
 *                 corrupting the policy store.
 *
 * Keep this enum file-private: the trichotomy is an implementation
 * detail of the --profile-info WARN. */
typedef enum
{
  WYL_PROBE_EMPTY,
  WYL_PROBE_NONEMPTY,
  WYL_PROBE_INDETERMINATE,
} WylBootstrapProbeResult;

/* Sanitize an operator-supplied subject id for safe printing to
 * stderr. The conf file is exactly the surface an attacker would
 * write to plant ANSI / CSI / OSC escape sequences in the
 * bootstrap_admin_subject field, and --profile-info output is
 * consumed by humans at terminals during onboarding -- so a raw
 * %s of that string would let the attacker spoof titles, overwrite
 * preceding lines, clear the screen, etc.
 *
 * Encoding rules (dmesg-style):
 *   - printable ASCII in [0x20, 0x7e] except backslash is passed
 *     through verbatim so operators recognise their own subject;
 *   - everything else (control bytes, high bits, backslash itself)
 *     is rendered as the literal seven-character sequence
 *     "\xNN" where NN is two lowercase hex digits.
 *
 * Backslash is escaped so the encoding round-trips reliably: a
 * subject containing "\\x1b" in source form cannot be confused with
 * the encoded form of a real ESC byte.
 *
 * NULL input maps to the empty string. */
static gchar *
sanitize_subject_for_stderr (const gchar *raw)
{
  if (raw == NULL)
    return g_strdup ("");
  GString *out = g_string_new (NULL);
  for (const guchar * p = (const guchar *)raw; *p; p++) {
    if (*p >= 0x20 && *p <= 0x7e && *p != '\\') {
      g_string_append_c (out, (gchar) * p);
    } else {
      g_string_append_printf (out, "\\x%02x", *p);
    }
  }
  return g_string_free (out, FALSE);
}

/* policy_store_probe_subjects -- read-only probe.
 *
 * Used by the --profile-info bootstrap-key staleness WARN. Opens the
 * policy authority store read-only (SQLITE_OPEN_READONLY, NO_MUTEX is
 * safe here because we are single-threaded in main() before runtime
 * spin-up) and asks "has any real subject row landed in this store
 * yet?" via principal_states.
 *
 * principal_states is the canonical "this subject ever existed" table
 * (PRIMARY KEY subject_id, populated on first FSM transition). The
 * seal marker in wyrelog_config does NOT count -- it is metadata about
 * the bootstrap key, not a subject row -- which is why we deliberately
 * pick principal_states rather than role_memberships (which also gets
 * the bootstrap admin's wr.system_admin grant).
 *
 * Empty-store fast path: a single SELECT 1 ... LIMIT 1. We never
 * enumerate rows; we never read row contents.
 *
 * Tri-state return contract (see WylBootstrapProbeResult):
 *   - EMPTY         the store opened cleanly and principal_states is
 *                   present but contains no rows.
 *   - NONEMPTY      the store opened cleanly and principal_states
 *                   contains at least one row.
 *   - INDETERMINATE the probe could not authoritatively determine
 *                   either of the above (unset path, sqlite_open
 *                   failure, missing/encrypted schema, step error).
 *                   *out_reason (caller-allocated, transfer full) is
 *                   set to a short, human-readable, ASCII-only reason
 *                   string; caller frees with g_free().
 *
 * The INDETERMINATE arm distinguishes commit 1's bootstrap WARN from
 * the existing runtime-open path so that an attacker who can write
 * the conf cannot silence the staleness signal merely by ALSO
 * corrupting the policy store -- the operator gets a different,
 * greppable line for that case. */
static WylBootstrapProbeResult
policy_store_probe_subjects (const gchar *policy_db, gchar **out_reason)
{
  if (out_reason != NULL)
    *out_reason = NULL;

  if (policy_db == NULL || policy_db[0] == '\0') {
    if (out_reason != NULL)
      *out_reason = g_strdup ("policy_db path is unset");
    return WYL_PROBE_INDETERMINATE;
  }

  sqlite3 *db = NULL;
  if (sqlite3_open_v2 (policy_db, &db,
          SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, NULL) != SQLITE_OK) {
    if (out_reason != NULL) {
      *out_reason = g_strdup_printf ("sqlite3_open_v2 failed: %s",
          db != NULL ? sqlite3_errmsg (db) : "(no handle)");
    }
    if (db != NULL)
      sqlite3_close (db);
    return WYL_PROBE_INDETERMINATE;
  }

  /* Probe whether the schema is even present. A fresh / encrypted /
   * non-policy-store file will fail this check and we report
   * INDETERMINATE so the caller emits the "indeterminate" WARN. */
  sqlite3_stmt *probe = NULL;
  if (sqlite3_prepare_v2 (db,
          "SELECT name FROM sqlite_master "
          "WHERE type='table' AND name='principal_states' LIMIT 1;",
          -1, &probe, NULL) != SQLITE_OK) {
    if (out_reason != NULL) {
      *out_reason = g_strdup_printf ("schema probe failed: %s",
          sqlite3_errmsg (db));
    }
    sqlite3_close (db);
    return WYL_PROBE_INDETERMINATE;
  }
  int probe_rc = sqlite3_step (probe);
  sqlite3_finalize (probe);
  if (probe_rc != SQLITE_ROW) {
    /* No principal_states table -> store is either pre-schema or
     * encrypted. INDETERMINATE: emit the dedicated WARN rather than
     * silently dropping the staleness signal. */
    if (out_reason != NULL)
      *out_reason = g_strdup ("principal_states table missing or unreadable");
    sqlite3_close (db);
    return WYL_PROBE_INDETERMINATE;
  }

  sqlite3_stmt *stmt = NULL;
  if (sqlite3_prepare_v2 (db,
          "SELECT 1 FROM principal_states LIMIT 1;", -1, &stmt,
          NULL) != SQLITE_OK) {
    if (out_reason != NULL) {
      *out_reason = g_strdup_printf ("subject probe prepare failed: %s",
          sqlite3_errmsg (db));
    }
    sqlite3_close (db);
    return WYL_PROBE_INDETERMINATE;
  }
  int rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  sqlite3_close (db);

  if (rc == SQLITE_ROW)
    return WYL_PROBE_NONEMPTY;
  if (rc == SQLITE_DONE)
    return WYL_PROBE_EMPTY;

  if (out_reason != NULL)
    *out_reason = g_strdup_printf ("subject probe step failed: sqlite rc=%d",
        rc);
  return WYL_PROBE_INDETERMINATE;
}

/* Emit the bootstrap-key staleness WARN to stderr when --profile-info
 * detects a populated policy store alongside bootstrap_admin_*
 * settings, OR a separate "indeterminate" WARN when the probe could
 * not authoritatively answer. Quiet on every other code path.
 *
 * The subject id is sanitized through sanitize_subject_for_stderr()
 * before emission: the conf file is exactly the write surface an
 * attacker would use to plant ANSI/CSI/OSC escape sequences, and
 * piping that verbatim through stderr at onboarding time would let
 * the attacker spoof terminal output. */
static void
maybe_warn_stale_bootstrap_key (const WylDaemonOptions *opts)
{
  gboolean subject_set = opts->bootstrap_admin_subject != NULL &&
      opts->bootstrap_admin_subject[0] != '\0';
  if (!subject_set && !opts->bootstrap_admin_allow_skip_mfa)
    return;

  g_autofree gchar *reason = NULL;
  WylBootstrapProbeResult res =
      policy_store_probe_subjects (opts->policy_store_path, &reason);

  if (res == WYL_PROBE_EMPTY)
    return;                     /* fresh store, nothing to warn about */

  g_autofree gchar *safe_subject =
      sanitize_subject_for_stderr (subject_set ?
      opts->bootstrap_admin_subject : "");

  if (res == WYL_PROBE_NONEMPTY) {
    /* Stable greppable line for operators and packagers. The subject
     * id is sanitized; allow_skip_mfa is a boolean. No policy-store
     * contents are emitted. */
    g_printerr ("wyrelogd: bootstrap_admin: stale-key "
        "subject=%s allow_skip_mfa=%s "
        "(remove bootstrap_admin_subject%s "
        "from /etc/wyrelog/wyrelogd.conf and restart)\n",
        safe_subject,
        opts->bootstrap_admin_allow_skip_mfa ? "true" : "false",
        opts->bootstrap_admin_allow_skip_mfa ?
        " and bootstrap_admin_allow_skip_mfa" : "");
    return;
  }

  /* INDETERMINATE: the probe could not confirm whether the store is
   * empty. An attacker who can write the conf can ALSO corrupt the
   * policy store (same filesystem, same operator UID); corrupting
   * the store deliberately to suppress the WARN would be a bypass.
   * Emit a dedicated greppable line so the operator can decide. */
  g_printerr ("wyrelogd: bootstrap_admin: indeterminate "
      "subject=%s allow_skip_mfa=%s "
      "(policy store unreadable: %s) "
      "-- cannot confirm bootstrap key is fresh\n",
      safe_subject,
      opts->bootstrap_admin_allow_skip_mfa ? "true" : "false",
      reason != NULL ? reason : "unknown");
}

int
main (int argc, char **argv)
{
  WylDaemonOptions opts = {
    .template_dir = WYL_DEFAULT_TEMPLATE_DIR,
    .listen_port = -1,
  };
  g_autoptr (GError) error = NULL;

  if (!wyl_daemon_parse_options (&argc, &argv, &opts, &error)) {
    g_printerr ("wyrelogd: %s\n", error->message);
    return 2;
  }
  if (!wyl_daemon_options_resolve (&opts, &error)) {
    g_printerr ("wyrelogd: %s\n", error->message);
    return 2;
  }

  if (opts.show_version) {
    g_print ("%s\n", wyrelog_version_string ());
    return 0;
  }

  if (opts.show_template_version) {
    gchar *dl_src = NULL;
    gsize dl_src_len = 0;
    wyrelog_error_t rc =
        wyl_engine_load_templates (opts.template_dir, &dl_src, &dl_src_len);
    guint32 template_version = 0;
    if (rc == WYRELOG_E_OK) {
      rc = wyl_engine_verify_template_manifest (opts.template_dir, dl_src,
          dl_src_len, TRUE, &template_version);
    }
    if (dl_src != NULL) {
      memset (dl_src, 0, dl_src_len);
      g_free (dl_src);
    }
    if (rc != WYRELOG_E_OK) {
      g_printerr ("wyrelogd: template version unavailable: %s\n",
          wyrelog_error_string (rc));
      return 3;
    }
    g_print ("%u\n", template_version);
    return 0;
  }

  if (opts.show_template_info) {
    gchar *dl_src = NULL;
    gsize dl_src_len = 0;
    wyrelog_error_t rc =
        wyl_engine_load_templates (opts.template_dir, &dl_src, &dl_src_len);
    WylTemplateArtifactInfo info = { 0 };
    if (rc == WYRELOG_E_OK) {
      rc = wyl_engine_inspect_template_artifact (opts.template_dir, dl_src,
          dl_src_len, TRUE, &info);
    }
    if (dl_src != NULL) {
      memset (dl_src, 0, dl_src_len);
      g_free (dl_src);
    }
    if (rc != WYRELOG_E_OK) {
      g_printerr ("wyrelogd: template info unavailable: %s\n",
          wyrelog_error_string (rc));
      return 3;
    }
    g_print
        ("version=%u\nsha256=%s\nmigrations=%u\nlatest_migration_version=%u\n",
        info.version, info.sha256_hex, info.migration_count,
        info.latest_migration_version);
    return 0;
  }

  if (opts.show_profile_info) {
    g_print ("profile=%s\n", wyl_daemon_profile_name (opts.profile));
    g_print ("template_dir=%s\n", opts.template_dir);
    g_print ("policy_db=%s\n",
        opts.policy_store_path != NULL ? opts.policy_store_path : "");
    g_print ("policy_keyprovider=%s\n",
        opts.policy_keyprovider_path != NULL ? opts.policy_keyprovider_path :
        "");
    g_print ("audit_db=%s\n",
        opts.audit_store_path != NULL ? opts.audit_store_path : "");
    g_print ("fact_root=%s\n", opts.fact_root != NULL ? opts.fact_root : "");
    g_print ("fact_store_mode=%s\n",
        (opts.fact_root != NULL && opts.fact_root[0] != '\0' &&
            opts.fact_store_mode != NULL) ? opts.fact_store_mode : "");
    g_print ("listen_port=%d\n", opts.listen_port);
    g_print ("system_url=%s\n", opts.system_url != NULL ? opts.system_url : "");
    g_print ("event_spool_dir=%s\n",
        opts.event_spool_dir != NULL ? opts.event_spool_dir : "");
    g_print ("event_queue_limit=%u\n", opts.event_queue_limit);
    /* WARN destination is stderr so --profile-info stdout stays a
     * parseable key=value report. Fires on every run while the
     * condition holds. */
    maybe_warn_stale_bootstrap_key (&opts);
    return 0;
  }

  return wyl_daemon_run_runtime (&opts);
}

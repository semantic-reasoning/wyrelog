/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"
#include <gio/gio.h>
#include <glib.h>
#include <glib/gstdio.h>

#include "wyctl-config.h"

static GSettings *
fresh_settings (void)
{
  GSettings *settings = wyctl_open_settings ();
  g_assert_nonnull (settings);
  /* Reset every key the test resolver touches so a previous test
     leaves no residue in the memory backend. */
  static const gchar *keys[] = {
    "daemon-url",
    "default-tenant",
    "default-graph",
    "access-token-file",
    "default-timeout-ms",
    "default-guard-loc-class",
    "default-guard-risk",
    "default-guard-timestamp-mode",
    "default-policy-store",
    "default-keyprovider",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (keys); i++)
    g_settings_reset (settings, keys[i]);
  return settings;
}

static void
test_resolve_string_nulls_propagate (void)
{
  g_autofree gchar *resolved = wyctl_resolve_string_option (NULL, NULL,
          "daemon-url");
  g_assert_null (resolved);
}

static void
test_resolve_string_cli_wins_over_settings (void)
{
  g_autoptr (GSettings) settings = fresh_settings ();
  g_settings_set_string (settings, "daemon-url",
      "http://from-gsettings.example");

  g_autofree gchar *resolved =
      wyctl_resolve_string_option ("http://from-cli.example", settings,
          "daemon-url");
  g_assert_cmpstr (resolved, ==, "http://from-cli.example");
}

static void
test_resolve_string_cli_absent_falls_back (void)
{
  g_autoptr (GSettings) settings = fresh_settings ();
  g_settings_set_string (settings, "daemon-url",
      "http://from-gsettings.example");

  g_autofree gchar *resolved = wyctl_resolve_string_option (NULL, settings,
          "daemon-url");
  g_assert_cmpstr (resolved, ==, "http://from-gsettings.example");
}

static void
test_resolve_string_empty_cli_is_user_value (void)
{
  g_autoptr (GSettings) settings = fresh_settings ();
  g_settings_set_string (settings, "daemon-url",
      "http://from-gsettings.example");

  /* Empty CLI is the user's deliberate-but-broken input. The resolver
     must NOT fall through to GSettings; downstream validation will
     reject it with the existing diagnostic. */
  g_autofree gchar *resolved = wyctl_resolve_string_option ("", settings,
          "daemon-url");
  g_assert_cmpstr (resolved, ==, "");
}

static void
test_resolve_string_empty_settings_is_unset (void)
{
  g_autoptr (GSettings) settings = fresh_settings ();
  /* The schema default is the empty string, which by project
     convention encodes "unset". With no CLI value, the resolver
     must surface that as NULL so the missing-option diagnostic
     remains the single source of truth. */
  g_autofree gchar *resolved = wyctl_resolve_string_option (NULL, settings,
          "daemon-url");
  g_assert_null (resolved);
}

static void
test_resolve_string_null_settings_returns_null (void)
{
  g_autofree gchar *resolved = wyctl_resolve_string_option (NULL, NULL,
          "daemon-url");
  g_assert_null (resolved);
}

static void
test_resolve_uint_cli_wins (void)
{
  g_autoptr (GSettings) settings = fresh_settings ();
  g_settings_set_uint (settings, "default-timeout-ms", 5000);

  g_autofree gchar *resolved = wyctl_resolve_uint_option_as_string ("12345",
          settings, "default-timeout-ms");
  g_assert_cmpstr (resolved, ==, "12345");
}

static void
test_resolve_uint_renders_settings_value (void)
{
  g_autoptr (GSettings) settings = fresh_settings ();
  g_settings_set_uint (settings, "default-timeout-ms", 5000);

  g_autofree gchar *resolved = wyctl_resolve_uint_option_as_string (NULL,
          settings, "default-timeout-ms");
  g_assert_cmpstr (resolved, ==, "5000");
}

static void
test_resolve_uint_no_settings_returns_null (void)
{
  g_autofree gchar *resolved = wyctl_resolve_uint_option_as_string (NULL,
          NULL, "default-timeout-ms");
  g_assert_null (resolved);
}

static void
test_resolve_string_policy_store_cli_wins (void)
{
  g_autoptr (GSettings) settings = fresh_settings ();
  g_settings_set_string (settings, "default-policy-store",
      "/var/lib/wyrelog/from-gsettings.sqlite");

  g_autofree gchar *resolved =
      wyctl_resolve_string_option ("/tmp/from-cli.sqlite", settings,
          "default-policy-store");
  g_assert_cmpstr (resolved, ==, "/tmp/from-cli.sqlite");
}

static void
test_resolve_string_policy_store_falls_back_to_settings (void)
{
  g_autoptr (GSettings) settings = fresh_settings ();
  g_settings_set_string (settings, "default-policy-store",
      "/var/lib/wyrelog/from-gsettings.sqlite");

  g_autofree gchar *resolved = wyctl_resolve_string_option (NULL, settings,
          "default-policy-store");
  g_assert_cmpstr (resolved, ==, "/var/lib/wyrelog/from-gsettings.sqlite");
}

static void
test_resolve_string_policy_store_empty_settings_is_unset (void)
{
  g_autoptr (GSettings) settings = fresh_settings ();
  /* Schema default is the empty string. Symmetry with daemon-url:
     no CLI value + empty-string in GSettings must surface as NULL so
     the caller's "missing --store" diagnostic fires unchanged. */
  g_autofree gchar *resolved = wyctl_resolve_string_option (NULL, settings,
          "default-policy-store");
  g_assert_null (resolved);
}

static void
test_resolve_string_keyprovider_cli_wins (void)
{
  g_autoptr (GSettings) settings = fresh_settings ();
  g_settings_set_string (settings, "default-keyprovider",
      "systemd-creds:wyrelog-policy-from-gsettings");

  g_autofree gchar *resolved =
      wyctl_resolve_string_option ("file:/etc/wyrelog/keyprovider.key",
          settings, "default-keyprovider");
  g_assert_cmpstr (resolved, ==, "file:/etc/wyrelog/keyprovider.key");
}

static void
test_resolve_string_keyprovider_falls_back_to_settings (void)
{
  g_autoptr (GSettings) settings = fresh_settings ();
  g_settings_set_string (settings, "default-keyprovider",
      "systemd-creds:wyrelog-policy");

  g_autofree gchar *resolved = wyctl_resolve_string_option (NULL, settings,
          "default-keyprovider");
  g_assert_cmpstr (resolved, ==, "systemd-creds:wyrelog-policy");
}

static void
test_resolve_string_keyprovider_empty_settings_is_unset (void)
{
  g_autoptr (GSettings) settings = fresh_settings ();
  /* Empty-string symmetry: matches the daemon-url test at line ~78
     and the policy-store equivalent above. */
  g_autofree gchar *resolved = wyctl_resolve_string_option (NULL, settings,
          "default-keyprovider");
  g_assert_null (resolved);
}

static void
test_open_settings_respects_kill_switch (void)
{
  /* WYCTL_DISABLE_GSETTINGS=1 must short-circuit before any schema
     lookup, so an operator can disable GSettings in a CI container
     that has no dconf available. */
  g_setenv (WYCTL_GSETTINGS_DISABLE_ENV, "1", TRUE);
  GSettings *settings = wyctl_open_settings ();
  g_unsetenv (WYCTL_GSETTINGS_DISABLE_ENV);
  g_assert_null (settings);
}

static void
test_open_settings_returns_handle_when_schema_present (void)
{
  /* The harness wires GSETTINGS_SCHEMA_DIR at the compiled schema,
     so this is the happy path. */
  g_autoptr (GSettings) settings = wyctl_open_settings ();
  g_assert_nonnull (settings);
}

static void
test_open_settings_returns_null_for_missing_schema_id (void)
{
  /* Verify the GLib invariant the resolver relies on: looking up a
     schema id that does not exist yields NULL, never g_error. If
     this ever changes wyctl_open_settings would start aborting,
     so it is worth pinning. */
  GSettingsSchemaSource *source = g_settings_schema_source_get_default ();
  g_assert_nonnull (source);
  g_autoptr (GSettingsSchema) schema =
      g_settings_schema_source_lookup (source,
          "org.wyrelog.this-does-not-exist", FALSE);
  g_assert_null (schema);

  /* wyctl_open_settings recurses, so pin the recursive mode too: that is
   * the one it actually relies on. */
  g_autoptr (GSettingsSchema) recursive =
      g_settings_schema_source_lookup (source,
          "org.wyrelog.this-does-not-exist", TRUE);
  g_assert_null (recursive);
}


/* A stale org.wyrelog.wyctl: the id wyctl looks for, carrying only
 * daemon-url.  This is what a partial or half-upgraded install leaves
 * behind, and it is the shape that used to abort the resolver. */
static const gchar STALE_WYCTL_GSCHEMA[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<schemalist>\n"
    "  <schema id=\"org.wyrelog.wyctl\" path=\"/org/wyrelog/wyctl/\">\n"
    "    <key name=\"daemon-url\" type=\"s\">\n"
    "      <default>'http://old.example/'</default>\n"
    "    </key>\n"
    "  </schema>\n"
    "</schemalist>\n";

/* A schema with an id wyctl never looks for.  Its only job is to make the
 * directory that holds it a schema source, so it can sit ahead of the real
 * one in the chain; GLib skips a directory that carries no compiled
 * schemas. */
static const gchar DECOY_GSCHEMA[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<schemalist>\n"
    "  <schema id=\"org.wyrelog.testdecoy\" path=\"/org/wyrelog/testdecoy/\">\n"
    "    <key name=\"unused\" type=\"b\">\n"
    "      <default>false</default>\n"
    "    </key>\n"
    "  </schema>\n"
    "</schemalist>\n";

/* Compile `gschema_xml' into a fresh temporary directory and return that
 * directory, which the caller passes to remove_schema_dir ().
 *
 * The compile is not a formality.  GLib skips a data directory that
 * carries no gschemas.compiled, so an uncompiled directory would not
 * become the head of the source chain at all and every test built on one
 * would pass while proving nothing.  Both the spawn's exit status and the
 * compiled file's existence are therefore asserted here. */
static gchar *
make_schema_dir (const gchar *tmpl, const gchar *gschema_xml)
{
  g_autoptr (GError) error = NULL;
  gchar *dir = g_dir_make_tmp (tmpl, &error);
  g_assert_no_error (error);
  g_assert_nonnull (dir);

  g_autofree gchar *xml_path = g_build_filename (dir, "test.gschema.xml",
          NULL);
  g_assert_true (g_file_set_contents (xml_path, gschema_xml, -1, &error));
  g_assert_no_error (error);

  gchar *argv[] = {
    (gchar *) WYL_TEST_GLIB_COMPILE_SCHEMAS,
    "--strict",
    dir,
    NULL,
  };
  gint wait_status = 0;
  g_assert_true (g_spawn_sync (NULL, argv, NULL, G_SPAWN_DEFAULT, NULL, NULL,
      NULL, NULL, &wait_status, &error));
  g_assert_no_error (error);
  g_assert_true (g_spawn_check_wait_status (wait_status, &error));
  g_assert_no_error (error);

  g_autofree gchar *compiled = g_build_filename (dir, "gschemas.compiled",
          NULL);
  g_assert_true (g_file_test (compiled, G_FILE_TEST_EXISTS));
  return dir;
}

/* Remove what make_schema_dir () created.  A test that leaks one directory
 * per run is a slow way to fill TMPDIR, which reddens this whole suite. */
static void
remove_schema_dir (const gchar *dir)
{
  static const gchar *names[] = { "test.gschema.xml", "gschemas.compiled" };
  for (gsize i = 0; i < G_N_ELEMENTS (names); i++) {
    g_autofree gchar *path = g_build_filename (dir, names[i], NULL);
    g_unlink (path);
  }
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

static void
test_open_settings_finds_schema_behind_a_decoy_source (void)
{
  /* The schema source chain has a head and parents, and wyctl used to
   * consult only the head.  So a correctly installed schema was invisible
   * whenever any other directory carrying compiled schemas came first,
   * while gsettings, which walks the chain, found it -- the divergence
   * #1190 reports.
   *
   * The child runs against a chain whose head is a decoy carrying an
   * unrelated schema, with this build's real one behind it.
   * GSETTINGS_SCHEMA_DIR prepends to that chain rather than replacing it,
   * so the machine's own data directories are still in it, further back.
   * That is why the child first asserts the head does not carry the id:
   * without it a pass would not distinguish "walked the chain" from "the
   * decoy was never the head". */
  if (g_test_subprocess ()) {
    GSettingsSchemaSource *source = g_settings_schema_source_get_default ();
    g_assert_nonnull (source);
    g_autoptr (GSettingsSchema) head =
        g_settings_schema_source_lookup (source, "org.wyrelog.wyctl", FALSE);
    g_assert_null (head);

    g_autoptr (GSettings) settings = wyctl_open_settings ();
    g_assert_nonnull (settings);
    /* Read a key as well: a non-NULL handle proves a schema was resolved,
     * not that it was the one carrying wyctl's keys. */
    g_autofree gchar *url = g_settings_get_string (settings, "daemon-url");
    g_assert_nonnull (url);
    return;
  }

  const gchar *real = g_getenv ("GSETTINGS_SCHEMA_DIR");
  g_assert_nonnull (real);
  g_autofree gchar *saved = g_strdup (real);
  g_autofree gchar *decoy = make_schema_dir ("wyctl-decoy-schema-XXXXXX",
          DECOY_GSCHEMA);
  g_autofree gchar *chain = g_strjoin (":", decoy, saved, NULL);

  g_setenv ("GSETTINGS_SCHEMA_DIR", chain, TRUE);
  g_test_trap_subprocess (NULL, 0, 0);
  g_setenv ("GSETTINGS_SCHEMA_DIR", saved, TRUE);
  remove_schema_dir (decoy);
  g_test_trap_assert_passed ();
}

static void
test_open_settings_degrades_on_a_partial_schema (void)
{
  /* wyctl-config.h promises this resolver never aborts.  That held for a
   * schema that is missing entirely and not for one that is merely
   * incomplete: GLib makes reading an absent key a fatal g_error, so a
   * stale org.wyrelog.wyctl reachable ahead of the real one turned a
   * missing-option diagnostic into a core dump (#1190).
   *
   * The child runs against a chain whose head is exactly that stale
   * schema.  A subprocess is needed because the default schema source is
   * cached on first use and this binary's other cases have already used
   * it. */
  if (g_test_subprocess ()) {
    g_autoptr (GSettings) settings = wyctl_open_settings ();
    g_assert_nonnull (settings);

    g_autofree gchar *url =
        wyctl_resolve_string_option (NULL, settings, "daemon-url");
    g_assert_cmpstr (url, ==, "http://old.example/");

    g_autofree gchar *store =
        wyctl_resolve_string_option (NULL, settings, "default-policy-store");
    g_assert_null (store);

    g_autofree gchar *timeout =
        wyctl_resolve_uint_option_as_string (NULL, settings,
            "default-timeout-ms");
    g_assert_null (timeout);
    return;
  }

  const gchar *real = g_getenv ("GSETTINGS_SCHEMA_DIR");
  g_assert_nonnull (real);
  g_autofree gchar *saved = g_strdup (real);
  g_autofree gchar *stale = make_schema_dir ("wyctl-stale-schema-XXXXXX",
          STALE_WYCTL_GSCHEMA);
  g_autofree gchar *chain = g_strjoin (":", stale, saved, NULL);

  g_setenv ("GSETTINGS_SCHEMA_DIR", chain, TRUE);
  g_test_trap_subprocess (NULL, 0, 0);
  g_setenv ("GSETTINGS_SCHEMA_DIR", saved, TRUE);
  remove_schema_dir (stale);
  g_test_trap_assert_passed ();
}

int
main (int argc, char **argv)
{
  /* Make sure the kill-switch is not inherited from the developer's
     environment so happy-path tests can open the schema. */
  g_unsetenv (WYCTL_GSETTINGS_DISABLE_ENV);

  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/wyctl/config/resolve-string/nulls",
      test_resolve_string_nulls_propagate);
  g_test_add_func ("/wyctl/config/resolve-string/cli-wins",
      test_resolve_string_cli_wins_over_settings);
  g_test_add_func ("/wyctl/config/resolve-string/cli-absent-falls-back",
      test_resolve_string_cli_absent_falls_back);
  g_test_add_func ("/wyctl/config/resolve-string/empty-cli-is-user-value",
      test_resolve_string_empty_cli_is_user_value);
  g_test_add_func ("/wyctl/config/resolve-string/empty-settings-is-unset",
      test_resolve_string_empty_settings_is_unset);
  g_test_add_func ("/wyctl/config/resolve-string/null-settings-returns-null",
      test_resolve_string_null_settings_returns_null);
  g_test_add_func ("/wyctl/config/resolve-uint/cli-wins",
      test_resolve_uint_cli_wins);
  g_test_add_func ("/wyctl/config/resolve-uint/renders-settings-value",
      test_resolve_uint_renders_settings_value);
  g_test_add_func ("/wyctl/config/resolve-uint/no-settings-returns-null",
      test_resolve_uint_no_settings_returns_null);
  g_test_add_func ("/wyctl/config/resolve-string/policy-store-cli-wins",
      test_resolve_string_policy_store_cli_wins);
  g_test_add_func
    ("/wyctl/config/resolve-string/policy-store-falls-back-to-settings",
      test_resolve_string_policy_store_falls_back_to_settings);
  g_test_add_func
    ("/wyctl/config/resolve-string/policy-store-empty-settings-is-unset",
      test_resolve_string_policy_store_empty_settings_is_unset);
  g_test_add_func ("/wyctl/config/resolve-string/keyprovider-cli-wins",
      test_resolve_string_keyprovider_cli_wins);
  g_test_add_func
    ("/wyctl/config/resolve-string/keyprovider-falls-back-to-settings",
      test_resolve_string_keyprovider_falls_back_to_settings);
  g_test_add_func
    ("/wyctl/config/resolve-string/keyprovider-empty-settings-is-unset",
      test_resolve_string_keyprovider_empty_settings_is_unset);
  g_test_add_func ("/wyctl/config/open/respects-kill-switch",
      test_open_settings_respects_kill_switch);
  g_test_add_func ("/wyctl/config/open/handle-when-schema-present",
      test_open_settings_returns_handle_when_schema_present);
  g_test_add_func ("/wyctl/config/open/null-for-missing-schema-id",
      test_open_settings_returns_null_for_missing_schema_id);
  g_test_add_func ("/wyctl/config/open/partial-schema-degrades",
      test_open_settings_degrades_on_a_partial_schema);
  g_test_add_func ("/wyctl/config/open/behind-decoy-source",
      test_open_settings_finds_schema_behind_a_decoy_source);
  return wyl_test_normalize_exit_status (g_test_run ());
}

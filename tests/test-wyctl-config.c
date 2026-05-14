/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <gio/gio.h>
#include <glib.h>

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
  g_test_add_func ("/wyctl/config/open/respects-kill-switch",
      test_open_settings_respects_kill_switch);
  g_test_add_func ("/wyctl/config/open/handle-when-schema-present",
      test_open_settings_returns_handle_when_schema_present);
  g_test_add_func ("/wyctl/config/open/null-for-missing-schema-id",
      test_open_settings_returns_null_for_missing_schema_id);
  return g_test_run ();
}

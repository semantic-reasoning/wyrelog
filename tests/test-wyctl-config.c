/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "test-exit-status.h"
#include <gio/gio.h>
#include <glib.h>
#include <glib/gstdio.h>

#include "wyctl-config.h"

#ifndef G_OS_WIN32
#include <sys/types.h>
#include <unistd.h>
GSettingsSchemaSource *wyctl_config_test_open_filtered_source (uid_t owner);
gboolean wyctl_config_test_trusted_path (const gchar *path, uid_t owner);
gboolean wyctl_config_test_identity_is_secure (uid_t real_uid,
    uid_t effective_uid, uid_t saved_uid, gid_t real_gid, gid_t effective_gid,
    gid_t saved_gid, gboolean platform_secure);
gboolean wyctl_config_test_filesystem_magic_supported (long magic,
    gboolean inspection_succeeded);
gboolean wyctl_config_test_filesystem_path_supported (const gchar *path);
void wyctl_config_test_reject_filesystem_path (const gchar *path);
#endif

#ifndef G_OS_WIN32
static gboolean
root_filter_host_supported (void)
{
  return wyctl_config_test_filesystem_path_supported ("/") &&
         wyctl_config_test_filesystem_path_supported (g_get_tmp_dir ());
}
#endif

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

static const gchar POISONED_WYCTL_GSCHEMA[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<schemalist>\n"
    "  <schema id=\"org.wyrelog.wyctl\" path=\"/org/wyrelog/wyctl/\">\n"
    "    <key name=\"daemon-url\" type=\"s\">\n"
    "      <default>'http://attacker.example/'</default>\n"
    "    </key>\n"
    "  </schema>\n"
    "</schemalist>\n";

static const gchar LOWER_WYCTL_GSCHEMA[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<schemalist>\n"
    "  <schema id=\"org.wyrelog.wyctl\" path=\"/org/wyrelog/wyctl/\">\n"
    "    <key name=\"daemon-url\" type=\"s\">\n"
    "      <default>'http://lower.example/'</default>\n"
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

#ifndef G_OS_WIN32
static void
test_root_filter_skips_writable_head_and_keeps_safe_parent (void)
{
  if (!root_filter_host_supported ()) {
    g_test_skip ("root schema filtering is unavailable on this filesystem");
    return;
  }
  const gchar *saved = g_getenv ("GSETTINGS_SCHEMA_DIR");
  g_autofree gchar *saved_copy = g_strdup (saved);
  g_autofree gchar *unsafe = make_schema_dir ("wyctl-poison-schema-XXXXXX",
          POISONED_WYCTL_GSCHEMA);
  g_autofree gchar *safe = make_schema_dir ("wyctl-safe-schema-XXXXXX",
          STALE_WYCTL_GSCHEMA);
  g_autofree gchar *lower = make_schema_dir ("wyctl-lower-schema-XXXXXX",
          LOWER_WYCTL_GSCHEMA);
  g_assert_cmpint (g_chmod (unsafe, 0777), ==, 0);
  g_autofree gchar *chain = g_strjoin (G_SEARCHPATH_SEPARATOR_S, unsafe,
          safe, lower, NULL);
  g_setenv ("GSETTINGS_SCHEMA_DIR", chain, TRUE);

  g_autoptr (GSettingsSchemaSource) source =
      wyctl_config_test_open_filtered_source (getuid ());
  g_assert_nonnull (source);
  g_autoptr (GSettingsSchema) schema = g_settings_schema_source_lookup
        (source, WYCTL_GSETTINGS_SCHEMA_ID, TRUE);
  g_assert_nonnull (schema);
  g_autoptr (GSettingsSchemaKey) key = g_settings_schema_get_key (schema,
          "daemon-url");
  g_autoptr (GVariant) value = g_settings_schema_key_get_default_value (key);
  g_assert_cmpstr (g_variant_get_string (value, NULL), ==,
      "http://old.example/");

  if (saved_copy != NULL)
    g_setenv ("GSETTINGS_SCHEMA_DIR", saved_copy, TRUE);
  else
    g_unsetenv ("GSETTINGS_SCHEMA_DIR");
  g_assert_cmpint (g_chmod (unsafe, 0700), ==, 0);
  remove_schema_dir (unsafe);
  remove_schema_dir (safe);
  remove_schema_dir (lower);
}

static void
test_root_filter_resolves_protected_symlink_and_dotdot (void)
{
  if (!root_filter_host_supported ()) {
    g_test_skip ("root schema filtering is unavailable on this filesystem");
    return;
  }
  const gchar *saved = g_getenv ("GSETTINGS_SCHEMA_DIR");
  g_autofree gchar *saved_copy = g_strdup (saved);
  g_autofree gchar *safe = make_schema_dir ("wyctl-link-schema-XXXXXX",
          STALE_WYCTL_GSCHEMA);
  g_autofree gchar *link = g_strdup_printf ("%s-link", safe);
  g_assert_cmpint (symlink (safe, link), ==, 0);
  g_autofree gchar *basename = g_path_get_basename (safe);
  g_autofree gchar *via_link = g_strconcat (link, "/../", basename, NULL);
  /* The link target is the schema directory; traversing .. then its basename
   * reaches the same protected directory while exercising actual resolution. */
  g_setenv ("GSETTINGS_SCHEMA_DIR", via_link, TRUE);
  g_autoptr (GSettingsSchemaSource) source =
      wyctl_config_test_open_filtered_source (getuid ());
  g_assert_nonnull (source);
  g_autoptr (GSettingsSchema) schema = g_settings_schema_source_lookup
        (source, WYCTL_GSETTINGS_SCHEMA_ID, TRUE);
  g_assert_nonnull (schema);

  if (saved_copy != NULL)
    g_setenv ("GSETTINGS_SCHEMA_DIR", saved_copy, TRUE);
  else
    g_unsetenv ("GSETTINGS_SCHEMA_DIR");
  g_unlink (link);
  remove_schema_dir (safe);
}

static void
test_root_filter_rejects_symlink_loop (void)
{
  if (!root_filter_host_supported ()) {
    g_test_skip ("root schema filtering is unavailable on this filesystem");
    return;
  }
  g_autofree gchar *loop = g_dir_make_tmp ("wyctl-loop-schema-XXXXXX", NULL);
  g_assert_nonnull (loop);
  g_autofree gchar *link = g_build_filename (loop, "loop", NULL);
  g_assert_cmpint (symlink ("loop", link), ==, 0);
  g_autofree gchar *cache = g_build_filename (loop, "loop",
          "gschemas.compiled", NULL);
  g_assert_false (wyctl_config_test_trusted_path (cache, getuid ()));
  g_unlink (link);
  g_assert_cmpint (g_rmdir (loop), ==, 0);
}

static void
test_root_filter_diagnostic_is_lazy_with_safe_fallback (void)
{
  if (!root_filter_host_supported ()) {
    g_test_skip ("root schema filtering is unavailable on this filesystem");
    return;
  }
  if (g_test_subprocess ()) {
    g_autoptr (GSettingsSchemaSource) source =
        wyctl_config_test_open_filtered_source (getuid ());
    g_assert_nonnull (source);
    g_autoptr (GSettingsSchema) schema = g_settings_schema_source_lookup
          (source, WYCTL_GSETTINGS_SCHEMA_ID, TRUE);
    g_assert_nonnull (schema);
    g_autoptr (GSettings) settings = g_settings_new_full (schema, NULL, NULL);
    wyctl_enable_settings_diagnostics ();
    g_autofree gchar *value = wyctl_resolve_string_option (NULL, settings,
            "daemon-url");
    g_assert_cmpstr (value, ==, "http://old.example/");
    return;
  }

  const gchar *saved = g_getenv ("GSETTINGS_SCHEMA_DIR");
  g_autofree gchar *saved_copy = g_strdup (saved);
  g_autofree gchar *unsafe = make_schema_dir ("wyctl-diagnostic-poison-XXXXXX",
          POISONED_WYCTL_GSCHEMA);
  g_autofree gchar *safe = make_schema_dir ("wyctl-diagnostic-safe-XXXXXX",
          STALE_WYCTL_GSCHEMA);
  g_assert_cmpint (g_chmod (unsafe, 0777), ==, 0);
  g_autofree gchar *chain = g_strjoin (G_SEARCHPATH_SEPARATOR_S, unsafe,
          safe, NULL);
  g_setenv ("GSETTINGS_SCHEMA_DIR", chain, TRUE);
  g_test_trap_subprocess (NULL, 0, 0);
  if (saved_copy != NULL)
    g_setenv ("GSETTINGS_SCHEMA_DIR", saved_copy, TRUE);
  else
    g_unsetenv ("GSETTINGS_SCHEMA_DIR");
  g_assert_cmpint (g_chmod (unsafe, 0700), ==, 0);
  remove_schema_dir (unsafe);
  remove_schema_dir (safe);
  g_test_trap_assert_passed ();
  g_test_trap_assert_stderr ("*untrusted schema source was ignored*");
}

static void
test_root_filter_rejects_writable_compiled_cache (void)
{
  if (!root_filter_host_supported ()) {
    g_test_skip ("root schema filtering is unavailable on this filesystem");
    return;
  }
  g_autofree gchar *unsafe = make_schema_dir ("wyctl-writable-cache-XXXXXX",
          STALE_WYCTL_GSCHEMA);
  g_autofree gchar *cache = g_build_filename (unsafe, "gschemas.compiled",
          NULL);
  g_assert_cmpint (g_chmod (cache, 0666), ==, 0);
  g_assert_false (wyctl_config_test_trusted_path (cache, getuid ()));

  g_assert_cmpint (g_chmod (cache, 0600), ==, 0);
  remove_schema_dir (unsafe);
}

static void
test_root_filter_rejects_writable_ancestor (void)
{
  if (!root_filter_host_supported ()) {
    g_test_skip ("root schema filtering is unavailable on this filesystem");
    return;
  }
  g_autofree gchar *base = g_dir_make_tmp ("wyctl-writable-parent-XXXXXX",
          NULL);
  g_assert_nonnull (base);
  g_autofree gchar *compiled = make_schema_dir ("wyctl-parent-child-XXXXXX",
          STALE_WYCTL_GSCHEMA);
  g_autofree gchar *schemas = g_build_filename (base, "schemas", NULL);
  g_assert_cmpint (g_rename (compiled, schemas), ==, 0);
  g_assert_cmpint (g_chmod (base, 0777), ==, 0);
  g_autofree gchar *cache = g_build_filename (schemas, "gschemas.compiled",
          NULL);
  g_assert_false (wyctl_config_test_trusted_path (cache, getuid ()));
  g_assert_cmpint (g_chmod (base, 0700), ==, 0);
  remove_schema_dir (schemas);
  g_assert_cmpint (g_rmdir (base), ==, 0);
}

static void
test_secure_execution_identity_policy (void)
{
  g_assert_false (wyctl_config_test_identity_is_secure (1000, 1000, 1000,
      1000, 1000, 1000, FALSE));
  g_assert_true (wyctl_config_test_identity_is_secure (1000, 0, 0,
      1000, 1000, 1000, FALSE));
  g_assert_true (wyctl_config_test_identity_is_secure (0, 0, 0,
      1000, 0, 0, FALSE));
  g_assert_true (wyctl_config_test_identity_is_secure (1000, 1000, 1000,
      1000, 1000, 1000, TRUE));
}

static void
test_filesystem_trust_allowlist (void)
{
#ifdef __linux__
  g_assert_true (wyctl_config_test_filesystem_magic_supported
        (0x58465342, TRUE)); /* XFS */
  g_assert_true (wyctl_config_test_filesystem_magic_supported
        (0xEF53, TRUE)); /* ext2/ext3/ext4 */
  g_assert_true (wyctl_config_test_filesystem_magic_supported
        (0x9123683E, TRUE)); /* Btrfs */
  g_assert_true (wyctl_config_test_filesystem_magic_supported
        (0x01021994, TRUE)); /* tmpfs */
  g_assert_true (wyctl_config_test_filesystem_magic_supported
        (0x858458f6, TRUE)); /* ramfs */
  g_assert_false (wyctl_config_test_filesystem_magic_supported
        (0x794c7630, TRUE)); /* overlayfs */
  g_assert_false (wyctl_config_test_filesystem_magic_supported
        (0x6969, TRUE)); /* NFS */
  g_assert_false (wyctl_config_test_filesystem_magic_supported
        (0x65735546, TRUE)); /* FUSE */
  g_assert_false (wyctl_config_test_filesystem_magic_supported
        (0x58465342, FALSE)); /* inspection failure */
#endif
}

static void
test_root_filter_rejects_untrusted_filesystem_ancestor (void)
{
  if (!root_filter_host_supported ()) {
    g_test_skip ("root schema filtering is unavailable on this filesystem");
    return;
  }
  g_autofree gchar *base = g_dir_make_tmp ("wyctl-fs-parent-XXXXXX", NULL);
  g_assert_nonnull (base);
  g_autofree gchar *schemas = g_build_filename (base, "schemas", NULL);
  g_assert_cmpint (g_mkdir (schemas, 0700), ==, 0);
  g_autofree gchar *compiled = g_build_filename (schemas,
          "gschemas.compiled", NULL);
  g_assert_true (g_file_set_contents (compiled, "compiled", -1, NULL));
  g_assert_true (wyctl_config_test_filesystem_path_supported (compiled));
  wyctl_config_test_reject_filesystem_path (base);
  g_assert_false (wyctl_config_test_trusted_path (compiled, getuid ()));
  wyctl_config_test_reject_filesystem_path (NULL);
  g_unlink (compiled);
  g_assert_cmpint (g_rmdir (schemas), ==, 0);
  g_assert_cmpint (g_rmdir (base), ==, 0);
}
#endif

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

static void
test_diagnostic_once_after_opt_in (void)
{
  if (g_test_subprocess ()) {
    g_autoptr (GSettings) settings = fresh_settings ();
    wyctl_enable_settings_diagnostics ();
    g_autofree gchar *cli = wyctl_resolve_string_option ("", settings,
            "absent-key");
    g_assert_cmpstr (cli, ==, "");
    g_autofree gchar *empty = wyctl_resolve_string_option (NULL, settings,
            "daemon-url");
    g_assert_null (empty);
    g_autofree gchar *no_key = wyctl_resolve_string_option (NULL, NULL, NULL);
    g_assert_null (no_key);
    g_autofree gchar *missing = wyctl_resolve_string_option (NULL, settings,
            "absent-key");
    g_assert_null (missing);
    /* Enabling twice must not reset the once-per-process budget. */
    wyctl_enable_settings_diagnostics ();
    g_autofree gchar *wrong = wyctl_resolve_uint_option_as_string (NULL,
            settings, "default-tenant");
    g_assert_null (wrong);
    g_autofree gchar *absent = wyctl_resolve_string_option (NULL, NULL,
            "daemon-url");
    g_assert_null (absent);
    return;
  }
  g_test_trap_subprocess (NULL, 0, 0);
  g_test_trap_assert_passed ();
  g_test_trap_assert_stderr ("*GSettings fallback unavailable: missing key "
      "'absent-key'*glib-compile-schemas*");
  g_test_trap_assert_stderr_unmatched ("*GSettings fallback unavailable:*"
      "GSettings fallback unavailable:*");
}

static void
test_diagnostic_wrong_type (gconstpointer data)
{
  gboolean uint = GPOINTER_TO_INT (data);
  if (g_test_subprocess ()) {
    g_autoptr (GSettings) settings = fresh_settings ();
    wyctl_enable_settings_diagnostics ();
    g_autofree gchar *value = uint ?
        wyctl_resolve_uint_option_as_string (NULL, settings, "daemon-url") :
        wyctl_resolve_string_option (NULL, settings, "default-timeout-ms");
    g_assert_null (value);
    return;
  }
  g_test_trap_subprocess (NULL, 0, 0);
  g_test_trap_assert_passed ();
  if (uint)
    g_test_trap_assert_stderr ("*key 'daemon-url' has type 's', expected "
        "type 'u'*org.wyrelog.wyctl*");
  else
    g_test_trap_assert_stderr ("*key 'default-timeout-ms' has type 'u', "
        "expected type 's'*org.wyrelog.wyctl*");
}

static void
test_diagnostic_silent_without_opt_in (void)
{
  if (g_test_subprocess ()) {
    g_autoptr (GSettings) settings = fresh_settings ();
    g_autofree gchar *missing = wyctl_resolve_string_option (NULL, settings,
            "absent-key");
    g_assert_null (missing);
    g_autofree gchar *wrong = wyctl_resolve_string_option (NULL, settings,
            "default-timeout-ms");
    g_assert_null (wrong);
    return;
  }
  g_test_trap_subprocess (NULL, 0, 0);
  g_test_trap_assert_passed ();
  g_test_trap_assert_stderr ("");
}

int
main (int argc, char **argv)
{
  /* Make sure the kill-switch is not inherited from the developer's
     environment so happy-path tests can open the schema. */
  g_unsetenv (WYCTL_GSETTINGS_DISABLE_ENV);

  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/wyctl/config/diagnostic/once",
      test_diagnostic_once_after_opt_in);
  g_test_add_func ("/wyctl/config/diagnostic/opt-in",
      test_diagnostic_silent_without_opt_in);
  g_test_add_data_func ("/wyctl/config/diagnostic/wrong-string",
      GINT_TO_POINTER (FALSE), test_diagnostic_wrong_type);
  g_test_add_data_func ("/wyctl/config/diagnostic/wrong-uint",
      GINT_TO_POINTER (TRUE), test_diagnostic_wrong_type);
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
#ifndef G_OS_WIN32
  g_test_add_func ("/wyctl/config/open/root-filter-skips-writable-head",
      test_root_filter_skips_writable_head_and_keeps_safe_parent);
  g_test_add_func ("/wyctl/config/open/root-filter-writable-cache",
      test_root_filter_rejects_writable_compiled_cache);
  g_test_add_func ("/wyctl/config/open/root-filter-writable-ancestor",
      test_root_filter_rejects_writable_ancestor);
  g_test_add_func ("/wyctl/config/open/secure-execution-identity",
      test_secure_execution_identity_policy);
  g_test_add_func ("/wyctl/config/open/root-filter-filesystem-allowlist",
      test_filesystem_trust_allowlist);
  g_test_add_func ("/wyctl/config/open/root-filter-unsupported-filesystem-ancestor",
      test_root_filter_rejects_untrusted_filesystem_ancestor);
  g_test_add_func ("/wyctl/config/open/root-filter-symlink-dotdot",
      test_root_filter_resolves_protected_symlink_and_dotdot);
  g_test_add_func ("/wyctl/config/open/root-filter-symlink-loop",
      test_root_filter_rejects_symlink_loop);
  g_test_add_func ("/wyctl/config/open/root-filter-diagnostic-lazy",
      test_root_filter_diagnostic_is_lazy_with_safe_fallback);
#endif
  return wyl_test_normalize_exit_status (g_test_run ());
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Expose POSIX.1-2008 chmod-mode-t and the write(2)/symlink(2) syscalls
 * the resolver / token-file fan-out tests use under strict c_std=c17.
 * Must precede every system header. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "test-exit-status.h"

#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef WYL_TEST_WYCTL_PATH
#error "WYL_TEST_WYCTL_PATH is required"
#endif

static void
run_child (gchar **argv, gchar **stdout_buf, gchar **stderr_buf,
    gint *wait_status)
{
  g_autoptr (GError) error = NULL;

  g_assert_true (g_spawn_sync (NULL, argv, NULL, G_SPAWN_DEFAULT, NULL, NULL,
      stdout_buf, stderr_buf, wait_status, &error));
  g_assert_no_error (error);
}

static void
run_child_with_env (gchar **argv, gchar **envp, gchar **stdout_buf,
    gchar **stderr_buf, gint *wait_status)
{
  g_autoptr (GError) error = NULL;

  g_assert_true (g_spawn_sync (NULL, argv, envp, G_SPAWN_DEFAULT, NULL, NULL,
      stdout_buf, stderr_buf, wait_status, &error));
  g_assert_no_error (error);
}

/* Report what the child actually printed when an expected diagnostic is
 * missing.  The bare assertion says only that a substring was absent, which
 * is the least useful half of the evidence (#1186). */
static void
assert_child_stderr_has (const gchar *stderr_buf, const gchar *needle)
{
  if (stderr_buf != NULL && g_strstr_len (stderr_buf, -1, needle) != NULL)
    return;
  g_printerr ("expected \"%s\" on the child's stderr, which was: %s\n",
      needle, stderr_buf != NULL ? stderr_buf : "(null)");
  g_assert_not_reached ();
}

/* A keyfile fixture only means anything if wyctl can find the
 * org.wyrelog.wyctl schema.  wyctl looks it up in the default schema source,
 * recursing into parent sources (wyctl_open_settings), so this mirrors that
 * lookup exactly: it accepts any environment wyctl accepts and rejects any
 * wyctl rejects.  The chain covers GSETTINGS_SCHEMA_DIR, which meson points
 * at this build's compiled schema, and the data dirs, where an installed
 * wyrelog ships one.
 *
 * With no schema reachable there, wyctl reports "missing daemon URL" rather
 * than reading the fixture, and only status-gsettings-supplies-daemon-url
 * notices: it fails on its own downstream assertion, which reads as a
 * resolver bug and is what #1186 recorded as an unexplained failure.  Every
 * other fixture case passes while proving nothing -- the kill-switch case
 * because "missing daemon URL" is precisely what it asserts, the
 * CLI-override case because its URL comes from the command line either way,
 * and the four subcommand cases because they exit at option parsing before
 * any resolution.  Abort here instead, naming the cause: a skip would be
 * counted as a pass, and in a correct environment this cannot fire. */
static void
assert_wyctl_gsettings_schema_available (void)
{
  GSettingsSchemaSource *source = g_settings_schema_source_get_default ();
  g_autoptr (GSettingsSchema) schema = source != NULL
      ? g_settings_schema_source_lookup (source, "org.wyrelog.wyctl", TRUE)
      : NULL;
  if (schema != NULL)
    return;
  const gchar *dir = g_getenv ("GSETTINGS_SCHEMA_DIR");
  g_printerr ("wyctl cannot reach the org.wyrelog.wyctl GSettings schema in "
      "this environment, so the keyfile fixture below would prove nothing "
      "(GSETTINGS_SCHEMA_DIR=%s).  Run this test through meson, which points "
      "the schema source at the compiled schema.\n",
      dir != NULL ? dir : "(unset)");
  g_assert_not_reached ();
}

/* Build a temporary XDG_CONFIG_HOME directory that holds a GSettings
 * keyfile with the supplied org.wyrelog.wyctl values, and return the
 * directory path (owned by caller). Caller must remove the directory
 * tree when done. Both key and value arrays are NULL-terminated and
 * must have matching length; values are stringified GVariant
 * literals so the GSettings keyfile backend reads them as the
 * declared schema type. */
static gchar *
make_keyfile_xdg_dir (const gchar *const *keys, const gchar *const *values)
{
  assert_wyctl_gsettings_schema_available ();
  g_autoptr (GError) error = NULL;
  gchar *xdg = g_dir_make_tmp ("wyctl-xdg-XXXXXX", &error);
  g_assert_no_error (error);

  g_autofree gchar *settings_dir = g_build_filename (xdg, "glib-2.0",
          "settings", NULL);
  g_assert_cmpint (g_mkdir_with_parents (settings_dir, 0700), ==, 0);

  g_autofree gchar *keyfile_path = g_build_filename (settings_dir, "keyfile",
          NULL);
  g_autoptr (GKeyFile) keyfile = g_key_file_new ();
  for (gsize i = 0; keys != NULL && keys[i] != NULL; i++) {
    g_assert_nonnull (values[i]);
    g_key_file_set_string (keyfile, "org/wyrelog/wyctl", keys[i], values[i]);
  }
  g_assert_true (g_key_file_save_to_file (keyfile, keyfile_path, &error));
  g_assert_no_error (error);

  return xdg;
}

static gchar *
gvariant_literal_for_string (const gchar *value)
{
  g_autoptr (GVariant) variant = g_variant_new_string (value);
  return g_variant_print (variant, FALSE);
}

static void
remove_dir_recursive (const gchar *path)
{
  g_autoptr (GError) error = NULL;
  g_autoptr (GFile) file = g_file_new_for_path (path);
  /* Walk and unlink children. Tests stage only files we wrote, so the
   * iteration is small. */
  g_autoptr (GFileEnumerator) en = g_file_enumerate_children (file,
          G_FILE_ATTRIBUTE_STANDARD_NAME ","
          G_FILE_ATTRIBUTE_STANDARD_TYPE, G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS,
          NULL, &error);
  if (en != NULL) {
    while (TRUE) {
      g_autoptr (GFileInfo) info = g_file_enumerator_next_file (en, NULL,
              &error);
      if (info == NULL)
        break;
      g_autofree gchar *child = g_build_filename (path,
              g_file_info_get_name (info), NULL);
      if (g_file_info_get_file_type (info) == G_FILE_TYPE_DIRECTORY)
        remove_dir_recursive (child);
      else
        g_unlink (child);
    }
  }
  g_clear_error (&error);
  g_rmdir (path);
}

/* Build an envp derived from the current process environment, with
 * GSettings pointed at the keyfile backend in xdg_dir. Caller frees
 * with g_strfreev. */
static gchar **
build_gsettings_envp (const gchar *xdg_dir, gboolean disable_gsettings)
{
  gchar **envp = g_get_environ ();
  envp = g_environ_setenv (envp, "XDG_CONFIG_HOME", xdg_dir, TRUE);
  envp = g_environ_setenv (envp, "GSETTINGS_BACKEND", "keyfile", TRUE);
  if (disable_gsettings)
    envp = g_environ_setenv (envp, "WYCTL_DISABLE_GSETTINGS", "1", TRUE);
  else
    envp = g_environ_unsetenv (envp, "WYCTL_DISABLE_GSETTINGS");
  return envp;
}

static gboolean
wait_status_is_success (gint wait_status)
{
  g_autoptr (GError) error = NULL;

  if (g_spawn_check_wait_status (wait_status, &error))
    return TRUE;

  g_clear_error (&error);
  return FALSE;
}

static void
test_version (void)
{
  gchar *argv[] = { WYL_TEST_WYCTL_PATH, "--version", NULL };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);

  g_assert_true (wait_status_is_success (wait_status));
  g_assert_nonnull (stdout_buf);
  g_assert_cmpstr (stdout_buf, !=, "");
  g_assert_null (strchr (stdout_buf, ' '));
  g_assert_cmpstr (stderr_buf, ==, "");
}

static void
test_top_level_help (void)
{
  gchar *help_argv[] = { WYL_TEST_WYCTL_PATH, "--help", NULL };
  gchar *empty_argv[] = { WYL_TEST_WYCTL_PATH, NULL };
  const gchar *const commands[] = {
    "status", "policy", "graph", "fact", "datalog", "audit", "key",
    "mfa", "auth", "service-principal", "service-credential",
    "service-permission-closure", "--daemon-url", "--timeout-ms",
    "--version", NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (help_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_true (wait_status_is_success (wait_status));
  g_assert_cmpstr (stderr_buf, ==, "");
  for (gsize i = 0; commands[i] != NULL; i++)
    g_assert_nonnull (g_strstr_len (stdout_buf, -1, commands[i]));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (empty_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_nonnull (stderr_buf);
  for (gsize i = 0; commands[i] != NULL; i++)
    g_assert_nonnull (g_strstr_len (stderr_buf, -1, commands[i]));
}

static void
test_status_connection_failure (void)
{
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "status",
    "--daemon-url",
    "http://127.0.0.1:1",
    "--timeout-ms",
    "100",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);

  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (stderr_buf);
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: daemon unavailable:"));
  g_assert_null (g_strstr_len (stderr_buf, -1, "backtrace"));
  g_assert_null (g_strstr_len (stderr_buf, -1, "assertion"));
  g_assert_null (g_strstr_len (stderr_buf, -1, "tracker"));
}

/* Run each case in a fresh process: GIO caches schemas and resolvers. */
static void
test_proxy_schema_environment (gconstpointer data)
{
  const gchar *mode = data;
  gboolean dummy = g_str_equal (mode, "dummy");
  gboolean normal = g_str_equal (mode, "normal");
  gboolean local = g_str_equal (mode, "version") ||
      g_str_equal (mode, "invalid-token");
  g_tls_backend_get_default ();
  GIOExtensionPoint *point = g_io_extension_point_lookup
        (G_PROXY_RESOLVER_EXTENSION_POINT_NAME);
  if (!dummy && !local && (point == NULL ||
      g_io_extension_point_get_extension_by_name (point, "gnome") == NULL)) {
    g_test_skip ("GNOME proxy resolver is not installed");
    return;
  }

  if (normal) {
    static const gchar *schemas[] = {
      "org.gnome.system.proxy", "org.gnome.system.proxy.http",
      "org.gnome.system.proxy.https", "org.gnome.system.proxy.ftp",
      "org.gnome.system.proxy.socks",
    };
    GSettingsSchemaSource *source = g_settings_schema_source_get_default ();
    for (gsize i = 0; i < G_N_ELEMENTS (schemas); i++) {
      g_autoptr (GSettingsSchema) schema = source != NULL ?
          g_settings_schema_source_lookup (source, schemas[i], TRUE) : NULL;
      if (schema == NULL) {
        g_test_skip ("Complete GNOME proxy schemas are not installed");
        return;
      }
    }
  }

  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyctl-proxy-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *token = g_build_filename (dir, "token", NULL);
  g_assert_true (g_file_set_contents (token, "test-token\n", -1, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (token, 0600), ==, 0);
  g_auto (GStrv) envp = g_get_environ ();
  if (!normal) {
    envp = g_environ_setenv (envp, "XDG_DATA_DIRS", dir, TRUE);
    envp = g_environ_setenv (envp, "XDG_DATA_HOME", dir, TRUE);
    envp = g_environ_setenv (envp, "GSETTINGS_SCHEMA_DIR", dir, TRUE);
  }
  envp = g_environ_setenv (envp, "XDG_CURRENT_DESKTOP", "GNOME", TRUE);
  envp = g_environ_setenv (envp, "GSETTINGS_BACKEND", "memory", TRUE);
  envp = g_environ_setenv (envp, "WYCTL_DISABLE_GSETTINGS", "1", TRUE);
  envp = g_environ_setenv (envp, "GIO_USE_PROXY_RESOLVER",
          dummy ? "dummy" : "gnome", TRUE);
  if (g_str_equal (mode, "automatic"))
    envp = g_environ_unsetenv (envp, "GIO_USE_PROXY_RESOLVER");

  if (g_str_equal (mode, "partial")) {
    g_autofree gchar *xml = g_build_filename (dir, "proxy.gschema.xml", NULL);
    g_assert_true (g_file_set_contents (xml,
        "<schemalist><schema id='org.gnome.system.proxy' "
        "path='/system/proxy/'/></schemalist>", -1, &error));
    g_assert_no_error (error);
    gchar *compile[] = { "glib-compile-schemas", dir, NULL };
    gint status = 0;
    g_assert_true (g_spawn_sync (NULL, compile, NULL, G_SPAWN_SEARCH_PATH,
        NULL, NULL, NULL, NULL, &status, &error));
    g_assert_no_error (error);
    g_assert_true (g_spawn_check_wait_status (status, &error));
    g_assert_no_error (error);
  }

  gchar *status_argv[] = { WYL_TEST_WYCTL_PATH, "status", "--daemon-url",
                           "http://127.0.0.1:1", "--timeout-ms", "100", NULL };
  gchar *policy_argv[] = { WYL_TEST_WYCTL_PATH, "--daemon-url",
                           "http://127.0.0.1:1", "policy", "check", "--user", "alice",
                           "--permission", "read", "--resource", "doc/1", "--access-token-file",
                           token, NULL };
  gchar *mfa_argv[] = { WYL_TEST_WYCTL_PATH, "--daemon-url",
                        "http://127.0.0.1:1", "mfa", "enroll", "--subject", "alice",
                        "--access-token-file", token, NULL };
  gchar *version_argv[] = { WYL_TEST_WYCTL_PATH, "--version", NULL };
  gchar **argv = status_argv;
  if (g_str_equal (mode, "policy") || g_str_equal (mode, "invalid-token"))
    argv = policy_argv;
  else if (g_str_equal (mode, "mfa"))
    argv = mfa_argv;
  else if (g_str_equal (mode, "version"))
    argv = version_argv;
  if (g_str_equal (mode, "invalid-token"))
    g_assert_cmpint (g_unlink (token), ==, 0);

  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;
  run_child_with_env (argv, envp, &stdout_buf, &stderr_buf, &wait_status);
  remove_dir_recursive (dir);
  g_test_message ("child stderr: %s", stderr_buf);
  g_assert_true (WIFEXITED (wait_status));
  if (g_str_equal (mode, "version")) {
    g_assert_cmpint (WEXITSTATUS (wait_status), ==, 0);
    g_assert_cmpstr (stderr_buf, ==, "");
  } else if (g_str_equal (mode, "invalid-token")) {
    g_assert_cmpint (WEXITSTATUS (wait_status), ==, 2);
    g_assert_nonnull (strstr (stderr_buf, "access token file"));
    g_assert_null (strstr (stderr_buf, "proxy settings unavailable"));
  } else {
    g_assert_cmpint (WEXITSTATUS (wait_status), ==, 1);
    g_assert_cmpstr (stdout_buf, ==, "");
    if (dummy || normal) {
      g_assert_nonnull (strstr (stderr_buf, "wyctl: daemon unavailable:"));
      g_assert_null (strstr (stderr_buf, "proxy settings unavailable"));
    } else {
      g_assert_nonnull (strstr (stderr_buf, "wyctl: proxy settings unavailable"));
      g_assert_nonnull (strstr (stderr_buf, g_str_equal (mode, "partial") ?
          "org.gnome.system.proxy.http" : "org.gnome.system.proxy"));
      g_assert_nonnull (strstr (stderr_buf, "XDG_DATA_DIRS"));
      g_assert_nonnull (strstr (stderr_buf, "GIO_USE_PROXY_RESOLVER=dummy"));
    }
  }
  g_assert_null (strstr (stderr_buf, "GLib-GIO-ERROR"));
}

static void
test_settings_diagnostic (gconstpointer data)
{
  const gchar *mode = data;
  gboolean missing = g_str_equal (mode, "missing");
  gboolean missing_key = g_str_equal (mode, "missing-key");
  gboolean wrong_type = g_str_equal (mode, "wrong-type");
  gboolean uint_missing = g_str_equal (mode, "uint-missing");
  gboolean uint_wrong = g_str_equal (mode, "uint-wrong");
  gboolean auth = g_str_equal (mode, "auth-timeout");
  gboolean diagnostic = missing || missing_key || wrong_type ||
      uint_missing || uint_wrong;
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyctl-settings-XXXXXX", &error);
  g_assert_no_error (error);
  g_auto (GStrv) envp = g_get_environ ();
  envp = g_environ_setenv (envp, "XDG_DATA_DIRS", dir, TRUE);
  envp = g_environ_setenv (envp, "XDG_DATA_HOME", dir, TRUE);
  envp = g_environ_setenv (envp, "GSETTINGS_SCHEMA_DIR", dir, TRUE);
  envp = g_environ_setenv (envp, "GSETTINGS_BACKEND", "memory", TRUE);
  envp = g_environ_setenv (envp, "GIO_USE_PROXY_RESOLVER", "dummy", TRUE);
  envp = g_environ_setenv (envp, "G_DEBUG", "fatal-warnings", TRUE);
  envp = g_environ_unsetenv (envp, "WYCTL_DISABLE_GSETTINGS");
  if (g_str_equal (mode, "disabled"))
    envp = g_environ_setenv (envp, "WYCTL_DISABLE_GSETTINGS", "1", TRUE);

  if (missing_key || wrong_type || uint_missing || uint_wrong || auth ||
      g_str_equal (mode, "empty")) {
    const gchar *url_key = missing_key ? "" : wrong_type ?
        "<key name='daemon-url' type='i'><default>7</default></key>" :
        "<key name='daemon-url' type='s'><default>''</default></key>";
    const gchar *timeout_key = uint_missing || missing_key ? "" :
        uint_wrong ? "<key name='default-timeout-ms' type='s'>"
        "<default>'not-a-timeout-canary'</default></key>" : auth ?
        "<key name='default-timeout-ms' type='u'><default>0</default></key>" :
        "<key name='default-timeout-ms' type='u'><default>2000</default></key>";
    g_autofree gchar *xml = g_strdup_printf
          ("<schemalist><schema id='org.wyrelog.wyctl' "
            "path='/org/wyrelog/wyctl/'>%s%s</schema></schemalist>",
            url_key, timeout_key);
    g_autofree gchar *path = g_build_filename (dir, "test.gschema.xml", NULL);
    g_assert_true (g_file_set_contents (path, xml, -1, &error));
    g_assert_no_error (error);
    gchar *compile[] = { "glib-compile-schemas", "--strict", dir, NULL };
    gint status = 0;
    g_assert_true (g_spawn_sync (NULL, compile, NULL, G_SPAWN_SEARCH_PATH,
        NULL, NULL, NULL, NULL, &status, &error));
    g_assert_no_error (error);
    g_assert_true (g_spawn_check_wait_status (status, &error));
    g_assert_no_error (error);
  }

  gchar *status_argv[] = { WYL_TEST_WYCTL_PATH, "status", NULL };
  gchar *uint_argv[] = { WYL_TEST_WYCTL_PATH, "status", "--daemon-url",
                         "http://127.0.0.1:1", NULL };
  gchar *explicit_argv[] = { WYL_TEST_WYCTL_PATH, "status", "--daemon-url",
                             "http://127.0.0.1:1", "--timeout-ms", "100", NULL };
  gchar *version_argv[] = { WYL_TEST_WYCTL_PATH, "--version", NULL };
  gchar *help_argv[] = { WYL_TEST_WYCTL_PATH, "status", "--help", NULL };
  g_autofree gchar *credential = g_build_filename (dir, "credential", NULL);
  g_autofree gchar *output = g_build_filename (dir, "token", NULL);
  gchar *auth_argv[] = { WYL_TEST_WYCTL_PATH, "--daemon-url",
                         "http://127.0.0.1:1", "auth", "service-token", "--credential-file",
                         credential, "--token-output", output, NULL };
  gchar **argv = status_argv;
  if (uint_missing || uint_wrong)
    argv = uint_argv;
  else if (g_str_equal (mode, "explicit"))
    argv = explicit_argv;
  else if (g_str_equal (mode, "version"))
    argv = version_argv;
  else if (g_str_equal (mode, "help"))
    argv = help_argv;
  else if (auth) {
    g_assert_true (g_file_set_contents (credential,
        "{\"version\":1,\"credential_id\":\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\","
        "\"credential_secret\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}\n",
        -1, &error));
    g_assert_no_error (error);
    g_assert_cmpint (g_chmod (credential, 0600), ==, 0);
    argv = auth_argv;
  }

  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;
  run_child_with_env (argv, envp, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (g_file_test (output, G_FILE_TEST_EXISTS));
  remove_dir_recursive (dir);
  g_test_message ("child stderr: %s", stderr_buf);
  g_assert_true (WIFEXITED (wait_status));
  if (argv == version_argv || argv == help_argv) {
    g_assert_cmpint (WEXITSTATUS (wait_status), ==, 0);
    g_assert_cmpstr (stderr_buf, ==, "");
  } else {
    g_assert_cmpstr (stdout_buf, ==, "");
    g_assert_cmpint (WEXITSTATUS (wait_status), ==,
        argv == explicit_argv || argv == uint_argv ? 1 : 2);
    g_assert_nonnull (strstr (stderr_buf, auth ? "wyctl: invalid timeout" :
        argv == status_argv ? "wyctl: missing daemon URL" :
        "wyctl: daemon unavailable:"));
  }
  const gchar *prefix = "wyctl: GSettings fallback unavailable:";
  const gchar *first = strstr (stderr_buf, prefix);
  if (diagnostic) {
    g_assert_nonnull (first);
    g_assert_null (strstr (first + strlen (prefix), prefix));
    g_assert_nonnull (strstr (stderr_buf, "org.wyrelog.wyctl"));
    g_assert_nonnull (strstr (stderr_buf, "glib-compile-schemas"));
    g_assert_nonnull (strstr (stderr_buf, "GSETTINGS_SCHEMA_DIR"));
    if (missing)
      g_assert_nonnull (strstr (stderr_buf, "schema not found"));
    else {
      g_assert_nonnull (strstr (stderr_buf,
          uint_missing || uint_wrong ? "default-timeout-ms" : "daemon-url"));
      g_assert_nonnull (strstr (stderr_buf,
          missing_key || uint_missing ? "missing key" : "expected type"));
    }
  } else
    g_assert_null (first);
  g_assert_null (strstr (stderr_buf, "not-a-timeout-canary"));
  g_assert_null (strstr (stderr_buf, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
}

static void
assert_status_invalid_timeout (const gchar *timeout_ms)
{
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "--timeout-ms",
    (gchar *) timeout_ms,
    "status",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);

  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (stderr_buf);
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: invalid timeout"));
}

static void
test_status_rejects_invalid_timeout (void)
{
  assert_status_invalid_timeout ("0");
  assert_status_invalid_timeout ("-1");
  assert_status_invalid_timeout ("abc");
  assert_status_invalid_timeout ("60001");
}

/*
 * Join a test server thread that may still be parked in
 * g_socket_listener_accept.  A server below returns on its own only once the
 * wyctl under test has connected.  The policy-check server, alone among
 * them, keeps accepting until a connection actually delivers a request; the
 * others answer whatever they get, so a bare connection is enough to let
 * them return with request still NULL.  The client need not connect at all:
 * one that fails locally, or that exhausts its request budget before the
 * connect completes, exits without ever touching the listener.  The accept
 * has no deadline of its own, so an unconditional join would block forever
 * and the whole binary would die on the meson timeout rather than fail a
 * case.  Cancelling first is what bounds it - the cancellable is the
 * documented, thread-safe way to break a blocking accept, whereas closing
 * the listener from another thread races with the accept itself.
 */
static void
stop_test_server (GThread *thread, GCancellable *cancel)
{
  g_cancellable_cancel (cancel);
  g_thread_join (thread);
}

typedef struct
{
  GSocketListener *listener;
  GCancellable *cancel;
} SlowHealthzServer;

typedef struct
{
  GSocketListener *listener;
  GCancellable *cancel;
  guint status;
  const gchar *body;
  gchar *request;
} StatusProbeServer;

static gpointer
slow_healthz_server_thread (gpointer data)
{
  SlowHealthzServer *server = data;
  g_autoptr (GError) error = NULL;
  g_autoptr (GSocketConnection) conn =
      g_socket_listener_accept (server->listener, NULL, server->cancel, &error);
  if (conn == NULL)
    return NULL;

  gchar buffer[512];
  GInputStream *input = g_io_stream_get_input_stream (G_IO_STREAM (conn));
  GOutputStream *output = g_io_stream_get_output_stream (G_IO_STREAM (conn));

  (void) g_input_stream_read (input, buffer, sizeof buffer, NULL, NULL);
  /* Longer than the client's budget below, so the case proves a wait for a
   * response that never came in time. wyctl reports a refused connect and a
   * cancelled request with the same "daemon unavailable" line, so only the
   * budget separates that proof from a child cancelled before it
   * connected. */
  g_usleep (1500 * 1000);
  (void) g_output_stream_write (output,
      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 40, NULL, NULL);
  (void) g_io_stream_close (G_IO_STREAM (conn), NULL, NULL);

  return NULL;
}

static gpointer
status_probe_server_thread (gpointer data)
{
  StatusProbeServer *server = data;
  g_autoptr (GError) error = NULL;
  g_autoptr (GSocketConnection) conn =
      g_socket_listener_accept (server->listener, NULL, server->cancel, &error);
  if (conn == NULL)
    return NULL;

  gchar buffer[1024];
  GInputStream *input = g_io_stream_get_input_stream (G_IO_STREAM (conn));
  GOutputStream *output = g_io_stream_get_output_stream (G_IO_STREAM (conn));
  gssize n = g_input_stream_read (input, buffer, sizeof buffer - 1, NULL, NULL);
  if (n > 0) {
    buffer[n] = '\0';
    server->request = g_strdup (buffer);
  }

  const gchar *body = server->body != NULL ? server->body : "{}";
  g_autofree gchar *response =
      g_strdup_printf ("HTTP/1.1 %u OK\r\nContent-Type: application/json\r\n"
          "Content-Length: %" G_GSIZE_FORMAT "\r\n\r\n%s",
          server->status, strlen (body), body);
  (void) g_output_stream_write (output, response, strlen (response), NULL,
      NULL);
  (void) g_io_stream_close (G_IO_STREAM (conn), NULL, NULL);
  return NULL;
}

static gchar *
listen_url_for_test_server (GSocketListener **out_listener)
{
  g_autoptr (GError) error = NULL;
  g_autoptr (GSocketListener) listener = g_socket_listener_new ();
  g_autoptr (GInetAddress) address =
      g_inet_address_new_loopback (G_SOCKET_FAMILY_IPV4);
  g_autoptr (GSocketAddress) socket_address =
      g_inet_socket_address_new (address, 0);
  g_autoptr (GSocketAddress) effective_address = NULL;

  g_assert_true (g_socket_listener_add_address (listener, socket_address,
      G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_TCP, NULL, &effective_address,
      &error));
  g_assert_no_error (error);

  guint16 port =
      g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS
            (effective_address));
  *out_listener = g_steal_pointer (&listener);
  return g_strdup_printf ("http://127.0.0.1:%u", port);
}

static void
test_status_times_out (void)
{
  g_autoptr (GError) error = NULL;
  g_autoptr (GSocketListener) listener = g_socket_listener_new ();
  g_autoptr (GInetAddress) address =
      g_inet_address_new_loopback (G_SOCKET_FAMILY_IPV4);
  g_autoptr (GSocketAddress) socket_address =
      g_inet_socket_address_new (address, 0);
  g_autoptr (GSocketAddress) effective_address = NULL;

  g_assert_true (g_socket_listener_add_address (listener, socket_address,
      G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_TCP, NULL, &effective_address,
      &error));
  g_assert_no_error (error);

  guint16 port =
      g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS
            (effective_address));
  g_autofree gchar *daemon_url = g_strdup_printf ("http://127.0.0.1:%u", port);
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    daemon_url,
    "--timeout-ms",
    "1000",
    "status",
    NULL,
  };
  g_autoptr (GCancellable) accept_cancel = g_cancellable_new ();
  SlowHealthzServer server = {.listener = listener, .cancel = accept_cancel };
  GThread *server_thread = g_thread_new ("slow-healthz",
          slow_healthz_server_thread, &server);
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  stop_test_server (server_thread, accept_cancel);

  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (stderr_buf);
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: daemon unavailable:"));
  g_assert_null (g_strstr_len (stderr_buf, -1, "backtrace"));
  g_assert_null (g_strstr_len (stderr_buf, -1, "assertion"));
  g_assert_null (g_strstr_len (stderr_buf, -1, "tracker"));
}

static void
run_status_readiness_case (guint status, const gchar *body,
    const gchar *expected_output, gboolean expect_success,
    const gchar *expected_error)
{
  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_test_server (&listener);
  g_autoptr (GCancellable) accept_cancel = g_cancellable_new ();
  StatusProbeServer server = {
    .listener = listener,
    .cancel = accept_cancel,
    .status = status,
    .body = body,
  };
  GThread *server_thread = g_thread_new ("status-readiness",
          status_probe_server_thread, &server);
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    daemon_url,
    "--timeout-ms",
    "1000",
    "status",
    "--readiness",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  stop_test_server (server_thread, accept_cancel);

  g_assert_cmpint (wait_status_is_success (wait_status), ==, expect_success);
  g_assert_cmpstr (stdout_buf, ==, expected_output);
  if (expected_error == NULL)
    g_assert_cmpstr (stderr_buf, ==, "");
  else
    g_assert_nonnull (g_strstr_len (stderr_buf, -1, expected_error));
  g_assert_nonnull (server.request);
  g_assert_nonnull (g_strstr_len (server.request, -1,
      "GET /readyz?format=json"));

  g_free (server.request);
}

static void
test_status_readiness (void)
{
  run_status_readiness_case (403, "{\"error\":\"status_denied\"}", "",
      FALSE, "status_denied");
  run_status_readiness_case (200, "{\"status\":\"ready\"}", "status=ready\n",
      TRUE, NULL);
  run_status_readiness_case (503,
      "{\"status\":\"not_ready\",\"reason\":\"delta_not_ready\"}",
      "status=not_ready reason=delta_not_ready\n", FALSE, NULL);
  run_status_readiness_case (200, "{\"status\":\"ok\"}", "",
      FALSE, "wyctl: daemon readiness failed");
  run_status_readiness_case (200, "not-json {\"status\":\"ready\"}", "",
      FALSE, "wyctl: daemon readiness failed");
  run_status_readiness_case (503,
      "{\"status\":\"not_ready\",\"reason\":\"unknown\"}", "",
      FALSE, "wyctl: daemon unavailable:");
}

static void
test_status_requires_daemon_url (void)
{
  gchar *argv[] = { WYL_TEST_WYCTL_PATH, "status", NULL };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);

  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (stderr_buf);
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing daemon URL"));
}

static void
test_status_rejects_invalid_daemon_url (void)
{
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "not-a-url",
    "status",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);

  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (stderr_buf);
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: invalid daemon URL"));
}

static void
test_status_help_command_first (void)
{
  gchar *argv[] = { WYL_TEST_WYCTL_PATH, "status", "--help", NULL };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);

  g_assert_true (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--daemon-url"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--readiness"));
  g_assert_cmpstr (stderr_buf, ==, "");
}

static void
test_policy_help (void)
{
  gchar *check_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--help",
    NULL,
  };
  gchar *explain_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "explain",
    "--help",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (check_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_true (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--permission"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1,
      "1: policy check returned deny"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1,
      "4: the daemon denied the request by policy"));
  g_assert_cmpstr (stderr_buf, ==, "");

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (explain_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_true (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--resource"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1,
      "explain may report a valid deny"));
  g_assert_cmpstr (stderr_buf, ==, "");
}

static void
test_audit_help (void)
{
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "audit",
    "query",
    "--help",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_true (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--access-token-file"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-timestamp"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-loc-class"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-risk"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "4: the daemon denied"));
  g_assert_cmpstr (stderr_buf, ==, "");
}

static void
test_service_token_help (void)
{
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "auth",
    "service-token",
    "--help",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);

  g_assert_true (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--credential-file"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1,
      "6: authentication failed or is required"));
  g_assert_cmpstr (stderr_buf, ==, "");
}

static void
test_audit_validation (void)
{
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-audit-token-XXXXXX", &token_path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

  gchar *missing_daemon_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "audit",
    "query",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *invalid_daemon_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "file:///tmp/wyrelog",
    "audit",
    "query",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *missing_timestamp_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "audit",
    "query",
    "--access-token-file",
    token_path,
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *invalid_loc_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "audit",
    "query",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "unknown",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *invalid_risk_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "audit",
    "query",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "101",
    NULL,
  };
  gchar *invalid_limit_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "audit",
    "query",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    "--limit",
    "0",
    NULL,
  };
  gchar *missing_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "audit",
    "query",
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *extra_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "audit",
    "query",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    "extra",
    NULL,
  };
  gchar *valid_scaffold_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "audit",
    "query",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    "--filter",
    "decision=deny",
    "--limit",
    "10",
    NULL,
  };
  gchar *unknown_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "audit",
    "unknown",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (missing_daemon_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing daemon URL"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (invalid_daemon_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: invalid daemon URL"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_timestamp_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: invalid --guard-timestamp"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (invalid_loc_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: invalid --guard-loc-class"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (invalid_risk_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: invalid --guard-risk"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (invalid_limit_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: invalid --limit"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: missing --access-token-file"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (extra_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: unexpected audit query argument"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (valid_scaffold_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: audit query failed"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (unknown_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: unknown audit command"));

  g_unlink (token_path);
}

static void
test_policy_validation (void)
{
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-token-XXXXXX", &token_path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

  g_autofree gchar *empty_token_path = NULL;
  fd = g_file_open_tmp ("wyctl-empty-token-XXXXXX", &empty_token_path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));

  g_autofree gchar *invalid_token_path = NULL;
  fd = g_file_open_tmp ("wyctl-invalid-token-XXXXXX", &invalid_token_path,
          &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (invalid_token_path, "token-1\nbad\n",
      -1, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (invalid_token_path, 0600), ==, 0);

  g_autofree gchar *nul_token_path = NULL;
  fd = g_file_open_tmp ("wyctl-nul-token-XXXXXX", &nul_token_path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  {
    const gchar token_with_nul[] = { 't', 'o', 'k', 'e', 'n', '\0', 'b' };
    g_assert_true (g_file_set_contents (nul_token_path, token_with_nul,
        sizeof token_with_nul, &error));
    g_assert_no_error (error);
    g_assert_cmpint (g_chmod (nul_token_path, 0600), ==, 0);
  }

  g_autofree gchar *leading_token_path = NULL;
  fd = g_file_open_tmp ("wyctl-leading-token-XXXXXX", &leading_token_path,
          &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (leading_token_path, "\ntoken-1\n", -1,
      &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (leading_token_path, 0600), ==, 0);

  g_autofree gchar *trailing_blank_token_path = NULL;
  fd = g_file_open_tmp ("wyctl-trailing-token-XXXXXX",
          &trailing_blank_token_path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (trailing_blank_token_path,
      "token-1\n\n", -1, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (trailing_blank_token_path, 0600), ==, 0);

  g_autofree gchar *space_token_path = NULL;
  fd = g_file_open_tmp ("wyctl-space-token-XXXXXX", &space_token_path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (space_token_path, " token-1\n", -1,
      &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (space_token_path, 0600), ==, 0);

  gchar *missing_resource_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--access-token-file",
    token_path,
    NULL,
  };
  gchar *missing_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    NULL,
  };
  gchar *unreadable_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    "--access-token-file",
    "/nonexistent/wyctl-token",
    NULL,
  };
  gchar *empty_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    "--access-token-file",
    empty_token_path,
    NULL,
  };
  gchar *invalid_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    "--access-token-file",
    invalid_token_path,
    NULL,
  };
  gchar *nul_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    "--access-token-file",
    nul_token_path,
    NULL,
  };
  gchar *leading_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    "--access-token-file",
    leading_token_path,
    NULL,
  };
  gchar *trailing_blank_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    "--access-token-file",
    trailing_blank_token_path,
    NULL,
  };
  gchar *space_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    "--access-token-file",
    space_token_path,
    NULL,
  };
  gchar *valid_scaffold_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    "--access-token-file",
    token_path,
    NULL,
  };
  gchar *unknown_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "unknown",
    NULL,
  };
  gchar *extra_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    "--access-token-file",
    token_path,
    "extra",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (missing_resource_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing --resource"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: missing --access-token-file"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (unreadable_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  /* Updated diagnostic from the typed token-file safety helper. */
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: access token file not found"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (empty_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: empty access token file"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (invalid_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: invalid access token file"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (leading_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: invalid access token file"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (trailing_blank_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: invalid access token file"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (space_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: invalid access token file"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (nul_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: invalid access token file"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (valid_scaffold_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing daemon URL"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (unknown_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: unknown policy command"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (extra_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: unexpected policy check argument"));

  g_unlink (token_path);
  g_unlink (empty_token_path);
  g_unlink (invalid_token_path);
  g_unlink (nul_token_path);
  g_unlink (leading_token_path);
  g_unlink (trailing_blank_token_path);
  g_unlink (space_token_path);
}

typedef struct
{
  GSocketListener *listener;
  GCancellable *cancel;
  const gchar *response_body;
  guint response_status;
  guint delay_us;
  gboolean stall_body;
  const gchar *create_path_before_response;
  gchar *request;
} PolicyCheckServer;

static gpointer
policy_check_server_thread (gpointer data)
{
  PolicyCheckServer *server = data;
  /*
   * The response below is written whether or not a request was captured, so
   * a connection that delivers nothing still lets the child succeed with
   * server->request left NULL -- which is how this raced in CI while every
   * earlier assertion in run_policy_decision_case passed. Keep accepting
   * until one connection actually delivers a request, and accumulate until
   * the header terminator arrives rather than trusting a single read to
   * return the whole thing.
   */
  gchar buffer[4096];
  gsize filled = 0;
  g_autoptr (GSocketConnection) conn = NULL;
  GInputStream *input = NULL;
  GOutputStream *output = NULL;
  while (filled == 0) {
    g_autoptr (GError) error = NULL;
    g_clear_object (&conn);
    conn = g_socket_listener_accept (server->listener, NULL, server->cancel,
            &error);
    if (conn == NULL)
      return NULL;
    input = g_io_stream_get_input_stream (G_IO_STREAM (conn));
    output = g_io_stream_get_output_stream (G_IO_STREAM (conn));
    while (filled < sizeof buffer - 1) {
      gssize n = g_input_stream_read (input, buffer + filled,
              sizeof buffer - 1 - filled, NULL, NULL);
      if (n <= 0)
        break;
      filled += (gsize) n;
      buffer[filled] = '\0';
      if (strstr (buffer, "\r\n\r\n") != NULL)
        break;
    }
  }
  buffer[filled] = '\0';
  server->request = g_strdup (buffer);
  if (server->create_path_before_response != NULL)
    g_assert_true (g_file_set_contents (server->create_path_before_response,
        "existing token", -1, NULL));
  if (server->delay_us > 0 && !server->stall_body)
    g_usleep (server->delay_us);

  guint status = server->response_status != 0 ? server->response_status : 200;
  const gchar *reason = status == 400 ? "Bad Request" :
      status == 401 ? "Unauthorized" : status == 403 ? "Forbidden" :
      status == 302 ? "Found" :
      status == 503 ? "Service Unavailable" : "OK";
  g_autofree gchar *response =
      g_strdup_printf ("HTTP/1.1 %u %s\r\nContent-Type: application/json\r\n"
          "Content-Length: %" G_GSIZE_FORMAT "\r\n\r\n%s",
          status, reason,
          strlen (server->response_body), server->response_body);
  if (server->stall_body) {
    gsize header_len = (gsize) (strstr (response, "\r\n\r\n") + 4 - response);
    (void) g_output_stream_write_all (output, response, header_len, NULL,
        NULL, NULL);
    (void) g_output_stream_flush (output, NULL, NULL);
    g_usleep (server->delay_us);
  } else {
    (void) g_output_stream_write_all (output, response, strlen (response),
        NULL, NULL, NULL);
  }
  (void) g_io_stream_close (G_IO_STREAM (conn), NULL, NULL);
  return NULL;
}

static gchar *
listen_url_for_policy_server (GSocketListener **out_listener)
{
  g_autoptr (GError) error = NULL;
  g_autoptr (GSocketListener) listener = g_socket_listener_new ();
  g_autoptr (GInetAddress) address =
      g_inet_address_new_loopback (G_SOCKET_FAMILY_IPV4);
  g_autoptr (GSocketAddress) socket_address =
      g_inet_socket_address_new (address, 0);
  g_autoptr (GSocketAddress) effective_address = NULL;

  g_assert_true (g_socket_listener_add_address (listener, socket_address,
      G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_TCP, NULL, &effective_address,
      &error));
  g_assert_no_error (error);

  guint16 port =
      g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS
            (effective_address));
  *out_listener = g_steal_pointer (&listener);
  return g_strdup_printf ("http://127.0.0.1:%u", port);
}

static void
run_policy_decision_response_case (const gchar *command, const gchar *response_body,
    guint response_status, const gchar *expected_output,
    gint expected_exit_status, const gchar *expected_stderr, guint delay_us,
    const gchar *timeout_ms, gboolean stall_body)
{
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-policy-token-XXXXXX", &token_path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  g_autoptr (GCancellable) accept_cancel = g_cancellable_new ();
  PolicyCheckServer server = {
    .listener = listener,
    .cancel = accept_cancel,
    .response_body = response_body,
    .response_status = response_status,
    .delay_us = delay_us,
    .stall_body = stall_body,
  };
  GThread *server_thread = g_thread_new ("policy-check",
          policy_check_server_thread, &server);
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    daemon_url,
    "--timeout-ms",
    (gchar *) timeout_ms,
    "policy",
    (gchar *) command,
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    "--access-token-file",
    token_path,
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  stop_test_server (server_thread, accept_cancel);

  g_assert_true (WIFEXITED (wait_status));
  g_assert_cmpint (WEXITSTATUS (wait_status), ==, expected_exit_status);
  g_assert_cmpstr (stdout_buf, ==, expected_output);
  g_assert_cmpstr (stderr_buf, ==, expected_stderr);
  g_assert_nonnull (server.request);
  g_assert_nonnull (g_strstr_len (server.request, -1, "POST /decide?"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "user=alice"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "perm=wr.audit.read"));
  g_assert_nonnull (g_strstr_len (server.request, -1,
      "session_token=doc%2F42"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "tenant=__wr_default"));
  g_assert_nonnull (g_strstr_len (server.request, -1,
      "Authorization: Bearer token-1"));

  g_free (server.request);
  g_unlink (token_path);
}

static void
run_policy_decision_case (const gchar *command, const gchar *response_body,
    guint status, const gchar *out, gint exit_status, const gchar *err,
    guint delay_us, const gchar *timeout_ms)
{
  run_policy_decision_response_case (command, response_body, status, out,
      exit_status, err, delay_us, timeout_ms, FALSE);
}

static void
test_policy_check (void)
{
  run_policy_decision_response_case ("check",
      "{\"decision\":1,\"deny_reason\":null,\"deny_origin\":null}",
      200, "", 5, "wyctl: policy check failed: decision_request_failed\n",
      1500 * 1000, "1000", TRUE);
  run_policy_decision_case
    ("check", "{\"decision\":1,\"deny_reason\":null,\"deny_origin\":null}",
      200, "allow\n", 0, "", 0, "1000");
  run_policy_decision_case ("check",
      "{\"decision\":0,\"deny_reason\":\"missing_grant\","
      "\"deny_origin\":\"policy\"}", 200, "deny\n", 1, "", 0,
      "1000");
  /* This case asserts that the server recorded the request, so the child
   * needs a budget to connect and send on a contended runner: the client's
   * deadline starts before it connects and cancels the whole request, so a
   * 50 ms budget expired mid-connect under load and left nothing to record.
   * Give it the same 1000 ms the success cases assume and make the server
   * the slow side: it records the request first and only then delays past
   * that deadline. */
  run_policy_decision_case ("check",
      "{\"decision\":1,\"deny_reason\":null,\"deny_origin\":null}",
      200, "", 5, "wyctl: policy check failed: decision_request_failed\n",
      1500 * 1000, "1000");
  run_policy_decision_case ("explain",
      "{\"decision\":0,\"deny_reason\":\"missing_grant\","
      "\"deny_origin\":\"policy\"}", 200,
      "deny\nreason=missing_grant\norigin=policy\n", 0, "", 0, "1000");
  run_policy_decision_case ("check", " { \"error\" : \"decide_denied\" } ",
      403, "", 4, "wyctl: policy check failed: decide_denied\n", 0,
      "1000");
  run_policy_decision_case ("check",
      "{\"er\\u0072or\":\"decide_denied\"}", 403, "", 4,
      "wyctl: policy check failed: decision_request_failed\n", 0, "1000");
  run_policy_decision_case ("explain", "{\"error\":\"decide_denied\"}",
      403, "", 4, "wyctl: policy explain failed: decide_denied\n", 0,
      "1000");
  run_policy_decision_case ("check", "{}", 200, "", 3,
      "wyctl: policy check failed: decision_request_failed\n", 0, "1000");
  run_policy_decision_case ("check",
      "{\"details\":{\"error\":\"nested_denial\"},"
      "\"metadata\":[true,7.5,null,{\"source\":\"policy\"}],"
      "\"error\":\"decide_denied\"}", 403, "", 4,
      "wyctl: policy check failed: decision_request_failed\n", 0, "1000");
  run_policy_decision_case ("check",
      "{\"details\":{\"error\":\"nested_denial\"}}", 403, "", 4,
      "wyctl: policy check failed: decision_request_failed\n", 0, "1000");
  run_policy_decision_case ("check",
      "{\"error\":\"decide_denied\",\"error\":\"other_denial\"}",
      403, "", 4,
      "wyctl: policy check failed: decision_request_failed\n", 0, "1000");
  run_policy_decision_case ("check",
      "{\"error\":\"decide_denied\",\"er\\u0072or\":\"other_denial\"}",
      403, "", 4,
      "wyctl: policy check failed: decision_request_failed\n", 0, "1000");
  run_policy_decision_case ("check",
      "{\"metadata\":\"\\uD800\",\"error\":\"decide_denied\"}",
      403, "", 4,
      "wyctl: policy check failed: decision_request_failed\n", 0, "1000");
  run_policy_decision_case ("check",
      "{\"error\"\v:\"decide_denied\"}", 403, "", 4,
      "wyctl: policy check failed: decision_request_failed\n", 0, "1000");
  run_policy_decision_case ("check",
      "{\"metadata\":\"value\"\f,\"error\":\"decide_denied\"}",
      403, "", 4,
      "wyctl: policy check failed: decision_request_failed\n", 0, "1000");
}

static void
test_policy_check_connection_failure (void)
{
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-policy-token-XXXXXX", &token_path,
          &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  g_socket_listener_close (listener);

  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    daemon_url,
    "--timeout-ms",
    "1000",
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    "--access-token-file",
    token_path,
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);

  g_assert_true (WIFEXITED (wait_status));
  g_assert_cmpint (WEXITSTATUS (wait_status), ==, 5);
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_cmpstr (stderr_buf, ==,
      "wyctl: policy check failed: decision_request_failed\n");
  g_unlink (token_path);
}

static void
run_audit_query_case (const gchar *response_body, guint response_status,
    const gchar *expected_output, gint expected_exit_status,
    const gchar *expected_stderr, guint delay_us, const gchar *timeout_ms,
    const gchar *limit)
{
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-audit-token-XXXXXX", &token_path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  g_autoptr (GCancellable) accept_cancel = g_cancellable_new ();
  PolicyCheckServer server = {
    .listener = listener,
    .cancel = accept_cancel,
    .response_body = response_body,
    .response_status = response_status,
    .delay_us = delay_us,
  };
  GThread *server_thread = g_thread_new ("audit-query",
          policy_check_server_thread, &server);
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    daemon_url,
    "--timeout-ms",
    (gchar *) timeout_ms,
    "audit",
    "query",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    "--filter",
    "decision=deny",
    "--limit",
    (gchar *) limit,
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  stop_test_server (server_thread, accept_cancel);

  g_assert_true (WIFEXITED (wait_status));
  g_assert_cmpint (WEXITSTATUS (wait_status), ==, expected_exit_status);
  g_assert_cmpstr (stdout_buf, ==, expected_output);
  g_assert_cmpstr (stderr_buf, ==, expected_stderr);
  g_assert_nonnull (server.request);
  g_assert_nonnull (g_strstr_len (server.request, -1, "GET /audit/events?"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "tenant=__wr_default"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "guard_timestamp=123"));
  g_assert_nonnull (g_strstr_len (server.request, -1,
      "guard_loc_class=public"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "guard_risk=69"));
  g_assert_nonnull (g_strstr_len (server.request, -1,
      "filter=decision%3Ddeny"));
  g_assert_null (g_strstr_len (server.request, -1, "session_token="));
  g_assert_nonnull (g_strstr_len (server.request, -1,
      "Authorization: Bearer token-1"));

  g_free (server.request);
  g_unlink (token_path);
}

static void
test_audit_query (void)
{
  run_audit_query_case
    ("[{\"id\":\"018f3f9b-7f4d-7a2e-8a51-467a0bc7d001\","
      "\"created_at_us\":1234567,"
      "\"subject_id\":\"ali\\nce\","
      "\"action\":\"read\","
      "\"resource_id\":\"doc/42\","
      "\"deny_reason\":null,"
      "\"deny_origin\":null,"
      "\"request_id\":null,"
      "\"decision\":1},"
      "{\"id\":\"018f3f9b-7f4d-7a2e-8a51-467a0bc7d002\","
      "\"created_at_us\":1234568,"
      "\"subject_id\":\"bob\","
      "\"action\":\"write\","
      "\"resource_id\":\"doc/43\","
      "\"deny_reason\":\"missing_grant\","
      "\"deny_origin\":\"policy\","
      "\"request_id\":\"req-audit\","
      "\"decision\":0}]", 200,
      "[{\"id\":\"018f3f9b-7f4d-7a2e-8a51-467a0bc7d001\","
      "\"created_at_us\":1234567,"
      "\"subject_id\":\"ali\\nce\","
      "\"action\":\"read\","
      "\"resource_id\":\"doc/42\","
      "\"deny_reason\":null,"
      "\"deny_origin\":null,"
      "\"request_id\":null," "\"decision\":1}]\n", 0, "", 0,
      "1000", "1");
  run_audit_query_case ("[]", 200, "[]\n", 0, "", 0, "1000", "100");
  /* Same budget rule as the policy-check timeout case: the server records
   * the request, then delays past the client's 1000 ms deadline. */
  run_audit_query_case ("[]", 200, "", 5,
      "wyctl: audit query failed: audit_query_failed\n", 1500 * 1000,
      "1000", "100");
  run_audit_query_case ("{\"error\":\"audit_denied\"}", 403, "", 4,
      "wyctl: audit query failed: audit_denied\n", 0, "1000", "100");
  run_audit_query_case ("{}", 302, "", 5,
      "wyctl: audit query failed: audit_query_failed\n", 0, "1000", "100");
}

typedef struct
{
  GSocketListener *listener;
  GCancellable *cancel;
  guint status;
  const gchar *body;
  gchar *request;
} PolicyMutationServer;

static gpointer
policy_mutation_server_thread (gpointer data)
{
  PolicyMutationServer *server = data;
  g_autoptr (GError) error = NULL;
  g_autoptr (GSocketConnection) conn =
      g_socket_listener_accept (server->listener, NULL, server->cancel, &error);
  if (conn == NULL)
    return NULL;

  gchar buffer[8192];
  GInputStream *input = g_io_stream_get_input_stream (G_IO_STREAM (conn));
  GOutputStream *output = g_io_stream_get_output_stream (G_IO_STREAM (conn));
  /* Read until the headers and the Content-Length body have both arrived:
   * a client may send the body in a separate segment. */
  gsize have = 0;
  while (have < sizeof buffer - 1) {
    gssize n = g_input_stream_read (input, buffer + have,
            sizeof buffer - 1 - have, NULL, NULL);
    if (n <= 0)
      break;
    have += (gsize) n;
    buffer[have] = '\0';
    const gchar *end = strstr (buffer, "\r\n\r\n");
    if (end == NULL)
      continue;
    const gchar *length = g_strstr_len (buffer, end - buffer,
            "Content-Length:");
    if (length == NULL)
      length = g_strstr_len (buffer, end - buffer, "content-length:");
    gsize want = length != NULL
        ? (gsize) g_ascii_strtoull (length + strlen ("Content-Length:"),
            NULL, 10) : 0;
    if (have >= (gsize) (end + 4 - buffer) + want)
      break;
  }
  if (have > 0)
    server->request = g_strndup (buffer, have);

  const gchar *body = server->body != NULL ? server->body : "{}";
  g_autofree gchar *response =
      g_strdup_printf ("HTTP/1.1 %u OK\r\nContent-Type: application/json\r\n"
          "Content-Length: %" G_GSIZE_FORMAT "\r\n\r\n%s",
          server->status, strlen (body), body);
  (void) g_output_stream_write (output, response, strlen (response), NULL,
      NULL);
  (void) g_io_stream_close (G_IO_STREAM (conn), NULL, NULL);
  return NULL;
}

static void
test_policy_permission_help (void)
{
  gchar *grant_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "permission-grant",
    "--help",
    NULL,
  };
  gchar *revoke_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "permission-revoke",
    "--help",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (grant_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_true (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--subject"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--perm"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--scope"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--access-token-file"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-timestamp"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-loc-class"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-risk"));
  g_assert_null (g_strstr_len (stdout_buf, -1, "--tenant"));
  g_assert_null (g_strstr_len (stdout_buf, -1, "--access-token "));
  g_assert_cmpstr (stderr_buf, ==, "");

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (revoke_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_true (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--subject"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--perm"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--scope"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--access-token-file"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-timestamp"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-loc-class"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-risk"));
  g_assert_null (g_strstr_len (stdout_buf, -1, "--tenant"));
  g_assert_null (g_strstr_len (stdout_buf, -1, "--access-token "));
  g_assert_cmpstr (stderr_buf, ==, "");
}

static void
run_policy_permission_success_case (const gchar *command, const gchar *path)
{
  gboolean transition = g_strcmp0 (command, "permission-transition") == 0;
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-policy-perm-token-XXXXXX", &token_path,
          &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  g_autoptr (GCancellable) accept_cancel = g_cancellable_new ();
  PolicyMutationServer server = {
    .listener = listener,
    .cancel = accept_cancel,
    .status = 200,
    .body = "{}",
  };
  GThread *server_thread = g_thread_new ("policy-mutation",
          policy_mutation_server_thread, &server);
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    daemon_url,
    "--timeout-ms",
    "1000",
    "policy",
    (gchar *) command,
    "--subject",
    "alice",
    "--perm",
    "wr.audit.read",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    transition ? "--event" : NULL,
    transition ? "grant" : NULL,
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  stop_test_server (server_thread, accept_cancel);

  g_assert_true (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "ok\n");
  g_assert_cmpstr (stderr_buf, ==, "");
  g_assert_nonnull (server.request);
  g_autofree gchar *expected_request_line = g_strdup_printf ("POST %s?", path);
  g_assert_nonnull (g_strstr_len (server.request, -1, expected_request_line));
  g_assert_nonnull (g_strstr_len (server.request, -1, "subject=alice"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "perm=wr.audit.read"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "scope=tenant%2Fa"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "tenant=__wr_default"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "guard_timestamp=123"));
  g_assert_nonnull (g_strstr_len (server.request, -1,
      "guard_loc_class=public"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "guard_risk=69"));
  if (transition)
    g_assert_nonnull (g_strstr_len (server.request, -1, "event=grant"));
  else
    g_assert_null (g_strstr_len (server.request, -1, "event="));
  g_assert_null (g_strstr_len (server.request, -1, "session_token="));
  g_assert_nonnull (g_strstr_len (server.request, -1,
      "Authorization: Bearer token-1"));

  g_free (server.request);
  g_unlink (token_path);
}

static void
test_policy_permission_grant_success (void)
{
  run_policy_permission_success_case ("permission-grant",
      "/policy/permissions/grant");
}

static void
test_policy_permission_revoke_success (void)
{
  run_policy_permission_success_case ("permission-revoke",
      "/policy/permissions/revoke");
}

static void
run_policy_permission_status_case (const gchar *command, guint status,
    gint expected_exit, const gchar *expected_stderr_marker)
{
  gboolean transition = g_strcmp0 (command, "permission-transition") == 0;
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-policy-perm-token-XXXXXX", &token_path,
          &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  g_autoptr (GCancellable) accept_cancel = g_cancellable_new ();
  PolicyMutationServer server = {
    .listener = listener,
    .cancel = accept_cancel,
    .status = status,
    .body = "{}",
  };
  GThread *server_thread = g_thread_new ("policy-mutation",
          policy_mutation_server_thread, &server);
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    daemon_url,
    "--timeout-ms",
    "1000",
    "policy",
    (gchar *) command,
    "--subject",
    "alice",
    "--perm",
    "wr.audit.read",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    transition ? "--event" : NULL,
    transition ? "grant" : NULL,
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  stop_test_server (server_thread, accept_cancel);

  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpint (WEXITSTATUS (wait_status), ==, expected_exit);
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, expected_stderr_marker));

  g_free (server.request);
  g_unlink (token_path);
}

static void
test_policy_permission_grant_status_errors (void)
{
  run_policy_permission_status_case ("permission-grant", 400, 3,
      "wyctl: policy permission-grant failed: invalid_policy_mutation");
  run_policy_permission_status_case ("permission-grant", 401, 6,
      "wyctl: policy permission-grant failed: policy_auth_required");
  run_policy_permission_status_case ("permission-grant", 403, 4,
      "wyctl: policy permission-grant failed: policy_mutation_denied");
  run_policy_permission_status_case ("permission-grant", 500, 5,
      "wyctl: policy permission-grant failed: policy_mutation_failed");
}

static void
test_policy_permission_revoke_status_errors (void)
{
  run_policy_permission_status_case ("permission-revoke", 400, 3,
      "wyctl: policy permission-revoke failed: invalid_policy_mutation");
  run_policy_permission_status_case ("permission-revoke", 401, 6,
      "wyctl: policy permission-revoke failed: policy_auth_required");
  run_policy_permission_status_case ("permission-revoke", 403, 4,
      "wyctl: policy permission-revoke failed: policy_mutation_denied");
  run_policy_permission_status_case ("permission-revoke", 500, 5,
      "wyctl: policy permission-revoke failed: policy_mutation_failed");
}

static void
test_policy_permission_transition_success (void)
{
  run_policy_permission_success_case ("permission-transition",
      "/policy/permissions/transition");
}

static void
test_policy_permission_transition_status_errors (void)
{
  run_policy_permission_status_case ("permission-transition", 400, 3,
      "wyctl: policy permission-transition failed: invalid_policy_mutation");
  run_policy_permission_status_case ("permission-transition", 401, 6,
      "wyctl: policy permission-transition failed: policy_auth_required");
  run_policy_permission_status_case ("permission-transition", 403, 4,
      "wyctl: policy permission-transition failed: policy_mutation_denied");
  run_policy_permission_status_case ("permission-transition", 500, 5,
      "wyctl: policy permission-transition failed: policy_mutation_failed");
}

/*
 * #1237: a grant alone leaves the permission dormant, so the grant help says
 * how to arm it, and only the transition command takes an --event.
 */
static void
test_policy_permission_transition_help (void)
{
  gchar *transition_argv[] = {
    WYL_TEST_WYCTL_PATH, "policy", "permission-transition", "--help", NULL,
  };
  gchar *grant_argv[] = {
    WYL_TEST_WYCTL_PATH, "policy", "permission-grant", "--help", NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (transition_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_true (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--subject"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--perm"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--scope"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--event=EVENT"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-risk"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (grant_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_true (wait_status_is_success (wait_status));
  /* The description names the transition command; the grant takes no
   * --event option of its own. */
  g_assert_null (g_strstr_len (stdout_buf, -1, "--event=EVENT"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1,
      "wyctl policy permission-transition"));
}

static void
test_policy_permission_transition_validation (void)
{
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-policy-perm-token-XXXXXX", &token_path,
          &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

  gchar *missing_event_argv[] = {
    WYL_TEST_WYCTL_PATH, "--daemon-url", "http://127.0.0.1:1", "policy",
    "permission-transition", "--subject", "alice", "--perm", "wr.audit.read",
    "--scope", "tenant/a", "--access-token-file", token_path,
    "--guard-timestamp", "123", "--guard-loc-class", "public",
    "--guard-risk", "69", NULL,
  };
  gchar *grant_with_event_argv[] = {
    WYL_TEST_WYCTL_PATH, "--daemon-url", "http://127.0.0.1:1", "policy",
    "permission-grant", "--subject", "alice", "--perm", "wr.audit.read",
    "--scope", "tenant/a", "--access-token-file", token_path,
    "--guard-timestamp", "123", "--guard-loc-class", "public",
    "--guard-risk", "69", "--event", "grant", NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (missing_event_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpint (WEXITSTATUS (wait_status), ==, 2);
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing --event"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (grant_with_event_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpint (WEXITSTATUS (wait_status), ==, 2);
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "--event"));
  g_unlink (token_path);
}

static void
test_policy_permission_validation (void)
{
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-policy-perm-token-XXXXXX", &token_path,
          &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

  gchar *missing_subject_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "permission-grant",
    "--perm",
    "wr.audit.read",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *missing_perm_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "permission-grant",
    "--subject",
    "alice",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *missing_scope_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "permission-grant",
    "--subject",
    "alice",
    "--perm",
    "wr.audit.read",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *missing_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "permission-grant",
    "--subject",
    "alice",
    "--perm",
    "wr.audit.read",
    "--scope",
    "tenant/a",
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *missing_timestamp_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "permission-grant",
    "--subject",
    "alice",
    "--perm",
    "wr.audit.read",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *invalid_loc_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "permission-grant",
    "--subject",
    "alice",
    "--perm",
    "wr.audit.read",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "unknown",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *invalid_risk_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "permission-grant",
    "--subject",
    "alice",
    "--perm",
    "wr.audit.read",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "101",
    NULL,
  };
  gchar *missing_daemon_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "permission-grant",
    "--subject",
    "alice",
    "--perm",
    "wr.audit.read",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (missing_subject_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing --subject"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_perm_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing --perm"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_scope_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing --scope"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: missing --access-token-file"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_timestamp_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: invalid --guard-timestamp"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (invalid_loc_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: invalid --guard-loc-class"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (invalid_risk_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: invalid --guard-risk"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_daemon_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing daemon URL"));

  g_unlink (token_path);
}

static void
test_policy_role_help (void)
{
  gchar *grant_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "role-grant",
    "--help",
    NULL,
  };
  gchar *revoke_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "role-revoke",
    "--help",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (grant_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_true (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--subject"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--role"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--scope"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--access-token-file"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-timestamp"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-loc-class"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-risk"));
  g_assert_null (g_strstr_len (stdout_buf, -1, "--tenant"));
  g_assert_null (g_strstr_len (stdout_buf, -1, "--access-token "));
  g_assert_null (g_strstr_len (stdout_buf, -1, "--perm"));
  g_assert_cmpstr (stderr_buf, ==, "");

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (revoke_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_true (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--subject"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--role"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--scope"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--access-token-file"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-timestamp"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-loc-class"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-risk"));
  g_assert_null (g_strstr_len (stdout_buf, -1, "--tenant"));
  g_assert_null (g_strstr_len (stdout_buf, -1, "--access-token "));
  g_assert_null (g_strstr_len (stdout_buf, -1, "--perm"));
  g_assert_cmpstr (stderr_buf, ==, "");
}

static void
run_policy_role_success_case (const gchar *command, const gchar *path)
{
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-policy-role-token-XXXXXX", &token_path,
          &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  g_autoptr (GCancellable) accept_cancel = g_cancellable_new ();
  PolicyMutationServer server = {
    .listener = listener,
    .cancel = accept_cancel,
    .status = 200,
    .body = "{}",
  };
  GThread *server_thread = g_thread_new ("policy-mutation",
          policy_mutation_server_thread, &server);
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    daemon_url,
    "--timeout-ms",
    "1000",
    "policy",
    (gchar *) command,
    "--subject",
    "alice",
    "--role",
    "wr.audit.reader",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  stop_test_server (server_thread, accept_cancel);

  g_assert_true (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "ok\n");
  g_assert_cmpstr (stderr_buf, ==, "");
  g_assert_nonnull (server.request);
  g_autofree gchar *expected_request_line = g_strdup_printf ("POST %s?", path);
  g_assert_nonnull (g_strstr_len (server.request, -1, expected_request_line));
  g_assert_nonnull (g_strstr_len (server.request, -1, "subject=alice"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "role=wr.audit.reader"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "scope=tenant%2Fa"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "tenant=__wr_default"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "guard_timestamp=123"));
  g_assert_nonnull (g_strstr_len (server.request, -1,
      "guard_loc_class=public"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "guard_risk=69"));
  g_assert_null (g_strstr_len (server.request, -1, "session_token="));
  g_assert_nonnull (g_strstr_len (server.request, -1,
      "Authorization: Bearer token-1"));

  g_free (server.request);
  g_unlink (token_path);
}

static void
test_policy_role_grant_success (void)
{
  run_policy_role_success_case ("role-grant", "/policy/roles/grant");
}

static void
test_policy_role_revoke_success (void)
{
  run_policy_role_success_case ("role-revoke", "/policy/roles/revoke");
}

static void
run_policy_role_status_case (const gchar *command, guint status,
    gint expected_exit, const gchar *expected_stderr_marker)
{
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-policy-role-token-XXXXXX", &token_path,
          &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  g_autoptr (GCancellable) accept_cancel = g_cancellable_new ();
  PolicyMutationServer server = {
    .listener = listener,
    .cancel = accept_cancel,
    .status = status,
    .body = "{}",
  };
  GThread *server_thread = g_thread_new ("policy-mutation",
          policy_mutation_server_thread, &server);
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    daemon_url,
    "--timeout-ms",
    "1000",
    "policy",
    (gchar *) command,
    "--subject",
    "alice",
    "--role",
    "wr.audit.reader",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  stop_test_server (server_thread, accept_cancel);

  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpint (WEXITSTATUS (wait_status), ==, expected_exit);
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, expected_stderr_marker));

  g_free (server.request);
  g_unlink (token_path);
}

static void
test_policy_role_grant_status_errors (void)
{
  run_policy_role_status_case ("role-grant", 400, 3,
      "wyctl: policy role-grant failed: invalid_policy_mutation");
  run_policy_role_status_case ("role-grant", 401, 6,
      "wyctl: policy role-grant failed: policy_auth_required");
  run_policy_role_status_case ("role-grant", 403, 4,
      "wyctl: policy role-grant failed: policy_mutation_denied");
  run_policy_role_status_case ("role-grant", 500, 5,
      "wyctl: policy role-grant failed: policy_mutation_failed");
}

static void
test_policy_role_revoke_status_errors (void)
{
  run_policy_role_status_case ("role-revoke", 400, 3,
      "wyctl: policy role-revoke failed: invalid_policy_mutation");
  run_policy_role_status_case ("role-revoke", 401, 6,
      "wyctl: policy role-revoke failed: policy_auth_required");
  run_policy_role_status_case ("role-revoke", 403, 4,
      "wyctl: policy role-revoke failed: policy_mutation_denied");
  run_policy_role_status_case ("role-revoke", 500, 5,
      "wyctl: policy role-revoke failed: policy_mutation_failed");
}

static void
test_policy_role_validation (void)
{
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-policy-role-token-XXXXXX", &token_path,
          &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

  gchar *missing_subject_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "role-grant",
    "--role",
    "wr.audit.reader",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *missing_role_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "role-grant",
    "--subject",
    "alice",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *missing_scope_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "role-grant",
    "--subject",
    "alice",
    "--role",
    "wr.audit.reader",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *missing_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "role-grant",
    "--subject",
    "alice",
    "--role",
    "wr.audit.reader",
    "--scope",
    "tenant/a",
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *missing_timestamp_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "role-grant",
    "--subject",
    "alice",
    "--role",
    "wr.audit.reader",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *invalid_loc_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "role-grant",
    "--subject",
    "alice",
    "--role",
    "wr.audit.reader",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "unknown",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *invalid_risk_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "role-grant",
    "--subject",
    "alice",
    "--role",
    "wr.audit.reader",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "101",
    NULL,
  };
  gchar *missing_daemon_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "role-grant",
    "--subject",
    "alice",
    "--role",
    "wr.audit.reader",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (missing_subject_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing --subject"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_role_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing --role"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_scope_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing --scope"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: missing --access-token-file"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_timestamp_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: invalid --guard-timestamp"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (invalid_loc_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: invalid --guard-loc-class"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (invalid_risk_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: invalid --guard-risk"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_daemon_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing daemon URL"));

  g_unlink (token_path);
}

static void
test_status_gsettings_supplies_daemon_url (void)
{
  /* When --daemon-url is omitted the resolver must read the URL from
   * GSettings and the daemon-unavailable diagnostic must reference
   * that URL (proving the resolver fed the probe). */
  g_autofree gchar *literal =
      gvariant_literal_for_string ("http://127.0.0.1:1");
  const gchar *keys[] = { "daemon-url", NULL };
  const gchar *values[] = { literal, NULL };
  g_autofree gchar *xdg = make_keyfile_xdg_dir (keys, values);
  g_auto (GStrv) envp = build_gsettings_envp (xdg, FALSE);

  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "status",
    "--timeout-ms",
    "100",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;
  run_child_with_env (argv, envp, &stdout_buf, &stderr_buf, &wait_status);
  remove_dir_recursive (xdg);

  g_assert_false (wait_status_is_success (wait_status));
  assert_child_stderr_has (stderr_buf,
      "wyctl: daemon unavailable: http://127.0.0.1:1");
  g_assert_null (g_strstr_len (stderr_buf, -1, "wyctl: missing daemon URL"));
}

/* The URL the two cases below put in the keyfile.  Loopback, so no name
 * resolution is involved; port 2 refuses at once, exactly as port 1 does for
 * the case above, which this suite has always depended on.  The path is
 * carried through verbatim by the daemon-unavailable diagnostic, which is
 * what makes the needle legible rather than a one-character difference from
 * the CLI URL. */
#define WYCTL_TEST_GSETTINGS_URL "http://127.0.0.1:2/from-gsettings"

/* Run `wyctl status' once against a keyfile holding
 * WYCTL_TEST_GSETTINGS_URL, with `extra_argv' spliced in after the
 * subcommand name, and hand back the child's stderr.  The fixture is torn
 * down before the caller asserts anything. */
static gchar *
run_status_against_gsettings_url (const gchar *const *extra_argv,
    gsize extra_argv_len, gboolean disable_gsettings, gint *wait_status)
{
  g_autofree gchar *literal =
      gvariant_literal_for_string (WYCTL_TEST_GSETTINGS_URL);
  const gchar *keys[] = { "daemon-url", NULL };
  const gchar *values[] = { literal, NULL };
  g_autofree gchar *xdg = make_keyfile_xdg_dir (keys, values);
  g_auto (GStrv) envp = build_gsettings_envp (xdg, disable_gsettings);

  GPtrArray *argv = g_ptr_array_new ();
  g_ptr_array_add (argv, WYL_TEST_WYCTL_PATH);
  g_ptr_array_add (argv, "status");
  for (gsize i = 0; i < extra_argv_len; i++)
    g_ptr_array_add (argv, (gpointer) extra_argv[i]);
  g_ptr_array_add (argv, "--timeout-ms");
  g_ptr_array_add (argv, "100");
  g_ptr_array_add (argv, NULL);

  g_autofree gchar *stdout_buf = NULL;
  gchar *stderr_buf = NULL;
  run_child_with_env ((gchar **) argv->pdata, envp, &stdout_buf, &stderr_buf,
      wait_status);
  g_ptr_array_free (argv, TRUE);
  remove_dir_recursive (xdg);
  return stderr_buf;
}

static void
test_status_cli_overrides_gsettings (void)
{
  /* GSettings carries a URL we want to be ignored; the CLI value must win
   * and the diagnostic must mention the CLI URL.
   *
   * The control spawn is what makes that mean anything.  Asserting only
   * that the CLI URL appears and the GSettings one does not is satisfied
   * just as well by a keyfile nothing ever read, so the case used to pass
   * with the GSettings fallback deleted (#1189).  The control proves a
   * child of this test can read a keyfile built this way; the override
   * spawn then shows the CLI value displacing a value that was
   * demonstrably available.  Each spawn mints its own fixture directory
   * from the same keys, so what they share is the construction, not the
   * directory. */
  const gchar *override_argv[] = { "--daemon-url", "http://127.0.0.1:1" };
  gint control_status = 0;
  gint override_status = 0;

  g_autofree gchar *control_stderr =
      run_status_against_gsettings_url (NULL, 0, FALSE, &control_status);
  g_autofree gchar *override_stderr =
      run_status_against_gsettings_url (override_argv,
          G_N_ELEMENTS (override_argv), FALSE, &override_status);

  g_assert_false (wait_status_is_success (control_status));
  assert_child_stderr_has (control_stderr,
      "wyctl: daemon unavailable: " WYCTL_TEST_GSETTINGS_URL);

  g_assert_false (wait_status_is_success (override_status));
  assert_child_stderr_has (override_stderr,
      "wyctl: daemon unavailable: http://127.0.0.1:1");
  g_assert_null (g_strstr_len (override_stderr, -1, "from-gsettings"));
}

/* Build a temporary access-token file with the supplied contents and
* mode bits, returning the path. The caller g_unlinks and g_frees. */
static gchar *
write_token_with_mode (const gchar *contents, mode_t mode)
{
  g_autoptr (GError) error = NULL;
  gchar *path = NULL;
  gint fd = g_file_open_tmp ("wyctl-broad-token-XXXXXX", &path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  if (contents != NULL && contents[0] != '\0') {
    gsize len = strlen (contents);
    gsize wrote = 0;
    while (wrote < len) {
      ssize_t n = write (fd, contents + wrote, len - wrote);
      g_assert_cmpint (n, >=, 0);
      wrote += (gsize) n;
    }
  }
  g_assert_true (g_close (fd, NULL));
  g_assert_cmpint (g_chmod (path, mode), ==, 0);
  return path;
}

/* One spawn for the helper below: write a keyfile fixture holding
 * `daemon_url', run the subcommand against it with no --daemon-url on the
 * command line, tear the fixture down, and hand back the child's stderr.
 *
 * The global flags lead the argv.  wyctl rejects --timeout-ms after a
 * subcommand name, which is what used to kill these children at option
 * parsing before any resolution (#1189).  --access-token-file is a
 * per-subcommand option, so it is appended instead; note that it is itself
 * a GSettings-resolved key, so a fixture that ever sets it would quietly
 * change what these cases cover. */
static gchar *
run_subcommand_against_gsettings_daemon_url (gchar **subcommand_argv,
    gsize subcommand_argv_len, const gchar *token_path,
    const gchar *daemon_url, gint *wait_status)
{
  g_autofree gchar *literal = gvariant_literal_for_string (daemon_url);
  const gchar *keys[] = { "daemon-url", NULL };
  const gchar *values[] = { literal, NULL };
  g_autofree gchar *xdg = make_keyfile_xdg_dir (keys, values);
  g_auto (GStrv) envp = build_gsettings_envp (xdg, FALSE);

  GPtrArray *argv = g_ptr_array_new ();
  g_ptr_array_add (argv, WYL_TEST_WYCTL_PATH);
  g_ptr_array_add (argv, "--timeout-ms");
  g_ptr_array_add (argv, "100");
  for (gsize i = 0; i < subcommand_argv_len; i++)
    g_ptr_array_add (argv, subcommand_argv[i]);
  g_ptr_array_add (argv, "--access-token-file");
  g_ptr_array_add (argv, (gpointer) token_path);
  g_ptr_array_add (argv, NULL);

  g_autofree gchar *stdout_buf = NULL;
  gchar *stderr_buf = NULL;
  run_child_with_env ((gchar **) argv->pdata, envp, &stdout_buf, &stderr_buf,
      wait_status);
  g_ptr_array_free (argv, TRUE);
  remove_dir_recursive (xdg);
  return stderr_buf;
}

/* Drive a wyctl subcommand against a GSettings keyfile that supplies the
 * daemon URL, and prove the keyfile is what supplied it.
 *
 * Two spawns against two fixtures, because neither alone survives deleting
 * the GSettings fallback (#1189):
 *
 *   - an invalid URL in the keyfile must produce "invalid daemon URL".
 *     Nothing else in the child's environment can put an invalid URL in
 *     front of validation: there is no --daemon-url on the command line,
 *     the resolver reads the CLI value and GSettings and nothing else, and
 *     the schema default is the empty string, which yields "missing daemon
 *     URL" instead.  So this is the positive, fixture-only proof that the
 *     keyfile value was read.
 *   - a syntactically valid URL must carry the child past validation and
 *     on to its own operation-failed diagnostic, proving the resolved value
 *     cleared the URL-validation gate.
 *
 * That second spawn proves nothing beyond the gate, which is why its
 * argument is named for the diagnostic rather than for a transport.  The
 * URL it supplies is unreachable, but arriving there is not what is being
 * tested, and a shared helper could not test it: `fact put' with an empty
 * input fails locally and never opens a connection at all, and `datalog
 * query' pointed at a listener that answers succeeds, which the shared
 * exit-status assertion below forbids.  The claim that the resolved URL
 * was the request's target is made once, by
 * /wyctl/policy-check-gsettings-daemon-url-is-the-transport-target, where a
 * listener can witness it.
 *
 * Both fixtures are torn down before anything is asserted, and the token
 * file with them, so a failing run leaves nothing behind under TMPDIR. */
static void
assert_subcommand_consumes_gsettings_daemon_url (gchar **subcommand_argv,
    gsize subcommand_argv_len, const gchar *post_validation_diagnostic)
{
  g_autofree gchar *token_path = write_token_with_mode ("token-1", 0600);
  gint invalid_status = 0;
  gint resolved_status = 0;

  g_autofree gchar *invalid_stderr =
      run_subcommand_against_gsettings_daemon_url (subcommand_argv,
          subcommand_argv_len, token_path, "not a url", &invalid_status);
  g_autofree gchar *resolved_stderr =
      run_subcommand_against_gsettings_daemon_url (subcommand_argv,
          subcommand_argv_len, token_path, "http://127.0.0.1:1",
          &resolved_status);
  g_unlink (token_path);

  g_assert_false (wait_status_is_success (invalid_status));
  assert_child_stderr_has (invalid_stderr, "wyctl: invalid daemon URL");

  g_assert_false (wait_status_is_success (resolved_status));
  assert_child_stderr_has (resolved_stderr, post_validation_diagnostic);
  g_assert_null (g_strstr_len (resolved_stderr, -1,
      "wyctl: missing daemon URL"));
  g_assert_null (g_strstr_len (resolved_stderr, -1,
      "wyctl: invalid daemon URL"));
}

static void
test_policy_check_gsettings_supplies_daemon_url (void)
{
  gchar *subcommand[] = {
    "policy", "check",
    "--user", "alice",
    "--permission", "read",
    "--resource", "doc/1",
  };
  assert_subcommand_consumes_gsettings_daemon_url (subcommand,
      G_N_ELEMENTS (subcommand),
      "wyctl: policy check failed");
}

static void
test_audit_query_gsettings_supplies_daemon_url (void)
{
  gchar *subcommand[] = {
    "audit", "query",
    "--limit", "1",
    "--guard-timestamp", "0",
    "--guard-loc-class", "trusted",
    "--guard-risk", "0",
  };
  assert_subcommand_consumes_gsettings_daemon_url (subcommand,
      G_N_ELEMENTS (subcommand),
      "wyctl: audit query failed");
}

static void
test_fact_put_gsettings_supplies_daemon_url (void)
{
  gchar *subcommand[] = {
    "fact", "put",
    "--tenant", "t",
    "--graph", "g",
    "--namespace", "ns",
    "--relation", "r",
    "--schema-version", "1",
    "--batch-id", "b",
    "--idempotency-key", "k",
    "--format", "csv",
    "--input", "/dev/null",
    "--guard-timestamp", "0",
    "--guard-loc-class", "trusted",
    "--guard-risk", "0",
  };
  assert_subcommand_consumes_gsettings_daemon_url (subcommand,
      G_N_ELEMENTS (subcommand),
      "wyctl: fact put failed");
}

/* When the access-token file is unsafe, the safety check MUST fire
* before any HTTP request. Witness: the subcommand's own "<op>
* failed" diagnostic must be absent, because reaching it requires
* a successful wyl_client_new + daemon probe. The
* permissions-too-broad diagnostic must be present in its place. */
static void
test_policy_check_safety_reject_prevents_http (void)
{
  g_autofree gchar *broad_token = write_token_with_mode ("token-1", 0640);

  /* --daemon-url and --timeout-ms are global flags and must come
   * before the subcommand name, per wyctl's CLI grammar. */
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "--timeout-ms", "100",
    "policy", "check",
    "--user", "alice",
    "--permission", "wr.audit.read",
    "--resource", "doc/42",
    "--access-token-file", broad_token,
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;
  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  g_unlink (broad_token);

  g_assert_false (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: access token file permissions too broad"));
  g_assert_null (g_strstr_len (stderr_buf, -1, "wyctl: policy check failed"));
}

static void
test_audit_query_safety_reject_prevents_http (void)
{
  g_autofree gchar *broad_token = write_token_with_mode ("token-1", 0644);

  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "--timeout-ms", "100",
    "audit", "query",
    "--limit", "1",
    "--access-token-file", broad_token,
    "--guard-timestamp", "0",
    "--guard-loc-class", "trusted",
    "--guard-risk", "0",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;
  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  g_unlink (broad_token);

  g_assert_false (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: access token file permissions too broad"));
  g_assert_null (g_strstr_len (stderr_buf, -1, "wyctl: audit query failed"));
}

static void
test_datalog_query_gsettings_supplies_daemon_url (void)
{
  gchar *subcommand[] = {
    "datalog", "query",
    "--tenant", "t",
    "--graph", "g",
    "--query", "rel()",
    "--limit", "1",
    "--guard-timestamp", "0",
    "--guard-loc-class", "trusted",
    "--guard-risk", "0",
  };
  assert_subcommand_consumes_gsettings_daemon_url (subcommand,
      G_N_ELEMENTS (subcommand),
      "wyctl: datalog query failed");
}

/* The four cases above prove the keyfile supplied the URL and that the
 * resolved value cleared validation.  Neither proves the URL was where the
 * request actually went.  Prove that once, here, by putting a real
 * listener's address in the keyfile and asserting the listener saw the
 * request.  It is done for policy check alone on purpose: `fact put' with
 * an empty input never opens a connection, and `datalog query' succeeds
 * against a canned 200, so a listener in the shared helper above would need
 * a response body and an exit-status rule per subcommand.
 *
 * The response body is a placeholder chosen so the decision parse fails,
 * which is what keeps the child's exit status non-zero;
 * policy_check_server_thread dereferences response_body unconditionally, so
 * it cannot be left out.  The 1000 ms budget is inherited from the
 * recorded-request case above, whose comment records a 50 ms budget
 * expiring mid-connect under load with nothing left to record.  It is a
 * ceiling rather than a cost: delay_us is zero, so the server answers at
 * once. */
static void
test_policy_check_gsettings_daemon_url_is_the_transport_target (void)
{
  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  g_autoptr (GCancellable) accept_cancel = g_cancellable_new ();
  PolicyCheckServer server = {
    .listener = listener,
    .cancel = accept_cancel,
    .response_body = "{}",
    .delay_us = 0,
  };
  GThread *server_thread = g_thread_new ("policy-check-gsettings",
          policy_check_server_thread, &server);

  g_autofree gchar *literal = gvariant_literal_for_string (daemon_url);
  const gchar *keys[] = { "daemon-url", NULL };
  const gchar *values[] = { literal, NULL };
  g_autofree gchar *xdg = make_keyfile_xdg_dir (keys, values);
  g_auto (GStrv) envp = build_gsettings_envp (xdg, FALSE);
  g_autofree gchar *token_path = write_token_with_mode ("token-1", 0600);

  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--timeout-ms", "1000",
    "policy", "check",
    "--user", "alice",
    "--permission", "read",
    "--resource", "doc/1",
    "--access-token-file", token_path,
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;
  run_child_with_env (argv, envp, &stdout_buf, &stderr_buf, &wait_status);
  stop_test_server (server_thread, accept_cancel);
  remove_dir_recursive (xdg);
  g_unlink (token_path);
  g_autofree gchar *request = server.request;

  /* Name the child's own diagnostic before asserting on the recording.
   * No sibling ever sees a reply; this one completes a round trip and
   * parses the answer, so a red here can have a cause that has nothing to
   * do with the resolver.  A bare "request != NULL" would print none of
   * it. */
  g_assert_false (wait_status_is_success (wait_status));
  assert_child_stderr_has (stderr_buf, "wyctl: policy check failed");
  g_assert_nonnull (request);
  g_assert_nonnull (g_strstr_len (request, -1, "POST /decide?"));
}

static void
test_status_kill_switch_disables_gsettings (void)
{
  /* GSettings carries a URL but WYCTL_DISABLE_GSETTINGS=1 must keep wyctl
   * from consulting it; with no CLI URL the existing missing-daemon-URL
   * diagnostic must fire.
   *
   * Breaking the kill switch has always reddened this case.  What it could
   * not tell apart was a suppressed fixture from one the child could never
   * have read, since both end in "missing daemon URL" (#1189).  The control
   * spawn settles that: a fixture built from the same keys, read by the
   * same binary, with the switch off. */
  gint control_status = 0;
  gint suppressed_status = 0;

  g_autofree gchar *control_stderr =
      run_status_against_gsettings_url (NULL, 0, FALSE, &control_status);
  g_autofree gchar *suppressed_stderr =
      run_status_against_gsettings_url (NULL, 0, TRUE, &suppressed_status);

  g_assert_false (wait_status_is_success (control_status));
  assert_child_stderr_has (control_stderr,
      "wyctl: daemon unavailable: " WYCTL_TEST_GSETTINGS_URL);

  g_assert_false (wait_status_is_success (suppressed_status));
  assert_child_stderr_has (suppressed_stderr, "wyctl: missing daemon URL");
  g_assert_null (g_strstr_len (suppressed_stderr, -1, "daemon unavailable:"));
}

static void
test_service_token_preflight_and_malformed_input (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *credential_path = NULL;
  gint fd = g_file_open_tmp ("wyctl-service-credential-XXXXXX",
          &credential_path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (credential_path,
      "credential-secret-canary", -1, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (credential_path, 0600), ==, 0);
  g_autofree gchar *output_path = g_build_filename (g_get_tmp_dir (),
          "wyctl-service-token-no-output", NULL);
  g_unlink (output_path);
  gchar *non_loopback_argv[] = {
    WYL_TEST_WYCTL_PATH, "--daemon-url", "http://example.invalid",
    "auth", "service-token", "--credential-file", credential_path,
    "--token-output", output_path, NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;
  run_child (non_loopback_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: invalid daemon URL"));
  g_assert_null (g_strstr_len (stderr_buf, -1, "credential-secret-canary"));
  g_assert_false (g_file_test (output_path, G_FILE_TEST_EXISTS));

  gchar *malformed_argv[] = {
    WYL_TEST_WYCTL_PATH, "--daemon-url", "http://127.0.0.1:1",
    "auth", "service-token", "--credential-file", credential_path,
    "--token-output", output_path, NULL,
  };
  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (malformed_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: invalid service credential file"));
  g_assert_null (g_strstr_len (stderr_buf, -1, "credential-secret-canary"));
  g_assert_false (g_file_test (output_path, G_FILE_TEST_EXISTS));
  g_unlink (credential_path);
}

static void
run_service_token_response_case (guint response_status,
    const gchar *response_body, gint expected_exit_status,
    const gchar *expected_error)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyctl-service-token-remote-XXXXXX",
          &error);
  g_assert_no_error (error);
  g_autofree gchar *credential_path = g_build_filename (dir,
          "credential.json", NULL);
  g_autofree gchar *output_path = g_build_filename (dir, "access.token",
          NULL);
  const gchar *credential_secret =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  g_autofree gchar *credential_doc = g_strdup_printf (
    "{\"version\":1,\"credential_id\":\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\","
    "\"credential_secret\":\"%s\"}\n", credential_secret);
  g_assert_true (g_file_set_contents (credential_path, credential_doc, -1,
      &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (credential_path, 0600), ==, 0);

  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  g_autoptr (GCancellable) accept_cancel = g_cancellable_new ();
  PolicyCheckServer server = {
    .listener = listener,
    .cancel = accept_cancel,
    .response_body = response_body,
    .response_status = response_status,
  };
  GThread *server_thread = g_thread_new ("service-token-error",
          policy_check_server_thread, &server);
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    daemon_url,
    "--timeout-ms",
    "1000",
    "auth",
    "service-token",
    "--credential-file",
    credential_path,
    "--token-output",
    output_path,
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  stop_test_server (server_thread, accept_cancel);

  g_assert_true (WIFEXITED (wait_status));
  g_assert_cmpint (WEXITSTATUS (wait_status), ==, expected_exit_status);
  g_assert_cmpstr (stdout_buf, ==, "");
  g_autofree gchar *expected_stderr = g_strdup_printf (
    "wyctl: auth service-token failed: %s\n", expected_error);
  g_assert_cmpstr (stderr_buf, ==, expected_stderr);
  g_assert_false (g_file_test (output_path, G_FILE_TEST_EXISTS));
  g_assert_nonnull (server.request);
  g_assert_nonnull (g_strstr_len (server.request, -1,
      "POST /auth/service-token HTTP/1.1"));
  g_assert_null (g_strstr_len (stdout_buf, -1, credential_secret));
  g_assert_null (g_strstr_len (stderr_buf, -1, credential_secret));

  g_free (server.request);
  remove_dir_recursive (dir);
}

static void
test_service_token_reports_remote_error (void)
{
  run_service_token_response_case (403,
      "{\"error\":\"service_token_auth_required\"}", 6,
      "service_token_auth_required");
  run_service_token_response_case (403,
      "{\"error\":\"service_token_denied\"}", 4,
      "service_token_denied");
  run_service_token_response_case (403,
      "{\"error\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}", 6,
      "service_token_exchange_failed");
  run_service_token_response_case (403,
      "{\"error\":\"a\\u0061a\"}", 6,
      "service_token_exchange_failed");
  run_service_token_response_case (200, "{}", 3,
      "service_token_exchange_failed");
  run_service_token_response_case (302, "{\"error\":\"redirected\"}", 5,
      "redirected");
}

static void
test_login_reports_remote_error (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyctl-login-error-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *access_path = g_build_filename (dir, "access", NULL);
  g_autofree gchar *refresh_path = g_build_filename (dir, "refresh", NULL);
  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  g_autoptr (GCancellable) cancel = g_cancellable_new ();
  PolicyCheckServer server = {
    .listener = listener, .cancel = cancel, .response_status = 403,
    .response_body = "{\"error\":\"login_denied\"}",
  };
  GThread *thread = g_thread_new ("login-error", policy_check_server_thread,
          &server);
  gchar *argv[] = {WYL_TEST_WYCTL_PATH, "--daemon-url", daemon_url,
                   "auth", "login", "--subject", "alice", "--skip-mfa",
                   "--tenant", "__wr_default", "--token-output", access_path,
                   "--refresh-token-output", refresh_path, NULL};
  g_autofree gchar *out = NULL;
  g_autofree gchar *err = NULL;
  gint status = 0;
  run_child (argv, &out, &err, &status);
  stop_test_server (thread, cancel);
  g_assert_true (WIFEXITED (status));
  g_assert_cmpint (WEXITSTATUS (status), ==, 1);
  g_assert_cmpstr (out, ==, "");
  g_assert_cmpstr (err, ==, "wyctl: login failed: login_denied\n");
  g_free (server.request);
  g_assert_false (g_file_test (access_path, G_FILE_TEST_EXISTS));
  g_assert_false (g_file_test (refresh_path, G_FILE_TEST_EXISTS));
  remove_dir_recursive (dir);
}

static void
test_login_existing_output_prevents_request (gconstpointer data)
{
  gboolean existing_access = GPOINTER_TO_INT (data) != 0;
  g_autofree gchar *dir = g_dir_make_tmp ("wyctl-login-existing-XXXXXX",
          NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *access_path = g_build_filename (dir, "access", NULL);
  g_autofree gchar *refresh_path = g_build_filename (dir, "refresh", NULL);
  const gchar *existing_path = existing_access ? access_path : refresh_path;
  const gchar *other_path = existing_access ? refresh_path : access_path;
  g_assert_true (g_file_set_contents (existing_path, "existing token", -1,
      NULL));
  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  g_autoptr (GCancellable) cancel = g_cancellable_new ();
  PolicyCheckServer server = {
    .listener = listener, .cancel = cancel, .response_status = 403,
    .response_body = "{\"error\":\"login_denied\"}",
  };
  GThread *thread = g_thread_new ("login-existing",
          policy_check_server_thread, &server);
  gchar *argv[] = { WYL_TEST_WYCTL_PATH, "--daemon-url", daemon_url,
                    "auth", "login", "--subject", "alice", "--skip-mfa",
                    "--tenant", "__wr_default", "--token-output", access_path,
                    "--refresh-token-output", refresh_path, NULL };
  g_autofree gchar *out = NULL;
  g_autofree gchar *err = NULL;
  gint status = 0;
  run_child (argv, &out, &err, &status);
  stop_test_server (thread, cancel);
  g_assert_true (WIFEXITED (status));
  g_assert_cmpint (WEXITSTATUS (status), ==, 2);
  g_assert_cmpstr (out, ==, "");
  g_autofree gchar *expected = g_strdup_printf (
    "wyctl: --%s already exists: %s\n",
    existing_access ? "token-output" : "refresh-token-output",
    existing_path);
  g_assert_cmpstr (err, ==, expected);
  g_assert_null (server.request);
  g_assert_false (g_file_test (other_path, G_FILE_TEST_EXISTS));
  remove_dir_recursive (dir);
}

static void
test_login_raced_output_reports_collision (gconstpointer data)
{
  gboolean collide_access = GPOINTER_TO_INT (data) != 0;
  g_autofree gchar *dir = g_dir_make_tmp ("wyctl-login-race-XXXXXX", NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *access_path = g_build_filename (dir, "access", NULL);
  g_autofree gchar *refresh_path = g_build_filename (dir, "refresh", NULL);
  const gchar *collision_path = collide_access ? access_path : refresh_path;
  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  g_autoptr (GCancellable) cancel = g_cancellable_new ();
  PolicyCheckServer server = {
    .listener = listener, .cancel = cancel,
    .response_body = "{\"session_token\":\"session\","
        "\"access_token\":\"new-access\","
        "\"refresh_token\":\"new-refresh\","
        "\"username\":\"alice\","
        "\"tenant\":\"__wr_default\","
        "\"principal_state\":\"authenticated\","
        "\"session_state\":\"active\"}",
    .create_path_before_response = collision_path,
  };
  GThread *thread = g_thread_new ("login-race", policy_check_server_thread,
          &server);
  gchar *argv[] = { WYL_TEST_WYCTL_PATH, "--daemon-url", daemon_url,
                    "--timeout-ms", "1000", "auth", "login", "--subject",
                    "alice", "--skip-mfa", "--tenant", "__wr_default",
                    "--token-output", access_path, "--refresh-token-output",
                    refresh_path, NULL };
  g_autofree gchar *out = NULL;
  g_autofree gchar *err = NULL;
  gint status = 0;
  run_child (argv, &out, &err, &status);
  stop_test_server (thread, cancel);
  g_assert_true (WIFEXITED (status));
  g_assert_cmpint (WEXITSTATUS (status), ==, 1);
  g_assert_cmpstr (out, ==, "");
  assert_child_stderr_has (err, "output already exists:");
  assert_child_stderr_has (err, collision_path);
  assert_child_stderr_has (err, "server logout was attempted");
  g_assert_nonnull (server.request);
  g_assert_nonnull (g_strstr_len (server.request, -1,
      "POST /auth/login?"));
  g_assert_false (g_file_test (collide_access ? refresh_path : access_path,
      G_FILE_TEST_EXISTS));
  remove_dir_recursive (dir);
  g_free (server.request);
}

#define FACT_FORGET_REFUSED \
  "wyctl: fact forget refused: a value holds a control byte, " \
  "--batch-id is \"operator\" or \"reason\", --operator is " \
  "\"reason\", or the request exceeds 4096 bytes\n"
#define FACT_FORGET_UNKNOWN_HINT \
  "wyctl: the forget outcome is unknown; re-run the same command, and a " \
  "404 fact_batch_not_found then means the batch is already erased or " \
  "never existed\n"

/* Run `wyctl fact forget` against a one-request fake daemon answering
 * STATUS with BODY.  EXTRA replaces the default target options when it is
 * not NULL.  With CONFIGURED, the daemon URL, default tenant and default
 * graph come from GSettings instead of the command line, so a command that
 * fell back to them would reach the fake daemon.  RUN->request stays NULL
 * when no request arrived. */
typedef struct
{
  gint exit_status;
  gchar *out;
  gchar *err;
  gchar *request;
} FactForgetRun;

static void
fact_forget_run_clear (FactForgetRun *run)
{
  g_clear_pointer (&run->out, g_free);
  g_clear_pointer (&run->err, g_free);
  g_clear_pointer (&run->request, g_free);
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (FactForgetRun, fact_forget_run_clear);

static void
run_fact_forget_case (guint status, const gchar *body,
    const gchar *const *extra, gboolean configured, FactForgetRun *run)
{
  g_autofree gchar *token_path = write_token_with_mode ("token-1", 0600);
  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  g_autoptr (GCancellable) cancel = g_cancellable_new ();
  PolicyMutationServer server = {
    .listener = listener, .cancel = cancel, .status = status, .body = body,
  };
  g_autofree gchar *xdg = NULL;
  g_auto (GStrv) envp = NULL;
  if (configured) {
    g_autofree gchar *url_literal = gvariant_literal_for_string (daemon_url);
    const gchar *const keys[] = {
      "daemon-url", "default-tenant", "default-graph", NULL,
    };
    const gchar *const values[] = {url_literal, "'t'", "'g'", NULL};
    xdg = make_keyfile_xdg_dir (keys, values);
    envp = build_gsettings_envp (xdg, FALSE);
  }
  GThread *thread = g_thread_new ("fact-forget",
          policy_mutation_server_thread, &server);
  static const gchar *const target[] = {
    "--tenant", "t", "--graph", "g", "--namespace", "ns", "--relation", "r",
    "--schema-version", "1", "--batch-id", "b 1", "--operator", "ops",
    "--reason", "gdpr erase", "--confirm", NULL,
  };
  g_autoptr (GPtrArray) argv = g_ptr_array_new ();
  g_ptr_array_add (argv, WYL_TEST_WYCTL_PATH);
  if (envp == NULL) {
    g_ptr_array_add (argv, "--daemon-url");
    g_ptr_array_add (argv, daemon_url);
  }
  g_ptr_array_add (argv, "--timeout-ms");
  g_ptr_array_add (argv, "2000");
  g_ptr_array_add (argv, "fact");
  g_ptr_array_add (argv, "forget");
  for (const gchar *const *arg = extra != NULL ? extra : target; *arg != NULL;
      arg++)
    g_ptr_array_add (argv, (gpointer) *arg);
  g_ptr_array_add (argv, "--access-token-file");
  g_ptr_array_add (argv, token_path);
  g_ptr_array_add (argv, "--guard-timestamp");
  g_ptr_array_add (argv, "123");
  g_ptr_array_add (argv, "--guard-loc-class");
  g_ptr_array_add (argv, "trusted");
  g_ptr_array_add (argv, "--guard-risk");
  g_ptr_array_add (argv, "29");
  g_ptr_array_add (argv, NULL);
  if (envp != NULL)
    run_child_with_env ((gchar **) argv->pdata, envp, &run->out, &run->err,
        &run->exit_status);
  else
    run_child ((gchar **) argv->pdata, &run->out, &run->err,
        &run->exit_status);
  stop_test_server (thread, cancel);
  run->request = server.request;
  g_unlink (token_path);
  if (xdg != NULL)
    remove_dir_recursive (xdg);
}

static void
assert_fact_forget_exit (const FactForgetRun *run, gint expected)
{
  if (WIFEXITED (run->exit_status)
      && WEXITSTATUS (run->exit_status) == expected)
    return;
  g_printerr ("expected fact forget exit %d; stdout: %s stderr: %s\n",
      expected, run->out, run->err);
  g_assert_not_reached ();
}

static void
test_fact_forget_success (void)
{
  g_auto (FactForgetRun) run = { 0 };
  run_fact_forget_case (200, "{\"ok\":true,\"committed\":true,"
      "\"rows_purged\":3,\"queryable\":true,\"reconcile\":false,"
      "\"engine_generation\":7,\"mutation_class\":\"forget\"}", NULL, FALSE,
      &run);
  assert_fact_forget_exit (&run, 0);
  g_assert_cmpstr (run.out, ==, "action=forget batch_id=b%201 rows_purged=3 "
      "mutation_class=forget reconcile=false\n");
  g_assert_cmpstr (run.err, ==, "");
  g_assert_nonnull (run.request);
  g_assert_true (g_str_has_prefix (run.request,
      "DELETE /facts/t/g/r:forget?"));
  g_assert_nonnull (g_strstr_len (run.request, -1, "namespace=ns"));
  g_assert_nonnull (g_strstr_len (run.request, -1,
      "Authorization: Bearer token-1"));
}

static void
test_fact_forget_audit_failed (void)
{
  g_auto (FactForgetRun) run = { 0 };
  run_fact_forget_case (500, "{\"ok\":false,"
      "\"error\":\"fact_forget_audit_failed\",\"purged\":true,"
      "\"rows_purged\":2,\"mutation_class\":\"forget\"}", NULL, FALSE, &run);
  assert_fact_forget_exit (&run, 5);
  g_assert_cmpstr (run.out, ==, "action=forget batch_id=b%201 rows_purged=2 "
      "purged=true audit=failed\n");
  g_assert_cmpstr (run.err, ==,
      "wyctl: fact forget failed: fact_forget_audit_failed\n"
      "wyctl: rows erased; audit record failed; do not retry\n");
}

/* The error code alone says the rows are gone, even in a body that does not
 * carry the purge fields. */
static void
test_fact_forget_audit_failed_bare (void)
{
  g_auto (FactForgetRun) run = { 0 };
  run_fact_forget_case (500, "{\"error\":\"fact_forget_audit_failed\"}",
      NULL, FALSE, &run);
  assert_fact_forget_exit (&run, 5);
  g_assert_cmpstr (run.out, ==, "");
  g_assert_cmpstr (run.err, ==,
      "wyctl: fact forget failed: fact_forget_audit_failed\n"
      "wyctl: rows erased; audit record failed; do not retry\n");
}

static void
test_fact_forget_status_errors (void)
{
  /* A server error may follow the commit, so it leaves the outcome
   * unknown; a client error or a missing batch does not. */
  static const struct
  {
    guint status;
    const gchar *code;
    gint exit_status;
    gboolean unknown;
  } cases[] = {
    {400, "invalid_fact_forget", 3, FALSE},
    {401, "fact_auth_required", 6, FALSE},
    {403, "fact_forget_denied", 4, FALSE},
    {404, "fact_batch_not_found", 5, FALSE},
    {409, "graph_sealed", 4, FALSE},
    {500, "policy_write_cleanup_failed", 5, TRUE},
    {503, "fact_store_busy", 5, TRUE},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++) {
    g_auto (FactForgetRun) run = { 0 };
    g_autofree gchar *body = g_strdup_printf ("{\"error\":\"%s\"}",
            cases[i].code);
    g_autofree gchar *expected = g_strdup_printf (
      "wyctl: fact forget failed: %s\n%s", cases[i].code,
      cases[i].unknown ? FACT_FORGET_UNKNOWN_HINT : "");
    run_fact_forget_case (cases[i].status, body, NULL, FALSE, &run);
    assert_fact_forget_exit (&run, cases[i].exit_status);
    g_assert_cmpstr (run.out, ==, "");
    g_assert_cmpstr (run.err, ==, expected);
  }
}

static void
test_fact_forget_unknown_outcome (void)
{
  g_autofree gchar *token_path = write_token_with_mode ("token-1", 0600);
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH, "--daemon-url", "http://127.0.0.1:1",
    "--timeout-ms", "1000", "fact", "forget", "--tenant", "t", "--graph", "g",
    "--namespace", "ns", "--relation", "r", "--schema-version", "1",
    "--batch-id", "b", "--operator", "ops", "--reason", "why", "--confirm",
    "--access-token-file", token_path, "--guard-timestamp", "123",
    "--guard-loc-class", "trusted", "--guard-risk", "29", NULL,
  };
  g_autofree gchar *out = NULL;
  g_autofree gchar *err = NULL;
  gint status = 0;
  run_child (argv, &out, &err, &status);
  g_unlink (token_path);
  g_assert_true (WIFEXITED (status));
  g_assert_cmpint (WEXITSTATUS (status), ==, 5);
  g_assert_cmpstr (out, ==, "");
  assert_child_stderr_has (err, "wyctl: fact forget failed: ");
  assert_child_stderr_has (err, "the forget outcome is unknown; re-run the "
      "same command, and a 404 fact_batch_not_found then means the batch is "
      "already erased or never existed");
}

/* A success status with a body wyctl cannot read leaves the outcome
 * unknown too. */
static void
test_fact_forget_unreadable_success (void)
{
  g_auto (FactForgetRun) run = { 0 };
  run_fact_forget_case (200, "{}", NULL, FALSE, &run);
  assert_fact_forget_exit (&run, 5);
  g_assert_cmpstr (run.out, ==, "");
  g_assert_cmpstr (run.err, ==, "wyctl: fact forget failed: "
      "fact_forget_failed\n" FACT_FORGET_UNKNOWN_HINT);
}

/* Every refusal happens before a request, and never reads as a transport
 * failure. */
static void
test_fact_forget_refusals (void)
{
  static const gchar *const no_confirm[] = {
    "--tenant", "t", "--graph", "g", "--namespace", "ns", "--relation", "r",
    "--schema-version", "1", "--batch-id", "b", "--operator", "ops",
    "--reason", "why", NULL,
  };
  static const gchar *const no_graph[] = {
    "--tenant", "t", "--namespace", "ns", "--relation", "r",
    "--schema-version", "1", "--batch-id", "b", "--operator", "ops",
    "--reason", "why", "--confirm", NULL,
  };
  static const gchar *const no_reason[] = {
    "--tenant", "t", "--graph", "g", "--namespace", "ns", "--relation", "r",
    "--schema-version", "1", "--batch-id", "b", "--operator", "ops",
    "--confirm", NULL,
  };
  static const gchar *const control_byte[] = {
    "--tenant", "t", "--graph", "g", "--namespace", "ns", "--relation", "r",
    "--schema-version", "1", "--batch-id", "b", "--operator", "ops",
    "--reason", "line\nbreak", "--confirm", NULL,
  };
  static const gchar *const delete_byte[] = {
    "--tenant", "t", "--graph", "g", "--namespace", "ns", "--relation", "r",
    "--schema-version", "1", "--batch-id", "b", "--operator", "ops\x7f",
    "--reason", "why", "--confirm", NULL,
  };
  static const gchar *const reserved_batch[] = {
    "--tenant", "t", "--graph", "g", "--namespace", "ns", "--relation", "r",
    "--schema-version", "1", "--batch-id", "reason", "--operator", "ops",
    "--reason", "why", "--confirm", NULL,
  };
  static const struct
  {
    const gchar *const *args;
    const gchar *err;
  } cases[] = {
    {no_confirm, "wyctl: fact forget erases the batch permanently; "
     "pass --confirm\n"},
    {no_graph, "wyctl: fact forget needs --tenant and --graph on the "
     "command line\n"},
    {no_reason, "wyctl: missing fact forget target option\n"},
    {control_byte, FACT_FORGET_REFUSED},
    {delete_byte, FACT_FORGET_REFUSED},
    {reserved_batch, FACT_FORGET_REFUSED},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++) {
    g_auto (FactForgetRun) run = { 0 };
    run_fact_forget_case (200, "{}", cases[i].args, FALSE, &run);
    assert_fact_forget_exit (&run, 2);
    g_assert_null (run.request);
    g_assert_cmpstr (run.out, ==, "");
    g_assert_cmpstr (run.err, ==, cases[i].err);
  }
}

/* The configured default tenant and graph are never an erase target. */
static void
test_fact_forget_ignores_configured_target (void)
{
  static const gchar *const configured[] = {
    "--namespace", "ns", "--relation", "r", "--schema-version", "1",
    "--batch-id", "b", "--operator", "ops", "--reason", "why", "--confirm",
    NULL,
  };
  g_auto (FactForgetRun) run = { 0 };
  run_fact_forget_case (200, "{}", configured, TRUE, &run);
  assert_fact_forget_exit (&run, 2);
  g_assert_null (run.request);
  g_assert_cmpstr (run.out, ==, "");
  g_assert_cmpstr (run.err, ==, "wyctl: fact forget needs --tenant and "
      "--graph on the command line\n");

  /* Positive control: the same keyfile environment does reach the fake
   * daemon once the target is typed, so the refusal above is not an
   * environment that could reach nothing. */
  static const gchar *const typed[] = {
    "--tenant", "t", "--graph", "g", "--namespace", "ns", "--relation", "r",
    "--schema-version", "1", "--batch-id", "b", "--operator", "ops",
    "--reason", "why", "--confirm", NULL,
  };
  g_auto (FactForgetRun) control = { 0 };
  run_fact_forget_case (200, "{\"ok\":true,\"committed\":true,"
      "\"rows_purged\":1,\"queryable\":true,\"reconcile\":true,"
      "\"engine_generation\":2,\"mutation_class\":\"committed_degraded\","
      "\"degraded_class\":\"replay\"}", typed, TRUE, &control);
  assert_fact_forget_exit (&control, 0);
  g_assert_nonnull (control.request);
  g_assert_true (g_str_has_prefix (control.request,
      "DELETE /facts/t/g/r:forget?"));
  g_assert_cmpstr (control.out, ==, "action=forget batch_id=b rows_purged=1 "
      "mutation_class=committed_degraded reconcile=true\n");
}

/* Run wyctl with ARGS against a one-request fake daemon answering STATUS
 * with BODY.  An argument "@TOKEN@" is replaced by a protected token file
 * holding "token-1"; DAEMON_URL NULL means the fake daemon's own URL.  With
 * CONFIGURED, GSettings supplies default-tenant "t", default-graph "orders"
 * and that token file as access-token-file. */
static void
run_fake_daemon_case (guint status, const gchar *body, const gchar *daemon_url,
    const gchar *const *args, gboolean configured, FactForgetRun *run)
{
  g_autofree gchar *token_path = write_token_with_mode ("token-1", 0600);
  g_autofree gchar *xdg = NULL;
  g_auto (GStrv) envp = NULL;
  if (configured) {
    g_autofree gchar *token_literal = gvariant_literal_for_string (token_path);
    const gchar *const keys[] = {
      "default-tenant", "access-token-file", "default-graph", NULL,
    };
    const gchar *const values[] = {"'t'", token_literal, "'orders'", NULL};
    xdg = make_keyfile_xdg_dir (keys, values);
    envp = build_gsettings_envp (xdg, FALSE);
  }
  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *server_url = listen_url_for_policy_server (&listener);
  g_autoptr (GCancellable) cancel = g_cancellable_new ();
  PolicyMutationServer server = {
    .listener = listener, .cancel = cancel, .status = status, .body = body,
  };
  GThread *thread = g_thread_new ("fake-daemon",
          policy_mutation_server_thread, &server);
  g_autoptr (GPtrArray) argv = g_ptr_array_new ();
  g_ptr_array_add (argv, WYL_TEST_WYCTL_PATH);
  g_ptr_array_add (argv, "--daemon-url");
  g_ptr_array_add (argv, (gpointer) (daemon_url != NULL ? daemon_url
      : server_url));
  g_ptr_array_add (argv, "--timeout-ms");
  g_ptr_array_add (argv, "2000");
  for (const gchar *const *arg = args; *arg != NULL; arg++)
    g_ptr_array_add (argv, g_strcmp0 (*arg, "@TOKEN@") == 0
        ? (gpointer) token_path : (gpointer) *arg);
  g_ptr_array_add (argv, NULL);
  if (envp != NULL)
    run_child_with_env ((gchar **) argv->pdata, envp, &run->out, &run->err,
        &run->exit_status);
  else
    run_child ((gchar **) argv->pdata, &run->out, &run->err,
        &run->exit_status);
  stop_test_server (thread, cancel);
  run->request = server.request;
  g_unlink (token_path);
  if (xdg != NULL)
    remove_dir_recursive (xdg);
}

#define FACT_STATUS_READY_BODY \
  "{\"status\":\"ready\",\"graphs_total\":2,\"graphs_ready\":2," \
  "\"graphs_degraded\":0,\"graphs_provisioned\":0,\"graphs_sealed\":0}"

#define FACT_STATUS_TENANT_BODY \
  "{\"status\":\"degraded\",\"graphs_total\":2,\"graphs_ready\":1," \
  "\"graphs_degraded\":1,\"graphs_provisioned\":0,\"graphs_sealed\":0," \
  "\"graphs\":[{\"tenant_id\":\"t\",\"graph_id\":\"orders\"," \
  "\"state\":\"ready\",\"queryable\":true,\"engine_generation\":3," \
  "\"last_error_class\":null},{\"tenant_id\":\"t\",\"graph_id\":\"bad\"," \
  "\"state\":\"replay_failed\",\"queryable\":false," \
  "\"engine_generation\":0,\"last_error_class\":\"replay_failed\"}]}"

static void
test_fact_status_anonymous (void)
{
  static const gchar *const args[] = {"fact", "status", NULL};
  g_auto (FactForgetRun) run = { 0 };
  run_fake_daemon_case (200, FACT_STATUS_READY_BODY, NULL, args, FALSE,
      &run);
  assert_fact_forget_exit (&run, 0);
  g_assert_cmpstr (run.out, ==, "scope=anonymous status=ready graphs_total=2 "
      "graphs_ready=2 graphs_degraded=0 graphs_provisioned=0 "
      "graphs_sealed=0\n");
  g_assert_cmpstr (run.err, ==, "");
  g_assert_nonnull (run.request);
  g_assert_true (g_str_has_prefix (run.request, "GET /facts/status "));
  g_assert_null (g_strstr_len (run.request, -1, "Authorization"));

  g_auto (FactForgetRun) degraded = { 0 };
  run_fake_daemon_case (200, "{\"status\":\"degraded\",\"graphs_total\":1,"
      "\"graphs_ready\":0,\"graphs_degraded\":1,\"graphs_sealed\":0}", NULL,
      args, FALSE, &degraded);
  assert_fact_forget_exit (&degraded, 1);
  g_assert_true (g_str_has_prefix (degraded.out,
      "scope=anonymous status=degraded "));

  g_auto (FactForgetRun) unknown = { 0 };
  run_fake_daemon_case (200, "{\"status\":\"rebalancing\",\"graphs_total\":1,"
      "\"graphs_ready\":0,\"graphs_degraded\":0,\"graphs_sealed\":0}", NULL,
      args, FALSE, &unknown);
  assert_fact_forget_exit (&unknown, 3);
  g_assert_true (g_str_has_prefix (unknown.out,
      "scope=anonymous status=rebalancing "));

  g_auto (FactForgetRun) invalid = { 0 };
  run_fake_daemon_case (200, "{}", NULL, args, FALSE, &invalid);
  assert_fact_forget_exit (&invalid, 3);
  g_assert_cmpstr (invalid.out, ==, "");
  g_assert_cmpstr (invalid.err, ==,
      "wyctl: fact status failed: invalid daemon response\n");
}

static void
test_fact_status_tenant (void)
{
  static const gchar *const args[] = {
    "fact", "status", "--tenant", "t", "--access-token-file", "@TOKEN@", NULL,
  };
  g_auto (FactForgetRun) run = { 0 };
  run_fake_daemon_case (200, FACT_STATUS_TENANT_BODY, NULL, args, FALSE,
      &run);
  assert_fact_forget_exit (&run, 1);
  g_assert_cmpstr (run.out, ==, "scope=tenant tenant=t status=degraded "
      "graphs_total=2 graphs_ready=1 graphs_degraded=1 graphs_provisioned=0 "
      "graphs_sealed=0\n"
      "graph=orders state=ready queryable=true engine_generation=3 "
      "reason=none\n"
      "graph=bad state=replay_failed queryable=false engine_generation=0 "
      "reason=replay_failed\n");
  g_assert_nonnull (run.request);
  g_assert_true (g_str_has_prefix (run.request,
      "GET /facts/status?tenant=t "));
  g_assert_nonnull (g_strstr_len (run.request, -1,
      "Authorization: Bearer token-1"));

  static const gchar *const one_graph[] = {
    "fact", "status", "--tenant", "t", "--access-token-file", "@TOKEN@",
    "--graph", "orders", NULL,
  };
  g_auto (FactForgetRun) ready = { 0 };
  run_fake_daemon_case (200, FACT_STATUS_TENANT_BODY, NULL, one_graph, FALSE,
      &ready);
  assert_fact_forget_exit (&ready, 0);
  g_assert_true (g_str_has_suffix (ready.out, "\ngraph=orders state=ready "
      "queryable=true engine_generation=3 reason=none\n"));

  static const gchar *const bad_graph[] = {
    "fact", "status", "--tenant", "t", "--access-token-file", "@TOKEN@",
    "--graph", "bad", NULL,
  };
  g_auto (FactForgetRun) failed = { 0 };
  run_fake_daemon_case (200, FACT_STATUS_TENANT_BODY, NULL, bad_graph, FALSE,
      &failed);
  assert_fact_forget_exit (&failed, 1);
  g_assert_true (g_str_has_suffix (failed.out, "\ngraph=bad "
      "state=replay_failed queryable=false engine_generation=0 "
      "reason=replay_failed\n"));

  static const gchar *const absent_graph[] = {
    "fact", "status", "--tenant", "t", "--access-token-file", "@TOKEN@",
    "--graph", "gone", NULL,
  };
  g_auto (FactForgetRun) absent = { 0 };
  run_fake_daemon_case (200, FACT_STATUS_TENANT_BODY, NULL, absent_graph, FALSE,
      &absent);
  assert_fact_forget_exit (&absent, 1);
  g_assert_true (g_str_has_suffix (absent.out, "\ngraph=gone state=absent\n"));

  g_auto (FactForgetRun) denied = { 0 };
  run_fake_daemon_case (401, "{\"error\":\"fact_status_auth_required\"}",
      NULL, args, FALSE, &denied);
  assert_fact_forget_exit (&denied, 6);
  g_assert_cmpstr (denied.out, ==, "");
}

/* Typing either --tenant or --access-token-file makes the request
 * authenticated; the configured default fills the other one. */
static void
test_fact_status_fills_from_settings (void)
{
  static const gchar *const tenant_only[] = {
    "fact", "status", "--tenant", "t", NULL,
  };
  g_auto (FactForgetRun) run = { 0 };
  run_fake_daemon_case (200, FACT_STATUS_TENANT_BODY, NULL, tenant_only,
      TRUE, &run);
  assert_fact_forget_exit (&run, 1);
  g_assert_nonnull (run.request);
  g_assert_nonnull (g_strstr_len (run.request, -1,
      "Authorization: Bearer token-1"));

  static const gchar *const token_only[] = {
    "fact", "status", "--access-token-file", "@TOKEN@", NULL,
  };
  g_auto (FactForgetRun) filled = { 0 };
  run_fake_daemon_case (200, FACT_STATUS_TENANT_BODY, NULL, token_only, TRUE,
      &filled);
  assert_fact_forget_exit (&filled, 1);
  g_assert_nonnull (filled.request);
  g_assert_true (g_str_has_prefix (filled.request,
      "GET /facts/status?tenant=t "));

  /* The configured values alone never make the request authenticated. */
  static const gchar *const anonymous[] = {"fact", "status", NULL};
  g_auto (FactForgetRun) plain = { 0 };
  run_fake_daemon_case (200, FACT_STATUS_READY_BODY, NULL, anonymous, TRUE,
      &plain);
  assert_fact_forget_exit (&plain, 0);
  g_assert_nonnull (plain.request);
  g_assert_true (g_str_has_prefix (plain.request, "GET /facts/status "));
  g_assert_null (g_strstr_len (plain.request, -1, "Authorization"));
}

/* Every refusal happens before a request. */
static void
test_fact_status_refusals (void)
{
  static const gchar *const graph_only[] = {
    "fact", "status", "--graph", "orders", NULL,
  };
  g_auto (FactForgetRun) run = { 0 };
  run_fake_daemon_case (200, FACT_STATUS_READY_BODY, NULL, graph_only,
      FALSE, &run);
  assert_fact_forget_exit (&run, 2);
  g_assert_null (run.request);
  g_assert_cmpstr (run.err, ==, "wyctl: fact status --graph needs --tenant "
      "or --access-token-file\n");

  static const gchar *const anonymous[] = {"fact", "status", NULL};
  g_auto (FactForgetRun) remote = { 0 };
  run_fake_daemon_case (200, FACT_STATUS_READY_BODY,
      "http://wyrelog.example:8080", anonymous, FALSE, &remote);
  assert_fact_forget_exit (&remote, 2);
  g_assert_null (remote.request);
  g_assert_cmpstr (remote.err, ==, "wyctl: invalid daemon URL; fact status "
      "needs the daemon's loopback listener\n");
}

static void
test_fact_verify (void)
{
  static const gchar *const args[] = {
    "fact", "verify", "--tenant", "t", "--graph", "orders",
    "--access-token-file", "@TOKEN@", "--guard-timestamp", "123",
    "--guard-loc-class", "trusted", "--guard-risk", "29", NULL,
  };
  g_auto (FactForgetRun) run = { 0 };
  run_fake_daemon_case (200, "{\"ok\":true,\"verified\":true,"
      "\"tenant_id\":\"t\",\"graph_id\":\"orders\"}", NULL, args, FALSE,
      &run);
  assert_fact_forget_exit (&run, 0);
  g_assert_cmpstr (run.out, ==, "tenant=t graph=orders verified=true\n");
  g_assert_cmpstr (run.err, ==, "");
  g_assert_nonnull (run.request);
  g_assert_true (g_str_has_prefix (run.request, "GET /facts/verify?"));
  g_assert_nonnull (g_strstr_len (run.request, -1, "graph=orders"));

  g_auto (FactForgetRun) mismatch = { 0 };
  run_fake_daemon_case (409, "{\"error\":\"fact_graph_verification_failed\"}",
      NULL, args, FALSE, &mismatch);
  assert_fact_forget_exit (&mismatch, 1);
  g_assert_cmpstr (mismatch.out, ==, "tenant=t graph=orders verified=false\n");
  g_assert_cmpstr (mismatch.err, ==,
      "wyctl: fact verify failed: fact_graph_verification_failed\n");

  static const struct
  {
    guint status;
    const gchar *code;
    gint exit_status;
  } cases[] = {
    {400, "invalid_fact_verify_request", 3},
    {401, "fact_verify_auth_required", 6},
    {403, "fact_verify_denied", 4},
    {404, "graph_not_found", 5},
    {409, "graph_sealed", 4},
    {503, "fact_graph_verification_unavailable", 5},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++) {
    g_auto (FactForgetRun) failed = { 0 };
    g_autofree gchar *body = g_strdup_printf ("{\"error\":\"%s\"}",
            cases[i].code);
    g_autofree gchar *expected = g_strdup_printf (
      "wyctl: fact verify failed: %s\n", cases[i].code);
    run_fake_daemon_case (cases[i].status, body, NULL, args, FALSE, &failed);
    assert_fact_forget_exit (&failed, cases[i].exit_status);
    g_assert_cmpstr (failed.out, ==, "");
    g_assert_cmpstr (failed.err, ==, expected);
  }
}

#define GRAPH_GUARDS \
  "--guard-timestamp", "123", "--guard-loc-class", "trusted", \
  "--guard-risk", "29"

static void
test_graph_list (void)
{
  static const gchar *const args[] = {
    "graph", "list", "--tenant", "t", "--access-token-file", "@TOKEN@",
    GRAPH_GUARDS, NULL,
  };
  g_auto (FactForgetRun) run = { 0 };
  run_fake_daemon_case (200, "{\"graphs\":[{\"tenant_id\":\"t\","
      "\"graph_id\":\"orders\",\"sealed\":false,\"schema_version\":1},"
      "{\"tenant_id\":\"t\",\"graph_id\":\"old:stuff\",\"sealed\":true,"
      "\"schema_version\":0}]}", NULL, args, FALSE, &run);
  assert_fact_forget_exit (&run, 0);
  g_assert_cmpstr (run.out, ==, "graph=orders sealed=false schema_version=1\n"
      "graph=old%3Astuff sealed=true schema_version=0\n");
  g_assert_cmpstr (run.err, ==, "");
  g_assert_nonnull (run.request);
  g_assert_true (g_str_has_prefix (run.request, "GET /graphs?"));
  g_assert_nonnull (g_strstr_len (run.request, -1, "tenant=t"));

  g_auto (FactForgetRun) other = { 0 };
  run_fake_daemon_case (200, "{\"graphs\":[{\"tenant_id\":\"u\","
      "\"graph_id\":\"orders\",\"sealed\":false,\"schema_version\":1}]}",
      NULL, args, FALSE, &other);
  assert_fact_forget_exit (&other, 5);
  g_assert_cmpstr (other.out, ==, "");

  g_auto (FactForgetRun) denied = { 0 };
  run_fake_daemon_case (403, "{\"error\":\"graph_denied\"}", NULL, args,
      FALSE, &denied);
  assert_fact_forget_exit (&denied, 4);
  g_assert_cmpstr (denied.err, ==, "wyctl: graph list failed: graph_denied\n");
}

#define GRAPH_SEAL_UNKNOWN_HINT \
  "wyctl: the seal outcome is unknown; `wyctl graph list` shows whether " \
  "the graph is sealed\n"

static void
test_graph_seal (void)
{
  static const gchar *const args[] = {
    "graph", "seal", "--tenant", "t", "--graph", "orders", "--confirm",
    "--access-token-file", "@TOKEN@", GRAPH_GUARDS, NULL,
  };
  g_auto (FactForgetRun) run = { 0 };
  run_fake_daemon_case (200, "{\"ok\":true,\"tenant_id\":\"t\","
      "\"graph_id\":\"orders\",\"sealed\":true}", NULL, args, FALSE, &run);
  assert_fact_forget_exit (&run, 0);
  g_assert_cmpstr (run.out, ==, "tenant=t graph=orders sealed=true\n");
  g_assert_cmpstr (run.err, ==, "");
  g_assert_nonnull (run.request);
  g_assert_true (g_str_has_prefix (run.request, "POST /graphs/seal?"));
  g_assert_nonnull (g_strstr_len (run.request, -1, "graph=orders"));

  static const struct
  {
    guint status;
    const gchar *code;
    gint exit_status;
    gboolean unknown;
  } cases[] = {
    {400, "invalid_graph_request", 3, FALSE},
    {401, "graph_auth_required", 6, FALSE},
    {403, "graph_denied", 4, FALSE},
    {404, "graph_not_found", 5, FALSE},
    {500, "graph_mutation_failed", 5, TRUE},
    {503, "graph_mutation_unavailable", 5, TRUE},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++) {
    g_auto (FactForgetRun) failed = { 0 };
    g_autofree gchar *body = g_strdup_printf ("{\"error\":\"%s\"}",
            cases[i].code);
    g_autofree gchar *expected = g_strdup_printf (
      "wyctl: graph seal failed: %s\n%s", cases[i].code,
      cases[i].unknown ? GRAPH_SEAL_UNKNOWN_HINT : "");
    run_fake_daemon_case (cases[i].status, body, NULL, args, FALSE, &failed);
    assert_fact_forget_exit (&failed, cases[i].exit_status);
    g_assert_cmpstr (failed.out, ==, "");
    g_assert_cmpstr (failed.err, ==, expected);
  }

  /* A success answer that names another graph leaves the outcome unknown. */
  g_auto (FactForgetRun) other = { 0 };
  run_fake_daemon_case (200, "{\"ok\":true,\"tenant_id\":\"t\","
      "\"graph_id\":\"archive\",\"sealed\":true}", NULL, args, FALSE,
      &other);
  assert_fact_forget_exit (&other, 5);
  g_assert_cmpstr (other.out, ==, "");
  g_assert_cmpstr (other.err, ==, "wyctl: graph seal failed: "
      "graph_seal_failed\n" GRAPH_SEAL_UNKNOWN_HINT);
}

/* Every refusal happens before a request; the configured default tenant
 * and graph are never a seal target. */
static void
test_graph_seal_refusals (void)
{
  static const gchar *const unconfirmed[] = {
    "graph", "seal", "--tenant", "t", "--graph", "orders",
    "--access-token-file", "@TOKEN@", GRAPH_GUARDS, NULL,
  };
  static const gchar *const no_tenant[] = {
    "graph", "seal", "--graph", "orders", "--confirm", GRAPH_GUARDS, NULL,
  };
  static const gchar *const no_graph[] = {
    "graph", "seal", "--tenant", "t", "--confirm", GRAPH_GUARDS, NULL,
  };
  static const struct
  {
    const gchar *const *args;
    const gchar *err;
  } cases[] = {
    {unconfirmed, "wyctl: graph seal cannot be undone; pass --confirm\n"},
    {no_tenant, "wyctl: graph seal needs --tenant and --graph on the "
     "command line\n"},
    {no_graph, "wyctl: graph seal needs --tenant and --graph on the "
     "command line\n"},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++) {
    g_auto (FactForgetRun) run = { 0 };
    run_fake_daemon_case (200, "{}", NULL, cases[i].args, TRUE, &run);
    assert_fact_forget_exit (&run, 2);
    g_assert_null (run.request);
    g_assert_cmpstr (run.out, ==, "");
    g_assert_cmpstr (run.err, ==, cases[i].err);
  }
}

static void
test_tenant_list_and_create (void)
{
  static const gchar *const list[] = {
    "tenant", "list", "--access-token-file", "@TOKEN@", GRAPH_GUARDS, NULL,
  };
  g_auto (FactForgetRun) run = { 0 };
  run_fake_daemon_case (200, "{\"tenants\":[{\"tenant\":\"__wr_default\","
      "\"sealed\":false},{\"tenant\":\"acme:eu\",\"sealed\":true}]}", NULL,
      list, FALSE, &run);
  assert_fact_forget_exit (&run, 0);
  g_assert_cmpstr (run.out, ==, "tenant=__wr_default sealed=false\n"
      "tenant=acme%3Aeu sealed=true\n");
  g_assert_nonnull (run.request);
  g_assert_true (g_str_has_prefix (run.request, "GET /tenants?"));
  g_assert_nonnull (g_strstr_len (run.request, -1, "tenant=__wr_default"));

  static const gchar *const create[] = {
    "tenant", "create", "--name", "acme", "--access-token-file", "@TOKEN@",
    GRAPH_GUARDS, NULL,
  };
  g_auto (FactForgetRun) created = { 0 };
  run_fake_daemon_case (200, "{\"ok\":true,\"tenant\":\"acme\","
      "\"changed\":true}", NULL, create, FALSE, &created);
  assert_fact_forget_exit (&created, 0);
  g_assert_cmpstr (created.out, ==, "tenant=acme changed=true\n");
  g_assert_true (g_str_has_prefix (created.request, "POST /tenants/create?"));
  g_assert_nonnull (g_strstr_len (created.request, -1, "name=acme"));

  g_auto (FactForgetRun) other = { 0 };
  run_fake_daemon_case (200, "{\"ok\":true,\"tenant\":\"other\","
      "\"changed\":true}", NULL, create, FALSE, &other);
  assert_fact_forget_exit (&other, 5);
  g_assert_cmpstr (other.out, ==, "");

  static const gchar *const unseal[] = {
    "tenant", "unseal", "--name", "acme", "--access-token-file", "@TOKEN@",
    GRAPH_GUARDS, NULL,
  };
  g_auto (FactForgetRun) unsealed = { 0 };
  run_fake_daemon_case (200, "{\"ok\":true,\"tenant\":\"acme\","
      "\"changed\":false}", NULL, unseal, FALSE, &unsealed);
  assert_fact_forget_exit (&unsealed, 0);
  g_assert_cmpstr (unsealed.out, ==, "tenant=acme changed=false\n");
  g_assert_true (g_str_has_prefix (unsealed.request,
      "POST /tenants/unseal?"));

  g_auto (FactForgetRun) denied = { 0 };
  run_fake_daemon_case (403, "{\"error\":\"tenant_denied\"}", NULL, create,
      FALSE, &denied);
  assert_fact_forget_exit (&denied, 4);
  g_assert_cmpstr (denied.err, ==, "wyctl: tenant create failed: "
      "tenant_denied\n");

  /* After a server error the outcome is unknown and a repeat is safe. */
  g_auto (FactForgetRun) failed = { 0 };
  run_fake_daemon_case (500, "{\"error\":\"tenant_mutation_failed\"}", NULL,
      create, FALSE, &failed);
  assert_fact_forget_exit (&failed, 5);
  g_assert_cmpstr (failed.err, ==, "wyctl: tenant create failed: "
      "tenant_mutation_failed\n"
      "wyctl: the outcome is unknown; repeating the same tenant create is "
      "safe\n");

  /* A pending repair from an earlier failure blocks every tenant change. */
  g_auto (FactForgetRun) pending = { 0 };
  run_fake_daemon_case (503, "{\"error\":\"tenant_mutation_unavailable\"}",
      NULL, unseal, FALSE, &pending);
  assert_fact_forget_exit (&pending, 5);
  g_assert_cmpstr (pending.err, ==, "wyctl: tenant unseal failed: "
      "tenant_mutation_unavailable\n"
      "wyctl: a tenant change that failed, this one or an earlier one, may "
      "be pending; repeat it (a seal with its --request-id) before other "
      "tenant changes\n");
}

/* Return the request_id the seal request carried in its JSON body. */
static gchar *
seal_request_id (const gchar *request)
{
  const gchar *key = request != NULL
      ? strstr (request, "\"request_id\":\"") : NULL;
  if (key == NULL)
    return NULL;
  key += strlen ("\"request_id\":\"");
  const gchar *end = strchr (key, '"');
  return end != NULL ? g_strndup (key, (gsize) (end - key)) : NULL;
}

static void
test_tenant_seal (void)
{
  static const gchar *const seal[] = {
    "tenant", "seal", "--name", "acme", "--confirm",
    "--access-token-file", "@TOKEN@", GRAPH_GUARDS, NULL,
  };
  g_auto (FactForgetRun) run = { 0 };
  run_fake_daemon_case (200, "{\"ok\":true,\"tenant\":\"acme\","
      "\"changed\":true}", NULL, seal, FALSE, &run);
  assert_fact_forget_exit (&run, 0);
  g_assert_true (g_str_has_prefix (run.request, "POST /tenants/seal?"));
  g_assert_nonnull (g_strstr_len (run.request, -1, "\"version\":\"1\""));
  g_autofree gchar *minted = seal_request_id (run.request);
  g_assert_nonnull (minted);
  g_assert_cmpuint (strlen (minted), ==, 27);
  g_autofree gchar *expected = g_strdup_printf ("tenant=acme changed=true "
          "request_id=%s\n", minted);
  g_assert_cmpstr (run.out, ==, expected);

  /* A failure names the id that was sent, so the retry can reuse it. */
  g_auto (FactForgetRun) busy = { 0 };
  run_fake_daemon_case (503, "{\"error\":\"tenant_mutation_unavailable\"}",
      NULL, seal, FALSE, &busy);
  assert_fact_forget_exit (&busy, 5);
  g_autofree gchar *sent = seal_request_id (busy.request);
  g_assert_nonnull (sent);
  g_autofree gchar *hint = g_strdup_printf ("wyctl: tenant seal failed: "
          "tenant_mutation_unavailable\n"
          "wyctl: tenant seal request_id=%s\n"
          "wyctl: a tenant change that failed, this one or an earlier one, "
          "may be pending; repeat it (a seal with its --request-id) before "
          "other tenant changes\n", sent);
  g_assert_cmpstr (busy.err, ==, hint);

  /* --request-id repeats that exact seal. */
  const gchar *const retry[] = {
    "tenant", "seal", "--name", "acme", "--confirm", "--request-id", sent,
    "--access-token-file", "@TOKEN@", GRAPH_GUARDS, NULL,
  };
  g_auto (FactForgetRun) again = { 0 };
  run_fake_daemon_case (200, "{\"ok\":true,\"tenant\":\"acme\","
      "\"changed\":false}", NULL, retry, FALSE, &again);
  assert_fact_forget_exit (&again, 0);
  g_autofree gchar *resent = seal_request_id (again.request);
  g_assert_cmpstr (resent, ==, sent);

  g_auto (FactForgetRun) conflict = { 0 };
  run_fake_daemon_case (409, "{\"error\":\"tenant_seal_superseded\"}", NULL,
      retry, FALSE, &conflict);
  assert_fact_forget_exit (&conflict, 4);
  g_autofree gchar *superseded = g_strdup_printf ("wyctl: tenant seal failed: "
          "tenant_seal_superseded\n"
          "wyctl: tenant seal request_id=%s\n"
          "wyctl: seal request_id=%s cannot apply: the tenant changed after it "
          "was recorded, or the id belongs to another request; `wyctl tenant "
          "list` shows the tenant's state; seal again without --request-id if "
          "it still needs sealing\n", sent, sent);
  g_assert_cmpstr (conflict.err, ==, superseded);

  /* A definite refusal needs no retry advice, but the id is still named:
   * a 400 can follow a repair the seal itself installed. */
  static const struct
  {
    guint status;
    const gchar *code;
    gint exit_status;
  } refusals[] = {
    {400, "invalid_tenant_request", 3},
    {403, "tenant_denied", 4},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (refusals); i++) {
    g_auto (FactForgetRun) refused = { 0 };
    g_autofree gchar *body = g_strdup_printf ("{\"error\":\"%s\"}",
            refusals[i].code);
    g_autofree gchar *expected = g_strdup_printf ("wyctl: tenant seal failed: "
            "%s\nwyctl: tenant seal request_id=%s\n", refusals[i].code, sent);
    run_fake_daemon_case (refusals[i].status, body, NULL, retry, FALSE,
        &refused);
    assert_fact_forget_exit (&refused, refusals[i].exit_status);
    g_assert_cmpstr (refused.err, ==, expected);
  }

  g_auto (FactForgetRun) lost = { 0 };
  run_fake_daemon_case (500, "{\"error\":\"tenant_mutation_failed\"}", NULL,
      retry, FALSE, &lost);
  assert_fact_forget_exit (&lost, 5);
  g_autofree gchar *lost_hint = g_strdup_printf ("wyctl: tenant seal failed: "
          "tenant_mutation_failed\n"
          "wyctl: tenant seal request_id=%s\n"
          "wyctl: the seal outcome is unknown; repeat it with --request-id %s, "
          "not a new id\n", sent, sent);
  g_assert_cmpstr (lost.err, ==, lost_hint);
}

static void
test_tenant_refusals (void)
{
  static const gchar *const unconfirmed[] = {
    "tenant", "seal", "--name", "acme", "--access-token-file", "@TOKEN@",
    GRAPH_GUARDS, NULL,
  };
  static const gchar *const bad_id[] = {
    "tenant", "seal", "--name", "acme", "--confirm", "--request-id", "abc",
    "--access-token-file", "@TOKEN@", GRAPH_GUARDS, NULL,
  };
  static const gchar *const no_name[] = {
    "tenant", "create", "--access-token-file", "@TOKEN@", GRAPH_GUARDS, NULL,
  };
  static const struct
  {
    const gchar *const *args;
    const gchar *err;
  } cases[] = {
    {unconfirmed, "wyctl: tenant seal closes the whole tenant; pass "
     "--confirm\n"},
    {bad_id, "wyctl: invalid --request-id\n"},
    {no_name, "wyctl: missing --name\n"},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++) {
    g_auto (FactForgetRun) run = { 0 };
    run_fake_daemon_case (200, "{}", NULL, cases[i].args, FALSE, &run);
    assert_fact_forget_exit (&run, 2);
    g_assert_null (run.request);
    g_assert_cmpstr (run.out, ==, "");
    g_assert_cmpstr (run.err, ==, cases[i].err);
  }
}

static void
test_profile_status (void)
{
  static const gchar *const args[] = {"profile", "status", NULL};
  g_auto (FactForgetRun) run = { 0 };
  run_fake_daemon_case (200, "{\"profile\":\"service\","
      "\"system_url\":\"http://127.0.0.1:8765\","
      "\"event_spool_dir\":\"/var/spool/wy relog\",\"event_queue_limit\":64}",
      NULL, args, FALSE, &run);
  assert_fact_forget_exit (&run, 0);
  g_assert_cmpstr (run.out, ==, "profile=service "
      "system_url=http://127.0.0.1:8765 "
      "event_spool_dir=/var/spool/wy%20relog event_queue_limit=64\n");
  g_assert_cmpstr (run.err, ==, "");
  g_assert_true (g_str_has_prefix (run.request, "GET /profile/status "));
  g_assert_null (g_strstr_len (run.request, -1, "Authorization"));

  g_auto (FactForgetRun) plain = { 0 };
  run_fake_daemon_case (200, "{\"profile\":\"system\",\"system_url\":null,"
      "\"event_spool_dir\":null,\"event_queue_limit\":0}", NULL, args, FALSE,
      &plain);
  assert_fact_forget_exit (&plain, 0);
  g_assert_cmpstr (plain.out, ==, "profile=system system_url=none "
      "event_spool_dir=none event_queue_limit=0\n");

  g_auto (FactForgetRun) failed = { 0 };
  run_fake_daemon_case (503, "{\"error\":\"not_ready\"}", NULL, args, FALSE,
      &failed);
  assert_fact_forget_exit (&failed, 1);
  g_assert_cmpstr (failed.out, ==, "");
  g_assert_cmpstr (failed.err, ==,
      "wyctl: profile status failed: not_ready\n");

  static const gchar *const invalid_bodies[] = {
    "{}",
    "{\"profile\":\"system\",\"system_url\":null,\"event_spool_dir\":null}",
    "{\"profile\":\"system\",\"system_url\":null,\"event_spool_dir\":null,"
    "\"event_queue_limit\":0,\"extra\":1}",
    "{\"profile\":\"system\",\"system_url\":null,\"event_spool_dir\":null,"
    "\"event_queue_limit\":4294967296}",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (invalid_bodies); i++) {
    g_auto (FactForgetRun) invalid = { 0 };
    run_fake_daemon_case (200, invalid_bodies[i], NULL, args, FALSE,
        &invalid);
    assert_fact_forget_exit (&invalid, 3);
    g_assert_cmpstr (invalid.out, ==, "");
    g_assert_cmpstr (invalid.err, ==,
        "wyctl: profile status failed: invalid daemon response\n");
  }
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/wyctl/login-remote-error", test_login_reports_remote_error);
  g_test_add_data_func ("/wyctl/login-existing-access-preflight",
      GINT_TO_POINTER (1), test_login_existing_output_prevents_request);
  g_test_add_data_func ("/wyctl/login-existing-refresh-preflight",
      GINT_TO_POINTER (0), test_login_existing_output_prevents_request);
  g_test_add_data_func ("/wyctl/login-raced-access-collision",
      GINT_TO_POINTER (1), test_login_raced_output_reports_collision);
  g_test_add_data_func ("/wyctl/login-raced-refresh-collision",
      GINT_TO_POINTER (0), test_login_raced_output_reports_collision);

  static const gchar *settings_cases[] = {
    "missing", "missing-key", "wrong-type", "uint-missing", "uint-wrong",
    "disabled", "explicit", "empty", "version", "help", "auth-timeout",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (settings_cases); i++) {
    g_autofree gchar *path = g_strdup_printf ("/wyctl/settings-diagnostic/%s",
            settings_cases[i]);
    g_test_add_data_func (path, settings_cases[i], test_settings_diagnostic);
  }

  static const gchar *proxy_cases[] = {
    "status", "policy", "mfa", "automatic", "dummy", "version",
    "invalid-token", "partial", "normal",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (proxy_cases); i++) {
    g_autofree gchar *path = g_strdup_printf ("/wyctl/proxy-schema/%s",
            proxy_cases[i]);
    g_test_add_data_func (path, proxy_cases[i], test_proxy_schema_environment);
  }

  g_test_add_func ("/wyctl/version", test_version);
  g_test_add_func ("/wyctl/top-level-help", test_top_level_help);
  g_test_add_func ("/wyctl/status-connection-failure",
      test_status_connection_failure);
  g_test_add_func ("/wyctl/status-rejects-invalid-timeout",
      test_status_rejects_invalid_timeout);
  g_test_add_func ("/wyctl/status-times-out", test_status_times_out);
  g_test_add_func ("/wyctl/status-readiness", test_status_readiness);
  g_test_add_func ("/wyctl/status-requires-daemon-url",
      test_status_requires_daemon_url);
  g_test_add_func ("/wyctl/status-rejects-invalid-daemon-url",
      test_status_rejects_invalid_daemon_url);
  g_test_add_func ("/wyctl/status-help-command-first",
      test_status_help_command_first);
  g_test_add_func ("/wyctl/policy-help", test_policy_help);
  g_test_add_func ("/wyctl/policy-validation", test_policy_validation);
  g_test_add_func ("/wyctl/policy-check", test_policy_check);
  g_test_add_func ("/wyctl/policy-check-connection-failure",
      test_policy_check_connection_failure);
  g_test_add_func ("/wyctl/policy-permission-help",
      test_policy_permission_help);
  g_test_add_func ("/wyctl/policy-permission-validation",
      test_policy_permission_validation);
  g_test_add_func ("/wyctl/policy-permission-grant-success",
      test_policy_permission_grant_success);
  g_test_add_func ("/wyctl/policy-permission-revoke-success",
      test_policy_permission_revoke_success);
  g_test_add_func ("/wyctl/policy-permission-grant-status-errors",
      test_policy_permission_grant_status_errors);
  g_test_add_func ("/wyctl/policy-permission-revoke-status-errors",
      test_policy_permission_revoke_status_errors);
  g_test_add_func ("/wyctl/policy-permission-transition-success",
      test_policy_permission_transition_success);
  g_test_add_func ("/wyctl/policy-permission-transition-status-errors",
      test_policy_permission_transition_status_errors);
  g_test_add_func ("/wyctl/policy-permission-transition-help",
      test_policy_permission_transition_help);
  g_test_add_func ("/wyctl/policy-permission-transition-validation",
      test_policy_permission_transition_validation);
  g_test_add_func ("/wyctl/policy-role-help", test_policy_role_help);
  g_test_add_func ("/wyctl/policy-role-validation",
      test_policy_role_validation);
  g_test_add_func ("/wyctl/policy-role-grant-success",
      test_policy_role_grant_success);
  g_test_add_func ("/wyctl/policy-role-revoke-success",
      test_policy_role_revoke_success);
  g_test_add_func ("/wyctl/policy-role-grant-status-errors",
      test_policy_role_grant_status_errors);
  g_test_add_func ("/wyctl/policy-role-revoke-status-errors",
      test_policy_role_revoke_status_errors);
  g_test_add_func ("/wyctl/audit-help", test_audit_help);
  g_test_add_func ("/wyctl/audit-validation", test_audit_validation);
  g_test_add_func ("/wyctl/audit-query", test_audit_query);
  g_test_add_func ("/wyctl/status-gsettings-supplies-daemon-url",
      test_status_gsettings_supplies_daemon_url);
  g_test_add_func ("/wyctl/status-cli-overrides-gsettings",
      test_status_cli_overrides_gsettings);
  g_test_add_func ("/wyctl/status-kill-switch-disables-gsettings",
      test_status_kill_switch_disables_gsettings);
  g_test_add_func ("/wyctl/policy-check-gsettings-supplies-daemon-url",
      test_policy_check_gsettings_supplies_daemon_url);
  g_test_add_func ("/wyctl/audit-query-gsettings-supplies-daemon-url",
      test_audit_query_gsettings_supplies_daemon_url);
  g_test_add_func ("/wyctl/fact-put-gsettings-supplies-daemon-url",
      test_fact_put_gsettings_supplies_daemon_url);
  g_test_add_func ("/wyctl/fact-forget-success", test_fact_forget_success);
  g_test_add_func ("/wyctl/fact-forget-audit-failed",
      test_fact_forget_audit_failed);
  g_test_add_func ("/wyctl/fact-forget-audit-failed-bare",
      test_fact_forget_audit_failed_bare);
  g_test_add_func ("/wyctl/fact-forget-status-errors",
      test_fact_forget_status_errors);
  g_test_add_func ("/wyctl/fact-forget-unknown-outcome",
      test_fact_forget_unknown_outcome);
  g_test_add_func ("/wyctl/fact-forget-unreadable-success",
      test_fact_forget_unreadable_success);
  g_test_add_func ("/wyctl/fact-forget-refusals", test_fact_forget_refusals);
  g_test_add_func ("/wyctl/fact-status-anonymous", test_fact_status_anonymous);
  g_test_add_func ("/wyctl/fact-status-tenant", test_fact_status_tenant);
  g_test_add_func ("/wyctl/fact-status-fills-from-settings",
      test_fact_status_fills_from_settings);
  g_test_add_func ("/wyctl/fact-status-refusals", test_fact_status_refusals);
  g_test_add_func ("/wyctl/fact-verify", test_fact_verify);
  g_test_add_func ("/wyctl/graph-list", test_graph_list);
  g_test_add_func ("/wyctl/graph-seal", test_graph_seal);
  g_test_add_func ("/wyctl/graph-seal-refusals", test_graph_seal_refusals);
  g_test_add_func ("/wyctl/tenant-list-and-create",
      test_tenant_list_and_create);
  g_test_add_func ("/wyctl/tenant-seal", test_tenant_seal);
  g_test_add_func ("/wyctl/tenant-refusals", test_tenant_refusals);
  g_test_add_func ("/wyctl/profile-status", test_profile_status);
  g_test_add_func ("/wyctl/fact-forget-ignores-configured-target",
      test_fact_forget_ignores_configured_target);
  g_test_add_func ("/wyctl/datalog-query-gsettings-supplies-daemon-url",
      test_datalog_query_gsettings_supplies_daemon_url);
  g_test_add_func (
    "/wyctl/policy-check-gsettings-daemon-url-is-the-transport-target",
    test_policy_check_gsettings_daemon_url_is_the_transport_target);
  g_test_add_func ("/wyctl/policy-check-safety-reject-prevents-http",
      test_policy_check_safety_reject_prevents_http);
  g_test_add_func ("/wyctl/audit-query-safety-reject-prevents-http",
      test_audit_query_safety_reject_prevents_http);
  g_test_add_func ("/wyctl/service-token-preflight-and-malformed-input",
      test_service_token_preflight_and_malformed_input);
  g_test_add_func ("/wyctl/service-token-help", test_service_token_help);
  g_test_add_func ("/wyctl/service-token-reports-remote-error",
      test_service_token_reports_remote_error);

  return wyl_test_normalize_exit_status (g_test_run ());
}

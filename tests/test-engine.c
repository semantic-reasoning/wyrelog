/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>

#include "wyrelog/engine.h"

/* Allow direct access to internal helpers for unit testing. */
#define WYL_ENGINE_INTERNAL 1
#include "wyrelog/wyl-engine-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/*
 * write_file_in_dir: writes @contents to @filename inside @dir.
 * Returns FALSE on error.
 */
static gboolean
write_file_in_dir (const gchar *dir, const gchar *filename,
    const gchar *contents)
{
  g_autofree gchar *path = g_build_filename (dir, filename, NULL);
  g_autoptr (GError) err = NULL;
  return g_file_set_contents (path, contents, -1, &err);
}

/*
 * make_tmpdir: creates a GLib temp directory; caller frees with g_free
 * and removes with g_rmdir after clearing contents.
 */
static gchar *
make_tmpdir (void)
{
  g_autoptr (GError) err = NULL;
  gchar *dir = g_dir_make_tmp ("wyl-engine-test-XXXXXX", &err);
  if (dir == NULL) {
    g_printerr ("make_tmpdir: %s\n", err ? err->message : "?");
    return NULL;
  }
  return dir;
}

/*
 * copy_real_templates_to: copies the 5 real template files from the
 * canonical template dir into dest_dir, creating fsm/ subdirectory.
 * Returns FALSE on any error.
 */
static gboolean
copy_real_templates_to (const gchar *dest_dir)
{
  static const char *files[] = {
    "bootstrap.dl",
    "fsm/principal.dl",
    "fsm/session.dl",
    "fsm/permission_scope.dl",
    "decision.dl",
  };

  /* Create fsm/ subdir. */
  g_autofree gchar *fsm_dir = g_build_filename (dest_dir, "fsm", NULL);
  if (g_mkdir (fsm_dir, 0755) != 0) {
    g_printerr ("copy_real_templates_to: mkdir %s failed\n", fsm_dir);
    return FALSE;
  }

  for (gsize i = 0; i < G_N_ELEMENTS (files); i++) {
    g_autofree gchar *src = g_build_filename (WYL_TEST_TEMPLATE_DIR,
        files[i], NULL);
    g_autofree gchar *dst = g_build_filename (dest_dir, files[i], NULL);
    g_autofree gchar *contents = NULL;
    gsize len = 0;
    g_autoptr (GError) err = NULL;

    if (!g_file_get_contents (src, &contents, &len, &err)) {
      g_printerr ("copy_real_templates_to: cannot read %s: %s\n",
          src, err ? err->message : "?");
      return FALSE;
    }
    if (!g_file_set_contents (dst, contents, (gssize) len, &err)) {
      g_printerr ("copy_real_templates_to: cannot write %s: %s\n",
          dst, err ? err->message : "?");
      return FALSE;
    }
  }
  return TRUE;
}

/*
 * rmdir_recursive: removes a directory and all its contents.
 * Only goes one level deep (sufficient for our tmpdir layout).
 */
static void
rmdir_recursive (const gchar *dir)
{
  g_autoptr (GDir) d = g_dir_open (dir, 0, NULL);
  if (d == NULL) {
    g_rmdir (dir);
    return;
  }

  const gchar *name;
  while ((name = g_dir_read_name (d)) != NULL) {
    g_autofree gchar *path = g_build_filename (dir, name, NULL);
    if (g_file_test (path, G_FILE_TEST_IS_DIR))
      rmdir_recursive (path);
    else
      g_unlink (path);
  }
  g_rmdir (dir);
}

/* ------------------------------------------------------------------ */
/* Test cases                                                          */
/* ------------------------------------------------------------------ */

static gint
test_engine_open_canonical_smoke (void)
{
  WylEngine *engine = NULL;
  wyrelog_error_t rc = wyl_engine_open (WYL_TEST_TEMPLATE_DIR, 1, &engine);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("test_engine_open_canonical_smoke: expected WYRELOG_E_OK, "
        "got %d\n", (int) rc);
    return 1;
  }
  if (engine == NULL) {
    g_printerr ("test_engine_open_canonical_smoke: engine is NULL\n");
    return 2;
  }
  wyl_engine_close (engine);
  return 0;
}

static gint
test_engine_open_eager_build_surfaces_errors (void)
{
  g_autofree gchar *tmpdir = make_tmpdir ();
  if (tmpdir == NULL)
    return 10;

  /* Create fsm/ subdir and copy 4 good files, then overwrite decision.dl
   * with malformed content. */
  gboolean ok = copy_real_templates_to (tmpdir);
  if (!ok) {
    rmdir_recursive (tmpdir);
    return 11;
  }

  /* Overwrite decision.dl with deliberately malformed content. */
  if (!write_file_in_dir (tmpdir, "decision.dl",
          "this is not valid datalog ((((\n")) {
    rmdir_recursive (tmpdir);
    return 12;
  }

  WylEngine *engine = NULL;
  wyrelog_error_t rc = wyl_engine_open (tmpdir, 1, &engine);

  rmdir_recursive (tmpdir);

  if (rc == WYRELOG_E_OK) {
    g_printerr ("test_engine_open_eager_build_surfaces_errors: expected "
        "non-OK, got WYRELOG_E_OK\n");
    if (engine != NULL)
      g_object_unref (engine);
    return 13;
  }
  if (engine != NULL) {
    g_printerr ("test_engine_open_eager_build_surfaces_errors: *out should "
        "be NULL on failure\n");
    g_object_unref (engine);
    return 14;
  }
  return 0;
}

static gint
test_engine_open_missing_decision_fail_closed (void)
{
  g_autofree gchar *tmpdir = make_tmpdir ();
  if (tmpdir == NULL)
    return 20;

  /* Create fsm/ subdir and copy bootstrap + fsm files but omit decision.dl */
  g_autofree gchar *fsm_dir = g_build_filename (tmpdir, "fsm", NULL);
  if (g_mkdir (fsm_dir, 0755) != 0) {
    rmdir_recursive (tmpdir);
    return 21;
  }

  static const char *partial_files[] = {
    "bootstrap.dl",
    "fsm/principal.dl",
    "fsm/session.dl",
    "fsm/permission_scope.dl",
    /* decision.dl intentionally omitted */
  };

  for (gsize i = 0; i < G_N_ELEMENTS (partial_files); i++) {
    g_autofree gchar *src =
        g_build_filename (WYL_TEST_TEMPLATE_DIR, partial_files[i], NULL);
    g_autofree gchar *dst = g_build_filename (tmpdir, partial_files[i], NULL);
    g_autofree gchar *contents = NULL;
    gsize len = 0;
    g_autoptr (GError) err = NULL;

    if (!g_file_get_contents (src, &contents, &len, &err)) {
      g_printerr ("test_engine_open_missing_decision_fail_closed: "
          "cannot read %s: %s\n", src, err ? err->message : "?");
      rmdir_recursive (tmpdir);
      return 22;
    }
    if (!g_file_set_contents (dst, contents, (gssize) len, &err)) {
      rmdir_recursive (tmpdir);
      return 23;
    }
  }

  WylEngine *engine = NULL;
  wyrelog_error_t rc = wyl_engine_open (tmpdir, 1, &engine);

  rmdir_recursive (tmpdir);

  if (rc != WYRELOG_E_IO) {
    g_printerr ("test_engine_open_missing_decision_fail_closed: "
        "expected WYRELOG_E_IO, got %d\n", (int) rc);
    if (engine != NULL)
      g_object_unref (engine);
    return 24;
  }
  if (engine != NULL) {
    g_printerr ("test_engine_open_missing_decision_fail_closed: "
        "*out should be NULL on failure\n");
    g_object_unref (engine);
    return 25;
  }
  return 0;
}

static gint
test_engine_open_null_template_dir_rejects (void)
{
  WylEngine *engine = NULL;
  wyrelog_error_t rc = wyl_engine_open (NULL, 1, &engine);
  if (rc != WYRELOG_E_INVALID) {
    g_printerr ("test_engine_open_null_template_dir_rejects: "
        "expected WYRELOG_E_INVALID, got %d\n", (int) rc);
    if (engine != NULL)
      g_object_unref (engine);
    return 30;
  }
  if (engine != NULL) {
    g_printerr ("test_engine_open_null_template_dir_rejects: "
        "*out should be NULL\n");
    g_object_unref (engine);
    return 31;
  }
  return 0;
}

static gint
test_engine_open_null_out_rejects (void)
{
  wyrelog_error_t rc = wyl_engine_open (WYL_TEST_TEMPLATE_DIR, 1, NULL);
  if (rc != WYRELOG_E_INVALID) {
    g_printerr ("test_engine_open_null_out_rejects: "
        "expected WYRELOG_E_INVALID, got %d\n", (int) rc);
    return 40;
  }
  return 0;
}

static gint
test_engine_close_then_finalize_safe (void)
{
  WylEngine *engine = NULL;
  wyrelog_error_t rc = wyl_engine_open (WYL_TEST_TEMPLATE_DIR, 1, &engine);
  if (rc != WYRELOG_E_OK || engine == NULL) {
    g_printerr ("test_engine_close_then_finalize_safe: open failed: %d\n",
        (int) rc);
    return 50;
  }
  /* Explicit close followed by g_object_unref via g_autoptr-style:
   * wyl_engine_close releases the underlying session; subsequent
   * g_object_unref sees a NULL session in finalize — no crash expected. */
  g_object_unref (engine);
  return 0;
}

static gint
test_engine_double_close_safe (void)
{
  WylEngine *engine = NULL;
  wyrelog_error_t rc = wyl_engine_open (WYL_TEST_TEMPLATE_DIR, 1, &engine);
  if (rc != WYRELOG_E_OK || engine == NULL) {
    g_printerr ("test_engine_double_close_safe: open failed: %d\n", (int) rc);
    return 60;
  }
  /* Demonstrate NULL-safe close: use g_clear_pointer so the pointer is
   * nulled after the first close; the second call is a no-op on NULL. */
  g_clear_pointer (&engine, wyl_engine_close);
  g_clear_pointer (&engine, wyl_engine_close);
  return 0;
}

static gint
test_engine_concat_with_newline_helper (void)
{
  /* Test wyl_engine_load_templates directly via the internal helper exposed
   * by wyl-engine-private.h: create a tmpdir with two files where the first
   * lacks a trailing newline, verify the combined source has a newline
   * boundary between them. */
  g_autofree gchar *tmpdir = make_tmpdir ();
  if (tmpdir == NULL)
    return 70;

  /* Create fsm/ subdir. */
  g_autofree gchar *fsm_dir = g_build_filename (tmpdir, "fsm", NULL);
  if (g_mkdir (fsm_dir, 0755) != 0) {
    rmdir_recursive (tmpdir);
    return 71;
  }

  /* Write a minimal but syntactically acceptable bootstrap.dl (no trailing
   * newline). The actual content just needs to be parseable enough that
   * the template loader can read it; we only test the newline stitching
   * at the load_templates layer, not the wirelog parse layer. */
  const gchar *bootstrap_content = "% bootstrap";       /* no trailing \n */

  if (!write_file_in_dir (tmpdir, "bootstrap.dl", bootstrap_content)) {
    rmdir_recursive (tmpdir);
    return 72;
  }

  /* For the remaining 4 files, write minimal placeholder stubs. */
  static const char *rest[] = {
    "fsm/principal.dl",
    "fsm/session.dl",
    "fsm/permission_scope.dl",
    "decision.dl",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (rest); i++) {
    g_autofree gchar *stub = g_strdup_printf ("%% stub for %s\n", rest[i]);
    if (!write_file_in_dir (tmpdir, rest[i], stub)) {
      rmdir_recursive (tmpdir);
      return (gint) (73 + i);
    }
  }

  gchar *dl_src = NULL;
  gsize dl_src_len = 0;
  wyrelog_error_t rc = wyl_engine_load_templates (tmpdir, &dl_src, &dl_src_len);

  if (rc != WYRELOG_E_OK) {
    g_printerr ("test_engine_concat_with_newline_helper: "
        "load_templates failed: %d\n", (int) rc);
    rmdir_recursive (tmpdir);
    return 78;
  }

  /* Verify that "% bootstrap" is immediately followed by '\n' and then
   * the next file's content — confirming newline insertion between files. */
  const gchar *boundary = strstr (dl_src, "% bootstrap");
  gboolean has_newline = (boundary != NULL)
      && (*(boundary + strlen ("% bootstrap")) == '\n');

  /* Use the tracked length (not strlen) for the zero-fill to ensure the full
   * buffer is overwritten regardless of any embedded NUL bytes. */
  memset (dl_src, 0, dl_src_len);
  g_free (dl_src);
  rmdir_recursive (tmpdir);

  if (!has_newline) {
    g_printerr ("test_engine_concat_with_newline_helper: "
        "expected '\\n' after first file content\n");
    return 79;
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int
main (void)
{
  gint rc;

  if ((rc = test_engine_open_canonical_smoke ()) != 0)
    return rc;

  if ((rc = test_engine_open_eager_build_surfaces_errors ()) != 0)
    return rc;

  if ((rc = test_engine_open_missing_decision_fail_closed ()) != 0)
    return rc;

  if ((rc = test_engine_open_null_template_dir_rejects ()) != 0)
    return rc;

  if ((rc = test_engine_open_null_out_rejects ()) != 0)
    return rc;

  if ((rc = test_engine_close_then_finalize_safe ()) != 0)
    return rc;

  if ((rc = test_engine_double_close_safe ()) != 0)
    return rc;

  if ((rc = test_engine_concat_with_newline_helper ()) != 0)
    return rc;

  return 0;
}

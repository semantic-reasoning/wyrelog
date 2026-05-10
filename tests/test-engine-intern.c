/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>

#include "wyrelog/engine.h"

/* Allow direct access to internal struct fields for test_intern_after_close. */
#define WYL_ENGINE_INTERNAL 1
#include "wyrelog/wyl-engine-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

/* ------------------------------------------------------------------ */
/* Fixture helpers                                                     */
/* ------------------------------------------------------------------ */

/*
 * open_engine_from_real_templates:
 *
 * Opens a WylEngine backed by the canonical in-tree templates.
 * Returns WYRELOG_E_OK and sets *out on success.
 */
static wyrelog_error_t
open_engine_from_real_templates (WylEngine **out)
{
  return wyl_engine_open (WYL_TEST_TEMPLATE_DIR, 1, out);
}

typedef struct
{
  gint64 expected_id;
  guint matches;
} SeenSnapshotExpect;

static gchar *
make_tmpdir (void)
{
  g_autoptr (GError) err = NULL;
  gchar *dir = g_dir_make_tmp ("wyl-engine-compound-test-XXXXXX", &err);
  if (dir == NULL) {
    g_printerr ("make_tmpdir: %s\n", err ? err->message : "?");
    return NULL;
  }
  return dir;
}

static gboolean
write_file_in_dir (const gchar *dir, const gchar *filename,
    const gchar *contents)
{
  g_autofree gchar *path = g_build_filename (dir, filename, NULL);
  g_autoptr (GError) err = NULL;
  return g_file_set_contents (path, contents, -1, &err);
}

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

static gboolean
write_compound_templates (const gchar *dir)
{
  g_autofree gchar *fsm_dir = g_build_filename (dir, "fsm", NULL);
  if (g_mkdir (fsm_dir, 0755) != 0)
    return FALSE;
  g_autofree gchar *lobac_dir = g_build_filename (dir, "lobac", NULL);
  if (g_mkdir (lobac_dir, 0755) != 0)
    return FALSE;

  return write_file_in_dir (dir, "bootstrap.dl",
      ".decl event(id: int64, payload: scope_ctx/3 side)\n"
      ".decl seen(id: int64)\n" "seen(ID) :- event(ID, scope_ctx(_, _, _)).\n")
      && write_file_in_dir (dir, "fsm/principal.dl", "// principal stub\n")
      && write_file_in_dir (dir, "fsm/session.dl", "// session stub\n")
      && write_file_in_dir (dir, "fsm/permission_scope.dl",
      "// permission scope stub\n")
      && write_file_in_dir (dir, "lobac/decision.dl", "// decision stub\n");
}

static wyrelog_error_t
open_engine_from_compound_templates (gchar **tmpdir_out, WylEngine **out)
{
  *tmpdir_out = NULL;
  *out = NULL;

  g_autofree gchar *tmpdir = make_tmpdir ();
  if (tmpdir == NULL)
    return WYRELOG_E_IO;
  if (!write_compound_templates (tmpdir)) {
    rmdir_recursive (tmpdir);
    return WYRELOG_E_IO;
  }

  wyrelog_error_t rc = wyl_engine_open (tmpdir, 1, out);
  if (rc != WYRELOG_E_OK) {
    rmdir_recursive (tmpdir);
    return rc;
  }

  *tmpdir_out = g_steal_pointer (&tmpdir);
  return WYRELOG_E_OK;
}

static void
seen_snapshot_cb (const gchar *relation, const gint64 *row, guint ncols,
    gpointer user_data)
{
  SeenSnapshotExpect *expect = user_data;

  if (g_strcmp0 (relation, "seen") != 0 || ncols != 1)
    return;

  if (row[0] == expect->expected_id)
    expect->matches++;
}

/* ------------------------------------------------------------------ */
/* Test cases                                                          */
/* ------------------------------------------------------------------ */

/*
 * test_intern_nominal:
 *
 * Intern "alice", expect OK and a non-negative id.
 * Intern "alice" again; expect the same id (stable within a session).
 */
static gint
test_intern_nominal (void)
{
  WylEngine *engine = NULL;
  wyrelog_error_t rc = open_engine_from_real_templates (&engine);
  if (rc != WYRELOG_E_OK || engine == NULL) {
    g_printerr ("test_intern_nominal: open failed: %d\n", (int) rc);
    return 1;
  }

  gint64 id1 = -999;
  rc = wyl_engine_intern_symbol (engine, "alice", &id1);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("test_intern_nominal: first intern failed: %d\n", (int) rc);
    wyl_engine_close (engine);
    return 2;
  }
  if (id1 < 0) {
    g_printerr ("test_intern_nominal: id1 is negative: %" G_GINT64_FORMAT "\n",
        id1);
    wyl_engine_close (engine);
    return 3;
  }

  gint64 id2 = -999;
  rc = wyl_engine_intern_symbol (engine, "alice", &id2);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("test_intern_nominal: second intern failed: %d\n", (int) rc);
    wyl_engine_close (engine);
    return 4;
  }
  if (id1 != id2) {
    g_printerr ("test_intern_nominal: ids differ: %" G_GINT64_FORMAT
        " vs %" G_GINT64_FORMAT "\n", id1, id2);
    wyl_engine_close (engine);
    return 5;
  }

  wyl_engine_close (engine);
  return 0;
}

/*
 * test_intern_distinct:
 *
 * Intern "alice" and "bob"; their ids must differ.
 */
static gint
test_intern_distinct (void)
{
  WylEngine *engine = NULL;
  wyrelog_error_t rc = open_engine_from_real_templates (&engine);
  if (rc != WYRELOG_E_OK || engine == NULL) {
    g_printerr ("test_intern_distinct: open failed: %d\n", (int) rc);
    return 10;
  }

  gint64 id_alice = -999;
  rc = wyl_engine_intern_symbol (engine, "alice", &id_alice);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("test_intern_distinct: intern alice failed: %d\n", (int) rc);
    wyl_engine_close (engine);
    return 11;
  }

  gint64 id_bob = -999;
  rc = wyl_engine_intern_symbol (engine, "bob", &id_bob);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("test_intern_distinct: intern bob failed: %d\n", (int) rc);
    wyl_engine_close (engine);
    return 12;
  }

  if (id_alice == id_bob) {
    g_printerr ("test_intern_distinct: alice and bob share the same id: %"
        G_GINT64_FORMAT "\n", id_alice);
    wyl_engine_close (engine);
    return 13;
  }

  wyl_engine_close (engine);
  return 0;
}

/*
 * test_intern_null_self:
 *
 * Pass NULL as self; expect WYRELOG_E_INVALID.
 */
static gint
test_intern_null_self (void)
{
  gint64 id = -999;
  wyrelog_error_t rc = wyl_engine_intern_symbol (NULL, "alice", &id);
  if (rc != WYRELOG_E_INVALID) {
    g_printerr ("test_intern_null_self: expected WYRELOG_E_INVALID, got %d\n",
        (int) rc);
    return 20;
  }
  return 0;
}

/*
 * test_intern_null_symbol:
 *
 * Open engine, pass NULL symbol; expect WYRELOG_E_INVALID, no crash.
 */
static gint
test_intern_null_symbol (void)
{
  WylEngine *engine = NULL;
  wyrelog_error_t rc = open_engine_from_real_templates (&engine);
  if (rc != WYRELOG_E_OK || engine == NULL) {
    g_printerr ("test_intern_null_symbol: open failed: %d\n", (int) rc);
    return 30;
  }

  gint64 id = -999;
  rc = wyl_engine_intern_symbol (engine, NULL, &id);
  if (rc != WYRELOG_E_INVALID) {
    g_printerr ("test_intern_null_symbol: expected WYRELOG_E_INVALID, got %d\n",
        (int) rc);
    wyl_engine_close (engine);
    return 31;
  }

  wyl_engine_close (engine);
  return 0;
}

/*
 * test_intern_null_out:
 *
 * Open engine, pass NULL out; expect WYRELOG_E_INVALID, no crash.
 */
static gint
test_intern_null_out (void)
{
  WylEngine *engine = NULL;
  wyrelog_error_t rc = open_engine_from_real_templates (&engine);
  if (rc != WYRELOG_E_OK || engine == NULL) {
    g_printerr ("test_intern_null_out: open failed: %d\n", (int) rc);
    return 40;
  }

  rc = wyl_engine_intern_symbol (engine, "alice", NULL);
  if (rc != WYRELOG_E_INVALID) {
    g_printerr ("test_intern_null_out: expected WYRELOG_E_INVALID, got %d\n",
        (int) rc);
    wyl_engine_close (engine);
    return 41;
  }

  wyl_engine_close (engine);
  return 0;
}

/*
 * test_intern_empty_symbol:
 *
 * Intern the empty string ""; wirelog accepts it per contract.
 * Expect OK and a valid (non-negative) id.
 */
static gint
test_intern_empty_symbol (void)
{
  WylEngine *engine = NULL;
  wyrelog_error_t rc = open_engine_from_real_templates (&engine);
  if (rc != WYRELOG_E_OK || engine == NULL) {
    g_printerr ("test_intern_empty_symbol: open failed: %d\n", (int) rc);
    return 50;
  }

  gint64 id = -999;
  rc = wyl_engine_intern_symbol (engine, "", &id);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("test_intern_empty_symbol: expected WYRELOG_E_OK, got %d\n",
        (int) rc);
    wyl_engine_close (engine);
    return 51;
  }
  if (id < 0) {
    g_printerr ("test_intern_empty_symbol: id is negative: %"
        G_GINT64_FORMAT "\n", id);
    wyl_engine_close (engine);
    return 52;
  }

  wyl_engine_close (engine);
  return 0;
}

/*
 * test_intern_after_close:
 *
 * Simulate a "closed" engine by directly nulling the session pointer via
 * the private struct (WYL_ENGINE_INTERNAL). The implementation checks
 * self->session == NULL and must return WYRELOG_E_INVALID.
 */
static gint
test_intern_after_close (void)
{
  WylEngine *engine = NULL;
  wyrelog_error_t rc = open_engine_from_real_templates (&engine);
  if (rc != WYRELOG_E_OK || engine == NULL) {
    g_printerr ("test_intern_after_close: open failed: %d\n", (int) rc);
    return 60;
  }

  /* Simulate a closed engine: close the underlying session directly and
   * null the pointer so the engine object remains alive but sessionless. */
  wirelog_easy_close (engine->session);
  engine->session = NULL;

  gint64 id = -999;
  rc = wyl_engine_intern_symbol (engine, "alice", &id);

  /* Release the engine. finalize will see session == NULL and skip
   * wirelog_easy_close (g_clear_pointer is a no-op on NULL). */
  g_object_unref (engine);

  if (rc != WYRELOG_E_INVALID) {
    g_printerr ("test_intern_after_close: expected WYRELOG_E_INVALID, "
        "got %d\n", (int) rc);
    return 61;
  }
  return 0;
}

static gint
test_make_compound_invalid_args (void)
{
  WylEngine *engine = NULL;
  wyrelog_error_t rc = open_engine_from_real_templates (&engine);
  if (rc != WYRELOG_E_OK || engine == NULL) {
    g_printerr ("test_make_compound_invalid_args: open failed: %d\n", (int) rc);
    return 70;
  }

  wirelog_compound_arg_t args[1] = {
    {WIRELOG_TYPE_INT64, 123},
  };
  gint64 out = -1;

  if (wyl_engine_make_compound (NULL, "ctx", args, 1, &out)
      != WYRELOG_E_INVALID) {
    wyl_engine_close (engine);
    return 71;
  }
  if (wyl_engine_make_compound (engine, NULL, args, 1, &out)
      != WYRELOG_E_INVALID) {
    wyl_engine_close (engine);
    return 72;
  }
  if (wyl_engine_make_compound (engine, "", args, 1, &out)
      != WYRELOG_E_INVALID) {
    wyl_engine_close (engine);
    return 73;
  }
  if (wyl_engine_make_compound (engine, "ctx", NULL, 1, &out)
      != WYRELOG_E_INVALID) {
    wyl_engine_close (engine);
    return 74;
  }
  if (wyl_engine_make_compound (engine, "ctx", args, 0, &out)
      != WYRELOG_E_INVALID) {
    wyl_engine_close (engine);
    return 75;
  }
  if (wyl_engine_make_compound (engine, "ctx", args, 1, NULL)
      != WYRELOG_E_INVALID) {
    wyl_engine_close (engine);
    return 76;
  }

  wyl_engine_close (engine);
  return 0;
}

static gint
test_make_compound_side_relation_contract (void)
{
  WylEngine *engine = NULL;
  g_autofree gchar *tmpdir = NULL;
  wyrelog_error_t rc = open_engine_from_compound_templates (&tmpdir, &engine);
  if (rc != WYRELOG_E_OK || engine == NULL) {
    g_printerr ("test_make_compound_side_relation_contract: "
        "open failed: %d\n", (int) rc);
    return 80;
  }

  gint64 loc_class = -1;
  rc = wyl_engine_intern_symbol (engine, "trusted", &loc_class);
  if (rc != WYRELOG_E_OK) {
    wyl_engine_close (engine);
    rmdir_recursive (tmpdir);
    return 81;
  }

  wirelog_compound_arg_t args[3] = {
    {WIRELOG_TYPE_INT64, 1700000000},
    {WIRELOG_TYPE_STRING, loc_class},
    {WIRELOG_TYPE_INT64, 20},
  };
  gint64 handle = -1;
  rc = wyl_engine_make_compound (engine, "scope_ctx", args, 3, &handle);
  if (rc != WYRELOG_E_OK || handle <= 0) {
    g_printerr ("test_make_compound_side_relation_contract: "
        "compound failed: %d handle=%" G_GINT64_FORMAT "\n", (int) rc, handle);
    wyl_engine_close (engine);
    rmdir_recursive (tmpdir);
    return 82;
  }

  const gint64 row[2] = { 42, handle };
  rc = wyl_engine_insert (engine, "event", row, G_N_ELEMENTS (row));
  if (rc != WYRELOG_E_OK) {
    g_printerr ("test_make_compound_side_relation_contract: "
        "insert failed: %d\n", (int) rc);
    wyl_engine_close (engine);
    rmdir_recursive (tmpdir);
    return 83;
  }

  SeenSnapshotExpect expect = {
    .expected_id = row[0],
    .matches = 0,
  };
  rc = wyl_engine_snapshot (engine, "seen", seen_snapshot_cb, &expect);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("test_make_compound_side_relation_contract: "
        "snapshot failed: %d\n", (int) rc);
    wyl_engine_close (engine);
    rmdir_recursive (tmpdir);
    return 84;
  }

  wyl_engine_close (engine);
  rmdir_recursive (tmpdir);
  if (expect.matches != 1) {
    g_printerr ("test_make_compound_side_relation_contract: "
        "matches=%u\n", expect.matches);
    return 85;
  }

  return 0;
}

static gint
test_make_nested_compound_contract (void)
{
  WylEngine *engine = NULL;
  wyrelog_error_t rc = open_engine_from_real_templates (&engine);
  if (rc != WYRELOG_E_OK || engine == NULL) {
    g_printerr ("test_make_nested_compound_contract: open failed: %d\n",
        (int) rc);
    return 90;
  }

  gint64 loc_class = -1;
  rc = wyl_engine_intern_symbol (engine, "public", &loc_class);
  if (rc != WYRELOG_E_OK) {
    wyl_engine_close (engine);
    return 91;
  }

  wirelog_compound_arg_t metadata_args[3] = {
    {WIRELOG_TYPE_INT64, 1700000001},
    {WIRELOG_TYPE_STRING, loc_class},
    {WIRELOG_TYPE_INT64, 70},
  };
  gint64 metadata = -1;
  rc = wyl_engine_make_compound (engine, "metadata", metadata_args, 3,
      &metadata);
  if (rc != WYRELOG_E_OK || metadata <= 0) {
    wyl_engine_close (engine);
    return 92;
  }

  wirelog_compound_arg_t scope_args[2] = {
    {WIRELOG_TYPE_INT64, metadata},
    {WIRELOG_TYPE_INT64, 7},
  };
  gint64 scope = -1;
  rc = wyl_engine_make_compound (engine, "scope", scope_args, 2, &scope);
  if (rc != WYRELOG_E_OK || scope <= 0 || scope == metadata) {
    wyl_engine_close (engine);
    return 93;
  }

  wyl_engine_close (engine);
  return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int
main (void)
{
  gint rc;

  if ((rc = test_intern_nominal ()) != 0)
    return rc;

  if ((rc = test_intern_distinct ()) != 0)
    return rc;

  if ((rc = test_intern_null_self ()) != 0)
    return rc;

  if ((rc = test_intern_null_symbol ()) != 0)
    return rc;

  if ((rc = test_intern_null_out ()) != 0)
    return rc;

  if ((rc = test_intern_empty_symbol ()) != 0)
    return rc;

  if ((rc = test_intern_after_close ()) != 0)
    return rc;

  if ((rc = test_make_compound_invalid_args ()) != 0)
    return rc;

  if ((rc = test_make_compound_side_relation_contract ()) != 0)
    return rc;

  if ((rc = test_make_nested_compound_contract ()) != 0)
    return rc;

  return 0;
}

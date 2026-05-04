/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
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
  wl_easy_close (engine->session);
  engine->session = NULL;

  gint64 id = -999;
  rc = wyl_engine_intern_symbol (engine, "alice", &id);

  /* Release the engine. finalize will see session == NULL and skip
   * wl_easy_close (g_clear_pointer is a no-op on NULL). */
  g_object_unref (engine);

  if (rc != WYRELOG_E_INVALID) {
    g_printerr ("test_intern_after_close: expected WYRELOG_E_INVALID, "
        "got %d\n", (int) rc);
    return 61;
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

  return 0;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/wyl-handle-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

static gint
check_init_keeps_engines_absent (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 10;
  if (wyl_handle_get_read_engine (handle) != NULL)
    return 11;
  if (wyl_handle_get_delta_engine (handle) != NULL)
    return 12;
  return 0;
}

static gint
check_open_pair_creates_distinct_engines (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 20;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 21;
  WylEngine *read_engine = wyl_handle_get_read_engine (handle);
  WylEngine *delta_engine = wyl_handle_get_delta_engine (handle);
  if (read_engine == NULL)
    return 22;
  if (delta_engine == NULL)
    return 23;
  if (read_engine == delta_engine)
    return 24;
  return 0;
}

static gint
check_invalid_template_pair_open_fails_closed (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 30;
  if (wyl_handle_open_engine_pair (handle,
          "/definitely/not/a/wyrelog/template-dir")
      != WYRELOG_E_IO)
    return 31;
  if (wyl_handle_get_read_engine (handle) != NULL)
    return 32;
  if (wyl_handle_get_delta_engine (handle) != NULL)
    return 33;
  return 0;
}

static gint
check_shutdown_clears_engine_pair (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 40;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 41;
  wyl_shutdown (handle);
  if (wyl_handle_get_read_engine (handle) != NULL)
    return 42;
  if (wyl_handle_get_delta_engine (handle) != NULL)
    return 43;
  return 0;
}

static gint
check_second_open_is_rejected (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 50;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 51;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_INVALID)
    return 52;
  return 0;
}

static gint
check_symbol_intern_reaches_both_engines (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 pair_id = -1;
  gint64 read_id = -1;
  gint64 delta_id = -1;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 60;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 61;
  if (wyl_handle_intern_engine_symbol (handle, "pair-symbol-a", &pair_id)
      != WYRELOG_E_OK)
    return 62;
  if (pair_id < 0)
    return 63;
  if (wyl_engine_intern_symbol (wyl_handle_get_read_engine (handle),
          "pair-symbol-a", &read_id) != WYRELOG_E_OK)
    return 64;
  if (wyl_engine_intern_symbol (wyl_handle_get_delta_engine (handle),
          "pair-symbol-a", &delta_id) != WYRELOG_E_OK)
    return 65;
  if (pair_id != read_id)
    return 66;
  if (pair_id != delta_id)
    return 67;
  return 0;
}

static gint
check_symbol_intern_is_stable (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 first = -1;
  gint64 second = -1;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 70;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 71;
  if (wyl_handle_intern_engine_symbol (handle, "pair-symbol-b", &first)
      != WYRELOG_E_OK)
    return 72;
  if (wyl_handle_intern_engine_symbol (handle, "pair-symbol-b", &second)
      != WYRELOG_E_OK)
    return 73;
  if (first != second)
    return 74;
  return 0;
}

static gint
check_symbol_intern_rejects_missing_pair (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 id = -1;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 80;
  if (wyl_handle_intern_engine_symbol (handle, "pair-symbol-c", &id)
      != WYRELOG_E_INVALID)
    return 81;
  if (id != -1)
    return 82;
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_init_keeps_engines_absent ()) != 0)
    return rc;
  if ((rc = check_open_pair_creates_distinct_engines ()) != 0)
    return rc;
  if ((rc = check_invalid_template_pair_open_fails_closed ()) != 0)
    return rc;
  if ((rc = check_shutdown_clears_engine_pair ()) != 0)
    return rc;
  if ((rc = check_second_open_is_rejected ()) != 0)
    return rc;
  if ((rc = check_symbol_intern_reaches_both_engines ()) != 0)
    return rc;
  if ((rc = check_symbol_intern_is_stable ()) != 0)
    return rc;
  if ((rc = check_symbol_intern_rejects_missing_pair ()) != 0)
    return rc;

  return 0;
}

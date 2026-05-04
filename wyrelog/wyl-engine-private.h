/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <glib-object.h>

#include <wirelog/wl_easy.h>

#include "wyrelog/engine.h"
#include "wyrelog/error.h"

G_BEGIN_DECLS;

/* Number of policy template files loaded at open time. */
#define WYL_ENGINE_TEMPLATE_COUNT 5

struct _WylEngine
{
  GObject parent_instance;
  wl_easy_session_t *session;
  /* Logical path strings for diagnostic logging only; freed in finalize. */
  gchar *dl_src_logical_paths[WYL_ENGINE_TEMPLATE_COUNT];
};

/*
 * wyl_engine_map_wirelog_error:
 *
 * Maps a wirelog_error_t value from the underlying evaluator into the
 * project's wyrelog_error_t taxonomy.
 */
wyrelog_error_t wyl_engine_map_wirelog_error (wirelog_error_t wl_err);

/*
 * wyl_engine_load_templates:
 * @template_dir:    Directory containing the policy template files.
 * @dl_src_out:      (out) On success, receives a newly-allocated gchar*
 *                   containing all template file contents concatenated with
 *                   '\n' between files. Caller is responsible for zeroing and
 *                   freeing the buffer via memset(@dl_src_len_out bytes) +
 *                   g_free.
 * @dl_src_len_out:  (out) On success, receives the byte length of the buffer
 *                   pointed to by *@dl_src_out, not including the NUL
 *                   terminator. Use this value — not strlen() — for memset to
 *                   ensure every byte is overwritten regardless of embedded
 *                   NUL bytes. Must not be NULL.
 *
 * Reads the policy templates in a fixed dependency order and concatenates
 * them into a single source string suitable for passing to the evaluator.
 *
 * Returns: WYRELOG_E_OK on success, WYRELOG_E_IO if any file is missing or
 * unreadable, WYRELOG_E_NOMEM on allocation failure.
 */
wyrelog_error_t wyl_engine_load_templates (const gchar * template_dir,
    gchar ** dl_src_out, gsize * dl_src_len_out);

G_END_DECLS;

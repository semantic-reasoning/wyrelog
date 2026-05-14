/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <glib-object.h>

#include <wirelog/wirelog-easy.h>

#include "wyrelog/engine.h"
#include "wyrelog/error.h"

G_BEGIN_DECLS;

/* Number of policy template files loaded at open time. */
#define WYL_ENGINE_TEMPLATE_COUNT 5

typedef enum
{
  WYL_ENGINE_MODE_NONE = 0,
  WYL_ENGINE_MODE_STEP,
  WYL_ENGINE_MODE_SNAPSHOT,
} wyl_engine_mode_t;

typedef enum
{
  WYL_ENGINE_OWNER_STANDALONE = 0,
  WYL_ENGINE_OWNER_READ,
  WYL_ENGINE_OWNER_DELTA,
} wyl_engine_owner_t;

typedef struct _WylDeltaCookie WylDeltaCookie;

typedef struct
{
  guint32 version;
  gchar sha256_hex[65];
  guint32 migration_count;
  guint32 latest_migration_version;
} WylTemplateArtifactInfo;

struct _WylEngine
{
  GObject parent_instance;
  wirelog_easy_session_t *session;
  /* Logical path strings for diagnostic logging only; freed in finalize. */
  gchar *dl_src_logical_paths[WYL_ENGINE_TEMPLATE_COUNT];
  wyl_engine_mode_t mode;       /* Latched at first step or snapshot. */
  wyl_engine_owner_t owner;     /* Handle pair role, or standalone. */
  WylDeltaCookie *delta_cookie; /* Heap-owned, NULL when no cb. */
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
 *                   g_free. Must not be NULL.
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

wyrelog_error_t wyl_engine_verify_template_manifest (const gchar * template_dir,
    const gchar * dl_src, gsize dl_src_len, gboolean require_manifest,
    guint32 * template_version_out);
wyrelog_error_t wyl_engine_inspect_template_artifact (const gchar *
    template_dir, const gchar * dl_src, gsize dl_src_len,
    gboolean require_manifest, WylTemplateArtifactInfo * info_out);
wyrelog_error_t wyl_engine_open_with_options (const gchar * template_dir,
    guint32 num_workers, gboolean require_template_manifest, WylEngine ** out);
wyrelog_error_t wyl_engine_open_source (const gchar * dl_src,
    guint32 num_workers, WylEngine ** out);

/*
 * wyl_engine_make_compound:
 * @self: A `WylEngine` instance. Must not be NULL.
 * @functor: Compound functor name. Must not be NULL or empty.
 * @args: (array length=nargs): Typed compound arguments. Must not be NULL.
 * @nargs: Compound arity. Must be > 0.
 * @out_id: (out) Receives a session-local compound handle. Must not be NULL.
 *
 * Allocates a wirelog side-tier compound term in @self's evaluator session and
 * returns its handle. The handle is meaningful only within the owning engine
 * session and must not be persisted across engine reloads.
 *
 * Returns: WYRELOG_E_OK on success; WYRELOG_E_INVALID for invalid arguments
 * or a sessionless engine; WYRELOG_E_EXEC if the evaluator rejects the
 * allocation; WYRELOG_E_NOMEM for allocation failure.
 */
wyrelog_error_t wyl_engine_make_compound (WylEngine * self,
    const gchar * functor, const wirelog_compound_arg_t * args, gsize nargs,
    gint64 * out_id);

void wyl_engine_set_owner (WylEngine * self, wyl_engine_owner_t owner);
wyrelog_error_t wyl_engine_owned_intern_symbol (WylEngine * self,
    const gchar * symbol, gint64 * out_id);
wyrelog_error_t wyl_engine_owned_make_compound (WylEngine * self,
    const gchar * functor, const wirelog_compound_arg_t * args, gsize nargs,
    gint64 * out_id);
wyrelog_error_t wyl_engine_owned_insert (WylEngine * self,
    const gchar * relation, const gint64 * row, gsize ncols);
wyrelog_error_t wyl_engine_owned_remove (WylEngine * self,
    const gchar * relation, const gint64 * row, gsize ncols);
wyrelog_error_t wyl_engine_owned_step (WylEngine * self);
wyrelog_error_t wyl_engine_owned_set_delta_callback (WylEngine * self,
    WylDeltaCallback cb, gpointer user_data);

G_END_DECLS;

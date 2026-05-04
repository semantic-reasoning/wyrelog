/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <glib-object.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

/*
 * WylEngine - evaluator session handle.
 *
 * Loads access-control policy templates and opens an evaluator session.
 * Created with wyl_engine_open, shut down with wyl_engine_close,
 * released with g_object_unref (or g_autoptr(WylEngine) in scoped form).
 *
 * Thread safety: a WylEngine is NOT thread-safe. Callers must serialize
 * all access to a given instance. Independent instances may be used on
 * separate threads without coordination.
 */
typedef struct _WylEngine WylEngine;

#define WYL_TYPE_ENGINE (wyl_engine_get_type ())
G_DECLARE_FINAL_TYPE (WylEngine, wyl_engine, WYL, ENGINE, GObject)
/*
 * wyl_engine_open:
 * @template_dir: Path to the directory containing the policy template files.
 *                Must not be NULL.
 * @num_workers:  Number of worker threads for the underlying session. Pass 1
 *                for single-threaded use; 0 is internally clamped to 1.
 * @out:          (out) Receives the new engine handle on success.
 *                Set to NULL at function entry; left NULL on any failure.
 *
 * Reads the policy templates from @template_dir in a fixed dependency order,
 * concatenates them with explicit newline separators, and opens the underlying
 * evaluator session with eager build enabled — so any policy parse or plan
 * failure surfaces synchronously here rather than at first use.
 *
 * Returns: WYRELOG_E_OK on success. On failure, *out is NULL and the return
 * value describes the failure class: WYRELOG_E_INVALID for NULL arguments,
 * WYRELOG_E_IO for missing or unreadable templates, WYRELOG_E_POLICY for
 * policy parse or plan errors, WYRELOG_E_NOMEM for allocation failures,
 * WYRELOG_E_INTERNAL for unexpected evaluator errors.
 */
     wyrelog_error_t wyl_engine_open (const gchar *template_dir,
    guint32 num_workers, WylEngine **out);

/*
 * wyl_engine_close:
 * @engine: Engine to close (NULL-safe).
 *
 * Releases the engine and its underlying evaluator session. Equivalent to
 * g_clear_object when called on a g_autoptr-managed variable, but available
 * as an explicit close site for callers that do not use autoptr.
 */
     void wyl_engine_close (WylEngine *engine);

/*
 * wyl_engine_intern_symbol:
 * @self: A `WylEngine` instance.
 * @symbol: A symbolic string to be assigned a stable identifier.
 *   Must not be NULL.
 * @out_id: (out) On success, receives the integer identifier
 *   that the engine has registered for @symbol. Must not be NULL.
 *
 * Registers @symbol with the engine and returns its stable
 * integer identifier. Subsequent calls on the same engine with
 * the same @symbol return the same identifier. Identifiers are
 * stable for the lifetime of @self; identifiers from different
 * engine instances are not interchangeable.
 *
 * Returns: %WYRELOG_E_OK on success; %WYRELOG_E_INVALID if any
 *   argument is NULL or @self has been closed; %WYRELOG_E_INTERNAL
 *   if the engine cannot register the symbol.
 */
     wyrelog_error_t wyl_engine_intern_symbol (WylEngine *self,
    const gchar *symbol, gint64 *out_id);

G_END_DECLS;

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

/*
 * wyl_engine_insert:
 * @self: A `WylEngine` instance. Must not be NULL.
 * @relation: The relation name to insert into. Must not be NULL.
 * @row: (array length=ncols): The integer row values. Must not be
 *   NULL when @ncols > 0. Each value is either a raw integer or
 *   the stable identifier returned by wyl_engine_intern_symbol().
 * @ncols: The number of columns in @row. Must be > 0.
 *
 * Inserts a single row into the named relation. The evaluator accepts
 * the row as fact data; if the loaded program declares the relation
 * with a different arity, the insert fails with %WYRELOG_E_EXEC.
 *
 * Returns: %WYRELOG_E_OK on success; %WYRELOG_E_INVALID if any
 *   argument fails its precondition or @self has no live session;
 *   %WYRELOG_E_EXEC if the underlying engine rejects the row;
 *   other %WYRELOG_E_* codes on internal failure.
 */
     wyrelog_error_t wyl_engine_insert (WylEngine *self,
    const gchar *relation, const gint64 *row, gsize ncols);

/*
 * wyl_engine_remove:
 * @self: A `WylEngine` instance. Must not be NULL.
 * @relation: The relation name to retract from. Must not be NULL.
 * @row: (array length=ncols): The integer row values to retract.
 *   Must not be NULL when @ncols > 0.
 * @ncols: The number of columns in @row. Must be > 0.
 *
 * Retracts a single previously-inserted row from the named relation.
 * Removing a row that was never inserted is not an error; the engine
 * treats it as a no-op.
 *
 * Returns: %WYRELOG_E_OK on success; %WYRELOG_E_INVALID if any
 *   argument fails its precondition or @self has no live session;
 *   %WYRELOG_E_EXEC if the underlying engine rejects the row;
 *   other %WYRELOG_E_* codes on internal failure.
 */
     wyrelog_error_t wyl_engine_remove (WylEngine *self,
    const gchar *relation, const gint64 *row, gsize ncols);

/*
 * WylTupleCallback:
 * @relation: The relation name for the delivered tuple.  Borrowed
 *   from the engine; valid only for the duration of this callback.
 * @row: (array length=ncols): The integer row values.  Borrowed;
 *   the array must not be retained beyond the callback's return.
 * @ncols: The number of columns in @row.
 * @user_data: The user-data pointer passed to wyl_engine_snapshot().
 *
 * Invoked once per tuple during a snapshot.  The relation name
 * and row pointer are owned by the engine and are only valid for
 * the duration of the callback; if the caller wishes to retain
 * either, it must copy them.
 */
     typedef void (*WylTupleCallback) (const gchar *relation,
    const gint64 *row, guint ncols, gpointer user_data);

/*
 * wyl_engine_step:
 * @self: A `WylEngine` instance.  Must not be NULL.
 *
 * Advances the engine's queued evaluation work by one logical step,
 * processing any pending fact changes accumulated via wyl_engine_insert() /
 * wyl_engine_remove() since the last step.
 *
 * Calling wyl_engine_step() commits this engine to step mode for the rest of
 * its lifetime.  After a successful step call, wyl_engine_snapshot() returns
 * %WYRELOG_E_INVALID.  This is intentional: the underlying evaluator does
 * not allow mixing step advancement and snapshot probing on the same batch.
 *
 * Returns: %WYRELOG_E_OK on success; %WYRELOG_E_INVALID if @self is NULL,
 *   has no live session, or has already been used in snapshot mode; other
 *   %WYRELOG_E_* codes on internal failure.
 */
     wyrelog_error_t wyl_engine_step (WylEngine *self);

/*
 * wyl_engine_snapshot:
 * @self: A `WylEngine` instance.  Must not be NULL.
 * @relation: The relation name to probe.  Must not be NULL.
 * @cb: A callback invoked once per tuple of the relation.  Must
 *   not be NULL.
 * @user_data: Opaque pointer passed through to @cb.
 *
 * Probes the named relation and invokes @cb once per tuple in the relation's
 * current state.  Tuples are delivered in an unspecified order; do not rely
 * on a particular ordering.
 *
 * Calling wyl_engine_snapshot() commits this engine to snapshot mode for the
 * rest of its lifetime.  After a successful snapshot call, wyl_engine_step()
 * returns %WYRELOG_E_INVALID.  This is intentional: the underlying evaluator
 * does not allow mixing snapshot probing and step advancement on the same
 * batch.
 *
 * Returns: %WYRELOG_E_OK on success; %WYRELOG_E_INVALID if any argument is
 *   NULL, @self has no live session, or the engine has already been used in
 *   step mode; other %WYRELOG_E_* codes on internal failure.
 */
     wyrelog_error_t wyl_engine_snapshot (WylEngine *self,
    const gchar *relation, WylTupleCallback cb, gpointer user_data);

G_END_DECLS;

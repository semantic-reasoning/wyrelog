/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/engine.h"
#include "wyrelog/error.h"

G_BEGIN_DECLS;

/*
 * Canonical, typed runtime-map key.  Keeping the two fields separate avoids
 * delimiter aliases and makes ownership explicit at every cache boundary.
 */
typedef struct
{
  gchar *tenant_id;
  gchar *graph_id;
} WylFactGraphKey;

/*
 * Entry lifecycle states:
 *
 * EMPTY        A newly-created entry with no completed refresh.
 * BUILDING     One graph-local refresh owns the writer lock.  A previously
 *              published generation, if any, remains queryable.
 * READY        The latest refresh published a complete engine generation.
 * READY_STALE  The latest refresh failed, but the previous complete
 *              generation remains queryable.
 * DEGRADED     The latest refresh failed and no generation is queryable.
 * EVICTED      The current generation was detached.  The entry remains as a
 *              tombstone so its generation counters are not reset.
 * ABANDONED    Manager shutdown has made the entry terminal.  Existing
 *              snapshots remain usable, but no new work can be accepted.
 */
typedef enum
{
  WYL_FACT_GRAPH_RUNTIME_EMPTY = 0,
  WYL_FACT_GRAPH_RUNTIME_BUILDING,
  WYL_FACT_GRAPH_RUNTIME_READY,
  WYL_FACT_GRAPH_RUNTIME_READY_STALE,
  WYL_FACT_GRAPH_RUNTIME_DEGRADED,
  WYL_FACT_GRAPH_RUNTIME_EVICTED,
  WYL_FACT_GRAPH_RUNTIME_ABANDONED,
} WylFactGraphRuntimeState;

typedef enum
{
  WYL_FACT_GRAPH_REPLAY_NONE = 0,
  WYL_FACT_GRAPH_REPLAY_STORE_UNAVAILABLE,
  WYL_FACT_GRAPH_REPLAY_SCHEMA_MISMATCH,
  WYL_FACT_GRAPH_REPLAY_FAILED,
  WYL_FACT_GRAPH_REPLAY_INTERNAL,
} WylFactGraphReplayClass;

typedef struct
{
  WylFactGraphKey key;
  WylFactGraphRuntimeState state;
  WylFactGraphReplayClass last_replay_class;
  guint64 operation_generation;
  guint64 engine_generation;
  gboolean queryable;
  gboolean operation_active;
  guint active_snapshots;
  guint active_engine_calls;
  guint waiting_engine_calls;
  gint64 last_replay_at_us;
} WylFactGraphRuntimeStatus;

typedef struct _WylFactGraphRuntimeManager WylFactGraphRuntimeManager;
typedef struct _WylFactGraphSnapshot WylFactGraphSnapshot;

typedef wyrelog_error_t (*WylFactGraphBuildFunc) (const WylFactGraphKey * key,
    WylEngine ** out_engine, gpointer user_data);
typedef wyrelog_error_t (*WylFactGraphSnapshotFunc) (WylEngine * engine,
    gpointer user_data);
typedef wyrelog_error_t (*WylFactGraphRuntimeStatusFunc) (const
    WylFactGraphRuntimeStatus * status, gpointer user_data);

wyrelog_error_t wyl_fact_graph_key_init (WylFactGraphKey * key,
    const gchar * tenant_id, const gchar * graph_id);
wyrelog_error_t wyl_fact_graph_key_copy (const WylFactGraphKey * source,
    WylFactGraphKey * destination);
void wyl_fact_graph_key_clear (WylFactGraphKey * key);
guint wyl_fact_graph_key_hash (gconstpointer key);
gboolean wyl_fact_graph_key_equal (gconstpointer left, gconstpointer right);

const gchar *wyl_fact_graph_runtime_state_name (WylFactGraphRuntimeState state);
const gchar *wyl_fact_graph_replay_class_name
    (WylFactGraphReplayClass replay_class);
void wyl_fact_graph_runtime_status_clear (WylFactGraphRuntimeStatus * status);

/*
 * Runtime and generation contract
 * --------------------------------
 * The manager map is keyed by the exact (tenant_id, graph_id) pair.  Its map
 * lock covers lookup, entry creation, enumeration capture, and shutdown map
 * replacement only.  A build never runs under the map lock.  Each entry has
 * its own writer lock, so refreshes of one key are serialized while different
 * tenant/graph keys can build independently.
 *
 * A refresh accepted by an entry increments operation_generation exactly
 * once, before invoking the build callback.  A successful refresh atomically
 * replaces the whole current engine and increments engine_generation exactly
 * once.  Readers therefore see either the previous complete generation or
 * the replacement complete generation, never a partially-built engine.
 *
 * While the manager remains active, a refresh whose builder fails still
 * consumes its operation generation.  It does not change engine_generation
 * or detach the previous engine: the result is READY_STALE when a previous
 * engine exists and DEGRADED otherwise.  If shutdown wins during a build, the
 * consumed operation ends ABANDONED with WYRELOG_E_BUSY instead.
 * Generation counters are local to one key.  Eviction and retirement do not
 * increment or reset them, and a later refresh of an EVICTED tombstone
 * continues both counters monotonically.  If either counter is G_MAXUINT64,
 * refresh fails before calling the builder rather than wrapping a counter;
 * neither counter changes in that overflow case.
 *
 * WylFactGraphRuntimeStatus owns its copied key strings.  Clear it with
 * wyl_fact_graph_runtime_status_clear().  foreach_status snapshots all status
 * values before invoking callbacks, and invokes callbacks without manager or
 * entry locks held, so callbacks may re-enter manager status APIs.
 */
wyrelog_error_t wyl_fact_graph_runtime_manager_new
    (WylFactGraphRuntimeManager ** out_manager);
WylFactGraphRuntimeManager *wyl_fact_graph_runtime_manager_ref
    (WylFactGraphRuntimeManager * manager);
void wyl_fact_graph_runtime_manager_unref
    (WylFactGraphRuntimeManager * manager);
void wyl_fact_graph_runtime_manager_shutdown
    (WylFactGraphRuntimeManager * manager);

wyrelog_error_t wyl_fact_graph_runtime_manager_refresh
    (WylFactGraphRuntimeManager * manager, const WylFactGraphKey * key,
    WylFactGraphBuildFunc build, gpointer user_data,
    WylFactGraphRuntimeStatus * out_status);
wyrelog_error_t wyl_fact_graph_runtime_manager_get_status
    (WylFactGraphRuntimeManager * manager, const WylFactGraphKey * key,
    WylFactGraphRuntimeStatus * out_status);
wyrelog_error_t wyl_fact_graph_runtime_manager_foreach_status
    (WylFactGraphRuntimeManager * manager,
    WylFactGraphRuntimeStatusFunc callback, gpointer user_data);

/*
 * try_evict() is non-blocking with respect to an entry refresh.  It returns
 * WYRELOG_E_BUSY, leaves out_evicted FALSE, and changes nothing when the
 * writer lock is owned/contended, the entry is abandoned, or any snapshot is
 * pinned.  Success detaches the current engine, sets EVICTED, preserves both
 * generation counters, and sets out_evicted TRUE.  An already-empty or
 * already-evicted entry may be successfully re-marked EVICTED.
 *
 * retire_unseen() is the authoritative sweep used after a complete store
 * enumeration.  Every entry absent from seen_keys is serialized against its
 * writer, detached, and marked EVICTED without changing generation counters.
 * Unlike try_evict(), retirement may detach a generation while snapshots pin
 * it: those snapshots remain usable, while subsequent acquire calls return
 * WYRELOG_E_NOT_FOUND until a refresh republishes the tombstone.  Passing an
 * empty set retires every entry.  If shutdown races after the sweep captures
 * its entries, retirement still detaches an unseen current generation but
 * preserves ABANDONED instead of overwriting it with EVICTED.  Callers must
 * not use a partial enumeration as seen_keys.
 */
wyrelog_error_t wyl_fact_graph_runtime_manager_try_evict
    (WylFactGraphRuntimeManager * manager, const WylFactGraphKey * key,
    gboolean * out_evicted);
wyrelog_error_t wyl_fact_graph_runtime_manager_retire_unseen
    (WylFactGraphRuntimeManager * manager,
    const WylFactGraphKey * const *seen_keys, gsize n_seen_keys);

/*
 * Snapshot and shutdown contract
 * ------------------------------
 * A snapshot pins one immutable, complete engine generation independently of
 * later publication, retirement, or manager lifetime.  Acquiring while a
 * refresh builds returns the previously published generation when one exists.
 * Acquiring an entry without a current generation returns
 * WYRELOG_E_NOT_FOUND.
 *
 * snapshot_use() serializes engine callbacks across every old and current
 * generation belonging to the same entry because WylEngine is not
 * thread-safe; callbacks for different entries may run concurrently.  The
 * call takes a temporary self-reference, so a callback may release the
 * caller's snapshot reference safely.  Recursive snapshot_use() on the same
 * entry from its callback returns WYRELOG_E_INVALID.
 *
 * shutdown() is idempotent and linearizes when it marks the manager shut down
 * under the map lock.  A refresh(), get_status(), foreach_status(),
 * try_evict(), retire_unseen(), or acquire_snapshot() lookup/enumeration that
 * observes the manager after that point returns WYRELOG_E_BUSY.  Operations
 * admitted before that point may finish according to their entry-local race;
 * in particular, an in-flight refresh discards its build result and ends
 * ABANDONED instead of publishing it.  Snapshots acquired before shutdown
 * keep their entry and engine alive and remain usable even after the final
 * manager reference is released; their resources are destroyed after the
 * last snapshot/use reference is released.
 */
wyrelog_error_t wyl_fact_graph_runtime_manager_acquire_snapshot
    (WylFactGraphRuntimeManager * manager, const WylFactGraphKey * key,
    WylFactGraphSnapshot ** out_snapshot);
WylFactGraphSnapshot *wyl_fact_graph_snapshot_ref
    (WylFactGraphSnapshot * snapshot);
void wyl_fact_graph_snapshot_unref (WylFactGraphSnapshot * snapshot);
guint64 wyl_fact_graph_snapshot_engine_generation
    (const WylFactGraphSnapshot * snapshot);
wyrelog_error_t wyl_fact_graph_snapshot_use (WylFactGraphSnapshot * snapshot,
    WylFactGraphSnapshotFunc callback, gpointer user_data);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylFactGraphRuntimeManager,
    wyl_fact_graph_runtime_manager_unref)
    G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylFactGraphSnapshot,
    wyl_fact_graph_snapshot_unref)
    G_END_DECLS;

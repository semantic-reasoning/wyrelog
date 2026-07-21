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
 * The manager map lock covers only exact-entry lookup/creation and shutdown.
 * Builds run under an entry-local writer lock and never under the map lock.
 * Successful publication swaps one complete engine generation atomically.
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
 * Eviction leaves a tombstone in the manager so future publications continue
 * both monotonic generations.  Active operations or snapshots make eviction
 * retryable and return WYRELOG_E_BUSY without changing the entry.
 */
wyrelog_error_t wyl_fact_graph_runtime_manager_try_evict
    (WylFactGraphRuntimeManager * manager, const WylFactGraphKey * key,
    gboolean * out_evicted);

/*
 * A snapshot pins an immutable engine generation independently of manager
 * shutdown or a later swap.  Engine callbacks for old and new generations of
 * one entry share an entry-local operation lock because WylEngine itself is
 * not thread-safe.  Recursive use from the callback returns WYRELOG_E_INVALID.
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

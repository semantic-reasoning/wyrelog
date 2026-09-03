/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "runtime-private.h"

#include <string.h>

typedef struct _WylFactGraphRuntimeEntry WylFactGraphRuntimeEntry;

typedef struct
{
  gatomicrefcount ref_count;
  WylEngine *engine;
  guint64 generation;
} WylFactGraphEngineGeneration;

struct _WylFactGraphRuntimeEntry
{
  gatomicrefcount ref_count;
  WylFactGraphKey key;
  GMutex writer_lock;
  GMutex state_lock;
  GMutex engine_call_lock;
  GCond drain_cond;
  GThread *engine_call_owner;
  GThread *operation_owner;
  WylFactGraphEngineGeneration *current;
  WylFactGraphRuntimeState state;
  WylFactGraphReplayClass last_replay_class;
  guint64 operation_generation;
  guint64 engine_generation;
  guint active_snapshots;
  guint active_engine_calls;
  guint waiting_engine_calls;
  guint waiting_drains;
  gboolean operation_active;
  gboolean abandoned;
  gint64 last_replay_at_us;
  WylFactGraphForgetState forget_state;
  WylFactGraphAdmission admission;
};

struct _WylFactGraphRuntimeManager
{
  gatomicrefcount ref_count;
  GMutex map_lock;
  GHashTable *entries;
  gint shutdown;
};

struct _WylFactGraphSnapshot
{
  gatomicrefcount ref_count;
  WylFactGraphRuntimeEntry *entry;
  WylFactGraphEngineGeneration *generation;
};

static gchar *
try_strdup (const gchar *value)
{
  gsize length = strlen (value);
  gchar *copy = g_try_malloc (length + 1);
  if (copy != NULL)
    memcpy (copy, value, length + 1);
  return copy;
}

static gboolean
canonical_component_is_valid (const gchar *component)
{
  if (component == NULL)
    return FALSE;
  gsize length = strlen (component);
  if (length == 0 || length > 128 || g_strcmp0 (component, ".") == 0
      || g_strcmp0 (component, "..") == 0)
    return FALSE;

  for (const gchar * p = component; *p != '\0'; p++) {
    guchar c = (guchar) * p;
    if (!g_ascii_isalnum (c) && c != '.' && c != '_' && c != ':' && c != '-')
      return FALSE;
  }
  return TRUE;
}

static gboolean
canonical_graph_id_is_valid (const gchar *graph_id)
{
  return canonical_component_is_valid (graph_id)
         && g_strcmp0 (graph_id, "wr") != 0
         && !g_str_has_prefix (graph_id, "wr.")
         && !g_str_has_prefix (graph_id, "__wyrelog.");
}

wyrelog_error_t
wyl_fact_graph_key_init (WylFactGraphKey *key, const gchar *tenant_id,
    const gchar *graph_id)
{
  if (key == NULL)
    return WYRELOG_E_INVALID;
  memset (key, 0, sizeof *key);
  if (!canonical_component_is_valid (tenant_id)
      || !canonical_graph_id_is_valid (graph_id))
    return WYRELOG_E_INVALID;

  key->tenant_id = try_strdup (tenant_id);
  key->graph_id = try_strdup (graph_id);
  if (key->tenant_id == NULL || key->graph_id == NULL) {
    wyl_fact_graph_key_clear (key);
    return WYRELOG_E_NOMEM;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_graph_key_copy (const WylFactGraphKey *source,
    WylFactGraphKey *destination)
{
  if (source == NULL)
    return WYRELOG_E_INVALID;
  return wyl_fact_graph_key_init (destination, source->tenant_id,
             source->graph_id);
}

void
wyl_fact_graph_key_clear (WylFactGraphKey *key)
{
  if (key == NULL)
    return;
  g_clear_pointer (&key->tenant_id, g_free);
  g_clear_pointer (&key->graph_id, g_free);
}

guint
wyl_fact_graph_key_hash (gconstpointer data)
{
  const WylFactGraphKey *key = data;
  guint tenant_hash = g_str_hash (key->tenant_id);
  guint graph_hash = g_str_hash (key->graph_id);
  return tenant_hash ^ (graph_hash + 0x9e3779b9u + (tenant_hash << 6)
         + (tenant_hash >> 2));
}

gboolean
wyl_fact_graph_key_equal (gconstpointer left_data, gconstpointer right_data)
{
  const WylFactGraphKey *left = left_data;
  const WylFactGraphKey *right = right_data;
  return g_str_equal (left->tenant_id, right->tenant_id)
         && g_str_equal (left->graph_id, right->graph_id);
}

const gchar *
wyl_fact_graph_runtime_state_name (WylFactGraphRuntimeState state)
{
  switch (state) {
    case WYL_FACT_GRAPH_RUNTIME_EMPTY:
      return "empty";
    case WYL_FACT_GRAPH_RUNTIME_BUILDING:
      return "building";
    case WYL_FACT_GRAPH_RUNTIME_READY:
      return "ready";
    case WYL_FACT_GRAPH_RUNTIME_READY_STALE:
      return "ready_stale";
    case WYL_FACT_GRAPH_RUNTIME_DEGRADED:
      return "degraded";
    case WYL_FACT_GRAPH_RUNTIME_EVICTED:
      return "evicted";
    case WYL_FACT_GRAPH_RUNTIME_ABANDONED:
      return "abandoned";
    default:
      return "degraded";
  }
}

const gchar *
wyl_fact_graph_replay_class_name (WylFactGraphReplayClass replay_class)
{
  switch (replay_class) {
    case WYL_FACT_GRAPH_REPLAY_NONE:
      return "none";
    case WYL_FACT_GRAPH_REPLAY_STORE_UNAVAILABLE:
      return "store_unavailable";
    case WYL_FACT_GRAPH_REPLAY_SCHEMA_MISMATCH:
      return "schema_mismatch";
    case WYL_FACT_GRAPH_REPLAY_FAILED:
      return "replay_failed";
    case WYL_FACT_GRAPH_REPLAY_INTERNAL:
      return "internal";
    default:
      return "internal";
  }
}

const gchar *
wyl_fact_graph_admission_name (WylFactGraphAdmission admission)
{
  switch (admission) {
    case WYL_FACT_GRAPH_ADMISSION_OPEN:
      return "open";
    case WYL_FACT_GRAPH_ADMISSION_CLOSED:
      return "closed";
    default:
      return "unknown";
  }
}

void
wyl_fact_graph_runtime_status_clear (WylFactGraphRuntimeStatus *status)
{
  if (status == NULL)
    return;
  wyl_fact_graph_key_clear (&status->key);
  memset (status, 0, sizeof *status);
}

static WylFactGraphReplayClass
classify_replay_error (wyrelog_error_t rc)
{
  switch (rc) {
    case WYRELOG_E_IO:
    case WYRELOG_E_NOT_FOUND:
      return WYL_FACT_GRAPH_REPLAY_STORE_UNAVAILABLE;
    case WYRELOG_E_POLICY:
      return WYL_FACT_GRAPH_REPLAY_SCHEMA_MISMATCH;
    case WYRELOG_E_NOMEM:
    case WYRELOG_E_INTERNAL:
    case WYRELOG_E_INVALID:
      return WYL_FACT_GRAPH_REPLAY_INTERNAL;
    default:
      return WYL_FACT_GRAPH_REPLAY_FAILED;
  }
}

static WylFactGraphEngineGeneration *
engine_generation_new (WylEngine *engine)
{
  WylFactGraphEngineGeneration *generation =
      g_try_new0 (WylFactGraphEngineGeneration, 1);
  if (generation == NULL)
    return NULL;
  g_atomic_ref_count_init (&generation->ref_count);
  generation->engine = engine;
  return generation;
}

static WylFactGraphEngineGeneration *
engine_generation_ref (WylFactGraphEngineGeneration *generation)
{
  g_atomic_ref_count_inc (&generation->ref_count);
  return generation;
}

static void
engine_generation_unref (WylFactGraphEngineGeneration *generation)
{
  if (generation == NULL || !g_atomic_ref_count_dec (&generation->ref_count))
    return;
  g_clear_object (&generation->engine);
  g_free (generation);
}

static void runtime_entry_unref (WylFactGraphRuntimeEntry * entry);

static WylFactGraphRuntimeEntry *
runtime_entry_ref (WylFactGraphRuntimeEntry *entry)
{
  g_atomic_ref_count_inc (&entry->ref_count);
  return entry;
}

static wyrelog_error_t
runtime_entry_new (const WylFactGraphKey *key,
    WylFactGraphRuntimeEntry **out_entry)
{
  *out_entry = NULL;
  WylFactGraphRuntimeEntry *entry = g_try_new0 (WylFactGraphRuntimeEntry, 1);
  if (entry == NULL)
    return WYRELOG_E_NOMEM;
  g_atomic_ref_count_init (&entry->ref_count);
  g_mutex_init (&entry->writer_lock);
  g_mutex_init (&entry->state_lock);
  g_mutex_init (&entry->engine_call_lock);
  g_cond_init (&entry->drain_cond);
  wyrelog_error_t rc = wyl_fact_graph_key_copy (key, &entry->key);
  if (rc != WYRELOG_E_OK) {
    runtime_entry_unref (entry);
    return rc;
  }
  entry->state = WYL_FACT_GRAPH_RUNTIME_EMPTY;
  *out_entry = entry;
  return WYRELOG_E_OK;
}

static void
runtime_entry_unref (WylFactGraphRuntimeEntry *entry)
{
  if (entry == NULL || !g_atomic_ref_count_dec (&entry->ref_count))
    return;
  g_assert_cmpuint (entry->active_snapshots, ==, 0);
  g_assert_cmpuint (entry->active_engine_calls, ==, 0);
  g_assert_cmpuint (entry->waiting_engine_calls, ==, 0);
  g_assert_cmpuint (entry->waiting_drains, ==, 0);
  g_assert_false (entry->operation_active);
  g_assert_null (entry->engine_call_owner);
  g_assert_null (entry->operation_owner);
  engine_generation_unref (entry->current);
  wyl_fact_graph_key_clear (&entry->key);
  g_cond_clear (&entry->drain_cond);
  g_mutex_clear (&entry->engine_call_lock);
  g_mutex_clear (&entry->state_lock);
  g_mutex_clear (&entry->writer_lock);
  g_free (entry);
}

static wyrelog_error_t
status_fill_locked (WylFactGraphRuntimeEntry *entry,
    WylFactGraphRuntimeStatus *out_status)
{
  out_status->state = entry->state;
  out_status->last_replay_class = entry->last_replay_class;
  out_status->operation_generation = entry->operation_generation;
  out_status->engine_generation = entry->engine_generation;
  out_status->queryable = entry->current != NULL && !entry->abandoned;
  out_status->operation_active = entry->operation_active;
  out_status->active_snapshots = entry->active_snapshots;
  out_status->active_engine_calls = entry->active_engine_calls;
  out_status->waiting_engine_calls = entry->waiting_engine_calls;
  out_status->waiting_drains = entry->waiting_drains;
  out_status->last_replay_at_us = entry->last_replay_at_us;
  out_status->forget_state = entry->forget_state;
  out_status->admission = entry->admission;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
status_copy_locked (WylFactGraphRuntimeEntry *entry,
    WylFactGraphRuntimeStatus *out_status)
{
  memset (out_status, 0, sizeof *out_status);
  wyrelog_error_t rc = wyl_fact_graph_key_copy (&entry->key,
          &out_status->key);
  if (rc != WYRELOG_E_OK)
    return rc;
  status_fill_locked (entry, out_status);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
status_copy (WylFactGraphRuntimeEntry *entry,
    WylFactGraphRuntimeStatus *out_status)
{
  g_mutex_lock (&entry->state_lock);
  wyrelog_error_t rc = status_copy_locked (entry, out_status);
  g_mutex_unlock (&entry->state_lock);
  return rc;
}

wyrelog_error_t
wyl_fact_graph_runtime_manager_new (WylFactGraphRuntimeManager **out_manager)
{
  if (out_manager == NULL)
    return WYRELOG_E_INVALID;
  *out_manager = NULL;
  WylFactGraphRuntimeManager *manager =
      g_try_new0 (WylFactGraphRuntimeManager, 1);
  if (manager == NULL)
    return WYRELOG_E_NOMEM;
  g_atomic_ref_count_init (&manager->ref_count);
  g_mutex_init (&manager->map_lock);
  manager->entries = g_hash_table_new_full (wyl_fact_graph_key_hash,
          wyl_fact_graph_key_equal, NULL, (GDestroyNotify) runtime_entry_unref);
  *out_manager = manager;
  return WYRELOG_E_OK;
}

WylFactGraphRuntimeManager *
wyl_fact_graph_runtime_manager_ref (WylFactGraphRuntimeManager *manager)
{
  if (manager != NULL)
    g_atomic_ref_count_inc (&manager->ref_count);
  return manager;
}

void
wyl_fact_graph_runtime_manager_shutdown (WylFactGraphRuntimeManager *manager)
{
  if (manager == NULL)
    return;

  g_mutex_lock (&manager->map_lock);
  if (g_atomic_int_get (&manager->shutdown)) {
    g_mutex_unlock (&manager->map_lock);
    return;
  }
  g_atomic_int_set (&manager->shutdown, TRUE);
  g_autoptr (GPtrArray) entries =
      g_ptr_array_new_with_free_func ((GDestroyNotify) runtime_entry_unref);
  GHashTableIter iter;
  gpointer value = NULL;
  g_hash_table_iter_init (&iter, manager->entries);
  while (g_hash_table_iter_next (&iter, NULL, &value))
    g_ptr_array_add (entries, runtime_entry_ref (value));
  GHashTable *old_entries = manager->entries;
  manager->entries = g_hash_table_new_full (wyl_fact_graph_key_hash,
          wyl_fact_graph_key_equal, NULL, (GDestroyNotify) runtime_entry_unref);
  g_mutex_unlock (&manager->map_lock);

  for (guint i = 0; i < entries->len; i++) {
    WylFactGraphRuntimeEntry *entry = g_ptr_array_index (entries, i);
    g_mutex_lock (&entry->state_lock);
    entry->abandoned = TRUE;
    entry->state = WYL_FACT_GRAPH_RUNTIME_ABANDONED;
    g_cond_broadcast (&entry->drain_cond);
    g_mutex_unlock (&entry->state_lock);
  }
  g_hash_table_destroy (old_entries);
}

void
wyl_fact_graph_runtime_manager_unref (WylFactGraphRuntimeManager *manager)
{
  if (manager == NULL || !g_atomic_ref_count_dec (&manager->ref_count))
    return;
  wyl_fact_graph_runtime_manager_shutdown (manager);
  g_hash_table_destroy (manager->entries);
  g_mutex_clear (&manager->map_lock);
  g_free (manager);
}

static wyrelog_error_t
manager_lookup_entry (WylFactGraphRuntimeManager *manager,
    const WylFactGraphKey *key, gboolean create,
    WylFactGraphRuntimeEntry **out_entry)
{
  *out_entry = NULL;
  if (manager == NULL || key == NULL
      || !canonical_component_is_valid (key->tenant_id)
      || !canonical_graph_id_is_valid (key->graph_id))
    return WYRELOG_E_INVALID;

  WylFactGraphRuntimeEntry *candidate = NULL;
  if (create) {
    wyrelog_error_t rc = runtime_entry_new (key, &candidate);
    if (rc != WYRELOG_E_OK)
      return rc;
  }

  g_mutex_lock (&manager->map_lock);
  if (g_atomic_int_get (&manager->shutdown)) {
    g_mutex_unlock (&manager->map_lock);
    runtime_entry_unref (candidate);
    return WYRELOG_E_BUSY;
  }
  WylFactGraphRuntimeEntry *entry = g_hash_table_lookup (manager->entries,
          key);
  if (entry == NULL && candidate != NULL) {
    entry = candidate;
    candidate = NULL;
    g_hash_table_insert (manager->entries, &entry->key, entry);
  }
  if (entry != NULL)
    runtime_entry_ref (entry);
  g_mutex_unlock (&manager->map_lock);
  runtime_entry_unref (candidate);
  if (entry == NULL)
    return WYRELOG_E_NOT_FOUND;
  *out_entry = entry;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_graph_runtime_manager_refresh (WylFactGraphRuntimeManager *manager,
    const WylFactGraphKey *key, WylFactGraphBuildFunc build,
    gpointer user_data, WylFactGraphRuntimeStatus *out_status)
{
  if (out_status != NULL)
    memset (out_status, 0, sizeof *out_status);
  if (build == NULL)
    return WYRELOG_E_INVALID;
  WylFactGraphRuntimeEntry *entry = NULL;
  wyrelog_error_t rc = manager_lookup_entry (manager, key, TRUE, &entry);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (out_status != NULL) {
    rc = wyl_fact_graph_key_copy (&entry->key, &out_status->key);
    if (rc != WYRELOG_E_OK) {
      runtime_entry_unref (entry);
      return rc;
    }
  }

  g_mutex_lock (&entry->writer_lock);
  g_mutex_lock (&entry->state_lock);
  if (entry->abandoned || g_atomic_int_get (&manager->shutdown)) {
    g_mutex_unlock (&entry->state_lock);
    g_mutex_unlock (&entry->writer_lock);
    if (out_status != NULL)
      wyl_fact_graph_runtime_status_clear (out_status);
    runtime_entry_unref (entry);
    return WYRELOG_E_BUSY;
  }
  /* Fill out_status rather than clearing it, so a caller can tell a barrier
   * from a manager going away.  The rule has a precedence and it is not
   * "filled means barrier": the post-build shutdown race below also fills,
   * and a graph closed mid-build then shut down fills a status that is
   * ABANDONED and CLOSED at once.  Read state first, admission second.
   *
   * Refused here, before the generation ceiling, so that a closed graph is
   * never stamped with a health verdict.  The ceiling path consumes no
   * generation either, so that is not the distinction -- what this ordering
   * buys is that a refusal writes neither state nor last_replay_class. */
  if (entry->admission == WYL_FACT_GRAPH_ADMISSION_CLOSED) {
    if (out_status != NULL)
      status_fill_locked (entry, out_status);
    g_mutex_unlock (&entry->state_lock);
    g_mutex_unlock (&entry->writer_lock);
    runtime_entry_unref (entry);
    return WYRELOG_E_BUSY;
  }
  /* Argued, not proved: like the post-build failure path below, this must not
   * touch forget_state, because a generation ceiling says nothing about
   * whether an erasure converged.  No test falsifies it -- nothing reaches
   * G_MAXUINT64 without a seam, and a seam is not worth adding to prove a
   * comment -- so clearing the axis here would survive the suite.  The
   * post-build sibling IS proved; this one rests on inspection. */
  if (entry->operation_generation == G_MAXUINT64
      || entry->engine_generation == G_MAXUINT64) {
    entry->state = entry->current == NULL
        ? WYL_FACT_GRAPH_RUNTIME_DEGRADED : WYL_FACT_GRAPH_RUNTIME_READY_STALE;
    entry->last_replay_class = WYL_FACT_GRAPH_REPLAY_INTERNAL;
    entry->last_replay_at_us = g_get_real_time ();
    if (out_status != NULL)
      status_fill_locked (entry, out_status);
    g_mutex_unlock (&entry->state_lock);
    g_mutex_unlock (&entry->writer_lock);
    runtime_entry_unref (entry);
    return WYRELOG_E_INTERNAL;
  }
  entry->operation_generation++;
  entry->operation_active = TRUE;
  entry->operation_owner = g_thread_self ();
  entry->state = WYL_FACT_GRAPH_RUNTIME_BUILDING;
  g_mutex_unlock (&entry->state_lock);

  WylEngine *engine = NULL;
  rc = build (&entry->key, &engine, user_data);
  if (rc == WYRELOG_E_OK && (engine == NULL || !WYL_IS_ENGINE (engine)))
    rc = WYRELOG_E_INTERNAL;
  WylFactGraphEngineGeneration *replacement = NULL;
  if (rc == WYRELOG_E_OK) {
    replacement = engine_generation_new (engine);
    if (replacement == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  if (rc != WYRELOG_E_OK && engine != NULL)
    g_object_unref (engine);

  WylFactGraphEngineGeneration *old = NULL;
  g_mutex_lock (&entry->state_lock);
  entry->operation_active = FALSE;
  entry->operation_owner = NULL;
  g_cond_broadcast (&entry->drain_cond);
  entry->last_replay_at_us = g_get_real_time ();
  if (entry->abandoned || g_atomic_int_get (&manager->shutdown)) {
    entry->abandoned = TRUE;
    entry->state = WYL_FACT_GRAPH_RUNTIME_ABANDONED;
    rc = WYRELOG_E_BUSY;
  } else if (rc == WYRELOG_E_OK) {
    replacement->generation = ++entry->engine_generation;
    old = entry->current;
    entry->current = replacement;
    replacement = NULL;
    entry->state = WYL_FACT_GRAPH_RUNTIME_READY;
    entry->last_replay_class = WYL_FACT_GRAPH_REPLAY_NONE;
  } else {
    entry->state = entry->current == NULL
        ? WYL_FACT_GRAPH_RUNTIME_DEGRADED : WYL_FACT_GRAPH_RUNTIME_READY_STALE;
    entry->last_replay_class = classify_replay_error (rc);
  }
  if (out_status != NULL)
    status_fill_locked (entry, out_status);
  g_mutex_unlock (&entry->state_lock);
  engine_generation_unref (old);
  engine_generation_unref (replacement);
  g_mutex_unlock (&entry->writer_lock);
  runtime_entry_unref (entry);
  return rc;
}

wyrelog_error_t
wyl_fact_graph_runtime_manager_set_forget_state
  (WylFactGraphRuntimeManager * manager, const WylFactGraphKey * key,
    WylFactGraphForgetState forget_state) {
  WylFactGraphRuntimeEntry *entry = NULL;
  /* create = FALSE: this reports on a graph the runtime already holds and must
   * never fabricate an entry for a key it does not.  NOT_FOUND therefore means
   * only that no entry has ever existed for this key -- a retired or evicted
   * entry stays mapped as a tombstone, and is refused below rather than
   * here. */
  wyrelog_error_t rc = manager_lookup_entry (manager, key, FALSE, &entry);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_mutex_lock (&entry->state_lock);
  /* Refuse a tombstone, atomically with the write under the lock already
   * held.  This and the reset performed by try_evict and retire_unseen cover
   * disjoint orderings and neither is redundant: the reset clears a verdict
   * written BEFORE the tombstone, and this refuses one arriving AFTER it.
   * Removing either restores the defect the other does not cover -- without
   * the reset a pre-existing INCOMPLETE survives retirement, and without this
   * a verdict landing just after a reset re-poisons the tombstone, so a later
   * refresh republishes a predecessor's erasure onto a READY graph.
   *
   * Writing the axis onto a tombstone is never useful in any case: the status
   * reader skips EVICTED, and if the entry is republished the value describes
   * a graph that was never probed.  Refusing a CONVERGED write is harmless,
   * because the tombstone site has already written CONVERGED.
   *
   * abandoned is checked for the same reason one step further out: it follows
   * shutdown, and the lookup above already refuses a shut-down manager, so
   * this closes the window between that lookup releasing map_lock and this
   * taking state_lock. */
  if (entry->abandoned || entry->state == WYL_FACT_GRAPH_RUNTIME_EVICTED)
    rc = WYRELOG_E_BUSY;
  else
    entry->forget_state = forget_state;
  g_mutex_unlock (&entry->state_lock);
  runtime_entry_unref (entry);
  return rc;
}

static wyrelog_error_t
set_admission (WylFactGraphRuntimeManager *manager,
    const WylFactGraphKey *key, WylFactGraphAdmission admission)
{
  WylFactGraphRuntimeEntry *entry = NULL;
  /* create = FALSE for the same reason set_forget_state uses it: this acts on
   * a graph the runtime already holds and must never fabricate one.  A key
   * the runtime has never seen is NOT_FOUND, not a closed graph -- closing
   * something that does not exist would report a barrier nothing enforces. */
  wyrelog_error_t rc = manager_lookup_entry (manager, key, FALSE, &entry);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_mutex_lock (&entry->state_lock);
  /* Argued, not proved: abandoned closes the window between the lookup
   * releasing map_lock and this taking state_lock, exactly as in
   * set_forget_state.  No test falsifies it -- the lookup already refuses a
   * shut-down manager, so reaching this branch needs an interleaving no
   * single-threaded test can produce, and deleting the branch leaves the
   * suite green.  A seam to force it is not worth its own production code
   * path; the guard stays because the window is real, not because a test
   * says so.
   *
   * A tombstone is NOT refused here, unlike in set_forget_state.  That
   * asymmetry is deliberate and load-bearing: an EVICTED entry can be
   * republished by a later refresh, and a caller closing admission wants that
   * republication refused too.  Refusing EVICTED would let a close that raced
   * a retirement sweep silently lose its barrier. */
  if (entry->abandoned) {
    rc = WYRELOG_E_BUSY;
  } else {
    entry->admission = admission;
    /* Wake any parked drain.  Reopening makes a drain's answer meaningless --
     * the graph is admitting again -- and the drain re-tests admission on
     * every wakeup, so without this broadcast it would keep waiting for a
     * graph it can no longer report on until something else happened to
     * signal.  Closing broadcasts too, harmlessly: a drain already parked is
     * on a closed graph by construction. */
    g_cond_broadcast (&entry->drain_cond);
  }
  g_mutex_unlock (&entry->state_lock);
  runtime_entry_unref (entry);
  return rc;
}

wyrelog_error_t
wyl_fact_graph_runtime_manager_close_admission
  (WylFactGraphRuntimeManager * manager, const WylFactGraphKey * key)
{
  return set_admission (manager, key, WYL_FACT_GRAPH_ADMISSION_CLOSED);
}

wyrelog_error_t
wyl_fact_graph_runtime_manager_open_admission
  (WylFactGraphRuntimeManager * manager, const WylFactGraphKey * key)
{
  return set_admission (manager, key, WYL_FACT_GRAPH_ADMISSION_OPEN);
}

/* Admitted work is exactly the three bounded counters.  active_snapshots is
 * NOT among them and must never be: a caller may hold a snapshot for as long
 * as it likes -- the contract says a snapshot outlives even the manager -- so
 * waiting on it would let one idle reader stall a drain forever.  A pinned
 * snapshot is possession, not an operation in flight. */
static gboolean
entry_drained_locked (const WylFactGraphRuntimeEntry *entry)
{
  return !entry->operation_active && entry->active_engine_calls == 0
         && entry->waiting_engine_calls == 0;
}

wyrelog_error_t
wyl_fact_graph_runtime_manager_drain
  (WylFactGraphRuntimeManager * manager, const WylFactGraphKey * key,
    gint64 timeout_us, WylFactGraphRuntimeStatus * out_status)
{
  if (out_status != NULL)
    memset (out_status, 0, sizeof *out_status);
  WylFactGraphRuntimeEntry *entry = NULL;
  wyrelog_error_t rc = manager_lookup_entry (manager, key, FALSE, &entry);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (out_status != NULL) {
    rc = wyl_fact_graph_key_copy (&entry->key, &out_status->key);
    if (rc != WYRELOG_E_OK) {
      runtime_entry_unref (entry);
      return rc;
    }
  }

  gboolean timed_out = FALSE;
  /* Clamped rather than added blind: g_get_monotonic_time () + timeout_us
   * overflows for a large timeout, and a negative deadline makes
   * g_cond_wait_until return immediately -- so a caller asking for a very
   * long bounded wait would get an instant BUSY, the opposite of the
   * request. */
  gint64 now = g_get_monotonic_time ();
  gint64 deadline = 0;
  if (timeout_us > 0) {
    deadline = timeout_us > G_MAXINT64 - now ? G_MAXINT64 : now + timeout_us;
  }
  g_mutex_lock (&entry->state_lock);
  /* Refuse a drain issued from inside this entry's own engine callback or its
   * own build callback.  Either would wait on a term the calling frame is
   * itself holding -- active_engine_calls in the first case, operation_active
   * in the second -- and nothing else can clear it, so the wait is a
   * self-deadlock rather than a slow answer.  Both are turned into an error
   * for that reason.  The same thread draining a DIFFERENT entry is legal, as
   * the status readers already are. */
  GThread *self = g_thread_self ();
  if (entry->engine_call_owner == self || entry->operation_owner == self)
    rc = WYRELOG_E_INVALID;
  while (rc == WYRELOG_E_OK) {
    /* entry->abandoned is tested FIRST on purpose, and the order is
     * load-bearing rather than stylistic.  A parked drain holds no manager
     * reference; shutdown sets abandoned under this same state_lock before it
     * broadcasts, so a woken drain that reads abandoned never evaluates the
     * right-hand side and never touches a manager that may already be freed.
     * Swapping these introduces a use-after-free.
     *
     * Testing it before admission also moved the first-iteration answer for
     * an abandoned entry from INVALID to BUSY.  No caller can observe that:
     * abandoned is only ever set under shutdown, and the lookup already
     * refuses a shut-down manager.  It is also the order the contract's own
     * "read state first" precedence implies. */
    if (entry->abandoned || g_atomic_int_get (&manager->shutdown)) {
      rc = WYRELOG_E_BUSY;
      break;
    }
    /* Re-tested every wakeup, not once before the loop.  A graph reopened
     * while the drain was parked is admitting new work again, so returning OK
     * for it would be exactly the stale answer the refusal below exists to
     * prevent. */
    if (entry->admission == WYL_FACT_GRAPH_ADMISSION_OPEN) {
      rc = WYRELOG_E_INVALID;
      break;
    }
    if (entry_drained_locked (entry))
      break;
    if (timeout_us == 0 || timed_out) {
      rc = WYRELOG_E_BUSY;
      break;
    }
    /* Counted so a caller -- and a test -- can see that a drain is parked
     * rather than merely slow.  waiting_engine_calls sets the precedent: this
     * runtime reports what it is waiting on, not just that it is waiting. */
    entry->waiting_drains++;
    if (timeout_us < 0) {
      g_cond_wait (&entry->drain_cond, &entry->state_lock);
      entry->waiting_drains--;
      continue;
    }
    gboolean signalled = g_cond_wait_until (&entry->drain_cond,
            &entry->state_lock, deadline);
    entry->waiting_drains--;
    /* Argued, not proved: do not answer from the wait's return value.  A
     * broadcast landing just before the deadline, or the lock being
     * reacquired after it, would otherwise report BUSY with a status showing
     * nothing outstanding -- contradicting the promise that a timeout names
     * what is still running.  Reverting this leaves the suite green, because
     * that window is not deterministically reachable from a test; the old
     * form was sound too, since BUSY never falsely claimed drained.  Kept
     * because the loop top is the only place that can answer correctly. */
    if (!signalled)
      timed_out = TRUE;
  }
  if (out_status != NULL)
    status_fill_locked (entry, out_status);
  g_mutex_unlock (&entry->state_lock);
  runtime_entry_unref (entry);
  return rc;
}

wyrelog_error_t
wyl_fact_graph_runtime_manager_get_status (WylFactGraphRuntimeManager *manager,
    const WylFactGraphKey *key, WylFactGraphRuntimeStatus *out_status)
{
  if (out_status == NULL)
    return WYRELOG_E_INVALID;
  WylFactGraphRuntimeEntry *entry = NULL;
  wyrelog_error_t rc = manager_lookup_entry (manager, key, FALSE, &entry);
  if (rc == WYRELOG_E_OK) {
    rc = status_copy (entry, out_status);
    runtime_entry_unref (entry);
  }
  return rc;
}

static void
runtime_status_free (gpointer data)
{
  WylFactGraphRuntimeStatus *status = data;
  wyl_fact_graph_runtime_status_clear (status);
  g_free (status);
}

wyrelog_error_t
wyl_fact_graph_runtime_manager_foreach_status
  (WylFactGraphRuntimeManager * manager,
    WylFactGraphRuntimeStatusFunc callback, gpointer user_data) {
  if (manager == NULL || callback == NULL)
    return WYRELOG_E_INVALID;
  g_autoptr (GPtrArray) entries =
      g_ptr_array_new_with_free_func ((GDestroyNotify) runtime_entry_unref);
  g_autoptr (GPtrArray) copies =
      g_ptr_array_new_with_free_func (runtime_status_free);

  g_mutex_lock (&manager->map_lock);
  if (g_atomic_int_get (&manager->shutdown)) {
    g_mutex_unlock (&manager->map_lock);
    return WYRELOG_E_BUSY;
  }
  GHashTableIter iter;
  gpointer value = NULL;
  g_hash_table_iter_init (&iter, manager->entries);
  while (g_hash_table_iter_next (&iter, NULL, &value))
    g_ptr_array_add (entries, runtime_entry_ref (value));
  g_mutex_unlock (&manager->map_lock);

  wyrelog_error_t rc = WYRELOG_E_OK;
  for (guint i = 0; rc == WYRELOG_E_OK && i < entries->len; i++) {
    WylFactGraphRuntimeStatus *copy = g_try_new0 (WylFactGraphRuntimeStatus, 1);
    if (copy == NULL) {
      rc = WYRELOG_E_NOMEM;
      break;
    }
    rc = status_copy (g_ptr_array_index (entries, i), copy);
    if (rc == WYRELOG_E_OK)
      g_ptr_array_add (copies, copy);
    else
      runtime_status_free (copy);
  }
  for (guint i = 0; rc == WYRELOG_E_OK && i < copies->len; i++)
    rc = callback (g_ptr_array_index (copies, i), user_data);
  return rc;
}

wyrelog_error_t
wyl_fact_graph_runtime_manager_try_evict
  (WylFactGraphRuntimeManager * manager, const WylFactGraphKey * key,
    gboolean * out_evicted)
{
  if (out_evicted == NULL)
    return WYRELOG_E_INVALID;
  *out_evicted = FALSE;
  WylFactGraphRuntimeEntry *entry = NULL;
  wyrelog_error_t rc = manager_lookup_entry (manager, key, FALSE, &entry);
  if (rc != WYRELOG_E_OK)
    return rc;

  if (!g_mutex_trylock (&entry->writer_lock)) {
    runtime_entry_unref (entry);
    return WYRELOG_E_BUSY;
  }
  WylFactGraphEngineGeneration *old = NULL;
  g_mutex_lock (&entry->state_lock);
  if (entry->operation_active || entry->active_snapshots > 0) {
    rc = WYRELOG_E_BUSY;
  } else if (entry->abandoned) {
    rc = WYRELOG_E_BUSY;
  } else {
    old = entry->current;
    entry->current = NULL;
    entry->state = WYL_FACT_GRAPH_RUNTIME_EVICTED;
    entry->last_replay_class = WYL_FACT_GRAPH_REPLAY_NONE;
    entry->forget_state = WYL_FACT_GRAPH_FORGET_CONVERGED;
    *out_evicted = TRUE;
  }
  g_mutex_unlock (&entry->state_lock);
  engine_generation_unref (old);
  g_mutex_unlock (&entry->writer_lock);
  runtime_entry_unref (entry);
  return rc;
}

static gboolean
key_is_seen (const WylFactGraphKey *key,
    const WylFactGraphKey *const *seen_keys, gsize n_seen_keys)
{
  for (gsize i = 0; i < n_seen_keys; i++) {
    if (seen_keys[i] != NULL && wyl_fact_graph_key_equal (key, seen_keys[i]))
      return TRUE;
  }
  return FALSE;
}

wyrelog_error_t
wyl_fact_graph_runtime_manager_retire_unseen
  (WylFactGraphRuntimeManager * manager,
    const WylFactGraphKey * const *seen_keys, gsize n_seen_keys)
{
  if (manager == NULL || (seen_keys == NULL && n_seen_keys > 0))
    return WYRELOG_E_INVALID;
  for (gsize i = 0; i < n_seen_keys; i++) {
    if (seen_keys[i] == NULL
        || !canonical_component_is_valid (seen_keys[i]->tenant_id)
        || !canonical_graph_id_is_valid (seen_keys[i]->graph_id))
      return WYRELOG_E_INVALID;
  }

  g_autoptr (GPtrArray) entries =
      g_ptr_array_new_with_free_func ((GDestroyNotify) runtime_entry_unref);
  g_mutex_lock (&manager->map_lock);
  if (g_atomic_int_get (&manager->shutdown)) {
    g_mutex_unlock (&manager->map_lock);
    return WYRELOG_E_BUSY;
  }
  GHashTableIter iter;
  gpointer value = NULL;
  g_hash_table_iter_init (&iter, manager->entries);
  while (g_hash_table_iter_next (&iter, NULL, &value))
    g_ptr_array_add (entries, runtime_entry_ref (value));
  g_mutex_unlock (&manager->map_lock);

  for (guint i = 0; i < entries->len; i++) {
    WylFactGraphRuntimeEntry *entry = g_ptr_array_index (entries, i);
    if (key_is_seen (&entry->key, seen_keys, n_seen_keys))
      continue;
    g_mutex_lock (&entry->writer_lock);
    g_mutex_lock (&entry->state_lock);
    WylFactGraphEngineGeneration *old = entry->current;
    entry->current = NULL;
    if (!entry->abandoned) {
      entry->state = WYL_FACT_GRAPH_RUNTIME_EVICTED;
      entry->last_replay_class = WYL_FACT_GRAPH_REPLAY_NONE;
      entry->forget_state = WYL_FACT_GRAPH_FORGET_CONVERGED;
    }
    g_mutex_unlock (&entry->state_lock);
    engine_generation_unref (old);
    g_mutex_unlock (&entry->writer_lock);
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_graph_runtime_manager_acquire_snapshot
  (WylFactGraphRuntimeManager * manager, const WylFactGraphKey * key,
    WylFactGraphSnapshot ** out_snapshot)
{
  if (out_snapshot == NULL)
    return WYRELOG_E_INVALID;
  *out_snapshot = NULL;
  WylFactGraphSnapshot *snapshot = g_try_new0 (WylFactGraphSnapshot, 1);
  if (snapshot == NULL)
    return WYRELOG_E_NOMEM;
  g_atomic_ref_count_init (&snapshot->ref_count);

  WylFactGraphRuntimeEntry *entry = NULL;
  wyrelog_error_t rc = manager_lookup_entry (manager, key, FALSE, &entry);
  if (rc != WYRELOG_E_OK) {
    g_free (snapshot);
    return rc;
  }
  g_mutex_lock (&entry->state_lock);
  if (entry->abandoned
      || entry->admission == WYL_FACT_GRAPH_ADMISSION_CLOSED) {
    rc = WYRELOG_E_BUSY;
  } else if (entry->current == NULL) {
    rc = WYRELOG_E_NOT_FOUND;
  } else {
    snapshot->entry = entry;
    snapshot->generation = engine_generation_ref (entry->current);
    entry->active_snapshots++;
  }
  g_mutex_unlock (&entry->state_lock);
  if (rc != WYRELOG_E_OK) {
    runtime_entry_unref (entry);
    g_free (snapshot);
    return rc;
  }
  entry = NULL;
  *out_snapshot = snapshot;
  return WYRELOG_E_OK;
}

WylFactGraphSnapshot *
wyl_fact_graph_snapshot_ref (WylFactGraphSnapshot *snapshot)
{
  if (snapshot != NULL)
    g_atomic_ref_count_inc (&snapshot->ref_count);
  return snapshot;
}

void
wyl_fact_graph_snapshot_unref (WylFactGraphSnapshot *snapshot)
{
  if (snapshot == NULL || !g_atomic_ref_count_dec (&snapshot->ref_count))
    return;
  WylFactGraphRuntimeEntry *entry = snapshot->entry;
  g_mutex_lock (&entry->state_lock);
  g_assert_cmpuint (entry->active_snapshots, >, 0);
  entry->active_snapshots--;
  g_mutex_unlock (&entry->state_lock);
  engine_generation_unref (snapshot->generation);
  runtime_entry_unref (entry);
  g_free (snapshot);
}

guint64
wyl_fact_graph_snapshot_engine_generation
  (const WylFactGraphSnapshot * snapshot)
{
  return snapshot == NULL ? 0 : snapshot->generation->generation;
}

wyrelog_error_t
wyl_fact_graph_snapshot_use (WylFactGraphSnapshot *snapshot,
    WylFactGraphSnapshotFunc callback, gpointer user_data)
{
  if (snapshot == NULL || callback == NULL)
    return WYRELOG_E_INVALID;
  wyl_fact_graph_snapshot_ref (snapshot);
  WylFactGraphRuntimeEntry *entry = snapshot->entry;
  GThread *self = g_thread_self ();
  g_mutex_lock (&entry->state_lock);
  if (entry->engine_call_owner == self) {
    g_mutex_unlock (&entry->state_lock);
    wyl_fact_graph_snapshot_unref (snapshot);
    return WYRELOG_E_INVALID;
  }
  entry->waiting_engine_calls++;
  g_mutex_unlock (&entry->state_lock);

  g_mutex_lock (&entry->engine_call_lock);
  g_mutex_lock (&entry->state_lock);
  g_assert_cmpuint (entry->waiting_engine_calls, >, 0);
  entry->waiting_engine_calls--;
  g_assert_null (entry->engine_call_owner);
  entry->engine_call_owner = self;
  entry->active_engine_calls++;
  g_mutex_unlock (&entry->state_lock);
  wyrelog_error_t rc = callback (snapshot->generation->engine, user_data);
  g_mutex_lock (&entry->state_lock);
  g_assert_true (entry->engine_call_owner == self);
  g_assert_cmpuint (entry->active_engine_calls, ==, 1);
  entry->active_engine_calls--;
  entry->engine_call_owner = NULL;
  g_cond_broadcast (&entry->drain_cond);
  g_mutex_unlock (&entry->state_lock);
  g_mutex_unlock (&entry->engine_call_lock);
  wyl_fact_graph_snapshot_unref (snapshot);
  return rc;
}

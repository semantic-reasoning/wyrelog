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

/*
 * Whether a forget recorded against this graph has converged.
 *
 * Orthogonal to replay health: a graph can serve queries from a complete
 * engine while an erasure it accepted remains outstanding, which is the state
 * this axis exists to make visible.  An engine refresh must leave it alone,
 * because a refresh does not read the forget ledger and therefore learns
 * nothing about any erasure.  The tombstone paths below are the only writers
 * besides the reconciler, and they only ever clear it.
 *
 * CONVERGED is the zero value, so a graph nothing has reported on reads as
 * converged rather than as unknown.  That is the accurate rendering of no
 * report, not an optimistic default: the axis asserts that a forget was
 * recorded and did not converge, and absent a report nothing has claimed it.
 *
 * The zero value is safe only because writers are required to be total.  A
 * caller that writes INCOMPLETE on failure must also write CONVERGED on
 * success, for every graph it examines.  A write made only on failure turns
 * the zero into a lie and strands a graph that later converges.  It is
 * deliberately not a latch.
 *
 * Tombstoning clears it.  try_evict and retire_unseen reset the axis as they
 * reset last_replay_class -- at tombstone time only.  The two axes diverge at
 * refresh, which resets last_replay_class on success and must never touch
 * this one; eviction destroys the incarnation so both go stale together,
 * while refresh replaces only the engine so only the replay axis does.
 *
 * The reset is safe at those two sites for different reasons, and only one of
 * them is durable.  retire_unseen is called once, at the tail of the boot
 * replay loop that also reconciles -- retirement and re-probe are the same
 * event, so no live verdict is discarded unrepaired.  try_evict has no
 * production caller at all; if one is ever added it will be capacity-driven
 * and asynchronous to boot, and nothing re-probes an evicted graph, so a
 * verdict could be discarded by a memory-pressure decision.  Whoever wires
 * try_evict up must re-probe the graph before republishing it, or stop
 * resetting the axis there.
 */
typedef enum
{
  WYL_FACT_GRAPH_FORGET_CONVERGED = 0,
  WYL_FACT_GRAPH_FORGET_INCOMPLETE,
} WylFactGraphForgetState;

/*
 * Whether the graph admits new runtime operations.
 *
 * A third axis, orthogonal to both of the above.  It is not a
 * WylFactGraphRuntimeState value on purpose: retire_unseen and try_evict
 * overwrite state with EVICTED, so an admission stored there would be
 * silently reopened by a retirement sweep.  Keeping it separate also lets a
 * closed graph keep its health verdict and both generation counters, which is
 * what makes closing reversible.
 *
 * OPEN is the zero value, so an entry nothing has closed admits.
 *
 * This closes the entry to NEW operations only.  A snapshot pinned before the
 * close stays usable, because snapshot_use() does not consult this axis, so a
 * closed graph is not yet a total read barrier.  Do not read the refusals
 * below as one: they stop a graph being rebuilt and stop new pins being
 * taken, which is what "admission" means here and is all it means.  Revoking
 * an already-pinned snapshot would narrow the standing promise that a
 * snapshot outlives even the manager, and that is a separate decision.
 *
 * This is the runtime axis and it is not the durable one.  A graph is sealed
 * durably in the policy store (WYL_POLICY_GRAPH_LIFECYCLE_SEALED), and that
 * axis means something narrower: sealing blocks admission of new data at the
 * request boundary while the store stays readable and forgettable, which is
 * why the boot forget sweep opens a sealed graph on purpose.  Nothing here
 * reads the policy store -- the runtime manager holds no pointer to one -- so
 * the two are set independently and a caller that wants them to agree must
 * drive both.  Admission is also runtime-only: a restart reopens every graph
 * regardless of the durable bit.
 */
typedef enum
{
  WYL_FACT_GRAPH_ADMISSION_OPEN = 0,
  WYL_FACT_GRAPH_ADMISSION_CLOSED,
} WylFactGraphAdmission;

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
  guint waiting_drains;
  gint64 last_replay_at_us;
  WylFactGraphForgetState forget_state;
  WylFactGraphAdmission admission;
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
const gchar *wyl_fact_graph_admission_name
  (WylFactGraphAdmission admission);
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
 * Record whether this graph's pending forget intents converged.
 *
 * Writes an existing entry only: an unknown key is WYRELOG_E_NOT_FOUND rather
 * than a newly minted entry.
 *
 * state_lock covers every read and every write of the field.  There are
 * four writers -- this setter, try_evict, retire_unseen and evict_closed --
 * and only the first three change the value: evict_closed tombstones the
 * entry while deliberately preserving this axis, because nothing re-probes a
 * sealed graph until an unseal or a restart, so clearing it there would drop
 * a verdict about an erasure that is still owed.  Engine refresh is not a
 * writer either: refresh never reads or writes forget_state on
 * any path, which is what makes the axis orthogonal to replay health in code
 * rather than only in a comment.  Writes are last-writer-wins, so a caller
 * whose write must reflect a complete ledger read may not run concurrently
 * with another such caller, or the loser's verdict stands.
 *
 * WYRELOG_E_BUSY once the manager is shut down.  Shutdown and abandoned are
 * one condition, not two: entry->abandoned is only ever set as a consequence
 * of shutdown, and the lookup already refuses a shut-down manager before this
 * runs.  The abandoned check here closes the window between the lookup
 * releasing map_lock and this taking state_lock.
 *
 * WYRELOG_E_BUSY also for a tombstone.  retire_unseen and try_evict mark an
 * entry EVICTED without marking it abandoned, and both clear the axis, but
 * they release state_lock before this runs -- so this refuses EVICTED under
 * the same lock as the write, which is what actually closes that window.
 * Refusal here is a second guarantee, not the only one: the status reader
 * independently skips EVICTED and ABANDONED
 * (fact_graph_runtime_status_cb).
 *
 * BUSY is therefore not uniformly fatal: from shutdown it means abandon the
 * sweep, from a tombstone it means skip this graph.  A caller that treats
 * every BUSY as fatal will stop early on a graph that was merely retired.
 *
 * The refusal also imposes an ordering on callers.  A verdict written while
 * the graph is a tombstone is refused and dropped, and a later refresh then
 * publishes CONVERGED -- so a real INCOMPLETE can be lost by writing too
 * early.  Call this after the graph's refresh, per graph.  That trade is
 * deliberate: dropping a verdict for a graph that is not on the surface beats
 * poisoning one that is about to be republished.
 */
wyrelog_error_t wyl_fact_graph_runtime_manager_set_forget_state
  (WylFactGraphRuntimeManager * manager, const WylFactGraphKey * key,
    WylFactGraphForgetState forget_state);

/*
 * Admission contract
 * ------------------
 * close_admission() denies new operations on one entry; open_admission()
 * restores them.  Both take state_lock alone and never writer_lock, so
 * closing returns immediately even while a build owns the entry.  That is
 * deliberate: denying new work and waiting for admitted work are separate
 * steps, and only the first can be made prompt.
 *
 * Neither touches state, last_replay_class, forget_state, either generation
 * counter, or the published engine.  Closing is therefore reversible with no
 * observable trace beyond the axis itself, which is what lets a close/open
 * cycle be idempotent under the generation rules: closing a CLOSED entry and
 * opening an OPEN one both succeed and leave the entry unchanged.
 *
 * refresh() and acquire_snapshot() return WYRELOG_E_BUSY on a closed entry,
 * alongside their existing abandoned checks.  In acquire_snapshot() admission
 * outranks WYRELOG_E_NOT_FOUND: a closed entry with no published engine
 * answers BUSY, because a closed graph will not be rebuilt either and
 * NOT_FOUND would invite a refresh that is refused too.
 *
 * Discriminating a barrier from a dying manager is refresh's job alone, and
 * the rule has a precedence.  Read out_status->state first: ABANDONED means
 * the manager is going away, whatever the admission field says.  Only then
 * does admission == CLOSED mean a barrier.  Both facts can be true at once --
 * close the admission of a graph mid-build, then shut the manager down, and
 * the post-build path fills a status that is ABANDONED and CLOSED together --
 * so a caller that tests admission first will retry forever against a dead
 * manager.  The status is not wrong there; it is complete, and the order is
 * what disambiguates it.
 *
 * acquire_snapshot() has no out_status and therefore cannot discriminate at
 * all, and neither can a refresh() called with out_status NULL.  A caller
 * that needs the distinction must follow up with get_status(), which is
 * exempt from the barrier for exactly this reason.
 *
 * queryable in the status describes the published engine, not admission.  A
 * closed graph with a published engine still reports queryable TRUE while
 * every read of it is refused; a reporting surface that wants to show a
 * closed graph as unavailable must read admission itself.
 *
 * try_evict(), retire_unseen(), get_status(), foreach_status() and
 * set_forget_state() are exempt.
 * Eviction must work on a closed graph, because a caller that closes
 * admission in order to evict would otherwise have locked itself out; and a
 * closed graph must stay reportable, or it would be indistinguishable from a
 * missing one.  Both sweepers leave the axis alone, so a retired entry that
 * is later republished by refresh comes back still closed.  set_forget_state
 * is exempt because a sealed graph stays forgettable: that is the durable
 * axis's own rule, and the boot sweep that converges an interrupted erasure
 * must be able to record its verdict on a closed graph.
 *
 * Admission is a property of the graph, not a lease held by a thread: any
 * thread may close or open, and the closer need not be whoever eventually
 * reopens.  Both return WYRELOG_E_NOT_FOUND for a key the runtime has never
 * held -- neither mints an entry -- and WYRELOG_E_BUSY once the manager is
 * shut down or the entry abandoned.
 *
 * Closing admission does not stop an operation that has already been
 * admitted.  A refresh mid-build keeps its writer lock, runs its callback to
 * completion, and publishes.  This differs from shutdown, which makes an
 * in-flight refresh discard its result, and the difference is deliberate:
 * shutdown is terminal so nothing will read the result, while a closed graph
 * is expected to reopen.  Discarding the result would also not stop the
 * builder, which is still inside the store holding its handles -- so it would
 * buy no barrier and cost a rebuild.
 */
wyrelog_error_t wyl_fact_graph_runtime_manager_close_admission
  (WylFactGraphRuntimeManager * manager, const WylFactGraphKey * key);
wyrelog_error_t wyl_fact_graph_runtime_manager_open_admission
  (WylFactGraphRuntimeManager * manager, const WylFactGraphKey * key);

/*
 * Drain contract
 * --------------
 * drain() waits until every operation admitted before the close has retired.
 * "Admitted" is exactly three counters: operation_active,
 * active_engine_calls, and waiting_engine_calls.  A thread queued on
 * engine_call_lock has already passed the admission check and will run, so it
 * is waited for.
 *
 * active_snapshots is deliberately NOT a term.  A caller may hold a snapshot
 * indefinitely -- the contract above says a snapshot outlives even the
 * manager -- so waiting on it would let one idle reader stall a drain
 * forever.  A pinned snapshot is possession, not work in flight, and it
 * follows that a drained graph can still be read through a snapshot taken
 * before the close.  That residue is 1c's to decide, not something drain can
 * close.
 *
 * timeout_us < 0 waits indefinitely, 0 polls once, > 0 is a monotonic
 * deadline, clamped so a large value cannot overflow into a deadline already
 * in the past.  WYRELOG_E_BUSY on timeout with work outstanding, and out_status
 * then names what is still running.  WYRELOG_E_BUSY also once the manager is
 * shut down or the entry abandoned; shutdown broadcasts, so a blocked drain
 * wakes rather than running to its deadline.
 *
 * WYRELOG_E_INVALID when admission is OPEN.  Draining an open graph is
 * meaningless rather than merely slow, because new work can be admitted while
 * the wait runs and the answer would be stale the instant it was produced.
 * Close first.  The test is repeated on every wakeup, not taken once: a graph
 * reopened while a drain is parked is admitting again, so that drain is
 * refused rather than allowed to report a quiet graph that is not.  Because
 * admission is tested before the drained predicate, a reopen racing the last
 * retirement turns what would have been OK into INVALID: the refusal makes no
 * claim either way about whether the admitted work had finished, and a caller
 * that needs to know can read the counters in out_status.  The bias is
 * deliberate -- a refusal is always safe, a false OK never is.
 *
 * WYRELOG_E_INVALID also for a drain issued from inside this entry's own
 * engine callback OR its own build callback.  Either waits on a term the
 * calling frame is itself holding -- active_engine_calls in the first case,
 * operation_active in the second -- and no other thread will clear it, so the
 * wait cannot end.  Both are refused for that reason: an error beats a hang.
 * Draining a different entry from either callback is legal, as the status
 * readers already are.  It is legal, not safe in every arrangement: two
 * callbacks that drain each other's entry indefinitely deadlock, and nothing
 * here detects it because each wait is individually well-formed.  A caller
 * draining across entries from inside a callback must impose its own order or
 * bound the wait.  This mirrors the recursive snapshot_use() rule.
 *
 * drain() returning OK is a point-in-time answer, not a latch.  Because
 * snapshot_use() is ungated, a snapshot pinned before the close can enter an
 * engine call the instant the drain returns.  A caller that needs the graph
 * to stay quiet must hold that property some other way; drain only reports
 * that the work admitted before the close has finished.
 *
 * A timeout and a shutdown both answer WYRELOG_E_BUSY with a filled status,
 * and are told apart the same way refresh's are: read state first, and
 * ABANDONED means the manager is going away whatever else the status says.
 *
 * The wait holds state_lock and releases it in g_cond_wait, so an engine
 * callback -- which runs with no entry lock held -- can still reach the
 * status readers while a drain is blocked.  drain() never takes writer_lock,
 * so it introduces no lock-order inversion against a refresh and does not
 * starve try_evict's trylock.  That is a statement about lock ordering only:
 * a drain issued from inside a refresh's own build callback still cannot
 * terminate, which is why that case is refused above rather than left to the
 * ordering argument.
 */
wyrelog_error_t wyl_fact_graph_runtime_manager_drain
  (WylFactGraphRuntimeManager * manager, const WylFactGraphKey * key,
    gint64 timeout_us, WylFactGraphRuntimeStatus * out_status);

/*
 * try_evict() is non-blocking with respect to an entry refresh.  It returns
 * WYRELOG_E_BUSY, leaves out_evicted FALSE, and changes nothing when the
 * writer lock is owned/contended, the entry is abandoned, or any snapshot is
 * pinned.  Success detaches the current engine, sets EVICTED, clears
 * forget_state, preserves both generation counters, and sets out_evicted
 * TRUE.  An already-empty or
 * already-evicted entry may be successfully re-marked EVICTED.
 *
 * retire_unseen() is the authoritative sweep used after a complete store
 * enumeration.  Every entry absent from seen_keys is serialized against its
 * writer, detached, marked EVICTED and cleared of forget_state, without
 * changing generation counters.
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
 * evict_closed() detaches a closed graph's engine.  It is the eviction a seal
 * uses, and it is deliberately not try_evict():
 *
 * WYRELOG_E_INVALID when admission is OPEN.  An eviction outside a barrier is
 * try_evict's job.  The two are not interchangeable, because this one
 * detaches a generation that readers may still be pinning, which is only
 * defensible once nothing new can be admitted.
 *
 * It SUCCEEDS with snapshots pinned, where try_evict refuses.  A seal that one
 * idle reader could hold off indefinitely would be no barrier at all -- the
 * same reason active_snapshots is not a term of drain.  Those snapshots keep
 * their generation alive and stay usable; what they cannot do is be joined by
 * new ones, because acquire_snapshot is refused on a closed graph and there is
 * no current generation to hand out either way.
 *
 * It blocks on writer_lock where try_evict tries.  A seal that has committed
 * durably cannot retry, so a spurious BUSY would strand the graph with its
 * engine still published; and the wait is bounded because a closed graph
 * admits no new refresh and the caller has drained.
 *
 * It preserves both generation counters and the admission axis, and clears
 * last_replay_class, exactly as the two sweepers do.  It PRESERVES
 * forget_state, which they do not -- see the forget axis contract above for
 * why the sweepers clear it, and why a seal must not.
 */
wyrelog_error_t wyl_fact_graph_runtime_manager_evict_closed
  (WylFactGraphRuntimeManager * manager, const WylFactGraphKey * key,
    gboolean * out_evicted);

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
 * try_evict(), retire_unseen(), set_forget_state(), acquire_snapshot(),
 * close_admission(), open_admission(), or drain()
 * lookup/enumeration that observes the manager after that point returns
 * WYRELOG_E_BUSY.  Operations
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

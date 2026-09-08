/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyrelog/fact/runtime-private.h"
#include "wyrelog/policy/store-private.h"

G_BEGIN_DECLS;

typedef struct
{
  /* TRUE once the durable transition has committed.  This is the field a
   * caller must read before deciding to retry: a seal that got this far
   * cannot be retried from the top, because the graph is already sealed and
   * the compensating reopen is no longer safe. */
  gboolean sealed_committed;
  /* TRUE if the graph is closed on return.  FALSE means it is admitting:
   * either the runtime held no entry for the key -- nothing could be admitted
   * through it, so the durable bit alone carries the barrier until the next
   * boot -- or an abort rolled the close back. */
  gboolean runtime_barrier_established;
  gboolean engine_evicted;
  WylFactGraphRuntimeStatus status;
} WylFactGraphSealOutcome;

/*
 * Seal ordering
 * -------------
 * Deny new work, wait for admitted work, commit the durable bit, then take
 * the engine away.  The caller owns the policy write lease and the replay
 * coordinator lock; this takes neither, so it can be composed under whichever
 * the caller already holds.
 *
 * The compensation rule is one sentence: reopen admission on an abort if and
 * only if the graph is not durably sealed.  That subsumes "never after the
 * commit" and also covers a graph sealed by an earlier call, or by the
 * pre-existing seal route that writes the durable bit with no runtime
 * involvement at all -- an abort against one of those must leave it closed.
 * Reopening a graph that may be durably sealed is the one unsafe direction --
 * it produces "durably sealed and admitting", which is the state this whole
 * unit exists to make unrepresentable.  When the durable write fails
 * ambiguously and the state cannot be re-read, the graph is deliberately left
 * closed with its durable state unknown; the next boot converges it, because
 * the boot pass sets admission from whatever the durable bit turns out to be.
 *
 * What a successful seal guarantees: no new operation is admitted, every
 * operation admitted before the close has retired, the durable bit is set,
 * and no engine is published.  It does NOT revoke a snapshot pinned before
 * the close -- see the admission contract for why that is a separate
 * decision, and note that the pinned generation stays readable until its
 * holder releases it.
 *
 * drain_timeout_us is passed through to drain().  It must be finite when the
 * caller holds a process-wide lease: an indefinite drain there blocks every
 * other writer until the graph goes quiet.  A drain that times out aborts the
 * seal and reopens, so the caller may retry.
 *
 * WYRELOG_E_BUSY when the drain did not finish or the manager is shutting
 * down; WYRELOG_E_NOT_FOUND for a graph the policy store does not hold;
 * WYRELOG_E_POLICY for a lifecycle that cannot be sealed -- provisioning or
 * degraded -- which propagates from the durable write and reopens.
 *
 * out_outcome is zeroed on entry and filled on the returns where the runtime
 * state changed: a drain abort, an ambiguous durable write, and success.  The
 * early argument and lookup failures leave it zeroed, which is accurate --
 * nothing was touched.  The field that matters on a failure is
 * runtime_barrier_established: FALSE with a zeroed status means the graph was
 * never closed.  The ambiguous-write return reports the barrier only when it
 * could not re-read the durable state: the close stands there until a restart
 * or a re-replay.  When the re-read succeeds and says the write never landed,
 * the close is rolled back and the field reports FALSE with the graph
 * admitting again. */
wyrelog_error_t wyl_fact_graph_seal (wyl_policy_store_t * policy,
    const wyl_policy_fact_graph_info_t * graph_info,
    WylFactGraphRuntimeManager * manager, gint64 drain_timeout_us,
    WylFactGraphSealOutcome * out_outcome);

void wyl_fact_graph_seal_outcome_clear (WylFactGraphSealOutcome * outcome);

typedef struct
{
  /* TRUE when the graph was durably sealed on entry and U4 CONFIRMED it
   * unsealed afterwards.  Confirmed, not merely written: the field is set
   * past the readback, so a readback that could not run leaves it FALSE even
   * though the write landed and the bit really is clear.  FALSE therefore
   * means "not established", never "nothing changed" -- a caller recovering
   * from an error must not read it as proof the graph is still sealed.
   *
   * It cannot distinguish this call's write from a concurrent one that landed
   * first -- the store's unseal reports OK for a lost compare-and-swap -- and
   * does not need to: either way the durable transition this call was asked
   * for has happened. */
  gboolean unseal_committed;
  /* TRUE when the durable bit was already clear on entry.  Not an error: the
   * durable clear and the runtime republish are separate steps, and a call
   * that failed between them leaves exactly this state behind. */
  gboolean already_unsealed;
  /* TRUE when the mandatory readback found the bit still set.  The graph is
   * left closed and WYRELOG_E_BUSY is returned; reopening a possibly-sealed
   * graph is the one direction that produces "durably sealed and
   * admitting". */
  gboolean readback_still_sealed;
  /* Both fields describe the graph AS OBSERVED ON RETURN, not the steps this
   * call attempted.  open_admission can fail, and evict_closed compensates
   * only best-effort, so a field derived from the intent would disagree with
   * the graph in exactly the cases a caller consults it.  A status that
   * cannot be read at all -- a shut-down manager, a key with no entry --
   * leaves both FALSE rather than letting a zeroed status report
   * WYL_FACT_GRAPH_ADMISSION_OPEN, which is 0.  The ordering block below
   * names every return that leaves them unobserved; read it before treating
   * FALSE as an observation. */
  gboolean engine_published;
  gboolean admission_open;
  /* The raw status behind those two booleans, and the reason they exist:
   * where it could not be read it is left ZEROED.  Read NOTHING out of it
   * until admission_open or engine_published has told you something was
   * observed.  The rule is the whole struct, and it is stated that way rather
   * than as a list of the dangerous fields on purpose: this struct has
   * fourteen members, any list here would be one refactor from being wrong,
   * and a list that looks complete is worse than no list -- a reader trusts
   * the omissions.
   *
   * What makes a zeroed status dangerous rather than obviously empty is that
   * most of it zeroes to the REASSURING answer.  Examples, not a partition:
   * admission reads WYL_FACT_GRAPH_ADMISSION_OPEN, exactly backwards for the
   * shut-down manager that made the read fail; forget_state reads
   * WYL_FACT_GRAPH_FORGET_CONVERGED over a graph that may still owe an
   * erasure, and that one already has a consumer, since the deferral recorded
   * below rests on an unsealed graph continuing to report FORGET_INCOMPLETE;
   * last_replay_class reads REPLAY_NONE, i.e. no fault; and the quiescence
   * counters all read "nothing outstanding". */
  WylFactGraphRuntimeStatus status;
} WylFactGraphUnsealOutcome;

/*
 * Unseal ordering
 * ---------------
 * The seal's inverse, and deliberately not its mirror image.  A seal denies,
 * drains, commits, evicts; an unseal commits, rebuilds behind the barrier,
 * and reopens last.  The asymmetry is the point: the reopen is the only edge
 * a reader observes, so the engine must already be published when it happens.
 *
 * U1  read the graph's OWN durable bit, never fact_graph_is_active -- the
 *     conflation argument on the seal above applies unchanged.
 * U2  close admission when the bit is set, so the rebuild happens behind a
 *     barrier.  NOT_FOUND is success for the seal's reason: no entry means
 *     nothing to admit through.
 * U3  the durable clear.  Irreversible: there is no compensating re-seal,
 *     because a re-seal would have to drain, and a caller that reached here
 *     asked for the graph to come back.
 * U4  read the bit back, always.  The store's unseal reports OK for a
 *     compare-and-swap that matched nothing, so this read is the only thing
 *     that establishes the bit is actually clear.  What that buys is the
 *     safety of U6, not the legality of U5: publishing and then reopening
 *     over a bit that is still set is precisely "durably sealed and
 *     admitting".  A bit that reads back set leaves the graph closed and
 *     answers WYRELOG_E_BUSY.
 *
 *     open_graph_engine's own refusal of a sealed info is NOT the mechanism
 *     here and cannot fire: U5 constructs its info with sealed FALSE
 *     unconditionally.  That construction is only truthful because U4 ran --
 *     which is the whole point, and worth separating from a guard that would
 *     never catch it.
 * U5  rebuild and publish into the still-closed entry, from an info this
 *     builds rather than the caller's: a caller holds the row it read before
 *     the clear, and a sealed info is refused before anything is opened.
 * U6  reopen.  The observable linearization point.  A failure here leaves an
 *     engine attached behind a barrier that nothing will lift, so it is
 *     compensated with evict_closed -- best-effort, and usually a no-op,
 *     since the reachable way to fail U6 is a manager shutdown that fails the
 *     eviction too.
 *
 * A graph that is durably unsealed AND admitting is returned untouched with
 * already_unsealed TRUE: no rebuild, no close, no reopen.  Every other
 * starting state ENTERS U4, which is what makes a retry after a failed U5 or
 * U6 converge instead of reporting success over a barred graph.  Entering is
 * not finishing: U3 can still refuse -- a sealed legacy_unclassified graph
 * returns POLICY -- and U4, U5 and U6 each have their own failure return,
 * enumerated below.
 * "Admitting" is read from the runtime, not assumed: a key the runtime has
 * never held is converged too, because refresh_closed mints it CLOSED and U6
 * opens it.
 *
 * Admitting is not the same as serving.  retire_unseen rewrites an entry to
 * EVICTED and leaves the axis alone, so an admitting entry can have no engine
 * -- and the fast path returns OK over it, because republishing an admitting
 * graph is plain refresh's job and not this one's.  A caller that needs to
 * know whether the graph came back must read engine_published, not the return
 * code.
 *
 * There is no drain phase, and it is not an omission.  Publication is a
 * pointer swap and existing snapshots pin their own generation, so a
 * republish needs no quiescence -- that is plain refresh's ordinary contract,
 * exercised on every live mutation.
 *
 * The caller owns the policy write lease and the replay coordinator lock;
 * this takes neither.  fact_root must be non-empty, and unlike the seal --
 * which takes no root -- it is checked up front rather than left to the
 * builder, because the builder runs at U5 and U3 is not reversible.
 *
 * PRECONDITION, and it is not satisfied today by one of the two seal routes.
 * A seal and an unseal must not run concurrently on one graph: refresh_closed
 * consumes its admission gate before the build and does not re-test it, so a
 * concurrent seal whose drain times out reopens admission underneath an
 * in-flight rebuild.  wyl_handle_seal_fact_graph takes
 * fact_replay_coordinator_lock; the daemon's graph_seal_handler
 * (wyrelog/daemon/http.c, the wyl_daemon_policy_write_acquire block) takes
 * only the policy write lease, so the two seal routes do not exclude each
 * other, let alone this one.  Whoever wires an unseal endpoint owns closing
 * that gap -- it is named here so the next unit cannot rediscover it as new.
 *
 * WYRELOG_E_NOT_FOUND for a graph the policy store does not hold, at either
 * read; WYRELOG_E_BUSY for a readback that is still sealed, and from the
 * manager for a shutdown; WYRELOG_E_POLICY from the store for a sealed
 * legacy_unclassified graph, which the schema refuses to unseal; whatever
 * the rebuild returns when the engine cannot be built.
 *
 * out is zeroed on entry, and its two observed fields are filled only where
 * something was observed.  Be precise about where that is, because FALSE is
 * also what "not observed" looks like: the argument checks, the key
 * allocation, U1's read failure and U1's NOT_FOUND all return with the
 * outcome still zeroed, which is accurate -- nothing was touched -- and a
 * caller must not read "not admitting" out of it there.  From U2 onward every
 * return reads the graph back, and even then a status that cannot be read at
 * all leaves both fields FALSE rather than reporting the zero value of
 * WylFactGraphAdmission, which is OPEN.  So the fields answer "is it
 * definitely admitting / definitely serving", never "is it barred".
 *
 * A caller retrying after a failure must pass a cleared outcome:
 * wyl_fact_graph_unseal zeroes the struct on entry without freeing the status
 * it may already hold, exactly as the seal does.  Call
 * wyl_fact_graph_unseal_outcome_clear between attempts.
 *
 * Two side effects on error paths, both deliberate and neither obvious.  U2
 * closes admission before U3 can refuse, so a graph the store will not unseal
 * -- a sealed legacy_unclassified one, which returns POLICY -- is left barred
 * by a call that failed.  That is a repair rather than damage: the graph is
 * durably sealed, and the boot pass would close it anyway.
 *
 * And U3 has no rollback, so a failure below it leaves the graph barred with
 * the durable bit ALREADY CLEARED -- with one exception, which is the reason
 * to state this carefully: a readback that finds the bit set again means
 * something re-sealed the graph after U3, so that return leaves it barred and
 * durably SEALED.  readback_still_sealed is what tells the two apart, and it
 * is the only field that does.  Its sibling -- a readback that could not RUN
 * -- has the same standing and no field at all: it leaves the durable state
 * unconfirmed, so in the same concurrent-re-seal world it can be sealed too,
 * with readback_still_sealed FALSE.  Neither case arises while the
 * precondition above holds; both are named because a caller that violates it
 * gets no warning from the outcome.  Either way a retry converges the graph,
 * and so does the next handle open, which always builds a fresh manager and
 * therefore refreshes before it writes the axis.  A re-replay on a LIVE
 * manager would restore the axis but not the engine, because plain refresh is
 * refused on a closed entry -- not reachable today, because although
 * wyl_handle_replay_fact_graphs is exported and tests do call it on a live
 * handle, its only production call site is handle open.
 *
 * Deferred, and named so unit 3c does not rediscover it: refresh_closed's
 * contract says the sequencer above owes a forget re-probe and a
 * set_forget_state, and this does neither.  The boot loop reconciles BEFORE
 * it refreshes; this republishes without reconciling, so an unsealed graph
 * can serve rows an owed erasure was meant to remove.  What holds it: the
 * verdict is preserved across seal and unseal rather than reset, so the graph
 * still reports FORGET_INCOMPLETE, no route can record a NEW intent on a
 * sealed graph -- the daemon's forget handler refuses one before any
 * destructive step -- and the next boot reconciles.  The endpoint unit owns
 * deciding whether that is enough. */
wyrelog_error_t wyl_fact_graph_unseal (wyl_policy_store_t * policy,
    const gchar * fact_root,
    const wyl_policy_fact_graph_info_t * graph_info,
    WylFactGraphRuntimeManager * manager,
    WylFactGraphUnsealOutcome * out_outcome);

void wyl_fact_graph_unseal_outcome_clear (WylFactGraphUnsealOutcome * outcome);

#if defined(WYL_TEST_HANDLE_SEAMS)
/*
 * Fail one step of the seal for a test, so the ambiguous-write branch can be
 * driven at all.  Returning non-OK makes that step fail *without running*:
 * a hook that let the step run and then overwrote its result would leave the
 * durable bit set, the compensating re-read would find the graph genuinely
 * sealed, and control would take the recovery arm instead -- measuring
 * identically to the unhooked code and reading as "no difference" rather than
 * "the probe never reached the branch".
 *
 * Phases:
 *   WYL_FACT_GRAPH_SEAL_PHASE_DURABLE_WRITE  the S4 policy-store write
 *   WYL_FACT_GRAPH_SEAL_PHASE_RESEAL_PROBE   the compensating re-read
 *
 * Process-global because the seal is a free function over a policy store and
 * a runtime manager, with no object to hang the hook on.  A shipped library
 * carries neither this declaration nor any way to set the hook -- verified by
 * checking the built libwyrelog for the setter symbol -- so the fault check
 * in seal_step_fault compiles to nothing there.
 */
typedef wyrelog_error_t (*WylFactGraphSealTestHook) (const gchar * phase,
    gpointer user_data);

void wyl_fact_graph_seal_set_test_hook (WylFactGraphSealTestHook hook,
    gpointer user_data);
#endif

/* The phase names are plain string constants and are declared unconditionally,
 * because the call sites naming them are unconditional -- only the hook that
 * can act on them is test-only.  A shipped build compiles the names and no
 * way to reach them. */
#define WYL_FACT_GRAPH_SEAL_PHASE_DURABLE_WRITE "durable_write"
#define WYL_FACT_GRAPH_SEAL_PHASE_RESEAL_PROBE  "reseal_probe"

/* The unseal's three seams, driven through the same hook.  The first two obey
 * the rule above -- non-OK fails the step without running it.  The third is
 * reached only as a scheduling point in practice: a test that wants the
 * reopen to fail shuts the manager down from the hook and returns OK, so the
 * failure is the manager's own rather than a substituted result. */
#define WYL_FACT_GRAPH_UNSEAL_PHASE_DURABLE_WRITE  "unseal_durable_write"
#define WYL_FACT_GRAPH_UNSEAL_PHASE_READBACK_PROBE "unseal_readback_probe"
#define WYL_FACT_GRAPH_UNSEAL_PHASE_OPEN_ADMISSION "unseal_open_admission"

G_END_DECLS;

/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef G_OS_WIN32
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#endif
#include "fact/graph-artifact-transition-posix-private.h"

#include "fact/graph-artifact-transition-names-private.h"
#include "wyl-id-private.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * BOTH OF THESE ARE CONSEQUENCES OF THE RESTRICTIVE FEATURE-TEST PREAMBLE
 * ABOVE, and the precedent this file follows carries them for the same
 * reason.  Defining _POSIX_C_SOURCE explicitly stops glibc's features.h from
 * implying _DEFAULT_SOURCE, so __USE_MISC is unset and <unistd.h> does NOT
 * declare syscall; <sys/syscall.h> supplies the SYS_* constants only, never
 * the prototype.  And on Darwin renameatx_np is declared in <stdio.h> under
 * __DARWIN_C_LEVEL >= __DARWIN_C_FULL rather than in <sys/stat.h>, which
 * supplies RENAME_EXCL alone -- glib cannot bring it in transitively, because
 * only glib/gprintf.h includes <stdio.h> and glib.h does not include that.
 *
 * Without them Apple clang makes the implicit declaration a hard ERROR while
 * gcc still warns, so the file would build green on Linux and red on macOS --
 * and would become a Linux error the moment the runner image reaches gcc-14.
 */
#if defined(__linux__)
#include <sys/syscall.h>
extern long syscall (long, ...);
#endif

/*
 * THE ATOMIC-PAIR RULE, AND IT GOVERNS EVERY CAPABILITY CLASSIFICATION IN
 * THIS FILE RATHER THAN ANY ONE OF THEM.
 *
 * ENOTSUP and EOPNOTSUPP are ONE VALUE on Linux and TWO SPELLINGS OF ONE
 * MEANING on Darwin.  Wherever either appears in a capability classification,
 * BOTH must appear -- every row, every file.  Splitting them is never a
 * design choice, only an accident that Linux CI cannot see, because there the
 * two are indistinguishable and any test covering one covers the other.
 *
 * THE LIVE INSTANCE THAT PROVES IT IS IN THIS FILE'S OWN HISTORY: the
 * directory-flush row below shipped for one review round accepting
 * EOPNOTSUPP without ENOTSUP, in platform-neutral code that runs on Darwin,
 * where that gap turns a genuine capability gap into a probe failure.
 *
 * ONE OTHER LIVE SITE EXISTS, and one DORMANT one that is worth
 * distinguishing rather than counting:
 *   wyctl's Darwin F_FULLFSYNC probe accepts EINVAL/ENOTTY/ENOTSUP and misses
 *     EOPNOTSUPP.  It sits inside #ifdef __APPLE__, so the two spellings
 *     genuinely differ there and the gap can bite.
 *   the OFD-lock fallback in the policy lease accepts EINVAL/ENOSYS/
 *     EOPNOTSUPP and misses ENOTSUP -- but it sits inside
 *     #if defined(__linux__) && defined(F_OFD_SETLK), where the two are ONE
 *     VALUE, so the missing spelling is the same integer and that site cannot
 *     misbehave as written.  It is latent, not broken: it would only bite if
 *     that code were ever built for Darwin.  Both are out of scope here.
 *
 * For the same reason every such test must be an if-CHAIN and never a switch:
 * a switch listing both labels is a duplicate-case compile error on Linux.
 */

#define MT_SLOT_COUNT WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_COUNT
#define POSIX_FAULT(name) WYL_FACT_ARTIFACT_TRANSITION_POSIX_TEST_FAULT_ ## name

struct WylFactArtifactTransitionPosix
{
  /* Borrowed.  The provider neither closes the descriptor nor releases the
   * lease; both must outlive it. */
  gint graph_fd;
  WylFactRootWriterLease *lease;
  WylFactArtifactTransitionNames names;
  guint8 operation_uuid[WYL_ID_BYTES];
  WylFactArtifactTransitionPosixCapability capability;
};

static gint transition_posix_test_fault;
static gint transition_posix_consumed_test_fault;
static gint transition_posix_test_rename_errno;
static gint transition_posix_test_flush_errno;

/*
 * Read-and-clear.  g_atomic_int_exchange would say this in one call but is
 * glib 2.74+, and this file cannot be compiled on the maintainer host to
 * check that, so it uses the pair that has always existed.  The seam is
 * test-only and single-threaded, so the two steps are equivalent here.
 *
 * IT CLEARS ON CONSUMPTION ONLY.  A level set for a seam that never fires --
 * the probe failing at preclean or create before it reaches the rename --
 * SURVIVES.  Both callers here always reach their seam, so nothing leaks
 * today, but the fixture's own resets are what make that true in general and
 * are load-bearing rather than belt-and-braces.
 */
static gint
posix_take_level (gint *level)
{
  gint value = g_atomic_int_get (level);
  g_atomic_int_set (level, 0);
  return value;
}

static gboolean
posix_fault_take (WylFactArtifactTransitionPosixTestFault fault)
{
  gboolean consumed
    = g_atomic_int_compare_and_exchange (&transition_posix_test_fault, fault,
          POSIX_FAULT (NONE));
  if (consumed)
    g_atomic_int_set (&transition_posix_consumed_test_fault, fault);
  return consumed;
}

void
wyl_fact_artifact_transition_posix_set_test_fault
  (WylFactArtifactTransitionPosixTestFault fault)
{
  if (fault >= POSIX_FAULT (NONE) && fault < POSIX_FAULT (COUNT)) {
    g_atomic_int_set (&transition_posix_consumed_test_fault,
        POSIX_FAULT (NONE));
    g_atomic_int_set (&transition_posix_test_fault, fault);
  }
}

void
wyl_fact_artifact_transition_posix_set_test_rename_errno (gint errno_value)
{
  g_atomic_int_set (&transition_posix_test_rename_errno, errno_value);
}

void
wyl_fact_artifact_transition_posix_set_test_flush_errno (gint errno_value)
{
  g_atomic_int_set (&transition_posix_test_flush_errno, errno_value);
}

gboolean
wyl_fact_artifact_transition_posix_test_fault_was_consumed
  (WylFactArtifactTransitionPosixTestFault fault)
{
  return fault != POSIX_FAULT (NONE)
         && g_atomic_int_compare_and_exchange
           (&transition_posix_consumed_test_fault, fault,
             POSIX_FAULT (NONE));
}

/*
 * A no-replace rename, owned by this backend, REPORTING ITS ERRNO RATHER THAN
 * A COLLAPSED RETURN.
 *
 * This is a third copy of a primitive the tree already carries twice, and it
 * exists only because neither existing copy is reachable: the artifact
 * namespace's is `static` in a 5652-line file and declared in no header, and
 * wyctl's is `static` too and takes a different signature.  Exporting the
 * namespace's would mean reaching into the #609 authority this unit is
 * deliberately built to leave alone.
 *
 * Owning the copy is what lets the probe classify from the errno itself.  The
 * namespace's version collapses ENOSYS, EINVAL, ENOENT and EEXIST onto one
 * value, and a probe inheriting that collapse cannot tell a genuine
 * capability gap from a name that was interfered with -- which is the exact
 * misclassification an out-of-band probe exists to prevent.
 *
 * ERRNO CAPTURE DISCIPLINE: errno is read on the line immediately after the
 * failing syscall and returned as a value.  Callers classify from THAT VALUE
 * and must never read errno themselves further down, because any intervening
 * libc call -- a g_free, a log line, a g_strdup on an error path -- may
 * clobber it.
 *
 * Returns 0 on success, otherwise the captured errno.
 */
static gint
transition_rename_no_replace (gint dirfd, const gchar *source,
    const gchar *destination)
{
#if defined(__linux__) && defined(SYS_renameat2)
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1
#endif
  if (syscall (SYS_renameat2, dirfd, source, dirfd, destination,
      RENAME_NOREPLACE) == 0)
    return 0;
  return errno;
#elif defined(__APPLE__)
  if (renameatx_np (dirfd, source, dirfd, destination, RENAME_EXCL) == 0)
    return 0;
  return errno;
#else
  (void) dirfd;
  (void) source;
  (void) destination;
  /* No no-replace primitive on this target at all, which is the capability
   * gap itself rather than a failure to observe one. */
  return ENOSYS;
#endif
}

static const gchar *
slot_name (const WylFactArtifactTransitionPosix *provider,
    WylFactArtifactMainTransitionSlot slot)
{
  switch (slot) {
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_MAIN:
      return WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME;
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_STAGE:
      return provider->names.stage;
    default:
      return provider->names.rollback;
  }
}

static WylFactArtifactInventoryIdentity
identity_from_stat (const struct stat *st)
{
  return (WylFactArtifactInventoryIdentity) {
           .domain = (guint64) st->st_dev,
           .object = (guint64) st->st_ino,
  };
}

/*
 * Conformance for one slot, read from the FD's own stat.
 *
 * A NON-REGULAR FILE MAPS TO OWNER_UNKNOWN rather than to a new enumerator.
 * The contract documents OWNER_UNKNOWN as the value a zero-filled entry
 * carries so that it fails closed -- that is, "conformance could not be
 * established" -- and a FIFO or a device node at one of these names is
 * exactly a failure to establish conformance.  It refuses as OWNERSHIP, which
 * is the correct outcome, without amending the merged contract for a case it
 * already rejects.
 *
 * OWNER_UNPROTECTED_ACL and OWNER_INHERITED_ACE are Windows concepts and this
 * provider never emits them.  Their absence here is not a gap.
 */
static WylFactArtifactMainTransitionOwnerState
owner_state_from_stat (const struct stat *st)
{
  if (!S_ISREG (st->st_mode))
    return WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_UNKNOWN;
  if (st->st_uid != geteuid ())
    return WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_WRONG_PRINCIPAL;
  /* 07777 rather than 0777: a setuid or setgid bit on an otherwise 0600 file
   * must not read as conforming. */
  if ((st->st_mode & 07777) != 0600)
    return WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_WRONG_MODE;
  return WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_CONFORMING;
}

/*
 * The detection ladder for one slot.  THE ORDER IS LOAD-BEARING.
 *
 * 1. fstatat with AT_SYMLINK_NOFOLLOW is a SYMLINK SCREEN ONLY.  Its values
 *    are discarded; nothing it reports is ever published.
 * 2. openat with O_NOFOLLOW.  ELOOP is the RACE ARM -- the name became a
 *    symlink between 1 and 2 -- and it is reported IDENTICALLY to a symlink
 *    seen at step 1, so the window is closed rather than narrowed.
 * 3. fstat on the descriptor is authoritative for everything published.
 *
 * THE THIRD RACE ARM, absent -> present between steps 1 and 2, is not handled
 * here and does not need to be, but the reason lives outside this file and is
 * therefore written down here: the contract authorizes a rename only when the
 * DESTINATION SLOT IS REPORTED ABSENT in the authorizing observation, and the
 * executor's rename is no-replace.  So if something appears between the
 * observation and the syscall the kernel refuses the rename and the executor
 * records a failed mutation.  A stale absence cannot become a silent
 * overwrite, which is what makes the observation window tolerable at all.
 */
static wyrelog_error_t
observe_slot (WylFactArtifactTransitionPosix *provider,
    WylFactArtifactMainTransitionSlot slot,
    WylFactArtifactMainTransitionEntryEvidence *out_entry)
{
  const gchar *name = slot_name (provider, slot);
  struct stat screen = { 0 };
  *out_entry = (WylFactArtifactMainTransitionEntryEvidence) { 0 };

  if (posix_fault_take (POSIX_FAULT (OBSERVE_SLOT_SUBSTITUTE))) {
    out_entry->present = TRUE;
    out_entry->reparse = TRUE;
    return WYRELOG_E_OK;
  }
  if (fstatat (provider->graph_fd, name, &screen, AT_SYMLINK_NOFOLLOW) != 0) {
    gint screen_errno = errno;
    if (screen_errno == ENOENT)
      return WYRELOG_E_OK;
    return WYRELOG_E_IO;
  }
  if (S_ISLNK (screen.st_mode)) {
    /* Never opened and never followed, and NO identity is published: the
     * target's identity is not this slot's. */
    out_entry->present = TRUE;
    out_entry->reparse = TRUE;
    return WYRELOG_E_OK;
  }

  /* Same capture discipline as the probe: errno becomes a local on the line
   * that produces it, so the arms below read a value rather than a global
   * that a later inserted call could clobber. */
  gint fd = -1;
  gint open_errno;
  if (posix_fault_take (POSIX_FAULT (OBSERVE_SLOT_OPEN))) {
    open_errno = EIO;
  } else {
    fd = openat (provider->graph_fd, name,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    open_errno = fd < 0 ? errno : 0;
  }
  if (fd < 0) {
    if (open_errno == ELOOP) {
      out_entry->present = TRUE;
      out_entry->reparse = TRUE;
      return WYRELOG_E_OK;
    }
    if (open_errno == ENOENT)
      return WYRELOG_E_OK;
    /* A slot we cannot read is never reported absent. */
    return WYRELOG_E_IO;
  }

  struct stat authoritative = { 0 };
  if (fstat (fd, &authoritative) != 0) {
    close (fd);
    return WYRELOG_E_IO;
  }
  close (fd);
  out_entry->present = TRUE;
  out_entry->reparse = FALSE;
  out_entry->identity = identity_from_stat (&authoritative);
  out_entry->link_count = (guint) authoritative.st_nlink;
  out_entry->owner_state = owner_state_from_stat (&authoritative);
  return WYRELOG_E_OK;
}

/* ------------------------------------------------------------------ */
/* the capability probe                                                */
/* ------------------------------------------------------------------ */

/*
 * TRUE when both names are gone.  THE UNLINKS ARE DECISIVE AND THE FLUSH IS
 * DELIBERATELY NOT, which is a narrower rule than "check every return" and
 * the difference matters in both directions.
 *
 * An unlink that fails for anything but ENOENT is the section 7 hazard
 * itself: a probe name left resident is a non-fixed entry, so the inventory
 * gate's unknown-entry count would refuse EVERY future operation on this
 * graph.  probe_preclean fails closed on exactly that error and this path
 * must match it.
 *
 * A FAILED DIRECTORY FLUSH IS NOT THAT, AND GATING ON IT WOULD BE A BUG.  The
 * names are already unlinked when it runs, so nothing is resident; the flush
 * only makes that durable.  Worse, on a filesystem whose directory flush is
 * legitimately unsupported -- precisely the case the capability model above
 * exists to describe -- gating on it would fail EVERY probe and deny restore
 * on the filesystems the bounded exit was built for.  A flush that fails
 * leaves at most a name that reappears after a crash, and the next probe's
 * step 0 clears it unconditionally.
 */
static gboolean
probe_retire (gint graph_fd, const WylFactArtifactTransitionNames *names)
{
  if (posix_fault_take (POSIX_FAULT (PROBE_RETIRE)))
    return FALSE;
  gboolean retired = TRUE;
  const gchar *targets[] = { names->probe, names->probe_moved };
  for (gsize index = 0; index < G_N_ELEMENTS (targets); index++) {
    if (unlinkat (graph_fd, targets[index], 0) != 0) {
      gint unlink_errno = errno;
      /* Already absent is the retired state, not a failure. */
      if (unlink_errno != ENOENT)
        retired = FALSE;
    }
  }
  (void) fsync (graph_fd);
  return retired;
}

/*
 * STEP 0 IS THE CRASH-RECOVERY PATH, AND WITHOUT IT THE PROBE BRICKS THE
 * GRAPH.  Retiring both names on the way out covers every path on which the
 * probe RETURNS; it does not cover the process dying between the create and
 * the retire.  A crash there leaves the probe file, the next probe for that
 * UUID gets EEXIST from O_EXCL, the probe fails and open () fails with it --
 * so that UUID can never probe again, the graph cannot even be INSPECTED, and
 * for every other operation the leftover is an unknown entry the inventory
 * gate refuses on permanently.  Nothing could clear it, because the only code
 * that retires it lives inside the probe that now fails before reaching it.
 *
 * Step 0 is licensed by exactly the argument that licenses the contract's own
 * RETIRE_STAGE and FINALIZE: both names derive from THIS operation's UUID, so
 * anything found at them is only this operation's own debris.  O_EXCL stays
 * and now means what it says, because step 0 has made the name absent.
 *
 * THE RESIDUAL, stated rather than glossed: a crashed probe still blocks
 * OTHER operations on that graph until either the same UUID probes again or
 * an operator clears the name.  A different UUID's provider must not touch
 * this UUID's names -- the same rule that keeps RETIRE_STAGE safe -- so this
 * belongs to #552's operator story.
 */
static wyrelog_error_t
probe_preclean (gint graph_fd, const WylFactArtifactTransitionNames *names)
{
  const gchar *targets[] = { names->probe, names->probe_moved };
  for (gsize index = 0; index < G_N_ELEMENTS (targets); index++) {
    if (posix_fault_take (POSIX_FAULT (PROBE_PRECLEAN)))
      return WYRELOG_E_IO;
    if (unlinkat (graph_fd, targets[index], 0) != 0) {
      gint unlink_errno = errno;
      if (unlink_errno != ENOENT)
        return WYRELOG_E_IO;
    }
  }
  return WYRELOG_E_OK;
}

/*
 * Classify the no-replace rename from ITS ERRNO.  One three-way table, no
 * platform conditionals -- the per-platform split this used to carry existed
 * only to work around a collapsed return value this backend no longer
 * inherits.
 *
 *   ENOSYS, EINVAL, ENOTSUP, EOPNOTSUPP -> the genuine capability gap.
 *   EEXIST, ENOENT                      -> the probe's OWN preconditions were
 *                                          violated: step 0 cleared both
 *                                          names and step 1 created the
 *                                          source, so something reached into
 *                                          them between step 0 and step 2.
 *                                          Not evidence about capability.
 *                                          The probe fails.
 *   anything else                       -> unclassified.  The probe fails.
 *
 * READING EINVAL AS "the flag is unsupported" IS STILL A CONSTRUCTION
 * ARGUMENT, and saying otherwise would overclaim.  EINVAL also means
 * genuinely invalid arguments; that reading is safe here ONLY BECAUSE THE
 * PROBE'S ARGUMENTS ARE FIXED LITERALS IT CONTROLS -- one dirfd it holds, two
 * names it derived, one flag constant.  It is a categorically stronger
 * argument than the old one, because it is about OUR OWN INPUTS rather than
 * about what other processes might do, but it is an argument and not an
 * observation.
 *
 * AN if-CHAIN AND NOT A switch, DELIBERATELY: ENOTSUP and EOPNOTSUPP are THE
 * SAME VALUE on Linux and DIFFERENT ON DARWIN, so a switch listing both would
 * be a duplicate-case compile error on Linux.  Both must appear, because with
 * only one of them a macOS filesystem returning the other would fall through
 * to "anything else" and a genuine capability gap would be reported as a
 * probe failure -- the macOS asymmetry this rewrite exists to remove,
 * reintroduced by a different route.
 */
static wyrelog_error_t
probe_classify_rename (gint rename_errno, gboolean *out_supported)
{
  if (rename_errno == 0) {
    *out_supported = TRUE;
    return WYRELOG_E_OK;
  }
  if (rename_errno == ENOSYS || rename_errno == EINVAL
      || rename_errno == ENOTSUP || rename_errno == EOPNOTSUPP) {
    *out_supported = FALSE;
    return WYRELOG_E_OK;
  }
  return WYRELOG_E_IO;
}

wyrelog_error_t
wyl_fact_artifact_transition_posix_probe_capability
  (const WylFactGraphDirectory *directory, const gchar *operation_uuid,
    WylFactArtifactTransitionPosixCapability *out_capability)
{
  if (out_capability != NULL)
    *out_capability = (WylFactArtifactTransitionPosixCapability) {
      .no_replace_supported = FALSE,
      .directory_flush
        = WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_UNPROVEN,
    };
  if (directory == NULL || out_capability == NULL || directory->graph_fd < 0)
    return WYRELOG_E_INVALID;

  WylFactArtifactTransitionNames names = { 0 };
  wyrelog_error_t status
    = wyl_fact_artifact_transition_names_derive (operation_uuid, &names);
  if (status != WYRELOG_E_OK)
    return status;

  gint graph_fd = directory->graph_fd;
  gboolean supported = FALSE;
  status = probe_preclean (graph_fd, &names);
  if (status != WYRELOG_E_OK)
    goto done;

  gint probe_fd = -1;
  if (posix_fault_take (POSIX_FAULT (PROBE_CREATE))) {
    /* No errno is set here on purpose: this path never classifies by errno.
     * It fails on probe_fd < 0 and reports IO unconditionally, because
     * without a created source the rename's errno says nothing about the
     * flag.  Writing the global would be a dead store and would suggest a
     * classification that does not happen. */
  } else {
    probe_fd = openat (graph_fd, names.probe,
            O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
  }
  if (probe_fd < 0) {
    status = WYRELOG_E_IO;
    goto done;
  }
  close (probe_fd);

  gint rename_errno;
  if (posix_fault_take (POSIX_FAULT (PROBE_RENAME))) {
    /* Take-and-disarm, like the one-shot fault beside it -- but the clear
     * happens HERE, on consumption, so it bounds nothing when this arm is
     * never reached.  See posix_take_level. */
    gint injected = posix_take_level (&transition_posix_test_rename_errno);
    rename_errno = injected != 0 ? injected : ENOSYS;
  } else {
    rename_errno = transition_rename_no_replace (graph_fd, names.probe,
            names.probe_moved);
  }
  status = probe_classify_rename (rename_errno, &supported);
  if (status != WYRELOG_E_OK)
    goto done;

  /*
   * Directory-flush capability, same run.  EINVAL, ENOTSUP and EOPNOTSUPP are
   * the "this filesystem cannot prove a flush" answers; anything else is a
   * real failure and the probe must not paper over it.
   *
   * THIS ROW MUST ACCEPT THE SAME PAIR THE RENAME ROW DOES, and for the same
   * reason: ENOTSUP and EOPNOTSUPP are one value on Linux and two spellings
   * of "operation not supported" on Darwin, so accepting only one lets a
   * macOS filesystem with a genuine capability gap fall through to a PROBE
   * FAILURE.  The two outcomes are not both merely conservative --
   * UNSUPPORTED claims nothing and still blocks PUBLISHED_DURABLE, requiring
   * an explicit acknowledgement to finalize, whereas a probe failure means
   * that filesystem cannot run a restore AT ALL.  An if-chain and not a
   * switch, because on Linux the pair would be a duplicate-case error.
   *
   * ERRNO IS CAPTURED INTO A LOCAL ON THE LINE THAT PRODUCES IT, matching the
   * rename path, so the classification below reads a value rather than a
   * global that any intervening call could clobber.
   */
  gint flush_result;
  gint flush_errno;
  if (posix_fault_take (POSIX_FAULT (PROBE_DIRECTORY_FSYNC))) {
    /* Take-and-disarm, as above. */
    gint injected = posix_take_level (&transition_posix_test_flush_errno);
    flush_result = -1;
    flush_errno = injected != 0 ? injected : EIO;
  } else {
    flush_result = fsync (graph_fd);
    flush_errno = flush_result == 0 ? 0 : errno;
  }
  if (flush_result == 0) {
    out_capability->directory_flush
      = WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_PROVEN;
  } else if (flush_errno == EINVAL || flush_errno == ENOTSUP
      || flush_errno == EOPNOTSUPP) {
    out_capability->directory_flush
      = WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_UNSUPPORTED;
  } else {
    status = WYRELOG_E_IO;
    goto done;
  }
  out_capability->no_replace_supported = supported;

done:
  /* The probe's two names are operation-owned artifacts, so they must have a
   * retirement path on EVERY exit -- success, unsupported, and every error.
   * A probe that leaves either behind poisons the inventory gate's
   * unknown-entry count for every future operation on this graph, exactly as
   * a stranded stage would. */
  gboolean retired = probe_retire (graph_fd, &names);
  wyl_fact_artifact_transition_names_clear (&names);
  /*
   * A RETIRE THAT GENUINELY FAILED MUST NOT REPORT SUCCESS.  Dropping the
   * unlink return here would hand back WYRELOG_E_OK with a probe name
   * resident, and that name is a non-fixed entry -- so the inventory gate's
   * unknown-entry count would then refuse EVERY future operation on this
   * graph.  probe_preclean fails closed on exactly the same error and this
   * path must match it.  Ordered so it reports the failure without masking an
   * earlier, more specific one.
   */
  if (!retired && status == WYRELOG_E_OK)
    status = WYRELOG_E_IO;
  if (status != WYRELOG_E_OK)
    *out_capability = (WylFactArtifactTransitionPosixCapability) {
      .no_replace_supported = FALSE,
      .directory_flush
        = WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_UNPROVEN,
    };
  return status;
}

/* ------------------------------------------------------------------ */
/* open / observe / free                                               */
/* ------------------------------------------------------------------ */

wyrelog_error_t
wyl_fact_artifact_transition_posix_open
  (const WylFactGraphDirectory *directory, WylFactRootWriterLease *lease,
    const gchar *operation_uuid,
    const WylFactArtifactTransitionPosixCapability *capability,
    WylFactArtifactTransitionPosix **out_provider)
{
  if (out_provider != NULL)
    *out_provider = NULL;
  if (directory == NULL || lease == NULL || capability == NULL
      || out_provider == NULL || directory->graph_fd < 0)
    return WYRELOG_E_INVALID;

  WylFactArtifactTransitionNames names = { 0 };
  wyrelog_error_t status
    = wyl_fact_artifact_transition_names_derive (operation_uuid, &names);
  if (status != WYRELOG_E_OK)
    return status;
  wyl_id_t id;
  if (wyl_id_parse (operation_uuid, &id) != WYRELOG_E_OK) {
    wyl_fact_artifact_transition_names_clear (&names);
    return WYRELOG_E_INVALID;
  }

  WylFactArtifactTransitionPosix *provider
    = g_new0 (WylFactArtifactTransitionPosix, 1);
  provider->graph_fd = directory->graph_fd;
  provider->lease = lease;
  provider->names = names;
  provider->capability = *capability;
  memcpy (provider->operation_uuid, id.bytes,
      sizeof provider->operation_uuid);
  *out_provider = provider;
  return WYRELOG_E_OK;
}

void
wyl_fact_artifact_transition_posix_free
  (WylFactArtifactTransitionPosix *provider)
{
  if (provider == NULL)
    return;
  wyl_fact_artifact_transition_names_clear (&provider->names);
  g_free (provider);
}

wyrelog_error_t
wyl_fact_artifact_transition_posix_observe
  (WylFactArtifactTransitionPosix *provider,
    const WylFactArtifactTransitionPosixLifecycle *lifecycle,
    WylFactArtifactMainTransitionObservation *out_observation)
{
  if (out_observation != NULL)
    *out_observation = (WylFactArtifactMainTransitionObservation) { 0 };
  if (provider == NULL || lifecycle == NULL || out_observation == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t status
    = wyl_fact_root_writer_lease_verify (provider->lease);
  if (status != WYRELOG_E_OK)
    return status;

  struct stat directory = { 0 };
  if (posix_fault_take (POSIX_FAULT (OBSERVE_DIRECTORY_FSTAT))
      || fstat (provider->graph_fd, &directory) != 0)
    return WYRELOG_E_IO;

  /* The lease identity is the graph lock's (st_dev, st_ino).  The contract
   * only requires that admission and every later observation agree; the lock
   * is the natural choice because #612 pins it and the inventory already uses
   * it as its guard identity.  A missing lock is a broken lease, not an
   * absent slot, so it fails the observation rather than zeroing a field. */
  struct stat lock = { 0 };
  if (posix_fault_take (POSIX_FAULT (OBSERVE_LEASE_FSTAT))
      || fstatat (provider->graph_fd, WYL_FACT_ARTIFACT_TRANSITION_LOCK_NAME,
      &lock, AT_SYMLINK_NOFOLLOW) != 0)
    return WYRELOG_E_IO;

  WylFactArtifactMainTransitionObservation observation = {
    .directory_identity = identity_from_stat (&directory),
    .lease_identity = identity_from_stat (&lock),
    .sealed = lifecycle->sealed,
    .main_binding_live = lifecycle->main_binding_live,
    .no_replace_supported = provider->capability.no_replace_supported,
  };
  memcpy (observation.operation_uuid, provider->operation_uuid,
      sizeof observation.operation_uuid);
  for (guint slot = 0; slot < MT_SLOT_COUNT; slot++) {
    status = observe_slot (provider, slot, &observation.entries[slot]);
    if (status != WYRELOG_E_OK)
      return status;
  }
  /* All four durability fields stay UNPROVEN.  They are inputs to record only
   * and unit 2b fills them; a provider that invented them would be claiming
   * receipts it never took. */
  *out_observation = observation;
  return WYRELOG_E_OK;
}

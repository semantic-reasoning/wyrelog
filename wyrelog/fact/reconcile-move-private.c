/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#endif

#include "wyrelog/fact/reconcile-move-private.h"

#include "wyrelog/fact/graph-locator-private.h"
#include "wyrelog/fact/root-writer-lease-private.h"

#include <string.h>

#include <glib/gstdio.h>

#ifndef G_OS_WIN32
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#include <windows.h>

#include <io.h>
#endif

#define WYL_FACT_RECONCILE_MOVE_COPY_CHUNK 65536u

#ifdef G_OS_WIN32
/* Capture V1 evidence from a native Windows file handle: FileIdInfo identity,
 * GetFileSizeEx size, and a SHA-256 over the whole file read at explicit
 * offsets.  A non-regular file, a torn read that overshoots the recorded size,
 * or a short read fails closed. */
static wyrelog_error_t
reconcile_capture_from_handle (HANDLE handle,
    WylPolicyFactReconcileArtifactEvidence *out_evidence)
{
  FILE_ID_INFO id_info = { 0 };
  BY_HANDLE_FILE_INFORMATION basic = { 0 };
  if (!GetFileInformationByHandleEx (handle, FileIdInfo, &id_info,
          sizeof id_info))
    return WYRELOG_E_IO;
  if (!GetFileInformationByHandle (handle, &basic))
    return WYRELOG_E_IO;
  if ((basic.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY
              | FILE_ATTRIBUTE_REPARSE_POINT)) != 0
      || basic.nNumberOfLinks != 1)
    return WYRELOG_E_POLICY;

  LARGE_INTEGER file_size = { 0 };
  if (!GetFileSizeEx (handle, &file_size) || file_size.QuadPart < 0)
    return WYRELOG_E_IO;
  guint64 expected = (guint64) file_size.QuadPart;

  g_autoptr (GChecksum) checksum = g_checksum_new (G_CHECKSUM_SHA256);
  if (checksum == NULL)
    return WYRELOG_E_NOMEM;

  guint8 buffer[WYL_FACT_RECONCILE_MOVE_COPY_CHUNK];
  guint64 total = 0;
  guint64 offset = 0;
  for (;;) {
    OVERLAPPED overlapped = { 0 };
    overlapped.Offset = (DWORD) (offset & 0xffffffffu);
    overlapped.OffsetHigh = (DWORD) (offset >> 32);
    DWORD got = 0;
    if (!ReadFile (handle, buffer, (DWORD) sizeof buffer, &got, &overlapped)) {
      if (GetLastError () == ERROR_HANDLE_EOF)
        break;
      return WYRELOG_E_IO;
    }
    if (got == 0)
      break;
    g_checksum_update (checksum, buffer, (gssize) got);
    total += (guint64) got;
    offset += (guint64) got;
    if (total > expected)
      return WYRELOG_E_POLICY;
  }
  if (total != expected)
    return WYRELOG_E_POLICY;

  gsize digest_length = sizeof out_evidence->digest;
  g_checksum_get_digest (checksum, out_evidence->digest, &digest_length);
  if (digest_length != sizeof out_evidence->digest)
    return WYRELOG_E_INTERNAL;

  out_evidence->version = WYL_POLICY_FACT_RECONCILE_ARTIFACT_EVIDENCE_V1;
  out_evidence->identity_kind =
      WYL_POLICY_FACT_RECONCILE_ARTIFACT_IDENTITY_WINDOWS;
  out_evidence->windows_volume_serial = id_info.VolumeSerialNumber;
  memcpy (out_evidence->windows_file_id, id_info.FileId.Identifier,
      sizeof out_evidence->windows_file_id);
  out_evidence->size_bytes = expected;
  out_evidence->digest_algorithm =
      WYL_POLICY_FACT_RECONCILE_ARTIFACT_DIGEST_SHA256;
  return WYRELOG_E_OK;
}

/* Copy exactly |size| bytes from |src| into |dst| at explicit offsets.  Any
 * read or write fault, or a source shorter than the promised size, is an I/O
 * failure: the copied artifact would not reproduce the verified digest. */
static wyrelog_error_t
reconcile_move_copy_exact_windows (HANDLE src, HANDLE dst, guint64 size)
{
  guint8 buffer[WYL_FACT_RECONCILE_MOVE_COPY_CHUNK];
  guint64 remaining = size;
  guint64 offset = 0;
  while (remaining > 0) {
    DWORD want = remaining < sizeof buffer ? (DWORD) remaining
        : (DWORD) sizeof buffer;
    OVERLAPPED read_ov = { 0 };
    read_ov.Offset = (DWORD) (offset & 0xffffffffu);
    read_ov.OffsetHigh = (DWORD) (offset >> 32);
    DWORD got = 0;
    if (!ReadFile (src, buffer, want, &got, &read_ov) || got == 0)
      return WYRELOG_E_IO;
    DWORD written = 0;
    while (written < got) {
      guint64 at = offset + written;
      OVERLAPPED write_ov = { 0 };
      write_ov.Offset = (DWORD) (at & 0xffffffffu);
      write_ov.OffsetHigh = (DWORD) (at >> 32);
      DWORD put = 0;
      if (!WriteFile (dst, buffer + written, got - written, &put, &write_ov)
          || put == 0)
        return WYRELOG_E_IO;
      written += put;
    }
    remaining -= (guint64) got;
    offset += (guint64) got;
  }
  return WYRELOG_E_OK;
}
#endif /* G_OS_WIN32 */

wyrelog_error_t
wyl_fact_reconcile_capture_artifact_evidence (gint fd,
    WylPolicyFactReconcileArtifactEvidence *out_evidence)
{
  if (out_evidence == NULL || fd < 0)
    return WYRELOG_E_INVALID;
  *out_evidence = (WylPolicyFactReconcileArtifactEvidence) {
  0};

#ifdef G_OS_WIN32
  HANDLE handle = (HANDLE) _get_osfhandle (fd);
  if (handle == INVALID_HANDLE_VALUE)
    return WYRELOG_E_IO;
  return reconcile_capture_from_handle (handle, out_evidence);
#else
  struct stat st;
  if (fstat (fd, &st) != 0)
    return WYRELOG_E_IO;
  if (!S_ISREG (st.st_mode))
    return WYRELOG_E_POLICY;

  g_autoptr (GChecksum) checksum = g_checksum_new (G_CHECKSUM_SHA256);
  if (checksum == NULL)
    return WYRELOG_E_NOMEM;

  guint8 buffer[WYL_FACT_RECONCILE_MOVE_COPY_CHUNK];
  guint64 total = 0;
  off_t offset = 0;
  for (;;) {
    ssize_t got = pread (fd, buffer, sizeof buffer, offset);
    if (got < 0) {
      if (errno == EINTR)
        continue;
      return WYRELOG_E_IO;
    }
    if (got == 0)
      break;
    g_checksum_update (checksum, buffer, (gssize) got);
    total += (guint64) got;
    offset += got;
    /* A source that grows past its stat size while we read it is torn: the
     * captured digest would not describe a single durable state. */
    if (total > (guint64) st.st_size)
      return WYRELOG_E_POLICY;
  }
  if (total != (guint64) st.st_size)
    return WYRELOG_E_POLICY;

  gsize digest_length = sizeof out_evidence->digest;
  g_checksum_get_digest (checksum, out_evidence->digest, &digest_length);
  if (digest_length != sizeof out_evidence->digest)
    return WYRELOG_E_INTERNAL;

  out_evidence->version = WYL_POLICY_FACT_RECONCILE_ARTIFACT_EVIDENCE_V1;
  out_evidence->identity_kind =
      WYL_POLICY_FACT_RECONCILE_ARTIFACT_IDENTITY_POSIX;
  out_evidence->posix_device = (guint64) st.st_dev;
  out_evidence->posix_inode = (guint64) st.st_ino;
  out_evidence->size_bytes = (guint64) st.st_size;
  out_evidence->digest_algorithm =
      WYL_POLICY_FACT_RECONCILE_ARTIFACT_DIGEST_SHA256;
  return WYRELOG_E_OK;
#endif /* G_OS_WIN32 */
}

#ifndef G_OS_WIN32
/* Copy exactly |size| bytes from |src_fd| into |dst_fd| starting at offset 0.
 * A source that is shorter than the promised size, or any read/write fault,
 * is an I/O failure: the copied artifact would not reproduce the verified
 * digest. */
static wyrelog_error_t
reconcile_move_copy_exact (gint src_fd, gint dst_fd, guint64 size)
{
  guint8 buffer[WYL_FACT_RECONCILE_MOVE_COPY_CHUNK];
  guint64 remaining = size;
  off_t offset = 0;
  while (remaining > 0) {
    gsize want = remaining < sizeof buffer ? (gsize) remaining : sizeof buffer;
    ssize_t got = pread (src_fd, buffer, want, offset);
    if (got < 0) {
      if (errno == EINTR)
        continue;
      return WYRELOG_E_IO;
    }
    if (got == 0)
      return WYRELOG_E_IO;
    gsize written = 0;
    while (written < (gsize) got) {
      ssize_t put = write (dst_fd, buffer + written, (gsize) got - written);
      if (put < 0) {
        if (errno == EINTR)
          continue;
        return WYRELOG_E_IO;
      }
      written += (gsize) put;
    }
    remaining -= (guint64) got;
    offset += got;
  }
  return WYRELOG_E_OK;
}
#endif /* !G_OS_WIN32 */

/* True when two evidence records name the same native file identity: the same
 * device+inode on POSIX, or the same volume serial and 16-byte file id on
 * Windows.  Used to reject a canonical target that is merely another link to
 * the source. */
static gboolean
same_native_identity (const WylPolicyFactReconcileArtifactEvidence *a,
    const WylPolicyFactReconcileArtifactEvidence *b)
{
  if (a->identity_kind != b->identity_kind)
    return FALSE;
  switch (a->identity_kind) {
    case WYL_POLICY_FACT_RECONCILE_ARTIFACT_IDENTITY_POSIX:
      return a->posix_device == b->posix_device
          && a->posix_inode == b->posix_inode;
    case WYL_POLICY_FACT_RECONCILE_ARTIFACT_IDENTITY_WINDOWS:
      return a->windows_volume_serial == b->windows_volume_serial
          && memcmp (a->windows_file_id, b->windows_file_id,
          sizeof a->windows_file_id) == 0;
    default:
      return FALSE;
  }
}

/* True when |ev| reproduces the recorded source content: same size, digest
 * algorithm and digest.  Native identity is deliberately not compared, so a
 * distinct-inode copy of the same bytes matches. */
static gboolean
content_matches (const WylPolicyFactReconcileArtifactEvidence *ev,
    const WylPolicyFactReconcileArtifactEvidence *expected)
{
  return ev->size_bytes == expected->size_bytes
      && ev->digest_algorithm == expected->digest_algorithm
      && memcmp (ev->digest, expected->digest, sizeof ev->digest) == 0;
}

/* Capture evidence from an opened source regular file.  Leaf that forks on the
 * platform-specific handle the source struct holds; the orchestration body
 * never touches that handle directly. */
static wyrelog_error_t
reconcile_capture_source (const WylFactGraphRegularFile *src,
    WylPolicyFactReconcileArtifactEvidence *out_evidence)
{
#ifdef G_OS_WIN32
  return reconcile_capture_from_handle ((HANDLE) src->handle, out_evidence);
#else
  return wyl_fact_reconcile_capture_artifact_evidence (src->fd, out_evidence);
#endif
}

/* Copy exactly |size| bytes from the opened source into the stage.  Leaf that
 * forks on the platform-specific source and stage handles. */
static wyrelog_error_t
reconcile_copy_source_to_stage (const WylFactGraphRegularFile *src,
    WylFactGraphStage *stage, guint64 size)
{
#ifdef G_OS_WIN32
  HANDLE dst = (HANDLE) _get_osfhandle (stage->fd);
  if (dst == INVALID_HANDLE_VALUE)
    return WYRELOG_E_IO;
  return reconcile_move_copy_exact_windows ((HANDLE) src->handle, dst, size);
#else
  return reconcile_move_copy_exact (src->fd, stage->fd, size);
#endif
}

/* The one canonical published artifact name for every graph. */
#define WYL_FACT_RECONCILE_MOVE_FINAL_BASENAME "facts.duckdb"

static wyrelog_error_t
reconcile_move_map_cas (WylPolicyAuthorityMutationResult result,
    gboolean copied, WylFactReconcileMoveOutcome *out_outcome)
{
  switch (result) {
    case WYL_POLICY_AUTHORITY_MUTATION_APPLIED:
      /* A skipped copy (target already our own artifact) converged the CAS
       * but changed no bytes this call: report it as a replay. */
      *out_outcome = copied ? WYL_FACT_RECONCILE_MOVE_APPLIED
          : WYL_FACT_RECONCILE_MOVE_UNCHANGED_REPLAY;
      return WYRELOG_E_OK;
    case WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY:
      *out_outcome = WYL_FACT_RECONCILE_MOVE_UNCHANGED_REPLAY;
      return WYRELOG_E_OK;
    case WYL_POLICY_AUTHORITY_MUTATION_NOT_FOUND:
      return WYRELOG_E_NOT_FOUND;
    case WYL_POLICY_AUTHORITY_MUTATION_STALE:
    case WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION:
    default:
      return WYRELOG_E_POLICY;
  }
}

wyrelog_error_t
wyl_fact_reconcile_move_publish (const WylFactReconcileMoveContext *ctx,
    WylFactReconcileMoveOutcome *out_outcome)
{
  if (ctx == NULL || ctx->store == NULL || ctx->fact_root == NULL
      || ctx->op_uuid == NULL || out_outcome == NULL)
    return WYRELOG_E_INVALID;

  g_autoptr (WylFactRootWriterLease) lease = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (ctx->fact_root,
      &lease);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphStage stage = WYL_FACT_GRAPH_STAGE_INIT;
  WylFactGraphRegularFile source = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  WylPolicyFactReconcileJournalRecord *record = NULL;
  WylPolicyGraphAuthorityRecord *graph_authority = NULL;
  WylPolicyTenantAuthorityRecord *tenant_authority = NULL;
  gint published_fd = -1;
  gboolean copied = FALSE;
  gboolean run_cas = FALSE;

  rc = wyl_fact_graph_resolver_open (ctx->fact_root, &resolver);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (ctx->checkpoint != NULL)
    wyl_fact_graph_resolver_set_checkpoint_for_test (&resolver, ctx->checkpoint,
        ctx->checkpoint_data);
  /* Issue-mandated identity gate: the resolver must name the exact root the
   * lease covers, even though the lease carries its own resolver. */
  rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc != WYRELOG_E_OK)
    goto out;

  rc = wyl_policy_store_reconcile_journal_read (ctx->store, ctx->op_uuid,
      &record);
  if (rc != WYRELOG_E_OK)
    goto out;

  if (record->state == WYL_POLICY_FACT_RECONCILE_MOVED) {
    *out_outcome = WYL_FACT_RECONCILE_MOVE_UNCHANGED_REPLAY;
    rc = WYRELOG_E_OK;
    goto out;
  }
  if (record->state != WYL_POLICY_FACT_RECONCILE_MOVING) {
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  if (g_strcmp0 (record->tenant_id, ctx->tenant_id) != 0
      || g_strcmp0 (record->graph_id, ctx->graph_id) != 0) {
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  if (!wyl_policy_fact_reconcile_artifact_evidence_is_valid
      (&record->source_evidence)) {
    rc = WYRELOG_E_INVALID;
    goto out;
  }

  /* Authority-generation validation: the graph the record binds must still
   * sit at the generations reconciliation prepared against, and the owning
   * tenant must exist.  This is a fail-closed gate, not a generation-atomic
   * CAS: the authoritative atomic guard remains the attempt-gated journal
   * transition plus the unique active-operation index (the transition API is
   * intentionally unchanged).  The graph generations are re-read and
   * re-checked immediately before the CAS so this window stays tight. */
  rc = wyl_policy_store_read_graph_authority (ctx->store, record->tenant_id,
      record->graph_id, &graph_authority);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (graph_authority->lifecycle_generation
      != record->expected_lifecycle_generation
      || graph_authority->reconciliation_generation
      != record->expected_reconciliation_generation) {
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  g_clear_pointer (&graph_authority, wyl_policy_graph_authority_record_free);

  rc = wyl_policy_store_read_tenant_authority (ctx->store, record->tenant_id,
      &tenant_authority);
  if (rc != WYRELOG_E_OK) {
    /* The tenant must exist for reconciliation to publish under it.  We do
     * not gate on sealed/lifecycle_state here to avoid rejecting legitimate
     * reconciliation. */
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  g_clear_pointer (&tenant_authority, wyl_policy_tenant_authority_record_free);

  rc = wyl_fact_graph_locator_init (&locator, record->tenant_id,
      record->graph_id);
  if (rc != WYRELOG_E_OK)
    goto out;

  /* Basename authority: publish only under the fixed canonical name and only
   * where the persisted path already agrees with the derived graph dir. */
  {
    g_autofree gchar *relative_dir =
        wyl_fact_graph_locator_relative_dir (&locator);
    g_autofree gchar *canonical_dir =
        g_path_get_dirname (record->canonical_relative_path);
    g_autofree gchar *canonical_base =
        g_path_get_basename (record->canonical_relative_path);
    if (relative_dir == NULL || g_strcmp0 (canonical_dir, relative_dir) != 0
        || g_strcmp0 (canonical_base,
            WYL_FACT_RECONCILE_MOVE_FINAL_BASENAME) != 0) {
      rc = WYRELOG_E_POLICY;
      goto out;
    }
  }

  /* Lexical aliasing: the recorded source and canonical target must be
   * distinct relative paths.  Publishing a file onto its own name is never a
   * legitimate move, regardless of what the filesystem currently holds. */
  if (g_strcmp0 (record->source_relative_path,
          record->canonical_relative_path) == 0) {
    rc = WYRELOG_E_POLICY;
    goto out;
  }

  /* Reassert that the lease still authorizes this resolver before each
   * filesystem mutation.  Root-identity or resolver drift between gates fails
   * closed with the journal left MOVING, never a false MOVED. */
  rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc != WYRELOG_E_OK)
    goto out;

  rc = wyl_fact_graph_resolver_open_directory (&resolver, &locator, TRUE,
      &directory);
  if (rc != WYRELOG_E_OK)
    goto out;

  /* Idempotent target pre-check: converge on our own already-published
   * artifact, never overwrite unknown bytes. */
  {
    gint target_fd = -1;
    wyrelog_error_t probe = wyl_fact_graph_directory_open_file (&directory,
        WYL_FACT_RECONCILE_MOVE_FINAL_BASENAME, FALSE, &target_fd);
    if (probe == WYRELOG_E_OK) {
      WylPolicyFactReconcileArtifactEvidence target_ev;
      rc = wyl_fact_reconcile_capture_artifact_evidence (target_fd, &target_ev);
      g_close (target_fd, NULL);
      if (rc != WYRELOG_E_OK)
        goto out;

      /* Identity aliasing (best-effort): if the source still opens and shares
       * the present target's native identity, the canonical name is merely
       * another link to the source - reject rather than "converge" a file
       * onto itself.  A source that cannot be opened for any reason is
       * skipped: the target-digest match below is independent proof and must
       * not wedge a legitimate replay. */
      {
        wyrelog_error_t alias = wyl_fact_graph_resolver_open_relative_regular
            (&resolver, record->source_relative_path, &source);
        if (alias == WYRELOG_E_OK) {
          WylPolicyFactReconcileArtifactEvidence alias_ev;
          alias = reconcile_capture_source (&source, &alias_ev);
          if (alias == WYRELOG_E_OK
              && same_native_identity (&alias_ev, &target_ev))
            rc = WYRELOG_E_POLICY;
        }
        wyl_fact_graph_regular_file_clear (&source);
        if (rc != WYRELOG_E_OK)
          goto out;
      }

      if (content_matches (&target_ev, &record->source_evidence)) {
        run_cas = TRUE;
      } else {
        rc = WYRELOG_E_POLICY;
        goto out;
      }
    } else if (probe == WYRELOG_E_NOT_FOUND) {
      /* Copy path: re-verify the source against the journal, then stage,
       * copy, sync and atomically publish before touching the journal. */
      rc = wyl_fact_graph_resolver_open_relative_regular (&resolver,
          record->source_relative_path, &source);
      if (rc != WYRELOG_E_OK)
        goto out;

      WylPolicyFactReconcileArtifactEvidence source_ev;
      rc = reconcile_capture_source (&source, &source_ev);
      if (rc != WYRELOG_E_OK)
        goto out;
      if (!wyl_policy_fact_reconcile_artifact_evidence_equal (&source_ev,
              &record->source_evidence)) {
        rc = WYRELOG_E_POLICY;
        goto out;
      }

      if (ctx->checkpoint != NULL) {
        rc = ctx->checkpoint ("source-verified", ctx->checkpoint_data);
        if (rc != WYRELOG_E_OK)
          goto out;
      }

      rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
      if (rc != WYRELOG_E_OK)
        goto out;

      rc = wyl_fact_graph_directory_stage_create (&directory,
          WYL_FACT_RECONCILE_MOVE_FINAL_BASENAME, &stage);
      if (rc != WYRELOG_E_OK)
        goto out;

      rc = reconcile_copy_source_to_stage (&source, &stage,
          record->source_evidence.size_bytes);
      if (rc == WYRELOG_E_OK)
        rc = wyl_fact_graph_stage_sync (&stage);
      if (rc != WYRELOG_E_OK) {
        /* The final is still absent: drop the temp before releasing it. */
        (void) wyl_fact_graph_stage_abort (&directory, &stage);
        goto out;
      }

      rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
      if (rc != WYRELOG_E_OK) {
        /* Nothing is published yet; drop the synced temp before releasing. */
        (void) wyl_fact_graph_stage_abort (&directory, &stage);
        goto out;
      }

      rc = wyl_fact_graph_stage_publish (&directory, &stage);
      if (rc != WYRELOG_E_OK)
        /* The final may now be durable; never abort by mutable name here. */
        goto out;
      copied = TRUE;

      /* Post-publish reopen-verify.  Reopen the durable final and confirm its
       * content still reproduces the recorded source digest before the CAS: a
       * fault or swap between publish and CAS that changed the bytes must fail
       * closed, never a MOVED over content that no longer matches.  Identity
       * is deliberately not compared here - the copy has a distinct inode. */
      if (ctx->checkpoint != NULL) {
        rc = ctx->checkpoint ("published", ctx->checkpoint_data);
        if (rc != WYRELOG_E_OK)
          goto out;
      }
      rc = wyl_fact_graph_directory_open_file (&directory,
          WYL_FACT_RECONCILE_MOVE_FINAL_BASENAME, FALSE, &published_fd);
      if (rc != WYRELOG_E_OK)
        goto out;
      {
        WylPolicyFactReconcileArtifactEvidence published_ev;
        rc = wyl_fact_reconcile_capture_artifact_evidence (published_fd,
            &published_ev);
        if (rc != WYRELOG_E_OK)
          goto out;
        if (!content_matches (&published_ev, &record->source_evidence)) {
          rc = WYRELOG_E_POLICY;
          goto out;
        }
      }
      run_cas = TRUE;
    } else {
      rc = probe;
      goto out;
    }
  }

  if (!run_cas) {
    rc = WYRELOG_E_INTERNAL;
    goto out;
  }

  if (ctx->checkpoint != NULL) {
    rc = ctx->checkpoint ("pre-journal-cas", ctx->checkpoint_data);
    if (rc != WYRELOG_E_OK)
      goto out;
  }

  /* Final reassert immediately before the CAS: reprove the lease authorizes
   * this resolver and that the graph still sits at the prepared generations.
   * Placed after the pre-journal-cas checkpoint so a checkpoint fault still
   * leaves a recoverable MOVING.  Any drift fails closed with no MOVED. */
  rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc != WYRELOG_E_OK)
    goto out;
  rc = wyl_policy_store_read_graph_authority (ctx->store, record->tenant_id,
      record->graph_id, &graph_authority);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (graph_authority->lifecycle_generation
      != record->expected_lifecycle_generation
      || graph_authority->reconciliation_generation
      != record->expected_reconciliation_generation) {
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  g_clear_pointer (&graph_authority, wyl_policy_graph_authority_record_free);

  {
    WylPolicyAuthorityMutationResult mutation =
        WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
    rc = wyl_policy_store_reconcile_journal_transition (ctx->store,
        ctx->op_uuid, WYL_POLICY_FACT_RECONCILE_MOVING,
        WYL_POLICY_FACT_RECONCILE_MOVED, record->attempt, &mutation);
    if (rc == WYRELOG_E_OK)
      rc = reconcile_move_map_cas (mutation, copied, out_outcome);
  }

out:
  wyl_fact_graph_stage_clear (&stage);
  wyl_fact_graph_regular_file_clear (&source);
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_graph_resolver_clear (&resolver);
  g_clear_pointer (&graph_authority, wyl_policy_graph_authority_record_free);
  g_clear_pointer (&tenant_authority, wyl_policy_tenant_authority_record_free);
  if (published_fd >= 0)
    g_close (published_fd, NULL);
  wyl_policy_fact_reconcile_journal_record_free (record);
  return rc;
}

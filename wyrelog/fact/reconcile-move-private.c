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

#ifndef G_OS_WIN32
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define WYL_FACT_RECONCILE_MOVE_COPY_CHUNK 65536u

wyrelog_error_t
wyl_fact_reconcile_capture_artifact_evidence (gint fd,
    WylPolicyFactReconcileArtifactEvidence *out_evidence)
{
  if (out_evidence == NULL || fd < 0)
    return WYRELOG_E_INVALID;
  *out_evidence = (WylPolicyFactReconcileArtifactEvidence) {
  0};

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
}

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
      close (target_fd);
      if (rc != WYRELOG_E_OK)
        goto out;
      if (target_ev.size_bytes == record->source_evidence.size_bytes
          && target_ev.digest_algorithm
          == record->source_evidence.digest_algorithm
          && memcmp (target_ev.digest, record->source_evidence.digest,
              sizeof target_ev.digest) == 0) {
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
      rc = wyl_fact_reconcile_capture_artifact_evidence (source.fd, &source_ev);
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

      rc = wyl_fact_graph_directory_stage_create (&directory,
          WYL_FACT_RECONCILE_MOVE_FINAL_BASENAME, &stage);
      if (rc != WYRELOG_E_OK)
        goto out;

      rc = reconcile_move_copy_exact (source.fd, stage.fd,
          record->source_evidence.size_bytes);
      if (rc == WYRELOG_E_OK)
        rc = wyl_fact_graph_stage_sync (&stage);
      if (rc != WYRELOG_E_OK) {
        /* The final is still absent: drop the temp before releasing it. */
        (void) wyl_fact_graph_stage_abort (&directory, &stage);
        goto out;
      }

      rc = wyl_fact_graph_stage_publish (&directory, &stage);
      if (rc != WYRELOG_E_OK)
        /* The final may now be durable; never abort by mutable name here. */
        goto out;
      copied = TRUE;
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
  wyl_policy_fact_reconcile_journal_record_free (record);
  return rc;
}

#endif /* !G_OS_WIN32 */

/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "fact/offline-restore-stage-private.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifdef G_OS_WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#define RESTORE_STAGE_MAX_WRITE (1024u * 1024u)
#define RESTORE_STAGE_READ_CHUNK (64u * 1024u)

struct WylFactOfflineRestoreStage
{
  WylFactGraphResolver *resolver;
  WylFactGraphDirectory *directory;
  WylFactRootWriterLease *writer_lease;
  WylFactGraphStage native_stage;
  guint64 bytes_written;
  guint64 expected_bytes;
  guint8 expected_digest[32];
  GChecksum *stream_checksum;
  gboolean failed;
  gboolean finalized;
};

struct WylFactOfflineRestoreStageReader
{
  WylFactGraphResolver *resolver;
  WylFactGraphDirectory *directory;
  WylFactRootWriterLease *writer_lease;
  WylFactGraphRestoreStageReader *native_reader;
};

static gboolean same_root (const WylFactGraphResolver *resolver,
    const WylFactGraphDirectory *directory);

static wyrelog_error_t
reader_authority_revalidate (WylFactOfflineRestoreStageReader *reader)
{
  if (reader == NULL || reader->resolver == NULL || reader->directory == NULL
      || reader->writer_lease == NULL
      || !same_root (reader->resolver, reader->directory))
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_verify
        (reader->writer_lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver
          (reader->writer_lease, reader->resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (reader->resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_restore_stage_reader_revalidate
          (reader->native_reader);
  return rc;
}

wyrelog_error_t
wyl_fact_offline_restore_stage_reader_open (WylFactGraphResolver *resolver,
    WylFactGraphDirectory *directory, WylFactRootWriterLease *writer_lease,
    const gchar *operation_uuid,
    const WylFactArtifactInventoryIdentity *expected_identity,
    WylFactOfflineRestoreStageReader **out_reader)
{
  if (out_reader != NULL)
    *out_reader = NULL;
#ifdef G_OS_WIN32
  (void) resolver;
  (void) directory;
  (void) writer_lease;
  (void) operation_uuid;
  (void) expected_identity;
  return WYRELOG_E_POLICY;
#else
  if (resolver == NULL || directory == NULL || writer_lease == NULL
      || operation_uuid == NULL || expected_identity == NULL
      || out_reader == NULL || !same_root (resolver, directory))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_verify (writer_lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (writer_lease,
            resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (resolver);
  WylFactOfflineRestoreStageReader *reader = NULL;
  if (rc == WYRELOG_E_OK) {
    reader = g_try_new0 (WylFactOfflineRestoreStageReader, 1);
    if (reader == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  if (rc == WYRELOG_E_OK) {
    reader->resolver = resolver;
    reader->directory = directory;
    reader->writer_lease = writer_lease;
    rc = wyl_fact_graph_directory_restore_stage_reader_open_exact
          (directory, operation_uuid, expected_identity,
            &reader->native_reader);
  }
  if (rc == WYRELOG_E_OK)
    rc = reader_authority_revalidate (reader);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_offline_restore_stage_reader_free (reader);
    return rc;
  }
  *out_reader = reader;
  return WYRELOG_E_OK;
#endif
}

wyrelog_error_t
wyl_fact_offline_restore_stage_reader_revalidate
  (WylFactOfflineRestoreStageReader *reader)
{
#ifdef G_OS_WIN32
  (void) reader;
  return WYRELOG_E_POLICY;
#else
  return reader_authority_revalidate (reader);
#endif
}

wyrelog_error_t
wyl_fact_offline_restore_stage_reader_get_size
  (WylFactOfflineRestoreStageReader *reader, guint64 *out_size)
{
  if (out_size != NULL)
    *out_size = 0;
#ifdef G_OS_WIN32
  (void) reader;
  return WYRELOG_E_POLICY;
#else
  if (reader == NULL || out_size == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = reader_authority_revalidate (reader);
  guint64 size = 0;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_restore_stage_reader_get_size
          (reader->native_reader, &size);
  if (rc == WYRELOG_E_OK)
    rc = reader_authority_revalidate (reader);
  if (rc == WYRELOG_E_OK)
    *out_size = size;
  return rc;
#endif
}

wyrelog_error_t
wyl_fact_offline_restore_stage_reader_read_at
  (WylFactOfflineRestoreStageReader *reader, guint64 offset,
    guint8 *buffer, gsize length, gsize *out_bytes_read)
{
  if (out_bytes_read != NULL)
    *out_bytes_read = 0;
#ifdef G_OS_WIN32
  (void) reader;
  (void) offset;
  (void) buffer;
  (void) length;
  return WYRELOG_E_POLICY;
#else
  if (reader == NULL || buffer == NULL || out_bytes_read == NULL
      || length == 0 || length > RESTORE_STAGE_READ_CHUNK)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = reader_authority_revalidate (reader);
  gsize bytes_read = 0;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_restore_stage_reader_read_at
          (reader->native_reader, offset, buffer, length, &bytes_read);
  if (rc == WYRELOG_E_OK)
    rc = reader_authority_revalidate (reader);
  if (rc == WYRELOG_E_OK)
    *out_bytes_read = bytes_read;
  return rc;
#endif
}

void
wyl_fact_offline_restore_stage_reader_free
  (WylFactOfflineRestoreStageReader *reader)
{
  if (reader == NULL)
    return;
  wyl_fact_graph_restore_stage_reader_free (reader->native_reader);
  g_free (reader);
}

static gboolean
parse_checksum (const gchar *text, guint8 digest[32])
{
  if (text == NULL)
    return FALSE;
  gsize length = 0;
  while (length < 72 && text[length] != '\0')
    length++;
  if (length != 71 || !g_str_has_prefix (text, "sha256:"))
    return FALSE;
  for (guint i = 0; i < 64; i++) {
    gchar c = text[7 + i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
      return FALSE;
    guint8 nibble = (guint8) g_ascii_xdigit_value (c);
    if (i % 2 == 0)
      digest[i / 2] = (guint8) (nibble << 4);
    else
      digest[i / 2] |= nibble;
  }
  return TRUE;
}

static gboolean
checksum_matches (GChecksum *checksum, const guint8 expected[32])
{
  guint8 digest[32];
  gsize size = sizeof digest;
  g_checksum_get_digest (checksum, digest, &size);
  return size == sizeof digest && memcmp (digest, expected, size) == 0;
}

static wyrelog_error_t
checkpoint (WylFactOfflineRestoreStage *stage, const gchar *point)
{
  return stage->directory->checkpoint == NULL ? WYRELOG_E_OK :
         stage->directory->checkpoint (point, stage->directory->checkpoint_data);
}

static gboolean
same_root (const WylFactGraphResolver *resolver,
    const WylFactGraphDirectory *directory)
{
#ifdef G_OS_WIN32
  return resolver->identity.volume_serial
         == directory->root_identity.volume_serial
         && memcmp (resolver->identity.file_id,
             directory->root_identity.file_id,
             sizeof resolver->identity.file_id) == 0;
#else
  return resolver->device == directory->root_device
         && resolver->inode == directory->root_inode;
#endif
}

static wyrelog_error_t
authority_revalidate (WylFactOfflineRestoreStage *stage)
{
  if (stage == NULL || stage->resolver == NULL || stage->directory == NULL
      || stage->writer_lease == NULL
      || !same_root (stage->resolver, stage->directory))
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_verify
        (stage->writer_lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver
          (stage->writer_lease, stage->resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (stage->resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_restore_stage_revalidate
          (stage->directory, &stage->native_stage);
  return rc;
}

static void
stage_identity (const WylFactGraphStage *stage,
    WylFactArtifactInventoryIdentity *out_identity)
{
  memset (out_identity, 0, sizeof *out_identity);
#ifdef G_OS_WIN32
  out_identity->domain = stage->identity.volume_serial;
  memcpy (out_identity->object_bytes, stage->identity.file_id,
      sizeof out_identity->object_bytes);
  out_identity->object_width = sizeof out_identity->object_bytes;
#else
  out_identity->domain = stage->device;
  out_identity->object = stage->inode;
#endif
}

wyrelog_error_t
wyl_fact_offline_restore_stage_new (WylFactGraphResolver *resolver,
    WylFactGraphDirectory *directory, WylFactRootWriterLease *writer_lease,
    const gchar *operation_uuid, guint64 expected_bytes,
    const gchar *expected_checksum,
    WylFactOfflineRestoreStage **out_stage)
{
  if (out_stage != NULL)
    *out_stage = NULL;
  guint8 expected_digest[32] = { 0 };
  if (resolver == NULL || directory == NULL || writer_lease == NULL
      || operation_uuid == NULL || out_stage == NULL
      || expected_bytes == 0 || expected_bytes > G_MAXINT64
      || !parse_checksum (expected_checksum, expected_digest)
      || !same_root (resolver, directory))
    return WYRELOG_E_INVALID;

#ifndef G_OS_WIN32
  off_t bound = (off_t) expected_bytes;
  if (bound < 0 || (guint64) bound != expected_bytes)
    return WYRELOG_E_INVALID;
#endif

  WylFactOfflineRestoreStage *stage = g_try_new0
        (WylFactOfflineRestoreStage, 1);
  if (stage == NULL)
    return WYRELOG_E_NOMEM;
  stage->resolver = resolver;
  stage->directory = directory;
  stage->writer_lease = writer_lease;
  stage->expected_bytes = expected_bytes;
  memcpy (stage->expected_digest, expected_digest, sizeof expected_digest);
  stage->native_stage = (WylFactGraphStage) WYL_FACT_GRAPH_STAGE_INIT;
  stage->stream_checksum = g_checksum_new (G_CHECKSUM_SHA256);
  if (stage->stream_checksum == NULL) {
    g_free (stage);
    return WYRELOG_E_NOMEM;
  }

  wyrelog_error_t rc = wyl_fact_root_writer_lease_verify (writer_lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (writer_lease,
            resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (resolver);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_restore_stage_create_exact (directory,
            operation_uuid, &stage->native_stage);
  if (rc == WYRELOG_E_OK)
    rc = authority_revalidate (stage);
  if (rc != WYRELOG_E_OK) {
    /* A post-create authority failure leaves a possible orphan. Never unlink
     * by name; close the held object and leave classification to recovery. */
    wyl_fact_graph_stage_clear (&stage->native_stage);
    g_checksum_free (stage->stream_checksum);
    g_free (stage);
    return rc;
  }
  *out_stage = stage;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_offline_restore_stage_revalidate (WylFactOfflineRestoreStage *stage)
{
  if (stage == NULL || stage->failed || stage->finalized)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = authority_revalidate (stage);
  if (rc != WYRELOG_E_OK)
    stage->failed = TRUE;
  return rc;
}

wyrelog_error_t
wyl_fact_offline_restore_stage_write (WylFactOfflineRestoreStage *stage,
    guint64 offset, const guint8 *bytes, gsize length)
{
  if (stage == NULL || bytes == NULL || length == 0
      || length > RESTORE_STAGE_MAX_WRITE || stage->failed
      || stage->finalized || offset != stage->bytes_written
      || G_MAXUINT64 - stage->bytes_written < length
      || stage->bytes_written > stage->expected_bytes
      || (guint64) length > stage->expected_bytes - stage->bytes_written)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = authority_revalidate (stage);
  gsize written = 0;
  while (rc == WYRELOG_E_OK && written < length) {
#ifdef G_OS_WIN32
    int n = _write (stage->native_stage.fd, bytes + written,
            (unsigned int) (length - written));
#else
    ssize_t n = write (stage->native_stage.fd, bytes + written,
            length - written);
#endif
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0) {
      rc = WYRELOG_E_IO;
      break;
    }
    written += (gsize) n;
  }
  if (rc == WYRELOG_E_OK) {
    stage->bytes_written += written;
    rc = authority_revalidate (stage);
  }
  if (rc != WYRELOG_E_OK)
    stage->failed = TRUE;
  else
    g_checksum_update (stage->stream_checksum, bytes, length);
  return rc;
}

wyrelog_error_t
wyl_fact_offline_restore_stage_sink (guint64 offset, const guint8 *bytes,
    gsize length, gpointer user_data)
{
  return wyl_fact_offline_restore_stage_write (user_data, offset, bytes, length);
}

static wyrelog_error_t
verify_readback (WylFactOfflineRestoreStage *stage)
{
  g_autoptr (GChecksum) checksum = g_checksum_new (G_CHECKSUM_SHA256);
  if (checksum == NULL)
    return WYRELOG_E_NOMEM;
  wyrelog_error_t rc = checkpoint (stage, "restore-stage-before-readback");
  if (rc != WYRELOG_E_OK)
    return rc;
#ifdef G_OS_WIN32
  if (_lseeki64 (stage->native_stage.fd, 0, SEEK_SET) != 0)
    return WYRELOG_E_IO;
#endif
  guint8 buffer[RESTORE_STAGE_READ_CHUNK];
  guint64 offset = 0;
  for (;;) {
    guint64 remaining = stage->expected_bytes - offset;
    gsize requested = remaining == 0 ? 1 :
        (gsize) MIN (remaining, (guint64) sizeof buffer);
#ifdef G_OS_WIN32
    int n = _read (stage->native_stage.fd, buffer, (unsigned int) requested);
#else
    ssize_t n = pread (stage->native_stage.fd, buffer, requested,
            (off_t) offset);
#endif
    if (n < 0 && errno == EINTR)
      continue;
    if (n < 0)
      return WYRELOG_E_IO;
    if (remaining == 0)
      return n == 0 && checksum_matches (checksum, stage->expected_digest)
          ? WYRELOG_E_OK : WYRELOG_E_POLICY;
    if (n == 0)
      return WYRELOG_E_POLICY;
    g_checksum_update (checksum, buffer, (gsize) n);
    offset += (guint64) n;
    rc = checkpoint (stage, "restore-stage-readback-chunk");
    if (rc != WYRELOG_E_OK)
      return rc;
  }
}

wyrelog_error_t
wyl_fact_offline_restore_stage_finalize (WylFactOfflineRestoreStage *stage,
    guint64 *out_bytes_written,
    WylFactArtifactInventoryIdentity *out_identity)
{
  if (out_bytes_written != NULL)
    *out_bytes_written = 0;
  if (out_identity != NULL)
    memset (out_identity, 0, sizeof *out_identity);
  if (stage == NULL || stage->failed || stage->finalized)
    return WYRELOG_E_INVALID;
  stage->failed = TRUE;
  if (out_bytes_written == NULL || out_identity == NULL)
    return WYRELOG_E_INVALID;
  if (stage->bytes_written != stage->expected_bytes
      || !checksum_matches (stage->stream_checksum, stage->expected_digest))
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = authority_revalidate (stage);
  guint64 staged_size = 0;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_restore_stage_get_size (stage->directory,
            &stage->native_stage, &staged_size);
  if (rc == WYRELOG_E_OK && staged_size != stage->expected_bytes)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_restore_stage_sync (stage->directory,
            &stage->native_stage);
  if (rc == WYRELOG_E_OK)
    rc = verify_readback (stage);
  if (rc == WYRELOG_E_OK)
    rc = checkpoint (stage, "restore-stage-readback-complete");
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_restore_stage_get_size (stage->directory,
            &stage->native_stage, &staged_size);
  if (rc == WYRELOG_E_OK && staged_size != stage->expected_bytes)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = authority_revalidate (stage);
  if (rc == WYRELOG_E_OK) {
    stage_identity (&stage->native_stage, out_identity);
    *out_bytes_written = stage->bytes_written;
    /* Finalization retains the operation-named orphan on disk. Close only the
     * held descriptor; the generic clear primitive never unlinks it. */
    wyl_fact_graph_stage_clear (&stage->native_stage);
    stage->finalized = TRUE;
    stage->failed = FALSE;
  }
  return rc;
}

void
wyl_fact_offline_restore_stage_free (WylFactOfflineRestoreStage *stage)
{
  if (stage == NULL)
    return;
  /* Closing is not cleanup: operation-named orphans are recovery-owned. */
  wyl_fact_graph_stage_clear (&stage->native_stage);
  g_checksum_free (stage->stream_checksum);
  g_free (stage);
}

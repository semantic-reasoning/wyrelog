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

#endif /* !G_OS_WIN32 */

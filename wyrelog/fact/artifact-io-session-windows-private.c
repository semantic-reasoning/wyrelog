/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifdef G_OS_WIN32

#include "fact/artifact-io-session-private.h"
#include "fact/graph-artifact-windows-handle-private.h"
#include "fact/graph-artifact-windows-namespace-private.h"
#include <stdio.h>
#include <string.h>

struct WylFactArtifactIoSession
{
  WylFactArtifactIoSessionKind kind;
  WylFactArtifactWinIoSession *win_session;
  WylFactArtifactWinSidecarBinding *sidecar_binding;
};

wyrelog_error_t
wyl_fact_artifact_io_session_open_writer_main (
  WylFactArtifactWinLease *lease,
  WylFactArtifactIoSession **out_session)
{
  WylFactArtifactWinMainBinding *binding = NULL;
  WylFactArtifactWinIoSession *win_session = NULL;
  wyrelog_error_t rc;

  if (out_session != NULL)
    *out_session = NULL;
  if (lease == NULL || out_session == NULL)
    return WYRELOG_E_INVALID;

  rc = wyl_fact_artifact_win_lease_open_main (lease, &binding);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = wyl_fact_artifact_win_main_binding_open_io_session (binding, &win_session);
  wyl_fact_artifact_win_main_binding_free (binding);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylFactArtifactIoSession *session = g_try_new0 (WylFactArtifactIoSession, 1);
  if (session == NULL) {
    wyl_fact_artifact_win_io_session_abort (win_session);
    return WYRELOG_E_NOMEM;
  }
  session->kind = WYL_FACT_ARTIFACT_IO_SESSION_WRITER_MAIN;
  session->win_session = win_session;
  *out_session = session;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_io_session_open_reader_main (
  WylFactArtifactWinLease *lease,
  WylFactArtifactIoSession **out_session)
{
  WylFactArtifactWinMainBinding *binding = NULL;
  WylFactArtifactWinIoSession *win_session = NULL;
  wyrelog_error_t rc;

  if (out_session != NULL)
    *out_session = NULL;
  if (lease == NULL || out_session == NULL)
    return WYRELOG_E_INVALID;

  rc = wyl_fact_artifact_win_reader_lease_open_main (lease, &binding);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = wyl_fact_artifact_win_main_binding_open_io_session (binding, &win_session);
  wyl_fact_artifact_win_main_binding_free (binding);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylFactArtifactIoSession *session = g_try_new0 (WylFactArtifactIoSession, 1);
  if (session == NULL) {
    wyl_fact_artifact_win_io_session_abort (win_session);
    return WYRELOG_E_NOMEM;
  }
  session->kind = WYL_FACT_ARTIFACT_IO_SESSION_READER_MAIN;
  session->win_session = win_session;
  *out_session = session;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_io_session_open_sidecar (
  WylFactArtifactWinLease *lease,
  WylFactArtifactName artifact,
  gboolean create_if_missing,
  gboolean writable,
  WylFactArtifactIoSession **out_session)
{
  WylFactArtifactWinSidecarBinding *binding = NULL;
  WylFactArtifactWinIoSession *win_session = NULL;
  wyrelog_error_t rc;

  if (out_session != NULL)
    *out_session = NULL;
  if (lease == NULL || out_session == NULL)
    return WYRELOG_E_INVALID;

  rc = wyl_fact_artifact_win_lease_open_sidecar (lease, artifact, create_if_missing, writable, &binding);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = wyl_fact_artifact_win_sidecar_binding_open_io_session (binding, &win_session);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_artifact_win_sidecar_binding_free (binding);
    return rc;
  }

  WylFactArtifactIoSession *session = g_try_new0 (WylFactArtifactIoSession, 1);
  if (session == NULL) {
    wyl_fact_artifact_win_io_session_abort (win_session);
    wyl_fact_artifact_win_sidecar_binding_free (binding);
    return WYRELOG_E_NOMEM;
  }
  session->kind = WYL_FACT_ARTIFACT_IO_SESSION_WRITER_SIDECAR;
  session->win_session = win_session;
  session->sidecar_binding = binding;
  *out_session = session;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_io_session_open_reader_wal (
  WylFactArtifactWinLease *lease,
  WylFactArtifactIoSession **out_session)
{
  WylFactArtifactWinSidecarBinding *binding = NULL;
  WylFactArtifactWinIoSession *win_session = NULL;
  wyrelog_error_t rc;

  if (out_session != NULL)
    *out_session = NULL;
  if (lease == NULL || out_session == NULL)
    return WYRELOG_E_INVALID;

  rc = wyl_fact_artifact_win_reader_lease_open_sidecar (lease, WYL_FACT_ARTIFACT_WAL, &binding);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = wyl_fact_artifact_win_sidecar_binding_open_io_session (binding, &win_session);
  wyl_fact_artifact_win_sidecar_binding_free (binding);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylFactArtifactIoSession *session = g_try_new0 (WylFactArtifactIoSession, 1);
  if (session == NULL) {
    wyl_fact_artifact_win_io_session_abort (win_session);
    return WYRELOG_E_NOMEM;
  }
  session->kind = WYL_FACT_ARTIFACT_IO_SESSION_READER_WAL;
  session->win_session = win_session;
  *out_session = session;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_io_session_create_temp_root (
  WylFactArtifactWinLease *lease,
  WylFactArtifactWinTempRoot **out_root)
{
  return wyl_fact_artifact_win_lease_create_temp_root (lease, out_root);
}

wyrelog_error_t
wyl_fact_artifact_io_session_create_temp_child (
  WylFactArtifactWinTempRoot *root,
  const gchar *name,
  gboolean writable,
  WylFactArtifactWinTempChild **out_child,
  WylFactArtifactIoSession **out_session,
  WylFactArtifactWinTempOrphanEvidence **out_evidence)
{
  WylFactArtifactWinTempChildBinding *binding = NULL;
  WylFactArtifactWinIoSession *win_session = NULL;
  wyrelog_error_t rc;

  if (out_child != NULL)
    *out_child = NULL;
  if (out_session != NULL)
    *out_session = NULL;
  if (out_evidence != NULL)
    *out_evidence = NULL;

  if (root == NULL || name == NULL || out_session == NULL)
    return WYRELOG_E_INVALID;

  rc = wyl_fact_artifact_win_temp_root_create_child_with_orphan_evidence (root, name, writable, &binding, out_evidence);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = wyl_fact_artifact_win_temp_child_binding_open_io_session (binding, &win_session);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_artifact_win_temp_child_binding_free (binding);
    return rc;
  }

  WylFactArtifactIoSession *session = g_try_new0 (WylFactArtifactIoSession, 1);
  if (session == NULL) {
    wyl_fact_artifact_win_io_session_abort (win_session);
    wyl_fact_artifact_win_temp_child_binding_free (binding);
    return WYRELOG_E_NOMEM;
  }
  session->kind = WYL_FACT_ARTIFACT_IO_SESSION_TEMP_CHILD;
  session->win_session = win_session;
  *out_session = session;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_io_session_open_existing_temp_child (
  WylFactArtifactWinTempChild *child,
  gboolean writable,
  WylFactArtifactIoSession **out_session)
{
  WylFactArtifactWinTempChildBinding *binding = NULL;
  WylFactArtifactWinIoSession *win_session = NULL;
  wyrelog_error_t rc;

  if (out_session != NULL)
    *out_session = NULL;
  if (child == NULL || out_session == NULL)
    return WYRELOG_E_INVALID;

  rc = wyl_fact_artifact_win_temp_child_open (child, writable, &binding);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = wyl_fact_artifact_win_temp_child_binding_open_io_session (binding, &win_session);
  wyl_fact_artifact_win_temp_child_binding_free (binding);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylFactArtifactIoSession *session = g_try_new0 (WylFactArtifactIoSession, 1);
  if (session == NULL) {
    wyl_fact_artifact_win_io_session_abort (win_session);
    return WYRELOG_E_NOMEM;
  }
  session->kind = WYL_FACT_ARTIFACT_IO_SESSION_TEMP_CHILD;
  session->win_session = win_session;
  *out_session = session;
  return WYRELOG_E_OK;
}

WylFactArtifactIoSessionKind
wyl_fact_artifact_io_session_get_kind (const WylFactArtifactIoSession *session)
{
  return session != NULL ? session->kind : WYL_FACT_ARTIFACT_IO_SESSION_WRITER_MAIN;
}

wyrelog_error_t
wyl_fact_artifact_io_session_read (WylFactArtifactIoSession *session,
    guint64 offset, void *buf, gsize count, gsize *out_bytes_read)
{
  if (session == NULL || session->win_session == NULL)
    return WYRELOG_E_INVALID;
  return wyl_fact_artifact_win_io_session_read (session->win_session, offset, buf, count, out_bytes_read);
}

wyrelog_error_t
wyl_fact_artifact_io_session_write (WylFactArtifactIoSession *session,
    guint64 offset, const void *buf, gsize count, gsize *out_bytes_written)
{
  if (session == NULL || session->win_session == NULL)
    return WYRELOG_E_INVALID;
  return wyl_fact_artifact_win_io_session_write (session->win_session, offset, buf, count, out_bytes_written);
}

wyrelog_error_t
wyl_fact_artifact_io_session_flush (WylFactArtifactIoSession *session)
{
  if (session == NULL || session->win_session == NULL)
    return WYRELOG_E_INVALID;
  return wyl_fact_artifact_win_io_session_flush (session->win_session);
}

wyrelog_error_t
wyl_fact_artifact_io_session_truncate (WylFactArtifactIoSession *session,
    guint64 size)
{
  if (session == NULL || session->win_session == NULL)
    return WYRELOG_E_INVALID;
  return wyl_fact_artifact_win_io_session_truncate (session->win_session, size);
}

wyrelog_error_t
wyl_fact_artifact_io_session_size (WylFactArtifactIoSession *session,
    guint64 *out_size)
{
  if (session == NULL || session->win_session == NULL)
    return WYRELOG_E_INVALID;
  return wyl_fact_artifact_win_io_session_size (session->win_session, out_size);
}

wyrelog_error_t
wyl_fact_artifact_io_session_last_modified (WylFactArtifactIoSession *session,
    guint64 *out_sec, guint32 *out_nsec)
{
  guint64 size = 0;
  WylFactGraphWinIdentity identity = { 0 };
  if (session == NULL || session->win_session == NULL)
    return WYRELOG_E_INVALID;
  return wyl_fact_artifact_win_io_session_query_metadata (session->win_session,
             &size, out_sec, out_nsec, &identity);
}

wyrelog_error_t
wyl_fact_artifact_io_session_revalidate (WylFactArtifactIoSession *session)
{
  if (session == NULL || session->win_session == NULL)
    return WYRELOG_E_INVALID;
  return wyl_fact_artifact_win_io_session_revalidate (session->win_session);
}

wyrelog_error_t
wyl_fact_artifact_io_session_finish (WylFactArtifactIoSession *session)
{
  if (session == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = WYRELOG_E_OK;
  if (session->win_session != NULL) {
    rc = wyl_fact_artifact_win_io_session_finish (session->win_session);
    session->win_session = NULL;
  }
  if (session->sidecar_binding != NULL) {
    wyl_fact_artifact_win_sidecar_binding_free (session->sidecar_binding);
    session->sidecar_binding = NULL;
  }
  g_free (session);
  return rc;
}

void
wyl_fact_artifact_io_session_free (WylFactArtifactIoSession *session)
{
  if (session == NULL)
    return;
  if (session->win_session != NULL) {
    wyl_fact_artifact_win_io_session_abort (session->win_session);
    session->win_session = NULL;
  }
  if (session->sidecar_binding != NULL) {
    wyl_fact_artifact_win_sidecar_binding_free (session->sidecar_binding);
    session->sidecar_binding = NULL;
  }
  g_free (session);
}

void
wyl_fact_artifact_io_session_abort (WylFactArtifactIoSession *session)
{
  wyl_fact_artifact_io_session_free (session);
}

wyrelog_error_t
wyl_fact_artifact_io_session_version_tag (WylFactArtifactIoSession *session,
    gchar **out_tag)
{
  guint64 size = 0, sec = 0;
  guint32 nsec = 0;
  WylFactGraphWinIdentity identity = { 0 };
  wyrelog_error_t rc;

  if (out_tag != NULL)
    *out_tag = NULL;
  if (session == NULL || session->win_session == NULL || out_tag == NULL)
    return WYRELOG_E_INVALID;

  rc = wyl_fact_artifact_win_io_session_query_metadata (session->win_session,
          &size, &sec, &nsec, &identity);
  if (rc != WYRELOG_E_OK)
    return rc;

  gchar file_id_hex[33] = { 0 };
  for (gsize i = 0; i < sizeof (identity.file_id); i++)
    snprintf (file_id_hex + i * 2, 3, "%02x", (unsigned int) identity.file_id[i]);

  *out_tag = g_strdup_printf ("win:%08X:%s%" G_GUINT64_FORMAT,
          (unsigned int) identity.volume_serial, file_id_hex, size);
  return *out_tag != NULL ? WYRELOG_E_OK : WYRELOG_E_NOMEM;
}

wyrelog_error_t
wyl_fact_artifact_namespace_open_file (WylFactArtifactNamespace *ns,
    WylFactArtifactName name, gboolean create, gboolean writable, gint *out_fd)
{
  (void) ns;
  (void) name;
  (void) create;
  (void) writable;
  if (out_fd != NULL)
    *out_fd = -1;
  return WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_fact_artifact_namespace_revalidate (WylFactArtifactNamespace *ns)
{
  return wyl_fact_artifact_win_namespace_revalidate (ns);
}

void
wyl_fact_artifact_namespace_free (WylFactArtifactNamespace *ns)
{
  wyl_fact_artifact_win_namespace_free (ns);
}

wyrelog_error_t
wyl_fact_artifact_namespace_acquire_mutation_lease (WylFactArtifactNamespace *ns,
    WylFactArtifactMutationLease **out_lease)
{
  return wyl_fact_artifact_win_namespace_acquire_mutation (ns, out_lease);
}

wyrelog_error_t
wyl_fact_artifact_namespace_acquire_reader_guard (WylFactArtifactNamespace *ns,
    WylFactArtifactMutationLease **out_lease)
{
  return wyl_fact_artifact_win_namespace_acquire_reader (ns, out_lease);
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_revalidate (WylFactArtifactMutationLease *lease)
{
  return wyl_fact_artifact_win_lease_revalidate (lease);
}

void
wyl_fact_artifact_mutation_lease_free (WylFactArtifactMutationLease *lease)
{
  wyl_fact_artifact_win_lease_free (lease);
}

wyrelog_error_t
wyl_fact_duckdb_temp_root_create_with_orphan_evidence (
  WylFactArtifactMutationLease *lease, WylFactDuckdbTempRoot **out_root,
  WylFactDuckdbTempOrphanEvidence **out_evidence)
{
  return wyl_fact_artifact_win_temp_root_create_with_orphan_evidence (lease,
             out_root, out_evidence);
}

void
wyl_fact_duckdb_temp_orphan_evidence_free (WylFactDuckdbTempOrphanEvidence *ev)
{
  wyl_fact_artifact_win_temp_orphan_evidence_free (ev);
}

gchar *
wyl_fact_duckdb_temp_root_dup_logical_name (WylFactDuckdbTempRoot *root)
{
  return wyl_fact_artifact_win_temp_root_dup_logical_name (root);
}

void
wyl_fact_duckdb_temp_root_free (WylFactDuckdbTempRoot *root)
{
  wyl_fact_artifact_win_temp_root_free (root);
}

void
wyl_fact_duckdb_temp_child_free (WylFactDuckdbTempChild *child)
{
  wyl_fact_artifact_win_temp_child_free (child);
}

wyrelog_error_t
wyl_fact_duckdb_temp_root_child_exists (WylFactDuckdbTempRoot *root,
    const gchar *name, gboolean *out_exists)
{
  return wyl_fact_artifact_win_temp_root_child_exists (root, name, out_exists);
}

void
wyl_fact_artifact_sidecar_binding_free (WylFactArtifactSidecarBinding *binding)
{
  wyl_fact_artifact_win_sidecar_binding_free (binding);
}

#endif

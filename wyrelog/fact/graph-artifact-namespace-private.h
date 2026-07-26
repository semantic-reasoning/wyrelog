/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include "wyrelog/error.h"
#include "fact/graph-locator-private.h"

G_BEGIN_DECLS typedef struct WylFactArtifactNamespace WylFactArtifactNamespace;
typedef struct WylFactArtifactMutationLease WylFactArtifactMutationLease;

/* Only these names are part of the authority.  Callers cannot supply a path. */
typedef enum
{
  WYL_FACT_ARTIFACT_MAIN,
  WYL_FACT_ARTIFACT_WAL,
  WYL_FACT_ARTIFACT_CHECKPOINT,
  WYL_FACT_ARTIFACT_RECOVERY,
  WYL_FACT_ARTIFACT_LOCK,
  WYL_FACT_ARTIFACT_TEMP,
} WylFactArtifactName;

typedef enum
{
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_NONE = 0,
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_INITIAL_LOCK_DIRECTORY_FSYNC,
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_INITIAL_LOCK_POST_FSYNC_IDENTITY,
} WylFactArtifactNamespaceTestFault;

/* Private, process-local, one-shot fault injection for namespace tests. */
void wyl_fact_artifact_namespace_set_test_fault
    (WylFactArtifactNamespaceTestFault fault);

wyrelog_error_t wyl_fact_artifact_namespace_open
    (const WylFactGraphDirectory * directory,
    WylFactArtifactNamespace ** out_namespace);
void wyl_fact_artifact_namespace_free (WylFactArtifactNamespace * namespace_);
wyrelog_error_t wyl_fact_artifact_namespace_revalidate
    (WylFactArtifactNamespace * namespace_);
/* Cooperative 0700 graph-directory contract: only an exclusive opaque lease
 * authorizes sanctioned pathname mutation.  It pins both the held directory
 * and facts.duckdb.lock identities.  POSIX cannot make unlink/rename exact
 * against an uncooperative same-UID writer that bypasses this lease.
 *
 * A lease retains the namespace and owns its kernel flock; freeing it releases
 * both.  Operations on one live lease are serialized.  Every fd opened
 * through a lease is valid only while that lease lives,
 * and callers must close such fds and stop/join all lease operations before
 * freeing it.  Process death releases flock while a validated regular lock
 * entry remains reusable.  Fork with a live lease is unsupported: a child
 * must neither use nor rely on an inherited lease.  Fork after multithreading
 * is not a supported synchronization guarantee. */
wyrelog_error_t wyl_fact_artifact_namespace_acquire_reader_guard
    (WylFactArtifactNamespace *, WylFactArtifactMutationLease **);
wyrelog_error_t wyl_fact_artifact_namespace_acquire_mutation_lease
    (WylFactArtifactNamespace *, WylFactArtifactMutationLease **);
wyrelog_error_t wyl_fact_artifact_mutation_lease_revalidate
    (WylFactArtifactMutationLease *);
void wyl_fact_artifact_mutation_lease_free (WylFactArtifactMutationLease *);
wyrelog_error_t wyl_fact_artifact_mutation_lease_open_file
    (WylFactArtifactMutationLease *, WylFactArtifactName name,
    gboolean create, gboolean writable, gint * out_fd);
wyrelog_error_t wyl_fact_artifact_mutation_lease_open_temp
    (WylFactArtifactMutationLease *, const gchar * token,
    gboolean create, gboolean writable, gint * out_fd);
wyrelog_error_t wyl_fact_artifact_mutation_lease_unlink
    (WylFactArtifactMutationLease *, WylFactArtifactName name);
wyrelog_error_t wyl_fact_artifact_mutation_lease_rename
    (WylFactArtifactMutationLease *, WylFactArtifactName source,
    WylFactArtifactName destination);
wyrelog_error_t wyl_fact_artifact_namespace_open_file
    (WylFactArtifactNamespace * namespace_, WylFactArtifactName name,
    gboolean create, gboolean writable, gint * out_fd);
/* Deprecated mutation entry points are retained only to fail closed with
 * WYRELOG_E_POLICY; use the exclusive mutation-lease variants above. */
wyrelog_error_t wyl_fact_artifact_namespace_unlink
    (WylFactArtifactNamespace * namespace_, WylFactArtifactName name);
wyrelog_error_t wyl_fact_artifact_namespace_sync
    (WylFactArtifactNamespace * namespace_, WylFactArtifactName name);
/* Retained for source compatibility only; it always fails closed.  Raw flock
 * descriptors cannot carry the namespace lifetime/identity invariants. */
wyrelog_error_t wyl_fact_artifact_namespace_lock
    (WylFactArtifactNamespace * namespace_, gboolean exclusive, gint * out_fd);
wyrelog_error_t wyl_fact_artifact_namespace_bind_main
    (WylFactArtifactNamespace * namespace_);
wyrelog_error_t wyl_fact_artifact_namespace_revalidate_main
    (WylFactArtifactNamespace * namespace_);
wyrelog_error_t wyl_fact_artifact_namespace_open_temp
    (WylFactArtifactNamespace * namespace_, const gchar * token,
    gboolean create, gboolean writable, gint * out_fd);
wyrelog_error_t wyl_fact_artifact_namespace_rename
    (WylFactArtifactNamespace * namespace_, WylFactArtifactName source,
    WylFactArtifactName destination);
wyrelog_error_t wyl_fact_artifact_namespace_sync_directory
    (WylFactArtifactNamespace * namespace_);

G_END_DECLS

/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include "wyrelog/error.h"
#include "fact/graph-locator-private.h"

G_BEGIN_DECLS typedef struct WylFactArtifactNamespace WylFactArtifactNamespace;
typedef struct WylFactArtifactMutationLease WylFactArtifactMutationLease;
typedef struct WylFactArtifactTempBinding WylFactArtifactTempBinding;
typedef struct WylFactArtifactSidecarBinding WylFactArtifactSidecarBinding;
typedef struct WylFactArtifactTempRecoveryEvidence
    WylFactArtifactTempRecoveryEvidence;

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
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_TEMP_UNLINK_DIRECTORY_FSYNC,
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_TEMP_RENAME_DIRECTORY_FSYNC,
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_TEMP_REPLACE_DIRECTORY_FSYNC,
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_TEMP_RECOVER_DIRECTORY_FSYNC,
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_PUBLISH_PRE_RENAME_INSERT,
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_TEMP_REPLACE_PRE_RENAME_SUBSTITUTE,
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_TEMP_REPLACE_POST_RENAME_SUBSTITUTE,
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
/* Cooperative graph-directory contract: the held directory remains owned by
 * the effective UID with exact mode 0700, while facts.duckdb.lock remains a
 * same-owner regular file with exact mode 0600 and nlink 1.  Only an exclusive
 * opaque lease authorizes sanctioned pathname mutation.  It pins both the held
 * directory and lock identities.  POSIX cannot make unlink/rename exact
 * against an uncooperative same-UID writer that bypasses this lease.
 *
 * A lease retains the namespace and owns its kernel flock; freeing it releases
 * both.  Operations on one live lease are serialized.  Every fd opened
 * through a lease is valid only while that lease lives,
 * and callers must close such fds and stop/join all lease operations before
 * freeing it.  Normal process exit releases flock after every inherited copy
 * of its open file description closes; the validated regular entry remains
 * reusable.  Fork with a live lease is unsupported: the child must immediately
 * exec (the fd is CLOEXEC) or _exit without using the lease, or its inherited
 * fd will prolong the lock.  Fork after multithreading is not a supported
 * synchronization guarantee. */
wyrelog_error_t wyl_fact_artifact_namespace_acquire_reader_guard
    (WylFactArtifactNamespace *, WylFactArtifactMutationLease **);
wyrelog_error_t wyl_fact_artifact_namespace_acquire_mutation_lease
    (WylFactArtifactNamespace *, WylFactArtifactMutationLease **);
wyrelog_error_t wyl_fact_artifact_mutation_lease_revalidate
    (WylFactArtifactMutationLease *);
void wyl_fact_artifact_mutation_lease_free (WylFactArtifactMutationLease *);
/* Generic fixed-sidecar mutation is retired: WAL/checkpoint/recovery creation
 * and writable opens require SidecarBinding. */
wyrelog_error_t wyl_fact_artifact_mutation_lease_open_file
    (WylFactArtifactMutationLease *, WylFactArtifactName name,
    gboolean create, gboolean writable, gint * out_fd);
wyrelog_error_t wyl_fact_artifact_mutation_lease_open_temp
    (WylFactArtifactMutationLease *, const gchar * token,
    gboolean create, gboolean writable, gint * out_fd);
/* Binds a fixed DuckDB sidecar to an exclusive #612 mutation lease.  Only WAL,
 * checkpoint, and recovery sidecars are accepted; main and lock are never
 * replaceable.  This authority serializes cooperative writers; portable POSIX
 * cannot compare-and-swap a same-UID writer that bypasses the held lease.
 * The binding owns a lease reference and the caller owns both it and out_fd. */
wyrelog_error_t wyl_fact_artifact_mutation_lease_open_sidecar_binding
    (WylFactArtifactMutationLease *, WylFactArtifactName sidecar,
    gboolean create, gboolean writable,
    WylFactArtifactSidecarBinding ** out_binding, gint * out_fd);
/* Publishes the exact bound sidecar under a distinct absent fixed sidecar
 * name, using a platform no-replace primitive.  After the rename linearizes,
 * the binding identifies destination even if durability reporting fails. */
wyrelog_error_t wyl_fact_artifact_sidecar_binding_publish_no_replace
    (WylFactArtifactSidecarBinding *, WylFactArtifactName destination);
void wyl_fact_artifact_sidecar_binding_free (WylFactArtifactSidecarBinding *);
/* Atomically replaces the exact bound fixed sidecar with the exact owner
 * temporary artifact.  Both bindings must retain the same exclusive lease;
 * after rename linearizes, source becomes terminal and destination identifies
 * the replacement even when directory durability reporting fails. */
wyrelog_error_t wyl_fact_artifact_temp_binding_replace_sidecar
    (WylFactArtifactTempBinding *, WylFactArtifactSidecarBinding *);
/* Binds tmp-<token> to the exact regular file opened through an existing
 * lease.  The binding retains the lease until _free, so its directory/lock
 * authority cannot disappear while later lifecycle operations use it.  The
 * caller owns both the binding and out_fd. */
wyrelog_error_t wyl_fact_artifact_mutation_lease_open_temp_binding
    (WylFactArtifactMutationLease *, const gchar * token,
    gboolean create, gboolean writable,
    WylFactArtifactTempBinding ** out_binding, gint * out_fd);
/* Reopens only the file identity captured by an owner binding.  A
 * non-creator binding grants only the fd returned at construction time: it
 * cannot reopen, mutate, rename, unlink, or export recovery evidence. */
wyrelog_error_t wyl_fact_artifact_temp_binding_open
    (WylFactArtifactTempBinding *, gboolean writable, gint * out_fd);
/* An owner binding consumes its exact temporary artifact.  A successful
 * unlink makes the binding terminal even when the subsequent durability or
 * post-mutation check reports an error. */
wyrelog_error_t wyl_fact_artifact_temp_binding_unlink
    (WylFactArtifactTempBinding *);
/* Renames an owner binding only within its held namespace.  The destination
 * must be a distinct valid temporary token and must not exist.  After a
 * successful rename the binding names the destination even if durability or
 * post-mutation validation reports an error. */
wyrelog_error_t wyl_fact_artifact_temp_binding_rename
    (WylFactArtifactTempBinding *, const gchar * destination_token);
void wyl_fact_artifact_temp_binding_free (WylFactArtifactTempBinding *);
/* Recovery evidence is an immutable, serializable identity record issued from
 * a live owner binding.  It is not a pathname authority: recovery accepts it
 * only with a matching exclusive lease and matching on-disk identity. */
wyrelog_error_t wyl_fact_artifact_temp_binding_export_recovery_evidence
    (WylFactArtifactTempBinding *, WylFactArtifactTempRecoveryEvidence **);
void wyl_fact_artifact_temp_recovery_evidence_free
    (WylFactArtifactTempRecoveryEvidence *);
wyrelog_error_t wyl_fact_artifact_temp_recovery_evidence_encode
    (const WylFactArtifactTempRecoveryEvidence *, GBytes ** out_bytes);
wyrelog_error_t wyl_fact_artifact_temp_recovery_evidence_decode
    (GBytes *, WylFactArtifactTempRecoveryEvidence **);
/* Missing artifacts are idempotently recovered.  Existing artifacts must
 * match every evidence identity field before dirfd-relative unlink. */
wyrelog_error_t wyl_fact_artifact_mutation_lease_recover_temp
    (WylFactArtifactMutationLease *,
    const WylFactArtifactTempRecoveryEvidence *);
/* Retired generic pathname mutators; valid fixed artifact names fail closed.
 * TempBinding and SidecarBinding carry the only mutation authority. */
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

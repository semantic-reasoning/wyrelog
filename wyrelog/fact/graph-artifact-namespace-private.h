/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include "wyrelog/error.h"
#include "fact/graph-locator-private.h"

G_BEGIN_DECLS typedef struct WylFactArtifactNamespace WylFactArtifactNamespace;
typedef struct WylFactArtifactMutationLease WylFactArtifactMutationLease;
typedef struct WylFactArtifactTempBinding WylFactArtifactTempBinding;
typedef struct WylFactArtifactSidecarBinding WylFactArtifactSidecarBinding;
typedef struct WylFactArtifactMainBinding WylFactArtifactMainBinding;
typedef struct WylFactArtifactTempRecoveryEvidence
    WylFactArtifactTempRecoveryEvidence;
typedef struct WylFactDuckdbTempRoot WylFactDuckdbTempRoot;
typedef struct WylFactDuckdbTempChild WylFactDuckdbTempChild;
typedef struct WylFactDuckdbTempOrphanEvidence WylFactDuckdbTempOrphanEvidence;
typedef gboolean (*WylFactDuckdbTempChildVisitor) (WylFactDuckdbTempChild *,
    const gchar * logical_name, gpointer user_data);

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

/* The retirement result is deliberately separate from the error return.
 * RETIRED is the only successful terminal outcome.  RECONCILE_REQUIRED means
 * unlink may have linearized, or an active binding observed external removal;
 * the binding is terminal and must not be retried.  On every error before
 * either condition, the output is NOT_RETIRED. */
typedef enum
{
  WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED = 0,
  WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RETIRED,
  WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RECONCILE_REQUIRED,
} WylFactArtifactSidecarRetireResult;

/* The DuckDB spill directory is a separate, opaque authority.  It is not a
 * general directory capability: its root is minted internally, child names
 * are accepted only when they match the source-pinned DuckDB 1.5.5 grammar,
 * and child lifecycle always uses an identity binding. */
typedef enum
{
  WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED = 0,
  WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED,
  WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RECONCILE_REQUIRED,
} WylFactDuckdbTempRetireResult;

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
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_MAIN_OPEN_ABA,
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_MAIN_BINDING_POST_OPEN_SUBSTITUTE,
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_RETIRE_DIRECTORY_FSYNC,
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_RETIRE_POST_UNLINK_POLICY,
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_RETIRE_PRE_UNLINK_SUBSTITUTE,
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_RETIRE_POST_UNLINK_SUBSTITUTE,
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_DUCKDB_TEMP_ROOT_POST_MKDIR,
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_DUCKDB_TEMP_CHILD_POST_CREATE,
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_DUCKDB_TEMP_ROOT_POST_OPEN_IDENTITY,
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_DUCKDB_TEMP_CHILD_POST_OPEN_IDENTITY,
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_DUCKDB_TEMP_ROOT_PRE_IDENTITY,
  WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_DUCKDB_TEMP_CHILD_PRE_IDENTITY,
} WylFactArtifactNamespaceTestFault;

/* Private, process-local, one-shot fault injection for namespace tests. */
void wyl_fact_artifact_namespace_set_test_fault
    (WylFactArtifactNamespaceTestFault fault);

/* Imports a CLOEXEC duplicate of the caller-held canonical facts.duckdb
 * identity.  The caller retains ownership of main_file; construction checks
 * the held fd, declared identity, and dirfd-relative fixed name before and
 * after publishing the namespace. */
wyrelog_error_t wyl_fact_artifact_namespace_open
    (const WylFactGraphDirectory * directory,
    const WylFactGraphRegularFile * main_file,
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
/* Binds the already-imported canonical facts.duckdb for in-place DuckDB I/O.
 * This is deliberately not a pathname capability: it requires an exclusive
 * lease, opens only the existing fixed name with O_RDWR/CLOEXEC/NOFOLLOW, and
 * grants neither creation nor namespace mutation.  The binding retains the
 * lease and a separate identity pin.  #596 must call _revalidate_fd with its
 * actual working descriptor immediately before and after every raw I/O, sync,
 * and truncate boundary; plain _revalidate checks only held authority and is
 * not an I/O-boundary substitute.  _close validates then consumes the working
 * descriptor on success.  A failed validation terminally revokes this
 * binding, but never closes a possibly reused foreign descriptor.  As with #612, an
 * uncooperative same-UID writer can still race the final check and syscall. */
wyrelog_error_t wyl_fact_artifact_mutation_lease_open_main_binding
    (WylFactArtifactMutationLease *, WylFactArtifactMainBinding ** out_binding,
    gint * out_fd);
wyrelog_error_t wyl_fact_artifact_main_binding_revalidate
    (WylFactArtifactMainBinding *);
wyrelog_error_t wyl_fact_artifact_main_binding_revalidate_fd
    (WylFactArtifactMainBinding *, gint working_fd);
/* On success, closes and sets *working_fd to -1, then terminally consumes the
 * binding.  On validation failure it leaves *working_fd untouched because its
 * number could already refer to a foreign descriptor. */
wyrelog_error_t wyl_fact_artifact_main_binding_close
    (WylFactArtifactMainBinding *, gint * working_fd);
void wyl_fact_artifact_main_binding_free (WylFactArtifactMainBinding *);
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
/* Reopens an already-existing fixed sidecar for DuckDB recovery.  This is a
 * deliberately separate authority from strict creation: it accepts only an
 * exclusive lease and a writable request, never creates or publishes a name,
 * and pins the exact existing regular 0600 same-owner single-link entry.
 * Missing sidecars return NOT_FOUND with initialized outputs.  #596 must call
 * SidecarBinding _revalidate_fd immediately before and after every raw
 * returned FD I/O, sync, truncate, and close boundary; a failed FD check
 * terminally revokes the binding and the FD must not be used again.  Plain
 * _revalidate is lifecycle validation only: it neither authorizes raw I/O
 * nor consumes a valid lifecycle binding.  As with the existing #612
 * mutation contract, this does not claim to close POSIX's final-check to
 * syscall window against an uncooperative same-UID participant. */
wyrelog_error_t wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding
    (WylFactArtifactMutationLease *, WylFactArtifactName sidecar,
    gboolean writable, WylFactArtifactSidecarBinding ** out_binding,
    gint * out_fd);
/* Call at both sides of a DuckDB I/O boundary.  It rechecks the exclusive
 * lease plus imported main, graph directory, lock, named sidecar, and pinned
 * descriptor identities without granting any additional pathname authority. */
wyrelog_error_t wyl_fact_artifact_sidecar_binding_revalidate
    (WylFactArtifactSidecarBinding *);
/* Revalidates both held sidecar authority and the caller's actual working
 * descriptor.  Descriptor-number reuse therefore fails closed rather than
 * validating only the sidecar pin. */
wyrelog_error_t wyl_fact_artifact_sidecar_binding_revalidate_fd
    (WylFactArtifactSidecarBinding *, gint working_fd);
/* On success, closes and sets *working_fd to -1, consuming only the issued
 * I/O descriptor while retaining lifecycle authority for retirement.  On
 * validation failure it revokes the whole binding but leaves *working_fd
 * untouched because its number could already refer to a foreign descriptor. */
wyrelog_error_t wyl_fact_artifact_sidecar_binding_close
    (WylFactArtifactSidecarBinding *, gint * working_fd);
/* Publishes the exact bound sidecar under a distinct absent fixed sidecar
 * name, using a platform no-replace primitive.  After the rename linearizes,
 * the binding identifies destination even if durability reporting fails. */
wyrelog_error_t wyl_fact_artifact_sidecar_binding_publish_no_replace
    (WylFactArtifactSidecarBinding *, WylFactArtifactName destination);
/* Retires only the exact currently-bound WAL/checkpoint/recovery artifact.
 * This API is intentionally the sole fixed-sidecar deletion authority.  Its
 * result output is initialized to NOT_RETIRED on every entry.  It requires
 * that the issued I/O descriptor was closed through _close; a live descriptor
 * is rejected, and raw close/reuse is detected and revokes without unlink.
 * Callers must
 * discard a binding after any terminal result, including
 * RECONCILE_REQUIRED.  The #612 exclusive lease serializes cooperating
 * writers, but POSIX cannot prevent a same-UID nonparticipant from swapping
 * the pathname after the final check; a mismatch observed before unlink is
 * rejected without unlinking, while any observed external removal is terminal
 * reconciliation rather than a successful cleanup claim. */
wyrelog_error_t wyl_fact_artifact_sidecar_binding_retire
    (WylFactArtifactSidecarBinding *, WylFactArtifactSidecarRetireResult *);
void wyl_fact_artifact_sidecar_binding_free (WylFactArtifactSidecarBinding *);
/* Atomically replaces the exact bound fixed sidecar with the exact owner
 * temporary artifact.  Both bindings must retain the same exclusive lease,
 * and the destination must have no live issued sidecar descriptor;
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
wyrelog_error_t wyl_fact_artifact_namespace_open_temp
    (WylFactArtifactNamespace * namespace_, const gchar * token,
    gboolean create, gboolean writable, gint * out_fd);
wyrelog_error_t wyl_fact_artifact_namespace_rename
    (WylFactArtifactNamespace * namespace_, WylFactArtifactName source,
    WylFactArtifactName destination);
wyrelog_error_t wyl_fact_artifact_namespace_sync_directory
    (WylFactArtifactNamespace * namespace_);

/* These APIs deliberately expose neither the physical root spelling nor a
 * directory descriptor.  A root cannot be reopened or adopted after its live
 * authority is released.  The exclusive lease, imported main binding, graph
 * directory, and lock are revalidated around every mutation. */
wyrelog_error_t wyl_fact_duckdb_temp_root_create
    (WylFactArtifactMutationLease *, WylFactDuckdbTempRoot **);
/* On a post-mkdir failure before file identity is observable, returns POLICY
 * and required orphan evidence.  Evidence is terminal telemetry only: there
 * is intentionally no reopen/adopt/delete API for it. */
wyrelog_error_t wyl_fact_duckdb_temp_root_create_with_orphan_evidence
    (WylFactArtifactMutationLease *, WylFactDuckdbTempRoot **,
    WylFactDuckdbTempOrphanEvidence **);
void wyl_fact_duckdb_temp_orphan_evidence_free
    (WylFactDuckdbTempOrphanEvidence *);
gchar *wyl_fact_duckdb_temp_orphan_evidence_dup_logical_name
    (const WylFactDuckdbTempOrphanEvidence *);
/* A canonical virtual spelling identifies this live authority to #596.  It
 * is not a host path and cannot be converted into a dirfd/HANDLE. */
gchar *wyl_fact_duckdb_temp_root_dup_logical_name (WylFactDuckdbTempRoot *);
wyrelog_error_t wyl_fact_duckdb_temp_root_child_exists
    (WylFactDuckdbTempRoot *, const gchar * duckdb_name, gboolean * out_exists);
/* Calls visitor only for a complete, identity-verified snapshot.  The name is
 * DuckDB's logical child spelling, never a host path or reusable authority. */
wyrelog_error_t wyl_fact_duckdb_temp_root_foreach_child
    (WylFactDuckdbTempRoot *, WylFactDuckdbTempChildVisitor, gpointer);
gchar *wyl_fact_duckdb_temp_child_dup_logical_name (WylFactDuckdbTempChild *);
void wyl_fact_duckdb_temp_root_free (WylFactDuckdbTempRoot *);
wyrelog_error_t wyl_fact_duckdb_temp_root_create_child
    (WylFactDuckdbTempRoot *, const gchar * duckdb_name,
    WylFactDuckdbTempChild **, gint * out_fd);
/* The evidence output is required because a child may have been created but
 * not identity-bound when this returns POLICY. */
wyrelog_error_t wyl_fact_duckdb_temp_root_create_child_with_orphan_evidence
    (WylFactDuckdbTempRoot *, const gchar * duckdb_name,
    WylFactDuckdbTempChild **, gint * out_fd,
    WylFactDuckdbTempOrphanEvidence **);
wyrelog_error_t wyl_fact_duckdb_temp_child_open
    (WylFactDuckdbTempChild *, gboolean writable, gint * out_fd);
/* On success, returns owned WylFactDuckdbTempChild entries only.  Any
 * unbound/foreign entry makes enumeration fail with no partial array. */
wyrelog_error_t wyl_fact_duckdb_temp_root_list_children
    (WylFactDuckdbTempRoot *, GPtrArray ** out_children);
wyrelog_error_t wyl_fact_duckdb_temp_child_retire
    (WylFactDuckdbTempChild *, WylFactDuckdbTempRetireResult *);
void wyl_fact_duckdb_temp_child_free (WylFactDuckdbTempChild *);
wyrelog_error_t wyl_fact_duckdb_temp_root_retire
    (WylFactDuckdbTempRoot *, WylFactDuckdbTempRetireResult *);

G_END_DECLS

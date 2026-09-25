/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

/* The live-open handoff exposes duckdb C-API handles.  The amalgamated
 * duckdb.hpp bundles an unguarded copy of the C API, so a C++ translation unit
 * must take the types from duckdb.hpp (never both headers), while C consumers
 * use duckdb.h. */
#ifdef __cplusplus
#include <duckdb.hpp>
#else
#include <duckdb.h>
#endif
#include <glib.h>

#include "wyrelog/error.h"
#include "fact/graph-artifact-namespace-private.h"
#include "fact/offline-restore-stage-private.h"
#include "fact/store-identity-types-private.h"

G_BEGIN_DECLS;

typedef struct WylSecureDuckdbBridge WylSecureDuckdbBridge;
typedef enum
{ WYL_SECURE_DUCKDB_INIT_EMPTY = 0,
  WYL_SECURE_DUCKDB_VALIDATE_ONLY = 1} WylSecureDuckdbMode;

/* This experimental lifecycle bridge owns a DuckDB instance and connection.
 * The namespace constructor injects the bounded filesystem without exposing
 * paths, descriptors, C API handles, or C++ implementation types.  Call
 * finalize when terminal cleanup success must be observed; free remains a
 * best-effort cleanup for C ownership conventions. */
wyrelog_error_t wyl_secure_duckdb_bridge_new (WylSecureDuckdbBridge ** out);
wyrelog_error_t
wyl_secure_duckdb_bridge_new_with_namespace (WylFactArtifactNamespace *,
    WylSecureDuckdbMode, WylSecureDuckdbBridge **);
wyrelog_error_t wyl_secure_duckdb_bridge_health (WylSecureDuckdbBridge * self);
wyrelog_error_t
wyl_secure_duckdb_bridge_finalize (WylSecureDuckdbBridge * self);
void wyl_secure_duckdb_bridge_free (WylSecureDuckdbBridge * self);

/* Live secure open of a provisioned pair.  Builds a bounded DuckDB instance and
 * hands back a live C-API database + connection routed through the secure
 * filesystem, while the returned bridge retains only the authority lease and
 * health (no DuckDB reference).  The returned handle owns the instance, so
 * closing it -- duckdb_disconnect then duckdb_close -- destructs the instance
 * and its shutdown checkpoint runs through the still-live bounded filesystem
 * under the still-held lease.  Call wyl_secure_duckdb_bridge_release_live AFTER
 * duckdb_close to observe health and release the lease.  This is the live
 * counterpart to the one-shot pinned identity open, not a replacement. */
wyrelog_error_t wyl_secure_duckdb_bridge_open_live_pair
  (WylFactArtifactNamespace * namespace_, gboolean writable,
    WylSecureDuckdbBridge ** out_bridge, duckdb_database * out_db,
    duckdb_connection * out_conn);
wyrelog_error_t wyl_secure_duckdb_bridge_open_live_with_lease
  (WylFactArtifactNamespace * namespace_,
    WylFactArtifactMutationLease * adopted_lease, gboolean writable,
    WylSecureDuckdbBridge ** out_bridge, duckdb_database * out_db,
    duckdb_connection * out_conn);
/* Observe health and release the authority lease of a live bridge, then free it.
 * Must be called only after the handle returned by open_live_pair has been
 * duckdb_close'd, so the shutdown checkpoint has already run under the lease. */
wyrelog_error_t
wyl_secure_duckdb_bridge_release_live (WylSecureDuckdbBridge * self);
WylFactArtifactMutationLease *
wyl_secure_duckdb_bridge_authority_lease (WylSecureDuckdbBridge * self);

/* One-shot, read-only validation of an operation-bound restore stage. The
 * caller retains the reader and its resolver/directory/lease for the entire
 * call. The function verifies size and checksum before and after opening
 * DuckDB, exposes no DuckDB handle or path, and only returns the result of
 * validating the persisted store identity. It does not update the journal or
 * validate schema digest/replay. Windows fails closed. */
wyrelog_error_t wyl_secure_duckdb_bridge_validate_restore_stage_identity
  (WylFactOfflineRestoreStageReader * reader, guint64 expected_bytes,
    const gchar * expected_checksum,
    const WylFactStoreIdentity * expected_identity,
    WylFactStoreIdentityResult * out_result);

typedef enum
{
  WYL_SECURE_DUCKDB_RESTORE_STAGE_TEST_AFTER_IDENTITY = 1,
  WYL_SECURE_DUCKDB_RESTORE_STAGE_TEST_AFTER_CLOSE,
  WYL_SECURE_DUCKDB_RESTORE_STAGE_TEST_BEFORE_FIRST_READ,
} WylSecureDuckdbRestoreStageTestPoint;
typedef void (*WylSecureDuckdbRestoreStageTestHook)
  (WylSecureDuckdbRestoreStageTestPoint point, gpointer user_data);
void wyl_secure_duckdb_bridge_set_restore_stage_test_hook_for_test
  (WylSecureDuckdbRestoreStageTestHook hook, gpointer user_data);

enum
{
  WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_CGROUP_HIDDEN = 1u << 0,
  WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_SECRET_PATHS_VIRTUAL = 1u << 1,
  WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_HOST_PATH_DISPATCHED = 1u << 2,
  WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_HOST_PATH_REJECTED = 1u << 3,
  WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_ALIAS_REJECTED = 1u << 4,
  WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_WRITE_REJECTED = 1u << 5,
  WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_APPEND_REJECTED = 1u << 6,
  WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_CREATE_REJECTED = 1u << 7,
  WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_DIRECT_IO_REJECTED = 1u << 8,
  WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_MUTATION_REJECTED = 1u << 9,
  WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_PARALLEL_READ_ALLOWED = 1u << 10,
  WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_CLOSED_HANDLE_REJECTED = 1u << 11,
};
wyrelog_error_t
wyl_secure_duckdb_bridge_test_restore_stage_filesystem_contract
  (WylFactOfflineRestoreStageReader * reader, guint64 * out_contract);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylSecureDuckdbBridge,
    wyl_secure_duckdb_bridge_free)
G_END_DECLS;

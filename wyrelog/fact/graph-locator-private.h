/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

#define WYL_FACT_GRAPH_PATH_VERSION 1u

typedef struct
{
  guint version;
  gchar *tenant_component;
  gchar *graph_component;
} WylFactGraphLocator;

#ifdef G_OS_WIN32
typedef struct
{
  guint64 volume_serial;
  guint8 file_id[16];
} WylFactGraphWinIdentity;

/* Private, versioned locator evidence for a Windows provisioning operation.
 * UUIDv7 selects the operation-derived stage component, but it is not file
 * provenance: callers persist this tuple before they may later reopen a
 * stage or adopt `facts.duckdb`.  It intentionally exposes neither a path
 * nor a HANDLE. */
#define WYL_FACT_GRAPH_WIN_OPERATION_EVIDENCE_VERSION 1u
typedef struct
{
  guint version;
  /* Canonical UUIDv7 bytes bind this evidence to one operation, rather than
   * merely to whichever fixed final currently has the recorded FileId. */
  guint8 operation_uuid[16];
  WylFactGraphWinIdentity graph_identity;
  WylFactGraphWinIdentity artifact_identity;
} WylFactGraphWinOperationEvidence;
#endif

typedef struct
{
#ifdef G_OS_WIN32
  gpointer handle;
  WylFactGraphWinIdentity identity;
#else
  gint fd;
  guint64 device;
  guint64 inode;
#endif
  gchar *path;
  wyrelog_error_t (*checkpoint) (const gchar * point, gpointer user_data);
  gpointer checkpoint_data;
} WylFactGraphResolver;

typedef struct
{
#ifdef G_OS_WIN32
  gpointer handle;
  WylFactGraphWinIdentity identity;
#else
  gint fd;
  guint64 device;
  guint64 inode;
#endif
  guint64 size_bytes;
} WylFactGraphRegularFile;

typedef struct
{
#ifdef G_OS_WIN32
  gpointer root_handle;
  gpointer tenant_handle;
  gpointer graph_handle;
  WylFactGraphWinIdentity root_identity;
  WylFactGraphWinIdentity tenant_identity;
  WylFactGraphWinIdentity graph_identity;
#else
  gint root_fd;
  gint tenant_fd;
  gint graph_fd;
  guint64 root_device;
  guint64 root_inode;
  guint64 tenant_device;
  guint64 tenant_inode;
  guint64 graph_device;
  guint64 graph_inode;
#endif
  gchar *root_path;
  gchar *tenant_component;
  gchar *graph_component;
  wyrelog_error_t (*checkpoint) (const gchar * point, gpointer user_data);
  gpointer checkpoint_data;
} WylFactGraphDirectory;

/* Opaque authority for one exact retained provisioning pair.  It owns
 * independent root/tenant/graph and final-file handles and pins the identity
 * verified by the #595 exact opener; callers cannot retarget it by changing
 * either retained name.
 *
 * POSIX binds a retained nlink==2 hard-link pair.  Windows has no
 * representation yet and no code path that produces one: its locator rejects
 * NumberOfLinks != 1 for every regular file it hands out, so that proof is
 * unrepresentable there, and its authority fails closed.  A
 * WylFactGraphWinOperationEvidence tuple is the intended substitute, pending a
 * durable place to record it. */
typedef struct WylFactGraphProvisionedPair WylFactGraphProvisionedPair;

typedef struct
{
  gint fd;
  gchar *stage_basename;
  gchar *final_basename;
  /* Exact provisioning stages are derived from a durable UUIDv7 operation
   * record.  Their publication path never trusts a source pathname after the
   * handle has been acquired. */
  gboolean exact_provisioning_stage;
#ifdef G_OS_WIN32
  WylFactGraphWinIdentity identity;
  WylFactGraphWinIdentity graph_identity;
  WylFactGraphWinOperationEvidence operation_evidence;
#else
  guint64 device;
  guint64 inode;
  guint64 graph_device;
  guint64 graph_inode;
#endif
} WylFactGraphStage;

#ifdef G_OS_WIN32
#define WYL_FACT_GRAPH_RESOLVER_INIT { .handle = NULL }
#define WYL_FACT_GRAPH_DIRECTORY_INIT \
  { .root_handle = NULL, .tenant_handle = NULL, .graph_handle = NULL }
#define WYL_FACT_GRAPH_REGULAR_FILE_INIT { .handle = NULL }
#else
#define WYL_FACT_GRAPH_RESOLVER_INIT { .fd = -1 }
#define WYL_FACT_GRAPH_DIRECTORY_INIT \
  { .root_fd = -1, .tenant_fd = -1, .graph_fd = -1 }
#define WYL_FACT_GRAPH_REGULAR_FILE_INIT { .fd = -1 }
#endif
#define WYL_FACT_GRAPH_STAGE_INIT { .fd = -1 }

wyrelog_error_t wyl_fact_graph_component_encode (const gchar * value,
    gchar ** out_component);
wyrelog_error_t wyl_fact_graph_component_decode (const gchar * component,
    gchar ** out_value);
gboolean wyl_fact_graph_owner_mode_is_secure_for_test (guint32 mode,
    guint64 owner, guint64 expected_owner, guint32 expected_mode);
wyrelog_error_t wyl_fact_graph_locator_init (WylFactGraphLocator * locator,
    const gchar * tenant_id, const gchar * graph_id);
void wyl_fact_graph_locator_clear (WylFactGraphLocator * locator);
/* Two distinct domains.  `relative_dir` composes the canonical relative-path
 * domain, which is forward-slash on every platform: it is what the journal
 * and the store's CHECK constraints accept, and what
 * `wyl_fact_graph_relative_path_is_valid` validates.  `descriptive_path`
 * composes a native filesystem path under |fact_root| and therefore uses the
 * platform separator.  Neither is a substitute for the other. */
gchar *wyl_fact_graph_locator_relative_dir (const WylFactGraphLocator *
    locator);
gchar *wyl_fact_graph_locator_descriptive_path (const gchar * fact_root,
    const WylFactGraphLocator * locator);
gboolean wyl_fact_graph_relative_path_is_valid (const gchar * value);
wyrelog_error_t wyl_fact_graph_resolver_open (const gchar * fact_root,
    WylFactGraphResolver * out_resolver);
wyrelog_error_t wyl_fact_graph_resolver_revalidate (WylFactGraphResolver *
    resolver);
void wyl_fact_graph_resolver_clear (WylFactGraphResolver * resolver);
void wyl_fact_graph_resolver_set_checkpoint_for_test
  (WylFactGraphResolver * resolver,
    wyrelog_error_t (*checkpoint) (const gchar * point, gpointer user_data),
    gpointer user_data);
wyrelog_error_t wyl_fact_graph_resolver_open_directory
  (WylFactGraphResolver * resolver, const WylFactGraphLocator * locator,
    gboolean create, WylFactGraphDirectory * out_directory);
wyrelog_error_t wyl_fact_graph_resolver_open_relative_regular
  (WylFactGraphResolver * resolver, const gchar * relative_path,
    WylFactGraphRegularFile * out_file);
void wyl_fact_graph_regular_file_clear (WylFactGraphRegularFile * file);
void wyl_fact_graph_directory_clear (WylFactGraphDirectory * directory);
gchar *wyl_fact_graph_directory_descriptive_path (const WylFactGraphDirectory
    * directory);
gchar *wyl_fact_graph_directory_descriptive_file (const WylFactGraphDirectory
    * directory, const gchar * basename);
wyrelog_error_t wyl_fact_graph_directory_open_file
  (WylFactGraphDirectory * directory, const gchar * basename,
    gboolean writable, gint * out_fd);
wyrelog_error_t wyl_fact_graph_directory_secure_file_mode
  (WylFactGraphDirectory * directory, const gchar * basename);
wyrelog_error_t wyl_fact_graph_directory_stage_create
  (WylFactGraphDirectory * directory, const gchar * final_basename,
    WylFactGraphStage * out_stage);
/* Create exactly one durable provisioning stage.  |operation_uuid| must be a
 * canonical UUIDv7; the locator derives `provision-<uuidv7>.sqlite` and the
 * fixed `facts.duckdb` final name internally.  This API never generates
 * identifiers and never reuses an existing entry.  EEXIST is BUSY. */
wyrelog_error_t wyl_fact_graph_directory_stage_create_exact
  (WylFactGraphDirectory * directory, const gchar * operation_uuid,
    WylFactGraphStage * out_stage);
/* Reopen only the exact persisted provisioning-stage name.  This never
 * creates a file; absence is NOT_FOUND.  A returned handle proves current
 * resolver-relative binding, not pre-crash provenance. */
wyrelog_error_t wyl_fact_graph_directory_stage_open_exact
  (WylFactGraphDirectory * directory, const gchar * operation_uuid,
    WylFactGraphStage * out_stage);
#ifdef G_OS_WIN32
/* Return the versioned evidence minted by exact stage creation/reopen.  This
 * is private locator metadata; #544 owns its durable record and ordering. */
wyrelog_error_t wyl_fact_graph_stage_get_windows_operation_evidence
  (const WylFactGraphStage * stage,
    WylFactGraphWinOperationEvidence * out_evidence);
/* Reopen only the canonical UUIDv7-derived stage after exact equality with
 * durable operation evidence.  UUID-only stage reopen remains fail-closed on
 * Windows because a name does not establish provenance. */
wyrelog_error_t wyl_fact_graph_directory_stage_open_exact_with_evidence
  (WylFactGraphDirectory * directory, const gchar * operation_uuid,
    const WylFactGraphWinOperationEvidence * expected_evidence,
    WylFactGraphStage * out_stage);
/* Open the fixed native final only after exact evidence equality.  This is
 * the Windows replacement for the POSIX retained hard-link-pair API. */
wyrelog_error_t wyl_fact_graph_directory_open_provisioned_final_with_evidence
  (WylFactGraphDirectory * directory, const gchar * operation_uuid,
    const WylFactGraphWinOperationEvidence * expected_evidence,
    WylFactGraphRegularFile * out_final);
/* Publish the evidence-bound exact stage with a no-replace native rename.
* The expected tuple must be the same tuple returned at stage creation. */
wyrelog_error_t wyl_fact_graph_stage_publish_with_evidence
  (WylFactGraphDirectory * directory, WylFactGraphStage * stage,
    const WylFactGraphWinOperationEvidence * expected_evidence);
#endif
/* Open the intentionally retained `stage + facts.duckdb` provisioning pair.
 * The operation UUID is canonical UUIDv7 and derives both names internally.
 * This is read-only and accepts only a secure nlink=2 pair whose two names
 * identify the same file; callers must still validate the held DB identity. */
wyrelog_error_t wyl_fact_graph_directory_open_provisioned_final_exact
  (WylFactGraphDirectory * directory, const gchar * operation_uuid,
    WylFactGraphRegularFile * out_final);
/* Windows has no name-only adoption path, so its implementation of the opener
 * fails closed; see fact/graph-locator-windows-private.c. */
wyrelog_error_t wyl_fact_graph_directory_open_provisioned_pair_exact
  (WylFactGraphDirectory * directory, const gchar * operation_uuid,
    WylFactGraphProvisionedPair ** out_pair);
WylFactGraphProvisionedPair *wyl_fact_graph_provisioned_pair_ref
  (WylFactGraphProvisionedPair * pair);
void wyl_fact_graph_provisioned_pair_free (WylFactGraphProvisionedPair * pair);
wyrelog_error_t wyl_fact_graph_provisioned_pair_revalidate
  (WylFactGraphProvisionedPair * pair);
wyrelog_error_t wyl_fact_graph_stage_sync (WylFactGraphStage * stage);
wyrelog_error_t wyl_fact_graph_stage_publish (WylFactGraphDirectory *
    directory, WylFactGraphStage * stage);
wyrelog_error_t wyl_fact_graph_stage_abort (WylFactGraphDirectory * directory,
    WylFactGraphStage * stage);
void wyl_fact_graph_stage_clear (WylFactGraphStage * stage);

G_END_DECLS;

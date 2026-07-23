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
wyrelog_error_t wyl_fact_graph_stage_sync (WylFactGraphStage * stage);
wyrelog_error_t wyl_fact_graph_stage_publish (WylFactGraphDirectory *
    directory, WylFactGraphStage * stage);
wyrelog_error_t wyl_fact_graph_stage_abort (WylFactGraphDirectory * directory,
    WylFactGraphStage * stage);
void wyl_fact_graph_stage_clear (WylFactGraphStage * stage);

G_END_DECLS;

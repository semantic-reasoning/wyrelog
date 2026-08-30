/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

#define WYL_FACT_GRAPH_DARWIN_OPERATION_EVIDENCE_VERSION 1u
#define WYL_FACT_GRAPH_DARWIN_IDENTITY_KIND_FILEID64 1u
#define WYL_FACT_GRAPH_DARWIN_OPERATION_EVIDENCE_SIZE 56u

/* Opaque durable bytes owned by the locator boundary.  Native Darwin
 * attribute structures, padding, and endianness never cross this type. */
typedef struct
{
  guint8 bytes[WYL_FACT_GRAPH_DARWIN_OPERATION_EVIDENCE_SIZE];
} WylFactGraphDarwinOperationEvidence;

/* Parsed native observations are plain values so deterministic tests exercise
 * the same fail-closed classifier used after fstatfs/fgetattrlist. */
typedef struct
{
  gboolean apfs;
  gboolean local;
  gboolean returned_attributes;
  gboolean returned_capabilities;
  gboolean returned_volume_uuid;
  gboolean fileid64_valid;
  gboolean fileid64_supported;
  gboolean path_from_id_valid;
  gboolean path_from_id_supported;
  guint8 volume_uuid[16];
} WylFactGraphDarwinVolumeObservation;

typedef struct
{
  gboolean returned_attributes;
  gboolean returned_file_id;
  guint64 file_id;
} WylFactGraphDarwinFileIdObservation;

gboolean wyl_fact_graph_darwin_operation_uuid_is_valid
  (const gchar * operation_uuid);
wyrelog_error_t wyl_fact_graph_darwin_volume_observation_validate
  (const WylFactGraphDarwinVolumeObservation * observation);
wyrelog_error_t wyl_fact_graph_darwin_file_id_observation_validate
  (const WylFactGraphDarwinFileIdObservation * observation);
wyrelog_error_t wyl_fact_graph_darwin_identity_pair_encode
  (const gchar * operation_uuid, const guint8 graph_volume_uuid[16],
    guint64 graph_file_id, const guint8 artifact_volume_uuid[16],
    guint64 artifact_file_id,
    WylFactGraphDarwinOperationEvidence * out_evidence);
wyrelog_error_t wyl_fact_graph_darwin_evidence_encode
  (const gchar * operation_uuid, const guint8 volume_uuid[16],
    guint64 graph_file_id, guint64 artifact_file_id,
    WylFactGraphDarwinOperationEvidence * out_evidence);
wyrelog_error_t wyl_fact_graph_darwin_evidence_decode
  (const guint8 * bytes, gsize length, const gchar * expected_operation_uuid,
    WylFactGraphDarwinOperationEvidence * out_evidence);
gboolean wyl_fact_graph_darwin_evidence_equal
  (const WylFactGraphDarwinOperationEvidence * left,
    const WylFactGraphDarwinOperationEvidence * right);

#ifdef __APPLE__
/* Native capture and comparison query only held descriptors. */
wyrelog_error_t wyl_fact_graph_darwin_volume_preflight (gint directory_fd);
wyrelog_error_t wyl_fact_graph_darwin_evidence_capture
  (gint graph_directory_fd, gint artifact_fd, const gchar * operation_uuid,
    WylFactGraphDarwinOperationEvidence * out_evidence);
wyrelog_error_t wyl_fact_graph_darwin_evidence_compare
  (gint graph_directory_fd, gint artifact_fd, const gchar * operation_uuid,
    const WylFactGraphDarwinOperationEvidence * expected_evidence);
#endif

G_END_DECLS;

/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/graph-artifact-inventory-private.h"

G_BEGIN_DECLS

/*
 * Historical graph-artifact durability evidence (#862, contract unit).
 *
 * This is a value-only matching contract.  It contains no path, basename,
 * descriptor, HANDLE, or reopen token.  More importantly, constructing one
 * of these values does NOT establish durability: a later producer unit must
 * issue it from an already prepared journal operation around exactly one real
 * flush boundary.  Until that persisted producer exists, callers must treat
 * an absent record as UNKNOWN and must not infer history from #622's current
 * inventory.
 */

#define WYL_FACT_ARTIFACT_DURABILITY_OPERATION_UUID_BYTES 37u
#define WYL_FACT_ARTIFACT_DURABILITY_SHA256_BYTES 32u
#define WYL_FACT_ARTIFACT_DURABILITY_MAX_ARTIFACTS 7u

typedef enum
{
  WYL_FACT_ARTIFACT_DURABILITY_EVIDENCE_V1 = 1,
} WylFactArtifactDurabilityEvidenceVersion;

typedef enum
{
  WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_INVALID = 0,
  WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_PROVISIONING,
  WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_MAIN_TRANSITION,
  WYL_FACT_ARTIFACT_DURABILITY_PRODUCER_COUNT,
} WylFactArtifactDurabilityProducer;

/* Closed V1 producer boundaries.  Each FILE boundary requires a successful
 * file flush.  DIRECTORY boundaries are the only boundaries at which the
 * platform may truthfully report UNSUPPORTED. */
typedef enum
{
  WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_INVALID = 0,
  WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_STAGE_FILE,
  WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_PROVISIONING_PUBLISH_DIRECTORY,
  WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_STAGED_FILE,
  WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_ROLLBACK_FILE,
  WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_RETAIN_DIRECTORY,
  WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_TRANSITION_PUBLISH_DIRECTORY,
  WYL_FACT_ARTIFACT_DURABILITY_BOUNDARY_COUNT,
} WylFactArtifactDurabilityBoundary;

typedef enum
{
  WYL_FACT_ARTIFACT_DURABILITY_ROLE_INVALID = 0,
  WYL_FACT_ARTIFACT_DURABILITY_ROLE_MAIN,
  WYL_FACT_ARTIFACT_DURABILITY_ROLE_WAL,
  WYL_FACT_ARTIFACT_DURABILITY_ROLE_CHECKPOINT,
  WYL_FACT_ARTIFACT_DURABILITY_ROLE_RECOVERY,
  WYL_FACT_ARTIFACT_DURABILITY_ROLE_LOCK,
  WYL_FACT_ARTIFACT_DURABILITY_ROLE_STAGE,
  WYL_FACT_ARTIFACT_DURABILITY_ROLE_ROLLBACK,
  WYL_FACT_ARTIFACT_DURABILITY_ROLE_COUNT,
} WylFactArtifactDurabilityRole;

/* UNKNOWN is zero so a zero-filled result always fails closed.  NOT_DURABLE
 * means that the producer failed to establish the required boundary; it does
 * not assert that the storage device persisted no bytes. */
typedef enum
{
  WYL_FACT_ARTIFACT_DURABILITY_UNKNOWN = 0,
  WYL_FACT_ARTIFACT_DURABILITY_DURABLE,
  WYL_FACT_ARTIFACT_DURABILITY_NOT_DURABLE,
  WYL_FACT_ARTIFACT_DURABILITY_UNSUPPORTED,
  WYL_FACT_ARTIFACT_DURABILITY_OUTCOME_COUNT,
} WylFactArtifactDurabilityOutcome;

typedef enum
{
  WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_INVALID = 0,
  WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_PREPARED,
  WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_COMPLETED,
  WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_FAILED,
  WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_FLUSH_COMPLETION_AMBIGUOUS,
  WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_TERMINAL_COMMIT_AMBIGUOUS,
  WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_DIRECTORY_FLUSH_UNSUPPORTED,
  WYL_FACT_ARTIFACT_DURABILITY_RECORD_REASON_COUNT,
} WylFactArtifactDurabilityRecordReason;

typedef struct
{
  WylFactArtifactDurabilityRole role;
  gboolean present;
  WylFactArtifactInventoryIdentity identity;
  guint64 logical_bytes;
  /* Mandatory for every present V1 entry.  It must be collected through the
   * same held and identity-revalidated authority as the producer boundary;
   * an inventory fingerprint is not a substitute for this content digest. */
  guint8 sha256[WYL_FACT_ARTIFACT_DURABILITY_SHA256_BYTES];
} WylFactArtifactDurabilityArtifact;

typedef struct
{
  /* NUL-terminated, lowercase canonical RFC 9562 UUIDv7. */
  gchar operation_uuid[WYL_FACT_ARTIFACT_DURABILITY_OPERATION_UUID_BYTES];
  guint64 consumer_generation;
  WylFactArtifactInventoryObservation observation;
  guint artifact_count;
  /* Entries [0, artifact_count) are ordered strictly by role and every tail
   * entry is zero.  This is a native value type, NOT a persistence codec:
   * enums, integers and padding must never be written as raw struct bytes.
   * The persistence unit must define and validate a canonical encoding. */
  WylFactArtifactDurabilityArtifact
      artifacts[WYL_FACT_ARTIFACT_DURABILITY_MAX_ARTIFACTS];
} WylFactArtifactDurabilityScope;

typedef struct
{
  guint version;
  WylFactArtifactDurabilityProducer producer;
  WylFactArtifactDurabilityBoundary boundary;
  WylFactArtifactDurabilityOutcome outcome;
  WylFactArtifactDurabilityRecordReason reason;
  WylFactArtifactDurabilityScope scope;
} WylFactArtifactDurabilityEvidence;

typedef enum
{
  WYL_FACT_ARTIFACT_DURABILITY_MATCH_EVIDENCE_ABSENT = 0,
  WYL_FACT_ARTIFACT_DURABILITY_MATCH_EVIDENCE_INVALID,
  WYL_FACT_ARTIFACT_DURABILITY_MATCH_EXPECTATION_INVALID,
  WYL_FACT_ARTIFACT_DURABILITY_MATCH_PRODUCER_MISMATCH,
  WYL_FACT_ARTIFACT_DURABILITY_MATCH_BOUNDARY_MISMATCH,
  WYL_FACT_ARTIFACT_DURABILITY_MATCH_OPERATION_STALE,
  WYL_FACT_ARTIFACT_DURABILITY_MATCH_GENERATION_STALE,
  WYL_FACT_ARTIFACT_DURABILITY_MATCH_DIRECTORY_SUBSTITUTED,
  WYL_FACT_ARTIFACT_DURABILITY_MATCH_GUARD_SUBSTITUTED,
  WYL_FACT_ARTIFACT_DURABILITY_MATCH_ARTIFACT_SET_CHANGED,
  WYL_FACT_ARTIFACT_DURABILITY_MATCH_ARTIFACT_IDENTITY_SUBSTITUTED,
  WYL_FACT_ARTIFACT_DURABILITY_MATCH_ARTIFACT_SIZE_CHANGED,
  WYL_FACT_ARTIFACT_DURABILITY_MATCH_ARTIFACT_CONTENT_CHANGED,
  WYL_FACT_ARTIFACT_DURABILITY_MATCH_EXACT,
  WYL_FACT_ARTIFACT_DURABILITY_MATCH_REASON_COUNT,
} WylFactArtifactDurabilityMatchReason;

typedef struct
{
  WylFactArtifactDurabilityOutcome outcome;
  WylFactArtifactDurabilityRecordReason record_reason;
  WylFactArtifactDurabilityMatchReason match_reason;
} WylFactArtifactDurabilityClassification;

gboolean wyl_fact_artifact_durability_scope_is_valid
  (const WylFactArtifactDurabilityScope *scope);
gboolean wyl_fact_artifact_durability_evidence_is_valid
  (const WylFactArtifactDurabilityEvidence *evidence);

/* Compares historical evidence with a freshly collected, digest-bearing
 * value scope.  Any missing, malformed, stale, or substituted input returns
 * UNKNOWN.  The current scope is not itself historical durability evidence. */
void wyl_fact_artifact_durability_classify
  (const WylFactArtifactDurabilityEvidence *evidence,
    WylFactArtifactDurabilityProducer expected_producer,
    WylFactArtifactDurabilityBoundary expected_boundary,
    const WylFactArtifactDurabilityScope *current,
    WylFactArtifactDurabilityClassification *out_classification);

G_END_DECLS

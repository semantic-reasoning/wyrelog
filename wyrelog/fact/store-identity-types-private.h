/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

typedef struct WylFactArtifactNamespace WylFactArtifactNamespace;
#ifndef G_OS_WIN32
typedef struct WylFactGraphProvisionedPair WylFactGraphProvisionedPair;
#endif

typedef struct
{
  const gchar *tenant_id;
  const gchar *graph_id;
  const gchar *store_uuid;
  guint64 format_version;
  guint64 path_encoding_version;
} WylFactStoreIdentity;

typedef enum
{
  WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY = 0,
  WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
} WylFactStoreIdentityOpenMode;

typedef enum
{
  WYL_FACT_STORE_IDENTITY_RESULT_NONE = 0,
  WYL_FACT_STORE_IDENTITY_RESULT_IDENTITY,
  WYL_FACT_STORE_IDENTITY_RESULT_FORMAT,
  WYL_FACT_STORE_IDENTITY_RESULT_PATH_ENCODING,
  WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA,
  WYL_FACT_STORE_IDENTITY_RESULT_OPEN,
  WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL,
} WylFactStoreIdentityResult;

typedef enum
{
  WYL_FACT_STORE_IDENTITY_TEST_FAULT_NONE = 0,
  WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_CREATE,
  WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_STORE_KIND,
  WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_FORMAT_VERSION,
  WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_STORE_UUID,
  WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_PATH_ENCODING_VERSION,
  WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_TENANT_ID,
  WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_GRAPH_ID,
  WYL_FACT_STORE_IDENTITY_TEST_FAULT_BEFORE_COMMIT,
  WYL_FACT_STORE_IDENTITY_TEST_FAULT_COMMIT,
  WYL_FACT_STORE_IDENTITY_TEST_FAULT_COMMIT_AND_ROLLBACK,
} WylFactStoreIdentityTestFault;

typedef enum
{
  WYL_FACT_STORE_PINNED_RENDEZVOUS_R0_PRECONSTRUCT = 0,
  WYL_FACT_STORE_PINNED_RENDEZVOUS_R1_POSTCONSTRUCT,
  WYL_FACT_STORE_PINNED_RENDEZVOUS_R2_PREIDENTITY,
  WYL_FACT_STORE_PINNED_RENDEZVOUS_R3_POSTIDENTITY,
  WYL_FACT_STORE_PINNED_RENDEZVOUS_R4_PREFINALIZE,
  WYL_FACT_STORE_PINNED_RENDEZVOUS_R5_FINAL_REVALIDATE,
} WylFactStorePinnedRendezvous;

typedef void (*WylFactStorePinnedTestHook) (WylFactStorePinnedRendezvous,
    gpointer user_data);

/* The one-shot pinned API consumes only a caller-held artifact namespace,
 * returns no live DuckDB handle, and is the storage handoff intended for
 * #611/#544. */
wyrelog_error_t wyl_fact_store_open_identified_pinned
    (WylFactArtifactNamespace * namespace_,
    const WylFactStoreIdentity * identity,
    WylFactStoreIdentityOpenMode mode, WylFactStoreIdentityResult * out_result);
#ifndef G_OS_WIN32
/* One-shot handoff from the exact retained provisioning pair into the bounded
 * DuckDB filesystem.  It accepts no artifact pathname or descriptor. */
wyrelog_error_t wyl_fact_store_open_identified_provisioned_pair_pinned
    (WylFactGraphProvisionedPair * pair,
    const WylFactStoreIdentity * identity,
    WylFactStoreIdentityOpenMode mode, WylFactStoreIdentityResult * out_result);
#endif
void wyl_fact_store_pinned_set_test_hook
    (WylFactStorePinnedTestHook hook, gpointer user_data);
void wyl_fact_store_pinned_set_test_stage_errors
    (wyrelog_error_t authority_error, wyrelog_error_t finalize_error,
    wyrelog_error_t r5_error);

G_END_DECLS;

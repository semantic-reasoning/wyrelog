/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "fact/graph-locator-private.h"
#include "fact/store-private.h"
#include "policy/store-private.h"

G_BEGIN_DECLS;

/*
 * This is deliberately limited to the resolver-bound, pre-DuckDB part of a
 * provisioning attempt.  It must not publish, activate, or construct a
 * descriptive database pathname: those steps require the secure DuckDB
 * filesystem bridge to own every catalog sidecar open.
 */
typedef struct
{
  WylFactGraphResolver resolver;
  WylFactGraphDirectory directory;
  WylFactGraphStage stage;
  WylFactStoreIdentity identity;
  gchar *tenant_id;
  gchar *graph_id;
  gchar *store_uuid;
} WylFactGraphProvisioningStage;

#define WYL_FACT_GRAPH_PROVISIONING_STAGE_INIT \
  { .resolver = WYL_FACT_GRAPH_RESOLVER_INIT, \
    .directory = WYL_FACT_GRAPH_DIRECTORY_INIT, \
    .stage = WYL_FACT_GRAPH_STAGE_INIT }

wyrelog_error_t wyl_fact_graph_provisioning_stage_prepare
    (const gchar * fact_root, const WylPolicyGraphProvisioningRecord * record,
    const WylPolicyGraphAuthorityRecord * authority,
    WylFactGraphProvisioningStage * out_stage);
void wyl_fact_graph_provisioning_stage_clear
    (WylFactGraphProvisioningStage * stage);

G_END_DECLS;

/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "wyrelog/error.h"

G_BEGIN_DECLS;

/* Stable, fail-closed classes emitted by the offline graph reconciler. */
typedef enum
{
  WYL_FACT_RECONCILE_EXISTING_VALID = 0,
  WYL_FACT_RECONCILE_MISSING_WITHOUT_SCHEMA,
  WYL_FACT_RECONCILE_MISSING_WITH_SCHEMA,
  WYL_FACT_RECONCILE_PARTIAL,
  WYL_FACT_RECONCILE_CORRUPT,
  WYL_FACT_RECONCILE_FOREIGN,
  WYL_FACT_RECONCILE_UNSUPPORTED_NEWER,
  WYL_FACT_RECONCILE_PATH_COLLISION,
  WYL_FACT_RECONCILE_AMBIGUOUS,
  WYL_FACT_RECONCILE_ORPHAN,
} WylFactReconcileClass;

typedef enum
{
  WYL_FACT_RECONCILE_ACTION_NONE = 0,
  /* Verified offline reconciliation only; never production auto-open. */
  WYL_FACT_RECONCILE_ACTION_RECONCILE,
  WYL_FACT_RECONCILE_ACTION_DEGRADE,
  WYL_FACT_RECONCILE_ACTION_REVIEW,
} WylFactReconcileAction;

/* Evidence is collected by read-only probes.  The classifier never opens a
 * store writable and never mutates policy or filesystem state. */
typedef struct
{
  gboolean raw_present;
  gboolean canonical_present;
  gboolean raw_valid;
  gboolean canonical_valid;
  gboolean schema_registered;
  gboolean schema_valid;
  gboolean foreign;
  gboolean unsupported_newer;
  gboolean path_collision;
  gboolean ambiguous;
  gboolean orphan;
} WylFactReconcileEvidence;

typedef struct
{
  WylFactReconcileClass classification;
  WylFactReconcileAction action;
} WylFactReconcileResult;

wyrelog_error_t wyl_fact_reconcile_classify (const WylFactReconcileEvidence *
    evidence, WylFactReconcileResult * out_result);

const gchar *wyl_fact_reconcile_class_name (WylFactReconcileClass value);
const gchar *wyl_fact_reconcile_action_name (WylFactReconcileAction value);

G_END_DECLS;

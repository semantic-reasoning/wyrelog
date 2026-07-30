/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "fact/store-identity-types-private.h"

G_BEGIN_DECLS;

typedef enum
{
  WYL_FACT_STORE_IDENTITY_CELL_NULL = 0,
  WYL_FACT_STORE_IDENTITY_CELL_INT64,
  WYL_FACT_STORE_IDENTITY_CELL_BYTES,
} WylFactStoreIdentityCellType;

typedef struct
{
  WylFactStoreIdentityCellType type;
  union
  {
    gint64 int64_value;
    struct
    {
      const guint8 *data;
      gsize length;
    } bytes;
  } as;
} WylFactStoreIdentityCell;

typedef gboolean (*WylFactStoreIdentityRowFunc) (const
    WylFactStoreIdentityCell * cells, gsize n_cells, gpointer user_data);

typedef struct
{
  gpointer context;
    wyrelog_error_t (*execute) (gpointer context, const gchar * sql,
      const WylFactStoreIdentityCell * params, gsize n_params,
      WylFactStoreIdentityRowFunc row_func, gpointer row_data,
      guint64 * out_rows);
  void (*validation_barrier) (gpointer context);
} WylFactStoreIdentityExecutor;

typedef enum
{
  WYL_FACT_STORE_IDENTITY_GUARD_BEFORE_LOCK = 0,
  WYL_FACT_STORE_IDENTITY_GUARD_AFTER_LOCK,
} WylFactStoreIdentityGuardTestStage;

typedef void (*WylFactStoreIdentityGuardTestHook)
  (WylFactStoreIdentityGuardTestStage stage, gpointer user_data);

gboolean wyl_fact_store_identity_input_is_valid
    (const WylFactStoreIdentity * identity);
gboolean wyl_fact_store_identity_mode_is_valid
    (WylFactStoreIdentityOpenMode mode);

/* DuckDB cannot safely race independent database objects while creating the
 * same catalog.  Both pathname and pinned adapters bracket construction,
 * identity execution, and checked destruction with this process guard. */
void wyl_fact_store_identity_process_guard_lock (void);
void wyl_fact_store_identity_process_guard_unlock (void);
void wyl_fact_store_identity_process_guard_set_test_hook
    (WylFactStoreIdentityGuardTestHook hook, gpointer user_data);

wyrelog_error_t wyl_fact_store_identity_execute
    (const WylFactStoreIdentityExecutor * executor,
    const WylFactStoreIdentity * identity,
    WylFactStoreIdentityOpenMode mode, WylFactStoreIdentityResult * out_result);

void wyl_fact_store_identity_set_test_fault
    (WylFactStoreIdentityTestFault fault);

G_END_DECLS;

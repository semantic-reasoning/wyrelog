/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/store-identity-private.h"

#include <string.h>

#define WYL_FACT_STORE_KIND "wyrelog.fact"
#define WYL_FACT_STORE_FORMAT_VERSION 1
#define WYL_FACT_STORE_PATH_ENCODING_VERSION 1

static gint identity_test_fault;
G_LOCK_DEFINE_STATIC (identity_open);
static WylFactStoreIdentityGuardTestHook identity_guard_test_hook;
static gpointer identity_guard_test_hook_data;
G_LOCK_DEFINE_STATIC (identity_guard_test_hook);

typedef struct
{
  gboolean valid;
  gboolean seen;
  gint64 value;
} CountResult;

typedef struct
{
  gboolean valid;
  guint row;
} SchemaColumnsResult;

typedef struct
{
  gboolean valid;
  gboolean seen;
} DdlResult;

typedef struct
{
  gchar *values[6];
  gsize lengths[6];
  gboolean seen[6];
  gboolean valid;
} IdentityValuesResult;

static gboolean
identity_uuid_is_canonical (const gchar *value)
{
  if (value == NULL || strlen (value) != 36 || value[8] != '-'
      || value[13] != '-' || value[18] != '-' || value[23] != '-')
    return FALSE;
  for (gsize i = 0; i < 36; i++) {
    if (i == 8 || i == 13 || i == 18 || i == 23)
      continue;
    if (!g_ascii_isdigit (value[i])
        && !(value[i] >= 'a' && value[i] <= 'f'))
      return FALSE;
  }
  return TRUE;
}

gboolean
wyl_fact_store_identity_input_is_valid (const WylFactStoreIdentity *identity)
{
  return identity != NULL
      && identity->tenant_id != NULL && identity->tenant_id[0] != '\0'
      && g_utf8_validate (identity->tenant_id, -1, NULL)
      && identity->graph_id != NULL && identity->graph_id[0] != '\0'
      && g_utf8_validate (identity->graph_id, -1, NULL)
      && identity_uuid_is_canonical (identity->store_uuid)
      && identity->format_version > 0
      && identity->format_version <= G_MAXINT64
      && identity->path_encoding_version > 0
      && identity->path_encoding_version <= G_MAXINT64;
}

gboolean
wyl_fact_store_identity_mode_is_valid (WylFactStoreIdentityOpenMode mode)
{
  switch (mode) {
    case WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY:
    case WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY:
      return TRUE;
  }
  return FALSE;
}

void
wyl_fact_store_identity_process_guard_lock (void)
{
  WylFactStoreIdentityGuardTestHook hook = NULL;
  gpointer hook_data = NULL;
  G_LOCK (identity_guard_test_hook);
  hook = identity_guard_test_hook;
  hook_data = identity_guard_test_hook_data;
  identity_guard_test_hook = NULL;
  identity_guard_test_hook_data = NULL;
  G_UNLOCK (identity_guard_test_hook);
  if (hook != NULL)
    hook (WYL_FACT_STORE_IDENTITY_GUARD_BEFORE_LOCK, hook_data);
  G_LOCK (identity_open);
  if (hook != NULL)
    hook (WYL_FACT_STORE_IDENTITY_GUARD_AFTER_LOCK, hook_data);
}

void
wyl_fact_store_identity_process_guard_unlock (void)
{
  G_UNLOCK (identity_open);
}

void wyl_fact_store_identity_process_guard_set_test_hook
    (WylFactStoreIdentityGuardTestHook hook, gpointer user_data)
{
  G_LOCK (identity_guard_test_hook);
  identity_guard_test_hook = hook;
  identity_guard_test_hook_data = user_data;
  G_UNLOCK (identity_guard_test_hook);
}

static gboolean
canonical_decimal (const gchar *value, guint64 *out_value)
{
  guint64 parsed = 0;

  if (value == NULL || value[0] == '\0'
      || (value[0] == '0' && value[1] != '\0'))
    return FALSE;
  for (const gchar * p = value; *p != '\0'; p++) {
    if (!g_ascii_isdigit (*p))
      return FALSE;
    guint digit = (guint) (*p - '0');
    if (parsed > (G_MAXUINT64 - digit) / 10)
      return FALSE;
    parsed = parsed * 10 + digit;
  }
  if (parsed == 0 || parsed > G_MAXINT64)
    return FALSE;
  *out_value = parsed;
  return TRUE;
}

static gboolean
count_row (const WylFactStoreIdentityCell *cells, gsize n_cells,
    gpointer user_data)
{
  CountResult *result = user_data;
  if (result->seen || n_cells != 1
      || cells[0].type != WYL_FACT_STORE_IDENTITY_CELL_INT64) {
    result->valid = FALSE;
    return FALSE;
  }
  result->seen = TRUE;
  result->value = cells[0].as.int64_value;
  return TRUE;
}

static wyrelog_error_t
query_count (const WylFactStoreIdentityExecutor *executor, const gchar *sql,
    gint64 *out_count)
{
  CountResult result = { TRUE, FALSE, 0 };
  guint64 rows = 0;
  wyrelog_error_t rc = executor->execute (executor->context, sql, NULL, 0,
      count_row, &result, &rows);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!result.valid || !result.seen || rows != 1)
    return WYRELOG_E_IO;
  *out_count = result.value;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
execute_no_rows (const WylFactStoreIdentityExecutor *executor,
    const gchar *sql, const WylFactStoreIdentityCell *params, gsize n_params)
{
  guint64 rows = 0;
  return executor->execute (executor->context, sql, params, n_params, NULL,
      NULL, &rows);
}

static wyrelog_error_t
identity_metadata_exists (const WylFactStoreIdentityExecutor *executor,
    gboolean *out_exists)
{
  gint64 count = 0;
  wyrelog_error_t rc = query_count (executor,
      "SELECT CAST(COUNT(*) AS BIGINT) FROM duckdb_tables() "
      "WHERE schema_name='main' "
      "AND table_name='fact_store_metadata' AND NOT internal;", &count);
  if (rc != WYRELOG_E_OK)
    return rc;
  *out_exists = count == 1;
  return count <= 1 ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
identity_catalog_is_empty (const WylFactStoreIdentityExecutor *executor,
    gboolean *out_empty)
{
  static const gchar *queries[] = {
    "SELECT CAST(COUNT(*) AS BIGINT) FROM duckdb_tables() "
        "WHERE NOT internal;",
    "SELECT CAST(COUNT(*) AS BIGINT) FROM duckdb_views() "
        "WHERE NOT internal;",
    "SELECT CAST(COUNT(*) AS BIGINT) FROM duckdb_sequences();",
    "SELECT CAST(COUNT(*) AS BIGINT) FROM duckdb_types() "
        "WHERE NOT internal;",
    "SELECT CAST(COUNT(*) AS BIGINT) FROM duckdb_functions() "
        "WHERE NOT internal;",
    "SELECT CAST(COUNT(*) AS BIGINT) FROM duckdb_schemas() "
        "WHERE NOT internal "
        "AND schema_name NOT IN ('main','information_schema','pg_catalog');",
  };
  gint64 total = 0;
  for (gsize i = 0; i < G_N_ELEMENTS (queries); i++) {
    gint64 count = 0;
    wyrelog_error_t rc = query_count (executor, queries[i], &count);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (count < 0 || total > G_MAXINT64 - count)
      return WYRELOG_E_IO;
    total += count;
  }
  *out_empty = total == 0;
  return WYRELOG_E_OK;
}

static gboolean
bytes_equal_literal (const WylFactStoreIdentityCell *cell, const gchar *literal)
{
  gsize length = strlen (literal);
  return cell->type == WYL_FACT_STORE_IDENTITY_CELL_BYTES
      && cell->as.bytes.length == length
      && memcmp (cell->as.bytes.data, literal, length) == 0;
}

static gboolean
schema_columns_row (const WylFactStoreIdentityCell *cells, gsize n_cells,
    gpointer user_data)
{
  static const gchar *names[] = { "key", "value" };
  SchemaColumnsResult *result = user_data;
  guint row = result->row++;
  if (row >= G_N_ELEMENTS (names) || n_cells != 6
      || !bytes_equal_literal (&cells[0], names[row])
      || !bytes_equal_literal (&cells[1], "VARCHAR")
      || !bytes_equal_literal (&cells[2], "NO")
      || cells[3].type != WYL_FACT_STORE_IDENTITY_CELL_NULL
      || cells[4].type != WYL_FACT_STORE_IDENTITY_CELL_INT64
      || cells[4].as.int64_value != (gint64) row + 1
      || cells[5].type != WYL_FACT_STORE_IDENTITY_CELL_NULL) {
    result->valid = FALSE;
    return FALSE;
  }
  return TRUE;
}

static gboolean
ddl_row (const WylFactStoreIdentityCell *cells, gsize n_cells,
    gpointer user_data)
{
  DdlResult *result = user_data;
  if (result->seen || n_cells != 1
      || cells[0].type != WYL_FACT_STORE_IDENTITY_CELL_BYTES
      || cells[0].as.bytes.length == 0
      || !g_utf8_validate ((const gchar *) cells[0].as.bytes.data,
          cells[0].as.bytes.length, NULL)) {
    result->valid = FALSE;
    return FALSE;
  }
  result->seen = TRUE;
  g_autofree gchar *ddl = g_strndup ((const gchar *) cells[0].as.bytes.data,
      cells[0].as.bytes.length);
  g_autofree gchar *lower = ddl != NULL ? g_ascii_strdown (ddl, -1) : NULL;
  result->valid = lower != NULL && strstr (lower, "collate") == NULL;
  return result->valid;
}

static wyrelog_error_t
validate_identity_schema (const WylFactStoreIdentityExecutor *executor)
{
  static const gchar *columns_sql =
      "SELECT column_name,data_type,is_nullable,column_default,"
      "CAST(ordinal_position AS BIGINT),collation_name "
      "FROM information_schema.columns "
      "WHERE table_schema='main' "
      "AND table_name='fact_store_metadata' ORDER BY ordinal_position;";
  SchemaColumnsResult columns = { TRUE, 0 };
  guint64 rows = 0;
  wyrelog_error_t rc = executor->execute (executor->context, columns_sql,
      NULL, 0, schema_columns_row, &columns, &rows);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!columns.valid || rows != 2 || columns.row != 2)
    return WYRELOG_E_POLICY;

  gint64 total_count = 0;
  gint64 table_shape_count = 0;
  gint64 primary_key_shape_count = 0;
  rc = query_count (executor,
      "SELECT CAST(COUNT(*) AS BIGINT) FROM duckdb_constraints() "
      "WHERE schema_name='main' "
      "AND table_name='fact_store_metadata';", &total_count);
  if (rc == WYRELOG_E_OK)
    rc = query_count (executor,
        "SELECT CAST(COUNT(*) AS BIGINT) FROM duckdb_tables() "
        "WHERE schema_name='main' "
        "AND table_name='fact_store_metadata' AND NOT internal "
        "AND has_primary_key AND column_count=2 AND index_count=1 "
        "AND check_constraint_count=0;", &table_shape_count);
  if (rc == WYRELOG_E_OK)
    rc = query_count (executor,
        "SELECT CAST(COUNT(*) AS BIGINT) FROM duckdb_constraints() "
        "WHERE schema_name='main' "
        "AND table_name='fact_store_metadata' "
        "AND constraint_type='PRIMARY KEY' "
        "AND constraint_text='PRIMARY KEY(\"key\")';",
        &primary_key_shape_count);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (total_count != 3 || table_shape_count != 1
      || primary_key_shape_count != 1)
    return WYRELOG_E_POLICY;

  DdlResult ddl = { TRUE, FALSE };
  rows = 0;
  rc = executor->execute (executor->context,
      "SELECT sql FROM duckdb_tables() "
      "WHERE schema_name='main' "
      "AND table_name='fact_store_metadata' AND NOT internal;",
      NULL, 0, ddl_row, &ddl, &rows);
  if (rc != WYRELOG_E_OK)
    return rc;
  return ddl.valid && ddl.seen && rows == 1 ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static gboolean
identity_values_row (const WylFactStoreIdentityCell *cells, gsize n_cells,
    gpointer user_data)
{
  static const gchar *keys[] = {
    "store_kind", "format_version", "store_uuid", "path_encoding_version",
    "tenant_id", "graph_id"
  };
  IdentityValuesResult *result = user_data;
  if (n_cells != 2
      || cells[0].type != WYL_FACT_STORE_IDENTITY_CELL_BYTES
      || cells[1].type != WYL_FACT_STORE_IDENTITY_CELL_BYTES
      || cells[0].as.bytes.length == 0 || cells[1].as.bytes.length == 0
      || memchr (cells[0].as.bytes.data, '\0', cells[0].as.bytes.length)
      || memchr (cells[1].as.bytes.data, '\0', cells[1].as.bytes.length)
      || !g_utf8_validate ((const gchar *) cells[0].as.bytes.data,
          cells[0].as.bytes.length, NULL)
      || !g_utf8_validate ((const gchar *) cells[1].as.bytes.data,
          cells[1].as.bytes.length, NULL)) {
    result->valid = FALSE;
    return FALSE;
  }
  gsize slot = G_N_ELEMENTS (keys);
  for (gsize i = 0; i < G_N_ELEMENTS (keys); i++)
    if (cells[0].as.bytes.length == strlen (keys[i])
        && memcmp (cells[0].as.bytes.data, keys[i], strlen (keys[i])) == 0) {
      slot = i;
      break;
    }
  if (slot == G_N_ELEMENTS (keys) || result->seen[slot]) {
    result->valid = FALSE;
    return FALSE;
  }
  result->values[slot] =
      g_strndup ((const gchar *) cells[1].as.bytes.data,
      cells[1].as.bytes.length);
  if (result->values[slot] == NULL) {
    result->valid = FALSE;
    return FALSE;
  }
  result->lengths[slot] = cells[1].as.bytes.length;
  result->seen[slot] = TRUE;
  return TRUE;
}

static wyrelog_error_t
validate_identity_values (const WylFactStoreIdentityExecutor *executor,
    const WylFactStoreIdentity *identity,
    WylFactStoreIdentityResult *out_result)
{
  IdentityValuesResult values = {.valid = TRUE };
  guint64 rows = 0;
  wyrelog_error_t rc = executor->execute (executor->context,
      "SELECT key,value FROM main.fact_store_metadata;", NULL, 0,
      identity_values_row, &values, &rows);
  if (rc != WYRELOG_E_OK) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    goto out;
  }
  if (!values.valid || rows != G_N_ELEMENTS (values.values)) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA;
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  for (gsize i = 0; i < G_N_ELEMENTS (values.values); i++)
    if (!values.seen[i]) {
      *out_result = WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA;
      rc = WYRELOG_E_POLICY;
      goto out;
    }

  if (strcmp (values.values[0], WYL_FACT_STORE_KIND) != 0
      || !identity_uuid_is_canonical (values.values[2])
      || strcmp (values.values[2], identity->store_uuid) != 0
      || strcmp (values.values[4], identity->tenant_id) != 0
      || strcmp (values.values[5], identity->graph_id) != 0) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_IDENTITY;
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  guint64 path_version = 0;
  if (!canonical_decimal (values.values[3], &path_version)
      || path_version != identity->path_encoding_version
      || path_version != WYL_FACT_STORE_PATH_ENCODING_VERSION) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_PATH_ENCODING;
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  guint64 format_version = 0;
  if (!canonical_decimal (values.values[1], &format_version)
      || format_version != identity->format_version
      || format_version != WYL_FACT_STORE_FORMAT_VERSION) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_FORMAT;
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  *out_result = WYL_FACT_STORE_IDENTITY_RESULT_NONE;
  rc = WYRELOG_E_OK;

out:
  for (gsize i = 0; i < G_N_ELEMENTS (values.values); i++)
    g_free (values.values[i]);
  return rc;
}

static wyrelog_error_t
validate_identity_unlocked (const WylFactStoreIdentityExecutor *executor,
    const WylFactStoreIdentity *identity, gboolean *out_missing,
    WylFactStoreIdentityResult *out_result)
{
  gboolean exists = FALSE;
  *out_missing = FALSE;
  wyrelog_error_t rc = identity_metadata_exists (executor, &exists);
  if (rc != WYRELOG_E_OK) {
    *out_result = rc == WYRELOG_E_POLICY ?
        WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA :
        WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    return rc;
  }
  if (!exists) {
    *out_missing = TRUE;
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA;
    return WYRELOG_E_POLICY;
  }
  rc = validate_identity_schema (executor);
  if (rc != WYRELOG_E_OK) {
    *out_result = rc == WYRELOG_E_POLICY ?
        WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA :
        WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    return rc;
  }
  if (executor->validation_barrier != NULL)
    executor->validation_barrier (executor->context);
  gint64 audit_tables = 0;
  rc = query_count (executor,
      "SELECT CAST(COUNT(*) AS BIGINT) FROM duckdb_tables() "
      "WHERE schema_name='main' "
      "AND table_name='audit_events' AND NOT internal;", &audit_tables);
  if (rc != WYRELOG_E_OK) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    return rc;
  }
  if (audit_tables != 0) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_IDENTITY;
    return WYRELOG_E_POLICY;
  }
  return validate_identity_values (executor, identity, out_result);
}

static wyrelog_error_t
validate_identity_snapshot (const WylFactStoreIdentityExecutor *executor,
    const WylFactStoreIdentity *identity, gboolean *out_missing,
    WylFactStoreIdentityResult *out_result)
{
  wyrelog_error_t rc = execute_no_rows (executor, "BEGIN TRANSACTION;", NULL,
      0);
  if (rc != WYRELOG_E_OK) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    return rc;
  }
  rc = validate_identity_unlocked (executor, identity, out_missing, out_result);
  const gchar *cleanup =
      rc == WYRELOG_E_OK || rc == WYRELOG_E_POLICY ? "COMMIT;" : "ROLLBACK;";
  if (execute_no_rows (executor, cleanup, NULL, 0) != WYRELOG_E_OK) {
    if (cleanup[0] == 'C')
      (void) execute_no_rows (executor, "ROLLBACK;", NULL, 0);
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    return WYRELOG_E_INTERNAL;
  }
  return rc;
}

static gboolean
identity_fault (WylFactStoreIdentityTestFault fault)
{
  return g_atomic_int_compare_and_exchange (&identity_test_fault, fault,
      WYL_FACT_STORE_IDENTITY_TEST_FAULT_NONE);
}

void
wyl_fact_store_identity_set_test_fault (WylFactStoreIdentityTestFault fault)
{
  if (fault >= WYL_FACT_STORE_IDENTITY_TEST_FAULT_NONE
      && fault <= WYL_FACT_STORE_IDENTITY_TEST_FAULT_COMMIT_AND_ROLLBACK)
    g_atomic_int_set (&identity_test_fault, fault);
}

static WylFactStoreIdentityCell
bytes_param (const gchar *value)
{
  WylFactStoreIdentityCell cell = {
    .type = WYL_FACT_STORE_IDENTITY_CELL_BYTES,
    .as.bytes = {
        (const guint8 *) value, strlen (value)}
  };
  return cell;
}

static wyrelog_error_t
insert_identity_value (const WylFactStoreIdentityExecutor *executor,
    const gchar *key, const gchar *value)
{
  WylFactStoreIdentityCell params[] = {
    bytes_param (key), bytes_param (value)
  };
  return execute_no_rows (executor,
      "INSERT INTO main.fact_store_metadata(key,value) VALUES (?,?);",
      params, G_N_ELEMENTS (params));
}

static wyrelog_error_t
initialize_identity_unlocked (const WylFactStoreIdentityExecutor *executor,
    const WylFactStoreIdentity *identity,
    WylFactStoreIdentityResult *out_result)
{
  gboolean in_transaction = FALSE;
  gboolean injected_rollback_failure = FALSE;
  gboolean empty = FALSE;
  wyrelog_error_t rc = execute_no_rows (executor, "BEGIN TRANSACTION;", NULL,
      0);
  if (rc != WYRELOG_E_OK) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    return rc;
  }
  in_transaction = TRUE;
  rc = identity_catalog_is_empty (executor, &empty);
  if (rc != WYRELOG_E_OK || !empty) {
    *out_result = rc == WYRELOG_E_OK ? WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA :
        WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    rc = rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
    goto rollback;
  }
  rc = execute_no_rows (executor,
      "CREATE TABLE main.fact_store_metadata("
      "key VARCHAR PRIMARY KEY,value VARCHAR NOT NULL);", NULL, 0);
  if (rc != WYRELOG_E_OK)
    goto internal_or_open;
  if (identity_fault (WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_CREATE))
    goto injected;

  gchar format[32];
  gchar path_encoding[32];
  g_snprintf (format, sizeof format, "%" G_GUINT64_FORMAT,
      identity->format_version);
  g_snprintf (path_encoding, sizeof path_encoding, "%" G_GUINT64_FORMAT,
      identity->path_encoding_version);
  static const gchar *keys[] = {
    "store_kind", "format_version", "store_uuid", "path_encoding_version",
    "tenant_id", "graph_id"
  };
  const gchar *values[] = {
    WYL_FACT_STORE_KIND, format, identity->store_uuid, path_encoding,
    identity->tenant_id, identity->graph_id
  };
  const WylFactStoreIdentityTestFault faults[] = {
    WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_STORE_KIND,
    WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_FORMAT_VERSION,
    WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_STORE_UUID,
    WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_PATH_ENCODING_VERSION,
    WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_TENANT_ID,
    WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_GRAPH_ID,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (keys); i++) {
    rc = insert_identity_value (executor, keys[i], values[i]);
    if (rc != WYRELOG_E_OK)
      goto internal_or_open;
    if (identity_fault (faults[i]))
      goto injected;
  }
  gboolean missing = FALSE;
  rc = validate_identity_unlocked (executor, identity, &missing, out_result);
  if (rc != WYRELOG_E_OK || missing)
    goto rollback;
  if (identity_fault (WYL_FACT_STORE_IDENTITY_TEST_FAULT_BEFORE_COMMIT))
    goto injected;
  if (identity_fault (WYL_FACT_STORE_IDENTITY_TEST_FAULT_COMMIT)) {
    rc = WYRELOG_E_IO;
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    goto rollback;
  }
  if (identity_fault (WYL_FACT_STORE_IDENTITY_TEST_FAULT_COMMIT_AND_ROLLBACK)) {
    rc = WYRELOG_E_IO;
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    injected_rollback_failure = TRUE;
    goto rollback;
  }
  rc = execute_no_rows (executor, "COMMIT;", NULL, 0);
  if (rc != WYRELOG_E_OK) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
    goto rollback;
  }
  return WYRELOG_E_OK;

injected:
  rc = WYRELOG_E_INTERNAL;
  *out_result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
  goto rollback;

internal_or_open:
  *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;

rollback:
  if (in_transaction
      && (injected_rollback_failure
          || execute_no_rows (executor, "ROLLBACK;", NULL,
              0) != WYRELOG_E_OK)) {
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    return WYRELOG_E_INTERNAL;
  }
  return rc;
}

wyrelog_error_t
wyl_fact_store_identity_execute (const WylFactStoreIdentityExecutor *executor,
    const WylFactStoreIdentity *identity, WylFactStoreIdentityOpenMode mode,
    WylFactStoreIdentityResult *out_result)
{
  if (out_result != NULL)
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_NONE;
  if (executor == NULL || executor->execute == NULL || out_result == NULL
      || !wyl_fact_store_identity_input_is_valid (identity)
      || !wyl_fact_store_identity_mode_is_valid (mode))
    return WYRELOG_E_INVALID;

  gboolean missing = FALSE;
  wyrelog_error_t rc = validate_identity_snapshot (executor, identity,
      &missing, out_result);
  if (rc != WYRELOG_E_OK && missing) {
    switch (mode) {
      case WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY:
        break;
      case WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY:
        if (identity->path_encoding_version
            != WYL_FACT_STORE_PATH_ENCODING_VERSION) {
          *out_result = WYL_FACT_STORE_IDENTITY_RESULT_PATH_ENCODING;
          rc = WYRELOG_E_POLICY;
        } else if (identity->format_version != WYL_FACT_STORE_FORMAT_VERSION) {
          *out_result = WYL_FACT_STORE_IDENTITY_RESULT_FORMAT;
          rc = WYRELOG_E_POLICY;
        } else {
          rc = initialize_identity_unlocked (executor, identity, out_result);
        }
        break;
    }
  }
  return rc;
}

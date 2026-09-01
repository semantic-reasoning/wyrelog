// SPDX-License-Identifier: GPL-3.0-or-later

#include <duckdb.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int
main (void)
{
  duckdb_database database = NULL;
  duckdb_connection connection = NULL;
  duckdb_result result = { 0 };
  int status = 1;

  if (duckdb_open (NULL, &database) != DuckDBSuccess) {
    fputs ("duckdb_open failed\n", stderr);
    goto out;
  }
  if (duckdb_connect (database, &connection) != DuckDBSuccess) {
    fputs ("duckdb_connect failed\n", stderr);
    goto out;
  }
  if (duckdb_query (connection, "SELECT 42 AS answer", &result)
      != DuckDBSuccess) {
    fputs ("duckdb_query failed\n", stderr);
    duckdb_destroy_result (&result);
    goto out;
  }

  const char *column_name = duckdb_column_name (&result, 0);
  if (duckdb_row_count (&result) != 1
      || duckdb_column_count (&result) != 1
      || column_name == NULL
      || strcmp (column_name, "answer") != 0
      || duckdb_value_int64 (&result, 0, 0) != INT64_C (42)) {
    fputs ("unexpected DuckDB query result\n", stderr);
    duckdb_destroy_result (&result);
    goto out;
  }

  duckdb_destroy_result (&result);
  status = 0;

out:
  if (connection != NULL)
    duckdb_disconnect (&connection);
  if (database != NULL)
    duckdb_close (&database);
  return status;
}

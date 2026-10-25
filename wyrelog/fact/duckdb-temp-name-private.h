/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <string.h>

#include <glib.h>

G_BEGIN_DECLS;

/* The grammar of DuckDB 2.0's spill-directory children
 * (src/storage/temporary_file_manager.cpp and standard_buffer_manager.cpp).
 * Every name starts "duckdb_temp_<pid>_<instance>_" and continues with one
 * of:
 *
 *   storage_<class>-<n>.tmp   a temporary file of one buffer size class
 *   block-<n>.block           a temporary file holding one large block
 *   owner                     the empty marker an instance creates to claim
 *                             its <pid>_<instance> id
 *
 * DuckDB writes every number with to_string, so only canonical decimals are
 * accepted: no sign, no leading zero, at most 20 digits.  Callers decide
 * which pid they accept; the classifier only reports it, and only for a name
 * it accepts. */
typedef enum
{
  WYL_DUCKDB_TEMP_NAME_INVALID = 0,
  WYL_DUCKDB_TEMP_NAME_STORAGE,
  WYL_DUCKDB_TEMP_NAME_BLOCK,
  WYL_DUCKDB_TEMP_NAME_OWNER,
} WylDuckdbTempNameKind;

/* Consume one canonical decimal at *p; on success advance *p past it and
 * store the value, which must fit in a gint64 when out_value is not NULL. */
static inline gboolean
wyl_duckdb_temp_name_take_decimal (const gchar **p, gint64 *out_value)
{
  const gchar *digits = *p;
  const gchar *end = digits;
  while (g_ascii_isdigit (*end))
    end++;
  if (end == digits || end - digits > 20
      || (digits[0] == '0' && end != digits + 1))
    return FALSE;
  if (out_value != NULL) {
    guint64 value = 0;
    for (const gchar *c = digits; c < end; c++) {
      if (value > ((guint64) G_MAXINT64 - (guint64) (*c - '0')) / 10)
        return FALSE;
      value = value * 10 + (guint64) (*c - '0');
    }
    *out_value = (gint64) value;
  }
  *p = end;
  return TRUE;
}

static inline WylDuckdbTempNameKind
wyl_duckdb_temp_name_classify (const gchar *name, gint64 *out_pid)
{
  static const gchar prefix[] = "duckdb_temp_";
  static const gchar *const classes[] = {
    "DEFAULT", "S32K", "S64K", "S96K", "S128K", "S160K", "S192K", "S224K",
  };
  gint64 pid = 0;
  const gchar *p;

  if (out_pid != NULL)
    *out_pid = 0;
  if (name == NULL || strpbrk (name, "/\\") != NULL
      || !g_str_has_prefix (name, prefix))
    return WYL_DUCKDB_TEMP_NAME_INVALID;
  p = name + strlen (prefix);
  if (!wyl_duckdb_temp_name_take_decimal (&p, &pid) || *p++ != '_'
      || !wyl_duckdb_temp_name_take_decimal (&p, NULL) || *p++ != '_')
    return WYL_DUCKDB_TEMP_NAME_INVALID;
  WylDuckdbTempNameKind kind = WYL_DUCKDB_TEMP_NAME_INVALID;
  if (g_strcmp0 (p, "owner") == 0) {
    kind = WYL_DUCKDB_TEMP_NAME_OWNER;
  } else if (g_str_has_prefix (p, "block-")) {
    p += strlen ("block-");
    if (wyl_duckdb_temp_name_take_decimal (&p, NULL)
        && g_strcmp0 (p, ".block") == 0)
      kind = WYL_DUCKDB_TEMP_NAME_BLOCK;
  } else if (g_str_has_prefix (p, "storage_")) {
    p += strlen ("storage_");
    gboolean matched = FALSE;
    for (guint i = 0; i < G_N_ELEMENTS (classes); i++)
      if (g_str_has_prefix (p, classes[i])) {
        p += strlen (classes[i]);
        matched = TRUE;
        break;
      }
    if (matched && *p++ == '-' && wyl_duckdb_temp_name_take_decimal (&p, NULL)
        && g_strcmp0 (p, ".tmp") == 0)
      kind = WYL_DUCKDB_TEMP_NAME_STORAGE;
  }
  if (kind != WYL_DUCKDB_TEMP_NAME_INVALID && out_pid != NULL)
    *out_pid = pid;
  return kind;
}

G_END_DECLS;

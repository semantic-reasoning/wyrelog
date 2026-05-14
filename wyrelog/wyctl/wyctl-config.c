/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyctl-config.h"

GSettings *
wyctl_open_settings (void)
{
  const gchar *disable = g_getenv (WYCTL_GSETTINGS_DISABLE_ENV);
  if (disable != NULL && g_strcmp0 (disable, "1") == 0)
    return NULL;

  GSettingsSchemaSource *source = g_settings_schema_source_get_default ();
  if (source == NULL)
    return NULL;

  GSettingsSchema *schema = g_settings_schema_source_lookup (source,
      WYCTL_GSETTINGS_SCHEMA_ID, FALSE);
  if (schema == NULL)
    return NULL;

  GSettings *settings = g_settings_new_full (schema, NULL, NULL);
  g_settings_schema_unref (schema);
  return settings;
}

gchar *
wyctl_resolve_string_option (const gchar *cli_value, GSettings *settings,
    const gchar *key)
{
  if (cli_value != NULL)
    return g_strdup (cli_value);

  if (settings == NULL || key == NULL)
    return NULL;

  gchar *value = g_settings_get_string (settings, key);
  if (value == NULL || value[0] == '\0') {
    g_free (value);
    return NULL;
  }
  return value;
}

gchar *
wyctl_resolve_uint_option_as_string (const gchar *cli_value,
    GSettings *settings, const gchar *key)
{
  if (cli_value != NULL)
    return g_strdup (cli_value);

  if (settings == NULL || key == NULL)
    return NULL;

  guint32 value = g_settings_get_uint (settings, key);
  return g_strdup_printf ("%u", value);
}

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

/* Is `key' present in the schema behind `settings', with type `type'?
 *
 * Both resolvers below read a key the caller names, from a schema this
 * process did not choose: it is whatever carries the org.wyrelog.wyctl id
 * in the reachable sources.  A stale or partial install can therefore hand
 * back a schema that lacks a key, or declares it with another type, and
 * GLib treats both as programmer error.  Reading an absent key is a fatal
 * g_error.  Reading one of the wrong type is a CRITICAL, after which the
 * string read returns NULL and the unsigned read returns zero, which is
 * indistinguishable from a configured zero and goes on to the timeout
 * parser.  Neither is a diagnosis an operator can act on, and
 * wyctl-config.h promises this resolver never aborts.
 *
 * So ask first.  A key that is absent or of the wrong type resolves to
 * "unset", which is the same answer the caller already handles for an
 * empty value, and the caller's own missing-option diagnostic fires. */
static gboolean
wyctl_settings_has_key_of_type (GSettings *settings, const gchar *key,
    const GVariantType *type)
{
  g_autoptr (GSettingsSchema) schema = NULL;
  g_object_get (settings, "settings-schema", &schema, NULL);
  if (schema == NULL || !g_settings_schema_has_key (schema, key))
    return FALSE;

  g_autoptr (GSettingsSchemaKey) schema_key =
      g_settings_schema_get_key (schema, key);
  return g_variant_type_equal (
    g_settings_schema_key_get_value_type (schema_key), type);
}

gchar *
wyctl_resolve_string_option (const gchar *cli_value, GSettings *settings,
    const gchar *key)
{
  if (cli_value != NULL)
    return g_strdup (cli_value);

  if (settings == NULL || key == NULL)
    return NULL;

  if (!wyctl_settings_has_key_of_type (settings, key, G_VARIANT_TYPE_STRING))
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

  if (!wyctl_settings_has_key_of_type (settings, key, G_VARIANT_TYPE_UINT32))
    return NULL;

  guint32 value = g_settings_get_uint (settings, key);
  return g_strdup_printf ("%u", value);
}

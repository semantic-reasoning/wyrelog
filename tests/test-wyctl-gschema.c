/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <gio/gio.h>
#include <glib.h>

#define WYCTL_SCHEMA_ID "org.wyrelog.wyctl"
#define WYCTL_SCHEMA_PATH "/org/wyrelog/wyctl/"

typedef struct
{
  const gchar *name;
  const GVariantType *type;
} KeySpec;

static GSettingsSchema *
lookup_schema (void)
{
  GSettingsSchemaSource *source = g_settings_schema_source_get_default ();
  g_assert_nonnull (source);
  GSettingsSchema *schema = g_settings_schema_source_lookup (source,
      WYCTL_SCHEMA_ID, FALSE);
  g_assert_nonnull (schema);
  return schema;
}

static void
test_schema_keys_and_types (void)
{
  g_autoptr (GSettingsSchema) schema = lookup_schema ();

  g_assert_cmpstr (g_settings_schema_get_path (schema), ==, WYCTL_SCHEMA_PATH);

  const KeySpec expected[] = {
    {"daemon-url", G_VARIANT_TYPE_STRING},
    {"default-tenant", G_VARIANT_TYPE_STRING},
    {"default-graph", G_VARIANT_TYPE_STRING},
    {"access-token-file", G_VARIANT_TYPE_STRING},
    {"default-timeout-ms", G_VARIANT_TYPE_UINT32},
    {"default-guard-loc-class", G_VARIANT_TYPE_STRING},
    {"default-guard-risk", G_VARIANT_TYPE_INT32},
    {"default-guard-timestamp-mode", G_VARIANT_TYPE_STRING},
  };

  for (gsize i = 0; i < G_N_ELEMENTS (expected); i++) {
    g_assert_true (g_settings_schema_has_key (schema, expected[i].name));
    g_autoptr (GSettingsSchemaKey) key = g_settings_schema_get_key (schema,
        expected[i].name);
    g_assert_true (g_variant_type_equal (g_settings_schema_key_get_value_type
            (key), expected[i].type));
  }
}

static void
test_schema_omits_token_value_keys (void)
{
  g_autoptr (GSettingsSchema) schema = lookup_schema ();
  g_auto (GStrv) keys = g_settings_schema_list_keys (schema);
  g_assert_nonnull (keys);

  /* Acceptance criterion #2: token *bytes* must never live in
     GSettings; only the path may. Any key whose name suggests a
     credential value is a regression. */
  static const gchar *forbidden[] = {
    "access-token",
    "bearer-token",
    "token",
    "secret",
    "credential",
    "password",
  };

  for (gsize i = 0; keys[i] != NULL; i++) {
    for (gsize j = 0; j < G_N_ELEMENTS (forbidden); j++) {
      g_assert_cmpstr (keys[i], !=, forbidden[j]);
    }
  }
}

static void
test_schema_defaults_safe (void)
{
  g_autoptr (GSettingsSchema) schema = lookup_schema ();

  /* String defaults must be the empty sentinel so a fresh
     installation does not silently inject an unintended daemon
     URL, tenant, or token-file path. */
  static const gchar *string_keys[] = {
    "daemon-url",
    "default-tenant",
    "default-graph",
    "access-token-file",
    "default-guard-loc-class",
  };

  for (gsize i = 0; i < G_N_ELEMENTS (string_keys); i++) {
    g_autoptr (GSettingsSchemaKey) key = g_settings_schema_get_key (schema,
        string_keys[i]);
    g_autoptr (GVariant) def = g_settings_schema_key_get_default_value (key);
    g_assert_true (g_variant_is_of_type (def, G_VARIANT_TYPE_STRING));
    g_assert_cmpstr (g_variant_get_string (def, NULL), ==, "");
  }

  /* Numeric sentinels: 2000ms timeout, -1 risk score. */
  {
    g_autoptr (GSettingsSchemaKey) key = g_settings_schema_get_key (schema,
        "default-timeout-ms");
    g_autoptr (GVariant) def = g_settings_schema_key_get_default_value (key);
    g_assert_cmpuint (g_variant_get_uint32 (def), ==, 2000);
  }
  {
    g_autoptr (GSettingsSchemaKey) key = g_settings_schema_get_key (schema,
        "default-guard-risk");
    g_autoptr (GVariant) def = g_settings_schema_key_get_default_value (key);
    g_assert_cmpint (g_variant_get_int32 (def), ==, -1);
  }

  /* Guard-timestamp-mode default must be "none" (the safe option
     that preserves required-on-every-call semantics). */
  {
    g_autoptr (GSettingsSchemaKey) key = g_settings_schema_get_key (schema,
        "default-guard-timestamp-mode");
    g_autoptr (GVariant) def = g_settings_schema_key_get_default_value (key);
    g_assert_cmpstr (g_variant_get_string (def, NULL), ==, "none");
  }
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/wyctl/gschema/keys-and-types", test_schema_keys_and_types);
  g_test_add_func ("/wyctl/gschema/no-token-value-keys",
      test_schema_omits_token_value_keys);
  g_test_add_func ("/wyctl/gschema/defaults-safe", test_schema_defaults_safe);
  return g_test_run ();
}

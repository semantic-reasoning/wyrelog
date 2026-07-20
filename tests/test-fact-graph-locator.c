/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "fact/graph-locator-private.h"

typedef struct
{
  const gchar *plain;
  const gchar *encoded;
} EncodingVector;

static void
test_encoding_vectors (void)
{
  static const EncodingVector vectors[] = {
    {"", "v1-"},
    {".", "v1-2e"},
    {"..", "v1-2e2e"},
    {"a/b\\c", "v1-612f625c63"},
    {"tenant-a", "v1-74656e616e742d61"},
    {"A", "v1-41"},
    {"a", "v1-61"},
    {"é", "v1-c3a9"},
    {"雪", "v1-e99baa"},
  };

  for (gsize i = 0; i < G_N_ELEMENTS (vectors); i++) {
    g_autofree gchar *encoded = NULL;
    g_autofree gchar *decoded = NULL;

    g_assert_cmpint (wyl_fact_graph_component_encode (vectors[i].plain,
            &encoded), ==, WYRELOG_E_OK);
    g_assert_cmpstr (encoded, ==, vectors[i].encoded);
    g_assert_cmpstr (encoded, !=, ".");
    g_assert_cmpstr (encoded, !=, "..");
    g_assert_null (strchr (encoded, G_DIR_SEPARATOR));

    g_assert_cmpint (wyl_fact_graph_component_decode (encoded, &decoded), ==,
        WYRELOG_E_OK);
    g_assert_cmpstr (decoded, ==, vectors[i].plain);
  }
}

static void
test_encoding_is_collision_free_for_candidates (void)
{
  static const gchar *values[] = {
    "", ".", "..", "/", "_", "-", "a", "A", "aa", "a/a",
    "v1-61", "é", "é",
  };
  g_autoptr (GHashTable) seen =
      g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  for (gsize i = 0; i < G_N_ELEMENTS (values); i++) {
    gchar *encoded = NULL;
    g_assert_cmpint (wyl_fact_graph_component_encode (values[i], &encoded), ==,
        WYRELOG_E_OK);
    g_assert_true (g_hash_table_add (seen, encoded));
  }
}

static void
test_encoding_long_value (void)
{
  g_autofree gchar *plain = g_strnfill (4096, 'x');
  g_autofree gchar *encoded = NULL;
  g_autofree gchar *decoded = NULL;

  g_assert_cmpint (wyl_fact_graph_component_encode (plain, &encoded), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (strlen (encoded), ==, 3 + (4096 * 2));
  g_assert_cmpint (wyl_fact_graph_component_decode (encoded, &decoded), ==,
      WYRELOG_E_OK);
  g_assert_cmpstr (decoded, ==, plain);
}

static void
test_decoder_rejects_noncanonical_components (void)
{
  static const gchar *invalid[] = {
    NULL, "", "v0-61", "v1-6", "v1-6A", "v1-gg", "v1-00", "v1-c3",
    "v1-2f/", ".", "..",
  };

  for (gsize i = 0; i < G_N_ELEMENTS (invalid); i++) {
    g_autofree gchar *decoded = (gchar *) 0x1;
    g_assert_cmpint (wyl_fact_graph_component_decode (invalid[i], &decoded), ==,
        WYRELOG_E_INVALID);
    g_assert_null (decoded);
  }
}

static void
test_locator_round_trip (void)
{
  WylFactGraphLocator locator = { 0 };
  g_autofree gchar *relative = NULL;
  g_autofree gchar *path = NULL;

  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant/雪",
          "../orders"), ==, WYRELOG_E_OK);
  g_assert_cmpuint (locator.version, ==, WYL_FACT_GRAPH_PATH_VERSION);
  g_assert_cmpstr (locator.tenant_component, ==, "v1-74656e616e742fe99baa");
  g_assert_cmpstr (locator.graph_component, ==, "v1-2e2e2f6f7264657273");

  relative = wyl_fact_graph_locator_relative_dir (&locator);
  path = wyl_fact_graph_locator_descriptive_path ("/facts", &locator);
  g_assert_cmpstr (relative, ==,
      "v1-74656e616e742fe99baa/v1-2e2e2f6f7264657273");
  g_assert_cmpstr (path, ==,
      "/facts/v1-74656e616e742fe99baa/v1-2e2e2f6f7264657273");

  wyl_fact_graph_locator_clear (&locator);
  g_assert_null (locator.tenant_component);
  g_assert_null (locator.graph_component);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact-graph-locator/encoding/vectors",
      test_encoding_vectors);
  g_test_add_func ("/fact-graph-locator/encoding/collisions",
      test_encoding_is_collision_free_for_candidates);
  g_test_add_func ("/fact-graph-locator/encoding/long",
      test_encoding_long_value);
  g_test_add_func ("/fact-graph-locator/encoding/reject-noncanonical",
      test_decoder_rejects_noncanonical_components);
  g_test_add_func ("/fact-graph-locator/locator/round-trip",
      test_locator_round_trip);
  return g_test_run ();
}

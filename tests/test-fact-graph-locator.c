/* SPDX-License-Identifier: GPL-3.0-or-later */
#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700
#endif
#include <glib.h>
#include <glib/gstdio.h>

#include <errno.h>
#include <stdlib.h>

#ifndef G_OS_WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

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
    {".", "v1-5o"},
    {"..", "v1-5on0"},
    {"a/b\\c", "v1-c4nm4n33"},
    {"tenant-a", "v1-ehimsobeegmm2"},
    {"A", "v1-84"},
    {"a", "v1-c4"},
    {"a:b", "v1-c4t64"},
    {"foo.", "v1-cpnmubg"},
    {"é", "v1-oekg"},
    {"雪", "v1-t6dqk"},
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
    g_assert_null (strpbrk (encoded, ".:"));
    for (const gchar * p = encoded; *p != '\0'; p++)
      g_assert_false (g_ascii_isupper (*p));

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
  g_assert_cmpuint (strlen (encoded), ==, 3 + (4096 * 8 + 4) / 5);
  g_assert_cmpint (wyl_fact_graph_component_decode (encoded, &decoded), ==,
      WYRELOG_E_OK);
  g_assert_cmpstr (decoded, ==, plain);
}

static void
test_decoder_rejects_noncanonical_components (void)
{
  static const gchar *invalid[] = {
    NULL, "", "v0-a", "v1-0", "v1-000", "v1-000000", "v1-w",
    "v1-A4", "v1-c5", "v1-00", "v1-vs", "v1-/", "v1-c4=", ".", "..",
  };

  for (gsize i = 0; i < G_N_ELEMENTS (invalid); i++) {
    g_autofree gchar *decoded = (gchar *) 0x1;
    g_assert_cmpint (wyl_fact_graph_component_decode (invalid[i], &decoded), ==,
        WYRELOG_E_INVALID);
    g_assert_null (decoded);
  }
}

static void
test_owner_mode_contract (void)
{
  g_assert_true (wyl_fact_graph_owner_mode_is_secure_for_test (0700, 1000,
          1000, 0700));
  g_assert_false (wyl_fact_graph_owner_mode_is_secure_for_test (0700, 1001,
          1000, 0700));
  g_assert_false (wyl_fact_graph_owner_mode_is_secure_for_test (01700, 1000,
          1000, 0700));
  g_assert_false (wyl_fact_graph_owner_mode_is_secure_for_test (0750, 1000,
          1000, 0700));
}

static void
test_locator_round_trip (void)
{
  WylFactGraphLocator locator = { 0 };
  g_autofree gchar *relative = NULL;
  g_autofree gchar *path = NULL;
  g_autofree gchar *expected_relative = NULL;
  g_autofree gchar *expected_path = NULL;

  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant/雪",
          "../orders"), ==, WYRELOG_E_OK);
  g_assert_cmpuint (locator.version, ==, WYL_FACT_GRAPH_PATH_VERSION);
  g_assert_cmpstr (locator.tenant_component, ==, "v1-ehimsobeegnuj6ta");
  g_assert_cmpstr (locator.graph_component, ==, "v1-5on2urrichin4so");

  relative = wyl_fact_graph_locator_relative_dir (&locator);
  path = wyl_fact_graph_locator_descriptive_path ("/facts", &locator);
  expected_relative = g_build_filename ("v1-ehimsobeegnuj6ta",
      "v1-5on2urrichin4so", NULL);
  expected_path = g_build_filename ("/facts", "v1-ehimsobeegnuj6ta",
      "v1-5on2urrichin4so", NULL);
  g_assert_cmpstr (relative, ==, expected_relative);
  g_assert_cmpstr (path, ==, expected_path);

  wyl_fact_graph_locator_clear (&locator);
  g_assert_null (locator.tenant_component);
  g_assert_null (locator.graph_component);
}

static void
test_locator_rejects_manually_tampered_components (void)
{
  static const gchar *tampered[] = {
    "..", "../../escape", "v1-C4", "v1-c5", "v1-a/b", "v0-a",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (tampered); i++) {
    WylFactGraphLocator locator = {
      .version = WYL_FACT_GRAPH_PATH_VERSION,
      .tenant_component = (gchar *) "v1-ehimsobk",
      .graph_component = (gchar *) tampered[i],
    };
    g_autofree gchar *relative = wyl_fact_graph_locator_relative_dir (&locator);
    g_assert_null (relative);
  }
}

#ifndef G_OS_WIN32
static void
remove_tree (const gchar *path)
{
  g_autoptr (GDir) dir = g_dir_open (path, 0, NULL);
  if (dir != NULL) {
    const gchar *name;
    while ((name = g_dir_read_name (dir)) != NULL) {
      g_autofree gchar *child = g_build_filename (path, name, NULL);
      if (g_file_test (child, G_FILE_TEST_IS_DIR)
          && !g_file_test (child, G_FILE_TEST_IS_SYMLINK))
        remove_tree (child);
      else
        g_assert_cmpint (g_remove (child), ==, 0);
    }
  }
  g_assert_cmpint (g_rmdir (path), ==, 0);
}

static gchar *
make_root (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *created =
      g_dir_make_tmp ("wyl-graph-resolver-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (created);
  gchar *root = realpath (created, NULL);
  if (root == NULL) {
    gint saved_errno = errno;
    (void) g_rmdir (created);
    g_set_error (&error, G_FILE_ERROR, g_file_error_from_errno (saved_errno),
        "Failed to resolve temporary directory '%s': %s", created,
        g_strerror (saved_errno));
  }
  g_assert_no_error (error);
  g_assert_nonnull (root);
  g_assert_cmpint (g_chmod (root, 0700), ==, 0);
  return root;
}

static void
test_posix_resolver_creates_validated_graph (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphLocator locator = { 0 };
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;

  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant/a",
          "../graph"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator, TRUE, &graph), ==, WYRELOG_E_OK);
  g_autofree gchar *path = wyl_fact_graph_directory_descriptive_path (&graph);
  g_assert_true (g_file_test (path, G_FILE_TEST_IS_DIR));
  g_assert_true (g_str_has_prefix (path, root));

  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree (root);
}

static void
test_posix_resolver_rejects_symlinked_components (void)
{
  g_autofree gchar *outer = make_root ();
  g_autofree gchar *real_root = g_build_filename (outer, "real", NULL);
  g_autofree gchar *root_link = g_build_filename (outer, "root-link", NULL);
  g_assert_cmpint (g_mkdir (real_root, 0700), ==, 0);
  g_assert_cmpint (symlink (real_root, root_link), ==, 0);
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  g_assert_cmpint (wyl_fact_graph_resolver_open (root_link, &resolver), ==,
      WYRELOG_E_POLICY);
  g_autofree gchar *real_child = g_build_filename (real_root, "child", NULL);
  g_autofree gchar *linked_child = g_build_filename (root_link, "child", NULL);
  g_assert_cmpint (g_mkdir (real_child, 0700), ==, 0);
  g_assert_cmpint (wyl_fact_graph_resolver_open (linked_child, &resolver), ==,
      WYRELOG_E_POLICY);

  g_autofree gchar *root = make_root ();
  WylFactGraphLocator locator = { 0 };
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_autofree gchar *tenant = g_build_filename (root,
      locator.tenant_component, NULL);
  g_assert_cmpint (symlink (outer, tenant), ==, 0);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator, FALSE, &graph), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (g_remove (tenant), ==, 0);
  g_assert_cmpint (g_mkdir (tenant, 0700), ==, 0);
  g_autofree gchar *graph_path = g_build_filename (tenant,
      locator.graph_component, NULL);
  g_assert_cmpint (symlink (outer, graph_path), ==, 0);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator, FALSE, &graph), ==, WYRELOG_E_POLICY);

  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree (root);
  remove_tree (outer);
}

static void
test_posix_resolver_rejects_root_replacement (void)
{
  g_autofree gchar *root = make_root ();
  g_autofree gchar *old_root = g_strdup_printf ("%s-old", root);
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (g_rename (root, old_root), ==, 0);
  g_assert_cmpint (g_mkdir (root, 0700), ==, 0);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator, TRUE, &graph), ==, WYRELOG_E_POLICY);

  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree (root);
  remove_tree (old_root);
}

static void
test_posix_resolver_rejects_wrong_type_and_mode (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (g_chmod (root, 0750), ==, 0);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (g_chmod (root, 01700), ==, 0);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (g_chmod (root, 0700), ==, 0);
  g_autofree gchar *tenant = g_build_filename (root,
      locator.tenant_component, NULL);
  g_assert_true (g_file_set_contents (tenant, "x", 1, NULL));
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator, FALSE, &graph), ==, WYRELOG_E_POLICY);

  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree (root);
}

static void
test_posix_resolver_component_length_boundaries (void)
{
  g_autofree gchar *root = make_root ();
  g_autofree gchar *graph_id = g_strnfill (128, 'G');
  g_autofree gchar *long_tenant = g_strnfill (300, 't');
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", graph_id),
      ==, WYRELOG_E_OK);
  g_assert_cmpuint (strlen (locator.graph_component), ==, 208);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator, TRUE, &graph), ==, WYRELOG_E_OK);
  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_locator_clear (&locator);

  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, long_tenant,
          "graph"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator, TRUE, &graph), ==, WYRELOG_E_POLICY);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_graph_resolver_clear (&resolver);
  remove_tree (root);
}

static void
test_posix_resolver_stages_and_publishes_durably (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphStage stage = WYL_FACT_GRAPH_STAGE_INIT;
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator, TRUE, &graph), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_directory_stage_create (&graph,
          "facts.duckdb", &stage), ==, WYRELOG_E_OK);
  g_assert_cmpint (write (stage.fd, "duck", 4), ==, 4);
  g_assert_cmpint (wyl_fact_graph_stage_sync (&stage), ==, WYRELOG_E_OK);
  g_autofree gchar *final_path =
      wyl_fact_graph_directory_descriptive_file (&graph, "facts.duckdb");
  g_assert_false (g_file_test (final_path, G_FILE_TEST_EXISTS));
  g_assert_cmpint (wyl_fact_graph_stage_publish (&graph, &stage), ==,
      WYRELOG_E_OK);
  g_assert_true (g_file_test (final_path, G_FILE_TEST_IS_REGULAR));

  gint fd = -1;
  g_assert_cmpint (wyl_fact_graph_directory_open_file (&graph,
          "facts.duckdb", FALSE, &fd), ==, WYRELOG_E_OK);
  gchar buf[5] = { 0 };
  g_assert_cmpint (read (fd, buf, 4), ==, 4);
  g_assert_cmpstr (buf, ==, "duck");
  close (fd);

  wyl_fact_graph_stage_clear (&stage);
  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree (root);
}

static void
test_posix_resolver_stage_abort_and_final_substitution (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphStage stage = WYL_FACT_GRAPH_STAGE_INIT;
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator, TRUE, &graph), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_directory_stage_create (&graph,
          "facts.duckdb", &stage), ==, WYRELOG_E_OK);
  g_autofree gchar *final_path =
      wyl_fact_graph_directory_descriptive_file (&graph, "facts.duckdb");
  g_assert_false (g_file_test (final_path, G_FILE_TEST_EXISTS));
  g_assert_cmpint (wyl_fact_graph_stage_abort (&graph, &stage), ==,
      WYRELOG_E_OK);
  g_assert_false (g_file_test (final_path, G_FILE_TEST_EXISTS));

  g_autofree gchar *outside = g_build_filename (root, "outside", NULL);
  g_assert_true (g_file_set_contents (outside, "outside", -1, NULL));
  g_assert_cmpint (g_chmod (outside, 0600), ==, 0);
  g_assert_cmpint (symlink (outside, final_path), ==, 0);
  gint fd = -1;
  g_assert_cmpint (wyl_fact_graph_directory_open_file (&graph,
          "facts.duckdb", FALSE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_graph_directory_secure_file_mode (&graph,
          "facts.duckdb"), ==, WYRELOG_E_POLICY);

  wyl_fact_graph_stage_clear (&stage);
  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree (root);
}

static void
test_posix_resolver_rejects_graph_replacement_and_file_mode (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator, TRUE, &graph), ==, WYRELOG_E_OK);
  g_autofree gchar *graph_path =
      wyl_fact_graph_directory_descriptive_path (&graph);
  g_autofree gchar *old_graph = g_strdup_printf ("%s-old", graph_path);
  g_assert_cmpint (g_rename (graph_path, old_graph), ==, 0);
  g_assert_cmpint (g_mkdir (graph_path, 0700), ==, 0);
  WylFactGraphStage stage = WYL_FACT_GRAPH_STAGE_INIT;
  g_assert_cmpint (wyl_fact_graph_directory_stage_create (&graph,
          "facts.duckdb", &stage), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (g_rmdir (graph_path), ==, 0);
  g_assert_cmpint (g_rename (old_graph, graph_path), ==, 0);

  g_autofree gchar *file = g_build_filename (graph_path, "facts.duckdb",
      NULL);
  g_assert_true (g_file_set_contents (file, "db", 2, NULL));
  g_assert_cmpint (g_chmod (file, 0640), ==, 0);
  gint fd = -1;
  g_assert_cmpint (wyl_fact_graph_directory_open_file (&graph,
          "facts.duckdb", FALSE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_graph_directory_secure_file_mode (&graph,
          "facts.duckdb"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_directory_open_file (&graph,
          "facts.duckdb", FALSE, &fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (close (fd), ==, 0);

  wyl_fact_graph_stage_clear (&stage);
  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree (root);
}

static void
test_posix_resolver_never_overwrites_final_or_replaced_stage (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphStage stage = WYL_FACT_GRAPH_STAGE_INIT;
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator, TRUE, &graph), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_directory_stage_create (&graph,
          "facts.duckdb", &stage), ==, WYRELOG_E_OK);
  g_autofree gchar *final_path =
      wyl_fact_graph_directory_descriptive_file (&graph, "facts.duckdb");
  g_assert_true (g_file_set_contents (final_path, "foreign", -1, NULL));
  g_assert_cmpint (g_chmod (final_path, 0600), ==, 0);
  g_assert_cmpint (wyl_fact_graph_stage_publish (&graph, &stage), ==,
      WYRELOG_E_POLICY);
  g_autofree gchar *contents = NULL;
  g_assert_true (g_file_get_contents (final_path, &contents, NULL, NULL));
  g_assert_cmpstr (contents, ==, "foreign");
  g_assert_cmpint (g_remove (final_path), ==, 0);

  g_autofree gchar *graph_path =
      wyl_fact_graph_directory_descriptive_path (&graph);
  g_autofree gchar *stage_path = g_build_filename (graph_path,
      stage.stage_basename, NULL);
  g_assert_cmpint (g_remove (stage_path), ==, 0);
  g_assert_true (g_file_set_contents (stage_path, "replacement", -1, NULL));
  g_assert_cmpint (g_chmod (stage_path, 0600), ==, 0);
  g_assert_cmpint (wyl_fact_graph_stage_publish (&graph, &stage), ==,
      WYRELOG_E_POLICY);
  g_assert_false (g_file_test (final_path, G_FILE_TEST_EXISTS));

  wyl_fact_graph_stage_clear (&stage);
  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree (root);
}

static const gchar exact_operation_uuid[] =
    "01890f47-3c4b-7cc2-b8c4-dc0c0c070544";

typedef struct
{
  const gchar *stage_path;
  const gchar *backup_path;
  gboolean fired;
} ExactStageReplacement;

typedef struct
{
  const gchar *final_path;
  const gchar *backup_path;
  gboolean fired;
} ExactFinalReplacement;

typedef struct
{
  const gchar *point;
  gboolean fired;
} ExactStageFault;

static wyrelog_error_t
fail_exact_stage_checkpoint_once (const gchar *point, gpointer user_data)
{
  ExactStageFault *fault = user_data;
  if (!fault->fired && g_strcmp0 (point, fault->point) == 0) {
    fault->fired = TRUE;
    return WYRELOG_E_IO;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
replace_exact_stage_name (const gchar *point, gpointer user_data)
{
  ExactStageReplacement *replacement = user_data;
  if (g_strcmp0 (point, "stage-validated") != 0)
    return WYRELOG_E_OK;
  g_assert_false (replacement->fired);
  replacement->fired = TRUE;
  g_assert_cmpint (g_rename (replacement->stage_path, replacement->backup_path),
      ==, 0);
  g_assert_true (g_file_set_contents (replacement->stage_path, "foreign", -1,
          NULL));
  g_assert_cmpint (g_chmod (replacement->stage_path, 0600), ==, 0);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
replace_exact_final_after_sync (const gchar *point, gpointer user_data)
{
  ExactFinalReplacement *replacement = user_data;
  if (g_strcmp0 (point, "stage-parent-synced") != 0)
    return WYRELOG_E_OK;
  g_assert_false (replacement->fired);
  replacement->fired = TRUE;
  g_assert_cmpint (g_rename (replacement->final_path, replacement->backup_path),
      ==, 0);
  g_assert_true (g_file_set_contents (replacement->final_path, "foreign", -1,
          NULL));
  g_assert_cmpint (g_chmod (replacement->final_path, 0600), ==, 0);
  return WYRELOG_E_OK;
}

static void
test_posix_resolver_exact_stage_create_open_publish (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphStage stage = WYL_FACT_GRAPH_STAGE_INIT;
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator, TRUE, &graph), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_directory_stage_create_exact (&graph,
          exact_operation_uuid, &stage), ==, WYRELOG_E_OK);
  g_assert_cmpstr (stage.stage_basename, ==,
      "provision-01890f47-3c4b-7cc2-b8c4-dc0c0c070544.sqlite");
  g_assert_cmpstr (stage.final_basename, ==, "facts.duckdb");
  g_assert_cmpint (write (stage.fd, "held", 4), ==, 4);
  g_assert_cmpint (wyl_fact_graph_stage_sync (&stage), ==, WYRELOG_E_OK);
  wyl_fact_graph_stage_clear (&stage);

  g_assert_cmpint (wyl_fact_graph_directory_stage_open_exact (&graph,
          exact_operation_uuid, &stage), ==, WYRELOG_E_OK);
#ifdef __linux__
  g_assert_cmpint (wyl_fact_graph_stage_publish (&graph, &stage), ==,
      WYRELOG_E_OK);
  g_autofree gchar *final_path =
      wyl_fact_graph_directory_descriptive_file (&graph, "facts.duckdb");
  g_autofree gchar *contents = NULL;
  g_assert_true (g_file_get_contents (final_path, &contents, NULL, NULL));
  g_assert_cmpstr (contents, ==, "held");

  /* A post-link crash leaves the precise stage and final aliases.  That is
   * the only nlink=2 form the exact reopen API accepts. */
  g_assert_cmpint (wyl_fact_graph_directory_stage_open_exact (&graph,
          exact_operation_uuid, &stage), ==, WYRELOG_E_OK);
  wyl_fact_graph_stage_clear (&stage);
#else
  g_assert_cmpint (wyl_fact_graph_stage_publish (&graph, &stage), ==,
      WYRELOG_E_POLICY);
  g_autofree gchar *final_path =
      wyl_fact_graph_directory_descriptive_file (&graph, "facts.duckdb");
  g_assert_false (g_file_test (final_path, G_FILE_TEST_EXISTS));
  wyl_fact_graph_stage_clear (&stage);
#endif
  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree (root);
}

static void
test_posix_resolver_exact_stage_rejects_conflicts_and_invalid_ids (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphStage stage = WYL_FACT_GRAPH_STAGE_INIT;
  WylFactGraphStage conflict = WYL_FACT_GRAPH_STAGE_INIT;
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator, TRUE, &graph), ==, WYRELOG_E_OK);
  static const gchar *invalid[] = {
    "", "../01890f47-3c4b-7cc2-b8c4-dc0c0c070544",
    "01890f47-3c4b-6cc2-b8c4-dc0c0c070544",
    "01890F47-3C4B-7CC2-B8C4-DC0C0C070544",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (invalid); i++)
    g_assert_cmpint (wyl_fact_graph_directory_stage_create_exact (&graph,
            invalid[i], &stage), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_graph_directory_stage_open_exact (&graph,
          exact_operation_uuid, &stage), ==, WYRELOG_E_NOT_FOUND);
  g_assert_cmpint (wyl_fact_graph_directory_stage_create_exact (&graph,
          exact_operation_uuid, &stage), ==, WYRELOG_E_OK);
  g_assert_cmpint (write (stage.fd, "first", 5), ==, 5);
  g_assert_cmpint (wyl_fact_graph_directory_stage_create_exact (&graph,
          exact_operation_uuid, &conflict), ==, WYRELOG_E_BUSY);
  gchar buffer[6] = { 0 };
  g_assert_cmpint (pread (stage.fd, buffer, 5, 0), ==, 5);
  g_assert_cmpstr (buffer, ==, "first");
  g_assert_cmpint (wyl_fact_graph_stage_abort (&graph, &stage), ==,
      WYRELOG_E_POLICY);
  wyl_fact_graph_stage_clear (&stage);
  wyl_fact_graph_stage_clear (&conflict);
  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree (root);
}

static void
test_posix_resolver_exact_stage_adversarial_states (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphStage stage = WYL_FACT_GRAPH_STAGE_INIT;
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator, TRUE, &graph), ==, WYRELOG_E_OK);
  g_autofree gchar *graph_path =
      wyl_fact_graph_directory_descriptive_path (&graph);
  g_autofree gchar *stage_path = g_build_filename (graph_path,
      "provision-01890f47-3c4b-7cc2-b8c4-dc0c0c070544.sqlite", NULL);
  g_autofree gchar *final_path = g_build_filename (graph_path, "facts.duckdb",
      NULL);
  g_autofree gchar *outside = g_build_filename (root, "outside", NULL);
  g_assert_true (g_file_set_contents (outside, "outside", -1, NULL));
  g_assert_cmpint (g_chmod (outside, 0600), ==, 0);

  /* A symlink at the recorded name is rejected and never removed. */
  g_assert_cmpint (symlink (outside, stage_path), ==, 0);
  g_assert_cmpint (wyl_fact_graph_directory_stage_open_exact (&graph,
          exact_operation_uuid, &stage), ==, WYRELOG_E_POLICY);
  g_assert_true (g_file_test (stage_path, G_FILE_TEST_IS_SYMLINK));
  g_assert_cmpint (g_remove (stage_path), ==, 0);

  g_assert_cmpint (wyl_fact_graph_directory_stage_create_exact (&graph,
          exact_operation_uuid, &stage), ==, WYRELOG_E_OK);
  g_assert_cmpint (write (stage.fd, "held", 4), ==, 4);
  wyl_fact_graph_stage_clear (&stage);
  g_autofree gchar *alias = g_build_filename (graph_path, "foreign-link",
      NULL);
  g_assert_cmpint (link (stage_path, alias), ==, 0);
  g_assert_cmpint (wyl_fact_graph_directory_stage_open_exact (&graph,
          exact_operation_uuid, &stage), ==, WYRELOG_E_POLICY);
  g_assert_true (g_file_test (alias, G_FILE_TEST_IS_REGULAR));
  g_assert_cmpint (g_remove (alias), ==, 0);

  /* The one permitted two-link form is the recorded stage plus final. */
  g_assert_cmpint (link (stage_path, final_path), ==, 0);
  g_assert_cmpint (wyl_fact_graph_directory_stage_open_exact (&graph,
          exact_operation_uuid, &stage), ==, WYRELOG_E_OK);
  wyl_fact_graph_stage_clear (&stage);
  g_assert_cmpint (link (stage_path, alias), ==, 0);
  g_assert_cmpint (wyl_fact_graph_directory_stage_open_exact (&graph,
          exact_operation_uuid, &stage), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (g_remove (alias), ==, 0);
  g_assert_cmpint (g_remove (final_path), ==, 0);

  /* The held descriptor is the only link source.  Replacing its name during
   * the test seam cannot publish the foreign replacement. */
  g_assert_cmpint (wyl_fact_graph_directory_stage_open_exact (&graph,
          exact_operation_uuid, &stage), ==, WYRELOG_E_OK);
  g_autofree gchar *backup = g_strdup_printf ("%s-held", stage_path);
  ExactStageReplacement replacement = { stage_path, backup, FALSE };
  graph.checkpoint = replace_exact_stage_name;
  graph.checkpoint_data = &replacement;
#ifdef __linux__
  g_assert_cmpint (wyl_fact_graph_stage_publish (&graph, &stage), ==,
      WYRELOG_E_OK);
  g_assert_true (replacement.fired);
  g_autofree gchar *contents = NULL;
  g_assert_true (g_file_get_contents (final_path, &contents, NULL, NULL));
  g_assert_cmpstr (contents, ==, "held");
  g_clear_pointer (&contents, g_free);
  g_assert_true (g_file_get_contents (stage_path, &contents, NULL, NULL));
  g_assert_cmpstr (contents, ==, "foreign");
  g_clear_pointer (&contents, g_free);
  g_assert_true (g_file_get_contents (backup, &contents, NULL, NULL));
  g_assert_cmpstr (contents, ==, "held");
#else
  g_assert_cmpint (wyl_fact_graph_stage_publish (&graph, &stage), ==,
      WYRELOG_E_POLICY);
  g_assert_false (g_file_test (final_path, G_FILE_TEST_EXISTS));
  g_assert_true (replacement.fired);
#endif
  graph.checkpoint = NULL;
  graph.checkpoint_data = NULL;

  wyl_fact_graph_stage_clear (&stage);
  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree (root);
}

static void
test_posix_resolver_exact_stage_collision_and_durability (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphStage stage = WYL_FACT_GRAPH_STAGE_INIT;
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator, TRUE, &graph), ==, WYRELOG_E_OK);
  g_autofree gchar *final_path =
      wyl_fact_graph_directory_descriptive_file (&graph, "facts.duckdb");
  g_assert_cmpint (wyl_fact_graph_directory_stage_create_exact (&graph,
          exact_operation_uuid, &stage), ==, WYRELOG_E_OK);
  g_assert_cmpint (write (stage.fd, "held", 4), ==, 4);
  g_assert_true (g_file_set_contents (final_path, "foreign", -1, NULL));
  g_assert_cmpint (g_chmod (final_path, 0600), ==, 0);
  g_assert_cmpint (wyl_fact_graph_stage_publish (&graph, &stage), ==,
      WYRELOG_E_POLICY);
  g_autofree gchar *contents = NULL;
  g_assert_true (g_file_get_contents (final_path, &contents, NULL, NULL));
  g_assert_cmpstr (contents, ==, "foreign");
  g_assert_cmpint (g_remove (final_path), ==, 0);

#ifdef __linux__
  /* A fault after the FD-based link leaves only the known recoverable pair;
   * retry then reaches the parent-sync seam and likewise cannot claim
   * completion before the directory sync succeeds. */
  ExactStageFault fault = { "stage-linked", FALSE };
  graph.checkpoint = fail_exact_stage_checkpoint_once;
  graph.checkpoint_data = &fault;
  g_assert_cmpint (wyl_fact_graph_stage_publish (&graph, &stage), ==,
      WYRELOG_E_IO);
  g_assert_true (fault.fired);
  g_clear_pointer (&contents, g_free);
  g_assert_true (g_file_get_contents (final_path, &contents, NULL, NULL));
  g_assert_cmpstr (contents, ==, "held");

  g_autofree gchar *backup = g_strdup_printf ("%s-held", final_path);
  ExactFinalReplacement replacement = { final_path, backup, FALSE };
  graph.checkpoint = replace_exact_final_after_sync;
  graph.checkpoint_data = &replacement;
  g_assert_cmpint (wyl_fact_graph_stage_publish (&graph, &stage), ==,
      WYRELOG_E_POLICY);
  g_assert_true (replacement.fired);
  g_clear_pointer (&contents, g_free);
  g_assert_true (g_file_get_contents (final_path, &contents, NULL, NULL));
  g_assert_cmpstr (contents, ==, "foreign");
  g_assert_cmpint (g_remove (final_path), ==, 0);
  graph.checkpoint = NULL;
  graph.checkpoint_data = NULL;
  g_assert_cmpint (wyl_fact_graph_stage_publish (&graph, &stage), ==,
      WYRELOG_E_OK);
#else
  g_assert_cmpint (wyl_fact_graph_stage_publish (&graph, &stage), ==,
      WYRELOG_E_POLICY);
  g_assert_false (g_file_test (final_path, G_FILE_TEST_EXISTS));
#endif
  wyl_fact_graph_stage_clear (&stage);
  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree (root);
}

static void
test_posix_resolver_exact_stage_create_sync_failure (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphStage stage = WYL_FACT_GRAPH_STAGE_INIT;
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator, TRUE, &graph), ==, WYRELOG_E_OK);
  ExactStageFault fault = { "stage-created", FALSE };
  graph.checkpoint = fail_exact_stage_checkpoint_once;
  graph.checkpoint_data = &fault;
  g_assert_cmpint (wyl_fact_graph_directory_stage_create_exact (&graph,
          exact_operation_uuid, &stage), ==, WYRELOG_E_IO);
  g_assert_true (fault.fired);
  g_assert_cmpint (stage.fd, ==, -1);
  /* Failure never advertises a durable create, but it also never unlinks the
   * exact name by a potentially substituted pathname. */
  graph.checkpoint = NULL;
  graph.checkpoint_data = NULL;
  g_assert_cmpint (wyl_fact_graph_directory_stage_open_exact (&graph,
          exact_operation_uuid, &stage), ==, WYRELOG_E_OK);
  wyl_fact_graph_stage_clear (&stage);
  fault = (ExactStageFault) {
  "stage-create-parent-synced", FALSE};
  graph.checkpoint = fail_exact_stage_checkpoint_once;
  graph.checkpoint_data = &fault;
  g_assert_cmpint (wyl_fact_graph_directory_stage_create_exact (&graph,
          "01890f47-3c4b-7cc2-b8c4-dc0c0c070545", &stage), ==, WYRELOG_E_IO);
  g_assert_true (fault.fired);
  g_assert_cmpint (stage.fd, ==, -1);
  graph.checkpoint = NULL;
  graph.checkpoint_data = NULL;
  g_assert_cmpint (wyl_fact_graph_directory_stage_open_exact (&graph,
          "01890f47-3c4b-7cc2-b8c4-dc0c0c070545", &stage), ==, WYRELOG_E_OK);
  wyl_fact_graph_stage_clear (&stage);
  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree (root);
}

typedef struct
{
  const gchar *point;
  gboolean fired;
} PublishFault;

static wyrelog_error_t
fail_publish_checkpoint_once (const gchar *point, gpointer user_data)
{
  PublishFault *fault = user_data;
  if (!fault->fired && g_strcmp0 (point, fault->point) == 0) {
    fault->fired = TRUE;
    return WYRELOG_E_IO;
  }
  return WYRELOG_E_OK;
}

static void
test_posix_resolver_opens_nested_relative_regular_file (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphRegularFile file = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  g_autofree gchar *tenant = g_build_filename (root, "tenant", NULL);
  g_autofree gchar *graph = g_build_filename (tenant, "graph", NULL);
  g_autofree gchar *legacy = g_build_filename (graph, "legacy", NULL);
  g_autofree gchar *nested = g_build_filename (legacy, "nested", NULL);
  g_autofree gchar *path = g_build_filename (nested, "facts.duckdb", NULL);

  g_assert_cmpint (g_mkdir (tenant, 0700), ==, 0);
  g_assert_cmpint (g_mkdir (graph, 0700), ==, 0);
  g_assert_cmpint (g_mkdir (legacy, 0700), ==, 0);
  g_assert_cmpint (g_mkdir (nested, 0700), ==, 0);
  g_assert_true (g_file_set_contents (path, "duck", 4, NULL));
  g_assert_cmpint (g_chmod (path, 0600), ==, 0);

  g_assert_true (wyl_fact_graph_relative_path_is_valid
      ("tenant/graph/legacy/nested/facts.duckdb"));
  static const gchar *invalid[] = {
    "", "/", ".", "..", "tenant//graph", "tenant/./graph",
    "tenant/../graph", "tenant\\graph", "tenant:graph",
    "tenant/graph/",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (invalid); i++)
    g_assert_false (wyl_fact_graph_relative_path_is_valid (invalid[i]));

  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_relative_regular (&resolver,
          "tenant/graph/legacy/nested/facts.duckdb", &file), ==, WYRELOG_E_OK);
  g_assert_cmpuint (file.size_bytes, ==, 4);
  gchar contents[5] = { 0 };
  g_assert_cmpint (read (file.fd, contents, 4), ==, 4);
  g_assert_cmpstr (contents, ==, "duck");
  wyl_fact_graph_regular_file_clear (&file);

  wyl_fact_graph_resolver_clear (&resolver);
  remove_tree (root);
}

static void
test_posix_resolver_rejects_hardlink_and_aliases (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphRegularFile file = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  g_autofree gchar *tenant = g_build_filename (root, "tenant", NULL);
  g_autofree gchar *graph = g_build_filename (tenant, "graph", NULL);
  g_autofree gchar *legacy = g_build_filename (graph, "legacy", NULL);
  g_autofree gchar *path = g_build_filename (legacy, "facts.duckdb", NULL);
  g_autofree gchar *hardlink = g_build_filename (legacy, "facts-hard.duckdb",
      NULL);
  g_autofree gchar *branch_link = g_build_filename (graph, "legacy-link",
      NULL);
  g_autofree gchar *final_link = g_build_filename (legacy, "facts-link.duckdb",
      NULL);
  g_autofree gchar *outside = g_build_filename (root, "outside", NULL);

  g_assert_cmpint (g_mkdir (tenant, 0700), ==, 0);
  g_assert_cmpint (g_mkdir (graph, 0700), ==, 0);
  g_assert_cmpint (g_mkdir (legacy, 0700), ==, 0);
  g_assert_true (g_file_set_contents (path, "duck", 4, NULL));
  g_assert_cmpint (g_chmod (path, 0600), ==, 0);
  g_assert_cmpint (link (path, hardlink), ==, 0);

  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_relative_regular (&resolver,
          "tenant/graph/legacy/facts.duckdb", &file), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (g_unlink (hardlink), ==, 0);

  g_assert_true (g_file_set_contents (outside, "outside", -1, NULL));
  g_assert_cmpint (g_chmod (outside, 0600), ==, 0);
  g_assert_cmpint (symlink (outside, branch_link), ==, 0);
  g_assert_cmpint (wyl_fact_graph_resolver_open_relative_regular (&resolver,
          "tenant/graph/legacy-link/facts.duckdb", &file), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (g_remove (branch_link), ==, 0);

  g_assert_cmpint (symlink (outside, final_link), ==, 0);
  g_assert_cmpint (wyl_fact_graph_resolver_open_relative_regular (&resolver,
          "tenant/graph/legacy/facts-link.duckdb", &file), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (g_remove (final_link), ==, 0);

  wyl_fact_graph_regular_file_clear (&file);
  wyl_fact_graph_resolver_clear (&resolver);
  remove_tree (root);
}

static void
test_posix_resolver_publish_retries_converge (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator, TRUE, &graph), ==, WYRELOG_E_OK);

  static const gchar *points[] = { "stage-linked", "stage-unlinked" };
  for (gsize i = 0; i < G_N_ELEMENTS (points); i++) {
    g_autofree gchar *final = g_strdup_printf ("facts-%zu.duckdb", i);
    WylFactGraphStage stage = WYL_FACT_GRAPH_STAGE_INIT;
    g_assert_cmpint (wyl_fact_graph_directory_stage_create (&graph, final,
            &stage), ==, WYRELOG_E_OK);
    PublishFault fault = {.point = points[i] };
    graph.checkpoint = fail_publish_checkpoint_once;
    graph.checkpoint_data = &fault;
    g_assert_cmpint (wyl_fact_graph_stage_publish (&graph, &stage), ==,
        WYRELOG_E_IO);
    g_assert_true (fault.fired);
    if (i == 0)
      g_assert_cmpint (wyl_fact_graph_stage_abort (&graph, &stage), ==,
          WYRELOG_E_POLICY);
    graph.checkpoint = NULL;
    graph.checkpoint_data = NULL;
    g_assert_cmpint (wyl_fact_graph_stage_publish (&graph, &stage), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (stage.fd, ==, -1);
  }

  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree (root);
}

static void
test_posix_resolver_rejects_stage_tampering_and_cross_graph_use (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator_a = { 0 };
  WylFactGraphLocator locator_b = { 0 };
  WylFactGraphDirectory graph_a = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphDirectory graph_b = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphStage stage = WYL_FACT_GRAPH_STAGE_INIT;
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator_a, "tenant", "a"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator_b, "tenant", "b"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator_a, TRUE, &graph_a), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator_b, TRUE, &graph_b), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_directory_stage_create (&graph_a,
          "facts.duckdb", &stage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_stage_publish (&graph_b, &stage), ==,
      WYRELOG_E_INVALID);
  g_autofree gchar *valid_final = g_steal_pointer (&stage.final_basename);
  stage.final_basename = g_strdup ("../foreign");
  g_assert_cmpint (wyl_fact_graph_stage_publish (&graph_a, &stage), ==,
      WYRELOG_E_INVALID);
  g_free (stage.final_basename);
  stage.final_basename = g_steal_pointer (&valid_final);
  g_assert_cmpint (wyl_fact_graph_stage_abort (&graph_a, &stage), ==,
      WYRELOG_E_OK);

  wyl_fact_graph_stage_clear (&stage);
  wyl_fact_graph_directory_clear (&graph_b);
  wyl_fact_graph_directory_clear (&graph_a);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator_b);
  wyl_fact_graph_locator_clear (&locator_a);
  remove_tree (root);
}

typedef struct
{
  const gchar *expected_point;
  const gchar *target;
  const gchar *backup;
  const gchar *outside;
  gboolean directory;
  gboolean fired;
} ResolverRace;

static wyrelog_error_t
replace_at_resolver_checkpoint (const gchar *point, gpointer user_data)
{
  ResolverRace *race = user_data;
  if (g_strcmp0 (point, race->expected_point) != 0)
    return WYRELOG_E_OK;
  g_assert_false (race->fired);
  race->fired = TRUE;
  g_assert_cmpint (g_rename (race->target, race->backup), ==, 0);
  if (race->directory)
    g_assert_cmpint (g_mkdir (race->target, 0700), ==, 0);
  else
    g_assert_cmpint (symlink (race->outside, race->target), ==, 0);
  return WYRELOG_E_OK;
}

static void
restore_raced_target (ResolverRace *race)
{
  g_assert_true (race->fired);
  if (race->directory)
    g_assert_cmpint (g_rmdir (race->target), ==, 0);
  else
    g_assert_cmpint (g_remove (race->target), ==, 0);
  g_assert_cmpint (g_rename (race->backup, race->target), ==, 0);
}

static void
test_posix_resolver_checkpoint_replacements_fail_closed (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphLocator locator = { 0 };
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator, TRUE, &graph), ==, WYRELOG_E_OK);
  wyl_fact_graph_directory_clear (&graph);

  g_autofree gchar *tenant = g_build_filename (root,
      locator.tenant_component, NULL);
  g_autofree gchar *graph_path = g_build_filename (tenant,
      locator.graph_component, NULL);
  static const gchar *points[] = {
    "root-opened", "tenant-opened", "graph-opened",
  };
  const gchar *targets[] = { root, tenant, graph_path };
  for (gsize i = 0; i < G_N_ELEMENTS (points); i++) {
    g_autofree gchar *backup = g_strdup_printf ("%s-raced", targets[i]);
    ResolverRace race = {
      .expected_point = points[i],
      .target = targets[i],
      .backup = backup,
      .directory = TRUE,
    };
    wyl_fact_graph_resolver_set_checkpoint_for_test (&resolver,
        replace_at_resolver_checkpoint, &race);
    g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
            &locator, FALSE, &graph), ==, WYRELOG_E_POLICY);
    restore_raced_target (&race);
  }

  wyl_fact_graph_resolver_set_checkpoint_for_test (&resolver, NULL, NULL);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator, FALSE, &graph), ==, WYRELOG_E_OK);
  g_autofree gchar *file = g_build_filename (graph_path, "facts.duckdb",
      NULL);
  g_assert_true (g_file_set_contents (file, "db", 2, NULL));
  g_assert_cmpint (g_chmod (file, 0600), ==, 0);
  g_autofree gchar *backup = g_strdup_printf ("%s-raced", file);
  g_autofree gchar *outside = g_build_filename (root, "outside", NULL);
  g_assert_true (g_file_set_contents (outside, "outside", -1, NULL));
  g_assert_cmpint (g_chmod (outside, 0600), ==, 0);
  ResolverRace file_race = {
    .expected_point = "file-opened",
    .target = file,
    .backup = backup,
    .outside = outside,
  };
  graph.checkpoint = replace_at_resolver_checkpoint;
  graph.checkpoint_data = &file_race;
  gint fd = -1;
  g_assert_cmpint (wyl_fact_graph_directory_open_file (&graph,
          "facts.duckdb", FALSE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
  restore_raced_target (&file_race);

  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree (root);
}
#endif

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
  g_test_add_func ("/fact-graph-locator/metadata/owner-mode",
      test_owner_mode_contract);
  g_test_add_func ("/fact-graph-locator/locator/round-trip",
      test_locator_round_trip);
  g_test_add_func ("/fact-graph-locator/locator/reject-tampered",
      test_locator_rejects_manually_tampered_components);
#ifndef G_OS_WIN32
  g_test_add_func ("/fact-graph-locator/posix/create",
      test_posix_resolver_creates_validated_graph);
  g_test_add_func ("/fact-graph-locator/posix/symlinks",
      test_posix_resolver_rejects_symlinked_components);
  g_test_add_func ("/fact-graph-locator/posix/root-replacement",
      test_posix_resolver_rejects_root_replacement);
  g_test_add_func ("/fact-graph-locator/posix/type-mode",
      test_posix_resolver_rejects_wrong_type_and_mode);
  g_test_add_func ("/fact-graph-locator/posix/component-lengths",
      test_posix_resolver_component_length_boundaries);
  g_test_add_func ("/fact-graph-locator/posix/stage-publish",
      test_posix_resolver_stages_and_publishes_durably);
  g_test_add_func ("/fact-graph-locator/posix/stage-abort-substitution",
      test_posix_resolver_stage_abort_and_final_substitution);
  g_test_add_func ("/fact-graph-locator/posix/graph-replacement-file-mode",
      test_posix_resolver_rejects_graph_replacement_and_file_mode);
  g_test_add_func ("/fact-graph-locator/posix/relative-regular-nested",
      test_posix_resolver_opens_nested_relative_regular_file);
  g_test_add_func ("/fact-graph-locator/posix/relative-regular-rejects-aliases",
      test_posix_resolver_rejects_hardlink_and_aliases);
  g_test_add_func ("/fact-graph-locator/posix/no-overwrite-stage-replacement",
      test_posix_resolver_never_overwrites_final_or_replaced_stage);
  g_test_add_func ("/fact-graph-locator/posix/exact-stage-create-open-publish",
      test_posix_resolver_exact_stage_create_open_publish);
  g_test_add_func ("/fact-graph-locator/posix/exact-stage-conflicts-invalid",
      test_posix_resolver_exact_stage_rejects_conflicts_and_invalid_ids);
  g_test_add_func ("/fact-graph-locator/posix/exact-stage-adversarial",
      test_posix_resolver_exact_stage_adversarial_states);
  g_test_add_func ("/fact-graph-locator/posix/exact-stage-durability",
      test_posix_resolver_exact_stage_collision_and_durability);
  g_test_add_func ("/fact-graph-locator/posix/exact-stage-create-sync-failure",
      test_posix_resolver_exact_stage_create_sync_failure);
  g_test_add_func ("/fact-graph-locator/posix/publish-retry",
      test_posix_resolver_publish_retries_converge);
  g_test_add_func ("/fact-graph-locator/posix/stage-binding",
      test_posix_resolver_rejects_stage_tampering_and_cross_graph_use);
  g_test_add_func ("/fact-graph-locator/posix/checkpoint-replacements",
      test_posix_resolver_checkpoint_replacements_fail_closed);
#endif
  return g_test_run ();
}

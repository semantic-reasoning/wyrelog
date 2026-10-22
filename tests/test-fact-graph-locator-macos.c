/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _DARWIN_C_SOURCE
#include "test-exit-status.h"

#include <glib.h>
#include <glib/gstdio.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "fact/graph-locator-darwin-private.h"
#include "fact/graph-locator-private.h"

static const gchar operation_uuid[] =
    "01890f47-3c4b-7cc2-b8c4-dc0c0c070544";

typedef struct
{
  guint8 volume_uuid[16];
  guint64 file_id;
} DarwinIdentity;

typedef struct
{
  guint32 length;
  attribute_set_t returned;
  vol_capabilities_attr_t capabilities;
  uuid_t volume_uuid;
} VolumeAttributeBuffer;

typedef struct
{
  guint32 length;
  attribute_set_t returned;
  guint64 file_id;
} FileIdAttributeBuffer;

typedef struct
{
  gchar *root;
  gint root_fd;
  gint graph_fd;
  gint artifact_fd;
} ProbeFixture;

static gboolean
bytes_are_zero (const guint8 *bytes, gsize length)
{
  guint8 accumulator = 0;
  for (gsize i = 0; i < length; i++)
    accumulator |= bytes[i];
  return accumulator == 0;
}

static gboolean
write_exact (gint fd, const void *buffer, gsize length)
{
  const guint8 *cursor = buffer;
  while (length > 0) {
    ssize_t written = write (fd, cursor, length);
    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      return FALSE;
    cursor += written;
    length -= (gsize) written;
  }
  return TRUE;
}

static gboolean
read_exact (gint fd, void *buffer, gsize length)
{
  guint8 *cursor = buffer;
  while (length > 0) {
    ssize_t received = read (fd, cursor, length);
    if (received < 0 && errno == EINTR)
      continue;
    if (received <= 0)
      return FALSE;
    cursor += received;
    length -= (gsize) received;
  }
  return TRUE;
}

static gboolean
volume_contract_for_fd (gint fd, guint8 out_uuid[16], guint32 *out_supported)
{
  struct attrlist attributes = {
    .bitmapcount = ATTR_BIT_MAP_COUNT,
    .commonattr = ATTR_CMN_RETURNED_ATTRS,
    .volattr = ATTR_VOL_INFO | ATTR_VOL_CAPABILITIES | ATTR_VOL_UUID,
  };
  VolumeAttributeBuffer buffer = { 0 };

  if (fgetattrlist (fd, &attributes, &buffer, sizeof buffer, 0) != 0
      || buffer.length != sizeof buffer
      || (buffer.returned.commonattr & ATTR_CMN_RETURNED_ATTRS) == 0
      || (buffer.returned.volattr
      & (ATTR_VOL_CAPABILITIES | ATTR_VOL_UUID))
      != (ATTR_VOL_CAPABILITIES | ATTR_VOL_UUID))
    return FALSE;

  const guint32 required = VOL_CAP_FMT_64BIT_OBJECT_IDS
      | VOL_CAP_FMT_PATH_FROM_ID;
  guint32 valid =
      buffer.capabilities.valid[VOL_CAPABILITIES_FORMAT];
  guint32 supported =
      buffer.capabilities.capabilities[VOL_CAPABILITIES_FORMAT];
  if ((valid & required) != required || (supported & required) != required
      || bytes_are_zero (buffer.volume_uuid, sizeof buffer.volume_uuid))
    return FALSE;

  memcpy (out_uuid, buffer.volume_uuid, 16);
  if (out_supported != NULL)
    *out_supported = supported;
  return TRUE;
}

static gboolean
file_id_for_fd (gint fd, guint64 *out_file_id)
{
  struct attrlist attributes = {
    .bitmapcount = ATTR_BIT_MAP_COUNT,
    .commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_FILEID,
  };
  FileIdAttributeBuffer buffer = { 0 };

  if (fgetattrlist (fd, &attributes, &buffer, sizeof buffer, 0) != 0
      || buffer.length != sizeof buffer
      || (buffer.returned.commonattr
      & (ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_FILEID))
      != (ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_FILEID)
      || buffer.file_id == 0)
    return FALSE;

  *out_file_id = buffer.file_id;
  return TRUE;
}

static gboolean
identity_for_fd (gint fd, DarwinIdentity *out_identity,
    guint32 *out_supported)
{
  DarwinIdentity identity = { 0 };
  if (!volume_contract_for_fd (fd, identity.volume_uuid, out_supported)
      || !file_id_for_fd (fd, &identity.file_id))
    return FALSE;
  *out_identity = identity;
  return TRUE;
}

static gboolean
identity_equal (const DarwinIdentity *left, const DarwinIdentity *right)
{
  return left->file_id == right->file_id
         && memcmp (left->volume_uuid, right->volume_uuid,
             sizeof left->volume_uuid) == 0;
}

static void
assert_production_evidence (gint graph_fd, gint artifact_fd,
    const DarwinIdentity *graph, const DarwinIdentity *artifact)
{
  WylFactGraphDarwinOperationEvidence evidence = { 0 };
  g_assert_cmpint (wyl_fact_graph_darwin_evidence_capture (graph_fd,
      artifact_fd, operation_uuid, &evidence), ==, WYRELOG_E_OK);
  g_assert_cmpmem (evidence.bytes + 24, 16, graph->volume_uuid, 16);
  guint64 graph_be = GUINT64_TO_BE (graph->file_id);
  guint64 artifact_be = GUINT64_TO_BE (artifact->file_id);
  g_assert_cmpmem (evidence.bytes + 40, 8, &graph_be, 8);
  g_assert_cmpmem (evidence.bytes + 48, 8, &artifact_be, 8);
  g_assert_cmpint (wyl_fact_graph_darwin_evidence_compare (graph_fd,
      artifact_fd, operation_uuid, &evidence), ==, WYRELOG_E_OK);
}

static ProbeFixture
fixture_create (void)
{
  g_autoptr (GError) error = NULL;
  ProbeFixture fixture = {
    .root_fd = -1,
    .graph_fd = -1,
    .artifact_fd = -1,
  };

  fixture.root = g_dir_make_tmp ("wyl-macos-object-identity-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (fixture.root);
  g_assert_cmpint (g_chmod (fixture.root, 0700), ==, 0);

  fixture.root_fd = open (fixture.root,
          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  g_assert_cmpint (fixture.root_fd, >=, 0);
  g_assert_cmpint (mkdirat (fixture.root_fd, "graph", 0700), ==, 0);
  fixture.graph_fd = openat (fixture.root_fd, "graph",
          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  g_assert_cmpint (fixture.graph_fd, >=, 0);
  fixture.artifact_fd = openat (fixture.graph_fd, "facts.duckdb",
          O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
  g_assert_cmpint (fixture.artifact_fd, >=, 0);
  g_assert_true (write_exact (fixture.artifact_fd, "probe", 5));
  g_assert_cmpint (fsync (fixture.artifact_fd), ==, 0);
  g_assert_cmpint (fsync (fixture.graph_fd), ==, 0);
  return fixture;
}

static void
fixture_clear (ProbeFixture *fixture)
{
  if (fixture->artifact_fd >= 0)
    g_assert_cmpint (close (fixture->artifact_fd), ==, 0);
  if (fixture->graph_fd >= 0)
    g_assert_cmpint (close (fixture->graph_fd), ==, 0);
  if (fixture->root_fd >= 0)
    g_assert_cmpint (close (fixture->root_fd), ==, 0);
  g_assert_cmpint (g_rmdir (fixture->root), ==, 0);
  g_clear_pointer (&fixture->root, g_free);
  fixture->root_fd = -1;
  fixture->graph_fd = -1;
  fixture->artifact_fd = -1;
}

static void
test_hosted_volume_contract (void)
{
  ProbeFixture fixture = fixture_create ();
  DarwinIdentity graph = { 0 };
  DarwinIdentity artifact = { 0 };
  guint32 supported = 0;
  struct statfs filesystem = { 0 };

  g_assert_cmpint (fstatfs (fixture.graph_fd, &filesystem), ==, 0);
  g_assert_cmpstr (filesystem.f_fstypename, ==, "apfs");
  g_assert_true ((filesystem.f_flags & MNT_LOCAL) != 0);
  g_assert_true (identity_for_fd (fixture.graph_fd, &graph, &supported));
  g_assert_true (identity_for_fd (fixture.artifact_fd, &artifact, NULL));
  g_assert_cmpmem (graph.volume_uuid, sizeof graph.volume_uuid,
      artifact.volume_uuid, sizeof artifact.volume_uuid);
  g_assert_cmpuint (graph.file_id, !=, artifact.file_id);
  assert_production_evidence (fixture.graph_fd, fixture.artifact_fd, &graph,
      &artifact);

  g_test_message ("filesystem=%s format-capabilities=0x%08x "
      "identity=darwin-fileid64", filesystem.f_fstypename, supported);

  g_assert_cmpint (unlinkat (fixture.graph_fd, "facts.duckdb", 0), ==, 0);
  g_assert_cmpint (g_rmdir (fixture.root), !=, 0);
  g_assert_cmpint (unlinkat (fixture.root_fd, "graph", AT_REMOVEDIR), ==, 0);
  fixture_clear (&fixture);
}

typedef struct
{
  const gchar *fail_at;
  const gchar *replace_final_at;
  const gchar *replace_graph_at;
  WylFactGraphDirectory *graph;
  gboolean acted;
  GPtrArray *seen;
} DirectFinalCheckpoint;

static void
replace_final_with_foreign (DirectFinalCheckpoint *checkpoint)
{
  g_assert_nonnull (checkpoint->graph);
  g_assert_cmpint (unlinkat (checkpoint->graph->graph_fd, "facts.duckdb", 0),
      ==, 0);
  gint foreign = openat (checkpoint->graph->graph_fd, "facts.duckdb",
          O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
  g_assert_cmpint (foreign, >=, 0);
  g_assert_true (write_exact (foreign, "foreign", 7));
  g_assert_cmpint (fsync (foreign), ==, 0);
  g_assert_cmpint (close (foreign), ==, 0);
  checkpoint->acted = TRUE;
}

static void
replace_graph_with_foreign (DirectFinalCheckpoint *checkpoint)
{
  g_assert_nonnull (checkpoint->graph);
  g_assert_cmpint (renameat (checkpoint->graph->tenant_fd,
      checkpoint->graph->graph_component, checkpoint->graph->tenant_fd,
      "graph-held"), ==, 0);
  g_assert_cmpint (mkdirat (checkpoint->graph->tenant_fd,
      checkpoint->graph->graph_component, 0700), ==, 0);
  gint replacement = openat (checkpoint->graph->tenant_fd,
          checkpoint->graph->graph_component,
          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  g_assert_cmpint (replacement, >=, 0);
  gint marker = openat (replacement, "foreign.keep",
          O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
  g_assert_cmpint (marker, >=, 0);
  g_assert_true (write_exact (marker, "foreign", 7));
  g_assert_cmpint (fsync (marker), ==, 0);
  g_assert_cmpint (close (marker), ==, 0);
  g_assert_cmpint (fsync (replacement), ==, 0);
  g_assert_cmpint (close (replacement), ==, 0);
  g_assert_cmpint (fsync (checkpoint->graph->tenant_fd), ==, 0);
  checkpoint->acted = TRUE;
}

static wyrelog_error_t
direct_final_checkpoint (const gchar *point, gpointer user_data)
{
  DirectFinalCheckpoint *checkpoint = user_data;
  g_ptr_array_add (checkpoint->seen, g_strdup (point));
  if (g_strcmp0 (point, checkpoint->replace_final_at) == 0)
    replace_final_with_foreign (checkpoint);
  if (g_strcmp0 (point, checkpoint->replace_graph_at) == 0)
    replace_graph_with_foreign (checkpoint);
  return g_strcmp0 (point, checkpoint->fail_at) == 0 ?
         WYRELOG_E_IO : WYRELOG_E_OK;
}

static void
remove_tree (const gchar *path)
{
  g_autoptr (GDir) directory = g_dir_open (path, 0, NULL);
  if (directory != NULL) {
    const gchar *name;
    while ((name = g_dir_read_name (directory)) != NULL) {
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
make_resolver_root (const gchar *template_name)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *created = g_dir_make_tmp (template_name, &error);
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
run_direct_final_case (const gchar *fail_at)
{
  g_autofree gchar *root =
      make_resolver_root ("wyl-macos-direct-final-XXXXXX");

  DirectFinalCheckpoint checkpoint = {
    .fail_at = fail_at,
    .seen = g_ptr_array_new_with_free_func (g_free),
  };
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  wyl_fact_graph_resolver_set_checkpoint_for_test (&resolver,
      direct_final_checkpoint, &checkpoint);
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant-provision",
      "graph-provision"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver, &locator,
      TRUE, &graph), ==, WYRELOG_E_OK);
  g_ptr_array_set_size (checkpoint.seen, 0);

  WylFactGraphDarwinOperationEvidence evidence = { 0 };
  WylFactGraphRegularFile final = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  wyrelog_error_t rc =
      wyl_fact_graph_directory_create_darwin_provisioned_final (&graph,
          operation_uuid, &evidence, &final);
  g_assert_cmpint (rc, ==, fail_at == NULL ? WYRELOG_E_OK : WYRELOG_E_IO);

  g_autofree gchar *final_path =
      wyl_fact_graph_directory_descriptive_file (&graph, "facts.duckdb");
  g_autofree gchar *stage_basename =
      g_strdup_printf ("provision-%s.sqlite", operation_uuid);
  g_autofree gchar *stage_path =
      wyl_fact_graph_directory_descriptive_file (&graph, stage_basename);
  struct stat final_status;
  g_assert_cmpint (stat (final_path, &final_status), ==, 0);
  g_assert_true (S_ISREG (final_status.st_mode));
  g_assert_cmpuint (final_status.st_mode & 0777, ==, 0600);
  g_assert_cmpuint (final_status.st_nlink, ==, 1);
  g_assert_false (g_file_test (stage_path, G_FILE_TEST_EXISTS));

  if (fail_at == NULL) {
    const gchar *expected[] = {
      "darwin-final-created",
      "darwin-final-synced",
      "darwin-evidence-captured",
      "darwin-directory-synced",
    };
    g_assert_cmpuint (checkpoint.seen->len, ==, G_N_ELEMENTS (expected));
    for (gsize i = 0; i < G_N_ELEMENTS (expected); i++)
      g_assert_cmpstr (g_ptr_array_index (checkpoint.seen, i), ==, expected[i]);
    g_assert_cmpint (wyl_fact_graph_darwin_evidence_compare (graph.graph_fd,
        final.fd, operation_uuid, &evidence), ==, WYRELOG_E_OK);
    WylFactGraphDarwinOperationEvidence second_evidence = { 0 };
    WylFactGraphRegularFile second_final = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
    g_assert_cmpint (
      wyl_fact_graph_directory_create_darwin_provisioned_final (&graph,
      operation_uuid, &second_evidence, &second_final), ==, WYRELOG_E_BUSY);
    g_assert_cmpint (stat (final_path, &final_status), ==, 0);
    g_assert_cmpuint (final_status.st_nlink, ==, 1);
  } else {
    const WylFactGraphDarwinOperationEvidence zero = { 0 };
    g_assert_cmpmem (&evidence, sizeof evidence, &zero, sizeof zero);
    g_assert_cmpint (final.fd, ==, -1);
  }

  wyl_fact_graph_regular_file_clear (&final);
  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_graph_resolver_clear (&resolver);
  g_ptr_array_unref (checkpoint.seen);
  remove_tree (root);
}

static void
test_direct_final_contract (void)
{
  run_direct_final_case (NULL);
  const gchar *faults[] = {
    "darwin-final-created",
    "darwin-final-synced",
    "darwin-evidence-captured",
    "darwin-directory-synced",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (faults); i++)
    run_direct_final_case (faults[i]);
}

static void
run_direct_substitution_case (const gchar *action_at, gboolean replace_graph)
{
  g_autofree gchar *root =
      make_resolver_root ("wyl-macos-direct-substitution-XXXXXX");

  DirectFinalCheckpoint checkpoint = {
    .replace_final_at = replace_graph ? NULL : action_at,
    .replace_graph_at = replace_graph ? action_at : NULL,
    .seen = g_ptr_array_new_with_free_func (g_free),
  };
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  wyl_fact_graph_resolver_set_checkpoint_for_test (&resolver,
      direct_final_checkpoint, &checkpoint);
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant-provision",
      "graph-provision"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver, &locator,
      TRUE, &graph), ==, WYRELOG_E_OK);
  checkpoint.graph = &graph;
  g_ptr_array_set_size (checkpoint.seen, 0);

  WylFactGraphDarwinOperationEvidence evidence = { 0 };
  WylFactGraphRegularFile final = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  g_assert_cmpint (
    wyl_fact_graph_directory_create_darwin_provisioned_final (&graph,
    operation_uuid, &evidence, &final), ==, WYRELOG_E_POLICY);
  const WylFactGraphDarwinOperationEvidence zero = { 0 };
  g_assert_true (checkpoint.acted);
  g_assert_cmpmem (&evidence, sizeof evidence, &zero, sizeof zero);
  g_assert_cmpint (final.fd, ==, -1);

  if (replace_graph) {
    gint replacement = openat (graph.tenant_fd, graph.graph_component,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    g_assert_cmpint (replacement, >=, 0);
    gint marker = openat (replacement, "foreign.keep",
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    g_assert_cmpint (marker, >=, 0);
    g_assert_cmpint (close (marker), ==, 0);
    g_assert_cmpint (close (replacement), ==, 0);
    struct stat original_final;
    g_assert_cmpint (fstatat (graph.graph_fd, "facts.duckdb",
        &original_final, AT_SYMLINK_NOFOLLOW), ==, 0);
  } else {
    gint foreign = openat (graph.graph_fd, "facts.duckdb",
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    g_assert_cmpint (foreign, >=, 0);
    gchar contents[7];
    g_assert_true (read_exact (foreign, contents, sizeof contents));
    g_assert_cmpmem (contents, sizeof contents, "foreign", 7);
    g_assert_cmpint (close (foreign), ==, 0);
  }

  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_graph_resolver_clear (&resolver);
  g_ptr_array_unref (checkpoint.seen);
  remove_tree (root);
}

static void
test_direct_final_substitution (void)
{
  run_direct_substitution_case ("darwin-final-synced", FALSE);
  run_direct_substitution_case ("darwin-evidence-captured", FALSE);
  run_direct_substitution_case ("darwin-directory-synced", FALSE);
  run_direct_substitution_case ("darwin-evidence-captured", TRUE);
  run_direct_substitution_case ("darwin-directory-synced", TRUE);
}

static void
run_direct_preexisting_case (gboolean legacy_stage)
{
  g_autofree gchar *root =
      make_resolver_root ("wyl-macos-direct-preexisting-XXXXXX");

  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant-provision",
      "graph-provision"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver, &locator,
      TRUE, &graph), ==, WYRELOG_E_OK);

  g_autofree gchar *stage_basename =
      g_strdup_printf ("provision-%s.sqlite", operation_uuid);
  if (legacy_stage) {
    gint stage = openat (graph.graph_fd, stage_basename,
            O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    g_assert_cmpint (stage, >=, 0);
    g_assert_cmpint (close (stage), ==, 0);
  } else {
    g_assert_cmpint (symlinkat ("foreign-target", graph.graph_fd,
        "facts.duckdb"), ==, 0);
  }

  WylFactGraphDarwinOperationEvidence evidence = { 0 };
  WylFactGraphRegularFile final = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  g_assert_cmpint (
    wyl_fact_graph_directory_create_darwin_provisioned_final (&graph,
    operation_uuid, &evidence, &final), ==,
    legacy_stage ? WYRELOG_E_POLICY : WYRELOG_E_BUSY);
  const WylFactGraphDarwinOperationEvidence zero = { 0 };
  g_assert_cmpmem (&evidence, sizeof evidence, &zero, sizeof zero);
  g_assert_cmpint (final.fd, ==, -1);
  if (legacy_stage) {
    struct stat stage_status;
    g_assert_cmpint (fstatat (graph.graph_fd, stage_basename, &stage_status,
        AT_SYMLINK_NOFOLLOW), ==, 0);
    g_assert_cmpint (fstatat (graph.graph_fd, "facts.duckdb", &stage_status,
        AT_SYMLINK_NOFOLLOW), ==, -1);
    g_assert_cmpint (errno, ==, ENOENT);
  } else {
    gchar target[32] = { 0 };
    g_assert_cmpint (readlinkat (graph.graph_fd, "facts.duckdb", target,
        sizeof target), ==, 14);
    g_assert_cmpstr (target, ==, "foreign-target");
  }

  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_graph_resolver_clear (&resolver);
  remove_tree (root);
}

static void
test_direct_final_preexisting_entries (void)
{
  run_direct_preexisting_case (FALSE);
  run_direct_preexisting_case (TRUE);
}

static void
test_descriptor_stability_and_replacement (void)
{
  ProbeFixture fixture = fixture_create ();
  DarwinIdentity graph = { 0 };
  DarwinIdentity artifact = { 0 };
  DarwinIdentity reopened = { 0 };
  DarwinIdentity child = { 0 };
  DarwinIdentity replacement = { 0 };
  DarwinIdentity replacement_graph = { 0 };

  g_assert_true (identity_for_fd (fixture.graph_fd, &graph, NULL));
  g_assert_true (identity_for_fd (fixture.artifact_fd, &artifact, NULL));

  g_assert_cmpint (close (fixture.artifact_fd), ==, 0);
  fixture.artifact_fd = -1;

  gint reopened_fd = openat (fixture.graph_fd, "facts.duckdb",
          O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  g_assert_cmpint (reopened_fd, >=, 0);
  g_assert_true (identity_for_fd (reopened_fd, &reopened, NULL));
  g_assert_true (identity_equal (&artifact, &reopened));
  g_assert_cmpint (close (reopened_fd), ==, 0);

  g_assert_cmpint (renameat (fixture.graph_fd, "facts.duckdb",
      fixture.graph_fd, "renamed.duckdb"), ==, 0);
  reopened_fd = openat (fixture.graph_fd, "renamed.duckdb",
          O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  g_assert_cmpint (reopened_fd, >=, 0);
  g_assert_true (identity_for_fd (reopened_fd, &reopened, NULL));
  g_assert_true (identity_equal (&artifact, &reopened));
  g_assert_cmpint (close (reopened_fd), ==, 0);
  g_assert_cmpint (renameat (fixture.graph_fd, "renamed.duckdb",
      fixture.graph_fd, "facts.duckdb"), ==, 0);

  gint pipe_fds[2] = { -1, -1 };
  g_assert_cmpint (pipe (pipe_fds), ==, 0);
  pid_t child_pid = fork ();
  g_assert_cmpint (child_pid, >=, 0);
  if (child_pid == 0) {
    (void) close (pipe_fds[0]);
    gint child_fd = openat (fixture.graph_fd, "facts.duckdb",
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    DarwinIdentity child_identity = { 0 };
    gboolean ok = child_fd >= 0
        && identity_for_fd (child_fd, &child_identity, NULL)
        && write_exact (pipe_fds[1], &child_identity, sizeof child_identity);
    if (child_fd >= 0)
      (void) close (child_fd);
    (void) close (pipe_fds[1]);
    WYL_TEST_EXIT(ok ? 0 : 1);
  }
  g_assert_cmpint (close (pipe_fds[1]), ==, 0);
  g_assert_true (read_exact (pipe_fds[0], &child, sizeof child));
  g_assert_cmpint (close (pipe_fds[0]), ==, 0);
  gint child_status = 0;
  g_assert_cmpint (waitpid (child_pid, &child_status, 0), ==, child_pid);
  g_assert_true (WIFEXITED (child_status));
  g_assert_cmpint (WEXITSTATUS (child_status), ==, 0);
  g_assert_true (identity_equal (&artifact, &child));

  g_assert_cmpint (unlinkat (fixture.graph_fd, "facts.duckdb", 0), ==, 0);
  gint replacement_fd = openat (fixture.graph_fd, "facts.duckdb",
          O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
  g_assert_cmpint (replacement_fd, >=, 0);
  g_assert_true (identity_for_fd (replacement_fd, &replacement, NULL));
  g_assert_cmpmem (artifact.volume_uuid, sizeof artifact.volume_uuid,
      replacement.volume_uuid, sizeof replacement.volume_uuid);
  g_assert_cmpuint (artifact.file_id, !=, replacement.file_id);
  g_assert_cmpint (close (replacement_fd), ==, 0);
  g_assert_cmpint (unlinkat (fixture.graph_fd, "facts.duckdb", 0), ==, 0);

  g_assert_cmpint (close (fixture.graph_fd), ==, 0);
  fixture.graph_fd = -1;
  g_assert_cmpint (unlinkat (fixture.root_fd, "graph", AT_REMOVEDIR), ==, 0);
  g_assert_cmpint (mkdirat (fixture.root_fd, "graph", 0700), ==, 0);
  gint replacement_graph_fd = openat (fixture.root_fd, "graph",
          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  g_assert_cmpint (replacement_graph_fd, >=, 0);
  g_assert_true (identity_for_fd (replacement_graph_fd, &replacement_graph,
      NULL));
  g_assert_cmpmem (graph.volume_uuid, sizeof graph.volume_uuid,
      replacement_graph.volume_uuid, sizeof replacement_graph.volume_uuid);
  g_assert_cmpuint (graph.file_id, !=, replacement_graph.file_id);
  g_assert_cmpint (close (replacement_graph_fd), ==, 0);
  g_assert_cmpint (unlinkat (fixture.root_fd, "graph", AT_REMOVEDIR), ==, 0);
  fixture_clear (&fixture);
}

/* ------------------------------------------------------------------ */
/* provisioned restore witness (#1303 U3)                             */
/* ------------------------------------------------------------------ */

static const gchar witness_restore_uuid[] =
    "01890f47-3c4b-7cc2-b8c4-dc0c0c070546";
static const gchar witness_other_operation_uuid[] =
    "01890f47-3c4b-7cc2-b8c4-dc0c0c070548";

/* One ADR 0006 final per graph directory: the canonical name only, one
 * link, and the evidence captured from the held descriptors.  The old main
 * identity is the dev/ino the restore journal would pin. */
typedef struct
{
  gchar *root;
  WylFactGraphResolver resolver;
  WylFactGraphLocator locator;
  WylFactGraphDirectory graph;
  WylFactGraphDarwinOperationEvidence evidence;
  WylFactArtifactInventoryIdentity old_main;
  gchar *legacy_stage;
} WitnessFixture;

static void
witness_fixture_init (WitnessFixture *fixture, const gchar *graph_id,
    const gchar *provisioning_uuid)
{
  memset (fixture, 0, sizeof *fixture);
  fixture->root = make_resolver_root ("wyl-macos-restore-witness-XXXXXX");
  fixture->resolver = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
  fixture->graph = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_assert_cmpint (wyl_fact_graph_resolver_open (fixture->root,
      &fixture->resolver), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&fixture->locator,
      "tenant-restore", graph_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&fixture->resolver,
      &fixture->locator, TRUE, &fixture->graph), ==, WYRELOG_E_OK);
  WylFactGraphRegularFile final = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  g_assert_cmpint (wyl_fact_graph_directory_create_darwin_provisioned_final
        (&fixture->graph, provisioning_uuid, &fixture->evidence, &final), ==,
      WYRELOG_E_OK);
  g_assert_true (write_exact (final.fd, "provisioned", 11));
  struct stat status;
  g_assert_cmpint (fstat (final.fd, &status), ==, 0);
  fixture->old_main = (WylFactArtifactInventoryIdentity) {
    .domain = (guint64) status.st_dev, .object = (guint64) status.st_ino,
  };
  wyl_fact_graph_regular_file_clear (&final);
  fixture->legacy_stage = g_strdup_printf ("provision-%s.sqlite",
          provisioning_uuid);
}

static void
witness_fixture_clear (WitnessFixture *fixture)
{
  wyl_fact_graph_directory_clear (&fixture->graph);
  wyl_fact_graph_locator_clear (&fixture->locator);
  wyl_fact_graph_resolver_clear (&fixture->resolver);
  remove_tree (fixture->root);
  g_clear_pointer (&fixture->root, g_free);
  g_clear_pointer (&fixture->legacy_stage, g_free);
}

static wyrelog_error_t
witness_open (WitnessFixture *fixture,
    const WylFactGraphDarwinOperationEvidence *evidence,
    const WylFactArtifactInventoryIdentity *old_main,
    WylFactGraphProvisionedRestoreSlot slot,
    WylFactGraphProvisionedRestoreWitness **out_witness)
{
  return wyl_fact_graph_provisioned_restore_witness_open_with_evidence
           (&fixture->graph, operation_uuid, evidence, witness_restore_uuid,
             old_main, slot, out_witness);
}

static void
assert_witness_open_refused (WitnessFixture *fixture,
    const WylFactGraphDarwinOperationEvidence *evidence,
    const WylFactArtifactInventoryIdentity *old_main,
    WylFactGraphProvisionedRestoreSlot slot, wyrelog_error_t expected)
{
  WylFactGraphProvisionedRestoreWitness *witness = NULL;
  g_assert_cmpint (witness_open (fixture, evidence, old_main, slot,
      &witness), ==, expected);
  g_assert_null (witness);
}

static WylFactGraphProvisionedRestoreWitness *
witness_open_ready (WitnessFixture *fixture)
{
  WylFactGraphProvisionedRestoreWitness *witness = NULL;
  g_assert_cmpint (witness_open (fixture, &fixture->evidence,
      &fixture->old_main, WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN,
      &witness), ==, WYRELOG_E_OK);
  g_assert_nonnull (witness);
  g_assert_cmpint (wyl_fact_graph_provisioned_restore_witness_revalidate
        (witness, &fixture->graph), ==, WYRELOG_E_OK);
  return witness;
}

static void
witness_create_extra_file (WitnessFixture *fixture, const gchar *name,
    mode_t mode)
{
  gint fd = openat (fixture->graph.graph_fd, name,
          O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, mode);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (write_exact (fd, "other", 5));
  g_assert_cmpint (close (fd), ==, 0);
}

static void
test_provisioned_restore_witness_evidence (void)
{
  WitnessFixture f;
  witness_fixture_init (&f, "graph-restore", operation_uuid);
  const guint8 *artifact_id = f.evidence.bytes + 48;
  guint64 evidenced_object = 0;
  for (gsize i = 0; i < 8; i++)
    evidenced_object = (evidenced_object << 8) | artifact_id[i];
  /* The journal pins st_ino; the evidence pins ATTR_CMN_FILEID.  APFS reports
   * the same number through both, which is what lets one witness satisfy
   * both the Linux-shaped identity pin and the Darwin evidence. */
  g_assert_cmpuint (evidenced_object, ==, f.old_main.object);

  /* The name-only opener never proves a Darwin main. */
  WylFactGraphProvisionedRestoreWitness *witness = NULL;
  g_assert_cmpint (wyl_fact_graph_provisioned_restore_witness_open (&f.graph,
      operation_uuid, witness_restore_uuid, &f.old_main,
      WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN, &witness), ==,
      WYRELOG_E_POLICY);
  g_assert_null (witness);

  /* Before any RETAIN nothing sits at this restore's rollback name, so the
   * rollback slot has no object to witness.  DUAL_COMPANION is never a
   * single-witness slot. */
  assert_witness_open_refused (&f, &f.evidence, &f.old_main,
      WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK,
      WYRELOG_E_NOT_FOUND);
  assert_witness_open_refused (&f, &f.evidence, &f.old_main,
      WYL_FACT_GRAPH_PROVISIONED_RESTORE_DUAL_COMPANION, WYRELOG_E_INVALID);
  assert_witness_open_refused (&f, NULL, &f.old_main,
      WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN, WYRELOG_E_INVALID);

  /* Positive: open, revalidate twice, free. */
  witness = witness_open_ready (&f);
  g_assert_cmpint (wyl_fact_graph_provisioned_restore_witness_revalidate
        (witness, &f.graph), ==, WYRELOG_E_OK);
  wyl_fact_graph_provisioned_restore_witness_free (witness);

  /* Evidence that does not describe this object. */
  WylFactGraphDarwinOperationEvidence flipped = f.evidence;
  flipped.bytes[55] ^= 0x01u;
  assert_witness_open_refused (&f, &flipped, &f.old_main,
      WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN, WYRELOG_E_POLICY);
  WitnessFixture foreign_operation;
  witness_fixture_init (&foreign_operation, "graph-foreign-operation",
      witness_other_operation_uuid);
  assert_witness_open_refused (&f, &foreign_operation.evidence, &f.old_main,
      WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN, WYRELOG_E_POLICY);
  witness_fixture_clear (&foreign_operation);
  WitnessFixture foreign_graph;
  witness_fixture_init (&foreign_graph, "graph-foreign", operation_uuid);
  assert_witness_open_refused (&f, &foreign_graph.evidence, &f.old_main,
      WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN, WYRELOG_E_POLICY);
  /* A witness revalidated against another graph directory is refused. */
  witness = witness_open_ready (&f);
  g_assert_cmpint (wyl_fact_graph_provisioned_restore_witness_revalidate
        (witness, &foreign_graph.graph), ==, WYRELOG_E_POLICY);
  wyl_fact_graph_provisioned_restore_witness_free (witness);
  witness_fixture_clear (&foreign_graph);

  /* An identity pin that does not match the evidenced object. */
  WylFactArtifactInventoryIdentity shifted = f.old_main;
  shifted.object += 1;
  assert_witness_open_refused (&f, &f.evidence, &shifted,
      WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN, WYRELOG_E_POLICY);

  /* Hard link: a second name on the object fails both open and revalidate. */
  g_assert_cmpint (linkat (f.graph.graph_fd, "facts.duckdb", f.graph.graph_fd,
      "extra", 0), ==, 0);
  assert_witness_open_refused (&f, &f.evidence, &f.old_main,
      WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN, WYRELOG_E_POLICY);
  g_assert_cmpint (unlinkat (f.graph.graph_fd, "extra", 0), ==, 0);
  witness = witness_open_ready (&f);
  g_assert_cmpint (linkat (f.graph.graph_fd, "facts.duckdb", f.graph.graph_fd,
      "extra", 0), ==, 0);
  g_assert_cmpint (wyl_fact_graph_provisioned_restore_witness_revalidate
        (witness, &f.graph), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (unlinkat (f.graph.graph_fd, "extra", 0), ==, 0);
  g_assert_cmpint (wyl_fact_graph_provisioned_restore_witness_revalidate
        (witness, &f.graph), ==, WYRELOG_E_OK);
  wyl_fact_graph_provisioned_restore_witness_free (witness);

  /* The legacy provisioning stage name must stay absent on Darwin. */
  witness_create_extra_file (&f, f.legacy_stage, 0600);
  assert_witness_open_refused (&f, &f.evidence, &f.old_main,
      WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN, WYRELOG_E_POLICY);
  g_assert_cmpint (unlinkat (f.graph.graph_fd, f.legacy_stage, 0), ==, 0);
  witness = witness_open_ready (&f);
  witness_create_extra_file (&f, f.legacy_stage, 0600);
  g_assert_cmpint (wyl_fact_graph_provisioned_restore_witness_revalidate
        (witness, &f.graph), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (unlinkat (f.graph.graph_fd, f.legacy_stage, 0), ==, 0);
  g_assert_cmpint (wyl_fact_graph_provisioned_restore_witness_revalidate
        (witness, &f.graph), ==, WYRELOG_E_OK);
  wyl_fact_graph_provisioned_restore_witness_free (witness);

  /* Mode: 0644 is refused at open and after open.  An owner mismatch is not
   * testable without privileges; the same check covers it. */
  g_assert_cmpint (fchmodat (f.graph.graph_fd, "facts.duckdb", 0644,
      AT_SYMLINK_NOFOLLOW), ==, 0);
  assert_witness_open_refused (&f, &f.evidence, &f.old_main,
      WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN, WYRELOG_E_POLICY);
  g_assert_cmpint (fchmodat (f.graph.graph_fd, "facts.duckdb", 0600,
      AT_SYMLINK_NOFOLLOW), ==, 0);
  witness = witness_open_ready (&f);
  g_assert_cmpint (fchmodat (f.graph.graph_fd, "facts.duckdb", 0644,
      AT_SYMLINK_NOFOLLOW), ==, 0);
  g_assert_cmpint (wyl_fact_graph_provisioned_restore_witness_revalidate
        (witness, &f.graph), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fchmodat (f.graph.graph_fd, "facts.duckdb", 0600,
      AT_SYMLINK_NOFOLLOW), ==, 0);
  g_assert_cmpint (wyl_fact_graph_provisioned_restore_witness_revalidate
        (witness, &f.graph), ==, WYRELOG_E_OK);
  wyl_fact_graph_provisioned_restore_witness_free (witness);

  /* Substitution: a new object under the canonical name is refused at open,
   * whichever identity the caller pins, and after open; a rename-away with
   * no replacement reports the absence rather than a policy breach. */
  g_assert_cmpint (renameat (f.graph.graph_fd, "facts.duckdb",
      f.graph.graph_fd, "parked"), ==, 0);
  witness_create_extra_file (&f, "facts.duckdb", 0600);
  struct stat substitute;
  g_assert_cmpint (fstatat (f.graph.graph_fd, "facts.duckdb", &substitute,
      AT_SYMLINK_NOFOLLOW), ==, 0);
  WylFactArtifactInventoryIdentity substitute_identity = {
    .domain = (guint64) substitute.st_dev,
    .object = (guint64) substitute.st_ino,
  };
  assert_witness_open_refused (&f, &f.evidence, &substitute_identity,
      WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN, WYRELOG_E_POLICY);
  assert_witness_open_refused (&f, &f.evidence, &f.old_main,
      WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN, WYRELOG_E_POLICY);
  g_assert_cmpint (unlinkat (f.graph.graph_fd, "facts.duckdb", 0), ==, 0);
  g_assert_cmpint (renameat (f.graph.graph_fd, "parked", f.graph.graph_fd,
      "facts.duckdb"), ==, 0);
  witness = witness_open_ready (&f);
  g_assert_cmpint (renameat (f.graph.graph_fd, "facts.duckdb",
      f.graph.graph_fd, "parked"), ==, 0);
  g_assert_cmpint (wyl_fact_graph_provisioned_restore_witness_revalidate
        (witness, &f.graph), ==, WYRELOG_E_NOT_FOUND);
  witness_create_extra_file (&f, "facts.duckdb", 0600);
  g_assert_cmpint (wyl_fact_graph_provisioned_restore_witness_revalidate
        (witness, &f.graph), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (unlinkat (f.graph.graph_fd, "facts.duckdb", 0), ==, 0);
  g_assert_cmpint (renameat (f.graph.graph_fd, "parked", f.graph.graph_fd,
      "facts.duckdb"), ==, 0);
  g_assert_cmpint (wyl_fact_graph_provisioned_restore_witness_revalidate
        (witness, &f.graph), ==, WYRELOG_E_OK);
  wyl_fact_graph_provisioned_restore_witness_free (witness);

  /* Symlink under the canonical name. */
  g_assert_cmpint (renameat (f.graph.graph_fd, "facts.duckdb",
      f.graph.graph_fd, "parked"), ==, 0);
  g_assert_cmpint (symlinkat ("parked", f.graph.graph_fd, "facts.duckdb"),
      ==, 0);
  assert_witness_open_refused (&f, &f.evidence, &f.old_main,
      WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN, WYRELOG_E_POLICY);
  g_assert_cmpint (unlinkat (f.graph.graph_fd, "facts.duckdb", 0), ==, 0);
  g_assert_cmpint (renameat (f.graph.graph_fd, "parked", f.graph.graph_fd,
      "facts.duckdb"), ==, 0);
  witness = witness_open_ready (&f);
  g_assert_cmpint (renameat (f.graph.graph_fd, "facts.duckdb",
      f.graph.graph_fd, "parked"), ==, 0);
  g_assert_cmpint (symlinkat ("parked", f.graph.graph_fd, "facts.duckdb"),
      ==, 0);
  g_assert_cmpint (wyl_fact_graph_provisioned_restore_witness_revalidate
        (witness, &f.graph), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (unlinkat (f.graph.graph_fd, "facts.duckdb", 0), ==, 0);
  g_assert_cmpint (renameat (f.graph.graph_fd, "parked", f.graph.graph_fd,
      "facts.duckdb"), ==, 0);
  g_assert_cmpint (wyl_fact_graph_provisioned_restore_witness_revalidate
        (witness, &f.graph), ==, WYRELOG_E_OK);
  wyl_fact_graph_provisioned_restore_witness_free (witness);

  witness_fixture_clear (&f);
}

/* The old main after RETAIN: the same ADR 0006 final, renamed to this
 * restore's operation-derived rollback name (#1303 U5-1). */
static void
witness_rename (WitnessFixture *fixture, const gchar *from, const gchar *to)
{
  g_assert_cmpint (renameat (fixture->graph.graph_fd, from,
      fixture->graph.graph_fd, to), ==, 0);
}

static void
assert_rollback_revalidate (WitnessFixture *fixture,
    WylFactGraphProvisionedRestoreWitness *witness, wyrelog_error_t expected)
{
  g_assert_cmpint (wyl_fact_graph_provisioned_restore_witness_revalidate
        (witness, &fixture->graph), ==, expected);
}

static void
test_provisioned_restore_witness_rollback (void)
{
  const WylFactGraphProvisionedRestoreSlot rollback_slot =
      WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK;
  WitnessFixture f;
  witness_fixture_init (&f, "graph-rollback", operation_uuid);
  g_autofree gchar *rollback = g_strdup_printf ("restore-%s.duckdb.superseded",
          witness_restore_uuid);
  g_autofree gchar *other_rollback =
      g_strdup_printf ("restore-%s.duckdb.superseded",
          witness_other_operation_uuid);
  witness_rename (&f, "facts.duckdb", rollback);

  /* READY_MAIN has nothing at the canonical name any more. */
  assert_witness_open_refused (&f, &f.evidence, &f.old_main,
      WYL_FACT_GRAPH_PROVISIONED_RESTORE_READY_MAIN, WYRELOG_E_NOT_FOUND);

  /* Positive with the main absent: open, revalidate twice, free. */
  WylFactGraphProvisionedRestoreWitness *witness = NULL;
  g_assert_cmpint (witness_open (&f, &f.evidence, &f.old_main, rollback_slot,
      &witness), ==, WYRELOG_E_OK);
  assert_rollback_revalidate (&f, witness, WYRELOG_E_OK);
  assert_rollback_revalidate (&f, witness, WYRELOG_E_OK);

  /* A different one-link main appearing later, as PUBLISH makes it, keeps
   * the witness valid. */
  witness_create_extra_file (&f, "facts.duckdb", 0600);
  assert_rollback_revalidate (&f, witness, WYRELOG_E_OK);
  wyl_fact_graph_provisioned_restore_witness_free (witness);
  witness = NULL;
  g_assert_cmpint (witness_open (&f, &f.evidence, &f.old_main, rollback_slot,
      &witness), ==, WYRELOG_E_OK);

  /* The main must be a one-link 0600 regular file. */
  g_assert_cmpint (linkat (f.graph.graph_fd, "facts.duckdb", f.graph.graph_fd,
      "main-link", 0), ==, 0);
  assert_rollback_revalidate (&f, witness, WYRELOG_E_POLICY);
  assert_witness_open_refused (&f, &f.evidence, &f.old_main, rollback_slot,
      WYRELOG_E_POLICY);
  g_assert_cmpint (unlinkat (f.graph.graph_fd, "main-link", 0), ==, 0);
  g_assert_cmpint (fchmodat (f.graph.graph_fd, "facts.duckdb", 0644,
      AT_SYMLINK_NOFOLLOW), ==, 0);
  assert_rollback_revalidate (&f, witness, WYRELOG_E_POLICY);
  g_assert_cmpint (fchmodat (f.graph.graph_fd, "facts.duckdb", 0600,
      AT_SYMLINK_NOFOLLOW), ==, 0);
  assert_rollback_revalidate (&f, witness, WYRELOG_E_OK);
  g_assert_cmpint (unlinkat (f.graph.graph_fd, "facts.duckdb", 0), ==, 0);
  g_assert_cmpint (symlinkat (rollback, f.graph.graph_fd, "facts.duckdb"),
      ==, 0);
  assert_rollback_revalidate (&f, witness, WYRELOG_E_POLICY);
  assert_witness_open_refused (&f, &f.evidence, &f.old_main, rollback_slot,
      WYRELOG_E_POLICY);
  g_assert_cmpint (unlinkat (f.graph.graph_fd, "facts.duckdb", 0), ==, 0);
  g_assert_cmpint (mkdirat (f.graph.graph_fd, "facts.duckdb", 0700), ==, 0);
  assert_rollback_revalidate (&f, witness, WYRELOG_E_POLICY);
  g_assert_cmpint (unlinkat (f.graph.graph_fd, "facts.duckdb", AT_REMOVEDIR),
      ==, 0);
  assert_rollback_revalidate (&f, witness, WYRELOG_E_OK);

  /* The main must not be the old object: a second name for it refuses on
   * the held link count, and moving it back to the canonical name leaves
   * nothing at the rollback name. */
  g_assert_cmpint (linkat (f.graph.graph_fd, rollback, f.graph.graph_fd,
      "facts.duckdb", 0), ==, 0);
  assert_rollback_revalidate (&f, witness, WYRELOG_E_POLICY);
  assert_witness_open_refused (&f, &f.evidence, &f.old_main, rollback_slot,
      WYRELOG_E_POLICY);
  g_assert_cmpint (unlinkat (f.graph.graph_fd, "facts.duckdb", 0), ==, 0);
  witness_rename (&f, rollback, "facts.duckdb");
  assert_rollback_revalidate (&f, witness, WYRELOG_E_NOT_FOUND);
  witness_rename (&f, "facts.duckdb", rollback);
  assert_rollback_revalidate (&f, witness, WYRELOG_E_OK);

  /* Only this restore's rollback name is witnessed: the same object under
   * another restore's rollback name is not looked up. */
  witness_rename (&f, rollback, other_rollback);
  assert_rollback_revalidate (&f, witness, WYRELOG_E_NOT_FOUND);
  assert_witness_open_refused (&f, &f.evidence, &f.old_main, rollback_slot,
      WYRELOG_E_NOT_FOUND);
  witness_rename (&f, other_rollback, rollback);
  assert_rollback_revalidate (&f, witness, WYRELOG_E_OK);

  /* A second link on the old object, the legacy stage name, and mode 0644
   * each refuse at open and after open. */
  g_assert_cmpint (linkat (f.graph.graph_fd, rollback, f.graph.graph_fd,
      "extra", 0), ==, 0);
  assert_rollback_revalidate (&f, witness, WYRELOG_E_POLICY);
  assert_witness_open_refused (&f, &f.evidence, &f.old_main, rollback_slot,
      WYRELOG_E_POLICY);
  g_assert_cmpint (unlinkat (f.graph.graph_fd, "extra", 0), ==, 0);
  witness_create_extra_file (&f, f.legacy_stage, 0600);
  assert_rollback_revalidate (&f, witness, WYRELOG_E_POLICY);
  assert_witness_open_refused (&f, &f.evidence, &f.old_main, rollback_slot,
      WYRELOG_E_POLICY);
  g_assert_cmpint (unlinkat (f.graph.graph_fd, f.legacy_stage, 0), ==, 0);
  g_assert_cmpint (fchmodat (f.graph.graph_fd, rollback, 0644,
      AT_SYMLINK_NOFOLLOW), ==, 0);
  assert_rollback_revalidate (&f, witness, WYRELOG_E_POLICY);
  assert_witness_open_refused (&f, &f.evidence, &f.old_main, rollback_slot,
      WYRELOG_E_POLICY);
  g_assert_cmpint (fchmodat (f.graph.graph_fd, rollback, 0600,
      AT_SYMLINK_NOFOLLOW), ==, 0);
  assert_rollback_revalidate (&f, witness, WYRELOG_E_OK);

  /* A substituted object at the rollback name refuses whichever identity
   * the caller pins: the journal pin by dev/ino, its own by evidence. */
  witness_rename (&f, rollback, "parked");
  witness_create_extra_file (&f, rollback, 0600);
  struct stat substitute;
  g_assert_cmpint (fstatat (f.graph.graph_fd, rollback, &substitute,
      AT_SYMLINK_NOFOLLOW), ==, 0);
  WylFactArtifactInventoryIdentity substitute_identity = {
    .domain = (guint64) substitute.st_dev,
    .object = (guint64) substitute.st_ino,
  };
  assert_rollback_revalidate (&f, witness, WYRELOG_E_POLICY);
  assert_witness_open_refused (&f, &f.evidence, &f.old_main, rollback_slot,
      WYRELOG_E_POLICY);
  assert_witness_open_refused (&f, &f.evidence, &substitute_identity,
      rollback_slot, WYRELOG_E_POLICY);
  g_assert_cmpint (unlinkat (f.graph.graph_fd, rollback, 0), ==, 0);
  witness_rename (&f, "parked", rollback);
  assert_rollback_revalidate (&f, witness, WYRELOG_E_OK);
  wyl_fact_graph_provisioned_restore_witness_free (witness);

  /* Evidence and pins that do not describe this object. */
  WylFactGraphDarwinOperationEvidence flipped = f.evidence;
  flipped.bytes[55] ^= 0x01u;
  assert_witness_open_refused (&f, &flipped, &f.old_main, rollback_slot,
      WYRELOG_E_POLICY);
  WylFactArtifactInventoryIdentity shifted = f.old_main;
  shifted.object += 1;
  assert_witness_open_refused (&f, &f.evidence, &shifted, rollback_slot,
      WYRELOG_E_POLICY);
  WitnessFixture foreign;
  witness_fixture_init (&foreign, "graph-rollback-foreign", operation_uuid);
  assert_witness_open_refused (&f, &foreign.evidence, &f.old_main,
      rollback_slot, WYRELOG_E_POLICY);
  witness = NULL;
  g_assert_cmpint (witness_open (&f, &f.evidence, &f.old_main, rollback_slot,
      &witness), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_provisioned_restore_witness_revalidate
        (witness, &foreign.graph), ==, WYRELOG_E_POLICY);
  wyl_fact_graph_provisioned_restore_witness_free (witness);
  witness_fixture_clear (&foreign);
  /* An owner mismatch is not testable without privileges; the same check
   * covers it. */
  witness_fixture_clear (&f);
}

typedef struct
{
  gint graph_fd;
  const gchar *rollback;
  guint acted;
} RollbackRace;

static wyrelog_error_t
rollback_race_checkpoint (const gchar *point, gpointer user_data)
{
  RollbackRace *race = user_data;
  if (g_strcmp0 (point, "darwin-restore-witness-rollback-bound") == 0
      && race->acted++ == 0)
    g_assert_cmpint (renameat (race->graph_fd, race->rollback, race->graph_fd,
        "facts.duckdb"), ==, 0);
  return WYRELOG_E_OK;
}

/* The rollback name moving onto an absent or staged `facts.duckdb` between
 * the pass's two name lookups keeps one link; only the pass's dev/ino
 * inequality refuses it (#1303 U5-2, ADR 0006 "Restore witness"). */
static void
test_provisioned_restore_witness_rollback_race (void)
{
  g_autofree gchar *rollback = g_strdup_printf ("restore-%s.duckdb.superseded",
          witness_restore_uuid);
  for (guint staged = 0; staged < 2; staged++) {
    WitnessFixture f;
    witness_fixture_init (&f, "graph-rollback-race", operation_uuid);
    witness_rename (&f, "facts.duckdb", rollback);
    if (staged)
      witness_create_extra_file (&f, "facts.duckdb", 0600);
    WylFactGraphProvisionedRestoreWitness *witness = NULL;
    g_assert_cmpint (witness_open (&f, &f.evidence, &f.old_main,
        WYL_FACT_GRAPH_PROVISIONED_RESTORE_RETAINED_ROLLBACK, &witness), ==,
        WYRELOG_E_OK);
    RollbackRace race = {
      .graph_fd = f.graph.graph_fd,
      .rollback = rollback,
    };
    f.graph.checkpoint = rollback_race_checkpoint;
    f.graph.checkpoint_data = &race;
    assert_rollback_revalidate (&f, witness, WYRELOG_E_POLICY);
    g_assert_cmpuint (race.acted, ==, 1);
    f.graph.checkpoint = NULL;
    f.graph.checkpoint_data = NULL;
    wyl_fact_graph_provisioned_restore_witness_free (witness);
    witness_fixture_clear (&f);
  }
}

/* ------------------------------------------------------------------ */

static const gchar replacement_uuid[] =
    "01890f47-3c4b-7cc2-b8c4-dc0c0c07054a";

/* Three full 64 KiB read chunks and a partial tail. */
#define REPLACEMENT_BYTES (3u * 65536u + 17u)
#define REPLACEMENT_READ "darwin-replacement-main-read"
#define REPLACEMENT_CHUNK "darwin-replacement-main-read-chunk"

typedef enum
{
  REPLACEMENT_RECORD,
  REPLACEMENT_SUBSTITUTE,
  REPLACEMENT_LINK,
  REPLACEMENT_CHMOD,
  REPLACEMENT_CREATE_LEGACY,
  REPLACEMENT_RENAME_AWAY,
  REPLACEMENT_SWAP_GRAPH,
  REPLACEMENT_FAIL,
  REPLACEMENT_TRUNCATE,
  REPLACEMENT_APPEND,
  REPLACEMENT_OVERWRITE,
} ReplacementAction;

/* The post-SYNC_PUBLISH_DIR shape of a macOS restore (#1303 U5-6): the old
 * provisioned main retained at this restore's rollback name, and the restore
 * stage the journal pinned published at `facts.duckdb`.  The checkpoint
 * records every point and performs one action at `act_at`. */
typedef struct
{
  gchar *root;
  WylFactGraphResolver resolver;
  WylFactGraphLocator locator;
  WylFactGraphDirectory graph;
  WylFactGraphDarwinOperationEvidence old_evidence;
  WylFactArtifactInventoryIdentity old_main;
  WylFactArtifactInventoryIdentity staged;
  guint64 logical_bytes;
  guint8 *content;
  gchar *checksum;
  gchar *legacy;
  gchar *rollback;
  GPtrArray *seen;
  const gchar *act_at;
  ReplacementAction action;
  guint hits;
} ReplacementFixture;

static WylFactArtifactInventoryIdentity
replacement_write_file (ReplacementFixture *fixture, const gchar *name)
{
  gint fd = openat (fixture->graph.graph_fd, name,
          O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (write_exact (fd, fixture->content, fixture->logical_bytes));
  g_assert_cmpint (fsync (fd), ==, 0);
  struct stat status;
  g_assert_cmpint (fstat (fd, &status), ==, 0);
  g_assert_cmpint (close (fd), ==, 0);
  return (WylFactArtifactInventoryIdentity) {
           .domain = (guint64) status.st_dev,
           .object = (guint64) status.st_ino,
  };
}

static void
replacement_pwrite (ReplacementFixture *fixture, guint8 value, guint64 offset)
{
  gint fd = openat (fixture->graph.graph_fd, "facts.duckdb",
          O_RDWR | O_CLOEXEC | O_NOFOLLOW);
  g_assert_cmpint (fd, >=, 0);
  g_assert_cmpint (pwrite (fd, &value, 1, (off_t) offset), ==, 1);
  g_assert_cmpint (close (fd), ==, 0);
}

static void
replacement_rename (ReplacementFixture *fixture, const gchar *from,
    const gchar *to)
{
  g_assert_cmpint (renameat (fixture->graph.graph_fd, from,
      fixture->graph.graph_fd, to), ==, 0);
}

static void
replacement_unlink (ReplacementFixture *fixture, const gchar *name)
{
  g_assert_cmpint (unlinkat (fixture->graph.graph_fd, name, 0), ==, 0);
}

static wyrelog_error_t
replacement_checkpoint (const gchar *point, gpointer user_data)
{
  ReplacementFixture *fixture = user_data;
  g_ptr_array_add (fixture->seen, g_strdup (point));
  if (g_strcmp0 (point, fixture->act_at) != 0 || fixture->hits > 0)
    return WYRELOG_E_OK;
  fixture->hits++;
  gint graph_fd = fixture->graph.graph_fd;
  if (fixture->action == REPLACEMENT_SUBSTITUTE) {
    replacement_rename (fixture, "facts.duckdb", "parked");
    (void) replacement_write_file (fixture, "facts.duckdb");
  } else if (fixture->action == REPLACEMENT_LINK) {
    g_assert_cmpint (linkat (graph_fd, "facts.duckdb", graph_fd, "extra", 0),
        ==, 0);
  } else if (fixture->action == REPLACEMENT_CHMOD) {
    g_assert_cmpint (fchmodat (graph_fd, "facts.duckdb", 0644,
        AT_SYMLINK_NOFOLLOW), ==, 0);
  } else if (fixture->action == REPLACEMENT_CREATE_LEGACY) {
    (void) replacement_write_file (fixture, fixture->legacy);
  } else if (fixture->action == REPLACEMENT_RENAME_AWAY) {
    replacement_rename (fixture, "facts.duckdb", "parked");
  } else if (fixture->action == REPLACEMENT_SWAP_GRAPH) {
    DirectFinalCheckpoint swap = {.graph = &fixture->graph };
    replace_graph_with_foreign (&swap);
  } else if (fixture->action == REPLACEMENT_FAIL) {
    return WYRELOG_E_IO;
  } else if (fixture->action == REPLACEMENT_TRUNCATE) {
    gint fd = openat (graph_fd, "facts.duckdb",
            O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    g_assert_cmpint (fd, >=, 0);
    g_assert_cmpint (ftruncate (fd, 1), ==, 0);
    g_assert_cmpint (close (fd), ==, 0);
  } else if (fixture->action == REPLACEMENT_APPEND) {
    replacement_pwrite (fixture, 0x5a, fixture->logical_bytes);
  } else if (fixture->action == REPLACEMENT_OVERWRITE) {
    replacement_pwrite (fixture, (guint8) (fixture->content[0] ^ 0xffu), 0);
  }
  return WYRELOG_E_OK;
}

static void
replacement_fixture_init (ReplacementFixture *fixture, const gchar *graph_id)
{
  memset (fixture, 0, sizeof *fixture);
  fixture->root = make_resolver_root ("wyl-macos-restore-replacement-XXXXXX");
  fixture->resolver = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
  fixture->graph = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_assert_cmpint (wyl_fact_graph_resolver_open (fixture->root,
      &fixture->resolver), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&fixture->locator,
      "tenant-restore", graph_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&fixture->resolver,
      &fixture->locator, TRUE, &fixture->graph), ==, WYRELOG_E_OK);

  /* RETAIN: the old ADR 0006 final now sits at the rollback name. */
  WylFactGraphRegularFile final = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  g_assert_cmpint (wyl_fact_graph_directory_create_darwin_provisioned_final
        (&fixture->graph, operation_uuid, &fixture->old_evidence, &final), ==,
      WYRELOG_E_OK);
  g_assert_true (write_exact (final.fd, "provisioned", 11));
  struct stat status;
  g_assert_cmpint (fstat (final.fd, &status), ==, 0);
  fixture->old_main = (WylFactArtifactInventoryIdentity) {
    .domain = (guint64) status.st_dev, .object = (guint64) status.st_ino,
  };
  wyl_fact_graph_regular_file_clear (&final);
  fixture->rollback = g_strdup_printf ("restore-%s.duckdb.superseded",
          witness_restore_uuid);
  replacement_rename (fixture, "facts.duckdb", fixture->rollback);

  /* The restore stage, created exclusively and pinned by the journal.  The
   * checksum is computed here, independently of the locator. */
  fixture->logical_bytes = REPLACEMENT_BYTES;
  fixture->content = g_malloc (REPLACEMENT_BYTES);
  for (guint i = 0; i < REPLACEMENT_BYTES; i++)
    fixture->content[i] = (guint8) ((i * 31u + 7u) & 0xffu);
  g_autofree gchar *stage = g_strdup_printf ("restore-%s.duckdb",
          witness_restore_uuid);
  fixture->staged = replacement_write_file (fixture, stage);
  g_autofree gchar *hex = g_compute_checksum_for_data (G_CHECKSUM_SHA256,
          fixture->content, REPLACEMENT_BYTES);
  fixture->checksum = g_strconcat ("sha256:", hex, NULL);

  /* PUBLISH keeps the stage's device and inode; SYNC_PUBLISH_DIR. */
  replacement_rename (fixture, stage, "facts.duckdb");
  g_assert_cmpint (fsync (fixture->graph.graph_fd), ==, 0);
  fixture->legacy = g_strdup_printf ("provision-%s.sqlite", replacement_uuid);

  fixture->seen = g_ptr_array_new_with_free_func (g_free);
  fixture->graph.checkpoint = replacement_checkpoint;
  fixture->graph.checkpoint_data = fixture;
}

static void
replacement_fixture_clear (ReplacementFixture *fixture)
{
  fixture->graph.checkpoint = NULL;
  fixture->graph.checkpoint_data = NULL;
  wyl_fact_graph_directory_clear (&fixture->graph);
  wyl_fact_graph_locator_clear (&fixture->locator);
  wyl_fact_graph_resolver_clear (&fixture->resolver);
  remove_tree (fixture->root);
  g_clear_pointer (&fixture->root, g_free);
  g_clear_pointer (&fixture->content, g_free);
  g_clear_pointer (&fixture->checksum, g_free);
  g_clear_pointer (&fixture->legacy, g_free);
  g_clear_pointer (&fixture->rollback, g_free);
  g_clear_pointer (&fixture->seen, g_ptr_array_unref);
}

static guint
replacement_seen (ReplacementFixture *fixture, const gchar *point)
{
  guint count = 0;
  for (guint i = 0; i < fixture->seen->len; i++)
    if (g_strcmp0 (g_ptr_array_index (fixture->seen, i), point) == 0)
      count++;
  return count;
}

static guint
open_fd_count (void)
{
  g_autoptr (GDir) fds = g_dir_open ("/dev/fd", 0, NULL);
  g_assert_nonnull (fds);
  guint count = 0;
  while (g_dir_read_name (fds) != NULL)
    count++;
  return count;
}

static wyrelog_error_t
replacement_capture (ReplacementFixture *fixture,
    const WylFactArtifactInventoryIdentity *staged, guint64 logical_bytes,
    const gchar *checksum, WylFactGraphDarwinOperationEvidence *out_evidence)
{
  g_ptr_array_set_size (fixture->seen, 0);
  return wyl_fact_graph_directory_capture_darwin_replacement_evidence
           (&fixture->graph, replacement_uuid, staged, logical_bytes,
             checksum, out_evidence);
}

static wyrelog_error_t
replacement_compare (ReplacementFixture *fixture, const gchar *uuid,
    const WylFactArtifactInventoryIdentity *staged, guint64 logical_bytes,
    const gchar *checksum, const WylFactGraphDarwinOperationEvidence *expected)
{
  g_ptr_array_set_size (fixture->seen, 0);
  return wyl_fact_graph_directory_compare_darwin_replacement_evidence
           (&fixture->graph, uuid, staged, logical_bytes, checksum, expected);
}

/* A refusal leaves the output zeroed and closes every descriptor it
 * opened. */
static void
assert_capture_refused (ReplacementFixture *fixture,
    const WylFactArtifactInventoryIdentity *staged, guint64 logical_bytes,
    const gchar *checksum, wyrelog_error_t expected)
{
  WylFactGraphDarwinOperationEvidence evidence;
  memset (&evidence, 0xa5, sizeof evidence);
  guint fds = open_fd_count ();
  g_assert_cmpint (replacement_capture (fixture, staged, logical_bytes,
      checksum, &evidence), ==, expected);
  g_assert_cmpuint (open_fd_count (), ==, fds);
  g_assert_true (bytes_are_zero (evidence.bytes, sizeof evidence.bytes));
}

static gchar *
replacement_checksum_flipped (const gchar *checksum)
{
  gchar *flipped = g_strdup (checksum);
  gsize last = strlen (flipped) - 1;
  flipped[last] = flipped[last] == '0' ? '1' : '0';
  return flipped;
}

static guint64
replacement_artifact_file_id (const WylFactGraphDarwinOperationEvidence *e)
{
  guint64 value = 0;
  for (gsize i = 48; i < 56; i++)
    value = (value << 8) | e->bytes[i];
  return value;
}

static void
test_restore_replacement_evidence_capture (void)
{
  ReplacementFixture f;
  replacement_fixture_init (&f, "graph-replacement");
  WylFactGraphDarwinOperationEvidence evidence = { 0 };
  g_assert_cmpint (replacement_capture (&f, &f.staged, f.logical_bytes,
      f.checksum, &evidence), ==, WYRELOG_E_OK);

  /* One reopen, the cheap pins, four read chunks, then the capture. */
  g_assert_cmpuint (f.seen->len, ==, 6);
  g_assert_cmpstr (g_ptr_array_index (f.seen, 0), ==, "file-opened");
  for (guint i = 1; i < 5; i++)
    g_assert_cmpstr (g_ptr_array_index (f.seen, i), ==, REPLACEMENT_CHUNK);
  g_assert_cmpstr (g_ptr_array_index (f.seen, 5), ==, REPLACEMENT_READ);

  /* Version 1 evidence bound to the replacement UUID, not to the old
   * provisioning operation, naming the journal-pinned object. */
  WylFactGraphDarwinOperationEvidence decoded = { 0 };
  g_assert_cmpint (wyl_fact_graph_darwin_evidence_decode (evidence.bytes,
      sizeof evidence.bytes, replacement_uuid, &decoded), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_darwin_evidence_decode (evidence.bytes,
      sizeof evidence.bytes, operation_uuid, &decoded), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (replacement_artifact_file_id (&evidence), ==,
      f.staged.object);
  g_assert_false (wyl_fact_graph_darwin_evidence_equal (&evidence,
      &f.old_evidence));
  gint fd = openat (f.graph.graph_fd, "facts.duckdb",
          O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  g_assert_cmpint (fd, >=, 0);
  g_assert_cmpint (wyl_fact_graph_darwin_evidence_compare (f.graph.graph_fd,
      fd, replacement_uuid, &evidence), ==, WYRELOG_E_OK);
  g_assert_cmpint (close (fd), ==, 0);

  WylFactGraphDarwinOperationEvidence second = { 0 };
  g_assert_cmpint (replacement_capture (&f, &f.staged, f.logical_bytes,
      f.checksum, &second), ==, WYRELOG_E_OK);
  g_assert_true (wyl_fact_graph_darwin_evidence_equal (&evidence, &second));

  /* Nothing on disk moved: the retained old main still carries its own
   * evidence, the main holds the staged bytes, and no legacy name exists. */
  fd = openat (f.graph.graph_fd, f.rollback, O_RDONLY | O_CLOEXEC
          | O_NOFOLLOW);
  g_assert_cmpint (fd, >=, 0);
  g_assert_cmpint (wyl_fact_graph_darwin_evidence_compare (f.graph.graph_fd,
      fd, operation_uuid, &f.old_evidence), ==, WYRELOG_E_OK);
  g_assert_cmpint (close (fd), ==, 0);
  fd = openat (f.graph.graph_fd, "facts.duckdb",
          O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  g_assert_cmpint (fd, >=, 0);
  g_autofree guint8 *bytes = g_malloc (REPLACEMENT_BYTES + 1);
  g_assert_true (read_exact (fd, bytes, REPLACEMENT_BYTES));
  g_assert_cmpint (read (fd, bytes + REPLACEMENT_BYTES, 1), ==, 0);
  g_assert_cmpint (close (fd), ==, 0);
  g_assert_cmpmem (bytes, REPLACEMENT_BYTES, f.content, REPLACEMENT_BYTES);
  struct stat status;
  g_assert_cmpint (fstatat (f.graph.graph_fd, f.legacy, &status,
      AT_SYMLINK_NOFOLLOW), !=, 0);
  g_assert_cmpint (errno, ==, ENOENT);
  replacement_fixture_clear (&f);
}

static void
test_restore_replacement_evidence_invalid (void)
{
  ReplacementFixture f;
  replacement_fixture_init (&f, "graph-replacement-invalid");
  WylFactArtifactInventoryIdentity bad;
  WylFactGraphDarwinOperationEvidence evidence;
  /* Any call reaching the reopen would count a hit here. */
  f.act_at = "file-opened";

  memset (&evidence, 0xa5, sizeof evidence);
  g_assert_cmpint (wyl_fact_graph_directory_capture_darwin_replacement_evidence
        (NULL, replacement_uuid, &f.staged, f.logical_bytes, f.checksum,
      &evidence), ==, WYRELOG_E_INVALID);
  g_assert_true (bytes_are_zero (evidence.bytes, sizeof evidence.bytes));
  assert_capture_refused (&f, NULL, f.logical_bytes, f.checksum,
      WYRELOG_E_INVALID);
  bad = f.staged;
  bad.domain = 0;
  assert_capture_refused (&f, &bad, f.logical_bytes, f.checksum,
      WYRELOG_E_INVALID);
  bad = f.staged;
  bad.object = 0;
  assert_capture_refused (&f, &bad, f.logical_bytes, f.checksum,
      WYRELOG_E_INVALID);
  bad = f.staged;
  bad.object_width = 1;
  assert_capture_refused (&f, &bad, f.logical_bytes, f.checksum,
      WYRELOG_E_INVALID);
  bad = f.staged;
  bad.object_bytes[0] = 1;
  assert_capture_refused (&f, &bad, f.logical_bytes, f.checksum,
      WYRELOG_E_INVALID);
  assert_capture_refused (&f, &f.staged, 0, f.checksum, WYRELOG_E_INVALID);
  assert_capture_refused (&f, &f.staged, G_MAXUINT64, f.checksum,
      WYRELOG_E_INVALID);
  assert_capture_refused (&f, &f.staged, (guint64) G_MAXINT64 + 1u,
      f.checksum, WYRELOG_E_INVALID);
  assert_capture_refused (&f, &f.staged, f.logical_bytes, NULL,
      WYRELOG_E_INVALID);
  g_autofree gchar *short_checksum = g_strndup (f.checksum, 70);
  assert_capture_refused (&f, &f.staged, f.logical_bytes, short_checksum,
      WYRELOG_E_INVALID);
  g_autofree gchar *long_checksum = g_strconcat (f.checksum, "0", NULL);
  assert_capture_refused (&f, &f.staged, f.logical_bytes, long_checksum,
      WYRELOG_E_INVALID);
  g_autofree gchar *upper_hex = g_ascii_strup (f.checksum + 7, -1);
  g_autofree gchar *upper = g_strconcat ("sha256:", upper_hex, NULL);
  g_assert_cmpstr (upper, !=, f.checksum);
  assert_capture_refused (&f, &f.staged, f.logical_bytes, upper,
      WYRELOG_E_INVALID);
  g_autofree gchar *sha512 = g_strconcat ("sha512:", f.checksum + 7, NULL);
  assert_capture_refused (&f, &f.staged, f.logical_bytes, sha512,
      WYRELOG_E_INVALID);
  g_autofree gchar *upper_uuid = g_ascii_strup (replacement_uuid, -1);
  memset (&evidence, 0xa5, sizeof evidence);
  g_assert_cmpint (wyl_fact_graph_directory_capture_darwin_replacement_evidence
        (&f.graph, upper_uuid, &f.staged, f.logical_bytes, f.checksum,
      &evidence), ==, WYRELOG_E_INVALID);
  g_assert_true (bytes_are_zero (evidence.bytes, sizeof evidence.bytes));
  /* Canonical but not UUIDv7: refused before any reopen (the legacy name
   * derivation rejects it too). */
  g_assert_cmpint (wyl_fact_graph_directory_capture_darwin_replacement_evidence
        (&f.graph, "01890f47-3c4b-4cc2-b8c4-dc0c0c07054a", &f.staged,
      f.logical_bytes, f.checksum, &evidence), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_graph_directory_capture_darwin_replacement_evidence
        (&f.graph, replacement_uuid, &f.staged, f.logical_bytes, f.checksum,
      NULL), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (replacement_compare (&f, replacement_uuid, &f.staged,
      f.logical_bytes, f.checksum, NULL), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (replacement_compare (&f, replacement_uuid, &bad,
      f.logical_bytes, f.checksum, &f.old_evidence), ==, WYRELOG_E_INVALID);
  /* None of these reached the reopen. */
  g_assert_cmpuint (f.hits, ==, 0);
  f.act_at = NULL;

  /* The fixture itself is acceptable. */
  g_assert_cmpint (replacement_capture (&f, &f.staged, f.logical_bytes,
      f.checksum, &evidence), ==, WYRELOG_E_OK);
  replacement_fixture_clear (&f);
}

/* Pin mismatches before the call.  The nlink 2, mode 0644 and symlink
 * cases are refused by the reopen itself; the pass-level link and mode
 * checks are reached only by the LINK and CHMOD race actions, so those
 * stay. */
static void
test_restore_replacement_evidence_pins (void)
{
  ReplacementFixture f;
  replacement_fixture_init (&f, "graph-replacement-pins");
  WylFactArtifactInventoryIdentity shifted;

  /* A remount or reboot may change the device number; it is compared, not
   * relaxed (ADR 0006).  The cheap pins refuse before any read. */
  shifted = f.staged;
  shifted.domain ^= 1;
  assert_capture_refused (&f, &shifted, f.logical_bytes, f.checksum,
      WYRELOG_E_POLICY);
  g_assert_cmpuint (replacement_seen (&f, "file-opened"), ==, 1);
  g_assert_cmpuint (replacement_seen (&f, REPLACEMENT_CHUNK), ==, 0);
  shifted = f.staged;
  shifted.object += 1;
  assert_capture_refused (&f, &shifted, f.logical_bytes, f.checksum,
      WYRELOG_E_POLICY);
  g_assert_cmpuint (replacement_seen (&f, REPLACEMENT_CHUNK), ==, 0);
  assert_capture_refused (&f, &f.staged, f.logical_bytes + 1, f.checksum,
      WYRELOG_E_POLICY);
  g_assert_cmpuint (replacement_seen (&f, REPLACEMENT_CHUNK), ==, 0);
  assert_capture_refused (&f, &f.staged, f.logical_bytes - 1, f.checksum,
      WYRELOG_E_POLICY);
  g_assert_cmpuint (replacement_seen (&f, REPLACEMENT_CHUNK), ==, 0);

  /* Content: a different checksum, or the same pins over changed bytes. */
  g_autofree gchar *flipped = replacement_checksum_flipped (f.checksum);
  assert_capture_refused (&f, &f.staged, f.logical_bytes, flipped,
      WYRELOG_E_POLICY);
  g_assert_cmpuint (replacement_seen (&f, REPLACEMENT_CHUNK), ==, 4);
  g_assert_cmpuint (replacement_seen (&f, REPLACEMENT_READ), ==, 0);
  replacement_pwrite (&f, (guint8) (f.content[70000] ^ 0xffu), 70000);
  assert_capture_refused (&f, &f.staged, f.logical_bytes, f.checksum,
      WYRELOG_E_POLICY);
  g_assert_cmpuint (replacement_seen (&f, REPLACEMENT_CHUNK), ==, 4);
  replacement_pwrite (&f, f.content[70000], 70000);

  /* Link count, mode and symlink: refused by the reopen. */
  g_assert_cmpint (linkat (f.graph.graph_fd, "facts.duckdb", f.graph.graph_fd,
      "extra", 0), ==, 0);
  assert_capture_refused (&f, &f.staged, f.logical_bytes, f.checksum,
      WYRELOG_E_POLICY);
  replacement_unlink (&f, "extra");
  g_assert_cmpint (fchmodat (f.graph.graph_fd, "facts.duckdb", 0644,
      AT_SYMLINK_NOFOLLOW), ==, 0);
  assert_capture_refused (&f, &f.staged, f.logical_bytes, f.checksum,
      WYRELOG_E_POLICY);
  g_assert_cmpint (fchmodat (f.graph.graph_fd, "facts.duckdb", 0600,
      AT_SYMLINK_NOFOLLOW), ==, 0);
  replacement_rename (&f, "facts.duckdb", "parked");
  g_assert_cmpint (symlinkat ("parked", f.graph.graph_fd, "facts.duckdb"),
      ==, 0);
  assert_capture_refused (&f, &f.staged, f.logical_bytes, f.checksum,
      WYRELOG_E_POLICY);
  replacement_unlink (&f, "facts.duckdb");

  /* An absent main is reported as absent. */
  assert_capture_refused (&f, &f.staged, f.logical_bytes, f.checksum,
      WYRELOG_E_NOT_FOUND);
  replacement_rename (&f, "parked", "facts.duckdb");

  /* The replacement's legacy stage name is refused before any reopen. */
  (void) replacement_write_file (&f, f.legacy);
  assert_capture_refused (&f, &f.staged, f.logical_bytes, f.checksum,
      WYRELOG_E_POLICY);
  g_assert_cmpuint (replacement_seen (&f, "file-opened"), ==, 0);
  replacement_unlink (&f, f.legacy);

  /* A same-bytes substitute under the journal's pins.  The same substitute
   * under its own pins is not a refusal case: choosing pins is the
   * journal's job, and capture accepts matching pins by design. */
  replacement_rename (&f, "facts.duckdb", "parked");
  (void) replacement_write_file (&f, "facts.duckdb");
  assert_capture_refused (&f, &f.staged, f.logical_bytes, f.checksum,
      WYRELOG_E_POLICY);
  replacement_unlink (&f, "facts.duckdb");
  replacement_rename (&f, "parked", "facts.duckdb");

  /* Another graph directory holding the same bytes. */
  ReplacementFixture foreign;
  replacement_fixture_init (&foreign, "graph-replacement-foreign");
  assert_capture_refused (&foreign, &f.staged, f.logical_bytes, f.checksum,
      WYRELOG_E_POLICY);
  replacement_fixture_clear (&foreign);

  WylFactGraphDarwinOperationEvidence evidence = { 0 };
  g_assert_cmpint (replacement_capture (&f, &f.staged, f.logical_bytes,
      f.checksum, &evidence), ==, WYRELOG_E_OK);
  replacement_fixture_clear (&f);
}

/* One change during the proof, each from a fresh fixture.  The read point
 * follows the capture, so these also cover the capture's window. */
static void
test_restore_replacement_evidence_race (void)
{
  static const struct
  {
    const gchar *at;
    ReplacementAction action;
    wyrelog_error_t expected;
  } cases[] = {
    {REPLACEMENT_READ, REPLACEMENT_SUBSTITUTE, WYRELOG_E_POLICY},
    {REPLACEMENT_READ, REPLACEMENT_LINK, WYRELOG_E_POLICY},
    {REPLACEMENT_READ, REPLACEMENT_CHMOD, WYRELOG_E_POLICY},
    {REPLACEMENT_READ, REPLACEMENT_CREATE_LEGACY, WYRELOG_E_POLICY},
    {REPLACEMENT_READ, REPLACEMENT_RENAME_AWAY, WYRELOG_E_POLICY},
    {REPLACEMENT_READ, REPLACEMENT_SWAP_GRAPH, WYRELOG_E_POLICY},
    {REPLACEMENT_READ, REPLACEMENT_FAIL, WYRELOG_E_IO},
    {REPLACEMENT_CHUNK, REPLACEMENT_FAIL, WYRELOG_E_IO},
    {REPLACEMENT_CHUNK, REPLACEMENT_TRUNCATE, WYRELOG_E_POLICY},
    {REPLACEMENT_CHUNK, REPLACEMENT_APPEND, WYRELOG_E_POLICY},
    {REPLACEMENT_CHUNK, REPLACEMENT_OVERWRITE, WYRELOG_E_POLICY},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++) {
    ReplacementFixture f;
    replacement_fixture_init (&f, "graph-replacement-race");
    f.act_at = cases[i].at;
    f.action = cases[i].action;
    g_test_message ("race case %" G_GSIZE_FORMAT, i);
    assert_capture_refused (&f, &f.staged, f.logical_bytes, f.checksum,
        cases[i].expected);
    g_assert_cmpuint (f.hits, ==, 1);
    /* The first short read refuses; nothing past it is hashed. */
    if (cases[i].action == REPLACEMENT_TRUNCATE)
      g_assert_cmpuint (replacement_seen (&f, REPLACEMENT_CHUNK), ==, 1);
    replacement_fixture_clear (&f);
  }
}

static void
test_restore_replacement_evidence_compare (void)
{
  ReplacementFixture f;
  replacement_fixture_init (&f, "graph-replacement-compare");
  WylFactGraphDarwinOperationEvidence evidence = { 0 };
  g_assert_cmpint (replacement_capture (&f, &f.staged, f.logical_bytes,
      f.checksum, &evidence), ==, WYRELOG_E_OK);
  for (guint i = 0; i < 2; i++)
    g_assert_cmpint (replacement_compare (&f, replacement_uuid, &f.staged,
        f.logical_bytes, f.checksum, &evidence), ==, WYRELOG_E_OK);

  WylFactGraphDarwinOperationEvidence altered = evidence;
  altered.bytes[55] ^= 0x01u;
  g_assert_cmpint (replacement_compare (&f, replacement_uuid, &f.staged,
      f.logical_bytes, f.checksum, &altered), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (replacement_compare (&f, replacement_uuid, &f.staged,
      f.logical_bytes, f.checksum, &f.old_evidence), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (replacement_compare (&f, witness_other_operation_uuid,
      &f.staged, f.logical_bytes, f.checksum, &evidence), ==,
      WYRELOG_E_POLICY);

  /* Evidence for the same replacement UUID naming another object: every
   * pin and the full read pass, and the evidence comparison refuses. */
  ReplacementFixture foreign;
  replacement_fixture_init (&foreign, "graph-replacement-compare-foreign");
  WylFactGraphDarwinOperationEvidence foreign_evidence = { 0 };
  g_assert_cmpint (replacement_capture (&foreign, &foreign.staged,
      foreign.logical_bytes, foreign.checksum, &foreign_evidence), ==,
      WYRELOG_E_OK);
  replacement_fixture_clear (&foreign);
  g_assert_cmpint (replacement_compare (&f, replacement_uuid, &f.staged,
      f.logical_bytes, f.checksum, &foreign_evidence), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (replacement_seen (&f, REPLACEMENT_CHUNK), ==, 4);
  g_assert_cmpuint (replacement_seen (&f, REPLACEMENT_READ), ==, 0);

  /* The journal pins are still required alongside matching evidence. */
  WylFactArtifactInventoryIdentity shifted = f.staged;
  shifted.domain ^= 1;
  g_assert_cmpint (replacement_compare (&f, replacement_uuid, &shifted,
      f.logical_bytes, f.checksum, &evidence), ==, WYRELOG_E_POLICY);
  g_autofree gchar *flipped = replacement_checksum_flipped (f.checksum);
  g_assert_cmpint (replacement_compare (&f, replacement_uuid, &f.staged,
      f.logical_bytes, flipped, &evidence), ==, WYRELOG_E_POLICY);

  /* Compare never recaptures: a same-bytes substitute under its own pins
   * would be captured, yet the recorded evidence refuses it. */
  replacement_rename (&f, "facts.duckdb", "parked");
  WylFactArtifactInventoryIdentity substitute =
      replacement_write_file (&f, "facts.duckdb");
  WylFactGraphDarwinOperationEvidence substitute_evidence = { 0 };
  g_assert_cmpint (replacement_capture (&f, &substitute, f.logical_bytes,
      f.checksum, &substitute_evidence), ==, WYRELOG_E_OK);
  g_assert_cmpint (replacement_compare (&f, replacement_uuid, &substitute,
      f.logical_bytes, f.checksum, &evidence), ==, WYRELOG_E_POLICY);
  replacement_unlink (&f, "facts.duckdb");
  replacement_rename (&f, "parked", "facts.duckdb");
  g_assert_cmpint (replacement_compare (&f, replacement_uuid, &f.staged,
      f.logical_bytes, f.checksum, &evidence), ==, WYRELOG_E_OK);
  replacement_fixture_clear (&f);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/macos-object-identity/hosted-volume-contract",
      test_hosted_volume_contract);
  g_test_add_func ("/fact/macos-object-identity/stability-and-replacement",
      test_descriptor_stability_and_replacement);
  g_test_add_func ("/fact/macos-object-identity/direct-final-contract",
      test_direct_final_contract);
  g_test_add_func ("/fact/macos-object-identity/direct-final-substitution",
      test_direct_final_substitution);
  g_test_add_func (
    "/fact/macos-object-identity/direct-final-preexisting-entries",
    test_direct_final_preexisting_entries);
  g_test_add_func (
    "/fact/macos-object-identity/provisioned-restore-witness",
    test_provisioned_restore_witness_evidence);
  g_test_add_func (
    "/fact/macos-object-identity/provisioned-restore-witness-rollback",
    test_provisioned_restore_witness_rollback);
  g_test_add_func (
    "/fact/macos-object-identity/provisioned-restore-witness-rollback-race",
    test_provisioned_restore_witness_rollback_race);
  g_test_add_func (
    "/fact/macos-object-identity/restore-replacement-evidence-capture",
    test_restore_replacement_evidence_capture);
  g_test_add_func (
    "/fact/macos-object-identity/restore-replacement-evidence-invalid",
    test_restore_replacement_evidence_invalid);
  g_test_add_func (
    "/fact/macos-object-identity/restore-replacement-evidence-pins",
    test_restore_replacement_evidence_pins);
  g_test_add_func (
    "/fact/macos-object-identity/restore-replacement-evidence-race",
    test_restore_replacement_evidence_race);
  g_test_add_func (
    "/fact/macos-object-identity/restore-replacement-evidence-compare",
    test_restore_replacement_evidence_compare);
  return wyl_test_normalize_exit_status (g_test_run ());
}

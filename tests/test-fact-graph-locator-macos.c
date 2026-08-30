/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _DARWIN_C_SOURCE

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
    _exit (ok ? 0 : 1);
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
  return g_test_run ();
}

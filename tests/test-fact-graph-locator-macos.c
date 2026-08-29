/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _DARWIN_C_SOURCE

#include <glib.h>
#include <glib/gstdio.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <uuid/uuid.h>

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

  g_test_message ("filesystem=%s format-capabilities=0x%08x "
      "identity=darwin-fileid64", filesystem.f_fstypename, supported);

  g_assert_cmpint (unlinkat (fixture.graph_fd, "facts.duckdb", 0), ==, 0);
  g_assert_cmpint (g_rmdir (fixture.root), !=, 0);
  g_assert_cmpint (unlinkat (fixture.root_fd, "graph", AT_REMOVEDIR), ==, 0);
  fixture_clear (&fixture);
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
  return g_test_run ();
}

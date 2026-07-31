/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _POSIX_C_SOURCE 200809L
/* Apple SDKs hide O_NOFOLLOW under strict POSIX modes unless Darwin
 * extensions are requested before system headers. */
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif

#include <duckdb.hpp>
#include <glib.h>
#include <glib/gstdio.h>

#include <climits>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fcntl.h>
#include <limits>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "fact/secure-duckdb-bridge-private.h"
#include "fact/secure-duckdb-filesystem-private.hpp"
#include "fact/store-identity-private.h"

#include <algorithm>
#include <string>
#include <vector>

namespace fs = std::filesystem;

extern "C"
{
  typedef struct wyl_fact_store_t wyl_fact_store_t;
  wyrelog_error_t wyl_fact_store_open_identified (const gchar *,
      const WylFactStoreIdentity *, WylFactStoreIdentityOpenMode,
      WylFactStoreIdentityResult *, wyl_fact_store_t **);
  void wyl_fact_store_close (wyl_fact_store_t *);
}

static void
remove_tree (const gchar *path)
{
  g_autoptr (GDir) directory = g_dir_open (path, 0, nullptr);
  if (directory != nullptr) {
    const gchar *
        name;
    while ((name = g_dir_read_name (directory)) != nullptr) {
      g_autofree gchar *
          child = g_build_filename (path, name, nullptr);
      if (g_file_test (child, G_FILE_TEST_IS_DIR)
          && !g_file_test (child, G_FILE_TEST_IS_SYMLINK))
        remove_tree (child);
      else
        g_assert_cmpint (g_remove (child), ==, 0);
    }
  }
  g_assert_cmpint (g_rmdir (path), ==, 0);
}

struct Fixture
{
  gchar *
      root = nullptr;
  gchar *
      graph_path = nullptr;
  WylFactGraphResolver
      resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator
      locator = { };
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactArtifactNamespace *
      namespace_ = nullptr;

  explicit Fixture (bool populated = true, bool zero_byte = false) {
    g_autoptr (GError) error = nullptr;
    g_autofree gchar *
        created_root = g_dir_make_tmp ("wyl-secure-filesystem-XXXXXX", &error);
    g_assert_no_error (error);
    g_assert_nonnull (created_root);
    /* macOS may spell TMPDIR through /var, which is a symlink to /private/var.
     * Resolve the owned fixture root before the resolver's no-symlink walk. */
    auto
        canonical_root = fs::canonical (created_root);
    root = g_strdup (canonical_root.c_str ());
    g_assert_nonnull (root);
    g_assert_cmpint (g_chmod (root, 0700), ==, 0);
    g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
        ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
        &locator, TRUE, &directory), ==, WYRELOG_E_OK);
    graph_path = wyl_fact_graph_directory_descriptive_path (&directory);
    g_assert_nonnull (graph_path);

    /* Provisioning owns initial main creation.  Seed a valid database outside
     * the adapter, close it, and import that already-held identity. */
    g_autofree gchar *
        main_path = g_build_filename (graph_path, "facts.duckdb", nullptr);
    {
      duckdb::DuckDB database (main_path);
      duckdb::Connection connection (database);
      if (populated) {
        auto result =
            connection.Query
              ("CREATE TABLE seed(value BIGINT); INSERT INTO seed VALUES (1)");
        g_assert_false (result->HasError ());
      }
    }
    if (zero_byte)
      g_assert_cmpint (truncate (main_path, 0), ==, 0);
    g_assert_cmpint (g_chmod (main_path, 0600), ==, 0);
    WylFactGraphRegularFile main = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
    main.fd = openat (directory.graph_fd, "facts.duckdb",
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    g_assert_cmpint (main.fd >= 0, ==, TRUE);
    struct stat
        status;
    g_assert_cmpint (fstat (main.fd, &status), ==, 0);
    main.device = status.st_dev;
    main.inode = status.st_ino;
    main.size_bytes = status.st_size;
    g_assert_cmpint (wyl_fact_artifact_namespace_open (&directory, &main,
        &namespace_), ==, WYRELOG_E_OK);
    wyl_fact_graph_regular_file_clear (&main);
  }

  ~Fixture () {
    wyl_fact_artifact_namespace_free (namespace_);
    wyl_fact_graph_directory_clear (&directory);
    wyl_fact_graph_locator_clear (&locator);
    wyl_fact_graph_resolver_clear (&resolver);
    g_free (graph_path);
    remove_tree (root);
    g_free (root);
  }
};

struct ProvisionedPairFixture
{
  static constexpr const char *operation_uuid =
      "01890f47-3c4b-7cc2-b8c4-dc0c0c070544";
  gchar *root = nullptr;
  gchar *graph_path = nullptr;
  gchar *stage_path = nullptr;
  gchar *final_path = nullptr;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { };
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphProvisionedPair *pair = nullptr;

  ProvisionedPairFixture ()
  {
    g_autoptr (GError) error = nullptr;
    g_autofree gchar *created_root =
        g_dir_make_tmp ("wyl-secure-pair-XXXXXX", &error);
    g_assert_no_error (error);
    auto canonical_root = fs::canonical (created_root);
    root = g_strdup (canonical_root.c_str ());
    g_assert_cmpint (g_chmod (root, 0700), ==, 0);
    g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
        ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
        &locator, TRUE, &directory), ==, WYRELOG_E_OK);
    graph_path = wyl_fact_graph_directory_descriptive_path (&directory);
    stage_path = g_build_filename (graph_path,
        "provision-01890f47-3c4b-7cc2-b8c4-dc0c0c070544.sqlite", nullptr);
    final_path = g_build_filename (graph_path, "facts.duckdb", nullptr);
    g_assert_true (g_file_set_contents (stage_path, "", 0, nullptr));
    g_assert_cmpint (g_chmod (stage_path, 0600), ==, 0);
    g_assert_cmpint (link (stage_path, final_path), ==, 0);
    g_assert_cmpint (wyl_fact_graph_directory_open_provisioned_pair_exact
        (&directory, operation_uuid, &pair), ==, WYRELOG_E_OK);
  }

  ~ProvisionedPairFixture ()
  {
    wyl_fact_graph_provisioned_pair_free (pair);
    wyl_fact_graph_directory_clear (&directory);
    wyl_fact_graph_locator_clear (&locator);
    wyl_fact_graph_resolver_clear (&resolver);
    g_free (stage_path);
    g_free (final_path);
    g_free (graph_path);
    remove_tree (root);
    g_free (root);
  }
};

static std::vector<std::string>
snapshot_directory_names (const gchar *path)
{
  std::vector<std::string> names;
  g_autoptr (GDir) directory = g_dir_open (path, 0, nullptr);
  g_assert_nonnull (directory);
  const gchar *name;
  while ((name = g_dir_read_name (directory)) != nullptr)
    names.emplace_back (name);
  std::sort (names.begin (), names.end ());
  return names;
}

static void
assert_file_bytes (const gchar *path, const gchar *expected,
    gsize expected_size)
{
  g_autofree gchar *actual = nullptr;
  gsize actual_size = 0;
  g_assert_true (g_file_get_contents (path, &actual, &actual_size, nullptr));
  g_assert_cmpuint (actual_size, ==, expected_size);
  g_assert_cmpmem (actual, actual_size, expected, expected_size);
}

struct SecureDatabase
{
  WylSecureDuckdbFileSystem *
      filesystem = nullptr;
  std::unique_ptr <
  duckdb::DuckDB >
  database;
  std::unique_ptr <
  duckdb::Connection >
  connection;

  SecureDatabase (WylFactArtifactNamespace * namespace_, bool read_only)
  {
    duckdb::DBConfig config;
    auto
        filesystem = wyl_secure_duckdb_filesystem_new (namespace_, read_only);
    this->
    filesystem = filesystem.get ();
    config.
    options.
    access_mode =
        read_only ? duckdb::AccessMode::READ_ONLY
        : duckdb::AccessMode::READ_WRITE;
    config.
    options.
    load_extensions = false;
    config.
    options.
    use_temporary_directory = !read_only;
    if (!read_only)
      config.
      options.
      temporary_directory = filesystem->TemporaryDirectory ();
    config.
    SetOptionByName ("enable_external_access", duckdb::Value (false));
    config.
    SetOptionByName ("allow_community_extensions", duckdb::Value (false));
    config.
    SetOptionByName ("autoinstall_known_extensions", duckdb::Value (false));
    config.
    SetOptionByName ("autoload_known_extensions", duckdb::Value (false));
    config.
    file_system = std::move (filesystem);
    database = std::make_unique < duckdb::DuckDB > ("facts.duckdb", &config);
    connection = std::make_unique < duckdb::Connection > (*database);
  }
};

static void
assert_query_ok (duckdb::Connection & connection, const char *sql)
{
  auto result = connection.Query (sql);
  if (result->HasError ())
    g_test_message ("%s", result->GetError ().c_str ());
  g_assert_false (result->HasError ());
}

static duckdb::FileOpenFlags
writer_sidecar_flags ()
{
  return duckdb::FileOpenFlags (2090, duckdb::FileLockType::WRITE_LOCK,
             duckdb::FileCompressionType::UNCOMPRESSED);
}

static void
write_sidecar (WylSecureDuckdbFileSystem &filesystem,
    duckdb::FileHandle &handle, const char *contents)
{
  filesystem.Write (handle, const_cast < char * >(contents),
      static_cast < int64_t > (strlen (contents)), 0);
  filesystem.FileSync (handle);
}

static void
assert_file_contents (const gchar *path, const char *expected)
{
  g_autofree gchar *contents = nullptr;
  gsize size = 0;
  g_assert_true (g_file_get_contents (path, &contents, &size, nullptr));
  g_assert_cmpuint (size, ==, strlen (expected));
  g_assert_cmpmem (contents, size, expected, strlen (expected));
}

static void
test_real_main_wal_lock_and_bridge (void)
{
  Fixture fixture;
  {
    SecureDatabase secure (fixture.namespace_, false);
    assert_query_ok (*secure.connection,
        "CREATE TABLE bounded(value BIGINT);"
        "INSERT INTO bounded VALUES (42)");
    auto value = secure.connection->Query ("SELECT value FROM bounded");
    g_assert_false (value->HasError ());
    g_assert_cmpstr (value->GetValue (0, 0).ToString ().c_str (), ==, "42");
    g_autofree gchar *
        wal =
        g_build_filename (fixture.graph_path, "facts.duckdb.wal", nullptr);
    g_autofree gchar *
        lock =
        g_build_filename (fixture.graph_path, "facts.duckdb.lock", nullptr);
    g_assert_true (g_file_test (wal, G_FILE_TEST_IS_REGULAR));
    g_assert_true (g_file_test (lock, G_FILE_TEST_IS_REGULAR));
    assert_query_ok (*secure.connection, "CHECKPOINT");
    value = secure.connection->Query ("SELECT value FROM bounded");
    g_assert_false (value->HasError ());
    g_assert_cmpstr (value->GetValue (0, 0).ToString ().c_str (), ==, "42");
    g_assert_cmpint (secure.filesystem->SharedHealth ()->Status (), ==,
        WYRELOG_E_OK);

    auto redirected =
        secure.connection->Query ("SET temp_directory='/tmp/wyrelog-escape'");
    g_assert_true (redirected->HasError ());
  }

  g_autoptr (WylSecureDuckdbBridge) bridge = nullptr;
  g_assert_cmpint (wyl_secure_duckdb_bridge_new_with_namespace
        (fixture.namespace_, WYL_SECURE_DUCKDB_VALIDATE_ONLY, &bridge), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_secure_duckdb_bridge_health (bridge), ==, WYRELOG_E_OK);
}

static void
test_bridge_modes_are_real_and_bounded (void)
{
  {
    Fixture populated;
    WylSecureDuckdbBridge *
        bridge = reinterpret_cast < WylSecureDuckdbBridge * >(0x1);
    g_assert_cmpint (wyl_secure_duckdb_bridge_new_with_namespace
          (populated.namespace_, WYL_SECURE_DUCKDB_INIT_EMPTY, &bridge), ==,
        WYRELOG_E_POLICY);
    g_assert_null (bridge);
  }
  {
    Fixture empty (false);
    g_autoptr (WylSecureDuckdbBridge) bridge = nullptr;
    g_assert_cmpint (wyl_secure_duckdb_bridge_new_with_namespace
          (empty.namespace_, WYL_SECURE_DUCKDB_INIT_EMPTY, &bridge), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_secure_duckdb_bridge_health (bridge), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_secure_duckdb_bridge_finalize (bridge), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_secure_duckdb_bridge_health (bridge), ==,
        WYRELOG_E_OK);
  }
}

static void
test_fixed_wal_replacement_grammars_and_live_detach (void)
{
  Fixture fixture;
  WylSecureDuckdbFileSystem filesystem (fixture.namespace_, false);
  const struct
  {
    const char *source;
    const char *contents;
  } cases[] = {
    { "facts.duckdb.wal.checkpoint", "checkpoint-replacement" },
    { "facts.duckdb.wal.recovery", "recovery-replacement" },
  };
  g_autofree gchar *wal_path =
      g_build_filename (fixture.graph_path, "facts.duckdb.wal", nullptr);

  for (const auto &test_case : cases) {
    auto wal = filesystem.OpenFile ("facts.duckdb.wal",
            writer_sidecar_flags (), nullptr);
    write_sidecar (filesystem, *wal, "old-wal");
    struct stat old_wal_identity;
    g_assert_cmpint (g_stat (wal_path, &old_wal_identity), ==, 0);

    auto source = filesystem.OpenFile (test_case.source,
            writer_sidecar_flags (), nullptr);
    write_sidecar (filesystem, *source, test_case.contents);
    g_autofree gchar *source_path =
        g_build_filename (fixture.graph_path, test_case.source, nullptr);
    struct stat source_identity;
    g_assert_cmpint (g_stat (source_path, &source_identity), ==, 0);
    source->Close ();

    filesystem.MoveFile (test_case.source, "facts.duckdb.wal", nullptr);

    struct stat replaced_identity;
    g_assert_cmpint (g_stat (wal_path, &replaced_identity), ==, 0);
    g_assert_cmpuint (static_cast < guint64 > (replaced_identity.st_dev), ==,
        static_cast < guint64 > (source_identity.st_dev));
    g_assert_cmpuint (static_cast < guint64 > (replaced_identity.st_ino), ==,
        static_cast < guint64 > (source_identity.st_ino));
    g_assert_true (old_wal_identity.st_dev != replaced_identity.st_dev
        || old_wal_identity.st_ino != replaced_identity.st_ino);
    g_assert_false (g_file_test (source_path, G_FILE_TEST_EXISTS));
    assert_file_contents (wal_path, test_case.contents);

    /* MoveFile checked-closes and detaches the live old-WAL binding.  DuckDB's
     * later close is deliberately idempotent and cannot close a reused fd. */
    wal->Close ();
    wal->Close ();
  }
}

static void
test_terminal_wal_replacement_poison_has_no_retry (void)
{
  Fixture fixture;
  WylSecureDuckdbFileSystem filesystem (fixture.namespace_, false);
  auto wal = filesystem.OpenFile ("facts.duckdb.wal",
          writer_sidecar_flags (), nullptr);
  write_sidecar (filesystem, *wal, "old-wal");
  auto source = filesystem.OpenFile ("facts.duckdb.wal.checkpoint",
          writer_sidecar_flags (), nullptr);
  write_sidecar (filesystem, *source, "new-wal");
  source->Close ();

  wyl_fact_artifact_namespace_set_test_fault
    (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_REPLACE_RENAME_AMBIGUOUS);
  try {
    filesystem.MoveFile ("facts.duckdb.wal.checkpoint",
        "facts.duckdb.wal", nullptr);
    g_assert_not_reached ();
  } catch (const WylSecureDuckdbAuthorityException &exception)
  {
    g_assert_cmpint (exception.error, ==, WYRELOG_E_IO);
  }
  g_assert_cmpint (filesystem.SharedHealth ()->Status (), ==, WYRELOG_E_IO);

  /* The ambiguous call consumed both binding authorities.  Shared poison
   * rejects the next operation before it can attempt replacement again. */
  try {
    filesystem.MoveFile ("facts.duckdb.wal.checkpoint",
        "facts.duckdb.wal", nullptr);
    g_assert_not_reached ();
  } catch (const WylSecureDuckdbAuthorityException &exception)
  {
    g_assert_cmpint (exception.error, ==, WYRELOG_E_IO);
  }
  try {
    (void) filesystem.FileExists ("facts.duckdb", nullptr);
    g_assert_not_reached ();
  } catch (const WylSecureDuckdbAuthorityException &exception)
  {
    g_assert_cmpint (exception.error, ==, WYRELOG_E_IO);
  }
  wal->Close ();
}

static void
test_wal_replacement_source_substitution_fails_closed (void)
{
  Fixture fixture;
  WylSecureDuckdbFileSystem filesystem (fixture.namespace_, false);
  auto wal = filesystem.OpenFile ("facts.duckdb.wal",
          writer_sidecar_flags (), nullptr);
  write_sidecar (filesystem, *wal, "old-wal");
  auto source = filesystem.OpenFile ("facts.duckdb.wal.checkpoint",
          writer_sidecar_flags (), nullptr);
  write_sidecar (filesystem, *source, "new-wal");
  source->Close ();

  g_autofree gchar *wal_path =
      g_build_filename (fixture.graph_path, "facts.duckdb.wal", nullptr);
  g_autofree gchar *source_path =
      g_build_filename (fixture.graph_path, "facts.duckdb.wal.checkpoint",
          nullptr);
  g_autofree gchar *saved_path =
      g_build_filename (fixture.graph_path,
          "facts.duckdb.wal.checkpoint.saved", nullptr);
  g_autofree gchar *outside_path =
      g_build_filename (fixture.root, "outside-wal", nullptr);
  g_assert_true (g_file_set_contents (outside_path, "outside-sentinel", -1,
      nullptr));
  g_assert_cmpint (g_rename (source_path, saved_path), ==, 0);
  g_assert_cmpint (symlink (outside_path, source_path), ==, 0);

  try {
    filesystem.MoveFile ("facts.duckdb.wal.checkpoint",
        "facts.duckdb.wal", nullptr);
    g_assert_not_reached ();
  } catch (const duckdb::IOException &)
  {
  }
  g_assert_cmpint (filesystem.SharedHealth ()->Status (), ==,
      WYRELOG_E_POLICY);
  assert_file_contents (wal_path, "old-wal");
  assert_file_contents (outside_path, "outside-sentinel");
  wal->Close ();
}

static void
test_wal_replacement_destination_substitution_fails_closed (void)
{
  Fixture fixture;
  WylSecureDuckdbFileSystem filesystem (fixture.namespace_, false);
  auto wal = filesystem.OpenFile ("facts.duckdb.wal",
          writer_sidecar_flags (), nullptr);
  write_sidecar (filesystem, *wal, "old-wal");
  auto source = filesystem.OpenFile ("facts.duckdb.wal.checkpoint",
          writer_sidecar_flags (), nullptr);
  write_sidecar (filesystem, *source, "new-wal");
  source->Close ();

  g_autofree gchar *wal_path =
      g_build_filename (fixture.graph_path, "facts.duckdb.wal", nullptr);
  g_autofree gchar *source_path =
      g_build_filename (fixture.graph_path, "facts.duckdb.wal.checkpoint",
          nullptr);
  g_autofree gchar *saved_path =
      g_build_filename (fixture.graph_path, "facts.duckdb.wal.saved", nullptr);
  g_autofree gchar *outside_path =
      g_build_filename (fixture.root, "outside-destination-wal", nullptr);
  g_assert_true (g_file_set_contents (outside_path, "outside-sentinel", -1,
      nullptr));
  g_assert_cmpint (g_rename (wal_path, saved_path), ==, 0);
  g_assert_cmpint (symlink (outside_path, wal_path), ==, 0);

  try {
    filesystem.MoveFile ("facts.duckdb.wal.checkpoint",
        "facts.duckdb.wal", nullptr);
    g_assert_not_reached ();
  } catch (const duckdb::IOException &)
  {
  }
  g_assert_cmpint (filesystem.SharedHealth ()->Status (), ==,
      WYRELOG_E_POLICY);
  assert_file_contents (outside_path, "outside-sentinel");
  assert_file_contents (saved_path, "old-wal");
  assert_file_contents (source_path, "new-wal");
  g_assert_true (g_file_test (wal_path, G_FILE_TEST_IS_SYMLINK));
  try {
    wal->Close ();
    g_assert_not_reached ();
  } catch (const duckdb::IOException &)
  {
  }
}

static void
test_live_sidecar_retirement_detaches_handle (void)
{
  Fixture fixture;
  WylSecureDuckdbFileSystem filesystem (fixture.namespace_, false);
  auto recovery = filesystem.OpenFile ("facts.duckdb.wal.recovery",
          writer_sidecar_flags (), nullptr);
  write_sidecar (filesystem, *recovery, "recovery");
  g_autofree gchar *recovery_path =
      g_build_filename (fixture.graph_path, "facts.duckdb.wal.recovery",
          nullptr);
  g_assert_true (g_file_test (recovery_path, G_FILE_TEST_IS_REGULAR));

  g_assert_true (filesystem.TryRemoveFile
        ("facts.duckdb.wal.recovery", nullptr));
  g_assert_false (g_file_test (recovery_path, G_FILE_TEST_EXISTS));
  recovery->Close ();
  recovery->Close ();
  g_assert_cmpint (filesystem.SharedHealth ()->Status (), ==, WYRELOG_E_OK);
}

static void
test_pending_binding_allocation_failure_is_not_clean (void)
{
  Fixture fixture;
  {
    WylSecureDuckdbFileSystem filesystem (fixture.namespace_, false);
    wyl_secure_duckdb_filesystem_set_test_faults (
      WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_HANDLE_ALLOCATION);
    try {
      (void) filesystem.OpenFile ("facts.duckdb",
          duckdb::FileOpenFlags (2307, duckdb::FileLockType::WRITE_LOCK,
          duckdb::FileCompressionType::UNCOMPRESSED), nullptr);
      g_assert_not_reached ();
    } catch (const std::bad_alloc &)
    {
    }
    g_assert_cmpint (filesystem.SharedHealth ()->Status (), ==,
        WYRELOG_E_NOMEM);
  }

  /* A checked pending-binding close leaves no provider retirement barrier. */
  WylSecureDuckdbFileSystem retry (fixture.namespace_, false);
  auto main = retry.OpenFile ("facts.duckdb",
          duckdb::FileOpenFlags (2307, duckdb::FileLockType::WRITE_LOCK,
          duckdb::FileCompressionType::UNCOMPRESSED), nullptr);
  main->Close ();
}

static void
test_pending_binding_close_failure_poison_is_terminal (void)
{
  Fixture fixture;
  WylSecureDuckdbFileSystem filesystem (fixture.namespace_, false);
  wyl_secure_duckdb_filesystem_set_test_faults (
    WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_HANDLE_ALLOCATION
    | WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_CHECKED_CLOSE_REVALIDATION);
  try {
    (void) filesystem.OpenFile ("facts.duckdb",
        duckdb::FileOpenFlags (2307, duckdb::FileLockType::WRITE_LOCK,
        duckdb::FileCompressionType::UNCOMPRESSED), nullptr);
    g_assert_not_reached ();
  } catch (const std::bad_alloc &)
  {
  }
  g_assert_cmpint (filesystem.SharedHealth ()->Status (), ==,
      WYRELOG_E_POLICY);
  try {
    (void) filesystem.FileExists ("facts.duckdb", nullptr);
    g_assert_not_reached ();
  } catch (const WylSecureDuckdbAuthorityException &exception)
  {
    g_assert_cmpint (exception.error, ==, WYRELOG_E_POLICY);
  }
}

static void
test_file_exists_uses_checked_main_handle (void)
{
  {
    Fixture fixture (false, true);
    WylSecureDuckdbFileSystem filesystem (fixture.namespace_, false);
    g_assert_false (filesystem.FileExists ("facts.duckdb", nullptr));
    g_assert_cmpint (filesystem.SharedHealth ()->Status (), ==, WYRELOG_E_OK);
  }
  {
    Fixture fixture (false, true);
    WylSecureDuckdbFileSystem filesystem (fixture.namespace_, false);
    wyl_secure_duckdb_filesystem_set_test_faults (
      WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_CHECKED_CLOSE_REVALIDATION);
    try {
      (void) filesystem.FileExists ("facts.duckdb", nullptr);
      g_assert_not_reached ();
    } catch (const duckdb::IOException &)
    {
    }
    g_assert_cmpint (filesystem.SharedHealth ()->Status (), ==,
        WYRELOG_E_POLICY);
  }
  {
    Fixture fixture (false, true);
    {
      WylSecureDuckdbFileSystem filesystem (fixture.namespace_, false);
      wyl_secure_duckdb_filesystem_set_test_faults (
        WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_HANDLE_ALLOCATION);
      try {
        (void) filesystem.FileExists ("facts.duckdb", nullptr);
        g_assert_not_reached ();
      } catch (const std::bad_alloc &)
      {
      }
      g_assert_cmpint (filesystem.SharedHealth ()->Status (), ==,
          WYRELOG_E_NOMEM);
    }
    WylSecureDuckdbFileSystem retry (fixture.namespace_, false);
    g_assert_false (retry.FileExists ("facts.duckdb", nullptr));
  }
  {
    Fixture fixture (false, true);
    WylSecureDuckdbFileSystem filesystem (fixture.namespace_, false);
    wyl_secure_duckdb_filesystem_set_test_faults (
      WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_HANDLE_ALLOCATION
      | WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_CHECKED_CLOSE_REVALIDATION);
    try {
      (void) filesystem.FileExists ("facts.duckdb", nullptr);
      g_assert_not_reached ();
    } catch (const std::bad_alloc &)
    {
    }
    g_assert_cmpint (filesystem.SharedHealth ()->Status (), ==,
        WYRELOG_E_POLICY);
  }
}

static void
test_temp_registration_failure_rolls_back_durable_child (void)
{
  Fixture fixture;
  {
    WylSecureDuckdbFileSystem filesystem (fixture.namespace_, false);
    const auto temp_path = filesystem.TemporaryDirectory ()
        + "/duckdb_temp_storage_S32K-0.tmp";
    wyl_secure_duckdb_filesystem_set_test_faults (
      WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_TEMP_REGISTRATION);
    try {
      (void) filesystem.OpenFile (temp_path,
          duckdb::FileOpenFlags (11, duckdb::FileLockType::NO_LOCK,
          duckdb::FileCompressionType::UNCOMPRESSED), nullptr);
      g_assert_not_reached ();
    } catch (const std::bad_alloc &)
    {
    }
    g_assert_cmpint (filesystem.SharedHealth ()->Status (), ==,
        WYRELOG_E_NOMEM);
    g_assert_cmpuint (filesystem.TempChildrenCreatedForTest (), ==, 0);
  }
  g_autoptr (GDir) graph = g_dir_open (fixture.graph_path, 0, nullptr);
  g_assert_nonnull (graph);
  for (const gchar *name; (name = g_dir_read_name (graph)) != nullptr;)
    g_assert_false (g_str_has_prefix (name, ".duckdb-private-temp-"));
}

static void
test_bridge_construction_allocation_failure_rolls_back (void)
{
  Fixture fixture (false);
  WylSecureDuckdbBridge *bridge = nullptr;
  wyl_secure_duckdb_filesystem_set_test_faults (
    WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_HANDLE_ALLOCATION);
  g_assert_cmpint (wyl_secure_duckdb_bridge_new_with_namespace
        (fixture.namespace_, WYL_SECURE_DUCKDB_INIT_EMPTY, &bridge), ==,
      WYRELOG_E_NOMEM);
  g_assert_null (bridge);

  g_autoptr (GDir) graph = g_dir_open (fixture.graph_path, 0, nullptr);
  g_assert_nonnull (graph);
  for (const gchar *name; (name = g_dir_read_name (graph)) != nullptr;)
    g_assert_false (g_str_has_prefix (name, ".duckdb-private-temp-"));
}

static void
test_handle_destructor_poison_reaches_bridge_finalize (void)
{
  Fixture fixture (false);
  g_autoptr (WylSecureDuckdbBridge) bridge = nullptr;
  g_assert_cmpint (wyl_secure_duckdb_bridge_new_with_namespace
        (fixture.namespace_, WYL_SECURE_DUCKDB_INIT_EMPTY, &bridge), ==,
      WYRELOG_E_OK);
  wyl_secure_duckdb_filesystem_set_test_faults (
    WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_CHECKED_CLOSE_REVALIDATION);
  g_assert_cmpint (wyl_secure_duckdb_bridge_finalize (bridge), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_secure_duckdb_bridge_health (bridge), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_secure_duckdb_bridge_finalize (bridge), ==,
      WYRELOG_E_POLICY);
}

static void
test_checked_finalize_reports_cleanup_failure (void)
{
  Fixture fixture (false);
  g_autoptr (WylSecureDuckdbBridge) bridge = nullptr;
  g_assert_cmpint (wyl_secure_duckdb_bridge_new_with_namespace
        (fixture.namespace_, WYL_SECURE_DUCKDB_INIT_EMPTY, &bridge), ==,
      WYRELOG_E_OK);

  g_autoptr (GDir) graph = g_dir_open (fixture.graph_path, 0, nullptr);
  g_assert_nonnull (graph);
  g_autofree gchar *temp_name = nullptr;
  for (const gchar *name; (name = g_dir_read_name (graph)) != nullptr;) {
    if (g_str_has_prefix (name, ".duckdb-private-temp-")) {
      temp_name = g_strdup (name);
      break;
    }
  }
  g_assert_nonnull (temp_name);
  g_autofree gchar *temp_path =
      g_build_filename (fixture.graph_path, temp_name, nullptr);
  g_autofree gchar *saved_path =
      g_strdup_printf ("%s.saved", temp_path);
  g_autofree gchar *outside_path =
      g_build_filename (fixture.root, "outside-temp", nullptr);
  g_assert_cmpint (g_mkdir (outside_path, 0700), ==, 0);
  g_assert_cmpint (g_rename (temp_path, saved_path), ==, 0);
  g_assert_cmpint (symlink (outside_path, temp_path), ==, 0);

  g_assert_cmpint (wyl_secure_duckdb_bridge_finalize (bridge), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_secure_duckdb_bridge_health (bridge), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_secure_duckdb_bridge_finalize (bridge), ==,
      WYRELOG_E_POLICY);

  g_assert_cmpint (g_remove (temp_path), ==, 0);
  g_assert_cmpint (g_rmdir (saved_path), ==, 0);
  g_assert_cmpint (g_rmdir (outside_path), ==, 0);
}

static void
test_wal_crash_recovery_and_locking (void)
{
  Fixture fixture;
  const
  pid_t
      child = fork ();
  g_assert_cmpint (child >= 0, ==, TRUE);
  if (child == 0) {
    try {
      SecureDatabase secure (fixture.namespace_, false);
      auto result =
          secure.connection->Query ("CREATE TABLE recovery(value BIGINT);"
              "INSERT INTO recovery VALUES (7)");
      if (result->HasError ())
        _exit (91);
      _exit (0);
    }
    catch ( ...) {
      _exit (92);
    }
  }
  int
      status = 0;
  g_assert_cmpint (waitpid (child, &status, 0), ==, child);
  g_assert_true (WIFEXITED (status));
  g_assert_cmpint (WEXITSTATUS (status), ==, 0);
  g_autofree gchar *
      wal = g_build_filename (fixture.graph_path, "facts.duckdb.wal", nullptr);
  g_assert_true (g_file_test (wal, G_FILE_TEST_IS_REGULAR));

  {
    SecureDatabase recovered (fixture.namespace_, true);
    auto value = recovered.connection->Query ("SELECT value FROM recovery");
    if (value->HasError ())
      g_test_message ("%s", value->GetError ().c_str ());
    g_assert_false (value->HasError ());
    g_assert_cmpstr (value->GetValue (0, 0).ToString ().c_str (), ==, "7");

    WylSecureDuckdbBridge *
        writer = reinterpret_cast < WylSecureDuckdbBridge * >(0x1);
    g_assert_cmpint (wyl_secure_duckdb_bridge_new_with_namespace
          (fixture.namespace_, WYL_SECURE_DUCKDB_INIT_EMPTY, &writer), ==,
        WYRELOG_E_BUSY);
    g_assert_null (writer);
  }
}

static void
test_real_temp_spill_cleanup (void)
{
  Fixture fixture;
  {
    SecureDatabase secure (fixture.namespace_, false);
    assert_query_ok (*secure.connection,
        "SET threads=1; SET preserve_insertion_order=false;"
        "SET memory_limit='50MB'");
    auto result = secure.connection->Query ("SELECT i FROM range(5000000) t(i) "
            "ORDER BY (i * 1103515245) % 1000003 DESC");
    if (result->HasError ())
      g_test_message ("%s", result->GetError ().c_str ());
    g_assert_false (result->HasError ());
    g_assert_cmpuint (result->RowCount (), ==, 5000000);
    g_assert_cmpuint (secure.filesystem->TempChildrenCreatedForTest (), >, 0);
  }
  g_autoptr (GDir) graph = g_dir_open (fixture.graph_path, 0, nullptr);
  g_assert_nonnull (graph);
  for (const gchar * name; (name = g_dir_read_name (graph)) != nullptr;)
    g_assert_false (g_str_has_prefix (name, ".duckdb-private-temp-"));
}

static void
test_denial_and_numeric_no_mutation (void)
{
  Fixture fixture;
  WylSecureDuckdbFileSystem filesystem (fixture.namespace_, false);
  const
  auto
      home = filesystem.GetHomeDirectory ();
  g_assert_cmpstr (home.c_str (), ==, "/__wyrelog_duckdb_home__");
  g_assert_false (filesystem.FileExists
        ("/__wyrelog_duckdb_home__/.duckdb/stored_secrets", nullptr));
  g_assert_false (filesystem.FileExists ("/proc/self/cgroup", nullptr));
  try {
    (void) filesystem.FileExists ("/tmp/facts.duckdb", nullptr);
    g_assert_not_reached ();
  } catch (const duckdb::IOException &)
  {
  }
  try {
    (void) filesystem.FileExists ("../facts.duckdb", nullptr);
    g_assert_not_reached ();
  } catch (const duckdb::IOException &)
  {
  }
  try {
    (void) filesystem.OpenFile ("facts.duckdb",
        duckdb::FileFlags::FILE_FLAGS_READ
        | duckdb::FileFlags::FILE_FLAGS_WRITE, nullptr);
    g_assert_not_reached ();
  } catch (const duckdb::IOException &)
  {
  }

  auto main = filesystem.OpenFile ("facts.duckdb",
          duckdb::FileOpenFlags (2307, duckdb::FileLockType::WRITE_LOCK,
          duckdb::FileCompressionType::UNCOMPRESSED), nullptr);
  const
  auto
      original_size = filesystem.GetFileSize (*main);
  const
  auto
      original_cursor = filesystem.SeekPosition (*main);
  unsigned char
      sentinel = 0x5a;
  const auto ssize_max = static_cast < int64_t > (SSIZE_MAX);
  try {
    filesystem.Write (*main, nullptr, ssize_max, 0);
    g_assert_not_reached ();
  } catch (const duckdb::IOException &)
  {
  }
  g_assert_cmpint (filesystem.GetFileSize (*main), ==, original_size);
  g_assert_cmpuint (filesystem.SeekPosition (*main), ==, original_cursor);
  try {
    filesystem.Read (*main, &sentinel, -1, 0);
    g_assert_not_reached ();
  } catch (const duckdb::IOException &)
  {
  }
  g_assert_cmphex (sentinel, ==, 0x5a);
  g_assert_cmpint (filesystem.GetFileSize (*main), ==, original_size);
  g_assert_cmpuint (filesystem.SeekPosition (*main), ==, original_cursor);
  try {
    (void) filesystem.Read (*main, &sentinel, -1);
    g_assert_not_reached ();
  } catch (const duckdb::IOException &)
  {
  }
  g_assert_cmpuint (filesystem.SeekPosition (*main), ==, original_cursor);
  try {
    (void) filesystem.Write (*main, &sentinel, -1);
    g_assert_not_reached ();
  } catch (const duckdb::IOException &)
  {
  }
  g_assert_cmpuint (filesystem.SeekPosition (*main), ==, original_cursor);
  try {
    filesystem.Write (*main, &sentinel, 1,
        static_cast < duckdb::idx_t > (LLONG_MAX));
    g_assert_not_reached ();
  } catch (const duckdb::IOException &)
  {
  }
  g_assert_cmpint (filesystem.GetFileSize (*main), ==, original_size);
  g_assert_cmpuint (filesystem.SeekPosition (*main), ==, original_cursor);
  try {
    filesystem.Read (*main, &sentinel, 1,
        static_cast < duckdb::idx_t > (LLONG_MAX));
    g_assert_not_reached ();
  } catch (const duckdb::IOException &)
  {
  }
  g_assert_cmphex (sentinel, ==, 0x5a);
  g_assert_cmpuint (filesystem.SeekPosition (*main), ==, original_cursor);
  const auto off_max = static_cast < duckdb::idx_t >
      (std::numeric_limits < off_t >::max ());
  try {
    filesystem.Seek (*main, off_max + 1);
    g_assert_not_reached ();
  } catch (const duckdb::IOException &)
  {
  }
  g_assert_cmpuint (filesystem.SeekPosition (*main), ==, original_cursor);
  filesystem.Seek (*main, off_max);
  g_assert_cmpuint (filesystem.SeekPosition (*main), ==, off_max);
  try {
    (void) filesystem.Read (*main, &sentinel, 1);
    g_assert_not_reached ();
  } catch (const duckdb::IOException &)
  {
  }
  try {
    (void) filesystem.Write (*main, &sentinel, 1);
    g_assert_not_reached ();
  } catch (const duckdb::IOException &)
  {
  }
  g_assert_cmpuint (filesystem.SeekPosition (*main), ==, off_max);
  filesystem.Seek (*main, original_cursor);
  try {
    filesystem.Truncate (*main, -1);
    g_assert_not_reached ();
  } catch (const duckdb::IOException &)
  {
  }
  g_assert_cmpint (filesystem.GetFileSize (*main), ==, original_size);
  main->Close ();

  auto reader = filesystem.OpenFile ("facts.duckdb",
          duckdb::FileOpenFlags (129, duckdb::FileLockType::NO_LOCK,
          duckdb::FileCompressionType::UNCOMPRESSED), nullptr);
  try {
    filesystem.Write (*reader, &sentinel, 1, 0);
    g_assert_not_reached ();
  } catch (const duckdb::IOException &)
  {
  }
  g_assert_cmpint (filesystem.GetFileSize (*reader), ==, original_size);
  reader->Close ();

  const
  auto
      temp_path = filesystem.TemporaryDirectory ()
      + "/duckdb_temp_storage_S32K-0.tmp";
  auto temporary = filesystem.OpenFile (temp_path,
          duckdb::FileOpenFlags (11, duckdb::FileLockType::NO_LOCK,
          duckdb::FileCompressionType::UNCOMPRESSED), nullptr);
  constexpr
  duckdb::idx_t
      sparse_offset = static_cast < duckdb::idx_t > (UINT64_C (1) << 32);
  unsigned char
      sparse_written = 0xa5;
  unsigned char
      sparse_read = 0;
  filesystem.Write (*temporary, &sparse_written, 1, sparse_offset);
  filesystem.Read (*temporary, &sparse_read, 1, sparse_offset);
  g_assert_cmphex (sparse_read, ==, sparse_written);
  g_assert_cmpint (filesystem.GetFileSize (*temporary), ==,
      static_cast < int64_t > (sparse_offset + 1));
  temporary->Close ();
  g_assert_true (filesystem.TryRemoveFile (temp_path, nullptr));
}

static void
restore_environment (const char *name, const char *value)
{
  if (value == nullptr)
    g_unsetenv (name);
  else
    g_setenv (name, value, TRUE);
}

static void
test_virtual_home_and_environment_are_not_authority (void)
{
  g_autofree gchar *saved_home = g_strdup (g_getenv ("HOME"));
  g_autofree gchar *saved_xdg = g_strdup (g_getenv ("XDG_CONFIG_HOME"));
  g_autofree gchar *saved_tmp = g_strdup (g_getenv ("TMPDIR"));
  Fixture fixture;
  g_setenv ("HOME", "/tmp/wyrelog-attacker-home", TRUE);
  g_setenv ("XDG_CONFIG_HOME", "/tmp/wyrelog-attacker-config", TRUE);
  g_setenv ("TMPDIR", "/tmp/wyrelog-attacker-temp", TRUE);

  {
    WylSecureDuckdbFileSystem filesystem (fixture.namespace_, false);
    const auto home = filesystem.GetHomeDirectory ();
    g_assert_cmpstr (home.c_str (), ==,
        "/__wyrelog_duckdb_home__");
    g_assert_false (g_str_has_prefix (filesystem.TemporaryDirectory ().c_str (),
        "/tmp/"));
    g_assert_false (filesystem.CanHandleFile
          ("/tmp/wyrelog-attacker-home/.duckdb/stored_secrets"));
    try {
      (void) filesystem.ExpandPath ("~/.duckdb/stored_secrets");
      g_assert_not_reached ();
    } catch (const duckdb::IOException &)
    {
    }
  }

  restore_environment ("HOME", saved_home);
  restore_environment ("XDG_CONFIG_HOME", saved_xdg);
  restore_environment ("TMPDIR", saved_tmp);
}

static void
test_main_symlink_substitution_fails_closed (void)
{
  Fixture fixture;
  g_autofree gchar *
      main_path =
      g_build_filename (fixture.graph_path, "facts.duckdb", nullptr);
  g_autofree gchar *
      saved_path =
      g_build_filename (fixture.graph_path, "facts.duckdb.saved", nullptr);
  g_autofree gchar *
      outside_path = g_build_filename (fixture.root, "outside.duckdb", nullptr);
  g_assert_true (g_file_set_contents (outside_path, "outside-sentinel", -1,
      nullptr));
  g_assert_cmpint (g_rename (main_path, saved_path), ==, 0);
  g_assert_cmpint (symlink (outside_path, main_path), ==, 0);

  try {
    WylSecureDuckdbFileSystem filesystem (fixture.namespace_, false);
    g_assert_not_reached ();
  } catch (const duckdb::IOException &)
  {
  }
  g_autofree gchar *
      outside_contents = nullptr;
  gsize outside_size = 0;
  g_assert_true (g_file_get_contents (outside_path, &outside_contents,
      &outside_size, nullptr));
  g_assert_cmpuint (outside_size, ==, strlen ("outside-sentinel"));
  g_assert_cmpmem (outside_contents, outside_size,
      "outside-sentinel", strlen ("outside-sentinel"));

  g_assert_cmpint (g_remove (main_path), ==, 0);
  g_assert_cmpint (g_rename (saved_path, main_path), ==, 0);
}

static const WylFactStoreIdentity pinned_identity = {
  "tenant",
  "graph",
  "01890f47-3c4b-6cc2-b8c4-dc0c0c073989",
  1,
  1,
};

static void
test_provisioned_pair_pinned_modes (void)
{
  ProvisionedPairFixture fixture;
  WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
  struct stat before, initialized;
  g_assert_cmpint (g_stat (fixture.final_path, &before), ==, 0);
  g_assert_cmpint (before.st_size, ==, 0);
  wyl_fact_artifact_namespace_pair_access_reset_for_test ();
  g_assert_cmpint (wyl_fact_store_open_identified_provisioned_pair_pinned
      (fixture.pair, &pinned_identity,
          WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_NONE);
  g_assert_true (wyl_fact_artifact_namespace_pair_access_observed_for_test
      (WYL_FACT_ARTIFACT_PAIR_ACCESS_WRITER_BINDING, O_RDWR));
  g_assert_cmpint (g_stat (fixture.final_path, &initialized), ==, 0);
  g_assert_cmpint (initialized.st_size, >, 0);
  g_assert_cmpuint (initialized.st_nlink, ==, 2);

  g_autofree gchar *before_bytes = nullptr;
  gsize before_size = 0;
  g_assert_true (g_file_get_contents (fixture.final_path, &before_bytes,
      &before_size, nullptr));
  result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
  wyl_fact_artifact_namespace_pair_access_reset_for_test ();
  g_assert_cmpint (wyl_fact_store_open_identified_provisioned_pair_pinned
      (fixture.pair, &pinned_identity, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY,
          &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_NONE);
  g_assert_true (wyl_fact_artifact_namespace_pair_access_observed_for_test
      (WYL_FACT_ARTIFACT_PAIR_ACCESS_READ_PIN, O_RDONLY));
  g_assert_true (wyl_fact_artifact_namespace_pair_access_observed_for_test
      (WYL_FACT_ARTIFACT_PAIR_ACCESS_READER_BINDING, O_RDONLY));
  g_autofree gchar *after_bytes = nullptr;
  gsize after_size = 0;
  g_assert_true (g_file_get_contents (fixture.final_path, &after_bytes,
      &after_size, nullptr));
  g_assert_cmpuint (after_size, ==, before_size);
  g_assert_cmpint (memcmp (after_bytes, before_bytes, before_size), ==, 0);

  g_autofree gchar *wal =
      g_build_filename (fixture.graph_path, "facts.duckdb.wal", nullptr);
  g_assert_false (g_file_test (wal, G_FILE_TEST_EXISTS));
}

struct PairPreflightAction
{
  const gchar *stage_path;
  gboolean remove_stage;
  guint calls;
};

static void
pair_preflight_action (WylFactStorePairPreflightForTest seam,
    gpointer user_data)
{
  auto *action = static_cast<PairPreflightAction *> (user_data);
  g_assert_cmpint (seam, ==, WYL_FACT_STORE_PAIR_PREFLIGHT_PRE_FACTORY);
  action->calls++;
  if (action->remove_stage)
    g_assert_cmpint (g_remove (action->stage_path), ==, 0);
}

static void
test_provisioned_pair_pinned_preflight_no_mutation (void)
{
  {
    ProvisionedPairFixture fixture;
    struct stat stage_before, final_before;
    g_assert_cmpint (g_stat (fixture.stage_path, &stage_before), ==, 0);
    g_assert_cmpint (g_stat (fixture.final_path, &final_before), ==, 0);
    g_assert_cmpuint (stage_before.st_dev, ==, final_before.st_dev);
    g_assert_cmpuint (stage_before.st_ino, ==, final_before.st_ino);
    g_assert_cmpuint (stage_before.st_size, ==, 0);
    g_assert_cmpuint (final_before.st_size, ==, 0);
    const auto names_before = snapshot_directory_names (fixture.graph_path);
    g_autofree gchar *lock_path =
        g_build_filename (fixture.graph_path, "facts.duckdb.lock", nullptr);
    g_autofree gchar *wal_path =
        g_build_filename (fixture.graph_path, "facts.duckdb.wal", nullptr);
    PairPreflightAction action = { fixture.stage_path, FALSE, 0 };
    wyl_fact_store_pinned_set_pair_preflight_hook_for_test
        (pair_preflight_action, &action);
    wyl_fact_store_pinned_set_pair_preflight_error_for_test
        (WYL_FACT_STORE_PAIR_PREFLIGHT_PRE_FACTORY, WYRELOG_E_POLICY);

    WylFactStoreIdentityResult result =
        WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    g_assert_cmpint (wyl_fact_store_open_identified_provisioned_pair_pinned
        (fixture.pair, &pinned_identity,
            WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &result), ==,
        WYRELOG_E_POLICY);
    g_assert_cmpuint (action.calls, ==, 1);
    struct stat stage_after, final_after;
    g_assert_cmpint (g_stat (fixture.stage_path, &stage_after), ==, 0);
    g_assert_cmpint (g_stat (fixture.final_path, &final_after), ==, 0);
    g_assert_cmpuint (stage_after.st_dev, ==, stage_before.st_dev);
    g_assert_cmpuint (stage_after.st_ino, ==, stage_before.st_ino);
    g_assert_cmpuint (stage_after.st_nlink, ==, stage_before.st_nlink);
    g_assert_cmpuint (stage_after.st_size, ==, stage_before.st_size);
    g_assert_cmpuint (final_after.st_dev, ==, final_before.st_dev);
    g_assert_cmpuint (final_after.st_ino, ==, final_before.st_ino);
    g_assert_cmpuint (final_after.st_nlink, ==, final_before.st_nlink);
    g_assert_cmpuint (final_after.st_size, ==, final_before.st_size);
    g_assert_true (snapshot_directory_names (fixture.graph_path)
        == names_before);
    g_assert_false (g_file_test (lock_path, G_FILE_TEST_EXISTS));
    g_assert_false (g_file_test (wal_path, G_FILE_TEST_EXISTS));
    g_assert_cmpint (wyl_fact_graph_provisioned_pair_revalidate (fixture.pair),
        ==, WYRELOG_E_OK);
  }

  {
    ProvisionedPairFixture fixture;
    struct stat stage_before, final_before;
    g_assert_cmpint (g_stat (fixture.stage_path, &stage_before), ==, 0);
    g_assert_cmpint (g_stat (fixture.final_path, &final_before), ==, 0);
    g_assert_cmpuint (stage_before.st_dev, ==, final_before.st_dev);
    g_assert_cmpuint (stage_before.st_ino, ==, final_before.st_ino);
    g_assert_cmpuint (stage_before.st_size, ==, 0);
    g_assert_cmpuint (final_before.st_size, ==, 0);
    const auto names_before = snapshot_directory_names (fixture.graph_path);
    auto expected_names = names_before;
    g_autofree gchar *stage_name = g_path_get_basename (fixture.stage_path);
    expected_names.erase (std::remove (expected_names.begin (),
            expected_names.end (), std::string (stage_name)),
        expected_names.end ());
    g_autofree gchar *lock_path =
        g_build_filename (fixture.graph_path, "facts.duckdb.lock", nullptr);
    g_autofree gchar *wal_path =
        g_build_filename (fixture.graph_path, "facts.duckdb.wal", nullptr);
    PairPreflightAction action = { fixture.stage_path, TRUE, 0 };
    wyl_fact_store_pinned_set_pair_preflight_hook_for_test
        (pair_preflight_action, &action);

    WylFactStoreIdentityResult result =
        WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    g_assert_cmpint (wyl_fact_store_open_identified_provisioned_pair_pinned
        (fixture.pair, &pinned_identity,
            WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &result), ==,
        WYRELOG_E_POLICY);
    g_assert_cmpuint (action.calls, ==, 1);
    g_assert_false (g_file_test (fixture.stage_path, G_FILE_TEST_EXISTS));
    struct stat final_after;
    g_assert_cmpint (g_stat (fixture.final_path, &final_after), ==, 0);
    g_assert_cmpuint (final_after.st_dev, ==, final_before.st_dev);
    g_assert_cmpuint (final_after.st_ino, ==, final_before.st_ino);
    g_assert_cmpuint (final_after.st_nlink + 1, ==, final_before.st_nlink);
    g_assert_cmpuint (final_after.st_size, ==, final_before.st_size);
    g_assert_true (snapshot_directory_names (fixture.graph_path)
        == expected_names);
    g_assert_false (g_file_test (lock_path, G_FILE_TEST_EXISTS));
    g_assert_false (g_file_test (wal_path, G_FILE_TEST_EXISTS));
    g_assert_cmpint (wyl_fact_graph_provisioned_pair_revalidate (fixture.pair),
        ==, WYRELOG_E_POLICY);
  }
}

enum class PairLifecycleAttack
{
  STAGE_REMOVAL,
  FINAL_SUBSTITUTION,
  GRAPH_REPLACEMENT,
};

struct PairLifecycleAttackContext
{
  WylFactStorePinnedRendezvous target;
  PairLifecycleAttack attack;
  ProvisionedPairFixture *fixture;
  const gchar *saved_path;
  guint calls;
  gboolean fired;
};

static void
attack_pair_lifecycle (WylFactStorePinnedRendezvous rendezvous,
    gpointer user_data)
{
  auto *context = static_cast<PairLifecycleAttackContext *> (user_data);
  context->calls++;
  if (context->fired || rendezvous != context->target)
    return;
  context->fired = TRUE;
  switch (context->attack) {
    case PairLifecycleAttack::STAGE_REMOVAL:
      g_assert_cmpint (g_remove (context->fixture->stage_path), ==, 0);
      break;
    case PairLifecycleAttack::FINAL_SUBSTITUTION:
      g_assert_cmpint (g_rename (context->fixture->final_path,
              context->saved_path), ==, 0);
      g_assert_true (g_file_set_contents (context->fixture->final_path,
          "attacker", -1, nullptr));
      g_assert_cmpint (g_chmod (context->fixture->final_path, 0600), ==, 0);
      break;
    case PairLifecycleAttack::GRAPH_REPLACEMENT:
      g_assert_cmpint (g_rename (context->fixture->graph_path,
              context->saved_path), ==, 0);
      g_assert_cmpint (g_mkdir (context->fixture->graph_path, 0700), ==, 0);
      break;
  }
}

static void
test_provisioned_pair_pinned_actual_rendezvous (void)
{
  for (int value = WYL_FACT_STORE_PINNED_RENDEZVOUS_R0_PRECONSTRUCT;
      value <= WYL_FACT_STORE_PINNED_RENDEZVOUS_R5_FINAL_REVALIDATE; value++) {
    ProvisionedPairFixture fixture;
    WylFactStoreIdentityResult result =
        WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    g_assert_cmpint (wyl_fact_store_open_identified_provisioned_pair_pinned
        (fixture.pair, &pinned_identity,
            WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &result), ==,
        WYRELOG_E_OK);
    g_autofree gchar *database_bytes = nullptr;
    gsize database_size = 0;
    g_assert_true (g_file_get_contents (fixture.stage_path, &database_bytes,
        &database_size, nullptr));
    const auto names_before = snapshot_directory_names (fixture.graph_path);
    g_autofree gchar *lock_path =
        g_build_filename (fixture.graph_path, "facts.duckdb.lock", nullptr);
    struct stat lock_before;
    g_assert_cmpint (g_stat (lock_path, &lock_before), ==, 0);
    g_autofree gchar *wal_path =
        g_build_filename (fixture.graph_path, "facts.duckdb.wal", nullptr);
    g_assert_false (g_file_test (wal_path, G_FILE_TEST_EXISTS));

    const auto attack = static_cast<PairLifecycleAttack> (value % 3);
    g_autofree gchar *saved_path =
        attack == PairLifecycleAttack::GRAPH_REPLACEMENT
        ? g_strdup_printf ("%s.saved", fixture.graph_path)
        : g_build_filename (fixture.graph_path, "facts.duckdb.saved", nullptr);
    PairLifecycleAttackContext context = {
      static_cast<WylFactStorePinnedRendezvous> (value),
      attack,
      &fixture,
      saved_path,
      0,
      FALSE,
    };
    wyl_fact_store_pinned_set_pair_test_hook_for_test (attack_pair_lifecycle,
        &context);
    g_assert_cmpint (wyl_fact_store_open_identified_provisioned_pair_pinned
        (fixture.pair, &pinned_identity, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY,
            &result), ==, WYRELOG_E_POLICY);
    g_assert_true (context.fired);

    gchar *authority_path = fixture.graph_path;
    if (attack == PairLifecycleAttack::GRAPH_REPLACEMENT) {
      authority_path = saved_path;
      g_assert_true (snapshot_directory_names (authority_path)
          == names_before);
      g_assert_true (snapshot_directory_names (fixture.graph_path).empty ());
    }
    g_autofree gchar *authority_lock =
        g_build_filename (authority_path, "facts.duckdb.lock", nullptr);
    struct stat lock_after;
    g_assert_cmpint (g_stat (authority_lock, &lock_after), ==, 0);
    g_assert_cmpuint (lock_after.st_dev, ==, lock_before.st_dev);
    g_assert_cmpuint (lock_after.st_ino, ==, lock_before.st_ino);
    g_autofree gchar *authority_wal =
        g_build_filename (authority_path, "facts.duckdb.wal", nullptr);
    g_assert_false (g_file_test (authority_wal, G_FILE_TEST_EXISTS));

    if (attack == PairLifecycleAttack::STAGE_REMOVAL) {
      assert_file_bytes (fixture.final_path, database_bytes, database_size);
      auto expected_names = names_before;
      g_autofree gchar *stage_name =
          g_path_get_basename (fixture.stage_path);
      expected_names.erase (std::remove (expected_names.begin (),
              expected_names.end (), std::string (stage_name)),
          expected_names.end ());
      g_assert_true (snapshot_directory_names (fixture.graph_path)
          == expected_names);
      g_assert_cmpint (link (fixture.final_path, fixture.stage_path), ==, 0);
    } else if (attack == PairLifecycleAttack::FINAL_SUBSTITUTION) {
      assert_file_bytes (fixture.stage_path, database_bytes, database_size);
      assert_file_contents (fixture.final_path, "attacker");
      auto expected_names = names_before;
      expected_names.emplace_back ("facts.duckdb.saved");
      std::sort (expected_names.begin (), expected_names.end ());
      g_assert_true (snapshot_directory_names (fixture.graph_path)
          == expected_names);
      g_assert_cmpint (g_remove (fixture.final_path), ==, 0);
      g_assert_cmpint (g_rename (saved_path, fixture.final_path), ==, 0);
    } else {
      g_autofree gchar *authority_stage =
          g_build_filename (authority_path,
          "provision-01890f47-3c4b-7cc2-b8c4-dc0c0c070544.sqlite", nullptr);
      assert_file_bytes (authority_stage, database_bytes, database_size);
      g_assert_cmpint (g_rmdir (fixture.graph_path), ==, 0);
      g_assert_cmpint (g_rename (saved_path, fixture.graph_path), ==, 0);
    }

    const guint calls_after_attack = context.calls;
    g_assert_cmpint (wyl_fact_graph_provisioned_pair_revalidate (fixture.pair),
        ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_store_open_identified_provisioned_pair_pinned
        (fixture.pair, &pinned_identity, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY,
            &result), ==, WYRELOG_E_OK);
    g_assert_cmpuint (context.calls, ==, calls_after_attack);
  }
}

struct PinnedControlTrace
{
  guint calls;
  guint fired;
};

static void
trace_pinned_control (WylFactStorePinnedRendezvous rendezvous,
    gpointer user_data)
{
  auto *trace = static_cast<PinnedControlTrace *> (user_data);
  trace->calls++;
  trace->fired |= 1U << static_cast<guint> (rendezvous);
}

static void
test_provisioned_pair_pinned_control_isolation (void)
{
  {
    Fixture generic_fixture (false);
    ProvisionedPairFixture pair_fixture;
    PairPreflightAction pair_trace = {
      pair_fixture.stage_path, FALSE, 0
    };
    wyl_fact_store_pinned_set_pair_preflight_hook_for_test
        (pair_preflight_action, &pair_trace);
    wyl_fact_store_pinned_set_pair_preflight_error_for_test
        (WYL_FACT_STORE_PAIR_PREFLIGHT_PRE_FACTORY, WYRELOG_E_POLICY);

    WylFactStoreIdentityResult result =
        WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    g_assert_cmpint (wyl_fact_store_open_identified_pinned
        (generic_fixture.namespace_, &pinned_identity,
            WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &result), ==,
        WYRELOG_E_OK);
    g_assert_cmpuint (pair_trace.calls, ==, 0);

    g_assert_cmpint (wyl_fact_store_open_identified_provisioned_pair_pinned
        (pair_fixture.pair, &pinned_identity,
            WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &result), ==,
        WYRELOG_E_POLICY);
    g_assert_cmpuint (pair_trace.calls, ==, 1);

    g_assert_cmpint (wyl_fact_store_open_identified_provisioned_pair_pinned
        (pair_fixture.pair, &pinned_identity,
            WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &result), ==,
        WYRELOG_E_OK);
    g_assert_cmpuint (pair_trace.calls, ==, 1);
  }

  {
    Fixture generic_fixture (false);
    ProvisionedPairFixture pair_fixture;
    PinnedControlTrace generic_trace = { 0, 0 };
    wyl_fact_store_pinned_set_test_hook (trace_pinned_control,
        &generic_trace);
    wyl_fact_store_pinned_set_test_stage_errors (WYRELOG_E_OK,
        WYRELOG_E_OK, WYRELOG_E_POLICY);

    WylFactStoreIdentityResult result =
        WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    g_assert_cmpint (wyl_fact_store_open_identified_provisioned_pair_pinned
        (pair_fixture.pair, &pinned_identity,
            WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &result), ==,
        WYRELOG_E_OK);
    g_assert_cmpuint (generic_trace.calls, ==, 0);

    g_assert_cmpint (wyl_fact_store_open_identified_pinned
        (generic_fixture.namespace_, &pinned_identity,
            WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &result), ==,
        WYRELOG_E_POLICY);
    g_assert_cmpuint (generic_trace.calls, ==, 6);
    g_assert_cmpuint (generic_trace.fired, ==, (1U << 6) - 1);

    g_assert_cmpint (wyl_fact_store_open_identified_pinned
        (generic_fixture.namespace_, &pinned_identity,
            WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, &result), ==,
        WYRELOG_E_OK);
    g_assert_cmpuint (generic_trace.calls, ==, 6);
  }
}

static void
test_pinned_identified_modes_and_identity (void)
{
  Fixture fixture (false, true);
  WylFactStoreIdentityResult result =
      WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
  g_autofree gchar *main_path =
      g_build_filename (fixture.graph_path, "facts.duckdb", nullptr);
  struct stat initial_status;
  g_assert_cmpint (g_stat (main_path, &initial_status), ==, 0);
  g_assert_cmpint (initial_status.st_size, ==, 0);

  g_assert_cmpint (wyl_fact_store_open_identified_pinned (fixture.namespace_,
          &pinned_identity, WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
          &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_NONE);
  g_assert_cmpint (wyl_fact_store_open_identified_pinned (fixture.namespace_,
          &pinned_identity, WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
          &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_NONE);
  g_assert_cmpint (wyl_fact_store_open_identified_pinned (fixture.namespace_,
          &pinned_identity, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, &result),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_NONE);

  WylFactStoreIdentity foreign = pinned_identity;
  foreign.graph_id = "foreign";
  g_assert_cmpint (wyl_fact_store_open_identified_pinned (fixture.namespace_,
          &foreign, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, &result), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_IDENTITY);

  const gint invalid_modes[] = { -1, 2, G_MAXINT };
  for (gsize i = 0; i < G_N_ELEMENTS (invalid_modes); i++) {
    result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    g_assert_cmpint (wyl_fact_store_open_identified_pinned (fixture.namespace_,
            &pinned_identity,
            static_cast<WylFactStoreIdentityOpenMode> (invalid_modes[i]),
            &result), ==, WYRELOG_E_INVALID);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_NONE);
  }
  result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
  g_assert_cmpint (wyl_fact_store_open_identified_pinned (nullptr,
          &pinned_identity, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, &result),
      ==, WYRELOG_E_INVALID);
  g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_NONE);

  g_autofree gchar *wal =
      g_build_filename (fixture.graph_path, "facts.duckdb.wal", nullptr);
  g_assert_false (g_file_test (wal, G_FILE_TEST_EXISTS));
  g_autoptr (GDir) directory = g_dir_open (fixture.graph_path, 0, nullptr);
  g_assert_nonnull (directory);
  const gchar *name;
  while ((name = g_dir_read_name (directory)) != nullptr)
    g_assert_false (g_str_has_prefix (name, ".facts.duckdb.tmp."));
}

static void
test_pinned_validate_only_does_not_initialize (void)
{
  Fixture fixture (false);
  WylFactStoreIdentityResult result =
      WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
  g_assert_cmpint (wyl_fact_store_open_identified_pinned (fixture.namespace_,
          &pinned_identity, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, &result),
      ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA);

  g_autofree gchar *main_path =
      g_build_filename (fixture.graph_path, "facts.duckdb", nullptr);
  duckdb::DuckDB database (main_path);
  duckdb::Connection connection (database);
  auto count = connection.Query (
      "SELECT CAST(COUNT(*) AS BIGINT) FROM duckdb_tables() "
      "WHERE NOT internal");
  g_assert_false (count->HasError ());
  g_assert_cmpint (count->GetValue (0, 0).GetValue<int64_t> (), ==, 0);
}

static void
test_pinned_initialization_faults_roll_back (void)
{
  for (gint fault = WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_CREATE;
      fault <= WYL_FACT_STORE_IDENTITY_TEST_FAULT_BEFORE_COMMIT; fault++) {
    Fixture fixture (false);
    wyl_fact_store_identity_set_test_fault (
      static_cast<WylFactStoreIdentityTestFault> (fault));
    WylFactStoreIdentityResult result =
        WYL_FACT_STORE_IDENTITY_RESULT_NONE;
    g_assert_cmpint (wyl_fact_store_open_identified_pinned (fixture.namespace_,
            &pinned_identity, WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
            &result), ==, WYRELOG_E_INTERNAL);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL);
    g_assert_cmpint (wyl_fact_store_open_identified_pinned (fixture.namespace_,
            &pinned_identity, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, &result),
        ==, WYRELOG_E_POLICY);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA);
    g_assert_cmpint (wyl_fact_store_open_identified_pinned (fixture.namespace_,
            &pinned_identity, WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
            &result), ==, WYRELOG_E_OK);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_NONE);
  }
  {
    Fixture fixture (false);
    wyl_fact_store_identity_set_test_fault (
      WYL_FACT_STORE_IDENTITY_TEST_FAULT_COMMIT);
    WylFactStoreIdentityResult result =
        WYL_FACT_STORE_IDENTITY_RESULT_NONE;
    g_assert_cmpint (wyl_fact_store_open_identified_pinned (fixture.namespace_,
            &pinned_identity, WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
            &result), ==, WYRELOG_E_IO);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_OPEN);
    g_assert_cmpint (wyl_fact_store_open_identified_pinned (fixture.namespace_,
            &pinned_identity, WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
            &result), ==, WYRELOG_E_OK);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_NONE);
  }
  {
    Fixture fixture (false);
    wyl_fact_store_identity_set_test_fault (
      WYL_FACT_STORE_IDENTITY_TEST_FAULT_COMMIT_AND_ROLLBACK);
    WylFactStoreIdentityResult result =
        WYL_FACT_STORE_IDENTITY_RESULT_NONE;
    g_assert_cmpint (wyl_fact_store_open_identified_pinned (fixture.namespace_,
            &pinned_identity, WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
            &result), ==, WYRELOG_E_INTERNAL);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL);
  }
}

struct PinnedRendezvousTrace
{
  guint fired = 0;
  WylFactStorePinnedRendezvous substitute_at =
      WYL_FACT_STORE_PINNED_RENDEZVOUS_R5_FINAL_REVALIDATE;
  const gchar *main_path = nullptr;
  const gchar *saved_path = nullptr;
  WylFactArtifactNamespace *namespace_ = nullptr;
  gboolean substituted = FALSE;
};

static void
pinned_rendezvous_hook (WylFactStorePinnedRendezvous rendezvous,
    gpointer user_data)
{
  auto *trace = static_cast<PinnedRendezvousTrace *> (user_data);
  trace->fired |= 1U << static_cast<guint> (rendezvous);
  if (rendezvous != trace->substitute_at)
    return;
  if (rendezvous == WYL_FACT_STORE_PINNED_RENDEZVOUS_R5_FINAL_REVALIDATE) {
    WylFactArtifactMutationLease *lease = nullptr;
    g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
          (trace->namespace_, &lease), ==, WYRELOG_E_BUSY);
    g_assert_null (lease);
  }
  g_assert_cmpint (g_rename (trace->main_path, trace->saved_path), ==, 0);
  g_assert_true (g_file_set_contents (trace->main_path, "attacker", -1,
      nullptr));
  g_assert_cmpint (g_chmod (trace->main_path, 0600), ==, 0);
  trace->substituted = TRUE;
}

static void
test_pinned_rendezvous_substitution_fails_closed (void)
{
  const WylFactStorePinnedRendezvous stages[] = {
    WYL_FACT_STORE_PINNED_RENDEZVOUS_R3_POSTIDENTITY,
    WYL_FACT_STORE_PINNED_RENDEZVOUS_R4_PREFINALIZE,
    WYL_FACT_STORE_PINNED_RENDEZVOUS_R5_FINAL_REVALIDATE,
  };
  for (const auto stage:stages) {
    Fixture fixture (false);
    g_autofree gchar *main_path =
        g_build_filename (fixture.graph_path, "facts.duckdb", nullptr);
    g_autofree gchar *saved_path =
        g_build_filename (fixture.graph_path, "facts.duckdb.saved", nullptr);
    PinnedRendezvousTrace trace;
    trace.substitute_at = stage;
    trace.main_path = main_path;
    trace.saved_path = saved_path;
    trace.namespace_ = fixture.namespace_;
    wyl_fact_store_pinned_set_test_hook (pinned_rendezvous_hook, &trace);
    WylFactStoreIdentityResult result =
        WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    g_assert_cmpint (wyl_fact_store_open_identified_pinned (fixture.namespace_,
            &pinned_identity, WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
            &result), ==, WYRELOG_E_POLICY);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL);
    g_assert_true (trace.substituted);
    g_assert_cmpuint (trace.fired, ==, (1U << 6) - 1);
    assert_file_contents (main_path, "attacker");
    g_assert_cmpint (g_remove (main_path), ==, 0);
    g_assert_cmpint (g_rename (saved_path, main_path), ==, 0);
  }
}

static void
pinned_finalize_fault_hook (WylFactStorePinnedRendezvous rendezvous,
    gpointer user_data)
{
  gboolean *fired = static_cast<gboolean *> (user_data);
  if (rendezvous != WYL_FACT_STORE_PINNED_RENDEZVOUS_R4_PREFINALIZE)
    return;
  *fired = TRUE;
  wyl_secure_duckdb_filesystem_set_test_faults (
    WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_CHECKED_CLOSE_REVALIDATION);
}

static void
test_pinned_lifecycle_precedence (void)
{
  struct PrecedenceCase
  {
    wyrelog_error_t authority_error;
    wyrelog_error_t finalize_error;
    wyrelog_error_t r5_error;
    wyrelog_error_t expected;
  };
  const PrecedenceCase cases[] = {
    { WYRELOG_E_IO, WYRELOG_E_NOMEM, WYRELOG_E_POLICY, WYRELOG_E_NOMEM },
    { WYRELOG_E_IO, WYRELOG_E_OK, WYRELOG_E_POLICY, WYRELOG_E_POLICY },
    { WYRELOG_E_IO, WYRELOG_E_OK, WYRELOG_E_OK, WYRELOG_E_IO },
    { WYRELOG_E_OK, WYRELOG_E_OK, WYRELOG_E_OK, WYRELOG_E_INTERNAL },
  };
  for (gsize case_index = 0; case_index < G_N_ELEMENTS (cases);
      case_index++) {
    const auto &test_case = cases[case_index];
    g_test_message ("corpus SQL case %" G_GSIZE_FORMAT, case_index);
    Fixture fixture (false);
    wyl_fact_store_identity_set_test_fault (
      WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_CREATE);
    wyl_fact_store_pinned_set_test_stage_errors (test_case.authority_error,
        test_case.finalize_error, test_case.r5_error);
    WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_NONE;
    g_assert_cmpint (wyl_fact_store_open_identified_pinned (fixture.namespace_,
            &pinned_identity, WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
            &result), ==, test_case.expected);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL);
  }

  {
    Fixture fixture (false);
    gboolean fired = FALSE;
    wyl_fact_store_pinned_set_test_hook (pinned_finalize_fault_hook, &fired);
    WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_NONE;
    g_assert_cmpint (wyl_fact_store_open_identified_pinned (fixture.namespace_,
            &pinned_identity, WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
            &result), ==, WYRELOG_E_POLICY);
    g_assert_true (fired);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL);
  }

  {
    Fixture fixture (false);
    wyl_secure_duckdb_filesystem_set_test_faults (
      WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_HANDLE_ALLOCATION
      | WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_CHECKED_CLOSE_REVALIDATION);
    WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_NONE;
    g_assert_cmpint (wyl_fact_store_open_identified_pinned (fixture.namespace_,
            &pinned_identity, WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
            &result), ==, WYRELOG_E_POLICY);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL);
  }
}

static void
test_pinned_provider_open_seams_fail_closed (void)
{
  const WylFactArtifactNamespaceTestFault faults[] = {
    WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_MAIN_OPEN_ABA,
    WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_MAIN_BINDING_POST_OPEN_SUBSTITUTE,
  };
  const WylFactStoreIdentityOpenMode modes[] = {
    WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
    WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY,
  };
  for (const auto fault:faults) {
    for (const auto mode:modes) {
      Fixture fixture (false);
      if (mode == WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY) {
        WylFactStoreIdentityResult initialized =
            WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
        g_assert_cmpint (wyl_fact_store_open_identified_pinned
              (fixture.namespace_, &pinned_identity,
              WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &initialized), ==,
            WYRELOG_E_OK);
      }
      g_autofree gchar *main_path =
          g_build_filename (fixture.graph_path, "facts.duckdb", nullptr);
      struct stat before;
      g_assert_cmpint (g_stat (main_path, &before), ==, 0);
      g_autofree gchar *before_bytes = nullptr;
      gsize before_length = 0;
      g_assert_true (g_file_get_contents (main_path, &before_bytes,
          &before_length, nullptr));

      wyl_fact_artifact_namespace_set_test_fault (fault);
      WylFactStoreIdentityResult result =
          WYL_FACT_STORE_IDENTITY_RESULT_NONE;
      g_assert_cmpint (wyl_fact_store_open_identified_pinned
            (fixture.namespace_, &pinned_identity, mode, &result), ==,
          WYRELOG_E_POLICY);
      g_assert_true (wyl_fact_artifact_namespace_test_fault_was_consumed
            (fault));

      struct stat after;
      g_assert_cmpint (g_stat (main_path, &after), ==, 0);
      g_autofree gchar *after_bytes = nullptr;
      gsize after_length = 0;
      g_assert_true (g_file_get_contents (main_path, &after_bytes,
          &after_length, nullptr));
      if (fault == WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_MAIN_OPEN_ABA) {
        g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL);
        g_assert_cmpuint (after.st_dev, ==, before.st_dev);
        g_assert_cmpuint (after.st_ino, ==, before.st_ino);
        g_assert_cmpuint (after_length, ==, before_length);
        g_assert_cmpmem (after_bytes, after_length, before_bytes,
            before_length);
      } else {
        g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL);
        g_assert_true (S_ISREG (after.st_mode));
        g_assert_cmpuint (after.st_mode & 07777, ==, 0600);
        g_assert_cmpuint (after.st_nlink, ==, 1);
        g_assert_true (after.st_dev != before.st_dev
            || after.st_ino != before.st_ino);
        g_assert_cmpuint (after_length, ==, 0);
        g_assert_true (g_file_set_contents (main_path, "provider-decoy", -1,
            nullptr));
        assert_file_contents (main_path, "provider-decoy");
      }

      g_autoptr (GDir) graph = g_dir_open (fixture.graph_path, 0, nullptr);
      g_assert_nonnull (graph);
      for (const gchar *name; (name = g_dir_read_name (graph)) != nullptr;) {
        g_assert_false (g_str_has_prefix (name, ".duckdb-private-temp-"));
        g_assert_cmpstr (name, !=, "facts.duckdb.wal");
        g_assert_cmpstr (name, !=, "facts.duckdb.wal.checkpoint");
        g_assert_cmpstr (name, !=, "facts.duckdb.wal.recovery");
      }
    }
  }
}

static void
assert_pathname_pinned_validation_parity (Fixture &fixture,
    WylFactStoreIdentityResult expected)
{
  g_autofree gchar *main_path =
      g_build_filename (fixture.graph_path, "facts.duckdb", nullptr);
  const WylFactStoreIdentityOpenMode modes[] = {
    WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY,
    WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
  };
  for (const auto mode:modes) {
    WylFactStoreIdentityResult pathname_result =
        WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    wyl_fact_store_t *store = nullptr;
    wyrelog_error_t pathname_rc = wyl_fact_store_open_identified (main_path,
        &pinned_identity, mode, &pathname_result, &store);
    wyl_fact_store_close (store);
    WylFactStoreIdentityResult pinned_result =
        WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    wyrelog_error_t pinned_rc =
        wyl_fact_store_open_identified_pinned (fixture.namespace_,
        &pinned_identity, mode, &pinned_result);
    g_assert_cmpint (pinned_rc, ==, pathname_rc);
    g_assert_cmpint (pathname_result, ==, expected);
    g_assert_cmpint (pinned_result, ==, expected);
  }
}

static void
test_pinned_pathname_identity_corpus_parity (void)
{
  struct CorpusCase
  {
    const gchar *sql;
    WylFactStoreIdentityResult result;
  };
  const CorpusCase cases[] = {
    {
      "UPDATE fact_store_metadata SET value='2' "
          "WHERE key='format_version';",
      WYL_FACT_STORE_IDENTITY_RESULT_FORMAT,
    },
    {
      "UPDATE fact_store_metadata SET value='01' "
          "WHERE key='format_version';",
      WYL_FACT_STORE_IDENTITY_RESULT_FORMAT,
    },
    {
      "UPDATE fact_store_metadata SET value='0' "
          "WHERE key='format_version';",
      WYL_FACT_STORE_IDENTITY_RESULT_FORMAT,
    },
    {
      "UPDATE fact_store_metadata SET value='9223372036854775808' "
          "WHERE key='format_version';",
      WYL_FACT_STORE_IDENTITY_RESULT_FORMAT,
    },
    {
      "UPDATE fact_store_metadata SET value='2' "
          "WHERE key='path_encoding_version';",
      WYL_FACT_STORE_IDENTITY_RESULT_PATH_ENCODING,
    },
    {
      "UPDATE fact_store_metadata SET value='01' "
          "WHERE key='path_encoding_version';",
      WYL_FACT_STORE_IDENTITY_RESULT_PATH_ENCODING,
    },
    {
      "UPDATE fact_store_metadata SET value='0' "
          "WHERE key='path_encoding_version';",
      WYL_FACT_STORE_IDENTITY_RESULT_PATH_ENCODING,
    },
    {
      "UPDATE fact_store_metadata SET value='9223372036854775808' "
          "WHERE key='path_encoding_version';",
      WYL_FACT_STORE_IDENTITY_RESULT_PATH_ENCODING,
    },
    {
      "UPDATE fact_store_metadata SET value="
          "'01890F47-3c4b-6cc2-b8c4-dc0c0c073989' "
          "WHERE key='store_uuid';",
      WYL_FACT_STORE_IDENTITY_RESULT_IDENTITY,
    },
    {
      "INSERT INTO fact_store_metadata VALUES ('unknown','value');",
      WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA,
    },
    {
      "DELETE FROM fact_store_metadata WHERE key='graph_id';",
      WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA,
    },
    {
      "DROP TABLE fact_store_metadata;"
          "CREATE TABLE fact_store_metadata(key VARCHAR,value VARCHAR NOT NULL);"
          "INSERT INTO fact_store_metadata VALUES"
          "('store_kind','wyrelog.fact'),('store_kind','wyrelog.fact'),"
          "('format_version','1'),"
          "('store_uuid','01890f47-3c4b-6cc2-b8c4-dc0c0c073989'),"
          "('path_encoding_version','1'),('tenant_id','tenant'),"
          "('graph_id','graph');",
      WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA,
    },
    {
      "DROP TABLE fact_store_metadata;"
          "CREATE TABLE fact_store_metadata("
          "key VARCHAR PRIMARY KEY,value VARCHAR);"
          "INSERT INTO fact_store_metadata VALUES"
          "('store_kind','wyrelog.fact'),('format_version','1'),"
          "('store_uuid','01890f47-3c4b-6cc2-b8c4-dc0c0c073989'),"
          "('path_encoding_version','1'),('tenant_id',NULL),"
          "('graph_id','graph');",
      WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA,
    },
    {
      "ALTER TABLE fact_store_metadata ADD COLUMN extra VARCHAR;",
      WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA,
    },
    {
      "ALTER TABLE fact_store_metadata ALTER value SET DEFAULT 'x';",
      WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA,
    },
    {
      "CREATE INDEX extra_metadata_index "
          "ON fact_store_metadata(value);",
      WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA,
    },
    {
      "DROP TABLE fact_store_metadata;"
          "CREATE TABLE fact_store_metadata("
          "key VARCHAR COLLATE nocase PRIMARY KEY,"
          "value VARCHAR COLLATE nocase NOT NULL);"
          "INSERT INTO fact_store_metadata VALUES"
          "('store_kind','wyrelog.fact'),('format_version','1'),"
          "('store_uuid','01890f47-3c4b-6cc2-b8c4-dc0c0c073989'),"
          "('path_encoding_version','1'),('tenant_id','tenant'),"
          "('graph_id','graph');",
      WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA,
    },
    {
      "DROP TABLE fact_store_metadata;"
          "CREATE TABLE fact_store_metadata("
          "key VARCHAR NOT NULL,value VARCHAR NOT NULL,"
          "PRIMARY KEY(key,value));"
          "INSERT INTO fact_store_metadata VALUES"
          "('store_kind','wyrelog.fact'),"
          "('format_version','1'),"
          "('store_uuid','01890f47-3c4b-6cc2-b8c4-dc0c0c073989'),"
          "('path_encoding_version','1'),"
          "('tenant_id','tenant'),"
          "('graph_id','graph');",
      WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA,
    },
    {
      "CREATE TABLE audit_events(seq BIGINT PRIMARY KEY);",
      WYL_FACT_STORE_IDENTITY_RESULT_IDENTITY,
    },
  };
  for (const auto &test_case:cases) {
    Fixture fixture (false);
    WylFactStoreIdentityResult result =
        WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    g_assert_cmpint (wyl_fact_store_open_identified_pinned (fixture.namespace_,
            &pinned_identity, WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
            &result), ==, WYRELOG_E_OK);
    g_autofree gchar *main_path =
        g_build_filename (fixture.graph_path, "facts.duckdb", nullptr);
    {
      duckdb::DuckDB database (main_path);
      duckdb::Connection connection (database);
      assert_query_ok (connection, test_case.sql);
    }
    assert_pathname_pinned_validation_parity (fixture, test_case.result);
  }

  const duckdb::string raw_values[] = {
    duckdb::string ("tenant\0-x", 9),
  };
  for (gsize raw_index = 0; raw_index < G_N_ELEMENTS (raw_values);
      raw_index++) {
    const auto &raw_value = raw_values[raw_index];
    g_test_message ("corpus raw case %" G_GSIZE_FORMAT, raw_index);
    Fixture fixture (false);
    WylFactStoreIdentityResult result =
        WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    g_assert_cmpint (wyl_fact_store_open_identified_pinned (fixture.namespace_,
            &pinned_identity, WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
            &result), ==, WYRELOG_E_OK);
    g_autofree gchar *main_path =
        g_build_filename (fixture.graph_path, "facts.duckdb", nullptr);
    {
      duckdb::DuckDB database (main_path);
      duckdb::Connection connection (database);
      auto statement = connection.Prepare (
          "UPDATE fact_store_metadata SET value=? WHERE key='tenant_id'");
      g_assert_nonnull (statement);
      g_assert_false (statement->HasError ());
      duckdb::vector<duckdb::Value> values;
      values.emplace_back (raw_value);
      auto update = statement->Execute (values, false);
      g_assert_nonnull (update);
      g_assert_false (update->HasError ());
    }
    assert_pathname_pinned_validation_parity (fixture,
        WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA);
  }

  {
    Fixture fixture (false);
    g_autofree gchar *main_path =
        g_build_filename (fixture.graph_path, "facts.duckdb", nullptr);
    WylFactStoreIdentity invalid_utf8 = pinned_identity;
    invalid_utf8.tenant_id = "tenant-\xff";
    const WylFactStoreIdentityOpenMode modes[] = {
      WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY,
      WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
    };
    for (const auto mode:modes) {
      WylFactStoreIdentityResult pathname_result =
          WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
      wyl_fact_store_t *store = nullptr;
      g_assert_cmpint (wyl_fact_store_open_identified (main_path,
              &invalid_utf8, mode, &pathname_result, &store), ==,
          WYRELOG_E_INVALID);
      g_assert_null (store);
      g_assert_cmpint (pathname_result, ==,
          WYL_FACT_STORE_IDENTITY_RESULT_NONE);
      WylFactStoreIdentityResult pinned_result =
          WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
      g_assert_cmpint (wyl_fact_store_open_identified_pinned (
              fixture.namespace_, &invalid_utf8, mode, &pinned_result), ==,
          WYRELOG_E_INVALID);
      g_assert_cmpint (pinned_result, ==,
          WYL_FACT_STORE_IDENTITY_RESULT_NONE);
    }
  }
}

struct PinnedSwapSeam
{
  WylFactStorePinnedRendezvous at;
  const gchar *source;
  const gchar *saved;
  const gchar *attacker;
  gboolean parent;
  gboolean fired;
};

static void
pinned_swap_seam_hook (WylFactStorePinnedRendezvous rendezvous,
    gpointer user_data)
{
  auto *seam = static_cast<PinnedSwapSeam *> (user_data);
  if (rendezvous != seam->at)
    return;
  seam->fired = TRUE;
  g_assert_cmpint (g_rename (seam->source, seam->saved), ==, 0);
  if (seam->parent) {
    g_assert_cmpint (g_mkdir (seam->source, 0700), ==, 0);
    g_autofree gchar *decoy =
        g_build_filename (seam->source, "facts.duckdb", nullptr);
    g_assert_true (g_file_set_contents (decoy, "parent-decoy", -1, nullptr));
    g_assert_cmpint (g_chmod (decoy, 0600), ==, 0);
  } else {
    g_assert_cmpint (symlink (seam->attacker, seam->source), ==, 0);
  }
}

static void
test_pinned_symlink_and_parent_decoys_fail_closed (void)
{
  {
    Fixture fixture (false);
    g_autofree gchar *main_path =
        g_build_filename (fixture.graph_path, "facts.duckdb", nullptr);
    g_autofree gchar *saved_path =
        g_build_filename (fixture.graph_path, "facts.duckdb.saved", nullptr);
    g_autofree gchar *attacker =
        g_build_filename (fixture.root, "attacker.duckdb", nullptr);
    g_assert_true (g_file_set_contents (attacker, "attacker", -1, nullptr));
    PinnedSwapSeam seam = {
      WYL_FACT_STORE_PINNED_RENDEZVOUS_R0_PRECONSTRUCT,
      main_path, saved_path, attacker, FALSE, FALSE
    };
    wyl_fact_store_pinned_set_test_hook (pinned_swap_seam_hook, &seam);
    WylFactStoreIdentityResult result =
        WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    g_assert_cmpint (wyl_fact_store_open_identified_pinned (fixture.namespace_,
            &pinned_identity, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, &result),
        ==, WYRELOG_E_POLICY);
    g_assert_true (seam.fired);
    assert_file_contents (attacker, "attacker");
    g_assert_cmpint (g_remove (main_path), ==, 0);
    g_assert_cmpint (g_rename (saved_path, main_path), ==, 0);
    g_assert_cmpint (g_remove (attacker), ==, 0);
  }
  {
    Fixture fixture (false);
    g_autofree gchar *saved_graph =
        g_strdup_printf ("%s.saved", fixture.graph_path);
    PinnedSwapSeam seam = {
      WYL_FACT_STORE_PINNED_RENDEZVOUS_R0_PRECONSTRUCT,
      fixture.graph_path, saved_graph, nullptr, TRUE, FALSE
    };
    wyl_fact_store_pinned_set_test_hook (pinned_swap_seam_hook, &seam);
    WylFactStoreIdentityResult result =
        WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    g_assert_cmpint (wyl_fact_store_open_identified_pinned (fixture.namespace_,
            &pinned_identity, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, &result),
        ==, WYRELOG_E_POLICY);
    g_assert_true (seam.fired);
    g_autofree gchar *decoy =
        g_build_filename (fixture.graph_path, "facts.duckdb", nullptr);
    assert_file_contents (decoy, "parent-decoy");
    g_assert_cmpint (g_remove (decoy), ==, 0);
    g_assert_cmpint (g_rmdir (fixture.graph_path), ==, 0);
    g_assert_cmpint (g_rename (saved_graph, fixture.graph_path), ==, 0);
  }
}

struct PinnedHold
{
  GMutex mutex;
  GCond cond;
  gboolean reached;
  gboolean release;
};

static void
pinned_hold_hook (WylFactStorePinnedRendezvous rendezvous, gpointer user_data)
{
  if (rendezvous != WYL_FACT_STORE_PINNED_RENDEZVOUS_R2_PREIDENTITY)
    return;
  auto *hold = static_cast<PinnedHold *> (user_data);
  g_mutex_lock (&hold->mutex);
  hold->reached = TRUE;
  g_cond_broadcast (&hold->cond);
  while (!hold->release)
    g_cond_wait (&hold->cond, &hold->mutex);
  g_mutex_unlock (&hold->mutex);
}

struct IdentityOpenThread
{
  WylFactArtifactNamespace *namespace_;
  const gchar *path;
  gboolean pinned;
  wyrelog_error_t rc;
  WylFactStoreIdentityResult result;
};

static gpointer
identity_open_thread (gpointer user_data)
{
  auto *thread = static_cast<IdentityOpenThread *> (user_data);
  if (thread->pinned) {
    thread->rc =
        wyl_fact_store_open_identified_pinned (thread->namespace_,
        &pinned_identity, WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
        &thread->result);
  } else {
    wyl_fact_store_t *store = nullptr;
    thread->rc = wyl_fact_store_open_identified (thread->path,
        &pinned_identity, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY,
        &thread->result, &store);
    wyl_fact_store_close (store);
  }
  return nullptr;
}

struct IdentityGuardTrace
{
  GMutex mutex;
  GCond cond;
  gboolean before_lock;
  gboolean after_lock;
};

static void
identity_guard_hook (WylFactStoreIdentityGuardTestStage stage,
    gpointer user_data)
{
  auto *trace = static_cast<IdentityGuardTrace *> (user_data);
  g_mutex_lock (&trace->mutex);
  if (stage == WYL_FACT_STORE_IDENTITY_GUARD_BEFORE_LOCK)
    trace->before_lock = TRUE;
  else
    trace->after_lock = TRUE;
  g_cond_broadcast (&trace->cond);
  g_mutex_unlock (&trace->mutex);
}

static void
run_pinned_serialization_case (gboolean second_pinned)
{
  Fixture fixture (false);
  g_autofree gchar *main_path =
      g_build_filename (fixture.graph_path, "facts.duckdb", nullptr);
  PinnedHold hold;
  g_mutex_init (&hold.mutex);
  g_cond_init (&hold.cond);
  hold.reached = FALSE;
  hold.release = FALSE;
  wyl_fact_store_pinned_set_test_hook (pinned_hold_hook, &hold);
  IdentityOpenThread first = {
    fixture.namespace_, main_path, TRUE, WYRELOG_E_INTERNAL,
    WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL
  };
  IdentityOpenThread second = {
    fixture.namespace_, main_path, second_pinned, WYRELOG_E_INTERNAL,
    WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL
  };
  GThread *first_thread =
      g_thread_new ("pinned-first", identity_open_thread, &first);
  g_mutex_lock (&hold.mutex);
  while (!hold.reached)
    g_cond_wait (&hold.cond, &hold.mutex);
  g_mutex_unlock (&hold.mutex);
  IdentityGuardTrace guard;
  g_mutex_init (&guard.mutex);
  g_cond_init (&guard.cond);
  guard.before_lock = FALSE;
  guard.after_lock = FALSE;
  wyl_fact_store_identity_process_guard_set_test_hook (identity_guard_hook,
      &guard);
  GThread *second_thread =
      g_thread_new ("identity-second", identity_open_thread, &second);
  g_mutex_lock (&guard.mutex);
  while (!guard.before_lock)
    g_cond_wait (&guard.cond, &guard.mutex);
  g_assert_false (guard.after_lock);
  g_mutex_unlock (&guard.mutex);
  g_mutex_lock (&hold.mutex);
  hold.release = TRUE;
  g_cond_broadcast (&hold.cond);
  g_mutex_unlock (&hold.mutex);
  g_thread_join (first_thread);
  g_thread_join (second_thread);
  g_assert_true (guard.after_lock);
  g_assert_cmpint (first.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (second.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (first.result, ==, WYL_FACT_STORE_IDENTITY_RESULT_NONE);
  g_assert_cmpint (second.result, ==, WYL_FACT_STORE_IDENTITY_RESULT_NONE);
  g_cond_clear (&hold.cond);
  g_mutex_clear (&hold.mutex);
  g_cond_clear (&guard.cond);
  g_mutex_clear (&guard.mutex);
}

static void
test_pinned_identity_process_serialization (void)
{
  run_pinned_serialization_case (TRUE);
  run_pinned_serialization_case (FALSE);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, nullptr);
  g_test_add_func ("/secure-duckdb-filesystem/main-wal-lock-bridge",
      test_real_main_wal_lock_and_bridge);
  g_test_add_func ("/secure-duckdb-filesystem/bridge-modes",
      test_bridge_modes_are_real_and_bounded);
  g_test_add_func ("/secure-duckdb-filesystem/fixed-wal-replacement-grammars",
      test_fixed_wal_replacement_grammars_and_live_detach);
  g_test_add_func ("/secure-duckdb-filesystem/terminal-replacement-poison",
      test_terminal_wal_replacement_poison_has_no_retry);
  g_test_add_func ("/secure-duckdb-filesystem/replacement-substitution",
      test_wal_replacement_source_substitution_fails_closed);
  g_test_add_func (
    "/secure-duckdb-filesystem/replacement-destination-substitution",
    test_wal_replacement_destination_substitution_fails_closed);
  g_test_add_func ("/secure-duckdb-filesystem/live-sidecar-retirement",
      test_live_sidecar_retirement_detaches_handle);
  g_test_add_func ("/secure-duckdb-filesystem/pending-allocation-cleanup",
      test_pending_binding_allocation_failure_is_not_clean);
  g_test_add_func ("/secure-duckdb-filesystem/pending-close-poison",
      test_pending_binding_close_failure_poison_is_terminal);
  g_test_add_func ("/secure-duckdb-filesystem/file-exists-checked-main",
      test_file_exists_uses_checked_main_handle);
  g_test_add_func ("/secure-duckdb-filesystem/temp-registration-rollback",
      test_temp_registration_failure_rolls_back_durable_child);
  g_test_add_func ("/secure-duckdb-filesystem/bridge-construction-allocation",
      test_bridge_construction_allocation_failure_rolls_back);
  g_test_add_func ("/secure-duckdb-filesystem/destructor-finalize-poison",
      test_handle_destructor_poison_reaches_bridge_finalize);
  g_test_add_func ("/secure-duckdb-filesystem/checked-finalize",
      test_checked_finalize_reports_cleanup_failure);
  g_test_add_func ("/secure-duckdb-filesystem/wal-crash-recovery-locking",
      test_wal_crash_recovery_and_locking);
  g_test_add_func ("/secure-duckdb-filesystem/temp-spill-cleanup",
      test_real_temp_spill_cleanup);
  g_test_add_func ("/secure-duckdb-filesystem/denial-numeric",
      test_denial_and_numeric_no_mutation);
  g_test_add_func ("/secure-duckdb-filesystem/virtual-home-environment",
      test_virtual_home_and_environment_are_not_authority);
  g_test_add_func ("/secure-duckdb-filesystem/main-symlink-substitution",
      test_main_symlink_substitution_fails_closed);
  g_test_add_func ("/secure-duckdb-filesystem/pinned-identified/modes",
      test_pinned_identified_modes_and_identity);
  g_test_add_func ("/secure-duckdb-filesystem/provisioned-pair/modes",
      test_provisioned_pair_pinned_modes);
  g_test_add_func (
    "/secure-duckdb-filesystem/provisioned-pair/preflight-no-mutation",
    test_provisioned_pair_pinned_preflight_no_mutation);
  g_test_add_func (
    "/secure-duckdb-filesystem/provisioned-pair/actual-rendezvous",
    test_provisioned_pair_pinned_actual_rendezvous);
  g_test_add_func (
    "/secure-duckdb-filesystem/provisioned-pair/control-isolation",
    test_provisioned_pair_pinned_control_isolation);
  g_test_add_func (
    "/secure-duckdb-filesystem/pinned-identified/validate-no-write",
    test_pinned_validate_only_does_not_initialize);
  g_test_add_func (
    "/secure-duckdb-filesystem/pinned-identified/init-fault-rollback",
    test_pinned_initialization_faults_roll_back);
  g_test_add_func (
    "/secure-duckdb-filesystem/pinned-identified/rendezvous-substitution",
    test_pinned_rendezvous_substitution_fails_closed);
  g_test_add_func (
    "/secure-duckdb-filesystem/pinned-identified/lifecycle-precedence",
    test_pinned_lifecycle_precedence);
  g_test_add_func (
    "/secure-duckdb-filesystem/pinned-identified/provider-open-seams",
    test_pinned_provider_open_seams_fail_closed);
  g_test_add_func (
    "/secure-duckdb-filesystem/pinned-identified/pathname-corpus-parity",
    test_pinned_pathname_identity_corpus_parity);
  g_test_add_func (
    "/secure-duckdb-filesystem/pinned-identified/symlink-parent-decoys",
    test_pinned_symlink_and_parent_decoys_fail_closed);
  g_test_add_func (
    "/secure-duckdb-filesystem/pinned-identified/process-serialization",
    test_pinned_identity_process_serialization);
  return g_test_run ();
}

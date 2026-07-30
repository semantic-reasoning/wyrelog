/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _POSIX_C_SOURCE 200809L

#include <duckdb.hpp>
#include <glib.h>
#include <glib/gstdio.h>

#include <climits>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "fact/secure-duckdb-bridge-private.h"
#include "fact/secure-duckdb-filesystem-private.hpp"

namespace fs = std::filesystem;

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

  explicit Fixture (bool populated = true) {
    g_autoptr (GError) error = nullptr;
    root = g_dir_make_tmp ("wyl-secure-filesystem-XXXXXX", &error);
    g_assert_no_error (error);
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
  }
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
    filesystem.Write (*main, &sentinel, 1,
        static_cast < duckdb::idx_t > (LLONG_MAX));
    g_assert_not_reached ();
  } catch (const duckdb::IOException &)
  {
  }
  g_assert_cmpint (filesystem.GetFileSize (*main), ==, original_size);
  g_assert_cmpuint (filesystem.SeekPosition (*main), ==, original_cursor);
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

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, nullptr);
  g_test_add_func ("/secure-duckdb-filesystem/main-wal-lock-bridge",
      test_real_main_wal_lock_and_bridge);
  g_test_add_func ("/secure-duckdb-filesystem/bridge-modes",
      test_bridge_modes_are_real_and_bounded);
  g_test_add_func ("/secure-duckdb-filesystem/wal-crash-recovery-locking",
      test_wal_crash_recovery_and_locking);
  g_test_add_func ("/secure-duckdb-filesystem/temp-spill-cleanup",
      test_real_temp_spill_cleanup);
  g_test_add_func ("/secure-duckdb-filesystem/denial-numeric",
      test_denial_and_numeric_no_mutation);
  g_test_add_func ("/secure-duckdb-filesystem/main-symlink-substitution",
      test_main_symlink_substitution_fails_closed);
  return g_test_run ();
}

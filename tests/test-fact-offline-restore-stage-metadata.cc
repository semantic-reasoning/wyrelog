/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>

#include <cstdint>
#ifndef G_OS_WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

#include "fact-test-support.h"
#include "test-exit-status.h"
#include "wyrelog/fact/graph-locator-private.h"
#include "wyrelog/fact/offline-restore-stage-private.h"
#include "wyrelog/fact/root-writer-lease-private.h"
#include "wyrelog/fact/secure-duckdb-bridge-private.h"
#include "wyrelog/wyl-id-private.h"

namespace {

  constexpr char store_uuid[] = "01890f47-3c4b-6cc2-b8c4-dc0c0c073989";
  constexpr char tenant_id[] = "tenant-a";
  constexpr char graph_id[] = "alpha";

  static WylFactStoreIdentity
  expected_identity (void)
  {
    return { tenant_id, graph_id, store_uuid, 1, 1 };
  }

#ifndef G_OS_WIN32
  struct Fixture
  {
    gchar *root = nullptr;
    WylFactGraphLocator locator = { 0 };
    WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
    WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
    WylFactRootWriterLease *lease = nullptr;
    gchar operation_uuid[WYL_ID_STRING_BUF] = { 0 };
    gchar *stage_path = nullptr;
  };

  static void
  remove_tree (const gchar *path)
  {
    g_autoptr (GDir) dir = g_dir_open (path, 0, nullptr);
    if (dir != nullptr) {
      const gchar *name;
      while ((name = g_dir_read_name (dir)) != nullptr) {
        g_autofree gchar *child = g_build_filename (path, name, nullptr);
        if (g_file_test (child, G_FILE_TEST_IS_DIR)
            && !g_file_test (child, G_FILE_TEST_IS_SYMLINK))
          remove_tree (child);
        else
          g_assert_cmpint (g_remove (child), ==, 0);
      }
    }
    g_assert_cmpint (g_rmdir (path), ==, 0);
  }

  static void
  fixture_init (Fixture *fixture)
  {
    fixture->root = wyl_test_make_secure_fact_root
          ("wyl-restore-metadata-XXXXXX", nullptr);
    g_assert_nonnull (fixture->root);
    g_assert_cmpint (wyl_fact_graph_locator_init (&fixture->locator,
        tenant_id, graph_id), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_graph_resolver_open (fixture->root,
        &fixture->resolver), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_graph_resolver_open_directory
          (&fixture->resolver, &fixture->locator, TRUE, &fixture->directory),
        ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_root_writer_lease_acquire (fixture->root,
        &fixture->lease), ==, WYRELOG_E_OK);
    wyl_id_t operation;
    g_assert_cmpint (wyl_id_new (&operation), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_id_format (&operation, fixture->operation_uuid,
        sizeof fixture->operation_uuid), ==, WYRELOG_E_OK);
    g_autofree gchar *basename = g_strdup_printf ("restore-%s.duckdb",
            fixture->operation_uuid);
    fixture->stage_path = wyl_fact_graph_directory_descriptive_file
          (&fixture->directory, basename);
  }

  static void
  fixture_clear (Fixture *fixture)
  {
    wyl_fact_graph_directory_clear (&fixture->directory);
    wyl_fact_graph_resolver_clear (&fixture->resolver);
    wyl_fact_root_writer_lease_release (fixture->lease);
    wyl_fact_graph_locator_clear (&fixture->locator);
    remove_tree (fixture->root);
    g_free (fixture->stage_path);
    g_free (fixture->root);
  }

  static gchar *
  checksum_text (const guint8 *bytes, gsize length)
  {
    g_autoptr (GChecksum) checksum = g_checksum_new (G_CHECKSUM_SHA256);
    g_checksum_update (checksum, bytes, length);
    return g_strdup_printf ("sha256:%s", g_checksum_get_string (checksum));
  }

  static GBytes *
  make_duckdb_payload (bool valid_metadata = true)
  {
    g_autofree gchar *dir = g_dir_make_tmp ("wyl-restore-metadata-db-XXXXXX",
            nullptr);
    g_assert_nonnull (dir);
    g_autofree gchar *path = g_build_filename (dir, "source.duckdb", nullptr);
    duckdb_database database = nullptr;
    duckdb_connection connection = nullptr;
    g_assert_cmpint (duckdb_open (path, &database), ==, DuckDBSuccess);
    g_assert_cmpint (duckdb_connect (database, &connection), ==,
        DuckDBSuccess);
    auto query = [&] (const char *sql) {
      duckdb_result result = {};
      const duckdb_state state = duckdb_query (connection, sql, &result);
      if (state != DuckDBSuccess)
        g_test_message ("DuckDB fixture query failed: %s (%s)", sql,
            duckdb_result_error (&result));
      g_assert_cmpint (state, ==, DuckDBSuccess);
      duckdb_destroy_result (&result);
    };
    if (valid_metadata) {
      query ("CREATE TABLE main.fact_store_metadata("
          "key VARCHAR PRIMARY KEY,value VARCHAR NOT NULL);");
      query ("INSERT INTO main.fact_store_metadata VALUES "
          "('store_kind','wyrelog.fact'),('format_version','1'),"
          "('store_uuid','01890f47-3c4b-6cc2-b8c4-dc0c0c073989'),"
          "('path_encoding_version','1'),('tenant_id','tenant-a'),"
          "('graph_id','alpha');");
    } else {
      query ("CREATE TABLE main.fact_store_metadata("
          "key VARCHAR,value INTEGER);");
    }
    query ("CREATE TABLE main.payload AS "
        "SELECT i, CAST(i AS VARCHAR) || '-' || CAST(i AS VARCHAR) || '-' "
        "|| CAST(i AS VARCHAR) || '-' || CAST(i AS VARCHAR) AS value "
        "FROM range(20000) r(i);");
    query ("CHECKPOINT;");
    duckdb_disconnect (&connection);
    duckdb_close (&database);

    gchar *raw = nullptr;
    gsize length = 0;
    g_assert_true (g_file_get_contents (path, &raw, &length, nullptr));
    g_assert_cmpuint (length, >, 64 * 1024);
    GBytes *bytes = g_bytes_new_take (raw, length);
    remove_tree (dir);
    return bytes;
  }

  static WylFactArtifactInventoryIdentity
  make_stage (Fixture *fixture, GBytes *payload, const gchar *checksum)
  {
    gsize length = 0;
    const auto *data = static_cast<const guint8 *>
        (g_bytes_get_data (payload, &length));
    WylFactOfflineRestoreStage *stage = nullptr;
    g_assert_cmpint (wyl_fact_offline_restore_stage_new (&fixture->resolver,
        &fixture->directory, fixture->lease, fixture->operation_uuid, length,
        checksum, &stage), ==, WYRELOG_E_OK);
    for (gsize offset = 0; offset < length;) {
      const gsize chunk = MIN (64 * 1024, length - offset);
      g_assert_cmpint (wyl_fact_offline_restore_stage_sink (offset,
          data + offset, chunk, stage), ==, WYRELOG_E_OK);
      offset += chunk;
    }
    guint64 written = 0;
    WylFactArtifactInventoryIdentity identity = {};
    g_assert_cmpint (wyl_fact_offline_restore_stage_finalize (stage, &written,
        &identity), ==, WYRELOG_E_OK);
    g_assert_cmpuint (written, ==, length);
    wyl_fact_offline_restore_stage_free (stage);
    return identity;
  }

  static void
  test_stage_identity_validation (void)
  {
    Fixture fixture;
    fixture_init (&fixture);
    g_autoptr (GBytes) payload = make_duckdb_payload ();
    gsize length = 0;
    const auto *data = static_cast<const guint8 *>
        (g_bytes_get_data (payload, &length));
    g_autofree gchar *checksum = checksum_text (data, length);
    const auto stage_identity = make_stage (&fixture, payload, checksum);

    WylFactOfflineRestoreStageReader *reader = nullptr;
    g_assert_cmpint (wyl_fact_offline_restore_stage_reader_open
          (&fixture.resolver, &fixture.directory, fixture.lease,
        fixture.operation_uuid, &stage_identity, &reader), ==, WYRELOG_E_OK);
    guint64 fs_contract = 0;
    g_assert_cmpint
      (wyl_secure_duckdb_bridge_test_restore_stage_filesystem_contract
          (reader, &fs_contract), ==, WYRELOG_E_OK);
    constexpr guint64 expected_fs_contract =
        WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_CGROUP_HIDDEN
        | WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_SECRET_PATHS_VIRTUAL
        | WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_HOST_PATH_DISPATCHED
        | WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_HOST_PATH_REJECTED
        | WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_ALIAS_REJECTED
        | WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_WRITE_REJECTED
        | WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_APPEND_REJECTED
        | WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_CREATE_REJECTED
        | WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_DIRECT_IO_REJECTED
        | WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_MUTATION_REJECTED
        | WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_PARALLEL_READ_ALLOWED
        | WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_CLOSED_HANDLE_REJECTED;
    g_assert_cmpuint (fs_contract, ==, expected_fs_contract);
    auto identity = expected_identity ();
    WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    g_assert_cmpint (wyl_secure_duckdb_bridge_validate_restore_stage_identity
          (reader, length, checksum, &identity, &result), ==, WYRELOG_E_OK);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_NONE);

    auto mismatch = identity;
    mismatch.tenant_id = "tenant-b";
    g_assert_cmpint (wyl_secure_duckdb_bridge_validate_restore_stage_identity
          (reader, length, checksum, &mismatch, &result), ==, WYRELOG_E_POLICY);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_IDENTITY);
    mismatch = identity;
    mismatch.store_uuid = "01890f47-3c4b-6cc2-b8c4-dc0c0c073988";
    g_assert_cmpint (wyl_secure_duckdb_bridge_validate_restore_stage_identity
          (reader, length, checksum, &mismatch, &result), ==, WYRELOG_E_POLICY);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_IDENTITY);
    mismatch = identity;
    mismatch.format_version = 2;
    g_assert_cmpint (wyl_secure_duckdb_bridge_validate_restore_stage_identity
          (reader, length, checksum, &mismatch, &result), ==, WYRELOG_E_POLICY);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_FORMAT);
    mismatch = identity;
    mismatch.path_encoding_version = 2;
    g_assert_cmpint (wyl_secure_duckdb_bridge_validate_restore_stage_identity
          (reader, length, checksum, &mismatch, &result), ==, WYRELOG_E_POLICY);
    g_assert_cmpint (result, ==,
        WYL_FACT_STORE_IDENTITY_RESULT_PATH_ENCODING);

    result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    g_assert_cmpint (wyl_secure_duckdb_bridge_validate_restore_stage_identity
          (reader, length + 1, checksum, &identity, &result), ==,
        WYRELOG_E_POLICY);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_NONE);
    g_autofree gchar *invalid_checksum = checksum_text (data, length - 1);
    g_assert_cmpint (wyl_secure_duckdb_bridge_validate_restore_stage_identity
          (reader, length, invalid_checksum, &identity, &result), ==,
        WYRELOG_E_POLICY);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_NONE);

    g_assert_cmpint (wyl_fact_offline_restore_stage_reader_verify_content
          (reader, length, checksum), ==, WYRELOG_E_OK);
    g_autofree gchar *main_path =
        wyl_fact_graph_directory_descriptive_file (&fixture.directory,
            "facts.duckdb");
    g_assert_false (g_file_test (main_path, G_FILE_TEST_EXISTS));
    g_assert_true (g_file_test (fixture.stage_path, G_FILE_TEST_IS_REGULAR));
    wyl_fact_offline_restore_stage_reader_free (reader);
    fixture_clear (&fixture);
  }

  static void
  test_malformed_metadata_schema_rejected (void)
  {
    Fixture fixture;
    fixture_init (&fixture);
    g_autoptr (GBytes) payload = make_duckdb_payload (false);
    gsize length = 0;
    const auto *data = static_cast<const guint8 *>
        (g_bytes_get_data (payload, &length));
    g_autofree gchar *checksum = checksum_text (data, length);
    const auto stage_identity = make_stage (&fixture, payload, checksum);
    WylFactOfflineRestoreStageReader *reader = nullptr;
    g_assert_cmpint (wyl_fact_offline_restore_stage_reader_open
          (&fixture.resolver, &fixture.directory, fixture.lease,
        fixture.operation_uuid, &stage_identity, &reader), ==, WYRELOG_E_OK);
    auto identity = expected_identity ();
    WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_NONE;
    g_assert_cmpint (wyl_secure_duckdb_bridge_validate_restore_stage_identity
          (reader, length, checksum, &identity, &result), ==, WYRELOG_E_POLICY);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_SCHEMA);
    g_assert_cmpint (wyl_fact_offline_restore_stage_reader_verify_content
          (reader, length, checksum), ==, WYRELOG_E_OK);
    wyl_fact_offline_restore_stage_reader_free (reader);
    fixture_clear (&fixture);
  }

  struct MutateAfterClose
  {
    const gchar *path;
    gboolean fired;
  };

  static void
  mutate_after_close (WylSecureDuckdbRestoreStageTestPoint point,
      gpointer user_data)
  {
    auto *state = static_cast<MutateAfterClose *> (user_data);
    if (point != WYL_SECURE_DUCKDB_RESTORE_STAGE_TEST_AFTER_CLOSE
        || state->fired)
      return;
    state->fired = TRUE;
    const gint fd = g_open (state->path, O_WRONLY, 0);
    g_assert_cmpint (fd, >=, 0);
    const guint8 replacement = 0x5a;
    g_assert_cmpint (pwrite (fd, &replacement, 1, 0), ==, 1);
    g_assert_cmpint (close (fd), ==, 0);
  }

  static void
  truncate_before_first_read (WylSecureDuckdbRestoreStageTestPoint point,
      gpointer user_data)
  {
    auto *state = static_cast<MutateAfterClose *> (user_data);
    if (point != WYL_SECURE_DUCKDB_RESTORE_STAGE_TEST_BEFORE_FIRST_READ
        || state->fired)
      return;
    state->fired = TRUE;
    g_assert_cmpint (truncate (state->path, 0), ==, 0);
  }

  static void
  test_truncation_during_initial_database_read_fails_closed (void)
  {
    Fixture fixture;
    fixture_init (&fixture);
    g_autoptr (GBytes) payload = make_duckdb_payload ();
    gsize length = 0;
    const auto *data = static_cast<const guint8 *>
        (g_bytes_get_data (payload, &length));
    g_autofree gchar *checksum = checksum_text (data, length);
    const auto stage_identity = make_stage (&fixture, payload, checksum);
    WylFactOfflineRestoreStageReader *reader = nullptr;
    g_assert_cmpint (wyl_fact_offline_restore_stage_reader_open
          (&fixture.resolver, &fixture.directory, fixture.lease,
        fixture.operation_uuid, &stage_identity, &reader), ==, WYRELOG_E_OK);
    MutateAfterClose mutation = { fixture.stage_path, FALSE };
    wyl_secure_duckdb_bridge_set_restore_stage_test_hook_for_test
      (truncate_before_first_read, &mutation);
    auto identity = expected_identity ();
    WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    const wyrelog_error_t rc =
        wyl_secure_duckdb_bridge_validate_restore_stage_identity (reader,
            length, checksum, &identity, &result);
    wyl_secure_duckdb_bridge_set_restore_stage_test_hook_for_test (nullptr,
        nullptr);
    g_assert_true (mutation.fired);
    g_assert_cmpint (rc, ==, WYRELOG_E_POLICY);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_NONE);
    wyl_fact_offline_restore_stage_reader_free (reader);
    fixture_clear (&fixture);
  }

  static void
  test_content_revalidated_after_database_close (void)
  {
    Fixture fixture;
    fixture_init (&fixture);
    g_autoptr (GBytes) payload = make_duckdb_payload ();
    gsize length = 0;
    const auto *data = static_cast<const guint8 *>
        (g_bytes_get_data (payload, &length));
    g_autofree gchar *checksum = checksum_text (data, length);
    const auto stage_identity = make_stage (&fixture, payload, checksum);
    WylFactOfflineRestoreStageReader *reader = nullptr;
    g_assert_cmpint (wyl_fact_offline_restore_stage_reader_open
          (&fixture.resolver, &fixture.directory, fixture.lease,
        fixture.operation_uuid, &stage_identity, &reader), ==, WYRELOG_E_OK);
    MutateAfterClose mutation = { fixture.stage_path, FALSE };
    wyl_secure_duckdb_bridge_set_restore_stage_test_hook_for_test
      (mutate_after_close, &mutation);
    auto identity = expected_identity ();
    WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    const wyrelog_error_t rc =
        wyl_secure_duckdb_bridge_validate_restore_stage_identity (reader,
            length, checksum, &identity, &result);
    wyl_secure_duckdb_bridge_set_restore_stage_test_hook_for_test (nullptr,
        nullptr);
    g_assert_true (mutation.fired);
    g_assert_cmpint (rc, ==, WYRELOG_E_POLICY);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_NONE);
    g_assert_true (g_file_test (fixture.stage_path, G_FILE_TEST_IS_REGULAR));
    wyl_fact_offline_restore_stage_reader_free (reader);
    fixture_clear (&fixture);
  }
#endif

  static void
  test_windows_fails_closed_before_reader_access (void)
  {
#ifdef G_OS_WIN32
    const auto identity = expected_identity ();
    WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    auto *uninspectable = reinterpret_cast<WylFactOfflineRestoreStageReader *>
        (static_cast<uintptr_t> (1));
    g_assert_cmpint (wyl_secure_duckdb_bridge_validate_restore_stage_identity
          (uninspectable, 17, "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        &identity, &result), ==, WYRELOG_E_POLICY);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_NONE);
#else
    g_test_skip ("Windows fail-closed boundary is platform-specific");
#endif
  }
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, nullptr);
#ifndef G_OS_WIN32
  g_test_add_func ("/fact/offline-restore-stage-metadata/identity",
      test_stage_identity_validation);
  g_test_add_func ("/fact/offline-restore-stage-metadata/malformed-schema",
      test_malformed_metadata_schema_rejected);
  g_test_add_func ("/fact/offline-restore-stage-metadata/read-truncation",
      test_truncation_during_initial_database_read_fails_closed);
  g_test_add_func ("/fact/offline-restore-stage-metadata/post-close-content",
      test_content_revalidated_after_database_close);
#endif
  g_test_add_func ("/fact/offline-restore-stage-metadata/windows-fail-closed",
      test_windows_fails_closed_before_reader_access);
  return wyl_test_normalize_exit_status (g_test_run ());
}

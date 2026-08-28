/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>

#ifdef G_OS_WIN32
#include <aclapi.h>
#include <string.h>
#include <windows.h>
#include <winternl.h>

#include "fact-test-support.h"
#include "fact-artifact-transition-driver-fixture.h"
#include "fact/graph-artifact-inventory-private.h"
#include "fact/graph-artifact-main-transition-private.h"
#include "fact/graph-artifact-transition-names-private.h"
#include "fact/graph-artifact-transition-windows-private.h"
#include "fact/graph-locator-private.h"
#include "fact/graph-windows-security-private.h"
#include "fact/root-writer-lease-private.h"

#define MT(name) WYL_FACT_ARTIFACT_MAIN_TRANSITION_ ## name
#define WF(name) WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_ ## name

#define SLOT_MAIN     MT (SLOT_MAIN)
#define SLOT_STAGE    MT (SLOT_STAGE)
#define SLOT_ROLLBACK MT (SLOT_ROLLBACK)

typedef WylFactArtifactMainTransitionObservation Observation;
typedef WylFactArtifactMainTransitionRequest Request;
typedef WylFactArtifactMainTransitionResult Result;
typedef WylFactArtifactMainTransition Transition;
typedef WylFactArtifactInventoryIdentity Identity;
typedef WylFactArtifactInventorySnapshot Snapshot;
typedef WylFactArtifactTransitionWindows Provider;
typedef WylFactArtifactTransitionWindowsCapability Capability;
typedef WylFactArtifactTransitionWindowsLifecycle Lifecycle;

static const gchar OPERATION_UUID[] = "018f1a2b-3c4d-7e5f-8a9b-0c1d2e3f4a5b";

typedef struct
{
  gchar *root;
  WylFactRootWriterLease *lease;
  WylFactGraphResolver resolver;
  WylFactGraphLocator locator;
  WylFactGraphDirectory directory;
  WylFactArtifactTransitionNames names;
  gchar *graph_path;
} Fixture;

static void
create_owner_only_file (HANDLE dir_handle, const gchar *name,
    const gchar *content)
{
  g_autoptr (GError) error = NULL;
  glong wide_len = 0;
  g_autofree WCHAR *wide = g_utf8_to_utf16 (name, -1, NULL, &wide_len, &error);
  g_assert_no_error (error);
  g_assert_nonnull (wide);

  WylFactGraphWinOwnerOnlySecurity security = { 0 };
  g_assert_cmpint (wyl_fact_graph_win_owner_only_security_init (&security, 0),
      ==, WYRELOG_E_OK);

  UNICODE_STRING uname = {
    .Length = (USHORT) (wide_len * sizeof (WCHAR)),
    .MaximumLength = (USHORT) (wide_len * sizeof (WCHAR)),
    .Buffer = wide,
  };
  OBJECT_ATTRIBUTES attr = {
    .Length = sizeof attr,
    .RootDirectory = dir_handle,
    .ObjectName = &uname,
    .Attributes = OBJ_CASE_INSENSITIVE,
    .SecurityDescriptor = &security.descriptor,
  };

  HMODULE ntdll = GetModuleHandleW (L"ntdll.dll");
  g_assert_nonnull (ntdll);
  typedef NTSTATUS (NTAPI * WylNtCreateFile) (PHANDLE, ACCESS_MASK,
      POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG,
      ULONG, ULONG, PVOID, ULONG);
  WylNtCreateFile nt_create = (WylNtCreateFile) GetProcAddress (ntdll,
          "NtCreateFile");
  g_assert_nonnull (nt_create);

  HANDLE handle = INVALID_HANDLE_VALUE;
  IO_STATUS_BLOCK io_status = { 0 };
  NTSTATUS status = nt_create (&handle,
          GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
          &attr, &io_status, NULL, FILE_ATTRIBUTE_NORMAL,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
          FILE_OVERWRITE_IF,
          FILE_OPEN_REPARSE_POINT | FILE_NON_DIRECTORY_FILE
          | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
  g_assert_cmpint (status, ==, 0);
  g_assert_true (handle != INVALID_HANDLE_VALUE);

  if (content != NULL && *content != '\0') {
    DWORD written = 0;
    g_assert_true (WriteFile (handle, content, (DWORD) strlen (content),
        &written, NULL));
  }
  CloseHandle (handle);
  wyl_fact_graph_win_owner_only_security_clear (&security);
}

static void
set_directory_owner_only_acl (const gchar *path)
{
  g_autoptr (GError) error = NULL;
  g_autofree WCHAR *wide = (WCHAR *) g_utf8_to_utf16 (path, -1, NULL, NULL,
          &error);
  g_assert_no_error (error);
  g_assert_nonnull (wide);
  WylFactGraphWinOwnerOnlySecurity security = { 0 };
  g_assert_cmpint (wyl_fact_graph_win_owner_only_security_init (&security,
      OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE), ==, WYRELOG_E_OK);
  g_assert_cmpint (SetNamedSecurityInfoW (wide, SE_FILE_OBJECT,
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
      | PROTECTED_DACL_SECURITY_INFORMATION, security.user, NULL,
      security.acl, NULL), ==, ERROR_SUCCESS);
  wyl_fact_graph_win_owner_only_security_clear (&security);
}

static void
unprotect_directory_acl (const gchar *path)
{
  g_autoptr (GError) error = NULL;
  g_autofree WCHAR *wide = (WCHAR *) g_utf8_to_utf16 (path, -1, NULL, NULL,
          &error);
  g_assert_no_error (error);
  g_assert_nonnull (wide);
  g_assert_cmpint (SetNamedSecurityInfoW (wide, SE_FILE_OBJECT,
      DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
      NULL, NULL, NULL, NULL), ==, ERROR_SUCCESS);
}

static void
fixture_init (Fixture *fixture, const gchar *tag)
{
  g_autoptr (GError) error = NULL;
  memset (fixture, 0, sizeof *fixture);
  fixture->resolver = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
  fixture->directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_autofree gchar *tmpl = g_strdup_printf ("wyl-win-tx-%s-XXXXXX", tag);
  fixture->root = wyl_test_make_secure_fact_root (tmpl, &error);
  g_assert_no_error (error);
  g_assert_nonnull (fixture->root);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (fixture->root,
      &fixture->lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (fixture->root,
      &fixture->resolver), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&fixture->locator, "tenant",
      "graph"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&fixture->resolver,
      &fixture->locator, TRUE, &fixture->directory), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_transition_names_derive (OPERATION_UUID,
      &fixture->names), ==, WYRELOG_E_OK);
  fixture->graph_path
    = wyl_fact_graph_directory_descriptive_path (&fixture->directory);
  g_assert_nonnull (fixture->graph_path);

  create_owner_only_file (fixture->directory.graph_handle,
      WYL_FACT_ARTIFACT_TRANSITION_LOCK_NAME, "lock");
}

static void
fixture_open_existing (Fixture *fixture, const gchar *root)
{
  memset (fixture, 0, sizeof *fixture);
  fixture->resolver = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
  fixture->directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  fixture->root = g_strdup (root);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (fixture->root,
      &fixture->lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (fixture->root,
      &fixture->resolver), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&fixture->locator, "tenant",
      "graph"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&fixture->resolver,
      &fixture->locator, FALSE, &fixture->directory), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_transition_names_derive (OPERATION_UUID,
      &fixture->names), ==, WYRELOG_E_OK);
  fixture->graph_path
    = wyl_fact_graph_directory_descriptive_path (&fixture->directory);
  g_assert_nonnull (fixture->graph_path);
}

static void
fixture_clear (Fixture *fixture)
{
  wyl_fact_artifact_transition_windows_set_test_fault (WF (NONE));
  wyl_fact_artifact_transition_windows_set_test_rename_status (0);
  wyl_fact_artifact_transition_windows_set_test_flush_error (0);
  wyl_fact_artifact_transition_windows_set_test_post_open_hook (NULL, NULL);

  wyl_fact_artifact_transition_names_clear (&fixture->names);
  g_clear_pointer (&fixture->graph_path, g_free);
  wyl_fact_graph_directory_clear (&fixture->directory);
  wyl_fact_graph_locator_clear (&fixture->locator);
  wyl_fact_graph_resolver_clear (&fixture->resolver);
  g_clear_pointer (&fixture->lease, wyl_fact_root_writer_lease_release);
  g_clear_pointer (&fixture->root, g_free);
}

static Snapshot *
hand_built_snapshot (const Observation *observation, gboolean lock_present)
{
  Snapshot *snapshot = wyl_fact_artifact_inventory_snapshot_new (32);
  WylFactArtifactInventoryObservation point = {
    .directory_identity = observation->directory_identity,
    .guard_identity = observation->lease_identity,
    .entry_fingerprint = 11,
  };
  wyl_fact_artifact_inventory_snapshot_begin (snapshot, &point);
  gboolean main_present = observation->entries[SLOT_MAIN].present;
  Identity main_identity = observation->entries[SLOT_MAIN].identity;
  Identity lock_identity = observation->lease_identity;
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_MAIN,
      main_present ? &main_identity : NULL, main_present,
      main_present ? 1 : 0, TRUE, main_present ? 1 : 0), ==, WYRELOG_E_OK);
  const WylFactArtifactInventorySlot absent[] = {
    WYL_FACT_ARTIFACT_INVENTORY_WAL,
    WYL_FACT_ARTIFACT_INVENTORY_CHECKPOINT,
    WYL_FACT_ARTIFACT_INVENTORY_RECOVERY,
  };
  for (gsize index = 0; index < G_N_ELEMENTS (absent); index++)
    g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
        absent[index], NULL, FALSE, 0, TRUE, 0), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_LOCK,
      lock_present ? &lock_identity : NULL, lock_present,
      lock_present ? 1 : 0, TRUE, lock_present ? 1 : 0), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_set_slot (snapshot,
      WYL_FACT_ARTIFACT_INVENTORY_TEMP, NULL, FALSE, 0, TRUE, 0), ==,
      WYRELOG_E_OK);
  guint unknown = (observation->entries[SLOT_STAGE].present ? 1u : 0u)
      + (observation->entries[SLOT_ROLLBACK].present ? 1u : 0u);
  for (guint index = 0; index < unknown; index++)
    g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_add_anomaly
          (snapshot, WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY), ==,
        WYRELOG_E_OK);
  wyl_fact_artifact_inventory_snapshot_end (snapshot, &point);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_finalize (snapshot),
      ==, WYRELOG_E_OK);
  return snapshot;
}

static Request
request_for (const Observation *observation, Identity expected_main,
    Identity staged_main, gboolean expected_main_absent)
{
  Request request = {
    .operation_uuid = OPERATION_UUID,
    .directory_identity = observation->directory_identity,
    .lease_identity = observation->lease_identity,
    .expected_main_absent = expected_main_absent,
    .expected_main_identity = expected_main_absent ? (Identity) { 0 }
        : expected_main,
    .staged_main_identity = staged_main,
  };
  return request;
}

static WylTestDriverStoredValue
completed_driver_value (const Request *request,
    WylFactArtifactMainTransitionOp op,
    WylFactArtifactMainTransitionState state)
{
  WylTestDriverStoredValue value = {
    .version = 1,
    .revision = 29,
    .consumer_generation = 31,
    .directory_identity = request->directory_identity,
    .lease_identity = request->lease_identity,
    .expected_main_absent = request->expected_main_absent,
    .expected_main_identity = request->expected_main_identity,
    .staged_main_identity = request->staged_main_identity,
    .resume_forbidden = request->resume_forbidden,
    .durability_unprovable_acknowledged
      = request->durability_unprovable_acknowledged,
    .marker = WYL_TEST_DRIVER_MARKER_COMPLETED,
    .pending_op = op,
    .completed_state = state,
  };
  g_strlcpy (value.operation_uuid, request->operation_uuid,
      sizeof value.operation_uuid);
  return value;
}

static wyrelog_error_t
admit (const Observation *observation, const Request *request,
    Result *out_result, Transition **out_transition)
{
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot
    = hand_built_snapshot (observation, TRUE);
  return wyl_fact_artifact_main_transition_admit (request, snapshot,
             observation, out_result, out_transition);
}

enum
{
  DRIVER_CHILD_CRASHED_AFTER_RETAIN = 77,
  DRIVER_CHILD_ERROR = 78,
};

typedef struct
{
  const gchar *path;
} WindowsFileStore;

static wyrelog_error_t
windows_store_load (gpointer user_data, WylTestDriverStoredValue *out_value)
{
  WindowsFileStore *store = user_data;
  g_autofree WCHAR *wide = g_utf8_to_utf16 (store->path, -1, NULL, NULL, NULL);
  HANDLE file = CreateFileW (wide, GENERIC_READ, FILE_SHARE_READ, NULL,
          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file == INVALID_HANDLE_VALUE)
    return WYRELOG_E_IO;
  DWORD read_bytes = 0;
  guint8 extra = 0;
  DWORD extra_bytes = 0;
  gboolean ok = ReadFile (file, out_value, (DWORD) sizeof *out_value,
          &read_bytes, NULL) && read_bytes == (DWORD) sizeof *out_value
      && ReadFile (file, &extra, 1, &extra_bytes, NULL) && extra_bytes == 0;
  ok = CloseHandle (file) && ok;
  return ok ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
windows_store_write (const gchar *path, const WylTestDriverStoredValue *value,
    gboolean exclusive)
{
  g_autofree WCHAR *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  HANDLE file = CreateFileW (wide, GENERIC_WRITE, 0, NULL,
          exclusive ? CREATE_NEW : TRUNCATE_EXISTING,
          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
  if (file == INVALID_HANDLE_VALUE)
    return WYRELOG_E_IO;
  DWORD written = 0;
  gboolean ok = WriteFile (file, value, (DWORD) sizeof *value, &written, NULL)
      && written == (DWORD) sizeof *value && FlushFileBuffers (file);
  ok = CloseHandle (file) && ok;
  return ok ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
windows_store_cas (gpointer user_data, guint64 expected_revision,
    const WylTestDriverStoredValue *desired,
    WylTestDriverStoredValue *out_committed)
{
  WindowsFileStore *store = user_data;
  WylTestDriverStoredValue current = { 0 };
  wyrelog_error_t rc = windows_store_load (store, &current);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (current.revision != expected_revision)
    return WYRELOG_E_BUSY;
  rc = windows_store_write (store->path, desired, FALSE);
  if (rc == WYRELOG_E_OK)
    *out_committed = *desired;
  return rc;
}

static WylTestDriverValueStore
windows_value_store (WindowsFileStore *file)
{
  return (WylTestDriverValueStore) {
           .load = windows_store_load,
           .compare_and_swap = windows_store_cas,
           .user_data = file,
  };
}

static Request
request_from_stored (const WylTestDriverStoredValue *stored)
{
  return (Request) {
           .operation_uuid = stored->operation_uuid,
           .directory_identity = stored->directory_identity,
           .lease_identity = stored->lease_identity,
           .expected_main_absent = stored->expected_main_absent,
           .expected_main_identity = stored->expected_main_identity,
           .staged_main_identity = stored->staged_main_identity,
           .resume_forbidden = stored->resume_forbidden,
           .durability_unprovable_acknowledged
             = stored->durability_unprovable_acknowledged,
  };
}

static gboolean
windows_write_counter (const gchar *path, guint value)
{
  gchar encoded[32];
  gint length = g_snprintf (encoded, sizeof encoded, "%u", value);
  g_autofree WCHAR *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  HANDLE file = CreateFileW (wide, GENERIC_WRITE, 0, NULL, TRUNCATE_EXISTING,
          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
  DWORD written = 0;
  gboolean ok = file != INVALID_HANDLE_VALUE
      && WriteFile (file, encoded, (DWORD) length, &written, NULL)
      && written == (DWORD) length && FlushFileBuffers (file);
  if (file != INVALID_HANDLE_VALUE)
    ok = CloseHandle (file) && ok;
  return ok;
}

static gboolean
windows_create_counter (const gchar *path)
{
  g_autofree WCHAR *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  HANDLE file = CreateFileW (wide, GENERIC_WRITE, 0, NULL, CREATE_NEW,
          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
  DWORD written = 0;
  gboolean ok = file != INVALID_HANDLE_VALUE
      && WriteFile (file, "0", 1, &written, NULL) && written == 1
      && FlushFileBuffers (file);
  if (file != INVALID_HANDLE_VALUE)
    ok = CloseHandle (file) && ok;
  return ok;
}

typedef struct
{
  Provider *provider;
  Transition *transition;
  Lifecycle lifecycle;
  Observation observation;
  Result result;
  gboolean crash_after_execute;
  const gchar *counter_path;
} WindowsDriverAction;

static wyrelog_error_t
run_windows_backend_action (WylFactArtifactMainTransitionOp op,
    gpointer user_data,
    WylFactArtifactMainTransitionState *out_completed_state)
{
  WindowsDriverAction *action = user_data;
  wyrelog_error_t rc = wyl_fact_artifact_main_transition_authorize
        (action->transition, op, &action->observation, &action->result);
  if (rc != WYRELOG_E_OK)
    return rc;
  WylFactArtifactMainTransitionEffect effect = MT (EFFECT_NOT_APPLIED);
  WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
  rc = wyl_fact_artifact_transition_windows_execute (action->provider,
          &action->observation, op, &effect, &durability);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (action->crash_after_execute) {
    ExitProcess (effect == MT (EFFECT_APPLIED)
        && windows_write_counter (action->counter_path, 1)
        ? DRIVER_CHILD_CRASHED_AFTER_RETAIN : DRIVER_CHILD_ERROR);
    return WYRELOG_E_IO;
  }
  rc = wyl_fact_artifact_transition_windows_observe (action->provider,
          &action->lifecycle, &action->observation);
  if (rc != WYRELOG_E_OK)
    return rc;
  action->observation.durability = durability;
  rc = wyl_fact_artifact_main_transition_record (action->transition, op,
          effect, &action->observation, &action->result);
  if (rc == WYRELOG_E_OK)
    *out_completed_state = action->result.state;
  return rc;
}

static int
run_driver_crash_child (const gchar *root, const gchar *store_path,
    const gchar *counter_path)
{
  Fixture fixture;
  fixture_open_existing (&fixture, root);
  WindowsFileStore file = { .path = store_path };
  WylTestDriverValueStore store = windows_value_store (&file);
  WylTestDriverStoredValue stored = { 0 };
  if (store.load (store.user_data, &stored) != WYRELOG_E_OK)
    return DRIVER_CHILD_ERROR;
  Capability capability = { .no_replace_supported = TRUE,
                            .directory_flush = MT (DURABILITY_PROVEN) };
  g_autoptr (WylFactArtifactTransitionWindows) provider = NULL;
  if (wyl_fact_artifact_transition_windows_open (&fixture.resolver,
      &fixture.directory, fixture.lease, OPERATION_UUID, &capability,
      &provider) != WYRELOG_E_OK)
    return DRIVER_CHILD_ERROR;
  Lifecycle lifecycle = { .sealed = TRUE, .main_binding_live = FALSE };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  Observation observation = { 0 };
  if (wyl_fact_artifact_transition_windows_capture (provider, &lifecycle,
      &snapshot, &observation) != WYRELOG_E_OK)
    return DRIVER_CHILD_ERROR;
  Request request = request_from_stored (&stored);
  Result result = { 0 };
  g_autoptr (WylFactArtifactMainTransition) transition = NULL;
  if (wyl_fact_artifact_main_transition_admit (&request, snapshot,
      &observation, &result, &transition) != WYRELOG_E_OK)
    return DRIVER_CHILD_ERROR;
  WindowsDriverAction action = { .provider = provider,
                                 .transition = transition,
                                 .lifecycle = lifecycle,
                                 .observation = observation,
                                 .result = result };
  WylTestDriverStoredValue attempt = { 0 };
  WylFactArtifactMainTransitionState completed_state = MT (STATE_INVALID);
  if (wyl_test_driver_run_mutation (&store, FALSE,
      stored.consumer_generation,
      MT (OP_SYNC_STAGED), run_windows_backend_action, &action, NULL, NULL,
      &attempt, &completed_state) != WYRELOG_E_OK)
    return DRIVER_CHILD_ERROR;
  WylTestDriverStoredValue completed = { 0 };
  if (wyl_test_driver_complete_mutation (&store, MT (OP_SYNC_STAGED),
      completed_state, NULL, NULL, &completed) != WYRELOG_E_OK)
    return DRIVER_CHILD_ERROR;
  action.crash_after_execute = TRUE;
  action.counter_path = counter_path;
  (void) wyl_test_driver_run_mutation (&store, FALSE,
      stored.consumer_generation,
      MT (OP_RETAIN), run_windows_backend_action, &action, NULL, NULL,
      &attempt, &completed_state);
  return DRIVER_CHILD_ERROR;
}

static void
spawn_driver_crash_child (const gchar *root, const gchar *store_path,
    const gchar *counter_path)
{
  WCHAR executable[MAX_PATH + 1] = { 0 };
  DWORD length = GetModuleFileNameW (NULL, executable,
          (DWORD) G_N_ELEMENTS (executable));
  g_assert_cmpuint (length, >, 0);
  g_assert_cmpuint (length, <, G_N_ELEMENTS (executable));
  g_autofree gchar *exe_utf8 = g_utf16_to_utf8 ((gunichar2 *) executable,
          -1, NULL, NULL, NULL);
  g_assert_nonnull (exe_utf8);
  g_autofree gchar *command_utf8 = g_strdup_printf (
    "\"%s\" --driver-crash-child \"%s\" \"%s\" \"%s\"", exe_utf8,
    root, store_path, counter_path);
  g_autofree WCHAR *command = g_utf8_to_utf16 (command_utf8, -1, NULL, NULL,
          NULL);
  g_assert_nonnull (command);
  STARTUPINFOW startup = { .cb = (DWORD) sizeof startup };
  PROCESS_INFORMATION process = { 0 };
  g_assert_true (CreateProcessW (NULL, command, NULL, NULL, FALSE,
      CREATE_NO_WINDOW, NULL, NULL, &startup, &process));
  g_assert_true (CloseHandle (process.hThread));
  DWORD wait = WaitForSingleObject (process.hProcess, 30000);
  if (wait != WAIT_OBJECT_0) {
    TerminateProcess (process.hProcess, DRIVER_CHILD_ERROR);
    WaitForSingleObject (process.hProcess, 10000);
  }
  g_assert_cmpuint (wait, ==, WAIT_OBJECT_0);
  DWORD exit_code = STILL_ACTIVE;
  g_assert_true (GetExitCodeProcess (process.hProcess, &exit_code));
  g_assert_cmpuint (exit_code, ==, DRIVER_CHILD_CRASHED_AFTER_RETAIN);
  g_assert_true (CloseHandle (process.hProcess));
}

static void
test_names_derived_internally_match (void)
{
  Fixture f;
  fixture_init (&f, "names-match");
  g_assert_cmpstr (f.names.stage, ==,
      "restore-018f1a2b-3c4d-7e5f-8a9b-0c1d2e3f4a5b.duckdb");
  g_assert_cmpstr (f.names.rollback, ==,
      "restore-018f1a2b-3c4d-7e5f-8a9b-0c1d2e3f4a5b.duckdb.superseded");
  g_assert_cmpstr (f.names.probe, ==,
      "restore-018f1a2b-3c4d-7e5f-8a9b-0c1d2e3f4a5b.duckdb.probe");
  g_assert_cmpstr (f.names.probe_moved, ==,
      "restore-018f1a2b-3c4d-7e5f-8a9b-0c1d2e3f4a5b.duckdb.probe.moved");
  fixture_clear (&f);
}

static void
test_observe_all_three_slots_present (void)
{
  Fixture f;
  fixture_init (&f, "observe-triple");
  create_owner_only_file (f.directory.graph_handle,
      WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, "main-data");
  create_owner_only_file (f.directory.graph_handle, f.names.stage,
      "stage-data");
  create_owner_only_file (f.directory.graph_handle, f.names.rollback,
      "rollback-data");

  Capability cap = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_probe_capability
        (&f.directory, OPERATION_UUID, &cap), ==, WYRELOG_E_OK);
  g_assert_true (cap.no_replace_supported);

  g_autoptr (WylFactArtifactTransitionWindows) p = NULL;
  g_assert_cmpint (wyl_fact_artifact_transition_windows_open
        (&f.resolver, &f.directory, f.lease, OPERATION_UUID, &cap, &p), ==,
      WYRELOG_E_OK);

  Lifecycle life = { .sealed = TRUE, .main_binding_live = FALSE };
  Observation obs = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_observe (p, &life,
      &obs), ==, WYRELOG_E_OK);

  g_assert_true (obs.sealed);
  g_assert_false (obs.main_binding_live);
  g_assert_true (obs.no_replace_supported);

  for (gint i = 0; i < MT (SLOT_COUNT); i++) {
    g_assert_true (obs.entries[i].present);
    g_assert_cmpuint (obs.entries[i].link_count, ==, 1);
    g_assert_false (obs.entries[i].reparse);
    g_assert_cmpint (obs.entries[i].owner_state, ==, MT (OWNER_CONFORMING));
    g_assert_cmpuint (obs.entries[i].identity.object_width, ==, 16);
    g_assert_cmpuint (obs.entries[i].identity.domain, !=, 0);
  }

  g_assert_false (wyl_fact_artifact_inventory_identity_equal
        (&obs.entries[SLOT_MAIN].identity, &obs.entries[SLOT_STAGE].identity));
  g_assert_false (wyl_fact_artifact_inventory_identity_equal
        (&obs.entries[SLOT_MAIN].identity,
      &obs.entries[SLOT_ROLLBACK].identity));

  fixture_clear (&f);
}

static void
test_observe_absent_permutations (void)
{
  Fixture f;
  fixture_init (&f, "observe-absent");
  Capability cap = { .no_replace_supported = TRUE, .directory_flush = MT (
                       DURABILITY_PROVEN) };
  g_autoptr (WylFactArtifactTransitionWindows) p = NULL;
  g_assert_cmpint (wyl_fact_artifact_transition_windows_open
        (&f.resolver, &f.directory, f.lease, OPERATION_UUID, &cap, &p), ==,
      WYRELOG_E_OK);

  Lifecycle life = { .sealed = TRUE, .main_binding_live = FALSE };
  Observation obs = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_observe (p, &life,
      &obs), ==, WYRELOG_E_OK);

  g_assert_false (obs.entries[SLOT_MAIN].present);
  g_assert_false (obs.entries[SLOT_STAGE].present);
  g_assert_false (obs.entries[SLOT_ROLLBACK].present);

  fixture_clear (&f);
}

static void
test_observe_unreadable_slot_fails_closed (void)
{
  Fixture f;
  fixture_init (&f, "observe-unreadable");
  create_owner_only_file (f.directory.graph_handle,
      WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, "main");

  Capability cap = { .no_replace_supported = TRUE, .directory_flush = MT (
                       DURABILITY_PROVEN) };
  g_autoptr (WylFactArtifactTransitionWindows) p = NULL;
  g_assert_cmpint (wyl_fact_artifact_transition_windows_open
        (&f.resolver, &f.directory, f.lease, OPERATION_UUID, &cap, &p), ==,
      WYRELOG_E_OK);

  wyl_fact_artifact_transition_windows_set_test_fault (WF (OBSERVE_SLOT_OPEN));
  Lifecycle life = { .sealed = TRUE, .main_binding_live = FALSE };
  Observation obs = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_observe (p, &life,
      &obs), ==, WYRELOG_E_IO);
  g_assert_true (wyl_fact_artifact_transition_windows_test_fault_was_consumed (
        WF (OBSERVE_SLOT_OPEN)));

  fixture_clear (&f);
}

static void
test_probe_capability_happy_path (void)
{
  Fixture f;
  fixture_init (&f, "probe-happy");
  Capability cap = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_probe_capability
        (&f.directory, OPERATION_UUID, &cap), ==, WYRELOG_E_OK);
  g_assert_true (cap.no_replace_supported);
  g_assert_cmpint (cap.directory_flush, !=, MT (DURABILITY_UNPROVEN));
  fixture_clear (&f);
}

static void
test_probe_capability_preclean_recovery (void)
{
  Fixture f;
  fixture_init (&f, "probe-preclean");
  create_owner_only_file (f.directory.graph_handle, f.names.probe, "debris1");
  create_owner_only_file (f.directory.graph_handle, f.names.probe_moved,
      "debris2");

  Capability cap = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_probe_capability
        (&f.directory, OPERATION_UUID, &cap), ==, WYRELOG_E_OK);
  g_assert_true (cap.no_replace_supported);
  fixture_clear (&f);
}

static void
test_probe_capability_preclean_failure_fails_closed (void)
{
  Fixture f;
  fixture_init (&f, "probe-preclean-fail");
  wyl_fact_artifact_transition_windows_set_test_fault (WF (PROBE_PRECLEAN));
  Capability cap = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_probe_capability
        (&f.directory, OPERATION_UUID, &cap), ==, WYRELOG_E_IO);
  g_assert_true (wyl_fact_artifact_transition_windows_test_fault_was_consumed (
        WF (PROBE_PRECLEAN)));
  fixture_clear (&f);
}

static void
test_probe_capability_rename_unsupported (void)
{
  Fixture f;
  fixture_init (&f, "probe-rename-unsupp");
  wyl_fact_artifact_transition_windows_set_test_fault (WF (PROBE_RENAME));
  wyl_fact_artifact_transition_windows_set_test_rename_status (0xC00000BBL); /* STATUS_NOT_SUPPORTED */
  Capability cap = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_probe_capability
        (&f.directory, OPERATION_UUID, &cap), ==, WYRELOG_E_OK);
  g_assert_false (cap.no_replace_supported);
  g_assert_true (wyl_fact_artifact_transition_windows_test_fault_was_consumed (
        WF (PROBE_RENAME)));
  fixture_clear (&f);
}

static void
test_mode_a_full_lifecycle (void)
{
  Fixture f;
  fixture_init (&f, "mode-a-lifecycle");
  create_owner_only_file (f.directory.graph_handle,
      WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, "old-main-bytes");
  create_owner_only_file (f.directory.graph_handle, f.names.stage,
      "new-stage-bytes");

  Capability cap = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_probe_capability
        (&f.directory, OPERATION_UUID, &cap), ==, WYRELOG_E_OK);

  g_autoptr (WylFactArtifactTransitionWindows) provider = NULL;
  g_assert_cmpint (wyl_fact_artifact_transition_windows_open
        (&f.resolver, &f.directory, f.lease, OPERATION_UUID, &cap,
      &provider), ==,
      WYRELOG_E_OK);

  Lifecycle life = { .sealed = TRUE, .main_binding_live = FALSE };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  Observation obs = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_capture (provider,
      &life, &snapshot, &obs), ==, WYRELOG_E_OK);

  Identity main_id = obs.entries[SLOT_MAIN].identity;
  Identity stage_id = obs.entries[SLOT_STAGE].identity;
  Request req = request_for (&obs, main_id, stage_id, FALSE);

  Result res = { 0 };
  g_autoptr (WylFactArtifactMainTransition) tx = NULL;
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&req, snapshot,
      &obs, &res, &tx), ==, WYRELOG_E_OK);
  g_assert_cmpint (res.refusal, ==, MT (REFUSAL_NONE));
  g_assert_cmpint (res.state, ==, MT (STATE_READY));

  /* Walk Mode A: SYNC_STAGED -> RETAIN -> SYNC_ROLLBACK_FILE -> SYNC_RETAIN_DIR
   * -> PUBLISH -> SYNC_PUBLISH_DIR -> FINALIZE */
  WylFactArtifactMainTransitionOp ops[] = {
    MT (OP_SYNC_STAGED),
    MT (OP_RETAIN),
    MT (OP_SYNC_ROLLBACK_FILE),
    MT (OP_SYNC_RETAIN_DIR),
    MT (OP_PUBLISH),
    MT (OP_SYNC_PUBLISH_DIR),
    MT (OP_FINALIZE),
  };

  for (gsize i = 0; i < G_N_ELEMENTS (ops); i++) {
    Observation step_obs = { 0 };
    g_assert_cmpint (wyl_fact_artifact_transition_windows_observe (provider,
        &life, &step_obs), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_main_transition_authorize (tx,
        ops[i], &step_obs, &res), ==, WYRELOG_E_OK);
    g_assert_cmpint (res.refusal, ==, MT (REFUSAL_NONE));

    WylFactArtifactMainTransitionEffect effect
      = MT (EFFECT_NOT_APPLIED);
    WylFactArtifactMainTransitionDurabilityEvidence dur = { 0 };
    g_assert_cmpint (wyl_fact_artifact_transition_windows_execute
          (provider, &step_obs, ops[i], &effect, &dur), ==, WYRELOG_E_OK);
    g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));

    g_assert_cmpint (wyl_fact_artifact_transition_windows_observe (provider,
        &life, &step_obs), ==, WYRELOG_E_OK);
    step_obs.durability = dur;
    g_assert_cmpint (wyl_fact_artifact_main_transition_record (tx, ops[i],
        effect, &step_obs, &res), ==, WYRELOG_E_OK);
    g_assert_cmpint (res.refusal, ==, MT (REFUSAL_NONE));
    if (ops[i] == MT (OP_SYNC_PUBLISH_DIR)) {
      WylTestDriverStoredValue synced = completed_driver_value (&req,
              ops[i], res.state);
      g_autoptr (WylFactArtifactInventorySnapshot) restarted_snapshot = NULL;
      Observation restarted_observation = { 0 };
      g_assert_cmpint (wyl_fact_artifact_transition_windows_capture (provider,
          &life, &restarted_snapshot, &restarted_observation), ==,
          WYRELOG_E_OK);
      Result restarted_result = { 0 };
      g_autoptr (WylFactArtifactMainTransition) restarted_transition = NULL;
      g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&req,
          restarted_snapshot, &restarted_observation, &restarted_result,
          &restarted_transition), ==, WYRELOG_E_OK);
      g_assert_cmpint (restarted_result.state, ==, MT (STATE_PUBLISHED));
      g_assert_cmpint (wyl_test_driver_restart_action (&synced,
          restarted_result.state), ==,
          WYL_TEST_DRIVER_RESTART_SYNC_PUBLISH_DIR);
    }
  }

  g_assert_cmpint (res.state, ==, MT (STATE_FINALIZED));
  fixture_clear (&f);
}

static void
test_mode_b_full_lifecycle_absent_rollback (void)
{
  Fixture f;
  fixture_init (&f, "mode-b-lifecycle");
  create_owner_only_file (f.directory.graph_handle, f.names.stage,
      "brand-new-main");

  Capability cap = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_probe_capability
        (&f.directory, OPERATION_UUID, &cap), ==, WYRELOG_E_OK);

  g_autoptr (WylFactArtifactTransitionWindows) provider = NULL;
  g_assert_cmpint (wyl_fact_artifact_transition_windows_open
        (&f.resolver, &f.directory, f.lease, OPERATION_UUID, &cap,
      &provider), ==,
      WYRELOG_E_OK);

  Lifecycle life = { .sealed = TRUE, .main_binding_live = FALSE };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  Observation obs = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_capture (provider,
      &life, &snapshot, &obs), ==, WYRELOG_E_OK);

  Identity stage_id = obs.entries[SLOT_STAGE].identity;
  Request req = request_for (&obs, (Identity) { 0 }, stage_id, TRUE);

  Result res = { 0 };
  g_autoptr (WylFactArtifactMainTransition) tx = NULL;
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&req, snapshot,
      &obs, &res, &tx), ==, WYRELOG_E_OK);
  g_assert_cmpint (res.refusal, ==, MT (REFUSAL_NONE));
  g_assert_cmpint (res.state, ==, MT (STATE_READY));

  /* Walk Mode B: SYNC_STAGED -> PUBLISH -> SYNC_PUBLISH_DIR -> FINALIZE */
  WylFactArtifactMainTransitionOp ops[] = {
    MT (OP_SYNC_STAGED),
    MT (OP_PUBLISH),
    MT (OP_SYNC_PUBLISH_DIR),
    MT (OP_FINALIZE),
  };

  for (gsize i = 0; i < G_N_ELEMENTS (ops); i++) {
    Observation step_obs = { 0 };
    g_assert_cmpint (wyl_fact_artifact_transition_windows_observe (provider,
        &life, &step_obs), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_main_transition_authorize (tx,
        ops[i], &step_obs, &res), ==, WYRELOG_E_OK);
    g_assert_cmpint (res.refusal, ==, MT (REFUSAL_NONE));

    WylFactArtifactMainTransitionEffect effect
      = MT (EFFECT_NOT_APPLIED);
    WylFactArtifactMainTransitionDurabilityEvidence dur = { 0 };
    g_assert_cmpint (wyl_fact_artifact_transition_windows_execute
          (provider, &step_obs, ops[i], &effect, &dur), ==, WYRELOG_E_OK);
    g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));

    g_assert_cmpint (wyl_fact_artifact_transition_windows_observe (provider,
        &life, &step_obs), ==, WYRELOG_E_OK);
    step_obs.durability = dur;
    g_assert_cmpint (wyl_fact_artifact_main_transition_record (tx, ops[i],
        effect, &step_obs, &res), ==, WYRELOG_E_OK);
    g_assert_cmpint (res.refusal, ==, MT (REFUSAL_NONE));
  }

  g_assert_cmpint (res.state, ==, MT (STATE_FINALIZED));
  fixture_clear (&f);
}

static void
test_mode_a_rollback_lifecycle (void)
{
  Fixture f;
  fixture_init (&f, "mode-a-rollback");
  create_owner_only_file (f.directory.graph_handle,
      WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, "original-main");
  create_owner_only_file (f.directory.graph_handle, f.names.stage,
      "aborted-stage");

  Capability cap = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_probe_capability
        (&f.directory, OPERATION_UUID, &cap), ==, WYRELOG_E_OK);

  g_autoptr (WylFactArtifactTransitionWindows) provider = NULL;
  g_assert_cmpint (wyl_fact_artifact_transition_windows_open
        (&f.resolver, &f.directory, f.lease, OPERATION_UUID, &cap,
      &provider), ==,
      WYRELOG_E_OK);

  Lifecycle life = { .sealed = TRUE, .main_binding_live = FALSE };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  Observation obs = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_capture (provider,
      &life, &snapshot, &obs), ==, WYRELOG_E_OK);

  Identity main_id = obs.entries[SLOT_MAIN].identity;
  Identity stage_id = obs.entries[SLOT_STAGE].identity;
  Request req = request_for (&obs, main_id, stage_id, FALSE);

  Result res = { 0 };
  g_autoptr (WylFactArtifactMainTransition) tx = NULL;
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&req, snapshot,
      &obs, &res, &tx), ==, WYRELOG_E_OK);

  /* SYNC_STAGED -> RETAIN */
  WylFactArtifactMainTransitionOp prep_ops[] = {
    MT (OP_SYNC_STAGED),
    MT (OP_RETAIN),
  };
  for (gsize i = 0; i < G_N_ELEMENTS (prep_ops); i++) {
    Observation step_obs = { 0 };
    g_assert_cmpint (wyl_fact_artifact_transition_windows_observe (provider,
        &life, &step_obs), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_main_transition_authorize (tx,
        prep_ops[i], &step_obs, &res), ==, WYRELOG_E_OK);
    WylFactArtifactMainTransitionEffect effect
      = MT (EFFECT_NOT_APPLIED);
    WylFactArtifactMainTransitionDurabilityEvidence dur = { 0 };
    g_assert_cmpint (wyl_fact_artifact_transition_windows_execute
          (provider, &step_obs, prep_ops[i], &effect, &dur), ==, WYRELOG_E_OK);

    g_assert_cmpint (wyl_fact_artifact_transition_windows_observe (provider,
        &life, &step_obs), ==, WYRELOG_E_OK);
    step_obs.durability = dur;
    g_assert_cmpint (wyl_fact_artifact_main_transition_record (tx, prep_ops[i],
        effect, &step_obs, &res), ==, WYRELOG_E_OK);
  }

  req.resume_forbidden = TRUE;
  g_clear_pointer (&snapshot, wyl_fact_artifact_inventory_snapshot_free);
  g_assert_cmpint (wyl_fact_artifact_transition_windows_capture (provider,
      &life, &snapshot, &obs), ==, WYRELOG_E_OK);
  g_clear_pointer (&tx, wyl_fact_artifact_main_transition_free);
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&req, snapshot,
      &obs, &res, &tx), ==, WYRELOG_E_OK);
  g_assert_cmpint (res.state, ==, MT (STATE_RETAINED));

  /* Unwind: ROLLBACK -> RETIRE_STAGE */
  WylFactArtifactMainTransitionOp unwind_ops[] = {
    MT (OP_ROLLBACK),
    MT (OP_RETIRE_STAGE),
  };
  for (gsize i = 0; i < G_N_ELEMENTS (unwind_ops); i++) {
    Observation step_obs = { 0 };
    g_assert_cmpint (wyl_fact_artifact_transition_windows_observe (provider,
        &life, &step_obs), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_main_transition_authorize (tx,
        unwind_ops[i], &step_obs, &res), ==, WYRELOG_E_OK);
    WylFactArtifactMainTransitionEffect effect
      = MT (EFFECT_NOT_APPLIED);
    WylFactArtifactMainTransitionDurabilityEvidence dur = { 0 };
    g_assert_cmpint (wyl_fact_artifact_transition_windows_execute
          (provider, &step_obs, unwind_ops[i], &effect, &dur), ==, WYRELOG_E_OK);
    g_assert_cmpint (effect, ==, MT (EFFECT_APPLIED));

    g_assert_cmpint (wyl_fact_artifact_transition_windows_observe (provider,
        &life, &step_obs), ==, WYRELOG_E_OK);
    step_obs.durability = dur;
    g_assert_cmpint (wyl_fact_artifact_main_transition_record (tx,
        unwind_ops[i], effect, &step_obs, &res), ==, WYRELOG_E_OK);
    if (unwind_ops[i] == MT (OP_ROLLBACK)) {
      g_assert_cmpint (res.state, ==, MT (STATE_ROLLED_BACK));
      WylTestDriverStoredValue rolled_back = completed_driver_value (&req,
              unwind_ops[i], res.state);
      g_clear_pointer (&snapshot, wyl_fact_artifact_inventory_snapshot_free);
      Observation restarted_observation = { 0 };
      g_assert_cmpint (wyl_fact_artifact_transition_windows_capture (provider,
          &life, &snapshot, &restarted_observation), ==, WYRELOG_E_OK);
      Result restarted_result = { 0 };
      g_autoptr (WylFactArtifactMainTransition) restarted_transition = NULL;
      g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&req, snapshot,
          &restarted_observation, &restarted_result, &restarted_transition),
          ==, WYRELOG_E_OK);
      g_assert_cmpint (restarted_result.state, ==, MT (STATE_READY));
      g_assert_cmpint (wyl_test_driver_restart_action (&rolled_back,
          restarted_result.state), ==, WYL_TEST_DRIVER_RESTART_RETIRE_STAGE);
      g_clear_pointer (&tx, wyl_fact_artifact_main_transition_free);
      tx = g_steal_pointer (&restarted_transition);
      res = restarted_result;
    }
  }

  g_assert_cmpint (res.state, ==, MT (STATE_ABANDONED));
  fixture_clear (&f);
}

static void
test_execute_fault_seams_coverage (void)
{
  Fixture f;
  fixture_init (&f, "fault-seams");
  create_owner_only_file (f.directory.graph_handle,
      WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, "main");
  create_owner_only_file (f.directory.graph_handle, f.names.stage, "stage");

  Capability cap = { .no_replace_supported = TRUE, .directory_flush = MT (
                       DURABILITY_PROVEN) };
  g_autoptr (WylFactArtifactTransitionWindows) provider = NULL;
  g_assert_cmpint (wyl_fact_artifact_transition_windows_open
        (&f.resolver, &f.directory, f.lease, OPERATION_UUID, &cap,
      &provider), ==,
      WYRELOG_E_OK);

  Lifecycle life = { .sealed = TRUE, .main_binding_live = FALSE };
  Observation obs = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_observe (provider,
      &life, &obs), ==, WYRELOG_E_OK);

  /* Fault: EXECUTE_LEASE_VERIFY */
  wyl_fact_artifact_transition_windows_set_test_fault (WF (EXECUTE_LEASE_VERIFY));
  WylFactArtifactMainTransitionEffect eff = MT (EFFECT_NOT_APPLIED);
  WylFactArtifactMainTransitionDurabilityEvidence dur = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_execute (provider,
      &obs, MT (OP_SYNC_STAGED), &eff, &dur), ==, WYRELOG_E_POLICY);
  g_assert_true (wyl_fact_artifact_transition_windows_test_fault_was_consumed (
        WF (EXECUTE_LEASE_VERIFY)));

  /* Fault: EXECUTE_SYNC_STAGED_OPEN */
  wyl_fact_artifact_transition_windows_set_test_fault (WF (
        EXECUTE_SYNC_STAGED_OPEN));
  g_assert_cmpint (wyl_fact_artifact_transition_windows_execute (provider,
      &obs, MT (OP_SYNC_STAGED), &eff, &dur), ==, WYRELOG_E_OK);
  g_assert_cmpint (eff, ==, MT (EFFECT_UNKNOWN));
  g_assert_true (wyl_fact_artifact_transition_windows_test_fault_was_consumed (
        WF (EXECUTE_SYNC_STAGED_OPEN)));

  fixture_clear (&f);
}

static void
test_observe_hardlink_detected (void)
{
  Fixture f;
  fixture_init (&f, "hardlink");
  create_owner_only_file (f.directory.graph_handle, f.names.stage, "data");

  g_autofree gchar *target_path = g_build_filename (f.root, "target.duckdb",
          NULL);
  g_autofree gchar *stage_path = g_build_filename (f.graph_path, f.names.stage,
          NULL);
  glong target_len = 0, stage_len = 0;
  g_autofree WCHAR *wide_target = g_utf8_to_utf16 (target_path, -1, NULL,
          &target_len, NULL);
  g_autofree WCHAR *wide_stage = g_utf8_to_utf16 (stage_path, -1, NULL,
          &stage_len, NULL);
  g_assert_true (CreateHardLinkW (wide_target, wide_stage, NULL));

  Capability cap = { .no_replace_supported = TRUE, .directory_flush = MT (
                       DURABILITY_PROVEN) };
  g_autoptr (WylFactArtifactTransitionWindows) provider = NULL;
  g_assert_cmpint (wyl_fact_artifact_transition_windows_open
        (&f.resolver, &f.directory, f.lease, OPERATION_UUID, &cap,
      &provider), ==,
      WYRELOG_E_OK);

  Lifecycle life = { .sealed = TRUE, .main_binding_live = FALSE };
  Observation obs = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_observe (provider,
      &life, &obs), ==, WYRELOG_E_OK);

  g_assert_true (obs.entries[SLOT_STAGE].present);
  g_assert_cmpuint (obs.entries[SLOT_STAGE].link_count, ==, 2);

  Request req = request_for (&obs, (Identity) { 0 },
          obs.entries[SLOT_STAGE].identity, TRUE);
  Result res = { 0 };
  g_autoptr (WylFactArtifactMainTransition) tx = NULL;
  g_assert_cmpint (admit (&obs, &req, &res, &tx), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (res.refusal, ==, MT (REFUSAL_LINK_SUBSTITUTION));

  fixture_clear (&f);
}

static void
test_probe_capability_directory_flush_unsupported (void)
{
  Fixture f;
  fixture_init (&f, "probe-dir-unsupp");
  wyl_fact_artifact_transition_windows_set_test_fault (WF (
        PROBE_DIRECTORY_FSYNC));
  wyl_fact_artifact_transition_windows_set_test_flush_error (ERROR_NOT_SUPPORTED);
  Capability cap = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_probe_capability
        (&f.directory, OPERATION_UUID, &cap), ==, WYRELOG_E_OK);
  g_assert_true (cap.no_replace_supported);
  g_assert_cmpint (cap.directory_flush, ==, MT (DURABILITY_UNSUPPORTED));
  g_assert_true (wyl_fact_artifact_transition_windows_test_fault_was_consumed (
        WF (PROBE_DIRECTORY_FSYNC)));
  fixture_clear (&f);
}

static void
test_probe_capability_directory_flush_io_fails_closed (void)
{
  Fixture f;
  fixture_init (&f, "probe-dir-io");
  wyl_fact_artifact_transition_windows_set_test_fault (WF (
        PROBE_DIRECTORY_FSYNC));
  wyl_fact_artifact_transition_windows_set_test_flush_error (ERROR_IO_DEVICE);
  Capability cap = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_probe_capability
        (&f.directory, OPERATION_UUID, &cap), ==, WYRELOG_E_IO);
  g_assert_true (wyl_fact_artifact_transition_windows_test_fault_was_consumed (
        WF (PROBE_DIRECTORY_FSYNC)));
  fixture_clear (&f);
}

static void
test_execute_authorization_mismatch_fails_closed (void)
{
  Fixture f;
  fixture_init (&f, "auth-mismatch");
  create_owner_only_file (f.directory.graph_handle, f.names.stage, "stage");

  Capability cap = { .no_replace_supported = TRUE, .directory_flush = MT (
                       DURABILITY_PROVEN) };
  g_autoptr (WylFactArtifactTransitionWindows) provider = NULL;
  g_assert_cmpint (wyl_fact_artifact_transition_windows_open
        (&f.resolver, &f.directory, f.lease, OPERATION_UUID, &cap,
      &provider), ==,
      WYRELOG_E_OK);

  Lifecycle life = { .sealed = TRUE, .main_binding_live = FALSE };
  Observation obs = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_observe (provider,
      &life, &obs), ==, WYRELOG_E_OK);

  /* Tamper with operation UUID */
  Observation tampered = obs;
  tampered.operation_uuid[0] ^= 1;
  WylFactArtifactMainTransitionEffect eff = MT (EFFECT_NOT_APPLIED);
  WylFactArtifactMainTransitionDurabilityEvidence dur = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_execute (provider,
      &tampered, MT (OP_SYNC_STAGED), &eff, &dur), ==, WYRELOG_E_INVALID);

  /* Tamper with lease lock identity */
  tampered = obs;
  tampered.lease_identity.object_bytes[0] ^= 1;
  g_assert_cmpint (wyl_fact_artifact_transition_windows_execute (provider,
      &tampered, MT (OP_SYNC_STAGED), &eff, &dur), ==, WYRELOG_E_POLICY);

  fixture_clear (&f);
}

static void
test_execute_entry_substitution_detected (void)
{
  Fixture f;
  fixture_init (&f, "entry-subst");
  create_owner_only_file (f.directory.graph_handle,
      WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, "main");
  create_owner_only_file (f.directory.graph_handle, f.names.stage, "stage");

  Capability cap = { .no_replace_supported = TRUE, .directory_flush = MT (
                       DURABILITY_PROVEN) };
  g_autoptr (WylFactArtifactTransitionWindows) provider = NULL;
  g_assert_cmpint (wyl_fact_artifact_transition_windows_open
        (&f.resolver, &f.directory, f.lease, OPERATION_UUID, &cap,
      &provider), ==,
      WYRELOG_E_OK);

  Lifecycle life = { .sealed = TRUE, .main_binding_live = FALSE };
  Observation obs = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_observe (provider,
      &life, &obs), ==, WYRELOG_E_OK);

  /* Tamper with observed main identity */
  Observation tampered = obs;
  tampered.entries[SLOT_MAIN].identity.object_bytes[0] ^= 0x55;

  WylFactArtifactMainTransitionEffect eff = MT (EFFECT_APPLIED);
  WylFactArtifactMainTransitionDurabilityEvidence dur = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_execute (provider,
      &tampered, MT (OP_RETAIN), &eff, &dur), ==, WYRELOG_E_OK);
  g_assert_cmpint (eff, ==, MT (EFFECT_NOT_APPLIED));

  /* Tamper with observed stage identity for SYNC_STAGED */
  tampered = obs;
  tampered.entries[SLOT_STAGE].identity.object_bytes[0] ^= 0xAA;
  eff = MT (EFFECT_APPLIED);
  g_assert_cmpint (wyl_fact_artifact_transition_windows_execute (provider,
      &tampered, MT (OP_SYNC_STAGED), &eff, &dur), ==, WYRELOG_E_OK);
  g_assert_cmpint (eff, ==, MT (EFFECT_NOT_APPLIED));

  fixture_clear (&f);
}

static void
test_correlated_capture_uses_real_inventory (void)
{
  Fixture f;
  fixture_init (&f, "driver-capture");
  create_owner_only_file (f.directory.graph_handle,
      WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, "main");
  create_owner_only_file (f.directory.graph_handle, f.names.stage, "stage");
  Capability cap = { .no_replace_supported = TRUE,
                     .directory_flush = MT (DURABILITY_PROVEN) };
  g_autoptr (WylFactArtifactTransitionWindows) provider = NULL;
  g_assert_cmpint (wyl_fact_artifact_transition_windows_open (&f.resolver,
      &f.directory, f.lease, OPERATION_UUID, &cap, &provider), ==,
      WYRELOG_E_OK);
  Lifecycle lifecycle = { .sealed = TRUE, .main_binding_live = FALSE };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  Observation observation = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_capture (provider,
      &lifecycle, &snapshot, &observation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_inventory_snapshot_status (snapshot), ==,
      WYL_FACT_ARTIFACT_INVENTORY_STATUS_STABLE_WITH_UNKNOWN);
  g_assert_cmpuint (wyl_fact_artifact_inventory_snapshot_anomaly_count
        (snapshot, WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY), ==, 1);
  WylFactArtifactInventoryObservation inventory = { 0 };
  g_assert_true (wyl_fact_artifact_inventory_snapshot_get_observation
        (snapshot, &inventory));
  g_assert_true (wyl_fact_artifact_inventory_identity_equal
        (&inventory.directory_identity, &observation.directory_identity));
  g_assert_true (wyl_fact_artifact_inventory_identity_equal
        (&inventory.guard_identity, &observation.lease_identity));
  Request request = request_for (&observation,
          observation.entries[SLOT_MAIN].identity,
          observation.entries[SLOT_STAGE].identity, FALSE);
  Result result = { 0 };
  g_autoptr (WylFactArtifactMainTransition) transition = NULL;
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&request, snapshot,
      &observation, &result, &transition), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_READY));
  fixture_clear (&f);
}

static void
test_between_scan_mutation_publishes_no_outputs (void)
{
  Fixture fixture;
  fixture_init (&fixture, "driver-unstable");
  create_owner_only_file (fixture.directory.graph_handle,
      WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, "main");
  create_owner_only_file (fixture.directory.graph_handle, fixture.names.stage,
      "stage");
  Capability capability = { .no_replace_supported = TRUE,
                            .directory_flush = MT (DURABILITY_PROVEN) };
  g_autoptr (WylFactArtifactTransitionWindows) provider = NULL;
  g_assert_cmpint (wyl_fact_artifact_transition_windows_open
        (&fixture.resolver, &fixture.directory, fixture.lease, OPERATION_UUID,
      &capability, &provider), ==, WYRELOG_E_OK);
  wyl_fact_artifact_transition_windows_set_test_fault (WF (
        CAPTURE_BETWEEN_SCANS_RETIRE_STAGE));
  Lifecycle lifecycle = { .sealed = TRUE, .main_binding_live = FALSE };
  WylFactArtifactInventorySnapshot *snapshot
    = (WylFactArtifactInventorySnapshot *) 0x1;
  Observation observation;
  memset (&observation, 0xA5, sizeof observation);
  g_assert_cmpint (wyl_fact_artifact_transition_windows_capture (provider,
      &lifecycle, &snapshot, &observation), ==, WYRELOG_E_BUSY);
  g_assert_null (snapshot);
  g_assert_cmpmem (&observation, sizeof observation,
      &(Observation) { 0 }, sizeof observation);
  g_assert_true (wyl_fact_artifact_transition_windows_test_fault_was_consumed
        (WF (CAPTURE_BETWEEN_SCANS_RETIRE_STAGE)));
  fixture_clear (&fixture);
}

static void
test_case_alias_is_ambiguous_without_mutation (void)
{
  Fixture fixture;
  fixture_init (&fixture, "driver-case-alias");
  create_owner_only_file (fixture.directory.graph_handle,
      WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, "main");
  g_autofree gchar *alias = g_ascii_strup (fixture.names.stage, -1);
  g_assert_cmpstr (alias, !=, fixture.names.stage);
  create_owner_only_file (fixture.directory.graph_handle, alias, "stage");
  Capability capability = { .no_replace_supported = TRUE,
                            .directory_flush = MT (DURABILITY_PROVEN) };
  g_autoptr (WylFactArtifactTransitionWindows) provider = NULL;
  g_assert_cmpint (wyl_fact_artifact_transition_windows_open
        (&fixture.resolver, &fixture.directory, fixture.lease, OPERATION_UUID,
      &capability, &provider), ==, WYRELOG_E_OK);
  Lifecycle lifecycle = { .sealed = TRUE, .main_binding_live = FALSE };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  Observation observation = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_capture (provider,
      &lifecycle, &snapshot, &observation), ==, WYRELOG_E_OK);
  g_assert_cmpuint (wyl_fact_artifact_inventory_snapshot_anomaly_count
        (snapshot, WYL_FACT_ARTIFACT_INVENTORY_AMBIGUOUS_ENTRY), ==, 1);
  Identity staged = observation.directory_identity;
  staged.object_bytes[0] ^= 1;
  Request request = request_for (&observation,
          observation.entries[SLOT_MAIN].identity, staged, FALSE);
  Result result = { 0 };
  g_autoptr (WylFactArtifactMainTransition) transition = NULL;
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&request, snapshot,
      &observation, &result, &transition), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result.refusal, ==, MT (REFUSAL_INVENTORY_ANOMALOUS));
  g_assert_true (observation.entries[SLOT_MAIN].present);
  g_assert_false (observation.entries[SLOT_STAGE].present);
  g_assert_false (observation.entries[SLOT_ROLLBACK].present);
  fixture_clear (&fixture);
}

typedef struct
{
  gboolean main_present;
  gboolean main_is_stage;
  gboolean stage_present;
  gboolean rollback_present;
  gboolean expected_main_absent;
  WylFactArtifactMainTransitionState expected_state;
} RealCaptureRow;

static Identity
fabricated_identity (const Observation *observation, guint8 discriminator)
{
  Identity identity = observation->directory_identity;
  identity.object = 0;
  memset (identity.object_bytes, 0, sizeof identity.object_bytes);
  identity.object_bytes[0] = discriminator;
  return identity;
}

static void
test_real_capture_state_matrix (void)
{
  const RealCaptureRow rows[] = {
    { TRUE, FALSE, TRUE, FALSE, FALSE, MT (STATE_READY) },
    { FALSE, FALSE, TRUE, TRUE, FALSE, MT (STATE_RETAINED) },
    { FALSE, FALSE, FALSE, TRUE, FALSE, MT (STATE_RETAINED_STAGE_LOST) },
    { TRUE, TRUE, FALSE, TRUE, FALSE, MT (STATE_PUBLISHED) },
    { TRUE, TRUE, FALSE, FALSE, FALSE, MT (STATE_FINALIZED) },
    { TRUE, FALSE, FALSE, FALSE, FALSE, MT (STATE_ABANDONED) },
    { FALSE, FALSE, TRUE, FALSE, TRUE, MT (STATE_READY) },
    { TRUE, TRUE, FALSE, FALSE, TRUE, MT (STATE_PUBLISHED) },
    { FALSE, FALSE, FALSE, FALSE, TRUE, MT (STATE_ABANDONED) },
  };
  for (guint index = 0; index < G_N_ELEMENTS (rows); index++) {
    Fixture fixture;
    g_autofree gchar *tag = g_strdup_printf ("driver-state-%u", index);
    fixture_init (&fixture, tag);
    if (rows[index].main_present)
      create_owner_only_file (fixture.directory.graph_handle,
          WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, "main");
    if (rows[index].stage_present)
      create_owner_only_file (fixture.directory.graph_handle,
          fixture.names.stage, "stage");
    if (rows[index].rollback_present)
      create_owner_only_file (fixture.directory.graph_handle,
          fixture.names.rollback, "rollback");
    Capability capability = { .no_replace_supported = TRUE,
                              .directory_flush = MT (DURABILITY_PROVEN) };
    g_autoptr (WylFactArtifactTransitionWindows) provider = NULL;
    g_assert_cmpint (wyl_fact_artifact_transition_windows_open
          (&fixture.resolver, &fixture.directory, fixture.lease,
        OPERATION_UUID, &capability, &provider), ==, WYRELOG_E_OK);
    Lifecycle lifecycle = { .sealed = TRUE, .main_binding_live = FALSE };
    g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
    Observation observation = { 0 };
    g_assert_cmpint (wyl_fact_artifact_transition_windows_capture (provider,
        &lifecycle, &snapshot, &observation), ==, WYRELOG_E_OK);
    Identity expected = fabricated_identity (&observation, 0x31);
    Identity staged = fabricated_identity (&observation, 0x32);
    if (rows[index].rollback_present)
      expected = observation.entries[SLOT_ROLLBACK].identity;
    else if (rows[index].main_present && !rows[index].main_is_stage)
      expected = observation.entries[SLOT_MAIN].identity;
    if (rows[index].stage_present)
      staged = observation.entries[SLOT_STAGE].identity;
    else if (rows[index].main_is_stage)
      staged = observation.entries[SLOT_MAIN].identity;
    Request request = request_for (&observation, expected, staged,
            rows[index].expected_main_absent);
    Result result = { 0 };
    g_autoptr (WylFactArtifactMainTransition) transition = NULL;
    g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&request,
        snapshot, &observation, &result, &transition), ==, WYRELOG_E_OK);
    g_assert_cmpint (result.state, ==, rows[index].expected_state);
    fixture_clear (&fixture);
  }
}

static void
test_foreign_root_authority_never_mutates (void)
{
  Fixture f;
  Fixture foreign;
  fixture_init (&f, "driver-authority-a");
  fixture_init (&foreign, "driver-authority-b");
  create_owner_only_file (f.directory.graph_handle,
      WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, "main");
  create_owner_only_file (f.directory.graph_handle, f.names.stage, "stage");
  Capability cap = { .no_replace_supported = TRUE,
                     .directory_flush = MT (DURABILITY_PROVEN) };
  g_autoptr (WylFactArtifactTransitionWindows) provider = NULL;
  g_assert_cmpint (wyl_fact_artifact_transition_windows_open (&f.resolver,
      &f.directory, f.lease, OPERATION_UUID, &cap, &provider), ==,
      WYRELOG_E_OK);
  Lifecycle lifecycle = { .sealed = TRUE, .main_binding_live = FALSE };
  Observation authorized = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_observe (provider,
      &lifecycle, &authorized), ==, WYRELOG_E_OK);
  g_autoptr (WylFactArtifactTransitionWindows) refused = NULL;
  g_assert_cmpint (wyl_fact_artifact_transition_windows_open
        (&foreign.resolver, &foreign.directory, f.lease, OPERATION_UUID, &cap,
      &refused), ==, WYRELOG_E_POLICY);
  g_assert_null (refused);

  WylFactGraphResolver original = f.resolver;
  f.resolver = foreign.resolver;
  foreign.resolver = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  Observation refused_observation = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_capture (provider,
      &lifecycle, &snapshot, &refused_observation), ==, WYRELOG_E_POLICY);
  g_assert_null (snapshot);
  WylFactArtifactMainTransitionEffect effect = MT (EFFECT_APPLIED);
  WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_execute (provider,
      &authorized, MT (OP_RETAIN), &effect, &durability), ==,
      WYRELOG_E_POLICY);
  WylFactGraphResolver foreign_value = f.resolver;
  f.resolver = original;
  foreign.resolver = foreign_value;
  Observation after = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_observe (provider,
      &lifecycle, &after), ==, WYRELOG_E_OK);
  g_assert_true (after.entries[SLOT_MAIN].present);
  g_assert_true (after.entries[SLOT_STAGE].present);
  g_assert_false (after.entries[SLOT_ROLLBACK].present);
  fixture_clear (&foreign);
  fixture_clear (&f);
}

static void
test_graph_directory_authority_is_revalidated (void)
{
  Fixture fixture;
  fixture_init (&fixture, "driver-directory-authority");
  create_owner_only_file (fixture.directory.graph_handle,
      WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, "main");
  create_owner_only_file (fixture.directory.graph_handle, fixture.names.stage,
      "stage");
  Capability capability = { .no_replace_supported = TRUE,
                            .directory_flush = MT (DURABILITY_PROVEN) };
  g_autoptr (WylFactArtifactTransitionWindows) provider = NULL;

  g_assert_true (SetHandleInformation (fixture.directory.graph_handle,
      HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT));
  g_assert_cmpint (wyl_fact_artifact_transition_windows_open
        (&fixture.resolver, &fixture.directory, fixture.lease, OPERATION_UUID,
      &capability, &provider), ==, WYRELOG_E_POLICY);
  g_assert_null (provider);
  g_assert_true (SetHandleInformation (fixture.directory.graph_handle,
      HANDLE_FLAG_INHERIT, 0));

  g_assert_true (SetHandleInformation (fixture.directory.root_handle,
      HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT));
  g_assert_cmpint (wyl_fact_artifact_transition_windows_open
        (&fixture.resolver, &fixture.directory, fixture.lease, OPERATION_UUID,
      &capability, &provider), ==, WYRELOG_E_POLICY);
  g_assert_null (provider);
  g_assert_true (SetHandleInformation (fixture.directory.root_handle,
      HANDLE_FLAG_INHERIT, 0));

  unprotect_directory_acl (fixture.graph_path);
  g_assert_cmpint (wyl_fact_artifact_transition_windows_open
        (&fixture.resolver, &fixture.directory, fixture.lease, OPERATION_UUID,
      &capability, &provider), ==, WYRELOG_E_POLICY);
  g_assert_null (provider);
  set_directory_owner_only_acl (fixture.graph_path);

  g_assert_cmpint (wyl_fact_artifact_transition_windows_open
        (&fixture.resolver, &fixture.directory, fixture.lease, OPERATION_UUID,
      &capability, &provider), ==, WYRELOG_E_OK);
  Lifecycle lifecycle = { .sealed = TRUE, .main_binding_live = FALSE };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  Observation authorized = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_capture (provider,
      &lifecycle, &snapshot, &authorized), ==, WYRELOG_E_OK);

  g_assert_true (SetHandleInformation (fixture.directory.graph_handle,
      HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT));
  WylFactArtifactInventorySnapshot *refused_snapshot
    = (WylFactArtifactInventorySnapshot *) 0x1;
  Observation refused_observation;
  memset (&refused_observation, 0xA5, sizeof refused_observation);
  g_assert_cmpint (wyl_fact_artifact_transition_windows_capture (provider,
      &lifecycle, &refused_snapshot, &refused_observation), ==,
      WYRELOG_E_POLICY);
  g_assert_null (refused_snapshot);
  WylFactArtifactMainTransitionEffect effect = MT (EFFECT_APPLIED);
  WylFactArtifactMainTransitionDurabilityEvidence durability = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_execute (provider,
      &authorized, MT (OP_RETAIN), &effect, &durability), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (effect, ==, MT (EFFECT_NOT_APPLIED));
  g_assert_true (SetHandleInformation (fixture.directory.graph_handle,
      HANDLE_FLAG_INHERIT, 0));

  g_assert_true (SetHandleInformation (fixture.directory.root_handle,
      HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT));
  refused_snapshot = (WylFactArtifactInventorySnapshot *) 0x1;
  memset (&refused_observation, 0xA5, sizeof refused_observation);
  g_assert_cmpint (wyl_fact_artifact_transition_windows_capture (provider,
      &lifecycle, &refused_snapshot, &refused_observation), ==,
      WYRELOG_E_POLICY);
  g_assert_null (refused_snapshot);
  effect = MT (EFFECT_APPLIED);
  g_assert_cmpint (wyl_fact_artifact_transition_windows_execute (provider,
      &authorized, MT (OP_RETAIN), &effect, &durability), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (effect, ==, MT (EFFECT_NOT_APPLIED));
  g_assert_true (SetHandleInformation (fixture.directory.root_handle,
      HANDLE_FLAG_INHERIT, 0));

  unprotect_directory_acl (fixture.graph_path);
  refused_snapshot = (WylFactArtifactInventorySnapshot *) 0x1;
  memset (&refused_observation, 0xA5, sizeof refused_observation);
  g_assert_cmpint (wyl_fact_artifact_transition_windows_capture (provider,
      &lifecycle, &refused_snapshot, &refused_observation), ==,
      WYRELOG_E_POLICY);
  g_assert_null (refused_snapshot);
  effect = MT (EFFECT_APPLIED);
  g_assert_cmpint (wyl_fact_artifact_transition_windows_execute (provider,
      &authorized, MT (OP_RETAIN), &effect, &durability), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (effect, ==, MT (EFFECT_NOT_APPLIED));
  set_directory_owner_only_acl (fixture.graph_path);

  g_clear_pointer (&snapshot, wyl_fact_artifact_inventory_snapshot_free);
  authorized = (Observation) { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_capture (provider,
      &lifecycle, &snapshot, &authorized), ==, WYRELOG_E_OK);
  g_assert_true (authorized.entries[SLOT_MAIN].present);
  g_assert_true (authorized.entries[SLOT_STAGE].present);
  g_assert_false (authorized.entries[SLOT_ROLLBACK].present);
  fixture_clear (&fixture);
}

static void
test_child_crash_restarts_from_fresh_capture (void)
{
  Fixture fixture;
  fixture_init (&fixture, "driver-child-crash");
  create_owner_only_file (fixture.directory.graph_handle,
      WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME, "main");
  create_owner_only_file (fixture.directory.graph_handle, fixture.names.stage,
      "stage");
  Capability capability = { .no_replace_supported = TRUE,
                            .directory_flush = MT (DURABILITY_PROVEN) };
  g_autoptr (WylFactArtifactTransitionWindows) provider = NULL;
  g_assert_cmpint (wyl_fact_artifact_transition_windows_open
        (&fixture.resolver, &fixture.directory, fixture.lease, OPERATION_UUID,
      &capability, &provider), ==, WYRELOG_E_OK);
  Lifecycle lifecycle = { .sealed = TRUE, .main_binding_live = FALSE };
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot = NULL;
  Observation observation = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_capture (provider,
      &lifecycle, &snapshot, &observation), ==, WYRELOG_E_OK);
  Request request = request_for (&observation,
          observation.entries[SLOT_MAIN].identity,
          observation.entries[SLOT_STAGE].identity, FALSE);
  WylTestDriverStoredValue initial = {
    .version = 1,
    .revision = 11,
    .consumer_generation = 23,
    .directory_identity = request.directory_identity,
    .lease_identity = request.lease_identity,
    .expected_main_absent = request.expected_main_absent,
    .expected_main_identity = request.expected_main_identity,
    .staged_main_identity = request.staged_main_identity,
    .resume_forbidden = request.resume_forbidden,
    .durability_unprovable_acknowledged
      = request.durability_unprovable_acknowledged,
    .marker = WYL_TEST_DRIVER_MARKER_NONE,
    .pending_op = MT (OP_NONE),
    .completed_state = MT (STATE_INVALID),
  };
  g_strlcpy (initial.operation_uuid, OPERATION_UUID,
      sizeof initial.operation_uuid);
  g_autofree gchar *root = g_strdup (fixture.root);
  g_autofree gchar *store_path = g_build_filename (root,
          "driver-state-windows", NULL);
  g_autofree gchar *counter_path = g_build_filename (root,
          "driver-count-windows", NULL);
  g_assert_cmpint (windows_store_write (store_path, &initial, TRUE), ==,
      WYRELOG_E_OK);
  g_assert_true (windows_create_counter (counter_path));
  g_clear_pointer (&snapshot, wyl_fact_artifact_inventory_snapshot_free);
  g_clear_pointer (&provider, wyl_fact_artifact_transition_windows_free);
  fixture_clear (&fixture);

  spawn_driver_crash_child (root, store_path, counter_path);
  WindowsFileStore file = { .path = store_path };
  WylTestDriverValueStore store = windows_value_store (&file);
  WylTestDriverStoredValue stored = { 0 };
  g_assert_cmpint (store.load (store.user_data, &stored), ==, WYRELOG_E_OK);
  g_assert_cmpint (stored.marker, ==, WYL_TEST_DRIVER_MARKER_ATTEMPT_UNKNOWN);
  g_assert_cmpint (stored.pending_op, ==, MT (OP_RETAIN));
  g_assert_cmpuint (stored.consumer_generation, ==, 23);
  g_assert_true (wyl_fact_artifact_inventory_identity_equal
        (&stored.expected_main_identity, &initial.expected_main_identity));
  g_assert_true (wyl_fact_artifact_inventory_identity_equal
        (&stored.staged_main_identity, &initial.staged_main_identity));

  fixture_open_existing (&fixture, root);
  provider = NULL;
  g_assert_cmpint (wyl_fact_artifact_transition_windows_open
        (&fixture.resolver, &fixture.directory, fixture.lease, OPERATION_UUID,
      &capability, &provider), ==, WYRELOG_E_OK);
  observation = (Observation) { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_capture (provider,
      &lifecycle, &snapshot, &observation), ==, WYRELOG_E_OK);
  g_assert_false (observation.entries[SLOT_MAIN].present);
  g_assert_true (observation.entries[SLOT_STAGE].present);
  g_assert_true (observation.entries[SLOT_ROLLBACK].present);
  request = request_from_stored (&stored);
  Result result = { 0 };
  g_autoptr (WylFactArtifactMainTransition) transition = NULL;
  g_assert_cmpint (wyl_fact_artifact_main_transition_admit (&request, snapshot,
      &observation, &result, &transition), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.state, ==, MT (STATE_RETAINED));
  g_assert_cmpint (wyl_test_driver_restart_action (&stored, result.state), ==,
      WYL_TEST_DRIVER_RESTART_INSPECT_ONLY);
  g_autofree gchar *count = NULL;
  g_assert_true (g_file_get_contents (counter_path, &count, NULL, NULL));
  g_assert_cmpstr (count, ==, "1");
  fixture_clear (&fixture);
}

int
main (int argc, char **argv)
{
  if (argc == 5 && strcmp (argv[1], "--driver-crash-child") == 0)
    return run_driver_crash_child (argv[2], argv[3], argv[4]);
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact-artifact-transition/windows/names-match",
      test_names_derived_internally_match);
  g_test_add_func ("/fact-artifact-transition/windows/observe-triple",
      test_observe_all_three_slots_present);
  g_test_add_func ("/fact-artifact-transition/windows/observe-absent",
      test_observe_absent_permutations);
  g_test_add_func ("/fact-artifact-transition/windows/observe-unreadable",
      test_observe_unreadable_slot_fails_closed);
  g_test_add_func ("/fact-artifact-transition/windows/observe-hardlink",
      test_observe_hardlink_detected);
  g_test_add_func ("/fact-artifact-transition/windows/probe-happy",
      test_probe_capability_happy_path);
  g_test_add_func ("/fact-artifact-transition/windows/probe-preclean",
      test_probe_capability_preclean_recovery);
  g_test_add_func ("/fact-artifact-transition/windows/probe-preclean-fail",
      test_probe_capability_preclean_failure_fails_closed);
  g_test_add_func ("/fact-artifact-transition/windows/probe-rename-unsupp",
      test_probe_capability_rename_unsupported);
  g_test_add_func ("/fact-artifact-transition/windows/probe-dir-unsupp",
      test_probe_capability_directory_flush_unsupported);
  g_test_add_func ("/fact-artifact-transition/windows/probe-dir-io-fail",
      test_probe_capability_directory_flush_io_fails_closed);
  g_test_add_func ("/fact-artifact-transition/windows/mode-a-lifecycle",
      test_mode_a_full_lifecycle);
  g_test_add_func ("/fact-artifact-transition/windows/mode-b-lifecycle",
      test_mode_b_full_lifecycle_absent_rollback);
  g_test_add_func ("/fact-artifact-transition/windows/mode-a-rollback",
      test_mode_a_rollback_lifecycle);
  g_test_add_func ("/fact-artifact-transition/windows/fault-seams",
      test_execute_fault_seams_coverage);
  g_test_add_func ("/fact-artifact-transition/windows/auth-mismatch",
      test_execute_authorization_mismatch_fails_closed);
  g_test_add_func ("/fact-artifact-transition/windows/entry-substitution",
      test_execute_entry_substitution_detected);
  g_test_add_func ("/fact-artifact-transition/windows/driver/capture",
      test_correlated_capture_uses_real_inventory);
  g_test_add_func ("/fact-artifact-transition/windows/driver/unstable",
      test_between_scan_mutation_publishes_no_outputs);
  g_test_add_func ("/fact-artifact-transition/windows/driver/case-alias",
      test_case_alias_is_ambiguous_without_mutation);
  g_test_add_func ("/fact-artifact-transition/windows/driver/state-matrix",
      test_real_capture_state_matrix);
  g_test_add_func ("/fact-artifact-transition/windows/driver/root-authority",
      test_foreign_root_authority_never_mutates);
  g_test_add_func ("/fact-artifact-transition/windows/driver/directory-authority",
      test_graph_directory_authority_is_revalidated);
  g_test_add_func ("/fact-artifact-transition/windows/driver/child-crash-restart",
      test_child_crash_restarts_from_fresh_capture);
  return g_test_run ();
}

#else
int
main (void)
{
  return 0;
}
#endif

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>

#ifdef G_OS_WIN32
#include <aclapi.h>
#include <string.h>
#include <windows.h>
#include <winternl.h>

#include "fact-test-support.h"
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

static wyrelog_error_t
admit (const Observation *observation, const Request *request,
    Result *out_result, Transition **out_transition)
{
  g_autoptr (WylFactArtifactInventorySnapshot) snapshot
    = hand_built_snapshot (observation, TRUE);
  return wyl_fact_artifact_main_transition_admit (request, snapshot,
             observation, out_result, out_transition);
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
        (&f.directory, f.lease, OPERATION_UUID, &cap, &p), ==, WYRELOG_E_OK);

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
        (&f.directory, f.lease, OPERATION_UUID, &cap, &p), ==, WYRELOG_E_OK);

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
        (&f.directory, f.lease, OPERATION_UUID, &cap, &p), ==, WYRELOG_E_OK);

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
        (&f.directory, f.lease, OPERATION_UUID, &cap, &provider), ==,
      WYRELOG_E_OK);

  Lifecycle life = { .sealed = TRUE, .main_binding_live = FALSE };
  Observation obs = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_observe (provider,
      &life, &obs), ==, WYRELOG_E_OK);

  Identity main_id = obs.entries[SLOT_MAIN].identity;
  Identity stage_id = obs.entries[SLOT_STAGE].identity;
  Request req = request_for (&obs, main_id, stage_id, FALSE);

  Result res = { 0 };
  g_autoptr (WylFactArtifactMainTransition) tx = NULL;
  g_assert_cmpint (admit (&obs, &req, &res, &tx), ==, WYRELOG_E_OK);
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
        (&f.directory, f.lease, OPERATION_UUID, &cap, &provider), ==,
      WYRELOG_E_OK);

  Lifecycle life = { .sealed = TRUE, .main_binding_live = FALSE };
  Observation obs = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_observe (provider,
      &life, &obs), ==, WYRELOG_E_OK);

  Identity stage_id = obs.entries[SLOT_STAGE].identity;
  Request req = request_for (&obs, (Identity) { 0 }, stage_id, TRUE);

  Result res = { 0 };
  g_autoptr (WylFactArtifactMainTransition) tx = NULL;
  g_assert_cmpint (admit (&obs, &req, &res, &tx), ==, WYRELOG_E_OK);
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
        (&f.directory, f.lease, OPERATION_UUID, &cap, &provider), ==,
      WYRELOG_E_OK);

  Lifecycle life = { .sealed = TRUE, .main_binding_live = FALSE };
  Observation obs = { 0 };
  g_assert_cmpint (wyl_fact_artifact_transition_windows_observe (provider,
      &life, &obs), ==, WYRELOG_E_OK);

  Identity main_id = obs.entries[SLOT_MAIN].identity;
  Identity stage_id = obs.entries[SLOT_STAGE].identity;
  Request req = request_for (&obs, main_id, stage_id, FALSE);

  Result res = { 0 };
  g_autoptr (WylFactArtifactMainTransition) tx = NULL;
  g_assert_cmpint (admit (&obs, &req, &res, &tx), ==, WYRELOG_E_OK);

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
        (&f.directory, f.lease, OPERATION_UUID, &cap, &provider), ==,
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
        (&f.directory, f.lease, OPERATION_UUID, &cap, &provider), ==,
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
        (&f.directory, f.lease, OPERATION_UUID, &cap, &provider), ==,
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
        (&f.directory, f.lease, OPERATION_UUID, &cap, &provider), ==,
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

int
main (int argc, char **argv)
{
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
  return g_test_run ();
}

#else
int
main (void)
{
  return 0;
}
#endif

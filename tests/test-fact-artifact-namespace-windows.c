/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>

#include <string.h>

#ifdef G_OS_WIN32
#include <aclapi.h>
#include <windows.h>

#include "fact/graph-artifact-windows-handle-private.h"
#include "fact/graph-artifact-windows-locator-private.h"
#include "fact/graph-artifact-windows-lock-private.h"
#include "fact/graph-artifact-windows-namespace-private.h"
#include "fact/graph-windows-security-private.h"

#include "fact-test-support.h"

static WylFactGraphWinIdentity
identity_for (HANDLE handle)
{
  FILE_ID_INFO info = { 0 };
  WylFactGraphWinIdentity identity = { 0 };

  g_assert_true (GetFileInformationByHandleEx (handle, FileIdInfo, &info,
      sizeof info));
  identity.volume_serial = info.VolumeSerialNumber;
  memcpy (identity.file_id, info.FileId.Identifier, sizeof identity.file_id);
  return identity;
}

static gboolean
identity_matches (const WylFactGraphWinIdentity *a,
    const WylFactGraphWinIdentity *b)
{
  return a->volume_serial == b->volume_serial
         && memcmp (a->file_id, b->file_id, sizeof a->file_id) == 0;
}

static void
await_deleted_artifact_name (const gchar *stage, const gchar *path,
    const wchar_t *wide)
{
  const gint64 timeout_us = 5 * G_USEC_PER_SEC;
  const gint64 deadline = g_get_monotonic_time () + timeout_us;
  DWORD last_attrs = INVALID_FILE_ATTRIBUTES;
  DWORD last_error = ERROR_SUCCESS;

  while (TRUE) {
    gint64 remaining;

    last_attrs = GetFileAttributesW (wide);
    last_error = last_attrs == INVALID_FILE_ATTRIBUTES
        ? GetLastError () : ERROR_SUCCESS;
    if (last_attrs == INVALID_FILE_ATTRIBUTES
        && last_error == ERROR_FILE_NOT_FOUND)
      return;

    if (last_attrs == INVALID_FILE_ATTRIBUTES
        && last_error != ERROR_ACCESS_DENIED
        && last_error != ERROR_SHARING_VIOLATION
        && last_error != ERROR_DELETE_PENDING)
      g_error ("artifact name retirement failed: stage=%s path=%s "
          "timeout-ms=5000 last-attrs=0x%08lx "
          "last-observation-error=%lu",
          stage, path, (unsigned long) last_attrs, (unsigned long) last_error);

    remaining = deadline - g_get_monotonic_time ();
    if (remaining <= 1)
      break;
    g_usleep ((gulong) MIN (remaining - 1, 10 * G_TIME_SPAN_MILLISECOND));
  }

  g_error ("artifact name retirement timed out: stage=%s path=%s "
      "timeout-ms=5000 last-attrs=0x%08lx last-observation-error=%lu",
      stage, path, (unsigned long) last_attrs, (unsigned long) last_error);
}

/* Resolves a name to whatever object it currently addresses.  Observations
 * about the namespace must come from a fresh open, never from a HANDLE the
 * test already holds: a replaced name and a superseded object are exactly
 * what these scenarios have to tell apart. */
static WylFactGraphWinIdentity
identity_for_path (const gchar *path)
{
  g_autofree wchar_t *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  /* Backup semantics only so that a directory can be named here too; the
   * identity of one is read exactly like the identity of a file. */
  HANDLE handle = CreateFileW (wide, FILE_READ_ATTRIBUTES, FILE_SHARE_READ
          | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
          FILE_FLAG_BACKUP_SEMANTICS, NULL);
  WylFactGraphWinIdentity identity;

  g_assert_true (handle != INVALID_HANDLE_VALUE);
  identity = identity_for (handle);
  g_assert_true (CloseHandle (handle));
  return identity;
}

static void
read_named_file_prefix (const gchar *path, gchar *out, gsize length)
{
  g_autofree wchar_t *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  HANDLE handle = CreateFileW (wide, GENERIC_READ, FILE_SHARE_READ
          | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
          FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD read = 0;

  g_assert_true (handle != INVALID_HANDLE_VALUE);
  g_assert_true (ReadFile (handle, out, (DWORD) length, &read, NULL));
  g_assert_cmpuint (read, ==, (DWORD) length);
  g_assert_true (CloseHandle (handle));
}

typedef struct
{
  WylFactArtifactWinNamespace *namespace_;
} NamespaceReleaseProbe;

static WylFactArtifactWinNamespace *open_namespace_at_path (const gchar * path,
    gboolean create_main, HANDLE * out_graph);
static void remove_tree_for_test (const gchar * root);

static gpointer
release_namespace_thread (gpointer user_data)
{
  NamespaceReleaseProbe *probe = user_data;
  wyl_fact_artifact_win_namespace_free (probe->namespace_);
  return NULL;
}

static HANDLE
open_scratch_file (gchar **out_path)
{
  g_autoptr (GError) error = NULL;
  gchar *directory = g_dir_make_tmp ("wyl-win-artifact-XXXXXX", &error);
  gchar *path;
  wchar_t *wide;
  HANDLE handle;

  g_assert_no_error (error);
  g_assert_nonnull (directory);
  path = g_build_filename (directory, "facts.duckdb.wal", NULL);
  wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_nonnull (wide);
  handle = CreateFileW (wide, GENERIC_READ | GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
          CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  g_free (wide);
  g_assert_cmpint (handle != INVALID_HANDLE_VALUE, !=, FALSE);
  g_free (directory);
  *out_path = path;
  return handle;
}

static HANDLE
open_existing_scratch_file (const gchar *path)
{
  g_autofree wchar_t *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  HANDLE handle = CreateFileW (wide, GENERIC_READ | GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

  g_assert_cmpint (handle != INVALID_HANDLE_VALUE, !=, FALSE);
  return handle;
}

static void
remove_scratch_file (gchar *path)
{
  g_autofree gchar *directory = g_path_get_dirname (path);
  g_autofree wchar_t *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_autofree wchar_t *wide_directory = g_utf8_to_utf16 (directory, -1, NULL,
          NULL, NULL);

  g_assert_true (DeleteFileW (wide));
  g_assert_true (RemoveDirectoryW (wide_directory));
  g_free (path);
}

/* Opens the volume that g_dir_make_tmp draws scratch directories from, so an
 * object on it stays addressable by file id once its last name is gone. */
static HANDLE
open_scratch_volume (void)
{
  g_autofree wchar_t *wide = g_utf8_to_utf16 (g_get_tmp_dir (), -1, NULL,
          NULL, NULL);
  HANDLE handle = CreateFileW (wide, FILE_READ_ATTRIBUTES, FILE_SHARE_READ
          | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
          FILE_FLAG_BACKUP_SEMANTICS, NULL);

  g_assert_cmpint (handle != INVALID_HANDLE_VALUE, !=, FALSE);
  return handle;
}

/* Whether the object |identity| names is still alive.  An object whose last
 * link is gone outlives that link for exactly as long as some handle to it
 * does, so opening it by id asks whether a handle to the one object under
 * test is still open.  Nothing else the process holds can change the answer,
 * which is what a handle count cannot say. */
static gboolean
unlinked_object_is_open (HANDLE volume, const WylFactGraphWinIdentity *identity)
{
  FILE_ID_DESCRIPTOR descriptor = { 0 };
  WylFactGraphWinIdentity observed;
  HANDLE handle;

  descriptor.dwSize = sizeof descriptor;
  descriptor.Type = ExtendedFileIdType;
  memcpy (&descriptor.ExtendedFileId, identity->file_id,
      sizeof identity->file_id);
  SetLastError (ERROR_SUCCESS);
  handle = OpenFileById (volume, &descriptor, FILE_READ_ATTRIBUTES,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
          FILE_FLAG_BACKUP_SEMANTICS);
  if (handle == INVALID_HANDLE_VALUE) {
    DWORD error = GetLastError ();

    /* These three answer that the object is gone.  ERROR_INVALID_PARAMETER
     * is deliberately among them even though a volume with no file-id
     * namespace reports the same code: the callers establish which world
     * they are in by running this identical lookup while a handle is
     * knowingly held, so a volume that cannot answer is caught there and
     * skips rather than reaching an observation. */
    if (error == ERROR_INVALID_PARAMETER || error == ERROR_FILE_NOT_FOUND
        || error == ERROR_NOT_FOUND)
      return FALSE;

    /* A refusal that means the object is still there.  TRUE is the failing
     * answer at every observation site, so reporting it here costs a false
     * abort at worst, where FALSE would read a live guardian as a clean
     * close.  The transport case retries, so a transient one settles. */
    if (error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION
        || error == ERROR_DELETE_PENDING)
      return TRUE;

    g_error ("lookup of an unlinked object by file id was inconclusive: "
        "error=%lu", (unsigned long) error);
  }
  /* This compares the id the object was just found by against itself, so the
   * only disagreement it can report is an answer from another volume.  It
   * cannot see an id this volume has recycled onto a different object, and
   * no comparison at this level could: what rules recycling out is the
   * sequence number NTFS packs into the file reference inside the
   * FILE_ID_128, which makes a reused index come back as a different id.
   * The premise the cases below rest on is narrower, and each one enforces
   * it rather than assuming it -- this same lookup must succeed while a
   * handle is knowingly held, immediately before the observation. */
  observed = identity_for (handle);
  g_assert_true (CloseHandle (handle));
  return identity_matches (identity, &observed);
}

/* Whether the object behind a just-deleted name is still open.  Windows ends
 * a name by one of two routes and each answers the question on its own terms:
 * a delete that only marks the name refuses every open of it until the last
 * handle goes, and a delete that takes the name away at once leaves the
 * object reachable by id for exactly as long as one is held.  Either way the
 * answer is about the one object under test and not about the process. */
static gboolean
deleted_object_is_open (HANDLE volume, const wchar_t *wide,
    const WylFactGraphWinIdentity *identity)
{
  DWORD error;

  SetLastError (ERROR_SUCCESS);
  if (GetFileAttributesW (wide) != INVALID_FILE_ATTRIBUTES)
    return TRUE;
  error = GetLastError ();
  /* A name that refuses to answer is a name whose object is still held: the
   * marked-name route keeps every open out until the last handle goes.
   * await_deleted_artifact_name reads these same three states as "not
   * finished yet", so none of them may read as "closed" here. */
  if (error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION
      || error == ERROR_DELETE_PENDING)
    return TRUE;
  return unlinked_object_is_open (volume, identity);
}

/* The same question, waited on to the bounded deadline
 * await_deleted_artifact_name uses.  The close a destructor performs is not
 * always visible in the instant it returns -- the name can still be marked,
 * or the object still winding down -- and a single sample taken in that
 * window reads a finished destructor as a leak.  Waiting costs no leak
 * coverage: a guardian that is really leaked holds the object open for the
 * whole window, so this runs out and returns TRUE, which is the caller's
 * failure. */
static gboolean
deleted_object_is_open_after_wait (HANDLE volume, const wchar_t *wide,
    const WylFactGraphWinIdentity *identity)
{
  const gint64 deadline = g_get_monotonic_time () + 5 * G_USEC_PER_SEC;

  while (TRUE) {
    gint64 remaining;

    if (!deleted_object_is_open (volume, wide, identity))
      return FALSE;
    remaining = deadline - g_get_monotonic_time ();
    if (remaining <= 1)
      return TRUE;
    g_usleep ((gulong) MIN (remaining - 1, 10 * G_TIME_SPAN_MILLISECOND));
  }
}

/* The session, rather than a numeric HANDLE, is the externally visible I/O
 * capability.  Releasing the binding-side state first must not invalidate the
 * live private duplicate, and a second session must not bypass the lifecycle
 * barrier. */
static void
test_private_io_session_lifetime_and_singleton (void)
{
  gchar *path = NULL;
  HANDLE source = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (source);
  WylFactArtifactWinWorkingHandle *working = NULL;
  WylFactArtifactWinIoState *state = NULL;
  WylFactArtifactWinIoSession *first = NULL;
  WylFactArtifactWinIoSession *second = NULL;
  gchar readback[4] = { 0 };
  gsize n = 0;

  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (source,
      &identity, &working), ==, WYRELOG_E_OK);
  source = INVALID_HANDLE_VALUE;
  g_assert_cmpint (wyl_fact_artifact_win_io_state_new (working, &state), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_open (state, TRUE, &first), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_open (state, TRUE, &second), ==,
      WYRELOG_E_BUSY);
  g_assert_null (second);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_write (first, 0, "abc",
      3, &n), ==, WYRELOG_E_OK);
  g_assert_cmpuint (n, ==, 3);
  /* Drops the binding's reference. The active session owns the remaining
   * private state until finish. */
  wyl_fact_artifact_win_io_state_free (state);
  state = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_io_session_read (first, 0, readback,
      3, &n), ==, WYRELOG_E_OK);
  g_assert_cmpstr (readback, ==, "abc");
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (first), ==,
      WYRELOG_E_OK);
  remove_scratch_file (path);
}

/* A reader guard must be able to read main, and must not be able to write it.
 * The bounded DuckDB filesystem opens read-only whenever the caller asked to
 * validate rather than initialize, and that path acquires a shared reader
 * guard, so a main opener that demanded an exclusive lease made read-only
 * validation impossible on Windows.
 *
 * Relaxing the exclusive check in place would have been wrong: the binding
 * used to hand out sessions with writable hardcoded TRUE against a
 * GENERIC_READ|GENERIC_WRITE guardian, so a shared reader would have received
 * a genuinely writable handle to facts.duckdb.  The authority is split
 * instead, and this pins both halves. */
static void
test_reader_guard_opens_main_read_only (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *path = wyl_test_make_secure_fact_root
        ("wyl-win-reader-main-XXXXXX", &error);
  WylFactArtifactWinNamespace *namespace_ = NULL;
  WylFactArtifactWinLease *reader = NULL;
  WylFactArtifactWinLease *writer = NULL;
  WylFactArtifactWinMainBinding *binding = NULL;
  WylFactArtifactWinIoSession *session = NULL;
  HANDLE graph = INVALID_HANDLE_VALUE;
  gchar buffer[8] = { 0 };
  gsize n = 1;

  g_assert_no_error (error);
  namespace_ = open_namespace_at_path (path, TRUE, &graph);

  /* Seed a byte through the writable authority so the read below has
   * something to prove it can see. */
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation
        (namespace_, &writer), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_main (writer, &binding),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_main_binding_open_io_session (binding,
      &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_write (session, 0, "x", 1,
      &n), ==, WYRELOG_E_OK);
  g_assert_cmpuint (n, ==, 1);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_win_main_binding_free (binding);
  binding = NULL;
  session = NULL;
  wyl_fact_artifact_win_lease_free (writer);
  writer = NULL;

  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_reader (namespace_,
      &reader), ==, WYRELOG_E_OK);

  /* The writable opener still refuses a shared lease: the split did not widen
   * it.  Delete the (writable && !lease->exclusive) term from
   * lease_open_main_binding and this line goes green. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_main (reader, &binding),
      ==, WYRELOG_E_POLICY);
  g_assert_null (binding);

  g_assert_cmpint (wyl_fact_artifact_win_lease_open_main_reader (reader,
      &binding), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_main_binding_open_io_session (binding,
      &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_read (session, 0, buffer,
      sizeof buffer, &n), ==, WYRELOG_E_OK);
  g_assert_cmpuint (n, ==, 1);
  g_assert_cmpint (buffer[0], ==, 'x');

  /* The grant is physical, not advisory: the duplicate carries GENERIC_READ
   * alone.  Restore the hardcoded TRUE in
   * wyl_fact_artifact_win_main_binding_open_io_session and these two fail. */
  g_assert_cmpint (wyl_fact_artifact_win_io_session_write (session, 0, "y", 1,
      &n), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_truncate (session, 0), ==,
      WYRELOG_E_POLICY);

  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_win_main_binding_free (binding);
  wyl_fact_artifact_win_lease_free (reader);
  wyl_fact_artifact_win_namespace_free (namespace_);
  g_assert_true (CloseHandle (graph));
  remove_tree_for_test (path);
}

/* The neutral spelling of the sidecar authorities, which is what the bounded
 * DuckDB filesystem actually calls.  Two of the three shapes here are what a
 * fresh DuckDB database does before it writes anything: it asks to remove
 * sidecars it never opened, so the absent case must answer NOT_FOUND -- the
 * caller reads that as "nothing to remove" and reads anything else as a fault.
 * The stub answered POLICY and poisoned the filesystem. */
static void
test_neutral_sidecar_authorities_forward (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *path = wyl_test_make_secure_fact_root
        ("wyl-win-neutral-sidecar-XXXXXX", &error);
  g_autofree gchar *wal_path = NULL;
  WylFactArtifactWinNamespace *namespace_ = NULL;
  WylFactArtifactWinLease *lease = NULL;
  WylFactArtifactSidecarBinding *binding = NULL;
  WylFactArtifactWinIoSession *session = NULL;
  WylFactArtifactSidecarRetireResult retired =
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED;
  HANDLE graph = INVALID_HANDLE_VALUE;
  gint fd = -1;
  gsize n = 0;

  g_assert_no_error (error);
  wal_path = g_build_filename (path, "facts.duckdb.wal", NULL);
  namespace_ = open_namespace_at_path (path, TRUE, &graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation
        (namespace_, &lease), ==, WYRELOG_E_OK);

  /* Absent: the shape a fresh database hits first. */
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding
        (lease, WYL_FACT_ARTIFACT_WAL, TRUE, &binding, &fd), ==,
      WYRELOG_E_NOT_FOUND);
  g_assert_null (binding);
  g_assert_cmpint (fd, ==, -1);

  /* Create one, then reacquire it by name through the neutral opener. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &binding), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
        (binding, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_write (session, 0, "w", 1,
      &n), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;
  wyl_fact_artifact_win_sidecar_binding_free (binding);
  binding = NULL;

  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding
        (lease, WYL_FACT_ARTIFACT_WAL, TRUE, &binding, &fd), ==, WYRELOG_E_OK);
  g_assert_nonnull (binding);
  /* Windows issues sessions, not descriptors: the neutral out-parameter stays
   * absent, and presenting one to the close is a refusal rather than a
   * close. */
  g_assert_cmpint (fd, ==, -1);
  fd = 3;
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (binding, &fd), ==,
      WYRELOG_E_POLICY);
  fd = -1;
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (binding, &fd), ==,
      WYRELOG_E_OK);

  /* The retirement DuckDB performs after its shutdown checkpoint. */
  g_assert_true (g_file_test (wal_path, G_FILE_TEST_EXISTS));
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (binding,
      &retired), ==, WYRELOG_E_OK);
  g_assert_cmpint (retired, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RETIRED);
  g_assert_false (g_file_test (wal_path, G_FILE_TEST_EXISTS));

  wyl_fact_artifact_win_sidecar_binding_free (binding);
  wyl_fact_artifact_win_lease_free (lease);
  wyl_fact_artifact_win_namespace_free (namespace_);
  g_assert_true (CloseHandle (graph));
  remove_tree_for_test (path);
}

/* The sidecar half of the same split.  A read-only DuckDB replays an existing
 * WAL, so a reader guard must be able to open one; it must not be able to
 * create, write, or retire anything.  The exclusivity requirement moved out of
 * sidecar_revalidate_locked, which readers now also run, and into each
 * mutator, so this pins the mutators too. */
static void
test_reader_guard_sidecar_is_read_only (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *path = wyl_test_make_secure_fact_root
        ("wyl-win-reader-wal-XXXXXX", &error);
  g_autofree gchar *wal_path = NULL;
  WylFactArtifactWinNamespace *namespace_ = NULL;
  WylFactArtifactWinLease *lease = NULL;
  WylFactArtifactWinSidecarBinding *sidecar = NULL;
  WylFactArtifactWinIoSession *session = NULL;
  WylFactArtifactSidecarRetireResult retired =
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED;
  HANDLE graph = INVALID_HANDLE_VALUE;
  gchar buffer[4] = { 0 };
  gsize n = 0;

  g_assert_no_error (error);
  wal_path = g_build_filename (path, "facts.duckdb.wal", NULL);
  namespace_ = open_namespace_at_path (path, TRUE, &graph);

  /* Create and seed the WAL through the exclusive authority. */
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation
        (namespace_, &lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
        (sidecar, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_write (session, 0, "wal",
      3, &n), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  sidecar = NULL;
  wyl_fact_artifact_win_lease_free (lease);
  lease = NULL;

  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_reader (namespace_,
      &lease), ==, WYRELOG_E_OK);

  /* Creating or writably opening still needs exclusivity. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &sidecar), ==, WYRELOG_E_POLICY);
  g_assert_null (sidecar);
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease,
      WYL_FACT_ARTIFACT_WAL, FALSE, TRUE, &sidecar), ==, WYRELOG_E_POLICY);
  g_assert_null (sidecar);

  /* Read-only on an existing name is admitted, and revalidation runs for it:
   * restore the !binding->lease->exclusive term in sidecar_revalidate_locked
   * and opening this session returns POLICY. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease,
      WYL_FACT_ARTIFACT_WAL, FALSE, FALSE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
        (sidecar, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_read (session, 0, buffer,
      3, &n), ==, WYRELOG_E_OK);
  g_assert_cmpuint (n, ==, 3);
  g_assert_cmpint (memcmp (buffer, "wal", 3), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_write (session, 0, "z", 1,
      &n), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  sidecar = NULL;

  /* Retirement is a mutation and a reader guard must not achieve one.  This
   * pins the outcome, not a particular mechanism: deleting the
   * !binding->lease->exclusive term from
   * wyl_fact_artifact_win_sidecar_binding_retire does NOT make this fail,
   * because a read-only working handle has no DELETE access and
   * wyl_fact_artifact_win_entry_delete_exact refuses one layer down (measured:
   * rc=POLICY, effect=NOT_APPLIED).  The outcome is what the namespace owes;
   * the explicit term only states the requirement where it is decided. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease,
      WYL_FACT_ARTIFACT_WAL, FALSE, FALSE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_retire (sidecar,
      &retired), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (retired, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED);
  g_assert_true (g_file_test (wal_path, G_FILE_TEST_EXISTS));

  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  wyl_fact_artifact_win_lease_free (lease);
  wyl_fact_artifact_win_namespace_free (namespace_);
  g_assert_true (CloseHandle (graph));
  remove_tree_for_test (path);
}

/* A read that starts at or past end-of-file is a short read, not an I/O
 * failure.  POSIX pread answers 0 bytes with success and every caller is
 * written to that contract -- DuckDB's magic-byte probe reads 16 bytes from a
 * freshly published empty store before it will create anything in it, and
 * relies on a zeroed buffer plus a zero count.  A positional ReadFile fails
 * with ERROR_HANDLE_EOF instead, which win_error does not name, so it used to
 * fall through to WYRELOG_E_IO and abort the open.  reconcile-move-private.c
 * already treats that code as end-of-data for the same reason. */
static void
test_io_session_read_at_eof_is_a_short_read (void)
{
  gchar *path = NULL;
  HANDLE source = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (source);
  WylFactArtifactWinWorkingHandle *working = NULL;
  WylFactArtifactWinIoState *state = NULL;
  WylFactArtifactWinIoSession *session = NULL;
  gchar buffer[16] = { 0 };
  gsize n = 1;

  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (source,
      &identity, &working), ==, WYRELOG_E_OK);
  source = INVALID_HANDLE_VALUE;
  g_assert_cmpint (wyl_fact_artifact_win_io_state_new (working, &state), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_open (state, TRUE,
      &session), ==, WYRELOG_E_OK);

  /* The scratch file is empty, so offset 0 is already end-of-file. */
  g_assert_cmpint (wyl_fact_artifact_win_io_session_read (session, 0, buffer,
      sizeof buffer, &n), ==, WYRELOG_E_OK);
  g_assert_cmpuint (n, ==, 0);

  /* Past the end answers the same way, and a partial read still reports only
   * the bytes that existed. */
  g_assert_cmpint (wyl_fact_artifact_win_io_session_write (session, 0, "ab", 2,
      &n), ==, WYRELOG_E_OK);
  g_assert_cmpuint (n, ==, 2);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_read (session, 2, buffer,
      sizeof buffer, &n), ==, WYRELOG_E_OK);
  g_assert_cmpuint (n, ==, 0);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_read (session, 1, buffer,
      sizeof buffer, &n), ==, WYRELOG_E_OK);
  g_assert_cmpuint (n, ==, 1);

  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_win_io_state_free (state);
  remove_scratch_file (path);
}

static void
test_io_session_guardian_failure_is_policy (void)
{
  gchar *path = NULL;
  HANDLE source = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (source);
  WylFactArtifactWinWorkingHandle *working = NULL;
  WylFactArtifactWinIoState *state = NULL;
  WylFactArtifactWinIoSession *session = NULL;
  g_autofree gchar *directory = NULL;
  g_autofree gchar *alternate_path = NULL;
  g_autofree wchar_t *source_wide = NULL;
  g_autofree wchar_t *alternate_wide = NULL;
  guint64 size = 0;
  gchar byte = 0;
  gsize read = 0;

  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (source,
      &identity, &working), ==, WYRELOG_E_OK);
  source = INVALID_HANDLE_VALUE;
  g_assert_cmpint (wyl_fact_artifact_win_io_state_new (working, &state), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_open (state, TRUE, &session),
      ==, WYRELOG_E_OK);
  /* A hard-link changes the guardian's required single-link association.
   * Every typed I/O operation must preserve POLICY, not relabel this security
   * failure as INVALID (which is reserved for malformed arguments). */
  directory = g_path_get_dirname (path);
  alternate_path = g_build_filename (directory, "alternate", NULL);
  source_wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  alternate_wide = g_utf8_to_utf16 (alternate_path, -1, NULL, NULL, NULL);
  g_assert_true (CreateHardLinkW (alternate_wide, source_wide, NULL));
  g_assert_cmpint (wyl_fact_artifact_win_io_session_size (session, &size), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_read (session, 0, &byte,
      1, &read), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_read (session, 0, NULL,
      1, &read), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  g_assert_true (DeleteFileW (alternate_wide));
  wyl_fact_artifact_win_io_state_free (state);
  remove_scratch_file (path);
}

static void
test_session_blocks_mutation_until_finish (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *path = g_dir_make_tmp ("wyl-win-session-XXXXXX", &error);
  WylFactArtifactWinNamespace *namespace_;
  WylFactArtifactWinLease *lease = NULL;
  WylFactArtifactWinSidecarBinding *sidecar = NULL;
  WylFactArtifactWinIoSession *session = NULL;
  WylFactArtifactWinMutationEffect effect;
  HANDLE graph = INVALID_HANDLE_VALUE;

  g_assert_no_error (error);
  namespace_ = open_namespace_at_path (path, TRUE, &graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (namespace_,
      &lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
        (sidecar, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_publish_no_replace
        (sidecar, WYL_FACT_ARTIFACT_CHECKPOINT, &effect), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_publish_no_replace
        (sidecar, WYL_FACT_ARTIFACT_CHECKPOINT, &effect), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED);
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  wyl_fact_artifact_win_lease_free (lease);
  wyl_fact_artifact_win_namespace_free (namespace_);
  /* open_namespace_at_path owns only the graph HANDLE; its entries have been
   * retired from the test namespace by the OS directory teardown below. */
  CloseHandle (graph);
  {
    g_autofree gchar *main_path = g_build_filename (path, "facts.duckdb", NULL);
    g_autofree gchar *lock_path =
        g_build_filename (path, "facts.duckdb.lock", NULL);
    g_autofree gchar *checkpoint_path = g_build_filename (path,
            "facts.duckdb.wal.checkpoint", NULL);
    g_autofree wchar_t *main_wide =
        g_utf8_to_utf16 (main_path, -1, NULL, NULL, NULL);
    g_autofree wchar_t *lock_wide =
        g_utf8_to_utf16 (lock_path, -1, NULL, NULL, NULL);
    g_autofree wchar_t *checkpoint_wide =
        g_utf8_to_utf16 (checkpoint_path, -1, NULL, NULL, NULL);
    g_autofree wchar_t *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
    g_assert_true (DeleteFileW (main_wide));
    g_assert_true (DeleteFileW (lock_wide));
    g_assert_true (DeleteFileW (checkpoint_wide));
    g_assert_true (RemoveDirectoryW (wide));
  }
}

static void
test_session_retains_mutation_lease_until_finish (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *path = g_dir_make_tmp ("wyl-win-session-lease-XXXXXX",
          &error);
  WylFactArtifactWinNamespace *first;
  WylFactArtifactWinNamespace *second;
  WylFactArtifactWinLease *held_lease = NULL;
  WylFactArtifactWinLease *fresh_lease = NULL;
  WylFactArtifactWinSidecarBinding *sidecar = NULL;
  WylFactArtifactWinIoSession *session = NULL;
  HANDLE first_graph = INVALID_HANDLE_VALUE;
  HANDLE second_graph = INVALID_HANDLE_VALUE;

  g_assert_no_error (error);
  first = open_namespace_at_path (path, TRUE, &first_graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (first,
      &held_lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (held_lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
        (sidecar, &session), ==, WYRELOG_E_OK);
  /* Releasing every public owner must not release the private session lease. */
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  sidecar = NULL;
  wyl_fact_artifact_win_lease_free (held_lease);
  held_lease = NULL;
  wyl_fact_artifact_win_namespace_free (first);
  first = NULL;

  second = open_namespace_at_path (path, FALSE, &second_graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (second,
      &fresh_lease), ==, WYRELOG_E_BUSY);
  g_assert_null (fresh_lease);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (second,
      &fresh_lease), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_lease_free (fresh_lease);
  wyl_fact_artifact_win_namespace_free (second);
  CloseHandle (first_graph);
  CloseHandle (second_graph);
  {
    g_autofree gchar *main_path = g_build_filename (path, "facts.duckdb", NULL);
    g_autofree gchar *lock_path =
        g_build_filename (path, "facts.duckdb.lock", NULL);
    g_autofree gchar *wal_path =
        g_build_filename (path, "facts.duckdb.wal", NULL);
    g_autofree wchar_t *main_wide =
        g_utf8_to_utf16 (main_path, -1, NULL, NULL, NULL);
    g_autofree wchar_t *lock_wide =
        g_utf8_to_utf16 (lock_path, -1, NULL, NULL, NULL);
    g_autofree wchar_t *wal_wide =
        g_utf8_to_utf16 (wal_path, -1, NULL, NULL, NULL);
    g_autofree wchar_t *directory_wide =
        g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
    g_assert_true (DeleteFileW (main_wide));
    g_assert_true (DeleteFileW (lock_wide));
    g_assert_true (DeleteFileW (wal_wide));
    g_assert_true (RemoveDirectoryW (directory_wide));
  }
}

/* These are namespace (not merely locator) adversaries.  The replacement is
 * performed through the native Win32 namespace after a binding was minted:
 * the retained graph HANDLE must not turn a hard link or reparse spelling
 * into authority over a different entry. */
static void
test_native_namespace_reparse_and_hardlink_substitution (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *path = g_dir_make_tmp ("wyl-win-substitute-XXXXXX", &error);
  g_autofree gchar *main_path = NULL;
  g_autofree gchar *wal_path = NULL;
  g_autofree wchar_t *main_wide = NULL;
  g_autofree wchar_t *wal_wide = NULL;
  g_autofree wchar_t *directory_wide = NULL;
  WylFactArtifactWinNamespace *namespace_ = NULL;
  WylFactArtifactWinLease *lease = NULL;
  WylFactArtifactWinSidecarBinding *sidecar = NULL;
  HANDLE graph = INVALID_HANDLE_VALUE;
  WylFactArtifactWinIoSession *session = NULL;

  g_assert_no_error (error);
  namespace_ = open_namespace_at_path (path, TRUE, &graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (namespace_,
      &lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
        (sidecar, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;

  main_path = g_build_filename (path, "facts.duckdb", NULL);
  wal_path = g_build_filename (path, "facts.duckdb.wal", NULL);
  main_wide = g_utf8_to_utf16 (main_path, -1, NULL, NULL, NULL);
  wal_wide = g_utf8_to_utf16 (wal_path, -1, NULL, NULL, NULL);
  g_assert_true (DeleteFileW (wal_wide));
  await_deleted_artifact_name ("hard-link", wal_path, wal_wide);
  if (!CreateHardLinkW (wal_wide, main_wide, NULL)) {
    DWORD create_error = GetLastError ();
    DWORD probe_attrs = GetFileAttributesW (wal_wide);
    DWORD probe_error = probe_attrs == INVALID_FILE_ATTRIBUTES
        ? GetLastError () : ERROR_SUCCESS;

    g_error ("artifact substitution failed: operation=CreateHardLinkW "
        "stage=hard-link path=%s create-error=%lu "
        "probe-attrs=0x%08lx probe-error=%lu",
        wal_path, (unsigned long) create_error, (unsigned long) probe_attrs,
        (unsigned long) probe_error);
  }
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
        (sidecar, &session), ==, WYRELOG_E_POLICY);
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  sidecar = NULL;
  wyl_fact_artifact_win_lease_free (lease);
  lease = NULL;
  wyl_fact_artifact_win_namespace_free (namespace_);
  namespace_ = NULL;
  g_assert_true (CloseHandle (graph));
  graph = INVALID_HANDLE_VALUE;
  g_assert_true (DeleteFileW (wal_wide));

  namespace_ = open_namespace_at_path (path, FALSE, &graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (namespace_,
      &lease), ==, WYRELOG_E_OK);
  /* Minting the reparse spelling takes either Developer Mode, which the
   * unprivileged flag asks for, or SeCreateSymbolicLinkPrivilege, which the
   * unflagged call uses.  Ask for each in turn before concluding that this
   * machine offers neither: a refusal of the flagged form alone says only
   * that Developer Mode is off, not that the privilege is absent.
   *
   * An account holding neither -- the service account the Windows runner
   * executes as -- cannot mint the adversary at all, so the case reports a
   * skip rather than failing on an environment it cannot create.  What that
   * gives up is narrow: the hard-link phase above still drives the same
   * identity predicate, and only FILE_OPEN_REPARSE_POINT in the sidecar open,
   * which is what makes the attribute observable instead of followed, goes
   * unproven where the skip fires.  Issue #808 tracks restoring it. */
  await_deleted_artifact_name ("reparse", wal_path, wal_wide);
  if (!CreateSymbolicLinkW (wal_wide, main_wide,
      SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)
      && !CreateSymbolicLinkW (wal_wide, main_wide, 0)) {
    DWORD create_error = GetLastError ();
    DWORD probe_attrs = GetFileAttributesW (wal_wide);
    DWORD probe_error = probe_attrs == INVALID_FILE_ATTRIBUTES
        ? GetLastError () : ERROR_SUCCESS;

    if (create_error == ERROR_PRIVILEGE_NOT_HELD) {
      g_autofree gchar *message = g_strdup_printf
            ("reparse substitution unproven: operation=CreateSymbolicLinkW "
              "stage=reparse create-error=%lu probe-attrs=0x%08lx "
              "probe-error=%lu", (unsigned long) create_error,
              (unsigned long) probe_attrs, (unsigned long) probe_error);

      g_test_skip (message);
    } else {
      g_error ("artifact substitution failed: operation=CreateSymbolicLinkW "
          "stage=reparse path=%s create-error=%lu "
          "probe-attrs=0x%08lx probe-error=%lu",
          wal_path, (unsigned long) create_error, (unsigned long) probe_attrs,
          (unsigned long) probe_error);
    }
  } else {
    g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease, WYL_FACT_ARTIFACT_WAL, FALSE, TRUE, &sidecar), ==, WYRELOG_E_POLICY);
    g_assert_null (sidecar);
    /* Retiring the reparse name belongs to the branch that minted it, not to
     * the cleanup below.  g_test_skip does not return, so every step after
     * this block runs on the skip path too, where this name never existed.
     * The rejected open closed its handle, so the name is deletable here. */
    g_assert_true (DeleteFileW (wal_wide));
  }
  wyl_fact_artifact_win_lease_free (lease);
  wyl_fact_artifact_win_namespace_free (namespace_);
  g_assert_true (CloseHandle (graph));
  g_assert_true (DeleteFileW (main_wide));
  {
    g_autofree gchar *lock_path =
        g_build_filename (path, "facts.duckdb.lock", NULL);
    g_autofree wchar_t *lock_wide =
        g_utf8_to_utf16 (lock_path, -1, NULL, NULL, NULL);
    g_assert_true (DeleteFileW (lock_wide));
  }
  directory_wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_true (RemoveDirectoryW (directory_wide));
}

static HANDLE
open_scratch_directory (gchar **out_path)
{
  g_autoptr (GError) error = NULL;
  gchar *path = g_dir_make_tmp ("wyl-win-locator-XXXXXX", &error);
  g_autofree wchar_t *wide = NULL;
  HANDLE handle;

  g_assert_no_error (error);
  g_assert_nonnull (path);
  wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_nonnull (wide);
  handle = CreateFileW (wide, FILE_LIST_DIRECTORY | FILE_ADD_FILE
          | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE
          | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
          FILE_FLAG_BACKUP_SEMANTICS, NULL);
  g_assert_true (handle != INVALID_HANDLE_VALUE);
  *out_path = path;
  return handle;
}

static WylFactArtifactWinLocator *
open_locator_for_test (HANDLE graph, WylFactGraphWinIdentity *out_identity)
{
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactArtifactWinLocator *locator = NULL;

  *out_identity = identity_for (graph);
  directory.graph_handle = graph;
  directory.graph_identity = *out_identity;
  g_assert_cmpint (wyl_fact_artifact_win_locator_new (&directory, &locator),
      ==, WYRELOG_E_OK);
  g_assert_nonnull (locator);
  return locator;
}

/* This opens the same graph from a fresh process.  It deliberately uses no
 * inherited HANDLE: the child must prove that the on-disk protected entries
 * and LockFileEx domain, rather than this test process' static domain table,
 * enforce the lease. */
static WylFactArtifactWinNamespace *
open_namespace_at_path (const gchar *path, gboolean create_main,
    HANDLE *out_graph)
{
  g_autofree wchar_t *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactArtifactWinLocator *locator = NULL;
  WylFactArtifactWinEntry *entry = NULL;
  WylFactGraphRegularFile main_file = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  WylFactArtifactWinNamespace *namespace_ = NULL;
  HANDLE graph;
  HANDLE main = INVALID_HANDLE_VALUE;
  wyrelog_error_t rc;

  g_assert_nonnull (wide);
  graph = CreateFileW (wide, FILE_LIST_DIRECTORY | FILE_ADD_FILE
          | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
          OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
  g_assert_true (graph != INVALID_HANDLE_VALUE);
  directory.graph_handle = graph;
  directory.graph_identity = identity_for (graph);
  locator = open_locator_for_test (graph, &directory.graph_identity);
  rc = wyl_fact_artifact_win_locator_open (locator, "facts.duckdb",
          GENERIC_READ | GENERIC_WRITE, create_main, &entry);
  if (rc == WYRELOG_E_BUSY && create_main)
    rc = wyl_fact_artifact_win_locator_open (locator, "facts.duckdb",
            GENERIC_READ | GENERIC_WRITE, FALSE, &entry);
  g_assert_cmpint (rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_entry_issue_working_handle (locator,
      entry, &main), ==, WYRELOG_E_OK);
  main_file.handle = main;
  main_file.identity = *wyl_fact_artifact_win_entry_identity (entry);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_new_with_main (&directory,
      &main_file, &namespace_), ==, WYRELOG_E_OK);
  g_assert_true (CloseHandle (main));
  wyl_fact_artifact_win_entry_free (entry);
  wyl_fact_artifact_win_locator_free (locator);
  *out_graph = graph;
  return namespace_;
}

enum
{
  LEASE_CHILD_OK = 0,
  LEASE_CHILD_BUSY = 42,
  LEASE_CHILD_ERROR = 43,
};

static int
run_lease_child (const gchar *mode, const gchar *path)
{
  HANDLE graph = INVALID_HANDLE_VALUE;
  WylFactArtifactWinNamespace *namespace_ = open_namespace_at_path (path,
          FALSE, &graph);
  WylFactArtifactWinLease *lease = NULL;
  wyrelog_error_t rc = strcmp (mode, "reader") == 0
      || strcmp (mode, "hold-reader") == 0
      ? wyl_fact_artifact_win_namespace_acquire_reader (namespace_, &lease)
      : strcmp (mode, "mutation") == 0
      ? wyl_fact_artifact_win_namespace_acquire_mutation (namespace_, &lease)
      : WYRELOG_E_INVALID;
  int result = rc == WYRELOG_E_OK ? LEASE_CHILD_OK
      : rc == WYRELOG_E_BUSY ? LEASE_CHILD_BUSY : LEASE_CHILD_ERROR;

  if (result == LEASE_CHILD_OK && strcmp (mode, "hold-reader") == 0)
    Sleep (INFINITE);           /* Parent proves crash-release via terminate. */
  wyl_fact_artifact_win_lease_free (lease);
  wyl_fact_artifact_win_namespace_free (namespace_);
  g_assert_true (CloseHandle (graph));
  return result;
}

static HANDLE
spawn_lease_child (const gchar *mode, const gchar *path)
{
  wchar_t executable[MAX_PATH + 1] = { 0 };
  DWORD length = GetModuleFileNameW (NULL, executable,
          G_N_ELEMENTS (executable));
  g_autofree gchar *exe_utf8 = NULL;
  g_autofree gchar *command_utf8 = NULL;
  g_autofree wchar_t *command = NULL;
  STARTUPINFOW startup = {.cb = sizeof startup };
  PROCESS_INFORMATION process = { 0 };

  g_assert_cmpuint (length, >, 0);
  g_assert_cmpuint (length, <, G_N_ELEMENTS (executable));
  exe_utf8 = g_utf16_to_utf8 ((gunichar2 *) executable, -1, NULL, NULL, NULL);
  g_assert_nonnull (exe_utf8);
  command_utf8 = g_strdup_printf ("\"%s\" --win-lease-child %s \"%s\"",
          exe_utf8, mode, path);
  command = g_utf8_to_utf16 (command_utf8, -1, NULL, NULL, NULL);
  g_assert_nonnull (command);
  g_assert_true (CreateProcessW (NULL, command, NULL, NULL, FALSE,
      CREATE_NO_WINDOW, NULL, NULL, &startup, &process));
  g_assert_true (CloseHandle (process.hThread));
  return process.hProcess;
}

static void
assert_child_exit (HANDLE process, DWORD expected)
{
  DWORD exit_code = STILL_ACTIVE;
  g_assert_cmpuint (WaitForSingleObject (process, 10000), ==, WAIT_OBJECT_0);
  g_assert_true (GetExitCodeProcess (process, &exit_code));
  g_assert_cmpuint (exit_code, ==, expected);
  g_assert_true (CloseHandle (process));
}

static void
test_native_namespace_cross_process_leases_and_crash_release (void)
{
  gchar *path = NULL;
  HANDLE graph = open_scratch_directory (&path);
  WylFactArtifactWinNamespace *namespace_ = NULL;
  WylFactArtifactWinLease *lease = NULL;
  HANDLE child;
  gboolean observed_busy = FALSE;
  g_autofree gchar *main_path = NULL;
  g_autofree gchar *lock_path = NULL;
  g_autofree wchar_t *main_wide = NULL;
  g_autofree wchar_t *lock_wide = NULL;
  g_autofree wchar_t *directory_wide = NULL;

  g_assert_true (CloseHandle (graph));
  graph = INVALID_HANDLE_VALUE;
  namespace_ = open_namespace_at_path (path, TRUE, &graph);

  /* These are independent processes, so success would prove that the native
   * lock is process-local rather than kernel-enforced. */
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_reader (namespace_,
      &lease), ==, WYRELOG_E_OK);
  child = spawn_lease_child ("mutation", path);
  assert_child_exit (child, LEASE_CHILD_BUSY);
  wyl_fact_artifact_win_lease_free (lease);
  lease = NULL;

  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation
        (namespace_, &lease), ==, WYRELOG_E_OK);
  child = spawn_lease_child ("reader", path);
  assert_child_exit (child, LEASE_CHILD_BUSY);
  wyl_fact_artifact_win_lease_free (lease);
  lease = NULL;

  /* A killed reader has no finally block.  Poll until its real kernel lease
   * is observed, terminate it, then require a fresh mutation lease. */
  child = spawn_lease_child ("hold-reader", path);
  for (guint i = 0; i < 200; i++) {
    wyrelog_error_t rc = wyl_fact_artifact_win_namespace_acquire_mutation
          (namespace_, &lease);
    if (rc == WYRELOG_E_BUSY) {
      observed_busy = TRUE;
      break;
    }
    if (rc == WYRELOG_E_OK) {
      wyl_fact_artifact_win_lease_free (lease);
      lease = NULL;
    } else
      g_assert_cmpint (rc, ==, WYRELOG_E_BUSY);
    Sleep (25);
  }
  g_assert_true (observed_busy);
  g_assert_true (TerminateProcess (child, 0xC000013A));
  g_assert_cmpuint (WaitForSingleObject (child, 10000), ==, WAIT_OBJECT_0);
  g_assert_true (CloseHandle (child));
  child = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation
        (namespace_, &lease), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_lease_free (lease);
  lease = NULL;

  wyl_fact_artifact_win_namespace_free (namespace_);
  g_assert_true (CloseHandle (graph));
  main_path = g_build_filename (path, "facts.duckdb", NULL);
  lock_path = g_build_filename (path, "facts.duckdb.lock", NULL);
  main_wide = g_utf8_to_utf16 (main_path, -1, NULL, NULL, NULL);
  lock_wide = g_utf8_to_utf16 (lock_path, -1, NULL, NULL, NULL);
  directory_wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_true (DeleteFileW (main_wide));
  g_assert_true (DeleteFileW (lock_wide));
  g_assert_true (RemoveDirectoryW (directory_wide));
  g_free (path);
}

static void
test_locator_directory_flush_capability_mapping (void)
{
  gchar *path = NULL;
  HANDLE graph = open_scratch_directory (&path);
  WylFactGraphWinIdentity identity = { 0 };
  WylFactArtifactWinLocator *locator = open_locator_for_test (graph, &identity);
  g_autofree wchar_t *wide = NULL;

  wyl_fact_artifact_win_locator_fail_next_directory_flush_for_test
    (ERROR_NOT_SUPPORTED);
  g_assert_cmpint (wyl_fact_artifact_win_locator_flush_directory (locator), ==,
      WYRELOG_E_POLICY);
  wyl_fact_artifact_win_locator_fail_next_directory_flush_for_test
    (ERROR_INVALID_FUNCTION);
  g_assert_cmpint (wyl_fact_artifact_win_locator_flush_directory (locator), ==,
      WYRELOG_E_POLICY);
  wyl_fact_artifact_win_locator_fail_next_directory_flush_for_test
    (ERROR_WRITE_FAULT);
  g_assert_cmpint (wyl_fact_artifact_win_locator_flush_directory (locator), ==,
      WYRELOG_E_IO);
  wyl_fact_artifact_win_locator_free (locator);
  g_assert_true (CloseHandle (graph));
  wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_true (RemoveDirectoryW (wide));
  g_free (path);
}

static void
test_locator_rename_unsupported_class_mapping (void)
{
  gchar *path = NULL;
  HANDLE graph = open_scratch_directory (&path);
  WylFactGraphWinIdentity identity = { 0 };
  WylFactArtifactWinLocator *locator = open_locator_for_test (graph, &identity);
  WylFactArtifactWinEntry *entry = NULL;
  WylFactArtifactWinMutationEffect effect =
      WYL_FACT_ARTIFACT_WIN_MUTATION_UNKNOWN;
  g_autofree wchar_t *wide = NULL;
  wyrelog_error_t err;

  err = wyl_fact_artifact_win_locator_open (locator, "source.tmp",
          GENERIC_READ | GENERIC_WRITE | DELETE, TRUE, &entry);
  g_assert_cmpint (err, ==, WYRELOG_E_OK);

  /* 1. Force STATUS_INVALID_INFO_CLASS (0xC0000003) */
  wyl_fact_artifact_win_locator_fail_next_rename_status_for_test (0xC0000003UL);
  err = wyl_fact_artifact_win_entry_rename_replace_verified (locator, entry,
          "dest.target", &effect);
  g_assert_cmpint (err, ==, WYRELOG_E_POLICY);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED);

  /* 2. Force STATUS_NOT_SUPPORTED (0xC00000BB) */
  wyl_fact_artifact_win_locator_fail_next_rename_status_for_test (0xC00000BBUL);
  err = wyl_fact_artifact_win_entry_rename_replace_verified (locator, entry,
          "dest.target", &effect);
  g_assert_cmpint (err, ==, WYRELOG_E_POLICY);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED);

  /* 3. Force STATUS_INVALID_PARAMETER (0xC000000D) */
  wyl_fact_artifact_win_locator_fail_next_rename_status_for_test (0xC000000DUL);
  err = wyl_fact_artifact_win_entry_rename_replace_verified (locator, entry,
          "dest.target", &effect);
  g_assert_cmpint (err, ==, WYRELOG_E_POLICY);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED);

  g_assert_cmpint (wyl_fact_artifact_win_entry_delete_exact (locator, entry,
      &effect), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_entry_free (entry);
  wyl_fact_artifact_win_locator_free (locator);
  g_assert_true (CloseHandle (graph));
  wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_true (RemoveDirectoryW (wide));
  g_free (path);
}

/* These two cases are a pair and the second is only meaningful while it runs
 * immediately after the first.  GLib does not honour registration order across
 * the whole binary: g_test_run_suite_internal drains a suite's own cases
 * before it recurses into child suites, so insertion order holds only among
 * siblings of one suite.  What keeps these adjacent is therefore that both are
 * registered under the same /fact/artifact-namespace/windows/locator/ suite
 * path with no other sibling registered between them -- not their adjacency in
 * the table.  Moving either one under a different prefix, or registering
 * another /locator/ case between them, silently separates them. */
static void
test_locator_leaked_flush_fault (void)
{
  gchar *path = NULL;
  HANDLE graph = open_scratch_directory (&path);
  WylFactGraphWinIdentity identity = { 0 };
  WylFactArtifactWinLocator *locator = open_locator_for_test (graph, &identity);
  WylFactArtifactWinEntry *entry = NULL;
  WylFactArtifactWinMutationEffect effect =
      WYL_FACT_ARTIFACT_WIN_MUTATION_UNKNOWN;
  g_autofree wchar_t *wide = NULL;

  /* Arm both process-wide faults, then do transport work that consumes
   * neither: locator_open goes straight to NtCreateFile and no operation on
   * this path flushes the directory, and the namespace fault is taken only on
   * the sidecar-replace path, which this case never enters.  Both are still
   * armed when the body returns, which is exactly what this row's declared
   * teardown expectation requires -- so the fixture, not this body, is where
   * "an unconsumed fault is detectable" is asserted. */
  wyl_fact_artifact_win_locator_fail_next_directory_flush_for_test
    (ERROR_NOT_SUPPORTED);
  wyl_fact_artifact_win_namespace_set_test_fault
    (WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_REPLACE_POST_RENAME_UNCERTAIN);
  g_assert_cmpint (wyl_fact_artifact_win_locator_open (locator,
      "tmp-leak-probe", GENERIC_READ | GENERIC_WRITE | DELETE, TRUE,
      &entry), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_entry_delete_exact (locator, entry,
      &effect), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED);
  wyl_fact_artifact_win_entry_free (entry);
  wyl_fact_artifact_win_locator_free (locator);
  g_assert_true (CloseHandle (graph));
  wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_true (RemoveDirectoryW (wide));
  g_free (path);
}

/* Corroboration for the row above, and the target of its mutation test: this
 * is an ordinary flush on a fresh locator that must succeed.  Without the
 * fixture's disarm it would instead consume the flush fault the previous case
 * left armed and report WYRELOG_E_POLICY -- indistinguishable from a real
 * authority violation.  Removing only one of the fixture's two takes does not
 * reproduce that: set_up's take is unconditional and destructive, so it would
 * absorb the leak (and fail there) before this body ran. */
static void
test_locator_flush_after_leaked_fault (void)
{
  gchar *path = NULL;
  HANDLE graph = open_scratch_directory (&path);
  WylFactGraphWinIdentity identity = { 0 };
  WylFactArtifactWinLocator *locator = open_locator_for_test (graph, &identity);
  g_autofree wchar_t *wide = NULL;

  g_assert_cmpint (wyl_fact_artifact_win_locator_flush_directory (locator), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_win_locator_free (locator);
  g_assert_true (CloseHandle (graph));
  wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_true (RemoveDirectoryW (wide));
  g_free (path);
}

static void
test_locator_relative_entry_lifecycle (void)
{
  gchar *path = NULL;
  HANDLE graph = open_scratch_directory (&path);
  WylFactGraphWinIdentity graph_identity = { 0 };
  WylFactArtifactWinLocator *locator = open_locator_for_test (graph,
          &graph_identity);
  WylFactArtifactWinEntry *entry = NULL;
  WylFactArtifactWinEntry *occupied = NULL;
  WylFactArtifactWinEntry *replacement = NULL;
  HANDLE issued = INVALID_HANDLE_VALUE;
  DWORD flags = HANDLE_FLAG_INHERIT;
  WylFactArtifactWinMutationEffect effect =
      WYL_FACT_ARTIFACT_WIN_MUTATION_UNKNOWN;
  wyrelog_error_t flush_rc;
  g_autofree gchar *renamed = g_build_filename (path, "facts.duckdb.wal", NULL);
  g_autofree gchar *outside = g_build_filename (path, "outside", NULL);
  g_autofree wchar_t *wide = NULL;
  g_autofree wchar_t *outside_wide = NULL;
  g_autofree wchar_t *directory_wide = NULL;

  g_assert_cmpint (wyl_fact_artifact_win_locator_open (locator,
      "tmp-source", GENERIC_READ | GENERIC_WRITE | DELETE, TRUE, &entry),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_locator_open (locator, "occupied",
      GENERIC_READ | GENERIC_WRITE | DELETE, TRUE, &occupied), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_entry_rename_no_replace (locator,
      entry, "occupied", &effect), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED);
  g_assert_cmpint (wyl_fact_artifact_win_entry_delete_exact (locator,
      occupied, &effect), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_entry_free (occupied);
  occupied = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_entry_issue_working_handle (locator,
      entry, &issued), ==, WYRELOG_E_OK);
  g_assert_true (GetHandleInformation (issued, &flags));
  g_assert_cmpuint (flags & HANDLE_FLAG_INHERIT, ==, 0);
  g_assert_true (CloseHandle (issued));
  g_assert_cmpint (wyl_fact_artifact_win_entry_rename_no_replace (locator,
      entry, "facts.duckdb.wal", &effect), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED);
  g_assert_cmpint (wyl_fact_artifact_win_entry_revalidate (locator, entry),
      ==, WYRELOG_E_OK);
  /* Move the entry outside the canonical name and install a replacement.  A
   * stale entry's working-HANDLE issuance must validate the whole locator
   * hierarchy/name association, not only its retained HANDLE/FileId. */
  wide = g_utf8_to_utf16 (renamed, -1, NULL, NULL, NULL);
  outside_wide = g_utf8_to_utf16 (outside, -1, NULL, NULL, NULL);
  g_assert_true (MoveFileExW (wide, outside_wide, MOVEFILE_WRITE_THROUGH));
  g_assert_cmpint (wyl_fact_artifact_win_locator_open (locator,
      "facts.duckdb.wal", GENERIC_READ | GENERIC_WRITE | DELETE, TRUE,
      &replacement), ==, WYRELOG_E_OK);
  issued = (HANDLE) 1;
  g_assert_cmpint (wyl_fact_artifact_win_entry_issue_working_handle (locator,
      entry, &issued), ==, WYRELOG_E_POLICY);
  g_assert_true (issued == INVALID_HANDLE_VALUE);
  wyl_fact_artifact_win_entry_free (entry);
  entry = NULL;
  g_assert_true (DeleteFileW (outside_wide));
  g_assert_cmpint (wyl_fact_artifact_win_entry_delete_exact (locator,
      replacement, &effect), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_entry_free (replacement);
  replacement = NULL;
  /* Filesystems that cannot flush a directory fail closed: the physical
   * operation is still independently proven by its explicit return value. */
  flush_rc = wyl_fact_artifact_win_locator_flush_directory (locator);
  g_assert_true (flush_rc == WYRELOG_E_OK || flush_rc == WYRELOG_E_IO
      || flush_rc == WYRELOG_E_POLICY);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED);
  g_clear_pointer (&wide, g_free);
  wide = g_utf8_to_utf16 (renamed, -1, NULL, NULL, NULL);
  g_assert_false (GetFileAttributesW (wide) != INVALID_FILE_ATTRIBUTES);
  wyl_fact_artifact_win_locator_free (locator);
  g_assert_true (CloseHandle (graph));
  directory_wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_true (RemoveDirectoryW (directory_wide));
  g_free (path);
}

/* Replacement has to linearize while the destination's own HANDLE is still
 * open, and has to leave that HANDLE addressing the same, now nameless,
 * object.  Classic FileRenameInformation can do neither: the kernel refuses
 * it on the target's open count alone, whatever the share modes. */
static void
test_locator_replace_open_destination (void)
{
  gchar *path = NULL;
  HANDLE graph = open_scratch_directory (&path);
  WylFactGraphWinIdentity graph_identity = { 0 };
  WylFactArtifactWinLocator *locator = open_locator_for_test (graph,
          &graph_identity);
  WylFactArtifactWinEntry *source = NULL;
  WylFactArtifactWinEntry *target = NULL;
  WylFactArtifactWinEntry *resolved = NULL;
  WylFactGraphWinIdentity source_identity = { 0 };
  WylFactGraphWinIdentity target_identity = { 0 };
  WylFactGraphWinIdentity held_identity = { 0 };
  WylFactArtifactWinMutationEffect effect =
      WYL_FACT_ARTIFACT_WIN_MUTATION_UNKNOWN;
  HANDLE held = INVALID_HANDLE_VALUE;
  g_autofree wchar_t *directory_wide = NULL;

  g_assert_cmpint (wyl_fact_artifact_win_locator_open (locator, "tmp-source",
      GENERIC_READ | GENERIC_WRITE | DELETE, TRUE, &source), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_locator_open (locator, "target",
      GENERIC_READ | GENERIC_WRITE | DELETE, TRUE, &target), ==,
      WYRELOG_E_OK);
  source_identity = *wyl_fact_artifact_win_entry_identity (source);
  target_identity = *wyl_fact_artifact_win_entry_identity (target);
  g_assert_cmpint (wyl_fact_artifact_win_entry_issue_working_handle (locator,
      target, &held), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_entry_rename_replace_verified
        (locator, source, "target", &effect), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED);
  /* The replaced object outlives its only link and stays reachable through
   * the HANDLE its holder already owns, while the name now answers with the
   * source. */
  held_identity = identity_for (held);
  g_assert_true (identity_matches (&held_identity, &target_identity));
  g_assert_cmpint (wyl_fact_artifact_win_locator_open (locator, "target",
      GENERIC_READ, FALSE, &resolved), ==, WYRELOG_E_OK);
  g_assert_true (identity_matches (wyl_fact_artifact_win_entry_identity
        (resolved), &source_identity));
  wyl_fact_artifact_win_entry_free (resolved);
  g_assert_true (CloseHandle (held));
  g_assert_cmpint (wyl_fact_artifact_win_entry_delete_exact (locator, source,
      &effect), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED);
  wyl_fact_artifact_win_entry_free (source);
  wyl_fact_artifact_win_entry_free (target);
  wyl_fact_artifact_win_locator_free (locator);
  g_assert_true (CloseHandle (graph));
  directory_wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_true (RemoveDirectoryW (directory_wide));
  g_free (path);
}

static void
test_locator_nested_directory_transport (void)
{
  gchar *path = NULL;
  HANDLE graph = open_scratch_directory (&path);
  WylFactGraphWinIdentity graph_identity = { 0 };
  WylFactArtifactWinLocator *locator = open_locator_for_test (graph,
          &graph_identity);
  WylFactArtifactWinDirectory *root = NULL;
  WylFactArtifactWinDirectory *stale_root = NULL;
  WylFactArtifactWinEntry *child = NULL;
  WylFactGraphWinIdentity root_identity = { 0 };
  WylFactGraphWinIdentity child_identity = { 0 };
  HANDLE volume = open_scratch_volume ();
  HANDLE issued = INVALID_HANDLE_VALUE;
  WylFactArtifactWinMutationEffect effect =
      WYL_FACT_ARTIFACT_WIN_MUTATION_UNKNOWN;
  DWORD flags = HANDLE_FLAG_INHERIT;
  g_autofree gchar *root_path = g_build_filename (path, "duckdb-root", NULL);
  g_autofree gchar *child_path = g_build_filename (root_path,
          "duckdb_temp_storage_DEFAULT-1.tmp", NULL);
  g_autofree gchar *old_child_path = g_build_filename (root_path,
          "child-old", NULL);
  g_autofree gchar *stale_path = g_build_filename (path, "stale-root", NULL);
  g_autofree gchar *stale_old_path = g_build_filename (path,
          "stale-root-old", NULL);
  g_autofree wchar_t *root_wide = g_utf8_to_utf16 (root_path, -1, NULL, NULL,
          NULL);
  g_autofree wchar_t *child_wide = g_utf8_to_utf16 (child_path, -1, NULL,
          NULL, NULL);
  g_autofree wchar_t *old_child_wide = g_utf8_to_utf16 (old_child_path, -1,
          NULL, NULL, NULL);
  g_autofree wchar_t *stale_wide = g_utf8_to_utf16 (stale_path, -1, NULL,
          NULL, NULL);
  g_autofree wchar_t *stale_old_wide = g_utf8_to_utf16 (stale_old_path, -1,
          NULL, NULL, NULL);

  g_assert_cmpint (wyl_fact_artifact_win_locator_create_directory (locator,
      "duckdb-root", &root), ==, WYRELOG_E_OK);
  root_identity = identity_for_path (root_path);
  HANDLE root_handle = CreateFileW (root_wide, READ_CONTROL,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
          OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
  g_assert_true (root_handle != INVALID_HANDLE_VALUE);
  g_assert_cmpint (wyl_fact_graph_win_validate_protected_owner_acl (root_handle,
      0), ==, WYRELOG_E_OK);
  g_assert_true (CloseHandle (root_handle));
  g_assert_cmpint (wyl_fact_artifact_win_directory_open_file (locator, root,
      "duckdb_temp_storage_DEFAULT-1.tmp",
      GENERIC_READ | GENERIC_WRITE | DELETE, TRUE, &child), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_directory_entry_issue_working_handle
        (locator, root, child, &issued), ==, WYRELOG_E_OK);
  g_assert_true (GetHandleInformation (issued, &flags));
  g_assert_cmpuint (flags & HANDLE_FLAG_INHERIT, ==, 0);
  g_assert_cmpint (wyl_fact_graph_win_validate_protected_owner_acl (issued, 0),
      ==, WYRELOG_E_OK);
  g_assert_true (CloseHandle (issued));
  issued = INVALID_HANDLE_VALUE;

  /* Replacing a child's canonical name cannot turn the retained entry into a
   * new working capability.  The output is initialized on this failure. */
  g_assert_true (MoveFileExW (child_wide, old_child_wide,
      MOVEFILE_WRITE_THROUGH));
  HANDLE replacement = CreateFileW (child_wide, GENERIC_READ | GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_NEW,
          FILE_ATTRIBUTE_NORMAL, NULL);
  g_assert_true (replacement != INVALID_HANDLE_VALUE);
  g_assert_true (CloseHandle (replacement));
  issued = (HANDLE) 1;
  g_assert_cmpint (wyl_fact_artifact_win_directory_entry_issue_working_handle
        (locator, root, child, &issued), ==, WYRELOG_E_POLICY);
  g_assert_true (issued == INVALID_HANDLE_VALUE);
  wyl_fact_artifact_win_entry_free (child);
  child = NULL;
  g_assert_true (DeleteFileW (old_child_wide));
  g_assert_true (DeleteFileW (child_wide));
  /* Reopen a fresh exact child, then prove child-before-root deletion. */
  g_assert_cmpint (wyl_fact_artifact_win_directory_open_file (locator, root,
      "duckdb_temp_storage_DEFAULT-1.tmp",
      GENERIC_READ | GENERIC_WRITE | DELETE, TRUE, &child), ==,
      WYRELOG_E_OK);
  child_identity = identity_for_path (child_path);
  g_assert_cmpint (wyl_fact_artifact_win_directory_entry_delete_exact (locator,
      root, child, &effect), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED);
  /* The entry now holds the only handle to a nameless object, so the object
   * itself reports whether the destructor released it.  A process handle
   * count cannot: the scratch churn around it moves that count by as much as
   * one retained handle would.  Each pair below enforces its own premise --
   * the object must still be reachable while the owner is alive -- so an
   * unreachable result afterwards can only be the destructor's close. */
  g_assert_true (deleted_object_is_open (volume, child_wide, &child_identity));
  wyl_fact_artifact_win_entry_free (child);
  child = NULL;
  g_assert_false (deleted_object_is_open_after_wait (volume, child_wide,
      &child_identity));
  g_assert_cmpint (wyl_fact_artifact_win_directory_delete_empty (locator, root,
      &effect), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED);
  /* DeletePending must not turn the owned directory handle into a destructor
   * leak: terminal cleanup closes exactly that retained handle. */
  g_assert_true (deleted_object_is_open (volume, root_wide, &root_identity));
  wyl_fact_artifact_win_directory_free (root);
  root = NULL;
  g_assert_false (deleted_object_is_open_after_wait (volume, root_wide,
      &root_identity));

  /* The root itself is also name-bound.  A raw name substitution revokes the
   * opaque directory capability, and free must leave the replacement alone. */
  g_assert_cmpint (wyl_fact_artifact_win_locator_create_directory (locator,
      "stale-root", &stale_root), ==, WYRELOG_E_OK);
  g_assert_true (MoveFileExW (stale_wide, stale_old_wide,
      MOVEFILE_WRITE_THROUGH));
  g_assert_true (CreateDirectoryW (stale_wide, NULL));
  g_assert_cmpint (wyl_fact_artifact_win_directory_revalidate (locator,
      stale_root), ==, WYRELOG_E_POLICY);
  wyl_fact_artifact_win_directory_free (stale_root);
  stale_root = NULL;
  g_assert_true (RemoveDirectoryW (stale_wide));
  g_assert_true (RemoveDirectoryW (stale_old_wide));

  wyl_fact_artifact_win_locator_free (locator);
  g_assert_true (CloseHandle (volume));
  g_assert_true (CloseHandle (graph));
  g_autofree wchar_t *directory_wide = g_utf8_to_utf16 (path, -1, NULL, NULL,
          NULL);
  g_assert_true (RemoveDirectoryW (directory_wide));
  g_free (path);
}

static void
test_native_namespace_captured_owner_acl_binding (void)
{
  gchar *path = NULL;
  HANDLE graph = open_scratch_directory (&path);
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactArtifactWinNamespace *namespace_ = NULL;
  WylFactArtifactWinNamespace *owner = NULL;
  WylFactArtifactWinLease *mutation = NULL;
  WylFactArtifactWinSidecarBinding *seed = NULL;
  WylFactArtifactWinBinding *binding = NULL;
  WylFactArtifactWinBinding *reopened = NULL;
  WylFactArtifactWinIoSession *session = NULL;
  HANDLE owner_graph = INVALID_HANDLE_VALUE;
  g_autofree gchar *wal_path = NULL;
  g_autofree gchar *main_path = NULL;
  g_autofree gchar *lock_path = NULL;
  g_autofree wchar_t *wal = NULL;
  g_autofree wchar_t *main_wide = NULL;
  g_autofree wchar_t *lock_wide = NULL;

  directory.graph_handle = graph;
  directory.graph_identity = identity_for (graph);
  /* Generic fixed I/O is reader-authorized only.  Provision the main and
   * sidecar through the normal imported-main/exclusive-lease path first. */
  owner = open_namespace_at_path (path, TRUE, &owner_graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (owner,
      &mutation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (mutation, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &seed), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_sidecar_binding_free (seed);
  wyl_fact_artifact_win_lease_free (mutation);
  wyl_fact_artifact_win_namespace_free (owner);
  owner = NULL;
  g_assert_true (CloseHandle (owner_graph));
  owner_graph = INVALID_HANDLE_VALUE;
  g_assert_cmpint (wyl_fact_artifact_win_namespace_new (&directory,
      &namespace_), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_open_fixed (namespace_,
      WYL_FACT_ARTIFACT_WAL, GENERIC_READ, FALSE,
      &binding), ==, WYRELOG_E_OK);
  /* MAIN cannot be minted through the generic namespace, including strict
   * creation.  Only #615 evidence import plus an exclusive native lease may
   * issue a main HANDLE. */
  g_assert_cmpint (wyl_fact_artifact_win_namespace_open_fixed (namespace_,
      WYL_FACT_ARTIFACT_MAIN, GENERIC_READ, FALSE,
      &reopened), ==, WYRELOG_E_POLICY);
  g_assert_null (reopened);
  g_assert_cmpint (wyl_fact_artifact_win_binding_open_io_session (binding,
      &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;
  wyl_fact_artifact_win_binding_free (binding);
  binding = NULL;
  wyl_fact_artifact_win_namespace_free (namespace_);
  namespace_ = NULL;
  /* Existing entries must prove the same captured-owner protected DACL before
   * they are re-issued through a new opaque binding. */
  g_assert_cmpint (wyl_fact_artifact_win_namespace_new (&directory,
      &namespace_), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_open_fixed (namespace_,
      WYL_FACT_ARTIFACT_WAL, GENERIC_READ, FALSE,
      &reopened), ==, WYRELOG_E_OK);
  /* The binding holds its own namespace reference; lifetime handoff must not
   * invalidate native revalidation between a caller releasing the namespace
   * and the final HANDLE close. */
  wyl_fact_artifact_win_namespace_free (namespace_);
  namespace_ = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_binding_open_io_session (reopened,
      &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;
  wyl_fact_artifact_win_binding_free (reopened);
  reopened = NULL;
  /* ACL substitution itself is covered by the locator's controlled native
   * hook. Artifact I/O intentionally has no HANDLE escape route. */
  g_assert_cmpint (wyl_fact_artifact_win_namespace_new (&directory,
      &namespace_), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_open_fixed (namespace_,
      WYL_FACT_ARTIFACT_WAL, GENERIC_READ, FALSE,
      &reopened), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_binding_open_io_session (reopened,
      &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;
  wyl_fact_artifact_win_binding_free (reopened);
  reopened = NULL;
  /* The legacy gint API remains deliberately unavailable on Windows. */
  g_assert_cmpint (wyl_fact_artifact_namespace_open_file (NULL,
      WYL_FACT_ARTIFACT_WAL, FALSE, TRUE, NULL), ==, WYRELOG_E_POLICY);
  wal_path = g_build_filename (path, "facts.duckdb.wal", NULL);
  main_path = g_build_filename (path, "facts.duckdb", NULL);
  lock_path = g_build_filename (path, "facts.duckdb.lock", NULL);
  wal = g_utf8_to_utf16 (wal_path, -1, NULL, NULL, NULL);
  main_wide = g_utf8_to_utf16 (main_path, -1, NULL, NULL, NULL);
  lock_wide = g_utf8_to_utf16 (lock_path, -1, NULL, NULL, NULL);
  g_assert_true (DeleteFileW (wal));
  wyl_fact_artifact_win_namespace_free (namespace_);
  namespace_ = NULL;
  g_autofree wchar_t *directory_wide = g_utf8_to_utf16 (path, -1, NULL,
          NULL, NULL);
  g_assert_true (CloseHandle (graph));
  g_assert_true (DeleteFileW (main_wide));
  g_assert_true (DeleteFileW (lock_wide));
  g_assert_true (RemoveDirectoryW (directory_wide));
  g_free (path);
}

static void
test_native_namespace_release_binding_stress (void)
{
  gchar *path = NULL;
  HANDLE graph = open_scratch_directory (&path);
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactArtifactWinNamespace *owner = NULL;
  WylFactArtifactWinLease *mutation = NULL;
  WylFactArtifactWinSidecarBinding *seed = NULL;
  HANDLE owner_graph = INVALID_HANDLE_VALUE;
  g_autofree gchar *wal_path = NULL;
  g_autofree gchar *main_path = NULL;
  g_autofree gchar *lock_path = NULL;
  g_autofree wchar_t *wal = NULL;
  g_autofree wchar_t *main_wide = NULL;
  g_autofree wchar_t *lock_wide = NULL;

  directory.graph_handle = graph;
  directory.graph_identity = identity_for (graph);
  owner = open_namespace_at_path (path, TRUE, &owner_graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (owner,
      &mutation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (mutation, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &seed), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_sidecar_binding_free (seed);
  wyl_fact_artifact_win_lease_free (mutation);
  wyl_fact_artifact_win_namespace_free (owner);
  owner = NULL;
  g_assert_true (CloseHandle (owner_graph));
  owner_graph = INVALID_HANDLE_VALUE;
  wal_path = g_build_filename (path, "facts.duckdb.wal", NULL);
  wal = g_utf8_to_utf16 (wal_path, -1, NULL, NULL, NULL);
  for (guint i = 0; i < 64; i++) {
    WylFactArtifactWinNamespace *namespace_ = NULL;
    WylFactArtifactWinBinding *binding = NULL;
    NamespaceReleaseProbe probe = { 0 };
    WylFactArtifactWinIoSession *session = NULL;
    g_autoptr (GThread) releaser = NULL;

    g_assert_cmpint (wyl_fact_artifact_win_namespace_new (&directory,
        &namespace_), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_win_namespace_open_fixed (namespace_,
        WYL_FACT_ARTIFACT_WAL, GENERIC_READ, FALSE,
        &binding), ==, WYRELOG_E_OK);
    probe.namespace_ = namespace_;
    releaser = g_thread_new ("namespace-release", release_namespace_thread,
            &probe);
    g_thread_join (g_steal_pointer (&releaser));
    g_assert_cmpint (wyl_fact_artifact_win_binding_open_io_session (binding,
        &session), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
        WYRELOG_E_OK);
    wyl_fact_artifact_win_binding_free (binding);
  }
  g_assert_true (DeleteFileW (wal));
  main_path = g_build_filename (path, "facts.duckdb", NULL);
  lock_path = g_build_filename (path, "facts.duckdb.lock", NULL);
  main_wide = g_utf8_to_utf16 (main_path, -1, NULL, NULL, NULL);
  lock_wide = g_utf8_to_utf16 (lock_path, -1, NULL, NULL, NULL);
  g_autofree wchar_t *directory_wide = g_utf8_to_utf16 (path, -1, NULL,
          NULL, NULL);
  g_assert_true (CloseHandle (graph));
  g_assert_true (DeleteFileW (main_wide));
  g_assert_true (DeleteFileW (lock_wide));
  g_assert_true (RemoveDirectoryW (directory_wide));
  g_free (path);
}

static void
test_generic_reader_session_blocks_cross_namespace_mutation (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *path = g_dir_make_tmp ("wyl-win-reader-domain-XXXXXX",
          &error);
  WylFactArtifactWinNamespace *seed = NULL;
  WylFactArtifactWinNamespace *reader = NULL;
  WylFactArtifactWinNamespace *writer = NULL;
  WylFactArtifactWinLease *mutation = NULL;
  WylFactArtifactWinLease *writer_mutation = NULL;
  WylFactArtifactWinSidecarBinding *sidecar = NULL;
  WylFactArtifactWinBinding *binding = NULL;
  WylFactArtifactWinIoSession *session = NULL;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  HANDLE seed_graph = INVALID_HANDLE_VALUE;
  HANDLE reader_graph = INVALID_HANDLE_VALUE;
  HANDLE writer_graph = INVALID_HANDLE_VALUE;

  g_assert_no_error (error);
  seed = open_namespace_at_path (path, TRUE, &seed_graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (seed,
      &mutation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (mutation, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &sidecar), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  wyl_fact_artifact_win_lease_free (mutation);
  wyl_fact_artifact_win_namespace_free (seed);
  g_assert_true (CloseHandle (seed_graph));

  {
    g_autofree wchar_t *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
    reader_graph = CreateFileW (wide, FILE_LIST_DIRECTORY | FILE_ADD_FILE
            | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
  }
  g_assert_true (reader_graph != INVALID_HANDLE_VALUE);
  directory.graph_handle = reader_graph;
  directory.graph_identity = identity_for (reader_graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_new (&directory, &reader),
      ==, WYRELOG_E_OK);
  /* Failed generic opens must release their reader lease.  Otherwise a
   * missing sidecar would permanently strand an exclusive writer in BUSY. */
  binding = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_artifact_win_namespace_open_fixed (reader,
      WYL_FACT_ARTIFACT_CHECKPOINT, GENERIC_READ, FALSE, &binding), ==,
      WYRELOG_E_NOT_FOUND);
  g_assert_null (binding);
  writer = open_namespace_at_path (path, FALSE, &writer_graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (writer,
      &writer_mutation), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_lease_free (writer_mutation);
  writer_mutation = NULL;
  wyl_fact_artifact_win_namespace_free (writer);
  writer = NULL;
  g_assert_true (CloseHandle (writer_graph));
  writer_graph = INVALID_HANDLE_VALUE;
  g_assert_cmpint (wyl_fact_artifact_win_namespace_open_fixed (reader,
      WYL_FACT_ARTIFACT_WAL, GENERIC_READ, FALSE, &binding), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_binding_open_io_session (binding,
      &session), ==, WYRELOG_E_OK);
  /* The live reader session keeps its private reader lease after all public
   * reader handles are released.  A fresh namespace must still observe BUSY
   * when it asks for an exclusive mutation lease. */
  wyl_fact_artifact_win_binding_free (binding);
  binding = NULL;
  wyl_fact_artifact_win_namespace_free (reader);
  reader = NULL;
  writer = open_namespace_at_path (path, FALSE, &writer_graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (writer,
      &writer_mutation), ==, WYRELOG_E_BUSY);
  g_assert_null (writer_mutation);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (writer,
      &writer_mutation), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_lease_free (writer_mutation);
  wyl_fact_artifact_win_namespace_free (writer);
  g_assert_true (CloseHandle (reader_graph));
  g_assert_true (CloseHandle (writer_graph));
  {
    g_autofree gchar *main_path = g_build_filename (path, "facts.duckdb", NULL);
    g_autofree gchar *lock_path =
        g_build_filename (path, "facts.duckdb.lock", NULL);
    g_autofree gchar *wal_path =
        g_build_filename (path, "facts.duckdb.wal", NULL);
    g_autofree wchar_t *main_wide =
        g_utf8_to_utf16 (main_path, -1, NULL, NULL, NULL);
    g_autofree wchar_t *lock_wide =
        g_utf8_to_utf16 (lock_path, -1, NULL, NULL, NULL);
    g_autofree wchar_t *wal_wide =
        g_utf8_to_utf16 (wal_path, -1, NULL, NULL, NULL);
    g_autofree wchar_t *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
    g_assert_true (DeleteFileW (main_wide));
    g_assert_true (DeleteFileW (lock_wide));
    g_assert_true (DeleteFileW (wal_wide));
    g_assert_true (RemoveDirectoryW (wide));
  }
}

static void
test_live_session_source_substitution_is_policy (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *path = g_dir_make_tmp ("wyl-win-live-source-XXXXXX",
          &error);
  WylFactArtifactWinNamespace *namespace_ = NULL;
  WylFactArtifactWinLease *lease = NULL;
  WylFactArtifactWinSidecarBinding *sidecar = NULL;
  WylFactArtifactWinIoSession *session = NULL;
  HANDLE graph = INVALID_HANDLE_VALUE;
  g_autofree gchar *wal_path = NULL;
  g_autofree gchar *outside_path = NULL;
  g_autofree gchar *main_path = NULL;
  g_autofree gchar *lock_path = NULL;
  g_autofree wchar_t *wal_wide = NULL;
  g_autofree wchar_t *outside_wide = NULL;
  g_autofree wchar_t *main_wide = NULL;
  g_autofree wchar_t *lock_wide = NULL;
  g_autofree wchar_t *directory_wide = NULL;
  guint64 size = 0;

  g_assert_no_error (error);
  namespace_ = open_namespace_at_path (path, TRUE, &graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (namespace_,
      &lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
        (sidecar, &session), ==, WYRELOG_E_OK);
  wal_path = g_build_filename (path, "facts.duckdb.wal", NULL);
  outside_path = g_build_filename (path, "outside-wal", NULL);
  wal_wide = g_utf8_to_utf16 (wal_path, -1, NULL, NULL, NULL);
  outside_wide = g_utf8_to_utf16 (outside_path, -1, NULL, NULL, NULL);
  g_assert_true (MoveFileExW (wal_wide, outside_wide, MOVEFILE_WRITE_THROUGH));
  /* The private guardian still names the old object, but the session's
   * retained validator must fail the canonical source association before I/O. */
  g_assert_cmpint (wyl_fact_artifact_win_io_session_size (session, &size), ==,
      WYRELOG_E_POLICY);
  /* The exact FileId/name may come back, but a session that observed an
   * association failure remains terminally revoked. */
  g_assert_true (MoveFileExW (outside_wide, wal_wide, MOVEFILE_WRITE_THROUGH));
  g_assert_cmpint (wyl_fact_artifact_win_io_session_size (session, &size), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  wyl_fact_artifact_win_lease_free (lease);
  wyl_fact_artifact_win_namespace_free (namespace_);
  g_assert_true (CloseHandle (graph));
  main_path = g_build_filename (path, "facts.duckdb", NULL);
  lock_path = g_build_filename (path, "facts.duckdb.lock", NULL);
  main_wide = g_utf8_to_utf16 (main_path, -1, NULL, NULL, NULL);
  lock_wide = g_utf8_to_utf16 (lock_path, -1, NULL, NULL, NULL);
  directory_wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_true (DeleteFileW (wal_wide));
  g_assert_true (DeleteFileW (main_wide));
  g_assert_true (DeleteFileW (lock_wide));
  g_assert_true (RemoveDirectoryW (directory_wide));
}

static void
test_working_handle_adopt_noninherit_close_once (void)
{
  gchar *path = NULL;
  HANDLE issued = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (issued);
  WylFactArtifactWinWorkingHandle *working = NULL;
  WylFactArtifactWinIoState *state = NULL;
  WylFactArtifactWinIoSession *session = NULL;

  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (issued,
      &identity, &working), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_state_new (working, &state), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_open (state, TRUE, &session), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_win_io_state_free (state);
  remove_scratch_file (path);
}

static void
test_working_handle_identity_mismatch_initializes_output (void)
{
  gchar *path = NULL;
  HANDLE issued = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (issued);
  WylFactArtifactWinWorkingHandle *binding = (gpointer) 0x1;

  identity.file_id[0] ^= 0xff;
  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (issued,
      &identity, &binding), ==, WYRELOG_E_POLICY);
  g_assert_null (binding);
  g_assert_true (CloseHandle (issued));
  remove_scratch_file (path);
}

static void
test_working_handle_free_never_closes_reused_handle (void)
{
  gchar *path = NULL;
  gchar *foreign_path = NULL;
  HANDLE issued = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (issued);
  WylFactArtifactWinWorkingHandle *binding = NULL;
  HANDLE foreign = INVALID_HANDLE_VALUE;
  BY_HANDLE_FILE_INFORMATION info = { 0 };
  guint attempt;

  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (issued,
      &identity, &binding), ==, WYRELOG_E_OK);
  /* Adoption consumed |issued| and retained only a private duplicate. */
  g_assert_false (CloseHandle (issued));
  /* Numeric reuse of the consumed slot is this test's precondition, not the
   * property it proves; nothing obliges the kernel to hand the value straight
   * back.  Retry a bounded number of times and make a precondition that never
   * arrives visible as a skip rather than as a silent pass. */
  for (attempt = 0; attempt < 64; attempt++) {
    foreign = open_scratch_file (&foreign_path);
    if (foreign == issued)
      break;
    g_assert_true (CloseHandle (foreign));
    foreign = INVALID_HANDLE_VALUE;
    remove_scratch_file (foreign_path);
    foreign_path = NULL;
  }
  if (foreign != issued) {
    g_autofree gchar *message = g_strdup_printf
          ("the consumed handle slot did not return in %u attempts", attempt);

    g_test_skip (message);
    wyl_fact_artifact_win_working_handle_free (binding);
    remove_scratch_file (path);
    return;
  }
  wyl_fact_artifact_win_working_handle_free (binding);
  g_assert_true (GetFileInformationByHandle (foreign, &info));
  g_assert_true (CloseHandle (foreign));
  remove_scratch_file (foreign_path);
  remove_scratch_file (path);
}

typedef enum
{
  /* The destructor closed the guardian; the nameless object went with it. */
  UNLINKED_RELEASE_CLOSED,
  /* Some handle to the nameless object outlived the destructor. */
  UNLINKED_RELEASE_SURVIVED,
  /* The filesystem keeps the name until the last handle goes, so the unlink
   * never produced a nameless object to ask about. */
  UNLINKED_RELEASE_NAME_KEPT,
  /* The volume serves no lookup by file id, not even for an object this
   * function knows to be open, so the observation is unavailable here. */
  UNLINKED_RELEASE_NO_ID_LOOKUP
} UnlinkedReleaseResult;

/* Adopts a working handle, unlinks its only name so the guardian addresses a
 * live object with no remaining link, then releases the binding and reports
 * whether that now-nameless object was still alive once the destructor
 * returned, which is so exactly when the guardian duplicate outlived it.
 *
 * Both unavailable results are decided before anything about reachability is
 * asserted, because on the filesystems they stand for the assertion cannot
 * hold: a name that survives its last unlink leaves the object delete-pending
 * and refusing every open until the last handle goes, and a volume with no id
 * namespace refuses the lookup outright.  Asserting first would abort the
 * whole binary in place of the caller's skip. */
static UnlinkedReleaseResult
release_unlinked_working_handle (void)
{
  gchar *path = NULL;
  HANDLE issued = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (issued);
  HANDLE witness = open_existing_scratch_file (path);
  HANDLE volume = open_scratch_volume ();
  WylFactArtifactWinWorkingHandle *binding = NULL;
  BY_HANDLE_FILE_INFORMATION info = { 0 };
  gboolean survived;
  g_autofree gchar *directory = g_path_get_dirname (path);
  g_autofree wchar_t *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_autofree wchar_t *wide_directory = g_utf8_to_utf16 (directory, -1, NULL,
          NULL, NULL);

  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (issued,
      &identity, &binding), ==, WYRELOG_E_OK);
  g_assert_true (DeleteFileW (wide));
  g_assert_true (GetFileInformationByHandle (witness, &info));
  g_assert_true (CloseHandle (witness));
  if (info.nNumberOfLinks != 0) {
    wyl_fact_artifact_win_working_handle_free (binding);
    g_assert_true (CloseHandle (volume));
    /* Deliberately best-effort: the marked name is only retired once the
     * last handle to it goes, which may be later than this call. */
    RemoveDirectoryW (wide_directory);
    g_free (path);
    return UNLINKED_RELEASE_NAME_KEPT;
  }
  /* The control for the observation below, and the very same call: with the
  * guardian known to be open the object must be reachable here, or its
  * later unreachability would prove nothing about who closed it.  A volume
  * that cannot answer even now is not reporting a leak -- the object is
  * certainly alive -- so that reading is unavailable rather than failed. */
  if (!unlinked_object_is_open (volume, &identity)) {
    wyl_fact_artifact_win_working_handle_free (binding);
    g_assert_true (CloseHandle (volume));
    g_assert_true (RemoveDirectoryW (wide_directory));
    g_free (path);
    return UNLINKED_RELEASE_NO_ID_LOOKUP;
  }
  wyl_fact_artifact_win_working_handle_free (binding);
  survived = unlinked_object_is_open (volume, &identity);
  g_assert_true (CloseHandle (volume));
  /* The unlink already took the name away, so the directory is empty whether
   * or not a handle to the object remains. */
  g_assert_true (RemoveDirectoryW (wide_directory));
  g_free (path);
  return survived ? UNLINKED_RELEASE_SURVIVED : UNLINKED_RELEASE_CLOSED;
}

/* Retirement leaves a guardian on an object whose last link is gone.  The
 * destructor still owns that duplicate and must close it.
 *
 * This deliberately does not budget a GetProcessHandleCount delta across the
 * releases, as it once did.  That budget was an estimate of ambient noise,
 * and a wrong one: creating and removing one scratch directory per cycle
 * moves the process handle count by roughly as much per iteration as a leaked
 * guardian would, so no budget over the loop can separate the two, and
 * sampling either side of a single release only trades that for other
 * threads' churn, which is the same size again.
 *
 * Ask the object rather than the process.  The assumption is that an unlinked
 * object stays addressable by file id for as long as any handle to it is
 * open, and the case enforces that on every iteration instead of trusting it:
 * the identical lookup must succeed while the guardian is still held.  A
 * lookup that then fails is the destructor's close and nothing else.
 *
 * The two ways a machine can fail to offer that assumption -- a filesystem
 * that keeps the name past its last unlink, and a volume that serves no id
 * lookup at all -- are settled by the first release, before any assertion
 * depends on them, and reported here as a skip. */
static void
test_working_handle_free_closes_unlinked_object (void)
{
  UnlinkedReleaseResult first = release_unlinked_working_handle ();
  guint i;

  if (first == UNLINKED_RELEASE_NAME_KEPT) {
    g_test_skip ("unlinking a held name kept the link count here");
    return;
  }
  if (first == UNLINKED_RELEASE_NO_ID_LOOKUP) {
    g_test_skip ("the scratch volume serves no lookup by file id");
    return;
  }
  g_assert_cmpint (first, ==, UNLINKED_RELEASE_CLOSED);
  for (i = 0; i < 50; i++)
    g_assert_cmpint (release_unlinked_working_handle (), ==,
        UNLINKED_RELEASE_CLOSED);
}

static void
test_working_handle_source_reuse_cannot_revoke_guardian (void)
{
  gchar *path = NULL;
  HANDLE issued = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (issued);
  WylFactArtifactWinWorkingHandle *working = NULL;
  WylFactArtifactWinIoState *state = NULL;
  WylFactArtifactWinIoSession *session = NULL;

  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (issued,
      &identity, &working), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_state_new (working, &state), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_open (state, TRUE, &session), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_win_io_session_abort (session);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_open (state, TRUE, &session), ==,
      WYRELOG_E_BUSY);
  wyl_fact_artifact_win_io_state_free (state);
  remove_scratch_file (path);
}

static void
test_session_abort_is_terminal (void)
{
  gchar *path = NULL;
  HANDLE issued = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (issued);
  WylFactArtifactWinWorkingHandle *working = NULL;
  WylFactArtifactWinIoState *state = NULL;
  WylFactArtifactWinIoSession *session = NULL;

  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (issued,
      &identity, &working), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_state_new (working, &state), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_open (state, TRUE, &session), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_win_io_session_abort (session);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_open (state, TRUE, &session), ==,
      WYRELOG_E_BUSY);
  wyl_fact_artifact_win_io_state_free (state);
  remove_scratch_file (path);
}

static void
test_native_lock_domain_alias_reader_writer_contention (void)
{
  gchar *path = NULL;
  HANDLE pin = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (pin);
  WylFactGraphWinIdentity directory_identity = identity;
  WylFactArtifactWinLockDomain *domain = NULL;
  WylFactArtifactWinLockDomain *alias_domain = NULL;
  WylFactArtifactWinLockLease *reader_a = NULL;
  WylFactArtifactWinLockLease *reader_b = NULL;
  WylFactArtifactWinLockLease *writer = (gpointer) 0x1;
  HANDLE alias_pin = open_existing_scratch_file (path);
  HANDLE reader_a_handle = open_existing_scratch_file (path);
  HANDLE reader_b_handle = open_existing_scratch_file (path);
  HANDLE writer_handle = open_existing_scratch_file (path);

  /* The key is the graph-directory tuple, not a spelling of its path.  Use a
   * distinct fixture key so parallel tests cannot accidentally join. */
  directory_identity.file_id[0] ^= 0x80;
  g_assert_cmpint (wyl_fact_artifact_win_lock_domain_open (&directory_identity,
      &identity, pin, &domain), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lock_domain_open (&directory_identity,
      &identity, alias_pin, &alias_domain), ==, WYRELOG_E_OK);
  g_assert_true (domain == alias_domain);
  g_assert_cmpint (wyl_fact_artifact_win_lock_domain_acquire (domain,
      reader_a_handle, FALSE, &reader_a), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lock_domain_acquire (alias_domain,
      reader_b_handle, FALSE, &reader_b), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lock_domain_acquire (domain,
      writer_handle, TRUE, &writer), ==, WYRELOG_E_BUSY);
  g_assert_null (writer);
  g_assert_true (CloseHandle (writer_handle));
  wyl_fact_artifact_win_lock_lease_free (reader_a);
  wyl_fact_artifact_win_lock_lease_free (reader_b);
  writer_handle = open_existing_scratch_file (path);
  g_assert_cmpint (wyl_fact_artifact_win_lock_domain_acquire (alias_domain,
      writer_handle, TRUE, &writer), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lock_lease_revalidate (writer), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_win_lock_lease_free (writer);
  wyl_fact_artifact_win_lock_domain_free (alias_domain);
  wyl_fact_artifact_win_lock_domain_free (domain);
  remove_scratch_file (path);
}

typedef struct
{
  WylFactArtifactWinLockDomain *domain;
  const gchar *path;
  gint failure;
} LockStress;

static gpointer
lock_stress_worker (gpointer user_data)
{
  LockStress *stress = user_data;

  for (guint i = 0; i < 200; i++) {
    HANDLE handle = open_existing_scratch_file (stress->path);
    WylFactArtifactWinLockLease *lease = NULL;
    wyrelog_error_t rc =
        wyl_fact_artifact_win_lock_domain_acquire (stress->domain, handle,
            FALSE, &lease);

    if (rc == WYRELOG_E_OK)
      wyl_fact_artifact_win_lock_lease_free (lease);
    else {
      /* Failed acquire retains caller ownership by contract. */
      CloseHandle (handle);
      g_atomic_int_set (&stress->failure, 1);
      break;
    }
  }
  return NULL;
}

static void
test_native_lock_domain_concurrent_acquire_release (void)
{
  gchar *path = NULL;
  HANDLE pin = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (pin);
  WylFactGraphWinIdentity directory_identity = identity;
  WylFactArtifactWinLockDomain *domain = NULL;
  LockStress stress = { 0 };
  GThread *workers[6] = { 0 };

  directory_identity.file_id[0] ^= 0x40;
  g_assert_cmpint (wyl_fact_artifact_win_lock_domain_open (&directory_identity,
      &identity, pin, &domain), ==, WYRELOG_E_OK);
  stress.domain = domain;
  stress.path = path;
  for (guint i = 0; i < G_N_ELEMENTS (workers); i++)
    workers[i] = g_thread_new ("native-lock-stress", lock_stress_worker,
            &stress);
  for (guint i = 0; i < G_N_ELEMENTS (workers); i++)
    g_thread_join (workers[i]);
  g_assert_cmpint (g_atomic_int_get (&stress.failure), ==, 0);
  wyl_fact_artifact_win_lock_domain_free (domain);
  remove_scratch_file (path);
}

static void
test_native_namespace_main_sidecar_lifecycle (void)
{
  gchar *path = NULL;
  HANDLE graph = open_scratch_directory (&path);
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactArtifactWinLocator *locator = NULL;
  WylFactGraphWinIdentity graph_identity = { 0 };
  WylFactArtifactWinEntry *main_entry = NULL;
  WylFactGraphRegularFile main_file = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  WylFactArtifactWinNamespace *namespace_ = NULL;
  WylFactArtifactWinLease *lease = NULL;
  WylFactArtifactWinMainBinding *main_binding = NULL;
  WylFactArtifactWinSidecarBinding *sidecar = NULL;
  WylFactArtifactWinTempBinding *replacement_source = NULL;
  WylFactArtifactWinTempRoot *temp_root = NULL;
  WylFactArtifactWinTempChild *temp_child = NULL;
  WylFactArtifactWinTempChildBinding *temp_binding = NULL;
  WylFactArtifactWinTempToken *temp_token = NULL;
  WylFactArtifactWinTempRecoveryEvidence *temp_evidence = NULL;
  WylFactArtifactWinIoSession *session = NULL;
  GBytes *temp_evidence_bytes = NULL;
  GBytes *mismatched_temp_evidence_bytes = NULL;
  HANDLE main_handle = INVALID_HANDLE_VALUE;
  WylFactArtifactWinMutationEffect effect =
      WYL_FACT_ARTIFACT_WIN_MUTATION_UNKNOWN;
  WylFactArtifactSidecarRetireResult retire =
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED;
  WylFactArtifactWinSidecarReplaceResult replace_result =
      WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_NOT_REPLACED;
  WylFactDuckdbTempRetireResult temp_retire =
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED;
  gsize written = 0;
  g_autofree wchar_t *main_wide = NULL;
  g_autofree wchar_t *lock_wide = NULL;
  g_autofree wchar_t *checkpoint_wide = NULL;
  g_autofree wchar_t *directory_wide = NULL;
  g_autofree wchar_t *old_lock_wide = NULL;
  g_autofree gchar *main_path = NULL;
  g_autofree gchar *lock_path = NULL;
  g_autofree gchar *old_lock_path = NULL;
  g_autofree gchar *checkpoint_path = NULL;

  directory.graph_handle = graph;
  directory.graph_identity = identity_for (graph);
  locator = open_locator_for_test (graph, &graph_identity);
  g_assert_cmpint (wyl_fact_artifact_win_locator_open (locator, "facts.duckdb",
      GENERIC_READ | GENERIC_WRITE, TRUE, &main_entry), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_entry_issue_working_handle (locator,
      main_entry, &main_handle), ==, WYRELOG_E_OK);
  main_file.handle = main_handle;
  main_file.identity = *wyl_fact_artifact_win_entry_identity (main_entry);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_new_with_main (&directory,
      &main_file, &namespace_), ==, WYRELOG_E_OK);
  /* Import does not consume #615's caller-held authority. */
  g_assert_true (CloseHandle (main_handle));
  main_file.handle = NULL;
  wyl_fact_artifact_win_entry_free (main_entry);
  main_entry = NULL;
  wyl_fact_artifact_win_locator_free (locator);
  locator = NULL;

  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (namespace_,
      &lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_main (lease, &main_binding),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_main_binding_open_io_session
        (main_binding, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_win_main_binding_free (main_binding);
  main_binding = NULL;

  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
        (sidecar, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  /* Checked close consumes only working I/O; the exact lifecycle authority
   * remains available for the one publication and later retirement. */
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_publish_no_replace
        (sidecar, WYL_FACT_ARTIFACT_CHECKPOINT, &effect), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_retire (sidecar,
      &retire), ==, WYRELOG_E_OK);
  g_assert_cmpint (retire, ==, WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RETIRED);
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  sidecar = NULL;

  /* #609 replacement consumes only an owner staging binding and an existing
   * closed destination.  A live destination working HANDLE is a hard barrier;
   * after replacement the source is terminal and the destination owns
   * the source identity for its later lifecycle operation. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
        (sidecar, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_write (session, 0, "old",
      3, &written), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_create_temp_binding (lease,
      "replace-sidecar", &replacement_source), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_binding_open_io_session
        (replacement_source, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_write (session, 0, "new",
      3, &written), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  replace_result = WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_REPLACED;
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
        (sidecar, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_binding_replace_sidecar
        (replacement_source, sidecar, &replace_result), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (replace_result, ==,
      WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_NOT_REPLACED);
  {
    /* A live destination session is a barrier taken before any mutation, not
     * a rename that was attempted and refused.  The reported code alone
     * cannot tell those apart, so observe the namespace: the staging name is
     * still occupied and the destination name still resolves to the
     * superseded content. */
    g_autofree gchar *staged_path = g_build_filename (path,
            "tmp-replace-sidecar", NULL);
    g_autofree wchar_t *staged_wide = g_utf8_to_utf16 (staged_path, -1, NULL,
            NULL, NULL);
    g_autofree gchar *published_path = g_build_filename (path,
            "facts.duckdb.wal", NULL);
    gchar rejected_readback[4] = { 0 };

    g_assert_true (GetFileAttributesW (staged_wide) != INVALID_FILE_ATTRIBUTES);
    read_named_file_prefix (published_path, rejected_readback, 3);
    g_assert_cmpstr (rejected_readback, ==, "old");
  }
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_binding_replace_sidecar
        (replacement_source, sidecar, &replace_result), ==, WYRELOG_E_OK);
  g_assert_cmpint (replace_result, ==,
      WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_REPLACED);
  {
    gchar replacement_readback[4] = { 0 };
    gsize replacement_read = 0;
    g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
          (sidecar, &session), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_win_io_session_read (session, 0,
        replacement_readback, 3, &replacement_read), ==, WYRELOG_E_OK);
    g_assert_cmpuint (replacement_read, ==, 3);
    g_assert_cmpstr (replacement_readback, ==, "new");
    g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
        WYRELOG_E_OK);
    session = NULL;
  }
  g_assert_cmpint (wyl_fact_artifact_win_temp_binding_open_io_session
        (replacement_source, &session), ==, WYRELOG_E_POLICY);
  g_assert_null (session);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_retire (sidecar,
      &retire), ==, WYRELOG_E_OK);
  g_assert_cmpint (retire, ==, WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RETIRED);
  wyl_fact_artifact_win_temp_binding_free (replacement_source);
  replacement_source = NULL;
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  sidecar = NULL;

  /* Abort is terminal before mutation; no external numeric HANDLE is part of
   * the artifact API. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease, WYL_FACT_ARTIFACT_RECOVERY, TRUE, TRUE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
        (sidecar, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_create_temp_binding (lease,
      "raw-replace", &replacement_source), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_binding_open_io_session
        (replacement_source, &session), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_io_session_abort (session);
  session = NULL;
  replace_result = WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_REPLACED;
  g_assert_cmpint (wyl_fact_artifact_win_temp_binding_replace_sidecar
        (replacement_source, sidecar, &replace_result), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (replace_result, ==,
      WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_NOT_REPLACED);
  wyl_fact_artifact_win_temp_binding_free (replacement_source);
  replacement_source = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_retire (sidecar,
      &retire), ==, WYRELOG_E_OK);
  g_assert_cmpint (retire, ==, WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RETIRED);
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_autofree gchar *raw_replace_path = g_build_filename (path,
          "tmp-raw-replace", NULL);
  g_autofree wchar_t *raw_replace_wide = g_utf8_to_utf16 (raw_replace_path,
          -1, NULL, NULL, NULL);
  g_assert_true (DeleteFileW (raw_replace_wide));

  /* Native Windows replacement has no target-FileId CAS.  The exclusive
   * lease serializes sanctioned writers, while a deterministic substitution
   * immediately before the final destination revalidation proves that the
   * sanctioned path fails closed without moving its source.  The substitute
   * genuinely takes the destination name -- its FileId is observable there
   * afterwards -- so this proves the sanctioned path lost a destination it
   * had already validated, not merely that two names still exist. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease, WYL_FACT_ARTIFACT_CHECKPOINT, TRUE, TRUE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
        (sidecar, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_create_temp_binding (lease,
      "pre-final", &replacement_source), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_binding_open_io_session
        (replacement_source, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  g_autofree gchar *pre_source_path = g_build_filename (path, "tmp-pre-final",
          NULL);
  g_autofree gchar *pre_destination_path = g_build_filename (path,
          "facts.duckdb.wal.checkpoint", NULL);
  WylFactGraphWinIdentity validated_destination =
      identity_for_path (pre_destination_path);
  wyl_fact_artifact_win_namespace_set_test_fault
    (WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_REPLACE_PRE_FINAL_DESTINATION_SUBSTITUTE);
  g_assert_cmpint (wyl_fact_artifact_win_temp_binding_replace_sidecar
        (replacement_source, sidecar, &replace_result), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (replace_result, ==,
      WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_NOT_REPLACED);
  {
    WylFactGraphWinIdentity substituted =
        identity_for_path (pre_destination_path);

    g_assert_false (identity_matches (&validated_destination, &substituted));
  }
  g_autofree wchar_t *pre_source_wide = g_utf8_to_utf16 (pre_source_path, -1,
          NULL, NULL, NULL);
  g_autofree wchar_t *pre_destination_wide = g_utf8_to_utf16
        (pre_destination_path, -1, NULL, NULL, NULL);
  g_assert_true (GetFileAttributesW (pre_source_wide) !=
      INVALID_FILE_ATTRIBUTES);
  g_assert_true (GetFileAttributesW (pre_destination_wide) !=
      INVALID_FILE_ATTRIBUTES);
  wyl_fact_artifact_win_temp_binding_free (replacement_source);
  replacement_source = NULL;
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_assert_true (DeleteFileW (pre_source_wide));
  g_assert_true (DeleteFileW (pre_destination_wide));

  /* Once rename linearizes, a later durability/reporting uncertainty is
  * terminal reconciliation evidence rather than a retryable failure. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease, WYL_FACT_ARTIFACT_RECOVERY, TRUE, TRUE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
        (sidecar, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_create_temp_binding (lease,
      "post-rename", &replacement_source), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_binding_open_io_session
        (replacement_source, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_win_namespace_set_test_fault
    (WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_REPLACE_POST_RENAME_UNCERTAIN);
  g_assert_cmpint (wyl_fact_artifact_win_temp_binding_replace_sidecar
        (replacement_source, sidecar, &replace_result), ==, WYRELOG_E_IO);
  g_assert_cmpint (replace_result, ==,
      WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_RECONCILE_REQUIRED);
  g_autofree gchar *post_source_path = g_build_filename (path,
          "tmp-post-rename", NULL);
  g_autofree gchar *post_destination_path = g_build_filename (path,
          "facts.duckdb.wal.recovery", NULL);
  g_autofree wchar_t *post_source_wide = g_utf8_to_utf16 (post_source_path,
          -1, NULL, NULL, NULL);
  g_autofree wchar_t *post_destination_wide = g_utf8_to_utf16
        (post_destination_path, -1, NULL, NULL, NULL);
  g_assert_false (GetFileAttributesW (post_source_wide) !=
      INVALID_FILE_ATTRIBUTES);
  g_assert_true (GetFileAttributesW (post_destination_wide) !=
      INVALID_FILE_ATTRIBUTES);
  wyl_fact_artifact_win_temp_binding_free (replacement_source);
  replacement_source = NULL;
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_assert_true (DeleteFileW (post_destination_wide));

  /* Native spill roots are lease-bound virtual authorities: child I/O must
   * be closed through its binding before either child or root can retire. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_create_temp_root (lease,
      &temp_root), ==, WYRELOG_E_OK);
  g_autofree gchar *temp_logical =
      wyl_fact_artifact_win_temp_root_dup_logical_name (temp_root);
  g_assert_nonnull (temp_logical);
  g_assert_true (g_str_has_prefix (temp_logical, "/wyrelog-duckdb-temp/"));
  g_assert_cmpint (wyl_fact_artifact_win_temp_root_create_child (temp_root,
      "duckdb_temp_storage_DEFAULT-1.tmp", &temp_child), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_open (temp_child, TRUE, &temp_binding), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_binding_open_io_session
        (temp_binding, &session), ==, WYRELOG_E_OK);
  WylFactArtifactWinIoSession *second_child_session = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_binding_open_io_session
        (temp_binding, &second_child_session), ==, WYRELOG_E_BUSY);
  g_assert_null (second_child_session);
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_retire (temp_child,
      &temp_retire), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (temp_retire, ==,
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_retire (temp_child,
      &temp_retire), ==, WYRELOG_E_OK);
  g_assert_cmpint (temp_retire, ==, WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED);
  wyl_fact_artifact_win_temp_child_free (temp_child);
  temp_child = NULL;
  wyl_fact_artifact_win_temp_child_binding_free (temp_binding);
  temp_binding = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_temp_root_retire (temp_root,
      &temp_retire), ==, WYRELOG_E_OK);
  g_assert_cmpint (temp_retire, ==, WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED);
  wyl_fact_artifact_win_temp_root_free (temp_root);
  temp_root = NULL;

  /* Adversarial lifecycle: no arbitrary child spelling is accepted and a
   * live opaque session prevents root retirement. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_create_temp_root (lease,
      &temp_root), ==, WYRELOG_E_OK);
  g_autofree gchar *raw_logical =
      wyl_fact_artifact_win_temp_root_dup_logical_name (temp_root);
  g_assert_cmpint (wyl_fact_artifact_win_temp_root_create_child (temp_root,
      "../outside", &temp_child), ==, WYRELOG_E_INVALID);
  g_assert_null (temp_child);
  g_assert_cmpint (wyl_fact_artifact_win_temp_root_create_child (temp_root,
      "duckdb_temp_block-1.block", &temp_child), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_open (temp_child, TRUE, &temp_binding), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_root_retire (temp_root,
      &temp_retire), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (temp_retire, ==,
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED);
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_binding_open_io_session
        (temp_binding, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_retire (temp_child,
      &temp_retire), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (temp_retire, ==,
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED);
  wyl_fact_artifact_win_io_session_abort (session);
  session = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_retire (temp_child,
      &temp_retire), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (temp_retire, ==,
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED);
  wyl_fact_artifact_win_temp_child_binding_free (temp_binding);
  temp_binding = NULL;
  g_autofree gchar *raw_root_name = g_strdup (raw_logical
          + strlen ("/wyrelog-duckdb-temp/"));
  g_autofree gchar *raw_root_path = g_build_filename (path, raw_root_name,
          NULL);
  g_autofree gchar *raw_child_path = g_build_filename (raw_root_path,
          "duckdb_temp_block-1.block", NULL);
  g_autofree wchar_t *raw_root_wide = g_utf8_to_utf16 (raw_root_path, -1,
          NULL, NULL, NULL);
  g_autofree wchar_t *raw_child_wide = g_utf8_to_utf16 (raw_child_path, -1,
          NULL, NULL, NULL);
  wyl_fact_artifact_win_temp_child_free (temp_child);
  temp_child = NULL;
  wyl_fact_artifact_win_temp_root_free (temp_root);
  temp_root = NULL;
  /* An aborted session is terminal authority; only external test cleanup
   * removes the untouched child. */
  g_assert_true (DeleteFileW (raw_child_wide));
  g_assert_true (RemoveDirectoryW (raw_root_wide));

  /* #608-equivalent native temp-token lifecycle has no path or CRT-fd
   * escape.  A closed owner may move no-replace, export identity evidence,
   * and be recovered idempotently only through a matching exclusive lease. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_create_temp_token (lease,
      "token-old", &temp_token), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_token_open_io_session (temp_token,
      &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_token_rename_no_replace
        (temp_token, "token-next", &effect), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_token_rename_no_replace
        (temp_token, "token-next", &effect), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED);
  /* Unlike unlink, APPLIED rename preserves the same owner authority under
   * its new closed token spelling. */
  g_assert_cmpint (wyl_fact_artifact_win_temp_token_export_recovery_evidence
        (temp_token, &temp_evidence), ==, WYRELOG_E_OK);
  g_assert_nonnull (temp_evidence);
  g_assert_cmpint (wyl_fact_artifact_win_temp_recovery_evidence_encode
        (temp_evidence, &temp_evidence_bytes), ==, WYRELOG_E_OK);
  g_assert_nonnull (temp_evidence_bytes);
  /* Simulate process loss: only durable bytes and the artifact remain.
   * Reacquiring the native lease must prove directory + lock + FileId before
   * it can clean up the abandoned token. */
  wyl_fact_artifact_win_temp_recovery_evidence_free (temp_evidence);
  temp_evidence = NULL;
  wyl_fact_artifact_win_temp_token_free (temp_token);
  temp_token = NULL;
  wyl_fact_artifact_win_lease_free (lease);
  lease = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation
        (namespace_, &lease), ==, WYRELOG_E_OK);
  /* A record from a different graph namespace is likewise not authority in
   * this lease, even when its token spelling happens to collide. */
  {
    gsize evidence_size = 0;
    const guint8 *evidence_data = g_bytes_get_data (temp_evidence_bytes,
            &evidence_size);
    guint8 *mismatch = g_memdup2 (evidence_data, evidence_size);
    mismatch[5] ^= 0x01;        /* serialized graph-directory FileId volume */
    mismatched_temp_evidence_bytes = g_bytes_new_take (mismatch, evidence_size);
  }
  g_assert_cmpint (wyl_fact_artifact_win_temp_recovery_evidence_decode
        (mismatched_temp_evidence_bytes, &temp_evidence), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_recover_temp_token (lease,
      temp_evidence, &effect), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED);
  wyl_fact_artifact_win_temp_recovery_evidence_free (temp_evidence);
  temp_evidence = NULL;
  g_bytes_unref (mismatched_temp_evidence_bytes);
  mismatched_temp_evidence_bytes = NULL;
  /* A durable record from another lock/domain cannot be replayed into this
   * otherwise valid lease; it must fail before touching the named artifact. */
  {
    gsize evidence_size = 0;
    const guint8 *evidence_data = g_bytes_get_data (temp_evidence_bytes,
            &evidence_size);
    guint8 *mismatch = g_memdup2 (evidence_data, evidence_size);
    mismatch[29] ^= 0x01;       /* serialized lock FileId volume byte */
    mismatched_temp_evidence_bytes = g_bytes_new_take (mismatch, evidence_size);
  }
  g_assert_cmpint (wyl_fact_artifact_win_temp_recovery_evidence_decode
        (mismatched_temp_evidence_bytes, &temp_evidence), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_recover_temp_token (lease,
      temp_evidence, &effect), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED);
  wyl_fact_artifact_win_temp_recovery_evidence_free (temp_evidence);
  temp_evidence = NULL;
  g_bytes_unref (mismatched_temp_evidence_bytes);
  mismatched_temp_evidence_bytes = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_temp_recovery_evidence_decode
        (temp_evidence_bytes, &temp_evidence), ==, WYRELOG_E_OK);
  g_bytes_unref (temp_evidence_bytes);
  temp_evidence_bytes = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_lease_recover_temp_token (lease,
      temp_evidence, &effect), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED);
  /* The same immutable evidence is safe after an already-applied recovery. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_recover_temp_token (lease,
      temp_evidence, &effect), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED);
  wyl_fact_artifact_win_temp_recovery_evidence_free (temp_evidence);
  temp_evidence = NULL;
  /* Abort terminally revokes the owner before unlink. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_create_temp_token (lease,
      "token-raw", &temp_token), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_token_open_io_session (temp_token,
      &session), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_io_session_abort (session);
  session = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_temp_token_unlink (temp_token,
      &effect), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED);
  wyl_fact_artifact_win_temp_token_free (temp_token);
  temp_token = NULL;
  g_autofree gchar *raw_token_path = g_build_filename (path, "tmp-token-raw",
          NULL);
  g_autofree wchar_t *raw_token_wide = g_utf8_to_utf16 (raw_token_path, -1,
          NULL, NULL, NULL);
  g_assert_true (DeleteFileW (raw_token_wide));
  wyl_fact_artifact_win_lease_free (lease);
  lease = NULL;

  /* An exclusive lease is not authority over a renamed/replaced coordination
   * name.  Both main issuance and sidecar creation fail closed and the
   * replacement is left untouched. */
  main_path = g_build_filename (path, "facts.duckdb", NULL);
  lock_path = g_build_filename (path, "facts.duckdb.lock", NULL);
  old_lock_path = g_build_filename (path, "facts.duckdb.lock.old", NULL);
  lock_wide = g_utf8_to_utf16 (lock_path, -1, NULL, NULL, NULL);
  old_lock_wide = g_utf8_to_utf16 (old_lock_path, -1, NULL, NULL, NULL);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (namespace_,
      &lease), ==, WYRELOG_E_OK);
  g_assert_true (MoveFileExW (lock_wide, old_lock_wide,
      MOVEFILE_WRITE_THROUGH));
  HANDLE replacement = CreateFileW (lock_wide, GENERIC_READ | GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_NEW,
          FILE_ATTRIBUTE_NORMAL, NULL);
  g_assert_true (replacement != INVALID_HANDLE_VALUE);
  g_assert_true (CloseHandle (replacement));
  main_binding = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_main (lease, &main_binding),
      ==, WYRELOG_E_POLICY);
  g_assert_null (main_binding);
  sidecar = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &sidecar), ==, WYRELOG_E_POLICY);
  g_assert_null (sidecar);
  g_assert_true (GetFileAttributesW (lock_wide) != INVALID_FILE_ATTRIBUTES);
  wyl_fact_artifact_win_lease_free (lease);
  lease = NULL;
  wyl_fact_artifact_win_namespace_free (namespace_);
  namespace_ = NULL;

  checkpoint_path =
      g_build_filename (path, "facts.duckdb.wal.checkpoint", NULL);
  main_wide = g_utf8_to_utf16 (main_path, -1, NULL, NULL, NULL);
  lock_wide = g_utf8_to_utf16 (lock_path, -1, NULL, NULL, NULL);
  checkpoint_wide = g_utf8_to_utf16 (checkpoint_path, -1, NULL, NULL, NULL);
  g_assert_false (GetFileAttributesW (checkpoint_wide) !=
      INVALID_FILE_ATTRIBUTES);
  g_assert_true (DeleteFileW (main_wide));
  g_assert_true (DeleteFileW (lock_wide));
  g_assert_true (DeleteFileW (old_lock_wide));
  directory_wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_true (CloseHandle (graph));
  g_assert_true (RemoveDirectoryW (directory_wide));
  g_free (path);
}

/* Both native Windows artifact modules keep their forced-fault state in a
 * process-wide global that is consumed only when the faulted step is actually
 * reached.  A case that arms one and returns without reaching that step
 * leaves it armed for every later case in the same binary, and both faults
 * surface as WYRELOG_E_POLICY -- the very code a genuine authority violation
 * returns -- so the leak presents as an unrelated later case failing a policy
 * assertion.  Every case therefore runs inside this fixture: set_up disarms
 * both globals before the body, and tear_down disarms them again and requires
 * what it found to match the row's declared expectation.
 *
 * The guarantee is a clean-run property only.  A case that aborts never
 * reaches its tear_down, so a passing run proves nothing about a failing
 * one. */
typedef struct
{
  /* The guard holds no per-case state.  g_test_add passes the same row to
   * set_up, the body and tear_down, so tear_down already has everything it
   * needs from its own |user_data| argument and a member here would only
   * duplicate it.  C17 has no empty struct, so this placeholder exists to
   * make the type legal and is never read. */
  gchar unused;
} WinFaultGuard;

typedef struct
{
  const gchar *path;
  void (*run) (void);
  /* What the body is permitted to leave armed. */
  DWORD expected_flush_error;
  WylFactArtifactWinNamespaceTestFault expected_namespace_fault;
} WinGuardedCase;

static void
win_fault_guard_set_up (WinFaultGuard *guard, gconstpointer user_data)
{
  DWORD flush_error =
      wyl_fact_artifact_win_locator_take_next_directory_flush_error_for_test ();
  WylFactArtifactWinNamespaceTestFault fault =
      wyl_fact_artifact_win_namespace_take_test_fault ();

  (void) guard;
  (void) user_data;
  /* Unreachable while every case goes through this fixture: a case that runs
   * set_up also runs tear_down unless the process aborts, and no later case
   * runs after an abort.  Its real value is as the only defence against a
   * future case registered with g_test_add_func, which bypasses the fixture
   * entirely and would silently stop being guarded. */
  g_assert_cmpuint (flush_error, ==, ERROR_SUCCESS);
  g_assert_cmpint (fault, ==, WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_NONE);
}

static void
win_fault_guard_run (WinFaultGuard *guard, gconstpointer user_data)
{
  const WinGuardedCase *guarded = user_data;

  (void) guard;
  guarded->run ();
}

static void
win_fault_guard_tear_down (WinFaultGuard *guard, gconstpointer user_data)
{
  const WinGuardedCase *guarded = user_data;
  DWORD flush_error =
      wyl_fact_artifact_win_locator_take_next_directory_flush_error_for_test ();
  WylFactArtifactWinNamespaceTestFault fault =
      wyl_fact_artifact_win_namespace_take_test_fault ();

  (void) guard;
  /* Both globals are already disarmed by the takes above, so the process is
   * clean here and every later case is safe to run.  Fail only this case
   * rather than aborting the binary: with g_error one leaking case would
   * decide whether the remaining cases ever report at all, which is the same
   * ordering-dependent blast radius this fixture exists to remove, just moved
   * up a level.  g_test_fail is effective from teardown because test_case_run
   * reads its success flag after fixture_teardown returns. */
  if (flush_error != guarded->expected_flush_error
      || fault != guarded->expected_namespace_fault) {
    g_test_message ("%s left an unexpected Windows artifact test fault armed: "
        "flush=%lu want %lu, namespace=%d want %d", guarded->path,
        (gulong) flush_error, (gulong) guarded->expected_flush_error,
        (gint) fault, (gint) guarded->expected_namespace_fault);
    g_test_fail ();
  }
}

G_STATIC_ASSERT (ERROR_SUCCESS == 0
    && WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_NONE == 0);

static void
test_io_session_query_metadata_and_revalidate (void)
{
  g_autofree gchar *path = NULL;
  HANDLE graph = open_scratch_directory (&path);
  WylFactGraphWinIdentity identity_unused = { 0 };
  WylFactArtifactWinLocator *locator = open_locator_for_test (graph, &identity_unused);
  WylFactArtifactWinEntry *main_entry = NULL;
  WylFactArtifactWinEntry *lock_entry = NULL;
  WylFactArtifactWinNamespace *ns = NULL;
  WylFactArtifactWinLease *lease = NULL;
  WylFactArtifactWinSidecarBinding *binding = NULL;
  WylFactArtifactWinIoSession *session = NULL;
  guint64 size = 999, sec = 999;
  guint32 nsec = 999;
  WylFactGraphWinIdentity identity = { 0 };

  g_assert_cmpint (wyl_fact_artifact_win_locator_open (locator, "facts.duckdb", GENERIC_READ | GENERIC_WRITE | DELETE, TRUE, &main_entry), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_locator_open (locator, "facts.duckdb.lock", GENERIC_READ | GENERIC_WRITE | DELETE, TRUE, &lock_entry), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_adopt_entries_for_test (locator, main_entry, lock_entry, &ns), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (ns, &lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &binding), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session (binding, &session), ==, WYRELOG_E_OK);

  /* Revalidate nullary export test */
  g_assert_cmpint (wyl_fact_artifact_win_io_session_revalidate (session), ==, WYRELOG_E_OK);

  /* Write test data */
  const gchar test_payload[] = "metadata-test-payload";
  gsize written = 0;
  g_assert_cmpint (wyl_fact_artifact_win_io_session_write (session, 0, test_payload, strlen (test_payload), &written), ==, WYRELOG_E_OK);

  /* Query metadata */
  g_assert_cmpint (wyl_fact_artifact_win_io_session_query_metadata (session, &size, &sec, &nsec, &identity), ==, WYRELOG_E_OK);
  g_assert_cmpuint (size, ==, strlen (test_payload));
  g_assert_cmpuint (sec, >, 0);
  g_assert_cmpuint (identity.volume_serial, >, 0);

  /* Failure path initializes out parameters */
  wyl_fact_artifact_win_io_session_abort (session);
  size = 999; sec = 999; nsec = 999;
  memset (&identity, 0xFF, sizeof (identity));
  g_assert_cmpint (wyl_fact_artifact_win_io_session_query_metadata (session, &size, &sec, &nsec, &identity), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (size, ==, 0);
  g_assert_cmpuint (sec, ==, 0);
  g_assert_cmpuint (nsec, ==, 0);
  g_assert_cmpuint (identity.volume_serial, ==, 0);

  wyl_fact_artifact_win_sidecar_binding_free (binding);
  wyl_fact_artifact_win_lease_free (lease);
  wyl_fact_artifact_win_namespace_free (ns);
  CloseHandle (graph);
}

static void
test_temp_root_spill_child_capabilities (void)
{
  g_autofree gchar *path = NULL;
  HANDLE graph = open_scratch_directory (&path);
  WylFactGraphWinIdentity identity_unused = { 0 };
  WylFactArtifactWinLocator *locator = open_locator_for_test (graph, &identity_unused);
  WylFactArtifactWinEntry *main_entry = NULL;
  WylFactArtifactWinEntry *lock_entry = NULL;
  WylFactArtifactWinNamespace *ns = NULL;
  WylFactArtifactWinLease *lease = NULL;
  WylFactArtifactWinTempRoot *root = NULL;
  WylFactArtifactWinTempChildBinding *binding = NULL;
  WylFactArtifactWinTempOrphanEvidence *root_evidence = NULL;
  WylFactArtifactWinTempOrphanEvidence *child_evidence = NULL;
  gboolean exists = FALSE;
  GPtrArray *children = NULL;

  g_assert_cmpint (wyl_fact_artifact_win_locator_open (locator, "facts.duckdb", GENERIC_READ | GENERIC_WRITE | DELETE, TRUE, &main_entry), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_locator_open (locator, "facts.duckdb.lock", GENERIC_READ | GENERIC_WRITE | DELETE, TRUE, &lock_entry), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_adopt_entries_for_test (locator, main_entry, lock_entry, &ns), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (ns, &lease), ==, WYRELOG_E_OK);

  /* Create temp root with orphan evidence */
  g_assert_cmpint (wyl_fact_artifact_win_temp_root_create_with_orphan_evidence (lease, &root, &root_evidence), ==, WYRELOG_E_OK);
  g_assert_nonnull (root_evidence);
  GBytes *root_bytes = wyl_fact_artifact_win_temp_orphan_evidence_bytes (root_evidence);
  g_assert_nonnull (root_bytes);
  g_bytes_unref (root_bytes);
  wyl_fact_artifact_win_temp_orphan_evidence_free (root_evidence);

  /* Check non-existent child */
  g_assert_cmpint (wyl_fact_artifact_win_temp_root_child_exists (root, "duckdb_temp_storage_S32K-1.tmp", &exists), ==, WYRELOG_E_OK);
  g_assert_false (exists);

  /* Atomic create-and-bind with orphan evidence */
  g_assert_cmpint (wyl_fact_artifact_win_temp_root_create_child_with_orphan_evidence (root, "duckdb_temp_storage_S32K-1.tmp", TRUE, &binding, &child_evidence), ==, WYRELOG_E_OK);
  g_assert_nonnull (binding);
  g_assert_nonnull (child_evidence);
  GBytes *child_bytes = wyl_fact_artifact_win_temp_orphan_evidence_bytes (child_evidence);
  g_assert_nonnull (child_bytes);
  g_bytes_unref (child_bytes);
  wyl_fact_artifact_win_temp_orphan_evidence_free (child_evidence);

  /* Check existing child */
  g_assert_cmpint (wyl_fact_artifact_win_temp_root_child_exists (root, "duckdb_temp_storage_S32K-1.tmp", &exists), ==, WYRELOG_E_OK);
  g_assert_true (exists);

  /* Snapshot children */
  g_assert_cmpint (wyl_fact_artifact_win_temp_root_snapshot_children (root, &children), ==, WYRELOG_E_OK);
  g_assert_nonnull (children);
  g_assert_cmpuint (children->len, ==, 1);
  g_assert_cmpstr (g_ptr_array_index (children, 0), ==, "duckdb_temp_storage_S32K-1.tmp");
  g_ptr_array_free (children, TRUE);

  wyl_fact_artifact_win_temp_child_binding_free (binding);
  wyl_fact_artifact_win_temp_root_free (root);
  wyl_fact_artifact_win_lease_free (lease);
  wyl_fact_artifact_win_namespace_free (ns);
  CloseHandle (graph);
}

static void
test_io_session_read_only_access_intent (void)
{
  g_autofree gchar *path = NULL;
  HANDLE graph = open_scratch_directory (&path);
  WylFactGraphWinIdentity identity_unused = { 0 };
  WylFactArtifactWinLocator *locator = open_locator_for_test (graph, &identity_unused);
  WylFactArtifactWinEntry *main_entry = NULL;
  WylFactArtifactWinEntry *lock_entry = NULL;
  WylFactArtifactWinNamespace *ns = NULL;
  WylFactArtifactWinLease *lease = NULL;
  WylFactArtifactWinSidecarBinding *write_binding = NULL;
  WylFactArtifactWinSidecarBinding *read_binding = NULL;
  WylFactArtifactWinIoSession *write_session = NULL;
  WylFactArtifactWinIoSession *read_session = NULL;

  g_assert_cmpint (wyl_fact_artifact_win_locator_open (locator, "facts.duckdb", GENERIC_READ | GENERIC_WRITE | DELETE, TRUE, &main_entry), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_locator_open (locator, "facts.duckdb.lock", GENERIC_READ | GENERIC_WRITE | DELETE, TRUE, &lock_entry), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_adopt_entries_for_test (locator, main_entry, lock_entry, &ns), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (ns, &lease), ==, WYRELOG_E_OK);

  /* Open write sidecar */
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &write_binding), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session (write_binding, &write_session), ==, WYRELOG_E_OK);
  gsize written = 0;
  g_assert_cmpint (wyl_fact_artifact_win_io_session_write (write_session, 0, "hello", 5, &written), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_io_session_finish (write_session);
  wyl_fact_artifact_win_sidecar_binding_free (write_binding);

  /* Open read-only sidecar */
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease, WYL_FACT_ARTIFACT_WAL, FALSE, FALSE, &read_binding), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session (read_binding, &read_session), ==, WYRELOG_E_OK);

  /* Read succeeds */
  gchar buf[10] = { 0 };
  gsize read_bytes = 0;
  g_assert_cmpint (wyl_fact_artifact_win_io_session_read (read_session, 0, buf, 5, &read_bytes), ==, WYRELOG_E_OK);
  g_assert_cmpuint (read_bytes, ==, 5);
  g_assert_cmpstr (buf, ==, "hello");

  /* Write and truncate fail with POLICY */
  g_assert_cmpint (wyl_fact_artifact_win_io_session_write (read_session, 0, "world", 5, &written), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_truncate (read_session, 0), ==, WYRELOG_E_POLICY);

  wyl_fact_artifact_win_io_session_finish (read_session);
  wyl_fact_artifact_win_sidecar_binding_free (read_binding);
  wyl_fact_artifact_win_lease_free (lease);
  wyl_fact_artifact_win_namespace_free (ns);
  CloseHandle (graph);
}

/* A row that must leave nothing armed omits both expectation fields; the
 * assertion above pins the two clean values to the zero that the omitted
 * initializers supply. */
static void
remove_tree_for_test (const gchar *path)
{
  g_autoptr (GDir) dir = g_dir_open (path, 0, NULL);
  if (dir != NULL) {
    const gchar *name;
    while ((name = g_dir_read_name (dir)) != NULL) {
      g_autofree gchar *child = g_build_filename (path, name, NULL);
      if (g_file_test (child, G_FILE_TEST_IS_DIR))
        remove_tree_for_test (child);
      else
        g_remove (child);
    }
  }
  g_rmdir (path);
}

/* Declared where it is used rather than in a header: the neutral pair-bound
 * opener is the storage seam consumed by fact/store.c and the secure DuckDB
 * bridge, both of which declare it locally too. */
G_GNUC_INTERNAL wyrelog_error_t
wyl_fact_artifact_namespace_open_provisioned_pair_internal
  (WylFactGraphProvisionedPair *, WylFactArtifactNamespace **);

/* These are the only cases in this file that walk a path with the resolver
 * rather than driving the namespace from a handle, so they are the only ones
 * that need a fact root the resolver will accept.  Two properties matter and
 * a bare g_dir_make_tmp directory has neither: a protected owner-only ACL, and
 * an exactly-spelled path.  GetTempPath hands back an 8.3 short name on hosts
 * whose user directory needs one -- C:\Users\RUNNER~1 on the CI runner -- and
 * validate_parent_entry accepts only the exact spelling, so the walk refuses
 * the alias with WYRELOG_E_POLICY.  wyl_test_make_secure_fact_root applies the
 * ACL and canonicalises through GetFinalPathNameByHandleW and
 * GetLongPathNameW, which is why this borrows it rather than building a root
 * here. */
static gchar *
provisioned_root (void)
{
  g_autoptr (GError) error = NULL;
  gchar *root = wyl_test_make_secure_fact_root ("wyl-pair-ns-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (root);
  return root;
}

/* Publish an exact stage and adopt the published final as a pair, capturing
 * the evidence before the publishing rename forgets it. */
static WylFactGraphProvisionedPair *
provisioned_pair_for_test (const gchar *root, const gchar *operation,
    WylFactGraphLocator *locator, WylFactGraphResolver *resolver,
    WylFactGraphDirectory *graph)
{
  WylFactGraphStage stage = WYL_FACT_GRAPH_STAGE_INIT;
  WylFactGraphWinOperationEvidence evidence = { 0 };
  WylFactGraphProvisionedPair *pair = NULL;

  g_assert_cmpint (wyl_fact_graph_locator_init (locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (resolver, locator,
      TRUE, graph), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_directory_stage_create_exact (graph,
      operation, &stage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_stage_get_windows_operation_evidence (&stage,
      &evidence), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_stage_publish_with_evidence (graph, &stage,
      &evidence), ==, WYRELOG_E_OK);
  wyl_fact_graph_stage_clear (&stage);
  g_assert_cmpint
    (wyl_fact_graph_directory_open_provisioned_pair_exact_with_evidence (graph,
      operation, &evidence, &pair), ==, WYRELOG_E_OK);
  g_assert_nonnull (pair);
  return pair;
}

/* The pair reaches a real namespace, and the namespace does not borrow the
 * pair's authority handle: it holds its own. */
static void
test_namespace_from_provisioned_pair (void)
{
  g_autofree gchar *root = provisioned_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactArtifactWinLease *lease = NULL;
  WylFactArtifactNamespace *ns = NULL;

  WylFactGraphProvisionedPair *pair = provisioned_pair_for_test (root,
          "01890f47-3c4b-7cc2-b8c4-dc0c0c0705a0", &locator, &resolver, &graph);

  g_assert_cmpint (wyl_fact_artifact_namespace_open_provisioned_pair_internal
        (NULL, &ns), ==, WYRELOG_E_INVALID);
  g_assert_null (ns);

  g_assert_cmpint (wyl_fact_artifact_namespace_open_provisioned_pair_internal
        (pair, &ns), ==, WYRELOG_E_OK);
  g_assert_nonnull (ns);

  /* The adopted namespace is usable: a mutation lease and a sidecar session
   * both go through the same authorities a namespace opened any other way
   * would use. */
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (ns,
      &lease), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_lease_free (lease);

  /* The namespace took a reference, so releasing the caller's does not revoke
   * it -- and the hot-path re-proof still passes afterwards. */
  wyl_fact_graph_provisioned_pair_free (pair);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_revalidate (ns), ==,
      WYRELOG_E_OK);

  wyl_fact_artifact_win_namespace_free (ns);
  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_graph_resolver_clear (&resolver);
  remove_tree_for_test (root);
}

/* The hook is what makes the pair's provenance live rather than a
 * construction-time fact.  Unprotect the graph directory's DACL under a
 * pair-backed namespace and the next revalidation must revoke it; delete the
 * revalidate_bound call from wyl_fact_artifact_win_namespace_revalidate and
 * this goes green, because the locator's own revalidation only re-proves its
 * directory handle's FileId. */
static void
test_namespace_from_pair_revokes_on_directory_acl_rewrite (void)
{
  g_autofree gchar *root = provisioned_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactArtifactNamespace *ns = NULL;

  WylFactGraphProvisionedPair *pair = provisioned_pair_for_test (root,
          "01890f47-3c4b-7cc2-b8c4-dc0c0c0705a1", &locator, &resolver, &graph);
  g_assert_cmpint (wyl_fact_artifact_namespace_open_provisioned_pair_internal
        (pair, &ns), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_revalidate (ns), ==,
      WYRELOG_E_OK);

  g_autofree gchar *graph_path = g_build_filename (root,
          locator.tenant_component, locator.graph_component, NULL);
  g_autofree gunichar2 *wide = g_utf8_to_utf16 (graph_path, -1, NULL, NULL,
          NULL);
  g_assert_nonnull (wide);
  g_assert_cmpint (SetNamedSecurityInfoW ((LPWSTR) wide, SE_FILE_OBJECT,
      DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
      NULL, NULL, NULL, NULL), ==, ERROR_SUCCESS);

  g_assert_cmpint (wyl_fact_artifact_win_namespace_revalidate (ns), ==,
      WYRELOG_E_POLICY);
  /* Revocation is terminal: the namespace does not recover on a later call. */
  g_assert_cmpint (wyl_fact_artifact_win_namespace_revalidate (ns), ==,
      WYRELOG_E_POLICY);

  wyl_fact_artifact_win_namespace_free (ns);
  wyl_fact_graph_provisioned_pair_free (pair);
  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_graph_resolver_clear (&resolver);
  remove_tree_for_test (root);
}

static const WinGuardedCase win_guarded_cases[] = {
  {"/fact/artifact-namespace/windows/provisioned-pair/namespace",
   test_namespace_from_provisioned_pair},
  {"/fact/artifact-namespace/windows/provisioned-pair/revoke-on-acl",
   test_namespace_from_pair_revokes_on_directory_acl_rewrite},
  {"/fact/artifact-namespace/windows/working-handle/adopt-close",
   test_working_handle_adopt_noninherit_close_once},
  {"/fact/artifact-namespace/windows/io-session/lifetime-singleton",
   test_private_io_session_lifetime_and_singleton},
  {"/fact/artifact-namespace/windows/io-session/guardian-policy",
   test_io_session_guardian_failure_is_policy},
  {"/fact/artifact-namespace/windows/io-session/read-at-eof",
   test_io_session_read_at_eof_is_a_short_read},
  {"/fact/artifact-namespace/windows/reader-guard/main-read-only",
   test_reader_guard_opens_main_read_only},
  {"/fact/artifact-namespace/windows/reader-guard/sidecar-read-only",
   test_reader_guard_sidecar_is_read_only},
  {"/fact/artifact-namespace/windows/sidecar/neutral-authorities",
   test_neutral_sidecar_authorities_forward},
  {"/fact/artifact-namespace/windows/io-session/mutation-gate",
   test_session_blocks_mutation_until_finish},
  {"/fact/artifact-namespace/windows/io-session/retains-lease",
   test_session_retains_mutation_lease_until_finish},
  {"/fact/artifact-namespace/windows/locator/entry-lifecycle",
   test_locator_relative_entry_lifecycle},
  {"/fact/artifact-namespace/windows/locator/replace-open-destination",
   test_locator_replace_open_destination},
  {"/fact/artifact-namespace/windows/locator/nested-transport",
   test_locator_nested_directory_transport},
  {"/fact/artifact-namespace/windows/namespace/captured-owner-binding",
   test_native_namespace_captured_owner_acl_binding},
  {"/fact/artifact-namespace/windows/namespace/release-binding-stress",
   test_native_namespace_release_binding_stress},
  {"/fact/artifact-namespace/windows/namespace/generic-reader-lock-domain",
   test_generic_reader_session_blocks_cross_namespace_mutation},
  {"/fact/artifact-namespace/windows/io-session/source-substitution",
   test_live_session_source_substitution_is_policy},
  {"/fact/artifact-namespace/windows/working-handle/identity-output",
   test_working_handle_identity_mismatch_initializes_output},
  {"/fact/artifact-namespace/windows/working-handle/free-reused-handle",
   test_working_handle_free_never_closes_reused_handle},
  {"/fact/artifact-namespace/windows/working-handle/free-unlinked-object",
   test_working_handle_free_closes_unlinked_object},
  {"/fact/artifact-namespace/windows/working-handle/source-reuse-guardian",
   test_working_handle_source_reuse_cannot_revoke_guardian},
  {"/fact/artifact-namespace/windows/io-session/abort-terminal",
   test_session_abort_is_terminal},
  {"/fact/artifact-namespace/windows/lock-domain/alias-contention",
   test_native_lock_domain_alias_reader_writer_contention},
  {"/fact/artifact-namespace/windows/lock-domain/concurrent-release",
   test_native_lock_domain_concurrent_acquire_release},
  {"/fact/artifact-namespace/windows/lock-domain/cross-process",
   test_native_namespace_cross_process_leases_and_crash_release},
  {"/fact/artifact-namespace/windows/locator/directory-flush-capability",
   test_locator_directory_flush_capability_mapping},
  {"/fact/artifact-namespace/windows/locator/rename-unsupported-class",
   test_locator_rename_unsupported_class_mapping},
  /* Keep these two adjacent and both under /locator/; see the comment above
   * test_locator_leaked_flush_fault for why the suite path, not this table
   * position, is what actually orders them. */
  {"/fact/artifact-namespace/windows/locator/leaked-flush-fault",
   test_locator_leaked_flush_fault, ERROR_NOT_SUPPORTED,
   WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_REPLACE_POST_RENAME_UNCERTAIN},
  {"/fact/artifact-namespace/windows/locator/flush-after-leaked-fault",
   test_locator_flush_after_leaked_fault},
  {"/fact/artifact-namespace/windows/namespace/main-sidecar",
   test_native_namespace_main_sidecar_lifecycle},
  {"/fact/artifact-namespace/windows/namespace/substitution",
   test_native_namespace_reparse_and_hardlink_substitution},
  {"/fact/artifact-namespace/windows/io-session/query-metadata-and-revalidate",
   test_io_session_query_metadata_and_revalidate},
  {"/fact/artifact-namespace/windows/temp-root/spill-child-capabilities",
   test_temp_root_spill_child_capabilities},
  {"/fact/artifact-namespace/windows/io-session/read-only-access-intent",
   test_io_session_read_only_access_intent},
};

int
main (int argc, char **argv)
{
  if (argc == 4 && strcmp (argv[1], "--win-lease-child") == 0)
    return run_lease_child (argv[2], argv[3]);
  g_test_init (&argc, &argv, NULL);
  for (gsize i = 0; i < G_N_ELEMENTS (win_guarded_cases); i++)
    g_test_add (win_guarded_cases[i].path, WinFaultGuard,
        &win_guarded_cases[i], win_fault_guard_set_up, win_fault_guard_run,
        win_fault_guard_tear_down);
  return g_test_run ();
}
#else
int
main (void)
{
  return 77;
}
#endif

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/graph-artifact-windows-locator-private.h"
#include "fact/graph-windows-security-private.h"
#include "wyrelog/wyl-log-private.h"

#ifdef G_OS_WIN32
#include <winternl.h>
#include <stddef.h>
#include <string.h>

typedef NTSTATUS (NTAPI * WylNtCreateFile) (PHANDLE, ACCESS_MASK,
    POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG,
    ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI * WylNtSetInformationFile) (HANDLE,
    PIO_STATUS_BLOCK, PVOID, ULONG, int);

#define WYL_NT_FILE_RENAME_INFO_CLASS 10
#define WYL_NT_FILE_DISPOSITION_INFO_CLASS 13
#define WYL_FILE_ID_EXTD_DIRECTORY_INFO 19
#define WYL_FILE_ID_EXTD_DIRECTORY_RESTART_INFO 20
#define WYL_NT_FILE_RENAME_INFO_EX_CLASS 65
#define WYL_FILE_RENAME_REPLACE_IF_EXISTS 0x00000001UL
#define WYL_FILE_RENAME_POSIX_SEMANTICS 0x00000002UL

typedef struct
{
  BOOLEAN delete_file;
} WylFileDispositionInfo;
typedef struct
{
  BOOLEAN replace_if_exists;
  HANDLE root_directory;
  ULONG file_name_length;
  WCHAR file_name[1];
} WylFileRenameInfo;
/* Same layout and alignment as the classic form; the leading BOOLEAN is
 * widened into the flag word that carries POSIX semantics. */
typedef struct
{
  ULONG flags;
  HANDLE root_directory;
  ULONG file_name_length;
  WCHAR file_name[1];
} WylFileRenameInfoEx;
typedef struct
{
  DWORD next_entry_offset;
  DWORD file_index;
  LARGE_INTEGER creation_time;
  LARGE_INTEGER last_access_time;
  LARGE_INTEGER last_write_time;
  LARGE_INTEGER change_time;
  LARGE_INTEGER end_of_file;
  LARGE_INTEGER allocation_size;
  DWORD file_attributes;
  DWORD file_name_length;
  DWORD ea_size;
  DWORD reparse_point_tag;
  FILE_ID_128 file_id;
  WCHAR file_name[1];
} WylFileIdExtdDirInfo;

struct WylFactArtifactWinLocator
{
  HANDLE directory;
  WylFactGraphWinIdentity identity;
  /* This is captured once, when the graph authority is imported.  Never
   * re-query the effective token at a later I/O boundary: impersonation or a
   * token change must not silently widen the authority of existing entries. */
  PSID owner;
  gboolean unsupported_rename_class_logged;
};
struct WylFactArtifactWinEntry
{
  HANDLE handle;
  WylFactGraphWinIdentity identity;
  gchar *name;
};
struct WylFactArtifactWinDirectory
{
  HANDLE handle;
  WylFactGraphWinIdentity identity;
  gchar *name;
};

#ifdef WYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS
static volatile LONG next_directory_flush_error;
static volatile LONG next_rename_status;
static volatile LONG next_inventory_fault;

void
wyl_fact_artifact_win_locator_set_inventory_test_fault
  (WylFactArtifactWinInventoryTestFault fault)
{
  InterlockedExchange (&next_inventory_fault, (LONG) fault);
}

WylFactArtifactWinInventoryTestFault
wyl_fact_artifact_win_locator_take_inventory_test_fault (void)
{
  return (WylFactArtifactWinInventoryTestFault)
         InterlockedExchange (&next_inventory_fault,
             WYL_FACT_ARTIFACT_WIN_INVENTORY_TEST_FAULT_NONE);
}

static gboolean
inventory_fault_take (WylFactArtifactWinInventoryTestFault fault)
{
  return InterlockedCompareExchange (&next_inventory_fault,
             WYL_FACT_ARTIFACT_WIN_INVENTORY_TEST_FAULT_NONE,
             (LONG) fault) == (LONG) fault;
}

void
wyl_fact_artifact_win_locator_fail_next_directory_flush_for_test (DWORD error)
{
  InterlockedExchange (&next_directory_flush_error, (LONG) error);
}

DWORD
wyl_fact_artifact_win_locator_take_next_directory_flush_error_for_test (void)
{
  return (DWORD) InterlockedExchange (&next_directory_flush_error,
             ERROR_SUCCESS);
}

void
wyl_fact_artifact_win_locator_fail_next_rename_status_for_test (NTSTATUS status)
{
  InterlockedExchange (&next_rename_status, (LONG) status);
}

NTSTATUS
wyl_fact_artifact_win_locator_take_next_rename_status_for_test (void)
{
  return (NTSTATUS) InterlockedExchange (&next_rename_status, 0);
}
#endif /* WYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS */

static WylNtCreateFile
nt_create_file (void)
{
  HMODULE module = GetModuleHandleW (L"ntdll.dll");
  return module == NULL ? NULL : (WylNtCreateFile) GetProcAddress (module,
             "NtCreateFile");
}

static WylNtSetInformationFile
nt_set_information_file (void)
{
  HMODULE module = GetModuleHandleW (L"ntdll.dll");
  return module == NULL ? NULL : (WylNtSetInformationFile) GetProcAddress
           (module, "NtSetInformationFile");
}

static gboolean
valid_handle (HANDLE handle)
{
  return handle != NULL && handle != INVALID_HANDLE_VALUE;
}

static gboolean
identity_equal (const WylFactGraphWinIdentity *a,
    const WylFactGraphWinIdentity *b)
{
  return a->volume_serial == b->volume_serial
         && memcmp (a->file_id, b->file_id, sizeof a->file_id) == 0;
}

static wyrelog_error_t
nt_error (NTSTATUS status)
{
  switch ((ULONG) status) {
    case 0xC0000034UL:
    case 0xC000003AUL:
      return WYRELOG_E_NOT_FOUND;
    case 0xC0000035UL:
    case 0xC0000043UL:
      return WYRELOG_E_BUSY;
    case 0xC0000022UL:
    case 0xC0000024UL:
    case 0xC00000BAUL:
    case 0xC0000103UL:
    case 0xC0000276UL:
    case 0xC0000277UL:
    case 0xC0000278UL:
    case 0xC0000279UL:
    case 0xC0000280UL:
    case 0xC0000281UL:
    case 0xC0000106UL:
    case 0xC0000368UL:
    case 0xC000050BUL:
    case 0x8000002DUL:
      return WYRELOG_E_POLICY;
    default:
      return WYRELOG_E_IO;
  }
}

static gboolean
nt_unsupported_class (NTSTATUS status)
{
  switch ((ULONG) status) {
    case 0xC00000BBUL:         /* STATUS_NOT_SUPPORTED */
    case 0xC00000C0UL:         /* STATUS_NOT_IMPLEMENTED */
    case 0xC0000003UL:         /* STATUS_INVALID_INFO_CLASS */
    case 0xC000000DUL:         /* STATUS_INVALID_PARAMETER */
    case 0xC0000010UL:         /* STATUS_INVALID_DEVICE_REQUEST */
      return TRUE;
    default:
      return FALSE;
  }
}

static gboolean
nt_unsupported_info_class (NTSTATUS status)
{
  switch ((ULONG) status) {
    case 0xC00000BBUL:         /* STATUS_NOT_SUPPORTED */
    case 0xC00000C0UL:         /* STATUS_NOT_IMPLEMENTED */
    case 0xC0000003UL:         /* STATUS_INVALID_INFO_CLASS */
    case 0xC0000010UL:         /* STATUS_INVALID_DEVICE_REQUEST */
      return TRUE;
    default:
      return FALSE;
  }
}

/* NtSetInformationFile is an optional native primitive, not a best-effort
 * pathname fallback.  Unsupported information classes or filesystems must
 * fail closed: callers cannot infer whether a mutation linearized. */
static wyrelog_error_t
nt_mutation_error (NTSTATUS status)
{
  return nt_unsupported_class (status) ? WYRELOG_E_POLICY : nt_error (status);
}

static wyrelog_error_t
file_identity (HANDLE handle, gboolean directory,
    WylFactGraphWinIdentity *out_identity)
{
  FILE_BASIC_INFO basic = { 0 };
  FILE_STANDARD_INFO standard = { 0 };
  FILE_ID_INFO id = { 0 };
  if (!valid_handle (handle) || out_identity == NULL)
    return WYRELOG_E_INVALID;
  if (!GetFileInformationByHandleEx (handle, FileBasicInfo, &basic,
      sizeof basic) || !GetFileInformationByHandleEx (handle,
      FileStandardInfo, &standard, sizeof standard)
      || !GetFileInformationByHandleEx (handle, FileIdInfo, &id, sizeof id))
    return WYRELOG_E_IO;
  if (((basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory
      || (basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
      || standard.DeletePending || (!directory && standard.NumberOfLinks != 1))
    return WYRELOG_E_POLICY;
  out_identity->volume_serial = id.VolumeSerialNumber;
  memcpy (out_identity->file_id, id.FileId.Identifier,
      sizeof out_identity->file_id);
  return WYRELOG_E_OK;
}

/* Deletion is a terminal lifecycle transition.  The normal identity audit
 * rejects DeletePending so no live authority can be issued from it, but its
 * own retained HANDLE still has to be closed exactly once.  This narrower
 * destructor-only check permits DeletePending while proving the same native
 * object and rejecting a raw-close/reused foreign HANDLE. */
static gboolean
terminal_handle_matches_identity (HANDLE handle, gboolean directory,
    const WylFactGraphWinIdentity *expected)
{
  FILE_BASIC_INFO basic = { 0 };
  FILE_STANDARD_INFO standard = { 0 };
  FILE_ID_INFO id = { 0 };
  WylFactGraphWinIdentity observed = { 0 };
  DWORD flags = 0;
  if (!valid_handle (handle) || expected == NULL
      || !GetHandleInformation (handle, &flags)
      || (flags & HANDLE_FLAG_INHERIT) != 0
      || !GetFileInformationByHandleEx (handle, FileBasicInfo, &basic,
      sizeof basic)
      || !GetFileInformationByHandleEx (handle, FileStandardInfo, &standard,
      sizeof standard)
      || !GetFileInformationByHandleEx (handle, FileIdInfo, &id, sizeof id)
      || ((basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory
      || (basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
      || standard.Directory != directory)
    return FALSE;
  observed.volume_serial = id.VolumeSerialNumber;
  memcpy (observed.file_id, id.FileId.Identifier, sizeof observed.file_id);
  return identity_equal (&observed, expected);
}

static wyrelog_error_t
close_directory_if_exact (WylFactArtifactWinDirectory *directory)
{
  if (directory != NULL && valid_handle (directory->handle)
      && terminal_handle_matches_identity (directory->handle, TRUE,
      &directory->identity))
    CloseHandle (directory->handle);
  return WYRELOG_E_OK;
}

static gboolean
safe_component (const gchar *name)
{
  return name != NULL && name[0] != '\0' && g_utf8_validate (name, -1, NULL)
         && strcmp (name, ".") != 0 && strcmp (name, "..") != 0
         && strpbrk (name, "/\\:") == NULL;
}

static wyrelog_error_t
wide_component (const gchar *name, gunichar2 **out_wide, glong *out_units)
{
  if (out_wide != NULL)
    *out_wide = NULL;
  if (out_units != NULL)
    *out_units = 0;
  if (out_wide == NULL || out_units == NULL || !safe_component (name))
    return WYRELOG_E_INVALID;
  *out_wide = g_utf8_to_utf16 (name, -1, NULL, out_units, NULL);
  if (*out_wide == NULL)
    return WYRELOG_E_NOMEM;
  if (*out_units <= 0 || (gsize) * out_units > G_MAXUSHORT / sizeof (WCHAR)) {
    g_clear_pointer (out_wide, g_free);
    return WYRELOG_E_POLICY;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
validate_named_entry (HANDLE directory, const gchar *name,
    const WylFactGraphWinIdentity *identity)
{
  g_autofree gunichar2 *wanted = NULL;
  glong wanted_units = 0;
  BYTE buffer[64 * 1024];
  gboolean restart = TRUE;
  guint matches = 0;
  wyrelog_error_t rc = wide_component (name, &wanted, &wanted_units);
  if (rc != WYRELOG_E_OK)
    return rc;
  for (;;) {
    FILE_INFO_BY_HANDLE_CLASS klass = (FILE_INFO_BY_HANDLE_CLASS)
        (restart ? WYL_FILE_ID_EXTD_DIRECTORY_RESTART_INFO
        : WYL_FILE_ID_EXTD_DIRECTORY_INFO);
    if (!GetFileInformationByHandleEx (directory, klass, buffer, sizeof buffer)) {
      DWORD error = GetLastError ();
      if (error == ERROR_NO_MORE_FILES)
        break;
      return error == ERROR_MORE_DATA ? WYRELOG_E_POLICY : WYRELOG_E_IO;
    }
    restart = FALSE;
    WylFileIdExtdDirInfo *current = (WylFileIdExtdDirInfo *) buffer;
    for (;;) {
      gsize units = current->file_name_length / sizeof (WCHAR);
      if (units == (gsize) wanted_units
          && CompareStringOrdinal (current->file_name, (int) units, wanted,
          (int) wanted_units, FALSE) == CSTR_EQUAL) {
        if (memcmp (&current->file_id, identity->file_id,
            sizeof current->file_id) != 0)
          return WYRELOG_E_POLICY;
        matches++;
      }
      if (current->next_entry_offset == 0)
        break;
      current = (WylFileIdExtdDirInfo *) ((BYTE *) current
          + current->next_entry_offset);
    }
  }
  return matches == 1 ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

#define WYL_WIN_INVENTORY_MAX_ROOT_ENTRIES 512u
#define WYL_WIN_INVENTORY_MAX_TEMP_ROOTS 256u
#define WYL_WIN_INVENTORY_MAX_TEMP_CHILDREN 256u
#define WYL_WIN_INVENTORY_MAX_TOTAL_ENTRIES 4096u
#define WYL_WIN_INVENTORY_MAX_ANOMALIES 256u
#define WYL_WIN_INVENTORY_MAX_NAME_UNITS 255u
#define WYL_WIN_INVENTORY_DIGEST_SIZE 32u

typedef enum
{
  WYL_WIN_INVENTORY_CLASS_FIXED = 1,
  WYL_WIN_INVENTORY_CLASS_TEMP_ROOT,
  WYL_WIN_INVENTORY_CLASS_TEMP_CHILD,
  WYL_WIN_INVENTORY_CLASS_UNKNOWN,
  WYL_WIN_INVENTORY_CLASS_MALFORMED,
} WylWinInventoryClass;

typedef struct
{
  guint8 bytes[WYL_WIN_INVENTORY_DIGEST_SIZE];
} WylWinInventoryDigest;

typedef struct
{
  WylFactGraphWinIdentity identity;
  DWORD attributes;
  DWORD links;
  guint64 logical_bytes;
  guint64 allocated_bytes;
  gboolean directory;
  gboolean reparse;
  gboolean delete_pending;
  gboolean identity_matches_listing;
  gboolean acl_valid;
  gboolean allocation_supported;
} WylWinInventoryMetadata;

typedef struct
{
  GArray *digests;
  guint total_entries;
  guint anomaly_count;
  guint temp_roots;
  gboolean allocation_unsupported;
} WylWinInventoryState;

static gboolean
inventory_enumeration_fault_take (void)
{
#ifdef WYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS
  return inventory_fault_take
           (WYL_FACT_ARTIFACT_WIN_INVENTORY_TEST_FAULT_ENUMERATION_IO);
#else
  return FALSE;
#endif
}

static gboolean
inventory_fixed_metadata_fault_take (void)
{
#ifdef WYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS
  return inventory_fault_take
           (WYL_FACT_ARTIFACT_WIN_INVENTORY_TEST_FAULT_FIXED_METADATA_IO);
#else
  return FALSE;
#endif
}

static gboolean
inventory_temp_metadata_fault_take (void)
{
#ifdef WYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS
  return inventory_fault_take
           (WYL_FACT_ARTIFACT_WIN_INVENTORY_TEST_FAULT_TEMP_METADATA_IO);
#else
  return FALSE;
#endif
}

static gboolean
inventory_allocation_fault_take (void)
{
#ifdef WYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS
  return inventory_fault_take
           (WYL_FACT_ARTIFACT_WIN_INVENTORY_TEST_FAULT_ALLOCATION_UNSUPPORTED);
#else
  return FALSE;
#endif
}

static wyrelog_error_t
inventory_fail (WylFactArtifactWinInventoryScan *scan,
    WylFactArtifactInventoryStatus status, wyrelog_error_t rc)
{
  if (scan->failure_status == WYL_FACT_ARTIFACT_INVENTORY_STATUS_INVALID)
    scan->failure_status = status;
  return rc;
}

static wyrelog_error_t
inventory_add_anomaly (WylFactArtifactWinInventoryScan *scan,
    WylWinInventoryState *state, WylFactArtifactInventoryAnomaly anomaly)
{
  if (anomaly >= WYL_FACT_ARTIFACT_INVENTORY_ANOMALY_COUNT
      || state->anomaly_count >= WYL_WIN_INVENTORY_MAX_ANOMALIES)
    return inventory_fail (scan,
               WYL_FACT_ARTIFACT_INVENTORY_STATUS_OVERFLOW, WYRELOG_E_POLICY);
  scan->anomalies[anomaly]++;
  state->anomaly_count++;
  return WYRELOG_E_OK;
}

static void
inventory_checksum_u64 (GChecksum *checksum, guint64 value)
{
  guint8 bytes[8];
  for (guint i = 0; i < G_N_ELEMENTS (bytes); i++) {
    bytes[i] = (guint8) (value & 0xffu);
    value >>= 8;
  }
  g_checksum_update (checksum, bytes, sizeof bytes);
}

static void
inventory_checksum_bytes (GChecksum *checksum, gconstpointer bytes,
    gsize length)
{
  inventory_checksum_u64 (checksum, length);
  if (length > 0)
    g_checksum_update (checksum, bytes, length);
}

static gboolean
inventory_add_digest (WylWinInventoryState *state, guint scope,
    const WCHAR *name, gsize name_units, WylWinInventoryClass classification,
    const WylFileIdExtdDirInfo *listed,
    const WylWinInventoryMetadata *metadata)
{
  g_autoptr (GChecksum) checksum = g_checksum_new (G_CHECKSUM_SHA256);
  WylWinInventoryDigest digest = { { 0 } };
  gsize digest_length = sizeof digest.bytes;
  if (checksum == NULL || state == NULL || listed == NULL)
    return FALSE;
  inventory_checksum_u64 (checksum, scope);
  inventory_checksum_bytes (checksum, name,
      name_units * sizeof (WCHAR));
  inventory_checksum_u64 (checksum, classification);
  inventory_checksum_u64 (checksum, listed->file_attributes);
  inventory_checksum_u64 (checksum, listed->reparse_point_tag);
  inventory_checksum_u64 (checksum, (guint64) listed->end_of_file.QuadPart);
  inventory_checksum_u64 (checksum,
      (guint64) listed->allocation_size.QuadPart);
  inventory_checksum_bytes (checksum, listed->file_id.Identifier,
      sizeof listed->file_id.Identifier);
  inventory_checksum_u64 (checksum, metadata != NULL);
  if (metadata != NULL) {
    inventory_checksum_u64 (checksum, metadata->identity.volume_serial);
    inventory_checksum_bytes (checksum, metadata->identity.file_id,
        sizeof metadata->identity.file_id);
    inventory_checksum_u64 (checksum, metadata->attributes);
    inventory_checksum_u64 (checksum, metadata->links);
    inventory_checksum_u64 (checksum, metadata->logical_bytes);
    inventory_checksum_u64 (checksum, metadata->allocated_bytes);
    inventory_checksum_u64 (checksum, metadata->directory);
    inventory_checksum_u64 (checksum, metadata->reparse);
    inventory_checksum_u64 (checksum, metadata->delete_pending);
    inventory_checksum_u64 (checksum, metadata->identity_matches_listing);
    inventory_checksum_u64 (checksum, metadata->acl_valid);
    inventory_checksum_u64 (checksum, metadata->allocation_supported);
  }
  g_checksum_get_digest (checksum, digest.bytes, &digest_length);
  if (digest_length != sizeof digest.bytes)
    return FALSE;
  g_array_append_val (state->digests, digest);
  return TRUE;
}

static gint
inventory_digest_compare (gconstpointer left, gconstpointer right)
{
  const WylWinInventoryDigest *a = left;
  const WylWinInventoryDigest *b = right;
  return memcmp (a->bytes, b->bytes, sizeof a->bytes);
}

static gboolean
inventory_finish_fingerprint (WylWinInventoryState *state,
    const WylFactGraphWinIdentity *directory_identity, guint64 *out_fingerprint)
{
  g_autoptr (GChecksum) checksum = g_checksum_new (G_CHECKSUM_SHA256);
  guint8 digest[WYL_WIN_INVENTORY_DIGEST_SIZE] = { 0 };
  gsize digest_length = sizeof digest;
  guint64 fingerprint = 0;
  if (state == NULL || state->digests == NULL || directory_identity == NULL
      || out_fingerprint == NULL || checksum == NULL)
    return FALSE;
  g_array_sort (state->digests, inventory_digest_compare);
  inventory_checksum_u64 (checksum, directory_identity->volume_serial);
  inventory_checksum_bytes (checksum, directory_identity->file_id,
      sizeof directory_identity->file_id);
  inventory_checksum_u64 (checksum, state->digests->len);
  for (guint i = 0; i < state->digests->len; i++) {
    const WylWinInventoryDigest *entry = &g_array_index (state->digests,
            WylWinInventoryDigest, i);
    inventory_checksum_bytes (checksum, entry->bytes, sizeof entry->bytes);
  }
  g_checksum_get_digest (checksum, digest, &digest_length);
  if (digest_length != sizeof digest)
    return FALSE;
  for (guint i = 0; i < sizeof fingerprint; i++)
    fingerprint = (fingerprint << 8) | digest[i];
  *out_fingerprint = fingerprint;
  return TRUE;
}

static gboolean
inventory_temp_root_name (const gchar *name)
{
  static const gchar prefix[] = "wyrelog-duckdb-temp-";
  const gchar *uuid;
  if (name == NULL || !g_str_has_prefix (name, prefix))
    return FALSE;
  uuid = name + sizeof prefix - 1;
  if (strlen (uuid) != 36)
    return FALSE;
  for (guint i = 0; i < 36; i++) {
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (uuid[i] != '-')
        return FALSE;
    } else if (!g_ascii_isdigit (uuid[i])
        && !(uuid[i] >= 'a' && uuid[i] <= 'f')) {
      return FALSE;
    }
  }
  return TRUE;
}

static gboolean
inventory_temp_child_name (const gchar *name)
{
  const gchar *p;
  if (name == NULL || strpbrk (name, "/\\") != NULL)
    return FALSE;
  if (g_str_has_prefix (name, "duckdb_temp_storage_")) {
    static const gchar *const classes[] = {
      "DEFAULT", "S32K", "S64K", "S96K", "S128K", "S160K", "S192K",
      "S224K",
    };
    gboolean matched = FALSE;
    p = name + strlen ("duckdb_temp_storage_");
    for (guint i = 0; i < G_N_ELEMENTS (classes); i++)
      if (g_str_has_prefix (p, classes[i])) {
        p += strlen (classes[i]);
        matched = TRUE;
        break;
      }
    if (!matched || *p++ != '-')
      return FALSE;
    const gchar *digits = p;
    while (g_ascii_isdigit (*p))
      p++;
    return p != digits && (digits[0] == '0' ? p == digits + 1
        : (p - digits) <= 20) && g_strcmp0 (p, ".tmp") == 0;
  }
  if (!g_str_has_prefix (name, "duckdb_temp_block-"))
    return FALSE;
  p = name + strlen ("duckdb_temp_block-");
  const gchar *digits = p;
  while (g_ascii_isdigit (*p))
    p++;
  return p != digits && (digits[0] == '0' ? p == digits + 1
      : (p - digits) <= 20) && g_strcmp0 (p, ".block") == 0;
}

static gint
inventory_fixed_slot (const gchar *name, gboolean *out_case_collision)
{
  static const gchar *const names[] = {
    "facts.duckdb", "facts.duckdb.wal", "facts.duckdb.wal.checkpoint",
    "facts.duckdb.wal.recovery", "facts.duckdb.lock",
  };
  if (out_case_collision != NULL)
    *out_case_collision = FALSE;
  for (guint i = 0; i < G_N_ELEMENTS (names); i++) {
    if (g_strcmp0 (name, names[i]) == 0)
      return (gint) i;
    if (name != NULL && g_ascii_strcasecmp (name, names[i]) == 0
        && out_case_collision != NULL)
      *out_case_collision = TRUE;
  }
  return -1;
}

static wyrelog_error_t
inventory_open_relative (HANDLE parent, const gchar *name,
    gint expected_directory, HANDLE *out_handle)
{
  WylNtCreateFile create = nt_create_file ();
  g_autofree gunichar2 *wide = NULL;
  glong units = 0;
  UNICODE_STRING object_name = { 0 };
  OBJECT_ATTRIBUTES attributes = { 0 };
  IO_STATUS_BLOCK iosb = { 0 };
  HANDLE handle = INVALID_HANDLE_VALUE;
  ULONG options = FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT;
  ACCESS_MASK access = FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
  wyrelog_error_t rc;
  if (out_handle != NULL)
    *out_handle = INVALID_HANDLE_VALUE;
  if (!valid_handle (parent) || out_handle == NULL || create == NULL)
    return WYRELOG_E_INVALID;
  if ((rc = wide_component (name, &wide, &units)) != WYRELOG_E_OK)
    return rc;
  if (expected_directory > 0) {
    options |= FILE_DIRECTORY_FILE;
    access |= FILE_LIST_DIRECTORY;
  } else if (expected_directory == 0) {
    options |= FILE_NON_DIRECTORY_FILE;
  }
  object_name.Length = (USHORT) (units * sizeof (WCHAR));
  object_name.MaximumLength = object_name.Length;
  object_name.Buffer = (PWSTR) wide;
  attributes.Length = sizeof attributes;
  attributes.RootDirectory = parent;
  attributes.ObjectName = &object_name;
  NTSTATUS status = create (&handle, access, &attributes, &iosb, NULL,
          FILE_ATTRIBUTE_NORMAL,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
          options, NULL, 0);
  if (status < 0 || !valid_handle (handle))
    return nt_error (status);
  if (!SetHandleInformation (handle, HANDLE_FLAG_INHERIT, 0)) {
    CloseHandle (handle);
    return WYRELOG_E_IO;
  }
  *out_handle = handle;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
inventory_query_metadata (WylFactArtifactWinLocator *locator, HANDLE handle,
    const WylFileIdExtdDirInfo *listed, WylWinInventoryState *state,
    WylWinInventoryMetadata *out_metadata)
{
  FILE_BASIC_INFO basic = { 0 };
  FILE_STANDARD_INFO standard = { 0 };
  FILE_ID_INFO id = { 0 };
  DWORD flags = 0;
  if (locator == NULL || !valid_handle (handle) || listed == NULL
      || state == NULL || out_metadata == NULL)
    return WYRELOG_E_INVALID;
  memset (out_metadata, 0, sizeof *out_metadata);
  if (!GetHandleInformation (handle, &flags) || (flags & HANDLE_FLAG_INHERIT)
      || !GetFileInformationByHandleEx (handle, FileBasicInfo, &basic,
      sizeof basic) || !GetFileInformationByHandleEx (handle,
      FileStandardInfo, &standard, sizeof standard)
      || !GetFileInformationByHandleEx (handle, FileIdInfo, &id, sizeof id))
    return WYRELOG_E_IO;
  if (standard.EndOfFile.QuadPart < 0 || standard.AllocationSize.QuadPart < 0)
    return WYRELOG_E_POLICY;
  out_metadata->identity.volume_serial = id.VolumeSerialNumber;
  memcpy (out_metadata->identity.file_id, id.FileId.Identifier,
      sizeof out_metadata->identity.file_id);
  out_metadata->attributes = basic.FileAttributes;
  out_metadata->links = standard.NumberOfLinks;
  out_metadata->logical_bytes = (guint64) standard.EndOfFile.QuadPart;
  out_metadata->allocated_bytes = (guint64) standard.AllocationSize.QuadPart;
  out_metadata->directory = standard.Directory;
  out_metadata->reparse =
      (basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
  out_metadata->delete_pending = standard.DeletePending;
  out_metadata->identity_matches_listing =
      id.VolumeSerialNumber == locator->identity.volume_serial
      && memcmp (id.FileId.Identifier, listed->file_id.Identifier,
          sizeof listed->file_id.Identifier) == 0;
  out_metadata->acl_valid =
      wyl_fact_graph_win_validate_protected_owner_acl_for_user (handle,
          locator->owner, 0) == WYRELOG_E_OK;
  out_metadata->allocation_supported = TRUE;
  if (inventory_allocation_fault_take ()) {
    out_metadata->allocation_supported = FALSE;
    out_metadata->allocated_bytes = 0;
    state->allocation_unsupported = TRUE;
  }
  return WYRELOG_E_OK;
}

static gboolean
inventory_entry_bounds_valid (const BYTE *buffer,
    const WylFileIdExtdDirInfo *entry)
{
  const BYTE *start = (const BYTE *) entry;
  gsize header = offsetof (WylFileIdExtdDirInfo, file_name);
  if (start < buffer || start > buffer + 64 * 1024
      || (gsize) (buffer + 64 * 1024 - start) < header
      || entry->file_name_length > buffer + 64 * 1024 - start - header
      || entry->file_name_length % sizeof (WCHAR) != 0)
    return FALSE;
  if (entry->next_entry_offset != 0
      && (entry->next_entry_offset < header
      || entry->next_entry_offset > buffer + 64 * 1024 - start))
    return FALSE;
  return TRUE;
}

static void
inventory_transition_value_from_metadata
  (const WylWinInventoryMetadata *metadata,
    WylFactArtifactMainTransitionEntryEvidence *out_entry)
{
  *out_entry = (WylFactArtifactMainTransitionEntryEvidence) {
    .present = TRUE,
    .link_count = metadata->links,
    .reparse = metadata->reparse,
    .owner_state = metadata->directory
        ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_UNKNOWN
        : metadata->acl_valid
        ? WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_CONFORMING
        : WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_UNPROTECTED_ACL,
  };
  if (!metadata->reparse) {
    out_entry->identity.domain = metadata->identity.volume_serial;
    out_entry->identity.object_width = 16;
    memcpy (out_entry->identity.object_bytes, metadata->identity.file_id,
        sizeof out_entry->identity.object_bytes);
  }
}

static wyrelog_error_t
inventory_add_bytes (WylFactArtifactWinInventoryScan *scan,
    WylFactArtifactWinInventoryValue *value,
    const WylWinInventoryMetadata *metadata)
{
  if (value->logical_bytes > G_MAXUINT64 - metadata->logical_bytes
      || value->allocated_bytes > G_MAXUINT64 - metadata->allocated_bytes)
    return inventory_fail (scan,
               WYL_FACT_ARTIFACT_INVENTORY_STATUS_OVERFLOW, WYRELOG_E_POLICY);
  value->logical_bytes += metadata->logical_bytes;
  value->allocated_bytes += metadata->allocated_bytes;
  value->allocation_supported &= metadata->allocation_supported;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
inventory_scan_temp_root (WylFactArtifactWinLocator *locator, HANDLE root,
    WylFactArtifactWinInventoryScan *scan, WylWinInventoryState *state)
{
  BYTE buffer[64 * 1024];
  gboolean restart = TRUE;
  guint child_count = 0;
  if (inventory_enumeration_fault_take ())
    return inventory_fail (scan, WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO,
               WYRELOG_E_IO);
  for (;;) {
    FILE_INFO_BY_HANDLE_CLASS klass = (FILE_INFO_BY_HANDLE_CLASS)
        (restart ? WYL_FILE_ID_EXTD_DIRECTORY_RESTART_INFO
        : WYL_FILE_ID_EXTD_DIRECTORY_INFO);
    if (!GetFileInformationByHandleEx (root, klass, buffer, sizeof buffer)) {
      DWORD error = GetLastError ();
      if (error == ERROR_NO_MORE_FILES)
        break;
      return inventory_fail (scan,
                 error == ERROR_MORE_DATA
          ? WYL_FACT_ARTIFACT_INVENTORY_STATUS_OVERFLOW
          : WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO,
                 error == ERROR_MORE_DATA ? WYRELOG_E_POLICY : WYRELOG_E_IO);
    }
    restart = FALSE;
    WylFileIdExtdDirInfo *current = (WylFileIdExtdDirInfo *) buffer;
    for (;;) {
      g_autofree gchar *name = NULL;
      WylWinInventoryMetadata metadata = { 0 };
      HANDLE handle = INVALID_HANDLE_VALUE;
      gsize units;
      gboolean valid_name;
      wyrelog_error_t rc;
      if (!inventory_entry_bounds_valid (buffer, current))
        return inventory_fail (scan,
                   WYL_FACT_ARTIFACT_INVENTORY_STATUS_POLICY, WYRELOG_E_POLICY);
      units = current->file_name_length / sizeof (WCHAR);
      if ((units == 1 && current->file_name[0] == L'.')
          || (units == 2 && current->file_name[0] == L'.'
          && current->file_name[1] == L'.'))
        goto next_child;
      if (child_count++ >= WYL_WIN_INVENTORY_MAX_TEMP_CHILDREN
          || state->total_entries++ >= WYL_WIN_INVENTORY_MAX_TOTAL_ENTRIES)
        return inventory_fail (scan,
                   WYL_FACT_ARTIFACT_INVENTORY_STATUS_OVERFLOW, WYRELOG_E_POLICY);
      if (units > WYL_WIN_INVENTORY_MAX_NAME_UNITS) {
        if (!inventory_add_digest (state, 2, current->file_name, units,
            WYL_WIN_INVENTORY_CLASS_MALFORMED, current, NULL))
          return inventory_fail (scan,
                     WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO, WYRELOG_E_NOMEM);
        rc = inventory_add_anomaly (scan, state,
                WYL_FACT_ARTIFACT_INVENTORY_OVER_LIMIT_ENTRY);
        if (rc != WYRELOG_E_OK)
          return rc;
        goto next_child;
      }
      name = g_utf16_to_utf8 ((const gunichar2 *) current->file_name,
              units, NULL, NULL, NULL);
      valid_name = name != NULL && safe_component (name)
          && inventory_temp_child_name (name);
      if (!valid_name) {
        if (!inventory_add_digest (state, 2, current->file_name, units,
            WYL_WIN_INVENTORY_CLASS_MALFORMED, current, NULL))
          return inventory_fail (scan,
                     WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO, WYRELOG_E_NOMEM);
        rc = inventory_add_anomaly (scan, state,
                WYL_FACT_ARTIFACT_INVENTORY_MALFORMED_ENTRY);
        if (rc != WYRELOG_E_OK)
          return rc;
        goto next_child;
      }
      if (inventory_temp_metadata_fault_take ())
        return inventory_fail (scan, WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO,
                   WYRELOG_E_IO);
      rc = inventory_open_relative (root, name, 0, &handle);
      if (rc == WYRELOG_E_OK)
        rc = inventory_query_metadata (locator, handle, current, state,
                &metadata);
      if (rc != WYRELOG_E_OK) {
        if (valid_handle (handle))
          CloseHandle (handle);
        if (!inventory_add_digest (state, 2, current->file_name, units,
            WYL_WIN_INVENTORY_CLASS_TEMP_CHILD, current, NULL))
          return inventory_fail (scan,
                     WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO, WYRELOG_E_NOMEM);
        rc = inventory_add_anomaly (scan, state,
                WYL_FACT_ARTIFACT_INVENTORY_UNREADABLE_ENTRY);
        if (rc != WYRELOG_E_OK)
          return rc;
        goto next_child;
      }
      CloseHandle (handle);
      if (!inventory_add_digest (state, 2, current->file_name, units,
          WYL_WIN_INVENTORY_CLASS_TEMP_CHILD, current, &metadata))
        return inventory_fail (scan, WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO,
                   WYRELOG_E_NOMEM);
      if (!metadata.identity_matches_listing) {
        rc = inventory_add_anomaly (scan, state,
                WYL_FACT_ARTIFACT_INVENTORY_SUBSTITUTED_ENTRY);
      } else if (metadata.links != 1) {
        rc = inventory_add_anomaly (scan, state,
                WYL_FACT_ARTIFACT_INVENTORY_AMBIGUOUS_ENTRY);
      } else if (metadata.directory || metadata.reparse
          || metadata.delete_pending || !metadata.acl_valid) {
        rc = inventory_add_anomaly (scan, state,
                WYL_FACT_ARTIFACT_INVENTORY_MALFORMED_ENTRY);
      } else {
        rc = inventory_add_bytes (scan, &scan->temporary, &metadata);
      }
      if (rc != WYRELOG_E_OK)
        return rc;
next_child:
      if (current->next_entry_offset == 0)
        break;
      current = (WylFileIdExtdDirInfo *) ((BYTE *) current
          + current->next_entry_offset);
    }
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
inventory_scan (WylFactArtifactWinLocator *locator, const gchar *stage_name,
    const gchar *rollback_name, WylFactArtifactWinInventoryScan *out_scan,
    WylFactArtifactMainTransitionEntryEvidence *out_entries)
{
  BYTE buffer[64 * 1024];
  WylWinInventoryState state = { 0 };
  gboolean restart = TRUE;
  guint root_count = 0;
  wyrelog_error_t rc;
  if (out_scan != NULL)
    memset (out_scan, 0, sizeof *out_scan);
  if (out_entries != NULL)
    memset (out_entries, 0, sizeof (*out_entries)
        * WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_COUNT);
  if (locator == NULL || out_scan == NULL)
    return WYRELOG_E_INVALID;
  out_scan->failure_status = WYL_FACT_ARTIFACT_INVENTORY_STATUS_INVALID;
  for (guint i = 0; i <= WYL_FACT_ARTIFACT_INVENTORY_LOCK; i++)
    out_scan->fixed[i].allocation_supported = TRUE;
  out_scan->temporary.allocation_supported = TRUE;
  rc = wyl_fact_artifact_win_locator_revalidate (locator);
  if (rc != WYRELOG_E_OK)
    return inventory_fail (out_scan,
               rc == WYRELOG_E_POLICY ? WYL_FACT_ARTIFACT_INVENTORY_STATUS_POLICY
        : WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO, rc);
  out_scan->directory_identity = locator->identity;
  state.digests = g_array_sized_new (FALSE, FALSE,
          sizeof (WylWinInventoryDigest), 64);
  if (state.digests == NULL)
    return inventory_fail (out_scan, WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO,
               WYRELOG_E_NOMEM);
  if (inventory_enumeration_fault_take ()) {
    rc = inventory_fail (out_scan, WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO,
            WYRELOG_E_IO);
    goto done;
  }
  for (;;) {
    FILE_INFO_BY_HANDLE_CLASS klass = (FILE_INFO_BY_HANDLE_CLASS)
        (restart ? WYL_FILE_ID_EXTD_DIRECTORY_RESTART_INFO
        : WYL_FILE_ID_EXTD_DIRECTORY_INFO);
    if (!GetFileInformationByHandleEx (locator->directory, klass, buffer,
        sizeof buffer)) {
      DWORD error = GetLastError ();
      if (error == ERROR_NO_MORE_FILES)
        break;
      rc = inventory_fail (out_scan,
              error == ERROR_MORE_DATA
              ? WYL_FACT_ARTIFACT_INVENTORY_STATUS_OVERFLOW
              : WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO,
              error == ERROR_MORE_DATA ? WYRELOG_E_POLICY : WYRELOG_E_IO);
      goto done;
    }
    restart = FALSE;
    WylFileIdExtdDirInfo *current = (WylFileIdExtdDirInfo *) buffer;
    for (;;) {
      g_autofree gchar *name = NULL;
      WylWinInventoryMetadata metadata = { 0 };
      HANDLE handle = INVALID_HANDLE_VALUE;
      gboolean case_collision = FALSE;
      WylWinInventoryClass classification = WYL_WIN_INVENTORY_CLASS_UNKNOWN;
      gsize units;
      gint slot = -1;
      gint transition_slot = -1;
      if (!inventory_entry_bounds_valid (buffer, current)) {
        rc = inventory_fail (out_scan,
                WYL_FACT_ARTIFACT_INVENTORY_STATUS_POLICY, WYRELOG_E_POLICY);
        goto done;
      }
      units = current->file_name_length / sizeof (WCHAR);
      if ((units == 1 && current->file_name[0] == L'.')
          || (units == 2 && current->file_name[0] == L'.'
          && current->file_name[1] == L'.'))
        goto next_root;
      if (root_count++ >= WYL_WIN_INVENTORY_MAX_ROOT_ENTRIES
          || state.total_entries++ >= WYL_WIN_INVENTORY_MAX_TOTAL_ENTRIES) {
        rc = inventory_fail (out_scan,
                WYL_FACT_ARTIFACT_INVENTORY_STATUS_OVERFLOW, WYRELOG_E_POLICY);
        goto done;
      }
      if (units > WYL_WIN_INVENTORY_MAX_NAME_UNITS) {
        if (!inventory_add_digest (&state, 1, current->file_name, units,
            WYL_WIN_INVENTORY_CLASS_MALFORMED, current, NULL)) {
          rc = inventory_fail (out_scan,
                  WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO, WYRELOG_E_NOMEM);
          goto done;
        }
        rc = inventory_add_anomaly (out_scan, &state,
                WYL_FACT_ARTIFACT_INVENTORY_OVER_LIMIT_ENTRY);
        if (rc != WYRELOG_E_OK)
          goto done;
        goto next_root;
      }
      name = g_utf16_to_utf8 ((const gunichar2 *) current->file_name,
              units, NULL, NULL, NULL);
      if (name == NULL || !safe_component (name)) {
        if (!inventory_add_digest (&state, 1, current->file_name, units,
            WYL_WIN_INVENTORY_CLASS_MALFORMED, current, NULL)) {
          rc = inventory_fail (out_scan,
                  WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO, WYRELOG_E_NOMEM);
          goto done;
        }
        rc = inventory_add_anomaly (out_scan, &state,
                WYL_FACT_ARTIFACT_INVENTORY_MALFORMED_ENTRY);
        if (rc != WYRELOG_E_OK)
          goto done;
        goto next_root;
      }
      slot = inventory_fixed_slot (name, &case_collision);
      if (slot < 0 && !case_collision && stage_name != NULL) {
        if (strcmp (name, stage_name) == 0)
          transition_slot = WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_STAGE;
        else if (strcmp (name, rollback_name) == 0)
          transition_slot = WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_ROLLBACK;
        else if (g_ascii_strcasecmp (name, stage_name) == 0
            || g_ascii_strcasecmp (name, rollback_name) == 0)
          case_collision = TRUE;
      }
      if (slot >= 0)
        classification = WYL_WIN_INVENTORY_CLASS_FIXED;
      else if (case_collision)
        classification = WYL_WIN_INVENTORY_CLASS_MALFORMED;
      else if (inventory_temp_root_name (name))
        classification = WYL_WIN_INVENTORY_CLASS_TEMP_ROOT;

      if (case_collision) {
        if (!inventory_add_digest (&state, 1, current->file_name, units,
            classification, current, NULL)) {
          rc = inventory_fail (out_scan,
                  WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO, WYRELOG_E_NOMEM);
          goto done;
        }
        rc = inventory_add_anomaly (out_scan, &state,
                WYL_FACT_ARTIFACT_INVENTORY_AMBIGUOUS_ENTRY);
        if (rc != WYRELOG_E_OK)
          goto done;
        goto next_root;
      }
      if (slot >= 0 && inventory_fixed_metadata_fault_take ()) {
        rc = inventory_fail (out_scan,
                WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO, WYRELOG_E_IO);
        goto done;
      }
      if (classification == WYL_WIN_INVENTORY_CLASS_TEMP_ROOT
          && inventory_temp_metadata_fault_take ()) {
        rc = inventory_fail (out_scan,
                WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO, WYRELOG_E_IO);
        goto done;
      }
      rc = inventory_open_relative (locator->directory, name,
              slot >= 0 ? 0
              : classification == WYL_WIN_INVENTORY_CLASS_TEMP_ROOT ? 1 : -1,
              &handle);
      if (rc == WYRELOG_E_OK)
        rc = inventory_query_metadata (locator, handle, current, &state,
                &metadata);
      if (rc != WYRELOG_E_OK) {
        if (valid_handle (handle))
          CloseHandle (handle);
        if (slot >= 0) {
          rc = inventory_fail (out_scan,
                  rc == WYRELOG_E_POLICY
              ? WYL_FACT_ARTIFACT_INVENTORY_STATUS_POLICY
              : WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO, rc);
          goto done;
        }
        if (!inventory_add_digest (&state, 1, current->file_name, units,
            classification, current, NULL)) {
          rc = inventory_fail (out_scan,
                  WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO, WYRELOG_E_NOMEM);
          goto done;
        }
        rc = inventory_add_anomaly (out_scan, &state,
                WYL_FACT_ARTIFACT_INVENTORY_UNREADABLE_ENTRY);
        if (rc != WYRELOG_E_OK)
          goto done;
        goto next_root;
      }
      if (!inventory_add_digest (&state, 1, current->file_name, units,
          classification, current, &metadata)) {
        CloseHandle (handle);
        rc = inventory_fail (out_scan,
                WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO, WYRELOG_E_NOMEM);
        goto done;
      }
      if (slot >= 0) {
        WylFactArtifactWinInventoryValue *value = &out_scan->fixed[slot];
        gboolean malformed = value->present || !metadata.identity_matches_listing
            || metadata.directory || metadata.reparse
            || metadata.delete_pending || metadata.links != 1
            || !metadata.acl_valid;
        if (malformed && out_entries == NULL) {
          CloseHandle (handle);
          rc = inventory_fail (out_scan,
                  WYL_FACT_ARTIFACT_INVENTORY_STATUS_POLICY, WYRELOG_E_POLICY);
          goto done;
        }
        if (malformed) {
          rc = inventory_add_anomaly (out_scan, &state,
                  metadata.links > 1
                  ? WYL_FACT_ARTIFACT_INVENTORY_AMBIGUOUS_ENTRY
                  : metadata.identity_matches_listing
                  ? WYL_FACT_ARTIFACT_INVENTORY_MALFORMED_ENTRY
                  : WYL_FACT_ARTIFACT_INVENTORY_SUBSTITUTED_ENTRY);
          if (rc != WYRELOG_E_OK) {
            CloseHandle (handle);
            goto done;
          }
        }
        value->present = TRUE;
        value->identity = metadata.identity;
        value->logical_bytes = metadata.logical_bytes;
        value->allocation_supported = metadata.allocation_supported;
        value->allocated_bytes = metadata.allocated_bytes;
        if (out_entries != NULL
            && slot == WYL_FACT_ARTIFACT_INVENTORY_MAIN)
          inventory_transition_value_from_metadata (&metadata,
              &out_entries[WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_MAIN]);
      } else if (classification == WYL_WIN_INVENTORY_CLASS_TEMP_ROOT) {
        if (!metadata.identity_matches_listing || !metadata.directory
            || metadata.reparse || metadata.delete_pending
            || !metadata.acl_valid) {
          rc = inventory_add_anomaly (out_scan, &state,
                  WYL_FACT_ARTIFACT_INVENTORY_MALFORMED_ENTRY);
        } else if (state.temp_roots++ >= WYL_WIN_INVENTORY_MAX_TEMP_ROOTS) {
          rc = inventory_fail (out_scan,
                  WYL_FACT_ARTIFACT_INVENTORY_STATUS_OVERFLOW, WYRELOG_E_POLICY);
        } else {
          out_scan->temporary.present = TRUE;
          rc = inventory_scan_temp_root (locator, handle, out_scan, &state);
        }
      } else if (transition_slot >= 0) {
        inventory_transition_value_from_metadata (&metadata,
            &out_entries[transition_slot]);
        if (!metadata.identity_matches_listing)
          rc = inventory_add_anomaly (out_scan, &state,
                  WYL_FACT_ARTIFACT_INVENTORY_SUBSTITUTED_ENTRY);
        else if (metadata.links != 1)
          rc = inventory_add_anomaly (out_scan, &state,
                  WYL_FACT_ARTIFACT_INVENTORY_AMBIGUOUS_ENTRY);
        else if (metadata.directory || metadata.reparse
            || metadata.delete_pending || !metadata.acl_valid)
          rc = inventory_add_anomaly (out_scan, &state,
                  WYL_FACT_ARTIFACT_INVENTORY_MALFORMED_ENTRY);
        else
          rc = inventory_add_anomaly (out_scan, &state,
                  WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY);
      } else if (!metadata.identity_matches_listing) {
        rc = inventory_add_anomaly (out_scan, &state,
                WYL_FACT_ARTIFACT_INVENTORY_SUBSTITUTED_ENTRY);
      } else if (metadata.links != 1) {
        rc = inventory_add_anomaly (out_scan, &state,
                WYL_FACT_ARTIFACT_INVENTORY_AMBIGUOUS_ENTRY);
      } else if (metadata.directory || metadata.reparse
          || metadata.delete_pending || !metadata.acl_valid) {
        rc = inventory_add_anomaly (out_scan, &state,
                WYL_FACT_ARTIFACT_INVENTORY_MALFORMED_ENTRY);
      } else {
        rc = inventory_add_anomaly (out_scan, &state,
                WYL_FACT_ARTIFACT_INVENTORY_UNKNOWN_ENTRY);
      }
      CloseHandle (handle);
      if (rc != WYRELOG_E_OK)
        goto done;
next_root:
      if (current->next_entry_offset == 0)
        break;
      current = (WylFileIdExtdDirInfo *) ((BYTE *) current
          + current->next_entry_offset);
    }
  }
  rc = wyl_fact_artifact_win_locator_revalidate (locator);
  if (rc != WYRELOG_E_OK) {
    rc = inventory_fail (out_scan,
            rc == WYRELOG_E_POLICY ? WYL_FACT_ARTIFACT_INVENTORY_STATUS_POLICY
        : WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO, rc);
    goto done;
  }
  if (state.allocation_unsupported) {
    rc = inventory_fail (out_scan,
            WYL_FACT_ARTIFACT_INVENTORY_STATUS_UNSUPPORTED_ALLOCATION,
            WYRELOG_E_POLICY);
    goto done;
  }
  if (!inventory_finish_fingerprint (&state, &out_scan->directory_identity,
      &out_scan->fingerprint)) {
    rc = inventory_fail (out_scan, WYL_FACT_ARTIFACT_INVENTORY_STATUS_IO,
            WYRELOG_E_IO);
    goto done;
  }
  rc = WYRELOG_E_OK;
done:
  g_array_unref (state.digests);
  return rc;
}

wyrelog_error_t
wyl_fact_artifact_win_locator_inventory_scan (WylFactArtifactWinLocator *locator,
    WylFactArtifactWinInventoryScan *out_scan)
{
  return inventory_scan (locator, NULL, NULL, out_scan, NULL);
}

wyrelog_error_t
wyl_fact_artifact_win_locator_transition_inventory_scan
  (WylFactArtifactWinLocator *locator, const gchar *stage_name,
    const gchar *rollback_name, WylFactArtifactWinInventoryScan *out_scan,
    WylFactArtifactMainTransitionEntryEvidence out_entries
    [WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_COUNT])
{
  if (!safe_component (stage_name) || !safe_component (rollback_name)
      || strcmp (stage_name, rollback_name) == 0 || out_entries == NULL)
    return WYRELOG_E_INVALID;
  return inventory_scan (locator, stage_name, rollback_name, out_scan,
             out_entries);
}

wyrelog_error_t
wyl_fact_artifact_win_locator_new (const WylFactGraphDirectory *directory,
    WylFactArtifactWinLocator **out_locator)
{
  WylFactArtifactWinLocator *locator;
  WylFactGraphWinIdentity observed = { 0 };
  WylFactGraphWinTokenIdentity token = { 0 };
  HANDLE duplicate = INVALID_HANDLE_VALUE;
  wyrelog_error_t rc;
  if (out_locator != NULL)
    *out_locator = NULL;
  if (directory == NULL || out_locator == NULL
      || !valid_handle ((HANDLE) directory->graph_handle))
    return WYRELOG_E_INVALID;
  rc = wyl_fact_graph_win_token_identity_init (&token);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!DuplicateHandle (GetCurrentProcess (), (HANDLE) directory->graph_handle,
      GetCurrentProcess (), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
    rc = WYRELOG_E_IO;
    goto out_token;
  }
  if (!SetHandleInformation (duplicate, HANDLE_FLAG_INHERIT, 0)) {
    CloseHandle (duplicate);
    rc = WYRELOG_E_IO;
    goto out_token;
  }
  rc = file_identity (duplicate, TRUE, &observed);
  if (rc != WYRELOG_E_OK || !identity_equal (&observed,
      &directory->graph_identity)) {
    CloseHandle (duplicate);
    rc = rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
    goto out_token;
  }
  locator = g_try_new0 (WylFactArtifactWinLocator, 1);
  if (locator == NULL) {
    CloseHandle (duplicate);
    rc = WYRELOG_E_NOMEM;
    goto out_token;
  }
  locator->directory = duplicate;
  locator->identity = observed;
  locator->owner = token.user;
  token.user = NULL;
  *out_locator = locator;
  wyl_fact_graph_win_token_identity_clear (&token);
  return WYRELOG_E_OK;

out_token:
  wyl_fact_graph_win_token_identity_clear (&token);
  return rc;
}

wyrelog_error_t
wyl_fact_artifact_win_locator_revalidate (WylFactArtifactWinLocator *locator)
{
  WylFactGraphWinIdentity observed = { 0 };
  DWORD flags = 0;
  if (locator == NULL || !valid_handle (locator->directory))
    return WYRELOG_E_INVALID;
  if (!GetHandleInformation (locator->directory, &flags))
    return WYRELOG_E_POLICY;
  if ((flags & HANDLE_FLAG_INHERIT) != 0)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = file_identity (locator->directory, TRUE, &observed);
  return rc == WYRELOG_E_OK && !identity_equal (&observed, &locator->identity)
      ? WYRELOG_E_POLICY : rc;
}

const WylFactGraphWinIdentity *
wyl_fact_artifact_win_locator_identity (const WylFactArtifactWinLocator
    *locator)
{
  return locator != NULL ? &locator->identity : NULL;
}

void
wyl_fact_artifact_win_locator_free (WylFactArtifactWinLocator *locator)
{
  if (locator == NULL)
    return;
  /* A raw CloseHandle plus numeric reuse must not close a foreign directory
   * object during ordinary destructor cleanup. */
  if (valid_handle (locator->directory)
      && wyl_fact_artifact_win_locator_revalidate (locator) == WYRELOG_E_OK)
    CloseHandle (locator->directory);
  g_free (locator->owner);
  g_free (locator);
}

wyrelog_error_t
wyl_fact_artifact_win_locator_open (WylFactArtifactWinLocator *locator,
    const gchar *name, ACCESS_MASK access, gboolean create_new,
    WylFactArtifactWinEntry **out_entry)
{
  WylNtCreateFile create = nt_create_file ();
  g_autofree gunichar2 *wide = NULL;
  glong units = 0;
  UNICODE_STRING object_name = { 0 };
  OBJECT_ATTRIBUTES attributes = { 0 };
  IO_STATUS_BLOCK iosb = { 0 };
  WylFactArtifactWinEntry *entry;
  HANDLE handle = INVALID_HANDLE_VALUE;
  WylFactGraphWinIdentity identity = { 0 };
  WylFactGraphWinOwnerOnlySecurity security = { 0 };
  wyrelog_error_t rc;
  if (out_entry != NULL)
    *out_entry = NULL;
  if (out_entry == NULL || create == NULL)
    return WYRELOG_E_INVALID;
  if ((rc = wyl_fact_artifact_win_locator_revalidate (locator)) != WYRELOG_E_OK)
    return rc;
  if ((rc = wide_component (name, &wide, &units)) != WYRELOG_E_OK)
    return rc;
  if (create_new) {
    rc = wyl_fact_graph_win_owner_only_security_init_for_user (&security,
            locator->owner, 0);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  object_name.Length = (USHORT) (units * sizeof (WCHAR));
  object_name.MaximumLength = object_name.Length;
  object_name.Buffer = (PWSTR) wide;
  attributes.Length = sizeof attributes;
  attributes.RootDirectory = locator->directory;
  attributes.ObjectName = &object_name;
  attributes.Attributes = OBJ_CASE_INSENSITIVE;
  attributes.SecurityDescriptor = create_new ? &security.descriptor : NULL;
  NTSTATUS status = create (&handle,
          access | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE, &attributes,
          &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
          create_new ? FILE_CREATE : FILE_OPEN,
          FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT
          | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
  wyl_fact_graph_win_owner_only_security_clear (&security);
  if (status < 0 || !valid_handle (handle))
    return nt_error (status);
  if (!SetHandleInformation (handle, HANDLE_FLAG_INHERIT, 0)) {
    CloseHandle (handle);
    return WYRELOG_E_IO;
  }
  rc = file_identity (handle, FALSE, &identity);
  if (rc == WYRELOG_E_OK)
    rc = validate_named_entry (locator->directory, name, &identity);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_win_validate_protected_owner_acl_for_user (handle,
            locator->owner, 0);
  if (rc != WYRELOG_E_OK) {
    CloseHandle (handle);
    return rc;
  }
  entry = g_try_new0 (WylFactArtifactWinEntry, 1);
  if (entry == NULL) {
    CloseHandle (handle);
    return WYRELOG_E_NOMEM;
  }
  entry->name = g_strdup (name);
  if (entry->name == NULL) {
    CloseHandle (handle);
    g_free (entry);
    return WYRELOG_E_NOMEM;
  }
  entry->handle = handle;
  entry->identity = identity;
  *out_entry = entry;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_entry_revalidate (WylFactArtifactWinLocator *locator,
    WylFactArtifactWinEntry *entry)
{
  WylFactGraphWinIdentity observed = { 0 };
  DWORD flags = 0;
  wyrelog_error_t rc = wyl_fact_artifact_win_locator_revalidate (locator);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (entry == NULL || !valid_handle (entry->handle))
    return WYRELOG_E_INVALID;
  if (!GetHandleInformation (entry->handle, &flags)
      || (flags & HANDLE_FLAG_INHERIT))
    return WYRELOG_E_POLICY;
  rc = file_identity (entry->handle, FALSE, &observed);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!identity_equal (&observed, &entry->identity))
    return WYRELOG_E_POLICY;
  rc = validate_named_entry (locator->directory, entry->name, &entry->identity);
  return rc == WYRELOG_E_OK
      ? wyl_fact_graph_win_validate_protected_owner_acl_for_user
           (entry->handle, locator->owner, 0) : rc;
}

wyrelog_error_t
wyl_fact_artifact_win_entry_flush (WylFactArtifactWinLocator *locator,
    WylFactArtifactWinEntry *entry)
{
  wyrelog_error_t rc = wyl_fact_artifact_win_entry_revalidate (locator, entry);
  if (rc != WYRELOG_E_OK)
    return rc;
  return FlushFileBuffers (entry->handle) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_fact_artifact_win_entry_issue_working_handle (WylFactArtifactWinLocator
    *locator, WylFactArtifactWinEntry *entry, HANDLE *out_handle)
{
  if (out_handle != NULL)
    *out_handle = INVALID_HANDLE_VALUE;
  if (locator == NULL || entry == NULL || out_handle == NULL)
    return WYRELOG_E_INVALID;
  /* Issuance is an I/O boundary, not merely a HANDLE duplication.  Retest
   * the retained directory and the current exact name before exposing an
   * owned duplicate: a source moved out and replaced at the canonical name
   * therefore fails closed. */
  wyrelog_error_t rc = wyl_fact_artifact_win_entry_revalidate (locator, entry);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!DuplicateHandle (GetCurrentProcess (), entry->handle,
      GetCurrentProcess (), out_handle, 0, FALSE, DUPLICATE_SAME_ACCESS))
    return WYRELOG_E_IO;
  if (!SetHandleInformation (*out_handle, HANDLE_FLAG_INHERIT, 0)) {
    CloseHandle (*out_handle);
    *out_handle = INVALID_HANDLE_VALUE;
    return WYRELOG_E_IO;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
mutation_precondition (WylFactArtifactWinLocator *locator,
    WylFactArtifactWinEntry *entry)
{
  return wyl_fact_artifact_win_entry_revalidate (locator, entry);
}

static wyrelog_error_t
entry_rename (WylFactArtifactWinLocator *locator,
    WylFactArtifactWinEntry *entry, const gchar *destination,
    gboolean replace_existing, WylFactArtifactWinMutationEffect *out_effect)
{
  WylNtSetInformationFile set = nt_set_information_file ();
  g_autofree gunichar2 *wide = NULL;
  glong units = 0;
  IO_STATUS_BLOCK iosb = { 0 };
  if (out_effect != NULL)
    *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED;
  if (out_effect == NULL)
    return WYRELOG_E_INVALID;
  if (set == NULL)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = mutation_precondition (locator, entry);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = wide_component (destination, &wide, &units)) != WYRELOG_E_OK)
    return rc;
  gsize bytes = (gsize) units * sizeof (WCHAR);
  NTSTATUS status = 0;
#ifdef WYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS
  NTSTATUS injected_status =
      wyl_fact_artifact_win_locator_take_next_rename_status_for_test ();
  if (injected_status != 0) {
    status = injected_status;
  } else
#endif
  if (replace_existing) {
    /* The replaced link's file is still open through the caller's own
     * destination authority, and the kernel refuses a classic replace on the
     * target's open count alone.  Only POSIX semantics can linearize that,
     * and it unlinks the replaced name in the same operation.
     *
     * The credential-operation storage answers the same kernel rule the
     * other way, by closing its destination before the rename
     * (auth/service-credential-operation-storage-windows-private.c).  That
     * is sound there and unavailable here: it opens the destination
     * transiently, for FILE_READ_ATTRIBUTES only, purely to reject a reparse
     * point, and holds no authority over it afterwards -- it even carries a
     * test hook for injecting a race into the window that close-then-rename
     * opens.  This module's destination binding holds live authority that
     * has to survive the replacement, so the two must not be reconciled. */
    gsize size = offsetof (WylFileRenameInfoEx, file_name) + bytes;
    WylFileRenameInfoEx *info = g_try_malloc0 (size);
    if (info == NULL)
      return WYRELOG_E_NOMEM;
    info->flags = WYL_FILE_RENAME_REPLACE_IF_EXISTS
        | WYL_FILE_RENAME_POSIX_SEMANTICS;
    info->root_directory = locator->directory;
    info->file_name_length = (ULONG) bytes;
    memcpy (info->file_name, wide, bytes);
    status = set (entry->handle, &iosb, info, (ULONG) size,
            WYL_NT_FILE_RENAME_INFO_EX_CLASS);
    g_free (info);
  } else {
    /* No target link exists here, so the open-count rule never applies and
     * the classic class keeps working on every supported filesystem. */
    gsize size = offsetof (WylFileRenameInfo, file_name) + bytes;
    WylFileRenameInfo *info = g_try_malloc0 (size);
    if (info == NULL)
      return WYRELOG_E_NOMEM;
    info->replace_if_exists = FALSE;
    info->root_directory = locator->directory;
    info->file_name_length = (ULONG) bytes;
    memcpy (info->file_name, wide, bytes);
    status = set (entry->handle, &iosb, info, (ULONG) size,
            WYL_NT_FILE_RENAME_INFO_CLASS);
    g_free (info);
  }
  if (status < 0) {
    /* A missing class and a denied authority both map to POLICY.  Label the
     * capability gap here so the two stay distinguishable without widening
     * the public error ABI. */
    if (replace_existing && nt_unsupported_info_class (status)
        && locator != NULL && !locator->unsupported_rename_class_logged) {
      locator->unsupported_rename_class_logged = TRUE;
      WYL_LOG_INFO (WYL_LOG_SECTION_IO, "native artifact replacement is "
          "unsupported by this kernel or filesystem (status 0x%08lX)",
          (unsigned long) status);
    }
    return nt_mutation_error (status);
  }
  g_free (entry->name);
  entry->name = g_strdup (destination);
  if (entry->name == NULL) {
    /* Rename already linearized; callers must reconcile through the applied
     * effect rather than treating allocation failure as an undoable retry. */
    *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED;
    return WYRELOG_E_NOMEM;
  }
  *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_entry_rename_no_replace (WylFactArtifactWinLocator
    *locator, WylFactArtifactWinEntry *entry, const gchar *destination,
    WylFactArtifactWinMutationEffect *out_effect)
{
  return entry_rename (locator, entry, destination, FALSE, out_effect);
}

wyrelog_error_t
wyl_fact_artifact_win_entry_rename_replace_verified (WylFactArtifactWinLocator
    *locator, WylFactArtifactWinEntry *entry, const gchar *destination,
    WylFactArtifactWinMutationEffect *out_effect)
{
  return entry_rename (locator, entry, destination, TRUE, out_effect);
}

wyrelog_error_t
wyl_fact_artifact_win_entry_delete_exact (WylFactArtifactWinLocator *locator,
    WylFactArtifactWinEntry *entry,
    WylFactArtifactWinMutationEffect *out_effect)
{
  WylNtSetInformationFile set = nt_set_information_file ();
  if (out_effect != NULL)
    *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED;
  if (out_effect == NULL)
    return WYRELOG_E_INVALID;
  if (set == NULL)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = mutation_precondition (locator, entry);
  if (rc != WYRELOG_E_OK)
    return rc;
  WylFileDispositionInfo info = { TRUE };
  IO_STATUS_BLOCK iosb = { 0 };
  NTSTATUS status = set (entry->handle, &iosb, &info, sizeof info,
          WYL_NT_FILE_DISPOSITION_INFO_CLASS);
  if (status < 0)
    return nt_mutation_error (status);
  *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_locator_flush_directory (WylFactArtifactWinLocator
    *locator)
{
  wyrelog_error_t rc = wyl_fact_artifact_win_locator_revalidate (locator);
  DWORD error;
#ifdef WYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS
  LONG forced;
#endif
  if (rc != WYRELOG_E_OK)
    return rc;
#ifdef WYL_ENABLE_WINDOWS_ARTIFACT_TEST_HOOKS
  forced = InterlockedExchange (&next_directory_flush_error, ERROR_SUCCESS);
  if (forced == ERROR_SUCCESS && FlushFileBuffers (locator->directory))
    return WYRELOG_E_OK;
  error = forced == ERROR_SUCCESS ? GetLastError () : (DWORD) forced;
#else
  /* Unhooked shipped form: the native result is the only result, and no
   * armable state is read on this path. */
  if (FlushFileBuffers (locator->directory))
    return WYRELOG_E_OK;
  error = GetLastError ();
#endif
  /* A volume which cannot flush a directory offers no durable namespace
   * evidence.  Do not turn that into success: lifecycle callers must retain
   * their APPLIED/UNKNOWN reconciliation result and fail closed. */
  if (error == ERROR_NOT_SUPPORTED || error == ERROR_INVALID_FUNCTION
      || error == ERROR_INVALID_HANDLE)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_IO;
}

const WylFactGraphWinIdentity *
wyl_fact_artifact_win_entry_identity (const WylFactArtifactWinEntry *entry)
{
  return entry == NULL ? NULL : &entry->identity;
}

const gchar *
wyl_fact_artifact_win_entry_name (const WylFactArtifactWinEntry *entry)
{
  return entry != NULL ? entry->name : NULL;
}

void
wyl_fact_artifact_win_entry_free (WylFactArtifactWinEntry *entry)
{
  if (entry == NULL)
    return;
  /* Do not close an externally-closed/reused numeric HANDLE.  The entry may
   * be stale after an ownership violation, but freeing its metadata must not
   * mutate a foreign object. */
  if (valid_handle (entry->handle)
      && terminal_handle_matches_identity (entry->handle, FALSE,
      &entry->identity))
    CloseHandle (entry->handle);
  g_free (entry->name);
  g_free (entry);
}

/* The temp root is intentionally opened through the held graph directory,
 * not through a path reconstructed from it.  The same owner-only descriptor
 * that protects fixed artifacts is stamped at creation and audited again
 * before every descendant operation. */
wyrelog_error_t
wyl_fact_artifact_win_locator_create_directory (WylFactArtifactWinLocator
    *locator, const gchar *name, WylFactArtifactWinDirectory **out_directory)
{
  WylNtCreateFile create = nt_create_file ();
  g_autofree gunichar2 *wide = NULL;
  glong units = 0;
  UNICODE_STRING object_name = { 0 };
  OBJECT_ATTRIBUTES attributes = { 0 };
  IO_STATUS_BLOCK iosb = { 0 };
  WylFactGraphWinOwnerOnlySecurity security = { 0 };
  WylFactArtifactWinDirectory *directory = NULL;
  WylFactGraphWinIdentity identity = { 0 };
  HANDLE handle = INVALID_HANDLE_VALUE;
  wyrelog_error_t rc;

  if (out_directory != NULL)
    *out_directory = NULL;
  if (locator == NULL || out_directory == NULL || create == NULL)
    return WYRELOG_E_INVALID;
  if ((rc = wyl_fact_artifact_win_locator_revalidate (locator)) != WYRELOG_E_OK
      || (rc = wide_component (name, &wide, &units)) != WYRELOG_E_OK)
    return rc;
  rc = wyl_fact_graph_win_owner_only_security_init_for_user (&security,
          locator->owner, 0);
  if (rc != WYRELOG_E_OK)
    return rc;
  object_name.Length = (USHORT) (units * sizeof (WCHAR));
  object_name.MaximumLength = object_name.Length;
  object_name.Buffer = (PWSTR) wide;
  attributes.Length = sizeof attributes;
  attributes.RootDirectory = locator->directory;
  attributes.ObjectName = &object_name;
  attributes.Attributes = OBJ_CASE_INSENSITIVE;
  attributes.SecurityDescriptor = &security.descriptor;
  NTSTATUS status = create (&handle,
          FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_READ_ATTRIBUTES | READ_CONTROL
          | DELETE | SYNCHRONIZE, &attributes, &iosb, NULL,
          FILE_ATTRIBUTE_DIRECTORY,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE,
          FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT |
          FILE_SYNCHRONOUS_IO_NONALERT,
          NULL, 0);
  wyl_fact_graph_win_owner_only_security_clear (&security);
  if (status < 0 || !valid_handle (handle))
    return nt_error (status);
  if (!SetHandleInformation (handle, HANDLE_FLAG_INHERIT, 0)) {
    CloseHandle (handle);
    return WYRELOG_E_IO;
  }
  rc = file_identity (handle, TRUE, &identity);
  if (rc == WYRELOG_E_OK)
    rc = validate_named_entry (locator->directory, name, &identity);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_win_validate_protected_owner_acl_for_user (handle,
            locator->owner, 0);
  if (rc != WYRELOG_E_OK) {
    CloseHandle (handle);
    return rc;
  }
  directory = g_try_new0 (WylFactArtifactWinDirectory, 1);
  if (directory == NULL) {
    CloseHandle (handle);
    return WYRELOG_E_NOMEM;
  }
  directory->name = g_strdup (name);
  if (directory->name == NULL) {
    CloseHandle (handle);
    g_free (directory);
    return WYRELOG_E_NOMEM;
  }
  directory->handle = handle;
  directory->identity = identity;
  *out_directory = directory;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_directory_revalidate (WylFactArtifactWinLocator *locator,
    WylFactArtifactWinDirectory *directory)
{
  WylFactGraphWinIdentity observed = { 0 };
  DWORD flags = 0;
  wyrelog_error_t rc = wyl_fact_artifact_win_locator_revalidate (locator);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (directory == NULL || !valid_handle (directory->handle)
      || !GetHandleInformation (directory->handle, &flags)
      || (flags & HANDLE_FLAG_INHERIT) != 0)
    return WYRELOG_E_POLICY;
  rc = file_identity (directory->handle, TRUE, &observed);
  if (rc != WYRELOG_E_OK || !identity_equal (&observed, &directory->identity))
    return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
  rc = validate_named_entry (locator->directory, directory->name,
          &directory->identity);
  return rc == WYRELOG_E_OK
      ? wyl_fact_graph_win_validate_protected_owner_acl_for_user
           (directory->handle, locator->owner, 0) : rc;
}

wyrelog_error_t
wyl_fact_artifact_win_directory_open_file (WylFactArtifactWinLocator *locator,
    WylFactArtifactWinDirectory *directory, const gchar *name,
    ACCESS_MASK access, gboolean create_new,
    WylFactArtifactWinEntry **out_entry)
{
  WylNtCreateFile create = nt_create_file ();
  g_autofree gunichar2 *wide = NULL;
  glong units = 0;
  UNICODE_STRING object_name = { 0 };
  OBJECT_ATTRIBUTES attributes = { 0 };
  IO_STATUS_BLOCK iosb = { 0 };
  WylFactGraphWinOwnerOnlySecurity security = { 0 };
  WylFactArtifactWinEntry *entry = NULL;
  WylFactGraphWinIdentity identity = { 0 };
  HANDLE handle = INVALID_HANDLE_VALUE;
  wyrelog_error_t rc;
  if (out_entry != NULL)
    *out_entry = NULL;
  if (out_entry == NULL || create == NULL)
    return WYRELOG_E_INVALID;
  if ((rc = wyl_fact_artifact_win_directory_revalidate (locator, directory))
      != WYRELOG_E_OK
      || (rc = wide_component (name, &wide, &units)) != WYRELOG_E_OK)
    return rc;
  if (create_new && (rc = wyl_fact_graph_win_owner_only_security_init_for_user
        (&security, locator->owner, 0)) != WYRELOG_E_OK)
    return rc;
  object_name.Length = (USHORT) (units * sizeof (WCHAR));
  object_name.MaximumLength = object_name.Length;
  object_name.Buffer = (PWSTR) wide;
  attributes.Length = sizeof attributes;
  attributes.RootDirectory = directory->handle;
  attributes.ObjectName = &object_name;
  attributes.Attributes = OBJ_CASE_INSENSITIVE;
  attributes.SecurityDescriptor = create_new ? &security.descriptor : NULL;
  NTSTATUS status = create (&handle,
          access | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE, &attributes,
          &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
          create_new ? FILE_CREATE : FILE_OPEN,
          FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT
          | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
  wyl_fact_graph_win_owner_only_security_clear (&security);
  if (status < 0 || !valid_handle (handle))
    return nt_error (status);
  if (!SetHandleInformation (handle, HANDLE_FLAG_INHERIT, 0)) {
    CloseHandle (handle);
    return WYRELOG_E_IO;
  }
  rc = file_identity (handle, FALSE, &identity);
  if (rc == WYRELOG_E_OK)
    rc = validate_named_entry (directory->handle, name, &identity);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_win_validate_protected_owner_acl_for_user (handle,
            locator->owner, 0);
  if (rc != WYRELOG_E_OK) {
    CloseHandle (handle);
    return rc;
  }
  entry = g_try_new0 (WylFactArtifactWinEntry, 1);
  if (entry == NULL || (entry->name = g_strdup (name)) == NULL) {
    CloseHandle (handle);
    g_free (entry);
    return WYRELOG_E_NOMEM;
  }
  entry->handle = handle;
  entry->identity = identity;
  *out_entry = entry;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_directory_entry_revalidate (WylFactArtifactWinLocator
    *locator, WylFactArtifactWinDirectory *directory,
    WylFactArtifactWinEntry *entry)
{
  WylFactGraphWinIdentity observed = { 0 };
  DWORD flags = 0;
  wyrelog_error_t rc = wyl_fact_artifact_win_directory_revalidate (locator,
          directory);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (entry == NULL || !valid_handle (entry->handle)
      || !GetHandleInformation (entry->handle, &flags)
      || (flags & HANDLE_FLAG_INHERIT) != 0)
    return WYRELOG_E_POLICY;
  rc = file_identity (entry->handle, FALSE, &observed);
  if (rc != WYRELOG_E_OK || !identity_equal (&observed, &entry->identity))
    return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
  rc = validate_named_entry (directory->handle, entry->name, &entry->identity);
  return rc == WYRELOG_E_OK
      ? wyl_fact_graph_win_validate_protected_owner_acl_for_user
           (entry->handle, locator->owner, 0) : rc;
}

wyrelog_error_t
wyl_fact_artifact_win_directory_entry_issue_working_handle
  (WylFactArtifactWinLocator * locator,
    WylFactArtifactWinDirectory * directory, WylFactArtifactWinEntry * entry,
    HANDLE * out_handle) {
  if (out_handle != NULL)
    *out_handle = INVALID_HANDLE_VALUE;
  if (out_handle == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = wyl_fact_artifact_win_directory_entry_revalidate
        (locator, directory, entry);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!DuplicateHandle (GetCurrentProcess (), entry->handle,
      GetCurrentProcess (), out_handle, 0, FALSE, DUPLICATE_SAME_ACCESS))
    return WYRELOG_E_IO;
  if (!SetHandleInformation (*out_handle, HANDLE_FLAG_INHERIT, 0)) {
    CloseHandle (*out_handle);
    *out_handle = INVALID_HANDLE_VALUE;
    return WYRELOG_E_IO;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_directory_entry_delete_exact (WylFactArtifactWinLocator
    *locator, WylFactArtifactWinDirectory *directory,
    WylFactArtifactWinEntry *entry,
    WylFactArtifactWinMutationEffect *out_effect)
{
  WylNtSetInformationFile set = nt_set_information_file ();
  WylFileDispositionInfo info = { TRUE };
  IO_STATUS_BLOCK iosb = { 0 };
  if (out_effect != NULL)
    *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED;
  if (out_effect == NULL)
    return WYRELOG_E_INVALID;
  if (set == NULL)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = wyl_fact_artifact_win_directory_entry_revalidate
        (locator, directory, entry);
  if (rc != WYRELOG_E_OK)
    return rc;
  NTSTATUS status = set (entry->handle, &iosb, &info, sizeof info,
          WYL_NT_FILE_DISPOSITION_INFO_CLASS);
  if (status < 0)
    return nt_mutation_error (status);
  *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_directory_delete_empty (WylFactArtifactWinLocator
    *locator, WylFactArtifactWinDirectory *directory,
    WylFactArtifactWinMutationEffect *out_effect)
{
  WylNtSetInformationFile set = nt_set_information_file ();
  WylFileDispositionInfo info = { TRUE };
  IO_STATUS_BLOCK iosb = { 0 };
  if (out_effect != NULL)
    *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED;
  if (out_effect == NULL)
    return WYRELOG_E_INVALID;
  if (set == NULL)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = wyl_fact_artifact_win_directory_revalidate (locator,
          directory);
  if (rc != WYRELOG_E_OK)
    return rc;
  NTSTATUS status = set (directory->handle, &iosb, &info, sizeof info,
          WYL_NT_FILE_DISPOSITION_INFO_CLASS);
  if (status < 0)
    return nt_mutation_error (status);
  *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED;
  return WYRELOG_E_OK;
}

void
wyl_fact_artifact_win_directory_free (WylFactArtifactWinDirectory *directory)
{
  if (directory == NULL)
    return;
  close_directory_if_exact (directory);
  g_free (directory->name);
  g_free (directory);
}

WylFactArtifactWinEntry *
wyl_fact_artifact_win_directory_get_entry (WylFactArtifactWinDirectory *directory)
{
  if (directory == NULL)
    return NULL;
  return (WylFactArtifactWinEntry *) directory;
}

wyrelog_error_t
wyl_fact_artifact_win_directory_list_entries (WylFactArtifactWinLocator *locator,
    WylFactArtifactWinDirectory *directory, GPtrArray **out_entries)
{
  BYTE buffer[64 * 1024];
  gboolean restart = TRUE;
  GPtrArray *entries = NULL;
  wyrelog_error_t rc;

  if (out_entries != NULL)
    *out_entries = NULL;

  if (locator == NULL || directory == NULL || out_entries == NULL)
    return WYRELOG_E_INVALID;

  if ((rc = wyl_fact_artifact_win_directory_revalidate (locator, directory))
      != WYRELOG_E_OK)
    return rc;

  entries = g_ptr_array_new_with_free_func (g_free);

  for (;;) {
    FILE_INFO_BY_HANDLE_CLASS klass = (FILE_INFO_BY_HANDLE_CLASS)
        (restart ? WYL_FILE_ID_EXTD_DIRECTORY_RESTART_INFO
        : WYL_FILE_ID_EXTD_DIRECTORY_INFO);
    if (!GetFileInformationByHandleEx (directory->handle, klass, buffer, sizeof buffer)) {
      DWORD error = GetLastError ();
      if (error == ERROR_NO_MORE_FILES)
        break;
      g_ptr_array_free (entries, TRUE);
      return error == ERROR_MORE_DATA ? WYRELOG_E_POLICY : WYRELOG_E_IO;
    }
    restart = FALSE;
    WylFileIdExtdDirInfo *current = (WylFileIdExtdDirInfo *) buffer;
    for (;;) {
      gsize units = current->file_name_length / sizeof (WCHAR);
      if (units > 0) {
        gchar *utf8_name = g_utf16_to_utf8 (current->file_name, (glong) units, NULL, NULL, NULL);
        if (utf8_name != NULL) {
          if (g_strcmp0 (utf8_name, ".") != 0 && g_strcmp0 (utf8_name, "..") != 0) {
            g_ptr_array_add (entries, utf8_name);
          } else {
            g_free (utf8_name);
          }
        }
      }
      if (current->next_entry_offset == 0)
        break;
      current = (WylFileIdExtdDirInfo *) ((BYTE *) current + current->next_entry_offset);
    }
  }

  *out_entries = entries;
  return WYRELOG_E_OK;
}
#endif

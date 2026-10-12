/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#endif

#include "fact/offline-backup-bundle-private.h"

#include "fact/graph-locator-private.h"
#include "fact/offline-backup-manifest-private.h"
#include "fact/store-identity-types-private.h"

#include <string.h>

#ifdef G_OS_WIN32
#include <windows.h>
#include <stddef.h>

/* The Windows bundle is read through the handle-relative, proof-carrying
 * locator openers only.  Every entry is a WylFactGraphRegularFile whose
 * handle, identity and size came out of one of them, and every later check
 * either re-queries that held handle or re-opens the name through the same
 * opener and compares.  The volume must keep ACLs and stable file identities,
 * or none of those re-proofs would mean anything; a FAT or exFAT carrier is
 * refused outright. */
typedef struct
{
  gchar *graph_id;
  gchar *name;
  gchar *checksum;
  guint64 length;
  WylFactGraphRegularFile file;
} BundleFile;

struct WylFactOfflineBackupBundle
{
  WylFactGraphResolver directory;
  GBytes *manifest_bytes;
  GPtrArray *files;
  WylFactGraphRegularFile manifest;
  guint8 digest[32];
};

static void
bundle_file_free (gpointer data)
{
  BundleFile *file = data;
  if (file == NULL)
    return;
  wyl_fact_graph_regular_file_clear (&file->file);
  g_free (file->graph_id);
  g_free (file->name);
  g_free (file->checksum);
  g_free (file);
}

static gboolean
win_identity_equal (const WylFactGraphWinIdentity *left,
    const WylFactGraphWinIdentity *right)
{
  return left->volume_serial == right->volume_serial
         && memcmp (left->file_id, right->file_id, sizeof left->file_id) == 0;
}

/* Without persistent ACLs the owner-only contract has nothing to stand on,
 * and without stable file identities every re-proof below would be vacuous. */
static wyrelog_error_t
require_persistent_volume (WylFactOfflineBackupBundle *bundle)
{
  DWORD flags = 0;
  if (!GetVolumeInformationByHandleW ((HANDLE) bundle->directory.handle, NULL,
      0, NULL, NULL, &flags, NULL, 0))
    return WYRELOG_E_IO;
  if ((flags & FILE_PERSISTENT_ACLS) == 0
      || (flags & FILE_SUPPORTS_OPEN_BY_FILE_ID) == 0)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

/* The held object is still a plain regular file of the proven size, with the
 * identity it was opened with: the fstat half of the POSIX check. */
static wyrelog_error_t
held_file_check (const WylFactGraphRegularFile *file, guint64 expected_length)
{
  FILE_BASIC_INFO basic = { 0 };
  FILE_STANDARD_INFO standard = { 0 };
  FILE_ID_INFO id = { 0 };
  HANDLE handle = (HANDLE) file->handle;
  if (handle == NULL || handle == INVALID_HANDLE_VALUE)
    return WYRELOG_E_INVALID;
  if (!GetFileInformationByHandleEx (handle, FileBasicInfo, &basic,
      sizeof basic)
      || !GetFileInformationByHandleEx (handle, FileStandardInfo, &standard,
      sizeof standard)
      || !GetFileInformationByHandleEx (handle, FileIdInfo, &id, sizeof id))
    return WYRELOG_E_IO;
  if ((basic.FileAttributes
      & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0
      || standard.Directory || standard.DeletePending
      || standard.NumberOfLinks != 1 || standard.EndOfFile.QuadPart < 0
      || (guint64) standard.EndOfFile.QuadPart != expected_length
      || id.VolumeSerialNumber != file->identity.volume_serial
      || memcmp (&id.FileId, file->identity.file_id,
      sizeof file->identity.file_id) != 0)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

/* The name still resolves to the held object, through the same opener that
 * admitted it: the fstatat half.  A failure here is tampering, never absence,
 * so a vanished name collapses to a policy refusal. */
static wyrelog_error_t
named_file_check (WylFactOfflineBackupBundle *bundle, const gchar *name,
    const WylFactGraphRegularFile *file, guint64 expected_length)
{
  WylFactGraphRegularFile probe = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  wyrelog_error_t rc = held_file_check (file, expected_length);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_fact_graph_resolver_open_child_regular (&bundle->directory, name,
          &probe);
  if (rc == WYRELOG_E_NOT_FOUND)
    return WYRELOG_E_POLICY;
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!win_identity_equal (&probe.identity, &file->identity)
      || probe.size_bytes != expected_length)
    rc = WYRELOG_E_POLICY;
  wyl_fact_graph_regular_file_clear (&probe);
  return rc;
}

static wyrelog_error_t
open_named_file (WylFactOfflineBackupBundle *bundle, const gchar *name,
    guint64 length, WylFactGraphRegularFile *out_file)
{
  wyrelog_error_t rc = wyl_fact_graph_resolver_open_child_regular
        (&bundle->directory, name, out_file);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (out_file->size_bytes != length) {
    wyl_fact_graph_regular_file_clear (out_file);
    return WYRELOG_E_POLICY;
  }
  return WYRELOG_E_OK;
}

/* Positional read of exactly |length| bytes.  The size was proved before any
 * read, so a short read is a fault, never the end of the file. */
static wyrelog_error_t
read_exact (HANDLE handle, guint64 offset, guint8 *buffer, gsize length)
{
  gsize done = 0;
  while (done < length) {
    OVERLAPPED overlapped = { 0 };
    guint64 position = offset + done;
    DWORD amount = (DWORD) MIN (length - done, (gsize) 0x40000000u);
    DWORD got = 0;
    overlapped.Offset = (DWORD) (position & 0xffffffffu);
    overlapped.OffsetHigh = (DWORD) (position >> 32);
    if (!ReadFile (handle, buffer + done, amount, &got, &overlapped)
        || got == 0)
      return WYRELOG_E_IO;
    done += got;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
hash_file (HANDLE handle, guint64 length, const gchar *expected)
{
  if (expected == NULL || !g_str_has_prefix (expected, "sha256:")
      || strlen (expected) != 71)
    return WYRELOG_E_POLICY;
  g_autoptr (GChecksum) checksum = g_checksum_new (G_CHECKSUM_SHA256);
  if (checksum == NULL)
    return WYRELOG_E_NOMEM;
  guint8 bytes[65536];
  guint64 offset = 0;
  while (offset < length) {
    gsize amount = (gsize) MIN ((guint64) sizeof bytes, length - offset);
    wyrelog_error_t rc = read_exact (handle, offset, bytes, amount);
    if (rc != WYRELOG_E_OK)
      return rc;
    g_checksum_update (checksum, bytes, amount);
    offset += amount;
  }
  return g_strcmp0 (expected + 7, g_checksum_get_string (checksum)) == 0
      ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static gboolean
entry_bounds_valid (const guint8 *buffer, gsize capacity,
    const FILE_ID_BOTH_DIR_INFO *entry)
{
  const guint8 *start = (const guint8 *) entry;
  gsize header = offsetof (FILE_ID_BOTH_DIR_INFO, FileName);
  if (start < buffer || start > buffer + capacity
      || (gsize) (buffer + capacity - start) < header
      || entry->FileNameLength > buffer + capacity - start - header
      || entry->FileNameLength % sizeof (WCHAR) != 0)
    return FALSE;
  if (entry->NextEntryOffset != 0
      && (entry->NextEntryOffset < header
      || entry->NextEntryOffset > buffer + capacity - start))
    return FALSE;
  return TRUE;
}

/* The directory holds exactly the manifest and the artifacts, by their exact
 * spellings.  Names alone decide membership; identity is proved through the
 * held handles.  Alternate data streams are invisible to this enumeration as
 * to every Windows enumeration, and cannot be adopted as an artifact, whose
 * bytes are read through a handle to the unnamed stream; they are a documented
 * residual, not an opening. */
static wyrelog_error_t
verify_entry_set (WylFactOfflineBackupBundle *bundle)
{
  gint64 buffer[8192];
  FILE_INFO_BY_HANDLE_CLASS info_class = FileIdBothDirectoryRestartInfo;
  guint seen = 0;
  for (;;) {
    if (!GetFileInformationByHandleEx ((HANDLE) bundle->directory.handle,
        info_class, buffer, sizeof buffer)) {
      DWORD error = GetLastError ();
      if (error == ERROR_NO_MORE_FILES)
        break;
      return error == ERROR_MORE_DATA ? WYRELOG_E_POLICY : WYRELOG_E_IO;
    }
    info_class = FileIdBothDirectoryInfo;
    for (FILE_ID_BOTH_DIR_INFO * entry = (FILE_ID_BOTH_DIR_INFO *) buffer;;) {
      if (!entry_bounds_valid ((const guint8 *) buffer, sizeof buffer, entry))
        return WYRELOG_E_POLICY;
      glong units = (glong) (entry->FileNameLength / sizeof (WCHAR));
      g_autofree gchar *name = g_utf16_to_utf8 ((const gunichar2 *)
              entry->FileName, units, NULL, NULL, NULL);
      if (name == NULL)
        return WYRELOG_E_POLICY;
      if (g_strcmp0 (name, ".") != 0 && g_strcmp0 (name, "..") != 0) {
        gboolean expected = g_strcmp0 (name, "manifest") == 0;
        for (guint i = 0; !expected && i < bundle->files->len; i++) {
          BundleFile *file = g_ptr_array_index (bundle->files, i);
          expected = g_strcmp0 (name, file->name) == 0;
        }
        if (!expected)
          return WYRELOG_E_POLICY;
        seen++;
      }
      if (entry->NextEntryOffset == 0)
        break;
      entry = (FILE_ID_BOTH_DIR_INFO *) ((guint8 *) entry
          + entry->NextEntryOffset);
    }
  }
  return seen == bundle->files->len + 1 ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static BundleFile *
find_file (WylFactOfflineBackupBundle *bundle, const gchar *graph_id)
{
  for (guint i = 0; i < bundle->files->len; i++) {
    BundleFile *file = g_ptr_array_index (bundle->files, i);
    if (g_strcmp0 (file->graph_id, graph_id) == 0)
      return file;
  }
  return NULL;
}
#endif

#ifndef G_OS_WIN32
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct
{
  gchar *graph_id;
  gchar *name;
  gchar *checksum;
  guint64 length;
  dev_t device;
  ino_t inode;
  gint fd;
} BundleFile;

struct WylFactOfflineBackupBundle
{
  WylFactGraphResolver directory;
  GBytes *manifest_bytes;
  GPtrArray *files;
  gint manifest_fd;
  dev_t manifest_device;
  ino_t manifest_inode;
  guint8 digest[32];
};

static void
bundle_file_free (gpointer data)
{
  BundleFile *file = data;
  if (file == NULL)
    return;
  if (file->fd >= 0)
    close (file->fd);
  g_free (file->graph_id);
  g_free (file->name);
  g_free (file->checksum);
  g_free (file);
}

static wyrelog_error_t
file_stat (gint fd, guint64 expected_length, dev_t *device, ino_t *inode)
{
  struct stat st;
  if (fstat (fd, &st) != 0)
    return WYRELOG_E_IO;
  if (!S_ISREG (st.st_mode) || (st.st_mode & 07777) != 0600
      || st.st_uid != geteuid () || st.st_nlink != 1
      || st.st_size < 0 || (guint64) st.st_size != expected_length)
    return WYRELOG_E_POLICY;
  if (device != NULL)
    *device = st.st_dev;
  if (inode != NULL)
    *inode = st.st_ino;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
open_named_file (WylFactOfflineBackupBundle *bundle, const gchar *name,
    guint64 length, gint *out_fd, dev_t *device, ino_t *inode)
{
  *out_fd = -1;
  gint fd = openat (bundle->directory.fd, name,
          O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0)
    return errno == ENOENT ? WYRELOG_E_NOT_FOUND : WYRELOG_E_POLICY;
  wyrelog_error_t rc = file_stat (fd, length, device, inode);
  if (rc == WYRELOG_E_OK)
    *out_fd = fd;
  else
    close (fd);
  return rc;
}

static wyrelog_error_t
read_exact (gint fd, guint8 *buffer, gsize length)
{
  gsize done = 0;
  while (done < length) {
    ssize_t got = pread (fd, buffer + done, length - done, (off_t) done);
    if (got < 0 && errno == EINTR)
      continue;
    if (got <= 0)
      return WYRELOG_E_IO;
    done += (gsize) got;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
hash_file (gint fd, guint64 length, const gchar *expected)
{
  if (expected == NULL || !g_str_has_prefix (expected, "sha256:")
      || strlen (expected) != 71)
    return WYRELOG_E_POLICY;
  g_autoptr (GChecksum) checksum = g_checksum_new (G_CHECKSUM_SHA256);
  if (checksum == NULL)
    return WYRELOG_E_NOMEM;
  guint8 bytes[65536];
  guint64 offset = 0;
  while (offset < length) {
    gsize amount = (gsize) MIN ((guint64) sizeof bytes, length - offset);
    ssize_t got = pread (fd, bytes, amount, (off_t) offset);
    if (got < 0 && errno == EINTR)
      continue;
    if (got <= 0)
      return WYRELOG_E_IO;
    g_checksum_update (checksum, bytes, (gsize) got);
    offset += (guint64) got;
  }
  return g_strcmp0 (expected + 7, g_checksum_get_string (checksum)) == 0
      ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
verify_named_file (WylFactOfflineBackupBundle *bundle, const gchar *name,
    gint fd, guint64 length, dev_t device, ino_t inode)
{
  wyrelog_error_t rc = file_stat (fd, length, NULL, NULL);
  if (rc != WYRELOG_E_OK)
    return rc;
  struct stat named;
  if (fstatat (bundle->directory.fd, name, &named,
      AT_SYMLINK_NOFOLLOW) != 0)
    return WYRELOG_E_POLICY;
  if (!S_ISREG (named.st_mode) || named.st_dev != device
      || named.st_ino != inode || (named.st_mode & 07777) != 0600
      || named.st_uid != geteuid () || named.st_nlink != 1
      || named.st_size < 0 || (guint64) named.st_size != length)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
verify_entry_set (WylFactOfflineBackupBundle *bundle)
{
  gint copy = openat (bundle->directory.fd, ".",
          O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (copy < 0)
    return WYRELOG_E_IO;
  DIR *dir = fdopendir (copy);
  if (dir == NULL) {
    close (copy);
    return WYRELOG_E_IO;
  }
  rewinddir (dir);
  GHashTable *expected = g_hash_table_new (g_str_hash, g_str_equal);
  g_hash_table_add (expected, "manifest");
  for (guint i = 0; i < bundle->files->len; i++) {
    BundleFile *file = g_ptr_array_index (bundle->files, i);
    g_hash_table_add (expected, file->name);
  }
  guint seen = 0;
  wyrelog_error_t rc = WYRELOG_E_OK;
  errno = 0;
  struct dirent *entry;
  while ((entry = readdir (dir)) != NULL) {
    if (g_strcmp0 (entry->d_name, ".") == 0
        || g_strcmp0 (entry->d_name, "..") == 0)
      continue;
    if (!g_hash_table_contains (expected, entry->d_name)) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    seen++;
    errno = 0;
  }
  if (rc == WYRELOG_E_OK && errno != 0)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && seen != bundle->files->len + 1)
    rc = WYRELOG_E_POLICY;
  g_hash_table_unref (expected);
  closedir (dir);
  return rc;
}

static BundleFile *
find_file (WylFactOfflineBackupBundle *bundle, const gchar *graph_id)
{
  for (guint i = 0; i < bundle->files->len; i++) {
    BundleFile *file = g_ptr_array_index (bundle->files, i);
    if (g_strcmp0 (file->graph_id, graph_id) == 0)
      return file;
  }
  return NULL;
}
#endif

wyrelog_error_t
wyl_fact_offline_backup_bundle_open (const gchar *directory,
    const guint8 trusted_manifest_sha256[32],
    WylFactOfflineBackupBundle **out_bundle)
{
  if (out_bundle != NULL)
    *out_bundle = NULL;
  if (directory == NULL || trusted_manifest_sha256 == NULL
      || out_bundle == NULL)
    return WYRELOG_E_INVALID;
#ifdef G_OS_WIN32
  WylFactOfflineBackupBundle *bundle = g_new0
        (WylFactOfflineBackupBundle, 1);
  bundle->directory = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
  bundle->manifest = (WylFactGraphRegularFile) WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  bundle->files = g_ptr_array_new_with_free_func (bundle_file_free);
  g_autoptr (GChecksum) checksum = NULL;
  g_autoptr (GBytes) canonical = NULL;
  WylFactOfflineBackupManifest manifest = { 0 };
  wyrelog_error_t rc = wyl_fact_graph_resolver_open (directory,
          &bundle->directory);
  if (rc == WYRELOG_E_OK)
    rc = require_persistent_volume (bundle);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_child_regular (&bundle->directory,
            "manifest", &bundle->manifest);
  if (rc != WYRELOG_E_OK)
    goto fail;
  if (bundle->manifest.size_bytes == 0
      || bundle->manifest.size_bytes
      > WYL_FACT_OFFLINE_RESTORE_MAX_MANIFEST_BYTES) {
    rc = WYRELOG_E_POLICY;
    goto fail;
  }
  gsize manifest_length = (gsize) bundle->manifest.size_bytes;
  guint8 *manifest_data = g_malloc (manifest_length);
  rc = read_exact ((HANDLE) bundle->manifest.handle, 0, manifest_data,
          manifest_length);
  if (rc != WYRELOG_E_OK) {
    g_free (manifest_data);
    goto fail;
  }
  bundle->manifest_bytes = g_bytes_new_take (manifest_data, manifest_length);
  checksum = g_checksum_new (G_CHECKSUM_SHA256);
  if (checksum == NULL) {
    rc = WYRELOG_E_NOMEM;
    goto fail;
  }
  g_checksum_update (checksum, manifest_data, manifest_length);
  gsize digest_length = sizeof bundle->digest;
  g_checksum_get_digest (checksum, bundle->digest, &digest_length);
  if (digest_length != sizeof bundle->digest
      || memcmp (bundle->digest, trusted_manifest_sha256,
      sizeof bundle->digest) != 0) {
    rc = WYRELOG_E_POLICY;
    goto fail;
  }
  rc = wyl_fact_offline_backup_manifest_decode (bundle->manifest_bytes,
          &manifest);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_manifest_encode (&manifest, &canonical);
  if (rc == WYRELOG_E_OK && !g_bytes_equal (bundle->manifest_bytes, canonical))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK
      && manifest.artifacts->len > WYL_FACT_OFFLINE_RESTORE_MAX_GRAPHS)
    rc = WYRELOG_E_POLICY;
  for (guint i = 0; rc == WYRELOG_E_OK
      && i < manifest.artifacts->len; i++) {
    WylFactOfflineBackupArtifact *artifact = g_ptr_array_index
          (manifest.artifacts, i);
    if (artifact->format_version != WYL_FACT_STORE_FORMAT_VERSION
        || artifact->path_encoding_version != WYL_FACT_GRAPH_PATH_VERSION
        || artifact->graph_id[0] == '\0'
        || artifact->logical_bytes > G_MAXINT64) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    BundleFile *file = g_new0 (BundleFile, 1);
    file->file = (WylFactGraphRegularFile) WYL_FACT_GRAPH_REGULAR_FILE_INIT;
    file->graph_id = g_strdup (artifact->graph_id);
    file->checksum = g_strdup (artifact->checksum);
    g_autofree gchar *component = NULL;
    rc = wyl_fact_graph_component_encode (artifact->graph_id, &component);
    if (rc == WYRELOG_E_OK)
      file->name = g_strdup_printf ("graph-%s.duckdb", component);
    if (rc == WYRELOG_E_OK && file->name == NULL)
      rc = WYRELOG_E_NOMEM;
    if (rc == WYRELOG_E_OK)
      rc = open_named_file (bundle, file->name, artifact->logical_bytes,
              &file->file);
    file->length = artifact->logical_bytes;
    if (rc == WYRELOG_E_OK)
      rc = hash_file ((HANDLE) file->file.handle, file->length,
              file->checksum);
    if (rc == WYRELOG_E_OK)
      g_ptr_array_add (bundle->files, file);
    else
      bundle_file_free (file);
  }
  wyl_fact_offline_backup_manifest_clear (&manifest);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_bundle_revalidate (bundle);
  if (rc != WYRELOG_E_OK)
    goto fail;
  *out_bundle = bundle;
  return WYRELOG_E_OK;
fail:
  wyl_fact_offline_backup_manifest_clear (&manifest);
  wyl_fact_offline_backup_bundle_free (bundle);
  return rc;
#else
  WylFactOfflineBackupBundle *bundle = g_new0
        (WylFactOfflineBackupBundle, 1);
  bundle->directory = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
  bundle->manifest_fd = -1;
  bundle->files = g_ptr_array_new_with_free_func (bundle_file_free);
  g_autoptr (GChecksum) checksum = NULL;
  g_autoptr (GBytes) canonical = NULL;
  WylFactOfflineBackupManifest manifest = { 0 };
  wyrelog_error_t rc = wyl_fact_graph_resolver_open (directory,
          &bundle->directory);
  if (rc != WYRELOG_E_OK)
    goto fail;
  struct stat manifest_stat;
  bundle->manifest_fd = openat (bundle->directory.fd, "manifest",
          O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (bundle->manifest_fd < 0) {
    rc = errno == ENOENT ? WYRELOG_E_NOT_FOUND : WYRELOG_E_POLICY;
    goto fail;
  }
  if (fstat (bundle->manifest_fd, &manifest_stat) != 0) {
    rc = WYRELOG_E_IO;
    goto fail;
  }
  if (manifest_stat.st_size <= 0
      || manifest_stat.st_size > WYL_FACT_OFFLINE_RESTORE_MAX_MANIFEST_BYTES) {
    rc = WYRELOG_E_POLICY;
    goto fail;
  }
  rc = file_stat (bundle->manifest_fd, (guint64) manifest_stat.st_size,
          &bundle->manifest_device, &bundle->manifest_inode);
  if (rc != WYRELOG_E_OK)
    goto fail;
  gsize manifest_length = (gsize) manifest_stat.st_size;
  guint8 *manifest_data = g_malloc (manifest_length);
  rc = read_exact (bundle->manifest_fd, manifest_data, manifest_length);
  if (rc != WYRELOG_E_OK) {
    g_free (manifest_data);
    goto fail;
  }
  bundle->manifest_bytes = g_bytes_new_take (manifest_data, manifest_length);
  checksum = g_checksum_new (G_CHECKSUM_SHA256);
  if (checksum == NULL) {
    rc = WYRELOG_E_NOMEM;
    goto fail;
  }
  g_checksum_update (checksum, manifest_data, manifest_length);
  gsize digest_length = sizeof bundle->digest;
  g_checksum_get_digest (checksum, bundle->digest, &digest_length);
  if (digest_length != sizeof bundle->digest
      || memcmp (bundle->digest, trusted_manifest_sha256,
      sizeof bundle->digest) != 0) {
    rc = WYRELOG_E_POLICY;
    goto fail;
  }
  rc = wyl_fact_offline_backup_manifest_decode (bundle->manifest_bytes,
          &manifest);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_manifest_encode (&manifest, &canonical);
  if (rc == WYRELOG_E_OK && !g_bytes_equal (bundle->manifest_bytes, canonical))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK
      && manifest.artifacts->len > WYL_FACT_OFFLINE_RESTORE_MAX_GRAPHS)
    rc = WYRELOG_E_POLICY;
  for (guint i = 0; rc == WYRELOG_E_OK
      && i < manifest.artifacts->len; i++) {
    WylFactOfflineBackupArtifact *artifact = g_ptr_array_index
          (manifest.artifacts, i);
    if (artifact->format_version != WYL_FACT_STORE_FORMAT_VERSION
        || artifact->path_encoding_version != WYL_FACT_GRAPH_PATH_VERSION
        || artifact->graph_id[0] == '\0'
        || artifact->logical_bytes > G_MAXINT64) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    BundleFile *file = g_new0 (BundleFile, 1);
    file->fd = -1;
    file->graph_id = g_strdup (artifact->graph_id);
    file->checksum = g_strdup (artifact->checksum);
    g_autofree gchar *component = NULL;
    rc = wyl_fact_graph_component_encode (artifact->graph_id, &component);
    if (rc == WYRELOG_E_OK)
      file->name = g_strdup_printf ("graph-%s.duckdb", component);
    if (rc == WYRELOG_E_OK && file->name == NULL)
      rc = WYRELOG_E_NOMEM;
    if (rc == WYRELOG_E_OK)
      rc = open_named_file (bundle, file->name, artifact->logical_bytes,
              &file->fd, &file->device, &file->inode);
    file->length = artifact->logical_bytes;
    if (rc == WYRELOG_E_OK)
      rc = hash_file (file->fd, file->length, file->checksum);
    if (rc == WYRELOG_E_OK)
      g_ptr_array_add (bundle->files, file);
    else
      bundle_file_free (file);
  }
  wyl_fact_offline_backup_manifest_clear (&manifest);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_offline_backup_bundle_revalidate (bundle);
  if (rc != WYRELOG_E_OK)
    goto fail;
  *out_bundle = bundle;
  return WYRELOG_E_OK;
fail:
  wyl_fact_offline_backup_manifest_clear (&manifest);
  wyl_fact_offline_backup_bundle_free (bundle);
  return rc;
#endif
}

GBytes *
wyl_fact_offline_backup_bundle_manifest_bytes
  (WylFactOfflineBackupBundle *bundle)
{
  return bundle == NULL ? NULL : g_bytes_ref (bundle->manifest_bytes);
}

const guint8 *
wyl_fact_offline_backup_bundle_manifest_sha256
  (WylFactOfflineBackupBundle *bundle)
{
  return bundle == NULL ? NULL : bundle->digest;
}

wyrelog_error_t
wyl_fact_offline_backup_bundle_revalidate (WylFactOfflineBackupBundle *bundle)
{
  if (bundle == NULL)
    return WYRELOG_E_INVALID;
#ifdef G_OS_WIN32
  wyrelog_error_t rc = wyl_fact_graph_resolver_revalidate
        (&bundle->directory);
  if (rc == WYRELOG_E_OK)
    rc = require_persistent_volume (bundle);
  if (rc == WYRELOG_E_OK)
    rc = verify_entry_set (bundle);
  if (rc == WYRELOG_E_OK)
    rc = named_file_check (bundle, "manifest", &bundle->manifest,
            g_bytes_get_size (bundle->manifest_bytes));
  if (rc == WYRELOG_E_OK) {
    gsize length = g_bytes_get_size (bundle->manifest_bytes);
    guint8 *bytes = g_malloc (length);
    rc = read_exact ((HANDLE) bundle->manifest.handle, 0, bytes, length);
    if (rc == WYRELOG_E_OK
        && memcmp (bytes, g_bytes_get_data (bundle->manifest_bytes, NULL),
        length) != 0)
      rc = WYRELOG_E_POLICY;
    g_free (bytes);
  }
  for (guint i = 0; rc == WYRELOG_E_OK
      && i < bundle->files->len; i++) {
    BundleFile *file = g_ptr_array_index (bundle->files, i);
    rc = named_file_check (bundle, file->name, &file->file, file->length);
    if (rc == WYRELOG_E_OK)
      rc = hash_file ((HANDLE) file->file.handle, file->length,
              file->checksum);
  }
  return rc;
#else
  wyrelog_error_t rc = wyl_fact_graph_resolver_revalidate
        (&bundle->directory);
  if (rc == WYRELOG_E_OK)
    rc = verify_entry_set (bundle);
  if (rc == WYRELOG_E_OK)
    rc = verify_named_file (bundle, "manifest", bundle->manifest_fd,
            g_bytes_get_size (bundle->manifest_bytes),
            bundle->manifest_device, bundle->manifest_inode);
  if (rc == WYRELOG_E_OK) {
    gsize length = g_bytes_get_size (bundle->manifest_bytes);
    guint8 *bytes = g_malloc (length);
    rc = read_exact (bundle->manifest_fd, bytes, length);
    if (rc == WYRELOG_E_OK
        && memcmp (bytes, g_bytes_get_data (bundle->manifest_bytes, NULL),
        length) != 0)
      rc = WYRELOG_E_POLICY;
    g_free (bytes);
  }
  for (guint i = 0; rc == WYRELOG_E_OK
      && i < bundle->files->len; i++) {
    BundleFile *file = g_ptr_array_index (bundle->files, i);
    rc = verify_named_file (bundle, file->name, file->fd, file->length,
            file->device, file->inode);
    if (rc == WYRELOG_E_OK)
      rc = hash_file (file->fd, file->length, file->checksum);
  }
  return rc;
#endif
}

wyrelog_error_t
wyl_fact_offline_backup_bundle_read_at (WylFactOfflineBackupBundle *bundle,
    const gchar *graph_id, guint64 offset, guint8 *buffer, gsize capacity,
    gsize *out_read)
{
  if (out_read != NULL)
    *out_read = 0;
  if (bundle == NULL || graph_id == NULL || buffer == NULL
      || capacity == 0 || out_read == NULL)
    return WYRELOG_E_INVALID;
#ifdef G_OS_WIN32
  /* The held handle is pinned to the object, so re-querying it brackets the
   * read as the POSIX fstat pair does.  POSIX also re-binds the name and
   * re-checks the DACL on every read; this arm leaves both to revalidate, so
   * an artifact renamed away and replaced keeps serving the bytes whose
   * checksum was proved until the next revalidate refuses it.  That is a
   * deliberate divergence: the pinned object is the proven one, and the
   * by-name proof costs two resolver re-walks per call. */
  BundleFile *file = find_file (bundle, graph_id);
  if (file == NULL)
    return WYRELOG_E_NOT_FOUND;
  wyrelog_error_t rc = held_file_check (&file->file, file->length);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (offset >= file->length)
    return WYRELOG_E_OK;
  gsize amount = (gsize) MIN ((guint64) capacity, file->length - offset);
  rc = read_exact ((HANDLE) file->file.handle, offset, buffer, amount);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = held_file_check (&file->file, file->length);
  if (rc == WYRELOG_E_OK)
    *out_read = amount;
  return rc;
#else
  BundleFile *file = find_file (bundle, graph_id);
  if (file == NULL)
    return WYRELOG_E_NOT_FOUND;
  wyrelog_error_t rc = verify_named_file (bundle, file->name, file->fd,
          file->length, file->device, file->inode);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (offset >= file->length)
    return WYRELOG_E_OK;
  gsize amount = (gsize) MIN ((guint64) capacity, file->length - offset);
  ssize_t got;
  do {
    got = pread (file->fd, buffer, amount, (off_t) offset);
  } while (got < 0 && errno == EINTR);
  if (got <= 0)
    return WYRELOG_E_IO;
  rc = verify_named_file (bundle, file->name, file->fd, file->length,
          file->device, file->inode);
  if (rc == WYRELOG_E_OK)
    *out_read = (gsize) got;
  return rc;
#endif
}

static wyrelog_error_t
tenant_read (const gchar *graph_id, guint64 offset, guint8 *buffer,
    gsize capacity, gsize *out_read, gpointer user_data)
{
  return wyl_fact_offline_backup_bundle_read_at (user_data, graph_id,
             offset, buffer, capacity, out_read);
}

static wyrelog_error_t
graph_read (guint64 offset, guint8 *buffer, gsize capacity,
    gsize *out_read, gpointer user_data)
{
  WylFactOfflineBackupGraphView *view = user_data;
  if (view == NULL || view->bundle == NULL || view->graph_id == NULL)
    return WYRELOG_E_INVALID;
  return wyl_fact_offline_backup_bundle_read_at (view->bundle,
             view->graph_id, offset, buffer, capacity, out_read);
}

static wyrelog_error_t
revalidate_adapter (gpointer user_data)
{
  return wyl_fact_offline_backup_bundle_revalidate (user_data);
}

static wyrelog_error_t
graph_revalidate_adapter (gpointer user_data)
{
  WylFactOfflineBackupGraphView *view = user_data;
  if (view == NULL || view->bundle == NULL || view->graph_id == NULL)
    return WYRELOG_E_INVALID;
  return wyl_fact_offline_backup_bundle_revalidate (view->bundle);
}

wyrelog_error_t
wyl_fact_offline_backup_bundle_graph_view
  (WylFactOfflineBackupBundle *bundle, const gchar *graph_id,
    WylFactOfflineBackupGraphView *out_view)
{
  if (out_view != NULL)
    *out_view = (WylFactOfflineBackupGraphView) { 0 };
  if (bundle == NULL || graph_id == NULL || out_view == NULL)
    return WYRELOG_E_INVALID;
  BundleFile *file = find_file (bundle, graph_id);
  if (file == NULL)
    return WYRELOG_E_NOT_FOUND;
  *out_view = (WylFactOfflineBackupGraphView) {
    .bundle = bundle,
    .graph_id = file->graph_id,
  };
  return WYRELOG_E_OK;
}

const WylFactOfflineRestoreTenantInput *
wyl_fact_offline_backup_bundle_tenant_input (void)
{
  static const WylFactOfflineRestoreTenantInput input = {
    .read_at = tenant_read,
    .revalidate = revalidate_adapter,
  };
  return &input;
}

const WylFactOfflineRestoreInput *
wyl_fact_offline_backup_bundle_graph_input (void)
{
  static const WylFactOfflineRestoreInput input = {
    .read_at = graph_read,
    .revalidate = graph_revalidate_adapter,
  };
  return &input;
}

void
wyl_fact_offline_backup_bundle_free (WylFactOfflineBackupBundle *bundle)
{
  if (bundle == NULL)
    return;
#ifdef G_OS_WIN32
  wyl_fact_graph_regular_file_clear (&bundle->manifest);
  g_clear_pointer (&bundle->manifest_bytes, g_bytes_unref);
  g_clear_pointer (&bundle->files, g_ptr_array_unref);
  wyl_fact_graph_resolver_clear (&bundle->directory);
#else
  if (bundle->manifest_fd >= 0)
    close (bundle->manifest_fd);
  g_clear_pointer (&bundle->manifest_bytes, g_bytes_unref);
  g_clear_pointer (&bundle->files, g_ptr_array_unref);
  wyl_fact_graph_resolver_clear (&bundle->directory);
#endif
  g_free (bundle);
}

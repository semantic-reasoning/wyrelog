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
  return WYRELOG_E_POLICY;
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
#ifdef G_OS_WIN32
  (void) bundle;
  return NULL;
#else
  return bundle == NULL ? NULL : g_bytes_ref (bundle->manifest_bytes);
#endif
}

wyrelog_error_t
wyl_fact_offline_backup_bundle_revalidate (WylFactOfflineBackupBundle *bundle)
{
  if (bundle == NULL)
    return WYRELOG_E_INVALID;
#ifdef G_OS_WIN32
  return WYRELOG_E_POLICY;
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
  return WYRELOG_E_POLICY;
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
#ifdef G_OS_WIN32
  return WYRELOG_E_POLICY;
#else
  BundleFile *file = find_file (bundle, graph_id);
  if (file == NULL)
    return WYRELOG_E_NOT_FOUND;
  *out_view = (WylFactOfflineBackupGraphView) {
    .bundle = bundle,
    .graph_id = file->graph_id,
  };
  return WYRELOG_E_OK;
#endif
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
#ifndef G_OS_WIN32
  if (bundle->manifest_fd >= 0)
    close (bundle->manifest_fd);
  g_clear_pointer (&bundle->manifest_bytes, g_bytes_unref);
  g_clear_pointer (&bundle->files, g_ptr_array_unref);
  wyl_fact_graph_resolver_clear (&bundle->directory);
#endif
  g_free (bundle);
}

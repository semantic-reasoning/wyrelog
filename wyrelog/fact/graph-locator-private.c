/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef G_OS_WIN32
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#endif
#include "fact/graph-locator-private.h"
#include "wyl-id-private.h"

#include <string.h>

#ifdef G_OS_WIN32
#include <windows.h>
#endif

#ifndef G_OS_WIN32
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

static const gchar base32hex_digits[] = "0123456789abcdefghijklmnopqrstuv";

static gchar *
try_strdup (const gchar *value)
{
  gsize len = strlen (value);
  gchar *copy = g_try_malloc (len + 1);
  if (copy != NULL)
    memcpy (copy, value, len + 1);
  return copy;
}

gboolean
wyl_fact_graph_owner_mode_is_secure_for_test (guint32 mode, guint64 owner,
    guint64 expected_owner, guint32 expected_mode)
{
  return owner == expected_owner && (mode & 07777u) == expected_mode;
}

wyrelog_error_t
wyl_fact_graph_component_encode (const gchar *value, gchar **out_component)
{
  if (out_component != NULL)
    *out_component = NULL;
  if (value == NULL || out_component == NULL || !g_utf8_validate (value, -1,
          NULL))
    return WYRELOG_E_INVALID;

  gsize len = strlen (value);
  if (len > (G_MAXSIZE - 4) / 8)
    return WYRELOG_E_NOMEM;
  gsize encoded_len = 3 + (len * 8 + 4) / 5;
  gchar *component = g_try_malloc (encoded_len + 1);
  if (component == NULL)
    return WYRELOG_E_NOMEM;

  memcpy (component, "v1-", 3);
  gsize output = 3;
  guint32 buffer = 0;
  guint bits = 0;
  for (gsize i = 0; i < len; i++) {
    buffer = (buffer << 8) | (guchar) value[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      component[output++] = base32hex_digits[(buffer >> bits) & 0x1f];
    }
    buffer &= bits == 0 ? 0 : (1u << bits) - 1;
  }
  if (bits != 0)
    component[output++] = base32hex_digits[(buffer << (5 - bits)) & 0x1f];
  g_assert (output == encoded_len);
  component[output] = '\0';
  *out_component = component;
  return WYRELOG_E_OK;
}

static gint
base32hex_value (gchar c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'v')
    return 10 + c - 'a';
  return -1;
}

wyrelog_error_t
wyl_fact_graph_component_decode (const gchar *component, gchar **out_value)
{
  if (out_value != NULL)
    *out_value = NULL;
  if (component == NULL || out_value == NULL
      || !g_str_has_prefix (component, "v1-"))
    return WYRELOG_E_INVALID;

  gsize encoded_len = strlen (component + 3);
  gsize remainder = encoded_len % 8;
  if (remainder != 0 && remainder != 2 && remainder != 4
      && remainder != 5 && remainder != 7)
    return WYRELOG_E_INVALID;
  gsize value_len = (encoded_len / 8) * 5 + (remainder * 5) / 8;
  gchar *value = g_try_malloc (value_len + 1);
  if (value == NULL)
    return WYRELOG_E_NOMEM;

  gsize output = 0;
  guint32 buffer = 0;
  guint bits = 0;
  for (gsize i = 0; i < encoded_len; i++) {
    gint digit = base32hex_value (component[3 + i]);
    if (digit < 0) {
      g_free (value);
      return WYRELOG_E_INVALID;
    }
    buffer = (buffer << 5) | (guint32) digit;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      guchar byte = (guchar) ((buffer >> bits) & 0xff);
      if (byte == '\0') {
        g_free (value);
        return WYRELOG_E_INVALID;
      }
      value[output++] = (gchar) byte;
    }
    buffer &= bits == 0 ? 0 : (1u << bits) - 1;
  }
  if (buffer != 0 || output != value_len) {
    g_free (value);
    return WYRELOG_E_INVALID;
  }
  value[value_len] = '\0';
  if (!g_utf8_validate (value, value_len, NULL)) {
    g_free (value);
    return WYRELOG_E_INVALID;
  }
  *out_value = value;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_graph_locator_init (WylFactGraphLocator *locator,
    const gchar *tenant_id, const gchar *graph_id)
{
  if (locator == NULL)
    return WYRELOG_E_INVALID;
  *locator = (WylFactGraphLocator) {
  0};

  wyrelog_error_t rc = wyl_fact_graph_component_encode (tenant_id,
      &locator->tenant_component);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_component_encode (graph_id, &locator->graph_component);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_graph_locator_clear (locator);
    return rc;
  }
  locator->version = WYL_FACT_GRAPH_PATH_VERSION;
  return WYRELOG_E_OK;
}

void
wyl_fact_graph_locator_clear (WylFactGraphLocator *locator)
{
  if (locator == NULL)
    return;
  g_clear_pointer (&locator->tenant_component, g_free);
  g_clear_pointer (&locator->graph_component, g_free);
  locator->version = 0;
}

static gboolean
component_is_canonical (const gchar *component)
{
  g_autofree gchar *decoded = NULL;
  g_autofree gchar *encoded = NULL;
  return wyl_fact_graph_component_decode (component, &decoded) == WYRELOG_E_OK
      && wyl_fact_graph_component_encode (decoded, &encoded) == WYRELOG_E_OK
      && g_strcmp0 (component, encoded) == 0;
}

static gboolean
locator_is_valid (const WylFactGraphLocator *locator)
{
  return locator != NULL && locator->version == WYL_FACT_GRAPH_PATH_VERSION
      && component_is_canonical (locator->tenant_component)
      && component_is_canonical (locator->graph_component);
}

gchar *
wyl_fact_graph_locator_relative_dir (const WylFactGraphLocator *locator)
{
  if (!locator_is_valid (locator))
    return NULL;
  return g_build_filename (locator->tenant_component,
      locator->graph_component, NULL);
}

gchar *
wyl_fact_graph_locator_descriptive_path (const gchar *fact_root,
    const WylFactGraphLocator *locator)
{
  if (fact_root == NULL || fact_root[0] == '\0' || !locator_is_valid (locator))
    return NULL;
  return g_build_filename (fact_root, locator->tenant_component,
      locator->graph_component, NULL);
}

gboolean
wyl_fact_graph_relative_path_is_valid (const gchar *value)
{
  if (value == NULL || value[0] == '\0' || strchr (value, '/') == NULL
      || g_path_is_absolute (value)
      || strchr (value, '\\') != NULL || strchr (value, ':') != NULL)
    return FALSE;
  g_auto (GStrv) components = g_strsplit (value, "/", -1);
  if (components == NULL)
    return FALSE;
  for (gsize i = 0; components[i] != NULL; i++) {
    if (components[i][0] == '\0' || g_strcmp0 (components[i], ".") == 0
        || g_strcmp0 (components[i], "..") == 0)
      return FALSE;
  }
  return TRUE;
}

#ifndef G_OS_WIN32
static wyrelog_error_t
errno_to_resolver_error (gint error_number)
{
  if (error_number == ENOENT)
    return WYRELOG_E_NOT_FOUND;
  if (error_number == EBUSY || error_number == ETXTBSY)
    return WYRELOG_E_BUSY;
  if (error_number == ELOOP || error_number == ENOTDIR
      || error_number == EACCES || error_number == EPERM)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_IO;
}

static gboolean
name_is_safe (const gchar *name)
{
  return name != NULL && name[0] != '\0' && strcmp (name, ".") != 0
      && strcmp (name, "..") != 0 && strchr (name, '/') == NULL
      && strchr (name, '\\') == NULL;
}

static gboolean
provisioning_stage_name_is_canonical (const gchar *name)
{
  static const gchar prefix[] = "provision-";
  static const gchar suffix[] = ".sqlite";
  if (!name_is_safe (name) || !g_str_has_prefix (name, prefix)
      || !g_str_has_suffix (name, suffix))
    return FALSE;
  gsize name_len = strlen (name);
  gsize prefix_len = sizeof prefix - 1;
  gsize suffix_len = sizeof suffix - 1;
  if (name_len != prefix_len + WYL_ID_STRING_LEN + suffix_len)
    return FALSE;
  gchar uuid[WYL_ID_STRING_BUF];
  memcpy (uuid, name + prefix_len, WYL_ID_STRING_LEN);
  uuid[WYL_ID_STRING_LEN] = '\0';
  wyl_id_t id;
  if (wyl_id_parse (uuid, &id) != WYRELOG_E_OK)
    return FALSE;
  gchar canonical[WYL_ID_STRING_BUF];
  return wyl_id_format (&id, canonical, sizeof canonical) == WYRELOG_E_OK
      && memcmp (canonical, uuid, WYL_ID_STRING_LEN) == 0;
}

static wyrelog_error_t
provisioning_stage_name_from_operation (const gchar *operation_uuid,
    gchar **out_stage_basename)
{
  if (out_stage_basename != NULL)
    *out_stage_basename = NULL;
  if (operation_uuid == NULL || out_stage_basename == NULL)
    return WYRELOG_E_INVALID;
  wyl_id_t id;
  gchar canonical[WYL_ID_STRING_BUF];
  if (wyl_id_parse (operation_uuid, &id) != WYRELOG_E_OK
      || wyl_id_format (&id, canonical, sizeof canonical) != WYRELOG_E_OK
      || g_strcmp0 (operation_uuid, canonical) != 0)
    return WYRELOG_E_INVALID;
  gchar *name = g_strdup_printf ("provision-%s.sqlite", canonical);
  if (name == NULL)
    return WYRELOG_E_NOMEM;
  if (!provisioning_stage_name_is_canonical (name)) {
    g_free (name);
    return WYRELOG_E_INTERNAL;
  }
  *out_stage_basename = name;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
validate_fd (gint fd, gboolean directory, mode_t expected_mode,
    guint64 *out_device, guint64 *out_inode)
{
  struct stat st;
  if (fstat (fd, &st) != 0)
    return WYRELOG_E_IO;
  if ((directory && !S_ISDIR (st.st_mode))
      || (!directory && !S_ISREG (st.st_mode))
      || !wyl_fact_graph_owner_mode_is_secure_for_test ((guint32) st.st_mode,
          (guint64) st.st_uid, (guint64) geteuid (), expected_mode))
    return WYRELOG_E_POLICY;
  if (out_device != NULL)
    *out_device = (guint64) st.st_dev;
  if (out_inode != NULL)
    *out_inode = (guint64) st.st_ino;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
validate_regular_fd (gint fd, mode_t expected_mode, guint64 *out_device,
    guint64 *out_inode, guint64 *out_size)
{
  struct stat st;
  if (fstat (fd, &st) != 0)
    return WYRELOG_E_IO;
  if (!S_ISREG (st.st_mode) || st.st_nlink != 1
      || !wyl_fact_graph_owner_mode_is_secure_for_test ((guint32) st.st_mode,
          (guint64) st.st_uid, (guint64) geteuid (), expected_mode))
    return WYRELOG_E_POLICY;
  if (out_device != NULL)
    *out_device = (guint64) st.st_dev;
  if (out_inode != NULL)
    *out_inode = (guint64) st.st_ino;
  if (out_size != NULL)
    *out_size = (guint64) st.st_size;
  return WYRELOG_E_OK;
}

static gboolean
stat_matches (const struct stat *st, guint64 device, guint64 inode,
    gboolean directory, mode_t expected_mode)
{
  return ((directory && S_ISDIR (st->st_mode))
      || (!directory && S_ISREG (st->st_mode)))
      && wyl_fact_graph_owner_mode_is_secure_for_test ((guint32) st->st_mode,
      (guint64) st->st_uid, (guint64) geteuid (), expected_mode)
      && (guint64) st->st_dev == device && (guint64) st->st_ino == inode;
}

static wyrelog_error_t
validate_fd_exact (gint fd, gboolean directory, mode_t expected_mode,
    guint64 device, guint64 inode)
{
  guint64 current_device = 0;
  guint64 current_inode = 0;
  wyrelog_error_t rc = validate_fd (fd, directory, expected_mode,
      &current_device, &current_inode);
  if (rc != WYRELOG_E_OK)
    return rc;
  return current_device == device && current_inode == inode ?
      WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t validate_name_length (gint parent_fd,
    const gchar * name);

static wyrelog_error_t
open_relative_regular_at (gint root_fd, const gchar *relative_path,
    WylFactGraphRegularFile *out_file)
{
  if (out_file != NULL)
    *out_file = (WylFactGraphRegularFile) WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  if (root_fd < 0 || out_file == NULL
      || !wyl_fact_graph_relative_path_is_valid (relative_path))
    return WYRELOG_E_INVALID;
  gint current = dup (root_fd);
  if (current < 0)
    return WYRELOG_E_IO;
  g_auto (GStrv) components = g_strsplit (relative_path, "/", -1);
  if (components == NULL) {
    close (current);
    return WYRELOG_E_NOMEM;
  }
  if (fcntl (current, F_SETFD, FD_CLOEXEC) != 0) {
    close (current);
    return WYRELOG_E_IO;
  }
  wyrelog_error_t rc = WYRELOG_E_OK;
  for (gsize i = 0; rc == WYRELOG_E_OK && components[i + 1] != NULL; i++) {
    rc = validate_name_length (current, components[i]);
    if (rc != WYRELOG_E_OK)
      break;
    gint next = openat (current, components[i],
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (next < 0) {
      rc = errno_to_resolver_error (errno);
      break;
    }
    close (current);
    current = next;
  }
  if (rc == WYRELOG_E_OK) {
    const gchar *basename = components[0];
    for (gsize i = 1; components[i] != NULL; i++)
      basename = components[i];
    rc = validate_name_length (current, basename);
    if (rc == WYRELOG_E_OK) {
      struct stat before;
      if (fstatat (current, basename, &before, AT_SYMLINK_NOFOLLOW) != 0)
        rc = errno_to_resolver_error (errno);
      else if (!S_ISREG (before.st_mode) || before.st_nlink != 1
          || !wyl_fact_graph_owner_mode_is_secure_for_test (
              (guint32) before.st_mode, (guint64) before.st_uid,
              (guint64) geteuid (), 0600))
        rc = WYRELOG_E_POLICY;
      else {
        gint fd = openat (current, basename,
            O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0)
          rc = errno_to_resolver_error (errno);
        else {
          guint64 device = 0;
          guint64 inode = 0;
          guint64 size_bytes = 0;
          rc = validate_regular_fd (fd, 0600, &device, &inode, &size_bytes);
          struct stat after;
          if (rc == WYRELOG_E_OK
              && (fstatat (current, basename, &after, AT_SYMLINK_NOFOLLOW) != 0
                  || !stat_matches (&before, device, inode, FALSE, 0600)
                  || !stat_matches (&after, device, inode, FALSE, 0600)
                  || (guint64) before.st_size != size_bytes))
            rc = WYRELOG_E_POLICY;
          if (rc == WYRELOG_E_OK) {
            out_file->fd = fd;
            out_file->device = device;
            out_file->inode = inode;
            out_file->size_bytes = size_bytes;
          } else
            close (fd);
        }
      }
    }
  }
  close (current);
  if (rc != WYRELOG_E_OK)
    wyl_fact_graph_regular_file_clear (out_file);
  return rc;
}

static wyrelog_error_t
open_absolute_directory (const gchar *path, gint *out_fd)
{
  *out_fd = -1;
  if (!g_path_is_absolute (path))
    return WYRELOG_E_INVALID;

  gint current = open (G_DIR_SEPARATOR_S,
      O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (current < 0)
    return WYRELOG_E_IO;
  g_auto (GStrv) components = g_strsplit (path, G_DIR_SEPARATOR_S, -1);
  for (gsize i = 0; components[i] != NULL; i++) {
    if (components[i][0] == '\0')
      continue;
    if (strcmp (components[i], ".") == 0 || strcmp (components[i], "..") == 0) {
      close (current);
      return WYRELOG_E_INVALID;
    }
    gint next = openat (current, components[i],
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (next < 0) {
      wyrelog_error_t rc = errno_to_resolver_error (errno);
      close (current);
      return rc;
    }
    close (current);
    current = next;
  }
  *out_fd = current;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
resolver_revalidate (const gchar *path, guint64 device, guint64 inode,
    gint *out_current_fd)
{
  gint fd = -1;
  wyrelog_error_t rc = open_absolute_directory (path, &fd);
  if (rc != WYRELOG_E_OK)
    return rc == WYRELOG_E_NOT_FOUND ? WYRELOG_E_POLICY : rc;
  guint64 current_device = 0;
  guint64 current_inode = 0;
  rc = validate_fd (fd, TRUE, 0700, &current_device, &current_inode);
  if (rc == WYRELOG_E_OK
      && (current_device != device || current_inode != inode))
    rc = WYRELOG_E_POLICY;
  if (rc != WYRELOG_E_OK || out_current_fd == NULL)
    close (fd);
  else
    *out_current_fd = fd;
  return rc;
}

wyrelog_error_t
wyl_fact_graph_resolver_open (const gchar *fact_root,
    WylFactGraphResolver *out_resolver)
{
  if (out_resolver == NULL)
    return WYRELOG_E_INVALID;
  *out_resolver = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
  if (fact_root == NULL || fact_root[0] == '\0')
    return WYRELOG_E_INVALID;

  gint fd = -1;
  wyrelog_error_t rc = open_absolute_directory (fact_root, &fd);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = validate_fd (fd, TRUE, 0700, &out_resolver->device,
      &out_resolver->inode);
  if (rc != WYRELOG_E_OK) {
    close (fd);
    return rc;
  }
  out_resolver->path = try_strdup (fact_root);
  if (out_resolver->path == NULL) {
    close (fd);
    return WYRELOG_E_NOMEM;
  }
  out_resolver->fd = fd;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_graph_resolver_revalidate (WylFactGraphResolver *resolver)
{
  if (resolver == NULL || resolver->fd < 0 || resolver->path == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = validate_fd_exact (resolver->fd, TRUE, 0700,
      resolver->device, resolver->inode);
  if (rc == WYRELOG_E_OK)
    rc = resolver_revalidate (resolver->path, resolver->device,
        resolver->inode, NULL);
  return rc;
}

void
wyl_fact_graph_resolver_clear (WylFactGraphResolver *resolver)
{
  if (resolver == NULL)
    return;
  if (resolver->fd >= 0)
    close (resolver->fd);
  g_free (resolver->path);
  *resolver = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
}

void
wyl_fact_graph_regular_file_clear (WylFactGraphRegularFile *file)
{
  if (file == NULL)
    return;
#ifdef G_OS_WIN32
  if (handle_is_valid (file->handle))
    CloseHandle (file->handle);
  file->handle = NULL;
  memset (&file->identity, 0, sizeof file->identity);
#else
  if (file->fd >= 0)
    close (file->fd);
  file->fd = -1;
  file->device = 0;
  file->inode = 0;
#endif
  file->size_bytes = 0;
}

void wyl_fact_graph_resolver_set_checkpoint_for_test
    (WylFactGraphResolver * resolver,
    wyrelog_error_t (*checkpoint) (const gchar * point, gpointer user_data),
    gpointer user_data)
{
  if (resolver == NULL)
    return;
  resolver->checkpoint = checkpoint;
  resolver->checkpoint_data = user_data;
}

static wyrelog_error_t
validate_name_length (gint parent_fd, const gchar *name)
{
  errno = 0;
  long name_max = fpathconf (parent_fd, _PC_NAME_MAX);
  if (name_max < 0)
    return WYRELOG_E_IO;
  return strlen (name) <= (gsize) name_max ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
open_or_create_dir (gint parent_fd, const gchar *name, gboolean create,
    gint *out_fd, guint64 *out_device, guint64 *out_inode,
    wyrelog_error_t (*checkpoint) (const gchar *point, gpointer user_data),
    gpointer checkpoint_data, const gchar *checkpoint_name)
{
  *out_fd = -1;
  wyrelog_error_t rc = validate_name_length (parent_fd, name);
  if (rc != WYRELOG_E_OK)
    return rc;
  gint fd = openat (parent_fd, name,
      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0 && errno == ENOENT && create) {
    if (mkdirat (parent_fd, name, 0700) != 0 && errno != EEXIST)
      return errno_to_resolver_error (errno);
    if (fsync (parent_fd) != 0)
      return WYRELOG_E_IO;
    fd = openat (parent_fd, name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  }
  if (fd < 0)
    return errno_to_resolver_error (errno);
  rc = validate_fd (fd, TRUE, 0700, out_device, out_inode);
  if (rc != WYRELOG_E_OK) {
    close (fd);
    return rc;
  }
  if (checkpoint != NULL) {
    rc = checkpoint (checkpoint_name, checkpoint_data);
    if (rc != WYRELOG_E_OK) {
      close (fd);
      return rc;
    }
  }
  struct stat named;
  if (fstatat (parent_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0
      || !stat_matches (&named, *out_device, *out_inode, TRUE, 0700)) {
    close (fd);
    return WYRELOG_E_POLICY;
  }
  *out_fd = fd;
  return WYRELOG_E_OK;
}

static wyrelog_error_t directory_revalidate (WylFactGraphDirectory * directory);

wyrelog_error_t
wyl_fact_graph_resolver_open_directory (WylFactGraphResolver *resolver,
    const WylFactGraphLocator *locator, gboolean create,
    WylFactGraphDirectory *out_directory)
{
  if (out_directory == NULL)
    return WYRELOG_E_INVALID;
  *out_directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  if (resolver == NULL || resolver->fd < 0 || resolver->path == NULL
      || !locator_is_valid (locator))
    return WYRELOG_E_INVALID;

  gint current_root = -1;
  wyrelog_error_t rc = resolver_revalidate (resolver->path, resolver->device,
      resolver->inode, &current_root);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (resolver->checkpoint != NULL) {
    rc = resolver->checkpoint ("root-opened", resolver->checkpoint_data);
    if (rc != WYRELOG_E_OK) {
      close (current_root);
      return rc;
    }
  }
  rc = resolver_revalidate (resolver->path, resolver->device,
      resolver->inode, NULL);
  if (rc != WYRELOG_E_OK) {
    close (current_root);
    return rc;
  }
  gint tenant_fd = -1;
  guint64 tenant_device = 0;
  guint64 tenant_inode = 0;
  rc = open_or_create_dir (current_root, locator->tenant_component, create,
      &tenant_fd, &tenant_device, &tenant_inode, resolver->checkpoint,
      resolver->checkpoint_data, "tenant-opened");
  if (rc != WYRELOG_E_OK) {
    close (current_root);
    return rc;
  }
  gint graph_fd = -1;
  guint64 graph_device = 0;
  guint64 graph_inode = 0;
  rc = open_or_create_dir (tenant_fd, locator->graph_component, create,
      &graph_fd, &graph_device, &graph_inode, resolver->checkpoint,
      resolver->checkpoint_data, "graph-opened");
  if (rc != WYRELOG_E_OK) {
    close (tenant_fd);
    close (current_root);
    return rc;
  }

  out_directory->root_path = try_strdup (resolver->path);
  out_directory->tenant_component = try_strdup (locator->tenant_component);
  out_directory->graph_component = try_strdup (locator->graph_component);
  if (out_directory->root_path == NULL
      || out_directory->tenant_component == NULL
      || out_directory->graph_component == NULL) {
    close (graph_fd);
    close (tenant_fd);
    close (current_root);
    wyl_fact_graph_directory_clear (out_directory);
    return WYRELOG_E_NOMEM;
  }
  out_directory->root_fd = current_root;
  out_directory->tenant_fd = tenant_fd;
  out_directory->graph_fd = graph_fd;
  out_directory->root_device = resolver->device;
  out_directory->root_inode = resolver->inode;
  out_directory->tenant_device = tenant_device;
  out_directory->tenant_inode = tenant_inode;
  out_directory->graph_device = graph_device;
  out_directory->graph_inode = graph_inode;
  out_directory->checkpoint = resolver->checkpoint;
  out_directory->checkpoint_data = resolver->checkpoint_data;
  rc = directory_revalidate (out_directory);
  if (rc != WYRELOG_E_OK)
    wyl_fact_graph_directory_clear (out_directory);
  return rc;
}

wyrelog_error_t
wyl_fact_graph_resolver_open_relative_regular (WylFactGraphResolver *resolver,
    const gchar *relative_path, WylFactGraphRegularFile *out_file)
{
  if (out_file != NULL)
    *out_file = (WylFactGraphRegularFile) WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  if (resolver == NULL || resolver->fd < 0 || resolver->path == NULL
      || out_file == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = wyl_fact_graph_resolver_revalidate (resolver);
  if (rc == WYRELOG_E_OK)
    rc = open_relative_regular_at (resolver->fd, relative_path, out_file);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_revalidate (resolver);
  if (rc != WYRELOG_E_OK)
    wyl_fact_graph_regular_file_clear (out_file);
  return rc;
}

void
wyl_fact_graph_directory_clear (WylFactGraphDirectory *directory)
{
  if (directory == NULL)
    return;
  if (directory->graph_fd >= 0)
    close (directory->graph_fd);
  if (directory->tenant_fd >= 0)
    close (directory->tenant_fd);
  if (directory->root_fd >= 0)
    close (directory->root_fd);
  g_free (directory->root_path);
  g_free (directory->tenant_component);
  g_free (directory->graph_component);
  *directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
}

static wyrelog_error_t
directory_revalidate (WylFactGraphDirectory *directory)
{
  if (directory == NULL || directory->root_fd < 0 || directory->tenant_fd < 0
      || directory->graph_fd < 0)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = resolver_revalidate (directory->root_path,
      directory->root_device, directory->root_inode, NULL);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = validate_fd_exact (directory->root_fd, TRUE, 0700,
      directory->root_device, directory->root_inode);
  if (rc == WYRELOG_E_OK)
    rc = validate_fd_exact (directory->tenant_fd, TRUE, 0700,
        directory->tenant_device, directory->tenant_inode);
  if (rc == WYRELOG_E_OK)
    rc = validate_fd_exact (directory->graph_fd, TRUE, 0700,
        directory->graph_device, directory->graph_inode);
  if (rc != WYRELOG_E_OK)
    return rc;
  struct stat named;
  if (fstatat (directory->root_fd, directory->tenant_component, &named,
          AT_SYMLINK_NOFOLLOW) != 0
      || !stat_matches (&named, directory->tenant_device,
          directory->tenant_inode, TRUE, 0700))
    return WYRELOG_E_POLICY;
  if (fstatat (directory->tenant_fd, directory->graph_component, &named,
          AT_SYMLINK_NOFOLLOW) != 0
      || !stat_matches (&named, directory->graph_device,
          directory->graph_inode, TRUE, 0700))
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

gchar *
wyl_fact_graph_directory_descriptive_path (const WylFactGraphDirectory
    *directory)
{
  if (directory == NULL || directory->root_path == NULL)
    return NULL;
  return g_build_filename (directory->root_path, directory->tenant_component,
      directory->graph_component, NULL);
}

gchar *
wyl_fact_graph_directory_descriptive_file (const WylFactGraphDirectory
    *directory, const gchar *basename)
{
  if (!name_is_safe (basename))
    return NULL;
  g_autofree gchar *path =
      wyl_fact_graph_directory_descriptive_path (directory);
  return path == NULL ? NULL : g_build_filename (path, basename, NULL);
}

wyrelog_error_t
wyl_fact_graph_directory_open_file (WylFactGraphDirectory *directory,
    const gchar *basename, gboolean writable, gint *out_fd)
{
  if (out_fd != NULL)
    *out_fd = -1;
  if (out_fd == NULL || !name_is_safe (basename))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = directory_revalidate (directory);
  if (rc == WYRELOG_E_OK)
    rc = validate_name_length (directory->graph_fd, basename);
  if (rc != WYRELOG_E_OK)
    return rc;

  struct stat before;
  if (fstatat (directory->graph_fd, basename, &before,
          AT_SYMLINK_NOFOLLOW) != 0)
    return errno_to_resolver_error (errno);
  if (!S_ISREG (before.st_mode) || before.st_nlink != 1)
    return WYRELOG_E_POLICY;
  gint fd = openat (directory->graph_fd, basename,
      (writable ? O_RDWR : O_RDONLY) | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return errno_to_resolver_error (errno);
  if (directory->checkpoint != NULL) {
    rc = directory->checkpoint ("file-opened", directory->checkpoint_data);
    if (rc != WYRELOG_E_OK) {
      close (fd);
      return rc;
    }
  }
  guint64 device = 0;
  guint64 inode = 0;
  rc = validate_regular_fd (fd, 0600, &device, &inode, NULL);
  struct stat after;
  if (rc == WYRELOG_E_OK
      && (fstatat (directory->graph_fd, basename, &after,
              AT_SYMLINK_NOFOLLOW) != 0
          || !stat_matches (&before, device, inode, FALSE, 0600)
          || !stat_matches (&after, device, inode, FALSE, 0600)))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = directory_revalidate (directory);
  if (rc != WYRELOG_E_OK) {
    close (fd);
    return rc;
  }
  *out_fd = fd;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_graph_directory_secure_file_mode (WylFactGraphDirectory *directory,
    const gchar *basename)
{
  if (!name_is_safe (basename))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = directory_revalidate (directory);
  if (rc == WYRELOG_E_OK)
    rc = validate_name_length (directory->graph_fd, basename);
  if (rc != WYRELOG_E_OK)
    return rc;
  struct stat before;
  if (fstatat (directory->graph_fd, basename, &before,
          AT_SYMLINK_NOFOLLOW) != 0)
    return errno_to_resolver_error (errno);
  if (!S_ISREG (before.st_mode) || before.st_uid != geteuid ()
      || before.st_nlink != 1)
    return WYRELOG_E_POLICY;
  gint fd = openat (directory->graph_fd, basename,
      O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return errno_to_resolver_error (errno);
  struct stat opened;
  struct stat after;
  if (fstat (fd, &opened) != 0)
    rc = WYRELOG_E_IO;
  else if (!S_ISREG (opened.st_mode) || opened.st_uid != geteuid ()
      || opened.st_dev != before.st_dev || opened.st_ino != before.st_ino)
    rc = WYRELOG_E_POLICY;
  else if (fchmod (fd, 0600) != 0 || fsync (fd) != 0)
    rc = WYRELOG_E_IO;
  else if (fstatat (directory->graph_fd, basename, &after,
          AT_SYMLINK_NOFOLLOW) != 0)
    rc = errno == ENOENT ? WYRELOG_E_POLICY : errno_to_resolver_error (errno);
  else if (after.st_dev != opened.st_dev || after.st_ino != opened.st_ino)
    rc = WYRELOG_E_POLICY;
  else
    rc = validate_regular_fd (fd, 0600, NULL, NULL, NULL);
  close (fd);
  if (rc == WYRELOG_E_OK && fsync (directory->graph_fd) != 0)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = directory_revalidate (directory);
  return rc;
}

wyrelog_error_t
wyl_fact_graph_directory_stage_create (WylFactGraphDirectory *directory,
    const gchar *final_basename, WylFactGraphStage *out_stage)
{
  if (out_stage == NULL)
    return WYRELOG_E_INVALID;
  *out_stage = (WylFactGraphStage) WYL_FACT_GRAPH_STAGE_INIT;
  if (!name_is_safe (final_basename))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = directory_revalidate (directory);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *uuid = g_uuid_string_random ();
  g_autofree gchar *stage = g_strdup_printf (".%s.stage-%s",
      final_basename, uuid);
  if (rc == WYRELOG_E_OK)
    rc = validate_name_length (directory->graph_fd, final_basename);
  if (rc == WYRELOG_E_OK)
    rc = validate_name_length (directory->graph_fd, stage);
  if (rc != WYRELOG_E_OK)
    return rc;
  gint fd = openat (directory->graph_fd, stage,
      O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0)
    return errno_to_resolver_error (errno);
  rc = validate_fd (fd, FALSE, 0600, &out_stage->device, &out_stage->inode);
  if (rc != WYRELOG_E_OK) {
    close (fd);
    (void) unlinkat (directory->graph_fd, stage, 0);
    return rc;
  }
  out_stage->stage_basename = g_steal_pointer (&stage);
  out_stage->final_basename = try_strdup (final_basename);
  if (out_stage->final_basename == NULL) {
    close (fd);
    (void) unlinkat (directory->graph_fd, out_stage->stage_basename, 0);
    wyl_fact_graph_stage_clear (out_stage);
    return WYRELOG_E_NOMEM;
  }
  out_stage->fd = fd;
  out_stage->graph_device = directory->graph_device;
  out_stage->graph_inode = directory->graph_inode;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
stage_names_validate (WylFactGraphDirectory *directory,
    const gchar *stage_basename, const gchar *final_basename)
{
  if (directory == NULL || !provisioning_stage_name_is_canonical
      (stage_basename) || !name_is_safe (final_basename)
      || g_strcmp0 (stage_basename, final_basename) == 0)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = directory_revalidate (directory);
  if (rc == WYRELOG_E_OK)
    rc = validate_name_length (directory->graph_fd, stage_basename);
  if (rc == WYRELOG_E_OK)
    rc = validate_name_length (directory->graph_fd, final_basename);
  return rc;
}

static wyrelog_error_t
stage_populate_exact (WylFactGraphDirectory *directory, gint fd,
    const gchar *stage_basename, const gchar *final_basename,
    gboolean allow_published_link, WylFactGraphStage *out_stage)
{
  guint64 device = 0;
  guint64 inode = 0;
  wyrelog_error_t rc = validate_fd (fd, FALSE, 0600, &device, &inode);
  struct stat named;
  if (rc == WYRELOG_E_OK && (fstat (fd, &named) != 0
          || (named.st_nlink != 1 && (!allow_published_link
                  || named.st_nlink != 2))))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK
      && (fstatat (directory->graph_fd, stage_basename, &named,
              AT_SYMLINK_NOFOLLOW) != 0
          || !stat_matches (&named, device, inode, FALSE, 0600)))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && named.st_nlink == 2
      && (fstatat (directory->graph_fd, final_basename, &named,
              AT_SYMLINK_NOFOLLOW) != 0
          || !stat_matches (&named, device, inode, FALSE, 0600)))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = directory_revalidate (directory);
  if (rc != WYRELOG_E_OK)
    return rc;
  out_stage->stage_basename = try_strdup (stage_basename);
  out_stage->final_basename = try_strdup (final_basename);
  if (out_stage->stage_basename == NULL || out_stage->final_basename == NULL) {
    g_clear_pointer (&out_stage->stage_basename, g_free);
    g_clear_pointer (&out_stage->final_basename, g_free);
    return WYRELOG_E_NOMEM;
  }
  out_stage->fd = fd;
  out_stage->device = device;
  out_stage->inode = inode;
  out_stage->graph_device = directory->graph_device;
  out_stage->graph_inode = directory->graph_inode;
  out_stage->exact_provisioning_stage = TRUE;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_graph_directory_stage_create_exact (WylFactGraphDirectory *directory,
    const gchar *operation_uuid, WylFactGraphStage *out_stage)
{
  if (out_stage == NULL)
    return WYRELOG_E_INVALID;
  *out_stage = (WylFactGraphStage) WYL_FACT_GRAPH_STAGE_INIT;
  g_autofree gchar *stage_basename = NULL;
  const gchar *final_basename = "facts.duckdb";
  wyrelog_error_t rc = provisioning_stage_name_from_operation (operation_uuid,
      &stage_basename);
  if (rc == WYRELOG_E_OK)
    rc = stage_names_validate (directory, stage_basename, final_basename);
  if (rc != WYRELOG_E_OK)
    return rc;
  gint fd = openat (directory->graph_fd, stage_basename,
      O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0)
    return errno == EEXIST ? WYRELOG_E_BUSY : errno_to_resolver_error (errno);
  rc = stage_populate_exact (directory, fd, stage_basename, final_basename,
      FALSE, out_stage);
  if (rc == WYRELOG_E_OK && directory->checkpoint != NULL)
    rc = directory->checkpoint ("stage-created", directory->checkpoint_data);
  if (rc == WYRELOG_E_OK && fsync (directory->graph_fd) != 0)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && directory->checkpoint != NULL)
    rc = directory->checkpoint ("stage-create-parent-synced",
        directory->checkpoint_data);
  if (rc == WYRELOG_E_OK)
    rc = directory_revalidate (directory);
  if (rc == WYRELOG_E_OK)
    return WYRELOG_E_OK;
  /* Do not unlink on a failed post-create check.  A pathname can be swapped
   * between validation and unlink; retaining a known name is fail-closed. */
  if (out_stage->fd >= 0)
    wyl_fact_graph_stage_clear (out_stage);
  else
    close (fd);
  return rc;
}

wyrelog_error_t
wyl_fact_graph_directory_stage_open_exact (WylFactGraphDirectory *directory,
    const gchar *operation_uuid, WylFactGraphStage *out_stage)
{
  if (out_stage == NULL)
    return WYRELOG_E_INVALID;
  *out_stage = (WylFactGraphStage) WYL_FACT_GRAPH_STAGE_INIT;
  g_autofree gchar *stage_basename = NULL;
  const gchar *final_basename = "facts.duckdb";
  wyrelog_error_t rc = provisioning_stage_name_from_operation (operation_uuid,
      &stage_basename);
  if (rc == WYRELOG_E_OK)
    rc = stage_names_validate (directory, stage_basename, final_basename);
  if (rc != WYRELOG_E_OK)
    return rc;
  struct stat before;
  if (fstatat (directory->graph_fd, stage_basename, &before,
          AT_SYMLINK_NOFOLLOW) != 0)
    return errno_to_resolver_error (errno);
  if (!S_ISREG (before.st_mode) || (before.st_nlink != 1
          && before.st_nlink != 2))
    return WYRELOG_E_POLICY;
  gint fd = openat (directory->graph_fd, stage_basename,
      O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return errno_to_resolver_error (errno);
  if (directory->checkpoint != NULL)
    rc = directory->checkpoint ("stage-opened", directory->checkpoint_data);
  if (rc == WYRELOG_E_OK)
    rc = stage_populate_exact (directory, fd, stage_basename, final_basename,
        TRUE, out_stage);
  if (rc != WYRELOG_E_OK)
    close (fd);
  return rc;
}

static wyrelog_error_t
provisioned_pair_stat (WylFactGraphDirectory *directory,
    const gchar *stage_basename, const gchar *final_basename,
    struct stat *out_final)
{
  struct stat stage;
  struct stat final;
  if (fstatat (directory->graph_fd, stage_basename, &stage,
          AT_SYMLINK_NOFOLLOW) != 0
      || fstatat (directory->graph_fd, final_basename, &final,
          AT_SYMLINK_NOFOLLOW) != 0)
    return errno ==
        ENOENT ? WYRELOG_E_NOT_FOUND : errno_to_resolver_error (errno);
  if (!S_ISREG (stage.st_mode) || !S_ISREG (final.st_mode)
      || stage.st_nlink != 2 || final.st_nlink != 2
      || !wyl_fact_graph_owner_mode_is_secure_for_test ((guint32) stage.st_mode,
          (guint64) stage.st_uid, (guint64) geteuid (), 0600)
      || !wyl_fact_graph_owner_mode_is_secure_for_test ((guint32) final.st_mode,
          (guint64) final.st_uid, (guint64) geteuid (), 0600)
      || stage.st_dev != final.st_dev || stage.st_ino != final.st_ino)
    return WYRELOG_E_POLICY;
  if (out_final != NULL)
    *out_final = final;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
provisioned_final_revalidate (WylFactGraphDirectory *directory,
    const gchar *final_basename, guint64 device, guint64 inode)
{
  struct stat final;
  if (fstatat (directory->graph_fd, final_basename, &final,
          AT_SYMLINK_NOFOLLOW) != 0)
    return errno_to_resolver_error (errno);
  if (!S_ISREG (final.st_mode) || final.st_nlink != 2
      || !wyl_fact_graph_owner_mode_is_secure_for_test ((guint32) final.st_mode,
          (guint64) final.st_uid, (guint64) geteuid (), 0600)
      || final.st_dev != (dev_t) device || final.st_ino != (ino_t) inode)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

wyrelog_error_t
    wyl_fact_graph_directory_open_provisioned_final_exact
    (WylFactGraphDirectory * directory, const gchar * operation_uuid,
    WylFactGraphRegularFile * out_final)
{
  if (out_final != NULL)
    *out_final = (WylFactGraphRegularFile) WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  if (out_final == NULL)
    return WYRELOG_E_INVALID;
  g_autofree gchar *stage_basename = NULL;
  const gchar *final_basename = "facts.duckdb";
  wyrelog_error_t rc = provisioning_stage_name_from_operation (operation_uuid,
      &stage_basename);
  if (rc == WYRELOG_E_OK)
    rc = stage_names_validate (directory, stage_basename, final_basename);
  struct stat expected;
  if (rc == WYRELOG_E_OK)
    rc = provisioned_pair_stat (directory, stage_basename, final_basename,
        &expected);
  gint fd = -1;
  if (rc == WYRELOG_E_OK) {
    fd = openat (directory->graph_fd, final_basename,
        O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
      rc = errno_to_resolver_error (errno);
  }
  if (rc == WYRELOG_E_OK && directory->checkpoint != NULL)
    rc = directory->checkpoint ("provisioned-final-opened",
        directory->checkpoint_data);
  guint64 device = 0;
  guint64 inode = 0;
  guint64 size = 0;
  if (rc == WYRELOG_E_OK)
    rc = validate_fd (fd, FALSE, 0600, &device, &inode);
  if (rc == WYRELOG_E_OK && (device != (guint64) expected.st_dev
          || inode != (guint64) expected.st_ino))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = provisioned_pair_stat (directory, stage_basename, final_basename,
        &expected);
  if (rc == WYRELOG_E_OK && directory->checkpoint != NULL)
    rc = directory->checkpoint ("provisioned-final-validated",
        directory->checkpoint_data);
  if (rc == WYRELOG_E_OK)
    rc = directory_revalidate (directory);
  /* Do not re-stat the stage here: a retained-stage handoff may replace its
   * name after pair validation.  The canonical final name must still bind to
   * the held descriptor before it is returned. */
  if (rc == WYRELOG_E_OK)
    rc = provisioned_final_revalidate (directory, final_basename, device,
        inode);
  if (rc == WYRELOG_E_OK) {
    struct stat held;
    if (fstat (fd, &held) != 0)
      rc = errno_to_resolver_error (errno);
    else if (!S_ISREG (held.st_mode) || held.st_nlink != 2
        || !wyl_fact_graph_owner_mode_is_secure_for_test ((guint32)
            held.st_mode, (guint64) held.st_uid, (guint64) geteuid (), 0600)
        || held.st_dev != (dev_t) device || held.st_ino != (ino_t) inode)
      rc = WYRELOG_E_POLICY;
    else
      size = (guint64) held.st_size;
  }
  if (rc != WYRELOG_E_OK) {
    if (fd >= 0)
      close (fd);
    return rc;
  }
  out_final->fd = fd;
  out_final->device = device;
  out_final->inode = inode;
  out_final->size_bytes = size;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_graph_stage_sync (WylFactGraphStage *stage)
{
  if (stage == NULL || stage->fd < 0)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = validate_fd (stage->fd, FALSE, 0600, NULL, NULL);
  if (rc != WYRELOG_E_OK)
    return rc;
  return fsync (stage->fd) == 0 ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static gboolean
stage_is_bound (WylFactGraphDirectory *directory, WylFactGraphStage *stage)
{
  return stage != NULL && stage->fd >= 0 && name_is_safe (stage->stage_basename)
      && name_is_safe (stage->final_basename)
      && stage->graph_device == directory->graph_device
      && stage->graph_inode == directory->graph_inode;
}

static wyrelog_error_t
named_stage_state (WylFactGraphDirectory *directory, const gchar *name,
    WylFactGraphStage *stage, gboolean *out_present, gboolean *out_exact)
{
  *out_present = FALSE;
  *out_exact = FALSE;
  struct stat named;
  if (fstatat (directory->graph_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0) {
    if (errno == ENOENT)
      return WYRELOG_E_OK;
    return errno_to_resolver_error (errno);
  }
  *out_present = TRUE;
  *out_exact = stat_matches (&named, stage->device, stage->inode, FALSE, 0600);
  return WYRELOG_E_OK;
}

static void
stage_mark_complete (WylFactGraphStage *stage)
{
  close (stage->fd);
  stage->fd = -1;
  g_clear_pointer (&stage->stage_basename, g_free);
  g_clear_pointer (&stage->final_basename, g_free);
  stage->device = 0;
  stage->inode = 0;
  stage->graph_device = 0;
  stage->graph_inode = 0;
  stage->exact_provisioning_stage = FALSE;
}

/* Link the held stage descriptor, never the mutable stage pathname.  This is
 * deliberately Linux-only: /proc/self/fd is the verified platform primitive
 * used to name the already-open descriptor while linkat keeps the destination
 * resolver-relative and no-replace.  A non-Linux POSIX build (or a Linux
 * system without a usable procfs fd view) fails closed; it must not substitute
 * a name-after-validation link. */
static wyrelog_error_t
link_held_stage_no_overwrite (WylFactGraphDirectory *directory,
    WylFactGraphStage *stage)
{
#ifdef __linux__
  g_autofree gchar *source = g_strdup_printf ("/proc/self/fd/%d", stage->fd);
  if (source == NULL)
    return WYRELOG_E_NOMEM;
  if (linkat (AT_FDCWD, source, directory->graph_fd, stage->final_basename,
          AT_SYMLINK_FOLLOW) != 0) {
    switch (errno) {
      case EEXIST:
      case EACCES:
      case EPERM:
      case ENOENT:
      case ENOTDIR:
      case ELOOP:
      case EXDEV:
      case EOPNOTSUPP:
        return WYRELOG_E_POLICY;
      default:
        return WYRELOG_E_IO;
    }
  }
  return WYRELOG_E_OK;
#else
  (void) directory;
  (void) stage;
  return WYRELOG_E_POLICY;
#endif
}

static wyrelog_error_t
exact_stage_publish (WylFactGraphDirectory *directory, WylFactGraphStage *stage)
{
  wyrelog_error_t rc = directory_revalidate (directory);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_stage_sync (stage);
  gboolean stage_present = FALSE;
  gboolean stage_exact = FALSE;
  gboolean final_present = FALSE;
  gboolean final_exact = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = named_stage_state (directory, stage->stage_basename, stage,
        &stage_present, &stage_exact);
  if (rc == WYRELOG_E_OK && directory->checkpoint != NULL)
    rc = directory->checkpoint ("stage-validated", directory->checkpoint_data);
  /* A lost stage name does not make the held descriptor unsafe, but checking
   * here detects deterministic replacement races before any namespace
   * mutation.  A later replacement cannot redirect the FD-based link. */
  if (rc == WYRELOG_E_OK)
    rc = named_stage_state (directory, stage->stage_basename, stage,
        &stage_present, &stage_exact);
  if (rc == WYRELOG_E_OK)
    rc = named_stage_state (directory, stage->final_basename, stage,
        &final_present, &final_exact);
  if (rc == WYRELOG_E_OK && final_present && !final_exact)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && !final_present)
    rc = link_held_stage_no_overwrite (directory, stage);
  if (rc == WYRELOG_E_OK && !final_present && directory->checkpoint != NULL)
    rc = directory->checkpoint ("stage-linked", directory->checkpoint_data);
  if (rc == WYRELOG_E_OK)
    rc = named_stage_state (directory, stage->final_basename, stage,
        &final_present, &final_exact);
  if (rc == WYRELOG_E_OK && (!final_present || !final_exact))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && fsync (directory->graph_fd) != 0)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && directory->checkpoint != NULL)
    rc = directory->checkpoint ("stage-parent-synced",
        directory->checkpoint_data);
  if (rc == WYRELOG_E_OK)
    rc = named_stage_state (directory, stage->final_basename, stage,
        &final_present, &final_exact);
  if (rc == WYRELOG_E_OK && (!final_present || !final_exact))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = directory_revalidate (directory);
  /* Keep the recorded stage hard link.  POSIX offers no fd-relative unlink;
   * deleting by its mutable name could remove an attacker replacement. */
  if (rc == WYRELOG_E_OK)
    stage_mark_complete (stage);
  return rc;
}

wyrelog_error_t
wyl_fact_graph_stage_publish (WylFactGraphDirectory *directory,
    WylFactGraphStage *stage)
{
  if (directory == NULL || !stage_is_bound (directory, stage))
    return WYRELOG_E_INVALID;
  if (stage->exact_provisioning_stage)
    return exact_stage_publish (directory, stage);
  wyrelog_error_t rc = directory_revalidate (directory);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_stage_sync (stage);
  gboolean stage_present = FALSE;
  gboolean stage_exact = FALSE;
  gboolean final_present = FALSE;
  gboolean final_exact = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = named_stage_state (directory, stage->stage_basename, stage,
        &stage_present, &stage_exact);
  if (rc == WYRELOG_E_OK)
    rc = named_stage_state (directory, stage->final_basename, stage,
        &final_present, &final_exact);
  if (rc == WYRELOG_E_OK && ((!stage_present && !final_present)
          || (stage_present && !stage_exact)
          || (final_present && !final_exact)))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && stage_exact && !final_present) {
    if (linkat (directory->graph_fd, stage->stage_basename,
            directory->graph_fd, stage->final_basename, 0) != 0)
      rc = errno_to_resolver_error (errno);
    else if (directory->checkpoint != NULL)
      rc = directory->checkpoint ("stage-linked", directory->checkpoint_data);
  }
  if (rc == WYRELOG_E_OK) {
    rc = named_stage_state (directory, stage->final_basename, stage,
        &final_present, &final_exact);
    if (rc == WYRELOG_E_OK && (!final_present || !final_exact))
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK && fsync (directory->graph_fd) != 0)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && stage_exact) {
    if (unlinkat (directory->graph_fd, stage->stage_basename, 0) != 0)
      rc = WYRELOG_E_IO;
    else if (directory->checkpoint != NULL)
      rc = directory->checkpoint ("stage-unlinked", directory->checkpoint_data);
  }
  if (rc == WYRELOG_E_OK && fsync (directory->graph_fd) != 0)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK) {
    rc = named_stage_state (directory, stage->final_basename, stage,
        &final_present, &final_exact);
    if (rc == WYRELOG_E_OK && (!final_present || !final_exact))
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    rc = directory_revalidate (directory);
  if (rc == WYRELOG_E_OK)
    stage_mark_complete (stage);
  return rc;
}

wyrelog_error_t
wyl_fact_graph_stage_abort (WylFactGraphDirectory *directory,
    WylFactGraphStage *stage)
{
  if (directory == NULL || !stage_is_bound (directory, stage))
    return WYRELOG_E_INVALID;
  /* Do not unlink an exact persisted stage by a name that may have been
   * replaced after validation.  The coordinator can degrade and retain this
   * known artifact; it must never clean up unknown bytes. */
  if (stage->exact_provisioning_stage)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = directory_revalidate (directory);
  gboolean stage_present = FALSE;
  gboolean stage_exact = FALSE;
  gboolean final_present = FALSE;
  gboolean final_exact = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = named_stage_state (directory, stage->stage_basename, stage,
        &stage_present, &stage_exact);
  if (rc == WYRELOG_E_OK)
    rc = named_stage_state (directory, stage->final_basename, stage,
        &final_present, &final_exact);
  if (rc == WYRELOG_E_OK && final_present)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && (!stage_present || !stage_exact))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK
      && unlinkat (directory->graph_fd, stage->stage_basename, 0) != 0)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && fsync (directory->graph_fd) != 0)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    stage_mark_complete (stage);
  return rc;
}

void
wyl_fact_graph_stage_clear (WylFactGraphStage *stage)
{
  if (stage == NULL)
    return;
  if (stage->fd >= 0)
    close (stage->fd);
  g_free (stage->stage_basename);
  g_free (stage->final_basename);
  *stage = (WylFactGraphStage) WYL_FACT_GRAPH_STAGE_INIT;
}
#endif

#ifdef G_OS_WIN32
void
wyl_fact_graph_regular_file_clear (WylFactGraphRegularFile *file)
{
  if (file == NULL)
    return;
  if (file->handle != NULL)
    CloseHandle ((HANDLE) file->handle);
  file->handle = NULL;
  memset (&file->identity, 0, sizeof file->identity);
  file->size_bytes = 0;
}
#endif

/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "wyctl-config.h"

#ifdef G_OS_UNIX
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/auxv.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#endif

#ifdef __APPLE__
#include <sys/acl.h>
#include <unistd.h>
#endif
#endif

/* wyctl enables this once in main; diagnostics describe the first unusable
 * fallback in that process, not each option or each settings handle. */
static gboolean diagnostics_enabled;
static gboolean diagnostic_emitted;
static gboolean rejected_schema_source;
static gboolean settings_suppressed_for_secure_execution;

#ifdef G_OS_UNIX
static gboolean
identity_is_secure (uid_t real_uid, uid_t effective_uid, uid_t saved_uid,
    gid_t real_gid, gid_t effective_gid, gid_t saved_gid,
    gboolean platform_secure)
{
  if (real_uid != effective_uid || saved_uid != effective_uid ||
      real_gid != effective_gid || saved_gid != effective_gid ||
      platform_secure)
    return TRUE;
  return FALSE;
}

static gboolean
is_secure_execution (void)
{
  uid_t real_uid = getuid (), effective_uid = geteuid ();
  uid_t saved_uid = effective_uid;
  gid_t real_gid = getgid (), effective_gid = getegid ();
  gid_t saved_gid = effective_gid;
  gboolean platform_secure = FALSE;
#if defined(__linux__)
  {
    uid_t saved_real_uid, saved_effective_uid, saved_uid_result;
    gid_t saved_real_gid, saved_effective_gid, saved_gid_result;
    if (getresuid (&saved_real_uid, &saved_effective_uid,
        &saved_uid_result) == 0) {
      real_uid = saved_real_uid;
      effective_uid = saved_effective_uid;
      saved_uid = saved_uid_result;
    }
    if (getresgid (&saved_real_gid, &saved_effective_gid,
        &saved_gid_result) == 0) {
      real_gid = saved_real_gid;
      effective_gid = saved_effective_gid;
      saved_gid = saved_gid_result;
    }
  }
#endif
#if defined(__linux__) && defined(AT_SECURE)
  if (getauxval (AT_SECURE) != 0)
    platform_secure = TRUE;
#endif
#if defined(__APPLE__)
  if (issetugid ())
    platform_secure = TRUE;
#endif
  return identity_is_secure (real_uid, effective_uid, saved_uid,
             real_gid, effective_gid, saved_gid, platform_secure);
}

#ifdef __linux__
static gboolean
linux_filesystem_magic_supported (long magic)
{
  return magic == XFS_SUPER_MAGIC || magic == EXT4_SUPER_MAGIC ||
         magic == BTRFS_SUPER_MAGIC || magic == TMPFS_MAGIC ||
         magic == RAMFS_MAGIC;
}
#endif

#ifdef WYCTL_CONFIG_TESTING
static const gchar *test_untrusted_filesystem_path;
#endif

static gboolean
has_supported_filesystem (const gchar *path)
{
#ifdef WYCTL_CONFIG_TESTING
  if (test_untrusted_filesystem_path != NULL &&
      g_strcmp0 (path, test_untrusted_filesystem_path) == 0)
    return FALSE;
#endif
#ifdef __linux__
  struct statfs fs;
  return statfs (path, &fs) == 0 &&
         linux_filesystem_magic_supported (fs.f_type);
#elif defined(__APPLE__)
  (void) path;
  return TRUE;
#else
  (void) path;
  return FALSE;
#endif
}

static gboolean
is_protected_mode (const struct stat *st, uid_t owner, gboolean allow_sticky)
{
  if ((st->st_uid == owner || st->st_uid == 0) &&
      (st->st_mode & (S_IWGRP | S_IWOTH)) == 0)
    return TRUE;
#if defined(__linux__)
  return allow_sticky && st->st_uid == 0 && S_ISDIR (st->st_mode) &&
         (st->st_mode & S_ISVTX) != 0;
#else
  (void) allow_sticky;
  return FALSE;
#endif
}

static gboolean
has_safe_acl (const gchar *path)
{
#ifdef __APPLE__
  acl_t acl = acl_get_file (path, ACL_TYPE_EXTENDED);
  if (acl == NULL)
    return errno == ENOENT;
  if (acl_valid (acl) != 0) {
    acl_free (acl);
    return FALSE;
  }
  gboolean safe = TRUE;
  acl_entry_t entry;
  int entry_id = ACL_FIRST_ENTRY;
  int next_entry;
  for (;;) {
    errno = 0;
    next_entry = acl_get_entry (acl, entry_id, &entry);
#ifdef __APPLE__
    if (next_entry == -1) {
      if (errno != EINVAL)
        safe = FALSE;
      break;
    }
    if (next_entry != 0) {
      safe = FALSE;
      break;
    }
#else
    if (next_entry == 0)
      break;
    if (next_entry < 0) {
      safe = FALSE;
      break;
    }
#endif
    entry_id = ACL_NEXT_ENTRY;
    acl_tag_t type;
    if (acl_get_tag_type (entry, &type) != 0) {
      safe = FALSE;
      break;
    }
    if (type != ACL_EXTENDED_ALLOW)
      continue;
    acl_permset_t perms;
    if (acl_get_permset (entry, &perms) != 0) {
      safe = FALSE;
      break;
    }
    const acl_perm_t mutations[] = { ACL_WRITE_DATA, ACL_APPEND_DATA,
                                     ACL_ADD_FILE, ACL_ADD_SUBDIRECTORY, ACL_DELETE, ACL_DELETE_CHILD,
                                     ACL_WRITE_ATTRIBUTES, ACL_WRITE_EXTATTRIBUTES, ACL_WRITE_SECURITY,
                                     ACL_CHANGE_OWNER };
    for (guint i = 0; i < G_N_ELEMENTS (mutations); i++) {
      int allowed = acl_get_perm_np (perms, mutations[i]);
      if (allowed != 0) {
        safe = FALSE;
        break;
      }
    }
    if (!safe)
      break;
  }
  acl_free (acl);
  return safe;
#else
  (void) path;
  return TRUE;
#endif
}

/* Walk without canonicalizing away components.  Every directory entry and
 * symlink in the spelling GLib will later open must itself be immutable to
 * an unprivileged writer; `..' is processed during traversal. Each entry is
 * checked beneath a parent already proved non-writable. The Linux sticky
 * exception additionally requires the next entry to be root-owned, so a
 * non-owner cannot replace it before GLib reopens the same pathname. */
static gboolean
trusted_schema_path (const gchar *path, uid_t owner, int *cache_fd)
{
  g_autofree gchar *absolute = NULL;
  g_auto (GStrv) pending = NULL;
  GPtrArray *resolved = g_ptr_array_new_with_free_func (g_free);
  guint links = 0;
  gboolean trusted = FALSE;
  struct stat root_st;

  if (stat (G_DIR_SEPARATOR_S, &root_st) != 0 || root_st.st_uid != 0 ||
      (root_st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
      !has_supported_filesystem (G_DIR_SEPARATOR_S) ||
      !has_safe_acl (G_DIR_SEPARATOR_S))
    goto out;

  if (path == NULL || path[0] == '\0')
    goto out;
  if (g_path_is_absolute (path))
    absolute = g_strdup (path);
  else {
    g_autofree gchar *cwd = g_get_current_dir ();
    if (cwd == NULL)
      goto out;
    absolute = g_build_filename (cwd, path, NULL);
  }
  pending = g_strsplit (absolute, G_DIR_SEPARATOR_S, -1);
  /* The stack contains path components below the trusted root. */
  for (guint i = 0; pending[i] != NULL; i++) {
    const gchar *part = pending[i];
    if (part[0] == '\0' || g_str_equal (part, "."))
      continue;
    if (g_str_equal (part, "..")) {
      if (resolved->len > 0)
        g_ptr_array_remove_index (resolved, resolved->len - 1);
      continue;
    }

    g_autofree gchar *prefix = g_strdup (G_DIR_SEPARATOR_S);
    for (guint j = 0; j < resolved->len; j++) {
      g_autofree gchar *next = g_build_filename (prefix,
              (const gchar *) g_ptr_array_index (resolved, j), NULL);
      g_free (g_steal_pointer (&prefix));
      prefix = g_steal_pointer (&next);
    }
    g_autofree gchar *candidate = g_build_filename (prefix, part, NULL);
    struct stat st;
    if (lstat (candidate, &st) != 0)
      goto out;

    if (S_ISLNK (st.st_mode)) {
      if (++links > 40 ||
          (st.st_uid != owner && st.st_uid != 0))
        goto out;
      /* The containing directory must be protected. Linux's sticky /tmp
       * rule is safe here only because the link itself is root-owned. */
      struct stat parent_st;
      if (stat (prefix, &parent_st) != 0 ||
          !is_protected_mode (&parent_st, owner, TRUE) ||
          !has_supported_filesystem (prefix) ||
          !has_supported_filesystem (candidate) ||
          !has_safe_acl (prefix) || !has_safe_acl (candidate))
        goto out;
      g_autofree gchar *target = g_malloc (PATH_MAX + 1);
      ssize_t n = readlink (candidate, target, PATH_MAX);
      if (n <= 0 || n >= PATH_MAX)
        goto out;
      target[n] = '\0';
      g_auto (GStrv) target_parts = g_strsplit (target,
              G_DIR_SEPARATOR_S, -1);
      /* Insert the link target ahead of the unvisited suffix. */
      GPtrArray *joined = g_ptr_array_new_with_free_func (g_free);
      if (g_path_is_absolute (target)) {
        g_ptr_array_set_size (resolved, 0);
      }
      for (guint j = 0; target_parts[j] != NULL; j++)
        g_ptr_array_add (joined, g_strdup (target_parts[j]));
      for (guint j = i + 1; pending[j] != NULL; j++)
        g_ptr_array_add (joined, g_strdup (pending[j]));
      g_ptr_array_add (joined, NULL);
      g_strfreev (pending);
      pending = (gchar **) g_ptr_array_free (joined, FALSE);
      i = (guint) -1;
      continue;
    }

    gboolean last = pending[i + 1] == NULL;
    if (last) {
      if (!S_ISREG (st.st_mode) || !is_protected_mode (&st, owner, FALSE) ||
          !has_safe_acl (candidate))
        goto out;
      int fd = open (candidate, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
      if (fd < 0)
        goto out;
      struct stat opened;
      gboolean same = fstat (fd, &opened) == 0 &&
          opened.st_dev == st.st_dev && opened.st_ino == st.st_ino &&
          S_ISREG (opened.st_mode) &&
          is_protected_mode (&opened, owner, FALSE);
#ifdef __linux__
      struct statfs fs;
      same = same && fstatfs (fd, &fs) == 0 &&
          linux_filesystem_magic_supported (fs.f_type);
#else
      same = same && has_supported_filesystem (candidate);
#endif
      if (!same) {
        close (fd);
        goto out;
      }
      if (cache_fd != NULL)
        *cache_fd = fd;
      else
        close (fd);
      trusted = TRUE;
      goto out;
    }
    if (!S_ISDIR (st.st_mode) || !is_protected_mode (&st, owner, TRUE) ||
        !has_supported_filesystem (candidate) ||
        !has_safe_acl (candidate))
      goto out;
    g_ptr_array_add (resolved, g_strdup (part));
  }

out:
  g_ptr_array_unref (resolved);
  return trusted;
}

static GSettingsSchemaSource *
open_filtered_schema_source (uid_t owner)
{
  g_autoptr (GPtrArray) dirs = g_ptr_array_new_with_free_func (g_free);
  const gchar *extra = g_getenv ("GSETTINGS_SCHEMA_DIR");
  if (extra != NULL && extra[0] != '\0') {
    g_auto (GStrv) entries = g_strsplit (extra, G_SEARCHPATH_SEPARATOR_S, -1);
    g_autofree gchar *cwd = g_get_current_dir ();
    for (guint i = 0; entries[i] != NULL; i++) {
      const gchar *entry = entries[i];
      g_autofree gchar *absolute = NULL;
      if (g_path_is_absolute (entry))
        absolute = g_strdup (entry);
      else if (cwd != NULL)
        absolute = g_build_filename (cwd,
                entry[0] == '\0' ? "." : entry, NULL);
      if (absolute == NULL) {
        rejected_schema_source = TRUE;
        continue;
      }
      g_ptr_array_add (dirs, g_strdup (absolute));
    }
  }
  g_ptr_array_add (dirs, g_build_filename (g_get_user_data_dir (),
      "glib-2.0", "schemas", NULL));
  const gchar * const *system_dirs = g_get_system_data_dirs ();
  for (guint i = 0; system_dirs[i] != NULL; i++)
    g_ptr_array_add (dirs, g_build_filename (system_dirs[i], "glib-2.0",
        "schemas", NULL));

  GSettingsSchemaSource *source = NULL;
  for (guint i = dirs->len; i > 0; i--) {
    const gchar *dir = g_ptr_array_index (dirs, i - 1);
    g_autofree gchar *cache = g_build_filename (dir, "gschemas.compiled",
            NULL);
    struct stat cache_st;
    if (lstat (cache, &cache_st) != 0) {
      if (errno == ENOENT)
        continue;
      rejected_schema_source = TRUE;
      continue;
    }
    if (!S_ISREG (cache_st.st_mode)) {
      rejected_schema_source = TRUE;
      continue;
    }
    int cache_fd = -1;
    if (!trusted_schema_path (cache, owner, &cache_fd)) {
      rejected_schema_source = TRUE;
      continue;
    }
    g_autoptr (GError) error = NULL;
    GSettingsSchemaSource *next = g_settings_schema_source_new_from_directory
          (dir, source, FALSE, &error);
    close (cache_fd);
    if (next == NULL) {
      rejected_schema_source = TRUE;
      continue;
    }
    if (source != NULL)
      g_settings_schema_source_unref (source);
    source = next;
  }
  return source;
}

#ifdef WYCTL_CONFIG_TESTING
GSettingsSchemaSource *
wyctl_config_test_open_filtered_source (uid_t owner)
{
  return open_filtered_schema_source (owner);
}

gboolean
wyctl_config_test_trusted_path (const gchar *path, uid_t owner)
{
  return trusted_schema_path (path, owner, NULL);
}

gboolean
wyctl_config_test_identity_is_secure (uid_t real_uid, uid_t effective_uid,
    uid_t saved_uid, gid_t real_gid, gid_t effective_gid, gid_t saved_gid,
    gboolean platform_secure)
{
  return identity_is_secure (real_uid, effective_uid, saved_uid,
             real_gid, effective_gid, saved_gid, platform_secure);
}

gboolean
wyctl_config_test_filesystem_magic_supported (long magic,
    gboolean inspection_succeeded)
{
#ifdef __linux__
  return inspection_succeeded && linux_filesystem_magic_supported (magic);
#else
  (void) magic;
  (void) inspection_succeeded;
  return FALSE;
#endif
}

gboolean
wyctl_config_test_filesystem_path_supported (const gchar *path)
{
  return has_supported_filesystem (path);
}

void
wyctl_config_test_reject_filesystem_path (const gchar *path)
{
  test_untrusted_filesystem_path = path;
}
#endif
#endif

void
wyctl_enable_settings_diagnostics (void)
{
  diagnostics_enabled = TRUE;
}

static void
report_unavailable_fallback (const gchar *reason)
{
  if (!diagnostics_enabled || diagnostic_emitted ||
      g_strcmp0 (g_getenv (WYCTL_GSETTINGS_DISABLE_ENV), "1") == 0)
    return;
  diagnostic_emitted = TRUE;
  if (settings_suppressed_for_secure_execution) {
    g_printerr ("wyctl: GSettings fallback unavailable: disabled for a ");
    g_printerr ("set-ID or secure-execution process; supply explicit CLI options\n");
    return;
  }
  if (rejected_schema_source) {
    g_printerr ("wyctl: GSettings fallback unavailable: an untrusted schema ");
    g_printerr ("source was ignored; use a protected schema directory or explicit CLI options\n");
    return;
  }
  g_printerr ("wyctl: GSettings fallback unavailable: %s (schema '%s'); "
      "install the matching wyctl schema and run glib-compile-schemas, "
      "check GSETTINGS_SCHEMA_DIR/XDG_DATA_HOME/XDG_DATA_DIRS, "
      "or supply explicit CLI options\n", reason, WYCTL_GSETTINGS_SCHEMA_ID);
}

GSettings *
wyctl_open_settings (void)
{
  const gchar *disable = g_getenv (WYCTL_GSETTINGS_DISABLE_ENV);
  if (disable != NULL && g_strcmp0 (disable, "1") == 0)
    return NULL;

#ifdef G_OS_UNIX
  if (is_secure_execution ()) {
    settings_suppressed_for_secure_execution = TRUE;
    return NULL;
  }

  g_autoptr (GSettingsSchemaSource) owned_source = NULL;
  GSettingsSchemaSource *source;
  if (geteuid () == 0) {
#if !defined(__linux__) && !defined(__APPLE__)
    rejected_schema_source = TRUE;
    return NULL;
#else
    owned_source = open_filtered_schema_source (0);
    source = owned_source;
#endif
  } else {
    source = g_settings_schema_source_get_default ();
  }
#else
  GSettingsSchemaSource *source = g_settings_schema_source_get_default ();
#endif
  if (source == NULL)
    return NULL;

  /* Recurse, because that is what g_settings_new does and what every
   * other GSettings client sees.  The lookup is hand-rolled only so a
   * missing schema yields NULL instead of aborting; the recursion flag was
   * never the point, and consulting the head source alone hid a correctly
   * installed schema from wyctl while gsettings found it (#1190). */
  GSettingsSchema *schema = g_settings_schema_source_lookup (source,
          WYCTL_GSETTINGS_SCHEMA_ID, TRUE);
  if (schema == NULL)
    return NULL;

  GSettings *settings = g_settings_new_full (schema, NULL, NULL);
  g_settings_schema_unref (schema);
  return settings;
}

/* Is `key' present in the schema behind `settings', with type `type'?
 *
 * Both resolvers below read a key the caller names, from a schema this
 * process did not choose: it is whatever carries the org.wyrelog.wyctl id
 * in the reachable sources.  A stale or partial install can therefore hand
 * back a schema that lacks a key, or declares it with another type, and
 * GLib treats both as programmer error.  Reading an absent key is a fatal
 * g_error.  Reading one of the wrong type is a CRITICAL, after which the
 * string read returns NULL and the unsigned read returns zero, which is
 * indistinguishable from a configured zero and goes on to the timeout
 * parser.  Neither is a diagnosis an operator can act on, and
 * wyctl-config.h promises this resolver never aborts.
 *
 * So ask first.  A key that is absent or of the wrong type resolves to
 * "unset", which is the same answer the caller already handles for an
 * empty value, and the caller's own missing-option diagnostic fires. */
static gboolean
wyctl_settings_has_key_of_type (GSettings *settings, const gchar *key,
    const GVariantType *type)
{
  g_autoptr (GSettingsSchema) schema = NULL;
  g_object_get (settings, "settings-schema", &schema, NULL);
  if (schema == NULL || !g_settings_schema_has_key (schema, key)) {
    g_autofree gchar *reason = g_strdup_printf ("missing key '%s'", key);
    report_unavailable_fallback (reason);
    return FALSE;
  }

  g_autoptr (GSettingsSchemaKey) schema_key =
      g_settings_schema_get_key (schema, key);
  const GVariantType *actual = g_settings_schema_key_get_value_type (schema_key);
  if (!g_variant_type_equal (actual, type)) {
    g_autofree gchar *expected_text = g_variant_type_dup_string (type);
    g_autofree gchar *actual_text = g_variant_type_dup_string (actual);
    g_autofree gchar *reason = g_strdup_printf
          ("key '%s' has type '%s', expected type '%s'", key,
            actual_text, expected_text);
    report_unavailable_fallback (reason);
    return FALSE;
  }
  return TRUE;
}

gchar *
wyctl_resolve_string_option (const gchar *cli_value, GSettings *settings,
    const gchar *key)
{
  if (cli_value != NULL)
    return g_strdup (cli_value);

  if (key == NULL)
    return NULL;
  if (rejected_schema_source || settings_suppressed_for_secure_execution)
    report_unavailable_fallback ("schema source trust check failed");
  if (settings == NULL) {
    report_unavailable_fallback ("schema not found");
    return NULL;
  }

  if (!wyctl_settings_has_key_of_type (settings, key, G_VARIANT_TYPE_STRING))
    return NULL;

  gchar *value = g_settings_get_string (settings, key);
  if (value == NULL || value[0] == '\0') {
    g_free (value);
    return NULL;
  }
  return value;
}

gchar *
wyctl_resolve_uint_option_as_string (const gchar *cli_value,
    GSettings *settings, const gchar *key)
{
  if (cli_value != NULL)
    return g_strdup (cli_value);

  if (key == NULL)
    return NULL;
  if (rejected_schema_source || settings_suppressed_for_secure_execution)
    report_unavailable_fallback ("schema source trust check failed");
  if (settings == NULL) {
    report_unavailable_fallback ("schema not found");
    return NULL;
  }

  if (!wyctl_settings_has_key_of_type (settings, key, G_VARIANT_TYPE_UINT32))
    return NULL;

  guint32 value = g_settings_get_uint (settings, key);
  return g_strdup_printf ("%u", value);
}

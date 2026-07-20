/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>

#ifdef G_OS_WIN32
#include <windows.h>
#include <aclapi.h>
#include <io.h>
#include <stddef.h>
#include <string.h>
#include <winioctl.h>
#include <wchar.h>

#include "fact/graph-locator-private.h"

typedef struct
{
  PSID user;
  PACL acl;
  SECURITY_DESCRIPTOR descriptor;
  SECURITY_ATTRIBUTES attributes;
} TestSecurity;

typedef struct
{
  DWORD tag;
  WORD data_length;
  WORD reserved;
  WORD substitute_offset;
  WORD substitute_length;
  WORD print_offset;
  WORD print_length;
  WCHAR path_buffer[1];
} TestMountPointReparseData;

static void
test_security_clear (TestSecurity *security)
{
  g_free (security->acl);
  g_free (security->user);
  memset (security, 0, sizeof *security);
}

static gboolean
copy_token_user (PSID *out_user)
{
  HANDLE token = NULL;
  TOKEN_USER *info = NULL;
  DWORD needed = 0;
  PSID copy = NULL;

  *out_user = NULL;
  if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token))
    return FALSE;
  GetTokenInformation (token, TokenUser, NULL, 0, &needed);
  if (GetLastError () != ERROR_INSUFFICIENT_BUFFER || needed == 0)
    goto out;
  info = g_malloc0 (needed);
  if (info == NULL
      || !GetTokenInformation (token, TokenUser, info, needed, &needed)
      || info->User.Sid == NULL || !IsValidSid (info->User.Sid))
    goto out;
  needed = GetLengthSid (info->User.Sid);
  copy = g_malloc (needed);
  if (copy == NULL || !CopySid (needed, copy, info->User.Sid))
    g_clear_pointer (&copy, g_free);
out:
  g_free (info);
  CloseHandle (token);
  *out_user = copy;
  return copy != NULL;
}

static gboolean
test_security_init (TestSecurity *security, BYTE ace_flags,
    gboolean protected_dacl)
{
  DWORD acl_length;

  memset (security, 0, sizeof *security);
  if (!copy_token_user (&security->user))
    return FALSE;
  acl_length = sizeof (ACL) + sizeof (ACCESS_ALLOWED_ACE) - sizeof (DWORD)
      + GetLengthSid (security->user);
  security->acl = g_malloc0 (acl_length);
  if (security->acl == NULL
      || !InitializeAcl (security->acl, acl_length, ACL_REVISION)
      || !AddAccessAllowedAceEx (security->acl, ACL_REVISION, ace_flags,
          FILE_ALL_ACCESS, security->user)
      || !InitializeSecurityDescriptor (&security->descriptor,
          SECURITY_DESCRIPTOR_REVISION)
      || !SetSecurityDescriptorOwner (&security->descriptor, security->user,
          FALSE)
      || !SetSecurityDescriptorDacl (&security->descriptor, TRUE,
          security->acl, FALSE)) {
    test_security_clear (security);
    return FALSE;
  }
  if (protected_dacl
      && !SetSecurityDescriptorControl (&security->descriptor,
          SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
    test_security_clear (security);
    return FALSE;
  }
  security->attributes.nLength = sizeof security->attributes;
  security->attributes.lpSecurityDescriptor = &security->descriptor;
  return TRUE;
}

static gunichar2 *
wide_path (const gchar *path)
{
  return g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
}

static gchar *
long_path (const gchar *path)
{
  g_autofree gunichar2 *wide = wide_path (path);
  if (wide == NULL)
    return NULL;

  DWORD capacity = MAX_PATH;
  g_autofree WCHAR *expanded = NULL;
  for (;;) {
    if (capacity > G_MAXSIZE / sizeof *expanded)
      return NULL;
    g_clear_pointer (&expanded, g_free);
    expanded = g_try_new0 (WCHAR, capacity);
    if (expanded == NULL)
      return NULL;
    DWORD length = GetLongPathNameW ((LPCWSTR) wide, expanded, capacity);
    if (length == 0)
      return NULL;
    if (length < capacity)
      break;
    capacity = length;
  }
  return g_utf16_to_utf8 ((const gunichar2 *) expanded, -1, NULL, NULL, NULL);
}

static gchar *
unique_path (const gchar *prefix)
{
  g_autofree gchar *temp = long_path (g_get_tmp_dir ());
  g_autofree gchar *uuid = g_uuid_string_random ();
  g_autofree gchar *name = g_strdup_printf ("%s-%lu-%s", prefix,
      (gulong) GetCurrentProcessId (), uuid);
  if (temp == NULL)
    return NULL;
  return g_build_filename (temp, name, NULL);
}

static gboolean
create_private_directory (const gchar *path)
{
  TestSecurity security;
  g_autofree gunichar2 *wide = wide_path (path);
  gboolean created;

  if (wide == NULL
      || !test_security_init (&security,
          OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, TRUE))
    return FALSE;
  created = CreateDirectoryW ((LPCWSTR) wide, &security.attributes);
  test_security_clear (&security);
  return created;
}

static gboolean
create_insecure_directory (const gchar *path)
{
  TestSecurity security;
  g_autofree gunichar2 *wide = wide_path (path);
  gboolean created;

  if (wide == NULL
      || !test_security_init (&security,
          OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, FALSE))
    return FALSE;
  created = CreateDirectoryW ((LPCWSTR) wide, &security.attributes);
  test_security_clear (&security);
  return created;
}

static gboolean
create_extra_ace_directory (const gchar *path)
{
  g_autofree PSID user = NULL;
  BYTE everyone_buffer[SECURITY_MAX_SID_SIZE] = { 0 };
  PSID everyone = (PSID) everyone_buffer;
  DWORD everyone_length = sizeof everyone_buffer;
  PACL acl = NULL;
  SECURITY_DESCRIPTOR descriptor = { 0 };
  SECURITY_ATTRIBUTES attributes = { 0 };
  g_autofree gunichar2 *wide = wide_path (path);
  gboolean created = FALSE;

  if (wide == NULL || !copy_token_user (&user)
      || !CreateWellKnownSid (WinWorldSid, NULL, everyone, &everyone_length))
    return FALSE;
  DWORD acl_length = sizeof (ACL)
      + 2 * (sizeof (ACCESS_ALLOWED_ACE) - sizeof (DWORD))
      + GetLengthSid (user) + GetLengthSid (everyone);
  acl = g_malloc0 (acl_length);
  if (acl == NULL || !InitializeAcl (acl, acl_length, ACL_REVISION)
      || !AddAccessAllowedAceEx (acl, ACL_REVISION,
          OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, FILE_ALL_ACCESS, user)
      || !AddAccessAllowedAceEx (acl, ACL_REVISION,
          OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, FILE_GENERIC_READ,
          everyone)
      || !InitializeSecurityDescriptor (&descriptor,
          SECURITY_DESCRIPTOR_REVISION)
      || !SetSecurityDescriptorOwner (&descriptor, user, FALSE)
      || !SetSecurityDescriptorDacl (&descriptor, TRUE, acl, FALSE)
      || !SetSecurityDescriptorControl (&descriptor, SE_DACL_PROTECTED,
          SE_DACL_PROTECTED))
    goto out;
  attributes.nLength = sizeof attributes;
  attributes.lpSecurityDescriptor = &descriptor;
  created = CreateDirectoryW ((LPCWSTR) wide, &attributes);
out:
  g_free (acl);
  return created;
}

static gboolean
create_private_file (const gchar *path, const gchar *contents)
{
  TestSecurity security;
  g_autofree gunichar2 *wide = wide_path (path);
  HANDLE handle = INVALID_HANDLE_VALUE;
  DWORD written = 0;
  gsize length = strlen (contents);
  gboolean ok = FALSE;

  if (wide == NULL || !test_security_init (&security, 0, TRUE))
    return FALSE;
  handle = CreateFileW ((LPCWSTR) wide, GENERIC_READ | GENERIC_WRITE | DELETE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      &security.attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  test_security_clear (&security);
  if (handle == INVALID_HANDLE_VALUE)
    return FALSE;
  ok = WriteFile (handle, contents, (DWORD) length, &written, NULL)
      && written == length && FlushFileBuffers (handle);
  CloseHandle (handle);
  return ok;
}

static gboolean
create_insecure_file (const gchar *path, const gchar *contents)
{
  g_autofree gunichar2 *wide = wide_path (path);
  HANDLE handle = wide != NULL ? CreateFileW ((LPCWSTR) wide,
      GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE
      | FILE_SHARE_DELETE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
      NULL) : INVALID_HANDLE_VALUE;
  DWORD written = 0;
  gsize length = strlen (contents);
  gboolean ok;

  if (handle == INVALID_HANDLE_VALUE)
    return FALSE;
  ok = WriteFile (handle, contents, (DWORD) length, &written, NULL)
      && written == length && FlushFileBuffers (handle);
  CloseHandle (handle);
  return ok;
}

typedef struct
{
  const gchar *expected_point;
  const gchar *target;
  const gchar *aside;
  gboolean fired;
} ReplacementRace;

static void
remove_tree_no_follow (const gchar *path)
{
  g_autofree gunichar2 *wide = wide_path (path);
  DWORD attributes;

  if (wide == NULL)
    return;
  attributes = GetFileAttributesW ((LPCWSTR) wide);
  if (attributes == INVALID_FILE_ATTRIBUTES)
    return;
  if ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
    g_assert_true (DeleteFileW ((LPCWSTR) wide));
    return;
  }
  if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
    g_assert_true (RemoveDirectoryW ((LPCWSTR) wide));
    return;
  }

  g_autofree gchar *pattern = g_build_filename (path, "*", NULL);
  g_autofree gunichar2 *wide_pattern = wide_path (pattern);
  WIN32_FIND_DATAW entry = { 0 };
  HANDLE find = FindFirstFileW ((LPCWSTR) wide_pattern, &entry);
  if (find != INVALID_HANDLE_VALUE) {
    do {
      if (wcscmp (entry.cFileName, L".") == 0
          || wcscmp (entry.cFileName, L"..") == 0)
        continue;
      g_autofree gchar *name = g_utf16_to_utf8 ((gunichar2 *) entry.cFileName,
          -1, NULL, NULL, NULL);
      g_assert_nonnull (name);
      g_autofree gchar *child = g_build_filename (path, name, NULL);
      remove_tree_no_follow (child);
    } while (FindNextFileW (find, &entry));
    g_assert_cmpuint (GetLastError (), ==, ERROR_NO_MORE_FILES);
    FindClose (find);
  } else {
    g_assert_cmpuint (GetLastError (), ==, ERROR_FILE_NOT_FOUND);
  }
  g_assert_true (RemoveDirectoryW ((LPCWSTR) wide));
}

static gchar *
make_root (void)
{
  gchar *root = unique_path ("wyl-fact-win");
  g_assert_nonnull (root);
  g_assert_true (create_private_directory (root));
  return root;
}

static gboolean
move_path (const gchar *source, const gchar *destination)
{
  g_autofree gunichar2 *wide_source = wide_path (source);
  g_autofree gunichar2 *wide_destination = wide_path (destination);
  return wide_source != NULL && wide_destination != NULL
      && MoveFileExW ((LPCWSTR) wide_source, (LPCWSTR) wide_destination, 0);
}

static gboolean
create_directory_junction (const gchar *junction, const gchar *target)
{
  g_autofree gunichar2 *wide_junction = wide_path (junction);
  g_autofree gunichar2 *wide_target = wide_path (target);
  g_autofree wchar_t *substitute = NULL;
  g_autofree TestMountPointReparseData *data = NULL;
  HANDLE handle = INVALID_HANDLE_VALUE;
  DWORD returned = 0;

  if (wide_junction == NULL || wide_target == NULL)
    return FALSE;
  substitute = g_new (wchar_t, wcslen ((wchar_t *) wide_target) + 5);
  if (substitute == NULL
      || swprintf (substitute, wcslen ((wchar_t *) wide_target) + 5,
          L"\\??\\%ls", (wchar_t *) wide_target) < 0)
    return FALSE;
  gsize substitute_bytes = wcslen (substitute) * sizeof (wchar_t);
  gsize target_bytes = wcslen ((wchar_t *) wide_target) * sizeof (wchar_t);
  gsize path_bytes = substitute_bytes + sizeof (wchar_t) + target_bytes
      + sizeof (wchar_t);
  gsize total = offsetof (TestMountPointReparseData, path_buffer) + path_bytes;
  if (total > MAXIMUM_REPARSE_DATA_BUFFER_SIZE
      || !CreateDirectoryW ((LPCWSTR) wide_junction, NULL))
    return FALSE;
  handle = CreateFileW ((LPCWSTR) wide_junction, GENERIC_WRITE, 0, NULL,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
      NULL);
  if (handle == INVALID_HANDLE_VALUE)
    goto fail;
  data = g_malloc0 (total);
  if (data == NULL)
    goto fail;
  data->tag = IO_REPARSE_TAG_MOUNT_POINT;
  data->data_length = (WORD) (total - 8);
  data->substitute_length = (WORD) substitute_bytes;
  data->print_offset = (WORD) (substitute_bytes + sizeof (wchar_t));
  data->print_length = (WORD) target_bytes;
  memcpy (data->path_buffer, substitute, substitute_bytes);
  memcpy ((guint8 *) data->path_buffer + data->print_offset,
      wide_target, target_bytes);
  gboolean ok = DeviceIoControl (handle, FSCTL_SET_REPARSE_POINT, data,
      (DWORD) total, NULL, 0, &returned, NULL);
  CloseHandle (handle);
  if (ok)
    return TRUE;
fail:
  if (handle != INVALID_HANDLE_VALUE)
    CloseHandle (handle);
  RemoveDirectoryW ((LPCWSTR) wide_junction);
  return FALSE;
}

static void
init_locator (WylFactGraphLocator *locator, const gchar *tenant,
    const gchar *graph)
{
  *locator = (WylFactGraphLocator) {
  0};
  g_assert_cmpint (wyl_fact_graph_locator_init (locator, tenant, graph), ==,
      WYRELOG_E_OK);
}

static void
open_graph (const gchar *root, WylFactGraphLocator *locator,
    WylFactGraphResolver *resolver, WylFactGraphDirectory *directory)
{
  *resolver = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
  *directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (resolver, locator,
          TRUE, directory), ==, WYRELOG_E_OK);
}

static void
test_create_revalidate_and_component_lengths (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphLocator locator = { 0 };
  g_autofree gchar *graph_id = g_strnfill (128, 'G');
  g_autofree gchar *too_long = g_strnfill (300, 't');

  init_locator (&locator, "tenant/a", graph_id);
  g_assert_cmpuint (strlen (locator.graph_component), ==, 208);
  open_graph (root, &locator, &resolver, &graph);
  g_assert_cmpint (wyl_fact_graph_resolver_revalidate (&resolver), ==,
      WYRELOG_E_OK);
  g_autofree gchar *path = wyl_fact_graph_directory_descriptive_path (&graph);
  g_assert_true (g_file_test (path, G_FILE_TEST_IS_DIR));
  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_locator_clear (&locator);

  init_locator (&locator, too_long, "graph");
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver, &locator,
          TRUE, &graph), ==, WYRELOG_E_POLICY);

  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree_no_follow (root);
}

static void
test_rejects_reserved_names_and_uppercase_alias (void)
{
  static const gchar *reserved[] = {
    "CON", "NUL", "COM1", "COM\xc2\xb9", "LPT\xc2\xb3", "facts.", "facts ",
    "facts:stream",
  };
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphLocator locator = { 0 };

  init_locator (&locator, "tenant", "graph");
  open_graph (root, &locator, &resolver, &graph);
  for (gsize i = 0; i < G_N_ELEMENTS (reserved); i++) {
    WylFactGraphStage stage = WYL_FACT_GRAPH_STAGE_INIT;
    g_autofree gchar *path =
        wyl_fact_graph_directory_descriptive_file (&graph, reserved[i]);
    g_assert_null (path);
    g_assert_cmpint (wyl_fact_graph_directory_stage_create (&graph,
            reserved[i], &stage), !=, WYRELOG_E_OK);
    wyl_fact_graph_stage_clear (&stage);
  }
  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  remove_tree_no_follow (root);

  g_clear_pointer (&root, g_free);
  root = make_root ();
  g_autofree gchar *alias = g_ascii_strup (locator.tenant_component, -1);
  g_autofree gchar *alias_path = g_build_filename (root, alias, NULL);
  g_assert_true (create_private_directory (alias_path));
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver, &locator,
          FALSE, &graph), ==, WYRELOG_E_POLICY);

  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree_no_follow (root);
}

static void
test_rejects_insecure_acls (void)
{
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphLocator locator = { 0 };
  g_autofree gchar *root = unique_path ("wyl-fact-insecure-root");

  init_locator (&locator, "tenant", "graph");
  g_assert_true (create_insecure_directory (root));
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_POLICY);
  remove_tree_no_follow (root);

  g_clear_pointer (&root, g_free);
  root = unique_path ("wyl-fact-extra-ace-root");
  g_assert_true (create_extra_ace_directory (root));
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_POLICY);
  remove_tree_no_follow (root);

  g_clear_pointer (&root, g_free);
  root = make_root ();
  g_autofree gchar *tenant = g_build_filename (root,
      locator.tenant_component, NULL);
  g_assert_true (create_insecure_directory (tenant));
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver, &locator,
          FALSE, &graph), ==, WYRELOG_E_POLICY);
  wyl_fact_graph_resolver_clear (&resolver);
  remove_tree_no_follow (root);

  g_clear_pointer (&root, g_free);
  root = make_root ();
  g_clear_pointer (&tenant, g_free);
  tenant = g_build_filename (root, locator.tenant_component, NULL);
  g_assert_true (create_private_directory (tenant));
  g_autofree gchar *graph_path = g_build_filename (tenant,
      locator.graph_component, NULL);
  g_assert_true (create_insecure_directory (graph_path));
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver, &locator,
          FALSE, &graph), ==, WYRELOG_E_POLICY);

  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree_no_follow (root);
}

static wyrelog_error_t
replace_file_checkpoint (const gchar *point, gpointer user_data)
{
  ReplacementRace *race = user_data;
  if (g_strcmp0 (point, race->expected_point) != 0)
    return WYRELOG_E_OK;
  g_assert_false (race->fired);
  race->fired = TRUE;
  g_assert_true (move_path (race->target, race->aside));
  g_assert_true (create_private_file (race->target, "replacement"));
  return WYRELOG_E_OK;
}

static void
test_file_replacement_checkpoint_fails_closed (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphLocator locator = { 0 };

  init_locator (&locator, "tenant", "graph");
  open_graph (root, &locator, &resolver, &graph);
  g_autofree gchar *file =
      wyl_fact_graph_directory_descriptive_file (&graph, "facts.duckdb");
  g_autofree gchar *aside = g_strdup_printf ("%s-raced", file);
  g_assert_true (create_private_file (file, "original"));
  ReplacementRace race = {
    .expected_point = "file-opened",
    .target = file,
    .aside = aside,
  };
  graph.checkpoint = replace_file_checkpoint;
  graph.checkpoint_data = &race;
  gint fd = -1;
  g_assert_cmpint (wyl_fact_graph_directory_open_file (&graph,
          "facts.duckdb", FALSE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
  g_assert_true (race.fired);
  g_autofree gchar *contents = NULL;
  g_assert_true (g_file_get_contents (file, &contents, NULL, NULL));
  g_assert_cmpstr (contents, ==, "replacement");
  graph.checkpoint = NULL;
  graph.checkpoint_data = NULL;
  remove_tree_no_follow (file);
  g_assert_true (move_path (aside, file));

  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree_no_follow (root);
}

static wyrelog_error_t
replace_directory_checkpoint (const gchar *point, gpointer user_data)
{
  ReplacementRace *race = user_data;
  if (g_strcmp0 (point, race->expected_point) != 0)
    return WYRELOG_E_OK;
  g_assert_false (race->fired);
  race->fired = TRUE;
  g_assert_true (move_path (race->target, race->aside));
  g_assert_true (create_private_directory (race->target));
  return WYRELOG_E_OK;
}

static void
restore_replacement (ReplacementRace *race)
{
  g_assert_true (race->fired);
  remove_tree_no_follow (race->target);
  g_assert_true (move_path (race->aside, race->target));
}

static void
test_replacement_checkpoints_fail_closed (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphLocator locator = { 0 };

  init_locator (&locator, "tenant", "graph");
  open_graph (root, &locator, &resolver, &graph);
  wyl_fact_graph_directory_clear (&graph);
  g_autofree gchar *tenant = g_build_filename (root,
      locator.tenant_component, NULL);
  g_autofree gchar *graph_path = g_build_filename (tenant,
      locator.graph_component, NULL);
  static const gchar *points[] = {
    "root-opened", "tenant-opened", "graph-opened",
  };
  const gchar *targets[] = { root, tenant, graph_path };

  for (gsize i = 0; i < G_N_ELEMENTS (points); i++) {
    g_autofree gchar *aside = g_strdup_printf ("%s-raced", targets[i]);
    ReplacementRace race = {
      .expected_point = points[i],
      .target = targets[i],
      .aside = aside,
    };
    wyl_fact_graph_resolver_set_checkpoint_for_test (&resolver,
        replace_directory_checkpoint, &race);
    g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
            &locator, FALSE, &graph), ==, WYRELOG_E_POLICY);
    restore_replacement (&race);
  }

  wyl_fact_graph_resolver_set_checkpoint_for_test (&resolver, NULL, NULL);
  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree_no_follow (root);
}

static void
test_reparse_points_fail_closed (void)
{
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphLocator locator = { 0 };
  g_autofree gchar *root = make_root ();
  g_autofree gchar *target = g_build_filename (root, "target", NULL);
  g_autofree gchar *root_link = g_build_filename (root, "root-link", NULL);

  init_locator (&locator, "tenant", "graph");
  g_assert_true (create_private_directory (target));
  g_assert_true (create_directory_junction (root_link, target));
  g_assert_cmpint (wyl_fact_graph_resolver_open (root_link, &resolver), ==,
      WYRELOG_E_POLICY);

  g_autofree gchar *tenant = g_build_filename (root,
      locator.tenant_component, NULL);
  g_assert_true (create_directory_junction (tenant, target));
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver, &locator,
          FALSE, &graph), ==, WYRELOG_E_POLICY);
  remove_tree_no_follow (tenant);

  g_assert_true (create_private_directory (tenant));
  g_autofree gchar *graph_path = g_build_filename (tenant,
      locator.graph_component, NULL);
  g_assert_true (create_directory_junction (graph_path, target));
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver, &locator,
          FALSE, &graph), ==, WYRELOG_E_POLICY);
  remove_tree_no_follow (graph_path);

  g_assert_true (create_private_directory (graph_path));
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver, &locator,
          FALSE, &graph), ==, WYRELOG_E_OK);
  g_autofree gchar *file = g_build_filename (graph_path, "facts.duckdb", NULL);
  g_assert_true (create_directory_junction (file, target));
  gint fd = -1;
  g_assert_cmpint (wyl_fact_graph_directory_open_file (&graph,
          "facts.duckdb", FALSE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);

  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree_no_follow (root);
}

static void
test_file_acl_hardening (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphLocator locator = { 0 };

  init_locator (&locator, "tenant", "graph");
  open_graph (root, &locator, &resolver, &graph);
  g_autofree gchar *file =
      wyl_fact_graph_directory_descriptive_file (&graph, "facts.duckdb");
  g_assert_true (create_insecure_file (file, "db"));
  gint fd = -1;
  g_assert_cmpint (wyl_fact_graph_directory_open_file (&graph,
          "facts.duckdb", FALSE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_graph_directory_secure_file_mode (&graph,
          "facts.duckdb"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_directory_open_file (&graph,
          "facts.duckdb", FALSE, &fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (_close (fd), ==, 0);

  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree_no_follow (root);
}

static void
test_stage_roundtrip_and_abort (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphStage stage = WYL_FACT_GRAPH_STAGE_INIT;

  init_locator (&locator, "tenant", "graph");
  open_graph (root, &locator, &resolver, &graph);
  g_assert_cmpint (wyl_fact_graph_directory_stage_create (&graph,
          "facts.duckdb", &stage), ==, WYRELOG_E_OK);
  g_assert_cmpint (_write (stage.fd, "duck", 4), ==, 4);
  g_assert_cmpint (wyl_fact_graph_stage_sync (&stage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_stage_publish (&graph, &stage), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (stage.fd, ==, -1);
  gint fd = -1;
  g_assert_cmpint (wyl_fact_graph_directory_open_file (&graph,
          "facts.duckdb", FALSE, &fd), ==, WYRELOG_E_OK);
  gchar buffer[5] = { 0 };
  g_assert_cmpint (_read (fd, buffer, 4), ==, 4);
  g_assert_cmpstr (buffer, ==, "duck");
  g_assert_cmpint (_close (fd), ==, 0);

  g_assert_cmpint (wyl_fact_graph_directory_stage_create (&graph,
          "aborted.duckdb", &stage), ==, WYRELOG_E_OK);
  g_autofree gchar *stage_path = g_build_filename (root,
      locator.tenant_component, locator.graph_component,
      stage.stage_basename, NULL);
  g_assert_true (g_file_test (stage_path, G_FILE_TEST_EXISTS));
  g_assert_cmpint (wyl_fact_graph_stage_abort (&graph, &stage), ==,
      WYRELOG_E_OK);
  g_assert_false (g_file_test (stage_path, G_FILE_TEST_EXISTS));

  wyl_fact_graph_stage_clear (&stage);
  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree_no_follow (root);
}

static void
test_stage_attack_bindings (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory graph_a = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphDirectory graph_b = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphLocator locator_a = { 0 };
  WylFactGraphLocator locator_b = { 0 };
  WylFactGraphStage stage = WYL_FACT_GRAPH_STAGE_INIT;

  init_locator (&locator_a, "tenant", "a");
  init_locator (&locator_b, "tenant", "b");
  open_graph (root, &locator_a, &resolver, &graph_a);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
          &locator_b, TRUE, &graph_b), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_directory_stage_create (&graph_a,
          "cross.duckdb", &stage), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_stage_publish (&graph_b, &stage), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_graph_stage_abort (&graph_a, &stage), ==,
      WYRELOG_E_OK);

  g_assert_cmpint (wyl_fact_graph_directory_stage_create (&graph_a,
          "foreign.duckdb", &stage), ==, WYRELOG_E_OK);
  g_assert_cmpint (_write (stage.fd, "owned", 5), ==, 5);
  g_autofree gchar *final =
      wyl_fact_graph_directory_descriptive_file (&graph_a, "foreign.duckdb");
  g_assert_true (create_private_file (final, "foreign"));
  g_assert_cmpint (wyl_fact_graph_stage_publish (&graph_a, &stage), ==,
      WYRELOG_E_POLICY);
  g_autofree gchar *contents = NULL;
  g_assert_true (g_file_get_contents (final, &contents, NULL, NULL));
  g_assert_cmpstr (contents, ==, "foreign");
  wyl_fact_graph_stage_clear (&stage);

  g_assert_cmpint (wyl_fact_graph_directory_stage_create (&graph_a,
          "replaced.duckdb", &stage), ==, WYRELOG_E_OK);
  g_autofree gchar *graph_path =
      wyl_fact_graph_directory_descriptive_path (&graph_a);
  g_autofree gchar *named_stage = g_build_filename (graph_path,
      stage.stage_basename, NULL);
  g_autofree gchar *aside = g_strdup_printf ("%s-aside", named_stage);
  g_assert_true (move_path (named_stage, aside));
  g_assert_true (create_private_file (named_stage, "replacement"));
  g_assert_cmpint (wyl_fact_graph_stage_publish (&graph_a, &stage), ==,
      WYRELOG_E_POLICY);
  wyl_fact_graph_stage_clear (&stage);

  wyl_fact_graph_directory_clear (&graph_b);
  wyl_fact_graph_directory_clear (&graph_a);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator_b);
  wyl_fact_graph_locator_clear (&locator_a);
  remove_tree_no_follow (root);
}

typedef struct
{
  const gchar *point;
  gboolean fired;
} PublishFault;

static wyrelog_error_t
fail_publish_once (const gchar *point, gpointer user_data)
{
  PublishFault *fault = user_data;
  if (!fault->fired && g_strcmp0 (point, fault->point) == 0) {
    fault->fired = TRUE;
    return WYRELOG_E_IO;
  }
  return WYRELOG_E_OK;
}

static void
test_publish_retries_converge (void)
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphDirectory graph = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphLocator locator = { 0 };
  static const gchar *points[] = { "stage-linked", "stage-unlinked" };

  init_locator (&locator, "tenant", "graph");
  open_graph (root, &locator, &resolver, &graph);
  for (gsize i = 0; i < G_N_ELEMENTS (points); i++) {
    g_autofree gchar *final = g_strdup_printf ("retry-%zu.duckdb", i);
    WylFactGraphStage stage = WYL_FACT_GRAPH_STAGE_INIT;
    PublishFault fault = {.point = points[i] };
    g_assert_cmpint (wyl_fact_graph_directory_stage_create (&graph, final,
            &stage), ==, WYRELOG_E_OK);
    g_assert_cmpint (_write (stage.fd, "retry", 5), ==, 5);
    graph.checkpoint = fail_publish_once;
    graph.checkpoint_data = &fault;
    g_assert_cmpint (wyl_fact_graph_stage_publish (&graph, &stage), ==,
        WYRELOG_E_IO);
    g_assert_true (fault.fired);
    graph.checkpoint = NULL;
    graph.checkpoint_data = NULL;
    g_assert_cmpint (wyl_fact_graph_stage_publish (&graph, &stage), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (stage.fd, ==, -1);
  }

  wyl_fact_graph_directory_clear (&graph);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_fact_graph_locator_clear (&locator);
  remove_tree_no_follow (root);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact-graph-locator/windows/create-revalidate-lengths",
      test_create_revalidate_and_component_lengths);
  g_test_add_func ("/fact-graph-locator/windows/reserved-case-alias",
      test_rejects_reserved_names_and_uppercase_alias);
  g_test_add_func ("/fact-graph-locator/windows/insecure-acls",
      test_rejects_insecure_acls);
  g_test_add_func ("/fact-graph-locator/windows/replacement-checkpoints",
      test_replacement_checkpoints_fail_closed);
  g_test_add_func ("/fact-graph-locator/windows/file-replacement-checkpoint",
      test_file_replacement_checkpoint_fails_closed);
  g_test_add_func ("/fact-graph-locator/windows/reparse-components",
      test_reparse_points_fail_closed);
  g_test_add_func ("/fact-graph-locator/windows/file-acl-hardening",
      test_file_acl_hardening);
  g_test_add_func ("/fact-graph-locator/windows/stage-roundtrip-abort",
      test_stage_roundtrip_and_abort);
  g_test_add_func ("/fact-graph-locator/windows/stage-attack-bindings",
      test_stage_attack_bindings);
  g_test_add_func ("/fact-graph-locator/windows/publish-retry",
      test_publish_retries_converge);
  return g_test_run ();
}
#endif

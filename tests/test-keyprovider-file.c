/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>

#include "wyrelog/wyl-keyprovider-file-private.h"

static gboolean
write_key (const gchar *path, guint8 seed)
{
  guint8 key[32];
  for (gsize i = 0; i < sizeof key; i++)
    key[i] = (guint8) (seed + i);
  return g_file_set_contents (path, (const gchar *) key, sizeof key, NULL);
}

static gint
check_file_spec_roundtrip (void)
{
  g_autoptr (GError) err = NULL;
  g_autofree gchar *tmpdir = g_dir_make_tmp ("wyl-kp-file-XXXXXX", &err);
  if (tmpdir == NULL)
    return 1;
  g_autofree gchar *path = g_build_filename (tmpdir, "policy.key", NULL);
  if (!write_key (path, 1))
    return 2;

  g_autofree gchar *spec = g_strdup_printf ("file:%s", path);
  g_autoptr (wyl_keyprovider_file_t) self =
      wyl_keyprovider_file_new_from_spec (spec);
  if (self == NULL)
    return 3;
  if (g_strcmp0 (wyl_keyprovider_file_get_source_name (self), "file") != 0)
    return 4;

  const wyl_keyprovider_vtable_t *vt = wyl_keyprovider_file_get_vtable ();
  if (vt->probe (self) != WYRELOG_E_OK)
    return 5;

  const guint8 plaintext[] = { 'w', 'y', 'r', 'e', 'l', 'o', 'g' };
  wyl_sealed_blob_t blob = { 0 };
  if (vt->seal (self, plaintext, sizeof plaintext, &blob) != WYRELOG_E_OK)
    return 6;
  if (blob.len <= sizeof plaintext || blob.bytes == NULL)
    return 7;
  if (memcmp (blob.bytes, plaintext, sizeof plaintext) == 0)
    return 8;

  guint8 recovered[sizeof plaintext];
  gsize written = 0;
  if (vt->unseal (self, &blob, recovered, sizeof recovered, &written)
      != WYRELOG_E_OK)
    return 9;
  if (written != sizeof plaintext || memcmp (recovered, plaintext,
          sizeof plaintext) != 0)
    return 10;
  g_free (blob.bytes);

  g_unlink (path);
  g_rmdir (tmpdir);
  return 0;
}

static gint
check_wrong_provider_state_fails_unseal (void)
{
  g_autoptr (GError) err = NULL;
  g_autofree gchar *tmpdir = g_dir_make_tmp ("wyl-kp-wrong-XXXXXX", &err);
  if (tmpdir == NULL)
    return 20;
  g_autofree gchar *path_a = g_build_filename (tmpdir, "a.key", NULL);
  g_autofree gchar *path_b = g_build_filename (tmpdir, "b.key", NULL);
  if (!write_key (path_a, 11) || !write_key (path_b, 99))
    return 21;

  g_autoptr (wyl_keyprovider_file_t) a = wyl_keyprovider_file_new (path_a);
  g_autoptr (wyl_keyprovider_file_t) b = wyl_keyprovider_file_new (path_b);
  if (a == NULL || b == NULL)
    return 22;

  const wyl_keyprovider_vtable_t *vt = wyl_keyprovider_file_get_vtable ();
  const guint8 plaintext[] = { 1, 2, 3, 4 };
  wyl_sealed_blob_t blob = { 0 };
  if (vt->seal (a, plaintext, sizeof plaintext, &blob) != WYRELOG_E_OK)
    return 23;

  guint8 recovered[sizeof plaintext] = { 0 };
  gsize written = 0;
  if (vt->unseal (b, &blob, recovered, sizeof recovered, &written)
      != WYRELOG_E_CRYPTO)
    return 24;
  if (written != 0)
    return 25;
  g_free (blob.bytes);

  g_unlink (path_a);
  g_unlink (path_b);
  g_rmdir (tmpdir);
  return 0;
}

static gint
check_systemd_credentials_spec (void)
{
  g_autoptr (GError) err = NULL;
  g_autofree gchar *tmpdir = g_dir_make_tmp ("wyl-kp-creds-XXXXXX", &err);
  if (tmpdir == NULL)
    return 30;
  g_autofree gchar *path = g_build_filename (tmpdir, "policy.key", NULL);
  if (!write_key (path, 33))
    return 31;

  const gchar *old_dir = g_getenv ("CREDENTIALS_DIRECTORY");
  g_autofree gchar *old_dir_copy = g_strdup (old_dir);
  g_setenv ("CREDENTIALS_DIRECTORY", tmpdir, TRUE);

  g_autoptr (wyl_keyprovider_file_t) self =
      wyl_keyprovider_file_new_from_spec ("systemd-creds:policy.key");
  if (old_dir_copy != NULL)
    g_setenv ("CREDENTIALS_DIRECTORY", old_dir_copy, TRUE);
  else
    g_unsetenv ("CREDENTIALS_DIRECTORY");
  if (self == NULL)
    return 32;
  if (g_strcmp0 (wyl_keyprovider_file_get_source_name (self),
          "systemd-creds") != 0)
    return 33;

  const wyl_keyprovider_vtable_t *vt = wyl_keyprovider_file_get_vtable ();
  guint8 key_a[16];
  guint8 key_b[16];
  if (vt->derive (self, "label-a", key_a, sizeof key_a) != WYRELOG_E_OK)
    return 34;
  if (vt->derive (self, "label-b", key_b, sizeof key_b) != WYRELOG_E_OK)
    return 35;
  if (memcmp (key_a, key_b, sizeof key_a) == 0)
    return 36;

  g_unlink (path);
  g_rmdir (tmpdir);
  return 0;
}

static gint
check_unavailable_and_invalid_specs_fail_closed (void)
{
  const gchar *old_dir = g_getenv ("CREDENTIALS_DIRECTORY");
  g_autofree gchar *old_dir_copy = g_strdup (old_dir);
  g_unsetenv ("CREDENTIALS_DIRECTORY");

  g_autoptr (wyl_keyprovider_file_t) missing =
      wyl_keyprovider_file_new_from_spec ("systemd-creds:policy.key");
  if (old_dir_copy != NULL)
    g_setenv ("CREDENTIALS_DIRECTORY", old_dir_copy, TRUE);
  if (missing != NULL)
    return 40;
  if (wyl_keyprovider_file_new_from_spec ("systemd-creds:../policy.key")
      != NULL)
    return 41;
  if (wyl_keyprovider_file_new_from_spec ("systemd-creds:dir/policy.key")
      != NULL)
    return 42;
  if (wyl_keyprovider_file_new_from_spec ("file:") != NULL)
    return 43;
  return 0;
}

static gint
check_wipe_fails_closed (void)
{
  g_autoptr (GError) err = NULL;
  g_autofree gchar *tmpdir = g_dir_make_tmp ("wyl-kp-wipe-XXXXXX", &err);
  if (tmpdir == NULL)
    return 50;
  g_autofree gchar *path = g_build_filename (tmpdir, "policy.key", NULL);
  if (!write_key (path, 51))
    return 51;

  g_autoptr (wyl_keyprovider_file_t) self = wyl_keyprovider_file_new (path);
  if (self == NULL)
    return 52;

  const wyl_keyprovider_vtable_t *vt = wyl_keyprovider_file_get_vtable ();
  vt->wipe (self);
  if (vt->probe (self) != WYRELOG_E_INTERNAL)
    return 53;
  guint8 out[16] = { 0 };
  if (vt->derive (self, "label", out, sizeof out) != WYRELOG_E_INTERNAL)
    return 54;

  g_unlink (path);
  g_rmdir (tmpdir);
  return 0;
}

int
main (void)
{
  gint rc;
  if ((rc = check_file_spec_roundtrip ()) != 0)
    return rc;
  if ((rc = check_wrong_provider_state_fails_unseal ()) != 0)
    return rc;
  if ((rc = check_systemd_credentials_spec ()) != 0)
    return rc;
  if ((rc = check_unavailable_and_invalid_specs_fail_closed ()) != 0)
    return rc;
  if ((rc = check_wipe_fails_closed ()) != 0)
    return rc;
  return 0;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700
#endif

#include <glib.h>
#include <glib/gstdio.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyl-keyprovider-file-private.h"

#ifndef G_OS_WIN32
#include <unistd.h>
#endif

#ifndef WYL_TEST_SQLITE_SCHEMA_PATH
#error "WYL_TEST_SQLITE_SCHEMA_PATH must be defined by the build."
#endif

static gint
check_store_creates_authority_schema (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 10;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 11;

  for (gsize i = 0; i < wyl_policy_store_required_table_count (); i++) {
    gboolean exists = FALSE;
    const gchar *table = wyl_policy_store_required_table_name (i);
    if (wyl_policy_store_table_exists (store, table, &exists) != WYRELOG_E_OK)
      return 12;
    if (!exists)
      return 13;
  }
  if (wyl_policy_store_required_table_name
      (wyl_policy_store_required_table_count ()) != NULL)
    return 14;

  return 0;
}

static gint
check_template_schema_creates_state_tables (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_autofree gchar *schema = NULL;
  gsize schema_len = 0;
  g_autoptr (GError) error = NULL;
  char *errmsg = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 20;
  if (!g_file_get_contents (WYL_TEST_SQLITE_SCHEMA_PATH, &schema,
          &schema_len, &error))
    return 21;
  if (sqlite3_exec (wyl_policy_store_get_db (store), schema, NULL, NULL,
          &errmsg) != SQLITE_OK) {
    sqlite3_free (errmsg);
    return 22;
  }

  for (gsize i = 0; i < wyl_policy_store_required_table_count (); i++) {
    gboolean exists = FALSE;
    const gchar *table = wyl_policy_store_required_table_name (i);
    if (wyl_policy_store_table_exists (store, table, &exists) != WYRELOG_E_OK)
      return 23;
    if (!exists)
      return 24;
  }
  return 0;
}

static gint
check_store_rejects_invalid_args (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 30;
  gboolean exists = FALSE;
  if (wyl_policy_store_create_schema (NULL) != WYRELOG_E_INVALID)
    return 31;
  if (wyl_policy_store_table_exists (NULL, "roles", &exists)
      != WYRELOG_E_INVALID)
    return 32;
  if (wyl_policy_store_table_exists (store, NULL, &exists)
      != WYRELOG_E_INVALID)
    return 33;
  if (wyl_policy_store_table_exists (store, "roles", NULL)
      != WYRELOG_E_INVALID)
    return 34;
  if (wyl_policy_store_set_deployment_mode (NULL, "production")
      != WYRELOG_E_INVALID)
    return 35;
  if (wyl_policy_store_set_deployment_mode (store, NULL) != WYRELOG_E_INVALID)
    return 36;
  if (wyl_policy_store_get_deployment_mode (NULL, NULL) != WYRELOG_E_INVALID)
    return 37;
  if (wyl_policy_store_get_deployment_mode (store, NULL)
      != WYRELOG_E_INVALID)
    return 38;
  if (wyl_policy_store_apply_permission_state_transition (NULL, "user",
          "perm", "scope", "grant", NULL) != WYRELOG_E_INVALID)
    return 39;
  if (wyl_policy_store_apply_permission_state_transition (store, NULL,
          "perm", "scope", "grant", NULL) != WYRELOG_E_INVALID)
    return 56;
  if (wyl_policy_store_apply_permission_state_transition (store, "user",
          NULL, "scope", "grant", NULL) != WYRELOG_E_INVALID)
    return 57;
  if (wyl_policy_store_apply_permission_state_transition (store, "user",
          "perm", NULL, "grant", NULL) != WYRELOG_E_INVALID)
    return 62;
  if (wyl_policy_store_apply_permission_state_transition (store, "user",
          "perm", "scope", NULL, NULL) != WYRELOG_E_INVALID)
    return 63;
  if (wyl_policy_store_apply_permission_state_transition (store, "user",
          "perm", "scope", "bogus", NULL) != WYRELOG_E_INVALID)
    return 64;
  return 0;
}

static gint
check_store_gets_default_deployment_mode (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_autofree gchar *mode = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 40;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 41;
  if (wyl_policy_store_get_deployment_mode (store, &mode) != WYRELOG_E_OK)
    return 42;
  if (g_strcmp0 (mode, "production") != 0)
    return 43;
  return 0;
}

typedef struct
{
  guint count;
  gboolean saw_default;
  gboolean saw_tenant_a;
  gboolean tenant_a_sealed;
} TenantIterProbe;

static wyrelog_error_t
tenant_iter_probe_cb (const gchar *tenant_id, gboolean sealed,
    gpointer user_data)
{
  TenantIterProbe *probe = user_data;
  probe->count++;
  if (g_strcmp0 (tenant_id, "__wr_default") == 0)
    probe->saw_default = TRUE;
  if (g_strcmp0 (tenant_id, "tenant-a") == 0) {
    probe->saw_tenant_a = TRUE;
    probe->tenant_a_sealed = sealed;
  }
  return WYRELOG_E_OK;
}

static gint
check_store_manages_tenant_registry (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  gboolean created = FALSE;
  gboolean exists = FALSE;
  gboolean active = FALSE;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 65;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 66;
  if (wyl_policy_store_tenant_exists (store, "__wr_default", &exists)
      != WYRELOG_E_OK || !exists)
    return 67;
  if (wyl_policy_store_tenant_is_active (store, "__wr_default", &active)
      != WYRELOG_E_OK || !active)
    return 68;
  if (wyl_policy_store_create_tenant (store, "tenant-a", &created)
      != WYRELOG_E_OK || !created)
    return 69;
  if (wyl_policy_store_create_tenant (store, "tenant-a", &created)
      != WYRELOG_E_OK || created)
    return 70;
  if (wyl_policy_store_set_tenant_sealed (store, "tenant-a", TRUE)
      != WYRELOG_E_OK)
    return 71;
  if (wyl_policy_store_tenant_is_active (store, "tenant-a", &active)
      != WYRELOG_E_OK || active)
    return 72;
  if (wyl_policy_store_set_tenant_sealed (store, "__wr_default", TRUE)
      != WYRELOG_E_POLICY)
    return 73;
  if (wyl_policy_store_create_tenant (store, "bad tenant", &created)
      != WYRELOG_E_INVALID)
    return 74;

  TenantIterProbe probe = { 0 };
  if (wyl_policy_store_foreach_tenant (store, tenant_iter_probe_cb, &probe)
      != WYRELOG_E_OK)
    return 75;
  if (probe.count != 2 || !probe.saw_default || !probe.saw_tenant_a ||
      !probe.tenant_a_sealed)
    return 76;
  return 0;
}

static gint
check_store_sets_deployment_mode (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_autofree gchar *mode = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 44;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 45;
  if (wyl_policy_store_set_deployment_mode (store, "development")
      != WYRELOG_E_OK)
    return 46;
  if (wyl_policy_store_get_deployment_mode (store, &mode) != WYRELOG_E_OK)
    return 47;
  if (g_strcmp0 (mode, "development") != 0)
    return 48;

  g_clear_pointer (&mode, g_free);
  if (wyl_policy_store_set_deployment_mode (store, "demo") != WYRELOG_E_OK)
    return 49;
  if (wyl_policy_store_get_deployment_mode (store, &mode) != WYRELOG_E_OK)
    return 50;
  if (g_strcmp0 (mode, "demo") != 0)
    return 51;
  const gchar *bad_modes[] = { "test", "", " demo", "DEMO" };
  for (gsize i = 0; i < G_N_ELEMENTS (bad_modes); i++) {
    if (wyl_policy_store_set_deployment_mode (store, bad_modes[i])
        != WYRELOG_E_POLICY)
      return 52;
  }
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "UPDATE wyrelog_config SET config_value = 'test' "
          "WHERE config_key = 'deployment_mode';", NULL, NULL, NULL)
      == SQLITE_OK)
    return 53;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 54;
  g_clear_pointer (&mode, g_free);
  if (wyl_policy_store_get_deployment_mode (store, &mode) != WYRELOG_E_OK)
    return 55;
  if (g_strcmp0 (mode, "demo") != 0)
    return 56;
  return 0;
}

static gint
check_handle_owns_policy_store (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 30;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (store == NULL)
    return 31;
  if (wyl_policy_store_get_db (store) == NULL)
    return 32;

  gboolean exists = FALSE;
  if (wyl_policy_store_table_exists (store, "role_permissions", &exists)
      != WYRELOG_E_OK)
    return 33;
  if (!exists)
    return 34;
  return 0;
}

static gboolean
write_policy_key (const gchar *path, guint8 seed)
{
  guint8 key[32];
  for (gsize i = 0; i < sizeof key; i++)
    key[i] = (guint8) (seed + i);
  return g_file_set_contents (path, (const gchar *) key, sizeof key, NULL);
}

static wyrelog_error_t
open_encrypted_policy_store (const gchar *store_path, const gchar *key_path,
    wyl_policy_store_t **out_store)
{
  wyl_keyprovider_file_t *keyprovider = wyl_keyprovider_file_new (key_path);
  if (keyprovider == NULL)
    return WYRELOG_E_IO;
  wyl_policy_store_open_options_t opts = {
    .path = store_path,
    .keyprovider_vtable = wyl_keyprovider_file_get_vtable (),
    .keyprovider_state = keyprovider,
    .keyprovider_state_free = (void (*)(gpointer)) wyl_keyprovider_file_free,
    .require_encrypted = TRUE,
  };
  return wyl_policy_store_open_with_options (&opts, out_store);
}

static wyrelog_error_t
rotate_encrypted_policy_store (const gchar *store_path,
    const gchar *old_key_path, const gchar *new_key_path)
{
  wyl_keyprovider_file_t *old_keyprovider =
      wyl_keyprovider_file_new (old_key_path);
  if (old_keyprovider == NULL)
    return WYRELOG_E_IO;
  wyl_keyprovider_file_t *new_keyprovider =
      wyl_keyprovider_file_new (new_key_path);
  if (new_keyprovider == NULL) {
    wyl_keyprovider_file_free (old_keyprovider);
    return WYRELOG_E_IO;
  }
  const wyl_keyprovider_vtable_t *vt = wyl_keyprovider_file_get_vtable ();
  wyl_policy_store_open_options_t old_opts = {
    .keyprovider_vtable = vt,
    .keyprovider_state = old_keyprovider,
    .keyprovider_state_free = (void (*)(gpointer)) wyl_keyprovider_file_free,
    .require_encrypted = TRUE,
  };
  wyl_policy_store_open_options_t new_opts = {
    .keyprovider_vtable = vt,
    .keyprovider_state = new_keyprovider,
    .keyprovider_state_free = (void (*)(gpointer)) wyl_keyprovider_file_free,
    .require_encrypted = TRUE,
  };
  return wyl_policy_store_rotate_keyprovider (store_path, &old_opts, &new_opts);
}

static wyrelog_error_t
failing_keyprovider_probe (gpointer self)
{
  (void) self;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
failing_keyprovider_derive (gpointer self, const gchar *label, guint8 *out_key,
    gsize out_len)
{
  (void) self;
  (void) label;
  (void) out_key;
  (void) out_len;
  return WYRELOG_E_INTERNAL;
}

static wyrelog_error_t
failing_keyprovider_seal (gpointer self, const guint8 *plaintext,
    gsize plaintext_len, wyl_sealed_blob_t *out_blob)
{
  (void) self;
  (void) plaintext;
  (void) plaintext_len;
  if (out_blob != NULL)
    *out_blob = (wyl_sealed_blob_t) {
    0};
  return WYRELOG_E_INTERNAL;
}

static wyrelog_error_t
failing_keyprovider_unseal (gpointer self, const wyl_sealed_blob_t *blob,
    guint8 *out, gsize capacity, gsize *written)
{
  (void) self;
  (void) blob;
  (void) out;
  (void) capacity;
  (void) written;
  return WYRELOG_E_INTERNAL;
}

static void
failing_keyprovider_wipe (gpointer self)
{
  (void) self;
}

static void
failing_keyprovider_clear_blob (gpointer self, wyl_sealed_blob_t *blob)
{
  (void) self;
  if (blob == NULL)
    return;
  g_free (blob->bytes);
  *blob = (wyl_sealed_blob_t) {
  0};
}

static const wyl_keyprovider_vtable_t failing_keyprovider_vtable = {
  .probe = failing_keyprovider_probe,
  .seal = failing_keyprovider_seal,
  .unseal = failing_keyprovider_unseal,
  .derive = failing_keyprovider_derive,
  .wipe = failing_keyprovider_wipe,
  .clear_sealed_blob = failing_keyprovider_clear_blob,
};

static wyrelog_error_t
rotate_encrypted_policy_store_to_failing_provider (const gchar *store_path,
    const gchar *old_key_path)
{
  wyl_keyprovider_file_t *old_keyprovider =
      wyl_keyprovider_file_new (old_key_path);
  if (old_keyprovider == NULL)
    return WYRELOG_E_IO;
  const guint8 failing_state = 0;
  wyl_policy_store_open_options_t old_opts = {
    .keyprovider_vtable = wyl_keyprovider_file_get_vtable (),
    .keyprovider_state = old_keyprovider,
    .keyprovider_state_free = (void (*)(gpointer)) wyl_keyprovider_file_free,
    .require_encrypted = TRUE,
  };
  wyl_policy_store_open_options_t new_opts = {
    .keyprovider_vtable = &failing_keyprovider_vtable,
    .keyprovider_state = (gpointer) & failing_state,
    .require_encrypted = TRUE,
  };
  return wyl_policy_store_rotate_keyprovider (store_path, &old_opts, &new_opts);
}

static gint
check_encrypted_policy_store_hardening_and_rotation (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *tmpdir = g_dir_make_tmp ("wyl-policy-enc-XXXXXX", &error);
  if (tmpdir == NULL)
    return 300;
  g_autofree gchar *store_path =
      g_build_filename (tmpdir, "policy.store", NULL);
  g_autofree gchar *old_key_path = g_build_filename (tmpdir, "old.key", NULL);
  g_autofree gchar *new_key_path = g_build_filename (tmpdir, "new.key", NULL);
  g_autofree gchar *wrong_key_path =
      g_build_filename (tmpdir, "wrong.key", NULL);
  if (!write_policy_key (old_key_path, 1)
      || !write_policy_key (new_key_path, 44)
      || !write_policy_key (wrong_key_path, 99))
    return 301;

  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    if (open_encrypted_policy_store (store_path, old_key_path, &store)
        != WYRELOG_E_OK)
      return 302;
    if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
      return 303;
    if (wyl_policy_store_set_deployment_mode (store, "development")
        != WYRELOG_E_OK)
      return 304;
    char *sqlite_error = NULL;
    if (sqlite3_exec (wyl_policy_store_get_db (store),
            "INSERT INTO service_credential_cvk"
            " (slot,generation,envelope_format_version,provider_binding,"
            "sealed_cvk,created_at_us,updated_at_us)"
            " VALUES(1,1,1,zeroblob(32),x'010203',1,1);", NULL, NULL,
            &sqlite_error) != SQLITE_OK) {
      sqlite3_free (sqlite_error);
      return 333;
    }
  }

  g_autofree gchar *valid_bytes = NULL;
  gsize valid_len = 0;
  if (!g_file_get_contents (store_path, &valid_bytes, &valid_len, &error))
    return 305;
  if (valid_len < 96)
    return 306;
  if (memcmp (valid_bytes, "WYLPS", 5) != 0)
    return 307;
  if (((const guint8 *) valid_bytes)[5] != 1)
    return 308;
#ifndef G_OS_WIN32
  struct stat st;
  if (g_stat (store_path, &st) != 0)
    return 309;
  if ((st.st_mode & 0777) != 0600)
    return 310;
#endif

  g_autoptr (wyl_policy_store_t) wrong_store = NULL;
  if (open_encrypted_policy_store (store_path, wrong_key_path, &wrong_store)
      == WYRELOG_E_OK)
    return 311;

  g_autofree gchar *variant_path = g_build_filename (tmpdir, "variant.store",
      NULL);
  g_autofree gchar *variant_bytes = g_memdup2 (valid_bytes, valid_len);
  variant_bytes[0] ^= 0x01;
  if (!g_file_set_contents (variant_path, variant_bytes, valid_len, NULL))
    return 312;
  g_autoptr (wyl_policy_store_t) variant_store = NULL;
  if (open_encrypted_policy_store (variant_path, old_key_path, &variant_store)
      == WYRELOG_E_OK)
    return 313;

  memcpy (variant_bytes, valid_bytes, valid_len);
  ((guint8 *) variant_bytes)[5] = 0xff;
  if (!g_file_set_contents (variant_path, variant_bytes, valid_len, NULL))
    return 314;
  g_clear_pointer (&variant_store, wyl_policy_store_close);
  if (open_encrypted_policy_store (variant_path, old_key_path, &variant_store)
      == WYRELOG_E_OK)
    return 315;

  memcpy (variant_bytes, valid_bytes, valid_len);
  variant_bytes[8] ^= 0x01;
  if (!g_file_set_contents (variant_path, variant_bytes, valid_len, NULL))
    return 316;
  g_clear_pointer (&variant_store, wyl_policy_store_close);
  if (open_encrypted_policy_store (variant_path, old_key_path, &variant_store)
      == WYRELOG_E_OK)
    return 317;

  if (!g_file_set_contents (variant_path, valid_bytes, valid_len - 3, NULL))
    return 318;
  g_clear_pointer (&variant_store, wyl_policy_store_close);
  if (open_encrypted_policy_store (variant_path, old_key_path, &variant_store)
      == WYRELOG_E_OK)
    return 319;

  g_autofree gchar *tmp_write_path = g_strdup_printf ("%s.wyrelog-tmp",
      store_path);
  if (!g_file_set_contents (tmp_write_path, "interrupted", -1, NULL))
    return 320;
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_autofree gchar *mode = NULL;
    if (open_encrypted_policy_store (store_path, old_key_path, &store)
        != WYRELOG_E_OK)
      return 321;
    if (wyl_policy_store_get_deployment_mode (store, &mode) != WYRELOG_E_OK)
      return 322;
    if (g_strcmp0 (mode, "development") != 0)
      return 323;
  }

  if (rotate_encrypted_policy_store (store_path, old_key_path, new_key_path)
      != WYRELOG_E_POLICY)
    return 324;
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    if (open_encrypted_policy_store (store_path, old_key_path, &store)
        != WYRELOG_E_OK)
      return 338;
    wyl_policy_service_cvk_info_t cvk = { 0 };
    if (wyl_policy_store_load_service_cvk (store, &cvk) != WYRELOG_E_OK
        || cvk.sealed_cvk_len != 3
        || memcmp (cvk.sealed_cvk, "\x01\x02\x03", 3) != 0) {
      wyl_policy_service_cvk_info_clear (&cvk);
      return 339;
    }
    wyl_policy_service_cvk_info_clear (&cvk);
    if (sqlite3_exec (wyl_policy_store_get_db (store),
            "DELETE FROM service_credential_cvk;", NULL, NULL, NULL)
        != SQLITE_OK)
      return 340;
  }
  if (rotate_encrypted_policy_store (store_path, old_key_path, new_key_path)
      != WYRELOG_E_OK)
    return 341;
  g_clear_pointer (&wrong_store, wyl_policy_store_close);
  if (open_encrypted_policy_store (store_path, old_key_path, &wrong_store)
      == WYRELOG_E_OK)
    return 325;
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_autofree gchar *mode = NULL;
    if (open_encrypted_policy_store (store_path, new_key_path, &store)
        != WYRELOG_E_OK)
      return 326;
    if (wyl_policy_store_get_deployment_mode (store, &mode) != WYRELOG_E_OK)
      return 327;
    if (g_strcmp0 (mode, "development") != 0)
      return 328;
    wyl_policy_service_cvk_info_t cvk = { 0 };
    if (wyl_policy_store_load_service_cvk (store, &cvk)
        != WYRELOG_E_NOT_FOUND)
      return 334;
    wyl_policy_service_cvk_info_clear (&cvk);
  }

  if (rotate_encrypted_policy_store_to_failing_provider (store_path,
          new_key_path)
      == WYRELOG_E_OK)
    return 329;
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_autofree gchar *mode = NULL;
    if (open_encrypted_policy_store (store_path, new_key_path, &store)
        != WYRELOG_E_OK)
      return 330;
    if (wyl_policy_store_get_deployment_mode (store, &mode) != WYRELOG_E_OK)
      return 331;
    if (g_strcmp0 (mode, "development") != 0)
      return 332;
    wyl_policy_service_cvk_info_t cvk = { 0 };
    if (wyl_policy_store_load_service_cvk (store, &cvk)
        != WYRELOG_E_NOT_FOUND)
      return 336;
    wyl_policy_service_cvk_info_clear (&cvk);
  }

  (void) g_remove (tmp_write_path);
  (void) g_remove (variant_path);
  (void) g_remove (store_path);
  (void) g_remove (old_key_path);
  (void) g_remove (new_key_path);
  (void) g_remove (wrong_key_path);
  (void) g_rmdir (tmpdir);
  return 0;
}

static gint
count_rows (wyl_policy_store_t *store, const gchar *sql, gint *out_count)
{
  sqlite3_stmt *stmt = NULL;

  if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), sql, -1, &stmt,
          NULL) != SQLITE_OK)
    return 1;

  int rc = sqlite3_step (stmt);
  if (rc != SQLITE_ROW) {
    sqlite3_finalize (stmt);
    return 2;
  }

  *out_count = sqlite3_column_int (stmt, 0);
  sqlite3_finalize (stmt);
  return 0;
}

typedef struct
{
  guint count;
  gboolean saw_tenant_a;
  gboolean saw_tenant_b;
  gboolean tenant_a_sealed;
  gchar *tenant_a_path;
  gchar *tenant_b_path;
  gchar *tenant_a_uri;
} FactGraphIterProbe;

static void
fact_graph_iter_probe_clear (FactGraphIterProbe *probe)
{
  if (probe == NULL)
    return;
  g_clear_pointer (&probe->tenant_a_path, g_free);
  g_clear_pointer (&probe->tenant_b_path, g_free);
  g_clear_pointer (&probe->tenant_a_uri, g_free);
}

static wyrelog_error_t
fact_graph_iter_probe_cb (const wyl_policy_fact_graph_info_t *info,
    gpointer user_data)
{
  FactGraphIterProbe *probe = user_data;
  probe->count++;
  if (g_strcmp0 (info->tenant_id, "tenant-a") == 0) {
    probe->saw_tenant_a = TRUE;
    probe->tenant_a_sealed = info->sealed;
    g_free (probe->tenant_a_path);
    g_free (probe->tenant_a_uri);
    probe->tenant_a_path = g_strdup (info->storage_path);
    probe->tenant_a_uri = g_strdup (info->storage_uri);
    if (info->schema_version != 1
        || g_strcmp0 (info->owner_scope, "tenant-a") != 0)
      return WYRELOG_E_POLICY;
  }
  if (g_strcmp0 (info->tenant_id, "tenant-b") == 0) {
    probe->saw_tenant_b = TRUE;
    g_free (probe->tenant_b_path);
    probe->tenant_b_path = g_strdup (info->storage_path);
  }
  return WYRELOG_E_OK;
}

static void
cleanup_fact_graph_root (const gchar *root)
{
  if (root == NULL)
    return;
  g_autofree gchar *tenant_a_graph =
      g_build_filename (root, "tenant-a", "graph-main", NULL);
  g_autofree gchar *tenant_a_other =
      g_build_filename (root, "tenant-a", "graph-sealed", NULL);
  g_autofree gchar *tenant_b_graph =
      g_build_filename (root, "tenant-b", "graph-main", NULL);
  g_autofree gchar *tenant_a = g_build_filename (root, "tenant-a", NULL);
  g_autofree gchar *tenant_b = g_build_filename (root, "tenant-b", NULL);
  (void) g_rmdir (tenant_a_graph);
  (void) g_rmdir (tenant_a_other);
  (void) g_rmdir (tenant_b_graph);
  (void) g_rmdir (tenant_a);
  (void) g_rmdir (tenant_b);
  (void) g_rmdir (root);
}

static wyl_policy_fact_graph_create_options_t
make_fact_graph_options (const gchar *tenant_id, const gchar *graph_id,
    const gchar *fact_root,
    const wyl_policy_fact_graph_relation_t *relations, gsize n_relations,
    const wyl_policy_fact_graph_query_t *queries, gsize n_queries)
{
  wyl_policy_fact_graph_create_options_t opts = {
    .tenant_id = tenant_id,
    .graph_id = graph_id,
    .fact_root = fact_root,
    .schema_version = 1,
    .owner_scope = tenant_id,
    .relations = relations,
    .n_relations = n_relations,
    .queries = queries,
    .n_queries = n_queries,
  };
  return opts;
}

static gint
check_store_manages_fact_graph_registry (void)
{
#ifdef G_OS_WIN32
#define WYL_TEST_FACT_ROOT "C:\\\\wyrelog-facts"
  g_autoptr (wyl_policy_store_t) store = NULL;
  gboolean created = FALSE;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 390;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 391;
  if (wyl_policy_store_create_tenant (store, "tenant-a", &created)
      != WYRELOG_E_OK || !created)
    return 392;
  const wyl_policy_fact_graph_column_t columns[] = {
    {"subject", "symbol"},
  };
  const wyl_policy_fact_graph_relation_t relations[] = {
    {"site.node", columns, G_N_ELEMENTS (columns)},
  };
  wyl_policy_fact_graph_create_options_t opts =
      make_fact_graph_options ("tenant-a", "graph-main", WYL_TEST_FACT_ROOT,
      relations, G_N_ELEMENTS (relations), NULL, 0);
  if (wyl_policy_store_create_fact_graph (store, &opts, NULL)
      != WYRELOG_E_POLICY)
    return 393;
#undef WYL_TEST_FACT_ROOT
  return 0;
#else
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = g_dir_make_tmp ("wyl-facts-XXXXXX", &error);
  if (root == NULL)
    return 400;

  g_autoptr (wyl_policy_store_t) store = NULL;
  gboolean created = FALSE;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 401;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 402;
  if (wyl_policy_store_create_tenant (store, "tenant-a", &created)
      != WYRELOG_E_OK || !created)
    return 403;
  if (wyl_policy_store_create_tenant (store, "tenant-b", &created)
      != WYRELOG_E_OK || !created)
    return 404;

  const wyl_policy_fact_graph_column_t columns[] = {
    {"subject", "symbol"},
    {"object", "symbol"},
  };
  const wyl_policy_fact_graph_relation_t relations[] = {
    {"site.edge", columns, G_N_ELEMENTS (columns)},
  };
  const wyl_policy_fact_graph_query_t queries[] = {
    {"site.edge.visible", "site.edge", "wr.fact.read", 1000},
  };

  g_autofree gchar *tenant_a_uri = NULL;
  wyl_policy_fact_graph_create_options_t opts =
      make_fact_graph_options ("tenant-a", "graph-main", root, relations,
      G_N_ELEMENTS (relations), queries, G_N_ELEMENTS (queries));
  if (wyl_policy_store_create_fact_graph (store, &opts, &tenant_a_uri)
      != WYRELOG_E_OK)
    return 405;
  if (tenant_a_uri == NULL || !g_str_has_prefix (tenant_a_uri, "file://"))
    return 406;

  opts = make_fact_graph_options ("tenant-b", "graph-main", root, relations,
      G_N_ELEMENTS (relations), queries, G_N_ELEMENTS (queries));
  if (wyl_policy_store_create_fact_graph (store, &opts, NULL)
      != WYRELOG_E_OK)
    return 407;

  gint matches = 0;
  if (count_rows (store, "SELECT COUNT(*) FROM fact_graphs;",
          &matches) != 0 || matches != 2)
    return 408;
  if (count_rows (store, "SELECT COUNT(*) FROM fact_graph_relations;",
          &matches) != 0 || matches != 2)
    return 409;
  if (count_rows (store, "SELECT COUNT(*) FROM fact_graph_relation_columns;",
          &matches) != 0 || matches != 4)
    return 410;
  if (count_rows (store, "SELECT COUNT(*) FROM fact_graph_query_allowlist;",
          &matches) != 0 || matches != 2)
    return 411;

  FactGraphIterProbe probe = { 0 };
  if (wyl_policy_store_foreach_fact_graph (store, NULL,
          fact_graph_iter_probe_cb, &probe) != WYRELOG_E_OK) {
    fact_graph_iter_probe_clear (&probe);
    return 412;
  }
  if (probe.count != 2 || !probe.saw_tenant_a || !probe.saw_tenant_b
      || probe.tenant_a_sealed || g_strcmp0 (probe.tenant_a_uri,
          tenant_a_uri) != 0 || g_strcmp0 (probe.tenant_a_path,
          probe.tenant_b_path) == 0) {
    fact_graph_iter_probe_clear (&probe);
    return 413;
  }

  fact_graph_iter_probe_clear (&probe);
  cleanup_fact_graph_root (root);
  return 0;
#endif
}

static gint
check_store_seals_fact_graph_registry (void)
{
#ifdef G_OS_WIN32
  return 0;
#else
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = g_dir_make_tmp ("wyl-facts-seal-XXXXXX", &error);
  if (root == NULL)
    return 420;

  g_autoptr (wyl_policy_store_t) store = NULL;
  gboolean created = FALSE;
  gboolean active = FALSE;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 421;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 422;
  if (wyl_policy_store_create_tenant (store, "tenant-a", &created)
      != WYRELOG_E_OK || !created)
    return 423;

  const wyl_policy_fact_graph_column_t columns[] = {
    {"subject", "symbol"},
  };
  const wyl_policy_fact_graph_relation_t relations[] = {
    {"site.node", columns, G_N_ELEMENTS (columns)},
  };
  wyl_policy_fact_graph_create_options_t opts =
      make_fact_graph_options ("tenant-a", "graph-sealed", root, relations,
      G_N_ELEMENTS (relations), NULL, 0);
  if (wyl_policy_store_create_fact_graph (store, &opts, NULL)
      != WYRELOG_E_OK)
    return 424;
  if (wyl_policy_store_fact_graph_is_active (store, "tenant-a",
          "graph-sealed", &active) != WYRELOG_E_OK || !active)
    return 425;
  if (wyl_policy_store_seal_fact_graph (store, "tenant-a", "graph-sealed")
      != WYRELOG_E_OK)
    return 426;
  if (wyl_policy_store_fact_graph_is_active (store, "tenant-a",
          "graph-sealed", &active) != WYRELOG_E_OK || active)
    return 427;
  if (wyl_policy_store_create_fact_graph (store, &opts, NULL)
      != WYRELOG_E_POLICY)
    return 428;
  if (wyl_policy_store_seal_fact_graph (store, "tenant-a", "graph-sealed")
      != WYRELOG_E_OK)
    return 429;

  if (wyl_policy_store_set_tenant_sealed (store, "tenant-a", TRUE)
      != WYRELOG_E_OK)
    return 430;
  opts = make_fact_graph_options ("tenant-a", "graph-main", root, relations,
      G_N_ELEMENTS (relations), NULL, 0);
  if (wyl_policy_store_create_fact_graph (store, &opts, NULL)
      != WYRELOG_E_POLICY)
    return 431;

  cleanup_fact_graph_root (root);
  return 0;
#endif
}

static gint
check_store_rejects_fact_graph_registry_escapes (void)
{
#ifdef G_OS_WIN32
  return 0;
#else
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = g_dir_make_tmp ("wyl-facts-esc-XXXXXX", &error);
  g_autofree gchar *outside = g_dir_make_tmp ("wyl-facts-out-XXXXXX",
      &error);
  if (root == NULL || outside == NULL)
    return 440;

  g_autoptr (wyl_policy_store_t) store = NULL;
  gboolean created = FALSE;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 441;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 442;
  if (wyl_policy_store_create_tenant (store, "tenant-a", &created)
      != WYRELOG_E_OK || !created)
    return 443;

  const wyl_policy_fact_graph_column_t columns[] = {
    {"subject", "symbol"},
  };
  const wyl_policy_fact_graph_relation_t relations[] = {
    {"site.node", columns, G_N_ELEMENTS (columns)},
  };
  wyl_policy_fact_graph_create_options_t opts =
      make_fact_graph_options ("tenant-a", "../escape", root, relations,
      G_N_ELEMENTS (relations), NULL, 0);
  if (wyl_policy_store_create_fact_graph (store, &opts, NULL)
      != WYRELOG_E_INVALID)
    return 444;
  opts = make_fact_graph_options ("tenant-a", "bad/name", root, relations,
      G_N_ELEMENTS (relations), NULL, 0);
  if (wyl_policy_store_create_fact_graph (store, &opts, NULL)
      != WYRELOG_E_INVALID)
    return 445;

  g_autofree gchar *tenant_link = g_build_filename (root, "tenant-a", NULL);
  if (symlink (outside, tenant_link) != 0)
    return 446;
  opts = make_fact_graph_options ("tenant-a", "graph-main", root, relations,
      G_N_ELEMENTS (relations), NULL, 0);
  if (wyl_policy_store_create_fact_graph (store, &opts, NULL)
      != WYRELOG_E_POLICY)
    return 447;

  (void) g_remove (tenant_link);
  (void) g_rmdir (root);
  (void) g_rmdir (outside);
  return 0;
#endif
}

static gint
check_store_rejects_fact_graph_reserved_metadata (void)
{
#ifdef G_OS_WIN32
  return 0;
#else
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = g_dir_make_tmp ("wyl-facts-rsv-XXXXXX", &error);
  if (root == NULL)
    return 460;

  g_autoptr (wyl_policy_store_t) store = NULL;
  gboolean created = FALSE;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 461;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 462;
  if (wyl_policy_store_create_tenant (store, "tenant-a", &created)
      != WYRELOG_E_OK || !created)
    return 463;

  const wyl_policy_fact_graph_column_t columns[] = {
    {"subject", "symbol"},
  };
  const wyl_policy_fact_graph_relation_t reserved_relations[] = {
    {"wr.bad", columns, G_N_ELEMENTS (columns)},
  };
  wyl_policy_fact_graph_create_options_t opts =
      make_fact_graph_options ("tenant-a", "graph-main", root,
      reserved_relations, G_N_ELEMENTS (reserved_relations), NULL, 0);
  if (wyl_policy_store_create_fact_graph (store, &opts, NULL)
      != WYRELOG_E_POLICY)
    return 464;

  const wyl_policy_fact_graph_relation_t relations[] = {
    {"site.node", columns, G_N_ELEMENTS (columns)},
  };
  const wyl_policy_fact_graph_query_t queries[] = {
    {"site.node.query", "site.node", "wr.fact.missing", 100},
  };
  opts = make_fact_graph_options ("tenant-a", "graph-main", root, relations,
      G_N_ELEMENTS (relations), queries, G_N_ELEMENTS (queries));
  if (wyl_policy_store_create_fact_graph (store, &opts, NULL)
      != WYRELOG_E_POLICY)
    return 465;

  const wyl_policy_fact_graph_query_t reserved_queries[] = {
    {"wr.node.query", "site.node", "wr.fact.read", 100},
  };
  opts = make_fact_graph_options ("tenant-a", "graph-main", root, relations,
      G_N_ELEMENTS (relations), reserved_queries,
      G_N_ELEMENTS (reserved_queries));
  if (wyl_policy_store_create_fact_graph (store, &opts, NULL)
      != WYRELOG_E_POLICY)
    return 469;

  const wyl_policy_fact_graph_column_t reserved_columns[] = {
    {"wr.subject", "symbol"},
  };
  const wyl_policy_fact_graph_relation_t column_relations[] = {
    {"site.bad_columns", reserved_columns, G_N_ELEMENTS (reserved_columns)},
  };
  opts = make_fact_graph_options ("tenant-a", "graph-main", root,
      column_relations, G_N_ELEMENTS (column_relations), NULL, 0);
  if (wyl_policy_store_create_fact_graph (store, &opts, NULL)
      != WYRELOG_E_POLICY)
    return 466;

  opts = make_fact_graph_options ("tenant-a", "wr.graph", root, relations,
      G_N_ELEMENTS (relations), NULL, 0);
  if (wyl_policy_store_create_fact_graph (store, &opts, NULL)
      != WYRELOG_E_INVALID)
    return 467;

  opts = make_fact_graph_options ("tenant-a", "graph-main", root, relations,
      G_N_ELEMENTS (relations), NULL, 0);
  opts.owner_scope = "tenant-b";
  if (wyl_policy_store_create_fact_graph (store, &opts, NULL)
      != WYRELOG_E_INVALID)
    return 468;

  cleanup_fact_graph_root (root);
  return 0;
#endif
}

static gint
check_store_fact_graph_metadata_only (void)
{
#ifdef G_OS_WIN32
  return 0;
#else
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = g_dir_make_tmp ("wyl-facts-meta-XXXXXX", &error);
  if (root == NULL)
    return 480;

  g_autoptr (wyl_policy_store_t) store = NULL;
  gboolean created = FALSE;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 481;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 482;
  if (wyl_policy_store_create_tenant (store, "tenant-a", &created)
      != WYRELOG_E_OK || !created)
    return 483;

  const wyl_policy_fact_graph_column_t columns[] = {
    {"subject", "symbol"},
    {"details_ref", "compound_ref"},
  };
  const wyl_policy_fact_graph_relation_t relations[] = {
    {"site.node", columns, G_N_ELEMENTS (columns)},
  };
  wyl_policy_fact_graph_create_options_t opts =
      make_fact_graph_options ("tenant-a", "graph-main", root, relations,
      G_N_ELEMENTS (relations), NULL, 0);
  if (wyl_policy_store_create_fact_graph (store, &opts, NULL)
      != WYRELOG_E_OK)
    return 484;

  gint matches = 0;
  if (count_rows (store,
          "SELECT COUNT(*) FROM sqlite_master "
          "WHERE type = 'table' AND ("
          "name LIKE '%fact_row%' OR name LIKE '%tuple%' OR "
          "name LIKE '%payload%' OR name LIKE '%edb%');", &matches) != 0)
    return 485;
  if (matches != 0)
    return 486;
  if (count_rows (store,
          "SELECT COUNT(*) FROM pragma_table_info('fact_graphs') "
          "WHERE name IN ('payload', 'tuple', 'row_value', 'fact_value', "
          "'compound_payload');", &matches) != 0)
    return 487;
  if (matches != 0)
    return 488;

  cleanup_fact_graph_root (root);
  return 0;
#endif
}

static gint
check_permission_seed (wyl_policy_store_t *store, const gchar *perm_id,
    const gchar *klass, gint error_base)
{
  g_autofree gchar *sql = g_strdup_printf ("SELECT COUNT(*) FROM permissions "
      "WHERE perm_id = '%s' AND class = '%s';",
      perm_id, klass);
  gint matches = 0;
  if (count_rows (store, sql, &matches) != 0)
    return error_base;
  return matches == 1 ? 0 : error_base + 1;
}

static gint
check_role_permission_seed (wyl_policy_store_t *store, const gchar *role_id,
    const gchar *perm_id, gboolean expected, gint error_base)
{
  g_autofree gchar *sql =
      g_strdup_printf ("SELECT COUNT(*) FROM role_permissions "
      "WHERE role_id = '%s' AND perm_id = '%s';",
      role_id, perm_id);
  gint matches = 0;
  if (count_rows (store, sql, &matches) != 0)
    return error_base;
  return (matches == (expected ? 1 : 0)) ? 0 : error_base + 1;
}

static gint
check_store_seeds_builtin_catalog (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 200;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 201;

  gboolean exists = FALSE;
  if (wyl_policy_store_role_exists (store, "wr.auditor", &exists)
      != WYRELOG_E_OK)
    return 202;
  if (!exists)
    return 203;
  if (wyl_policy_store_permission_exists (store, "wr.audit.read", &exists)
      != WYRELOG_E_OK)
    return 204;
  if (!exists)
    return 205;

  gint matches = 0;
  if (count_rows (store, "SELECT COUNT(*) FROM roles "
          "WHERE role_id = 'wr.auditor';", &matches) != 0)
    return 206;
  if (matches != 1)
    return 207;

  if (count_rows (store, "SELECT COUNT(*) FROM permissions "
          "WHERE perm_id = 'wr.audit.read';", &matches) != 0)
    return 208;
  if (matches != 1)
    return 209;
  if (count_rows (store, "SELECT COUNT(*) FROM permissions "
          "WHERE perm_id = 'wr.login.skip_mfa' "
          "AND class = 'critical';", &matches) != 0)
    return 210;
  if (matches != 1)
    return 211;

  struct
  {
    const gchar *perm_id;
    const gchar *klass;
  } permission_seeds[] = {
    {"wr.policy.read", "sensitive"},
    {"wr.policy.write", "critical"},
    {"wr.policy.grant_role", "critical"},
    {"wr.audit.read", "sensitive"},
    {"wr.audit.write", "critical"},
    {"wr.login.skip_mfa", "critical"},
    {"wr.graph.manage", "critical"},
    {"wr.fact.write", "critical"},
    {"wr.fact.read", "sensitive"},
    {"wr.datalog.query", "sensitive"},
    {"wr.schema.manage", "critical"},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (permission_seeds); i++) {
    gint rc = check_permission_seed (store, permission_seeds[i].perm_id,
        permission_seeds[i].klass, (gint) (244 + (i * 2)));
    if (rc != 0)
      return rc;
  }

  struct
  {
    const gchar *role_id;
    const gchar *perm_id;
    gboolean expected;
  } role_permission_seeds[] = {
    {"wr.system_admin", "wr.policy.write", FALSE},
    {"wr.service_admin", "wr.policy.write", FALSE},
    {"wr.auditor", "wr.audit.read", FALSE},
    {"wr.system_agent", "wr.audit.write", FALSE},
    {"wr.system_admin", "wr.login.skip_mfa", FALSE},
    {"wr.service_admin", "wr.login.skip_mfa", FALSE},
    {"wr.auditor", "wr.login.skip_mfa", FALSE},
    {"wr.system_agent", "wr.login.skip_mfa", FALSE},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (role_permission_seeds); i++) {
    gint rc = check_role_permission_seed (store,
        role_permission_seeds[i].role_id, role_permission_seeds[i].perm_id,
        role_permission_seeds[i].expected, (gint) (260 + (i * 2)));
    if (rc != 0)
      return rc;
  }

  if (wyl_policy_store_upsert_role (store, "site.local-admin",
          "local admin") != WYRELOG_E_OK)
    return 212;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 213;
  if (wyl_policy_store_role_exists (store, "site.local-admin", &exists)
      != WYRELOG_E_OK)
    return 214;
  if (!exists)
    return 215;

  if (count_rows (store, "SELECT COUNT(*) FROM roles "
          "WHERE role_id = 'wr.auditor';", &matches) != 0)
    return 216;
  if (matches != 1)
    return 217;

  return 0;
}

static gint
check_store_rejects_builtin_catalog_drift (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 216;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 217;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "UPDATE roles SET role_name = 'changed auditor' "
          "WHERE role_id = 'wr.auditor';", NULL, NULL, NULL) != SQLITE_OK)
    return 218;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_POLICY)
    return 219;

  g_clear_pointer (&store, wyl_policy_store_close);
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 220;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 221;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "UPDATE permissions SET class = 'basic' "
          "WHERE perm_id = 'wr.audit.read';", NULL, NULL, NULL) != SQLITE_OK)
    return 222;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_POLICY)
    return 223;

  g_clear_pointer (&store, wyl_policy_store_close);
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 224;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 225;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "INSERT INTO roles (role_id, role_name, description, created_at, "
          "modified_at) VALUES ('wr.unregistered', 'unregistered', "
          "'raw', unixepoch(), unixepoch());", NULL, NULL, NULL) != SQLITE_OK)
    return 226;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_POLICY)
    return 227;

  g_clear_pointer (&store, wyl_policy_store_close);
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 228;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 229;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "INSERT INTO permissions (perm_id, perm_name, class, created_at) "
          "VALUES ('wr.unregistered.read', 'unregistered read', 'basic', "
          "unixepoch());", NULL, NULL, NULL) != SQLITE_OK)
    return 230;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_POLICY)
    return 231;

  return 0;
}

static gint
check_store_rejects_builtin_catalog_upsert_drift (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 232;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 233;

  if (wyl_policy_store_upsert_role (store, "wr.auditor", "auditor")
      != WYRELOG_E_OK)
    return 234;
  if (wyl_policy_store_upsert_role (store, "wr.auditor", "changed auditor")
      != WYRELOG_E_POLICY)
    return 235;

  if (wyl_policy_store_upsert_permission (store, "wr.audit.read",
          "audit read", "sensitive") != WYRELOG_E_OK)
    return 236;
  if (wyl_policy_store_upsert_permission (store, "wr.audit.read",
          "changed audit read", "sensitive") != WYRELOG_E_POLICY)
    return 237;
  if (wyl_policy_store_upsert_permission (store, "wr.login.skip_mfa",
          "login skip mfa", "critical") != WYRELOG_E_OK)
    return 242;
  if (wyl_policy_store_upsert_permission (store, "wr.login.skip_mfa",
          "login skip mfa", "sensitive") != WYRELOG_E_POLICY)
    return 243;
  if (wyl_policy_store_upsert_permission (store, "wr.audit.read",
          "audit read", "basic") != WYRELOG_E_POLICY)
    return 238;
  if (wyl_policy_store_upsert_role (store, "wr.unregistered",
          "unregistered") != WYRELOG_E_POLICY)
    return 239;
  if (wyl_policy_store_upsert_permission (store, "wr.unregistered.read",
          "unregistered read", "basic") != WYRELOG_E_POLICY)
    return 240;
  if (wyl_policy_store_apply_direct_permission_mutation (store, "subject",
          "wr.unregistered.read", "scope", TRUE) != WYRELOG_E_POLICY)
    return 241;

  return 0;
}

typedef struct
{
  const gchar *subject_id;
  const gchar *perm_id;
  const gchar *scope;
  const gchar *operation;
  guint matches;
} DirectPermissionExpect;

static wyrelog_error_t
direct_permission_expect_cb (const gchar *subject_id, const gchar *perm_id,
    const gchar *scope, gpointer user_data)
{
  DirectPermissionExpect *expect = user_data;

  if (g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (perm_id, expect->perm_id) == 0
      && g_strcmp0 (scope, expect->scope) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
direct_permission_event_expect_cb (const gchar *subject_id,
    const gchar *perm_id, const gchar *scope, const gchar *operation,
    gpointer user_data)
{
  DirectPermissionExpect *expect = user_data;

  if (g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (perm_id, expect->perm_id) == 0
      && g_strcmp0 (scope, expect->scope) == 0
      && g_strcmp0 (operation, expect->operation) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

typedef struct
{
  const gchar *subject_id;
  const gchar *perm_id;
  const gchar *scope;
  const gchar *state;
  guint matches;
} PermissionStateExpect;

typedef struct
{
  gint64 event_id;
  const gchar *subject_id;
  const gchar *perm_id;
  const gchar *scope;
  const gchar *event;
  const gchar *from_state;
  const gchar *to_state;
  guint matches;
} PermissionStateEventExpect;

typedef struct
{
  const gchar *subject_id;
  const gchar *state;
  guint matches;
} PrincipalStateExpect;

typedef struct
{
  gint64 event_id;
  const gchar *subject_id;
  const gchar *event;
  const gchar *from_state;
  const gchar *to_state;
  guint matches;
} PrincipalEventExpect;

static wyrelog_error_t
permission_state_expect_cb (const gchar *subject_id, const gchar *perm_id,
    const gchar *scope, const gchar *state, gpointer user_data)
{
  PermissionStateExpect *expect = user_data;

  if (g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (perm_id, expect->perm_id) == 0
      && g_strcmp0 (scope, expect->scope) == 0
      && g_strcmp0 (state, expect->state) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
permission_state_event_expect_cb (gint64 event_id, const gchar *subject_id,
    const gchar *perm_id, const gchar *scope, const gchar *event,
    const gchar *from_state, const gchar *to_state, gpointer user_data)
{
  PermissionStateEventExpect *expect = user_data;

  if ((expect->event_id <= 0 || event_id == expect->event_id)
      && g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (perm_id, expect->perm_id) == 0
      && g_strcmp0 (scope, expect->scope) == 0
      && g_strcmp0 (event, expect->event) == 0
      && g_strcmp0 (from_state, expect->from_state) == 0
      && g_strcmp0 (to_state, expect->to_state) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
principal_state_expect_cb (const gchar *subject_id, const gchar *state,
    gpointer user_data)
{
  PrincipalStateExpect *expect = user_data;

  if (g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (state, expect->state) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
principal_event_expect_cb (gint64 event_id, const gchar *subject_id,
    const gchar *event, const gchar *from_state, const gchar *to_state,
    gpointer user_data)
{
  PrincipalEventExpect *expect = user_data;

  if ((expect->event_id <= 0 || event_id == expect->event_id)
      && g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (event, expect->event) == 0
      && g_strcmp0 (from_state, expect->from_state) == 0
      && g_strcmp0 (to_state, expect->to_state) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

typedef struct
{
  const gchar *session_id;
  const gchar *state;
  guint matches;
} SessionStateExpect;

typedef struct
{
  gint64 event_id;
  const gchar *session_id;
  const gchar *event;
  const gchar *from_state;
  const gchar *to_state;
  guint matches;
} SessionEventExpect;

static wyrelog_error_t
session_state_expect_cb (const gchar *session_id, const gchar *state,
    gpointer user_data)
{
  SessionStateExpect *expect = user_data;

  if (g_strcmp0 (session_id, expect->session_id) == 0
      && g_strcmp0 (state, expect->state) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
session_event_expect_cb (gint64 event_id, const gchar *session_id,
    const gchar *event, const gchar *from_state, const gchar *to_state,
    gpointer user_data)
{
  SessionEventExpect *expect = user_data;

  if ((expect->event_id <= 0 || event_id == expect->event_id)
      && g_strcmp0 (session_id, expect->session_id) == 0
      && g_strcmp0 (event, expect->event) == 0
      && g_strcmp0 (from_state, expect->from_state) == 0
      && g_strcmp0 (to_state, expect->to_state) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

typedef struct
{
  const gchar *role_id;
  const gchar *perm_id;
  guint matches;
} RolePermissionExpect;

typedef struct
{
  const gchar *child_role_id;
  const gchar *parent_role_id;
  guint matches;
} RoleInheritanceExpect;

typedef struct
{
  const gchar *subject_id;
  const gchar *role_id;
  const gchar *scope;
  guint matches;
} RoleMembershipExpect;

typedef struct
{
  const gchar *subject_id;
  const gchar *role_id;
  const gchar *scope;
  const gchar *operation;
  guint matches;
} RoleMembershipEventExpect;

typedef struct
{
  const gchar *id;
  gint64 created_at_us;
  const gchar *subject_id;
  const gchar *action;
  const gchar *resource_id;
  const gchar *deny_reason;
  const gchar *deny_origin;
  const gchar *request_id;
  wyl_decision_t decision;
  guint matches;
} AuditEventExpect;

typedef struct
{
  const gchar *id;
  gint64 created_at_us;
  const gchar *subject_id;
  const gchar *action;
  const gchar *resource_id;
  const gchar *deny_reason;
  const gchar *deny_origin;
  const gchar *request_id;
  wyl_decision_t decision;
  const gchar *state;
  gint64 attempt_count;
  const gchar *last_error;
  guint matches;
} AuditIntentionExpect;

static wyrelog_error_t
role_permission_expect_cb (const gchar *role_id, const gchar *perm_id,
    gpointer user_data)
{
  RolePermissionExpect *expect = user_data;

  if (g_strcmp0 (role_id, expect->role_id) == 0
      && g_strcmp0 (perm_id, expect->perm_id) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
role_inheritance_expect_cb (const gchar *child_role_id,
    const gchar *parent_role_id, gpointer user_data)
{
  RoleInheritanceExpect *expect = user_data;

  if (g_strcmp0 (child_role_id, expect->child_role_id) == 0
      && g_strcmp0 (parent_role_id, expect->parent_role_id) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
role_membership_expect_cb (const gchar *subject_id, const gchar *role_id,
    const gchar *scope, gpointer user_data)
{
  RoleMembershipExpect *expect = user_data;

  if (g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (role_id, expect->role_id) == 0
      && g_strcmp0 (scope, expect->scope) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
role_membership_event_expect_cb (const gchar *subject_id,
    const gchar *role_id, const gchar *scope, const gchar *operation,
    gpointer user_data)
{
  RoleMembershipEventExpect *expect = user_data;

  if (g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (role_id, expect->role_id) == 0
      && g_strcmp0 (scope, expect->scope) == 0
      && g_strcmp0 (operation, expect->operation) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
audit_event_expect_cb (const gchar *id, gint64 created_at_us,
    const gchar *subject_id, const gchar *action, const gchar *resource_id,
    const gchar *deny_reason, const gchar *deny_origin, const gchar *request_id,
    wyl_decision_t decision, gpointer user_data)
{
  AuditEventExpect *expect = user_data;

  if (g_strcmp0 (id, expect->id) == 0
      && created_at_us == expect->created_at_us
      && g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (action, expect->action) == 0
      && g_strcmp0 (resource_id, expect->resource_id) == 0
      && g_strcmp0 (deny_reason, expect->deny_reason) == 0
      && g_strcmp0 (deny_origin, expect->deny_origin) == 0
      && g_strcmp0 (request_id, expect->request_id) == 0
      && decision == expect->decision)
    expect->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
audit_intention_expect_cb (const gchar *id, gint64 created_at_us,
    const gchar *subject_id, const gchar *action, const gchar *resource_id,
    const gchar *deny_reason, const gchar *deny_origin, const gchar *request_id,
    wyl_decision_t decision, const gchar *state, gint64 attempt_count,
    const gchar *last_error, gpointer user_data)
{
  AuditIntentionExpect *expect = user_data;

  if (g_strcmp0 (id, expect->id) == 0
      && created_at_us == expect->created_at_us
      && g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (action, expect->action) == 0
      && g_strcmp0 (resource_id, expect->resource_id) == 0
      && g_strcmp0 (deny_reason, expect->deny_reason) == 0
      && g_strcmp0 (deny_origin, expect->deny_origin) == 0
      && g_strcmp0 (request_id, expect->request_id) == 0
      && decision == expect->decision
      && g_strcmp0 (state, expect->state) == 0
      && attempt_count == expect->attempt_count
      && g_strcmp0 (last_error, expect->last_error) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static gint
check_store_grants_role_permission (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 40;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 41;
  if (wyl_policy_store_upsert_role (store, "site.test-role", "test role")
      != WYRELOG_E_OK)
    return 42;
  if (wyl_policy_store_upsert_permission (store, "site.test.read", "test read",
          "basic") != WYRELOG_E_OK)
    return 43;
  if (wyl_policy_store_grant_role_permission (store, "site.test-role",
          "site.test.read") != WYRELOG_E_OK)
    return 44;
  if (wyl_policy_store_grant_role_permission (store, "site.test-role",
          "site.test.read") != WYRELOG_E_OK)
    return 45;

  RolePermissionExpect expect = {
    .role_id = "site.test-role",
    .perm_id = "site.test.read",
  };
  if (wyl_policy_store_foreach_role_permission (store,
          role_permission_expect_cb, &expect) != WYRELOG_E_OK)
    return 46;
  if (expect.matches != 1)
    return 47;
  return 0;
}

static gint
check_store_catalog_existence_probes (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 218;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 219;

  gboolean exists = TRUE;
  if (wyl_policy_store_role_exists (store, "wr.missing-role", &exists)
      != WYRELOG_E_OK)
    return 220;
  if (exists)
    return 221;
  if (wyl_policy_store_permission_exists (store, "wr.missing-perm", &exists)
      != WYRELOG_E_OK)
    return 222;
  if (exists)
    return 223;

  if (wyl_policy_store_upsert_role (store, "site.exists-role",
          "exists role") != WYRELOG_E_OK)
    return 224;
  if (wyl_policy_store_upsert_permission (store, "site.exists-perm",
          "exists perm", "basic") != WYRELOG_E_OK)
    return 225;

  if (wyl_policy_store_role_exists (store, "site.exists-role", &exists)
      != WYRELOG_E_OK)
    return 226;
  if (!exists)
    return 227;
  if (wyl_policy_store_permission_exists (store, "site.exists-perm", &exists)
      != WYRELOG_E_OK)
    return 228;
  if (!exists)
    return 229;

  if (wyl_policy_store_role_exists (NULL, "site.exists-role", &exists)
      != WYRELOG_E_INVALID)
    return 230;
  if (wyl_policy_store_permission_exists (store, NULL, &exists)
      != WYRELOG_E_INVALID)
    return 231;
  if (wyl_policy_store_permission_exists (store, "site.exists-perm", NULL)
      != WYRELOG_E_INVALID)
    return 232;
  return 0;
}

static gint
check_store_grants_role_inheritance (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 48;
  {
    wyrelog_error_t _dbg_rc = wyl_policy_store_create_schema (store);
    if (_dbg_rc != WYRELOG_E_OK) {
      g_printerr ("DEBUG inheritance create_schema rc=%d\n", (int) _dbg_rc);
      return 49;
    }
  }
  if (wyl_policy_store_upsert_role (store, "site.child-role", "child role")
      != WYRELOG_E_OK)
    return 58;
  if (wyl_policy_store_upsert_role (store, "site.parent-role", "parent role")
      != WYRELOG_E_OK)
    return 59;
  if (wyl_policy_store_grant_role_inheritance (store, "site.child-role",
          "site.parent-role") != WYRELOG_E_OK)
    return 60;
  if (wyl_policy_store_grant_role_inheritance (store, "site.child-role",
          "site.parent-role") != WYRELOG_E_OK)
    return 61;
  if (wyl_policy_store_upsert_permission (store, "site.inherited.read",
          "inherited read", "basic") != WYRELOG_E_OK)
    return 62;
  if (wyl_policy_store_grant_role_permission (store, "site.parent-role",
          "site.inherited.read") != WYRELOG_E_OK)
    return 63;

  RoleInheritanceExpect expect = {
    .child_role_id = "site.child-role",
    .parent_role_id = "site.parent-role",
  };
  if (wyl_policy_store_foreach_role_inheritance (store,
          role_inheritance_expect_cb, &expect) != WYRELOG_E_OK)
    return 64;
  if (expect.matches != 1)
    return 65;

  RolePermissionExpect permission_expect = {
    .role_id = "site.child-role",
    .perm_id = "site.inherited.read",
  };
  if (wyl_policy_store_foreach_role_permission (store,
          role_permission_expect_cb, &permission_expect) != WYRELOG_E_OK)
    return 66;
  if (permission_expect.matches != 1)
    return 67;
  return 0;
}

static gint
check_store_grants_role_membership (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 68;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 69;
  if (wyl_policy_store_upsert_role (store, "site.member-role", "member role")
      != WYRELOG_E_OK)
    return 70;
  if (wyl_policy_store_grant_role_membership (store, "member-user",
          "site.member-role", "member-scope") != WYRELOG_E_OK)
    return 71;
  if (wyl_policy_store_append_role_membership_event (store, "member-user",
          "site.member-role", "member-scope", "grant") != WYRELOG_E_OK)
    return 100;
  if (wyl_policy_store_grant_role_membership (store, "member-user",
          "site.member-role", "member-scope") != WYRELOG_E_OK)
    return 72;

  RoleMembershipExpect expect = {
    .subject_id = "member-user",
    .role_id = "site.member-role",
    .scope = "member-scope",
  };
  if (wyl_policy_store_foreach_role_membership (store,
          role_membership_expect_cb, &expect) != WYRELOG_E_OK)
    return 73;
  if (expect.matches != 1)
    return 74;
  gboolean exists = FALSE;
  if (wyl_policy_store_role_membership_exists (store, "member-user",
          "site.member-role", "member-scope", &exists) != WYRELOG_E_OK)
    return 101;
  if (!exists)
    return 102;

  RoleMembershipEventExpect event_expect = {
    .subject_id = "member-user",
    .role_id = "site.member-role",
    .scope = "member-scope",
    .operation = "grant",
  };
  if (wyl_policy_store_foreach_role_membership_event (store,
          role_membership_event_expect_cb, &event_expect) != WYRELOG_E_OK)
    return 103;
  if (event_expect.matches != 1)
    return 104;
  if (wyl_policy_store_revoke_role_membership (store, "member-user",
          "site.member-role", "member-scope") != WYRELOG_E_OK)
    return 105;
  if (wyl_policy_store_append_role_membership_event (store, "member-user",
          "site.member-role", "member-scope", "revoke") != WYRELOG_E_OK)
    return 106;
  exists = TRUE;
  if (wyl_policy_store_role_membership_exists (store, "member-user",
          "site.member-role", "member-scope", &exists) != WYRELOG_E_OK)
    return 107;
  if (exists)
    return 108;
  return 0;
}

static gint
check_store_grants_direct_permission (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 60;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 61;
  if (wyl_policy_store_upsert_permission (store, "site.direct.read",
          "direct read", "basic") != WYRELOG_E_OK)
    return 62;
  if (wyl_policy_store_grant_direct_permission (store, "direct-user",
          "site.direct.read", "direct-scope") != WYRELOG_E_OK)
    return 63;
  if (wyl_policy_store_grant_direct_permission (store, "direct-user",
          "site.direct.read", "direct-scope") != WYRELOG_E_OK)
    return 64;

  gboolean exists = FALSE;
  if (wyl_policy_store_direct_permission_exists (store, "direct-user",
          "site.direct.read", "direct-scope", &exists) != WYRELOG_E_OK)
    return 65;
  if (!exists)
    return 66;
  DirectPermissionExpect expect = {
    .subject_id = "direct-user",
    .perm_id = "site.direct.read",
    .scope = "direct-scope",
  };
  if (wyl_policy_store_foreach_direct_permission (store,
          direct_permission_expect_cb, &expect) != WYRELOG_E_OK)
    return 78;
  if (expect.matches != 1)
    return 79;
  if (wyl_policy_store_revoke_direct_permission (store, "direct-user",
          "site.direct.read", "direct-scope") != WYRELOG_E_OK)
    return 67;
  if (wyl_policy_store_direct_permission_exists (store, "direct-user",
          "site.direct.read", "direct-scope", &exists) != WYRELOG_E_OK)
    return 68;
  if (exists)
    return 69;
  return 0;
}

static gint
check_store_checks_effective_subject_permission (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 233;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 234;
  if (wyl_policy_store_upsert_permission (store, "site.effective.read",
          "effective read", "basic") != WYRELOG_E_OK)
    return 235;
  if (wyl_policy_store_grant_direct_permission (store, "direct-effective-user",
          "site.effective.read", "effective-scope") != WYRELOG_E_OK)
    return 236;

  gboolean has_permission = FALSE;
  if (wyl_policy_store_subject_has_permission (store, "direct-effective-user",
          "site.effective.read", "effective-scope", &has_permission)
      != WYRELOG_E_OK)
    return 237;
  if (!has_permission)
    return 238;

  if (wyl_policy_store_upsert_role (store, "site.effective-role",
          "effective role") != WYRELOG_E_OK)
    return 239;
  if (wyl_policy_store_grant_role_permission (store, "site.effective-role",
          "site.effective.read") != WYRELOG_E_OK)
    return 240;
  if (wyl_policy_store_grant_role_membership (store, "role-effective-user",
          "site.effective-role", "effective-scope") != WYRELOG_E_OK)
    return 241;

  has_permission = FALSE;
  if (wyl_policy_store_subject_has_permission (store, "role-effective-user",
          "site.effective.read", "effective-scope", &has_permission)
      != WYRELOG_E_OK)
    return 242;
  if (!has_permission)
    return 243;

  has_permission = TRUE;
  if (wyl_policy_store_subject_has_permission (store, "role-effective-user",
          "site.effective.read", "other-scope", &has_permission)
      != WYRELOG_E_OK)
    return 244;
  if (has_permission)
    return 245;
  if (wyl_policy_store_subject_has_permission (store, "role-effective-user",
          "site.effective.read", "effective-scope", NULL)
      != WYRELOG_E_INVALID)
    return 246;
  return 0;
}

static gint
check_role_membership_mutation_rolls_back_on_event_failure (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 197;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 198;
  if (wyl_policy_store_upsert_role (store, "site.rollback-role",
          "rollback role") != WYRELOG_E_OK)
    return 199;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "CREATE TRIGGER fail_role_membership_event "
          "BEFORE INSERT ON role_membership_events "
          "BEGIN SELECT RAISE(ABORT, 'fail event'); END;",
          NULL, NULL, NULL) != SQLITE_OK)
    return 200;

  if (wyl_policy_store_apply_role_membership_mutation (store,
          "rollback-role-user", "site.rollback-role", "rollback-role-scope",
          TRUE) != WYRELOG_E_IO)
    return 201;

  gboolean exists = TRUE;
  if (wyl_policy_store_role_membership_exists (store, "rollback-role-user",
          "site.rollback-role", "rollback-role-scope", &exists)
      != WYRELOG_E_OK)
    return 202;
  if (exists)
    return 203;

  RoleMembershipEventExpect expect = {
    .subject_id = "rollback-role-user",
    .role_id = "site.rollback-role",
    .scope = "rollback-role-scope",
    .operation = "grant",
  };
  if (wyl_policy_store_foreach_role_membership_event (store,
          role_membership_event_expect_cb, &expect) != WYRELOG_E_OK)
    return 204;
  if (expect.matches != 0)
    return 205;
  return 0;
}

static gint
check_role_membership_revoke_rolls_back_on_event_failure (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 206;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 207;
  if (wyl_policy_store_upsert_role (store, "site.rollback-role-revoke",
          "rollback role revoke") != WYRELOG_E_OK)
    return 208;
  if (wyl_policy_store_grant_role_membership (store,
          "rollback-role-revoke-user", "site.rollback-role-revoke",
          "rollback-role-revoke-scope") != WYRELOG_E_OK)
    return 209;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "CREATE TRIGGER fail_role_membership_revoke_event "
          "BEFORE INSERT ON role_membership_events "
          "BEGIN SELECT RAISE(ABORT, 'fail event'); END;",
          NULL, NULL, NULL) != SQLITE_OK)
    return 210;

  if (wyl_policy_store_apply_role_membership_mutation (store,
          "rollback-role-revoke-user", "site.rollback-role-revoke",
          "rollback-role-revoke-scope", FALSE) != WYRELOG_E_IO)
    return 211;

  gboolean exists = FALSE;
  if (wyl_policy_store_role_membership_exists (store,
          "rollback-role-revoke-user", "site.rollback-role-revoke",
          "rollback-role-revoke-scope", &exists) != WYRELOG_E_OK)
    return 212;
  if (!exists)
    return 213;
  return 0;
}

static gint
check_store_appends_direct_permission_event (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 92;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 93;
  if (wyl_policy_store_append_direct_permission_event (store, "direct-user",
          "site.direct.read", "direct-scope", "grant") != WYRELOG_E_OK)
    return 94;

  DirectPermissionExpect expect = {
    .subject_id = "direct-user",
    .perm_id = "site.direct.read",
    .scope = "direct-scope",
    .operation = "grant",
  };
  if (wyl_policy_store_foreach_direct_permission_event (store,
          direct_permission_event_expect_cb, &expect) != WYRELOG_E_OK)
    return 95;
  if (expect.matches != 1)
    return 96;
  return 0;
}

static gint
check_direct_permission_mutation_rolls_back_on_event_failure (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 180;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 181;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "CREATE TRIGGER fail_direct_permission_event "
          "BEFORE INSERT ON direct_permission_events "
          "BEGIN SELECT RAISE(ABORT, 'fail event'); END;",
          NULL, NULL, NULL) != SQLITE_OK)
    return 182;

  if (wyl_policy_store_apply_direct_permission_mutation (store,
          "rollback-user", "site.rollback-direct", "rollback-scope", TRUE)
      != WYRELOG_E_IO)
    return 183;

  gboolean exists = TRUE;
  if (wyl_policy_store_direct_permission_exists (store, "rollback-user",
          "site.rollback-direct", "rollback-scope", &exists) != WYRELOG_E_OK)
    return 184;
  if (exists)
    return 185;

  DirectPermissionExpect expect = {
    .subject_id = "rollback-user",
    .perm_id = "site.rollback-direct",
    .scope = "rollback-scope",
    .operation = "grant",
  };
  if (wyl_policy_store_foreach_direct_permission_event (store,
          direct_permission_event_expect_cb, &expect) != WYRELOG_E_OK)
    return 186;
  if (expect.matches != 0)
    return 187;

  gboolean permission_exists = FALSE;
  if (wyl_policy_store_table_exists (store, "permissions", &permission_exists)
      != WYRELOG_E_OK || !permission_exists)
    return 188;
  sqlite3_stmt *stmt = NULL;
  if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store),
          "SELECT 1 FROM permissions WHERE perm_id = ?;", -1, &stmt,
          NULL) != SQLITE_OK)
    return 214;
  if (sqlite3_bind_text (stmt, 1, "site.rollback-direct", -1,
          SQLITE_TRANSIENT) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return 215;
  }
  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  if (step_rc == SQLITE_ROW)
    return 216;
  if (step_rc != SQLITE_DONE)
    return 217;
  return 0;
}

static gint
check_direct_permission_revoke_rolls_back_on_event_failure (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 189;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 190;
  if (wyl_policy_store_upsert_permission (store, "site.rollback-revoke",
          "rollback revoke", "basic") != WYRELOG_E_OK)
    return 191;
  if (wyl_policy_store_grant_direct_permission (store, "rollback-revoke-user",
          "site.rollback-revoke", "rollback-revoke-scope") != WYRELOG_E_OK)
    return 192;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "CREATE TRIGGER fail_direct_permission_revoke_event "
          "BEFORE INSERT ON direct_permission_events "
          "BEGIN SELECT RAISE(ABORT, 'fail event'); END;",
          NULL, NULL, NULL) != SQLITE_OK)
    return 193;

  if (wyl_policy_store_apply_direct_permission_mutation (store,
          "rollback-revoke-user", "site.rollback-revoke",
          "rollback-revoke-scope", FALSE) != WYRELOG_E_IO)
    return 194;

  gboolean exists = FALSE;
  if (wyl_policy_store_direct_permission_exists (store,
          "rollback-revoke-user", "site.rollback-revoke",
          "rollback-revoke-scope", &exists) != WYRELOG_E_OK)
    return 195;
  if (!exists)
    return 196;
  return 0;
}

static gint
check_store_sets_permission_state (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 218;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 219;
  if (wyl_policy_store_set_permission_state (store, "perm-user",
          "wr.perm.read", "perm-scope", "armed") != WYRELOG_E_OK)
    return 220;
  if (wyl_policy_store_set_permission_state (store, "perm-user",
          "wr.perm.read", "perm-scope", "dormant") != WYRELOG_E_OK)
    return 221;

  gboolean exists = FALSE;
  if (wyl_policy_store_permission_state_exists (store, "perm-user",
          "wr.perm.read", "perm-scope", &exists) != WYRELOG_E_OK)
    return 222;
  if (!exists)
    return 223;
  if (wyl_policy_store_permission_state_exists (store, "perm-user",
          "wr.perm.read", "missing-scope", &exists) != WYRELOG_E_OK)
    return 224;
  if (exists)
    return 225;

  PermissionStateExpect expect = {
    .subject_id = "perm-user",
    .perm_id = "wr.perm.read",
    .scope = "perm-scope",
    .state = "dormant",
  };
  if (wyl_policy_store_foreach_permission_state (store,
          permission_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 226;
  if (expect.matches != 1)
    return 227;
  return 0;
}

static gint
check_store_appends_permission_state_event (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 228;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 229;
  gint64 event_id = -1;
  if (wyl_policy_store_append_permission_state_event (store, "perm-event-user",
          "wr.perm.event", "perm-event-scope", "grant", "dormant", "armed",
          &event_id) != WYRELOG_E_OK)
    return 230;

  PermissionStateEventExpect expect = {
    .event_id = event_id,
    .subject_id = "perm-event-user",
    .perm_id = "wr.perm.event",
    .scope = "perm-event-scope",
    .event = "grant",
    .from_state = "dormant",
    .to_state = "armed",
  };
  if (wyl_policy_store_foreach_permission_state_event (store,
          permission_state_event_expect_cb, &expect) != WYRELOG_E_OK)
    return 231;
  if (expect.matches != 1)
    return 232;
  return 0;
}

static gint
check_store_applies_permission_state_transition (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 238;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 239;

  gint64 grant_event_id = -1;
  if (wyl_policy_store_apply_permission_state_transition (store,
          "perm-apply-user", "wr.perm.apply", "perm-apply-scope", "grant",
          &grant_event_id) != WYRELOG_E_OK)
    return 240;
  if (grant_event_id <= 0)
    return 241;

  PermissionStateExpect state_expect = {
    .subject_id = "perm-apply-user",
    .perm_id = "wr.perm.apply",
    .scope = "perm-apply-scope",
    .state = "armed",
  };
  if (wyl_policy_store_foreach_permission_state (store,
          permission_state_expect_cb, &state_expect) != WYRELOG_E_OK)
    return 242;
  if (state_expect.matches != 1)
    return 243;

  PermissionStateEventExpect grant_expect = {
    .event_id = grant_event_id,
    .subject_id = "perm-apply-user",
    .perm_id = "wr.perm.apply",
    .scope = "perm-apply-scope",
    .event = "grant",
    .from_state = "dormant",
    .to_state = "armed",
  };
  if (wyl_policy_store_foreach_permission_state_event (store,
          permission_state_event_expect_cb, &grant_expect) != WYRELOG_E_OK)
    return 244;
  if (grant_expect.matches != 1)
    return 245;

  gint64 revoke_event_id = -1;
  if (wyl_policy_store_apply_permission_state_transition (store,
          "perm-apply-user", "wr.perm.apply", "perm-apply-scope", "revoke",
          &revoke_event_id) != WYRELOG_E_OK)
    return 246;
  if (revoke_event_id <= grant_event_id)
    return 247;

  PermissionStateExpect dormant_expect = {
    .subject_id = "perm-apply-user",
    .perm_id = "wr.perm.apply",
    .scope = "perm-apply-scope",
    .state = "dormant",
  };
  if (wyl_policy_store_foreach_permission_state (store,
          permission_state_expect_cb, &dormant_expect) != WYRELOG_E_OK)
    return 248;
  if (dormant_expect.matches != 1)
    return 249;

  gint64 trigger_event_id = -1;
  if (wyl_policy_store_apply_permission_state_transition (store,
          "perm-trigger-user", "wr.perm.trigger", "perm-trigger-scope",
          "grant", NULL) != WYRELOG_E_OK)
    return 279;
  if (wyl_policy_store_apply_permission_state_transition (store,
          "perm-trigger-user", "wr.perm.trigger", "perm-trigger-scope",
          "trigger", &trigger_event_id) != WYRELOG_E_OK)
    return 280;
  if (trigger_event_id <= revoke_event_id)
    return 281;

  PermissionStateExpect firing_expect = {
    .subject_id = "perm-trigger-user",
    .perm_id = "wr.perm.trigger",
    .scope = "perm-trigger-scope",
    .state = "firing",
  };
  if (wyl_policy_store_foreach_permission_state (store,
          permission_state_expect_cb, &firing_expect) != WYRELOG_E_OK)
    return 282;
  if (firing_expect.matches != 1)
    return 283;

  PermissionStateEventExpect trigger_expect = {
    .event_id = trigger_event_id,
    .subject_id = "perm-trigger-user",
    .perm_id = "wr.perm.trigger",
    .scope = "perm-trigger-scope",
    .event = "trigger",
    .from_state = "armed",
    .to_state = "firing",
  };
  if (wyl_policy_store_foreach_permission_state_event (store,
          permission_state_event_expect_cb, &trigger_expect) != WYRELOG_E_OK)
    return 284;
  if (trigger_expect.matches != 1)
    return 285;
  return 0;
}

static gint
check_store_permission_state_transition_rejects_invalid_edge (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 250;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 251;

  gint64 event_id = 77;
  if (wyl_policy_store_apply_permission_state_transition (store,
          "perm-invalid-user", "wr.perm.invalid", "perm-invalid-scope",
          "revoke", &event_id) != WYRELOG_E_POLICY)
    return 252;
  if (event_id != -1)
    return 253;

  gboolean exists = TRUE;
  if (wyl_policy_store_permission_state_exists (store, "perm-invalid-user",
          "wr.perm.invalid", "perm-invalid-scope", &exists) != WYRELOG_E_OK)
    return 254;
  if (exists)
    return 255;

  PermissionStateEventExpect expect = {
    .event_id = -1,
    .subject_id = "perm-invalid-user",
    .perm_id = "wr.perm.invalid",
    .scope = "perm-invalid-scope",
    .event = "revoke",
    .from_state = "dormant",
    .to_state = "dormant",
  };
  if (wyl_policy_store_foreach_permission_state_event (store,
          permission_state_event_expect_cb, &expect) != WYRELOG_E_OK)
    return 256;
  if (expect.matches != 0)
    return 257;
  return 0;
}

static gint
check_store_permission_state_transition_rolls_back_event_failure (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 258;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 259;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "CREATE TRIGGER fail_permission_state_event "
          "BEFORE INSERT ON permission_state_events "
          "BEGIN SELECT RAISE(ABORT, 'fail event'); END;",
          NULL, NULL, NULL) != SQLITE_OK)
    return 260;

  if (wyl_policy_store_apply_permission_state_transition (store,
          "perm-rollback-user", "wr.perm.rollback", "perm-rollback-scope",
          "grant", NULL) != WYRELOG_E_IO)
    return 261;

  gboolean exists = TRUE;
  if (wyl_policy_store_permission_state_exists (store, "perm-rollback-user",
          "wr.perm.rollback", "perm-rollback-scope", &exists)
      != WYRELOG_E_OK)
    return 262;
  if (exists)
    return 263;
  return 0;
}

static gint
check_store_permission_state_transition_appends_audit (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 264;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 265;

  gint64 event_id = -1;
  if (wyl_policy_store_apply_permission_state_transition_with_audit (store,
          "perm-audit-user", "wr.perm.audit", "perm-audit-scope", "grant",
          &event_id, "01890c10-2e3f-7000-8000-000000000010", 999,
          "perm-audit-user", "permission_state.grant", "wr.perm.audit",
          "allowed", "permission_state", NULL,
          WYL_DECISION_ALLOW) != WYRELOG_E_OK)
    return 266;
  if (event_id <= 0)
    return 267;

  AuditEventExpect audit_expect = {
    .id = "01890c10-2e3f-7000-8000-000000000010",
    .created_at_us = 999,
    .subject_id = "perm-audit-user",
    .action = "permission_state.grant",
    .resource_id = "wr.perm.audit",
    .deny_reason = "allowed",
    .deny_origin = "permission_state",
    .decision = WYL_DECISION_ALLOW,
  };
  if (wyl_policy_store_foreach_audit_event (store, audit_event_expect_cb,
          &audit_expect) != WYRELOG_E_OK)
    return 268;
  if (audit_expect.matches != 1)
    return 269;
  return 0;
}

static gint
check_store_permission_state_transition_rolls_back_audit_failure (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 270;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 271;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "CREATE TRIGGER fail_permission_state_audit "
          "BEFORE INSERT ON audit_events "
          "BEGIN SELECT RAISE(ABORT, 'fail audit'); END;",
          NULL, NULL, NULL) != SQLITE_OK)
    return 272;

  gint64 event_id = 99;
  if (wyl_policy_store_apply_permission_state_transition_with_audit (store,
          "perm-audit-rollback-user", "wr.perm.audit.rollback",
          "perm-audit-rollback-scope", "grant", &event_id,
          "01890c10-2e3f-7000-8000-000000000011", 1000,
          "perm-audit-rollback-user", "permission_state.grant",
          "wr.perm.audit.rollback", "allowed", "permission_state",
          NULL, WYL_DECISION_ALLOW) != WYRELOG_E_IO)
    return 273;
  if (event_id != -1)
    return 274;

  gboolean exists = TRUE;
  if (wyl_policy_store_permission_state_exists (store,
          "perm-audit-rollback-user", "wr.perm.audit.rollback",
          "perm-audit-rollback-scope", &exists) != WYRELOG_E_OK)
    return 275;
  if (exists)
    return 276;

  PermissionStateEventExpect event_expect = {
    .subject_id = "perm-audit-rollback-user",
    .perm_id = "wr.perm.audit.rollback",
    .scope = "perm-audit-rollback-scope",
    .event = "grant",
    .from_state = "dormant",
    .to_state = "armed",
  };
  if (wyl_policy_store_foreach_permission_state_event (store,
          permission_state_event_expect_cb, &event_expect) != WYRELOG_E_OK)
    return 277;
  if (event_expect.matches != 0)
    return 278;
  return 0;
}

static gint
check_store_permission_state_transition_rejects_invalid_audit (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 286;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 287;

  gint64 event_id = 101;
  if (wyl_policy_store_apply_permission_state_transition_with_audit (store,
          "perm-bad-audit-user", "wr.perm.bad.audit",
          "perm-bad-audit-scope", "grant", &event_id, "not-a-wyl-id", 1000,
          "perm-bad-audit-user", "permission_state.grant",
          "wr.perm.bad.audit", "allowed", "permission_state",
          NULL, WYL_DECISION_ALLOW) != WYRELOG_E_INVALID)
    return 288;
  if (event_id != -1)
    return 289;

  gboolean exists = TRUE;
  if (wyl_policy_store_permission_state_exists (store, "perm-bad-audit-user",
          "wr.perm.bad.audit", "perm-bad-audit-scope", &exists)
      != WYRELOG_E_OK)
    return 290;
  if (exists)
    return 291;

  PermissionStateEventExpect event_expect = {
    .subject_id = "perm-bad-audit-user",
    .perm_id = "wr.perm.bad.audit",
    .scope = "perm-bad-audit-scope",
    .event = "grant",
    .from_state = "dormant",
    .to_state = "armed",
  };
  if (wyl_policy_store_foreach_permission_state_event (store,
          permission_state_event_expect_cb, &event_expect) != WYRELOG_E_OK)
    return 292;
  if (event_expect.matches != 0)
    return 293;
  return 0;
}

static gint
check_store_permission_state_transition_rolls_back_audit_conflict (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  static const gchar *id = "01890c10-2e3f-7000-8000-000000000012";

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 294;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 295;
  if (wyl_policy_store_append_audit_event (store, id, 1001,
          "existing-audit-user", "existing.action", "existing-resource",
          NULL, NULL, WYL_DECISION_ALLOW) != WYRELOG_E_OK)
    return 296;

  gint64 event_id = 102;
  if (wyl_policy_store_apply_permission_state_transition_with_audit (store,
          "perm-audit-conflict-user", "wr.perm.audit.conflict",
          "perm-audit-conflict-scope", "grant", &event_id, id, 1001,
          "perm-audit-conflict-user", "permission_state.grant",
          "wr.perm.audit.conflict", "allowed", "permission_state",
          NULL, WYL_DECISION_ALLOW) != WYRELOG_E_POLICY)
    return 297;
  if (event_id != -1)
    return 298;

  gboolean exists = TRUE;
  if (wyl_policy_store_permission_state_exists (store,
          "perm-audit-conflict-user", "wr.perm.audit.conflict",
          "perm-audit-conflict-scope", &exists) != WYRELOG_E_OK)
    return 299;
  if (exists)
    return 300;

  PermissionStateEventExpect event_expect = {
    .subject_id = "perm-audit-conflict-user",
    .perm_id = "wr.perm.audit.conflict",
    .scope = "perm-audit-conflict-scope",
    .event = "grant",
    .from_state = "dormant",
    .to_state = "armed",
  };
  if (wyl_policy_store_foreach_permission_state_event (store,
          permission_state_event_expect_cb, &event_expect) != WYRELOG_E_OK)
    return 301;
  if (event_expect.matches != 0)
    return 302;

  AuditEventExpect audit_expect = {
    .id = id,
    .created_at_us = 1001,
    .subject_id = "existing-audit-user",
    .action = "existing.action",
    .resource_id = "existing-resource",
    .decision = WYL_DECISION_ALLOW,
  };
  if (wyl_policy_store_foreach_audit_event (store, audit_event_expect_cb,
          &audit_expect) != WYRELOG_E_OK)
    return 303;
  if (audit_expect.matches != 1)
    return 304;
  return 0;
}

static gint
check_store_sets_principal_state (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 80;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 81;
  if (wyl_policy_store_set_principal_state (store, "principal-user",
          "mfa_required") != WYRELOG_E_OK)
    return 82;
  if (wyl_policy_store_set_principal_state (store, "principal-user",
          "authenticated") != WYRELOG_E_OK)
    return 83;

  PrincipalStateExpect expect = {
    .subject_id = "principal-user",
    .state = "authenticated",
  };
  if (wyl_policy_store_foreach_principal_state (store,
          principal_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 84;
  if (expect.matches != 1)
    return 85;
  return 0;
}

static gint
check_store_get_principal_state_round_trip (void)
{
  /* Commit-5: forward flag from architect.  The new public accessor
   * wyl_policy_store_get_principal_state replaces the historical
   * foreach-based two-step lookup in daemon/http.c.  This test
   * exercises: (a) the missing-row branch returns out_found=FALSE with
   * *out_state=NULL, (b) the row-present branch round-trips state, and
   * (c) the helper rejects NULL pointers without touching the store. */
  g_autoptr (wyl_policy_store_t) store = NULL;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 1500;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 1501;

  /* Missing row: out_found=FALSE, *out_state=NULL, return OK. */
  g_autofree gchar *missing = (gchar *) 0x1;    /* deliberate sentinel */
  gboolean found = TRUE;
  if (wyl_policy_store_get_principal_state (store, "no-such-subject",
          &missing, &found) != WYRELOG_E_OK)
    return 1502;
  if (found)
    return 1503;
  if (missing != NULL)
    return 1504;

  /* Row present: round-trip a value via the existing set_principal_state. */
  if (wyl_policy_store_set_principal_state (store, "subject-A",
          "mfa_required") != WYRELOG_E_OK)
    return 1505;
  g_autofree gchar *state_a = NULL;
  gboolean found_a = FALSE;
  if (wyl_policy_store_get_principal_state (store, "subject-A", &state_a,
          &found_a) != WYRELOG_E_OK)
    return 1506;
  if (!found_a)
    return 1507;
  if (g_strcmp0 (state_a, "mfa_required") != 0)
    return 1508;

  /* Updated row: re-read picks up the new value. */
  if (wyl_policy_store_set_principal_state (store, "subject-A",
          "authenticated") != WYRELOG_E_OK)
    return 1509;
  g_clear_pointer (&state_a, g_free);
  if (wyl_policy_store_get_principal_state (store, "subject-A", &state_a,
          &found_a) != WYRELOG_E_OK)
    return 1510;
  if (!found_a)
    return 1511;
  if (g_strcmp0 (state_a, "authenticated") != 0)
    return 1512;

  /* NULL-input shape check. */
  if (wyl_policy_store_get_principal_state (NULL, "subject-A", &state_a,
          &found_a) != WYRELOG_E_INVALID)
    return 1513;
  if (wyl_policy_store_get_principal_state (store, NULL, &state_a,
          &found_a) != WYRELOG_E_INVALID)
    return 1514;
  if (wyl_policy_store_get_principal_state (store, "subject-A", NULL,
          &found_a) != WYRELOG_E_INVALID)
    return 1515;
  if (wyl_policy_store_get_principal_state (store, "subject-A", &state_a,
          NULL) != WYRELOG_E_INVALID)
    return 1516;
  return 0;
}

static gint
check_store_apply_principal_failure_increments_counter (void)
{
  /* Commit-5: each call increments the failure counter atomically.
   * Below the |threshold| the row stays in mfa_required; locked_at
   * remains NULL (surfaced as INT64_MIN). */
  g_autoptr (wyl_policy_store_t) store = NULL;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 1520;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 1521;
  if (wyl_policy_store_set_principal_state (store, "lockout.below",
          "mfa_required") != WYRELOG_E_OK)
    return 1522;

  for (gint64 expected = 1; expected <= 4; expected++) {
    g_autofree gchar *st = NULL;
    gint64 count = -1;
    gint64 locked_at = 0;
    if (wyl_policy_store_apply_principal_failure (store, "lockout.below",
            5, 100000, &st, &count, &locked_at) != WYRELOG_E_OK)
      return 1523;
    if (g_strcmp0 (st, "mfa_required") != 0)
      return 1524;
    if (count != expected)
      return 1525;
    if (locked_at != G_MININT64)
      return 1526;
  }
  return 0;
}

static gint
check_store_apply_principal_failure_transitions_to_locked (void)
{
  /* Threshold hit on the 5th call: state moves to locked, locked_at is
   * the |now_secs| passed in, and the counter equals the threshold. */
  g_autoptr (wyl_policy_store_t) store = NULL;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 1530;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 1531;
  if (wyl_policy_store_set_principal_state (store, "lockout.cross",
          "mfa_required") != WYRELOG_E_OK)
    return 1532;

  gint64 final_locked_at = 0;
  for (gint64 i = 1; i <= 5; i++) {
    g_autofree gchar *st = NULL;
    gint64 count = -1;
    gint64 locked_at = 0;
    if (wyl_policy_store_apply_principal_failure (store, "lockout.cross",
            5, 200000 + i, &st, &count, &locked_at) != WYRELOG_E_OK)
      return 1533;
    if (i < 5) {
      if (g_strcmp0 (st, "mfa_required") != 0)
        return 1534;
      if (locked_at != G_MININT64)
        return 1535;
    } else {
      if (g_strcmp0 (st, "locked") != 0)
        return 1536;
      if (count != 5)
        return 1537;
      if (locked_at != 200000 + 5)
        return 1538;
      final_locked_at = locked_at;
    }
  }

  /* Reload the row via the new public accessor: still locked, same
   * counter, same locked_at.  The persistence guarantee is verified by
   * walking the row through a separate read. */
  g_autofree gchar *st = NULL;
  gint64 count = -1;
  gint64 locked_at = -1;
  gboolean found = FALSE;
  if (wyl_policy_store_get_principal_lock_info (store, "lockout.cross", &st,
          &count, &locked_at, &found) != WYRELOG_E_OK)
    return 1539;
  if (!found)
    return 1540;
  if (g_strcmp0 (st, "locked") != 0)
    return 1541;
  if (count != 5)
    return 1542;
  if (locked_at != final_locked_at)
    return 1543;
  return 0;
}

static gint
check_store_apply_principal_failure_survives_reopen (void)
{
  /* Critic-flagged invariant: lockout state durable across daemon
   * restart.  Drive 5 failures, close the store, reopen, assert state
   * is still locked with locked_at preserved.  Uses an encrypted store
   * on disk so the reopen actually touches the same SQLite file. */
  g_autofree gchar *root = g_dir_make_tmp ("wyl-store-lockout-XXXXXX", NULL);
  if (root == NULL)
    return 1550;
  g_autofree gchar *db_path = g_build_filename (root, "policy-store.db", NULL);
  gint rc_inner = 0;

  /* Phase 1: open, populate. */
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    wyl_policy_store_open_options_t opts = {
      .path = db_path,
      .require_encrypted = FALSE,
    };
    if (wyl_policy_store_open_with_options (&opts, &store) != WYRELOG_E_OK) {
      rc_inner = 1551;
      goto cleanup;
    }
    if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK) {
      rc_inner = 1552;
      goto cleanup;
    }
    if (wyl_policy_store_set_principal_state (store, "lockout.persist",
            "mfa_required") != WYRELOG_E_OK) {
      rc_inner = 1553;
      goto cleanup;
    }
    for (gint64 i = 1; i <= 5; i++) {
      g_autofree gchar *st = NULL;
      gint64 count = -1;
      gint64 locked_at = 0;
      if (wyl_policy_store_apply_principal_failure (store, "lockout.persist",
              5, 300000 + i, &st, &count, &locked_at) != WYRELOG_E_OK) {
        rc_inner = 1554;
        goto cleanup;
      }
    }
  }

  /* Phase 2: reopen, assert lockout is still present. */
  {
    g_autoptr (wyl_policy_store_t) store2 = NULL;
    wyl_policy_store_open_options_t opts = {
      .path = db_path,
      .require_encrypted = FALSE,
    };
    if (wyl_policy_store_open_with_options (&opts, &store2) != WYRELOG_E_OK) {
      rc_inner = 1555;
      goto cleanup;
    }
    g_autofree gchar *st = NULL;
    gint64 count = -1;
    gint64 locked_at = 0;
    gboolean found = FALSE;
    if (wyl_policy_store_get_principal_lock_info (store2, "lockout.persist",
            &st, &count, &locked_at, &found) != WYRELOG_E_OK) {
      rc_inner = 1556;
      goto cleanup;
    }
    if (!found || g_strcmp0 (st, "locked") != 0 || count != 5
        || locked_at != 300000 + 5) {
      rc_inner = 1557;
      goto cleanup;
    }
  }

cleanup:
  (void) g_unlink (db_path);
  (void) g_rmdir (root);
  return rc_inner;
}

static gint
check_store_reset_principal_failure_counter (void)
{
  /* On a successful TOTP verify the validator resets the counter and
   * clears locked_at; this helper exercises that primitive directly. */
  g_autoptr (wyl_policy_store_t) store = NULL;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 1560;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 1561;
  if (wyl_policy_store_set_principal_state (store, "lockout.reset",
          "mfa_required") != WYRELOG_E_OK)
    return 1562;

  /* Bump the counter to 4 (below threshold). */
  for (gint64 i = 1; i <= 4; i++) {
    g_autofree gchar *st = NULL;
    gint64 c = 0;
    gint64 l = 0;
    if (wyl_policy_store_apply_principal_failure (store, "lockout.reset",
            5, 400000 + i, &st, &c, &l) != WYRELOG_E_OK)
      return 1563;
  }

  /* Reset; counter must be 0, locked_at NULL (INT64_MIN). */
  if (wyl_policy_store_reset_principal_failure_counter (store,
          "lockout.reset") != WYRELOG_E_OK)
    return 1564;
  g_autofree gchar *st = NULL;
  gint64 count = -1;
  gint64 locked_at = -1;
  gboolean found = FALSE;
  if (wyl_policy_store_get_principal_lock_info (store, "lockout.reset", &st,
          &count, &locked_at, &found) != WYRELOG_E_OK)
    return 1565;
  if (!found || count != 0 || locked_at != G_MININT64)
    return 1566;

  /* A subsequent failure restarts the counter at 1. */
  g_autofree gchar *st2 = NULL;
  gint64 c2 = 0;
  gint64 l2 = 0;
  if (wyl_policy_store_apply_principal_failure (store, "lockout.reset", 5,
          500000, &st2, &c2, &l2) != WYRELOG_E_OK)
    return 1567;
  if (c2 != 1 || g_strcmp0 (st2, "mfa_required") != 0)
    return 1568;
  return 0;
}

static gint
check_store_apply_principal_failure_sequential_race (void)
{
  /* Critic-flagged read-modify-write race: 5 sequential failures must
   * end at counter=5 with the row in LOCKED state, and any further
   * FAILED_ATTEMPT against the LOCKED row must be refused with
   * WYRELOG_E_POLICY without bumping the counter or locked_at (the
   * commit-5 iteration LOW #2 defensive guard).  Concurrent threads
   * are not exercised here because the daemon serialises mutations on
   * the policy store's single sqlite connection via the existing
   * SAVEPOINT primitive (which is composed inside apply_principal_failure).
   * The atomicity guarantee we lock down here is: each call observes
   * the durable counter from the prior call, no "AT MOST one locks"
   * regression where a stale read leaves the row stuck below threshold. */
  g_autoptr (wyl_policy_store_t) store = NULL;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 1580;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 1581;
  if (wyl_policy_store_set_principal_state (store, "lockout.race",
          "mfa_required") != WYRELOG_E_OK)
    return 1582;

  /* Five successful failures, threshold cross on the fifth. */
  for (gint i = 0; i < 5; i++) {
    g_autofree gchar *st = NULL;
    gint64 c = 0;
    gint64 l = 0;
    if (wyl_policy_store_apply_principal_failure (store, "lockout.race",
            5, 700000 + i, &st, &c, &l) != WYRELOG_E_OK)
      return 1583;
  }

  /* Sixth call against the LOCKED row: must return WYRELOG_E_POLICY,
   * counter/locked_at unchanged. */
  {
    g_autofree gchar *st = NULL;
    gint64 c = 0;
    gint64 l = 0;
    if (wyl_policy_store_apply_principal_failure (store, "lockout.race",
            5, 700100, &st, &c, &l) != WYRELOG_E_POLICY)
      return 1589;
  }

  g_autofree gchar *st = NULL;
  gint64 count = -1;
  gint64 locked_at = -1;
  gboolean found = FALSE;
  if (wyl_policy_store_get_principal_lock_info (store, "lockout.race", &st,
          &count, &locked_at, &found) != WYRELOG_E_OK)
    return 1584;
  if (!found)
    return 1585;
  /* Counter is pinned at the threshold value (5) once the row is
   * LOCKED; the sixth call did NOT bump anything. */
  if (count != 5)
    return 1586;
  if (g_strcmp0 (st, "locked") != 0)
    return 1587;
  if (locked_at == G_MININT64)
    return 1588;
  return 0;
}

static gint
check_store_apply_principal_unlock (void)
{
  /* LOCKED -> UNVERIFIED atomic transition: state moves to unverified,
   * locked_at and counter both clear, and a principal_event row of
   * shape (subject, 'unlock', 'locked', 'unverified') is appended. */
  g_autoptr (wyl_policy_store_t) store = NULL;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 1570;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 1571;
  if (wyl_policy_store_set_principal_state (store, "lockout.unlock",
          "mfa_required") != WYRELOG_E_OK)
    return 1572;
  for (gint64 i = 1; i <= 5; i++) {
    g_autofree gchar *st = NULL;
    gint64 c = 0;
    gint64 l = 0;
    if (wyl_policy_store_apply_principal_failure (store, "lockout.unlock",
            5, 600000 + i, &st, &c, &l) != WYRELOG_E_OK)
      return 1573;
  }
  if (wyl_policy_store_apply_principal_unlock (store, "lockout.unlock")
      != WYRELOG_E_OK)
    return 1574;
  g_autofree gchar *st = NULL;
  gint64 count = -1;
  gint64 locked_at = -1;
  gboolean found = FALSE;
  if (wyl_policy_store_get_principal_lock_info (store, "lockout.unlock", &st,
          &count, &locked_at, &found) != WYRELOG_E_OK)
    return 1575;
  if (!found || g_strcmp0 (st, "unverified") != 0 || count != 0
      || locked_at != G_MININT64)
    return 1576;
  return 0;
}

/* Issue #331 commit 5 iteration (LOW #2): apply_principal_failure
 * MUST refuse to extend a lockout when the row is already LOCKED.  The
 * validator's lockout gate prevents this in production, but the helper
 * is library-internal and future callers (e.g. wyctl in commit 6)
 * must not be able to bump locked_at or the counter by re-driving
 * FAILED_ATTEMPT against a LOCKED row.  The helper returns
 * WYRELOG_E_POLICY, leaves locked_at and the counter untouched, and
 * emits no extra principal_event row. */
static gint
check_store_apply_principal_failure_refuses_already_locked (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 1580;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 1581;
  if (wyl_policy_store_set_principal_state (store, "lockout.relock",
          "mfa_required") != WYRELOG_E_OK)
    return 1582;

  /* Drive the subject across the 5-failure threshold to LOCKED. */
  for (gint64 i = 1; i <= 5; i++) {
    g_autofree gchar *st = NULL;
    gint64 c = 0;
    gint64 l = 0;
    if (wyl_policy_store_apply_principal_failure (store, "lockout.relock",
            5, 700000 + i, &st, &c, &l) != WYRELOG_E_OK)
      return 1583;
  }

  /* Capture the original locked_at + counter for the post-condition. */
  g_autofree gchar *st_before = NULL;
  gint64 count_before = -1;
  gint64 locked_at_before = -1;
  gboolean found_before = FALSE;
  if (wyl_policy_store_get_principal_lock_info (store, "lockout.relock",
          &st_before, &count_before, &locked_at_before, &found_before)
      != WYRELOG_E_OK)
    return 1584;
  if (!found_before || g_strcmp0 (st_before, "locked") != 0
      || count_before != 5 || locked_at_before != 700005)
    return 1585;

  /* Count the principal_event rows once before the second-LOCK attempt
   * so we can prove no new event was appended. */
  gint events_before = 0;
  if (count_rows (store,
          "SELECT COUNT(*) FROM principal_events "
          "WHERE subject_id = 'lockout.relock';", &events_before) != 0)
    return 1586;

  /* Re-drive FAILED_ATTEMPT against the already-LOCKED row with a
   * later wallclock so a buggy implementation that overwrote locked_at
   * would be detectable. */
  g_autofree gchar *st_attempt = NULL;
  gint64 c_attempt = 0;
  gint64 l_attempt = 0;
  wyrelog_error_t relock_rc =
      wyl_policy_store_apply_principal_failure (store, "lockout.relock", 5,
      800000, &st_attempt, &c_attempt, &l_attempt);
  if (relock_rc != WYRELOG_E_POLICY)
    return 1587;
  /* Out-params on the refuse path should not leak partial state. */
  if (st_attempt != NULL || c_attempt != 0 || l_attempt != G_MININT64)
    return 1588;

  /* The persisted row must be unchanged: same state, same counter,
   * same locked_at - the second FAILED_ATTEMPT did NOT bump anything. */
  g_autofree gchar *st_after = NULL;
  gint64 count_after = -1;
  gint64 locked_at_after = -1;
  gboolean found_after = FALSE;
  if (wyl_policy_store_get_principal_lock_info (store, "lockout.relock",
          &st_after, &count_after, &locked_at_after, &found_after)
      != WYRELOG_E_OK)
    return 1589;
  if (!found_after || g_strcmp0 (st_after, "locked") != 0
      || count_after != count_before || locked_at_after != locked_at_before)
    return 1590;

  /* No additional principal_event row should have been emitted. */
  gint events_after = 0;
  if (count_rows (store,
          "SELECT COUNT(*) FROM principal_events "
          "WHERE subject_id = 'lockout.relock';", &events_after) != 0)
    return 1591;
  if (events_after != events_before)
    return 1592;

  return 0;
}

/* Issue #331 commit 5 iteration (LOW #4): legacy-schema migration.
 * A pre-#331-commit-5 store has principal_states with three columns
 * (subject_id, state, updated_at) - no failed_attempt_count, no
 * locked_at.  On reopen, create_schema's PRAGMA table_info / ALTER
 * TABLE ADD COLUMN block must back-fill the new columns idempotently,
 * preserving the existing rows' subject_id / state / updated_at and
 * defaulting the new columns to (0, NULL). */
static gint
check_store_principal_states_legacy_schema_migration (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *tmpdir =
      g_dir_make_tmp ("wyl-policy-ps-legacy-XXXXXX", &error);
  if (tmpdir == NULL)
    return 1600;
  g_autofree gchar *store_path =
      g_build_filename (tmpdir, "policy.store", NULL);
  g_autofree gchar *key_path = g_build_filename (tmpdir, "policy.key", NULL);
  if (!write_policy_key (key_path, 17))
    return 1601;

  /* Phase A: stand up the store with the full modern schema, then
   * mutate principal_states down to the legacy three-column shape and
   * insert a hand-rolled legacy row.  We drop and recreate the table
   * to model a store written by a pre-#331-commit-5 binary. */
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    if (open_encrypted_policy_store (store_path, key_path, &store)
        != WYRELOG_E_OK)
      return 1602;
    if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
      return 1603;
    if (sqlite3_exec (wyl_policy_store_get_db (store),
            "DROP TABLE principal_states;"
            "CREATE TABLE principal_states ("
            "  subject_id TEXT PRIMARY KEY,"
            "  state TEXT NOT NULL,"
            "  updated_at INTEGER"
            ");"
            "INSERT INTO principal_states (subject_id, state, updated_at) "
            "  VALUES ('legacy.user', 'mfa_required', 1234567);",
            NULL, NULL, NULL) != SQLITE_OK)
      return 1604;
  }

  /* Phase B: reopen; create_schema's ALTER TABLE ADD COLUMN block
   * should back-fill failed_attempt_count and locked_at on the
   * existing row without disturbing the columns that were already
   * there. */
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    if (open_encrypted_policy_store (store_path, key_path, &store)
        != WYRELOG_E_OK)
      return 1605;
    if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
      return 1606;

    /* The new columns must be present and defaulted to (0, NULL) on
     * the migrated row.  Use the lock_info accessor so we exercise
     * the same SELECT path that the validator uses in production. */
    g_autofree gchar *st = NULL;
    gint64 count = -1;
    gint64 locked_at = -1;
    gboolean found = FALSE;
    if (wyl_policy_store_get_principal_lock_info (store, "legacy.user",
            &st, &count, &locked_at, &found) != WYRELOG_E_OK)
      return 1607;
    if (!found)
      return 1608;
    if (g_strcmp0 (st, "mfa_required") != 0)
      return 1609;
    if (count != 0)
      return 1610;
    if (locked_at != G_MININT64)
      return 1611;

    /* Cross-check updated_at preservation via a raw SELECT - the
     * lock_info accessor does not expose it. */
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store),
            "SELECT updated_at FROM principal_states "
            "WHERE subject_id = 'legacy.user';", -1, &stmt, NULL)
        != SQLITE_OK)
      return 1612;
    if (sqlite3_step (stmt) != SQLITE_ROW) {
      sqlite3_finalize (stmt);
      return 1613;
    }
    gint64 updated_at = sqlite3_column_int64 (stmt, 0);
    sqlite3_finalize (stmt);
    if (updated_at != 1234567)
      return 1614;
  }

  (void) g_remove (store_path);
  (void) g_remove (key_path);
  (void) g_rmdir (tmpdir);
  return 0;
}

static gint
check_store_sets_session_state (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 86;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 87;
  if (wyl_policy_store_set_session_state (store, "session/1", "active")
      != WYRELOG_E_OK)
    return 88;
  if (wyl_policy_store_set_session_state (store, "session/1", "closed")
      != WYRELOG_E_OK)
    return 89;

  SessionStateExpect expect = {
    .session_id = "session/1",
    .state = "closed",
  };
  if (wyl_policy_store_foreach_session_state (store,
          session_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 90;
  if (expect.matches != 1)
    return 91;
  return 0;
}

static gint
check_store_appends_principal_event (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 92;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 93;
  gint64 event_id = -1;
  if (wyl_policy_store_append_principal_event (store, "principal-user",
          "login_skip_mfa", "unverified", "authenticated", &event_id)
      != WYRELOG_E_OK)
    return 94;

  PrincipalEventExpect expect = {
    .event_id = event_id,
    .subject_id = "principal-user",
    .event = "login_skip_mfa",
    .from_state = "unverified",
    .to_state = "authenticated",
  };
  if (wyl_policy_store_foreach_principal_event (store,
          principal_event_expect_cb, &expect) != WYRELOG_E_OK)
    return 95;
  if (expect.matches != 1)
    return 96;
  return 0;
}

static gint
check_store_appends_session_event (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 97;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 98;
  gint64 event_id = -1;
  if (wyl_policy_store_append_session_event (store, "session/1",
          "elevate_grant", "active", "elevated", &event_id) != WYRELOG_E_OK)
    return 99;

  SessionEventExpect expect = {
    .event_id = event_id,
    .session_id = "session/1",
    .event = "elevate_grant",
    .from_state = "active",
    .to_state = "elevated",
  };
  if (wyl_policy_store_foreach_session_event (store, session_event_expect_cb,
          &expect) != WYRELOG_E_OK)
    return 100;
  if (expect.matches != 1)
    return 101;
  return 0;
}

static gint
check_store_distinguishes_duplicate_events (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 102;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 103;
  gint64 principal_first = -1;
  gint64 principal_second = -1;
  if (wyl_policy_store_append_principal_event (store, "principal-dup",
          "login_ok", "unverified", "mfa_required", &principal_first)
      != WYRELOG_E_OK)
    return 104;
  if (wyl_policy_store_append_principal_event (store, "principal-dup",
          "login_ok", "unverified", "mfa_required", &principal_second)
      != WYRELOG_E_OK)
    return 105;
  if (principal_first <= 0 || principal_second <= principal_first)
    return 106;

  PrincipalEventExpect principal_expect = {
    .subject_id = "principal-dup",
    .event = "login_ok",
    .from_state = "unverified",
    .to_state = "mfa_required",
  };
  if (wyl_policy_store_foreach_principal_event (store,
          principal_event_expect_cb, &principal_expect) != WYRELOG_E_OK)
    return 107;
  if (principal_expect.matches != 2)
    return 108;

  gint64 session_first = -1;
  gint64 session_second = -1;
  if (wyl_policy_store_append_session_event (store, "session-dup",
          "elevate_grant", "active", "elevated", &session_first)
      != WYRELOG_E_OK)
    return 109;
  if (wyl_policy_store_append_session_event (store, "session-dup",
          "elevate_grant", "active", "elevated", &session_second)
      != WYRELOG_E_OK)
    return 110;
  if (session_first <= 0 || session_second <= session_first)
    return 111;

  SessionEventExpect session_expect = {
    .session_id = "session-dup",
    .event = "elevate_grant",
    .from_state = "active",
    .to_state = "elevated",
  };
  if (wyl_policy_store_foreach_session_event (store, session_event_expect_cb,
          &session_expect) != WYRELOG_E_OK)
    return 112;
  if (session_expect.matches != 2)
    return 113;
  gint64 perm_first = -1;
  gint64 perm_second = -1;
  if (wyl_policy_store_append_permission_state_event (store, "perm-dup-user",
          "wr.perm.dup", "perm-dup-scope", "grant", "dormant", "armed",
          &perm_first) != WYRELOG_E_OK)
    return 233;
  if (wyl_policy_store_append_permission_state_event (store, "perm-dup-user",
          "wr.perm.dup", "perm-dup-scope", "grant", "dormant", "armed",
          &perm_second) != WYRELOG_E_OK)
    return 234;
  if (perm_first <= 0 || perm_second <= perm_first)
    return 235;
  PermissionStateEventExpect perm_expect = {
    .subject_id = "perm-dup-user",
    .perm_id = "wr.perm.dup",
    .scope = "perm-dup-scope",
    .event = "grant",
    .from_state = "dormant",
    .to_state = "armed",
  };
  if (wyl_policy_store_foreach_permission_state_event (store,
          permission_state_event_expect_cb, &perm_expect) != WYRELOG_E_OK)
    return 236;
  if (perm_expect.matches != 2)
    return 237;
  return 0;
}

static gint
check_store_appends_audit_event (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 120;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 121;
  gboolean inserted = FALSE;
  if (wyl_policy_store_append_audit_event_full (store,
          "01890c10-2e3f-7000-8000-000000000001", 123,
          "audit-user", "read", "doc/1", "not_armed", "perm_state",
          "req-policy-store", WYL_DECISION_DENY, &inserted) != WYRELOG_E_OK)
    return 122;
  if (!inserted)
    return 123;

  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT subject_id, action, resource_id, deny_reason, deny_origin, "
      "request_id, decision FROM audit_events WHERE id = ?;";
  if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), sql, -1, &stmt,
          NULL) != SQLITE_OK)
    return 124;
  if (sqlite3_bind_text (stmt, 1, "01890c10-2e3f-7000-8000-000000000001",
          -1, SQLITE_TRANSIENT) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return 125;
  }

  int step_rc = sqlite3_step (stmt);
  gint rc = 0;
  if (step_rc != SQLITE_ROW)
    rc = 126;
  else if (g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 0),
          "audit-user") != 0)
    rc = 127;
  else if (g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 1),
          "read") != 0)
    rc = 128;
  else if (g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 2),
          "doc/1") != 0)
    rc = 129;
  else if (g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 3),
          "not_armed") != 0)
    rc = 130;
  else if (g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 4),
          "perm_state") != 0)
    rc = 131;
  else if (g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 5),
          "req-policy-store") != 0)
    rc = 132;
  else if (sqlite3_column_int (stmt, 6) != WYL_DECISION_DENY)
    rc = 133;

  sqlite3_finalize (stmt);
  return rc;
}

static gint
check_store_iterates_audit_event (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 132;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 133;
  gboolean inserted = FALSE;
  if (wyl_policy_store_append_audit_event_full (store,
          "01890c10-2e3f-7000-8000-000000000002", 456,
          "audit-user", "write", "doc/2", "allowed", "test",
          "req-iter", WYL_DECISION_ALLOW, &inserted) != WYRELOG_E_OK)
    return 134;

  AuditEventExpect expect = {
    .id = "01890c10-2e3f-7000-8000-000000000002",
    .created_at_us = 456,
    .subject_id = "audit-user",
    .action = "write",
    .resource_id = "doc/2",
    .deny_reason = "allowed",
    .deny_origin = "test",
    .request_id = "req-iter",
    .decision = WYL_DECISION_ALLOW,
  };
  if (wyl_policy_store_foreach_audit_event (store, audit_event_expect_cb,
          &expect) != WYRELOG_E_OK)
    return 135;
  if (expect.matches != 1)
    return 136;
  return 0;
}

static gint
check_store_append_audit_event_is_idempotent (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  static const gchar *id = "01890c10-2e3f-7000-8000-000000000005";

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 144;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 145;
  if (wyl_policy_store_append_audit_event (store, id, 777, NULL,
          "same.action", NULL, NULL, NULL, WYL_DECISION_ALLOW)
      != WYRELOG_E_OK)
    return 146;
  if (wyl_policy_store_append_audit_event (store, id, 777, NULL,
          "same.action", NULL, NULL, NULL, WYL_DECISION_ALLOW)
      != WYRELOG_E_OK)
    return 147;
  if (wyl_policy_store_append_audit_event (store, id, 777, NULL,
          "different.action", NULL, NULL, NULL, WYL_DECISION_ALLOW)
      != WYRELOG_E_POLICY)
    return 148;

  sqlite3_stmt *stmt = NULL;
  static const gchar *sql = "SELECT COUNT(*) FROM audit_events WHERE id = ?;";
  if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), sql, -1, &stmt,
          NULL) != SQLITE_OK)
    return 149;
  if (sqlite3_bind_text (stmt, 1, id, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return 150;
  }

  int step_rc = sqlite3_step (stmt);
  gint rc = 0;
  if (step_rc != SQLITE_ROW)
    rc = 151;
  else if (sqlite3_column_int64 (stmt, 0) != 1)
    rc = 152;

  sqlite3_finalize (stmt);
  return rc;
}

static gint
check_store_records_audit_intention (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  static const gchar *id = "01890c10-2e3f-7000-8000-000000000006";

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 240;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 241;
  gboolean inserted = FALSE;
  if (wyl_policy_store_record_audit_intention_full (store, id, 1002,
          "audit-user", "read", "doc/intent", "not_armed", "perm_state",
          "req-intent", WYL_DECISION_DENY, &inserted) != WYRELOG_E_OK)
    return 242;
  if (!inserted)
    return 243;

  AuditIntentionExpect expect = {
    .id = id,
    .created_at_us = 1002,
    .subject_id = "audit-user",
    .action = "read",
    .resource_id = "doc/intent",
    .deny_reason = "not_armed",
    .deny_origin = "perm_state",
    .request_id = "req-intent",
    .decision = WYL_DECISION_DENY,
    .state = "pending",
    .attempt_count = 0,
  };
  if (wyl_policy_store_foreach_audit_intention (store, "pending",
          audit_intention_expect_cb, &expect) != WYRELOG_E_OK)
    return 244;
  if (expect.matches != 1)
    return 245;

  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT chain_prev, chain_hash, anchor_batch_id "
      "FROM audit_intentions WHERE audit_id = ?;";
  if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), sql, -1, &stmt,
          NULL) != SQLITE_OK)
    return 246;
  if (sqlite3_bind_text (stmt, 1, id, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return 247;
  }

  int step_rc = sqlite3_step (stmt);
  gint rc = 0;
  if (step_rc != SQLITE_ROW)
    rc = 248;
  else if (sqlite3_column_type (stmt, 0) != SQLITE_NULL
      || sqlite3_column_type (stmt, 1) != SQLITE_NULL
      || sqlite3_column_type (stmt, 2) != SQLITE_NULL)
    rc = 249;

  sqlite3_finalize (stmt);
  return rc;
}

static gint
check_store_audit_intention_is_idempotent (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  static const gchar *id = "01890c10-2e3f-7000-8000-000000000007";

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 250;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 251;
  gboolean inserted = FALSE;
  if (wyl_policy_store_record_audit_intention_full (store, id, 1003,
          "audit-user", "same.action", NULL, NULL, NULL, "req-same",
          WYL_DECISION_ALLOW, &inserted) != WYRELOG_E_OK)
    return 252;
  if (!inserted)
    return 253;
  inserted = TRUE;
  if (wyl_policy_store_record_audit_intention_full (store, id, 1003,
          "audit-user", "same.action", NULL, NULL, NULL, "req-same",
          WYL_DECISION_ALLOW, &inserted) != WYRELOG_E_OK)
    return 254;
  if (inserted)
    return 255;
  if (wyl_policy_store_record_audit_intention_full (store, id, 1003,
          "audit-user", "different.action", NULL, NULL, NULL, "req-same",
          WYL_DECISION_ALLOW, &inserted) != WYRELOG_E_POLICY)
    return 256;

  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT COUNT(*) FROM audit_intentions WHERE audit_id = ?;";
  if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), sql, -1, &stmt,
          NULL) != SQLITE_OK)
    return 257;
  if (sqlite3_bind_text (stmt, 1, id, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return 258;
  }

  int step_rc = sqlite3_step (stmt);
  gint rc = 0;
  if (step_rc != SQLITE_ROW)
    rc = 259;
  else if (sqlite3_column_int64 (stmt, 0) != 1)
    rc = 260;

  sqlite3_finalize (stmt);
  return rc;
}

static gint
check_store_marks_audit_intention_states (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  static const gchar *committed_id = "01890c10-2e3f-7000-8000-000000000008";
  static const gchar *failed_id = "01890c10-2e3f-7000-8000-000000000009";

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 261;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 262;
  gboolean inserted = FALSE;
  if (wyl_policy_store_record_audit_intention_full (store, committed_id, 1004,
          "audit-user", "commit.action", NULL, NULL, NULL, NULL,
          WYL_DECISION_ALLOW, &inserted) != WYRELOG_E_OK)
    return 263;
  if (wyl_policy_store_record_audit_intention_full (store, failed_id, 1005,
          "audit-user", "fail.action", NULL, NULL, NULL, NULL,
          WYL_DECISION_DENY, &inserted) != WYRELOG_E_OK)
    return 264;
  if (wyl_policy_store_mark_audit_intention_committed (store, committed_id)
      != WYRELOG_E_OK)
    return 265;
  if (wyl_policy_store_mark_audit_intention_committed (store, committed_id)
      != WYRELOG_E_OK)
    return 283;
  if (wyl_policy_store_mark_audit_intention_failed (store, committed_id,
          "late failure") != WYRELOG_E_POLICY)
    return 284;
  if (wyl_policy_store_mark_audit_intention_failed (store, failed_id,
          "duckdb append failed") != WYRELOG_E_OK)
    return 266;
  if (wyl_policy_store_mark_audit_intention_committed (store, failed_id)
      != WYRELOG_E_OK)
    return 285;
  if (wyl_policy_store_mark_audit_intention_failed (store, failed_id,
          "late failure") != WYRELOG_E_POLICY)
    return 286;

  AuditIntentionExpect committed = {
    .id = committed_id,
    .created_at_us = 1004,
    .subject_id = "audit-user",
    .action = "commit.action",
    .decision = WYL_DECISION_ALLOW,
    .state = "committed",
    .attempt_count = 0,
  };
  if (wyl_policy_store_foreach_audit_intention (store, "committed",
          audit_intention_expect_cb, &committed) != WYRELOG_E_OK)
    return 267;
  if (committed.matches != 1)
    return 268;

  AuditIntentionExpect failed = {
    .id = failed_id,
    .created_at_us = 1005,
    .subject_id = "audit-user",
    .action = "fail.action",
    .decision = WYL_DECISION_DENY,
    .state = "committed",
    .attempt_count = 1,
  };
  if (wyl_policy_store_foreach_audit_intention (store, "committed",
          audit_intention_expect_cb, &failed) != WYRELOG_E_OK)
    return 269;
  if (failed.matches != 1)
    return 270;
  return 0;
}

static gint
check_store_rejects_bad_audit_intentions (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  gboolean inserted = FALSE;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 271;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 272;
  if (wyl_policy_store_record_audit_intention_full (NULL,
          "01890c10-2e3f-7000-8000-000000000010", 1, NULL, NULL, NULL, NULL,
          NULL, NULL, WYL_DECISION_ALLOW, &inserted) != WYRELOG_E_INVALID)
    return 273;
  if (wyl_policy_store_record_audit_intention_full (store, NULL, 1, NULL,
          NULL, NULL, NULL, NULL, NULL, WYL_DECISION_ALLOW, &inserted)
      != WYRELOG_E_INVALID)
    return 274;
  if (wyl_policy_store_record_audit_intention_full (store,
          "01890c10-2e3f-7000-8000-000000000010", -1, NULL, NULL, NULL, NULL,
          NULL, NULL, WYL_DECISION_ALLOW, &inserted) != WYRELOG_E_INVALID)
    return 275;
  if (wyl_policy_store_record_audit_intention_full (store, "not-a-uuid", 1,
          NULL, NULL, NULL, NULL, NULL, NULL, WYL_DECISION_ALLOW, &inserted)
      != WYRELOG_E_INVALID)
    return 276;
  if (wyl_policy_store_record_audit_intention_full (store,
          "01890c10-2e3f-7000-8000-000000000010", 1, NULL, NULL, NULL, NULL,
          NULL, NULL, (wyl_decision_t) 9, &inserted) != WYRELOG_E_INVALID)
    return 277;
  if (wyl_policy_store_record_audit_intention_full (store,
          "01890c10-2e3f-7000-8000-000000000010", 1, NULL, NULL, NULL, NULL,
          NULL, NULL, WYL_DECISION_ALLOW, NULL) != WYRELOG_E_INVALID)
    return 278;
  if (wyl_policy_store_foreach_audit_intention (store, "unknown",
          audit_intention_expect_cb, NULL) != WYRELOG_E_INVALID)
    return 279;
  if (wyl_policy_store_foreach_audit_intention (store, NULL, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 280;
  if (wyl_policy_store_mark_audit_intention_committed (store,
          "01890c10-2e3f-7000-8000-000000000010") != WYRELOG_E_POLICY)
    return 281;
  if (wyl_policy_store_mark_audit_intention_failed (store,
          "01890c10-2e3f-7000-8000-000000000010", NULL)
      != WYRELOG_E_INVALID)
    return 282;
  return 0;
}

static gint
check_store_rejects_corrupt_audit_events (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 137;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 138;

  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "INSERT INTO audit_events "
          "(id, created_at_us, action, decision) "
          "VALUES ('not-a-uuid', 1, 'bad.id', 1);",
          NULL, NULL, NULL) != SQLITE_OK)
    return 139;
  if (wyl_policy_store_foreach_audit_event (store, audit_event_expect_cb,
          NULL) != WYRELOG_E_POLICY)
    return 140;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "DELETE FROM audit_events;", NULL, NULL, NULL) != SQLITE_OK)
    return 141;

  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "INSERT INTO audit_events "
          "(id, created_at_us, action, decision) "
          "VALUES ('01890c10-2e3f-7000-8000-000000000004', -1, "
          "'bad.timestamp', 1);", NULL, NULL, NULL) != SQLITE_OK)
    return 142;
  if (wyl_policy_store_foreach_audit_event (store, audit_event_expect_cb,
          NULL) != WYRELOG_E_POLICY)
    return 143;

  return 0;
}

static gint
check_store_rejects_bad_direct_permission (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  gboolean exists = FALSE;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 70;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 71;
  if (wyl_policy_store_grant_direct_permission (store, "direct-user",
          "missing-perm", "direct-scope") != WYRELOG_E_IO)
    return 72;
  if (wyl_policy_store_grant_direct_permission (NULL, "direct-user",
          "missing-perm", "direct-scope") != WYRELOG_E_INVALID)
    return 73;
  if (wyl_policy_store_revoke_direct_permission (store, NULL,
          "missing-perm", "direct-scope") != WYRELOG_E_INVALID)
    return 74;
  if (wyl_policy_store_direct_permission_exists (store, "direct-user",
          "missing-perm", "direct-scope", NULL) != WYRELOG_E_INVALID)
    return 75;
  if (wyl_policy_store_foreach_direct_permission (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 78;
  if (wyl_policy_store_append_direct_permission_event (store, NULL,
          "missing-perm", "direct-scope", "grant") != WYRELOG_E_INVALID)
    return 79;
  if (wyl_policy_store_foreach_direct_permission_event (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 80;
  if (wyl_policy_store_direct_permission_exists (store, "direct-user",
          "missing-perm", "direct-scope", &exists) != WYRELOG_E_OK)
    return 76;
  if (exists)
    return 77;
  return 0;
}

static gint
check_store_rejects_bad_role_permission (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 50;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 51;
  if (wyl_policy_store_grant_role_permission (store, "missing-role",
          "missing-perm") != WYRELOG_E_IO)
    return 52;
  if (wyl_policy_store_upsert_role (NULL, "role", "role") != WYRELOG_E_INVALID)
    return 53;
  if (wyl_policy_store_upsert_permission (store, "perm", "perm", "unknown")
      != WYRELOG_E_IO)
    return 54;
  if (wyl_policy_store_foreach_role_permission (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 55;
  if (wyl_policy_store_grant_role_inheritance (store, "missing-child",
          "missing-parent") != WYRELOG_E_IO)
    return 58;
  if (wyl_policy_store_foreach_role_inheritance (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 59;
  if (wyl_policy_store_grant_role_membership (store, "role-user",
          "missing-role", "role-scope") != WYRELOG_E_IO)
    return 97;
  if (wyl_policy_store_grant_role_membership (store, NULL, "missing-role",
          "role-scope") != WYRELOG_E_INVALID)
    return 98;
  if (wyl_policy_store_revoke_role_membership (store, NULL, "missing-role",
          "role-scope") != WYRELOG_E_INVALID)
    return 100;
  gboolean exists = TRUE;
  if (wyl_policy_store_role_membership_exists (store, NULL, "missing-role",
          "role-scope", &exists) != WYRELOG_E_INVALID)
    return 101;
  if (wyl_policy_store_foreach_role_membership (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 99;
  if (wyl_policy_store_append_role_membership_event (store, "role-user",
          "missing-role", "role-scope", "grant") != WYRELOG_E_IO)
    return 102;
  if (wyl_policy_store_append_role_membership_event (store, "role-user",
          "missing-role", "role-scope", "invalid") != WYRELOG_E_IO)
    return 103;
  if (wyl_policy_store_foreach_role_membership_event (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 104;
  if (wyl_policy_store_set_permission_state (store, NULL, "wr.read", "scope",
          "armed") != WYRELOG_E_INVALID)
    return 105;
  if (wyl_policy_store_set_permission_state (store, "user", NULL, "scope",
          "armed") != WYRELOG_E_INVALID)
    return 106;
  if (wyl_policy_store_set_permission_state (store, "user", "wr.read", NULL,
          "armed") != WYRELOG_E_INVALID)
    return 107;
  if (wyl_policy_store_set_permission_state (store, "user", "wr.read", "scope",
          NULL) != WYRELOG_E_INVALID)
    return 108;
  gboolean permission_state_exists = FALSE;
  if (wyl_policy_store_permission_state_exists (store, NULL, "wr.read", "scope",
          &permission_state_exists) != WYRELOG_E_INVALID)
    return 109;
  if (wyl_policy_store_permission_state_exists (store, "user", NULL, "scope",
          &permission_state_exists) != WYRELOG_E_INVALID)
    return 110;
  if (wyl_policy_store_permission_state_exists (store, "user", "wr.read", NULL,
          &permission_state_exists) != WYRELOG_E_INVALID)
    return 111;
  if (wyl_policy_store_permission_state_exists (store, "user", "wr.read",
          "scope", NULL) != WYRELOG_E_INVALID)
    return 112;
  if (wyl_policy_store_foreach_permission_state (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 113;
  if (wyl_policy_store_append_permission_state_event (store, NULL, "wr.read",
          "scope", "grant", "dormant", "armed", NULL) != WYRELOG_E_INVALID)
    return 114;
  if (wyl_policy_store_append_permission_state_event (store, "user", NULL,
          "scope", "grant", "dormant", "armed", NULL) != WYRELOG_E_INVALID)
    return 115;
  if (wyl_policy_store_append_permission_state_event (store, "user", "wr.read",
          NULL, "grant", "dormant", "armed", NULL) != WYRELOG_E_INVALID)
    return 116;
  if (wyl_policy_store_append_permission_state_event (store, "user", "wr.read",
          "scope", NULL, "dormant", "armed", NULL) != WYRELOG_E_INVALID)
    return 117;
  if (wyl_policy_store_append_permission_state_event (store, "user", "wr.read",
          "scope", "grant", NULL, "armed", NULL) != WYRELOG_E_INVALID)
    return 118;
  if (wyl_policy_store_append_permission_state_event (store, "user", "wr.read",
          "scope", "grant", "dormant", NULL, NULL) != WYRELOG_E_INVALID)
    return 119;
  if (wyl_policy_store_foreach_permission_state_event (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 120;
  if (wyl_policy_store_set_principal_state (store, NULL, "authenticated")
      != WYRELOG_E_INVALID)
    return 56;
  if (wyl_policy_store_foreach_principal_state (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 57;
  if (wyl_policy_store_append_principal_event (store, NULL, "login_ok",
          "unverified", "mfa_required", NULL) != WYRELOG_E_INVALID)
    return 92;
  if (wyl_policy_store_foreach_principal_event (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 93;
  if (wyl_policy_store_set_session_state (store, NULL, "active")
      != WYRELOG_E_INVALID)
    return 58;
  if (wyl_policy_store_foreach_session_state (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 59;
  if (wyl_policy_store_append_session_event (store, NULL, "request", "idle",
          "active", NULL) != WYRELOG_E_INVALID)
    return 60;
  if (wyl_policy_store_foreach_session_event (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 61;
  if (wyl_policy_store_append_audit_event (store, NULL, 0, NULL, NULL, NULL,
          NULL, NULL, WYL_DECISION_ALLOW) != WYRELOG_E_INVALID)
    return 94;
  if (wyl_policy_store_append_audit_event (store,
          "01890c10-2e3f-7000-8000-000000000003", -1, NULL, NULL, NULL,
          NULL, NULL, WYL_DECISION_ALLOW) != WYRELOG_E_INVALID)
    return 95;
  if (wyl_policy_store_append_audit_event (store, "audit-bad", 0, NULL,
          NULL, NULL, NULL, NULL, (wyl_decision_t) 9) != WYRELOG_E_INVALID)
    return 96;
  if (wyl_policy_store_foreach_audit_event (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 105;
  return 0;
}

static gint
check_bootstrap_admin_applies_on_fresh_store (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 800;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 801;

  gboolean eligible = FALSE;
  if (wyl_policy_store_bootstrap_admin_eligible (store, &eligible)
      != WYRELOG_E_OK)
    return 802;
  if (!eligible)
    return 803;

  gboolean applied = FALSE;
  g_autofree gchar *existing = NULL;
  if (wyl_policy_store_apply_bootstrap_admin (store, "alice.root", FALSE,
          &applied, &existing) != WYRELOG_E_OK)
    return 804;
  if (!applied)
    return 805;
  if (existing != NULL)
    return 806;

  if (wyl_policy_store_bootstrap_admin_eligible (store, &eligible)
      != WYRELOG_E_OK)
    return 807;
  if (eligible)
    return 808;

  g_autofree gchar *subject = NULL;
  gint64 sealed_at_us = 0;
  if (wyl_policy_store_get_bootstrap_admin (store, &subject, &sealed_at_us)
      != WYRELOG_E_OK)
    return 809;
  if (g_strcmp0 (subject, "alice.root") != 0)
    return 810;
  if (sealed_at_us <= 0)
    return 811;

  gint membership_count = 0;
  if (count_rows (store,
          "SELECT COUNT(*) FROM role_memberships "
          "WHERE subject_id = 'alice.root' "
          "  AND role_id = 'wr.system_admin' "
          "  AND scope = '__wr_default';", &membership_count) != 0)
    return 812;
  if (membership_count != 1)
    return 813;

  gint default_scope_state_count = 0;
  if (count_rows (store,
          "SELECT COUNT(*) FROM session_states "
          "WHERE session_id = '__wr_default' "
          "  AND state = 'active';", &default_scope_state_count) != 0)
    return 816;
  if (default_scope_state_count != 1)
    return 817;

  gint default_scope_event_count = 0;
  if (count_rows (store,
          "SELECT COUNT(*) FROM session_events "
          "WHERE session_id = '__wr_default' "
          "  AND event = 'request' "
          "  AND from_state = 'idle' "
          "  AND to_state = 'active';", &default_scope_event_count) != 0)
    return 818;
  if (default_scope_event_count != 1)
    return 819;

  gint skip_mfa_count = 0;
  if (count_rows (store,
          "SELECT COUNT(*) FROM direct_permissions "
          "WHERE subject_id = 'alice.root' "
          "  AND perm_id = 'wr.login.skip_mfa';", &skip_mfa_count) != 0)
    return 814;
  if (skip_mfa_count != 0)
    return 815;

  return 0;
}

static gint
check_bootstrap_admin_same_subject_is_idempotent (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 820;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 821;

  gboolean applied = FALSE;
  g_autofree gchar *existing = NULL;
  if (wyl_policy_store_apply_bootstrap_admin (store, "alice.root", FALSE,
          &applied, &existing) != WYRELOG_E_OK)
    return 822;
  if (!applied)
    return 823;

  applied = TRUE;
  g_autofree gchar *existing2 = NULL;
  if (wyl_policy_store_apply_bootstrap_admin (store, "alice.root", FALSE,
          &applied, &existing2) != WYRELOG_E_OK)
    return 824;
  if (applied)
    return 825;
  if (existing2 != NULL)
    return 826;

  gint membership_count = 0;
  if (count_rows (store,
          "SELECT COUNT(*) FROM role_memberships "
          "WHERE role_id = 'wr.system_admin';", &membership_count) != 0)
    return 827;
  if (membership_count != 1)
    return 828;

  gint marker_rows = 0;
  if (count_rows (store,
          "SELECT COUNT(*) FROM wyrelog_config "
          "WHERE config_key = 'bootstrap_admin_subject';", &marker_rows) != 0)
    return 829;
  if (marker_rows != 1)
    return 830;

  return 0;
}

static gint
check_bootstrap_admin_different_subject_is_refused (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 840;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 841;

  gboolean applied = FALSE;
  g_autofree gchar *existing = NULL;
  if (wyl_policy_store_apply_bootstrap_admin (store, "alice.root", FALSE,
          &applied, &existing) != WYRELOG_E_OK)
    return 842;
  if (!applied)
    return 843;

  applied = TRUE;
  g_autofree gchar *existing2 = NULL;
  if (wyl_policy_store_apply_bootstrap_admin (store, "bob.root", FALSE,
          &applied, &existing2) != WYRELOG_E_POLICY)
    return 844;
  if (applied)
    return 845;
  if (g_strcmp0 (existing2, "alice.root") != 0)
    return 846;

  gint membership_count = 0;
  if (count_rows (store,
          "SELECT COUNT(*) FROM role_memberships "
          "WHERE subject_id = 'bob.root';", &membership_count) != 0)
    return 847;
  if (membership_count != 0)
    return 848;

  return 0;
}

static gint
check_bootstrap_admin_rejects_empty_subject (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 860;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 861;

  gboolean applied = TRUE;
  g_autofree gchar *existing = NULL;
  if (wyl_policy_store_apply_bootstrap_admin (store, "", FALSE,
          &applied, &existing) != WYRELOG_E_INVALID)
    return 862;
  if (applied)
    return 863;
  if (existing != NULL)
    return 864;

  applied = TRUE;
  g_autofree gchar *existing2 = NULL;
  if (wyl_policy_store_apply_bootstrap_admin (store, NULL, FALSE,
          &applied, &existing2) != WYRELOG_E_INVALID)
    return 865;
  if (applied)
    return 866;
  if (existing2 != NULL)
    return 867;

  return 0;
}

static gint
check_bootstrap_admin_rejects_whitespace_subject (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 870;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 871;

  gboolean applied = TRUE;
  g_autofree gchar *existing = NULL;
  if (wyl_policy_store_apply_bootstrap_admin (store, "alice root", FALSE,
          &applied, &existing) != WYRELOG_E_INVALID)
    return 872;
  if (applied)
    return 873;

  applied = TRUE;
  g_autofree gchar *existing2 = NULL;
  if (wyl_policy_store_apply_bootstrap_admin (store, "alice/root", FALSE,
          &applied, &existing2) != WYRELOG_E_INVALID)
    return 874;
  if (applied)
    return 875;

  applied = TRUE;
  g_autofree gchar *existing3 = NULL;
  if (wyl_policy_store_apply_bootstrap_admin (store, "alice\troot", FALSE,
          &applied, &existing3) != WYRELOG_E_INVALID)
    return 876;
  if (applied)
    return 877;

  return 0;
}

static gint
check_bootstrap_admin_rejects_overlong_subject (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 880;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 881;

  /* 129 'a's: one over the 128-byte limit. */
  gchar overlong[130];
  for (gsize i = 0; i < 129; i++)
    overlong[i] = 'a';
  overlong[129] = '\0';

  gboolean applied = TRUE;
  g_autofree gchar *existing = NULL;
  if (wyl_policy_store_apply_bootstrap_admin (store, overlong, FALSE,
          &applied, &existing) != WYRELOG_E_INVALID)
    return 882;
  if (applied)
    return 883;

  /* 2-char subject: under the 3-byte minimum. */
  applied = TRUE;
  g_autofree gchar *existing2 = NULL;
  if (wyl_policy_store_apply_bootstrap_admin (store, "ab", FALSE,
          &applied, &existing2) != WYRELOG_E_INVALID)
    return 884;
  if (applied)
    return 885;

  return 0;
}

static gint
check_bootstrap_admin_seal_survives_reopen (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *tmpdir = g_dir_make_tmp ("wyl-policy-bootstrap-XXXXXX",
      &error);
  if (tmpdir == NULL)
    return 900;
  g_autofree gchar *store_path =
      g_build_filename (tmpdir, "policy.store", NULL);
  g_autofree gchar *key_path = g_build_filename (tmpdir, "policy.key", NULL);
  if (!write_policy_key (key_path, 7))
    return 901;

  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    if (open_encrypted_policy_store (store_path, key_path, &store)
        != WYRELOG_E_OK)
      return 902;
    if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
      return 903;
    gboolean applied = FALSE;
    g_autofree gchar *existing = NULL;
    if (wyl_policy_store_apply_bootstrap_admin (store, "alice.root", FALSE,
            &applied, &existing) != WYRELOG_E_OK)
      return 904;
    if (!applied)
      return 905;
  }

  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    if (open_encrypted_policy_store (store_path, key_path, &store)
        != WYRELOG_E_OK)
      return 906;
    if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
      return 907;
    g_autofree gchar *subject = NULL;
    gint64 sealed_at_us = 0;
    if (wyl_policy_store_get_bootstrap_admin (store, &subject, &sealed_at_us)
        != WYRELOG_E_OK)
      return 908;
    if (g_strcmp0 (subject, "alice.root") != 0)
      return 909;
    if (sealed_at_us <= 0)
      return 910;
    gboolean eligible = TRUE;
    if (wyl_policy_store_bootstrap_admin_eligible (store, &eligible)
        != WYRELOG_E_OK)
      return 911;
    if (eligible)
      return 912;
  }

  (void) g_remove (store_path);
  (void) g_remove (key_path);
  (void) g_rmdir (tmpdir);
  return 0;
}

static gint
check_bootstrap_admin_legacy_skip_migration (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *tmpdir = g_dir_make_tmp ("wyl-policy-legacy-XXXXXX",
      &error);
  if (tmpdir == NULL)
    return 920;
  g_autofree gchar *store_path =
      g_build_filename (tmpdir, "policy.store", NULL);
  g_autofree gchar *key_path = g_build_filename (tmpdir, "policy.key", NULL);
  if (!write_policy_key (key_path, 11))
    return 921;

  /* Stage a pre-#305 store: schema present, an admin membership row,
   * no bootstrap_admin_subject marker. */
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    if (open_encrypted_policy_store (store_path, key_path, &store)
        != WYRELOG_E_OK)
      return 922;
    if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
      return 923;
    if (wyl_policy_store_grant_role_membership (store, "legacy.admin",
            "wr.system_admin", "__wr_default") != WYRELOG_E_OK)
      return 924;
    /* Erase any marker the migration may have written so this
     * fixture genuinely looks like a pre-#305 store on the next
     * open. */
    if (sqlite3_exec (wyl_policy_store_get_db (store),
            "DELETE FROM wyrelog_config "
            "WHERE config_key IN ('bootstrap_admin_subject',"
            "                     'bootstrap_admin_sealed_at_us');",
            NULL, NULL, NULL) != SQLITE_OK)
      return 925;
  }

  /* Reopen and re-run create_schema: migration should plant the
   * legacy-skip sentinel. */
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    if (open_encrypted_policy_store (store_path, key_path, &store)
        != WYRELOG_E_OK)
      return 926;
    if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
      return 927;

    g_autofree gchar *subject = NULL;
    gint64 sealed_at_us = 0;
    if (wyl_policy_store_get_bootstrap_admin (store, &subject, &sealed_at_us)
        != WYRELOG_E_OK)
      return 928;
    if (g_strcmp0 (subject, "legacy-skip") != 0)
      return 929;

    gboolean eligible = TRUE;
    if (wyl_policy_store_bootstrap_admin_eligible (store, &eligible)
        != WYRELOG_E_OK)
      return 930;
    if (eligible)
      return 931;

    /* A bootstrap attempt against a legacy-skip store must refuse
     * and report the sentinel as the existing subject. */
    gboolean applied = TRUE;
    g_autofree gchar *existing = NULL;
    if (wyl_policy_store_apply_bootstrap_admin (store, "alice.root", FALSE,
            &applied, &existing) != WYRELOG_E_POLICY)
      return 932;
    if (applied)
      return 933;
    if (g_strcmp0 (existing, "legacy-skip") != 0)
      return 934;
  }

  (void) g_remove (store_path);
  (void) g_remove (key_path);
  (void) g_rmdir (tmpdir);
  return 0;
}

static gint
check_bootstrap_admin_allow_skip_mfa_flag (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 940;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 941;

  gboolean applied = FALSE;
  g_autofree gchar *existing = NULL;
  if (wyl_policy_store_apply_bootstrap_admin (store, "alice.root", TRUE,
          &applied, &existing) != WYRELOG_E_OK)
    return 942;
  if (!applied)
    return 943;

  gint skip_mfa_count = 0;
  if (count_rows (store,
          "SELECT COUNT(*) FROM direct_permissions "
          "WHERE subject_id = 'alice.root' "
          "  AND perm_id = 'wr.login.skip_mfa' "
          "  AND scope = 'login';", &skip_mfa_count) != 0)
    return 944;
  if (skip_mfa_count != 1)
    return 945;

  gint skip_mfa_state_count = 0;
  if (count_rows (store,
          "SELECT COUNT(*) FROM permission_states "
          "WHERE subject_id = 'alice.root' "
          "  AND perm_id = 'wr.login.skip_mfa' "
          "  AND scope = 'login' "
          "  AND state = 'armed';", &skip_mfa_state_count) != 0)
    return 946;
  if (skip_mfa_state_count != 1)
    return 947;

  gint skip_mfa_state_event_count = 0;
  if (count_rows (store,
          "SELECT COUNT(*) FROM permission_state_events "
          "WHERE subject_id = 'alice.root' "
          "  AND perm_id = 'wr.login.skip_mfa' "
          "  AND scope = 'login' "
          "  AND event = 'grant' "
          "  AND from_state = 'dormant' "
          "  AND to_state = 'armed';", &skip_mfa_state_event_count) != 0)
    return 948;
  if (skip_mfa_state_event_count != 1)
    return 949;

  /* Reapply with allow_login_skip_mfa = FALSE: idempotent no-op, the
   * existing skip-mfa grant and state remain untouched. */
  applied = TRUE;
  g_autofree gchar *existing2 = NULL;
  if (wyl_policy_store_apply_bootstrap_admin (store, "alice.root", FALSE,
          &applied, &existing2) != WYRELOG_E_OK)
    return 950;
  if (applied)
    return 951;

  if (count_rows (store,
          "SELECT COUNT(*) FROM direct_permissions "
          "WHERE subject_id = 'alice.root' "
          "  AND perm_id = 'wr.login.skip_mfa';", &skip_mfa_count) != 0)
    return 952;
  if (skip_mfa_count != 1)
    return 953;

  if (count_rows (store,
          "SELECT COUNT(*) FROM permission_states "
          "WHERE subject_id = 'alice.root' "
          "  AND perm_id = 'wr.login.skip_mfa';", &skip_mfa_state_count) != 0)
    return 954;
  if (skip_mfa_state_count != 1)
    return 955;

  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_store_creates_authority_schema ()) != 0)
    return rc;
  if ((rc = check_template_schema_creates_state_tables ()) != 0)
    return rc;
  if ((rc = check_store_rejects_invalid_args ()) != 0)
    return rc;
  if ((rc = check_store_gets_default_deployment_mode ()) != 0)
    return rc;
  if ((rc = check_store_manages_tenant_registry ()) != 0)
    return rc;
  if ((rc = check_store_manages_fact_graph_registry ()) != 0)
    return rc;
  if ((rc = check_store_seals_fact_graph_registry ()) != 0)
    return rc;
  if ((rc = check_store_rejects_fact_graph_registry_escapes ()) != 0)
    return rc;
  if ((rc = check_store_rejects_fact_graph_reserved_metadata ()) != 0)
    return rc;
  if ((rc = check_store_fact_graph_metadata_only ()) != 0)
    return rc;
  if ((rc = check_store_sets_deployment_mode ()) != 0)
    return rc;
  if ((rc = check_handle_owns_policy_store ()) != 0)
    return rc;
  if ((rc = check_encrypted_policy_store_hardening_and_rotation ()) != 0)
    return rc;
  if ((rc = check_store_seeds_builtin_catalog ()) != 0)
    return rc;
  if ((rc = check_store_rejects_builtin_catalog_drift ()) != 0)
    return rc;
  if ((rc = check_store_rejects_builtin_catalog_upsert_drift ()) != 0)
    return rc;
  if ((rc = check_store_grants_role_permission ()) != 0)
    return rc;
  if ((rc = check_store_catalog_existence_probes ()) != 0)
    return rc;
  if ((rc = check_store_grants_role_inheritance ()) != 0)
    return rc;
  if ((rc = check_store_grants_role_membership ()) != 0)
    return rc;
  if ((rc = check_store_grants_direct_permission ()) != 0)
    return rc;
  if ((rc = check_store_checks_effective_subject_permission ()) != 0)
    return rc;
  if ((rc = check_role_membership_mutation_rolls_back_on_event_failure ())
      != 0)
    return rc;
  if ((rc = check_role_membership_revoke_rolls_back_on_event_failure ())
      != 0)
    return rc;
  if ((rc = check_store_appends_direct_permission_event ()) != 0)
    return rc;
  if ((rc = check_direct_permission_mutation_rolls_back_on_event_failure ())
      != 0)
    return rc;
  if ((rc = check_direct_permission_revoke_rolls_back_on_event_failure ())
      != 0)
    return rc;
  if ((rc = check_store_sets_permission_state ()) != 0)
    return rc;
  if ((rc = check_store_appends_permission_state_event ()) != 0)
    return rc;
  if ((rc = check_store_applies_permission_state_transition ()) != 0)
    return rc;
  if ((rc = check_store_permission_state_transition_rejects_invalid_edge ())
      != 0)
    return rc;
  if ((rc = check_store_permission_state_transition_rolls_back_event_failure ())
      != 0)
    return rc;
  if ((rc = check_store_permission_state_transition_appends_audit ()) != 0)
    return rc;
  if ((rc = check_store_permission_state_transition_rolls_back_audit_failure ())
      != 0)
    return rc;
  if ((rc = check_store_permission_state_transition_rejects_invalid_audit ())
      != 0)
    return rc;
  if ((rc =
          check_store_permission_state_transition_rolls_back_audit_conflict ())
      != 0)
    return rc;
  if ((rc = check_store_sets_principal_state ()) != 0)
    return rc;
  if ((rc = check_store_get_principal_state_round_trip ()) != 0)
    return rc;
  if ((rc = check_store_apply_principal_failure_increments_counter ()) != 0)
    return rc;
  if ((rc = check_store_apply_principal_failure_transitions_to_locked ()) != 0)
    return rc;
  if ((rc = check_store_apply_principal_failure_survives_reopen ()) != 0)
    return rc;
  if ((rc = check_store_reset_principal_failure_counter ()) != 0)
    return rc;
  if ((rc = check_store_apply_principal_failure_sequential_race ()) != 0)
    return rc;
  if ((rc = check_store_apply_principal_unlock ()) != 0)
    return rc;
  if ((rc = check_store_apply_principal_failure_refuses_already_locked ()) != 0)
    return rc;
  if ((rc = check_store_principal_states_legacy_schema_migration ()) != 0)
    return rc;
  if ((rc = check_store_sets_session_state ()) != 0)
    return rc;
  if ((rc = check_store_appends_principal_event ()) != 0)
    return rc;
  if ((rc = check_store_appends_session_event ()) != 0)
    return rc;
  if ((rc = check_store_distinguishes_duplicate_events ()) != 0)
    return rc;
  if ((rc = check_store_appends_audit_event ()) != 0)
    return rc;
  if ((rc = check_store_iterates_audit_event ()) != 0)
    return rc;
  if ((rc = check_store_append_audit_event_is_idempotent ()) != 0)
    return rc;
  if ((rc = check_store_records_audit_intention ()) != 0)
    return rc;
  if ((rc = check_store_audit_intention_is_idempotent ()) != 0)
    return rc;
  if ((rc = check_store_marks_audit_intention_states ()) != 0)
    return rc;
  if ((rc = check_store_rejects_bad_audit_intentions ()) != 0)
    return rc;
  if ((rc = check_store_rejects_corrupt_audit_events ()) != 0)
    return rc;
  if ((rc = check_store_rejects_bad_direct_permission ()) != 0)
    return rc;
  if ((rc = check_store_rejects_bad_role_permission ()) != 0)
    return rc;
  if ((rc = check_bootstrap_admin_applies_on_fresh_store ()) != 0)
    return rc;
  if ((rc = check_bootstrap_admin_same_subject_is_idempotent ()) != 0)
    return rc;
  if ((rc = check_bootstrap_admin_different_subject_is_refused ()) != 0)
    return rc;
  if ((rc = check_bootstrap_admin_rejects_empty_subject ()) != 0)
    return rc;
  if ((rc = check_bootstrap_admin_rejects_whitespace_subject ()) != 0)
    return rc;
  if ((rc = check_bootstrap_admin_rejects_overlong_subject ()) != 0)
    return rc;
  if ((rc = check_bootstrap_admin_seal_survives_reopen ()) != 0)
    return rc;
  if ((rc = check_bootstrap_admin_legacy_skip_migration ()) != 0)
    return rc;
  if ((rc = check_bootstrap_admin_allow_skip_mfa_flag ()) != 0)
    return rc;
  return 0;
}

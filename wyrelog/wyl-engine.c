/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>

#include <sodium.h>

#include "wyrelog/wyrelog.h"
#include "wyl-engine-private.h"
#include "wyl-common-private.h"

G_STATIC_ASSERT (sizeof (gint64) == sizeof (int64_t));
G_STATIC_ASSERT (sizeof (gint32) == sizeof (int32_t));

/*
 * Fixed dependency order for policy template files.
 *
 * The order is load-bearing: later files may reference relations declared
 * in earlier files. Do not reorder without updating the dependency analysis.
 */
static const char *const TEMPLATE_FILES[] = {
  "bootstrap.dl",
  "fsm/principal.dl",
  "fsm/session.dl",
  "fsm/permission_scope.dl",
  "lobac/decision.dl",
};

G_STATIC_ASSERT (G_N_ELEMENTS (TEMPLATE_FILES) == WYL_ENGINE_TEMPLATE_COUNT);

#define WYL_ENGINE_LOBAC_DECISION_TEMPLATE "lobac/decision.dl"
#define WYL_ENGINE_LEGACY_DECISION_TEMPLATE "decision.dl"
#define WYL_ENGINE_TEMPLATE_MANIFEST "manifest.ini"
#define WYL_ENGINE_TEMPLATE_SIGNATURE_CONTEXT "wyrelog-template-v0-sha256"
#define WYL_ENGINE_TEMPLATE_MIGRATION_DIR "migrations"
#define WYL_ENGINE_TEMPLATE_MIGRATION_SIGNATURE_CONTEXT \
  "wyrelog-template-migration-v0-sha256"

typedef struct
{
  WylTupleCallback cb;
  gpointer user_data;
} wyl_engine_tuple_cookie_t;

struct _WylDeltaCookie
{
  WylDeltaCallback callback;
  gpointer user_data;
};

static void
wyl_engine_tuple_trampoline (const char *relation, const int64_t *row,
    uint32_t ncols, void *user)
{
  const wyl_engine_tuple_cookie_t *cookie = user;

  cookie->cb (relation, (const gint64 *) row, (guint) ncols, cookie->user_data);
}

static gboolean
relation_emits_delta_callback (const char *relation)
{
  if (g_strcmp0 (relation, "guard_row") == 0
      || g_strcmp0 (relation, "guard_cmp_row") == 0
      || g_strcmp0 (relation, "guard_and_row") == 0
      || g_strcmp0 (relation, "perm_window_guard") == 0
      || g_strcmp0 (relation, "perm_window_guard_observed") == 0)
    return FALSE;

  return TRUE;
}

static wyrelog_error_t
decode_hex_field (const gchar *field_name, const gchar *hex, guint8 *out,
    gsize out_len)
{
  if (hex == NULL || out == NULL || out_len == 0)
    return WYRELOG_E_POLICY;

  gsize parsed_len = 0;
  if (sodium_hex2bin (out, out_len, hex, strlen (hex), NULL, &parsed_len,
          NULL) != 0 || parsed_len != out_len) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "template manifest has invalid %s hex", field_name);
    return WYRELOG_E_POLICY;
  }
  return WYRELOG_E_OK;
}

static void
hash_template_source_canonical (guint8 out_hash[crypto_hash_sha256_BYTES],
    const gchar *dl_src, gsize dl_src_len)
{
  crypto_hash_sha256_state state;

  crypto_hash_sha256_init (&state);
  for (gsize i = 0; i < dl_src_len; i++) {
    const guint8 c = (const guint8) dl_src[i];
    if (c != '\r')
      crypto_hash_sha256_update (&state, &c, 1);
  }
  crypto_hash_sha256_final (&state, out_hash);
}

static gchar *
hex_encode (const guint8 *data, gsize len)
{
  gchar *hex = g_malloc0 ((len * 2) + 1);
  sodium_bin2hex (hex, (len * 2) + 1, data, len);
  return hex;
}

static gchar *
canonical_migration_payload (const gchar *id, guint64 sequence,
    guint64 from_version, guint64 to_version, const gchar *semantics,
    const gchar *operation, const gchar *reserved_namespace)
{
  return g_strdup_printf ("id=%s\nsequence=%" G_GUINT64_FORMAT
      "\nfrom_version=%" G_GUINT64_FORMAT "\nto_version=%" G_GUINT64_FORMAT
      "\nsemantics=%s\noperation=%s\n" "reserved_namespace=%s\n", id, sequence,
      from_version, to_version, semantics, operation, reserved_namespace);
}

static gboolean
migration_operation_is_append_only (const gchar *operation)
{
  return g_strcmp0 (operation, "baseline") == 0
      || g_strcmp0 (operation, "additive") == 0
      || g_strcmp0 (operation, "supersession") == 0;
}

static gint
compare_string_ptr (gconstpointer a, gconstpointer b)
{
  const gchar *const *sa = a;
  const gchar *const *sb = b;
  return g_strcmp0 (*sa, *sb);
}

static wyrelog_error_t
verify_migration_artifact (const gchar *path, const gchar *name,
    guint32 expected_sequence, guint32 expected_from_version,
    GHashTable *seen_ids, GHashTable *seen_sequences, guint32 *to_version_out)
{
  g_autoptr (GKeyFile) key_file = g_key_file_new ();
  g_autoptr (GError) error = NULL;
  if (!g_key_file_load_from_file (key_file, path, G_KEY_FILE_NONE, &error)) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "unreadable template migration artifact: %s", name);
    return WYRELOG_E_IO;
  }

  gint64 sequence = g_key_file_get_int64 (key_file, "migration", "sequence",
      &error);
  if (error != NULL || sequence < 0 || sequence > G_MAXUINT32
      || (guint32) sequence != expected_sequence) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "template migration artifact has invalid sequence: %s", name);
    return WYRELOG_E_POLICY;
  }

  gchar expected_prefix[16];
  g_snprintf (expected_prefix, sizeof expected_prefix, "%04u-",
      (guint) expected_sequence);
  if (!g_str_has_prefix (name, expected_prefix)) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "template migration artifact order does not match filename: %s", name);
    return WYRELOG_E_POLICY;
  }

  g_autofree gchar *id = g_key_file_get_string (key_file, "migration", "id",
      &error);
  if (error != NULL || id == NULL || id[0] == '\0') {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "template migration artifact has invalid id: %s", name);
    return WYRELOG_E_POLICY;
  }

  if (g_hash_table_contains (seen_ids, id)
      || g_hash_table_contains (seen_sequences, GUINT_TO_POINTER ((guint)
              sequence))) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "template migration artifact is duplicated: %s", name);
    return WYRELOG_E_POLICY;
  }

  gint64 from_version = g_key_file_get_int64 (key_file, "migration",
      "from_version", &error);
  if (error != NULL || from_version < 0 || from_version > G_MAXUINT32
      || (guint32) from_version != expected_from_version) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "template migration artifact has invalid from_version: %s", name);
    return WYRELOG_E_POLICY;
  }

  gint64 to_version = g_key_file_get_int64 (key_file, "migration",
      "to_version", &error);
  if (error != NULL || to_version < from_version || to_version > G_MAXUINT32) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "template migration artifact has invalid to_version: %s", name);
    return WYRELOG_E_POLICY;
  }

  g_autofree gchar *semantics = g_key_file_get_string (key_file, "migration",
      "semantics", &error);
  if (error != NULL || g_strcmp0 (semantics, "append-only") != 0) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "template migration artifact rejects append-only semantics: %s", name);
    return WYRELOG_E_POLICY;
  }

  g_autofree gchar *operation = g_key_file_get_string (key_file, "migration",
      "operation", &error);
  if (error != NULL || !migration_operation_is_append_only (operation)) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "template migration artifact has non append-only operation: %s", name);
    return WYRELOG_E_POLICY;
  }

  g_autofree gchar *reserved_namespace = g_key_file_get_string (key_file,
      "migration", "reserved_namespace", &error);
  if (error != NULL || g_strcmp0 (reserved_namespace, "wr.") != 0) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "template migration artifact violates reserved namespace: %s", name);
    return WYRELOG_E_POLICY;
  }

  g_autofree gchar *hash_hex = g_key_file_get_string (key_file, "migration",
      "sha256", &error);
  g_autofree gchar *public_key_hex = g_key_file_get_string (key_file,
      "signature", "public_key", &error);
  g_autofree gchar *signature_hex = g_key_file_get_string (key_file,
      "signature", "ed25519", &error);
  if (error != NULL) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "template migration artifact is missing signed identity: %s", name);
    return WYRELOG_E_POLICY;
  }

  guint8 expected_hash[crypto_hash_sha256_BYTES];
  wyrelog_error_t rc = decode_hex_field ("migration sha256", hash_hex,
      expected_hash, sizeof expected_hash);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *payload = canonical_migration_payload (id,
      (guint64) sequence, (guint64) from_version, (guint64) to_version,
      semantics, operation, reserved_namespace);
  guint8 actual_hash[crypto_hash_sha256_BYTES];
  crypto_hash_sha256 (actual_hash, (const guint8 *) payload, strlen (payload));
  if (sodium_memcmp (actual_hash, expected_hash, sizeof actual_hash) != 0) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "template migration artifact hash mismatch: %s", name);
    return WYRELOG_E_POLICY;
  }

  guint8 public_key[crypto_sign_PUBLICKEYBYTES];
  rc = decode_hex_field ("migration public_key", public_key_hex, public_key,
      sizeof public_key);
  if (rc != WYRELOG_E_OK)
    return rc;
  guint8 signature[crypto_sign_BYTES];
  rc = decode_hex_field ("migration ed25519", signature_hex, signature,
      sizeof signature);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autoptr (GByteArray) signed_payload = g_byte_array_new ();
  g_byte_array_append (signed_payload,
      (const guint8 *) WYL_ENGINE_TEMPLATE_MIGRATION_SIGNATURE_CONTEXT,
      strlen (WYL_ENGINE_TEMPLATE_MIGRATION_SIGNATURE_CONTEXT));
  g_byte_array_append (signed_payload, actual_hash, sizeof actual_hash);
  if (crypto_sign_verify_detached (signature, signed_payload->data,
          signed_payload->len, public_key) != 0) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "template migration artifact signature verification failed: %s", name);
    return WYRELOG_E_CRYPTO;
  }

  g_hash_table_add (seen_ids, g_strdup (id));
  g_hash_table_add (seen_sequences, GUINT_TO_POINTER ((guint) sequence));
  *to_version_out = (guint32) to_version;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
verify_template_migrations (const gchar *template_dir,
    const gchar *migration_path, guint32 template_version,
    guint32 *migration_count_out, guint32 *latest_migration_version_out)
{
  *migration_count_out = 0;
  *latest_migration_version_out = template_version;

  if (migration_path == NULL || migration_path[0] == '\0')
    return WYRELOG_E_OK;
  if (g_path_is_absolute (migration_path)
      || strstr (migration_path, "..") != NULL) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "template manifest has invalid migration path");
    return WYRELOG_E_POLICY;
  }

  g_autofree gchar *dir_path = g_build_filename (template_dir,
      migration_path, NULL);
  g_autoptr (GDir) dir = g_dir_open (dir_path, 0, NULL);
  if (dir == NULL) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "missing template migration directory: %s", migration_path);
    return WYRELOG_E_POLICY;
  }

  g_autoptr (GPtrArray) names = g_ptr_array_new_with_free_func (g_free);
  const gchar *entry = NULL;
  while ((entry = g_dir_read_name (dir)) != NULL) {
    if (g_str_has_suffix (entry, ".ini"))
      g_ptr_array_add (names, g_strdup (entry));
  }
  if (names->len == 0) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "template migration directory is empty: %s", migration_path);
    return WYRELOG_E_POLICY;
  }
  g_ptr_array_sort (names, compare_string_ptr);

  g_autoptr (GHashTable) seen_ids = g_hash_table_new_full (g_str_hash,
      g_str_equal, g_free, NULL);
  g_autoptr (GHashTable) seen_sequences = g_hash_table_new (g_direct_hash,
      g_direct_equal);
  guint32 expected_from_version = template_version;
  for (guint i = 0; i < names->len; i++) {
    const gchar *name = g_ptr_array_index (names, i);
    g_autofree gchar *path = g_build_filename (dir_path, name, NULL);
    guint32 to_version = 0;
    wyrelog_error_t rc = verify_migration_artifact (path, name, i,
        expected_from_version, seen_ids, seen_sequences, &to_version);
    if (rc != WYRELOG_E_OK)
      return rc;
    expected_from_version = to_version;
  }

  *migration_count_out = names->len;
  *latest_migration_version_out = expected_from_version;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_engine_inspect_template_artifact (const gchar *template_dir,
    const gchar *dl_src, gsize dl_src_len, gboolean require_manifest,
    WylTemplateArtifactInfo *info_out)
{
  if (info_out != NULL)
    memset (info_out, 0, sizeof *info_out);

  if (template_dir == NULL || dl_src == NULL)
    return WYRELOG_E_INVALID;

  if (sodium_init () < 0)
    return WYRELOG_E_CRYPTO;

  g_autofree gchar *manifest_path =
      g_build_filename (template_dir, WYL_ENGINE_TEMPLATE_MANIFEST, NULL);
  if (!g_file_test (manifest_path, G_FILE_TEST_EXISTS)) {
    if (require_manifest) {
      WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
          "missing required template manifest: %s",
          WYL_ENGINE_TEMPLATE_MANIFEST);
      return WYRELOG_E_POLICY;
    }
    return WYRELOG_E_OK;
  }

  g_autoptr (GKeyFile) key_file = g_key_file_new ();
  g_autoptr (GError) error = NULL;
  if (!g_key_file_load_from_file (key_file, manifest_path,
          G_KEY_FILE_NONE, &error)) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT, "unreadable template manifest");
    return WYRELOG_E_IO;
  }

  gint64 version = g_key_file_get_int64 (key_file, "template",
      "version", &error);
  if (error != NULL || version < 0 || version > G_MAXUINT32) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "template manifest has invalid version");
    return WYRELOG_E_POLICY;
  }

  g_autofree gchar *migration_semantics = g_key_file_get_string (key_file,
      "template", "migration_semantics", &error);
  if (error != NULL || g_strcmp0 (migration_semantics, "append-only") != 0) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "template manifest rejects non append-only migration semantics");
    return WYRELOG_E_POLICY;
  }

  g_autofree gchar *migration_path = g_key_file_get_string (key_file,
      "template", "migration_path", NULL);
  g_autofree gchar *hash_hex = g_key_file_get_string (key_file, "template",
      "sha256", &error);
  if (error != NULL) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT, "template manifest is missing sha256");
    return WYRELOG_E_POLICY;
  }

  g_autofree gchar *public_key_hex = g_key_file_get_string (key_file,
      "signature", "public_key", &error);
  if (error != NULL) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "template manifest is missing signature public key");
    return WYRELOG_E_POLICY;
  }

  g_autofree gchar *signature_hex = g_key_file_get_string (key_file,
      "signature", "ed25519", &error);
  if (error != NULL) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "template manifest is missing Ed25519 signature");
    return WYRELOG_E_POLICY;
  }

  guint8 expected_hash[crypto_hash_sha256_BYTES];
  wyrelog_error_t rc = decode_hex_field ("sha256", hash_hex, expected_hash,
      sizeof expected_hash);
  if (rc != WYRELOG_E_OK)
    return rc;

  guint8 public_key[crypto_sign_PUBLICKEYBYTES];
  rc = decode_hex_field ("public_key", public_key_hex, public_key,
      sizeof public_key);
  if (rc != WYRELOG_E_OK)
    return rc;

  guint8 signature[crypto_sign_BYTES];
  rc = decode_hex_field ("ed25519", signature_hex, signature, sizeof signature);
  if (rc != WYRELOG_E_OK)
    return rc;

  guint8 actual_hash[crypto_hash_sha256_BYTES];
  hash_template_source_canonical (actual_hash, dl_src, dl_src_len);
  if (sodium_memcmp (actual_hash, expected_hash, sizeof actual_hash) != 0) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "template manifest hash does not match loaded templates");
    return WYRELOG_E_POLICY;
  }

  g_autoptr (GByteArray) signed_payload = g_byte_array_new ();
  g_byte_array_append (signed_payload,
      (const guint8 *) WYL_ENGINE_TEMPLATE_SIGNATURE_CONTEXT,
      strlen (WYL_ENGINE_TEMPLATE_SIGNATURE_CONTEXT));
  g_byte_array_append (signed_payload, actual_hash, sizeof actual_hash);
  if (crypto_sign_verify_detached (signature, signed_payload->data,
          signed_payload->len, public_key) != 0) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "template manifest signature verification failed");
    return WYRELOG_E_CRYPTO;
  }

  guint32 migration_count = 0;
  guint32 latest_migration_version = 0;
  rc = verify_template_migrations (template_dir, migration_path,
      (guint32) version, &migration_count, &latest_migration_version);
  if (rc != WYRELOG_E_OK)
    return rc;

  if (info_out != NULL) {
    info_out->version = (guint32) version;
    info_out->migration_count = migration_count;
    info_out->latest_migration_version = latest_migration_version;
    g_autofree gchar *actual_hash_hex = hex_encode (actual_hash,
        sizeof actual_hash);
    g_strlcpy (info_out->sha256_hex, actual_hash_hex,
        sizeof info_out->sha256_hex);
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_engine_verify_template_manifest (const gchar *template_dir,
    const gchar *dl_src, gsize dl_src_len, gboolean require_manifest,
    guint32 *template_version_out)
{
  WylTemplateArtifactInfo info = { 0 };
  wyrelog_error_t rc = wyl_engine_inspect_template_artifact (template_dir,
      dl_src, dl_src_len, require_manifest, &info);
  if (rc == WYRELOG_E_OK && template_version_out != NULL)
    *template_version_out = info.version;
  return rc;
}

static void
wyl_engine_delta_trampoline (const char *relation, const int64_t *row,
    uint32_t ncols, int32_t diff, void *user)
{
  const WylDeltaCookie *cookie = user;
  WylDeltaKind kind;

  if (!relation_emits_delta_callback (relation))
    return;

  if (diff == 1) {
    kind = WYL_DELTA_INSERT;
  } else if (diff == -1) {
    kind = WYL_DELTA_REMOVE;
  } else {
    WYL_LOG_ERROR (WYL_LOG_SECTION_POLICY,
        "engine: unexpected delta diff value (skipping callback)");
    return;
  }

  cookie->callback (relation, (const gint64 *) row, (guint) ncols, kind,
      cookie->user_data);
}

/* --- GObject boilerplate ------------------------------------------- */

G_DEFINE_FINAL_TYPE (WylEngine, wyl_engine, G_TYPE_OBJECT);

void
wyl_engine_set_owner (WylEngine *self, wyl_engine_owner_t owner)
{
  g_return_if_fail (WYL_IS_ENGINE (self));

  self->owner = owner;
}

static void
wyl_engine_finalize (GObject *object)
{
  WylEngine *self = WYL_ENGINE (object);

  g_clear_pointer (&self->session, wirelog_easy_close);
  g_clear_pointer (&self->delta_cookie, g_free);
  g_clear_pointer (&self->symbols_by_id, g_hash_table_unref);

  for (gsize i = 0; i < WYL_ENGINE_TEMPLATE_COUNT; i++)
    g_clear_pointer (&self->dl_src_logical_paths[i], g_free);

  G_OBJECT_CLASS (wyl_engine_parent_class)->finalize (object);
}

static void
wyl_engine_class_init (WylEngineClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = wyl_engine_finalize;
}

static void
wyl_engine_init (WylEngine *self)
{
  self->session = NULL;
  self->symbols_by_id =
      g_hash_table_new_full (g_int64_hash, g_int64_equal, g_free, g_free);
  self->mode = WYL_ENGINE_MODE_NONE;
  for (gsize i = 0; i < WYL_ENGINE_TEMPLATE_COUNT; i++)
    self->dl_src_logical_paths[i] = NULL;
}

/* --- Internal helpers --------------------------------------------- */

wyrelog_error_t
wyl_engine_map_wirelog_error (wirelog_error_t wl_err)
{
  switch (wl_err) {
    case WIRELOG_OK:
      return WYRELOG_E_OK;
    case WIRELOG_ERR_PARSE:
    case WIRELOG_ERR_INVALID_IR:
      return WYRELOG_E_POLICY;
    case WIRELOG_ERR_EXEC:
      return WYRELOG_E_EXEC;
    case WIRELOG_ERR_MEMORY:
      return WYRELOG_E_NOMEM;
    case WIRELOG_ERR_IO:
      return WYRELOG_E_IO;
    case WIRELOG_ERR_COMPOUND_SATURATED:
    case WIRELOG_ERR_COMPOUND_BUSY:
      return WYRELOG_E_EXEC;
    case WIRELOG_ERR_UNKNOWN:
      return WYRELOG_E_INTERNAL;
    default:
      return WYRELOG_E_INTERNAL;
  }
}

static wyrelog_error_t
load_templates_internal (const gchar *template_dir,
    gboolean require_template_manifest, gchar **dl_src_out,
    gsize *dl_src_len_out)
{
  g_autoptr (GString) combined = g_string_new (NULL);
  gsize total_content_bytes = 0;

  for (gsize i = 0; i < G_N_ELEMENTS (TEMPLATE_FILES); i++) {
    const gchar *logical_path = TEMPLATE_FILES[i];
    g_autofree gchar *path =
        g_build_filename (template_dir, logical_path, NULL);
    g_autofree gchar *contents = NULL;
    gsize len = 0;
    g_autoptr (GError) err = NULL;

    if (!g_file_get_contents (path, &contents, &len, &err)) {
      if (g_strcmp0 (logical_path, WYL_ENGINE_LOBAC_DECISION_TEMPLATE) == 0
          && g_error_matches (err, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
        g_clear_error (&err);
        g_clear_pointer (&path, g_free);
        path = g_build_filename (template_dir,
            WYL_ENGINE_LEGACY_DECISION_TEMPLATE, NULL);
        logical_path = WYL_ENGINE_LEGACY_DECISION_TEMPLATE;
        if (g_file_get_contents (path, &contents, &len, &err)) {
          WYL_LOG_INFO (WYL_LOG_SECTION_BOOT,
              "loaded legacy decision template: %s", logical_path);
        }
      }
    }

    if (contents == NULL) {
      WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
          "missing or unreadable template: %s", TEMPLATE_FILES[i]);
      return WYRELOG_E_IO;
    }

    /* Insert newline between files unconditionally for concat-boundary safety. */
    if (i > 0)
      g_string_append_c (combined, '\n');

    g_string_append_len (combined, contents, (gssize) len);
    total_content_bytes += len;
  }

  /* In-tree invariant: the 5 template files must collectively contain at
   * least one byte of policy content.  A zero total means all files are
   * empty, which is a wyrelog-side invariant violation (not operator-authored
   * bad policy).  Separator newlines inserted above are not counted. */
  if (total_content_bytes == 0) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "engine: invariant violated — in-tree templates produced zero bytes");
    return WYRELOG_E_INTERNAL;
  }

  wyrelog_error_t rc = wyl_engine_verify_template_manifest (template_dir,
      combined->str, combined->len, require_template_manifest,
      NULL);
  if (rc != WYRELOG_E_OK)
    return rc;

  /* Capture the authoritative byte count before transferring ownership of the
   * underlying buffer.  strlen() must not be used for the subsequent memset
   * because it short-circuits at the first embedded NUL byte. */
  *dl_src_len_out = combined->len;
  *dl_src_out = g_string_free (g_steal_pointer (&combined), FALSE);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_engine_load_templates (const gchar *template_dir, gchar **dl_src_out,
    gsize *dl_src_len_out)
{
  return load_templates_internal (template_dir,
#ifdef WYL_REQUIRE_TEMPLATE_MANIFEST
      TRUE,
#else
      FALSE,
#endif
      dl_src_out, dl_src_len_out);
}

/* --- Public API ---------------------------------------------------- */

wyrelog_error_t
wyl_engine_open_with_options (const gchar *template_dir, guint32 num_workers,
    gboolean require_template_manifest, WylEngine **out)
{
  /* Set out-param to NULL at entry; every failure path leaves it NULL. */
  if (out != NULL)
    *out = NULL;

  if (out == NULL)
    return WYRELOG_E_INVALID;

  if (template_dir == NULL)
    return WYRELOG_E_INVALID;

  gchar *dl_src = NULL;
  gsize dl_src_len = 0;
  wyrelog_error_t rc = load_templates_internal (template_dir,
      require_template_manifest, &dl_src, &dl_src_len);
  if (rc != WYRELOG_E_OK)
    return rc;

  wirelog_easy_open_opts_t opts = {
    .size = sizeof (opts),
    .num_workers = num_workers,
    .eager_build = true,
    ._reserved = NULL,
  };

  wirelog_easy_session_t *session = NULL;
  wirelog_error_t wl_rc = wirelog_easy_open_opts (dl_src, &opts, &session);

  /* FC4: zero-fill the policy source buffer before freeing to avoid leaving
   * policy text in core dumps or swap.  Use the tracked length rather than
   * strlen() to ensure every byte — including any tail past an embedded NUL —
   * is overwritten. */
  memset (dl_src, 0, dl_src_len);
  g_free (dl_src);
  dl_src = NULL;

  if (wl_rc != WIRELOG_OK) {
    /* wirelog_easy_open_opts sets *out to NULL on error per its contract,
     * but be defensive: close any partial session that may have been
     * returned despite the error. */
    if (session != NULL)
      wirelog_easy_close (session);
    return wyl_engine_map_wirelog_error (wl_rc);
  }

  WylEngine *engine = g_object_new (WYL_TYPE_ENGINE, NULL);
  engine->session = session;
  /* Keep the initial mode explicit instead of relying on zero-fill. */
  engine->mode = WYL_ENGINE_MODE_NONE;

  /* Store logical paths for diagnostic logging. */
  for (gsize i = 0; i < WYL_ENGINE_TEMPLATE_COUNT; i++)
    engine->dl_src_logical_paths[i] = g_strdup (TEMPLATE_FILES[i]);

  *out = engine;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_engine_open (const gchar *template_dir, guint32 num_workers,
    WylEngine **out)
{
  return wyl_engine_open_with_options (template_dir, num_workers,
#ifdef WYL_REQUIRE_TEMPLATE_MANIFEST
      TRUE,
#else
      FALSE,
#endif
      out);
}

wyrelog_error_t
wyl_engine_open_source (const gchar *dl_src, guint32 num_workers,
    WylEngine **out)
{
  if (out != NULL)
    *out = NULL;
  if (dl_src == NULL || out == NULL)
    return WYRELOG_E_INVALID;

  wirelog_easy_open_opts_t opts = {
    .size = sizeof (wirelog_easy_open_opts_t),
    .num_workers = num_workers > 0 ? num_workers : 1,
    .eager_build = true,
    ._reserved = NULL,
  };
  wirelog_easy_session_t *session = NULL;
  wirelog_error_t wl_rc = wirelog_easy_open_opts (dl_src, &opts, &session);
  if (wl_rc != WIRELOG_OK) {
    if (session != NULL)
      wirelog_easy_close (session);
    return wyl_engine_map_wirelog_error (wl_rc);
  }

  WylEngine *engine = g_object_new (WYL_TYPE_ENGINE, NULL);
  engine->session = session;
  engine->mode = WYL_ENGINE_MODE_NONE;
  *out = engine;
  return WYRELOG_E_OK;
}

void
wyl_engine_close (WylEngine *engine)
{
  if (engine == NULL)
    return;
  g_object_unref (engine);
}

static wyrelog_error_t
wyl_engine_intern_symbol_unchecked (WylEngine *self, const gchar *symbol,
    gint64 *out_id)
{
  if (self == NULL || !WYL_IS_ENGINE (self))
    return WYRELOG_E_INVALID;
  if (symbol == NULL || out_id == NULL)
    return WYRELOG_E_INVALID;
  if (self->session == NULL)
    return WYRELOG_E_INVALID;

  int64_t id = wirelog_easy_intern (self->session, symbol);
  if (id < 0) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_POLICY,
        "engine: symbol interning failed for symbol of length %zu",
        strlen (symbol));
    return WYRELOG_E_INTERNAL;
  }

  gint64 *key = g_new (gint64, 1);
  *key = id;
  g_hash_table_replace (self->symbols_by_id, key, g_strdup (symbol));

  *out_id = id;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_engine_intern_symbol (WylEngine *self, const gchar *symbol, gint64 *out_id)
{
  if (self == NULL || !WYL_IS_ENGINE (self))
    return WYRELOG_E_INVALID;
  if (self->owner != WYL_ENGINE_OWNER_STANDALONE)
    return WYRELOG_E_INVALID;

  return wyl_engine_intern_symbol_unchecked (self, symbol, out_id);
}

wyrelog_error_t
wyl_engine_owned_intern_symbol (WylEngine *self, const gchar *symbol,
    gint64 *out_id)
{
  return wyl_engine_intern_symbol_unchecked (self, symbol, out_id);
}

gchar *
wyl_engine_owned_dup_interned_symbol (WylEngine *self, gint64 id)
{
  if (self == NULL || !WYL_IS_ENGINE (self) || self->symbols_by_id == NULL)
    return NULL;
  const gchar *symbol = g_hash_table_lookup (self->symbols_by_id, &id);
  return g_strdup (symbol);
}

static wyrelog_error_t
wyl_engine_make_compound_unchecked (WylEngine *self, const gchar *functor,
    const wirelog_compound_arg_t *args, gsize nargs, gint64 *out_id)
{
  if (out_id != NULL)
    *out_id = (gint64) WIRELOG_COMPOUND_HANDLE_NULL;

  if (self == NULL || !WYL_IS_ENGINE (self))
    return WYRELOG_E_INVALID;
  if (functor == NULL || functor[0] == '\0' || args == NULL || out_id == NULL)
    return WYRELOG_E_INVALID;
  if (nargs == 0 || nargs > G_MAXUINT32)
    return WYRELOG_E_INVALID;
  if (self->session == NULL)
    return WYRELOG_E_INVALID;

  uint64_t handle = WIRELOG_COMPOUND_HANDLE_NULL;
  wirelog_error_t wl_rc =
      wirelog_easy_make_compound (self->session, functor, (uint32_t) nargs,
      args, &handle);
  wyrelog_error_t rc = wyl_engine_map_wirelog_error (wl_rc);
  if (rc != WYRELOG_E_OK) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_POLICY,
        "engine: compound allocation failed for functor '%s/%" G_GSIZE_FORMAT
        "' (rc=%d)", functor, nargs, (int) rc);
    return rc;
  }

  if (handle == WIRELOG_COMPOUND_HANDLE_NULL || handle > (uint64_t) G_MAXINT64) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_POLICY,
        "engine: compound allocation returned an invalid handle");
    return WYRELOG_E_INTERNAL;
  }

  *out_id = (gint64) handle;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_engine_make_compound (WylEngine *self, const gchar *functor,
    const wirelog_compound_arg_t *args, gsize nargs, gint64 *out_id)
{
  if (self == NULL || !WYL_IS_ENGINE (self))
    return WYRELOG_E_INVALID;
  if (self->owner != WYL_ENGINE_OWNER_STANDALONE)
    return WYRELOG_E_INVALID;

  return wyl_engine_make_compound_unchecked (self, functor, args, nargs,
      out_id);
}

wyrelog_error_t
wyl_engine_owned_make_compound (WylEngine *self, const gchar *functor,
    const wirelog_compound_arg_t *args, gsize nargs, gint64 *out_id)
{
  return wyl_engine_make_compound_unchecked (self, functor, args, nargs,
      out_id);
}

static wyrelog_error_t
wyl_engine_insert_unchecked (WylEngine *self, const gchar *relation,
    const gint64 *row, gsize ncols)
{
  if (self == NULL || !WYL_IS_ENGINE (self))
    return WYRELOG_E_INVALID;
  if (relation == NULL || ncols == 0 || ncols > G_MAXUINT32)
    return WYRELOG_E_INVALID;
  if (row == NULL)
    return WYRELOG_E_INVALID;
  if (self->session == NULL)
    return WYRELOG_E_INVALID;

  wirelog_error_t wl_rc =
      wirelog_easy_insert (self->session, relation, (const int64_t *) row,
      (uint32_t) ncols);
  wyrelog_error_t rc = wyl_engine_map_wirelog_error (wl_rc);
  if (rc != WYRELOG_E_OK) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_POLICY,
        "engine: insert failed for relation '%s' with %" G_GSIZE_FORMAT
        " columns", relation, ncols);
  }

  return rc;
}

wyrelog_error_t
wyl_engine_insert (WylEngine *self, const gchar *relation, const gint64 *row,
    gsize ncols)
{
  if (self == NULL || !WYL_IS_ENGINE (self))
    return WYRELOG_E_INVALID;
  if (self->owner != WYL_ENGINE_OWNER_STANDALONE)
    return WYRELOG_E_INVALID;

  return wyl_engine_insert_unchecked (self, relation, row, ncols);
}

wyrelog_error_t
wyl_engine_owned_insert (WylEngine *self, const gchar *relation,
    const gint64 *row, gsize ncols)
{
  return wyl_engine_insert_unchecked (self, relation, row, ncols);
}

static wyrelog_error_t
wyl_engine_step_unchecked (WylEngine *self)
{
  if (self == NULL || !WYL_IS_ENGINE (self))
    return WYRELOG_E_INVALID;
  if (self->session == NULL)
    return WYRELOG_E_INVALID;
  if (self->mode == WYL_ENGINE_MODE_SNAPSHOT)
    return WYRELOG_E_INVALID;

  wirelog_error_t wl_rc = wirelog_easy_step (self->session);
  wyrelog_error_t rc = wyl_engine_map_wirelog_error (wl_rc);
  if (rc == WYRELOG_E_OK) {
    self->mode = WYL_ENGINE_MODE_STEP;
  } else {
    WYL_LOG_ERROR (WYL_LOG_SECTION_POLICY,
        "engine: step failed (rc=%d)", (int) rc);
  }

  return rc;
}

wyrelog_error_t
wyl_engine_step (WylEngine *self)
{
  if (self == NULL || !WYL_IS_ENGINE (self))
    return WYRELOG_E_INVALID;
  if (self->owner != WYL_ENGINE_OWNER_STANDALONE)
    return WYRELOG_E_INVALID;

  return wyl_engine_step_unchecked (self);
}

wyrelog_error_t
wyl_engine_owned_step (WylEngine *self)
{
  return wyl_engine_step_unchecked (self);
}

wyrelog_error_t
wyl_engine_snapshot (WylEngine *self, const gchar *relation,
    WylTupleCallback cb, gpointer user_data)
{
  if (self == NULL || !WYL_IS_ENGINE (self))
    return WYRELOG_E_INVALID;
  if (relation == NULL || cb == NULL)
    return WYRELOG_E_INVALID;
  if (self->session == NULL)
    return WYRELOG_E_INVALID;
  if (self->owner == WYL_ENGINE_OWNER_DELTA)
    return WYRELOG_E_INVALID;
  if (self->mode == WYL_ENGINE_MODE_STEP)
    return WYRELOG_E_INVALID;

  wyl_engine_tuple_cookie_t cookie = { cb, user_data };
  wirelog_error_t wl_rc = wirelog_easy_snapshot (self->session, relation,
      wyl_engine_tuple_trampoline,
      &cookie);
  wyrelog_error_t rc = wyl_engine_map_wirelog_error (wl_rc);
  if (rc == WYRELOG_E_OK) {
    self->mode = WYL_ENGINE_MODE_SNAPSHOT;
  } else {
    WYL_LOG_ERROR (WYL_LOG_SECTION_POLICY,
        "engine: snapshot failed for relation '%s' (rc=%d)", relation,
        (int) rc);
  }

  return rc;
}

static wyrelog_error_t
wyl_engine_set_delta_callback_unchecked (WylEngine *self, WylDeltaCallback cb,
    gpointer user_data)
{
  if (self == NULL || !WYL_IS_ENGINE (self))
    return WYRELOG_E_INVALID;
  if (self->session == NULL)
    return WYRELOG_E_INVALID;
  if (self->mode == WYL_ENGINE_MODE_SNAPSHOT)
    return WYRELOG_E_INVALID;

  if (cb == NULL) {
    /* Clear the substrate hook before releasing the cookie it may reference. */
    wirelog_error_t wl_rc =
        wirelog_easy_set_delta_cb (self->session, NULL, NULL);
    wyrelog_error_t rc = wyl_engine_map_wirelog_error (wl_rc);
    if (rc != WYRELOG_E_OK) {
      WYL_LOG_ERROR (WYL_LOG_SECTION_POLICY,
          "engine: clear delta callback failed (rc=%d)", (int) rc);
      return rc;
    }

    g_clear_pointer (&self->delta_cookie, g_free);
    return WYRELOG_E_OK;
  }

  WylDeltaCookie *new_cookie = g_new0 (WylDeltaCookie, 1);
  new_cookie->callback = cb;
  new_cookie->user_data = user_data;

  wirelog_error_t wl_rc =
      wirelog_easy_set_delta_cb (self->session, wyl_engine_delta_trampoline,
      new_cookie);
  wyrelog_error_t rc = wyl_engine_map_wirelog_error (wl_rc);
  if (rc != WYRELOG_E_OK) {
    g_free (new_cookie);
    WYL_LOG_ERROR (WYL_LOG_SECTION_POLICY,
        "engine: install delta callback failed (rc=%d)", (int) rc);
    return rc;
  }

  WylDeltaCookie *old = self->delta_cookie;
  self->delta_cookie = new_cookie;
  g_free (old);

  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_engine_set_delta_callback (WylEngine *self, WylDeltaCallback cb,
    gpointer user_data)
{
  if (self == NULL || !WYL_IS_ENGINE (self))
    return WYRELOG_E_INVALID;
  if (self->owner != WYL_ENGINE_OWNER_STANDALONE)
    return WYRELOG_E_INVALID;

  return wyl_engine_set_delta_callback_unchecked (self, cb, user_data);
}

wyrelog_error_t
wyl_engine_owned_set_delta_callback (WylEngine *self, WylDeltaCallback cb,
    gpointer user_data)
{
  return wyl_engine_set_delta_callback_unchecked (self, cb, user_data);
}

static wyrelog_error_t
wyl_engine_remove_unchecked (WylEngine *self, const gchar *relation,
    const gint64 *row, gsize ncols)
{
  if (self == NULL || !WYL_IS_ENGINE (self))
    return WYRELOG_E_INVALID;
  if (relation == NULL || ncols == 0 || ncols > G_MAXUINT32)
    return WYRELOG_E_INVALID;
  if (row == NULL)
    return WYRELOG_E_INVALID;
  if (self->session == NULL)
    return WYRELOG_E_INVALID;

  wirelog_error_t wl_rc =
      wirelog_easy_remove (self->session, relation, (const int64_t *) row,
      (uint32_t) ncols);
  wyrelog_error_t rc = wyl_engine_map_wirelog_error (wl_rc);
  if (rc != WYRELOG_E_OK) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_POLICY,
        "engine: remove failed for relation '%s' with %" G_GSIZE_FORMAT
        " columns", relation, ncols);
  }

  return rc;
}

wyrelog_error_t
wyl_engine_remove (WylEngine *self, const gchar *relation, const gint64 *row,
    gsize ncols)
{
  if (self == NULL || !WYL_IS_ENGINE (self))
    return WYRELOG_E_INVALID;
  if (self->owner != WYL_ENGINE_OWNER_STANDALONE)
    return WYRELOG_E_INVALID;

  return wyl_engine_remove_unchecked (self, relation, row, ncols);
}

wyrelog_error_t
wyl_engine_owned_remove (WylEngine *self, const gchar *relation,
    const gint64 *row, gsize ncols)
{
  return wyl_engine_remove_unchecked (self, relation, row, ncols);
}

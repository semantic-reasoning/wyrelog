/* SPDX-License-Identifier: GPL-3.0-or-later */
#if defined(__unix__) || defined(__APPLE__)
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#endif

#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>

#ifndef G_OS_WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "wyrelog/policy/service-permission-maintenance-private.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-request-id-private.h"

/* A canonical request id generated once for the whole suite. */
static gchar g_request_id[WYL_REQUEST_ID_STRING_BUF];

static WylPolicyPermissionClosureRemoval *
make_removal (WylPolicyPermissionClosureRemovalAction action,
    const gchar *subject, const gchar *right, const gchar *scope)
{
  WylPolicyPermissionClosureRemoval *removal =
      g_new0 (WylPolicyPermissionClosureRemoval, 1);
  removal->action = action;
  removal->reason = WYL_POLICY_PERMISSION_CLOSURE_UNSAFE_PERMISSION;
  removal->subject_id = g_strdup (subject);
  removal->right_id = g_strdup (right);
  removal->scope = g_strdup (scope);
  return removal;
}

static void
fill_digest (guint8 digest[32])
{
  for (guint i = 0; i < 32; i++)
    digest[i] = (guint8) (i + 1);
}

/* Build a two-operation manifest (one of each op kind), canonically ordered:
 * revoke_direct_permission sorts before remove_service_role_membership. */
static void
make_valid_manifest (WylServicePermissionManifest *manifest)
{
  memset (manifest, 0, sizeof *manifest);
  manifest->version = 1;
  manifest->request_id = g_strdup (g_request_id);
  manifest->store_generation = 7;
  fill_digest (manifest->store_digest);
  manifest->operations = g_ptr_array_new_with_free_func
      ((GDestroyNotify) wyl_policy_permission_closure_removal_free);
  g_ptr_array_add (manifest->operations,
      make_removal (WYL_POLICY_PERMISSION_CLOSURE_REVOKE_DIRECT, "svc:alpha",
          "perm.read", "res:doc"));
  g_ptr_array_add (manifest->operations,
      make_removal (WYL_POLICY_PERMISSION_CLOSURE_REMOVE_MEMBERSHIP, "svc:beta",
          "role.admin", "res:proj"));
}

static gchar *
canonical_document (gsize *out_len)
{
  WylServicePermissionManifest manifest;
  make_valid_manifest (&manifest);
  gchar *document = NULL;
  g_assert_cmpint (wyl_service_permission_manifest_encode (&manifest, &document,
          out_len), ==, WYRELOG_E_OK);
  g_assert_nonnull (document);
  wyl_service_permission_manifest_clear (&manifest);
  return document;
}

static gchar *
str_replace (const gchar *source, const gchar *from, const gchar *to)
{
  gchar **parts = g_strsplit (source, from, -1);
  g_assert_cmpuint (g_strv_length (parts), ==, 2);      /* substring is unique */
  gchar *result = g_strjoinv (to, parts);
  g_strfreev (parts);
  return result;
}

static void
expect_decode_error (const gchar *document, wyrelog_error_t expected)
{
  WylServicePermissionManifest manifest;
  g_assert_cmpint (wyl_service_permission_manifest_decode (document,
          strlen (document), &manifest), ==, expected);
}

static void
expect_mutation_rejected (const gchar *canonical, const gchar *from,
    const gchar *to)
{
  g_autofree gchar *mutated = str_replace (canonical, from, to);
  expect_decode_error (mutated, WYRELOG_E_POLICY);
}

/* A valid manifest, and a single-op manifest of each kind, decode and then
 * re-encode to byte-identical documents. */
static void
test_round_trip (void)
{
  gsize len = 0;
  g_autofree gchar *canonical = canonical_document (&len);

  WylServicePermissionManifest decoded;
  g_assert_cmpint (wyl_service_permission_manifest_decode (canonical, len,
          &decoded), ==, WYRELOG_E_OK);
  g_assert_cmpuint (decoded.version, ==, 1);
  g_assert_cmpstr (decoded.request_id, ==, g_request_id);
  g_assert_cmpuint (decoded.store_generation, ==, 7);
  g_assert_cmpuint (decoded.operations->len, ==, 2);

  gchar *reencoded = NULL;
  gsize reencoded_len = 0;
  g_assert_cmpint (wyl_service_permission_manifest_encode (&decoded, &reencoded,
          &reencoded_len), ==, WYRELOG_E_OK);
  g_assert_cmpuint (reencoded_len, ==, len);
  g_assert_cmpint (memcmp (reencoded, canonical, len), ==, 0);
  g_free (reencoded);
  wyl_service_permission_manifest_clear (&decoded);
}

static void
round_trip_single (WylPolicyPermissionClosureRemovalAction action,
    const gchar *right)
{
  WylServicePermissionManifest manifest;
  memset (&manifest, 0, sizeof manifest);
  manifest.version = 1;
  manifest.request_id = g_strdup (g_request_id);
  manifest.store_generation = 42;
  fill_digest (manifest.store_digest);
  manifest.operations = g_ptr_array_new_with_free_func
      ((GDestroyNotify) wyl_policy_permission_closure_removal_free);
  g_ptr_array_add (manifest.operations,
      make_removal (action, "svc:solo", right, "res:only"));

  gchar *document = NULL;
  gsize len = 0;
  g_assert_cmpint (wyl_service_permission_manifest_encode (&manifest, &document,
          &len), ==, WYRELOG_E_OK);
  wyl_service_permission_manifest_clear (&manifest);

  WylServicePermissionManifest decoded;
  g_assert_cmpint (wyl_service_permission_manifest_decode (document, len,
          &decoded), ==, WYRELOG_E_OK);
  g_assert_cmpuint (decoded.operations->len, ==, 1);
  const WylPolicyPermissionClosureRemoval *op =
      g_ptr_array_index (decoded.operations, 0);
  g_assert_cmpint (op->action, ==, action);
  g_assert_cmpstr (op->right_id, ==, right);

  gchar *reencoded = NULL;
  gsize reencoded_len = 0;
  g_assert_cmpint (wyl_service_permission_manifest_encode (&decoded, &reencoded,
          &reencoded_len), ==, WYRELOG_E_OK);
  g_assert_cmpuint (reencoded_len, ==, len);
  g_assert_cmpint (memcmp (reencoded, document, len), ==, 0);
  g_free (reencoded);
  g_free (document);
  wyl_service_permission_manifest_clear (&decoded);
}

static void
test_round_trip_each_op (void)
{
  round_trip_single (WYL_POLICY_PERMISSION_CLOSURE_REVOKE_DIRECT, "perm.write");
  round_trip_single (WYL_POLICY_PERMISSION_CLOSURE_REMOVE_MEMBERSHIP,
      "role.editor");
}

/* Every out-of-grammar op kind is rejected before use: grant, role-permission
 * mutation, inheritance mutation, class/catalog change, arbitrary SQL. */
static void
test_reject_forbidden_ops (void)
{
  gsize len = 0;
  g_autofree gchar *canonical = canonical_document (&len);
  expect_mutation_rejected (canonical, "revoke_direct_permission",
      "grant_direct_permission");
  expect_mutation_rejected (canonical, "revoke_direct_permission",
      "set_role_permission");
  expect_mutation_rejected (canonical, "remove_service_role_membership",
      "modify_role_inheritance");
  expect_mutation_rejected (canonical, "revoke_direct_permission",
      "alter_permission_class");
  expect_mutation_rejected (canonical, "revoke_direct_permission",
      "DELETE FROM permissions");
}

/* A human (non-svc:) subject is rejected. */
static void
test_reject_human_subject (void)
{
  gsize len = 0;
  g_autofree gchar *canonical = canonical_document (&len);
  expect_mutation_rejected (canonical, "svc:alpha", "user:alpha");
}

/* Unknown, duplicate, missing, extra and mistyped fields are all rejected. */
static void
test_reject_field_defects (void)
{
  gsize len = 0;
  g_autofree gchar *canonical = canonical_document (&len);

  /* unknown / mistyped field name */
  expect_mutation_rejected (canonical, "\"permission_id\":", "\"perm_id\":");
  /* duplicate field */
  expect_mutation_rejected (canonical, "{\"version\":1,",
      "{\"version\":1,\"version\":1,");
  /* missing required field (store_generation) */
  expect_mutation_rejected (canonical, "\"store_generation\":7,", "");
  /* extra trailing field inside an operation */
  expect_mutation_rejected (canonical, "\"scope\":\"res:proj\"}",
      "\"scope\":\"res:proj\",\"extra\":\"x\"}");
  /* mistyped field type: numeric generation encoded as a string */
  expect_mutation_rejected (canonical, "\"store_generation\":7",
      "\"store_generation\":\"7\"");
}

/* A non-canonical request id is rejected (wrong length here). */
static void
test_reject_non_canonical_request_id (void)
{
  gsize len = 0;
  g_autofree gchar *canonical = canonical_document (&len);
  expect_mutation_rejected (canonical, g_request_id, "not-a-canonical-id");
}

/* version must be exactly 1. */
static void
test_reject_bad_version (void)
{
  gsize len = 0;
  g_autofree gchar *canonical = canonical_document (&len);
  expect_mutation_rejected (canonical, "{\"version\":1,", "{\"version\":2,");
}

/* Trailing bytes after the terminating newline are rejected. */
static void
test_reject_trailing_bytes (void)
{
  gsize len = 0;
  g_autofree gchar *canonical = canonical_document (&len);
  g_autofree gchar *trailing = g_strconcat (canonical, "x", NULL);
  expect_decode_error (trailing, WYRELOG_E_POLICY);
}

/* Oversize documents (byte bound) and too-many-operations (op bound). */
static void
test_reject_oversize (void)
{
  gsize big = WYL_SERVICE_PERMISSION_MANIFEST_V1_MAX_BYTES + 1;
  gchar *buffer = g_malloc (big);
  memset (buffer, 'a', big);
  WylServicePermissionManifest manifest;
  g_assert_cmpint (wyl_service_permission_manifest_decode (buffer, big,
          &manifest), ==, WYRELOG_E_INVALID);
  g_free (buffer);

  GString *doc = g_string_new (NULL);
  g_string_append (doc, "{\"version\":1,\"request_id\":\"");
  g_string_append (doc, g_request_id);
  g_string_append (doc, "\",\"store_generation\":7,\"store_digest\":\"");
  for (guint i = 0; i < 32; i++)
    g_string_append_printf (doc, "%02x", i + 1);
  g_string_append (doc, "\",\"operations\":[");
  for (guint i = 0; i <= WYL_SERVICE_PERMISSION_MANIFEST_V1_MAX_OPERATIONS; i++) {
    if (i > 0)
      g_string_append_c (doc, ',');
    g_string_append (doc, "{\"action\":\"revoke_direct_permission\","
        "\"subject_id\":\"svc:a\",\"permission_id\":\"p\",\"scope\":\"s\"}");
  }
  g_string_append (doc, "]}\n");
  expect_decode_error (doc->str, WYRELOG_E_POLICY);
  g_string_free (doc, TRUE);
}

/* from_analysis builds a manifest whose ops matches_analysis accepts against
 * the same closure; mismatched binding and scope are rejected. */
static void
test_from_analysis_matches (void)
{
  WylPolicyPermissionClosureAnalysis analysis;
  memset (&analysis, 0, sizeof analysis);
  analysis.generation = 7;
  fill_digest (analysis.digest);
  analysis.removals = g_ptr_array_new_with_free_func
      ((GDestroyNotify) wyl_policy_permission_closure_removal_free);
  g_ptr_array_add (analysis.removals,
      make_removal (WYL_POLICY_PERMISSION_CLOSURE_REVOKE_DIRECT, "svc:alpha",
          "perm.read", "res:doc"));
  g_ptr_array_add (analysis.removals,
      make_removal (WYL_POLICY_PERMISSION_CLOSURE_REMOVE_MEMBERSHIP, "svc:beta",
          "role.admin", "res:proj"));

  /* non-canonical request id is refused up front */
  WylServicePermissionManifest bad;
  g_assert_cmpint (wyl_service_permission_manifest_from_analysis (&analysis,
          "nope", &bad), ==, WYRELOG_E_INVALID);

  WylServicePermissionManifest manifest;
  g_assert_cmpint (wyl_service_permission_manifest_from_analysis (&analysis,
          g_request_id, &manifest), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_permission_manifest_matches_analysis (&manifest,
          &analysis), ==, WYRELOG_E_OK);

  /* generation/digest binding mismatch */
  analysis.generation = 8;
  g_assert_cmpint (wyl_service_permission_manifest_matches_analysis (&manifest,
          &analysis), ==, WYRELOG_E_POLICY);
  analysis.generation = 7;

  /* scope mismatch: an ambiguous ("*") closure scope does not match the
   * concrete manifest op -- scope semantics are enforced by the closure
   * binding, the byte grammar treats scope as an opaque field. */
  WylPolicyPermissionClosureRemoval *first =
      g_ptr_array_index (analysis.removals, 0);
  g_free (first->scope);
  first->scope = g_strdup ("*");
  g_assert_cmpint (wyl_service_permission_manifest_matches_analysis (&manifest,
          &analysis), ==, WYRELOG_E_POLICY);

  wyl_service_permission_manifest_clear (&manifest);
  wyl_policy_permission_closure_analysis_clear (&analysis);
}

#ifndef G_OS_WIN32
static void
test_owner_only_round_trip (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-manifest-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *path = g_build_filename (dir, "manifest.json", NULL);

  WylServicePermissionManifest manifest;
  make_valid_manifest (&manifest);
  g_assert_cmpint (wyl_service_permission_manifest_write_new_owner_only (path,
          &manifest), ==, WYRELOG_E_OK);

  /* refuses to re-create over an existing path */
  g_assert_cmpint (wyl_service_permission_manifest_write_new_owner_only (path,
          &manifest), ==, WYRELOG_E_POLICY);

  WylServicePermissionManifest loaded;
  g_assert_cmpint (wyl_service_permission_manifest_read_owner_only (path,
          &loaded), ==, WYRELOG_E_OK);
  g_assert_cmpuint (loaded.operations->len, ==, manifest.operations->len);
  g_assert_cmpstr (loaded.request_id, ==, manifest.request_id);
  wyl_service_permission_manifest_clear (&loaded);
  wyl_service_permission_manifest_clear (&manifest);

  g_remove (path);
  g_rmdir (dir);
}

static void
test_owner_only_rejects_group_world (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-manifest-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *path = g_build_filename (dir, "manifest.json", NULL);

  gsize len = 0;
  g_autofree gchar *document = canonical_document (&len);
  g_assert_true (g_file_set_contents (path, document, len, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (path, 0644), ==, 0);

  WylServicePermissionManifest loaded;
  g_assert_cmpint (wyl_service_permission_manifest_read_owner_only (path,
          &loaded), ==, WYRELOG_E_POLICY);

  g_remove (path);
  g_rmdir (dir);
}

static void
test_owner_only_rejects_symlink (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-manifest-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *path = g_build_filename (dir, "manifest.json", NULL);
  g_autofree gchar *link = g_build_filename (dir, "manifest-link.json", NULL);

  WylServicePermissionManifest manifest;
  make_valid_manifest (&manifest);
  g_assert_cmpint (wyl_service_permission_manifest_write_new_owner_only (path,
          &manifest), ==, WYRELOG_E_OK);
  wyl_service_permission_manifest_clear (&manifest);

  g_assert_cmpint (symlink (path, link), ==, 0);
  WylServicePermissionManifest loaded;
  g_assert_cmpint (wyl_service_permission_manifest_read_owner_only (link,
          &loaded), ==, WYRELOG_E_POLICY);

  g_remove (link);
  g_remove (path);
  g_rmdir (dir);
}
#endif

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
  g_assert_cmpint (wyl_request_id_new (g_request_id, sizeof g_request_id), ==,
      WYRELOG_E_OK);

  g_test_add_func ("/service-permission-manifest/round-trip", test_round_trip);
  g_test_add_func ("/service-permission-manifest/round-trip-each-op",
      test_round_trip_each_op);
  g_test_add_func ("/service-permission-manifest/reject-forbidden-ops",
      test_reject_forbidden_ops);
  g_test_add_func ("/service-permission-manifest/reject-human-subject",
      test_reject_human_subject);
  g_test_add_func ("/service-permission-manifest/reject-field-defects",
      test_reject_field_defects);
  g_test_add_func
      ("/service-permission-manifest/reject-non-canonical-request-id",
      test_reject_non_canonical_request_id);
  g_test_add_func ("/service-permission-manifest/reject-bad-version",
      test_reject_bad_version);
  g_test_add_func ("/service-permission-manifest/reject-trailing-bytes",
      test_reject_trailing_bytes);
  g_test_add_func ("/service-permission-manifest/reject-oversize",
      test_reject_oversize);
  g_test_add_func ("/service-permission-manifest/from-analysis-matches",
      test_from_analysis_matches);
#ifndef G_OS_WIN32
  g_test_add_func ("/service-permission-manifest/owner-only-round-trip",
      test_owner_only_round_trip);
  g_test_add_func
      ("/service-permission-manifest/owner-only-rejects-group-world",
      test_owner_only_rejects_group_world);
  g_test_add_func ("/service-permission-manifest/owner-only-rejects-symlink",
      test_owner_only_rejects_symlink);
#endif
  return g_test_run ();
}

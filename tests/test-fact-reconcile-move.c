/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <glib.h>
#include <glib/gstdio.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fact-test-support.h"
#include "wyrelog/fact/reconcile-move-private.h"

/* SHA-256 of the three bytes "abc" (FIPS-180 test vector). */
static const guint8 sha256_abc[32] = {
  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
  0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
  0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
  0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
};

static gchar *
make_root (void)
{
  g_autoptr (GError) error = NULL;
  gchar *root = wyl_test_make_secure_fact_root ("wyl-reconcile-move-XXXXXX",
      &error);
  g_assert_no_error (error);
  g_assert_nonnull (root);
  return root;
}

static gchar *
write_secure_file (const gchar *root, const gchar *name, const gchar *bytes,
    gssize length)
{
  gchar *path = g_build_filename (root, name, NULL);
  g_assert_true (g_file_set_contents (path, bytes, length, NULL));
  g_autoptr (GError) error = NULL;
  g_assert_true (wyl_test_secure_regular_file (path, &error));
  g_assert_no_error (error);
  return path;
}

static gint
open_regular (const gchar *path)
{
  gint fd = open (path, O_RDONLY | O_CLOEXEC);
  g_assert_cmpint (fd, >=, 0);
  return fd;
}

static void
test_capture_known_vector (void)
{
  g_autofree gchar *root = make_root ();
  g_autofree gchar *path = write_secure_file (root, "abc.bin", "abc", 3);
  gint fd = open_regular (path);

  struct stat st;
  g_assert_cmpint (fstat (fd, &st), ==, 0);

  WylPolicyFactReconcileArtifactEvidence evidence;
  g_assert_cmpint (wyl_fact_reconcile_capture_artifact_evidence (fd,
          &evidence), ==, WYRELOG_E_OK);
  g_assert_cmpuint (evidence.version, ==,
      WYL_POLICY_FACT_RECONCILE_ARTIFACT_EVIDENCE_V1);
  g_assert_cmpint (evidence.identity_kind, ==,
      WYL_POLICY_FACT_RECONCILE_ARTIFACT_IDENTITY_POSIX);
  g_assert_cmpuint (evidence.posix_device, ==, (guint64) st.st_dev);
  g_assert_cmpuint (evidence.posix_inode, ==, (guint64) st.st_ino);
  g_assert_cmpuint (evidence.size_bytes, ==, 3);
  g_assert_cmpint (evidence.digest_algorithm, ==,
      WYL_POLICY_FACT_RECONCILE_ARTIFACT_DIGEST_SHA256);
  g_assert_cmpmem (evidence.digest, sizeof evidence.digest, sha256_abc,
      sizeof sha256_abc);
  g_assert_cmpuint (evidence.windows_volume_serial, ==, 0);

  g_assert_cmpint (close (fd), ==, 0);
  (void) g_remove (path);
  g_assert_true (wyl_test_remove_empty_directory (root, NULL));
}

static void
test_capture_reproduces_across_inodes (void)
{
  g_autofree gchar *root = make_root ();
  g_autofree gchar *path_a = write_secure_file (root, "a.bin",
      "duckdb-payload", -1);
  g_autofree gchar *path_b = write_secure_file (root, "b.bin",
      "duckdb-payload", -1);
  gint fd_a = open_regular (path_a);
  gint fd_b = open_regular (path_b);

  WylPolicyFactReconcileArtifactEvidence ev_a;
  WylPolicyFactReconcileArtifactEvidence ev_b;
  g_assert_cmpint (wyl_fact_reconcile_capture_artifact_evidence (fd_a, &ev_a),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_reconcile_capture_artifact_evidence (fd_b, &ev_b),
      ==, WYRELOG_E_OK);

  /* Different inodes, identical bytes: size and digest reproduce exactly. */
  g_assert_cmpuint (ev_a.posix_inode, !=, ev_b.posix_inode);
  g_assert_cmpuint (ev_a.size_bytes, ==, ev_b.size_bytes);
  g_assert_cmpmem (ev_a.digest, sizeof ev_a.digest, ev_b.digest,
      sizeof ev_b.digest);

  g_assert_cmpint (close (fd_a), ==, 0);
  g_assert_cmpint (close (fd_b), ==, 0);
  (void) g_remove (path_a);
  (void) g_remove (path_b);
  g_assert_true (wyl_test_remove_empty_directory (root, NULL));
}

static void
test_capture_rejects_bad_input (void)
{
  WylPolicyFactReconcileArtifactEvidence evidence;
  g_assert_cmpint (wyl_fact_reconcile_capture_artifact_evidence (-1,
          &evidence), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_reconcile_capture_artifact_evidence (0, NULL), ==,
      WYRELOG_E_INVALID);

  g_autofree gchar *root = make_root ();
  gint dir_fd = open (root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  g_assert_cmpint (dir_fd, >=, 0);
  g_assert_cmpint (wyl_fact_reconcile_capture_artifact_evidence (dir_fd,
          &evidence), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (close (dir_fd), ==, 0);
  g_assert_true (wyl_test_remove_empty_directory (root, NULL));
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/reconcile-move/capture/known-vector",
      test_capture_known_vector);
  g_test_add_func ("/fact/reconcile-move/capture/reproduces-across-inodes",
      test_capture_reproduces_across_inodes);
  g_test_add_func ("/fact/reconcile-move/capture/rejects-bad-input",
      test_capture_rejects_bad_input);
  return g_test_run ();
}

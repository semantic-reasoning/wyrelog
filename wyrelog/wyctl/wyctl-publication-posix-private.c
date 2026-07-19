/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "wyctl-publication-posix-private.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include <sodium.h>

#include "wyrelog/wyl-common-private.h"

typedef struct
{
  int dirfd;
  struct stat dir_st;
  gchar *dir_path;
} WyctlPublicationPosixAnchor;

static gboolean
string_is_present (const gchar *value)
{
  return value != NULL && value[0] != '\0';
}

static wyrelog_error_t
map_errno_to_error (int err)
{
  switch (err) {
    case EACCES:
    case EPERM:
    case EEXIST:
    case ENOTEMPTY:
    case ELOOP:
    case ENOTDIR:
    case ENAMETOOLONG:
    case EXDEV:
    case EROFS:
      return WYRELOG_E_POLICY;
    case ENOENT:
      return WYRELOG_E_NOT_FOUND;
    case ENOMEM:
      return WYRELOG_E_NOMEM;
    default:
      return WYRELOG_E_IO;
  }
}

static gboolean
stat_is_owner_only_regular (const struct stat *st, gboolean require_empty)
{
  if (st == NULL)
    return FALSE;
  if (!S_ISREG (st->st_mode))
    return FALSE;
  if (st->st_nlink != 1)
    return FALSE;
  if (st->st_uid != geteuid ())
    return FALSE;
  if ((st->st_mode & 0777) != 0600)
    return FALSE;
  if (require_empty && st->st_size != 0)
    return FALSE;
  return TRUE;
}

/* Recovery may act on a durable basename after a crash. POSIX has no
 * unlink/rename operation that accepts an already-verified file descriptor,
 * so the publication root is a trust boundary: only this service account may
 * modify entries while a receipt is live. */
static gboolean
stat_is_private_root_directory (const struct stat *st)
{
  return st != NULL && S_ISDIR (st->st_mode) && st->st_uid == geteuid ()
      && (st->st_mode & 0777) == 0700;
}

static gchar *
encode_stat_identity (const struct stat *st)
{
  if (st == NULL)
    return NULL;
  return g_strdup_printf ("%" G_GUINT64_FORMAT ":%" G_GUINT64_FORMAT ":"
      "%" G_GUINT64_FORMAT ":%" G_GUINT64_FORMAT ":"
      "%" G_GUINT64_FORMAT,
      (guint64) st->st_dev,
      (guint64) st->st_ino,
      (guint64) st->st_uid, (guint64) st->st_gid, (guint64) st->st_mode);
}

static gboolean
identity_matches_stat (const gchar *identity, const struct stat *st)
{
  g_autofree gchar *expected = encode_stat_identity (st);
  return string_is_present (identity) && expected != NULL
      && g_strcmp0 (identity, expected) == 0;
}

static gboolean
backend_is_valid (const WyctlPublicationPosixBackend *backend)
{
  return backend != NULL && string_is_present (backend->root_dir);
}

static gboolean
open_root_anchor (const WyctlPublicationPosixBackend *backend,
    WyctlPublicationPosixAnchor *anchor, wyrelog_error_t *out_error)
{
  struct stat st;
  int dirfd;

  if (out_error != NULL)
    *out_error = WYRELOG_E_INVALID;
  if (anchor == NULL || !backend_is_valid (backend))
    return FALSE;

  memset (anchor, 0, sizeof *anchor);
  anchor->dirfd = -1;

  dirfd = open (backend->root_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC
#ifdef O_NOFOLLOW
      | O_NOFOLLOW
#endif
      );
  if (dirfd < 0) {
    if (out_error != NULL)
      *out_error = map_errno_to_error (errno);
    return FALSE;
  }

  if (fstat (dirfd, &st) != 0) {
    if (out_error != NULL)
      *out_error = WYRELOG_E_IO;
    close (dirfd);
    return FALSE;
  }
  if (!stat_is_private_root_directory (&st)) {
    if (out_error != NULL)
      *out_error = WYRELOG_E_POLICY;
    close (dirfd);
    return FALSE;
  }

  anchor->dirfd = dirfd;
  anchor->dir_st = st;
  anchor->dir_path = g_strdup (backend->root_dir);
  if (anchor->dir_path == NULL) {
    if (out_error != NULL)
      *out_error = WYRELOG_E_NOMEM;
    close (dirfd);
    g_clear_pointer (&anchor->dir_path, g_free);
    anchor->dirfd = -1;
    return FALSE;
  }
  if (out_error != NULL)
    *out_error = WYRELOG_E_OK;
  return TRUE;
}

static void
close_root_anchor (WyctlPublicationPosixAnchor *anchor)
{
  if (anchor == NULL)
    return;
  if (anchor->dirfd >= 0)
    close (anchor->dirfd);
  anchor->dirfd = -1;
  g_clear_pointer (&anchor->dir_path, g_free);
  memset (&anchor->dir_st, 0, sizeof anchor->dir_st);
}

static gboolean
plan_matches_anchor (const WyctlPublicationPlan *plan,
    const WyctlPublicationPosixAnchor *anchor)
{
  return plan != NULL && anchor != NULL
      && identity_matches_stat (plan->parent_identity, &anchor->dir_st);
}

static gboolean
receipt_matches_plan_anchor (const WyctlPublicationReceipt *receipt,
    const WyctlPublicationPlan *plan, const WyctlPublicationPosixAnchor *anchor)
{
  return receipt != NULL && plan_matches_anchor (plan, anchor)
      && g_strcmp0 (receipt->parent_identity, plan->parent_identity) == 0;
}

static gchar *
stage_path_for_plan (const WyctlPublicationPosixBackend *backend,
    const WyctlPublicationPlan *plan)
{
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (plan))
    return NULL;
  return g_build_filename (backend->root_dir, plan->stage_basename, NULL);
}

static gchar *
destination_path_for_plan (const WyctlPublicationPosixBackend *backend,
    const WyctlPublicationPlan *plan)
{
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (plan))
    return NULL;
  return g_build_filename (backend->root_dir, plan->destination, NULL);
}

static wyrelog_error_t
fsync_fd_checked (int fd)
{
  if (fd < 0)
    return WYRELOG_E_INVALID;
#ifdef __APPLE__
#ifdef F_FULLFSYNC
  if (fcntl (fd, F_FULLFSYNC) == 0)
    return WYRELOG_E_OK;
  if (errno != EINVAL && errno != ENOTTY && errno != ENOTSUP)
    return map_errno_to_error (errno);
#endif
#endif
  if (fsync (fd) != 0)
    return map_errno_to_error (errno);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
rename_no_replace (const gchar *root_dir, int dirfd,
    const gchar *src_basename, const gchar *dst_relative)
{
  (void) root_dir;
#if defined(__linux__)
#ifdef SYS_renameat2
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1
#endif
  if (syscall (SYS_renameat2, dirfd, src_basename, dirfd, dst_relative,
          RENAME_NOREPLACE) != 0)
    return map_errno_to_error (errno);
  return WYRELOG_E_OK;
#else
  return WYRELOG_E_POLICY;
#endif
#elif defined(__APPLE__)
  if (renameatx_np (dirfd, src_basename, dirfd, dst_relative, RENAME_EXCL) != 0)
    return map_errno_to_error (errno);
  return WYRELOG_E_OK;
#else
  return WYRELOG_E_POLICY;
#endif
}

static wyrelog_error_t
write_all (int fd, const guint8 *bytes, gsize len)
{
  gsize total = 0;

  while (total < len) {
    ssize_t put = write (fd, bytes + total, len - total);
    if (put < 0) {
      if (errno == EINTR)
        continue;
      return map_errno_to_error (errno);
    }
    if (put == 0)
      return WYRELOG_E_IO;
    total += (gsize) put;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
read_all (int fd, gchar **out_bytes, gsize *out_len)
{
  struct stat st;
  gchar *buf;
  gsize total = 0;

  if (out_bytes != NULL)
    *out_bytes = NULL;
  if (out_len != NULL)
    *out_len = 0;

  if (fd < 0 || out_bytes == NULL || out_len == NULL)
    return WYRELOG_E_INVALID;
  if (fstat (fd, &st) != 0 || !S_ISREG (st.st_mode) || st.st_size < 0)
    return WYRELOG_E_IO;

  buf = g_malloc ((gsize) st.st_size + 1);
  if (buf == NULL)
    return WYRELOG_E_NOMEM;

  if (lseek (fd, 0, SEEK_SET) < 0) {
    sodium_memzero (buf, (gsize) st.st_size + 1);
    g_free (buf);
    return map_errno_to_error (errno);
  }

  while (total < (gsize) st.st_size) {
    ssize_t got = read (fd, buf + total, (gsize) st.st_size - total);
    if (got < 0) {
      if (errno == EINTR)
        continue;
      sodium_memzero (buf, (gsize) st.st_size + 1);
      g_free (buf);
      return map_errno_to_error (errno);
    }
    if (got == 0)
      break;
    total += (gsize) got;
  }
  if (total != (gsize) st.st_size) {
    sodium_memzero (buf, (gsize) st.st_size + 1);
    g_free (buf);
    return WYRELOG_E_IO;
  }
  buf[total] = '\0';
  *out_bytes = buf;
  *out_len = total;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
document_matches_expected (const gchar *path,
    const gchar *expected_credential_id,
    const WyctlSensitiveText *expected_credential_secret,
    gboolean *out_matches, gboolean *out_empty)
{
  gchar *content = NULL;
  g_autofree gchar *decoded_id = NULL;
  WyctlSensitiveText decoded_secret = { 0 };
  gsize content_len = 0;
  wyrelog_error_t rc;
  int fd;

  if (out_matches == NULL || out_empty == NULL)
    return WYRELOG_E_INVALID;
  *out_matches = FALSE;
  *out_empty = FALSE;
  fd = open (path, O_RDONLY | O_CLOEXEC
#ifdef O_NOFOLLOW
      | O_NOFOLLOW
#endif
      );
  if (fd < 0)
    return map_errno_to_error (errno);
  rc = read_all (fd, &content, &content_len);
  close (fd);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (content_len == 0) {
    *out_empty = TRUE;
    sodium_memzero (content, content_len + 1);
    g_free (content);
    return WYRELOG_E_OK;
  }
  rc = wyctl_publication_credential_document_decode (content, content_len,
      &decoded_id, &decoded_secret);
  sodium_memzero (content, content_len + 1);
  g_free (content);
  if (rc == WYRELOG_E_OK)
    *out_matches = wyctl_publication_credential_document_matches (decoded_id,
        &decoded_secret, expected_credential_id, expected_credential_secret);
  wyctl_sensitive_text_clear (&decoded_secret);
  return rc;
}

static wyrelog_error_t
document_matches_expected_at (int dirfd, const gchar *basename,
    const gchar *expected_identity, const gchar *expected_credential_id,
    const WyctlSensitiveText *expected_credential_secret,
    gboolean *out_matches, gboolean *out_empty)
{
  gchar *content = NULL;
  g_autofree gchar *decoded_id = NULL;
  WyctlSensitiveText decoded_secret = { 0 };
  struct stat st;
  gsize content_len = 0;
  wyrelog_error_t rc;
  int fd;

  if (dirfd < 0 || !string_is_present (basename)
      || !string_is_present (expected_identity) || out_matches == NULL
      || out_empty == NULL)
    return WYRELOG_E_INVALID;
  *out_matches = FALSE;
  *out_empty = FALSE;
  fd = openat (dirfd, basename, O_RDONLY | O_CLOEXEC
#ifdef O_NOFOLLOW
      | O_NOFOLLOW
#endif
      );
  if (fd < 0)
    return map_errno_to_error (errno);
  if (fstat (fd, &st) != 0 || !stat_is_owner_only_regular (&st, FALSE)
      || !identity_matches_stat (expected_identity, &st)) {
    close (fd);
    return WYRELOG_E_POLICY;
  }
  rc = read_all (fd, &content, &content_len);
  close (fd);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (content_len == 0) {
    *out_empty = TRUE;
  } else {
    rc = wyctl_publication_credential_document_decode (content, content_len,
        &decoded_id, &decoded_secret);
    if (rc == WYRELOG_E_OK)
      *out_matches = wyctl_publication_credential_document_matches
          (decoded_id, &decoded_secret, expected_credential_id,
          expected_credential_secret);
  }
  sodium_memzero (content, content_len + 1);
  g_free (content);
  wyctl_sensitive_text_clear (&decoded_secret);
  return rc;
}

static wyrelog_error_t
document_matches_expected_fd (int fd,
    const gchar *expected_credential_id,
    const WyctlSensitiveText *expected_credential_secret, gboolean *out_matches)
{
  gchar *content = NULL;
  g_autofree gchar *decoded_id = NULL;
  WyctlSensitiveText decoded_secret = { 0 };
  struct stat st;
  gsize content_len = 0;
  wyrelog_error_t rc;

  if (fd < 0 || out_matches == NULL)
    return WYRELOG_E_INVALID;
  *out_matches = FALSE;
  if (fstat (fd, &st) != 0 || !stat_is_owner_only_regular (&st, FALSE)
      || st.st_size <= 0 || st.st_size > 1024)
    return WYRELOG_E_POLICY;
  rc = read_all (fd, &content, &content_len);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyctl_publication_credential_document_decode (content, content_len,
      &decoded_id, &decoded_secret);
  if (rc == WYRELOG_E_OK)
    *out_matches = wyctl_publication_credential_document_matches (decoded_id,
        &decoded_secret, expected_credential_id, expected_credential_secret);
  wyctl_sensitive_text_clear (&decoded_secret);
  sodium_memzero (content, content_len + 1);
  g_free (content);
  return rc;
}

static gboolean
named_entry_matches_receipt (int dirfd, const gchar *basename,
    const gchar *expected_identity)
{
  struct stat st;

  return dirfd >= 0 && string_is_present (basename)
      && fstatat (dirfd, basename, &st, AT_SYMLINK_NOFOLLOW) == 0
      && stat_is_owner_only_regular (&st, FALSE)
      && identity_matches_stat (expected_identity, &st);
}

static wyrelog_error_t
write_credential_document_to_fd (int fd, const gchar *credential_id,
    const gchar *credential_secret)
{
  gchar *document = NULL;
  wyrelog_error_t rc;

  rc = wyctl_publication_credential_document_encode (credential_id,
      credential_secret, &document);
  if (rc != WYRELOG_E_OK)
    return rc;

  if (lseek (fd, 0, SEEK_SET) < 0) {
    rc = map_errno_to_error (errno);
    goto out;
  }
  if (ftruncate (fd, 0) != 0) {
    rc = map_errno_to_error (errno);
    goto out;
  }
  rc = write_all (fd, (const guint8 *) document, strlen (document));
  if (rc != WYRELOG_E_OK)
    goto out;
  rc = fsync_fd_checked (fd);
  if (rc != WYRELOG_E_OK)
    goto out;

  {
    g_autofree gchar *roundtrip = NULL;
    gsize roundtrip_len = 0;
    g_autofree gchar *decoded_id = NULL;
    WyctlSensitiveText decoded_secret = { 0 };

    rc = read_all (fd, &roundtrip, &roundtrip_len);
    if (rc != WYRELOG_E_OK)
      goto out;
    rc = wyctl_publication_credential_document_decode (roundtrip, roundtrip_len,
        &decoded_id, &decoded_secret);
    if (rc != WYRELOG_E_OK) {
      sodium_memzero (roundtrip, roundtrip_len + 1);
      goto out;
    }
    if (g_strcmp0 (decoded_id, credential_id) != 0
        || decoded_secret.len != strlen (credential_secret)
        || memcmp (decoded_secret.text, credential_secret,
            decoded_secret.len) != 0) {
      wyctl_sensitive_text_clear (&decoded_secret);
      sodium_memzero (roundtrip, roundtrip_len + 1);
      rc = WYRELOG_E_IO;
      goto out;
    }
    wyctl_sensitive_text_clear (&decoded_secret);
    sodium_memzero (roundtrip, roundtrip_len + 1);
  }

out:
  sodium_memzero (document, strlen (document));
  g_free (document);
  return rc;
}

static wyrelog_error_t
stat_path_identity (const gchar *path, struct stat *out_st,
    gboolean allow_missing)
{
  if (out_st == NULL || !string_is_present (path))
    return WYRELOG_E_INVALID;
  if (lstat (path, out_st) != 0) {
    if (errno == ENOENT && allow_missing)
      return WYRELOG_E_NOT_FOUND;
    return map_errno_to_error (errno);
  }
  return WYRELOG_E_OK;
}

void
wyctl_publication_posix_backend_init (WyctlPublicationPosixBackend *backend,
    const gchar *root_dir)
{
  if (backend == NULL)
    return;
  g_clear_pointer (&backend->root_dir, g_free);
  backend->root_dir = g_strdup (root_dir);
}

void
wyctl_publication_posix_backend_clear (WyctlPublicationPosixBackend *backend)
{
  if (backend == NULL)
    return;
  g_clear_pointer (&backend->root_dir, g_free);
}

wyrelog_error_t
wyctl_publication_posix_plan (const WyctlPublicationPosixBackend *backend,
    const WyctlPublicationPlan *request, WyctlPublicationPlan *out_plan)
{
  WyctlPublicationPosixAnchor anchor = { 0 };
  g_autofree gchar *destination_path = NULL;
  struct stat st;
  wyrelog_error_t rc;

  if (out_plan == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_plan_clear (out_plan);
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (request))
    return WYRELOG_E_INVALID;

  if (!open_root_anchor (backend, &anchor, &rc))
    return rc;

  destination_path = destination_path_for_plan (backend, request);
  if (destination_path == NULL) {
    close_root_anchor (&anchor);
    return WYRELOG_E_NOMEM;
  }
  if (lstat (destination_path, &st) == 0) {
    close_root_anchor (&anchor);
    return WYRELOG_E_POLICY;
  }
  if (errno != ENOENT) {
    close_root_anchor (&anchor);
    return map_errno_to_error (errno);
  }

  rc = wyctl_publication_plan_clone (request, out_plan);
  if (rc == WYRELOG_E_OK) {
    g_free (out_plan->parent_identity);
    out_plan->parent_identity = encode_stat_identity (&anchor.dir_st);
    if (out_plan->parent_identity == NULL) {
      wyctl_publication_plan_clear (out_plan);
      rc = WYRELOG_E_NOMEM;
    }
  }
  close_root_anchor (&anchor);
  return rc;
}

wyrelog_error_t
wyctl_publication_posix_prepare (const WyctlPublicationPosixBackend *backend,
    const WyctlPublicationPlan *plan, WyctlPublicationReceipt *out_receipt)
{
  WyctlPublicationPosixAnchor anchor = { 0 };
  g_autofree gchar *stage_path = NULL;
  struct stat stage_st;
  int stage_fd = -1;
  wyrelog_error_t rc;
  gchar *identity = NULL;

  if (out_receipt == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_receipt_clear (out_receipt);
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (plan))
    return WYRELOG_E_INVALID;

  stage_path = stage_path_for_plan (backend, plan);
  if (stage_path == NULL)
    return WYRELOG_E_NOMEM;

  if (!open_root_anchor (backend, &anchor, &rc))
    return rc;
  if (!plan_matches_anchor (plan, &anchor)) {
    close_root_anchor (&anchor);
    return WYRELOG_E_POLICY;
  }

  stage_fd = openat (anchor.dirfd, plan->stage_basename,
      O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC
#ifdef O_NOFOLLOW
      | O_NOFOLLOW
#endif
      , 0600);
  if (stage_fd < 0) {
    rc = map_errno_to_error (errno);
    close_root_anchor (&anchor);
    return rc;
  }

  if (fchmod (stage_fd, 0600) != 0) {
    rc = map_errno_to_error (errno);
    close (stage_fd);
    (void) unlinkat (anchor.dirfd, plan->stage_basename, 0);
    close_root_anchor (&anchor);
    return rc;
  }
  if (fstat (stage_fd, &stage_st) != 0
      || !stat_is_owner_only_regular (&stage_st, TRUE)) {
    rc = WYRELOG_E_IO;
    close (stage_fd);
    (void) unlinkat (anchor.dirfd, plan->stage_basename, 0);
    close_root_anchor (&anchor);
    return rc;
  }

  identity = encode_stat_identity (&stage_st);
  if (identity == NULL) {
    rc = WYRELOG_E_NOMEM;
    close (stage_fd);
    (void) unlinkat (anchor.dirfd, plan->stage_basename, 0);
    close_root_anchor (&anchor);
    return rc;
  }

  close (stage_fd);
  close_root_anchor (&anchor);

  rc = wyctl_publication_receipt_create (plan, identity, out_receipt);
  g_free (identity);
  return rc;
}

static void
stage_result_fill (WyctlPublicationResult *out_result,
    WyctlPublicationResultKind kind, gboolean exact_identity,
    gboolean cleanup_required)
{
  *out_result = (WyctlPublicationResult) {
  .version = WYCTL_PUBLICATION_RESULT_VERSION,.kind = kind,.exact_identity =
        exact_identity,.cleanup_required = cleanup_required,};
}

/* The publication root is an owner-only trust boundary.  POSIX cannot unlink
 * by file descriptor, so cleanup first proves that the anchored basename still
 * names the exact object held by this invocation. */
static gboolean
cleanup_created_stage (WyctlPublicationPosixAnchor *anchor,
    const gchar *basename, int stage_fd, const struct stat *created_st)
{
  struct stat held_st;
  struct stat named_st;

  if (anchor == NULL || anchor->dirfd < 0 || stage_fd < 0
      || created_st == NULL || fstat (stage_fd, &held_st) != 0
      || held_st.st_dev != created_st->st_dev
      || held_st.st_ino != created_st->st_ino
      || fstatat (anchor->dirfd, basename, &named_st,
          AT_SYMLINK_NOFOLLOW) != 0
      || named_st.st_dev != held_st.st_dev || named_st.st_ino != held_st.st_ino
      || unlinkat (anchor->dirfd, basename, 0) != 0)
    return FALSE;
  return fsync_fd_checked (anchor->dirfd) == WYRELOG_E_OK;
}

wyrelog_error_t
wyctl_publication_posix_stage_exact (const WyctlPublicationPosixBackend
    *backend, const WyctlPublicationPlan *plan, const gchar *credential_id,
    const WyctlSensitiveText *credential_secret,
    WyctlPublicationReceipt *out_receipt,
    WyctlPublicationResult *out_result, gboolean *out_replayed)
{
  WyctlPublicationPosixAnchor anchor = { 0 };
  struct stat stage_st = { 0 };
  int stage_fd = -1;
  gboolean created = FALSE;
  gboolean matches = FALSE;
  gboolean cleanup_durable;
  g_autofree gchar *identity = NULL;
  wyrelog_error_t rc;

  if (out_receipt == NULL || out_result == NULL || out_replayed == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_receipt_clear (out_receipt);
  wyctl_publication_result_clear (out_result);
  *out_replayed = FALSE;
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (plan)
      || !wyctl_publication_expected_credential_is_valid (credential_id,
          credential_secret))
    return WYRELOG_E_INVALID;
  if (!open_root_anchor (backend, &anchor, &rc))
    return rc;
  if (!plan_matches_anchor (plan, &anchor)) {
    close_root_anchor (&anchor);
    return WYRELOG_E_POLICY;
  }

  stage_fd = openat (anchor.dirfd, plan->stage_basename,
      O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC
#ifdef O_NOFOLLOW
      | O_NOFOLLOW
#endif
      , 0600);
  if (stage_fd >= 0) {
    created = TRUE;
  } else if (errno == EEXIST) {
    stage_fd = openat (anchor.dirfd, plan->stage_basename, O_RDONLY | O_CLOEXEC
#ifdef O_NOFOLLOW
        | O_NOFOLLOW
#endif
        );
    if (stage_fd < 0) {
      stage_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
      close_root_anchor (&anchor);
      return WYRELOG_E_OK;
    }
  } else {
    rc = map_errno_to_error (errno);
    close_root_anchor (&anchor);
    return rc;
  }

  if (fstat (stage_fd, &stage_st) != 0) {
    close (stage_fd);
    close_root_anchor (&anchor);
    stage_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
    return WYRELOG_E_OK;
  }
  if (!stat_is_owner_only_regular (&stage_st, created)) {
    if (created) {
      rc = WYRELOG_E_POLICY;
      goto created_failure;
    }
    close (stage_fd);
    close_root_anchor (&anchor);
    stage_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
    return WYRELOG_E_OK;
  }

  if (created) {
    gchar *secret_copy;

    if (fchmod (stage_fd, 0600) != 0) {
      rc = map_errno_to_error (errno);
      goto created_failure;
    }
    secret_copy = g_strndup (credential_secret->text, credential_secret->len);
    if (secret_copy == NULL) {
      rc = WYRELOG_E_NOMEM;
      goto created_failure;
    }
    rc = write_credential_document_to_fd (stage_fd, credential_id, secret_copy);
    sodium_memzero (secret_copy, credential_secret->len + 1);
    g_free (secret_copy);
    if (rc != WYRELOG_E_OK)
      goto created_failure;
    if (fsync_fd_checked (anchor.dirfd) != WYRELOG_E_OK) {
      rc = WYRELOG_E_IO;
      goto created_failure;
    }
  } else {
    /* Re-establish durability before accepting a crash survivor. */
    if (fsync_fd_checked (stage_fd) != WYRELOG_E_OK
        || fsync_fd_checked (anchor.dirfd) != WYRELOG_E_OK) {
      close (stage_fd);
      close_root_anchor (&anchor);
      stage_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
      return WYRELOG_E_OK;
    }
  }

  rc = document_matches_expected_fd (stage_fd, credential_id,
      credential_secret, &matches);
  if (rc != WYRELOG_E_OK || !matches) {
    if (created) {
      rc = rc == WYRELOG_E_OK ? WYRELOG_E_IO : rc;
      goto created_failure;
    }
    close (stage_fd);
    close_root_anchor (&anchor);
    stage_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
    return WYRELOG_E_OK;
  }
  if (fstat (stage_fd, &stage_st) != 0
      || !stat_is_owner_only_regular (&stage_st, FALSE)) {
    if (created) {
      rc = WYRELOG_E_IO;
      goto created_failure;
    }
    close (stage_fd);
    close_root_anchor (&anchor);
    stage_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
    return WYRELOG_E_OK;
  }
  {
    struct stat named_st;
    if (fstatat (anchor.dirfd, plan->stage_basename, &named_st,
            AT_SYMLINK_NOFOLLOW) != 0
        || named_st.st_dev != stage_st.st_dev
        || named_st.st_ino != stage_st.st_ino) {
      if (created) {
        rc = WYRELOG_E_IO;
        goto created_failure;
      }
      close (stage_fd);
      close_root_anchor (&anchor);
      stage_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
      return WYRELOG_E_OK;
    }
  }
  identity = encode_stat_identity (&stage_st);
  if (identity == NULL) {
    if (created) {
      rc = WYRELOG_E_NOMEM;
      goto created_failure;
    }
    close (stage_fd);
    close_root_anchor (&anchor);
    return WYRELOG_E_NOMEM;
  }
  rc = wyctl_publication_receipt_create (plan, identity, out_receipt);
  if (rc != WYRELOG_E_OK) {
    if (created)
      goto created_failure;
    close (stage_fd);
    close_root_anchor (&anchor);
    return rc;
  }
  close (stage_fd);
  close_root_anchor (&anchor);
  *out_replayed = !created;
  stage_result_fill (out_result, WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE,
      TRUE, FALSE);
  return WYRELOG_E_OK;

created_failure:
  cleanup_durable = cleanup_created_stage (&anchor, plan->stage_basename,
      stage_fd, &stage_st);
  close (stage_fd);
  close_root_anchor (&anchor);
  if (!cleanup_durable) {
    wyctl_publication_receipt_clear (out_receipt);
    stage_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
    return WYRELOG_E_OK;
  }
  stage_result_fill (out_result, WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED,
      FALSE, FALSE);
  return rc;
}

static wyrelog_error_t
commit_stage_to_destination (const WyctlPublicationPosixBackend *backend,
    const WyctlPublicationPlan *plan, const WyctlPublicationReceipt *receipt,
    const gchar *credential_id, const gchar *credential_secret,
    WyctlPublicationResult *out_result)
{
  WyctlPublicationPosixAnchor anchor = { 0 };
  int stage_fd = -1;
  struct stat stage_st;
  wyrelog_error_t rc;

  if (out_result == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_result_clear (out_result);

  if (!open_root_anchor (backend, &anchor, &rc))
    return rc;
  if (!receipt_matches_plan_anchor (receipt, plan, &anchor)) {
    close_root_anchor (&anchor);
    return WYRELOG_E_POLICY;
  }

  stage_fd = openat (anchor.dirfd, plan->stage_basename, O_RDWR | O_CLOEXEC
#ifdef O_NOFOLLOW
      | O_NOFOLLOW
#endif
      );
  if (stage_fd < 0) {
    rc = map_errno_to_error (errno);
    close_root_anchor (&anchor);
    return rc;
  }

  if (fstat (stage_fd, &stage_st) != 0 || !identity_matches_stat
      (receipt->stage_identity, &stage_st) || !stat_is_owner_only_regular
      (&stage_st, TRUE)) {
    close (stage_fd);
    close_root_anchor (&anchor);
    return WYRELOG_E_POLICY;
  }

  rc = write_credential_document_to_fd (stage_fd, credential_id,
      credential_secret);
  if (rc != WYRELOG_E_OK) {
    close (stage_fd);
    close_root_anchor (&anchor);
    out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
    out_result->kind = WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED;
    out_result->exact_identity = TRUE;
    out_result->cleanup_required = TRUE;
    return rc;
  }

  rc = rename_no_replace (backend->root_dir, anchor.dirfd, plan->stage_basename,
      plan->destination);
  if (rc != WYRELOG_E_OK) {
    close (stage_fd);
    close_root_anchor (&anchor);
    out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
    out_result->kind = WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED;
    out_result->exact_identity = TRUE;
    out_result->cleanup_required = TRUE;
    return rc;
  }

  rc = fsync_fd_checked (anchor.dirfd);
  close (stage_fd);
  close_root_anchor (&anchor);
  if (rc != WYRELOG_E_OK) {
    out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
    out_result->kind = WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN;
    out_result->exact_identity = TRUE;
    out_result->cleanup_required = FALSE;
    return WYRELOG_E_OK;
  }

  out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
  out_result->kind = WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE;
  out_result->exact_identity = TRUE;
  out_result->cleanup_required = FALSE;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyctl_publication_posix_commit (const WyctlPublicationPosixBackend *backend,
    const WyctlPublicationPlan *plan, const WyctlPublicationReceipt *receipt,
    const gchar *credential_id, const gchar *credential_secret,
    WyctlPublicationResult *out_result)
{
  if (backend == NULL || !backend_is_valid (backend)
      || !wyctl_publication_plan_is_valid (plan)
      || !wyctl_publication_receipt_is_valid (receipt)
      || !string_is_present (credential_id)
      || !string_is_present (credential_secret))
    return WYRELOG_E_INVALID;
  return commit_stage_to_destination (backend, plan, receipt, credential_id,
      credential_secret, out_result);
}

wyrelog_error_t
wyctl_publication_posix_inspect (const WyctlPublicationPosixBackend *backend,
    const WyctlPublicationPlan *plan, const WyctlPublicationReceipt *receipt,
    const gchar *expected_credential_id,
    const WyctlSensitiveText *expected_credential_secret,
    WyctlPublicationResult *out_result)
{
  WyctlPublicationPosixAnchor anchor = { 0 };
  g_autofree gchar *stage_path = NULL;
  g_autofree gchar *destination_path = NULL;
  struct stat stage_st;
  struct stat destination_st;
  wyrelog_error_t rc;

  if (out_result == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_result_clear (out_result);
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (plan)
      || !wyctl_publication_receipt_is_valid (receipt)
      || !wyctl_publication_expected_credential_is_valid
      (expected_credential_id, expected_credential_secret))
    return WYRELOG_E_INVALID;

  stage_path = stage_path_for_plan (backend, plan);
  destination_path = destination_path_for_plan (backend, plan);
  if (stage_path == NULL || destination_path == NULL)
    return WYRELOG_E_NOMEM;
  if (!open_root_anchor (backend, &anchor, &rc))
    return rc;
  if (!receipt_matches_plan_anchor (receipt, plan, &anchor)) {
    close_root_anchor (&anchor);
    return WYRELOG_E_POLICY;
  }
  close_root_anchor (&anchor);

  rc = stat_path_identity (destination_path, &destination_st, TRUE);
  if (rc == WYRELOG_E_OK && identity_matches_stat (receipt->stage_identity,
          &destination_st)) {
    gboolean matches = FALSE;
    gboolean empty = FALSE;
    rc = document_matches_expected (destination_path, expected_credential_id,
        expected_credential_secret, &matches, &empty);
    if (rc == WYRELOG_E_OK && matches)
      out_result->kind = WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE;
    else
      out_result->kind = WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN;
    out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
    out_result->exact_identity = matches;
    out_result->cleanup_required = FALSE;
    return WYRELOG_E_OK;
  }

  rc = stat_path_identity (stage_path, &stage_st, TRUE);
  if (rc == WYRELOG_E_OK && identity_matches_stat (receipt->stage_identity,
          &stage_st)) {
    gboolean matches = FALSE;
    gboolean empty = FALSE;
    rc = document_matches_expected (stage_path, expected_credential_id,
        expected_credential_secret, &matches, &empty);
    out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
    out_result->kind = rc == WYRELOG_E_OK && matches ?
        WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED :
        rc == WYRELOG_E_OK && empty ? WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED
        : WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN;
    out_result->exact_identity = matches || empty;
    out_result->cleanup_required = matches || empty;
    return WYRELOG_E_OK;
  }
  if (rc != WYRELOG_E_NOT_FOUND && rc != WYRELOG_E_OK)
    return rc;

  out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
  out_result->kind = WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN;
  out_result->exact_identity = FALSE;
  out_result->cleanup_required = FALSE;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyctl_publication_posix_resync (const WyctlPublicationPosixBackend *backend,
    const WyctlPublicationPlan *plan, const WyctlPublicationReceipt *receipt,
    const gchar *expected_credential_id,
    const WyctlSensitiveText *expected_credential_secret,
    WyctlPublicationResult *out_result)
{
  WyctlPublicationPosixAnchor anchor = { 0 };
  g_autofree gchar *stage_path = NULL;
  g_autofree gchar *destination_path = NULL;
  struct stat stage_st;
  wyrelog_error_t rc;

  if (out_result == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_result_clear (out_result);
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (plan)
      || !wyctl_publication_receipt_is_valid (receipt)
      || !wyctl_publication_expected_credential_is_valid
      (expected_credential_id, expected_credential_secret))
    return WYRELOG_E_INVALID;

  stage_path = stage_path_for_plan (backend, plan);
  destination_path = destination_path_for_plan (backend, plan);
  if (stage_path == NULL || destination_path == NULL)
    return WYRELOG_E_NOMEM;

  if (!open_root_anchor (backend, &anchor, &rc))
    return rc;
  if (!receipt_matches_plan_anchor (receipt, plan, &anchor)) {
    close_root_anchor (&anchor);
    return WYRELOG_E_POLICY;
  }

  rc = stat_path_identity (destination_path, &stage_st, TRUE);
  if (rc == WYRELOG_E_OK && identity_matches_stat (receipt->stage_identity,
          &stage_st)) {
    gboolean matches = FALSE;
    gboolean empty = FALSE;
    rc = document_matches_expected (destination_path, expected_credential_id,
        expected_credential_secret, &matches, &empty);
    close_root_anchor (&anchor);
    out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
    out_result->kind = rc == WYRELOG_E_OK && matches ?
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE :
        WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN;
    out_result->exact_identity = matches;
    out_result->cleanup_required = FALSE;
    return WYRELOG_E_OK;
  }

  rc = stat_path_identity (stage_path, &stage_st, TRUE);
  if (rc != WYRELOG_E_OK) {
    close_root_anchor (&anchor);
    if (rc == WYRELOG_E_NOT_FOUND) {
      out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
      out_result->kind = WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN;
      out_result->exact_identity = FALSE;
      out_result->cleanup_required = FALSE;
      return WYRELOG_E_OK;
    }
    return rc;
  }
  if (!identity_matches_stat (receipt->stage_identity, &stage_st)) {
    close_root_anchor (&anchor);
    out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
    out_result->kind = WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN;
    out_result->exact_identity = FALSE;
    out_result->cleanup_required = FALSE;
    return WYRELOG_E_OK;
  }

  {
    gboolean matches = FALSE;
    gboolean empty = FALSE;
    rc = document_matches_expected_at (anchor.dirfd, plan->stage_basename,
        receipt->stage_identity, expected_credential_id,
        expected_credential_secret, &matches, &empty);
    if (rc != WYRELOG_E_OK || !matches) {
      close_root_anchor (&anchor);
      out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
      out_result->kind = empty ? WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED :
          WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN;
      out_result->exact_identity = empty;
      out_result->cleanup_required = empty;
      return WYRELOG_E_OK;
    }
    if (!named_entry_matches_receipt (anchor.dirfd, plan->stage_basename,
            receipt->stage_identity)) {
      close_root_anchor (&anchor);
      out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
      out_result->kind = WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN;
      out_result->exact_identity = FALSE;
      out_result->cleanup_required = FALSE;
      return WYRELOG_E_OK;
    }
    rc = rename_no_replace (backend->root_dir, anchor.dirfd,
        plan->stage_basename, plan->destination);
    if (rc != WYRELOG_E_OK) {
      close_root_anchor (&anchor);
      out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
      out_result->kind =
          WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN;
      out_result->exact_identity = TRUE;
      out_result->cleanup_required = TRUE;
      return WYRELOG_E_OK;
    }
    rc = fsync_fd_checked (anchor.dirfd);
    close_root_anchor (&anchor);
    out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
    out_result->kind = rc == WYRELOG_E_OK ?
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE :
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN;
    out_result->exact_identity = TRUE;
    out_result->cleanup_required = FALSE;
    return WYRELOG_E_OK;
  }
}

wyrelog_error_t
wyctl_publication_posix_cleanup (const WyctlPublicationPosixBackend *backend,
    const WyctlPublicationPlan *plan, const WyctlPublicationReceipt *receipt,
    const gchar *expected_credential_id,
    const WyctlSensitiveText *expected_credential_secret,
    WyctlPublicationResult *out_result)
{
  WyctlPublicationPosixAnchor anchor = { 0 };
  g_autofree gchar *stage_path = NULL;
  g_autofree gchar *destination_path = NULL;
  struct stat st;
  wyrelog_error_t rc;

  if (out_result == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_result_clear (out_result);
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (plan)
      || !wyctl_publication_receipt_is_valid (receipt)
      || !wyctl_publication_expected_credential_is_valid
      (expected_credential_id, expected_credential_secret))
    return WYRELOG_E_INVALID;

  stage_path = stage_path_for_plan (backend, plan);
  destination_path = destination_path_for_plan (backend, plan);
  if (stage_path == NULL || destination_path == NULL)
    return WYRELOG_E_NOMEM;

  if (!open_root_anchor (backend, &anchor, &rc))
    return rc;
  if (!receipt_matches_plan_anchor (receipt, plan, &anchor)) {
    close_root_anchor (&anchor);
    return WYRELOG_E_POLICY;
  }

  rc = stat_path_identity (stage_path, &st, TRUE);
  if (rc == WYRELOG_E_OK && identity_matches_stat (receipt->stage_identity,
          &st)) {
    gboolean matches = FALSE;
    gboolean empty = FALSE;
    rc = document_matches_expected_at (anchor.dirfd, plan->stage_basename,
        receipt->stage_identity, expected_credential_id,
        expected_credential_secret, &matches, &empty);
    if (rc != WYRELOG_E_OK || (!matches && !empty)) {
      close_root_anchor (&anchor);
      out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
      out_result->kind = WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN;
      out_result->exact_identity = FALSE;
      out_result->cleanup_required = FALSE;
      return WYRELOG_E_OK;
    }
    if (!named_entry_matches_receipt (anchor.dirfd, plan->stage_basename,
            receipt->stage_identity)) {
      close_root_anchor (&anchor);
      out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
      out_result->kind = WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN;
      out_result->exact_identity = FALSE;
      out_result->cleanup_required = FALSE;
      return WYRELOG_E_OK;
    }
    if (unlinkat (anchor.dirfd, plan->stage_basename, 0) != 0) {
      close_root_anchor (&anchor);
      return map_errno_to_error (errno);
    }
    rc = fsync_fd_checked (anchor.dirfd);
    close_root_anchor (&anchor);
    out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
    out_result->kind = rc == WYRELOG_E_OK ?
        WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED :
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN;
    out_result->exact_identity = TRUE;
    out_result->cleanup_required = FALSE;
    return WYRELOG_E_OK;
  }

  rc = stat_path_identity (destination_path, &st, TRUE);
  if (rc == WYRELOG_E_OK && identity_matches_stat (receipt->stage_identity,
          &st)) {
    gboolean matches = FALSE;
    gboolean empty = FALSE;
    rc = document_matches_expected (destination_path, expected_credential_id,
        expected_credential_secret, &matches, &empty);
    close_root_anchor (&anchor);
    if (rc != WYRELOG_E_OK || !matches) {
      out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
      out_result->kind = WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN;
      out_result->exact_identity = FALSE;
      out_result->cleanup_required = FALSE;
      return WYRELOG_E_OK;
    }
    out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
    out_result->kind = WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE;
    out_result->exact_identity = TRUE;
    out_result->cleanup_required = FALSE;
    return WYRELOG_E_OK;
  }

  close_root_anchor (&anchor);
  out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
  out_result->kind = WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN;
  out_result->exact_identity = FALSE;
  out_result->cleanup_required = FALSE;
  return WYRELOG_E_OK;
}

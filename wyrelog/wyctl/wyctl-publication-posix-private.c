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

  if (fstat (dirfd, &st) != 0 || !S_ISDIR (st.st_mode)) {
    if (out_error != NULL)
      *out_error = WYRELOG_E_IO;
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
  g_autofree gchar *src_path = NULL;
  g_autofree gchar *dst_path = NULL;
  struct stat st;

  src_path = g_build_filename (root_dir, src_basename, NULL);
  dst_path = g_build_filename (root_dir, dst_relative, NULL);
  if (src_path == NULL || dst_path == NULL)
    return WYRELOG_E_NOMEM;
  if (fstatat (dirfd, dst_relative, &st, AT_SYMLINK_NOFOLLOW) == 0)
    return WYRELOG_E_POLICY;
  if (errno != ENOENT)
    return map_errno_to_error (errno);
  if (rename (src_path, dst_path) != 0)
    return map_errno_to_error (errno);
  return WYRELOG_E_OK;
#endif
#elif defined(__APPLE__)
  if (renameatx_np (dirfd, src_basename, dirfd, dst_relative, RENAME_EXCL) != 0)
    return map_errno_to_error (errno);
  return WYRELOG_E_OK;
#else
  g_autofree gchar *src_path = NULL;
  g_autofree gchar *dst_path = NULL;
  struct stat st;

  src_path = g_build_filename (root_dir, src_basename, NULL);
  dst_path = g_build_filename (root_dir, dst_relative, NULL);
  if (src_path == NULL || dst_path == NULL)
    return WYRELOG_E_NOMEM;
  if (fstatat (dirfd, dst_relative, &st, AT_SYMLINK_NOFOLLOW) == 0)
    return WYRELOG_E_POLICY;
  if (errno != ENOENT)
    return map_errno_to_error (errno);
  if (rename (src_path, dst_path) != 0)
    return map_errno_to_error (errno);
  return WYRELOG_E_OK;
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
    g_free (buf);
    return map_errno_to_error (errno);
  }

  while (total < (gsize) st.st_size) {
    ssize_t got = read (fd, buf + total, (gsize) st.st_size - total);
    if (got < 0) {
      if (errno == EINTR)
        continue;
      g_free (buf);
      return map_errno_to_error (errno);
    }
    if (got == 0)
      break;
    total += (gsize) got;
  }
  if (total != (gsize) st.st_size) {
    g_free (buf);
    return WYRELOG_E_IO;
  }
  buf[total] = '\0';
  *out_bytes = buf;
  *out_len = total;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
write_credential_document_to_fd (int fd, const gchar *credential_id,
    const gchar *credential_secret)
{
  g_autofree gchar *document = NULL;
  wyrelog_error_t rc;

  rc = wyctl_publication_credential_document_encode (credential_id,
      credential_secret, &document);
  if (rc != WYRELOG_E_OK)
    return rc;

  if (lseek (fd, 0, SEEK_SET) < 0)
    return map_errno_to_error (errno);
  if (ftruncate (fd, 0) != 0)
    return map_errno_to_error (errno);
  rc = write_all (fd, (const guint8 *) document, strlen (document));
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = fsync_fd_checked (fd);
  if (rc != WYRELOG_E_OK)
    return rc;

  {
    g_autofree gchar *roundtrip = NULL;
    gsize roundtrip_len = 0;
    g_autofree gchar *decoded_id = NULL;
    WyctlSensitiveText decoded_secret = { 0 };

    rc = read_all (fd, &roundtrip, &roundtrip_len);
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyctl_publication_credential_document_decode (roundtrip, roundtrip_len,
        &decoded_id, &decoded_secret);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (g_strcmp0 (decoded_id, credential_id) != 0
        || decoded_secret.len != strlen (credential_secret)
        || memcmp (decoded_secret.text, credential_secret,
            decoded_secret.len) != 0) {
      wyctl_sensitive_text_clear (&decoded_secret);
      return WYRELOG_E_IO;
    }
    wyctl_sensitive_text_clear (&decoded_secret);
  }

  return WYRELOG_E_OK;
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
  g_autofree gchar *destination_path = NULL;
  struct stat st;

  if (out_plan == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_plan_clear (out_plan);
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (request))
    return WYRELOG_E_INVALID;

  destination_path = destination_path_for_plan (backend, request);
  if (destination_path == NULL)
    return WYRELOG_E_NOMEM;
  if (lstat (destination_path, &st) == 0)
    return WYRELOG_E_POLICY;
  if (errno != ENOENT)
    return map_errno_to_error (errno);

  return wyctl_publication_plan_clone (request, out_plan);
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
    WyctlPublicationResult *out_result)
{
  g_autofree gchar *stage_path = NULL;
  g_autofree gchar *destination_path = NULL;
  struct stat stage_st;
  struct stat destination_st;
  wyrelog_error_t rc;

  if (out_result == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_result_clear (out_result);
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (plan)
      || !wyctl_publication_receipt_is_valid (receipt))
    return WYRELOG_E_INVALID;

  stage_path = stage_path_for_plan (backend, plan);
  destination_path = destination_path_for_plan (backend, plan);
  if (stage_path == NULL || destination_path == NULL)
    return WYRELOG_E_NOMEM;

  rc = stat_path_identity (destination_path, &destination_st, TRUE);
  if (rc == WYRELOG_E_OK && identity_matches_stat (receipt->stage_identity,
          &destination_st)) {
    g_autofree gchar *content = NULL;
    g_autofree gchar *decoded_id = NULL;
    WyctlSensitiveText decoded_secret = { 0 };
    gsize content_len = 0;
    int fd = open (destination_path, O_RDONLY | O_CLOEXEC
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
    rc = wyctl_publication_credential_document_decode (content, content_len,
        &decoded_id, &decoded_secret);
    wyctl_sensitive_text_clear (&decoded_secret);
    if (rc == WYRELOG_E_OK)
      out_result->kind = WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE;
    else
      out_result->kind =
          WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN;
    out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
    out_result->exact_identity = TRUE;
    out_result->cleanup_required = FALSE;
    return WYRELOG_E_OK;
  }

  rc = stat_path_identity (stage_path, &stage_st, TRUE);
  if (rc == WYRELOG_E_OK && identity_matches_stat (receipt->stage_identity,
          &stage_st)) {
    out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
    out_result->kind = WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED;
    out_result->exact_identity = TRUE;
    out_result->cleanup_required = TRUE;
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
      || !wyctl_publication_receipt_is_valid (receipt))
    return WYRELOG_E_INVALID;

  stage_path = stage_path_for_plan (backend, plan);
  destination_path = destination_path_for_plan (backend, plan);
  if (stage_path == NULL || destination_path == NULL)
    return WYRELOG_E_NOMEM;

  if (!open_root_anchor (backend, &anchor, &rc))
    return rc;

  rc = stat_path_identity (destination_path, &stage_st, TRUE);
  if (rc == WYRELOG_E_OK && identity_matches_stat (receipt->stage_identity,
          &stage_st)) {
    close_root_anchor (&anchor);
    out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
    out_result->kind = WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE;
    out_result->exact_identity = TRUE;
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
    g_autofree gchar *content = NULL;
    g_autofree gchar *decoded_id = NULL;
    WyctlSensitiveText decoded_secret = { 0 };
    gsize content_len = 0;
    int fd = open (stage_path, O_RDONLY | O_CLOEXEC
#ifdef O_NOFOLLOW
        | O_NOFOLLOW
#endif
        );
    if (fd < 0) {
      close_root_anchor (&anchor);
      return map_errno_to_error (errno);
    }
    rc = read_all (fd, &content, &content_len);
    close (fd);
    if (rc != WYRELOG_E_OK) {
      close_root_anchor (&anchor);
      return rc;
    }
    if (content_len == 0) {
      close_root_anchor (&anchor);
      out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
      out_result->kind = WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED;
      out_result->exact_identity = TRUE;
      out_result->cleanup_required = TRUE;
      return WYRELOG_E_OK;
    }
    rc = wyctl_publication_credential_document_decode (content, content_len,
        &decoded_id, &decoded_secret);
    wyctl_sensitive_text_clear (&decoded_secret);
    if (rc != WYRELOG_E_OK) {
      close_root_anchor (&anchor);
      out_result->version = WYCTL_PUBLICATION_RESULT_VERSION;
      out_result->kind =
          WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN;
      out_result->exact_identity = TRUE;
      out_result->cleanup_required = TRUE;
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
      || !wyctl_publication_receipt_is_valid (receipt))
    return WYRELOG_E_INVALID;

  stage_path = stage_path_for_plan (backend, plan);
  destination_path = destination_path_for_plan (backend, plan);
  if (stage_path == NULL || destination_path == NULL)
    return WYRELOG_E_NOMEM;

  if (!open_root_anchor (backend, &anchor, &rc))
    return rc;

  rc = stat_path_identity (stage_path, &st, TRUE);
  if (rc == WYRELOG_E_OK && identity_matches_stat (receipt->stage_identity,
          &st)) {
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
    close_root_anchor (&anchor);
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

/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "wyctl-publication-posix-private.h"

#include <errno.h>
#include <dirent.h>
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

struct wyctl_publication_receipt_target_lease_t
{
  int dirfd;
  int target_fd;
  gchar *root_dir;
  gchar *basename;
  gchar *destination;
  gchar *identity;
  const WyctlPublicationPosixBackend *owner;
  gboolean destination_target;
  gboolean inspected_exact;
};

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
      && g_strcmp0 (receipt->destination, plan->destination) == 0
      && g_strcmp0 (receipt->reservation_id, plan->reservation_id) == 0
      && g_strcmp0 (receipt->parent_identity, plan->parent_identity) == 0
      && g_strcmp0 (receipt->stage_basename, plan->stage_basename) == 0;
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
receipt_target_sync (const WyctlPublicationPosixBackend *backend, int fd,
    WyctlPublicationReceiptTargetSyncPoint point)
{
  if (backend->receipt_target_sync_hook != NULL)
    return backend->receipt_target_sync_hook
        (backend->receipt_target_sync_hook_data, point);
  return fsync_fd_checked (fd);
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
write_credential_document_unsynced_to_fd (int fd, const gchar *credential_id,
    const gchar *credential_secret)
{
  gchar *document = NULL;
  gsize document_len = 0;
  wyrelog_error_t rc;

  rc = wyctl_publication_credential_document_encode (credential_id,
      credential_secret, &document);
  if (rc != WYRELOG_E_OK)
    return rc;
  document_len = strlen (document);
  if (lseek (fd, 0, SEEK_SET) < 0 || ftruncate (fd, 0) != 0)
    rc = map_errno_to_error (errno);
  else
    rc = write_all (fd, (const guint8 *) document, document_len);
  sodium_memzero (document, document_len + 1);
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
  backend->stage_exact_hook = NULL;
  backend->stage_exact_hook_data = NULL;
  backend->receipt_target_sync_hook = NULL;
  backend->receipt_target_sync_hook_data = NULL;
}

void
wyctl_publication_posix_backend_clear (WyctlPublicationPosixBackend *backend)
{
  if (backend == NULL)
    return;
  g_clear_pointer (&backend->root_dir, g_free);
  backend->stage_exact_hook = NULL;
  backend->stage_exact_hook_data = NULL;
  backend->receipt_target_sync_hook = NULL;
  backend->receipt_target_sync_hook_data = NULL;
}

void wyctl_publication_posix_backend_set_stage_exact_hook
    (WyctlPublicationPosixBackend * backend,
    WyctlPublicationStageExactHook hook, gpointer data)
{
  if (backend == NULL)
    return;
  backend->stage_exact_hook = hook;
  backend->stage_exact_hook_data = data;
}

void wyctl_publication_posix_backend_set_receipt_target_sync_hook
    (WyctlPublicationPosixBackend * backend,
    WyctlPublicationReceiptTargetSyncHook hook, gpointer data)
{
  if (backend == NULL)
    return;
  backend->receipt_target_sync_hook = hook;
  backend->receipt_target_sync_hook_data = data;
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

static WyctlPublicationStageExactAction
stage_exact_hook (const WyctlPublicationPosixBackend *backend,
    WyctlPublicationStageExactPoint point)
{
  if (backend->stage_exact_hook == NULL)
    return WYCTL_PUBLICATION_STAGE_EXACT_CONTINUE;
  return backend->stage_exact_hook (backend->stage_exact_hook_data, point);
}

static gchar *
stage_temp_prefix (const WyctlPublicationPlan *plan)
{
  return g_strdup_printf (".%s.tmp-", plan->stage_basename);
}

static gchar *
stage_temp_basename (const WyctlPublicationPlan *plan)
{
  wyl_id_t nonce;
  gchar nonce_buf[WYL_ID_STRING_BUF];

  if (wyl_id_new (&nonce) != WYRELOG_E_OK
      || wyl_id_format (&nonce, nonce_buf, sizeof nonce_buf) != WYRELOG_E_OK)
    return NULL;
  return g_strdup_printf (".%s.tmp-%s", plan->stage_basename, nonce_buf);
}

/* A crashed writer can leave a secret-bearing sibling temp.  The random name
 * is scoped by the plan's unique reservation, and the private anchored root
 * excludes other users.  Recovery removes only owner-only regular entries
 * with a canonical temp nonce and proves each basename still names the opened
 * object before unlinking.  An unsafe matching entry makes recovery foreign
 * rather than risking deletion. */
static gboolean
cleanup_stage_temp_orphans (WyctlPublicationPosixAnchor *anchor,
    const WyctlPublicationPlan *plan)
{
  g_autofree gchar *prefix = stage_temp_prefix (plan);
  DIR *dir = NULL;
  struct dirent *entry;
  gboolean removed = FALSE;
  gboolean safe = TRUE;
  int scan_fd;

  if (prefix == NULL)
    return FALSE;
  scan_fd = dup (anchor->dirfd);
  if (scan_fd < 0)
    return FALSE;
  dir = fdopendir (scan_fd);
  if (dir == NULL) {
    close (scan_fd);
    return FALSE;
  }
  errno = 0;
  while ((entry = readdir (dir)) != NULL) {
    const gchar *nonce_text;
    wyl_id_t nonce;
    struct stat st;
    g_autofree gchar *identity = NULL;
    int fd;

    if (!g_str_has_prefix (entry->d_name, prefix))
      continue;
    nonce_text = entry->d_name + strlen (prefix);
    if (wyl_id_parse (nonce_text, &nonce) != WYRELOG_E_OK) {
      safe = FALSE;
      break;
    }
    fd = openat (anchor->dirfd, entry->d_name, O_RDONLY | O_CLOEXEC
#ifdef O_NOFOLLOW
        | O_NOFOLLOW
#endif
        );
    if (fd < 0 || fstat (fd, &st) != 0
        || !stat_is_owner_only_regular (&st, FALSE)
        || (identity = encode_stat_identity (&st)) == NULL
        || !named_entry_matches_receipt (anchor->dirfd, entry->d_name, identity)
        || unlinkat (anchor->dirfd, entry->d_name, 0) != 0) {
      if (fd >= 0)
        close (fd);
      safe = FALSE;
      break;
    }
    close (fd);
    removed = TRUE;
  }
  if (errno != 0)
    safe = FALSE;
  closedir (dir);
  return safe && (!removed || fsync_fd_checked (anchor->dirfd) == WYRELOG_E_OK);
}

static wyrelog_error_t
inspect_exact_stage (WyctlPublicationPosixAnchor *anchor,
    const WyctlPublicationPlan *plan, const gchar *credential_id,
    const WyctlSensitiveText *credential_secret,
    WyctlPublicationReceipt *out_receipt,
    WyctlPublicationResult *out_result, gboolean *out_present)
{
  struct stat st;
  gboolean matches = FALSE;
  g_autofree gchar *identity = NULL;
  int fd;
  wyrelog_error_t rc;

  *out_present = FALSE;
  fd = openat (anchor->dirfd, plan->stage_basename, O_RDONLY | O_CLOEXEC
#ifdef O_NOFOLLOW
      | O_NOFOLLOW
#endif
      );
  if (fd < 0) {
    if (errno == ENOENT)
      return WYRELOG_E_OK;
    stage_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
    *out_present = TRUE;
    return WYRELOG_E_OK;
  }
  *out_present = TRUE;
  if (fstat (fd, &st) != 0 || !stat_is_owner_only_regular (&st, FALSE)
      || fsync_fd_checked (fd) != WYRELOG_E_OK
      || fsync_fd_checked (anchor->dirfd) != WYRELOG_E_OK
      || (identity = encode_stat_identity (&st)) == NULL
      || !named_entry_matches_receipt (anchor->dirfd, plan->stage_basename,
          identity)) {
    close (fd);
    stage_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
    return WYRELOG_E_OK;
  }
  rc = document_matches_expected_fd (fd, credential_id, credential_secret,
      &matches);
  close (fd);
  if (rc != WYRELOG_E_OK || !matches) {
    stage_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
    return WYRELOG_E_OK;
  }
  rc = wyctl_publication_receipt_create (plan, identity, out_receipt);
  if (rc != WYRELOG_E_OK)
    return rc;
  stage_result_fill (out_result, WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE,
      TRUE, FALSE);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyctl_publication_posix_stage_exact (const WyctlPublicationPosixBackend
    *backend, const WyctlPublicationPlan *plan, const gchar *credential_id,
    const WyctlSensitiveText *credential_secret,
    WyctlPublicationReceipt *out_receipt,
    WyctlPublicationResult *out_result, gboolean *out_replayed)
{
  WyctlPublicationPosixAnchor anchor = { 0 };
  struct stat temp_st = { 0 };
  int temp_fd = -1;
  gboolean present = FALSE;
  gboolean matches = FALSE;
  gboolean cleanup_durable;
  g_autofree gchar *temp_basename = NULL;
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

  if (!cleanup_stage_temp_orphans (&anchor, plan)) {
    close_root_anchor (&anchor);
    stage_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
    return WYRELOG_E_OK;
  }
  rc = inspect_exact_stage (&anchor, plan, credential_id, credential_secret,
      out_receipt, out_result, &present);
  if (rc != WYRELOG_E_OK || present) {
    close_root_anchor (&anchor);
    if (rc == WYRELOG_E_OK && out_result->kind ==
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE)
      *out_replayed = TRUE;
    return rc;
  }

  for (guint attempt = 0; attempt < 8 && temp_fd < 0; attempt++) {
    g_clear_pointer (&temp_basename, g_free);
    temp_basename = stage_temp_basename (plan);
    if (temp_basename == NULL) {
      close_root_anchor (&anchor);
      return WYRELOG_E_CRYPTO;
    }
    temp_fd = openat (anchor.dirfd, temp_basename,
        O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC
#ifdef O_NOFOLLOW
        | O_NOFOLLOW
#endif
        , 0600);
    if (temp_fd < 0 && errno != EEXIST) {
      rc = map_errno_to_error (errno);
      close_root_anchor (&anchor);
      return rc;
    }
  }
  if (temp_fd < 0) {
    close_root_anchor (&anchor);
    return WYRELOG_E_POLICY;
  }
  if (fchmod (temp_fd, 0600) != 0 || fstat (temp_fd, &temp_st) != 0
      || !stat_is_owner_only_regular (&temp_st, TRUE)) {
    rc = WYRELOG_E_POLICY;
    goto temp_failure;
  }
  switch (stage_exact_hook (backend,
          WYCTL_PUBLICATION_STAGE_EXACT_TEMP_CREATED)) {
    case WYCTL_PUBLICATION_STAGE_EXACT_CRASH:
      goto simulated_crash;
    case WYCTL_PUBLICATION_STAGE_EXACT_FAIL:
      rc = WYRELOG_E_IO;
      goto temp_failure;
    default:
      break;
  }
  {
    gchar *secret_copy = g_strndup (credential_secret->text,
        credential_secret->len);
    if (secret_copy == NULL) {
      rc = WYRELOG_E_NOMEM;
      goto temp_failure;
    }
    rc = write_credential_document_unsynced_to_fd (temp_fd, credential_id,
        secret_copy);
    sodium_memzero (secret_copy, credential_secret->len + 1);
    g_free (secret_copy);
    if (rc != WYRELOG_E_OK)
      goto temp_failure;
  }
  switch (stage_exact_hook (backend,
          WYCTL_PUBLICATION_STAGE_EXACT_DOCUMENT_WRITTEN)) {
    case WYCTL_PUBLICATION_STAGE_EXACT_CRASH:
      goto simulated_crash;
    case WYCTL_PUBLICATION_STAGE_EXACT_FAIL:
      rc = WYRELOG_E_IO;
      goto temp_failure;
    default:
      break;
  }
  if (fsync_fd_checked (temp_fd) != WYRELOG_E_OK) {
    rc = WYRELOG_E_IO;
    goto temp_failure;
  }
  switch (stage_exact_hook (backend, WYCTL_PUBLICATION_STAGE_EXACT_FILE_SYNCED)) {
    case WYCTL_PUBLICATION_STAGE_EXACT_CRASH:
      goto simulated_crash;
    case WYCTL_PUBLICATION_STAGE_EXACT_FAIL:
      rc = WYRELOG_E_IO;
      goto temp_failure;
    default:
      break;
  }

  rc = rename_no_replace (backend->root_dir, anchor.dirfd, temp_basename,
      plan->stage_basename);
  if (rc != WYRELOG_E_OK) {
    cleanup_durable = cleanup_created_stage (&anchor, temp_basename, temp_fd,
        &temp_st);
    close (temp_fd);
    temp_fd = -1;
    if (!cleanup_durable) {
      close_root_anchor (&anchor);
      stage_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
      return WYRELOG_E_OK;
    }
    rc = inspect_exact_stage (&anchor, plan, credential_id,
        credential_secret, out_receipt, out_result, &present);
    close_root_anchor (&anchor);
    if (rc == WYRELOG_E_OK && present && out_result->kind ==
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE)
      *out_replayed = TRUE;
    else if (rc == WYRELOG_E_OK && !present)
      stage_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
    return rc;
  }
  switch (stage_exact_hook (backend, WYCTL_PUBLICATION_STAGE_EXACT_PUBLISHED)) {
    case WYCTL_PUBLICATION_STAGE_EXACT_CRASH:
    case WYCTL_PUBLICATION_STAGE_EXACT_FAIL:
      goto simulated_crash;
    default:
      break;
  }
  if (fsync_fd_checked (anchor.dirfd) != WYRELOG_E_OK)
    goto published_uncertain;
  switch (stage_exact_hook (backend,
          WYCTL_PUBLICATION_STAGE_EXACT_DIRECTORY_SYNCED)) {
    case WYCTL_PUBLICATION_STAGE_EXACT_CRASH:
    case WYCTL_PUBLICATION_STAGE_EXACT_FAIL:
      goto simulated_crash;
    default:
      break;
  }
  rc = document_matches_expected_fd (temp_fd, credential_id,
      credential_secret, &matches);
  if (rc != WYRELOG_E_OK || !matches || fstat (temp_fd, &temp_st) != 0
      || !stat_is_owner_only_regular (&temp_st, FALSE)
      || (identity = encode_stat_identity (&temp_st)) == NULL
      || !named_entry_matches_receipt (anchor.dirfd, plan->stage_basename,
          identity))
    goto published_uncertain;
  rc = wyctl_publication_receipt_create (plan, identity, out_receipt);
  if (rc != WYRELOG_E_OK)
    goto published_uncertain;
  switch (stage_exact_hook (backend,
          WYCTL_PUBLICATION_STAGE_EXACT_BEFORE_SUCCESS_RETURN)) {
    case WYCTL_PUBLICATION_STAGE_EXACT_CRASH:
    case WYCTL_PUBLICATION_STAGE_EXACT_FAIL:
      wyctl_publication_receipt_clear (out_receipt);
      goto simulated_crash;
    default:
      break;
  }
  close (temp_fd);
  close_root_anchor (&anchor);
  stage_result_fill (out_result, WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE,
      TRUE, FALSE);
  return WYRELOG_E_OK;

temp_failure:
  cleanup_durable = cleanup_created_stage (&anchor, temp_basename, temp_fd,
      &temp_st);
  close (temp_fd);
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

published_uncertain:
  wyctl_publication_receipt_clear (out_receipt);
  close (temp_fd);
  close_root_anchor (&anchor);
  stage_result_fill (out_result,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
  return WYRELOG_E_OK;

simulated_crash:
  wyctl_publication_receipt_clear (out_receipt);
  close (temp_fd);
  close_root_anchor (&anchor);
  stage_result_fill (out_result,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
  return WYRELOG_E_IO;
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
wyctl_publication_posix_receipt_target_acquire (const
    WyctlPublicationPosixBackend *backend, const WyctlPublicationPlan *plan,
    const WyctlPublicationReceipt *receipt, gboolean require_destination,
    WyctlPublicationReceiptTargetLease **out_lease,
    WyctlPublicationReceiptTargetKind *out_kind)
{
  WyctlPublicationPosixAnchor anchor = { 0 };
  WyctlPublicationReceiptTargetLease *lease = NULL;
  const gchar *basename = plan != NULL ? plan->destination : NULL;
  struct stat st;
  wyrelog_error_t rc;
  int fd = -1;

  if (out_lease == NULL || out_kind == NULL)
    return WYRELOG_E_INVALID;
  *out_lease = NULL;
  *out_kind = WYCTL_PUBLICATION_RECEIPT_TARGET_FOREIGN_OR_UNCERTAIN;
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (plan)
      || !wyctl_publication_receipt_is_valid (receipt))
    return WYRELOG_E_INVALID;

  if (!open_root_anchor (backend, &anchor, &rc))
    return rc;
  if (!receipt_matches_plan_anchor (receipt, plan, &anchor)) {
    close_root_anchor (&anchor);
    return WYRELOG_E_POLICY;
  }

  fd = openat (anchor.dirfd, plan->destination, O_RDONLY | O_CLOEXEC
#ifdef O_NOFOLLOW
      | O_NOFOLLOW
#endif
      );
  if (fd >= 0) {
    gboolean owned = fstat (fd, &st) == 0
        && identity_matches_stat (receipt->stage_identity, &st)
        && stat_is_owner_only_regular (&st, FALSE)
        && named_entry_matches_receipt (anchor.dirfd, plan->destination,
        receipt->stage_identity);
    if (!owned)
      goto foreign;
    goto acquired;
  }
  rc = map_errno_to_error (errno);
  if (rc != WYRELOG_E_NOT_FOUND) {
    close_root_anchor (&anchor);
    return rc;
  }
  if (require_destination) {
    goto foreign;
  }

  basename = plan->stage_basename;
  fd = openat (anchor.dirfd, plan->stage_basename, O_RDONLY | O_CLOEXEC
#ifdef O_NOFOLLOW
      | O_NOFOLLOW
#endif
      );
  if (fd >= 0) {
    gboolean owned = fstat (fd, &st) == 0
        && identity_matches_stat (receipt->stage_identity, &st)
        && stat_is_owner_only_regular (&st, FALSE)
        && named_entry_matches_receipt (anchor.dirfd, plan->stage_basename,
        receipt->stage_identity);
    if (!owned)
      goto foreign;
    goto acquired;
  }
  rc = map_errno_to_error (errno);
  if (rc != WYRELOG_E_NOT_FOUND) {
    close_root_anchor (&anchor);
    return rc;
  }

foreign:
  if (fd >= 0)
    close (fd);
  close_root_anchor (&anchor);
  return WYRELOG_E_OK;

acquired:
  lease = g_new0 (WyctlPublicationReceiptTargetLease, 1);
  if (lease == NULL) {
    close (fd);
    close_root_anchor (&anchor);
    return WYRELOG_E_NOMEM;
  }
  lease->dirfd = anchor.dirfd;
  lease->target_fd = fd;
  lease->root_dir = g_strdup (backend->root_dir);
  lease->basename = g_strdup (basename);
  lease->destination = g_strdup (plan->destination);
  lease->identity = g_strdup (receipt->stage_identity);
  lease->owner = backend;
  lease->destination_target = g_strcmp0 (basename, plan->destination) == 0;
  anchor.dirfd = -1;
  close_root_anchor (&anchor);
  if (lease->root_dir == NULL || lease->basename == NULL
      || lease->destination == NULL || lease->identity == NULL) {
    wyctl_publication_posix_receipt_target_release (backend, lease);
    return WYRELOG_E_NOMEM;
  }
  *out_lease = lease;
  *out_kind = lease->destination_target ?
      WYCTL_PUBLICATION_RECEIPT_TARGET_DESTINATION :
      WYCTL_PUBLICATION_RECEIPT_TARGET_STAGE;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyctl_publication_posix_receipt_target_inspect (const
    WyctlPublicationPosixBackend *backend,
    WyctlPublicationReceiptTargetLease *lease,
    const gchar *expected_credential_id,
    const WyctlSensitiveText *expected_credential_secret,
    WyctlPublicationResult *out_result)
{
  wyrelog_error_t directory_sync_rc = WYRELOG_E_OK;
  gboolean matches = FALSE;
  struct stat st;
  wyrelog_error_t rc;
  wyrelog_error_t target_sync_rc = WYRELOG_E_OK;

  if (out_result == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_result_clear (out_result);
  if (!backend_is_valid (backend) || lease == NULL || lease->owner != backend
      || lease->dirfd < 0
      || lease->target_fd < 0
      || !wyctl_publication_expected_credential_is_valid
      (expected_credential_id, expected_credential_secret))
    return WYRELOG_E_INVALID;
  if (fstat (lease->target_fd, &st) != 0
      || !stat_is_owner_only_regular (&st, FALSE)
      || !identity_matches_stat (lease->identity, &st)
      || !named_entry_matches_receipt (lease->dirfd, lease->basename,
          lease->identity))
    goto foreign;
  if (lseek (lease->target_fd, 0, SEEK_SET) < 0)
    return map_errno_to_error (errno);
  rc = document_matches_expected_fd (lease->target_fd,
      expected_credential_id, expected_credential_secret, &matches);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!matches || !named_entry_matches_receipt (lease->dirfd,
          lease->basename, lease->identity))
    goto foreign;
  lease->inspected_exact = TRUE;
  if (lease->destination_target) {
    target_sync_rc = receipt_target_sync (backend, lease->target_fd,
        WYCTL_PUBLICATION_RECEIPT_TARGET_SYNC_FILE);
    directory_sync_rc = receipt_target_sync (backend, lease->dirfd,
        WYCTL_PUBLICATION_RECEIPT_TARGET_SYNC_DIRECTORY);
    if (!named_entry_matches_receipt (lease->dirfd, lease->basename,
            lease->identity))
      goto foreign;
  }
  if (target_sync_rc != WYRELOG_E_OK || directory_sync_rc != WYRELOG_E_OK) {
    *out_result = (WyctlPublicationResult) {
    .version = WYCTL_PUBLICATION_RESULT_VERSION,.kind =
          WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN,.exact_identity
          = TRUE,};
    return WYRELOG_E_OK;
  }
  *out_result = (WyctlPublicationResult) {
  .version = WYCTL_PUBLICATION_RESULT_VERSION,.kind =
        lease->destination_target ?
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE :
        WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED,.exact_identity =
        TRUE,.cleanup_required = !lease->destination_target,};
  return WYRELOG_E_OK;

foreign:
  lease->inspected_exact = FALSE;
  *out_result = (WyctlPublicationResult) {
  .version = WYCTL_PUBLICATION_RESULT_VERSION,.kind =
        WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN,};
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyctl_publication_posix_receipt_target_commit (const
    WyctlPublicationPosixBackend *backend,
    WyctlPublicationReceiptTargetLease *lease,
    const gchar *expected_credential_id,
    const WyctlSensitiveText *expected_credential_secret,
    WyctlPublicationResult *out_result)
{
  g_autofree gchar *next_basename = NULL;
  gboolean matches = FALSE;
  wyrelog_error_t directory_sync_rc;
  wyrelog_error_t rc;
  wyrelog_error_t target_sync_rc;

  if (out_result == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_result_clear (out_result);
  if (!backend_is_valid (backend) || lease == NULL || lease->owner != backend
      || lease->dirfd < 0
      || lease->target_fd < 0 || lease->destination_target
      || !lease->inspected_exact
      || !wyctl_publication_expected_credential_is_valid
      (expected_credential_id, expected_credential_secret))
    return WYRELOG_E_INVALID;
  if (lseek (lease->target_fd, 0, SEEK_SET) < 0)
    return map_errno_to_error (errno);
  rc = document_matches_expected_fd (lease->target_fd,
      expected_credential_id, expected_credential_secret, &matches);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!matches)
    goto foreign;
  if (!named_entry_matches_receipt (lease->dirfd, lease->basename,
          lease->identity))
    goto foreign;
  next_basename = g_strdup (lease->destination);
  if (next_basename == NULL)
    return WYRELOG_E_NOMEM;
  rc = rename_no_replace (lease->root_dir, lease->dirfd, lease->basename,
      lease->destination);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_free (lease->basename);
  lease->basename = g_steal_pointer (&next_basename);
  lease->destination_target = TRUE;
  target_sync_rc = receipt_target_sync (backend, lease->target_fd,
      WYCTL_PUBLICATION_RECEIPT_TARGET_SYNC_FILE);
  directory_sync_rc = receipt_target_sync (backend, lease->dirfd,
      WYCTL_PUBLICATION_RECEIPT_TARGET_SYNC_DIRECTORY);
  if (!named_entry_matches_receipt (lease->dirfd, lease->basename,
          lease->identity))
    goto foreign;
  *out_result = (WyctlPublicationResult) {
  .version = WYCTL_PUBLICATION_RESULT_VERSION,.kind =
        target_sync_rc == WYRELOG_E_OK
        && directory_sync_rc == WYRELOG_E_OK ?
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE :
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN,.exact_identity
        = TRUE,};
  return WYRELOG_E_OK;

foreign:
  *out_result = (WyctlPublicationResult) {
  .version = WYCTL_PUBLICATION_RESULT_VERSION,.kind =
        WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN,};
  return WYRELOG_E_OK;
}

void
wyctl_publication_posix_receipt_target_release (const
    WyctlPublicationPosixBackend *backend,
    WyctlPublicationReceiptTargetLease *lease)
{
  (void) backend;
  if (lease == NULL)
    return;
  if (lease->target_fd >= 0)
    close (lease->target_fd);
  if (lease->dirfd >= 0)
    close (lease->dirfd);
  g_free (lease->root_dir);
  g_free (lease->basename);
  g_free (lease->destination);
  g_free (lease->identity);
  g_free (lease);
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

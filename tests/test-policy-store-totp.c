/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Unit tests for the policy-store totp_enrollment fact schema and
 * helpers (wyrelog/policy/store.c).
 *
 * Each subject can hold a single TOTP enrollment row carrying:
 *   - secret_blob: raw 20-byte SHA-1 seed (BLOB)
 *   - last_verified_step: replay watermark (gint64, INT64_MIN = never
 *     verified)
 *   - enrolled_at: unix seconds at enroll time
 *   - id_uuidv7: minted via wyl_id_new (libchronoid UUIDv7)
 *
 * The helpers under test are the persistence primitives; higher-level
 * enroll/verify wiring lives in later commits in the #331 series.
 *
 * Footgun coverage these tests exist to lock down:
 *   F2 (secret leak): round-trip preserves seed bytes verbatim, and
 *     the helpers never expose the seed except through the explicit
 *     out_secret buffer.
 *   F3 (replay): update_step persists the watermark monotonically and
 *     it survives a close+reopen of the encrypted store.
 *   F4 (zeroing): the wyl_totp_enrollment_clear helper zeroes the
 *     secret buffer regardless of caller state.
 */

#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700
#endif

#include <stdint.h>
#include <string.h>

#include <glib.h>
#include <glib/gstdio.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-keyprovider-file-private.h"

#ifndef G_OS_WIN32
#include <unistd.h>
#endif

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

static void
fill_seed (guint8 *seed, guint8 base)
{
  for (gsize i = 0; i < WYL_TOTP_ENROLLMENT_SECRET_BYTES; i++)
    seed[i] = (guint8) (base + i);
}

static gint
check_totp_enrollment_table_is_created_on_fresh_store (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 10;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 11;

  gboolean exists = FALSE;
  if (wyl_policy_store_table_exists (store, "totp_enrollments", &exists)
      != WYRELOG_E_OK)
    return 12;
  if (!exists)
    return 13;
  return 0;
}

static gint
check_totp_enrollment_migration_is_idempotent (void)
{
  /* Simulate a pre-#331 store: open a fresh store, create the schema,
   * then DROP the totp_enrollments table to mimic an upgrade path.
   * Re-invoking create_schema must restore the table; a second
   * invocation must remain a no-op (the IF NOT EXISTS contract). */
  g_autoptr (wyl_policy_store_t) store = NULL;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 20;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 21;

  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "DROP TABLE totp_enrollments;", NULL, NULL, NULL) != SQLITE_OK)
    return 22;

  gboolean exists = TRUE;
  if (wyl_policy_store_table_exists (store, "totp_enrollments", &exists)
      != WYRELOG_E_OK)
    return 23;
  if (exists)
    return 24;

  /* First re-application of create_schema: must restore the table. */
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 25;
  if (wyl_policy_store_table_exists (store, "totp_enrollments", &exists)
      != WYRELOG_E_OK)
    return 26;
  if (!exists)
    return 27;

  /* Second application: no-op, still green. */
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 28;
  if (wyl_policy_store_table_exists (store, "totp_enrollments", &exists)
      != WYRELOG_E_OK)
    return 29;
  if (!exists)
    return 30;
  return 0;
}

static gint
check_totp_enrollment_insert_lookup_round_trip (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 40;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 41;

  WylTotpEnrollment enr = { 0 };
  enr.subject_id = g_strdup ("alice.root");
  fill_seed (enr.secret, 0x10);
  enr.last_verified_step = INT64_MIN;
  enr.enrolled_at = 1700000000;
  if (wyl_policy_store_totp_enrollment_insert (store, &enr) != WYRELOG_E_OK) {
    wyl_totp_enrollment_clear (&enr);
    return 42;
  }
  /* Insert must have assigned an id_uuidv7. */
  if (enr.id_uuidv7 == NULL || strlen (enr.id_uuidv7) != 36) {
    wyl_totp_enrollment_clear (&enr);
    return 43;
  }
  gchar *minted_id = g_strdup (enr.id_uuidv7);
  wyl_totp_enrollment_clear (&enr);

  WylTotpEnrollment out = { 0 };
  gboolean found = FALSE;
  if (wyl_policy_store_totp_enrollment_lookup (store, "alice.root", &out,
          &found) != WYRELOG_E_OK) {
    g_free (minted_id);
    wyl_totp_enrollment_clear (&out);
    return 44;
  }
  if (!found) {
    g_free (minted_id);
    wyl_totp_enrollment_clear (&out);
    return 45;
  }
  if (g_strcmp0 (out.subject_id, "alice.root") != 0) {
    g_free (minted_id);
    wyl_totp_enrollment_clear (&out);
    return 46;
  }
  guint8 expected[WYL_TOTP_ENROLLMENT_SECRET_BYTES];
  fill_seed (expected, 0x10);
  if (memcmp (out.secret, expected, sizeof expected) != 0) {
    g_free (minted_id);
    wyl_totp_enrollment_clear (&out);
    return 47;
  }
  if (out.last_verified_step != INT64_MIN) {
    g_free (minted_id);
    wyl_totp_enrollment_clear (&out);
    return 48;
  }
  if (out.enrolled_at != 1700000000) {
    g_free (minted_id);
    wyl_totp_enrollment_clear (&out);
    return 49;
  }
  if (g_strcmp0 (out.id_uuidv7, minted_id) != 0) {
    g_free (minted_id);
    wyl_totp_enrollment_clear (&out);
    return 50;
  }
  g_free (minted_id);
  wyl_totp_enrollment_clear (&out);
  return 0;
}

static gint
check_totp_enrollment_lookup_unknown_subject (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 60;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 61;

  WylTotpEnrollment out = { 0 };
  gboolean found = TRUE;
  if (wyl_policy_store_totp_enrollment_lookup (store, "nobody", &out,
          &found) != WYRELOG_E_OK) {
    wyl_totp_enrollment_clear (&out);
    return 62;
  }
  if (found) {
    wyl_totp_enrollment_clear (&out);
    return 63;
  }
  /* The out struct must remain a zero-initialised shell on miss. */
  if (out.subject_id != NULL || out.id_uuidv7 != NULL) {
    wyl_totp_enrollment_clear (&out);
    return 64;
  }
  wyl_totp_enrollment_clear (&out);
  return 0;
}

static gint
check_totp_enrollment_delete_then_lookup_miss (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 70;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 71;

  WylTotpEnrollment enr = { 0 };
  enr.subject_id = g_strdup ("carol.svc");
  fill_seed (enr.secret, 0x20);
  enr.last_verified_step = INT64_MIN;
  enr.enrolled_at = 1700000100;
  if (wyl_policy_store_totp_enrollment_insert (store, &enr) != WYRELOG_E_OK) {
    wyl_totp_enrollment_clear (&enr);
    return 72;
  }
  wyl_totp_enrollment_clear (&enr);

  if (wyl_policy_store_totp_enrollment_delete (store, "carol.svc")
      != WYRELOG_E_OK)
    return 73;

  WylTotpEnrollment out = { 0 };
  gboolean found = TRUE;
  if (wyl_policy_store_totp_enrollment_lookup (store, "carol.svc", &out,
          &found) != WYRELOG_E_OK) {
    wyl_totp_enrollment_clear (&out);
    return 74;
  }
  if (found) {
    wyl_totp_enrollment_clear (&out);
    return 75;
  }
  wyl_totp_enrollment_clear (&out);

  /* Re-deleting an absent row is a no-op, not an error. */
  if (wyl_policy_store_totp_enrollment_delete (store, "carol.svc")
      != WYRELOG_E_OK)
    return 76;
  return 0;
}

static gint
check_totp_enrollment_update_step_durability (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *tmpdir = g_dir_make_tmp ("wyl-policy-totp-XXXXXX", &error);
  if (tmpdir == NULL)
    return 80;
  g_autofree gchar *store_path =
      g_build_filename (tmpdir, "policy.store", NULL);
  g_autofree gchar *key_path = g_build_filename (tmpdir, "policy.key", NULL);
  if (!write_policy_key (key_path, 17))
    return 81;

  /* Pass 1: insert an enrollment, advance the replay watermark. */
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    if (open_encrypted_policy_store (store_path, key_path, &store)
        != WYRELOG_E_OK)
      return 82;
    if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
      return 83;

    WylTotpEnrollment enr = { 0 };
    enr.subject_id = g_strdup ("bob.admin");
    fill_seed (enr.secret, 0x30);
    enr.last_verified_step = INT64_MIN;
    enr.enrolled_at = 1700000200;
    if (wyl_policy_store_totp_enrollment_insert (store, &enr)
        != WYRELOG_E_OK) {
      wyl_totp_enrollment_clear (&enr);
      return 84;
    }
    wyl_totp_enrollment_clear (&enr);

    if (wyl_policy_store_totp_enrollment_update_step (store, "bob.admin",
            56700000) != WYRELOG_E_OK)
      return 85;
  }

  /* Pass 2: reopen and confirm the watermark survived. */
  {
    g_autoptr (wyl_policy_store_t) store = NULL;
    if (open_encrypted_policy_store (store_path, key_path, &store)
        != WYRELOG_E_OK)
      return 86;
    if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
      return 87;
    WylTotpEnrollment out = { 0 };
    gboolean found = FALSE;
    if (wyl_policy_store_totp_enrollment_lookup (store, "bob.admin", &out,
            &found) != WYRELOG_E_OK) {
      wyl_totp_enrollment_clear (&out);
      return 88;
    }
    if (!found) {
      wyl_totp_enrollment_clear (&out);
      return 89;
    }
    if (out.last_verified_step != 56700000) {
      wyl_totp_enrollment_clear (&out);
      return 90;
    }
    guint8 expected[WYL_TOTP_ENROLLMENT_SECRET_BYTES];
    fill_seed (expected, 0x30);
    if (memcmp (out.secret, expected, sizeof expected) != 0) {
      wyl_totp_enrollment_clear (&out);
      return 91;
    }
    wyl_totp_enrollment_clear (&out);
  }

  (void) g_remove (store_path);
  (void) g_remove (key_path);
  (void) g_rmdir (tmpdir);
  return 0;
}

static gint
check_totp_enrollment_two_subjects_isolated (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 100;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 101;

  WylTotpEnrollment enr_a = { 0 };
  enr_a.subject_id = g_strdup ("subject.a");
  fill_seed (enr_a.secret, 0x40);
  enr_a.last_verified_step = INT64_MIN;
  enr_a.enrolled_at = 1700000300;
  if (wyl_policy_store_totp_enrollment_insert (store, &enr_a)
      != WYRELOG_E_OK) {
    wyl_totp_enrollment_clear (&enr_a);
    return 102;
  }
  wyl_totp_enrollment_clear (&enr_a);

  WylTotpEnrollment enr_b = { 0 };
  enr_b.subject_id = g_strdup ("subject.b");
  fill_seed (enr_b.secret, 0x70);
  enr_b.last_verified_step = INT64_MIN;
  enr_b.enrolled_at = 1700000400;
  if (wyl_policy_store_totp_enrollment_insert (store, &enr_b)
      != WYRELOG_E_OK) {
    wyl_totp_enrollment_clear (&enr_b);
    return 103;
  }
  wyl_totp_enrollment_clear (&enr_b);

  /* Advance only subject.a; subject.b must remain at INT64_MIN. */
  if (wyl_policy_store_totp_enrollment_update_step (store, "subject.a", 42)
      != WYRELOG_E_OK)
    return 104;

  WylTotpEnrollment out_a = { 0 };
  WylTotpEnrollment out_b = { 0 };
  gboolean found_a = FALSE;
  gboolean found_b = FALSE;
  if (wyl_policy_store_totp_enrollment_lookup (store, "subject.a", &out_a,
          &found_a) != WYRELOG_E_OK || !found_a) {
    wyl_totp_enrollment_clear (&out_a);
    return 105;
  }
  if (wyl_policy_store_totp_enrollment_lookup (store, "subject.b", &out_b,
          &found_b) != WYRELOG_E_OK || !found_b) {
    wyl_totp_enrollment_clear (&out_a);
    wyl_totp_enrollment_clear (&out_b);
    return 106;
  }
  if (out_a.last_verified_step != 42 || out_b.last_verified_step != INT64_MIN) {
    wyl_totp_enrollment_clear (&out_a);
    wyl_totp_enrollment_clear (&out_b);
    return 107;
  }
  guint8 exp_a[WYL_TOTP_ENROLLMENT_SECRET_BYTES];
  guint8 exp_b[WYL_TOTP_ENROLLMENT_SECRET_BYTES];
  fill_seed (exp_a, 0x40);
  fill_seed (exp_b, 0x70);
  if (memcmp (out_a.secret, exp_a, sizeof exp_a) != 0
      || memcmp (out_b.secret, exp_b, sizeof exp_b) != 0) {
    wyl_totp_enrollment_clear (&out_a);
    wyl_totp_enrollment_clear (&out_b);
    return 108;
  }
  if (g_strcmp0 (out_a.id_uuidv7, out_b.id_uuidv7) == 0) {
    /* IDs must differ. */
    wyl_totp_enrollment_clear (&out_a);
    wyl_totp_enrollment_clear (&out_b);
    return 109;
  }
  wyl_totp_enrollment_clear (&out_a);
  wyl_totp_enrollment_clear (&out_b);
  return 0;
}

static gint
check_totp_enrollment_utf8_subject_id (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 120;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 121;

  /* U+00E9 LATIN SMALL LETTER E WITH ACUTE plus a CJK ideograph; the
   * helpers must round-trip the bytes verbatim through SQLite TEXT. */
  const gchar *subject = "user.\xc3\xa9.\xe4\xb8\xad";

  WylTotpEnrollment enr = { 0 };
  enr.subject_id = g_strdup (subject);
  fill_seed (enr.secret, 0x55);
  enr.last_verified_step = INT64_MIN;
  enr.enrolled_at = 1700000500;
  if (wyl_policy_store_totp_enrollment_insert (store, &enr) != WYRELOG_E_OK) {
    wyl_totp_enrollment_clear (&enr);
    return 122;
  }
  wyl_totp_enrollment_clear (&enr);

  WylTotpEnrollment out = { 0 };
  gboolean found = FALSE;
  if (wyl_policy_store_totp_enrollment_lookup (store, subject, &out, &found)
      != WYRELOG_E_OK) {
    wyl_totp_enrollment_clear (&out);
    return 123;
  }
  if (!found) {
    wyl_totp_enrollment_clear (&out);
    return 124;
  }
  if (g_strcmp0 (out.subject_id, subject) != 0) {
    wyl_totp_enrollment_clear (&out);
    return 125;
  }
  wyl_totp_enrollment_clear (&out);
  return 0;
}

static gint
check_totp_enrollment_clear_zeros_secret (void)
{
  /* wyl_totp_enrollment_clear must zero the secret buffer even when
   * subject_id/id_uuidv7 are NULL (i.e. on an uninitialised stack
   * struct) and must tolerate a NULL pointer. */
  wyl_totp_enrollment_clear (NULL);

  WylTotpEnrollment enr = { 0 };
  fill_seed (enr.secret, 0x77);
  wyl_totp_enrollment_clear (&enr);
  for (gsize i = 0; i < WYL_TOTP_ENROLLMENT_SECRET_BYTES; i++) {
    if (enr.secret[i] != 0)
      return 130;
  }
  return 0;
}

static gint
check_totp_enrollment_rejects_invalid_args (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 140;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 141;

  WylTotpEnrollment enr = { 0 };
  enr.subject_id = g_strdup ("victim");
  fill_seed (enr.secret, 0x88);
  if (wyl_policy_store_totp_enrollment_insert (NULL, &enr)
      != WYRELOG_E_INVALID) {
    wyl_totp_enrollment_clear (&enr);
    return 142;
  }
  if (wyl_policy_store_totp_enrollment_insert (store, NULL)
      != WYRELOG_E_INVALID) {
    wyl_totp_enrollment_clear (&enr);
    return 143;
  }
  wyl_totp_enrollment_clear (&enr);

  WylTotpEnrollment with_empty_subject = { 0 };
  with_empty_subject.subject_id = g_strdup ("");
  fill_seed (with_empty_subject.secret, 0x99);
  if (wyl_policy_store_totp_enrollment_insert (store, &with_empty_subject)
      != WYRELOG_E_INVALID) {
    wyl_totp_enrollment_clear (&with_empty_subject);
    return 144;
  }
  wyl_totp_enrollment_clear (&with_empty_subject);

  WylTotpEnrollment out = { 0 };
  gboolean found = FALSE;
  if (wyl_policy_store_totp_enrollment_lookup (NULL, "x", &out, &found)
      != WYRELOG_E_INVALID)
    return 145;
  if (wyl_policy_store_totp_enrollment_lookup (store, NULL, &out, &found)
      != WYRELOG_E_INVALID)
    return 146;
  if (wyl_policy_store_totp_enrollment_lookup (store, "x", NULL, &found)
      != WYRELOG_E_INVALID)
    return 147;
  if (wyl_policy_store_totp_enrollment_lookup (store, "x", &out, NULL)
      != WYRELOG_E_INVALID)
    return 148;

  if (wyl_policy_store_totp_enrollment_update_step (NULL, "x", 0)
      != WYRELOG_E_INVALID)
    return 149;
  if (wyl_policy_store_totp_enrollment_update_step (store, NULL, 0)
      != WYRELOG_E_INVALID)
    return 150;

  if (wyl_policy_store_totp_enrollment_delete (NULL, "x")
      != WYRELOG_E_INVALID)
    return 151;
  if (wyl_policy_store_totp_enrollment_delete (store, NULL)
      != WYRELOG_E_INVALID)
    return 152;
  return 0;
}

static gint
check_totp_enrollment_insert_replaces_existing (void)
{
  /* Re-enrolling the same subject overwrites the prior row in place
   * (subject_id is the primary key). This is the contract that the
   * eventual wyctl mfa reset path relies on. */
  g_autoptr (wyl_policy_store_t) store = NULL;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 160;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 161;

  WylTotpEnrollment first = { 0 };
  first.subject_id = g_strdup ("rotator");
  fill_seed (first.secret, 0xA0);
  first.last_verified_step = INT64_MIN;
  first.enrolled_at = 1700000600;
  if (wyl_policy_store_totp_enrollment_insert (store, &first)
      != WYRELOG_E_OK) {
    wyl_totp_enrollment_clear (&first);
    return 162;
  }
  wyl_totp_enrollment_clear (&first);

  /* Advance the step so we can prove the replace resets it. */
  if (wyl_policy_store_totp_enrollment_update_step (store, "rotator", 100)
      != WYRELOG_E_OK)
    return 163;

  WylTotpEnrollment second = { 0 };
  second.subject_id = g_strdup ("rotator");
  fill_seed (second.secret, 0xB0);
  second.last_verified_step = INT64_MIN;
  second.enrolled_at = 1700000700;
  if (wyl_policy_store_totp_enrollment_insert (store, &second)
      != WYRELOG_E_OK) {
    wyl_totp_enrollment_clear (&second);
    return 164;
  }
  wyl_totp_enrollment_clear (&second);

  WylTotpEnrollment out = { 0 };
  gboolean found = FALSE;
  if (wyl_policy_store_totp_enrollment_lookup (store, "rotator", &out,
          &found) != WYRELOG_E_OK || !found) {
    wyl_totp_enrollment_clear (&out);
    return 165;
  }
  guint8 expected[WYL_TOTP_ENROLLMENT_SECRET_BYTES];
  fill_seed (expected, 0xB0);
  if (memcmp (out.secret, expected, sizeof expected) != 0) {
    wyl_totp_enrollment_clear (&out);
    return 166;
  }
  /* The replay watermark must reset to INT64_MIN: the new seed has no
   * prior verifications. */
  if (out.last_verified_step != INT64_MIN) {
    wyl_totp_enrollment_clear (&out);
    return 167;
  }
  if (out.enrolled_at != 1700000700) {
    wyl_totp_enrollment_clear (&out);
    return 168;
  }
  wyl_totp_enrollment_clear (&out);
  return 0;
}

static gint
check_totp_enrollment_update_step_absent_subject_is_noop (void)
{
  /* Locks the documented contract at store-private.h:533-542:
   * update_step against a subject with no enrollment row returns
   * WYRELOG_E_OK without creating a row.  The commit-3 transactional
   * verify path layers on top of this no-op behaviour. */
  g_autoptr (wyl_policy_store_t) store = NULL;
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 180;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 181;

  if (wyl_policy_store_totp_enrollment_update_step (store, "never-enrolled", 5)
      != WYRELOG_E_OK)
    return 182;

  WylTotpEnrollment out = { 0 };
  gboolean found = TRUE;
  if (wyl_policy_store_totp_enrollment_lookup (store, "never-enrolled", &out,
          &found) != WYRELOG_E_OK) {
    wyl_totp_enrollment_clear (&out);
    return 183;
  }
  if (found) {
    wyl_totp_enrollment_clear (&out);
    return 184;
  }
  wyl_totp_enrollment_clear (&out);
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_totp_enrollment_table_is_created_on_fresh_store ()) != 0)
    return rc;
  if ((rc = check_totp_enrollment_migration_is_idempotent ()) != 0)
    return rc;
  if ((rc = check_totp_enrollment_insert_lookup_round_trip ()) != 0)
    return rc;
  if ((rc = check_totp_enrollment_lookup_unknown_subject ()) != 0)
    return rc;
  if ((rc = check_totp_enrollment_delete_then_lookup_miss ()) != 0)
    return rc;
  if ((rc = check_totp_enrollment_update_step_durability ()) != 0)
    return rc;
  if ((rc = check_totp_enrollment_two_subjects_isolated ()) != 0)
    return rc;
  if ((rc = check_totp_enrollment_utf8_subject_id ()) != 0)
    return rc;
  if ((rc = check_totp_enrollment_clear_zeros_secret ()) != 0)
    return rc;
  if ((rc = check_totp_enrollment_rejects_invalid_args ()) != 0)
    return rc;
  if ((rc = check_totp_enrollment_insert_replaces_existing ()) != 0)
    return rc;
  if ((rc = check_totp_enrollment_update_step_absent_subject_is_noop ()) != 0)
    return rc;
  return 0;
}

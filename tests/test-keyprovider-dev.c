/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "wyrelog/wyl-keyprovider-dev-private.h"

/* --- Round-trip tests ------------------------------------------- */

static gint
check_probe_ok_on_fresh (void)
{
  g_autoptr (wyl_keyprovider_dev_t) self = wyl_keyprovider_dev_new ();
  const wyl_keyprovider_vtable_t *vt = wyl_keyprovider_dev_get_vtable ();
  if (vt->probe (self) != WYRELOG_E_OK)
    return 1;
  return 0;
}

static gint
roundtrip_for (const guint8 *plaintext, gsize plaintext_len)
{
  g_autoptr (wyl_keyprovider_dev_t) self = wyl_keyprovider_dev_new ();
  const wyl_keyprovider_vtable_t *vt = wyl_keyprovider_dev_get_vtable ();
  wyl_sealed_blob_t blob = { 0 };
  if (vt->seal (self, plaintext, plaintext_len, &blob) != WYRELOG_E_OK)
    return 10;
  if (blob.len != plaintext_len)
    return 11;
  if (plaintext_len > 0 && blob.bytes == NULL)
    return 12;

  /* Ciphertext must differ from plaintext (proves XOR is exercised)
   * for non-empty inputs whose first key byte is nonzero. */
  if (plaintext_len > 0 && memcmp (blob.bytes, plaintext, plaintext_len) == 0)
    return 13;

  g_autofree guint8 *recovered = g_malloc (plaintext_len + 1);
  recovered[plaintext_len] = 0xCC;      /* canary */
  gsize written = 0;
  if (vt->unseal (self, &blob, recovered, plaintext_len,
          &written) != WYRELOG_E_OK)
    return 14;
  if (written != plaintext_len)
    return 15;
  if (recovered[plaintext_len] != 0xCC)
    return 16;
  if (plaintext_len > 0 && memcmp (recovered, plaintext, plaintext_len) != 0)
    return 17;

  g_free (blob.bytes);
  return 0;
}

static gint
check_roundtrip_basic (void)
{
  const guint8 *plaintext = (const guint8 *) "hello world";
  gint rc = roundtrip_for (plaintext, strlen ((const gchar *) plaintext));
  return (rc == 0) ? 0 : (20 + rc);
}

static gint
check_roundtrip_binary (void)
{
  guint8 plaintext[256];
  for (gsize i = 0; i < 256; i++)
    plaintext[i] = (guint8) i;
  gint rc = roundtrip_for (plaintext, 256);
  return (rc == 0) ? 0 : (40 + rc);
}

/* --- Capacity check fail-closed --------------------------------- */

static gint
check_unseal_capacity_too_small (void)
{
  g_autoptr (wyl_keyprovider_dev_t) self = wyl_keyprovider_dev_new ();
  const wyl_keyprovider_vtable_t *vt = wyl_keyprovider_dev_get_vtable ();
  const guint8 plaintext[] = { 1, 2, 3, 4, 5 };
  wyl_sealed_blob_t blob = { 0 };
  if (vt->seal (self, plaintext, sizeof (plaintext), &blob) != WYRELOG_E_OK)
    return 60;

  guint8 small_buf[3];
  memset (small_buf, 0xAA, sizeof (small_buf));
  gsize written = 0xDEAD;
  wyrelog_error_t rc = vt->unseal (self, &blob, small_buf, 3, &written);
  if (rc == WYRELOG_E_OK)
    return 61;
  /* On invalid: out parameters must be untouched. */
  if (small_buf[0] != 0xAA || small_buf[1] != 0xAA || small_buf[2] != 0xAA)
    return 62;
  if (written != 0xDEAD)
    return 63;

  g_free (blob.bytes);
  return 0;
}

/* --- derive determinism + label distinctness ------------------- */

static gint
check_derive_determinism (void)
{
  g_autoptr (wyl_keyprovider_dev_t) self = wyl_keyprovider_dev_new ();
  const wyl_keyprovider_vtable_t *vt = wyl_keyprovider_dev_get_vtable ();
  guint8 a1[16], a2[16], b[16];
  if (vt->derive (self, "label_a", a1, sizeof (a1)) != WYRELOG_E_OK)
    return 70;
  if (vt->derive (self, "label_a", a2, sizeof (a2)) != WYRELOG_E_OK)
    return 71;
  if (memcmp (a1, a2, sizeof (a1)) != 0)
    return 72;
  if (vt->derive (self, "label_b", b, sizeof (b)) != WYRELOG_E_OK)
    return 73;
  if (memcmp (a1, b, sizeof (a1)) == 0)
    return 74;
  return 0;
}

/* --- Wipe semantics: all ops fail-closed ------------------------ */

static gint
check_wipe_fail_closed (void)
{
  g_autoptr (wyl_keyprovider_dev_t) self = wyl_keyprovider_dev_new ();
  const wyl_keyprovider_vtable_t *vt = wyl_keyprovider_dev_get_vtable ();
  vt->wipe (self);

  if (vt->probe (self) != WYRELOG_E_INTERNAL)
    return 80;

  const guint8 plaintext[] = { 0xFF };
  wyl_sealed_blob_t blob = { 0 };
  if (vt->seal (self, plaintext, 1, &blob) != WYRELOG_E_INTERNAL)
    return 81;
  /* On internal: out_blob must be untouched. */
  if (blob.bytes != NULL || blob.len != 0)
    return 82;

  guint8 buf[1] = { 0xAA };
  gsize written = 0xBEEF;
  wyl_sealed_blob_t fake = {.bytes = (guint8 *) plaintext,.len = 1 };
  if (vt->unseal (self, &fake, buf, sizeof (buf), &written)
      != WYRELOG_E_INTERNAL)
    return 83;
  if (buf[0] != 0xAA || written != 0xBEEF)
    return 84;

  guint8 dk[8];
  memset (dk, 0xAA, sizeof (dk));
  if (vt->derive (self, "anything", dk, sizeof (dk)) != WYRELOG_E_INTERNAL)
    return 85;
  for (gsize i = 0; i < sizeof (dk); i++) {
    if (dk[i] != 0xAA)
      return 86;
  }

  /* Double wipe must be a no-op. */
  vt->wipe (self);
  if (vt->probe (self) != WYRELOG_E_INTERNAL)
    return 87;
  return 0;
}

/* --- Argument validation --------------------------------------- */

static gint
check_argument_validation (void)
{
  g_autoptr (wyl_keyprovider_dev_t) self = wyl_keyprovider_dev_new ();
  const wyl_keyprovider_vtable_t *vt = wyl_keyprovider_dev_get_vtable ();

  if (vt->probe (NULL) != WYRELOG_E_INVALID)
    return 100;
  wyl_sealed_blob_t blob = { 0 };
  if (vt->seal (self, NULL, 4, &blob) != WYRELOG_E_INVALID)
    return 101;
  if (vt->seal (self, (const guint8 *) "x", 1, NULL) != WYRELOG_E_INVALID)
    return 102;

  guint8 buf[8];
  gsize written = 0;
  if (vt->unseal (self, NULL, buf, sizeof (buf), &written)
      != WYRELOG_E_INVALID)
    return 103;
  if (vt->unseal (self, &blob, buf, sizeof (buf), NULL) != WYRELOG_E_INVALID)
    return 104;

  guint8 dk[4];
  if (vt->derive (self, NULL, dk, sizeof (dk)) != WYRELOG_E_INVALID)
    return 105;
  if (vt->derive (self, "x", NULL, 4) != WYRELOG_E_INVALID)
    return 106;
  return 0;
}

int
main (void)
{
  gint rc;
  if ((rc = check_probe_ok_on_fresh ()) != 0)
    return rc;
  if ((rc = check_roundtrip_basic ()) != 0)
    return rc;
  if ((rc = check_roundtrip_binary ()) != 0)
    return rc;
  if ((rc = check_unseal_capacity_too_small ()) != 0)
    return rc;
  if ((rc = check_derive_determinism ()) != 0)
    return rc;
  if ((rc = check_wipe_fail_closed ()) != 0)
    return rc;
  if ((rc = check_argument_validation ()) != 0)
    return rc;
  return 0;
}

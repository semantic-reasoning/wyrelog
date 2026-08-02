/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Test helper for the packaged service-credential lifecycle e2e harness. The
 * lifecycle CLI operates on an encrypted policy store, so the shell harness
 * cannot read authoritative credential rows with sqlite3 directly. This helper
 * opens the store under its owner-only KeyProvider and prints one credential's
 * NON-SECRET authoritative fields:
 *
 *   <policy.sqlite> <policy.key> <credential_id>
 *       print "state=<...> generation=<N> verifier=<64-hex> salt=<32-hex>"
 *       for the named credential; exit 0 on found, non-zero on not-found or
 *       open failure.
 *
 * Only the allow-listed salt/verifier columns are read; the plaintext secret
 * and the CVK are never in wyl_policy_service_credential_info_t and are never
 * touched. The offline open takes a maintenance-exclusive lease and returns
 * WYRELOG_E_BUSY while the daemon holds the store, so this helper is only ever
 * invoked while the daemon is STOPPED.
 */
#if defined(__unix__) || defined(__APPLE__)
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#endif

#include <glib.h>
#include <stdio.h>
#include <string.h>

#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-keyprovider-file-private.h"

static wyl_policy_store_t *
open_store (const gchar *store_path, const gchar *key_path)
{
  wyl_keyprovider_file_t *keyprovider = wyl_keyprovider_file_new (key_path);
  if (keyprovider == NULL) {
    g_printerr ("store-inspect: cannot mint keyprovider from %s\n", key_path);
    return NULL;
  }
  wyl_policy_store_open_options_t opts = {
    .path = store_path,
    .keyprovider_vtable = wyl_keyprovider_file_get_vtable (),
    .keyprovider_state = keyprovider,
    .keyprovider_state_free = (void (*)(gpointer)) wyl_keyprovider_file_free,
    .require_encrypted = TRUE,
  };
  wyl_policy_store_t *store = NULL;
  wyrelog_error_t rc = wyl_policy_store_open_with_options (&opts, &store);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("store-inspect: open %s failed: %s\n", store_path,
        wyrelog_error_string (rc));
    return NULL;
  }
  return store;
}

static void
append_hex (GString *out, const guint8 *bytes, gsize len)
{
  for (gsize i = 0; i < len; i++)
    g_string_append_printf (out, "%02x", bytes[i]);
}

int
main (int argc, char **argv)
{
  if (argc != 4) {
    g_printerr ("usage: %s <policy.sqlite> <policy.key> <credential_id>\n",
        argv[0]);
    return 2;
  }
  const gchar *store_path = argv[1];
  const gchar *key_path = argv[2];
  const gchar *credential_id = argv[3];

  wyl_policy_store_t *store = open_store (store_path, key_path);
  if (store == NULL)
    return 1;

  wyl_policy_service_credential_info_t info = { 0 };
  wyrelog_error_t rc =
      wyl_policy_store_lookup_service_credential_by_id (store, credential_id,
      &info);
  wyl_policy_store_close (store);

  if (rc != WYRELOG_E_OK) {
    g_printerr ("store-inspect: lookup %s failed: %s\n", credential_id,
        wyrelog_error_string (rc));
    wyl_policy_service_credential_info_clear (&info);
    return 1;
  }

  GString *salt_hex = g_string_new (NULL);
  GString *verifier_hex = g_string_new (NULL);
  append_hex (salt_hex, info.salt, sizeof (info.salt));
  append_hex (verifier_hex, info.verifier, sizeof (info.verifier));

  g_print ("state=%s generation=%" G_GUINT64_FORMAT " verifier=%s salt=%s\n",
      info.state != NULL ? info.state : "", info.generation,
      verifier_hex->str, salt_hex->str);

  g_string_free (salt_hex, TRUE);
  g_string_free (verifier_hex, TRUE);
  wyl_policy_service_credential_info_clear (&info);
  return 0;
}

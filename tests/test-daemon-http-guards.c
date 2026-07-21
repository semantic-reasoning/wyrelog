/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <glib.h>
#include <gio/gio.h>
#include <libsoup/soup.h>

#include "wyrelog/daemon/http-guards-private.h"

static void
test_loopback_predicate (void)
{
  g_autoptr (GInetAddress) loop_v4 =
      g_inet_address_new_loopback (G_SOCKET_FAMILY_IPV4);
  g_autoptr (GInetAddress) loop_v6 =
      g_inet_address_new_loopback (G_SOCKET_FAMILY_IPV6);
  g_autoptr (GInetAddress) ext = g_inet_address_new_from_string ("8.8.8.8");
  g_autoptr (GInetAddress) private_addr =
      g_inet_address_new_from_string ("192.168.1.10");
  g_autoptr (GInetAddress) mapped =
      g_inet_address_new_from_string ("::ffff:8.8.8.8");
  g_autoptr (GInetAddress) unspecified =
      g_inet_address_new_from_string ("0.0.0.0");
  g_assert_nonnull (loop_v4);
  g_assert_nonnull (loop_v6);
  g_assert_nonnull (ext);
  g_assert_nonnull (private_addr);
  g_assert_nonnull (mapped);
  g_assert_nonnull (unspecified);
  g_autoptr (GSocketAddress) loop_v4_sock =
      G_SOCKET_ADDRESS (g_inet_socket_address_new (loop_v4, 8080));
  g_autoptr (GSocketAddress) loop_v6_sock =
      G_SOCKET_ADDRESS (g_inet_socket_address_new (loop_v6, 8080));
  g_autoptr (GSocketAddress) ext_sock =
      G_SOCKET_ADDRESS (g_inet_socket_address_new (ext, 8080));
  g_autoptr (GSocketAddress) private_sock =
      G_SOCKET_ADDRESS (g_inet_socket_address_new (private_addr, 8080));
  g_autoptr (GSocketAddress) mapped_sock =
      G_SOCKET_ADDRESS (g_inet_socket_address_new (mapped, 8080));
  g_autoptr (GSocketAddress) unspecified_sock =
      G_SOCKET_ADDRESS (g_inet_socket_address_new (unspecified, 8080));
  g_autoptr (GSocketAddress) unix_sock = NULL;
#ifndef G_OS_WIN32
  unix_sock = G_SOCKET_ADDRESS (g_unix_socket_address_new
      ("/tmp/wyrelog-guard.sock"));
#endif

  g_assert_true (wyl_daemon_http_socket_addresses_are_actual_loopback
      (loop_v4_sock, loop_v6_sock));
  g_assert_true (wyl_daemon_http_socket_addresses_are_actual_loopback
      (loop_v6_sock, loop_v4_sock));
  g_assert_false (wyl_daemon_http_socket_addresses_are_actual_loopback
      (loop_v4_sock, ext_sock));
  g_assert_false (wyl_daemon_http_socket_addresses_are_actual_loopback
      (ext_sock, loop_v4_sock));
  g_assert_false (wyl_daemon_http_socket_addresses_are_actual_loopback
      (loop_v4_sock, private_sock));
  g_assert_false (wyl_daemon_http_socket_addresses_are_actual_loopback
      (loop_v4_sock, mapped_sock));
  g_assert_false (wyl_daemon_http_socket_addresses_are_actual_loopback
      (loop_v4_sock, unspecified_sock));
  if (unix_sock != NULL) {
    g_assert_false (wyl_daemon_http_socket_addresses_are_actual_loopback
        (unix_sock, loop_v4_sock));
  }
  g_assert_false (wyl_daemon_http_socket_addresses_are_actual_loopback
      (loop_v4_sock, NULL));
  g_assert_false (wyl_daemon_http_socket_addresses_are_actual_loopback
      (NULL, loop_v4_sock));
}

static void
test_strict_json_object_parser (void)
{
  const WylDaemonHttpStrictJsonField fields[] = {
    {"subject", 64, WYL_DAEMON_HTTP_STRICT_JSON_STRING},
    {"tenant", 64, WYL_DAEMON_HTTP_STRICT_JSON_STRING},
  };
  gchar *values[G_N_ELEMENTS (fields)] = { NULL, NULL };

  g_assert_true (wyl_daemon_http_dup_strict_json_object
      ("{\"subject\":\"svc:jobs:worker\",\"tenant\":\"tenant-a\"}",
          strlen ("{\"subject\":\"svc:jobs:worker\",\"tenant\":\"tenant-a\"}"),
          fields, G_N_ELEMENTS (fields), values));
  g_assert_cmpstr (values[0], ==, "svc:jobs:worker");
  g_assert_cmpstr (values[1], ==, "tenant-a");
  wyl_daemon_http_clear_strv (values, G_N_ELEMENTS (values));

  const gchar *escaped =
      "{\"subject\":\"svc:\\u006aobs:worker\",\"tenant\":\"tenant-a\"}";
  g_assert_true (wyl_daemon_http_dup_strict_json_object (escaped,
          strlen (escaped), fields, G_N_ELEMENTS (fields), values));
  g_assert_cmpstr (values[0], ==, "svc:jobs:worker");
  wyl_daemon_http_clear_strv (values, G_N_ELEMENTS (values));

  const gchar *duplicate =
      "{\"subject\":\"a\",\"subject\":\"b\",\"tenant\":\"tenant-a\"}";
  g_assert_false (wyl_daemon_http_dup_strict_json_object (duplicate,
          strlen (duplicate), fields, G_N_ELEMENTS (fields), values));
  g_assert_null (values[0]);
  g_assert_null (values[1]);

  const gchar *unknown =
      "{\"subject\":\"a\",\"tenant\":\"tenant-a\",\"extra\":\"nope\"}";
  g_assert_false (wyl_daemon_http_dup_strict_json_object (unknown,
          strlen (unknown), fields, G_N_ELEMENTS (fields), values));

  const gchar *nested = "{\"subject\":{\"bad\":true},\"tenant\":\"tenant-a\"}";
  g_assert_false (wyl_daemon_http_dup_strict_json_object (nested,
          strlen (nested), fields, G_N_ELEMENTS (fields), values));

  const gchar *array_value = "{\"subject\":[\"bad\"],\"tenant\":\"tenant-a\"}";
  g_assert_false (wyl_daemon_http_dup_strict_json_object (array_value,
          strlen (array_value), fields, G_N_ELEMENTS (fields), values));

  const gchar *trailing = "{\"subject\":\"a\",\"tenant\":\"tenant-a\"}  x";
  g_assert_false (wyl_daemon_http_dup_strict_json_object (trailing,
          strlen (trailing), fields, G_N_ELEMENTS (fields), values));

  const gchar *bad_utf8 = "{\"subject\":\"\xC3\x28\",\"tenant\":\"tenant-a\"}";
  g_assert_false (wyl_daemon_http_dup_strict_json_object (bad_utf8,
          strlen (bad_utf8), fields, G_N_ELEMENTS (fields), values));

  const gchar *nul_escape =
      "{\"subject\":\"a\\u0000b\",\"tenant\":\"tenant-a\"}";
  g_assert_false (wyl_daemon_http_dup_strict_json_object (nul_escape,
          strlen (nul_escape), fields, G_N_ELEMENTS (fields), values));

  gchar oversize[16 * 1024 + 8];
  memset (oversize, 'a', sizeof oversize);
  memcpy (oversize, "{\"subject\":\"", 12);
  memcpy (oversize + sizeof oversize - 14, "\"}", 2);
  oversize[sizeof oversize - 12] = '\0';
  g_assert_false (wyl_daemon_http_dup_strict_json_object (oversize,
          sizeof oversize - 1, fields, G_N_ELEMENTS (fields), values));

  gchar embedded_nul[] = "{\"subject\":\"a\",\"\0tenant\":\"tenant-a\"}";
  g_assert_false (wyl_daemon_http_dup_strict_json_object (embedded_nul,
          sizeof embedded_nul - 1, fields, G_N_ELEMENTS (fields), values));
}

static void
test_strict_json_typed_int (void)
{
  const WylDaemonHttpStrictJsonField fields[] = {
    {"event", 128, WYL_DAEMON_HTTP_STRICT_JSON_STRING},
    {"timestamp_us", 32, WYL_DAEMON_HTTP_STRICT_JSON_INT64},
  };
  gchar *values[G_N_ELEMENTS (fields)] = { NULL, NULL };

  /* A valid non-negative int64 that overflows guint parses and is stored
   * as its canonical decimal string. */
  const gchar *ok = "{\"event\":\"startup\",\"timestamp_us\":1750000000000000}";
  g_assert_true (wyl_daemon_http_dup_strict_json_object (ok, strlen (ok),
          fields, G_N_ELEMENTS (fields), values));
  g_assert_cmpstr (values[0], ==, "startup");
  g_assert_cmpstr (values[1], ==, "1750000000000000");
  wyl_daemon_http_clear_strv (values, G_N_ELEMENTS (values));

  /* Zero is a valid non-negative value. */
  const gchar *zero = "{\"event\":\"e\",\"timestamp_us\":0}";
  g_assert_true (wyl_daemon_http_dup_strict_json_object (zero, strlen (zero),
          fields, G_N_ELEMENTS (fields), values));
  g_assert_cmpstr (values[1], ==, "0");
  wyl_daemon_http_clear_strv (values, G_N_ELEMENTS (values));

  static const gchar *reject[] = {
    "{\"event\":\"e\",\"timestamp_us\":-1}",    /* negative */
    "{\"event\":\"e\",\"timestamp_us\":+1}",    /* leading plus */
    "{\"event\":\"e\",\"timestamp_us\":\"5\"}", /* quoted int */
    "{\"event\":\"e\",\"timestamp_us\":abc}",   /* non-numeric */
    "{\"event\":\"e\",\"timestamp_us\":1.0}",   /* fractional */
    "{\"event\":\"e\",\"timestamp_us\":1e5}",   /* exponent */
    "{\"event\":\"e\",\"timestamp_us\":}",      /* empty value */
    "{\"event\":\"e\",\"timestamp_us\":99999999999999999999}",  /* overflow */
    "{\"event\":\"e\",\"timestamp_us\":9223372036854775808}",   /* G_MAXINT64+1 */
    "{\"event\":\"e\",\"timestamp_us\":01}",    /* non-canonical leading zero */
    "{\"event\":\"e\"}",        /* missing field */
    "{\"event\":\"e\",\"timestamp_us\":1,\"timestamp_us\":2}",  /* extra member */
    "{\"timestamp_us\":1,\"timestamp_us\":2}",  /* duplicate int field */
    "{\"event\":\"e\",\"timestamp_us\":12 34}", /* trailing junk */
  };
  for (gsize i = 0; i < G_N_ELEMENTS (reject); i++) {
    g_assert_false (wyl_daemon_http_dup_strict_json_object (reject[i],
            strlen (reject[i]), fields, G_N_ELEMENTS (fields), values));
    g_assert_null (values[0]);
    g_assert_null (values[1]);
  }
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/daemon/http/loopback-predicate", test_loopback_predicate);
  g_test_add_func ("/daemon/http/strict-json-object",
      test_strict_json_object_parser);
  g_test_add_func ("/daemon/http/strict-json-typed-int",
      test_strict_json_typed_int);
  return g_test_run ();
}

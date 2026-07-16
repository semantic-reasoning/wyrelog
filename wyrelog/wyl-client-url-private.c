/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyl-client-url-private.h"

#include <gio/gio.h>
#include <string.h>

static gboolean
ipv4_is_canonical (const gchar *host, GInetAddress *address)
{
  g_autofree gchar *canonical = NULL;
  if (g_inet_address_get_family (address) != G_SOCKET_FAMILY_IPV4)
    return FALSE;
  if (g_inet_address_to_bytes (address)[0] != 127)
    return FALSE;
  canonical = g_inet_address_to_string (address);
  return canonical != NULL && g_strcmp0 (host, canonical) == 0;
}

static gboolean
ipv6_is_canonical_loopback (const gchar *host, GInetAddress *address)
{
  const guint8 *bytes;
  g_autofree gchar *canonical = NULL;
  if (g_inet_address_get_family (address) != G_SOCKET_FAMILY_IPV6)
    return FALSE;
  bytes = g_inet_address_to_bytes (address);
  if (bytes == NULL)
    return FALSE;
  /* IPv4-mapped IPv6 is not accepted as a canonical IPv6 authority. */
  if (memcmp (bytes, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) == 0)
    return FALSE;
  for (guint i = 0; i < 15; i++)
    if (bytes[i] != 0)
      return FALSE;
  if (bytes[15] != 1)
    return FALSE;
  canonical = g_inet_address_to_string (address);
  return canonical != NULL && g_ascii_strcasecmp (host, canonical) == 0;
}

gboolean
wyl_client_secret_url_is_canonical_literal_loopback (const gchar *url)
{
  g_autoptr (GError) error = NULL;
  g_autoptr (GUri) uri = NULL;
  g_autoptr (GInetAddress) address = NULL;
  const gchar *scheme;
  const gchar *host;
  gint port;

  if (url == NULL || url[0] == '\0')
    return FALSE;
  uri = g_uri_parse (url, G_URI_FLAGS_NONE, &error);
  if (uri == NULL)
    return FALSE;
  scheme = g_uri_get_scheme (uri);
  if (g_strcmp0 (scheme, "http") != 0 && g_strcmp0 (scheme, "https") != 0)
    return FALSE;
  if (g_uri_get_userinfo (uri) != NULL || g_uri_get_password (uri) != NULL)
    return FALSE;
  host = g_uri_get_host (uri);
  if (host == NULL || host[0] == '\0' || strchr (host, '%') != NULL)
    return FALSE;
  port = g_uri_get_port (uri);
  if (port == 0 || port > 65535)
    return FALSE;
  address = g_inet_address_new_from_string (host);
  if (address == NULL)
    return FALSE;
  if (g_inet_address_get_family (address) == G_SOCKET_FAMILY_IPV4)
    return ipv4_is_canonical (host, address);
  return ipv6_is_canonical_loopback (host, address);
}

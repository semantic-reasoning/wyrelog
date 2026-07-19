/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-destination-private.h"

#include <string.h>

static gboolean
base_is (const gchar *value, gsize base_len, const gchar *reserved)
{
  return strlen (reserved) == base_len
      && g_ascii_strncasecmp (value, reserved, base_len) == 0;
}

gboolean
wyl_service_credential_operation_destination_is_valid (const gchar *destination)
{
  const gchar *cursor;
  const gchar *dot;
  gsize base_len;
  gsize len;

  if (destination == NULL || destination[0] == '\0')
    return FALSE;
  len = strlen (destination);
  if (len > WYL_SERVICE_CREDENTIAL_OPERATION_DESTINATION_MAX_BYTES
      || !g_utf8_validate (destination, (gssize) len, NULL)
      || g_str_equal (destination, ".") || g_str_equal (destination, "..")
      || destination[len - 1] == '.' || destination[len - 1] == ' ')
    return FALSE;

  for (cursor = destination; *cursor != '\0';
      cursor = g_utf8_next_char (cursor)) {
    gunichar ch = g_utf8_get_char (cursor);
    if (g_unichar_iscntrl (ch) || ch == '/' || ch == '\\' || ch == ':'
        || ch == '<' || ch == '>' || ch == '"' || ch == '|'
        || ch == '?' || ch == '*')
      return FALSE;
  }

  dot = strchr (destination, '.');
  base_len = dot == NULL ? len : (gsize) (dot - destination);
  if (base_is (destination, base_len, "CON")
      || base_is (destination, base_len, "PRN")
      || base_is (destination, base_len, "AUX")
      || base_is (destination, base_len, "NUL")
      || base_is (destination, base_len, "CLOCK$"))
    return FALSE;
  if (base_len == 4
      && (g_ascii_strncasecmp (destination, "COM", 3) == 0
          || g_ascii_strncasecmp (destination, "LPT", 3) == 0)
      && destination[3] >= '1' && destination[3] <= '9')
    return FALSE;
  return TRUE;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyl-id-private.h"

#include <string.h>

#include <chronoid/uuidv7.h>

G_STATIC_ASSERT (sizeof (wyl_id_t) == sizeof (chronoid_uuidv7_t));
G_STATIC_ASSERT (WYL_ID_BYTES == CHRONOID_UUIDV7_BYTES);
G_STATIC_ASSERT (WYL_ID_STRING_LEN == CHRONOID_UUIDV7_STRING_LEN);

const wyl_id_t WYL_ID_NIL = { {0} };

wyrelog_error_t
wyl_id_new (wyl_id_t *out)
{
  chronoid_uuidv7_err_t rc;

  if (out == NULL)
    return WYRELOG_E_INVALID;

  rc = chronoid_uuidv7_new ((chronoid_uuidv7_t *) out);

  switch (rc) {
    case CHRONOID_UUIDV7_OK:
      return WYRELOG_E_OK;
    case CHRONOID_UUIDV7_ERR_RNG:
      return WYRELOG_E_CRYPTO;
    case CHRONOID_UUIDV7_ERR_TIME_RANGE:
      return WYRELOG_E_INTERNAL;
    default:
      return WYRELOG_E_INTERNAL;
  }
}

wyrelog_error_t
wyl_id_format (const wyl_id_t *id, gchar *buf, gsize buf_len)
{
  if (id == NULL || buf == NULL || buf_len < WYL_ID_STRING_BUF)
    return WYRELOG_E_INVALID;

  chronoid_uuidv7_format ((const chronoid_uuidv7_t *) id, buf);
  buf[WYL_ID_STRING_LEN] = '\0';
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_id_parse (const gchar *str, wyl_id_t *out)
{
  chronoid_uuidv7_err_t rc;
  wyl_id_t tmp;
  gsize len;

  if (str == NULL || out == NULL)
    return WYRELOG_E_INVALID;

  len = strlen (str);
  rc = chronoid_uuidv7_parse ((chronoid_uuidv7_t *) & tmp, str, len);
  if (rc != CHRONOID_UUIDV7_OK)
    return WYRELOG_E_INVALID;

  /* The backing parser validates length, hex characters, and hyphen
   * placement, but does not enforce the RFC 9562 version (=7) or
   * variant (=10xx) nibbles. Reject those at the wrapper boundary so
   * the wyl_id_t parse contract is strictly stronger than the bytes
   * the parser will accept. */
  if ((tmp.bytes[6] & 0xF0u) != 0x70u)
    return WYRELOG_E_INVALID;
  if ((tmp.bytes[8] & 0xC0u) != 0x80u)
    return WYRELOG_E_INVALID;

  *out = tmp;
  return WYRELOG_E_OK;
}

gboolean
wyl_id_equal (const wyl_id_t *a, const wyl_id_t *b)
{
  if (a == NULL || b == NULL)
    return FALSE;
  return memcmp (a->bytes, b->bytes, WYL_ID_BYTES) == 0;
}

gint
wyl_id_compare (const wyl_id_t *a, const wyl_id_t *b)
{
  const wyl_id_t *lhs = (a != NULL) ? a : &WYL_ID_NIL;
  const wyl_id_t *rhs = (b != NULL) ? b : &WYL_ID_NIL;
  return memcmp (lhs->bytes, rhs->bytes, WYL_ID_BYTES);
}

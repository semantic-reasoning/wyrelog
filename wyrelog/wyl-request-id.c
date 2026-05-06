/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyl-request-id-private.h"

#include <string.h>

#include <chronoid/ksuid.h>

G_STATIC_ASSERT (WYL_REQUEST_ID_STRING_LEN == CHRONOID_KSUID_STRING_LEN);

wyrelog_error_t
wyl_request_id_new (gchar *buf, gsize buf_len)
{
  if (buf == NULL || buf_len < WYL_REQUEST_ID_STRING_BUF)
    return WYRELOG_E_INVALID;

  chronoid_ksuid_t id;
  chronoid_ksuid_err_t rc = chronoid_ksuid_new (&id);
  switch (rc) {
    case CHRONOID_KSUID_OK:
      break;
    case CHRONOID_KSUID_ERR_RNG:
      return WYRELOG_E_CRYPTO;
    case CHRONOID_KSUID_ERR_TIME_RANGE:
      return WYRELOG_E_INTERNAL;
    default:
      return WYRELOG_E_INTERNAL;
  }

  gchar tmp[WYL_REQUEST_ID_STRING_BUF];
  chronoid_ksuid_format (&id, tmp);
  tmp[WYL_REQUEST_ID_STRING_LEN] = '\0';
  memcpy (buf, tmp, sizeof tmp);
  return WYRELOG_E_OK;
}

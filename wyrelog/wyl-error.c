/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/error.h"

const gchar *
wyrelog_error_string (wyrelog_error_t err)
{
  switch (err) {
    case WYRELOG_E_OK:
      return "success";
    case WYRELOG_E_INVALID:
      return "invalid argument";
    case WYRELOG_E_NOMEM:
      return "out of memory";
    case WYRELOG_E_IO:
      return "i/o error";
    case WYRELOG_E_CRYPTO:
      return "cryptographic operation failed";
    case WYRELOG_E_POLICY:
      return "policy load or shape error";
    case WYRELOG_E_AUTH:
      return "authentication or authorization failure";
    case WYRELOG_E_INTERNAL:
      return "internal invariant violated";
    case WYRELOG_E_EXEC:
      return "policy evaluation runtime fault";
  }
  return "unknown error";
}

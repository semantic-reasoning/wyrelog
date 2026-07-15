/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/auth/service-exchange-audit-private.h"
#include "wyrelog/auth/service-exchange-private.h"
#include "wyrelog/policy/store-private.h"

int
main (void)
{
  return sizeof (wyl_service_exchange_audit_input_t) == 0
      || sizeof (WylServiceExchangeAuthority) == 0
      || sizeof (wyl_policy_store_t *) == 0;
}

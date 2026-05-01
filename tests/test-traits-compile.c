/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <stddef.h>

#include "wyrelog/wyl-traits-private.h"

int
main (void)
{
  /* Verify the vtable struct types compile and have non-zero size.
   * The compile is the real test; the runtime checks keep the
   * compiler from optimizing the type references away. */
  if (sizeof (wyl_keyprovider_vtable_t) == 0)
    return 1;
  if (sizeof (wyl_auditsink_vtable_t) == 0)
    return 2;
  if (sizeof (wyl_ingress_vtable_t) == 0)
    return 3;
  if (sizeof (wyl_ctxprovider_vtable_t) == 0)
    return 4;

  /* Zero-initialize one of each vtable to confirm the struct types
   * are complete (not just forward-declared). */
  wyl_keyprovider_vtable_t kp = { 0 };
  wyl_auditsink_vtable_t as = { 0 };
  wyl_ingress_vtable_t is = { 0 };
  wyl_ctxprovider_vtable_t cp = { 0 };

  (void) kp;
  (void) as;
  (void) is;
  (void) cp;

  return 0;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <stddef.h>

#include "wyrelog/wyl-boot-private.h"

static int call_count;

static wyrelog_error_t
phase_ok (void *ctx)
{
  (void) ctx;
  call_count++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
phase_failing (void *ctx)
{
  (void) ctx;
  call_count++;
  return WYRELOG_E_IO;
}

int
main (void)
{
  /* Empty sequence returns OK. */
  if (wyl_boot_run (NULL, 0, NULL) != WYRELOG_E_OK)
    return 1;

  /* Non-zero count with NULL seq is an invalid argument. */
  if (wyl_boot_run (NULL, 1, NULL) != WYRELOG_E_INVALID)
    return 2;

  /* All-success sequence runs every phase and returns OK. */
  call_count = 0;
  const boot_phase_t happy[] = {
    {BOOT_01_TPM_PROBE, "probe", phase_ok, true},
    {BOOT_02_DEK_UNSEAL, "unseal", phase_ok, true},
  };
  if (wyl_boot_run (happy, 2, NULL) != WYRELOG_E_OK)
    return 3;
  if (call_count != 2)
    return 4;

  /* Fail-closed failure short-circuits with the phase's return code. */
  call_count = 0;
  const boot_phase_t closed[] = {
    {BOOT_01_TPM_PROBE, "probe", phase_failing, true},
    {BOOT_02_DEK_UNSEAL, "unseal", phase_ok, true},
  };
  if (wyl_boot_run (closed, 2, NULL) != WYRELOG_E_IO)
    return 5;
  if (call_count != 1)
    return 6;

  /* Non-fail-closed failure is logged and the run continues. */
  call_count = 0;
  const boot_phase_t open[] = {
    {BOOT_01_TPM_PROBE, "probe", phase_failing, false},
    {BOOT_02_DEK_UNSEAL, "unseal", phase_ok, true},
  };
  if (wyl_boot_run (open, 2, NULL) != WYRELOG_E_OK)
    return 7;
  if (call_count != 2)
    return 8;

  return 0;
}

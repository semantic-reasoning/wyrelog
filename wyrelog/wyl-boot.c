/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyl-boot-private.h"
#include "wyl-common-private.h"

const gchar *
wyl_boot_phase_failure_code (boot_phase_id_t id)
{
  switch (id) {
    case BOOT_01_TPM_PROBE:
      return "boot_tpm_probe_failed";
    case BOOT_02_DEK_UNSEAL:
      return "boot_dek_unseal_failed";
    default:
      return "boot_phase_failed";
  }
}

wyrelog_error_t
wyl_boot_run (const boot_phase_t *seq, gsize n, gpointer ctx)
{
  if (n == 0)
    return WYRELOG_E_OK;

  if (seq == NULL)
    return WYRELOG_E_INVALID;

  for (gsize i = 0; i < n; i++) {
    const boot_phase_t *phase = &seq[i];
    wyrelog_error_t rc;

    if (phase->fn == NULL) {
      if (phase->fail_closed)
        return WYRELOG_E_INTERNAL;
      WYL_LOG_WARN (WYL_LOG_SECTION_BOOT,
          "boot phase %d (%s) has no fn; skipping",
          phase->id, phase->name ? phase->name : "?");
      continue;
    }

    rc = phase->fn (ctx);
    if (rc != WYRELOG_E_OK) {
      if (phase->fail_closed) {
        WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
            "boot phase %d (%s) failed; code=%s; halting",
            phase->id, phase->name ? phase->name : "?",
            wyl_boot_phase_failure_code (phase->id));
        return rc;
      }
      WYL_LOG_WARN (WYL_LOG_SECTION_BOOT,
          "boot phase %d (%s) failed; code=%s (continuing)",
          phase->id, phase->name ? phase->name : "?",
          wyl_boot_phase_failure_code (phase->id));
    }
  }

  return WYRELOG_E_OK;
}

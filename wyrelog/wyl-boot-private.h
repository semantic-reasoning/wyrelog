/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

/*
 * boot_phase_id_t identifies a single phase in the daemon's
 * sequenced startup. Phases run one at a time in the order given
 * to wyl_boot_run; each phase is idempotent on its own state.
 *
 * Only the first two phases are nailed down today. Subsequent
 * identifiers are added incrementally as their phase functions
 * land. The reserved sentinel BOOT_LAST sits at the end of the
 * range so callers can size static arrays without tracking the
 * highest-numbered phase by hand.
 */
typedef enum boot_phase_id_t
{
  BOOT_01_TPM_PROBE = 1,
  BOOT_02_DEK_UNSEAL = 2,
  /* BOOT_03 .. BOOT_20 reserved; added in subsequent commits. */
  BOOT_LAST = 21,
} boot_phase_id_t;

typedef wyrelog_error_t (*boot_phase_fn_t) (void *ctx);

typedef struct boot_phase_t
{
  boot_phase_id_t id;
  const char *name;
  boot_phase_fn_t fn;
  bool fail_closed;
} boot_phase_t;

/*
 * wyl_boot_run runs the phases in seq[0..n) sequentially against
 * ctx. A phase whose fn returns non-zero halts the run if its
 * fail_closed flag is set; otherwise the failure is recorded and
 * the run continues with the next phase.
 *
 * Return value: WYRELOG_E_OK if all phases reported success or
 * non-fail-closed failures only; the first fail-closed phase's
 * non-zero return code otherwise. WYRELOG_E_INVALID if seq is
 * NULL while n > 0.
 */
wyrelog_error_t wyl_boot_run (const boot_phase_t * seq, size_t n, void *ctx);

G_END_DECLS;

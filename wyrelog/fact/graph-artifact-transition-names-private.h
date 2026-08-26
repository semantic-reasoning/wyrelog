/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <string.h>

#include "wyl-id-private.h"
#include "wyrelog/error.h"

G_BEGIN_DECLS

/*
 * THE ONE BACKEND-SIDE DERIVATION OF THE OPERATION-SCOPED NAMES.
 *
 * This file is PLATFORM-NEUTRAL and header-only on purpose.  The POSIX
 * backend uses it today and the native Windows backend includes it later, so
 * there are EXACTLY TWO implementations of these names in the tree forever --
 * the contract's own, inside graph-artifact-main-transition-private.c, and
 * this one -- and EXACTLY ONE agreement test between them.  A third
 * derivation appearing anywhere is the signal that a backend has gone around
 * this file.
 *
 * WHY A SECOND DERIVATION EXISTS AT ALL, since duplicating a predicate is
 * normally the thing to avoid: the obvious alternative is circular and cannot
 * be done.  wyl_fact_artifact_main_transition_dup_stage_name needs a
 * transition, admit () needs an Observation to produce one, and the
 * Observation is precisely what a backend provider is trying to build; admit
 * () also NULLs its out-parameter on every refusal, so there is no name-only
 * path through it.  Exposing the contract's internal helper was the other
 * option and is worse: a uuid-only accessor would hand the operation's
 * derived names to anything holding a 36-character string, and needing a
 * transition is the only thing standing behind the contract's rule that a
 * driver opening either name by hand has bypassed the authorize/record
 * interlock.
 *
 * The duplication is safe here for a reason that does not generalise: these
 * are pure functions of one 36-character input, so an agreement test over a
 * corpus is a near-exhaustive check of the actual domain rather than a sample
 * of a state space, and it fails loudly the moment either side changes.
 */

/* The fixed names.  These are not derived and are spelled once here so a
 * backend never writes either literal itself. */
#define WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME "facts.duckdb"
#define WYL_FACT_ARTIFACT_TRANSITION_LOCK_NAME  "facts.duckdb.lock"

/*
 * All four names this operation owns.  The two probe names are here rather
 * than in the POSIX backend because they are derived from the same canonical
 * UUID by the same rule, and a backend that spelled them itself would be a
 * third derivation of exactly the kind this file exists to prevent.
 */
typedef struct
{
  gchar *stage;         /* restore-<canonical>.duckdb                  */
  gchar *rollback;      /* restore-<canonical>.duckdb.superseded       */
  gchar *probe;         /* restore-<canonical>.duckdb.probe            */
  gchar *probe_moved;   /* restore-<canonical>.duckdb.probe.moved      */
} WylFactArtifactTransitionNames;

static inline void
wyl_fact_artifact_transition_names_clear
  (WylFactArtifactTransitionNames *names)
{
  if (names == NULL)
    return;
  g_clear_pointer (&names->stage, g_free);
  g_clear_pointer (&names->rollback, g_free);
  g_clear_pointer (&names->probe, g_free);
  g_clear_pointer (&names->probe_moved, g_free);
}

/*
 * Round-trip validation, identical in shape to the contract's: parse enforces
 * UUIDv7 and the RFC 9562 variant, format re-renders the canonical spelling,
 * and the compare rejects any input that is not already canonical -- an
 * uppercase form, a v4 UUID, a wrong length, a trailing separator.  A
 * non-canonical input must not merely be normalised, because two spellings of
 * one UUID would derive two different sets of names for one operation.
 */
static inline wyrelog_error_t
wyl_fact_artifact_transition_names_derive (const gchar *operation_uuid,
    WylFactArtifactTransitionNames *out_names)
{
  if (out_names != NULL)
    *out_names = (WylFactArtifactTransitionNames) { 0 };
  if (operation_uuid == NULL || out_names == NULL)
    return WYRELOG_E_INVALID;
  wyl_id_t id;
  gchar canonical[WYL_ID_STRING_BUF];
  if (wyl_id_parse (operation_uuid, &id) != WYRELOG_E_OK
      || wyl_id_format (&id, canonical, sizeof canonical) != WYRELOG_E_OK
      || g_strcmp0 (operation_uuid, canonical) != 0)
    return WYRELOG_E_INVALID;
  out_names->stage = g_strdup_printf ("restore-%s.duckdb", canonical);
  out_names->rollback = g_strdup_printf ("restore-%s.duckdb.superseded",
          canonical);
  out_names->probe = g_strdup_printf ("restore-%s.duckdb.probe", canonical);
  out_names->probe_moved = g_strdup_printf ("restore-%s.duckdb.probe.moved",
          canonical);
  return WYRELOG_E_OK;
}

G_END_DECLS

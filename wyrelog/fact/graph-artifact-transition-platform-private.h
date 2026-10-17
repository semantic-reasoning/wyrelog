/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/graph-artifact-transition-posix-private.h"
#ifdef G_OS_WIN32
#include "fact/graph-artifact-transition-windows-private.h"
#endif

G_BEGIN_DECLS

/*
 * One spelling of the bounded main artifact transition provider for the
 * offline-restore consumers, chosen at compile time.  It covers only the
 * entry points whose POSIX and Windows signatures are identical up to the
 * provider's own type names and which carry no provenance: probing,
 * opening, observing, capturing, executing an authorized step, and the two
 * recovery proofs.  The provisioned capture and execute differ in what
 * proves the old main (a companion link on Linux, operation evidence on
 * macOS and Windows), so their callers keep naming the platform form at
 * the point of use.
 *
 * These are wrappers, not macro aliases, so a call site names a function;
 * a scan that forbids a platform call by name must also forbid the facade
 * spelling here (tests/test-darwin-restore-bind-wiring.py does).
 */

#ifdef G_OS_WIN32
typedef WylFactArtifactTransitionWindows WylFactArtifactTransition;
typedef WylFactArtifactTransitionWindowsCapability
    WylFactArtifactTransitionCapability;
typedef WylFactArtifactTransitionWindowsLifecycle
    WylFactArtifactTransitionLifecycle;

static inline wyrelog_error_t
wyl_fact_artifact_transition_probe_capability
  (const WylFactGraphDirectory *directory, const gchar *operation_uuid,
    WylFactArtifactTransitionCapability *out_capability)
{
  return wyl_fact_artifact_transition_windows_probe_capability (directory,
             operation_uuid, out_capability);
}

static inline wyrelog_error_t
wyl_fact_artifact_transition_open (WylFactGraphResolver *resolver,
    const WylFactGraphDirectory *directory, WylFactRootWriterLease *lease,
    const gchar *operation_uuid,
    const WylFactArtifactTransitionCapability *capability,
    WylFactArtifactTransition **out_provider)
{
  return wyl_fact_artifact_transition_windows_open (resolver, directory,
             lease, operation_uuid, capability, out_provider);
}

static inline void
wyl_fact_artifact_transition_free (WylFactArtifactTransition *provider)
{
  wyl_fact_artifact_transition_windows_free (provider);
}

static inline wyrelog_error_t
wyl_fact_artifact_transition_observe (WylFactArtifactTransition *provider,
    const WylFactArtifactTransitionLifecycle *lifecycle,
    WylFactArtifactMainTransitionObservation *out_observation)
{
  return wyl_fact_artifact_transition_windows_observe (provider, lifecycle,
             out_observation);
}

static inline wyrelog_error_t
wyl_fact_artifact_transition_capture (WylFactArtifactTransition *provider,
    const WylFactArtifactTransitionLifecycle *lifecycle,
    WylFactArtifactInventorySnapshot **out_snapshot,
    WylFactArtifactMainTransitionObservation *out_observation)
{
  return wyl_fact_artifact_transition_windows_capture (provider, lifecycle,
             out_snapshot, out_observation);
}

static inline wyrelog_error_t
wyl_fact_artifact_transition_execute (WylFactArtifactTransition *provider,
    const WylFactArtifactMainTransitionObservation *authorized,
    WylFactArtifactMainTransitionOp op,
    WylFactArtifactMainTransitionEffect *out_effect,
    WylFactArtifactMainTransitionDurabilityEvidence *out_durability)
{
  return wyl_fact_artifact_transition_windows_execute (provider, authorized,
             op, out_effect, out_durability);
}

static inline wyrelog_error_t
wyl_fact_artifact_transition_with_retired_stage_recovery
  (WylFactArtifactTransition *provider,
    const WylFactArtifactMainTransitionRequest *request,
    const WylFactArtifactTransitionLifecycle *lifecycle,
    wyrelog_error_t (*callback) (gpointer user_data), gpointer user_data)
{
  return wyl_fact_artifact_transition_windows_with_retired_stage_recovery
           (provider, request, lifecycle, callback, user_data);
}

static inline wyrelog_error_t
wyl_fact_artifact_transition_with_unbound_absence
  (WylFactArtifactTransition *provider, WylFactGraphProvisionedPair *pair,
    const WylFactArtifactMainTransitionRequest *request,
    const WylFactArtifactTransitionLifecycle *lifecycle,
    wyrelog_error_t (*callback) (gpointer user_data), gpointer user_data)
{
  return wyl_fact_artifact_transition_windows_with_unbound_absence (provider,
             pair, request, lifecycle, callback, user_data);
}
#else
typedef WylFactArtifactTransitionPosix WylFactArtifactTransition;
typedef WylFactArtifactTransitionPosixCapability
    WylFactArtifactTransitionCapability;
typedef WylFactArtifactTransitionPosixLifecycle
    WylFactArtifactTransitionLifecycle;

static inline wyrelog_error_t
wyl_fact_artifact_transition_probe_capability
  (const WylFactGraphDirectory *directory, const gchar *operation_uuid,
    WylFactArtifactTransitionCapability *out_capability)
{
  return wyl_fact_artifact_transition_posix_probe_capability (directory,
             operation_uuid, out_capability);
}

static inline wyrelog_error_t
wyl_fact_artifact_transition_open (WylFactGraphResolver *resolver,
    const WylFactGraphDirectory *directory, WylFactRootWriterLease *lease,
    const gchar *operation_uuid,
    const WylFactArtifactTransitionCapability *capability,
    WylFactArtifactTransition **out_provider)
{
  return wyl_fact_artifact_transition_posix_open (resolver, directory, lease,
             operation_uuid, capability, out_provider);
}

static inline void
wyl_fact_artifact_transition_free (WylFactArtifactTransition *provider)
{
  wyl_fact_artifact_transition_posix_free (provider);
}

static inline wyrelog_error_t
wyl_fact_artifact_transition_observe (WylFactArtifactTransition *provider,
    const WylFactArtifactTransitionLifecycle *lifecycle,
    WylFactArtifactMainTransitionObservation *out_observation)
{
  return wyl_fact_artifact_transition_posix_observe (provider, lifecycle,
             out_observation);
}

static inline wyrelog_error_t
wyl_fact_artifact_transition_capture (WylFactArtifactTransition *provider,
    const WylFactArtifactTransitionLifecycle *lifecycle,
    WylFactArtifactInventorySnapshot **out_snapshot,
    WylFactArtifactMainTransitionObservation *out_observation)
{
  return wyl_fact_artifact_transition_posix_capture (provider, lifecycle,
             out_snapshot, out_observation);
}

static inline wyrelog_error_t
wyl_fact_artifact_transition_execute (WylFactArtifactTransition *provider,
    const WylFactArtifactMainTransitionObservation *authorized,
    WylFactArtifactMainTransitionOp op,
    WylFactArtifactMainTransitionEffect *out_effect,
    WylFactArtifactMainTransitionDurabilityEvidence *out_durability)
{
  return wyl_fact_artifact_transition_posix_execute (provider, authorized, op,
             out_effect, out_durability);
}

static inline wyrelog_error_t
wyl_fact_artifact_transition_with_retired_stage_recovery
  (WylFactArtifactTransition *provider,
    const WylFactArtifactMainTransitionRequest *request,
    const WylFactArtifactTransitionLifecycle *lifecycle,
    wyrelog_error_t (*callback) (gpointer user_data), gpointer user_data)
{
  return wyl_fact_artifact_transition_posix_with_retired_stage_recovery
           (provider, request, lifecycle, callback, user_data);
}

static inline wyrelog_error_t
wyl_fact_artifact_transition_with_unbound_absence
  (WylFactArtifactTransition *provider, WylFactGraphProvisionedPair *pair,
    const WylFactArtifactMainTransitionRequest *request,
    const WylFactArtifactTransitionLifecycle *lifecycle,
    wyrelog_error_t (*callback) (gpointer user_data), gpointer user_data)
{
  return wyl_fact_artifact_transition_posix_with_unbound_absence (provider,
             pair, request, lifecycle, callback, user_data);
}
#endif

G_END_DECLS

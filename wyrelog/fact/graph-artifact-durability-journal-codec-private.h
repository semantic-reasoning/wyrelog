/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/graph-artifact-durability-private.h"
#include "wyrelog/error.h"

G_BEGIN_DECLS

/*
 * Canonical V1 journal record layout.  All integers are big-endian.
 *
 *   0..7    magic "WYLDRJ1\0"
 *   8..9    codec version (1)
 *   10..13  payload byte count, excluding this envelope and the checksum
 *   14..    payload (fixed prefix followed by fixed-size artifact entries)
 *   final 32 bytes: SHA-256 of the envelope and payload
 *
 * The checksum detects accidental tearing, mixing, and corruption; it is not
 * an authenticity mechanism.  A successfully decoded value has no authority
 * until a later loader obtains it from an authenticated or authority-protected
 * journal.  In particular, a standalone graph-directory record MUST NOT be
 * treated as historical durability proof.
 *
 * On caller misuse or invalid encode input these functions return
 * WYRELOG_E_INVALID.  Malformed, unsupported, or checksum-invalid stored bytes
 * return WYRELOG_E_POLICY.  Encode always clears *out_bytes before returning;
 * decode zeroes every accessible field in *out_evidence on every failure.
 */
wyrelog_error_t wyl_fact_artifact_durability_journal_encode
  (const WylFactArtifactDurabilityEvidence *evidence, GBytes **out_bytes);
wyrelog_error_t wyl_fact_artifact_durability_journal_decode
  (GBytes *bytes, WylFactArtifactDurabilityEvidence *out_evidence);

G_END_DECLS

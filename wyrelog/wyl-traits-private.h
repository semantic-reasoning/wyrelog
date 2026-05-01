/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "wyrelog/error.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Internal trait vtables.
 *
 * The wyrelog server library swaps in different concrete backends at
 * different points in its lifecycle: a hardware-backed key store in
 * production vs. a deterministic stub in unit tests, an embedded
 * append-only sink for production audit vs. an in-memory ring under
 * test, and so on. The four vtables declared in this header give the
 * engine a single seam to register an implementation against.
 *
 * Each vtable is a plain C struct of function pointers. The first
 * argument of every method is `void *self` and identifies the
 * implementation's private state. None of the vtables are GObject
 * types: they are not introspected at runtime, they are not held by
 * autoptr scopes, and they are not finalized by the GObject system.
 * Implementations register a vtable + self pair once at startup; the
 * engine drives them through the function pointers from then on.
 *
 * This header is not installed.
 *
 * Field-ordering rule: new method pointers are appended to the end
 * of each struct. Inserting in the middle breaks struct-literal
 * initialization in implementations and is forbidden until the
 * vtable shapes are versioned.
 *
 * Failure-mode contract: every operation that returns wyrelog_error_t
 * fails closed -- on non-zero return the implementation must leave
 * its observable state unchanged and out-parameters undefined. The
 * caller decides whether to retry or surface the error.
 */


/* --- KeyProvider -------------------------------------------------- */

/*
 * Opaque buffer for a sealed blob.
 *
 * Allocated by the implementation, freed via the trait's wipe op.
 * The engine sees only the bytes pointer + length and never inspects
 * the format.
 */
  typedef struct wyl_sealed_blob_t
  {
    uint8_t *bytes;
    size_t len;
  } wyl_sealed_blob_t;

  typedef struct wyl_keyprovider_vtable_t
  {
    /* Verify that the backing key material is reachable and the
     * implementation is healthy enough to satisfy unseal calls. */
    wyrelog_error_t (*probe) (void *self);

    /* Seal a plaintext key into an opaque blob suitable for at-rest
     * storage. Output blob ownership transfers to the caller. */
    wyrelog_error_t (*seal) (void *self,
        const uint8_t * plaintext, size_t plaintext_len,
        wyl_sealed_blob_t * out_blob);

    /* Reverse of seal: returns the plaintext into a caller-owned
     * buffer. */
    wyrelog_error_t (*unseal) (void *self,
        const wyl_sealed_blob_t * blob,
        uint8_t * out_plaintext, size_t out_capacity, size_t *out_written);

    /* Derive a sub-key from an unsealed root through HKDF (or an
     * equivalent KDF the implementation chooses). The label scopes
     * the derivation so the same root yields independent sub-keys
     * for distinct uses. */
    wyrelog_error_t (*derive) (void *self,
        const char *label, uint8_t * out_key, size_t out_len);

    /* Zero out any in-memory copies the implementation holds. Called
     * during shutdown and on error paths. */
    void (*wipe) (void *self);
  } wyl_keyprovider_vtable_t;


/* --- AuditSink ---------------------------------------------------- */

/*
 * Opaque audit record.
 *
 * The full record type is defined in a private header local to the
 * audit module; the trait only sees an opaque pointer.
 */
  typedef struct wyl_audit_record_t wyl_audit_record_t;

  typedef struct wyl_auditsink_vtable_t
  {
    /* Open the underlying store and prepare it for appends. */
    wyrelog_error_t (*open) (void *self);

    /* Append a single record. The sink may buffer; durability is
     * promised only after a subsequent flush. */
    wyrelog_error_t (*append) (void *self, const wyl_audit_record_t * record);

    /* Force any buffered records to durable storage. */
    wyrelog_error_t (*flush) (void *self);

    /* Close the store cleanly. After close, append is invalid until a
     * subsequent open. */
    wyrelog_error_t (*close) (void *self);
  } wyl_auditsink_vtable_t;


/* --- IngressSource ------------------------------------------------ */

/*
 * Opaque ingress event.
 *
 * Concrete event payloads are defined elsewhere; this trait only
 * shuttles them from source to engine.
 */
  typedef struct wyl_ingress_event_t wyl_ingress_event_t;

/*
 * Callback signature for subscribers. The source invokes this for
 * each event it produces; the callback returns OK to acknowledge,
 * non-OK to reject (the source may choose to retry or drop).
 */
  typedef wyrelog_error_t (*wyl_ingress_handler_fn) (void *user_data,
      const wyl_ingress_event_t * event);

  typedef struct wyl_ingress_vtable_t
  {
    /* Register a handler. Subsequent poll calls dispatch events to it. */
    wyrelog_error_t (*subscribe) (void *self,
        wyl_ingress_handler_fn handler, void *user_data);

    /* Drive a single iteration of the event loop. Implementations
     * decide whether this blocks, returns immediately on empty, or
     * yields after a fixed quantum. */
    wyrelog_error_t (*poll) (void *self);

    /* Stop accepting new events and release source-side resources. */
    void (*close) (void *self);
  } wyl_ingress_vtable_t;


/* --- ContextProvider --------------------------------------------- */

/*
 * Opaque snapshot handle.
 *
 * A snapshot is the immutable view of state used to evaluate a
 * single decide call. The provider produces it; the engine reads
 * principals and sessions through it; the engine releases it when
 * the call ends.
 */
  typedef struct wyl_ctx_snapshot_t wyl_ctx_snapshot_t;

/*
 * Opaque principal and session handles produced by the snapshot.
 */
  typedef struct wyl_ctx_principal_t wyl_ctx_principal_t;
  typedef struct wyl_ctx_session_t wyl_ctx_session_t;

  typedef struct wyl_ctxprovider_vtable_t
  {
    /* Take a consistent snapshot of current state. The handle must
     * remain valid until release is called against it. */
    wyrelog_error_t (*snapshot) (void *self, wyl_ctx_snapshot_t ** out_snap);

    /* Resolve a principal identifier inside a snapshot. Returns
     * WYRELOG_E_INVALID if the id has no entry in the snapshot. */
    wyrelog_error_t (*get_principal) (void *self,
        wyl_ctx_snapshot_t * snap,
        const char *principal_id, const wyl_ctx_principal_t ** out_principal);

    /* Resolve a session identifier inside a snapshot. */
    wyrelog_error_t (*get_session) (void *self,
        wyl_ctx_snapshot_t * snap,
        uint64_t session_id, const wyl_ctx_session_t ** out_session);

    /* Release the snapshot and any handles derived from it. */
    void (*release) (void *self, wyl_ctx_snapshot_t * snap);
  } wyl_ctxprovider_vtable_t;


#ifdef __cplusplus
}
#endif

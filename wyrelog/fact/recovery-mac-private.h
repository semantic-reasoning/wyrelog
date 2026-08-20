/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS

#define WYL_FACT_RECOVERY_MAC_TAG_BYTES 32u
#define WYL_FACT_RECOVERY_MAC_MAX_FIELD_BYTES G_MAXUINT16

typedef struct WylFactRecoveryMacHandle WylFactRecoveryMacHandle;

/* The provider owns all key material.  The fact layer receives only this
 * callback boundary and the canonical public derivation label. */
typedef wyrelog_error_t (*WylFactRecoveryMacComputeFunc)
  (gpointer provider_state, const guint8 *label, gsize label_len,
    const guint8 *payload, gsize payload_len,
    guint8 out_tag[WYL_FACT_RECOVERY_MAC_TAG_BYTES]);
typedef wyrelog_error_t (*WylFactRecoveryMacVerifyFunc)
  (gpointer provider_state, const guint8 *label, gsize label_len,
    const guint8 *payload, gsize payload_len,
    const guint8 tag[WYL_FACT_RECOVERY_MAC_TAG_BYTES]);
typedef void (*WylFactRecoveryMacWipeFunc) (gpointer provider_state);
typedef void (*WylFactRecoveryMacFreeFunc) (gpointer provider_state);

typedef struct
{
  WylFactRecoveryMacComputeFunc compute;
  WylFactRecoveryMacVerifyFunc verify;
  WylFactRecoveryMacWipeFunc wipe;
  WylFactRecoveryMacFreeFunc free;
  gpointer state;
} WylFactRecoveryMacProvider;

/* Takes ownership of |provider.state|.  Raw key bytes must remain entirely
 * inside that provider state and must never be stored in this handle. */
WylFactRecoveryMacHandle *wyl_fact_recovery_mac_handle_new
  (const WylFactRecoveryMacProvider *provider, const gchar *key_id,
    guint64 key_generation, const gchar *tenant_id, const gchar *graph_id,
    const gchar *operation_id);
WylFactRecoveryMacHandle *wyl_fact_recovery_mac_handle_ref
  (WylFactRecoveryMacHandle *handle);
void wyl_fact_recovery_mac_handle_unref (WylFactRecoveryMacHandle *handle);
void wyl_fact_recovery_mac_handle_close (WylFactRecoveryMacHandle *handle);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylFactRecoveryMacHandle,
    wyl_fact_recovery_mac_handle_unref);

guint64 wyl_fact_recovery_mac_handle_get_generation
  (const WylFactRecoveryMacHandle *handle);
const gchar *wyl_fact_recovery_mac_handle_get_key_id
  (const WylFactRecoveryMacHandle *handle);
void wyl_fact_recovery_mac_handle_get_scope
  (const WylFactRecoveryMacHandle *handle, const gchar **out_tenant_id,
    const gchar **out_graph_id, const gchar **out_operation_id);
gboolean wyl_fact_recovery_mac_handle_scope_matches
  (const WylFactRecoveryMacHandle *handle, const gchar *tenant_id,
    const gchar *graph_id, const gchar *operation_id,
    guint64 key_generation);

/* The label is public derivation metadata, not key material. */
wyrelog_error_t wyl_fact_recovery_mac_handle_dup_label
  (const WylFactRecoveryMacHandle *handle, GBytes **out_label);
wyrelog_error_t wyl_fact_recovery_mac_compute
  (WylFactRecoveryMacHandle *handle, const guint8 *payload, gsize payload_len,
    guint8 out_tag[WYL_FACT_RECOVERY_MAC_TAG_BYTES]);
wyrelog_error_t wyl_fact_recovery_mac_verify
  (WylFactRecoveryMacHandle *handle, const guint8 *payload, gsize payload_len,
    const guint8 tag[WYL_FACT_RECOVERY_MAC_TAG_BYTES]);

G_END_DECLS

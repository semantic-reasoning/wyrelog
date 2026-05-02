/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyl-traits-private.h"

G_BEGIN_DECLS;

/*
 * DEVELOPMENT ONLY -- NOT FOR PRODUCTION USE
 *
 * This module ships a deterministic, fixed-key implementation of
 * the key-provider trait for use as a unit-test fixture and an
 * early integration target while the hardware-backed provider is
 * still in flight. The seal operation XORs the plaintext against
 * a compile-time constant byte pattern; ciphertext provides no
 * confidentiality, no authentication, and no replay resistance.
 * Treat any byte that passes through this provider as if it were
 * pasted into a public chat log -- one known plaintext byte
 * recovers the corresponding key byte.
 *
 * Lifecycle: callers create a fresh state via
 * wyl_keyprovider_dev_new and release it through
 * wyl_keyprovider_dev_free; the vtable returned by
 * wyl_keyprovider_dev_get_vtable is a process-lifetime singleton
 * keyed off the per-state pointer passed as the trait's `self`
 * argument. Multiple concurrent states are independent.
 *
 * Wipe semantics: every method honours the trait fail-closed
 * contract. After wipe, probe / seal / unseal / derive each
 * return WYRELOG_E_INTERNAL until the state is released. There is
 * no implicit re-init.
 *
 * Sealed blob layout: raw XOR ciphertext, no header, no MAC,
 * length equal to the plaintext length. Real backends (TPM /
 * libsodium) will adopt an authenticated layout in a later
 * commit; nothing outside this module is allowed to depend on
 * the dev layout.
 *
 * derive() is NOT a key-derivation function. The label string is
 * folded against the fixed key with g_str_hash and a wrapping
 * pattern. Real backends will use HKDF.
 *
 * This header is private; it is not exported via install_headers.
 */

typedef struct wyl_keyprovider_dev_t wyl_keyprovider_dev_t;

/*
 * Allocates a fresh dev key-provider state. The returned pointer
 * is opaque; pass it as the `self` argument when calling the
 * vtable methods. Free with wyl_keyprovider_dev_free.
 */
wyl_keyprovider_dev_t *wyl_keyprovider_dev_new (void);

/*
 * Wipes and releases a state previously returned by
 * wyl_keyprovider_dev_new. NULL-safe.
 */
void wyl_keyprovider_dev_free (wyl_keyprovider_dev_t * self);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (wyl_keyprovider_dev_t, wyl_keyprovider_dev_free);

/*
 * Returns the dev key-provider vtable. The pointer is stable for
 * the process lifetime and may be safely cached.
 */
const wyl_keyprovider_vtable_t *wyl_keyprovider_dev_get_vtable (void);

G_END_DECLS;

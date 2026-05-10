/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyl-traits-private.h"

G_BEGIN_DECLS;

/*
 * Filesystem-backed keyprovider state.
 *
 * The file must contain a raw 32-byte root key. This is intentionally
 * a narrow implementation used for bootstrap and CI-style deployments:
 * production hosts are expected to replace this with a hardware-backed
 * provider at build/runtime time, while retaining the same trait
 * seam for future key custody backends.
 */
typedef struct wyl_keyprovider_file_t wyl_keyprovider_file_t;

wyl_keyprovider_file_t *wyl_keyprovider_file_new (const gchar * path);

void wyl_keyprovider_file_free (wyl_keyprovider_file_t * self);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (wyl_keyprovider_file_t,
    wyl_keyprovider_file_free);

const wyl_keyprovider_vtable_t *wyl_keyprovider_file_get_vtable (void);

G_END_DECLS;

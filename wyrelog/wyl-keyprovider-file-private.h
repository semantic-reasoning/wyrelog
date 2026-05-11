/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyl-traits-private.h"

G_BEGIN_DECLS;

/*
 * Filesystem-backed keyprovider state.
 *
 * The provider spec accepts:
 *
 *   systemd-creds:NAME  read NAME from $CREDENTIALS_DIRECTORY
 *   file:PATH          read PATH directly
 *   PATH               compatibility alias for file:PATH
 *
 * The selected file must contain a raw 32-byte root key. systemd-creds is
 * the supported packaged production custody path; direct file mode remains a
 * bootstrap/test path for hosts that are not launched by systemd.
 */
typedef struct wyl_keyprovider_file_t wyl_keyprovider_file_t;

wyl_keyprovider_file_t *wyl_keyprovider_file_new (const gchar * path);
wyl_keyprovider_file_t *wyl_keyprovider_file_new_from_spec (const gchar * spec);

void wyl_keyprovider_file_free (wyl_keyprovider_file_t * self);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (wyl_keyprovider_file_t,
    wyl_keyprovider_file_free);

const wyl_keyprovider_vtable_t *wyl_keyprovider_file_get_vtable (void);
const gchar *wyl_keyprovider_file_get_source_name
    (const wyl_keyprovider_file_t * self);

G_END_DECLS;

/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

G_BEGIN_DECLS;

gboolean wyl_client_secret_url_is_canonical_literal_loopback
    (const gchar * url);

G_END_DECLS;

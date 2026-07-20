/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

gchar *wyl_test_make_secure_fact_root (const gchar * tmpl, GError ** error);
gboolean wyl_test_create_secure_directory (const gchar * path, GError ** error);
gboolean wyl_test_secure_regular_file (const gchar * path, GError ** error);
gboolean wyl_test_create_directory_alias (const gchar * alias,
    const gchar * target, GError ** error);
gboolean wyl_test_remove_directory_alias (const gchar * alias, GError ** error);

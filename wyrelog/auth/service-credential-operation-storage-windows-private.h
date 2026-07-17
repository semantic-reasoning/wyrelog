/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#ifdef G_OS_WIN32
#include <windows.h>

G_BEGIN_DECLS
/* Opens one validated child relative to root without resolving a path. */
    BOOL wyl_win_nt_create_relative (HANDLE root, const gchar * component,
    ACCESS_MASK access, HANDLE * out_handle);

G_END_DECLS
#endif

/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyctl-publication-private.h"

#ifdef G_OS_WIN32
#include "wyctl-publication-windows-private.h"
#else
#include "wyctl-publication-posix-private.h"
#endif

G_BEGIN_DECLS;

/* Production OS-dispatch holder for the concrete publication backend. The
 * embedded struct carries all per-root state; the vtable returned by
 * wyctl_publication_backend_vtable() is a stateless re-entrant singleton and
 * every method routes through the `self` obtained from
 * wyctl_publication_backend_self(). The daemon and focused tests open one
 * holder per root and drive the escrow executor with (vtable, self). */
typedef struct wyctl_publication_backend_t
{
#ifdef G_OS_WIN32
  WyctlPublicationWindowsBackend concrete;
#else
  WyctlPublicationPosixBackend concrete;
#endif
} WyctlPublicationBackend;

wyrelog_error_t wyctl_publication_backend_open
    (WyctlPublicationBackend * backend, const gchar * root_dir);
void wyctl_publication_backend_close (WyctlPublicationBackend * backend);
const WyctlPublicationBackendVTable *wyctl_publication_backend_vtable (void);
gpointer wyctl_publication_backend_self (WyctlPublicationBackend * backend);

G_END_DECLS;

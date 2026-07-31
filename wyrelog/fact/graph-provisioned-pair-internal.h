/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "fact/graph-locator-private.h"

#ifndef G_OS_WIN32
/* Shared only by the POSIX locator and artifact-namespace implementations.
 * The callable private API keeps this representation opaque: in particular,
 * no caller can extract a pathname, descriptor, or mutable identity tuple. */
struct WylFactGraphProvisionedPair
{
  gint references;
  WylFactGraphDirectory directory;
  gchar *operation_uuid;
  gchar *stage_basename;
  guint64 expected_device;
  guint64 expected_inode;
  guint64 expected_owner;
  gint held_final_fd;
  gint writable_final_fd;
};
#endif

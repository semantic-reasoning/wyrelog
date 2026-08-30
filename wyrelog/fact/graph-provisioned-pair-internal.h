/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "fact/graph-locator-private.h"
#ifdef G_OS_WIN32
#include "fact/graph-windows-security-private.h"
#endif

#ifdef G_OS_WIN32
/* Shared only by the Windows locator and artifact-namespace implementations.
 * The callable private API keeps this representation opaque: in particular,
 * no caller can extract a pathname, HANDLE, or mutable identity tuple.
 *
 * This is NOT the POSIX representation renamed.  POSIX retains two names under
 * the operation's control that must resolve to one inode, and pins nlink==2.
 * Windows publishes by rename, so after publish the stage name does not exist
 * and the final is at NumberOfLinks == 1 by construction; the substitute is the
 * operation-evidence tuple minted from the stage BEFORE the rename, whose
 * artifact_identity survives it.
 *
 * The difference that matters is not the count of witnesses.  POSIX's second
 * name is synthesisable by anyone who can write into the graph directory, so
 * it is load-bearing only behind the directory ACL, whereas a FileId captured
 * from the stage handle cannot be forged.  What Windows lacks is that its
 * witness must be SUPPLIED BY THE CALLER and cannot be read back from the
 * filesystem -- which is exactly why a pair cannot survive a restart until the
 * tuple has a durable home (#816).
 *
 * |owner_token| is pinned once at construction and re-compared against the
 * live process token on every revalidation, mirroring the POSIX pair, which
 * checks both expected_owner and geteuid().  Be honest about its reach: the
 * process token's user SID is immutable for the process lifetime, so within
 * one process that comparison cannot fire, and the DACL check that runs beside
 * it already resolves the same SID through the live token.  Catching an
 * impersonating thread would need OpenThreadToken.  The pinned copy earns its
 * place at the boundary #816 introduces, where a pair is reconstituted from a
 * durable record and the identity that minted it is no longer implied. */
struct WylFactGraphProvisionedPair
{
  gint references;
  WylFactGraphDirectory directory;
  gchar *operation_uuid;
  gchar *stage_basename;
  WylFactGraphWinOperationEvidence evidence;
  WylFactGraphWinTokenIdentity owner_token;
  gpointer held_final_handle;
};

#else
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
#ifdef __APPLE__
  WylFactGraphDarwinOperationEvidence evidence;
#endif
};
#endif

/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

G_BEGIN_DECLS;

#ifndef G_OS_WIN32
struct stat;

/* Test seams for the two stat-based change detectors (#1348).  Both must
 * treat an allocation-only change (st_blocks) as no change, because a
 * filesystem can make one with no write, and must still see a change to
 * mtime, ctime or size.  Kept out of the locator and namespace headers so
 * the frozen POSIX lock header closure does not move for test code. */

/* TRUE when the restore inventory treats two stat records as unchanged. */
gboolean wyl_fact_graph_restore_inventory_same_stat_for_test
  (const struct stat * a, const struct stat * b);

/* The inventory hash one directory entry contributes to an observation's
 * entry fingerprint. */
gboolean wyl_fact_artifact_inventory_entry_hash_for_test (const gchar * name,
    const struct stat * st, guint64 * out_hash);
#endif

G_END_DECLS;

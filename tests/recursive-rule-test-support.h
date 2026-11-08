/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once
#include <glib.h>
#include <string.h>
#define WYL_TEST_RECURSIVE_VERTICES 64

/* Independent finite-graph BFS oracle shared by engine and durable replay. */
static void
wyl_test_recursive_closure (
  const gboolean edge[WYL_TEST_RECURSIVE_VERTICES][WYL_TEST_RECURSIVE_VERTICES],
  gboolean expected[WYL_TEST_RECURSIVE_VERTICES][WYL_TEST_RECURSIVE_VERTICES])
{
  const guint n = WYL_TEST_RECURSIVE_VERTICES;
  memset (expected, 0, sizeof (gboolean) * n * n);
  for (guint start = 0; start < n; start++) {
    guint queue[WYL_TEST_RECURSIVE_VERTICES], head = 0, tail = 0;
    for (guint v = 0; v < n; v++) {
      if (edge[start][v]) {
        expected[start][v] = TRUE;
        queue[tail++] = v;
      }
    }
    while (head < tail) {
      guint v = queue[head++];
      for (guint next = 0; next < n; next++) {
        if (edge[v][next] && !expected[start][next]) {
          expected[start][next] = TRUE;
          g_assert_cmpuint (tail, <, n);
          queue[tail++] = next;
        }
      }
    }
  }
}

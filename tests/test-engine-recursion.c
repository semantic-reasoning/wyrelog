/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"
#include <glib.h>
#include <string.h>
#include "wyrelog/wyl-engine-private.h"

#define N 64

typedef struct
{
  WylEngine *engine;
  gint64 ids[N];
  gboolean edge[N][N];
  gboolean seed[N];
} Fixture;

typedef struct
{
  Fixture *fixture;
  const gchar *relation;
  guint width;
  gboolean rows[N][N];
  guint count;
} Image;

static const gchar *decls =
    ".decl edge(x:symbol,y:symbol)\n"
    ".decl reachable(x:symbol,y:symbol)\n"
    ".decl observed(x:symbol,y:symbol)\n"
    "reachable(X,Y) :- edge(X,Y).\n"
    "observed(X,Y) :- reachable(X,Y).\n";
static const gchar *mutual =
    ".decl seed(x:symbol)\n.decl edge(x:symbol,y:symbol)\n"
    ".decl p(x:symbol)\n.decl q(x:symbol)\n"
    ".decl seed_seen(x:symbol)\nseed_seen(X) :- seed(X).\n"
    "p(X) :- seed(X).\nq(X) :- p(X).\n"
    "p(Y) :- q(X), edge(X,Y).\n";

static void
open_fixture (Fixture *f, const gchar *source, guint workers)
{
  memset (f, 0, sizeof (*f));
  g_assert_cmpint (wyl_engine_open_source (source, workers, &f->engine),
      ==, WYRELOG_E_OK);
  /* The fact replay path uses a handle-owned read engine. */
  wyl_engine_set_owner (f->engine, WYL_ENGINE_OWNER_READ);
  for (guint i = 0; i < N; i++) {
    g_autofree gchar *name = g_strdup_printf ("vertex-%u", i);
    g_assert_cmpint (wyl_engine_owned_intern_symbol (f->engine, name,
        &f->ids[i]), ==, WYRELOG_E_OK);
  }
}

static void
edge (Fixture *f, guint x, guint y, gboolean add)
{
  gint64 row[] = { f->ids[x], f->ids[y] };
  g_assert_cmpint (f->edge[x][y], !=, add);
  wyrelog_error_t rc = add
      ? wyl_engine_owned_insert (f->engine, "edge", row, 2)
      : wyl_engine_owned_remove (f->engine, "edge", row, 2);
  g_assert_cmpint (rc, ==, WYRELOG_E_OK);
  f->edge[x][y] = add;
}

/* Independent graph-search oracle, not an implementation of Datalog joins. */
static void
closure (Fixture *f, gboolean expected[N][N])
{
  memset (expected, 0, sizeof (gboolean) * N * N);
  for (guint start = 0; start < N; start++) {
    guint queue[N], head = 0, tail = 0;
    for (guint v = 0; v < N; v++) {
      if (f->edge[start][v]) {
        expected[start][v] = TRUE;
        queue[tail++] = v;
      }
    }
    while (head < tail) {
      guint v = queue[head++];
      for (guint next = 0; next < N; next++) {
        if (f->edge[v][next] && !expected[start][next]) {
          expected[start][next] = TRUE;
          g_assert_cmpuint (tail, <, N);
          queue[tail++] = next;
        }
      }
    }
  }
}

static guint
vertex (Fixture *f, gint64 id)
{
  for (guint i = 0; i < N; i++)
    if (f->ids[i] == id)
      return i;
  g_error ("unknown symbolic vertex: %" G_GINT64_FORMAT, id);
  return N;
}

static void
capture (const gchar *relation, const gint64 *row, guint width, gpointer data)
{
  Image *image = data;
  g_assert_cmpstr (relation, ==, image->relation);
  g_assert_cmpuint (width, ==, image->width);
  guint x = vertex (image->fixture, row[0]);
  guint y = width == 2 ? vertex (image->fixture, row[1]) : 0;
  g_assert_false (image->rows[x][y]);
  image->rows[x][y] = TRUE;
  image->count++;
}

static void
check_image (Fixture *f, const gchar *relation, gboolean unary)
{
  gboolean expected[N][N];
  closure (f, expected);
  Image image = { .fixture = f, .relation = relation,
                  .width = unary ? 1 : 2 };
  g_assert_cmpint (wyl_engine_snapshot (f->engine, relation, capture, &image),
      ==, WYRELOG_E_OK);
  for (guint x = 0; x < N; x++) {
    if (unary) {
      gboolean present = f->seed[x];
      for (guint s = 0; s < N; s++)
        present |= f->seed[s] && expected[s][x];
      g_assert_cmpint (image.rows[x][0], ==, present);
    } else {
      for (guint y = 0; y < N; y++)
        g_assert_cmpint (image.rows[x][y], ==, expected[x][y]);
    }
  }
}

static void
check_pair (Fixture *f, gboolean unary)
{
  check_image (f, unary ? "p" : "reachable", unary);
  check_image (f, unary ? "q" : "observed", unary);
  check_image (f, unary ? "p" : "reachable", unary);
}

static void
lifecycle (gconstpointer data)
{
  if (!g_test_subprocess ()) {
    g_test_trap_subprocess (NULL, 30 * G_USEC_PER_SEC, 0);
    g_test_trap_assert_passed ();
    return;
  }
  guint config = GPOINTER_TO_UINT (data);
  guint workers = config / 3;
  guint kind = config % 3;
  g_autofree gchar *source = kind == 2 ? g_strdup (mutual)
      : g_strconcat (decls, kind == 0
          ? "reachable(X,Z) :- reachable(X,Y), edge(Y,Z).\n"
          : "reachable(X,Z) :- reachable(X,Y), reachable(Y,Z).\n", NULL);
  Fixture f;
  open_fixture (&f, source, workers);
  check_pair (&f, kind == 2); /* first read: empty seed */
  if (kind == 2) {
    g_assert_cmpint (wyl_engine_owned_insert (f.engine, "seed", &f.ids[0], 1),
        ==, WYRELOG_E_OK);
    f.seed[0] = TRUE;
    check_pair (&f, TRUE); /* exactly vertex-0 in both p and q */
  }
  edge (&f, 0, 1, TRUE);
  edge (&f, 1, 2, TRUE);
  check_pair (&f, kind == 2);
  edge (&f, 0, 3, TRUE);
  edge (&f, 3, 2, TRUE); /* two derivations of (0,2) */
  check_pair (&f, kind == 2);
  edge (&f, 1, 2, FALSE); /* alternate support survives */
  check_pair (&f, kind == 2);
  edge (&f, 3, 2, FALSE); /* last support disappears */
  check_pair (&f, kind == 2);
  edge (&f, 1, 0, TRUE); /* finite cycle gives reflexive reachability */
  check_pair (&f, kind == 2);
  edge (&f, 1, 0, FALSE);
  edge (&f, 0, 3, FALSE);
  for (guint i = 1; i + 1 < N; i++)
    edge (&f, i, i + 1, TRUE);
  check_pair (&f, kind == 2); /* 64 vertices, every expected tuple */
  edge (&f, 31, 32, FALSE);
  check_pair (&f, kind == 2);
  edge (&f, 31, 32, TRUE);
  check_pair (&f, kind == 2);
  if (kind == 2) {
    g_assert_cmpint (wyl_engine_owned_remove (f.engine, "seed", &f.ids[0], 1),
        ==, WYRELOG_E_OK);
    f.seed[0] = FALSE;
    check_pair (&f, TRUE);
  }
  wyl_engine_close (f.engine);
  /* Also cover seeded input before the first evaluating read. */
  open_fixture (&f, source, workers);
  edge (&f, 0, 1, TRUE);
  edge (&f, 1, 0, TRUE);
  if (kind == 2) {
    g_assert_cmpint (wyl_engine_owned_insert (f.engine, "seed", &f.ids[0], 1),
        ==, WYRELOG_E_OK);
    f.seed[0] = TRUE;
  }
  check_pair (&f, kind == 2);
  wyl_engine_close (f.engine);
}

/* Configure before process startup: GLib and the evaluator can use different
 * CRT environment copies on Windows. Restore before any trap assertion. */
static void
trap_configured (const gchar *mode)
{
  const gchar *keys[] = { "WIRELOG_JOIN_OUTPUT_LIMIT",
                          "WIRELOG_TDD_MIN_ROWS_PER_WORKER", "WIRELOG_TDD_DECISION_DEBUG",
                          "WYL_TEST_RECURSION_MODE" };
  const gchar *values[] = { g_str_equal (mode, "limited") ? "1" : NULL,
                            g_str_equal (mode, "parallel") ? "1" : NULL,
                            g_str_equal (mode, "parallel") ? "1" : NULL, mode };
  gchar *saved[G_N_ELEMENTS (keys)];
  for (guint i = 0; i < G_N_ELEMENTS (keys); i++) {
    saved[i] = g_strdup (g_getenv (keys[i]));
    if (values[i])
      g_assert_true (g_setenv (keys[i], values[i], TRUE));
    else
      g_unsetenv (keys[i]);
  }
  g_test_trap_subprocess (NULL, 30 * G_USEC_PER_SEC, 0);
  for (guint i = 0; i < G_N_ELEMENTS (keys); i++) {
    if (saved[i])
      g_assert_true (g_setenv (keys[i], saved[i], TRUE));
    else
      g_unsetenv (keys[i]);
    g_free (saved[i]);
  }
  g_test_trap_assert_passed ();
}

static void
join_limit (void)
{
  if (!g_test_subprocess ()) {
    trap_configured ("limited");
    trap_configured ("unlimited");
    return;
  }
  const gchar *mode = g_getenv ("WYL_TEST_RECURSION_MODE");
  g_assert_nonnull (mode);
  gboolean limited = g_str_equal (mode, "limited");
  g_assert_true (limited || g_str_equal (mode, "unlimited"));
  g_assert_cmpstr (g_getenv ("WIRELOG_JOIN_OUTPUT_LIMIT"), ==,
      limited ? "1" : NULL);
  Fixture f;
  open_fixture (&f, mutual, 1);
  g_assert_cmpint (wyl_engine_owned_insert (f.engine, "seed", &f.ids[0], 1),
      ==, WYRELOG_E_OK);
  f.seed[0] = TRUE;
  for (guint i = 1; i < 8; i++)
    edge (&f, 0, i, TRUE);
  if (!limited) {
    check_pair (&f, TRUE);
    wyl_engine_close (f.engine);
    return;
  }
  for (guint retry = 0; retry < 2; retry++) {
    Image image = { .fixture = &f, .relation = "p", .width = 1 };
    g_assert_cmpint (wyl_engine_snapshot (f.engine, "p", capture, &image),
        ==, WYRELOG_E_EXEC);
    g_assert_cmpuint (image.count, ==, 0);
    g_assert_cmpint (f.engine->mode, ==, WYL_ENGINE_MODE_NONE);
    /* POSIX also proves that changing env cannot repair this session. */
#ifndef G_OS_WIN32
    g_unsetenv ("WIRELOG_JOIN_OUTPUT_LIMIT");
#endif
  }
  wyl_engine_close (f.engine);
#ifndef G_OS_WIN32
  /* On Windows the separate unlimited child proves unrestricted recovery. */
  open_fixture (&f, mutual, 1);
  g_assert_cmpint (wyl_engine_owned_insert (f.engine, "seed", &f.ids[0], 1),
      ==, WYRELOG_E_OK);
  f.seed[0] = TRUE;
  for (guint i = 1; i < 8; i++)
    edge (&f, 0, i, TRUE);
  check_pair (&f, TRUE);
  wyl_engine_close (f.engine);
#endif
}

static void
parallel_route (void)
{
  if (!g_test_subprocess ()) {
    trap_configured ("parallel");
    /* Runtime dispatch evidence, not merely the requested worker count. */
    g_test_trap_assert_stderr ("*use_tdd=1*");
    return;
  }
  g_assert_cmpstr (g_getenv ("WIRELOG_TDD_MIN_ROWS_PER_WORKER"), ==, "1");
  g_assert_cmpstr (g_getenv ("WIRELOG_TDD_DECISION_DEBUG"), ==, "1");
  const gchar *rules[] = {
    "reachable(X,Z) :- reachable(X,Y), edge(Y,Z).\n",
    "reachable(X,Z) :- reachable(X,Y), reachable(Y,Z).\n"
  };
  for (guint kind = 0; kind < 3; kind++) {
    g_autofree gchar *source = kind == 2 ? g_strdup (mutual)
        : g_strconcat (decls, rules[kind], NULL);
    Fixture f;
    open_fixture (&f, source, 2);
    for (guint i = 0; i + 1 < N; i++)
      edge (&f, i, i + 1, TRUE);
    if (kind == 2) {
      g_assert_cmpint (wyl_engine_owned_insert (f.engine, "seed", &f.ids[0], 1),
          ==, WYRELOG_E_OK);
      f.seed[0] = TRUE;
    }
    check_pair (&f, kind == 2);
    edge (&f, 31, 32, FALSE);
    check_pair (&f, kind == 2);
    edge (&f, 31, 32, TRUE);
    check_pair (&f, kind == 2);
    wyl_engine_close (f.engine);
  }
}

#ifdef WL_SESSION_TEST_HOOKS
/* These are real upstream limits, linked only by the separate static,
 * hook-enabled qualification build. Never fake a snapshot return status. */
extern uint32_t wl_columnar_eval_serial_test_iteration_limit;
extern uint32_t wl_columnar_session_test_iteration_limit;

static void
iteration_cap (void)
{
  if (!g_test_subprocess ()) {
    g_test_trap_subprocess (NULL, 30 * G_USEC_PER_SEC, 0);
    g_test_trap_assert_passed ();
    return;
  }
  const gchar *relations[] = { "p", "q", "seed_seen", "absent" };
  for (guint workers = 0; workers <= 2; workers++) {
    for (guint r = 0; r < G_N_ELEMENTS (relations); r++) {
      Fixture f;
      open_fixture (&f, mutual, workers);
      g_assert_cmpint (wyl_engine_owned_insert (f.engine, "seed", &f.ids[0], 1),
          ==, WYRELOG_E_OK);
      f.seed[0] = TRUE;
      for (guint i = 0; i < 13; i++)
        edge (&f, i, i + 1, TRUE);
      for (guint dirty = 0; dirty < 2; dirty++) {
        if (dirty) {
          /* Force a complete rebuild after a previously successful model. */
          edge (&f, 0, 1, FALSE);
          edge (&f, 0, 1, TRUE);
        }
        wl_columnar_eval_serial_test_iteration_limit = 1;
        wl_columnar_session_test_iteration_limit = 1;
        Image image = { .fixture = &f, .relation = relations[r], .width = 1 };
        wyrelog_error_t rc = wyl_engine_snapshot (f.engine, relations[r],
                capture, &image);
        wl_columnar_eval_serial_test_iteration_limit = 0;
        wl_columnar_session_test_iteration_limit = 0;
        g_test_message ("real cap: workers=%u target=%s dirty=%u rc=%d rows=%u",
            workers, relations[r], dirty, rc, image.count);
        g_assert_cmpint (rc, ==, WYRELOG_E_EXEC);
        g_assert_cmpuint (image.count, ==, 0);
        g_assert_cmpint (f.engine->mode, ==, dirty ? WYL_ENGINE_MODE_SNAPSHOT
            : WYL_ENGINE_MODE_NONE);
        check_pair (&f, TRUE); /* SAME engine, complete retry + unchanged read */
      }
      wyl_engine_close (f.engine);
    }
  }
}

static void
iteration_cap_parallel (void)
{
  if (!g_test_subprocess ()) {
    trap_configured ("parallel");
    g_test_trap_assert_stderr ("*use_tdd=1*");
    return;
  }
  g_assert_cmpstr (g_getenv ("WIRELOG_TDD_MIN_ROWS_PER_WORKER"), ==, "1");
  g_assert_cmpstr (g_getenv ("WIRELOG_TDD_DECISION_DEBUG"), ==, "1");
  g_autofree gchar *source = g_strconcat (decls,
          "reachable(X,Z) :- reachable(X,Y), edge(Y,Z).\n", NULL);
  Fixture f;
  open_fixture (&f, source, 2);
  for (guint i = 0; i + 1 < N; i++)
    edge (&f, i, i + 1, TRUE);
  wl_columnar_eval_serial_test_iteration_limit = 1;
  Image image = { .fixture = &f, .relation = "reachable", .width = 2 };
  wyrelog_error_t rc = wyl_engine_snapshot (f.engine, "reachable", capture,
          &image);
  wl_columnar_eval_serial_test_iteration_limit = 0;
  g_assert_cmpint (rc, ==, WYRELOG_E_EXEC);
  g_assert_cmpuint (image.count, ==, 0);
  check_pair (&f, FALSE);
  wyl_engine_close (f.engine);
}

#endif

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  /* Only the launcher sanitizes ambient knobs; children inherit intentional
   * settings before their runtimes initialize. No engine runs in the parent. */
  if (!g_test_subprocess ()) {
    g_unsetenv ("WIRELOG_JOIN_OUTPUT_LIMIT");
    g_unsetenv ("WIRELOG_TDD_MIN_ROWS_PER_WORKER");
    g_unsetenv ("WIRELOG_TDD_DECISION_DEBUG");
    g_unsetenv ("WIRELOG_MAX_WORKERS");
    g_unsetenv ("WIRELOG_TDD_GLOBAL_READ");
    g_unsetenv ("WIRELOG_DIFF_ENABLED");
    g_unsetenv ("WYL_TEST_RECURSION_MODE");
  }
  g_test_add_func ("/engine-recursion/join-limit", join_limit);
  g_test_add_func ("/engine-recursion/parallel-route", parallel_route);
  for (guint workers = 0; workers <= 2; workers++) {
    const gchar *kinds[] = { "linear", "nonlinear", "mutual" };
    for (guint kind = 0; kind < G_N_ELEMENTS (kinds); kind++) {
      g_autofree gchar *name = g_strdup_printf ("/engine-recursion/w%u/%s",
              workers, kinds[kind]);
      g_test_add_data_func (name, GUINT_TO_POINTER (workers * 3 + kind),
          lifecycle);
    }
  }
#ifdef WL_SESSION_TEST_HOOKS
  g_test_add_func ("/engine-recursion/iteration-cap", iteration_cap);
  g_test_add_func ("/engine-recursion/iteration-cap-parallel",
      iteration_cap_parallel);
#endif
  return wyl_test_normalize_exit_status (g_test_run ());
}

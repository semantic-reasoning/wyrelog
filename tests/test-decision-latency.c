/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <stdlib.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-handle-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

typedef struct
{
  gint64 usec;
} Sample;

static gint
sample_cmp (gconstpointer a, gconstpointer b)
{
  const Sample *sa = a;
  const Sample *sb = b;
  return (sa->usec > sb->usec) - (sa->usec < sb->usec);
}

static gint64
env_i64 (const gchar *name, gint64 fallback)
{
  const gchar *value = g_getenv (name);
  if (value == NULL || value[0] == '\0')
    return fallback;
  gchar *end = NULL;
  gint64 parsed = g_ascii_strtoll (value, &end, 10);
  return end != value && end != NULL && *end == '\0' ? parsed : fallback;
}

static wyrelog_error_t
seed_fixture (WylHandle *handle)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyrelog_error_t rc = wyl_policy_store_upsert_permission (store,
      "bench.decision.read", "bench decision read", "basic");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_grant_direct_permission (store, "bench-user",
      "bench.decision.read", "bench-scope");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_set_principal_state (store, "bench-user",
      "authenticated");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_set_session_state (store, "bench-scope", "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_set_permission_state (store, "bench-user",
      "bench.decision.read", "bench-scope", "armed");
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_reload_engine_pair (handle);
}

static wyrelog_error_t
run_one_decide (WylHandle *handle, wyl_decide_req_t *req,
    wyl_decide_resp_t *resp)
{
  wyl_decide_resp_set_decision (resp, WYL_DECISION_DENY);
  wyrelog_error_t rc = wyl_decide (handle, req, resp);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_decide_resp_get_decision (resp) == WYL_DECISION_ALLOW ?
      WYRELOG_E_OK : WYRELOG_E_POLICY;
}

int
main (void)
{
  const guint warmup = (guint) env_i64 ("WYL_LATENCY_WARMUP", 4);
  const guint iterations = (guint) env_i64 ("WYL_LATENCY_ITERATIONS", 32);
  const gint64 p50_budget = env_i64 ("WYL_LATENCY_P50_USEC", 250000);
  const gint64 p95_budget = env_i64 ("WYL_LATENCY_P95_USEC", 750000);
  const gint64 p99_budget = env_i64 ("WYL_LATENCY_P99_USEC", 1000000);

  if (iterations < 32)
    return 1;

  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 2;
  if (seed_fixture (handle) != WYRELOG_E_OK)
    return 3;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  wyl_decide_req_set_subject_id (req, "bench-user");
  wyl_decide_req_set_action (req, "bench.decision.read");
  wyl_decide_req_set_resource_id (req, "bench-scope");

  for (guint i = 0; i < warmup; i++) {
    if (run_one_decide (handle, req, resp) != WYRELOG_E_OK)
      return 4;
  }

  g_autofree Sample *samples = g_new0 (Sample, iterations);
  for (guint i = 0; i < iterations; i++) {
    gint64 start = g_get_monotonic_time ();
    if (run_one_decide (handle, req, resp) != WYRELOG_E_OK)
      return 5;
    samples[i].usec = g_get_monotonic_time () - start;
  }

  qsort (samples, iterations, sizeof (Sample), sample_cmp);
  gint64 p50 = samples[(iterations * 50) / 100].usec;
  gint64 p95 = samples[(iterations * 95) / 100].usec;
  gint64 p99 = samples[(iterations * 99) / 100].usec;
  g_print ("decision-latency iterations=%u p50=%" G_GINT64_FORMAT
      "us p95=%" G_GINT64_FORMAT "us p99=%" G_GINT64_FORMAT "us\n",
      iterations, p50, p95, p99);

  if (p50 > p50_budget || p95 > p95_budget || p99 > p99_budget) {
    g_printerr ("decision latency budget exceeded: p50<=%" G_GINT64_FORMAT
        "us p95<=%" G_GINT64_FORMAT "us p99<=%" G_GINT64_FORMAT "us\n",
        p50_budget, p95_budget, p99_budget);
    return 6;
  }
  return 0;
}

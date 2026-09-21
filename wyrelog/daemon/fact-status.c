/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/fact-status.h"

#include "wyrelog/wyl-handle-private.h"

typedef struct
{
  GString *graphs;
  /* NULL renders every tenant's graphs; a tenant id renders only that
   * tenant's (#1031). */
  const gchar *tenant_filter;
  guint total;
  guint ready;
  guint degraded;
  guint provisioned;
  guint sealed;
} FactStatusJsonCtx;

static void
append_json_string (GString *json, const gchar *value)
{
  g_string_append_c (json, '"');
  for (const guchar * p = (const guchar *)value; p != NULL && *p != '\0'; p++) {
    switch (*p) {
      case '"':
        g_string_append (json, "\\\"");
        break;
      case '\\':
        g_string_append (json, "\\\\");
        break;
      case '\b':
        g_string_append (json, "\\b");
        break;
      case '\f':
        g_string_append (json, "\\f");
        break;
      case '\n':
        g_string_append (json, "\\n");
        break;
      case '\r':
        g_string_append (json, "\\r");
        break;
      case '\t':
        g_string_append (json, "\\t");
        break;
      default:
        if (*p < 0x20)
          g_string_append_printf (json, "\\u%04x", *p);
        else
          g_string_append_c (json, (gchar) * p);
        break;
    }
  }
  g_string_append_c (json, '"');
}

#ifdef WYL_HAS_FACT_STORE
static wyrelog_error_t
append_graph_status_json (const wyl_fact_graph_status_t *status,
    gpointer user_data)
{
  FactStatusJsonCtx *ctx = user_data;
  /* Skip before counting, not just before rendering.  A caller scoped to one
   * tenant that still saw a global graphs_total would learn how many graphs
   * every other tenant holds -- the same disclosure #1031 closes, only
   * quieter. */
  if (ctx->tenant_filter != NULL
      && g_strcmp0 (status->tenant_id, ctx->tenant_filter) != 0)
    return WYRELOG_E_OK;
  ctx->total++;
  /* Sealed is neither bucket.  It is an operator's own decision, so counting
   * it as degraded raises an alert for an intended state, and counting it as
   * ready hides a graph that answers nothing.  It leaves the aggregate
   * verdict alone for the same reason. */
  if (status->state == WYL_FACT_GRAPH_STATE_SEALED)
    ctx->sealed++;
  else if (status->state == WYL_FACT_GRAPH_STATE_READY)
    ctx->ready++;
  else if (status->state == WYL_FACT_GRAPH_STATE_EMPTY)
    /* Provisioning a graph before its first write is healthy and expected. */
    ctx->provisioned++;
  else
    ctx->degraded++;

  if (ctx->graphs != NULL) {
    if (ctx->graphs->len > 0)
      g_string_append_c (ctx->graphs, ',');
    g_string_append (ctx->graphs, "{\"tenant_id\":");
    append_json_string (ctx->graphs, status->tenant_id);
    g_string_append (ctx->graphs, ",\"graph_id\":");
    append_json_string (ctx->graphs, status->graph_id);
    g_string_append (ctx->graphs, ",\"state\":");
    append_json_string (ctx->graphs, wyl_fact_graph_state_name (status->state));
    g_string_append_printf (ctx->graphs, ",\"queryable\":%s",
        status->queryable ? "true" : "false");
    g_string_append (ctx->graphs, ",\"last_error_class\":");
    if (status->last_error_class == NULL)
      g_string_append (ctx->graphs, "null");
    else
      append_json_string (ctx->graphs, status->last_error_class);
    g_string_append_printf (ctx->graphs,
        ",\"operation_generation\":%" G_GUINT64_FORMAT
        ",\"engine_generation\":%" G_GUINT64_FORMAT
        ",\"last_replay_at_us\":%" G_GINT64_FORMAT,
        status->operation_generation, status->engine_generation,
        status->last_replay_at_us);
    g_string_append_c (ctx->graphs, '}');
  }
  return WYRELOG_E_OK;
}
#endif

gchar *
wyl_daemon_fact_status_json (WylHandle *handle, gboolean include_graphs,
    const gchar *tenant_filter)
{
  FactStatusJsonCtx ctx = { 0 };
  WylFactReplayResourceSnapshot replay = { 0 };
  g_autoptr (GString) graphs = include_graphs ? g_string_new (NULL) : NULL;
  ctx.graphs = graphs;
  ctx.tenant_filter = tenant_filter;

#ifdef WYL_HAS_FACT_STORE
  if (handle != NULL) {
    (void) wyl_handle_foreach_fact_graph_status (handle,
        append_graph_status_json, &ctx);
    wyl_handle_fact_replay_resource_snapshot (handle, &replay);
  }
  const gchar *status = ctx.degraded > 0 ? "degraded" : "ready";
#else
  (void) handle;
  const gchar *status = "disabled";
#endif

  g_autoptr (GString) body = g_string_new ("{\"status\":");
  append_json_string (body, status);
  g_string_append_printf (body,
      ",\"graphs_total\":%u,\"graphs_ready\":%u,\"graphs_degraded\":%u"
      ",\"graphs_provisioned\":%u,\"graphs_sealed\":%u"
      ",\"replay_resources\":{\"active\":%" G_GUINT64_FORMAT
      ",\"queued\":%" G_GUINT64_FORMAT
      ",\"active_opens\":%" G_GUINT64_FORMAT
      ",\"completed_total\":%" G_GUINT64_FORMAT
      ",\"rows_total\":%" G_GUINT64_FORMAT
      ",\"runtime_us_total\":%" G_GUINT64_FORMAT
      ",\"queue_delay_us_total\":%" G_GUINT64_FORMAT
      ",\"queue_delay_us_max\":%" G_GUINT64_FORMAT
      ",\"cancelled_total\":%" G_GUINT64_FORMAT
      ",\"timed_out_total\":%" G_GUINT64_FORMAT
      ",\"row_limit_total\":%" G_GUINT64_FORMAT
      ",\"queue_rejected_total\":%" G_GUINT64_FORMAT
      ",\"quota_rejected_total\":%" G_GUINT64_FORMAT "}",
      ctx.total, ctx.ready, ctx.degraded, ctx.provisioned, ctx.sealed,
      replay.active, replay.queued, replay.active_opens,
      replay.completed_total, replay.rows_total, replay.runtime_us_total,
      replay.queue_delay_us_total, replay.queue_delay_us_max,
      replay.cancelled_total, replay.timed_out_total, replay.row_limit_total,
      replay.queue_rejected_total, replay.quota_rejected_total);
  if (include_graphs) {
    g_string_append (body, ",\"graphs\":[");
    if (graphs != NULL)
      g_string_append (body, graphs->str);
    g_string_append_c (body, ']');
  }
  g_string_append_c (body, '}');
  return g_string_free (g_steal_pointer (&body), FALSE);
}

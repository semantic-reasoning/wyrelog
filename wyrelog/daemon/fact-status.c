/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/fact-status.h"

#include "wyrelog/wyl-handle-private.h"

typedef struct
{
  GString *graphs;
  guint total;
  guint ready;
  guint degraded;
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
  ctx->total++;
  if (status->state == WYL_FACT_GRAPH_STATE_READY)
    ctx->ready++;
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
    g_string_append_c (ctx->graphs, '}');
  }
  return WYRELOG_E_OK;
}
#endif

gchar *
wyl_daemon_fact_status_json (WylHandle *handle, gboolean include_graphs)
{
  FactStatusJsonCtx ctx = { 0 };
  g_autoptr (GString) graphs = include_graphs ? g_string_new (NULL) : NULL;
  ctx.graphs = graphs;

#ifdef WYL_HAS_FACT_STORE
  if (handle != NULL)
    (void) wyl_handle_foreach_fact_graph_status (handle,
        append_graph_status_json, &ctx);
  const gchar *status = ctx.degraded > 0 ? "degraded" : "ready";
#else
  (void) handle;
  const gchar *status = "disabled";
#endif

  g_autoptr (GString) body = g_string_new ("{\"status\":");
  append_json_string (body, status);
  g_string_append_printf (body,
      ",\"graphs_total\":%u,\"graphs_ready\":%u,\"graphs_degraded\":%u",
      ctx.total, ctx.ready, ctx.degraded);
  if (include_graphs) {
    g_string_append (body, ",\"graphs\":[");
    if (graphs != NULL)
      g_string_append (body, graphs->str);
    g_string_append_c (body, ']');
  }
  g_string_append_c (body, '}');
  return g_string_free (g_steal_pointer (&body), FALSE);
}

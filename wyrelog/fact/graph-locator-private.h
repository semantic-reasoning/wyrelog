/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

#define WYL_FACT_GRAPH_PATH_VERSION 1u

typedef struct
{
  guint version;
  gchar *tenant_component;
  gchar *graph_component;
} WylFactGraphLocator;

wyrelog_error_t wyl_fact_graph_component_encode (const gchar * value,
    gchar ** out_component);
wyrelog_error_t wyl_fact_graph_component_decode (const gchar * component,
    gchar ** out_value);
wyrelog_error_t wyl_fact_graph_locator_init (WylFactGraphLocator * locator,
    const gchar * tenant_id, const gchar * graph_id);
void wyl_fact_graph_locator_clear (WylFactGraphLocator * locator);
gchar *wyl_fact_graph_locator_relative_dir (const WylFactGraphLocator *
    locator);
gchar *wyl_fact_graph_locator_descriptive_path (const gchar * fact_root,
    const WylFactGraphLocator * locator);

G_END_DECLS;

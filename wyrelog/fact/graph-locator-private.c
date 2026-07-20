/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/graph-locator-private.h"

#include <string.h>

static const gchar hex_digits[] = "0123456789abcdef";

wyrelog_error_t
wyl_fact_graph_component_encode (const gchar *value, gchar **out_component)
{
  if (out_component != NULL)
    *out_component = NULL;
  if (value == NULL || out_component == NULL || !g_utf8_validate (value, -1,
          NULL))
    return WYRELOG_E_INVALID;

  gsize len = strlen (value);
  if (len > (G_MAXSIZE - 4) / 2)
    return WYRELOG_E_NOMEM;
  gchar *component = g_try_malloc (4 + (len * 2));
  if (component == NULL)
    return WYRELOG_E_NOMEM;

  memcpy (component, "v1-", 3);
  for (gsize i = 0; i < len; i++) {
    guchar byte = (guchar) value[i];
    component[3 + (i * 2)] = hex_digits[byte >> 4];
    component[4 + (i * 2)] = hex_digits[byte & 0x0f];
  }
  component[3 + (len * 2)] = '\0';
  *out_component = component;
  return WYRELOG_E_OK;
}

static gint
lower_hex_value (gchar c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return 10 + c - 'a';
  return -1;
}

wyrelog_error_t
wyl_fact_graph_component_decode (const gchar *component, gchar **out_value)
{
  if (out_value != NULL)
    *out_value = NULL;
  if (component == NULL || out_value == NULL
      || !g_str_has_prefix (component, "v1-"))
    return WYRELOG_E_INVALID;

  gsize encoded_len = strlen (component + 3);
  if ((encoded_len % 2) != 0)
    return WYRELOG_E_INVALID;
  gsize value_len = encoded_len / 2;
  gchar *value = g_try_malloc (value_len + 1);
  if (value == NULL)
    return WYRELOG_E_NOMEM;

  for (gsize i = 0; i < value_len; i++) {
    gint high = lower_hex_value (component[3 + (i * 2)]);
    gint low = lower_hex_value (component[4 + (i * 2)]);
    if (high < 0 || low < 0 || (high == 0 && low == 0)) {
      g_free (value);
      return WYRELOG_E_INVALID;
    }
    value[i] = (gchar) ((high << 4) | low);
  }
  value[value_len] = '\0';
  if (!g_utf8_validate (value, value_len, NULL)) {
    g_free (value);
    return WYRELOG_E_INVALID;
  }
  *out_value = value;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_graph_locator_init (WylFactGraphLocator *locator,
    const gchar *tenant_id, const gchar *graph_id)
{
  if (locator == NULL)
    return WYRELOG_E_INVALID;
  *locator = (WylFactGraphLocator) {
  0};

  wyrelog_error_t rc = wyl_fact_graph_component_encode (tenant_id,
      &locator->tenant_component);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_component_encode (graph_id, &locator->graph_component);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_graph_locator_clear (locator);
    return rc;
  }
  locator->version = WYL_FACT_GRAPH_PATH_VERSION;
  return WYRELOG_E_OK;
}

void
wyl_fact_graph_locator_clear (WylFactGraphLocator *locator)
{
  if (locator == NULL)
    return;
  g_clear_pointer (&locator->tenant_component, g_free);
  g_clear_pointer (&locator->graph_component, g_free);
  locator->version = 0;
}

static gboolean
locator_is_valid (const WylFactGraphLocator *locator)
{
  return locator != NULL && locator->version == WYL_FACT_GRAPH_PATH_VERSION
      && locator->tenant_component != NULL && locator->graph_component != NULL;
}

gchar *
wyl_fact_graph_locator_relative_dir (const WylFactGraphLocator *locator)
{
  if (!locator_is_valid (locator))
    return NULL;
  return g_build_filename (locator->tenant_component,
      locator->graph_component, NULL);
}

gchar *
wyl_fact_graph_locator_descriptive_path (const gchar *fact_root,
    const WylFactGraphLocator *locator)
{
  if (fact_root == NULL || fact_root[0] == '\0' || !locator_is_valid (locator))
    return NULL;
  return g_build_filename (fact_root, locator->tenant_component,
      locator->graph_component, NULL);
}

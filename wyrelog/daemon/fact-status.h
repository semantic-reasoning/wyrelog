/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/wyrelog.h"

G_BEGIN_DECLS;

gchar *wyl_daemon_fact_status_json (WylHandle * handle,
    gboolean include_graphs);

G_END_DECLS;

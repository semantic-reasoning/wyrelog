/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

#define WYL_REQUEST_ID_STRING_LEN 27
#define WYL_REQUEST_ID_STRING_BUF 28

wyrelog_error_t wyl_request_id_new (gchar * buf, gsize buf_len);

G_END_DECLS;

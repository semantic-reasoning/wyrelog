/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "wyrelog/wyrelog.h"

G_BEGIN_DECLS
    G_GNUC_INTERNAL wyrelog_error_t
wyl_daemon_recover_service_exchange_on_startup (WylHandle * handle);

G_END_DECLS

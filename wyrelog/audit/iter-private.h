/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WYL_AUDIT_ITER_PRIVATE_H
#define WYL_AUDIT_ITER_PRIVATE_H

#include <libsoup/soup.h>

#include "wyrelog/client.h"

SoupMessage *wyl_audit_iter_new_request_message (WylAuditIter * iter);

#endif /* WYL_AUDIT_ITER_PRIVATE_H */

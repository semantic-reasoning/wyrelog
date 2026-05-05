/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WYL_CLIENT_PRIVATE_H
#define WYL_CLIENT_PRIVATE_H

#include <libsoup/soup.h>

#include "wyrelog/client.h"

SoupSession *wyl_client_get_soup_session (WylClient * client);

#endif /* WYL_CLIENT_PRIVATE_H */

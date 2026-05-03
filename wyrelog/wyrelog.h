/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

/*
 * Umbrella header for the wyrelog public API. Includes every per-
 * domain header so callers that include <wyrelog/wyrelog.h> see the
 * full surface in one shot. Direct inclusion of the per-domain
 * headers (handle.h, session.h, audit.h, decide.h, perm.h,
 * version.h) is supported and reduces compile coupling for callers
 * that only touch one slice.
 */

#include "wyrelog/error.h"
#include "wyrelog/handle.h"
#include "wyrelog/session.h"
#include "wyrelog/audit.h"
#include "wyrelog/decide.h"
#include "wyrelog/perm.h"
#include "wyrelog/version.h"

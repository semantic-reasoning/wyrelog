/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

typedef enum
{
  WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_MALFORMED = 0,
  WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_CANONICAL = 1,
} WylServiceExchangeLimiterRequestKind;

typedef struct
{
  gboolean allowed;
  guint retry_after_seconds;
  gboolean global_charged;
  gboolean secondary_charged;
  gboolean global_denied;
  gboolean secondary_denied;
  gboolean used_anonymous_bucket;
  gboolean used_credential_bucket;
} WylServiceExchangeLimiterDecision;

typedef struct
{
  guint credential_bucket_count;
  guint full_credential_bucket_count;
  guint global_tokens;
  guint anonymous_tokens;
} WylServiceExchangeLimiterSnapshot;

typedef struct
{
  gboolean present;
  guint tokens;
  gboolean full;
  gint64 last_full_us;
  gint64 last_update_us;
} WylServiceExchangeLimiterBucketSnapshot;

typedef struct _WylServiceExchangeLimiter WylServiceExchangeLimiter;

G_GNUC_INTERNAL wyrelog_error_t wyl_service_exchange_limiter_new
    (const guint8 * key, gsize key_len, guint max_credential_buckets,
    gint64 (*now_us) (gpointer data), gpointer now_data,
    WylServiceExchangeLimiter ** out_limiter);
G_GNUC_INTERNAL wyrelog_error_t wyl_service_exchange_limiter_reseed
    (WylServiceExchangeLimiter * limiter, const guint8 * key, gsize key_len,
    guint max_credential_buckets, gint64 (*now_us) (gpointer data),
    gpointer now_data);
G_GNUC_INTERNAL wyrelog_error_t wyl_service_exchange_limiter_decide
    (WylServiceExchangeLimiter * limiter,
    WylServiceExchangeLimiterRequestKind request_kind,
    const gchar * credential_id, WylServiceExchangeLimiterDecision * out);
G_GNUC_INTERNAL void wyl_service_exchange_limiter_free
    (WylServiceExchangeLimiter * limiter);

G_GNUC_INTERNAL void wyl_service_exchange_limiter_snapshot_for_test
    (WylServiceExchangeLimiter * limiter,
    WylServiceExchangeLimiterSnapshot * out_snapshot);
G_GNUC_INTERNAL wyrelog_error_t wyl_service_exchange_limiter_bucket_snapshot
    (WylServiceExchangeLimiter * limiter, const gchar * credential_id,
    WylServiceExchangeLimiterBucketSnapshot * out_snapshot);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylServiceExchangeLimiter,
    wyl_service_exchange_limiter_free);

G_END_DECLS;

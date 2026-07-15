/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "service-exchange-limiter-private.h"

#include <sodium.h>

#include "wyrelog/auth/service-credential-private.h"

#define WYL_SERVICE_EXCHANGE_LIMITER_GLOBAL_CAPACITY 100
#define WYL_SERVICE_EXCHANGE_LIMITER_GLOBAL_REFILL_NUM 100
#define WYL_SERVICE_EXCHANGE_LIMITER_SECONDARY_CAPACITY 5
#define WYL_SERVICE_EXCHANGE_LIMITER_SECONDARY_REFILL_NUM 1
#define WYL_SERVICE_EXCHANGE_LIMITER_REFILL_DENOM_US 10000000ULL
#define WYL_SERVICE_EXCHANGE_LIMITER_MAX_BUCKETS 4096
#define WYL_SERVICE_EXCHANGE_LIMITER_RETRY_AFTER_MIN 1
#define WYL_SERVICE_EXCHANGE_LIMITER_RETRY_AFTER_MAX 10

typedef struct
{
  GBytes *digest_key;
  guint capacity;
  guint refill_num;
  guint tokens;
  guint64 fractional_num;
  gint64 last_update_us;
  gint64 last_full_us;
} WylServiceExchangeLimiterBucket;

struct _WylServiceExchangeLimiter
{
  GMutex mutex;
  guint8 key[crypto_generichash_KEYBYTES];
  gboolean key_initialized;
  guint max_credential_buckets;
    gint64 (*now_us) (gpointer data);
  gpointer now_data;
  GHashTable *credential_buckets;
  WylServiceExchangeLimiterBucket global;
  WylServiceExchangeLimiterBucket anonymous;
  guint credential_bucket_count;
};

static gint64
limiter_now_us (WylServiceExchangeLimiter *limiter)
{
  return limiter != NULL && limiter->now_us != NULL ?
      limiter->now_us (limiter->now_data) : g_get_monotonic_time ();
}

static gboolean
limiter_key_is_valid (const guint8 *key, gsize key_len)
{
  return key != NULL && key_len == crypto_generichash_KEYBYTES;
}

static wyrelog_error_t
limiter_key_install (WylServiceExchangeLimiter *limiter, const guint8 *key,
    gsize key_len)
{
  if (limiter == NULL)
    return WYRELOG_E_INVALID;
  if (limiter->key_initialized)
    sodium_memzero (limiter->key, sizeof limiter->key);
  if (limiter_key_is_valid (key, key_len)) {
    memcpy (limiter->key, key, sizeof limiter->key);
    limiter->key_initialized = TRUE;
    return WYRELOG_E_OK;
  }
  if (key != NULL || key_len != 0)
    return WYRELOG_E_INVALID;
  randombytes_buf (limiter->key, sizeof limiter->key);
  limiter->key_initialized = TRUE;
  return WYRELOG_E_OK;
}

static void
limiter_bucket_clear (WylServiceExchangeLimiterBucket *bucket)
{
  if (bucket == NULL)
    return;
  g_clear_pointer (&bucket->digest_key, g_bytes_unref);
  memset (bucket, 0, sizeof *bucket);
}

static void
limiter_bucket_free (gpointer data)
{
  WylServiceExchangeLimiterBucket *bucket = data;
  if (bucket == NULL)
    return;
  limiter_bucket_clear (bucket);
  g_free (bucket);
}

static void
limiter_bucket_init (WylServiceExchangeLimiterBucket *bucket, guint capacity,
    guint refill_num, gint64 now_us, GBytes *digest_key)
{
  g_assert (bucket != NULL);
  memset (bucket, 0, sizeof *bucket);
  bucket->digest_key = digest_key != NULL ? g_bytes_ref (digest_key) : NULL;
  bucket->capacity = capacity;
  bucket->refill_num = refill_num;
  bucket->tokens = capacity;
  bucket->last_update_us = now_us;
  bucket->last_full_us = now_us;
}

static gboolean
limiter_bucket_is_full (const WylServiceExchangeLimiterBucket *bucket)
{
  return bucket != NULL && bucket->tokens >= bucket->capacity;
}

static gboolean
limiter_bucket_refill_locked (WylServiceExchangeLimiterBucket *bucket,
    gint64 now_us)
{
  if (bucket == NULL)
    return FALSE;
  if (now_us <= bucket->last_update_us)
    return limiter_bucket_is_full (bucket);

  if (limiter_bucket_is_full (bucket)) {
    bucket->last_update_us = now_us;
    bucket->fractional_num = 0;
    return TRUE;
  }

  guint64 delta_us = (guint64) (now_us - bucket->last_update_us);
  if (bucket->refill_num == 0) {
    bucket->last_update_us = now_us;
    return limiter_bucket_is_full (bucket);
  }
  if (delta_us > G_MAXUINT64 / bucket->refill_num) {
    bucket->tokens = bucket->capacity;
    bucket->fractional_num = 0;
    bucket->last_update_us = now_us;
    bucket->last_full_us = now_us;
    return TRUE;
  }

  guint64 accrued_num = delta_us * bucket->refill_num + bucket->fractional_num;
  guint64 refilled = accrued_num / WYL_SERVICE_EXCHANGE_LIMITER_REFILL_DENOM_US;
  guint64 remainder =
      accrued_num % WYL_SERVICE_EXCHANGE_LIMITER_REFILL_DENOM_US;

  if (refilled == 0) {
    bucket->fractional_num = remainder;
    bucket->last_update_us = now_us;
    return FALSE;
  }

  guint64 new_tokens = (guint64) bucket->tokens + refilled;
  if (new_tokens >= bucket->capacity) {
    bucket->tokens = bucket->capacity;
    bucket->fractional_num = 0;
    bucket->last_full_us = now_us;
    bucket->last_update_us = now_us;
    return TRUE;
  }

  bucket->tokens = (guint) new_tokens;
  bucket->fractional_num = remainder;
  bucket->last_update_us = now_us;
  return FALSE;
}

static guint
    limiter_bucket_retry_after_seconds_locked
    (const WylServiceExchangeLimiterBucket * bucket)
{
  if (bucket == NULL || bucket->tokens > 0)
    return 0;

  guint64 wait_us = 0;
  if (bucket->fractional_num == 0) {
    wait_us = WYL_SERVICE_EXCHANGE_LIMITER_REFILL_DENOM_US / bucket->refill_num;
  } else {
    guint64 remaining_num =
        WYL_SERVICE_EXCHANGE_LIMITER_REFILL_DENOM_US - bucket->fractional_num;
    wait_us = (remaining_num + bucket->refill_num - 1) / bucket->refill_num;
  }
  guint64 wait_s = (wait_us + G_USEC_PER_SEC - 1) / G_USEC_PER_SEC;
  if (wait_s < WYL_SERVICE_EXCHANGE_LIMITER_RETRY_AFTER_MIN)
    wait_s = WYL_SERVICE_EXCHANGE_LIMITER_RETRY_AFTER_MIN;
  if (wait_s > WYL_SERVICE_EXCHANGE_LIMITER_RETRY_AFTER_MAX)
    wait_s = WYL_SERVICE_EXCHANGE_LIMITER_RETRY_AFTER_MAX;
  return (guint) wait_s;
}

static gboolean
limiter_bucket_consume_locked (WylServiceExchangeLimiterBucket *bucket,
    gint64 now_us, guint *out_retry_after_seconds)
{
  if (bucket == NULL)
    return FALSE;
  limiter_bucket_refill_locked (bucket, now_us);
  if (bucket->tokens == 0) {
    if (out_retry_after_seconds != NULL)
      *out_retry_after_seconds =
          limiter_bucket_retry_after_seconds_locked (bucket);
    return FALSE;
  }
  bucket->tokens--;
  return TRUE;
}

static guint8 *
limiter_digest_credential_id (const WylServiceExchangeLimiter *limiter,
    const gchar *credential_id)
{
  if (limiter == NULL || credential_id == NULL || !limiter->key_initialized)
    return NULL;

  guint8 digest[crypto_generichash_BYTES];
  if (crypto_generichash (digest, sizeof digest,
          (const guint8 *) credential_id, strlen (credential_id),
          limiter->key, sizeof limiter->key) != 0)
    return NULL;

  guint8 *out_digest = g_memdup2 (digest, sizeof digest);
  sodium_memzero (digest, sizeof digest);
  return out_digest;
}

static GBytes *
limiter_digest_credential_id_bytes (const WylServiceExchangeLimiter *limiter,
    const gchar *credential_id)
{
  g_autofree guint8 *digest = limiter_digest_credential_id (limiter,
      credential_id);
  if (digest == NULL)
    return NULL;
  return g_bytes_new (digest, crypto_generichash_BYTES);
}

static WylServiceExchangeLimiterBucket *
limiter_credential_bucket_lookup_locked (WylServiceExchangeLimiter *limiter,
    const gchar *credential_id, gint64 now_us)
{
  g_autoptr (GBytes) key = limiter_digest_credential_id_bytes (limiter,
      credential_id);
  if (key == NULL)
    return NULL;
  WylServiceExchangeLimiterBucket *bucket = g_hash_table_lookup
      (limiter->credential_buckets, key);
  if (bucket != NULL)
    limiter_bucket_refill_locked (bucket, now_us);
  return bucket;
}

static WylServiceExchangeLimiterBucket *
limiter_credential_bucket_evictable_locked (WylServiceExchangeLimiter *limiter,
    gint64 now_us)
{
  WylServiceExchangeLimiterBucket *best = NULL;
  GHashTableIter iter;
  gpointer key = NULL;
  gpointer value = NULL;

  g_hash_table_iter_init (&iter, limiter->credential_buckets);
  while (g_hash_table_iter_next (&iter, &key, &value)) {
    WylServiceExchangeLimiterBucket *bucket = value;
    if (!limiter_bucket_refill_locked (bucket, now_us))
      continue;
    if (bucket->tokens != bucket->capacity)
      continue;
    if (best == NULL || bucket->last_full_us < best->last_full_us)
      best = bucket;
  }
  return best;
}

static wyrelog_error_t
limiter_reserve_credential_bucket_locked (WylServiceExchangeLimiter *limiter,
    const gchar *credential_id, gint64 now_us,
    WylServiceExchangeLimiterBucket **out_bucket)
{
  g_autoptr (GBytes) key = limiter_digest_credential_id_bytes (limiter,
      credential_id);
  if (out_bucket != NULL)
    *out_bucket = NULL;
  if (key == NULL)
    return WYRELOG_E_INVALID;

  WylServiceExchangeLimiterBucket *bucket = g_hash_table_lookup
      (limiter->credential_buckets, key);
  if (bucket != NULL) {
    limiter_bucket_refill_locked (bucket, now_us);
    if (out_bucket != NULL)
      *out_bucket = bucket;
    return WYRELOG_E_OK;
  }

  if (limiter->credential_bucket_count >= limiter->max_credential_buckets) {
    WylServiceExchangeLimiterBucket *evictable =
        limiter_credential_bucket_evictable_locked (limiter, now_us);
    if (evictable == NULL)
      return WYRELOG_E_BUSY;
    g_assert (evictable->digest_key != NULL);
    if (!g_hash_table_remove (limiter->credential_buckets,
            evictable->digest_key))
      return WYRELOG_E_INTERNAL;
    g_assert_cmpuint (limiter->credential_bucket_count, >, 0);
    limiter->credential_bucket_count--;
  }

  bucket = g_new0 (WylServiceExchangeLimiterBucket, 1);
  if (bucket == NULL)
    return WYRELOG_E_INTERNAL;
  limiter_bucket_init (bucket, WYL_SERVICE_EXCHANGE_LIMITER_SECONDARY_CAPACITY,
      WYL_SERVICE_EXCHANGE_LIMITER_SECONDARY_REFILL_NUM, now_us, key);
  g_hash_table_insert (limiter->credential_buckets, g_bytes_ref (key), bucket);
  limiter->credential_bucket_count++;
  if (out_bucket != NULL)
    *out_bucket = bucket;
  return WYRELOG_E_OK;
}

static void
limiter_bucket_snapshot_from_bucket (const WylServiceExchangeLimiterBucket
    *bucket, WylServiceExchangeLimiterBucketSnapshot *out_snapshot)
{
  if (out_snapshot == NULL)
    return;
  memset (out_snapshot, 0, sizeof *out_snapshot);
  if (bucket == NULL)
    return;
  out_snapshot->present = TRUE;
  out_snapshot->tokens = bucket->tokens;
  out_snapshot->full = limiter_bucket_is_full (bucket);
  out_snapshot->last_full_us = bucket->last_full_us;
  out_snapshot->last_update_us = bucket->last_update_us;
}

static void
limiter_snapshot_bucket_counts_locked (WylServiceExchangeLimiter *limiter,
    gint64 now_us, guint *out_full_count)
{
  if (out_full_count != NULL)
    *out_full_count = 0;
  if (limiter == NULL || out_full_count == NULL)
    return;

  GHashTableIter iter;
  gpointer key = NULL;
  gpointer value = NULL;
  guint full_count = 0;
  g_hash_table_iter_init (&iter, limiter->credential_buckets);
  while (g_hash_table_iter_next (&iter, &key, &value)) {
    WylServiceExchangeLimiterBucket *bucket = value;
    if (limiter_bucket_refill_locked (bucket, now_us)
        && limiter_bucket_is_full (bucket))
      full_count++;
  }
  *out_full_count = full_count;
}

static wyrelog_error_t
limiter_reset_locked (WylServiceExchangeLimiter *limiter, const guint8 *key,
    gsize key_len, guint max_credential_buckets, gint64 now_us)
{
  if (limiter->credential_buckets != NULL)
    g_hash_table_destroy (limiter->credential_buckets);
  limiter->credential_buckets = g_hash_table_new_full (g_bytes_hash,
      g_bytes_equal, (GDestroyNotify) g_bytes_unref, limiter_bucket_free);
  limiter->credential_bucket_count = 0;
  limiter->max_credential_buckets = max_credential_buckets;
  limiter_bucket_init (&limiter->global,
      WYL_SERVICE_EXCHANGE_LIMITER_GLOBAL_CAPACITY,
      WYL_SERVICE_EXCHANGE_LIMITER_GLOBAL_REFILL_NUM, now_us, NULL);
  limiter_bucket_init (&limiter->anonymous,
      WYL_SERVICE_EXCHANGE_LIMITER_SECONDARY_CAPACITY,
      WYL_SERVICE_EXCHANGE_LIMITER_SECONDARY_REFILL_NUM, now_us, NULL);
  return limiter_key_install (limiter, key, key_len);
}

wyrelog_error_t
wyl_service_exchange_limiter_new (const guint8 *key, gsize key_len,
    guint max_credential_buckets, gint64 (*now_us) (gpointer data),
    gpointer now_data, WylServiceExchangeLimiter **out_limiter)
{
  if (out_limiter != NULL)
    *out_limiter = NULL;
  if (out_limiter == NULL || max_credential_buckets == 0
      || max_credential_buckets > WYL_SERVICE_EXCHANGE_LIMITER_MAX_BUCKETS)
    return WYRELOG_E_INVALID;
  if ((key == NULL && key_len != 0)
      || (key != NULL && key_len != crypto_generichash_KEYBYTES))
    return WYRELOG_E_INVALID;

  WylServiceExchangeLimiter *limiter = g_new0 (WylServiceExchangeLimiter, 1);
  if (limiter == NULL)
    return WYRELOG_E_INTERNAL;
  g_mutex_init (&limiter->mutex);
  limiter->now_us = now_us;
  limiter->now_data = now_data;

  gint64 now = limiter_now_us (limiter);
  g_mutex_lock (&limiter->mutex);
  wyrelog_error_t rc = limiter_reset_locked (limiter, key, key_len,
      max_credential_buckets, now);
  g_mutex_unlock (&limiter->mutex);
  if (rc != WYRELOG_E_OK) {
    wyl_service_exchange_limiter_free (limiter);
    return rc;
  }
  *out_limiter = limiter;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_service_exchange_limiter_reseed (WylServiceExchangeLimiter *limiter,
    const guint8 *key, gsize key_len, guint max_credential_buckets,
    gint64 (*now_us) (gpointer data), gpointer now_data)
{
  if (limiter == NULL || max_credential_buckets == 0
      || max_credential_buckets > WYL_SERVICE_EXCHANGE_LIMITER_MAX_BUCKETS)
    return WYRELOG_E_INVALID;
  if ((key == NULL && key_len != 0)
      || (key != NULL && key_len != crypto_generichash_KEYBYTES))
    return WYRELOG_E_INVALID;

  g_mutex_lock (&limiter->mutex);
  limiter->now_us = now_us;
  limiter->now_data = now_data;
  wyrelog_error_t rc = limiter_reset_locked (limiter, key, key_len,
      max_credential_buckets, limiter_now_us (limiter));
  g_mutex_unlock (&limiter->mutex);
  return rc;
}

void
wyl_service_exchange_limiter_free (WylServiceExchangeLimiter *limiter)
{
  if (limiter == NULL)
    return;
  g_mutex_lock (&limiter->mutex);
  if (limiter->credential_buckets != NULL) {
    g_hash_table_destroy (limiter->credential_buckets);
    limiter->credential_buckets = NULL;
  }
  sodium_memzero (limiter->key, sizeof limiter->key);
  limiter->key_initialized = FALSE;
  g_mutex_unlock (&limiter->mutex);
  g_mutex_clear (&limiter->mutex);
  limiter_bucket_clear (&limiter->global);
  limiter_bucket_clear (&limiter->anonymous);
  g_free (limiter);
}

static guint
limiter_response_retry_after (guint a, guint b)
{
  guint retry_after = MAX (a, b);
  if (retry_after < WYL_SERVICE_EXCHANGE_LIMITER_RETRY_AFTER_MIN)
    retry_after = WYL_SERVICE_EXCHANGE_LIMITER_RETRY_AFTER_MIN;
  if (retry_after > WYL_SERVICE_EXCHANGE_LIMITER_RETRY_AFTER_MAX)
    retry_after = WYL_SERVICE_EXCHANGE_LIMITER_RETRY_AFTER_MAX;
  return retry_after;
}

wyrelog_error_t
wyl_service_exchange_limiter_decide (WylServiceExchangeLimiter *limiter,
    WylServiceExchangeLimiterRequestKind request_kind,
    const gchar *credential_id, WylServiceExchangeLimiterDecision *out)
{
  if (out != NULL)
    memset (out, 0, sizeof *out);
  if (limiter == NULL || out == NULL)
    return WYRELOG_E_INVALID;
  if (request_kind != WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_MALFORMED
      && request_kind != WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_CANONICAL)
    return WYRELOG_E_INVALID;
  if (request_kind == WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_MALFORMED
      && credential_id != NULL)
    return WYRELOG_E_INVALID;
  if (request_kind == WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_CANONICAL
      && (credential_id == NULL || *credential_id == '\0'))
    return WYRELOG_E_INVALID;

  g_mutex_lock (&limiter->mutex);
  gint64 now = limiter_now_us (limiter);
  guint global_retry_after = 0;
  gboolean global_ok = limiter_bucket_consume_locked (&limiter->global, now,
      &global_retry_after);
  out->global_charged = global_ok;
  if (!global_ok) {
    out->global_denied = TRUE;
    out->retry_after_seconds = global_retry_after;
    g_mutex_unlock (&limiter->mutex);
    return WYRELOG_E_OK;
  }

  if (request_kind == WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_MALFORMED) {
    guint secondary_retry_after = 0;
    gboolean secondary_ok = limiter_bucket_consume_locked (&limiter->anonymous,
        now, &secondary_retry_after);
    out->used_anonymous_bucket = TRUE;
    out->secondary_charged = secondary_ok;
    if (!secondary_ok) {
      out->secondary_denied = TRUE;
      out->retry_after_seconds = limiter_response_retry_after
          (limiter_bucket_retry_after_seconds_locked (&limiter->global),
          secondary_retry_after);
      g_mutex_unlock (&limiter->mutex);
      return WYRELOG_E_OK;
    }
    out->allowed = TRUE;
    g_mutex_unlock (&limiter->mutex);
    return WYRELOG_E_OK;
  }

  WylServiceExchangeLimiterBucket *bucket =
      limiter_credential_bucket_lookup_locked (limiter, credential_id, now);
  if (bucket == NULL) {
    wyrelog_error_t rc = limiter_reserve_credential_bucket_locked (limiter,
        credential_id, now, &bucket);
    if (rc != WYRELOG_E_OK) {
      out->secondary_denied = TRUE;
      out->retry_after_seconds = limiter_response_retry_after
          (limiter_bucket_retry_after_seconds_locked (&limiter->global),
          WYL_SERVICE_EXCHANGE_LIMITER_RETRY_AFTER_MAX);
      g_mutex_unlock (&limiter->mutex);
      return WYRELOG_E_OK;
    }
  }
  guint secondary_retry_after = 0;
  if (!limiter_bucket_consume_locked (bucket, now, &secondary_retry_after)) {
    out->used_credential_bucket = TRUE;
    out->secondary_denied = TRUE;
    out->retry_after_seconds = limiter_response_retry_after
        (limiter_bucket_retry_after_seconds_locked (&limiter->global),
        secondary_retry_after);
    g_mutex_unlock (&limiter->mutex);
    return WYRELOG_E_OK;
  }
  out->used_credential_bucket = TRUE;
  out->secondary_charged = TRUE;
  out->allowed = TRUE;
  g_mutex_unlock (&limiter->mutex);
  return WYRELOG_E_OK;
}

void wyl_service_exchange_limiter_snapshot_for_test
    (WylServiceExchangeLimiter * limiter,
    WylServiceExchangeLimiterSnapshot * out_snapshot)
{
  if (out_snapshot == NULL)
    return;
  memset (out_snapshot, 0, sizeof *out_snapshot);
  if (limiter == NULL)
    return;

  g_mutex_lock (&limiter->mutex);
  gint64 now = limiter_now_us (limiter);
  guint full_credential_count = 0;
  limiter_snapshot_bucket_counts_locked (limiter, now, &full_credential_count);
  out_snapshot->credential_bucket_count = limiter->credential_bucket_count;
  out_snapshot->full_credential_bucket_count = full_credential_count;
  out_snapshot->global_tokens = limiter->global.tokens;
  out_snapshot->anonymous_tokens = limiter->anonymous.tokens;
  g_mutex_unlock (&limiter->mutex);
}

wyrelog_error_t
wyl_service_exchange_limiter_bucket_snapshot (WylServiceExchangeLimiter
    *limiter, const gchar *credential_id,
    WylServiceExchangeLimiterBucketSnapshot *out_snapshot)
{
  if (out_snapshot != NULL)
    memset (out_snapshot, 0, sizeof *out_snapshot);
  if (limiter == NULL || credential_id == NULL || out_snapshot == NULL)
    return WYRELOG_E_INVALID;

  g_mutex_lock (&limiter->mutex);
  gint64 now = limiter_now_us (limiter);
  g_autoptr (GBytes) key = limiter_digest_credential_id_bytes (limiter,
      credential_id);
  if (key == NULL) {
    g_mutex_unlock (&limiter->mutex);
    return WYRELOG_E_INVALID;
  }
  WylServiceExchangeLimiterBucket *bucket = g_hash_table_lookup
      (limiter->credential_buckets, key);
  if (bucket != NULL)
    limiter_bucket_refill_locked (bucket, now);
  limiter_bucket_snapshot_from_bucket (bucket, out_snapshot);
  g_mutex_unlock (&limiter->mutex);
  return bucket != NULL ? WYRELOG_E_OK : WYRELOG_E_NOT_FOUND;
}

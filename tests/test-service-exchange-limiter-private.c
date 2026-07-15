/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <sodium.h>
#include <string.h>

#include "auth/service-credential-private.h"
#include "wyrelog/auth/service-exchange-limiter-private.h"

typedef struct
{
  gint64 now_us;
} FakeClock;

static gint64
fake_now_us (gpointer data)
{
  return data != NULL ? ((FakeClock *) data)->now_us : 0;
}

static void
advance_clock (FakeClock *clock, gint64 delta_us)
{
  g_assert_nonnull (clock);
  clock->now_us += delta_us;
}

static void
init_limiter (WylServiceExchangeLimiter **out_limiter, FakeClock *clock,
    guint8 key_seed, guint max_credential_buckets)
{
  guint8 key[crypto_generichash_KEYBYTES];
  for (guint i = 0; i < sizeof key; i++)
    key[i] = (guint8) (key_seed + i);
  g_assert_cmpint (wyl_service_exchange_limiter_new (key, sizeof key,
          max_credential_buckets,
          fake_now_us, clock, out_limiter), ==, WYRELOG_E_OK);
}

static void
assert_bucket_state (WylServiceExchangeLimiter *limiter, const gchar *id,
    guint expected_tokens, gboolean expected_full)
{
  WylServiceExchangeLimiterBucketSnapshot snapshot = { 0 };
  g_assert_cmpint (wyl_service_exchange_limiter_bucket_snapshot (limiter, id,
          &snapshot), ==, WYRELOG_E_OK);
  g_assert_true (snapshot.present);
  g_assert_cmpuint (snapshot.tokens, ==, expected_tokens);
  g_assert_cmpint (snapshot.full, ==, expected_full);
}

static void
test_malformed_global_anonymous_and_refill (void)
{
  FakeClock clock = {.now_us = 1 * G_USEC_PER_SEC };
  g_autoptr (WylServiceExchangeLimiter) limiter = NULL;
  init_limiter (&limiter, &clock, 1, 4);

  WylServiceExchangeLimiterDecision decision = { 0 };
  for (guint i = 0; i < 5; i++) {
    g_assert_cmpint (wyl_service_exchange_limiter_decide (limiter,
            WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_MALFORMED, NULL, &decision),
        ==, WYRELOG_E_OK);
    g_assert_true (decision.allowed);
    g_assert_true (decision.global_charged);
    g_assert_true (decision.secondary_charged);
    g_assert_true (decision.used_anonymous_bucket);
    g_assert_false (decision.global_denied);
    g_assert_false (decision.secondary_denied);
  }

  WylServiceExchangeLimiterSnapshot snapshot = { 0 };
  wyl_service_exchange_limiter_snapshot_for_test (limiter, &snapshot);
  g_assert_cmpuint (snapshot.global_tokens, ==, 95);
  g_assert_cmpuint (snapshot.anonymous_tokens, ==, 0);

  g_assert_cmpint (wyl_service_exchange_limiter_decide (limiter,
          WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_MALFORMED, NULL, &decision), ==,
      WYRELOG_E_OK);
  g_assert_false (decision.allowed);
  g_assert_true (decision.secondary_denied);
  g_assert_cmpuint (decision.retry_after_seconds, ==, 10);
  wyl_service_exchange_limiter_snapshot_for_test (limiter, &snapshot);
  g_assert_cmpuint (snapshot.global_tokens, ==, 94);
  g_assert_cmpuint (snapshot.anonymous_tokens, ==, 0);

  advance_clock (&clock, 10 * G_USEC_PER_SEC);
  g_assert_cmpint (wyl_service_exchange_limiter_decide (limiter,
          WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_MALFORMED, NULL, &decision), ==,
      WYRELOG_E_OK);
  g_assert_true (decision.allowed);
  wyl_service_exchange_limiter_snapshot_for_test (limiter, &snapshot);
  g_assert_cmpuint (snapshot.anonymous_tokens, ==, 0);

  for (guint i = 0; i < 99; i++) {
    g_assert_cmpint (wyl_service_exchange_limiter_decide (limiter,
            WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_MALFORMED, NULL, &decision),
        ==, WYRELOG_E_OK);
  }
  wyl_service_exchange_limiter_snapshot_for_test (limiter, &snapshot);
  g_assert_cmpuint (snapshot.global_tokens, ==, 0);

  g_assert_cmpint (wyl_service_exchange_limiter_decide (limiter,
          WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_MALFORMED, NULL, &decision), ==,
      WYRELOG_E_OK);
  g_assert_false (decision.allowed);
  g_assert_true (decision.global_denied);
  g_assert_false (decision.secondary_charged);
  g_assert_cmpuint (decision.retry_after_seconds, ==, 1);
  wyl_service_exchange_limiter_snapshot_for_test (limiter, &snapshot);
  g_assert_cmpuint (snapshot.global_tokens, ==, 0);
  g_assert_cmpuint (snapshot.anonymous_tokens, ==, 0);

  advance_clock (&clock, 10 * G_USEC_PER_SEC);
  g_assert_cmpint (wyl_service_exchange_limiter_decide (limiter,
          WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_MALFORMED, NULL, &decision), ==,
      WYRELOG_E_OK);
  g_assert_true (decision.allowed);
}

static void
test_canonical_ids_get_distinct_buckets (void)
{
  FakeClock clock = {.now_us = 100 * G_USEC_PER_SEC };
  g_autoptr (WylServiceExchangeLimiter) limiter = NULL;
  init_limiter (&limiter, &clock, 7, 4);

  const gchar *id1 = "wlc_000000000000000000000000000";
  const gchar *id2 = "wlc_000000000000000000000000001";
  g_assert_true (wyl_service_credential_id_is_canonical (id1, strlen (id1)));
  g_assert_true (wyl_service_credential_id_is_canonical (id2, strlen (id2)));

  WylServiceExchangeLimiterDecision decision = { 0 };
  g_assert_cmpint (wyl_service_exchange_limiter_decide (limiter,
          WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_CANONICAL, id1, &decision), ==,
      WYRELOG_E_OK);
  g_assert_true (decision.allowed);
  g_assert_true (decision.used_credential_bucket);
  assert_bucket_state (limiter, id1, 4, FALSE);

  g_assert_cmpint (wyl_service_exchange_limiter_decide (limiter,
          WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_CANONICAL, id1, &decision), ==,
      WYRELOG_E_OK);
  g_assert_true (decision.allowed);
  assert_bucket_state (limiter, id1, 3, FALSE);

  g_assert_cmpint (wyl_service_exchange_limiter_decide (limiter,
          WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_CANONICAL, id2, &decision), ==,
      WYRELOG_E_OK);
  g_assert_true (decision.allowed);
  assert_bucket_state (limiter, id2, 4, FALSE);

  WylServiceExchangeLimiterSnapshot snapshot = { 0 };
  wyl_service_exchange_limiter_snapshot_for_test (limiter, &snapshot);
  g_assert_cmpuint (snapshot.credential_bucket_count, ==, 2);
  g_assert_cmpuint (snapshot.global_tokens, ==, 97);
}

static void
test_capacity_eviction_and_restart_reset (void)
{
  FakeClock clock = {.now_us = 0 };
  g_autoptr (WylServiceExchangeLimiter) limiter = NULL;
  init_limiter (&limiter, &clock, 11, 2);

  const gchar *id1 = "wlc_000000000000000000000000000";
  const gchar *id2 = "wlc_000000000000000000000000001";
  const gchar *id3 = "wlc_000000000000000000000000002";

  WylServiceExchangeLimiterDecision decision = { 0 };
  g_assert_cmpint (wyl_service_exchange_limiter_decide (limiter,
          WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_CANONICAL, id1, &decision), ==,
      WYRELOG_E_OK);
  g_assert_true (decision.allowed);
  g_assert_cmpint (wyl_service_exchange_limiter_decide (limiter,
          WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_CANONICAL, id2, &decision), ==,
      WYRELOG_E_OK);
  g_assert_true (decision.allowed);

  g_assert_cmpint (wyl_service_exchange_limiter_decide (limiter,
          WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_CANONICAL, id3, &decision), ==,
      WYRELOG_E_OK);
  g_assert_false (decision.allowed);
  g_assert_true (decision.secondary_denied);
  g_assert_cmpuint (decision.retry_after_seconds, ==, 10);

  advance_clock (&clock, 50 * G_USEC_PER_SEC);
  WylServiceExchangeLimiterBucketSnapshot id1_snapshot = { 0 };
  g_assert_cmpint (wyl_service_exchange_limiter_bucket_snapshot (limiter, id1,
          &id1_snapshot), ==, WYRELOG_E_OK);
  g_assert_true (id1_snapshot.full);
  g_assert_cmpuint (id1_snapshot.tokens, ==, 5);

  advance_clock (&clock, 5 * G_USEC_PER_SEC);
  WylServiceExchangeLimiterBucketSnapshot id2_snapshot = { 0 };
  g_assert_cmpint (wyl_service_exchange_limiter_bucket_snapshot (limiter, id2,
          &id2_snapshot), ==, WYRELOG_E_OK);
  g_assert_true (id2_snapshot.full);
  g_assert_cmpuint (id2_snapshot.tokens, ==, 5);

  g_assert_cmpint (wyl_service_exchange_limiter_decide (limiter,
          WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_CANONICAL, id2, &decision), ==,
      WYRELOG_E_OK);
  g_assert_true (decision.allowed);
  assert_bucket_state (limiter, id2, 4, FALSE);

  g_assert_cmpint (wyl_service_exchange_limiter_decide (limiter,
          WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_CANONICAL, id3, &decision), ==,
      WYRELOG_E_OK);
  g_assert_true (decision.allowed);
  g_assert_true (decision.used_credential_bucket);
  g_assert_false (decision.secondary_denied);
  g_assert_cmpint (wyl_service_exchange_limiter_bucket_snapshot (limiter, id1,
          &id1_snapshot), ==, WYRELOG_E_NOT_FOUND);
  assert_bucket_state (limiter, id2, 4, FALSE);
  assert_bucket_state (limiter, id3, 4, FALSE);

  WylServiceExchangeLimiterSnapshot snapshot = { 0 };
  wyl_service_exchange_limiter_snapshot_for_test (limiter, &snapshot);
  g_assert_cmpuint (snapshot.credential_bucket_count, ==, 2);
  g_assert_cmpuint (snapshot.anonymous_tokens, ==, 5);

  guint8 new_key[crypto_generichash_KEYBYTES];
  for (guint i = 0; i < sizeof new_key; i++)
    new_key[i] = (guint8) (200 + i);
  g_assert_cmpint (wyl_service_exchange_limiter_reseed (limiter, new_key,
          sizeof new_key, 4, fake_now_us, &clock), ==, WYRELOG_E_OK);

  wyl_service_exchange_limiter_snapshot_for_test (limiter, &snapshot);
  g_assert_cmpuint (snapshot.credential_bucket_count, ==, 0);
  g_assert_cmpuint (snapshot.full_credential_bucket_count, ==, 0);
  g_assert_cmpuint (snapshot.global_tokens, ==, 100);
  g_assert_cmpuint (snapshot.anonymous_tokens, ==, 5);
  g_assert_cmpint (wyl_service_exchange_limiter_bucket_snapshot (limiter, id2,
          &id2_snapshot), ==, WYRELOG_E_NOT_FOUND);

  g_assert_cmpint (wyl_service_exchange_limiter_decide (limiter,
          WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_CANONICAL, id1, &decision), ==,
      WYRELOG_E_OK);
  g_assert_true (decision.allowed);
  wyl_service_exchange_limiter_snapshot_for_test (limiter, &snapshot);
  g_assert_cmpuint (snapshot.credential_bucket_count, ==, 1);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/service-exchange-limiter-private/malformed-global-anon",
      test_malformed_global_anonymous_and_refill);
  g_test_add_func ("/service-exchange-limiter-private/canonical-buckets",
      test_canonical_ids_get_distinct_buckets);
  g_test_add_func ("/service-exchange-limiter-private/eviction-restart",
      test_capacity_eviction_and_restart_reset);
  return g_test_run ();
}

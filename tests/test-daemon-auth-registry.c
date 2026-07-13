/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "daemon/auth-registry-private.h"

#define SESSION_A "01890c10-2e3f-7000-8000-000000000101"
#define JTI_A "01890c10-2e3f-7000-8000-000000000102"
#define SESSION_B "01890c10-2e3f-7000-8000-000000000103"
#define JTI_B "01890c10-2e3f-7000-8000-000000000104"
#define CREDENTIAL_A "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv"
#define CREDENTIAL_B "wlc_000000000000000000000000000"

static WylServiceAuthReservation
fixture (const gchar *session_id, const gchar *jti)
{
  WylServiceAuthReservation value = {
    .session_id = (gchar *) session_id,
    .jti = (gchar *) jti,
    .credential_id = (gchar *) CREDENTIAL_A,
    .generation = 1,
    .principal = (gchar *) "svc:tenant-a:worker",
    .tenant = (gchar *) "tenant-a",
  };
  return value;
}

static WylServiceAuthRegistry *
new_registry (void)
{
  WylServiceAuthRegistry *registry = NULL;
  g_assert_cmpint (wyl_service_auth_registry_new (&registry), ==, WYRELOG_E_OK);
  g_assert_nonnull (registry);
  return registry;
}

static void
assert_lookup (WylServiceAuthRegistry *registry,
    const WylServiceAuthReservation *expected, WylServiceAuthState state)
{
  WylServiceAuthReservation snapshot = { 0 };
  WylServiceAuthState actual_state = WYL_SERVICE_AUTH_PENDING;
  gboolean found = FALSE;

  g_assert_cmpint (wyl_service_auth_registry_lookup (registry,
          expected->session_id, expected->jti, &snapshot, &actual_state,
          &found), ==, WYRELOG_E_OK);
  g_assert_true (found);
  g_assert_cmpint (actual_state, ==, state);
  g_assert_cmpstr (snapshot.session_id, ==, expected->session_id);
  g_assert_cmpstr (snapshot.jti, ==, expected->jti);
  g_assert_cmpstr (snapshot.credential_id, ==, expected->credential_id);
  g_assert_cmpuint (snapshot.generation, ==, expected->generation);
  g_assert_cmpstr (snapshot.principal, ==, expected->principal);
  g_assert_cmpstr (snapshot.tenant, ==, expected->tenant);
  wyl_service_auth_reservation_clear (&snapshot);
}

static void
test_copy_lifetime_and_state_table (void)
{
  WylServiceAuthRegistry *registry = new_registry ();
  WylServiceAuthReservation value = fixture (SESSION_A, JTI_A);
  gboolean changed = FALSE;

  value.credential_id = g_strdup (value.credential_id);
  value.principal = g_strdup (value.principal);
  value.tenant = g_strdup (value.tenant);
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &value), ==,
      WYRELOG_E_OK);
  value.credential_id[4] = '1';
  value.principal[4] = 'X';
  value.tenant[0] = 'X';
  g_free (value.credential_id);
  g_free (value.principal);
  g_free (value.tenant);

  value = fixture (SESSION_A, JTI_A);
  assert_lookup (registry, &value, WYL_SERVICE_AUTH_PENDING);
  g_assert_cmpint (wyl_service_auth_registry_activate (registry, &value,
          &changed), ==, WYRELOG_E_OK);
  g_assert_true (changed);
  changed = TRUE;
  g_assert_cmpint (wyl_service_auth_registry_activate (registry, &value,
          &changed), ==, WYRELOG_E_POLICY);
  g_assert_false (changed);
  assert_lookup (registry, &value, WYL_SERVICE_AUTH_ACTIVE);
  g_assert_cmpint (wyl_service_auth_registry_revoke_exact (registry, &value,
          &changed), ==, WYRELOG_E_OK);
  g_assert_true (changed);
  changed = TRUE;
  g_assert_cmpint (wyl_service_auth_registry_revoke_exact (registry, &value,
          &changed), ==, WYRELOG_E_OK);
  g_assert_false (changed);
  g_assert_cmpint (wyl_service_auth_registry_activate (registry, &value,
          &changed), ==, WYRELOG_E_POLICY);
  assert_lookup (registry, &value, WYL_SERVICE_AUTH_REVOKED);
  g_assert_true (wyl_service_auth_registry_check_invariants_for_test
      (registry));
  wyl_service_auth_registry_unref (registry);
}

static void
test_validation_and_mismatches (void)
{
  WylServiceAuthRegistry *registry = new_registry ();
  WylServiceAuthReservation original = fixture (SESSION_A, JTI_A);
  WylServiceAuthReservation changed;
  gboolean result = TRUE;

  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &original), ==,
      WYRELOG_E_OK);

  changed = original;
  changed.session_id = (gchar *) JTI_A;
  g_assert_cmpint (wyl_service_auth_registry_activate (registry, &changed,
          &result), ==, WYRELOG_E_INVALID);
  g_assert_false (result);
  changed = original;
  changed.session_id = (gchar *) SESSION_B;
  g_assert_cmpint (wyl_service_auth_registry_activate (registry, &changed,
          &result), ==, WYRELOG_E_POLICY);
  g_assert_false (result);
  changed = original;
  changed.jti = (gchar *) JTI_B;
  g_assert_cmpint (wyl_service_auth_registry_activate (registry, &changed,
          &result), ==, WYRELOG_E_POLICY);
  g_assert_false (result);
  changed = original;
  changed.credential_id = (gchar *) CREDENTIAL_B;
  g_assert_cmpint (wyl_service_auth_registry_activate (registry, &changed,
          &result), ==, WYRELOG_E_POLICY);
  g_assert_false (result);
  changed = original;
  changed.generation = 2;
  g_assert_cmpint (wyl_service_auth_registry_activate (registry, &changed,
          &result), ==, WYRELOG_E_POLICY);
  g_assert_false (result);
  changed = original;
  changed.principal = (gchar *) "svc:tenant-a:other";
  g_assert_cmpint (wyl_service_auth_registry_activate (registry, &changed,
          &result), ==, WYRELOG_E_POLICY);
  g_assert_false (result);
  changed = original;
  changed.tenant = (gchar *) "tenant-b";
  g_assert_cmpint (wyl_service_auth_registry_activate (registry, &changed,
          &result), ==, WYRELOG_E_POLICY);
  g_assert_false (result);
  assert_lookup (registry, &original, WYL_SERVICE_AUTH_PENDING);

  WylServiceAuthReservation mismatches[6];
  for (guint i = 0; i < G_N_ELEMENTS (mismatches); i++)
    mismatches[i] = original;
  mismatches[0].session_id = (gchar *) SESSION_B;
  mismatches[1].jti = (gchar *) JTI_B;
  mismatches[2].credential_id = (gchar *) CREDENTIAL_B;
  mismatches[3].generation = 2;
  mismatches[4].principal = (gchar *) "svc:tenant-a:other";
  mismatches[5].tenant = (gchar *) "tenant-b";
  for (guint i = 0; i < G_N_ELEMENTS (mismatches); i++) {
    result = TRUE;
    g_assert_cmpint (wyl_service_auth_registry_revoke_exact (registry,
            &mismatches[i], &result), ==, WYRELOG_E_POLICY);
    g_assert_false (result);
    result = TRUE;
    g_assert_cmpint (wyl_service_auth_registry_remove_exact (registry,
            &mismatches[i], &result), ==, WYRELOG_E_POLICY);
    g_assert_false (result);
    assert_lookup (registry, &original, WYL_SERVICE_AUTH_PENDING);
    g_assert_cmpuint (wyl_service_auth_registry_size_for_test (registry), ==,
        1);
    g_assert_true (wyl_service_auth_registry_check_invariants_for_test
        (registry));
  }

  changed = original;
  changed.generation = 0;
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &changed), ==,
      WYRELOG_E_INVALID);
  changed = original;
  changed.principal = (gchar *) "human:a";
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &changed), ==,
      WYRELOG_E_INVALID);
  changed = original;
  changed.tenant = (gchar *) "tenant/a";
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &changed), ==,
      WYRELOG_E_INVALID);
  changed = original;
  changed.credential_id = (gchar *) "WLC_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &changed), ==,
      WYRELOG_E_INVALID);
  changed = original;
  changed.jti = (gchar *) "01890C10-2e3f-7000-8000-000000000102";
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &changed), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpuint (wyl_service_auth_registry_size_for_test (registry), ==, 1);
  wyl_service_auth_registry_unref (registry);
}

static void
test_duplicates_crossed_and_remove (void)
{
  WylServiceAuthRegistry *registry = new_registry ();
  WylServiceAuthReservation first = fixture (SESSION_A, JTI_A);
  WylServiceAuthReservation second = fixture (SESSION_B, JTI_B);
  WylServiceAuthReservation crossed = fixture (SESSION_A, JTI_B);
  WylServiceAuthReservation duplicate_session = fixture (SESSION_A,
      "01890c10-2e3f-7000-8000-000000000105");
  WylServiceAuthReservation duplicate_jti = fixture
      ("01890c10-2e3f-7000-8000-000000000106", JTI_A);
  WylServiceAuthReservation absent = fixture
      ("01890c10-2e3f-7000-8000-000000000107",
      "01890c10-2e3f-7000-8000-000000000108");
  WylServiceAuthReservation snapshot = { 0 };
  WylServiceAuthState state;
  gboolean result = FALSE;

  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &first), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &first), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &second), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry,
          &duplicate_session), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry,
          &duplicate_jti), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &crossed), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_service_auth_registry_lookup (registry,
          crossed.session_id, crossed.jti, &snapshot, &state, &result), ==,
      WYRELOG_E_POLICY);
  g_assert_false (result);
  g_assert_cmpint (wyl_service_auth_registry_remove_exact (registry, &crossed,
          &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (wyl_service_auth_registry_size_for_test (registry), ==, 2);

  g_assert_cmpint (wyl_service_auth_registry_remove_exact (registry, &first,
          &result), ==, WYRELOG_E_OK);
  g_assert_true (result);
  result = TRUE;
  g_assert_cmpint (wyl_service_auth_registry_remove_exact (registry, &first,
          &result), ==, WYRELOG_E_OK);
  g_assert_false (result);
  g_assert_cmpint (wyl_service_auth_registry_remove_exact (registry, &absent,
          &result), ==, WYRELOG_E_OK);
  g_assert_false (result);
  g_assert_cmpint (wyl_service_auth_registry_activate (registry, &absent,
          &result), ==, WYRELOG_E_NOT_FOUND);
  g_assert_cmpint (wyl_service_auth_registry_revoke_exact (registry, &absent,
          &result), ==, WYRELOG_E_NOT_FOUND);
  g_assert_cmpint (wyl_service_auth_registry_activate (registry, &second,
          &result), ==, WYRELOG_E_OK);
  g_assert_true (result);
  g_assert_cmpint (wyl_service_auth_registry_remove_exact (registry, &second,
          &result), ==, WYRELOG_E_OK);
  g_assert_true (result);
  g_assert_true (wyl_service_auth_registry_check_invariants_for_test
      (registry));
  wyl_service_auth_registry_unref (registry);
}

static void
test_populated_clear_and_reuse (void)
{
  WylServiceAuthRegistry *registry = new_registry ();
  WylServiceAuthReservation first = fixture (SESSION_A, JTI_A);
  WylServiceAuthReservation second = fixture (SESSION_B, JTI_B);
  WylServiceAuthReservation snapshot = { 0 };
  WylServiceAuthState state = WYL_SERVICE_AUTH_REVOKED;
  gboolean found = TRUE;

  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &first), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &second), ==,
      WYRELOG_E_OK);
  wyl_service_auth_registry_clear (registry);
  g_assert_cmpuint (wyl_service_auth_registry_size_for_test (registry), ==, 0);
  g_assert_true (wyl_service_auth_registry_check_invariants_for_test
      (registry));
  g_assert_cmpint (wyl_service_auth_registry_lookup (registry,
          first.session_id, first.jti, &snapshot, &state, &found), ==,
      WYRELOG_E_OK);
  g_assert_false (found);
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &first), ==,
      WYRELOG_E_OK);
  assert_lookup (registry, &first, WYL_SERVICE_AUTH_PENDING);
  wyl_service_auth_registry_clear (registry);
  wyl_service_auth_registry_unref (registry);
}

static void
assert_revoke_result (const WylServiceAuthRevokeResult *result,
    gsize matched, gsize transitioned)
{
  g_assert_cmpuint (result->matched, ==, matched);
  g_assert_cmpuint (result->transitioned, ==, transitioned);
}

static void
test_indexed_authority_sets (void)
{
  WylServiceAuthRegistry *registry = new_registry ();
  WylServiceAuthReservation first = fixture (SESSION_A, JTI_A);
  WylServiceAuthReservation second = fixture (SESSION_B, JTI_B);
  WylServiceAuthReservation third = fixture
      ("01890c10-2e3f-7000-8000-000000000105",
      "01890c10-2e3f-7000-8000-000000000106");
  WylServiceAuthReservation fourth = fixture
      ("01890c10-2e3f-7000-8000-000000000107",
      "01890c10-2e3f-7000-8000-000000000108");
  WylServiceAuthRevokeResult result = { 0 };
  gboolean changed = FALSE;

  second.tenant = (gchar *) "tenant-b";
  third.generation = 2;
  third.principal = (gchar *) "svc:tenant-a:other";
  fourth.credential_id = (gchar *) CREDENTIAL_B;
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &first), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &second), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &third), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &fourth), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_registry_activate (registry, &second,
          &changed), ==, WYRELOG_E_OK);

  g_assert_cmpint (wyl_service_auth_registry_revoke_credential_generation
      (registry, CREDENTIAL_A, 1, &result), ==, WYRELOG_E_OK);
  assert_revoke_result (&result, 2, 2);
  assert_lookup (registry, &first, WYL_SERVICE_AUTH_REVOKED);
  assert_lookup (registry, &second, WYL_SERVICE_AUTH_REVOKED);
  assert_lookup (registry, &third, WYL_SERVICE_AUTH_PENDING);
  assert_lookup (registry, &fourth, WYL_SERVICE_AUTH_PENDING);
  g_assert_cmpint (wyl_service_auth_registry_revoke_credential_generation
      (registry, CREDENTIAL_A, 1, &result), ==, WYRELOG_E_OK);
  assert_revoke_result (&result, 2, 0);

  g_assert_cmpint (wyl_service_auth_registry_revoke_principal (registry,
          third.principal, &result), ==, WYRELOG_E_OK);
  assert_revoke_result (&result, 1, 1);
  g_assert_cmpint (wyl_service_auth_registry_revoke_principal (registry,
          third.principal, &result), ==, WYRELOG_E_OK);
  assert_revoke_result (&result, 1, 0);
  g_assert_cmpint (wyl_service_auth_registry_revoke_tenant (registry,
          "tenant-a", &result), ==, WYRELOG_E_OK);
  assert_revoke_result (&result, 3, 1);
  g_assert_cmpint (wyl_service_auth_registry_revoke_tenant (registry,
          "tenant-a", &result), ==, WYRELOG_E_OK);
  assert_revoke_result (&result, 3, 0);
  assert_lookup (registry, &fourth, WYL_SERVICE_AUTH_REVOKED);
  g_assert_cmpint (wyl_service_auth_registry_revoke_principal (registry,
          first.principal, &result), ==, WYRELOG_E_OK);
  assert_revoke_result (&result, 3, 0);
  g_assert_cmpint (wyl_service_auth_registry_revoke_credential_generation
      (registry, CREDENTIAL_A, 99, &result), ==, WYRELOG_E_OK);
  assert_revoke_result (&result, 0, 0);
  g_assert_cmpint (wyl_service_auth_registry_revoke_principal (registry,
          "svc:tenant-a:absent", &result), ==, WYRELOG_E_OK);
  assert_revoke_result (&result, 0, 0);
  g_assert_cmpint (wyl_service_auth_registry_revoke_tenant (registry,
          "tenant-absent", &result), ==, WYRELOG_E_OK);
  assert_revoke_result (&result, 0, 0);

  result.matched = result.transitioned = 9;
  g_assert_cmpint (wyl_service_auth_registry_revoke_credential_generation
      (registry, CREDENTIAL_A, 0, &result), ==, WYRELOG_E_INVALID);
  assert_revoke_result (&result, 0, 0);
  g_assert_cmpint (wyl_service_auth_registry_revoke_credential_generation
      (registry, "wlc_invalid", 1, &result), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_service_auth_registry_revoke_principal (registry,
          "human:a", &result), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_service_auth_registry_revoke_tenant (registry,
          "tenant/a", &result), ==, WYRELOG_E_INVALID);
  g_assert_true (wyl_service_auth_registry_check_invariants_for_test
      (registry));
  wyl_service_auth_registry_unref (registry);
}

static void
test_indexed_remove_ordering (void)
{
  WylServiceAuthRegistry *registry = new_registry ();
  WylServiceAuthReservation value = fixture (SESSION_A, JTI_A);
  WylServiceAuthRevokeResult result = { 0 };
  gboolean removed = FALSE;

  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &value), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_registry_remove_exact (registry, &value,
          &removed), ==, WYRELOG_E_OK);
  g_assert_true (removed);
  g_assert_cmpint (wyl_service_auth_registry_revoke_credential_generation
      (registry, value.credential_id, value.generation, &result), ==,
      WYRELOG_E_OK);
  assert_revoke_result (&result, 0, 0);

  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &value), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_registry_revoke_credential_generation
      (registry, value.credential_id, value.generation, &result), ==,
      WYRELOG_E_OK);
  assert_revoke_result (&result, 1, 1);
  g_assert_cmpint (wyl_service_auth_registry_remove_exact (registry, &value,
          &removed), ==, WYRELOG_E_OK);
  g_assert_true (removed);
  g_assert_cmpint (wyl_service_auth_registry_revoke_principal (registry,
          value.principal, &result), ==, WYRELOG_E_OK);
  assert_revoke_result (&result, 0, 0);
  g_assert_cmpint (wyl_service_auth_registry_revoke_tenant (registry,
          value.tenant, &result), ==, WYRELOG_E_OK);
  assert_revoke_result (&result, 0, 0);
  g_assert_true (wyl_service_auth_registry_check_invariants_for_test
      (registry));
  wyl_service_auth_registry_unref (registry);
}

typedef struct
{
  GMutex mutex;
  GCond cond;
  guint ready;
  gboolean go;
} StartGate;

typedef struct
{
  GMutex mutex;
  GCond cond;
  guint allocations;
  guint frees;
  guint fail_at;
  guint block_at;
  gboolean blocked;
  gboolean released;
} CountingAllocator;

static gpointer
counting_alloc (gsize size, gpointer user_data)
{
  CountingAllocator *counter = user_data;
  guint ordinal;

  g_mutex_lock (&counter->mutex);
  ordinal = ++counter->allocations;
  if (counter->block_at == ordinal) {
    counter->blocked = TRUE;
    g_cond_broadcast (&counter->cond);
    while (!counter->released)
      g_cond_wait (&counter->cond, &counter->mutex);
  }
  g_mutex_unlock (&counter->mutex);
  if (ordinal == counter->fail_at)
    return NULL;
  return g_try_malloc (size);
}

static void
counting_free (gpointer memory, gpointer user_data)
{
  CountingAllocator *counter = user_data;

  if (memory == NULL)
    return;
  g_mutex_lock (&counter->mutex);
  counter->frees++;
  g_mutex_unlock (&counter->mutex);
  g_free (memory);
}

static WylServiceAuthRegistry *
new_counting_registry (CountingAllocator *counter)
{
  WylServiceAuthAllocator allocator = {
    .try_alloc = counting_alloc,
    .free = counting_free,
    .user_data = counter,
  };
  WylServiceAuthRegistry *registry = NULL;
  g_assert_cmpint (wyl_service_auth_registry_new_with_allocator (&allocator,
          &registry), ==, WYRELOG_E_OK);
  return registry;
}

static void
counter_clear (CountingAllocator *counter)
{
  g_cond_clear (&counter->cond);
  g_mutex_clear (&counter->mutex);
}

static void
test_counted_clear_reuse (void)
{
  CountingAllocator counter = { 0 };
  WylServiceAuthReservation first = fixture (SESSION_A, JTI_A);
  WylServiceAuthReservation second = fixture (SESSION_B, JTI_B);

  g_mutex_init (&counter.mutex);
  g_cond_init (&counter.cond);
  WylServiceAuthRegistry *registry = new_counting_registry (&counter);
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &first), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &second), ==,
      WYRELOG_E_OK);
  wyl_service_auth_registry_clear (registry);
  g_assert_cmpuint (counter.allocations, ==, counter.frees);
  g_assert_true (wyl_service_auth_registry_check_invariants_for_test
      (registry));
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &first), ==,
      WYRELOG_E_OK);
  wyl_service_auth_registry_unref (registry);
  g_assert_cmpuint (counter.allocations, ==, counter.frees);
  counter_clear (&counter);
}

static void
test_allocation_failures_and_cleanup (void)
{
  WylServiceAuthReservation value = fixture (SESSION_A, JTI_A);

  for (guint fail_at = 1; fail_at <= 12; fail_at++) {
    CountingAllocator counter = { 0 };
    WylServiceAuthRegistry *registry;
    g_mutex_init (&counter.mutex);
    g_cond_init (&counter.cond);
    counter.fail_at = fail_at;
    registry = new_counting_registry (&counter);
    g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &value), ==,
        WYRELOG_E_NOMEM);
    g_assert_cmpuint (wyl_service_auth_registry_size_for_test (registry), ==,
        0);
    g_assert_true (wyl_service_auth_registry_check_invariants_for_test
        (registry));
    g_assert_cmpuint (counter.frees, ==, fail_at - 1);
    wyl_service_auth_registry_unref (registry);
    counter_clear (&counter);
  }

  CountingAllocator counter = { 0 };
  g_mutex_init (&counter.mutex);
  g_cond_init (&counter.cond);
  WylServiceAuthRegistry *registry = new_counting_registry (&counter);
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &value), ==,
      WYRELOG_E_OK);
  for (guint fail_offset = 1; fail_offset <= 5; fail_offset++) {
    WylServiceAuthReservation snapshot = { 0 };
    WylServiceAuthState state = WYL_SERVICE_AUTH_REVOKED;
    gboolean found = TRUE;
    counter.fail_at = counter.allocations + fail_offset;
    g_assert_cmpint (wyl_service_auth_registry_lookup (registry,
            value.session_id, value.jti, &snapshot, &state, &found), ==,
        WYRELOG_E_NOMEM);
    g_assert_false (found);
    g_assert_null (snapshot.session_id);
    g_assert_null (snapshot.jti);
    g_assert_null (snapshot.credential_id);
    g_assert_null (snapshot.principal);
    g_assert_null (snapshot.tenant);
  }
  counter.fail_at = 0;
  WylServiceAuthReservation reusable = { 0 };
  WylServiceAuthState reusable_state = WYL_SERVICE_AUTH_REVOKED;
  gboolean reusable_found = FALSE;
  g_assert_cmpint (wyl_service_auth_registry_lookup (registry,
          value.session_id, value.jti, &reusable, &reusable_state,
          &reusable_found), ==, WYRELOG_E_OK);
  g_assert_true (reusable_found);
  guint frees_before_reuse = counter.frees;
  g_assert_cmpint (wyl_service_auth_registry_lookup (registry,
          reusable.session_id, reusable.jti, &reusable, &reusable_state,
          &reusable_found), ==, WYRELOG_E_OK);
  g_assert_true (reusable_found);
  g_assert_cmpuint (counter.frees, ==, frees_before_reuse + 5);
  counter.fail_at = counter.allocations + 1;
  frees_before_reuse = counter.frees;
  g_assert_cmpint (wyl_service_auth_registry_lookup (registry,
          reusable.session_id, reusable.jti, &reusable, &reusable_state,
          &reusable_found), ==, WYRELOG_E_NOMEM);
  g_assert_false (reusable_found);
  g_assert_null (reusable.session_id);
  g_assert_null (reusable.jti);
  g_assert_null (reusable.credential_id);
  g_assert_null (reusable.principal);
  g_assert_null (reusable.tenant);
  g_assert_cmpint (reusable_state, ==, WYL_SERVICE_AUTH_PENDING);
  g_assert_cmpuint (counter.frees, ==, frees_before_reuse + 5);
  counter.fail_at = 0;
  g_assert_true (wyl_service_auth_registry_check_invariants_for_test
      (registry));
  g_assert_cmpint (wyl_service_auth_registry_lookup (registry,
          value.session_id, value.jti, &reusable, &reusable_state,
          &reusable_found), ==, WYRELOG_E_OK);
  g_assert_true (reusable_found);
  wyl_service_auth_reservation_clear (&reusable);

  WylServiceAuthReservation retained = { 0 };
  WylServiceAuthState retained_state = WYL_SERVICE_AUTH_REVOKED;
  gboolean retained_found = FALSE;
  g_assert_cmpint (wyl_service_auth_registry_lookup (registry,
          value.session_id, value.jti, &retained, &retained_state,
          &retained_found), ==, WYRELOG_E_OK);
  g_assert_true (retained_found);
  g_assert_cmpint (retained_state, ==, WYL_SERVICE_AUTH_PENDING);
  wyl_service_auth_registry_ref (registry);
  wyl_service_auth_registry_unref (registry);
  wyl_service_auth_registry_unref (registry);
  g_assert_cmpstr (retained.principal, ==, value.principal);
  wyl_service_auth_reservation_clear (&retained);
  g_assert_cmpuint (counter.allocations, ==, counter.frees + 6);
  counter_clear (&counter);
}

typedef struct
{
  WylServiceAuthRegistry *registry;
  WylServiceAuthReservation value;
  wyrelog_error_t rc;
  gboolean result;
  guint operation;
  StartGate *gate;
} ThreadCall;

static void
start_gate_wait (StartGate *gate)
{
  if (gate == NULL)
    return;
  g_mutex_lock (&gate->mutex);
  gate->ready++;
  g_cond_broadcast (&gate->cond);
  while (!gate->go)
    g_cond_wait (&gate->cond, &gate->mutex);
  g_mutex_unlock (&gate->mutex);
}

static gpointer
thread_call (gpointer data)
{
  ThreadCall *call = data;
  start_gate_wait (call->gate);
  if (call->operation == 0)
    call->rc = wyl_service_auth_registry_reserve (call->registry, &call->value);
  else if (call->operation == 1)
    call->rc = wyl_service_auth_registry_activate (call->registry,
        &call->value, &call->result);
  else if (call->operation == 2)
    call->rc = wyl_service_auth_registry_revoke_exact (call->registry,
        &call->value, &call->result);
  else
    call->rc = wyl_service_auth_registry_remove_exact (call->registry,
        &call->value, &call->result);
  return NULL;
}

static void
start_gate_release (StartGate *gate, guint expected)
{
  g_mutex_lock (&gate->mutex);
  while (gate->ready != expected)
    g_cond_wait (&gate->cond, &gate->mutex);
  gate->go = TRUE;
  g_cond_broadcast (&gate->cond);
  g_mutex_unlock (&gate->mutex);
}

static void
start_gate_clear (StartGate *gate)
{
  g_cond_clear (&gate->cond);
  g_mutex_clear (&gate->mutex);
}

static void
test_concurrent_shared_bucket_reserve (void)
{
  CountingAllocator counter = { 0 };
  ThreadCall calls[8] = { 0 };
  GThread *threads[8];
  gchar session_ids[8][37];
  gchar jtis[8][37];
  StartGate gate = { 0 };
  WylServiceAuthRevokeResult result = { 0 };

  g_mutex_init (&counter.mutex);
  g_cond_init (&counter.cond);
  WylServiceAuthRegistry *registry = new_counting_registry (&counter);
  g_mutex_init (&gate.mutex);
  g_cond_init (&gate.cond);
  for (guint i = 0; i < G_N_ELEMENTS (calls); i++) {
    g_snprintf (session_ids[i], sizeof session_ids[i],
        "01890c10-2e3f-7000-8000-%012x", 0x200 + i);
    g_snprintf (jtis[i], sizeof jtis[i],
        "01890c10-2e3f-7000-8000-%012x", 0x300 + i);
    calls[i].registry = registry;
    calls[i].value = fixture (session_ids[i], jtis[i]);
    calls[i].gate = &gate;
    threads[i] = g_thread_new ("shared-bucket", thread_call, &calls[i]);
  }
  start_gate_release (&gate, G_N_ELEMENTS (calls));
  for (guint i = 0; i < G_N_ELEMENTS (calls); i++) {
    g_thread_join (threads[i]);
    g_assert_cmpint (calls[i].rc, ==, WYRELOG_E_OK);
  }
  start_gate_clear (&gate);
  g_assert_cmpuint (wyl_service_auth_registry_size_for_test (registry), ==,
      G_N_ELEMENTS (calls));
  g_assert_true (wyl_service_auth_registry_check_invariants_for_test
      (registry));
  g_assert_cmpint (wyl_service_auth_registry_revoke_credential_generation
      (registry, CREDENTIAL_A, 1, &result), ==, WYRELOG_E_OK);
  assert_revoke_result (&result, G_N_ELEMENTS (calls), G_N_ELEMENTS (calls));
  wyl_service_auth_registry_unref (registry);
  g_assert_cmpuint (counter.allocations, ==, counter.frees);
  counter_clear (&counter);
}

typedef struct
{
  WylServiceAuthRegistry *registry;
  WylServiceAuthReservation value;
  StartGate *gate;
  gboolean remove;
  gboolean removed;
  WylServiceAuthRevokeResult result;
  wyrelog_error_t rc;
} IndexedRaceCall;

static gpointer
indexed_race_call (gpointer data)
{
  IndexedRaceCall *call = data;

  start_gate_wait (call->gate);
  if (call->remove)
    call->rc = wyl_service_auth_registry_remove_exact (call->registry,
        &call->value, &call->removed);
  else
    call->rc = wyl_service_auth_registry_revoke_credential_generation
        (call->registry, call->value.credential_id, call->value.generation,
        &call->result);
  return NULL;
}

static void
test_indexed_revoke_remove_race (void)
{
  for (guint iteration = 0; iteration < 50; iteration++) {
    WylServiceAuthRegistry *registry = new_registry ();
    WylServiceAuthReservation value = fixture (SESSION_A, JTI_A);
    StartGate gate = { 0 };
    IndexedRaceCall revoke = { registry, value, &gate, FALSE, FALSE,
      {0}, WYRELOG_E_INTERNAL
    };
    IndexedRaceCall remove = { registry, value, &gate, TRUE, FALSE,
      {0}, WYRELOG_E_INTERNAL
    };

    g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &value), ==,
        WYRELOG_E_OK);
    g_mutex_init (&gate.mutex);
    g_cond_init (&gate.cond);
    GThread *revoke_thread = g_thread_new ("indexed-revoke",
        indexed_race_call, &revoke);
    GThread *remove_thread = g_thread_new ("indexed-remove",
        indexed_race_call, &remove);
    start_gate_release (&gate, 2);
    g_thread_join (revoke_thread);
    g_thread_join (remove_thread);
    start_gate_clear (&gate);

    g_assert_cmpint (revoke.rc, ==, WYRELOG_E_OK);
    g_assert_cmpint (remove.rc, ==, WYRELOG_E_OK);
    g_assert_true (remove.removed);
    g_assert_true ((revoke.result.matched == 0
            && revoke.result.transitioned == 0)
        || (revoke.result.matched == 1 && revoke.result.transitioned == 1));
    g_assert_cmpuint (wyl_service_auth_registry_size_for_test (registry), ==,
        0);
    g_assert_true (wyl_service_auth_registry_check_invariants_for_test
        (registry));
    wyl_service_auth_registry_unref (registry);
  }
}

static void
test_concurrent_indexed_revokes (void)
{
  for (guint iteration = 0; iteration < 50; iteration++) {
    WylServiceAuthRegistry *registry = new_registry ();
    WylServiceAuthReservation values[4] = {
      fixture (SESSION_A, JTI_A),
      fixture (SESSION_B, JTI_B),
      fixture ("01890c10-2e3f-7000-8000-000000000105",
          "01890c10-2e3f-7000-8000-000000000106"),
      fixture ("01890c10-2e3f-7000-8000-000000000107",
          "01890c10-2e3f-7000-8000-000000000108"),
    };
    StartGate gate = { 0 };
    IndexedRaceCall first = { registry, values[0], &gate, FALSE, FALSE,
      {0}, WYRELOG_E_INTERNAL
    };
    IndexedRaceCall second = { registry, values[0], &gate, FALSE, FALSE,
      {0}, WYRELOG_E_INTERNAL
    };
    gboolean changed = FALSE;

    for (guint i = 0; i < G_N_ELEMENTS (values); i++)
      g_assert_cmpint (wyl_service_auth_registry_reserve (registry,
              &values[i]), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_service_auth_registry_activate (registry, &values[1],
            &changed), ==, WYRELOG_E_OK);
    g_mutex_init (&gate.mutex);
    g_cond_init (&gate.cond);
    GThread *first_thread = g_thread_new ("indexed-revoke-a",
        indexed_race_call, &first);
    GThread *second_thread = g_thread_new ("indexed-revoke-b",
        indexed_race_call, &second);
    start_gate_release (&gate, 2);
    g_thread_join (first_thread);
    g_thread_join (second_thread);
    start_gate_clear (&gate);

    g_assert_cmpint (first.rc, ==, WYRELOG_E_OK);
    g_assert_cmpint (second.rc, ==, WYRELOG_E_OK);
    g_assert_cmpuint (first.result.matched, ==, G_N_ELEMENTS (values));
    g_assert_cmpuint (second.result.matched, ==, G_N_ELEMENTS (values));
    g_assert_cmpuint (first.result.transitioned + second.result.transitioned,
        ==, G_N_ELEMENTS (values));
    g_assert_true ((first.result.transitioned == G_N_ELEMENTS (values)
            && second.result.transitioned == 0)
        || (first.result.transitioned == 0
            && second.result.transitioned == G_N_ELEMENTS (values)));
    for (guint i = 0; i < G_N_ELEMENTS (values); i++)
      assert_lookup (registry, &values[i], WYL_SERVICE_AUTH_REVOKED);
    g_assert_true (wyl_service_auth_registry_check_invariants_for_test
        (registry));
    wyl_service_auth_registry_unref (registry);
  }
}

static void
test_duplicate_after_preflight (void)
{
  CountingAllocator counter = { 0 };
  g_mutex_init (&counter.mutex);
  g_cond_init (&counter.cond);
  counter.block_at = 12;
  WylServiceAuthRegistry *registry = new_counting_registry (&counter);
  ThreadCall delayed = {
    .registry = registry,
    .value = fixture (SESSION_A, JTI_A),
  };
  ThreadCall winner = {
    .registry = registry,
    .value = fixture (SESSION_A, JTI_A),
  };
  GThread *first = g_thread_new ("preflight", thread_call, &delayed);

  g_mutex_lock (&counter.mutex);
  while (!counter.blocked)
    g_cond_wait (&counter.cond, &counter.mutex);
  g_mutex_unlock (&counter.mutex);
  GThread *second = g_thread_new ("winner", thread_call, &winner);
  g_thread_join (second);
  g_assert_cmpint (winner.rc, ==, WYRELOG_E_OK);
  g_mutex_lock (&counter.mutex);
  counter.released = TRUE;
  g_cond_broadcast (&counter.cond);
  g_mutex_unlock (&counter.mutex);
  g_thread_join (first);
  g_assert_cmpint (delayed.rc, ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (wyl_service_auth_registry_size_for_test (registry), ==, 1);
  g_assert_true (wyl_service_auth_registry_check_invariants_for_test
      (registry));
  wyl_service_auth_registry_unref (registry);
  g_assert_cmpuint (counter.allocations, ==, counter.frees);
  counter_clear (&counter);
}

static void
test_concurrent_duplicate_and_transitions (void)
{
  WylServiceAuthRegistry *registry = new_registry ();
  ThreadCall calls[12] = { 0 };
  GThread *threads[12];
  guint winners = 0;

  for (guint i = 0; i < G_N_ELEMENTS (calls); i++) {
    calls[i].registry = registry;
    calls[i].value = fixture (SESSION_A, JTI_A);
    threads[i] = g_thread_new ("duplicate", thread_call, &calls[i]);
  }
  for (guint i = 0; i < G_N_ELEMENTS (calls); i++) {
    g_thread_join (threads[i]);
    if (calls[i].rc == WYRELOG_E_OK)
      winners++;
    else
      g_assert_cmpint (calls[i].rc, ==, WYRELOG_E_POLICY);
  }
  g_assert_cmpuint (winners, ==, 1);

  StartGate gate = { 0 };
  g_mutex_init (&gate.mutex);
  g_cond_init (&gate.cond);
  ThreadCall activate = {
    registry, fixture (SESSION_A, JTI_A), 0, FALSE, 1, &gate
  };
  ThreadCall revoke = {
    registry, fixture (SESSION_A, JTI_A), 0, FALSE, 2, &gate
  };
  threads[0] = g_thread_new ("activate", thread_call, &activate);
  threads[1] = g_thread_new ("revoke", thread_call, &revoke);
  start_gate_release (&gate, 2);
  g_thread_join (threads[0]);
  g_thread_join (threads[1]);
  start_gate_clear (&gate);
  g_assert_cmpint (revoke.rc, ==, WYRELOG_E_OK);
  g_assert_true (revoke.result);
  g_assert_true (activate.rc == WYRELOG_E_OK
      || activate.rc == WYRELOG_E_POLICY);
  WylServiceAuthReservation value = fixture (SESSION_A, JTI_A);
  assert_lookup (registry, &value, WYL_SERVICE_AUTH_REVOKED);

  guint removed = 0;
  for (guint i = 0; i < G_N_ELEMENTS (calls); i++) {
    calls[i].operation = 3;
    calls[i].result = FALSE;
    threads[i] = g_thread_new ("remove", thread_call, &calls[i]);
  }
  for (guint i = 0; i < G_N_ELEMENTS (calls); i++) {
    g_thread_join (threads[i]);
    g_assert_cmpint (calls[i].rc, ==, WYRELOG_E_OK);
    if (calls[i].result)
      removed++;
  }
  g_assert_cmpuint (removed, ==, 1);
  g_assert_cmpuint (wyl_service_auth_registry_size_for_test (registry), ==, 0);
  g_assert_true (wyl_service_auth_registry_check_invariants_for_test
      (registry));
  wyl_service_auth_registry_unref (registry);
}

static void
test_transition_remove_races (void)
{
  for (guint operation = 1; operation <= 2; operation++) {
    for (guint iteration = 0; iteration < 50; iteration++) {
      WylServiceAuthRegistry *registry = new_registry ();
      WylServiceAuthReservation value = fixture (SESSION_A, JTI_A);
      WylServiceAuthReservation snapshot = { 0 };
      WylServiceAuthState state = WYL_SERVICE_AUTH_PENDING;
      gboolean found = TRUE;
      StartGate gate = { 0 };
      ThreadCall transition = {
        registry, value, 0, FALSE, operation, &gate
      };
      ThreadCall remove = { registry, value, 0, FALSE, 3, &gate };

      g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &value),
          ==, WYRELOG_E_OK);
      g_mutex_init (&gate.mutex);
      g_cond_init (&gate.cond);
      GThread *transition_thread = g_thread_new ("transition", thread_call,
          &transition);
      GThread *remove_thread = g_thread_new ("remove", thread_call, &remove);
      start_gate_release (&gate, 2);
      g_thread_join (transition_thread);
      g_thread_join (remove_thread);
      start_gate_clear (&gate);

      g_assert_cmpint (remove.rc, ==, WYRELOG_E_OK);
      g_assert_true (remove.result);
      g_assert_true (transition.rc == WYRELOG_E_OK
          || transition.rc == WYRELOG_E_NOT_FOUND);
      g_assert_cmpint (transition.result, ==, transition.rc == WYRELOG_E_OK);
      g_assert_cmpint (wyl_service_auth_registry_lookup (registry,
              value.session_id, value.jti, &snapshot, &state, &found), ==,
          WYRELOG_E_OK);
      g_assert_false (found);
      g_assert_true (wyl_service_auth_registry_check_invariants_for_test
          (registry));
      wyl_service_auth_registry_unref (registry);
    }
  }
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/daemon/auth-registry/copy-state",
      test_copy_lifetime_and_state_table);
  g_test_add_func ("/daemon/auth-registry/validation-mismatch",
      test_validation_and_mismatches);
  g_test_add_func ("/daemon/auth-registry/duplicates-remove",
      test_duplicates_crossed_and_remove);
  g_test_add_func ("/daemon/auth-registry/clear-reuse",
      test_populated_clear_and_reuse);
  g_test_add_func ("/daemon/auth-registry/indexed-authority-sets",
      test_indexed_authority_sets);
  g_test_add_func ("/daemon/auth-registry/indexed-remove-ordering",
      test_indexed_remove_ordering);
  g_test_add_func ("/daemon/auth-registry/allocation-cleanup",
      test_allocation_failures_and_cleanup);
  g_test_add_func ("/daemon/auth-registry/counted-clear-reuse",
      test_counted_clear_reuse);
  g_test_add_func ("/daemon/auth-registry/preflight-race",
      test_duplicate_after_preflight);
  g_test_add_func ("/daemon/auth-registry/shared-bucket-concurrency",
      test_concurrent_shared_bucket_reserve);
  g_test_add_func ("/daemon/auth-registry/indexed-revoke-remove-race",
      test_indexed_revoke_remove_race);
  g_test_add_func ("/daemon/auth-registry/concurrent-indexed-revokes",
      test_concurrent_indexed_revokes);
  g_test_add_func ("/daemon/auth-registry/concurrency",
      test_concurrent_duplicate_and_transitions);
  g_test_add_func ("/daemon/auth-registry/transition-remove-races",
      test_transition_remove_races);
  return g_test_run ();
}

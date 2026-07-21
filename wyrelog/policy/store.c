/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef G_OS_WIN32
/* Expose POSIX.1-2008 openat/renameat/unlinkat/O_NOFOLLOW/O_CLOEXEC.
 * Must be set before any system header is pulled in. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
/* Apple SDKs gate O_NOFOLLOW (and friends) behind _DARWIN_C_SOURCE
 * when the compiler is invoked with -std=cNN; setting _POSIX_C_SOURCE
 * alone is not sufficient because clang predefines __STRICT_ANSI__
 * and the Darwin headers drop __DARWIN_C_LEVEL below what
 * sys/fcntl.h requires for O_NOFOLLOW visibility. */
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>
#include <chronoid/ksuid.h>
#include <glib/gstdio.h>

#ifdef G_OS_WIN32
#include <io.h>
#include <windows.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

#include "store-private.h"

#include "policy/store-handoff-delivery-private.h"
#include "policy/store-handoff-maintenance-private.h"
#include "policy/store-handoff-retirement-private.h"
#include "wyrelog/auth/service-credential-private.h"
#include "wyrelog/wyl-id-private.h"
#include "wyrelog/wyl-common-private.h"
#include "wyrelog/wyl-fsm-permission-scope-private.h"
#include "wyrelog/wyl-log-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "store-lease-private.h"
#include "fact/graph-locator-private.h"
#include "fact/root-writer-lease-private.h"

#define WYL_POLICY_STORE_CLEAR_SUFFIX ".wyrelog-clear"
#define WYL_POLICY_STORE_TMP_SUFFIX ".wyrelog-tmp"

#define WYL_POLICY_STORE_KEY_LEN crypto_secretbox_KEYBYTES
#define WYL_POLICY_STORE_KEY_ID_LEN crypto_generichash_BYTES
#define WYL_POLICY_STORE_ENCRYPTION_LABEL "policy_store_v1"
#define WYL_POLICY_STORE_MAGIC "WYLPS"
#define WYL_POLICY_STORE_MAGIC_LEN 5
#define WYL_POLICY_STORE_FORMAT_VERSION 1
#define WYL_POLICY_STORE_DESERIALIZE_GROWTH_BYTES (1024u * 1024u)
#define WYL_POLICY_STORE_MAX_IMAGE_BYTES (64u * 1024u * 1024u)
#define WYL_POLICY_ROTATION_INTENT_AUTH_LABEL \
  "wyrelog.policy.rotation-intent.auth.v1"

#define WYL_SERVICE_CVK_ENVELOPE_BYTES 124u
#define WYL_SERVICE_CVK_MAGIC_OFFSET 0u
#define WYL_SERVICE_CVK_MAGIC_BYTES 8u
#define WYL_SERVICE_CVK_DOMAIN_OFFSET 8u
#define WYL_SERVICE_CVK_DOMAIN_BYTES 40u
#define WYL_SERVICE_CVK_VERSION_OFFSET 48u
#define WYL_SERVICE_CVK_SLOT_OFFSET 49u
#define WYL_SERVICE_CVK_GENERATION_OFFSET 50u
#define WYL_SERVICE_CVK_BINDING_OFFSET 58u
#define WYL_SERVICE_CVK_CVK_LEN_OFFSET 90u
#define WYL_SERVICE_CVK_CVK_OFFSET 92u
#define WYL_SERVICE_CVK_ENVELOPE_VERSION 1u
#define WYL_SERVICE_CVK_SLOT 1u
#define WYL_SERVICE_CVK_GENERATION 1u
#define WYL_SERVICE_CVK_BINDING_BYTES 32u
#define WYL_SERVICE_CVK_MAGIC "WYLCVK1\0"
#define WYL_SERVICE_CVK_DOMAIN "wyrelog.service-credential.cvk-envelope"
#define WYL_SERVICE_CVK_BINDING_LABEL \
  "wyrelog.service-credential.cvk.provider-binding.v1"
#define WYL_SERVICE_CVK_BINDING_DOMAIN \
  "wyrelog.service-credential.cvk.provider-binding"
#define WYL_SERVICE_HANDOFF_ENVELOPE_BYTES 179u
#define WYL_SERVICE_HANDOFF_MAGIC_BYTES 8u
#define WYL_SERVICE_HANDOFF_DOMAIN_BYTES 42u
#define WYL_SERVICE_HANDOFF_BINDING_BYTES 32u
#define WYL_SERVICE_HANDOFF_MAGIC "WYLESC1\0"
#define WYL_SERVICE_HANDOFF_DOMAIN "wyrelog.service-credential.handoff.escrow"
#define WYL_SERVICE_HANDOFF_BINDING_LABEL \
  "wyrelog.service-credential.handoff.escrow.provider-binding.v1"
#define WYL_SERVICE_HANDOFF_BINDING_DOMAIN \
  "wyrelog.service-credential.handoff.escrow.provider-binding"
#define WYL_SERVICE_CREDENTIAL_ID_ATTEMPTS 4u

G_STATIC_ASSERT (sizeof (WYL_SERVICE_CVK_MAGIC) - 1
    == WYL_SERVICE_CVK_MAGIC_BYTES);
G_STATIC_ASSERT (sizeof (WYL_SERVICE_CVK_DOMAIN) ==
    WYL_SERVICE_CVK_DOMAIN_BYTES);
G_STATIC_ASSERT (WYL_SERVICE_CVK_CVK_OFFSET +
    WYL_SERVICE_CREDENTIAL_CVK_BYTES == WYL_SERVICE_CVK_ENVELOPE_BYTES);
G_STATIC_ASSERT (sizeof (WYL_SERVICE_HANDOFF_MAGIC) - 1 ==
    WYL_SERVICE_HANDOFF_MAGIC_BYTES);
G_STATIC_ASSERT (sizeof (WYL_SERVICE_HANDOFF_DOMAIN) ==
    WYL_SERVICE_HANDOFF_DOMAIN_BYTES);

typedef struct
{
  guint8 magic[WYL_POLICY_STORE_MAGIC_LEN];
  guint8 version;
  guint8 flags;
  guint8 reserved;
  guint8 provider_id[WYL_POLICY_STORE_KEY_ID_LEN];
  guint8 nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  guint64 ciphertext_len_le;
} __attribute__((packed)) WylPolicyStoreFileHeader;

G_STATIC_ASSERT (WYL_POLICY_STORE_MAGIC_LEN == 5);

typedef struct
{
  wyl_keyprovider_vtable_t vtable;
  gpointer state;
  void (*state_free) (gpointer state);
  gboolean owned;
} WylOwnedKeyProvider;

struct wyl_policy_store_t
{
  sqlite3 *db;
  /* SQLite uses this caller-owned deserialize buffer until sqlite3_close().
   * Retain the metadata so it can be wiped and freed immediately afterward. */
  guint8 *deserialized_image;
  gsize deserialized_image_capacity;
  wyl_policy_store_lease_t *lease;
  gchar *canonical_path;
  gchar *work_path;
  /* Directory fd anchoring Wyrelog-owned openat()/renameat() calls against
   * canonical_path. SQLite opens the main database and later auxiliary files
   * by pathname throughout the store lifetime, so the resolved namespace must
   * satisfy docs/developer-lifecycle.md until close completes. -1 when unused
   * (in-memory stores or non-POSIX builds). */
  int canonical_dirfd;
  gchar *canonical_basename;
  gchar *work_basename;
  guint8 encryption_key[WYL_POLICY_STORE_KEY_LEN];
  guint8 encryption_key_id[WYL_POLICY_STORE_KEY_ID_LEN];
  WylOwnedKeyProvider keyprovider;
  /* Provider retired by rotation and released during ordered store close. */
  WylOwnedKeyProvider rotation_cleanup_keyprovider;
  gboolean encrypted;
  gboolean key_materialized;
  gboolean suppress_close_persist;
  GMutex service_cvk_mutex;
  GMutex service_domain_gate_mutex;
  GMutex service_lifecycle_mutex;
  GRecMutex graph_authority_mutex;
  gchar *fact_root_path;
  WylFactGraphResolver fact_root_resolver;
  gint service_authority_transaction_active;
  gint service_authority_transaction_poisoned;
  gint service_authority_abort_allowed;
  GThread *service_authority_poison_owner;
  guint64 service_authority_poison_serial;
  gint service_authority_coordination_terminal;
  WylPolicyGraphAuthorityMigrationFailStage graph_authority_migration_fail_once;
  WylPolicyGraphAuthorityMutationFailStage mutation_fail_once;
  guint64 next_service_authority_transaction_id;
    WylPolicyAuthorityTransactionFailStage
      service_authority_transaction_fail_once;
  gboolean service_lifecycle_fail_commit_once;
  WylPolicyServiceHandoffFailStage service_handoff_fail_once;
  wyl_policy_service_rotate_fail_stage_t service_rotate_fail_once;
  wyl_policy_store_cvk_runtime_t service_cvk_runtime;
  guint8 *service_cvk_envelope;
  wyl_policy_store_service_handoff_unseal_gate_fn service_handoff_unseal_gate;
  gpointer service_handoff_unseal_gate_data;
  WylPolicyServiceHandoffMaintenanceNowFunc service_handoff_maintenance_now;
  gpointer service_handoff_maintenance_clock_data;
};

gboolean
wyl_policy_store_pinned_backend_available (void)
{
  /* Keep the platform matrix explicit until the first VFS implementation is
   * merged. No supported build currently provides the required pinned
   * xOpen/xDelete/xAccess/xFullPathname and journal/WAL/SHM semantics. */
#if defined(G_OS_WIN32)
  return FALSE;                 /* HANDLE/reparse-aware VFS is tracked separately. */
#elif defined(__APPLE__)
  return FALSE;                 /* dirfd-backed VFS is not available in this slice. */
#elif defined(__linux__)
  return FALSE;                 /* POSIX rollback-journal VFS is tracked separately. */
#else
  return FALSE;                 /* Unknown platforms fail closed by default. */
#endif
}

typedef enum
{
  WYL_SERVICE_AUTHORITY_EVIDENCE_PENDING,
  WYL_SERVICE_AUTHORITY_EVIDENCE_COMMITTED,
  WYL_SERVICE_AUTHORITY_EVIDENCE_INVALID,
} WylServiceAuthorityEvidenceState;

typedef enum
{
  WYL_SERVICE_AUTHORITY_WRITE_INTENT_STATE_NONE,
  WYL_SERVICE_AUTHORITY_WRITE_INTENT_STATE_ACQUIRED,
  WYL_SERVICE_AUTHORITY_WRITE_INTENT_STATE_ROLLBACK_REQUIRED,
} WylServiceAuthorityWriteIntentState;

struct _WylServiceAuthorityCommitEvidence
{
  gint refs;
  GMutex mutex;
  WylHandle *handle;
  WylServiceAuthAuthority *authority_identity;  /* borrowed from handle */
  guint64 store_generation;
  guint64 transaction_serial;
  guint64 write_lease_serial;
  WylServiceAuthorityEvidenceState state;
  GThread *pending_owner;
};

struct _WylServiceAuthorityTransaction
{
  wyl_policy_store_t *store;
  WylHandle *handle;
  WylServiceAuthWriteLease *write_lease;        /* claimed; borrowed */
  GThread *owner;
  gchar *savepoint;
  WylServiceAuthorityTransactionState state;
  wyrelog_error_t primary_result;
  wyrelog_error_t cleanup_result;
  int primary_sqlite_extended_error;
  int recovery_sqlite_extended_error;
  WylPolicyAuthorityTransactionFailStage fault;
  gboolean owns_store_locks;
  gboolean owns_handle_pin;
  gboolean owns_store_rank;
  guint64 originating_writer_serial;
  GMutex abort_barrier_mutex;
  GCond abort_barrier_cond;
  gboolean abort_barrier_armed;
  gboolean abort_barrier_reached;
  gboolean abort_barrier_released;
  GMutex cleanup_barrier_mutex;
  GCond cleanup_barrier_cond;
  gboolean cleanup_barrier_armed;
  gboolean cleanup_barrier_reached;
  gboolean cleanup_barrier_released;
  guint64 serial;
  WylServiceAuthorityCommitEvidence *commit_evidence;
  gboolean durable_operation_started;
  gboolean fail_evidence_allocation_once;
  guint evidence_allocation_count;
  gboolean fail_last_used_sql_once;
  WylServiceAuthorityWriteIntentState write_intent_state;
  wyrelog_error_t write_intent_failure_rc;
  WylServiceAuthorityWriteIntentOutcome write_intent_failure;
  GMutex write_intent_barrier_mutex;
  GCond write_intent_barrier_cond;
  gboolean write_intent_barrier_armed;
  gboolean write_intent_barrier_reached;
  gboolean write_intent_barrier_released;
  int write_intent_fail_sql_once;
  gboolean participant_rollback_only;
  wyrelog_error_t participant_failure_rc;
  int participant_failure_sqlite_extended_error;
  gboolean fail_service_exchange_preallocation_once;
  gboolean fail_service_exchange_readback_once;
  gboolean fail_service_exchange_typed_read_prepare_once;
  gboolean fail_service_exchange_typed_read_step_once;
  gboolean fail_service_exchange_typed_read_allocation_once;
  WylServiceExchangeReceipt *service_exchange_pending;
  guint service_exchange_receipt_fail_allocation_at;
  guint service_exchange_receipt_allocation_count;
  gboolean fail_service_exchange_evidence_ref_once;
};

struct _WylServiceExchangeReceipt
{
  gint refs;
  WylHandle *handle;
  WylServiceExchangeIntentionRecord *record;
  WylServiceExchangeIntentionClassification classification;
  guint64 transaction_serial;
  guint64 store_generation;
  WylServiceAuthorityCommitEvidence *evidence;
};

static wyrelog_error_t prepare_stmt (sqlite3 * db, const gchar * sql,
    sqlite3_stmt ** out_stmt);
static wyrelog_error_t bind_text (sqlite3_stmt * stmt, int index,
    const gchar * value);
static wyrelog_error_t query_single_text (sqlite3 * db, const gchar * sql,
    const gchar * id, gchar ** out_value);
static wyrelog_error_t service_domain_claim_request (wyl_policy_store_t * store,
    const gchar * request_id, const gchar * operation,
    const gchar * resource_id,
    const guint8 fingerprint[crypto_generichash_BYTES], gint64 now_us);
static wyrelog_error_t service_domain_append_audit (wyl_policy_store_t * store,
    const gchar * audit_id, gint64 now_us, const gchar * actor_subject_id,
    const gchar * action, const gchar * subject_id, const gchar * request_id);
static gboolean service_handoff_request_id_is_canonical (const gchar * value);
static gboolean service_handoff_exact_tuple_is_valid
    (const WylPolicyServiceHandoffExactTuple * tuple);
static wyrelog_error_t service_handoff_validate_exact_escrow
    (wyl_policy_store_t * store,
    const WylPolicyServiceHandoffExactTuple * tuple);
static wyrelog_error_t service_handoff_lookup_minted_disposition
    (wyl_policy_store_t * store,
    const WylPolicyServiceHandoffExactTuple * tuple,
    WylPolicyServiceHandoffDispositionReason reason,
    WylPolicyServiceHandoffDispositionOutcome outcome,
    gboolean * out_found, WylPolicyServiceHandoffDispositionResult * out);
static gboolean service_handoff_cancellation_shape_valid
    (const WylPolicyServiceHandoffCancellationInput * input);
static wyrelog_error_t service_handoff_cancellation_lookup
    (wyl_policy_store_t * store,
    const WylPolicyServiceHandoffCancellationInput * input,
    gboolean validate_authority, gboolean validate_escrow,
    gboolean strict_cardinality,
    gboolean * out_found, WylPolicyServiceHandoffCancellationResult * out);
static wyrelog_error_t service_handoff_classify_successor_without_escrow
    (wyl_policy_store_t * store,
    const WylPolicyServiceHandoffExactTuple * tuple, gint64 now_us,
    WylPolicyServiceSuccessorExactClassification * out_classification);
typedef enum
{
  SERVICE_HANDOFF_MAINTENANCE_ESCROW_EXACT,
  SERVICE_HANDOFF_MAINTENANCE_ESCROW_MISSING,
  SERVICE_HANDOFF_MAINTENANCE_ESCROW_FOREIGN,
} ServiceHandoffMaintenanceEscrowState;
static wyrelog_error_t
    service_handoff_maintenance_classify_escrow
    (wyl_policy_store_t * store,
    const WylPolicyServiceHandoffMaintenanceProof * proof,
    const gchar * successor_credential_id, guint64 successor_generation,
    const guint8 * binding_digest,
    ServiceHandoffMaintenanceEscrowState * out_state,
    wyl_policy_service_handoff_escrow_info_t * out_escrow);
static wyrelog_error_t
    service_handoff_maintenance_proof_digest
    (const WylPolicyServiceHandoffMaintenanceProof * proof,
    guint8 out[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES]);
static wyrelog_error_t
    service_handoff_maintenance_no_commit_evidence
    (const WylPolicyServiceHandoffMaintenanceProof * proof,
    WylPolicyServiceHandoffNoCommitEvidence * out_evidence);
static wyrelog_error_t
    service_handoff_maintenance_validate_no_commit
    (wyl_policy_store_t * store,
    const WylPolicyServiceHandoffMaintenanceProof * proof,
    const gchar * disposition_id, const gchar * audit_id,
    const gchar * actor_subject_id);
static wyrelog_error_t
    service_authority_transaction_validate_active
    (WylServiceAuthorityTransaction * txn, wyl_policy_store_t * store);
static wyrelog_error_t
    service_handoff_cancellation_validate_committed
    (wyl_policy_store_t * store,
    const WylPolicyServiceHandoffCancellationInput * input,
    gboolean validate_escrow);
static gchar *service_handoff_try_strdup (const gchar * value);
static wyrelog_error_t
    service_credential_operation_fence_committed_lookup_db
    (sqlite3 * db, const gchar * request_id,
    WylServiceCredentialFenceOperation operation,
    gboolean * out_operation_matches,
    guint8 out_fingerprint[crypto_generichash_BYTES],
    gchar out_credential_id[WYL_SERVICE_CREDENTIAL_ID_BUF],
    guint64 * out_generation);

static void
service_exchange_pending_clear (WylServiceAuthorityTransaction * txn);

typedef struct
{
  wyl_policy_store_t *stores[4];
  guint depth;
} WylServiceStoreScope;

static GPrivate service_store_scope = G_PRIVATE_INIT (g_free);

static wyrelog_error_t
service_store_scope_enter (wyl_policy_store_t *store)
{
  WylServiceStoreScope *scope = g_private_get (&service_store_scope);
  if (scope == NULL) {
    scope = g_new0 (WylServiceStoreScope, 1);
    g_private_set (&service_store_scope, scope);
  }
  if (scope->depth == G_N_ELEMENTS (scope->stores))
    return WYRELOG_E_BUSY;
  for (guint i = 0; i < scope->depth; i++)
    if (scope->stores[i] == store)
      return WYRELOG_E_BUSY;
  scope->stores[scope->depth++] = store;
  return WYRELOG_E_OK;
}

static void
service_store_scope_leave (wyl_policy_store_t *store)
{
  WylServiceStoreScope *scope = g_private_get (&service_store_scope);
  g_assert_nonnull (scope);
  g_assert_cmpuint (scope->depth, >, 0);
  g_assert_true (scope->stores[scope->depth - 1] == store);
  scope->stores[--scope->depth] = NULL;
  if (scope->depth == 0)
    g_private_replace (&service_store_scope, NULL);
}

static gboolean
service_authority_store_unavailable (wyl_policy_store_t *store)
{
  return g_atomic_int_get (&store->service_authority_transaction_active)
      || g_atomic_int_get (&store->service_authority_transaction_poisoned)
      || g_atomic_int_get (&store->service_authority_coordination_terminal);
}

static wyrelog_error_t
service_mutation_scope_enter (wyl_policy_store_t *store)
{
  if (service_authority_store_unavailable (store))
    return WYRELOG_E_BUSY;
  return service_store_scope_enter (store);
}

static void
service_mutation_scope_leave (wyl_policy_store_t *store)
{
  service_store_scope_leave (store);
}

static int
service_authority_poison_authorizer (gpointer data, int action,
    const gchar *arg1, const gchar *arg2, const gchar *database,
    const gchar *trigger)
{
  wyl_policy_store_t *store = data;
  (void) arg1;
  (void) arg2;
  (void) database;
  (void) trigger;
  if (g_atomic_int_get (&store->service_authority_abort_allowed)
      && store->service_authority_poison_owner == g_thread_self ()
      && store->service_authority_poison_serial != 0
      && action == SQLITE_TRANSACTION && g_strcmp0 (arg1, "ROLLBACK") == 0)
    return SQLITE_OK;
  return SQLITE_DENY;
}

static gboolean
service_authority_poison (WylServiceAuthorityTransaction *txn)
{
  wyl_policy_store_t *store = txn->store;
  store->service_authority_poison_owner = txn->owner;
  store->service_authority_poison_serial = txn->serial;
  int install_rc = txn->fault ==
      WYL_POLICY_AUTHORITY_TXN_FAIL_AUTHORIZER_INSTALL ? SQLITE_NOMEM
      : sqlite3_set_authorizer (store->db,
      service_authority_poison_authorizer, store);
  if (install_rc != SQLITE_OK) {
    /* The connection is still owner-locked. Keep the recoverable marker so
     * abort can retry a full rollback; the handle/store are terminalized by
     * the caller because external SQL could not be fenced by an authorizer. */
    g_atomic_int_set (&store->service_authority_transaction_poisoned, TRUE);
    return FALSE;
  }
  g_atomic_int_set (&store->service_authority_transaction_poisoned, TRUE);
  return TRUE;
}

static wyrelog_error_t prepare_keyprovider_rotation_work
    (wyl_policy_store_t * store, WylOwnedKeyProvider * new_provider,
    const wyl_policy_store_rotation_runtime_t * rotation_runtime,
    guint8 ** out_new_key_material);
static wyrelog_error_t service_handoff_rewrap_all (wyl_policy_store_t * store,
    WylOwnedKeyProvider * new_provider);

static gpointer
cvk_default_alloc (gpointer data, gsize size)
{
  (void) data;
  return sodium_malloc (size);
}

static int
cvk_default_lock (gpointer data, gpointer ptr, gsize size)
{
  (void) data;
  return sodium_mlock (ptr, size);
}

static void
cvk_default_wipe (gpointer data, gpointer ptr, gsize size)
{
  (void) data;
  sodium_memzero (ptr, size);
}

static int
cvk_default_unlock (gpointer data, gpointer ptr, gsize size)
{
  (void) data;
  return sodium_munlock (ptr, size);
}

static void
cvk_default_free (gpointer data, gpointer ptr)
{
  (void) data;
  sodium_free (ptr);
}

static int
cvk_default_random (gpointer data, guint8 *out, gsize len)
{
  (void) data;
  randombytes_buf (out, len);
  return 0;
}

static gint64
cvk_default_now_us (gpointer data)
{
  (void) data;
  return g_get_real_time ();
}

static wyrelog_error_t
cvk_runtime_snapshot (const wyl_policy_store_cvk_runtime_t *runtime,
    wyl_policy_store_cvk_runtime_t *out)
{
  if (sodium_init () < 0)
    return WYRELOG_E_CRYPTO;
  if (runtime == NULL) {
    *out = (wyl_policy_store_cvk_runtime_t) {
    .secure_alloc = cvk_default_alloc,.secure_lock =
          cvk_default_lock,.secure_wipe = cvk_default_wipe,.secure_unlock =
          cvk_default_unlock,.secure_free = cvk_default_free,.fill_random =
          cvk_default_random,.now_us = cvk_default_now_us,};
  } else {
    *out = *runtime;
  }
  if (out->secure_alloc == NULL || out->secure_lock == NULL
      || out->secure_wipe == NULL || out->secure_unlock == NULL
      || out->secure_free == NULL || out->fill_random == NULL
      || out->now_us == NULL)
    return WYRELOG_E_INVALID;
  return WYRELOG_E_OK;
}

static guint8 *
cvk_locked_alloc (wyl_policy_store_t *store, gsize size)
{
  wyl_policy_store_cvk_runtime_t *runtime = &store->service_cvk_runtime;
  guint8 *ptr = runtime->secure_alloc (runtime->data, size);
  if (ptr == NULL)
    return NULL;
  if (runtime->secure_lock (runtime->data, ptr, size) != 0) {
    runtime->secure_wipe (runtime->data, ptr, size);
    runtime->secure_free (runtime->data, ptr);
    return NULL;
  }
  runtime->secure_wipe (runtime->data, ptr, size);
  return ptr;
}

static void
cvk_locked_free (wyl_policy_store_t *store, guint8 *ptr, gsize size)
{
  if (ptr == NULL)
    return;
  wyl_policy_store_cvk_runtime_t *runtime = &store->service_cvk_runtime;
  runtime->secure_wipe (runtime->data, ptr, size);
  (void) runtime->secure_unlock (runtime->data, ptr, size);
  runtime->secure_free (runtime->data, ptr);
}

typedef struct
{
  const gchar *id;
  const gchar *name;
} BuiltinRole;

typedef struct
{
  const gchar *id;
  const gchar *name;
  const gchar *klass;
} BuiltinPermission;

static const BuiltinRole builtin_roles[] = {
  {"wr.system_admin", "system admin"},
  {"wr.auditor", "auditor"},
  {"wr.system_agent", "system agent"},
  {"wr.break_glass", "break glass"},
  {"wr.service_admin", "service admin"},
  {"wr.operator", "operator"},
  {"wr.analyst", "analyst"},
  {"wr.viewer", "viewer"},
  {"wr.svc_agent", "service agent"},
  {"wr.security_officer", "security officer"},
};

static const BuiltinPermission builtin_permissions[] = {
  {"wr.sys.admin", "system admin", "critical"},
  {"wr.sys.key_rotate", "system key rotate", "critical"},
  {"wr.sys.merkle_seal", "system merkle seal", "critical"},
  {"wr.sys.reload_template", "system template reload", "critical"},
  {"wr.policy.read", "policy read", "sensitive"},
  {"wr.policy.write", "policy write", "critical"},
  {"wr.policy.grant_role", "policy role grant", "critical"},
  {"wr.tenant.manage", "tenant manage", "critical"},
  {"wr.login.skip_mfa", "login skip mfa", "critical"},
  {"wr.stream.read", "stream read", "basic"},
  {"wr.stream.write_reserved", "reserved stream write", "critical"},
  {"wr.stream.list", "stream list", "basic"},
  {"wr.svc.admin", "service admin", "critical"},
  {"wr.service_principal.manage", "service principal manage",
      "critical"},
  {"wr.service_credential.manage", "service credential manage",
      "critical"},
  {"wr.svc.reload", "service reload", "sensitive"},
  {"wr.svc.flush_cache", "service cache flush", "sensitive"},
  {"wr.svc.grant_role", "service role grant", "critical"},
  {"wr.svc.freeze", "service freeze", "critical"},
  {"wr.svc.unfreeze", "service unfreeze", "critical"},
  {"wr.svc.read_decision", "service decision read", "basic"},
  {"wr.explain.read", "explanation read", "sensitive"},
  {"wr.explain.read_sensitive", "sensitive explanation read", "sensitive"},
  {"wr.audit.read", "audit read", "sensitive"},
  {"wr.audit.explain", "audit explanation read", "sensitive"},
  {"wr.audit.write", "audit write", "critical"},
  {"wr.graph.manage", "fact graph manage", "critical"},
  {"wr.fact.write", "fact write", "critical"},
  {"wr.fact.read", "fact read", "sensitive"},
  {"wr.datalog.query", "datalog query", "sensitive"},
  {"wr.schema.manage", "fact schema manage", "critical"},
};

/* Login skip-MFA authorization is intentionally scoped to the synthetic
 * "login" resource rather than a tenant. Keep the bootstrap grant aligned
 * with wyl-handle.c's WYL_LOGIN_SKIP_MFA_SCOPE so a freshly bootstrapped
 * admin can mint its first bearer token through the normal login path. */
#define WYL_BOOTSTRAP_LOGIN_SKIP_MFA_SCOPE "login"

static const gchar *const required_tables[] = {
  "wyrelog_config",
  "tenants",
  "roles",
  "permissions",
  "role_permissions",
  "role_inheritances",
  "role_memberships",
  "role_membership_events",
  "direct_permissions",
  "direct_permission_events",
  "permission_states",
  "permission_state_events",
  "principal_events",
  "principal_states",
  "session_states",
  "session_events",
  "audit_intentions",
  "audit_events",
  "fact_graphs",
  "fact_graph_relations",
  "fact_graph_relation_columns",
  "fact_graph_query_allowlist",
  "fact_namespaces",
  "fact_relation_schemas",
  "fact_relation_schema_columns",
  "fact_relation_query_allowlist",
  "policy_signatures",
  "totp_enrollments",
  "service_principals",
  "service_credentials",
  "service_credential_cvk",
  "service_credential_handoff_escrows",
  "service_principal_events",
  "service_credential_events",
  "service_domain_requests",
  "service_exchange_audit_intentions",
  "service_authority_writer_gate",
  "service_credential_operation_fences",
  "service_credential_handoff_dispositions",
  "service_credential_handoff_cancellation_claims",
  "service_credential_handoff_remediation_actions",
  "service_credential_handoff_retirement_receipts",
};

/* Kept separate from the baseline DDL so upgrading a pre-#353 store can
 * create the complete inert service authority in one savepoint. */
static const gchar service_schema_ddl[] =
    "CREATE TABLE IF NOT EXISTS service_principals ("
    " subject_id TEXT NOT NULL PRIMARY KEY CHECK ("
    "   length(subject_id) BETWEEN 5 AND 128 AND"
    "   instr(subject_id, char(0)) = 0 AND"
    "   substr(subject_id, 1, 4) = 'svc:' AND"
    "   substr(subject_id, 5, 1) GLOB '[A-Za-z0-9]' AND"
    "   substr(subject_id, -1, 1) GLOB '[A-Za-z0-9]' AND"
    "   subject_id NOT GLOB '*[^-A-Za-z0-9._:]*' AND"
    "   subject_id NOT GLOB '*:[^A-Za-z0-9]*' AND"
    "   subject_id NOT GLOB '*[^A-Za-z0-9]:*'"
    " ),"
    " display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),"
    " state TEXT NOT NULL CHECK (state IN ('active', 'disabled')),"
    " generation INTEGER NOT NULL DEFAULT 1 CHECK (generation >= 1),"
    " created_by TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 128),"
    " created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),"
    " updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),"
    " disabled_by TEXT,"
    " disabled_at_us INTEGER,"
    " CHECK (disabled_by IS NULL OR length(disabled_by) BETWEEN 1 AND 128),"
    " CHECK ((state = 'active' AND disabled_by IS NULL AND disabled_at_us IS NULL)"
    "   OR (state = 'disabled' AND disabled_by IS NOT NULL"
    "     AND disabled_at_us IS NOT NULL AND disabled_at_us >= created_at_us))"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_service_principals_state_subject"
    " ON service_principals (state, subject_id);"
    "CREATE TABLE IF NOT EXISTS service_credential_cvk ("
    " slot INTEGER PRIMARY KEY CHECK (slot = 1),"
    " generation INTEGER NOT NULL UNIQUE CHECK (generation >= 1),"
    " envelope_format_version INTEGER NOT NULL CHECK (envelope_format_version >= 1),"
    " provider_binding BLOB NOT NULL CHECK (typeof(provider_binding) = 'blob'"
    "   AND length(provider_binding) = 32),"
    " sealed_cvk BLOB NOT NULL CHECK (typeof(sealed_cvk) = 'blob'"
    "   AND length(sealed_cvk) BETWEEN 1 AND 65536),"
    " created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),"
    " updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us)"
    ");"
    "CREATE TABLE IF NOT EXISTS service_credential_handoff_escrows ("
    " escrow_id TEXT NOT NULL PRIMARY KEY CHECK (typeof(escrow_id) = 'text'"
    "   AND length(escrow_id) = 36 AND instr(escrow_id,char(0)) = 0),"
    " operation TEXT NOT NULL CHECK (operation IN ('issue','rotate')),"
    " request_id TEXT NOT NULL UNIQUE CHECK (typeof(request_id) = 'text'"
    "   AND length(request_id) BETWEEN 1 AND 256 AND instr(request_id,char(0)) = 0),"
    " actor_subject_id TEXT NOT NULL CHECK (typeof(actor_subject_id) = 'text'"
    "   AND length(actor_subject_id) BETWEEN 1 AND 128 AND instr(actor_subject_id,char(0)) = 0),"
    " target_digest BLOB NOT NULL CHECK (typeof(target_digest) = 'blob'"
    "   AND length(target_digest) = 32),"
    " credential_id TEXT NOT NULL CHECK (typeof(credential_id) = 'text'"
    "   AND length(credential_id) = 31 AND substr(credential_id,1,4) = 'wlc_'"
    "   AND instr(credential_id,char(0)) = 0),"
    " credential_generation INTEGER NOT NULL CHECK (credential_generation >= 1),"
    " deadline_at_us INTEGER NOT NULL CHECK (deadline_at_us > 0),"
    " binding_digest BLOB NOT NULL CHECK (typeof(binding_digest) = 'blob'"
    "   AND length(binding_digest) = 32),"
    " sealed_envelope BLOB NOT NULL CHECK (typeof(sealed_envelope) = 'blob'"
    "   AND length(sealed_envelope) BETWEEN 1 AND 65536),"
    " created_at_us INTEGER NOT NULL CHECK (created_at_us > 0)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_service_handoff_escrows_credential"
    " ON service_credential_handoff_escrows(credential_id,credential_generation);"
    "CREATE TABLE IF NOT EXISTS service_credentials ("
    " credential_id TEXT NOT NULL PRIMARY KEY CHECK ("
    "   length(credential_id) BETWEEN 1 AND 128 AND"
    "   instr(credential_id, char(0)) = 0),"
    " credential_format_version INTEGER NOT NULL CHECK (credential_format_version >= 1),"
    " subject_id TEXT NOT NULL,"
    " tenant_id TEXT NOT NULL,"
    " generation INTEGER NOT NULL DEFAULT 1 CHECK (generation >= 1),"
    " state TEXT NOT NULL CHECK (state IN ('active', 'revoked')),"
    " verifier_version INTEGER NOT NULL CHECK (verifier_version >= 1),"
    " salt BLOB NOT NULL CHECK (typeof(salt) = 'blob' AND length(salt) = 16),"
    " verifier BLOB NOT NULL CHECK (typeof(verifier) = 'blob'"
    "   AND length(verifier) = 32),"
    " created_by TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 128),"
    " created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),"
    " updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),"
    " expires_at_us INTEGER CHECK (expires_at_us IS NULL OR expires_at_us > created_at_us),"
    " last_used_at_us INTEGER CHECK (last_used_at_us IS NULL OR last_used_at_us >= created_at_us),"
    " revoked_by TEXT,"
    " revoked_at_us INTEGER,"
    " rotated_from_id TEXT,"
    " CHECK (revoked_by IS NULL OR length(revoked_by) BETWEEN 1 AND 128),"
    " UNIQUE (credential_id, subject_id, tenant_id),"
    " UNIQUE (rotated_from_id),"
    " FOREIGN KEY (subject_id) REFERENCES service_principals (subject_id)"
    "   ON UPDATE RESTRICT ON DELETE RESTRICT,"
    " FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id)"
    "   ON UPDATE RESTRICT ON DELETE RESTRICT,"
    " FOREIGN KEY (rotated_from_id, subject_id, tenant_id)"
    "   REFERENCES service_credentials (credential_id, subject_id, tenant_id)"
    "   ON UPDATE RESTRICT ON DELETE RESTRICT,"
    " CHECK (rotated_from_id IS NULL OR rotated_from_id <> credential_id),"
    " CHECK ((state = 'active' AND revoked_by IS NULL AND revoked_at_us IS NULL)"
    "   OR (state = 'revoked' AND revoked_by IS NOT NULL"
    "     AND revoked_at_us IS NOT NULL AND revoked_at_us >= created_at_us))"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_service_credentials_subject_tenant_state"
    " ON service_credentials (subject_id, tenant_id, state);"
    "CREATE INDEX IF NOT EXISTS idx_service_credentials_tenant_state_expiry"
    " ON service_credentials (tenant_id, state, expires_at_us);"
    "CREATE TABLE IF NOT EXISTS service_principal_events ("
    " event_id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " subject_id TEXT NOT NULL,"
    " event TEXT NOT NULL CHECK (event IN ('created', 'disabled')),"
    " from_state TEXT CHECK (from_state IS NULL OR from_state IN ('active', 'disabled')),"
    " to_state TEXT NOT NULL CHECK (to_state IN ('active', 'disabled')),"
    " generation INTEGER NOT NULL CHECK (generation >= 1),"
    " actor_subject_id TEXT NOT NULL"
    "   CHECK (length(actor_subject_id) BETWEEN 1 AND 128),"
    " request_id TEXT,"
    " created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),"
    " FOREIGN KEY (subject_id) REFERENCES service_principals (subject_id)"
    "   ON UPDATE RESTRICT ON DELETE RESTRICT,"
    " CHECK ((event = 'created' AND from_state IS NULL AND to_state = 'active')"
    "   OR (event = 'disabled' AND from_state = 'active' AND to_state = 'disabled'))"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_service_principal_events_subject_time"
    " ON service_principal_events (subject_id, created_at_us, event_id);"
    "CREATE INDEX IF NOT EXISTS idx_service_principal_events_request"
    " ON service_principal_events (request_id);"
    "CREATE TABLE IF NOT EXISTS service_credential_events ("
    " event_id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " credential_id TEXT NOT NULL,"
    " subject_id TEXT NOT NULL,"
    " tenant_id TEXT NOT NULL,"
    " event TEXT NOT NULL CHECK (event IN ('issued', 'rotated', 'revoked')),"
    " from_state TEXT CHECK (from_state IS NULL OR from_state IN ('active', 'revoked')),"
    " to_state TEXT NOT NULL CHECK (to_state IN ('active', 'revoked')),"
    " generation INTEGER NOT NULL CHECK (generation >= 1),"
    " actor_subject_id TEXT NOT NULL"
    "   CHECK (length(actor_subject_id) BETWEEN 1 AND 128),"
    " request_id TEXT,"
    " related_credential_id TEXT,"
    " created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),"
    " FOREIGN KEY (credential_id, subject_id, tenant_id)"
    "   REFERENCES service_credentials (credential_id, subject_id, tenant_id)"
    "   ON UPDATE RESTRICT ON DELETE RESTRICT,"
    " FOREIGN KEY (related_credential_id, subject_id, tenant_id)"
    "   REFERENCES service_credentials (credential_id, subject_id, tenant_id)"
    "   ON UPDATE RESTRICT ON DELETE RESTRICT,"
    " CHECK ((event IN ('issued', 'rotated') AND from_state IS NULL AND to_state = 'active')"
    "   OR (event = 'revoked' AND from_state = 'active' AND to_state = 'revoked'))"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_service_credential_events_credential_time"
    " ON service_credential_events (credential_id, created_at_us, event_id);"
    "CREATE INDEX IF NOT EXISTS idx_service_credential_events_owner_time"
    " ON service_credential_events (subject_id, tenant_id, created_at_us, event_id);"
    "CREATE INDEX IF NOT EXISTS idx_service_credential_events_request"
    " ON service_credential_events (request_id);"
    "CREATE TABLE IF NOT EXISTS service_domain_requests ("
    " request_id TEXT NOT NULL PRIMARY KEY CHECK ("
    "   length(request_id) BETWEEN 1 AND 256 AND"
    "   instr(request_id, char(0)) = 0),"
    " operation TEXT NOT NULL CHECK (operation IN ("
    "   'principal_create','principal_disable','credential_issue',"
    "   'credential_revoke','credential_rotate')) ,"
    " resource_id TEXT NOT NULL CHECK ("
    "   length(resource_id) BETWEEN 1 AND 128 AND"
    "   instr(resource_id, char(0)) = 0),"
    " input_fingerprint BLOB NOT NULL CHECK ("
    "   typeof(input_fingerprint) = 'blob' AND length(input_fingerprint) = 32),"
    " created_at_us INTEGER NOT NULL CHECK (created_at_us > 0)"
    ");"
    "CREATE TABLE IF NOT EXISTS service_credential_handoff_dispositions ("
    " disposition_id TEXT NOT NULL PRIMARY KEY CHECK (typeof(disposition_id)='text'"
    "   AND length(disposition_id)=36 AND instr(disposition_id,char(0))=0),"
    " semantic_key BLOB NOT NULL UNIQUE CHECK (typeof(semantic_key)='blob'"
    "   AND length(semantic_key)=32),"
    " original_request_id TEXT NOT NULL CHECK (typeof(original_request_id)='text'"
    "   AND length(original_request_id)=27 AND instr(original_request_id,char(0))=0),"
    " escrow_id TEXT NOT NULL CHECK (typeof(escrow_id)='text'"
    "   AND length(escrow_id)=36 AND instr(escrow_id,char(0))=0),"
    " binding_digest BLOB NOT NULL CHECK (typeof(binding_digest)='blob'"
    "   AND length(binding_digest)=32),"
    " successor_credential_id TEXT CHECK (successor_credential_id IS NULL OR"
    "   (typeof(successor_credential_id)='text'"
    "   AND length(successor_credential_id)=31"
    "   AND substr(successor_credential_id,1,4)='wlc_'"
    "   AND instr(successor_credential_id,char(0))=0)),"
    " successor_issuance_generation INTEGER"
    "   CHECK (successor_issuance_generation IS NULL"
    "   OR successor_issuance_generation>=1),"
    " actor_subject_id TEXT NOT NULL CHECK (typeof(actor_subject_id)='text'"
    "   AND length(actor_subject_id) BETWEEN 1 AND 128"
    "   AND instr(actor_subject_id,char(0))=0),"
    " reason TEXT NOT NULL CHECK (reason IN ('not_committed','operation_expired',"
    "   'operation_cancelled','successor_expired','successor_revoked','delivered')) ,"
    " outcome TEXT NOT NULL CHECK (outcome IN ('terminal_not_committed','attention_required',"
    "   'operator_action_required','escrow_deleted')) ,"
    " audit_id TEXT NOT NULL UNIQUE CHECK (typeof(audit_id)='text'"
    "   AND length(audit_id)=36 AND instr(audit_id,char(0))=0),"
    " created_at_us INTEGER NOT NULL CHECK (created_at_us>0),"
    " CHECK ((reason='not_committed' AND outcome='terminal_not_committed'"
    "     AND successor_credential_id IS NULL"
    "     AND successor_issuance_generation IS NULL)"
    "   OR (reason<>'not_committed' AND binding_digest<>zeroblob(32)"
    "     AND successor_credential_id IS NOT NULL"
    "     AND successor_issuance_generation IS NOT NULL AND ("
    "    (reason IN ('operation_expired','operation_cancelled')"
    "     AND outcome='attention_required')"
    "   OR (reason IN ('successor_expired','successor_revoked')"
    "     AND outcome='operator_action_required')"
    "   OR (reason='delivered' AND outcome='escrow_deleted'))))"
    ");"
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_service_handoff_disposition_exact"
    " ON service_credential_handoff_dispositions(original_request_id,reason,"
    " outcome,escrow_id,binding_digest,"
    " coalesce(successor_credential_id,''),"
    " coalesce(successor_issuance_generation,0));"
    "CREATE TABLE IF NOT EXISTS service_credential_handoff_cancellation_claims ("
    " cancellation_request_id TEXT NOT NULL PRIMARY KEY"
    "   CHECK (typeof(cancellation_request_id)='text'"
    "   AND length(cancellation_request_id)=27"
    "   AND instr(cancellation_request_id,char(0))=0),"
    " request_fingerprint BLOB NOT NULL CHECK (typeof(request_fingerprint)='blob'"
    "   AND length(request_fingerprint)=32),"
    " decision_request_id TEXT NOT NULL UNIQUE"
    "   CHECK (typeof(decision_request_id)='text'"
    "   AND length(decision_request_id)=27"
    "   AND instr(decision_request_id,char(0))=0),"
    " original_request_id TEXT NOT NULL CHECK (typeof(original_request_id)='text'"
    "   AND length(original_request_id)=27 AND instr(original_request_id,char(0))=0),"
    " original_actor_subject_id TEXT NOT NULL"
    "   CHECK (typeof(original_actor_subject_id)='text'"
    "   AND length(original_actor_subject_id) BETWEEN 1 AND 128"
    "   AND instr(original_actor_subject_id,char(0))=0),"
    " current_actor_subject_id TEXT NOT NULL"
    "   CHECK (typeof(current_actor_subject_id)='text'"
    "   AND length(current_actor_subject_id) BETWEEN 1 AND 128"
    "   AND instr(current_actor_subject_id,char(0))=0),"
    " resolution TEXT NOT NULL CHECK (resolution IN"
    "   ('committed_attention','terminal_not_committed')) ,"
    " escrow_id TEXT NOT NULL CHECK (typeof(escrow_id)='text'"
    "   AND length(escrow_id)=36 AND instr(escrow_id,char(0))=0),"
    " binding_digest BLOB NOT NULL CHECK (typeof(binding_digest)='blob'"
    "   AND length(binding_digest)=32),"
    " successor_credential_id TEXT CHECK (successor_credential_id IS NULL OR"
    "   (typeof(successor_credential_id)='text'"
    "   AND length(successor_credential_id)=31"
    "   AND substr(successor_credential_id,1,4)='wlc_'"
    "   AND instr(successor_credential_id,char(0))=0)),"
    " successor_issuance_generation INTEGER"
    "   CHECK (successor_issuance_generation IS NULL"
    "   OR successor_issuance_generation>=1),"
    " operation TEXT NOT NULL CHECK (operation IN ('issue','rotate')) ,"
    " target_a TEXT NOT NULL CHECK (typeof(target_a)='text'"
    "   AND length(target_a) BETWEEN 1 AND 128 AND instr(target_a,char(0))=0),"
    " target_b TEXT CHECK (target_b IS NULL OR (typeof(target_b)='text'"
    "   AND length(target_b) BETWEEN 1 AND 128 AND instr(target_b,char(0))=0)),"
    " target_digest BLOB NOT NULL CHECK (typeof(target_digest)='blob'"
    "   AND length(target_digest)=32 AND target_digest<>zeroblob(32)),"
    " maintenance_proof_digest BLOB NOT NULL"
    "   CHECK (typeof(maintenance_proof_digest)='blob'"
    "   AND length(maintenance_proof_digest)=32"
    "   AND maintenance_proof_digest<>zeroblob(32)),"
    " deadline_at_us INTEGER NOT NULL CHECK (deadline_at_us>0),"
    " disposition_id TEXT NOT NULL UNIQUE CHECK (typeof(disposition_id)='text'"
    "   AND length(disposition_id)=36 AND instr(disposition_id,char(0))=0),"
    " audit_id TEXT NOT NULL UNIQUE CHECK (typeof(audit_id)='text'"
    "   AND length(audit_id)=36 AND instr(audit_id,char(0))=0),"
    " created_at_us INTEGER NOT NULL CHECK (created_at_us>0),"
    " CHECK (original_request_id<>cancellation_request_id"
    "   AND original_request_id<>decision_request_id"
    "   AND cancellation_request_id<>decision_request_id),"
    " CHECK (original_actor_subject_id<>current_actor_subject_id),"
    " CHECK ((operation='issue' AND target_b IS NOT NULL)"
    "   OR (operation='rotate' AND target_b IS NULL)),"
    " CHECK ((resolution='committed_attention'"
    "     AND binding_digest<>zeroblob(32)"
    "     AND successor_credential_id IS NOT NULL"
    "     AND successor_issuance_generation IS NOT NULL)"
    "   OR (resolution='terminal_not_committed'"
    "     AND binding_digest=zeroblob(32)"
    "     AND successor_credential_id IS NULL"
    "     AND successor_issuance_generation IS NULL))"
    ");"
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_service_handoff_cancellation_exact"
    " ON service_credential_handoff_cancellation_claims"
    " (original_request_id);"
    "CREATE TABLE IF NOT EXISTS service_credential_handoff_remediation_actions ("
    " remediation_request_id TEXT NOT NULL PRIMARY KEY"
    "   CHECK (typeof(remediation_request_id)='text'"
    "   AND length(remediation_request_id)=27"
    "   AND instr(remediation_request_id,char(0))=0),"
    " request_fingerprint BLOB NOT NULL CHECK (typeof(request_fingerprint)='blob'"
    "   AND length(request_fingerprint)=32"
    "   AND request_fingerprint<>zeroblob(32)),"
    " incident_fingerprint BLOB NOT NULL CHECK (typeof(incident_fingerprint)='blob'"
    "   AND length(incident_fingerprint)=32 AND incident_fingerprint<>zeroblob(32)),"
    " decision_request_id TEXT NOT NULL UNIQUE"
    "   CHECK (typeof(decision_request_id)='text'"
    "   AND length(decision_request_id)=27"
    "   AND instr(decision_request_id,char(0))=0),"
    " original_request_id TEXT NOT NULL CHECK (typeof(original_request_id)='text'"
    "   AND length(original_request_id)=27 AND instr(original_request_id,char(0))=0),"
    " original_actor_subject_id TEXT NOT NULL"
    "   CHECK (typeof(original_actor_subject_id)='text'"
    "   AND length(original_actor_subject_id) BETWEEN 1 AND 128"
    "   AND instr(original_actor_subject_id,char(0))=0),"
    " current_actor_subject_id TEXT NOT NULL"
    "   CHECK (typeof(current_actor_subject_id)='text'"
    "   AND length(current_actor_subject_id) BETWEEN 1 AND 128"
    "   AND instr(current_actor_subject_id,char(0))=0),"
    " source_kind TEXT NOT NULL CHECK (source_kind IN"
    "   ('committed_attention','operator_action_required')) ,"
    " journal_snapshot_digest BLOB NOT NULL CHECK"
    "   (typeof(journal_snapshot_digest)='blob'"
    "   AND length(journal_snapshot_digest)=32"
    "   AND journal_snapshot_digest<>zeroblob(32)),"
    " observed_state TEXT NOT NULL CHECK (observed_state IN"
    "   ('server_committed','publication_planned','publication_prepared',"
    "   'file_published','cleanup_required','operator_action_required')) ,"
    " source_disposition_id TEXT CHECK (source_disposition_id IS NULL OR"
    "   (typeof(source_disposition_id)='text' AND length(source_disposition_id)=36"
    "   AND instr(source_disposition_id,char(0))=0)),"
    " source_audit_id TEXT CHECK (source_audit_id IS NULL OR"
    "   (typeof(source_audit_id)='text' AND length(source_audit_id)=36"
    "   AND instr(source_audit_id,char(0))=0)),"
    " source_reason TEXT CHECK (source_reason IS NULL OR source_reason IN"
    "   ('operation_cancelled','operation_expired')) ,"
    " oar_source_state TEXT CHECK (oar_source_state IS NULL OR oar_source_state IN"
    "   ('server_committed','publication_planned','publication_prepared',"
    "   'file_published','cleanup_required')) ,"
    " oar_cause TEXT CHECK (oar_cause IS NULL OR oar_cause IN"
    "   ('receipt_foreign','receipt_uncertain','escrow_foreign','escrow_uncertain',"
    "   'successor_revoked','successor_expired','explicit_hold','escrow_missing')) ,"
    " resume_target_state TEXT CHECK (resume_target_state IS NULL OR"
    "   resume_target_state IN ('server_committed','publication_planned',"
    "   'publication_prepared','file_published','cleanup_required')) ,"
    " escrow_id TEXT NOT NULL CHECK (typeof(escrow_id)='text'"
    "   AND length(escrow_id)=36 AND instr(escrow_id,char(0))=0),"
    " binding_digest BLOB NOT NULL CHECK (typeof(binding_digest)='blob'"
    "   AND length(binding_digest)=32 AND binding_digest<>zeroblob(32)),"
    " successor_credential_id TEXT NOT NULL CHECK (typeof(successor_credential_id)='text'"
    "   AND length(successor_credential_id)=31"
    "   AND substr(successor_credential_id,1,4)='wlc_'"
    "   AND instr(successor_credential_id,char(0))=0),"
    " successor_issuance_generation INTEGER NOT NULL"
    "   CHECK (successor_issuance_generation>=1),"
    " action TEXT NOT NULL CHECK (action IN ('resume','revoke_and_wipe')) ,"
    " confirmation_version INTEGER NOT NULL"
    "   CHECK (confirmation_version IN (0,1)),"
    " confirmed INTEGER NOT NULL CHECK (confirmed IN (0,1)"
    "   AND typeof(confirmed)='integer'),"
    " outcome TEXT NOT NULL CHECK (outcome IN ('recorded',"
    "   'revoked_and_wiped','expired_and_wiped','already_revoked_and_wiped')) ,"
    " escrow_outcome TEXT NOT NULL CHECK"
    "   (escrow_outcome IN ('retained','deleted','already_absent')) ,"
    " credential_generation_after INTEGER NOT NULL"
    "   CHECK (credential_generation_after>=1),"
    " revoke_event_id INTEGER CHECK (revoke_event_id IS NULL OR revoke_event_id>0),"
    " revoke_event_generation INTEGER CHECK"
    "   (revoke_event_generation IS NULL OR revoke_event_generation>=1),"
    " revoke_event_request_id TEXT CHECK (revoke_event_request_id IS NULL OR"
    "   (typeof(revoke_event_request_id)='text'"
    "   AND length(revoke_event_request_id) BETWEEN 1 AND 256"
    "   AND instr(revoke_event_request_id,char(0))=0)),"
    " revoke_event_actor_subject_id TEXT CHECK"
    "   (revoke_event_actor_subject_id IS NULL OR"
    "   (typeof(revoke_event_actor_subject_id)='text'"
    "   AND length(revoke_event_actor_subject_id) BETWEEN 1 AND 128"
    "   AND instr(revoke_event_actor_subject_id,char(0))=0)),"
    " revoke_event_created_at_us INTEGER CHECK"
    "   (revoke_event_created_at_us IS NULL OR revoke_event_created_at_us>0),"
    " audit_id TEXT NOT NULL UNIQUE CHECK (typeof(audit_id)='text'"
    "   AND length(audit_id)=36 AND instr(audit_id,char(0))=0),"
    " created_at_us INTEGER NOT NULL CHECK (created_at_us>0),"
    " CHECK (original_request_id<>remediation_request_id"
    "   AND original_request_id<>decision_request_id"
    "   AND remediation_request_id<>decision_request_id),"
    " CHECK (original_actor_subject_id<>current_actor_subject_id),"
    " CHECK ((source_kind='committed_attention'"
    "     AND observed_state IN ('server_committed','publication_planned',"
    "       'publication_prepared','file_published','cleanup_required')"
    "     AND source_disposition_id IS NOT NULL AND source_audit_id IS NOT NULL"
    "     AND source_reason IS NOT NULL AND oar_source_state IS NULL"
    "     AND oar_cause IS NULL AND resume_target_state IS NULL)"
    "   OR (source_kind='operator_action_required'"
    "     AND observed_state='operator_action_required'"
    "     AND source_disposition_id IS NULL AND source_audit_id IS NULL"
    "     AND source_reason IS NULL AND oar_source_state IS NOT NULL"
    "     AND oar_cause IS NOT NULL"
    "     AND resume_target_state=oar_source_state)),"
    " CHECK (NOT (oar_source_state='server_committed'"
    "   AND oar_cause IN ('receipt_foreign','receipt_uncertain'))),"
    " CHECK (NOT (action='resume' AND oar_cause IN"
    "   ('successor_revoked','successor_expired','escrow_missing'))),"
    " CHECK (escrow_outcome<>'already_absent' OR"
    "   (source_kind='operator_action_required'"
    "    AND oar_cause='escrow_missing' AND action='revoke_and_wipe')),"
    " CHECK ((action='resume' AND confirmation_version=0 AND confirmed=0"
    "     AND outcome='recorded' AND escrow_outcome='retained'"
    "     AND credential_generation_after=successor_issuance_generation"
    "     AND revoke_event_id IS NULL AND revoke_event_generation IS NULL"
    "     AND revoke_event_request_id IS NULL"
    "     AND revoke_event_actor_subject_id IS NULL"
    "     AND revoke_event_created_at_us IS NULL)"
    "   OR (action='revoke_and_wipe' AND confirmation_version=1 AND confirmed=1"
    "     AND outcome IN ('revoked_and_wiped',"
    "     'expired_and_wiped','already_revoked_and_wiped')"
    "     AND escrow_outcome IN ('deleted','already_absent')"
    "     AND ((outcome='expired_and_wiped'"
    "       AND credential_generation_after=successor_issuance_generation"
    "       AND revoke_event_id IS NULL AND revoke_event_generation IS NULL"
    "       AND revoke_event_request_id IS NULL"
    "       AND revoke_event_actor_subject_id IS NULL"
    "       AND revoke_event_created_at_us IS NULL)"
    "      OR (outcome IN ('revoked_and_wiped','already_revoked_and_wiped')"
    "       AND successor_issuance_generation<9223372036854775807"
    "       AND credential_generation_after=successor_issuance_generation+1"
    "       AND revoke_event_id IS NOT NULL AND revoke_event_generation IS NOT NULL"
    "       AND revoke_event_generation=credential_generation_after"
    "       AND revoke_event_request_id IS NOT NULL"
    "       AND revoke_event_actor_subject_id IS NOT NULL"
    "       AND revoke_event_created_at_us IS NOT NULL"
    "       AND (outcome<>'revoked_and_wiped'"
    "        OR (revoke_event_request_id=remediation_request_id"
    "         AND revoke_event_actor_subject_id=current_actor_subject_id"
    "         AND revoke_event_created_at_us=created_at_us))))))"
    ");"
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_service_handoff_remediation_incident"
    " ON service_credential_handoff_remediation_actions"
    " (incident_fingerprint);"
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_service_handoff_completed_revoke"
    " ON service_credential_handoff_remediation_actions"
    " (original_request_id,escrow_id,binding_digest,successor_credential_id,"
    " successor_issuance_generation,action)"
    " WHERE action='revoke_and_wipe';"
    "CREATE TABLE IF NOT EXISTS service_credential_handoff_retirement_receipts ("
    " original_request_id TEXT NOT NULL PRIMARY KEY"
    "   CHECK (typeof(original_request_id)='text'"
    "   AND length(original_request_id)=27 AND instr(original_request_id,char(0))=0),"
    " terminal_kind TEXT NOT NULL CHECK (terminal_kind IN"
    "   ('file_published','operator_revoke_and_wipe')) ,"
    " raw_journal_snapshot_digest BLOB NOT NULL CHECK"
    "   (typeof(raw_journal_snapshot_digest)='blob'"
    "   AND length(raw_journal_snapshot_digest)=32"
    "   AND raw_journal_snapshot_digest<>zeroblob(32)),"
    " delivery_disposition_id TEXT CHECK (delivery_disposition_id IS NULL OR"
    "   (typeof(delivery_disposition_id)='text'"
    "   AND length(delivery_disposition_id)=36"
    "   AND instr(delivery_disposition_id,char(0))=0)),"
    " delivery_audit_id TEXT CHECK (delivery_audit_id IS NULL OR"
    "   (typeof(delivery_audit_id)='text' AND length(delivery_audit_id)=36"
    "   AND instr(delivery_audit_id,char(0))=0)),"
    " delivery_proof_digest BLOB NOT NULL CHECK"
    "   (typeof(delivery_proof_digest)='blob'"
    "   AND length(delivery_proof_digest)=32),"
    " revoke_remediation_request_id TEXT CHECK"
    "   (revoke_remediation_request_id IS NULL OR"
    "   (typeof(revoke_remediation_request_id)='text'"
    "   AND length(revoke_remediation_request_id)=27"
    "   AND instr(revoke_remediation_request_id,char(0))=0)),"
    " revoke_audit_id TEXT CHECK (revoke_audit_id IS NULL OR"
    "   (typeof(revoke_audit_id)='text' AND length(revoke_audit_id)=36"
    "   AND instr(revoke_audit_id,char(0))=0)),"
    " revoke_event_id INTEGER CHECK (revoke_event_id IS NULL OR revoke_event_id>0),"
    " resume_remediation_request_id TEXT CHECK"
    "   (resume_remediation_request_id IS NULL OR"
    "   (typeof(resume_remediation_request_id)='text'"
    "   AND length(resume_remediation_request_id)=27"
    "   AND instr(resume_remediation_request_id,char(0))=0)),"
    " resume_audit_id TEXT CHECK (resume_audit_id IS NULL OR"
    "   (typeof(resume_audit_id)='text' AND length(resume_audit_id)=36"
    "   AND instr(resume_audit_id,char(0))=0)),"
    " remediation_source_snapshot_digest BLOB CHECK"
    "   (remediation_source_snapshot_digest IS NULL OR"
    "   (typeof(remediation_source_snapshot_digest)='blob'"
    "   AND length(remediation_source_snapshot_digest)=32"
    "   AND remediation_source_snapshot_digest<>zeroblob(32))),"
    " remediation_request_fingerprint BLOB CHECK"
    "   (remediation_request_fingerprint IS NULL OR"
    "   (typeof(remediation_request_fingerprint)='blob'"
    "   AND length(remediation_request_fingerprint)=32"
    "   AND remediation_request_fingerprint<>zeroblob(32))),"
    " retention_basis_at_us INTEGER NOT NULL CHECK (retention_basis_at_us>0),"
    " retired_at_us INTEGER NOT NULL CHECK"
    "   (retired_at_us>=retention_basis_at_us"
    "   AND retired_at_us-retention_basis_at_us>=2592000000000),"
    " CHECK ((terminal_kind='file_published'"
    "     AND delivery_disposition_id IS NOT NULL"
    "     AND delivery_audit_id IS NOT NULL"
    "     AND delivery_proof_digest<>zeroblob(32)"
    "     AND revoke_remediation_request_id IS NULL"
    "     AND revoke_audit_id IS NULL AND revoke_event_id IS NULL"
    "     AND ((resume_remediation_request_id IS NULL"
    "       AND resume_audit_id IS NULL"
    "       AND remediation_source_snapshot_digest IS NULL"
    "       AND remediation_request_fingerprint IS NULL)"
    "      OR (resume_remediation_request_id IS NOT NULL"
    "       AND resume_audit_id IS NOT NULL"
    "       AND remediation_source_snapshot_digest<>zeroblob(32)"
    "       AND remediation_request_fingerprint<>zeroblob(32))))"
    "   OR (terminal_kind='operator_revoke_and_wipe'"
    "     AND delivery_disposition_id IS NULL AND delivery_audit_id IS NULL"
    "     AND delivery_proof_digest=zeroblob(32)"
    "     AND revoke_remediation_request_id IS NOT NULL"
    "     AND revoke_audit_id IS NOT NULL"
    "     AND resume_remediation_request_id IS NULL"
    "     AND resume_audit_id IS NULL"
    "     AND remediation_source_snapshot_digest<>zeroblob(32)"
    "     AND remediation_request_fingerprint<>zeroblob(32)))"
    ");"
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_service_handoff_retirement_raw"
    " ON service_credential_handoff_retirement_receipts"
    " (raw_journal_snapshot_digest);"
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_service_handoff_retirement_delivery"
    " ON service_credential_handoff_retirement_receipts"
    " (delivery_disposition_id) WHERE delivery_disposition_id IS NOT NULL;"
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_service_handoff_retirement_revoke"
    " ON service_credential_handoff_retirement_receipts"
    " (revoke_remediation_request_id)"
    " WHERE revoke_remediation_request_id IS NOT NULL;"
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_service_handoff_retirement_resume"
    " ON service_credential_handoff_retirement_receipts"
    " (resume_remediation_request_id)"
    " WHERE resume_remediation_request_id IS NOT NULL;"
    "CREATE TABLE IF NOT EXISTS service_authority_writer_gate ("
    " singleton INTEGER PRIMARY KEY CHECK (singleton = 1),"
    " lock_word INTEGER NOT NULL CHECK (lock_word = 0)"
    ") WITHOUT ROWID;"
    "INSERT OR IGNORE INTO service_authority_writer_gate(singleton,lock_word)"
    " VALUES(1,0);"
    "CREATE TABLE IF NOT EXISTS service_exchange_audit_intentions ("
    " intention_id TEXT NOT NULL PRIMARY KEY CHECK (typeof(intention_id) = 'text'"
    "   AND length(intention_id) = 36 AND instr(intention_id,char(0)) = 0),"
    " payload_digest TEXT NOT NULL UNIQUE CHECK (typeof(payload_digest) = 'text'"
    "   AND length(payload_digest) = 64 AND payload_digest = lower(payload_digest)"
    "   AND payload_digest NOT GLOB '*[^0-9a-f]*'),"
    " payload_schema_version INTEGER NOT NULL CHECK ("
    "   typeof(payload_schema_version) = 'integer' AND payload_schema_version = 1),"
    " event_type TEXT NOT NULL CHECK (typeof(event_type) = 'text'"
    "   AND event_type = 'service.credential.exchange'),"
    " outcome TEXT NOT NULL CHECK (typeof(outcome) = 'text' AND outcome = 'allowed'),"
    " created_at_us INTEGER NOT NULL CHECK (typeof(created_at_us) = 'integer'"
    "   AND created_at_us > 0),"
    " request_id TEXT NOT NULL CHECK (typeof(request_id) = 'text'"
    "   AND length(request_id) = 27 AND instr(request_id,char(0)) = 0),"
    " credential_id TEXT NOT NULL CHECK (typeof(credential_id) = 'text'"
    "   AND length(credential_id) = 31 AND substr(credential_id,1,4) = 'wlc_'"
    "   AND instr(credential_id,char(0)) = 0),"
    " credential_generation BLOB NOT NULL CHECK ("
    "   typeof(credential_generation) = 'blob' AND length(credential_generation) = 8),"
    " service_principal TEXT NOT NULL CHECK (typeof(service_principal) = 'text'"
    "   AND length(CAST(service_principal AS BLOB)) BETWEEN 5 AND 128"
    "   AND instr(service_principal,char(0)) = 0),"
    " tenant_id TEXT NOT NULL CHECK (typeof(tenant_id) = 'text'"
    "   AND length(CAST(tenant_id AS BLOB)) BETWEEN 1 AND 128"
    "   AND instr(tenant_id,char(0)) = 0),"
    " fingerprint_schema_version INTEGER NOT NULL CHECK ("
    "   typeof(fingerprint_schema_version) = 'integer'"
    "   AND fingerprint_schema_version = 1),"
    " session_fingerprint TEXT NOT NULL CHECK (typeof(session_fingerprint) = 'text'"
    "   AND length(session_fingerprint) = 64"
    "   AND session_fingerprint = lower(session_fingerprint)"
    "   AND session_fingerprint NOT GLOB '*[^0-9a-f]*'),"
    " jti_fingerprint TEXT NOT NULL CHECK (typeof(jti_fingerprint) = 'text'"
    "   AND length(jti_fingerprint) = 64"
    "   AND jti_fingerprint = lower(jti_fingerprint)"
    "   AND jti_fingerprint NOT GLOB '*[^0-9a-f]*'),"
    " canonical_payload BLOB NOT NULL CHECK (typeof(canonical_payload) = 'blob'"
    "   AND length(canonical_payload) BETWEEN 1 AND 4096)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_service_exchange_audit_created"
    " ON service_exchange_audit_intentions(created_at_us,intention_id);"
    "CREATE TRIGGER IF NOT EXISTS trg_service_exchange_audit_no_update"
    " BEFORE UPDATE ON service_exchange_audit_intentions"
    " BEGIN SELECT RAISE(ABORT, 'service exchange audit intentions are append-only'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_exchange_audit_no_delete"
    " BEFORE DELETE ON service_exchange_audit_intentions"
    " BEGIN SELECT RAISE(ABORT, 'service exchange audit intentions are append-only'); END;"
    "CREATE TABLE IF NOT EXISTS service_credential_operation_fences ("
    " request_id TEXT NOT NULL PRIMARY KEY CHECK ("
    "   length(request_id) BETWEEN 1 AND 256 AND"
    "   instr(request_id, char(0)) = 0),"
    " operation TEXT NOT NULL CHECK (operation IN ("
    "   'credential_issue','credential_rotate')),"
    " operation_fingerprint BLOB NOT NULL CHECK ("
    "   typeof(operation_fingerprint) = 'blob' AND"
    "   length(operation_fingerprint) = 32),"
    " terminal_state TEXT NOT NULL CHECK (terminal_state = 'not_committed'),"
    " created_at_us INTEGER NOT NULL CHECK (created_at_us > 0)"
    ");"
    "CREATE TRIGGER IF NOT EXISTS trg_service_credential_operation_fences_no_update"
    " BEFORE UPDATE ON service_credential_operation_fences"
    " BEGIN SELECT RAISE(ABORT,"
    "   'service credential operation fences are append-only'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_credential_operation_fences_no_delete"
    " BEFORE DELETE ON service_credential_operation_fences"
    " BEGIN SELECT RAISE(ABORT,"
    "   'service credential operation fences are append-only'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_handoff_dispositions_no_update"
    " BEFORE UPDATE ON service_credential_handoff_dispositions"
    " BEGIN SELECT RAISE(ABORT,"
    "   'service credential handoff dispositions are append-only'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_handoff_dispositions_no_delete"
    " BEFORE DELETE ON service_credential_handoff_dispositions"
    " BEGIN SELECT RAISE(ABORT,"
    "   'service credential handoff dispositions are append-only'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_handoff_cancellation_no_update"
    " BEFORE UPDATE ON service_credential_handoff_cancellation_claims"
    " BEGIN SELECT RAISE(ABORT,"
    "   'service credential handoff cancellation claims are append-only'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_handoff_cancellation_no_delete"
    " BEFORE DELETE ON service_credential_handoff_cancellation_claims"
    " BEGIN SELECT RAISE(ABORT,"
    "   'service credential handoff cancellation claims are append-only'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_handoff_cancellation_no_legacy_collision"
    " BEFORE INSERT ON service_credential_handoff_cancellation_claims"
    " WHEN EXISTS (SELECT 1 FROM service_domain_requests"
    "   WHERE request_id = NEW.cancellation_request_id)"
    " BEGIN SELECT RAISE(ABORT,"
    "   'service handoff cancellation request collides with service domain request'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_handoff_cancellation_no_remediation_collision"
    " BEFORE INSERT ON service_credential_handoff_cancellation_claims"
    " WHEN EXISTS (SELECT 1 FROM service_credential_handoff_remediation_actions"
    "   WHERE remediation_request_id = NEW.cancellation_request_id)"
    " BEGIN SELECT RAISE(ABORT,"
    "   'service handoff cancellation request collides with remediation request'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_handoff_remediation_no_update"
    " BEFORE UPDATE ON service_credential_handoff_remediation_actions"
    " BEGIN SELECT RAISE(ABORT,"
    "   'service credential handoff remediation actions are append-only'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_handoff_remediation_no_delete"
    " BEFORE DELETE ON service_credential_handoff_remediation_actions"
    " BEGIN SELECT RAISE(ABORT,"
    "   'service credential handoff remediation actions are append-only'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_handoff_remediation_no_legacy_collision"
    " BEFORE INSERT ON service_credential_handoff_remediation_actions"
    " WHEN EXISTS (SELECT 1 FROM service_domain_requests"
    "   WHERE request_id = NEW.remediation_request_id)"
    " BEGIN SELECT RAISE(ABORT,"
    "   'service handoff remediation request collides with service domain request'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_handoff_remediation_no_cancellation_collision"
    " BEFORE INSERT ON service_credential_handoff_remediation_actions"
    " WHEN EXISTS (SELECT 1 FROM service_credential_handoff_cancellation_claims"
    "   WHERE cancellation_request_id = NEW.remediation_request_id)"
    " BEGIN SELECT RAISE(ABORT,"
    "   'service handoff remediation request collides with cancellation request'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_handoff_retirement_no_update"
    " BEFORE UPDATE ON service_credential_handoff_retirement_receipts"
    " BEGIN SELECT RAISE(ABORT,"
    "   'service credential handoff retirement receipts are append-only'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_handoff_retirement_no_delete"
    " BEFORE DELETE ON service_credential_handoff_retirement_receipts"
    " BEGIN SELECT RAISE(ABORT,"
    "   'service credential handoff retirement receipts are permanent'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_domain_requests_no_remediation_collision"
    " BEFORE INSERT ON service_domain_requests"
    " WHEN EXISTS (SELECT 1 FROM service_credential_handoff_remediation_actions"
    "   WHERE remediation_request_id = NEW.request_id)"
    " BEGIN SELECT RAISE(ABORT,"
    "   'service domain request collides with service handoff remediation request'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_domain_requests_no_cancellation_collision"
    " BEFORE INSERT ON service_domain_requests"
    " WHEN EXISTS (SELECT 1 FROM service_credential_handoff_cancellation_claims"
    "   WHERE cancellation_request_id = NEW.request_id)"
    " BEGIN SELECT RAISE(ABORT,"
    "   'service domain request collides with service handoff cancellation request'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_principals_identity_immutable"
    " BEFORE UPDATE ON service_principals WHEN"
    " OLD.subject_id IS NOT NEW.subject_id OR"
    " OLD.created_by IS NOT NEW.created_by OR"
    " OLD.created_at_us IS NOT NEW.created_at_us"
    " BEGIN SELECT RAISE(ABORT, 'service principal identity is immutable'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_credentials_identity_immutable"
    " BEFORE UPDATE ON service_credentials WHEN"
    " OLD.credential_id IS NOT NEW.credential_id OR"
    " OLD.credential_format_version IS NOT NEW.credential_format_version OR"
    " OLD.subject_id IS NOT NEW.subject_id OR OLD.tenant_id IS NOT NEW.tenant_id OR"
    " OLD.verifier_version IS NOT NEW.verifier_version OR"
    " OLD.salt IS NOT NEW.salt OR OLD.verifier IS NOT NEW.verifier OR"
    " OLD.created_by IS NOT NEW.created_by OR"
    " OLD.created_at_us IS NOT NEW.created_at_us OR"
    " OLD.expires_at_us IS NOT NEW.expires_at_us OR"
    " OLD.rotated_from_id IS NOT NEW.rotated_from_id"
    " BEGIN SELECT RAISE(ABORT, 'service credential identity is immutable'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_principal_events_no_update"
    " BEFORE UPDATE ON service_principal_events"
    " BEGIN SELECT RAISE(ABORT, 'service principal events are append-only'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_principal_events_no_delete"
    " BEFORE DELETE ON service_principal_events"
    " BEGIN SELECT RAISE(ABORT, 'service principal events are append-only'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_credential_events_no_update"
    " BEFORE UPDATE ON service_credential_events"
    " BEGIN SELECT RAISE(ABORT, 'service credential events are append-only'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_credential_events_no_delete"
    " BEFORE DELETE ON service_credential_events"
    " BEGIN SELECT RAISE(ABORT, 'service credential events are append-only'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_domain_requests_no_update"
    " BEFORE UPDATE ON service_domain_requests"
    " BEGIN SELECT RAISE(ABORT, 'service domain requests are append-only'); END;"
    "CREATE TRIGGER IF NOT EXISTS trg_service_domain_requests_no_delete"
    " BEFORE DELETE ON service_domain_requests"
    " BEGIN SELECT RAISE(ABORT, 'service domain requests are append-only'); END;";

typedef struct
{
  const gchar *name;
  const gchar *column_signature;
  const gchar *const *sql_needles;
  guint check_count;
  const gchar *foreign_key_signature;
  const gchar *index_signature;
} ServiceTableDescriptor;

typedef struct
{
  const gchar *name;
  const gchar *table;
  const gchar *sql_fingerprint;
} ServiceTriggerDescriptor;

typedef struct
{
  const gchar *name;
  const gchar *table;
  const gchar *sql_fingerprint;
} ServiceIndexDescriptor;

static const gchar *const service_principal_needles[] = {
  "check(length(subject_id)between5and128andinstr(subject_id,char(0))=0andsubstr(subject_id,1,4)='svc:'andsubstr(subject_id,5,1)glob'[a-za-z0-9]'andsubstr(subject_id,-1,1)glob'[a-za-z0-9]'andsubject_idnotglob'*[^-a-za-z0-9._:]*'andsubject_idnotglob'*:[^a-za-z0-9]*'andsubject_idnotglob'*[^a-za-z0-9]:*')",
  "check(length(display_name)between1and256)",
  "check(statein('active','disabled'))",
  "check(generation>=1)",
  "check(length(created_by)between1and128)",
  "check(created_at_us>0)",
  "check(updated_at_us>=created_at_us)",
  "check(disabled_byisnullorlength(disabled_by)between1and128)",
  "check((state='active'anddisabled_byisnullanddisabled_at_usisnull)or(state='disabled'anddisabled_byisnotnullanddisabled_at_usisnotnullanddisabled_at_us>=created_at_us))",
  NULL,
};

static const gchar *const service_cvk_needles[] = {
  "check(slot=1)",
  "check(generation>=1)",
  "check(envelope_format_version>=1)",
  "check(typeof(provider_binding)='blob'andlength(provider_binding)=32)",
  "check(typeof(sealed_cvk)='blob'andlength(sealed_cvk)between1and65536)",
  "check(created_at_us>0)",
  "check(updated_at_us>=created_at_us)",
  NULL,
};

static const gchar *const service_handoff_escrow_needles[] = {
  "check(typeof(escrow_id)='text'andlength(escrow_id)=36andinstr(escrow_id,char(0))=0)",
  "check(operationin('issue','rotate'))",
  "check(typeof(request_id)='text'andlength(request_id)between1and256andinstr(request_id,char(0))=0)",
  "check(typeof(actor_subject_id)='text'andlength(actor_subject_id)between1and128andinstr(actor_subject_id,char(0))=0)",
  "check(typeof(target_digest)='blob'andlength(target_digest)=32)",
  "check(typeof(credential_id)='text'andlength(credential_id)=31andsubstr(credential_id,1,4)='wlc_'andinstr(credential_id,char(0))=0)",
  "check(credential_generation>=1)", "check(deadline_at_us>0)",
  "check(typeof(binding_digest)='blob'andlength(binding_digest)=32)",
  "check(typeof(sealed_envelope)='blob'andlength(sealed_envelope)between1and65536)",
  "check(created_at_us>0)", NULL,
};

static const gchar *const service_credential_needles[] = {
  "check(length(credential_id)between1and128andinstr(credential_id,char(0))=0)",
  "check(credential_format_version>=1)",
  "check(generation>=1)",
  "check(statein('active','revoked'))",
  "check(verifier_version>=1)",
  "check(typeof(salt)='blob'andlength(salt)=16)",
  "check(typeof(verifier)='blob'andlength(verifier)=32)",
  "check(length(created_by)between1and128)",
  "check(created_at_us>0)",
  "check(updated_at_us>=created_at_us)",
  "check(expires_at_usisnullorexpires_at_us>created_at_us)",
  "check(last_used_at_usisnullorlast_used_at_us>=created_at_us)",
  "check(revoked_byisnullorlength(revoked_by)between1and128)",
  "unique(credential_id,subject_id,tenant_id)",
  "unique(rotated_from_id)",
  "check(rotated_from_idisnullorrotated_from_id<>credential_id)",
  "check((state='active'andrevoked_byisnullandrevoked_at_usisnull)or(state='revoked'andrevoked_byisnotnullandrevoked_at_usisnotnullandrevoked_at_us>=created_at_us))",
  NULL,
};

static const gchar *const service_principal_event_needles[] = {
  "check(eventin('created','disabled'))",
  "check(from_stateisnullorfrom_statein('active','disabled'))",
  "check(to_statein('active','disabled'))",
  "check(generation>=1)",
  "check(length(actor_subject_id)between1and128)",
  "check(created_at_us>0)",
  "check((event='created'andfrom_stateisnullandto_state='active')or(event='disabled'andfrom_state='active'andto_state='disabled'))",
  NULL,
};

static const gchar *const service_credential_event_needles[] = {
  "check(eventin('issued','rotated','revoked'))",
  "check(from_stateisnullorfrom_statein('active','revoked'))",
  "check(to_statein('active','revoked'))",
  "check(generation>=1)",
  "check(length(actor_subject_id)between1and128)",
  "check(created_at_us>0)",
  "check((eventin('issued','rotated')andfrom_stateisnullandto_state='active')or(event='revoked'andfrom_state='active'andto_state='revoked'))",
  NULL,
};

static const gchar *const service_domain_request_needles[] = {
  "check(length(request_id)between1and256andinstr(request_id,char(0))=0)",
  "check(operationin('principal_create','principal_disable','credential_issue','credential_revoke','credential_rotate'))",
  "check(length(resource_id)between1and128andinstr(resource_id,char(0))=0)",
  "check(typeof(input_fingerprint)='blob'andlength(input_fingerprint)=32)",
  "check(created_at_us>0)",
  NULL,
};

static const gchar *const service_handoff_disposition_needles[] = {
  "check(typeof(disposition_id)='text'andlength(disposition_id)=36andinstr(disposition_id,char(0))=0)",
  "check(typeof(semantic_key)='blob'andlength(semantic_key)=32)",
  "check(typeof(original_request_id)='text'andlength(original_request_id)=27andinstr(original_request_id,char(0))=0)",
  "check(typeof(escrow_id)='text'andlength(escrow_id)=36andinstr(escrow_id,char(0))=0)",
  "check(typeof(binding_digest)='blob'andlength(binding_digest)=32)",
  "check(successor_credential_idisnullor(typeof(successor_credential_id)='text'andlength(successor_credential_id)=31andsubstr(successor_credential_id,1,4)='wlc_'andinstr(successor_credential_id,char(0))=0))",
  "check(successor_issuance_generationisnullorsuccessor_issuance_generation>=1)",
  "check(typeof(actor_subject_id)='text'andlength(actor_subject_id)between1and128andinstr(actor_subject_id,char(0))=0)",
  "check(reasonin('not_committed','operation_expired','operation_cancelled','successor_expired','successor_revoked','delivered'))",
  "check(outcomein('terminal_not_committed','attention_required','operator_action_required','escrow_deleted'))",
  "check(typeof(audit_id)='text'andlength(audit_id)=36andinstr(audit_id,char(0))=0)",
  "check(created_at_us>0)",
  "check((reason='not_committed'andoutcome='terminal_not_committed'andsuccessor_credential_idisnullandsuccessor_issuance_generationisnull)or(reason<>'not_committed'andbinding_digest<>zeroblob(32)andsuccessor_credential_idisnotnullandsuccessor_issuance_generationisnotnulland((reasonin('operation_expired','operation_cancelled')andoutcome='attention_required')or(reasonin('successor_expired','successor_revoked')andoutcome='operator_action_required')or(reason='delivered'andoutcome='escrow_deleted'))))",
  NULL,
};

static const gchar *const service_handoff_remediation_needles[] = {
  "check(typeof(remediation_request_id)='text'andlength(remediation_request_id)=27andinstr(remediation_request_id,char(0))=0)",
  "check(typeof(request_fingerprint)='blob'andlength(request_fingerprint)=32andrequest_fingerprint<>zeroblob(32))",
  "check(typeof(incident_fingerprint)='blob'andlength(incident_fingerprint)=32andincident_fingerprint<>zeroblob(32))",
  "check(typeof(decision_request_id)='text'andlength(decision_request_id)=27andinstr(decision_request_id,char(0))=0)",
  "check(typeof(original_request_id)='text'andlength(original_request_id)=27andinstr(original_request_id,char(0))=0)",
  "check(typeof(original_actor_subject_id)='text'andlength(original_actor_subject_id)between1and128andinstr(original_actor_subject_id,char(0))=0)",
  "check(typeof(current_actor_subject_id)='text'andlength(current_actor_subject_id)between1and128andinstr(current_actor_subject_id,char(0))=0)",
  "check(source_kindin('committed_attention','operator_action_required'))",
  "check(typeof(journal_snapshot_digest)='blob'andlength(journal_snapshot_digest)=32andjournal_snapshot_digest<>zeroblob(32))",
  "check(observed_statein('server_committed','publication_planned','publication_prepared','file_published','cleanup_required','operator_action_required'))",
  "check(source_disposition_idisnullor(typeof(source_disposition_id)='text'andlength(source_disposition_id)=36andinstr(source_disposition_id,char(0))=0))",
  "check(source_audit_idisnullor(typeof(source_audit_id)='text'andlength(source_audit_id)=36andinstr(source_audit_id,char(0))=0))",
  "check(source_reasonisnullorsource_reasonin('operation_cancelled','operation_expired'))",
  "check(oar_source_stateisnulloroar_source_statein('server_committed','publication_planned','publication_prepared','file_published','cleanup_required'))",
  "check(oar_causeisnulloroar_causein('receipt_foreign','receipt_uncertain','escrow_foreign','escrow_uncertain','successor_revoked','successor_expired','explicit_hold','escrow_missing'))",
  "check(resume_target_stateisnullorresume_target_statein('server_committed','publication_planned','publication_prepared','file_published','cleanup_required'))",
  "check(typeof(escrow_id)='text'andlength(escrow_id)=36andinstr(escrow_id,char(0))=0)",
  "check(typeof(binding_digest)='blob'andlength(binding_digest)=32andbinding_digest<>zeroblob(32))",
  "check(typeof(successor_credential_id)='text'andlength(successor_credential_id)=31andsubstr(successor_credential_id,1,4)='wlc_'andinstr(successor_credential_id,char(0))=0)",
  "check(successor_issuance_generation>=1)",
  "check(actionin('resume','revoke_and_wipe'))",
  "check(confirmation_versionin(0,1))",
  "check(confirmedin(0,1)andtypeof(confirmed)='integer')",
  "check(outcomein('recorded','revoked_and_wiped','expired_and_wiped','already_revoked_and_wiped'))",
  "check(escrow_outcomein('retained','deleted','already_absent'))",
  "check(credential_generation_after>=1)",
  "check(revoke_event_idisnullorrevoke_event_id>0)",
  "check(revoke_event_generationisnullorrevoke_event_generation>=1)",
  "check(revoke_event_request_idisnullor(typeof(revoke_event_request_id)='text'andlength(revoke_event_request_id)between1and256andinstr(revoke_event_request_id,char(0))=0))",
  "check(revoke_event_actor_subject_idisnullor(typeof(revoke_event_actor_subject_id)='text'andlength(revoke_event_actor_subject_id)between1and128andinstr(revoke_event_actor_subject_id,char(0))=0))",
  "check(revoke_event_created_at_usisnullorrevoke_event_created_at_us>0)",
  "check(typeof(audit_id)='text'andlength(audit_id)=36andinstr(audit_id,char(0))=0)",
  "check(created_at_us>0)",
  "check(original_request_id<>remediation_request_idandoriginal_request_id<>decision_request_idandremediation_request_id<>decision_request_id)",
  "check(original_actor_subject_id<>current_actor_subject_id)",
  "check((source_kind='committed_attention'andobserved_statein('server_committed','publication_planned','publication_prepared','file_published','cleanup_required')andsource_disposition_idisnotnullandsource_audit_idisnotnullandsource_reasonisnotnullandoar_source_stateisnullandoar_causeisnullandresume_target_stateisnull)or(source_kind='operator_action_required'andobserved_state='operator_action_required'andsource_disposition_idisnullandsource_audit_idisnullandsource_reasonisnullandoar_source_stateisnotnullandoar_causeisnotnullandresume_target_state=oar_source_state))",
  "check(not(oar_source_state='server_committed'andoar_causein('receipt_foreign','receipt_uncertain')))",
  "check(not(action='resume'andoar_causein('successor_revoked','successor_expired','escrow_missing')))",
  "check(escrow_outcome<>'already_absent'or(source_kind='operator_action_required'andoar_cause='escrow_missing'andaction='revoke_and_wipe'))",
  "check((action='resume'andconfirmation_version=0andconfirmed=0andoutcome='recorded'andescrow_outcome='retained'andcredential_generation_after=successor_issuance_generationandrevoke_event_idisnullandrevoke_event_generationisnullandrevoke_event_request_idisnullandrevoke_event_actor_subject_idisnullandrevoke_event_created_at_usisnull)or(action='revoke_and_wipe'andconfirmation_version=1andconfirmed=1andoutcomein('revoked_and_wiped','expired_and_wiped','already_revoked_and_wiped')andescrow_outcomein('deleted','already_absent')and((outcome='expired_and_wiped'andcredential_generation_after=successor_issuance_generationandrevoke_event_idisnullandrevoke_event_generationisnullandrevoke_event_request_idisnullandrevoke_event_actor_subject_idisnullandrevoke_event_created_at_usisnull)or(outcomein('revoked_and_wiped','already_revoked_and_wiped')andsuccessor_issuance_generation<9223372036854775807andcredential_generation_after=successor_issuance_generation+1andrevoke_event_idisnotnullandrevoke_event_generationisnotnullandrevoke_event_generation=credential_generation_afterandrevoke_event_request_idisnotnullandrevoke_event_actor_subject_idisnotnullandrevoke_event_created_at_usisnotnulland(outcome<>'revoked_and_wiped'or(revoke_event_request_id=remediation_request_idandrevoke_event_actor_subject_id=current_actor_subject_idandrevoke_event_created_at_us=created_at_us))))))",
  NULL,
};

static const gchar *const service_handoff_retirement_needles[] = {
  "check(typeof(original_request_id)='text'andlength(original_request_id)=27andinstr(original_request_id,char(0))=0)",
  "check(terminal_kindin('file_published','operator_revoke_and_wipe'))",
  "check(typeof(raw_journal_snapshot_digest)='blob'andlength(raw_journal_snapshot_digest)=32andraw_journal_snapshot_digest<>zeroblob(32))",
  "check(delivery_disposition_idisnullor(typeof(delivery_disposition_id)='text'andlength(delivery_disposition_id)=36andinstr(delivery_disposition_id,char(0))=0))",
  "check(delivery_audit_idisnullor(typeof(delivery_audit_id)='text'andlength(delivery_audit_id)=36andinstr(delivery_audit_id,char(0))=0))",
  "check(typeof(delivery_proof_digest)='blob'andlength(delivery_proof_digest)=32)",
  "check(revoke_remediation_request_idisnullor(typeof(revoke_remediation_request_id)='text'andlength(revoke_remediation_request_id)=27andinstr(revoke_remediation_request_id,char(0))=0))",
  "check(revoke_audit_idisnullor(typeof(revoke_audit_id)='text'andlength(revoke_audit_id)=36andinstr(revoke_audit_id,char(0))=0))",
  "check(revoke_event_idisnullorrevoke_event_id>0)",
  "check(resume_remediation_request_idisnullor(typeof(resume_remediation_request_id)='text'andlength(resume_remediation_request_id)=27andinstr(resume_remediation_request_id,char(0))=0))",
  "check(resume_audit_idisnullor(typeof(resume_audit_id)='text'andlength(resume_audit_id)=36andinstr(resume_audit_id,char(0))=0))",
  "check(remediation_source_snapshot_digestisnullor(typeof(remediation_source_snapshot_digest)='blob'andlength(remediation_source_snapshot_digest)=32andremediation_source_snapshot_digest<>zeroblob(32)))",
  "check(remediation_request_fingerprintisnullor(typeof(remediation_request_fingerprint)='blob'andlength(remediation_request_fingerprint)=32andremediation_request_fingerprint<>zeroblob(32)))",
  "check(retention_basis_at_us>0)",
  "check(retired_at_us>=retention_basis_at_usandretired_at_us-retention_basis_at_us>=2592000000000)",
  "check((terminal_kind='file_published'anddelivery_disposition_idisnotnullanddelivery_audit_idisnotnullanddelivery_proof_digest<>zeroblob(32)andrevoke_remediation_request_idisnullandrevoke_audit_idisnullandrevoke_event_idisnulland((resume_remediation_request_idisnullandresume_audit_idisnullandremediation_source_snapshot_digestisnullandremediation_request_fingerprintisnull)or(resume_remediation_request_idisnotnullandresume_audit_idisnotnullandremediation_source_snapshot_digest<>zeroblob(32)andremediation_request_fingerprint<>zeroblob(32))))or(terminal_kind='operator_revoke_and_wipe'anddelivery_disposition_idisnullanddelivery_audit_idisnullanddelivery_proof_digest=zeroblob(32)andrevoke_remediation_request_idisnotnullandrevoke_audit_idisnotnullandresume_remediation_request_idisnullandresume_audit_idisnullandremediation_source_snapshot_digest<>zeroblob(32)andremediation_request_fingerprint<>zeroblob(32)))",
  NULL,
};

static const gchar *const service_handoff_cancellation_needles[] = {
  "check(typeof(cancellation_request_id)='text'andlength(cancellation_request_id)=27andinstr(cancellation_request_id,char(0))=0)",
  "check(typeof(request_fingerprint)='blob'andlength(request_fingerprint)=32)",
  "check(typeof(decision_request_id)='text'andlength(decision_request_id)=27andinstr(decision_request_id,char(0))=0)",
  "check(typeof(original_request_id)='text'andlength(original_request_id)=27andinstr(original_request_id,char(0))=0)",
  "check(typeof(original_actor_subject_id)='text'andlength(original_actor_subject_id)between1and128andinstr(original_actor_subject_id,char(0))=0)",
  "check(typeof(current_actor_subject_id)='text'andlength(current_actor_subject_id)between1and128andinstr(current_actor_subject_id,char(0))=0)",
  "check(resolutionin('committed_attention','terminal_not_committed'))",
  "check(typeof(escrow_id)='text'andlength(escrow_id)=36andinstr(escrow_id,char(0))=0)",
  "check(typeof(binding_digest)='blob'andlength(binding_digest)=32)",
  "check(successor_credential_idisnullor(typeof(successor_credential_id)='text'andlength(successor_credential_id)=31andsubstr(successor_credential_id,1,4)='wlc_'andinstr(successor_credential_id,char(0))=0))",
  "check(successor_issuance_generationisnullorsuccessor_issuance_generation>=1)",
  "check(operationin('issue','rotate'))",
  "check(typeof(target_a)='text'andlength(target_a)between1and128andinstr(target_a,char(0))=0)",
  "check(target_bisnullor(typeof(target_b)='text'andlength(target_b)between1and128andinstr(target_b,char(0))=0))",
  "check(typeof(target_digest)='blob'andlength(target_digest)=32andtarget_digest<>zeroblob(32))",
  "check(typeof(maintenance_proof_digest)='blob'andlength(maintenance_proof_digest)=32andmaintenance_proof_digest<>zeroblob(32))",
  "check(deadline_at_us>0)",
  "check(typeof(disposition_id)='text'andlength(disposition_id)=36andinstr(disposition_id,char(0))=0)",
  "check(typeof(audit_id)='text'andlength(audit_id)=36andinstr(audit_id,char(0))=0)",
  "check(created_at_us>0)",
  "check(original_request_id<>cancellation_request_idandoriginal_request_id<>decision_request_idandcancellation_request_id<>decision_request_id)",
  "check(original_actor_subject_id<>current_actor_subject_id)",
  "check((operation='issue'andtarget_bisnotnull)or(operation='rotate'andtarget_bisnull))",
  "check((resolution='committed_attention'andbinding_digest<>zeroblob(32)andsuccessor_credential_idisnotnullandsuccessor_issuance_generationisnotnull)or(resolution='terminal_not_committed'andbinding_digest=zeroblob(32)andsuccessor_credential_idisnullandsuccessor_issuance_generationisnull))",
  NULL,
};

static const gchar *const service_writer_gate_needles[] = {
  "check(singleton=1)",
  "check(lock_word=0)",
  "withoutrowid",
  NULL,
};

static const gchar *const service_credential_operation_fence_needles[] = {
  "check(length(request_id)between1and256andinstr(request_id,char(0))=0)",
  "check(operationin('credential_issue','credential_rotate'))",
  "check(typeof(operation_fingerprint)='blob'and"
      "length(operation_fingerprint)=32)",
  "check(terminal_state='not_committed')",
  "check(created_at_us>0)",
  NULL,
};

static const gchar *const service_exchange_audit_needles[] = {
  "check(typeof(intention_id)='text'andlength(intention_id)=36andinstr(intention_id,char(0))=0)",
  "check(typeof(payload_digest)='text'andlength(payload_digest)=64andpayload_digest=lower(payload_digest)andpayload_digestnotglob'*[^0-9a-f]*')",
  "check(typeof(payload_schema_version)='integer'andpayload_schema_version=1)",
  "check(typeof(event_type)='text'andevent_type='service.credential.exchange')",
  "check(typeof(outcome)='text'andoutcome='allowed')",
  "check(typeof(created_at_us)='integer'andcreated_at_us>0)",
  "check(typeof(request_id)='text'andlength(request_id)=27andinstr(request_id,char(0))=0)",
  "check(typeof(credential_id)='text'andlength(credential_id)=31andsubstr(credential_id,1,4)='wlc_'andinstr(credential_id,char(0))=0)",
  "check(typeof(credential_generation)='blob'andlength(credential_generation)=8)",
  "check(typeof(service_principal)='text'andlength(cast(service_principalasblob))between5and128andinstr(service_principal,char(0))=0)",
  "check(typeof(tenant_id)='text'andlength(cast(tenant_idasblob))between1and128andinstr(tenant_id,char(0))=0)",
  "check(typeof(fingerprint_schema_version)='integer'andfingerprint_schema_version=1)",
  "check(typeof(session_fingerprint)='text'andlength(session_fingerprint)=64andsession_fingerprint=lower(session_fingerprint)andsession_fingerprintnotglob'*[^0-9a-f]*')",
  "check(typeof(jti_fingerprint)='text'andlength(jti_fingerprint)=64andjti_fingerprint=lower(jti_fingerprint)andjti_fingerprintnotglob'*[^0-9a-f]*')",
  "check(typeof(canonical_payload)='blob'andlength(canonical_payload)between1and4096)",
  NULL,
};

static const ServiceTableDescriptor service_table_descriptors[] = {
  {"service_principals",
        "subject_id:TEXT:1::1,display_name:TEXT:1::0,state:TEXT:1::0,generation:INTEGER:1:1:0,created_by:TEXT:1::0,created_at_us:INTEGER:1::0,updated_at_us:INTEGER:1::0,disabled_by:TEXT:0::0,disabled_at_us:INTEGER:0::0",
        service_principal_needles, 9, "",
      "idx_service_principals_state_subject:0:c:0:0:2:state:0:BINARY:1,1:0:subject_id:0:BINARY:1,2:-1::0:BINARY:0;sqlite_autoindex_service_principals_1:1:pk:0:0:0:subject_id:0:BINARY:1,1:-1::0:BINARY:0"},
  {"service_credentials",
        "credential_id:TEXT:1::1,credential_format_version:INTEGER:1::0,subject_id:TEXT:1::0,tenant_id:TEXT:1::0,generation:INTEGER:1:1:0,state:TEXT:1::0,verifier_version:INTEGER:1::0,salt:BLOB:1::0,verifier:BLOB:1::0,created_by:TEXT:1::0,created_at_us:INTEGER:1::0,updated_at_us:INTEGER:1::0,expires_at_us:INTEGER:0::0,last_used_at_us:INTEGER:0::0,revoked_by:TEXT:0::0,revoked_at_us:INTEGER:0::0,rotated_from_id:TEXT:0::0",
        service_credential_needles, 15,
        "0:0:service_credentials:rotated_from_id:credential_id:RESTRICT:RESTRICT:NONE;0:1:service_credentials:subject_id:subject_id:RESTRICT:RESTRICT:NONE;0:2:service_credentials:tenant_id:tenant_id:RESTRICT:RESTRICT:NONE;1:0:tenants:tenant_id:tenant_id:RESTRICT:RESTRICT:NONE;2:0:service_principals:subject_id:subject_id:RESTRICT:RESTRICT:NONE",
      "idx_service_credentials_subject_tenant_state:0:c:0:0:2:subject_id:0:BINARY:1,1:3:tenant_id:0:BINARY:1,2:5:state:0:BINARY:1,3:-1::0:BINARY:0;idx_service_credentials_tenant_state_expiry:0:c:0:0:3:tenant_id:0:BINARY:1,1:5:state:0:BINARY:1,2:12:expires_at_us:0:BINARY:1,3:-1::0:BINARY:0;sqlite_autoindex_service_credentials_1:1:pk:0:0:0:credential_id:0:BINARY:1,1:-1::0:BINARY:0;sqlite_autoindex_service_credentials_2:1:u:0:0:0:credential_id:0:BINARY:1,1:2:subject_id:0:BINARY:1,2:3:tenant_id:0:BINARY:1,3:-1::0:BINARY:0;sqlite_autoindex_service_credentials_3:1:u:0:0:16:rotated_from_id:0:BINARY:1,1:-1::0:BINARY:0"},
  {"service_credential_cvk",
        "slot:INTEGER:0::1,generation:INTEGER:1::0,envelope_format_version:INTEGER:1::0,provider_binding:BLOB:1::0,sealed_cvk:BLOB:1::0,created_at_us:INTEGER:1::0,updated_at_us:INTEGER:1::0",
        service_cvk_needles, 7, "",
      "sqlite_autoindex_service_credential_cvk_1:1:u:0:0:1:generation:0:BINARY:1,1:-1::0:BINARY:0"},
  {"service_credential_handoff_escrows",
        "escrow_id:TEXT:1::1,operation:TEXT:1::0,request_id:TEXT:1::0,actor_subject_id:TEXT:1::0,target_digest:BLOB:1::0,credential_id:TEXT:1::0,credential_generation:INTEGER:1::0,deadline_at_us:INTEGER:1::0,binding_digest:BLOB:1::0,sealed_envelope:BLOB:1::0,created_at_us:INTEGER:1::0",
        service_handoff_escrow_needles, 11, "",
      "idx_service_handoff_escrows_credential:0:c:0:0:5:credential_id:0:BINARY:1,1:6:credential_generation:0:BINARY:1,2:-1::0:BINARY:0;sqlite_autoindex_service_credential_handoff_escrows_1:1:pk:0:0:0:escrow_id:0:BINARY:1,1:-1::0:BINARY:0;sqlite_autoindex_service_credential_handoff_escrows_2:1:u:0:0:2:request_id:0:BINARY:1,1:-1::0:BINARY:0"},
  {"service_principal_events",
        "event_id:INTEGER:0::1,subject_id:TEXT:1::0,event:TEXT:1::0,from_state:TEXT:0::0,to_state:TEXT:1::0,generation:INTEGER:1::0,actor_subject_id:TEXT:1::0,request_id:TEXT:0::0,created_at_us:INTEGER:1::0",
        service_principal_event_needles, 7,
        "0:0:service_principals:subject_id:subject_id:RESTRICT:RESTRICT:NONE",
      "idx_service_principal_events_request:0:c:0:0:7:request_id:0:BINARY:1,1:-1::0:BINARY:0;idx_service_principal_events_subject_time:0:c:0:0:1:subject_id:0:BINARY:1,1:8:created_at_us:0:BINARY:1,2:0:event_id:0:BINARY:1,3:-1::0:BINARY:0"},
  {"service_credential_events",
        "event_id:INTEGER:0::1,credential_id:TEXT:1::0,subject_id:TEXT:1::0,tenant_id:TEXT:1::0,event:TEXT:1::0,from_state:TEXT:0::0,to_state:TEXT:1::0,generation:INTEGER:1::0,actor_subject_id:TEXT:1::0,request_id:TEXT:0::0,related_credential_id:TEXT:0::0,created_at_us:INTEGER:1::0",
        service_credential_event_needles, 7,
        "0:0:service_credentials:related_credential_id:credential_id:RESTRICT:RESTRICT:NONE;0:1:service_credentials:subject_id:subject_id:RESTRICT:RESTRICT:NONE;0:2:service_credentials:tenant_id:tenant_id:RESTRICT:RESTRICT:NONE;1:0:service_credentials:credential_id:credential_id:RESTRICT:RESTRICT:NONE;1:1:service_credentials:subject_id:subject_id:RESTRICT:RESTRICT:NONE;1:2:service_credentials:tenant_id:tenant_id:RESTRICT:RESTRICT:NONE",
      "idx_service_credential_events_credential_time:0:c:0:0:1:credential_id:0:BINARY:1,1:11:created_at_us:0:BINARY:1,2:0:event_id:0:BINARY:1,3:-1::0:BINARY:0;idx_service_credential_events_owner_time:0:c:0:0:2:subject_id:0:BINARY:1,1:3:tenant_id:0:BINARY:1,2:11:created_at_us:0:BINARY:1,3:0:event_id:0:BINARY:1,4:-1::0:BINARY:0;idx_service_credential_events_request:0:c:0:0:9:request_id:0:BINARY:1,1:-1::0:BINARY:0"},
  {"service_domain_requests",
        "request_id:TEXT:1::1,operation:TEXT:1::0,resource_id:TEXT:1::0,input_fingerprint:BLOB:1::0,created_at_us:INTEGER:1::0",
        service_domain_request_needles, 5, "",
      "sqlite_autoindex_service_domain_requests_1:1:pk:0:0:0:request_id:0:BINARY:1,1:-1::0:BINARY:0"},
  {"service_authority_writer_gate",
        "singleton:INTEGER:1::1,lock_word:INTEGER:1::0",
        service_writer_gate_needles, 2, "",
      "sqlite_autoindex_service_authority_writer_gate_1:1:pk:0:0:0:singleton:0:BINARY:1,1:1:lock_word:0:BINARY:0"},
  {"service_exchange_audit_intentions",
        "intention_id:TEXT:1::1,payload_digest:TEXT:1::0,payload_schema_version:INTEGER:1::0,event_type:TEXT:1::0,outcome:TEXT:1::0,created_at_us:INTEGER:1::0,request_id:TEXT:1::0,credential_id:TEXT:1::0,credential_generation:BLOB:1::0,service_principal:TEXT:1::0,tenant_id:TEXT:1::0,fingerprint_schema_version:INTEGER:1::0,session_fingerprint:TEXT:1::0,jti_fingerprint:TEXT:1::0,canonical_payload:BLOB:1::0",
        service_exchange_audit_needles, 15, "",
      "idx_service_exchange_audit_created:0:c:0:0:5:created_at_us:0:BINARY:1,1:0:intention_id:0:BINARY:1,2:-1::0:BINARY:0;sqlite_autoindex_service_exchange_audit_intentions_1:1:pk:0:0:0:intention_id:0:BINARY:1,1:-1::0:BINARY:0;sqlite_autoindex_service_exchange_audit_intentions_2:1:u:0:0:1:payload_digest:0:BINARY:1,1:-1::0:BINARY:0"},
  {"service_credential_operation_fences",
        "request_id:TEXT:1::1,operation:TEXT:1::0,operation_fingerprint:BLOB:1::0,terminal_state:TEXT:1::0,created_at_us:INTEGER:1::0",
        service_credential_operation_fence_needles, 5, "",
      "sqlite_autoindex_service_credential_operation_fences_1:1:pk:0:0:0:request_id:0:BINARY:1,1:-1::0:BINARY:0"},
  {"service_credential_handoff_dispositions",
        "disposition_id:TEXT:1::1,semantic_key:BLOB:1::0,original_request_id:TEXT:1::0,escrow_id:TEXT:1::0,binding_digest:BLOB:1::0,successor_credential_id:TEXT:0::0,successor_issuance_generation:INTEGER:0::0,actor_subject_id:TEXT:1::0,reason:TEXT:1::0,outcome:TEXT:1::0,audit_id:TEXT:1::0,created_at_us:INTEGER:1::0",
        service_handoff_disposition_needles, 13, "",
      "idx_service_handoff_disposition_exact:1:c:0:0:2:original_request_id:0:BINARY:1,1:8:reason:0:BINARY:1,2:9:outcome:0:BINARY:1,3:3:escrow_id:0:BINARY:1,4:4:binding_digest:0:BINARY:1,5:-2::0:BINARY:1,6:-2::0:BINARY:1,7:-1::0:BINARY:0;sqlite_autoindex_service_credential_handoff_dispositions_1:1:pk:0:0:0:disposition_id:0:BINARY:1,1:-1::0:BINARY:0;sqlite_autoindex_service_credential_handoff_dispositions_2:1:u:0:0:1:semantic_key:0:BINARY:1,1:-1::0:BINARY:0;sqlite_autoindex_service_credential_handoff_dispositions_3:1:u:0:0:10:audit_id:0:BINARY:1,1:-1::0:BINARY:0"},
  {"service_credential_handoff_cancellation_claims",
        "cancellation_request_id:TEXT:1::1,request_fingerprint:BLOB:1::0,decision_request_id:TEXT:1::0,original_request_id:TEXT:1::0,original_actor_subject_id:TEXT:1::0,current_actor_subject_id:TEXT:1::0,resolution:TEXT:1::0,escrow_id:TEXT:1::0,binding_digest:BLOB:1::0,successor_credential_id:TEXT:0::0,successor_issuance_generation:INTEGER:0::0,operation:TEXT:1::0,target_a:TEXT:1::0,target_b:TEXT:0::0,target_digest:BLOB:1::0,maintenance_proof_digest:BLOB:1::0,deadline_at_us:INTEGER:1::0,disposition_id:TEXT:1::0,audit_id:TEXT:1::0,created_at_us:INTEGER:1::0",
        service_handoff_cancellation_needles, 24, "",
      "idx_service_handoff_cancellation_exact:1:c:0:0:3:original_request_id:0:BINARY:1,1:-1::0:BINARY:0;sqlite_autoindex_service_credential_handoff_cancellation_claims_1:1:pk:0:0:0:cancellation_request_id:0:BINARY:1,1:-1::0:BINARY:0;sqlite_autoindex_service_credential_handoff_cancellation_claims_2:1:u:0:0:2:decision_request_id:0:BINARY:1,1:-1::0:BINARY:0;sqlite_autoindex_service_credential_handoff_cancellation_claims_3:1:u:0:0:17:disposition_id:0:BINARY:1,1:-1::0:BINARY:0;sqlite_autoindex_service_credential_handoff_cancellation_claims_4:1:u:0:0:18:audit_id:0:BINARY:1,1:-1::0:BINARY:0"},
  {"service_credential_handoff_remediation_actions",
        "remediation_request_id:TEXT:1::1,request_fingerprint:BLOB:1::0,incident_fingerprint:BLOB:1::0,decision_request_id:TEXT:1::0,original_request_id:TEXT:1::0,original_actor_subject_id:TEXT:1::0,current_actor_subject_id:TEXT:1::0,source_kind:TEXT:1::0,journal_snapshot_digest:BLOB:1::0,observed_state:TEXT:1::0,source_disposition_id:TEXT:0::0,source_audit_id:TEXT:0::0,source_reason:TEXT:0::0,oar_source_state:TEXT:0::0,oar_cause:TEXT:0::0,resume_target_state:TEXT:0::0,escrow_id:TEXT:1::0,binding_digest:BLOB:1::0,successor_credential_id:TEXT:1::0,successor_issuance_generation:INTEGER:1::0,action:TEXT:1::0,confirmation_version:INTEGER:1::0,confirmed:INTEGER:1::0,outcome:TEXT:1::0,escrow_outcome:TEXT:1::0,credential_generation_after:INTEGER:1::0,revoke_event_id:INTEGER:0::0,revoke_event_generation:INTEGER:0::0,revoke_event_request_id:TEXT:0::0,revoke_event_actor_subject_id:TEXT:0::0,revoke_event_created_at_us:INTEGER:0::0,audit_id:TEXT:1::0,created_at_us:INTEGER:1::0",
        service_handoff_remediation_needles, 40, "",
      "idx_service_handoff_completed_revoke:1:c:1:0:4:original_request_id:0:BINARY:1,1:16:escrow_id:0:BINARY:1,2:17:binding_digest:0:BINARY:1,3:18:successor_credential_id:0:BINARY:1,4:19:successor_issuance_generation:0:BINARY:1,5:20:action:0:BINARY:1,6:-1::0:BINARY:0;idx_service_handoff_remediation_incident:1:c:0:0:2:incident_fingerprint:0:BINARY:1,1:-1::0:BINARY:0;sqlite_autoindex_service_credential_handoff_remediation_actions_1:1:pk:0:0:0:remediation_request_id:0:BINARY:1,1:-1::0:BINARY:0;sqlite_autoindex_service_credential_handoff_remediation_actions_2:1:u:0:0:3:decision_request_id:0:BINARY:1,1:-1::0:BINARY:0;sqlite_autoindex_service_credential_handoff_remediation_actions_3:1:u:0:0:31:audit_id:0:BINARY:1,1:-1::0:BINARY:0"},
  {"service_credential_handoff_retirement_receipts",
        "original_request_id:TEXT:1::1,terminal_kind:TEXT:1::0,raw_journal_snapshot_digest:BLOB:1::0,delivery_disposition_id:TEXT:0::0,delivery_audit_id:TEXT:0::0,delivery_proof_digest:BLOB:1::0,revoke_remediation_request_id:TEXT:0::0,revoke_audit_id:TEXT:0::0,revoke_event_id:INTEGER:0::0,resume_remediation_request_id:TEXT:0::0,resume_audit_id:TEXT:0::0,remediation_source_snapshot_digest:BLOB:0::0,remediation_request_fingerprint:BLOB:0::0,retention_basis_at_us:INTEGER:1::0,retired_at_us:INTEGER:1::0",
        service_handoff_retirement_needles, 16, "",
      "idx_service_handoff_retirement_delivery:1:c:1:0:3:delivery_disposition_id:0:BINARY:1,1:-1::0:BINARY:0;idx_service_handoff_retirement_raw:1:c:0:0:2:raw_journal_snapshot_digest:0:BINARY:1,1:-1::0:BINARY:0;idx_service_handoff_retirement_resume:1:c:1:0:9:resume_remediation_request_id:0:BINARY:1,1:-1::0:BINARY:0;idx_service_handoff_retirement_revoke:1:c:1:0:6:revoke_remediation_request_id:0:BINARY:1,1:-1::0:BINARY:0;sqlite_autoindex_service_credential_handoff_retirement_receipts_1:1:pk:0:0:0:original_request_id:0:BINARY:1,1:-1::0:BINARY:0"},
};

static const ServiceIndexDescriptor service_index_descriptors[] = {
  {"idx_service_handoff_disposition_exact",
        "service_credential_handoff_dispositions",
      "createuniqueindexidx_service_handoff_disposition_exactonservice_credential_handoff_dispositions(original_request_id,reason,outcome,escrow_id,binding_digest,coalesce(successor_credential_id,''),coalesce(successor_issuance_generation,0))"},
  {"idx_service_handoff_cancellation_exact",
        "service_credential_handoff_cancellation_claims",
      "createuniqueindexidx_service_handoff_cancellation_exactonservice_credential_handoff_cancellation_claims(original_request_id)"},
  {"idx_service_handoff_remediation_incident",
        "service_credential_handoff_remediation_actions",
      "createuniqueindexidx_service_handoff_remediation_incidentonservice_credential_handoff_remediation_actions(incident_fingerprint)"},
  {"idx_service_handoff_completed_revoke",
        "service_credential_handoff_remediation_actions",
      "createuniqueindexidx_service_handoff_completed_revokeonservice_credential_handoff_remediation_actions(original_request_id,escrow_id,binding_digest,successor_credential_id,successor_issuance_generation,action)whereaction='revoke_and_wipe'"},
  {"idx_service_handoff_retirement_raw",
        "service_credential_handoff_retirement_receipts",
      "createuniqueindexidx_service_handoff_retirement_rawonservice_credential_handoff_retirement_receipts(raw_journal_snapshot_digest)"},
  {"idx_service_handoff_retirement_delivery",
        "service_credential_handoff_retirement_receipts",
      "createuniqueindexidx_service_handoff_retirement_deliveryonservice_credential_handoff_retirement_receipts(delivery_disposition_id)wheredelivery_disposition_idisnotnull"},
  {"idx_service_handoff_retirement_revoke",
        "service_credential_handoff_retirement_receipts",
      "createuniqueindexidx_service_handoff_retirement_revokeonservice_credential_handoff_retirement_receipts(revoke_remediation_request_id)whererevoke_remediation_request_idisnotnull"},
  {"idx_service_handoff_retirement_resume",
        "service_credential_handoff_retirement_receipts",
      "createuniqueindexidx_service_handoff_retirement_resumeonservice_credential_handoff_retirement_receipts(resume_remediation_request_id)whereresume_remediation_request_idisnotnull"},
};

static const ServiceTriggerDescriptor service_trigger_descriptors[] = {
  {"trg_service_principals_identity_immutable", "service_principals",
      "createtriggertrg_service_principals_identity_immutablebeforeupdateonservice_principalswhenold.subject_idisnotnew.subject_idorold.created_byisnotnew.created_byorold.created_at_usisnotnew.created_at_usbeginselectraise(abort,'serviceprincipalidentityisimmutable');end"},
  {"trg_service_credentials_identity_immutable", "service_credentials",
      "createtriggertrg_service_credentials_identity_immutablebeforeupdateonservice_credentialswhenold.credential_idisnotnew.credential_idorold.credential_format_versionisnotnew.credential_format_versionorold.subject_idisnotnew.subject_idorold.tenant_idisnotnew.tenant_idorold.verifier_versionisnotnew.verifier_versionorold.saltisnotnew.saltorold.verifierisnotnew.verifierorold.created_byisnotnew.created_byorold.created_at_usisnotnew.created_at_usorold.expires_at_usisnotnew.expires_at_usorold.rotated_from_idisnotnew.rotated_from_idbeginselectraise(abort,'servicecredentialidentityisimmutable');end"},
  {"trg_service_principal_events_no_update", "service_principal_events",
      "createtriggertrg_service_principal_events_no_updatebeforeupdateonservice_principal_eventsbeginselectraise(abort,'serviceprincipaleventsareappend-only');end"},
  {"trg_service_principal_events_no_delete", "service_principal_events",
      "createtriggertrg_service_principal_events_no_deletebeforedeleteonservice_principal_eventsbeginselectraise(abort,'serviceprincipaleventsareappend-only');end"},
  {"trg_service_credential_events_no_update", "service_credential_events",
      "createtriggertrg_service_credential_events_no_updatebeforeupdateonservice_credential_eventsbeginselectraise(abort,'servicecredentialeventsareappend-only');end"},
  {"trg_service_credential_events_no_delete", "service_credential_events",
      "createtriggertrg_service_credential_events_no_deletebeforedeleteonservice_credential_eventsbeginselectraise(abort,'servicecredentialeventsareappend-only');end"},
  {"trg_service_domain_requests_no_update", "service_domain_requests",
      "createtriggertrg_service_domain_requests_no_updatebeforeupdateonservice_domain_requestsbeginselectraise(abort,'servicedomainrequestsareappend-only');end"},
  {"trg_service_domain_requests_no_delete", "service_domain_requests",
      "createtriggertrg_service_domain_requests_no_deletebeforedeleteonservice_domain_requestsbeginselectraise(abort,'servicedomainrequestsareappend-only');end"},
  {"trg_service_exchange_audit_no_update",
        "service_exchange_audit_intentions",
      "createtriggertrg_service_exchange_audit_no_updatebeforeupdateonservice_exchange_audit_intentionsbeginselectraise(abort,'serviceexchangeauditintentionsareappend-only');end"},
  {"trg_service_exchange_audit_no_delete",
        "service_exchange_audit_intentions",
      "createtriggertrg_service_exchange_audit_no_deletebeforedeleteonservice_exchange_audit_intentionsbeginselectraise(abort,'serviceexchangeauditintentionsareappend-only');end"},
  {"trg_service_credential_operation_fences_no_update",
        "service_credential_operation_fences",
      "createtriggertrg_service_credential_operation_fences_no_updatebeforeupdateonservice_credential_operation_fencesbeginselectraise(abort,'servicecredentialoperationfencesareappend-only');end"},
  {"trg_service_credential_operation_fences_no_delete",
        "service_credential_operation_fences",
      "createtriggertrg_service_credential_operation_fences_no_deletebeforedeleteonservice_credential_operation_fencesbeginselectraise(abort,'servicecredentialoperationfencesareappend-only');end"},
  {"trg_service_handoff_dispositions_no_update",
        "service_credential_handoff_dispositions",
      "createtriggertrg_service_handoff_dispositions_no_updatebeforeupdateonservice_credential_handoff_dispositionsbeginselectraise(abort,'servicecredentialhandoffdispositionsareappend-only');end"},
  {"trg_service_handoff_dispositions_no_delete",
        "service_credential_handoff_dispositions",
      "createtriggertrg_service_handoff_dispositions_no_deletebeforedeleteonservice_credential_handoff_dispositionsbeginselectraise(abort,'servicecredentialhandoffdispositionsareappend-only');end"},
  {"trg_service_handoff_cancellation_no_update",
        "service_credential_handoff_cancellation_claims",
      "createtriggertrg_service_handoff_cancellation_no_updatebeforeupdateonservice_credential_handoff_cancellation_claimsbeginselectraise(abort,'servicecredentialhandoffcancellationclaimsareappend-only');end"},
  {"trg_service_handoff_cancellation_no_delete",
        "service_credential_handoff_cancellation_claims",
      "createtriggertrg_service_handoff_cancellation_no_deletebeforedeleteonservice_credential_handoff_cancellation_claimsbeginselectraise(abort,'servicecredentialhandoffcancellationclaimsareappend-only');end"},
  {"trg_service_handoff_cancellation_no_legacy_collision",
        "service_credential_handoff_cancellation_claims",
      "createtriggertrg_service_handoff_cancellation_no_legacy_collisionbeforeinsertonservice_credential_handoff_cancellation_claimswhenexists(select1fromservice_domain_requestswhererequest_id=new.cancellation_request_id)beginselectraise(abort,'servicehandoffcancellationrequestcollideswithservicedomainrequest');end"},
  {"trg_service_handoff_cancellation_no_remediation_collision",
        "service_credential_handoff_cancellation_claims",
      "createtriggertrg_service_handoff_cancellation_no_remediation_collisionbeforeinsertonservice_credential_handoff_cancellation_claimswhenexists(select1fromservice_credential_handoff_remediation_actionswhereremediation_request_id=new.cancellation_request_id)beginselectraise(abort,'servicehandoffcancellationrequestcollideswithremediationrequest');end"},
  {"trg_service_handoff_remediation_no_update",
        "service_credential_handoff_remediation_actions",
      "createtriggertrg_service_handoff_remediation_no_updatebeforeupdateonservice_credential_handoff_remediation_actionsbeginselectraise(abort,'servicecredentialhandoffremediationactionsareappend-only');end"},
  {"trg_service_handoff_remediation_no_delete",
        "service_credential_handoff_remediation_actions",
      "createtriggertrg_service_handoff_remediation_no_deletebeforedeleteonservice_credential_handoff_remediation_actionsbeginselectraise(abort,'servicecredentialhandoffremediationactionsareappend-only');end"},
  {"trg_service_handoff_remediation_no_legacy_collision",
        "service_credential_handoff_remediation_actions",
      "createtriggertrg_service_handoff_remediation_no_legacy_collisionbeforeinsertonservice_credential_handoff_remediation_actionswhenexists(select1fromservice_domain_requestswhererequest_id=new.remediation_request_id)beginselectraise(abort,'servicehandoffremediationrequestcollideswithservicedomainrequest');end"},
  {"trg_service_handoff_remediation_no_cancellation_collision",
        "service_credential_handoff_remediation_actions",
      "createtriggertrg_service_handoff_remediation_no_cancellation_collisionbeforeinsertonservice_credential_handoff_remediation_actionswhenexists(select1fromservice_credential_handoff_cancellation_claimswherecancellation_request_id=new.remediation_request_id)beginselectraise(abort,'servicehandoffremediationrequestcollideswithcancellationrequest');end"},
  {"trg_service_handoff_retirement_no_update",
        "service_credential_handoff_retirement_receipts",
      "createtriggertrg_service_handoff_retirement_no_updatebeforeupdateonservice_credential_handoff_retirement_receiptsbeginselectraise(abort,'servicecredentialhandoffretirementreceiptsareappend-only');end"},
  {"trg_service_handoff_retirement_no_delete",
        "service_credential_handoff_retirement_receipts",
      "createtriggertrg_service_handoff_retirement_no_deletebeforedeleteonservice_credential_handoff_retirement_receiptsbeginselectraise(abort,'servicecredentialhandoffretirementreceiptsarepermanent');end"},
  {"trg_service_domain_requests_no_remediation_collision",
        "service_domain_requests",
      "createtriggertrg_service_domain_requests_no_remediation_collisionbeforeinsertonservice_domain_requestswhenexists(select1fromservice_credential_handoff_remediation_actionswhereremediation_request_id=new.request_id)beginselectraise(abort,'servicedomainrequestcollideswithservicehandoffremediationrequest');end"},
  {"trg_service_domain_requests_no_cancellation_collision",
        "service_domain_requests",
      "createtriggertrg_service_domain_requests_no_cancellation_collisionbeforeinsertonservice_domain_requestswhenexists(select1fromservice_credential_handoff_cancellation_claimswherecancellation_request_id=new.request_id)beginselectraise(abort,'servicedomainrequestcollideswithservicehandoffcancellationrequest');end"},
};

static const BuiltinRole *
find_builtin_role (const gchar *role_id)
{
  if (role_id == NULL)
    return NULL;
  for (gsize i = 0; i < G_N_ELEMENTS (builtin_roles); i++) {
    if (g_strcmp0 (builtin_roles[i].id, role_id) == 0)
      return &builtin_roles[i];
  }
  return NULL;
}

static const BuiltinPermission *
find_builtin_permission (const gchar *perm_id)
{
  if (perm_id == NULL)
    return NULL;
  for (gsize i = 0; i < G_N_ELEMENTS (builtin_permissions); i++) {
    if (g_strcmp0 (builtin_permissions[i].id, perm_id) == 0)
      return &builtin_permissions[i];
  }
  return NULL;
}

static gboolean
permission_class_is_data_plane (const gchar *klass)
{
  return g_strcmp0 (klass, "basic") == 0;
}

const gchar *
wyl_permission_plane_name (wyl_permission_plane_t plane)
{
  switch (plane) {
    case WYL_PERMISSION_PLANE_CONTROL:
      return "control";
    case WYL_PERMISSION_PLANE_DATA:
      return "data";
    case WYL_PERMISSION_PLANE_LAST_:
    default:
      return NULL;
  }
}

wyrelog_error_t
wyl_policy_store_permission_plane (wyl_policy_store_t *store,
    const gchar *perm_id, wyl_permission_plane_t *out_plane)
{
  if (store == NULL || store->db == NULL || perm_id == NULL
      || out_plane == NULL)
    return WYRELOG_E_INVALID;

  *out_plane = WYL_PERMISSION_PLANE_CONTROL;
  static const gchar *sql = "SELECT class FROM permissions WHERE perm_id = ?;";
  gchar *klass = NULL;
  wyrelog_error_t rc = query_single_text (store->db, sql, perm_id, &klass);
  if (rc == WYRELOG_E_POLICY) {
    *out_plane = WYL_PERMISSION_PLANE_CONTROL;
    return WYRELOG_E_OK;
  }
  if (rc != WYRELOG_E_OK)
    return rc;

  if (permission_class_is_data_plane (klass)) {
    *out_plane = WYL_PERMISSION_PLANE_DATA;
  } else if (g_strcmp0 (klass, "sensitive") == 0
      || g_strcmp0 (klass, "critical") == 0) {
    *out_plane = WYL_PERMISSION_PLANE_CONTROL;
  } else {
    g_free (klass);
    return WYRELOG_E_POLICY;
  }
  g_free (klass);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
role_has_service_principal_descendants (wyl_policy_store_t *store,
    const gchar *role_id, gboolean *out_has_service_members)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || role_id == NULL
      || out_has_service_members == NULL)
    return WYRELOG_E_INVALID;

  *out_has_service_members = FALSE;
  static const gchar *sql =
      "WITH RECURSIVE role_desc(role_id) AS ("
      "  SELECT ?"
      "  UNION"
      "  SELECT ri.child_role_id"
      "  FROM role_desc rd"
      "  JOIN role_inheritances ri ON ri.parent_role_id = rd.role_id"
      ") "
      "SELECT 1 FROM role_desc rd "
      "JOIN role_memberships rm ON rm.role_id = rd.role_id "
      "JOIN service_principals sp ON sp.subject_id = rm.subject_id " "LIMIT 1;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, role_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }
  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW)
    *out_has_service_members = TRUE;
  else if (step_rc != SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_role_is_service_eligible (wyl_policy_store_t *store,
    const gchar *role_id, gboolean *out_eligible)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || role_id == NULL
      || out_eligible == NULL)
    return WYRELOG_E_INVALID;

  *out_eligible = FALSE;
  static const gchar *sql =
      "WITH RECURSIVE role_closure(role_id, effective_role_id) AS ("
      "  SELECT role_id, role_id FROM roles WHERE role_id = ?"
      "  UNION"
      "  SELECT rc.role_id, ri.parent_role_id"
      "  FROM role_closure rc"
      "  JOIN role_inheritances ri ON ri.child_role_id = rc.effective_role_id"
      ") "
      "SELECT 1 FROM role_closure rc "
      "JOIN role_permissions rp ON rp.role_id = rc.effective_role_id "
      "JOIN permissions p ON p.perm_id = rp.perm_id "
      "WHERE p.class != 'basic' " "LIMIT 1;";
  gboolean has_control = FALSE;
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, role_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }
  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW)
    has_control = TRUE;
  else if (step_rc != SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  sqlite3_finalize (stmt);
  *out_eligible = !has_control;
  return WYRELOG_E_OK;
}

static gboolean
is_reserved_catalog_id (const gchar *id)
{
  return g_str_has_prefix (id, "wr.");
}

static wyrelog_error_t
exec_sql (sqlite3 *db, const gchar *sql)
{
  char *errmsg = NULL;

  if (sqlite3_exec (db, sql, NULL, NULL, &errmsg) != SQLITE_OK) {
    sqlite3_free (errmsg);
    return WYRELOG_E_IO;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
prepare_stmt (sqlite3 *db, const gchar *sql, sqlite3_stmt **out_stmt)
{
  if (sqlite3_prepare_v2 (db, sql, -1, out_stmt, NULL) != SQLITE_OK)
    return WYRELOG_E_IO;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
bind_text (sqlite3_stmt *stmt, int index, const gchar *value)
{
  if (sqlite3_bind_text (stmt, index, value, -1, SQLITE_TRANSIENT)
      != SQLITE_OK)
    return WYRELOG_E_IO;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
bind_nullable_text (sqlite3_stmt *stmt, int index, const gchar *value)
{
  if (value == NULL) {
    if (sqlite3_bind_null (stmt, index) != SQLITE_OK)
      return WYRELOG_E_IO;
    return WYRELOG_E_OK;
  }
  return bind_text (stmt, index, value);
}

static gboolean
column_nullable_text_equal (sqlite3_stmt *stmt, int col, const gchar *expected)
{
  if (sqlite3_column_type (stmt, col) == SQLITE_NULL)
    return expected == NULL;
  return g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, col),
      expected) == 0;
}

static gboolean
column_text_exact (sqlite3_stmt *stmt, int col, const gchar *expected)
{
  if (expected == NULL || sqlite3_column_type (stmt, col) != SQLITE_TEXT)
    return FALSE;
  const guint8 *stored = sqlite3_column_text (stmt, col);
  int stored_len = sqlite3_column_bytes (stmt, col);
  gsize expected_len = strlen (expected);
  return stored != NULL && stored_len >= 0
      && (gsize) stored_len == expected_len
      && memchr (stored, '\0', (gsize) stored_len) == NULL
      && g_utf8_validate ((const gchar *) stored, stored_len, NULL)
      && memcmp (stored, expected, expected_len) == 0;
}

static gboolean
is_valid_audit_intention_state (const gchar *state)
{
  return g_strcmp0 (state, "pending") == 0
      || g_strcmp0 (state, "committed") == 0
      || g_strcmp0 (state, "failed") == 0;
}

static gboolean
deployment_mode_is_valid (const gchar *mode)
{
  return g_strcmp0 (mode, "production") == 0
      || g_strcmp0 (mode, "development") == 0 || g_strcmp0 (mode, "demo") == 0;
}

gboolean
wyl_policy_store_tenant_id_is_valid (const gchar *tenant_id)
{
  if (tenant_id == NULL || tenant_id[0] == '\0')
    return FALSE;

  for (const gchar * p = tenant_id; *p != '\0'; p++) {
    if (g_ascii_isspace (*p) || g_ascii_iscntrl (*p) || *p == '/')
      return FALSE;
  }
  return TRUE;
}

/* Subject-id validator for the bootstrap-admin marker. Stricter than
 * the tenant-id validator because the bootstrap admin string is parsed
 * out of an operator-supplied flag and is then granted system-admin
 * role membership: no whitespace, no control bytes, no Unicode high
 * bytes, no path separators. Length 3..128 bytes; charset is ASCII
 * alphanumerics plus '.', '_', ':' and '-'. */
static gboolean
bootstrap_admin_subject_is_valid (const gchar *s)
{
  if (s == NULL)
    return FALSE;

  gsize len = strlen (s);
  if (len < 3 || len > 128)
    return FALSE;

  for (const gchar * p = s; *p != '\0'; p++) {
    guchar c = (guchar) * p;
    if (g_ascii_isalnum (c))
      continue;
    if (c == '.' || c == '_' || c == ':' || c == '-')
      continue;
    return FALSE;
  }
  return TRUE;
}

static gboolean
path_is_memory_db (const gchar *path)
{
  return path == NULL || path[0] == '\0' || g_strcmp0 (path, ":memory:") == 0;
}

static void
policy_store_zero_key_material (wyl_policy_store_t *store)
{
  if (store == NULL)
    return;
  sodium_memzero (store->encryption_key, sizeof store->encryption_key);
  sodium_memzero (store->encryption_key_id, sizeof store->encryption_key_id);
  store->key_materialized = FALSE;
}

static void
owned_keyprovider_release (WylOwnedKeyProvider *provider)
{
  if (provider == NULL || !provider->owned)
    return;
  gpointer state = provider->state;
  void (*wipe) (gpointer state) = provider->vtable.wipe;
  void (*state_free) (gpointer state) = provider->state_free;
  memset (provider, 0, sizeof *provider);
  if (state != NULL && wipe != NULL)
    wipe (state);
  if (state != NULL && state_free != NULL)
    state_free (state);
}

static void
owned_keyprovider_adopt (WylOwnedKeyProvider *provider,
    const wyl_policy_store_open_options_t *opts)
{
  g_return_if_fail (provider != NULL);
  g_return_if_fail (opts != NULL);
  owned_keyprovider_release (provider);
  if (opts->keyprovider_vtable == NULL && opts->keyprovider_state == NULL
      && opts->keyprovider_state_free == NULL)
    return;
  if (opts->keyprovider_vtable != NULL)
    provider->vtable = *opts->keyprovider_vtable;
  provider->state = opts->keyprovider_state;
  provider->state_free = opts->keyprovider_state_free;
  provider->owned = TRUE;
}

static void
owned_keyprovider_move (WylOwnedKeyProvider *destination,
    WylOwnedKeyProvider *source)
{
  g_return_if_fail (destination != NULL);
  g_return_if_fail (source != NULL);
  if (destination == source)
    return;
  owned_keyprovider_release (destination);
  *destination = *source;
  memset (source, 0, sizeof *source);
}

static wyrelog_error_t
owned_keyprovider_validate (const WylOwnedKeyProvider *provider)
{
  if (provider == NULL)
    return WYRELOG_E_INVALID;
  if (!provider->owned)
    return WYRELOG_E_OK;
  if (provider->state == NULL || provider->vtable.probe == NULL
      || provider->vtable.seal == NULL || provider->vtable.unseal == NULL
      || provider->vtable.derive == NULL || provider->vtable.wipe == NULL
      || provider->vtable.clear_sealed_blob == NULL)
    return WYRELOG_E_INVALID;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
owned_keyprovider_probe (WylOwnedKeyProvider *provider)
{
  if (provider == NULL || !provider->owned)
    return WYRELOG_E_OK;
  return provider->vtable.probe (provider->state);
}

static wyrelog_error_t
materialize_store_key (wyl_policy_store_t *store,
    WylOwnedKeyProvider *provider, gboolean require_encrypted)
{
  if (store == NULL || provider == NULL)
    return WYRELOG_E_INVALID;

  if (!require_encrypted) {
    store->encrypted = FALSE;
    store->key_materialized = FALSE;
    return WYRELOG_E_OK;
  }

  if (sodium_init () < 0)
    return WYRELOG_E_CRYPTO;

  if (!provider->owned)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = provider->vtable.derive (provider->state,
      WYL_POLICY_STORE_ENCRYPTION_LABEL, store->encryption_key,
      WYL_POLICY_STORE_KEY_LEN);
  if (rc != WYRELOG_E_OK)
    return rc;

  if (crypto_generichash (store->encryption_key_id, WYL_POLICY_STORE_KEY_ID_LEN,
          store->encryption_key, sizeof store->encryption_key, NULL, 0) != 0)
    return WYRELOG_E_CRYPTO;

  store->encrypted = TRUE;
  store->key_materialized = TRUE;
  return WYRELOG_E_OK;
}

#ifdef G_OS_WIN32
/* TOCTOU mitigation for Windows: probe the final path component with
 * FILE_FLAG_OPEN_REPARSE_POINT so a symlink or junction at that
 * position is opened as itself rather than transparently followed.
 * The handle is closed immediately after the attribute check; the
 * read/write helpers below perform their own handle-based reparse
 * validation for each Wyrelog-owned operation. This does not pin
 * SQLite's later pathname-derived VFS opens.
 *
 * Return contract mirrors the POSIX reject_if_symlink + open pair:
 *   WYRELOG_E_OK         -- regular file present, safe to proceed
 *   WYRELOG_E_NOT_FOUND  -- canonical absent (legitimate fresh-store)
 *   WYRELOG_E_POLICY     -- reparse point present, refuse to follow
 *   WYRELOG_E_IO         -- attribute query failed for another reason
 */
static wyrelog_error_t
reject_reparse_point_win32 (const gchar *path)
{
  if (path == NULL || path[0] == '\0')
    return WYRELOG_E_INVALID;

  GError *err = NULL;
  wchar_t *wpath = (wchar_t *) g_utf8_to_utf16 (path, -1, NULL, NULL, &err);
  if (wpath == NULL) {
    g_clear_error (&err);
    return WYRELOG_E_INVALID;
  }

  HANDLE h = CreateFileW (wpath, FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      OPEN_EXISTING,
      FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
  /* Capture LastError BEFORE g_free: the Windows CRT free() forwards
   * to HeapFree which does not document last-error preservation, so a
   * deferred GetLastError() after free can return a stale or
   * irrelevant code (observed in CI as a non-ENOENT classification of
   * a legitimate fresh-store path). */
  DWORD last_err = (h == INVALID_HANDLE_VALUE) ? GetLastError () : 0;
  g_free (wpath);
  if (h == INVALID_HANDLE_VALUE) {
    if (last_err == ERROR_FILE_NOT_FOUND || last_err == ERROR_PATH_NOT_FOUND)
      return WYRELOG_E_NOT_FOUND;
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "policy store CreateFileW attribute probe failed");
    return WYRELOG_E_IO;
  }

  BY_HANDLE_FILE_INFORMATION info;
  BOOL ok = GetFileInformationByHandle (h, &info);
  CloseHandle (h);
  if (!ok)
    return WYRELOG_E_IO;
  if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "policy store refused reparse point at canonical path");
    return WYRELOG_E_POLICY;
  }
  return WYRELOG_E_OK;
}

/* Read the entire file at path through a CreateFileW handle that
 * carries FILE_FLAG_OPEN_REPARSE_POINT, then ReadFile via that same
 * handle. This pins the inode for the duration of the read so a
 * same-user attacker cannot swap canonical to a symlink between the
 * open-time probe and the read.
 *
 * If the file does not exist (legitimate fresh-store case), returns
 * WYRELOG_E_NOT_FOUND so the caller can distinguish from a real I/O
 * failure -- parallels the POSIX read_through_dirfd contract. */
static wyrelog_error_t
read_whole_file (const gchar *path, guint8 **out_bytes, gsize *out_len)
{
  if (path == NULL || out_bytes == NULL || out_len == NULL)
    return WYRELOG_E_INVALID;
  *out_bytes = NULL;
  *out_len = 0;

  wchar_t *wpath = (wchar_t *) g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  if (wpath == NULL)
    return WYRELOG_E_INVALID;

  /* FILE_SHARE_READ|WRITE|DELETE matches the share mode sqlite uses
   * for the work-path handle and the share mode glib's
   * g_file_get_contents uses internally. Restricting to FILE_SHARE_READ
   * alone produced ERROR_SHARING_VIOLATION on the close-time persist
   * path because sqlite still holds the work-path file open for
   * read+write when read_whole_file is invoked from
   * persist_policy_store_encrypted. */
  HANDLE h = CreateFileW (wpath, GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  /* See reject_reparse_point_win32 for why LastError is captured
   * before g_free rather than after. */
  DWORD last_err = (h == INVALID_HANDLE_VALUE) ? GetLastError () : 0;
  g_free (wpath);
  if (h == INVALID_HANDLE_VALUE) {
    if (last_err == ERROR_FILE_NOT_FOUND || last_err == ERROR_PATH_NOT_FOUND)
      return WYRELOG_E_NOT_FOUND;
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "policy store CreateFileW for read failed");
    return WYRELOG_E_IO;
  }

  BY_HANDLE_FILE_INFORMATION info;
  if (!GetFileInformationByHandle (h, &info)) {
    CloseHandle (h);
    return WYRELOG_E_IO;
  }
  if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
    CloseHandle (h);
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "policy store refused reparse point during read");
    return WYRELOG_E_POLICY;
  }
  if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
    CloseHandle (h);
    return WYRELOG_E_POLICY;
  }

  LARGE_INTEGER fsize;
  if (!GetFileSizeEx (h, &fsize) || fsize.QuadPart < 0
      || (guint64) fsize.QuadPart > (guint64) G_MAXSIZE) {
    CloseHandle (h);
    return WYRELOG_E_IO;
  }
  gsize len = (gsize) fsize.QuadPart;
  guint8 *buf = g_malloc (len > 0 ? len : 1);
  gsize total = 0;
  while (total < len) {
    /* 64 KiB cap per ReadFile call. Earlier revisions used a single
     * call sized to the full payload and were observed to wedge on
     * hosted GitHub Actions Windows runners around 288 KiB; bounded
     * chunks keep each syscall short. */
    gsize remain = len - total;
    DWORD chunk = remain > 0x10000 ? 0x10000 : (DWORD) remain;
    DWORD got = 0;
    if (!ReadFile (h, buf + total, chunk, &got, NULL)) {
      g_free (buf);
      CloseHandle (h);
      WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
          "policy store ReadFile from canonical handle failed");
      return WYRELOG_E_IO;
    }
    if (got == 0)
      break;
    total += got;
  }
  CloseHandle (h);
  if (total != len) {
    g_free (buf);
    return WYRELOG_E_IO;
  }
  *out_bytes = buf;
  *out_len = len;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
write_whole_file_atomic_private (const gchar *path, const guint8 *bytes,
    gsize len, const wyl_policy_store_rotation_runtime_t *rotation_runtime,
    gboolean *out_replaced)
{
  if (out_replaced != NULL)
    *out_replaced = FALSE;
  if (path == NULL || path[0] == '\0' || (bytes == NULL && len > 0))
    return WYRELOG_E_INVALID;

  /* Algorithm parallels the POSIX write_through_dirfd: write a sibling
   * temp file via CreateFileW with FILE_FLAG_OPEN_REPARSE_POINT and
   * CREATE_NEW (refuses to clobber an existing reparse point left
   * by a same-uid attacker), flush, then MoveFileExW onto the
   * canonical name. MOVEFILE_WRITE_THROUGH stands in for the dirfd
   * fsync on POSIX so the directory-entry rewrite is durable across
   * crash. The destination is re-probed immediately before the move
   * to refuse following a freshly-planted reparse point. */
  g_autofree gchar *tmp_path = g_strdup_printf ("%s%s", path,
      WYL_POLICY_STORE_TMP_SUFFIX);
  wchar_t *wtmp = (wchar_t *) g_utf8_to_utf16 (tmp_path, -1, NULL, NULL, NULL);
  wchar_t *wdst = (wchar_t *) g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  if (wtmp == NULL || wdst == NULL) {
    g_free (wtmp);
    g_free (wdst);
    return WYRELOG_E_INVALID;
  }

  (void) DeleteFileW (wtmp);

  HANDLE h = CreateFileW (wtmp, GENERIC_WRITE, 0, NULL, CREATE_NEW,
      FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (h == INVALID_HANDLE_VALUE) {
    g_free (wtmp);
    g_free (wdst);
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "policy store CreateFileW for tmp write failed");
    return WYRELOG_E_IO;
  }

  BY_HANDLE_FILE_INFORMATION info;
  if (!GetFileInformationByHandle (h, &info)
      || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
    CloseHandle (h);
    (void) DeleteFileW (wtmp);
    g_free (wtmp);
    g_free (wdst);
    return WYRELOG_E_POLICY;
  }

  gsize total = 0;
  while (total < len) {
    gsize remain = len - total;
    DWORD chunk = remain > 0x10000 ? 0x10000 : (DWORD) remain;
    DWORD put = 0;
    if (!WriteFile (h, bytes + total, chunk, &put, NULL) || put == 0) {
      CloseHandle (h);
      (void) DeleteFileW (wtmp);
      g_free (wtmp);
      g_free (wdst);
      WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
          "policy store WriteFile to tmp failed");
      return WYRELOG_E_IO;
    }
    total += put;
  }

  if (!FlushFileBuffers (h)) {
    CloseHandle (h);
    (void) DeleteFileW (wtmp);
    g_free (wtmp);
    g_free (wdst);
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "policy store FlushFileBuffers of tmp failed");
    return WYRELOG_E_IO;
  }
  if (!CloseHandle (h)) {
    (void) DeleteFileW (wtmp);
    g_free (wtmp);
    g_free (wdst);
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "policy store CloseHandle of tmp failed");
    return WYRELOG_E_IO;
  }

  DWORD dst_attrs = GetFileAttributesW (wdst);
  if (dst_attrs != INVALID_FILE_ATTRIBUTES
      && (dst_attrs & FILE_ATTRIBUTE_REPARSE_POINT)) {
    (void) DeleteFileW (wtmp);
    g_free (wtmp);
    g_free (wdst);
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "policy store refused reparse point at canonical before rename");
    return WYRELOG_E_POLICY;
  }

  if (rotation_runtime != NULL && rotation_runtime->checkpoint != NULL
      && rotation_runtime->checkpoint (rotation_runtime->data,
          WYL_POLICY_ROTATION_BEFORE_CANONICAL_RENAME) != 0) {
    (void) DeleteFileW (wtmp);
    g_free (wtmp);
    g_free (wdst);
    return WYRELOG_E_IO;
  }

  BOOL moved = MoveFileExW (wtmp, wdst,
      MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
  g_free (wtmp);
  g_free (wdst);
  if (!moved) {
    (void) g_remove (tmp_path);
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "policy store MoveFileExW onto canonical failed");
    return WYRELOG_E_IO;
  }

  if (out_replaced != NULL)
    *out_replaced = TRUE;
  if (rotation_runtime != NULL && rotation_runtime->checkpoint != NULL
      && rotation_runtime->checkpoint (rotation_runtime->data,
          WYL_POLICY_ROTATION_AFTER_CANONICAL_RENAME) != 0)
    WYL_LOG_WARN (WYL_LOG_SECTION_BOOT,
        "policy store canonical replacement completed with a durability warning");

  (void) g_chmod (path, 0600);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
write_plaintext_work_file (const gchar *path, const guint8 *bytes, gsize len)
{
  return write_whole_file_atomic_private (path, bytes, len, NULL, NULL);
}
#endif /* G_OS_WIN32 */

#define WYL_POLICY_ROTATION_INTENT_MAGIC "WYLROT1\0"
#define WYL_POLICY_ROTATION_INTENT_MAGIC_LEN 8u
#define WYL_POLICY_ROTATION_INTENT_AUTH_LEN crypto_generichash_BYTES
#define WYL_POLICY_ROTATION_INTENT_WIRE_LEN \
  (WYL_POLICY_ROTATION_INTENT_MAGIC_LEN + 1u + 1u + 2u + WYL_ID_BYTES \
   + (crypto_generichash_BYTES * 3u) + (sizeof (guint64) * 2u) \
   + WYL_POLICY_ROTATION_INTENT_AUTH_LEN)

static gboolean
rotation_intent_bytes_nonzero (const guint8 *bytes, gsize len)
{
  guint8 acc = 0;
  for (gsize i = 0; i < len; i++)
    acc |= bytes[i];
  return acc != 0;
}

static wyrelog_error_t
rotation_intent_validate (const WylPolicyRotationIntent *intent)
{
  if (intent == NULL || wyl_id_equal (&intent->transaction_id, &WYL_ID_NIL)
      || !rotation_intent_bytes_nonzero (intent->canonical_digest,
          sizeof intent->canonical_digest)
      || !rotation_intent_bytes_nonzero (intent->old_provider_id,
          sizeof intent->old_provider_id)
      || !rotation_intent_bytes_nonzero (intent->new_provider_id,
          sizeof intent->new_provider_id)
      || memcmp (intent->old_provider_id, intent->new_provider_id,
          sizeof intent->old_provider_id) == 0
      || intent->expected_new_generation != intent->old_generation + 1
      || (intent->state != WYL_POLICY_ROTATION_INTENT_PENDING
          && intent->state != WYL_POLICY_ROTATION_INTENT_COMMITTED))
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_rotation_intent_derive_auth_key (const wyl_policy_store_t *store,
    guint8 *out_key, gsize out_key_len)
{
  if (out_key == NULL)
    return WYRELOG_E_INVALID;
  sodium_memzero (out_key, out_key_len);
  if (out_key_len != crypto_generichash_KEYBYTES)
    return WYRELOG_E_INVALID;
  if (store == NULL || !store->encrypted || !store->key_materialized)
    return WYRELOG_E_POLICY;
  if (crypto_generichash (out_key, out_key_len,
          (const guint8 *) WYL_POLICY_ROTATION_INTENT_AUTH_LABEL,
          sizeof (WYL_POLICY_ROTATION_INTENT_AUTH_LABEL) - 1,
          store->encryption_key, sizeof store->encryption_key) != 0) {
    sodium_memzero (out_key, out_key_len);
    return WYRELOG_E_CRYPTO;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_rotation_intent_encode (const WylPolicyRotationIntent *intent,
    const guint8 *auth_key, gsize auth_key_len, guint8 **out_bytes,
    gsize *out_len)
{
  if (out_bytes != NULL)
    *out_bytes = NULL;
  if (out_len != NULL)
    *out_len = 0;
  if (out_bytes == NULL || out_len == NULL || auth_key == NULL
      || auth_key_len != crypto_generichash_KEYBYTES
      || rotation_intent_validate (intent) != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;

  guint8 *wire = g_malloc0 (WYL_POLICY_ROTATION_INTENT_WIRE_LEN);
  if (wire == NULL)
    return WYRELOG_E_NOMEM;
  gsize offset = 0;
  memcpy (wire + offset, WYL_POLICY_ROTATION_INTENT_MAGIC,
      WYL_POLICY_ROTATION_INTENT_MAGIC_LEN);
  offset += WYL_POLICY_ROTATION_INTENT_MAGIC_LEN;
  wire[offset++] = WYL_POLICY_ROTATION_INTENT_VERSION;
  wire[offset++] = (guint8) intent->state;
  offset += 2;
  memcpy (wire + offset, intent->transaction_id.bytes, WYL_ID_BYTES);
  offset += WYL_ID_BYTES;
  memcpy (wire + offset, intent->canonical_digest,
      sizeof intent->canonical_digest);
  offset += sizeof intent->canonical_digest;
  memcpy (wire + offset, intent->old_provider_id,
      sizeof intent->old_provider_id);
  offset += sizeof intent->old_provider_id;
  memcpy (wire + offset, intent->new_provider_id,
      sizeof intent->new_provider_id);
  offset += sizeof intent->new_provider_id;
  guint64 old_generation = GUINT64_TO_BE (intent->old_generation);
  guint64 new_generation = GUINT64_TO_BE (intent->expected_new_generation);
  memcpy (wire + offset, &old_generation, sizeof old_generation);
  offset += sizeof old_generation;
  memcpy (wire + offset, &new_generation, sizeof new_generation);
  offset += sizeof new_generation;
  if (crypto_generichash (wire + offset, WYL_POLICY_ROTATION_INTENT_AUTH_LEN,
          wire, offset, auth_key, crypto_generichash_KEYBYTES) != 0) {
    sodium_memzero (wire, WYL_POLICY_ROTATION_INTENT_WIRE_LEN);
    g_free (wire);
    return WYRELOG_E_CRYPTO;
  }
  *out_bytes = wire;
  *out_len = WYL_POLICY_ROTATION_INTENT_WIRE_LEN;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_rotation_intent_decode (const guint8 *bytes, gsize len,
    const guint8 *auth_key, gsize auth_key_len,
    WylPolicyRotationIntent *out_intent)
{
  if (out_intent != NULL)
    memset (out_intent, 0, sizeof *out_intent);
  if (bytes == NULL || auth_key == NULL
      || auth_key_len != crypto_generichash_KEYBYTES || out_intent == NULL
      || len != WYL_POLICY_ROTATION_INTENT_WIRE_LEN
      || memcmp (bytes, WYL_POLICY_ROTATION_INTENT_MAGIC,
          WYL_POLICY_ROTATION_INTENT_MAGIC_LEN) != 0
      || bytes[WYL_POLICY_ROTATION_INTENT_MAGIC_LEN]
      != WYL_POLICY_ROTATION_INTENT_VERSION
      || bytes[WYL_POLICY_ROTATION_INTENT_MAGIC_LEN + 2] != 0
      || bytes[WYL_POLICY_ROTATION_INTENT_MAGIC_LEN + 3] != 0)
    return WYRELOG_E_POLICY;
  guint8 expected_auth[WYL_POLICY_ROTATION_INTENT_AUTH_LEN];
  gsize body_len = len - WYL_POLICY_ROTATION_INTENT_AUTH_LEN;
  if (crypto_generichash (expected_auth, sizeof expected_auth, bytes, body_len,
          auth_key, crypto_generichash_KEYBYTES) != 0
      || sodium_memcmp (expected_auth, bytes + body_len,
          sizeof expected_auth) != 0) {
    sodium_memzero (expected_auth, sizeof expected_auth);
    return WYRELOG_E_POLICY;
  }
  sodium_memzero (expected_auth, sizeof expected_auth);
  gsize offset = WYL_POLICY_ROTATION_INTENT_MAGIC_LEN + 4;
  memcpy (out_intent->transaction_id.bytes, bytes + offset, WYL_ID_BYTES);
  offset += WYL_ID_BYTES;
  memcpy (out_intent->canonical_digest, bytes + offset,
      sizeof out_intent->canonical_digest);
  offset += sizeof out_intent->canonical_digest;
  memcpy (out_intent->old_provider_id, bytes + offset,
      sizeof out_intent->old_provider_id);
  offset += sizeof out_intent->old_provider_id;
  memcpy (out_intent->new_provider_id, bytes + offset,
      sizeof out_intent->new_provider_id);
  offset += sizeof out_intent->new_provider_id;
  guint64 old_generation = 0;
  guint64 new_generation = 0;
  memcpy (&old_generation, bytes + offset, sizeof old_generation);
  offset += sizeof old_generation;
  memcpy (&new_generation, bytes + offset, sizeof new_generation);
  out_intent->old_generation = GUINT64_FROM_BE (old_generation);
  out_intent->expected_new_generation = GUINT64_FROM_BE (new_generation);
  out_intent->state =
      (WylPolicyRotationIntentState) bytes[WYL_POLICY_ROTATION_INTENT_MAGIC_LEN
      + 1];
  if (rotation_intent_validate (out_intent) != WYRELOG_E_OK) {
    memset (out_intent, 0, sizeof *out_intent);
    return WYRELOG_E_POLICY;
  }
  return WYRELOG_E_OK;
}

#define WYL_POLICY_ROTATION_INTENT_SUFFIX ".wyrelog-rotation-intent"

#ifndef G_OS_WIN32
static wyrelog_error_t read_through_dirfd (int dirfd, const gchar * basename,
    guint8 ** out_bytes, gsize * out_len);
static wyrelog_error_t write_through_dirfd (int dirfd, const gchar * basename,
    const guint8 * bytes, gsize len,
    const wyl_policy_store_rotation_runtime_t * rotation_runtime,
    gboolean * out_replaced);
#endif

static wyrelog_error_t
rotation_intent_sidecar_path (const wyl_policy_store_t *store,
    gchar **out_path, gchar **out_basename)
{
  if (out_path != NULL)
    *out_path = NULL;
  if (out_basename != NULL)
    *out_basename = NULL;
  if (store == NULL || store->canonical_path == NULL
      || store->canonical_path[0] == '\0')
    return WYRELOG_E_INVALID;
#ifdef G_OS_WIN32
  if (out_path == NULL)
    return WYRELOG_E_INVALID;
  *out_path = g_strconcat (store->canonical_path,
      WYL_POLICY_ROTATION_INTENT_SUFFIX, NULL);
#else
  if (store->canonical_dirfd < 0 || store->canonical_basename == NULL
      || out_basename == NULL)
    return WYRELOG_E_POLICY;
  *out_basename = g_strconcat (store->canonical_basename,
      WYL_POLICY_ROTATION_INTENT_SUFFIX, NULL);
#endif
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_rotation_intent_write_sidecar (wyl_policy_store_t *store,
    const WylPolicyRotationIntent *intent, const guint8 *auth_key,
    gsize auth_key_len)
{
  guint8 *wire = NULL;
  gsize wire_len = 0;
  wyrelog_error_t rc = wyl_policy_rotation_intent_encode (intent, auth_key,
      auth_key_len, &wire, &wire_len);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *path = NULL;
  g_autofree gchar *basename = NULL;
  rc = rotation_intent_sidecar_path (store, &path, &basename);
  if (rc == WYRELOG_E_OK) {
#ifdef G_OS_WIN32
    rc = write_whole_file_atomic_private (path, wire, wire_len, NULL, NULL);
#else
    rc = write_through_dirfd (store->canonical_dirfd, basename, wire,
        wire_len, NULL, NULL);
#endif
  }
  sodium_memzero (wire, wire_len);
  g_free (wire);
  return rc;
}

void wyl_policy_service_handoff_disposition_result_clear
    (WylPolicyServiceHandoffDispositionResult * result)
{
  if (result == NULL)
    return;
  g_clear_pointer (&result->disposition_id, g_free);
  g_clear_pointer (&result->audit_id, g_free);
  memset (result, 0, sizeof *result);
}

void wyl_policy_service_handoff_cancellation_result_clear
    (WylPolicyServiceHandoffCancellationResult * result)
{
  if (result == NULL)
    return;
  g_clear_pointer (&result->disposition_id, g_free);
  g_clear_pointer (&result->audit_id, g_free);
  memset (result, 0, sizeof *result);
}

void wyl_policy_service_handoff_remediation_result_clear
    (WylPolicyServiceHandoffRemediationResult * result)
{
  if (result == NULL)
    return;
  g_clear_pointer (&result->audit_id, g_free);
  g_clear_pointer (&result->remediation_request_id, g_free);
  g_clear_pointer (&result->decision_request_id, g_free);
  g_clear_pointer (&result->current_actor_subject_id, g_free);
  g_clear_pointer (&result->original_request_id, g_free);
  g_clear_pointer (&result->original_actor_subject_id, g_free);
  g_clear_pointer (&result->source_disposition_id, g_free);
  g_clear_pointer (&result->source_audit_id, g_free);
  g_clear_pointer (&result->revoke_event_request_id, g_free);
  g_clear_pointer (&result->revoke_event_actor_subject_id, g_free);
  memset (result, 0, sizeof *result);
}

void
wyl_policy_store_service_handoff_fail_once (wyl_policy_store_t *store,
    WylPolicyServiceHandoffFailStage stage)
{
  if (store != NULL)
    store->service_handoff_fail_once = stage;
}

static gboolean
service_handoff_should_fail (wyl_policy_store_t *store,
    WylPolicyServiceHandoffFailStage stage)
{
  if (store->service_handoff_fail_once != stage)
    return FALSE;
  store->service_handoff_fail_once = WYL_POLICY_HANDOFF_FAIL_NONE;
  return TRUE;
}

static gboolean
service_handoff_uuid_is_canonical (const gchar *value)
{
  wyl_id_t parsed;
  gchar canonical[WYL_ID_STRING_BUF];
  return value != NULL && wyl_id_parse (value, &parsed) == WYRELOG_E_OK
      && wyl_id_format (&parsed, canonical, sizeof canonical) == WYRELOG_E_OK
      && g_str_equal (value, canonical);
}

static wyrelog_error_t
service_handoff_sqlite_error (sqlite3 *db, int sqlite_rc)
{
  int primary = sqlite_rc & 0xff;
  if (primary == SQLITE_NOMEM)
    return WYRELOG_E_NOMEM;
  if (primary == SQLITE_CONSTRAINT)
    return WYRELOG_E_POLICY;
  if (primary == SQLITE_OK || primary == SQLITE_ROW || primary == SQLITE_DONE)
    return WYRELOG_E_OK;
  (void) db;
  return WYRELOG_E_IO;
}

static wyrelog_error_t
service_handoff_map_sqlite_io (sqlite3 *db, wyrelog_error_t rc)
{
  return rc == WYRELOG_E_IO ? service_handoff_sqlite_error (db,
      sqlite3_extended_errcode (db)) : rc;
}

wyrelog_error_t
wyl_policy_store_service_handoff_sqlite_error_for_test (int sqlite_rc)
{
  return service_handoff_sqlite_error (NULL, sqlite_rc);
}

static gboolean
    service_handoff_no_commit_evidence_shape_valid
    (const WylPolicyServiceHandoffNoCommitEvidence * evidence)
{
  if (evidence == NULL || evidence->target_a == NULL)
    return FALSE;
  return (evidence->operation == WYL_POLICY_HANDOFF_FENCE_ISSUE
      && wyl_policy_service_subject_is_valid (evidence->target_a,
          strlen (evidence->target_a)) && evidence->target_b != NULL
      && wyl_policy_store_tenant_id_is_valid (evidence->target_b))
      || (evidence->operation == WYL_POLICY_HANDOFF_FENCE_ROTATE
      && evidence->target_b == NULL
      && wyl_service_credential_id_is_canonical (evidence->target_a,
          strlen (evidence->target_a)));
}

static const gchar *
service_handoff_reason_name (WylPolicyServiceHandoffDispositionReason reason)
{
  switch (reason) {
    case WYL_POLICY_HANDOFF_DISPOSITION_NOT_COMMITTED:
      return "not_committed";
    case WYL_POLICY_HANDOFF_DISPOSITION_OPERATION_EXPIRED:
      return "operation_expired";
    case WYL_POLICY_HANDOFF_DISPOSITION_OPERATION_CANCELLED:
      return "operation_cancelled";
    case WYL_POLICY_HANDOFF_DISPOSITION_SUCCESSOR_EXPIRED:
      return "successor_expired";
    case WYL_POLICY_HANDOFF_DISPOSITION_SUCCESSOR_REVOKED:
      return "successor_revoked";
    case WYL_POLICY_HANDOFF_DISPOSITION_DELIVERED:
      return "delivered";
    default:
      return NULL;
  }
}

static const gchar *
service_handoff_outcome_name (WylPolicyServiceHandoffDispositionOutcome outcome)
{
  switch (outcome) {
    case WYL_POLICY_HANDOFF_OUTCOME_TERMINAL_NOT_COMMITTED:
      return "terminal_not_committed";
    case WYL_POLICY_HANDOFF_OUTCOME_ATTENTION_REQUIRED:
      return "attention_required";
    case WYL_POLICY_HANDOFF_OUTCOME_OPERATOR_ACTION_REQUIRED:
      return "operator_action_required";
    case WYL_POLICY_HANDOFF_OUTCOME_ESCROW_DELETED:
      return "escrow_deleted";
    default:
      return NULL;
  }
}

static gboolean
    service_handoff_disposition_shape_valid
    (const WylPolicyServiceHandoffDispositionInput * input)
{
  if (input == NULL || !service_handoff_uuid_is_canonical
      (input->disposition_id) || !service_handoff_uuid_is_canonical
      (input->audit_id)
      || !wyl_policy_service_actor_subject_is_valid (input->actor_subject_id)
      || !service_handoff_exact_tuple_is_valid (&input->tuple))
    return FALSE;
  if (input->reason == WYL_POLICY_HANDOFF_DISPOSITION_NOT_COMMITTED)
    return input->outcome ==
        WYL_POLICY_HANDOFF_OUTCOME_TERMINAL_NOT_COMMITTED
        && input->tuple.successor_credential_id == NULL
        && service_handoff_no_commit_evidence_shape_valid
        (input->no_commit_evidence);
  if (input->tuple.successor_credential_id == NULL)
    return FALSE;
  if (input->reason == WYL_POLICY_HANDOFF_DISPOSITION_DELIVERED)
    return input->outcome == WYL_POLICY_HANDOFF_OUTCOME_ESCROW_DELETED
        && input->no_commit_evidence == NULL;
  if (input->no_commit_evidence != NULL)
    return FALSE;
  return ((input->reason == WYL_POLICY_HANDOFF_DISPOSITION_OPERATION_EXPIRED
          || input->reason ==
          WYL_POLICY_HANDOFF_DISPOSITION_OPERATION_CANCELLED)
      && input->outcome == WYL_POLICY_HANDOFF_OUTCOME_ATTENTION_REQUIRED)
      || ((input->reason ==
          WYL_POLICY_HANDOFF_DISPOSITION_SUCCESSOR_EXPIRED
          || input->reason == WYL_POLICY_HANDOFF_DISPOSITION_SUCCESSOR_REVOKED)
      && input->outcome == WYL_POLICY_HANDOFF_OUTCOME_OPERATOR_ACTION_REQUIRED);
}

static wyrelog_error_t
service_handoff_hash_fields (const gchar *domain,
    const gchar *const *fields, gsize n_fields,
    guint8 out[crypto_generichash_BYTES])
{
  crypto_generichash_state state;
  if (crypto_generichash_init (&state, NULL, 0, crypto_generichash_BYTES) != 0
      || crypto_generichash_update (&state, (const guint8 *) domain,
          strlen (domain)) != 0)
    return WYRELOG_E_CRYPTO;
  static const guint8 separator = 0;
  for (gsize i = 0; i < n_fields; i++)
    if (crypto_generichash_update (&state, (const guint8 *) fields[i],
            strlen (fields[i])) != 0
        || crypto_generichash_update (&state, &separator, 1) != 0) {
      sodium_memzero (&state, sizeof state);
      return WYRELOG_E_CRYPTO;
    }
  int failed = crypto_generichash_final (&state, out,
      crypto_generichash_BYTES);
  sodium_memzero (&state, sizeof state);
  return failed == 0 ? WYRELOG_E_OK : WYRELOG_E_CRYPTO;
}

static wyrelog_error_t
service_handoff_append_audit_strict (wyl_policy_store_t *store,
    const gchar *audit_id, gint64 now_us, const gchar *actor_subject_id,
    const gchar *action, const gchar *resource_id, const gchar *request_id)
{
  gboolean inserted = FALSE;
  wyrelog_error_t rc = wyl_policy_store_append_audit_event_full (store,
      audit_id, now_us, actor_subject_id, action, resource_id, NULL, NULL,
      request_id, WYL_DECISION_ALLOW, &inserted);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!inserted)
    return WYRELOG_E_POLICY;
  inserted = FALSE;
  rc = wyl_policy_store_record_audit_intention_full (store, audit_id,
      now_us, actor_subject_id, action, resource_id, NULL, NULL, request_id,
      WYL_DECISION_ALLOW, &inserted);
  rc = rc != WYRELOG_E_OK ? rc : (inserted ? WYRELOG_E_OK : WYRELOG_E_POLICY);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
    service_handoff_disposition_semantic_key
    (const WylPolicyServiceHandoffDispositionInput * input,
    guint8 out[crypto_generichash_BYTES])
{
  gchar escrow[WYL_ID_STRING_BUF];
  gchar generation[32];
  gchar binding[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES * 2 + 1];
  guint8 proof_digest[WYL_POLICY_STORE_OPERATION_FINGERPRINT_BYTES] = { 0 };
  gchar proof_hex[WYL_POLICY_STORE_OPERATION_FINGERPRINT_BYTES * 2 + 1] = "";
  const gchar *proof_tag = "none";
  if (wyl_id_format (input->tuple.escrow_id, escrow, sizeof escrow)
      != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  g_snprintf (generation, sizeof generation, "%" G_GUINT64_FORMAT,
      input->tuple.successor_issuance_generation);
  sodium_bin2hex (binding, sizeof binding, input->tuple.binding_digest,
      sizeof input->tuple.binding_digest);
  if (input->reason == WYL_POLICY_HANDOFF_DISPOSITION_NOT_COMMITTED) {
    const WylPolicyServiceHandoffNoCommitEvidence *evidence =
        input->no_commit_evidence;
    if (!service_handoff_no_commit_evidence_shape_valid (evidence))
      return WYRELOG_E_INVALID;
    if (!sodium_is_zero (evidence->maintenance_proof_digest,
            sizeof evidence->maintenance_proof_digest)) {
      memcpy (proof_digest, evidence->maintenance_proof_digest,
          sizeof proof_digest);
      proof_tag = "not-committed-maintenance-v1";
    } else {
      WylServiceCredentialFenceOperation operation =
          evidence->operation == WYL_POLICY_HANDOFF_FENCE_ISSUE ?
          WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE :
          WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE;
      wyrelog_error_t rc =
          wyl_policy_store_service_credential_operation_fence_fingerprint
          (operation, evidence->target_a, strlen (evidence->target_a),
          evidence->target_b,
          evidence->target_b != NULL ? strlen (evidence->target_b) : 0,
          proof_digest);
      if (rc != WYRELOG_E_OK)
        return rc;
      proof_tag = "not-committed-fence-v1";
    }
    sodium_bin2hex (proof_hex, sizeof proof_hex, proof_digest,
        sizeof proof_digest);
  }
  const gchar *fields[] = {
    input->tuple.original_request_id,
    service_handoff_reason_name (input->reason),
    service_handoff_outcome_name (input->outcome), escrow, binding,
    input->tuple.successor_credential_id != NULL ?
        input->tuple.successor_credential_id : "", generation,
    proof_tag, proof_hex,
  };
  wyrelog_error_t rc = service_handoff_hash_fields
      ("wyrelog.service-handoff-disposition.v2", fields,
      G_N_ELEMENTS (fields), out);
  sodium_memzero (proof_digest, sizeof proof_digest);
  sodium_memzero (proof_hex, sizeof proof_hex);
  return rc;
}

static wyrelog_error_t
service_handoff_fill_disposition_result (const gchar *disposition_id,
    const gchar *audit_id, gint64 created_at_us, gboolean replayed,
    WylPolicyServiceHandoffDispositionResult *out)
{
  if (created_at_us <= 0)
    return WYRELOG_E_POLICY;
  out->disposition_id = service_handoff_try_strdup (disposition_id);
  out->audit_id = service_handoff_try_strdup (audit_id);
  if (out->disposition_id == NULL || out->audit_id == NULL) {
    wyl_policy_service_handoff_disposition_result_clear (out);
    return WYRELOG_E_NOMEM;
  }
  out->replayed = replayed;
  out->created_at_us = created_at_us;
  return WYRELOG_E_OK;
}

static wyrelog_error_t service_handoff_validate_exact_audit_pair
    (wyl_policy_store_t * store, const gchar * audit_id,
    gint64 created_at_us, const gchar * actor_subject_id,
    const gchar * action, const gchar * resource_id, const gchar * request_id);

static wyrelog_error_t
service_handoff_disposition_lookup_exact (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffDispositionInput *input,
    const guint8 semantic_key[crypto_generichash_BYTES], gboolean *out_found,
    WylPolicyServiceHandoffDispositionResult *out)
{
  *out_found = FALSE;
  gchar escrow[WYL_ID_STRING_BUF];
  wyl_id_format (input->tuple.escrow_id, escrow, sizeof escrow);
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT disposition_id,semantic_key,original_request_id,escrow_id,"
      "binding_digest,successor_credential_id,successor_issuance_generation,"
      "actor_subject_id,reason,outcome,audit_id,created_at_us FROM"
      " service_credential_handoff_dispositions WHERE semantic_key=? OR"
      " (original_request_id=? AND reason=? AND outcome=? AND escrow_id=?"
      " AND binding_digest=? AND coalesce(successor_credential_id,'')=?"
      " AND coalesce(successor_issuance_generation,0)=?) LIMIT 2;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  const gchar *reason = service_handoff_reason_name (input->reason);
  const gchar *outcome = service_handoff_outcome_name (input->outcome);
  if (rc == WYRELOG_E_OK
      && (sqlite3_bind_blob (stmt, 1, semantic_key, 32, SQLITE_TRANSIENT)
          != SQLITE_OK
          || (rc = bind_text (stmt, 2, input->tuple.original_request_id))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 3, reason))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 4, outcome))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 5, escrow))
          != WYRELOG_E_OK || sqlite3_bind_blob (stmt, 6,
              input->tuple.binding_digest, 32, SQLITE_TRANSIENT) != SQLITE_OK
          || (rc = bind_text (stmt, 7,
                  input->tuple.successor_credential_id != NULL ?
                  input->tuple.successor_credential_id : "")) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 8,
              (sqlite3_int64) input->tuple.successor_issuance_generation)
          != SQLITE_OK))
    rc = WYRELOG_E_IO;
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW) {
    *out_found = TRUE;
    const gchar *disposition_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *original_request_id = (const gchar *) sqlite3_column_text
        (stmt, 2);
    const gchar *stored_escrow = (const gchar *) sqlite3_column_text (stmt, 3);
    const gchar *successor = (const gchar *) sqlite3_column_text (stmt, 5);
    const gchar *actor = (const gchar *) sqlite3_column_text (stmt, 7);
    const gchar *stored_reason = (const gchar *) sqlite3_column_text (stmt, 8);
    const gchar *stored_outcome = (const gchar *) sqlite3_column_text (stmt, 9);
    const gchar *audit_id = (const gchar *) sqlite3_column_text (stmt, 10);
    gint64 stored_created_at_us = sqlite3_column_int64 (stmt, 11);
    gboolean exact = disposition_id != NULL && audit_id != NULL
        && g_strcmp0 (disposition_id, input->disposition_id) == 0
        && sqlite3_column_type (stmt, 1) == SQLITE_BLOB
        && sqlite3_column_bytes (stmt, 1) == 32
        && sodium_memcmp (sqlite3_column_blob (stmt, 1), semantic_key, 32) == 0
        && g_strcmp0 (original_request_id,
        input->tuple.original_request_id) == 0
        && g_strcmp0 (stored_escrow, escrow) == 0
        && sqlite3_column_type (stmt, 4) == SQLITE_BLOB
        && sqlite3_column_bytes (stmt, 4) == 32
        && sodium_memcmp (sqlite3_column_blob (stmt, 4),
        input->tuple.binding_digest, 32) == 0 && g_strcmp0 (successor,
        input->tuple.successor_credential_id) == 0
        && (guint64) sqlite3_column_int64 (stmt, 6) ==
        input->tuple.successor_issuance_generation
        && g_strcmp0 (actor, input->actor_subject_id) == 0
        && g_strcmp0 (stored_reason, reason) == 0
        && g_strcmp0 (stored_outcome, outcome) == 0
        && g_strcmp0 (audit_id, input->audit_id) == 0
        && sqlite3_column_type (stmt, 11) == SQLITE_INTEGER
        && stored_created_at_us > 0;
    rc = exact ? service_handoff_validate_exact_audit_pair (store, audit_id,
        stored_created_at_us, actor,
        "service.credential.handoff.disposition", original_request_id,
        original_request_id) : WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK)
      rc = service_handoff_fill_disposition_result (disposition_id, audit_id,
          stored_created_at_us, TRUE, out);
    if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
      rc = WYRELOG_E_POLICY;
  } else if (rc == WYRELOG_E_OK && step != SQLITE_DONE) {
    rc = WYRELOG_E_IO;
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
service_handoff_disposition_insert (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffDispositionInput *input,
    const guint8 semantic_key[crypto_generichash_BYTES], gint64 now_us)
{
  gchar escrow[WYL_ID_STRING_BUF];
  wyl_id_format (input->tuple.escrow_id, escrow, sizeof escrow);
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "INSERT INTO service_credential_handoff_dispositions("
      "disposition_id,semantic_key,original_request_id,escrow_id,"
      "binding_digest,successor_credential_id,successor_issuance_generation,"
      "actor_subject_id,reason,outcome,audit_id,created_at_us)"
      " VALUES(?,?,?,?,?,?,?,?,?,?,?,?);";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK
      && ((rc = bind_text (stmt, 1, input->disposition_id)) != WYRELOG_E_OK
          || sqlite3_bind_blob (stmt, 2, semantic_key, 32, SQLITE_TRANSIENT)
          != SQLITE_OK || (rc = bind_text (stmt, 3,
                  input->tuple.original_request_id)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 4, escrow)) != WYRELOG_E_OK
          || sqlite3_bind_blob (stmt, 5, input->tuple.binding_digest, 32,
              SQLITE_TRANSIENT) != SQLITE_OK
          || (input->tuple.successor_credential_id == NULL ?
              sqlite3_bind_null (stmt, 6) : sqlite3_bind_text (stmt, 6,
                  input->tuple.successor_credential_id, -1,
                  SQLITE_TRANSIENT)) != SQLITE_OK
          || (input->tuple.successor_issuance_generation == 0 ?
              sqlite3_bind_null (stmt, 7) : sqlite3_bind_int64 (stmt, 7,
                  (sqlite3_int64)
                  input->tuple.successor_issuance_generation)) != SQLITE_OK
          || (rc = bind_text (stmt, 8, input->actor_subject_id))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 9,
                  service_handoff_reason_name (input->reason))) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 10,
                  service_handoff_outcome_name (input->outcome))) !=
          WYRELOG_E_OK
          || (rc = bind_text (stmt, 11, input->audit_id)) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 12, now_us) != SQLITE_OK))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
    rc = (sqlite3_extended_errcode (store->db) & 0xff) == SQLITE_CONSTRAINT ?
        WYRELOG_E_POLICY : WYRELOG_E_IO;
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
service_handoff_escrow_absent (wyl_policy_store_t *store,
    const wyl_id_t *escrow_id)
{
  if (service_handoff_should_fail (store, WYL_POLICY_HANDOFF_FAIL_SQLITE_NOMEM))
    return service_handoff_sqlite_error (store->db, SQLITE_NOMEM);
  gchar formatted[WYL_ID_STRING_BUF];
  if (wyl_id_format (escrow_id, formatted, sizeof formatted) != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = prepare_stmt (store->db,
      "SELECT 1 FROM service_credential_handoff_escrows WHERE escrow_id=?;",
      &stmt);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 1, formatted);
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK)
    rc = step == SQLITE_DONE ? WYRELOG_E_OK :
        (step == SQLITE_ROW ? WYRELOG_E_POLICY :
        service_handoff_sqlite_error (store->db, step));
  else
    rc = service_handoff_map_sqlite_io (store->db, rc);
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return rc;
}

static wyrelog_error_t
service_handoff_request_escrow_absent (wyl_policy_store_t *store,
    const gchar *request_id)
{
  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = prepare_stmt (store->db,
      "SELECT 1 FROM service_credential_handoff_escrows WHERE request_id=?"
      " LIMIT 1;", &stmt);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 1, request_id);
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK)
    rc = step == SQLITE_DONE ? WYRELOG_E_OK :
        (step == SQLITE_ROW ? WYRELOG_E_POLICY :
        service_handoff_sqlite_error (store->db, step));
  else
    rc = service_handoff_map_sqlite_io (store->db, rc);
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return rc;
}

static wyrelog_error_t
service_handoff_validate_no_commit_fence (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffDispositionInput *input)
{
  const WylPolicyServiceHandoffNoCommitEvidence *evidence =
      input->no_commit_evidence;
  WylServiceCredentialFenceOperation operation =
      evidence->operation == WYL_POLICY_HANDOFF_FENCE_ISSUE ?
      WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE :
      WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE;
  guint8 expected[WYL_POLICY_STORE_OPERATION_FINGERPRINT_BYTES] = { 0 };
  wyrelog_error_t rc =
      wyl_policy_store_service_credential_operation_fence_fingerprint
      (operation, evidence->target_a, strlen (evidence->target_a),
      evidence->target_b,
      evidence->target_b != NULL ? strlen (evidence->target_b) : 0, expected);
  gboolean committed_operation_matches = FALSE;
  guint8 committed_fingerprint[crypto_generichash_BYTES] = { 0 };
  gchar committed_credential_id[WYL_SERVICE_CREDENTIAL_ID_BUF] = { 0 };
  guint64 committed_generation = 0;
  if (rc == WYRELOG_E_OK) {
    rc = service_credential_operation_fence_committed_lookup_db (store->db,
        input->tuple.original_request_id, operation,
        &committed_operation_matches, committed_fingerprint,
        committed_credential_id, &committed_generation);
    if (rc == WYRELOG_E_OK)
      rc = WYRELOG_E_POLICY;
    else if (rc == WYRELOG_E_NOT_FOUND)
      rc = WYRELOG_E_OK;
  }
  sqlite3_stmt *stmt = NULL;
  if (rc == WYRELOG_E_OK)
    rc = prepare_stmt (store->db,
        "SELECT operation,operation_fingerprint,terminal_state FROM"
        " service_credential_operation_fences WHERE request_id=?;", &stmt);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 1, input->tuple.original_request_id);
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW) {
    const gchar *stored_operation =
        (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *terminal = (const gchar *) sqlite3_column_text (stmt, 2);
    gboolean exact = g_strcmp0 (stored_operation,
        operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE ?
        "credential_issue" : "credential_rotate") == 0
        && sqlite3_column_type (stmt, 1) == SQLITE_BLOB
        && sqlite3_column_bytes (stmt, 1) == sizeof expected
        && sodium_memcmp (sqlite3_column_blob (stmt, 1), expected,
        sizeof expected) == 0 && g_strcmp0 (terminal, "not_committed") == 0;
    rc = exact && sqlite3_step (stmt) == SQLITE_DONE ? WYRELOG_E_OK :
        WYRELOG_E_POLICY;
  } else if (rc == WYRELOG_E_OK) {
    rc = step == SQLITE_DONE ? WYRELOG_E_POLICY :
        service_handoff_sqlite_error (store->db, step);
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  sodium_memzero (expected, sizeof expected);
  sodium_memzero (committed_fingerprint, sizeof committed_fingerprint);
  sodium_memzero (committed_credential_id, sizeof committed_credential_id);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
service_handoff_record_disposition (WylServiceAuthorityTransaction *transaction,
    wyl_policy_store_t *store,
    const WylPolicyServiceHandoffDispositionInput *input,
    gboolean require_absent, gint64 trusted_now,
    WylPolicyServiceHandoffDispositionResult *out)
{
  if (trusted_now <= 0)
    return WYRELOG_E_INVALID;
  guint8 semantic_key[crypto_generichash_BYTES];
  wyrelog_error_t rc = service_handoff_disposition_semantic_key (input,
      semantic_key);
  gboolean found = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_disposition_lookup_exact (store, input,
        semantic_key, &found, out);
  if (rc != WYRELOG_E_OK || found) {
    sodium_memzero (semantic_key, sizeof semantic_key);
    return rc;
  }
  if (require_absent) {
    rc = service_handoff_validate_no_commit_fence (store, input);
    if (rc == WYRELOG_E_OK)
      rc = service_handoff_escrow_absent (store, input->tuple.escrow_id);
    if (rc == WYRELOG_E_OK)
      rc = service_handoff_request_escrow_absent (store,
          input->tuple.original_request_id);
  } else {
    rc = service_handoff_validate_exact_escrow (store, &input->tuple);
  }
  if (rc == WYRELOG_E_OK
      && input->reason == WYL_POLICY_HANDOFF_DISPOSITION_OPERATION_EXPIRED) {
    gchar escrow_id[WYL_ID_STRING_BUF];
    sqlite3_stmt *stmt = NULL;
    if (wyl_id_format (input->tuple.escrow_id, escrow_id, sizeof escrow_id)
        != WYRELOG_E_OK)
      rc = WYRELOG_E_INVALID;
    if (rc == WYRELOG_E_OK)
      rc = prepare_stmt (store->db,
          "SELECT deadline_at_us FROM service_credential_handoff_escrows"
          " WHERE escrow_id=?;", &stmt);
    if (rc == WYRELOG_E_OK)
      rc = bind_text (stmt, 1, escrow_id);
    int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
    if (rc == WYRELOG_E_OK && step == SQLITE_ROW) {
      gint64 deadline = sqlite3_column_int64 (stmt, 0);
      rc = sqlite3_column_type (stmt, 0) == SQLITE_INTEGER
          && deadline > 0 && deadline <= trusted_now
          && sqlite3_step (stmt) == SQLITE_DONE ? WYRELOG_E_OK :
          WYRELOG_E_POLICY;
    } else if (rc == WYRELOG_E_OK) {
      rc = step == SQLITE_DONE ? WYRELOG_E_POLICY :
          service_handoff_sqlite_error (store->db, step);
    } else {
      rc = service_handoff_map_sqlite_io (store->db, rc);
    }
    if (stmt != NULL)
      sqlite3_finalize (stmt);
  }
  WylPolicyServiceSuccessorExactClassification classification = { 0 };
  if (rc == WYRELOG_E_OK
      && (input->reason ==
          WYL_POLICY_HANDOFF_DISPOSITION_SUCCESSOR_EXPIRED
          || input->reason ==
          WYL_POLICY_HANDOFF_DISPOSITION_SUCCESSOR_REVOKED)) {
    rc = wyl_policy_store_classify_service_credential_successor_exact_core
        (transaction, store, &input->tuple, trusted_now, &classification);
  }
  if (rc == WYRELOG_E_OK
      && input->reason == WYL_POLICY_HANDOFF_DISPOSITION_SUCCESSOR_EXPIRED
      && classification.disposition != WYL_POLICY_SERVICE_SUCCESSOR_EXPIRED)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK
      && input->reason == WYL_POLICY_HANDOFF_DISPOSITION_SUCCESSOR_REVOKED
      && classification.disposition != WYL_POLICY_SERVICE_SUCCESSOR_REVOKED)
    rc = WYRELOG_E_POLICY;
  wyl_policy_service_successor_exact_classification_clear (&classification);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_append_audit_strict (store, input->audit_id,
        trusted_now, input->actor_subject_id,
        "service.credential.handoff.disposition",
        input->tuple.original_request_id, input->tuple.original_request_id);
  if (rc == WYRELOG_E_OK && service_handoff_should_fail (store,
          WYL_POLICY_HANDOFF_FAIL_AFTER_AUDIT))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_disposition_insert (store, input, semantic_key,
        trusted_now);
  if (rc == WYRELOG_E_OK && service_handoff_should_fail (store,
          WYL_POLICY_HANDOFF_FAIL_AFTER_PROVENANCE))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_fill_disposition_result (input->disposition_id,
        input->audit_id, trusted_now, FALSE, out);
  sodium_memzero (semantic_key, sizeof semantic_key);
  return rc;
}

wyrelog_error_t
    wyl_policy_store_record_service_handoff_disposition_core
    (WylServiceAuthorityTransaction * transaction,
    wyl_policy_store_t * store,
    const WylPolicyServiceHandoffDispositionInput * input,
    WylPolicyServiceHandoffDispositionResult * out_result)
{
  if (out_result != NULL)
    wyl_policy_service_handoff_disposition_result_clear (out_result);
  if (store == NULL || out_result == NULL
      || !service_handoff_disposition_shape_valid (input)
      || input->reason == WYL_POLICY_HANDOFF_DISPOSITION_DELIVERED
      || input->reason == WYL_POLICY_HANDOFF_DISPOSITION_OPERATION_CANCELLED
      || input->reason == WYL_POLICY_HANDOFF_DISPOSITION_NOT_COMMITTED)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc =
      wyl_policy_store_service_authority_transaction_enter_participant
      (transaction, store);
  return rc == WYRELOG_E_OK ? service_handoff_record_disposition
      (transaction, store, input,
      input->reason == WYL_POLICY_HANDOFF_DISPOSITION_NOT_COMMITTED,
      g_get_real_time (), out_result) : rc;
}

wyrelog_error_t
    wyl_policy_store_record_service_handoff_not_committed_core
    (WylServiceAuthorityTransaction * transaction,
    wyl_policy_store_t * store,
    const WylPolicyServiceHandoffDispositionInput * input,
    WylPolicyServiceHandoffDispositionResult * out_result)
{
  if (out_result != NULL)
    wyl_policy_service_handoff_disposition_result_clear (out_result);
  if (store == NULL || out_result == NULL
      || !service_handoff_disposition_shape_valid (input)
      || input->reason != WYL_POLICY_HANDOFF_DISPOSITION_NOT_COMMITTED)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc =
      wyl_policy_store_service_authority_transaction_enter_participant
      (transaction, store);
  return rc == WYRELOG_E_OK ? service_handoff_record_disposition
      (transaction, store, input, TRUE, g_get_real_time (), out_result) : rc;
}

static wyrelog_error_t
service_handoff_delete_exact (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffExactTuple *tuple)
{
  gchar escrow[WYL_ID_STRING_BUF];
  wyl_id_format (tuple->escrow_id, escrow, sizeof escrow);
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "DELETE FROM service_credential_handoff_escrows WHERE escrow_id=?"
      " AND request_id=? AND actor_subject_id=? AND credential_id=?"
      " AND credential_generation=? AND binding_digest=?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK
      && ((rc = bind_text (stmt, 1, escrow)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 2, tuple->original_request_id))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 3,
                  tuple->original_actor_subject_id)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 4, tuple->successor_credential_id))
          != WYRELOG_E_OK || sqlite3_bind_int64 (stmt, 5,
              (sqlite3_int64) tuple->successor_issuance_generation)
          != SQLITE_OK || sqlite3_bind_blob (stmt, 6, tuple->binding_digest,
              32, SQLITE_TRANSIENT) != SQLITE_OK))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && sqlite3_changes (store->db) != 1)
    rc = WYRELOG_E_POLICY;
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static const gchar *service_handoff_remediation_action_name
    (WylPolicyServiceHandoffRemediationAction action)
{
  return action == WYL_POLICY_HANDOFF_REMEDIATION_RESUME ? "resume" :
      (action == WYL_POLICY_HANDOFF_REMEDIATION_REVOKE_AND_WIPE ?
      "revoke_and_wipe" : NULL);
}

static const gchar *service_handoff_remediation_outcome_name
    (WylPolicyServiceHandoffRemediationOutcome outcome)
{
  switch (outcome) {
    case WYL_POLICY_HANDOFF_REMEDIATION_RECORDED:
      return "recorded";
    case WYL_POLICY_HANDOFF_REMEDIATION_REVOKED_AND_WIPED:
      return "revoked_and_wiped";
    case WYL_POLICY_HANDOFF_REMEDIATION_EXPIRED_AND_WIPED:
      return "expired_and_wiped";
    case WYL_POLICY_HANDOFF_REMEDIATION_ALREADY_REVOKED_AND_WIPED:
      return "already_revoked_and_wiped";
    default:
      return NULL;
  }
}

static WylPolicyServiceHandoffRemediationOutcome
service_handoff_remediation_outcome_parse (const gchar *outcome)
{
  if (g_strcmp0 (outcome, "recorded") == 0)
    return WYL_POLICY_HANDOFF_REMEDIATION_RECORDED;
  if (g_strcmp0 (outcome, "revoked_and_wiped") == 0)
    return WYL_POLICY_HANDOFF_REMEDIATION_REVOKED_AND_WIPED;
  if (g_strcmp0 (outcome, "expired_and_wiped") == 0)
    return WYL_POLICY_HANDOFF_REMEDIATION_EXPIRED_AND_WIPED;
  if (g_strcmp0 (outcome, "already_revoked_and_wiped") == 0)
    return WYL_POLICY_HANDOFF_REMEDIATION_ALREADY_REVOKED_AND_WIPED;
  return 0;
}

static const gchar *service_handoff_remediation_source_name
    (WylPolicyServiceHandoffRemediationSourceKind source)
{
  return source == WYL_POLICY_HANDOFF_REMEDIATION_SOURCE_COMMITTED_ATTENTION ?
      "committed_attention" :
      (source ==
      WYL_POLICY_HANDOFF_REMEDIATION_SOURCE_OPERATOR_ACTION_REQUIRED ?
      "operator_action_required" : NULL);
}

static const gchar *service_handoff_remediation_state_name
    (WylPolicyServiceHandoffRemediationJournalState state)
{
  switch (state) {
    case WYL_POLICY_HANDOFF_REMEDIATION_STATE_SERVER_COMMITTED:
      return "server_committed";
    case WYL_POLICY_HANDOFF_REMEDIATION_STATE_PUBLICATION_PLANNED:
      return "publication_planned";
    case WYL_POLICY_HANDOFF_REMEDIATION_STATE_PUBLICATION_PREPARED:
      return "publication_prepared";
    case WYL_POLICY_HANDOFF_REMEDIATION_STATE_FILE_PUBLISHED:
      return "file_published";
    case WYL_POLICY_HANDOFF_REMEDIATION_STATE_CLEANUP_REQUIRED:
      return "cleanup_required";
    case WYL_POLICY_HANDOFF_REMEDIATION_STATE_OPERATOR_ACTION_REQUIRED:
      return "operator_action_required";
    default:
      return NULL;
  }
}

static const gchar *service_handoff_remediation_oar_cause_name
    (WylPolicyServiceHandoffRemediationOarCause cause)
{
  static const gchar *const names[] = {
    NULL, "receipt_foreign", "receipt_uncertain", "escrow_foreign",
    "escrow_uncertain", "successor_revoked", "successor_expired",
    "explicit_hold", "escrow_missing",
  };
  return cause > WYL_POLICY_HANDOFF_REMEDIATION_OAR_NONE
      && cause <= WYL_POLICY_HANDOFF_REMEDIATION_OAR_ESCROW_MISSING ?
      names[cause] : NULL;
}

static const gchar *service_handoff_remediation_escrow_outcome_name
    (WylPolicyServiceHandoffRemediationEscrowOutcome outcome)
{
  return outcome == WYL_POLICY_HANDOFF_REMEDIATION_ESCROW_RETAINED ?
      "retained" :
      (outcome == WYL_POLICY_HANDOFF_REMEDIATION_ESCROW_DELETED ? "deleted" :
      (outcome == WYL_POLICY_HANDOFF_REMEDIATION_ESCROW_ALREADY_ABSENT ?
          "already_absent" : NULL));
}

static WylPolicyServiceHandoffRemediationJournalState
service_handoff_remediation_state_parse (const gchar *state)
{
  if (state == NULL)
    return 0;
  for (guint i = WYL_POLICY_HANDOFF_REMEDIATION_STATE_SERVER_COMMITTED;
      i <= WYL_POLICY_HANDOFF_REMEDIATION_STATE_PUBLICATION_PLANNED; i++) {
    const gchar *candidate = service_handoff_remediation_state_name
        ((WylPolicyServiceHandoffRemediationJournalState) i);
    if (candidate != NULL && g_strcmp0 (state, candidate) == 0)
      return (WylPolicyServiceHandoffRemediationJournalState) i;
  }
  return 0;
}

static WylPolicyServiceHandoffRemediationOarCause
service_handoff_remediation_oar_cause_parse (const gchar *cause)
{
  for (guint i = WYL_POLICY_HANDOFF_REMEDIATION_OAR_RECEIPT_FOREIGN;
      i <= WYL_POLICY_HANDOFF_REMEDIATION_OAR_ESCROW_MISSING; i++)
    if (g_strcmp0 (cause, service_handoff_remediation_oar_cause_name
            ((WylPolicyServiceHandoffRemediationOarCause) i)) == 0)
      return (WylPolicyServiceHandoffRemediationOarCause) i;
  return 0;
}

static gboolean
    service_handoff_remediation_committed_state_valid
    (WylPolicyServiceHandoffRemediationJournalState state)
{
  return state == WYL_POLICY_HANDOFF_REMEDIATION_STATE_SERVER_COMMITTED
      || state == WYL_POLICY_HANDOFF_REMEDIATION_STATE_PUBLICATION_PLANNED
      || state == WYL_POLICY_HANDOFF_REMEDIATION_STATE_PUBLICATION_PREPARED
      || state == WYL_POLICY_HANDOFF_REMEDIATION_STATE_FILE_PUBLISHED
      || state == WYL_POLICY_HANDOFF_REMEDIATION_STATE_CLEANUP_REQUIRED;
}

static gboolean
    service_handoff_remediation_shape_valid
    (const WylPolicyServiceHandoffRemediationInput * input)
{
  return input != NULL
      && service_handoff_request_id_is_canonical (input->remediation_request_id)
      && service_handoff_request_id_is_canonical (input->decision_request_id)
      && service_handoff_uuid_is_canonical (input->audit_id)
      && service_handoff_exact_tuple_is_valid (&input->tuple)
      && input->tuple.successor_credential_id != NULL
      && wyl_policy_service_actor_subject_is_valid
      (input->current_actor_subject_id)
      && g_strcmp0 (input->tuple.original_request_id,
      input->remediation_request_id) != 0
      && g_strcmp0 (input->tuple.original_request_id,
      input->decision_request_id) != 0
      && g_strcmp0 (input->remediation_request_id,
      input->decision_request_id) != 0
      && g_strcmp0 (input->tuple.original_actor_subject_id,
      input->current_actor_subject_id) != 0
      && !sodium_is_zero (input->journal_snapshot_digest,
      sizeof input->journal_snapshot_digest)
      && service_handoff_remediation_state_name (input->observed_state) != NULL
      && ((input->source_kind ==
          WYL_POLICY_HANDOFF_REMEDIATION_SOURCE_COMMITTED_ATTENTION
          && service_handoff_remediation_committed_state_valid
          (input->observed_state)
          && service_handoff_uuid_is_canonical (input->source_disposition_id)
          && service_handoff_uuid_is_canonical (input->source_audit_id)
          && (input->source_reason ==
              WYL_POLICY_HANDOFF_DISPOSITION_OPERATION_CANCELLED
              || input->source_reason ==
              WYL_POLICY_HANDOFF_DISPOSITION_OPERATION_EXPIRED)
          && input->oar_source_state == 0 && input->oar_cause == 0
          && input->resume_target_state == 0)
      || (input->source_kind ==
          WYL_POLICY_HANDOFF_REMEDIATION_SOURCE_OPERATOR_ACTION_REQUIRED
          && input->observed_state ==
          WYL_POLICY_HANDOFF_REMEDIATION_STATE_OPERATOR_ACTION_REQUIRED
          && input->source_disposition_id == NULL
          && input->source_audit_id == NULL && input->source_reason == 0
          && service_handoff_remediation_committed_state_valid
          (input->oar_source_state)
          && service_handoff_remediation_oar_cause_name (input->oar_cause)
          != NULL && input->resume_target_state == input->oar_source_state))
      && !((input->oar_cause ==
          WYL_POLICY_HANDOFF_REMEDIATION_OAR_RECEIPT_FOREIGN
          || input->oar_cause ==
          WYL_POLICY_HANDOFF_REMEDIATION_OAR_RECEIPT_UNCERTAIN)
      && input->oar_source_state ==
      WYL_POLICY_HANDOFF_REMEDIATION_STATE_SERVER_COMMITTED)
      && !(input->source_kind ==
      WYL_POLICY_HANDOFF_REMEDIATION_SOURCE_OPERATOR_ACTION_REQUIRED
      && input->oar_cause == WYL_POLICY_HANDOFF_REMEDIATION_OAR_ESCROW_MISSING
      && input->action != WYL_POLICY_HANDOFF_REMEDIATION_REVOKE_AND_WIPE)
      && !(input->action == WYL_POLICY_HANDOFF_REMEDIATION_RESUME
      && (input->oar_cause ==
          WYL_POLICY_HANDOFF_REMEDIATION_OAR_SUCCESSOR_REVOKED
          || input->oar_cause ==
          WYL_POLICY_HANDOFF_REMEDIATION_OAR_SUCCESSOR_EXPIRED))
      && ((input->action == WYL_POLICY_HANDOFF_REMEDIATION_RESUME
          && input->confirmation_version == 0 && !input->confirmed)
      || (input->action ==
          WYL_POLICY_HANDOFF_REMEDIATION_REVOKE_AND_WIPE
          && input->confirmation_version == 1 && input->confirmed));
}

static wyrelog_error_t
    service_handoff_remediation_incident_fingerprint
    (const WylPolicyServiceHandoffRemediationInput * input,
    guint8 out[crypto_generichash_BYTES])
{
  gchar escrow[WYL_ID_STRING_BUF];
  gchar generation[32];
  gchar binding[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES * 2 + 1];
  gchar snapshot[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES * 2 + 1];
  if (wyl_id_format (input->tuple.escrow_id, escrow, sizeof escrow)
      != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  g_snprintf (generation, sizeof generation, "%" G_GUINT64_FORMAT,
      input->tuple.successor_issuance_generation);
  sodium_bin2hex (binding, sizeof binding, input->tuple.binding_digest,
      sizeof input->tuple.binding_digest);
  sodium_bin2hex (snapshot, sizeof snapshot, input->journal_snapshot_digest,
      sizeof input->journal_snapshot_digest);
  const gchar *fields[] = {
    service_handoff_remediation_source_name (input->source_kind), snapshot,
    service_handoff_remediation_state_name (input->observed_state),
    input->tuple.original_request_id,
    input->tuple.original_actor_subject_id,
    escrow, binding, input->tuple.successor_credential_id, generation,
    input->source_disposition_id != NULL ? input->source_disposition_id : "",
    input->source_audit_id != NULL ? input->source_audit_id : "",
    input->source_reason != 0 ?
        service_handoff_reason_name (input->source_reason) : "",
    input->oar_source_state != 0 ?
        service_handoff_remediation_state_name (input->oar_source_state) : "",
    input->oar_cause != 0 ?
        service_handoff_remediation_oar_cause_name (input->oar_cause) : "",
    input->resume_target_state != 0 ?
        service_handoff_remediation_state_name (input->resume_target_state) :
        "",
  };
  return service_handoff_hash_fields
      ("wyrelog.service-handoff-remediation-incident.v1", fields,
      G_N_ELEMENTS (fields), out);
}

static wyrelog_error_t
    service_handoff_remediation_fingerprint
    (const WylPolicyServiceHandoffRemediationInput * input,
    const guint8 incident_fingerprint[crypto_generichash_BYTES],
    guint8 out[crypto_generichash_BYTES])
{
  gchar confirmation[16];
  gchar incident[crypto_generichash_BYTES * 2 + 1];
  g_snprintf (confirmation, sizeof confirmation, "%u:%u",
      input->confirmation_version, input->confirmed ? 1 : 0);
  sodium_bin2hex (incident, sizeof incident, incident_fingerprint,
      crypto_generichash_BYTES);
  const gchar *fields[] = {
    incident, service_handoff_remediation_action_name (input->action),
    input->remediation_request_id, input->decision_request_id,
    input->current_actor_subject_id, confirmation, input->audit_id,
  };
  return service_handoff_hash_fields
      ("wyrelog.service-handoff-remediation-request.v2", fields,
      G_N_ELEMENTS (fields), out);
}

static wyrelog_error_t
    service_handoff_remediation_validate_cancelled_incident
    (wyl_policy_store_t * store,
    const WylPolicyServiceHandoffRemediationInput * input)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT cancellation_request_id,decision_request_id,"
      "current_actor_subject_id,operation,target_a,target_b,target_digest,"
      "deadline_at_us FROM service_credential_handoff_cancellation_claims"
      " WHERE original_request_id=? AND disposition_id=? AND audit_id=?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK
      && ((rc = bind_text (stmt, 1, input->tuple.original_request_id))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 2,
                  input->source_disposition_id)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 3, input->source_audit_id))
          != WYRELOG_E_OK))
    rc = WYRELOG_E_IO;
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  WylPolicyServiceHandoffCancellationInput cancellation = { 0 };
  g_autofree gchar *cancellation_request = NULL;
  g_autofree gchar *decision_request = NULL;
  g_autofree gchar *current_actor = NULL;
  g_autofree gchar *target_a = NULL;
  g_autofree gchar *target_b = NULL;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW) {
    cancellation_request = service_handoff_try_strdup
        ((const gchar *) sqlite3_column_text (stmt, 0));
    decision_request = service_handoff_try_strdup
        ((const gchar *) sqlite3_column_text (stmt, 1));
    current_actor = service_handoff_try_strdup
        ((const gchar *) sqlite3_column_text (stmt, 2));
    target_a = service_handoff_try_strdup
        ((const gchar *) sqlite3_column_text (stmt, 4));
    target_b = sqlite3_column_type (stmt, 5) == SQLITE_TEXT ?
        service_handoff_try_strdup
        ((const gchar *) sqlite3_column_text (stmt, 5)) : NULL;
    const gchar *operation = (const gchar *) sqlite3_column_text (stmt, 3);
    cancellation = (WylPolicyServiceHandoffCancellationInput) {
    .cancellation_request_id = cancellation_request,.decision_request_id =
          decision_request,.current_actor_subject_id =
          current_actor,.disposition_id =
          input->source_disposition_id,.audit_id =
          input->source_audit_id,.tuple = input->tuple,.observation =
          WYL_POLICY_HANDOFF_CANCELLATION_OBSERVATION_COMMITTED,.operation =
          g_strcmp0 (operation,
          "issue") ==
          0 ? WYL_POLICY_HANDOFF_FENCE_ISSUE :
          WYL_POLICY_HANDOFF_FENCE_ROTATE,.target_a = target_a,.target_b =
          target_b,.deadline_at_us = sqlite3_column_int64 (stmt, 7),};
    if (sqlite3_column_type (stmt, 6) == SQLITE_BLOB
        && sqlite3_column_bytes (stmt, 6) == sizeof cancellation.target_digest)
      memcpy (cancellation.target_digest, sqlite3_column_blob (stmt, 6),
          sizeof cancellation.target_digest);
    if (cancellation_request == NULL || decision_request == NULL
        || current_actor == NULL || target_a == NULL
        || (sqlite3_column_type (stmt, 5) == SQLITE_TEXT && target_b == NULL))
      rc = WYRELOG_E_NOMEM;
    else if ((g_strcmp0 (operation, "issue") != 0
            && g_strcmp0 (operation, "rotate") != 0)
        || sqlite3_step (stmt) != SQLITE_DONE)
      rc = WYRELOG_E_POLICY;
  } else if (rc == WYRELOG_E_OK) {
    rc = step == SQLITE_DONE ? WYRELOG_E_POLICY :
        service_handoff_sqlite_error (store->db, step);
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  WylPolicyServiceHandoffCancellationResult result = { 0 };
  gboolean found = FALSE;
  if (rc == WYRELOG_E_OK && !service_handoff_cancellation_shape_valid
      (&cancellation))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_cancellation_lookup (store, &cancellation, TRUE,
        FALSE, TRUE, &found, &result);
  if (rc == WYRELOG_E_OK && (!found
          || result.outcome !=
          WYL_POLICY_HANDOFF_CANCELLATION_COMMITTED_ATTENTION))
    rc = WYRELOG_E_POLICY;
  wyl_policy_service_handoff_cancellation_result_clear (&result);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
service_handoff_remediation_validate_incident (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffRemediationInput *input)
{
  if (input->source_kind ==
      WYL_POLICY_HANDOFF_REMEDIATION_SOURCE_OPERATOR_ACTION_REQUIRED)
    return WYRELOG_E_OK;
  if (input->source_reason ==
      WYL_POLICY_HANDOFF_DISPOSITION_OPERATION_CANCELLED)
    return service_handoff_remediation_validate_cancelled_incident (store,
        input);
  gboolean found = FALSE;
  WylPolicyServiceHandoffDispositionResult disposition = { 0 };
  wyrelog_error_t rc = service_handoff_lookup_minted_disposition (store,
      &input->tuple, WYL_POLICY_HANDOFF_DISPOSITION_OPERATION_EXPIRED,
      WYL_POLICY_HANDOFF_OUTCOME_ATTENTION_REQUIRED, &found, &disposition);
  if (rc == WYRELOG_E_OK
      && (!found
          || g_strcmp0 (disposition.disposition_id,
              input->source_disposition_id) != 0
          || g_strcmp0 (disposition.audit_id, input->source_audit_id) != 0))
    rc = WYRELOG_E_POLICY;
  wyl_policy_service_handoff_disposition_result_clear (&disposition);
  return rc;
}

static wyrelog_error_t
    service_handoff_fill_remediation_result
    (const WylPolicyServiceHandoffRemediationInput * input,
    const gchar * audit_id,
    WylPolicyServiceHandoffRemediationOutcome outcome, gboolean replayed,
    gboolean revoked_now, WylPolicyServiceSuccessorDisposition disposition,
    WylPolicyServiceHandoffRemediationEscrowOutcome escrow_outcome,
    guint64 invalidation_generation, guint64 credential_generation_after,
    gint64 revoke_event_id, guint64 revoke_event_generation,
    const gchar * revoke_event_request_id,
    const gchar * revoke_event_actor_subject_id,
    gint64 revoke_event_created_at_us,
    gint64 created_at_us, WylPolicyServiceHandoffRemediationResult * out)
{
  out->audit_id = service_handoff_try_strdup (audit_id);
  out->remediation_request_id = service_handoff_try_strdup
      (input->remediation_request_id);
  out->decision_request_id = service_handoff_try_strdup
      (input->decision_request_id);
  out->current_actor_subject_id = service_handoff_try_strdup
      (input->current_actor_subject_id);
  out->original_request_id = service_handoff_try_strdup
      (input->tuple.original_request_id);
  out->original_actor_subject_id = service_handoff_try_strdup
      (input->tuple.original_actor_subject_id);
  out->source_disposition_id = input->source_disposition_id != NULL ?
      service_handoff_try_strdup (input->source_disposition_id) : NULL;
  out->source_audit_id = input->source_audit_id != NULL ?
      service_handoff_try_strdup (input->source_audit_id) : NULL;
  if (out->audit_id == NULL || out->remediation_request_id == NULL
      || out->decision_request_id == NULL
      || out->current_actor_subject_id == NULL
      || out->original_request_id == NULL
      || out->original_actor_subject_id == NULL
      || (input->source_disposition_id != NULL
          && out->source_disposition_id == NULL)
      || (input->source_audit_id != NULL && out->source_audit_id == NULL)) {
    wyl_policy_service_handoff_remediation_result_clear (out);
    return WYRELOG_E_NOMEM;
  }
  out->outcome = outcome;
  out->action = input->action;
  out->confirmation_version = input->confirmation_version;
  out->confirmed = input->confirmed;
  out->created_at_us = created_at_us;
  out->escrow_outcome = escrow_outcome;
  out->replayed = replayed;
  out->revoked_now = revoked_now;
  out->successor_disposition = disposition;
  out->invalidation_generation = invalidation_generation;
  out->credential_generation_after = credential_generation_after;
  out->revoke_event_id = revoke_event_id;
  out->revoke_event_generation = revoke_event_generation;
  out->revoke_event_request_id = revoke_event_request_id != NULL ?
      service_handoff_try_strdup (revoke_event_request_id) : NULL;
  out->revoke_event_actor_subject_id = revoke_event_actor_subject_id != NULL ?
      service_handoff_try_strdup (revoke_event_actor_subject_id) : NULL;
  out->revoke_event_created_at_us = revoke_event_created_at_us;
  if ((revoke_event_request_id != NULL && out->revoke_event_request_id == NULL)
      || (revoke_event_actor_subject_id != NULL
          && out->revoke_event_actor_subject_id == NULL)) {
    wyl_policy_service_handoff_remediation_result_clear (out);
    return WYRELOG_E_NOMEM;
  }
  out->source_kind = input->source_kind;
  memcpy (out->journal_snapshot_digest, input->journal_snapshot_digest,
      sizeof out->journal_snapshot_digest);
  guint8 incident_fingerprint[crypto_generichash_BYTES] = { 0 };
  wyrelog_error_t fingerprint_rc =
      service_handoff_remediation_incident_fingerprint (input,
      incident_fingerprint);
  if (fingerprint_rc == WYRELOG_E_OK)
    fingerprint_rc = service_handoff_remediation_fingerprint (input,
        incident_fingerprint, out->request_fingerprint);
  sodium_memzero (incident_fingerprint, sizeof incident_fingerprint);
  if (fingerprint_rc != WYRELOG_E_OK) {
    wyl_policy_service_handoff_remediation_result_clear (out);
    return fingerprint_rc;
  }
  out->observed_state = input->observed_state;
  out->oar_source_state = input->oar_source_state;
  out->oar_cause = input->oar_cause;
  out->resume_target_state = input->resume_target_state;
  out->source_reason = input->source_reason;
  if (wyl_id_format (input->tuple.escrow_id, out->escrow_id,
          sizeof out->escrow_id) != WYRELOG_E_OK) {
    wyl_policy_service_handoff_remediation_result_clear (out);
    return WYRELOG_E_INVALID;
  }
  memcpy (out->binding_digest, input->tuple.binding_digest,
      sizeof out->binding_digest);
  g_strlcpy (out->successor_credential_id,
      input->tuple.successor_credential_id,
      sizeof out->successor_credential_id);
  out->successor_issuance_generation =
      input->tuple.successor_issuance_generation;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
service_handoff_validate_exact_audit_pair (wyl_policy_store_t *store,
    const gchar *audit_id, gint64 created_at_us, const gchar *actor_subject_id,
    const gchar *action, const gchar *resource_id, const gchar *request_id)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT"
      " (SELECT count(*) FROM audit_events WHERE id=? AND created_at_us=?"
      "  AND subject_id IS ? AND action IS ? AND resource_id IS ?"
      "  AND deny_reason IS NULL AND deny_origin IS NULL AND request_id IS ?"
      "  AND decision=?),"
      " (SELECT count(*) FROM audit_intentions WHERE audit_id=?"
      "  AND created_at_us=? AND subject_id IS ? AND action IS ?"
      "  AND resource_id IS ? AND deny_reason IS NULL AND deny_origin IS NULL"
      "  AND request_id IS ? AND decision=?);";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK
      && ((rc = bind_text (stmt, 1, audit_id)) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 2, created_at_us) != SQLITE_OK
          || (rc = bind_text (stmt, 3, actor_subject_id)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 4, action)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 5, resource_id)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 6, request_id)) != WYRELOG_E_OK
          || sqlite3_bind_int (stmt, 7, WYL_DECISION_ALLOW) != SQLITE_OK
          || (rc = bind_text (stmt, 8, audit_id)) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 9, created_at_us) != SQLITE_OK
          || (rc = bind_text (stmt, 10, actor_subject_id)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 11, action)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 12, resource_id)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 13, request_id)) != WYRELOG_E_OK
          || sqlite3_bind_int (stmt, 14, WYL_DECISION_ALLOW) != SQLITE_OK))
    rc = service_handoff_sqlite_error (store->db,
        sqlite3_extended_errcode (store->db));
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW) {
    gboolean exact = sqlite3_column_type (stmt, 0) == SQLITE_INTEGER
        && sqlite3_column_int64 (stmt, 0) == 1
        && sqlite3_column_type (stmt, 1) == SQLITE_INTEGER
        && sqlite3_column_int64 (stmt, 1) == 1;
    int final_step = sqlite3_step (stmt);
    rc = final_step == SQLITE_DONE ?
        (exact ? WYRELOG_E_OK : WYRELOG_E_POLICY) :
        service_handoff_sqlite_error (store->db, final_step);
  } else if (rc == WYRELOG_E_OK) {
    rc = service_handoff_sqlite_error (store->db, step);
    if (rc == WYRELOG_E_OK)
      rc = WYRELOG_E_POLICY;
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
service_handoff_validate_historical_revoke_event (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffRemediationInput *input, gint64 event_id,
    guint64 event_generation, const gchar *event_request,
    const gchar *event_actor, gint64 event_created)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT 1 FROM service_credential_events WHERE event_id=?"
      " AND credential_id=? AND event='revoked' AND from_state='active'"
      " AND to_state='revoked' AND generation=? AND actor_subject_id=?"
      " AND request_id=? AND created_at_us=?;";
  wyrelog_error_t rc = event_id > 0 && event_generation > 0
      && event_request != NULL && event_actor != NULL && event_created > 0 ?
      prepare_stmt (store->db, sql, &stmt) : WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK
      && (input->tuple.successor_issuance_generation == G_MAXINT64
          || event_generation !=
          input->tuple.successor_issuance_generation + 1))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK
      && (sqlite3_bind_int64 (stmt, 1, event_id) != SQLITE_OK
          || (rc = bind_text (stmt, 2,
                  input->tuple.successor_credential_id)) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 3,
              (sqlite3_int64) event_generation) != SQLITE_OK
          || (rc = bind_text (stmt, 4, event_actor)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 5, event_request)) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 6, event_created) != SQLITE_OK))
    rc = WYRELOG_E_IO;
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW) {
    int final_step = sqlite3_step (stmt);
    rc = final_step == SQLITE_DONE ? WYRELOG_E_OK :
        service_handoff_sqlite_error (store->db, final_step);
  } else if (rc == WYRELOG_E_OK) {
    rc = step == SQLITE_DONE ? WYRELOG_E_POLICY :
        service_handoff_sqlite_error (store->db, step);
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
service_handoff_remediation_lookup (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffRemediationInput *input,
    const guint8 fingerprint[crypto_generichash_BYTES],
    const guint8 incident_fingerprint[crypto_generichash_BYTES],
    gboolean validate_live_state,
    gboolean *out_found, WylPolicyServiceHandoffRemediationResult *out)
{
  *out_found = FALSE;
  gchar escrow[WYL_ID_STRING_BUF];
  wyl_id_format (input->tuple.escrow_id, escrow, sizeof escrow);
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT request_fingerprint,incident_fingerprint,decision_request_id,"
      "original_request_id,original_actor_subject_id,current_actor_subject_id,"
      "source_kind,journal_snapshot_digest,observed_state,"
      "source_disposition_id,source_audit_id,source_reason,oar_source_state,"
      "oar_cause,resume_target_state,escrow_id,binding_digest,"
      "successor_credential_id,successor_issuance_generation,action,"
      "confirmation_version,confirmed,outcome,escrow_outcome,"
      "credential_generation_after,revoke_event_id,revoke_event_generation,"
      "revoke_event_request_id,revoke_event_actor_subject_id,"
      "revoke_event_created_at_us,audit_id,created_at_us"
      " FROM service_credential_handoff_remediation_actions"
      " WHERE remediation_request_id=?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 1, input->remediation_request_id);
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW) {
    *out_found = TRUE;
    const gchar *decision = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *original = (const gchar *) sqlite3_column_text (stmt, 3);
    const gchar *original_actor = (const gchar *) sqlite3_column_text (stmt, 4);
    const gchar *current_actor = (const gchar *) sqlite3_column_text (stmt, 5);
    const gchar *stored_escrow = (const gchar *) sqlite3_column_text (stmt, 15);
    const gchar *successor = (const gchar *) sqlite3_column_text (stmt, 17);
    const gchar *action = (const gchar *) sqlite3_column_text (stmt, 19);
    const gchar *outcome_text = (const gchar *) sqlite3_column_text (stmt, 22);
    const gchar *escrow_outcome_text =
        (const gchar *) sqlite3_column_text (stmt, 23);
    const gchar *event_request = (const gchar *) sqlite3_column_text (stmt, 27);
    const gchar *event_actor = (const gchar *) sqlite3_column_text (stmt, 28);
    const gchar *audit = (const gchar *) sqlite3_column_text (stmt, 30);
    gint64 stored_created_at_us = sqlite3_column_int64 (stmt, 31);
    WylPolicyServiceHandoffRemediationOutcome outcome =
        service_handoff_remediation_outcome_parse (outcome_text);
    WylPolicyServiceHandoffRemediationEscrowOutcome escrow_outcome =
        g_strcmp0 (escrow_outcome_text, "retained") == 0 ?
        WYL_POLICY_HANDOFF_REMEDIATION_ESCROW_RETAINED :
        (g_strcmp0 (escrow_outcome_text, "deleted") == 0 ?
        WYL_POLICY_HANDOFF_REMEDIATION_ESCROW_DELETED :
        (g_strcmp0 (escrow_outcome_text, "already_absent") == 0 ?
            WYL_POLICY_HANDOFF_REMEDIATION_ESCROW_ALREADY_ABSENT : 0));
    gboolean exact = sqlite3_column_type (stmt, 0) == SQLITE_BLOB
        && sqlite3_column_bytes (stmt, 0) == 32
        && sodium_memcmp (sqlite3_column_blob (stmt, 0), fingerprint, 32) == 0
        && sqlite3_column_type (stmt, 1) == SQLITE_BLOB
        && sqlite3_column_bytes (stmt, 1) == 32
        && sodium_memcmp (sqlite3_column_blob (stmt, 1), incident_fingerprint,
        32) == 0
        && g_strcmp0 (decision, input->decision_request_id) == 0
        && g_strcmp0 (original, input->tuple.original_request_id) == 0
        && g_strcmp0 (original_actor,
        input->tuple.original_actor_subject_id) == 0
        && g_strcmp0 (current_actor, input->current_actor_subject_id) == 0
        && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 6),
        service_handoff_remediation_source_name (input->source_kind)) == 0
        && sqlite3_column_type (stmt, 7) == SQLITE_BLOB
        && sqlite3_column_bytes (stmt, 7) == 32
        && sodium_memcmp (sqlite3_column_blob (stmt, 7),
        input->journal_snapshot_digest, 32) == 0
        && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 8),
        service_handoff_remediation_state_name (input->observed_state)) == 0
        && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 9),
        input->source_disposition_id) == 0
        && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 10),
        input->source_audit_id) == 0
        && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 11),
        input->source_reason != 0 ?
        service_handoff_reason_name (input->source_reason) : NULL) == 0
        && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 12),
        input->oar_source_state != 0 ?
        service_handoff_remediation_state_name (input->oar_source_state) :
        NULL) == 0 && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 13),
        input->oar_cause != 0 ?
        service_handoff_remediation_oar_cause_name (input->oar_cause) :
        NULL) == 0 && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 14),
        input->resume_target_state != 0 ?
        service_handoff_remediation_state_name (input->resume_target_state) :
        NULL) == 0
        && g_strcmp0 (stored_escrow, escrow) == 0
        && sqlite3_column_type (stmt, 16) == SQLITE_BLOB
        && sqlite3_column_bytes (stmt, 16) == 32
        && sodium_memcmp (sqlite3_column_blob (stmt, 16),
        input->tuple.binding_digest, 32) == 0
        && g_strcmp0 (successor, input->tuple.successor_credential_id) == 0
        && (guint64) sqlite3_column_int64 (stmt, 18) ==
        input->tuple.successor_issuance_generation && g_strcmp0 (action,
        service_handoff_remediation_action_name (input->action)) == 0
        && (guint32) sqlite3_column_int64 (stmt, 20) ==
        input->confirmation_version
        && (sqlite3_column_int (stmt, 21) != 0) == input->confirmed
        && outcome != 0 && g_strcmp0 (audit, input->audit_id) == 0
        && escrow_outcome != 0
        && sqlite3_column_type (stmt, 24) == SQLITE_INTEGER
        && sqlite3_column_int64 (stmt, 24) > 0
        && sqlite3_column_type (stmt, 31) == SQLITE_INTEGER
        && stored_created_at_us > 0;
    WylPolicyServiceSuccessorDisposition disposition =
        outcome == WYL_POLICY_HANDOFF_REMEDIATION_EXPIRED_AND_WIPED ?
        WYL_POLICY_SERVICE_SUCCESSOR_EXPIRED :
        (outcome ==
        WYL_POLICY_HANDOFF_REMEDIATION_ALREADY_REVOKED_AND_WIPED ?
        WYL_POLICY_SERVICE_SUCCESSOR_REVOKED :
        WYL_POLICY_SERVICE_SUCCESSOR_ACTIVE);
    rc = exact ? WYRELOG_E_OK : WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK)
      rc = service_handoff_remediation_validate_incident (store, input);
    if (rc == WYRELOG_E_OK)
      rc = service_handoff_validate_exact_audit_pair (store, audit,
          stored_created_at_us, current_actor,
          input->action == WYL_POLICY_HANDOFF_REMEDIATION_RESUME ?
          "service.credential.handoff.remediation.resume" :
          "service.credential.handoff.remediation.revoke_and_wipe", successor,
          input->remediation_request_id);
    if (rc == WYRELOG_E_OK && validate_live_state && escrow_outcome ==
        WYL_POLICY_HANDOFF_REMEDIATION_ESCROW_RETAINED)
      rc = service_handoff_validate_exact_escrow (store, &input->tuple);
    if (rc == WYRELOG_E_OK && validate_live_state && escrow_outcome !=
        WYL_POLICY_HANDOFF_REMEDIATION_ESCROW_RETAINED)
      rc = service_handoff_escrow_absent (store, input->tuple.escrow_id);
    if (rc == WYRELOG_E_OK && validate_live_state && escrow_outcome !=
        WYL_POLICY_HANDOFF_REMEDIATION_ESCROW_RETAINED)
      rc = service_handoff_request_escrow_absent (store,
          input->tuple.original_request_id);
    WylPolicyServiceSuccessorExactClassification classification = { 0 };
    if (rc == WYRELOG_E_OK && validate_live_state)
      rc = service_handoff_classify_successor_without_escrow (store,
          &input->tuple, stored_created_at_us, &classification);
    gint64 event_id = sqlite3_column_type (stmt, 25) == SQLITE_INTEGER ?
        sqlite3_column_int64 (stmt, 25) : 0;
    guint64 event_generation = sqlite3_column_type (stmt,
        26) == SQLITE_INTEGER ? (guint64) sqlite3_column_int64 (stmt, 26) : 0;
    gint64 event_created = sqlite3_column_type (stmt,
        29) == SQLITE_INTEGER ? sqlite3_column_int64 (stmt, 29) : 0;
    guint64 credential_generation_after =
        (guint64) sqlite3_column_int64 (stmt, 24);
    if (rc == WYRELOG_E_OK && validate_live_state
        && classification.observed_generation != credential_generation_after)
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK && validate_live_state
        && outcome == WYL_POLICY_HANDOFF_REMEDIATION_RECORDED
        && classification.disposition != WYL_POLICY_SERVICE_SUCCESSOR_ACTIVE)
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK && validate_live_state
        && outcome == WYL_POLICY_HANDOFF_REMEDIATION_EXPIRED_AND_WIPED
        && classification.disposition != WYL_POLICY_SERVICE_SUCCESSOR_EXPIRED)
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK && validate_live_state
        && (outcome == WYL_POLICY_HANDOFF_REMEDIATION_REVOKED_AND_WIPED
            || outcome ==
            WYL_POLICY_HANDOFF_REMEDIATION_ALREADY_REVOKED_AND_WIPED)
        && (classification.disposition != WYL_POLICY_SERVICE_SUCCESSOR_REVOKED
            || !classification.has_revocation_event
            || classification.revocation_event_id != event_id
            || classification.revocation_event_generation != event_generation
            || g_strcmp0 (classification.revocation_event_request_id,
                event_request) != 0
            || g_strcmp0 (classification.revocation_event_actor_subject_id,
                event_actor) != 0
            || classification.revocation_event_created_at_us != event_created))
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK && !validate_live_state
        && (outcome == WYL_POLICY_HANDOFF_REMEDIATION_REVOKED_AND_WIPED
            || outcome ==
            WYL_POLICY_HANDOFF_REMEDIATION_ALREADY_REVOKED_AND_WIPED))
      rc = service_handoff_validate_historical_revoke_event (store, input,
          event_id, event_generation, event_request, event_actor,
          event_created);
    if (rc == WYRELOG_E_OK)
      rc = service_handoff_fill_remediation_result (input, audit, outcome,
          TRUE, FALSE, disposition, escrow_outcome,
          input->action == WYL_POLICY_HANDOFF_REMEDIATION_REVOKE_AND_WIPE ?
          input->tuple.successor_issuance_generation : 0,
          credential_generation_after, event_id, event_generation,
          event_request, event_actor, event_created, stored_created_at_us, out);
    wyl_policy_service_successor_exact_classification_clear (&classification);
    if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
      rc = WYRELOG_E_POLICY;
  } else if (rc == WYRELOG_E_OK && step != SQLITE_DONE) {
    rc = WYRELOG_E_IO;
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
service_handoff_remediation_resolve_stmt (wyl_policy_store_t *store,
    sqlite3_stmt *stmt, gboolean validate_live_state,
    WylPolicyServiceHandoffRemediationResult *out)
{
  int step = sqlite3_step (stmt);
  if (step != SQLITE_ROW)
    return step == SQLITE_DONE ? WYRELOG_E_NOT_FOUND :
        service_handoff_sqlite_error (store->db, step);
  g_autofree gchar *remediation = service_handoff_try_strdup
      ((const gchar *) sqlite3_column_text (stmt, 0));
  g_autofree gchar *decision = service_handoff_try_strdup
      ((const gchar *) sqlite3_column_text (stmt, 1));
  g_autofree gchar *original = service_handoff_try_strdup
      ((const gchar *) sqlite3_column_text (stmt, 2));
  g_autofree gchar *original_actor = service_handoff_try_strdup
      ((const gchar *) sqlite3_column_text (stmt, 3));
  g_autofree gchar *current_actor = service_handoff_try_strdup
      ((const gchar *) sqlite3_column_text (stmt, 4));
  g_autofree gchar *source_kind = service_handoff_try_strdup
      ((const gchar *) sqlite3_column_text (stmt, 5));
  guint8 journal_snapshot_digest[32] = { 0 };
  g_autofree gchar *observed_state = service_handoff_try_strdup
      ((const gchar *) sqlite3_column_text (stmt, 7));
  g_autofree gchar *source_disposition =
      sqlite3_column_type (stmt, 8) == SQLITE_TEXT ?
      service_handoff_try_strdup
      ((const gchar *) sqlite3_column_text (stmt, 8)) : NULL;
  g_autofree gchar *source_audit =
      sqlite3_column_type (stmt, 9) == SQLITE_TEXT ?
      service_handoff_try_strdup
      ((const gchar *) sqlite3_column_text (stmt, 9)) : NULL;
  g_autofree gchar *reason = sqlite3_column_type (stmt, 10) == SQLITE_TEXT ?
      service_handoff_try_strdup
      ((const gchar *) sqlite3_column_text (stmt, 10)) : NULL;
  g_autofree gchar *oar_source_state =
      sqlite3_column_type (stmt, 11) == SQLITE_TEXT ?
      service_handoff_try_strdup
      ((const gchar *) sqlite3_column_text (stmt, 11)) : NULL;
  g_autofree gchar *oar_cause =
      sqlite3_column_type (stmt, 12) == SQLITE_TEXT ?
      service_handoff_try_strdup
      ((const gchar *) sqlite3_column_text (stmt, 12)) : NULL;
  g_autofree gchar *resume_target_state =
      sqlite3_column_type (stmt, 13) == SQLITE_TEXT ?
      service_handoff_try_strdup
      ((const gchar *) sqlite3_column_text (stmt, 13)) : NULL;
  g_autofree gchar *escrow = service_handoff_try_strdup
      ((const gchar *) sqlite3_column_text (stmt, 15));
  guint8 binding_digest[32] = { 0 };
  g_autofree gchar *successor = service_handoff_try_strdup
      ((const gchar *) sqlite3_column_text (stmt, 17));
  guint64 successor_generation = (guint64) sqlite3_column_int64 (stmt, 18);
  g_autofree gchar *action = service_handoff_try_strdup
      ((const gchar *) sqlite3_column_text (stmt, 19));
  guint32 confirmation_version = (guint32) sqlite3_column_int64 (stmt, 20);
  gboolean confirmed = sqlite3_column_int (stmt, 21) != 0;
  g_autofree gchar *audit = service_handoff_try_strdup
      ((const gchar *) sqlite3_column_text (stmt, 22));
  wyl_id_t escrow_id;
  gboolean malformed = sqlite3_column_type (stmt, 0) != SQLITE_TEXT
      || sqlite3_column_type (stmt, 1) != SQLITE_TEXT
      || sqlite3_column_type (stmt, 2) != SQLITE_TEXT
      || sqlite3_column_type (stmt, 3) != SQLITE_TEXT
      || sqlite3_column_type (stmt, 4) != SQLITE_TEXT
      || sqlite3_column_type (stmt, 5) != SQLITE_TEXT
      || sqlite3_column_type (stmt, 7) != SQLITE_TEXT
      || (sqlite3_column_type (stmt, 8) != SQLITE_NULL
      && sqlite3_column_type (stmt, 8) != SQLITE_TEXT)
      || (sqlite3_column_type (stmt, 9) != SQLITE_NULL
      && sqlite3_column_type (stmt, 9) != SQLITE_TEXT)
      || (sqlite3_column_type (stmt, 10) != SQLITE_NULL
      && sqlite3_column_type (stmt, 10) != SQLITE_TEXT)
      || (sqlite3_column_type (stmt, 11) != SQLITE_NULL
      && sqlite3_column_type (stmt, 11) != SQLITE_TEXT)
      || (sqlite3_column_type (stmt, 12) != SQLITE_NULL
      && sqlite3_column_type (stmt, 12) != SQLITE_TEXT)
      || (sqlite3_column_type (stmt, 13) != SQLITE_NULL
      && sqlite3_column_type (stmt, 13) != SQLITE_TEXT)
      || sqlite3_column_type (stmt, 15) != SQLITE_TEXT
      || sqlite3_column_type (stmt, 17) != SQLITE_TEXT
      || sqlite3_column_type (stmt, 19) != SQLITE_TEXT
      || sqlite3_column_type (stmt, 22) != SQLITE_TEXT
      || sqlite3_column_type (stmt, 6) != SQLITE_BLOB
      || sqlite3_column_bytes (stmt, 6) != 32
      || sqlite3_column_type (stmt, 16) != SQLITE_BLOB
      || sqlite3_column_bytes (stmt, 16) != 32;
  if (malformed)
    return WYRELOG_E_POLICY;
  if (remediation == NULL || decision == NULL || original == NULL
      || original_actor == NULL || current_actor == NULL || source_kind == NULL
      || observed_state == NULL || escrow == NULL || successor == NULL
      || action == NULL || audit == NULL
      || (sqlite3_column_type (stmt, 8) == SQLITE_TEXT
          && source_disposition == NULL)
      || (sqlite3_column_type (stmt, 9) == SQLITE_TEXT && source_audit == NULL)
      || (sqlite3_column_type (stmt, 10) == SQLITE_TEXT && reason == NULL)
      || (sqlite3_column_type (stmt, 11) == SQLITE_TEXT
          && oar_source_state == NULL)
      || (sqlite3_column_type (stmt, 12) == SQLITE_TEXT && oar_cause == NULL)
      || (sqlite3_column_type (stmt, 13) == SQLITE_TEXT
          && resume_target_state == NULL))
    return WYRELOG_E_NOMEM;
  if (wyl_id_parse (escrow, &escrow_id) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  memcpy (journal_snapshot_digest, sqlite3_column_blob (stmt, 6), 32);
  memcpy (binding_digest, sqlite3_column_blob (stmt, 16), 32);
  int second = sqlite3_step (stmt);
  if (second != SQLITE_DONE)
    return second == SQLITE_ROW ? WYRELOG_E_POLICY :
        service_handoff_sqlite_error (store->db, second);
  WylPolicyServiceHandoffRemediationInput input = {
    .remediation_request_id = remediation,
    .decision_request_id = decision,
    .current_actor_subject_id = current_actor,
    .audit_id = audit,
    .tuple = {
          .original_request_id = original,
          .escrow_id = &escrow_id,
          .successor_credential_id = successor,
          .successor_issuance_generation = successor_generation,
          .original_actor_subject_id = original_actor,
        },
    .action = g_strcmp0 (action, "resume") == 0 ?
        WYL_POLICY_HANDOFF_REMEDIATION_RESUME :
        WYL_POLICY_HANDOFF_REMEDIATION_REVOKE_AND_WIPE,
    .confirmation_version = confirmation_version,
    .confirmed = confirmed,
    .source_kind = g_strcmp0 (source_kind, "committed_attention") == 0 ?
        WYL_POLICY_HANDOFF_REMEDIATION_SOURCE_COMMITTED_ATTENTION :
        WYL_POLICY_HANDOFF_REMEDIATION_SOURCE_OPERATOR_ACTION_REQUIRED,
    .observed_state = service_handoff_remediation_state_parse (observed_state),
    .source_disposition_id = source_disposition,
    .source_audit_id = source_audit,
    .source_reason = g_strcmp0 (reason, "operation_cancelled") == 0 ?
        WYL_POLICY_HANDOFF_DISPOSITION_OPERATION_CANCELLED :
        (g_strcmp0 (reason, "operation_expired") == 0 ?
        WYL_POLICY_HANDOFF_DISPOSITION_OPERATION_EXPIRED : 0),
    .oar_source_state = service_handoff_remediation_state_parse
        (oar_source_state),
    .oar_cause = service_handoff_remediation_oar_cause_parse (oar_cause),
    .resume_target_state = service_handoff_remediation_state_parse
        (resume_target_state),
  };
  memcpy (input.journal_snapshot_digest, journal_snapshot_digest, 32);
  memcpy (input.tuple.binding_digest, binding_digest, 32);
  if (!service_handoff_remediation_shape_valid (&input)
      || (g_strcmp0 (action, "resume") != 0
          && g_strcmp0 (action, "revoke_and_wipe") != 0)
      || (g_strcmp0 (source_kind, "committed_attention") != 0
          && g_strcmp0 (source_kind, "operator_action_required") != 0))
    return WYRELOG_E_POLICY;
  guint8 incident_fingerprint[crypto_generichash_BYTES] = { 0 };
  guint8 fingerprint[crypto_generichash_BYTES] = { 0 };
  wyrelog_error_t rc = service_handoff_remediation_incident_fingerprint
      (&input, incident_fingerprint);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_remediation_fingerprint (&input,
        incident_fingerprint, fingerprint);
  gboolean found = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_remediation_lookup (store, &input, fingerprint,
        incident_fingerprint, validate_live_state, &found, out);
  if (rc == WYRELOG_E_OK && !found)
    rc = WYRELOG_E_POLICY;
  sodium_memzero (fingerprint, sizeof fingerprint);
  sodium_memzero (incident_fingerprint, sizeof incident_fingerprint);
  return rc;
}

static const gchar *const service_handoff_remediation_resolve_columns =
    "remediation_request_id,decision_request_id,original_request_id,"
    "original_actor_subject_id,current_actor_subject_id,source_kind,"
    "journal_snapshot_digest,observed_state,source_disposition_id,"
    "source_audit_id,source_reason,oar_source_state,oar_cause,"
    "resume_target_state,incident_fingerprint,escrow_id,binding_digest,"
    "successor_credential_id,successor_issuance_generation,action,"
    "confirmation_version,confirmed,audit_id";

wyrelog_error_t
    wyl_policy_store_resolve_service_handoff_remediation_core
    (WylServiceAuthorityTransaction * transaction, wyl_policy_store_t * store,
    const gchar * remediation_request_id,
    const gchar * current_actor_subject_id,
    WylPolicyServiceHandoffRemediationResult * out_result)
{
  if (out_result != NULL)
    wyl_policy_service_handoff_remediation_result_clear (out_result);
  if (store == NULL || out_result == NULL
      || !service_handoff_request_id_is_canonical (remediation_request_id)
      || !wyl_policy_service_actor_subject_is_valid (current_actor_subject_id))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc =
      wyl_policy_store_service_authority_transaction_enter_participant
      (transaction, store);
  g_autofree gchar *sql = g_strdup_printf
      ("SELECT %s FROM service_credential_handoff_remediation_actions"
      " WHERE remediation_request_id=? AND current_actor_subject_id=?;",
      service_handoff_remediation_resolve_columns);
  sqlite3_stmt *stmt = NULL;
  if (rc == WYRELOG_E_OK)
    rc = sql != NULL ? prepare_stmt (store->db, sql, &stmt) : WYRELOG_E_NOMEM;
  if (rc == WYRELOG_E_OK
      && ((rc = bind_text (stmt, 1, remediation_request_id)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 2, current_actor_subject_id))
          != WYRELOG_E_OK))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_remediation_resolve_stmt (store, stmt, TRUE,
        out_result);
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

wyrelog_error_t
    wyl_policy_store_resolve_service_handoff_remediation_incident_core
    (WylServiceAuthorityTransaction * transaction, wyl_policy_store_t * store,
    const gchar * original_request_id,
    const guint8 journal_snapshot_digest
    [WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES],
    WylPolicyServiceHandoffRemediationResult * out_result)
{
  if (out_result != NULL)
    wyl_policy_service_handoff_remediation_result_clear (out_result);
  if (store == NULL || out_result == NULL
      || !service_handoff_request_id_is_canonical (original_request_id)
      || journal_snapshot_digest == NULL
      || sodium_is_zero (journal_snapshot_digest, 32))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc =
      wyl_policy_store_service_authority_transaction_enter_participant
      (transaction, store);
  g_autofree gchar *sql = g_strdup_printf
      ("SELECT %s FROM service_credential_handoff_remediation_actions"
      " WHERE original_request_id=? AND journal_snapshot_digest=? LIMIT 2;",
      service_handoff_remediation_resolve_columns);
  sqlite3_stmt *stmt = NULL;
  if (rc == WYRELOG_E_OK)
    rc = sql != NULL ? prepare_stmt (store->db, sql, &stmt) : WYRELOG_E_NOMEM;
  if (rc == WYRELOG_E_OK
      && ((rc = bind_text (stmt, 1, original_request_id)) != WYRELOG_E_OK
          || sqlite3_bind_blob (stmt, 2, journal_snapshot_digest, 32,
              SQLITE_TRANSIENT) != SQLITE_OK))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_remediation_resolve_stmt (store, stmt, TRUE,
        out_result);
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
service_handoff_reject_legacy_request_collision (wyl_policy_store_t *store,
    const gchar *request_id)
{
  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = prepare_stmt (store->db,
      "SELECT 1 FROM service_domain_requests WHERE request_id=? LIMIT 1;",
      &stmt);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 1, request_id);
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK)
    rc = step == SQLITE_DONE ? WYRELOG_E_OK :
        (step == SQLITE_ROW ? WYRELOG_E_POLICY :
        service_handoff_sqlite_error (store->db, step));
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
service_handoff_reject_completed_target (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffRemediationInput *input)
{
  if (input->action != WYL_POLICY_HANDOFF_REMEDIATION_REVOKE_AND_WIPE)
    return WYRELOG_E_OK;
  gchar escrow[WYL_ID_STRING_BUF];
  wyl_id_format (input->tuple.escrow_id, escrow, sizeof escrow);
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT 1 FROM service_credential_handoff_remediation_actions"
      " WHERE original_request_id=? AND escrow_id=? AND binding_digest=?"
      " AND successor_credential_id=? AND successor_issuance_generation=?"
      " AND action='revoke_and_wipe' LIMIT 1;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK
      && ((rc = bind_text (stmt, 1, input->tuple.original_request_id))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 2, escrow))
          != WYRELOG_E_OK || sqlite3_bind_blob (stmt, 3,
              input->tuple.binding_digest, 32, SQLITE_TRANSIENT) != SQLITE_OK
          || (rc = bind_text (stmt, 4,
                  input->tuple.successor_credential_id)) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 5,
              (sqlite3_int64) input->tuple.successor_issuance_generation)
          != SQLITE_OK))
    rc = WYRELOG_E_IO;
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW)
    rc = WYRELOG_E_POLICY;
  else if (rc == WYRELOG_E_OK && step != SQLITE_DONE)
    rc = WYRELOG_E_IO;
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
service_handoff_revoke_successor_exact (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffRemediationInput *input, gint64 now_us)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "UPDATE service_credentials SET state='revoked',generation=?,"
      "updated_at_us=?,revoked_by=?,revoked_at_us=? WHERE credential_id=?"
      " AND state='active' AND generation=?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  guint64 revoked_generation = input->tuple.successor_issuance_generation + 1;
  if (rc == WYRELOG_E_OK
      && (sqlite3_bind_int64 (stmt, 1,
              (sqlite3_int64) revoked_generation) != SQLITE_OK
          || sqlite3_bind_int64 (stmt, 2, now_us) != SQLITE_OK
          || (rc = bind_text (stmt, 3, input->current_actor_subject_id))
          != WYRELOG_E_OK || sqlite3_bind_int64 (stmt, 4,
              now_us) != SQLITE_OK
          || (rc = bind_text (stmt, 5,
                  input->tuple.successor_credential_id)) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 6, (sqlite3_int64)
              input->tuple.successor_issuance_generation) != SQLITE_OK))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && sqlite3_changes (store->db) != 1)
    rc = WYRELOG_E_POLICY;
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  rc = service_handoff_map_sqlite_io (store->db, rc);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (service_handoff_should_fail (store,
          WYL_POLICY_HANDOFF_FAIL_AFTER_CLASSIFY_OR_CAS))
    return WYRELOG_E_IO;
  stmt = NULL;
  rc = prepare_stmt (store->db,
      "INSERT INTO service_credential_events(credential_id,subject_id,"
      "tenant_id,event,from_state,to_state,generation,actor_subject_id,"
      "request_id,created_at_us) SELECT credential_id,subject_id,tenant_id,"
      "'revoked','active','revoked',generation,?,?,? FROM service_credentials"
      " WHERE credential_id=? AND state='revoked' AND generation=?;", &stmt);
  if (rc == WYRELOG_E_OK
      && ((rc = bind_text (stmt, 1, input->current_actor_subject_id))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 2,
                  input->remediation_request_id)) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 3, now_us) != SQLITE_OK
          || (rc = bind_text (stmt, 4,
                  input->tuple.successor_credential_id)) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 5,
              (sqlite3_int64) revoked_generation) != SQLITE_OK))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && sqlite3_changes (store->db) != 1)
    rc = WYRELOG_E_POLICY;
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  rc = service_handoff_map_sqlite_io (store->db, rc);
  if (rc == WYRELOG_E_OK && service_handoff_should_fail (store,
          WYL_POLICY_HANDOFF_FAIL_AFTER_SUCCESSOR_EVENT))
    rc = WYRELOG_E_IO;
  return rc;
}

static wyrelog_error_t
service_handoff_insert_remediation (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffRemediationInput *input,
    const guint8 fingerprint[crypto_generichash_BYTES],
    const guint8 incident_fingerprint[crypto_generichash_BYTES],
    WylPolicyServiceHandoffRemediationOutcome outcome,
    WylPolicyServiceHandoffRemediationEscrowOutcome escrow_outcome,
    const WylPolicyServiceSuccessorExactClassification *classification,
    gint64 now_us)
{
  gchar escrow[WYL_ID_STRING_BUF];
  wyl_id_format (input->tuple.escrow_id, escrow, sizeof escrow);
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "INSERT INTO service_credential_handoff_remediation_actions("
      "remediation_request_id,request_fingerprint,incident_fingerprint,"
      "decision_request_id,original_request_id,original_actor_subject_id,"
      "current_actor_subject_id,source_kind,journal_snapshot_digest,"
      "observed_state,source_disposition_id,source_audit_id,source_reason,"
      "oar_source_state,oar_cause,resume_target_state,escrow_id,"
      "binding_digest,successor_credential_id,successor_issuance_generation,"
      "action,confirmation_version,confirmed,outcome,escrow_outcome,"
      "credential_generation_after,revoke_event_id,revoke_event_generation,"
      "revoke_event_request_id,revoke_event_actor_subject_id,"
      "revoke_event_created_at_us,audit_id,created_at_us)"
      " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK
      && ((rc = bind_text (stmt, 1, input->remediation_request_id))
          != WYRELOG_E_OK || sqlite3_bind_blob (stmt, 2, fingerprint, 32,
              SQLITE_TRANSIENT) != SQLITE_OK || sqlite3_bind_blob (stmt, 3,
              incident_fingerprint, 32, SQLITE_TRANSIENT) != SQLITE_OK
          || (rc = bind_text (stmt, 4,
                  input->decision_request_id)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 5, input->tuple.original_request_id))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 6,
                  input->tuple.original_actor_subject_id)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 7, input->current_actor_subject_id))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 8,
                  service_handoff_remediation_source_name
                  (input->source_kind))) != WYRELOG_E_OK
          || sqlite3_bind_blob (stmt, 9, input->journal_snapshot_digest, 32,
              SQLITE_TRANSIENT) != SQLITE_OK || (rc = bind_text (stmt, 10,
                  service_handoff_remediation_state_name
                  (input->observed_state))) != WYRELOG_E_OK
          || (input->source_disposition_id == NULL ?
              sqlite3_bind_null (stmt, 11) : sqlite3_bind_text (stmt, 11,
                  input->source_disposition_id, -1, SQLITE_TRANSIENT))
          != SQLITE_OK || (input->source_audit_id == NULL ?
              sqlite3_bind_null (stmt, 12) : sqlite3_bind_text (stmt, 12,
                  input->source_audit_id, -1, SQLITE_TRANSIENT)) != SQLITE_OK
          || (input->source_reason == 0 ? sqlite3_bind_null (stmt, 13) :
              sqlite3_bind_text (stmt, 13,
                  service_handoff_reason_name (input->source_reason), -1,
                  SQLITE_STATIC)) != SQLITE_OK
          || (input->oar_source_state == 0 ? sqlite3_bind_null (stmt, 14) :
              sqlite3_bind_text (stmt, 14,
                  service_handoff_remediation_state_name
                  (input->oar_source_state), -1, SQLITE_STATIC)) != SQLITE_OK
          || (input->oar_cause == 0 ? sqlite3_bind_null (stmt, 15) :
              sqlite3_bind_text (stmt, 15,
                  service_handoff_remediation_oar_cause_name
                  (input->oar_cause), -1, SQLITE_STATIC)) != SQLITE_OK
          || (input->resume_target_state == 0 ? sqlite3_bind_null (stmt, 16) :
              sqlite3_bind_text (stmt, 16,
                  service_handoff_remediation_state_name
                  (input->resume_target_state), -1, SQLITE_STATIC)) != SQLITE_OK
          || (rc = bind_text (stmt, 17, escrow)) != WYRELOG_E_OK
          || sqlite3_bind_blob (stmt, 18,
              input->tuple.binding_digest, 32, SQLITE_TRANSIENT) != SQLITE_OK
          || (rc = bind_text (stmt, 19,
                  input->tuple.successor_credential_id)) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 20, (sqlite3_int64)
              input->tuple.successor_issuance_generation) != SQLITE_OK
          || (rc = bind_text (stmt, 21,
                  service_handoff_remediation_action_name (input->action)))
          != WYRELOG_E_OK || sqlite3_bind_int (stmt, 22,
              (int) input->confirmation_version) != SQLITE_OK
          || sqlite3_bind_int (stmt, 23, input->confirmed ? 1 : 0)
          != SQLITE_OK || (rc = bind_text (stmt, 24,
                  service_handoff_remediation_outcome_name (outcome)))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 25,
                  service_handoff_remediation_escrow_outcome_name
                  (escrow_outcome))) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 26,
              (sqlite3_int64) classification->observed_generation) != SQLITE_OK
          || (!classification->has_revocation_event ?
              sqlite3_bind_null (stmt, 27) : sqlite3_bind_int64 (stmt, 27,
                  classification->revocation_event_id)) != SQLITE_OK
          || (!classification->has_revocation_event ?
              sqlite3_bind_null (stmt, 28) : sqlite3_bind_int64 (stmt, 28,
                  (sqlite3_int64)
                  classification->revocation_event_generation)) != SQLITE_OK
          || (!classification->has_revocation_event ?
              sqlite3_bind_null (stmt, 29) : sqlite3_bind_text (stmt, 29,
                  classification->revocation_event_request_id, -1,
                  SQLITE_TRANSIENT)) != SQLITE_OK
          || (!classification->has_revocation_event ?
              sqlite3_bind_null (stmt, 30) : sqlite3_bind_text (stmt, 30,
                  classification->revocation_event_actor_subject_id, -1,
                  SQLITE_TRANSIENT)) != SQLITE_OK
          || (!classification->has_revocation_event ?
              sqlite3_bind_null (stmt, 31) : sqlite3_bind_int64 (stmt, 31,
                  classification->revocation_event_created_at_us)) != SQLITE_OK
          || (rc = bind_text (stmt, 32, input->audit_id))
          != WYRELOG_E_OK || sqlite3_bind_int64 (stmt, 33,
              now_us) != SQLITE_OK))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
    rc = (sqlite3_extended_errcode (store->db) & 0xff) == SQLITE_CONSTRAINT ?
        WYRELOG_E_POLICY : WYRELOG_E_IO;
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

wyrelog_error_t
    wyl_policy_store_remediate_service_handoff_exact_core
    (WylServiceAuthorityTransaction * transaction,
    wyl_policy_store_t * store,
    const WylPolicyServiceHandoffRemediationInput * input,
    WylPolicyServiceHandoffRemediationResult * out_result)
{
  if (out_result != NULL)
    wyl_policy_service_handoff_remediation_result_clear (out_result);
  if (store == NULL || out_result == NULL
      || !service_handoff_remediation_shape_valid (input))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc =
      wyl_policy_store_service_authority_transaction_enter_participant
      (transaction, store);
  guint8 fingerprint[crypto_generichash_BYTES] = { 0 };
  guint8 incident_fingerprint[crypto_generichash_BYTES] = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_remediation_incident_fingerprint (input,
        incident_fingerprint);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_remediation_fingerprint (input,
        incident_fingerprint, fingerprint);
  gboolean found = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_remediation_lookup (store, input, fingerprint,
        incident_fingerprint, TRUE, &found, out_result);
  if (rc != WYRELOG_E_OK || found) {
    sodium_memzero (fingerprint, sizeof fingerprint);
    sodium_memzero (incident_fingerprint, sizeof incident_fingerprint);
    return rc;
  }
  /* Replays are validated entirely from their durable action and audit pair;
   * only a fresh mutation samples trusted wall time. */
  gint64 trusted_now = g_get_real_time ();
  rc = service_handoff_reject_legacy_request_collision (store,
      input->remediation_request_id);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_reject_completed_target (store, input);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_remediation_validate_incident (store, input);
  gboolean authoritative_absence = input->source_kind ==
      WYL_POLICY_HANDOFF_REMEDIATION_SOURCE_OPERATOR_ACTION_REQUIRED
      && input->oar_cause ==
      WYL_POLICY_HANDOFF_REMEDIATION_OAR_ESCROW_MISSING
      && input->action == WYL_POLICY_HANDOFF_REMEDIATION_REVOKE_AND_WIPE;
  if (rc == WYRELOG_E_OK && authoritative_absence)
    rc = service_handoff_escrow_absent (store, input->tuple.escrow_id);
  if (rc == WYRELOG_E_OK && authoritative_absence)
    rc = service_handoff_request_escrow_absent (store,
        input->tuple.original_request_id);
  if (rc == WYRELOG_E_OK && !authoritative_absence)
    rc = service_handoff_validate_exact_escrow (store, &input->tuple);
  WylPolicyServiceSuccessorExactClassification classification = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_classify_successor_without_escrow (store,
        &input->tuple, trusted_now, &classification);
  if (rc == WYRELOG_E_OK
      && input->action == WYL_POLICY_HANDOFF_REMEDIATION_RESUME
      && classification.disposition != WYL_POLICY_SERVICE_SUCCESSOR_ACTIVE)
    rc = WYRELOG_E_POLICY;
  gboolean revoked_now = FALSE;
  WylPolicyServiceHandoffRemediationOutcome outcome =
      WYL_POLICY_HANDOFF_REMEDIATION_RECORDED;
  WylPolicyServiceHandoffRemediationEscrowOutcome escrow_outcome =
      input->action == WYL_POLICY_HANDOFF_REMEDIATION_RESUME ?
      WYL_POLICY_HANDOFF_REMEDIATION_ESCROW_RETAINED :
      (authoritative_absence ?
      WYL_POLICY_HANDOFF_REMEDIATION_ESCROW_ALREADY_ABSENT :
      WYL_POLICY_HANDOFF_REMEDIATION_ESCROW_DELETED);
  if (rc == WYRELOG_E_OK && input->action ==
      WYL_POLICY_HANDOFF_REMEDIATION_REVOKE_AND_WIPE) {
    if (classification.disposition == WYL_POLICY_SERVICE_SUCCESSOR_ACTIVE) {
      if (input->tuple.successor_issuance_generation == G_MAXINT64)
        rc = WYRELOG_E_POLICY;
      outcome = WYL_POLICY_HANDOFF_REMEDIATION_REVOKED_AND_WIPED;
    } else if (classification.disposition ==
        WYL_POLICY_SERVICE_SUCCESSOR_EXPIRED) {
      outcome = WYL_POLICY_HANDOFF_REMEDIATION_EXPIRED_AND_WIPED;
    } else if (classification.disposition ==
        WYL_POLICY_SERVICE_SUCCESSOR_REVOKED) {
      outcome = WYL_POLICY_HANDOFF_REMEDIATION_ALREADY_REVOKED_AND_WIPED;
    } else {
      rc = WYRELOG_E_POLICY;
    }
  }
  WylPolicyServiceSuccessorDisposition initial_disposition =
      classification.disposition;
  if (rc == WYRELOG_E_OK && input->action ==
      WYL_POLICY_HANDOFF_REMEDIATION_REVOKE_AND_WIPE
      && classification.disposition == WYL_POLICY_SERVICE_SUCCESSOR_ACTIVE) {
    rc = service_handoff_revoke_successor_exact (store, input, trusted_now);
    revoked_now = rc == WYRELOG_E_OK;
    wyl_policy_service_successor_exact_classification_clear (&classification);
    if (rc == WYRELOG_E_OK)
      rc = service_handoff_classify_successor_without_escrow (store,
          &input->tuple, trusted_now, &classification);
    if (rc == WYRELOG_E_OK
        && (classification.disposition != WYL_POLICY_SERVICE_SUCCESSOR_REVOKED
            || !classification.has_revocation_event
            || g_strcmp0 (classification.revocation_event_request_id,
                input->remediation_request_id) != 0
            || g_strcmp0 (classification.revocation_event_actor_subject_id,
                input->current_actor_subject_id) != 0
            || classification.revocation_event_created_at_us != trusted_now))
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK && !revoked_now
      && service_handoff_should_fail (store,
          WYL_POLICY_HANDOFF_FAIL_AFTER_CLASSIFY_OR_CAS))
    rc = WYRELOG_E_IO;
  /* The append-only action is inserted only after all normalized credential
   * and event facts are known; the surrounding authority savepoint still
   * rolls the claim and prior CAS/event back together on every failure. */
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_insert_remediation (store, input, fingerprint,
        incident_fingerprint, outcome, escrow_outcome, &classification,
        trusted_now);
  if (rc == WYRELOG_E_OK && service_handoff_should_fail (store,
          WYL_POLICY_HANDOFF_FAIL_AFTER_REQUEST_CLAIM))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_append_audit_strict (store, input->audit_id,
        trusted_now, input->current_actor_subject_id,
        input->action == WYL_POLICY_HANDOFF_REMEDIATION_RESUME ?
        "service.credential.handoff.remediation.resume" :
        "service.credential.handoff.remediation.revoke_and_wipe",
        input->tuple.successor_credential_id, input->remediation_request_id);
  if (rc == WYRELOG_E_OK && service_handoff_should_fail (store,
          WYL_POLICY_HANDOFF_FAIL_AFTER_AUDIT))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && input->action ==
      WYL_POLICY_HANDOFF_REMEDIATION_REVOKE_AND_WIPE)
    rc = escrow_outcome == WYL_POLICY_HANDOFF_REMEDIATION_ESCROW_DELETED ?
        service_handoff_delete_exact (store, &input->tuple) : WYRELOG_E_OK;
  if (rc == WYRELOG_E_OK && input->action ==
      WYL_POLICY_HANDOFF_REMEDIATION_REVOKE_AND_WIPE
      && service_handoff_should_fail (store,
          WYL_POLICY_HANDOFF_FAIL_AFTER_ESCROW_DELETE))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && service_handoff_should_fail (store,
          WYL_POLICY_HANDOFF_FAIL_AFTER_PROVENANCE))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_fill_remediation_result (input, input->audit_id,
        outcome, FALSE, revoked_now, initial_disposition, escrow_outcome,
        input->action == WYL_POLICY_HANDOFF_REMEDIATION_REVOKE_AND_WIPE ?
        input->tuple.successor_issuance_generation : 0,
        classification.observed_generation,
        classification.has_revocation_event ?
        classification.revocation_event_id : 0,
        classification.has_revocation_event ?
        classification.revocation_event_generation : 0,
        classification.revocation_event_request_id,
        classification.revocation_event_actor_subject_id,
        classification.has_revocation_event ?
        classification.revocation_event_created_at_us : 0, trusted_now,
        out_result);
  wyl_policy_service_successor_exact_classification_clear (&classification);
  sodium_memzero (fingerprint, sizeof fingerprint);
  sodium_memzero (incident_fingerprint, sizeof incident_fingerprint);
  return rc;
}

static const gchar *service_handoff_cancellation_operation_name
    (WylPolicyServiceHandoffFenceOperation operation)
{
  return operation == WYL_POLICY_HANDOFF_FENCE_ISSUE ? "issue" :
      (operation == WYL_POLICY_HANDOFF_FENCE_ROTATE ? "rotate" : NULL);
}

static gboolean
    service_handoff_cancellation_shape_valid
    (const WylPolicyServiceHandoffCancellationInput * input)
{
  if (input == NULL
      || !service_handoff_request_id_is_canonical
      (input->cancellation_request_id)
      || !service_handoff_request_id_is_canonical (input->decision_request_id)
      || !service_handoff_uuid_is_canonical (input->disposition_id)
      || !service_handoff_uuid_is_canonical (input->audit_id)
      || !service_handoff_exact_tuple_is_valid (&input->tuple)
      || !wyl_policy_service_actor_subject_is_valid
      (input->current_actor_subject_id)
      || g_strcmp0 (input->tuple.original_actor_subject_id,
          input->current_actor_subject_id) == 0
      || g_strcmp0 (input->tuple.original_request_id,
          input->cancellation_request_id) == 0
      || g_strcmp0 (input->tuple.original_request_id,
          input->decision_request_id) == 0
      || g_strcmp0 (input->cancellation_request_id,
          input->decision_request_id) == 0 || input->deadline_at_us <= 0
      || sodium_is_zero (input->target_digest, sizeof input->target_digest))
    return FALSE;
  gboolean committed =
      input->observation ==
      WYL_POLICY_HANDOFF_CANCELLATION_OBSERVATION_COMMITTED;
  gboolean unresolved =
      input->observation ==
      WYL_POLICY_HANDOFF_CANCELLATION_OBSERVATION_PREPARED
      || input->observation ==
      WYL_POLICY_HANDOFF_CANCELLATION_OBSERVATION_TERMINAL_NOT_COMMITTED;
  if ((!committed && !unresolved)
      || (committed && input->tuple.successor_credential_id == NULL)
      || (unresolved && (input->tuple.successor_credential_id != NULL
              || !sodium_is_zero (input->tuple.binding_digest,
                  sizeof input->tuple.binding_digest))))
    return FALSE;
  return (input->operation == WYL_POLICY_HANDOFF_FENCE_ISSUE
      && input->target_a != NULL
      && wyl_policy_service_subject_is_valid (input->target_a,
          strlen (input->target_a)) && input->target_b != NULL
      && wyl_policy_store_tenant_id_is_valid (input->target_b))
      || (input->operation == WYL_POLICY_HANDOFF_FENCE_ROTATE
      && input->target_a != NULL && input->target_b == NULL
      && wyl_service_credential_id_is_canonical (input->target_a,
          strlen (input->target_a)));
}

static const gchar *service_handoff_cancellation_resolution_name
    (WylPolicyServiceHandoffCancellationOutcome outcome);

static wyrelog_error_t
    service_handoff_cancellation_fingerprint
    (const WylPolicyServiceHandoffCancellationInput * input,
    WylPolicyServiceHandoffCancellationOutcome resolution,
    const WylPolicyServiceHandoffExactTuple * resolved_tuple,
    guint8 out[crypto_generichash_BYTES])
{
  gchar escrow[WYL_ID_STRING_BUF];
  gchar generation[32];
  gchar deadline[32];
  gchar binding[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES * 2 + 1];
  gchar target_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES * 2 + 1];
  const gchar *resolution_name =
      service_handoff_cancellation_resolution_name (resolution);
  if (resolved_tuple == NULL || resolution_name == NULL
      || wyl_id_format (resolved_tuple->escrow_id, escrow, sizeof escrow)
      != WYRELOG_E_OK
      || ((resolution == WYL_POLICY_HANDOFF_CANCELLATION_COMMITTED_ATTENTION)
          != (resolved_tuple->successor_credential_id != NULL)))
    return WYRELOG_E_INVALID;
  g_snprintf (generation, sizeof generation, "%" G_GUINT64_FORMAT,
      resolved_tuple->successor_issuance_generation);
  g_snprintf (deadline, sizeof deadline, "%" G_GINT64_FORMAT,
      input->deadline_at_us);
  sodium_bin2hex (binding, sizeof binding, resolved_tuple->binding_digest,
      sizeof resolved_tuple->binding_digest);
  sodium_bin2hex (target_digest, sizeof target_digest, input->target_digest,
      sizeof input->target_digest);
  const gchar *fields[] = {
    input->cancellation_request_id, input->decision_request_id,
    input->tuple.original_request_id,
    input->tuple.original_actor_subject_id, input->current_actor_subject_id,
    resolution_name, escrow, binding,
    resolved_tuple->successor_credential_id != NULL ?
        resolved_tuple->successor_credential_id : "",
    generation, service_handoff_cancellation_operation_name (input->operation),
    input->target_a, input->target_b != NULL ? input->target_b : "",
    target_digest, deadline, input->disposition_id, input->audit_id,
  };
  return service_handoff_hash_fields
      ("wyrelog.service-handoff-cancellation.v2", fields,
      G_N_ELEMENTS (fields), out);
}

static wyrelog_error_t
    service_handoff_fill_cancellation_result
    (WylPolicyServiceHandoffCancellationOutcome outcome,
    const gchar * successor_credential_id, guint64 successor_generation,
    const guint8 binding_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES],
    const gchar * disposition_id, const gchar * audit_id,
    gint64 created_at_us, gboolean replayed,
    WylPolicyServiceHandoffCancellationResult * out)
{
  if (created_at_us <= 0
      || (outcome == WYL_POLICY_HANDOFF_CANCELLATION_COMMITTED_ATTENTION
          && (successor_credential_id == NULL || successor_generation == 0
              || binding_digest == NULL
              || sodium_is_zero (binding_digest,
                  WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES)))
      || (outcome == WYL_POLICY_HANDOFF_CANCELLATION_TERMINAL_NOT_COMMITTED
          && (successor_credential_id != NULL || successor_generation != 0)))
    return WYRELOG_E_POLICY;
  out->disposition_id = service_handoff_try_strdup (disposition_id);
  out->audit_id = service_handoff_try_strdup (audit_id);
  if (out->disposition_id == NULL || out->audit_id == NULL) {
    wyl_policy_service_handoff_cancellation_result_clear (out);
    return WYRELOG_E_NOMEM;
  }
  out->created_at_us = created_at_us;
  out->replayed = replayed;
  out->outcome = outcome;
  if (successor_credential_id != NULL) {
    g_strlcpy (out->successor_credential_id, successor_credential_id,
        sizeof out->successor_credential_id);
    out->successor_issuance_generation = successor_generation;
    memcpy (out->binding_digest, binding_digest, sizeof out->binding_digest);
  }
  return WYRELOG_E_OK;
}

static void
    service_handoff_cancellation_proof
    (const WylPolicyServiceHandoffCancellationInput * input,
    WylPolicyServiceHandoffMaintenanceProof * proof)
{
  *proof = (WylPolicyServiceHandoffMaintenanceProof) {
  .tuple = input->tuple,.operation =
        input->operation == WYL_POLICY_HANDOFF_FENCE_ISSUE ?
        WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE :
        WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE,.subject_id =
        input->operation == WYL_POLICY_HANDOFF_FENCE_ISSUE ?
        input->target_a : NULL,.tenant_id =
        input->operation == WYL_POLICY_HANDOFF_FENCE_ISSUE ?
        input->target_b : NULL,.old_credential_id =
        input->operation == WYL_POLICY_HANDOFF_FENCE_ROTATE ?
        input->target_a : NULL,.deadline_at_us = input->deadline_at_us,};
  proof->tuple.successor_credential_id = NULL;
  proof->tuple.successor_issuance_generation = 0;
  sodium_memzero (proof->tuple.binding_digest,
      sizeof proof->tuple.binding_digest);
  memcpy (proof->target_digest, input->target_digest,
      sizeof proof->target_digest);
}

static const gchar *service_handoff_cancellation_resolution_name
    (WylPolicyServiceHandoffCancellationOutcome outcome)
{
  return outcome == WYL_POLICY_HANDOFF_CANCELLATION_COMMITTED_ATTENTION ?
      "committed_attention" :
      (outcome == WYL_POLICY_HANDOFF_CANCELLATION_TERMINAL_NOT_COMMITTED ?
      "terminal_not_committed" : NULL);
}

static WylPolicyServiceHandoffCancellationOutcome
service_handoff_cancellation_resolution_parse (const gchar *resolution)
{
  if (g_strcmp0 (resolution, "committed_attention") == 0)
    return WYL_POLICY_HANDOFF_CANCELLATION_COMMITTED_ATTENTION;
  if (g_strcmp0 (resolution, "terminal_not_committed") == 0)
    return WYL_POLICY_HANDOFF_CANCELLATION_TERMINAL_NOT_COMMITTED;
  return 0;
}

static wyrelog_error_t
service_handoff_validate_cancellation_disposition (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffCancellationInput *input,
    WylPolicyServiceHandoffCancellationOutcome resolution,
    const WylPolicyServiceHandoffExactTuple *resolved_tuple,
    gint64 created_at_us, gboolean strict_cardinality)
{
  WylPolicyServiceHandoffMaintenanceProof proof = { 0 };
  service_handoff_cancellation_proof (input, &proof);
  WylPolicyServiceHandoffNoCommitEvidence evidence = { 0 };
  WylPolicyServiceHandoffDispositionInput disposition = {
    .disposition_id = input->disposition_id,
    .audit_id = input->audit_id,
    .tuple = *resolved_tuple,
    .actor_subject_id = input->current_actor_subject_id,
    .reason = resolution ==
        WYL_POLICY_HANDOFF_CANCELLATION_COMMITTED_ATTENTION ?
        WYL_POLICY_HANDOFF_DISPOSITION_OPERATION_CANCELLED :
        WYL_POLICY_HANDOFF_DISPOSITION_NOT_COMMITTED,
    .outcome = resolution ==
        WYL_POLICY_HANDOFF_CANCELLATION_COMMITTED_ATTENTION ?
        WYL_POLICY_HANDOFF_OUTCOME_ATTENTION_REQUIRED :
        WYL_POLICY_HANDOFF_OUTCOME_TERMINAL_NOT_COMMITTED,
  };
  wyrelog_error_t rc = WYRELOG_E_OK;
  if (resolution == WYL_POLICY_HANDOFF_CANCELLATION_TERMINAL_NOT_COMMITTED) {
    rc = service_handoff_maintenance_no_commit_evidence (&proof, &evidence);
    disposition.no_commit_evidence = &evidence;
  }
  guint8 semantic_key[crypto_generichash_BYTES] = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_disposition_semantic_key (&disposition, semantic_key);
  gchar escrow[WYL_ID_STRING_BUF];
  if (rc == WYRELOG_E_OK
      && wyl_id_format (resolved_tuple->escrow_id, escrow, sizeof escrow)
      != WYRELOG_E_OK)
    rc = WYRELOG_E_INVALID;
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT semantic_key,original_request_id,escrow_id,binding_digest,"
      "successor_credential_id,successor_issuance_generation,"
      "actor_subject_id,reason,outcome,audit_id,created_at_us FROM"
      " service_credential_handoff_dispositions WHERE disposition_id=?;";
  if (rc == WYRELOG_E_OK)
    rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 1, input->disposition_id);
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW) {
    gboolean exact = sqlite3_column_type (stmt, 0) == SQLITE_BLOB
        && sqlite3_column_bytes (stmt, 0) == sizeof semantic_key
        && sodium_memcmp (sqlite3_column_blob (stmt, 0), semantic_key,
        sizeof semantic_key) == 0
        && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 1),
        resolved_tuple->original_request_id) == 0
        && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 2),
        escrow) == 0 && sqlite3_column_type (stmt, 3) == SQLITE_BLOB
        && sqlite3_column_bytes (stmt, 3) == 32
        && sodium_memcmp (sqlite3_column_blob (stmt, 3),
        resolved_tuple->binding_digest, 32) == 0
        && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 4),
        resolved_tuple->successor_credential_id) == 0
        && ((resolved_tuple->successor_issuance_generation == 0
            && sqlite3_column_type (stmt, 5) == SQLITE_NULL)
        || (resolved_tuple->successor_issuance_generation != 0
            && sqlite3_column_type (stmt, 5) == SQLITE_INTEGER
            && (guint64) sqlite3_column_int64 (stmt, 5) ==
            resolved_tuple->successor_issuance_generation))
        && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 6),
        input->current_actor_subject_id) == 0
        && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 7),
        service_handoff_reason_name (disposition.reason)) == 0
        && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 8),
        service_handoff_outcome_name (disposition.outcome)) == 0
        && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 9),
        input->audit_id) == 0
        && sqlite3_column_type (stmt, 10) == SQLITE_INTEGER
        && sqlite3_column_int64 (stmt, 10) == created_at_us;
    rc = exact
        && sqlite3_step (stmt) == SQLITE_DONE ? WYRELOG_E_OK : WYRELOG_E_POLICY;
  } else if (rc == WYRELOG_E_OK) {
    rc = step == SQLITE_DONE ? WYRELOG_E_POLICY :
        service_handoff_sqlite_error (store->db, step);
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  sodium_memzero (semantic_key, sizeof semantic_key);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_validate_exact_audit_pair (store, input->audit_id,
        created_at_us, input->current_actor_subject_id,
        "service.credential.handoff.cancel",
        resolved_tuple->successor_credential_id != NULL ?
        resolved_tuple->successor_credential_id :
        resolved_tuple->original_request_id, input->cancellation_request_id);
  if (rc == WYRELOG_E_OK
      && resolution == WYL_POLICY_HANDOFF_CANCELLATION_TERMINAL_NOT_COMMITTED)
    rc = service_handoff_maintenance_validate_no_commit (store, &proof,
        input->disposition_id, input->audit_id,
        input->current_actor_subject_id);
  stmt = NULL;
  static const gchar *cardinality_sql =
      "SELECT count(*),"
      " sum(CASE WHEN disposition_id=? THEN 1 ELSE 0 END),"
      " sum(CASE WHEN disposition_id<>?"
      "  AND reason NOT IN ('successor_expired','successor_revoked')"
      "  THEN 1 ELSE 0 END)"
      " FROM service_credential_handoff_dispositions"
      " WHERE original_request_id=?;";
  if (rc == WYRELOG_E_OK)
    rc = prepare_stmt (store->db, cardinality_sql, &stmt);
  if (rc == WYRELOG_E_OK
      && ((rc = bind_text (stmt, 1, input->disposition_id)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 2, input->disposition_id)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 3,
                  resolved_tuple->original_request_id)) != WYRELOG_E_OK))
    rc = WYRELOG_E_IO;
  step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW) {
    gint64 total = sqlite3_column_int64 (stmt, 0);
    gint64 linked = sqlite3_column_int64 (stmt, 1);
    gint64 foreign_non_precedence = sqlite3_column_int64 (stmt, 2);
    rc = linked == 1 && foreign_non_precedence == 0
        && (!strict_cardinality || total == 1)
        && sqlite3_step (stmt) == SQLITE_DONE ? WYRELOG_E_OK : WYRELOG_E_POLICY;
  } else if (rc == WYRELOG_E_OK) {
    rc = service_handoff_sqlite_error (store->db, step);
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
    service_handoff_cancellation_lookup
    (wyl_policy_store_t * store,
    const WylPolicyServiceHandoffCancellationInput * input,
    gboolean validate_authority, gboolean validate_escrow,
    gboolean strict_cardinality,
    gboolean * out_found, WylPolicyServiceHandoffCancellationResult * out)
{
  *out_found = FALSE;
  gchar escrow[WYL_ID_STRING_BUF];
  wyl_id_format (input->tuple.escrow_id, escrow, sizeof escrow);
  WylPolicyServiceHandoffMaintenanceProof proof = { 0 };
  service_handoff_cancellation_proof (input, &proof);
  guint8 proof_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES] = { 0 };
  wyrelog_error_t rc = service_handoff_maintenance_proof_digest (&proof,
      proof_digest);
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT request_fingerprint,decision_request_id,original_request_id,"
      "original_actor_subject_id,current_actor_subject_id,resolution,escrow_id,"
      "binding_digest,successor_credential_id,successor_issuance_generation,"
      "operation,target_a,target_b,target_digest,maintenance_proof_digest,"
      "deadline_at_us,"
      "disposition_id,audit_id,created_at_us FROM"
      " service_credential_handoff_cancellation_claims"
      " WHERE cancellation_request_id=?;";
  if (rc == WYRELOG_E_OK)
    rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 1, input->cancellation_request_id);
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW) {
    *out_found = TRUE;
    WylPolicyServiceHandoffCancellationOutcome resolution =
        service_handoff_cancellation_resolution_parse
        ((const gchar *) sqlite3_column_text (stmt, 5));
    const gchar *successor = (const gchar *) sqlite3_column_text (stmt, 8);
    guint64 generation = sqlite3_column_type (stmt, 9) == SQLITE_INTEGER ?
        (guint64) sqlite3_column_int64 (stmt, 9) : 0;
    g_autofree gchar *resolved_successor =
        successor != NULL ? service_handoff_try_strdup (successor) : NULL;
    g_autofree gchar *disposition = service_handoff_try_strdup
        ((const gchar *) sqlite3_column_text (stmt, 16));
    g_autofree gchar *audit = service_handoff_try_strdup
        ((const gchar *) sqlite3_column_text (stmt, 17));
    gint64 created_at_us = sqlite3_column_int64 (stmt, 18);
    WylPolicyServiceHandoffExactTuple resolved = input->tuple;
    resolved.successor_credential_id = resolved_successor;
    resolved.successor_issuance_generation = generation;
    if (sqlite3_column_type (stmt, 7) == SQLITE_BLOB
        && sqlite3_column_bytes (stmt, 7) ==
        WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES)
      memcpy (resolved.binding_digest, sqlite3_column_blob (stmt, 7),
          sizeof resolved.binding_digest);
    gboolean resolution_shape =
        (resolution == WYL_POLICY_HANDOFF_CANCELLATION_COMMITTED_ATTENTION
        && resolved_successor != NULL && generation > 0
        && !sodium_is_zero (resolved.binding_digest,
            sizeof resolved.binding_digest))
        || (resolution ==
        WYL_POLICY_HANDOFF_CANCELLATION_TERMINAL_NOT_COMMITTED
        && resolved_successor == NULL && generation == 0
        && sodium_is_zero (resolved.binding_digest,
            sizeof resolved.binding_digest));
    gboolean observation_exact =
        (input->observation ==
        WYL_POLICY_HANDOFF_CANCELLATION_OBSERVATION_PREPARED)
        || (input->observation ==
        WYL_POLICY_HANDOFF_CANCELLATION_OBSERVATION_COMMITTED
        && resolution == WYL_POLICY_HANDOFF_CANCELLATION_COMMITTED_ATTENTION
        && g_strcmp0 (input->tuple.successor_credential_id,
            resolved_successor) == 0
        && input->tuple.successor_issuance_generation == generation
        && sodium_memcmp (input->tuple.binding_digest,
            resolved.binding_digest, sizeof resolved.binding_digest) == 0)
        || (input->observation ==
        WYL_POLICY_HANDOFF_CANCELLATION_OBSERVATION_TERMINAL_NOT_COMMITTED
        && resolution ==
        WYL_POLICY_HANDOFF_CANCELLATION_TERMINAL_NOT_COMMITTED);
    guint8 expected_fingerprint[crypto_generichash_BYTES] = { 0 };
    if (resolution_shape)
      rc = service_handoff_cancellation_fingerprint (input, resolution,
          &resolved, expected_fingerprint);
    gboolean exact = sqlite3_column_type (stmt, 0) == SQLITE_BLOB
        && sqlite3_column_bytes (stmt, 0) == 32
        && sodium_memcmp (sqlite3_column_blob (stmt, 0), expected_fingerprint,
        32) == 0 && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 1),
        input->decision_request_id) == 0
        && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 2),
        input->tuple.original_request_id) == 0
        && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 3),
        input->tuple.original_actor_subject_id) == 0
        && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 4),
        input->current_actor_subject_id) == 0
        && resolution_shape && observation_exact
        && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 6),
        escrow) == 0 && sqlite3_column_type (stmt, 7) == SQLITE_BLOB
        && sqlite3_column_bytes (stmt, 7) == 32
        && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 10),
        service_handoff_cancellation_operation_name (input->operation)) == 0
        && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 11),
        input->target_a) == 0
        && g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 12),
        input->target_b) == 0 && sqlite3_column_type (stmt, 13) == SQLITE_BLOB
        && sqlite3_column_bytes (stmt, 13) == 32
        && sodium_memcmp (sqlite3_column_blob (stmt, 13),
        input->target_digest, 32) == 0
        && sqlite3_column_type (stmt, 14) == SQLITE_BLOB
        && sqlite3_column_bytes (stmt, 14) == 32
        && sodium_memcmp (sqlite3_column_blob (stmt, 14), proof_digest, 32) == 0
        && sqlite3_column_int64 (stmt, 15) == input->deadline_at_us
        && g_strcmp0 (disposition, input->disposition_id) == 0
        && g_strcmp0 (audit, input->audit_id) == 0
        && sqlite3_column_type (stmt, 18) == SQLITE_INTEGER
        && created_at_us > 0;
    if (rc != WYRELOG_E_OK) {
      /* Preserve the normalized fingerprint error. */
    } else if ((successor != NULL && resolved_successor == NULL)
        || disposition == NULL || audit == NULL)
      rc = WYRELOG_E_NOMEM;
    else
      rc = exact && sqlite3_step (stmt) == SQLITE_DONE ? WYRELOG_E_OK :
          WYRELOG_E_POLICY;
    sodium_memzero (expected_fingerprint, sizeof expected_fingerprint);
    if (rc == WYRELOG_E_OK)
      rc = service_handoff_validate_cancellation_disposition (store, input,
          resolution, &resolved, created_at_us, strict_cardinality);
    if (rc == WYRELOG_E_OK
        && validate_authority
        && resolution == WYL_POLICY_HANDOFF_CANCELLATION_COMMITTED_ATTENTION) {
      WylPolicyServiceHandoffCancellationInput resolved_input = *input;
      resolved_input.tuple = resolved;
      resolved_input.observation =
          WYL_POLICY_HANDOFF_CANCELLATION_OBSERVATION_COMMITTED;
      rc = service_handoff_cancellation_validate_committed (store,
          &resolved_input, validate_escrow);
    }
    if (rc == WYRELOG_E_OK)
      rc = service_handoff_fill_cancellation_result (resolution,
          resolved_successor, generation, resolved.binding_digest,
          disposition, audit, created_at_us, TRUE, out);
  } else if (rc == WYRELOG_E_OK && step != SQLITE_DONE) {
    rc = service_handoff_sqlite_error (store->db, step);
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  sodium_memzero (proof_digest, sizeof proof_digest);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
service_handoff_cancellation_validate_committed (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffCancellationInput *input,
    gboolean validate_escrow)
{
  WylServiceCredentialFenceOperation operation =
      input->operation == WYL_POLICY_HANDOFF_FENCE_ISSUE ?
      WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE :
      WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE;
  guint8 expected[crypto_generichash_BYTES] = { 0 };
  guint8 committed[crypto_generichash_BYTES] = { 0 };
  gchar credential[WYL_SERVICE_CREDENTIAL_ID_BUF] = { 0 };
  guint64 generation = 0;
  gboolean operation_matches = FALSE;
  wyrelog_error_t rc =
      wyl_policy_store_service_credential_operation_fence_fingerprint
      (operation, input->target_a, strlen (input->target_a), input->target_b,
      input->target_b != NULL ? strlen (input->target_b) : 0, expected);
  if (rc == WYRELOG_E_OK)
    rc = service_credential_operation_fence_committed_lookup_db (store->db,
        input->tuple.original_request_id, operation, &operation_matches,
        committed, credential, &generation);
  if (rc == WYRELOG_E_NOT_FOUND)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK
      && (!operation_matches
          || sodium_memcmp (expected, committed, sizeof expected) != 0
          || g_strcmp0 (credential,
              input->tuple.successor_credential_id) != 0
          || generation != input->tuple.successor_issuance_generation))
    rc = WYRELOG_E_POLICY;
  sodium_memzero (expected, sizeof expected);
  sodium_memzero (committed, sizeof committed);
  sodium_memzero (credential, sizeof credential);
  if (rc == WYRELOG_E_OK && !validate_escrow)
    return WYRELOG_E_OK;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_validate_exact_escrow (store, &input->tuple);
  gchar escrow[WYL_ID_STRING_BUF];
  sqlite3_stmt *stmt = NULL;
  if (rc == WYRELOG_E_OK
      && wyl_id_format (input->tuple.escrow_id, escrow, sizeof escrow)
      != WYRELOG_E_OK)
    rc = WYRELOG_E_INVALID;
  if (rc == WYRELOG_E_OK)
    rc = prepare_stmt (store->db,
        "SELECT operation,target_digest,deadline_at_us FROM"
        " service_credential_handoff_escrows WHERE escrow_id=?;", &stmt);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 1, escrow);
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW) {
    gboolean exact = g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 0),
        service_handoff_cancellation_operation_name (input->operation)) == 0
        && sqlite3_column_type (stmt, 1) == SQLITE_BLOB
        && sqlite3_column_bytes (stmt, 1) == 32
        && sodium_memcmp (sqlite3_column_blob (stmt, 1),
        input->target_digest, 32) == 0
        && sqlite3_column_type (stmt, 2) == SQLITE_INTEGER
        && sqlite3_column_int64 (stmt, 2) == input->deadline_at_us;
    rc = exact && sqlite3_step (stmt) == SQLITE_DONE ? WYRELOG_E_OK :
        WYRELOG_E_POLICY;
  } else if (rc == WYRELOG_E_OK) {
    rc = step == SQLITE_DONE ? WYRELOG_E_POLICY :
        service_handoff_sqlite_error (store->db, step);
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
    service_handoff_cancellation_reject_existing_artifacts
    (wyl_policy_store_t * store,
    const WylPolicyServiceHandoffCancellationInput * input)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT"
      " (SELECT count(*) FROM service_credential_handoff_cancellation_claims"
      "  WHERE original_request_id=?),"
      " (SELECT count(*) FROM service_credential_handoff_dispositions"
      "  WHERE original_request_id=?);";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK
      && ((rc = bind_text (stmt, 1, input->tuple.original_request_id))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 2,
                  input->tuple.original_request_id)) != WYRELOG_E_OK))
    rc = WYRELOG_E_IO;
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW)
    rc = sqlite3_column_int64 (stmt, 0) == 0
        && sqlite3_column_int64 (stmt, 1) == 0
        && sqlite3_step (stmt) == SQLITE_DONE ? WYRELOG_E_OK : WYRELOG_E_POLICY;
  else if (rc == WYRELOG_E_OK)
    rc = service_handoff_sqlite_error (store->db, step);
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
service_handoff_cancellation_now (wyl_policy_store_t *store, gint64 *out_now_us)
{
  gint64 now_us = store->service_handoff_maintenance_now != NULL ?
      store->service_handoff_maintenance_now
      (store->service_handoff_maintenance_clock_data) : g_get_real_time ();
  if (now_us <= 0)
    return WYRELOG_E_INVALID;
  *out_now_us = now_us;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
service_handoff_cancellation_insert (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffCancellationInput *input,
    WylPolicyServiceHandoffCancellationOutcome resolution,
    const WylPolicyServiceHandoffExactTuple *resolved_tuple,
    const guint8 fingerprint[crypto_generichash_BYTES],
    const guint8 proof_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES],
    gint64 now_us)
{
  gchar escrow[WYL_ID_STRING_BUF];
  wyl_id_format (resolved_tuple->escrow_id, escrow, sizeof escrow);
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "INSERT INTO service_credential_handoff_cancellation_claims("
      "cancellation_request_id,request_fingerprint,decision_request_id,"
      "original_request_id,original_actor_subject_id,current_actor_subject_id,"
      "resolution,escrow_id,binding_digest,successor_credential_id,"
      "successor_issuance_generation,operation,target_a,target_b,target_digest,"
      "maintenance_proof_digest,deadline_at_us,disposition_id,audit_id,"
      "created_at_us)" " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK
      && ((rc = bind_text (stmt, 1, input->cancellation_request_id))
          != WYRELOG_E_OK || sqlite3_bind_blob (stmt, 2, fingerprint, 32,
              SQLITE_TRANSIENT) != SQLITE_OK || (rc = bind_text (stmt, 3,
                  input->decision_request_id)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 4, input->tuple.original_request_id))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 5,
                  input->tuple.original_actor_subject_id)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 6, input->current_actor_subject_id))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 7,
                  service_handoff_cancellation_resolution_name (resolution)))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 8, escrow))
          != WYRELOG_E_OK || sqlite3_bind_blob (stmt, 9,
              resolved_tuple->binding_digest, 32, SQLITE_TRANSIENT) != SQLITE_OK
          || (resolved_tuple->successor_credential_id == NULL ?
              sqlite3_bind_null (stmt, 10) : sqlite3_bind_text (stmt, 10,
                  resolved_tuple->successor_credential_id, -1,
                  SQLITE_TRANSIENT)) != SQLITE_OK
          || (resolved_tuple->successor_issuance_generation == 0 ?
              sqlite3_bind_null (stmt, 11) : sqlite3_bind_int64 (stmt, 11,
                  (sqlite3_int64)
                  resolved_tuple->successor_issuance_generation)) != SQLITE_OK
          || (rc = bind_text (stmt, 12,
                  service_handoff_cancellation_operation_name
                  (input->operation))) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 13, input->target_a)) != WYRELOG_E_OK
          || (input->target_b == NULL ? sqlite3_bind_null (stmt, 14) :
              sqlite3_bind_text (stmt, 14, input->target_b, -1,
                  SQLITE_TRANSIENT)) != SQLITE_OK
          || sqlite3_bind_blob (stmt, 15, input->target_digest, 32,
              SQLITE_TRANSIENT) != SQLITE_OK
          || sqlite3_bind_blob (stmt, 16, proof_digest, 32,
              SQLITE_TRANSIENT) != SQLITE_OK
          || sqlite3_bind_int64 (stmt, 17, input->deadline_at_us) != SQLITE_OK
          || (rc = bind_text (stmt, 18, input->disposition_id))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 19, input->audit_id))
          != WYRELOG_E_OK || sqlite3_bind_int64 (stmt, 20, now_us)
          != SQLITE_OK))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
    rc = service_handoff_sqlite_error (store->db,
        sqlite3_extended_errcode (store->db));
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

wyrelog_error_t
    wyl_policy_store_handoff_claim_cancellation_core
    (WylServiceAuthorityTransaction * transaction, wyl_policy_store_t * store,
    const WylPolicyServiceHandoffCancellationInput * input,
    WylPolicyServiceHandoffCancellationResult * out_result)
{
  if (out_result != NULL)
    wyl_policy_service_handoff_cancellation_result_clear (out_result);
  if (store == NULL || out_result == NULL
      || !service_handoff_cancellation_shape_valid (input))
    return WYRELOG_E_INVALID;
  /* A PREPARED cancellation must let fence reconciliation acquire the first
   * write intent.  Exact-claim recovery is read before both that acquisition
   * and the mutable trusted clock. */
  wyrelog_error_t rc = service_authority_transaction_validate_active
      (transaction, store);
  guint8 fingerprint[crypto_generichash_BYTES] = { 0 };
  gboolean found = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_cancellation_lookup (store, input, TRUE, TRUE, TRUE,
        &found, out_result);
  if (rc != WYRELOG_E_OK || found) {
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_service_authority_transaction_enter_participant
          (transaction, store);
    sodium_memzero (fingerprint, sizeof fingerprint);
    return rc;
  }
  if (input->observation ==
      WYL_POLICY_HANDOFF_CANCELLATION_OBSERVATION_TERMINAL_NOT_COMMITTED) {
    sodium_memzero (fingerprint, sizeof fingerprint);
    return WYRELOG_E_POLICY;
  }
  gint64 trusted_now = 0;
  rc = service_handoff_cancellation_now (store, &trusted_now);
  if (rc == WYRELOG_E_OK && trusted_now >= input->deadline_at_us)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_reject_legacy_request_collision (store,
        input->cancellation_request_id);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_cancellation_reject_existing_artifacts (store, input);

  WylPolicyServiceHandoffMaintenanceProof proof = { 0 };
  service_handoff_cancellation_proof (input, &proof);
  guint8 proof_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES] = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_maintenance_proof_digest (&proof, proof_digest);
  WylPolicyServiceHandoffCancellationOutcome resolution = 0;
  WylPolicyServiceHandoffExactTuple resolved = input->tuple;
  WylServiceCredentialFenceResult fence = { 0 };
  wyl_policy_service_handoff_escrow_info_t escrow = { 0 };

  if (rc == WYRELOG_E_OK && input->observation ==
      WYL_POLICY_HANDOFF_CANCELLATION_OBSERVATION_PREPARED)
    rc = wyl_policy_store_reconcile_service_credential_operation_fence
        (transaction, store, NULL, proof.operation,
        proof.tuple.original_request_id, proof.subject_id, proof.tenant_id,
        proof.old_credential_id, &fence);
  if (rc == WYRELOG_E_OK && input->observation ==
      WYL_POLICY_HANDOFF_CANCELLATION_OBSERVATION_PREPARED
      && fence.state == WYL_SERVICE_CREDENTIAL_FENCE_RESULT_CONFLICT)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && input->observation ==
      WYL_POLICY_HANDOFF_CANCELLATION_OBSERVATION_PREPARED
      && fence.state == WYL_SERVICE_CREDENTIAL_FENCE_RESULT_COMMITTED) {
    ServiceHandoffMaintenanceEscrowState escrow_state = 0;
    rc = service_handoff_maintenance_classify_escrow (store, &proof,
        fence.successor_credential_id, fence.successor_generation, NULL,
        &escrow_state, &escrow);
    if (rc == WYRELOG_E_OK
        && escrow_state != SERVICE_HANDOFF_MAINTENANCE_ESCROW_EXACT)
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK) {
      resolution = WYL_POLICY_HANDOFF_CANCELLATION_COMMITTED_ATTENTION;
      resolved.successor_credential_id = fence.successor_credential_id;
      resolved.successor_issuance_generation = fence.successor_generation;
      memcpy (resolved.binding_digest, escrow.binding_digest,
          sizeof resolved.binding_digest);
    }
  } else if (rc == WYRELOG_E_OK && input->observation ==
      WYL_POLICY_HANDOFF_CANCELLATION_OBSERVATION_PREPARED
      && fence.state ==
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL) {
    resolution = WYL_POLICY_HANDOFF_CANCELLATION_TERMINAL_NOT_COMMITTED;
  } else if (rc == WYRELOG_E_OK && input->observation ==
      WYL_POLICY_HANDOFF_CANCELLATION_OBSERVATION_PREPARED) {
    rc = WYRELOG_E_POLICY;
  }

  if (rc == WYRELOG_E_OK && input->observation ==
      WYL_POLICY_HANDOFF_CANCELLATION_OBSERVATION_COMMITTED) {
    rc = wyl_policy_store_service_authority_transaction_enter_participant
        (transaction, store);
    if (rc == WYRELOG_E_OK)
      resolution = WYL_POLICY_HANDOFF_CANCELLATION_COMMITTED_ATTENTION;
  }

  if (rc == WYRELOG_E_OK
      && resolution == WYL_POLICY_HANDOFF_CANCELLATION_COMMITTED_ATTENTION) {
    WylPolicyServiceHandoffCancellationInput resolved_input = *input;
    resolved_input.tuple = resolved;
    memcpy (resolved_input.target_digest, input->target_digest,
        sizeof resolved_input.target_digest);
    rc = service_handoff_cancellation_validate_committed (store,
        &resolved_input, TRUE);
  }
  if (rc == WYRELOG_E_OK
      && resolution == WYL_POLICY_HANDOFF_CANCELLATION_TERMINAL_NOT_COMMITTED)
    rc = service_handoff_maintenance_validate_no_commit (store, &proof,
        input->disposition_id, input->audit_id,
        input->current_actor_subject_id);

  WylPolicyServiceSuccessorExactClassification classification = { 0 };
  if (rc == WYRELOG_E_OK
      && resolution == WYL_POLICY_HANDOFF_CANCELLATION_COMMITTED_ATTENTION)
    rc = wyl_policy_store_classify_service_credential_successor_exact_core
        (transaction, store, &resolved, trusted_now, &classification);
  if (rc == WYRELOG_E_OK
      && resolution == WYL_POLICY_HANDOFF_CANCELLATION_COMMITTED_ATTENTION
      && classification.disposition != WYL_POLICY_SERVICE_SUCCESSOR_ACTIVE)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_cancellation_fingerprint (input, resolution,
        &resolved, fingerprint);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_cancellation_insert (store, input, resolution,
        &resolved, fingerprint, proof_digest, trusted_now);
  if (rc == WYRELOG_E_OK && service_handoff_should_fail (store,
          WYL_POLICY_HANDOFF_FAIL_AFTER_REQUEST_CLAIM))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_append_audit_strict (store, input->audit_id,
        trusted_now, input->current_actor_subject_id,
        "service.credential.handoff.cancel",
        resolved.successor_credential_id != NULL ?
        resolved.successor_credential_id : resolved.original_request_id,
        input->cancellation_request_id);
  if (rc == WYRELOG_E_OK && service_handoff_should_fail (store,
          WYL_POLICY_HANDOFF_FAIL_AFTER_AUDIT))
    rc = WYRELOG_E_IO;
  WylPolicyServiceHandoffDispositionInput disposition = {
    .disposition_id = input->disposition_id,
    .audit_id = input->audit_id,
    .tuple = resolved,
    .actor_subject_id = input->current_actor_subject_id,
    .reason = resolution ==
        WYL_POLICY_HANDOFF_CANCELLATION_COMMITTED_ATTENTION ?
        WYL_POLICY_HANDOFF_DISPOSITION_OPERATION_CANCELLED :
        WYL_POLICY_HANDOFF_DISPOSITION_NOT_COMMITTED,
    .outcome = resolution ==
        WYL_POLICY_HANDOFF_CANCELLATION_COMMITTED_ATTENTION ?
        WYL_POLICY_HANDOFF_OUTCOME_ATTENTION_REQUIRED :
        WYL_POLICY_HANDOFF_OUTCOME_TERMINAL_NOT_COMMITTED,
  };
  WylPolicyServiceHandoffNoCommitEvidence evidence = { 0 };
  if (rc == WYRELOG_E_OK
      && resolution == WYL_POLICY_HANDOFF_CANCELLATION_TERMINAL_NOT_COMMITTED) {
    rc = service_handoff_maintenance_no_commit_evidence (&proof, &evidence);
    disposition.no_commit_evidence = &evidence;
  }
  guint8 semantic_key[crypto_generichash_BYTES] = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_disposition_semantic_key (&disposition, semantic_key);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_disposition_insert (store, &disposition,
        semantic_key, trusted_now);
  if (rc == WYRELOG_E_OK && service_handoff_should_fail (store,
          WYL_POLICY_HANDOFF_FAIL_AFTER_PROVENANCE))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_fill_cancellation_result (resolution,
        resolved.successor_credential_id,
        resolved.successor_issuance_generation, resolved.binding_digest,
        input->disposition_id, input->audit_id, trusted_now, FALSE, out_result);
  sodium_memzero (semantic_key, sizeof semantic_key);
  sodium_memzero (fingerprint, sizeof fingerprint);
  sodium_memzero (proof_digest, sizeof proof_digest);
  wyl_policy_service_successor_exact_classification_clear (&classification);
  wyl_policy_service_handoff_escrow_info_clear (&escrow);
  sodium_memzero (&fence, sizeof fence);
  return rc;
}

wyrelog_error_t
wyl_policy_rotation_intent_read_sidecar (const wyl_policy_store_t *store,
    const guint8 *auth_key, gsize auth_key_len,
    WylPolicyRotationIntent *out_intent)
{
  if (out_intent != NULL)
    memset (out_intent, 0, sizeof *out_intent);
  if (out_intent == NULL || auth_key == NULL
      || auth_key_len != crypto_generichash_KEYBYTES)
    return WYRELOG_E_INVALID;
  g_autofree gchar *path = NULL;
  g_autofree gchar *basename = NULL;
  wyrelog_error_t rc = rotation_intent_sidecar_path (store, &path, &basename);
  if (rc != WYRELOG_E_OK)
    return rc;
  guint8 *wire = NULL;
  gsize wire_len = 0;
#ifdef G_OS_WIN32
  rc = read_whole_file (path, &wire, &wire_len);
#else
  rc = read_through_dirfd (store->canonical_dirfd, basename, &wire, &wire_len);
#endif
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_rotation_intent_decode (wire, wire_len, auth_key,
      auth_key_len, out_intent);
  sodium_memzero (wire, wire_len);
  g_free (wire);
  return rc;
}

wyrelog_error_t
wyl_policy_rotation_intent_clear_sidecar (wyl_policy_store_t *store)
{
  g_autofree gchar *path = NULL;
  g_autofree gchar *basename = NULL;
  wyrelog_error_t rc = rotation_intent_sidecar_path (store, &path, &basename);
  if (rc != WYRELOG_E_OK)
    return rc;
#ifdef G_OS_WIN32
  rc = reject_reparse_point_win32 (path);
  if (rc == WYRELOG_E_NOT_FOUND)
    return WYRELOG_E_OK;
  if (rc != WYRELOG_E_OK)
    return rc;
  if (g_remove (path) != 0 && errno != ENOENT)
    return WYRELOG_E_IO;
#else
  if (unlinkat (store->canonical_dirfd, basename, 0) != 0 && errno != ENOENT)
    return WYRELOG_E_IO;
  if (fsync (store->canonical_dirfd) != 0)
    return WYRELOG_E_IO;
#endif
  return WYRELOG_E_OK;
}

static wyrelog_error_t
rotation_intent_digest_canonical (const wyl_policy_store_t * store,
    guint8 out_digest[crypto_generichash_BYTES]);

wyrelog_error_t
wyl_policy_store_rotation_intent_status (const wyl_policy_store_t *store,
    WylPolicyRotationIntentStatus *out_status)
{
  if (out_status != NULL)
    memset (out_status, 0, sizeof *out_status);
  if (store == NULL || out_status == NULL)
    return WYRELOG_E_INVALID;

  guint8 auth_key[crypto_generichash_KEYBYTES] = { 0 };
  guint8 canonical_digest[crypto_generichash_BYTES] = { 0 };
  WylPolicyRotationIntent intent = { 0 };
  wyrelog_error_t rc = wyl_policy_rotation_intent_derive_auth_key (store,
      auth_key, sizeof auth_key);
  if (rc == WYRELOG_E_OK && store->lease != NULL)
    rc = wyl_policy_store_lease_verify_parent (store->lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_rotation_intent_read_sidecar (store, auth_key,
        sizeof auth_key, &intent);
  if (rc == WYRELOG_E_NOT_FOUND) {
    out_status->state = WYL_POLICY_ROTATION_INTENT_STATUS_ABSENT;
    out_status->probe_required = TRUE;
    rc = WYRELOG_E_OK;
    goto out;
  }
  if (rc == WYRELOG_E_OK) {
    if (memcmp (intent.old_provider_id, store->encryption_key_id,
            sizeof intent.old_provider_id) != 0
        && (intent.state == WYL_POLICY_ROTATION_INTENT_PENDING
            || memcmp (intent.new_provider_id, store->encryption_key_id,
                sizeof intent.new_provider_id) != 0)) {
      rc = WYRELOG_E_POLICY;
      goto out;
    }
    if (intent.state == WYL_POLICY_ROTATION_INTENT_PENDING) {
      rc = rotation_intent_digest_canonical (store, canonical_digest);
      if (rc != WYRELOG_E_OK
          || sodium_memcmp (canonical_digest, intent.canonical_digest,
              sizeof intent.canonical_digest) != 0) {
        rc = WYRELOG_E_POLICY;
        goto out;
      }
    }
    out_status->state = intent.state == WYL_POLICY_ROTATION_INTENT_PENDING
        ? WYL_POLICY_ROTATION_INTENT_STATUS_PENDING
        : WYL_POLICY_ROTATION_INTENT_STATUS_COMMITTED;
    out_status->transaction_id = intent.transaction_id;
    memcpy (out_status->old_provider_id, intent.old_provider_id,
        sizeof out_status->old_provider_id);
    memcpy (out_status->new_provider_id, intent.new_provider_id,
        sizeof out_status->new_provider_id);
    out_status->old_generation = intent.old_generation;
    out_status->expected_new_generation = intent.expected_new_generation;
    out_status->probe_required = TRUE;
  }
out:
  sodium_memzero (auth_key, sizeof auth_key);
  sodium_memzero (canonical_digest, sizeof canonical_digest);
  sodium_memzero (&intent, sizeof intent);
  if (rc != WYRELOG_E_OK)
    memset (out_status, 0, sizeof *out_status);
  return rc;
}

static wyrelog_error_t
rotation_intent_digest_canonical (const wyl_policy_store_t *store,
    guint8 out_digest[crypto_generichash_BYTES])
{
  if (store == NULL || out_digest == NULL)
    return WYRELOG_E_INVALID;
  guint8 *canonical = NULL;
  gsize canonical_len = 0;
  wyrelog_error_t rc;
#ifdef G_OS_WIN32
  rc = read_whole_file (store->canonical_path, &canonical, &canonical_len);
#else
  rc = read_through_dirfd (store->canonical_dirfd, store->canonical_basename,
      &canonical, &canonical_len);
#endif
  if (rc != WYRELOG_E_OK)
    return rc;
  if (canonical_len == 0
      || crypto_generichash (out_digest, crypto_generichash_BYTES, canonical,
          canonical_len, NULL, 0) != 0) {
    sodium_memzero (canonical, canonical_len);
    g_free (canonical);
    sodium_memzero (out_digest, crypto_generichash_BYTES);
    return WYRELOG_E_CRYPTO;
  }
  sodium_memzero (canonical, canonical_len);
  g_free (canonical);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
rotation_intent_write_pending (wyl_policy_store_t *store,
    const wyl_policy_service_cvk_info_t *info, const guint8 *new_key_material)
{
  if (store == NULL || info == NULL || new_key_material == NULL)
    return WYRELOG_E_INVALID;
  WylPolicyRotationIntent intent = { 0 };
  guint8 auth_key[crypto_generichash_KEYBYTES] = { 0 };
  wyrelog_error_t rc = wyl_policy_rotation_intent_derive_auth_key (store,
      auth_key, sizeof auth_key);
  if (rc == WYRELOG_E_OK) {
    WylPolicyRotationIntent existing = { 0 };
    wyrelog_error_t existing_rc =
        wyl_policy_rotation_intent_read_sidecar (store, auth_key,
        sizeof auth_key, &existing);
    sodium_memzero (&existing, sizeof existing);
    if (existing_rc == WYRELOG_E_OK)
      rc = WYRELOG_E_POLICY;
    else if (existing_rc != WYRELOG_E_NOT_FOUND)
      rc = existing_rc;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_id_new (&intent.transaction_id);
  if (rc == WYRELOG_E_OK)
    rc = rotation_intent_digest_canonical (store, intent.canonical_digest);
  if (rc == WYRELOG_E_OK)
    memcpy (intent.old_provider_id, store->encryption_key_id,
        sizeof intent.old_provider_id);
  if (rc == WYRELOG_E_OK)
    memcpy (intent.new_provider_id,
        new_key_material + WYL_POLICY_STORE_KEY_LEN,
        sizeof intent.new_provider_id);
  if (rc == WYRELOG_E_OK) {
    intent.old_generation = info->generation;
    if (intent.old_generation == G_MAXUINT64)
      rc = WYRELOG_E_POLICY;
    else
      intent.expected_new_generation = intent.old_generation + 1;
    intent.state = WYL_POLICY_ROTATION_INTENT_PENDING;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_rotation_intent_write_sidecar (store, &intent, auth_key,
        sizeof auth_key);
  sodium_memzero (auth_key, sizeof auth_key);
  sodium_memzero (&intent, sizeof intent);
  return rc;
}

static wyrelog_error_t
rotation_intent_finalize_committed (wyl_policy_store_t *store,
    const guint8 *new_key_material,
    const wyl_policy_store_rotation_runtime_t *rotation_runtime)
{
  if (store == NULL || new_key_material == NULL)
    return WYRELOG_E_INVALID;
  guint8 auth_key[crypto_generichash_KEYBYTES] = { 0 };
  WylPolicyRotationIntent intent = { 0 };
  wyrelog_error_t rc = wyl_policy_rotation_intent_derive_auth_key (store,
      auth_key, sizeof auth_key);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_rotation_intent_read_sidecar (store, auth_key,
        sizeof auth_key, &intent);
  if (rc == WYRELOG_E_NOT_FOUND)
    goto out;
  if (rc == WYRELOG_E_OK
      && memcmp (intent.old_provider_id, store->encryption_key_id,
          sizeof intent.old_provider_id) != 0)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK
      && memcmp (intent.new_provider_id,
          new_key_material + WYL_POLICY_STORE_KEY_LEN,
          sizeof intent.new_provider_id) != 0)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK
      && intent.state != WYL_POLICY_ROTATION_INTENT_PENDING
      && intent.state != WYL_POLICY_ROTATION_INTENT_COMMITTED)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK) {
    wyl_policy_service_cvk_info_t info = { 0 };
    wyrelog_error_t info_rc = wyl_policy_store_load_service_cvk (store, &info);
    if (info_rc == WYRELOG_E_OK) {
      if (info.generation != intent.expected_new_generation)
        rc = WYRELOG_E_POLICY;
    } else if (info_rc != WYRELOG_E_NOT_FOUND || intent.old_generation != 0) {
      rc = info_rc;
    }
    wyl_policy_service_cvk_info_clear (&info);
  }
  if (rc == WYRELOG_E_OK && intent.state == WYL_POLICY_ROTATION_INTENT_PENDING) {
    intent.state = WYL_POLICY_ROTATION_INTENT_COMMITTED;
    rc = wyl_policy_rotation_intent_write_sidecar (store, &intent, auth_key,
        sizeof auth_key);
  }
  /* Post-linearization: the rotation is already durable. This seam is log-only
   * and never reverses the committed rename; recovery clears any residual
   * sidecar left by a crash between the committed write and the unlink. */
  if (rc == WYRELOG_E_OK && rotation_runtime != NULL
      && rotation_runtime->checkpoint != NULL
      && rotation_runtime->checkpoint (rotation_runtime->data,
          WYL_POLICY_ROTATION_DURING_INTENT_CLEANUP) != 0)
    WYL_LOG_WARN (WYL_LOG_SECTION_BOOT,
        "policy store rotation committed but an intent-cleanup seam signalled");
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_rotation_intent_clear_sidecar (store);
out:
  sodium_memzero (auth_key, sizeof auth_key);
  sodium_memzero (&intent, sizeof intent);
  return rc;
}

wyrelog_error_t
wyl_policy_rotation_recovery_classify (const WylPolicyRotationRecoveryProbe
    *probe, WylPolicyRotationRecoveryState *out_state)
{
  if (out_state != NULL)
    *out_state = WYL_POLICY_ROTATION_RECOVERY_AMBIGUOUS;
  if (probe == NULL || out_state == NULL)
    return WYRELOG_E_INVALID;

  gboolean old_valid = probe->old_root_authenticated
      && probe->old_generation_matches && probe->old_binding_matches
      && probe->old_inner_invariants_match;
  gboolean new_valid = probe->new_root_authenticated
      && probe->new_generation_matches && probe->new_binding_matches
      && probe->new_inner_invariants_match;
  if (old_valid == new_valid) {
    /* Neither root or both roots authenticating is deliberately ambiguous;
     * callers must fail closed and retain both roots for operator recovery. */
    *out_state = WYL_POLICY_ROTATION_RECOVERY_AMBIGUOUS;
  } else if (old_valid) {
    *out_state = WYL_POLICY_ROTATION_RECOVERY_OLD;
  } else {
    *out_state = WYL_POLICY_ROTATION_RECOVERY_NEW;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_rotation_recovery_plan (const WylPolicyRotationIntent *intent,
    const WylPolicyRotationRecoveryProbe *probe,
    WylPolicyRotationRecoveryState *out_state,
    WylPolicyRotationRecoveryAction *out_action)
{
  if (out_state != NULL)
    *out_state = WYL_POLICY_ROTATION_RECOVERY_AMBIGUOUS;
  if (out_action != NULL)
    *out_action = WYL_POLICY_ROTATION_RECOVERY_FAIL_CLOSED;
  if (intent == NULL || probe == NULL || out_state == NULL
      || out_action == NULL)
    return WYRELOG_E_INVALID;
  if (rotation_intent_validate (intent) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;

  wyrelog_error_t rc = wyl_policy_rotation_recovery_classify (probe, out_state);
  if (rc != WYRELOG_E_OK)
    return rc;

  if (*out_state == WYL_POLICY_ROTATION_RECOVERY_OLD
      && intent->state == WYL_POLICY_ROTATION_INTENT_PENDING) {
    *out_action = WYL_POLICY_ROTATION_RECOVERY_RESUME_OLD;
    return WYRELOG_E_OK;
  }
  if (*out_state == WYL_POLICY_ROTATION_RECOVERY_NEW) {
    *out_action = WYL_POLICY_ROTATION_RECOVERY_FINALIZE_NEW;
    return WYRELOG_E_OK;
  }
  if (*out_state == WYL_POLICY_ROTATION_RECOVERY_AMBIGUOUS)
    return WYRELOG_E_OK;
  return WYRELOG_E_POLICY;
}

/* Pinned canonical-file helpers (CWE-367 / CodeQL
 * cpp/toctou-race-condition).
 *
 * After the lease resolves a trusted parent, Wyrelog-owned canonical reads,
 * encrypted persistence, and clear-work cleanup use its retained directory
 * fd with O_NOFOLLOW. SQLite itself still opens the encrypted clear-work
 * database, or the plaintext provider-backed canonical database, by the
 * lease-resolved pathname. The namespace therefore MUST satisfy the
 * operator-owned, non-replaceable deployment contract in
 * docs/developer-lifecycle.md for the entire store lifetime. Pre/post parent
 * checks bracket only the initial main-database sqlite3_open_v2(). Later VFS
 * opens for journal, WAL, SHM, temporary, and other files are pathname-derived
 * and unpinned; namespace changes after the post-open check are not detected. */

#ifndef G_OS_WIN32
static wyrelog_error_t
read_through_dirfd (int dirfd, const gchar *basename, guint8 **out_bytes,
    gsize *out_len)
{
  *out_bytes = NULL;
  *out_len = 0;

  int fd = openat (dirfd, basename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) {
    if (errno == ENOENT)
      return WYRELOG_E_NOT_FOUND;
    if (errno == ELOOP) {
      WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
          "policy store refused symlinked file at canonical path");
      return WYRELOG_E_POLICY;
    }
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT, "policy store openat for read failed");
    return WYRELOG_E_IO;
  }

  struct stat st;
  if (fstat (fd, &st) != 0) {
    close (fd);
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "policy store fstat after openat failed");
    return WYRELOG_E_IO;
  }
  if (!S_ISREG (st.st_mode)) {
    close (fd);
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "policy store canonical fd is not a regular file");
    return WYRELOG_E_POLICY;
  }
  if (st.st_size < 0 || (guint64) st.st_size > (guint64) G_MAXSIZE) {
    close (fd);
    return WYRELOG_E_IO;
  }

  gsize len = (gsize) st.st_size;
  guint8 *buf = g_malloc (len > 0 ? len : 1);
  gsize total = 0;
  while (total < len) {
    ssize_t got = read (fd, buf + total, len - total);
    if (got < 0) {
      if (errno == EINTR)
        continue;
      g_free (buf);
      close (fd);
      WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
          "policy store read from canonical fd failed");
      return WYRELOG_E_IO;
    }
    if (got == 0)
      break;
    total += (gsize) got;
  }
  close (fd);

  if (total != len) {
    g_free (buf);
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "policy store short read from canonical fd");
    return WYRELOG_E_IO;
  }

  *out_bytes = buf;
  *out_len = len;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
read_work_through_dirfd (int dirfd, const gchar *basename, guint8 **out_bytes,
    gsize *out_len)
{
  *out_bytes = NULL;
  *out_len = 0;

  int fd = openat (dirfd, basename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) {
    if (errno == ELOOP) {
      WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
          "policy store refused symlinked work path");
      return WYRELOG_E_POLICY;
    }
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "policy store openat for work read failed");
    return WYRELOG_E_IO;
  }

  struct stat st;
  if (fstat (fd, &st) != 0 || !S_ISREG (st.st_mode) || st.st_size < 0
      || (guint64) st.st_size > (guint64) G_MAXSIZE) {
    close (fd);
    return WYRELOG_E_IO;
  }

  gsize len = (gsize) st.st_size;
  guint8 *buf = g_malloc (len > 0 ? len : 1);
  gsize total = 0;
  while (total < len) {
    ssize_t got = read (fd, buf + total, len - total);
    if (got < 0) {
      if (errno == EINTR)
        continue;
      g_free (buf);
      close (fd);
      return WYRELOG_E_IO;
    }
    if (got == 0)
      break;
    total += (gsize) got;
  }
  close (fd);

  if (total != len) {
    g_free (buf);
    return WYRELOG_E_IO;
  }

  *out_bytes = buf;
  *out_len = len;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
write_through_dirfd (int dirfd, const gchar *basename, const guint8 *bytes,
    gsize len, const wyl_policy_store_rotation_runtime_t *rotation_runtime,
    gboolean *out_replaced)
{
  if (out_replaced != NULL)
    *out_replaced = FALSE;
  g_autofree gchar *tmp_basename = g_strdup_printf ("%s%s", basename,
      WYL_POLICY_STORE_TMP_SUFFIX);

  /* Best-effort sweep of any stale tmp file from a prior aborted
   * write. ENOENT is the common case and is not an error. */
  (void) unlinkat (dirfd, tmp_basename, 0);

  int fd = openat (dirfd, tmp_basename,
      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "policy store openat for write (tmp) failed");
    return WYRELOG_E_IO;
  }

  gsize total = 0;
  while (total < len) {
    ssize_t put = write (fd, bytes + total, len - total);
    if (put < 0) {
      if (errno == EINTR)
        continue;
      close (fd);
      (void) unlinkat (dirfd, tmp_basename, 0);
      WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
          "policy store write to canonical tmp failed");
      return WYRELOG_E_IO;
    }
    total += (gsize) put;
  }

  if (fsync (fd) != 0) {
    close (fd);
    (void) unlinkat (dirfd, tmp_basename, 0);
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "policy store fsync of canonical tmp failed");
    return WYRELOG_E_IO;
  }

  if (close (fd) != 0) {
    (void) unlinkat (dirfd, tmp_basename, 0);
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "policy store close of canonical tmp failed");
    return WYRELOG_E_IO;
  }

  if (rotation_runtime != NULL && rotation_runtime->checkpoint != NULL
      && rotation_runtime->checkpoint (rotation_runtime->data,
          WYL_POLICY_ROTATION_BEFORE_CANONICAL_RENAME) != 0) {
    (void) unlinkat (dirfd, tmp_basename, 0);
    return WYRELOG_E_IO;
  }

  if (renameat (dirfd, tmp_basename, dirfd, basename) != 0) {
    (void) unlinkat (dirfd, tmp_basename, 0);
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "policy store renameat onto canonical name failed");
    return WYRELOG_E_IO;
  }
  if (out_replaced != NULL)
    *out_replaced = TRUE;

  if (rotation_runtime != NULL && rotation_runtime->checkpoint != NULL
      && rotation_runtime->checkpoint (rotation_runtime->data,
          WYL_POLICY_ROTATION_AFTER_CANONICAL_RENAME) != 0) {
    WYL_LOG_WARN (WYL_LOG_SECTION_BOOT,
        "policy store canonical replacement completed with a durability warning");
    return WYRELOG_E_OK;
  }

  /* Fsync the parent directory so the rename is durable across crash.
   * Without this, the kernel may have flushed the new file inode but
   * not the directory entry rewrite, leaving recovery to either lose
   * the canonical name entirely or retain the tmp name. */
  if (fsync (dirfd) != 0)
    WYL_LOG_WARN (WYL_LOG_SECTION_BOOT,
        "policy store canonical replacement completed but directory fsync failed");

  /* Post-linearization: the rename already committed, so this seam is log-only
   * and the rotation still succeeds. The Windows MoveFileEx twin is write-
   * through and has no corresponding parent-directory fsync site. */
  if (rotation_runtime != NULL && rotation_runtime->checkpoint != NULL
      && rotation_runtime->checkpoint (rotation_runtime->data,
          WYL_POLICY_ROTATION_AFTER_PARENT_DIR_FSYNC) != 0)
    WYL_LOG_WARN (WYL_LOG_SECTION_BOOT,
        "policy store canonical replacement durable but a post-fsync seam signalled");

  return WYRELOG_E_OK;
}

static wyrelog_error_t
write_plaintext_work_through_dirfd (int dirfd, const gchar *basename,
    const guint8 *bytes, gsize len)
{
  /* Unlink any stale work file before recreating with O_NOFOLLOW. */
  (void) unlinkat (dirfd, basename, 0);
  int fd = openat (dirfd, basename,
      O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "policy store openat for work-path write failed");
    return WYRELOG_E_IO;
  }
  gsize total = 0;
  while (total < len) {
    ssize_t put = write (fd, bytes + total, len - total);
    if (put < 0) {
      if (errno == EINTR)
        continue;
      close (fd);
      WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
          "policy store write to work fd failed");
      return WYRELOG_E_IO;
    }
    total += (gsize) put;
  }
  if (fsync (fd) != 0) {
    close (fd);
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "policy store fsync of work fd failed");
    return WYRELOG_E_IO;
  }
  close (fd);
  return WYRELOG_E_OK;
}
#endif /* !G_OS_WIN32 */

static wyrelog_error_t
decrypt_policy_store_from_bytes (wyl_policy_store_t *store,
    const guint8 *ciphertext, gsize ciphertext_len)
{
  if (ciphertext_len < sizeof (WylPolicyStoreFileHeader))
    return WYRELOG_E_POLICY;
  const WylPolicyStoreFileHeader *header =
      (const WylPolicyStoreFileHeader *) (const void *) ciphertext;
  if (memcmp (header->magic, WYL_POLICY_STORE_MAGIC, WYL_POLICY_STORE_MAGIC_LEN)
      != 0)
    return WYRELOG_E_POLICY;
  if (header->version != WYL_POLICY_STORE_FORMAT_VERSION || header->flags != 0
      || header->reserved != 0)
    return WYRELOG_E_POLICY;
  if (memcmp (header->provider_id, store->encryption_key_id,
          WYL_POLICY_STORE_KEY_ID_LEN)
      != 0)
    return WYRELOG_E_POLICY;

  const gsize max_header_and_mac = sizeof (WylPolicyStoreFileHeader)
      + crypto_aead_xchacha20poly1305_ietf_ABYTES;
  if (ciphertext_len < max_header_and_mac)
    return WYRELOG_E_POLICY;
  guint64 cipher_len_le = GUINT64_FROM_LE (header->ciphertext_len_le);
  if (cipher_len_le == 0)
    return WYRELOG_E_POLICY;
  if (cipher_len_le > G_MAXSIZE
      || header->ciphertext_len_le > (guint64) (G_MAXSIZE
          - sizeof (WylPolicyStoreFileHeader)))
    return WYRELOG_E_POLICY;

  if (cipher_len_le + sizeof (WylPolicyStoreFileHeader) != ciphertext_len
      || cipher_len_le <= crypto_aead_xchacha20poly1305_ietf_ABYTES)
    return WYRELOG_E_POLICY;

  gsize plaintext_len = (gsize) cipher_len_le
      - crypto_aead_xchacha20poly1305_ietf_ABYTES;
  if (plaintext_len > G_MAXSIZE - WYL_POLICY_STORE_DESERIALIZE_GROWTH_BYTES)
    return WYRELOG_E_POLICY;
  if (plaintext_len > WYL_POLICY_STORE_MAX_IMAGE_BYTES)
    return WYRELOG_E_POLICY;
  gsize plaintext_capacity = plaintext_len
      + WYL_POLICY_STORE_DESERIALIZE_GROWTH_BYTES;
  guint8 *plaintext = sqlite3_malloc64 ((sqlite3_uint64) plaintext_capacity);
  if (plaintext == NULL)
    return WYRELOG_E_NOMEM;
  memset (plaintext + plaintext_len, 0, plaintext_capacity - plaintext_len);
  const guint8 *ciphertext_body =
      ciphertext + sizeof (WylPolicyStoreFileHeader);
  unsigned long long decrypted_len = 0;

  if (crypto_aead_xchacha20poly1305_ietf_decrypt (plaintext, &decrypted_len,
          NULL, ciphertext_body, cipher_len_le,
          (const guint8 *) header, sizeof (WylPolicyStoreFileHeader),
          header->nonce, store->encryption_key) != 0) {
    sodium_memzero (plaintext, plaintext_capacity);
    sqlite3_free (plaintext);
    return WYRELOG_E_CRYPTO;
  }
  if (decrypted_len != plaintext_len) {
    sodium_memzero (plaintext, plaintext_capacity);
    sqlite3_free (plaintext);
    return WYRELOG_E_CRYPTO;
  }
  /* A serialized image can retain the source connection's WAL header bits.
   * WAL requires a filesystem sidecar, which an in-memory database cannot
   * provide. Normalize the private image to rollback-journal semantics before
   * deserialization; the authenticated canonical envelope is unchanged. */
  if (plaintext_len >= 20 && plaintext[18] == 2 && plaintext[19] == 2) {
    plaintext[18] = 1;
    plaintext[19] = 1;
  }

  if (store->db == NULL
      && sqlite3_open_v2 (":memory:", &store->db,
          SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, NULL) != SQLITE_OK) {
    if (store->db != NULL)
      sqlite3_close (store->db);
    store->db = NULL;
    sodium_memzero (plaintext, plaintext_capacity);
    sqlite3_free (plaintext);
    return WYRELOG_E_IO;
  }
  if (sqlite3_deserialize (store->db, "main", plaintext,
          (sqlite3_int64) plaintext_len, (sqlite3_int64) plaintext_capacity,
          0) != SQLITE_OK) {
    sqlite3_close (store->db);
    store->db = NULL;
    sodium_memzero (plaintext, plaintext_capacity);
    sqlite3_free (plaintext);
    return WYRELOG_E_POLICY;
  }
  store->deserialized_image = plaintext;
  store->deserialized_image_capacity = plaintext_capacity;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
query_has_rows (sqlite3 *db, const gchar *sql, gboolean *out_has_rows)
{
  if (db == NULL || sql == NULL || out_has_rows == NULL)
    return WYRELOG_E_INVALID;
  *out_has_rows = FALSE;

  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = prepare_stmt (db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW) {
    *out_has_rows = TRUE;
    sqlite3_finalize (stmt);
    return WYRELOG_E_OK;
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
query_single_text (sqlite3 *db, const gchar *sql, const gchar *id,
    gchar **out_value)
{
  sqlite3_stmt *stmt = NULL;

  if (db == NULL || sql == NULL || id == NULL || out_value == NULL)
    return WYRELOG_E_INVALID;
  *out_value = NULL;

  wyrelog_error_t rc = prepare_stmt (db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW) {
    if (sqlite3_column_type (stmt, 0) == SQLITE_NULL) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_POLICY;
    }
    *out_value = g_strdup ((const gchar *) sqlite3_column_text (stmt, 0));
    sqlite3_finalize (stmt);
    return *out_value == NULL ? WYRELOG_E_IO : WYRELOG_E_OK;
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_POLICY : WYRELOG_E_IO;
}

static wyrelog_error_t
validate_builtin_roles (sqlite3 *db)
{
  static const gchar *sql = "SELECT role_name FROM roles WHERE role_id = ?;";

  for (gsize i = 0; i < G_N_ELEMENTS (builtin_roles); i++) {
    g_autofree gchar *name = NULL;
    wyrelog_error_t rc = query_single_text (db, sql, builtin_roles[i].id,
        &name);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (g_strcmp0 (name, builtin_roles[i].name) != 0)
      return WYRELOG_E_POLICY;
  }

  return WYRELOG_E_OK;
}

static wyrelog_error_t
validate_builtin_permissions (sqlite3 *db)
{
  static const gchar *name_sql =
      "SELECT perm_name FROM permissions WHERE perm_id = ?;";
  static const gchar *class_sql =
      "SELECT class FROM permissions WHERE perm_id = ?;";

  for (gsize i = 0; i < G_N_ELEMENTS (builtin_permissions); i++) {
    g_autofree gchar *name = NULL;
    wyrelog_error_t rc = query_single_text (db, name_sql,
        builtin_permissions[i].id, &name);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (g_strcmp0 (name, builtin_permissions[i].name) != 0)
      return WYRELOG_E_POLICY;

    g_autofree gchar *klass = NULL;
    rc = query_single_text (db, class_sql, builtin_permissions[i].id, &klass);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (g_strcmp0 (klass, builtin_permissions[i].klass) != 0)
      return WYRELOG_E_POLICY;
  }

  return WYRELOG_E_OK;
}

static wyrelog_error_t
validate_reserved_roles (sqlite3 *db)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT role_id FROM roles WHERE substr(role_id, 1, 3) = 'wr.';";
  wyrelog_error_t rc = prepare_stmt (db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *role_id = (const gchar *) sqlite3_column_text (stmt, 0);
    if (find_builtin_role (role_id) == NULL) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_POLICY;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
validate_reserved_permissions (sqlite3 *db)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT perm_id FROM permissions WHERE substr(perm_id, 1, 3) = 'wr.';";
  wyrelog_error_t rc = prepare_stmt (db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *perm_id = (const gchar *) sqlite3_column_text (stmt, 0);
    if (find_builtin_permission (perm_id) == NULL) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_POLICY;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
validate_builtin_catalog (sqlite3 *db)
{
  wyrelog_error_t rc = validate_builtin_roles (db);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = validate_builtin_permissions (db);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = validate_reserved_roles (db);
  if (rc != WYRELOG_E_OK)
    return rc;
  return validate_reserved_permissions (db);
}

static wyrelog_error_t
seed_builtin_roles (sqlite3 *db)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "INSERT OR IGNORE INTO roles "
      "  (role_id, role_name, description, created_at, modified_at) "
      "VALUES (?, ?, 'built-in', unixepoch(), unixepoch());";
  wyrelog_error_t rc = prepare_stmt (db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  for (gsize i = 0; i < G_N_ELEMENTS (builtin_roles); i++) {
    sqlite3_reset (stmt);
    sqlite3_clear_bindings (stmt);
    if ((rc = bind_text (stmt, 1, builtin_roles[i].id)) != WYRELOG_E_OK
        || (rc = bind_text (stmt, 2, builtin_roles[i].name))
        != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
    if (sqlite3_step (stmt) != SQLITE_DONE) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_IO;
    }
  }

  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
seed_builtin_permissions (sqlite3 *db)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "INSERT OR IGNORE INTO permissions "
      "  (perm_id, perm_name, class, created_at) "
      "VALUES (?, ?, ?, unixepoch());";
  wyrelog_error_t rc = prepare_stmt (db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  for (gsize i = 0; i < G_N_ELEMENTS (builtin_permissions); i++) {
    sqlite3_reset (stmt);
    sqlite3_clear_bindings (stmt);
    if ((rc = bind_text (stmt, 1, builtin_permissions[i].id)) != WYRELOG_E_OK
        || (rc = bind_text (stmt, 2, builtin_permissions[i].name))
        != WYRELOG_E_OK
        || (rc = bind_text (stmt, 3, builtin_permissions[i].klass))
        != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
    if (sqlite3_step (stmt) != SQLITE_DONE) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_IO;
    }
  }

  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
seed_builtin_catalog (sqlite3 *db)
{
  wyrelog_error_t rc = seed_builtin_roles (db);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = seed_builtin_permissions (db);
  if (rc != WYRELOG_E_OK)
    return rc;
  return validate_builtin_catalog (db);
}

static wyrelog_error_t
prepare_policy_store_encrypted (wyl_policy_store_t *store,
    const guint8 key[WYL_POLICY_STORE_KEY_LEN],
    const guint8 key_id[WYL_POLICY_STORE_KEY_ID_LEN], guint8 **out_encrypted,
    gsize *out_encrypted_len)
{
  if (store == NULL || key == NULL || key_id == NULL || out_encrypted == NULL
      || out_encrypted_len == NULL)
    return WYRELOG_E_INVALID;
  *out_encrypted = NULL;
  *out_encrypted_len = 0;
  if (!store->encrypted)
    return WYRELOG_E_INVALID;
  if (store->canonical_path == NULL || store->canonical_path[0] == '\0'
      || store->db == NULL)
    return WYRELOG_E_INVALID;

  if (store->db != NULL && sqlite3_db_cacheflush (store->db) != SQLITE_OK)
    return WYRELOG_E_IO;

  sqlite3_int64 serialized_len = 0;
  guint8 *serialized = sqlite3_serialize (store->db, "main",
      &serialized_len, 0);
  if (serialized == NULL || serialized_len <= 0
      || (guint64) serialized_len > G_MAXSIZE
      || (guint64) serialized_len > WYL_POLICY_STORE_MAX_IMAGE_BYTES) {
    if (serialized != NULL)
      sqlite3_free (serialized);
    return WYRELOG_E_IO;
  }
  gsize plaintext_len = (gsize) serialized_len;
  g_autofree guint8 *plaintext = g_try_malloc (plaintext_len);
  if (plaintext == NULL) {
    sodium_memzero (serialized, plaintext_len);
    sqlite3_free (serialized);
    return WYRELOG_E_NOMEM;
  }
  memcpy (plaintext, serialized, plaintext_len);
  sodium_memzero (serialized, plaintext_len);
  sqlite3_free (serialized);

  const gsize encrypted_len = sizeof (WylPolicyStoreFileHeader)
      + crypto_aead_xchacha20poly1305_ietf_ABYTES + plaintext_len;
  guint8 *encrypted = g_try_malloc0 (encrypted_len);
  if (encrypted == NULL) {
    sodium_memzero (plaintext, plaintext_len);
    return WYRELOG_E_NOMEM;
  }
  WylPolicyStoreFileHeader *header = (WylPolicyStoreFileHeader *) encrypted;
  memcpy (header->magic, WYL_POLICY_STORE_MAGIC, WYL_POLICY_STORE_MAGIC_LEN);
  header->version = WYL_POLICY_STORE_FORMAT_VERSION;
  header->flags = 0;
  header->reserved = 0;
  memcpy (header->provider_id, key_id, WYL_POLICY_STORE_KEY_ID_LEN);
  randombytes_buf (header->nonce, sizeof (header->nonce));
  header->ciphertext_len_le = GUINT64_TO_LE ((guint64) (plaintext_len
          + crypto_aead_xchacha20poly1305_ietf_ABYTES));

  guint8 *ciphertext = encrypted + sizeof (WylPolicyStoreFileHeader);
  unsigned long long ciphertext_len = 0;
  if (crypto_aead_xchacha20poly1305_ietf_encrypt (ciphertext, &ciphertext_len,
          plaintext, plaintext_len,
          (const guint8 *) header, sizeof (WylPolicyStoreFileHeader), NULL,
          header->nonce, key) != 0) {
    sodium_memzero (plaintext, plaintext_len);
    sodium_memzero (encrypted, encrypted_len);
    g_free (encrypted);
    return WYRELOG_E_CRYPTO;
  }
  if (ciphertext_len != (unsigned long long) (encrypted_len
          - sizeof (WylPolicyStoreFileHeader))) {
    sodium_memzero (plaintext, plaintext_len);
    sodium_memzero (encrypted, encrypted_len);
    g_free (encrypted);
    return WYRELOG_E_CRYPTO;
  }

  *out_encrypted = encrypted;
  *out_encrypted_len = encrypted_len;
  sodium_memzero (plaintext, plaintext_len);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
publish_policy_store_encrypted (wyl_policy_store_t *store,
    const guint8 *encrypted, gsize encrypted_len,
    const wyl_policy_store_rotation_runtime_t *rotation_runtime,
    gboolean *out_replaced)
{
  if (store == NULL || encrypted == NULL || encrypted_len == 0)
    return WYRELOG_E_INVALID;

#ifndef G_OS_WIN32
  /* POSIX builds always have canonical_dirfd; the open path enforces
   * this invariant. */
  if (store->canonical_dirfd < 0 || store->canonical_basename == NULL)
    return WYRELOG_E_INTERNAL;
  return write_through_dirfd (store->canonical_dirfd,
      store->canonical_basename, encrypted, encrypted_len, rotation_runtime,
      out_replaced);
#else
  return write_whole_file_atomic_private (store->canonical_path, encrypted,
      encrypted_len, rotation_runtime, out_replaced);
#endif
}

static wyrelog_error_t
persist_policy_store_encrypted (wyl_policy_store_t *store)
{
  if (store == NULL)
    return WYRELOG_E_INVALID;
  if (!store->encrypted)
    return WYRELOG_E_OK;
  if (!store->key_materialized)
    return WYRELOG_E_INTERNAL;

  g_autofree guint8 *encrypted = NULL;
  gsize encrypted_len = 0;
  wyrelog_error_t rc = prepare_policy_store_encrypted (store,
      store->encryption_key, store->encryption_key_id, &encrypted,
      &encrypted_len);
  if (rc != WYRELOG_E_OK)
    return rc;
  return publish_policy_store_encrypted (store, encrypted, encrypted_len, NULL,
      NULL);
}

wyrelog_error_t
wyl_policy_store_begin_mutation (wyl_policy_store_t *store)
{
  if (store == NULL || store->db == NULL)
    return WYRELOG_E_INVALID;
  return exec_sql (store->db, "SAVEPOINT wyrelog_policy_mutation;");
}

wyrelog_error_t
wyl_policy_store_commit_mutation (wyl_policy_store_t *store)
{
  if (store == NULL || store->db == NULL)
    return WYRELOG_E_INVALID;
  return exec_sql (store->db, "RELEASE SAVEPOINT wyrelog_policy_mutation;");
}

void
wyl_policy_store_rollback_mutation (wyl_policy_store_t *store)
{
  if (store == NULL || store->db == NULL)
    return;
  (void) exec_sql (store->db, "ROLLBACK TO SAVEPOINT wyrelog_policy_mutation;");
  (void) exec_sql (store->db, "RELEASE SAVEPOINT wyrelog_policy_mutation;");
}

static wyrelog_error_t
service_authority_transaction_exec (WylServiceAuthorityTransaction *txn,
    const gchar *operation)
{
  g_autofree gchar *sql = g_strdup_printf ("%s %s;", operation,
      txn->savepoint);
  return exec_sql (txn->store->db, sql);
}

WylServiceAuthorityCommitEvidence
    * wyl_policy_store_service_authority_commit_evidence_ref
    (WylServiceAuthorityCommitEvidence * evidence) {
  g_return_val_if_fail (evidence != NULL, NULL);
  gint refs = g_atomic_int_get (&evidence->refs);
  while (refs > 0 && refs < G_MAXINT) {
    if (g_atomic_int_compare_and_exchange (&evidence->refs, refs, refs + 1))
      return evidence;
    refs = g_atomic_int_get (&evidence->refs);
  }
  return NULL;
}

void wyl_policy_store_service_authority_commit_evidence_unref
    (WylServiceAuthorityCommitEvidence * evidence)
{
  if (evidence == NULL || !g_atomic_int_dec_and_test (&evidence->refs))
    return;
  g_clear_object (&evidence->handle);
  g_mutex_clear (&evidence->mutex);
  g_free (evidence);
}

static void
    service_authority_commit_evidence_transition
    (WylServiceAuthorityCommitEvidence * evidence,
    WylServiceAuthorityEvidenceState state)
{
  if (evidence == NULL)
    return;
  g_mutex_lock (&evidence->mutex);
  g_assert_cmpint (evidence->state, ==, WYL_SERVICE_AUTHORITY_EVIDENCE_PENDING);
  evidence->state = state;
  if (state != WYL_SERVICE_AUTHORITY_EVIDENCE_PENDING)
    evidence->pending_owner = NULL;
  g_mutex_unlock (&evidence->mutex);
}

static int
service_authority_fault_authorizer (gpointer data, int action,
    const gchar *arg1, const gchar *arg2, const gchar *database,
    const gchar *trigger)
{
  WylServiceAuthorityTransaction *txn = data;
  (void) database;
  (void) trigger;
  if (action == SQLITE_SAVEPOINT
      && g_strcmp0 (arg2, txn->savepoint) == 0
      && (g_strcmp0 (arg1, "RELEASE") == 0
          || g_strcmp0 (arg1, "ROLLBACK") == 0))
    return SQLITE_DENY;
  return SQLITE_OK;
}

static wyrelog_error_t
service_authority_transaction_fault_exec (WylServiceAuthorityTransaction *txn,
    const gchar *operation, int *out_extended_error)
{
  (void) sqlite3_set_authorizer (txn->store->db,
      service_authority_fault_authorizer, txn);
  wyrelog_error_t rc = service_authority_transaction_exec (txn, operation);
  *out_extended_error = sqlite3_extended_errcode (txn->store->db);
  (void) sqlite3_set_authorizer (txn->store->db, NULL, NULL);
  return rc;
}

/*
 * Restore autocommit without ever releasing a savepoint whose rollback failed:
 * RELEASE would commit its writes. Because begin rejects nesting, a fallback
 * full ROLLBACK can only affect this authority transaction.
 */
static wyrelog_error_t
service_authority_transaction_restore (WylServiceAuthorityTransaction *txn)
{
  if (sqlite3_get_autocommit (txn->store->db))
    return WYRELOG_E_OK;
  if (txn->fault == WYL_POLICY_AUTHORITY_TXN_FAIL_ROLLBACK
      || txn->fault == WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_AND_ROLLBACK
      || txn->fault == WYL_POLICY_AUTHORITY_TXN_FAIL_AUTHORIZER_INSTALL
      || txn->fault == WYL_POLICY_AUTHORITY_TXN_FAIL_AUTHORIZER_REMOVE)
    return service_authority_transaction_fault_exec (txn,
        "ROLLBACK TO SAVEPOINT", &txn->recovery_sqlite_extended_error);

  wyrelog_error_t primary = service_authority_transaction_exec (txn,
      "ROLLBACK TO SAVEPOINT");
  if (primary != WYRELOG_E_OK)
    txn->recovery_sqlite_extended_error = sqlite3_extended_errcode
        (txn->store->db);
  if (primary == WYRELOG_E_OK) {
    wyrelog_error_t release = service_authority_transaction_exec (txn,
        "RELEASE SAVEPOINT");
    if (release == WYRELOG_E_OK)
      return WYRELOG_E_OK;
    primary = release;
    txn->recovery_sqlite_extended_error = sqlite3_extended_errcode
        (txn->store->db);
  }

  /* Best-effort recovery after either rollback or release failed. */
  (void) exec_sql (txn->store->db, "ROLLBACK;");
  return primary;
}

static void
service_authority_transaction_finish (WylServiceAuthorityTransaction *txn)
{
  g_assert_true (txn->owns_store_locks);
  if (!sqlite3_get_autocommit (txn->store->db)) {
    if (!service_authority_poison (txn)) {
      /* With all mutex ownership retained, the exact owner may immediately
       * recover even though the fail-closed authorizer could not be installed. */
      wyrelog_error_t rollback_rc = exec_sql (txn->store->db, "ROLLBACK;");
      if (rollback_rc == WYRELOG_E_OK
          && sqlite3_get_autocommit (txn->store->db)) {
        txn->store->service_authority_poison_owner = NULL;
        txn->store->service_authority_poison_serial = 0;
        g_atomic_int_set (&txn->store->service_authority_transaction_poisoned,
            FALSE);
        g_atomic_int_set
            (&txn->store->service_authority_coordination_terminal, TRUE);
        wyrelog_error_t latch_rc =
            wyl_service_auth_write_lease_terminalize_cleanup
            (txn->write_lease, txn->handle);
        if (latch_rc != WYRELOG_E_OK)
          latch_rc = wyl_service_auth_write_lease_terminalize_store_fallback
              (txn->write_lease, txn->handle, txn->originating_writer_serial);
        if (latch_rc == WYRELOG_E_OK) {
          service_authority_transaction_finish (txn);
          return;
        }
      }
      g_atomic_int_set
          (&txn->store->service_authority_coordination_terminal, TRUE);
      if (txn->cleanup_result == WYRELOG_E_OK)
        txn->cleanup_result = WYRELOG_E_INTERNAL;
    }
    return;
  }

  /* SQLite is durable. Release the store mutexes, but keep the atomic active
   * bit set until all fallible coordination bookkeeping has been consumed. */
  g_mutex_unlock (&txn->store->service_lifecycle_mutex);
  g_mutex_unlock (&txn->store->service_domain_gate_mutex);
  txn->owns_store_locks = FALSE;

  if (txn->fault == WYL_POLICY_AUTHORITY_TXN_FAIL_LEASE_SERIAL_AT_FINISH)
    wyl_service_auth_write_lease_test_corrupt_serial (txn->write_lease);
  wyrelog_error_t rank_rc = txn->fault ==
      WYL_POLICY_AUTHORITY_TXN_FAIL_RANK_BEFORE ? WYRELOG_E_INTERNAL
      : wyl_service_auth_rank_leave (txn->handle,
      WYL_SERVICE_AUTH_RANK_STORE);
  if (rank_rc == WYRELOG_E_OK)
    txn->owns_store_rank = FALSE;
  wyrelog_error_t unclaim_rc = txn->fault ==
      WYL_POLICY_AUTHORITY_TXN_FAIL_CLAIM_BEFORE ? WYRELOG_E_INTERNAL
      : wyl_service_auth_write_lease_unclaim_transaction (txn->write_lease,
      txn->handle);
  if (txn->fault == WYL_POLICY_AUTHORITY_TXN_FAIL_RANK_AFTER
      || txn->fault == WYL_POLICY_AUTHORITY_TXN_FAIL_RANK_AND_CLAIM_AFTER)
    rank_rc = WYRELOG_E_INTERNAL;
  if (txn->fault == WYL_POLICY_AUTHORITY_TXN_FAIL_CLAIM_AFTER
      || txn->fault == WYL_POLICY_AUTHORITY_TXN_FAIL_RANK_AND_CLAIM_AFTER)
    unclaim_rc = WYRELOG_E_INTERNAL;
  if (rank_rc != WYRELOG_E_OK || unclaim_rc != WYRELOG_E_OK) {
    g_atomic_int_set (&txn->store->service_authority_coordination_terminal,
        TRUE);
    wyrelog_error_t latch_rc =
        wyl_service_auth_write_lease_terminalize_cleanup (txn->write_lease,
        txn->handle);
    wyrelog_error_t fallback_rc =
        wyl_service_auth_write_lease_terminalize_store_fallback
        (txn->write_lease, txn->handle, txn->originating_writer_serial);
    if (latch_rc != WYRELOG_E_OK || fallback_rc != WYRELOG_E_OK)
      latch_rc = fallback_rc;
    if (txn->owns_store_rank && latch_rc == WYRELOG_E_OK) {
      rank_rc = wyl_service_auth_rank_leave_expected (txn->handle,
          WYL_SERVICE_AUTH_RANK_STORE);
      if (rank_rc == WYRELOG_E_OK)
        txn->owns_store_rank = FALSE;
    }
    if (txn->cleanup_result == WYRELOG_E_OK)
      txn->cleanup_result = WYRELOG_E_INTERNAL;
    if (latch_rc != WYRELOG_E_OK || txn->owns_store_rank)
      return;
  }
  g_mutex_lock (&txn->cleanup_barrier_mutex);
  if (txn->cleanup_barrier_armed) {
    txn->cleanup_barrier_reached = TRUE;
    g_cond_broadcast (&txn->cleanup_barrier_cond);
    while (!txn->cleanup_barrier_released)
      g_cond_wait (&txn->cleanup_barrier_cond, &txn->cleanup_barrier_mutex);
    txn->cleanup_barrier_armed = FALSE;
  }
  g_mutex_unlock (&txn->cleanup_barrier_mutex);
  g_atomic_int_set (&txn->store->service_authority_transaction_active, FALSE);
  service_mutation_scope_leave (txn->store);
  wyl_handle_policy_store_unpin (txn->handle, txn->store);
  txn->owns_handle_pin = FALSE;
}

wyrelog_error_t
    wyl_policy_store_service_authority_transaction_begin
    (wyl_policy_store_t * store, WylHandle * handle,
    WylServiceAuthWriteLease * write_lease,
    WylServiceAuthorityTransaction ** out_transaction) {
  if (out_transaction != NULL)
    *out_transaction = NULL;
  if (store == NULL || !WYL_IS_HANDLE (handle)
      || write_lease == NULL || out_transaction == NULL)
    return WYRELOG_E_INVALID;
  wyl_policy_store_t *pinned_store = NULL;
  wyrelog_error_t rc = wyl_handle_policy_store_pin_current (handle,
      &pinned_store);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (pinned_store != store) {
    wyl_handle_policy_store_unpin (handle, pinned_store);
    return WYRELOG_E_INVALID;
  }
  if (store->db == NULL) {
    wyl_handle_policy_store_unpin (handle, store);
    return WYRELOG_E_INVALID;
  }
  rc = service_mutation_scope_enter (store);
  if (rc != WYRELOG_E_OK) {
    wyl_handle_policy_store_unpin (handle, store);
    return rc;
  }

  rc = wyl_service_auth_write_lease_claim_transaction (write_lease, handle);
  if (rc != WYRELOG_E_OK) {
    service_mutation_scope_leave (store);
    wyl_handle_policy_store_unpin (handle, store);
    return rc;
  }
  rc = wyl_service_auth_rank_enter (handle, WYL_SERVICE_AUTH_RANK_STORE);
  if (rc != WYRELOG_E_OK) {
    g_assert_cmpint (wyl_service_auth_write_lease_unclaim_transaction
        (write_lease, handle), ==, WYRELOG_E_OK);
    service_mutation_scope_leave (store);
    wyl_handle_policy_store_unpin (handle, store);
    return rc;
  }

  g_mutex_lock (&store->service_domain_gate_mutex);
  g_mutex_lock (&store->service_lifecycle_mutex);
  if (service_authority_store_unavailable (store)
      || !sqlite3_get_autocommit (store->db)
      || store->next_service_authority_transaction_id == 0) {
    g_mutex_unlock (&store->service_lifecycle_mutex);
    g_mutex_unlock (&store->service_domain_gate_mutex);
    g_assert_cmpint (wyl_service_auth_rank_leave (handle,
            WYL_SERVICE_AUTH_RANK_STORE), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_service_auth_write_lease_unclaim_transaction
        (write_lease, handle), ==, WYRELOG_E_OK);
    service_mutation_scope_leave (store);
    wyl_handle_policy_store_unpin (handle, store);
    return WYRELOG_E_BUSY;
  }

  WylServiceAuthorityTransaction *txn =
      g_new0 (WylServiceAuthorityTransaction, 1);
  g_mutex_init (&txn->write_intent_barrier_mutex);
  g_cond_init (&txn->write_intent_barrier_cond);
  g_mutex_init (&txn->abort_barrier_mutex);
  g_cond_init (&txn->abort_barrier_cond);
  g_mutex_init (&txn->cleanup_barrier_mutex);
  g_cond_init (&txn->cleanup_barrier_cond);
  txn->store = store;
  txn->handle = g_object_ref (handle);
  txn->write_lease = write_lease;
  txn->owner = g_thread_self ();
  txn->serial = store->next_service_authority_transaction_id++;
  txn->savepoint =
      g_strdup_printf ("wyrelog_service_authority_%" G_GUINT64_FORMAT,
      txn->serial);
  txn->state = WYL_SERVICE_AUTHORITY_TXN_ACTIVE;
  txn->primary_result = WYRELOG_E_OK;
  txn->cleanup_result = WYRELOG_E_OK;
  txn->fault = store->service_authority_transaction_fail_once;
  store->service_authority_transaction_fail_once =
      WYL_POLICY_AUTHORITY_TXN_FAIL_NONE;
  txn->owns_store_locks = TRUE;
  txn->owns_handle_pin = TRUE;
  txn->owns_store_rank = TRUE;
  g_assert_cmpint (wyl_service_auth_write_lease_get_serial (write_lease,
          handle, &txn->originating_writer_serial), ==, WYRELOG_E_OK);
  g_atomic_int_set (&store->service_authority_transaction_active, TRUE);

  rc = service_authority_transaction_exec (txn, "SAVEPOINT");
  if (rc != WYRELOG_E_OK) {
    txn->primary_result = rc;
    txn->state = WYL_SERVICE_AUTHORITY_TXN_FAILED_ROLLBACK;
    service_authority_transaction_finish (txn);
    g_clear_object (&txn->handle);
    g_cond_clear (&txn->write_intent_barrier_cond);
    g_mutex_clear (&txn->write_intent_barrier_mutex);
    g_cond_clear (&txn->abort_barrier_cond);
    g_mutex_clear (&txn->abort_barrier_mutex);
    g_cond_clear (&txn->cleanup_barrier_cond);
    g_mutex_clear (&txn->cleanup_barrier_mutex);
    g_free (txn->savepoint);
    g_free (txn);
    return rc;
  }
  *out_transaction = txn;
  return WYRELOG_E_OK;
}

wyrelog_error_t
    wyl_policy_store_service_authority_transaction_commit
    (WylServiceAuthorityTransaction * txn) {
  if (txn == NULL || txn->state != WYL_SERVICE_AUTHORITY_TXN_ACTIVE
      || txn->owner != g_thread_self () || !txn->owns_store_locks)
    return WYRELOG_E_INVALID;
  if (txn->write_intent_state ==
      WYL_SERVICE_AUTHORITY_WRITE_INTENT_STATE_ROLLBACK_REQUIRED
      || txn->participant_rollback_only)
    return WYRELOG_E_BUSY;

  gboolean release_succeeded = FALSE;
  wyrelog_error_t rc = wyl_service_auth_write_lease_validate_operation
      (txn->write_lease, txn->handle);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_validate_snapshot (txn->store);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_validate_service_schema (txn->store);
  if (rc == WYRELOG_E_OK) {
    if (txn->fault == WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_BEFORE
        || txn->fault == WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_AND_ROLLBACK
        || txn->fault == WYL_POLICY_AUTHORITY_TXN_FAIL_AUTHORIZER_INSTALL
        || txn->fault == WYL_POLICY_AUTHORITY_TXN_FAIL_AUTHORIZER_REMOVE) {
      rc = service_authority_transaction_fault_exec (txn,
          "RELEASE SAVEPOINT", &txn->primary_sqlite_extended_error);
    } else {
      rc = service_authority_transaction_exec (txn, "RELEASE SAVEPOINT");
      release_succeeded = rc == WYRELOG_E_OK;
      if (release_succeeded)
        service_authority_commit_evidence_transition (txn->commit_evidence,
            WYL_SERVICE_AUTHORITY_EVIDENCE_COMMITTED);
      if (rc != WYRELOG_E_OK)
        txn->primary_sqlite_extended_error = sqlite3_extended_errcode
            (txn->store->db);
      if (rc == WYRELOG_E_OK
          && txn->fault == WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_AFTER)
        rc = WYRELOG_E_IO;
    }
  }

  txn->primary_result = rc;
  if (!release_succeeded)
    service_authority_commit_evidence_transition (txn->commit_evidence,
        WYL_SERVICE_AUTHORITY_EVIDENCE_INVALID);
  if (rc == WYRELOG_E_OK) {
    txn->state = WYL_SERVICE_AUTHORITY_TXN_COMMITTED;
  } else {
    txn->cleanup_result = service_authority_transaction_restore (txn);
    txn->state = WYL_SERVICE_AUTHORITY_TXN_FAILED_COMMIT;
  }
  service_authority_transaction_finish (txn);
  if (txn->primary_result != WYRELOG_E_OK
      || txn->state != WYL_SERVICE_AUTHORITY_TXN_COMMITTED
      || txn->cleanup_result != WYRELOG_E_OK || txn->owns_store_locks
      || txn->service_exchange_pending == NULL
      || txn->service_exchange_pending->evidence != txn->commit_evidence
      || txn->service_exchange_pending->transaction_serial != txn->serial
      || wyl_handle_policy_store_validate_generation (txn->handle, txn->store,
          txn->service_exchange_pending->store_generation) != WYRELOG_E_OK)
    service_exchange_pending_clear (txn);
  return txn->primary_result;
}

gboolean
    wyl_policy_store_service_authority_transaction_is_active
    (wyl_policy_store_t * store) {
  return store != NULL
      && g_atomic_int_get (&store->service_authority_transaction_active);
}

wyrelog_error_t
    wyl_policy_store_service_authority_transaction_rollback
    (WylServiceAuthorityTransaction * txn) {
  if (txn == NULL || txn->state != WYL_SERVICE_AUTHORITY_TXN_ACTIVE
      || txn->owner != g_thread_self () || !txn->owns_store_locks)
    return WYRELOG_E_INVALID;

  service_exchange_pending_clear (txn);
  txn->primary_result = service_authority_transaction_restore (txn);
  txn->cleanup_result = txn->primary_result;
  txn->state = txn->primary_result == WYRELOG_E_OK
      ? WYL_SERVICE_AUTHORITY_TXN_ROLLED_BACK
      : WYL_SERVICE_AUTHORITY_TXN_FAILED_ROLLBACK;
  service_authority_commit_evidence_transition (txn->commit_evidence,
      WYL_SERVICE_AUTHORITY_EVIDENCE_INVALID);
  service_authority_transaction_finish (txn);
  return txn->primary_result;
}

wyrelog_error_t
    wyl_policy_store_service_authority_transaction_abort
    (WylServiceAuthorityTransaction * txn) {
  if (txn == NULL || txn->owner != g_thread_self ()
      || !txn->owns_store_locks || sqlite3_get_autocommit (txn->store->db))
    return WYRELOG_E_INVALID;
  if ((txn->state != WYL_SERVICE_AUTHORITY_TXN_FAILED_COMMIT
          && txn->state != WYL_SERVICE_AUTHORITY_TXN_FAILED_ROLLBACK)
      || !g_atomic_int_get (&txn->store->service_authority_transaction_poisoned)
      || txn->store->service_authority_poison_owner != txn->owner
      || txn->store->service_authority_poison_owner != g_thread_self ()
      || txn->store->service_authority_poison_serial != txn->serial)
    return WYRELOG_E_INVALID;

  g_atomic_int_set (&txn->store->service_authority_abort_allowed, TRUE);
  g_mutex_lock (&txn->abort_barrier_mutex);
  if (txn->abort_barrier_armed) {
    txn->abort_barrier_reached = TRUE;
    g_cond_broadcast (&txn->abort_barrier_cond);
    while (!txn->abort_barrier_released)
      g_cond_wait (&txn->abort_barrier_cond, &txn->abort_barrier_mutex);
    txn->abort_barrier_armed = FALSE;
  }
  g_mutex_unlock (&txn->abort_barrier_mutex);
  wyrelog_error_t rc = exec_sql (txn->store->db, "ROLLBACK;");
  if (rc != WYRELOG_E_OK && txn->recovery_sqlite_extended_error == SQLITE_OK)
    txn->recovery_sqlite_extended_error = sqlite3_extended_errcode
        (txn->store->db);
  g_atomic_int_set (&txn->store->service_authority_abort_allowed, FALSE);
  if (rc != WYRELOG_E_OK || !sqlite3_get_autocommit (txn->store->db))
    return rc != WYRELOG_E_OK ? rc : WYRELOG_E_IO;

  int removal_rc = txn->fault ==
      WYL_POLICY_AUTHORITY_TXN_FAIL_AUTHORIZER_REMOVE ? SQLITE_NOMEM
      : sqlite3_set_authorizer (txn->store->db, NULL, NULL);
  if (removal_rc != SQLITE_OK) {
    g_atomic_int_set (&txn->store->service_authority_coordination_terminal,
        TRUE);
    wyrelog_error_t latch_rc =
        wyl_service_auth_write_lease_terminalize_cleanup (txn->write_lease,
        txn->handle);
    wyrelog_error_t fallback_rc =
        wyl_service_auth_write_lease_terminalize_store_fallback
        (txn->write_lease, txn->handle, txn->originating_writer_serial);
    if (txn->cleanup_result == WYRELOG_E_OK)
      txn->cleanup_result = WYRELOG_E_INTERNAL;
    if (latch_rc != WYRELOG_E_OK && fallback_rc != WYRELOG_E_OK)
      return WYRELOG_E_INTERNAL;
    txn->store->service_authority_poison_owner = NULL;
    txn->store->service_authority_poison_serial = 0;
    g_atomic_int_set (&txn->store->service_authority_transaction_poisoned,
        FALSE);
    service_authority_transaction_finish (txn);
    return WYRELOG_E_INTERNAL;
  }
  txn->store->service_authority_poison_owner = NULL;
  txn->store->service_authority_poison_serial = 0;
  g_atomic_int_set (&txn->store->service_authority_transaction_poisoned, FALSE);
  service_authority_transaction_finish (txn);
  return WYRELOG_E_OK;
}

WylServiceAuthorityTransactionState
    wyl_policy_store_service_authority_transaction_get_state
    (const WylServiceAuthorityTransaction * txn)
{
  return txn != NULL ? txn->state : WYL_SERVICE_AUTHORITY_TXN_FAILED_ROLLBACK;
}

wyrelog_error_t
    wyl_policy_store_service_authority_transaction_get_primary_result
    (const WylServiceAuthorityTransaction * txn)
{
  return txn != NULL ? txn->primary_result : WYRELOG_E_INVALID;
}

wyrelog_error_t
    wyl_policy_store_service_authority_transaction_get_cleanup_result
    (const WylServiceAuthorityTransaction * txn)
{
  return txn != NULL ? txn->cleanup_result : WYRELOG_E_INVALID;
}

int
wyl_policy_store_service_authority_transaction_get_primary_sqlite_extended_error
    (const WylServiceAuthorityTransaction *txn)
{
  return txn != NULL ? txn->primary_sqlite_extended_error : SQLITE_MISUSE;
}

int
wyl_policy_store_service_authority_transaction_get_recovery_sqlite_extended_error
    (const WylServiceAuthorityTransaction *txn)
{
  return txn != NULL ? txn->recovery_sqlite_extended_error : SQLITE_MISUSE;
}

void wyl_policy_store_service_authority_transaction_abort_barrier_arm
    (WylServiceAuthorityTransaction * txn)
{
  if (txn == NULL)
    return;
  g_mutex_lock (&txn->abort_barrier_mutex);
  txn->abort_barrier_armed = TRUE;
  txn->abort_barrier_reached = FALSE;
  txn->abort_barrier_released = FALSE;
  g_mutex_unlock (&txn->abort_barrier_mutex);
}

void wyl_policy_store_service_authority_transaction_abort_barrier_wait
    (WylServiceAuthorityTransaction * txn)
{
  if (txn == NULL)
    return;
  g_mutex_lock (&txn->abort_barrier_mutex);
  while (txn->abort_barrier_armed && !txn->abort_barrier_reached)
    g_cond_wait (&txn->abort_barrier_cond, &txn->abort_barrier_mutex);
  g_mutex_unlock (&txn->abort_barrier_mutex);
}

void wyl_policy_store_service_authority_transaction_abort_barrier_release
    (WylServiceAuthorityTransaction * txn)
{
  if (txn == NULL)
    return;
  g_mutex_lock (&txn->abort_barrier_mutex);
  txn->abort_barrier_released = TRUE;
  g_cond_broadcast (&txn->abort_barrier_cond);
  g_mutex_unlock (&txn->abort_barrier_mutex);
}

void wyl_policy_store_service_authority_transaction_cleanup_barrier_arm
    (WylServiceAuthorityTransaction * txn)
{
  if (txn == NULL)
    return;
  g_mutex_lock (&txn->cleanup_barrier_mutex);
  txn->cleanup_barrier_armed = TRUE;
  txn->cleanup_barrier_reached = FALSE;
  txn->cleanup_barrier_released = FALSE;
  g_mutex_unlock (&txn->cleanup_barrier_mutex);
}

void wyl_policy_store_service_authority_transaction_cleanup_barrier_wait
    (WylServiceAuthorityTransaction * txn)
{
  if (txn == NULL)
    return;
  g_mutex_lock (&txn->cleanup_barrier_mutex);
  while (txn->cleanup_barrier_armed && !txn->cleanup_barrier_reached)
    g_cond_wait (&txn->cleanup_barrier_cond, &txn->cleanup_barrier_mutex);
  g_mutex_unlock (&txn->cleanup_barrier_mutex);
}

void wyl_policy_store_service_authority_transaction_cleanup_barrier_release
    (WylServiceAuthorityTransaction * txn)
{
  if (txn == NULL)
    return;
  g_mutex_lock (&txn->cleanup_barrier_mutex);
  txn->cleanup_barrier_released = TRUE;
  g_cond_broadcast (&txn->cleanup_barrier_cond);
  g_mutex_unlock (&txn->cleanup_barrier_mutex);
}

void wyl_policy_store_service_authority_transaction_free
    (WylServiceAuthorityTransaction * txn)
{
  if (txn == NULL)
    return;
  if (txn->state == WYL_SERVICE_AUTHORITY_TXN_ACTIVE) {
    if (txn->owner != g_thread_self ())
      return;
    (void) wyl_policy_store_service_authority_transaction_rollback (txn);
  }
  if (txn->owns_store_locks)
    return;
  service_exchange_pending_clear (txn);
  g_clear_pointer (&txn->commit_evidence,
      wyl_policy_store_service_authority_commit_evidence_unref);
  g_clear_object (&txn->handle);
  g_cond_clear (&txn->write_intent_barrier_cond);
  g_mutex_clear (&txn->write_intent_barrier_mutex);
  g_cond_clear (&txn->abort_barrier_cond);
  g_mutex_clear (&txn->abort_barrier_mutex);
  g_cond_clear (&txn->cleanup_barrier_cond);
  g_mutex_clear (&txn->cleanup_barrier_mutex);
  g_free (txn->savepoint);
  g_free (txn);
}

void wyl_policy_store_service_authority_transaction_fail_once
    (wyl_policy_store_t * store, WylPolicyAuthorityTransactionFailStage stage)
{
  if (store == NULL || stage < WYL_POLICY_AUTHORITY_TXN_FAIL_NONE
      || stage > WYL_POLICY_AUTHORITY_TXN_FAIL_LEASE_SERIAL_AT_FINISH)
    return;
  g_mutex_lock (&store->service_lifecycle_mutex);
  store->service_authority_transaction_fail_once = stage;
  g_mutex_unlock (&store->service_lifecycle_mutex);
}

void
wyl_policy_store_service_authority_transaction_fail_evidence_allocation_once
    (WylServiceAuthorityTransaction *txn)
{
  if (txn != NULL)
    txn->fail_evidence_allocation_once = TRUE;
}

guint
    wyl_policy_store_service_authority_transaction_get_evidence_allocation_count
    (const WylServiceAuthorityTransaction * txn)
{
  return txn != NULL ? txn->evidence_allocation_count : 0;
}

gboolean
    wyl_policy_store_service_authority_transaction_is_poisoned
    (wyl_policy_store_t * store) {
  if (store == NULL)
    return TRUE;
  return g_atomic_int_get (&store->service_authority_transaction_poisoned);
}

void wyl_policy_store_service_authority_transaction_test_set_poison_identity
    (WylServiceAuthorityTransaction * txn, gboolean owner_exact,
    gboolean serial_exact)
{
  if (txn == NULL)
    return;
  txn->store->service_authority_poison_owner = owner_exact ? txn->owner : NULL;
  txn->store->service_authority_poison_serial = serial_exact
      ? txn->serial : txn->serial ^ (G_GUINT64_CONSTANT (1) << 63);
}

gboolean
    wyl_policy_store_service_authority_transaction_test_poison_identity_is_clear
    (WylServiceAuthorityTransaction * txn) {
  return txn != NULL
      && txn->store->service_authority_poison_owner == NULL
      && txn->store->service_authority_poison_serial == 0;
}

wyrelog_error_t
wyl_policy_store_rotate_keyprovider (const gchar *path,
    const wyl_policy_store_open_options_t *old_opts,
    const wyl_policy_store_open_options_t *new_opts)
{
  if (path == NULL || path[0] == '\0' || old_opts == NULL || new_opts == NULL)
    return WYRELOG_E_INVALID;
  if (old_opts->keyprovider_state != NULL
      && old_opts->keyprovider_state == new_opts->keyprovider_state)
    return WYRELOG_E_INVALID;

  WylOwnedKeyProvider new_provider = { 0 };
  owned_keyprovider_adopt (&new_provider, new_opts);

  wyl_policy_store_open_options_t open_opts = *old_opts;
  open_opts.path = path;
  open_opts.require_encrypted = TRUE;

  wyl_policy_store_t *store = NULL;
  wyrelog_error_t rc = wyl_policy_store_open_with_options (&open_opts, &store);
  if (rc != WYRELOG_E_OK) {
    owned_keyprovider_release (&new_provider);
    return rc;
  }

  /* The clear work database is disposable staging for rotation. The encrypted
   * canonical file is the sole authority until its atomic replacement. */
  store->suppress_close_persist = TRUE;

  rc = wyl_policy_store_create_schema (store);
  guint8 *new_key_material = NULL;
  if (rc == WYRELOG_E_OK)
    rc = prepare_keyprovider_rotation_work (store, &new_provider,
        old_opts->rotation_runtime, &new_key_material);

  g_autofree guint8 *encrypted = NULL;
  gsize encrypted_len = 0;
  if (rc == WYRELOG_E_OK)
    rc = prepare_policy_store_encrypted (store, new_key_material,
        new_key_material + WYL_POLICY_STORE_KEY_LEN, &encrypted,
        &encrypted_len);
  /* Pre-linearization: the encrypted image is staged in memory only; a
   * signalled seam aborts before publish, leaving the old canonical root. */
  if (rc == WYRELOG_E_OK && old_opts->rotation_runtime != NULL
      && old_opts->rotation_runtime->checkpoint != NULL
      && old_opts->rotation_runtime->checkpoint (old_opts->
          rotation_runtime->data,
          WYL_POLICY_ROTATION_AFTER_ENCRYPTED_IMAGE_PREP) != 0)
    rc = WYRELOG_E_POLICY;

  gboolean replaced = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = publish_policy_store_encrypted (store, encrypted, encrypted_len,
        old_opts->rotation_runtime, &replaced);
  if (rc == WYRELOG_E_OK && !replaced)
    rc = WYRELOG_E_INTERNAL;

  if (replaced) {
    /* Rename/MoveFileEx is the linearization point. No later fallible cleanup
     * may reverse or report failure for the committed rotation. */
    wyrelog_error_t intent_rc = rotation_intent_finalize_committed (store,
        new_key_material, old_opts->rotation_runtime);
    if (intent_rc != WYRELOG_E_OK && intent_rc != WYRELOG_E_NOT_FOUND)
      WYL_LOG_WARN (WYL_LOG_SECTION_BOOT,
          "policy store rotation committed but intent finalization needs recovery");
    rc = WYRELOG_E_OK;
  }
  /* suppress_close_persist makes the new key unnecessary after publish. Keep
   * it exclusively in locked scratch and destroy it before either provider is
   * released; the store continues to hold only its old key until close wipes
   * that ordinary buffer. */
  cvk_locked_free (store, new_key_material,
      WYL_POLICY_STORE_KEY_LEN + WYL_POLICY_STORE_KEY_ID_LEN);

  if (replaced) {
    owned_keyprovider_move (&store->rotation_cleanup_keyprovider,
        &store->keyprovider);
    owned_keyprovider_move (&store->keyprovider, &new_provider);
  } else {
    owned_keyprovider_move (&store->rotation_cleanup_keyprovider,
        &new_provider);
  }

  wyl_policy_store_close (store);
  return rc;
}

wyrelog_error_t
wyl_policy_store_open_with_options (const wyl_policy_store_open_options_t *opts,
    wyl_policy_store_t **out_store)
{
  if (opts == NULL || out_store == NULL)
    return WYRELOG_E_INVALID;
  *out_store = NULL;

  const gchar *effective_path = opts->path;
  if (path_is_memory_db (effective_path))
    effective_path = ":memory:";

  wyl_policy_store_t *self = g_new0 (wyl_policy_store_t, 1);
  g_mutex_init (&self->service_cvk_mutex);
  g_mutex_init (&self->service_domain_gate_mutex);
  g_mutex_init (&self->service_lifecycle_mutex);
  g_rec_mutex_init (&self->graph_authority_mutex);
  self->fact_root_resolver = (WylFactGraphResolver)
      WYL_FACT_GRAPH_RESOLVER_INIT;
  self->next_service_authority_transaction_id = 1;
  owned_keyprovider_adopt (&self->keyprovider, opts);
  self->encrypted = opts->require_encrypted;
  self->canonical_path = g_strdup (effective_path);
  self->canonical_dirfd = -1;
  wyrelog_error_t rc = WYRELOG_E_OK;

  rc = cvk_runtime_snapshot (opts->service_cvk_runtime,
      &self->service_cvk_runtime);
  if (rc != WYRELOG_E_OK)
    goto fail;

  gboolean provider_backed = opts->require_encrypted || self->keyprovider.owned;
  if (!path_is_memory_db (effective_path) && provider_backed) {
    rc = wyl_policy_store_lease_acquire (effective_path, &self->lease);
    if (rc != WYRELOG_E_OK)
      goto fail;
    g_free (self->canonical_path);
    self->canonical_path =
        g_strdup (wyl_policy_store_lease_resolved_path (self->lease));
#ifndef G_OS_WIN32
    self->canonical_dirfd = wyl_policy_store_lease_parent_dirfd (self->lease);
    self->canonical_basename =
        g_strdup (wyl_policy_store_lease_basename (self->lease));
#endif
  }

  rc = owned_keyprovider_validate (&self->keyprovider);
  if (rc != WYRELOG_E_OK)
    goto fail;
  if (opts->require_encrypted && !self->keyprovider.owned) {
    rc = WYRELOG_E_POLICY;
    goto fail;
  }

  const gchar *open_path = self->lease != NULL ? self->canonical_path :
      effective_path;
  gboolean fresh_encrypted_memory = self->encrypted && self->db == NULL;
  if (self->encrypted) {
    if (path_is_memory_db (effective_path)) {
      rc = WYRELOG_E_POLICY;
      goto fail;
    }

    self->work_path = g_strdup_printf ("%s%s",
        self->canonical_path, WYL_POLICY_STORE_CLEAR_SUFFIX);

#ifndef G_OS_WIN32
    /* The lease owns the retained parent dirfd used by Wyrelog's encrypted
     * canonical reads, persistence, and work-file cleanup. SQLite opens the
     * work database itself by the resolved pathname. */
    self->work_basename = g_strdup_printf ("%s%s",
        self->canonical_basename, WYL_POLICY_STORE_CLEAR_SUFFIX);
    /* Best-effort sweep of any stale work file from a prior aborted
     * close. ENOENT is the common case. */
    (void) unlinkat (self->canonical_dirfd, self->work_basename, 0);
#else
    /* Windows analogue of reject_if_symlink: refuse a reparse point
     * (symbolic link, junction, or mount point) at the final component
     * of the canonical path. NOT_FOUND is the fresh-store case and is
     * not an error here; the subsequent read_whole_file call will see
     * the same ENOENT and route through the create-new path. */
    rc = reject_reparse_point_win32 (self->canonical_path);
    if (rc != WYRELOG_E_OK && rc != WYRELOG_E_NOT_FOUND)
      goto fail;
    (void) g_remove (self->work_path);
#endif

    if (owned_keyprovider_probe (&self->keyprovider) != WYRELOG_E_OK) {
      rc = WYRELOG_E_CRYPTO;
      goto fail;
    }
    rc = materialize_store_key (self, &self->keyprovider, TRUE);
    if (rc != WYRELOG_E_OK)
      goto fail;

#ifndef G_OS_WIN32
    {
      g_autofree guint8 *canonical_bytes = NULL;
      gsize canonical_len = 0;
      rc = read_through_dirfd (self->canonical_dirfd,
          self->canonical_basename, &canonical_bytes, &canonical_len);
      if (rc == WYRELOG_E_OK) {
        rc = decrypt_policy_store_from_bytes (self, canonical_bytes,
            canonical_len);
        if (rc != WYRELOG_E_OK)
          goto fail;
      } else if (rc == WYRELOG_E_NOT_FOUND) {
        /* Fresh store: fall through and let sqlite3 create the work db. */
      } else {
        goto fail;
      }
    }
#else
    {
      g_autofree guint8 *canonical_bytes = NULL;
      gsize canonical_len = 0;
      rc = read_whole_file (self->canonical_path, &canonical_bytes,
          &canonical_len);
      if (rc == WYRELOG_E_OK) {
        rc = decrypt_policy_store_from_bytes (self, canonical_bytes,
            canonical_len);
        if (rc != WYRELOG_E_OK)
          goto fail;
      } else if (rc == WYRELOG_E_NOT_FOUND) {
        /* Fresh store: fall through and let sqlite3 create the work db. */
      } else {
        goto fail;
      }
    }
#endif
    /* The decrypted image is loaded into an in-memory SQLite connection by
     * decrypt_policy_store_from_bytes(). A fresh encrypted store is opened
     * in memory below; no clear-work pathname is ever handed to SQLite. */
    open_path = NULL;
  } else {
    if (self->keyprovider.owned
        && owned_keyprovider_probe (&self->keyprovider) != WYRELOG_E_OK) {
      rc = WYRELOG_E_CRYPTO;
      goto fail;
    }
    rc = materialize_store_key (self, &self->keyprovider, FALSE);
    if (rc != WYRELOG_E_OK)
      goto fail;
    /* A provider-backed plaintext database would still make SQLite resolve
     * the main file and its journal/WAL/SHM companions by pathname.  Until a
     * pinned-capable VFS is available, reject this combination before the
     * first sqlite3_open_v2() so the retained lease cannot be undermined by a
     * pathname replacement race.  Providerless plaintext and memory stores
     * remain supported. */
    if (self->keyprovider.owned && !path_is_memory_db (effective_path)
        && !wyl_policy_store_pinned_backend_available ()) {
      rc = WYRELOG_E_POLICY;
      goto fail;
    }
  }

  if (self->lease != NULL && wyl_policy_store_lease_verify_parent (self->lease)
      != WYRELOG_E_OK) {
    rc = WYRELOG_E_POLICY;
    goto fail;
  }

  if (self->encrypted) {
    if (self->db == NULL
        && sqlite3_open_v2 (":memory:", &self->db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, NULL) != SQLITE_OK) {
      if (self->db != NULL)
        sqlite3_close (self->db);
      self->db = NULL;
      rc = WYRELOG_E_IO;
      goto fail;
    }
  } else if (sqlite3_open_v2 (open_path, &self->db,
          SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
          NULL) != SQLITE_OK) {
    if (self->db != NULL)
      sqlite3_close (self->db);
    self->db = NULL;
    rc = WYRELOG_E_IO;
    goto fail;
  }
  if (fresh_encrypted_memory
      && exec_sql (self->db,
          "CREATE TABLE __wyrelog_memory_seed (value INTEGER);"
          "DROP TABLE __wyrelog_memory_seed;") != WYRELOG_E_OK) {
    rc = WYRELOG_E_IO;
    goto fail;
  }

  if (self->lease != NULL && wyl_policy_store_lease_verify_parent (self->lease)
      != WYRELOG_E_OK) {
    sqlite3_close (self->db);
    self->db = NULL;
    if (self->deserialized_image != NULL) {
      sodium_memzero (self->deserialized_image,
          self->deserialized_image_capacity);
      sqlite3_free (self->deserialized_image);
      self->deserialized_image = NULL;
      self->deserialized_image_capacity = 0;
    }
    rc = WYRELOG_E_POLICY;
    goto fail;
  }

  const gchar *open_pragmas = self->encrypted ?
      "PRAGMA foreign_keys = ON;" "PRAGMA temp_store = MEMORY;" :
      "PRAGMA foreign_keys = ON;" "PRAGMA journal_mode = WAL;";
  if (exec_sql (self->db, open_pragmas) != WYRELOG_E_OK) {
    rc = WYRELOG_E_IO;
    goto fail;
  }
  sqlite3_busy_handler (self->db, NULL, NULL);
  if (sqlite3_busy_timeout (self->db, 0) != SQLITE_OK) {
    rc = WYRELOG_E_IO;
    goto fail;
  }
  if (sqlite3_extended_result_codes (self->db, 1) != SQLITE_OK) {
    rc = WYRELOG_E_IO;
    goto fail;
  }

  *out_store = self;
  return WYRELOG_E_OK;

fail:
  /* An unsuccessful open must never serialize a partially initialized or
   * rejected in-memory image back over the authenticated canonical bytes. */
  self->suppress_close_persist = TRUE;
  wyl_policy_store_close (self);
  return rc;
}

wyrelog_error_t
wyl_policy_store_open (const gchar *path, wyl_policy_store_t **out_store)
{
  wyl_policy_store_open_options_t opts = {.path = path };
  return wyl_policy_store_open_with_options (&opts, out_store);
}

void
wyl_policy_store_close (wyl_policy_store_t *store)
{
  if (store == NULL)
    return;
  if (store->db != NULL) {
    if (store->encrypted && !store->suppress_close_persist)
      (void) persist_policy_store_encrypted (store);
    sqlite3_close (store->db);
    store->db = NULL;
    if (store->deserialized_image != NULL) {
      sodium_memzero (store->deserialized_image,
          store->deserialized_image_capacity);
      sqlite3_free (store->deserialized_image);
      store->deserialized_image = NULL;
      store->deserialized_image_capacity = 0;
    }
    if (store->encrypted) {
#ifndef G_OS_WIN32
      if (store->canonical_dirfd >= 0 && store->work_basename != NULL)
        (void) unlinkat (store->canonical_dirfd, store->work_basename, 0);
#else
      if (store->work_path != NULL)
        (void) g_remove (store->work_path);
#endif
    }
  }
#ifndef G_OS_WIN32
  if (store->lease == NULL && store->canonical_dirfd >= 0) {
    close (store->canonical_dirfd);
    store->canonical_dirfd = -1;
  }
#endif
  policy_store_zero_key_material (store);
  cvk_locked_free (store, store->service_cvk_envelope,
      WYL_SERVICE_CVK_ENVELOPE_BYTES);
  store->service_cvk_envelope = NULL;
  owned_keyprovider_release (&store->rotation_cleanup_keyprovider);
  owned_keyprovider_release (&store->keyprovider);
  wyl_policy_store_lease_release (store->lease);
  store->lease = NULL;
  g_clear_pointer (&store->canonical_basename, g_free);
  g_clear_pointer (&store->work_basename, g_free);
  g_clear_pointer (&store->canonical_path, g_free);
  g_clear_pointer (&store->work_path, g_free);
  g_clear_pointer (&store->fact_root_path, g_free);
  wyl_fact_graph_resolver_clear (&store->fact_root_resolver);
  g_mutex_clear (&store->service_cvk_mutex);
  g_mutex_clear (&store->service_domain_gate_mutex);
  g_mutex_clear (&store->service_lifecycle_mutex);
  g_rec_mutex_clear (&store->graph_authority_mutex);
  g_free (store);
}

sqlite3 *
wyl_policy_store_get_db (wyl_policy_store_t *store)
{
  if (store == NULL)
    return NULL;
  return store->db;
}

static wyrelog_error_t
bind_fact_root_locked (wyl_policy_store_t *store, const gchar *fact_root,
    WylFactRootWriterLease *lease)
{
  if (store->fact_root_path != NULL) {
    if (g_strcmp0 (store->fact_root_path, fact_root) != 0)
      return WYRELOG_E_POLICY;
    wyrelog_error_t rc = wyl_fact_graph_resolver_revalidate
        (&store->fact_root_resolver);
    if (rc == WYRELOG_E_OK && lease != NULL)
      rc = wyl_fact_root_writer_lease_authorizes_resolver (lease,
          &store->fact_root_resolver);
    return rc;
  }

  gchar *bound_path = g_strdup (fact_root);
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  wyrelog_error_t rc = wyl_fact_graph_resolver_open (fact_root, &resolver);
  if (rc == WYRELOG_E_OK && lease != NULL)
    rc = wyl_fact_root_writer_lease_authorizes_resolver (lease, &resolver);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_graph_resolver_clear (&resolver);
    g_free (bound_path);
    return rc;
  }
  store->fact_root_resolver = resolver;
  store->fact_root_path = bound_path;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_bind_fact_root (wyl_policy_store_t *store,
    const gchar *fact_root)
{
  if (store == NULL || store->db == NULL || fact_root == NULL
      || fact_root[0] == '\0')
    return WYRELOG_E_INVALID;
  g_autoptr (GRecMutexLocker) authority_locker =
      g_rec_mutex_locker_new (&store->graph_authority_mutex);
  return bind_fact_root_locked (store, fact_root, NULL);
}

wyrelog_error_t
wyl_policy_store_bind_fact_root_authorized (wyl_policy_store_t *store,
    const gchar *fact_root, WylFactRootWriterLease *lease)
{
  if (store == NULL || store->db == NULL || fact_root == NULL
      || fact_root[0] == '\0' || lease == NULL)
    return WYRELOG_E_INVALID;
  g_autoptr (GRecMutexLocker) authority_locker =
      g_rec_mutex_locker_new (&store->graph_authority_mutex);
  return bind_fact_root_locked (store, fact_root, lease);
}

wyrelog_error_t
wyl_policy_store_open_fact_graph_directory (wyl_policy_store_t *store,
    const gchar *fact_root, const gchar *tenant_id, const gchar *graph_id,
    gboolean create, WylFactGraphDirectory *out_directory)
{
  if (out_directory == NULL)
    return WYRELOG_E_INVALID;
  *out_directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  if (store == NULL || store->db == NULL || fact_root == NULL
      || fact_root[0] == '\0')
    return WYRELOG_E_INVALID;

  WylFactGraphLocator locator = { 0 };
  wyrelog_error_t rc = wyl_fact_graph_locator_init (&locator, tenant_id,
      graph_id);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_autoptr (GRecMutexLocker) authority_locker =
      g_rec_mutex_locker_new (&store->graph_authority_mutex);
  rc = bind_fact_root_locked (store, fact_root, NULL);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_resolver_open_directory (&store->fact_root_resolver,
        &locator, create, out_directory);
  wyl_fact_graph_locator_clear (&locator);
  return rc;
}

typedef struct
{
  const gchar *table;
  const gchar *column;
  const gchar *type;
  gboolean not_null;
  const gchar *default_value;
  const gchar *constraint_sql;
  const gchar *alter_sql;
} WylGraphAuthorityColumn;

static const WylGraphAuthorityColumn graph_authority_columns[] = {
  {
        "tenants", "lifecycle_state", "TEXT", TRUE,
        "'legacy_unclassified'",
        "CHECK(lifecycle_state IN "
        "('legacy_unclassified','active','sealing','sealed','unsealing'))",
      "ALTER TABLE tenants ADD COLUMN lifecycle_state TEXT NOT NULL "
        "DEFAULT 'legacy_unclassified' CHECK (lifecycle_state IN "
        "('legacy_unclassified','active','sealing','sealed','unsealing'))"},
  {
        "tenants", "lifecycle_generation", "INTEGER", TRUE, "0",
        "CHECK(typeof(lifecycle_generation)='integer' AND "
        "lifecycle_generation BETWEEN 0 AND 9223372036854775807)",
      "ALTER TABLE tenants ADD COLUMN lifecycle_generation INTEGER NOT NULL "
        "DEFAULT 0 CHECK (typeof(lifecycle_generation)='integer' AND "
        "lifecycle_generation BETWEEN 0 AND 9223372036854775807)"},
  {
        "tenants", "reconciliation_generation", "INTEGER", TRUE, "0",
        "CHECK(typeof(reconciliation_generation)='integer' AND "
        "reconciliation_generation BETWEEN 0 AND 9223372036854775807)",
      "ALTER TABLE tenants ADD COLUMN reconciliation_generation INTEGER "
        "NOT NULL DEFAULT 0 CHECK (typeof(reconciliation_generation)="
        "'integer' AND reconciliation_generation BETWEEN 0 AND "
        "9223372036854775807)"},
  {
        "fact_graphs", "lifecycle_state", "TEXT", TRUE,
        "'legacy_unclassified'",
        "CHECK(lifecycle_state IN "
        "('legacy_unclassified','provisioning','active','sealed','degraded'))",
      "ALTER TABLE fact_graphs ADD COLUMN lifecycle_state TEXT NOT NULL "
        "DEFAULT 'legacy_unclassified' CHECK (lifecycle_state IN "
        "('legacy_unclassified','provisioning','active','sealed',"
        "'degraded'))"},
  {
        "fact_graphs", "store_uuid", "TEXT", FALSE, NULL,
        NULL,
      "ALTER TABLE fact_graphs ADD COLUMN store_uuid TEXT"},
  {
        "fact_graphs", "format_version", "INTEGER", FALSE, NULL,
        "CHECK(format_version IS NULL OR (typeof(format_version)='integer' AND "
        "format_version BETWEEN 1 AND 9223372036854775807))",
      "ALTER TABLE fact_graphs ADD COLUMN format_version INTEGER CHECK "
        "(format_version IS NULL OR (typeof(format_version)='integer' AND "
        "format_version BETWEEN 1 AND 9223372036854775807))"},
  {
        "fact_graphs", "path_encoding_version", "INTEGER", FALSE, NULL,
        "CHECK(path_encoding_version IS NULL OR "
        "(typeof(path_encoding_version)='integer' AND "
        "path_encoding_version BETWEEN 1 AND 9223372036854775807))",
      "ALTER TABLE fact_graphs ADD COLUMN path_encoding_version INTEGER CHECK "
        "(path_encoding_version IS NULL OR "
        "(typeof(path_encoding_version)='integer' AND "
        "path_encoding_version BETWEEN 1 AND 9223372036854775807))"},
  {
        "fact_graphs", "lifecycle_generation", "INTEGER", TRUE, "0",
        "CHECK(typeof(lifecycle_generation)='integer' AND "
        "lifecycle_generation BETWEEN 0 AND 9223372036854775807)",
      "ALTER TABLE fact_graphs ADD COLUMN lifecycle_generation INTEGER NOT "
        "NULL DEFAULT 0 CHECK (typeof(lifecycle_generation)='integer' AND "
        "lifecycle_generation BETWEEN 0 AND 9223372036854775807)"},
  {
        "fact_graphs", "reconciliation_generation", "INTEGER", TRUE, "0",
        "CHECK(typeof(reconciliation_generation)='integer' AND "
        "reconciliation_generation BETWEEN 0 AND 9223372036854775807)",
      "ALTER TABLE fact_graphs ADD COLUMN reconciliation_generation INTEGER "
        "NOT NULL DEFAULT 0 CHECK (typeof(reconciliation_generation)="
        "'integer' AND reconciliation_generation BETWEEN 0 AND "
        "9223372036854775807)"},
  {
        "fact_graphs", "last_error_class", "TEXT", TRUE, "'none'",
        "CHECK(last_error_class IN "
        "('none','path','identity','format','schema','open','replay',"
        "'recovery','internal'))",
      "ALTER TABLE fact_graphs ADD COLUMN last_error_class TEXT NOT NULL "
        "DEFAULT 'none' CHECK (last_error_class IN "
        "('none','path','identity','format','schema','open','replay',"
        "'recovery','internal'))"},
};

static const gchar graph_authority_uuid_index_sql[] =
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_fact_graphs_store_uuid "
    "ON fact_graphs(store_uuid) WHERE store_uuid IS NOT NULL";

static const gchar tenant_authority_insert_guard_sql[] =
    "CREATE TRIGGER IF NOT EXISTS tenant_authority_insert_guard "
    "BEFORE INSERT ON tenants BEGIN "
    "SELECT CASE WHEN NOT ("
    "typeof(NEW.lifecycle_generation)='integer' AND "
    "NEW.lifecycle_generation BETWEEN 0 AND 9223372036854775807 AND "
    "typeof(NEW.reconciliation_generation)='integer' AND "
    "NEW.reconciliation_generation BETWEEN 0 AND 9223372036854775807) "
    "THEN RAISE(ABORT,'invalid tenant generation domain') END; "
    "SELECT CASE WHEN NOT ("
    "NEW.lifecycle_state='legacy_unclassified' AND "
    "NEW.lifecycle_generation=0 AND NEW.reconciliation_generation=0) "
    "THEN RAISE(ABORT,'invalid tenant authority') END; END";

static const gchar tenant_authority_update_guard_sql[] =
    "CREATE TRIGGER IF NOT EXISTS tenant_authority_update_guard "
    "BEFORE UPDATE ON tenants BEGIN "
    "SELECT CASE WHEN NOT ("
    "typeof(NEW.lifecycle_generation)='integer' AND "
    "NEW.lifecycle_generation BETWEEN 0 AND 9223372036854775807 AND "
    "typeof(NEW.reconciliation_generation)='integer' AND "
    "NEW.reconciliation_generation BETWEEN 0 AND 9223372036854775807) "
    "THEN RAISE(ABORT,'invalid tenant generation domain') END; "
    "SELECT CASE WHEN NOT ("
    "NEW.lifecycle_state='legacy_unclassified' OR "
    "(NEW.lifecycle_state IN ('active','sealing') AND NEW.sealed=0) OR "
    "(NEW.lifecycle_state IN ('sealed','unsealing') AND NEW.sealed=1)) "
    "THEN RAISE(ABORT,'invalid tenant authority') END; "
    "SELECT CASE WHEN NEW.lifecycle_state=OLD.lifecycle_state AND "
    "NEW.lifecycle_generation!=OLD.lifecycle_generation "
    "THEN RAISE(ABORT,'invalid tenant lifecycle generation') END; "
    "SELECT CASE WHEN NEW.lifecycle_state!=OLD.lifecycle_state AND ("
    "OLD.lifecycle_generation=9223372036854775807 OR "
    "NEW.lifecycle_generation!=OLD.lifecycle_generation+1 OR NOT ("
    "(OLD.lifecycle_state='legacy_unclassified' AND "
    " NEW.lifecycle_state IN ('active','sealed')) OR "
    "(OLD.lifecycle_state='active' AND NEW.lifecycle_state='sealing') OR "
    "(OLD.lifecycle_state='sealing' AND "
    " NEW.lifecycle_state IN ('active','sealed')) OR "
    "(OLD.lifecycle_state='sealed' AND NEW.lifecycle_state='unsealing') OR "
    "(OLD.lifecycle_state='unsealing' AND "
    " NEW.lifecycle_state IN ('active','sealed')))) "
    "THEN RAISE(ABORT,'illegal tenant lifecycle transition') END; "
    "SELECT CASE WHEN NEW.reconciliation_generation<"
    "OLD.reconciliation_generation OR "
    "NEW.reconciliation_generation>OLD.reconciliation_generation+1 "
    "THEN RAISE(ABORT,'invalid tenant reconciliation generation') END; "
    "SELECT CASE WHEN OLD.lifecycle_state='legacy_unclassified' AND "
    "NEW.lifecycle_state IN ('active','sealed') AND "
    "NEW.reconciliation_generation!=OLD.reconciliation_generation+1 "
    "THEN RAISE(ABORT,'tenant promotion requires reconciliation') END; "
    "SELECT CASE WHEN NOT (OLD.lifecycle_state='legacy_unclassified' AND "
    "NEW.lifecycle_state IN ('active','sealed')) AND "
    "NEW.reconciliation_generation!=OLD.reconciliation_generation "
    "THEN RAISE(ABORT,'unexpected tenant reconciliation generation') END; "
    "END";

static const gchar graph_authority_insert_guard_sql[] =
    "CREATE TRIGGER IF NOT EXISTS fact_graph_authority_insert_guard "
    "BEFORE INSERT ON fact_graphs BEGIN "
    "SELECT CASE WHEN NOT ("
    "typeof(NEW.lifecycle_generation)='integer' AND "
    "NEW.lifecycle_generation BETWEEN 0 AND 9223372036854775807 AND "
    "typeof(NEW.reconciliation_generation)='integer' AND "
    "NEW.reconciliation_generation BETWEEN 0 AND 9223372036854775807 AND "
    "(NEW.format_version IS NULL OR (typeof(NEW.format_version)='integer' "
    " AND NEW.format_version BETWEEN 1 AND 9223372036854775807)) AND "
    "(NEW.path_encoding_version IS NULL OR "
    " (typeof(NEW.path_encoding_version)='integer' AND "
    " NEW.path_encoding_version BETWEEN 1 AND 9223372036854775807))) "
    "THEN RAISE(ABORT,'invalid graph integer domain') END; "
    "SELECT CASE WHEN NOT ("
    "(NEW.store_uuid IS NULL AND NEW.format_version IS NULL AND "
    " NEW.path_encoding_version IS NULL AND "
    " NEW.lifecycle_state='legacy_unclassified' AND "
    " NEW.lifecycle_generation=0 AND NEW.reconciliation_generation=0)) "
    "THEN RAISE(ABORT,'incomplete graph store identity') END; "
    "SELECT CASE WHEN NEW.store_uuid IS NOT NULL AND NOT ("
    "length(NEW.store_uuid)=36 AND substr(NEW.store_uuid,9,1)='-' AND "
    "substr(NEW.store_uuid,14,1)='-' AND substr(NEW.store_uuid,19,1)='-' AND "
    "substr(NEW.store_uuid,24,1)='-' AND "
    "length(replace(NEW.store_uuid,'-',''))=32 AND "
    "NEW.store_uuid NOT GLOB '*[^0-9a-f-]*') "
    "THEN RAISE(ABORT,'invalid graph store uuid') END; "
    "SELECT CASE WHEN NOT ("
    "(NEW.lifecycle_state='legacy_unclassified' AND "
    " NEW.last_error_class='none') OR "
    "(NEW.lifecycle_state='degraded' AND NEW.last_error_class!='none') OR "
    "(NEW.lifecycle_state IN ('provisioning','active','sealed') AND "
    " NEW.last_error_class='none')) "
    "THEN RAISE(ABORT,'invalid graph error class') END; "
    "SELECT CASE WHEN NOT ("
    "NEW.lifecycle_state='legacy_unclassified' OR "
    "(NEW.lifecycle_state='sealed' AND NEW.sealed=1) OR "
    "(NEW.lifecycle_state IN ('provisioning','active','degraded') AND "
    " NEW.sealed=0)) THEN RAISE(ABORT,'invalid graph sealed state') END; "
    "END";

static const gchar graph_authority_update_guard_sql[] =
    "CREATE TRIGGER IF NOT EXISTS fact_graph_authority_update_guard "
    "BEFORE UPDATE ON fact_graphs BEGIN "
    "SELECT CASE WHEN NOT ("
    "typeof(NEW.lifecycle_generation)='integer' AND "
    "NEW.lifecycle_generation BETWEEN 0 AND 9223372036854775807 AND "
    "typeof(NEW.reconciliation_generation)='integer' AND "
    "NEW.reconciliation_generation BETWEEN 0 AND 9223372036854775807 AND "
    "(NEW.format_version IS NULL OR (typeof(NEW.format_version)='integer' "
    " AND NEW.format_version BETWEEN 1 AND 9223372036854775807)) AND "
    "(NEW.path_encoding_version IS NULL OR "
    " (typeof(NEW.path_encoding_version)='integer' AND "
    " NEW.path_encoding_version BETWEEN 1 AND 9223372036854775807))) "
    "THEN RAISE(ABORT,'invalid graph integer domain') END; "
    "SELECT CASE WHEN OLD.store_uuid IS NOT NULL AND "
    "OLD.store_uuid IS NOT NEW.store_uuid "
    "THEN RAISE(ABORT,'immutable graph store uuid') END; "
    "SELECT CASE WHEN OLD.format_version IS NOT NULL AND "
    "OLD.format_version IS NOT NEW.format_version "
    "THEN RAISE(ABORT,'immutable graph format version') END; "
    "SELECT CASE WHEN OLD.path_encoding_version IS NOT NULL AND "
    "OLD.path_encoding_version IS NOT NEW.path_encoding_version "
    "THEN RAISE(ABORT,'immutable graph path encoding version') END; "
    "SELECT CASE WHEN OLD.lifecycle_state='legacy_unclassified' AND "
    "OLD.sealed=1 AND NEW.sealed=0 "
    "THEN RAISE(ABORT,'sealed legacy graph cannot be unsealed') END; "
    "SELECT CASE WHEN NOT ("
    "(NEW.store_uuid IS NULL AND NEW.format_version IS NULL AND "
    " NEW.path_encoding_version IS NULL AND "
    " NEW.lifecycle_state='legacy_unclassified') OR "
    "(NEW.store_uuid IS NOT NULL AND NEW.format_version IS NOT NULL AND "
    " NEW.path_encoding_version IS NOT NULL AND "
    " NEW.lifecycle_state!='legacy_unclassified')) "
    "THEN RAISE(ABORT,'incomplete graph store identity') END; "
    "SELECT CASE WHEN NEW.store_uuid IS NOT NULL AND NOT ("
    "length(NEW.store_uuid)=36 AND substr(NEW.store_uuid,9,1)='-' AND "
    "substr(NEW.store_uuid,14,1)='-' AND substr(NEW.store_uuid,19,1)='-' AND "
    "substr(NEW.store_uuid,24,1)='-' AND "
    "length(replace(NEW.store_uuid,'-',''))=32 AND "
    "NEW.store_uuid NOT GLOB '*[^0-9a-f-]*') "
    "THEN RAISE(ABORT,'invalid graph store uuid') END; "
    "SELECT CASE WHEN NEW.lifecycle_state=OLD.lifecycle_state AND "
    "NEW.lifecycle_generation!=OLD.lifecycle_generation "
    "THEN RAISE(ABORT,'invalid graph lifecycle generation') END; "
    "SELECT CASE WHEN NEW.lifecycle_state!=OLD.lifecycle_state AND ("
    "OLD.lifecycle_generation=9223372036854775807 OR "
    "NEW.lifecycle_generation!=OLD.lifecycle_generation+1 OR NOT ("
    "(OLD.lifecycle_state='legacy_unclassified' AND "
    " NEW.lifecycle_state='provisioning' AND OLD.sealed=0) OR "
    "(OLD.lifecycle_state='provisioning' AND "
    " NEW.lifecycle_state IN ('active','degraded')) OR "
    "(OLD.lifecycle_state='active' AND "
    " NEW.lifecycle_state IN ('sealed','degraded')) OR "
    "(OLD.lifecycle_state='sealed' AND "
    " NEW.lifecycle_state IN ('active','degraded')) OR "
    "(OLD.lifecycle_state='degraded' AND NEW.lifecycle_state='active'))) "
    "THEN RAISE(ABORT,'illegal graph lifecycle transition') END; "
    "SELECT CASE WHEN NEW.reconciliation_generation<"
    "OLD.reconciliation_generation OR "
    "NEW.reconciliation_generation>OLD.reconciliation_generation+1 "
    "THEN RAISE(ABORT,'invalid graph reconciliation generation') END; "
    "SELECT CASE WHEN OLD.lifecycle_state='degraded' AND "
    "NEW.lifecycle_state='active' AND "
    "NEW.reconciliation_generation!=OLD.reconciliation_generation+1 "
    "THEN RAISE(ABORT,'graph transition requires reconciliation') END; "
    "SELECT CASE WHEN NOT (OLD.lifecycle_state='degraded' AND "
    "NEW.lifecycle_state='active') AND "
    "NEW.reconciliation_generation!=OLD.reconciliation_generation "
    "THEN RAISE(ABORT,'unexpected graph reconciliation generation') END; "
    "SELECT CASE WHEN NEW.lifecycle_state=OLD.lifecycle_state AND "
    "NEW.last_error_class IS NOT OLD.last_error_class "
    "THEN RAISE(ABORT,'graph error class requires transition') END; "
    "SELECT CASE WHEN NOT ("
    "(NEW.lifecycle_state='legacy_unclassified' AND "
    " NEW.last_error_class='none') OR "
    "(NEW.lifecycle_state='degraded' AND NEW.last_error_class!='none') OR "
    "(NEW.lifecycle_state IN ('provisioning','active','sealed') AND "
    " NEW.last_error_class='none')) "
    "THEN RAISE(ABORT,'invalid graph error class') END; "
    "SELECT CASE WHEN NOT ("
    "NEW.lifecycle_state='legacy_unclassified' OR "
    "(NEW.lifecycle_state='sealed' AND NEW.sealed=1) OR "
    "(NEW.lifecycle_state IN ('provisioning','active','degraded') AND "
    " NEW.sealed=0)) THEN RAISE(ABORT,'invalid graph sealed state') END; "
    "END";

static gchar *
graph_authority_normalize_sql (const gchar *sql)
{
  g_autoptr (GString) normalized = g_string_new (NULL);
  gboolean in_string = FALSE;
  if (sql == NULL)
    return g_string_free (g_steal_pointer (&normalized), FALSE);
  for (const gchar * cursor = sql; *cursor != '\0'; cursor++) {
    if (in_string && *cursor == '\'' && cursor[1] == '\'') {
      g_string_append_c (normalized, *cursor);
      g_string_append_c (normalized, *++cursor);
      continue;
    }
    if (*cursor == '\'')
      in_string = !in_string;
    if (!in_string && g_ascii_isspace (*cursor))
      continue;
    g_string_append_c (normalized, *cursor);
  }
  return g_string_free (g_steal_pointer (&normalized), FALSE);
}

static gchar *
graph_authority_strip_sql_comments (const gchar *sql)
{
  g_autoptr (GString) stripped = g_string_new (NULL);
  gboolean in_string = FALSE;
  for (const gchar * cursor = sql; cursor != NULL && *cursor != '\0'; cursor++) {
    if (in_string && *cursor == '\'' && cursor[1] == '\'') {
      g_string_append_c (stripped, *cursor);
      g_string_append_c (stripped, *++cursor);
      continue;
    }
    if (*cursor == '\'') {
      in_string = !in_string;
      g_string_append_c (stripped, *cursor);
      continue;
    }
    if (!in_string && *cursor == '-' && cursor[1] == '-') {
      cursor += 2;
      while (*cursor != '\0' && *cursor != '\n' && *cursor != '\r')
        cursor++;
      if (*cursor == '\0')
        break;
      g_string_append_c (stripped, ' ');
      continue;
    }
    if (!in_string && *cursor == '/' && cursor[1] == '*') {
      cursor += 2;
      while (*cursor != '\0' && !(cursor[0] == '*' && cursor[1] == '/'))
        cursor++;
      if (*cursor == '\0')
        break;
      cursor++;
      g_string_append_c (stripped, ' ');
      continue;
    }
    g_string_append_c (stripped, *cursor);
  }
  return g_string_free (g_steal_pointer (&stripped), FALSE);
}

static gboolean
graph_authority_column_segment_has_constraint (const gchar *table_sql,
    const WylGraphAuthorityColumn *expected)
{
  g_autofree gchar *without_comments =
      graph_authority_strip_sql_comments (table_sql);
  const gchar *open = without_comments != NULL ? strchr (without_comments,
      '(') : NULL;
  if (open == NULL)
    return FALSE;
  const gchar *segment_start = open + 1;
  guint depth = 1;
  gboolean in_string = FALSE;
  for (const gchar * cursor = segment_start; *cursor != '\0'; cursor++) {
    if (in_string && *cursor == '\'' && cursor[1] == '\'') {
      cursor++;
      continue;
    }
    if (*cursor == '\'') {
      in_string = !in_string;
      continue;
    }
    if (in_string)
      continue;
    if (*cursor == '(') {
      depth++;
      continue;
    }
    gboolean segment_ends = *cursor == ',' && depth == 1;
    if (*cursor == ')') {
      if (depth == 1)
        segment_ends = TRUE;
      else
        depth--;
    }
    if (!segment_ends)
      continue;
    g_autofree gchar *segment = g_strndup (segment_start,
        (gsize) (cursor - segment_start));
    gchar *definition = g_strstrip (segment);
    gsize column_len = strlen (expected->column);
    if (strlen (definition) > column_len
        && g_ascii_strncasecmp (definition, expected->column, column_len) == 0
        && g_ascii_isspace (definition[column_len])) {
      g_autofree gchar *actual = graph_authority_normalize_sql (definition);
      g_autofree gchar *constraint =
          graph_authority_normalize_sql (expected->constraint_sql);
      return strstr (actual, constraint) != NULL;
    }
    if (*cursor == ')')
      break;
    segment_start = cursor + 1;
  }
  return FALSE;
}

static wyrelog_error_t
graph_authority_table_has_constraint (sqlite3 *db,
    const WylGraphAuthorityColumn *expected, gboolean *out_matches)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT sql FROM sqlite_master WHERE type='table' AND name=?;";
  *out_matches = FALSE;
  if (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL) != SQLITE_OK)
    return WYRELOG_E_IO;
  if (bind_text (stmt, 1, expected->table) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  int step = sqlite3_step (stmt);
  if (step == SQLITE_ROW) {
    const gchar *table_sql = (const gchar *) sqlite3_column_text (stmt, 0);
    *out_matches = graph_authority_column_segment_has_constraint (table_sql,
        expected);
  }
  sqlite3_finalize (stmt);
  if (step != SQLITE_ROW)
    return step == SQLITE_DONE ? WYRELOG_E_POLICY : WYRELOG_E_IO;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
graph_authority_column_status (sqlite3 *db,
    const WylGraphAuthorityColumn *expected, gboolean *out_exists,
    gboolean *out_matches)
{
  sqlite3_stmt *stmt = NULL;
  g_autofree gchar *sql = g_strdup_printf ("PRAGMA table_info(%s);",
      expected->table);
  *out_exists = FALSE;
  *out_matches = FALSE;
  if (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL) != SQLITE_OK)
    return WYRELOG_E_IO;
  while (sqlite3_step (stmt) == SQLITE_ROW) {
    const gchar *name = (const gchar *) sqlite3_column_text (stmt, 1);
    if (g_strcmp0 (name, expected->column) != 0)
      continue;
    const gchar *type = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *default_value = (const gchar *) sqlite3_column_text (stmt, 4);
    *out_exists = TRUE;
    *out_matches = g_ascii_strcasecmp (type, expected->type) == 0
        && (sqlite3_column_int (stmt, 3) != 0) == expected->not_null
        && g_strcmp0 (default_value, expected->default_value) == 0;
    break;
  }
  sqlite3_finalize (stmt);
  if (*out_exists && *out_matches && expected->constraint_sql != NULL) {
    gboolean constraint_matches = FALSE;
    wyrelog_error_t rc = graph_authority_table_has_constraint (db, expected,
        &constraint_matches);
    if (rc != WYRELOG_E_OK)
      return rc;
    *out_matches = constraint_matches;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
graph_authority_object_matches (sqlite3 *db, const gchar *type,
    const gchar *name, const gchar *expected_sql)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT sql FROM sqlite_master WHERE type=? AND name=?;";
  if (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL) != SQLITE_OK)
    return WYRELOG_E_IO;
  if (bind_text (stmt, 1, type) != WYRELOG_E_OK
      || bind_text (stmt, 2, name) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  int step = sqlite3_step (stmt);
  const gchar *actual = step == SQLITE_ROW ?
      (const gchar *) sqlite3_column_text (stmt, 0) : NULL;
  g_autofree gchar *canonical = g_strdup (expected_sql);
  gchar *if_not_exists = strstr (canonical, " IF NOT EXISTS");
  if (if_not_exists != NULL)
    memmove (if_not_exists, if_not_exists + strlen (" IF NOT EXISTS"),
        strlen (if_not_exists + strlen (" IF NOT EXISTS")) + 1);
  g_autofree gchar *actual_normalized = graph_authority_normalize_sql (actual);
  g_autofree gchar *expected_normalized =
      graph_authority_normalize_sql (canonical);
  gboolean matches = actual != NULL
      && g_strcmp0 (actual_normalized, expected_normalized) == 0;
  sqlite3_finalize (stmt);
  if (step != SQLITE_ROW)
    return step == SQLITE_DONE ? WYRELOG_E_POLICY : WYRELOG_E_IO;
  return matches ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
validate_graph_authority_rows (sqlite3 *db)
{
  static const gchar *const validation_queries[] = {
    "SELECT EXISTS(SELECT 1 FROM tenants WHERE "
        "typeof(lifecycle_generation)!='integer' OR "
        "lifecycle_generation NOT BETWEEN 0 AND 9223372036854775807 OR "
        "typeof(reconciliation_generation)!='integer' OR "
        "reconciliation_generation NOT BETWEEN 0 AND 9223372036854775807 OR "
        "lifecycle_state NOT IN "
        "('legacy_unclassified','active','sealing','sealed','unsealing') OR "
        "sealed NOT IN (0,1) OR NOT ("
        "lifecycle_state='legacy_unclassified' OR "
        "(lifecycle_state IN ('active','sealing') AND sealed=0) OR "
        "(lifecycle_state IN ('sealed','unsealing') AND sealed=1)));",
    "SELECT EXISTS(SELECT 1 FROM fact_graphs WHERE "
        "typeof(lifecycle_generation)!='integer' OR "
        "lifecycle_generation NOT BETWEEN 0 AND 9223372036854775807 OR "
        "typeof(reconciliation_generation)!='integer' OR "
        "reconciliation_generation NOT BETWEEN 0 AND 9223372036854775807 OR "
        "(format_version IS NOT NULL AND "
        " (typeof(format_version)!='integer' OR "
        " format_version NOT BETWEEN 1 AND 9223372036854775807)) OR "
        "(path_encoding_version IS NOT NULL AND "
        " (typeof(path_encoding_version)!='integer' OR "
        " path_encoding_version NOT BETWEEN 1 AND 9223372036854775807)) OR "
        "(store_uuid IS NOT NULL AND (typeof(store_uuid)!='text' OR NOT ("
        " length(store_uuid)=36 AND substr(store_uuid,9,1)='-' AND "
        " substr(store_uuid,14,1)='-' AND substr(store_uuid,19,1)='-' AND "
        " substr(store_uuid,24,1)='-' AND "
        " length(replace(store_uuid,'-',''))=32 AND "
        " store_uuid NOT GLOB '*[^0-9a-f-]*'))) OR NOT ("
        "(store_uuid IS NULL AND format_version IS NULL AND "
        " path_encoding_version IS NULL AND "
        " lifecycle_state='legacy_unclassified') OR "
        "(store_uuid IS NOT NULL AND format_version IS NOT NULL AND "
        " path_encoding_version IS NOT NULL AND "
        " lifecycle_state!='legacy_unclassified')) OR "
        "lifecycle_state NOT IN "
        "('legacy_unclassified','provisioning','active','sealed','degraded') OR "
        "last_error_class NOT IN "
        "('none','path','identity','format','schema','open','replay',"
        "'recovery','internal') OR NOT ("
        "(lifecycle_state='legacy_unclassified' AND last_error_class='none') OR "
        "(lifecycle_state='degraded' AND last_error_class!='none') OR "
        "(lifecycle_state IN ('provisioning','active','sealed') AND "
        " last_error_class='none')) OR sealed NOT IN (0,1) OR NOT ("
        "lifecycle_state='legacy_unclassified' OR "
        "(lifecycle_state='sealed' AND sealed=1) OR "
        "(lifecycle_state IN ('provisioning','active','degraded') AND "
        " sealed=0)));",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (validation_queries); i++) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2 (db, validation_queries[i], -1, &stmt, NULL) !=
        SQLITE_OK)
      return WYRELOG_E_IO;
    int step = sqlite3_step (stmt);
    gboolean invalid = step == SQLITE_ROW && sqlite3_column_int (stmt, 0) != 0;
    sqlite3_finalize (stmt);
    if (step != SQLITE_ROW)
      return WYRELOG_E_IO;
    if (invalid)
      return WYRELOG_E_POLICY;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
validate_graph_authority_schema (sqlite3 *db)
{
  for (gsize i = 0; i < G_N_ELEMENTS (graph_authority_columns); i++) {
    gboolean exists = FALSE, matches = FALSE;
    wyrelog_error_t rc = graph_authority_column_status (db,
        &graph_authority_columns[i], &exists, &matches);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (!exists || !matches)
      return WYRELOG_E_POLICY;
  }
  static const struct
  {
    const gchar *type;
    const gchar *name;
    const gchar *sql;
  } objects[] = {
    {"index", "idx_fact_graphs_store_uuid", graph_authority_uuid_index_sql},
    {"trigger", "tenant_authority_insert_guard",
        tenant_authority_insert_guard_sql},
    {"trigger", "tenant_authority_update_guard",
        tenant_authority_update_guard_sql},
    {"trigger", "fact_graph_authority_insert_guard",
        graph_authority_insert_guard_sql},
    {"trigger", "fact_graph_authority_update_guard",
        graph_authority_update_guard_sql},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (objects); i++) {
    wyrelog_error_t rc = graph_authority_object_matches (db, objects[i].type,
        objects[i].name, objects[i].sql);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  return validate_graph_authority_rows (db);
}

static wyrelog_error_t
graph_authority_migration_checkpoint (wyl_policy_store_t *store,
    WylPolicyGraphAuthorityMigrationFailStage stage)
{
  if (store->graph_authority_migration_fail_once != stage)
    return WYRELOG_E_OK;
  store->graph_authority_migration_fail_once =
      WYL_POLICY_GRAPH_AUTHORITY_MIGRATION_FAIL_NONE;
  return WYRELOG_E_IO;
}

void
wyl_policy_store_graph_authority_migration_fail_once (wyl_policy_store_t *store,
    WylPolicyGraphAuthorityMigrationFailStage stage)
{
  if (store == NULL || stage <=
      WYL_POLICY_GRAPH_AUTHORITY_MIGRATION_FAIL_NONE || stage >=
      WYL_POLICY_GRAPH_AUTHORITY_MIGRATION_FAIL_COUNT)
    return;
  store->graph_authority_migration_fail_once = stage;
}

void
wyl_policy_store_graph_authority_mutation_fail_once (wyl_policy_store_t *store,
    WylPolicyGraphAuthorityMutationFailStage stage)
{
  if (store == NULL || stage <=
      WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_NONE || stage >=
      WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_COUNT)
    return;
  store->mutation_fail_once = stage;
}

static wyrelog_error_t
migrate_graph_authority_schema (wyl_policy_store_t *store)
{
  sqlite3 *db = store->db;
  for (gsize i = 0; i < G_N_ELEMENTS (graph_authority_columns); i++) {
    gboolean exists = FALSE, matches = FALSE;
    wyrelog_error_t rc = graph_authority_column_status (db,
        &graph_authority_columns[i], &exists, &matches);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (exists && !matches)
      return WYRELOG_E_POLICY;
    if (!exists && (rc = exec_sql (db,
                graph_authority_columns[i].alter_sql)) != WYRELOG_E_OK)
      return rc;
  }
  wyrelog_error_t rc = graph_authority_migration_checkpoint (store,
      WYL_POLICY_GRAPH_AUTHORITY_MIGRATION_FAIL_AFTER_COLUMNS);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = exec_sql (db, graph_authority_uuid_index_sql)) != WYRELOG_E_OK)
    return rc;
  if ((rc = graph_authority_migration_checkpoint (store,
              WYL_POLICY_GRAPH_AUTHORITY_MIGRATION_FAIL_AFTER_UUID_INDEX)) !=
      WYRELOG_E_OK)
    return rc;
  if ((rc = exec_sql (db, tenant_authority_insert_guard_sql)) != WYRELOG_E_OK
      || (rc = exec_sql (db, tenant_authority_update_guard_sql)) !=
      WYRELOG_E_OK)
    return rc;
  if ((rc = graph_authority_migration_checkpoint (store,
              WYL_POLICY_GRAPH_AUTHORITY_MIGRATION_FAIL_AFTER_TENANT_TRIGGERS))
      != WYRELOG_E_OK)
    return rc;
  if ((rc = exec_sql (db, graph_authority_insert_guard_sql)) != WYRELOG_E_OK
      || (rc = exec_sql (db, graph_authority_update_guard_sql)) != WYRELOG_E_OK)
    return rc;
  if ((rc = graph_authority_migration_checkpoint (store,
              WYL_POLICY_GRAPH_AUTHORITY_MIGRATION_FAIL_AFTER_GRAPH_TRIGGERS))
      != WYRELOG_E_OK)
    return rc;
  if ((rc = graph_authority_migration_checkpoint (store,
              WYL_POLICY_GRAPH_AUTHORITY_MIGRATION_FAIL_BEFORE_VALIDATION)) !=
      WYRELOG_E_OK)
    return rc;
  return validate_graph_authority_schema (db);
}

wyrelog_error_t
wyl_policy_store_create_schema (wyl_policy_store_t *store)
{
  /* wyrelog_config holds singleton config rows. Keys currently in use:
   *   deployment_mode               - 'production' | 'development' | 'demo'
   *   bootstrap_admin_subject       - subject id of the bootstrap admin,
   *                                   or the 'legacy-skip' sentinel
   *   bootstrap_admin_sealed_at_us  - wallclock us at seal time (decimal)
   *   bootstrap_admin_allow_skip_mfa - '0' or '1'
   * Unknown keys are tolerated by the CHECK so this column can carry
   * forward-compatible additions, but the known keys constrain their
   * value space. */
  static const gchar *ddl =
      "CREATE TABLE IF NOT EXISTS wyrelog_config ("
      "  config_key TEXT PRIMARY KEY,"
      "  config_value TEXT NOT NULL CHECK ("
      "    (config_key = 'deployment_mode' AND "
      "       config_value IN ('production', 'development', 'demo')) OR "
      "    (config_key = 'bootstrap_admin_subject') OR "
      "    (config_key = 'bootstrap_admin_sealed_at_us') OR "
      "    (config_key = 'bootstrap_admin_allow_skip_mfa' AND "
      "       config_value IN ('0', '1')) OR "
      "    (config_key NOT IN ('deployment_mode', "
      "       'bootstrap_admin_subject', 'bootstrap_admin_sealed_at_us', "
      "       'bootstrap_admin_allow_skip_mfa'))"
      "  ),"
      "  updated_at INTEGER NOT NULL"
      ");"
      "CREATE TABLE IF NOT EXISTS tenants ("
      "  tenant_id TEXT PRIMARY KEY,"
      "  sealed INTEGER NOT NULL DEFAULT 0 CHECK (sealed IN (0, 1)),"
      "  lifecycle_state TEXT NOT NULL DEFAULT 'legacy_unclassified' "
      "    CHECK (lifecycle_state IN ('legacy_unclassified', 'active', "
      "      'sealing', 'sealed', 'unsealing')),"
      "  lifecycle_generation INTEGER NOT NULL DEFAULT 0 "
      "    CHECK (typeof(lifecycle_generation) = 'integer' AND "
      "      lifecycle_generation BETWEEN 0 AND 9223372036854775807),"
      "  reconciliation_generation INTEGER NOT NULL DEFAULT 0 "
      "    CHECK (typeof(reconciliation_generation) = 'integer' AND "
      "      reconciliation_generation BETWEEN 0 AND 9223372036854775807),"
      "  created_at INTEGER NOT NULL,"
      "  updated_at INTEGER NOT NULL"
      ");"
      "CREATE TABLE IF NOT EXISTS roles ("
      "  role_id TEXT PRIMARY KEY,"
      "  role_name TEXT UNIQUE NOT NULL,"
      "  description TEXT,"
      "  created_at INTEGER,"
      "  modified_at INTEGER"
      ");"
      "CREATE TABLE IF NOT EXISTS permissions ("
      "  perm_id TEXT PRIMARY KEY,"
      "  perm_name TEXT UNIQUE NOT NULL,"
      "  class TEXT NOT NULL CHECK "
      "    (class IN ('basic', 'sensitive', 'critical')),"
      "  created_at INTEGER"
      ");"
      "CREATE TABLE IF NOT EXISTS role_permissions ("
      "  role_id TEXT NOT NULL,"
      "  perm_id TEXT NOT NULL,"
      "  granted_at INTEGER,"
      "  granted_by TEXT,"
      "  PRIMARY KEY (role_id, perm_id),"
      "  FOREIGN KEY (role_id) REFERENCES roles (role_id),"
      "  FOREIGN KEY (perm_id) REFERENCES permissions (perm_id)"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id "
      "  ON role_permissions (role_id);"
      "CREATE INDEX IF NOT EXISTS idx_role_permissions_perm_id "
      "  ON role_permissions (perm_id);"
      "CREATE TABLE IF NOT EXISTS role_inheritances ("
      "  child_role_id TEXT NOT NULL,"
      "  parent_role_id TEXT NOT NULL,"
      "  granted_at INTEGER,"
      "  granted_by TEXT,"
      "  PRIMARY KEY (child_role_id, parent_role_id),"
      "  FOREIGN KEY (child_role_id) REFERENCES roles (role_id),"
      "  FOREIGN KEY (parent_role_id) REFERENCES roles (role_id)"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_role_inheritances_child "
      "  ON role_inheritances (child_role_id);"
      "CREATE INDEX IF NOT EXISTS idx_role_inheritances_parent "
      "  ON role_inheritances (parent_role_id);"
      "CREATE TABLE IF NOT EXISTS role_memberships ("
      "  subject_id TEXT NOT NULL,"
      "  role_id TEXT NOT NULL,"
      "  scope TEXT NOT NULL,"
      "  granted_at INTEGER,"
      "  granted_by TEXT,"
      "  PRIMARY KEY (subject_id, role_id, scope),"
      "  FOREIGN KEY (role_id) REFERENCES roles (role_id)"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_role_memberships_role_id "
      "  ON role_memberships (role_id);"
      "CREATE INDEX IF NOT EXISTS idx_role_memberships_subject_scope "
      "  ON role_memberships (subject_id, scope);"
      "CREATE TABLE IF NOT EXISTS role_membership_events ("
      "  event_id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "  subject_id TEXT NOT NULL,"
      "  role_id TEXT NOT NULL,"
      "  scope TEXT NOT NULL,"
      "  operation TEXT NOT NULL CHECK (operation IN ('grant', 'revoke')),"
      "  created_at INTEGER NOT NULL,"
      "  FOREIGN KEY (role_id) REFERENCES roles (role_id)"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_role_membership_events_subject "
      "  ON role_membership_events (subject_id);"
      "CREATE INDEX IF NOT EXISTS idx_role_membership_events_role "
      "  ON role_membership_events (role_id);"
      "CREATE TABLE IF NOT EXISTS direct_permissions ("
      "  subject_id TEXT NOT NULL,"
      "  perm_id TEXT NOT NULL,"
      "  scope TEXT NOT NULL,"
      "  granted_at INTEGER,"
      "  PRIMARY KEY (subject_id, perm_id, scope),"
      "  FOREIGN KEY (perm_id) REFERENCES permissions (perm_id)"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_direct_permissions_perm_id "
      "  ON direct_permissions (perm_id);"
      "CREATE INDEX IF NOT EXISTS idx_direct_permissions_subject_scope "
      "  ON direct_permissions (subject_id, scope);"
      "CREATE TABLE IF NOT EXISTS direct_permission_events ("
      "  event_id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "  subject_id TEXT NOT NULL,"
      "  perm_id TEXT NOT NULL,"
      "  scope TEXT NOT NULL,"
      "  operation TEXT NOT NULL CHECK "
      "    (operation IN ('grant', 'revoke')),"
      "  created_at INTEGER NOT NULL"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_direct_permission_events_subject "
      "  ON direct_permission_events (subject_id);"
      "CREATE INDEX IF NOT EXISTS idx_direct_permission_events_perm "
      "  ON direct_permission_events (perm_id);"
      "CREATE TABLE IF NOT EXISTS permission_states ("
      "  subject_id TEXT NOT NULL,"
      "  perm_id TEXT NOT NULL,"
      "  scope TEXT NOT NULL,"
      "  state TEXT NOT NULL,"
      "  updated_at INTEGER,"
      "  PRIMARY KEY (subject_id, perm_id, scope)"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_permission_states_state "
      "  ON permission_states (state);"
      "CREATE INDEX IF NOT EXISTS idx_permission_states_perm "
      "  ON permission_states (perm_id);"
      "CREATE TABLE IF NOT EXISTS permission_state_events ("
      "  event_id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "  subject_id TEXT NOT NULL,"
      "  perm_id TEXT NOT NULL,"
      "  scope TEXT NOT NULL,"
      "  event TEXT NOT NULL,"
      "  from_state TEXT NOT NULL,"
      "  to_state TEXT NOT NULL,"
      "  created_at INTEGER NOT NULL"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_permission_state_events_subject "
      "  ON permission_state_events (subject_id);"
      "CREATE INDEX IF NOT EXISTS idx_permission_state_events_perm "
      "  ON permission_state_events (perm_id);"
      "CREATE INDEX IF NOT EXISTS idx_permission_state_events_event "
      "  ON permission_state_events (event);"
      "CREATE TABLE IF NOT EXISTS principal_states ("
      "  subject_id TEXT PRIMARY KEY,"
      "  state TEXT NOT NULL," "  updated_at INTEGER,"
      /* Issue #331 commit 5: lockout counter and lock timestamp live on
       * the principal_states row.  failed_attempt_count is the running
       * tally of consecutive verify failures since the last successful
       * MFA verify (or admin reset); locked_at is the unix-epoch seconds
       * timestamp the row entered the LOCKED state, NULL otherwise.
       * Pre-#331-commit-5 stores get these columns via the
       * ALTER TABLE migration block below in create_schema (idempotent
       * via PRAGMA table_info probe). */
      "  failed_attempt_count INTEGER NOT NULL DEFAULT 0,"
      "  locked_at INTEGER"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_principal_states_state "
      "  ON principal_states (state);"
      "CREATE TABLE IF NOT EXISTS principal_events ("
      "  event_id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "  subject_id TEXT NOT NULL,"
      "  event TEXT NOT NULL,"
      "  from_state TEXT NOT NULL,"
      "  to_state TEXT NOT NULL,"
      "  created_at INTEGER NOT NULL"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_principal_events_subject_id "
      "  ON principal_events (subject_id);"
      "CREATE INDEX IF NOT EXISTS idx_principal_events_event "
      "  ON principal_events (event);"
      "CREATE TABLE IF NOT EXISTS session_states ("
      "  session_id TEXT PRIMARY KEY,"
      "  state TEXT NOT NULL,"
      "  updated_at INTEGER"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_session_states_state "
      "  ON session_states (state);"
      "CREATE TABLE IF NOT EXISTS session_events ("
      "  event_id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "  session_id TEXT NOT NULL,"
      "  event TEXT NOT NULL,"
      "  from_state TEXT NOT NULL,"
      "  to_state TEXT NOT NULL,"
      "  created_at INTEGER NOT NULL"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_session_events_session_id "
      "  ON session_events (session_id);"
      "CREATE INDEX IF NOT EXISTS idx_session_events_event "
      "  ON session_events (event);"
      "CREATE TABLE IF NOT EXISTS audit_events ("
      "  id TEXT PRIMARY KEY,"
      "  created_at_us INTEGER NOT NULL,"
      "  subject_id TEXT,"
      "  action TEXT,"
      "  resource_id TEXT,"
      "  deny_reason TEXT,"
      "  deny_origin TEXT,"
      "  request_id TEXT,"
      "  decision INTEGER NOT NULL CHECK (decision IN (0, 1))"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_created_at_us "
      "  ON audit_events (created_at_us);"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_subject_id "
      "  ON audit_events (subject_id);"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_action "
      "  ON audit_events (action);"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_decision "
      "  ON audit_events (decision);"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_deny_reason "
      "  ON audit_events (deny_reason);"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_deny_origin "
      "  ON audit_events (deny_origin);"
      "CREATE TABLE IF NOT EXISTS audit_intentions ("
      "  audit_id TEXT PRIMARY KEY,"
      "  created_at_us INTEGER NOT NULL,"
      "  subject_id TEXT,"
      "  action TEXT,"
      "  resource_id TEXT,"
      "  deny_reason TEXT,"
      "  deny_origin TEXT,"
      "  request_id TEXT,"
      "  decision INTEGER NOT NULL CHECK (decision IN (0, 1)),"
      "  state TEXT NOT NULL CHECK "
      "    (state IN ('pending', 'committed', 'failed')),"
      "  created_at INTEGER NOT NULL,"
      "  updated_at INTEGER NOT NULL,"
      "  attempt_count INTEGER NOT NULL DEFAULT 0,"
      "  last_error TEXT,"
      "  chain_prev TEXT,"
      "  chain_hash TEXT,"
      "  anchor_batch_id TEXT"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_audit_intentions_state "
      "  ON audit_intentions (state);"
      "CREATE INDEX IF NOT EXISTS idx_audit_intentions_action "
      "  ON audit_intentions (action);"
      "CREATE INDEX IF NOT EXISTS idx_audit_intentions_updated "
      "  ON audit_intentions (updated_at);"
      "CREATE TABLE IF NOT EXISTS fact_graphs ("
      "  tenant_id TEXT NOT NULL,"
      "  graph_id TEXT NOT NULL,"
      "  storage_uri TEXT NOT NULL,"
      "  storage_path TEXT NOT NULL,"
      "  schema_version INTEGER NOT NULL CHECK (schema_version > 0),"
      "  owner_scope TEXT NOT NULL CHECK (owner_scope = tenant_id),"
      "  sealed INTEGER NOT NULL DEFAULT 0 CHECK (sealed IN (0, 1)),"
      "  lifecycle_state TEXT NOT NULL DEFAULT 'legacy_unclassified' "
      "    CHECK (lifecycle_state IN ('legacy_unclassified', "
      "      'provisioning', 'active', 'sealed', 'degraded')),"
      "  store_uuid TEXT,"
      "  format_version INTEGER CHECK (format_version IS NULL OR "
      "    (typeof(format_version) = 'integer' AND "
      "      format_version BETWEEN 1 AND 9223372036854775807)),"
      "  path_encoding_version INTEGER CHECK (path_encoding_version IS NULL "
      "    OR (typeof(path_encoding_version) = 'integer' AND "
      "      path_encoding_version BETWEEN 1 AND 9223372036854775807)),"
      "  lifecycle_generation INTEGER NOT NULL DEFAULT 0 "
      "    CHECK (typeof(lifecycle_generation) = 'integer' AND "
      "      lifecycle_generation BETWEEN 0 AND 9223372036854775807),"
      "  reconciliation_generation INTEGER NOT NULL DEFAULT 0 "
      "    CHECK (typeof(reconciliation_generation) = 'integer' AND "
      "      reconciliation_generation BETWEEN 0 AND 9223372036854775807),"
      "  last_error_class TEXT NOT NULL DEFAULT 'none' CHECK "
      "    (last_error_class IN ('none', 'path', 'identity', 'format', "
      "      'schema', 'open', 'replay', 'recovery', 'internal')),"
      "  created_at INTEGER NOT NULL,"
      "  updated_at INTEGER NOT NULL,"
      "  sealed_at INTEGER,"
      "  PRIMARY KEY (tenant_id, graph_id),"
      "  FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id)"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_fact_graphs_tenant "
      "  ON fact_graphs (tenant_id);"
      "CREATE TABLE IF NOT EXISTS fact_reconcile_journal ("
      "  op_uuid TEXT PRIMARY KEY,"
      "  tenant_id TEXT NOT NULL,"
      "  graph_id TEXT NOT NULL,"
      "  expected_lifecycle_generation INTEGER NOT NULL CHECK "
      "    (expected_lifecycle_generation >= 0),"
      "  expected_reconciliation_generation INTEGER NOT NULL CHECK "
      "    (expected_reconciliation_generation >= 0),"
      "  expected_store_uuid TEXT,"
      "  source_relative_path TEXT NOT NULL CHECK "
      "    (length(source_relative_path) > 0 AND instr(source_relative_path, '/') > 0),"
      "  canonical_relative_path TEXT NOT NULL CHECK "
      "    (length(canonical_relative_path) > 0 AND instr(canonical_relative_path, '/') > 0),"
      "  state TEXT NOT NULL DEFAULT 'prepared' CHECK "
      "    (state IN ('prepared', 'moving', 'moved', 'identity_committed', "
      "      'authority_committed', 'done', 'aborted', 'needs_review')),"
      "  attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),"
      "  created_at INTEGER NOT NULL,"
      "  updated_at INTEGER NOT NULL,"
      "  FOREIGN KEY (tenant_id, graph_id) REFERENCES fact_graphs "
      "    (tenant_id, graph_id)"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_fact_reconcile_journal_state "
      "  ON fact_reconcile_journal (state, updated_at);"
      "CREATE TABLE IF NOT EXISTS fact_graph_relations ("
      "  tenant_id TEXT NOT NULL,"
      "  graph_id TEXT NOT NULL,"
      "  relation_name TEXT NOT NULL,"
      "  arity INTEGER NOT NULL CHECK (arity > 0),"
      "  PRIMARY KEY (tenant_id, graph_id, relation_name),"
      "  FOREIGN KEY (tenant_id, graph_id) "
      "    REFERENCES fact_graphs (tenant_id, graph_id) "
      "    ON DELETE CASCADE"
      ");"
      "CREATE TABLE IF NOT EXISTS fact_graph_relation_columns ("
      "  tenant_id TEXT NOT NULL,"
      "  graph_id TEXT NOT NULL,"
      "  relation_name TEXT NOT NULL,"
      "  column_index INTEGER NOT NULL CHECK (column_index >= 0),"
      "  column_name TEXT NOT NULL,"
      "  column_type TEXT NOT NULL CHECK "
      "    (column_type IN ('symbol', 'int64', 'bool', 'compound_ref')),"
      "  PRIMARY KEY (tenant_id, graph_id, relation_name, column_index),"
      "  FOREIGN KEY (tenant_id, graph_id, relation_name) "
      "    REFERENCES fact_graph_relations "
      "      (tenant_id, graph_id, relation_name) "
      "    ON DELETE CASCADE"
      ");"
      "CREATE TABLE IF NOT EXISTS fact_graph_query_allowlist ("
      "  tenant_id TEXT NOT NULL,"
      "  graph_id TEXT NOT NULL,"
      "  query_name TEXT NOT NULL,"
      "  relation_name TEXT NOT NULL,"
      "  required_permission_id TEXT NOT NULL,"
      "  max_rows INTEGER NOT NULL CHECK (max_rows > 0),"
      "  PRIMARY KEY (tenant_id, graph_id, query_name),"
      "  FOREIGN KEY (tenant_id, graph_id, relation_name) "
      "    REFERENCES fact_graph_relations "
      "      (tenant_id, graph_id, relation_name),"
      "  FOREIGN KEY (required_permission_id) REFERENCES permissions (perm_id)"
      ");"
      "CREATE TABLE IF NOT EXISTS fact_namespaces ("
      "  tenant_id TEXT NOT NULL,"
      "  graph_id TEXT NOT NULL,"
      "  namespace_id TEXT NOT NULL,"
      "  visibility INTEGER NOT NULL DEFAULT 1 CHECK (visibility IN (0, 1)),"
      "  created_at INTEGER NOT NULL,"
      "  updated_at INTEGER NOT NULL,"
      "  PRIMARY KEY (tenant_id, graph_id, namespace_id),"
      "  FOREIGN KEY (tenant_id, graph_id) "
      "    REFERENCES fact_graphs (tenant_id, graph_id) "
      "    ON DELETE CASCADE"
      ");"
      "CREATE TABLE IF NOT EXISTS fact_relation_schemas ("
      "  tenant_id TEXT NOT NULL,"
      "  graph_id TEXT NOT NULL,"
      "  namespace_id TEXT NOT NULL,"
      "  relation_name TEXT NOT NULL,"
      "  schema_version INTEGER NOT NULL CHECK (schema_version > 0),"
      "  arity INTEGER NOT NULL CHECK (arity > 0),"
      "  relation_visible INTEGER NOT NULL DEFAULT 1 CHECK "
      "    (relation_visible IN (0, 1)),"
      "  created_at INTEGER NOT NULL,"
      "  updated_at INTEGER NOT NULL,"
      "  PRIMARY KEY (tenant_id, graph_id, namespace_id, relation_name, "
      "    schema_version),"
      "  FOREIGN KEY (tenant_id, graph_id, namespace_id) "
      "    REFERENCES fact_namespaces (tenant_id, graph_id, namespace_id) "
      "    ON DELETE CASCADE"
      ");"
      "CREATE TABLE IF NOT EXISTS fact_relation_schema_columns ("
      "  tenant_id TEXT NOT NULL,"
      "  graph_id TEXT NOT NULL,"
      "  namespace_id TEXT NOT NULL,"
      "  relation_name TEXT NOT NULL,"
      "  schema_version INTEGER NOT NULL CHECK (schema_version > 0),"
      "  column_index INTEGER NOT NULL CHECK (column_index >= 0),"
      "  column_name TEXT NOT NULL,"
      "  column_type TEXT NOT NULL CHECK "
      "    (column_type IN ('symbol', 'string', 'int64', 'bool', "
      "      'compound_ref')),"
      "  nullable INTEGER NOT NULL DEFAULT 0 CHECK (nullable IN (0, 1)),"
      "  visible INTEGER NOT NULL DEFAULT 1 CHECK (visible IN (0, 1)),"
      "  PRIMARY KEY (tenant_id, graph_id, namespace_id, relation_name, "
      "    schema_version, column_index),"
      "  UNIQUE (tenant_id, graph_id, namespace_id, relation_name, "
      "    schema_version, column_name),"
      "  FOREIGN KEY (tenant_id, graph_id, namespace_id, relation_name, "
      "    schema_version) REFERENCES fact_relation_schemas "
      "      (tenant_id, graph_id, namespace_id, relation_name, "
      "        schema_version) "
      "    ON DELETE CASCADE"
      ");"
      "CREATE TABLE IF NOT EXISTS fact_relation_query_allowlist ("
      "  tenant_id TEXT NOT NULL,"
      "  graph_id TEXT NOT NULL,"
      "  namespace_id TEXT NOT NULL,"
      "  relation_name TEXT NOT NULL,"
      "  schema_version INTEGER NOT NULL CHECK (schema_version > 0),"
      "  query_name TEXT NOT NULL,"
      "  required_permission_id TEXT NOT NULL,"
      "  max_rows INTEGER NOT NULL CHECK (max_rows > 0),"
      "  PRIMARY KEY (tenant_id, graph_id, query_name),"
      "  FOREIGN KEY (tenant_id, graph_id, namespace_id, relation_name, "
      "    schema_version) REFERENCES fact_relation_schemas "
      "      (tenant_id, graph_id, namespace_id, relation_name, "
      "        schema_version),"
      "  FOREIGN KEY (required_permission_id) REFERENCES permissions (perm_id)"
      ");"
      "CREATE TABLE IF NOT EXISTS policy_signatures ("
      "  policy_version INTEGER PRIMARY KEY,"
      "  policy_hash BLOB NOT NULL,"
      "  signature BLOB NOT NULL,"
      "  signed_by TEXT NOT NULL," "  signed_at INTEGER NOT NULL" ");"
      /* TOTP enrollment per principal (issue #331).  secret_blob is
       * the raw RFC 6238 SHA-1 seed (20 bytes).  last_verified_step is
       * the replay watermark stored as INTEGER (no native u64 in
       * SQLite); INT64_MIN means "never verified".  id_uuidv7 is the
       * libchronoid UUIDv7 minted at insert time.  CREATE TABLE IF
       * NOT EXISTS makes the migration onto a pre-#331 store
       * transparent on first re-invocation of create_schema. */
      "CREATE TABLE IF NOT EXISTS totp_enrollments ("
      "  subject_id TEXT PRIMARY KEY,"
      "  secret_blob BLOB NOT NULL,"
      "  last_verified_step INTEGER NOT NULL,"
      "  enrolled_at INTEGER NOT NULL," "  id_uuidv7 TEXT NOT NULL" ");";

  if (store == NULL || store->db == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = exec_sql (store->db,
      "SAVEPOINT wyrelog_graph_authority_schema;");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = exec_sql (store->db, ddl);
  if (rc == WYRELOG_E_OK)
    rc = graph_authority_migration_checkpoint (store,
        WYL_POLICY_GRAPH_AUTHORITY_MIGRATION_FAIL_AFTER_BASE_DDL);
  if (rc == WYRELOG_E_OK)
    rc = migrate_graph_authority_schema (store);
  if (rc == WYRELOG_E_OK)
    rc = graph_authority_migration_checkpoint (store,
        WYL_POLICY_GRAPH_AUTHORITY_MIGRATION_FAIL_BEFORE_RELEASE);
  if (rc == WYRELOG_E_OK) {
    wyrelog_error_t release_rc = exec_sql (store->db,
        "RELEASE SAVEPOINT wyrelog_graph_authority_schema;");
    if (release_rc != WYRELOG_E_OK) {
      (void) exec_sql (store->db,
          "ROLLBACK TO SAVEPOINT wyrelog_graph_authority_schema;");
      (void) exec_sql (store->db,
          "RELEASE SAVEPOINT wyrelog_graph_authority_schema;");
      return release_rc;
    }
  } else {
    (void) exec_sql (store->db,
        "ROLLBACK TO SAVEPOINT wyrelog_graph_authority_schema;");
    (void) exec_sql (store->db,
        "RELEASE SAVEPOINT wyrelog_graph_authority_schema;");
    return rc;
  }
  sqlite3_stmt *stmt = NULL;
  gboolean has_request_id = FALSE;
  if (sqlite3_prepare_v2 (store->db, "PRAGMA table_info(audit_events);", -1,
          &stmt, NULL) != SQLITE_OK)
    return WYRELOG_E_IO;
  while (sqlite3_step (stmt) == SQLITE_ROW) {
    const gchar *name = (const gchar *) sqlite3_column_text (stmt, 1);
    if (g_strcmp0 (name, "request_id") == 0) {
      has_request_id = TRUE;
      break;
    }
  }
  sqlite3_finalize (stmt);
  if (!has_request_id) {
    rc = exec_sql (store->db,
        "ALTER TABLE audit_events ADD COLUMN request_id TEXT;");
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  rc = exec_sql (store->db,
      "CREATE INDEX IF NOT EXISTS idx_audit_events_request_id "
      "ON audit_events (request_id);");
  if (rc != WYRELOG_E_OK)
    return rc;
  /* Issue #331 commit 5: principal_states lockout columns migration.
   * Pre-#331-commit-5 stores have the principal_states row but lack
   * failed_attempt_count and locked_at.  We probe via PRAGMA table_info
   * and ALTER TABLE ADD COLUMN only on miss, matching the audit_events
   * migration pattern above.  ADD COLUMN with a literal DEFAULT
   * synthesises the value for existing rows, so post-migration the
   * counter starts at 0 (no false-lock on upgrade). */
  gboolean has_failed_count = FALSE;
  gboolean has_locked_at = FALSE;
  sqlite3_stmt *ps_stmt = NULL;
  if (sqlite3_prepare_v2 (store->db, "PRAGMA table_info(principal_states);",
          -1, &ps_stmt, NULL) != SQLITE_OK)
    return WYRELOG_E_IO;
  while (sqlite3_step (ps_stmt) == SQLITE_ROW) {
    const gchar *name = (const gchar *) sqlite3_column_text (ps_stmt, 1);
    if (g_strcmp0 (name, "failed_attempt_count") == 0)
      has_failed_count = TRUE;
    else if (g_strcmp0 (name, "locked_at") == 0)
      has_locked_at = TRUE;
  }
  sqlite3_finalize (ps_stmt);
  if (!has_failed_count) {
    rc = exec_sql (store->db,
        "ALTER TABLE principal_states "
        "ADD COLUMN failed_attempt_count INTEGER NOT NULL DEFAULT 0;");
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  if (!has_locked_at) {
    rc = exec_sql (store->db,
        "ALTER TABLE principal_states ADD COLUMN locked_at INTEGER;");
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  rc = wyl_policy_store_ensure_default_tenant (store);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = seed_builtin_catalog (store->db);
  if (rc != WYRELOG_E_OK)
    return rc;

  /* One-shot backward-compat migration for pre-#305 stores: if the
   * store already has at least one wr.system_admin role membership
   * but no bootstrap_admin_subject marker, seal it with the
   * 'legacy-skip' sentinel. This prevents an operator who upgrades
   * such a store and then re-runs with --bootstrap-admin-subject
   * from silently minting a second admin on a store that already
   * has one. */
  rc = exec_sql (store->db,
      "INSERT INTO wyrelog_config (config_key, config_value, updated_at) "
      "SELECT 'bootstrap_admin_subject', 'legacy-skip', unixepoch() "
      "WHERE NOT EXISTS ("
      "  SELECT 1 FROM wyrelog_config "
      "  WHERE config_key = 'bootstrap_admin_subject') "
      "  AND EXISTS ("
      "    SELECT 1 FROM role_memberships "
      "    WHERE role_id = 'wr.system_admin');");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = exec_sql (store->db,
      "INSERT INTO wyrelog_config (config_key, config_value, updated_at) "
      "SELECT 'bootstrap_admin_sealed_at_us', '0', unixepoch() "
      "WHERE EXISTS ("
      "  SELECT 1 FROM wyrelog_config "
      "  WHERE config_key = 'bootstrap_admin_subject' "
      "    AND config_value = 'legacy-skip') "
      "  AND NOT EXISTS ("
      "    SELECT 1 FROM wyrelog_config "
      "    WHERE config_key = 'bootstrap_admin_sealed_at_us');");
  if (rc != WYRELOG_E_OK)
    return rc;

  /* Apply all seven inert service-authority tables, their indexes and their
   * ten immutability/append-only triggers atomically. CREATE TABLE IF NOT
   * EXISTS cannot repair a malformed same-name legacy object, so validate
   * before release and roll the entire service migration back on mismatch. */
  rc = exec_sql (store->db, "SAVEPOINT wyrelog_service_schema;");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = exec_sql (store->db, service_schema_ddl);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_validate_service_schema (store);
  if (rc == WYRELOG_E_OK) {
    wyrelog_error_t release_rc =
        exec_sql (store->db, "RELEASE SAVEPOINT wyrelog_service_schema;");
    return release_rc;
  }
  (void) exec_sql (store->db, "ROLLBACK TO SAVEPOINT wyrelog_service_schema;");
  (void) exec_sql (store->db, "RELEASE SAVEPOINT wyrelog_service_schema;");
  return rc;
}

gsize
wyl_policy_store_required_table_count (void)
{
  return G_N_ELEMENTS (required_tables);
}

const gchar *
wyl_policy_store_required_table_name (gsize idx)
{
  if (idx >= G_N_ELEMENTS (required_tables))
    return NULL;
  return required_tables[idx];
}

gsize
wyl_policy_store_builtin_role_count (void)
{
  return G_N_ELEMENTS (builtin_roles);
}

const gchar *
wyl_policy_store_builtin_role_id (gsize idx)
{
  if (idx >= G_N_ELEMENTS (builtin_roles))
    return NULL;
  return builtin_roles[idx].id;
}

gsize
wyl_policy_store_builtin_permission_count (void)
{
  return G_N_ELEMENTS (builtin_permissions);
}

const gchar *
wyl_policy_store_builtin_permission_id (gsize idx)
{
  if (idx >= G_N_ELEMENTS (builtin_permissions))
    return NULL;
  return builtin_permissions[idx].id;
}

wyrelog_error_t
wyl_policy_store_set_deployment_mode (wyl_policy_store_t *store,
    const gchar *mode)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || mode == NULL)
    return WYRELOG_E_INVALID;
  if (!deployment_mode_is_valid (mode))
    return WYRELOG_E_POLICY;

  static const gchar *sql =
      "INSERT INTO wyrelog_config (config_key, config_value, updated_at) "
      "VALUES ('deployment_mode', ?, unixepoch()) "
      "ON CONFLICT(config_key) DO UPDATE SET "
      "  config_value = excluded.config_value,"
      "  updated_at = excluded.updated_at;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, mode)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_get_deployment_mode (wyl_policy_store_t *store,
    gchar **out_mode)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || out_mode == NULL)
    return WYRELOG_E_INVALID;

  *out_mode = NULL;
  static const gchar *sql =
      "SELECT config_value FROM wyrelog_config "
      "WHERE config_key = 'deployment_mode';";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW) {
    const gchar *mode = (const gchar *) sqlite3_column_text (stmt, 0);
    if (!deployment_mode_is_valid (mode)) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_POLICY;
    }
    *out_mode = g_strdup (mode);
  } else if (step_rc == SQLITE_DONE) {
    *out_mode = g_strdup ("production");
  } else {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_ensure_default_tenant (wyl_policy_store_t *store)
{
  gboolean created = FALSE;
  return wyl_policy_store_create_tenant (store, WYL_TENANT_DEFAULT, &created);
}

wyrelog_error_t
wyl_policy_store_create_tenant (wyl_policy_store_t *store,
    const gchar *tenant_id, gboolean *out_created)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || out_created == NULL ||
      !wyl_policy_store_tenant_id_is_valid (tenant_id))
    return WYRELOG_E_INVALID;
  *out_created = FALSE;
  g_autoptr (GRecMutexLocker) authority_locker =
      g_rec_mutex_locker_new (&store->graph_authority_mutex);

  static const gchar *sql =
      "INSERT OR IGNORE INTO tenants "
      "(tenant_id, sealed, created_at, updated_at) "
      "VALUES (?, 0, unixepoch(), unixepoch());";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, tenant_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_DONE)
    *out_created = sqlite3_changes (store->db) > 0;
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_set_tenant_sealed (wyl_policy_store_t *store,
    const gchar *tenant_id, gboolean sealed)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL ||
      !wyl_policy_store_tenant_id_is_valid (tenant_id))
    return WYRELOG_E_INVALID;
  if (sealed && g_strcmp0 (tenant_id, WYL_TENANT_DEFAULT) == 0)
    return WYRELOG_E_POLICY;
  g_autoptr (GRecMutexLocker) authority_locker =
      g_rec_mutex_locker_new (&store->graph_authority_mutex);

  static const gchar *sql =
      "UPDATE tenants SET sealed = ?, updated_at = unixepoch() "
      "WHERE tenant_id = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (sqlite3_bind_int (stmt, 1, sealed ? 1 : 0) != SQLITE_OK ||
      (rc = bind_text (stmt, 2, tenant_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  int step_rc = sqlite3_step (stmt);
  gboolean changed = sqlite3_changes (store->db) > 0;
  sqlite3_finalize (stmt);
  if (step_rc != SQLITE_DONE)
    return WYRELOG_E_IO;
  return changed ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_policy_store_tenant_exists (wyl_policy_store_t *store,
    const gchar *tenant_id, gboolean *out_exists)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || out_exists == NULL ||
      !wyl_policy_store_tenant_id_is_valid (tenant_id))
    return WYRELOG_E_INVALID;
  *out_exists = FALSE;

  static const gchar *sql =
      "SELECT 1 FROM tenants WHERE tenant_id = ? LIMIT 1;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, tenant_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW)
    *out_exists = TRUE;
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_ROW || step_rc == SQLITE_DONE) ?
      WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_tenant_is_active (wyl_policy_store_t *store,
    const gchar *tenant_id, gboolean *out_active)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || out_active == NULL ||
      !wyl_policy_store_tenant_id_is_valid (tenant_id))
    return WYRELOG_E_INVALID;
  *out_active = FALSE;

  static const gchar *sql =
      "SELECT sealed FROM tenants WHERE tenant_id = ? LIMIT 1;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, tenant_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW)
    *out_active = sqlite3_column_int (stmt, 0) == 0;
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_ROW || step_rc == SQLITE_DONE) ?
      WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_foreach_tenant (wyl_policy_store_t *store,
    wyl_policy_tenant_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT tenant_id, sealed FROM tenants ORDER BY tenant_id ASC;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *tenant_id = (const gchar *) sqlite3_column_text (stmt, 0);
    gboolean sealed = sqlite3_column_int (stmt, 1) != 0;
    rc = cb (tenant_id, sealed, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static gboolean
fact_graph_component_is_valid (const gchar *component)
{
  if (component == NULL)
    return FALSE;

  gsize len = strlen (component);
  if (len == 0 || len > 128)
    return FALSE;
  if (g_strcmp0 (component, ".") == 0 || g_strcmp0 (component, "..") == 0)
    return FALSE;

  for (const gchar * p = component; *p != '\0'; p++) {
    guchar c = (guchar) * p;
    if (g_ascii_isalnum (c))
      continue;
    if (c == '.' || c == '_' || c == ':' || c == '-')
      continue;
    return FALSE;
  }
  return TRUE;
}

static gboolean
fact_graph_customer_name_is_valid (const gchar *name)
{
  if (!fact_graph_component_is_valid (name))
    return FALSE;
  if (g_strcmp0 (name, "wr") == 0 || g_str_has_prefix (name, "wr.")
      || g_str_has_prefix (name, "__wyrelog."))
    return FALSE;
  return TRUE;
}

static gboolean
fact_graph_column_type_is_valid (const gchar *column_type)
{
  return g_strcmp0 (column_type, "symbol") == 0
      || g_strcmp0 (column_type, "int64") == 0
      || g_strcmp0 (column_type, "bool") == 0
      || g_strcmp0 (column_type, "compound_ref") == 0;
}

static gboolean
fact_relation_schema_column_type_is_valid (const gchar *column_type)
{
  return g_strcmp0 (column_type, "symbol") == 0
      || g_strcmp0 (column_type, "string") == 0
      || g_strcmp0 (column_type, "int64") == 0
      || g_strcmp0 (column_type, "bool") == 0
      || g_strcmp0 (column_type, "compound_ref") == 0;
}

static gboolean
fact_graph_options_relation_exists (const wyl_policy_fact_graph_create_options_t
    *opts, const gchar *relation_name)
{
  for (gsize i = 0; i < opts->n_relations; i++) {
    if (g_strcmp0 (opts->relations[i].relation_name, relation_name) == 0)
      return TRUE;
  }
  return FALSE;
}

static wyrelog_error_t
validate_fact_graph_options (wyl_policy_store_t *store,
    const wyl_policy_fact_graph_create_options_t *opts)
{
  if (store == NULL || store->db == NULL || opts == NULL)
    return WYRELOG_E_INVALID;
  if (!wyl_policy_store_tenant_id_is_valid (opts->tenant_id)
      || !fact_graph_component_is_valid (opts->tenant_id)
      || !fact_graph_customer_name_is_valid (opts->graph_id)
      || opts->fact_root == NULL || opts->fact_root[0] == '\0'
      || opts->schema_version == 0 || opts->owner_scope == NULL
      || g_strcmp0 (opts->owner_scope, opts->tenant_id) != 0)
    return WYRELOG_E_INVALID;
  if (opts->relations == NULL && opts->n_relations > 0)
    return WYRELOG_E_INVALID;
  if (opts->queries == NULL && opts->n_queries > 0)
    return WYRELOG_E_INVALID;
  if (opts->n_relations == 0 && opts->n_queries > 0)
    return WYRELOG_E_POLICY;

  for (gsize i = 0; i < opts->n_relations; i++) {
    const wyl_policy_fact_graph_relation_t *rel = &opts->relations[i];
    if (!fact_graph_customer_name_is_valid (rel->relation_name)
        || rel->columns == NULL || rel->n_columns == 0
        || rel->n_columns > G_MAXINT)
      return WYRELOG_E_POLICY;
    for (gsize j = 0; j < i; j++) {
      if (g_strcmp0 (opts->relations[j].relation_name, rel->relation_name) == 0)
        return WYRELOG_E_POLICY;
    }
    for (gsize j = 0; j < rel->n_columns; j++) {
      if (!fact_graph_customer_name_is_valid (rel->columns[j].column_name)
          || !fact_graph_column_type_is_valid (rel->columns[j].column_type))
        return WYRELOG_E_POLICY;
      for (gsize k = 0; k < j; k++) {
        if (g_strcmp0 (rel->columns[k].column_name,
                rel->columns[j].column_name) == 0)
          return WYRELOG_E_POLICY;
      }
    }
  }

  for (gsize i = 0; i < opts->n_queries; i++) {
    const wyl_policy_fact_graph_query_t *query = &opts->queries[i];
    if (!fact_graph_customer_name_is_valid (query->query_name)
        || !fact_graph_options_relation_exists (opts, query->relation_name)
        || query->required_permission_id == NULL
        || query->required_permission_id[0] == '\0' || query->max_rows == 0
        || query->max_rows > WYL_POLICY_FACT_QUERY_MAX_ROWS)
      return WYRELOG_E_POLICY;
    gboolean permission_exists = FALSE;
    wyrelog_error_t rc = wyl_policy_store_permission_exists (store,
        query->required_permission_id, &permission_exists);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (!permission_exists)
      return WYRELOG_E_POLICY;
  }

  return WYRELOG_E_OK;
}

static wyrelog_error_t
materialize_fact_graph_storage (wyl_policy_store_t *store,
    const wyl_policy_fact_graph_create_options_t *opts,
    gchar **out_storage_path, gchar **out_storage_uri)
{
  if (store == NULL || opts == NULL || out_storage_path == NULL
      || out_storage_uri == NULL)
    return WYRELOG_E_INVALID;
  *out_storage_path = NULL;
  *out_storage_uri = NULL;

  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  wyrelog_error_t rc = wyl_policy_store_open_fact_graph_directory (store,
      opts->fact_root, opts->tenant_id, opts->graph_id, TRUE, &directory);
  g_autofree gchar *graph_path = NULL;
  if (rc == WYRELOG_E_OK) {
    graph_path = wyl_fact_graph_directory_descriptive_path (&directory);
    if (graph_path == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  g_autofree gchar *uri = rc == WYRELOG_E_OK ?
      g_filename_to_uri (graph_path, NULL, NULL) : NULL;
  if (uri == NULL)
    rc = rc == WYRELOG_E_OK ? WYRELOG_E_IO : rc;

  if (rc == WYRELOG_E_OK) {
    *out_storage_path = g_steal_pointer (&graph_path);
    *out_storage_uri = g_steal_pointer (&uri);
  }
  wyl_fact_graph_directory_clear (&directory);
  return rc;
}

static wyrelog_error_t
fact_graph_existing_sealed (wyl_policy_store_t *store, const gchar *tenant_id,
    const gchar *graph_id, gboolean *out_exists, gboolean *out_sealed)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || out_exists == NULL
      || out_sealed == NULL)
    return WYRELOG_E_INVALID;
  *out_exists = FALSE;
  *out_sealed = FALSE;

  static const gchar *sql =
      "SELECT sealed FROM fact_graphs "
      "WHERE tenant_id = ? AND graph_id = ? LIMIT 1;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, tenant_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, graph_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW) {
    *out_exists = TRUE;
    *out_sealed = sqlite3_column_int (stmt, 0) != 0;
  }
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_ROW || step_rc == SQLITE_DONE) ?
      WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
insert_fact_graph_metadata (wyl_policy_store_t *store,
    const wyl_policy_fact_graph_create_options_t *opts,
    const gchar *storage_path, const gchar *storage_uri)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "INSERT INTO fact_graphs "
      "(tenant_id, graph_id, storage_uri, storage_path, schema_version, "
      " owner_scope, sealed, created_at, updated_at) "
      "VALUES (?, ?, ?, ?, ?, ?, 0, unixepoch(), unixepoch());";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, opts->tenant_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, opts->graph_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, storage_uri)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 4, storage_path)) != WYRELOG_E_OK
      || sqlite3_bind_int64 (stmt, 5, opts->schema_version) != SQLITE_OK
      || (rc = bind_text (stmt, 6, opts->owner_scope)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
insert_fact_graph_relation_metadata (wyl_policy_store_t *store,
    const wyl_policy_fact_graph_create_options_t *opts,
    const wyl_policy_fact_graph_relation_t *rel)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "INSERT INTO fact_graph_relations "
      "(tenant_id, graph_id, relation_name, arity) VALUES (?, ?, ?, ?);";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, opts->tenant_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, opts->graph_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, rel->relation_name)) != WYRELOG_E_OK
      || sqlite3_bind_int64 (stmt, 4, rel->n_columns) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
insert_fact_graph_column_metadata (wyl_policy_store_t *store,
    const wyl_policy_fact_graph_create_options_t *opts,
    const wyl_policy_fact_graph_relation_t *rel, gsize column_index)
{
  sqlite3_stmt *stmt = NULL;
  const wyl_policy_fact_graph_column_t *column = &rel->columns[column_index];
  static const gchar *sql =
      "INSERT INTO fact_graph_relation_columns "
      "(tenant_id, graph_id, relation_name, column_index, column_name, "
      " column_type) VALUES (?, ?, ?, ?, ?, ?);";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, opts->tenant_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, opts->graph_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, rel->relation_name)) != WYRELOG_E_OK
      || sqlite3_bind_int64 (stmt, 4, (sqlite3_int64) column_index)
      != SQLITE_OK || (rc = bind_text (stmt, 5, column->column_name))
      != WYRELOG_E_OK || (rc = bind_text (stmt, 6, column->column_type))
      != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
insert_fact_graph_query_metadata (wyl_policy_store_t *store,
    const wyl_policy_fact_graph_create_options_t *opts,
    const wyl_policy_fact_graph_query_t *query)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "INSERT INTO fact_graph_query_allowlist "
      "(tenant_id, graph_id, query_name, relation_name, "
      " required_permission_id, max_rows) VALUES (?, ?, ?, ?, ?, ?);";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, opts->tenant_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, opts->graph_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, query->query_name)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 4, query->relation_name)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 5, query->required_permission_id))
      != WYRELOG_E_OK || sqlite3_bind_int64 (stmt, 6, query->max_rows)
      != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_create_fact_graph (wyl_policy_store_t *store,
    const wyl_policy_fact_graph_create_options_t *opts, gchar **out_storage_uri)
{
  if (out_storage_uri != NULL)
    *out_storage_uri = NULL;

  wyrelog_error_t rc = validate_fact_graph_options (store, opts);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_autoptr (GRecMutexLocker) authority_locker =
      g_rec_mutex_locker_new (&store->graph_authority_mutex);

  gboolean tenant_exists = FALSE;
  rc = wyl_policy_store_tenant_exists (store, opts->tenant_id, &tenant_exists);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!tenant_exists)
    return WYRELOG_E_NOT_FOUND;

  gboolean tenant_active = FALSE;
  rc = wyl_policy_store_tenant_is_active (store, opts->tenant_id,
      &tenant_active);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!tenant_active)
    return WYRELOG_E_POLICY;

  gboolean graph_exists = FALSE;
  gboolean graph_sealed = FALSE;
  rc = fact_graph_existing_sealed (store, opts->tenant_id, opts->graph_id,
      &graph_exists, &graph_sealed);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (graph_exists || graph_sealed)
    return WYRELOG_E_POLICY;

  g_autofree gchar *storage_path = NULL;
  g_autofree gchar *storage_uri = NULL;
  rc = materialize_fact_graph_storage (store, opts, &storage_path,
      &storage_uri);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = wyl_policy_store_begin_mutation (store);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = insert_fact_graph_metadata (store, opts, storage_path, storage_uri);
  for (gsize i = 0; rc == WYRELOG_E_OK && i < opts->n_relations; i++) {
    const wyl_policy_fact_graph_relation_t *rel = &opts->relations[i];
    rc = insert_fact_graph_relation_metadata (store, opts, rel);
    for (gsize j = 0; rc == WYRELOG_E_OK && j < rel->n_columns; j++)
      rc = insert_fact_graph_column_metadata (store, opts, rel, j);
  }
  for (gsize i = 0; rc == WYRELOG_E_OK && i < opts->n_queries; i++)
    rc = insert_fact_graph_query_metadata (store, opts, &opts->queries[i]);

  if (rc != WYRELOG_E_OK) {
    wyl_policy_store_rollback_mutation (store);
    return rc;
  }
  rc = wyl_policy_store_commit_mutation (store);
  if (rc != WYRELOG_E_OK)
    return rc;

  if (out_storage_uri != NULL)
    *out_storage_uri = g_strdup (storage_uri);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_foreach_fact_graph (wyl_policy_store_t *store,
    const gchar *tenant_id, wyl_policy_fact_graph_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;
  if (tenant_id != NULL && !wyl_policy_store_tenant_id_is_valid (tenant_id))
    return WYRELOG_E_INVALID;

  const gchar *sql =
      tenant_id == NULL ?
      "SELECT tenant_id, graph_id, storage_uri, storage_path, "
      "schema_version, owner_scope, sealed FROM fact_graphs "
      "ORDER BY tenant_id, graph_id;" :
      "SELECT tenant_id, graph_id, storage_uri, storage_path, "
      "schema_version, owner_scope, sealed FROM fact_graphs "
      "WHERE tenant_id = ? ORDER BY graph_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (tenant_id != NULL
      && (rc = bind_text (stmt, 1, tenant_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    wyl_policy_fact_graph_info_t info = {
      .tenant_id = (const gchar *) sqlite3_column_text (stmt, 0),
      .graph_id = (const gchar *) sqlite3_column_text (stmt, 1),
      .storage_uri = (const gchar *) sqlite3_column_text (stmt, 2),
      .storage_path = (const gchar *) sqlite3_column_text (stmt, 3),
      .schema_version = (guint32) sqlite3_column_int64 (stmt, 4),
      .owner_scope = (const gchar *) sqlite3_column_text (stmt, 5),
      .sealed = sqlite3_column_int (stmt, 6) != 0,
    };
    rc = cb (&info, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_seal_fact_graph (wyl_policy_store_t *store,
    const gchar *tenant_id, const gchar *graph_id)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL
      || !wyl_policy_store_tenant_id_is_valid (tenant_id)
      || !fact_graph_component_is_valid (tenant_id)
      || !fact_graph_customer_name_is_valid (graph_id))
    return WYRELOG_E_INVALID;
  g_autoptr (GRecMutexLocker) authority_locker =
      g_rec_mutex_locker_new (&store->graph_authority_mutex);

  gboolean exists = FALSE;
  gboolean sealed = FALSE;
  wyrelog_error_t rc = fact_graph_existing_sealed (store, tenant_id, graph_id,
      &exists, &sealed);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!exists)
    return WYRELOG_E_NOT_FOUND;
  if (sealed)
    return WYRELOG_E_OK;

  static const gchar *sql =
      "UPDATE fact_graphs "
      "SET sealed = 1, sealed_at = unixepoch(), updated_at = unixepoch() "
      "WHERE tenant_id = ? AND graph_id = ? AND sealed = 0;";
  rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, tenant_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, graph_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_fact_graph_is_active (wyl_policy_store_t *store,
    const gchar *tenant_id, const gchar *graph_id, gboolean *out_active)
{
  if (store == NULL || store->db == NULL || out_active == NULL
      || !wyl_policy_store_tenant_id_is_valid (tenant_id)
      || !fact_graph_component_is_valid (tenant_id)
      || !fact_graph_customer_name_is_valid (graph_id))
    return WYRELOG_E_INVALID;
  *out_active = FALSE;

  gboolean graph_exists = FALSE;
  gboolean graph_sealed = FALSE;
  wyrelog_error_t rc = fact_graph_existing_sealed (store, tenant_id, graph_id,
      &graph_exists, &graph_sealed);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!graph_exists)
    return WYRELOG_E_OK;

  gboolean tenant_active = FALSE;
  rc = wyl_policy_store_tenant_is_active (store, tenant_id, &tenant_active);
  if (rc != WYRELOG_E_OK)
    return rc;
  *out_active = tenant_active && !graph_sealed;
  return WYRELOG_E_OK;
}

static gboolean
tenant_lifecycle_state_parse (const gchar *value,
    WylPolicyTenantLifecycleState *out_state)
{
  static const struct
  {
    const gchar *name;
    WylPolicyTenantLifecycleState state;
  } values[] = {
    {"legacy_unclassified", WYL_POLICY_TENANT_LIFECYCLE_LEGACY_UNCLASSIFIED},
    {"active", WYL_POLICY_TENANT_LIFECYCLE_ACTIVE},
    {"sealing", WYL_POLICY_TENANT_LIFECYCLE_SEALING},
    {"sealed", WYL_POLICY_TENANT_LIFECYCLE_SEALED},
    {"unsealing", WYL_POLICY_TENANT_LIFECYCLE_UNSEALING},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (values); i++) {
    if (g_strcmp0 (value, values[i].name) == 0) {
      *out_state = values[i].state;
      return TRUE;
    }
  }
  return FALSE;
}

static const gchar *
tenant_lifecycle_state_name (WylPolicyTenantLifecycleState state)
{
  switch (state) {
    case WYL_POLICY_TENANT_LIFECYCLE_LEGACY_UNCLASSIFIED:
      return "legacy_unclassified";
    case WYL_POLICY_TENANT_LIFECYCLE_ACTIVE:
      return "active";
    case WYL_POLICY_TENANT_LIFECYCLE_SEALING:
      return "sealing";
    case WYL_POLICY_TENANT_LIFECYCLE_SEALED:
      return "sealed";
    case WYL_POLICY_TENANT_LIFECYCLE_UNSEALING:
      return "unsealing";
  }
  return NULL;
}

static gboolean
graph_lifecycle_state_parse (const gchar *value,
    WylPolicyGraphLifecycleState *out_state)
{
  static const struct
  {
    const gchar *name;
    WylPolicyGraphLifecycleState state;
  } values[] = {
    {"legacy_unclassified", WYL_POLICY_GRAPH_LIFECYCLE_LEGACY_UNCLASSIFIED},
    {"provisioning", WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING},
    {"active", WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE},
    {"sealed", WYL_POLICY_GRAPH_LIFECYCLE_SEALED},
    {"degraded", WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (values); i++) {
    if (g_strcmp0 (value, values[i].name) == 0) {
      *out_state = values[i].state;
      return TRUE;
    }
  }
  return FALSE;
}

static const gchar *
graph_lifecycle_state_name (WylPolicyGraphLifecycleState state)
{
  switch (state) {
    case WYL_POLICY_GRAPH_LIFECYCLE_LEGACY_UNCLASSIFIED:
      return "legacy_unclassified";
    case WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING:
      return "provisioning";
    case WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE:
      return "active";
    case WYL_POLICY_GRAPH_LIFECYCLE_SEALED:
      return "sealed";
    case WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED:
      return "degraded";
  }
  return NULL;
}

static gboolean
graph_error_class_parse (const gchar *value,
    WylPolicyGraphErrorClass *out_error_class)
{
  static const struct
  {
    const gchar *name;
    WylPolicyGraphErrorClass error_class;
  } values[] = {
    {"none", WYL_POLICY_GRAPH_ERROR_NONE},
    {"path", WYL_POLICY_GRAPH_ERROR_PATH},
    {"identity", WYL_POLICY_GRAPH_ERROR_IDENTITY},
    {"format", WYL_POLICY_GRAPH_ERROR_FORMAT},
    {"schema", WYL_POLICY_GRAPH_ERROR_SCHEMA},
    {"open", WYL_POLICY_GRAPH_ERROR_OPEN},
    {"replay", WYL_POLICY_GRAPH_ERROR_REPLAY},
    {"recovery", WYL_POLICY_GRAPH_ERROR_RECOVERY},
    {"internal", WYL_POLICY_GRAPH_ERROR_INTERNAL},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (values); i++) {
    if (g_strcmp0 (value, values[i].name) == 0) {
      *out_error_class = values[i].error_class;
      return TRUE;
    }
  }
  return FALSE;
}

static const gchar *
graph_error_class_name (WylPolicyGraphErrorClass error_class)
{
  switch (error_class) {
    case WYL_POLICY_GRAPH_ERROR_NONE:
      return "none";
    case WYL_POLICY_GRAPH_ERROR_PATH:
      return "path";
    case WYL_POLICY_GRAPH_ERROR_IDENTITY:
      return "identity";
    case WYL_POLICY_GRAPH_ERROR_FORMAT:
      return "format";
    case WYL_POLICY_GRAPH_ERROR_SCHEMA:
      return "schema";
    case WYL_POLICY_GRAPH_ERROR_OPEN:
      return "open";
    case WYL_POLICY_GRAPH_ERROR_REPLAY:
      return "replay";
    case WYL_POLICY_GRAPH_ERROR_RECOVERY:
      return "recovery";
    case WYL_POLICY_GRAPH_ERROR_INTERNAL:
      return "internal";
  }
  return NULL;
}

static gboolean
graph_store_uuid_is_canonical (const gchar *value)
{
  if (value == NULL || strlen (value) != 36 || value[8] != '-'
      || value[13] != '-' || value[18] != '-' || value[23] != '-')
    return FALSE;
  for (gsize i = 0; i < 36; i++) {
    if (i == 8 || i == 13 || i == 18 || i == 23)
      continue;
    if (!g_ascii_isdigit (value[i])
        && !(value[i] >= 'a' && value[i] <= 'f'))
      return FALSE;
  }
  return TRUE;
}

void
wyl_policy_tenant_authority_record_free (WylPolicyTenantAuthorityRecord *record)
{
  if (record == NULL)
    return;
  g_free (record->tenant_id);
  g_free (record);
}

void
wyl_policy_graph_authority_record_free (WylPolicyGraphAuthorityRecord *record)
{
  if (record == NULL)
    return;
  g_free (record->tenant_id);
  g_free (record->graph_id);
  g_free (record->store_uuid);
  g_free (record);
}

static wyrelog_error_t
tenant_authority_record_from_row (sqlite3_stmt *stmt,
    WylPolicyTenantAuthorityRecord **out_record)
{
  *out_record = NULL;
  if (sqlite3_column_type (stmt, 0) != SQLITE_TEXT
      || sqlite3_column_type (stmt, 1) != SQLITE_INTEGER
      || sqlite3_column_type (stmt, 2) != SQLITE_TEXT
      || sqlite3_column_type (stmt, 3) != SQLITE_INTEGER
      || sqlite3_column_type (stmt, 4) != SQLITE_INTEGER)
    return WYRELOG_E_POLICY;
  gint64 lifecycle_generation = sqlite3_column_int64 (stmt, 3);
  gint64 reconciliation_generation = sqlite3_column_int64 (stmt, 4);
  gint sealed = sqlite3_column_int (stmt, 1);
  const gchar *tenant_id = (const gchar *) sqlite3_column_text (stmt, 0);
  const gchar *state_name = (const gchar *) sqlite3_column_text (stmt, 2);
  WylPolicyTenantLifecycleState state;
  if (!wyl_policy_store_tenant_id_is_valid (tenant_id)
      || lifecycle_generation < 0 || reconciliation_generation < 0
      || (sealed != 0 && sealed != 1)
      || !tenant_lifecycle_state_parse (state_name, &state)
      || (state != WYL_POLICY_TENANT_LIFECYCLE_LEGACY_UNCLASSIFIED
          && ((state == WYL_POLICY_TENANT_LIFECYCLE_ACTIVE
                  || state == WYL_POLICY_TENANT_LIFECYCLE_SEALING)
              != (sealed == 0))))
    return WYRELOG_E_POLICY;
  WylPolicyTenantAuthorityRecord *record =
      g_new0 (WylPolicyTenantAuthorityRecord, 1);
  record->tenant_id = g_strdup (tenant_id);
  record->lifecycle_state = state;
  record->lifecycle_generation = (guint64) lifecycle_generation;
  record->reconciliation_generation = (guint64) reconciliation_generation;
  record->sealed_compatibility = sealed != 0;
  *out_record = record;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
graph_authority_record_from_row (sqlite3_stmt *stmt,
    WylPolicyGraphAuthorityRecord **out_record)
{
  *out_record = NULL;
  const int required_types[] = {
    SQLITE_TEXT, SQLITE_TEXT, SQLITE_INTEGER, SQLITE_TEXT,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (required_types); i++) {
    if (sqlite3_column_type (stmt, (int) i) != required_types[i])
      return WYRELOG_E_POLICY;
  }
  if (sqlite3_column_type (stmt, 7) != SQLITE_INTEGER
      || sqlite3_column_type (stmt, 8) != SQLITE_INTEGER
      || sqlite3_column_type (stmt, 9) != SQLITE_TEXT)
    return WYRELOG_E_POLICY;
  gboolean has_identity = sqlite3_column_type (stmt, 4) != SQLITE_NULL;
  if (has_identity != (sqlite3_column_type (stmt, 5) != SQLITE_NULL)
      || has_identity != (sqlite3_column_type (stmt, 6) != SQLITE_NULL))
    return WYRELOG_E_POLICY;
  if (has_identity
      && (sqlite3_column_type (stmt, 4) != SQLITE_TEXT
          || sqlite3_column_type (stmt, 5) != SQLITE_INTEGER
          || sqlite3_column_type (stmt, 6) != SQLITE_INTEGER))
    return WYRELOG_E_POLICY;

  const gchar *tenant_id = (const gchar *) sqlite3_column_text (stmt, 0);
  const gchar *graph_id = (const gchar *) sqlite3_column_text (stmt, 1);
  gint sealed = sqlite3_column_int (stmt, 2);
  const gchar *state_name = (const gchar *) sqlite3_column_text (stmt, 3);
  const gchar *store_uuid = has_identity ?
      (const gchar *) sqlite3_column_text (stmt, 4) : NULL;
  const gchar *error_name = (const gchar *) sqlite3_column_text (stmt, 9);
  gint64 format_version = has_identity ? sqlite3_column_int64 (stmt, 5) : 0;
  gint64 path_encoding_version =
      has_identity ? sqlite3_column_int64 (stmt, 6) : 0;
  gint64 lifecycle_generation = sqlite3_column_int64 (stmt, 7);
  gint64 reconciliation_generation = sqlite3_column_int64 (stmt, 8);
  WylPolicyGraphLifecycleState state;
  WylPolicyGraphErrorClass error_class;
  if (!wyl_policy_store_tenant_id_is_valid (tenant_id)
      || !fact_graph_customer_name_is_valid (graph_id)
      || (sealed != 0 && sealed != 1) || format_version < 0
      || path_encoding_version < 0 || lifecycle_generation < 0
      || reconciliation_generation < 0
      || !graph_lifecycle_state_parse (state_name, &state)
      || !graph_error_class_parse (error_name, &error_class)
      || (has_identity
          != (state != WYL_POLICY_GRAPH_LIFECYCLE_LEGACY_UNCLASSIFIED))
      || (has_identity && !graph_store_uuid_is_canonical (store_uuid))
      || (has_identity && (format_version == 0 || path_encoding_version == 0))
      || (state == WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED
          ? error_class == WYL_POLICY_GRAPH_ERROR_NONE
          : error_class != WYL_POLICY_GRAPH_ERROR_NONE)
      || (state != WYL_POLICY_GRAPH_LIFECYCLE_LEGACY_UNCLASSIFIED
          && ((state == WYL_POLICY_GRAPH_LIFECYCLE_SEALED) != (sealed != 0))))
    return WYRELOG_E_POLICY;

  WylPolicyGraphAuthorityRecord *record =
      g_new0 (WylPolicyGraphAuthorityRecord, 1);
  record->tenant_id = g_strdup (tenant_id);
  record->graph_id = g_strdup (graph_id);
  record->lifecycle_state = state;
  record->store_uuid = has_identity ? g_strdup (store_uuid) : NULL;
  record->format_version = (guint64) format_version;
  record->path_encoding_version = (guint64) path_encoding_version;
  record->lifecycle_generation = (guint64) lifecycle_generation;
  record->reconciliation_generation = (guint64) reconciliation_generation;
  record->last_error_class = error_class;
  record->has_store_identity = has_identity;
  record->sealed_compatibility = sealed != 0;
  *out_record = record;
  return WYRELOG_E_OK;
}

#define TENANT_AUTHORITY_SELECT_COLUMNS                                      \
  "tenant_id,sealed,lifecycle_state,lifecycle_generation,"                  \
  "reconciliation_generation"
#define GRAPH_AUTHORITY_SELECT_COLUMNS                                       \
  "tenant_id,graph_id,sealed,lifecycle_state,store_uuid,format_version,"    \
  "path_encoding_version,lifecycle_generation,reconciliation_generation,"  \
  "last_error_class"

wyrelog_error_t
wyl_policy_store_read_tenant_authority (wyl_policy_store_t *store,
    const gchar *tenant_id, WylPolicyTenantAuthorityRecord **out_record)
{
  if (out_record != NULL)
    *out_record = NULL;
  if (store == NULL || store->db == NULL || out_record == NULL
      || !wyl_policy_store_tenant_id_is_valid (tenant_id))
    return WYRELOG_E_INVALID;
  g_rec_mutex_lock (&store->graph_authority_mutex);
  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = prepare_stmt (store->db,
      "SELECT " TENANT_AUTHORITY_SELECT_COLUMNS
      " FROM tenants WHERE tenant_id=?;", &stmt);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 1, tenant_id);
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_ERROR;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW)
    rc = tenant_authority_record_from_row (stmt, out_record);
  else if (rc == WYRELOG_E_OK)
    rc = step == SQLITE_DONE ? WYRELOG_E_NOT_FOUND : WYRELOG_E_IO;
  sqlite3_finalize (stmt);
  g_rec_mutex_unlock (&store->graph_authority_mutex);
  return rc;
}

wyrelog_error_t
wyl_policy_store_list_tenant_authorities (wyl_policy_store_t *store,
    GPtrArray **out_records)
{
  if (out_records != NULL)
    *out_records = NULL;
  if (store == NULL || store->db == NULL || out_records == NULL)
    return WYRELOG_E_INVALID;
  g_rec_mutex_lock (&store->graph_authority_mutex);
  GPtrArray *records = g_ptr_array_new_with_free_func (
      (GDestroyNotify) wyl_policy_tenant_authority_record_free);
  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = prepare_stmt (store->db,
      "SELECT " TENANT_AUTHORITY_SELECT_COLUMNS
      " FROM tenants ORDER BY tenant_id;", &stmt);
  int step = SQLITE_ERROR;
  while (rc == WYRELOG_E_OK && (step = sqlite3_step (stmt)) == SQLITE_ROW) {
    WylPolicyTenantAuthorityRecord *record = NULL;
    rc = tenant_authority_record_from_row (stmt, &record);
    if (rc == WYRELOG_E_OK)
      g_ptr_array_add (records, record);
  }
  if (rc == WYRELOG_E_OK && step != SQLITE_DONE)
    rc = WYRELOG_E_IO;
  sqlite3_finalize (stmt);
  if (rc != WYRELOG_E_OK) {
    g_ptr_array_unref (records);
    g_rec_mutex_unlock (&store->graph_authority_mutex);
    return rc;
  }
  *out_records = records;
  g_rec_mutex_unlock (&store->graph_authority_mutex);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_read_graph_authority (wyl_policy_store_t *store,
    const gchar *tenant_id, const gchar *graph_id,
    WylPolicyGraphAuthorityRecord **out_record)
{
  if (out_record != NULL)
    *out_record = NULL;
  if (store == NULL || store->db == NULL || out_record == NULL
      || !wyl_policy_store_tenant_id_is_valid (tenant_id)
      || !fact_graph_customer_name_is_valid (graph_id))
    return WYRELOG_E_INVALID;
  g_rec_mutex_lock (&store->graph_authority_mutex);
  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = prepare_stmt (store->db,
      "SELECT " GRAPH_AUTHORITY_SELECT_COLUMNS
      " FROM fact_graphs WHERE tenant_id=? AND graph_id=?;", &stmt);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 1, tenant_id);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 2, graph_id);
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_ERROR;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW)
    rc = graph_authority_record_from_row (stmt, out_record);
  else if (rc == WYRELOG_E_OK)
    rc = step == SQLITE_DONE ? WYRELOG_E_NOT_FOUND : WYRELOG_E_IO;
  sqlite3_finalize (stmt);
  g_rec_mutex_unlock (&store->graph_authority_mutex);
  return rc;
}

wyrelog_error_t
wyl_policy_store_list_graph_authorities (wyl_policy_store_t *store,
    const gchar *tenant_id, GPtrArray **out_records)
{
  if (out_records != NULL)
    *out_records = NULL;
  if (store == NULL || store->db == NULL || out_records == NULL
      || (tenant_id != NULL
          && !wyl_policy_store_tenant_id_is_valid (tenant_id)))
    return WYRELOG_E_INVALID;
  g_rec_mutex_lock (&store->graph_authority_mutex);
  GPtrArray *records = g_ptr_array_new_with_free_func (
      (GDestroyNotify) wyl_policy_graph_authority_record_free);
  sqlite3_stmt *stmt = NULL;
  const gchar *sql = tenant_id == NULL ?
      "SELECT " GRAPH_AUTHORITY_SELECT_COLUMNS
      " FROM fact_graphs ORDER BY tenant_id,graph_id;" :
      "SELECT " GRAPH_AUTHORITY_SELECT_COLUMNS
      " FROM fact_graphs WHERE tenant_id=? ORDER BY graph_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK && tenant_id != NULL)
    rc = bind_text (stmt, 1, tenant_id);
  int step = SQLITE_ERROR;
  while (rc == WYRELOG_E_OK && (step = sqlite3_step (stmt)) == SQLITE_ROW) {
    WylPolicyGraphAuthorityRecord *record = NULL;
    rc = graph_authority_record_from_row (stmt, &record);
    if (rc == WYRELOG_E_OK)
      g_ptr_array_add (records, record);
  }
  if (rc == WYRELOG_E_OK && step != SQLITE_DONE)
    rc = WYRELOG_E_IO;
  sqlite3_finalize (stmt);
  if (rc != WYRELOG_E_OK) {
    g_ptr_array_unref (records);
    g_rec_mutex_unlock (&store->graph_authority_mutex);
    return rc;
  }
  *out_records = records;
  g_rec_mutex_unlock (&store->graph_authority_mutex);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
classify_graph_authority_mutation (wyl_policy_store_t *store,
    const gchar *tenant_id, const gchar *graph_id,
    WylPolicyGraphLifecycleState expected_state,
    guint64 expected_lifecycle_generation,
    guint64 expected_reconciliation_generation,
    WylPolicyGraphLifecycleState replay_state,
    WylPolicyGraphErrorClass replay_error_class,
    guint lifecycle_increment, guint reconciliation_increment,
    gboolean replay_allowed,
    const gchar *replay_store_uuid, guint64 replay_format_version,
    guint64 replay_path_encoding_version,
    WylPolicyAuthorityMutationResult *out_result)
{
  WylPolicyGraphAuthorityRecord *record = NULL;
  wyrelog_error_t rc = wyl_policy_store_read_graph_authority (store,
      tenant_id, graph_id, &record);
  if (rc == WYRELOG_E_NOT_FOUND) {
    *out_result = WYL_POLICY_AUTHORITY_MUTATION_NOT_FOUND;
    return WYRELOG_E_OK;
  }
  if (rc != WYRELOG_E_OK)
    return rc;
  gboolean generation_can_advance =
      expected_lifecycle_generation <=
      (guint64) G_MAXINT64 - lifecycle_increment
      && expected_reconciliation_generation <=
      (guint64) G_MAXINT64 - reconciliation_increment;
  gboolean replay = replay_allowed && generation_can_advance
      && record->lifecycle_state == replay_state
      && record->last_error_class == replay_error_class
      && record->lifecycle_generation ==
      expected_lifecycle_generation + lifecycle_increment
      && record->reconciliation_generation ==
      expected_reconciliation_generation + reconciliation_increment;
  if (replay_store_uuid != NULL)
    replay = replay && record->has_store_identity
        && g_strcmp0 (record->store_uuid, replay_store_uuid) == 0
        && record->format_version == replay_format_version
        && record->path_encoding_version == replay_path_encoding_version;
  if (replay)
    *out_result = WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY;
  else if (record->lifecycle_state != expected_state
      || record->lifecycle_generation != expected_lifecycle_generation
      || record->reconciliation_generation !=
      expected_reconciliation_generation)
    *out_result = WYL_POLICY_AUTHORITY_MUTATION_STALE;
  else
    *out_result = WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  wyl_policy_graph_authority_record_free (record);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
classify_tenant_authority_mutation (wyl_policy_store_t *store,
    const gchar *tenant_id, WylPolicyTenantLifecycleState expected_state,
    guint64 expected_lifecycle_generation,
    guint64 expected_reconciliation_generation,
    WylPolicyTenantLifecycleState replay_state, guint lifecycle_increment,
    guint reconciliation_increment, gboolean replay_allowed,
    WylPolicyAuthorityMutationResult *out_result)
{
  WylPolicyTenantAuthorityRecord *record = NULL;
  wyrelog_error_t rc = wyl_policy_store_read_tenant_authority (store,
      tenant_id, &record);
  if (rc == WYRELOG_E_NOT_FOUND) {
    *out_result = WYL_POLICY_AUTHORITY_MUTATION_NOT_FOUND;
    return WYRELOG_E_OK;
  }
  if (rc != WYRELOG_E_OK)
    return rc;
  gboolean generation_can_advance =
      expected_lifecycle_generation <=
      (guint64) G_MAXINT64 - lifecycle_increment
      && expected_reconciliation_generation <=
      (guint64) G_MAXINT64 - reconciliation_increment;
  if (replay_allowed && generation_can_advance
      && record->lifecycle_state == replay_state
      && record->lifecycle_generation ==
      expected_lifecycle_generation + lifecycle_increment
      && record->reconciliation_generation ==
      expected_reconciliation_generation + reconciliation_increment)
    *out_result = WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY;
  else if (record->lifecycle_state != expected_state
      || record->lifecycle_generation != expected_lifecycle_generation
      || record->reconciliation_generation !=
      expected_reconciliation_generation)
    *out_result = WYL_POLICY_AUTHORITY_MUTATION_STALE;
  else
    *out_result = WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  wyl_policy_tenant_authority_record_free (record);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
graph_authority_sqlite_error (int sqlite_rc)
{
  int primary = sqlite_rc & 0xff;
  if (primary == SQLITE_BUSY || primary == SQLITE_LOCKED)
    return WYRELOG_E_BUSY;
  return WYRELOG_E_IO;
}

typedef struct
{
  gboolean owns_transaction;
  gboolean active;
  gboolean locked;
} GraphAuthorityMutationFrame;

static wyrelog_error_t
graph_authority_mutation_checkpoint (wyl_policy_store_t *store,
    WylPolicyGraphAuthorityMutationFailStage stage)
{
  if (store->mutation_fail_once != stage)
    return WYRELOG_E_OK;
  store->mutation_fail_once = WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_NONE;
  return WYRELOG_E_IO;
}

static wyrelog_error_t
graph_authority_mutation_begin (wyl_policy_store_t *store,
    GraphAuthorityMutationFrame *frame)
{
  *frame = (GraphAuthorityMutationFrame) {
  0};
  g_rec_mutex_lock (&store->graph_authority_mutex);
  frame->locked = TRUE;
  frame->owns_transaction = sqlite3_get_autocommit (store->db) != 0;
  const gchar *sql = frame->owns_transaction ? "BEGIN IMMEDIATE;" :
      "SAVEPOINT wyrelog_graph_authority_mutation;";
  int sqlite_rc = sqlite3_exec (store->db, sql, NULL, NULL, NULL);
  if (sqlite_rc != SQLITE_OK) {
    g_rec_mutex_unlock (&store->graph_authority_mutex);
    frame->locked = FALSE;
    return graph_authority_sqlite_error (sqlite_rc);
  }
  frame->active = TRUE;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
graph_authority_mutation_finish (wyl_policy_store_t *store,
    GraphAuthorityMutationFrame *frame, gboolean rollback)
{
  if (!frame->active)
    return WYRELOG_E_OK;
  if (rollback) {
    const gchar *sql = frame->owns_transaction ? "ROLLBACK;" :
        "ROLLBACK TO SAVEPOINT wyrelog_graph_authority_mutation;"
        "RELEASE SAVEPOINT wyrelog_graph_authority_mutation;";
    int sqlite_rc = sqlite3_exec (store->db, sql, NULL, NULL, NULL);
    frame->active = FALSE;
    g_rec_mutex_unlock (&store->graph_authority_mutex);
    frame->locked = FALSE;
    return sqlite_rc == SQLITE_OK ? WYRELOG_E_OK :
        graph_authority_sqlite_error (sqlite_rc);
  }
  const gchar *sql = frame->owns_transaction ? "COMMIT;" :
      "RELEASE SAVEPOINT wyrelog_graph_authority_mutation;";
  int sqlite_rc = sqlite3_exec (store->db, sql, NULL, NULL, NULL);
  if (sqlite_rc == SQLITE_OK) {
    frame->active = FALSE;
    g_rec_mutex_unlock (&store->graph_authority_mutex);
    frame->locked = FALSE;
    return WYRELOG_E_OK;
  }
  wyrelog_error_t commit_rc = graph_authority_sqlite_error (sqlite_rc);
  wyrelog_error_t cleanup_rc = graph_authority_mutation_finish (store, frame,
      TRUE);
  return cleanup_rc != WYRELOG_E_OK ? cleanup_rc : commit_rc;
}

static wyrelog_error_t
graph_authority_mutation_complete (wyl_policy_store_t *store,
    GraphAuthorityMutationFrame *frame, wyrelog_error_t body_rc)
{
  wyrelog_error_t finish_rc = graph_authority_mutation_finish (store, frame,
      body_rc != WYRELOG_E_OK);
  return finish_rc != WYRELOG_E_OK ? finish_rc : body_rc;
}

static wyrelog_error_t
authority_update_step (wyl_policy_store_t *store, sqlite3_stmt *stmt,
    gboolean allow_unique_constraint, gboolean *out_applied)
{
  int step = sqlite3_step (stmt);
  *out_applied = step == SQLITE_DONE && sqlite3_changes (store->db) == 1;
  if (step == SQLITE_DONE)
    return WYRELOG_E_OK;
  int extended = sqlite3_extended_errcode (store->db);
  if (allow_unique_constraint && extended == SQLITE_CONSTRAINT_UNIQUE)
    return WYRELOG_E_OK;
  if ((extended & 0xff) == SQLITE_CONSTRAINT)
    return WYRELOG_E_POLICY;
  return graph_authority_sqlite_error (extended);
}

wyrelog_error_t
wyl_policy_store_reserve_graph_authority (wyl_policy_store_t *store,
    const gchar *tenant_id, const gchar *graph_id, const gchar *store_uuid,
    guint64 format_version, guint64 path_encoding_version,
    guint64 expected_lifecycle_generation,
    guint64 expected_reconciliation_generation,
    WylPolicyAuthorityMutationResult *out_result)
{
  if (store == NULL || store->db == NULL || out_result == NULL
      || !wyl_policy_store_tenant_id_is_valid (tenant_id)
      || !fact_graph_customer_name_is_valid (graph_id)
      || !graph_store_uuid_is_canonical (store_uuid) || format_version == 0
      || format_version > G_MAXINT64 || path_encoding_version == 0
      || path_encoding_version > G_MAXINT64
      || expected_lifecycle_generation > G_MAXINT64
      || expected_reconciliation_generation > G_MAXINT64)
    return WYRELOG_E_INVALID;
  *out_result = WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  gboolean applied = FALSE;
  GraphAuthorityMutationFrame frame;
  wyrelog_error_t rc = graph_authority_mutation_begin (store, &frame);
  if (rc != WYRELOG_E_OK)
    return rc;
  sqlite3_stmt *stmt = NULL;
  rc = prepare_stmt (store->db,
      "UPDATE fact_graphs SET store_uuid=?,format_version=?,"
      "path_encoding_version=?,lifecycle_state='provisioning',"
      "lifecycle_generation=lifecycle_generation+1,updated_at=unixepoch() "
      "WHERE tenant_id=? AND graph_id=? "
      "AND lifecycle_state='legacy_unclassified' "
      "AND sealed=0 "
      "AND store_uuid IS NULL AND format_version IS NULL "
      "AND path_encoding_version IS NULL AND lifecycle_generation=? "
      "AND lifecycle_generation<9223372036854775807 "
      "AND reconciliation_generation=?;", &stmt);
  if (rc == WYRELOG_E_OK
      && (bind_text (stmt, 1, store_uuid) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 2,
              (sqlite3_int64) format_version) != SQLITE_OK
          || sqlite3_bind_int64 (stmt, 3,
              (sqlite3_int64) path_encoding_version) != SQLITE_OK
          || bind_text (stmt, 4, tenant_id) != WYRELOG_E_OK
          || bind_text (stmt, 5, graph_id) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 6,
              (sqlite3_int64) expected_lifecycle_generation) != SQLITE_OK
          || sqlite3_bind_int64 (stmt, 7,
              (sqlite3_int64) expected_reconciliation_generation) != SQLITE_OK))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = authority_update_step (store, stmt, TRUE, &applied);
  sqlite3_finalize (stmt);
  if (rc == WYRELOG_E_OK)
    rc = graph_authority_mutation_checkpoint (store,
        WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_AFTER_UPDATE);
  if (rc != WYRELOG_E_OK)
    return graph_authority_mutation_complete (store, &frame, rc);
  if (applied) {
    *out_result = WYL_POLICY_AUTHORITY_MUTATION_APPLIED;
  } else {
    rc = classify_graph_authority_mutation (store, tenant_id, graph_id,
        WYL_POLICY_GRAPH_LIFECYCLE_LEGACY_UNCLASSIFIED,
        expected_lifecycle_generation, expected_reconciliation_generation,
        WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING, WYL_POLICY_GRAPH_ERROR_NONE,
        1, 0, expected_lifecycle_generation < G_MAXINT64, store_uuid,
        format_version, path_encoding_version, out_result);
  }
  if (rc == WYRELOG_E_OK)
    rc = graph_authority_mutation_checkpoint (store,
        WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_BEFORE_FINISH);
  return graph_authority_mutation_complete (store, &frame, rc);
}

static gboolean
graph_normal_transition_is_legal (WylPolicyGraphLifecycleState from,
    WylPolicyGraphLifecycleState to)
{
  return (from == WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING
      && (to == WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE
          || to == WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED))
      || (from == WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE
      && (to == WYL_POLICY_GRAPH_LIFECYCLE_SEALED
          || to == WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED))
      || (from == WYL_POLICY_GRAPH_LIFECYCLE_SEALED
      && (to == WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE
          || to == WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED));
}

wyrelog_error_t
wyl_policy_store_transition_graph_authority (wyl_policy_store_t *store,
    const gchar *tenant_id, const gchar *graph_id,
    WylPolicyGraphLifecycleState expected_state,
    WylPolicyGraphLifecycleState target_state,
    WylPolicyGraphErrorClass target_error_class,
    guint64 expected_lifecycle_generation,
    guint64 expected_reconciliation_generation,
    WylPolicyAuthorityMutationResult *out_result)
{
  const gchar *expected_name = graph_lifecycle_state_name (expected_state);
  const gchar *target_name = graph_lifecycle_state_name (target_state);
  const gchar *error_name = graph_error_class_name (target_error_class);
  if (store == NULL || store->db == NULL || out_result == NULL
      || !wyl_policy_store_tenant_id_is_valid (tenant_id)
      || !fact_graph_customer_name_is_valid (graph_id)
      || expected_name == NULL || target_name == NULL || error_name == NULL
      || expected_lifecycle_generation > G_MAXINT64
      || expected_reconciliation_generation > G_MAXINT64)
    return WYRELOG_E_INVALID;
  *out_result = WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  gboolean error_matches = target_state == WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED
      ? target_error_class != WYL_POLICY_GRAPH_ERROR_NONE
      : target_error_class == WYL_POLICY_GRAPH_ERROR_NONE;
  gboolean legal = graph_normal_transition_is_legal (expected_state,
      target_state) && error_matches;
  if (!legal)
    return WYRELOG_E_OK;
  gboolean applied = FALSE;
  GraphAuthorityMutationFrame frame;
  wyrelog_error_t rc = graph_authority_mutation_begin (store, &frame);
  if (rc != WYRELOG_E_OK)
    return rc;
  sqlite3_stmt *stmt = NULL;
  rc = prepare_stmt (store->db,
      "UPDATE fact_graphs SET lifecycle_state=?,last_error_class=?,sealed=?,"
      "lifecycle_generation=lifecycle_generation+1,updated_at=unixepoch() "
      "WHERE tenant_id=? AND graph_id=? AND lifecycle_state=? "
      "AND lifecycle_generation=? "
      "AND lifecycle_generation<9223372036854775807 "
      "AND reconciliation_generation=?;", &stmt);
  if (rc == WYRELOG_E_OK
      && (bind_text (stmt, 1, target_name) != WYRELOG_E_OK
          || bind_text (stmt, 2, error_name) != WYRELOG_E_OK
          || sqlite3_bind_int (stmt, 3,
              target_state == WYL_POLICY_GRAPH_LIFECYCLE_SEALED) != SQLITE_OK
          || bind_text (stmt, 4, tenant_id) != WYRELOG_E_OK
          || bind_text (stmt, 5, graph_id) != WYRELOG_E_OK
          || bind_text (stmt, 6, expected_name) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 7,
              (sqlite3_int64) expected_lifecycle_generation) != SQLITE_OK
          || sqlite3_bind_int64 (stmt, 8,
              (sqlite3_int64) expected_reconciliation_generation) != SQLITE_OK))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = authority_update_step (store, stmt, FALSE, &applied);
  sqlite3_finalize (stmt);
  if (rc == WYRELOG_E_OK)
    rc = graph_authority_mutation_checkpoint (store,
        WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_AFTER_UPDATE);
  if (rc != WYRELOG_E_OK)
    return graph_authority_mutation_complete (store, &frame, rc);
  if (applied) {
    *out_result = WYL_POLICY_AUTHORITY_MUTATION_APPLIED;
  } else {
    rc = classify_graph_authority_mutation (store, tenant_id, graph_id,
        expected_state, expected_lifecycle_generation,
        expected_reconciliation_generation, target_state, target_error_class,
        1, 0, expected_lifecycle_generation < G_MAXINT64, NULL, 0, 0,
        out_result);
  }
  if (rc == WYRELOG_E_OK)
    rc = graph_authority_mutation_checkpoint (store,
        WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_BEFORE_FINISH);
  return graph_authority_mutation_complete (store, &frame, rc);
}

wyrelog_error_t
wyl_policy_store_reconcile_graph_authority (wyl_policy_store_t *store,
    const gchar *tenant_id, const gchar *graph_id,
    guint64 expected_lifecycle_generation,
    guint64 expected_reconciliation_generation,
    WylPolicyAuthorityMutationResult *out_result)
{
  if (store == NULL || store->db == NULL || out_result == NULL
      || !wyl_policy_store_tenant_id_is_valid (tenant_id)
      || !fact_graph_customer_name_is_valid (graph_id)
      || expected_lifecycle_generation > G_MAXINT64
      || expected_reconciliation_generation > G_MAXINT64)
    return WYRELOG_E_INVALID;
  *out_result = WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  gboolean applied = FALSE;
  GraphAuthorityMutationFrame frame;
  wyrelog_error_t rc = graph_authority_mutation_begin (store, &frame);
  if (rc != WYRELOG_E_OK)
    return rc;
  sqlite3_stmt *stmt = NULL;
  rc = prepare_stmt (store->db,
      "UPDATE fact_graphs SET lifecycle_state='active',"
      "last_error_class='none',sealed=0,"
      "lifecycle_generation=lifecycle_generation+1,"
      "reconciliation_generation=reconciliation_generation+1,"
      "updated_at=unixepoch() WHERE tenant_id=? AND graph_id=? "
      "AND lifecycle_state='degraded' AND lifecycle_generation=? "
      "AND lifecycle_generation<9223372036854775807 "
      "AND reconciliation_generation=? "
      "AND reconciliation_generation<9223372036854775807;", &stmt);
  if (rc == WYRELOG_E_OK
      && (bind_text (stmt, 1, tenant_id) != WYRELOG_E_OK
          || bind_text (stmt, 2, graph_id) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 3,
              (sqlite3_int64) expected_lifecycle_generation) != SQLITE_OK
          || sqlite3_bind_int64 (stmt, 4,
              (sqlite3_int64) expected_reconciliation_generation) != SQLITE_OK))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = authority_update_step (store, stmt, FALSE, &applied);
  sqlite3_finalize (stmt);
  if (rc == WYRELOG_E_OK)
    rc = graph_authority_mutation_checkpoint (store,
        WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_AFTER_UPDATE);
  if (rc != WYRELOG_E_OK)
    return graph_authority_mutation_complete (store, &frame, rc);
  if (applied) {
    *out_result = WYL_POLICY_AUTHORITY_MUTATION_APPLIED;
  } else {
    rc = classify_graph_authority_mutation (store, tenant_id, graph_id,
        WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED,
        expected_lifecycle_generation, expected_reconciliation_generation,
        WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE, WYL_POLICY_GRAPH_ERROR_NONE, 1, 1,
        expected_lifecycle_generation < G_MAXINT64
        && expected_reconciliation_generation < G_MAXINT64,
        NULL, 0, 0, out_result);
  }
  if (rc == WYRELOG_E_OK)
    rc = graph_authority_mutation_checkpoint (store,
        WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_BEFORE_FINISH);
  return graph_authority_mutation_complete (store, &frame, rc);
}

static gboolean
tenant_normal_transition_is_legal (WylPolicyTenantLifecycleState from,
    WylPolicyTenantLifecycleState to)
{
  return (from == WYL_POLICY_TENANT_LIFECYCLE_ACTIVE
      && to == WYL_POLICY_TENANT_LIFECYCLE_SEALING)
      || (from == WYL_POLICY_TENANT_LIFECYCLE_SEALING
      && (to == WYL_POLICY_TENANT_LIFECYCLE_ACTIVE
          || to == WYL_POLICY_TENANT_LIFECYCLE_SEALED))
      || (from == WYL_POLICY_TENANT_LIFECYCLE_SEALED
      && to == WYL_POLICY_TENANT_LIFECYCLE_UNSEALING)
      || (from == WYL_POLICY_TENANT_LIFECYCLE_UNSEALING
      && (to == WYL_POLICY_TENANT_LIFECYCLE_ACTIVE
          || to == WYL_POLICY_TENANT_LIFECYCLE_SEALED));
}

wyrelog_error_t
wyl_policy_store_transition_tenant_authority (wyl_policy_store_t *store,
    const gchar *tenant_id, WylPolicyTenantLifecycleState expected_state,
    WylPolicyTenantLifecycleState target_state,
    guint64 expected_lifecycle_generation,
    guint64 expected_reconciliation_generation,
    WylPolicyAuthorityMutationResult *out_result)
{
  const gchar *expected_name = tenant_lifecycle_state_name (expected_state);
  const gchar *target_name = tenant_lifecycle_state_name (target_state);
  if (store == NULL || store->db == NULL || out_result == NULL
      || !wyl_policy_store_tenant_id_is_valid (tenant_id)
      || expected_name == NULL || target_name == NULL
      || expected_lifecycle_generation > G_MAXINT64
      || expected_reconciliation_generation > G_MAXINT64)
    return WYRELOG_E_INVALID;
  *out_result = WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  gboolean legal = tenant_normal_transition_is_legal (expected_state,
      target_state);
  if (!legal)
    return WYRELOG_E_OK;
  gboolean applied = FALSE;
  GraphAuthorityMutationFrame frame;
  wyrelog_error_t rc = graph_authority_mutation_begin (store, &frame);
  if (rc != WYRELOG_E_OK)
    return rc;
  sqlite3_stmt *stmt = NULL;
  gboolean sealed = target_state == WYL_POLICY_TENANT_LIFECYCLE_SEALED
      || target_state == WYL_POLICY_TENANT_LIFECYCLE_UNSEALING;
  rc = prepare_stmt (store->db,
      "UPDATE tenants SET lifecycle_state=?,sealed=?,"
      "lifecycle_generation=lifecycle_generation+1,updated_at=unixepoch() "
      "WHERE tenant_id=? AND lifecycle_state=? AND lifecycle_generation=? "
      "AND lifecycle_generation<9223372036854775807 "
      "AND reconciliation_generation=?;", &stmt);
  if (rc == WYRELOG_E_OK
      && (bind_text (stmt, 1, target_name) != WYRELOG_E_OK
          || sqlite3_bind_int (stmt, 2, sealed) != SQLITE_OK
          || bind_text (stmt, 3, tenant_id) != WYRELOG_E_OK
          || bind_text (stmt, 4, expected_name) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 5,
              (sqlite3_int64) expected_lifecycle_generation) != SQLITE_OK
          || sqlite3_bind_int64 (stmt, 6,
              (sqlite3_int64) expected_reconciliation_generation) != SQLITE_OK))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = authority_update_step (store, stmt, FALSE, &applied);
  sqlite3_finalize (stmt);
  if (rc == WYRELOG_E_OK)
    rc = graph_authority_mutation_checkpoint (store,
        WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_AFTER_UPDATE);
  if (rc != WYRELOG_E_OK)
    return graph_authority_mutation_complete (store, &frame, rc);
  if (applied) {
    *out_result = WYL_POLICY_AUTHORITY_MUTATION_APPLIED;
  } else {
    rc = classify_tenant_authority_mutation (store, tenant_id, expected_state,
        expected_lifecycle_generation, expected_reconciliation_generation,
        target_state, 1, 0, expected_lifecycle_generation < G_MAXINT64,
        out_result);
  }
  if (rc == WYRELOG_E_OK)
    rc = graph_authority_mutation_checkpoint (store,
        WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_BEFORE_FINISH);
  return graph_authority_mutation_complete (store, &frame, rc);
}

wyrelog_error_t
wyl_policy_store_reconcile_tenant_authority (wyl_policy_store_t *store,
    const gchar *tenant_id, WylPolicyTenantLifecycleState target_state,
    guint64 expected_lifecycle_generation,
    guint64 expected_reconciliation_generation,
    WylPolicyAuthorityMutationResult *out_result)
{
  const gchar *target_name = tenant_lifecycle_state_name (target_state);
  if (store == NULL || store->db == NULL || out_result == NULL
      || !wyl_policy_store_tenant_id_is_valid (tenant_id)
      || target_name == NULL || expected_lifecycle_generation > G_MAXINT64
      || expected_reconciliation_generation > G_MAXINT64)
    return WYRELOG_E_INVALID;
  *out_result = WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  gboolean legal = (target_state == WYL_POLICY_TENANT_LIFECYCLE_ACTIVE
      || target_state == WYL_POLICY_TENANT_LIFECYCLE_SEALED);
  if (!legal)
    return WYRELOG_E_OK;
  gboolean applied = FALSE;
  GraphAuthorityMutationFrame frame;
  wyrelog_error_t rc = graph_authority_mutation_begin (store, &frame);
  if (rc != WYRELOG_E_OK)
    return rc;
  sqlite3_stmt *stmt = NULL;
  rc = prepare_stmt (store->db,
      "UPDATE tenants SET lifecycle_state=?,sealed=?,"
      "lifecycle_generation=lifecycle_generation+1,"
      "reconciliation_generation=reconciliation_generation+1,"
      "updated_at=unixepoch() WHERE tenant_id=? "
      "AND lifecycle_state='legacy_unclassified' "
      "AND lifecycle_generation=? "
      "AND lifecycle_generation<9223372036854775807 "
      "AND reconciliation_generation=? "
      "AND reconciliation_generation<9223372036854775807;", &stmt);
  if (rc == WYRELOG_E_OK
      && (bind_text (stmt, 1, target_name) != WYRELOG_E_OK
          || sqlite3_bind_int (stmt, 2,
              target_state == WYL_POLICY_TENANT_LIFECYCLE_SEALED) != SQLITE_OK
          || bind_text (stmt, 3, tenant_id) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 4,
              (sqlite3_int64) expected_lifecycle_generation) != SQLITE_OK
          || sqlite3_bind_int64 (stmt, 5,
              (sqlite3_int64) expected_reconciliation_generation) != SQLITE_OK))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = authority_update_step (store, stmt, FALSE, &applied);
  sqlite3_finalize (stmt);
  if (rc == WYRELOG_E_OK)
    rc = graph_authority_mutation_checkpoint (store,
        WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_AFTER_UPDATE);
  if (rc != WYRELOG_E_OK)
    return graph_authority_mutation_complete (store, &frame, rc);
  if (applied) {
    *out_result = WYL_POLICY_AUTHORITY_MUTATION_APPLIED;
  } else {
    rc = classify_tenant_authority_mutation (store, tenant_id,
        WYL_POLICY_TENANT_LIFECYCLE_LEGACY_UNCLASSIFIED,
        expected_lifecycle_generation, expected_reconciliation_generation,
        target_state, 1, 1, expected_lifecycle_generation < G_MAXINT64
        && expected_reconciliation_generation < G_MAXINT64, out_result);
  }
  if (rc == WYRELOG_E_OK)
    rc = graph_authority_mutation_checkpoint (store,
        WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_BEFORE_FINISH);
  return graph_authority_mutation_complete (store, &frame, rc);
}

#undef TENANT_AUTHORITY_SELECT_COLUMNS
#undef GRAPH_AUTHORITY_SELECT_COLUMNS

void wyl_policy_fact_relation_schema_columns_free
    (wyl_policy_fact_relation_schema_column_info_t * columns, gsize n_columns)
{
  if (columns == NULL)
    return;
  for (gsize i = 0; i < n_columns; i++) {
    g_free (columns[i].column_name);
    g_free (columns[i].column_type);
  }
  g_free (columns);
}

static wyrelog_error_t
validate_fact_relation_schema_options (wyl_policy_store_t *store,
    const wyl_policy_fact_relation_schema_options_t *opts)
{
  if (store == NULL || store->db == NULL || opts == NULL)
    return WYRELOG_E_INVALID;
  if (!wyl_policy_store_tenant_id_is_valid (opts->tenant_id)
      || !fact_graph_component_is_valid (opts->tenant_id)
      || !fact_graph_customer_name_is_valid (opts->graph_id)
      || !fact_graph_customer_name_is_valid (opts->namespace_id)
      || !fact_graph_customer_name_is_valid (opts->relation_name)
      || opts->schema_version == 0 || opts->columns == NULL
      || opts->n_columns == 0 || opts->n_columns > G_MAXINT)
    return WYRELOG_E_INVALID;
  if (opts->queries == NULL && opts->n_queries > 0)
    return WYRELOG_E_INVALID;

  for (gsize i = 0; i < opts->n_columns; i++) {
    const wyl_policy_fact_relation_schema_column_t *column = &opts->columns[i];
    if (!fact_graph_customer_name_is_valid (column->column_name)
        || !fact_relation_schema_column_type_is_valid (column->column_type))
      return WYRELOG_E_POLICY;
    for (gsize j = 0; j < i; j++) {
      if (g_strcmp0 (opts->columns[j].column_name, column->column_name) == 0)
        return WYRELOG_E_POLICY;
    }
  }

  for (gsize i = 0; i < opts->n_queries; i++) {
    const wyl_policy_fact_relation_schema_query_t *query = &opts->queries[i];
    if (!fact_graph_customer_name_is_valid (query->query_name)
        || query->required_permission_id == NULL
        || query->required_permission_id[0] == '\0' || query->max_rows == 0
        || query->max_rows > WYL_POLICY_FACT_QUERY_MAX_ROWS)
      return WYRELOG_E_POLICY;
    gboolean permission_exists = FALSE;
    wyrelog_error_t rc = wyl_policy_store_permission_exists (store,
        query->required_permission_id, &permission_exists);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (!permission_exists)
      return WYRELOG_E_POLICY;
  }

  return WYRELOG_E_OK;
}

static wyrelog_error_t
insert_fact_namespace_metadata (wyl_policy_store_t *store,
    const wyl_policy_fact_relation_schema_options_t *opts)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "INSERT INTO fact_namespaces "
      "(tenant_id, graph_id, namespace_id, visibility, created_at, updated_at) "
      "VALUES (?, ?, ?, 1, unixepoch(), unixepoch()) "
      "ON CONFLICT (tenant_id, graph_id, namespace_id) DO UPDATE SET "
      "updated_at = excluded.updated_at;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, opts->tenant_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, opts->graph_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, opts->namespace_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }
  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
insert_fact_relation_schema_metadata (wyl_policy_store_t *store,
    const wyl_policy_fact_relation_schema_options_t *opts)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "INSERT INTO fact_relation_schemas "
      "(tenant_id, graph_id, namespace_id, relation_name, schema_version, "
      " arity, relation_visible, created_at, updated_at) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, unixepoch(), unixepoch());";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, opts->tenant_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, opts->graph_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, opts->namespace_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 4, opts->relation_name)) != WYRELOG_E_OK
      || sqlite3_bind_int64 (stmt, 5, opts->schema_version) != SQLITE_OK
      || sqlite3_bind_int64 (stmt, 6, opts->n_columns) != SQLITE_OK
      || sqlite3_bind_int (stmt, 7, opts->relation_visible ? 1 : 0)
      != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
insert_fact_relation_schema_column_metadata (wyl_policy_store_t *store,
    const wyl_policy_fact_relation_schema_options_t *opts, gsize column_index)
{
  sqlite3_stmt *stmt = NULL;
  const wyl_policy_fact_relation_schema_column_t *column =
      &opts->columns[column_index];
  static const gchar *sql =
      "INSERT INTO fact_relation_schema_columns "
      "(tenant_id, graph_id, namespace_id, relation_name, schema_version, "
      " column_index, column_name, column_type, nullable, visible) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, opts->tenant_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, opts->graph_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, opts->namespace_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 4, opts->relation_name)) != WYRELOG_E_OK
      || sqlite3_bind_int64 (stmt, 5, opts->schema_version) != SQLITE_OK
      || sqlite3_bind_int64 (stmt, 6, (sqlite3_int64) column_index)
      != SQLITE_OK || (rc = bind_text (stmt, 7, column->column_name))
      != WYRELOG_E_OK || (rc = bind_text (stmt, 8, column->column_type))
      != WYRELOG_E_OK || sqlite3_bind_int (stmt, 9,
          column->nullable ? 1 : 0) != SQLITE_OK
      || sqlite3_bind_int (stmt, 10, column->visible ? 1 : 0) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
insert_fact_relation_query_metadata (wyl_policy_store_t *store,
    const wyl_policy_fact_relation_schema_options_t *opts,
    const wyl_policy_fact_relation_schema_query_t *query)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "INSERT INTO fact_relation_query_allowlist "
      "(tenant_id, graph_id, namespace_id, relation_name, schema_version, "
      " query_name, required_permission_id, max_rows) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, opts->tenant_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, opts->graph_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, opts->namespace_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 4, opts->relation_name)) != WYRELOG_E_OK
      || sqlite3_bind_int64 (stmt, 5, opts->schema_version) != SQLITE_OK
      || (rc = bind_text (stmt, 6, query->query_name)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 7, query->required_permission_id))
      != WYRELOG_E_OK || sqlite3_bind_int64 (stmt, 8, query->max_rows)
      != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_register_fact_relation_schema (wyl_policy_store_t *store,
    const wyl_policy_fact_relation_schema_options_t *opts)
{
  wyrelog_error_t rc = validate_fact_relation_schema_options (store, opts);
  if (rc != WYRELOG_E_OK)
    return rc;

  gboolean active = FALSE;
  rc = wyl_policy_store_fact_graph_is_active (store, opts->tenant_id,
      opts->graph_id, &active);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!active)
    return WYRELOG_E_NOT_FOUND;

  rc = wyl_policy_store_begin_mutation (store);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_fact_namespace_metadata (store, opts);
  if (rc == WYRELOG_E_OK)
    rc = insert_fact_relation_schema_metadata (store, opts);
  for (gsize i = 0; rc == WYRELOG_E_OK && i < opts->n_columns; i++)
    rc = insert_fact_relation_schema_column_metadata (store, opts, i);
  for (gsize i = 0; rc == WYRELOG_E_OK && i < opts->n_queries; i++)
    rc = insert_fact_relation_query_metadata (store, opts, &opts->queries[i]);
  if (rc == WYRELOG_E_OK && opts->n_queries == 0 && opts->relation_visible) {
    const wyl_policy_fact_relation_schema_query_t default_query = {
      .query_name = opts->relation_name,
      .required_permission_id = "wr.datalog.query",
      .max_rows = WYL_POLICY_FACT_QUERY_DEFAULT_MAX_ROWS,
    };
    rc = insert_fact_relation_query_metadata (store, opts, &default_query);
  }
  if (rc != WYRELOG_E_OK) {
    wyl_policy_store_rollback_mutation (store);
    return rc;
  }
  return wyl_policy_store_commit_mutation (store);
}

wyrelog_error_t
wyl_policy_store_load_fact_relation_schema_columns (wyl_policy_store_t *store,
    const gchar *tenant_id, const gchar *graph_id, const gchar *namespace_id,
    const gchar *relation_name, guint32 schema_version,
    gboolean *out_relation_visible,
    wyl_policy_fact_relation_schema_column_info_t **out_columns,
    gsize *out_n_columns)
{
  sqlite3_stmt *stmt = NULL;
  wyl_policy_fact_relation_schema_column_info_t *columns = NULL;
  gsize len = 0;
  gsize cap = 0;

  if (out_relation_visible != NULL)
    *out_relation_visible = FALSE;
  if (out_columns != NULL)
    *out_columns = NULL;
  if (out_n_columns != NULL)
    *out_n_columns = 0;
  if (store == NULL || store->db == NULL || out_columns == NULL
      || out_n_columns == NULL || !wyl_policy_store_tenant_id_is_valid
      (tenant_id) || !fact_graph_component_is_valid (tenant_id)
      || !fact_graph_customer_name_is_valid (graph_id)
      || !fact_graph_customer_name_is_valid (namespace_id)
      || !fact_graph_customer_name_is_valid (relation_name)
      || schema_version == 0)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT c.column_name, c.column_type, c.nullable, c.visible, "
      "s.relation_visible "
      "FROM fact_relation_schema_columns c "
      "JOIN fact_relation_schemas s "
      "  ON s.tenant_id = c.tenant_id AND s.graph_id = c.graph_id "
      " AND s.namespace_id = c.namespace_id "
      " AND s.relation_name = c.relation_name "
      " AND s.schema_version = c.schema_version "
      "WHERE c.tenant_id = ? AND c.graph_id = ? AND c.namespace_id = ? "
      "  AND c.relation_name = ? AND c.schema_version = ? "
      "ORDER BY c.column_index;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, tenant_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, graph_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, namespace_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 4, relation_name)) != WYRELOG_E_OK
      || sqlite3_bind_int64 (stmt, 5, schema_version) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    if (len == cap) {
      gsize next_cap = cap == 0 ? 4 : cap * 2;
      wyl_policy_fact_relation_schema_column_info_t *next =
          g_renew (wyl_policy_fact_relation_schema_column_info_t, columns,
          next_cap);
      if (next == NULL) {
        wyl_policy_fact_relation_schema_columns_free (columns, len);
        sqlite3_finalize (stmt);
        return WYRELOG_E_NOMEM;
      }
      memset (next + cap, 0, sizeof (*next) * (next_cap - cap));
      columns = next;
      cap = next_cap;
    }
    columns[len].column_name =
        g_strdup ((const gchar *) sqlite3_column_text (stmt, 0));
    columns[len].column_type =
        g_strdup ((const gchar *) sqlite3_column_text (stmt, 1));
    if (columns[len].column_name == NULL || columns[len].column_type == NULL) {
      wyl_policy_fact_relation_schema_columns_free (columns, len + 1);
      sqlite3_finalize (stmt);
      return WYRELOG_E_NOMEM;
    }
    columns[len].nullable = sqlite3_column_int (stmt, 2) != 0;
    columns[len].visible = sqlite3_column_int (stmt, 3) != 0;
    if (out_relation_visible != NULL)
      *out_relation_visible = sqlite3_column_int (stmt, 4) != 0;
    len++;
  }
  sqlite3_finalize (stmt);
  if (step_rc != SQLITE_DONE) {
    wyl_policy_fact_relation_schema_columns_free (columns, len);
    return WYRELOG_E_IO;
  }
  if (len == 0)
    return WYRELOG_E_NOT_FOUND;

  *out_columns = columns;
  *out_n_columns = len;
  return WYRELOG_E_OK;
}

void wyl_policy_fact_relation_query_info_clear
    (wyl_policy_fact_relation_query_info_t * info)
{
  if (info == NULL)
    return;
  g_clear_pointer (&info->namespace_id, g_free);
  g_clear_pointer (&info->relation_name, g_free);
  g_clear_pointer (&info->query_name, g_free);
  g_clear_pointer (&info->required_permission_id, g_free);
  memset (info, 0, sizeof (*info));
}

wyrelog_error_t
wyl_policy_store_load_fact_relation_query (wyl_policy_store_t *store,
    const gchar *tenant_id, const gchar *graph_id, const gchar *query_name,
    wyl_policy_fact_relation_query_info_t *out_info)
{
  sqlite3_stmt *stmt = NULL;

  if (out_info != NULL)
    memset (out_info, 0, sizeof (*out_info));
  if (store == NULL || store->db == NULL || out_info == NULL
      || !wyl_policy_store_tenant_id_is_valid (tenant_id)
      || !fact_graph_component_is_valid (tenant_id)
      || !fact_graph_customer_name_is_valid (graph_id)
      || !fact_graph_customer_name_is_valid (query_name))
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT namespace_id, relation_name, schema_version, query_name, "
      "required_permission_id, max_rows "
      "FROM fact_relation_query_allowlist "
      "WHERE tenant_id = ? AND graph_id = ? AND query_name = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, tenant_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, graph_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, query_name)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_NOT_FOUND;
  }
  if (step_rc != SQLITE_ROW) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  out_info->namespace_id =
      g_strdup ((const gchar *) sqlite3_column_text (stmt, 0));
  out_info->relation_name =
      g_strdup ((const gchar *) sqlite3_column_text (stmt, 1));
  out_info->schema_version = (guint32) sqlite3_column_int64 (stmt, 2);
  out_info->query_name =
      g_strdup ((const gchar *) sqlite3_column_text (stmt, 3));
  out_info->required_permission_id =
      g_strdup ((const gchar *) sqlite3_column_text (stmt, 4));
  out_info->max_rows = (guint) sqlite3_column_int64 (stmt, 5);
  sqlite3_finalize (stmt);

  if (out_info->namespace_id == NULL || out_info->relation_name == NULL
      || out_info->query_name == NULL || out_info->required_permission_id
      == NULL || out_info->schema_version == 0 || out_info->max_rows == 0) {
    wyl_policy_fact_relation_query_info_clear (out_info);
    return WYRELOG_E_NOMEM;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_table_exists (wyl_policy_store_t *store,
    const gchar *table_name, gboolean *out_exists)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || table_name == NULL
      || out_exists == NULL)
    return WYRELOG_E_INVALID;

  *out_exists = FALSE;
  static const gchar *sql =
      "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?;";
  if (sqlite3_prepare_v2 (store->db, sql, -1, &stmt, NULL) != SQLITE_OK)
    return WYRELOG_E_IO;
  if (sqlite3_bind_text (stmt, 1, table_name, -1, SQLITE_TRANSIENT)
      != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  int rc = sqlite3_step (stmt);
  if (rc == SQLITE_ROW)
    *out_exists = TRUE;
  else if (rc != SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

static gchar *
compact_sql (const gchar *sql)
{
  if (sql == NULL)
    return NULL;
  GString *out = g_string_sized_new (strlen (sql));
  for (const gchar * p = sql; *p != '\0'; p++) {
    if (!g_ascii_isspace (*p) && *p != '`' && *p != '"')
      g_string_append_c (out, g_ascii_tolower (*p));
  }
  return g_string_free (out, FALSE);
}

static wyrelog_error_t
load_schema_object_sql (sqlite3 *db, const gchar *type, const gchar *name,
    const gchar *table, gchar **out_sql)
{
  sqlite3_stmt *stmt = NULL;
  *out_sql = NULL;
  static const gchar *sql =
      "SELECT sql FROM main.sqlite_schema WHERE type = ? AND name = ? "
      "AND (? IS NULL OR tbl_name = ?);";
  wyrelog_error_t rc = prepare_stmt (db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (bind_text (stmt, 1, type) != WYRELOG_E_OK
      || bind_text (stmt, 2, name) != WYRELOG_E_OK
      || (table == NULL ? sqlite3_bind_null (stmt, 3) :
          sqlite3_bind_text (stmt, 3, table, -1, SQLITE_TRANSIENT)) != SQLITE_OK
      || (table == NULL ? sqlite3_bind_null (stmt, 4) :
          sqlite3_bind_text (stmt, 4, table, -1,
              SQLITE_TRANSIENT)) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW) {
    const gchar *value = (const gchar *) sqlite3_column_text (stmt, 0);
    *out_sql = g_strdup (value);
    sqlite3_finalize (stmt);
    return *out_sql == NULL ? WYRELOG_E_IO : WYRELOG_E_OK;
  }
  sqlite3_finalize (stmt);
  return step_rc == SQLITE_DONE ? WYRELOG_E_POLICY : WYRELOG_E_IO;
}

static wyrelog_error_t
validate_table_descriptor (sqlite3 *db, const ServiceTableDescriptor *desc)
{
  g_autofree gchar *pragma =
      g_strdup_printf ("PRAGMA main.table_info(\"%s\");", desc->name);
  sqlite3_stmt *stmt = NULL;
  if (sqlite3_prepare_v2 (db, pragma, -1, &stmt, NULL) != SQLITE_OK)
    return WYRELOG_E_IO;
  g_autoptr (GString) columns = g_string_new (NULL);
  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *name = (const gchar *) sqlite3_column_text (stmt, 1);
    if (name == NULL) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_POLICY;
    }
    const gchar *type = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *default_value = (const gchar *) sqlite3_column_text (stmt, 4);
    if (type == NULL) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_POLICY;
    }
    if (columns->len > 0)
      g_string_append_c (columns, ',');
    g_string_append_printf (columns, "%s:%s:%d:%s:%d", name, type,
        sqlite3_column_int (stmt, 3),
        default_value != NULL ? default_value : "",
        sqlite3_column_int (stmt, 5));
  }
  sqlite3_finalize (stmt);
  if (step_rc != SQLITE_DONE)
    return WYRELOG_E_IO;
  if (g_strcmp0 (columns->str, desc->column_signature) != 0)
    return WYRELOG_E_POLICY;

  g_autofree gchar *object_sql = NULL;
  wyrelog_error_t rc = load_schema_object_sql (db, "table", desc->name,
      desc->name, &object_sql);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_autofree gchar *compacted = compact_sql (object_sql);
  guint check_count = 0;
  for (const gchar * p = compacted; (p = strstr (p, "check(")) != NULL;
      p += strlen ("check("))
    check_count++;
  if (check_count != desc->check_count)
    return WYRELOG_E_POLICY;
  for (gsize i = 0; desc->sql_needles[i] != NULL; i++) {
    if (strstr (compacted, desc->sql_needles[i]) == NULL)
      return WYRELOG_E_POLICY;
  }

  g_autofree gchar *fk_pragma =
      g_strdup_printf ("PRAGMA main.foreign_key_list(\"%s\");", desc->name);
  stmt = NULL;
  if (sqlite3_prepare_v2 (db, fk_pragma, -1, &stmt, NULL) != SQLITE_OK)
    return WYRELOG_E_IO;
  g_autoptr (GString) signature = g_string_new (NULL);
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *table = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *from = (const gchar *) sqlite3_column_text (stmt, 3);
    const gchar *to = (const gchar *) sqlite3_column_text (stmt, 4);
    const gchar *on_update = (const gchar *) sqlite3_column_text (stmt, 5);
    const gchar *on_delete = (const gchar *) sqlite3_column_text (stmt, 6);
    const gchar *match = (const gchar *) sqlite3_column_text (stmt, 7);
    if (table == NULL || from == NULL || to == NULL || on_update == NULL
        || on_delete == NULL || match == NULL) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_POLICY;
    }
    if (signature->len > 0)
      g_string_append_c (signature, ';');
    g_string_append_printf (signature, "%d:%d:%s:%s:%s:%s:%s:%s",
        sqlite3_column_int (stmt, 0), sqlite3_column_int (stmt, 1), table,
        from, to, on_update, on_delete, match);
  }
  sqlite3_finalize (stmt);
  if (step_rc != SQLITE_DONE)
    return WYRELOG_E_IO;
  if (g_strcmp0 (signature->str, desc->foreign_key_signature) != 0)
    return WYRELOG_E_POLICY;

  static const gchar *index_list_sql =
      "SELECT name, \"unique\", origin, partial"
      " FROM pragma_index_list(?, 'main') " "ORDER BY name;";
  if (sqlite3_prepare_v2 (db, index_list_sql, -1, &stmt, NULL) != SQLITE_OK)
    return WYRELOG_E_IO;
  if (sqlite3_bind_text (stmt, 1, desc->name, -1, SQLITE_TRANSIENT)
      != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  g_string_set_size (signature, 0);
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *name = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *origin = (const gchar *) sqlite3_column_text (stmt, 2);
    if (name == NULL || origin == NULL) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_POLICY;
    }
    g_autofree gchar *index_pragma =
        g_strdup_printf ("PRAGMA main.index_xinfo(\"%s\");", name);
    sqlite3_stmt *index_stmt = NULL;
    if (sqlite3_prepare_v2 (db, index_pragma, -1, &index_stmt, NULL)
        != SQLITE_OK) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_IO;
    }
    g_autoptr (GString) columns = g_string_new (NULL);
    int index_rc;
    while ((index_rc = sqlite3_step (index_stmt)) == SQLITE_ROW) {
      const gchar *column = (const gchar *) sqlite3_column_text (index_stmt, 2);
      const gchar *collation =
          (const gchar *) sqlite3_column_text (index_stmt, 4);
      if (collation == NULL) {
        sqlite3_finalize (index_stmt);
        sqlite3_finalize (stmt);
        return WYRELOG_E_POLICY;
      }
      if (columns->len > 0)
        g_string_append_c (columns, ',');
      g_string_append_printf (columns, "%d:%d:%s:%d:%s:%d",
          sqlite3_column_int (index_stmt, 0),
          sqlite3_column_int (index_stmt, 1), column != NULL ? column : "",
          sqlite3_column_int (index_stmt, 3), collation,
          sqlite3_column_int (index_stmt, 5));
    }
    sqlite3_finalize (index_stmt);
    if (index_rc != SQLITE_DONE) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_IO;
    }
    if (signature->len > 0)
      g_string_append_c (signature, ';');
    g_string_append_printf (signature, "%s:%d:%s:%d:%s", name,
        sqlite3_column_int (stmt, 1), origin, sqlite3_column_int (stmt, 3),
        columns->str);
  }
  sqlite3_finalize (stmt);
  if (step_rc != SQLITE_DONE)
    return WYRELOG_E_IO;
  if (g_strcmp0 (signature->str, desc->index_signature) != 0)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
validate_trigger_descriptor (sqlite3 *db, const ServiceTriggerDescriptor *desc)
{
  g_autofree gchar *object_sql = NULL;
  wyrelog_error_t rc = load_schema_object_sql (db, "trigger", desc->name,
      desc->table, &object_sql);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *compacted = compact_sql (object_sql);
  return g_strcmp0 (compacted, desc->sql_fingerprint) == 0 ?
      WYRELOG_E_OK : WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_policy_store_validate_service_schema (wyl_policy_store_t *store)
{
  if (store == NULL || store->db == NULL)
    return WYRELOG_E_INVALID;

  for (gsize i = 0; i < G_N_ELEMENTS (service_table_descriptors); i++) {
    wyrelog_error_t rc = validate_table_descriptor (store->db,
        &service_table_descriptors[i]);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  for (gsize i = 0; i < G_N_ELEMENTS (service_index_descriptors); i++) {
    g_autofree gchar *object_sql = NULL;
    wyrelog_error_t rc = load_schema_object_sql (store->db, "index",
        service_index_descriptors[i].name,
        service_index_descriptors[i].table, &object_sql);
    if (rc != WYRELOG_E_OK)
      return rc;
    g_autofree gchar *compacted = compact_sql (object_sql);
    if (g_strcmp0 (compacted,
            service_index_descriptors[i].sql_fingerprint) != 0)
      return WYRELOG_E_POLICY;
  }
  for (gsize i = 0; i < G_N_ELEMENTS (service_trigger_descriptors); i++) {
    wyrelog_error_t rc = validate_trigger_descriptor (store->db,
        &service_trigger_descriptors[i]);
    if (rc != WYRELOG_E_OK)
      return rc;
  }

  gboolean found = FALSE;
  wyrelog_error_t rc = query_has_rows (store->db,
      "SELECT 1 FROM main.sqlite_schema WHERE type = 'trigger' AND tbl_name IN ("
      "'service_principals','service_credentials','service_credential_cvk',"
      "'service_credential_handoff_escrows',"
      "'service_principal_events','service_credential_events',"
      "'service_domain_requests','service_credential_operation_fences',"
      "'service_credential_handoff_dispositions',"
      "'service_credential_handoff_cancellation_claims',"
      "'service_credential_handoff_remediation_actions',"
      "'service_credential_handoff_retirement_receipts',"
      "'service_exchange_audit_intentions') "
      "AND name NOT IN ("
      "'trg_service_principals_identity_immutable',"
      "'trg_service_credentials_identity_immutable',"
      "'trg_service_principal_events_no_update',"
      "'trg_service_principal_events_no_delete',"
      "'trg_service_credential_events_no_update',"
      "'trg_service_credential_events_no_delete',"
      "'trg_service_domain_requests_no_update',"
      "'trg_service_domain_requests_no_delete',"
      "'trg_service_credential_operation_fences_no_update',"
      "'trg_service_credential_operation_fences_no_delete',"
      "'trg_service_handoff_dispositions_no_update',"
      "'trg_service_handoff_dispositions_no_delete',"
      "'trg_service_handoff_cancellation_no_update',"
      "'trg_service_handoff_cancellation_no_delete',"
      "'trg_service_handoff_cancellation_no_legacy_collision',"
      "'trg_service_handoff_cancellation_no_remediation_collision',"
      "'trg_service_handoff_remediation_no_update',"
      "'trg_service_handoff_remediation_no_delete',"
      "'trg_service_handoff_remediation_no_legacy_collision',"
      "'trg_service_handoff_remediation_no_cancellation_collision',"
      "'trg_service_handoff_retirement_no_update',"
      "'trg_service_handoff_retirement_no_delete',"
      "'trg_service_domain_requests_no_remediation_collision',"
      "'trg_service_domain_requests_no_cancellation_collision',"
      "'trg_service_exchange_audit_no_update',"
      "'trg_service_exchange_audit_no_delete') LIMIT 1;", &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (found)
    return WYRELOG_E_POLICY;

  rc = query_has_rows (store->db,
      "SELECT 1 FROM sqlite_temp_schema AS temp_object WHERE"
      " temp_object.tbl_name IN ("
      "'service_principals','service_credentials','service_credential_cvk',"
      "'service_credential_handoff_escrows',"
      "'service_principal_events','service_credential_events',"
      "'service_domain_requests','service_credential_operation_fences',"
      "'service_credential_handoff_dispositions',"
      "'service_credential_handoff_cancellation_claims',"
      "'service_credential_handoff_remediation_actions',"
      "'service_credential_handoff_retirement_receipts',"
      "'service_exchange_audit_intentions',"
      "'service_authority_writer_gate') OR temp_object.name IN ("
      " SELECT name FROM main.sqlite_schema WHERE tbl_name IN ("
      "'service_principals','service_credentials','service_credential_cvk',"
      "'service_credential_handoff_escrows',"
      "'service_principal_events','service_credential_events',"
      "'service_domain_requests','service_credential_operation_fences',"
      "'service_credential_handoff_dispositions',"
      "'service_credential_handoff_cancellation_claims',"
      "'service_credential_handoff_remediation_actions',"
      "'service_credential_handoff_retirement_receipts',"
      "'service_exchange_audit_intentions',"
      "'service_authority_writer_gate')) LIMIT 1;", &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (found)
    return WYRELOG_E_POLICY;

  rc = query_has_rows (store->db,
      "SELECT 1 WHERE (SELECT count(*) FROM main.service_authority_writer_gate)<>1"
      " OR NOT EXISTS(SELECT 1 FROM main.service_authority_writer_gate"
      " WHERE singleton=1 AND lock_word=0"
      " AND typeof(singleton)='integer' AND typeof(lock_word)='integer');",
      &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (found)
    return WYRELOG_E_POLICY;

  rc = query_has_rows (store->db,
      "SELECT 1 FROM service_credential_cvk WHERE slot <> 1 "
      "UNION ALL SELECT 1 FROM service_credential_cvk "
      "GROUP BY slot HAVING count(*) > 1 LIMIT 1;", &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (found)
    return WYRELOG_E_POLICY;

  rc = query_has_rows (store->db,
      "SELECT 1 FROM pragma_foreign_key_check "
      "WHERE \"table\" IN ('service_principals','service_credentials',"
      "'service_credential_cvk','service_credential_handoff_escrows','service_principal_events',"
      "'service_credential_events','service_domain_requests',"
      "'service_credential_operation_fences',"
      "'service_credential_handoff_dispositions',"
      "'service_credential_handoff_cancellation_claims',"
      "'service_credential_handoff_remediation_actions',"
      "'service_credential_handoff_retirement_receipts') LIMIT 1;", &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (found)
    return WYRELOG_E_POLICY;

  /* Legacy stores may already contain unregistered `svc:` subjects in the
   * shared policy/authentication tables.  The inert migration must preserve
   * those rows without silently registering a service.  Once a service is
   * registered, however, human authentication state, TOTP, bootstrap identity
   * and login skip-MFA are conflicting authorities and fail closed. */
  rc = query_has_rows (store->db,
      "SELECT 1 FROM service_principals s JOIN principal_states p "
      "  ON p.subject_id = s.subject_id "
      "UNION ALL SELECT 1 FROM service_principals s JOIN totp_enrollments t "
      "  ON t.subject_id = s.subject_id "
      "UNION ALL SELECT 1 FROM service_principals s "
      "  JOIN direct_permissions d ON d.subject_id = s.subject_id "
      "  WHERE d.perm_id = 'wr.login.skip_mfa' "
      "UNION ALL SELECT 1 FROM service_principals s "
      "  JOIN wyrelog_config c ON c.config_value = s.subject_id "
      "  WHERE c.config_key = 'bootstrap_admin_subject' "
      "    AND c.config_value <> 'legacy-skip' LIMIT 1;", &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  return found ? WYRELOG_E_POLICY : WYRELOG_E_OK;
}

static gboolean
service_subject_component_char (guint8 c)
{
  return g_ascii_isalnum (c) || c == '.' || c == '_' || c == '-';
}

gboolean
wyl_policy_service_subject_is_valid (const gchar *subject_id,
    gsize subject_id_len)
{
  if (subject_id == NULL || subject_id_len < 5 || subject_id_len > 128
      || memcmp (subject_id, "svc:", 4) != 0)
    return FALSE;
  gsize component_start = 4;
  for (gsize i = 4; i <= subject_id_len; i++) {
    if (i < subject_id_len && subject_id[i] != ':') {
      guint8 c = (guint8) subject_id[i];
      if (c == 0 || c > 0x7f || !service_subject_component_char (c))
        return FALSE;
      continue;
    }
    if (i == component_start
        || !g_ascii_isalnum ((guint8) subject_id[component_start])
        || !g_ascii_isalnum ((guint8) subject_id[i - 1]))
      return FALSE;
    component_start = i + 1;
  }
  return TRUE;
}

gboolean
wyl_policy_subject_has_service_prefix (const gchar *subject_id)
{
  return subject_id != NULL && g_str_has_prefix (subject_id, "svc:");
}

static wyrelog_error_t
service_authorization_subject_check (wyl_policy_store_t *store,
    const gchar *subject_id, gboolean human_only)
{
  if (!wyl_policy_subject_has_service_prefix (subject_id))
    return WYRELOG_E_OK;
  if (human_only)
    return WYRELOG_E_POLICY;

  wyl_policy_principal_kind_t kind = WYL_POLICY_PRINCIPAL_KIND_UNKNOWN;
  wyrelog_error_t rc = wyl_policy_store_get_principal_kind (store, subject_id,
      &kind);
  if (rc != WYRELOG_E_OK)
    return rc;
  return kind == WYL_POLICY_PRINCIPAL_KIND_SERVICE ? WYRELOG_E_OK :
      WYRELOG_E_POLICY;
}

void wyl_policy_service_principal_info_clear
    (wyl_policy_service_principal_info_t * info)
{
  if (info == NULL)
    return;
  g_free (info->subject_id);
  g_free (info->display_name);
  g_free (info->state);
  g_free (info->created_by);
  g_free (info->disabled_by);
  memset (info, 0, sizeof (*info));
}

void wyl_policy_service_credential_info_clear
    (wyl_policy_service_credential_info_t * info)
{
  if (info == NULL)
    return;
  g_free (info->credential_id);
  g_free (info->subject_id);
  g_free (info->tenant_id);
  g_free (info->state);
  g_free (info->created_by);
  g_free (info->revoked_by);
  g_free (info->rotated_from_id);
  sodium_memzero (info->salt, sizeof info->salt);
  sodium_memzero (info->verifier, sizeof info->verifier);
  memset (info, 0, sizeof (*info));
}

void
wyl_policy_service_cvk_info_clear (wyl_policy_service_cvk_info_t *info)
{
  if (info == NULL)
    return;
  sodium_memzero (info->provider_binding, sizeof info->provider_binding);
  if (info->sealed_cvk != NULL) {
    sodium_memzero (info->sealed_cvk, info->sealed_cvk_len);
    g_free (info->sealed_cvk);
  }
  memset (info, 0, sizeof (*info));
}

void wyl_policy_service_principal_event_info_clear
    (wyl_policy_service_principal_event_info_t * info)
{
  if (info == NULL)
    return;
  g_free (info->subject_id);
  g_free (info->event);
  g_free (info->from_state);
  g_free (info->to_state);
  g_free (info->actor_subject_id);
  g_free (info->request_id);
  memset (info, 0, sizeof (*info));
}

void wyl_policy_service_credential_event_info_clear
    (wyl_policy_service_credential_event_info_t * info)
{
  if (info == NULL)
    return;
  g_free (info->credential_id);
  g_free (info->subject_id);
  g_free (info->tenant_id);
  g_free (info->event);
  g_free (info->from_state);
  g_free (info->to_state);
  g_free (info->actor_subject_id);
  g_free (info->request_id);
  g_free (info->related_credential_id);
  memset (info, 0, sizeof (*info));
}

static wyrelog_error_t
read_owned_text (sqlite3_stmt *stmt, int column, gboolean nullable,
    gsize min_len, gsize max_len, gchar **out)
{
  *out = NULL;
  int type = sqlite3_column_type (stmt, column);
  if (type == SQLITE_NULL)
    return nullable ? WYRELOG_E_OK : WYRELOG_E_POLICY;
  if (type != SQLITE_TEXT)
    return WYRELOG_E_POLICY;
  const gchar *value = (const gchar *) sqlite3_column_text (stmt, column);
  int bytes = sqlite3_column_bytes (stmt, column);
  if (value == NULL || bytes < 0 || (gsize) bytes < min_len
      || (gsize) bytes > max_len || memchr (value, 0, (gsize) bytes) != NULL)
    return WYRELOG_E_POLICY;
  *out = g_strndup (value, (gsize) bytes);
  return *out != NULL ? WYRELOG_E_OK : WYRELOG_E_NOMEM;
}

static wyrelog_error_t
read_positive_u64 (sqlite3_stmt *stmt, int column, guint64 *out)
{
  if (sqlite3_column_type (stmt, column) != SQLITE_INTEGER)
    return WYRELOG_E_POLICY;
  gint64 value = sqlite3_column_int64 (stmt, column);
  if (value < 1)
    return WYRELOG_E_POLICY;
  *out = (guint64) value;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
read_positive_i64 (sqlite3_stmt *stmt, int column, gboolean nullable,
    gint64 *out)
{
  *out = 0;
  if (sqlite3_column_type (stmt, column) == SQLITE_NULL)
    return nullable ? WYRELOG_E_OK : WYRELOG_E_POLICY;
  if (sqlite3_column_type (stmt, column) != SQLITE_INTEGER)
    return WYRELOG_E_POLICY;
  *out = sqlite3_column_int64 (stmt, column);
  return *out > 0 ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
read_fixed_blob (sqlite3_stmt *stmt, int column, guint8 *out, gsize len)
{
  if (sqlite3_column_type (stmt, column) != SQLITE_BLOB
      || sqlite3_column_bytes (stmt, column) != (int) len)
    return WYRELOG_E_POLICY;
  const guint8 *value = sqlite3_column_blob (stmt, column);
  if (value == NULL)
    return WYRELOG_E_POLICY;
  memcpy (out, value, len);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
parse_service_principal_row (sqlite3_stmt *stmt,
    wyl_policy_service_principal_info_t *out)
{
  memset (out, 0, sizeof (*out));
  wyrelog_error_t rc = read_owned_text (stmt, 0, FALSE, 5, 128,
      &out->subject_id);
  if (rc == WYRELOG_E_OK && !wyl_policy_service_subject_is_valid
      (out->subject_id, strlen (out->subject_id)))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 1, FALSE, 1, 256, &out->display_name);
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 2, FALSE, 1, 16, &out->state);
  if (rc == WYRELOG_E_OK)
    rc = read_positive_u64 (stmt, 3, &out->generation);
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 4, FALSE, 1, 128, &out->created_by);
  if (rc == WYRELOG_E_OK)
    rc = read_positive_i64 (stmt, 5, FALSE, &out->created_at_us);
  if (rc == WYRELOG_E_OK)
    rc = read_positive_i64 (stmt, 6, FALSE, &out->updated_at_us);
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 7, TRUE, 1, 128, &out->disabled_by);
  if (rc == WYRELOG_E_OK)
    rc = read_positive_i64 (stmt, 8, TRUE, &out->disabled_at_us);
  if (rc == WYRELOG_E_OK && ((g_str_equal (out->state, "active")
              && (out->disabled_by != NULL || out->disabled_at_us != 0))
          || (g_str_equal (out->state, "disabled")
              && (out->disabled_by == NULL || out->disabled_at_us == 0))
          || (!g_str_equal (out->state, "active")
              && !g_str_equal (out->state, "disabled"))
          || (out->disabled_at_us != 0
              && out->disabled_at_us < out->created_at_us)
          || out->updated_at_us < out->created_at_us))
    rc = WYRELOG_E_POLICY;
  if (rc != WYRELOG_E_OK)
    wyl_policy_service_principal_info_clear (out);
  return rc;
}

static wyrelog_error_t
parse_service_credential_row (sqlite3_stmt *stmt,
    wyl_policy_service_credential_info_t *out)
{
  memset (out, 0, sizeof (*out));
  guint64 version = 0;
  wyrelog_error_t rc = read_owned_text (stmt, 0, FALSE, 1, 128,
      &out->credential_id);
  if (rc == WYRELOG_E_OK)
    rc = read_positive_u64 (stmt, 1, &version);
  if (rc == WYRELOG_E_OK && version > G_MAXUINT32)
    rc = WYRELOG_E_POLICY;
  out->credential_format_version = (guint32) version;
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 2, FALSE, 5, 128, &out->subject_id);
  if (rc == WYRELOG_E_OK && !wyl_policy_service_subject_is_valid
      (out->subject_id, strlen (out->subject_id)))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 3, FALSE, 1, 128, &out->tenant_id);
  if (rc == WYRELOG_E_OK
      && !wyl_policy_store_tenant_id_is_valid (out->tenant_id))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = read_positive_u64 (stmt, 4, &out->generation);
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 5, FALSE, 1, 16, &out->state);
  version = 0;
  if (rc == WYRELOG_E_OK)
    rc = read_positive_u64 (stmt, 6, &version);
  if (rc == WYRELOG_E_OK && version > G_MAXUINT32)
    rc = WYRELOG_E_POLICY;
  out->verifier_version = (guint32) version;
  if (rc == WYRELOG_E_OK)
    rc = read_fixed_blob (stmt, 7, out->salt, sizeof out->salt);
  if (rc == WYRELOG_E_OK)
    rc = read_fixed_blob (stmt, 8, out->verifier, sizeof out->verifier);
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 9, FALSE, 1, 128, &out->created_by);
  if (rc == WYRELOG_E_OK)
    rc = read_positive_i64 (stmt, 10, FALSE, &out->created_at_us);
  if (rc == WYRELOG_E_OK)
    rc = read_positive_i64 (stmt, 11, FALSE, &out->updated_at_us);
  if (rc == WYRELOG_E_OK)
    rc = read_positive_i64 (stmt, 12, TRUE, &out->expires_at_us);
  if (rc == WYRELOG_E_OK)
    rc = read_positive_i64 (stmt, 13, TRUE, &out->last_used_at_us);
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 14, TRUE, 1, 128, &out->revoked_by);
  if (rc == WYRELOG_E_OK)
    rc = read_positive_i64 (stmt, 15, TRUE, &out->revoked_at_us);
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 16, TRUE, 1, 128, &out->rotated_from_id);
  if (rc == WYRELOG_E_OK && ((g_str_equal (out->state, "active")
              && (out->revoked_by != NULL || out->revoked_at_us != 0))
          || (g_str_equal (out->state, "revoked")
              && (out->revoked_by == NULL || out->revoked_at_us == 0))
          || (!g_str_equal (out->state, "active")
              && !g_str_equal (out->state, "revoked"))
          || (out->revoked_at_us != 0
              && out->revoked_at_us < out->created_at_us)
          || out->updated_at_us < out->created_at_us
          || (out->expires_at_us != 0
              && out->expires_at_us <= out->created_at_us)
          || (out->last_used_at_us != 0
              && out->last_used_at_us < out->created_at_us)
          || (out->rotated_from_id != NULL
              && g_str_equal (out->rotated_from_id, out->credential_id))))
    rc = WYRELOG_E_POLICY;
  if (rc != WYRELOG_E_OK)
    wyl_policy_service_credential_info_clear (out);
  return rc;
}

static wyrelog_error_t
bind_service_filter (sqlite3_stmt *stmt, const gchar *credential_id,
    const gchar *subject_id, const gchar *tenant_id)
{
  int index = 1;
  wyrelog_error_t rc;
  if (credential_id != NULL
      && (rc = bind_text (stmt, index++, credential_id)) != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, index++, subject_id)) != WYRELOG_E_OK)
    return rc;
  return bind_text (stmt, index, tenant_id);
}

static gboolean
credential_filter_is_valid (const gchar *credential_id,
    const gchar *subject_id, const gchar *tenant_id)
{
  return (credential_id == NULL
      || (credential_id[0] != '\0' && strlen (credential_id) <= 128))
      && subject_id != NULL
      && wyl_policy_service_subject_is_valid (subject_id, strlen (subject_id))
      && wyl_policy_store_tenant_id_is_valid (tenant_id);
}

wyrelog_error_t
wyl_policy_store_get_principal_kind (wyl_policy_store_t *store,
    const gchar *subject_id, wyl_policy_principal_kind_t *out_kind)
{
  if (out_kind != NULL)
    *out_kind = WYL_POLICY_PRINCIPAL_KIND_UNKNOWN;
  if (store == NULL || store->db == NULL || subject_id == NULL
      || subject_id[0] == '\0' || strlen (subject_id) > 256 || out_kind == NULL)
    return WYRELOG_E_INVALID;
  sqlite3_stmt *stmt = NULL;
  static const gchar *service_sql =
      "SELECT subject_id FROM service_principals WHERE subject_id=?;";
  wyrelog_error_t rc = prepare_stmt (store->db, service_sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }
  int step_rc = sqlite3_step (stmt);
  gboolean registered = step_rc == SQLITE_ROW;
  if (registered) {
    const gchar *stored = (const gchar *) sqlite3_column_text (stmt, 0);
    int len = sqlite3_column_bytes (stmt, 0);
    if (sqlite3_column_type (stmt, 0) != SQLITE_TEXT || stored == NULL
        || len < 0 || memchr (stored, 0, (gsize) len) != NULL
        || !wyl_policy_service_subject_is_valid (stored, (gsize) len)) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_POLICY;
    }
  }
  sqlite3_finalize (stmt);
  if (step_rc != SQLITE_ROW && step_rc != SQLITE_DONE)
    return WYRELOG_E_IO;

  const gchar *artifact_sql =
      "SELECT 1 FROM principal_states WHERE subject_id=? "
      "UNION ALL SELECT 1 FROM totp_enrollments WHERE subject_id=? "
      "UNION ALL SELECT 1 FROM direct_permissions"
      " WHERE subject_id=? AND perm_id='wr.login.skip_mfa' "
      "UNION ALL SELECT 1 FROM wyrelog_config"
      " WHERE config_key='bootstrap_admin_subject' AND config_value=?"
      " AND config_value<>'legacy-skip' LIMIT 1;";
  rc = prepare_stmt (store->db, artifact_sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  for (int i = 1; i <= 4; i++) {
    if ((rc = bind_text (stmt, i, subject_id)) != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }
  step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  if (step_rc != SQLITE_ROW && step_rc != SQLITE_DONE)
    return WYRELOG_E_IO;
  if (registered && step_rc == SQLITE_ROW)
    return WYRELOG_E_POLICY;
  *out_kind = registered ? WYL_POLICY_PRINCIPAL_KIND_SERVICE :
      (step_rc == SQLITE_ROW ? WYL_POLICY_PRINCIPAL_KIND_HUMAN :
      WYL_POLICY_PRINCIPAL_KIND_UNKNOWN);
  return WYRELOG_E_OK;
}

static gboolean
service_domain_text_is_valid (const gchar *value, gsize max_len)
{
  if (value == NULL)
    return FALSE;
  gsize len = strlen (value);
  return len >= 1 && len <= max_len;
}

gboolean
wyl_policy_service_actor_subject_is_valid (const gchar *actor_subject_id)
{
  return service_domain_text_is_valid (actor_subject_id, 128)
      && g_utf8_validate (actor_subject_id, -1, NULL);
}

static wyrelog_error_t
service_domain_fingerprint (const gchar *operation, const gchar *subject_id,
    const gchar *display_name, const gchar *actor_subject_id,
    guint8 out[crypto_generichash_BYTES])
{
  crypto_generichash_state state;
  static const guint8 domain[] = "wyrelog.service-principal-domain-request.v1";
  if (crypto_generichash_init (&state, NULL, 0, crypto_generichash_BYTES) != 0
      || crypto_generichash_update (&state, domain, sizeof domain - 1) != 0)
    return WYRELOG_E_CRYPTO;
  const gchar *fields[] = {
    operation, subject_id, display_name != NULL ? display_name : "",
    actor_subject_id,
  };
  static const guint8 separator = 0;
  for (gsize i = 0; i < G_N_ELEMENTS (fields); i++) {
    if (crypto_generichash_update (&state, (const guint8 *) fields[i],
            strlen (fields[i])) != 0
        || crypto_generichash_update (&state, &separator, 1) != 0) {
      sodium_memzero (&state, sizeof state);
      return WYRELOG_E_CRYPTO;
    }
  }
  int failed = crypto_generichash_final (&state, out,
      crypto_generichash_BYTES);
  sodium_memzero (&state, sizeof state);
  return failed == 0 ? WYRELOG_E_OK : WYRELOG_E_CRYPTO;
}

static wyrelog_error_t
service_domain_claim_request (wyl_policy_store_t *store,
    const gchar *request_id, const gchar *operation, const gchar *resource_id,
    const guint8 fingerprint[crypto_generichash_BYTES], gint64 now_us)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "INSERT INTO service_domain_requests "
      "(request_id,operation,resource_id,input_fingerprint,created_at_us) "
      "VALUES(?,?,?,?,?);";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, request_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, operation)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, resource_id)) != WYRELOG_E_OK
      || sqlite3_bind_blob (stmt, 4, fingerprint, crypto_generichash_BYTES,
          SQLITE_TRANSIENT) != SQLITE_OK
      || sqlite3_bind_int64 (stmt, 5, now_us) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  if (step_rc == SQLITE_DONE)
    return WYRELOG_E_OK;
  return (step_rc & 0xff) == SQLITE_CONSTRAINT ? WYRELOG_E_POLICY :
      WYRELOG_E_IO;
}

/* Frozen v1 transcript (see wyl_policy_store_service_credential_operation_fence_fingerprint
 * doc comment in store-private.h for the exact byte layout). Every caller that
 * persists, looks up, reconciles, or conflict-checks a service credential
 * operation fence must go through this one helper. */
static wyrelog_error_t
    service_credential_operation_fence_fingerprint
    (WylServiceCredentialFenceOperation operation, const gchar * field_a,
    gsize field_a_len, const gchar * field_b, gsize field_b_len,
    guint8 out[crypto_generichash_BYTES])
{
  static const guint8 domain[] =
      "wyrelog.service-credential-operation-fence.v1";
  gboolean is_issue = operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE;
  if ((!is_issue && operation != WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE)
      || field_a == NULL || field_a_len > G_MAXUINT32
      || (is_issue && (field_b == NULL || field_b_len > G_MAXUINT32))
      || (!is_issue && field_b != NULL))
    return WYRELOG_E_INVALID;

  crypto_generichash_state state;
  if (crypto_generichash_init (&state, NULL, 0, crypto_generichash_BYTES) != 0)
    return WYRELOG_E_CRYPTO;
#define FENCE_HASH(data, len) G_STMT_START { \
  if (crypto_generichash_update (&state, (const guint8 *) (data), \
          (gsize) (len)) != 0) { \
    sodium_memzero (&state, sizeof state); \
    return WYRELOG_E_CRYPTO; \
  } \
} G_STMT_END
  guint8 u32[4];
  u32[0] = 0;
  u32[1] = 0;
  u32[2] = 0;
  u32[3] = (guint8) (sizeof domain - 1);
  FENCE_HASH (u32, sizeof u32);
  FENCE_HASH (domain, sizeof domain - 1);
  guint8 version = 1;
  FENCE_HASH (&version, 1);
  guint8 tag = (guint8) operation;
  FENCE_HASH (&tag, 1);
  u32[0] = (guint8) (field_a_len >> 24);
  u32[1] = (guint8) (field_a_len >> 16);
  u32[2] = (guint8) (field_a_len >> 8);
  u32[3] = (guint8) field_a_len;
  FENCE_HASH (u32, sizeof u32);
  FENCE_HASH (field_a, field_a_len);
  if (is_issue) {
    u32[0] = (guint8) (field_b_len >> 24);
    u32[1] = (guint8) (field_b_len >> 16);
    u32[2] = (guint8) (field_b_len >> 8);
    u32[3] = (guint8) field_b_len;
    FENCE_HASH (u32, sizeof u32);
    FENCE_HASH (field_b, field_b_len);
  }
#undef FENCE_HASH
  int failed = crypto_generichash_final (&state, out, crypto_generichash_BYTES);
  sodium_memzero (&state, sizeof state);
  return failed == 0 ? WYRELOG_E_OK : WYRELOG_E_CRYPTO;
}

wyrelog_error_t
    wyl_policy_store_service_credential_operation_fence_fingerprint
    (WylServiceCredentialFenceOperation operation, const gchar * field_a,
    gsize field_a_len, const gchar * field_b, gsize field_b_len,
    guint8 out[crypto_generichash_BYTES])
{
  if (out == NULL)
    return WYRELOG_E_INVALID;
  return service_credential_operation_fence_fingerprint (operation, field_a,
      field_a_len, field_b, field_b_len, out);
}

/* Re-derives the operation-target fingerprint of an already-committed
 * credential_issue/credential_rotate request from its durable successor
 * event row, rather than trusting a persisted copy: service_domain_requests
 * predates this fence protocol and its own input_fingerprint column is a
 * different, richer hash (it also binds actor and expiry). Returns
 * WYRELOG_E_NOT_FOUND when no committed request exists for this ID. */
static wyrelog_error_t
service_credential_operation_fence_committed_lookup_db (sqlite3 *db,
    const gchar *request_id, WylServiceCredentialFenceOperation operation,
    gboolean *out_operation_matches,
    guint8 out_fingerprint[crypto_generichash_BYTES],
    gchar out_credential_id[WYL_SERVICE_CREDENTIAL_ID_BUF],
    guint64 *out_generation)
{
  *out_operation_matches = FALSE;
  memset (out_fingerprint, 0, crypto_generichash_BYTES);
  out_credential_id[0] = '\0';
  *out_generation = 0;

  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = prepare_stmt (db,
      "SELECT operation FROM service_domain_requests WHERE request_id=?;",
      &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = bind_text (stmt, 1, request_id);
  int step_rc = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_ERROR;
  if (rc == WYRELOG_E_OK && step_rc == SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_NOT_FOUND;
  }
  if (rc != WYRELOG_E_OK || step_rc != SQLITE_ROW) {
    sqlite3_finalize (stmt);
    return rc == WYRELOG_E_OK ? WYRELOG_E_IO : rc;
  }
  const gchar *db_operation = (const gchar *) sqlite3_column_text (stmt, 0);
  gboolean is_issue = operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE;
  gboolean operation_matches = db_operation != NULL
      && g_str_equal (db_operation, is_issue ? "credential_issue" :
      "credential_rotate");
  sqlite3_finalize (stmt);
  *out_operation_matches = operation_matches;
  if (!operation_matches)
    return WYRELOG_E_OK;

  stmt = NULL;
  rc = prepare_stmt (db, is_issue ?
      "SELECT credential_id,generation,subject_id,tenant_id"
      " FROM service_credential_events WHERE request_id=? AND event='issued';" :
      "SELECT credential_id,generation,related_credential_id"
      " FROM service_credential_events WHERE request_id=? AND event='rotated';",
      &stmt);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 1, request_id);
  step_rc = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_ERROR;
  if (rc != WYRELOG_E_OK || step_rc != SQLITE_ROW) {
    sqlite3_finalize (stmt);
    return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
  }
  const gchar *credential_id = (const gchar *) sqlite3_column_text (stmt, 0);
  gint64 generation = sqlite3_column_int64 (stmt, 1);
  gsize credential_id_len = sqlite3_column_bytes (stmt, 0);
  const gchar *field_a_val = is_issue ? credential_id :
      (const gchar *) sqlite3_column_text (stmt, 2);
  gsize field_a_len = is_issue ? credential_id_len :
      (gsize) sqlite3_column_bytes (stmt, 2);
  g_autofree gchar *subject_copy = NULL;
  g_autofree gchar *tenant_copy = NULL;
  g_autofree gchar *old_id_copy = NULL;
  g_autofree gchar *credential_id_copy = NULL;
  gboolean row_valid = sqlite3_column_type (stmt, 0) == SQLITE_TEXT
      && sqlite3_column_type (stmt, 1) == SQLITE_INTEGER
      && credential_id != NULL && credential_id_len > 0
      && credential_id_len < WYL_SERVICE_CREDENTIAL_ID_BUF
      && memchr (credential_id, '\0', credential_id_len) == NULL
      && wyl_service_credential_id_is_canonical (credential_id,
      credential_id_len) && generation > 0 && generation <= G_MAXINT64;
  if (is_issue) {
    const gchar *subject_text = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *tenant_text = (const gchar *) sqlite3_column_text (stmt, 3);
    gsize subject_len = sqlite3_column_bytes (stmt, 2);
    gsize tenant_len = sqlite3_column_bytes (stmt, 3);
    row_valid = row_valid && sqlite3_column_type (stmt, 2) == SQLITE_TEXT
        && sqlite3_column_type (stmt, 3) == SQLITE_TEXT && subject_text != NULL
        && tenant_text != NULL
        && memchr (subject_text, '\0', subject_len) == NULL
        && memchr (tenant_text, '\0', tenant_len) == NULL
        && wyl_policy_service_subject_is_valid (subject_text, subject_len)
        && wyl_policy_store_tenant_id_is_valid (tenant_text);
    if (row_valid) {
      subject_copy = g_strndup (subject_text, subject_len);
      tenant_copy = g_strndup (tenant_text, tenant_len);
      row_valid = subject_copy != NULL && tenant_copy != NULL;
    }
  } else {
    row_valid = row_valid && sqlite3_column_type (stmt, 2) == SQLITE_TEXT
        && field_a_val != NULL
        && memchr (field_a_val, '\0', field_a_len) == NULL
        && wyl_service_credential_id_is_canonical (field_a_val, field_a_len);
    if (row_valid) {
      old_id_copy = g_strndup (field_a_val, field_a_len);
      row_valid = old_id_copy != NULL;
    }
  }
  if (row_valid) {
    credential_id_copy = g_strndup (credential_id, credential_id_len);
    row_valid = credential_id_copy != NULL;
  }
  int final_step_rc = sqlite3_step (stmt);
  if (!row_valid || final_step_rc != SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return final_step_rc == SQLITE_DONE ? WYRELOG_E_POLICY : WYRELOG_E_IO;
  }
  g_strlcpy (out_credential_id, credential_id_copy,
      WYL_SERVICE_CREDENTIAL_ID_BUF);
  *out_generation = (guint64) generation;
  sqlite3_finalize (stmt);

  return is_issue ?
      service_credential_operation_fence_fingerprint (operation, subject_copy,
      strlen (subject_copy), tenant_copy, strlen (tenant_copy),
      out_fingerprint) :
      service_credential_operation_fence_fingerprint (operation, old_id_copy,
      strlen (old_id_copy), NULL, 0, out_fingerprint);
}

/* Looks up a durable terminal fence for |request_id|. Returns
 * WYRELOG_E_NOT_FOUND when none exists. */
static wyrelog_error_t service_credential_operation_fence_lookup_db
    (sqlite3 * db, const gchar * request_id,
    WylServiceCredentialFenceOperation operation,
    gboolean * out_operation_matches,
    guint8 out_fingerprint[crypto_generichash_BYTES]);
static wyrelog_error_t service_credential_operation_fence_precheck_on_db
    (sqlite3 * db, WylServiceCredentialFenceOperation operation,
    const gchar * request_id, const gchar * subject_id,
    const gchar * tenant_id, const gchar * old_credential_id,
    WylServiceCredentialFenceResult * out_result);
static wyrelog_error_t
    service_credential_operation_fence_precheck_with_committed_on_db
    (sqlite3 * db, WylServiceCredentialFenceOperation operation,
    const gchar * request_id, const gchar * subject_id,
    const gchar * tenant_id, const gchar * old_credential_id,
    WylServiceCredentialFenceResult * out_result);

static wyrelog_error_t
service_credential_operation_fence_lookup (wyl_policy_store_t *store,
    const gchar *request_id, WylServiceCredentialFenceOperation operation,
    gboolean *out_operation_matches,
    guint8 out_fingerprint[crypto_generichash_BYTES])
{
  return service_credential_operation_fence_lookup_db (store->db, request_id,
      operation, out_operation_matches, out_fingerprint);
}

static wyrelog_error_t
service_credential_operation_fence_lookup_db (sqlite3 *db,
    const gchar *request_id, WylServiceCredentialFenceOperation operation,
    gboolean *out_operation_matches,
    guint8 out_fingerprint[crypto_generichash_BYTES])
{
  *out_operation_matches = FALSE;
  memset (out_fingerprint, 0, crypto_generichash_BYTES);
  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = prepare_stmt (db,
      "SELECT operation,operation_fingerprint FROM"
      " service_credential_operation_fences WHERE request_id=?;", &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = bind_text (stmt, 1, request_id);
  int step_rc = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_ERROR;
  if (rc == WYRELOG_E_OK && step_rc == SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_NOT_FOUND;
  }
  if (rc != WYRELOG_E_OK || step_rc != SQLITE_ROW) {
    sqlite3_finalize (stmt);
    return rc == WYRELOG_E_OK ? WYRELOG_E_IO : rc;
  }
  const gchar *db_operation = (const gchar *) sqlite3_column_text (stmt, 0);
  gboolean is_issue = operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE;
  gboolean operation_matches = db_operation != NULL
      && g_str_equal (db_operation, is_issue ? "credential_issue" :
      "credential_rotate");
  *out_operation_matches = operation_matches;
  if (operation_matches) {
    if (sqlite3_column_type (stmt, 1) != SQLITE_BLOB
        || sqlite3_column_bytes (stmt, 1) != crypto_generichash_BYTES) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_POLICY;
    }
    memcpy (out_fingerprint, sqlite3_column_blob (stmt, 1),
        crypto_generichash_BYTES);
  }
  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
service_credential_operation_fence_insert (wyl_policy_store_t *store,
    const gchar *request_id, WylServiceCredentialFenceOperation operation,
    const guint8 fingerprint[crypto_generichash_BYTES], gint64 now_us)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "INSERT INTO service_credential_operation_fences"
      " (request_id,operation,operation_fingerprint,terminal_state,created_at_us)"
      " VALUES(?,?,?,'not_committed',?);";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  gboolean is_issue = operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE;
  if ((rc = bind_text (stmt, 1, request_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2,
              is_issue ? "credential_issue" : "credential_rotate"))
      != WYRELOG_E_OK
      || sqlite3_bind_blob (stmt, 3, fingerprint, crypto_generichash_BYTES,
          SQLITE_TRANSIENT) != SQLITE_OK
      || sqlite3_bind_int64 (stmt, 4, now_us) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  if (step_rc == SQLITE_DONE)
    return WYRELOG_E_OK;
  return (step_rc & 0xff) == SQLITE_CONSTRAINT ? WYRELOG_E_POLICY :
      WYRELOG_E_IO;
}

wyrelog_error_t
    wyl_policy_store_reconcile_service_credential_operation_fence
    (WylServiceAuthorityTransaction * txn, wyl_policy_store_t * store,
    GCancellable * cancellable, WylServiceCredentialFenceOperation operation,
    const gchar * request_id, const gchar * subject_id,
    const gchar * tenant_id, const gchar * old_credential_id,
    WylServiceCredentialFenceResult * out_result)
{
  if (out_result != NULL)
    memset (out_result, 0, sizeof *out_result);
  if (out_result == NULL || store == NULL
      || !service_domain_text_is_valid (request_id, 256)
      || (cancellable != NULL && !G_IS_CANCELLABLE (cancellable)))
    return WYRELOG_E_INVALID;
  gboolean is_issue = operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE;
  gboolean is_rotate = operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE;
  if (!is_issue && !is_rotate)
    return WYRELOG_E_INVALID;
  if (is_issue
      && (subject_id == NULL
          || !wyl_policy_service_subject_is_valid (subject_id,
              strlen (subject_id)) || !wyl_policy_store_tenant_id_is_valid
          (tenant_id) || old_credential_id != NULL))
    return WYRELOG_E_INVALID;
  if (is_rotate
      && (old_credential_id == NULL
          || !wyl_service_credential_id_is_canonical (old_credential_id,
              strlen (old_credential_id)) || subject_id != NULL
          || tenant_id != NULL))
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = wyl_policy_store_validate_service_schema (store);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylServiceAuthorityWriteIntentOutcome intent_outcome = { 0 };
  rc = wyl_policy_store_service_authority_transaction_acquire_write_intent
      (txn, store, cancellable, &intent_outcome);
  if (rc != WYRELOG_E_OK)
    return rc;

  guint8 requested_fingerprint[crypto_generichash_BYTES];
  rc = is_issue ?
      service_credential_operation_fence_fingerprint (operation, subject_id,
      strlen (subject_id), tenant_id, strlen (tenant_id),
      requested_fingerprint) :
      service_credential_operation_fence_fingerprint (operation,
      old_credential_id, strlen (old_credential_id), NULL, 0,
      requested_fingerprint);
  if (rc != WYRELOG_E_OK) {
    sodium_memzero (requested_fingerprint, sizeof requested_fingerprint);
    return rc;
  }

  gboolean committed_operation_matches = FALSE;
  guint8 committed_fingerprint[crypto_generichash_BYTES];
  gchar successor_id[WYL_SERVICE_CREDENTIAL_ID_BUF];
  guint64 successor_generation = 0;
  rc = service_credential_operation_fence_committed_lookup_db (store->db,
      request_id,
      operation, &committed_operation_matches, committed_fingerprint,
      successor_id, &successor_generation);
  if (rc != WYRELOG_E_OK && rc != WYRELOG_E_NOT_FOUND) {
    sodium_memzero (requested_fingerprint, sizeof requested_fingerprint);
    return rc;
  }
  if (rc == WYRELOG_E_OK) {
    gboolean fingerprint_matches = committed_operation_matches
        && memcmp (committed_fingerprint, requested_fingerprint,
        crypto_generichash_BYTES) == 0;
    sodium_memzero (requested_fingerprint, sizeof requested_fingerprint);
    sodium_memzero (committed_fingerprint, sizeof committed_fingerprint);
    if (!committed_operation_matches || !fingerprint_matches) {
      out_result->state = WYL_SERVICE_CREDENTIAL_FENCE_RESULT_CONFLICT;
      return WYRELOG_E_OK;
    }
    out_result->state = WYL_SERVICE_CREDENTIAL_FENCE_RESULT_COMMITTED;
    g_strlcpy (out_result->successor_credential_id, successor_id,
        sizeof out_result->successor_credential_id);
    out_result->successor_generation = successor_generation;
    return WYRELOG_E_OK;
  }

  gboolean fence_operation_matches = FALSE;
  guint8 fence_fingerprint[crypto_generichash_BYTES];
  rc = service_credential_operation_fence_lookup (store, request_id, operation,
      &fence_operation_matches, fence_fingerprint);
  if (rc != WYRELOG_E_OK && rc != WYRELOG_E_NOT_FOUND) {
    sodium_memzero (requested_fingerprint, sizeof requested_fingerprint);
    return rc;
  }
  if (rc == WYRELOG_E_OK) {
    gboolean fingerprint_matches = fence_operation_matches
        && memcmp (fence_fingerprint, requested_fingerprint,
        crypto_generichash_BYTES) == 0;
    sodium_memzero (requested_fingerprint, sizeof requested_fingerprint);
    sodium_memzero (fence_fingerprint, sizeof fence_fingerprint);
    out_result->state = fence_operation_matches && fingerprint_matches ?
        WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL :
        WYL_SERVICE_CREDENTIAL_FENCE_RESULT_CONFLICT;
    return WYRELOG_E_OK;
  }

  gint64 now_us = g_get_real_time ();
  rc = service_credential_operation_fence_insert (store, request_id, operation,
      requested_fingerprint, now_us);
  sodium_memzero (requested_fingerprint, sizeof requested_fingerprint);
  if (rc != WYRELOG_E_OK)
    return rc;
  out_result->state =
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
service_domain_has_legacy_collision (wyl_policy_store_t *store,
    const gchar *subject_id, gboolean *out_found)
{
  static const gchar *sql =
      "SELECT 1 FROM principal_states WHERE subject_id=? "
      "UNION ALL SELECT 1 FROM principal_events WHERE subject_id=? "
      "UNION ALL SELECT 1 FROM totp_enrollments WHERE subject_id=? "
      "UNION ALL SELECT 1 FROM wyrelog_config "
      " WHERE config_key='bootstrap_admin_subject' AND config_value=? "
      "UNION ALL SELECT 1 FROM session_states WHERE session_id=? "
      "UNION ALL SELECT 1 FROM session_events WHERE session_id=? "
      "UNION ALL SELECT 1 FROM permission_states WHERE subject_id=? "
      "UNION ALL SELECT 1 FROM permission_state_events WHERE subject_id=? "
      "UNION ALL SELECT 1 FROM role_memberships WHERE subject_id=? "
      "UNION ALL SELECT 1 FROM role_membership_events WHERE subject_id=? "
      "UNION ALL SELECT 1 FROM direct_permissions WHERE subject_id=? "
      "UNION ALL SELECT 1 FROM direct_permission_events WHERE subject_id=? "
      "LIMIT 1;";
  sqlite3_stmt *stmt = NULL;
  *out_found = FALSE;
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  for (int i = 1; i <= 12; i++) {
    if ((rc = bind_text (stmt, i, subject_id)) != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }
  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW)
    *out_found = TRUE;
  sqlite3_finalize (stmt);
  return step_rc == SQLITE_ROW || step_rc == SQLITE_DONE ? WYRELOG_E_OK :
      WYRELOG_E_IO;
}

static wyrelog_error_t
service_domain_new_audit_id (gchar out[WYL_ID_STRING_BUF])
{
  wyl_id_t id = WYL_ID_NIL;
  wyrelog_error_t rc = wyl_id_new (&id);
  return rc == WYRELOG_E_OK ? wyl_id_format (&id, out, WYL_ID_STRING_BUF) : rc;
}

static wyrelog_error_t
service_domain_append_audit (wyl_policy_store_t *store, const gchar *audit_id,
    gint64 now_us, const gchar *actor_subject_id, const gchar *action,
    const gchar *subject_id, const gchar *request_id)
{
  gboolean inserted = FALSE;
  wyrelog_error_t rc = wyl_policy_store_append_audit_event_full (store,
      audit_id, now_us, actor_subject_id, action, subject_id, NULL, NULL,
      request_id, WYL_DECISION_ALLOW, &inserted);
  if (rc != WYRELOG_E_OK)
    return rc;
  inserted = FALSE;
  return wyl_policy_store_record_audit_intention_full (store, audit_id,
      now_us, actor_subject_id, action, subject_id, NULL, NULL, request_id,
      WYL_DECISION_ALLOW, &inserted);
}

static wyrelog_error_t
service_domain_append_principal_event (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *event, const gchar *from_state,
    const gchar *to_state, guint64 generation, const gchar *actor_subject_id,
    const gchar *request_id, gint64 now_us)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "INSERT INTO service_principal_events "
      "(subject_id,event,from_state,to_state,generation,actor_subject_id,"
      "request_id,created_at_us) VALUES(?,?,?,?,?,?,?,?);";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, event)) != WYRELOG_E_OK
      || (rc = bind_nullable_text (stmt, 3, from_state)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 4, to_state)) != WYRELOG_E_OK
      || sqlite3_bind_int64 (stmt, 5, (sqlite3_int64) generation) != SQLITE_OK
      || (rc = bind_text (stmt, 6, actor_subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 7, request_id)) != WYRELOG_E_OK
      || sqlite3_bind_int64 (stmt, 8, now_us) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return step_rc == SQLITE_DONE ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
service_domain_validate_mutation (wyl_policy_store_t *store)
{
  wyrelog_error_t rc = wyl_policy_store_validate_snapshot (store);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_validate_service_schema (store);
  if (rc == WYRELOG_E_OK && store->service_lifecycle_fail_commit_once) {
    store->service_lifecycle_fail_commit_once = FALSE;
    rc = WYRELOG_E_IO;
  }
  return rc;
}

static wyrelog_error_t
service_domain_finish_mutation (wyl_policy_store_t *store)
{
  wyrelog_error_t rc = service_domain_validate_mutation (store);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_commit_mutation (store);
  if (rc != WYRELOG_E_OK)
    wyl_policy_store_rollback_mutation (store);
  return rc;
}

static wyrelog_error_t
    service_authority_transaction_validate_preconditions
    (WylServiceAuthorityTransaction * txn, wyl_policy_store_t * store)
{
  if (txn == NULL || store == NULL || txn->store != store
      || txn->owner != g_thread_self ()
      || txn->state != WYL_SERVICE_AUTHORITY_TXN_ACTIVE
      || !txn->owns_store_locks || !txn->owns_handle_pin
      || !g_atomic_int_get (&store->service_authority_transaction_active))
    return WYRELOG_E_INVALID;
  return wyl_service_auth_write_lease_validate_operation (txn->write_lease,
      txn->handle);
}

static wyrelog_error_t
    service_authority_transaction_validate_active
    (WylServiceAuthorityTransaction * txn, wyl_policy_store_t * store)
{
  wyrelog_error_t rc = service_authority_transaction_validate_preconditions
      (txn, store);
  if (rc == WYRELOG_E_OK && txn->write_intent_state ==
      WYL_SERVICE_AUTHORITY_WRITE_INTENT_STATE_ROLLBACK_REQUIRED)
    rc = WYRELOG_E_BUSY;
  if (rc == WYRELOG_E_OK && txn->participant_rollback_only)
    rc = WYRELOG_E_BUSY;
  return rc;
}

static void
service_authority_transaction_fail_participant (WylServiceAuthorityTransaction
    *txn, wyrelog_error_t rc)
{
  if (!txn->participant_rollback_only) {
    txn->participant_rollback_only = TRUE;
    txn->participant_failure_rc = rc;
    txn->participant_failure_sqlite_extended_error =
        sqlite3_extended_errcode (txn->store->db);
  }
}

wyrelog_error_t
    wyl_policy_store_service_authority_transaction_enter_participant
    (WylServiceAuthorityTransaction * txn, wyl_policy_store_t * expected_store)
{
  wyrelog_error_t rc = service_authority_transaction_validate_active (txn,
      expected_store);
  if (rc == WYRELOG_E_OK)
    txn->durable_operation_started = TRUE;
  return rc;
}

static wyrelog_error_t
write_intent_fail (WylServiceAuthorityTransaction *txn,
    WylServiceAuthorityWriteIntentOutcome *outcome,
    WylServiceAuthorityWriteIntentResult result, int extended_code,
    wyrelog_error_t rc)
{
  txn->write_intent_state =
      WYL_SERVICE_AUTHORITY_WRITE_INTENT_STATE_ROLLBACK_REQUIRED;
  txn->write_intent_failure_rc = rc;
  txn->write_intent_failure.result = result;
  txn->write_intent_failure.sqlite_extended_code = extended_code;
  *outcome = txn->write_intent_failure;
  return rc;
}

wyrelog_error_t
    wyl_policy_store_service_authority_transaction_acquire_write_intent
    (WylServiceAuthorityTransaction * txn, wyl_policy_store_t * expected_store,
    GCancellable * cancellable,
    WylServiceAuthorityWriteIntentOutcome * out_outcome) {
  if (out_outcome != NULL)
    *out_outcome = (WylServiceAuthorityWriteIntentOutcome) {
    WYL_SERVICE_AUTHORITY_WRITE_INTENT_NONE, SQLITE_OK};
  if (out_outcome == NULL
      || (cancellable != NULL && !G_IS_CANCELLABLE (cancellable)))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = service_authority_transaction_validate_preconditions
      (txn, expected_store);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (txn->write_intent_state ==
      WYL_SERVICE_AUTHORITY_WRITE_INTENT_STATE_ACQUIRED) {
    out_outcome->result = WYL_SERVICE_AUTHORITY_WRITE_INTENT_ACQUIRED;
    return WYRELOG_E_OK;
  }
  if (txn->write_intent_state ==
      WYL_SERVICE_AUTHORITY_WRITE_INTENT_STATE_ROLLBACK_REQUIRED) {
    *out_outcome = txn->write_intent_failure;
    return txn->write_intent_failure_rc;
  }

  if (txn->durable_operation_started)
    return write_intent_fail (txn, out_outcome,
        WYL_SERVICE_AUTHORITY_WRITE_INTENT_POLICY, SQLITE_MISUSE,
        WYRELOG_E_POLICY);

  rc = wyl_policy_store_service_authority_transaction_enter_participant (txn,
      expected_store);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (txn->commit_evidence == NULL)
    return write_intent_fail (txn, out_outcome,
        WYL_SERVICE_AUTHORITY_WRITE_INTENT_POLICY, SQLITE_MISUSE,
        WYRELOG_E_POLICY);
  sqlite3_stmt *stmt = NULL;
  int sql_rc = sqlite3_prepare_v2 (expected_store->db,
      "UPDATE main.service_authority_writer_gate SET lock_word=lock_word"
      " WHERE singleton=1 AND lock_word=0;", -1, &stmt, NULL);
  if (sql_rc == SQLITE_OK) {
    g_mutex_lock (&txn->write_intent_barrier_mutex);
    if (txn->write_intent_barrier_armed) {
      txn->write_intent_barrier_reached = TRUE;
      g_cond_broadcast (&txn->write_intent_barrier_cond);
      while (!txn->write_intent_barrier_released)
        g_cond_wait (&txn->write_intent_barrier_cond,
            &txn->write_intent_barrier_mutex);
      txn->write_intent_barrier_armed = FALSE;
    }
    g_mutex_unlock (&txn->write_intent_barrier_mutex);
    if (cancellable != NULL && g_cancellable_is_cancelled (cancellable)) {
      sqlite3_finalize (stmt);
      return write_intent_fail (txn, out_outcome,
          WYL_SERVICE_AUTHORITY_WRITE_INTENT_CANCELLED, SQLITE_INTERRUPT,
          WYRELOG_E_BUSY);
    }
  }
  int forced = txn->write_intent_fail_sql_once;
  txn->write_intent_fail_sql_once = SQLITE_OK;
  if (sql_rc == SQLITE_OK)
    sql_rc = forced != SQLITE_OK ? forced : sqlite3_step (stmt);
  int extended = forced != SQLITE_OK ? forced
      : sqlite3_extended_errcode (expected_store->db);
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  if (sql_rc == SQLITE_DONE && sqlite3_changes (expected_store->db) == 1
      && sqlite3_txn_state (expected_store->db, "main") == SQLITE_TXN_WRITE) {
    txn->write_intent_state = WYL_SERVICE_AUTHORITY_WRITE_INTENT_STATE_ACQUIRED;
    out_outcome->result = WYL_SERVICE_AUTHORITY_WRITE_INTENT_ACQUIRED;
    out_outcome->sqlite_extended_code = SQLITE_OK;
    return WYRELOG_E_OK;
  }
  if (sql_rc == SQLITE_BUSY_SNAPSHOT)
    return write_intent_fail (txn, out_outcome,
        WYL_SERVICE_AUTHORITY_WRITE_INTENT_BUSY_SNAPSHOT, extended,
        WYRELOG_E_BUSY);
  if ((sql_rc & 0xff) == SQLITE_BUSY)
    return write_intent_fail (txn, out_outcome,
        WYL_SERVICE_AUTHORITY_WRITE_INTENT_BUSY, extended, WYRELOG_E_BUSY);
  if ((sql_rc & 0xff) == SQLITE_LOCKED)
    return write_intent_fail (txn, out_outcome,
        WYL_SERVICE_AUTHORITY_WRITE_INTENT_LOCKED, extended, WYRELOG_E_BUSY);
  if (sql_rc == SQLITE_DONE)
    return write_intent_fail (txn, out_outcome,
        WYL_SERVICE_AUTHORITY_WRITE_INTENT_POLICY, extended, WYRELOG_E_POLICY);
  return write_intent_fail (txn, out_outcome,
      WYL_SERVICE_AUTHORITY_WRITE_INTENT_IO, extended, WYRELOG_E_IO);
}

wyrelog_error_t
    wyl_policy_store_service_authority_prepare_commit_evidence
    (WylServiceAuthorityTransaction * txn, wyl_policy_store_t * store,
    WylServiceAuthorityCommitEvidence ** out_evidence) {
  if (out_evidence != NULL)
    *out_evidence = NULL;
  if (out_evidence == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = service_authority_transaction_validate_active (txn,
      store);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (txn->durable_operation_started || txn->commit_evidence != NULL)
    return WYRELOG_E_BUSY;
  if (txn->fail_evidence_allocation_once) {
    txn->fail_evidence_allocation_once = FALSE;
    return WYRELOG_E_NOMEM;
  }

  guint64 store_generation = 0;
  rc = wyl_handle_policy_store_capture_generation (txn->handle, store,
      &store_generation);
  if (rc != WYRELOG_E_OK)
    return rc;
  guint64 write_lease_serial = 0;
  rc = wyl_service_auth_write_lease_get_serial (txn->write_lease,
      txn->handle, &write_lease_serial);
  if (rc != WYRELOG_E_OK)
    return rc;
  WylServiceAuthorityCommitEvidence *evidence =
      g_try_new0 (WylServiceAuthorityCommitEvidence, 1);
  if (evidence == NULL)
    return WYRELOG_E_NOMEM;
  g_atomic_int_set (&evidence->refs, 1);
  g_mutex_init (&evidence->mutex);
  evidence->handle = g_object_ref (txn->handle);
  evidence->authority_identity =
      wyl_handle_get_service_auth_authority (txn->handle);
  evidence->store_generation = store_generation;
  evidence->transaction_serial = txn->serial;
  evidence->write_lease_serial = write_lease_serial;
  evidence->state = WYL_SERVICE_AUTHORITY_EVIDENCE_PENDING;
  evidence->pending_owner = txn->owner;
  txn->commit_evidence = evidence;
  txn->evidence_allocation_count++;
  *out_evidence =
      wyl_policy_store_service_authority_commit_evidence_ref (evidence);
  if (*out_evidence == NULL) {
    txn->commit_evidence = NULL;
    wyl_policy_store_service_authority_commit_evidence_unref (evidence);
    return WYRELOG_E_INTERNAL;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
    wyl_policy_store_service_authority_commit_evidence_validate_pending
    (WylServiceAuthorityCommitEvidence * evidence,
    WylServiceAuthorityTransaction * txn, WylHandle * handle,
    wyl_policy_store_t * store) {
  if (evidence == NULL || txn == NULL || !WYL_IS_HANDLE (handle)
      || store == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&evidence->mutex);
  gboolean valid = evidence->state == WYL_SERVICE_AUTHORITY_EVIDENCE_PENDING
      && evidence->pending_owner == g_thread_self ()
      && evidence->handle == handle && txn->commit_evidence == evidence
      && txn->serial == evidence->transaction_serial;
  g_mutex_unlock (&evidence->mutex);
  if (!valid)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = service_authority_transaction_validate_active (txn,
      store);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_policy_store_validate_generation (handle, store,
      evidence->store_generation);
}

wyrelog_error_t
    wyl_policy_store_service_authority_commit_evidence_validate_committed_diagnostic
    (WylServiceAuthorityCommitEvidence * evidence, WylHandle * handle,
    wyl_policy_store_t * store) {
  if (evidence == NULL || !WYL_IS_HANDLE (handle) || store == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&evidence->mutex);
  gboolean valid =
      evidence->state == WYL_SERVICE_AUTHORITY_EVIDENCE_COMMITTED
      && evidence->handle == handle
      && evidence->authority_identity ==
      wyl_handle_get_service_auth_authority (handle)
      && evidence->transaction_serial != 0;
  guint64 generation = evidence->store_generation;
  g_mutex_unlock (&evidence->mutex);
  if (!valid)
    return WYRELOG_E_INVALID;
  return wyl_handle_policy_store_validate_generation (handle, store,
      generation);
}

wyrelog_error_t
    wyl_policy_store_service_authority_commit_evidence_validate_for_active_write
    (WylServiceAuthorityCommitEvidence * evidence,
    WylServiceAuthWriteLease * write_lease, WylHandle * handle,
    wyl_policy_store_t * expected_store, guint64 expected_transaction_serial) {
  if (evidence == NULL || write_lease == NULL || !WYL_IS_HANDLE (handle)
      || expected_store == NULL || expected_transaction_serial == 0)
    return WYRELOG_E_INVALID;

  wyl_policy_store_t *leased_store = NULL;
  wyrelog_error_t rc = wyl_service_auth_write_lease_get_policy_store
      (write_lease, handle, &leased_store);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (leased_store != expected_store)
    return WYRELOG_E_INVALID;
  guint64 active_lease_serial = 0;
  rc = wyl_service_auth_write_lease_get_serial (write_lease, handle,
      &active_lease_serial);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_mutex_lock (&evidence->mutex);
  gboolean valid =
      evidence->state == WYL_SERVICE_AUTHORITY_EVIDENCE_COMMITTED
      && evidence->handle == handle
      && evidence->authority_identity ==
      wyl_handle_get_service_auth_authority (handle)
      && evidence->transaction_serial == expected_transaction_serial
      && evidence->write_lease_serial == active_lease_serial;
  guint64 generation = evidence->store_generation;
  g_mutex_unlock (&evidence->mutex);
  if (!valid)
    return WYRELOG_E_INVALID;
  return wyl_handle_policy_store_validate_generation (handle, expected_store,
      generation);
}

guint64
    wyl_policy_store_service_authority_transaction_get_serial
    (const WylServiceAuthorityTransaction * txn)
{
  return txn != NULL && txn->owner == g_thread_self ()
      && txn->state == WYL_SERVICE_AUTHORITY_TXN_ACTIVE
      && txn->owns_store_locks ? txn->serial : 0;
}

wyrelog_error_t
    wyl_policy_store_service_authority_transaction_record_credential_last_used
    (WylServiceAuthorityTransaction * txn, wyl_policy_store_t * store,
    const gchar * credential_id, guint64 generation,
    const gchar * subject_id, const gchar * tenant_id, gint64 used_at_us)
{
  wyrelog_error_t rc =
      wyl_policy_store_service_authority_transaction_enter_participant (txn,
      store);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (credential_id == NULL
      || !wyl_service_credential_id_is_canonical (credential_id,
          strlen (credential_id)) || generation == 0
      || generation > G_MAXINT64 || subject_id == NULL
      || !wyl_policy_service_subject_is_valid (subject_id,
          strlen (subject_id)) || !wyl_policy_store_tenant_id_is_valid
      (tenant_id) || used_at_us <= 0)
    return WYRELOG_E_INVALID;

  sqlite3_stmt *stmt = NULL;
  rc = prepare_stmt (store->db,
      "SELECT generation,subject_id,tenant_id,state,created_at_us,last_used_at_us"
      " FROM service_credentials WHERE credential_id=?;", &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = bind_text (stmt, 1, credential_id);
  int step_rc = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_ERROR;
  if (rc == WYRELOG_E_OK && step_rc == SQLITE_DONE)
    rc = WYRELOG_E_NOT_FOUND;
  else if (rc == WYRELOG_E_OK && step_rc != SQLITE_ROW)
    rc = WYRELOG_E_IO;

  gint64 stored_generation = 0;
  gint64 created_at_us = 0;
  gint64 last_used_at_us = 0;
  gboolean last_used_is_null = FALSE;
  if (rc == WYRELOG_E_OK) {
    if (sqlite3_column_type (stmt, 0) != SQLITE_INTEGER
        || sqlite3_column_type (stmt, 1) != SQLITE_TEXT
        || sqlite3_column_type (stmt, 2) != SQLITE_TEXT
        || sqlite3_column_type (stmt, 3) != SQLITE_TEXT
        || sqlite3_column_type (stmt, 4) != SQLITE_INTEGER
        || (sqlite3_column_type (stmt, 5) != SQLITE_NULL
            && sqlite3_column_type (stmt, 5) != SQLITE_INTEGER))
      rc = WYRELOG_E_POLICY;
    else {
      stored_generation = sqlite3_column_int64 (stmt, 0);
      created_at_us = sqlite3_column_int64 (stmt, 4);
      last_used_is_null = sqlite3_column_type (stmt, 5) == SQLITE_NULL;
      last_used_at_us = last_used_is_null ? 0 : sqlite3_column_int64 (stmt, 5);
      if (stored_generation <= 0 || created_at_us <= 0
          || (!last_used_is_null && last_used_at_us < created_at_us)
          || (guint64) stored_generation != generation
          || !column_text_exact (stmt, 1, subject_id)
          || !column_text_exact (stmt, 2, tenant_id)
          || !column_text_exact (stmt, 3, "active"))
        rc = WYRELOG_E_POLICY;
      else if (used_at_us < created_at_us)
        rc = WYRELOG_E_INVALID;
    }
  }
  sqlite3_finalize (stmt);
  if (rc != WYRELOG_E_OK || (!last_used_is_null
          && used_at_us <= last_used_at_us))
    return rc;
  if (txn->fail_last_used_sql_once) {
    txn->fail_last_used_sql_once = FALSE;
    return WYRELOG_E_IO;
  }

  stmt = NULL;
  rc = prepare_stmt (store->db,
      "UPDATE service_credentials SET last_used_at_us=?"
      " WHERE credential_id=?;", &stmt);
  if (rc == WYRELOG_E_OK
      && sqlite3_bind_int64 (stmt, 1, used_at_us) != SQLITE_OK)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 2, credential_id);
  if (rc == WYRELOG_E_OK)
    rc = sqlite3_step (stmt) == SQLITE_DONE ? WYRELOG_E_OK : WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && sqlite3_changes (store->db) != 1)
    rc = WYRELOG_E_IO;
  sqlite3_finalize (stmt);
  return rc;
}

wyrelog_error_t
    wyl_policy_store_precheck_service_credential_operation_fence
    (wyl_policy_store_t * store, GCancellable * cancellable,
    WylServiceCredentialFenceOperation operation, const gchar * request_id,
    const gchar * subject_id, const gchar * tenant_id,
    const gchar * old_credential_id,
    WylServiceCredentialFenceResult * out_result)
{
  if (out_result != NULL)
    memset (out_result, 0, sizeof *out_result);
  if (out_result == NULL || store == NULL || store->db == NULL
      || !service_domain_text_is_valid (request_id, 256)
      || (cancellable != NULL && !G_IS_CANCELLABLE (cancellable)))
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = wyl_policy_store_validate_service_schema (store);
  if (rc != WYRELOG_E_OK)
    return rc;

  const gchar *db_path = sqlite3_db_filename (store->db, "main");
  sqlite3 *query_db = NULL;
  gboolean close_query_db = FALSE;
  if (db_path != NULL && db_path[0] != '\0'
      && g_strcmp0 (db_path, ":memory:") != 0) {
    if (sqlite3_open_v2 (db_path, &query_db,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, NULL) == SQLITE_OK
        && query_db != NULL) {
      close_query_db = TRUE;
    } else {
      if (query_db != NULL)
        sqlite3_close (query_db);
      query_db = store->db;
    }
  } else {
    query_db = store->db;
  }

  rc = service_credential_operation_fence_precheck_on_db (query_db, operation,
      request_id, subject_id, tenant_id, old_credential_id, out_result);
  if (close_query_db && query_db != NULL)
    sqlite3_close (query_db);
  return rc;
}

static wyrelog_error_t
service_credential_operation_fence_precheck_on_db (sqlite3 *db,
    WylServiceCredentialFenceOperation operation, const gchar *request_id,
    const gchar *subject_id, const gchar *tenant_id,
    const gchar *old_credential_id, WylServiceCredentialFenceResult *out_result)
{
  if (out_result != NULL)
    memset (out_result, 0, sizeof *out_result);
  if (out_result == NULL || db == NULL
      || !service_domain_text_is_valid (request_id, 256))
    return WYRELOG_E_INVALID;
  gboolean is_issue = operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE;
  gboolean is_rotate = operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE;
  if (!is_issue && !is_rotate)
    return WYRELOG_E_INVALID;
  if (is_issue
      && (subject_id == NULL
          || !wyl_policy_service_subject_is_valid (subject_id,
              strlen (subject_id)) || !wyl_policy_store_tenant_id_is_valid
          (tenant_id) || old_credential_id != NULL))
    return WYRELOG_E_INVALID;
  if (is_rotate
      && (old_credential_id == NULL
          || !wyl_service_credential_id_is_canonical (old_credential_id,
              strlen (old_credential_id)) || subject_id != NULL
          || tenant_id != NULL))
    return WYRELOG_E_INVALID;

  gboolean operation_matches = FALSE;
  guint8 fence_fingerprint[crypto_generichash_BYTES];
  wyrelog_error_t rc = service_credential_operation_fence_lookup_db (db,
      request_id, operation, &operation_matches, fence_fingerprint);
  if (rc == WYRELOG_E_NOT_FOUND)
    return rc;
  if (rc != WYRELOG_E_OK)
    return rc;

  guint8 requested_fingerprint[crypto_generichash_BYTES];
  rc = is_issue ?
      service_credential_operation_fence_fingerprint (operation, subject_id,
      strlen (subject_id), tenant_id, strlen (tenant_id),
      requested_fingerprint) :
      service_credential_operation_fence_fingerprint (operation,
      old_credential_id, strlen (old_credential_id), NULL, 0,
      requested_fingerprint);
  if (rc != WYRELOG_E_OK) {
    sodium_memzero (fence_fingerprint, sizeof fence_fingerprint);
    return rc;
  }

  gboolean fingerprint_matches = operation_matches
      && memcmp (fence_fingerprint, requested_fingerprint,
      crypto_generichash_BYTES) == 0;
  sodium_memzero (fence_fingerprint, sizeof fence_fingerprint);
  sodium_memzero (requested_fingerprint, sizeof requested_fingerprint);
  out_result->state = fingerprint_matches ?
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL :
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_CONFLICT;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
service_credential_operation_fence_precheck_with_committed_on_db (sqlite3 *db,
    WylServiceCredentialFenceOperation operation, const gchar *request_id,
    const gchar *subject_id, const gchar *tenant_id,
    const gchar *old_credential_id, WylServiceCredentialFenceResult *out_result)
{
  if (out_result != NULL)
    memset (out_result, 0, sizeof *out_result);
  if (out_result == NULL || db == NULL
      || !service_domain_text_is_valid (request_id, 256))
    return WYRELOG_E_INVALID;
  gboolean is_issue = operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE;
  gboolean is_rotate = operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE;
  if (!is_issue && !is_rotate)
    return WYRELOG_E_INVALID;
  if (is_issue
      && (subject_id == NULL
          || !wyl_policy_service_subject_is_valid (subject_id,
              strlen (subject_id)) || !wyl_policy_store_tenant_id_is_valid
          (tenant_id) || old_credential_id != NULL))
    return WYRELOG_E_INVALID;
  if (is_rotate
      && (old_credential_id == NULL
          || !wyl_service_credential_id_is_canonical (old_credential_id,
              strlen (old_credential_id)) || subject_id != NULL
          || tenant_id != NULL))
    return WYRELOG_E_INVALID;

  guint8 requested_fingerprint[crypto_generichash_BYTES];
  wyrelog_error_t rc = is_issue ?
      service_credential_operation_fence_fingerprint (operation, subject_id,
      strlen (subject_id), tenant_id, strlen (tenant_id),
      requested_fingerprint) :
      service_credential_operation_fence_fingerprint (operation,
      old_credential_id, strlen (old_credential_id), NULL, 0,
      requested_fingerprint);
  if (rc != WYRELOG_E_OK)
    return rc;

  gboolean operation_matches = FALSE;
  guint8 committed_fingerprint[crypto_generichash_BYTES];
  gchar successor_id[WYL_SERVICE_CREDENTIAL_ID_BUF];
  guint64 successor_generation = 0;
  rc = service_credential_operation_fence_committed_lookup_db (db, request_id,
      operation, &operation_matches, committed_fingerprint, successor_id,
      &successor_generation);
  if (rc == WYRELOG_E_OK) {
    gboolean fingerprint_matches = operation_matches
        && memcmp (committed_fingerprint, requested_fingerprint,
        sizeof committed_fingerprint) == 0;
    sodium_memzero (committed_fingerprint, sizeof committed_fingerprint);
    sodium_memzero (requested_fingerprint, sizeof requested_fingerprint);
    if (!operation_matches || !fingerprint_matches) {
      out_result->state = WYL_SERVICE_CREDENTIAL_FENCE_RESULT_CONFLICT;
      return WYRELOG_E_OK;
    }
    out_result->state = WYL_SERVICE_CREDENTIAL_FENCE_RESULT_COMMITTED;
    g_strlcpy (out_result->successor_credential_id, successor_id,
        sizeof out_result->successor_credential_id);
    out_result->successor_generation = successor_generation;
    return WYRELOG_E_OK;
  }
  sodium_memzero (committed_fingerprint, sizeof committed_fingerprint);
  sodium_memzero (requested_fingerprint, sizeof requested_fingerprint);
  if (rc != WYRELOG_E_NOT_FOUND)
    return rc;

  return service_credential_operation_fence_precheck_on_db (db, operation,
      request_id, subject_id, tenant_id, old_credential_id, out_result);
}

wyrelog_error_t
    wyl_policy_store_precheck_service_credential_operation_fence_with_committed
    (wyl_policy_store_t * store, GCancellable * cancellable,
    WylServiceCredentialFenceOperation operation, const gchar * request_id,
    const gchar * subject_id, const gchar * tenant_id,
    const gchar * old_credential_id,
    WylServiceCredentialFenceResult * out_result)
{
  if (out_result != NULL)
    memset (out_result, 0, sizeof *out_result);
  if (out_result == NULL || store == NULL || store->db == NULL
      || !service_domain_text_is_valid (request_id, 256)
      || (cancellable != NULL && !G_IS_CANCELLABLE (cancellable)))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = wyl_policy_store_validate_service_schema (store);
  if (rc != WYRELOG_E_OK)
    return rc;

  const gchar *db_path = sqlite3_db_filename (store->db, "main");
  sqlite3 *query_db = NULL;
  gboolean close_query_db = FALSE;
  if (db_path != NULL && db_path[0] != '\0'
      && g_strcmp0 (db_path, ":memory:") != 0) {
    if (sqlite3_open_v2 (db_path, &query_db,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, NULL) == SQLITE_OK
        && query_db != NULL)
      close_query_db = TRUE;
    else {
      if (query_db != NULL)
        sqlite3_close (query_db);
      query_db = store->db;
    }
  } else
    query_db = store->db;

  gboolean began_snapshot = FALSE;
  if (sqlite3_get_autocommit (query_db)) {
    int begin_rc = sqlite3_exec (query_db, "BEGIN", NULL, NULL, NULL);
    if (begin_rc != SQLITE_OK)
      rc = begin_rc == SQLITE_BUSY || begin_rc == SQLITE_LOCKED ?
          WYRELOG_E_BUSY : WYRELOG_E_IO;
    else
      began_snapshot = TRUE;
  }
  if (rc == WYRELOG_E_OK)
    rc = service_credential_operation_fence_precheck_with_committed_on_db
        (query_db, operation, request_id, subject_id, tenant_id,
        old_credential_id, out_result);
  if (began_snapshot) {
    int end_rc = sqlite3_exec (query_db, "COMMIT", NULL, NULL, NULL);
    if (rc == WYRELOG_E_OK && end_rc != SQLITE_OK)
      rc = end_rc == SQLITE_BUSY || end_rc == SQLITE_LOCKED ?
          WYRELOG_E_BUSY : WYRELOG_E_IO;
  }
  if (close_query_db)
    sqlite3_close (query_db);
  if (rc != WYRELOG_E_OK)
    memset (out_result, 0, sizeof *out_result);
  return rc;
}

#define SERVICE_EXCHANGE_SELECT_COLUMNS \
  "intention_id,payload_digest,payload_schema_version,event_type,outcome," \
  "created_at_us,request_id,credential_id,credential_generation," \
  "service_principal,tenant_id,fingerprint_schema_version," \
  "session_fingerprint,jti_fingerprint,canonical_payload"

static gboolean
service_exchange_hex_is_canonical (const gchar *value, gsize len)
{
  if (value == NULL || len != 64 || memchr (value, '\0', len) != NULL)
    return FALSE;
  for (gsize i = 0; i < len; i++)
    if (!g_ascii_isdigit (value[i])
        && (value[i] < 'a' || value[i] > 'f'))
      return FALSE;
  return TRUE;
}

static gboolean
service_exchange_request_id_is_canonical (const gchar *value, gsize len)
{
  chronoid_ksuid_t parsed;
  gchar canonical[CHRONOID_KSUID_STRING_LEN + 1];

  if (value == NULL || len != CHRONOID_KSUID_STRING_LEN
      || memchr (value, '\0', len) != NULL
      || chronoid_ksuid_parse (&parsed, value, len) != CHRONOID_KSUID_OK)
    return FALSE;
  chronoid_ksuid_format (&parsed, canonical);
  return memcmp (value, canonical, len) == 0;
}

static gboolean
service_exchange_payload_matches (const WylServiceExchangeIntentionRecord *r)
{
  wyl_service_exchange_audit_projection_t projection = {
    .intention_id = r->material.intention_id,
    .payload_digest = r->material.payload_digest,
    .request_id = r->material.request_id,
    .credential_id = r->credential_id,
    .credential_generation = r->credential_generation,
    .service_principal = r->service_principal,
    .tenant_id = r->tenant_id,
    .created_at_us = r->created_at_us,
    .payload_schema_version = WYL_SERVICE_EXCHANGE_PAYLOAD_SCHEMA_VERSION,
    .fingerprint_schema_version =
        WYL_SERVICE_EXCHANGE_FINGERPRINT_SCHEMA_VERSION,
    .session_fingerprint = r->material.session_fingerprint,
    .jti_fingerprint = r->material.jti_fingerprint,
    .canonical_payload = r->material.canonical_payload,
  };
  return wyl_service_exchange_audit_projection_validate (&projection)
      == WYRELOG_E_OK;
}

void wyl_service_exchange_intention_record_free
    (WylServiceExchangeIntentionRecord * record)
{
  if (record == NULL)
    return;
  wyl_service_exchange_audit_material_clear (&record->material);
  g_clear_pointer (&record->service_principal, g_free);
  g_clear_pointer (&record->tenant_id, g_free);
  sodium_memzero (record, sizeof *record);
  g_free (record);
}

static guint64
service_exchange_generation_from_be (const guint8 bytes[8])
{
  guint64 value = 0;
  for (guint i = 0; i < 8; i++)
    value = (value << 8) | bytes[i];
  return value;
}

static void
service_exchange_generation_to_be (guint64 value, guint8 bytes[8])
{
  for (guint i = 0; i < 8; i++)
    bytes[i] = (guint8) (value >> (56 - i * 8));
}

static wyrelog_error_t
service_exchange_record_from_row (WylServiceAuthorityTransaction *txn,
    sqlite3_stmt *stmt, WylServiceExchangeIntentionRecord **out_record)
{
  *out_record = NULL;
  const int text_columns[] = { 0, 1, 3, 4, 6, 7, 9, 10, 12, 13 };
  for (guint i = 0; i < G_N_ELEMENTS (text_columns); i++)
    if (sqlite3_column_type (stmt, text_columns[i]) != SQLITE_TEXT)
      return WYRELOG_E_POLICY;
  if (sqlite3_column_type (stmt, 2) != SQLITE_INTEGER
      || sqlite3_column_type (stmt, 5) != SQLITE_INTEGER
      || sqlite3_column_type (stmt, 8) != SQLITE_BLOB
      || sqlite3_column_type (stmt, 11) != SQLITE_INTEGER
      || sqlite3_column_type (stmt, 14) != SQLITE_BLOB)
    return WYRELOG_E_POLICY;
  if (sqlite3_column_int64 (stmt, 2) != 1
      || sqlite3_column_int64 (stmt, 11) != 1
      || sqlite3_column_int64 (stmt, 5) <= 0
      || sqlite3_column_bytes (stmt, 8) != 8
      || sqlite3_column_bytes (stmt, 14) <= 0
      || sqlite3_column_bytes (stmt, 14) > 4096)
    return WYRELOG_E_POLICY;

  WylServiceExchangeIntentionRecord *r = txn != NULL
      && txn->fail_service_exchange_typed_read_allocation_once ? NULL :
      g_try_new0 (WylServiceExchangeIntentionRecord, 1);
  if (txn != NULL)
    txn->fail_service_exchange_typed_read_allocation_once = FALSE;
  if (r == NULL)
    return WYRELOG_E_NOMEM;
#define TEXT_AT(column) ((const gchar *) sqlite3_column_text (stmt, (column)))
#define LEN_AT(column) ((gsize) sqlite3_column_bytes (stmt, (column)))
  const gchar *intention = TEXT_AT (0);
  const gchar *digest = TEXT_AT (1);
  const gchar *request = TEXT_AT (6);
  const gchar *credential = TEXT_AT (7);
  const gchar *principal = TEXT_AT (9);
  const gchar *tenant = TEXT_AT (10);
  const gchar *session_fp = TEXT_AT (12);
  const gchar *jti_fp = TEXT_AT (13);
  wyl_id_t parsed;
  gchar canonical[37];
  gboolean valid = LEN_AT (0) == 36 && memchr (intention, '\0', 36) == NULL
      && intention[14] == '7'
      && strchr ("89ab", intention[19]) != NULL
      && wyl_id_parse (intention, &parsed) == WYRELOG_E_OK
      && wyl_id_format (&parsed, canonical, sizeof canonical) == WYRELOG_E_OK
      && memcmp (intention, canonical, 36) == 0
      && service_exchange_hex_is_canonical (digest, LEN_AT (1))
      && column_text_exact (stmt, 3, "service.credential.exchange")
      && column_text_exact (stmt, 4, "allowed")
      && service_exchange_request_id_is_canonical (request, LEN_AT (6))
      && LEN_AT (7) == 31
      && wyl_service_credential_id_is_canonical (credential, LEN_AT (7))
      && LEN_AT (9) >= 5 && LEN_AT (9) <= 128
      && g_utf8_validate (principal, LEN_AT (9), NULL)
      && wyl_policy_service_subject_is_valid (principal, LEN_AT (9))
      && LEN_AT (10) >= 1 && LEN_AT (10) <= 128
      && memchr (tenant, '\0', LEN_AT (10)) == NULL
      && g_utf8_validate (tenant, LEN_AT (10), NULL)
      && service_exchange_hex_is_canonical (session_fp, LEN_AT (12))
      && service_exchange_hex_is_canonical (jti_fp, LEN_AT (13));
  guint64 generation = service_exchange_generation_from_be
      (sqlite3_column_blob (stmt, 8));
  if (!valid || generation == 0 || generation > G_MAXINT64) {
    wyl_service_exchange_intention_record_free (r);
    return WYRELOG_E_POLICY;
  }
  gchar tenant_copy[129];
  memcpy (tenant_copy, tenant, LEN_AT (10));
  tenant_copy[LEN_AT (10)] = '\0';
  if (!wyl_policy_store_tenant_id_is_valid (tenant_copy)) {
    wyl_service_exchange_intention_record_free (r);
    return WYRELOG_E_POLICY;
  }
  memcpy (r->material.intention_id, intention, 36);
  memcpy (r->material.request_id, request, 27);
  memcpy (r->credential_id, credential, 31);
  memcpy (r->material.payload_digest, digest, 64);
  memcpy (r->material.session_fingerprint, session_fp, 64);
  memcpy (r->material.jti_fingerprint, jti_fp, 64);
  r->credential_generation = generation;
  r->created_at_us = sqlite3_column_int64 (stmt, 5);
  r->service_principal = g_strndup (principal, LEN_AT (9));
  r->tenant_id = g_strndup (tenant, LEN_AT (10));
  r->material.canonical_payload = g_bytes_new (sqlite3_column_blob (stmt, 14),
      LEN_AT (14));
#undef TEXT_AT
#undef LEN_AT
  if (r->service_principal == NULL || r->tenant_id == NULL
      || r->material.canonical_payload == NULL) {
    wyl_service_exchange_intention_record_free (r);
    return WYRELOG_E_NOMEM;
  }
  if (!service_exchange_payload_matches (r)) {
    wyl_service_exchange_intention_record_free (r);
    return WYRELOG_E_POLICY;
  }
  *out_record = r;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
service_exchange_require_participant (WylServiceAuthorityTransaction *txn,
    wyl_policy_store_t *store)
{
  wyrelog_error_t rc = service_authority_transaction_validate_active (txn,
      store);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (txn->write_intent_state !=
      WYL_SERVICE_AUTHORITY_WRITE_INTENT_STATE_ACQUIRED)
    return WYRELOG_E_POLICY;
  return wyl_policy_store_service_authority_transaction_enter_participant
      (txn, store);
}

/* Typed recovery reads run inside the same authority transaction and WRITE
 * lease, but deliberately do not manufacture commit evidence or a SQLite
 * write intent.  The decoder remains the sole row-validation boundary. */
static wyrelog_error_t
service_exchange_require_read_participant (WylServiceAuthorityTransaction *txn,
    wyl_policy_store_t *store)
{
  return wyl_policy_store_service_authority_transaction_enter_participant
      (txn, store);
}

static gboolean
service_exchange_record_matches_input (const
    WylServiceExchangeIntentionRecord *record,
    const wyl_service_exchange_audit_input_t *input,
    const wyl_service_exchange_audit_material_t *material)
{
  gsize stored_len = 0, input_len = 0;
  const guint8 *stored = g_bytes_get_data (record->material.canonical_payload,
      &stored_len);
  const guint8 *encoded = g_bytes_get_data (material->canonical_payload,
      &input_len);
  return strcmp (record->material.intention_id, material->intention_id) == 0
      && strcmp (record->material.payload_digest, material->payload_digest) == 0
      && strcmp (record->material.request_id, material->request_id) == 0
      && strlen (record->credential_id) == input->credential_id.len
      && memcmp (record->credential_id, input->credential_id.data,
      input->credential_id.len) == 0
      && record->credential_generation == input->credential_generation
      && record->created_at_us == input->created_at_us
      && strlen (record->service_principal) == input->service_principal.len
      && memcmp (record->service_principal, input->service_principal.data,
      input->service_principal.len) == 0
      && strlen (record->tenant_id) == input->tenant_id.len
      && memcmp (record->tenant_id, input->tenant_id.data,
      input->tenant_id.len) == 0
      && strcmp (record->material.session_fingerprint,
      material->session_fingerprint) == 0
      && strcmp (record->material.jti_fingerprint,
      material->jti_fingerprint) == 0
      && stored_len == input_len && memcmp (stored, encoded, stored_len) == 0;
}

static WylServiceExchangeIntentionRecord *
service_exchange_record_new_from_input (const wyl_service_exchange_audit_input_t
    *input, const wyl_service_exchange_audit_material_t *material)
{
  WylServiceExchangeIntentionRecord *record = g_try_new0
      (WylServiceExchangeIntentionRecord, 1);
  if (record == NULL)
    return NULL;

  record->service_principal = g_try_malloc (input->service_principal.len + 1);
  record->tenant_id = g_try_malloc (input->tenant_id.len + 1);
  if (record->service_principal == NULL || record->tenant_id == NULL) {
    wyl_service_exchange_intention_record_free (record);
    return NULL;
  }
  memcpy (record->service_principal, input->service_principal.data,
      input->service_principal.len);
  record->service_principal[input->service_principal.len] = '\0';
  memcpy (record->tenant_id, input->tenant_id.data, input->tenant_id.len);
  record->tenant_id[input->tenant_id.len] = '\0';
  memcpy (record->material.intention_id, material->intention_id,
      sizeof record->material.intention_id);
  memcpy (record->material.request_id, material->request_id,
      sizeof record->material.request_id);
  memcpy (record->material.payload_digest, material->payload_digest,
      sizeof record->material.payload_digest);
  memcpy (record->material.session_fingerprint,
      material->session_fingerprint,
      sizeof record->material.session_fingerprint);
  memcpy (record->material.jti_fingerprint, material->jti_fingerprint,
      sizeof record->material.jti_fingerprint);
  memcpy (record->credential_id, input->credential_id.data,
      input->credential_id.len);
  record->material.canonical_payload = g_bytes_ref
      (material->canonical_payload);
  record->credential_generation = input->credential_generation;
  record->created_at_us = input->created_at_us;
  return record;
}

static gboolean
service_exchange_receipt_allocation_allowed (WylServiceAuthorityTransaction
    *txn)
{
  if (txn == NULL)
    return TRUE;
  txn->service_exchange_receipt_allocation_count++;
  if (txn->service_exchange_receipt_fail_allocation_at ==
      txn->service_exchange_receipt_allocation_count) {
    txn->service_exchange_receipt_fail_allocation_at = 0;
    return FALSE;
  }
  return TRUE;
}

static WylServiceExchangeIntentionRecord *
service_exchange_record_clone (WylServiceAuthorityTransaction *txn,
    const WylServiceExchangeIntentionRecord *source)
{
  WylServiceExchangeIntentionRecord *copy =
      service_exchange_receipt_allocation_allowed (txn) ?
      g_try_new0 (WylServiceExchangeIntentionRecord, 1) : NULL;
  if (copy == NULL)
    return NULL;
  copy->service_principal = service_exchange_receipt_allocation_allowed (txn) ?
      g_try_malloc (strlen (source->service_principal) + 1) : NULL;
  copy->tenant_id = service_exchange_receipt_allocation_allowed (txn) ?
      g_try_malloc (strlen (source->tenant_id) + 1) : NULL;
  if (copy->service_principal == NULL || copy->tenant_id == NULL) {
    wyl_service_exchange_intention_record_free (copy);
    return NULL;
  }
  strcpy (copy->service_principal, source->service_principal);
  strcpy (copy->tenant_id, source->tenant_id);
  copy->material = source->material;
  copy->material.canonical_payload = g_bytes_ref
      (source->material.canonical_payload);
  memcpy (copy->credential_id, source->credential_id,
      sizeof copy->credential_id);
  copy->credential_generation = source->credential_generation;
  copy->created_at_us = source->created_at_us;
  return copy;
}

WylServiceExchangeReceipt *
wyl_service_exchange_receipt_ref (WylServiceExchangeReceipt *receipt)
{
  if (receipt == NULL)
    return NULL;
  gint refs;
  do {
    refs = g_atomic_int_get (&receipt->refs);
    if (refs <= 0 || refs == G_MAXINT)
      return NULL;
  } while (!g_atomic_int_compare_and_exchange (&receipt->refs, refs, refs + 1));
  return receipt;
}

void
wyl_service_exchange_receipt_test_set_refcount_max (WylServiceExchangeReceipt
    *receipt)
{
  if (receipt != NULL && g_atomic_int_get (&receipt->refs) == 1)
    g_atomic_int_set (&receipt->refs, G_MAXINT);
}

void wyl_service_exchange_receipt_test_restore_refcount_one
    (WylServiceExchangeReceipt * receipt)
{
  if (receipt != NULL && g_atomic_int_get (&receipt->refs) == G_MAXINT)
    g_atomic_int_set (&receipt->refs, 1);
}

void
wyl_service_exchange_receipt_unref (WylServiceExchangeReceipt *receipt)
{
  if (receipt == NULL || !g_atomic_int_dec_and_test (&receipt->refs))
    return;
  wyl_service_exchange_intention_record_free (receipt->record);
  wyl_policy_store_service_authority_commit_evidence_unref (receipt->evidence);
  g_clear_object (&receipt->handle);
  sodium_memzero (receipt, sizeof *receipt);
  g_free (receipt);
}

static void
service_exchange_pending_clear (WylServiceAuthorityTransaction *txn)
{
  g_clear_pointer (&txn->service_exchange_pending,
      wyl_service_exchange_receipt_unref);
}

static wyrelog_error_t
service_exchange_pending_stage (WylServiceAuthorityTransaction *txn,
    WylServiceExchangeIntentionClassification classification,
    const WylServiceExchangeIntentionRecord *record)
{
  if (txn->service_exchange_pending != NULL)
    return WYRELOG_E_POLICY;
  guint64 generation = 0;
  wyrelog_error_t rc = wyl_handle_policy_store_capture_generation (txn->handle,
      txn->store, &generation);
  if (rc != WYRELOG_E_OK)
    return rc;
  WylServiceAuthorityCommitEvidence *evidence = NULL;
  if (!txn->fail_service_exchange_evidence_ref_once)
    evidence = wyl_policy_store_service_authority_commit_evidence_ref
        (txn->commit_evidence);
  txn->fail_service_exchange_evidence_ref_once = FALSE;
  if (evidence == NULL)
    return WYRELOG_E_INTERNAL;
  WylServiceExchangeReceipt *pending =
      service_exchange_receipt_allocation_allowed (txn) ?
      g_try_new0 (WylServiceExchangeReceipt, 1) : NULL;
  if (pending == NULL) {
    wyl_policy_store_service_authority_commit_evidence_unref (evidence);
    return WYRELOG_E_NOMEM;
  }
  pending->record = service_exchange_record_clone (txn, record);
  if (pending->record == NULL) {
    g_free (pending);
    wyl_policy_store_service_authority_commit_evidence_unref (evidence);
    return WYRELOG_E_NOMEM;
  }
  g_atomic_int_set (&pending->refs, 1);
  pending->handle = g_object_ref (txn->handle);
  pending->evidence = evidence;
  pending->classification = classification;
  pending->transaction_serial = txn->serial;
  pending->store_generation = generation;
  txn->service_exchange_pending = pending;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_service_exchange_receipt_dup_record (const WylServiceExchangeReceipt *r,
    WylServiceExchangeIntentionRecord **out_record)
{
  if (out_record != NULL)
    *out_record = NULL;
  if (r == NULL || out_record == NULL)
    return WYRELOG_E_INVALID;
  *out_record = service_exchange_record_clone (NULL, r->record);
  return *out_record != NULL ? WYRELOG_E_OK : WYRELOG_E_NOMEM;
}

WylServiceExchangeIntentionClassification
wyl_service_exchange_receipt_get_classification (const WylServiceExchangeReceipt
    *r)
{
  return r != NULL ? r->classification : WYL_SERVICE_EXCHANGE_INTENTION_NONE;
}

wyrelog_error_t
wyl_service_exchange_receipt_validate_handle (const WylServiceExchangeReceipt
    *receipt, WylHandle *handle, wyl_policy_store_t *store)
{
  if (receipt == NULL || handle == NULL || store == NULL
      || receipt->handle != handle)
    return WYRELOG_E_INVALID;
  return wyl_handle_policy_store_validate_generation (handle, store,
      receipt->store_generation);
}

wyrelog_error_t
    wyl_service_exchange_receipt_validate_for_active_write
    (const WylServiceExchangeReceipt * receipt,
    WylServiceAuthWriteLease * write_lease, WylHandle * handle,
    wyl_policy_store_t * store)
{
  if (receipt == NULL || write_lease == NULL || !WYL_IS_HANDLE (handle)
      || store == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_policy_store_service_authority_transaction_is_active (store))
    return WYRELOG_E_BUSY;
  wyrelog_error_t rc = wyl_service_exchange_receipt_validate_handle (receipt,
      handle, store);
  if (rc != WYRELOG_E_OK)
    return rc;
  return
      wyl_policy_store_service_authority_commit_evidence_validate_for_active_write
      (receipt->evidence, write_lease, handle, store,
      receipt->transaction_serial);
}

wyrelog_error_t
    wyl_service_exchange_receipt_snapshot_for_active_write
    (const WylServiceExchangeReceipt * receipt,
    WylServiceAuthWriteLease * write_lease, WylHandle * handle,
    wyl_policy_store_t * store, WylServiceExchangeReceiptIdentity * out)
{
  if (out != NULL)
    memset (out, 0, sizeof *out);
  if (out == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = wyl_service_exchange_receipt_validate_for_active_write
      (receipt, write_lease, handle, store);
  guint64 lease_serial = 0;
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_auth_write_lease_get_serial (write_lease, handle,
        &lease_serial);
  if (rc == WYRELOG_E_OK) {
    out->classification = receipt->classification;
    out->transaction_serial = receipt->transaction_serial;
    out->store_generation = receipt->store_generation;
    out->write_lease_serial = lease_serial;
  }
  return rc;
}

wyrelog_error_t
wyl_policy_store_service_exchange_receipt_take (WylServiceAuthorityTransaction
    *txn, WylServiceAuthorityCommitEvidence *evidence, WylHandle *handle,
    wyl_policy_store_t *store, WylServiceExchangeReceipt **out_receipt)
{
  if (out_receipt != NULL)
    *out_receipt = NULL;
  if (out_receipt == NULL || txn == NULL || evidence == NULL || handle == NULL
      || store == NULL || txn->owner != g_thread_self ()
      || txn->state != WYL_SERVICE_AUTHORITY_TXN_COMMITTED
      || txn->primary_result != WYRELOG_E_OK
      || txn->cleanup_result != WYRELOG_E_OK
      || txn->commit_evidence != evidence || txn->handle != handle
      || txn->store != store || txn->service_exchange_pending == NULL)
    return WYRELOG_E_INVALID;
  WylServiceExchangeReceipt *pending = txn->service_exchange_pending;
  if (pending->evidence != evidence || pending->handle != handle
      || pending->transaction_serial != txn->serial
      || wyl_handle_policy_store_validate_generation (handle, store,
          pending->store_generation) != WYRELOG_E_OK
      ||
      wyl_policy_store_service_authority_commit_evidence_validate_committed_diagnostic
      (evidence, handle, store) != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  txn->service_exchange_pending = NULL;
  *out_receipt = pending;
  return WYRELOG_E_OK;
}

void wyl_policy_store_service_exchange_receipt_fail_allocation
    (WylServiceAuthorityTransaction * txn, guint allocation_index)
{
  if (txn != NULL) {
    txn->service_exchange_receipt_allocation_count = 0;
    txn->service_exchange_receipt_fail_allocation_at = allocation_index;
  }
}

guint
wyl_policy_store_service_exchange_receipt_get_allocation_count (const
    WylServiceAuthorityTransaction *txn)
{
  return txn != NULL ? txn->service_exchange_receipt_allocation_count : 0;
}

void wyl_policy_store_service_exchange_receipt_fail_evidence_ref_once
    (WylServiceAuthorityTransaction * txn)
{
  if (txn != NULL)
    txn->fail_service_exchange_evidence_ref_once = TRUE;
}

/* Validate the authoritative row into storage allocated before INSERT.  Every
 * value is consumed from SQLite; equality permits retaining the preallocated
 * GBytes only after the row bytes themselves have been verified exactly. */
static wyrelog_error_t
service_exchange_decode_created_row (sqlite3_stmt *stmt,
    WylServiceExchangeIntentionRecord *record)
{
  gsize payload_len = 0;
  const guint8 *payload = g_bytes_get_data (record->material.canonical_payload,
      &payload_len);
  guint8 generation[8];
  service_exchange_generation_to_be (record->credential_generation, generation);
#define ROW_TEXT_EQ(c,v,n) (sqlite3_column_type (stmt, (c)) == SQLITE_TEXT \
    && sqlite3_column_bytes (stmt, (c)) == (int) (n) \
    && memcmp (sqlite3_column_text (stmt, (c)), (v), (n)) == 0)
  gboolean valid = ROW_TEXT_EQ (0, record->material.intention_id, 36)
      && ROW_TEXT_EQ (1, record->material.payload_digest, 64)
      && sqlite3_column_type (stmt, 2) == SQLITE_INTEGER
      && sqlite3_column_int64 (stmt, 2) == 1
      && ROW_TEXT_EQ (3, "service.credential.exchange", 27)
      && ROW_TEXT_EQ (4, "allowed", 7)
      && sqlite3_column_type (stmt, 5) == SQLITE_INTEGER
      && sqlite3_column_int64 (stmt, 5) == record->created_at_us
      && ROW_TEXT_EQ (6, record->material.request_id, 27)
      && ROW_TEXT_EQ (7, record->credential_id, 31)
      && sqlite3_column_type (stmt, 8) == SQLITE_BLOB
      && sqlite3_column_bytes (stmt, 8) == 8
      && memcmp (sqlite3_column_blob (stmt, 8), generation, 8) == 0
      && ROW_TEXT_EQ (9, record->service_principal,
      strlen (record->service_principal))
      && ROW_TEXT_EQ (10, record->tenant_id, strlen (record->tenant_id))
      && sqlite3_column_type (stmt, 11) == SQLITE_INTEGER
      && sqlite3_column_int64 (stmt, 11) == 1
      && ROW_TEXT_EQ (12, record->material.session_fingerprint, 64)
      && ROW_TEXT_EQ (13, record->material.jti_fingerprint, 64)
      && sqlite3_column_type (stmt, 14) == SQLITE_BLOB
      && sqlite3_column_bytes (stmt, 14) == (int) payload_len
      && memcmp (sqlite3_column_blob (stmt, 14), payload, payload_len) == 0
      && service_exchange_payload_matches (record);
#undef ROW_TEXT_EQ
  return valid ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
service_exchange_select_one (WylServiceAuthorityTransaction *txn,
    wyl_policy_store_t *store, const gchar *sql,
    const gchar *first, const gchar *second,
    WylServiceExchangeIntentionRecord **out_record, gboolean *out_found)
{
  *out_record = NULL;
  *out_found = FALSE;
  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = txn != NULL
      && txn->fail_service_exchange_typed_read_prepare_once ? WYRELOG_E_IO :
      prepare_stmt (store->db, sql, &stmt);
  if (txn != NULL)
    txn->fail_service_exchange_typed_read_prepare_once = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 1, first);
  if (rc == WYRELOG_E_OK && second != NULL)
    rc = bind_text (stmt, 2, second);
  int step = rc == WYRELOG_E_OK && txn != NULL
      && txn->fail_service_exchange_typed_read_step_once ? SQLITE_IOERR :
      rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_ERROR;
  if (txn != NULL)
    txn->fail_service_exchange_typed_read_step_once = FALSE;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW) {
    rc = service_exchange_record_from_row (txn, stmt, out_record);
    *out_found = rc == WYRELOG_E_OK;
    if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
      rc = WYRELOG_E_POLICY;
  } else if (rc == WYRELOG_E_OK && step != SQLITE_DONE) {
    rc = WYRELOG_E_IO;
  }
  sqlite3_finalize (stmt);
  if (rc != WYRELOG_E_OK)
    g_clear_pointer (out_record, wyl_service_exchange_intention_record_free);
  return rc;
}

wyrelog_error_t
    wyl_policy_store_service_exchange_intention_append
    (WylServiceAuthorityTransaction * txn, wyl_policy_store_t * store,
    const wyl_service_exchange_audit_input_t * input,
    WylServiceExchangeIntentionClassification * out_classification,
    WylServiceExchangeIntentionRecord ** out_record)
{
  if (out_classification != NULL)
    *out_classification = WYL_SERVICE_EXCHANGE_INTENTION_NONE;
  if (out_record != NULL)
    *out_record = NULL;
  if (out_classification == NULL || out_record == NULL)
    return WYRELOG_E_INVALID;
  wyl_service_exchange_audit_material_t material =
      WYL_SERVICE_EXCHANGE_AUDIT_MATERIAL_INIT;
  wyrelog_error_t rc = wyl_service_exchange_audit_encode (input, &material);
  if (rc != WYRELOG_E_OK)
    return rc;
  WylServiceExchangeIntentionRecord *prepared =
      txn != NULL && txn->fail_service_exchange_preallocation_once ? NULL :
      service_exchange_record_new_from_input (input, &material);
  if (txn != NULL)
    txn->fail_service_exchange_preallocation_once = FALSE;
  if (prepared == NULL) {
    wyl_service_exchange_audit_material_clear (&material);
    return WYRELOG_E_NOMEM;
  }
  rc = service_exchange_require_participant (txn, store);
  if (rc != WYRELOG_E_OK) {
    wyl_service_exchange_intention_record_free (prepared);
    wyl_service_exchange_audit_material_clear (&material);
    return rc;
  }
  rc = wyl_policy_store_validate_service_schema (store);
  if (rc != WYRELOG_E_OK) {
    wyl_service_exchange_intention_record_free (prepared);
    wyl_service_exchange_audit_material_clear (&material);
    return rc;
  }

  WylServiceExchangeIntentionRecord *existing = NULL;
  gboolean found = FALSE;
  rc = service_exchange_select_one (txn, store,
      "SELECT " SERVICE_EXCHANGE_SELECT_COLUMNS
      " FROM main.service_exchange_audit_intentions"
      " WHERE intention_id=? OR payload_digest=?;",
      material.intention_id, material.payload_digest, &existing, &found);
  if (rc != WYRELOG_E_OK) {
    wyl_service_exchange_intention_record_free (prepared);
    wyl_service_exchange_audit_material_clear (&material);
    return rc;
  }
  if (found) {
    gboolean matches = service_exchange_record_matches_input (existing, input,
        &material);
    wyl_service_exchange_intention_record_free (prepared);
    wyl_service_exchange_audit_material_clear (&material);
    if (!matches) {
      wyl_service_exchange_intention_record_free (existing);
      return WYRELOG_E_POLICY;
    }
    rc = service_exchange_pending_stage (txn,
        WYL_SERVICE_EXCHANGE_INTENTION_REPLAY, existing);
    if (rc != WYRELOG_E_OK) {
      wyl_service_exchange_intention_record_free (existing);
      return rc;
    }
    *out_classification = WYL_SERVICE_EXCHANGE_INTENTION_REPLAY;
    *out_record = existing;
    return WYRELOG_E_OK;
  }

  guint8 generation[8];
  service_exchange_generation_to_be (input->credential_generation, generation);
  gsize payload_len = 0;
  const guint8 *payload = g_bytes_get_data (material.canonical_payload,
      &payload_len);
  rc = service_exchange_pending_stage (txn,
      WYL_SERVICE_EXCHANGE_INTENTION_CREATED, prepared);
  if (rc != WYRELOG_E_OK) {
    wyl_service_exchange_intention_record_free (prepared);
    wyl_service_exchange_audit_material_clear (&material);
    return rc;
  }
  sqlite3_stmt *stmt = NULL;
  rc = prepare_stmt (store->db,
      "INSERT INTO main.service_exchange_audit_intentions("
      "intention_id,payload_digest,payload_schema_version,event_type,outcome,"
      "created_at_us,request_id,credential_id,credential_generation,"
      "service_principal,tenant_id,fingerprint_schema_version,"
      "session_fingerprint,jti_fingerprint,canonical_payload) VALUES"
      "(?,?,1,'service.credential.exchange','allowed',?,?,?,?,?,?,1,?,?,?);",
      &stmt);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 1, material.intention_id);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 2, material.payload_digest);
  if (rc == WYRELOG_E_OK && sqlite3_bind_int64 (stmt, 3,
          input->created_at_us) != SQLITE_OK)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 4, material.request_id);
  if (rc == WYRELOG_E_OK && sqlite3_bind_text (stmt, 5,
          input->credential_id.data, input->credential_id.len,
          SQLITE_TRANSIENT) != SQLITE_OK)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && sqlite3_bind_blob (stmt, 6, generation, 8,
          SQLITE_TRANSIENT) != SQLITE_OK)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && sqlite3_bind_text (stmt, 7,
          input->service_principal.data, input->service_principal.len,
          SQLITE_TRANSIENT) != SQLITE_OK)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && sqlite3_bind_text (stmt, 8,
          input->tenant_id.data, input->tenant_id.len,
          SQLITE_TRANSIENT) != SQLITE_OK)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 9, material.session_fingerprint);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 10, material.jti_fingerprint);
  if (rc == WYRELOG_E_OK && sqlite3_bind_blob (stmt, 11, payload, payload_len,
          SQLITE_TRANSIENT) != SQLITE_OK)
    rc = WYRELOG_E_IO;
  sqlite3_stmt *readback = NULL;
  if (rc == WYRELOG_E_OK)
    rc = prepare_stmt (store->db,
        "SELECT " SERVICE_EXCHANGE_SELECT_COLUMNS
        " FROM main.service_exchange_audit_intentions"
        " WHERE intention_id=? AND payload_digest=?;", &readback);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (readback, 1, material.intention_id);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (readback, 2, material.payload_digest);
  gboolean insert_attempted = rc == WYRELOG_E_OK;
  if (insert_attempted)
    rc = sqlite3_step (stmt) == SQLITE_DONE ? WYRELOG_E_OK : WYRELOG_E_IO;
  sqlite3_finalize (stmt);
  if (rc != WYRELOG_E_OK) {
    service_exchange_pending_clear (txn);
    sqlite3_finalize (readback);
    if (insert_attempted)
      service_authority_transaction_fail_participant (txn, rc);
    wyl_service_exchange_intention_record_free (prepared);
    wyl_service_exchange_audit_material_clear (&material);
    return rc;
  }
  if (txn->fail_service_exchange_readback_once) {
    txn->fail_service_exchange_readback_once = FALSE;
    sqlite3_finalize (readback);
    service_authority_transaction_fail_participant (txn, WYRELOG_E_IO);
    service_exchange_pending_clear (txn);
    wyl_service_exchange_intention_record_free (prepared);
    wyl_service_exchange_audit_material_clear (&material);
    return WYRELOG_E_IO;
  }
  int read_step = sqlite3_step (readback);
  if (read_step != SQLITE_ROW)
    rc = read_step == SQLITE_DONE ? WYRELOG_E_POLICY : WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = service_exchange_decode_created_row (readback, prepared);
  if (rc == WYRELOG_E_OK && sqlite3_step (readback) != SQLITE_DONE)
    rc = WYRELOG_E_POLICY;
  sqlite3_finalize (readback);
  if (rc == WYRELOG_E_OK) {
    *out_classification = WYL_SERVICE_EXCHANGE_INTENTION_CREATED;
    *out_record = prepared;
    prepared = NULL;
  } else {
    service_authority_transaction_fail_participant (txn, rc);
    service_exchange_pending_clear (txn);
  }
  wyl_service_exchange_audit_material_clear (&material);
  wyl_service_exchange_intention_record_free (prepared);
  if (rc != WYRELOG_E_OK)
    g_clear_pointer (out_record, wyl_service_exchange_intention_record_free);
  return rc;
}

void wyl_policy_store_service_exchange_intention_fail_preallocation_once
    (WylServiceAuthorityTransaction * txn)
{
  if (txn != NULL)
    txn->fail_service_exchange_preallocation_once = TRUE;
}

void wyl_policy_store_service_exchange_intention_fail_readback_once
    (WylServiceAuthorityTransaction * txn)
{
  if (txn != NULL)
    txn->fail_service_exchange_readback_once = TRUE;
}

void wyl_policy_store_service_exchange_intention_fail_typed_read_prepare_once
    (WylServiceAuthorityTransaction * txn)
{
  if (txn != NULL)
    txn->fail_service_exchange_typed_read_prepare_once = TRUE;
}

void wyl_policy_store_service_exchange_intention_fail_typed_read_step_once
    (WylServiceAuthorityTransaction * txn)
{
  if (txn != NULL)
    txn->fail_service_exchange_typed_read_step_once = TRUE;
}

void wyl_policy_store_service_exchange_intention_fail_typed_read_allocation_once
    (WylServiceAuthorityTransaction * txn)
{
  if (txn != NULL)
    txn->fail_service_exchange_typed_read_allocation_once = TRUE;
}

void wyl_policy_store_service_exchange_intention_typed_read_state_for_test
    (const WylServiceAuthorityTransaction * txn, gboolean * out_has_evidence,
    gboolean * out_has_write_intent)
{
  if (out_has_evidence != NULL)
    *out_has_evidence = txn != NULL && txn->commit_evidence != NULL;
  if (out_has_write_intent != NULL)
    *out_has_write_intent = txn != NULL
        && txn->write_intent_state ==
        WYL_SERVICE_AUTHORITY_WRITE_INTENT_STATE_ACQUIRED;
}

wyrelog_error_t
    wyl_policy_store_service_exchange_intention_load
    (WylServiceAuthorityTransaction * txn, wyl_policy_store_t * store,
    const wyl_id_t * intention_id, const gchar * payload_digest,
    WylServiceExchangeIntentionRecord ** out_record)
{
  if (out_record != NULL)
    *out_record = NULL;
  if (out_record == NULL || intention_id == NULL || payload_digest == NULL
      || !service_exchange_hex_is_canonical (payload_digest,
          strlen (payload_digest)))
    return WYRELOG_E_INVALID;
  gchar encoded[37];
  wyl_id_t parsed;
  if (wyl_id_equal (intention_id, &WYL_ID_NIL)
      || wyl_id_format (intention_id, encoded, sizeof encoded) != WYRELOG_E_OK
      || wyl_id_parse (encoded, &parsed) != WYRELOG_E_OK
      || !wyl_id_equal (intention_id, &parsed))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = service_exchange_require_read_participant (txn, store);
  if (rc != WYRELOG_E_OK)
    return rc;
  gboolean found = FALSE;
  rc = service_exchange_select_one (txn, store,
      "SELECT " SERVICE_EXCHANGE_SELECT_COLUMNS
      " FROM main.service_exchange_audit_intentions"
      " WHERE intention_id=? OR payload_digest=?;", encoded, payload_digest,
      out_record, &found);
  if (rc == WYRELOG_E_OK && found
      && (strcmp ((*out_record)->material.intention_id, encoded) != 0
          || strcmp ((*out_record)->material.payload_digest,
              payload_digest) != 0)) {
    g_clear_pointer (out_record, wyl_service_exchange_intention_record_free);
    return WYRELOG_E_POLICY;
  }
  return rc != WYRELOG_E_OK ? rc : found ? WYRELOG_E_OK : WYRELOG_E_NOT_FOUND;
}

wyrelog_error_t
    wyl_policy_store_service_exchange_intention_enumerate
    (WylServiceAuthorityTransaction * txn, wyl_policy_store_t * store,
    GPtrArray ** out_records) {
  if (out_records != NULL)
    *out_records = NULL;
  if (out_records == NULL)
    return WYRELOG_E_INVALID;
  GPtrArray *records = g_ptr_array_new_with_free_func
      ((GDestroyNotify) wyl_service_exchange_intention_record_free);
  if (records == NULL)
    return WYRELOG_E_NOMEM;
  wyrelog_error_t rc = service_exchange_require_read_participant (txn, store);
  sqlite3_stmt *stmt = NULL;
  if (rc == WYRELOG_E_OK && txn->fail_service_exchange_typed_read_prepare_once) {
    txn->fail_service_exchange_typed_read_prepare_once = FALSE;
    rc = WYRELOG_E_IO;
  }
  if (rc == WYRELOG_E_OK)
    rc = prepare_stmt (store->db,
        "SELECT " SERVICE_EXCHANGE_SELECT_COLUMNS
        " FROM main.service_exchange_audit_intentions"
        " ORDER BY created_at_us,intention_id;", &stmt);
  int step = SQLITE_ERROR;
  while (rc == WYRELOG_E_OK
      && (step = txn->fail_service_exchange_typed_read_step_once
          ? (txn->fail_service_exchange_typed_read_step_once = FALSE,
              SQLITE_IOERR) : sqlite3_step (stmt)) == SQLITE_ROW) {
    WylServiceExchangeIntentionRecord *record = NULL;
    rc = service_exchange_record_from_row (txn, stmt, &record);
    if (rc == WYRELOG_E_OK)
      g_ptr_array_add (records, record);
  }
  if (rc == WYRELOG_E_OK && step != SQLITE_DONE)
    rc = WYRELOG_E_IO;
  sqlite3_finalize (stmt);
  if (rc != WYRELOG_E_OK) {
    g_ptr_array_unref (records);
    return rc;
  }
  *out_records = records;
  return WYRELOG_E_OK;
}

#undef SERVICE_EXCHANGE_SELECT_COLUMNS

gboolean
    wyl_policy_store_service_authority_commit_evidence_test_ref_overflow_rejected
    (WylServiceAuthorityCommitEvidence * evidence) {
  if (evidence == NULL || g_atomic_int_get (&evidence->refs) != 1)
    return FALSE;
  g_atomic_int_set (&evidence->refs, G_MAXINT);
  gboolean rejected =
      wyl_policy_store_service_authority_commit_evidence_ref (evidence) == NULL;
  g_atomic_int_set (&evidence->refs, 1);
  return rejected;
}

void wyl_policy_store_service_authority_transaction_fail_last_used_sql_once
    (WylServiceAuthorityTransaction * txn)
{
  if (txn != NULL)
    txn->fail_last_used_sql_once = TRUE;
}

void wyl_policy_store_service_authority_transaction_test_arm_intent_barrier
    (WylServiceAuthorityTransaction * txn)
{
  if (txn == NULL || txn->owner != g_thread_self ()
      || txn->state != WYL_SERVICE_AUTHORITY_TXN_ACTIVE)
    return;
  g_mutex_lock (&txn->write_intent_barrier_mutex);
  txn->write_intent_barrier_armed = TRUE;
  txn->write_intent_barrier_reached = FALSE;
  txn->write_intent_barrier_released = FALSE;
  g_mutex_unlock (&txn->write_intent_barrier_mutex);
}

void wyl_policy_store_service_authority_transaction_test_wait_intent_barrier
    (WylServiceAuthorityTransaction * txn)
{
  if (txn == NULL)
    return;
  g_mutex_lock (&txn->write_intent_barrier_mutex);
  while (txn->write_intent_barrier_armed && !txn->write_intent_barrier_reached)
    g_cond_wait (&txn->write_intent_barrier_cond,
        &txn->write_intent_barrier_mutex);
  g_mutex_unlock (&txn->write_intent_barrier_mutex);
}

void wyl_policy_store_service_authority_transaction_test_release_intent_barrier
    (WylServiceAuthorityTransaction * txn)
{
  if (txn == NULL)
    return;
  g_mutex_lock (&txn->write_intent_barrier_mutex);
  txn->write_intent_barrier_released = TRUE;
  g_cond_broadcast (&txn->write_intent_barrier_cond);
  g_mutex_unlock (&txn->write_intent_barrier_mutex);
}

void wyl_policy_store_service_authority_transaction_test_fail_intent_once
    (WylServiceAuthorityTransaction * txn, int sqlite_extended_code)
{
  if (txn == NULL || (sqlite_extended_code != SQLITE_LOCKED
          && sqlite_extended_code != SQLITE_IOERR))
    return;
  txn->write_intent_fail_sql_once = sqlite_extended_code;
}

void wyl_policy_store_service_lifecycle_fail_commit_once
    (wyl_policy_store_t * store)
{
  if (store == NULL)
    return;
  g_mutex_lock (&store->service_lifecycle_mutex);
  store->service_lifecycle_fail_commit_once = TRUE;
  g_mutex_unlock (&store->service_lifecycle_mutex);
}

void
wyl_policy_store_service_rotate_fail_once (wyl_policy_store_t *store,
    wyl_policy_service_rotate_fail_stage_t stage)
{
  if (store == NULL)
    return;
  g_mutex_lock (&store->service_lifecycle_mutex);
  store->service_rotate_fail_once = stage;
  g_mutex_unlock (&store->service_lifecycle_mutex);
}

static wyrelog_error_t
service_principal_create_impl (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *display_name,
    const gchar *actor_subject_id, const gchar *request_id,
    wyl_policy_service_principal_info_t *out, gboolean authority_owned)
{
  if (out != NULL)
    wyl_policy_service_principal_info_clear (out);
  if (store == NULL || store->db == NULL || out == NULL || subject_id == NULL
      || !wyl_policy_service_subject_is_valid (subject_id, strlen (subject_id))
      || !service_domain_text_is_valid (display_name, 256)
      || !wyl_policy_service_actor_subject_is_valid (actor_subject_id)
      || !service_domain_text_is_valid (request_id, 256))
    return WYRELOG_E_INVALID;

  guint8 fingerprint[crypto_generichash_BYTES];
  wyrelog_error_t rc = service_domain_fingerprint ("principal_create",
      subject_id, display_name, actor_subject_id, fingerprint);
  gchar audit_id[WYL_ID_STRING_BUF];
  if (rc == WYRELOG_E_OK)
    rc = service_domain_new_audit_id (audit_id);
  if (rc != WYRELOG_E_OK) {
    sodium_memzero (fingerprint, sizeof fingerprint);
    return rc;
  }

  gint64 now_us = g_get_real_time ();
  if (!authority_owned) {
    rc = service_mutation_scope_enter (store);
    if (rc != WYRELOG_E_OK) {
      sodium_memzero (fingerprint, sizeof fingerprint);
      return rc;
    }
    g_mutex_lock (&store->service_domain_gate_mutex);
    g_mutex_lock (&store->service_lifecycle_mutex);
  }
  rc = authority_owned ? WYRELOG_E_OK : wyl_policy_store_begin_mutation (store);
  if (rc == WYRELOG_E_OK)
    rc = service_domain_claim_request (store, request_id, "principal_create",
        subject_id, fingerprint, now_us);
  sodium_memzero (fingerprint, sizeof fingerprint);

  gboolean collision = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = service_domain_has_legacy_collision (store, subject_id, &collision);
  if (rc == WYRELOG_E_OK && collision)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK) {
    sqlite3_stmt *stmt = NULL;
    rc = prepare_stmt (store->db,
        "INSERT INTO service_principals "
        "(subject_id,display_name,state,generation,created_by,created_at_us,"
        "updated_at_us) VALUES(?,?,'active',1,?,?,?);", &stmt);
    if (rc == WYRELOG_E_OK
        && ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
            || (rc = bind_text (stmt, 2, display_name)) != WYRELOG_E_OK
            || (rc = bind_text (stmt, 3, actor_subject_id)) != WYRELOG_E_OK
            || sqlite3_bind_int64 (stmt, 4, now_us) != SQLITE_OK
            || sqlite3_bind_int64 (stmt, 5, now_us) != SQLITE_OK))
      rc = WYRELOG_E_IO;
    if (rc == WYRELOG_E_OK) {
      int step_rc = sqlite3_step (stmt);
      if (step_rc != SQLITE_DONE)
        rc = (step_rc & 0xff) == SQLITE_CONSTRAINT ? WYRELOG_E_POLICY :
            WYRELOG_E_IO;
    }
    sqlite3_finalize (stmt);
  }
  if (rc == WYRELOG_E_OK)
    rc = service_domain_append_principal_event (store, subject_id, "created",
        NULL, "active", 1, actor_subject_id, request_id, now_us);
  if (rc == WYRELOG_E_OK)
    rc = service_domain_append_audit (store, audit_id, now_us,
        actor_subject_id, "service.principal.create", subject_id, request_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_lookup_service_principal (store, subject_id, out);
  if (rc == WYRELOG_E_OK)
    rc = authority_owned ? service_domain_validate_mutation (store) :
        service_domain_finish_mutation (store);
  else if (!authority_owned)
    wyl_policy_store_rollback_mutation (store);
  if (!authority_owned) {
    g_mutex_unlock (&store->service_lifecycle_mutex);
    g_mutex_unlock (&store->service_domain_gate_mutex);
    service_mutation_scope_leave (store);
  }
  if (rc != WYRELOG_E_OK)
    wyl_policy_service_principal_info_clear (out);
  return rc;
}

wyrelog_error_t
wyl_policy_store_create_service_principal (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *display_name,
    const gchar *actor_subject_id, const gchar *request_id,
    wyl_policy_service_principal_info_t *out)
{
  return service_principal_create_impl (store, subject_id, display_name,
      actor_subject_id, request_id, out, FALSE);
}

wyrelog_error_t
    wyl_policy_store_create_service_principal_core
    (WylServiceAuthorityTransaction * txn, wyl_policy_store_t * store,
    const gchar * subject_id, const gchar * display_name,
    const gchar * actor_subject_id, const gchar * request_id,
    wyl_policy_service_principal_info_t * out)
{
  if (out != NULL)
    wyl_policy_service_principal_info_clear (out);
  wyrelog_error_t rc =
      wyl_policy_store_service_authority_transaction_enter_participant (txn,
      store);
  return rc == WYRELOG_E_OK ? service_principal_create_impl (store,
      subject_id, display_name, actor_subject_id, request_id, out, TRUE) : rc;
}

static wyrelog_error_t
service_principal_disable_impl (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *actor_subject_id,
    const gchar *request_id, wyl_policy_service_principal_info_t *out,
    gboolean authority_owned)
{
  if (out != NULL)
    wyl_policy_service_principal_info_clear (out);
  if (store == NULL || store->db == NULL || out == NULL || subject_id == NULL
      || !wyl_policy_service_subject_is_valid (subject_id, strlen (subject_id))
      || !wyl_policy_service_actor_subject_is_valid (actor_subject_id)
      || !service_domain_text_is_valid (request_id, 256))
    return WYRELOG_E_INVALID;

  guint8 fingerprint[crypto_generichash_BYTES];
  wyrelog_error_t rc = service_domain_fingerprint ("principal_disable",
      subject_id, NULL, actor_subject_id, fingerprint);
  gchar audit_id[WYL_ID_STRING_BUF];
  if (rc == WYRELOG_E_OK)
    rc = service_domain_new_audit_id (audit_id);
  if (rc != WYRELOG_E_OK) {
    sodium_memzero (fingerprint, sizeof fingerprint);
    return rc;
  }

  gint64 now_us = g_get_real_time ();
  if (!authority_owned) {
    rc = service_mutation_scope_enter (store);
    if (rc != WYRELOG_E_OK) {
      sodium_memzero (fingerprint, sizeof fingerprint);
      return rc;
    }
    g_mutex_lock (&store->service_domain_gate_mutex);
    g_mutex_lock (&store->service_lifecycle_mutex);
  }
  rc = authority_owned ? WYRELOG_E_OK : wyl_policy_store_begin_mutation (store);
  if (rc == WYRELOG_E_OK)
    rc = service_domain_claim_request (store, request_id, "principal_disable",
        subject_id, fingerprint, now_us);
  sodium_memzero (fingerprint, sizeof fingerprint);

  wyl_policy_service_principal_info_t current = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_lookup_service_principal (store, subject_id,
        &current);
  if (rc == WYRELOG_E_OK && g_str_equal (current.state, "active")) {
    if (current.generation >= G_MAXINT64) {
      rc = WYRELOG_E_POLICY;
    } else {
      sqlite3_stmt *stmt = NULL;
      rc = prepare_stmt (store->db,
          "UPDATE service_principals SET state='disabled',generation=?,"
          "updated_at_us=?,disabled_by=?,disabled_at_us=? "
          "WHERE subject_id=? AND state='active';", &stmt);
      if (rc == WYRELOG_E_OK
          && (sqlite3_bind_int64 (stmt, 1,
                  (sqlite3_int64) current.generation + 1) != SQLITE_OK
              || sqlite3_bind_int64 (stmt, 2, now_us) != SQLITE_OK
              || (rc = bind_text (stmt, 3, actor_subject_id)) != WYRELOG_E_OK
              || sqlite3_bind_int64 (stmt, 4, now_us) != SQLITE_OK
              || (rc = bind_text (stmt, 5, subject_id)) != WYRELOG_E_OK))
        rc = WYRELOG_E_IO;
      if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
        rc = WYRELOG_E_IO;
      if (rc == WYRELOG_E_OK && sqlite3_changes (store->db) != 1)
        rc = WYRELOG_E_POLICY;
      sqlite3_finalize (stmt);
      if (rc == WYRELOG_E_OK)
        rc = service_domain_append_principal_event (store, subject_id,
            "disabled", "active", "disabled", current.generation + 1,
            actor_subject_id, request_id, now_us);
    }
  } else if (rc == WYRELOG_E_OK && !g_str_equal (current.state, "disabled")) {
    rc = WYRELOG_E_POLICY;
  }
  wyl_policy_service_principal_info_clear (&current);

  if (rc == WYRELOG_E_OK)
    rc = service_domain_append_audit (store, audit_id, now_us,
        actor_subject_id, "service.principal.disable", subject_id, request_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_lookup_service_principal (store, subject_id, out);
  if (rc == WYRELOG_E_OK)
    rc = authority_owned ? service_domain_validate_mutation (store) :
        service_domain_finish_mutation (store);
  else if (!authority_owned)
    wyl_policy_store_rollback_mutation (store);
  if (!authority_owned) {
    g_mutex_unlock (&store->service_lifecycle_mutex);
    g_mutex_unlock (&store->service_domain_gate_mutex);
    service_mutation_scope_leave (store);
  }
  if (rc != WYRELOG_E_OK)
    wyl_policy_service_principal_info_clear (out);
  return rc;
}

wyrelog_error_t
wyl_policy_store_disable_service_principal (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *actor_subject_id,
    const gchar *request_id, wyl_policy_service_principal_info_t *out)
{
  return service_principal_disable_impl (store, subject_id, actor_subject_id,
      request_id, out, FALSE);
}

wyrelog_error_t
    wyl_policy_store_disable_service_principal_core
    (WylServiceAuthorityTransaction * txn, wyl_policy_store_t * store,
    const gchar * subject_id, const gchar * actor_subject_id,
    const gchar * request_id, wyl_policy_service_principal_info_t * out)
{
  if (out != NULL)
    wyl_policy_service_principal_info_clear (out);
  wyrelog_error_t rc =
      wyl_policy_store_service_authority_transaction_enter_participant (txn,
      store);
  return rc == WYRELOG_E_OK ? service_principal_disable_impl (store,
      subject_id, actor_subject_id, request_id, out, TRUE) : rc;
}

wyrelog_error_t
wyl_policy_store_lookup_service_principal (wyl_policy_store_t *store,
    const gchar *subject_id, wyl_policy_service_principal_info_t *out)
{
  if (out != NULL)
    wyl_policy_service_principal_info_clear (out);
  if (store == NULL || store->db == NULL || out == NULL || subject_id == NULL
      || !wyl_policy_service_subject_is_valid (subject_id, strlen (subject_id)))
    return WYRELOG_E_INVALID;
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT subject_id,display_name,state,generation,created_by,created_at_us,"
      "updated_at_us,disabled_by,disabled_at_us FROM service_principals"
      " WHERE subject_id=?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }
  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW)
    rc = parse_service_principal_row (stmt, out);
  else
    rc = step_rc == SQLITE_DONE ? WYRELOG_E_NOT_FOUND : WYRELOG_E_IO;
  sqlite3_finalize (stmt);
  return rc;
}

wyrelog_error_t
wyl_policy_store_foreach_service_principal (wyl_policy_store_t *store,
    wyl_policy_service_principal_cb cb, gpointer user_data)
{
  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT subject_id,display_name,state,generation,created_by,created_at_us,"
      "updated_at_us,disabled_by,disabled_at_us FROM service_principals"
      " ORDER BY subject_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    wyl_policy_service_principal_info_t info = { 0 };
    rc = parse_service_principal_row (stmt, &info);
    if (rc == WYRELOG_E_OK)
      rc = cb (&info, user_data);
    wyl_policy_service_principal_info_clear (&info);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }
  sqlite3_finalize (stmt);
  return step_rc == SQLITE_DONE ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static const gchar service_credential_columns[] =
    "credential_id,credential_format_version,subject_id,tenant_id,generation,"
    "state,verifier_version,salt,verifier,created_by,created_at_us,updated_at_us,"
    "expires_at_us,last_used_at_us,revoked_by,revoked_at_us,rotated_from_id";

wyrelog_error_t
wyl_policy_store_lookup_service_credential (wyl_policy_store_t *store,
    const gchar *credential_id, const gchar *subject_id,
    const gchar *tenant_id, wyl_policy_service_credential_info_t *out)
{
  if (out != NULL)
    wyl_policy_service_credential_info_clear (out);
  if (store == NULL || store->db == NULL || out == NULL
      || credential_id == NULL
      || !credential_filter_is_valid (credential_id, subject_id, tenant_id))
    return WYRELOG_E_INVALID;
  g_autofree gchar *sql = g_strdup_printf ("SELECT %s FROM service_credentials"
      " WHERE credential_id=? AND subject_id=? AND tenant_id=?;",
      service_credential_columns);
  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_service_filter (stmt, credential_id, subject_id, tenant_id))
      != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }
  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW)
    rc = parse_service_credential_row (stmt, out);
  else
    rc = step_rc == SQLITE_DONE ? WYRELOG_E_NOT_FOUND : WYRELOG_E_IO;
  sqlite3_finalize (stmt);
  return rc;
}

wyrelog_error_t
wyl_policy_store_lookup_service_credential_by_id (wyl_policy_store_t *store,
    const gchar *credential_id, wyl_policy_service_credential_info_t *out)
{
  if (out != NULL)
    wyl_policy_service_credential_info_clear (out);
  if (store == NULL || store->db == NULL || out == NULL
      || credential_id == NULL
      || !wyl_service_credential_id_is_canonical (credential_id,
          strlen (credential_id)))
    return WYRELOG_E_INVALID;
  g_autofree gchar *sql = g_strdup_printf ("SELECT %s FROM service_credentials"
      " WHERE credential_id=?;", service_credential_columns);
  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, credential_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }
  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW)
    rc = parse_service_credential_row (stmt, out);
  else
    rc = step_rc == SQLITE_DONE ? WYRELOG_E_NOT_FOUND : WYRELOG_E_IO;
  sqlite3_finalize (stmt);
  return rc;
}

wyrelog_error_t
wyl_policy_store_foreach_service_credential (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *tenant_id,
    wyl_policy_service_credential_cb cb, gpointer user_data)
{
  if (store == NULL || store->db == NULL || cb == NULL
      || !credential_filter_is_valid (NULL, subject_id, tenant_id))
    return WYRELOG_E_INVALID;
  g_autofree gchar *sql = g_strdup_printf ("SELECT %s FROM service_credentials"
      " WHERE subject_id=? AND tenant_id=? ORDER BY generation,credential_id;",
      service_credential_columns);
  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_service_filter (stmt, NULL, subject_id, tenant_id))
      != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }
  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    wyl_policy_service_credential_info_t info = { 0 };
    rc = parse_service_credential_row (stmt, &info);
    if (rc == WYRELOG_E_OK)
      rc = cb (&info, user_data);
    wyl_policy_service_credential_info_clear (&info);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }
  sqlite3_finalize (stmt);
  return step_rc == SQLITE_DONE ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_load_service_cvk (wyl_policy_store_t *store,
    wyl_policy_service_cvk_info_t *out)
{
  if (out != NULL)
    wyl_policy_service_cvk_info_clear (out);
  if (store == NULL || store->db == NULL || out == NULL)
    return WYRELOG_E_INVALID;
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT slot,generation,envelope_format_version,provider_binding,"
      "sealed_cvk,created_at_us,updated_at_us FROM service_credential_cvk"
      " WHERE slot=1;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_NOT_FOUND;
  }
  if (step_rc != SQLITE_ROW || sqlite3_column_type (stmt, 0) != SQLITE_INTEGER
      || sqlite3_column_int64 (stmt, 0) != 1) {
    sqlite3_finalize (stmt);
    return step_rc == SQLITE_ROW ? WYRELOG_E_POLICY : WYRELOG_E_IO;
  }
  guint64 version = 0;
  rc = read_positive_u64 (stmt, 1, &out->generation);
  if (rc == WYRELOG_E_OK)
    rc = read_positive_u64 (stmt, 2, &version);
  if (rc == WYRELOG_E_OK && version > G_MAXUINT32)
    rc = WYRELOG_E_POLICY;
  out->envelope_format_version = (guint32) version;
  if (rc == WYRELOG_E_OK)
    rc = read_fixed_blob (stmt, 3, out->provider_binding,
        sizeof out->provider_binding);
  if (rc == WYRELOG_E_OK) {
    if (sqlite3_column_type (stmt, 4) != SQLITE_BLOB
        || sqlite3_column_bytes (stmt, 4) < 1
        || sqlite3_column_bytes (stmt, 4) > 65536) {
      rc = WYRELOG_E_POLICY;
    } else {
      out->sealed_cvk_len = (gsize) sqlite3_column_bytes (stmt, 4);
      out->sealed_cvk = g_memdup2 (sqlite3_column_blob (stmt, 4),
          out->sealed_cvk_len);
      if (out->sealed_cvk == NULL)
        rc = WYRELOG_E_NOMEM;
    }
  }
  if (rc == WYRELOG_E_OK)
    rc = read_positive_i64 (stmt, 5, FALSE, &out->created_at_us);
  if (rc == WYRELOG_E_OK)
    rc = read_positive_i64 (stmt, 6, FALSE, &out->updated_at_us);
  if (rc == WYRELOG_E_OK && out->updated_at_us < out->created_at_us)
    rc = WYRELOG_E_POLICY;
  sqlite3_finalize (stmt);
  if (rc != WYRELOG_E_OK)
    wyl_policy_service_cvk_info_clear (out);
  return rc;
}

static void
cvk_put_u64_be (guint8 out[8], guint64 value)
{
  for (gint i = 7; i >= 0; i--) {
    out[i] = (guint8) value;
    value >>= 8;
  }
}

static guint64
cvk_get_u64_be (const guint8 in[8])
{
  guint64 value = 0;
  for (guint i = 0; i < 8; i++)
    value = (value << 8) | in[i];
  return value;
}

static wyrelog_error_t
service_cvk_provider_binding (wyl_policy_store_t *store,
    WylOwnedKeyProvider *provider, guint8 out[WYL_SERVICE_CVK_BINDING_BYTES])
{
  if (provider == NULL || !provider->owned)
    return WYRELOG_E_POLICY;
  gsize state_len = crypto_generichash_statebytes ();
  gsize scratch_len = state_len + 2 * WYL_SERVICE_CVK_BINDING_BYTES;
  guint8 *scratch = cvk_locked_alloc (store, scratch_len);
  if (scratch == NULL)
    return WYRELOG_E_NOMEM;
  crypto_generichash_state *state = (crypto_generichash_state *) scratch;
  guint8 *derived = scratch + state_len;
  guint8 *digest = derived + WYL_SERVICE_CVK_BINDING_BYTES;
  wyrelog_error_t rc = provider->vtable.derive (provider->state,
      WYL_SERVICE_CVK_BINDING_LABEL, derived,
      WYL_SERVICE_CVK_BINDING_BYTES);
  if (rc != WYRELOG_E_OK) {
    rc = WYRELOG_E_CRYPTO;
    goto out;
  }
  static const guint8 suffix[2] = { 0x00, 0x01 };
  int failed = crypto_generichash_init (state, derived,
      WYL_SERVICE_CVK_BINDING_BYTES, WYL_SERVICE_CVK_BINDING_BYTES);
  if (failed == 0)
    failed = crypto_generichash_update (state,
        (const guint8 *) WYL_SERVICE_CVK_BINDING_DOMAIN,
        sizeof (WYL_SERVICE_CVK_BINDING_DOMAIN) - 1);
  if (failed == 0)
    failed = crypto_generichash_update (state, suffix, sizeof suffix);
  if (failed == 0)
    failed = crypto_generichash_final (state, digest,
        WYL_SERVICE_CVK_BINDING_BYTES);
  if (failed != 0) {
    rc = WYRELOG_E_CRYPTO;
    goto out;
  }
  memcpy (out, digest, WYL_SERVICE_CVK_BINDING_BYTES);
  rc = WYRELOG_E_OK;
out:
  cvk_locked_free (store, scratch, scratch_len);
  return rc;
}

static void
service_cvk_build_envelope (guint8 envelope[WYL_SERVICE_CVK_ENVELOPE_BYTES],
    guint64 generation,
    const guint8 binding[WYL_SERVICE_CVK_BINDING_BYTES],
    const guint8 cvk[WYL_SERVICE_CREDENTIAL_CVK_BYTES])
{
  g_return_if_fail (generation >= 1 && generation <= G_MAXINT64);
  memcpy (envelope + WYL_SERVICE_CVK_MAGIC_OFFSET, WYL_SERVICE_CVK_MAGIC,
      WYL_SERVICE_CVK_MAGIC_BYTES);
  memcpy (envelope + WYL_SERVICE_CVK_DOMAIN_OFFSET, WYL_SERVICE_CVK_DOMAIN,
      WYL_SERVICE_CVK_DOMAIN_BYTES);
  envelope[WYL_SERVICE_CVK_VERSION_OFFSET] = WYL_SERVICE_CVK_ENVELOPE_VERSION;
  envelope[WYL_SERVICE_CVK_SLOT_OFFSET] = WYL_SERVICE_CVK_SLOT;
  cvk_put_u64_be (envelope + WYL_SERVICE_CVK_GENERATION_OFFSET, generation);
  memcpy (envelope + WYL_SERVICE_CVK_BINDING_OFFSET, binding,
      WYL_SERVICE_CVK_BINDING_BYTES);
  envelope[WYL_SERVICE_CVK_CVK_LEN_OFFSET] = 0x00;
  envelope[WYL_SERVICE_CVK_CVK_LEN_OFFSET + 1] =
      WYL_SERVICE_CREDENTIAL_CVK_BYTES;
  memcpy (envelope + WYL_SERVICE_CVK_CVK_OFFSET, cvk,
      WYL_SERVICE_CREDENTIAL_CVK_BYTES);
}

static wyrelog_error_t
service_cvk_seal_envelope (WylOwnedKeyProvider *provider,
    const guint8 envelope[WYL_SERVICE_CVK_ENVELOPE_BYTES],
    wyl_sealed_blob_t *out_blob)
{
  *out_blob = (wyl_sealed_blob_t) {
  0};
  if (provider == NULL || !provider->owned)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = provider->vtable.seal (provider->state, envelope,
      WYL_SERVICE_CVK_ENVELOPE_BYTES, out_blob);
  if (rc != WYRELOG_E_OK || out_blob->bytes == NULL || out_blob->len == 0
      || out_blob->len > 65536 || out_blob->len > G_MAXINT)
    return WYRELOG_E_CRYPTO;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
service_cvk_validate_envelope (const guint8 *envelope, guint64 generation,
    const guint8 binding[WYL_SERVICE_CVK_BINDING_BYTES])
{
  if (memcmp (envelope + WYL_SERVICE_CVK_MAGIC_OFFSET, WYL_SERVICE_CVK_MAGIC,
          WYL_SERVICE_CVK_MAGIC_BYTES) != 0
      || memcmp (envelope + WYL_SERVICE_CVK_DOMAIN_OFFSET,
          WYL_SERVICE_CVK_DOMAIN, WYL_SERVICE_CVK_DOMAIN_BYTES) != 0
      || envelope[WYL_SERVICE_CVK_VERSION_OFFSET]
      != WYL_SERVICE_CVK_ENVELOPE_VERSION
      || envelope[WYL_SERVICE_CVK_SLOT_OFFSET] != WYL_SERVICE_CVK_SLOT
      || cvk_get_u64_be (envelope + WYL_SERVICE_CVK_GENERATION_OFFSET)
      != generation
      || envelope[WYL_SERVICE_CVK_CVK_LEN_OFFSET] != 0
      || envelope[WYL_SERVICE_CVK_CVK_LEN_OFFSET + 1]
      != WYL_SERVICE_CREDENTIAL_CVK_BYTES)
    return WYRELOG_E_POLICY;
  if (sodium_memcmp (envelope + WYL_SERVICE_CVK_BINDING_OFFSET, binding,
          WYL_SERVICE_CVK_BINDING_BYTES) != 0)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
service_cvk_begin (wyl_policy_store_t *store)
{
  if (!sqlite3_get_autocommit (store->db))
    return WYRELOG_E_BUSY;
  int sql_rc = sqlite3_exec (store->db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
  if (sql_rc == SQLITE_BUSY || sql_rc == SQLITE_LOCKED)
    return WYRELOG_E_BUSY;
  return sql_rc == SQLITE_OK ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
service_cvk_unseal_validate (wyl_policy_store_t *store,
    WylOwnedKeyProvider *provider,
    const wyl_policy_service_cvk_info_t *info, guint8 **out_envelope)
{
  if (info->generation > G_MAXINT64
      || info->envelope_format_version != WYL_SERVICE_CVK_ENVELOPE_VERSION)
    return WYRELOG_E_POLICY;
  guint8 binding[WYL_SERVICE_CVK_BINDING_BYTES];
  wyrelog_error_t rc = service_cvk_provider_binding (store, provider, binding);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (sodium_memcmp (binding, info->provider_binding, sizeof binding) != 0) {
    sodium_memzero (binding, sizeof binding);
    return WYRELOG_E_CRYPTO;
  }
  guint8 *envelope = cvk_locked_alloc (store,
      WYL_SERVICE_CVK_ENVELOPE_BYTES);
  if (envelope == NULL) {
    sodium_memzero (binding, sizeof binding);
    return WYRELOG_E_NOMEM;
  }
  wyl_sealed_blob_t blob = {
    .bytes = info->sealed_cvk,
    .len = info->sealed_cvk_len,
  };
  gsize written = 0;
  rc = provider->vtable.unseal (provider->state, &blob,
      envelope, WYL_SERVICE_CVK_ENVELOPE_BYTES, &written);
  if (rc != WYRELOG_E_OK || written != WYL_SERVICE_CVK_ENVELOPE_BYTES) {
    rc = WYRELOG_E_CRYPTO;
    goto fail;
  }
  rc = service_cvk_validate_envelope (envelope, info->generation, binding);
  if (rc != WYRELOG_E_OK)
    goto fail;
  sodium_memzero (binding, sizeof binding);
  *out_envelope = envelope;
  return WYRELOG_E_OK;
fail:
  sodium_memzero (binding, sizeof binding);
  cvk_locked_free (store, envelope, WYL_SERVICE_CVK_ENVELOPE_BYTES);
  return rc;
}

static gboolean
rotation_probe_store_authenticated (wyl_policy_store_t *store,
    guint64 *out_generation)
{
  if (out_generation != NULL)
    *out_generation = 0;
  if (store == NULL)
    return FALSE;
  wyl_policy_service_cvk_info_t info = { 0 };
  guint8 *envelope = NULL;
  wyrelog_error_t rc = wyl_policy_store_load_service_cvk (store, &info);
  if (rc == WYRELOG_E_OK)
    rc = service_cvk_unseal_validate (store, &store->keyprovider, &info,
        &envelope);
  if (rc == WYRELOG_E_OK && out_generation != NULL)
    *out_generation = info.generation;
  if (envelope != NULL)
    cvk_locked_free (store, envelope, WYL_SERVICE_CVK_ENVELOPE_BYTES);
  wyl_policy_service_cvk_info_clear (&info);
  return rc == WYRELOG_E_OK;
}

static void rotation_recovery_release_opts
    (wyl_policy_store_open_options_t * opts);

wyrelog_error_t
wyl_policy_store_rotation_probe (const gchar *path,
    wyl_policy_store_open_options_t *old_opts,
    wyl_policy_store_open_options_t *new_opts,
    WylPolicyRotationRecoveryProbeResult *out_result)
{
  if (out_result != NULL)
    memset (out_result, 0, sizeof *out_result);
  if (path == NULL || path[0] == '\0' || old_opts == NULL || new_opts == NULL
      || out_result == NULL)
    return WYRELOG_E_INVALID;
  if (old_opts == new_opts
      || (old_opts->keyprovider_state != NULL
          && old_opts->keyprovider_state == new_opts->keyprovider_state))
    return WYRELOG_E_INVALID;
  out_result->state = WYL_POLICY_ROTATION_RECOVERY_AMBIGUOUS;
  out_result->intent_state = WYL_POLICY_ROTATION_INTENT_STATUS_ABSENT;

  old_opts->path = path;
  old_opts->require_encrypted = TRUE;
  new_opts->path = path;
  new_opts->require_encrypted = TRUE;

  wyl_policy_store_t *old_store = NULL;
  wyl_policy_store_t *new_store = NULL;
  guint8 old_digest[crypto_generichash_BYTES] = { 0 };
  gboolean old_digest_valid = FALSE;
  wyrelog_error_t old_rc = wyl_policy_store_open_with_options (old_opts,
      &old_store);
  /* Open codes that mean "this retained root is simply not valid under this
   * provider" are treated as not-authenticated, not propagated: CRYPTO (AEAD
   * mismatch), NOT_FOUND (no canonical), and POLICY (the canonical header's
   * provider id does not match this provider, or a malformed/symlinked file).
   * A root is only ever counted when it fully authenticates, so at worst an
   * unrecognized canonical yields AMBIGUOUS and the caller fails closed. Only
   * environmental errors (I/O, BUSY lease, NOMEM) propagate verbatim. */
  /* A probe is strictly read-only. Encrypted fresh opens use an in-memory
   * SQLite image and would otherwise persist a newly-created canonical file
   * during close when the requested path is absent. */
  if (old_store != NULL)
    old_store->suppress_close_persist = TRUE;
  if (old_rc == WYRELOG_E_OK && old_store != NULL) {
    out_result->old_root_authenticated =
        rotation_probe_store_authenticated (old_store,
        &out_result->old_generation);
    memcpy (out_result->old_provider_id, old_store->encryption_key_id,
        sizeof out_result->old_provider_id);
    out_result->old_inner_invariants_match = out_result->old_root_authenticated;
    if (rotation_intent_digest_canonical (old_store, old_digest)
        == WYRELOG_E_OK)
      old_digest_valid = TRUE;

    WylPolicyRotationIntentStatus status = { 0 };
    wyrelog_error_t intent_rc =
        wyl_policy_store_rotation_intent_status (old_store, &status);
    if (intent_rc == WYRELOG_E_OK) {
      out_result->intent_state = status.state;
      out_result->transaction_id = status.transaction_id;
      if (status.state != WYL_POLICY_ROTATION_INTENT_STATUS_ABSENT
          && memcmp (status.old_provider_id, out_result->old_provider_id,
              sizeof status.old_provider_id) != 0) {
        out_result->old_inner_invariants_match = FALSE;
      }
    } else if (intent_rc != WYRELOG_E_NOT_FOUND) {
      wyl_policy_store_close (old_store);
      sodium_memzero (old_digest, sizeof old_digest);
      /* new_opts has not been opened yet, so open() never consumed its state.
       * Release the not-yet-opened provider box through its wiping free
       * callback so its secret key material is not leaked on this path. */
      rotation_recovery_release_opts (new_opts);
      return intent_rc;
    }
    wyl_policy_store_close (old_store);
    old_store = NULL;
  } else if (old_rc != WYRELOG_E_OK && old_rc != WYRELOG_E_CRYPTO
      && old_rc != WYRELOG_E_NOT_FOUND && old_rc != WYRELOG_E_POLICY) {
    if (old_store != NULL)
      wyl_policy_store_close (old_store);
    /* Same as above: new_opts is still unconsumed on this early return. */
    rotation_recovery_release_opts (new_opts);
    return old_rc;
  } else if (old_store != NULL) {
    wyl_policy_store_close (old_store);
    old_store = NULL;
  }
  wyrelog_error_t new_rc = wyl_policy_store_open_with_options (new_opts,
      &new_store);
  if (new_store != NULL)
    new_store->suppress_close_persist = TRUE;
  if (new_rc == WYRELOG_E_OK && new_store != NULL) {
    out_result->new_root_authenticated =
        rotation_probe_store_authenticated (new_store,
        &out_result->new_generation);
    memcpy (out_result->new_provider_id, new_store->encryption_key_id,
        sizeof out_result->new_provider_id);
    out_result->new_inner_invariants_match = out_result->new_root_authenticated;
    if (old_digest_valid) {
      guint8 new_digest[crypto_generichash_BYTES] = { 0 };
      wyrelog_error_t digest_rc =
          rotation_intent_digest_canonical (new_store, new_digest);
      if (digest_rc != WYRELOG_E_OK
          || sodium_memcmp (old_digest, new_digest, sizeof old_digest) != 0) {
        sodium_memzero (new_digest, sizeof new_digest);
        wyl_policy_store_close (new_store);
        sodium_memzero (old_digest, sizeof old_digest);
        return digest_rc == WYRELOG_E_OK ? WYRELOG_E_BUSY : digest_rc;
      }
      sodium_memzero (new_digest, sizeof new_digest);
    }
  } else if (new_rc != WYRELOG_E_OK && new_rc != WYRELOG_E_CRYPTO
      && new_rc != WYRELOG_E_NOT_FOUND && new_rc != WYRELOG_E_POLICY) {
    if (new_store != NULL)
      wyl_policy_store_close (new_store);
    return new_rc;
  }
  if (out_result->old_root_authenticated && !out_result->new_root_authenticated)
    out_result->state = WYL_POLICY_ROTATION_RECOVERY_OLD;
  else if (!out_result->old_root_authenticated
      && out_result->new_root_authenticated)
    out_result->state = WYL_POLICY_ROTATION_RECOVERY_NEW;

  if (new_store != NULL)
    wyl_policy_store_close (new_store);
  sodium_memzero (old_digest, sizeof old_digest);
  return WYRELOG_E_OK;
}

/* Releases a minted-but-unconsumed option set's provider state under the
 * open ownership contract (wipe once, then free if a free callback exists). */
static void
rotation_recovery_release_opts (wyl_policy_store_open_options_t *opts)
{
  WylOwnedKeyProvider orphan = { 0 };
  owned_keyprovider_adopt (&orphan, opts);
  owned_keyprovider_release (&orphan);
  memset (opts, 0, sizeof *opts);
}

/* Derives the safe next action directly from the probe's (state, intent_state),
 * without routing an absent intent through recovery_plan. */
static WylPolicyRotationRecoveryAction
rotation_recovery_action_from_probe (const WylPolicyRotationRecoveryProbeResult
    *probe)
{
  if (probe->state == WYL_POLICY_ROTATION_RECOVERY_NEW)
    return WYL_POLICY_ROTATION_RECOVERY_FINALIZE_NEW;
  if (probe->state == WYL_POLICY_ROTATION_RECOVERY_OLD) {
    if (probe->intent_state == WYL_POLICY_ROTATION_INTENT_STATUS_PENDING)
      return WYL_POLICY_ROTATION_RECOVERY_RESUME_OLD;
    if (probe->intent_state == WYL_POLICY_ROTATION_INTENT_STATUS_ABSENT)
      return WYL_POLICY_ROTATION_RECOVERY_NONE;
    /* A committed intent over a still-old root is contradictory: fail closed. */
    return WYL_POLICY_ROTATION_RECOVERY_FAIL_CLOSED;
  }
  return WYL_POLICY_ROTATION_RECOVERY_FAIL_CLOSED;
}

wyrelog_error_t
wyl_policy_store_rotation_recovery_status (const gchar *path,
    const wyl_policy_rotation_recovery_factory_t *factory,
    WylPolicyRotationRecoveryProbeResult *out_probe,
    WylPolicyRotationRecoveryAction *out_action)
{
  if (out_probe != NULL)
    memset (out_probe, 0, sizeof *out_probe);
  if (out_action != NULL)
    *out_action = WYL_POLICY_ROTATION_RECOVERY_FAIL_CLOSED;
  if (path == NULL || path[0] == '\0' || factory == NULL
      || factory->make_old_opts == NULL || factory->make_new_opts == NULL
      || out_probe == NULL || out_action == NULL)
    return WYRELOG_E_INVALID;

  wyl_policy_store_open_options_t old_opts = { 0 };
  wyl_policy_store_open_options_t new_opts = { 0 };
  wyrelog_error_t rc = factory->make_old_opts (factory->data, &old_opts);
  if (rc != WYRELOG_E_OK) {
    rotation_recovery_release_opts (&old_opts);
    return rc;
  }
  rc = factory->make_new_opts (factory->data, &new_opts);
  if (rc != WYRELOG_E_OK) {
    rotation_recovery_release_opts (&new_opts);
    rotation_recovery_release_opts (&old_opts);
    return rc;
  }
  /* The probe is strictly read-only and consumes both option sets. Any error
   * (including WYRELOG_E_BUSY for divergent roots) passes through verbatim. */
  rc = wyl_policy_store_rotation_probe (path, &old_opts, &new_opts, out_probe);
  if (rc != WYRELOG_E_OK)
    return rc;
  *out_action = rotation_recovery_action_from_probe (out_probe);
  return WYRELOG_E_OK;
}

/* Maps a recovery reopen failure. Environmental errors (I/O, BUSY lease, NOMEM,
 * argument shape) pass through verbatim so the operator can retry; only a
 * genuine authentication or validation failure (CRYPTO/POLICY) is normalized to
 * a fail-closed WYRELOG_E_POLICY. */
static wyrelog_error_t
rotation_recover_reopen_error (wyrelog_error_t rc)
{
  return (rc == WYRELOG_E_CRYPTO || rc == WYRELOG_E_POLICY)
      ? WYRELOG_E_POLICY : rc;
}

/* FINALIZE_NEW: the rename already linearized to the new root. Open under the
 * new provider and unlink any residual intent sidecar. The sidecar is keyed by
 * the old store key and is unreadable here, so the clear is keyless and
 * idempotent (ENOENT is success); the intent MAC is never read or verified and
 * rotation_intent_finalize_committed is not reused (it asserts the old provider
 * binding). */
static wyrelog_error_t
rotation_recover_finalize_new (const gchar *path,
    const wyl_policy_rotation_recovery_factory_t *factory)
{
  wyl_policy_store_open_options_t new_opts = { 0 };
  wyrelog_error_t rc = factory->make_new_opts (factory->data, &new_opts);
  if (rc != WYRELOG_E_OK) {
    rotation_recovery_release_opts (&new_opts);
    return rc;
  }
  new_opts.path = path;
  new_opts.require_encrypted = TRUE;
  wyl_policy_store_t *store = NULL;
  rc = wyl_policy_store_open_with_options (&new_opts, &store);
  if (rc != WYRELOG_E_OK) {
    if (store != NULL)
      wyl_policy_store_close (store);
    return rotation_recover_reopen_error (rc);
  }
  /* The new root is authoritative and unchanged: only the sidecar is touched. */
  store->suppress_close_persist = TRUE;
  rc = wyl_policy_rotation_intent_clear_sidecar (store);
  wyl_policy_store_close (store);
  return rc;
}

/* RESUME_OLD: the crash preserved the old root plus a pending intent. Re-verify
 * the intent under a fresh old-root handle, clear the stale pending sidecar so
 * the re-rotation's write_pending is not rejected, then re-run the unchanged
 * rotation. It converges to the same expected new generation reusing the same
 * CVK, so verifier bytes are identical. Any mismatch fails closed without
 * changing a byte. */
static wyrelog_error_t
rotation_recover_resume_old (const gchar *path,
    const wyl_policy_rotation_recovery_factory_t *factory,
    const WylPolicyRotationRecoveryProbeResult *probe)
{
  wyl_policy_store_open_options_t old_opts = { 0 };
  wyrelog_error_t rc = factory->make_old_opts (factory->data, &old_opts);
  if (rc != WYRELOG_E_OK) {
    rotation_recovery_release_opts (&old_opts);
    return rc;
  }
  old_opts.path = path;
  old_opts.require_encrypted = TRUE;
  wyl_policy_store_t *store = NULL;
  rc = wyl_policy_store_open_with_options (&old_opts, &store);
  if (rc != WYRELOG_E_OK) {
    if (store != NULL)
      wyl_policy_store_close (store);
    return rotation_recover_reopen_error (rc);
  }
  store->suppress_close_persist = TRUE;

  /* rotation_intent_status re-checks that the pending intent's provider binding
   * and canonical digest match the current old root; also require the pending
   * transaction id and CVK generation to be exactly those the probe observed. */
  WylPolicyRotationIntentStatus status = { 0 };
  rc = wyl_policy_store_rotation_intent_status (store, &status);
  gboolean matches = rc == WYRELOG_E_OK
      && status.state == WYL_POLICY_ROTATION_INTENT_STATUS_PENDING
      && memcmp (status.old_provider_id, store->encryption_key_id,
      sizeof status.old_provider_id) == 0
      && memcmp (&status.transaction_id, &probe->transaction_id,
      sizeof status.transaction_id) == 0;
  if (matches) {
    wyl_policy_service_cvk_info_t info = { 0 };
    wyrelog_error_t info_rc = wyl_policy_store_load_service_cvk (store, &info);
    if (info_rc == WYRELOG_E_OK) {
      if (info.generation != status.old_generation)
        matches = FALSE;
    } else if (info_rc == WYRELOG_E_NOT_FOUND) {
      if (status.old_generation != 0)
        matches = FALSE;
    } else {
      matches = FALSE;
    }
    wyl_policy_service_cvk_info_clear (&info);
  }
  if (!matches) {
    wyl_policy_store_close (store);
    return WYRELOG_E_POLICY;
  }
  rc = wyl_policy_rotation_intent_clear_sidecar (store);
  wyl_policy_store_close (store);
  if (rc != WYRELOG_E_OK)
    return rc;

  /* Liveness note (not a safety defect): a crash in the window between clearing
   * the pending sidecar here and the re-invoked rotation writing its own intent
   * below leaves the old root with an ABSENT intent. The next recover() then
   * classifies that as NONE (a no-op), so the interrupted rotation is safely
   * abandoned: the store stays consistent as a single clean old root, no secret
   * is exposed, and the generation never double-advances. Completing the
   * rotation must be re-initiated by the operator. */
  wyl_policy_store_open_options_t rotate_old = { 0 };
  wyl_policy_store_open_options_t rotate_new = { 0 };
  rc = factory->make_old_opts (factory->data, &rotate_old);
  if (rc != WYRELOG_E_OK) {
    rotation_recovery_release_opts (&rotate_old);
    return rc;
  }
  rc = factory->make_new_opts (factory->data, &rotate_new);
  if (rc != WYRELOG_E_OK) {
    rotation_recovery_release_opts (&rotate_new);
    rotation_recovery_release_opts (&rotate_old);
    return rc;
  }
  return wyl_policy_store_rotate_keyprovider (path, &rotate_old, &rotate_new);
}

wyrelog_error_t
wyl_policy_store_rotation_recover (const gchar *path,
    const wyl_policy_rotation_recovery_factory_t *factory)
{
  if (path == NULL || path[0] == '\0' || factory == NULL
      || factory->make_old_opts == NULL || factory->make_new_opts == NULL)
    return WYRELOG_E_INVALID;

  WylPolicyRotationRecoveryProbeResult probe = { 0 };
  WylPolicyRotationRecoveryAction action =
      WYL_POLICY_ROTATION_RECOVERY_FAIL_CLOSED;
  wyrelog_error_t rc = wyl_policy_store_rotation_recovery_status (path, factory,
      &probe, &action);
  if (rc != WYRELOG_E_OK)
    return rc;

  switch (action) {
    case WYL_POLICY_ROTATION_RECOVERY_FINALIZE_NEW:
      return rotation_recover_finalize_new (path, factory);
    case WYL_POLICY_ROTATION_RECOVERY_RESUME_OLD:
      return rotation_recover_resume_old (path, factory, &probe);
    case WYL_POLICY_ROTATION_RECOVERY_NONE:
      return WYRELOG_E_OK;
    case WYL_POLICY_ROTATION_RECOVERY_FAIL_CLOSED:
    default:
      return WYRELOG_E_POLICY;
  }
}

static wyrelog_error_t
service_cvk_insert_initial (wyl_policy_store_t *store, guint8 **out_envelope)
{
  WylOwnedKeyProvider *provider = &store->keyprovider;
  if (!provider->owned)
    return WYRELOG_E_POLICY;
  guint8 binding[WYL_SERVICE_CVK_BINDING_BYTES];
  wyrelog_error_t rc = service_cvk_provider_binding (store, provider, binding);
  if (rc != WYRELOG_E_OK)
    return rc;
  guint8 *envelope = cvk_locked_alloc (store,
      WYL_SERVICE_CVK_ENVELOPE_BYTES);
  if (envelope == NULL) {
    sodium_memzero (binding, sizeof binding);
    return WYRELOG_E_NOMEM;
  }
  guint8 *cvk = cvk_locked_alloc (store, WYL_SERVICE_CREDENTIAL_CVK_BYTES);
  if (cvk == NULL) {
    rc = WYRELOG_E_NOMEM;
    goto fail;
  }
  if (store->service_cvk_runtime.fill_random (store->service_cvk_runtime.data,
          cvk, WYL_SERVICE_CREDENTIAL_CVK_BYTES) != 0) {
    rc = WYRELOG_E_CRYPTO;
    goto fail_cvk;
  }
  service_cvk_build_envelope (envelope, WYL_SERVICE_CVK_GENERATION, binding,
      cvk);
  cvk_locked_free (store, cvk, WYL_SERVICE_CREDENTIAL_CVK_BYTES);
  cvk = NULL;
  wyl_sealed_blob_t sealed = { 0 };
  rc = service_cvk_seal_envelope (provider, envelope, &sealed);
  if (rc != WYRELOG_E_OK)
    goto fail_blob;
  gint64 now_us =
      store->service_cvk_runtime.now_us (store->service_cvk_runtime.data);
  if (now_us <= 0) {
    rc = WYRELOG_E_IO;
    goto fail_blob;
  }
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "INSERT INTO service_credential_cvk"
      "(slot,generation,envelope_format_version,provider_binding,sealed_cvk,"
      "created_at_us,updated_at_us) VALUES(1,1,1,?,?,?,?);";
  rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK
      && (sqlite3_bind_blob (stmt, 1, binding, sizeof binding,
              SQLITE_TRANSIENT) != SQLITE_OK
          || sqlite3_bind_blob (stmt, 2, sealed.bytes, (int) sealed.len,
              SQLITE_TRANSIENT) != SQLITE_OK
          || sqlite3_bind_int64 (stmt, 3, now_us) != SQLITE_OK
          || sqlite3_bind_int64 (stmt, 4, now_us) != SQLITE_OK))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
    rc = WYRELOG_E_IO;
  sqlite3_finalize (stmt);
fail_blob:
  provider->vtable.clear_sealed_blob (provider->state, &sealed);
  if (rc != WYRELOG_E_OK)
    goto fail;
  sodium_memzero (binding, sizeof binding);
  *out_envelope = envelope;
  return WYRELOG_E_OK;
fail_cvk:
  cvk_locked_free (store, cvk, WYL_SERVICE_CREDENTIAL_CVK_BYTES);
fail:
  sodium_memzero (binding, sizeof binding);
  cvk_locked_free (store, envelope, WYL_SERVICE_CVK_ENVELOPE_BYTES);
  return rc;
}

static wyrelog_error_t
rotation_derive_store_key (wyl_policy_store_t *store,
    WylOwnedKeyProvider *provider, guint8 **out_key_material)
{
  *out_key_material = NULL;
  guint8 *key_material = cvk_locked_alloc (store,
      WYL_POLICY_STORE_KEY_LEN + WYL_POLICY_STORE_KEY_ID_LEN);
  if (key_material == NULL)
    return WYRELOG_E_NOMEM;
  wyrelog_error_t rc = provider->vtable.derive (provider->state,
      WYL_POLICY_STORE_ENCRYPTION_LABEL, key_material,
      WYL_POLICY_STORE_KEY_LEN);
  if (rc != WYRELOG_E_OK
      || crypto_generichash (key_material + WYL_POLICY_STORE_KEY_LEN,
          WYL_POLICY_STORE_KEY_ID_LEN, key_material,
          WYL_POLICY_STORE_KEY_LEN, NULL, 0) != 0) {
    cvk_locked_free (store, key_material,
        WYL_POLICY_STORE_KEY_LEN + WYL_POLICY_STORE_KEY_ID_LEN);
    return WYRELOG_E_CRYPTO;
  }
  *out_key_material = key_material;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
rotation_update_cvk_row (wyl_policy_store_t *store,
    const wyl_policy_service_cvk_info_t *info,
    const guint8 binding[WYL_SERVICE_CVK_BINDING_BYTES],
    const wyl_sealed_blob_t *sealed)
{
  gint64 now_us =
      store->service_cvk_runtime.now_us (store->service_cvk_runtime.data);
  if (now_us <= 0)
    return WYRELOG_E_IO;
  gint64 updated_at_us = MAX (info->updated_at_us, now_us);
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "UPDATE service_credential_cvk SET generation=?,provider_binding=?,"
      "sealed_cvk=?,updated_at_us=? WHERE slot=1 AND generation=? AND "
      "envelope_format_version=? AND provider_binding=? AND sealed_cvk=?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK
      && (sqlite3_bind_int64 (stmt, 1, (sqlite3_int64) (info->generation + 1))
          != SQLITE_OK
          || sqlite3_bind_blob (stmt, 2, binding,
              WYL_SERVICE_CVK_BINDING_BYTES, SQLITE_TRANSIENT) != SQLITE_OK
          || sqlite3_bind_blob (stmt, 3, sealed->bytes, (int) sealed->len,
              SQLITE_TRANSIENT) != SQLITE_OK
          || sqlite3_bind_int64 (stmt, 4, updated_at_us) != SQLITE_OK
          || sqlite3_bind_int64 (stmt, 5, (sqlite3_int64) info->generation)
          != SQLITE_OK
          || sqlite3_bind_int (stmt, 6, info->envelope_format_version)
          != SQLITE_OK
          || sqlite3_bind_blob (stmt, 7, info->provider_binding,
              sizeof info->provider_binding, SQLITE_TRANSIENT) != SQLITE_OK
          || sqlite3_bind_blob (stmt, 8, info->sealed_cvk,
              (int) info->sealed_cvk_len, SQLITE_TRANSIENT) != SQLITE_OK))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
    rc = WYRELOG_E_IO;
  sqlite3_finalize (stmt);
  if (rc == WYRELOG_E_OK && sqlite3_changes (store->db) != 1)
    rc = WYRELOG_E_POLICY;
  return rc;
}

static wyrelog_error_t
prepare_keyprovider_rotation_work (wyl_policy_store_t *store,
    WylOwnedKeyProvider *new_provider,
    const wyl_policy_store_rotation_runtime_t *rotation_runtime,
    guint8 **out_new_key_material)
{
  *out_new_key_material = NULL;
  g_mutex_lock (&store->service_cvk_mutex);
  wyrelog_error_t rc = service_cvk_begin (store);
  if (rc != WYRELOG_E_OK)
    goto out;
  gboolean transaction = TRUE;
  wyl_policy_service_cvk_info_t info = { 0 };
  guint8 *old_envelope = NULL;
  guint8 *new_envelope = NULL;
  guint8 new_binding[WYL_SERVICE_CVK_BINDING_BYTES] = { 0 };
  wyl_sealed_blob_t sealed = { 0 };
  gboolean seal_called = FALSE;

  rc = wyl_policy_store_validate_snapshot (store);
  if (rc != WYRELOG_E_OK)
    goto finish;
  rc = wyl_policy_store_load_service_cvk (store, &info);
  if (rc == WYRELOG_E_NOT_FOUND) {
    gboolean credentials = FALSE;
    rc = query_has_rows (store->db,
        "SELECT 1 FROM service_credentials LIMIT 1;", &credentials);
    if (rc == WYRELOG_E_OK && credentials)
      rc = WYRELOG_E_POLICY;
    else if (rc == WYRELOG_E_OK)
      rc = WYRELOG_E_OK;
  } else if (rc == WYRELOG_E_OK) {
    if (info.generation < 1 || info.generation >= G_MAXINT64) {
      rc = WYRELOG_E_POLICY;
      goto finish;
    }
    rc = service_cvk_unseal_validate (store, &store->keyprovider, &info,
        &old_envelope);
  }
  if (rc != WYRELOG_E_OK)
    goto finish;

  rc = owned_keyprovider_validate (new_provider);
  if (rc != WYRELOG_E_OK)
    goto finish;
  if (!new_provider->owned) {
    rc = WYRELOG_E_POLICY;
    goto finish;
  }
  if (owned_keyprovider_probe (new_provider) != WYRELOG_E_OK) {
    rc = WYRELOG_E_CRYPTO;
    goto finish;
  }

  rc = service_handoff_rewrap_all (store, new_provider);
  if (rc != WYRELOG_E_OK)
    goto finish;

  if (old_envelope != NULL) {
    rc = service_cvk_provider_binding (store, new_provider, new_binding);
    if (rc != WYRELOG_E_OK)
      goto finish;
    if (sodium_memcmp (new_binding, info.provider_binding,
            sizeof new_binding) == 0) {
      rc = WYRELOG_E_POLICY;
      goto finish;
    }
    new_envelope = cvk_locked_alloc (store, WYL_SERVICE_CVK_ENVELOPE_BYTES);
    if (new_envelope == NULL) {
      rc = WYRELOG_E_NOMEM;
      goto finish;
    }
    service_cvk_build_envelope (new_envelope, info.generation + 1,
        new_binding, old_envelope + WYL_SERVICE_CVK_CVK_OFFSET);
    seal_called = TRUE;
    rc = service_cvk_seal_envelope (new_provider, new_envelope, &sealed);
    if (rc != WYRELOG_E_OK)
      goto finish;
  }

  rc = rotation_derive_store_key (store, new_provider, out_new_key_material);
  if (rc != WYRELOG_E_OK)
    goto finish;
  rc = rotation_intent_write_pending (store, &info, *out_new_key_material);
  if (rc != WYRELOG_E_OK)
    goto finish;
  /* Pre-linearization: the pending intent sidecar now exists but the canonical
   * root is unchanged, so a signalled seam aborts and preserves the old root. */
  if (rotation_runtime != NULL && rotation_runtime->checkpoint != NULL
      && rotation_runtime->checkpoint (rotation_runtime->data,
          WYL_POLICY_ROTATION_AFTER_INTENT_WRITE) != 0)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && old_envelope != NULL && rotation_runtime != NULL
      && rotation_runtime->checkpoint != NULL
      && rotation_runtime->checkpoint (rotation_runtime->data,
          WYL_POLICY_ROTATION_BEFORE_CVK_CAS) != 0)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && old_envelope != NULL)
    rc = rotation_update_cvk_row (store, &info, new_binding, &sealed);
  if (rc == WYRELOG_E_OK)
    rc = exec_sql (store->db, "COMMIT;");
  if (rc == WYRELOG_E_OK)
    transaction = FALSE;
  /* Pre-linearization: the CVK CAS committed only to the in-memory image, which
   * is discarded on abort; the durable canonical root is still the old one. */
  if (rc == WYRELOG_E_OK && rotation_runtime != NULL
      && rotation_runtime->checkpoint != NULL
      && rotation_runtime->checkpoint (rotation_runtime->data,
          WYL_POLICY_ROTATION_AFTER_SQLITE_COMMIT) != 0)
    rc = WYRELOG_E_POLICY;

finish:
  if (transaction)
    (void) exec_sql (store->db, "ROLLBACK;");
  if (rc != WYRELOG_E_OK) {
    cvk_locked_free (store, *out_new_key_material,
        WYL_POLICY_STORE_KEY_LEN + WYL_POLICY_STORE_KEY_ID_LEN);
    *out_new_key_material = NULL;
  }
  if (seal_called)
    new_provider->vtable.clear_sealed_blob (new_provider->state, &sealed);
  sodium_memzero (new_binding, sizeof new_binding);
  cvk_locked_free (store, new_envelope, WYL_SERVICE_CVK_ENVELOPE_BYTES);
  cvk_locked_free (store, old_envelope, WYL_SERVICE_CVK_ENVELOPE_BYTES);
  wyl_policy_service_cvk_info_clear (&info);
out:
  g_mutex_unlock (&store->service_cvk_mutex);
  return rc;
}

static wyrelog_error_t
service_cvk_materialize (wyl_policy_store_t *store, gboolean allow_create,
    const guint8 **out_cvk, gsize *out_len)
{
  *out_cvk = NULL;
  *out_len = 0;
  if (store == NULL || store->db == NULL)
    return WYRELOG_E_INVALID;
  if (!store->keyprovider.owned)
    return WYRELOG_E_POLICY;
  g_mutex_lock (&store->service_cvk_mutex);
  wyrelog_error_t rc = WYRELOG_E_OK;
  rc = service_cvk_begin (store);
  if (rc != WYRELOG_E_OK)
    goto out;
  gboolean transaction = TRUE;
  wyl_policy_service_cvk_info_t info = { 0 };
  guint8 *candidate = NULL;
  rc = wyl_policy_store_validate_service_schema (store);
  if (rc != WYRELOG_E_OK)
    goto finish_transaction;
  if (store->service_cvk_envelope != NULL)
    goto commit;
  rc = wyl_policy_store_load_service_cvk (store, &info);
  if (rc == WYRELOG_E_NOT_FOUND) {
    gboolean credentials = FALSE;
    rc = query_has_rows (store->db,
        "SELECT 1 FROM service_credentials LIMIT 1;", &credentials);
    if (rc == WYRELOG_E_OK && credentials)
      rc = WYRELOG_E_POLICY;
    else if (rc == WYRELOG_E_OK && allow_create)
      rc = service_cvk_insert_initial (store, &candidate);
    else if (rc == WYRELOG_E_OK)
      rc = WYRELOG_E_NOT_FOUND;
  } else if (rc == WYRELOG_E_OK) {
    rc = service_cvk_unseal_validate (store, &store->keyprovider, &info,
        &candidate);
  }
  wyl_policy_service_cvk_info_clear (&info);
commit:
  if (rc == WYRELOG_E_OK) {
    rc = exec_sql (store->db, "COMMIT;");
    if (rc == WYRELOG_E_OK) {
      transaction = FALSE;
      if (store->service_cvk_envelope == NULL) {
        store->service_cvk_envelope = candidate;
        candidate = NULL;
      }
      *out_cvk = store->service_cvk_envelope + WYL_SERVICE_CVK_CVK_OFFSET;
      *out_len = WYL_SERVICE_CREDENTIAL_CVK_BYTES;
    }
  } else if (rc == WYRELOG_E_NOT_FOUND) {
    wyrelog_error_t commit_rc = exec_sql (store->db, "COMMIT;");
    if (commit_rc == WYRELOG_E_OK)
      transaction = FALSE;
    else
      rc = commit_rc;
  }
finish_transaction:
  if (transaction)
    (void) exec_sql (store->db, "ROLLBACK;");
  cvk_locked_free (store, candidate, WYL_SERVICE_CVK_ENVELOPE_BYTES);
out:
  g_mutex_unlock (&store->service_cvk_mutex);
  return rc;
}

wyrelog_error_t
wyl_policy_store_materialize_service_cvk_existing (wyl_policy_store_t *store,
    const guint8 **out_cvk, gsize *out_len)
{
  if (out_cvk == NULL || out_len == NULL)
    return WYRELOG_E_INVALID;
  return service_cvk_materialize (store, FALSE, out_cvk, out_len);
}

wyrelog_error_t
wyl_policy_store_ensure_service_cvk_for_issuance (wyl_policy_store_t *store,
    const guint8 **out_cvk, gsize *out_len)
{
  if (out_cvk == NULL || out_len == NULL)
    return WYRELOG_E_INVALID;
  return service_cvk_materialize (store, TRUE, out_cvk, out_len);
}

struct wyl_policy_service_handoff_secret_t
{
  wyl_policy_store_t *store;
  guint8 *bytes;
  gsize len;
};

void wyl_policy_service_handoff_escrow_info_clear
    (wyl_policy_service_handoff_escrow_info_t * info)
{
  if (info == NULL)
    return;
  g_free (info->operation);
  g_free (info->request_id);
  g_free (info->actor_subject_id);
  g_free (info->credential_id);
  sodium_memzero (info, sizeof *info);
}

void wyl_policy_service_handoff_secret_clear
    (wyl_policy_service_handoff_secret_t ** secret)
{
  if (secret == NULL || *secret == NULL)
    return;
  wyl_policy_service_handoff_secret_t *value = *secret;
  cvk_locked_free (value->store, value->bytes, value->len);
  sodium_memzero (value, sizeof *value);
  g_free (value);
  *secret = NULL;
}

const guint8 *wyl_policy_service_handoff_secret_peek
    (const wyl_policy_service_handoff_secret_t * secret, gsize * out_len)
{
  if (out_len != NULL)
    *out_len = secret == NULL ? 0 : secret->len;
  return secret == NULL ? NULL : secret->bytes;
}

static wyrelog_error_t
service_handoff_provider_binding_for (wyl_policy_store_t *store,
    WylOwnedKeyProvider *provider,
    guint8 out[WYL_SERVICE_HANDOFF_BINDING_BYTES])
{
  if (store == NULL || provider == NULL || !provider->owned)
    return WYRELOG_E_POLICY;
  guint8 *scratch = cvk_locked_alloc (store, 64);
  if (scratch == NULL)
    return WYRELOG_E_NOMEM;
  wyrelog_error_t rc = provider->vtable.derive (provider->state,
      WYL_SERVICE_HANDOFF_BINDING_LABEL, scratch, 32);
  if (rc == WYRELOG_E_OK && crypto_generichash (out, 32, (const guint8 *)
          WYL_SERVICE_HANDOFF_BINDING_DOMAIN,
          sizeof WYL_SERVICE_HANDOFF_BINDING_DOMAIN - 1, scratch, 32) != 0)
    rc = WYRELOG_E_CRYPTO;
  else if (rc != WYRELOG_E_OK)
    rc = WYRELOG_E_CRYPTO;
  cvk_locked_free (store, scratch, 64);
  return rc;
}

static gboolean
service_handoff_input_valid (const wyl_policy_service_handoff_escrow_input_t
    *in)
{
  if (in == NULL || in->escrow_id == NULL || in->operation == NULL
      || (!g_str_equal (in->operation, "issue")
          && !g_str_equal (in->operation, "rotate"))
      || in->request_id == NULL || in->request_id[0] == '\0'
      || strlen (in->request_id) > 256
      || !wyl_policy_service_actor_subject_is_valid (in->actor_subject_id)
      || in->target_digest == NULL || in->binding_digest == NULL
      || in->secret == NULL
      || in->secret_len != WYL_SERVICE_CREDENTIAL_SECRET_BYTES
      || in->credential_id == NULL
      || !wyl_service_credential_id_is_canonical (in->credential_id,
          strlen (in->credential_id))
      || in->credential_generation == 0
      || in->credential_generation > G_MAXINT64 || in->deadline_at_us <= 0)
    return FALSE;
  gchar id[WYL_ID_STRING_BUF];
  return wyl_id_format (in->escrow_id, id, sizeof id) == WYRELOG_E_OK;
}

static wyrelog_error_t
service_handoff_binding_digest (const wyl_policy_service_handoff_escrow_input_t
    *in, guint8 out[32])
{
  crypto_generichash_state state;
  if (crypto_generichash_init (&state, NULL, 0, 32) != 0)
    return WYRELOG_E_CRYPTO;
  const gchar *parts[] = { "wyrelog.service-credential.handoff.binding.v1",
    in->operation, in->request_id, in->actor_subject_id, in->credential_id
  };
  for (gsize i = 0; i < G_N_ELEMENTS (parts); i++) {
    guint8 len[8];
    cvk_put_u64_be (len, strlen (parts[i]));
    if (crypto_generichash_update (&state, len, sizeof len) != 0
        || crypto_generichash_update (&state, (const guint8 *) parts[i],
            strlen (parts[i])) != 0)
      return WYRELOG_E_CRYPTO;
  }
  guint8 numbers[24];
  memcpy (numbers, in->escrow_id->bytes, WYL_ID_BYTES);
  cvk_put_u64_be (numbers + 16, in->credential_generation);
  if (crypto_generichash_update (&state, numbers, sizeof numbers) != 0
      || crypto_generichash_update (&state, in->target_digest, 32) != 0
      || crypto_generichash_final (&state, out, 32) != 0)
    return WYRELOG_E_CRYPTO;
  sodium_memzero (numbers, sizeof numbers);
  return WYRELOG_E_OK;
}

static void
service_handoff_build_envelope (guint8 out[WYL_SERVICE_HANDOFF_ENVELOPE_BYTES],
    const guint8 provider_binding[32], const guint8 binding_digest[32],
    const wyl_id_t *escrow_id, guint64 generation, gint64 deadline_at_us,
    const guint8 secret[WYL_SERVICE_CREDENTIAL_SECRET_BYTES])
{
  memcpy (out, WYL_SERVICE_HANDOFF_MAGIC, 8);
  memcpy (out + 8, WYL_SERVICE_HANDOFF_DOMAIN, 42);
  out[50] = 1;
  memcpy (out + 51, provider_binding, 32);
  memcpy (out + 83, binding_digest, 32);
  memcpy (out + 115, escrow_id->bytes, WYL_ID_BYTES);
  cvk_put_u64_be (out + 131, generation);
  cvk_put_u64_be (out + 139, (guint64) deadline_at_us);
  memmove (out + 147, secret, WYL_SERVICE_CREDENTIAL_SECRET_BYTES);
}

static gboolean
service_handoff_envelope_matches (const guint8 *envelope,
    const guint8 provider_binding[32],
    const wyl_policy_service_handoff_escrow_info_t *info)
{
  return memcmp (envelope, WYL_SERVICE_HANDOFF_MAGIC, 8) == 0
      && memcmp (envelope + 8, WYL_SERVICE_HANDOFF_DOMAIN, 42) == 0
      && envelope[50] == 1
      && sodium_memcmp (envelope + 51, provider_binding, 32) == 0
      && sodium_memcmp (envelope + 83, info->binding_digest, 32) == 0
      && sodium_memcmp (envelope + 115, info->escrow_id.bytes,
      WYL_ID_BYTES) == 0
      && cvk_get_u64_be (envelope + 131) == info->credential_generation
      && cvk_get_u64_be (envelope + 139) == (guint64) info->deadline_at_us;
}

static wyrelog_error_t
service_handoff_rewrap_one (wyl_policy_store_t *store,
    WylOwnedKeyProvider *new_provider,
    const guint8 old_binding[WYL_SERVICE_HANDOFF_BINDING_BYTES],
    const guint8 new_binding[WYL_SERVICE_HANDOFF_BINDING_BYTES],
    const wyl_id_t *escrow_id)
{
  wyl_policy_service_handoff_escrow_info_t info = { 0 };
  wyrelog_error_t rc = wyl_policy_store_service_handoff_escrow_load (store,
      escrow_id, &info);
  guint8 recomputed[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES] = { 0 };
  guint8 *sealed_copy = NULL;
  gsize sealed_len = 0;
  guint8 *envelope = NULL;
  wyl_sealed_blob_t sealed = { 0 };
  sqlite3_stmt *stmt = NULL;
  gchar id[WYL_ID_STRING_BUF];

  if (rc == WYRELOG_E_OK) {
    wyl_policy_service_handoff_escrow_input_t verified = {
      .escrow_id = &info.escrow_id,.operation = info.operation,
      .request_id = info.request_id,.actor_subject_id = info.actor_subject_id,
      .target_digest = info.target_digest,.credential_id = info.credential_id,
      .credential_generation = info.credential_generation,
      .deadline_at_us = info.deadline_at_us,
    };
    rc = service_handoff_binding_digest (&verified, recomputed);
    if (rc == WYRELOG_E_OK && sodium_memcmp (recomputed,
            info.binding_digest, sizeof recomputed) != 0)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_id_format (escrow_id, id, sizeof id);
  if (rc == WYRELOG_E_OK)
    rc = prepare_stmt (store->db,
        "SELECT sealed_envelope FROM service_credential_handoff_escrows "
        "WHERE escrow_id=?;", &stmt);
  if (rc == WYRELOG_E_OK
      && sqlite3_bind_text (stmt, 1, id, -1, SQLITE_TRANSIENT) != SQLITE_OK)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && sqlite3_step (stmt) == SQLITE_ROW
      && sqlite3_column_type (stmt, 0) == SQLITE_BLOB) {
    sealed_len = sqlite3_column_bytes (stmt, 0);
    if (sealed_len == 0 || sealed_len > 65536)
      rc = WYRELOG_E_POLICY;
    else
      sealed_copy = g_memdup2 (sqlite3_column_blob (stmt, 0), sealed_len);
    if (sealed_copy == NULL && rc == WYRELOG_E_OK)
      rc = WYRELOG_E_NOMEM;
  } else if (rc == WYRELOG_E_OK) {
    rc = WYRELOG_E_NOT_FOUND;
  }
  if (stmt != NULL) {
    sqlite3_finalize (stmt);
    stmt = NULL;
  }
  if (rc == WYRELOG_E_OK) {
    envelope = cvk_locked_alloc (store, WYL_SERVICE_HANDOFF_ENVELOPE_BYTES);
    if (envelope == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  gsize written = 0;
  if (rc == WYRELOG_E_OK) {
    wyl_sealed_blob_t old_sealed = {
      .bytes = sealed_copy,.len = sealed_len
    };
    rc = store->keyprovider.vtable.unseal (store->keyprovider.state,
        &old_sealed, envelope, WYL_SERVICE_HANDOFF_ENVELOPE_BYTES, &written);
  }
  if (rc == WYRELOG_E_OK && (written != WYL_SERVICE_HANDOFF_ENVELOPE_BYTES
          || !service_handoff_envelope_matches (envelope, old_binding, &info)))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    service_handoff_build_envelope (envelope, new_binding,
        info.binding_digest, &info.escrow_id, info.credential_generation,
        info.deadline_at_us, envelope + 147);
  if (rc == WYRELOG_E_OK)
    rc = new_provider->vtable.seal (new_provider->state, envelope,
        WYL_SERVICE_HANDOFF_ENVELOPE_BYTES, &sealed);
  if (rc == WYRELOG_E_OK && (sealed.bytes == NULL || sealed.len == 0
          || sealed.len > 65536 || sealed.len > G_MAXINT))
    rc = WYRELOG_E_CRYPTO;
  if (rc == WYRELOG_E_OK)
    rc = prepare_stmt (store->db,
        "UPDATE service_credential_handoff_escrows SET sealed_envelope=? "
        "WHERE escrow_id=? AND sealed_envelope=?;", &stmt);
  if (rc == WYRELOG_E_OK
      && (sqlite3_bind_blob (stmt, 1, sealed.bytes, (int) sealed.len,
              SQLITE_TRANSIENT) != SQLITE_OK
          || sqlite3_bind_text (stmt, 2, id, -1, SQLITE_TRANSIENT) != SQLITE_OK
          || sqlite3_bind_blob (stmt, 3, sealed_copy, (int) sealed_len,
              SQLITE_TRANSIENT) != SQLITE_OK))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && sqlite3_changes (store->db) != 1)
    rc = WYRELOG_E_POLICY;

  if (stmt != NULL)
    sqlite3_finalize (stmt);
  if (sealed.bytes != NULL)
    new_provider->vtable.clear_sealed_blob (new_provider->state, &sealed);
  if (sealed_copy != NULL) {
    sodium_memzero (sealed_copy, sealed_len);
    g_free (sealed_copy);
  }
  cvk_locked_free (store, envelope, WYL_SERVICE_HANDOFF_ENVELOPE_BYTES);
  sodium_memzero (recomputed, sizeof recomputed);
  wyl_policy_service_handoff_escrow_info_clear (&info);
  return rc;
}

static wyrelog_error_t
service_handoff_rewrap_all (wyl_policy_store_t *store,
    WylOwnedKeyProvider *new_provider)
{
  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = prepare_stmt (store->db,
      "SELECT escrow_id FROM service_credential_handoff_escrows;", &stmt);
  GPtrArray *ids = g_ptr_array_new_with_free_func (g_free);
  if (ids == NULL)
    rc = WYRELOG_E_NOMEM;
  int step = SQLITE_DONE;
  while (rc == WYRELOG_E_OK && (step = sqlite3_step (stmt)) == SQLITE_ROW) {
    if (sqlite3_column_type (stmt, 0) != SQLITE_TEXT) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    const gchar *id = (const gchar *) sqlite3_column_text (stmt, 0);
    gchar *copy = g_strdup (id);
    if (id == NULL || copy == NULL) {
      rc = id == NULL ? WYRELOG_E_POLICY : WYRELOG_E_NOMEM;
      g_free (copy);
      break;
    }
    g_ptr_array_add (ids, copy);
  }
  if (rc == WYRELOG_E_OK && step != SQLITE_DONE)
    rc = WYRELOG_E_IO;
  if (stmt != NULL)
    sqlite3_finalize (stmt);

  guint8 old_binding[WYL_SERVICE_HANDOFF_BINDING_BYTES] = { 0 };
  guint8 new_binding[WYL_SERVICE_HANDOFF_BINDING_BYTES] = { 0 };
  if (rc == WYRELOG_E_OK && ids->len != 0)
    rc = service_handoff_provider_binding_for (store, &store->keyprovider,
        old_binding);
  if (rc == WYRELOG_E_OK && ids->len != 0)
    rc = service_handoff_provider_binding_for (store, new_provider,
        new_binding);
  for (guint i = 0; rc == WYRELOG_E_OK && i < ids->len; i++) {
    wyl_id_t escrow_id;
    if (wyl_id_parse (g_ptr_array_index (ids, i), &escrow_id) != WYRELOG_E_OK)
      rc = WYRELOG_E_POLICY;
    else
      rc = service_handoff_rewrap_one (store, new_provider, old_binding,
          new_binding, &escrow_id);
  }
  sodium_memzero (old_binding, sizeof old_binding);
  sodium_memzero (new_binding, sizeof new_binding);
  if (ids != NULL)
    g_ptr_array_unref (ids);
  return rc;
}

wyrelog_error_t
wyl_policy_store_service_handoff_escrow_insert (wyl_policy_store_t *store,
    const wyl_policy_service_handoff_escrow_input_t *input)
{
  if (store == NULL || store->db == NULL
      || !service_handoff_input_valid (input))
    return WYRELOG_E_INVALID;
  if (!store->keyprovider.owned || store->keyprovider.vtable.probe
      (store->keyprovider.state) != WYRELOG_E_OK)
    return WYRELOG_E_CRYPTO;
  guint8 binding[32], computed_digest[32];
  wyrelog_error_t rc = service_handoff_binding_digest (input, computed_digest);
  if (rc != WYRELOG_E_OK
      || sodium_memcmp (computed_digest, input->binding_digest, 32) != 0) {
    sodium_memzero (computed_digest, sizeof computed_digest);
    return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
  }
  guint8 *envelope =
      cvk_locked_alloc (store, WYL_SERVICE_HANDOFF_ENVELOPE_BYTES);
  if (envelope == NULL)
    return WYRELOG_E_NOMEM;
  rc = service_handoff_provider_binding_for (store, &store->keyprovider,
      binding);
  if (rc == WYRELOG_E_OK)
    service_handoff_build_envelope (envelope, binding, input->binding_digest,
        input->escrow_id, input->credential_generation, input->deadline_at_us,
        input->secret);
  wyl_sealed_blob_t sealed = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = store->keyprovider.vtable.seal (store->keyprovider.state, envelope,
        WYL_SERVICE_HANDOFF_ENVELOPE_BYTES, &sealed);
  gchar id[WYL_ID_STRING_BUF];
  if (rc == WYRELOG_E_OK)
    rc = wyl_id_format (input->escrow_id, id, sizeof id);
  sqlite3_stmt *stmt = NULL;
  if (rc == WYRELOG_E_OK && (sealed.bytes == NULL || sealed.len == 0
          || sealed.len > 65536 || sealed.len > G_MAXINT))
    rc = WYRELOG_E_CRYPTO;
  if (rc == WYRELOG_E_OK)
    rc = prepare_stmt (store->db,
        "INSERT INTO service_credential_handoff_escrows"
        "(escrow_id,operation,request_id,actor_subject_id,target_digest,credential_id,"
        "credential_generation,deadline_at_us,binding_digest,sealed_envelope,created_at_us)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?);", &stmt);
  if (rc == WYRELOG_E_OK
      && (sqlite3_bind_text (stmt, 1, id, -1, SQLITE_TRANSIENT)
          != SQLITE_OK
          || sqlite3_bind_text (stmt, 2, input->operation, -1, SQLITE_TRANSIENT)
          != SQLITE_OK
          || sqlite3_bind_text (stmt, 3, input->request_id, -1,
              SQLITE_TRANSIENT)
          != SQLITE_OK
          || sqlite3_bind_text (stmt, 4, input->actor_subject_id, -1,
              SQLITE_TRANSIENT)
          != SQLITE_OK
          || sqlite3_bind_blob (stmt, 5, input->target_digest, 32,
              SQLITE_TRANSIENT)
          != SQLITE_OK
          || sqlite3_bind_text (stmt, 6, input->credential_id, -1,
              SQLITE_TRANSIENT)
          != SQLITE_OK
          || sqlite3_bind_int64 (stmt, 7, (gint64) input->credential_generation)
          != SQLITE_OK
          || sqlite3_bind_int64 (stmt, 8, input->deadline_at_us) != SQLITE_OK
          || sqlite3_bind_blob (stmt, 9, input->binding_digest, 32,
              SQLITE_TRANSIENT)
          != SQLITE_OK
          || sqlite3_bind_blob (stmt, 10, sealed.bytes, (int) sealed.len,
              SQLITE_TRANSIENT)
          != SQLITE_OK
          || sqlite3_bind_int64 (stmt, 11, g_get_real_time ()) != SQLITE_OK))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK) {
    int step = sqlite3_step (stmt);
    rc = step == SQLITE_DONE ? WYRELOG_E_OK :
        ((step == SQLITE_CONSTRAINT || step == SQLITE_CONSTRAINT_PRIMARYKEY
            || step ==
            SQLITE_CONSTRAINT_UNIQUE) ? WYRELOG_E_POLICY : WYRELOG_E_IO);
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  if (sealed.bytes != NULL)
    store->keyprovider.vtable.clear_sealed_blob
        (store->keyprovider.state, &sealed);
  sodium_memzero (binding, sizeof binding);
  sodium_memzero (computed_digest, sizeof computed_digest);
  cvk_locked_free (store, envelope, WYL_SERVICE_HANDOFF_ENVELOPE_BYTES);
  return rc;
}

wyrelog_error_t
wyl_policy_store_service_handoff_escrow_load (wyl_policy_store_t *store,
    const wyl_id_t *escrow_id, wyl_policy_service_handoff_escrow_info_t *out)
{
  if (out != NULL)
    wyl_policy_service_handoff_escrow_info_clear (out);
  if (store == NULL || store->db == NULL || escrow_id == NULL || out == NULL)
    return WYRELOG_E_INVALID;
  gchar id[WYL_ID_STRING_BUF];
  if (wyl_id_format (escrow_id, id, sizeof id) != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = prepare_stmt (store->db,
      "SELECT operation,request_id,actor_subject_id,target_digest,credential_id,"
      "credential_generation,deadline_at_us,binding_digest FROM "
      "service_credential_handoff_escrows WHERE escrow_id=?;", &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (sqlite3_bind_text (stmt, 1, id, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  int step = sqlite3_step (stmt);
  if (step == SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_NOT_FOUND;
  }
  if (step != SQLITE_ROW || sqlite3_column_type (stmt, 0) != SQLITE_TEXT
      || sqlite3_column_type (stmt, 1) != SQLITE_TEXT
      || sqlite3_column_type (stmt, 2) != SQLITE_TEXT
      || sqlite3_column_type (stmt, 4) != SQLITE_TEXT) {
    sqlite3_finalize (stmt);
    return step == SQLITE_ROW ? WYRELOG_E_POLICY : WYRELOG_E_IO;
  }
  const gchar *operation = (const gchar *) sqlite3_column_text (stmt, 0);
  const gchar *request = (const gchar *) sqlite3_column_text (stmt, 1);
  const gchar *actor = (const gchar *) sqlite3_column_text (stmt, 2);
  const gchar *credential = (const gchar *) sqlite3_column_text (stmt, 4);
  guint64 generation = 0;
  rc = read_fixed_blob (stmt, 3, out->target_digest, 32);
  if (rc == WYRELOG_E_OK)
    rc = read_positive_u64 (stmt, 5, &generation);
  if (rc == WYRELOG_E_OK && (sqlite3_column_type (stmt, 6) != SQLITE_INTEGER
          || sqlite3_column_int64 (stmt, 6) <= 0))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = read_fixed_blob (stmt, 7, out->binding_digest, 32);
  if (rc == WYRELOG_E_OK && (operation == NULL
          || (!g_str_equal (operation, "issue")
              && !g_str_equal (operation, "rotate"))
          || request == NULL || actor == NULL || credential == NULL
          || strlen (request) > 256
          || !wyl_policy_service_actor_subject_is_valid (actor)
          || !wyl_service_credential_id_is_canonical (credential,
              strlen (credential))))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK) {
    out->escrow_id = *escrow_id;
    out->operation = g_strdup (operation);
    out->request_id = g_strdup (request);
    out->actor_subject_id = g_strdup (actor);
    out->credential_id = g_strdup (credential);
    out->credential_generation = generation;
    out->deadline_at_us = sqlite3_column_int64 (stmt, 6);
    if (out->operation == NULL || out->request_id == NULL
        || out->actor_subject_id == NULL || out->credential_id == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  sqlite3_finalize (stmt);
  if (rc != WYRELOG_E_OK)
    wyl_policy_service_handoff_escrow_info_clear (out);
  return rc;
}

wyrelog_error_t
    wyl_policy_store_service_handoff_escrow_load_by_request
    (wyl_policy_store_t * store, const gchar * request_id,
    wyl_policy_service_handoff_escrow_info_t * out)
{
  if (out != NULL)
    wyl_policy_service_handoff_escrow_info_clear (out);
  if (store == NULL || store->db == NULL || out == NULL
      || !service_domain_text_is_valid (request_id, 256))
    return WYRELOG_E_INVALID;
  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = prepare_stmt (store->db,
      "SELECT escrow_id FROM service_credential_handoff_escrows "
      "WHERE request_id=?;", &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (sqlite3_bind_text (stmt, 1, request_id, -1, SQLITE_TRANSIENT)
      != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  int step = sqlite3_step (stmt);
  if (step == SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_NOT_FOUND;
  }
  if (step != SQLITE_ROW || sqlite3_column_type (stmt, 0) != SQLITE_TEXT) {
    sqlite3_finalize (stmt);
    return step == SQLITE_ROW ? WYRELOG_E_POLICY : WYRELOG_E_IO;
  }
  const gchar *id_text = (const gchar *) sqlite3_column_text (stmt, 0);
  wyl_id_t escrow_id;
  rc = id_text == NULL ? WYRELOG_E_POLICY : wyl_id_parse (id_text, &escrow_id);
  sqlite3_finalize (stmt);
  return rc == WYRELOG_E_OK ? wyl_policy_store_service_handoff_escrow_load
      (store, &escrow_id, out) : rc;
}

void wyl_policy_store_service_handoff_set_unseal_gate_for_test
    (wyl_policy_store_t * store,
    wyl_policy_store_service_handoff_unseal_gate_fn gate, gpointer data)
{
  if (store == NULL)
    return;
  store->service_handoff_unseal_gate = gate;
  store->service_handoff_unseal_gate_data = data;
}

wyrelog_error_t
wyl_policy_store_service_handoff_escrow_unseal (wyl_policy_store_t *store,
    const wyl_policy_service_handoff_escrow_info_t *expected,
    wyl_policy_service_handoff_secret_t **out_secret)
{
  if (out_secret != NULL)
    wyl_policy_service_handoff_secret_clear (out_secret);
  if (store == NULL || expected == NULL || out_secret == NULL
      || !store->keyprovider.owned)
    return WYRELOG_E_INVALID;
  wyl_policy_service_handoff_escrow_info_t actual = { 0 };
  wyrelog_error_t rc = wyl_policy_store_service_handoff_escrow_load (store,
      &expected->escrow_id, &actual);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (g_strcmp0 (actual.request_id, expected->request_id) != 0
      || g_strcmp0 (actual.operation, expected->operation) != 0
      || g_strcmp0 (actual.actor_subject_id, expected->actor_subject_id) != 0
      || g_strcmp0 (actual.credential_id, expected->credential_id) != 0
      || actual.credential_generation != expected->credential_generation
      || actual.deadline_at_us != expected->deadline_at_us
      || sodium_memcmp (actual.target_digest, expected->target_digest, 32) != 0
      || sodium_memcmp (actual.binding_digest, expected->binding_digest,
          32) != 0) {
    wyl_policy_service_handoff_escrow_info_clear (&actual);
    return WYRELOG_E_POLICY;
  }
  wyl_policy_service_handoff_escrow_input_t verified = {
    .escrow_id = &actual.escrow_id,.operation = actual.operation,
    .request_id = actual.request_id,.actor_subject_id = actual.actor_subject_id,
    .target_digest = actual.target_digest,.credential_id = actual.credential_id,
    .credential_generation = actual.credential_generation,
    .deadline_at_us = actual.deadline_at_us,
  };
  guint8 recomputed[32];
  rc = service_handoff_binding_digest (&verified, recomputed);
  if (rc != WYRELOG_E_OK
      || sodium_memcmp (recomputed, actual.binding_digest, 32) != 0) {
    sodium_memzero (recomputed, sizeof recomputed);
    wyl_policy_service_handoff_escrow_info_clear (&actual);
    return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
  }
  sodium_memzero (recomputed, sizeof recomputed);
  gchar id[WYL_ID_STRING_BUF];
  wyl_id_format (&expected->escrow_id, id, sizeof id);
  sqlite3_stmt *stmt = NULL;
  rc = prepare_stmt (store->db,
      "SELECT sealed_envelope FROM service_credential_handoff_escrows WHERE escrow_id=?;",
      &stmt);
  if (rc == WYRELOG_E_OK
      && sqlite3_bind_text (stmt, 1, id, -1, SQLITE_TRANSIENT) != SQLITE_OK)
    rc = WYRELOG_E_IO;
  guint8 *sealed_copy = NULL;
  gsize sealed_len = 0;
  if (rc == WYRELOG_E_OK && sqlite3_step (stmt) == SQLITE_ROW
      && sqlite3_column_type (stmt, 0) == SQLITE_BLOB) {
    sealed_len = sqlite3_column_bytes (stmt, 0);
    if (sealed_len > 0 && sealed_len <= 65536)
      sealed_copy = g_memdup2 (sqlite3_column_blob (stmt, 0), sealed_len);
    else
      rc = WYRELOG_E_POLICY;
    if (sealed_copy == NULL && rc == WYRELOG_E_OK)
      rc = WYRELOG_E_NOMEM;
  } else if (rc == WYRELOG_E_OK)
    rc = WYRELOG_E_NOT_FOUND;
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  guint8 binding[32];
  guint8 *envelope = NULL;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_provider_binding_for (store, &store->keyprovider,
        binding);
  if (rc == WYRELOG_E_OK) {
    envelope = cvk_locked_alloc (store, WYL_SERVICE_HANDOFF_ENVELOPE_BYTES);
    if (envelope == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  gsize written = 0;
  wyl_sealed_blob_t sealed = {.bytes = sealed_copy,.len = sealed_len };
  if (rc == WYRELOG_E_OK && store->service_handoff_unseal_gate != NULL)
    rc = store->service_handoff_unseal_gate
        (store->service_handoff_unseal_gate_data);
  if (rc == WYRELOG_E_OK)
    rc = store->keyprovider.vtable.unseal (store->keyprovider.state, &sealed,
        envelope, WYL_SERVICE_HANDOFF_ENVELOPE_BYTES, &written);
  if (rc != WYRELOG_E_OK || written != WYL_SERVICE_HANDOFF_ENVELOPE_BYTES
      || !service_handoff_envelope_matches (envelope, binding, &actual))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK) {
    wyl_policy_service_handoff_secret_t *secret =
        g_new0 (wyl_policy_service_handoff_secret_t, 1);
    if (secret == NULL)
      rc = WYRELOG_E_NOMEM;
    else {
      secret->bytes =
          cvk_locked_alloc (store, WYL_SERVICE_CREDENTIAL_SECRET_BYTES);
      if (secret->bytes == NULL) {
        g_free (secret);
        rc = WYRELOG_E_NOMEM;
      } else {
        memcpy (secret->bytes, envelope + 147, 32);
        secret->store = store;
        secret->len = 32;
        *out_secret = secret;
      }
    }
  }
  sodium_memzero (binding, sizeof binding);
  if (sealed_copy != NULL) {
    sodium_memzero (sealed_copy, sealed_len);
    g_free (sealed_copy);
  }
  cvk_locked_free (store, envelope, WYL_SERVICE_HANDOFF_ENVELOPE_BYTES);
  wyl_policy_service_handoff_escrow_info_clear (&actual);
  return rc;
}

static gboolean
service_handoff_request_id_is_canonical (const gchar *value)
{
  chronoid_ksuid_t parsed;
  gchar canonical[CHRONOID_KSUID_STRING_LEN + 1];
  if (value == NULL || strlen (value) != CHRONOID_KSUID_STRING_LEN
      || chronoid_ksuid_parse (&parsed, value, CHRONOID_KSUID_STRING_LEN)
      != CHRONOID_KSUID_OK)
    return FALSE;
  chronoid_ksuid_format (&parsed, canonical);
  return memcmp (value, canonical, CHRONOID_KSUID_STRING_LEN) == 0;
}

static gboolean
    service_handoff_exact_tuple_is_valid
    (const WylPolicyServiceHandoffExactTuple * tuple)
{
  gchar escrow_id[WYL_ID_STRING_BUF];
  if (tuple == NULL || tuple->escrow_id == NULL
      || wyl_id_format (tuple->escrow_id, escrow_id, sizeof escrow_id)
      != WYRELOG_E_OK
      || !service_handoff_request_id_is_canonical (tuple->original_request_id)
      || !wyl_policy_service_actor_subject_is_valid
      (tuple->original_actor_subject_id))
    return FALSE;
  if ((tuple->successor_credential_id == NULL)
      != (tuple->successor_issuance_generation == 0))
    return FALSE;
  return tuple->successor_credential_id == NULL
      || (wyl_service_credential_id_is_canonical
      (tuple->successor_credential_id, strlen (tuple->successor_credential_id))
      && tuple->successor_issuance_generation > 0
      && tuple->successor_issuance_generation <= G_MAXINT64
      && sodium_is_zero (tuple->binding_digest,
          WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES) == 0);
}

static wyrelog_error_t
service_handoff_validate_exact_escrow (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffExactTuple *tuple)
{
  gchar escrow_id[WYL_ID_STRING_BUF];
  if (wyl_id_format (tuple->escrow_id, escrow_id, sizeof escrow_id)
      != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT request_id,actor_subject_id,credential_id,"
      "credential_generation,binding_digest FROM"
      " service_credential_handoff_escrows WHERE escrow_id=?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 1, escrow_id);
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW) {
    const gchar *request = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *actor = (const gchar *) sqlite3_column_text (stmt, 1);
    const gchar *credential = (const gchar *) sqlite3_column_text (stmt, 2);
    gboolean exact = sqlite3_column_type (stmt, 0) == SQLITE_TEXT
        && sqlite3_column_type (stmt, 1) == SQLITE_TEXT
        && sqlite3_column_type (stmt, 2) == SQLITE_TEXT
        && sqlite3_column_type (stmt, 3) == SQLITE_INTEGER
        && sqlite3_column_type (stmt, 4) == SQLITE_BLOB
        && sqlite3_column_bytes (stmt, 4) ==
        WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES
        && g_strcmp0 (request, tuple->original_request_id) == 0
        && g_strcmp0 (actor, tuple->original_actor_subject_id) == 0
        && g_strcmp0 (credential, tuple->successor_credential_id) == 0
        && (guint64) sqlite3_column_int64 (stmt, 3) ==
        tuple->successor_issuance_generation
        && sodium_memcmp (sqlite3_column_blob (stmt, 4),
        tuple->binding_digest, WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES) == 0;
    int final_step = sqlite3_step (stmt);
    rc = exact && final_step == SQLITE_DONE ? WYRELOG_E_OK :
        (final_step == SQLITE_DONE ? WYRELOG_E_POLICY :
        service_handoff_sqlite_error (store->db, final_step));
  } else if (rc == WYRELOG_E_OK) {
    rc = step == SQLITE_DONE ? WYRELOG_E_POLICY :
        service_handoff_sqlite_error (store->db, step);
  } else {
    rc = service_handoff_map_sqlite_io (store->db, rc);
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return rc;
}

void wyl_policy_service_successor_exact_classification_clear
    (WylPolicyServiceSuccessorExactClassification * classification)
{
  if (classification == NULL)
    return;
  g_clear_pointer (&classification->observed_state, g_free);
  g_clear_pointer (&classification->revocation_event_actor_subject_id, g_free);
  g_clear_pointer (&classification->revocation_event_request_id, g_free);
  memset (classification, 0, sizeof *classification);
}

static gchar *
service_handoff_try_strdup (const gchar *value)
{
  gsize len = strlen (value) + 1;
  gchar *copy = g_try_malloc (len);
  if (copy != NULL)
    memcpy (copy, value, len);
  return copy;
}

static wyrelog_error_t
service_handoff_load_successor_credential (wyl_policy_store_t *store,
    const gchar *credential_id, wyl_policy_service_credential_info_t *out)
{
  if (service_handoff_should_fail (store,
          WYL_POLICY_HANDOFF_FAIL_CLASSIFIER_LOOKUP_NOMEM))
    return service_handoff_sqlite_error (store->db, SQLITE_NOMEM);
  wyrelog_error_t rc = wyl_policy_store_lookup_service_credential_by_id
      (store, credential_id, out);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
service_credential_load_exact_revoked_event (wyl_policy_store_t *store,
    const wyl_policy_service_credential_info_t *credential,
    guint64 expected_generation,
    WylPolicyServiceSuccessorExactClassification *classification)
{
  if (service_handoff_should_fail (store,
          WYL_POLICY_HANDOFF_FAIL_CLASSIFIER_REVOKED_EVENT_NOMEM))
    return service_handoff_sqlite_error (store->db, SQLITE_NOMEM);
  if (credential->revoked_by == NULL || credential->revoked_at_us <= 0
      || credential->updated_at_us != credential->revoked_at_us)
    return WYRELOG_E_POLICY;
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT event_id,subject_id,tenant_id,from_state,to_state,generation,"
      " actor_subject_id,request_id,created_at_us FROM service_credential_events"
      " WHERE credential_id=? AND event='revoked';";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK
      && (rc = bind_text (stmt, 1, credential->credential_id))
      != WYRELOG_E_OK)
    rc = service_handoff_map_sqlite_io (store->db, WYRELOG_E_IO);
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK && step != SQLITE_ROW) {
    rc = step == SQLITE_DONE ? WYRELOG_E_POLICY :
        service_handoff_sqlite_error (store->db, step);
  } else if (rc == WYRELOG_E_OK) {
    const gchar *subject_id = (const gchar *) sqlite3_column_text (stmt, 1);
    const gchar *tenant_id = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *from_state = (const gchar *) sqlite3_column_text (stmt, 3);
    const gchar *to_state = (const gchar *) sqlite3_column_text (stmt, 4);
    const gchar *actor = (const gchar *) sqlite3_column_text (stmt, 6);
    const gchar *request_id = (const gchar *) sqlite3_column_text (stmt, 7);
    if (sqlite3_column_type (stmt, 0) != SQLITE_INTEGER
        || sqlite3_column_int64 (stmt, 0) <= 0
        || sqlite3_column_type (stmt, 5) != SQLITE_INTEGER
        || sqlite3_column_int64 (stmt, 5) <= 0
        || sqlite3_column_type (stmt, 8) != SQLITE_INTEGER
        || sqlite3_column_int64 (stmt, 8) <= 0
        || g_strcmp0 (subject_id, credential->subject_id) != 0
        || g_strcmp0 (tenant_id, credential->tenant_id) != 0
        || g_strcmp0 (from_state, "active") != 0
        || g_strcmp0 (to_state, "revoked") != 0
        || (guint64) sqlite3_column_int64 (stmt, 5) != expected_generation
        || g_strcmp0 (actor, credential->revoked_by) != 0
        || sqlite3_column_int64 (stmt, 8) != credential->revoked_at_us
        || !service_domain_text_is_valid (request_id, 256)) {
      rc = WYRELOG_E_POLICY;
    } else {
      classification->has_revocation_event = TRUE;
      classification->revocation_event_id = sqlite3_column_int64 (stmt, 0);
      classification->revocation_event_generation = expected_generation;
      classification->revocation_event_actor_subject_id =
          service_handoff_try_strdup (actor);
      classification->revocation_event_request_id =
          service_handoff_try_strdup (request_id);
      classification->revocation_event_created_at_us =
          sqlite3_column_int64 (stmt, 8);
      if (classification->revocation_event_actor_subject_id == NULL
          || classification->revocation_event_request_id == NULL)
        rc = WYRELOG_E_NOMEM;
      else {
        int second = sqlite3_step (stmt);
        if (second != SQLITE_DONE)
          rc = second == SQLITE_ROW ? WYRELOG_E_POLICY :
              service_handoff_sqlite_error (store->db, second);
      }
    }
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
    service_handoff_classify_successor_without_escrow
    (wyl_policy_store_t * store,
    const WylPolicyServiceHandoffExactTuple * tuple, gint64 now_us,
    WylPolicyServiceSuccessorExactClassification * out_classification)
{
  if (out_classification != NULL)
    wyl_policy_service_successor_exact_classification_clear
        (out_classification);
  if (store == NULL || store->db == NULL || out_classification == NULL
      || now_us <= 0 || !service_handoff_exact_tuple_is_valid (tuple)
      || tuple->successor_credential_id == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = WYRELOG_E_OK;
  wyl_policy_service_credential_info_t credential = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_load_successor_credential (store,
        tuple->successor_credential_id, &credential);
  if (rc == WYRELOG_E_NOT_FOUND)
    rc = WYRELOG_E_POLICY;
  WylPolicyServiceSuccessorExactClassification classification = { 0 };
  if (rc == WYRELOG_E_OK && g_str_equal (credential.state, "active")) {
    if (credential.generation != tuple->successor_issuance_generation)
      rc = WYRELOG_E_POLICY;
    else {
      classification.disposition = credential.expires_at_us != 0
          && credential.expires_at_us <= now_us ?
          WYL_POLICY_SERVICE_SUCCESSOR_EXPIRED :
          WYL_POLICY_SERVICE_SUCCESSOR_ACTIVE;
      classification.observed_state = service_handoff_try_strdup
          (credential.state);
      classification.observed_generation = credential.generation;
      classification.observed_expires_at_us = credential.expires_at_us;
      if (classification.observed_state == NULL)
        rc = WYRELOG_E_NOMEM;
    }
  } else if (rc == WYRELOG_E_OK && g_str_equal (credential.state, "revoked")) {
    if (tuple->successor_issuance_generation >= G_MAXINT64
        || credential.generation != tuple->successor_issuance_generation + 1)
      rc = WYRELOG_E_POLICY;
    else
      rc = service_credential_load_exact_revoked_event (store, &credential,
          tuple->successor_issuance_generation + 1, &classification);
    if (rc == WYRELOG_E_OK) {
      classification.disposition = WYL_POLICY_SERVICE_SUCCESSOR_REVOKED;
      classification.observed_state = service_handoff_try_strdup
          (credential.state);
      classification.observed_generation = credential.generation;
      classification.observed_expires_at_us = credential.expires_at_us;
      if (classification.observed_state == NULL)
        rc = WYRELOG_E_NOMEM;
    }
  } else if (rc == WYRELOG_E_OK) {
    rc = WYRELOG_E_POLICY;
  }
  wyl_policy_service_credential_info_clear (&credential);
  if (rc == WYRELOG_E_OK)
    *out_classification = classification;
  else
    wyl_policy_service_successor_exact_classification_clear (&classification);
  return rc;
}

wyrelog_error_t
    wyl_policy_store_classify_service_credential_successor_exact_core
    (WylServiceAuthorityTransaction * transaction,
    wyl_policy_store_t * store,
    const WylPolicyServiceHandoffExactTuple * tuple, gint64 now_us,
    WylPolicyServiceSuccessorExactClassification * out_classification)
{
  if (out_classification != NULL)
    wyl_policy_service_successor_exact_classification_clear
        (out_classification);
  if (store == NULL || store->db == NULL || out_classification == NULL
      || now_us <= 0 || !service_handoff_exact_tuple_is_valid (tuple)
      || tuple->successor_credential_id == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc =
      wyl_policy_store_service_authority_transaction_enter_participant
      (transaction, store);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_validate_exact_escrow (store, tuple);
  return rc == WYRELOG_E_OK ?
      service_handoff_classify_successor_without_escrow (store, tuple,
      now_us, out_classification) : rc;
}

static wyrelog_error_t
service_handoff_lookup_minted_disposition (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffExactTuple *tuple,
    WylPolicyServiceHandoffDispositionReason reason,
    WylPolicyServiceHandoffDispositionOutcome outcome, gboolean *out_found,
    WylPolicyServiceHandoffDispositionResult *out)
{
  gchar escrow[WYL_ID_STRING_BUF];
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT disposition_id,semantic_key,audit_id,created_at_us,"
      " actor_subject_id FROM"
      " service_credential_handoff_dispositions WHERE original_request_id=?"
      " AND reason=? AND outcome=? AND escrow_id=? AND binding_digest=?"
      " AND successor_credential_id=? AND successor_issuance_generation=?"
      " LIMIT 2;";
  *out_found = FALSE;
  if (wyl_id_format (tuple->escrow_id, escrow, sizeof escrow) != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK
      && ((rc = bind_text (stmt, 1, tuple->original_request_id))
          != WYRELOG_E_OK
          || (rc = bind_text (stmt, 2, service_handoff_reason_name (reason)))
          != WYRELOG_E_OK
          || (rc = bind_text (stmt, 3,
                  service_handoff_outcome_name (outcome))) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 4, escrow)) != WYRELOG_E_OK
          || sqlite3_bind_blob (stmt, 5, tuple->binding_digest, 32,
              SQLITE_TRANSIENT) != SQLITE_OK
          || (rc = bind_text (stmt, 6, tuple->successor_credential_id))
          != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 7,
              (sqlite3_int64) tuple->successor_issuance_generation)
          != SQLITE_OK))
    rc = service_handoff_sqlite_error (store->db,
        sqlite3_extended_errcode (store->db));
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW) {
    const gchar *disposition_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *audit_id = (const gchar *) sqlite3_column_text (stmt, 2);
    gint64 created_at_us = sqlite3_column_int64 (stmt, 3);
    const gchar *stored_actor = (const gchar *) sqlite3_column_text (stmt, 4);
    WylPolicyServiceHandoffDispositionInput input = {
      .disposition_id = disposition_id,
      .audit_id = audit_id,
      .tuple = *tuple,
      .actor_subject_id = stored_actor,
      .reason = reason,
      .outcome = outcome,
    };
    guint8 semantic_key[crypto_generichash_BYTES] = { 0 };
    rc = disposition_id != NULL && audit_id != NULL
        && wyl_policy_service_actor_subject_is_valid (stored_actor)
        && sqlite3_column_type (stmt, 1) == SQLITE_BLOB
        && sqlite3_column_bytes (stmt, 1) == sizeof semantic_key
        && sqlite3_column_type (stmt, 3) == SQLITE_INTEGER
        && created_at_us > 0 ? service_handoff_disposition_semantic_key
        (&input, semantic_key) : WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK
        && sodium_memcmp (sqlite3_column_blob (stmt, 1), semantic_key,
            sizeof semantic_key) != 0)
      rc = WYRELOG_E_POLICY;
    sodium_memzero (semantic_key, sizeof semantic_key);
    if (rc == WYRELOG_E_OK)
      rc = service_handoff_validate_exact_audit_pair (store, audit_id,
          created_at_us, stored_actor,
          "service.credential.handoff.disposition",
          tuple->original_request_id, tuple->original_request_id);
    if (rc == WYRELOG_E_OK)
      rc = service_handoff_fill_disposition_result (disposition_id, audit_id,
          created_at_us, TRUE, out);
    if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK)
      *out_found = TRUE;
  } else if (rc == WYRELOG_E_OK && step != SQLITE_DONE) {
    rc = service_handoff_sqlite_error (store->db, step);
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
service_handoff_record_minted_disposition (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffExactTuple *tuple,
    const gchar *actor_subject_id,
    WylPolicyServiceHandoffDispositionReason reason,
    WylPolicyServiceHandoffDispositionOutcome outcome, gint64 now_us,
    WylPolicyServiceHandoffDispositionResult *out)
{
  gchar disposition_id[WYL_ID_STRING_BUF];
  gchar audit_id[WYL_ID_STRING_BUF];
  wyrelog_error_t rc = service_domain_new_audit_id (disposition_id);
  if (rc == WYRELOG_E_OK)
    rc = service_domain_new_audit_id (audit_id);
  WylPolicyServiceHandoffDispositionInput input = {
    .disposition_id = disposition_id,
    .audit_id = audit_id,
    .tuple = *tuple,
    .actor_subject_id = actor_subject_id,
    .reason = reason,
    .outcome = outcome,
  };
  guint8 semantic_key[crypto_generichash_BYTES] = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_disposition_semantic_key (&input, semantic_key);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_append_audit_strict (store, audit_id, now_us,
        actor_subject_id, "service.credential.handoff.disposition",
        tuple->original_request_id, tuple->original_request_id);
  if (rc == WYRELOG_E_OK && service_handoff_should_fail (store,
          WYL_POLICY_HANDOFF_FAIL_AFTER_AUDIT))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_disposition_insert (store, &input, semantic_key,
        now_us);
  if (rc == WYRELOG_E_OK && service_handoff_should_fail (store,
          WYL_POLICY_HANDOFF_FAIL_AFTER_PROVENANCE))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_fill_disposition_result (disposition_id, audit_id,
        now_us, FALSE, out);
  sodium_memzero (semantic_key, sizeof semantic_key);
  return rc;
}

static wyrelog_error_t
    service_handoff_lookup_minted_inactive_disposition
    (wyl_policy_store_t * store,
    const WylPolicyServiceHandoffExactTuple * tuple, gboolean * out_found,
    WylPolicyServiceHandoffPublicationOutcome * out_outcome,
    WylPolicyServiceHandoffDispositionResult * out_disposition)
{
  gboolean expired_found = FALSE;
  gboolean revoked_found = FALSE;
  WylPolicyServiceHandoffDispositionResult expired = { 0 };
  WylPolicyServiceHandoffDispositionResult revoked = { 0 };
  wyrelog_error_t rc = service_handoff_lookup_minted_disposition (store,
      tuple, WYL_POLICY_HANDOFF_DISPOSITION_SUCCESSOR_EXPIRED,
      WYL_POLICY_HANDOFF_OUTCOME_OPERATOR_ACTION_REQUIRED, &expired_found,
      &expired);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_lookup_minted_disposition (store, tuple,
        WYL_POLICY_HANDOFF_DISPOSITION_SUCCESSOR_REVOKED,
        WYL_POLICY_HANDOFF_OUTCOME_OPERATOR_ACTION_REQUIRED, &revoked_found,
        &revoked);
  if (rc == WYRELOG_E_OK && expired_found && revoked_found)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && expired_found) {
    *out_found = TRUE;
    *out_outcome = WYL_POLICY_HANDOFF_PUBLICATION_SUCCESSOR_EXPIRED;
    *out_disposition = expired;
    memset (&expired, 0, sizeof expired);
  } else if (rc == WYRELOG_E_OK && revoked_found) {
    *out_found = TRUE;
    *out_outcome = WYL_POLICY_HANDOFF_PUBLICATION_SUCCESSOR_REVOKED;
    *out_disposition = revoked;
    memset (&revoked, 0, sizeof revoked);
  }
  wyl_policy_service_handoff_disposition_result_clear (&expired);
  wyl_policy_service_handoff_disposition_result_clear (&revoked);
  return rc;
}

static wyrelog_error_t
    service_handoff_classify_for_publication_at
    (WylServiceAuthorityTransaction * transaction, wyl_policy_store_t * store,
    const WylPolicyServiceHandoffExactTuple * tuple,
    const gchar * actor_subject_id, gint64 now_us,
    WylPolicyServiceHandoffPublicationOutcome * out_outcome,
    WylPolicyServiceHandoffDispositionResult * out_disposition)
{
  if (out_disposition != NULL)
    wyl_policy_service_handoff_disposition_result_clear (out_disposition);
  if (store == NULL || tuple == NULL || out_outcome == NULL
      || out_disposition == NULL
      || !service_handoff_exact_tuple_is_valid (tuple)
      || tuple->successor_credential_id == NULL
      || now_us <= 0
      || !wyl_policy_service_actor_subject_is_valid (actor_subject_id))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc =
      wyl_policy_store_service_authority_transaction_enter_participant
      (transaction, store);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_validate_exact_escrow (store, tuple);
  gboolean found = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_lookup_minted_inactive_disposition (store, tuple,
        &found, out_outcome, out_disposition);
  if (rc != WYRELOG_E_OK || found)
    return rc;

  WylPolicyServiceSuccessorExactClassification classification = { 0 };
  rc = wyl_policy_store_classify_service_credential_successor_exact_core
      (transaction, store, tuple, now_us, &classification);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (classification.disposition == WYL_POLICY_SERVICE_SUCCESSOR_ACTIVE) {
    *out_outcome = WYL_POLICY_HANDOFF_PUBLICATION_ACTIVE;
    wyl_policy_service_successor_exact_classification_clear (&classification);
    return WYRELOG_E_OK;
  }
  WylPolicyServiceHandoffDispositionReason reason =
      classification.disposition == WYL_POLICY_SERVICE_SUCCESSOR_EXPIRED ?
      WYL_POLICY_HANDOFF_DISPOSITION_SUCCESSOR_EXPIRED :
      WYL_POLICY_HANDOFF_DISPOSITION_SUCCESSOR_REVOKED;
  WylPolicyServiceHandoffPublicationOutcome outcome =
      classification.disposition == WYL_POLICY_SERVICE_SUCCESSOR_EXPIRED ?
      WYL_POLICY_HANDOFF_PUBLICATION_SUCCESSOR_EXPIRED :
      WYL_POLICY_HANDOFF_PUBLICATION_SUCCESSOR_REVOKED;
  wyl_policy_service_successor_exact_classification_clear (&classification);
  rc = service_handoff_record_minted_disposition (store, tuple,
      actor_subject_id, reason,
      WYL_POLICY_HANDOFF_OUTCOME_OPERATOR_ACTION_REQUIRED, now_us,
      out_disposition);
  if (rc == WYRELOG_E_OK)
    *out_outcome = outcome;
  return rc;
}

wyrelog_error_t
    wyl_policy_store_handoff_classify_for_publication_core
    (WylServiceAuthorityTransaction * transaction, wyl_policy_store_t * store,
    const WylPolicyServiceHandoffExactTuple * tuple,
    const gchar * actor_subject_id,
    WylPolicyServiceHandoffPublicationOutcome * out_outcome,
    WylPolicyServiceHandoffDispositionResult * out_disposition)
{
  return service_handoff_classify_for_publication_at (transaction, store,
      tuple, actor_subject_id, g_get_real_time (), out_outcome,
      out_disposition);
}

static wyrelog_error_t
    service_handoff_delivered_semantic_key
    (const WylPolicyServiceHandoffExactTuple * tuple,
    const gchar * actor_subject_id,
    const guint8 proof_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES],
    guint8 out[crypto_generichash_BYTES])
{
  gchar escrow[WYL_ID_STRING_BUF];
  gchar generation[32];
  gchar binding[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES * 2 + 1];
  gchar proof[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES * 2 + 1];
  if (wyl_id_format (tuple->escrow_id, escrow, sizeof escrow)
      != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  g_snprintf (generation, sizeof generation, "%" G_GUINT64_FORMAT,
      tuple->successor_issuance_generation);
  sodium_bin2hex (binding, sizeof binding, tuple->binding_digest,
      sizeof tuple->binding_digest);
  sodium_bin2hex (proof, sizeof proof, proof_digest,
      WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES);
  const gchar *fields[] = {
    tuple->original_request_id, escrow, binding,
    tuple->successor_credential_id, generation,
    tuple->original_actor_subject_id, actor_subject_id,
    "delivered", "escrow_deleted", "journal-v5-receipt-v1", proof,
  };
  return service_handoff_hash_fields
      ("wyrelog.service-handoff-delivered.v1", fields,
      G_N_ELEMENTS (fields), out);
}

static wyrelog_error_t
service_handoff_lookup_delivered (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffExactTuple *tuple,
    const gchar *actor_subject_id,
    const guint8 proof_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES],
    gboolean *out_found, WylPolicyServiceHandoffDispositionResult *out)
{
  gchar escrow[WYL_ID_STRING_BUF];
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT disposition_id,semantic_key,audit_id,created_at_us FROM"
      " service_credential_handoff_dispositions WHERE original_request_id=?"
      " AND reason='delivered' AND outcome='escrow_deleted'"
      " AND escrow_id=? AND binding_digest=? AND successor_credential_id=?"
      " AND successor_issuance_generation=? AND actor_subject_id=? LIMIT 2;";
  *out_found = FALSE;
  if (wyl_id_format (tuple->escrow_id, escrow, sizeof escrow) != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK
      && ((rc = bind_text (stmt, 1, tuple->original_request_id))
          != WYRELOG_E_OK
          || (rc = bind_text (stmt, 2, escrow)) != WYRELOG_E_OK
          || sqlite3_bind_blob (stmt, 3, tuple->binding_digest, 32,
              SQLITE_TRANSIENT) != SQLITE_OK
          || (rc = bind_text (stmt, 4, tuple->successor_credential_id))
          != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 5,
              (sqlite3_int64) tuple->successor_issuance_generation)
          != SQLITE_OK
          || (rc = bind_text (stmt, 6, actor_subject_id)) != WYRELOG_E_OK))
    rc = service_handoff_sqlite_error (store->db,
        sqlite3_extended_errcode (store->db));
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW) {
    const gchar *disposition_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *audit_id = (const gchar *) sqlite3_column_text (stmt, 2);
    gint64 created_at_us = sqlite3_column_int64 (stmt, 3);
    guint8 semantic_key[crypto_generichash_BYTES] = { 0 };
    rc = disposition_id != NULL && audit_id != NULL
        && sqlite3_column_type (stmt, 1) == SQLITE_BLOB
        && sqlite3_column_bytes (stmt, 1) == sizeof semantic_key
        && sqlite3_column_type (stmt, 3) == SQLITE_INTEGER
        && created_at_us > 0 ? service_handoff_delivered_semantic_key
        (tuple, actor_subject_id, proof_digest, semantic_key) :
        WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK
        && sodium_memcmp (sqlite3_column_blob (stmt, 1), semantic_key,
            sizeof semantic_key) != 0)
      rc = WYRELOG_E_POLICY;
    sodium_memzero (semantic_key, sizeof semantic_key);
    if (rc == WYRELOG_E_OK)
      rc = service_handoff_validate_exact_audit_pair (store, audit_id,
          created_at_us, actor_subject_id,
          "service.credential.handoff.disposition",
          tuple->original_request_id, tuple->original_request_id);
    if (rc == WYRELOG_E_OK)
      rc = service_handoff_fill_disposition_result (disposition_id, audit_id,
          created_at_us, TRUE, out);
    if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK)
      *out_found = TRUE;
  } else if (rc == WYRELOG_E_OK && step != SQLITE_DONE) {
    rc = service_handoff_sqlite_error (store->db, step);
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
service_handoff_record_delivered (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffExactTuple *tuple,
    const gchar *actor_subject_id,
    const guint8 proof_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES],
    gint64 now_us, WylPolicyServiceHandoffDispositionResult *out)
{
  gchar disposition_id[WYL_ID_STRING_BUF];
  gchar audit_id[WYL_ID_STRING_BUF];
  wyrelog_error_t rc = service_domain_new_audit_id (disposition_id);
  if (rc == WYRELOG_E_OK)
    rc = service_domain_new_audit_id (audit_id);
  WylPolicyServiceHandoffDispositionInput input = {
    .disposition_id = disposition_id,
    .audit_id = audit_id,
    .tuple = *tuple,
    .actor_subject_id = actor_subject_id,
    .reason = WYL_POLICY_HANDOFF_DISPOSITION_DELIVERED,
    .outcome = WYL_POLICY_HANDOFF_OUTCOME_ESCROW_DELETED,
  };
  guint8 semantic_key[crypto_generichash_BYTES] = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_delivered_semantic_key (tuple, actor_subject_id,
        proof_digest, semantic_key);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_append_audit_strict (store, audit_id, now_us,
        actor_subject_id, "service.credential.handoff.disposition",
        tuple->original_request_id, tuple->original_request_id);
  if (rc == WYRELOG_E_OK && service_handoff_should_fail (store,
          WYL_POLICY_HANDOFF_FAIL_AFTER_AUDIT))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_disposition_insert (store, &input, semantic_key,
        now_us);
  if (rc == WYRELOG_E_OK && service_handoff_should_fail (store,
          WYL_POLICY_HANDOFF_FAIL_AFTER_PROVENANCE))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_fill_disposition_result (disposition_id, audit_id,
        now_us, FALSE, out);
  sodium_memzero (semantic_key, sizeof semantic_key);
  return rc;
}

wyrelog_error_t
    wyl_policy_store_handoff_lookup_delivered_core
    (WylServiceAuthorityTransaction * transaction, wyl_policy_store_t * store,
    const WylPolicyServiceHandoffExactTuple * tuple,
    const gchar * actor_subject_id,
    const guint8 proof_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES],
    gboolean * out_found,
    WylPolicyServiceHandoffDispositionResult * out_disposition)
{
  if (out_found != NULL)
    *out_found = FALSE;
  if (out_disposition != NULL)
    wyl_policy_service_handoff_disposition_result_clear (out_disposition);
  if (store == NULL || out_found == NULL || out_disposition == NULL
      || proof_digest == NULL || sodium_is_zero (proof_digest, 32)
      || !service_handoff_exact_tuple_is_valid (tuple)
      || tuple->successor_credential_id == NULL
      || !wyl_policy_service_actor_subject_is_valid (actor_subject_id))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc =
      wyl_policy_store_service_authority_transaction_enter_participant
      (transaction, store);
  return rc == WYRELOG_E_OK ? service_handoff_lookup_delivered
      (store, tuple, actor_subject_id, proof_digest, out_found,
      out_disposition) : rc;
}

wyrelog_error_t
    wyl_policy_store_handoff_backfill_delivered_core
    (WylServiceAuthorityTransaction * transaction, wyl_policy_store_t * store,
    const WylPolicyServiceHandoffExactTuple * tuple,
    const gchar * actor_subject_id,
    const guint8 proof_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES],
    WylPolicyServiceHandoffDispositionResult * out_disposition)
{
  if (out_disposition != NULL)
    wyl_policy_service_handoff_disposition_result_clear (out_disposition);
  if (store == NULL || out_disposition == NULL || proof_digest == NULL
      || sodium_is_zero (proof_digest, 32)
      || !service_handoff_exact_tuple_is_valid (tuple)
      || tuple->successor_credential_id == NULL
      || !wyl_policy_service_actor_subject_is_valid (actor_subject_id))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc =
      wyl_policy_store_service_authority_transaction_enter_participant
      (transaction, store);
  gint64 now_us = rc == WYRELOG_E_OK ? g_get_real_time () : 0;
  gboolean found = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_lookup_delivered (store, tuple, actor_subject_id,
        proof_digest, &found, out_disposition);
  if (rc == WYRELOG_E_OK && found)
    return WYRELOG_E_OK;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_escrow_absent (store, tuple->escrow_id);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_request_escrow_absent (store,
        tuple->original_request_id);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_record_delivered (store, tuple, actor_subject_id,
        proof_digest, now_us, out_disposition);
  return rc;
}

wyrelog_error_t
    wyl_policy_store_handoff_consume_delivered_core
    (WylServiceAuthorityTransaction * transaction, wyl_policy_store_t * store,
    const WylPolicyServiceHandoffExactTuple * tuple,
    const gchar * actor_subject_id,
    const guint8 proof_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES],
    WylPolicyServiceHandoffPublicationOutcome * out_outcome,
    WylPolicyServiceHandoffDispositionResult * out_disposition)
{
  if (out_outcome != NULL)
    *out_outcome = 0;
  if (out_disposition != NULL)
    wyl_policy_service_handoff_disposition_result_clear (out_disposition);
  if (store == NULL || out_outcome == NULL || out_disposition == NULL
      || proof_digest == NULL || sodium_is_zero (proof_digest, 32)
      || !service_handoff_exact_tuple_is_valid (tuple)
      || tuple->successor_credential_id == NULL
      || !wyl_policy_service_actor_subject_is_valid (actor_subject_id))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc =
      wyl_policy_store_service_authority_transaction_enter_participant
      (transaction, store);
  gint64 now_us = rc == WYRELOG_E_OK ? g_get_real_time () : 0;
  gboolean found = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_lookup_delivered (store, tuple, actor_subject_id,
        proof_digest, &found, out_disposition);
  if (rc == WYRELOG_E_OK && found)
    rc = WYRELOG_E_POLICY;
  WylPolicyServiceHandoffPublicationOutcome outcome = 0;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_handoff_classify_for_publication_core (transaction,
        store, tuple, actor_subject_id, &outcome, out_disposition);
  if (rc == WYRELOG_E_OK && outcome != WYL_POLICY_HANDOFF_PUBLICATION_ACTIVE) {
    *out_outcome = outcome;
    return WYRELOG_E_OK;
  }
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_record_delivered (store, tuple, actor_subject_id,
        proof_digest, now_us, out_disposition);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_delete_exact (store, tuple);
  if (rc == WYRELOG_E_OK && service_handoff_should_fail (store,
          WYL_POLICY_HANDOFF_FAIL_AFTER_ESCROW_DELETE))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    *out_outcome = WYL_POLICY_HANDOFF_PUBLICATION_ACTIVE;
  return rc;
}

#define SERVICE_HANDOFF_MAINTENANCE_ACTOR \
  "system:service-handoff-maintenance"

void wyl_policy_service_handoff_prepared_maintenance_result_clear
    (WylPolicyServiceHandoffPreparedMaintenanceResult * result)
{
  if (result == NULL)
    return;
  wyl_policy_service_handoff_disposition_result_clear (&result->disposition);
  sodium_memzero (result, sizeof *result);
}

void wyl_policy_service_handoff_committed_maintenance_result_clear
    (WylPolicyServiceHandoffCommittedMaintenanceResult * result)
{
  if (result == NULL)
    return;
  wyl_policy_service_handoff_disposition_result_clear (&result->disposition);
  sodium_memzero (result, sizeof *result);
}

void wyl_policy_store_handoff_maintenance_set_clock_for_test
    (wyl_policy_store_t * store,
    WylPolicyServiceHandoffMaintenanceNowFunc now_us, gpointer data)
{
  if (store == NULL)
    return;
  store->service_handoff_maintenance_now = now_us;
  store->service_handoff_maintenance_clock_data = now_us != NULL ? data : NULL;
}

static wyrelog_error_t
service_handoff_maintenance_now (wyl_policy_store_t *store, gint64 *out_now_us)
{
  gint64 now_us = store->service_handoff_maintenance_now != NULL ?
      store->service_handoff_maintenance_now
      (store->service_handoff_maintenance_clock_data) : g_get_real_time ();
  if (now_us <= 0)
    return WYRELOG_E_INVALID;
  *out_now_us = now_us;
  return WYRELOG_E_OK;
}

void wyl_policy_service_handoff_retirement_result_clear
    (WylPolicyServiceHandoffRetirementResult * result)
{
  if (result == NULL)
    return;
  g_free (result->original_request_id);
  g_free (result->delivery_disposition_id);
  g_free (result->delivery_audit_id);
  g_free (result->revoke_remediation_request_id);
  g_free (result->revoke_audit_id);
  g_free (result->resume_remediation_request_id);
  g_free (result->resume_audit_id);
  sodium_memzero (result, sizeof *result);
}

static const gchar *service_handoff_retirement_kind_name
    (WylPolicyServiceHandoffRetirementKind kind)
{
  return kind == WYL_POLICY_HANDOFF_RETIREMENT_FILE_PUBLISHED ?
      "file_published" :
      (kind == WYL_POLICY_HANDOFF_RETIREMENT_OPERATOR_REVOKE_AND_WIPE ?
      "operator_revoke_and_wipe" : NULL);
}

static WylPolicyServiceHandoffRetirementKind
service_handoff_retirement_kind_parse (const gchar *kind)
{
  return g_strcmp0 (kind, "file_published") == 0 ?
      WYL_POLICY_HANDOFF_RETIREMENT_FILE_PUBLISHED :
      (g_strcmp0 (kind, "operator_revoke_and_wipe") == 0 ?
      WYL_POLICY_HANDOFF_RETIREMENT_OPERATOR_REVOKE_AND_WIPE : 0);
}

static gboolean
    service_handoff_retirement_input_is_valid
    (const WylPolicyServiceHandoffRetirementInput * input)
{
  if (input == NULL || input->journal_version != 6
      || input->journal_state != WYL_POLICY_HANDOFF_REMEDIATION_STATE_TERMINAL
      || !service_handoff_exact_tuple_is_valid (&input->tuple)
      || input->tuple.successor_credential_id == NULL
      || input->journal_updated_at_us <= 0
      || sodium_is_zero (input->raw_journal_snapshot_digest, 32))
    return FALSE;
  gboolean marker_id = input->remediation_request_id != NULL;
  gboolean marker_source = !sodium_is_zero
      (input->remediation_source_snapshot_digest, 32);
  gboolean marker_fingerprint = !sodium_is_zero
      (input->remediation_request_fingerprint, 32);
  if (marker_id != marker_source || marker_id != marker_fingerprint
      || (marker_id && !service_handoff_request_id_is_canonical
          (input->remediation_request_id)))
    return FALSE;
  if (input->terminal_kind == WYL_POLICY_HANDOFF_RETIREMENT_FILE_PUBLISHED)
    return wyl_policy_service_actor_subject_is_valid
        (input->delivery_actor_subject_id)
        && g_strcmp0 (input->delivery_actor_subject_id,
        input->tuple.original_actor_subject_id) == 0
        && !sodium_is_zero (input->delivery_proof_digest, 32);
  return input->terminal_kind ==
      WYL_POLICY_HANDOFF_RETIREMENT_OPERATOR_REVOKE_AND_WIPE
      && marker_id && input->delivery_actor_subject_id == NULL
      && sodium_is_zero (input->delivery_proof_digest, 32);
}

static gboolean
    service_handoff_retirement_tuple_matches_result
    (const WylPolicyServiceHandoffExactTuple * tuple,
    const WylPolicyServiceHandoffRemediationResult * remediation)
{
  gchar escrow[WYL_ID_STRING_BUF];
  return wyl_id_format (tuple->escrow_id, escrow, sizeof escrow) ==
      WYRELOG_E_OK
      && g_strcmp0 (tuple->original_request_id,
      remediation->original_request_id) == 0
      && g_strcmp0 (tuple->original_actor_subject_id,
      remediation->original_actor_subject_id) == 0
      && g_strcmp0 (escrow, remediation->escrow_id) == 0
      && sodium_memcmp (tuple->binding_digest,
      remediation->binding_digest, 32) == 0
      && g_strcmp0 (tuple->successor_credential_id,
      remediation->successor_credential_id) == 0
      && tuple->successor_issuance_generation ==
      remediation->successor_issuance_generation;
}

static wyrelog_error_t
service_handoff_retirement_resolve_remediation (wyl_policy_store_t *store,
    const gchar *remediation_request_id,
    WylPolicyServiceHandoffRemediationResult *out)
{
  g_autofree gchar *sql = g_strdup_printf
      ("SELECT %s FROM service_credential_handoff_remediation_actions"
      " WHERE remediation_request_id=?;",
      service_handoff_remediation_resolve_columns);
  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = sql != NULL ? prepare_stmt (store->db, sql, &stmt) :
      WYRELOG_E_NOMEM;
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 1, remediation_request_id);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_remediation_resolve_stmt (store, stmt, FALSE, out);
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

typedef struct
{
  WylPolicyServiceHandoffExactTuple tuple;
  wyl_id_t escrow_id;
  gchar *original_request_id;
  gchar *successor_credential_id;
  gchar *actor_subject_id;
} ServiceHandoffRetirementDelivery;

static void
    service_handoff_retirement_delivery_clear
    (ServiceHandoffRetirementDelivery * delivery)
{
  if (delivery == NULL)
    return;
  g_free (delivery->original_request_id);
  g_free (delivery->successor_credential_id);
  g_free (delivery->actor_subject_id);
  sodium_memzero (delivery, sizeof *delivery);
}

static wyrelog_error_t
service_handoff_retirement_load_delivery (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffRetirementResult *receipt,
    ServiceHandoffRetirementDelivery *delivery, gint64 *out_created_at_us)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT original_request_id,escrow_id,binding_digest,"
      "successor_credential_id,successor_issuance_generation,"
      "actor_subject_id,created_at_us FROM"
      " service_credential_handoff_dispositions WHERE disposition_id=?"
      " AND audit_id=? AND reason='delivered'" " AND outcome='escrow_deleted';";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK
      && ((rc = bind_text (stmt, 1, receipt->delivery_disposition_id))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 2,
                  receipt->delivery_audit_id)) != WYRELOG_E_OK))
    rc = WYRELOG_E_IO;
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW) {
    const gchar *original = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *escrow = (const gchar *) sqlite3_column_text (stmt, 1);
    const gchar *successor = (const gchar *) sqlite3_column_text (stmt, 3);
    const gchar *actor = (const gchar *) sqlite3_column_text (stmt, 5);
    gint64 created = sqlite3_column_int64 (stmt, 6);
    guint8 binding_digest[32] = { 0 };
    guint64 successor_generation = (guint64) sqlite3_column_int64 (stmt, 4);
    g_autofree gchar *original_copy = sqlite3_column_type (stmt, 0) ==
        SQLITE_TEXT ? service_handoff_try_strdup (original) : NULL;
    g_autofree gchar *successor_copy = sqlite3_column_type (stmt, 3) ==
        SQLITE_TEXT ? service_handoff_try_strdup (successor) : NULL;
    g_autofree gchar *actor_copy = sqlite3_column_type (stmt, 5) ==
        SQLITE_TEXT ? service_handoff_try_strdup (actor) : NULL;
    if (sqlite3_column_type (stmt, 2) == SQLITE_BLOB
        && sqlite3_column_bytes (stmt, 2) == 32)
      memcpy (binding_digest, sqlite3_column_blob (stmt, 2), 32);
    gboolean exact = sqlite3_column_type (stmt, 0) == SQLITE_TEXT
        && sqlite3_column_type (stmt, 1) == SQLITE_TEXT
        && sqlite3_column_type (stmt, 2) == SQLITE_BLOB
        && sqlite3_column_bytes (stmt, 2) == 32
        && sqlite3_column_type (stmt, 3) == SQLITE_TEXT
        && sqlite3_column_type (stmt, 4) == SQLITE_INTEGER
        && sqlite3_column_int64 (stmt, 4) > 0
        && sqlite3_column_type (stmt, 5) == SQLITE_TEXT
        && sqlite3_column_type (stmt, 6) == SQLITE_INTEGER && created > 0
        && original_copy != NULL && successor_copy != NULL
        && actor_copy != NULL
        && g_strcmp0 (original_copy, receipt->original_request_id) == 0
        && wyl_id_parse (escrow, &delivery->escrow_id) == WYRELOG_E_OK
        && sqlite3_step (stmt) == SQLITE_DONE;
    if (!exact) {
      rc = WYRELOG_E_POLICY;
    } else {
      delivery->original_request_id = g_steal_pointer (&original_copy);
      delivery->successor_credential_id = g_steal_pointer (&successor_copy);
      delivery->actor_subject_id = g_steal_pointer (&actor_copy);
      delivery->tuple.original_request_id = delivery->original_request_id;
      delivery->tuple.escrow_id = &delivery->escrow_id;
      memcpy (delivery->tuple.binding_digest, binding_digest, 32);
      delivery->tuple.successor_credential_id =
          delivery->successor_credential_id;
      delivery->tuple.successor_issuance_generation = successor_generation;
      delivery->tuple.original_actor_subject_id = delivery->actor_subject_id;
      *out_created_at_us = created;
    }
    sodium_memzero (binding_digest, sizeof binding_digest);
  } else if (rc == WYRELOG_E_OK) {
    rc = step == SQLITE_DONE ? WYRELOG_E_POLICY :
        service_handoff_sqlite_error (store->db, step);
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  if (rc != WYRELOG_E_OK)
    service_handoff_retirement_delivery_clear (delivery);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
service_handoff_retirement_load_receipt_stmt (wyl_policy_store_t *store,
    sqlite3_stmt *stmt, WylPolicyServiceHandoffRetirementResult *out)
{
  int step = sqlite3_step (stmt);
  if (step != SQLITE_ROW)
    return step == SQLITE_DONE ? WYRELOG_E_NOT_FOUND :
        service_handoff_sqlite_error (store->db, step);
  const gchar *original = (const gchar *) sqlite3_column_text (stmt, 0);
  const gchar *kind_text = (const gchar *) sqlite3_column_text (stmt, 1);
  const gchar *delivery_disposition =
      (const gchar *) sqlite3_column_text (stmt, 3);
  const gchar *delivery_audit = (const gchar *) sqlite3_column_text (stmt, 4);
  const gchar *revoke_request = (const gchar *) sqlite3_column_text (stmt, 6);
  const gchar *revoke_audit = (const gchar *) sqlite3_column_text (stmt, 7);
  const gchar *resume_request = (const gchar *) sqlite3_column_text (stmt, 9);
  const gchar *resume_audit = (const gchar *) sqlite3_column_text (stmt, 10);
  WylPolicyServiceHandoffRetirementKind kind =
      service_handoff_retirement_kind_parse (kind_text);
  gboolean delivery_digest_valid = sqlite3_column_type (stmt, 5) ==
      SQLITE_BLOB && sqlite3_column_bytes (stmt, 5) == 32;
  gboolean delivery_digest_nonzero = delivery_digest_valid
      && !sodium_is_zero (sqlite3_column_blob (stmt, 5), 32);
  gboolean marker = sqlite3_column_type (stmt, 11) != SQLITE_NULL
      || sqlite3_column_type (stmt, 12) != SQLITE_NULL;
  gboolean malformed = sqlite3_column_type (stmt, 0) != SQLITE_TEXT
      || sqlite3_column_type (stmt, 1) != SQLITE_TEXT || kind == 0
      || !service_handoff_request_id_is_canonical (original)
      || sqlite3_column_type (stmt, 2) != SQLITE_BLOB
      || sqlite3_column_bytes (stmt, 2) != 32
      || sodium_is_zero (sqlite3_column_blob (stmt, 2), 32)
      || !delivery_digest_valid
      || (marker && (sqlite3_column_type (stmt, 11) != SQLITE_BLOB
          || sqlite3_column_bytes (stmt, 11) != 32
          || sodium_is_zero (sqlite3_column_blob (stmt, 11), 32)
          || sqlite3_column_type (stmt, 12) != SQLITE_BLOB
          || sqlite3_column_bytes (stmt, 12) != 32
          || sodium_is_zero (sqlite3_column_blob (stmt, 12), 32)))
      || sqlite3_column_type (stmt, 13) != SQLITE_INTEGER
      || sqlite3_column_int64 (stmt, 13) <= 0
      || sqlite3_column_type (stmt, 14) != SQLITE_INTEGER
      || sqlite3_column_int64 (stmt, 14) < sqlite3_column_int64 (stmt, 13);
  gboolean file_shape = kind == WYL_POLICY_HANDOFF_RETIREMENT_FILE_PUBLISHED
      && sqlite3_column_type (stmt, 3) == SQLITE_TEXT
      && sqlite3_column_type (stmt, 4) == SQLITE_TEXT
      && service_handoff_uuid_is_canonical (delivery_disposition)
      && service_handoff_uuid_is_canonical (delivery_audit)
      && delivery_digest_nonzero
      && sqlite3_column_type (stmt, 6) == SQLITE_NULL
      && sqlite3_column_type (stmt, 7) == SQLITE_NULL
      && sqlite3_column_type (stmt, 8) == SQLITE_NULL
      && ((sqlite3_column_type (stmt, 9) == SQLITE_NULL
          && sqlite3_column_type (stmt, 10) == SQLITE_NULL && !marker)
      || (sqlite3_column_type (stmt, 9) == SQLITE_TEXT
          && sqlite3_column_type (stmt, 10) == SQLITE_TEXT && marker));
  if (file_shape && resume_request != NULL)
    file_shape = service_handoff_request_id_is_canonical (resume_request)
        && service_handoff_uuid_is_canonical (resume_audit);
  gboolean revoke_shape = kind ==
      WYL_POLICY_HANDOFF_RETIREMENT_OPERATOR_REVOKE_AND_WIPE
      && sqlite3_column_type (stmt, 3) == SQLITE_NULL
      && sqlite3_column_type (stmt, 4) == SQLITE_NULL
      && delivery_digest_valid && !delivery_digest_nonzero
      && sqlite3_column_type (stmt, 6) == SQLITE_TEXT
      && sqlite3_column_type (stmt, 7) == SQLITE_TEXT
      && service_handoff_request_id_is_canonical (revoke_request)
      && service_handoff_uuid_is_canonical (revoke_audit)
      && (sqlite3_column_type (stmt, 8) == SQLITE_NULL
      || (sqlite3_column_type (stmt, 8) == SQLITE_INTEGER
          && sqlite3_column_int64 (stmt, 8) > 0))
      && sqlite3_column_type (stmt, 9) == SQLITE_NULL
      && sqlite3_column_type (stmt, 10) == SQLITE_NULL && marker;
  if (malformed || (!file_shape && !revoke_shape))
    return WYRELOG_E_POLICY;
  g_autofree gchar *original_copy = service_handoff_try_strdup (original);
  g_autofree gchar *delivery_disposition_copy = delivery_disposition != NULL ?
      service_handoff_try_strdup (delivery_disposition) : NULL;
  g_autofree gchar *delivery_audit_copy = delivery_audit != NULL ?
      service_handoff_try_strdup (delivery_audit) : NULL;
  g_autofree gchar *revoke_request_copy = revoke_request != NULL ?
      service_handoff_try_strdup (revoke_request) : NULL;
  g_autofree gchar *revoke_audit_copy = revoke_audit != NULL ?
      service_handoff_try_strdup (revoke_audit) : NULL;
  g_autofree gchar *resume_request_copy = resume_request != NULL ?
      service_handoff_try_strdup (resume_request) : NULL;
  g_autofree gchar *resume_audit_copy = resume_audit != NULL ?
      service_handoff_try_strdup (resume_audit) : NULL;
  if (original_copy == NULL
      || (delivery_disposition != NULL && delivery_disposition_copy == NULL)
      || (delivery_audit != NULL && delivery_audit_copy == NULL)
      || (revoke_request != NULL && revoke_request_copy == NULL)
      || (revoke_audit != NULL && revoke_audit_copy == NULL)
      || (resume_request != NULL && resume_request_copy == NULL)
      || (resume_audit != NULL && resume_audit_copy == NULL))
    return WYRELOG_E_NOMEM;
  memcpy (out->raw_journal_snapshot_digest, sqlite3_column_blob (stmt, 2), 32);
  memcpy (out->delivery_proof_digest, sqlite3_column_blob (stmt, 5), 32);
  if (marker) {
    memcpy (out->remediation_source_snapshot_digest,
        sqlite3_column_blob (stmt, 11), 32);
    memcpy (out->remediation_request_fingerprint,
        sqlite3_column_blob (stmt, 12), 32);
  }
  out->terminal_kind = kind;
  out->revoke_event_id = sqlite3_column_type (stmt, 8) == SQLITE_INTEGER ?
      sqlite3_column_int64 (stmt, 8) : 0;
  out->retention_basis_at_us = sqlite3_column_int64 (stmt, 13);
  out->retired_at_us = sqlite3_column_int64 (stmt, 14);
  out->original_request_id = g_steal_pointer (&original_copy);
  out->delivery_disposition_id = g_steal_pointer (&delivery_disposition_copy);
  out->delivery_audit_id = g_steal_pointer (&delivery_audit_copy);
  out->revoke_remediation_request_id = g_steal_pointer (&revoke_request_copy);
  out->revoke_audit_id = g_steal_pointer (&revoke_audit_copy);
  out->resume_remediation_request_id = g_steal_pointer (&resume_request_copy);
  out->resume_audit_id = g_steal_pointer (&resume_audit_copy);
  int second = sqlite3_step (stmt);
  if (second != SQLITE_DONE) {
    wyl_policy_service_handoff_retirement_result_clear (out);
    return second == SQLITE_ROW ? WYRELOG_E_POLICY :
        service_handoff_sqlite_error (store->db, second);
  }
  return WYRELOG_E_OK;
}

static const gchar *const service_handoff_retirement_columns =
    "original_request_id,terminal_kind,raw_journal_snapshot_digest,"
    "delivery_disposition_id,delivery_audit_id,delivery_proof_digest,"
    "revoke_remediation_request_id,revoke_audit_id,revoke_event_id,"
    "resume_remediation_request_id,resume_audit_id,"
    "remediation_source_snapshot_digest,remediation_request_fingerprint,"
    "retention_basis_at_us,retired_at_us";

static wyrelog_error_t
service_handoff_retirement_load_by_request (wyl_policy_store_t *store,
    const gchar *original_request_id,
    WylPolicyServiceHandoffRetirementResult *out)
{
  g_autofree gchar *sql = g_strdup_printf
      ("SELECT %s FROM service_credential_handoff_retirement_receipts"
      " WHERE original_request_id=?;", service_handoff_retirement_columns);
  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = sql != NULL ? prepare_stmt (store->db, sql, &stmt) :
      WYRELOG_E_NOMEM;
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 1, original_request_id);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_retirement_load_receipt_stmt (store, stmt, out);
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
    service_handoff_retirement_validate_receipt_authority
    (wyl_policy_store_t * store,
    const WylPolicyServiceHandoffRetirementResult * receipt)
{
  wyrelog_error_t rc = WYRELOG_E_OK;
  gint64 basis = 0;
  wyl_id_t escrow_id;
  WylPolicyServiceHandoffExactTuple remediation_tuple = { 0 };
  const WylPolicyServiceHandoffExactTuple *tuple = NULL;
  ServiceHandoffRetirementDelivery delivery = { 0 };
  WylPolicyServiceHandoffRemediationResult remediation = { 0 };
  if (receipt->terminal_kind == WYL_POLICY_HANDOFF_RETIREMENT_FILE_PUBLISHED) {
    gint64 delivery_created = 0;
    rc = service_handoff_retirement_load_delivery (store, receipt, &delivery,
        &delivery_created);
    WylPolicyServiceHandoffDispositionResult disposition = { 0 };
    gboolean found = FALSE;
    if (rc == WYRELOG_E_OK)
      rc = service_handoff_lookup_delivered (store, &delivery.tuple,
          delivery.actor_subject_id, receipt->delivery_proof_digest, &found,
          &disposition);
    if (rc == WYRELOG_E_OK
        && (!found || g_strcmp0 (disposition.disposition_id,
                receipt->delivery_disposition_id) != 0
            || g_strcmp0 (disposition.audit_id,
                receipt->delivery_audit_id) != 0))
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK)
      basis = delivery_created;
    wyl_policy_service_handoff_disposition_result_clear (&disposition);
    tuple = &delivery.tuple;
    if (rc == WYRELOG_E_OK && receipt->resume_remediation_request_id != NULL) {
      rc = service_handoff_retirement_resolve_remediation (store,
          receipt->resume_remediation_request_id, &remediation);
      if (rc == WYRELOG_E_OK
          && (remediation.action != WYL_POLICY_HANDOFF_REMEDIATION_RESUME
              || remediation.outcome !=
              WYL_POLICY_HANDOFF_REMEDIATION_RECORDED
              || remediation.escrow_outcome !=
              WYL_POLICY_HANDOFF_REMEDIATION_ESCROW_RETAINED
              || g_strcmp0 (remediation.audit_id,
                  receipt->resume_audit_id) != 0
              || sodium_memcmp (remediation.journal_snapshot_digest,
                  receipt->remediation_source_snapshot_digest, 32) != 0
              || sodium_memcmp (remediation.request_fingerprint,
                  receipt->remediation_request_fingerprint, 32) != 0
              || !service_handoff_retirement_tuple_matches_result
              (&delivery.tuple, &remediation)))
        rc = WYRELOG_E_POLICY;
      if (rc == WYRELOG_E_OK)
        basis = MAX (basis, remediation.created_at_us);
    }
  } else if (receipt->terminal_kind ==
      WYL_POLICY_HANDOFF_RETIREMENT_OPERATOR_REVOKE_AND_WIPE) {
    rc = service_handoff_retirement_resolve_remediation (store,
        receipt->revoke_remediation_request_id, &remediation);
    gboolean normalized = remediation.outcome ==
        WYL_POLICY_HANDOFF_REMEDIATION_REVOKED_AND_WIPED
        || remediation.outcome ==
        WYL_POLICY_HANDOFF_REMEDIATION_ALREADY_REVOKED_AND_WIPED
        || remediation.outcome ==
        WYL_POLICY_HANDOFF_REMEDIATION_EXPIRED_AND_WIPED;
    if (rc == WYRELOG_E_OK
        && (remediation.action !=
            WYL_POLICY_HANDOFF_REMEDIATION_REVOKE_AND_WIPE
            || !normalized || remediation.escrow_outcome ==
            WYL_POLICY_HANDOFF_REMEDIATION_ESCROW_RETAINED
            || g_strcmp0 (remediation.audit_id,
                receipt->revoke_audit_id) != 0
            || remediation.revoke_event_id != receipt->revoke_event_id
            || sodium_memcmp (remediation.journal_snapshot_digest,
                receipt->remediation_source_snapshot_digest, 32) != 0
            || sodium_memcmp (remediation.request_fingerprint,
                receipt->remediation_request_fingerprint, 32) != 0
            || g_strcmp0 (remediation.original_request_id,
                receipt->original_request_id) != 0
            || wyl_id_parse (remediation.escrow_id, &escrow_id)
            != WYRELOG_E_OK))
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK) {
      remediation_tuple.original_request_id = remediation.original_request_id;
      remediation_tuple.escrow_id = &escrow_id;
      memcpy (remediation_tuple.binding_digest, remediation.binding_digest, 32);
      remediation_tuple.successor_credential_id =
          remediation.successor_credential_id;
      remediation_tuple.successor_issuance_generation =
          remediation.successor_issuance_generation;
      remediation_tuple.original_actor_subject_id =
          remediation.original_actor_subject_id;
      tuple = &remediation_tuple;
      basis = MAX (remediation.created_at_us,
          remediation.revoke_event_created_at_us);
    }
  } else {
    rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK && tuple != NULL)
    rc = service_handoff_escrow_absent (store, tuple->escrow_id);
  if (rc == WYRELOG_E_OK && tuple != NULL)
    rc = service_handoff_request_escrow_absent (store,
        tuple->original_request_id);
  if (rc == WYRELOG_E_OK
      && (basis <= 0 || receipt->retention_basis_at_us < basis
          || receipt->retired_at_us < basis
          || receipt->retired_at_us - basis <
          WYL_POLICY_HANDOFF_RETENTION_MIN_US))
    rc = WYRELOG_E_POLICY;
  wyl_policy_service_handoff_remediation_result_clear (&remediation);
  service_handoff_retirement_delivery_clear (&delivery);
  return rc;
}

static wyrelog_error_t
service_handoff_retirement_build_expected (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffRetirementInput *input, gint64 trusted_now,
    gboolean enforce_due, WylPolicyServiceHandoffRetirementResult *out)
{
  out->original_request_id = service_handoff_try_strdup
      (input->tuple.original_request_id);
  if (out->original_request_id == NULL)
    return WYRELOG_E_NOMEM;
  out->terminal_kind = input->terminal_kind;
  memcpy (out->raw_journal_snapshot_digest,
      input->raw_journal_snapshot_digest, 32);
  out->retention_basis_at_us = input->journal_updated_at_us;
  wyrelog_error_t rc = WYRELOG_E_OK;
  if (input->terminal_kind == WYL_POLICY_HANDOFF_RETIREMENT_FILE_PUBLISHED) {
    WylPolicyServiceHandoffDispositionResult disposition = { 0 };
    gboolean found = FALSE;
    rc = service_handoff_lookup_delivered (store, &input->tuple,
        input->delivery_actor_subject_id, input->delivery_proof_digest, &found,
        &disposition);
    if (rc == WYRELOG_E_OK && !found)
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK) {
      out->delivery_disposition_id = g_strdup (disposition.disposition_id);
      out->delivery_audit_id = g_strdup (disposition.audit_id);
      if (out->delivery_disposition_id == NULL
          || out->delivery_audit_id == NULL)
        rc = WYRELOG_E_NOMEM;
      memcpy (out->delivery_proof_digest, input->delivery_proof_digest, 32);
      out->retention_basis_at_us = MAX (out->retention_basis_at_us,
          disposition.created_at_us);
    }
    wyl_policy_service_handoff_disposition_result_clear (&disposition);
  }
  WylPolicyServiceHandoffRemediationResult remediation = { 0 };
  if (rc == WYRELOG_E_OK && input->remediation_request_id != NULL) {
    rc = service_handoff_retirement_resolve_remediation (store,
        input->remediation_request_id, &remediation);
    if (rc == WYRELOG_E_OK
        && (!service_handoff_retirement_tuple_matches_result (&input->tuple,
                &remediation)
            || sodium_memcmp (remediation.journal_snapshot_digest,
                input->remediation_source_snapshot_digest, 32) != 0
            || sodium_memcmp (remediation.request_fingerprint,
                input->remediation_request_fingerprint, 32) != 0))
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK && input->terminal_kind ==
        WYL_POLICY_HANDOFF_RETIREMENT_FILE_PUBLISHED
        && (remediation.action != WYL_POLICY_HANDOFF_REMEDIATION_RESUME
            || remediation.outcome != WYL_POLICY_HANDOFF_REMEDIATION_RECORDED
            || remediation.escrow_outcome !=
            WYL_POLICY_HANDOFF_REMEDIATION_ESCROW_RETAINED))
      rc = WYRELOG_E_POLICY;
    gboolean normalized = remediation.outcome ==
        WYL_POLICY_HANDOFF_REMEDIATION_REVOKED_AND_WIPED
        || remediation.outcome ==
        WYL_POLICY_HANDOFF_REMEDIATION_ALREADY_REVOKED_AND_WIPED
        || remediation.outcome ==
        WYL_POLICY_HANDOFF_REMEDIATION_EXPIRED_AND_WIPED;
    if (rc == WYRELOG_E_OK && input->terminal_kind ==
        WYL_POLICY_HANDOFF_RETIREMENT_OPERATOR_REVOKE_AND_WIPE
        && (remediation.action !=
            WYL_POLICY_HANDOFF_REMEDIATION_REVOKE_AND_WIPE
            || !normalized || remediation.escrow_outcome ==
            WYL_POLICY_HANDOFF_REMEDIATION_ESCROW_RETAINED))
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK) {
      if (input->terminal_kind == WYL_POLICY_HANDOFF_RETIREMENT_FILE_PUBLISHED) {
        out->resume_remediation_request_id =
            g_strdup (remediation.remediation_request_id);
        out->resume_audit_id = g_strdup (remediation.audit_id);
        if (out->resume_remediation_request_id == NULL
            || out->resume_audit_id == NULL)
          rc = WYRELOG_E_NOMEM;
      } else {
        out->revoke_remediation_request_id =
            g_strdup (remediation.remediation_request_id);
        out->revoke_audit_id = g_strdup (remediation.audit_id);
        out->revoke_event_id = remediation.revoke_event_id;
        if (out->revoke_remediation_request_id == NULL
            || out->revoke_audit_id == NULL)
          rc = WYRELOG_E_NOMEM;
      }
      memcpy (out->remediation_source_snapshot_digest,
          input->remediation_source_snapshot_digest, 32);
      memcpy (out->remediation_request_fingerprint,
          input->remediation_request_fingerprint, 32);
      out->retention_basis_at_us = MAX (out->retention_basis_at_us,
          remediation.created_at_us);
      out->retention_basis_at_us = MAX (out->retention_basis_at_us,
          remediation.revoke_event_created_at_us);
    }
  }
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_escrow_absent (store, input->tuple.escrow_id);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_request_escrow_absent (store,
        input->tuple.original_request_id);
  if (rc == WYRELOG_E_OK && enforce_due
      && (trusted_now < out->retention_basis_at_us
          || trusted_now - out->retention_basis_at_us <
          WYL_POLICY_HANDOFF_RETENTION_MIN_US))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && enforce_due)
    out->retired_at_us = trusted_now;
  wyl_policy_service_handoff_remediation_result_clear (&remediation);
  if (rc != WYRELOG_E_OK)
    wyl_policy_service_handoff_retirement_result_clear (out);
  return rc;
}

static gboolean
    service_handoff_retirement_result_exact
    (const WylPolicyServiceHandoffRetirementResult * stored,
    const WylPolicyServiceHandoffRetirementResult * expected)
{
  return g_strcmp0 (stored->original_request_id,
      expected->original_request_id) == 0
      && stored->terminal_kind == expected->terminal_kind
      && sodium_memcmp (stored->raw_journal_snapshot_digest,
      expected->raw_journal_snapshot_digest, 32) == 0
      && g_strcmp0 (stored->delivery_disposition_id,
      expected->delivery_disposition_id) == 0
      && g_strcmp0 (stored->delivery_audit_id,
      expected->delivery_audit_id) == 0
      && sodium_memcmp (stored->delivery_proof_digest,
      expected->delivery_proof_digest, 32) == 0
      && g_strcmp0 (stored->revoke_remediation_request_id,
      expected->revoke_remediation_request_id) == 0
      && g_strcmp0 (stored->revoke_audit_id,
      expected->revoke_audit_id) == 0
      && stored->revoke_event_id == expected->revoke_event_id
      && g_strcmp0 (stored->resume_remediation_request_id,
      expected->resume_remediation_request_id) == 0
      && g_strcmp0 (stored->resume_audit_id,
      expected->resume_audit_id) == 0
      && sodium_memcmp (stored->remediation_source_snapshot_digest,
      expected->remediation_source_snapshot_digest, 32) == 0
      && sodium_memcmp (stored->remediation_request_fingerprint,
      expected->remediation_request_fingerprint, 32) == 0
      && stored->retention_basis_at_us == expected->retention_basis_at_us
      && stored->retired_at_us >= stored->retention_basis_at_us;
}

static wyrelog_error_t
service_handoff_retirement_reject_collision (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffRetirementResult *expected)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT 1 FROM service_credential_handoff_retirement_receipts WHERE"
      " raw_journal_snapshot_digest=?"
      " OR (? IS NOT NULL AND delivery_disposition_id=?)"
      " OR (? IS NOT NULL AND revoke_remediation_request_id=?)"
      " OR (? IS NOT NULL AND resume_remediation_request_id=?) LIMIT 1;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK
      && (sqlite3_bind_blob (stmt, 1,
              expected->raw_journal_snapshot_digest, 32, SQLITE_TRANSIENT)
          != SQLITE_OK
          || (expected->delivery_disposition_id == NULL ?
              sqlite3_bind_null (stmt, 2) : sqlite3_bind_text (stmt, 2,
                  expected->delivery_disposition_id, -1, SQLITE_TRANSIENT))
          != SQLITE_OK
          || (expected->delivery_disposition_id == NULL ?
              sqlite3_bind_null (stmt, 3) : sqlite3_bind_text (stmt, 3,
                  expected->delivery_disposition_id, -1, SQLITE_TRANSIENT))
          != SQLITE_OK
          || (expected->revoke_remediation_request_id == NULL ?
              sqlite3_bind_null (stmt, 4) : sqlite3_bind_text (stmt, 4,
                  expected->revoke_remediation_request_id, -1,
                  SQLITE_TRANSIENT)) != SQLITE_OK
          || (expected->revoke_remediation_request_id == NULL ?
              sqlite3_bind_null (stmt, 5) : sqlite3_bind_text (stmt, 5,
                  expected->revoke_remediation_request_id, -1,
                  SQLITE_TRANSIENT)) != SQLITE_OK
          || (expected->resume_remediation_request_id == NULL ?
              sqlite3_bind_null (stmt, 6) : sqlite3_bind_text (stmt, 6,
                  expected->resume_remediation_request_id, -1,
                  SQLITE_TRANSIENT)) != SQLITE_OK
          || (expected->resume_remediation_request_id == NULL ?
              sqlite3_bind_null (stmt, 7) : sqlite3_bind_text (stmt, 7,
                  expected->resume_remediation_request_id, -1,
                  SQLITE_TRANSIENT)) != SQLITE_OK))
    rc = WYRELOG_E_IO;
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK)
    rc = step == SQLITE_DONE ? WYRELOG_E_OK :
        (step == SQLITE_ROW ? WYRELOG_E_POLICY :
        service_handoff_sqlite_error (store->db, step));
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
service_handoff_retirement_insert (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffRetirementResult *receipt)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "INSERT INTO service_credential_handoff_retirement_receipts("
      "original_request_id,terminal_kind,raw_journal_snapshot_digest,"
      "delivery_disposition_id,delivery_audit_id,delivery_proof_digest,"
      "revoke_remediation_request_id,revoke_audit_id,revoke_event_id,"
      "resume_remediation_request_id,resume_audit_id,"
      "remediation_source_snapshot_digest,remediation_request_fingerprint,"
      "retention_basis_at_us,retired_at_us) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
#define BIND_NULLABLE_TEXT(index, value) \
  ((value) == NULL ? sqlite3_bind_null (stmt, (index)) : \
  sqlite3_bind_text (stmt, (index), (value), -1, SQLITE_TRANSIENT))
  gboolean marker = receipt->revoke_remediation_request_id != NULL
      || receipt->resume_remediation_request_id != NULL;
  if (rc == WYRELOG_E_OK
      && ((rc = bind_text (stmt, 1, receipt->original_request_id))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 2,
                  service_handoff_retirement_kind_name
                  (receipt->terminal_kind))) != WYRELOG_E_OK
          || sqlite3_bind_blob (stmt, 3,
              receipt->raw_journal_snapshot_digest, 32, SQLITE_TRANSIENT)
          != SQLITE_OK || BIND_NULLABLE_TEXT (4,
              receipt->delivery_disposition_id) != SQLITE_OK
          || BIND_NULLABLE_TEXT (5, receipt->delivery_audit_id) != SQLITE_OK
          || sqlite3_bind_blob (stmt, 6, receipt->delivery_proof_digest, 32,
              SQLITE_TRANSIENT) != SQLITE_OK
          || BIND_NULLABLE_TEXT (7,
              receipt->revoke_remediation_request_id) != SQLITE_OK
          || BIND_NULLABLE_TEXT (8, receipt->revoke_audit_id) != SQLITE_OK
          || (receipt->revoke_event_id == 0 ? sqlite3_bind_null (stmt, 9) :
              sqlite3_bind_int64 (stmt, 9, receipt->revoke_event_id))
          != SQLITE_OK || BIND_NULLABLE_TEXT (10,
              receipt->resume_remediation_request_id) != SQLITE_OK
          || BIND_NULLABLE_TEXT (11, receipt->resume_audit_id) != SQLITE_OK
          || (marker ? sqlite3_bind_blob (stmt, 12,
                  receipt->remediation_source_snapshot_digest, 32,
                  SQLITE_TRANSIENT) : sqlite3_bind_null (stmt, 12))
          != SQLITE_OK
          || (marker ? sqlite3_bind_blob (stmt, 13,
                  receipt->remediation_request_fingerprint, 32,
                  SQLITE_TRANSIENT) : sqlite3_bind_null (stmt, 13))
          != SQLITE_OK || sqlite3_bind_int64 (stmt, 14,
              receipt->retention_basis_at_us) != SQLITE_OK
          || sqlite3_bind_int64 (stmt, 15, receipt->retired_at_us)
          != SQLITE_OK))
    rc = WYRELOG_E_IO;
#undef BIND_NULLABLE_TEXT
  if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
    rc = (sqlite3_extended_errcode (store->db) & 0xff) == SQLITE_CONSTRAINT ?
        WYRELOG_E_POLICY : WYRELOG_E_IO;
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

wyrelog_error_t
    wyl_policy_store_handoff_retirement_lookup_core
    (WylServiceAuthorityTransaction * transaction,
    wyl_policy_store_t * store, const gchar * original_request_id,
    WylPolicyServiceHandoffRetirementResult * out_result)
{
  if (out_result != NULL)
    wyl_policy_service_handoff_retirement_result_clear (out_result);
  if (store == NULL || out_result == NULL
      || !service_handoff_request_id_is_canonical (original_request_id))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc =
      wyl_policy_store_service_authority_transaction_enter_participant
      (transaction, store);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_retirement_load_by_request (store,
        original_request_id, out_result);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_retirement_validate_receipt_authority (store,
        out_result);
  if (rc != WYRELOG_E_OK)
    wyl_policy_service_handoff_retirement_result_clear (out_result);
  return rc;
}

wyrelog_error_t
    wyl_policy_store_handoff_retirement_record_core
    (WylServiceAuthorityTransaction * transaction,
    wyl_policy_store_t * store,
    const WylPolicyServiceHandoffRetirementInput * input,
    WylPolicyServiceHandoffRetirementResult * out_result)
{
  if (out_result != NULL)
    wyl_policy_service_handoff_retirement_result_clear (out_result);
  if (store == NULL || out_result == NULL
      || !service_handoff_retirement_input_is_valid (input))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc =
      wyl_policy_store_service_authority_transaction_enter_participant
      (transaction, store);
  WylPolicyServiceHandoffRetirementResult stored = { 0 };
  if (rc == WYRELOG_E_OK) {
    rc = service_handoff_retirement_load_by_request (store,
        input->tuple.original_request_id, &stored);
    if (rc == WYRELOG_E_NOT_FOUND)
      rc = WYRELOG_E_OK;
  }
  WylPolicyServiceHandoffRetirementResult expected = { 0 };
  gboolean found = rc == WYRELOG_E_OK && stored.original_request_id != NULL;
  if (rc == WYRELOG_E_OK && found) {
    rc = service_handoff_retirement_validate_receipt_authority (store, &stored);
    if (rc == WYRELOG_E_OK)
      rc = service_handoff_retirement_build_expected (store, input, 0,
          FALSE, &expected);
    if (rc == WYRELOG_E_OK
        && !service_handoff_retirement_result_exact (&stored, &expected))
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK) {
      stored.replayed = TRUE;
      *out_result = stored;
      memset (&stored, 0, sizeof stored);
    }
  }
  gboolean replayed = out_result->replayed;
  gint64 trusted_now = 0;
  if (rc == WYRELOG_E_OK && !found)
    rc = service_handoff_maintenance_now (store, &trusted_now);
  if (rc == WYRELOG_E_OK && !found)
    rc = service_handoff_retirement_build_expected (store, input,
        trusted_now, TRUE, &expected);
  if (rc == WYRELOG_E_OK && !replayed)
    rc = service_handoff_retirement_reject_collision (store, &expected);
  if (rc == WYRELOG_E_OK && !replayed)
    rc = service_handoff_retirement_insert (store, &expected);
  if (rc == WYRELOG_E_OK && !replayed
      && service_handoff_should_fail (store,
          WYL_POLICY_HANDOFF_FAIL_AFTER_PROVENANCE))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && !replayed) {
    *out_result = expected;
    memset (&expected, 0, sizeof expected);
  }
  wyl_policy_service_handoff_retirement_result_clear (&expected);
  wyl_policy_service_handoff_retirement_result_clear (&stored);
  if (rc != WYRELOG_E_OK)
    wyl_policy_service_handoff_retirement_result_clear (out_result);
  return rc;
}

static gboolean
    service_handoff_maintenance_proof_is_valid
    (const WylPolicyServiceHandoffMaintenanceProof * proof)
{
  if (proof == NULL || !service_handoff_exact_tuple_is_valid (&proof->tuple)
      || proof->deadline_at_us <= 0
      || sodium_is_zero (proof->target_digest, sizeof proof->target_digest))
    return FALSE;
  if (proof->operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE)
    return proof->subject_id != NULL
        && wyl_policy_service_subject_is_valid (proof->subject_id,
        strlen (proof->subject_id))
        && wyl_policy_store_tenant_id_is_valid (proof->tenant_id)
        && proof->old_credential_id == NULL;
  if (proof->operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE)
    return proof->subject_id == NULL && proof->tenant_id == NULL
        && proof->old_credential_id != NULL
        && wyl_service_credential_id_is_canonical (proof->old_credential_id,
        strlen (proof->old_credential_id));
  return FALSE;
}

static const gchar *service_handoff_maintenance_operation_name
    (const WylPolicyServiceHandoffMaintenanceProof * proof)
{
  return proof->operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE ?
      "issue" : "rotate";
}

static gboolean
    service_handoff_maintenance_escrow_matches
    (const wyl_policy_service_handoff_escrow_info_t * escrow,
    const WylPolicyServiceHandoffMaintenanceProof * proof,
    const gchar * successor_credential_id, guint64 successor_generation,
    const guint8 * binding_digest)
{
  return g_strcmp0 (escrow->operation,
      service_handoff_maintenance_operation_name (proof)) == 0
      && g_strcmp0 (escrow->request_id,
      proof->tuple.original_request_id) == 0
      && g_strcmp0 (escrow->actor_subject_id,
      proof->tuple.original_actor_subject_id) == 0
      && sodium_memcmp (escrow->target_digest, proof->target_digest,
      sizeof proof->target_digest) == 0
      && escrow->deadline_at_us == proof->deadline_at_us
      && g_strcmp0 (escrow->credential_id, successor_credential_id) == 0
      && escrow->credential_generation == successor_generation
      && (binding_digest == NULL
      || sodium_memcmp (escrow->binding_digest, binding_digest,
          WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES) == 0);
}

static wyrelog_error_t
service_handoff_maintenance_classify_escrow (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffMaintenanceProof *proof,
    const gchar *successor_credential_id, guint64 successor_generation,
    const guint8 *binding_digest,
    ServiceHandoffMaintenanceEscrowState *out_state,
    wyl_policy_service_handoff_escrow_info_t *out_escrow)
{
  *out_state = SERVICE_HANDOFF_MAINTENANCE_ESCROW_FOREIGN;
  wyrelog_error_t rc = wyl_policy_store_service_handoff_escrow_load (store,
      proof->tuple.escrow_id, out_escrow);
  if (rc == WYRELOG_E_NOT_FOUND) {
    wyl_policy_service_handoff_escrow_info_t by_request = { 0 };
    rc = wyl_policy_store_service_handoff_escrow_load_by_request (store,
        proof->tuple.original_request_id, &by_request);
    if (rc == WYRELOG_E_NOT_FOUND) {
      *out_state = SERVICE_HANDOFF_MAINTENANCE_ESCROW_MISSING;
      return WYRELOG_E_OK;
    }
    if (rc == WYRELOG_E_POLICY) {
      *out_state = SERVICE_HANDOFF_MAINTENANCE_ESCROW_FOREIGN;
      return WYRELOG_E_OK;
    }
    if (rc != WYRELOG_E_OK)
      return rc;
    wyl_policy_service_handoff_escrow_info_clear (&by_request);
    *out_state = SERVICE_HANDOFF_MAINTENANCE_ESCROW_FOREIGN;
    return WYRELOG_E_OK;
  }
  if (rc == WYRELOG_E_POLICY) {
    *out_state = SERVICE_HANDOFF_MAINTENANCE_ESCROW_FOREIGN;
    return WYRELOG_E_OK;
  }
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!service_handoff_maintenance_escrow_matches (out_escrow, proof,
          successor_credential_id, successor_generation, binding_digest)) {
    *out_state = SERVICE_HANDOFF_MAINTENANCE_ESCROW_FOREIGN;
    return WYRELOG_E_OK;
  }
  wyl_policy_service_handoff_escrow_input_t binding_input = {
    .escrow_id = &out_escrow->escrow_id,
    .operation = out_escrow->operation,
    .request_id = out_escrow->request_id,
    .actor_subject_id = out_escrow->actor_subject_id,
    .target_digest = out_escrow->target_digest,
    .credential_id = out_escrow->credential_id,
    .credential_generation = out_escrow->credential_generation,
    .deadline_at_us = out_escrow->deadline_at_us,
  };
  guint8 recomputed[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES] = { 0 };
  rc = service_handoff_binding_digest (&binding_input, recomputed);
  gboolean exact = rc == WYRELOG_E_OK
      && sodium_memcmp (recomputed, out_escrow->binding_digest,
      sizeof recomputed) == 0;
  sodium_memzero (recomputed, sizeof recomputed);
  if (rc != WYRELOG_E_OK)
    return rc;
  *out_state = exact ? SERVICE_HANDOFF_MAINTENANCE_ESCROW_EXACT :
      SERVICE_HANDOFF_MAINTENANCE_ESCROW_FOREIGN;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
service_handoff_maintenance_digest_frame (crypto_generichash_state *state,
    const guint8 *value, gsize len)
{
  if (len > G_MAXUINT32 || (len != 0 && value == NULL))
    return WYRELOG_E_INVALID;
  guint32 framed_len = GUINT32_TO_BE ((guint32) len);
  if (crypto_generichash_update (state, (const guint8 *) &framed_len,
          sizeof framed_len) != 0
      || (len != 0 && crypto_generichash_update (state, value, len) != 0))
    return WYRELOG_E_CRYPTO;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
    service_handoff_maintenance_proof_digest
    (const WylPolicyServiceHandoffMaintenanceProof * proof,
    guint8 out[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES])
{
  static const gchar domain[] =
      "wyrelog.service-handoff-maintenance-not-committed-proof.v1";
  gchar escrow[WYL_ID_STRING_BUF];
  if (wyl_id_format (proof->tuple.escrow_id, escrow, sizeof escrow)
      != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  const gchar *operation = service_handoff_maintenance_operation_name (proof);
  const gchar *target_a = proof->operation ==
      WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE ? proof->subject_id :
      proof->old_credential_id;
  const gchar *target_b = proof->operation ==
      WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE ? proof->tenant_id : NULL;
  guint64 deadline = GUINT64_TO_BE ((guint64) proof->deadline_at_us);
  crypto_generichash_state state;
  if (crypto_generichash_init (&state, NULL, 0,
          WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES) != 0)
    return WYRELOG_E_CRYPTO;
  wyrelog_error_t rc = service_handoff_maintenance_digest_frame (&state,
      (const guint8 *) domain, sizeof domain - 1);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_maintenance_digest_frame (&state,
        (const guint8 *) operation, strlen (operation));
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_maintenance_digest_frame (&state,
        (const guint8 *) target_a, strlen (target_a));
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_maintenance_digest_frame (&state,
        (const guint8 *) target_b, target_b != NULL ? strlen (target_b) : 0);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_maintenance_digest_frame (&state,
        (const guint8 *) proof->tuple.original_request_id,
        strlen (proof->tuple.original_request_id));
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_maintenance_digest_frame (&state,
        (const guint8 *) escrow, strlen (escrow));
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_maintenance_digest_frame (&state,
        (const guint8 *) proof->tuple.original_actor_subject_id,
        strlen (proof->tuple.original_actor_subject_id));
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_maintenance_digest_frame (&state,
        proof->target_digest, sizeof proof->target_digest);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_maintenance_digest_frame (&state,
        (const guint8 *) &deadline, sizeof deadline);
  if (rc == WYRELOG_E_OK && crypto_generichash_final (&state, out,
          WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES) != 0)
    rc = WYRELOG_E_CRYPTO;
  sodium_memzero (&state, sizeof state);
  if (rc != WYRELOG_E_OK)
    sodium_memzero (out, WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES);
  return rc;
}

static wyrelog_error_t
    service_handoff_maintenance_no_commit_evidence
    (const WylPolicyServiceHandoffMaintenanceProof * proof,
    WylPolicyServiceHandoffNoCommitEvidence * out_evidence)
{
  *out_evidence = (WylPolicyServiceHandoffNoCommitEvidence) {
  .operation = proof->operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE ?
        WYL_POLICY_HANDOFF_FENCE_ISSUE :
        WYL_POLICY_HANDOFF_FENCE_ROTATE,.target_a =
        proof->operation ==
        WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE ? proof->
        subject_id : proof->old_credential_id,.target_b =
        proof->operation ==
        WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE ? proof->tenant_id : NULL,};
  return service_handoff_maintenance_proof_digest (proof,
      out_evidence->maintenance_proof_digest);
}

static wyrelog_error_t
service_handoff_maintenance_validate_no_commit (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffMaintenanceProof *proof,
    const gchar *disposition_id, const gchar *audit_id,
    const gchar *actor_subject_id)
{
  WylPolicyServiceHandoffNoCommitEvidence evidence = { 0 };
  wyrelog_error_t rc = service_handoff_maintenance_no_commit_evidence (proof,
      &evidence);
  WylPolicyServiceHandoffDispositionInput input = {
    .disposition_id = disposition_id,
    .audit_id = audit_id,
    .tuple = proof->tuple,
    .actor_subject_id = actor_subject_id,
    .reason = WYL_POLICY_HANDOFF_DISPOSITION_NOT_COMMITTED,
    .outcome = WYL_POLICY_HANDOFF_OUTCOME_TERMINAL_NOT_COMMITTED,
    .no_commit_evidence = &evidence,
  };
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_validate_no_commit_fence (store, &input);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_escrow_absent (store, proof->tuple.escrow_id);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_request_escrow_absent (store,
        proof->tuple.original_request_id);
  return rc;
}

static wyrelog_error_t
service_handoff_maintenance_lookup_not_committed (wyl_policy_store_t *store,
    const WylPolicyServiceHandoffMaintenanceProof *proof,
    gboolean *out_found, WylPolicyServiceHandoffDispositionResult *out)
{
  *out_found = FALSE;
  gchar escrow[WYL_ID_STRING_BUF];
  if (wyl_id_format (proof->tuple.escrow_id, escrow, sizeof escrow)
      != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT disposition_id,semantic_key,audit_id,created_at_us,"
      " actor_subject_id FROM service_credential_handoff_dispositions"
      " WHERE original_request_id=? AND reason='not_committed'"
      " AND outcome='terminal_not_committed' AND escrow_id=?"
      " AND binding_digest=? AND successor_credential_id IS NULL"
      " AND successor_issuance_generation IS NULL LIMIT 2;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK
      && ((rc = bind_text (stmt, 1, proof->tuple.original_request_id))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 2, escrow))
          != WYRELOG_E_OK || sqlite3_bind_blob (stmt, 3,
              proof->tuple.binding_digest, sizeof proof->tuple.binding_digest,
              SQLITE_TRANSIENT) != SQLITE_OK))
    rc = service_handoff_sqlite_error (store->db,
        sqlite3_extended_errcode (store->db));
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW) {
    const gchar *disposition_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *audit_id = (const gchar *) sqlite3_column_text (stmt, 2);
    gint64 created_at_us = sqlite3_column_int64 (stmt, 3);
    const gchar *actor = (const gchar *) sqlite3_column_text (stmt, 4);
    WylPolicyServiceHandoffNoCommitEvidence evidence = { 0 };
    WylPolicyServiceHandoffDispositionInput input = {
      .disposition_id = disposition_id,
      .audit_id = audit_id,
      .tuple = proof->tuple,
      .actor_subject_id = actor,
      .reason = WYL_POLICY_HANDOFF_DISPOSITION_NOT_COMMITTED,
      .outcome = WYL_POLICY_HANDOFF_OUTCOME_TERMINAL_NOT_COMMITTED,
      .no_commit_evidence = &evidence,
    };
    guint8 semantic_key[crypto_generichash_BYTES] = { 0 };
    rc = service_handoff_maintenance_no_commit_evidence (proof, &evidence);
    if (rc == WYRELOG_E_OK)
      rc = disposition_id != NULL && audit_id != NULL
          && wyl_policy_service_actor_subject_is_valid (actor)
          && sqlite3_column_type (stmt, 1) == SQLITE_BLOB
          && sqlite3_column_bytes (stmt, 1) == sizeof semantic_key
          && sqlite3_column_type (stmt, 3) == SQLITE_INTEGER
          && created_at_us > 0 ? service_handoff_disposition_semantic_key
          (&input, semantic_key) : WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK
        && sodium_memcmp (sqlite3_column_blob (stmt, 1), semantic_key,
            sizeof semantic_key) != 0)
      rc = WYRELOG_E_POLICY;
    sodium_memzero (semantic_key, sizeof semantic_key);
    if (rc == WYRELOG_E_OK)
      rc = service_handoff_validate_exact_audit_pair (store, audit_id,
          created_at_us, actor, "service.credential.handoff.disposition",
          proof->tuple.original_request_id, proof->tuple.original_request_id);
    if (rc == WYRELOG_E_OK)
      rc = service_handoff_maintenance_validate_no_commit (store, proof,
          disposition_id, audit_id, actor);
    if (rc == WYRELOG_E_OK)
      rc = service_handoff_fill_disposition_result (disposition_id, audit_id,
          created_at_us, TRUE, out);
    if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK)
      *out_found = TRUE;
  } else if (rc == WYRELOG_E_OK && step != SQLITE_DONE) {
    rc = service_handoff_sqlite_error (store->db, step);
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
    service_handoff_maintenance_reject_orphan_cancellation
    (wyl_policy_store_t * store,
    const WylPolicyServiceHandoffMaintenanceProof * proof)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT 1 FROM service_credential_handoff_dispositions"
      " WHERE original_request_id=? AND reason='operation_cancelled'"
      " AND outcome='attention_required' LIMIT 1;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 1, proof->tuple.original_request_id);
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW)
    rc = WYRELOG_E_POLICY;
  else if (rc == WYRELOG_E_OK && step != SQLITE_DONE)
    rc = service_handoff_sqlite_error (store->db, step);
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return service_handoff_map_sqlite_io (store->db, rc);
}

static wyrelog_error_t
    service_handoff_maintenance_mint_not_committed
    (WylServiceAuthorityTransaction * transaction, wyl_policy_store_t * store,
    const WylPolicyServiceHandoffMaintenanceProof * proof, gint64 now_us,
    WylPolicyServiceHandoffDispositionResult * out)
{
  gchar disposition_id[WYL_ID_STRING_BUF];
  gchar audit_id[WYL_ID_STRING_BUF];
  wyrelog_error_t rc = service_domain_new_audit_id (disposition_id);
  if (rc == WYRELOG_E_OK)
    rc = service_domain_new_audit_id (audit_id);
  WylPolicyServiceHandoffNoCommitEvidence evidence = { 0 };
  WylPolicyServiceHandoffDispositionInput input = {
    .disposition_id = disposition_id,
    .audit_id = audit_id,
    .tuple = proof->tuple,
    .actor_subject_id = SERVICE_HANDOFF_MAINTENANCE_ACTOR,
    .reason = WYL_POLICY_HANDOFF_DISPOSITION_NOT_COMMITTED,
    .outcome = WYL_POLICY_HANDOFF_OUTCOME_TERMINAL_NOT_COMMITTED,
    .no_commit_evidence = &evidence,
  };
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_maintenance_no_commit_evidence (proof, &evidence);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_record_disposition (transaction, store, &input, TRUE,
        now_us, out);
  return rc;
}

static wyrelog_error_t
    service_handoff_maintenance_recover_prepared_cancellation
    (wyl_policy_store_t * store,
    const WylPolicyServiceHandoffMaintenanceProof * proof,
    gboolean * out_found,
    WylPolicyServiceHandoffPreparedMaintenanceResult * out_result)
{
  *out_found = FALSE;
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT cancellation_request_id,decision_request_id,"
      "current_actor_subject_id,disposition_id,audit_id FROM"
      " service_credential_handoff_cancellation_claims"
      " WHERE original_request_id=? LIMIT 2;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 1, proof->tuple.original_request_id);
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  g_autofree gchar *cancellation_request_id = NULL;
  g_autofree gchar *decision_request_id = NULL;
  g_autofree gchar *current_actor = NULL;
  g_autofree gchar *disposition_id = NULL;
  g_autofree gchar *audit_id = NULL;
  gboolean row_found = step == SQLITE_ROW;
  if (rc == WYRELOG_E_OK && row_found) {
    cancellation_request_id = service_handoff_try_strdup
        ((const gchar *) sqlite3_column_text (stmt, 0));
    decision_request_id = service_handoff_try_strdup
        ((const gchar *) sqlite3_column_text (stmt, 1));
    current_actor = service_handoff_try_strdup
        ((const gchar *) sqlite3_column_text (stmt, 2));
    disposition_id = service_handoff_try_strdup
        ((const gchar *) sqlite3_column_text (stmt, 3));
    audit_id = service_handoff_try_strdup
        ((const gchar *) sqlite3_column_text (stmt, 4));
    if (cancellation_request_id == NULL || decision_request_id == NULL
        || current_actor == NULL || disposition_id == NULL || audit_id == NULL)
      rc = WYRELOG_E_NOMEM;
    else if (sqlite3_step (stmt) != SQLITE_DONE)
      rc = WYRELOG_E_POLICY;
  } else if (rc == WYRELOG_E_OK && step != SQLITE_DONE) {
    rc = service_handoff_sqlite_error (store->db, step);
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  if (rc != WYRELOG_E_OK || !row_found)
    return rc;

  WylPolicyServiceHandoffCancellationInput input = {
    .cancellation_request_id = cancellation_request_id,
    .decision_request_id = decision_request_id,
    .current_actor_subject_id = current_actor,
    .disposition_id = disposition_id,
    .audit_id = audit_id,
    .tuple = proof->tuple,
    .observation = WYL_POLICY_HANDOFF_CANCELLATION_OBSERVATION_PREPARED,
    .operation = proof->operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE ?
        WYL_POLICY_HANDOFF_FENCE_ISSUE : WYL_POLICY_HANDOFF_FENCE_ROTATE,
    .target_a = proof->operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE ?
        proof->subject_id : proof->old_credential_id,
    .target_b = proof->operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE ?
        proof->tenant_id : NULL,
    .deadline_at_us = proof->deadline_at_us,
  };
  memcpy (input.target_digest, proof->target_digest,
      sizeof input.target_digest);
  WylPolicyServiceHandoffCancellationResult cancellation = { 0 };
  if (!service_handoff_cancellation_shape_valid (&input))
    rc = WYRELOG_E_POLICY;
  gboolean exact_found = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_cancellation_lookup (store, &input, TRUE, TRUE, TRUE,
        &exact_found, &cancellation);
  if (rc == WYRELOG_E_OK && !exact_found)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK
      && cancellation.outcome ==
      WYL_POLICY_HANDOFF_CANCELLATION_COMMITTED_ATTENTION) {
    out_result->outcome = WYL_POLICY_HANDOFF_PREPARED_MAINTENANCE_COMMITTED;
    out_result->created_at_us = cancellation.created_at_us;
    g_strlcpy (out_result->successor_credential_id,
        cancellation.successor_credential_id,
        sizeof out_result->successor_credential_id);
    out_result->successor_generation =
        cancellation.successor_issuance_generation;
    memcpy (out_result->binding_digest, cancellation.binding_digest,
        sizeof out_result->binding_digest);
  } else if (rc == WYRELOG_E_OK
      && cancellation.outcome ==
      WYL_POLICY_HANDOFF_CANCELLATION_TERMINAL_NOT_COMMITTED) {
    out_result->outcome = WYL_POLICY_HANDOFF_PREPARED_MAINTENANCE_NOT_COMMITTED;
    out_result->created_at_us = cancellation.created_at_us;
    rc = service_handoff_fill_disposition_result
        (cancellation.disposition_id, cancellation.audit_id,
        cancellation.created_at_us, TRUE, &out_result->disposition);
  } else if (rc == WYRELOG_E_OK) {
    rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    *out_found = TRUE;
  wyl_policy_service_handoff_cancellation_result_clear (&cancellation);
  return rc;
}

wyrelog_error_t
    wyl_policy_store_handoff_maintain_prepared_core
    (WylServiceAuthorityTransaction * transaction, wyl_policy_store_t * store,
    const WylPolicyServiceHandoffMaintenanceProof * proof,
    WylPolicyServiceHandoffPreparedMaintenanceResult * out_result)
{
  if (out_result != NULL)
    wyl_policy_service_handoff_prepared_maintenance_result_clear (out_result);
  if (store == NULL || out_result == NULL
      || !service_handoff_maintenance_proof_is_valid (proof)
      || proof->tuple.successor_credential_id != NULL
      || !sodium_is_zero (proof->tuple.binding_digest,
          sizeof proof->tuple.binding_digest))
    return WYRELOG_E_INVALID;
  /* Fence reconciliation owns write-intent acquisition.  Merely entering as
   * a participant first would mark durable work started and make that later
   * acquisition fail closed. */
  wyrelog_error_t rc = service_authority_transaction_validate_active
      (transaction, store);
  gboolean cancellation_found = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_maintenance_recover_prepared_cancellation
        (store, proof, &cancellation_found, out_result);
  if (rc == WYRELOG_E_OK && cancellation_found) {
    rc = wyl_policy_store_service_authority_transaction_enter_participant
        (transaction, store);
    if (rc != WYRELOG_E_OK)
      wyl_policy_service_handoff_prepared_maintenance_result_clear (out_result);
    return rc;
  }
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_maintenance_reject_orphan_cancellation (store, proof);
  WylPolicyServiceHandoffDispositionResult disposition = { 0 };
  gboolean found = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_maintenance_lookup_not_committed (store, proof,
        &found, &disposition);
  if (rc == WYRELOG_E_OK && found) {
    rc = wyl_policy_store_service_authority_transaction_enter_participant
        (transaction, store);
    if (rc != WYRELOG_E_OK)
      goto out;
    out_result->outcome = WYL_POLICY_HANDOFF_PREPARED_MAINTENANCE_NOT_COMMITTED;
    out_result->created_at_us = disposition.created_at_us;
    out_result->disposition = disposition;
    memset (&disposition, 0, sizeof disposition);
    return WYRELOG_E_OK;
  }
  gint64 now_us = 0;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_maintenance_now (store, &now_us);
  if (rc == WYRELOG_E_OK && now_us < proof->deadline_at_us) {
    rc = wyl_policy_store_service_authority_transaction_enter_participant
        (transaction, store);
    if (rc != WYRELOG_E_OK)
      goto out;
    out_result->outcome = WYL_POLICY_HANDOFF_PREPARED_MAINTENANCE_NOT_DUE;
    out_result->created_at_us = now_us;
    return WYRELOG_E_OK;
  }
  WylServiceCredentialFenceResult fence = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_reconcile_service_credential_operation_fence
        (transaction, store, NULL, proof->operation,
        proof->tuple.original_request_id, proof->subject_id, proof->tenant_id,
        proof->old_credential_id, &fence);
  if (rc == WYRELOG_E_OK
      && fence.state == WYL_SERVICE_CREDENTIAL_FENCE_RESULT_CONFLICT)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK
      && fence.state == WYL_SERVICE_CREDENTIAL_FENCE_RESULT_COMMITTED) {
    wyl_policy_service_handoff_escrow_info_t escrow = { 0 };
    ServiceHandoffMaintenanceEscrowState escrow_state = 0;
    rc = service_handoff_maintenance_classify_escrow (store, proof,
        fence.successor_credential_id, fence.successor_generation, NULL,
        &escrow_state, &escrow);
    if (rc == WYRELOG_E_OK
        && escrow_state != SERVICE_HANDOFF_MAINTENANCE_ESCROW_EXACT)
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK) {
      out_result->outcome = WYL_POLICY_HANDOFF_PREPARED_MAINTENANCE_COMMITTED;
      out_result->created_at_us = now_us;
      g_strlcpy (out_result->successor_credential_id,
          fence.successor_credential_id,
          sizeof out_result->successor_credential_id);
      out_result->successor_generation = fence.successor_generation;
      memcpy (out_result->binding_digest, escrow.binding_digest,
          sizeof out_result->binding_digest);
    }
    wyl_policy_service_handoff_escrow_info_clear (&escrow);
    return rc;
  }
  if (rc == WYRELOG_E_OK
      && fence.state !=
      WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_maintenance_mint_not_committed (transaction, store,
        proof, now_us, &disposition);
  if (rc == WYRELOG_E_OK) {
    out_result->outcome = WYL_POLICY_HANDOFF_PREPARED_MAINTENANCE_NOT_COMMITTED;
    out_result->created_at_us = disposition.created_at_us;
    out_result->disposition = disposition;
    memset (&disposition, 0, sizeof disposition);
  }
out:
  wyl_policy_service_handoff_disposition_result_clear (&disposition);
  return rc;
}

static wyrelog_error_t
    service_handoff_maintenance_lookup_claimed_cancellation
    (wyl_policy_store_t * store,
    const WylPolicyServiceHandoffMaintenanceProof * proof,
    gboolean validate_authority, gboolean strict_cardinality,
    gboolean * out_found, WylPolicyServiceHandoffDispositionResult * out)
{
  *out_found = FALSE;
  sqlite3_stmt *stmt = NULL;
  static const gchar *claim_sql =
      "SELECT cancellation_request_id,decision_request_id,"
      "current_actor_subject_id,disposition_id,audit_id FROM"
      " service_credential_handoff_cancellation_claims"
      " WHERE original_request_id=? LIMIT 2;";
  wyrelog_error_t rc = prepare_stmt (store->db, claim_sql, &stmt);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 1, proof->tuple.original_request_id);
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  g_autofree gchar *cancellation_request_id = NULL;
  g_autofree gchar *decision_request_id = NULL;
  g_autofree gchar *current_actor = NULL;
  g_autofree gchar *disposition_id = NULL;
  g_autofree gchar *audit_id = NULL;
  gboolean claim_found = step == SQLITE_ROW;
  if (rc == WYRELOG_E_OK && claim_found) {
    cancellation_request_id = service_handoff_try_strdup
        ((const gchar *) sqlite3_column_text (stmt, 0));
    decision_request_id = service_handoff_try_strdup
        ((const gchar *) sqlite3_column_text (stmt, 1));
    current_actor = service_handoff_try_strdup
        ((const gchar *) sqlite3_column_text (stmt, 2));
    disposition_id = service_handoff_try_strdup
        ((const gchar *) sqlite3_column_text (stmt, 3));
    audit_id = service_handoff_try_strdup
        ((const gchar *) sqlite3_column_text (stmt, 4));
    if (cancellation_request_id == NULL || decision_request_id == NULL
        || current_actor == NULL || disposition_id == NULL || audit_id == NULL)
      rc = WYRELOG_E_NOMEM;
    else if (sqlite3_step (stmt) != SQLITE_DONE)
      rc = WYRELOG_E_POLICY;
  } else if (rc == WYRELOG_E_OK && step != SQLITE_DONE) {
    rc = service_handoff_sqlite_error (store->db, step);
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);

  stmt = NULL;
  static const gchar *disposition_sql =
      "SELECT count(*) FROM service_credential_handoff_dispositions"
      " WHERE original_request_id=?"
      " AND reason='operation_cancelled' AND outcome='attention_required';";
  if (rc == WYRELOG_E_OK)
    rc = prepare_stmt (store->db, disposition_sql, &stmt);
  if (rc == WYRELOG_E_OK)
    rc = bind_text (stmt, 1, proof->tuple.original_request_id);
  step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  gboolean disposition_found = FALSE;
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW) {
    gint64 count = sqlite3_column_int64 (stmt, 0);
    disposition_found = count == 1;
    rc = (count == 0 || count == 1) && sqlite3_step (stmt) == SQLITE_DONE ?
        WYRELOG_E_OK : WYRELOG_E_POLICY;
  } else if (rc == WYRELOG_E_OK) {
    rc = service_handoff_sqlite_error (store->db, step);
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  if (rc == WYRELOG_E_OK && claim_found != disposition_found)
    rc = WYRELOG_E_POLICY;
  if (rc != WYRELOG_E_OK || !claim_found)
    return rc;

  WylPolicyServiceHandoffCancellationInput input = {
    .cancellation_request_id = cancellation_request_id,
    .decision_request_id = decision_request_id,
    .current_actor_subject_id = current_actor,
    .disposition_id = disposition_id,
    .audit_id = audit_id,
    .tuple = proof->tuple,
    .observation = WYL_POLICY_HANDOFF_CANCELLATION_OBSERVATION_COMMITTED,
    .operation = proof->operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE ?
        WYL_POLICY_HANDOFF_FENCE_ISSUE : WYL_POLICY_HANDOFF_FENCE_ROTATE,
    .target_a = proof->operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE ?
        proof->subject_id : proof->old_credential_id,
    .target_b = proof->operation == WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE ?
        proof->tenant_id : NULL,
    .deadline_at_us = proof->deadline_at_us,
  };
  memcpy (input.target_digest, proof->target_digest,
      sizeof input.target_digest);
  WylPolicyServiceHandoffCancellationResult cancellation = { 0 };
  if (!service_handoff_cancellation_shape_valid (&input))
    rc = WYRELOG_E_POLICY;
  gboolean exact_found = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_cancellation_lookup (store, &input,
        validate_authority, validate_authority, strict_cardinality,
        &exact_found, &cancellation);
  if (rc == WYRELOG_E_OK && !exact_found)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_fill_disposition_result (cancellation.disposition_id,
        cancellation.audit_id, cancellation.created_at_us, TRUE, out);
  if (rc == WYRELOG_E_OK)
    *out_found = TRUE;
  wyl_policy_service_handoff_cancellation_result_clear (&cancellation);
  return rc;
}

static wyrelog_error_t
    service_handoff_maintenance_lookup_attention
    (wyl_policy_store_t * store,
    const WylPolicyServiceHandoffMaintenanceProof * proof, gboolean * out_found,
    WylPolicyServiceHandoffCommittedMaintenanceOutcome * out_outcome,
    WylPolicyServiceHandoffDispositionResult * out_disposition)
{
  gboolean expired_found = FALSE;
  gboolean cancelled_found = FALSE;
  WylPolicyServiceHandoffDispositionResult expired = { 0 };
  WylPolicyServiceHandoffDispositionResult cancelled = { 0 };
  wyrelog_error_t rc = service_handoff_lookup_minted_disposition (store,
      &proof->tuple, WYL_POLICY_HANDOFF_DISPOSITION_OPERATION_EXPIRED,
      WYL_POLICY_HANDOFF_OUTCOME_ATTENTION_REQUIRED, &expired_found, &expired);
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_maintenance_lookup_claimed_cancellation (store,
        proof, TRUE, TRUE, &cancelled_found, &cancelled);
  if (rc == WYRELOG_E_OK && expired_found && cancelled_found)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && expired_found) {
    *out_found = TRUE;
    *out_outcome = WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_OPERATION_EXPIRED;
    *out_disposition = expired;
    memset (&expired, 0, sizeof expired);
  } else if (rc == WYRELOG_E_OK && cancelled_found) {
    *out_found = TRUE;
    *out_outcome = WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_OPERATION_CANCELLED;
    *out_disposition = cancelled;
    memset (&cancelled, 0, sizeof cancelled);
  }
  wyl_policy_service_handoff_disposition_result_clear (&expired);
  wyl_policy_service_handoff_disposition_result_clear (&cancelled);
  return rc;
}

static wyrelog_error_t
    service_handoff_maintenance_attention_resumed
    (WylServiceAuthorityTransaction * transaction, wyl_policy_store_t * store,
    const WylPolicyServiceHandoffMaintenanceProof * proof,
    WylPolicyServiceHandoffCommittedMaintenanceOutcome attention,
    const WylPolicyServiceHandoffDispositionResult * disposition,
    gboolean * out_resumed)
{
  *out_resumed = FALSE;
  gchar escrow[WYL_ID_STRING_BUF];
  if (wyl_id_format (proof->tuple.escrow_id, escrow, sizeof escrow)
      != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  const gchar *reason = attention ==
      WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_OPERATION_CANCELLED ?
      "operation_cancelled" : "operation_expired";
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT journal_snapshot_digest FROM"
      " service_credential_handoff_remediation_actions"
      " WHERE source_kind='committed_attention' AND action='resume'"
      " AND outcome='recorded' AND escrow_outcome='retained'"
      " AND original_request_id=? AND source_disposition_id=?"
      " AND source_audit_id=? AND source_reason=? AND escrow_id=?"
      " AND binding_digest=? AND successor_credential_id=?"
      " AND successor_issuance_generation=? LIMIT 2;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK
      && ((rc = bind_text (stmt, 1, proof->tuple.original_request_id))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 2,
                  disposition->disposition_id)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 3, disposition->audit_id))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 4, reason))
          != WYRELOG_E_OK || (rc = bind_text (stmt, 5, escrow))
          != WYRELOG_E_OK || sqlite3_bind_blob (stmt, 6,
              proof->tuple.binding_digest, 32, SQLITE_TRANSIENT) != SQLITE_OK
          || (rc = bind_text (stmt, 7,
                  proof->tuple.successor_credential_id)) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 8, (sqlite3_int64)
              proof->tuple.successor_issuance_generation) != SQLITE_OK))
    rc = WYRELOG_E_IO;
  int step = rc == WYRELOG_E_OK ? sqlite3_step (stmt) : SQLITE_DONE;
  guint8 snapshot[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES] = { 0 };
  if (rc == WYRELOG_E_OK && step == SQLITE_ROW) {
    if (sqlite3_column_type (stmt, 0) != SQLITE_BLOB
        || sqlite3_column_bytes (stmt, 0) != sizeof snapshot)
      rc = WYRELOG_E_POLICY;
    else
      memcpy (snapshot, sqlite3_column_blob (stmt, 0), sizeof snapshot);
    if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
      rc = WYRELOG_E_POLICY;
  } else if (rc == WYRELOG_E_OK && step != SQLITE_DONE) {
    rc = service_handoff_sqlite_error (store->db, step);
  }
  gboolean row_found = step == SQLITE_ROW;
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  WylPolicyServiceHandoffRemediationResult remediation = { 0 };
  if (rc == WYRELOG_E_OK && row_found)
    rc = wyl_policy_store_resolve_service_handoff_remediation_incident_core
        (transaction, store, proof->tuple.original_request_id, snapshot,
        &remediation);
  if (rc == WYRELOG_E_OK && row_found
      && (remediation.action != WYL_POLICY_HANDOFF_REMEDIATION_RESUME
          || remediation.escrow_outcome !=
          WYL_POLICY_HANDOFF_REMEDIATION_ESCROW_RETAINED
          || g_strcmp0 (remediation.source_disposition_id,
              disposition->disposition_id) != 0
          || g_strcmp0 (remediation.source_audit_id,
              disposition->audit_id) != 0))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    *out_resumed = row_found;
  wyl_policy_service_handoff_remediation_result_clear (&remediation);
  sodium_memzero (snapshot, sizeof snapshot);
  return rc;
}

wyrelog_error_t
    wyl_policy_store_handoff_resolve_current_attention_core
    (WylServiceAuthorityTransaction * transaction, wyl_policy_store_t * store,
    const WylPolicyServiceHandoffMaintenanceProof * proof,
    WylPolicyServiceHandoffCommittedMaintenanceResult * out_result)
{
  if (out_result != NULL)
    wyl_policy_service_handoff_committed_maintenance_result_clear (out_result);
  if (store == NULL || out_result == NULL
      || !service_handoff_maintenance_proof_is_valid (proof)
      || proof->tuple.successor_credential_id == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc =
      wyl_policy_store_service_authority_transaction_enter_participant
      (transaction, store);
  gboolean found = FALSE;
  gboolean resumed = FALSE;
  WylPolicyServiceHandoffCommittedMaintenanceOutcome attention = 0;
  WylPolicyServiceHandoffDispositionResult disposition = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_maintenance_lookup_attention (store, proof, &found,
        &attention, &disposition);
  if (rc == WYRELOG_E_OK && found)
    rc = service_handoff_maintenance_attention_resumed (transaction, store,
        proof, attention, &disposition, &resumed);
  if (rc == WYRELOG_E_OK && (!found || resumed))
    rc = WYRELOG_E_NOT_FOUND;
  if (rc == WYRELOG_E_OK) {
    out_result->outcome = attention;
    out_result->created_at_us = disposition.created_at_us;
    out_result->disposition = disposition;
    memset (&disposition, 0, sizeof disposition);
  }
  wyl_policy_service_handoff_disposition_result_clear (&disposition);
  return rc;
}

wyrelog_error_t
    wyl_policy_store_handoff_maintain_committed_core
    (WylServiceAuthorityTransaction * transaction, wyl_policy_store_t * store,
    const WylPolicyServiceHandoffMaintenanceProof * proof,
    WylPolicyServiceHandoffCommittedMaintenanceResult * out_result)
{
  if (out_result != NULL)
    wyl_policy_service_handoff_committed_maintenance_result_clear (out_result);
  if (store == NULL || out_result == NULL
      || !service_handoff_maintenance_proof_is_valid (proof)
      || proof->tuple.successor_credential_id == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc =
      wyl_policy_store_service_authority_transaction_enter_participant
      (transaction, store);
  gint64 now_us = 0;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_maintenance_now (store, &now_us);
  gboolean cancellation_artifact_found = FALSE;
  WylPolicyServiceHandoffDispositionResult cancellation_artifact = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_maintenance_lookup_claimed_cancellation (store,
        proof, FALSE, FALSE, &cancellation_artifact_found,
        &cancellation_artifact);
  wyl_policy_service_handoff_disposition_result_clear (&cancellation_artifact);
  if (rc != WYRELOG_E_OK)
    return rc;
  wyl_policy_service_handoff_escrow_info_t escrow = { 0 };
  ServiceHandoffMaintenanceEscrowState escrow_state = 0;
  if (rc == WYRELOG_E_OK)
    rc = service_handoff_maintenance_classify_escrow (store, proof,
        proof->tuple.successor_credential_id,
        proof->tuple.successor_issuance_generation,
        proof->tuple.binding_digest, &escrow_state, &escrow);
  wyl_policy_service_handoff_escrow_info_clear (&escrow);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (escrow_state == SERVICE_HANDOFF_MAINTENANCE_ESCROW_MISSING) {
    out_result->outcome =
        WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_ESCROW_MISSING;
    out_result->created_at_us = now_us;
    return WYRELOG_E_OK;
  }
  if (escrow_state == SERVICE_HANDOFF_MAINTENANCE_ESCROW_FOREIGN) {
    out_result->outcome =
        WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_ESCROW_FOREIGN;
    out_result->created_at_us = now_us;
    return WYRELOG_E_OK;
  }

  WylPolicyServiceHandoffPublicationOutcome publication = 0;
  WylPolicyServiceHandoffDispositionResult disposition = { 0 };
  rc = service_handoff_classify_for_publication_at (transaction, store,
      &proof->tuple, SERVICE_HANDOFF_MAINTENANCE_ACTOR, now_us, &publication,
      &disposition);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (publication != WYL_POLICY_HANDOFF_PUBLICATION_ACTIVE) {
    out_result->outcome = publication ==
        WYL_POLICY_HANDOFF_PUBLICATION_SUCCESSOR_EXPIRED ?
        WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_SUCCESSOR_EXPIRED :
        WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_SUCCESSOR_REVOKED;
    out_result->created_at_us = disposition.created_at_us;
    out_result->disposition = disposition;
    memset (&disposition, 0, sizeof disposition);
    goto out;
  }

  gboolean found = FALSE;
  WylPolicyServiceHandoffCommittedMaintenanceOutcome attention = 0;
  rc = service_handoff_maintenance_lookup_attention (store, proof, &found,
      &attention, &disposition);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (found) {
    gboolean resumed = FALSE;
    rc = service_handoff_maintenance_attention_resumed (transaction, store,
        proof, attention, &disposition, &resumed);
    if (rc != WYRELOG_E_OK)
      goto out;
    if (resumed) {
      out_result->outcome = WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_ACTIVE;
      out_result->created_at_us = now_us;
      goto out;
    }
    out_result->outcome = attention;
    out_result->created_at_us = disposition.created_at_us;
    out_result->disposition = disposition;
    memset (&disposition, 0, sizeof disposition);
    goto out;
  }
  if (now_us < proof->deadline_at_us) {
    out_result->outcome = WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_ACTIVE;
    out_result->created_at_us = now_us;
    goto out;
  }
  rc = service_handoff_record_minted_disposition (store, &proof->tuple,
      SERVICE_HANDOFF_MAINTENANCE_ACTOR,
      WYL_POLICY_HANDOFF_DISPOSITION_OPERATION_EXPIRED,
      WYL_POLICY_HANDOFF_OUTCOME_ATTENTION_REQUIRED, now_us, &disposition);
  if (rc == WYRELOG_E_OK) {
    out_result->outcome =
        WYL_POLICY_HANDOFF_COMMITTED_MAINTENANCE_OPERATION_EXPIRED;
    out_result->created_at_us = disposition.created_at_us;
    out_result->disposition = disposition;
    memset (&disposition, 0, sizeof disposition);
  }
out:
  wyl_policy_service_handoff_disposition_result_clear (&disposition);
  return rc;
}

static wyrelog_error_t
service_credential_issue_fingerprint (const gchar *subject_id,
    const gchar *tenant_id, const gchar *actor_subject_id,
    gint64 expires_at_us, guint8 out[crypto_generichash_BYTES])
{
  g_autofree gchar *expiry = g_strdup_printf ("%" G_GINT64_FORMAT,
      expires_at_us);
  crypto_generichash_state state;
  static const guint8 domain[] = "wyrelog.service-credential-issue-request.v1";
  if (crypto_generichash_init (&state, NULL, 0, crypto_generichash_BYTES) != 0
      || crypto_generichash_update (&state, domain, sizeof domain - 1) != 0)
    return WYRELOG_E_CRYPTO;
  const gchar *fields[] = {
    subject_id, tenant_id, actor_subject_id, expiry,
  };
  static const guint8 separator = 0;
  for (gsize i = 0; i < G_N_ELEMENTS (fields); i++) {
    if (crypto_generichash_update (&state, (const guint8 *) fields[i],
            strlen (fields[i])) != 0
        || crypto_generichash_update (&state, &separator, 1) != 0) {
      sodium_memzero (&state, sizeof state);
      return WYRELOG_E_CRYPTO;
    }
  }
  int failed = crypto_generichash_final (&state, out,
      crypto_generichash_BYTES);
  sodium_memzero (&state, sizeof state);
  return failed == 0 ? WYRELOG_E_OK : WYRELOG_E_CRYPTO;
}

static wyrelog_error_t
service_credential_id_exists (wyl_policy_store_t *store,
    const gchar *credential_id, gboolean *out_exists)
{
  sqlite3_stmt *stmt = NULL;
  *out_exists = FALSE;
  wyrelog_error_t rc = prepare_stmt (store->db,
      "SELECT 1 FROM service_credentials WHERE credential_id=? LIMIT 1;",
      &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, credential_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }
  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW)
    *out_exists = TRUE;
  sqlite3_finalize (stmt);
  return step_rc == SQLITE_ROW || step_rc == SQLITE_DONE ? WYRELOG_E_OK :
      WYRELOG_E_IO;
}

static wyrelog_error_t
service_credential_insert (wyl_policy_store_t *store,
    const wyl_service_credential_material_t *material, const gchar *subject_id,
    const gchar *tenant_id, const gchar *actor_subject_id, gint64 now_us,
    gint64 expires_at_us)
{
  static const gchar *sql =
      "INSERT INTO service_credentials(credential_id,"
      "credential_format_version,subject_id,tenant_id,generation,state,"
      "verifier_version,salt,verifier,created_by,created_at_us,updated_at_us,"
      "expires_at_us) VALUES(?,?,?,?,1,'active',?,?,?,?,?,?,?);";
  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, material->credential_id)) != WYRELOG_E_OK
      || sqlite3_bind_int64 (stmt, 2,
          material->credential_format_version) != SQLITE_OK
      || (rc = bind_text (stmt, 3, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 4, tenant_id)) != WYRELOG_E_OK
      || sqlite3_bind_int64 (stmt, 5, material->verifier_version) != SQLITE_OK
      || sqlite3_bind_blob (stmt, 6, material->salt, sizeof material->salt,
          SQLITE_TRANSIENT) != SQLITE_OK
      || sqlite3_bind_blob (stmt, 7, material->verifier,
          sizeof material->verifier, SQLITE_TRANSIENT) != SQLITE_OK
      || (rc = bind_text (stmt, 8, actor_subject_id)) != WYRELOG_E_OK
      || sqlite3_bind_int64 (stmt, 9, now_us) != SQLITE_OK
      || sqlite3_bind_int64 (stmt, 10, now_us) != SQLITE_OK
      || (expires_at_us == 0 ? sqlite3_bind_null (stmt, 11) :
          sqlite3_bind_int64 (stmt, 11, expires_at_us)) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  if (step_rc == SQLITE_DONE)
    return WYRELOG_E_OK;
  return (step_rc & 0xff) == SQLITE_CONSTRAINT ? WYRELOG_E_POLICY :
      WYRELOG_E_IO;
}

static wyrelog_error_t
service_credential_append_issued_event (wyl_policy_store_t *store,
    const gchar *credential_id, const gchar *subject_id,
    const gchar *tenant_id, const gchar *actor_subject_id,
    const gchar *request_id, gint64 now_us)
{
  static const gchar *sql =
      "INSERT INTO service_credential_events(credential_id,subject_id,"
      "tenant_id,event,from_state,to_state,generation,actor_subject_id,"
      "request_id,created_at_us) VALUES(?,?,?,'issued',NULL,'active',1,?,?,?);";
  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, credential_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, tenant_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 4, actor_subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 5, request_id)) != WYRELOG_E_OK
      || sqlite3_bind_int64 (stmt, 6, now_us) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return step_rc == SQLITE_DONE ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
    service_credential_issue_impl
    (wyl_policy_store_t * store, const gchar * subject_id,
    const gchar * tenant_id, const gchar * actor_subject_id,
    const gchar * request_id, gint64 expires_at_us,
    const wyl_service_credential_runtime_t * runtime,
    const guint8 * authority_cvk, gsize authority_cvk_len,
    wyl_policy_service_credential_info_t * out,
    wyl_service_credential_secret_t ** out_secret, gboolean authority_owned)
{
  if (out != NULL)
    wyl_policy_service_credential_info_clear (out);
  if (out_secret != NULL)
    wyl_service_credential_secret_clear (out_secret);
  gint64 now_us = g_get_real_time ();
  if (store == NULL || store->db == NULL || out == NULL || out_secret == NULL
      || subject_id == NULL
      || !wyl_policy_service_subject_is_valid (subject_id, strlen (subject_id))
      || !wyl_policy_store_tenant_id_is_valid (tenant_id)
      || !wyl_policy_service_actor_subject_is_valid (actor_subject_id)
      || !service_domain_text_is_valid (request_id, 256)
      || expires_at_us < 0 || (expires_at_us != 0 && expires_at_us <= now_us))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = WYRELOG_E_OK;

  /* Serialize the CVK pre-initialization-to-savepoint handoff so a concurrent
   * issuer cannot start a second SQLite transaction in that narrow window.
   * The required inner order remains CVK ensure/unlock, lifecycle mutex,
   * savepoint. */
  if (authority_owned
      && (authority_cvk == NULL
          || authority_cvk_len != WYL_SERVICE_CREDENTIAL_CVK_BYTES))
    return WYRELOG_E_INVALID;
  if (!authority_owned) {
    WylServiceCredentialFenceResult fence = { 0 };
    rc = wyl_policy_store_precheck_service_credential_operation_fence (store,
        NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE, request_id, subject_id,
        tenant_id, NULL, &fence);
    if (rc == WYRELOG_E_OK)
      rc = WYRELOG_E_POLICY;
    else if (rc == WYRELOG_E_NOT_FOUND)
      rc = WYRELOG_E_OK;
  }
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!authority_owned) {
    wyrelog_error_t scope_rc = service_mutation_scope_enter (store);
    if (scope_rc != WYRELOG_E_OK)
      return scope_rc;
    g_mutex_lock (&store->service_domain_gate_mutex);
  }
  guint8 fingerprint[crypto_generichash_BYTES];
  rc = service_credential_issue_fingerprint (subject_id,
      tenant_id, actor_subject_id, expires_at_us, fingerprint);
  const guint8 *cvk = authority_cvk;
  gsize cvk_len = authority_cvk_len;
  if (rc == WYRELOG_E_OK && !authority_owned)
    rc = wyl_policy_store_ensure_service_cvk_for_issuance (store, &cvk,
        &cvk_len);
  if (rc != WYRELOG_E_OK) {
    sodium_memzero (fingerprint, sizeof fingerprint);
    if (!authority_owned) {
      g_mutex_unlock (&store->service_domain_gate_mutex);
      service_mutation_scope_leave (store);
    }
    return rc;
  }

  gchar audit_id[WYL_ID_STRING_BUF];
  rc = service_domain_new_audit_id (audit_id);
  wyl_service_credential_material_t material = { 0 };
  wyl_service_credential_secret_t *secret = NULL;
  if (!authority_owned)
    g_mutex_lock (&store->service_lifecycle_mutex);
  now_us = g_get_real_time ();
  if (rc == WYRELOG_E_OK && expires_at_us != 0 && expires_at_us <= now_us)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && !authority_owned)
    rc = wyl_policy_store_begin_mutation (store);
  if (rc == WYRELOG_E_OK)
    rc = service_domain_claim_request (store, request_id, "credential_issue",
        subject_id, fingerprint, now_us);
  sodium_memzero (fingerprint, sizeof fingerprint);

  wyl_policy_service_principal_info_t principal = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_lookup_service_principal (store, subject_id,
        &principal);
  if (rc == WYRELOG_E_OK && !g_str_equal (principal.state, "active"))
    rc = WYRELOG_E_POLICY;
  gboolean tenant_active = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_tenant_is_active (store, tenant_id, &tenant_active);
  if (rc == WYRELOG_E_OK && !tenant_active)
    rc = WYRELOG_E_POLICY;
  wyl_policy_service_principal_info_clear (&principal);

  for (guint attempt = 0;
      rc == WYRELOG_E_OK && attempt < WYL_SERVICE_CREDENTIAL_ID_ATTEMPTS;
      attempt++) {
    rc = wyl_service_credential_generate_with_runtime (cvk, cvk_len,
        tenant_id, strlen (tenant_id), subject_id, strlen (subject_id),
        runtime, &material, &secret);
    gboolean collision = FALSE;
    if (rc == WYRELOG_E_OK)
      rc = service_credential_id_exists (store, material.credential_id,
          &collision);
    if (rc != WYRELOG_E_OK || !collision)
      break;
    wyl_service_credential_secret_clear (&secret);
    wyl_service_credential_material_clear (&material);
    if (attempt + 1 == WYL_SERVICE_CREDENTIAL_ID_ATTEMPTS)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    rc = service_credential_insert (store, &material, subject_id, tenant_id,
        actor_subject_id, now_us, expires_at_us);
  if (rc == WYRELOG_E_OK)
    rc = service_credential_append_issued_event (store,
        material.credential_id, subject_id, tenant_id, actor_subject_id,
        request_id, now_us);
  if (rc == WYRELOG_E_OK)
    rc = service_domain_append_audit (store, audit_id, now_us,
        actor_subject_id, "service.credential.issue", material.credential_id,
        request_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_lookup_service_credential (store,
        material.credential_id, subject_id, tenant_id, out);
  if (rc == WYRELOG_E_OK)
    rc = authority_owned ? service_domain_validate_mutation (store) :
        service_domain_finish_mutation (store);
  else if (!authority_owned)
    wyl_policy_store_rollback_mutation (store);
  if (!authority_owned)
    g_mutex_unlock (&store->service_lifecycle_mutex);

  wyl_service_credential_material_clear (&material);
  if (rc == WYRELOG_E_OK) {
    *out_secret = secret;
    secret = NULL;
  } else {
    wyl_policy_service_credential_info_clear (out);
  }
  wyl_service_credential_secret_clear (&secret);
  if (!authority_owned) {
    g_mutex_unlock (&store->service_domain_gate_mutex);
    service_mutation_scope_leave (store);
  }
  return rc;
}

wyrelog_error_t
    wyl_policy_store_issue_service_credential_with_runtime
    (wyl_policy_store_t * store, const gchar * subject_id,
    const gchar * tenant_id, const gchar * actor_subject_id,
    const gchar * request_id, gint64 expires_at_us,
    const wyl_service_credential_runtime_t * runtime,
    wyl_policy_service_credential_info_t * out,
    wyl_service_credential_secret_t ** out_secret)
{
  return service_credential_issue_impl (store, subject_id, tenant_id,
      actor_subject_id, request_id, expires_at_us, runtime, NULL, 0, out,
      out_secret, FALSE);
}

wyrelog_error_t
    wyl_policy_store_issue_service_credential_core
    (WylServiceAuthorityTransaction * txn, wyl_policy_store_t * store,
    const gchar * subject_id, const gchar * tenant_id,
    const gchar * actor_subject_id, const gchar * request_id,
    gint64 expires_at_us, const wyl_service_credential_runtime_t * runtime,
    const guint8 * cvk, gsize cvk_len,
    wyl_policy_service_credential_info_t * out,
    wyl_service_credential_secret_t ** out_secret)
{
  if (out != NULL)
    wyl_policy_service_credential_info_clear (out);
  if (out_secret != NULL)
    wyl_service_credential_secret_clear (out_secret);
  wyrelog_error_t rc =
      wyl_policy_store_service_authority_transaction_enter_participant (txn,
      store);
  return rc == WYRELOG_E_OK ? service_credential_issue_impl (store,
      subject_id, tenant_id, actor_subject_id, request_id, expires_at_us,
      runtime, cvk, cvk_len, out, out_secret, TRUE) : rc;
}

static wyrelog_error_t
service_credential_handoff_store (wyl_policy_store_t *store,
    const gchar *operation, const gchar *request_id,
    const gchar *actor_subject_id,
    const wyl_policy_service_handoff_request_t *handoff,
    const wyl_policy_service_credential_info_t *credential,
    const wyl_service_credential_secret_t *secret,
    wyl_policy_service_handoff_escrow_info_t *out_escrow)
{
  if (store == NULL || operation == NULL || request_id == NULL
      || actor_subject_id == NULL || handoff == NULL
      || handoff->escrow_id == NULL || handoff->target_digest == NULL
      || handoff->deadline_at_us <= 0 || credential == NULL
      || credential->credential_id == NULL || credential->generation == 0
      || secret == NULL || out_escrow == NULL)
    return WYRELOG_E_INVALID;
  gchar escrow_id[WYL_ID_STRING_BUF];
  if (wyl_id_format (handoff->escrow_id, escrow_id, sizeof escrow_id)
      != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  gsize secret_len = 0;
  const guint8 *raw = wyl_service_credential_secret_peek_raw (secret,
      &secret_len);
  if (raw == NULL || secret_len != WYL_SERVICE_CREDENTIAL_SECRET_BYTES)
    return WYRELOG_E_POLICY;
  guint8 binding[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES] = { 0 };
  wyl_policy_service_handoff_escrow_input_t input = {
    .escrow_id = handoff->escrow_id,.operation = operation,
    .request_id = request_id,.actor_subject_id = actor_subject_id,
    .target_digest = handoff->target_digest,
    .credential_id = credential->credential_id,
    .credential_generation = credential->generation,
    .deadline_at_us = handoff->deadline_at_us,.binding_digest = binding,
    .secret = raw,.secret_len = secret_len,
  };
  wyl_policy_service_handoff_escrow_info_t prepared = {
    .escrow_id = *handoff->escrow_id,
    .operation = g_strdup (operation),.request_id = g_strdup (request_id),
    .actor_subject_id = g_strdup (actor_subject_id),
    .credential_id = g_strdup (credential->credential_id),
    .credential_generation = credential->generation,
    .deadline_at_us = handoff->deadline_at_us,
  };
  memcpy (prepared.target_digest, handoff->target_digest,
      sizeof prepared.target_digest);
  wyrelog_error_t rc = service_handoff_binding_digest (&input, binding);
  if (rc == WYRELOG_E_OK && (prepared.operation == NULL
          || prepared.request_id == NULL || prepared.actor_subject_id == NULL
          || prepared.credential_id == NULL))
    rc = WYRELOG_E_NOMEM;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_service_handoff_escrow_insert (store, &input);
  memcpy (prepared.binding_digest, binding, sizeof prepared.binding_digest);
  sodium_memzero (binding, sizeof binding);
  if (rc == WYRELOG_E_OK) {
    wyl_policy_service_handoff_escrow_info_clear (out_escrow);
    *out_escrow = prepared;
    memset (&prepared, 0, sizeof prepared);
  }
  wyl_policy_service_handoff_escrow_info_clear (&prepared);
  return rc;
}

static gboolean
    service_credential_handoff_request_valid
    (const wyl_policy_service_handoff_request_t * handoff)
{
  if (handoff == NULL || handoff->escrow_id == NULL
      || handoff->target_digest == NULL || handoff->deadline_at_us <= 0)
    return FALSE;
  gchar escrow_id[WYL_ID_STRING_BUF];
  return wyl_id_format (handoff->escrow_id, escrow_id, sizeof escrow_id)
      == WYRELOG_E_OK;
}

static wyrelog_error_t
service_credential_handoff_replay (wyl_policy_store_t *store,
    const gchar *operation, const gchar *request_id,
    const gchar *actor_subject_id,
    const wyl_policy_service_handoff_request_t *handoff,
    const gchar *domain_operation, const gchar *resource_id,
    const guint8 request_fingerprint[crypto_generichash_BYTES],
    wyl_policy_service_credential_info_t *out,
    wyl_policy_service_handoff_escrow_info_t *out_escrow)
{
  wyl_policy_service_handoff_escrow_info_t found = { 0 };
  wyrelog_error_t rc = wyl_policy_store_service_handoff_escrow_load_by_request
      (store, request_id, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!g_str_equal (found.operation, operation)
      || !g_str_equal (found.actor_subject_id, actor_subject_id)
      || !wyl_id_equal (&found.escrow_id, handoff->escrow_id)
      || found.deadline_at_us != handoff->deadline_at_us
      || sodium_memcmp (found.target_digest, handoff->target_digest,
          sizeof found.target_digest) != 0) {
    wyl_policy_service_handoff_escrow_info_clear (&found);
    return WYRELOG_E_POLICY;
  }
  sqlite3_stmt *stmt = NULL;
  rc = prepare_stmt (store->db,
      "SELECT operation,resource_id,input_fingerprint FROM "
      "service_domain_requests WHERE request_id=?;", &stmt);
  if (rc == WYRELOG_E_OK
      && sqlite3_bind_text (stmt, 1, request_id, -1, SQLITE_TRANSIENT)
      != SQLITE_OK)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK) {
    int step = sqlite3_step (stmt);
    if (step != SQLITE_ROW || sqlite3_column_type (stmt, 0) != SQLITE_TEXT
        || sqlite3_column_type (stmt, 1) != SQLITE_TEXT)
      rc = step == SQLITE_ROW ? WYRELOG_E_POLICY : WYRELOG_E_NOT_FOUND;
    else {
      const gchar *stored_operation = (const gchar *) sqlite3_column_text
          (stmt, 0);
      const gchar *stored_resource = (const gchar *) sqlite3_column_text
          (stmt, 1);
      guint8 stored_fingerprint[crypto_generichash_BYTES] = { 0 };
      rc = read_fixed_blob (stmt, 2, stored_fingerprint,
          sizeof stored_fingerprint);
      if (rc == WYRELOG_E_OK && (stored_operation == NULL
              || stored_resource == NULL
              || !g_str_equal (stored_operation, domain_operation)
              || !g_str_equal (stored_resource, resource_id)
              || sodium_memcmp (stored_fingerprint, request_fingerprint,
                  sizeof stored_fingerprint) != 0))
        rc = WYRELOG_E_POLICY;
      sodium_memzero (stored_fingerprint, sizeof stored_fingerprint);
    }
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  if (rc != WYRELOG_E_OK) {
    wyl_policy_service_handoff_escrow_info_clear (&found);
    return rc;
  }
  wyl_policy_service_handoff_escrow_input_t input = {
    .escrow_id = &found.escrow_id,.operation = found.operation,
    .request_id = found.request_id,.actor_subject_id = found.actor_subject_id,
    .target_digest = found.target_digest,.credential_id = found.credential_id,
    .credential_generation = found.credential_generation,
    .deadline_at_us = found.deadline_at_us,
  };
  guint8 binding[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES] = { 0 };
  rc = service_handoff_binding_digest (&input, binding);
  if (rc == WYRELOG_E_OK && sodium_memcmp (binding, found.binding_digest,
          sizeof binding) != 0)
    rc = WYRELOG_E_POLICY;
  sodium_memzero (binding, sizeof binding);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_lookup_service_credential_by_id (store,
        found.credential_id, out);
  if (rc == WYRELOG_E_OK) {
    *out_escrow = found;
    memset (&found, 0, sizeof found);
  }
  wyl_policy_service_handoff_escrow_info_clear (&found);
  return rc;
}

wyrelog_error_t
    wyl_policy_store_issue_service_credential_handoff_core
    (WylServiceAuthorityTransaction * txn, wyl_policy_store_t * store,
    const gchar * subject_id, const gchar * tenant_id,
    const gchar * actor_subject_id, const gchar * request_id,
    gint64 expires_at_us, const wyl_service_credential_runtime_t * runtime,
    const guint8 * cvk, gsize cvk_len,
    const wyl_policy_service_handoff_request_t * handoff,
    wyl_policy_service_credential_info_t * out,
    wyl_policy_service_handoff_escrow_info_t * out_escrow)
{
  if (out != NULL)
    wyl_policy_service_credential_info_clear (out);
  if (out_escrow != NULL)
    wyl_policy_service_handoff_escrow_info_clear (out_escrow);
  if (out == NULL || out_escrow == NULL
      || !service_credential_handoff_request_valid (handoff))
    return WYRELOG_E_INVALID;
  if (subject_id == NULL
      || !wyl_policy_service_subject_is_valid (subject_id, strlen (subject_id))
      || !wyl_policy_store_tenant_id_is_valid (tenant_id)
      || !wyl_policy_service_actor_subject_is_valid (actor_subject_id)
      || !service_domain_text_is_valid (request_id, 256) || expires_at_us < 0)
    return WYRELOG_E_INVALID;
  guint8 fingerprint[crypto_generichash_BYTES] = { 0 };
  wyrelog_error_t rc = service_credential_issue_fingerprint (subject_id,
      tenant_id, actor_subject_id, expires_at_us, fingerprint);
  if (rc != WYRELOG_E_OK) {
    sodium_memzero (fingerprint, sizeof fingerprint);
    return rc;
  }
  rc = wyl_policy_store_service_authority_transaction_enter_participant (txn,
      store);
  if (rc != WYRELOG_E_OK) {
    sodium_memzero (fingerprint, sizeof fingerprint);
    return rc;
  }
  rc = service_credential_handoff_replay (store, "issue", request_id,
      actor_subject_id, handoff, "credential_issue", subject_id, fingerprint,
      out, out_escrow);
  sodium_memzero (fingerprint, sizeof fingerprint);
  if (rc == WYRELOG_E_OK)
    return rc;
  if (rc != WYRELOG_E_NOT_FOUND)
    return rc;
  wyl_service_credential_secret_t *secret = NULL;
  rc = wyl_policy_store_issue_service_credential_core (txn,
      store, subject_id, tenant_id, actor_subject_id, request_id,
      expires_at_us, runtime, cvk, cvk_len, out, &secret);
  if (rc == WYRELOG_E_OK)
    rc = service_credential_handoff_store (store, "issue", request_id,
        actor_subject_id, handoff, out, secret, out_escrow);
  wyl_service_credential_secret_clear (&secret);
  if (rc != WYRELOG_E_OK) {
    wyl_policy_service_credential_info_clear (out);
    wyl_policy_service_handoff_escrow_info_clear (out_escrow);
  }
  return rc;
}

wyrelog_error_t
wyl_policy_store_issue_service_credential (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *tenant_id,
    const gchar *actor_subject_id, const gchar *request_id,
    gint64 expires_at_us, wyl_policy_service_credential_info_t *out,
    wyl_service_credential_secret_t **out_secret)
{
  return wyl_policy_store_issue_service_credential_with_runtime (store,
      subject_id, tenant_id, actor_subject_id, request_id, expires_at_us, NULL,
      out, out_secret);
}

static gint64
service_credential_default_now (gpointer data)
{
  (void) data;
  return g_get_real_time ();
}

static gboolean
service_credential_secret_text_is_canonical (const gchar *text, gsize text_len)
{
  guint8 raw[WYL_SERVICE_CREDENTIAL_SECRET_BYTES];
  gchar encoded[WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN + 1];
  size_t decoded_len = 0;
  const gchar *end = NULL;
  gboolean canonical = sodium_base642bin (raw, sizeof raw, text, text_len,
      NULL, &decoded_len, &end,
      sodium_base64_VARIANT_URLSAFE_NO_PADDING) == 0
      && decoded_len == sizeof raw && end == text + text_len
      && sodium_bin2base64 (encoded, sizeof encoded, raw, sizeof raw,
      sodium_base64_VARIANT_URLSAFE_NO_PADDING) != NULL
      && memcmp (encoded, text, text_len) == 0;
  sodium_memzero (raw, sizeof raw);
  sodium_memzero (encoded, sizeof encoded);
  return canonical;
}

wyrelog_error_t
wyl_policy_store_verify_service_credential_by_id (wyl_policy_store_t *store,
    const gchar *credential_id, const gchar *presented_secret,
    gsize presented_secret_len, void (*before_gate) (gpointer data),
    gint64 (*now_us) (gpointer data), gpointer now_data,
    const wyl_service_credential_runtime_t *runtime,
    gboolean *out_authenticated)
{
  if (out_authenticated != NULL)
    *out_authenticated = FALSE;
  if (store == NULL || store->db == NULL || out_authenticated == NULL
      || credential_id == NULL
      || !wyl_service_credential_id_is_canonical (credential_id,
          strlen (credential_id)) || presented_secret == NULL
      || presented_secret_len != WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN
      || memchr (presented_secret, 0, presented_secret_len) != NULL)
    return WYRELOG_E_INVALID;
  if (now_us == NULL)
    now_us = service_credential_default_now;

  if (before_gate != NULL)
    before_gate (now_data);
  g_mutex_lock (&store->service_domain_gate_mutex);
  gint64 now = now_us (now_data);
  if (now <= 0) {
    g_mutex_unlock (&store->service_domain_gate_mutex);
    return WYRELOG_E_IO;
  }
  wyl_policy_service_credential_info_t credential = { 0 };
  wyrelog_error_t rc = wyl_policy_store_lookup_service_credential_by_id
      (store, credential_id, &credential);
  /* Keep fixed-size content parsing behind the authoritative ID lookup for
   * both known and unknown IDs. Its result is consumed only if the stored
   * authority is otherwise eligible. */
  gboolean presented_canonical =
      service_credential_secret_text_is_canonical (presented_secret,
      presented_secret_len);
  if (rc == WYRELOG_E_NOT_FOUND)
    rc = WYRELOG_E_AUTH;
  wyl_policy_service_principal_info_t principal = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_lookup_service_principal (store,
        credential.subject_id, &principal);
  if (rc == WYRELOG_E_NOT_FOUND)
    rc = WYRELOG_E_AUTH;
  wyl_policy_principal_kind_t principal_kind =
      WYL_POLICY_PRINCIPAL_KIND_UNKNOWN;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_get_principal_kind (store, credential.subject_id,
        &principal_kind);
  if (rc == WYRELOG_E_OK && principal_kind != WYL_POLICY_PRINCIPAL_KIND_SERVICE)
    rc = WYRELOG_E_POLICY;
  gboolean tenant_active = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_tenant_is_active (store, credential.tenant_id,
        &tenant_active);
  if (rc == WYRELOG_E_OK && (!g_str_equal (credential.state, "active")
          || (credential.expires_at_us != 0 && credential.expires_at_us <= now)
          || !g_str_equal (principal.state, "active") || !tenant_active))
    rc = WYRELOG_E_AUTH;

  const guint8 *cvk = NULL;
  gsize cvk_len = 0;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_validate_service_schema (store);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_materialize_service_cvk_existing (store, &cvk,
        &cvk_len);
  gboolean match = FALSE;
  if (rc == WYRELOG_E_OK && !presented_canonical)
    rc = WYRELOG_E_AUTH;
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_credential_verify_with_runtime
        (credential.credential_format_version, credential.verifier_version,
        cvk, cvk_len, credential.credential_id,
        strlen (credential.credential_id), credential.tenant_id,
        strlen (credential.tenant_id), credential.subject_id,
        strlen (credential.subject_id), credential.salt,
        sizeof credential.salt, credential.verifier,
        sizeof credential.verifier, presented_secret, presented_secret_len,
        runtime, &match);
  if (rc == WYRELOG_E_OK && !match)
    rc = WYRELOG_E_AUTH;
  if (rc == WYRELOG_E_OK)
    *out_authenticated = TRUE;
  wyl_policy_service_principal_info_clear (&principal);
  wyl_policy_service_credential_info_clear (&credential);
  g_mutex_unlock (&store->service_domain_gate_mutex);
  return rc;
}

static wyrelog_error_t
service_credential_revoke_fingerprint (const gchar *credential_id,
    const gchar *actor_subject_id, guint8 out[crypto_generichash_BYTES])
{
  crypto_generichash_state state;
  static const guint8 domain[] = "wyrelog.service-credential-revoke-request.v1";
  if (crypto_generichash_init (&state, NULL, 0, crypto_generichash_BYTES) != 0
      || crypto_generichash_update (&state, domain, sizeof domain - 1) != 0)
    return WYRELOG_E_CRYPTO;
  const gchar *fields[] = { credential_id, actor_subject_id };
  static const guint8 separator = 0;
  for (gsize i = 0; i < G_N_ELEMENTS (fields); i++) {
    if (crypto_generichash_update (&state, (const guint8 *) fields[i],
            strlen (fields[i])) != 0
        || crypto_generichash_update (&state, &separator, 1) != 0) {
      sodium_memzero (&state, sizeof state);
      return WYRELOG_E_CRYPTO;
    }
  }
  int failed = crypto_generichash_final (&state, out,
      crypto_generichash_BYTES);
  sodium_memzero (&state, sizeof state);
  return failed == 0 ? WYRELOG_E_OK : WYRELOG_E_CRYPTO;
}

static wyrelog_error_t
service_credential_append_revoked_event (wyl_policy_store_t *store,
    const wyl_policy_service_credential_info_t *credential,
    guint64 generation, const gchar *actor_subject_id,
    const gchar *request_id, gint64 now_us)
{
  static const gchar *sql =
      "INSERT INTO service_credential_events(credential_id,subject_id,"
      "tenant_id,event,from_state,to_state,generation,actor_subject_id,"
      "request_id,related_credential_id,created_at_us) "
      "VALUES(?,?,?,'revoked','active','revoked',?,?,?,NULL,?);";
  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, credential->credential_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, credential->subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, credential->tenant_id)) != WYRELOG_E_OK
      || sqlite3_bind_int64 (stmt, 4, (sqlite3_int64) generation) != SQLITE_OK
      || (rc = bind_text (stmt, 5, actor_subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 6, request_id)) != WYRELOG_E_OK
      || sqlite3_bind_int64 (stmt, 7, now_us) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return step_rc == SQLITE_DONE ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
service_credential_revoke_impl (wyl_policy_store_t *store,
    const gchar *credential_id, const gchar *actor_subject_id,
    const gchar *request_id, wyl_policy_service_credential_info_t *out,
    gboolean authority_owned)
{
  if (out != NULL)
    wyl_policy_service_credential_info_clear (out);
  if (store == NULL || store->db == NULL || out == NULL
      || credential_id == NULL
      || !wyl_service_credential_id_is_canonical (credential_id,
          strlen (credential_id))
      || !wyl_policy_service_actor_subject_is_valid (actor_subject_id)
      || !service_domain_text_is_valid (request_id, 256))
    return WYRELOG_E_INVALID;

  guint8 fingerprint[crypto_generichash_BYTES];
  wyrelog_error_t rc = service_credential_revoke_fingerprint (credential_id,
      actor_subject_id, fingerprint);
  gchar audit_id[WYL_ID_STRING_BUF];
  if (rc == WYRELOG_E_OK)
    rc = service_domain_new_audit_id (audit_id);
  if (rc != WYRELOG_E_OK) {
    sodium_memzero (fingerprint, sizeof fingerprint);
    return rc;
  }

  gint64 now_us = g_get_real_time ();
  if (!authority_owned) {
    rc = service_mutation_scope_enter (store);
    if (rc != WYRELOG_E_OK) {
      sodium_memzero (fingerprint, sizeof fingerprint);
      return rc;
    }
    g_mutex_lock (&store->service_domain_gate_mutex);
    g_mutex_lock (&store->service_lifecycle_mutex);
  }
  rc = authority_owned ? WYRELOG_E_OK : wyl_policy_store_begin_mutation (store);
  if (rc == WYRELOG_E_OK)
    rc = service_domain_claim_request (store, request_id, "credential_revoke",
        credential_id, fingerprint, now_us);
  sodium_memzero (fingerprint, sizeof fingerprint);
  wyl_policy_service_credential_info_t current = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_lookup_service_credential_by_id (store,
        credential_id, &current);
  if (rc == WYRELOG_E_OK && g_str_equal (current.state, "active")) {
    if (current.generation >= G_MAXINT64) {
      rc = WYRELOG_E_POLICY;
    } else {
      sqlite3_stmt *stmt = NULL;
      rc = prepare_stmt (store->db,
          "UPDATE service_credentials SET state='revoked',generation=?,"
          "updated_at_us=?,revoked_by=?,revoked_at_us=? "
          "WHERE credential_id=? AND state='active';", &stmt);
      if (rc == WYRELOG_E_OK
          && (sqlite3_bind_int64 (stmt, 1,
                  (sqlite3_int64) current.generation + 1) != SQLITE_OK
              || sqlite3_bind_int64 (stmt, 2, now_us) != SQLITE_OK
              || (rc = bind_text (stmt, 3, actor_subject_id)) != WYRELOG_E_OK
              || sqlite3_bind_int64 (stmt, 4, now_us) != SQLITE_OK
              || (rc = bind_text (stmt, 5, credential_id)) != WYRELOG_E_OK))
        rc = WYRELOG_E_IO;
      if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
        rc = WYRELOG_E_IO;
      if (rc == WYRELOG_E_OK && sqlite3_changes (store->db) != 1)
        rc = WYRELOG_E_POLICY;
      sqlite3_finalize (stmt);
      if (rc == WYRELOG_E_OK)
        rc = service_credential_append_revoked_event (store, &current,
            current.generation + 1, actor_subject_id, request_id, now_us);
    }
  } else if (rc == WYRELOG_E_OK && !g_str_equal (current.state, "revoked")) {
    rc = WYRELOG_E_POLICY;
  }
  wyl_policy_service_credential_info_clear (&current);
  if (rc == WYRELOG_E_OK)
    rc = service_domain_append_audit (store, audit_id, now_us,
        actor_subject_id, "service.credential.revoke", credential_id,
        request_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_lookup_service_credential_by_id (store,
        credential_id, out);
  if (rc == WYRELOG_E_OK)
    rc = authority_owned ? service_domain_validate_mutation (store) :
        service_domain_finish_mutation (store);
  else if (!authority_owned)
    wyl_policy_store_rollback_mutation (store);
  if (!authority_owned) {
    g_mutex_unlock (&store->service_lifecycle_mutex);
    g_mutex_unlock (&store->service_domain_gate_mutex);
    service_mutation_scope_leave (store);
  }
  if (rc != WYRELOG_E_OK)
    wyl_policy_service_credential_info_clear (out);
  return rc;
}

wyrelog_error_t
wyl_policy_store_revoke_service_credential (wyl_policy_store_t *store,
    const gchar *credential_id, const gchar *actor_subject_id,
    const gchar *request_id, wyl_policy_service_credential_info_t *out)
{
  return service_credential_revoke_impl (store, credential_id,
      actor_subject_id, request_id, out, FALSE);
}

wyrelog_error_t
    wyl_policy_store_revoke_service_credential_core
    (WylServiceAuthorityTransaction * txn, wyl_policy_store_t * store,
    const gchar * credential_id, const gchar * actor_subject_id,
    const gchar * request_id, wyl_policy_service_credential_info_t * out)
{
  if (out != NULL)
    wyl_policy_service_credential_info_clear (out);
  wyrelog_error_t rc =
      wyl_policy_store_service_authority_transaction_enter_participant (txn,
      store);
  return rc == WYRELOG_E_OK ? service_credential_revoke_impl (store,
      credential_id, actor_subject_id, request_id, out, TRUE) : rc;
}

static wyrelog_error_t
service_credential_rotate_fingerprint (const gchar *old_credential_id,
    const gchar *actor_subject_id, gint64 expires_at_us,
    guint8 out[crypto_generichash_BYTES])
{
  g_autofree gchar *expiry = g_strdup_printf ("%" G_GINT64_FORMAT,
      expires_at_us);
  crypto_generichash_state state;
  static const guint8 domain[] = "wyrelog.service-credential-rotate-request.v1";
  if (crypto_generichash_init (&state, NULL, 0, crypto_generichash_BYTES) != 0
      || crypto_generichash_update (&state, domain, sizeof domain - 1) != 0)
    return WYRELOG_E_CRYPTO;
  const gchar *fields[] = { old_credential_id, actor_subject_id, expiry };
  static const guint8 separator = 0;
  for (gsize i = 0; i < G_N_ELEMENTS (fields); i++)
    if (crypto_generichash_update (&state, (const guint8 *) fields[i],
            strlen (fields[i])) != 0
        || crypto_generichash_update (&state, &separator, 1) != 0) {
      sodium_memzero (&state, sizeof state);
      return WYRELOG_E_CRYPTO;
    }
  int failed = crypto_generichash_final (&state, out,
      crypto_generichash_BYTES);
  sodium_memzero (&state, sizeof state);
  return failed == 0 ? WYRELOG_E_OK : WYRELOG_E_CRYPTO;
}

static wyrelog_error_t
service_credential_insert_successor (wyl_policy_store_t *store,
    const wyl_service_credential_material_t *material,
    const wyl_policy_service_credential_info_t *old,
    const gchar *actor_subject_id, gint64 now_us, gint64 expires_at_us)
{
  static const gchar *sql =
      "INSERT INTO service_credentials(credential_id,"
      "credential_format_version,subject_id,tenant_id,generation,state,"
      "verifier_version,salt,verifier,created_by,created_at_us,updated_at_us,"
      "expires_at_us,rotated_from_id) "
      "VALUES(?,?,?,?,1,'active',?,?,?,?,?,?,?,?);";
  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK
      && ((rc = bind_text (stmt, 1, material->credential_id)) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 2,
              material->credential_format_version) != SQLITE_OK
          || (rc = bind_text (stmt, 3, old->subject_id)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 4, old->tenant_id)) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 5, material->verifier_version)
          != SQLITE_OK
          || sqlite3_bind_blob (stmt, 6, material->salt,
              sizeof material->salt, SQLITE_TRANSIENT) != SQLITE_OK
          || sqlite3_bind_blob (stmt, 7, material->verifier,
              sizeof material->verifier, SQLITE_TRANSIENT) != SQLITE_OK
          || (rc = bind_text (stmt, 8, actor_subject_id)) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 9, now_us) != SQLITE_OK
          || sqlite3_bind_int64 (stmt, 10, now_us) != SQLITE_OK
          || (expires_at_us == 0 ? sqlite3_bind_null (stmt, 11) :
              sqlite3_bind_int64 (stmt, 11, expires_at_us)) != SQLITE_OK
          || (rc = bind_text (stmt, 12, old->credential_id))
          != WYRELOG_E_OK))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
    rc = sqlite3_extended_errcode (store->db) == SQLITE_CONSTRAINT_UNIQUE ?
        WYRELOG_E_POLICY : WYRELOG_E_IO;
  sqlite3_finalize (stmt);
  return rc;
}

static wyrelog_error_t
service_credential_append_rotation_event (wyl_policy_store_t *store,
    const gchar *credential_id, const gchar *subject_id,
    const gchar *tenant_id, const gchar *event, const gchar *from_state,
    const gchar *to_state, guint64 generation, const gchar *actor_subject_id,
    const gchar *request_id, const gchar *related_credential_id, gint64 now_us)
{
  static const gchar *sql =
      "INSERT INTO service_credential_events(credential_id,subject_id,"
      "tenant_id,event,from_state,to_state,generation,actor_subject_id,"
      "request_id,related_credential_id,created_at_us) "
      "VALUES(?,?,?,?,?,?,?,?,?,?,?);";
  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc == WYRELOG_E_OK
      && ((rc = bind_text (stmt, 1, credential_id)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 2, subject_id)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 3, tenant_id)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 4, event)) != WYRELOG_E_OK
          || (from_state == NULL ? sqlite3_bind_null (stmt, 5) :
              sqlite3_bind_text (stmt, 5, from_state, -1,
                  SQLITE_TRANSIENT)) != SQLITE_OK
          || (rc = bind_text (stmt, 6, to_state)) != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 7, (sqlite3_int64) generation)
          != SQLITE_OK
          || (rc = bind_text (stmt, 8, actor_subject_id)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 9, request_id)) != WYRELOG_E_OK
          || (rc = bind_text (stmt, 10, related_credential_id))
          != WYRELOG_E_OK
          || sqlite3_bind_int64 (stmt, 11, now_us) != SQLITE_OK))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
    rc = WYRELOG_E_IO;
  sqlite3_finalize (stmt);
  return rc;
}

static gboolean
service_credential_rotate_should_fail (wyl_policy_store_t *store,
    wyl_policy_service_rotate_fail_stage_t stage)
{
  if (store->service_rotate_fail_once != stage)
    return FALSE;
  store->service_rotate_fail_once = WYL_POLICY_SERVICE_ROTATE_FAIL_NONE;
  return TRUE;
}

static wyrelog_error_t
service_credential_append_rotation_audit (wyl_policy_store_t *store,
    const gchar *audit_id, gint64 now_us, const gchar *actor_subject_id,
    const gchar *old_credential_id, const gchar *request_id)
{
  if (service_credential_rotate_should_fail (store,
          WYL_POLICY_SERVICE_ROTATE_FAIL_AUDIT))
    return WYRELOG_E_IO;
  gboolean inserted = FALSE;
  wyrelog_error_t rc = wyl_policy_store_append_audit_event_full (store,
      audit_id, now_us, actor_subject_id, "service.credential.rotate",
      old_credential_id, NULL, NULL, request_id, WYL_DECISION_ALLOW,
      &inserted);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (service_credential_rotate_should_fail (store,
          WYL_POLICY_SERVICE_ROTATE_FAIL_INTENTION))
    return WYRELOG_E_IO;
  inserted = FALSE;
  return wyl_policy_store_record_audit_intention_full (store, audit_id,
      now_us, actor_subject_id, "service.credential.rotate",
      old_credential_id, NULL, NULL, request_id, WYL_DECISION_ALLOW, &inserted);
}

static wyrelog_error_t
service_credential_rotate_impl (wyl_policy_store_t *store,
    const gchar *old_credential_id, const gchar *actor_subject_id,
    const gchar *request_id, gint64 new_expires_at_us,
    gint64 (*now_us_cb) (gpointer data), gpointer now_data,
    const wyl_service_credential_runtime_t *runtime,
    guint64 expected_generation,
    const guint8 *authority_cvk, gsize authority_cvk_len,
    wyl_policy_service_credential_info_t *out,
    wyl_service_credential_secret_t **out_secret, gboolean authority_owned)
{
  if (out != NULL)
    wyl_policy_service_credential_info_clear (out);
  if (out_secret != NULL)
    wyl_service_credential_secret_clear (out_secret);
  if (store == NULL || store->db == NULL || out == NULL || out_secret == NULL
      || old_credential_id == NULL
      || !wyl_service_credential_id_is_canonical (old_credential_id,
          strlen (old_credential_id))
      || !wyl_policy_service_actor_subject_is_valid (actor_subject_id)
      || !service_domain_text_is_valid (request_id, 256)
      || new_expires_at_us < 0 || expected_generation > G_MAXINT64)
    return WYRELOG_E_INVALID;
  if (now_us_cb == NULL)
    now_us_cb = service_credential_default_now;
  if (authority_owned
      && (authority_cvk == NULL
          || authority_cvk_len != WYL_SERVICE_CREDENTIAL_CVK_BYTES))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = WYRELOG_E_OK;
  if (!authority_owned) {
    WylServiceCredentialFenceResult fence = { 0 };
    rc = wyl_policy_store_precheck_service_credential_operation_fence (store,
        NULL, WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE, request_id, NULL, NULL,
        old_credential_id, &fence);
    if (rc == WYRELOG_E_OK)
      rc = WYRELOG_E_POLICY;
    else if (rc == WYRELOG_E_NOT_FOUND)
      rc = WYRELOG_E_OK;
  }
  if (rc != WYRELOG_E_OK)
    return rc;

  guint8 fingerprint[crypto_generichash_BYTES];
  rc = service_credential_rotate_fingerprint
      (old_credential_id, actor_subject_id, new_expires_at_us, fingerprint);
  if (rc != WYRELOG_E_OK) {
    sodium_memzero (fingerprint, sizeof fingerprint);
    return rc;
  }

  if (!authority_owned) {
    rc = service_mutation_scope_enter (store);
    if (rc != WYRELOG_E_OK) {
      sodium_memzero (fingerprint, sizeof fingerprint);
      return rc;
    }
    g_mutex_lock (&store->service_domain_gate_mutex);
  }
  gint64 now_us = now_us_cb (now_data);
  if (now_us <= 0) {
    rc = WYRELOG_E_IO;
    goto unlock_gate;
  }
  if (new_expires_at_us != 0 && new_expires_at_us <= now_us) {
    rc = WYRELOG_E_POLICY;
    goto unlock_gate;
  }
  const guint8 *cvk = authority_cvk;
  gsize cvk_len = authority_cvk_len;
  if (!authority_owned)
    rc = wyl_policy_store_materialize_service_cvk_existing (store, &cvk,
        &cvk_len);
  if (rc == WYRELOG_E_NOT_FOUND)
    rc = WYRELOG_E_POLICY;
  if (rc != WYRELOG_E_OK)
    goto unlock_gate;

  wyl_service_credential_material_t material = { 0 };
  wyl_service_credential_secret_t *secret = NULL;
  wyl_policy_service_credential_info_t old = { 0 };
  wyl_policy_service_principal_info_t principal = { 0 };
  gchar audit_id[WYL_ID_STRING_BUF] = { 0 };
  if (!authority_owned)
    g_mutex_lock (&store->service_lifecycle_mutex);
  rc = authority_owned ? WYRELOG_E_OK : wyl_policy_store_begin_mutation (store);
  if (rc == WYRELOG_E_OK)
    rc = service_domain_claim_request (store, request_id, "credential_rotate",
        old_credential_id, fingerprint, now_us);
  sodium_memzero (fingerprint, sizeof fingerprint);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_lookup_service_credential_by_id (store,
        old_credential_id, &old);
  if (rc == WYRELOG_E_NOT_FOUND)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && (!g_str_equal (old.state, "active")
          || (old.expires_at_us != 0 && old.expires_at_us <= now_us)
          || old.generation >= G_MAXINT64))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && expected_generation != 0
      && old.generation != expected_generation)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_lookup_service_principal (store, old.subject_id,
        &principal);
  if (rc == WYRELOG_E_NOT_FOUND)
    rc = WYRELOG_E_POLICY;
  wyl_policy_principal_kind_t kind = WYL_POLICY_PRINCIPAL_KIND_UNKNOWN;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_get_principal_kind (store, old.subject_id, &kind);
  if (rc == WYRELOG_E_OK
      && (kind != WYL_POLICY_PRINCIPAL_KIND_SERVICE
          || !g_str_equal (principal.state, "active")))
    rc = WYRELOG_E_POLICY;
  gboolean tenant_active = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_tenant_is_active (store, old.tenant_id,
        &tenant_active);
  if (rc == WYRELOG_E_OK && !tenant_active)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && service_credential_rotate_should_fail (store,
          WYL_POLICY_SERVICE_ROTATE_FAIL_OLD_UPDATE))
    rc = WYRELOG_E_IO;

  /* The authoritative compare-and-swap must precede every durable rotate
   * effect. A stale expected generation rolls back this transaction. */
  if (rc == WYRELOG_E_OK) {
    sqlite3_stmt *stmt = NULL;
    guint64 compare_generation = expected_generation != 0 ?
        expected_generation : old.generation;
    rc = prepare_stmt (store->db,
        "UPDATE service_credentials SET state='revoked',generation=?,"
        "updated_at_us=?,revoked_by=?,revoked_at_us=? "
        "WHERE credential_id=? AND state='active' AND generation=?;", &stmt);
    if (rc == WYRELOG_E_OK
        && (sqlite3_bind_int64 (stmt, 1, (sqlite3_int64) old.generation + 1)
            != SQLITE_OK || sqlite3_bind_int64 (stmt, 2, now_us) != SQLITE_OK
            || (rc = bind_text (stmt, 3, actor_subject_id)) != WYRELOG_E_OK
            || sqlite3_bind_int64 (stmt, 4, now_us) != SQLITE_OK
            || (rc = bind_text (stmt, 5, old_credential_id)) != WYRELOG_E_OK
            || sqlite3_bind_int64 (stmt, 6, (sqlite3_int64) compare_generation)
            != SQLITE_OK))
      rc = WYRELOG_E_IO;
    if (rc == WYRELOG_E_OK && sqlite3_step (stmt) != SQLITE_DONE)
      rc = WYRELOG_E_IO;
    sqlite3_finalize (stmt);
    if (rc == WYRELOG_E_OK && sqlite3_changes (store->db) != 1)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    rc = service_domain_new_audit_id (audit_id);

  for (guint attempt = 0;
      rc == WYRELOG_E_OK && attempt < WYL_SERVICE_CREDENTIAL_ID_ATTEMPTS;
      attempt++) {
    rc = wyl_service_credential_generate_with_runtime (cvk, cvk_len,
        old.tenant_id, strlen (old.tenant_id), old.subject_id,
        strlen (old.subject_id), runtime, &material, &secret);
    gboolean collision = FALSE;
    if (rc == WYRELOG_E_OK)
      rc = service_credential_id_exists (store, material.credential_id,
          &collision);
    if (rc != WYRELOG_E_OK || !collision)
      break;
    wyl_service_credential_secret_clear (&secret);
    wyl_service_credential_material_clear (&material);
    if (attempt + 1 == WYL_SERVICE_CREDENTIAL_ID_ATTEMPTS)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK && service_credential_rotate_should_fail (store,
          WYL_POLICY_SERVICE_ROTATE_FAIL_INSERT))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = service_credential_insert_successor (store, &material, &old,
        actor_subject_id, now_us, new_expires_at_us);
  if (rc == WYRELOG_E_OK && service_credential_rotate_should_fail (store,
          WYL_POLICY_SERVICE_ROTATE_FAIL_SUCCESSOR_EVENT))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = service_credential_append_rotation_event (store,
        material.credential_id, old.subject_id, old.tenant_id, "rotated",
        NULL, "active", 1, actor_subject_id, request_id, old_credential_id,
        now_us);
  if (rc == WYRELOG_E_OK && service_credential_rotate_should_fail (store,
          WYL_POLICY_SERVICE_ROTATE_FAIL_OLD_EVENT))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = service_credential_append_rotation_event (store, old_credential_id,
        old.subject_id, old.tenant_id, "revoked", "active", "revoked",
        old.generation + 1, actor_subject_id, request_id,
        material.credential_id, now_us);
  if (rc == WYRELOG_E_OK)
    rc = service_credential_append_rotation_audit (store, audit_id, now_us,
        actor_subject_id, old_credential_id, request_id);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_lookup_service_credential_by_id (store,
        material.credential_id, out);
  if (rc == WYRELOG_E_OK && service_credential_rotate_should_fail (store,
          WYL_POLICY_SERVICE_ROTATE_FAIL_VALIDATOR))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = authority_owned ? service_domain_validate_mutation (store) :
        service_domain_finish_mutation (store);
  else if (!authority_owned)
    wyl_policy_store_rollback_mutation (store);
  if (!authority_owned)
    g_mutex_unlock (&store->service_lifecycle_mutex);
  wyl_policy_service_principal_info_clear (&principal);
  wyl_policy_service_credential_info_clear (&old);
  wyl_service_credential_material_clear (&material);
  if (rc == WYRELOG_E_OK) {
    *out_secret = secret;
    secret = NULL;
  } else {
    wyl_policy_service_credential_info_clear (out);
  }
  wyl_service_credential_secret_clear (&secret);

unlock_gate:
  sodium_memzero (fingerprint, sizeof fingerprint);
  if (!authority_owned) {
    g_mutex_unlock (&store->service_domain_gate_mutex);
    service_mutation_scope_leave (store);
  }
  return rc;
}

wyrelog_error_t
wyl_policy_store_rotate_service_credential (wyl_policy_store_t *store,
    const gchar *old_credential_id, const gchar *actor_subject_id,
    const gchar *request_id, gint64 new_expires_at_us,
    gint64 (*now_us_cb) (gpointer data), gpointer now_data,
    const wyl_service_credential_runtime_t *runtime,
    wyl_policy_service_credential_info_t *out,
    wyl_service_credential_secret_t **out_secret)
{
  return service_credential_rotate_impl (store, old_credential_id,
      actor_subject_id, request_id, new_expires_at_us, now_us_cb, now_data,
      runtime, 0, NULL, 0, out, out_secret, FALSE);
}

wyrelog_error_t
    wyl_policy_store_rotate_service_credential_core
    (WylServiceAuthorityTransaction * txn, wyl_policy_store_t * store,
    const gchar * old_credential_id, const gchar * actor_subject_id,
    const gchar * request_id, gint64 new_expires_at_us,
    gint64 (*now_us_cb) (gpointer data), gpointer now_data,
    const wyl_service_credential_runtime_t * runtime,
    guint64 expected_generation, const guint8 * cvk,
    gsize cvk_len, wyl_policy_service_credential_info_t * out,
    wyl_service_credential_secret_t ** out_secret)
{
  if (out != NULL)
    wyl_policy_service_credential_info_clear (out);
  if (out_secret != NULL)
    wyl_service_credential_secret_clear (out_secret);
  wyrelog_error_t rc =
      wyl_policy_store_service_authority_transaction_enter_participant (txn,
      store);
  return rc == WYRELOG_E_OK ? service_credential_rotate_impl (store,
      old_credential_id, actor_subject_id, request_id, new_expires_at_us,
      now_us_cb, now_data, runtime, expected_generation, cvk, cvk_len, out,
      out_secret, TRUE) : rc;
}

wyrelog_error_t
    wyl_policy_store_rotate_service_credential_handoff_core
    (WylServiceAuthorityTransaction * txn, wyl_policy_store_t * store,
    const gchar * old_credential_id, const gchar * actor_subject_id,
    const gchar * request_id, gint64 new_expires_at_us,
    gint64 (*now_us_cb) (gpointer data), gpointer now_data,
    const wyl_service_credential_runtime_t * runtime,
    guint64 expected_generation, const guint8 * cvk, gsize cvk_len,
    const wyl_policy_service_handoff_request_t * handoff,
    wyl_policy_service_credential_info_t * out,
    wyl_policy_service_handoff_escrow_info_t * out_escrow)
{
  if (out != NULL)
    wyl_policy_service_credential_info_clear (out);
  if (out_escrow != NULL)
    wyl_policy_service_handoff_escrow_info_clear (out_escrow);
  if (out == NULL || out_escrow == NULL
      || !service_credential_handoff_request_valid (handoff))
    return WYRELOG_E_INVALID;
  if (old_credential_id == NULL
      || !wyl_service_credential_id_is_canonical (old_credential_id,
          strlen (old_credential_id))
      || !wyl_policy_service_actor_subject_is_valid (actor_subject_id)
      || !service_domain_text_is_valid (request_id, 256)
      || new_expires_at_us < 0 || expected_generation > G_MAXINT64)
    return WYRELOG_E_INVALID;
  guint8 fingerprint[crypto_generichash_BYTES] = { 0 };
  wyrelog_error_t rc = service_credential_rotate_fingerprint (old_credential_id,
      actor_subject_id, new_expires_at_us, fingerprint);
  if (rc != WYRELOG_E_OK) {
    sodium_memzero (fingerprint, sizeof fingerprint);
    return rc;
  }
  rc = wyl_policy_store_service_authority_transaction_enter_participant (txn,
      store);
  if (rc != WYRELOG_E_OK) {
    sodium_memzero (fingerprint, sizeof fingerprint);
    return rc;
  }
  rc = service_credential_handoff_replay (store, "rotate", request_id,
      actor_subject_id, handoff, "credential_rotate", old_credential_id,
      fingerprint, out, out_escrow);
  sodium_memzero (fingerprint, sizeof fingerprint);
  if (rc == WYRELOG_E_OK)
    return rc;
  if (rc != WYRELOG_E_NOT_FOUND)
    return rc;
  wyl_service_credential_secret_t *secret = NULL;
  rc = wyl_policy_store_rotate_service_credential_core (txn,
      store, old_credential_id, actor_subject_id, request_id,
      new_expires_at_us, now_us_cb, now_data, runtime, expected_generation,
      cvk, cvk_len, out, &secret);
  if (rc == WYRELOG_E_OK)
    rc = service_credential_handoff_store (store, "rotate", request_id,
        actor_subject_id, handoff, out, secret, out_escrow);
  wyl_service_credential_secret_clear (&secret);
  if (rc != WYRELOG_E_OK) {
    wyl_policy_service_credential_info_clear (out);
    wyl_policy_service_handoff_escrow_info_clear (out_escrow);
  }
  return rc;
}

wyrelog_error_t
wyl_policy_store_verify_service_credential_secret (wyl_policy_store_t *store,
    const wyl_policy_service_credential_info_t *credential,
    const gchar *presented_secret, gsize presented_secret_len,
    gboolean *out_match)
{
  if (store == NULL || credential == NULL || presented_secret == NULL
      || out_match == NULL)
    return WYRELOG_E_INVALID;
  if (credential->credential_format_version
      != WYL_SERVICE_CREDENTIAL_FORMAT_VERSION
      || credential->verifier_version
      != WYL_SERVICE_CREDENTIAL_VERIFIER_VERSION
      || !wyl_service_credential_id_is_canonical (credential->credential_id,
          credential->credential_id != NULL
          ? strlen (credential->credential_id) : 0)
      || !wyl_policy_service_subject_is_valid (credential->subject_id,
          credential->subject_id != NULL ? strlen (credential->subject_id) : 0)
      || !wyl_policy_store_tenant_id_is_valid (credential->tenant_id))
    return WYRELOG_E_POLICY;
  const guint8 *cvk = NULL;
  gsize cvk_len = 0;
  wyrelog_error_t rc =
      wyl_policy_store_materialize_service_cvk_existing (store, &cvk, &cvk_len);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_service_credential_verify (credential->credential_format_version,
      credential->verifier_version, cvk, cvk_len, credential->credential_id,
      strlen (credential->credential_id), credential->tenant_id,
      strlen (credential->tenant_id), credential->subject_id,
      strlen (credential->subject_id), credential->salt,
      sizeof credential->salt, credential->verifier,
      sizeof credential->verifier, presented_secret, presented_secret_len,
      out_match);
}

static wyrelog_error_t
parse_service_principal_event_row (sqlite3_stmt *stmt,
    wyl_policy_service_principal_event_info_t *out)
{
  memset (out, 0, sizeof (*out));
  wyrelog_error_t rc = read_positive_i64 (stmt, 0, FALSE, &out->event_id);
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 1, FALSE, 5, 128, &out->subject_id);
  if (rc == WYRELOG_E_OK && !wyl_policy_service_subject_is_valid
      (out->subject_id, strlen (out->subject_id)))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 2, FALSE, 1, 16, &out->event);
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 3, TRUE, 1, 16, &out->from_state);
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 4, FALSE, 1, 16, &out->to_state);
  if (rc == WYRELOG_E_OK)
    rc = read_positive_u64 (stmt, 5, &out->generation);
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 6, FALSE, 1, 128, &out->actor_subject_id);
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 7, TRUE, 1, 256, &out->request_id);
  if (rc == WYRELOG_E_OK)
    rc = read_positive_i64 (stmt, 8, FALSE, &out->created_at_us);
  if (rc == WYRELOG_E_OK && !((g_str_equal (out->event, "created")
              && out->from_state == NULL
              && g_str_equal (out->to_state, "active"))
          || (g_str_equal (out->event, "disabled")
              && g_strcmp0 (out->from_state, "active") == 0
              && g_str_equal (out->to_state, "disabled"))))
    rc = WYRELOG_E_POLICY;
  if (rc != WYRELOG_E_OK)
    wyl_policy_service_principal_event_info_clear (out);
  return rc;
}

static wyrelog_error_t
parse_service_credential_event_row (sqlite3_stmt *stmt,
    wyl_policy_service_credential_event_info_t *out)
{
  memset (out, 0, sizeof (*out));
  wyrelog_error_t rc = read_positive_i64 (stmt, 0, FALSE, &out->event_id);
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 1, FALSE, 1, 128, &out->credential_id);
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 2, FALSE, 5, 128, &out->subject_id);
  if (rc == WYRELOG_E_OK && !wyl_policy_service_subject_is_valid
      (out->subject_id, strlen (out->subject_id)))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 3, FALSE, 1, 128, &out->tenant_id);
  if (rc == WYRELOG_E_OK
      && !wyl_policy_store_tenant_id_is_valid (out->tenant_id))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 4, FALSE, 1, 16, &out->event);
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 5, TRUE, 1, 16, &out->from_state);
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 6, FALSE, 1, 16, &out->to_state);
  if (rc == WYRELOG_E_OK)
    rc = read_positive_u64 (stmt, 7, &out->generation);
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 8, FALSE, 1, 128, &out->actor_subject_id);
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 9, TRUE, 1, 256, &out->request_id);
  if (rc == WYRELOG_E_OK)
    rc = read_owned_text (stmt, 10, TRUE, 1, 128, &out->related_credential_id);
  if (rc == WYRELOG_E_OK)
    rc = read_positive_i64 (stmt, 11, FALSE, &out->created_at_us);
  if (rc == WYRELOG_E_OK && !(((g_str_equal (out->event, "issued")
                  || g_str_equal (out->event, "rotated"))
              && out->from_state == NULL
              && g_str_equal (out->to_state, "active"))
          || (g_str_equal (out->event, "revoked")
              && g_strcmp0 (out->from_state, "active") == 0
              && g_str_equal (out->to_state, "revoked"))))
    rc = WYRELOG_E_POLICY;
  if (rc != WYRELOG_E_OK)
    wyl_policy_service_credential_event_info_clear (out);
  return rc;
}

wyrelog_error_t
wyl_policy_store_foreach_service_principal_event (wyl_policy_store_t *store,
    const gchar *subject_id, wyl_policy_service_principal_event_cb cb,
    gpointer user_data)
{
  if (store == NULL || store->db == NULL || cb == NULL || subject_id == NULL
      || !wyl_policy_service_subject_is_valid (subject_id, strlen (subject_id)))
    return WYRELOG_E_INVALID;
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT event_id,subject_id,event,from_state,to_state,generation,"
      "actor_subject_id,request_id,created_at_us FROM service_principal_events"
      " WHERE subject_id=? ORDER BY created_at_us,event_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }
  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    wyl_policy_service_principal_event_info_t info = { 0 };
    rc = parse_service_principal_event_row (stmt, &info);
    if (rc == WYRELOG_E_OK)
      rc = cb (&info, user_data);
    wyl_policy_service_principal_event_info_clear (&info);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }
  sqlite3_finalize (stmt);
  return step_rc == SQLITE_DONE ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_foreach_service_credential_event (wyl_policy_store_t *store,
    const gchar *credential_id, const gchar *subject_id,
    const gchar *tenant_id, wyl_policy_service_credential_event_cb cb,
    gpointer user_data)
{
  if (store == NULL || store->db == NULL || cb == NULL
      || credential_id == NULL
      || !credential_filter_is_valid (credential_id, subject_id, tenant_id))
    return WYRELOG_E_INVALID;
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT event_id,credential_id,subject_id,tenant_id,event,from_state,"
      "to_state,generation,actor_subject_id,request_id,related_credential_id,"
      "created_at_us FROM service_credential_events WHERE credential_id=?"
      " AND subject_id=? AND tenant_id=? ORDER BY created_at_us,event_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_service_filter (stmt, credential_id, subject_id, tenant_id))
      != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }
  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    wyl_policy_service_credential_event_info_t info = { 0 };
    rc = parse_service_credential_event_row (stmt, &info);
    if (rc == WYRELOG_E_OK)
      rc = cb (&info, user_data);
    wyl_policy_service_credential_event_info_clear (&info);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }
  sqlite3_finalize (stmt);
  return step_rc == SQLITE_DONE ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_validate_snapshot (wyl_policy_store_t *store)
{
  if (store == NULL || store->db == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = wyl_policy_store_validate_service_schema (store);
  if (rc != WYRELOG_E_OK)
    return rc;

  gboolean found = FALSE;
  static const gchar *cycle_sql =
      "WITH RECURSIVE walk(root, node, depth, path) AS ("
      "  SELECT child_role_id, parent_role_id, 1,"
      "    '|' || child_role_id || '|' || parent_role_id || '|' "
      "  FROM role_inheritances"
      "  UNION ALL "
      "  SELECT walk.root, ri.parent_role_id, walk.depth + 1,"
      "    walk.path || ri.parent_role_id || '|' "
      "  FROM walk "
      "  JOIN role_inheritances ri ON ri.child_role_id = walk.node "
      "  WHERE walk.depth < 32 "
      "    AND instr(walk.path, '|' || ri.parent_role_id || '|') = 0"
      ") "
      "SELECT 1 FROM walk WHERE root = node "
      "UNION ALL "
      "SELECT 1 FROM walk "
      "JOIN role_inheritances ri ON ri.child_role_id = walk.node "
      "WHERE ri.parent_role_id = walk.root " "LIMIT 1;";
  rc = query_has_rows (store->db, cycle_sql, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (found)
    return WYRELOG_E_POLICY;

  static const gchar *depth_sql =
      "WITH RECURSIVE walk(child, parent, depth) AS ("
      "  SELECT child_role_id, parent_role_id, 1 FROM role_inheritances"
      "  UNION ALL "
      "  SELECT walk.child, ri.parent_role_id, walk.depth + 1 "
      "  FROM walk "
      "  JOIN role_inheritances ri ON ri.child_role_id = walk.parent "
      "  WHERE walk.depth < 4"
      ") " "SELECT 1 FROM walk WHERE depth > 3 LIMIT 1;";
  rc = query_has_rows (store->db, depth_sql, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (found)
    return WYRELOG_E_POLICY;

  static const gchar *role_permission_sod_sql =
      "SELECT 1 FROM role_permissions "
      "WHERE (role_id = 'wr.break_glass' AND perm_id = 'wr.audit.write') "
      "   OR (role_id = 'wr.system_admin' AND perm_id GLOB 'wr.audit.*') "
      "   OR (role_id = 'wr.auditor' AND perm_id IN ("
      "        'wr.policy.write', 'wr.policy.grant_role', "
      "        'wr.svc.grant_role')) " "LIMIT 1;";
  rc = query_has_rows (store->db, role_permission_sod_sql, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (found)
    return WYRELOG_E_POLICY;

  static const gchar *role_membership_sod_sql =
      "WITH RECURSIVE role_closure(role_id, effective_role_id) AS ("
      "  SELECT role_id, role_id FROM roles "
      "  UNION "
      "  SELECT role_closure.role_id, ri.parent_role_id "
      "  FROM role_closure "
      "  JOIN role_inheritances ri "
      "    ON ri.child_role_id = role_closure.effective_role_id"
      "), effective_membership(subject_id, scope, effective_role_id) AS ("
      "  SELECT rm.subject_id, rm.scope, rc.effective_role_id "
      "  FROM role_memberships rm "
      "  JOIN role_closure rc ON rc.role_id = rm.role_id"
      ") "
      "SELECT 1 FROM effective_membership privileged "
      "JOIN effective_membership auditor "
      "  ON auditor.subject_id = privileged.subject_id "
      " AND auditor.scope = privileged.scope "
      "WHERE privileged.effective_role_id IN ("
      "    'wr.system_admin', 'wr.service_admin', 'wr.break_glass') "
      "  AND auditor.effective_role_id = 'wr.auditor' " "LIMIT 1;";
  rc = query_has_rows (store->db, role_membership_sod_sql, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (found)
    return WYRELOG_E_POLICY;

  static const gchar *direct_permission_sod_sql =
      "SELECT 1 FROM direct_permissions audit "
      "JOIN direct_permissions privileged "
      "  ON privileged.subject_id = audit.subject_id "
      " AND privileged.scope = audit.scope "
      "WHERE audit.perm_id IN ("
      "    'wr.audit.read', 'wr.audit.explain', 'wr.audit.write') "
      "  AND privileged.perm_id IN ("
      "    'wr.sys.admin', 'wr.svc.admin', "
      "    'wr.policy.write', 'wr.policy.grant_role', "
      "    'wr.svc.grant_role') " "LIMIT 1;";
  rc = query_has_rows (store->db, direct_permission_sod_sql, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (found)
    return WYRELOG_E_POLICY;

  static const gchar *mixed_permission_role_sod_sql =
      "WITH RECURSIVE role_closure(role_id, effective_role_id) AS ("
      "  SELECT role_id, role_id FROM roles "
      "  UNION "
      "  SELECT role_closure.role_id, ri.parent_role_id "
      "  FROM role_closure "
      "  JOIN role_inheritances ri "
      "    ON ri.child_role_id = role_closure.effective_role_id"
      "), effective_membership(subject_id, scope, effective_role_id) AS ("
      "  SELECT rm.subject_id, rm.scope, rc.effective_role_id "
      "  FROM role_memberships rm "
      "  JOIN role_closure rc ON rc.role_id = rm.role_id"
      ") "
      "SELECT 1 FROM direct_permissions audit "
      "JOIN effective_membership privileged "
      "  ON privileged.subject_id = audit.subject_id "
      " AND privileged.scope = audit.scope "
      "WHERE audit.perm_id IN ("
      "    'wr.audit.read', 'wr.audit.explain', 'wr.audit.write') "
      "  AND privileged.effective_role_id IN ("
      "    'wr.system_admin', 'wr.service_admin', 'wr.break_glass') "
      "UNION ALL "
      "SELECT 1 FROM effective_membership auditor "
      "JOIN direct_permissions privileged "
      "  ON privileged.subject_id = auditor.subject_id "
      " AND privileged.scope = auditor.scope "
      "WHERE auditor.effective_role_id = 'wr.auditor' "
      "  AND privileged.perm_id IN ("
      "    'wr.sys.admin', 'wr.svc.admin', "
      "    'wr.policy.write', 'wr.policy.grant_role', "
      "    'wr.svc.grant_role') " "LIMIT 1;";
  rc = query_has_rows (store->db, mixed_permission_role_sod_sql, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (found)
    return WYRELOG_E_POLICY;

  static const gchar *effective_permission_sod_sql =
      "WITH RECURSIVE role_closure(role_id, effective_role_id) AS ("
      "  SELECT role_id, role_id FROM roles "
      "  UNION "
      "  SELECT role_closure.role_id, ri.parent_role_id "
      "  FROM role_closure "
      "  JOIN role_inheritances ri "
      "    ON ri.child_role_id = role_closure.effective_role_id"
      "), role_subject_permission(subject_id, scope, perm_id) AS ("
      "  SELECT rm.subject_id, rm.scope, rp.perm_id "
      "  FROM role_memberships rm "
      "  JOIN role_closure rc ON rc.role_id = rm.role_id "
      "  JOIN role_permissions rp ON rp.role_id = rc.effective_role_id"
      "), subject_permission(subject_id, scope, perm_id) AS ("
      "  SELECT subject_id, scope, perm_id FROM direct_permissions "
      "  UNION "
      "  SELECT subject_id, scope, perm_id FROM role_subject_permission"
      ") "
      "SELECT 1 FROM subject_permission audit "
      "JOIN subject_permission privileged "
      "  ON privileged.subject_id = audit.subject_id "
      " AND privileged.scope = audit.scope "
      "WHERE audit.perm_id IN ("
      "    'wr.audit.read', 'wr.audit.explain', 'wr.audit.write') "
      "  AND privileged.perm_id IN ("
      "    'wr.sys.admin', 'wr.svc.admin', "
      "    'wr.policy.write', 'wr.policy.grant_role', "
      "    'wr.svc.grant_role') " "LIMIT 1;";
  rc = query_has_rows (store->db, effective_permission_sod_sql, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (found)
    return WYRELOG_E_POLICY;

  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_upsert_role (wyl_policy_store_t *store, const gchar *role_id,
    const gchar *role_name)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || role_id == NULL
      || role_name == NULL)
    return WYRELOG_E_INVALID;

  const BuiltinRole *builtin = find_builtin_role (role_id);
  if (builtin != NULL && g_strcmp0 (role_name, builtin->name) != 0)
    return WYRELOG_E_POLICY;
  if (builtin == NULL && is_reserved_catalog_id (role_id))
    return WYRELOG_E_POLICY;

  static const gchar *sql =
      "INSERT INTO roles (role_id, role_name, created_at, modified_at) "
      "VALUES (?, ?, unixepoch(), unixepoch()) "
      "ON CONFLICT(role_id) DO UPDATE SET "
      "  role_name = excluded.role_name,"
      "  modified_at = excluded.modified_at;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, role_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, role_name)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_grant_direct_permission (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || perm_id == NULL || scope == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = service_authorization_subject_check (store,
      subject_id, g_str_equal (perm_id, "wr.login.skip_mfa"));
  if (rc != WYRELOG_E_OK)
    return rc;
  if (wyl_policy_subject_has_service_prefix (subject_id)) {
    wyl_permission_plane_t plane = WYL_PERMISSION_PLANE_CONTROL;
    rc = wyl_policy_store_permission_plane (store, perm_id, &plane);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (plane != WYL_PERMISSION_PLANE_DATA)
      return WYRELOG_E_POLICY;
  }

  static const gchar *sql =
      "INSERT INTO direct_permissions "
      "  (subject_id, perm_id, scope, granted_at) "
      "VALUES (?, ?, ?, unixepoch()) "
      "ON CONFLICT(subject_id, perm_id, scope) DO UPDATE SET "
      "  granted_at = excluded.granted_at;";
  rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, perm_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_revoke_direct_permission (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || perm_id == NULL || scope == NULL)
    return WYRELOG_E_INVALID;

  /* Revocation is a repair operation: legacy unregistered service subjects
   * and registered services with human-only grants must remain removable. */

  static const gchar *sql =
      "DELETE FROM direct_permissions "
      "WHERE subject_id = ? AND perm_id = ? AND scope = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, perm_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
    wyl_policy_store_apply_direct_permission_mutation_with_audit
    (wyl_policy_store_t * store, const gchar * subject_id,
    const gchar * perm_id, const gchar * scope, gboolean insert,
    const gchar * audit_id, gint64 audit_created_at_us,
    const gchar * audit_subject_id, const gchar * audit_action,
    const gchar * audit_resource_id, const gchar * audit_deny_reason,
    const gchar * audit_deny_origin, const gchar * audit_request_id,
    wyl_decision_t audit_decision)
{
  if (store == NULL || store->db == NULL || subject_id == NULL
      || perm_id == NULL || scope == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = wyl_policy_store_begin_mutation (store);
  if (rc != WYRELOG_E_OK)
    return rc;

  if (insert) {
    gboolean exists = FALSE;
    rc = wyl_policy_store_permission_exists (store, perm_id, &exists);
    if (rc == WYRELOG_E_OK && !exists && is_reserved_catalog_id (perm_id))
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK && !exists)
      rc = wyl_policy_store_upsert_permission (store, perm_id, perm_id,
          "basic");
  } else {
    rc = WYRELOG_E_OK;
  }
  if (rc == WYRELOG_E_OK) {
    rc = insert
        ? wyl_policy_store_grant_direct_permission (store, subject_id, perm_id,
        scope)
        : wyl_policy_store_revoke_direct_permission (store, subject_id,
        perm_id, scope);
  }
  if (rc == WYRELOG_E_OK) {
    rc = wyl_policy_store_append_direct_permission_event (store, subject_id,
        perm_id, scope, insert ? "grant" : "revoke");
  }
  if (rc == WYRELOG_E_OK && audit_id != NULL) {
    gboolean inserted = FALSE;
    rc = wyl_policy_store_append_audit_event_full (store, audit_id,
        audit_created_at_us, audit_subject_id, audit_action,
        audit_resource_id, audit_deny_reason, audit_deny_origin,
        audit_request_id, audit_decision, &inserted);
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_validate_snapshot (store);
  if (rc != WYRELOG_E_OK) {
    wyl_policy_store_rollback_mutation (store);
    return rc;
  }

  rc = wyl_policy_store_commit_mutation (store);
  if (rc != WYRELOG_E_OK) {
    wyl_policy_store_rollback_mutation (store);
    return rc;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_apply_direct_permission_mutation (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope,
    gboolean insert)
{
  return wyl_policy_store_apply_direct_permission_mutation_with_audit (store,
      subject_id, perm_id, scope, insert, NULL, 0, NULL, NULL, NULL, NULL, NULL,
      NULL, WYL_DECISION_DENY);
}

wyrelog_error_t
wyl_policy_store_direct_permission_exists (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope,
    gboolean *out_exists)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || perm_id == NULL || scope == NULL || out_exists == NULL)
    return WYRELOG_E_INVALID;

  *out_exists = FALSE;
  static const gchar *sql =
      "SELECT 1 FROM direct_permissions "
      "WHERE subject_id = ? AND perm_id = ? AND scope = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, perm_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW)
    *out_exists = TRUE;
  else if (step_rc != SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_subject_has_permission (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope,
    gboolean *out_has_permission)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || perm_id == NULL || scope == NULL || out_has_permission == NULL)
    return WYRELOG_E_INVALID;

  *out_has_permission = FALSE;
  static const gchar *sql =
      "WITH RECURSIVE role_closure(role_id, effective_role_id) AS ("
      "  SELECT role_id, role_id FROM roles"
      "  UNION"
      "  SELECT role_closure.role_id, ri.parent_role_id"
      "  FROM role_closure"
      "  JOIN role_inheritances ri"
      "    ON ri.child_role_id = role_closure.effective_role_id"
      "), role_subject_permission(subject_id, scope, perm_id) AS ("
      "  SELECT rm.subject_id, rm.scope, rp.perm_id"
      "  FROM role_memberships rm"
      "  JOIN role_closure rc ON rc.role_id = rm.role_id"
      "  JOIN role_permissions rp ON rp.role_id = rc.effective_role_id"
      "), subject_permission(subject_id, scope, perm_id) AS ("
      "  SELECT subject_id, scope, perm_id FROM direct_permissions"
      "  UNION"
      "  SELECT subject_id, scope, perm_id FROM role_subject_permission"
      ") "
      "SELECT 1 FROM subject_permission "
      "WHERE subject_id = ? AND perm_id = ? AND scope = ? LIMIT 1;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, perm_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW)
    *out_has_permission = TRUE;
  else if (step_rc != SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_foreach_direct_permission (wyl_policy_store_t *store,
    wyl_policy_direct_permission_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT subject_id, perm_id, scope FROM direct_permissions "
      "ORDER BY subject_id, perm_id, scope;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *subject_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *perm_id = (const gchar *) sqlite3_column_text (stmt, 1);
    const gchar *scope = (const gchar *) sqlite3_column_text (stmt, 2);
    rc = cb (subject_id, perm_id, scope, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_append_direct_permission_event (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope,
    const gchar *operation)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || perm_id == NULL || scope == NULL || operation == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = WYRELOG_E_OK;
  /* A revoke event is the durable half of destructive repair and therefore
   * follows the same exception as the deletion it records. */
  if (!g_str_equal (operation, "revoke")) {
    rc = service_authorization_subject_check (store, subject_id,
        g_str_equal (perm_id, "wr.login.skip_mfa"));
    if (rc != WYRELOG_E_OK)
      return rc;
  }

  static const gchar *sql =
      "INSERT INTO direct_permission_events "
      "  (subject_id, perm_id, scope, operation, created_at) "
      "VALUES (?, ?, ?, ?, unixepoch());";
  rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, perm_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 4, operation)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_foreach_direct_permission_event (wyl_policy_store_t *store,
    wyl_policy_direct_permission_event_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT subject_id, perm_id, scope, operation "
      "FROM direct_permission_events ORDER BY event_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *subject_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *perm_id = (const gchar *) sqlite3_column_text (stmt, 1);
    const gchar *scope = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *operation = (const gchar *) sqlite3_column_text (stmt, 3);
    rc = cb (subject_id, perm_id, scope, operation, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_set_permission_state (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope,
    const gchar *state)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || perm_id == NULL || scope == NULL || state == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_policy_subject_has_service_prefix (subject_id))
    return WYRELOG_E_POLICY;

  static const gchar *sql =
      "INSERT INTO permission_states "
      "  (subject_id, perm_id, scope, state, updated_at) "
      "VALUES (?, ?, ?, ?, unixepoch()) "
      "ON CONFLICT(subject_id, perm_id, scope) DO UPDATE SET "
      "  state = excluded.state," "  updated_at = excluded.updated_at;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, perm_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 4, state)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_permission_state_exists (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope,
    gboolean *out_exists)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || perm_id == NULL || scope == NULL || out_exists == NULL)
    return WYRELOG_E_INVALID;

  *out_exists = FALSE;
  if (wyl_policy_subject_has_service_prefix (subject_id))
    return WYRELOG_E_POLICY;
  static const gchar *sql =
      "SELECT 1 FROM permission_states "
      "WHERE subject_id = ? AND perm_id = ? AND scope = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, perm_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW)
    *out_exists = TRUE;
  else if (step_rc != SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_permission_state_is (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope,
    const gchar *state, gboolean *out_matches)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || perm_id == NULL || scope == NULL || state == NULL
      || out_matches == NULL)
    return WYRELOG_E_INVALID;

  *out_matches = FALSE;
  if (wyl_policy_subject_has_service_prefix (subject_id))
    return WYRELOG_E_POLICY;
  static const gchar *sql =
      "SELECT 1 FROM permission_states "
      "WHERE subject_id = ? AND perm_id = ? AND scope = ? AND state = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, perm_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 4, state)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW)
    *out_matches = TRUE;
  else if (step_rc != SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
wyl_policy_store_get_permission_state (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope,
    gchar **out_state)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || perm_id == NULL || scope == NULL || out_state == NULL)
    return WYRELOG_E_INVALID;

  *out_state = NULL;
  if (wyl_policy_subject_has_service_prefix (subject_id))
    return WYRELOG_E_POLICY;
  static const gchar *sql =
      "SELECT state FROM permission_states "
      "WHERE subject_id = ? AND perm_id = ? AND scope = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, perm_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW) {
    const gchar *state = (const gchar *) sqlite3_column_text (stmt, 0);
    if (state == NULL) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_POLICY;
    }
    *out_state = g_strdup (state);
  } else if (step_rc != SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_foreach_permission_state (wyl_policy_store_t *store,
    wyl_policy_permission_state_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT subject_id, perm_id, scope, state "
      "FROM permission_states ORDER BY subject_id, perm_id, scope;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *subject_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *perm_id = (const gchar *) sqlite3_column_text (stmt, 1);
    const gchar *scope = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *state = (const gchar *) sqlite3_column_text (stmt, 3);
    rc = cb (subject_id, perm_id, scope, state, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_append_permission_state_event (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope,
    const gchar *event, const gchar *from_state, const gchar *to_state,
    gint64 *out_event_id)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || perm_id == NULL || scope == NULL || event == NULL
      || from_state == NULL || to_state == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_policy_subject_has_service_prefix (subject_id))
    return WYRELOG_E_POLICY;

  static const gchar *sql =
      "INSERT INTO permission_state_events "
      "  (subject_id, perm_id, scope, event, from_state, to_state, created_at) "
      "VALUES (?, ?, ?, ?, ?, ?, unixepoch());";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, perm_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 4, event)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 5, from_state)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 6, to_state)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  if (step_rc != SQLITE_DONE)
    return WYRELOG_E_IO;
  if (out_event_id != NULL) {
    sqlite3_int64 event_id = sqlite3_last_insert_rowid (store->db);
    if (event_id <= 0)
      return WYRELOG_E_IO;
    *out_event_id = event_id;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
    wyl_policy_store_apply_permission_state_transition_with_audit
    (wyl_policy_store_t * store, const gchar * subject_id,
    const gchar * perm_id, const gchar * scope, const gchar * event,
    gint64 * out_event_id, const gchar * audit_id,
    gint64 audit_created_at_us, const gchar * audit_subject_id,
    const gchar * audit_action, const gchar * audit_resource_id,
    const gchar * audit_deny_reason, const gchar * audit_deny_origin,
    const gchar * audit_request_id, wyl_decision_t audit_decision)
{
  if (out_event_id != NULL)
    *out_event_id = -1;
  if (store == NULL || store->db == NULL || subject_id == NULL
      || perm_id == NULL || scope == NULL || event == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_policy_subject_has_service_prefix (subject_id))
    return WYRELOG_E_POLICY;

  wyl_perm_event_t ev = wyl_perm_event_from_name (event);
  if (ev == WYL_PERM_EVENT_LAST_)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = wyl_policy_store_begin_mutation (store);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *from_state_name = NULL;
  rc = wyl_policy_store_get_permission_state (store, subject_id, perm_id,
      scope, &from_state_name);
  if (rc == WYRELOG_E_OK && from_state_name == NULL)
    from_state_name = g_strdup (wyl_perm_state_name (WYL_PERM_STATE_DORMANT));

  wyl_perm_state_t from = WYL_PERM_STATE_LAST_;
  wyl_perm_state_t to = WYL_PERM_STATE_LAST_;
  const gchar *to_state_name = NULL;
  if (rc == WYRELOG_E_OK) {
    from = wyl_perm_state_from_name (from_state_name);
    if (from == WYL_PERM_STATE_LAST_)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_fsm_permission_scope_step (from, ev, &to);
  if (rc == WYRELOG_E_OK) {
    to_state_name = wyl_perm_state_name (to);
    if (to_state_name == NULL)
      rc = WYRELOG_E_INTERNAL;
  }
  if (rc == WYRELOG_E_OK) {
    rc = wyl_policy_store_set_permission_state (store, subject_id, perm_id,
        scope, to_state_name);
  }

  gint64 event_id = -1;
  if (rc == WYRELOG_E_OK) {
    rc = wyl_policy_store_append_permission_state_event (store, subject_id,
        perm_id, scope, event, from_state_name, to_state_name, &event_id);
  }
  if (rc == WYRELOG_E_OK && audit_id != NULL) {
    gboolean inserted = FALSE;
    rc = wyl_policy_store_append_audit_event_full (store, audit_id,
        audit_created_at_us, audit_subject_id, audit_action,
        audit_resource_id, audit_deny_reason, audit_deny_origin,
        audit_request_id, audit_decision, &inserted);
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_validate_snapshot (store);
  if (rc != WYRELOG_E_OK) {
    wyl_policy_store_rollback_mutation (store);
    return rc;
  }

  rc = wyl_policy_store_commit_mutation (store);
  if (rc != WYRELOG_E_OK) {
    wyl_policy_store_rollback_mutation (store);
    return rc;
  }
  if (out_event_id != NULL)
    *out_event_id = event_id;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_apply_permission_state_transition (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope,
    const gchar *event, gint64 *out_event_id)
{
  return wyl_policy_store_apply_permission_state_transition_with_audit (store,
      subject_id, perm_id, scope, event, out_event_id, NULL, 0, NULL, NULL,
      NULL, NULL, NULL, NULL, WYL_DECISION_DENY);
}

wyrelog_error_t
wyl_policy_store_foreach_permission_state_event (wyl_policy_store_t *store,
    wyl_policy_permission_state_event_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT event_id, subject_id, perm_id, scope, event, from_state, to_state "
      "FROM permission_state_events ORDER BY event_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    gint64 event_id = sqlite3_column_int64 (stmt, 0);
    const gchar *subject_id = (const gchar *) sqlite3_column_text (stmt, 1);
    const gchar *perm_id = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *scope = (const gchar *) sqlite3_column_text (stmt, 3);
    const gchar *event = (const gchar *) sqlite3_column_text (stmt, 4);
    const gchar *from_state = (const gchar *) sqlite3_column_text (stmt, 5);
    const gchar *to_state = (const gchar *) sqlite3_column_text (stmt, 6);
    if (event_id <= 0) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_POLICY;
    }
    rc = cb (event_id, subject_id, perm_id, scope, event, from_state, to_state,
        user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_set_principal_state (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *state)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL || state == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_policy_subject_has_service_prefix (subject_id))
    return WYRELOG_E_POLICY;

  static const gchar *sql =
      "INSERT INTO principal_states (subject_id, state, updated_at) "
      "VALUES (?, ?, unixepoch()) "
      "ON CONFLICT(subject_id) DO UPDATE SET "
      "  state = excluded.state," "  updated_at = excluded.updated_at;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, state)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_foreach_principal_state (wyl_policy_store_t *store,
    wyl_policy_principal_state_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT subject_id, state FROM principal_states " "ORDER BY subject_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *subject_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *state = (const gchar *) sqlite3_column_text (stmt, 1);
    rc = cb (subject_id, state, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

/* ----------------------------------------------------------------------
 * Single-subject principal-state accessors (issue #331 commit 5).
 *
 * The historical foreach-based two-step lookup in daemon/http.c iterated
 * the entire principal_states table to surface a single subject's
 * current state.  The accessors below replace that O(N) scan with a
 * single-row SELECT keyed by subject_id, and surface the explicit
 * "no row" vs "iteration error" distinction via *out_found so callers
 * never have to grep for a NULL-string sentinel.
 *
 * F1 (timing): the validator hot-path calls get_principal_lock_info
 * before any HMAC work, so the cost is one indexed SELECT regardless of
 * the principal_states row count.  The earlier foreach-based path was a
 * full table scan and scaled with the number of enrolled subjects -
 * a more concerning timing differential than the validator's intentional
 * no-enrollment vs wrong-code gap (commit-3 rationale; documented in
 * mfa-validator.c above note_failed_attempt).
 *
 * F2 (secrets): no log/audit emission inside these helpers ever sees a
 * TOTP seed or submitted code.  The only subject-bound identifiers
 * surfaced are the subject_id passed in by the caller.
 * ---------------------------------------------------------------------- */

wyrelog_error_t
wyl_policy_store_get_principal_state (wyl_policy_store_t *store,
    const gchar *subject_id, gchar **out_state, gboolean *out_found)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || out_state == NULL || out_found == NULL)
    return WYRELOG_E_INVALID;

  *out_state = NULL;
  *out_found = FALSE;
  if (wyl_policy_subject_has_service_prefix (subject_id))
    return WYRELOG_E_POLICY;

  static const gchar *sql =
      "SELECT state FROM principal_states WHERE subject_id = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_OK;
  }
  if (step_rc != SQLITE_ROW) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  const gchar *db_state = (const gchar *) sqlite3_column_text (stmt, 0);
  *out_state = g_strdup (db_state != NULL ? db_state : "");
  *out_found = TRUE;
  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_get_principal_lock_info (wyl_policy_store_t *store,
    const gchar *subject_id, gchar **out_state, gint64 *out_failed_count,
    gint64 *out_locked_at, gboolean *out_found)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || out_state == NULL || out_failed_count == NULL
      || out_locked_at == NULL || out_found == NULL)
    return WYRELOG_E_INVALID;

  *out_state = NULL;
  *out_failed_count = 0;
  *out_locked_at = G_MININT64;
  *out_found = FALSE;
  if (wyl_policy_subject_has_service_prefix (subject_id))
    return WYRELOG_E_POLICY;

  static const gchar *sql =
      "SELECT state, failed_attempt_count, locked_at "
      "FROM principal_states WHERE subject_id = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_OK;
  }
  if (step_rc != SQLITE_ROW) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  const gchar *db_state = (const gchar *) sqlite3_column_text (stmt, 0);
  *out_state = g_strdup (db_state != NULL ? db_state : "");
  *out_failed_count = sqlite3_column_int64 (stmt, 1);
  if (sqlite3_column_type (stmt, 2) == SQLITE_NULL)
    *out_locked_at = G_MININT64;
  else
    *out_locked_at = sqlite3_column_int64 (stmt, 2);
  *out_found = TRUE;
  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

/* Atomic FAILED_ATTEMPT mutation: increment the counter, and if the
 * resulting value reaches |threshold|, transition the row to LOCKED in
 * the same savepoint.  The transaction defeats the read-modify-write
 * race that would let two concurrent failed verify attempts both see
 * counter=N-1 and each fail to LOCK independently (commit-5 critic
 * footgun).  The current-state read happens inside the savepoint via
 * a SELECT, then the UPDATE writes the new counter + (conditionally)
 * the LOCKED state and locked_at - all before COMMIT releases the
 * savepoint.
 */
wyrelog_error_t
wyl_policy_store_apply_principal_failure (wyl_policy_store_t *store,
    const gchar *subject_id, gint64 threshold, gint64 now_secs,
    gchar **out_state, gint64 *out_count, gint64 *out_locked_at)
{
  if (store == NULL || store->db == NULL || subject_id == NULL
      || out_state == NULL || out_count == NULL || out_locked_at == NULL
      || threshold <= 0)
    return WYRELOG_E_INVALID;
  *out_state = NULL;
  *out_count = 0;
  *out_locked_at = G_MININT64;
  if (wyl_policy_subject_has_service_prefix (subject_id))
    return WYRELOG_E_POLICY;

  wyrelog_error_t rc = wyl_policy_store_begin_mutation (store);
  if (rc != WYRELOG_E_OK)
    return rc;

  /* Phase 1: load current row inside the savepoint.  If no row exists,
   * we materialise mfa_required with counter=1 below.  If a row exists
   * we increment from the durable counter; the savepoint serialises
   * concurrent failures so we never miss an increment. */
  sqlite3_stmt *sel = NULL;
  rc = prepare_stmt (store->db,
      "SELECT state, failed_attempt_count FROM principal_states "
      "WHERE subject_id = ?;", &sel);
  if (rc != WYRELOG_E_OK)
    goto rollback;
  if ((rc = bind_text (sel, 1, subject_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (sel);
    goto rollback;
  }

  gint64 next_count = 0;
  gboolean already_locked = FALSE;
  int step_rc = sqlite3_step (sel);
  if (step_rc == SQLITE_ROW) {
    const gchar *cur_state = (const gchar *) sqlite3_column_text (sel, 0);
    if (g_strcmp0 (cur_state, "locked") == 0)
      already_locked = TRUE;
    next_count = sqlite3_column_int64 (sel, 1) + 1;
  } else if (step_rc == SQLITE_DONE) {
    next_count = 1;
  } else {
    sqlite3_finalize (sel);
    rc = WYRELOG_E_IO;
    goto rollback;
  }
  sqlite3_finalize (sel);

  /* Defensive: refuse to extend a lockout that is already in place.
   * The validator gates this in production (callers only invoke after
   * observing state=mfa_required), but this helper is library-internal
   * and future callers - notably the wyctl tooling in commit 6 - must
   * not be able to bump locked_at or the counter by repeatedly
   * driving FAILED_ATTEMPT against a LOCKED row.  Return WYRELOG_E_POLICY
   * and roll the savepoint back; no event row is emitted. */
  if (already_locked) {
    rc = WYRELOG_E_POLICY;
    goto rollback;
  }

  /* Phase 2: determine final state.  Once the counter reaches the
   * configured threshold we move the row to LOCKED with locked_at set
   * to the caller-supplied wallclock seconds.  The threshold-cross is
   * a one-way transition until reset_counter or apply_unlock fires.
   *
   * No-row materialises into mfa_required (the validator's gate ensures
   * we never reach this helper from any other principal state), so the
   * from_state is uniform across both the had_row and no-row branches. */
  const gchar *next_state =
      (next_count >= threshold) ? "locked" : "mfa_required";
  gint64 next_locked_at = (next_count >= threshold) ? now_secs : G_MININT64;
  const gchar *from_state = "mfa_required";
  /* FSM-edge validation lives at the auth/validator layer (see
   * wyl_mfa_validator_totp): the storage layer just writes the literal
   * state strings the caller has already validated.  Cross-layer FSM
   * drift surfaces at validator-layer tests, not here. */

  /* Phase 3: write back.  INSERT ... ON CONFLICT UPDATE handles both
   * the materialise-new-row and update-existing-row branches without
   * a separate UPDATE OR INSERT split. */
  sqlite3_stmt *upsert = NULL;
  rc = prepare_stmt (store->db,
      "INSERT INTO principal_states "
      "  (subject_id, state, updated_at, failed_attempt_count, locked_at) "
      "VALUES (?, ?, unixepoch(), ?, ?) "
      "ON CONFLICT(subject_id) DO UPDATE SET "
      "  state = excluded.state, "
      "  updated_at = excluded.updated_at, "
      "  failed_attempt_count = excluded.failed_attempt_count, "
      "  locked_at = excluded.locked_at;", &upsert);
  if (rc != WYRELOG_E_OK)
    goto rollback;
  if ((rc = bind_text (upsert, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (upsert, 2, next_state)) != WYRELOG_E_OK) {
    sqlite3_finalize (upsert);
    goto rollback;
  }
  if (sqlite3_bind_int64 (upsert, 3, next_count) != SQLITE_OK) {
    sqlite3_finalize (upsert);
    rc = WYRELOG_E_IO;
    goto rollback;
  }
  if (next_locked_at == G_MININT64) {
    if (sqlite3_bind_null (upsert, 4) != SQLITE_OK) {
      sqlite3_finalize (upsert);
      rc = WYRELOG_E_IO;
      goto rollback;
    }
  } else {
    if (sqlite3_bind_int64 (upsert, 4, next_locked_at) != SQLITE_OK) {
      sqlite3_finalize (upsert);
      rc = WYRELOG_E_IO;
      goto rollback;
    }
  }
  if (sqlite3_step (upsert) != SQLITE_DONE) {
    sqlite3_finalize (upsert);
    rc = WYRELOG_E_IO;
    goto rollback;
  }
  sqlite3_finalize (upsert);

  /* Phase 4: when we crossed the threshold, append a principal_event
   * row for the lock transition so the audit ledger captures it.  The
   * insert is inside the same savepoint, so the event is durable iff
   * the state change is durable (no torn-state on crash). */
  if (next_count >= threshold) {
    /* Event-name literal "lock" matches wyl_principal_event_name's
     * table entry for WYL_PRINCIPAL_EVENT_LOCK.  Inlined here so the
     * storage layer does not depend on the FSM private header for
     * what is fundamentally a string column write. */
    rc = wyl_policy_store_append_principal_event (store, subject_id,
        "lock", from_state, "locked", NULL);
    if (rc != WYRELOG_E_OK)
      goto rollback;
  }

  rc = wyl_policy_store_commit_mutation (store);
  if (rc != WYRELOG_E_OK)
    goto rollback;

  *out_state = g_strdup (next_state);
  *out_count = next_count;
  *out_locked_at = next_locked_at;
  return WYRELOG_E_OK;

rollback:
  wyl_policy_store_rollback_mutation (store);
  g_clear_pointer (out_state, g_free);
  *out_count = 0;
  *out_locked_at = G_MININT64;
  return rc;
}

wyrelog_error_t
wyl_policy_store_reset_principal_failure_counter (wyl_policy_store_t *store,
    const gchar *subject_id)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_policy_subject_has_service_prefix (subject_id))
    return WYRELOG_E_POLICY;

  /* Reset is a no-op when the row does not exist (the validator only
   * reaches this branch after a successful TOTP match, and the verify
   * path always materialises a row earlier via wyl-session.c on
   * login_ok).  An UPDATE with no matching row returns SQLITE_DONE
   * cleanly. */
  static const gchar *sql =
      "UPDATE principal_states SET "
      "  failed_attempt_count = 0, "
      "  locked_at = NULL, "
      "  updated_at = unixepoch() " "WHERE subject_id = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }
  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

/* Atomic LOCKED -> UNVERIFIED transition.  The state transition and
 * principal_event row both land inside the same savepoint so a crash
 * mid-update cannot leave the row half-unlocked. */
wyrelog_error_t
wyl_policy_store_apply_principal_unlock (wyl_policy_store_t *store,
    const gchar *subject_id)
{
  if (store == NULL || store->db == NULL || subject_id == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_policy_subject_has_service_prefix (subject_id))
    return WYRELOG_E_POLICY;

  /* FSM-edge validation is the auth/validator layer's responsibility
   * (see wyl_mfa_validator_totp / maybe_auto_unlock).  This helper just
   * writes the LOCKED -> UNVERIFIED literal-state transition the caller
   * has already validated.  Keeping the FSM-step call out of storage
   * preserves the layering rule: storage knows the string columns, the
   * FSM table belongs to auth. */
  wyrelog_error_t rc = wyl_policy_store_begin_mutation (store);
  if (rc != WYRELOG_E_OK)
    return rc;

  sqlite3_stmt *upd = NULL;
  rc = prepare_stmt (store->db,
      "UPDATE principal_states SET "
      "  state = 'unverified', "
      "  failed_attempt_count = 0, "
      "  locked_at = NULL, "
      "  updated_at = unixepoch() " "WHERE subject_id = ?;", &upd);
  if (rc != WYRELOG_E_OK)
    goto rollback;
  if ((rc = bind_text (upd, 1, subject_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (upd);
    goto rollback;
  }
  if (sqlite3_step (upd) != SQLITE_DONE) {
    sqlite3_finalize (upd);
    rc = WYRELOG_E_IO;
    goto rollback;
  }
  sqlite3_finalize (upd);

  /* Event-name literal "unlock" matches wyl_principal_event_name's
   * table entry for WYL_PRINCIPAL_EVENT_UNLOCK.  Inlined here so the
   * storage layer does not pull in the FSM private header solely for
   * a string column write. */
  rc = wyl_policy_store_append_principal_event (store, subject_id,
      "unlock", "locked", "unverified", NULL);
  if (rc != WYRELOG_E_OK)
    goto rollback;

  return wyl_policy_store_commit_mutation (store);

rollback:
  wyl_policy_store_rollback_mutation (store);
  return rc;
}

wyrelog_error_t
wyl_policy_store_append_principal_event (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *event, const gchar *from_state,
    const gchar *to_state, gint64 *out_event_id)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || event == NULL || from_state == NULL || to_state == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_policy_subject_has_service_prefix (subject_id))
    return WYRELOG_E_POLICY;

  static const gchar *sql =
      "INSERT INTO principal_events "
      "  (subject_id, event, from_state, to_state, created_at) "
      "VALUES (?, ?, ?, ?, unixepoch());";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, event)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, from_state)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 4, to_state)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  if (step_rc != SQLITE_DONE)
    return WYRELOG_E_IO;
  if (out_event_id != NULL) {
    sqlite3_int64 event_id = sqlite3_last_insert_rowid (store->db);
    if (event_id <= 0)
      return WYRELOG_E_IO;
    *out_event_id = event_id;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_foreach_principal_event (wyl_policy_store_t *store,
    wyl_policy_principal_event_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT event_id, subject_id, event, from_state, to_state "
      "FROM principal_events ORDER BY event_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    gint64 event_id = sqlite3_column_int64 (stmt, 0);
    const gchar *subject_id = (const gchar *) sqlite3_column_text (stmt, 1);
    const gchar *event = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *from_state = (const gchar *) sqlite3_column_text (stmt, 3);
    const gchar *to_state = (const gchar *) sqlite3_column_text (stmt, 4);
    if (event_id <= 0) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_POLICY;
    }
    rc = cb (event_id, subject_id, event, from_state, to_state, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_set_session_state (wyl_policy_store_t *store,
    const gchar *session_id, const gchar *state)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || session_id == NULL || state == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_policy_subject_has_service_prefix (session_id))
    return WYRELOG_E_POLICY;

  static const gchar *sql =
      "INSERT INTO session_states (session_id, state, updated_at) "
      "VALUES (?, ?, unixepoch()) "
      "ON CONFLICT(session_id) DO UPDATE SET "
      "  state = excluded.state," "  updated_at = excluded.updated_at;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, session_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, state)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_foreach_session_state (wyl_policy_store_t *store,
    wyl_policy_session_state_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT session_id, state FROM session_states " "ORDER BY session_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *session_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *state = (const gchar *) sqlite3_column_text (stmt, 1);
    rc = cb (session_id, state, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_append_session_event (wyl_policy_store_t *store,
    const gchar *session_id, const gchar *event, const gchar *from_state,
    const gchar *to_state, gint64 *out_event_id)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || session_id == NULL
      || event == NULL || from_state == NULL || to_state == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_policy_subject_has_service_prefix (session_id))
    return WYRELOG_E_POLICY;

  static const gchar *sql =
      "INSERT INTO session_events "
      "  (session_id, event, from_state, to_state, created_at) "
      "VALUES (?, ?, ?, ?, unixepoch());";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, session_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, event)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, from_state)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 4, to_state)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  if (step_rc != SQLITE_DONE)
    return WYRELOG_E_IO;
  if (out_event_id != NULL) {
    sqlite3_int64 event_id = sqlite3_last_insert_rowid (store->db);
    if (event_id <= 0)
      return WYRELOG_E_IO;
    *out_event_id = event_id;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_foreach_session_event (wyl_policy_store_t *store,
    wyl_policy_session_event_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT event_id, session_id, event, from_state, to_state "
      "FROM session_events ORDER BY event_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    gint64 event_id = sqlite3_column_int64 (stmt, 0);
    const gchar *session_id = (const gchar *) sqlite3_column_text (stmt, 1);
    const gchar *event = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *from_state = (const gchar *) sqlite3_column_text (stmt, 3);
    const gchar *to_state = (const gchar *) sqlite3_column_text (stmt, 4);
    if (event_id <= 0) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_POLICY;
    }
    rc = cb (event_id, session_id, event, from_state, to_state, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_upsert_permission (wyl_policy_store_t *store,
    const gchar *perm_id, const gchar *perm_name, const gchar *klass)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || perm_id == NULL
      || perm_name == NULL || klass == NULL)
    return WYRELOG_E_INVALID;

  const BuiltinPermission *builtin = find_builtin_permission (perm_id);
  if (builtin != NULL && (g_strcmp0 (perm_name, builtin->name) != 0
          || g_strcmp0 (klass, builtin->klass) != 0))
    return WYRELOG_E_POLICY;
  if (builtin == NULL && is_reserved_catalog_id (perm_id))
    return WYRELOG_E_POLICY;

  static const gchar *sql =
      "INSERT INTO permissions (perm_id, perm_name, class, created_at) "
      "VALUES (?, ?, ?, unixepoch()) "
      "ON CONFLICT(perm_id) DO UPDATE SET "
      "  perm_name = excluded.perm_name," "  class = excluded.class;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, perm_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, perm_name)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, klass)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
catalog_row_exists (wyl_policy_store_t *store, const gchar *table,
    const gchar *column, const gchar *value, gboolean *out_exists)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || table == NULL || column == NULL ||
      value == NULL || out_exists == NULL)
    return WYRELOG_E_INVALID;

  *out_exists = FALSE;
  g_autofree gchar *sql =
      g_strdup_printf ("SELECT 1 FROM %s WHERE %s = ?;", table, column);
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, value)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW)
    *out_exists = TRUE;
  else if (step_rc != SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_role_exists (wyl_policy_store_t *store, const gchar *role_id,
    gboolean *out_exists)
{
  return catalog_row_exists (store, "roles", "role_id", role_id, out_exists);
}

wyrelog_error_t
wyl_policy_store_permission_exists (wyl_policy_store_t *store,
    const gchar *perm_id, gboolean *out_exists)
{
  return catalog_row_exists (store, "permissions", "perm_id", perm_id,
      out_exists);
}

wyrelog_error_t
wyl_policy_store_grant_role_permission (wyl_policy_store_t *store,
    const gchar *role_id, const gchar *perm_id)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || role_id == NULL || perm_id == NULL)
    return WYRELOG_E_INVALID;

  wyl_permission_plane_t plane = WYL_PERMISSION_PLANE_CONTROL;
  wyrelog_error_t rc = wyl_policy_store_permission_plane (store, perm_id,
      &plane);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (plane == WYL_PERMISSION_PLANE_CONTROL) {
    gboolean has_service_members = FALSE;
    rc = role_has_service_principal_descendants (store, role_id,
        &has_service_members);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (has_service_members)
      return WYRELOG_E_POLICY;
  }

  static const gchar *sql =
      "INSERT INTO role_permissions (role_id, perm_id, granted_at) "
      "VALUES (?, ?, unixepoch()) "
      "ON CONFLICT(role_id, perm_id) DO UPDATE SET "
      "  granted_at = excluded.granted_at;";
  rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, role_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, perm_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_foreach_role_permission (wyl_policy_store_t *store,
    wyl_policy_role_permission_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "WITH RECURSIVE effective_role_permissions(role_id, perm_id) AS ("
      "  SELECT role_id, perm_id FROM role_permissions"
      "  UNION "
      "  SELECT ri.child_role_id, erp.perm_id "
      "  FROM role_inheritances ri "
      "  JOIN effective_role_permissions erp "
      "    ON erp.role_id = ri.parent_role_id"
      ") "
      "SELECT role_id, perm_id FROM effective_role_permissions "
      "ORDER BY role_id, perm_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *role_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *perm_id = (const gchar *) sqlite3_column_text (stmt, 1);
    rc = cb (role_id, perm_id, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_grant_role_inheritance (wyl_policy_store_t *store,
    const gchar *child_role_id, const gchar *parent_role_id)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || child_role_id == NULL
      || parent_role_id == NULL)
    return WYRELOG_E_INVALID;

  gboolean child_has_service_members = FALSE;
  wyrelog_error_t rc = role_has_service_principal_descendants (store,
      child_role_id, &child_has_service_members);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (child_has_service_members) {
    gboolean parent_is_eligible = FALSE;
    rc = wyl_policy_store_role_is_service_eligible (store, parent_role_id,
        &parent_is_eligible);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (!parent_is_eligible)
      return WYRELOG_E_POLICY;
  }

  static const gchar *sql =
      "INSERT INTO role_inheritances "
      "  (child_role_id, parent_role_id, granted_at) "
      "VALUES (?, ?, unixepoch()) "
      "ON CONFLICT(child_role_id, parent_role_id) DO UPDATE SET "
      "  granted_at = excluded.granted_at;";
  rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, child_role_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, parent_role_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_foreach_role_inheritance (wyl_policy_store_t *store,
    wyl_policy_role_inheritance_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT child_role_id, parent_role_id FROM role_inheritances "
      "ORDER BY child_role_id, parent_role_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *child_role_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *parent_role_id = (const gchar *) sqlite3_column_text (stmt, 1);
    rc = cb (child_role_id, parent_role_id, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_grant_role_membership (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *role_id, const gchar *scope)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || role_id == NULL || scope == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = service_authorization_subject_check (store,
      subject_id, FALSE);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (wyl_policy_subject_has_service_prefix (subject_id)) {
    gboolean eligible = FALSE;
    rc = wyl_policy_store_role_is_service_eligible (store, role_id, &eligible);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (!eligible)
      return WYRELOG_E_POLICY;
  }

  static const gchar *sql =
      "INSERT INTO role_memberships "
      "  (subject_id, role_id, scope, granted_at) "
      "VALUES (?, ?, ?, unixepoch()) "
      "ON CONFLICT(subject_id, role_id, scope) DO UPDATE SET "
      "  granted_at = excluded.granted_at;";
  rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, role_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_revoke_role_membership (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *role_id, const gchar *scope)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || role_id == NULL || scope == NULL)
    return WYRELOG_E_INVALID;

  /* Keep legacy namespace collisions remediable while grants remain guarded. */

  static const gchar *sql =
      "DELETE FROM role_memberships "
      "WHERE subject_id = ? AND role_id = ? AND scope = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, role_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
    wyl_policy_store_apply_role_membership_mutation_with_audit
    (wyl_policy_store_t * store, const gchar * subject_id,
    const gchar * role_id, const gchar * scope, gboolean insert,
    const gchar * audit_id, gint64 audit_created_at_us,
    const gchar * audit_subject_id, const gchar * audit_action,
    const gchar * audit_resource_id, const gchar * audit_deny_reason,
    const gchar * audit_deny_origin, const gchar * audit_request_id,
    wyl_decision_t audit_decision)
{
  if (store == NULL || store->db == NULL || subject_id == NULL
      || role_id == NULL || scope == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = wyl_policy_store_begin_mutation (store);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = insert
      ? wyl_policy_store_grant_role_membership (store, subject_id, role_id,
      scope)
      : wyl_policy_store_revoke_role_membership (store, subject_id, role_id,
      scope);
  if (rc == WYRELOG_E_OK) {
    rc = wyl_policy_store_append_role_membership_event (store, subject_id,
        role_id, scope, insert ? "grant" : "revoke");
  }
  if (rc == WYRELOG_E_OK && audit_id != NULL) {
    gboolean inserted = FALSE;
    rc = wyl_policy_store_append_audit_event_full (store, audit_id,
        audit_created_at_us, audit_subject_id, audit_action,
        audit_resource_id, audit_deny_reason, audit_deny_origin,
        audit_request_id, audit_decision, &inserted);
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_validate_snapshot (store);
  if (rc != WYRELOG_E_OK) {
    wyl_policy_store_rollback_mutation (store);
    return rc;
  }

  rc = wyl_policy_store_commit_mutation (store);
  if (rc != WYRELOG_E_OK) {
    wyl_policy_store_rollback_mutation (store);
    return rc;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_apply_role_membership_mutation (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *role_id, const gchar *scope,
    gboolean insert)
{
  return wyl_policy_store_apply_role_membership_mutation_with_audit (store,
      subject_id, role_id, scope, insert, NULL, 0, NULL, NULL, NULL, NULL, NULL,
      NULL, WYL_DECISION_DENY);
}

wyrelog_error_t
wyl_policy_store_role_membership_exists (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *role_id, const gchar *scope,
    gboolean *out_exists)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || role_id == NULL || scope == NULL || out_exists == NULL)
    return WYRELOG_E_INVALID;

  *out_exists = FALSE;
  static const gchar *sql =
      "SELECT 1 FROM role_memberships "
      "WHERE subject_id = ? AND role_id = ? AND scope = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, role_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW)
    *out_exists = TRUE;
  else if (step_rc != SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_foreach_role_membership (wyl_policy_store_t *store,
    wyl_policy_role_membership_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT subject_id, role_id, scope FROM role_memberships "
      "ORDER BY subject_id, role_id, scope;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *subject_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *role_id = (const gchar *) sqlite3_column_text (stmt, 1);
    const gchar *scope = (const gchar *) sqlite3_column_text (stmt, 2);
    rc = cb (subject_id, role_id, scope, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_append_role_membership_event (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *role_id, const gchar *scope,
    const gchar *operation)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || role_id == NULL || scope == NULL || operation == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = WYRELOG_E_OK;
  /* Repair revocations must be able to append their matching event. */
  if (!g_str_equal (operation, "revoke")) {
    rc = service_authorization_subject_check (store, subject_id, FALSE);
    if (rc != WYRELOG_E_OK)
      return rc;
  }

  static const gchar *sql =
      "INSERT INTO role_membership_events "
      "  (subject_id, role_id, scope, operation, created_at) "
      "VALUES (?, ?, ?, ?, unixepoch());";
  rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, role_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 4, operation)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_foreach_role_membership_event (wyl_policy_store_t *store,
    wyl_policy_role_membership_event_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT subject_id, role_id, scope, operation "
      "FROM role_membership_events ORDER BY event_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *subject_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *role_id = (const gchar *) sqlite3_column_text (stmt, 1);
    const gchar *scope = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *operation = (const gchar *) sqlite3_column_text (stmt, 3);
    rc = cb (subject_id, role_id, scope, operation, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_append_audit_event_full (wyl_policy_store_t *store,
    const gchar *id, gint64 created_at_us, const gchar *subject_id,
    const gchar *action, const gchar *resource_id, const gchar *deny_reason,
    const gchar *deny_origin, const gchar *request_id,
    wyl_decision_t decision, gboolean *out_inserted)
{
  sqlite3_stmt *stmt = NULL;
  wyl_id_t parsed_id;

  if (store == NULL || store->db == NULL || id == NULL || created_at_us < 0
      || out_inserted == NULL)
    return WYRELOG_E_INVALID;
  *out_inserted = FALSE;
  if (wyl_id_parse (id, &parsed_id) != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  if (decision != WYL_DECISION_DENY && decision != WYL_DECISION_ALLOW)
    return WYRELOG_E_INVALID;

  static const gchar *select_sql =
      "SELECT created_at_us, subject_id, action, resource_id, "
      "deny_reason, deny_origin, request_id, decision "
      "FROM audit_events WHERE id = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, select_sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int select_rc = sqlite3_step (stmt);
  if (select_rc == SQLITE_ROW) {
    gboolean equal =
        sqlite3_column_int64 (stmt, 0) == created_at_us
        && column_nullable_text_equal (stmt, 1, subject_id)
        && column_nullable_text_equal (stmt, 2, action)
        && column_nullable_text_equal (stmt, 3, resource_id)
        && column_nullable_text_equal (stmt, 4, deny_reason)
        && column_nullable_text_equal (stmt, 5, deny_origin)
        && column_nullable_text_equal (stmt, 6, request_id)
        && sqlite3_column_int (stmt, 7) == (int) decision;
    sqlite3_finalize (stmt);
    return equal ? WYRELOG_E_OK : WYRELOG_E_POLICY;
  }
  sqlite3_finalize (stmt);
  stmt = NULL;
  if (select_rc != SQLITE_DONE)
    return WYRELOG_E_IO;

  static const gchar *sql =
      "INSERT INTO audit_events "
      "  (id, created_at_us, subject_id, action, resource_id, "
      "   deny_reason, deny_origin, request_id, decision) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";
  rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, id)) != WYRELOG_E_OK
      || sqlite3_bind_int64 (stmt, 2, created_at_us) != SQLITE_OK
      || (rc = bind_nullable_text (stmt, 3, subject_id)) != WYRELOG_E_OK
      || (rc = bind_nullable_text (stmt, 4, action)) != WYRELOG_E_OK
      || (rc = bind_nullable_text (stmt, 5, resource_id)) != WYRELOG_E_OK
      || (rc = bind_nullable_text (stmt, 6, deny_reason)) != WYRELOG_E_OK
      || (rc = bind_nullable_text (stmt, 7, deny_origin)) != WYRELOG_E_OK
      || (rc = bind_nullable_text (stmt, 8, request_id)) != WYRELOG_E_OK
      || sqlite3_bind_int (stmt, 9, (int) decision) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  if (step_rc != SQLITE_DONE)
    return WYRELOG_E_IO;
  *out_inserted = TRUE;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_append_audit_event (wyl_policy_store_t *store,
    const gchar *id, gint64 created_at_us, const gchar *subject_id,
    const gchar *action, const gchar *resource_id, const gchar *deny_reason,
    const gchar *deny_origin, wyl_decision_t decision)
{
  gboolean inserted = FALSE;

  return wyl_policy_store_append_audit_event_full (store, id, created_at_us,
      subject_id, action, resource_id, deny_reason, deny_origin, NULL, decision,
      &inserted);
}

wyrelog_error_t
wyl_policy_store_record_audit_intention_full (wyl_policy_store_t *store,
    const gchar *id, gint64 created_at_us, const gchar *subject_id,
    const gchar *action, const gchar *resource_id, const gchar *deny_reason,
    const gchar *deny_origin, const gchar *request_id,
    wyl_decision_t decision, gboolean *out_inserted)
{
  sqlite3_stmt *stmt = NULL;
  wyl_id_t parsed_id;

  if (store == NULL || store->db == NULL || id == NULL || created_at_us < 0
      || out_inserted == NULL)
    return WYRELOG_E_INVALID;
  *out_inserted = FALSE;
  if (wyl_id_parse (id, &parsed_id) != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  if (decision != WYL_DECISION_DENY && decision != WYL_DECISION_ALLOW)
    return WYRELOG_E_INVALID;

  static const gchar *select_sql =
      "SELECT created_at_us, subject_id, action, resource_id, "
      "deny_reason, deny_origin, request_id, decision "
      "FROM audit_intentions WHERE audit_id = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, select_sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int select_rc = sqlite3_step (stmt);
  if (select_rc == SQLITE_ROW) {
    gboolean equal =
        sqlite3_column_int64 (stmt, 0) == created_at_us
        && column_nullable_text_equal (stmt, 1, subject_id)
        && column_nullable_text_equal (stmt, 2, action)
        && column_nullable_text_equal (stmt, 3, resource_id)
        && column_nullable_text_equal (stmt, 4, deny_reason)
        && column_nullable_text_equal (stmt, 5, deny_origin)
        && column_nullable_text_equal (stmt, 6, request_id)
        && sqlite3_column_int (stmt, 7) == (int) decision;
    sqlite3_finalize (stmt);
    return equal ? WYRELOG_E_OK : WYRELOG_E_POLICY;
  }
  sqlite3_finalize (stmt);
  stmt = NULL;
  if (select_rc != SQLITE_DONE)
    return WYRELOG_E_IO;

  static const gchar *sql =
      "INSERT INTO audit_intentions "
      "  (audit_id, created_at_us, subject_id, action, resource_id, "
      "   deny_reason, deny_origin, request_id, decision, state, "
      "   created_at, updated_at) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', unixepoch(), unixepoch());";
  rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, id)) != WYRELOG_E_OK
      || sqlite3_bind_int64 (stmt, 2, created_at_us) != SQLITE_OK
      || (rc = bind_nullable_text (stmt, 3, subject_id)) != WYRELOG_E_OK
      || (rc = bind_nullable_text (stmt, 4, action)) != WYRELOG_E_OK
      || (rc = bind_nullable_text (stmt, 5, resource_id)) != WYRELOG_E_OK
      || (rc = bind_nullable_text (stmt, 6, deny_reason)) != WYRELOG_E_OK
      || (rc = bind_nullable_text (stmt, 7, deny_origin)) != WYRELOG_E_OK
      || (rc = bind_nullable_text (stmt, 8, request_id)) != WYRELOG_E_OK
      || sqlite3_bind_int (stmt, 9, (int) decision) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  if (step_rc != SQLITE_DONE)
    return WYRELOG_E_IO;
  *out_inserted = TRUE;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
mark_audit_intention_state (wyl_policy_store_t *store, const gchar *id,
    const gchar *state, const gchar *last_error)
{
  sqlite3_stmt *stmt = NULL;
  wyl_id_t parsed_id;

  if (store == NULL || store->db == NULL || id == NULL
      || !is_valid_audit_intention_state (state))
    return WYRELOG_E_INVALID;
  if (g_strcmp0 (state, "failed") == 0 && last_error == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_id_parse (id, &parsed_id) != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "UPDATE audit_intentions "
      "SET state = ?, updated_at = unixepoch(), "
      "    attempt_count = attempt_count + ?, last_error = ? "
      "WHERE audit_id = ? AND (state != 'committed' OR ? = 'committed');";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, state)) != WYRELOG_E_OK
      || sqlite3_bind_int (stmt, 2,
          g_strcmp0 (state, "failed") == 0 ? 1 : 0) != SQLITE_OK
      || (rc = bind_nullable_text (stmt, 3, last_error)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 4, id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 5, state)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  if (step_rc != SQLITE_DONE)
    return WYRELOG_E_IO;
  return sqlite3_changes (store->db) == 1 ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_policy_store_mark_audit_intention_committed (wyl_policy_store_t *store,
    const gchar *id)
{
  return mark_audit_intention_state (store, id, "committed", NULL);
}

wyrelog_error_t
wyl_policy_store_mark_audit_intention_failed (wyl_policy_store_t *store,
    const gchar *id, const gchar *last_error)
{
  return mark_audit_intention_state (store, id, "failed", last_error);
}

wyrelog_error_t
wyl_policy_store_foreach_audit_intention (wyl_policy_store_t *store,
    const gchar *state, wyl_policy_audit_intention_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;
  if (state != NULL && !is_valid_audit_intention_state (state))
    return WYRELOG_E_INVALID;

  static const gchar *all_sql =
      "SELECT audit_id, created_at_us, subject_id, action, resource_id, "
      "deny_reason, deny_origin, request_id, decision, state, "
      "attempt_count, last_error "
      "FROM audit_intentions ORDER BY created_at_us ASC, audit_id ASC;";
  static const gchar *state_sql =
      "SELECT audit_id, created_at_us, subject_id, action, resource_id, "
      "deny_reason, deny_origin, request_id, decision, state, "
      "attempt_count, last_error "
      "FROM audit_intentions WHERE state = ? "
      "ORDER BY created_at_us ASC, audit_id ASC;";
  wyrelog_error_t rc = prepare_stmt (store->db,
      state == NULL ? all_sql : state_sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (state != NULL && (rc = bind_text (stmt, 1, state)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *id = (const gchar *) sqlite3_column_text (stmt, 0);
    gint64 created_at_us = sqlite3_column_int64 (stmt, 1);
    const gchar *subject_id = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *action = (const gchar *) sqlite3_column_text (stmt, 3);
    const gchar *resource_id = (const gchar *) sqlite3_column_text (stmt, 4);
    const gchar *deny_reason = (const gchar *) sqlite3_column_text (stmt, 5);
    const gchar *deny_origin = (const gchar *) sqlite3_column_text (stmt, 6);
    const gchar *request_id = (const gchar *) sqlite3_column_text (stmt, 7);
    int decision = sqlite3_column_int (stmt, 8);
    const gchar *row_state = (const gchar *) sqlite3_column_text (stmt, 9);
    gint64 attempt_count = sqlite3_column_int64 (stmt, 10);
    const gchar *last_error = (const gchar *) sqlite3_column_text (stmt, 11);
    wyl_id_t parsed_id;

    if (id == NULL || wyl_id_parse (id, &parsed_id) != WYRELOG_E_OK
        || created_at_us < 0 || (decision != WYL_DECISION_DENY
            && decision != WYL_DECISION_ALLOW)
        || !is_valid_audit_intention_state (row_state)
        || attempt_count < 0) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_POLICY;
    }
    rc = cb (id, created_at_us, subject_id, action, resource_id, deny_reason,
        deny_origin, request_id, (wyl_decision_t) decision, row_state,
        attempt_count, last_error, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_delete_audit_event (wyl_policy_store_t *store, const gchar *id)
{
  sqlite3_stmt *stmt = NULL;
  wyl_id_t parsed_id;

  if (store == NULL || store->db == NULL || id == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_id_parse (id, &parsed_id) != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;

  static const gchar *sql = "DELETE FROM audit_events WHERE id = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_foreach_audit_event (wyl_policy_store_t *store,
    wyl_policy_audit_event_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT id, created_at_us, subject_id, action, resource_id, "
      "deny_reason, deny_origin, request_id, decision "
      "FROM audit_events ORDER BY created_at_us ASC, id ASC;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *id = (const gchar *) sqlite3_column_text (stmt, 0);
    gint64 created_at_us = sqlite3_column_int64 (stmt, 1);
    const gchar *subject_id = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *action = (const gchar *) sqlite3_column_text (stmt, 3);
    const gchar *resource_id = (const gchar *) sqlite3_column_text (stmt, 4);
    const gchar *deny_reason = (const gchar *) sqlite3_column_text (stmt, 5);
    const gchar *deny_origin = (const gchar *) sqlite3_column_text (stmt, 6);
    const gchar *request_id = (const gchar *) sqlite3_column_text (stmt, 7);
    int decision = sqlite3_column_int (stmt, 8);
    wyl_id_t parsed_id;

    if (id == NULL || wyl_id_parse (id, &parsed_id) != WYRELOG_E_OK
        || created_at_us < 0 || (decision != WYL_DECISION_DENY
            && decision != WYL_DECISION_ALLOW)) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_POLICY;
    }
    rc = cb (id, created_at_us, subject_id, action, resource_id, deny_reason,
        deny_origin, request_id, (wyl_decision_t) decision, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

/* Reads a single value from wyrelog_config. *out_value is set to NULL
 * if the row does not exist; otherwise to a g_strdup'd copy the caller
 * must free. */
static wyrelog_error_t
read_config_row (wyl_policy_store_t *store, const gchar *key, gchar **out_value)
{
  sqlite3_stmt *stmt = NULL;

  *out_value = NULL;
  static const gchar *sql =
      "SELECT config_value FROM wyrelog_config WHERE config_key = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, key)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW) {
    const gchar *value = (const gchar *) sqlite3_column_text (stmt, 0);
    *out_value = g_strdup (value);
  } else if (step_rc != SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_get_bootstrap_admin (wyl_policy_store_t *store,
    gchar **out_subject, gint64 *out_sealed_at_us)
{
  if (store == NULL || store->db == NULL || out_subject == NULL
      || out_sealed_at_us == NULL)
    return WYRELOG_E_INVALID;

  *out_subject = NULL;
  *out_sealed_at_us = 0;

  g_autofree gchar *subject = NULL;
  wyrelog_error_t rc = read_config_row (store, "bootstrap_admin_subject",
      &subject);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (subject == NULL)
    return WYRELOG_E_OK;

  g_autofree gchar *sealed_at_us_text = NULL;
  rc = read_config_row (store, "bootstrap_admin_sealed_at_us",
      &sealed_at_us_text);
  if (rc != WYRELOG_E_OK)
    return rc;

  gint64 sealed_at_us = 0;
  if (sealed_at_us_text != NULL) {
    gchar *endptr = NULL;
    sealed_at_us = g_ascii_strtoll (sealed_at_us_text, &endptr, 10);
    if (endptr == sealed_at_us_text || (endptr != NULL && *endptr != '\0'))
      return WYRELOG_E_POLICY;
  }

  *out_subject = g_steal_pointer (&subject);
  *out_sealed_at_us = sealed_at_us;
  return WYRELOG_E_OK;
}

/* Counts rows matching a single static SQL query. The caller is
 * responsible for ensuring the query returns exactly one COUNT(*)
 * column. */
static wyrelog_error_t
count_static_query (sqlite3 *db, const gchar *sql, gint64 *out_count)
{
  sqlite3_stmt *stmt = NULL;

  *out_count = 0;
  wyrelog_error_t rc = prepare_stmt (db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc = sqlite3_step (stmt);
  if (step_rc != SQLITE_ROW) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  *out_count = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_bootstrap_admin_eligible (wyl_policy_store_t *store,
    gboolean *out_eligible)
{
  if (store == NULL || store->db == NULL || out_eligible == NULL)
    return WYRELOG_E_INVALID;
  *out_eligible = FALSE;

  gint64 marker_count = 0;
  wyrelog_error_t rc = count_static_query (store->db,
      "SELECT COUNT(*) FROM wyrelog_config "
      "WHERE config_key = 'bootstrap_admin_subject';",
      &marker_count);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (marker_count > 0)
    return WYRELOG_E_OK;

  gint64 admin_member_count = 0;
  rc = count_static_query (store->db,
      "SELECT COUNT(*) FROM role_memberships "
      "WHERE role_id = 'wr.system_admin';", &admin_member_count);
  if (rc != WYRELOG_E_OK)
    return rc;

  *out_eligible = (admin_member_count == 0);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_apply_bootstrap_admin (wyl_policy_store_t *store,
    const gchar *subject_id, gboolean allow_login_skip_mfa,
    gboolean *out_applied, gchar **out_existing_subject)
{
  if (store == NULL || store->db == NULL || out_applied == NULL
      || out_existing_subject == NULL)
    return WYRELOG_E_INVALID;
  *out_applied = FALSE;
  *out_existing_subject = NULL;

  if (wyl_policy_subject_has_service_prefix (subject_id))
    return WYRELOG_E_POLICY;
  if (!bootstrap_admin_subject_is_valid (subject_id))
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = exec_sql (store->db, "BEGIN IMMEDIATE;");
  if (rc != WYRELOG_E_OK)
    return rc;

  /* Race-safe second read: any concurrent daemon that took the
   * IMMEDIATE lock first will have already written the marker by the
   * time we get here. */
  g_autofree gchar *existing = NULL;
  rc = read_config_row (store, "bootstrap_admin_subject", &existing);
  if (rc != WYRELOG_E_OK) {
    (void) exec_sql (store->db, "ROLLBACK;");
    return rc;
  }

  if (existing != NULL) {
    /* 'legacy-skip' sentinel: refuse any subject. */
    if (g_strcmp0 (existing, "legacy-skip") == 0) {
      *out_existing_subject = g_steal_pointer (&existing);
      (void) exec_sql (store->db, "ROLLBACK;");
      return WYRELOG_E_POLICY;
    }
    if (g_strcmp0 (existing, subject_id) == 0) {
      /* Idempotent same-subject reapply: no writes. */
      (void) exec_sql (store->db, "ROLLBACK;");
      return WYRELOG_E_OK;
    }
    *out_existing_subject = g_steal_pointer (&existing);
    (void) exec_sql (store->db, "ROLLBACK;");
    return WYRELOG_E_POLICY;
  }

  gint64 admin_member_count = 0;
  rc = count_static_query (store->db,
      "SELECT COUNT(*) FROM role_memberships "
      "WHERE role_id = 'wr.system_admin';", &admin_member_count);
  if (rc != WYRELOG_E_OK) {
    (void) exec_sql (store->db, "ROLLBACK;");
    return rc;
  }
  if (admin_member_count > 0) {
    /* No marker but an admin already exists: refuse rather than mint
     * a second one. This is the same shape as the create_schema
     * legacy-skip migration but caught here for callers that bypass
     * create_schema between operations. */
    (void) exec_sql (store->db, "ROLLBACK;");
    return WYRELOG_E_POLICY;
  }

  /* Insert the marker FIRST and use NOT EXISTS so the race is closed
   * by SQL: a concurrent transaction that already inserted the marker
   * leaves this INSERT a no-op. */
  sqlite3_stmt *stmt = NULL;
  static const gchar *insert_subject_sql =
      "INSERT INTO wyrelog_config (config_key, config_value, updated_at) "
      "SELECT 'bootstrap_admin_subject', ?, unixepoch() "
      "WHERE NOT EXISTS ("
      "  SELECT 1 FROM wyrelog_config "
      "  WHERE config_key = 'bootstrap_admin_subject');";
  rc = prepare_stmt (store->db, insert_subject_sql, &stmt);
  if (rc != WYRELOG_E_OK) {
    (void) exec_sql (store->db, "ROLLBACK;");
    return rc;
  }
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    (void) exec_sql (store->db, "ROLLBACK;");
    return rc;
  }
  if (sqlite3_step (stmt) != SQLITE_DONE) {
    sqlite3_finalize (stmt);
    (void) exec_sql (store->db, "ROLLBACK;");
    return WYRELOG_E_IO;
  }
  int subject_changes = sqlite3_changes (store->db);
  sqlite3_finalize (stmt);

  if (subject_changes == 0) {
    /* A concurrent transaction beat us to the insert. Re-read and
     * decide between idempotent OK and mismatch. */
    g_autofree gchar *winner = NULL;
    rc = read_config_row (store, "bootstrap_admin_subject", &winner);
    if (rc != WYRELOG_E_OK) {
      (void) exec_sql (store->db, "ROLLBACK;");
      return rc;
    }
    (void) exec_sql (store->db, "ROLLBACK;");
    if (winner == NULL)
      return WYRELOG_E_INTERNAL;
    if (g_strcmp0 (winner, subject_id) == 0)
      return WYRELOG_E_OK;
    *out_existing_subject = g_steal_pointer (&winner);
    return WYRELOG_E_POLICY;
  }

  gint64 sealed_at_us = g_get_real_time ();
  g_autofree gchar *sealed_at_us_text =
      g_strdup_printf ("%" G_GINT64_FORMAT, sealed_at_us);
  static const gchar *insert_sealed_at_sql =
      "INSERT INTO wyrelog_config (config_key, config_value, updated_at) "
      "VALUES ('bootstrap_admin_sealed_at_us', ?, unixepoch());";
  rc = prepare_stmt (store->db, insert_sealed_at_sql, &stmt);
  if (rc != WYRELOG_E_OK) {
    (void) exec_sql (store->db, "ROLLBACK;");
    return rc;
  }
  if ((rc = bind_text (stmt, 1, sealed_at_us_text)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    (void) exec_sql (store->db, "ROLLBACK;");
    return rc;
  }
  if (sqlite3_step (stmt) != SQLITE_DONE) {
    sqlite3_finalize (stmt);
    (void) exec_sql (store->db, "ROLLBACK;");
    return WYRELOG_E_IO;
  }
  sqlite3_finalize (stmt);

  static const gchar *insert_allow_sql =
      "INSERT INTO wyrelog_config (config_key, config_value, updated_at) "
      "VALUES ('bootstrap_admin_allow_skip_mfa', ?, unixepoch());";
  rc = prepare_stmt (store->db, insert_allow_sql, &stmt);
  if (rc != WYRELOG_E_OK) {
    (void) exec_sql (store->db, "ROLLBACK;");
    return rc;
  }
  if ((rc = bind_text (stmt, 1, allow_login_skip_mfa ? "1" : "0"))
      != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    (void) exec_sql (store->db, "ROLLBACK;");
    return rc;
  }
  if (sqlite3_step (stmt) != SQLITE_DONE) {
    sqlite3_finalize (stmt);
    (void) exec_sql (store->db, "ROLLBACK;");
    return WYRELOG_E_IO;
  }
  sqlite3_finalize (stmt);

  rc = wyl_policy_store_grant_role_membership (store, subject_id,
      "wr.system_admin", WYL_TENANT_DEFAULT);
  if (rc != WYRELOG_E_OK) {
    (void) exec_sql (store->db, "ROLLBACK;");
    return rc;
  }
  rc = wyl_policy_store_append_role_membership_event (store, subject_id,
      "wr.system_admin", WYL_TENANT_DEFAULT, "grant");
  if (rc != WYRELOG_E_OK) {
    (void) exec_sql (store->db, "ROLLBACK;");
    return rc;
  }
  rc = wyl_policy_store_set_session_state (store, WYL_TENANT_DEFAULT, "active");
  if (rc != WYRELOG_E_OK) {
    (void) exec_sql (store->db, "ROLLBACK;");
    return rc;
  }
  rc = wyl_policy_store_append_session_event (store, WYL_TENANT_DEFAULT,
      "request", "idle", "active", NULL);
  if (rc != WYRELOG_E_OK) {
    (void) exec_sql (store->db, "ROLLBACK;");
    return rc;
  }

  if (allow_login_skip_mfa) {
    rc = wyl_policy_store_grant_direct_permission (store, subject_id,
        "wr.login.skip_mfa", WYL_BOOTSTRAP_LOGIN_SKIP_MFA_SCOPE);
    if (rc != WYRELOG_E_OK) {
      (void) exec_sql (store->db, "ROLLBACK;");
      return rc;
    }
    rc = wyl_policy_store_append_direct_permission_event (store, subject_id,
        "wr.login.skip_mfa", WYL_BOOTSTRAP_LOGIN_SKIP_MFA_SCOPE, "grant");
    if (rc != WYRELOG_E_OK) {
      (void) exec_sql (store->db, "ROLLBACK;");
      return rc;
    }
    rc = wyl_policy_store_set_permission_state (store, subject_id,
        "wr.login.skip_mfa", WYL_BOOTSTRAP_LOGIN_SKIP_MFA_SCOPE, "armed");
    if (rc != WYRELOG_E_OK) {
      (void) exec_sql (store->db, "ROLLBACK;");
      return rc;
    }
    rc = wyl_policy_store_append_permission_state_event (store, subject_id,
        "wr.login.skip_mfa", WYL_BOOTSTRAP_LOGIN_SKIP_MFA_SCOPE, "grant",
        "dormant", "armed", NULL);
    if (rc != WYRELOG_E_OK) {
      (void) exec_sql (store->db, "ROLLBACK;");
      return rc;
    }
  }

  /* Validate the post-grant snapshot before COMMIT so that an SoD
   * conflict (e.g. a pre-existing wr.auditor membership on the
   * bootstrap subject that would collide with the wr.system_admin
   * grant) aborts the transaction here rather than fail-loud at the
   * next engine reload. Matches the pattern used by sibling
   * apply_role_membership_mutation_with_audit and
   * apply_direct_permission_mutation_with_audit. */
  rc = wyl_policy_store_validate_snapshot (store);
  if (rc != WYRELOG_E_OK) {
    (void) exec_sql (store->db, "ROLLBACK;");
    return rc;
  }

  rc = exec_sql (store->db, "COMMIT;");
  if (rc != WYRELOG_E_OK) {
    (void) exec_sql (store->db, "ROLLBACK;");
    return rc;
  }
  *out_applied = TRUE;
  return WYRELOG_E_OK;
}

/* ----------------------------------------------------------------------
 * TOTP enrollment helpers (issue #331).
 *
 * All four helpers operate on the `totp_enrollments` table created in
 * wyl_policy_store_create_schema.  They follow the same pattern as
 * the role-membership helpers above: single-statement INSERT/SELECT/
 * UPDATE/DELETE wrapped in the local prepare_stmt/bind_text/
 * sqlite3_step boilerplate.  None of these helpers emits any log line
 * carrying secret bytes (footgun F2): the only identifiers that may
 * appear in error paths are subject_id and id_uuidv7.  Every error
 * exit that already populated the in-memory secret buffer zeroes it
 * via sodium_memzero before returning (footgun F4).
 * ---------------------------------------------------------------------- */

void
wyl_totp_enrollment_clear (WylTotpEnrollment *enr)
{
  if (enr == NULL)
    return;
  sodium_memzero (enr->secret, sizeof enr->secret);
  g_clear_pointer (&enr->subject_id, g_free);
  g_clear_pointer (&enr->id_uuidv7, g_free);
  enr->last_verified_step = 0;
  enr->enrolled_at = 0;
}

wyrelog_error_t
wyl_policy_store_totp_enrollment_insert (wyl_policy_store_t *store,
    WylTotpEnrollment *enr)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || enr == NULL
      || enr->subject_id == NULL || enr->subject_id[0] == '\0')
    return WYRELOG_E_INVALID;
  if (wyl_policy_subject_has_service_prefix (enr->subject_id))
    return WYRELOG_E_POLICY;

  /* Mint the persistent id_uuidv7 before touching SQLite so an
   * entropy failure does not leave a half-written row.  Discard any
   * caller-supplied value; the helper owns id provenance. */
  wyl_id_t id = WYL_ID_NIL;
  wyrelog_error_t rc = wyl_id_new (&id);
  if (rc != WYRELOG_E_OK)
    return rc;
  gchar id_buf[WYL_ID_STRING_BUF];
  rc = wyl_id_format (&id, id_buf, sizeof id_buf);
  if (rc != WYRELOG_E_OK)
    return rc;

  /* INSERT ... ON CONFLICT(subject_id) DO UPDATE: re-enrolling the
   * same subject overwrites the secret AND resets the watermark and
   * enrolled_at, so the verify path cannot accept a freshly-rotated
   * seed at a step the prior seed had already burned. */
  static const gchar *sql =
      "INSERT INTO totp_enrollments "
      "  (subject_id, secret_blob, last_verified_step, enrolled_at, "
      "   id_uuidv7) "
      "VALUES (?, ?, ?, ?, ?) "
      "ON CONFLICT(subject_id) DO UPDATE SET "
      "  secret_blob = excluded.secret_blob, "
      "  last_verified_step = excluded.last_verified_step, "
      "  enrolled_at = excluded.enrolled_at, "
      "  id_uuidv7 = excluded.id_uuidv7;";
  rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  if ((rc = bind_text (stmt, 1, enr->subject_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }
  /* SQLITE_TRANSIENT makes sqlite copy the bytes immediately so the
   * caller's secret buffer does not need to outlive the bind call. */
  if (sqlite3_bind_blob (stmt, 2, enr->secret, (int) sizeof enr->secret,
          SQLITE_TRANSIENT) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  if (sqlite3_bind_int64 (stmt, 3, enr->last_verified_step) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  if (sqlite3_bind_int64 (stmt, 4, enr->enrolled_at) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  if ((rc = bind_text (stmt, 5, id_buf)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  if (step_rc != SQLITE_DONE)
    return WYRELOG_E_IO;

  /* Publish the minted id back to the caller so the audit emission in
   * commit 3 can reference the row without a follow-up SELECT. */
  g_free (enr->id_uuidv7);
  enr->id_uuidv7 = g_strdup (id_buf);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_totp_enrollment_lookup (wyl_policy_store_t *store,
    const gchar *subject_id, WylTotpEnrollment *out, gboolean *out_found)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL || out == NULL
      || out_found == NULL)
    return WYRELOG_E_INVALID;

  *out_found = FALSE;
  /* The caller hands us a struct of unknown provenance: wipe it to a
   * clean shell so a miss leaves the secret buffer zeroed and the
   * owned-string pointers NULL.  wyl_totp_enrollment_clear is
   * NULL-safe for the strings and unconditionally zeroes the secret
   * (footgun F4). */
  wyl_totp_enrollment_clear (out);
  if (wyl_policy_subject_has_service_prefix (subject_id))
    return WYRELOG_E_POLICY;

  static const gchar *sql =
      "SELECT subject_id, secret_blob, last_verified_step, enrolled_at, "
      "       id_uuidv7 " "FROM totp_enrollments " "WHERE subject_id = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_OK;
  }
  if (step_rc != SQLITE_ROW) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  const gchar *db_subject = (const gchar *) sqlite3_column_text (stmt, 0);
  const void *db_secret = sqlite3_column_blob (stmt, 1);
  int db_secret_len = sqlite3_column_bytes (stmt, 1);
  gint64 db_last = sqlite3_column_int64 (stmt, 2);
  gint64 db_enrolled = sqlite3_column_int64 (stmt, 3);
  const gchar *db_id = (const gchar *) sqlite3_column_text (stmt, 4);

  if (db_secret == NULL || db_secret_len != (int) sizeof out->secret) {
    /* Schema invariant violation: a row exists but the BLOB is the
     * wrong length.  Treat as I/O error rather than silently fall
     * through with a partial seed.  Zero the buffer in case anything
     * copied in already. */
    sodium_memzero (out->secret, sizeof out->secret);
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  out->subject_id = g_strdup (db_subject != NULL ? db_subject : "");
  memcpy (out->secret, db_secret, sizeof out->secret);
  out->last_verified_step = db_last;
  out->enrolled_at = db_enrolled;
  out->id_uuidv7 = g_strdup (db_id != NULL ? db_id : "");

  sqlite3_finalize (stmt);
  *out_found = TRUE;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_totp_enrollment_update_step (wyl_policy_store_t *store,
    const gchar *subject_id, gint64 new_step)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_policy_subject_has_service_prefix (subject_id))
    return WYRELOG_E_POLICY;

  /* The atomic update primitive that commit 3 will compose with the
   * principal-state mutation in an outer transaction, mirroring
   * apply_login_state_mutation in wyl-session.c.  Standalone the
   * statement runs in sqlite's implicit per-statement transaction. */
  static const gchar *sql =
      "UPDATE totp_enrollments SET last_verified_step = ? "
      "WHERE subject_id = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (sqlite3_bind_int64 (stmt, 1, new_step) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  if ((rc = bind_text (stmt, 2, subject_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_totp_enrollment_delete (wyl_policy_store_t *store,
    const gchar *subject_id)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL)
    return WYRELOG_E_INVALID;

  /* Deletion is intentionally allowed for legacy `svc:` enrollment repair;
   * insert, lookup and watermark update remain human-only. */

  static const gchar *sql =
      "DELETE FROM totp_enrollments WHERE subject_id = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

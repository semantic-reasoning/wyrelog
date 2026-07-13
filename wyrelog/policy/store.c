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

#include "wyrelog/wyl-id-private.h"
#include "wyrelog/wyl-common-private.h"
#include "wyrelog/wyl-fsm-permission-scope-private.h"
#include "wyrelog/wyl-log-private.h"
#include "store-lease-private.h"

#define WYL_POLICY_STORE_CLEAR_SUFFIX ".wyrelog-clear"
#define WYL_POLICY_STORE_TMP_SUFFIX ".wyrelog-tmp"

#define WYL_POLICY_STORE_KEY_LEN crypto_secretbox_KEYBYTES
#define WYL_POLICY_STORE_KEY_ID_LEN crypto_generichash_BYTES
#define WYL_POLICY_STORE_ENCRYPTION_LABEL "policy_store_v1"
#define WYL_POLICY_STORE_MAGIC "WYLPS"
#define WYL_POLICY_STORE_MAGIC_LEN 5
#define WYL_POLICY_STORE_FORMAT_VERSION 1

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
};

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
  "service_principal_events",
  "service_credential_events",
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
    " BEGIN SELECT RAISE(ABORT, 'service credential events are append-only'); END;";

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
    gsize len)
{
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
  CloseHandle (h);

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

  (void) g_chmod (path, 0600);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
write_plaintext_work_file (const gchar *path, const guint8 *bytes, gsize len)
{
  return write_whole_file_atomic_private (path, bytes, len);
}
#endif /* G_OS_WIN32 */

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
    gsize len)
{
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

  if (renameat (dirfd, tmp_basename, dirfd, basename) != 0) {
    (void) unlinkat (dirfd, tmp_basename, 0);
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "policy store renameat onto canonical name failed");
    return WYRELOG_E_IO;
  }

  /* Fsync the parent directory so the rename is durable across crash.
   * Without this, the kernel may have flushed the new file inode but
   * not the directory entry rewrite, leaving recovery to either lose
   * the canonical name entirely or retain the tmp name. */
  if (fsync (dirfd) != 0) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "policy store fsync of canonical directory failed");
    return WYRELOG_E_IO;
  }

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
  g_autofree guint8 *plaintext = g_malloc (plaintext_len);
  const guint8 *ciphertext_body =
      ciphertext + sizeof (WylPolicyStoreFileHeader);
  unsigned long long decrypted_len = 0;

  if (crypto_aead_xchacha20poly1305_ietf_decrypt (plaintext, &decrypted_len,
          NULL, ciphertext_body, cipher_len_le,
          (const guint8 *) header, sizeof (WylPolicyStoreFileHeader),
          header->nonce, store->encryption_key) != 0)
    return WYRELOG_E_CRYPTO;
  if (decrypted_len != plaintext_len)
    return WYRELOG_E_CRYPTO;

#ifndef G_OS_WIN32
  /* POSIX builds always have canonical_dirfd set when store->encrypted
   * is true; the open path enforces the invariant. Bail with a clear
   * error if it has been violated by a future refactor rather than
   * fall through to the path-by-name survivor that would re-introduce
   * the TOCTOU surface this commit closes. */
  if (store->canonical_dirfd < 0 || store->work_basename == NULL)
    return WYRELOG_E_INTERNAL;
  return write_plaintext_work_through_dirfd (store->canonical_dirfd,
      store->work_basename, plaintext, plaintext_len);
#else
  return write_plaintext_work_file (store->work_path, plaintext, plaintext_len);
#endif
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
persist_policy_store_encrypted (wyl_policy_store_t *store)
{
  if (store == NULL)
    return WYRELOG_E_INVALID;
  if (!store->encrypted)
    return WYRELOG_E_OK;
  if (!store->key_materialized)
    return WYRELOG_E_INTERNAL;
  if (store->work_path == NULL || store->canonical_path == NULL
      || store->canonical_path[0] == '\0')
    return WYRELOG_E_INVALID;

  if (store->db != NULL && sqlite3_db_cacheflush (store->db) != SQLITE_OK)
    return WYRELOG_E_IO;

  g_autofree guint8 *plaintext = NULL;
  gsize plaintext_len = 0;
#ifndef G_OS_WIN32
  /* POSIX builds always have canonical_dirfd; the open path enforces
   * this invariant. Bail with a clear error if it's been violated by
   * a future refactor rather than fall through to the path-by-name
   * survivor that would re-introduce the TOCTOU surface. */
  if (store->canonical_dirfd < 0 || store->work_basename == NULL)
    return WYRELOG_E_INTERNAL;
  if (read_work_through_dirfd (store->canonical_dirfd, store->work_basename,
          &plaintext, &plaintext_len) != WYRELOG_E_OK)
    return WYRELOG_E_IO;
#else
  if (read_whole_file (store->work_path, &plaintext,
          &plaintext_len) != WYRELOG_E_OK)
    return WYRELOG_E_IO;
#endif

  const gsize encrypted_len = sizeof (WylPolicyStoreFileHeader)
      + crypto_aead_xchacha20poly1305_ietf_ABYTES + plaintext_len;
  g_autofree guint8 *encrypted = g_malloc0 (encrypted_len);
  WylPolicyStoreFileHeader *header = (WylPolicyStoreFileHeader *) encrypted;
  memcpy (header->magic, WYL_POLICY_STORE_MAGIC, WYL_POLICY_STORE_MAGIC_LEN);
  header->version = WYL_POLICY_STORE_FORMAT_VERSION;
  header->flags = 0;
  header->reserved = 0;
  memcpy (header->provider_id, store->encryption_key_id,
      WYL_POLICY_STORE_KEY_ID_LEN);
  randombytes_buf (header->nonce, sizeof (header->nonce));
  header->ciphertext_len_le = GUINT64_TO_LE ((guint64) (plaintext_len
          + crypto_aead_xchacha20poly1305_ietf_ABYTES));

  guint8 *ciphertext = encrypted + sizeof (WylPolicyStoreFileHeader);
  unsigned long long ciphertext_len = 0;
  if (crypto_aead_xchacha20poly1305_ietf_encrypt (ciphertext, &ciphertext_len,
          plaintext, plaintext_len,
          (const guint8 *) header, sizeof (WylPolicyStoreFileHeader), NULL,
          header->nonce, store->encryption_key) != 0)
    return WYRELOG_E_CRYPTO;
  if (ciphertext_len != (unsigned long long) (encrypted_len
          - sizeof (WylPolicyStoreFileHeader)))
    return WYRELOG_E_CRYPTO;

#ifndef G_OS_WIN32
  /* POSIX builds always have canonical_dirfd; the open path enforces
   * this invariant. */
  if (store->canonical_dirfd < 0 || store->canonical_basename == NULL)
    return WYRELOG_E_INTERNAL;
  return write_through_dirfd (store->canonical_dirfd,
      store->canonical_basename, encrypted, encrypted_len);
#else
  return write_whole_file_atomic_private (store->canonical_path, encrypted,
      encrypted_len);
#endif
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

  guint8 old_key[WYL_POLICY_STORE_KEY_LEN];
  guint8 old_key_id[WYL_POLICY_STORE_KEY_ID_LEN];
  memcpy (old_key, store->encryption_key, sizeof old_key);
  memcpy (old_key_id, store->encryption_key_id, sizeof old_key_id);

  rc = wyl_policy_store_create_schema (store);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_validate_snapshot (store);
  if (rc == WYRELOG_E_OK)
    rc = owned_keyprovider_validate (&new_provider);
  if (rc == WYRELOG_E_OK && !new_provider.owned)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK
      && owned_keyprovider_probe (&new_provider) != WYRELOG_E_OK)
    rc = WYRELOG_E_CRYPTO;
  if (rc == WYRELOG_E_OK)
    rc = materialize_store_key (store, &new_provider, TRUE);

  if (rc == WYRELOG_E_OK)
    rc = persist_policy_store_encrypted (store);

  if (rc != WYRELOG_E_OK) {
    memcpy (store->encryption_key, old_key, sizeof old_key);
    memcpy (store->encryption_key_id, old_key_id, sizeof old_key_id);
    store->key_materialized = TRUE;
    owned_keyprovider_move (&store->rotation_cleanup_keyprovider,
        &new_provider);
  } else {
    /* The explicit successful persist above is the authoritative rotation
     * write. Close must not perform a second, unchecked persist. Provider
     * callbacks are deferred until close has finished with the work DB. */
    store->suppress_close_persist = TRUE;
    owned_keyprovider_move (&store->rotation_cleanup_keyprovider,
        &store->keyprovider);
    owned_keyprovider_move (&store->keyprovider, &new_provider);
  }

  sodium_memzero (old_key, sizeof old_key);
  sodium_memzero (old_key_id, sizeof old_key_id);
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
  owned_keyprovider_adopt (&self->keyprovider, opts);
  self->encrypted = opts->require_encrypted;
  self->canonical_path = g_strdup (effective_path);
  self->canonical_dirfd = -1;
  wyrelog_error_t rc = WYRELOG_E_OK;

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
    open_path = self->work_path;
  } else {
    if (self->keyprovider.owned
        && owned_keyprovider_probe (&self->keyprovider) != WYRELOG_E_OK) {
      rc = WYRELOG_E_CRYPTO;
      goto fail;
    }
    rc = materialize_store_key (self, &self->keyprovider, FALSE);
    if (rc != WYRELOG_E_OK)
      goto fail;
  }

  if (self->lease != NULL && wyl_policy_store_lease_verify_parent (self->lease)
      != WYRELOG_E_OK) {
    rc = WYRELOG_E_POLICY;
    goto fail;
  }

  if (sqlite3_open_v2 (open_path, &self->db,
          SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
          NULL) != SQLITE_OK) {
    if (self->db != NULL)
      sqlite3_close (self->db);
    self->db = NULL;
    rc = WYRELOG_E_IO;
    goto fail;
  }

  if (self->lease != NULL && wyl_policy_store_lease_verify_parent (self->lease)
      != WYRELOG_E_OK) {
    sqlite3_close (self->db);
    self->db = NULL;
    rc = WYRELOG_E_POLICY;
    goto fail;
  }

  const gchar *open_pragmas = self->encrypted ?
      "PRAGMA foreign_keys = ON;" "PRAGMA journal_mode = MEMORY;" :
      "PRAGMA foreign_keys = ON;" "PRAGMA journal_mode = WAL;";
  if (exec_sql (self->db, open_pragmas) != WYRELOG_E_OK) {
    rc = WYRELOG_E_IO;
    goto fail;
  }

  *out_store = self;
  return WYRELOG_E_OK;

fail:
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
  owned_keyprovider_release (&store->rotation_cleanup_keyprovider);
  owned_keyprovider_release (&store->keyprovider);
  wyl_policy_store_lease_release (store->lease);
  store->lease = NULL;
  g_clear_pointer (&store->canonical_basename, g_free);
  g_clear_pointer (&store->work_basename, g_free);
  g_clear_pointer (&store->canonical_path, g_free);
  g_clear_pointer (&store->work_path, g_free);
  g_free (store);
}

sqlite3 *
wyl_policy_store_get_db (wyl_policy_store_t *store)
{
  if (store == NULL)
    return NULL;
  return store->db;
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
      "  created_at INTEGER NOT NULL,"
      "  updated_at INTEGER NOT NULL,"
      "  sealed_at INTEGER,"
      "  PRIMARY KEY (tenant_id, graph_id),"
      "  FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id)"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_fact_graphs_tenant "
      "  ON fact_graphs (tenant_id);"
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
  wyrelog_error_t rc = exec_sql (store->db, ddl);
  if (rc != WYRELOG_E_OK)
    return rc;
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

  /* Apply all five inert service-authority tables, their indexes and their
   * six immutability/append-only triggers atomically. CREATE TABLE IF NOT
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

#ifndef G_OS_WIN32
static gboolean
path_has_root_prefix (const gchar *root, const gchar *child)
{
  gsize root_len = strlen (root);
  return g_str_has_prefix (child, root)
      && (child[root_len] == G_DIR_SEPARATOR || child[root_len] == '\0');
}

static wyrelog_error_t
ensure_fact_graph_dir (const gchar *path)
{
  GStatBuf st;

  if (g_lstat (path, &st) == 0) {
    if (S_ISLNK (st.st_mode))
      return WYRELOG_E_POLICY;
    if (!S_ISDIR (st.st_mode))
      return WYRELOG_E_POLICY;
    return WYRELOG_E_OK;
  }
  if (errno != ENOENT)
    return WYRELOG_E_IO;
  if (g_mkdir (path, 0700) != 0) {
    if (errno == EEXIST)
      return ensure_fact_graph_dir (path);
    return WYRELOG_E_IO;
  }
  if (g_lstat (path, &st) != 0)
    return WYRELOG_E_IO;
  if (!S_ISDIR (st.st_mode) || S_ISLNK (st.st_mode))
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
materialize_fact_graph_storage (const wyl_policy_fact_graph_create_options_t
    *opts, gchar **out_storage_path, gchar **out_storage_uri)
{
  if (opts == NULL || out_storage_path == NULL || out_storage_uri == NULL)
    return WYRELOG_E_INVALID;
  *out_storage_path = NULL;
  *out_storage_uri = NULL;

  GStatBuf root_stat;
  if (g_lstat (opts->fact_root, &root_stat) != 0)
    return errno == ENOENT ? WYRELOG_E_NOT_FOUND : WYRELOG_E_IO;
  if (S_ISLNK (root_stat.st_mode) || !S_ISDIR (root_stat.st_mode))
    return WYRELOG_E_POLICY;

  g_autofree gchar *root_real = realpath (opts->fact_root, NULL);
  if (root_real == NULL)
    return WYRELOG_E_IO;

  g_autofree gchar *tenant_path =
      g_build_filename (root_real, opts->tenant_id, NULL);
  wyrelog_error_t rc = ensure_fact_graph_dir (tenant_path);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *tenant_real = realpath (tenant_path, NULL);
  if (tenant_real == NULL)
    return WYRELOG_E_IO;
  if (!path_has_root_prefix (root_real, tenant_real))
    return WYRELOG_E_POLICY;

  g_autofree gchar *graph_path =
      g_build_filename (tenant_real, opts->graph_id, NULL);
  rc = ensure_fact_graph_dir (graph_path);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *graph_real = realpath (graph_path, NULL);
  if (graph_real == NULL)
    return WYRELOG_E_IO;
  if (!path_has_root_prefix (root_real, graph_real))
    return WYRELOG_E_POLICY;

  g_autofree gchar *uri = g_filename_to_uri (graph_real, NULL, NULL);
  if (uri == NULL)
    return WYRELOG_E_IO;

  *out_storage_path = g_steal_pointer (&graph_real);
  *out_storage_uri = g_steal_pointer (&uri);
  return WYRELOG_E_OK;
}
#endif

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

#ifdef G_OS_WIN32
  /* The registry derives storage from a canonical fact root. Until this path
   * walk has a Win32 reparse-point-safe implementation, fail closed instead
   * of accepting metadata that cannot be bound to a safe physical store. */
  return WYRELOG_E_POLICY;
#else
  g_autofree gchar *storage_path = NULL;
  g_autofree gchar *storage_uri = NULL;
  rc = materialize_fact_graph_storage (opts, &storage_path, &storage_uri);
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
#endif
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
      "SELECT sql FROM sqlite_schema WHERE type = ? AND name = ? "
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
      g_strdup_printf ("PRAGMA table_info(\"%s\");", desc->name);
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
      g_strdup_printf ("PRAGMA foreign_key_list(\"%s\");", desc->name);
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
      "SELECT name, \"unique\", origin, partial FROM pragma_index_list(?) "
      "ORDER BY name;";
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
        g_strdup_printf ("PRAGMA index_xinfo(\"%s\");", name);
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
  for (gsize i = 0; i < G_N_ELEMENTS (service_trigger_descriptors); i++) {
    wyrelog_error_t rc = validate_trigger_descriptor (store->db,
        &service_trigger_descriptors[i]);
    if (rc != WYRELOG_E_OK)
      return rc;
  }

  gboolean found = FALSE;
  wyrelog_error_t rc = query_has_rows (store->db,
      "SELECT 1 FROM sqlite_schema WHERE type = 'trigger' AND tbl_name IN ("
      "'service_principals','service_credentials','service_credential_cvk',"
      "'service_principal_events','service_credential_events') "
      "AND name NOT IN ("
      "'trg_service_principals_identity_immutable',"
      "'trg_service_credentials_identity_immutable',"
      "'trg_service_principal_events_no_update',"
      "'trg_service_principal_events_no_delete',"
      "'trg_service_credential_events_no_update',"
      "'trg_service_credential_events_no_delete') LIMIT 1;", &found);
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
      "'service_credential_cvk','service_principal_events',"
      "'service_credential_events') LIMIT 1;", &found);
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

  static const gchar *sql =
      "INSERT INTO direct_permissions "
      "  (subject_id, perm_id, scope, granted_at) "
      "VALUES (?, ?, ?, unixepoch()) "
      "ON CONFLICT(subject_id, perm_id, scope) DO UPDATE SET "
      "  granted_at = excluded.granted_at;";
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
wyl_policy_store_revoke_direct_permission (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || perm_id == NULL || scope == NULL)
    return WYRELOG_E_INVALID;

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

  static const gchar *sql =
      "INSERT INTO direct_permission_events "
      "  (subject_id, perm_id, scope, operation, created_at) "
      "VALUES (?, ?, ?, ?, unixepoch());";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
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

  static const gchar *sql =
      "INSERT INTO role_permissions (role_id, perm_id, granted_at) "
      "VALUES (?, ?, unixepoch()) "
      "ON CONFLICT(role_id, perm_id) DO UPDATE SET "
      "  granted_at = excluded.granted_at;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
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

  static const gchar *sql =
      "INSERT INTO role_inheritances "
      "  (child_role_id, parent_role_id, granted_at) "
      "VALUES (?, ?, unixepoch()) "
      "ON CONFLICT(child_role_id, parent_role_id) DO UPDATE SET "
      "  granted_at = excluded.granted_at;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
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

  static const gchar *sql =
      "INSERT INTO role_memberships "
      "  (subject_id, role_id, scope, granted_at) "
      "VALUES (?, ?, ?, unixepoch()) "
      "ON CONFLICT(subject_id, role_id, scope) DO UPDATE SET "
      "  granted_at = excluded.granted_at;";
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
wyl_policy_store_revoke_role_membership (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *role_id, const gchar *scope)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || role_id == NULL || scope == NULL)
    return WYRELOG_E_INVALID;

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

  static const gchar *sql =
      "INSERT INTO role_membership_events "
      "  (subject_id, role_id, scope, operation, created_at) "
      "VALUES (?, ?, ?, ?, unixepoch());";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
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

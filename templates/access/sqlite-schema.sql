-- wyrelog SQLite Schema (Phase 1)
-- Role: Policy Authority (Single Source of Truth)
-- Storage: ACID, single-writer (Platform team), Ed25519-signed
-- Reference: internal-discussion/FACT-STORAGE-ARCHITECTURE.md

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- Table: wyrelog_config
-- Runtime policy settings owned by the policy authority.
-- deployment_mode defaults to production when absent.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS wyrelog_config (
    config_key   TEXT    PRIMARY KEY,
    config_value TEXT    NOT NULL CHECK (
        config_key != 'deployment_mode'
        OR config_value IN ('production', 'development', 'demo')
    ),
    updated_at   INTEGER NOT NULL
);

-- ---------------------------------------------------------------------------
-- Table: tenants
-- Registry of known tenant ownership domains. Sealed tenants remain known
-- but reject new login/auth/decision/mutation traffic until unsealed.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id  TEXT    PRIMARY KEY,
    sealed     INTEGER NOT NULL DEFAULT 0 CHECK (sealed IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

INSERT OR IGNORE INTO tenants (tenant_id, sealed, created_at, updated_at)
VALUES ('__wr_default', 0, unixepoch(), unixepoch());

-- ---------------------------------------------------------------------------
-- Table: roles
-- Defines named roles assignable to users/services.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
    role_id     TEXT    PRIMARY KEY,
    role_name   TEXT    UNIQUE NOT NULL,
    description TEXT,
    created_at  INTEGER,            -- Unix epoch (seconds)
    modified_at INTEGER
);

-- ---------------------------------------------------------------------------
-- Table: permissions
-- Atomic capability units, classed by sensitivity.
-- class: 'basic' | 'sensitive' | 'critical'
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS permissions (
    perm_id    TEXT PRIMARY KEY,
    perm_name  TEXT UNIQUE NOT NULL,
    class      TEXT NOT NULL CHECK (class IN ('basic', 'sensitive', 'critical')),
    created_at INTEGER                 -- Unix epoch (seconds)
);

-- ---------------------------------------------------------------------------
-- Table: role_permissions
-- Many-to-many mapping between roles and permissions.
-- Written only by Platform team; read by replication layer.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id    TEXT    NOT NULL,
    perm_id    TEXT    NOT NULL,
    granted_at INTEGER,               -- Unix epoch (seconds)
    granted_by TEXT,                  -- Platform engineer identifier
    PRIMARY KEY (role_id, perm_id),
    FOREIGN KEY (role_id) REFERENCES roles (role_id),
    FOREIGN KEY (perm_id) REFERENCES permissions (perm_id)
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id
    ON role_permissions (role_id);

CREATE INDEX IF NOT EXISTS idx_role_permissions_perm_id
    ON role_permissions (perm_id);

-- ---------------------------------------------------------------------------
-- Table: role_inheritances
-- Mutable role graph edges flattened into role_permission/2 snapshots.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS role_inheritances (
    child_role_id  TEXT    NOT NULL,
    parent_role_id TEXT    NOT NULL,
    granted_at     INTEGER,               -- Unix epoch (seconds)
    granted_by     TEXT,                  -- Platform engineer identifier
    PRIMARY KEY (child_role_id, parent_role_id),
    FOREIGN KEY (child_role_id) REFERENCES roles (role_id),
    FOREIGN KEY (parent_role_id) REFERENCES roles (role_id)
);

CREATE INDEX IF NOT EXISTS idx_role_inheritances_child
    ON role_inheritances (child_role_id);

CREATE INDEX IF NOT EXISTS idx_role_inheritances_parent
    ON role_inheritances (parent_role_id);

-- ---------------------------------------------------------------------------
-- Table: role_memberships
-- Per-principal role grants mirrored into member_of/3 snapshots.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS role_memberships (
    subject_id TEXT NOT NULL,
    role_id    TEXT NOT NULL,
    scope      TEXT NOT NULL,
    granted_at INTEGER,               -- Unix epoch (seconds)
    granted_by TEXT,                  -- Platform engineer identifier
    PRIMARY KEY (subject_id, role_id, scope),
    FOREIGN KEY (role_id) REFERENCES roles (role_id)
);

CREATE INDEX IF NOT EXISTS idx_role_memberships_role_id
    ON role_memberships (role_id);

CREATE INDEX IF NOT EXISTS idx_role_memberships_subject_scope
    ON role_memberships (subject_id, scope);

-- ---------------------------------------------------------------------------
-- Table: role_membership_events
-- Role membership grant/revoke history.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS role_membership_events (
    event_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id TEXT NOT NULL,
    role_id    TEXT NOT NULL,
    scope      TEXT NOT NULL,
    operation  TEXT NOT NULL CHECK (operation IN ('grant', 'revoke')),
    created_at INTEGER NOT NULL,       -- Unix epoch (seconds)
    FOREIGN KEY (role_id) REFERENCES roles (role_id)
);

CREATE INDEX IF NOT EXISTS idx_role_membership_events_subject
    ON role_membership_events (subject_id);

CREATE INDEX IF NOT EXISTS idx_role_membership_events_role
    ON role_membership_events (role_id);

-- ---------------------------------------------------------------------------
-- Table: direct_permissions
-- Per-principal direct grants mirrored into direct_permission/3.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS direct_permissions (
    subject_id TEXT NOT NULL,
    perm_id    TEXT NOT NULL,
    scope      TEXT NOT NULL,
    granted_at INTEGER,               -- Unix epoch (seconds)
    PRIMARY KEY (subject_id, perm_id, scope),
    FOREIGN KEY (perm_id) REFERENCES permissions (perm_id)
);

CREATE INDEX IF NOT EXISTS idx_direct_permissions_perm_id
    ON direct_permissions (perm_id);

CREATE INDEX IF NOT EXISTS idx_direct_permissions_subject_scope
    ON direct_permissions (subject_id, scope);

-- ---------------------------------------------------------------------------
-- Table: direct_permission_events
-- Append-only grant/revoke ledger for direct_permission/3 changes.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS direct_permission_events (
    event_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id TEXT    NOT NULL,
    perm_id    TEXT    NOT NULL,
    scope      TEXT    NOT NULL,
    operation  TEXT    NOT NULL CHECK (operation IN ('grant', 'revoke')),
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_direct_permission_events_subject
    ON direct_permission_events (subject_id);

CREATE INDEX IF NOT EXISTS idx_direct_permission_events_perm
    ON direct_permission_events (perm_id);

-- ---------------------------------------------------------------------------
-- Table: permission_states
-- Durable permission lifecycle state mirrored into perm_state/4.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS permission_states (
    subject_id TEXT    NOT NULL,
    perm_id    TEXT    NOT NULL,
    scope      TEXT    NOT NULL,
    state      TEXT    NOT NULL,
    updated_at INTEGER,
    PRIMARY KEY (subject_id, perm_id, scope)
);

CREATE INDEX IF NOT EXISTS idx_permission_states_state
    ON permission_states (state);

CREATE INDEX IF NOT EXISTS idx_permission_states_perm
    ON permission_states (perm_id);

-- ---------------------------------------------------------------------------
-- Table: permission_state_events
-- Append-only permission-state FSM transition ledger. Current state is kept in
-- permission_states; this table preserves the event edge that produced it.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS permission_state_events (
    event_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id TEXT    NOT NULL,
    perm_id    TEXT    NOT NULL,
    scope      TEXT    NOT NULL,
    event      TEXT    NOT NULL,
    from_state TEXT    NOT NULL,
    to_state   TEXT    NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_permission_state_events_subject
    ON permission_state_events (subject_id);

CREATE INDEX IF NOT EXISTS idx_permission_state_events_perm
    ON permission_state_events (perm_id);

CREATE INDEX IF NOT EXISTS idx_permission_state_events_event
    ON permission_state_events (event);

-- ---------------------------------------------------------------------------
-- Table: principal_states
-- Durable principal authentication state mirrored into principal_state/2.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS principal_states (
    subject_id           TEXT    PRIMARY KEY,
    state                TEXT    NOT NULL,
    updated_at           INTEGER,
    -- Issue #331 commit 5: failed_attempt_count is the count of
    -- consecutive verify failures since the last successful MFA verify
    -- (or admin reset); locked_at is the unix-epoch seconds the row
    -- entered the LOCKED state (NULL when not locked).
    failed_attempt_count INTEGER NOT NULL DEFAULT 0,
    locked_at            INTEGER
);

CREATE INDEX IF NOT EXISTS idx_principal_states_state
    ON principal_states (state);

-- ---------------------------------------------------------------------------
-- Table: principal_events
-- Append-only principal FSM transition ledger. Current state is kept in
-- principal_states; this table preserves the event edge that produced it.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS principal_events (
    event_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id TEXT    NOT NULL,
    event      TEXT    NOT NULL,
    from_state TEXT    NOT NULL,
    to_state   TEXT    NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_principal_events_subject_id
    ON principal_events (subject_id);

CREATE INDEX IF NOT EXISTS idx_principal_events_event
    ON principal_events (event);

-- ---------------------------------------------------------------------------
-- Table: session_states
-- Durable session lifecycle state mirrored into session_state/2.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS session_states (
    session_id TEXT PRIMARY KEY,
    state      TEXT    NOT NULL,
    updated_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_session_states_state
    ON session_states (state);

-- ---------------------------------------------------------------------------
-- Table: session_events
-- Append-only session FSM transition ledger. Current state is kept in
-- session_states; this table preserves the event edge that produced it.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS session_events (
    event_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT    NOT NULL,
    event      TEXT    NOT NULL,
    from_state TEXT    NOT NULL,
    to_state   TEXT    NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_session_events_session_id
    ON session_events (session_id);

CREATE INDEX IF NOT EXISTS idx_session_events_event
    ON session_events (event);

-- ---------------------------------------------------------------------------
-- Table: audit_events
-- Append-only audit sink mirrored from runtime audit emission.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_events (
    id            TEXT    PRIMARY KEY,
    created_at_us INTEGER NOT NULL,
    subject_id    TEXT,
    action        TEXT,
    resource_id   TEXT,
    deny_reason   TEXT,
    deny_origin   TEXT,
    request_id    TEXT,
    decision      INTEGER NOT NULL CHECK (decision IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_audit_events_created_at_us
    ON audit_events (created_at_us);

CREATE INDEX IF NOT EXISTS idx_audit_events_subject_id
    ON audit_events (subject_id);

CREATE INDEX IF NOT EXISTS idx_audit_events_action
    ON audit_events (action);

CREATE INDEX IF NOT EXISTS idx_audit_events_decision
    ON audit_events (decision);

CREATE INDEX IF NOT EXISTS idx_audit_events_deny_reason
    ON audit_events (deny_reason);

CREATE INDEX IF NOT EXISTS idx_audit_events_deny_origin
    ON audit_events (deny_origin);

CREATE INDEX IF NOT EXISTS idx_audit_events_request_id
    ON audit_events (request_id);

-- ---------------------------------------------------------------------------
-- Table: audit_intentions
-- Durable audit append lifecycle. SQLite is the source of truth; this ledger
-- lets boot/query reconciliation distinguish pending runtime projection work
-- from fully committed audit rows while reserving chain/anchor metadata hooks.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_intentions (
    audit_id        TEXT    PRIMARY KEY,
    created_at_us   INTEGER NOT NULL,
    subject_id      TEXT,
    action          TEXT,
    resource_id     TEXT,
    deny_reason     TEXT,
    deny_origin     TEXT,
    request_id      TEXT,
    decision        INTEGER NOT NULL CHECK (decision IN (0, 1)),
    state           TEXT    NOT NULL CHECK
        (state IN ('pending', 'committed', 'failed')),
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    chain_prev      TEXT,
    chain_hash      TEXT,
    anchor_batch_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_intentions_state
    ON audit_intentions (state);

CREATE INDEX IF NOT EXISTS idx_audit_intentions_action
    ON audit_intentions (action);

CREATE INDEX IF NOT EXISTS idx_audit_intentions_updated
    ON audit_intentions (updated_at);

-- ---------------------------------------------------------------------------
-- Table: fact_graphs
-- Metadata-only authority for tenant-owned fact graphs. Fact tuples and
-- compound payloads are stored outside this policy database; this registry
-- keeps only identity, ownership, schema version, and canonical storage
-- locators derived by the host from the configured fact root.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fact_graphs (
    tenant_id      TEXT    NOT NULL,
    graph_id       TEXT    NOT NULL,
    storage_uri    TEXT    NOT NULL,
    storage_path   TEXT    NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    owner_scope    TEXT    NOT NULL CHECK (owner_scope = tenant_id),
    sealed         INTEGER NOT NULL DEFAULT 0 CHECK (sealed IN (0, 1)),
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL,
    sealed_at      INTEGER,
    PRIMARY KEY (tenant_id, graph_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_fact_graphs_tenant
    ON fact_graphs (tenant_id);

-- ---------------------------------------------------------------------------
-- Table: fact_graph_relations
-- Relation declarations available in a fact graph. No fact rows live here.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fact_graph_relations (
    tenant_id     TEXT    NOT NULL,
    graph_id      TEXT    NOT NULL,
    relation_name TEXT    NOT NULL,
    arity         INTEGER NOT NULL CHECK (arity > 0),
    PRIMARY KEY (tenant_id, graph_id, relation_name),
    FOREIGN KEY (tenant_id, graph_id)
        REFERENCES fact_graphs (tenant_id, graph_id)
        ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Table: fact_graph_relation_columns
-- Ordered relation schema metadata. compound_ref identifies an external value
-- reference only; no compound payload is stored in policy SQLite.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fact_graph_relation_columns (
    tenant_id     TEXT    NOT NULL,
    graph_id      TEXT    NOT NULL,
    relation_name TEXT    NOT NULL,
    column_index  INTEGER NOT NULL CHECK (column_index >= 0),
    column_name   TEXT    NOT NULL,
    column_type   TEXT    NOT NULL CHECK
        (column_type IN ('symbol', 'int64', 'bool', 'compound_ref')),
    PRIMARY KEY (tenant_id, graph_id, relation_name, column_index),
    FOREIGN KEY (tenant_id, graph_id, relation_name)
        REFERENCES fact_graph_relations (tenant_id, graph_id, relation_name)
        ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Table: fact_graph_query_allowlist
-- Named query metadata tied to existing permissions.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fact_graph_query_allowlist (
    tenant_id              TEXT    NOT NULL,
    graph_id               TEXT    NOT NULL,
    query_name             TEXT    NOT NULL,
    relation_name          TEXT    NOT NULL,
    required_permission_id TEXT    NOT NULL,
    max_rows               INTEGER NOT NULL CHECK (max_rows > 0),
    PRIMARY KEY (tenant_id, graph_id, query_name),
    FOREIGN KEY (tenant_id, graph_id, relation_name)
        REFERENCES fact_graph_relations (tenant_id, graph_id, relation_name),
    FOREIGN KEY (required_permission_id) REFERENCES permissions (perm_id)
);

-- ---------------------------------------------------------------------------
-- Table: fact_namespaces
-- Tenant/graph-scoped customer namespace registry. Reserved namespaces are
-- rejected by store-side validators. No fact rows live here.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fact_namespaces (
    tenant_id    TEXT    NOT NULL,
    graph_id     TEXT    NOT NULL,
    namespace_id TEXT    NOT NULL,
    visibility   INTEGER NOT NULL DEFAULT 1 CHECK (visibility IN (0, 1)),
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, graph_id, namespace_id),
    FOREIGN KEY (tenant_id, graph_id)
        REFERENCES fact_graphs (tenant_id, graph_id)
        ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Table: fact_relation_schemas
-- Immutable relation schema metadata keyed by tenant, graph, namespace,
-- relation, and relation schema version.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fact_relation_schemas (
    tenant_id        TEXT    NOT NULL,
    graph_id         TEXT    NOT NULL,
    namespace_id     TEXT    NOT NULL,
    relation_name    TEXT    NOT NULL,
    schema_version   INTEGER NOT NULL CHECK (schema_version > 0),
    arity            INTEGER NOT NULL CHECK (arity > 0),
    relation_visible INTEGER NOT NULL DEFAULT 1 CHECK
        (relation_visible IN (0, 1)),
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, graph_id, namespace_id, relation_name,
        schema_version),
    FOREIGN KEY (tenant_id, graph_id, namespace_id)
        REFERENCES fact_namespaces (tenant_id, graph_id, namespace_id)
        ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Table: fact_relation_schema_columns
-- Ordered typed column metadata for validating fact batches before append.
-- compound_ref names a durable logical marker; raw evaluator handles are not
-- stored in policy SQLite.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fact_relation_schema_columns (
    tenant_id      TEXT    NOT NULL,
    graph_id       TEXT    NOT NULL,
    namespace_id   TEXT    NOT NULL,
    relation_name  TEXT    NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    column_index   INTEGER NOT NULL CHECK (column_index >= 0),
    column_name    TEXT    NOT NULL,
    column_type    TEXT    NOT NULL CHECK
        (column_type IN ('symbol', 'string', 'int64', 'bool',
            'compound_ref')),
    nullable       INTEGER NOT NULL DEFAULT 0 CHECK (nullable IN (0, 1)),
    visible        INTEGER NOT NULL DEFAULT 1 CHECK (visible IN (0, 1)),
    PRIMARY KEY (tenant_id, graph_id, namespace_id, relation_name,
        schema_version, column_index),
    UNIQUE (tenant_id, graph_id, namespace_id, relation_name, schema_version,
        column_name),
    FOREIGN KEY (tenant_id, graph_id, namespace_id, relation_name,
        schema_version)
        REFERENCES fact_relation_schemas (tenant_id, graph_id, namespace_id,
            relation_name, schema_version)
        ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Table: fact_relation_query_allowlist
-- Query metadata tied to an exact relation schema version.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fact_relation_query_allowlist (
    tenant_id              TEXT    NOT NULL,
    graph_id               TEXT    NOT NULL,
    namespace_id           TEXT    NOT NULL,
    relation_name          TEXT    NOT NULL,
    schema_version         INTEGER NOT NULL CHECK (schema_version > 0),
    query_name             TEXT    NOT NULL,
    required_permission_id TEXT    NOT NULL,
    max_rows               INTEGER NOT NULL CHECK (max_rows > 0),
    PRIMARY KEY (tenant_id, graph_id, query_name),
    FOREIGN KEY (tenant_id, graph_id, namespace_id, relation_name,
        schema_version)
        REFERENCES fact_relation_schemas (tenant_id, graph_id, namespace_id,
            relation_name, schema_version),
    FOREIGN KEY (required_permission_id) REFERENCES permissions (perm_id)
);

-- ---------------------------------------------------------------------------
-- Inert service identity and credential authority (#353).
-- No row in these tables is seeded by the schema.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS service_principals (
    subject_id TEXT NOT NULL PRIMARY KEY CHECK (
        length(subject_id) BETWEEN 5 AND 128
        AND instr(subject_id, char(0)) = 0
        AND substr(subject_id, 1, 4) = 'svc:'
        AND substr(subject_id, 5, 1) GLOB '[A-Za-z0-9]'
        AND substr(subject_id, -1, 1) GLOB '[A-Za-z0-9]'
        AND subject_id NOT GLOB '*[^-A-Za-z0-9._:]*'
        AND subject_id NOT GLOB '*:[^A-Za-z0-9]*'
        AND subject_id NOT GLOB '*[^A-Za-z0-9]:*'
    ),
    display_name   TEXT    NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    state          TEXT    NOT NULL CHECK (state IN ('active', 'disabled')),
    generation     INTEGER NOT NULL DEFAULT 1 CHECK (generation >= 1),
    created_by     TEXT    NOT NULL CHECK (length(created_by) BETWEEN 1 AND 128),
    created_at_us  INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us  INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    disabled_by    TEXT,
    disabled_at_us INTEGER,
    CHECK (disabled_by IS NULL OR length(disabled_by) BETWEEN 1 AND 128),
    CHECK (
        (state = 'active' AND disabled_by IS NULL AND disabled_at_us IS NULL)
        OR (state = 'disabled' AND disabled_by IS NOT NULL
            AND disabled_at_us IS NOT NULL
            AND disabled_at_us >= created_at_us)
    )
);

CREATE INDEX IF NOT EXISTS idx_service_principals_state_subject
    ON service_principals (state, subject_id);

CREATE TABLE IF NOT EXISTS service_credential_cvk (
    slot                    INTEGER PRIMARY KEY CHECK (slot = 1),
    generation              INTEGER NOT NULL UNIQUE CHECK (generation >= 1),
    envelope_format_version INTEGER NOT NULL CHECK (envelope_format_version >= 1),
    provider_binding        BLOB    NOT NULL CHECK (
        typeof(provider_binding) = 'blob' AND length(provider_binding) = 32),
    sealed_cvk              BLOB    NOT NULL CHECK (
        typeof(sealed_cvk) = 'blob' AND length(sealed_cvk) BETWEEN 1 AND 65536),
    created_at_us           INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us           INTEGER NOT NULL CHECK (updated_at_us >= created_at_us)
);

CREATE TABLE IF NOT EXISTS service_credentials (
    credential_id             TEXT    NOT NULL PRIMARY KEY CHECK (
        length(credential_id) BETWEEN 1 AND 128
        AND instr(credential_id, char(0)) = 0),
    credential_format_version INTEGER NOT NULL CHECK (credential_format_version >= 1),
    subject_id                TEXT    NOT NULL,
    tenant_id                 TEXT    NOT NULL,
    generation                INTEGER NOT NULL DEFAULT 1 CHECK (generation >= 1),
    state                     TEXT    NOT NULL CHECK (state IN ('active', 'revoked')),
    verifier_version          INTEGER NOT NULL CHECK (verifier_version >= 1),
    salt                      BLOB    NOT NULL CHECK (
        typeof(salt) = 'blob' AND length(salt) = 16),
    verifier                  BLOB    NOT NULL CHECK (
        typeof(verifier) = 'blob' AND length(verifier) = 32),
    created_by                TEXT    NOT NULL CHECK (length(created_by) BETWEEN 1 AND 128),
    created_at_us             INTEGER NOT NULL CHECK (created_at_us > 0),
    updated_at_us             INTEGER NOT NULL CHECK (updated_at_us >= created_at_us),
    expires_at_us             INTEGER CHECK (expires_at_us IS NULL OR expires_at_us > created_at_us),
    last_used_at_us           INTEGER CHECK (last_used_at_us IS NULL OR last_used_at_us >= created_at_us),
    revoked_by                TEXT,
    revoked_at_us             INTEGER,
    rotated_from_id           TEXT,
    CHECK (revoked_by IS NULL OR length(revoked_by) BETWEEN 1 AND 128),
    UNIQUE (credential_id, subject_id, tenant_id),
    UNIQUE (rotated_from_id),
    FOREIGN KEY (subject_id) REFERENCES service_principals (subject_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY (rotated_from_id, subject_id, tenant_id)
        REFERENCES service_credentials (credential_id, subject_id, tenant_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK (rotated_from_id IS NULL OR rotated_from_id <> credential_id),
    CHECK (
        (state = 'active' AND revoked_by IS NULL AND revoked_at_us IS NULL)
        OR (state = 'revoked' AND revoked_by IS NOT NULL
            AND revoked_at_us IS NOT NULL AND revoked_at_us >= created_at_us)
    )
);

CREATE INDEX IF NOT EXISTS idx_service_credentials_subject_tenant_state
    ON service_credentials (subject_id, tenant_id, state);
CREATE INDEX IF NOT EXISTS idx_service_credentials_tenant_state_expiry
    ON service_credentials (tenant_id, state, expires_at_us);

CREATE TABLE IF NOT EXISTS service_principal_events (
    event_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id       TEXT    NOT NULL,
    event            TEXT    NOT NULL CHECK (event IN ('created', 'disabled')),
    from_state       TEXT    CHECK (from_state IS NULL OR from_state IN ('active', 'disabled')),
    to_state         TEXT    NOT NULL CHECK (to_state IN ('active', 'disabled')),
    generation       INTEGER NOT NULL CHECK (generation >= 1),
    actor_subject_id TEXT    NOT NULL CHECK (
        length(actor_subject_id) BETWEEN 1 AND 128),
    request_id       TEXT,
    created_at_us    INTEGER NOT NULL CHECK (created_at_us > 0),
    FOREIGN KEY (subject_id) REFERENCES service_principals (subject_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK (
        (event = 'created' AND from_state IS NULL AND to_state = 'active')
        OR (event = 'disabled' AND from_state = 'active'
            AND to_state = 'disabled')
    )
);

CREATE INDEX IF NOT EXISTS idx_service_principal_events_subject_time
    ON service_principal_events (subject_id, created_at_us, event_id);
CREATE INDEX IF NOT EXISTS idx_service_principal_events_request
    ON service_principal_events (request_id);

CREATE TABLE IF NOT EXISTS service_credential_events (
    event_id              INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id         TEXT    NOT NULL,
    subject_id            TEXT    NOT NULL,
    tenant_id             TEXT    NOT NULL,
    event                 TEXT    NOT NULL CHECK (event IN ('issued', 'rotated', 'revoked')),
    from_state            TEXT    CHECK (from_state IS NULL OR from_state IN ('active', 'revoked')),
    to_state              TEXT    NOT NULL CHECK (to_state IN ('active', 'revoked')),
    generation            INTEGER NOT NULL CHECK (generation >= 1),
    actor_subject_id      TEXT    NOT NULL CHECK (
        length(actor_subject_id) BETWEEN 1 AND 128),
    request_id            TEXT,
    related_credential_id TEXT,
    created_at_us         INTEGER NOT NULL CHECK (created_at_us > 0),
    FOREIGN KEY (credential_id, subject_id, tenant_id)
        REFERENCES service_credentials (credential_id, subject_id, tenant_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY (related_credential_id, subject_id, tenant_id)
        REFERENCES service_credentials (credential_id, subject_id, tenant_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK (
        (event IN ('issued', 'rotated') AND from_state IS NULL
            AND to_state = 'active')
        OR (event = 'revoked' AND from_state = 'active'
            AND to_state = 'revoked')
    )
);

CREATE INDEX IF NOT EXISTS idx_service_credential_events_credential_time
    ON service_credential_events (credential_id, created_at_us, event_id);
CREATE INDEX IF NOT EXISTS idx_service_credential_events_owner_time
    ON service_credential_events (subject_id, tenant_id, created_at_us, event_id);
CREATE INDEX IF NOT EXISTS idx_service_credential_events_request
    ON service_credential_events (request_id);

CREATE TABLE IF NOT EXISTS service_domain_requests (
    request_id        TEXT NOT NULL PRIMARY KEY CHECK (
        length(request_id) BETWEEN 1 AND 256
        AND instr(request_id, char(0)) = 0),
    operation         TEXT NOT NULL CHECK (operation IN (
        'principal_create', 'principal_disable', 'credential_issue',
        'credential_revoke', 'credential_rotate')),
    resource_id       TEXT NOT NULL CHECK (
        length(resource_id) BETWEEN 1 AND 128
        AND instr(resource_id, char(0)) = 0),
    input_fingerprint BLOB NOT NULL CHECK (
        typeof(input_fingerprint) = 'blob'
        AND length(input_fingerprint) = 32),
    created_at_us     INTEGER NOT NULL CHECK (created_at_us > 0)
);

CREATE TRIGGER IF NOT EXISTS trg_service_principals_identity_immutable
BEFORE UPDATE ON service_principals
WHEN OLD.subject_id IS NOT NEW.subject_id
    OR OLD.created_by IS NOT NEW.created_by
    OR OLD.created_at_us IS NOT NEW.created_at_us
BEGIN
    SELECT RAISE(ABORT, 'service principal identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_credentials_identity_immutable
BEFORE UPDATE ON service_credentials
WHEN OLD.credential_id IS NOT NEW.credential_id
    OR OLD.credential_format_version IS NOT NEW.credential_format_version
    OR OLD.subject_id IS NOT NEW.subject_id
    OR OLD.tenant_id IS NOT NEW.tenant_id
    OR OLD.verifier_version IS NOT NEW.verifier_version
    OR OLD.salt IS NOT NEW.salt
    OR OLD.verifier IS NOT NEW.verifier
    OR OLD.created_by IS NOT NEW.created_by
    OR OLD.created_at_us IS NOT NEW.created_at_us
    OR OLD.expires_at_us IS NOT NEW.expires_at_us
    OR OLD.rotated_from_id IS NOT NEW.rotated_from_id
BEGIN
    SELECT RAISE(ABORT, 'service credential identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_principal_events_no_update
BEFORE UPDATE ON service_principal_events
BEGIN
    SELECT RAISE(ABORT, 'service principal events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_principal_events_no_delete
BEFORE DELETE ON service_principal_events
BEGIN
    SELECT RAISE(ABORT, 'service principal events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_credential_events_no_update
BEFORE UPDATE ON service_credential_events
BEGIN
    SELECT RAISE(ABORT, 'service credential events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_credential_events_no_delete
BEFORE DELETE ON service_credential_events
BEGIN
    SELECT RAISE(ABORT, 'service credential events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_domain_requests_no_update
BEFORE UPDATE ON service_domain_requests
BEGIN
    SELECT RAISE(ABORT, 'service domain requests are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_domain_requests_no_delete
BEFORE DELETE ON service_domain_requests
BEGIN
    SELECT RAISE(ABORT, 'service domain requests are append-only');
END;

-- ---------------------------------------------------------------------------
-- Table: policy_signatures
-- Ed25519 signatures over policy snapshots, authored by security_officer.
-- Each policy version is immutably signed; versions are monotonically
-- increasing so rollback to an unsigned state is detectable.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_signatures (
    policy_version INTEGER PRIMARY KEY,
    policy_hash    BLOB    NOT NULL,   -- SHA-256 over canonical policy state
    signature      BLOB    NOT NULL,   -- Ed25519 signature (libsodium)
    signed_by      TEXT    NOT NULL,   -- security_officer identifier
    signed_at      INTEGER NOT NULL    -- Unix epoch (seconds)
);

-- ---------------------------------------------------------------------------
-- Table: totp_enrollments
-- Per-principal TOTP enrollment (issue #331).  One row per subject
-- holds the RFC 6238 SHA-1 seed plus the replay watermark.  The seed
-- is the raw 20-byte BLOB; encryption-at-rest is provided by the
-- enclosing policy-store XChaCha20-Poly1305 envelope.
--
--   subject_id          principal that owns this enrollment (PK)
--   secret_blob         20-byte SHA-1 seed
--   last_verified_step  replay watermark; INT64_MIN sentinel means
--                       "never verified" (no native u64 in SQLite, so
--                       the u64 step counter is cast to gint64)
--   enrolled_at         unix seconds at enrollment time
--   id_uuidv7           libchronoid UUIDv7 minted via wyl_id_new
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS totp_enrollments (
    subject_id         TEXT    PRIMARY KEY,
    secret_blob        BLOB    NOT NULL,
    last_verified_step INTEGER NOT NULL,
    enrolled_at        INTEGER NOT NULL,
    id_uuidv7          TEXT    NOT NULL
);

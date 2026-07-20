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

CREATE TABLE IF NOT EXISTS service_credential_handoff_escrows (
    escrow_id             TEXT NOT NULL PRIMARY KEY CHECK (
        typeof(escrow_id) = 'text' AND length(escrow_id) = 36
        AND instr(escrow_id, char(0)) = 0),
    operation             TEXT NOT NULL CHECK (operation IN ('issue', 'rotate')),
    request_id            TEXT NOT NULL UNIQUE CHECK (
        typeof(request_id) = 'text' AND length(request_id) BETWEEN 1 AND 256
        AND instr(request_id, char(0)) = 0),
    actor_subject_id      TEXT NOT NULL CHECK (
        typeof(actor_subject_id) = 'text' AND length(actor_subject_id) BETWEEN 1 AND 128
        AND instr(actor_subject_id, char(0)) = 0),
    target_digest         BLOB NOT NULL CHECK (typeof(target_digest) = 'blob' AND length(target_digest) = 32),
    credential_id         TEXT NOT NULL CHECK (
        typeof(credential_id) = 'text' AND length(credential_id) = 31
        AND substr(credential_id, 1, 4) = 'wlc_' AND instr(credential_id, char(0)) = 0),
    credential_generation INTEGER NOT NULL CHECK (credential_generation >= 1),
    deadline_at_us        INTEGER NOT NULL CHECK (deadline_at_us > 0),
    binding_digest        BLOB NOT NULL CHECK (typeof(binding_digest) = 'blob' AND length(binding_digest) = 32),
    sealed_envelope       BLOB NOT NULL CHECK (
        typeof(sealed_envelope) = 'blob' AND length(sealed_envelope) BETWEEN 1 AND 65536),
    created_at_us         INTEGER NOT NULL CHECK (created_at_us > 0)
);

CREATE INDEX IF NOT EXISTS idx_service_handoff_escrows_credential
    ON service_credential_handoff_escrows (credential_id, credential_generation);

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

CREATE TABLE IF NOT EXISTS service_authority_writer_gate (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    lock_word INTEGER NOT NULL CHECK (lock_word = 0)
) WITHOUT ROWID;

INSERT OR IGNORE INTO service_authority_writer_gate (singleton, lock_word)
VALUES (1, 0);

CREATE TABLE IF NOT EXISTS service_exchange_audit_intentions (
    intention_id TEXT NOT NULL PRIMARY KEY CHECK (
        typeof(intention_id) = 'text' AND length(intention_id) = 36
        AND instr(intention_id, char(0)) = 0),
    payload_digest TEXT NOT NULL UNIQUE CHECK (
        typeof(payload_digest) = 'text' AND length(payload_digest) = 64
        AND payload_digest = lower(payload_digest)
        AND payload_digest NOT GLOB '*[^0-9a-f]*'),
    payload_schema_version INTEGER NOT NULL CHECK (
        typeof(payload_schema_version) = 'integer'
        AND payload_schema_version = 1),
    event_type TEXT NOT NULL CHECK (
        typeof(event_type) = 'text'
        AND event_type = 'service.credential.exchange'),
    outcome TEXT NOT NULL CHECK (typeof(outcome) = 'text'
        AND outcome = 'allowed'),
    created_at_us INTEGER NOT NULL CHECK (
        typeof(created_at_us) = 'integer' AND created_at_us > 0),
    request_id TEXT NOT NULL CHECK (
        typeof(request_id) = 'text' AND length(request_id) = 27
        AND instr(request_id, char(0)) = 0),
    credential_id TEXT NOT NULL CHECK (
        typeof(credential_id) = 'text' AND length(credential_id) = 31
        AND substr(credential_id, 1, 4) = 'wlc_'
        AND instr(credential_id, char(0)) = 0),
    credential_generation BLOB NOT NULL CHECK (
        typeof(credential_generation) = 'blob'
        AND length(credential_generation) = 8),
    service_principal TEXT NOT NULL CHECK (
        typeof(service_principal) = 'text'
    AND length(CAST(service_principal AS BLOB)) BETWEEN 5 AND 128
        AND instr(service_principal, char(0)) = 0),
    tenant_id TEXT NOT NULL CHECK (
        typeof(tenant_id) = 'text'
        AND length(CAST(tenant_id AS BLOB)) BETWEEN 1 AND 128
        AND instr(tenant_id, char(0)) = 0),
    fingerprint_schema_version INTEGER NOT NULL CHECK (
        typeof(fingerprint_schema_version) = 'integer'
        AND fingerprint_schema_version = 1),
    session_fingerprint TEXT NOT NULL CHECK (
        typeof(session_fingerprint) = 'text'
        AND length(session_fingerprint) = 64
        AND session_fingerprint = lower(session_fingerprint)
        AND session_fingerprint NOT GLOB '*[^0-9a-f]*'),
    jti_fingerprint TEXT NOT NULL CHECK (
        typeof(jti_fingerprint) = 'text' AND length(jti_fingerprint) = 64
        AND jti_fingerprint = lower(jti_fingerprint)
        AND jti_fingerprint NOT GLOB '*[^0-9a-f]*'),
    canonical_payload BLOB NOT NULL CHECK (
        typeof(canonical_payload) = 'blob'
        AND length(canonical_payload) BETWEEN 1 AND 4096)
);

CREATE INDEX IF NOT EXISTS idx_service_exchange_audit_created
    ON service_exchange_audit_intentions (created_at_us, intention_id);

CREATE TABLE IF NOT EXISTS service_credential_operation_fences (
    request_id            TEXT NOT NULL PRIMARY KEY CHECK (
        length(request_id) BETWEEN 1 AND 256
        AND instr(request_id, char(0)) = 0),
    operation             TEXT NOT NULL CHECK (operation IN (
        'credential_issue', 'credential_rotate')),
    operation_fingerprint BLOB NOT NULL CHECK (
        typeof(operation_fingerprint) = 'blob'
        AND length(operation_fingerprint) = 32),
    terminal_state        TEXT NOT NULL CHECK (terminal_state = 'not_committed'),
    created_at_us         INTEGER NOT NULL CHECK (created_at_us > 0)
);

CREATE TABLE IF NOT EXISTS service_credential_handoff_dispositions (
    disposition_id TEXT NOT NULL PRIMARY KEY CHECK (typeof(disposition_id) = 'text'
        AND length(disposition_id) = 36 AND instr(disposition_id, char(0)) = 0),
    semantic_key BLOB NOT NULL UNIQUE CHECK (typeof(semantic_key) = 'blob'
        AND length(semantic_key) = 32),
    original_request_id TEXT NOT NULL CHECK (typeof(original_request_id) = 'text'
        AND length(original_request_id) = 27 AND instr(original_request_id, char(0)) = 0),
    escrow_id TEXT NOT NULL CHECK (typeof(escrow_id) = 'text'
        AND length(escrow_id) = 36 AND instr(escrow_id, char(0)) = 0),
    binding_digest BLOB NOT NULL CHECK (typeof(binding_digest) = 'blob'
        AND length(binding_digest) = 32),
    successor_credential_id TEXT CHECK (successor_credential_id IS NULL OR
        (typeof(successor_credential_id) = 'text'
        AND length(successor_credential_id) = 31
        AND substr(successor_credential_id, 1, 4) = 'wlc_'
        AND instr(successor_credential_id, char(0)) = 0)),
    successor_issuance_generation INTEGER CHECK (successor_issuance_generation IS NULL
        OR successor_issuance_generation >= 1),
    actor_subject_id TEXT NOT NULL CHECK (typeof(actor_subject_id) = 'text'
        AND length(actor_subject_id) BETWEEN 1 AND 128
        AND instr(actor_subject_id, char(0)) = 0),
    reason TEXT NOT NULL CHECK (reason IN ('not_committed', 'operation_expired',
        'operation_cancelled', 'successor_expired', 'successor_revoked', 'delivered')),
    outcome TEXT NOT NULL CHECK (outcome IN ('terminal_not_committed', 'attention_required',
        'operator_action_required', 'escrow_deleted')),
    audit_id TEXT NOT NULL UNIQUE CHECK (typeof(audit_id) = 'text'
        AND length(audit_id) = 36 AND instr(audit_id, char(0)) = 0),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    CHECK ((reason = 'not_committed' AND outcome = 'terminal_not_committed'
            AND successor_credential_id IS NULL
            AND successor_issuance_generation IS NULL)
        OR (reason <> 'not_committed' AND binding_digest <> zeroblob(32)
            AND successor_credential_id IS NOT NULL
            AND successor_issuance_generation IS NOT NULL AND (
        (reason IN ('operation_expired', 'operation_cancelled')
            AND outcome = 'attention_required')
        OR (reason IN ('successor_expired', 'successor_revoked')
            AND outcome = 'operator_action_required')
        OR (reason = 'delivered' AND outcome = 'escrow_deleted'))))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_service_handoff_disposition_exact
    ON service_credential_handoff_dispositions (
        original_request_id, reason, outcome, escrow_id, binding_digest,
        coalesce(successor_credential_id, ''),
        coalesce(successor_issuance_generation, 0));

CREATE TABLE IF NOT EXISTS service_credential_handoff_cancellation_claims (
    cancellation_request_id TEXT NOT NULL PRIMARY KEY CHECK (
        typeof(cancellation_request_id) = 'text' AND length(cancellation_request_id) = 27
        AND instr(cancellation_request_id, char(0)) = 0),
    request_fingerprint BLOB NOT NULL CHECK (typeof(request_fingerprint) = 'blob'
        AND length(request_fingerprint) = 32),
    decision_request_id TEXT NOT NULL UNIQUE CHECK (typeof(decision_request_id) = 'text'
        AND length(decision_request_id) = 27 AND instr(decision_request_id, char(0)) = 0),
    original_request_id TEXT NOT NULL CHECK (typeof(original_request_id) = 'text'
        AND length(original_request_id) = 27 AND instr(original_request_id, char(0)) = 0),
    original_actor_subject_id TEXT NOT NULL CHECK (typeof(original_actor_subject_id) = 'text'
        AND length(original_actor_subject_id) BETWEEN 1 AND 128
        AND instr(original_actor_subject_id, char(0)) = 0),
    current_actor_subject_id TEXT NOT NULL CHECK (typeof(current_actor_subject_id) = 'text'
        AND length(current_actor_subject_id) BETWEEN 1 AND 128
        AND instr(current_actor_subject_id, char(0)) = 0),
    resolution TEXT NOT NULL CHECK (
        resolution IN ('committed_attention', 'terminal_not_committed')),
    escrow_id TEXT NOT NULL CHECK (typeof(escrow_id) = 'text'
        AND length(escrow_id) = 36 AND instr(escrow_id, char(0)) = 0),
    binding_digest BLOB NOT NULL CHECK (typeof(binding_digest) = 'blob'
        AND length(binding_digest) = 32),
    successor_credential_id TEXT CHECK (successor_credential_id IS NULL OR (
        typeof(successor_credential_id) = 'text' AND length(successor_credential_id) = 31
        AND substr(successor_credential_id, 1, 4) = 'wlc_'
        AND instr(successor_credential_id, char(0)) = 0)),
    successor_issuance_generation INTEGER CHECK (
        successor_issuance_generation IS NULL OR successor_issuance_generation >= 1),
    operation TEXT NOT NULL CHECK (operation IN ('issue', 'rotate')),
    target_a TEXT NOT NULL CHECK (typeof(target_a) = 'text'
        AND length(target_a) BETWEEN 1 AND 128 AND instr(target_a, char(0)) = 0),
    target_b TEXT CHECK (target_b IS NULL OR (typeof(target_b) = 'text'
        AND length(target_b) BETWEEN 1 AND 128 AND instr(target_b, char(0)) = 0)),
    target_digest BLOB NOT NULL CHECK (typeof(target_digest) = 'blob'
        AND length(target_digest) = 32 AND target_digest <> zeroblob(32)),
    maintenance_proof_digest BLOB NOT NULL CHECK (
        typeof(maintenance_proof_digest) = 'blob' AND length(maintenance_proof_digest) = 32
        AND maintenance_proof_digest <> zeroblob(32)),
    deadline_at_us INTEGER NOT NULL CHECK (deadline_at_us > 0),
    disposition_id TEXT NOT NULL UNIQUE CHECK (typeof(disposition_id) = 'text'
        AND length(disposition_id) = 36 AND instr(disposition_id, char(0)) = 0),
    audit_id TEXT NOT NULL UNIQUE CHECK (typeof(audit_id) = 'text'
        AND length(audit_id) = 36 AND instr(audit_id, char(0)) = 0),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    CHECK (original_request_id <> cancellation_request_id
        AND original_request_id <> decision_request_id
        AND cancellation_request_id <> decision_request_id),
    CHECK (original_actor_subject_id <> current_actor_subject_id),
    CHECK ((operation = 'issue' AND target_b IS NOT NULL)
        OR (operation = 'rotate' AND target_b IS NULL)),
    CHECK ((resolution = 'committed_attention' AND binding_digest <> zeroblob(32)
            AND successor_credential_id IS NOT NULL
            AND successor_issuance_generation IS NOT NULL)
        OR (resolution = 'terminal_not_committed' AND binding_digest = zeroblob(32)
            AND successor_credential_id IS NULL
            AND successor_issuance_generation IS NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_service_handoff_cancellation_exact
    ON service_credential_handoff_cancellation_claims (
        original_request_id);

CREATE TABLE IF NOT EXISTS service_credential_handoff_remediation_actions (
    remediation_request_id TEXT NOT NULL PRIMARY KEY CHECK (
        typeof(remediation_request_id) = 'text' AND length(remediation_request_id) = 27
        AND instr(remediation_request_id, char(0)) = 0),
    request_fingerprint BLOB NOT NULL CHECK (typeof(request_fingerprint) = 'blob'
        AND length(request_fingerprint) = 32
        AND request_fingerprint <> zeroblob(32)),
    incident_fingerprint BLOB NOT NULL CHECK (
        typeof(incident_fingerprint) = 'blob' AND length(incident_fingerprint) = 32
        AND incident_fingerprint <> zeroblob(32)),
    decision_request_id TEXT NOT NULL UNIQUE CHECK (typeof(decision_request_id) = 'text'
        AND length(decision_request_id) = 27
        AND instr(decision_request_id, char(0)) = 0),
    original_request_id TEXT NOT NULL CHECK (typeof(original_request_id) = 'text'
        AND length(original_request_id) = 27 AND instr(original_request_id, char(0)) = 0),
    original_actor_subject_id TEXT NOT NULL CHECK (typeof(original_actor_subject_id) = 'text'
        AND length(original_actor_subject_id) BETWEEN 1 AND 128
        AND instr(original_actor_subject_id, char(0)) = 0),
    current_actor_subject_id TEXT NOT NULL CHECK (typeof(current_actor_subject_id) = 'text'
        AND length(current_actor_subject_id) BETWEEN 1 AND 128
        AND instr(current_actor_subject_id, char(0)) = 0),
    source_kind TEXT NOT NULL CHECK (
        source_kind IN ('committed_attention', 'operator_action_required')),
    journal_snapshot_digest BLOB NOT NULL CHECK (
        typeof(journal_snapshot_digest) = 'blob' AND length(journal_snapshot_digest) = 32
        AND journal_snapshot_digest <> zeroblob(32)),
    observed_state TEXT NOT NULL CHECK (observed_state IN ('server_committed',
        'publication_planned', 'publication_prepared', 'file_published',
        'cleanup_required', 'operator_action_required')),
    source_disposition_id TEXT CHECK (source_disposition_id IS NULL OR (
        typeof(source_disposition_id) = 'text' AND length(source_disposition_id) = 36
        AND instr(source_disposition_id, char(0)) = 0)),
    source_audit_id TEXT CHECK (source_audit_id IS NULL OR (
        typeof(source_audit_id) = 'text' AND length(source_audit_id) = 36
        AND instr(source_audit_id, char(0)) = 0)),
    source_reason TEXT CHECK (
        source_reason IS NULL OR source_reason IN ('operation_cancelled', 'operation_expired')),
    oar_source_state TEXT CHECK (oar_source_state IS NULL OR oar_source_state IN (
        'server_committed', 'publication_planned', 'publication_prepared',
        'file_published', 'cleanup_required')),
    oar_cause TEXT CHECK (oar_cause IS NULL OR oar_cause IN ('receipt_foreign',
        'receipt_uncertain', 'escrow_foreign', 'escrow_uncertain',
        'successor_revoked', 'successor_expired', 'explicit_hold', 'escrow_missing')),
    resume_target_state TEXT CHECK (resume_target_state IS NULL OR resume_target_state IN (
        'server_committed', 'publication_planned', 'publication_prepared',
        'file_published', 'cleanup_required')),
    escrow_id TEXT NOT NULL CHECK (typeof(escrow_id) = 'text'
        AND length(escrow_id) = 36 AND instr(escrow_id, char(0)) = 0),
    binding_digest BLOB NOT NULL CHECK (typeof(binding_digest) = 'blob'
        AND length(binding_digest) = 32 AND binding_digest <> zeroblob(32)),
    successor_credential_id TEXT NOT NULL CHECK (typeof(successor_credential_id) = 'text'
        AND length(successor_credential_id) = 31
        AND substr(successor_credential_id, 1, 4) = 'wlc_'
        AND instr(successor_credential_id, char(0)) = 0),
    successor_issuance_generation INTEGER NOT NULL CHECK (successor_issuance_generation >= 1),
    action TEXT NOT NULL CHECK (action IN ('resume', 'revoke_and_wipe')),
    confirmation_version INTEGER NOT NULL CHECK (confirmation_version IN (0, 1)),
    confirmed INTEGER NOT NULL CHECK (confirmed IN (0, 1)
        AND typeof(confirmed) = 'integer'),
    outcome TEXT NOT NULL CHECK (outcome IN ('recorded', 'revoked_and_wiped',
        'expired_and_wiped', 'already_revoked_and_wiped')),
    escrow_outcome TEXT NOT NULL CHECK (
        escrow_outcome IN ('retained', 'deleted', 'already_absent')),
    credential_generation_after INTEGER NOT NULL CHECK (credential_generation_after >= 1),
    revoke_event_id INTEGER CHECK (revoke_event_id IS NULL OR revoke_event_id > 0),
    revoke_event_generation INTEGER CHECK (
        revoke_event_generation IS NULL OR revoke_event_generation >= 1),
    revoke_event_request_id TEXT CHECK (revoke_event_request_id IS NULL OR (
        typeof(revoke_event_request_id) = 'text'
        AND length(revoke_event_request_id) BETWEEN 1 AND 256
        AND instr(revoke_event_request_id, char(0)) = 0)),
    revoke_event_actor_subject_id TEXT CHECK (revoke_event_actor_subject_id IS NULL OR (
        typeof(revoke_event_actor_subject_id) = 'text'
        AND length(revoke_event_actor_subject_id) BETWEEN 1 AND 128
        AND instr(revoke_event_actor_subject_id, char(0)) = 0)),
    revoke_event_created_at_us INTEGER CHECK (
        revoke_event_created_at_us IS NULL OR revoke_event_created_at_us > 0),
    audit_id TEXT NOT NULL UNIQUE CHECK (typeof(audit_id) = 'text'
        AND length(audit_id) = 36 AND instr(audit_id, char(0)) = 0),
    created_at_us INTEGER NOT NULL CHECK (created_at_us > 0),
    CHECK (original_request_id <> remediation_request_id
        AND original_request_id <> decision_request_id
        AND remediation_request_id <> decision_request_id),
    CHECK (original_actor_subject_id <> current_actor_subject_id),
    CHECK ((source_kind = 'committed_attention'
            AND observed_state IN ('server_committed', 'publication_planned',
                'publication_prepared', 'file_published', 'cleanup_required')
            AND source_disposition_id IS NOT NULL AND source_audit_id IS NOT NULL
            AND source_reason IS NOT NULL AND oar_source_state IS NULL
            AND oar_cause IS NULL AND resume_target_state IS NULL)
        OR (source_kind = 'operator_action_required'
            AND observed_state = 'operator_action_required'
            AND source_disposition_id IS NULL AND source_audit_id IS NULL
            AND source_reason IS NULL AND oar_source_state IS NOT NULL
            AND oar_cause IS NOT NULL
            AND resume_target_state = oar_source_state)),
    CHECK (NOT (oar_source_state = 'server_committed'
        AND oar_cause IN ('receipt_foreign', 'receipt_uncertain'))),
    CHECK (NOT (action = 'resume' AND oar_cause IN (
        'successor_revoked', 'successor_expired', 'escrow_missing'))),
    CHECK (escrow_outcome <> 'already_absent'
        OR (source_kind = 'operator_action_required'
            AND oar_cause = 'escrow_missing' AND action = 'revoke_and_wipe')),
    CHECK ((action = 'resume' AND confirmation_version = 0 AND confirmed = 0
            AND outcome = 'recorded' AND escrow_outcome = 'retained'
            AND credential_generation_after = successor_issuance_generation
            AND revoke_event_id IS NULL AND revoke_event_generation IS NULL
            AND revoke_event_request_id IS NULL AND revoke_event_actor_subject_id IS NULL
            AND revoke_event_created_at_us IS NULL)
        OR (action = 'revoke_and_wipe' AND confirmation_version = 1 AND confirmed = 1
            AND outcome IN ('revoked_and_wiped',
            'expired_and_wiped', 'already_revoked_and_wiped')
            AND escrow_outcome IN ('deleted', 'already_absent')
            AND ((outcome = 'expired_and_wiped'
                    AND credential_generation_after = successor_issuance_generation
                    AND revoke_event_id IS NULL AND revoke_event_generation IS NULL
                    AND revoke_event_request_id IS NULL
                    AND revoke_event_actor_subject_id IS NULL
                    AND revoke_event_created_at_us IS NULL)
                OR (outcome IN ('revoked_and_wiped', 'already_revoked_and_wiped')
                    AND successor_issuance_generation < 9223372036854775807
                    AND credential_generation_after = successor_issuance_generation + 1
                    AND revoke_event_id IS NOT NULL AND revoke_event_generation IS NOT NULL
                    AND revoke_event_generation = credential_generation_after
                    AND revoke_event_request_id IS NOT NULL
                    AND revoke_event_actor_subject_id IS NOT NULL
                    AND revoke_event_created_at_us IS NOT NULL
                    AND (outcome <> 'revoked_and_wiped'
                        OR (revoke_event_request_id = remediation_request_id
                            AND revoke_event_actor_subject_id = current_actor_subject_id
                            AND revoke_event_created_at_us = created_at_us))))))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_service_handoff_remediation_incident
    ON service_credential_handoff_remediation_actions (incident_fingerprint);

CREATE UNIQUE INDEX IF NOT EXISTS idx_service_handoff_completed_revoke
    ON service_credential_handoff_remediation_actions (
        original_request_id, escrow_id, binding_digest, successor_credential_id,
        successor_issuance_generation, action)
    WHERE action = 'revoke_and_wipe';

CREATE TABLE IF NOT EXISTS service_credential_handoff_retirement_receipts (
    original_request_id TEXT NOT NULL PRIMARY KEY CHECK (
        typeof(original_request_id) = 'text' AND length(original_request_id) = 27
        AND instr(original_request_id, char(0)) = 0),
    terminal_kind TEXT NOT NULL CHECK (
        terminal_kind IN ('file_published', 'operator_revoke_and_wipe')),
    raw_journal_snapshot_digest BLOB NOT NULL CHECK (
        typeof(raw_journal_snapshot_digest) = 'blob'
        AND length(raw_journal_snapshot_digest) = 32
        AND raw_journal_snapshot_digest <> zeroblob(32)),
    delivery_disposition_id TEXT CHECK (delivery_disposition_id IS NULL OR (
        typeof(delivery_disposition_id) = 'text'
        AND length(delivery_disposition_id) = 36
        AND instr(delivery_disposition_id, char(0)) = 0)),
    delivery_audit_id TEXT CHECK (delivery_audit_id IS NULL OR (
        typeof(delivery_audit_id) = 'text' AND length(delivery_audit_id) = 36
        AND instr(delivery_audit_id, char(0)) = 0)),
    delivery_proof_digest BLOB NOT NULL CHECK (
        typeof(delivery_proof_digest) = 'blob'
        AND length(delivery_proof_digest) = 32),
    revoke_remediation_request_id TEXT CHECK (
        revoke_remediation_request_id IS NULL OR (
        typeof(revoke_remediation_request_id) = 'text'
        AND length(revoke_remediation_request_id) = 27
        AND instr(revoke_remediation_request_id, char(0)) = 0)),
    revoke_audit_id TEXT CHECK (revoke_audit_id IS NULL OR (
        typeof(revoke_audit_id) = 'text' AND length(revoke_audit_id) = 36
        AND instr(revoke_audit_id, char(0)) = 0)),
    revoke_event_id INTEGER CHECK (revoke_event_id IS NULL OR revoke_event_id > 0),
    resume_remediation_request_id TEXT CHECK (
        resume_remediation_request_id IS NULL OR (
        typeof(resume_remediation_request_id) = 'text'
        AND length(resume_remediation_request_id) = 27
        AND instr(resume_remediation_request_id, char(0)) = 0)),
    resume_audit_id TEXT CHECK (resume_audit_id IS NULL OR (
        typeof(resume_audit_id) = 'text' AND length(resume_audit_id) = 36
        AND instr(resume_audit_id, char(0)) = 0)),
    remediation_source_snapshot_digest BLOB CHECK (
        remediation_source_snapshot_digest IS NULL OR (
        typeof(remediation_source_snapshot_digest) = 'blob'
        AND length(remediation_source_snapshot_digest) = 32
        AND remediation_source_snapshot_digest <> zeroblob(32))),
    remediation_request_fingerprint BLOB CHECK (
        remediation_request_fingerprint IS NULL OR (
        typeof(remediation_request_fingerprint) = 'blob'
        AND length(remediation_request_fingerprint) = 32
        AND remediation_request_fingerprint <> zeroblob(32))),
    retention_basis_at_us INTEGER NOT NULL CHECK (retention_basis_at_us > 0),
    retired_at_us INTEGER NOT NULL CHECK (
        retired_at_us >= retention_basis_at_us
        AND retired_at_us - retention_basis_at_us >= 2592000000000),
    CHECK (
        (terminal_kind = 'file_published'
            AND delivery_disposition_id IS NOT NULL
            AND delivery_audit_id IS NOT NULL
            AND delivery_proof_digest <> zeroblob(32)
            AND revoke_remediation_request_id IS NULL
            AND revoke_audit_id IS NULL AND revoke_event_id IS NULL
            AND ((resume_remediation_request_id IS NULL
                    AND resume_audit_id IS NULL
                    AND remediation_source_snapshot_digest IS NULL
                    AND remediation_request_fingerprint IS NULL)
                OR (resume_remediation_request_id IS NOT NULL
                    AND resume_audit_id IS NOT NULL
                    AND remediation_source_snapshot_digest <> zeroblob(32)
                    AND remediation_request_fingerprint <> zeroblob(32))))
        OR (terminal_kind = 'operator_revoke_and_wipe'
            AND delivery_disposition_id IS NULL AND delivery_audit_id IS NULL
            AND delivery_proof_digest = zeroblob(32)
            AND revoke_remediation_request_id IS NOT NULL
            AND revoke_audit_id IS NOT NULL
            AND resume_remediation_request_id IS NULL
            AND resume_audit_id IS NULL
            AND remediation_source_snapshot_digest <> zeroblob(32)
            AND remediation_request_fingerprint <> zeroblob(32)))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_service_handoff_retirement_raw
    ON service_credential_handoff_retirement_receipts
        (raw_journal_snapshot_digest);
CREATE UNIQUE INDEX IF NOT EXISTS idx_service_handoff_retirement_delivery
    ON service_credential_handoff_retirement_receipts
        (delivery_disposition_id) WHERE delivery_disposition_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_service_handoff_retirement_revoke
    ON service_credential_handoff_retirement_receipts
        (revoke_remediation_request_id)
    WHERE revoke_remediation_request_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_service_handoff_retirement_resume
    ON service_credential_handoff_retirement_receipts
        (resume_remediation_request_id)
    WHERE resume_remediation_request_id IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS trg_service_exchange_audit_no_update
BEFORE UPDATE ON service_exchange_audit_intentions
BEGIN
    SELECT RAISE(ABORT, 'service exchange audit intentions are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_exchange_audit_no_delete
BEFORE DELETE ON service_exchange_audit_intentions
BEGIN
    SELECT RAISE(ABORT, 'service exchange audit intentions are append-only');
END;

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

CREATE TRIGGER IF NOT EXISTS trg_service_credential_operation_fences_no_update
BEFORE UPDATE ON service_credential_operation_fences
BEGIN
    SELECT RAISE(ABORT, 'service credential operation fences are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_credential_operation_fences_no_delete
BEFORE DELETE ON service_credential_operation_fences
BEGIN
    SELECT RAISE(ABORT, 'service credential operation fences are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_handoff_dispositions_no_update
BEFORE UPDATE ON service_credential_handoff_dispositions
BEGIN
    SELECT RAISE(ABORT, 'service credential handoff dispositions are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_handoff_dispositions_no_delete
BEFORE DELETE ON service_credential_handoff_dispositions
BEGIN
    SELECT RAISE(ABORT, 'service credential handoff dispositions are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_handoff_cancellation_no_update
BEFORE UPDATE ON service_credential_handoff_cancellation_claims
BEGIN
    SELECT RAISE(ABORT, 'service credential handoff cancellation claims are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_handoff_cancellation_no_delete
BEFORE DELETE ON service_credential_handoff_cancellation_claims
BEGIN
    SELECT RAISE(ABORT, 'service credential handoff cancellation claims are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_handoff_cancellation_no_legacy_collision
BEFORE INSERT ON service_credential_handoff_cancellation_claims
WHEN EXISTS (
    SELECT 1 FROM service_domain_requests
    WHERE request_id = NEW.cancellation_request_id
)
BEGIN
    SELECT RAISE(ABORT, 'service handoff cancellation request collides with service domain request');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_handoff_cancellation_no_remediation_collision
BEFORE INSERT ON service_credential_handoff_cancellation_claims
WHEN EXISTS (
    SELECT 1 FROM service_credential_handoff_remediation_actions
    WHERE remediation_request_id = NEW.cancellation_request_id
)
BEGIN
    SELECT RAISE(ABORT, 'service handoff cancellation request collides with remediation request');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_handoff_remediation_no_update
BEFORE UPDATE ON service_credential_handoff_remediation_actions
BEGIN
    SELECT RAISE(ABORT, 'service credential handoff remediation actions are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_handoff_remediation_no_delete
BEFORE DELETE ON service_credential_handoff_remediation_actions
BEGIN
    SELECT RAISE(ABORT, 'service credential handoff remediation actions are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_handoff_remediation_no_legacy_collision
BEFORE INSERT ON service_credential_handoff_remediation_actions
WHEN EXISTS (
    SELECT 1 FROM service_domain_requests
    WHERE request_id = NEW.remediation_request_id
)
BEGIN
    SELECT RAISE(ABORT, 'service handoff remediation request collides with service domain request');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_handoff_remediation_no_cancellation_collision
BEFORE INSERT ON service_credential_handoff_remediation_actions
WHEN EXISTS (
    SELECT 1 FROM service_credential_handoff_cancellation_claims
    WHERE cancellation_request_id = NEW.remediation_request_id
)
BEGIN
    SELECT RAISE(ABORT, 'service handoff remediation request collides with cancellation request');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_handoff_retirement_no_update
BEFORE UPDATE ON service_credential_handoff_retirement_receipts
BEGIN
    SELECT RAISE(ABORT, 'service credential handoff retirement receipts are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_handoff_retirement_no_delete
BEFORE DELETE ON service_credential_handoff_retirement_receipts
BEGIN
    SELECT RAISE(ABORT, 'service credential handoff retirement receipts are permanent');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_domain_requests_no_remediation_collision
BEFORE INSERT ON service_domain_requests
WHEN EXISTS (
    SELECT 1 FROM service_credential_handoff_remediation_actions
    WHERE remediation_request_id = NEW.request_id
)
BEGIN
    SELECT RAISE(ABORT, 'service domain request collides with service handoff remediation request');
END;

CREATE TRIGGER IF NOT EXISTS trg_service_domain_requests_no_cancellation_collision
BEFORE INSERT ON service_domain_requests
WHEN EXISTS (
    SELECT 1 FROM service_credential_handoff_cancellation_claims
    WHERE cancellation_request_id = NEW.request_id
)
BEGIN
    SELECT RAISE(ABORT, 'service domain request collides with service handoff cancellation request');
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

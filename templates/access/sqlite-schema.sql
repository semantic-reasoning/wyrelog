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
    subject_id TEXT PRIMARY KEY,
    state      TEXT    NOT NULL,
    updated_at INTEGER
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

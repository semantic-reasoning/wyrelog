-- wyrelog SQLite Schema (Phase 1)
-- Role: Policy Authority (Single Source of Truth)
-- Storage: ACID, single-writer (Platform team), Ed25519-signed
-- Reference: internal-discussion/FACT-STORAGE-ARCHITECTURE.md

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

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

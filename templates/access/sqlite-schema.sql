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

-- wyrelog DuckDB Schema (Phase 1)
-- Role: Context EDB + Policy Replica + Audit Log
-- Storage: Columnar, MVCC, high-concurrency reads
-- Reference: internal-discussion/FACT-STORAGE-ARCHITECTURE.md

-- ---------------------------------------------------------------------------
-- Table: policy_replica
-- Read-only replica of SQLite policy authority.
-- Populated by GIO inotify trigger -> differential.advance_to().
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_replica (
    role_id        TEXT    NOT NULL,
    perm_id        TEXT    NOT NULL,
    perm_class     TEXT    NOT NULL CHECK (perm_class IN ('basic', 'sensitive', 'critical')),
    replicated_at  INTEGER NOT NULL,  -- Unix epoch; pivot for differential.advance_to()
    PRIMARY KEY (role_id, perm_id)
);

CREATE INDEX IF NOT EXISTS idx_policy_replica_role
    ON policy_replica (role_id);

CREATE INDEX IF NOT EXISTS idx_policy_replica_perm
    ON policy_replica (perm_id);

CREATE INDEX IF NOT EXISTS idx_policy_replica_replicated
    ON policy_replica (replicated_at);

-- ---------------------------------------------------------------------------
-- Table: context_facts
-- Session-scoped EDB (Extensional Database) for Datalog evaluation.
-- FSM S2 INGEST_CTX inserts rows; TTL enforced at query time.
-- Dimensions (Phase 1): 'time', 'location', 'sensitivity'
--             (Phase 2): 'user_state', 'action_class'
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS context_facts (
    session_id  TEXT    NOT NULL,
    dimension   TEXT    NOT NULL,  -- context dimension identifier
    value       TEXT    NOT NULL,
    timestamp   INTEGER NOT NULL,  -- Unix epoch (seconds)
    ttl_seconds INTEGER,           -- NULL = no expiry
    PRIMARY KEY (session_id, dimension, value)
);

CREATE INDEX IF NOT EXISTS idx_context_facts_session
    ON context_facts (session_id);

CREATE INDEX IF NOT EXISTS idx_context_facts_timestamp
    ON context_facts (timestamp);

-- ---------------------------------------------------------------------------
-- Table: audit_events
-- Runtime audit sink used by libwyrelog. The id is minted by the host and
-- created_at_us carries a microsecond wall-clock timestamp.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_events (
    id            VARCHAR PRIMARY KEY,
    created_at_us BIGINT  NOT NULL,
    subject_id    VARCHAR,
    action        VARCHAR,
    resource_id   VARCHAR,
    deny_reason   VARCHAR,
    deny_origin   VARCHAR,
    decision      SMALLINT NOT NULL
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
-- Table: cache
-- In-process LRU decision cache. Invalidated on policy change.
-- p99 cache hit target: <2ms; p99 cache miss (DuckDB): <5ms.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cache (
    cache_key    TEXT    PRIMARY KEY,   -- "user_id:perm_id:scope"
    cached_value BLOB,                  -- serialised WrCtxFsmResult
    expires_at   INTEGER,               -- Unix epoch; NULL = no expiry
    hit_count    INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_cache_expires_at
    ON cache (expires_at);

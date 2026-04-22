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
-- Table: audit_log
-- Append-only WORM ledger. Written by FSM S6 COMMIT.
-- Merkle chain: each row seals the hash of the previous event.
-- TSA response attached asynchronously after insertion.
-- ---------------------------------------------------------------------------
CREATE SEQUENCE IF NOT EXISTS audit_log_seq START 1;

CREATE TABLE IF NOT EXISTS audit_log (
    event_id     INTEGER     PRIMARY KEY DEFAULT nextval('audit_log_seq'),
    timestamp    INTEGER     NOT NULL,   -- Unix epoch (seconds)
    user_id      TEXT        NOT NULL,
    operation    TEXT        NOT NULL,   -- e.g. 'authorize', 'deny', 'stepup'
    resource     TEXT,                   -- target resource identifier
    decision     TEXT,                   -- 'grant', 'deny', 'stepup', 'approval'
    seal_merkle  BLOB,                   -- Merkle hash chain (previous || current)
    tsa_response BLOB,                   -- TSA timestamp authority response (async)
    created_at   INTEGER     NOT NULL    -- wall-clock insertion time
);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp
    ON audit_log (timestamp);

CREATE INDEX IF NOT EXISTS idx_audit_log_user_id
    ON audit_log (user_id);

CREATE INDEX IF NOT EXISTS idx_audit_log_decision
    ON audit_log (decision);

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

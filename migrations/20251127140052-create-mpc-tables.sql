-- +migrate Up
-- 创建 audit_logs 表（如果尚未存在）
CREATE TABLE IF NOT EXISTS audit_logs (
    id bigserial PRIMARY KEY,
    timestamp timestamptz NOT NULL DEFAULT NOW(),
    event_type varchar(50) NOT NULL,
    user_id varchar(255),
    key_id varchar(255),
    node_id varchar(255),
    session_id varchar(255),
    operation varchar(50) NOT NULL,
    result varchar(50) NOT NULL,
    details jsonb,
    ip_address varchar(50)
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs (timestamp);

CREATE INDEX IF NOT EXISTS idx_audit_key_id ON audit_logs (key_id);

CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_logs (user_id);

CREATE TABLE keys (
    key_id varchar(255) PRIMARY KEY,
    public_key text NOT NULL,
    algorithm varchar(50) NOT NULL,
    curve varchar(50) NOT NULL,
    threshold integer NOT NULL,
    total_nodes integer NOT NULL,
    chain_type varchar(50) NOT NULL,
    address text,
    status varchar(50) NOT NULL,
    description text,
    tags jsonb,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW(),
    deletion_date timestamptz
);

CREATE INDEX idx_keys_chain_type ON keys (chain_type);

CREATE INDEX idx_keys_status ON keys (status);

CREATE INDEX idx_keys_created_at ON keys (created_at);

CREATE TABLE nodes (
    node_id varchar(255) PRIMARY KEY,
    node_type varchar(50) NOT NULL,
    endpoint varchar(255) NOT NULL,
    public_key text,
    status varchar(50) NOT NULL,
    capabilities jsonb,
    metadata jsonb,
    registered_at timestamptz NOT NULL DEFAULT NOW(),
    last_heartbeat timestamptz
);

CREATE INDEX idx_nodes_type ON nodes (node_type);

CREATE INDEX idx_nodes_status ON nodes (status);

CREATE TABLE signing_sessions (
    session_id varchar(255) PRIMARY KEY,
    key_id varchar(255) NOT NULL,
    protocol varchar(50) NOT NULL,
    status varchar(50) NOT NULL,
    threshold integer NOT NULL,
    total_nodes integer NOT NULL,
    participating_nodes jsonb,
    current_round integer DEFAULT 0,
    total_rounds integer NOT NULL,
    signature text,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    completed_at timestamptz,
    duration_ms integer,
    FOREIGN KEY (key_id) REFERENCES keys (key_id) ON DELETE CASCADE
);

CREATE INDEX idx_sessions_key_id ON signing_sessions (key_id);

CREATE INDEX idx_sessions_status ON signing_sessions (status);

CREATE INDEX idx_sessions_created_at ON signing_sessions (created_at);

-- 扩展audit_logs表，添加node_id和session_id字段
ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS node_id VARCHAR(255);

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS session_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_audit_node_id ON audit_logs (node_id);

CREATE INDEX IF NOT EXISTS idx_audit_session_id ON audit_logs (session_id);

-- +migrate Down
DROP INDEX IF EXISTS idx_audit_timestamp;

DROP INDEX IF EXISTS idx_audit_key_id;

DROP INDEX IF EXISTS idx_audit_user_id;

DROP INDEX IF EXISTS idx_audit_session_id;

DROP INDEX IF EXISTS idx_audit_node_id;

DROP TABLE IF EXISTS signing_sessions;

DROP TABLE IF EXISTS nodes;

DROP INDEX IF EXISTS idx_keys_created_at;

DROP INDEX IF EXISTS idx_keys_status;

DROP INDEX IF EXISTS idx_keys_chain_type;

DROP TABLE IF EXISTS keys;

ALTER TABLE audit_logs
    DROP COLUMN IF EXISTS session_id;

ALTER TABLE audit_logs
    DROP COLUMN IF EXISTS node_id;


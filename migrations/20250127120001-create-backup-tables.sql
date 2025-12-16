-- +migrate Up
-- 创建备份分片表（每个MPC分片有多个SSS备份分片）
CREATE TABLE IF NOT EXISTS backup_shares (
    id BIGSERIAL PRIMARY KEY,
    key_id VARCHAR(255) NOT NULL,
    node_id VARCHAR(255) NOT NULL, -- MPC节点ID（server-proxy-1, server-proxy-2, client-{userID}）
    share_index INTEGER NOT NULL,  -- 备份分片索引（1-5）
    share_data BYTEA NOT NULL,      -- 备份分片数据（加密存储）
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (key_id) REFERENCES keys(key_id) ON DELETE CASCADE,
    UNIQUE(key_id, node_id, share_index)
);

CREATE INDEX IF NOT EXISTS idx_backup_shares_key_node ON backup_shares(key_id, node_id);
CREATE INDEX IF NOT EXISTS idx_backup_shares_key ON backup_shares(key_id);

-- 创建备份分片下发记录表
CREATE TABLE IF NOT EXISTS backup_share_deliveries (
    id BIGSERIAL PRIMARY KEY,
    key_id VARCHAR(255) NOT NULL,
    node_id VARCHAR(255) NOT NULL, -- MPC节点ID
    user_id VARCHAR(255) NOT NULL,
    share_index INTEGER NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, delivered, confirmed, failed
    delivered_at TIMESTAMPTZ,
    confirmed_at TIMESTAMPTZ,
    failure_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (key_id) REFERENCES keys(key_id) ON DELETE CASCADE,
    UNIQUE(key_id, node_id, share_index, user_id)
);

CREATE INDEX IF NOT EXISTS idx_backup_deliveries_key_node ON backup_share_deliveries(key_id, node_id);
CREATE INDEX IF NOT EXISTS idx_backup_deliveries_user ON backup_share_deliveries(user_id);

-- +migrate Down
DROP INDEX IF EXISTS idx_backup_deliveries_user;
DROP INDEX IF EXISTS idx_backup_deliveries_key_node;
DROP TABLE IF EXISTS backup_share_deliveries;
DROP INDEX IF EXISTS idx_backup_shares_key;
DROP INDEX IF EXISTS idx_backup_shares_key_node;
DROP TABLE IF EXISTS backup_shares;


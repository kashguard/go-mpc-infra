-- +migrate Up
-- 添加 purpose 字段到 nodes 表
ALTER TABLE nodes
    ADD COLUMN IF NOT EXISTS purpose VARCHAR(50) DEFAULT 'signing';

-- 更新现有节点：participant 节点默认为 signing，client 节点为 backup
UPDATE nodes
SET purpose = 'signing'
WHERE node_type = 'participant' AND (purpose IS NULL OR purpose = '');

UPDATE nodes
SET purpose = 'backup'
WHERE node_type = 'client' AND (purpose IS NULL OR purpose = '');

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_nodes_purpose ON nodes (purpose);

-- +migrate Down
DROP INDEX IF EXISTS idx_nodes_purpose;
ALTER TABLE nodes
    DROP COLUMN IF EXISTS purpose;


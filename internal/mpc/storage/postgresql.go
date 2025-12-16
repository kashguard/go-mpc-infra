package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/pkg/errors"
)

// PostgreSQLStore PostgreSQL存储实现
type PostgreSQLStore struct {
	db *sql.DB
}

// NewPostgreSQLStore 创建PostgreSQL存储实例
func NewPostgreSQLStore(db *sql.DB) MetadataStore {
	return &PostgreSQLStore{db: db}
}

// SaveKeyMetadata 保存密钥元数据
func (s *PostgreSQLStore) SaveKeyMetadata(ctx context.Context, key *KeyMetadata) error {
	tagsJSON, err := json.Marshal(key.Tags)
	if err != nil {
		return errors.Wrap(err, "failed to marshal tags")
	}

	query := `
		INSERT INTO keys (
			key_id, public_key, algorithm, curve, threshold, total_nodes,
			chain_type, address, status, description, tags, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (key_id) DO UPDATE SET
			public_key = EXCLUDED.public_key,
			algorithm = EXCLUDED.algorithm,
			curve = EXCLUDED.curve,
			threshold = EXCLUDED.threshold,
			total_nodes = EXCLUDED.total_nodes,
			chain_type = EXCLUDED.chain_type,
			address = EXCLUDED.address,
			status = EXCLUDED.status,
			description = EXCLUDED.description,
			tags = EXCLUDED.tags,
			updated_at = EXCLUDED.updated_at
	`

	result, err := s.db.ExecContext(ctx, query,
		key.KeyID, key.PublicKey, key.Algorithm, key.Curve, key.Threshold, key.TotalNodes,
		key.ChainType, key.Address, key.Status, key.Description, tagsJSON,
		key.CreatedAt, key.UpdatedAt,
	)
	if err != nil {
		return errors.Wrapf(err, "failed to save key metadata for key_id: %s", key.KeyID)
	}

	// 验证插入是否成功
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "failed to get rows affected")
	}
	if rowsAffected == 0 {
		return errors.Errorf("no rows affected when saving key metadata for key_id: %s", key.KeyID)
	}

	return nil
}

// GetKeyMetadata 获取密钥元数据
func (s *PostgreSQLStore) GetKeyMetadata(ctx context.Context, keyID string) (*KeyMetadata, error) {
	query := `
		SELECT key_id, public_key, algorithm, curve, threshold, total_nodes,
			chain_type, address, status, description, tags, created_at, updated_at, deletion_date
		FROM keys
		WHERE key_id = $1
	`

	var key KeyMetadata
	var tagsJSON []byte
	var deletionDate sql.NullTime

	err := s.db.QueryRowContext(ctx, query, keyID).Scan(
		&key.KeyID, &key.PublicKey, &key.Algorithm, &key.Curve, &key.Threshold, &key.TotalNodes,
		&key.ChainType, &key.Address, &key.Status, &key.Description, &tagsJSON,
		&key.CreatedAt, &key.UpdatedAt, &deletionDate,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("key not found")
		}
		return nil, errors.Wrap(err, "failed to get key metadata")
	}

	if len(tagsJSON) > 0 {
		if err := json.Unmarshal(tagsJSON, &key.Tags); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal tags")
		}
	}
	if tagsJSON == nil {
		key.Tags = make(map[string]string)
	}

	if deletionDate.Valid {
		key.DeletionDate = &deletionDate.Time
	}

	return &key, nil
}

// UpdateKeyMetadata 更新密钥元数据
func (s *PostgreSQLStore) UpdateKeyMetadata(ctx context.Context, key *KeyMetadata) error {
	tagsJSON, err := json.Marshal(key.Tags)
	if err != nil {
		return errors.Wrap(err, "failed to marshal tags")
	}

	query := `
		UPDATE keys SET
			public_key = $2,
			algorithm = $3,
			curve = $4,
			threshold = $5,
			total_nodes = $6,
			chain_type = $7,
			address = $8,
			status = $9,
			description = $10,
			tags = $11,
			updated_at = $12,
			deletion_date = $13
		WHERE key_id = $1
	`

	var deletionDate interface{}
	if key.DeletionDate != nil {
		deletionDate = *key.DeletionDate
	}

	_, err = s.db.ExecContext(ctx, query,
		key.KeyID, key.PublicKey, key.Algorithm, key.Curve, key.Threshold, key.TotalNodes,
		key.ChainType, key.Address, key.Status, key.Description, tagsJSON,
		key.UpdatedAt, deletionDate,
	)
	if err != nil {
		return errors.Wrap(err, "failed to update key metadata")
	}

	return nil
}

// DeleteKeyMetadata 删除密钥元数据
func (s *PostgreSQLStore) DeleteKeyMetadata(ctx context.Context, keyID string) error {
	query := `DELETE FROM keys WHERE key_id = $1`
	_, err := s.db.ExecContext(ctx, query, keyID)
	if err != nil {
		return errors.Wrap(err, "failed to delete key metadata")
	}
	return nil
}

// ListKeys 列出密钥
func (s *PostgreSQLStore) ListKeys(ctx context.Context, filter *KeyFilter) ([]*KeyMetadata, error) {
	if filter == nil {
		filter = &KeyFilter{Limit: 50}
	}
	if filter.Limit <= 0 {
		filter.Limit = 50
	}

	query := `SELECT key_id, public_key, algorithm, curve, threshold, total_nodes,
		chain_type, address, status, description, tags, created_at, updated_at, deletion_date
		FROM keys WHERE 1=1`
	args := []interface{}{}
	argIndex := 1

	if filter.ChainType != "" {
		query += ` AND chain_type = $` + string(rune('0'+argIndex))
		args = append(args, filter.ChainType)
		argIndex++
	}

	if filter.Status != "" {
		query += ` AND status = $` + string(rune('0'+argIndex))
		args = append(args, filter.Status)
		argIndex++
	}

	query += ` ORDER BY created_at DESC LIMIT $` + string(rune('0'+argIndex)) + ` OFFSET $` + string(rune('0'+argIndex+1))
	args = append(args, filter.Limit, filter.Offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list keys")
	}
	defer rows.Close()

	var keys []*KeyMetadata
	for rows.Next() {
		var key KeyMetadata
		var tagsJSON []byte
		var deletionDate sql.NullTime

		err := rows.Scan(
			&key.KeyID, &key.PublicKey, &key.Algorithm, &key.Curve, &key.Threshold, &key.TotalNodes,
			&key.ChainType, &key.Address, &key.Status, &key.Description, &tagsJSON,
			&key.CreatedAt, &key.UpdatedAt, &deletionDate,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan key")
		}

		if len(tagsJSON) > 0 {
			if err := json.Unmarshal(tagsJSON, &key.Tags); err != nil {
				return nil, errors.Wrap(err, "failed to unmarshal tags")
			}
		}
		if tagsJSON == nil {
			key.Tags = make(map[string]string)
		}

		if deletionDate.Valid {
			key.DeletionDate = &deletionDate.Time
		}

		keys = append(keys, &key)
	}

	return keys, nil
}

// SaveNode 保存节点信息
func (s *PostgreSQLStore) SaveNode(ctx context.Context, node *NodeInfo) error {
	capabilitiesJSON, err := json.Marshal(node.Capabilities)
	if err != nil {
		return errors.Wrap(err, "failed to marshal capabilities")
	}

	metadataJSON, err := json.Marshal(node.Metadata)
	if err != nil {
		return errors.Wrap(err, "failed to marshal metadata")
	}

	// 设置默认 purpose
	purpose := node.Purpose
	if purpose == "" {
		if node.NodeType == "client" {
			purpose = "backup"
		} else {
			purpose = "signing"
		}
	}

	query := `
		INSERT INTO nodes (
			node_id, node_type, purpose, endpoint, public_key, status, capabilities, metadata,
			registered_at, last_heartbeat
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (node_id) DO UPDATE SET
			node_type = EXCLUDED.node_type,
			purpose = EXCLUDED.purpose,
			endpoint = EXCLUDED.endpoint,
			public_key = EXCLUDED.public_key,
			status = EXCLUDED.status,
			capabilities = EXCLUDED.capabilities,
			metadata = EXCLUDED.metadata,
			last_heartbeat = EXCLUDED.last_heartbeat
	`

	_, err = s.db.ExecContext(ctx, query,
		node.NodeID, node.NodeType, purpose, node.Endpoint, node.PublicKey, node.Status,
		capabilitiesJSON, metadataJSON, node.RegisteredAt, node.LastHeartbeat,
	)
	if err != nil {
		return errors.Wrap(err, "failed to save node")
	}

	return nil
}

// GetNode 获取节点信息
func (s *PostgreSQLStore) GetNode(ctx context.Context, nodeID string) (*NodeInfo, error) {
	query := `
		SELECT node_id, node_type, purpose, endpoint, public_key, status, capabilities, metadata,
			registered_at, last_heartbeat
		FROM nodes
		WHERE node_id = $1
	`

	var node NodeInfo
	var capabilitiesJSON []byte
	var metadataJSON []byte
	var lastHeartbeat sql.NullTime
	var publicKey sql.NullString // ✅ 使用 sql.NullString 处理 NULL 值
	var purpose sql.NullString

	err := s.db.QueryRowContext(ctx, query, nodeID).Scan(
		&node.NodeID, &node.NodeType, &purpose, &node.Endpoint, &publicKey, &node.Status,
		&capabilitiesJSON, &metadataJSON, &node.RegisteredAt, &lastHeartbeat,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("node not found")
		}
		return nil, errors.Wrap(err, "failed to get node")
	}

	// ✅ 处理 NULL public_key
	if publicKey.Valid {
		node.PublicKey = publicKey.String
	} else {
		node.PublicKey = ""
	}

	// ✅ 处理 NULL purpose
	if purpose.Valid {
		node.Purpose = purpose.String
	} else {
		// 设置默认值
		if node.NodeType == "client" {
			node.Purpose = "backup"
		} else {
			node.Purpose = "signing"
		}
	}

	if len(capabilitiesJSON) > 0 {
		if err := json.Unmarshal(capabilitiesJSON, &node.Capabilities); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal capabilities")
		}
	}
	if capabilitiesJSON == nil {
		node.Capabilities = []string{}
	}

	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &node.Metadata); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal metadata")
		}
	}
	if metadataJSON == nil {
		node.Metadata = make(map[string]interface{})
	}

	if lastHeartbeat.Valid {
		node.LastHeartbeat = &lastHeartbeat.Time
	}

	return &node, nil
}

// UpdateNode 更新节点信息
func (s *PostgreSQLStore) UpdateNode(ctx context.Context, node *NodeInfo) error {
	capabilitiesJSON, err := json.Marshal(node.Capabilities)
	if err != nil {
		return errors.Wrap(err, "failed to marshal capabilities")
	}

	metadataJSON, err := json.Marshal(node.Metadata)
	if err != nil {
		return errors.Wrap(err, "failed to marshal metadata")
	}

	// 设置默认 purpose
	purpose := node.Purpose
	if purpose == "" {
		if node.NodeType == "client" {
			purpose = "backup"
		} else {
			purpose = "signing"
		}
	}

	query := `
		UPDATE nodes SET
			node_type = $2,
			purpose = $3,
			endpoint = $4,
			public_key = $5,
			status = $6,
			capabilities = $7,
			metadata = $8,
			last_heartbeat = $9
		WHERE node_id = $1
	`

	_, err = s.db.ExecContext(ctx, query,
		node.NodeID, node.NodeType, purpose, node.Endpoint, node.PublicKey, node.Status,
		capabilitiesJSON, metadataJSON, node.LastHeartbeat,
	)
	if err != nil {
		return errors.Wrap(err, "failed to update node")
	}

	return nil
}

// ListNodes 列出节点
func (s *PostgreSQLStore) ListNodes(ctx context.Context, filter *NodeFilter) ([]*NodeInfo, error) {
	if filter == nil {
		filter = &NodeFilter{Limit: 50}
	}
	if filter.Limit <= 0 {
		filter.Limit = 50
	}

	query := `SELECT node_id, node_type, purpose, endpoint, public_key, status, capabilities, metadata,
		registered_at, last_heartbeat
		FROM nodes WHERE 1=1`
	args := []interface{}{}
	argIndex := 1

	if filter.NodeType != "" {
		query += ` AND node_type = $` + string(rune('0'+argIndex))
		args = append(args, filter.NodeType)
		argIndex++
	}

	if filter.Status != "" {
		query += ` AND status = $` + string(rune('0'+argIndex))
		args = append(args, filter.Status)
		argIndex++
	}

	query += ` ORDER BY registered_at DESC LIMIT $` + string(rune('0'+argIndex)) + ` OFFSET $` + string(rune('0'+argIndex+1))
	args = append(args, filter.Limit, filter.Offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list nodes")
	}
	defer rows.Close()

	var nodes []*NodeInfo
	for rows.Next() {
		var node NodeInfo
		var capabilitiesJSON []byte
		var metadataJSON []byte
		var lastHeartbeat sql.NullTime
		var publicKey sql.NullString // ✅ 使用 sql.NullString 处理 NULL 值
		var purpose sql.NullString

		err := rows.Scan(
			&node.NodeID, &node.NodeType, &purpose, &node.Endpoint, &publicKey, &node.Status,
			&capabilitiesJSON, &metadataJSON, &node.RegisteredAt, &lastHeartbeat,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan node")
		}

		// ✅ 处理 NULL public_key
		if publicKey.Valid {
			node.PublicKey = publicKey.String
		} else {
			node.PublicKey = ""
		}

		// ✅ 处理 NULL purpose
		if purpose.Valid {
			node.Purpose = purpose.String
		} else {
			// 设置默认值
			if node.NodeType == "client" {
				node.Purpose = "backup"
			} else {
				node.Purpose = "signing"
			}
		}

		if len(capabilitiesJSON) > 0 {
			if err := json.Unmarshal(capabilitiesJSON, &node.Capabilities); err != nil {
				return nil, errors.Wrap(err, "failed to unmarshal capabilities")
			}
		}
		if capabilitiesJSON == nil {
			node.Capabilities = []string{}
		}

		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &node.Metadata); err != nil {
				return nil, errors.Wrap(err, "failed to unmarshal metadata")
			}
		}
		if metadataJSON == nil {
			node.Metadata = make(map[string]interface{})
		}

		if lastHeartbeat.Valid {
			node.LastHeartbeat = &lastHeartbeat.Time
		}

		nodes = append(nodes, &node)
	}

	return nodes, nil
}

// UpdateNodeHeartbeat 更新节点心跳
func (s *PostgreSQLStore) UpdateNodeHeartbeat(ctx context.Context, nodeID string) error {
	query := `UPDATE nodes SET last_heartbeat = NOW() WHERE node_id = $1`
	_, err := s.db.ExecContext(ctx, query, nodeID)
	if err != nil {
		return errors.Wrap(err, "failed to update node heartbeat")
	}
	return nil
}

// SaveSigningSession 保存签名会话
func (s *PostgreSQLStore) SaveSigningSession(ctx context.Context, session *SigningSession) error {
	// 记录保存的节点列表（用于调试）
	// 注意：storage 包没有导入 log，所以我们不能在这里记录日志
	// 但我们可以通过返回错误来提供信息

	participatingNodesJSON, err := json.Marshal(session.ParticipatingNodes)
	if err != nil {
		return errors.Wrap(err, "failed to marshal participating nodes")
	}

	query := `
		INSERT INTO signing_sessions (
			session_id, key_id, protocol, status, threshold, total_nodes,
			participating_nodes, current_round, total_rounds, signature,
			created_at, completed_at, duration_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (session_id) DO UPDATE SET
			key_id = EXCLUDED.key_id,
			protocol = EXCLUDED.protocol,
			status = EXCLUDED.status,
			threshold = EXCLUDED.threshold,
			total_nodes = EXCLUDED.total_nodes,
			participating_nodes = EXCLUDED.participating_nodes,
			current_round = EXCLUDED.current_round,
			total_rounds = EXCLUDED.total_rounds,
			signature = EXCLUDED.signature,
			completed_at = EXCLUDED.completed_at,
			duration_ms = EXCLUDED.duration_ms
	`

	var completedAt interface{}
	if session.CompletedAt != nil {
		completedAt = *session.CompletedAt
	}

	// 首先验证 key_id 是否存在（在同一个事务/连接中检查，避免事务隔离问题）
	var keyExists bool
	checkQuery := `SELECT EXISTS(SELECT 1 FROM keys WHERE key_id = $1)`
	if err := s.db.QueryRowContext(ctx, checkQuery, session.KeyID).Scan(&keyExists); err != nil {
		// 如果查询失败，返回更详细的错误信息
		return errors.Wrapf(err, "failed to check if key_id %s exists in keys table", session.KeyID)
	}
	if !keyExists {
		// 记录详细的错误信息，包括可能的根因
		return errors.Errorf("key_id %s does not exist in keys table, cannot create signing session. This usually means: 1) the placeholder key was not created successfully, 2) the key was created in a different transaction that hasn't committed yet, or 3) there's a database connection/transaction isolation issue", session.KeyID)
	}

	_, err = s.db.ExecContext(ctx, query,
		session.SessionID, session.KeyID, session.Protocol, session.Status,
		session.Threshold, session.TotalNodes, participatingNodesJSON,
		session.CurrentRound, session.TotalRounds, session.Signature,
		session.CreatedAt, completedAt, session.DurationMs,
	)
	if err != nil {
		// 检查是否是外键约束错误
		errStr := err.Error()
		if strings.Contains(errStr, "foreign key") || strings.Contains(errStr, "violates foreign key constraint") {
			return errors.Wrapf(err, "failed to save signing session: foreign key constraint violation - key_id %s does not exist in keys table", session.KeyID)
		}
		// 检查是否是唯一约束错误
		if strings.Contains(errStr, "unique constraint") || strings.Contains(errStr, "duplicate key") {
			return errors.Wrapf(err, "failed to save signing session: unique constraint violation - session_id %s already exists", session.SessionID)
		}
		// 其他数据库错误
		return errors.Wrapf(err, "failed to save signing session (session_id: %s, key_id: %s)", session.SessionID, session.KeyID)
	}

	return nil
}

// GetSigningSession 获取签名会话
func (s *PostgreSQLStore) GetSigningSession(ctx context.Context, sessionID string) (*SigningSession, error) {
	query := `
		SELECT session_id, key_id, protocol, status, threshold, total_nodes,
			participating_nodes, current_round, total_rounds, signature,
			created_at, completed_at, duration_ms
		FROM signing_sessions
		WHERE session_id = $1
	`

	var session SigningSession
	var participatingNodesJSON []byte
	var completedAt sql.NullTime

	err := s.db.QueryRowContext(ctx, query, sessionID).Scan(
		&session.SessionID, &session.KeyID, &session.Protocol, &session.Status,
		&session.Threshold, &session.TotalNodes, &participatingNodesJSON,
		&session.CurrentRound, &session.TotalRounds, &session.Signature,
		&session.CreatedAt, &completedAt, &session.DurationMs,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("session not found")
		}
		return nil, errors.Wrap(err, "failed to get signing session")
	}

	if len(participatingNodesJSON) > 0 {
		if err := json.Unmarshal(participatingNodesJSON, &session.ParticipatingNodes); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal participating nodes")
		}
	}
	if participatingNodesJSON == nil {
		session.ParticipatingNodes = []string{}
	}

	if completedAt.Valid {
		session.CompletedAt = &completedAt.Time
	}

	return &session, nil
}

// UpdateSigningSession 更新签名会话
func (s *PostgreSQLStore) UpdateSigningSession(ctx context.Context, session *SigningSession) error {
	participatingNodesJSON, err := json.Marshal(session.ParticipatingNodes)
	if err != nil {
		return errors.Wrap(err, "failed to marshal participating nodes")
	}

	query := `
		UPDATE signing_sessions SET
			key_id = $2,
			protocol = $3,
			status = $4,
			threshold = $5,
			total_nodes = $6,
			participating_nodes = $7,
			current_round = $8,
			total_rounds = $9,
			signature = $10,
			completed_at = $11,
			duration_ms = $12
		WHERE session_id = $1
	`

	var completedAt interface{}
	if session.CompletedAt != nil {
		completedAt = *session.CompletedAt
	}

	_, err = s.db.ExecContext(ctx, query,
		session.SessionID, session.KeyID, session.Protocol, session.Status,
		session.Threshold, session.TotalNodes, participatingNodesJSON,
		session.CurrentRound, session.TotalRounds, session.Signature,
		completedAt, session.DurationMs,
	)
	if err != nil {
		return errors.Wrap(err, "failed to update signing session")
	}

	return nil
}

// SaveBackupShare 保存备份分片
func (s *PostgreSQLStore) SaveBackupShare(ctx context.Context, keyID, nodeID string, shareIndex int, shareData []byte) error {
	query := `
		INSERT INTO backup_shares (key_id, node_id, share_index, share_data, created_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (key_id, node_id, share_index) DO UPDATE SET
			share_data = EXCLUDED.share_data,
			created_at = EXCLUDED.created_at
	`

	_, err := s.db.ExecContext(ctx, query, keyID, nodeID, shareIndex, shareData)
	if err != nil {
		return errors.Wrap(err, "failed to save backup share")
	}

	return nil
}

// GetBackupShare 获取备份分片
func (s *PostgreSQLStore) GetBackupShare(ctx context.Context, keyID, nodeID string, shareIndex int) ([]byte, error) {
	query := `
		SELECT share_data
		FROM backup_shares
		WHERE key_id = $1 AND node_id = $2 AND share_index = $3
	`

	var shareData []byte
	err := s.db.QueryRowContext(ctx, query, keyID, nodeID, shareIndex).Scan(&shareData)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("backup share not found")
		}
		return nil, errors.Wrap(err, "failed to get backup share")
	}

	return shareData, nil
}

// ListBackupShares 列出某个MPC分片的所有备份分片
func (s *PostgreSQLStore) ListBackupShares(ctx context.Context, keyID, nodeID string) ([]*BackupShareInfo, error) {
	query := `
		SELECT key_id, node_id, share_index, share_data, created_at
		FROM backup_shares
		WHERE key_id = $1 AND node_id = $2
		ORDER BY share_index
	`

	rows, err := s.db.QueryContext(ctx, query, keyID, nodeID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list backup shares")
	}
	defer rows.Close()

	var shares []*BackupShareInfo
	for rows.Next() {
		var share BackupShareInfo
		err := rows.Scan(
			&share.KeyID,
			&share.NodeID,
			&share.ShareIndex,
			&share.ShareData,
			&share.CreatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan backup share")
		}
		shares = append(shares, &share)
	}

	return shares, nil
}

// ListAllBackupShares 列出根密钥的所有备份分片（按nodeID分组）
func (s *PostgreSQLStore) ListAllBackupShares(ctx context.Context, keyID string) (map[string][]*BackupShareInfo, error) {
	query := `
		SELECT key_id, node_id, share_index, share_data, created_at
		FROM backup_shares
		WHERE key_id = $1
		ORDER BY node_id, share_index
	`

	rows, err := s.db.QueryContext(ctx, query, keyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list all backup shares")
	}
	defer rows.Close()

	result := make(map[string][]*BackupShareInfo)
	for rows.Next() {
		var share BackupShareInfo
		err := rows.Scan(
			&share.KeyID,
			&share.NodeID,
			&share.ShareIndex,
			&share.ShareData,
			&share.CreatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan backup share")
		}

		if result[share.NodeID] == nil {
			result[share.NodeID] = make([]*BackupShareInfo, 0)
		}
		result[share.NodeID] = append(result[share.NodeID], &share)
	}

	return result, nil
}

// SaveBackupShareDelivery 保存备份分片下发记录
func (s *PostgreSQLStore) SaveBackupShareDelivery(ctx context.Context, delivery *BackupShareDelivery) error {
	query := `
		INSERT INTO backup_share_deliveries (
			key_id, node_id, user_id, share_index, status,
			delivered_at, confirmed_at, failure_reason, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (key_id, node_id, share_index, user_id) DO UPDATE SET
			status = EXCLUDED.status,
			delivered_at = EXCLUDED.delivered_at,
			confirmed_at = EXCLUDED.confirmed_at,
			failure_reason = EXCLUDED.failure_reason,
			updated_at = EXCLUDED.updated_at
	`

	var deliveredAt, confirmedAt interface{}
	if delivery.DeliveredAt != nil {
		deliveredAt = *delivery.DeliveredAt
	}
	if delivery.ConfirmedAt != nil {
		confirmedAt = *delivery.ConfirmedAt
	}

	_, err := s.db.ExecContext(ctx, query,
		delivery.KeyID, delivery.NodeID, delivery.UserID, delivery.ShareIndex, delivery.Status,
		deliveredAt, confirmedAt, delivery.FailureReason, delivery.CreatedAt, delivery.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, "failed to save backup share delivery")
	}

	return nil
}

// GetBackupShareDelivery 获取备份分片下发记录
func (s *PostgreSQLStore) GetBackupShareDelivery(ctx context.Context, keyID, userID, nodeID string, shareIndex int) (*BackupShareDelivery, error) {
	query := `
		SELECT key_id, node_id, user_id, share_index, status,
			delivered_at, confirmed_at, failure_reason, created_at, updated_at
		FROM backup_share_deliveries
		WHERE key_id = $1 AND user_id = $2 AND node_id = $3 AND share_index = $4
	`

	var delivery BackupShareDelivery
	var deliveredAt, confirmedAt sql.NullTime

	err := s.db.QueryRowContext(ctx, query, keyID, userID, nodeID, shareIndex).Scan(
		&delivery.KeyID, &delivery.NodeID, &delivery.UserID, &delivery.ShareIndex, &delivery.Status,
		&deliveredAt, &confirmedAt, &delivery.FailureReason, &delivery.CreatedAt, &delivery.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("backup share delivery not found")
		}
		return nil, errors.Wrap(err, "failed to get backup share delivery")
	}

	if deliveredAt.Valid {
		delivery.DeliveredAt = &deliveredAt.Time
	}
	if confirmedAt.Valid {
		delivery.ConfirmedAt = &confirmedAt.Time
	}

	return &delivery, nil
}

// UpdateBackupShareDeliveryStatus 更新备份分片下发状态
func (s *PostgreSQLStore) UpdateBackupShareDeliveryStatus(ctx context.Context, keyID, userID, nodeID string, shareIndex int, status string, reason string) error {
	query := `
		UPDATE backup_share_deliveries
		SET status = $5, failure_reason = $6, updated_at = NOW()
	`

	// 根据状态更新相应的时间字段
	if status == "delivered" {
		query += `, delivered_at = NOW()`
	} else if status == "confirmed" {
		query += `, confirmed_at = NOW()`
	}

	query += ` WHERE key_id = $1 AND user_id = $2 AND node_id = $3 AND share_index = $4`

	_, err := s.db.ExecContext(ctx, query, keyID, userID, nodeID, shareIndex, status, reason)
	if err != nil {
		return errors.Wrap(err, "failed to update backup share delivery status")
	}

	return nil
}

// ListBackupShareDeliveries 列出备份分片下发记录
func (s *PostgreSQLStore) ListBackupShareDeliveries(ctx context.Context, keyID, nodeID string) ([]*BackupShareDelivery, error) {
	query := `
		SELECT key_id, node_id, user_id, share_index, status,
			delivered_at, confirmed_at, failure_reason, created_at, updated_at
		FROM backup_share_deliveries
		WHERE key_id = $1 AND node_id = $2
		ORDER BY created_at DESC
	`

	rows, err := s.db.QueryContext(ctx, query, keyID, nodeID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list backup share deliveries")
	}
	defer rows.Close()

	var deliveries []*BackupShareDelivery
	for rows.Next() {
		var delivery BackupShareDelivery
		var deliveredAt, confirmedAt sql.NullTime

		err := rows.Scan(
			&delivery.KeyID, &delivery.NodeID, &delivery.UserID, &delivery.ShareIndex, &delivery.Status,
			&deliveredAt, &confirmedAt, &delivery.FailureReason, &delivery.CreatedAt, &delivery.UpdatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan backup share delivery")
		}

		if deliveredAt.Valid {
			delivery.DeliveredAt = &deliveredAt.Time
		}
		if confirmedAt.Valid {
			delivery.ConfirmedAt = &confirmedAt.Time
		}

		deliveries = append(deliveries, &delivery)
	}

	return deliveries, nil
}

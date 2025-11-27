package storage

import (
	"context"
	"database/sql"
	"encoding/json"

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

	_, err = s.db.ExecContext(ctx, query,
		key.KeyID, key.PublicKey, key.Algorithm, key.Curve, key.Threshold, key.TotalNodes,
		key.ChainType, key.Address, key.Status, key.Description, tagsJSON,
		key.CreatedAt, key.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, "failed to save key metadata")
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

	query := `
		INSERT INTO nodes (
			node_id, node_type, endpoint, public_key, status, capabilities, metadata,
			registered_at, last_heartbeat
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (node_id) DO UPDATE SET
			node_type = EXCLUDED.node_type,
			endpoint = EXCLUDED.endpoint,
			public_key = EXCLUDED.public_key,
			status = EXCLUDED.status,
			capabilities = EXCLUDED.capabilities,
			metadata = EXCLUDED.metadata,
			last_heartbeat = EXCLUDED.last_heartbeat
	`

	_, err = s.db.ExecContext(ctx, query,
		node.NodeID, node.NodeType, node.Endpoint, node.PublicKey, node.Status,
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
		SELECT node_id, node_type, endpoint, public_key, status, capabilities, metadata,
			registered_at, last_heartbeat
		FROM nodes
		WHERE node_id = $1
	`

	var node NodeInfo
	var capabilitiesJSON []byte
	var metadataJSON []byte
	var lastHeartbeat sql.NullTime

	err := s.db.QueryRowContext(ctx, query, nodeID).Scan(
		&node.NodeID, &node.NodeType, &node.Endpoint, &node.PublicKey, &node.Status,
		&capabilitiesJSON, &metadataJSON, &node.RegisteredAt, &lastHeartbeat,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("node not found")
		}
		return nil, errors.Wrap(err, "failed to get node")
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

	query := `
		UPDATE nodes SET
			node_type = $2,
			endpoint = $3,
			public_key = $4,
			status = $5,
			capabilities = $6,
			metadata = $7,
			last_heartbeat = $8
		WHERE node_id = $1
	`

	_, err = s.db.ExecContext(ctx, query,
		node.NodeID, node.NodeType, node.Endpoint, node.PublicKey, node.Status,
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

	query := `SELECT node_id, node_type, endpoint, public_key, status, capabilities, metadata,
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

		err := rows.Scan(
			&node.NodeID, &node.NodeType, &node.Endpoint, &node.PublicKey, &node.Status,
			&capabilitiesJSON, &metadataJSON, &node.RegisteredAt, &lastHeartbeat,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan node")
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

	_, err = s.db.ExecContext(ctx, query,
		session.SessionID, session.KeyID, session.Protocol, session.Status,
		session.Threshold, session.TotalNodes, participatingNodesJSON,
		session.CurrentRound, session.TotalRounds, session.Signature,
		session.CreatedAt, completedAt, session.DurationMs,
	)
	if err != nil {
		return errors.Wrap(err, "failed to save signing session")
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

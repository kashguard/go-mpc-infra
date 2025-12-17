package session

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/kashguard/go-mpc-wallet/internal/infra/storage"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// Manager 会话管理器
type Manager struct {
	metadataStore storage.MetadataStore
	sessionStore  storage.SessionStore
	timeout       time.Duration
	stateStore    *StateStore
}

// NewManager 创建会话管理器
func NewManager(metadataStore storage.MetadataStore, sessionStore storage.SessionStore, timeout time.Duration) *Manager {
	return &Manager{
		metadataStore: metadataStore,
		sessionStore:  sessionStore,
		timeout:       timeout,
		stateStore:    NewStateStore(metadataStore, sessionStore),
	}
}

// CreateSession 创建签名会话
func (m *Manager) CreateSession(ctx context.Context, keyID string, protocol string, threshold int, totalNodes int) (*Session, error) {
	sessionID := "session-" + uuid.New().String()
	now := time.Now()
	expiresAt := now.Add(m.timeout)

	session := &Session{
		SessionID:          sessionID,
		KeyID:              keyID,
		Protocol:           protocol,
		Status:             string(SessionStatusPending),
		Threshold:          threshold,
		TotalNodes:         totalNodes,
		ParticipatingNodes: []string{},
		CurrentRound:       0,
		TotalRounds:        4, // GG18/GG20需要4轮
		CreatedAt:          now,
		ExpiresAt:          expiresAt,
	}

	// 保存到PostgreSQL
	storageSession := &storage.SigningSession{
		SessionID:          session.SessionID,
		KeyID:              session.KeyID,
		Protocol:           session.Protocol,
		Status:             session.Status,
		Threshold:          session.Threshold,
		TotalNodes:         session.TotalNodes,
		ParticipatingNodes: session.ParticipatingNodes,
		CurrentRound:       session.CurrentRound,
		TotalRounds:        session.TotalRounds,
		Signature:          session.Signature,
		CreatedAt:          session.CreatedAt,
		CompletedAt:        session.CompletedAt,
		DurationMs:         session.DurationMs,
	}

	if err := m.metadataStore.SaveSigningSession(ctx, storageSession); err != nil {
		return nil, errors.Wrap(err, "failed to save session to database")
	}

	// 保存到Redis缓存
	if err := m.sessionStore.SaveSession(ctx, storageSession, m.timeout); err != nil {
		return nil, errors.Wrap(err, "failed to save session to cache")
	}

	return session, nil
}

// CreateKeyGenSession 创建DKG会话（密钥生成会话）
// 对于DKG，使用keyID作为sessionID，因为每个密钥的DKG是唯一的
func (m *Manager) CreateKeyGenSession(ctx context.Context, keyID string, protocol string, threshold int, totalNodes int, nodeIDs []string) (*Session, error) {
	// 记录节点列表（用于调试）
	// 注意：这里使用 errors 包的 New 来创建日志，因为 session 包没有导入 log
	// 但我们可以在保存前记录节点列表
	_ = nodeIDs // 避免未使用变量警告

	// DKG会话使用keyID作为sessionID
	sessionID := keyID
	now := time.Now()
	expiresAt := now.Add(m.timeout)

	// 确保protocol是keygen相关的
	if protocol == "" {
		protocol = "keygen"
	}

	session := &Session{
		SessionID:          sessionID,
		KeyID:              keyID,
		Protocol:           protocol, // "keygen" 或 "dkg"
		Status:             string(SessionStatusPending),
		Threshold:          threshold,
		TotalNodes:         totalNodes,
		ParticipatingNodes: nodeIDs, // 预定义的参与节点列表
		CurrentRound:       0,
		TotalRounds:        4, // GG18/GG20 DKG需要4轮
		CreatedAt:          now,
		ExpiresAt:          expiresAt,
	}

	// 保存到PostgreSQL（复用SigningSession结构，通过Protocol字段区分）
	storageSession := &storage.SigningSession{
		SessionID:          session.SessionID,
		KeyID:              session.KeyID,
		Protocol:           session.Protocol,
		Status:             session.Status,
		Threshold:          session.Threshold,
		TotalNodes:         session.TotalNodes,
		ParticipatingNodes: session.ParticipatingNodes,
		CurrentRound:       session.CurrentRound,
		TotalRounds:        session.TotalRounds,
		Signature:          session.Signature, // DKG会话中，Signature字段可以存储公钥
		CreatedAt:          session.CreatedAt,
		CompletedAt:        session.CompletedAt,
		DurationMs:         session.DurationMs,
	}

	// 添加重试机制，处理可能的数据库连接或事务隔离问题
	maxRetries := 3
	retryDelay := 100 * time.Millisecond
	var saveErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		saveErr = m.metadataStore.SaveSigningSession(ctx, storageSession)
		if saveErr == nil {
			// 保存成功，跳出重试循环
			break
		}
		if attempt < maxRetries {
			log.Warn().
				Err(saveErr).
				Str("session_id", session.SessionID).
				Str("key_id", session.KeyID).
				Int("attempt", attempt).
				Int("max_retries", maxRetries).
				Dur("retry_delay", retryDelay).
				Msg("Failed to save keygen session, retrying...")
			time.Sleep(retryDelay)
			retryDelay *= 2 // 指数退避
		}
	}
	if saveErr != nil {
		log.Error().
			Err(saveErr).
			Str("session_id", session.SessionID).
			Str("key_id", session.KeyID).
			Int("attempts", maxRetries).
			Msg("Failed to save keygen session to database after all retries")
		return nil, errors.Wrap(saveErr, "failed to save keygen session to database after retries")
	}

	// 立即验证会话是否真的保存了
	savedSession, err := m.metadataStore.GetSigningSession(ctx, sessionID)
	if err != nil {
		log.Error().
			Err(err).
			Str("session_id", sessionID).
			Str("key_id", session.KeyID).
			Msg("Session saved but cannot be retrieved - verification failed")
		return nil, errors.Wrap(err, "session saved but verification failed")
	}

	log.Info().
		Str("session_id", session.SessionID).
		Str("key_id", session.KeyID).
		Str("protocol", savedSession.Protocol).
		Str("status", savedSession.Status).
		Int("threshold", savedSession.Threshold).
		Int("total_nodes", savedSession.TotalNodes).
		Strs("participating_nodes", savedSession.ParticipatingNodes).
		Msg("Keygen session saved and verified successfully")

	// 保存到Redis缓存
	if err := m.sessionStore.SaveSession(ctx, storageSession, m.timeout); err != nil {
		log.Warn().
			Err(err).
			Str("session_id", session.SessionID).
			Str("key_id", session.KeyID).
			Msg("Failed to save keygen session to cache (non-critical)")
		// Redis 缓存失败不影响功能，只记录警告
	}

	return session, nil
}

// GetSession 获取会话
func (m *Manager) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	// 先从Redis获取
	storageSession, err := m.sessionStore.GetSession(ctx, sessionID)
	if err == nil {
		log.Debug().
			Str("session_id", sessionID).
			Msg("Session retrieved from Redis cache")
		return convertStorageSession(storageSession), nil
	}
	log.Debug().
		Err(err).
		Str("session_id", sessionID).
		Msg("Session not found in Redis cache, trying PostgreSQL")

	// 如果Redis中没有，从PostgreSQL获取
	storageSession, err = m.metadataStore.GetSigningSession(ctx, sessionID)
	if err != nil {
		log.Error().
			Err(err).
			Str("session_id", sessionID).
			Msg("Failed to get session from both Redis and PostgreSQL - session does not exist or database error")
		return nil, errors.Wrapf(err, "failed to get session %s from both Redis and PostgreSQL", sessionID)
	}

	log.Debug().
		Str("session_id", sessionID).
		Str("key_id", storageSession.KeyID).
		Str("protocol", storageSession.Protocol).
		Str("status", storageSession.Status).
		Msg("Session retrieved from PostgreSQL")

	// 转换并返回
	return convertStorageSession(storageSession), nil
}

// UpdateSession 更新会话
func (m *Manager) UpdateSession(ctx context.Context, session *Session) error {
	storageSession := &storage.SigningSession{
		SessionID:          session.SessionID,
		KeyID:              session.KeyID,
		Protocol:           session.Protocol,
		Status:             session.Status,
		Threshold:          session.Threshold,
		TotalNodes:         session.TotalNodes,
		ParticipatingNodes: session.ParticipatingNodes,
		CurrentRound:       session.CurrentRound,
		TotalRounds:        session.TotalRounds,
		Signature:          session.Signature,
		CreatedAt:          session.CreatedAt,
		CompletedAt:        session.CompletedAt,
		DurationMs:         session.DurationMs,
	}

	// 更新PostgreSQL
	if err := m.metadataStore.UpdateSigningSession(ctx, storageSession); err != nil {
		return errors.Wrap(err, "failed to update session in database")
	}

	// 更新Redis缓存
	remainingTTL := time.Until(session.ExpiresAt)
	if remainingTTL > 0 {
		if err := m.sessionStore.UpdateSession(ctx, storageSession, remainingTTL); err != nil {
			return errors.Wrap(err, "failed to update session in cache")
		}
	}

	return nil
}

// JoinSession 节点加入会话
func (m *Manager) JoinSession(ctx context.Context, sessionID string, nodeID string) error {
	session, err := m.GetSession(ctx, sessionID)
	if err != nil {
		return errors.Wrap(err, "failed to get session")
	}

	// 检查会话状态
	if session.Status != string(SessionStatusPending) && session.Status != string(SessionStatusActive) {
		return errors.Errorf("session is not joinable: status=%s", session.Status)
	}

	// 检查是否已加入
	for _, nid := range session.ParticipatingNodes {
		if nid == nodeID {
			return nil // 已经加入
		}
	}

	// 添加节点
	session.ParticipatingNodes = append(session.ParticipatingNodes, nodeID)
	session.Status = string(SessionStatusActive)

	if err := m.UpdateSession(ctx, session); err != nil {
		return errors.Wrap(err, "failed to update session")
	}

	return nil
}

// CompleteSession 完成会话
func (m *Manager) CompleteSession(ctx context.Context, sessionID string, signature string) error {
	session, err := m.GetSession(ctx, sessionID)
	if err != nil {
		return errors.Wrap(err, "failed to get session")
	}

	now := time.Now()
	session.Status = string(SessionStatusCompleted)
	session.Signature = signature
	session.CompletedAt = &now
	session.DurationMs = int(now.Sub(session.CreatedAt).Milliseconds())

	if err := m.UpdateSession(ctx, session); err != nil {
		return errors.Wrap(err, "failed to update session")
	}

	return nil
}

// CompleteKeygenSession 完成 DKG 会话并写入公钥，更新密钥为 Active
func (m *Manager) CompleteKeygenSession(ctx context.Context, keyID string, publicKey string) error {
	log.Info().
		Str("key_id", keyID).
		Str("public_key", publicKey).
		Msg("Starting CompleteKeygenSession")

	session, err := m.GetSession(ctx, keyID) // DKG 会话的 sessionID 等于 keyID
	if err != nil {
		log.Error().
			Err(err).
			Str("key_id", keyID).
			Msg("Failed to get keygen session in CompleteKeygenSession")
		return errors.Wrap(err, "failed to get keygen session")
	}

	// 仅允许在 Pending/Active 状态完成
	if session.Status != string(SessionStatusPending) && session.Status != string(SessionStatusActive) {
		log.Warn().
			Str("key_id", keyID).
			Str("session_status", session.Status).
			Msg("Cannot complete session - session is not in Pending or Active status")
		return errors.Errorf("cannot complete session in status %s", session.Status)
	}

	now := time.Now()
	session.Status = string(SessionStatusCompleted)
	session.Signature = publicKey // 对于 DKG，将公钥写入 Signature 字段
	session.CompletedAt = &now
	session.DurationMs = int(now.Sub(session.CreatedAt).Milliseconds())

	// 更新会话
	if err := m.UpdateSession(ctx, session); err != nil {
		log.Error().
			Err(err).
			Str("key_id", keyID).
			Msg("Failed to update keygen session in CompleteKeygenSession")
		return errors.Wrap(err, "failed to update keygen session")
	}
	log.Info().
		Str("key_id", keyID).
		Msg("Keygen session updated successfully")

	// 更新密钥元数据：公钥 + 状态 Active
	keyMeta, err := m.metadataStore.GetKeyMetadata(ctx, keyID)
	if err != nil {
		log.Error().
			Err(err).
			Str("key_id", keyID).
			Msg("Failed to get key metadata in CompleteKeygenSession")
		return errors.Wrap(err, "failed to get key metadata")
	}

	oldStatus := keyMeta.Status
	keyMeta.PublicKey = publicKey
	keyMeta.Status = "Active"
	keyMeta.UpdatedAt = now

	if err := m.metadataStore.UpdateKeyMetadata(ctx, keyMeta); err != nil {
		log.Error().
			Err(err).
			Str("key_id", keyID).
			Str("old_status", oldStatus).
			Str("new_status", "Active").
			Msg("Failed to update key metadata in CompleteKeygenSession")
		return errors.Wrap(err, "failed to update key metadata")
	}

	log.Info().
		Str("key_id", keyID).
		Str("old_status", oldStatus).
		Str("new_status", "Active").
		Str("public_key", publicKey).
		Msg("Key metadata updated successfully - DKG completed")

	return nil
}

// CancelSession 取消会话
func (m *Manager) CancelSession(ctx context.Context, sessionID string) error {
	session, err := m.GetSession(ctx, sessionID)
	if err != nil {
		return errors.Wrap(err, "failed to get session")
	}

	session.Status = string(SessionStatusCancelled)

	if err := m.UpdateSession(ctx, session); err != nil {
		return errors.Wrap(err, "failed to update session")
	}

	return nil
}

// CheckTimeout 检查会话超时
func (m *Manager) CheckTimeout(ctx context.Context, sessionID string) (bool, error) {
	session, err := m.GetSession(ctx, sessionID)
	if err != nil {
		return false, errors.Wrap(err, "failed to get session")
	}

	if time.Now().After(session.ExpiresAt) {
		session.Status = string(SessionStatusTimeout)
		if err := m.UpdateSession(ctx, session); err != nil {
			return true, errors.Wrap(err, "failed to update session")
		}
		return true, nil
	}

	return false, nil
}

// SaveRoundProgress 同步协议轮次信息
func (m *Manager) SaveRoundProgress(ctx context.Context, progress *RoundProgress) error {
	return m.stateStore.SaveRoundProgress(ctx, progress)
}

// LoadRoundProgress 读取协议轮次信息
func (m *Manager) LoadRoundProgress(ctx context.Context, sessionID string) (*RoundProgress, error) {
	return m.stateStore.LoadRoundProgress(ctx, sessionID)
}

// AppendWAL 追加 WAL 记录
func (m *Manager) AppendWAL(ctx context.Context, record *WALRecord) error {
	return m.stateStore.AppendWAL(ctx, record)
}

// ReplayWAL 回放 WAL
func (m *Manager) ReplayWAL(ctx context.Context, sessionID string) ([]*WALRecord, error) {
	return m.stateStore.ReplayWAL(ctx, sessionID)
}

// ObserveRoundMetric 记录轮次耗时指标
func (m *Manager) ObserveRoundMetric(protocol string, round int, duration time.Duration) {
	m.stateStore.ObserveRoundMetric(protocol, round, duration)
}

// convertStorageSession 转换存储会话为会话
func convertStorageSession(storageSession *storage.SigningSession) *Session {
	return &Session{
		SessionID:          storageSession.SessionID,
		KeyID:              storageSession.KeyID,
		Protocol:           storageSession.Protocol,
		Status:             storageSession.Status,
		Threshold:          storageSession.Threshold,
		TotalNodes:         storageSession.TotalNodes,
		ParticipatingNodes: storageSession.ParticipatingNodes,
		CurrentRound:       storageSession.CurrentRound,
		TotalRounds:        storageSession.TotalRounds,
		Signature:          storageSession.Signature,
		CreatedAt:          storageSession.CreatedAt,
		CompletedAt:        storageSession.CompletedAt,
		DurationMs:         storageSession.DurationMs,
		ExpiresAt:          storageSession.CreatedAt.Add(5 * time.Minute), // 默认5分钟超时
	}
}

package session

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/storage"
	"github.com/pkg/errors"
)

// Manager 会话管理器
type Manager struct {
	metadataStore storage.MetadataStore
	sessionStore  storage.SessionStore
	timeout       time.Duration
}

// NewManager 创建会话管理器
func NewManager(metadataStore storage.MetadataStore, sessionStore storage.SessionStore, timeout time.Duration) *Manager {
	return &Manager{
		metadataStore: metadataStore,
		sessionStore:  sessionStore,
		timeout:       timeout,
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

// GetSession 获取会话
func (m *Manager) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	// 先从Redis获取
	storageSession, err := m.sessionStore.GetSession(ctx, sessionID)
	if err == nil {
		return convertStorageSession(storageSession), nil
	}

	// 如果Redis中没有，从PostgreSQL获取
	storageSession, err = m.metadataStore.GetSigningSession(ctx, sessionID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get session")
	}

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

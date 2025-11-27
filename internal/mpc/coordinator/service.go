package coordinator

import (
	"context"

	"github.com/kashguard/go-mpc-wallet/internal/mpc/key"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/node"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/protocol"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/session"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/signing"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/storage"
	"github.com/pkg/errors"
)

// Service Coordinator服务
type Service struct {
	metadataStore  storage.MetadataStore
	keyService     *key.Service
	signingService *signing.Service
	sessionManager *session.Manager
	nodeManager    *node.Manager
	nodeDiscovery  *node.Discovery
	protocolEngine protocol.Engine
}

// NewService 创建Coordinator服务
func NewService(
	metadataStore storage.MetadataStore,
	keyService *key.Service,
	signingService *signing.Service,
	sessionManager *session.Manager,
	nodeManager *node.Manager,
	nodeDiscovery *node.Discovery,
	protocolEngine protocol.Engine,
) *Service {
	return &Service{
		metadataStore:  metadataStore,
		keyService:     keyService,
		signingService: signingService,
		sessionManager: sessionManager,
		nodeManager:    nodeManager,
		nodeDiscovery:  nodeDiscovery,
		protocolEngine: protocolEngine,
	}
}

// CreateSigningSession 创建签名会话
func (s *Service) CreateSigningSession(ctx context.Context, req *CreateSessionRequest) (*SigningSession, error) {
	// 获取密钥信息
	keyMetadata, err := s.keyService.GetKey(ctx, req.KeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get key")
	}

	// 选择协议
	protocol := req.Protocol
	if protocol == "" {
		protocol = s.protocolEngine.DefaultProtocol()
	}

	// 创建会话
	session, err := s.sessionManager.CreateSession(ctx, req.KeyID, protocol, keyMetadata.Threshold, keyMetadata.TotalNodes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create session")
	}

	return &SigningSession{
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
		ExpiresAt:          session.ExpiresAt,
	}, nil
}

// JoinSigningSession 节点加入签名会话
func (s *Service) JoinSigningSession(ctx context.Context, sessionID string, nodeID string) error {
	if err := s.sessionManager.JoinSession(ctx, sessionID, nodeID); err != nil {
		return errors.Wrap(err, "failed to join session")
	}
	return nil
}

// GetSigningSession 获取签名会话
func (s *Service) GetSigningSession(ctx context.Context, sessionID string) (*SigningSession, error) {
	session, err := s.sessionManager.GetSession(ctx, sessionID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get session")
	}

	return &SigningSession{
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
		ExpiresAt:          session.ExpiresAt,
	}, nil
}

// AggregateSignatures 聚合签名分片
func (s *Service) AggregateSignatures(ctx context.Context, sessionID string) (*Signature, error) {
	// TODO: 实现签名聚合
	// 1. 获取会话信息
	// 2. 收集所有节点的签名分片
	// 3. 使用协议引擎聚合签名
	// 4. 验证聚合后的签名

	return nil, errors.New("signature aggregation not yet fully implemented")
}

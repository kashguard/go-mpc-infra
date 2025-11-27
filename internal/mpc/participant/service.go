package participant

import (
	"context"

	"github.com/kashguard/go-mpc-wallet/internal/mpc/protocol"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/storage"
	"github.com/pkg/errors"
)

// Service Participant服务
type Service struct {
	nodeID          string
	keyShareStorage storage.KeyShareStorage
	protocolEngine  protocol.Engine
}

// NewService 创建Participant服务
func NewService(
	nodeID string,
	keyShareStorage storage.KeyShareStorage,
	protocolEngine protocol.Engine,
) *Service {
	return &Service{
		nodeID:          nodeID,
		keyShareStorage: keyShareStorage,
		protocolEngine:  protocolEngine,
	}
}

// ParticipateKeyGen 参与密钥生成
func (s *Service) ParticipateKeyGen(ctx context.Context, sessionID string) (*KeyShare, error) {
	// TODO: 实现参与DKG协议
	// 1. 接收DKG请求
	// 2. 生成随机分片
	// 3. 与其他节点交换分片
	// 4. 验证和聚合分片
	// 5. 返回最终分片

	return nil, errors.New("key generation participation not yet implemented")
}

// ParticipateSign 参与签名
func (s *Service) ParticipateSign(ctx context.Context, sessionID string, msg []byte) (*SignatureShare, error) {
	// TODO: 实现参与签名协议
	// 1. 获取密钥分片
	// 2. 执行签名协议（GG18/GG20）
	// 3. 生成签名分片
	// 4. 返回签名分片

	return nil, errors.New("signing participation not yet implemented")
}

// StoreKeyShare 存储密钥分片
func (s *Service) StoreKeyShare(ctx context.Context, keyID string, share *KeyShare) error {
	if err := s.keyShareStorage.StoreKeyShare(ctx, keyID, share.NodeID, share.Share); err != nil {
		return errors.Wrap(err, "failed to store key share")
	}
	return nil
}

// GetKeyShare 获取密钥分片
func (s *Service) GetKeyShare(ctx context.Context, keyID string) (*KeyShare, error) {
	share, err := s.keyShareStorage.GetKeyShare(ctx, keyID, s.nodeID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get key share")
	}

	return &KeyShare{
		KeyID:  keyID,
		NodeID: s.nodeID,
		Share:  share,
	}, nil
}

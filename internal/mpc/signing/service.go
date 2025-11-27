package signing

import (
	"context"

	"github.com/kashguard/go-mpc-wallet/internal/mpc/node"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/protocol"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/session"
	"github.com/pkg/errors"
)

// Service 签名服务
type Service struct {
	protocolEngine protocol.Engine
	sessionManager *session.Manager
	nodeDiscovery  *node.Discovery
}

// NewService 创建签名服务
func NewService(
	protocolEngine protocol.Engine,
	sessionManager *session.Manager,
	nodeDiscovery *node.Discovery,
) *Service {
	return &Service{
		protocolEngine: protocolEngine,
		sessionManager: sessionManager,
		nodeDiscovery:  nodeDiscovery,
	}
}

// ThresholdSign 阈值签名
func (s *Service) ThresholdSign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	// TODO: 实现完整签名流程
	// 1. 获取密钥信息（需要密钥服务）
	// 2. 创建签名会话
	// 3. 选择参与节点
	// 4. 执行签名协议
	// 5. 聚合签名
	// 6. 验证签名
	// 7. 完成会话

	return nil, errors.New("threshold signing not yet fully implemented")
}

// BatchSign 批量签名
func (s *Service) BatchSign(ctx context.Context, req *BatchSignRequest) (*BatchSignResponse, error) {
	// TODO: 实现批量签名
	// 并发执行多个签名请求

	return nil, errors.New("batch signing not yet implemented")
}

// Verify 验证签名
func (s *Service) Verify(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error) {
	// TODO: 实现签名验证
	// 使用协议引擎验证签名

	return nil, errors.New("signature verification not yet fully implemented")
}

package protocol

import (
	"context"

	"github.com/kashguard/tss-lib/tss"
	"github.com/pkg/errors"
)

// GG20Protocol GG20协议实现（改进版GG18，支持单轮签名和可识别的中止）
// GG20 的主要改进：
// 1. 单轮签名（相比 GG18 的多轮）
// 2. 可识别的中止（identifiable abort）- 如果协议失败，可以识别恶意节点
// 3. 更好的性能（减少网络通信轮次）
type GG20Protocol struct {
	*GG18Protocol
}

// NewGG20Protocol 创建GG20协议实例
func NewGG20Protocol(curve string, thisNodeID string, messageRouter func(sessionID string, nodeID string, msg tss.Message, isBroadcast bool) error, keyShareStorage KeyShareStorage) *GG20Protocol {
	return &GG20Protocol{
		GG18Protocol: NewGG18Protocol(curve, thisNodeID, messageRouter, keyShareStorage),
	}
}

// GenerateKeyShare 分布式密钥生成（复用GG18流程，GG20的DKG与GG18相同）
func (p *GG20Protocol) GenerateKeyShare(ctx context.Context, req *KeyGenRequest) (*KeyGenResponse, error) {
	// GG20 的 DKG 与 GG18 相同，直接复用
	return p.GG18Protocol.GenerateKeyShare(ctx, req)
}

// ThresholdSign 阈值签名（GG20优化版，使用tss-lib的signing模块）
// GG20 的主要改进：
// 1. 单轮签名（相比GG18的多轮）
// 2. 可识别的中止（identifiable abort）
// 3. 更好的性能
func (p *GG20Protocol) ThresholdSign(ctx context.Context, sessionID string, req *SignRequest) (*SignResponse, error) {
	if err := p.ValidateSignRequest(req); err != nil {
		return nil, errors.Wrap(err, "invalid sign request")
	}

	// 获取密钥记录
	record, ok := p.getKeyRecord(req.KeyID)
	if !ok {
		return nil, errors.Errorf("key %s not found", req.KeyID)
	}

	if record.KeyData == nil {
		return nil, errors.New("key data not found in record")
	}

	// 解析消息
	message, err := resolveMessagePayload(req)
	if err != nil {
		return nil, errors.Wrap(err, "resolve message payload")
	}

	// 使用 tss-lib 执行 GG20 签名协议（复用通用签名执行函数）
	sigData, err := p.partyManager.executeSigning(
		ctx,
		sessionID,
		req.KeyID,
		message,
		req.NodeIDs,
		p.thisNodeID,
		record.KeyData,
		GG20SigningOptions(),
	)
	if err != nil {
		return nil, errors.Wrap(err, "execute GG20 signing")
	}

	// 转换签名格式
	signature, err := convertTSSSignature(sigData)
	if err != nil {
		return nil, errors.Wrap(err, "convert tss signature")
	}

	return &SignResponse{
		Signature: signature,
		PublicKey: record.PublicKey,
	}, nil
}

// SupportedProtocols 支持的协议
func (p *GG20Protocol) SupportedProtocols() []string {
	return []string{"gg20"}
}

// DefaultProtocol 默认协议
func (p *GG20Protocol) DefaultProtocol() string {
	return "gg20"
}

// GetCurve 获取曲线类型
func (p *GG20Protocol) GetCurve() string {
	return p.GG18Protocol.GetCurve()
}

// ValidateKeyGenRequest 验证密钥生成请求（复用GG18的验证逻辑）
func (p *GG20Protocol) ValidateKeyGenRequest(req *KeyGenRequest) error {
	return p.GG18Protocol.ValidateKeyGenRequest(req)
}

// ValidateSignRequest 验证签名请求（复用GG18的验证逻辑）
func (p *GG20Protocol) ValidateSignRequest(req *SignRequest) error {
	return p.GG18Protocol.ValidateSignRequest(req)
}

// VerifySignature 签名验证（复用GG18的验证逻辑）
func (p *GG20Protocol) VerifySignature(ctx context.Context, sig *Signature, msg []byte, pubKey *PublicKey) (bool, error) {
	return p.GG18Protocol.VerifySignature(ctx, sig, msg, pubKey)
}

// RotateKey 密钥轮换（复用GG18的实现）
func (p *GG20Protocol) RotateKey(ctx context.Context, keyID string) error {
	return p.GG18Protocol.RotateKey(ctx, keyID)
}

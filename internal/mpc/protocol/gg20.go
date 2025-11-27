package protocol

import (
	"context"

	"github.com/pkg/errors"
)

// GG20Protocol GG20协议实现（改进版GG18）
type GG20Protocol struct {
	*GG18Protocol
}

// NewGG20Protocol 创建GG20协议实例
func NewGG20Protocol(curve string) *GG20Protocol {
	return &GG20Protocol{
		GG18Protocol: NewGG18Protocol(curve),
	}
}

// GenerateKeyShare 分布式密钥生成（DKG）
func (p *GG20Protocol) GenerateKeyShare(ctx context.Context, req *KeyGenRequest) (*KeyGenResponse, error) {
	// TODO: 实现GG20 DKG协议（改进版GG18）
	// GG20相比GG18的改进：
	// 1. 更高效的通信轮次
	// 2. 更好的错误处理
	// 3. 可识别的中止（Identifiable Abort）

	// 临时实现：返回错误，提示需要实现
	return nil, errors.New("GG20 DKG not yet implemented - requires tss-lib integration")
}

// ThresholdSign 阈值签名
func (p *GG20Protocol) ThresholdSign(ctx context.Context, sessionID string, req *SignRequest) (*SignResponse, error) {
	// TODO: 实现GG20阈值签名协议
	// GG20相比GG18的改进：
	// 1. 单轮通信（One Round）
	// 2. 可识别的中止
	// 3. 更好的性能

	// 临时实现：返回错误，提示需要实现
	return nil, errors.New("GG20 threshold signing not yet implemented - requires tss-lib integration")
}

// SupportedProtocols 支持的协议
func (p *GG20Protocol) SupportedProtocols() []string {
	return []string{"gg20"}
}

// DefaultProtocol 默认协议
func (p *GG20Protocol) DefaultProtocol() string {
	return "gg20"
}

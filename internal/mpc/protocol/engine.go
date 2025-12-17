package protocol

import (
	"context"
	"fmt"
)

// Engine 协议引擎接口
type Engine interface {
	// 分布式密钥生成（DKG）
	GenerateKeyShare(ctx context.Context, req *KeyGenRequest) (*KeyGenResponse, error)

	// 阈值签名
	ThresholdSign(ctx context.Context, sessionID string, req *SignRequest) (*SignResponse, error)

	// 签名验证
	VerifySignature(ctx context.Context, sig *Signature, msg []byte, pubKey *PublicKey) (bool, error)

	// 密钥轮换
	RotateKey(ctx context.Context, keyID string) error

	// 执行密钥轮换（Resharing）
	ExecuteResharing(ctx context.Context, keyID string, oldNodeIDs []string, newNodeIDs []string, oldThreshold int, newThreshold int) (*KeyGenResponse, error)

	// 处理接收到的DKG消息
	ProcessIncomingKeygenMessage(ctx context.Context, sessionID string, fromNodeID string, msgBytes []byte, isBroadcast bool) error

	// 处理接收到的签名消息
	// isBroadcast 标记消息是否广播，用于 tss UpdateFromBytes
	ProcessIncomingSigningMessage(ctx context.Context, sessionID string, fromNodeID string, msgBytes []byte, isBroadcast bool) error

	// 支持的协议
	SupportedProtocols() []string
	DefaultProtocol() string
}

// ProtocolRegistry 协议注册表
type ProtocolRegistry struct {
	protocols       map[string]Engine
	defaultProtocol string
}

// NewProtocolRegistry 创建协议注册表
func NewProtocolRegistry() *ProtocolRegistry {
	return &ProtocolRegistry{
		protocols: make(map[string]Engine),
	}
}

// Register 注册协议
func (r *ProtocolRegistry) Register(name string, engine Engine) {
	r.protocols[name] = engine
}

// Get 获取协议引擎
func (r *ProtocolRegistry) Get(name string) (Engine, error) {
	engine, ok := r.protocols[name]
	if !ok {
		return nil, fmt.Errorf("protocol %s not found", name)
	}
	return engine, nil
}

// SetDefault 设置默认协议
func (r *ProtocolRegistry) SetDefault(name string) {
	r.defaultProtocol = name
}

// GetDefault 获取默认协议
func (r *ProtocolRegistry) GetDefault() (Engine, error) {
	if r.defaultProtocol == "" {
		return nil, fmt.Errorf("no default protocol set")
	}
	return r.Get(r.defaultProtocol)
}

// List 列出所有支持的协议
func (r *ProtocolRegistry) List() []string {
	var names []string
	for name := range r.protocols {
		names = append(names, name)
	}
	return names
}

package key

import "time"

// RootKeyMetadata 根密钥元数据
type RootKeyMetadata struct {
	KeyID        string
	PublicKey    string
	Algorithm    string
	Curve        string
	Threshold    int
	TotalNodes   int
	Protocol     string // gg18, gg20, frost
	Status       string
	Description  string
	Tags         map[string]string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletionDate *time.Time
}

// WalletKeyMetadata 钱包密钥元数据
type WalletKeyMetadata struct {
	WalletID     string
	RootKeyID    string
	ChainType    string
	Index        uint32 // 派生索引
	PublicKey    string
	Address      string
	Status       string
	Description  string
	Tags         map[string]string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletionDate *time.Time
}

// CreateRootKeyRequest 创建根密钥请求
type CreateRootKeyRequest struct {
	KeyID       string // 可选的密钥ID，如果为空则自动生成
	Algorithm   string
	Curve       string
	Protocol    string // gg18, gg20, frost
	Threshold   int    // 默认 2
	TotalNodes  int    // 默认 3
	UserID      string // 用户ID，用于生成客户端节点ID
	Description string
	Tags        map[string]string
}

// DeriveWalletKeyRequest 派生钱包密钥请求
type DeriveWalletKeyRequest struct {
	RootKeyID   string
	ChainType   string
	Index       uint32
	Description string
	Tags        map[string]string
}


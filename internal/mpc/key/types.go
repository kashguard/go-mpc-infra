package key

import "time"

// KeyMetadata 密钥元数据
type KeyMetadata struct {
	KeyID        string
	PublicKey    string
	Algorithm    string
	Curve        string
	Threshold    int
	TotalNodes   int
	ChainType    string
	Address      string
	Status       string
	Description  string
	Tags         map[string]string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletionDate *time.Time
}

// KeyShare 密钥分片
type KeyShare struct {
	KeyID  string
	NodeID string
	Share  []byte
	Index  int
}

// CreateKeyRequest 创建密钥请求
type CreateKeyRequest struct {
	KeyID       string // 可选的密钥ID，如果为空则自动生成
	Algorithm   string
	Curve       string
	Threshold   int
	TotalNodes  int
	ChainType   string
	Description string
	Tags        map[string]string
	UserID      string // 用户ID，用于生成客户端节点ID（client-{userID}）
}

// KeyFilter 密钥过滤条件
type KeyFilter struct {
	ChainType string
	Status    string
	TagKey    string
	TagValue  string
	Limit     int
	Offset    int
}

package storage

import (
	"context"
	"time"
)

// KeyMetadata 密钥元数据
type KeyMetadata struct {
	KeyID        string
	PublicKey    string
	Algorithm    string
	Curve        string
	ChainCode    string // Hex encoded chain code
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

// NodeInfo 节点信息
type NodeInfo struct {
	NodeID        string
	NodeType      string
	Purpose       string // signing, backup
	Endpoint      string
	PublicKey     string
	Status        string
	Capabilities  []string
	Metadata      map[string]interface{}
	RegisteredAt  time.Time
	LastHeartbeat *time.Time
}

// SigningSession 签名会话
type SigningSession struct {
	SessionID          string
	KeyID              string
	Protocol           string
	Status             string
	Threshold          int
	TotalNodes         int
	ParticipatingNodes []string
	CurrentRound       int
	TotalRounds        int
	Signature          string
	CreatedAt          time.Time
	CompletedAt        *time.Time
	DurationMs         int
}

// MetadataStore 密钥元数据存储接口
type MetadataStore interface {
	// 密钥操作
	SaveKeyMetadata(ctx context.Context, key *KeyMetadata) error
	GetKeyMetadata(ctx context.Context, keyID string) (*KeyMetadata, error)
	UpdateKeyMetadata(ctx context.Context, key *KeyMetadata) error
	DeleteKeyMetadata(ctx context.Context, keyID string) error
	ListKeys(ctx context.Context, filter *KeyFilter) ([]*KeyMetadata, error)

	// 节点操作
	SaveNode(ctx context.Context, node *NodeInfo) error
	GetNode(ctx context.Context, nodeID string) (*NodeInfo, error)
	UpdateNode(ctx context.Context, node *NodeInfo) error
	ListNodes(ctx context.Context, filter *NodeFilter) ([]*NodeInfo, error)
	UpdateNodeHeartbeat(ctx context.Context, nodeID string) error

	// 会话操作
	SaveSigningSession(ctx context.Context, session *SigningSession) error
	GetSigningSession(ctx context.Context, sessionID string) (*SigningSession, error)
	UpdateSigningSession(ctx context.Context, session *SigningSession) error

	// 备份分片下发记录操作
	SaveBackupShareDelivery(ctx context.Context, delivery *BackupShareDelivery) error
	GetBackupShareDelivery(ctx context.Context, keyID, userID, nodeID string, shareIndex int) (*BackupShareDelivery, error)
	UpdateBackupShareDeliveryStatus(ctx context.Context, keyID, userID, nodeID string, shareIndex int, status string, reason string) error
	ListBackupShareDeliveries(ctx context.Context, keyID, nodeID string) ([]*BackupShareDelivery, error)
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

// NodeFilter 节点过滤条件
type NodeFilter struct {
	NodeType string
	Purpose  string // signing, backup
	Status   string
	Limit    int
	Offset   int
}

// KeyShareStorage 密钥分片存储接口
type KeyShareStorage interface {
	// 存储密钥分片（加密）
	StoreKeyShare(ctx context.Context, keyID string, nodeID string, share []byte) error

	// 获取密钥分片（解密）
	GetKeyShare(ctx context.Context, keyID string, nodeID string) ([]byte, error)

	// 删除密钥分片
	DeleteKeyShare(ctx context.Context, keyID string, nodeID string) error

	// 列出所有密钥分片
	ListKeyShares(ctx context.Context, nodeID string) ([]string, error)

	// 存储密钥数据（LocalPartySaveData 序列化后的数据，加密存储）
	// 用于签名时重建 LocalPartySaveData
	StoreKeyData(ctx context.Context, keyID string, nodeID string, keyData []byte) error

	// 获取密钥数据（解密并返回序列化的 LocalPartySaveData）
	GetKeyData(ctx context.Context, keyID string, nodeID string) ([]byte, error)
}

// SessionStore 签名会话存储接口（Redis）
type SessionStore interface {
	// 保存会话状态（Redis缓存）
	SaveSession(ctx context.Context, session *SigningSession, ttl time.Duration) error

	// 获取会话状态
	GetSession(ctx context.Context, sessionID string) (*SigningSession, error)

	// 更新会话状态
	UpdateSession(ctx context.Context, session *SigningSession, ttl time.Duration) error

	// 删除会话
	DeleteSession(ctx context.Context, sessionID string) error

	// 获取分布式锁
	AcquireLock(ctx context.Context, key string, ttl time.Duration) (bool, error)

	// 释放分布式锁
	ReleaseLock(ctx context.Context, key string) error

	// 发布消息（用于节点间通信）
	PublishMessage(ctx context.Context, channel string, message interface{}) error

	// 订阅消息
	SubscribeMessages(ctx context.Context, channel string) (<-chan interface{}, error)
}

// BackupShareStorage 备份分片存储接口
type BackupShareStorage interface {
	// SaveBackupShare 保存备份分片
	SaveBackupShare(ctx context.Context, keyID, nodeID string, shareIndex int, shareData []byte) error

	// GetBackupShare 获取备份分片
	GetBackupShare(ctx context.Context, keyID, nodeID string, shareIndex int) ([]byte, error)

	// ListBackupShares 列出某个MPC分片的所有备份分片
	ListBackupShares(ctx context.Context, keyID, nodeID string) ([]*BackupShareInfo, error)

	// ListAllBackupShares 列出根密钥的所有备份分片（按nodeID分组）
	ListAllBackupShares(ctx context.Context, keyID string) (map[string][]*BackupShareInfo, error)
}

// BackupShareInfo 备份分片信息
type BackupShareInfo struct {
	KeyID      string
	NodeID     string
	ShareIndex int
	ShareData  []byte
	CreatedAt  time.Time
}

// BackupShareDelivery 备份分片下发记录
type BackupShareDelivery struct {
	KeyID         string
	UserID        string // 接收分片的客户端用户ID
	NodeID        string // 对应的MPC分片ID
	ShareIndex    int    // SSS分片索引
	Status        string // pending, delivered, confirmed, failed
	DeliveredAt   *time.Time
	ConfirmedAt   *time.Time
	FailureReason string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

package backup

import (
	"context"
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/infra/storage"
)

// Delivery Status Constants
const (
	DeliveryStatusPending   = "pending"
	DeliveryStatusDelivered = "delivered"
	DeliveryStatusConfirmed = "confirmed"
	DeliveryStatusFailed    = "failed"
)

// BackupShare 备份分片结构
type BackupShare struct {
	KeyID      string    // 根密钥ID
	NodeID     string    // 对应的MPC节点ID（server-proxy-1, server-proxy-2, client-{userID}）
	ShareIndex int       // 备份分片索引（1-5）
	ShareData  []byte    // 备份分片数据（加密存储）
	CreatedAt  time.Time
}

// Store defines the interface for backup storage operations
// It aligns with storage.MetadataStore and storage.BackupShareStorage
type Store interface {
	// Share Operations
	SaveBackupShare(ctx context.Context, keyID, nodeID string, shareIndex int, shareData []byte) error
	GetBackupShare(ctx context.Context, keyID, nodeID string, shareIndex int) ([]byte, error)
	ListBackupShares(ctx context.Context, keyID, nodeID string) ([]*storage.BackupShareInfo, error)

	// Delivery Operations
	SaveBackupShareDelivery(ctx context.Context, delivery *storage.BackupShareDelivery) error
	GetBackupShareDelivery(ctx context.Context, keyID, userID, nodeID string, shareIndex int) (*storage.BackupShareDelivery, error)
	UpdateBackupShareDeliveryStatus(ctx context.Context, keyID, userID, nodeID string, shareIndex int, status string, reason string) error
	ListBackupShareDeliveries(ctx context.Context, keyID, nodeID string) ([]*storage.BackupShareDelivery, error)
}

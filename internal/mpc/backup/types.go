package backup

import "time"

// BackupShare 备份分片结构
type BackupShare struct {
	KeyID      string    // 根密钥ID
	NodeID     string    // 对应的MPC节点ID（server-proxy-1, server-proxy-2, client-{userID}）
	ShareIndex int       // 备份分片索引（1-5）
	ShareData  []byte    // 备份分片数据（加密存储）
	CreatedAt  time.Time
}

// BackupShareDelivery 备份分片下发记录
type BackupShareDelivery struct {
	KeyID      string
	NodeID     string
	UserID     string
	ShareIndex int
	Status     string // pending, delivered, confirmed, failed
	DeliveredAt *time.Time
	ConfirmedAt *time.Time
	CreatedAt  time.Time
}


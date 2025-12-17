package backup

import (
	"context"
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/infra/storage"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// SSSBackupService SSS 备份服务接口
type SSSBackupService interface {
	// GenerateBackupShares 对单个MPC分片生成SSS备份分片
	// 注意：输入是单个MPC分片，不是完整密钥
	GenerateBackupShares(ctx context.Context, mpcShare []byte, threshold, totalShares int) ([]*BackupShare, error)

	// RecoverMPCShareFromBackup 从备份分片恢复单个MPC分片
	// 注意：恢复的是MPC分片，不是完整密钥
	RecoverMPCShareFromBackup(ctx context.Context, shares []*BackupShare) ([]byte, error)

	// DeliverBackupShareToClient 下发备份分片到客户端
	DeliverBackupShareToClient(ctx context.Context, keyID, userID, nodeID string, shareIndex int, share *BackupShare) error
}

// Service SSS 备份服务实现
type Service struct {
	sss            *SSS
	backupStorage  storage.BackupShareStorage
	metadataStore  storage.MetadataStore
}

// NewService 创建 SSS 备份服务
func NewService(
	backupStorage storage.BackupShareStorage,
	metadataStore storage.MetadataStore,
) SSSBackupService {
	return &Service{
		sss:           NewSSS(),
		backupStorage: backupStorage,
		metadataStore: metadataStore,
	}
}

// GenerateBackupShares 对单个MPC分片生成SSS备份分片
func (s *Service) GenerateBackupShares(
	ctx context.Context,
	mpcShare []byte,
	threshold int,
	totalShares int,
) ([]*BackupShare, error) {
	if len(mpcShare) == 0 {
		return nil, errors.New("MPC share cannot be empty")
	}
	if threshold < 2 {
		return nil, errors.New("threshold must be at least 2")
	}
	if totalShares < threshold {
		return nil, errors.New("total shares must be at least threshold")
	}

	// 使用SSS算法对单个MPC分片进行分割
	shareDataList, err := s.sss.Split(mpcShare, totalShares, threshold)
	if err != nil {
		return nil, errors.Wrap(err, "failed to split MPC share using SSS")
	}

	// 转换为BackupShare结构
	backupShares := make([]*BackupShare, len(shareDataList))
	for i, shareData := range shareDataList {
		backupShares[i] = &BackupShare{
			ShareIndex: i + 1,
			ShareData:  shareData,
		}
	}

	return backupShares, nil
}

// RecoverMPCShareFromBackup 从备份分片恢复单个MPC分片
func (s *Service) RecoverMPCShareFromBackup(
	ctx context.Context,
	shares []*BackupShare,
) ([]byte, error) {
	if len(shares) < 3 {
		return nil, errors.New("insufficient backup shares: need at least 3")
	}

	// 提取备份分片数据
	shareData := make([][]byte, len(shares))
	for i, share := range shares {
		shareData[i] = share.ShareData
	}

	// 使用SSS算法恢复MPC分片（不是完整密钥）
	mpcShare, err := s.sss.Combine(shareData)
	if err != nil {
		return nil, errors.Wrap(err, "failed to recover MPC share from backup")
	}

	return mpcShare, nil
}

// DeliverBackupShareToClient 下发备份分片到客户端
func (s *Service) DeliverBackupShareToClient(
	ctx context.Context,
	keyID, userID, nodeID string,
	shareIndex int,
	share *BackupShare,
) error {
	// 1. 保存备份分片到存储（用于后续恢复）
	// 注意：这里保存的是 SSS 备份分片，不是原始 MPC 分片
	if err := s.backupStorage.SaveBackupShare(ctx, keyID, nodeID, shareIndex, share.ShareData); err != nil {
		return errors.Wrapf(err, "failed to save backup share %d for node %s", shareIndex, nodeID)
	}

	// 2. 创建下发记录（初始状态为 pending）
	now := time.Now()
	delivery := &storage.BackupShareDelivery{
		KeyID:      keyID,
		UserID:     userID,
		NodeID:     nodeID,
		ShareIndex: shareIndex,
		Status:     "pending",
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := s.metadataStore.SaveBackupShareDelivery(ctx, delivery); err != nil {
		return errors.Wrap(err, "failed to save backup share delivery record")
	}

	// 3. 准备下发记录（状态为 pending）
	// 实际的加密和传输将由客户端通过 gRPC (RequestShareDelivery) 主动拉取触发
	// 服务端只需确保数据已保存且状态记录已创建

	// 当前实现：保存备份分片和下发记录，状态为 pending
	// 客户端将通过 RequestShareDelivery 接口获取加密分片并确认接收
	log.Info().
		Str("key_id", keyID).
		Str("user_id", userID).
		Str("node_id", nodeID).
		Int("share_index", shareIndex).
		Msg("Backup share saved and delivery record created. Waiting for client retrieval.")

	return nil
}


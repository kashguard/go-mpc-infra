package backup

import (
	"context"

	"github.com/kashguard/go-mpc-wallet/internal/mpc/storage"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// RecoveryService 密钥恢复服务
type RecoveryService struct {
	backupService  SSSBackupService
	backupStorage  storage.BackupShareStorage
	keyShareStorage storage.KeyShareStorage
}

// NewRecoveryService 创建恢复服务
func NewRecoveryService(
	backupService SSSBackupService,
	backupStorage storage.BackupShareStorage,
	keyShareStorage storage.KeyShareStorage,
) *RecoveryService {
	return &RecoveryService{
		backupService:   backupService,
		backupStorage:   backupStorage,
		keyShareStorage: keyShareStorage,
	}
}

// RecoverMPCShare 恢复单个MPC分片（从SSS备份分片）
// 这是分片式恢复的核心方法：只恢复单个MPC分片，不恢复完整密钥
func (s *RecoveryService) RecoverMPCShare(
	ctx context.Context,
	keyID string,
	nodeID string,
) ([]byte, error) {
	// 1. 获取该MPC分片的所有备份分片
	backupShares, err := s.backupStorage.ListBackupShares(ctx, keyID, nodeID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list backup shares")
	}

	if len(backupShares) < 3 {
		return nil, errors.Errorf("insufficient backup shares: need at least 3, have %d", len(backupShares))
	}

	// 2. 转换为 BackupShare 结构
	shares := make([]*BackupShare, len(backupShares))
	for i, bs := range backupShares {
		shares[i] = &BackupShare{
			KeyID:      bs.KeyID,
			NodeID:     bs.NodeID,
			ShareIndex: bs.ShareIndex,
			ShareData:  bs.ShareData,
			CreatedAt:  bs.CreatedAt,
		}
	}

	// 3. 使用SSS算法恢复MPC分片
	mpcShare, err := s.backupService.RecoverMPCShareFromBackup(ctx, shares)
	if err != nil {
		return nil, errors.Wrap(err, "failed to recover MPC share from backup")
	}

	log.Info().
		Str("key_id", keyID).
		Str("node_id", nodeID).
		Int("backup_shares_used", len(shares)).
		Msg("Successfully recovered MPC share from backup")

	return mpcShare, nil
}

// RecoverServerShares 恢复服务器分片（用于签名）
// 这是最常见的恢复场景：服务器分片丢失，需要从备份恢复
func (s *RecoveryService) RecoverServerShares(
	ctx context.Context,
	keyID string,
) error {
	// 恢复 server-proxy-1 的分片
	share1, err := s.RecoverMPCShare(ctx, keyID, "server-proxy-1")
	if err != nil {
		return errors.Wrap(err, "failed to recover server-proxy-1 share")
	}

	// 存储恢复的分片
	if err := s.keyShareStorage.StoreKeyShare(ctx, keyID, "server-proxy-1", share1); err != nil {
		return errors.Wrap(err, "failed to store recovered server-proxy-1 share")
	}

	log.Info().
		Str("key_id", keyID).
		Str("node_id", "server-proxy-1").
		Msg("Recovered and stored server-proxy-1 share")

	// 恢复 server-proxy-2 的分片
	share2, err := s.RecoverMPCShare(ctx, keyID, "server-proxy-2")
	if err != nil {
		return errors.Wrap(err, "failed to recover server-proxy-2 share")
	}

	// 存储恢复的分片
	if err := s.keyShareStorage.StoreKeyShare(ctx, keyID, "server-proxy-2", share2); err != nil {
		return errors.Wrap(err, "failed to store recovered server-proxy-2 share")
	}

	log.Info().
		Str("key_id", keyID).
		Str("node_id", "server-proxy-2").
		Msg("Recovered and stored server-proxy-2 share")

	return nil
}

// RecoverClientShare 恢复客户端分片（可选，不影响签名）
func (s *RecoveryService) RecoverClientShare(
	ctx context.Context,
	keyID string,
	userID string,
) ([]byte, error) {
	nodeID := "client-" + userID
	
	// 恢复客户端分片
	share, err := s.RecoverMPCShare(ctx, keyID, nodeID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to recover client share")
	}

	log.Info().
		Str("key_id", keyID).
		Str("node_id", nodeID).
		Str("user_id", userID).
		Msg("Recovered client share from backup")

	return share, nil
}

// CheckBackupStatus 检查备份分片状态
func (s *RecoveryService) CheckBackupStatus(
	ctx context.Context,
	keyID string,
) (map[string]*BackupStatus, error) {
	// 获取所有备份分片（按nodeID分组）
	allBackupShares, err := s.backupStorage.ListAllBackupShares(ctx, keyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list all backup shares")
	}

	status := make(map[string]*BackupStatus)
	for nodeID, shares := range allBackupShares {
		status[nodeID] = &BackupStatus{
			NodeID:        nodeID,
			TotalShares:   len(shares),
			RequiredShares: 3, // 3-of-5 配置
			Recoverable:   len(shares) >= 3,
		}
	}

	return status, nil
}

// BackupStatus 备份状态
type BackupStatus struct {
	NodeID        string
	TotalShares   int
	RequiredShares int
	Recoverable   bool
}

// ListBackupShares 列出备份分片（单个节点）
func (s *RecoveryService) ListBackupShares(ctx context.Context, keyID, nodeID string) ([]*storage.BackupShareInfo, error) {
	return s.backupStorage.ListBackupShares(ctx, keyID, nodeID)
}

// ListAllBackupShares 列出所有备份分片（所有节点）
func (s *RecoveryService) ListAllBackupShares(ctx context.Context, keyID string) (map[string][]*storage.BackupShareInfo, error) {
	return s.backupStorage.ListAllBackupShares(ctx, keyID)
}


package backup

import (
	"context"
	"testing"

	"github.com/kashguard/go-mpc-wallet/internal/mpc/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockBackupShareStorage 模拟备份分片存储
type MockBackupShareStorage struct {
	mock.Mock
}

func (m *MockBackupShareStorage) SaveBackupShare(ctx context.Context, keyID, nodeID string, shareIndex int, shareData []byte) error {
	args := m.Called(ctx, keyID, nodeID, shareIndex, shareData)
	return args.Error(0)
}

func (m *MockBackupShareStorage) GetBackupShare(ctx context.Context, keyID, nodeID string, shareIndex int) ([]byte, error) {
	args := m.Called(ctx, keyID, nodeID, shareIndex)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockBackupShareStorage) ListBackupShares(ctx context.Context, keyID, nodeID string) ([]*storage.BackupShareInfo, error) {
	args := m.Called(ctx, keyID, nodeID)
	return args.Get(0).([]*storage.BackupShareInfo), args.Error(1)
}

func (m *MockBackupShareStorage) ListAllBackupShares(ctx context.Context, keyID string) (map[string][]*storage.BackupShareInfo, error) {
	args := m.Called(ctx, keyID)
	return args.Get(0).(map[string][]*storage.BackupShareInfo), args.Error(1)
}

func TestSSSBackupService_GenerateBackupShares(t *testing.T) {
	ctx := context.Background()
	mockStorage := new(MockBackupShareStorage)
	
	service := NewService(mockStorage, nil).(*Service)

	// 测试数据：单个MPC分片
	mpcShare := []byte("test-mpc-share-data")
	threshold := 3
	totalShares := 5

	// 生成备份分片
	backupShares, err := service.GenerateBackupShares(ctx, mpcShare, threshold, totalShares)
	assert.NoError(t, err)
	assert.Equal(t, totalShares, len(backupShares))

	// 验证每个备份分片都有正确的索引
	for i, share := range backupShares {
		assert.Equal(t, i+1, share.ShareIndex)
		assert.NotEmpty(t, share.ShareData)
	}
}

func TestSSSBackupService_RecoverMPCShareFromBackup(t *testing.T) {
	ctx := context.Background()
	mockStorage := new(MockBackupShareStorage)
	
	service := NewService(mockStorage, nil).(*Service)

	// 原始MPC分片
	originalShare := []byte("test-mpc-share-for-recovery")

	// 生成备份分片
	backupShares, err := service.GenerateBackupShares(ctx, originalShare, 3, 5)
	assert.NoError(t, err)

	// 使用3个备份分片恢复
	recoveredShare, err := service.RecoverMPCShareFromBackup(ctx, backupShares[:3])
	assert.NoError(t, err)
	assert.Equal(t, originalShare, recoveredShare)

	// 测试使用不足的分片（应该失败）
	_, err = service.RecoverMPCShareFromBackup(ctx, backupShares[:2])
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient")
}


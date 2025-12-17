package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/infra/backup"
	"github.com/kashguard/go-mpc-wallet/internal/infra/storage"
	pb "github.com/kashguard/go-mpc-wallet/internal/pb/infra/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockBackupShareStorage) ListBackupShares(ctx context.Context, keyID, nodeID string) ([]*storage.BackupShareInfo, error) {
	args := m.Called(ctx, keyID, nodeID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*storage.BackupShareInfo), args.Error(1)
}

func (m *MockBackupShareStorage) ListAllBackupShares(ctx context.Context, keyID string) (map[string][]*storage.BackupShareInfo, error) {
	args := m.Called(ctx, keyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string][]*storage.BackupShareInfo), args.Error(1)
}

func TestInfrastructureServer_ListBackupShares_SingleNode(t *testing.T) {
	ctx := context.Background()
	mockStorage := new(MockBackupShareStorage)
	mockBackupService := backup.NewService(mockStorage, nil)
	mockKeyShareStorage := new(MockKeyShareStorage)
	recoveryService := backup.NewRecoveryService(mockBackupService, mockStorage, mockKeyShareStorage)

	server := &InfrastructureServer{
		recoveryService: recoveryService,
	}

	// 准备测试数据
	keyID := "test-key-123"
	nodeID := "server-proxy-1"
	shares := []*storage.BackupShareInfo{
		{
			KeyID:      keyID,
			NodeID:     nodeID,
			ShareIndex: 1,
			ShareData:  []byte("share1"),
			CreatedAt:  time.Now(),
		},
		{
			KeyID:      keyID,
			NodeID:     nodeID,
			ShareIndex: 2,
			ShareData:  []byte("share2"),
			CreatedAt:  time.Now(),
		},
	}

	mockStorage.On("ListBackupShares", ctx, keyID, nodeID).Return(shares, nil)

	// 执行测试
	req := &pb.ListBackupSharesRequest{
		KeyId:  keyID,
		NodeId: nodeID,
	}

	resp, err := server.ListBackupShares(ctx, req)

	// 验证结果
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, keyID, resp.KeyId)
	assert.Len(t, resp.SharesByNode, 1)
	assert.Contains(t, resp.SharesByNode, nodeID)
	assert.Len(t, resp.SharesByNode[nodeID].Shares, 2)

	mockStorage.AssertExpectations(t)
}

func TestInfrastructureServer_ListBackupShares_AllNodes(t *testing.T) {
	ctx := context.Background()
	mockStorage := new(MockBackupShareStorage)
	mockBackupService := backup.NewService(mockStorage, nil)
	mockKeyShareStorage := new(MockKeyShareStorage)
	recoveryService := backup.NewRecoveryService(mockBackupService, mockStorage, mockKeyShareStorage)

	server := &InfrastructureServer{
		recoveryService: recoveryService,
	}

	// 准备测试数据
	keyID := "test-key-123"
	allShares := map[string][]*storage.BackupShareInfo{
		"server-proxy-1": {
			{
				KeyID:      keyID,
				NodeID:     "server-proxy-1",
				ShareIndex: 1,
				ShareData:  []byte("share1"),
				CreatedAt:  time.Now(),
			},
		},
		"server-proxy-2": {
			{
				KeyID:      keyID,
				NodeID:     "server-proxy-2",
				ShareIndex: 1,
				ShareData:  []byte("share2"),
				CreatedAt:  time.Now(),
			},
		},
	}

	mockStorage.On("ListAllBackupShares", ctx, keyID).Return(allShares, nil)

	// 执行测试
	req := &pb.ListBackupSharesRequest{
		KeyId: keyID,
		// NodeId 为空，列出所有节点
	}

	resp, err := server.ListBackupShares(ctx, req)

	// 验证结果
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, keyID, resp.KeyId)
	assert.Len(t, resp.SharesByNode, 2)
	assert.Contains(t, resp.SharesByNode, "server-proxy-1")
	assert.Contains(t, resp.SharesByNode, "server-proxy-2")

	mockStorage.AssertExpectations(t)
}

func TestInfrastructureServer_ListBackupShares_NoRecoveryService(t *testing.T) {
	ctx := context.Background()
	server := &InfrastructureServer{
		recoveryService: nil,
	}

	req := &pb.ListBackupSharesRequest{
		KeyId: "test-key-123",
	}

	resp, err := server.ListBackupShares(ctx, req)

	// 验证错误
	assert.Error(t, err)
	assert.Nil(t, resp)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

// MockKeyShareStorage 模拟密钥分片存储（简化版，仅用于测试）
type MockKeyShareStorage struct {
	mock.Mock
}

func (m *MockKeyShareStorage) StoreKeyShare(ctx context.Context, keyID string, nodeID string, share []byte) error {
	args := m.Called(ctx, keyID, nodeID, share)
	return args.Error(0)
}

func (m *MockKeyShareStorage) GetKeyShare(ctx context.Context, keyID string, nodeID string) ([]byte, error) {
	args := m.Called(ctx, keyID, nodeID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockKeyShareStorage) DeleteKeyShare(ctx context.Context, keyID string, nodeID string) error {
	args := m.Called(ctx, keyID, nodeID)
	return args.Error(0)
}

func (m *MockKeyShareStorage) ListKeyShares(ctx context.Context, nodeID string) ([]string, error) {
	args := m.Called(ctx, nodeID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockKeyShareStorage) StoreKeyData(ctx context.Context, keyID string, nodeID string, keyData []byte) error {
	args := m.Called(ctx, keyID, nodeID, keyData)
	return args.Error(0)
}

func (m *MockKeyShareStorage) GetKeyData(ctx context.Context, keyID string, nodeID string) ([]byte, error) {
	args := m.Called(ctx, keyID, nodeID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}


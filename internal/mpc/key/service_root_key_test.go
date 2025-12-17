package key

import (
	"context"
	"testing"

	"github.com/kashguard/go-mpc-wallet/internal/mpc/backup"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/protocol"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockDKGService 模拟DKG服务
type MockDKGService struct {
	mock.Mock
}

func (m *MockDKGService) ExecuteDKG(ctx context.Context, keyID string, req *CreateKeyRequest) (*protocol.KeyGenResponse, error) {
	args := m.Called(ctx, keyID, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*protocol.KeyGenResponse), args.Error(1)
}

// MockBackupService 模拟备份服务
type MockBackupService struct {
	mock.Mock
}

func (m *MockBackupService) GenerateBackupShares(ctx context.Context, mpcShare []byte, threshold, totalShares int) ([]*backup.BackupShare, error) {
	args := m.Called(ctx, mpcShare, threshold, totalShares)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*backup.BackupShare), args.Error(1)
}

func (m *MockBackupService) RecoverMPCShareFromBackup(ctx context.Context, shares []*backup.BackupShare) ([]byte, error) {
	args := m.Called(ctx, shares)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockBackupService) DeliverBackupShareToClient(ctx context.Context, keyID, userID, nodeID string, shareIndex int, share *backup.BackupShare) error {
	args := m.Called(ctx, keyID, userID, nodeID, shareIndex, share)
	return args.Error(0)
}

func TestService_CreateRootKey_2of3(t *testing.T) {
	ctx := context.Background()

	// 创建模拟依赖
	mockMetadataStore := new(MockMetadataStore)
	mockKeyShareStorage := new(MockKeyShareStorage)
	mockProtocolEngine := new(MockProtocolEngine)
	mockDKGService := new(MockDKGService)
	mockBackupService := new(MockBackupService)

	// 设置DKG响应
	dkgResp := &protocol.KeyGenResponse{
		PublicKey: &protocol.PublicKey{
			Hex:   "test-public-key",
			Bytes: []byte("test-public-key"),
		},
		KeyShares: map[string]*protocol.KeyShare{
			"server-proxy-1": {
				Share: []byte("server-1-share"),
			},
			"server-proxy-2": {
				Share: []byte("server-2-share"),
			},
			"client-user123": {
				Share: []byte("client-share"),
			},
		},
	}

	mockDKGService.On("ExecuteDKG", mock.Anything, mock.Anything, mock.Anything).Return(dkgResp, nil)
	mockProtocolEngine.On("GenerateKeyShare", mock.Anything, mock.Anything).Return(dkgResp, nil)

	// 设置备份服务响应
	backupShares := []*backup.BackupShare{
		{ShareIndex: 1, ShareData: []byte("backup-share-1")},
		{ShareIndex: 2, ShareData: []byte("backup-share-2")},
		{ShareIndex: 3, ShareData: []byte("backup-share-3")},
		{ShareIndex: 4, ShareData: []byte("backup-share-4")},
		{ShareIndex: 5, ShareData: []byte("backup-share-5")},
	}

	mockBackupService.On("GenerateBackupShares", mock.Anything, mock.Anything, 3, 5).Return(backupShares, nil)
	mockBackupService.On("DeliverBackupShareToClient", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	// 设置存储响应
	mockMetadataStore.On("SaveKeyMetadata", mock.Anything, mock.Anything).Return(nil)
	mockKeyShareStorage.On("StoreKeyShare", mock.Anything, mock.Anything, mock.MatchedBy(func(nodeID string) bool {
		return nodeID == "server-proxy-1" || nodeID == "server-proxy-2"
	}), mock.Anything).Return(nil)
	mockMetadataStore.
		On("GetSigningSession", mock.Anything, mock.Anything).
		Return(&storage.SigningSession{
			SessionID:          "session-placeholder",
			KeyID:              "key-placeholder",
			Status:             "completed",
			ParticipatingNodes: []string{"server-proxy-1", "server-proxy-2", "client-user123"},
			Threshold:          2,
			TotalNodes:         3,
		}, nil).
		Run(func(args mock.Arguments) {
			if sess, ok := args.Get(0).(*storage.SigningSession); ok {
				id := args.String(1)
				sess.SessionID = id
				sess.KeyID = id
			}
		})
	mockMetadataStore.On("SaveSigningSession", mock.Anything, mock.Anything).Return(nil)
	mockMetadataStore.On("UpdateSigningSession", mock.Anything, mock.Anything).Return(nil)

	// 创建DKG服务（需要传入必要的依赖）
	dkgService := &DKGService{
		metadataStore:   mockMetadataStore,
		keyShareStorage: mockKeyShareStorage,
		protocolEngine:  mockProtocolEngine,
		nodeManager:     nil, // 测试中不需要
		nodeDiscovery:   nil, // 测试中不需要
		MaxWaitTime:     1_000_000_000, // 1s
		PollInterval:    10_000_000,    // 10ms
	}

	// 创建服务
	service := NewService(
		mockMetadataStore,
		mockKeyShareStorage,
		mockProtocolEngine,
		dkgService,
		mockBackupService,
	)

	// 测试创建根密钥
	req := &CreateRootKeyRequest{
		Algorithm:  "ECDSA",
		Curve:      "secp256k1",
		Protocol:   "gg20",
		Threshold:  2,
		TotalNodes: 3,
		UserID:     "user123",
	}

	rootKey, err := service.CreateRootKey(ctx, req)
	assert.NoError(t, err)
	assert.NotNil(t, rootKey)
	assert.Equal(t, 2, rootKey.Threshold)
	assert.Equal(t, 3, rootKey.TotalNodes)
	assert.Equal(t, "Active", rootKey.Status)

	// 验证只存储了服务器分片
	mockKeyShareStorage.AssertNumberOfCalls(t, "StoreKeyShare", 2)
	mockKeyShareStorage.AssertNotCalled(t, "StoreKeyShare", mock.Anything, mock.Anything, "client-user123", mock.Anything)

	// 验证生成了备份分片（每个MPC分片生成5个备份分片）
	mockBackupService.AssertNumberOfCalls(t, "GenerateBackupShares", 3) // 3个MPC分片
}

func TestService_DeriveWalletKey(t *testing.T) {
	ctx := context.Background()
	mockMetadataStore := new(MockMetadataStore)
	mockKeyShareStorage := new(MockKeyShareStorage)
	mockProtocolEngine := new(MockProtocolEngine)
	// mockDKGService := new(MockDKGService) // Unused
	mockBackupService := new(MockBackupService)

	// Create real DKGService with mocks
	dkgService := &DKGService{
		metadataStore:   mockMetadataStore,
		keyShareStorage: mockKeyShareStorage,
		protocolEngine:  mockProtocolEngine,
		MaxWaitTime:     100,
		PollInterval:    10,
	}

	service := NewService(mockMetadataStore, mockKeyShareStorage, mockProtocolEngine, dkgService, mockBackupService)

	rootKeyID := "root-key-123"
	// Compressed public key (33 bytes) hex
	pubKeyHex := "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
	chainCodeHex := "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"

	mockMetadataStore.On("GetKeyMetadata", mock.Anything, rootKeyID).Return(&storage.KeyMetadata{
		KeyID:     rootKeyID,
		PublicKey: pubKeyHex,
		Algorithm: "ECDSA",
		Curve:     "secp256k1",
		ChainCode: chainCodeHex,
		Status:    "Active",
	}, nil)

	// Capture the saved wallet key to verify ChainCode
	mockMetadataStore.On("SaveKeyMetadata", mock.Anything, mock.MatchedBy(func(k *storage.KeyMetadata) bool {
		return k.ChainCode != "" && k.PublicKey != pubKeyHex
	})).Return(nil)

	req := &DeriveWalletKeyRequest{
		RootKeyID:   rootKeyID,
		ChainType:   "ethereum",
		Index:       0,
		Description: "Derived Eth Key",
	}

	derivedKey, err := service.DeriveWalletKey(ctx, req)
	assert.NoError(t, err)
	assert.NotNil(t, derivedKey)
	assert.NotEqual(t, pubKeyHex, derivedKey.PublicKey)
	assert.NotEmpty(t, derivedKey.ChainCode)
	
	// Test migration (missing chain code)
	mockMetadataStore.On("GetKeyMetadata", mock.Anything, "root-key-migration").Return(&storage.KeyMetadata{
		KeyID:     "root-key-migration",
		PublicKey: pubKeyHex,
		Algorithm: "ECDSA",
		Curve:     "secp256k1",
		ChainCode: "", // Missing
		Status:    "Active",
	}, nil)

	// Expect update with generated chain code
	mockMetadataStore.On("UpdateKeyMetadata", mock.Anything, mock.MatchedBy(func(k *storage.KeyMetadata) bool {
		return k.KeyID == "root-key-migration" && k.ChainCode != ""
	})).Return(nil)

	reqMigration := &DeriveWalletKeyRequest{
		RootKeyID:   "root-key-migration",
		ChainType:   "ethereum",
		Index:       1,
	}

	derivedKey2, err := service.DeriveWalletKey(ctx, reqMigration)
	assert.NoError(t, err)
	assert.NotNil(t, derivedKey2)
	assert.NotEqual(t, pubKeyHex, derivedKey2.PublicKey)
	assert.NotEmpty(t, derivedKey2.ChainCode)
}

// MockMetadataStore 模拟元数据存储
type MockMetadataStore struct {
	mock.Mock
}

func (m *MockMetadataStore) SaveKeyMetadata(ctx context.Context, key *storage.KeyMetadata) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *MockMetadataStore) GetKeyMetadata(ctx context.Context, keyID string) (*storage.KeyMetadata, error) {
	args := m.Called(ctx, keyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.KeyMetadata), args.Error(1)
}

func (m *MockMetadataStore) UpdateKeyMetadata(ctx context.Context, key *storage.KeyMetadata) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *MockMetadataStore) DeleteKeyMetadata(ctx context.Context, keyID string) error {
	args := m.Called(ctx, keyID)
	return args.Error(0)
}

func (m *MockMetadataStore) ListKeys(ctx context.Context, filter *storage.KeyFilter) ([]*storage.KeyMetadata, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*storage.KeyMetadata), args.Error(1)
}

// BackupShareStorage 相关方法（用于类型断言）
func (m *MockMetadataStore) SaveBackupShare(ctx context.Context, keyID, nodeID string, shareIndex int, shareData []byte) error {
	return nil
}
func (m *MockMetadataStore) GetBackupShare(ctx context.Context, keyID, nodeID string, shareIndex int) ([]byte, error) {
	return nil, nil
}
func (m *MockMetadataStore) ListBackupShares(ctx context.Context, keyID, nodeID string) ([]*storage.BackupShareInfo, error) {
	return []*storage.BackupShareInfo{}, nil
}
func (m *MockMetadataStore) ListAllBackupShares(ctx context.Context, keyID string) (map[string][]*storage.BackupShareInfo, error) {
	return map[string][]*storage.BackupShareInfo{}, nil
}

func (m *MockMetadataStore) SaveNode(ctx context.Context, node *storage.NodeInfo) error {
	args := m.Called(ctx, node)
	return args.Error(0)
}

func (m *MockMetadataStore) GetNode(ctx context.Context, nodeID string) (*storage.NodeInfo, error) {
	args := m.Called(ctx, nodeID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.NodeInfo), args.Error(1)
}

func (m *MockMetadataStore) UpdateNode(ctx context.Context, node *storage.NodeInfo) error {
	args := m.Called(ctx, node)
	return args.Error(0)
}

func (m *MockMetadataStore) ListNodes(ctx context.Context, filter *storage.NodeFilter) ([]*storage.NodeInfo, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*storage.NodeInfo), args.Error(1)
}

func (m *MockMetadataStore) UpdateNodeHeartbeat(ctx context.Context, nodeID string) error {
	args := m.Called(ctx, nodeID)
	return args.Error(0)
}

func (m *MockMetadataStore) SaveSigningSession(ctx context.Context, session *storage.SigningSession) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

func (m *MockMetadataStore) GetSigningSession(ctx context.Context, sessionID string) (*storage.SigningSession, error) {
	args := m.Called(ctx, sessionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.SigningSession), args.Error(1)
}

func (m *MockMetadataStore) UpdateSigningSession(ctx context.Context, session *storage.SigningSession) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

func (m *MockMetadataStore) SaveBackupShareDelivery(ctx context.Context, delivery *storage.BackupShareDelivery) error {
	args := m.Called(ctx, delivery)
	return args.Error(0)
}

func (m *MockMetadataStore) GetBackupShareDelivery(ctx context.Context, keyID, userID, nodeID string, shareIndex int) (*storage.BackupShareDelivery, error) {
	args := m.Called(ctx, keyID, userID, nodeID, shareIndex)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.BackupShareDelivery), args.Error(1)
}

func (m *MockMetadataStore) UpdateBackupShareDeliveryStatus(ctx context.Context, keyID, userID, nodeID string, shareIndex int, status string, reason string) error {
	args := m.Called(ctx, keyID, userID, nodeID, shareIndex, status, reason)
	return args.Error(0)
}

func (m *MockMetadataStore) ListBackupShareDeliveries(ctx context.Context, keyID, nodeID string) ([]*storage.BackupShareDelivery, error) {
	args := m.Called(ctx, keyID, nodeID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*storage.BackupShareDelivery), args.Error(1)
}

// MockKeyShareStorage 模拟密钥分片存储
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

// MockProtocolEngine 模拟协议引擎
type MockProtocolEngine struct {
	mock.Mock
}

func (m *MockProtocolEngine) GenerateKeyShare(ctx context.Context, req *protocol.KeyGenRequest) (*protocol.KeyGenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*protocol.KeyGenResponse), args.Error(1)
}

func (m *MockProtocolEngine) ThresholdSign(ctx context.Context, sessionID string, req *protocol.SignRequest) (*protocol.SignResponse, error) {
	args := m.Called(ctx, sessionID, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*protocol.SignResponse), args.Error(1)
}

func (m *MockProtocolEngine) VerifySignature(ctx context.Context, sig *protocol.Signature, msg []byte, pubKey *protocol.PublicKey) (bool, error) {
	args := m.Called(ctx, sig, msg, pubKey)
	return args.Bool(0), args.Error(1)
}

func (m *MockProtocolEngine) DefaultProtocol() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockProtocolEngine) ProcessIncomingKeygenMessage(ctx context.Context, sessionID string, fromNodeID string, msgData []byte, isBroadcast bool) error {
	args := m.Called(ctx, sessionID, fromNodeID, msgData, isBroadcast)
	return args.Error(0)
}

func (m *MockProtocolEngine) ProcessIncomingSigningMessage(ctx context.Context, sessionID string, fromNodeID string, msgData []byte, isBroadcast bool) error {
	args := m.Called(ctx, sessionID, fromNodeID, msgData, isBroadcast)
	return args.Error(0)
}

func (m *MockProtocolEngine) RotateKey(ctx context.Context, keyID string) error {
	args := m.Called(ctx, keyID)
	return args.Error(0)
}

func (m *MockProtocolEngine) KeyRefresh(ctx context.Context, keyID string) error {
	args := m.Called(ctx, keyID)
	return args.Error(0)
}

func (m *MockProtocolEngine) SupportedProtocols() []string {
	args := m.Called()
	if args.Get(0) == nil {
		return []string{"gg20"}
	}
	return args.Get(0).([]string)
}


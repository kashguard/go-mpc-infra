package backup_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/kashguard/go-mpc-wallet/internal/config"
	"github.com/kashguard/go-mpc-wallet/internal/infra/backup"
	infra_grpc "github.com/kashguard/go-mpc-wallet/internal/infra/grpc"
	"github.com/kashguard/go-mpc-wallet/internal/infra/storage"
	pb "github.com/kashguard/go-mpc-wallet/internal/pb/infra/v1"
	sdk "github.com/kashguard/go-mpc-wallet/pkg/sdk/backup"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// InMemoryStore implements backup.Store
type InMemoryStore struct {
	shares     map[string][]byte
	deliveries map[string]*storage.BackupShareDelivery
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		shares:     make(map[string][]byte),
		deliveries: make(map[string]*storage.BackupShareDelivery),
	}
}

func (s *InMemoryStore) SaveBackupShare(ctx context.Context, keyID, nodeID string, shareIndex int, shareData []byte) error {
	key := fmt.Sprintf("%s-%s-%d", keyID, nodeID, shareIndex)
	s.shares[key] = shareData
	return nil
}

func (s *InMemoryStore) GetBackupShare(ctx context.Context, keyID, nodeID string, shareIndex int) ([]byte, error) {
	key := fmt.Sprintf("%s-%s-%d", keyID, nodeID, shareIndex)
	data, ok := s.shares[key]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return data, nil
}

func (s *InMemoryStore) ListBackupShares(ctx context.Context, keyID, nodeID string) ([]*storage.BackupShareInfo, error) {
	return nil, nil // Not needed for this test
}

func (s *InMemoryStore) SaveBackupShareDelivery(ctx context.Context, delivery *storage.BackupShareDelivery) error {
	key := fmt.Sprintf("%s-%s-%s-%d", delivery.KeyID, delivery.UserID, delivery.NodeID, delivery.ShareIndex)
	s.deliveries[key] = delivery
	return nil
}

func (s *InMemoryStore) GetBackupShareDelivery(ctx context.Context, keyID, userID, nodeID string, shareIndex int) (*storage.BackupShareDelivery, error) {
	key := fmt.Sprintf("%s-%s-%s-%d", keyID, userID, nodeID, shareIndex)
	d, ok := s.deliveries[key]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return d, nil
}

func (s *InMemoryStore) UpdateBackupShareDeliveryStatus(ctx context.Context, keyID, userID, nodeID string, shareIndex int, status string, reason string) error {
	key := fmt.Sprintf("%s-%s-%s-%d", keyID, userID, nodeID, shareIndex)
	d, ok := s.deliveries[key]
	if !ok {
		return fmt.Errorf("not found")
	}
	d.Status = status
	if reason != "" {
		d.FailureReason = reason
	}
	if status == "delivered" {
		now := time.Now()
		d.DeliveredAt = &now
	}
	if status == "confirmed" {
		now := time.Now()
		d.ConfirmedAt = &now
	}
	return nil
}

func (s *InMemoryStore) ListBackupShareDeliveries(ctx context.Context, keyID, nodeID string) ([]*storage.BackupShareDelivery, error) {
	return nil, nil // Not needed
}

const bufSize = 1024 * 1024

var lis *bufconn.Listener

func initServer(t *testing.T, store backup.Store) *grpc.Server {
	lis = bufconn.Listen(bufSize)
	s := grpc.NewServer()

	// Initialize InfrastructureServer
	cfg := &config.Server{
		MPC: config.MPC{
			GRPCPort:   0,
			TLSEnabled: false,
		},
	}

	// We only need store for this test
	srv := infra_grpc.NewInfrastructureServer(cfg, nil, nil, nil, nil, store)

	// Register service
	pb.RegisterBackupDeliveryServiceServer(s, srv)

	go func() {
		if err := s.Serve(lis); err != nil {
			// log.Fatalf("Server exited with error: %v", err)
		}
	}()

	return s
}

func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
}

func TestBackupDeliveryIntegration(t *testing.T) {
	// Setup
	store := NewInMemoryStore()

	// Pre-populate a share
	keyID := "key-123"
	nodeID := "node-1"
	shareIndex := 1
	originalShare := []byte("my-secret-share-data")
	err := store.SaveBackupShare(context.Background(), keyID, nodeID, shareIndex, originalShare)
	require.NoError(t, err)

	// Start Server
	server := initServer(t, store)
	defer server.Stop()

	// Create Client
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	// Generate client keys
	clientPrivKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	clientID := "user-456"

	client := sdk.NewClient(conn, clientPrivKey, clientID)

	// 1. Request and Decrypt Share
	decryptedShare, err := client.RequestAndDecryptShare(ctx, keyID, nodeID, shareIndex)
	require.NoError(t, err)
	assert.Equal(t, originalShare, decryptedShare)

	// Check state is delivered
	delivery, err := store.GetBackupShareDelivery(ctx, keyID, clientID, nodeID, shareIndex)
	require.NoError(t, err)
	assert.Equal(t, "delivered", delivery.Status)

	// 2. Confirm Delivery
	err = client.ConfirmDelivery(ctx, keyID, nodeID, shareIndex)
	require.NoError(t, err)

	// Check state is confirmed
	delivery, err = store.GetBackupShareDelivery(ctx, keyID, clientID, nodeID, shareIndex)
	require.NoError(t, err)
	assert.Equal(t, "confirmed", delivery.Status)

	// 3. Query Status
	statusResp, err := client.QueryStatus(ctx, keyID, nodeID, shareIndex)
	require.NoError(t, err)
	assert.Equal(t, "confirmed", statusResp.Status)
}

package backup

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	pb "github.com/kashguard/go-mpc-wallet/internal/pb/infra/v1"
	pkgbackup "github.com/kashguard/go-mpc-wallet/pkg/backup"
	"google.golang.org/grpc"
)

// Client is the backup delivery client.
type Client struct {
	client     pb.BackupDeliveryServiceClient
	privateKey *ecdsa.PrivateKey
	clientID   string
}

// NewClient creates a new backup delivery client.
func NewClient(conn grpc.ClientConnInterface, privateKey *ecdsa.PrivateKey, clientID string) *Client {
	return &Client{
		client:     pb.NewBackupDeliveryServiceClient(conn),
		privateKey: privateKey,
		clientID:   clientID,
	}
}

// RequestAndDecryptShare requests a backup share and decrypts it.
func (c *Client) RequestAndDecryptShare(ctx context.Context, keyID, nodeID string, shareIndex int) ([]byte, error) {
	// 1. Marshal public key
	pubKeyBytes := crypto.FromECDSAPub(&c.privateKey.PublicKey)

	// 2. Request share
	req := &pb.ShareDeliveryRequest{
		KeyId:           keyID,
		NodeId:          nodeID,
		ShareIndex:      int32(shareIndex),
		ClientPublicKey: pubKeyBytes,
		ClientId:        c.clientID,
	}

	resp, err := c.client.RequestShareDelivery(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to request share: %w", err)
	}

	// 3. Decrypt share
	decryptedShare, err := pkgbackup.DecryptShare(resp.EncryptedShare, c.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt share: %w", err)
	}

	return decryptedShare, nil
}

// ConfirmDelivery confirms that the share was received and processed successfully.
func (c *Client) ConfirmDelivery(ctx context.Context, keyID, nodeID string, shareIndex int) error {
	req := &pb.ShareConfirmationRequest{
		KeyId:                keyID,
		NodeId:               nodeID,
		ShareIndex:           int32(shareIndex),
		ReceivedSuccessfully: true,
		ClientId:             c.clientID,
	}

	resp, err := c.client.ConfirmShareDelivery(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to confirm delivery: %w", err)
	}

	if !resp.Confirmed {
		return fmt.Errorf("server rejected confirmation: %s", resp.Message)
	}

	return nil
}

// ReportFailure reports a failure in processing the share.
func (c *Client) ReportFailure(ctx context.Context, keyID, nodeID string, shareIndex int, reason string) error {
	req := &pb.ShareConfirmationRequest{
		KeyId:                keyID,
		NodeId:               nodeID,
		ShareIndex:           int32(shareIndex),
		ReceivedSuccessfully: false,
		FailureReason:        reason,
		ClientId:             c.clientID,
	}

	_, err := c.client.ConfirmShareDelivery(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to report failure: %w", err)
	}

	return nil
}

// QueryStatus queries the status of a share delivery.
func (c *Client) QueryStatus(ctx context.Context, keyID, nodeID string, shareIndex int) (*pb.ShareStatusResponse, error) {
	req := &pb.ShareStatusQuery{
		KeyId:      keyID,
		NodeId:     nodeID,
		ShareIndex: int32(shareIndex),
		ClientId:   c.clientID,
	}

	return c.client.QueryShareStatus(ctx, req)
}

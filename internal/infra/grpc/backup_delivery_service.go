package grpc

import (
	"context"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	pb "github.com/kashguard/go-mpc-wallet/internal/pb/infra/v1"
	pkgbackup "github.com/kashguard/go-mpc-wallet/pkg/backup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RequestShareDelivery 请求分片下发
func (s *InfrastructureServer) RequestShareDelivery(ctx context.Context, req *pb.ShareDeliveryRequest) (*pb.ShareDeliveryResponse, error) {
	// 1. Get the backup share data
	shareData, err := s.store.GetBackupShare(ctx, req.KeyId, req.NodeId, int(req.ShareIndex))
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backup share not found: %v", err)
	}

	// 2. Parse client public key
	pubKey, err := crypto.UnmarshalPubkey(req.ClientPublicKey)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid public key: %v", err)
	}

	// 3. Encrypt the share
	encryptedShare, err := pkgbackup.EncryptShare(shareData, pubKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to encrypt share: %v", err)
	}

	// 4. Update state machine
	// We use ClientId from request as UserID in storage
	_, err = s.deliveryStateMachine.StartDelivery(ctx, req.KeyId, req.NodeId, req.ClientId, int(req.ShareIndex))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to start delivery: %v", err)
	}

	if err := s.deliveryStateMachine.TransitionToDelivered(ctx, req.KeyId, req.ClientId, req.NodeId, int(req.ShareIndex)); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update state to delivered: %v", err)
	}

	return &pb.ShareDeliveryResponse{
		EncryptedShare: encryptedShare,
		Timestamp:      time.Now().Unix(),
	}, nil
}

// ConfirmShareDelivery 确认分片下发
func (s *InfrastructureServer) ConfirmShareDelivery(ctx context.Context, req *pb.ShareConfirmationRequest) (*pb.ShareConfirmationResponse, error) {
	if req.ReceivedSuccessfully {
		err := s.deliveryStateMachine.TransitionToConfirmed(ctx, req.KeyId, req.ClientId, req.NodeId, int(req.ShareIndex))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to confirm delivery: %v", err)
		}
		return &pb.ShareConfirmationResponse{
			Confirmed: true,
			Message:   "Delivery confirmed",
		}, nil
	} else {
		err := s.deliveryStateMachine.TransitionToFailed(ctx, req.KeyId, req.ClientId, req.NodeId, int(req.ShareIndex), req.FailureReason)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to report failure: %v", err)
		}
		return &pb.ShareConfirmationResponse{
			Confirmed: false,
			Message:   "Failure recorded",
		}, nil
	}
}

// QueryShareStatus 查询分片状态
func (s *InfrastructureServer) QueryShareStatus(ctx context.Context, req *pb.ShareStatusQuery) (*pb.ShareStatusResponse, error) {
	delivery, err := s.store.GetBackupShareDelivery(ctx, req.KeyId, req.ClientId, req.NodeId, int(req.ShareIndex))
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "delivery record not found: %v", err)
	}

	resp := &pb.ShareStatusResponse{
		Status: delivery.Status,
	}

	if delivery.DeliveredAt != nil {
		resp.DeliveredAt = delivery.DeliveredAt.Unix()
	}
	if delivery.ConfirmedAt != nil {
		resp.ConfirmedAt = delivery.ConfirmedAt.Unix()
	}
	resp.FailureReason = delivery.FailureReason

	return resp, nil
}

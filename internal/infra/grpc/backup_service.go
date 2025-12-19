package grpc

import (
	"context"
	"fmt"

	"github.com/kashguard/go-mpc-infra/internal/infra/backup"
	pb "github.com/kashguard/go-mpc-infra/internal/pb/infra/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// BackupService implementation

func (s *InfrastructureServer) RecoverMPCShare(ctx context.Context, req *pb.RecoverMPCShareRequest) (*pb.RecoverMPCShareResponse, error) {
	if req.KeyId == "" || req.NodeId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id and node_id are required")
	}

	// 1. Collect available shares
	var shares []*backup.BackupShare

	// A. From User Request (if provided)
	if len(req.ShareData) > 0 {
		// User provided share
		// SSS share data usually contains the index as the first byte
		if len(req.ShareData) < 2 {
			return nil, status.Error(codes.InvalidArgument, "invalid share data length")
		}
		// Index is the first byte
		idx := int(req.ShareData[0])
		shares = append(shares, &backup.BackupShare{
			ShareIndex: idx,
			ShareData:  req.ShareData,
		})
	}

	// B. From DB (server-held shares)
	storedShares, err := s.store.ListBackupShares(ctx, req.KeyId, req.NodeId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list stored shares: %v", err)
	}

	for _, info := range storedShares {
		shares = append(shares, &backup.BackupShare{
			ShareIndex: info.ShareIndex,
			ShareData:  info.ShareData,
		})
	}

	if len(shares) < 3 {
		return &pb.RecoverMPCShareResponse{
			KeyId:   req.KeyId,
			NodeId:  req.NodeId,
			Success: false,
			Message: fmt.Sprintf("Insufficient shares: have %d, need at least 3", len(shares)),
		}, nil
	}

	// 2. Recover
	mpcShare, err := s.backupService.RecoverMPCShareFromBackup(ctx, shares)
	if err != nil {
		return &pb.RecoverMPCShareResponse{
			KeyId:   req.KeyId,
			NodeId:  req.NodeId,
			Success: false,
			Message: fmt.Sprintf("Recovery failed: %v", err),
		}, nil
	}

	// 3. Save recovered MPC share to KeyShareStorage
	if err := s.keyService.RestoreKeyShare(ctx, req.KeyId, req.NodeId, mpcShare); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to restore key share: %v", err)
	}

	return &pb.RecoverMPCShareResponse{
		KeyId:   req.KeyId,
		NodeId:  req.NodeId,
		Success: true,
		Message: "Successfully recovered and restored MPC share",
	}, nil
}

func (s *InfrastructureServer) GetBackupStatus(ctx context.Context, req *pb.GetBackupStatusRequest) (*pb.GetBackupStatusResponse, error) {
	if s.recoveryService == nil {
		return nil, status.Error(codes.Unimplemented, "Recovery service not available")
	}
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	statusMap, err := s.recoveryService.CheckBackupStatus(ctx, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backup status: %v", err)
	}
	statuses := make([]*pb.BackupStatus, 0, len(statusMap))
	for _, st := range statusMap {
		statuses = append(statuses, &pb.BackupStatus{
			NodeId:         st.NodeID,
			TotalShares:    int32(st.TotalShares),
			RequiredShares: int32(st.RequiredShares),
			Recoverable:    st.Recoverable,
		})
	}
	return &pb.GetBackupStatusResponse{
		KeyId:    req.KeyId,
		Statuses: statuses,
	}, nil
}

func (s *InfrastructureServer) ListBackupShares(ctx context.Context, req *pb.ListBackupSharesRequest) (*pb.ListBackupSharesResponse, error) {
	// Use recoveryService to access backup storage and follow test expectations
	if s.recoveryService == nil {
		return nil, status.Error(codes.Unimplemented, "Recovery service not available")
	}

	sharesByNode := make(map[string]*pb.BackupShares)

	// If node_id provided, list that node's shares; otherwise list all nodes
	if req.NodeId != "" {
		storedShares, err := s.recoveryService.ListBackupShares(ctx, req.KeyId, req.NodeId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to list shares: %v", err)
		}

		// Group by NodeID (single group)
		for _, info := range storedShares {
			nodeGroup, ok := sharesByNode[info.NodeID]
			if !ok {
				nodeGroup = &pb.BackupShares{
					NodeId: info.NodeID,
					Shares: []*pb.BackupShare{},
				}
				sharesByNode[info.NodeID] = nodeGroup
			}

			nodeGroup.Shares = append(nodeGroup.Shares, &pb.BackupShare{
				KeyId:      info.KeyID,
				NodeId:     info.NodeID,
				ShareIndex: int32(info.ShareIndex),
				CreatedAt:  info.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			})
		}
	} else {
		allShares, err := s.recoveryService.ListAllBackupShares(ctx, req.KeyId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to list all shares: %v", err)
		}

		for nodeID, infos := range allShares {
			nodeGroup, ok := sharesByNode[nodeID]
			if !ok {
				nodeGroup = &pb.BackupShares{
					NodeId: nodeID,
					Shares: []*pb.BackupShare{},
				}
				sharesByNode[nodeID] = nodeGroup
			}

			for _, info := range infos {
				nodeGroup.Shares = append(nodeGroup.Shares, &pb.BackupShare{
					KeyId:      info.KeyID,
					NodeId:     info.NodeID,
					ShareIndex: int32(info.ShareIndex),
					CreatedAt:  info.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
				})
			}
		}
	}

	return &pb.ListBackupSharesResponse{
		KeyId:        req.KeyId,
		SharesByNode: sharesByNode,
	}, nil
}

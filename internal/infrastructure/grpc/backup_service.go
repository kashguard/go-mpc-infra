package grpc

import (
	"context"
	"time"

	pb "github.com/kashguard/go-mpc-wallet/internal/pb/infrastructure/v1"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RecoverMPCShare 恢复MPC分片
func (s *InfrastructureServer) RecoverMPCShare(ctx context.Context, req *pb.RecoverMPCShareRequest) (*pb.RecoverMPCShareResponse, error) {
	log.Info().
		Str("key_id", req.KeyId).
		Str("node_id", req.NodeId).
		Msg("RecoverMPCShare gRPC request")

	if s.recoveryService == nil {
		return nil, status.Error(codes.Unimplemented, "recovery service not available")
	}

	// 根据节点ID判断恢复类型
	if req.NodeId == "server-proxy-1" || req.NodeId == "server-proxy-2" {
		// 恢复服务器分片
		if err := s.recoveryService.RecoverServerShares(ctx, req.KeyId); err != nil {
			log.Error().Err(err).Str("key_id", req.KeyId).Msg("Failed to recover server shares")
			return &pb.RecoverMPCShareResponse{
				KeyId:    req.KeyId,
				NodeId:   req.NodeId,
				Success:  false,
				Message:  errors.Wrap(err, "failed to recover server shares").Error(),
			}, nil
		}

		return &pb.RecoverMPCShareResponse{
			KeyId:    req.KeyId,
			NodeId:   req.NodeId,
			Success:  true,
			Message:  "Server shares recovered successfully",
		}, nil
	} else if req.NodeId != "" {
		// 恢复客户端分片（需要 userID）
		// 从 nodeID 中提取 userID（格式：client-{userID}）
		userID := ""
		if len(req.NodeId) > 7 && req.NodeId[:7] == "client-" {
			userID = req.NodeId[7:]
		}

		if userID == "" {
			return nil, status.Error(codes.InvalidArgument, "invalid client node ID format")
		}

		share, err := s.recoveryService.RecoverClientShare(ctx, req.KeyId, userID)
		if err != nil {
			log.Error().Err(err).Str("key_id", req.KeyId).Str("node_id", req.NodeId).Msg("Failed to recover client share")
			return &pb.RecoverMPCShareResponse{
				KeyId:    req.KeyId,
				NodeId:   req.NodeId,
				Success:  false,
				Message:  errors.Wrap(err, "failed to recover client share").Error(),
			}, nil
		}

		log.Info().
			Str("key_id", req.KeyId).
			Str("node_id", req.NodeId).
			Int("share_len", len(share)).
			Msg("Client share recovered successfully")

		return &pb.RecoverMPCShareResponse{
			KeyId:    req.KeyId,
			NodeId:   req.NodeId,
			Success:  true,
			Message:  "Client share recovered successfully",
		}, nil
	} else {
		return nil, status.Error(codes.InvalidArgument, "node_id is required")
	}
}

// GetBackupStatus 获取备份状态
func (s *InfrastructureServer) GetBackupStatus(ctx context.Context, req *pb.GetBackupStatusRequest) (*pb.GetBackupStatusResponse, error) {
	if s.recoveryService == nil {
		return nil, status.Error(codes.Unimplemented, "recovery service not available")
	}

	statuses, err := s.recoveryService.CheckBackupStatus(ctx, req.KeyId)
	if err != nil {
		return nil, status.Error(codes.Internal, errors.Wrap(err, "failed to check backup status").Error())
	}

	// 转换为响应
	response := &pb.GetBackupStatusResponse{
		KeyId:    req.KeyId,
		Statuses: make([]*pb.BackupStatus, 0, len(statuses)),
	}

	for nodeID, status := range statuses {
		response.Statuses = append(response.Statuses, &pb.BackupStatus{
			NodeId:         nodeID,
			TotalShares:    int32(status.TotalShares),
			RequiredShares: int32(status.RequiredShares),
			Recoverable:    status.Recoverable,
		})
	}

	return response, nil
}

// ListBackupShares 列出备份分片
func (s *InfrastructureServer) ListBackupShares(ctx context.Context, req *pb.ListBackupSharesRequest) (*pb.ListBackupSharesResponse, error) {
	log.Info().
		Str("key_id", req.KeyId).
		Str("node_id", req.NodeId).
		Msg("ListBackupShares gRPC request")

	if s.recoveryService == nil {
		return nil, status.Error(codes.Unimplemented, "recovery service not available")
	}

	// 如果指定了 node_id，只列出该节点的备份分片
	if req.NodeId != "" {
		// 获取该节点的备份分片
		backupShares, err := s.recoveryService.ListBackupShares(ctx, req.KeyId, req.NodeId)
		if err != nil {
			log.Error().Err(err).Str("key_id", req.KeyId).Str("node_id", req.NodeId).Msg("Failed to list backup shares")
			return nil, status.Error(codes.Internal, errors.Wrap(err, "failed to list backup shares").Error())
		}

		// 转换为 protobuf 响应
		pbShares := make([]*pb.BackupShare, len(backupShares))
		for i, share := range backupShares {
			pbShares[i] = &pb.BackupShare{
				KeyId:      share.KeyID,
				NodeId:     share.NodeID,
				ShareIndex: int32(share.ShareIndex),
				CreatedAt:  share.CreatedAt.Format(time.RFC3339),
			}
		}

		return &pb.ListBackupSharesResponse{
			KeyId: req.KeyId,
			SharesByNode: map[string]*pb.BackupShares{
				req.NodeId: {
					NodeId: req.NodeId,
					Shares: pbShares,
				},
			},
		}, nil
	}

	// 如果未指定 node_id，列出所有节点的备份分片
	allBackupShares, err := s.recoveryService.ListAllBackupShares(ctx, req.KeyId)
	if err != nil {
		log.Error().Err(err).Str("key_id", req.KeyId).Msg("Failed to list all backup shares")
		return nil, status.Error(codes.Internal, errors.Wrap(err, "failed to list all backup shares").Error())
	}

	// 转换为 protobuf 响应
	sharesByNode := make(map[string]*pb.BackupShares)
	for nodeID, shares := range allBackupShares {
		pbShares := make([]*pb.BackupShare, len(shares))
		for i, share := range shares {
			pbShares[i] = &pb.BackupShare{
				KeyId:      share.KeyID,
				NodeId:     share.NodeID,
				ShareIndex: int32(share.ShareIndex),
				CreatedAt:  share.CreatedAt.Format(time.RFC3339),
			}
		}
		sharesByNode[nodeID] = &pb.BackupShares{
			NodeId: nodeID,
			Shares: pbShares,
		}
	}

	return &pb.ListBackupSharesResponse{
		KeyId:        req.KeyId,
		SharesByNode: sharesByNode,
	}, nil
}


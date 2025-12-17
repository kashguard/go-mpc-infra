package grpc

import (
	"context"
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/infra/key"
	pb "github.com/kashguard/go-mpc-wallet/internal/pb/infra/v1"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CreateRootKey 创建根密钥
func (s *InfrastructureServer) CreateRootKey(ctx context.Context, req *pb.CreateRootKeyRequest) (*pb.CreateRootKeyResponse, error) {
	log.Info().
		Str("key_id", req.KeyId).
		Str("algorithm", req.Algorithm).
		Str("curve", req.Curve).
		Str("protocol", req.Protocol).
		Int32("threshold", req.Threshold).
		Int32("total_nodes", req.TotalNodes).
		Str("user_id", req.UserId).
		Msg("CreateRootKey gRPC request")

	// 构建请求
	createReq := &key.CreateRootKeyRequest{
		KeyID:       req.KeyId,
		Algorithm:   req.Algorithm,
		Curve:       req.Curve,
		Protocol:    req.Protocol,
		Threshold:   int(req.Threshold),
		TotalNodes:  int(req.TotalNodes),
		UserID:      req.UserId,
		Description: req.Description,
		Tags:        req.Tags,
	}

	// 调用服务
	rootKey, err := s.keyService.CreateRootKey(ctx, createReq)
	if err != nil {
		log.Error().Err(err).Str("key_id", req.KeyId).Msg("Failed to create root key")
		return nil, status.Error(codes.Internal, errors.Wrap(err, "failed to create root key").Error())
	}

	// 转换为响应
	response := &pb.CreateRootKeyResponse{
		Key: &pb.RootKeyMetadata{
			KeyId:        rootKey.KeyID,
			PublicKey:    rootKey.PublicKey,
			Algorithm:    rootKey.Algorithm,
			Curve:        rootKey.Curve,
			Threshold:    int32(rootKey.Threshold),
			TotalNodes:   int32(rootKey.TotalNodes),
			Protocol:     rootKey.Protocol,
			Status:       rootKey.Status,
			Description:  rootKey.Description,
			Tags:         rootKey.Tags,
			CreatedAt:    rootKey.CreatedAt.Format(time.RFC3339),
			UpdatedAt:    rootKey.UpdatedAt.Format(time.RFC3339),
		},
	}

	if rootKey.DeletionDate != nil {
		response.Key.DeletionDate = rootKey.DeletionDate.Format(time.RFC3339)
	}

	return response, nil
}

// GetRootKey 获取根密钥
func (s *InfrastructureServer) GetRootKey(ctx context.Context, req *pb.GetRootKeyRequest) (*pb.GetRootKeyResponse, error) {
	rootKey, err := s.keyService.GetRootKey(ctx, req.KeyId)
	if err != nil {
		return nil, status.Error(codes.NotFound, errors.Wrap(err, "root key not found").Error())
	}

	response := &pb.GetRootKeyResponse{
		Key: &pb.RootKeyMetadata{
			KeyId:        rootKey.KeyID,
			PublicKey:    rootKey.PublicKey,
			Algorithm:    rootKey.Algorithm,
			Curve:        rootKey.Curve,
			Threshold:    int32(rootKey.Threshold),
			TotalNodes:   int32(rootKey.TotalNodes),
			Protocol:     rootKey.Protocol,
			Status:       rootKey.Status,
			Description:  rootKey.Description,
			Tags:         rootKey.Tags,
			CreatedAt:    rootKey.CreatedAt.Format(time.RFC3339),
			UpdatedAt:    rootKey.UpdatedAt.Format(time.RFC3339),
		},
	}

	if rootKey.DeletionDate != nil {
		response.Key.DeletionDate = rootKey.DeletionDate.Format(time.RFC3339)
	}

	return response, nil
}

// DeleteRootKey 删除根密钥
func (s *InfrastructureServer) DeleteRootKey(ctx context.Context, req *pb.DeleteRootKeyRequest) (*pb.StatusResponse, error) {
	if err := s.keyService.DeleteRootKey(ctx, req.KeyId); err != nil {
		return nil, status.Error(codes.Internal, errors.Wrap(err, "failed to delete root key").Error())
	}

	return &pb.StatusResponse{
		Success: true,
		Message: "Root key deleted successfully",
	}, nil
}

// ListRootKeys 列出根密钥
func (s *InfrastructureServer) ListRootKeys(ctx context.Context, req *pb.ListRootKeysRequest) (*pb.ListRootKeysResponse, error) {
	// TODO: 实现列表查询
	// 暂时返回空列表
	return &pb.ListRootKeysResponse{
		Keys: []*pb.RootKeyMetadata{},
		Pagination: &pb.PaginationResponse{
			Total:  0,
			Limit:  req.Pagination.Limit,
			Offset: req.Pagination.Offset,
		},
	}, nil
}

// DeriveWalletKey 派生钱包密钥
func (s *InfrastructureServer) DeriveWalletKey(ctx context.Context, req *pb.DeriveWalletKeyRequest) (*pb.DeriveWalletKeyResponse, error) {
	deriveReq := &key.DeriveWalletKeyRequest{
		RootKeyID:   req.RootKeyId,
		ChainType:   req.ChainType,
		Index:       req.Index,
		Description: req.Description,
		Tags:        req.Tags,
	}

	wallet, err := s.keyService.DeriveWalletKey(ctx, deriveReq)
	if err != nil {
		return nil, status.Error(codes.Internal, errors.Wrap(err, "failed to derive wallet key").Error())
	}

	response := &pb.DeriveWalletKeyResponse{
		Wallet: &pb.WalletKeyMetadata{
			WalletId:     wallet.WalletID,
			RootKeyId:    wallet.RootKeyID,
			ChainType:    wallet.ChainType,
			Index:        wallet.Index,
			PublicKey:    wallet.PublicKey,
			Address:      wallet.Address,
			Status:       wallet.Status,
			Description:  wallet.Description,
			Tags:         wallet.Tags,
			CreatedAt:    wallet.CreatedAt.Format(time.RFC3339),
			UpdatedAt:    wallet.UpdatedAt.Format(time.RFC3339),
		},
	}

	if wallet.DeletionDate != nil {
		response.Wallet.DeletionDate = wallet.DeletionDate.Format(time.RFC3339)
	}

	return response, nil
}

// GetWalletKey 获取钱包密钥
func (s *InfrastructureServer) GetWalletKey(ctx context.Context, req *pb.GetWalletKeyRequest) (*pb.GetWalletKeyResponse, error) {
	// TODO: 实现获取钱包密钥
	return nil, status.Error(codes.Unimplemented, "GetWalletKey not yet implemented")
}

// ListWalletKeys 列出钱包密钥
func (s *InfrastructureServer) ListWalletKeys(ctx context.Context, req *pb.ListWalletKeysRequest) (*pb.ListWalletKeysResponse, error) {
	// TODO: 实现列表查询
	return &pb.ListWalletKeysResponse{
		Wallets: []*pb.WalletKeyMetadata{},
		Pagination: &pb.PaginationResponse{
			Total:  0,
			Limit:  req.Pagination.Limit,
			Offset: req.Pagination.Offset,
		},
	}, nil
}


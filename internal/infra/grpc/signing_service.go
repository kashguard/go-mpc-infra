package grpc

import (
	"context"
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/infra/signing"
	pb "github.com/kashguard/go-mpc-wallet/internal/pb/infra/v1"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CreateSigningSession 创建签名会话
func (s *InfrastructureServer) CreateSigningSession(ctx context.Context, req *pb.CreateSigningSessionRequest) (*pb.CreateSigningSessionResponse, error) {
	log.Info().
		Str("key_id", req.KeyId).
		Str("protocol", req.Protocol).
		Msg("CreateSigningSession gRPC request")

	// 调用签名服务创建会话
	session, err := s.signingService.CreateSigningSession(ctx, req.KeyId, req.Protocol)
	if err != nil {
		log.Error().Err(err).Str("key_id", req.KeyId).Msg("Failed to create signing session")
		return nil, status.Error(codes.Internal, errors.Wrap(err, "failed to create signing session").Error())
	}

	// 转换为 protobuf 响应
	pbSession := &pb.SigningSession{
		SessionId:          session.SessionID,
		KeyId:              session.KeyID,
		Protocol:            session.Protocol,
		Status:              session.Status,
		Threshold:           int32(session.Threshold),
		TotalNodes:          int32(session.TotalNodes),
		ParticipatingNodes:  session.ParticipatingNodes,
		CurrentRound:        int32(session.CurrentRound),
		TotalRounds:         int32(session.TotalRounds),
		Signature:           session.Signature,
		CreatedAt:           session.CreatedAt.Format(time.RFC3339),
		DurationMs:          int32(session.DurationMs),
	}

	if session.CompletedAt != nil {
		pbSession.CompletedAt = session.CompletedAt.Format(time.RFC3339)
	}

	return &pb.CreateSigningSessionResponse{
		Session: pbSession,
	}, nil
}

// ThresholdSign 阈值签名
func (s *InfrastructureServer) ThresholdSign(ctx context.Context, req *pb.ThresholdSignRequest) (*pb.ThresholdSignResponse, error) {
	log.Info().
		Str("key_id", req.KeyId).
		Str("chain_type", req.ChainType).
		Int("message_len", len(req.Message)).
		Msg("ThresholdSign gRPC request")

	// 构建请求
	signReq := &signing.SignRequest{
		KeyID:      req.KeyId,
		Message:    req.Message,
		MessageHex: req.MessageHex,
		ChainType:  req.ChainType,
	}

	// 调用签名服务
	resp, err := s.signingService.ThresholdSign(ctx, signReq)
	if err != nil {
		log.Error().Err(err).Str("key_id", req.KeyId).Msg("Failed to perform threshold sign")
		return nil, status.Error(codes.Internal, errors.Wrap(err, "failed to perform threshold sign").Error())
	}

	// 转换为响应
	response := &pb.ThresholdSignResponse{
		Signature:          resp.Signature,
		KeyId:              resp.KeyID,
		PublicKey:          resp.PublicKey,
		Message:            resp.Message,
		ChainType:          resp.ChainType,
		SessionId:          resp.SessionID,
		SignedAt:           resp.SignedAt,
		ParticipatingNodes: resp.ParticipatingNodes,
	}

	return response, nil
}

// GetSigningSession 获取签名会话
func (s *InfrastructureServer) GetSigningSession(ctx context.Context, req *pb.GetSigningSessionRequest) (*pb.GetSigningSessionResponse, error) {
	log.Info().
		Str("session_id", req.SessionId).
		Msg("GetSigningSession gRPC request")

	// 调用签名服务获取会话
	session, err := s.signingService.GetSigningSession(ctx, req.SessionId)
	if err != nil {
		log.Error().Err(err).Str("session_id", req.SessionId).Msg("Failed to get signing session")
		return nil, status.Error(codes.Internal, errors.Wrap(err, "failed to get signing session").Error())
	}

	// 转换为 protobuf 响应
	pbSession := &pb.SigningSession{
		SessionId:          session.SessionID,
		KeyId:              session.KeyID,
		Protocol:            session.Protocol,
		Status:              session.Status,
		Threshold:           int32(session.Threshold),
		TotalNodes:          int32(session.TotalNodes),
		ParticipatingNodes:  session.ParticipatingNodes,
		CurrentRound:        int32(session.CurrentRound),
		TotalRounds:         int32(session.TotalRounds),
		Signature:           session.Signature,
		CreatedAt:           session.CreatedAt.Format(time.RFC3339),
		DurationMs:          int32(session.DurationMs),
	}

	if session.CompletedAt != nil {
		pbSession.CompletedAt = session.CompletedAt.Format(time.RFC3339)
	}

	return &pb.GetSigningSessionResponse{
		Session: pbSession,
	}, nil
}

// BatchSign 批量签名
func (s *InfrastructureServer) BatchSign(ctx context.Context, req *pb.BatchSignRequest) (*pb.BatchSignResponse, error) {
	// 构建批量签名请求
	batchReq := &signing.BatchSignRequest{
		Messages: make([]*signing.SignRequest, len(req.Messages)),
	}

	for i, msg := range req.Messages {
		batchReq.Messages[i] = &signing.SignRequest{
			KeyID:      msg.KeyId,
			Message:    msg.Message,
			MessageHex: msg.MessageHex,
			ChainType:  msg.ChainType,
		}
	}

	// 调用批量签名服务
	batchResp, err := s.signingService.BatchSign(ctx, batchReq)
	if err != nil {
		return nil, status.Error(codes.Internal, errors.Wrap(err, "failed to perform batch sign").Error())
	}

	// 转换为响应
	response := &pb.BatchSignResponse{
		Signatures: make([]*pb.ThresholdSignResponse, len(batchResp.Signatures)),
		Total:      int32(batchResp.Total),
		Success:    int32(batchResp.Success),
		Failed:     int32(batchResp.Failed),
	}

	for i, sig := range batchResp.Signatures {
		response.Signatures[i] = &pb.ThresholdSignResponse{
			Signature:          sig.Signature,
			KeyId:              sig.KeyID,
			PublicKey:          sig.PublicKey,
			Message:            sig.Message,
			ChainType:          sig.ChainType,
			SessionId:          sig.SessionID,
			SignedAt:           sig.SignedAt,
			ParticipatingNodes: sig.ParticipatingNodes,
		}
	}

	return response, nil
}

// VerifySignature 验证签名
func (s *InfrastructureServer) VerifySignature(ctx context.Context, req *pb.VerifySignatureRequest) (*pb.VerifySignatureResponse, error) {
	// 构建验证请求
	verifyReq := &signing.VerifyRequest{
		Signature:  req.Signature,
		PublicKey:   req.PublicKey,
		Message:    req.Message,
		MessageHex: req.MessageHex,
		ChainType:  req.ChainType,
	}

	// 调用验证服务
	verifyResp, err := s.signingService.Verify(ctx, verifyReq)
	if err != nil {
		return nil, status.Error(codes.Internal, errors.Wrap(err, "failed to verify signature").Error())
	}

	// 转换为响应
	response := &pb.VerifySignatureResponse{
		Valid:      verifyResp.Valid,
		PublicKey:  verifyResp.PublicKey,
		Address:    verifyResp.Address,
		VerifiedAt: verifyResp.VerifiedAt,
	}

	return response, nil
}


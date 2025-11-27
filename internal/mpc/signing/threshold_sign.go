package signing

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/mpc/key"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/protocol"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/session"
	"github.com/pkg/errors"
)

// ThresholdSigner 阈值签名器
type ThresholdSigner struct {
	keyService     *key.Service
	protocolEngine protocol.Engine
	sessionManager *session.Manager
}

// NewThresholdSigner 创建阈值签名器
func NewThresholdSigner(
	keyService *key.Service,
	protocolEngine protocol.Engine,
	sessionManager *session.Manager,
) *ThresholdSigner {
	return &ThresholdSigner{
		keyService:     keyService,
		protocolEngine: protocolEngine,
		sessionManager: sessionManager,
	}
}

// Sign 执行阈值签名
func (s *ThresholdSigner) Sign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	// 1. 获取密钥信息
	keyMetadata, err := s.keyService.GetKey(ctx, req.KeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get key")
	}

	// 2. 创建签名会话
	signingSession, err := s.sessionManager.CreateSession(ctx, req.KeyID, "gg20", keyMetadata.Threshold, keyMetadata.TotalNodes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create signing session")
	}

	// 3. 准备消息
	var message []byte
	if req.MessageHex != "" {
		var err error
		message, err = hex.DecodeString(req.MessageHex)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decode message hex")
		}
	} else {
		message = req.Message
	}

	// 4. 准备签名请求
	signReq := &protocol.SignRequest{
		KeyID:      req.KeyID,
		Message:    message,
		MessageHex: hex.EncodeToString(message),
		NodeIDs:    signingSession.ParticipatingNodes,
	}

	// 5. 执行签名协议
	signResp, err := s.protocolEngine.ThresholdSign(ctx, signingSession.SessionID, signReq)
	if err != nil {
		// 标记会话为失败
		signingSession.Status = "failed"
		s.sessionManager.UpdateSession(ctx, signingSession)
		return nil, errors.Wrap(err, "failed to execute threshold signing")
	}

	// 6. 验证签名
	pubKey := &protocol.PublicKey{
		Hex: keyMetadata.PublicKey,
	}
	valid, err := s.protocolEngine.VerifySignature(ctx, signResp.Signature, message, pubKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to verify signature")
	}
	if !valid {
		return nil, errors.New("signature verification failed")
	}

	// 7. 完成会话
	signatureHex := signResp.Signature.Hex
	if err := s.sessionManager.CompleteSession(ctx, signingSession.SessionID, signatureHex); err != nil {
		return nil, errors.Wrap(err, "failed to complete session")
	}

	// 8. 构建响应
	response := &SignResponse{
		Signature:          signatureHex,
		KeyID:              req.KeyID,
		PublicKey:          keyMetadata.PublicKey,
		Message:            hex.EncodeToString(message),
		ChainType:          req.ChainType,
		SessionID:          signingSession.SessionID,
		SignedAt:           time.Now().Format(time.RFC3339),
		ParticipatingNodes: signingSession.ParticipatingNodes,
	}

	return response, nil
}

package signing

import (
	"context"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/mpc/key"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/node"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/protocol"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/session"
	pb "github.com/kashguard/go-mpc-wallet/internal/pb/mpc/v1"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// GRPCClient gRPC客户端接口（用于调用participant节点）
type GRPCClient interface {
	SendStartSign(ctx context.Context, nodeID string, req *pb.StartSignRequest) (*pb.StartSignResponse, error)
}

// Service 签名服务
type Service struct {
	keyService      *key.Service
	protocolEngine  protocol.Engine
	sessionManager  *session.Manager
	nodeDiscovery   *node.Discovery
	defaultProtocol string     // 默认协议（从配置中获取）
	grpcClient      GRPCClient // gRPC客户端，用于调用participant节点
}

// NewService 创建签名服务
func NewService(
	keyService *key.Service,
	protocolEngine protocol.Engine,
	sessionManager *session.Manager,
	nodeDiscovery *node.Discovery,
	defaultProtocol string,
	grpcClient GRPCClient,
) *Service {
	return &Service{
		keyService:      keyService,
		protocolEngine:  protocolEngine,
		sessionManager:  sessionManager,
		nodeDiscovery:   nodeDiscovery,
		defaultProtocol: defaultProtocol,
		grpcClient:      grpcClient,
	}
}

// inferProtocol 根据密钥的 Algorithm 和 Curve 推断协议类型
// 返回协议名称（gg18, gg20, frost）
func inferProtocol(algorithm, curve, defaultProtocol string) string {
	algorithmLower := strings.ToLower(algorithm)
	curveLower := strings.ToLower(curve)

	// FROST 协议：EdDSA 或 Schnorr + Ed25519 或 secp256k1
	if algorithmLower == "eddsa" || algorithmLower == "schnorr" {
		if curveLower == "ed25519" || curveLower == "secp256k1" {
			return "frost"
		}
	}

	// ECDSA + secp256k1：使用默认协议（gg18 或 gg20）
	if algorithmLower == "ecdsa" && curveLower == "secp256k1" {
		// 如果默认协议是 gg18 或 gg20，使用默认协议
		if defaultProtocol == "gg18" || defaultProtocol == "gg20" {
			return defaultProtocol
		}
		// 否则默认使用 gg20
		return "gg20"
	}

	// 默认使用配置的默认协议
	if defaultProtocol != "" {
		return defaultProtocol
	}

	// 最后默认使用 gg20
	return "gg20"
}

// ThresholdSign 阈值签名
func (s *Service) ThresholdSign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	// 1. 获取密钥信息
	keyMetadata, err := s.keyService.GetKey(ctx, req.KeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get key")
	}

	// 2. 推断协议类型
	protocolName := inferProtocol(keyMetadata.Algorithm, keyMetadata.Curve, s.defaultProtocol)

	// 3. 创建签名会话
	signingSession, err := s.sessionManager.CreateSession(ctx, req.KeyID, protocolName, keyMetadata.Threshold, keyMetadata.TotalNodes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create signing session")
	}

	// 4. 选择参与节点（达到阈值即可）
	participants, err := s.nodeDiscovery.DiscoverNodes(ctx, node.NodeTypeParticipant, node.NodeStatusActive, keyMetadata.Threshold)
	if err != nil {
		return nil, errors.Wrap(err, "failed to discover participants")
	}

	if len(participants) < keyMetadata.Threshold {
		return nil, errors.Errorf("insufficient active nodes: need %d, have %d", keyMetadata.Threshold, len(participants))
	}

	// 选择前 threshold 个节点
	participatingNodes := make([]string, 0, keyMetadata.Threshold)
	for i := 0; i < keyMetadata.Threshold && i < len(participants); i++ {
		participatingNodes = append(participatingNodes, participants[i].NodeID)
	}

	// 更新会话的参与节点
	signingSession.ParticipatingNodes = participatingNodes
	if err := s.sessionManager.UpdateSession(ctx, signingSession); err != nil {
		return nil, errors.Wrap(err, "failed to update session with participating nodes")
	}

	// 5. 准备消息
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

	// 6. 通过 gRPC 调用 participant 节点执行签名
	// Coordinator 不直接执行签名，而是通知 participant 节点执行
	// 选择第一个 participant 节点作为 leader（类似 DKG 流程）
	if len(participatingNodes) == 0 {
		return nil, errors.New("no participating nodes available")
	}

	leaderNodeID := participatingNodes[0]

	// 准备 StartSign 请求
	startSignReq := &pb.StartSignRequest{
		SessionId:  signingSession.SessionID,
		KeyId:      req.KeyID,
		Message:    message,
		MessageHex: hex.EncodeToString(message),
		Protocol:   protocolName,
		Threshold:  int32(keyMetadata.Threshold),
		TotalNodes: int32(keyMetadata.TotalNodes),
		NodeIds:    participatingNodes,
	}

	log.Info().
		Str("key_id", req.KeyID).
		Str("session_id", signingSession.SessionID).
		Str("leader_node_id", leaderNodeID).
		Str("protocol", protocolName).
		Int("participating_nodes_count", len(participatingNodes)).
		Msg("Calling StartSign RPC on leader participant node")

	// 调用 leader participant 节点的 StartSign RPC
	// 注意：签名协议会在 participant 节点间执行，coordinator 只负责协调
	startSignCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	startResp, err := s.grpcClient.SendStartSign(startSignCtx, leaderNodeID, startSignReq)
	if err != nil {
		// 标记会话为失败
		signingSession.Status = "failed"
		s.sessionManager.UpdateSession(ctx, signingSession)
		return nil, errors.Wrap(err, "failed to call StartSign on leader participant")
	}

	if !startResp.Started {
		// 标记会话为失败
		signingSession.Status = "failed"
		s.sessionManager.UpdateSession(ctx, signingSession)
		return nil, errors.Errorf("StartSign failed: %s", startResp.Message)
	}

	log.Info().
		Str("key_id", req.KeyID).
		Str("session_id", signingSession.SessionID).
		Str("leader_node_id", leaderNodeID).
		Msg("StartSign RPC succeeded, waiting for signature completion")

	// 7. 等待签名完成（轮询会话状态）
	// 签名完成后，会话的 Signature 字段会被更新
	maxWaitTime := 5 * time.Minute
	pollInterval := 2 * time.Second
	deadline := time.Now().Add(maxWaitTime)

	var signatureHex string
	for time.Now().Before(deadline) {
		// 获取最新的会话状态
		updatedSession, err := s.sessionManager.GetSession(ctx, signingSession.SessionID)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get session status")
		}

		// 检查签名是否完成
		if updatedSession.Status == "completed" && updatedSession.Signature != "" {
			signatureHex = updatedSession.Signature
			log.Info().
				Str("key_id", req.KeyID).
				Str("session_id", signingSession.SessionID).
				Str("signature", signatureHex).
				Msg("Signature completed successfully")
			break
		}

		// 检查是否失败
		if updatedSession.Status == "failed" {
			return nil, errors.New("signing session failed")
		}

		// 等待一段时间后再次检查
		time.Sleep(pollInterval)
	}

	if signatureHex == "" {
		// 超时
		signingSession.Status = "failed"
		s.sessionManager.UpdateSession(ctx, signingSession)
		return nil, errors.New("signing timeout")
	}

	// 8. 验证签名（可选，但建议验证）
	pubKeyBytes, err := hex.DecodeString(keyMetadata.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode public key hex")
	}

	pubKey := &protocol.PublicKey{
		Hex:   keyMetadata.PublicKey,
		Bytes: pubKeyBytes,
	}

	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode signature hex")
	}

	signature := &protocol.Signature{
		Bytes: sigBytes,
		Hex:   signatureHex,
	}

	if len(sigBytes) >= 64 {
		signature.R = sigBytes[:32]
		signature.S = sigBytes[32:64]
	}

	valid, err := s.protocolEngine.VerifySignature(ctx, signature, message, pubKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to verify signature")
	}
	if !valid {
		return nil, errors.New("signature verification failed")
	}

	// 9. 构建响应
	response := &SignResponse{
		Signature:          signatureHex,
		KeyID:              req.KeyID,
		PublicKey:          keyMetadata.PublicKey,
		Message:            hex.EncodeToString(message),
		ChainType:          req.ChainType,
		SessionID:          signingSession.SessionID,
		SignedAt:           time.Now().Format(time.RFC3339),
		ParticipatingNodes: participatingNodes,
	}

	return response, nil
}

// BatchSign 批量签名
func (s *Service) BatchSign(ctx context.Context, req *BatchSignRequest) (*BatchSignResponse, error) {
	if len(req.Messages) == 0 {
		return nil, errors.New("no messages to sign")
	}

	// 使用 WaitGroup 和 channel 并发处理
	var wg sync.WaitGroup
	results := make([]*SignResponse, len(req.Messages))
	errors := make([]error, len(req.Messages))
	mu := sync.Mutex{}

	// 并发执行签名
	for i, msgReq := range req.Messages {
		wg.Add(1)
		go func(index int, signReq *SignRequest) {
			defer wg.Done()

			// 设置超时上下文（每个签名最多30秒）
			signCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()

			resp, err := s.ThresholdSign(signCtx, signReq)
			mu.Lock()
			if err != nil {
				errors[index] = err
			} else {
				results[index] = resp
			}
			mu.Unlock()
		}(i, msgReq)
	}

	// 等待所有签名完成
	wg.Wait()

	// 统计结果
	success := 0
	failed := 0
	validSignatures := make([]*SignResponse, 0, len(req.Messages))

	for i := range req.Messages {
		if errors[i] != nil {
			failed++
		} else if results[i] != nil {
			success++
			validSignatures = append(validSignatures, results[i])
		}
	}

	return &BatchSignResponse{
		Signatures: validSignatures,
		Total:      len(req.Messages),
		Success:    success,
		Failed:     failed,
	}, nil
}

// Verify 验证签名
func (s *Service) Verify(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error) {
	// 1. 解析签名
	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode signature hex")
	}

	// 构建签名对象（假设签名格式为 R||S）
	if len(sigBytes) < 64 {
		return nil, errors.New("invalid signature length")
	}

	signature := &protocol.Signature{
		Bytes: sigBytes,
		Hex:   req.Signature,
		R:     sigBytes[:32],
		S:     sigBytes[32:64],
	}

	// 2. 解析公钥
	pubKeyBytes, err := hex.DecodeString(req.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode public key hex")
	}

	pubKey := &protocol.PublicKey{
		Bytes: pubKeyBytes,
		Hex:   req.PublicKey,
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

	// 4. 验证签名
	valid, err := s.protocolEngine.VerifySignature(ctx, signature, message, pubKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to verify signature")
	}

	// 5. 如果验证成功，生成地址（可选）
	var address string
	if valid && req.ChainType != "" {
		// 这里可以根据链类型生成地址，但需要链适配器
		// 为了简化，暂时返回空地址
		address = ""
	}

	return &VerifyResponse{
		Valid:      valid,
		PublicKey:  req.PublicKey,
		Address:    address,
		VerifiedAt: time.Now().Format(time.RFC3339),
	}, nil
}

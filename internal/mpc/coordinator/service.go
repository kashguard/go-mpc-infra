package coordinator

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/mpc/key"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/node"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/protocol"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/session"
	pb "github.com/kashguard/go-mpc-wallet/internal/pb/mpc/v1"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// Service Coordinator服务
type Service struct {
	keyService     *key.Service
	sessionManager *session.Manager
	nodeDiscovery  *node.Discovery
	protocolEngine protocol.Engine
	grpcClient     GRPCClient // gRPC客户端，用于通知参与者
	thisNodeID     string     // 当前节点ID（coordinator节点）
}

// GRPCClient gRPC客户端接口（用于通知参与者）
type GRPCClient interface {
	// StartDKG RPC
	SendStartDKG(ctx context.Context, nodeID string, req *pb.StartDKGRequest) (*pb.StartDKGResponse, error)
	// StartSign RPC
	SendStartSign(ctx context.Context, nodeID string, req *pb.StartSignRequest) (*pb.StartSignResponse, error)
}

// NewService 创建Coordinator服务
func NewService(
	keyService *key.Service,
	sessionManager *session.Manager,
	nodeDiscovery *node.Discovery,
	protocolEngine protocol.Engine,
	grpcClient GRPCClient,
	thisNodeID string, // 当前节点ID（coordinator节点）
) *Service {
	// 记录 thisNodeID 的值（用于调试）
	log.Error().
		Str("this_node_id", thisNodeID).
		Bool("is_empty", thisNodeID == "").
		Msg("CoordinatorService initialized with thisNodeID")

	return &Service{
		keyService:     keyService,
		sessionManager: sessionManager,
		nodeDiscovery:  nodeDiscovery,
		protocolEngine: protocolEngine,
		grpcClient:     grpcClient,
		thisNodeID:     thisNodeID,
	}
}

// inferProtocolForDKG 根据算法/曲线推断协议，避免默认协议与请求不符
func inferProtocolForDKG(algorithm, curve string, defaultProtocol string) string {
	algo := strings.ToLower(algorithm)
	cv := strings.ToLower(curve)

	if algo == "eddsa" || algo == "schnorr" {
		if cv == "ed25519" || cv == "secp256k1" {
			return "frost"
		}
	}

	if algo == "ecdsa" {
		if cv == "secp256k1" || cv == "secp256r1" {
			return "gg20"
		}
	}

	// 回退到默认配置
	return defaultProtocol
}

// CreateSigningSession 创建签名会话
func (s *Service) CreateSigningSession(ctx context.Context, req *CreateSessionRequest) (*SigningSession, error) {
	// 获取密钥信息
	keyMetadata, err := s.keyService.GetKey(ctx, req.KeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get key")
	}

	// 选择协议
	protocol := req.Protocol
	if protocol == "" {
		protocol = s.protocolEngine.DefaultProtocol()
	}

	// 创建会话
	session, err := s.sessionManager.CreateSession(ctx, req.KeyID, protocol, keyMetadata.Threshold, keyMetadata.TotalNodes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create session")
	}

	return &SigningSession{
		SessionID:          session.SessionID,
		KeyID:              session.KeyID,
		Protocol:           session.Protocol,
		Status:             session.Status,
		Threshold:          session.Threshold,
		TotalNodes:         session.TotalNodes,
		ParticipatingNodes: session.ParticipatingNodes,
		CurrentRound:       session.CurrentRound,
		TotalRounds:        session.TotalRounds,
		Signature:          session.Signature,
		CreatedAt:          session.CreatedAt,
		CompletedAt:        session.CompletedAt,
		DurationMs:         session.DurationMs,
		ExpiresAt:          session.ExpiresAt,
	}, nil
}

// CreateDKGSession 创建DKG会话并通知所有参与者
func (s *Service) CreateDKGSession(ctx context.Context, req *CreateDKGSessionRequest) (*DKGSession, error) {
	// 记录请求参数和 thisNodeID（用于调试）
	log.Error().
		Str("this_node_id", s.thisNodeID).
		Bool("this_node_id_empty", s.thisNodeID == "").
		Strs("request_node_ids", req.NodeIDs).
		Int("request_total_nodes", req.TotalNodes).
		Int("request_threshold", req.Threshold).
		Str("key_id", req.KeyID).
		Msg("CreateDKGSession called")

	// 1. 选择参与节点（只包括 participant，不包括 coordinator）
	var nodeIDs []string
	if len(req.NodeIDs) > 0 {
		// 使用提供的节点列表（应该只包含 participant）
		nodeIDs = req.NodeIDs
		log.Info().
			Strs("node_ids", nodeIDs).
			Int("count", len(nodeIDs)).
			Msg("Using provided participant node IDs (coordinator does NOT participate)")
	} else {
		// 自动发现参与者（不包括 coordinator）
		log.Info().
			Int("required_participants", req.TotalNodes).
			Msg("Auto-discovering participants (coordinator does NOT participate)")

		participants, err := s.nodeDiscovery.DiscoverNodes(ctx, node.NodeTypeParticipant, node.NodeStatusActive, req.TotalNodes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to discover participants")
		}

		log.Info().
			Int("discovered_participants", len(participants)).
			Int("required_participants", req.TotalNodes).
			Msg("Discovered participants")

		if len(participants) < req.TotalNodes {
			return nil, errors.Errorf("insufficient active participants: need %d, have %d", req.TotalNodes, len(participants))
		}

		// 只包含 participant 节点，不包含 coordinator
		nodeIDs = make([]string, 0, len(participants))
		for _, n := range participants {
			nodeIDs = append(nodeIDs, n.NodeID)
		}
		// 确保节点列表有序，避免 PartyID 映射不一致
		sort.Strings(nodeIDs)

		log.Info().
			Strs("participant_node_ids", nodeIDs).
			Int("total_participants", len(nodeIDs)).
			Str("coordinator_node_id", s.thisNodeID).
			Msg("Final participant node IDs for DKG session (coordinator does NOT participate, sorted)")
	}

	// 2. 选择协议：先按请求/算法曲线推断，再回退默认
	log.Info().
		Str("key_id", req.KeyID).
		Str("algorithm", req.Algorithm).
		Str("curve", req.Curve).
		Str("request_protocol", req.Protocol).
		Str("default_protocol", s.protocolEngine.DefaultProtocol()).
		Msg("CreateDKGSession: protocol selection input")

	selectedProtocol := req.Protocol
	if selectedProtocol == "" {
		selectedProtocol = inferProtocolForDKG(req.Algorithm, req.Curve, s.protocolEngine.DefaultProtocol())
	}

	// 3. 创建DKG会话
	// 记录传递给 CreateKeyGenSession 的节点列表（用于调试）
	log.Error().
		Strs("node_ids", nodeIDs).
		Str("key_id", req.KeyID).
		Str("protocol", selectedProtocol).
		Int("threshold", req.Threshold).
		Int("total_nodes", req.TotalNodes).
		Msg("About to create DKG session with node IDs")

	dkgSession, err := s.sessionManager.CreateKeyGenSession(ctx, req.KeyID, selectedProtocol, req.Threshold, req.TotalNodes, nodeIDs)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create DKG session")
	}

	// 记录创建成功的会话信息（用于调试）
	log.Error().
		Str("session_id", dkgSession.SessionID).
		Strs("participating_nodes", dkgSession.ParticipatingNodes).
		Msg("DKG session created successfully")

	// 4. 通知所有参与者启动DKG
	if err := s.NotifyParticipantsForDKG(ctx, req, nodeIDs); err != nil {
		// 如果通知失败，取消会话
		_ = s.sessionManager.CancelSession(ctx, dkgSession.SessionID)
		return nil, errors.Wrap(err, "failed to notify participants")
	}

	return &DKGSession{
		SessionID:          dkgSession.SessionID,
		KeyID:              dkgSession.KeyID,
		Protocol:           dkgSession.Protocol,
		Status:             dkgSession.Status,
		Threshold:          dkgSession.Threshold,
		TotalNodes:         dkgSession.TotalNodes,
		ParticipatingNodes: dkgSession.ParticipatingNodes,
		CurrentRound:       dkgSession.CurrentRound,
		TotalRounds:        dkgSession.TotalRounds,
		CreatedAt:          dkgSession.CreatedAt,
		ExpiresAt:          dkgSession.ExpiresAt,
	}, nil
}

// NotifyParticipantsForDKG 通知所有参与者节点启动DKG
func (s *Service) NotifyParticipantsForDKG(ctx context.Context, req *CreateDKGSessionRequest, nodeIDs []string) error {
	// ✅ 方案一：Coordinator 不参与 DKG，只通知第一个 participant 启动
	// 第一个 participant 作为 leader 启动 DKG 协议，生成第一轮消息
	// 其他 participants 收到第一轮消息后会自动启动自己的 DKG 协议

	if len(nodeIDs) == 0 {
		return errors.New("no participants to notify")
	}

	// 选择第一个 participant 作为 leader（按 nodeID 排序，确保一致性）
	leaderNodeID := nodeIDs[0]

	log.Info().
		Str("key_id", req.KeyID).
		Str("leader_node_id", leaderNodeID).
		Strs("all_participants", nodeIDs).
		Int("threshold", req.Threshold).
		Int("total_nodes", req.TotalNodes).
		Msg("Notifying leader participant to start DKG protocol")

		// 通过 gRPC 发送 StartDKG RPC 给 leader
		// 使用独立的 context 和超时，避免受 HTTP 请求超时影响
		// 缩短超时时间，加快失败检测
	startReq := &pb.StartDKGRequest{
		SessionId:  req.KeyID,
		KeyId:      req.KeyID,
		Algorithm:  req.Algorithm,
		Curve:      req.Curve,
		Threshold:  int32(req.Threshold),
		TotalNodes: int32(req.TotalNodes),
		NodeIds:    nodeIDs,
	}

	// 异步调用 StartDKG，避免阻塞 HTTP 请求
	// 在 goroutine 内部创建 context，确保不会被外部 defer cancel 影响
	go func() {
		startDKGTimeout := 2 * time.Minute
		startDKGCtx, cancel := context.WithTimeout(context.Background(), startDKGTimeout)
		defer cancel()

		log.Info().
			Str("key_id", req.KeyID).
			Str("leader_node_id", leaderNodeID).
			Str("timeout", startDKGTimeout.String()).
			Msg("Starting async StartDKG RPC call")

		resp, err := s.grpcClient.SendStartDKG(startDKGCtx, leaderNodeID, startReq)
		if err != nil {
			log.Error().
				Err(err).
				Str("key_id", req.KeyID).
				Str("leader_node_id", leaderNodeID).
				Str("timeout", startDKGTimeout.String()).
				Msg("Failed to call StartDKG on leader participant - participant will auto-start DKG via message routing")
			// 不返回错误，让 participant 通过其他方式（如消息路由）自动启动 DKG
			// 即使 StartDKG RPC 失败，participant 在收到协议消息时会自动启动 DKG
		} else {
			log.Info().
				Str("key_id", req.KeyID).
				Str("leader_node_id", leaderNodeID).
				Bool("started", resp.Started).
				Str("message", resp.Message).
				Msg("StartDKG RPC call succeeded")
		}
	}()

	return nil
}

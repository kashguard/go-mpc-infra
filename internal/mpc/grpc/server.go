package grpc

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"encoding/hex"

	"github.com/kashguard/go-mpc-wallet/internal/config"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/protocol"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/session"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/storage"
	pb "github.com/kashguard/go-mpc-wallet/internal/pb/mpc/v1"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

// inferProtocolForDKG 根据算法和曲线推断DKG应该使用的协议
// ECDSA + secp256k1 -> GG20 (默认) 或 GG18
// EdDSA/Schnorr + ed25519/secp256k1 -> FROST
func inferProtocolForDKG(algorithm, curve string) string {
	algorithmLower := strings.ToLower(algorithm)
	curveLower := strings.ToLower(curve)

	// FROST 协议：EdDSA 或 Schnorr + Ed25519 或 secp256k1
	if algorithmLower == "eddsa" || algorithmLower == "schnorr" {
		if curveLower == "ed25519" || curveLower == "secp256k1" {
			return "frost"
		}
	}

	// ECDSA + secp256k1：使用 GG20（默认）或 GG18
	if algorithmLower == "ecdsa" {
		if curveLower == "secp256k1" || curveLower == "secp256r1" {
			return "gg20" // 默认使用 GG20
		}
	}

	// 默认使用 GG20
	return "gg20"
}

// GRPCServer gRPC服务端，用于接收节点间消息
type GRPCServer struct {
	pb.UnimplementedMPCNodeServer

	protocolEngine   protocol.Engine            // 默认协议引擎
	protocolRegistry *protocol.ProtocolRegistry // 协议注册表（用于动态选择协议）
	sessionManager   *session.Manager
	keyShareStorage  storage.KeyShareStorage // 用于存储密钥分片
	nodeID           string
	cfg              *ServerConfig

	// gRPC 服务器实例
	grpcServer *grpc.Server
	listener   net.Listener

	// 用于确保每个DKG会话只启动一次
	dkgStartOnce sync.Map // map[string]*sync.Once

	// 用于确保每个签名会话只启动一次
	signStartOnce sync.Map // map[string]*sync.Once
}

// ServerConfig gRPC服务端配置
type ServerConfig struct {
	Port          int
	TLSEnabled    bool
	TLSCertFile   string
	TLSKeyFile    string
	TLSCACertFile string
	MaxConnAge    time.Duration
	KeepAlive     time.Duration
}

// NewGRPCServer 创建gRPC服务端
func NewGRPCServer(
	cfg config.Server,
	protocolEngine protocol.Engine,
	sessionManager *session.Manager,
	keyShareStorage storage.KeyShareStorage,
	nodeID string,
) *GRPCServer {
	return NewGRPCServerWithRegistry(cfg, protocolEngine, nil, sessionManager, keyShareStorage, nodeID)
}

// NewGRPCServerWithRegistry 创建gRPC服务端（带协议注册表）
func NewGRPCServerWithRegistry(
	cfg config.Server,
	protocolEngine protocol.Engine,
	protocolRegistry *protocol.ProtocolRegistry, // 协议注册表（可选，用于动态选择协议）
	sessionManager *session.Manager,
	keyShareStorage storage.KeyShareStorage,
	nodeID string,
) *GRPCServer {
	serverCfg := &ServerConfig{
		Port:       cfg.MPC.GRPCPort,
		TLSEnabled: cfg.MPC.TLSEnabled,
		MaxConnAge: 2 * time.Hour,
		KeepAlive:  30 * time.Second,
	}

	srv := &GRPCServer{
		protocolEngine:   protocolEngine,
		protocolRegistry: protocolRegistry,
		sessionManager:   sessionManager,
		keyShareStorage:  keyShareStorage,
		nodeID:           nodeID,
		cfg:              serverCfg,
	}

	return srv
}

// GetServerOptions 获取gRPC服务器选项
func (s *GRPCServer) GetServerOptions() ([]grpc.ServerOption, error) {
	var opts []grpc.ServerOption

	// TLS配置
	if s.cfg.TLSEnabled {
		creds, err := credentials.NewServerTLSFromFile(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load TLS credentials")
		}
		opts = append(opts, grpc.Creds(creds))
	}

	// KeepAlive配置
	opts = append(opts, grpc.KeepaliveParams(keepalive.ServerParameters{
		MaxConnectionAge:      s.cfg.MaxConnAge,
		MaxConnectionAgeGrace: 30 * time.Second,
		Time:                  s.cfg.KeepAlive,
		Timeout:               20 * time.Second,
	}))

	// Enforcement Policy (防止 too_many_pings)
	opts = append(opts, grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
		MinTime:             10 * time.Second, // 允许客户端每 10s ping 一次
		PermitWithoutStream: true,             // 允许无流时的 ping
	}))

	// 最大消息大小
	opts = append(opts, grpc.MaxRecvMsgSize(10*1024*1024)) // 10MB
	opts = append(opts, grpc.MaxSendMsgSize(10*1024*1024)) // 10MB

	return opts, nil
}

// JoinSigningSession 双向流：加入签名会话
func (s *GRPCServer) JoinSigningSession(stream grpc.BidiStreamingServer[pb.SessionMessage, pb.SessionMessage]) error {
	ctx := stream.Context()
	var sessionID string

	// 接收初始加入请求
	req, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.Internal, "failed to receive join request: %v", err)
	}

	// 处理加入请求
	joinReq := req.GetJoinRequest()
	if joinReq == nil {
		return status.Error(codes.InvalidArgument, "first message must be a join request")
	}

	sessionID = joinReq.SessionId

	// 验证会话
	sess, err := s.sessionManager.GetSession(ctx, sessionID)
	if err != nil {
		return status.Errorf(codes.NotFound, "session not found: %v", err)
	}

	// 发送确认消息
	confirmation := &pb.SessionConfirmation{
		SessionId:    sessionID,
		Status:       sess.Status,
		Threshold:    int32(sess.Threshold),
		TotalNodes:   int32(sess.TotalNodes),
		Participants: sess.ParticipatingNodes,
		CurrentRound: int32(sess.CurrentRound),
		ConfirmedAt:  time.Now().Format(time.RFC3339),
	}

	if err := stream.Send(&pb.SessionMessage{
		MessageType: &pb.SessionMessage_Confirmation{
			Confirmation: confirmation,
		},
	}); err != nil {
		return status.Errorf(codes.Internal, "failed to send confirmation: %v", err)
	}

	// 处理后续消息
	for {
		msg, err := stream.Recv()
		if err != nil {
			// 流结束
			return nil
		}

		// 处理消息
		if shareMsg := msg.GetShareMessage(); shareMsg != nil {
			// 这是协议消息（DKG或签名）
			// 从joinReq中获取发送方节点ID（如果可用），否则使用空字符串
			fromNodeID := ""
			if joinReq.NodeId != "" {
				fromNodeID = joinReq.NodeId
			}
			if err := s.handleProtocolMessage(ctx, sessionID, fromNodeID, shareMsg); err != nil {
				// 发送错误消息
				errorMsg := &pb.ErrorMessage{
					ErrorCode:    "PROTOCOL_ERROR",
					ErrorMessage: err.Error(),
					Recoverable:  true,
					OccurredAt:   time.Now().Format(time.RFC3339),
				}
				if sendErr := stream.Send(&pb.SessionMessage{
					MessageType: &pb.SessionMessage_ErrorMessage{
						ErrorMessage: errorMsg,
					},
				}); sendErr != nil {
					return status.Errorf(codes.Internal, "failed to send error message: %v", sendErr)
				}
				continue
			}
		} else if heartbeatReq := msg.GetHeartbeatRequest(); heartbeatReq != nil {
			// 处理心跳
			heartbeatResp := &pb.HeartbeatResponse{
				Alive:      true,
				ReceivedAt: time.Now().Format(time.RFC3339),
			}
			_ = heartbeatResp // 用于后续扩展
			if err := stream.Send(&pb.SessionMessage{
				MessageType: &pb.SessionMessage_HeartbeatRequest{
					HeartbeatRequest: heartbeatReq,
				},
			}); err != nil {
				return status.Errorf(codes.Internal, "failed to send heartbeat response: %v", err)
			}
		}
	}
}

// StartDKG 由协调者调用以启动参与者的 DKG
func (s *GRPCServer) StartDKG(ctx context.Context, req *pb.StartDKGRequest) (*pb.StartDKGResponse, error) {
	log.Info().
		Str("key_id", req.KeyId).
		Str("session_id", req.SessionId).
		Str("algorithm", req.Algorithm).
		Str("curve", req.Curve).
		Int32("threshold", req.Threshold).
		Int32("total_nodes", req.TotalNodes).
		Strs("node_ids", req.NodeIds).
		Str("this_node_id", s.nodeID).
		Msg("StartDKG RPC received")

	// 使用sync.Once确保每个sessionID只启动一次DKG协议
	// 防止StartDKG RPC和自动启动机制同时启动DKG
	sessionID := req.SessionId
	if sessionID == "" {
		sessionID = req.KeyId // 如果sessionID为空，使用keyID
	}

	onceInterface, _ := s.dkgStartOnce.LoadOrStore(sessionID, &sync.Once{})
	once := onceInterface.(*sync.Once)

	var started bool

	once.Do(func() {
		started = true
		log.Info().
			Str("key_id", req.KeyId).
			Str("session_id", sessionID).
			Str("this_node_id", s.nodeID).
			Msg("sync.Once.Do executed in StartDKG RPC - starting DKG in goroutine")

		// 在goroutine中执行GenerateKeyShare，避免阻塞sync.Once.Do
		// 这样如果自动启动机制也尝试启动，sync.Once会立即返回，不会重复启动
		go func() {
			// 使用独立的context，避免RPC请求返回后context被取消
			keygenTimeout := 10 * time.Minute
			keygenCtx, cancel := context.WithTimeout(context.Background(), keygenTimeout)
			defer cancel()

			dkgReq := &protocol.KeyGenRequest{
				KeyID:      req.KeyId,
				Algorithm:  req.Algorithm,
				Curve:      req.Curve,
				Threshold:  int(req.Threshold),
				TotalNodes: int(req.TotalNodes),
				NodeIDs:    req.NodeIds,
			}

			// 根据算法和曲线选择正确的协议引擎
			// ECDSA + secp256k1 -> GG18 或 GG20
			// EdDSA/Schnorr + ed25519/secp256k1 -> FROST
			var selectedEngine protocol.Engine
			if s.protocolRegistry != nil {
				// 根据算法和曲线推断协议
				protocolName := inferProtocolForDKG(req.Algorithm, req.Curve)
				engine, err := s.protocolRegistry.Get(protocolName)
				if err != nil {
					log.Warn().
						Err(err).
						Str("key_id", req.KeyId).
						Str("algorithm", req.Algorithm).
						Str("curve", req.Curve).
						Str("inferred_protocol", protocolName).
						Msg("StartDKG: Failed to get protocol from registry, using default engine")
					selectedEngine = s.protocolEngine
				} else {
					log.Info().
						Str("key_id", req.KeyId).
						Str("algorithm", req.Algorithm).
						Str("curve", req.Curve).
						Str("selected_protocol", protocolName).
						Str("this_node_id", s.nodeID).
						Msg("StartDKG: Selected protocol from registry")
					selectedEngine = engine
				}
			} else {
				// 如果没有协议注册表，使用默认引擎
				log.Warn().
					Str("key_id", req.KeyId).
					Str("this_node_id", s.nodeID).
					Msg("StartDKG: Protocol registry not available, using default engine")
				selectedEngine = s.protocolEngine
			}

			log.Info().
				Str("key_id", req.KeyId).
				Str("session_id", sessionID).
				Str("this_node_id", s.nodeID).
				Msg("Calling protocolEngine.GenerateKeyShare (this may take several minutes)")

			resp, err := selectedEngine.GenerateKeyShare(keygenCtx, dkgReq)
			if err != nil {
				log.Error().
					Err(err).
					Str("key_id", req.KeyId).
					Str("session_id", sessionID).
					Str("this_node_id", s.nodeID).
					Msg("GenerateKeyShare failed in StartDKG RPC goroutine")
			} else if resp != nil && resp.PublicKey != nil && resp.PublicKey.Hex != "" {
				log.Info().
					Str("key_id", req.KeyId).
					Str("session_id", sessionID).
					Str("this_node_id", s.nodeID).
					Str("public_key", resp.PublicKey.Hex).
					Int("key_share_count", len(resp.KeyShares)).
					Msg("GenerateKeyShare completed successfully in StartDKG RPC goroutine")

				// 存储密钥分片（只存储当前节点的分片）
				if s.keyShareStorage != nil && len(resp.KeyShares) > 0 {
					for nodeID, share := range resp.KeyShares {
						if err := s.keyShareStorage.StoreKeyShare(keygenCtx, req.KeyId, nodeID, share.Share); err != nil {
							log.Error().
								Err(err).
								Str("key_id", req.KeyId).
								Str("node_id", nodeID).
								Str("this_node_id", s.nodeID).
								Msg("Failed to store key share in StartDKG RPC goroutine")
						} else {
							log.Info().
								Str("key_id", req.KeyId).
								Str("node_id", nodeID).
								Str("this_node_id", s.nodeID).
								Msg("Key share stored successfully in StartDKG RPC goroutine")
						}
					}
				} else {
					log.Warn().
						Str("key_id", req.KeyId).
						Str("this_node_id", s.nodeID).
						Bool("keyShareStorage_nil", s.keyShareStorage == nil).
						Int("key_share_count", len(resp.KeyShares)).
						Msg("Key share storage skipped (keyShareStorage is nil or no key shares)")
				}

				// DKG完成，更新会话
				if err := s.sessionManager.CompleteKeygenSession(keygenCtx, req.KeyId, resp.PublicKey.Hex); err != nil {
					log.Error().
						Err(err).
						Str("key_id", req.KeyId).
						Str("session_id", sessionID).
						Str("this_node_id", s.nodeID).
						Msg("Failed to complete keygen session in StartDKG RPC goroutine")
				} else {
					log.Info().
						Str("key_id", req.KeyId).
						Str("session_id", sessionID).
						Str("this_node_id", s.nodeID).
						Str("public_key", resp.PublicKey.Hex).
						Msg("Keygen session completed successfully in StartDKG RPC goroutine")
				}
			}
		}()
	})

	if !started {
		// DKG已经在运行（可能是通过自动启动机制启动的）
		log.Info().
			Str("key_id", req.KeyId).
			Str("session_id", sessionID).
			Str("this_node_id", s.nodeID).
			Msg("DKG already started (possibly via auto-start), returning success")
		return &pb.StartDKGResponse{Started: true, Message: "DKG already started"}, nil
	}

	// GenerateKeyShare在goroutine中执行，立即返回
	// DKG的完成会通过其他机制（如CompleteKeygenSession）来通知
	log.Info().
		Str("key_id", req.KeyId).
		Str("session_id", sessionID).
		Str("this_node_id", s.nodeID).
		Msg("DKG started in background, returning immediately")
	return &pb.StartDKGResponse{Started: true, Message: "DKG started in background"}, nil
}

// StartSign 由协调者调用以启动参与者的签名
func (s *GRPCServer) StartSign(ctx context.Context, req *pb.StartSignRequest) (*pb.StartSignResponse, error) {
	log.Info().
		Str("key_id", req.KeyId).
		Str("session_id", req.SessionId).
		Str("this_node_id", s.nodeID).
		Msg("StartSign RPC received")

	sessionID := req.SessionId
	if sessionID == "" {
		sessionID = req.KeyId
	}

	// 基本校验：节点数量应满足 threshold/totalNodes
	if req.Threshold > 0 && len(req.NodeIds) < int(req.Threshold) {
		msg := fmt.Sprintf("insufficient node_ids: need >= %d, got %d", req.Threshold, len(req.NodeIds))
		log.Error().
			Str("key_id", req.KeyId).
			Str("session_id", sessionID).
			Int("node_ids", len(req.NodeIds)).
			Int32("threshold", req.Threshold).
			Int32("total_nodes", req.TotalNodes).
			Msg(msg)
		return &pb.StartSignResponse{Started: false, Message: msg}, nil
	}
	if req.TotalNodes > 0 && len(req.NodeIds) > int(req.TotalNodes) {
		msg := fmt.Sprintf("too many node_ids: total_nodes=%d, got=%d", req.TotalNodes, len(req.NodeIds))
		log.Error().
			Str("key_id", req.KeyId).
			Str("session_id", sessionID).
			Int("node_ids", len(req.NodeIds)).
			Int32("threshold", req.Threshold).
			Int32("total_nodes", req.TotalNodes).
			Msg(msg)
		return &pb.StartSignResponse{Started: false, Message: msg}, nil
	}

	onceInterface, _ := s.signStartOnce.LoadOrStore(sessionID, &sync.Once{})
	once := onceInterface.(*sync.Once)

	var started bool

	once.Do(func() {
		started = true
		log.Info().
			Str("key_id", req.KeyId).
			Str("session_id", sessionID).
			Str("this_node_id", s.nodeID).
			Msg("sync.Once.Do executed in StartSign RPC - starting signing in goroutine")

		go func() {
			signTimeout := 10 * time.Minute
			signCtx, cancel := context.WithTimeout(context.Background(), signTimeout)
			defer cancel()

			// 准备消息
			msg := req.Message
			if len(msg) == 0 && req.MessageHex != "" {
				decoded, err := hex.DecodeString(req.MessageHex)
				if err != nil {
					log.Error().
						Err(err).
						Str("session_id", sessionID).
						Str("key_id", req.KeyId).
						Str("this_node_id", s.nodeID).
						Msg("Failed to decode message_hex in StartSign")
					return
				}
				msg = decoded
			}

			signReq := &protocol.SignRequest{
				KeyID:           req.KeyId,
				Message:         msg,
				MessageHex:      req.MessageHex,
				NodeIDs:         req.NodeIds,
				DerivationPath:  req.DerivationPath,
				ParentChainCode: req.ParentChainCode,
			}

			// 根据请求中的 Protocol 字段选择协议引擎
			// 如果请求中没有指定 Protocol，使用默认协议引擎
			var engine protocol.Engine
			if req.Protocol != "" {
				// 尝试从注册表获取协议引擎
				if s.protocolRegistry != nil {
					if regEngine, err := s.protocolRegistry.Get(req.Protocol); err == nil {
						engine = regEngine
						log.Info().
							Str("key_id", req.KeyId).
							Str("session_id", sessionID).
							Str("protocol", req.Protocol).
							Str("this_node_id", s.nodeID).
							Msg("Using protocol from registry based on request")
					} else {
						log.Warn().
							Err(err).
							Str("key_id", req.KeyId).
							Str("session_id", sessionID).
							Str("requested_protocol", req.Protocol).
							Str("this_node_id", s.nodeID).
							Msg("Failed to get protocol from registry, using default engine")
						engine = s.protocolEngine
					}
				} else {
					log.Warn().
						Str("key_id", req.KeyId).
						Str("session_id", sessionID).
						Str("requested_protocol", req.Protocol).
						Str("this_node_id", s.nodeID).
						Msg("Protocol registry not available, using default engine")
					engine = s.protocolEngine
				}
			} else {
				// 使用默认协议引擎
				engine = s.protocolEngine
			}

			log.Info().
				Str("key_id", req.KeyId).
				Str("session_id", sessionID).
				Str("protocol", req.Protocol).
				Str("this_node_id", s.nodeID).
				Msg("Calling protocolEngine.ThresholdSign (participant)")

			resp, err := engine.ThresholdSign(signCtx, sessionID, signReq)
			if err != nil {
				log.Error().
					Err(err).
					Str("key_id", req.KeyId).
					Str("session_id", sessionID).
					Str("this_node_id", s.nodeID).
					Msg("ThresholdSign failed in StartSign RPC goroutine")

				// ✅ 更新会话状态为失败
				if sess, getErr := s.sessionManager.GetSession(signCtx, sessionID); getErr == nil {
					sess.Status = "failed"
					if updateErr := s.sessionManager.UpdateSession(signCtx, sess); updateErr != nil {
						log.Error().
							Err(updateErr).
							Str("session_id", sessionID).
							Msg("Failed to update session status to failed")
					}
				}
				return
			}

			if resp != nil && resp.Signature != nil && resp.Signature.Hex != "" {
				log.Info().
					Str("key_id", req.KeyId).
					Str("session_id", sessionID).
					Str("this_node_id", s.nodeID).
					Str("signature", resp.Signature.Hex).
					Msg("ThresholdSign completed successfully in StartSign RPC goroutine")

				// ✅ 更新会话状态为完成，并保存签名
				// 使用 CompleteSession 方法，它会自动处理状态更新和时间戳
				log.Info().
					Str("session_id", sessionID).
					Str("this_node_id", s.nodeID).
					Str("signature", resp.Signature.Hex).
					Msg("🔍 [DIAGNOSTIC] Calling CompleteSession to update session status")

				if completeErr := s.sessionManager.CompleteSession(signCtx, sessionID, resp.Signature.Hex); completeErr != nil {
					log.Error().
						Err(completeErr).
						Str("session_id", sessionID).
						Str("this_node_id", s.nodeID).
						Msg("Failed to complete session (may be completed by another participant)")
				} else {
					log.Info().
						Str("session_id", sessionID).
						Str("this_node_id", s.nodeID).
						Str("signature", resp.Signature.Hex).
						Msg("🔍 [DIAGNOSTIC] Session completed successfully")
				}
			} else {
				log.Warn().
					Str("key_id", req.KeyId).
					Str("session_id", sessionID).
					Str("this_node_id", s.nodeID).
					Msg("ThresholdSign returned nil or empty signature")
			}
		}()
	})

	if !started {
		log.Info().
			Str("key_id", req.KeyId).
			Str("session_id", sessionID).
			Str("this_node_id", s.nodeID).
			Msg("Signing already started, returning success")
		return &pb.StartSignResponse{Started: true, Message: "Signing already started"}, nil
	}

	log.Info().
		Str("key_id", req.KeyId).
		Str("session_id", sessionID).
		Str("this_node_id", s.nodeID).
		Msg("Signing started in background, returning immediately")
	return &pb.StartSignResponse{Started: true, Message: "Signing started in background"}, nil
}

// handleProtocolMessage 处理协议消息（DKG或签名）
func (s *GRPCServer) handleProtocolMessage(ctx context.Context, sessionID string, fromNodeID string, shareMsg *pb.ShareMessage) error {
	// 从会话中判断消息类型
	sess, err := s.sessionManager.GetSession(ctx, sessionID)
	if err != nil {
		log.Error().
			Err(err).
			Str("session_id", sessionID).
			Str("from_node_id", fromNodeID).
			Str("this_node_id", s.nodeID).
			Msg("Failed to get session for protocol message - participant cannot start DKG without session")
		// 提供更详细的错误信息，帮助诊断问题
		return errors.Wrapf(err, "failed to get session %s for protocol message from node %s (this node: %s). Possible causes: 1) session was not created by coordinator, 2) session was created but not yet visible due to database replication lag, 3) session expired or was deleted", sessionID, fromNodeID, s.nodeID)
	}

	// 根据会话判断 DKG 还是签名：
	// - DKG: sessionID 等于 keyID 或以 key- 开头
	// - 签名: 其他情况一律视为签名（避免签名消息误入 DKG 逻辑）
	isKeygenSession := sessionID == sess.KeyID || strings.HasPrefix(strings.ToLower(sessionID), "key-")
	isDKG := isKeygenSession
	isBroadcast := shareMsg != nil && shareMsg.Round == -1

	if isDKG {
		// 处理特殊控制消息
		if len(shareMsg.ShareData) > 0 {
			data := string(shareMsg.ShareData)
			if data == "DKG_START" {
				// coordinator 发送的启动通知，只触发启动，不处理内容
				// 后续真实 DKG 消息会再到达
				return nil
			}
			if strings.HasPrefix(data, "DKG_COMPLETE:") {
				pubKey := strings.TrimPrefix(data, "DKG_COMPLETE:")
				if err := s.sessionManager.CompleteKeygenSession(ctx, sessionID, pubKey); err != nil {
					return errors.Wrap(err, "failed to complete keygen session")
				}
				return nil
			}
		}

		// ✅ 方案一：Coordinator 不参与 DKG，第一个 participant 作为 leader 启动
		// 检查当前节点是否是第一个 participant（按 nodeID 排序）
		isLeader := false
		if len(sess.ParticipatingNodes) > 0 {
			// 按 nodeID 排序，第一个节点作为 leader
			leaderNodeID := sess.ParticipatingNodes[0]
			isLeader = (s.nodeID == leaderNodeID)
		}
		_ = isLeader

		// 对于DKG消息，如果是参与者节点且还没有启动DKG协议，需要自动启动
		// 使用sync.Once确保每个sessionID只启动一次DKG协议
		if len(sess.ParticipatingNodes) > 0 && sess.Threshold > 0 && sess.TotalNodes > 0 {
			// 获取或创建sync.Once
			onceInterface, _ := s.dkgStartOnce.LoadOrStore(sessionID, &sync.Once{})
			once := onceInterface.(*sync.Once)

			// 检查是否已经有活跃的DKG实例（双重检查，防止sync.Once失效）
			// 注意：这个检查在sync.Once.Do之前，所以可能会有竞态条件
			// 但sync.Once应该能防止重复启动
			log.Debug().
				Str("session_id", sessionID).
				Str("this_node_id", s.nodeID).
				Msg("Checking if DKG should auto-start (before sync.Once.Do)")

			// 确保只启动一次
			var shouldStart bool
			once.Do(func() {
				shouldStart = true
				log.Info().
					Str("session_id", sessionID).
					Str("this_node_id", s.nodeID).
					Msg("sync.Once.Do executed - starting DKG")
				// 在后台启动DKG协议，不阻塞消息处理
				go func() {
					// 使用独立的上下文，避免 gRPC 请求结束导致 context 被取消
					// 缩短超时时间，加快失败检测（原 10 分钟）
					keygenTimeout := 2 * time.Minute
					keygenCtx, cancel := context.WithTimeout(context.Background(), keygenTimeout)
					defer cancel()

					log.Info().
						Str("session_id", sessionID).
						Str("key_id", sess.KeyID).
						Str("this_node_id", s.nodeID).
						Int("threshold", sess.Threshold).
						Int("total_nodes", sess.TotalNodes).
						Strs("participating_nodes", sess.ParticipatingNodes).
						Dur("keygen_timeout", keygenTimeout).
						Msg("Auto-starting DKG protocol on participant (triggered by incoming message)")

					// 从会话中获取DKG参数
					// 根据协议类型推断算法和曲线
					algorithm := "ECDSA"
					curve := "secp256k1"
					protocolLower := strings.ToLower(sess.Protocol)
					if protocolLower == "frost" {
						algorithm = "EdDSA"
						curve = "ed25519"
					} else if protocolLower == "gg18" || protocolLower == "gg20" {
						algorithm = "ECDSA"
						curve = "secp256k1"
					}

					dkgReq := &protocol.KeyGenRequest{
						KeyID:      sess.KeyID, // DKG会话使用keyID作为sessionID
						Algorithm:  algorithm,
						Curve:      curve,
						Threshold:  sess.Threshold,
						TotalNodes: sess.TotalNodes,
						NodeIDs:    sess.ParticipatingNodes,
					}

					log.Debug().
						Str("session_id", sessionID).
						Str("key_id", sess.KeyID).
						Str("protocol", sess.Protocol).
						Str("algorithm", algorithm).
						Str("curve", curve).
						Msg("Auto-start DKG request parameters determined from session protocol")

					// 选择与会话协议匹配的引擎，避免默认引擎（可能是 FROST）与 ECDSA 请求冲突
					engine := s.protocolEngine
					if s.protocolRegistry != nil && sess.Protocol != "" {
						if regEngine, err := s.protocolRegistry.Get(strings.ToLower(sess.Protocol)); err == nil {
							engine = regEngine
						} else {
							log.Warn().
								Err(err).
								Str("session_id", sessionID).
								Str("key_id", sess.KeyID).
								Str("requested_protocol", sess.Protocol).
								Str("this_node_id", s.nodeID).
								Msg("Auto-start DKG: failed to get protocol from registry, fallback to default engine")
						}
					}

					// 启动DKG协议（在后台，不阻塞）
					// 消息会被放入队列，等待DKG协议启动后处理
					resp, err := engine.GenerateKeyShare(keygenCtx, dkgReq)
					if err != nil {
						log.Error().
							Err(err).
							Str("session_id", sessionID).
							Str("key_id", sess.KeyID).
							Str("this_node_id", s.nodeID).
							Msg("DKG protocol failed on participant")
					} else if resp != nil && resp.PublicKey != nil && resp.PublicKey.Hex != "" {
						log.Info().
							Str("session_id", sessionID).
							Str("key_id", sess.KeyID).
							Str("this_node_id", s.nodeID).
							Str("public_key", resp.PublicKey.Hex).
							Int("key_share_count", len(resp.KeyShares)).
							Msg("DKG protocol completed successfully on participant, storing key share and calling CompleteKeygenSession")

						// 存储密钥分片（只存储当前节点的分片）
						if s.keyShareStorage != nil && len(resp.KeyShares) > 0 {
							for nodeID, share := range resp.KeyShares {
								if err := s.keyShareStorage.StoreKeyShare(keygenCtx, sess.KeyID, nodeID, share.Share); err != nil {
									log.Error().
										Err(err).
										Str("key_id", sess.KeyID).
										Str("node_id", nodeID).
										Str("this_node_id", s.nodeID).
										Msg("Failed to store key share in auto-start goroutine")
								} else {
									log.Info().
										Str("key_id", sess.KeyID).
										Str("node_id", nodeID).
										Str("this_node_id", s.nodeID).
										Msg("Key share stored successfully in auto-start goroutine")
								}
							}
						} else {
							log.Warn().
								Str("key_id", sess.KeyID).
								Str("this_node_id", s.nodeID).
								Bool("keyShareStorage_nil", s.keyShareStorage == nil).
								Int("key_share_count", len(resp.KeyShares)).
								Msg("Key share storage skipped in auto-start (keyShareStorage is nil or no key shares)")
						}

						// DKG 完成，直接更新会话与密钥（共享数据库）
						if err := s.sessionManager.CompleteKeygenSession(keygenCtx, sess.KeyID, resp.PublicKey.Hex); err != nil {
							log.Error().
								Err(err).
								Str("session_id", sessionID).
								Str("key_id", sess.KeyID).
								Str("this_node_id", s.nodeID).
								Msg("Failed to complete keygen session")
						} else {
							log.Info().
								Str("session_id", sessionID).
								Str("key_id", sess.KeyID).
								Str("this_node_id", s.nodeID).
								Msg("Keygen session completed successfully")
						}
					}
				}()
			})

			if !shouldStart {
				log.Info().
					Str("session_id", sessionID).
					Str("this_node_id", s.nodeID).
					Msg("DKG already started via sync.Once, skipping auto-start")
			}
		}

		// 作为DKG消息处理，传递发送方节点ID
		// 使用与 StartDKG 相同的协议引擎（基于 session 协议或 registry），避免不同引擎的队列不一致
		engine := s.protocolEngine
		if s.protocolRegistry != nil && sess.Protocol != "" {
			if regEngine, err := s.protocolRegistry.Get(strings.ToLower(sess.Protocol)); err == nil {
				engine = regEngine
			} else {
				log.Warn().
					Err(err).
					Str("session_id", sessionID).
					Str("from_node_id", fromNodeID).
					Str("requested_protocol", sess.Protocol).
					Str("this_node_id", s.nodeID).
					Msg("Failed to get protocol from registry for keygen message, fallback to default protocolEngine")
			}
		}

		// 消息会被放入队列，等待DKG协议启动后处理
		if err := engine.ProcessIncomingKeygenMessage(ctx, sessionID, fromNodeID, shareMsg.ShareData, isBroadcast); err != nil {
			return errors.Wrap(err, "failed to process keygen message")
		}
	} else {
		// 作为签名消息处理，传递发送方节点ID；签名阶段不再尝试自动启动 DKG
		// 确保使用与 StartSign 相同的协议引擎（基于 session 的协议或 registry）
		engine := s.protocolEngine
		if s.protocolRegistry != nil && sess.Protocol != "" {
			if regEngine, err := s.protocolRegistry.Get(sess.Protocol); err == nil {
				engine = regEngine
			} else {
				log.Warn().
					Err(err).
					Str("session_id", sessionID).
					Str("from_node_id", fromNodeID).
					Str("requested_protocol", sess.Protocol).
					Str("this_node_id", s.nodeID).
					Msg("Failed to get protocol from registry for signing message, fallback to default protocolEngine")
			}
		}

		if err := engine.ProcessIncomingSigningMessage(ctx, sessionID, fromNodeID, shareMsg.ShareData, isBroadcast); err != nil {
			return errors.Wrap(err, "failed to process signing message")
		}
	}

	return nil
}

// SubmitSignatureShare 提交签名分片（单向RPC）
// 这个方法同时用于DKG和签名消息
func (s *GRPCServer) SubmitSignatureShare(ctx context.Context, req *pb.ShareRequest) (*pb.ShareResponse, error) {
	log.Debug().
		Str("session_id", req.SessionId).
		Str("from_node", req.NodeId).
		Int32("round", req.Round).
		Int("data_len", len(req.ShareData)).
		Msg("Received SubmitSignatureShare request")

	// 处理协议消息，传递发送方节点ID
	if err := s.handleProtocolMessage(ctx, req.SessionId, req.NodeId, &pb.ShareMessage{
		ShareData:   req.ShareData,
		Round:       req.Round,
		SubmittedAt: req.Timestamp,
	}); err != nil {
		log.Error().Err(err).
			Str("session_id", req.SessionId).
			Str("from_node", req.NodeId).
			Msg("Failed to handle protocol message")
		return &pb.ShareResponse{
			Accepted:  false,
			Message:   err.Error(),
			NextRound: req.Round,
		}, nil
	}

	return &pb.ShareResponse{
		Accepted:  true,
		Message:   "share accepted",
		NextRound: req.Round + 1,
	}, nil
}

// Heartbeat 心跳检测
func (s *GRPCServer) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	return &pb.HeartbeatResponse{
		Alive:         true,
		CoordinatorId: s.nodeID,
		ReceivedAt:    time.Now().Format(time.RFC3339),
		Instructions:  make(map[string]string),
	}, nil
}

// Start 启动 gRPC 服务器
func (s *GRPCServer) Start(ctx context.Context) error {
	addr := fmt.Sprintf(":%d", s.cfg.Port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.listener = listener

	// 创建 gRPC 服务器实例
	opts, _ := s.GetServerOptions()
	s.grpcServer = grpc.NewServer(opts...)

	// 注册服务
	pb.RegisterMPCNodeServer(s.grpcServer, s)

	// 启用反射（开发环境）
	reflection.Register(s.grpcServer)

	log.Info().
		Str("address", addr).
		Bool("tls", s.cfg.TLSEnabled).
		Msg("Starting MPC gRPC server")

	// 在 goroutine 中启动服务器
	go func() {
		if err := s.grpcServer.Serve(listener); err != nil {
			log.Error().Err(err).Msg("MPC gRPC server failed")
		}
	}()

	// 等待上下文取消
	<-ctx.Done()
	return s.Stop()
}

// Stop 停止 gRPC 服务器
func (s *GRPCServer) Stop() error {
	log.Info().Msg("Stopping MPC gRPC server")

	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}

	if s.listener != nil {
		s.listener.Close()
	}

	return nil
}
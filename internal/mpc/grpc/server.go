package grpc

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"encoding/hex"

	"github.com/kashguard/go-mpc-infra/internal/config"
	"github.com/kashguard/go-mpc-infra/internal/infra/backup"
	"github.com/kashguard/go-mpc-infra/internal/infra/session"
	"github.com/kashguard/go-mpc-infra/internal/infra/storage"
	"github.com/kashguard/go-mpc-infra/internal/mpc/protocol"
	pb "github.com/kashguard/go-mpc-infra/internal/pb/mpc/v1"
	"github.com/kashguard/go-mpc-infra/internal/util/cert"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
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
	metadataStore    storage.MetadataStore   // 用于读取元数据（策略、公钥）
	backupService    backup.SSSBackupService // 用于生成备份分片
	nodeID           string
	cfg              *ServerConfig

	// gRPC 服务器实例
	grpcServer *grpc.Server
	listener   net.Listener

	// 用于确保每个DKG会话只启动一次
	dkgStartOnce sync.Map // map[string]*sync.Once

	// 用于确保每个签名会话只启动一次
	signStartOnce sync.Map // map[string]*sync.Once

	// 用于确保每个Resharing会话只启动一次
	resharingStartOnce sync.Map // map[string]*sync.Once
}

// ServerConfig gRPC服务端配置
type ServerConfig struct {
	Port           int
	TLSEnabled     bool
	TLSCertFile    string
	TLSKeyFile     string
	TLSCACertFile  string
	MaxConnAge     time.Duration
	KeepAlive      time.Duration
	IsGuardianNode bool // 是否作为 Guardian 节点运行
}

// NewGRPCServer 创建gRPC服务端
func NewGRPCServer(
	cfg config.Server,
	protocolEngine protocol.Engine,
	sessionManager *session.Manager,
	keyShareStorage storage.KeyShareStorage,
	metadataStore storage.MetadataStore,
	backupService backup.SSSBackupService,
	nodeID string,
) *GRPCServer {
	return NewGRPCServerWithRegistry(cfg, protocolEngine, nil, sessionManager, keyShareStorage, metadataStore, backupService, nodeID)
}

// NewGRPCServerWithRegistry 创建gRPC服务端（带协议注册表）
func NewGRPCServerWithRegistry(
	cfg config.Server,
	protocolEngine protocol.Engine,
	protocolRegistry *protocol.ProtocolRegistry, // 协议注册表（可选，用于动态选择协议）
	sessionManager *session.Manager,
	keyShareStorage storage.KeyShareStorage,
	metadataStore storage.MetadataStore,
	backupService backup.SSSBackupService,
	nodeID string,
) *GRPCServer {
	serverCfg := &ServerConfig{
		Port:           cfg.MPC.GRPCPort,
		TLSEnabled:     cfg.MPC.TLSEnabled,
		TLSCertFile:    cfg.MPC.TLSCertFile,
		TLSKeyFile:     cfg.MPC.TLSKeyFile,
		TLSCACertFile:  cfg.MPC.TLSCACertFile,
		MaxConnAge:     2 * time.Hour,
		KeepAlive:      30 * time.Second,
		IsGuardianNode: cfg.MPC.IsGuardianNode,
	}

	srv := &GRPCServer{
		protocolEngine:   protocolEngine,
		protocolRegistry: protocolRegistry,
		sessionManager:   sessionManager,
		keyShareStorage:  keyShareStorage,
		metadataStore:    metadataStore,
		backupService:    backupService,
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

							// 生成并保存SSS备份分片
							if s.backupService != nil && s.metadataStore != nil {
								backupStorage, ok := s.metadataStore.(storage.BackupShareStorage)
								if ok {
									// 对该MPC分片生成SSS备份分片 (默认 3-of-5 备份策略)
									// TODO: 从配置或请求中获取备份策略
									backupShares, err := s.backupService.GenerateBackupShares(keygenCtx, share.Share, 3, 5)
									if err != nil {
										log.Error().
											Err(err).
											Str("key_id", req.KeyId).
											Str("node_id", nodeID).
											Msg("Failed to generate backup shares")
									} else {
										for i, bs := range backupShares {
											// 这里的 shareIndex 是 SSS 分片的索引 (1-based)
											if err := backupStorage.SaveBackupShare(keygenCtx, req.KeyId, nodeID, i+1, bs.ShareData); err != nil {
												log.Error().
													Err(err).
													Str("key_id", req.KeyId).
													Str("node_id", nodeID).
													Int("share_index", i+1).
													Msg("Failed to save backup share")
											}
										}
										log.Info().
											Str("key_id", req.KeyId).
											Str("node_id", nodeID).
											Int("count", len(backupShares)).
											Msg("Generated and saved SSS backup shares")
									}
								} else {
									log.Warn().Msg("MetadataStore does not implement BackupShareStorage, skipping backup")
								}
							}
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

	// 鉴权代理逻辑：如果配置了 Guardian 模式，或者收到鉴权令牌，执行鉴权
	// 这里假设所有节点都具备 Guardian 能力，通过配置或动态策略激活
	// 为了简化，我们只检查是否存在 metadataStore 和 AuthTokens
	if s.metadataStore != nil && (len(req.AuthTokens) > 0 || s.cfg.IsGuardianNode) {
		if err := s.checkGuardianPolicy(ctx, req); err != nil {
			log.Warn().
				Err(err).
				Str("key_id", req.KeyId).
				Str("session_id", sessionID).
				Str("this_node_id", s.nodeID).
				Msg("Guardian check failed, rejecting StartSign request")
			return &pb.StartSignResponse{Started: false, Message: fmt.Sprintf("Guardian Access Denied: %v", err)}, nil
		}
		log.Info().
			Str("key_id", req.KeyId).
			Str("session_id", sessionID).
			Str("this_node_id", s.nodeID).
			Msg("Guardian check passed")
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

// StartResharing 由协调者调用以启动参与者的密钥轮换
func (s *GRPCServer) StartResharing(ctx context.Context, req *pb.StartResharingRequest) (*pb.StartResharingResponse, error) {
	log.Info().
		Str("key_id", req.KeyId).
		Str("session_id", req.SessionId).
		Str("this_node_id", s.nodeID).
		Msg("StartResharing RPC received")

	sessionID := req.SessionId
	if sessionID == "" {
		sessionID = req.KeyId
	}

	onceInterface, _ := s.resharingStartOnce.LoadOrStore(sessionID, &sync.Once{})
	once := onceInterface.(*sync.Once)

	var started bool

	once.Do(func() {
		started = true
		log.Info().
			Str("key_id", req.KeyId).
			Str("session_id", sessionID).
			Str("this_node_id", s.nodeID).
			Msg("sync.Once.Do executed in StartResharing RPC - starting resharing in goroutine")

		go func() {
			resharingTimeout := 10 * time.Minute
			resharingCtx, cancel := context.WithTimeout(context.Background(), resharingTimeout)
			defer cancel()

			// 获取协议引擎（Resharing 目前仅支持 GG20）
			// TODO: 支持其他协议
			engine := s.protocolEngine
			if s.protocolRegistry != nil {
				if regEngine, err := s.protocolRegistry.Get("gg20"); err == nil {
					engine = regEngine
				}
			}

			// 类型断言检查是否支持 ExecuteResharing
			// 目前只有 GG20Protocol 实现了 ExecuteResharing
			// 如果 engine 是 interface Wrapper，可能需要扩展 Engine 接口
			type Resharer interface {
				ExecuteResharing(
					ctx context.Context,
					keyID string,
					oldNodeIDs []string,
					newNodeIDs []string,
					oldThreshold int,
					newThreshold int,
				) (*protocol.KeyGenResponse, error)
			}

			resharer, ok := engine.(Resharer)
			if !ok {
				log.Error().
					Str("key_id", req.KeyId).
					Str("session_id", sessionID).
					Str("this_node_id", s.nodeID).
					Msg("Protocol engine does not support Resharing")
				return
			}

			resp, err := resharer.ExecuteResharing(
				resharingCtx,
				req.KeyId,
				req.OldNodeIds,
				req.NewNodeIds,
				int(req.OldThreshold),
				int(req.NewThreshold),
			)
			if err != nil {
				log.Error().
					Err(err).
					Str("key_id", req.KeyId).
					Str("session_id", sessionID).
					Str("this_node_id", s.nodeID).
					Msg("ExecuteResharing failed in StartResharing RPC goroutine")
				return
			}

			if resp != nil && resp.PublicKey != nil && resp.PublicKey.Hex != "" {
				log.Info().
					Str("key_id", req.KeyId).
					Str("session_id", sessionID).
					Str("this_node_id", s.nodeID).
					Str("public_key", resp.PublicKey.Hex).
					Msg("Resharing completed successfully")

				// 存储新分片
				if s.keyShareStorage != nil && len(resp.KeyShares) > 0 {
					for nodeID, share := range resp.KeyShares {
						if err := s.keyShareStorage.StoreKeyShare(resharingCtx, req.KeyId, nodeID, share.Share); err != nil {
							log.Error().Err(err).Msg("Failed to store new key share")
						}
					}
				}
			}
		}()
	})

	if !started {
		return &pb.StartResharingResponse{Started: true, Message: "Resharing already started"}, nil
	}

	return &pb.StartResharingResponse{Started: true, Message: "Resharing started in background"}, nil
}

// handleProtocolMessage 处理协议消息（DKG或签名）
func (s *GRPCServer) handleProtocolMessage(ctx context.Context, sessionID string, fromNodeID string, shareData []byte, round int32, isBroadcast bool) error {
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
	// isBroadcast is passed as argument

	if isDKG {
		// 处理特殊控制消息
		if len(shareData) > 0 {
			data := string(shareData)
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

									// 生成并保存SSS备份分片
									if s.backupService != nil && s.metadataStore != nil {
										backupStorage, ok := s.metadataStore.(storage.BackupShareStorage)
										if ok {
											// 对该MPC分片生成SSS备份分片 (默认 3-of-5 备份策略)
											// TODO: 从配置或请求中获取备份策略
											backupShares, err := s.backupService.GenerateBackupShares(keygenCtx, share.Share, 3, 5)
											if err != nil {
												log.Error().
													Err(err).
													Str("key_id", sess.KeyID).
													Str("node_id", nodeID).
													Msg("Failed to generate backup shares")
											} else {
												for i, bs := range backupShares {
													// 这里的 shareIndex 是 SSS 分片的索引 (1-based)
													if err := backupStorage.SaveBackupShare(keygenCtx, sess.KeyID, nodeID, i+1, bs.ShareData); err != nil {
														log.Error().
															Err(err).
															Str("key_id", sess.KeyID).
															Str("node_id", nodeID).
															Int("share_index", i+1).
															Msg("Failed to save backup share")
													}
												}
												log.Info().
													Str("key_id", sess.KeyID).
													Str("node_id", nodeID).
													Int("count", len(backupShares)).
													Msg("Generated and saved SSS backup shares")
											}
										} else {
											log.Warn().Msg("MetadataStore does not implement BackupShareStorage, skipping backup")
										}
									}
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
		if err := engine.ProcessIncomingKeygenMessage(ctx, sessionID, fromNodeID, shareData, isBroadcast); err != nil {
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

		if err := engine.ProcessIncomingSigningMessage(ctx, sessionID, fromNodeID, shareData, isBroadcast); err != nil {
			return errors.Wrap(err, "failed to process signing message")
		}
	}

	return nil
}

// SubmitProtocolMessage 提交协议消息（单向RPC）
// 这个方法同时用于DKG和签名消息
func (s *GRPCServer) SubmitProtocolMessage(ctx context.Context, req *pb.SubmitProtocolMessageRequest) (*pb.SubmitProtocolMessageResponse, error) {
	log.Debug().
		Str("session_id", req.SessionId).
		Str("from_node", req.NodeId).
		Int32("round", req.Round).
		Int("data_len", len(req.Data)).
		Msg("Received SubmitProtocolMessage request")

	// 处理协议消息，传递发送方节点ID
	isBroadcast := req.Round == -1
	if err := s.handleProtocolMessage(ctx, req.SessionId, req.NodeId, req.Data, req.Round, isBroadcast); err != nil {
		log.Error().Err(err).
			Str("session_id", req.SessionId).
			Str("from_node", req.NodeId).
			Msg("Failed to handle protocol message")
		return &pb.SubmitProtocolMessageResponse{
			Accepted:  false,
			Message:   err.Error(),
			NextRound: req.Round,
		}, nil
	}

	return &pb.SubmitProtocolMessageResponse{
		Accepted:  true,
		Message:   "message accepted",
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
	// 如果启用了 TLS，在启动前验证证书
	if s.cfg.TLSEnabled {
		if err := cert.VerifyTLSConfig(s.cfg.TLSCertFile, s.cfg.TLSKeyFile, s.cfg.TLSCACertFile); err != nil {
			return errors.Wrap(err, "TLS certificate verification failed")
		}
		log.Info().Msg("TLS certificates verified successfully")
	}

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

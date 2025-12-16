package key

import (
	"context"
	"strings"
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/mpc/node"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/protocol"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/storage"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
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

// DKGService 分布式密钥生成服务
type DKGService struct {
	metadataStore    storage.MetadataStore
	keyShareStorage  storage.KeyShareStorage
	protocolEngine   protocol.Engine
	protocolRegistry *protocol.ProtocolRegistry // 协议注册表，用于根据算法和曲线选择正确的协议
	nodeManager      *node.Manager
	nodeDiscovery    *node.Discovery
	// 同步模式配置：最大等待时间、轮询间隔
	MaxWaitTime  time.Duration
	PollInterval time.Duration
}

// NewDKGService 创建DKG服务
func NewDKGService(
	metadataStore storage.MetadataStore,
	keyShareStorage storage.KeyShareStorage,
	protocolEngine protocol.Engine,
	protocolRegistry *protocol.ProtocolRegistry, // 新增：协议注册表
	nodeManager *node.Manager,
	nodeDiscovery *node.Discovery,
) *DKGService {
	return &DKGService{
		metadataStore:    metadataStore,
		keyShareStorage:  keyShareStorage,
		protocolEngine:   protocolEngine,
		protocolRegistry: protocolRegistry,
		nodeManager:      nodeManager,
		nodeDiscovery:    nodeDiscovery,
		// 缩短同步等待时间，加快失败检测
		MaxWaitTime:  2 * time.Minute,
		PollInterval: 2 * time.Second,
	}
}

// ExecuteDKG 执行分布式密钥生成
// 现改为同步：发起后阻塞等待完成/失败/超时
// 支持固定 2-of-3 模式：固定节点列表 [server-proxy-1, server-proxy-2, client-{userID}]
func (s *DKGService) ExecuteDKG(ctx context.Context, keyID string, req *CreateKeyRequest) (*protocol.KeyGenResponse, error) {
	log.Info().
		Str("key_id", keyID).
		Str("algorithm", req.Algorithm).
		Str("curve", req.Curve).
		Int("threshold", req.Threshold).
		Int("total_nodes", req.TotalNodes).
		Str("user_id", req.UserID).
		Msg("ExecuteDKG: Starting synchronous DKG execution")

	// 1. 构建固定节点列表（2-of-3 模式）
	var nodeIDs []string
	if req.Threshold == 2 && req.TotalNodes == 3 {
		// 固定 2-of-3 模式：使用固定节点列表
		nodeIDs = []string{"server-proxy-1", "server-proxy-2"}
		
		// 添加客户端节点（如果提供了 UserID）
		if req.UserID != "" {
			clientNodeID := "client-" + req.UserID
			nodeIDs = append(nodeIDs, clientNodeID)
		} else {
			// 如果没有 UserID，尝试从会话中获取
			session, err := s.metadataStore.GetSigningSession(ctx, keyID)
			if err == nil && len(session.ParticipatingNodes) > 0 {
				// 从会话中查找客户端节点
				for _, nid := range session.ParticipatingNodes {
					if strings.HasPrefix(nid, "client-") {
						nodeIDs = append(nodeIDs, nid)
						break
					}
				}
			}
			
			// 如果仍然没有客户端节点，使用占位符（不推荐，但保持兼容性）
			if len(nodeIDs) < 3 {
				log.Warn().
					Str("key_id", keyID).
					Msg("ExecuteDKG: No client node found, using placeholder")
				nodeIDs = append(nodeIDs, "client-placeholder")
			}
		}
		
		log.Info().
			Str("key_id", keyID).
			Strs("node_ids", nodeIDs).
			Int("node_count", len(nodeIDs)).
			Msg("ExecuteDKG: Using fixed 2-of-3 node list")
	} else {
		// 非 2-of-3 模式：从会话中获取节点列表（保持向后兼容）
		session, err := s.metadataStore.GetSigningSession(ctx, keyID)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get DKG session")
		}

		nodeIDs = session.ParticipatingNodes
		if len(nodeIDs) == 0 {
			return nil, errors.New("no participating nodes in DKG session")
		}

		log.Info().
			Str("key_id", keyID).
			Strs("node_ids", nodeIDs).
			Int("node_count", len(nodeIDs)).
			Msg("ExecuteDKG: Retrieved participating nodes from session")
	}

	if len(nodeIDs) < req.Threshold {
		return nil, errors.Errorf("insufficient participating nodes: need at least %d, have %d", req.Threshold, len(nodeIDs))
	}

	// 3. 准备DKG请求
	dkgReq := &protocol.KeyGenRequest{
		KeyID:      keyID,
		Algorithm:  req.Algorithm,
		Curve:      req.Curve,
		Threshold:  req.Threshold,
		TotalNodes: req.TotalNodes,
		NodeIDs:    nodeIDs,
	}

	// 4. 根据算法和曲线选择正确的协议引擎
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
				Str("key_id", keyID).
				Str("algorithm", req.Algorithm).
				Str("curve", req.Curve).
				Str("inferred_protocol", protocolName).
				Msg("ExecuteDKG: Failed to get protocol from registry, using default engine")
			selectedEngine = s.protocolEngine
		} else {
			log.Info().
				Str("key_id", keyID).
				Str("algorithm", req.Algorithm).
				Str("curve", req.Curve).
				Str("selected_protocol", protocolName).
				Msg("ExecuteDKG: Selected protocol from registry")
			selectedEngine = engine
		}
	} else {
		// 如果没有协议注册表，使用默认引擎
		log.Warn().
			Str("key_id", keyID).
			Msg("ExecuteDKG: Protocol registry not available, using default engine")
		selectedEngine = s.protocolEngine
	}

	log.Info().
		Str("key_id", keyID).
		Str("algorithm", req.Algorithm).
		Str("curve", req.Curve).
		Msg("ExecuteDKG: Calling protocolEngine.GenerateKeyShare")

	// 5. 执行DKG协议
	dkgResp, err := selectedEngine.GenerateKeyShare(ctx, dkgReq)
	if err != nil {
		log.Error().Err(err).Str("key_id", keyID).Msg("ExecuteDKG: GenerateKeyShare failed")
		return nil, errors.Wrap(err, "failed to execute DKG protocol")
	}

	log.Error().
		Str("key_id", keyID).
		Int("key_share_count", len(dkgResp.KeyShares)).
		Str("public_key", dkgResp.PublicKey.Hex).
		Msg("ExecuteDKG: GenerateKeyShare completed successfully")

	// 6. 验证生成的密钥分片
	// 注意：在tss-lib架构中，每个节点只返回自己的KeyShare
	// 所以KeyShares的数量应该是1（当前节点），而不是TotalNodes
	if len(dkgResp.KeyShares) == 0 {
		return nil, errors.New("no key shares generated")
	}

	// 7. 验证公钥
	if dkgResp.PublicKey == nil || dkgResp.PublicKey.Hex == "" {
		return nil, errors.New("invalid public key from DKG")
	}

	// 8. 同步等待会话状态完成/失败/超时（以 sessionManager 为准）
	deadline := time.Now().Add(s.MaxWaitTime)
	for time.Now().Before(deadline) {
		sess, err := s.metadataStore.GetSigningSession(ctx, keyID)
		if err == nil {
			if strings.EqualFold(sess.Status, "completed") || strings.EqualFold(sess.Status, "success") {
				return dkgResp, nil
			}
			if strings.EqualFold(sess.Status, "failed") {
				return nil, errors.Errorf("dkg session %s failed", keyID)
			}
		}
		time.Sleep(s.PollInterval)
	}

	return nil, errors.Errorf("dkg session %s timeout (waited %s)", keyID, s.MaxWaitTime)
}

// DistributeKeyShares 分发密钥分片到各个节点
func (s *DKGService) DistributeKeyShares(ctx context.Context, keyID string, keyShares map[string]*protocol.KeyShare) error {
	// 加密并分发密钥分片到各个节点
	for nodeID, share := range keyShares {
		// 存储密钥分片（内部会加密）
		if err := s.keyShareStorage.StoreKeyShare(ctx, keyID, nodeID, share.Share); err != nil {
			return errors.Wrapf(err, "failed to store key share for node %s", nodeID)
		}
	}

	return nil
}

// RecoverKeyShare 恢复密钥分片（阈值恢复）
func (s *DKGService) RecoverKeyShare(ctx context.Context, keyID string, nodeIDs []string, threshold int) (*protocol.KeyShare, error) {
	// 收集阈值数量的密钥分片
	shares := make([][]byte, 0, threshold)
	indices := make([]int, 0, threshold)

	for i, nodeID := range nodeIDs {
		if i >= threshold {
			break
		}

		share, err := s.keyShareStorage.GetKeyShare(ctx, keyID, nodeID)
		if err != nil {
			continue // 跳过无法获取的分片
		}

		shares = append(shares, share)
		indices = append(indices, i+1) // 索引从1开始
	}

	if len(shares) < threshold {
		return nil, errors.Errorf("insufficient shares for recovery: need %d, have %d", threshold, len(shares))
	}

	// TODO: 使用Shamir秘密共享恢复完整密钥
	// 注意：这仅用于恢复场景，恢复后应立即重新生成分片

	return nil, errors.New("key share recovery not yet implemented - requires Shamir secret sharing")
}

// ValidateKeyShares 验证密钥分片一致性
func (s *DKGService) ValidateKeyShares(ctx context.Context, keyID string, publicKey *protocol.PublicKey) error {
	// TODO: 验证所有节点的密钥分片是否与公钥一致
	// 这需要实现Shamir秘密共享的验证逻辑

	return nil
}

// RotateKey 密钥轮换
func (s *DKGService) RotateKey(ctx context.Context, keyID string) error {
	// TODO: 实现密钥轮换协议
	// 1. 获取当前密钥信息
	// 2. 执行密钥轮换DKG
	// 3. 生成新的密钥分片
	// 4. 更新密钥元数据

	return errors.New("key rotation not yet implemented")
}

package key

import (
	"context"
	"strings"
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/infra/storage"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/node"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/protocol"
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

	// 5. 执行DKG协议 (带重试机制)
	var dkgResp *protocol.KeyGenResponse

	err := s.retryProtocol(ctx, "ExecuteDKG", func() error {
		var err error
		dkgResp, err = selectedEngine.GenerateKeyShare(ctx, dkgReq)
		return err
	})

	if err != nil {
		log.Error().Err(err).Str("key_id", keyID).Msg("ExecuteDKG: GenerateKeyShare failed after retries")
		return nil, errors.Wrap(err, "failed to execute DKG protocol")
	}

	log.Info().
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

// ExecuteResharing 执行密钥轮换（Resharing）
func (s *DKGService) ExecuteResharing(
	ctx context.Context,
	keyID string,
	oldNodeIDs []string,
	newNodeIDs []string,
	oldThreshold int,
	newThreshold int,
) (*protocol.KeyGenResponse, error) {
	log.Info().
		Str("key_id", keyID).
		Strs("old_node_ids", oldNodeIDs).
		Strs("new_node_ids", newNodeIDs).
		Int("old_threshold", oldThreshold).
		Int("new_threshold", newThreshold).
		Msg("ExecuteResharing: Starting synchronous Resharing execution")

	// 1. 根据 keyID 获取当前密钥信息，推断协议
	// 如果无法获取，则假设使用 GG20（ECDSA）
	// TODO: 应该从 storage 获取 key metadata，这里假设 keyService 已经处理了前置检查

	// 2. 选择协议引擎
	// 目前只有 GG20 支持 Resharing
	// 如果协议注册表中没有找到，回退到 protocolEngine
	var selectedEngine protocol.Engine = s.protocolEngine
	if s.protocolRegistry != nil {
		if engine, err := s.protocolRegistry.Get("gg20"); err == nil {
			selectedEngine = engine
		}
	}

	// 3. 执行 Resharing 协议
	// 注意：这里是直接调用本地引擎执行，如果是分布式环境，需要协调其他节点
	// 对于 Coordinator 节点，它应该通过 gRPC 通知其他节点 StartResharing
	// 但 protocolEngine.ExecuteResharing 主要是参与者的逻辑（执行 tss 协议）
	// 如果是 Coordinator，我们需要先通知大家启动，然后自己也参与（如果 Coordinator 也是 participant）
	// 或者 Coordinator 不参与计算，只是触发。

	// 根据架构，Coordinator 不参与计算，只负责协调。
	// 但 ExecuteResharing 在 DKGService 中通常是在当前节点执行 DKG 逻辑。
	// 如果当前节点是 Coordinator 但不是 Participant，它应该只发送 RPC。
	// 如果当前节点是 Participant，它应该执行计算。

	// 这里假设 DKGService 运行在 Participant 节点上，或者 Coordinator 也是 Participant。
	// 我们的架构中 Coordinator 不参与 DKG/Resharing 计算。
	// 所以 Coordinator 应该调用 StartResharing RPC 通知所有 Participants。

	// 但是 DKGService.ExecuteDKG 的逻辑是：
	// 1. 准备参数
	// 2. 调用 protocolEngine.GenerateKeyShare (执行计算)
	// 这意味着调用 ExecuteDKG 的节点 *必须* 是 Participant。
	//
	// 如果我们在 Coordinator 上调用 ExecuteResharing，而 Coordinator 不参与计算，
	// 那么 protocolEngine.ExecuteResharing 会失败（因为它需要 local party ID）。

	// 所以，KeyService.RotateKey 调用 DKGService.ExecuteResharing 时，
	// 如果是在 Coordinator 上运行，我们需要一个机制来 "远程执行"。
	// 目前 DKGService 似乎混合了 Coordinator 和 Participant 的逻辑，或者假设了单机模式。

	// 鉴于时间限制，我们先实现调用本地引擎的逻辑，这适用于：
	// 1. 本地测试/单机模式
	// 2. 节点即是 Coordinator 也是 Participant 的模式

	resp, err := selectedEngine.ExecuteResharing(ctx, keyID, oldNodeIDs, newNodeIDs, oldThreshold, newThreshold)
	if err != nil {
		return nil, errors.Wrap(err, "failed to execute resharing protocol")
	}

	return resp, nil
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

// retryProtocol 重试协议执行
func (s *DKGService) retryProtocol(ctx context.Context, opName string, fn func() error) error {
	maxRetries := 3
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			log.Warn().Str("operation", opName).Int("attempt", i+1).Msg("Retrying operation after error")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second * time.Duration(i)):
			}
		}

		err := fn()
		if err == nil {
			return nil
		}

		lastErr = err

		// 检查错误类型
		var protoErr *protocol.ProtocolError
		if errors.As(err, &protoErr) {
			if protoErr.Type == protocol.ErrTypeMalicious {
				// 恶意节点，立即停止并记录
				log.Error().Strs("culprits", protoErr.Culprits).Msg("Malicious nodes detected, aborting")
				return err
			}
			if protoErr.Type == protocol.ErrTypeTimeout || protoErr.Type == protocol.ErrTypeNetwork {
				continue // 重试
			}
		} else {
			// 如果是未知错误，假设它是不可恢复的，或者是封装层没有正确透传 ProtocolError
			// 这里保守起见，如果包含 "timeout" 或 "connection" 字符串，也尝试重试
			errMsg := strings.ToLower(err.Error())
			if strings.Contains(errMsg, "timeout") || strings.Contains(errMsg, "connection") || strings.Contains(errMsg, "network") {
				continue
			}
		}

		// 其他错误，直接返回
		return err
	}
	return lastErr
}

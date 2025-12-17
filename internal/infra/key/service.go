package key

import (
	"context"
	"encoding/hex"
	"math/big"
	"strings"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/google/uuid"
	"github.com/kashguard/go-mpc-wallet/internal/infra/backup"
	"github.com/kashguard/go-mpc-wallet/internal/infra/storage"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/chain"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/protocol"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// Service 密钥服务
type Service struct {
	metadataStore     storage.MetadataStore
	keyShareStorage   storage.KeyShareStorage
	protocolEngine    protocol.Engine
	dkgService        *DKGService
	backupService     backup.SSSBackupService
	derivationService *DerivationService
}

// NewService 创建密钥服务
func NewService(
	metadataStore storage.MetadataStore,
	keyShareStorage storage.KeyShareStorage,
	protocolEngine protocol.Engine,
	dkgService *DKGService,
	backupService backup.SSSBackupService,
) *Service {
	return &Service{
		metadataStore:     metadataStore,
		keyShareStorage:   keyShareStorage,
		protocolEngine:    protocolEngine,
		dkgService:        dkgService,
		backupService:     backupService,
		derivationService: NewDerivationService(),
	}
}

// GetKey 获取密钥信息
func (s *Service) GetKey(ctx context.Context, keyID string) (*KeyMetadata, error) {
	storageKey, err := s.metadataStore.GetKeyMetadata(ctx, keyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get key metadata")
	}

	keyMetadata := &KeyMetadata{
		KeyID:        storageKey.KeyID,
		PublicKey:    storageKey.PublicKey,
		Algorithm:    storageKey.Algorithm,
		Curve:        storageKey.Curve,
		Threshold:    storageKey.Threshold,
		TotalNodes:   storageKey.TotalNodes,
		ChainType:    storageKey.ChainType,
		Address:      storageKey.Address,
		Status:       storageKey.Status,
		Description:  storageKey.Description,
		Tags:         storageKey.Tags,
		CreatedAt:    storageKey.CreatedAt,
		UpdatedAt:    storageKey.UpdatedAt,
		DeletionDate: storageKey.DeletionDate,
	}

	return keyMetadata, nil
}

// DeleteKey 删除密钥
func (s *Service) DeleteKey(ctx context.Context, keyID string) error {
	// 获取密钥信息
	key, err := s.GetKey(ctx, keyID)
	if err != nil {
		return errors.Wrap(err, "failed to get key")
	}

	// 删除所有节点的密钥分片
	// TODO: 从节点管理器获取所有节点ID
	nodeIDs := []string{} // 需要实现
	for _, nodeID := range nodeIDs {
		if err := s.keyShareStorage.DeleteKeyShare(ctx, keyID, nodeID); err != nil {
			// 记录错误但继续删除其他分片
			// log error
		}
	}

	// 更新密钥状态为删除
	now := time.Now()
	key.Status = "Deleted"
	key.DeletionDate = &now
	key.UpdatedAt = now

	storageKey := &storage.KeyMetadata{
		KeyID:        key.KeyID,
		PublicKey:    key.PublicKey,
		Algorithm:    key.Algorithm,
		Curve:        key.Curve,
		Threshold:    key.Threshold,
		TotalNodes:   key.TotalNodes,
		ChainType:    key.ChainType,
		Address:      key.Address,
		Status:       key.Status,
		Description:  key.Description,
		Tags:         key.Tags,
		CreatedAt:    key.CreatedAt,
		UpdatedAt:    key.UpdatedAt,
		DeletionDate: key.DeletionDate,
	}

	if err := s.metadataStore.UpdateKeyMetadata(ctx, storageKey); err != nil {
		return errors.Wrap(err, "failed to update key status")
	}

	return nil
}

// ListKeys 列出密钥
func (s *Service) ListKeys(ctx context.Context, filter *KeyFilter) ([]*KeyMetadata, error) {
	storageFilter := &storage.KeyFilter{
		ChainType: filter.ChainType,
		Status:    filter.Status,
		TagKey:    filter.TagKey,
		TagValue:  filter.TagValue,
		Limit:     filter.Limit,
		Offset:    filter.Offset,
	}

	storageKeys, err := s.metadataStore.ListKeys(ctx, storageFilter)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list keys")
	}

	keys := make([]*KeyMetadata, len(storageKeys))
	for i, storageKey := range storageKeys {
		keys[i] = &KeyMetadata{
			KeyID:        storageKey.KeyID,
			PublicKey:    storageKey.PublicKey,
			Algorithm:    storageKey.Algorithm,
			Curve:        storageKey.Curve,
			Threshold:    storageKey.Threshold,
			TotalNodes:   storageKey.TotalNodes,
			ChainType:    storageKey.ChainType,
			Address:      storageKey.Address,
			Status:       storageKey.Status,
			Description:  storageKey.Description,
			Tags:         storageKey.Tags,
			CreatedAt:    storageKey.CreatedAt,
			UpdatedAt:    storageKey.UpdatedAt,
			DeletionDate: storageKey.DeletionDate,
		}
	}

	return keys, nil
}

// GenerateAddress 生成区块链地址
func (s *Service) GenerateAddress(ctx context.Context, keyID string, chainType string) (string, error) {
	// 获取密钥信息
	keyMetadata, err := s.GetKey(ctx, keyID)
	if err != nil {
		return "", errors.Wrap(err, "failed to get key")
	}

	// 如果地址已存在且链类型匹配，直接返回
	if keyMetadata.Address != "" && keyMetadata.ChainType == chainType {
		return keyMetadata.Address, nil
	}

	// 解析公钥
	pubKeyBytes, err := hex.DecodeString(keyMetadata.PublicKey)
	if err != nil {
		return "", errors.Wrap(err, "failed to decode public key")
	}

	// 根据链类型选择适配器
	var adapter chain.Adapter
	switch chainType {
	case "bitcoin", "btc":
		adapter = chain.NewBitcoinAdapter(&chaincfg.MainNetParams)
	case "ethereum", "eth", "evm":
		adapter = chain.NewEthereumAdapter(big.NewInt(1)) // mainnet
	default:
		return "", errors.Errorf("unsupported chain type: %s", chainType)
	}

	// 生成地址
	address, err := adapter.GenerateAddress(pubKeyBytes)
	if err != nil {
		return "", errors.Wrap(err, "failed to generate address")
	}

	// 更新密钥元数据中的地址
	now := time.Now()
	keyMetadata.Address = address
	keyMetadata.UpdatedAt = now

	storageKey := &storage.KeyMetadata{
		KeyID:        keyMetadata.KeyID,
		PublicKey:    keyMetadata.PublicKey,
		Algorithm:    keyMetadata.Algorithm,
		Curve:        keyMetadata.Curve,
		Threshold:    keyMetadata.Threshold,
		TotalNodes:   keyMetadata.TotalNodes,
		ChainType:    keyMetadata.ChainType,
		Address:      keyMetadata.Address,
		Status:       keyMetadata.Status,
		Description:  keyMetadata.Description,
		Tags:         keyMetadata.Tags,
		CreatedAt:    keyMetadata.CreatedAt,
		UpdatedAt:    keyMetadata.UpdatedAt,
		DeletionDate: keyMetadata.DeletionDate,
	}

	if err := s.metadataStore.UpdateKeyMetadata(ctx, storageKey); err != nil {
		return "", errors.Wrap(err, "failed to update key metadata with address")
	}

	return address, nil
}

// CreateRootKey 创建根密钥（执行DKG，2-of-3模式）
func (s *Service) CreateRootKey(ctx context.Context, req *CreateRootKeyRequest) (*RootKeyMetadata, error) {
	// 生成密钥ID（如果请求中未提供）
	keyID := req.KeyID
	if keyID == "" {
		keyID = "root-key-" + uuid.New().String()
	}

	// 设置默认值
	threshold := req.Threshold
	if threshold == 0 {
		threshold = 2 // 默认 2-of-3
	}
	totalNodes := req.TotalNodes
	if totalNodes == 0 {
		totalNodes = 3 // 默认 3 个节点
	}

	// 构建 CreateKeyRequest（用于 DKG）
	dkgReq := &CreateKeyRequest{
		KeyID:       keyID,
		Algorithm:   req.Algorithm,
		Curve:       req.Curve,
		Threshold:   threshold,
		TotalNodes:  totalNodes,
		UserID:      req.UserID,
		Description: req.Description,
		Tags:        req.Tags,
	}

	// 执行 DKG
	var dkgResp *protocol.KeyGenResponse
	var err error
	if s.dkgService != nil {
		dkgResp, err = s.dkgService.ExecuteDKG(ctx, keyID, dkgReq)
		if err != nil {
			return nil, errors.Wrap(err, "failed to execute DKG")
		}
	} else {
		return nil, errors.New("DKG service is required for root key creation")
	}

	// 存储密钥分片（只存储服务器节点的分片，客户端分片不存储）
	for nodeID, share := range dkgResp.KeyShares {
		// 只存储服务器节点（server-proxy-1, server-proxy-2）的分片
		// 客户端节点（client-{userID}）的分片不存储在服务器端
		if strings.HasPrefix(nodeID, "server-") {
			if err := s.keyShareStorage.StoreKeyShare(ctx, keyID, nodeID, share.Share); err != nil {
				return nil, errors.Wrapf(err, "failed to store key share for node %s", nodeID)
			}
		}
		// 客户端分片：不存储在服务器端，依赖 SSS 备份分片
	}

	// 保存根密钥元数据
	now := time.Now()

	// 生成随机 ChainCode
	chainCode, err := s.derivationService.GenerateRandomChainCode()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate chain code for root key")
	}
	chainCodeHex := hex.EncodeToString(chainCode)

	rootKeyMetadata := &RootKeyMetadata{
		KeyID:       keyID,
		PublicKey:   dkgResp.PublicKey.Hex,
		Algorithm:   req.Algorithm,
		Curve:       req.Curve,
		ChainCode:   chainCodeHex,
		Threshold:   threshold,
		TotalNodes:  totalNodes,
		Protocol:    req.Protocol,
		Status:      "Active",
		Description: req.Description,
		Tags:        req.Tags,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// 使用现有的 KeyMetadata 存储（暂时复用，后续可以分离）
	storageKey := &storage.KeyMetadata{
		KeyID:        rootKeyMetadata.KeyID,
		PublicKey:    rootKeyMetadata.PublicKey,
		Algorithm:    rootKeyMetadata.Algorithm,
		Curve:        rootKeyMetadata.Curve,
		ChainCode:    rootKeyMetadata.ChainCode,
		Threshold:    rootKeyMetadata.Threshold,
		TotalNodes:   rootKeyMetadata.TotalNodes,
		ChainType:    "", // 根密钥没有链类型
		Address:      "",
		Status:       rootKeyMetadata.Status,
		Description:  rootKeyMetadata.Description,
		Tags:         rootKeyMetadata.Tags,
		CreatedAt:    rootKeyMetadata.CreatedAt,
		UpdatedAt:    rootKeyMetadata.UpdatedAt,
		DeletionDate: rootKeyMetadata.DeletionDate,
	}

	if err := s.metadataStore.SaveKeyMetadata(ctx, storageKey); err != nil {
		return nil, errors.Wrap(err, "failed to save root key metadata")
	}

	// 集成 SSS 备份服务：对每个 MPC 分片分别进行 SSS 备份
	if s.backupService != nil {
		backupStorage, ok := s.metadataStore.(storage.BackupShareStorage)
		if !ok {
			log.Warn().Msg("MetadataStore does not implement BackupShareStorage, skipping SSS backup")
		} else {
			for nodeID, mpcShare := range dkgResp.KeyShares {
				// 对单个MPC分片进行SSS备份（不是完整密钥）
				backupShares, err := s.backupService.GenerateBackupShares(ctx, mpcShare.Share, 3, 5)
				if err != nil {
					log.Error().
						Err(err).
						Str("key_id", keyID).
						Str("node_id", nodeID).
						Msg("Failed to generate backup shares for MPC share")
					// 继续处理其他分片，不中断流程
					continue
				}

				// 存储备份分片
				for i, backupShare := range backupShares {
					shareIndex := i + 1

					// 保存备份分片到存储
					if err := backupStorage.SaveBackupShare(ctx, keyID, nodeID, shareIndex, backupShare.ShareData); err != nil {
						log.Error().
							Err(err).
							Str("key_id", keyID).
							Str("node_id", nodeID).
							Int("share_index", shareIndex).
							Msg("Failed to save backup share")
						// 继续处理其他备份分片
						continue
					}

					// 如果是客户端分片或需要下发的服务器分片，调用下发接口
					if (strings.HasPrefix(nodeID, "client-") && shareIndex == 1) ||
						(strings.HasPrefix(nodeID, "server-") && shareIndex == 3) {
						// 下发备份分片到客户端
						if err := s.backupService.DeliverBackupShareToClient(ctx, keyID, req.UserID, nodeID, shareIndex, backupShare); err != nil {
							log.Warn().
								Err(err).
								Str("key_id", keyID).
								Str("node_id", nodeID).
								Int("share_index", shareIndex).
								Msg("Failed to deliver backup share to client (non-critical)")
							// 下发失败不影响主流程，只记录警告
						} else {
							log.Info().
								Str("key_id", keyID).
								Str("node_id", nodeID).
								Int("share_index", shareIndex).
								Msg("Backup share delivered to client")
						}
					}
				}
			}
		}
	}

	return rootKeyMetadata, nil
}

// GetRootKey 获取根密钥信息
func (s *Service) GetRootKey(ctx context.Context, keyID string) (*RootKeyMetadata, error) {
	storageKey, err := s.metadataStore.GetKeyMetadata(ctx, keyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get root key metadata")
	}

	rootKeyMetadata := &RootKeyMetadata{
		KeyID:        storageKey.KeyID,
		PublicKey:    storageKey.PublicKey,
		Algorithm:    storageKey.Algorithm,
		Curve:        storageKey.Curve,
		ChainCode:    storageKey.ChainCode,
		Threshold:    storageKey.Threshold,
		TotalNodes:   storageKey.TotalNodes,
		Protocol:     "", // TODO: 从存储中读取协议信息
		Status:       storageKey.Status,
		Description:  storageKey.Description,
		Tags:         storageKey.Tags,
		CreatedAt:    storageKey.CreatedAt,
		UpdatedAt:    storageKey.UpdatedAt,
		DeletionDate: storageKey.DeletionDate,
	}

	return rootKeyMetadata, nil
}

// DeleteRootKey 删除根密钥
func (s *Service) DeleteRootKey(ctx context.Context, keyID string) error {
	// 获取根密钥信息
	rootKey, err := s.GetRootKey(ctx, keyID)
	if err != nil {
		return errors.Wrap(err, "failed to get root key")
	}

	// 删除所有节点的密钥分片
	// TODO: 从节点管理器获取所有节点ID
	nodeIDs := []string{"server-proxy-1", "server-proxy-2"}
	for _, nodeID := range nodeIDs {
		if err := s.keyShareStorage.DeleteKeyShare(ctx, keyID, nodeID); err != nil {
			// 记录错误但继续删除其他分片
			log.Warn().Err(err).Str("key_id", keyID).Str("node_id", nodeID).Msg("Failed to delete key share")
		}
	}

	// 更新密钥状态为删除
	now := time.Now()
	rootKey.Status = "Deleted"
	rootKey.DeletionDate = &now
	rootKey.UpdatedAt = now

	storageKey := &storage.KeyMetadata{
		KeyID:        rootKey.KeyID,
		PublicKey:    rootKey.PublicKey,
		Algorithm:    rootKey.Algorithm,
		Curve:        rootKey.Curve,
		Threshold:    rootKey.Threshold,
		TotalNodes:   rootKey.TotalNodes,
		ChainType:    "",
		Address:      "",
		Status:       rootKey.Status,
		Description:  rootKey.Description,
		Tags:         rootKey.Tags,
		CreatedAt:    rootKey.CreatedAt,
		UpdatedAt:    rootKey.UpdatedAt,
		DeletionDate: rootKey.DeletionDate,
	}

	if err := s.metadataStore.UpdateKeyMetadata(ctx, storageKey); err != nil {
		return errors.Wrap(err, "failed to update root key status")
	}

	return nil
}

// DeriveWalletKey 派生钱包密钥（Non-Hardened Derivation based on BIP-32）
func (s *Service) DeriveWalletKey(ctx context.Context, req *DeriveWalletKeyRequest) (*WalletKeyMetadata, error) {
	// 获取根密钥
	rootKey, err := s.GetRootKey(ctx, req.RootKeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get root key")
	}

	// 检查并生成 ChainCode（如果是旧数据可能缺失）
	chainCodeHex := rootKey.ChainCode
	if chainCodeHex == "" {
		if rootKey.Curve == "secp256k1" {
			log.Info().Str("key_id", rootKey.KeyID).Msg("Migrating root key: generating missing chain code")
			chainCode, err := s.derivationService.GenerateRandomChainCode()
			if err != nil {
				return nil, errors.Wrap(err, "failed to generate chain code")
			}
			chainCodeHex = hex.EncodeToString(chainCode)

			// 更新 DB
			// 需要构造完整的 storage.KeyMetadata 以避免覆盖其他字段
			storageKey, err := s.metadataStore.GetKeyMetadata(ctx, rootKey.KeyID)
			if err != nil {
				return nil, errors.Wrap(err, "failed to get raw key metadata for update")
			}
			storageKey.ChainCode = chainCodeHex
			storageKey.UpdatedAt = time.Now()

			if err := s.metadataStore.UpdateKeyMetadata(ctx, storageKey); err != nil {
				return nil, errors.Wrap(err, "failed to update root key with chain code")
			}
			rootKey.ChainCode = chainCodeHex
		} else {
			// 其他曲线可能不需要或者我们暂不支持自动生成
			log.Warn().Str("curve", rootKey.Curve).Msg("Root key missing chain code but curve is not secp256k1, skipping generation")
		}
	}

	// 解析根密钥的公钥
	pubKeyBytes, err := hex.DecodeString(rootKey.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode root key public key")
	}

	// 解析 ChainCode
	chainCodeBytes, err := hex.DecodeString(chainCodeHex)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode chain code")
	}

	// 执行派生
	deriveReq := &DeriveChildKeyRequest{
		ParentPubKey:    pubKeyBytes,
		ParentChainCode: chainCodeBytes,
		Curve:           rootKey.Curve,
		Index:           req.Index,
	}

	result, err := s.derivationService.DeriveChildKey(deriveReq)
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive child key")
	}

	walletPubKey := result.PublicKey

	// 生成地址
	var adapter chain.Adapter
	switch req.ChainType {
	case "bitcoin", "btc":
		adapter = chain.NewBitcoinAdapter(&chaincfg.MainNetParams)
	case "ethereum", "eth", "evm":
		adapter = chain.NewEthereumAdapter(big.NewInt(1)) // mainnet
	default:
		return nil, errors.Errorf("unsupported chain type: %s", req.ChainType)
	}

	address, err := adapter.GenerateAddress(walletPubKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate wallet address")
	}

	// 生成钱包ID
	walletID := "wallet-" + uuid.New().String()
	now := time.Now()

	walletMetadata := &WalletKeyMetadata{
		WalletID:    walletID,
		RootKeyID:   req.RootKeyID,
		ChainType:   req.ChainType,
		Index:       req.Index,
		PublicKey:   hex.EncodeToString(walletPubKey),
		ChainCode:   hex.EncodeToString(result.ChainCode),
		Address:     address,
		Status:      "Active",
		Description: req.Description,
		Tags:        req.Tags,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// 保存到数据库
	if walletMetadata.Tags == nil {
		walletMetadata.Tags = make(map[string]string)
	}
	// Record derivation info
	walletMetadata.Tags["parent_key_id"] = req.RootKeyID
	walletMetadata.Tags["derivation_index"] = big.NewInt(int64(req.Index)).String()

	storageKey := &storage.KeyMetadata{
		KeyID:       walletMetadata.WalletID,
		PublicKey:   walletMetadata.PublicKey,
		Algorithm:   rootKey.Algorithm,                    // 继承算法
		Curve:       rootKey.Curve,                        // 继承曲线
		ChainCode:   hex.EncodeToString(result.ChainCode), // 保存子 ChainCode
		Threshold:   rootKey.Threshold,
		TotalNodes:  rootKey.TotalNodes,
		ChainType:   walletMetadata.ChainType,
		Address:     walletMetadata.Address,
		Status:      walletMetadata.Status,
		Description: walletMetadata.Description,
		Tags:        walletMetadata.Tags,
		CreatedAt:   walletMetadata.CreatedAt,
		UpdatedAt:   walletMetadata.UpdatedAt,
	}

	if err := s.metadataStore.SaveKeyMetadata(ctx, storageKey); err != nil {
		return nil, errors.Wrap(err, "failed to save wallet key metadata")
	}

	return walletMetadata, nil
}

// RotateKey 密钥轮换（Resharing）
func (s *Service) RotateKey(ctx context.Context, keyID string, oldNodeIDs []string, newNodeIDs []string, oldThreshold int, newThreshold int) (*KeyMetadata, error) {
	// 1. 获取密钥元数据
	key, err := s.GetKey(ctx, keyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get key metadata")
	}

	// 2. 验证参数
	if oldThreshold == 0 {
		oldThreshold = key.Threshold
	}
	if newThreshold == 0 {
		newThreshold = key.Threshold // 默认不改变阈值
	}

	// 3. 执行 Resharing (需要 Coordinator 协调，这里假设通过 DKGService 或类似机制)
	// TODO: 实现 ResharingService 类似于 DKGService
	// 目前我们假设 DKGService 扩展了 ExecuteResharing 方法
	// 或者直接调用 protocolEngine.ExecuteResharing (如果是在参与者节点上)
	// 但这里是 KeyService，通常运行在 Coordinator 或 Server 上

	// 如果有 DKGService，使用它来协调 Resharing
	if s.dkgService != nil {
		// 使用 DKGService 执行 Resharing
		resp, err := s.dkgService.ExecuteResharing(ctx, keyID, oldNodeIDs, newNodeIDs, oldThreshold, newThreshold)
		if err != nil {
			return nil, errors.Wrap(err, "failed to execute resharing via DKGService")
		}

		// 4. 更新存储 (如果 DKGService 返回了 KeyShares，说明本节点参与了计算)
		// 注意：如果本节点是 Coordinator 但不是 Participant，KeyShares 可能为空
		if len(resp.KeyShares) > 0 {
			for nodeID, share := range resp.KeyShares {
				if err := s.keyShareStorage.StoreKeyShare(ctx, keyID, nodeID, share.Share); err != nil {
					return nil, errors.Wrapf(err, "failed to store new key share for node %s", nodeID)
				}
			}
		}

		// 5. 更新元数据
		key.Threshold = newThreshold
		key.TotalNodes = len(newNodeIDs)
		key.UpdatedAt = time.Now()
		// PublicKey 应该保持不变
		if resp.PublicKey != nil && resp.PublicKey.Hex != key.PublicKey {
			log.Warn().Str("old_pub", key.PublicKey).Str("new_pub", resp.PublicKey.Hex).Msg("Resharing resulted in different public key (unexpected!)")
		}

		storageKey := &storage.KeyMetadata{
			KeyID:        key.KeyID,
			PublicKey:    key.PublicKey,
			Algorithm:    key.Algorithm,
			Curve:        key.Curve,
			Threshold:    key.Threshold,
			TotalNodes:   key.TotalNodes,
			ChainType:    key.ChainType,
			Address:      key.Address,
			Status:       key.Status,
			Description:  key.Description,
			Tags:         key.Tags,
			CreatedAt:    key.CreatedAt,
			UpdatedAt:    key.UpdatedAt,
			DeletionDate: key.DeletionDate,
		}

		if err := s.metadataStore.UpdateKeyMetadata(ctx, storageKey); err != nil {
			return nil, errors.Wrap(err, "failed to update key metadata")
		}

		return key, nil
	}

	// 如果没有 DKGService，尝试直接使用 ProtocolEngine (单机或测试模式)
	// 需要检查 ProtocolEngine 是否支持 Resharing
	resharer, ok := s.protocolEngine.(interface {
		ExecuteResharing(ctx context.Context, keyID string, oldNodeIDs []string, newNodeIDs []string, oldThreshold int, newThreshold int) (*protocol.KeyGenResponse, error)
	})
	if !ok {
		return nil, errors.New("ProtocolEngine does not support Resharing")
	}

	resp, err := resharer.ExecuteResharing(ctx, keyID, oldNodeIDs, newNodeIDs, oldThreshold, newThreshold)
	if err != nil {
		return nil, errors.Wrap(err, "failed to execute resharing")
	}

	// 4. 更新存储
	// 存储新分片
	for nodeID, share := range resp.KeyShares {
		if err := s.keyShareStorage.StoreKeyShare(ctx, keyID, nodeID, share.Share); err != nil {
			return nil, errors.Wrapf(err, "failed to store new key share for node %s", nodeID)
		}
	}

	// 5. 更新元数据
	key.Threshold = newThreshold
	key.TotalNodes = len(newNodeIDs)
	key.UpdatedAt = time.Now()
	// PublicKey 应该保持不变，但可以校验一下
	if resp.PublicKey.Hex != key.PublicKey {
		log.Warn().Str("old_pub", key.PublicKey).Str("new_pub", resp.PublicKey.Hex).Msg("Resharing resulted in different public key (unexpected!)")
	}

	storageKey := &storage.KeyMetadata{
		KeyID:        key.KeyID,
		PublicKey:    key.PublicKey,
		Algorithm:    key.Algorithm,
		Curve:        key.Curve,
		Threshold:    key.Threshold,
		TotalNodes:   key.TotalNodes,
		ChainType:    key.ChainType,
		Address:      key.Address,
		Status:       key.Status,
		Description:  key.Description,
		Tags:         key.Tags,
		CreatedAt:    key.CreatedAt,
		UpdatedAt:    key.UpdatedAt,
		DeletionDate: key.DeletionDate,
	}

	if err := s.metadataStore.UpdateKeyMetadata(ctx, storageKey); err != nil {
		return nil, errors.Wrap(err, "failed to update key metadata")
	}

	return key, nil
}

// DeriveWalletKeyByPath 派生钱包密钥（支持路径）
func (s *Service) DeriveWalletKeyByPath(ctx context.Context, req *DeriveWalletKeyByPathRequest) (*WalletKeyMetadata, error) {
	// 获取根密钥
	rootKey, err := s.GetRootKey(ctx, req.RootKeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get root key")
	}

	// 检查并生成 ChainCode（如果是旧数据可能缺失）
	chainCodeHex := rootKey.ChainCode
	if chainCodeHex == "" {
		if rootKey.Curve == "secp256k1" || rootKey.Curve == "ed25519" {
			log.Info().Str("key_id", rootKey.KeyID).Msg("Migrating root key: generating missing chain code")
			chainCode, err := s.derivationService.GenerateRandomChainCode()
			if err != nil {
				return nil, errors.Wrap(err, "failed to generate chain code")
			}
			chainCodeHex = hex.EncodeToString(chainCode)

			// 更新 DB
			storageKey, err := s.metadataStore.GetKeyMetadata(ctx, rootKey.KeyID)
			if err != nil {
				return nil, errors.Wrap(err, "failed to get raw key metadata for update")
			}
			storageKey.ChainCode = chainCodeHex
			storageKey.UpdatedAt = time.Now()

			if err := s.metadataStore.UpdateKeyMetadata(ctx, storageKey); err != nil {
				return nil, errors.Wrap(err, "failed to update root key with chain code")
			}
			rootKey.ChainCode = chainCodeHex
		} else {
			log.Warn().Str("curve", rootKey.Curve).Msg("Root key missing chain code but curve is not supported for auto-generation, skipping")
		}
	}

	// 解析根密钥的公钥
	pubKeyBytes, err := hex.DecodeString(rootKey.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode root key public key")
	}

	// 解析 ChainCode
	chainCodeBytes, err := hex.DecodeString(chainCodeHex)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode chain code")
	}

	// 执行路径派生
	result, err := s.derivationService.DerivePublicKeyFromPath(pubKeyBytes, chainCodeBytes, rootKey.Curve, req.Path)
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive key from path")
	}

	walletPubKey := result.PublicKey

	// 生成地址
	var adapter chain.Adapter
	switch req.ChainType {
	case "bitcoin", "btc":
		adapter = chain.NewBitcoinAdapter(&chaincfg.MainNetParams)
	case "ethereum", "eth", "evm":
		adapter = chain.NewEthereumAdapter(big.NewInt(1)) // mainnet
	default:
		// 如果不支持，暂时不生成地址
		log.Warn().Str("chain_type", req.ChainType).Msg("Unsupported chain type for address generation")
	}

	var address string
	if adapter != nil {
		address, err = adapter.GenerateAddress(walletPubKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate wallet address")
		}
	}

	// 生成钱包ID
	walletID := "wallet-" + uuid.New().String()
	now := time.Now()

	walletMetadata := &WalletKeyMetadata{
		WalletID:    walletID,
		RootKeyID:   req.RootKeyID,
		ChainType:   req.ChainType,
		Index:       0, // 路径派生不对应单一索引
		PublicKey:   hex.EncodeToString(walletPubKey),
		ChainCode:   hex.EncodeToString(result.ChainCode),
		Address:     address,
		Status:      "Active",
		Description: req.Description,
		Tags:        req.Tags,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// 保存到数据库
	if walletMetadata.Tags == nil {
		walletMetadata.Tags = make(map[string]string)
	}
	// Record derivation info
	walletMetadata.Tags["parent_key_id"] = req.RootKeyID
	walletMetadata.Tags["derivation_path"] = req.Path

	storageKey := &storage.KeyMetadata{
		KeyID:       walletMetadata.WalletID,
		PublicKey:   walletMetadata.PublicKey,
		Algorithm:   rootKey.Algorithm,                    // 继承算法
		Curve:       rootKey.Curve,                        // 继承曲线
		ChainCode:   hex.EncodeToString(result.ChainCode), // 保存子 ChainCode
		Threshold:   rootKey.Threshold,
		TotalNodes:  rootKey.TotalNodes,
		ChainType:   walletMetadata.ChainType,
		Address:     walletMetadata.Address,
		Status:      walletMetadata.Status,
		Description: walletMetadata.Description,
		Tags:        walletMetadata.Tags,
		CreatedAt:   walletMetadata.CreatedAt,
		UpdatedAt:   walletMetadata.UpdatedAt,
	}

	if err := s.metadataStore.SaveKeyMetadata(ctx, storageKey); err != nil {
		return nil, errors.Wrap(err, "failed to save wallet key metadata")
	}

	return walletMetadata, nil
}

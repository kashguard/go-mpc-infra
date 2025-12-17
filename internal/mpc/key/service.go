package key

import (
	"context"
	"encoding/hex"
	"math/big"
	"strings"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/google/uuid"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/backup"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/chain"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/protocol"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/storage"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// Service 密钥服务
type Service struct {
	metadataStore   storage.MetadataStore
	keyShareStorage storage.KeyShareStorage
	protocolEngine  protocol.Engine
	dkgService      *DKGService
	backupService   backup.SSSBackupService
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

// CreateKey 创建密钥（执行DKG）
func (s *Service) CreateKey(ctx context.Context, req *CreateKeyRequest) (*KeyMetadata, error) {
	// 生成密钥ID（如果请求中未提供）
	keyID := req.KeyID
	if keyID == "" {
		keyID = "key-" + uuid.New().String()
	}

	// 使用DKGService执行DKG（如果可用）
	var dkgResp *protocol.KeyGenResponse
	var err error

	if s.dkgService != nil {
		// 使用DKGService执行DKG（包含节点发现和选择）
		dkgResp, err = s.dkgService.ExecuteDKG(ctx, keyID, req)
		if err != nil {
			return nil, errors.Wrap(err, "failed to execute DKG")
		}
	} else {
		// 如果没有DKGService，直接调用协议引擎（需要外部提供节点列表）
		// 注意：这种情况下nodeIDs应该由调用方提供
		dkgReq := &protocol.KeyGenRequest{
			KeyID:      keyID,
			Algorithm:  req.Algorithm,
			Curve:      req.Curve,
			Threshold:  req.Threshold,
			TotalNodes: req.TotalNodes,
			NodeIDs:    []string{}, // 如果为空，协议引擎会自动生成
		}

		dkgResp, err = s.protocolEngine.GenerateKeyShare(ctx, dkgReq)
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate key shares")
		}
	}

	// 存储密钥分片（只存储当前节点的分片）
	// 注意：在tss-lib架构中，每个节点只保存自己的分片
	for nodeID, share := range dkgResp.KeyShares {
		if err := s.keyShareStorage.StoreKeyShare(ctx, keyID, nodeID, share.Share); err != nil {
			return nil, errors.Wrapf(err, "failed to store key share for node %s", nodeID)
		}
	}

	// 保存密钥元数据
	now := time.Now()
	keyMetadata := &KeyMetadata{
		KeyID:       keyID,
		PublicKey:   dkgResp.PublicKey.Hex,
		Algorithm:   req.Algorithm,
		Curve:       req.Curve,
		Threshold:   req.Threshold,
		TotalNodes:  req.TotalNodes,
		ChainType:   req.ChainType,
		Status:      "Active",
		Description: req.Description,
		Tags:        req.Tags,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

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

	if err := s.metadataStore.SaveKeyMetadata(ctx, storageKey); err != nil {
		return nil, errors.Wrap(err, "failed to save key metadata")
	}

	return keyMetadata, nil
}

// CreatePlaceholderKey 创建占位符密钥（不执行DKG，只创建元数据）
// 用于在DKG会话创建前满足外键约束
func (s *Service) CreatePlaceholderKey(ctx context.Context, req *CreateKeyRequest) (*KeyMetadata, error) {
	keyID := req.KeyID
	if keyID == "" {
		keyID = "key-" + uuid.New().String()
	}

	now := time.Now()
	keyMetadata := &KeyMetadata{
		KeyID:       keyID,
		PublicKey:   "pending", // 占位符值，DKG 完成后更新为真实公钥
		Algorithm:   req.Algorithm,
		Curve:       req.Curve,
		Threshold:   req.Threshold,
		TotalNodes:  req.TotalNodes,
		ChainType:   req.ChainType,
		Status:      "Pending", // 占位符状态
		Description: req.Description,
		Tags:        req.Tags,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	storageKey := &storage.KeyMetadata{
		KeyID:        keyMetadata.KeyID,
		PublicKey:    keyMetadata.PublicKey, // 可以为空字符串，数据库允许
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

	if err := s.metadataStore.SaveKeyMetadata(ctx, storageKey); err != nil {
		log.Error().
			Err(err).
			Str("key_id", keyID).
			Msg("Failed to save placeholder key metadata to database")
		return nil, errors.Wrap(err, "failed to save placeholder key metadata")
	}

	// 立即验证密钥是否真的保存了
	savedKey, err := s.metadataStore.GetKeyMetadata(ctx, keyID)
	if err != nil {
		log.Error().
			Err(err).
			Str("key_id", keyID).
			Msg("Key saved but cannot be retrieved - verification failed")
		return nil, errors.Wrap(err, "key saved but verification failed")
	}

	log.Info().
		Str("key_id", keyID).
		Str("status", savedKey.Status).
		Str("public_key", savedKey.PublicKey).
		Msg("Placeholder key saved and verified successfully")

	return keyMetadata, nil
}

// CreateKeyWithExistingMetadata 在已有占位符密钥的基础上执行DKG并更新密钥
func (s *Service) CreateKeyWithExistingMetadata(ctx context.Context, req *CreateKeyRequest) (*KeyMetadata, error) {
	keyID := req.KeyID
	if keyID == "" {
		return nil, errors.New("keyID is required for CreateKeyWithExistingMetadata")
	}

	log.Error().
		Str("key_id", keyID).
		Str("algorithm", req.Algorithm).
		Str("curve", req.Curve).
		Int("threshold", req.Threshold).
		Int("total_nodes", req.TotalNodes).
		Msg("CreateKeyWithExistingMetadata: Starting DKG execution")

	// 检查密钥是否存在
	existingKey, err := s.metadataStore.GetKeyMetadata(ctx, keyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get existing key metadata")
	}
	if existingKey.Status != "Pending" {
		return nil, errors.Errorf("key %s is not in Pending status", keyID)
	}

	// 执行DKG
	var dkgResp *protocol.KeyGenResponse
	if s.dkgService != nil {
		log.Error().Str("key_id", keyID).Msg("CreateKeyWithExistingMetadata: Calling dkgService.ExecuteDKG")
		dkgResp, err = s.dkgService.ExecuteDKG(ctx, keyID, req)
		if err != nil {
			log.Error().Err(err).Str("key_id", keyID).Msg("CreateKeyWithExistingMetadata: ExecuteDKG failed")
			return nil, errors.Wrap(err, "failed to execute DKG")
		}
		log.Error().Str("key_id", keyID).Msg("CreateKeyWithExistingMetadata: ExecuteDKG completed successfully")
	} else {
		dkgReq := &protocol.KeyGenRequest{
			KeyID:      keyID,
			Algorithm:  req.Algorithm,
			Curve:      req.Curve,
			Threshold:  req.Threshold,
			TotalNodes: req.TotalNodes,
			NodeIDs:    []string{},
		}
		dkgResp, err = s.protocolEngine.GenerateKeyShare(ctx, dkgReq)
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate key shares")
		}
	}

	// 存储密钥分片
	for nodeID, share := range dkgResp.KeyShares {
		if err := s.keyShareStorage.StoreKeyShare(ctx, keyID, nodeID, share.Share); err != nil {
			return nil, errors.Wrapf(err, "failed to store key share for node %s", nodeID)
		}
	}

	// 更新密钥元数据（添加公钥，更新状态为Active）
	now := time.Now()
	storageKey := &storage.KeyMetadata{
		KeyID:        keyID,
		PublicKey:    dkgResp.PublicKey.Hex,
		Algorithm:    req.Algorithm,
		Curve:        req.Curve,
		Threshold:    req.Threshold,
		TotalNodes:   req.TotalNodes,
		ChainType:    req.ChainType,
		Address:      existingKey.Address, // 保持原有地址（如果有）
		Status:       "Active",
		Description:  req.Description,
		Tags:         req.Tags,
		CreatedAt:    existingKey.CreatedAt, // 保持原有创建时间
		UpdatedAt:    now,
		DeletionDate: existingKey.DeletionDate,
	}

	// 生成地址（如果需要）
	if req.ChainType != "" {
		// 解析公钥
		pubKeyBytes, err := hex.DecodeString(dkgResp.PublicKey.Hex)
		if err == nil {
			// 根据链类型选择适配器
			var adapter chain.Adapter
			switch req.ChainType {
			case "bitcoin", "btc":
				adapter = chain.NewBitcoinAdapter(&chaincfg.MainNetParams)
			case "ethereum", "eth", "evm":
				adapter = chain.NewEthereumAdapter(big.NewInt(1)) // mainnet
			default:
				// 不支持的链类型，跳过地址生成
				adapter = nil
			}
			if adapter != nil {
				address, err := adapter.GenerateAddress(pubKeyBytes)
				if err == nil {
					storageKey.Address = address
				}
			}
		}
	}

	if err := s.metadataStore.UpdateKeyMetadata(ctx, storageKey); err != nil {
		return nil, errors.Wrap(err, "failed to update key metadata")
	}

	keyMetadata := &KeyMetadata{
		KeyID:        storageKey.KeyID,
		PublicKey:    storageKey.PublicKey,
		Algorithm:    storageKey.Algorithm,
		Curve:        storageKey.Curve,
		ChainCode:    storageKey.ChainCode,
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
		KeyID:        keyID,
		PublicKey:    dkgResp.PublicKey.Hex,
		Algorithm:    req.Algorithm,
		Curve:        req.Curve,
		ChainCode:    chainCodeHex,
		Threshold:    threshold,
		TotalNodes:   totalNodes,
		Protocol:     req.Protocol,
		Status:       "Active",
		Description:  req.Description,
		Tags:         req.Tags,
		CreatedAt:    now,
		UpdatedAt:    now,
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
		WalletID:     walletID,
		RootKeyID:    req.RootKeyID,
		ChainType:    req.ChainType,
		Index:        req.Index,
		PublicKey:    hex.EncodeToString(walletPubKey),
		ChainCode:    hex.EncodeToString(result.ChainCode),
		Address:      address,
		Status:       "Active",
		Description:  req.Description,
		Tags:         req.Tags,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	// 保存到数据库
	if walletMetadata.Tags == nil {
		walletMetadata.Tags = make(map[string]string)
	}
	// Record derivation info
	walletMetadata.Tags["parent_key_id"] = req.RootKeyID
	walletMetadata.Tags["derivation_index"] = big.NewInt(int64(req.Index)).String()

	storageKey := &storage.KeyMetadata{
		KeyID:        walletMetadata.WalletID,
		PublicKey:    walletMetadata.PublicKey,
		Algorithm:    rootKey.Algorithm, // 继承算法
		Curve:        rootKey.Curve,     // 继承曲线
		ChainCode:    hex.EncodeToString(result.ChainCode), // 保存子 ChainCode
		Threshold:    rootKey.Threshold,
		TotalNodes:   rootKey.TotalNodes,
		ChainType:    walletMetadata.ChainType,
		Address:      walletMetadata.Address,
		Status:       walletMetadata.Status,
		Description:  walletMetadata.Description,
		Tags:         walletMetadata.Tags,
		CreatedAt:    walletMetadata.CreatedAt,
		UpdatedAt:    walletMetadata.UpdatedAt,
	}

	if err := s.metadataStore.SaveKeyMetadata(ctx, storageKey); err != nil {
		return nil, errors.Wrap(err, "failed to save wallet key metadata")
	}

	return walletMetadata, nil
}

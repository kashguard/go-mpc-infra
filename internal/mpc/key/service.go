package key

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/protocol"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/storage"
	"github.com/pkg/errors"
)

// Service 密钥服务
type Service struct {
	metadataStore   storage.MetadataStore
	keyShareStorage storage.KeyShareStorage
	protocolEngine  protocol.Engine
}

// NewService 创建密钥服务
func NewService(
	metadataStore storage.MetadataStore,
	keyShareStorage storage.KeyShareStorage,
	protocolEngine protocol.Engine,
) *Service {
	return &Service{
		metadataStore:   metadataStore,
		keyShareStorage: keyShareStorage,
		protocolEngine:  protocolEngine,
	}
}

// CreateKey 创建密钥（执行DKG）
func (s *Service) CreateKey(ctx context.Context, req *CreateKeyRequest) (*KeyMetadata, error) {
	// 生成密钥ID
	keyID := "key-" + uuid.New().String()

	// 准备DKG请求
	// TODO: 获取参与节点列表
	nodeIDs := []string{} // 需要从节点管理器获取

	dkgReq := &protocol.KeyGenRequest{
		Algorithm:  req.Algorithm,
		Curve:      req.Curve,
		Threshold:  req.Threshold,
		TotalNodes: req.TotalNodes,
		NodeIDs:    nodeIDs,
	}

	// 执行DKG
	dkgResp, err := s.protocolEngine.GenerateKeyShare(ctx, dkgReq)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate key shares")
	}

	// 存储密钥分片
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

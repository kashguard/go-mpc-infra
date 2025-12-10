package protocol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/kashguard/tss-lib/ecdsa/keygen"
	"github.com/kashguard/tss-lib/tss"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// gg18KeyRecord 保存密钥生成后的内部状态（使用 tss-lib 的真实数据）
type gg18KeyRecord struct {
	// 注意：不再存储完整私钥，只存储 tss-lib 的保存数据
	KeyData    *keygen.LocalPartySaveData
	PublicKey  *PublicKey
	Threshold  int
	TotalNodes int
	NodeIDs    []string
}

// KeyShareStorage 密钥分片存储接口（用于持久化 LocalPartySaveData）
type KeyShareStorage interface {
	StoreKeyData(ctx context.Context, keyID string, nodeID string, keyData []byte) error
	GetKeyData(ctx context.Context, keyID string, nodeID string) ([]byte, error)
}

// GG18Protocol GG18协议实现（基于 tss-lib 的生产级实现）
type GG18Protocol struct {
	curve string

	mu         sync.RWMutex
	keyRecords map[string]*gg18KeyRecord

	// tss-lib 管理器
	partyManager *tssPartyManager

	// 当前节点ID（用于参与协议）
	thisNodeID string

	// 消息路由函数（用于节点间通信）
	// 参数：sessionID（用于DKG或签名会话），nodeID（目标节点），msg（tss-lib消息），isBroadcast（是否广播）
	messageRouter func(sessionID string, nodeID string, msg tss.Message, isBroadcast bool) error

	// 密钥数据存储（用于持久化 LocalPartySaveData）
	keyShareStorage KeyShareStorage
}

// NewGG18Protocol 创建GG18协议实例（生产级实现，基于 tss-lib）
func NewGG18Protocol(curve string, thisNodeID string, messageRouter func(sessionID string, nodeID string, msg tss.Message, isBroadcast bool) error, keyShareStorage KeyShareStorage) *GG18Protocol {
	partyManager := newTSSPartyManager(messageRouter)
	return &GG18Protocol{
		curve:           curve,
		keyRecords:      make(map[string]*gg18KeyRecord),
		partyManager:    partyManager,
		thisNodeID:      thisNodeID,
		messageRouter:   messageRouter,
		keyShareStorage: keyShareStorage,
	}
}

// getKeyRecord 获取密钥记录（测试或签名阶段使用）
func (p *GG18Protocol) getKeyRecord(keyID string) (*gg18KeyRecord, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	record, ok := p.keyRecords[keyID]
	return record, ok
}

func (p *GG18Protocol) saveKeyRecord(keyID string, record *gg18KeyRecord) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keyRecords[keyID] = record
}

// GenerateKeyShare 分布式密钥生成（使用 tss-lib 的真实 DKG 协议）
func (p *GG18Protocol) GenerateKeyShare(ctx context.Context, req *KeyGenRequest) (*KeyGenResponse, error) {
	if err := p.ValidateKeyGenRequest(req); err != nil {
		return nil, errors.Wrap(err, "invalid key generation request")
	}

	keyID := req.KeyID
	if keyID == "" {
		keyID = fmt.Sprintf("gg18-key-%s", generateKeyID())
	}

	nodeIDs, err := normalizeNodeIDs(req.NodeIDs, req.TotalNodes)
	if err != nil {
		return nil, errors.Wrap(err, "invalid node IDs")
	}

	// 使用 tss-lib 执行真正的 DKG
	keyData, err := p.partyManager.executeKeygen(ctx, keyID, nodeIDs, req.Threshold, p.thisNodeID)
	if err != nil {
		return nil, errors.Wrap(err, "execute tss-lib keygen")
	}

	// 转换 tss-lib 数据为我们的格式
	// 注意：只返回当前节点的KeyShare
	keyShare, publicKey, err := convertTSSKeyData(keyID, keyData, p.thisNodeID)
	if err != nil {
		return nil, errors.Wrap(err, "convert tss key data")
	}

	// 保存密钥记录（不包含完整私钥）
	record := &gg18KeyRecord{
		KeyData:    keyData,
		PublicKey:  publicKey,
		Threshold:  req.Threshold,
		TotalNodes: req.TotalNodes,
		NodeIDs:    nodeIDs,
	}
	p.saveKeyRecord(keyID, record)

	// 持久化 LocalPartySaveData 到 keyShareStorage（用于签名时加载）
	if p.keyShareStorage != nil {
		keyDataBytes, err := serializeLocalPartySaveData(keyData)
		if err != nil {
			return nil, errors.Wrap(err, "failed to serialize LocalPartySaveData")
		}
		log.Info().
			Str("key_id", keyID).
			Str("node_id", p.thisNodeID).
			Int("key_data_bytes", len(keyDataBytes)).
			Msg("Storing LocalPartySaveData to keyShareStorage")
		if err := p.keyShareStorage.StoreKeyData(ctx, keyID, p.thisNodeID, keyDataBytes); err != nil {
			log.Error().
				Err(err).
				Str("key_id", keyID).
				Str("node_id", p.thisNodeID).
				Msg("Failed to store LocalPartySaveData")
			return nil, errors.Wrap(err, "failed to store LocalPartySaveData")
		}
		log.Info().
			Str("key_id", keyID).
			Str("node_id", p.thisNodeID).
			Msg("LocalPartySaveData stored successfully")
	} else {
		log.Warn().
			Str("key_id", keyID).
			Str("node_id", p.thisNodeID).
			Msg("keyShareStorage is nil, cannot store LocalPartySaveData")
	}

	// 返回当前节点的KeyShare（在map中）
	keyShares := make(map[string]*KeyShare)
	keyShares[p.thisNodeID] = keyShare

	return &KeyGenResponse{
		KeyShares: keyShares,
		PublicKey: publicKey,
	}, nil
}

// ThresholdSign 阈值签名（使用 tss-lib 的真实签名协议）
func (p *GG18Protocol) ThresholdSign(ctx context.Context, sessionID string, req *SignRequest) (*SignResponse, error) {
	if err := p.ValidateSignRequest(req); err != nil {
		return nil, errors.Wrap(err, "invalid sign request")
	}

	// 获取密钥记录（优先从内存，如果不存在则从 keyShareStorage 加载）
	record, ok := p.getKeyRecord(req.KeyID)
	if !ok {
		// 内存中没有，尝试从 keyShareStorage 加载
		if p.keyShareStorage != nil {
			keyDataBytes, err := p.keyShareStorage.GetKeyData(ctx, req.KeyID, p.thisNodeID)
			if err != nil {
				return nil, errors.Wrapf(err, "key %s not found in memory or storage", req.KeyID)
			}

			// 反序列化 LocalPartySaveData
			keyData, err := deserializeLocalPartySaveData(keyDataBytes)
			if err != nil {
				return nil, errors.Wrap(err, "failed to deserialize LocalPartySaveData")
			}

			// 从密钥元数据获取公钥（需要从 keyService 获取，但这里我们没有 keyService）
			// 暂时从 keyData 中提取公钥
			ecdsaPubKey := keyData.ECDSAPub.ToECDSAPubKey()
			if ecdsaPubKey == nil {
				return nil, errors.New("failed to extract public key from LocalPartySaveData")
			}

			var pubKeyBytes []byte
			if ecdsaPubKey.Y.Bit(0) == 0 {
				pubKeyBytes = append([]byte{0x02}, ecdsaPubKey.X.Bytes()...)
			} else {
				pubKeyBytes = append([]byte{0x03}, ecdsaPubKey.X.Bytes()...)
			}
			if len(ecdsaPubKey.X.Bytes()) < 32 {
				padded := make([]byte, 32)
				copy(padded[32-len(ecdsaPubKey.X.Bytes()):], ecdsaPubKey.X.Bytes())
				if ecdsaPubKey.Y.Bit(0) == 0 {
					pubKeyBytes = append([]byte{0x02}, padded...)
				} else {
					pubKeyBytes = append([]byte{0x03}, padded...)
				}
			}
			pubKeyHex := hex.EncodeToString(pubKeyBytes)

			publicKey := &PublicKey{
				Bytes: pubKeyBytes,
				Hex:   pubKeyHex,
			}

			// 创建密钥记录并保存到内存
			record = &gg18KeyRecord{
				KeyData:    keyData,
				PublicKey:  publicKey,
				Threshold:  0, // 这些信息需要从密钥元数据获取，暂时使用默认值
				TotalNodes: 0,
				NodeIDs:    nil,
			}
			p.saveKeyRecord(req.KeyID, record)
		} else {
			return nil, errors.Errorf("key %s not found", req.KeyID)
		}
	}

	if record.KeyData == nil {
		return nil, errors.New("key data not found in record")
	}

	// 解析消息
	message, err := resolveMessagePayload(req)
	if err != nil {
		return nil, errors.Wrap(err, "resolve message payload")
	}

	// 使用 tss-lib 执行真正的阈值签名（GG18 默认选项）
	sigData, err := p.partyManager.executeSigning(
		ctx,
		sessionID,
		req.KeyID,
		message,
		req.NodeIDs,
		p.thisNodeID,
		record.KeyData,
		DefaultSigningOptions(),
	)
	if err != nil {
		return nil, errors.Wrap(err, "execute tss-lib signing")
	}

	// 转换签名格式
	signature, err := convertTSSSignature(sigData)
	if err != nil {
		return nil, errors.Wrap(err, "convert tss signature")
	}

	return &SignResponse{
		Signature: signature,
		PublicKey: record.PublicKey,
	}, nil
}

// VerifySignature 签名验证
func (p *GG18Protocol) VerifySignature(ctx context.Context, sig *Signature, msg []byte, pubKey *PublicKey) (bool, error) {
	return verifyECDSASignature(sig, msg, pubKey)
}

// 辅助函数

func generateKeyID() string {
	return fmt.Sprintf("key-%d", time.Now().UnixNano())
}

func normalizeNodeIDs(ids []string, total int) ([]string, error) {
	if len(ids) == 0 {
		generated := make([]string, total)
		for i := 0; i < total; i++ {
			generated[i] = fmt.Sprintf("node-%02d", i+1)
		}
		return generated, nil
	}
	if len(ids) != total {
		return nil, fmt.Errorf("node IDs count mismatch: expected %d, got %d", total, len(ids))
	}
	return ids, nil
}

func resolveMessagePayload(req *SignRequest) ([]byte, error) {
	switch {
	case len(req.Message) > 0:
		return req.Message, nil
	case req.MessageHex != "":
		payload := strings.TrimPrefix(req.MessageHex, "0x")
		msg, err := hex.DecodeString(payload)
		if err != nil {
			return nil, errors.Wrap(err, "invalid message hex")
		}
		return msg, nil
	default:
		return nil, errors.New("message payload is empty")
	}
}

func verifyECDSASignature(sig *Signature, msg []byte, pubKey *PublicKey) (bool, error) {
	if sig == nil || len(sig.Bytes) == 0 {
		return false, errors.New("signature bytes missing")
	}
	if len(msg) == 0 {
		return false, errors.New("message is empty")
	}
	if pubKey == nil || len(pubKey.Bytes) == 0 {
		return false, errors.New("public key is empty")
	}

	hash := sha256.Sum256(msg)
	parsedSig, err := ecdsa.ParseDERSignature(sig.Bytes)
	if err != nil {
		return false, errors.Wrap(err, "parse signature")
	}
	parsedPub, err := secp256k1.ParsePubKey(pubKey.Bytes)
	if err != nil {
		return false, errors.Wrap(err, "parse pub key")
	}

	return parsedSig.Verify(hash[:], parsedPub), nil
}

// RotateKey 密钥轮换
func (p *GG18Protocol) RotateKey(ctx context.Context, keyID string) error {
	// TODO: 实现密钥轮换协议
	// 1. 执行密钥轮换DKG
	// 2. 生成新的密钥分片
	// 3. 更新密钥元数据

	// 临时实现：返回错误，提示需要实现
	return errors.New("GG18 key rotation not yet implemented")
}

// ProcessIncomingKeygenMessage 处理接收到的DKG消息
func (p *GG18Protocol) ProcessIncomingKeygenMessage(ctx context.Context, sessionID string, fromNodeID string, msgBytes []byte, isBroadcast bool) error {
	return p.partyManager.ProcessIncomingKeygenMessage(ctx, sessionID, fromNodeID, msgBytes, isBroadcast)
}

// ProcessIncomingSigningMessage 处理接收到的签名消息
func (p *GG18Protocol) ProcessIncomingSigningMessage(ctx context.Context, sessionID string, fromNodeID string, msgBytes []byte) error {
	return p.partyManager.ProcessIncomingSigningMessage(ctx, sessionID, fromNodeID, msgBytes)
}

// SupportedProtocols 支持的协议
func (p *GG18Protocol) SupportedProtocols() []string {
	return []string{"gg18"}
}

// DefaultProtocol 默认协议
func (p *GG18Protocol) DefaultProtocol() string {
	return "gg18"
}

// GetCurve 获取曲线类型
func (p *GG18Protocol) GetCurve() string {
	return p.curve
}

// ValidateKeyGenRequest 验证密钥生成请求
func (p *GG18Protocol) ValidateKeyGenRequest(req *KeyGenRequest) error {
	if req.Algorithm != "ECDSA" {
		return fmt.Errorf("unsupported algorithm: %s", req.Algorithm)
	}

	if req.Curve != "secp256k1" {
		return fmt.Errorf("unsupported curve: %s", req.Curve)
	}

	if req.Threshold < 2 {
		return fmt.Errorf("threshold must be at least 2")
	}

	if req.TotalNodes < req.Threshold {
		return fmt.Errorf("total nodes must be at least threshold")
	}

	if len(req.NodeIDs) != 0 && len(req.NodeIDs) != req.TotalNodes {
		return fmt.Errorf("node IDs count mismatch: expected %d, got %d", req.TotalNodes, len(req.NodeIDs))
	}

	return nil
}

// ValidateSignRequest 验证签名请求
func (p *GG18Protocol) ValidateSignRequest(req *SignRequest) error {
	if req.KeyID == "" {
		return fmt.Errorf("key ID is required")
	}

	if len(req.Message) == 0 && req.MessageHex == "" {
		return fmt.Errorf("message is required")
	}

	if len(req.NodeIDs) == 0 {
		return fmt.Errorf("node IDs are required")
	}

	return nil
}

// serializeLocalPartySaveData 序列化 LocalPartySaveData 为字节
// 使用 encoding/gob 进行序列化，因为 LocalPartySaveData 包含 big.Int 等复杂类型
func serializeLocalPartySaveData(keyData *keygen.LocalPartySaveData) ([]byte, error) {
	if keyData == nil {
		return nil, errors.New("keyData is nil")
	}

	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	if err := encoder.Encode(keyData); err != nil {
		return nil, errors.Wrap(err, "failed to encode LocalPartySaveData")
	}

	return buf.Bytes(), nil
}

// deserializeLocalPartySaveData 从字节反序列化 LocalPartySaveData
func deserializeLocalPartySaveData(data []byte) (*keygen.LocalPartySaveData, error) {
	if len(data) == 0 {
		return nil, errors.New("data is empty")
	}

	var keyData keygen.LocalPartySaveData
	decoder := gob.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&keyData); err != nil {
		return nil, errors.Wrap(err, "failed to decode LocalPartySaveData")
	}

	return &keyData, nil
}

package protocol

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
	"github.com/kashguard/tss-lib/common"
	eddsaKeygen "github.com/kashguard/tss-lib/eddsa/keygen"
	eddsaSigning "github.com/kashguard/tss-lib/eddsa/signing"
	"github.com/kashguard/tss-lib/tss"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// FROSTProtocol FROST协议实现（基于 Schnorr 签名的阈值签名）
// FROST 的主要特点：
// 1. 2 轮通信（相比 GG18 的 4-9 轮，GG20 的优化轮次）
// 2. 基于 Schnorr 签名（更适合 Bitcoin BIP-340）
// 3. 更高的性能和效率
// 4. IETF 标准协议
//
// 注意：DKG 只支持 Ed25519 曲线（tss-lib 的 EdDSA keygen 限制）
// 签名验证支持 Ed25519 和 secp256k1 两种曲线
type FROSTProtocol struct {
	curve string

	mu         sync.RWMutex
	keyRecords map[string]*frostKeyRecord

	// roundMu 和 roundStates 保留用于未来扩展（协议进度跟踪）
	// roundMu     sync.Mutex
	// roundStates map[string]*signingRoundState

	// tss-lib 管理器（复用通用适配层）
	partyManager *tssPartyManager

	// 当前节点ID（用于参与协议）
	thisNodeID string

	// 消息路由函数（用于节点间通信）
	// 参数：sessionID（用于DKG或签名会话），nodeID（目标节点），msg（tss-lib消息），isBroadcast（是否广播）
	messageRouter func(sessionID string, nodeID string, msg tss.Message, isBroadcast bool) error

	// 密钥数据存储（用于持久化 LocalPartySaveData）
	keyShareStorage KeyShareStorage
}

// NewFROSTProtocol 创建 FROST 协议实例
func NewFROSTProtocol(curve string, thisNodeID string, messageRouter func(sessionID string, nodeID string, msg tss.Message, isBroadcast bool) error, keyShareStorage KeyShareStorage) *FROSTProtocol {
	return &FROSTProtocol{
		curve:           curve, // Default to Ed25519 for DKG if empty, but respect input
		keyRecords:      make(map[string]*frostKeyRecord),
		partyManager:    newTSSPartyManager(messageRouter),
		thisNodeID:      thisNodeID,
		messageRouter:   messageRouter,
		keyShareStorage: keyShareStorage,
	}
}

type frostKeyRecord struct {
	// 使用 EdDSA keygen 的数据结构（Schnorr 兼容）
	KeyData    *eddsaKeygen.LocalPartySaveData
	PublicKey  *PublicKey
	Curve      string // 曲线类型（ed25519 或 secp256k1）
	Threshold  int
	TotalNodes int
	NodeIDs    []string
}

// getKeyRecord 获取密钥记录
func (p *FROSTProtocol) getKeyRecord(keyID string) (*frostKeyRecord, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	record, ok := p.keyRecords[keyID]
	return record, ok
}

func (p *FROSTProtocol) saveKeyRecord(keyID string, record *frostKeyRecord) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keyRecords[keyID] = record
}

// GenerateKeyShare 分布式密钥生成（使用 EdDSA DKG，Schnorr 兼容）
// 注意：DKG 只支持 Ed25519 曲线，不支持 secp256k1（tss-lib 的 EdDSA keygen 限制）
func (p *FROSTProtocol) GenerateKeyShare(ctx context.Context, req *KeyGenRequest) (*KeyGenResponse, error) {
	if err := p.ValidateKeyGenRequest(req); err != nil {
		return nil, errors.Wrap(err, "invalid key generation request")
	}

	keyID := req.KeyID
	if keyID == "" {
		keyID = fmt.Sprintf("frost-key-%s", generateKeyID())
	}

	nodeIDs, err := normalizeNodeIDs(req.NodeIDs, req.TotalNodes)
	if err != nil {
		return nil, errors.Wrap(err, "invalid node IDs")
	}

	// 使用 tss-lib 执行 EdDSA DKG（通过 tssPartyManager）
	keyData, err := p.partyManager.executeEdDSAKeygen(ctx, keyID, nodeIDs, req.Threshold, p.thisNodeID)
	if err != nil {
		return nil, errors.Wrap(err, "execute FROST keygen")
	}

	// 转换密钥数据
	keyShares, publicKey, err := convertFROSTKeyData(keyID, keyData, nodeIDs)
	if err != nil {
		return nil, errors.Wrap(err, "convert FROST key data")
	}

	// 确定曲线类型（FROST DKG 只支持 Ed25519）
	curve := req.Curve
	if curve == "" {
		curve = p.curve
	}
	// 标准化曲线名称（统一为小写）
	curve = strings.ToLower(curve)
	// FROST DKG 只支持 Ed25519，强制设置为 ed25519
	if curve != "ed25519" {
		log.Warn().
			Str("requested_curve", req.Curve).
			Str("default_curve", p.curve).
			Msg("FROST DKG only supports Ed25519, forcing curve to ed25519")
		curve = "ed25519"
	}

	// 保存密钥记录
	record := &frostKeyRecord{
		KeyData:    keyData,
		PublicKey:  publicKey,
		Curve:      curve,
		Threshold:  req.Threshold,
		TotalNodes: req.TotalNodes,
		NodeIDs:    nodeIDs,
	}
	p.saveKeyRecord(keyID, record)

	// 持久化 LocalPartySaveData 到 keyShareStorage（用于签名时加载）
	// 注意：keyShareStorage 是必需的，如果为 nil，DKG 应该失败
	if p.keyShareStorage == nil {
		log.Error().
			Str("key_id", keyID).
			Str("node_id", p.thisNodeID).
			Msg("keyShareStorage is nil, cannot store LocalPartySaveData - DKG will fail")
		return nil, errors.New("keyShareStorage is nil, cannot store LocalPartySaveData")
	}

	keyDataBytes, err := serializeEdDSALocalPartySaveData(keyData)
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

	return &KeyGenResponse{
		KeyShares: keyShares,
		PublicKey: publicKey,
	}, nil
}

// ThresholdSign 阈值签名（FROST 2 轮签名协议）
func (p *FROSTProtocol) ThresholdSign(ctx context.Context, sessionID string, req *SignRequest) (*SignResponse, error) {
	if err := p.ValidateSignRequest(req); err != nil {
		return nil, errors.Wrap(err, "invalid sign request")
	}

	// 复用密钥加载逻辑（从内存或 keyShareStorage 加载）
	record, ok := p.getKeyRecord(req.KeyID)
	if !ok {
		// 内存中没有，尝试从 keyShareStorage 加载
		if p.keyShareStorage != nil {
			keyDataBytes, err := p.keyShareStorage.GetKeyData(ctx, req.KeyID, p.thisNodeID)
			if err != nil {
				return nil, errors.Wrapf(err, "key %s not found in memory or storage", req.KeyID)
			}

			// 反序列化 EdDSA LocalPartySaveData
			keyData, err := deserializeEdDSALocalPartySaveData(keyDataBytes)
			if err != nil {
				return nil, errors.Wrap(err, "failed to deserialize EdDSA LocalPartySaveData")
			}

			// 从 keyData 中提取公钥（使用与 convertFROSTKeyData 相同的方法）
			if keyData.EDDSAPub == nil {
				return nil, errors.New("EDDSAPub is nil in EdDSA LocalPartySaveData")
			}

			// 使用 tss-lib 提供的转换函数将公钥转换为标准 Ed25519 格式（big-endian）
			standardPubKey := eddsaSigning.PublicKeyToStandardEd25519(
				keyData.EDDSAPub.X(),
				keyData.EDDSAPub.Y(),
			)

			pubKeyBytes := standardPubKey[:]
			pubKeyHex := hex.EncodeToString(pubKeyBytes)

			log.Info().
				Int("public_key_len", len(pubKeyBytes)).
				Str("public_key_hex", pubKeyHex).
				Msg("✅ [DIAGNOSTIC] ThresholdSign: converted public key to standard Ed25519 format (big-endian)")

			// 确定曲线类型（从协议实例获取）
			curve := strings.ToLower(p.curve)
			if curve != "ed25519" && curve != "secp256k1" {
				// 默认使用 ed25519（EdDSA keygen 的默认曲线）
				curve = "ed25519"
			}

			// 创建密钥记录并保存到内存
			record = &frostKeyRecord{
				KeyData:    keyData,
				PublicKey:  &PublicKey{Bytes: pubKeyBytes, Hex: pubKeyHex},
				Curve:      curve,
				Threshold:  0,
				TotalNodes: 0,
				NodeIDs:    nil,
			}
			p.saveKeyRecord(req.KeyID, record)
		} else {
			return nil, errors.Errorf("key %s not found in memory and keyShareStorage is nil", req.KeyID)
		}
	}

	if record == nil || record.KeyData == nil {
		return nil, errors.New("key data not found in record")
	}

	// 解析消息
	message, err := resolveMessagePayload(req)
	if err != nil {
		return nil, errors.Wrap(err, "resolve message payload")
	}

	// 使用 tss-lib 执行 FROST 签名协议（通过 tssPartyManager，使用 EdDSA signing）
	sigData, err := p.partyManager.executeEdDSASigning(
		ctx,
		sessionID,
		req.KeyID,
		message,
		req.NodeIDs,
		p.thisNodeID,
		record.KeyData,
		FROSTSigningOptions(),
	)
	if err != nil {
		return nil, errors.Wrap(err, "execute FROST signing")
	}

	// 转换签名格式（Schnorr 签名格式）
	signature, err := convertFROSTSignature(sigData)
	if err != nil {
		return nil, errors.Wrap(err, "convert FROST signature")
	}

	return &SignResponse{
		Signature: signature,
		PublicKey: record.PublicKey,
	}, nil
}

// convertFROSTKeyData 将 EdDSA keygen 数据转换为我们的 KeyShare 格式
func convertFROSTKeyData(
	keyID string,
	saveData *eddsaKeygen.LocalPartySaveData,
	nodeIDs []string,
) (map[string]*KeyShare, *PublicKey, error) {
	keyShares := make(map[string]*KeyShare)

	// 检查 saveData 是否为 nil
	if saveData == nil {
		return nil, nil, errors.New("saveData is nil")
	}

	// 获取公钥（EdDSA 公钥格式）
	if saveData.EDDSAPub == nil {
		return nil, nil, errors.New("EDDSAPub is nil")
	}

	// 使用 tss-lib 提供的转换函数将公钥转换为标准 Ed25519 格式（RFC 8032，little-endian）
	// PublicKeyToStandardEd25519 将 tss-lib 的内部公钥格式转换为标准 Ed25519 格式
	standardPubKey := eddsaSigning.PublicKeyToStandardEd25519(
		saveData.EDDSAPub.X(),
		saveData.EDDSAPub.Y(),
	)

	pubKeyBytes := standardPubKey[:]
	pubKeyHex := hex.EncodeToString(pubKeyBytes)

	log.Info().
		Int("public_key_len", len(pubKeyBytes)).
		Str("public_key_hex", pubKeyHex).
		Msg("✅ [DIAGNOSTIC] convertFROSTKeyData: converted to standard Ed25519 format (RFC 8032, little-endian)")

	publicKey := &PublicKey{
		Bytes: pubKeyBytes,
		Hex:   pubKeyHex,
	}

	// 为每个节点创建 KeyShare
	for idx, nodeID := range nodeIDs {
		shareID := fmt.Sprintf("%s-%02d", keyID, idx+1)
		keyShares[nodeID] = &KeyShare{
			ShareID: shareID,
			NodeID:  nodeID,
			Share:   nil, // 实际应该从 saveData 中提取
			Index:   idx + 1,
		}
	}

	return keyShares, publicKey, nil
}

// convertFROSTSignature 将 EdDSA 签名数据转换为我们的 Signature 格式（标准 Ed25519 格式）
// tss-lib v0.0.2 已确认签名输出即为标准 Ed25519 格式（RFC 8032，little-endian）
// SignatureToStandardEd25519 主要做长度校验并返回副本
func convertFROSTSignature(sigData *common.SignatureData) (*Signature, error) {
	if sigData == nil {
		return nil, errors.New("signature data is nil")
	}

	// 添加调试日志
	log.Info().
		Int("signature_len", len(sigData.Signature)).
		Int("r_len", len(sigData.R)).
		Int("s_len", len(sigData.S)).
		Str("signature_hex", hex.EncodeToString(sigData.Signature)).
		Str("r_hex", hex.EncodeToString(sigData.R)).
		Str("s_hex", hex.EncodeToString(sigData.S)).
		Msg("🔍 [DIAGNOSTIC] convertFROSTSignature: signature data")

	// tss-lib 输出已经是标准 Ed25519 格式（little-endian），这里仅做校验并返回副本
	standardSig, err := eddsaSigning.SignatureToStandardEd25519(sigData.Signature)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert signature to standard Ed25519 format")
	}

	log.Info().
		Int("standard_signature_len", len(standardSig)).
		Str("standard_signature_hex", hex.EncodeToString(standardSig[:])).
		Msg("✅ [DIAGNOSTIC] convertFROSTSignature: converted to standard Ed25519 format (big-endian)")

	return &Signature{
		R:     standardSig[:32],
		S:     standardSig[32:64],
		Bytes: standardSig[:],
		Hex:   hex.EncodeToString(standardSig[:]),
	}, nil
}

// 注意：reverseBytes 函数已移除，现在使用 tss-lib 提供的转换函数
// SignatureToStandardEd25519 和 PublicKeyToStandardEd25519 来处理字节序转换

// VerifySignature 签名验证（Schnorr 签名验证）
func (p *FROSTProtocol) VerifySignature(ctx context.Context, sig *Signature, msg []byte, pubKey *PublicKey) (bool, error) {
	// 根据公钥长度自动判断曲线类型
	// Ed25519 公钥：32 字节
	// secp256k1 公钥：33 字节（压缩）或 65 字节（未压缩）
	var curve string
	if len(pubKey.Bytes) == 32 {
		curve = "ed25519"
	} else if len(pubKey.Bytes) == 33 || len(pubKey.Bytes) == 65 {
		curve = "secp256k1"
	} else {
		// 默认使用协议实例的曲线
		curve = strings.ToLower(p.curve)
		if curve != "ed25519" && curve != "secp256k1" {
			curve = "ed25519"
		}
	}
	return verifySchnorrSignature(sig, msg, pubKey, curve)
}

// SupportedProtocols 支持的协议
func (p *FROSTProtocol) SupportedProtocols() []string {
	return []string{"frost"}
}

// DefaultProtocol 默认协议
func (p *FROSTProtocol) DefaultProtocol() string {
	return "frost"
}

// GetCurve 获取曲线类型
func (p *FROSTProtocol) GetCurve() string {
	return p.curve
}

// ValidateKeyGenRequest 验证密钥生成请求
func (p *FROSTProtocol) ValidateKeyGenRequest(req *KeyGenRequest) error {
	if req == nil {
		return errors.New("key generation request is nil")
	}

	// FROST DKG 只支持 Ed25519 曲线（tss-lib 的 EdDSA keygen 限制）
	// 注意：签名验证支持 Ed25519 和 secp256k1，但 DKG 只支持 Ed25519
	curveLower := strings.ToLower(req.Curve)
	if req.Curve != "" && curveLower != "ed25519" {
		if curveLower == "secp256k1" {
			return errors.Errorf("FROST DKG does not support secp256k1 curve (only Ed25519 is supported for DKG). Use Ed25519 for DKG, or use GG18/GG20 protocol for secp256k1")
		}
		return errors.Errorf("unsupported curve for FROST DKG: %s (only Ed25519 is supported for DKG)", req.Curve)
	}

	if req.Algorithm != "" && req.Algorithm != "Schnorr" && req.Algorithm != "EdDSA" {
		return errors.Errorf("unsupported algorithm for FROST: %s (supported: Schnorr, EdDSA)", req.Algorithm)
	}

	if req.Threshold < 2 {
		return errors.New("threshold must be at least 2")
	}

	if req.TotalNodes < req.Threshold {
		return errors.New("total nodes must be at least threshold")
	}

	return nil
}

// ValidateSignRequest 验证签名请求
func (p *FROSTProtocol) ValidateSignRequest(req *SignRequest) error {
	return validateSignRequest(req)
}

// RotateKey 密钥轮换
func (p *FROSTProtocol) RotateKey(ctx context.Context, keyID string) error {
	return errors.New("FROST key rotation not yet implemented")
}

// ExecuteResharing 执行密钥轮换（Resharing）
func (p *FROSTProtocol) ExecuteResharing(ctx context.Context, keyID string, oldNodeIDs []string, newNodeIDs []string, oldThreshold int, newThreshold int) (*KeyGenResponse, error) {
	return nil, errors.New("FROST does not support Resharing yet")
}

// ProcessIncomingKeygenMessage 处理接收到的DKG消息
func (p *FROSTProtocol) ProcessIncomingKeygenMessage(
	ctx context.Context,
	sessionID string,
	fromNodeID string,
	msgBytes []byte,
	isBroadcast bool,
) error {
	return p.partyManager.ProcessIncomingKeygenMessage(ctx, sessionID, fromNodeID, msgBytes, isBroadcast)
}

// ProcessIncomingSigningMessage 处理接收到的签名消息
func (p *FROSTProtocol) ProcessIncomingSigningMessage(
	ctx context.Context,
	sessionID string,
	fromNodeID string,
	msgBytes []byte,
	isBroadcast bool,
) error {
	return p.partyManager.ProcessIncomingSigningMessage(ctx, sessionID, fromNodeID, msgBytes, isBroadcast)
}

// verifySchnorrSignature 验证 Schnorr 签名（根据曲线类型选择验证方法）
func verifySchnorrSignature(sig *Signature, msg []byte, pubKey *PublicKey, curve string) (bool, error) {
	if sig == nil || len(sig.Bytes) == 0 {
		return false, errors.New("signature bytes missing")
	}
	if len(msg) == 0 {
		return false, errors.New("message is empty")
	}
	if pubKey == nil || len(pubKey.Bytes) == 0 {
		return false, errors.New("public key is empty")
	}

	// 标准化曲线名称
	curveLower := strings.ToLower(curve)

	// 根据曲线类型选择不同的验证方法
	switch curveLower {
	case "ed25519":
		return verifyEd25519Signature(sig, msg, pubKey)
	case "secp256k1":
		// secp256k1 使用 Schnorr 签名验证（BIP-340）
		// 注意：这里暂时使用 ECDSA 验证，因为 tss-lib 的 EdDSA keygen 可能不支持 secp256k1
		// 如果 tss-lib 支持 secp256k1 的 Schnorr，应该使用专门的 Schnorr 验证函数
		return verifySecp256k1SchnorrSignature(sig, msg, pubKey)
	default:
		// 默认使用 Ed25519 验证
		return verifyEd25519Signature(sig, msg, pubKey)
	}
}

// verifyEd25519Signature 验证 Ed25519 签名（标准 Ed25519，RFC 8032）
// 注意：tss-lib v0.1 已修改为支持标准 Ed25519，签名时使用原始消息
// Ed25519.Verify 内部会使用 SHA-512 对消息进行哈希（标准 Ed25519 规范）
func verifyEd25519Signature(sig *Signature, msg []byte, pubKey *PublicKey) (bool, error) {
	// Ed25519 公钥应该是 32 字节
	if len(pubKey.Bytes) != 32 {
		return false, errors.Errorf("invalid Ed25519 public key length: expected 32 bytes, got %d", len(pubKey.Bytes))
	}

	// Ed25519 签名应该是 64 字节（R || S）
	if len(sig.Bytes) != 64 {
		return false, errors.Errorf("invalid Ed25519 signature length: expected 64 bytes, got %d", len(sig.Bytes))
	}

	// 标准 Ed25519 验证：使用原始消息
	// Ed25519.Verify 内部会使用 SHA-512 对消息进行哈希（符合 RFC 8032 标准）
	log.Debug().
		Int("message_length", len(msg)).
		Str("message_hex", hex.EncodeToString(msg)).
		Int("signature_length", len(sig.Bytes)).
		Str("signature_hex", hex.EncodeToString(sig.Bytes)).
		Int("public_key_length", len(pubKey.Bytes)).
		Str("public_key_hex", hex.EncodeToString(pubKey.Bytes)).
		Msg("🔍 [DIAGNOSTIC] verifyEd25519Signature: verifying signature with standard Ed25519")

	valid := ed25519.Verify(pubKey.Bytes, msg, sig.Bytes)

	if !valid {
		log.Warn().
			Int("message_length", len(msg)).
			Str("message_hex", hex.EncodeToString(msg)).
			Int("signature_length", len(sig.Bytes)).
			Str("signature_hex", hex.EncodeToString(sig.Bytes)).
			Int("public_key_length", len(pubKey.Bytes)).
			Str("public_key_hex", hex.EncodeToString(pubKey.Bytes)).
			Msg("Ed25519 signature verification failed")
	} else {
		log.Info().
			Int("message_length", len(msg)).
			Msg("✅ Ed25519 signature verification succeeded")
	}

	return valid, nil
}

// verifySecp256k1SchnorrSignature 验证 secp256k1 Schnorr 签名（BIP-340）
// 注意：这里使用简化的验证方法，实际应该实现完整的 BIP-340 Schnorr 验证
func verifySecp256k1SchnorrSignature(sig *Signature, msg []byte, pubKey *PublicKey) (bool, error) {
	// secp256k1 Schnorr 签名格式：R (32 bytes) || S (32 bytes) = 64 bytes
	if len(sig.Bytes) != 64 {
		return false, errors.Errorf("invalid secp256k1 Schnorr signature length: expected 64 bytes, got %d", len(sig.Bytes))
	}

	// 验证公钥格式
	if _, err := secp256k1.ParsePubKey(pubKey.Bytes); err != nil {
		return false, errors.Wrap(err, "failed to parse secp256k1 public key")
	}

	// BIP-340 Schnorr 验证
	// 使用 dcrd/secp256k1/v4 的 Schnorr 验证功能
	// 解析 Schnorr 签名
	signature, err := schnorr.ParseSignature(sig.Bytes)
	if err != nil {
		return false, errors.Wrap(err, "failed to parse schnorr signature")
	}

	// 解析公钥（使用 ParsePubKey，它支持 33 字节压缩格式）
	// 注意：BIP-340 使用 x-only 公钥 (32 bytes)，如果传入的是 33 字节，需要确保它是有效的
	// schnorr.ParsePubKey 专门用于 Schnorr 签名的公钥解析
	pk, err := schnorr.ParsePubKey(pubKey.Bytes)
	if err != nil {
		// 尝试作为普通 ECDSA 公钥解析，然后转换
		ecdsaPk, err := secp256k1.ParsePubKey(pubKey.Bytes)
		if err != nil {
			return false, errors.Wrap(err, "failed to parse public key")
		}
		// 转换为 Schnorr 公钥 (x-only)
		// 注意：dcrd 库可能没有直接转换方法，通常使用 ParsePubKey 处理 32 字节 x 坐标
		// 如果是 33 字节，ParsePubKey 会处理
		// 这里假设 ParsePubKey 已经处理了

		// secp256k1.PublicKey.SerializeCompressed()[1:] 提取 x 坐标
		xOnly := ecdsaPk.SerializeCompressed()[1:]
		pk, err = schnorr.ParsePubKey(xOnly)
		if err != nil {
			return false, errors.Wrap(err, "failed to parse x-only public key")
		}
	}

	// 计算消息哈希
	// BIP-340 签名通常是对消息哈希进行签名，或者对消息进行签名（内部哈希）
	// Verify 方法通常接受消息哈希
	hash := sha256.Sum256(msg)

	// 验证签名
	return signature.Verify(hash[:], pk), nil
}

// validateSignRequest 验证签名请求（通用验证逻辑）
func validateSignRequest(req *SignRequest) error {
	if req == nil {
		return errors.New("sign request is nil")
	}
	if req.KeyID == "" {
		return errors.New("key ID is required")
	}
	if len(req.Message) == 0 && req.MessageHex == "" {
		return errors.New("message is required")
	}
	if len(req.NodeIDs) == 0 {
		return errors.New("node IDs are required")
	}
	return nil
}

// serializeEdDSALocalPartySaveData 序列化 EdDSA LocalPartySaveData 为字节
// 使用 JSON 序列化，因为 tss-lib 的 LocalPartySaveData 内部使用 JSON 进行序列化
// gob 序列化可能导致 ECPoint 等类型在反序列化时出现问题
func serializeEdDSALocalPartySaveData(keyData *eddsaKeygen.LocalPartySaveData) ([]byte, error) {
	if keyData == nil {
		return nil, errors.New("keyData is nil")
	}

	// 使用 JSON 序列化，因为 tss-lib 的 LocalPartySaveData 内部使用 JSON
	jsonBytes, err := json.Marshal(keyData)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal LocalPartySaveData to JSON")
	}

	return jsonBytes, nil
}

// deserializeEdDSALocalPartySaveData 从字节反序列化 EdDSA LocalPartySaveData
// 使用 JSON 反序列化，与 tss-lib 的内部序列化方式一致
func deserializeEdDSALocalPartySaveData(data []byte) (*eddsaKeygen.LocalPartySaveData, error) {
	if len(data) == 0 {
		return nil, errors.New("data is empty")
	}

	var keyData eddsaKeygen.LocalPartySaveData
	if err := json.Unmarshal(data, &keyData); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal LocalPartySaveData from JSON")
	}

	return &keyData, nil
}

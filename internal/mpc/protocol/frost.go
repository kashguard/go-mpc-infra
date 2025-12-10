package protocol

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/kashguard/tss-lib/common"
	eddsaKeygen "github.com/kashguard/tss-lib/eddsa/keygen"
	"github.com/kashguard/tss-lib/tss"
	"github.com/pkg/errors"
)

// FROSTProtocol FROST协议实现（基于 Schnorr 签名的阈值签名）
// FROST 的主要特点：
// 1. 2 轮通信（相比 GG18 的 4-9 轮，GG20 的优化轮次）
// 2. 基于 Schnorr 签名（更适合 Bitcoin BIP-340）
// 3. 更高的性能和效率
// 4. IETF 标准协议
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
}

// frostKeyRecord 保存 FROST 密钥生成后的内部状态
type frostKeyRecord struct {
	// 使用 EdDSA keygen 的数据结构（Schnorr 兼容）
	KeyData    *eddsaKeygen.LocalPartySaveData
	PublicKey  *PublicKey
	Threshold  int
	TotalNodes int
	NodeIDs    []string
}

// NewFROSTProtocol 创建 FROST 协议实例
func NewFROSTProtocol(curve string, thisNodeID string, messageRouter func(sessionID string, nodeID string, msg tss.Message, isBroadcast bool) error) *FROSTProtocol {
	partyManager := newTSSPartyManager(messageRouter)
	return &FROSTProtocol{
		curve:         curve,
		keyRecords:    make(map[string]*frostKeyRecord),
		partyManager:  partyManager,
		thisNodeID:    thisNodeID,
		messageRouter: messageRouter,
	}
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

	// 保存密钥记录
	record := &frostKeyRecord{
		KeyData:    keyData,
		PublicKey:  publicKey,
		Threshold:  req.Threshold,
		TotalNodes: req.TotalNodes,
		NodeIDs:    nodeIDs,
	}
	p.saveKeyRecord(keyID, record)

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

	// 获取密钥记录
	record, ok := p.getKeyRecord(req.KeyID)
	if !ok {
		return nil, errors.Errorf("key %s not found", req.KeyID)
	}

	if record.KeyData == nil {
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

// executeFROSTKeygen 和 executeFROSTSigning 已移至 tss_adapter.go
// 现在使用 partyManager.executeEdDSAKeygen 和 partyManager.executeEdDSASigning

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

	// EdDSA/Ed25519 公钥格式：直接使用 ECPoint 的坐标
	// Ed25519 公钥是 32 字节，使用 Y 坐标（压缩格式）
	xBytes := saveData.EDDSAPub.X().Bytes()
	yBytes := saveData.EDDSAPub.Y().Bytes()

	// Ed25519 公钥使用 Y 坐标（32 字节），最高位表示 X 的符号
	var pubKeyBytes []byte
	if len(yBytes) >= 32 {
		pubKeyBytes = append([]byte(nil), yBytes[:32]...)
	} else {
		// 如果 Y 坐标不足 32 字节，进行填充
		pubKeyBytes = make([]byte, 32)
		copy(pubKeyBytes[32-len(yBytes):], yBytes)
	}

	// 设置最高位表示 X 的符号（Ed25519 压缩格式）
	if len(xBytes) > 0 && xBytes[len(xBytes)-1]&1 != 0 {
		pubKeyBytes[31] |= 0x80
	}

	pubKeyHex := hex.EncodeToString(pubKeyBytes)

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

// convertFROSTSignature 将 EdDSA 签名数据转换为我们的 Signature 格式（Schnorr 格式）
func convertFROSTSignature(sigData *common.SignatureData) (*Signature, error) {
	if sigData == nil {
		return nil, errors.New("signature data is nil")
	}

	// EdDSA/Schnorr 签名格式：R 和 S 都是 []byte
	rBytes := sigData.R
	sBytes := sigData.S

	// 填充到 32 字节
	rPadded := padScalarBytes(rBytes)
	sPadded := padScalarBytes(sBytes)

	// Schnorr 签名格式：R || S（64 字节）
	schnorrSig := append(rPadded, sPadded...)

	return &Signature{
		R:     rPadded,
		S:     sPadded,
		Bytes: schnorrSig,
		Hex:   hex.EncodeToString(schnorrSig),
	}, nil
}

// VerifySignature 签名验证（Schnorr 签名验证）
func (p *FROSTProtocol) VerifySignature(ctx context.Context, sig *Signature, msg []byte, pubKey *PublicKey) (bool, error) {
	return verifySchnorrSignature(sig, msg, pubKey)
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

	// FROST 支持 Ed25519 曲线（大小写不敏感）
	curveLower := strings.ToLower(req.Curve)
	if req.Curve != "" && curveLower != "ed25519" && curveLower != "secp256k1" {
		return errors.Errorf("unsupported curve for FROST: %s (supported: ed25519, secp256k1)", req.Curve)
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
) error {
	return p.partyManager.ProcessIncomingSigningMessage(ctx, sessionID, fromNodeID, msgBytes)
}

// verifySchnorrSignature 验证 Schnorr 签名
func verifySchnorrSignature(sig *Signature, msg []byte, pubKey *PublicKey) (bool, error) {
	if sig == nil || len(sig.Bytes) == 0 {
		return false, errors.New("signature bytes missing")
	}
	if len(msg) == 0 {
		return false, errors.New("message is empty")
	}
	if pubKey == nil || len(pubKey.Bytes) == 0 {
		return false, errors.New("public key is empty")
	}

	// Schnorr 签名验证逻辑
	// 注意：这里需要根据实际的 Schnorr 签名验证算法实现
	// 可以使用 secp256k1 或 Ed25519 的验证函数

	// 简化实现：使用 secp256k1 验证（如果曲线是 secp256k1）
	// 实际应该根据曲线类型选择不同的验证方法
	return verifyECDSASignature(sig, msg, pubKey)
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

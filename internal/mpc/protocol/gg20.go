package protocol

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/kashguard/tss-lib/ecdsa/keygen"
	"github.com/kashguard/tss-lib/tss"
	"github.com/pkg/errors"
)

// GG20Protocol GG20协议实现（改进版GG18，支持单轮签名和可识别的中止）
// GG20 的主要改进：
// 1. 单轮签名（相比 GG18 的多轮）
// 2. 可识别的中止（identifiable abort）- 如果协议失败，可以识别恶意节点
// 3. 更好的性能（减少网络通信轮次）
type GG20Protocol struct {
	*GG18Protocol
}

// NewGG20Protocol 创建GG20协议实例
func NewGG20Protocol(curve string, thisNodeID string, messageRouter func(sessionID string, nodeID string, msg tss.Message, isBroadcast bool) error, keyShareStorage KeyShareStorage) *GG20Protocol {
	return &GG20Protocol{
		GG18Protocol: NewGG18Protocol(curve, thisNodeID, messageRouter, keyShareStorage),
	}
}

// GenerateKeyShare 分布式密钥生成（复用GG18流程，GG20的DKG与GG18相同）
func (p *GG20Protocol) GenerateKeyShare(ctx context.Context, req *KeyGenRequest) (*KeyGenResponse, error) {
	// GG20 的 DKG 与 GG18 相同，直接复用
	return p.GG18Protocol.GenerateKeyShare(ctx, req)
}

// ThresholdSign 阈值签名（GG20优化版，使用tss-lib的signing模块）
// GG20 的主要改进：
// 1. 单轮签名（相比GG18的多轮）
// 2. 可识别的中止（identifiable abort）
// 3. 更好的性能
// 注意：密钥加载逻辑复用 GG18 的实现（从内存或 keyShareStorage 加载）
func (p *GG20Protocol) ThresholdSign(ctx context.Context, sessionID string, req *SignRequest) (*SignResponse, error) {
	if err := p.ValidateSignRequest(req); err != nil {
		return nil, errors.Wrap(err, "invalid sign request")
	}

	// 复用 GG18 的密钥加载逻辑（从内存或 keyShareStorage 加载）
	// 这样可以确保 GG20 也能从持久化存储中加载密钥
	record, ok := p.getKeyRecord(req.KeyID)
	if !ok {
		// 内存中没有，尝试从 keyShareStorage 加载（复用 GG18 的逻辑）
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

			// 从 keyData 中提取公钥
			ecdsaPubKey := keyData.ECDSAPub.ToECDSAPubKey()
			if ecdsaPubKey == nil {
				return nil, errors.New("failed to extract public key from LocalPartySaveData")
			}

			// 构建公钥字节
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

			// 创建密钥记录并保存到内存
			record = &gg18KeyRecord{
				KeyData:    keyData,
				PublicKey:  &PublicKey{Bytes: pubKeyBytes, Hex: pubKeyHex},
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

	// 处理密钥派生
	keyData := record.KeyData
	if req.DerivationPath != "" {
		if len(req.ParentChainCode) != 32 {
			return nil, errors.New("parent chain code required for derivation")
		}

		log.Info().
			Str("key_id", req.KeyID).
			Str("path", req.DerivationPath).
			Msg("Deriving key share for GG20 signing")

		derivedData, err := DeriveLocalPartySaveData(keyData, req.ParentChainCode, req.DerivationPath)
		if err != nil {
			return nil, errors.Wrap(err, "derivation failed")
		}
		keyData = derivedData
	}

	// 解析消息
	message, err := resolveMessagePayload(req)
	if err != nil {
		return nil, errors.Wrap(err, "resolve message payload")
	}

	// 使用 tss-lib 执行 GG20 签名协议（复用通用签名执行函数）
	sigData, err := p.partyManager.executeSigning(
		ctx,
		sessionID,
		req.KeyID,
		message,
		req.NodeIDs,
		p.thisNodeID,
		keyData,
		TSSSigningOptions{
			Timeout:                 1 * time.Minute,
			EnableIdentifiableAbort: true,
			ProtocolName:            "GG20",
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, "execute GG20 signing")
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

// SupportedProtocols 支持的协议
func (p *GG20Protocol) SupportedProtocols() []string {
	return []string{"gg20"}
}

// DefaultProtocol 默认协议
func (p *GG20Protocol) DefaultProtocol() string {
	return "gg20"
}

// GetCurve 获取曲线类型
func (p *GG20Protocol) GetCurve() string {
	return p.GG18Protocol.GetCurve()
}

// ValidateKeyGenRequest 验证密钥生成请求（复用GG18的验证逻辑）
func (p *GG20Protocol) ValidateKeyGenRequest(req *KeyGenRequest) error {
	return p.GG18Protocol.ValidateKeyGenRequest(req)
}

// ValidateSignRequest 验证签名请求（复用GG18的验证逻辑）
func (p *GG20Protocol) ValidateSignRequest(req *SignRequest) error {
	return p.GG18Protocol.ValidateSignRequest(req)
}

// VerifySignature 签名验证（复用GG18的验证逻辑）
func (p *GG20Protocol) VerifySignature(ctx context.Context, sig *Signature, msg []byte, pubKey *PublicKey) (bool, error) {
	return p.GG18Protocol.VerifySignature(ctx, sig, msg, pubKey)
}

// ProcessIncomingKeygenMessage 处理DKG消息（复用 GG18）
func (p *GG20Protocol) ProcessIncomingKeygenMessage(ctx context.Context, sessionID string, fromNodeID string, msgBytes []byte, isBroadcast bool) error {
	return p.GG18Protocol.ProcessIncomingKeygenMessage(ctx, sessionID, fromNodeID, msgBytes, isBroadcast)
}

// ProcessIncomingSigningMessage 处理签名消息（复用 GG18）
func (p *GG20Protocol) ProcessIncomingSigningMessage(ctx context.Context, sessionID string, fromNodeID string, msgBytes []byte, isBroadcast bool) error {
	return p.GG18Protocol.ProcessIncomingSigningMessage(ctx, sessionID, fromNodeID, msgBytes, isBroadcast)
}

// RotateKey 密钥轮换（Resharing）
func (p *GG20Protocol) RotateKey(ctx context.Context, keyID string) error {
	// 1. 获取旧的密钥数据
	record, ok := p.getKeyRecord(keyID)
	if !ok {
		// 尝试从存储加载
		if p.keyShareStorage != nil {
			keyDataBytes, err := p.keyShareStorage.GetKeyData(ctx, keyID, p.thisNodeID)
			if err != nil {
				return errors.Wrapf(err, "key %s not found in memory or storage", keyID)
			}
			keyData, err := deserializeLocalPartySaveData(keyDataBytes)
			if err != nil {
				return errors.Wrap(err, "failed to deserialize key data")
			}
			// 重构 record (简化，仅用于 RotateKey)
			record = &gg18KeyRecord{
				KeyData:    keyData,
				TotalNodes: len(keyData.Ks),     // 从 LocalPreParams 推断
				Threshold:  len(keyData.Ks) - 1, // 粗略推断，实际上 Threshold 不直接存储在 keyData 中
				NodeIDs:    nil,                 // 需要从外部传入或推断，Resharing通常需要显式的 old/new party ID 列表
			}
			// 注意：这里没有完整的 record 信息（如 NodeIDs），可能需要从其他地方获取
			// 但 executeResharing 需要 NodeIDs
		} else {
			return errors.Errorf("key %s not found", keyID)
		}
	}
	_ = record // Suppress unused variable error until implementation is complete

	// TODO: RotateKey 接口定义目前只接受 keyID，这不足以支持 Resharing
	// Resharing 需要 NewNodeIDs, NewThreshold 等参数
	// 我们需要扩展 Engine 接口或提供特定于 Resharing 的方法
	// 暂时返回未实现错误，直到上层服务准备好传递所需参数
	return errors.New("RotateKey requires extended parameters (NewNodeIDs, NewThreshold), please use ExecuteResharing instead")
}

// ExecuteResharing 执行密钥轮换
func (p *GG20Protocol) ExecuteResharing(
	ctx context.Context,
	keyID string,
	oldNodeIDs []string,
	newNodeIDs []string,
	oldThreshold int,
	newThreshold int,
) (*KeyGenResponse, error) {
	// 1. 获取旧密钥数据
	record, ok := p.getKeyRecord(keyID)
	var keyData *keygen.LocalPartySaveData
	if ok {
		keyData = record.KeyData
	} else {
		// 从存储加载
		if p.keyShareStorage == nil {
			return nil, errors.New("key storage is nil")
		}
		dataBytes, err := p.keyShareStorage.GetKeyData(ctx, keyID, p.thisNodeID)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load key data")
		}
		keyData, err = deserializeLocalPartySaveData(dataBytes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to deserialize key data")
		}
	}

	// 2. 执行 Resharing
	newKeyData, err := p.partyManager.executeResharing(
		ctx,
		keyID,
		oldNodeIDs,
		newNodeIDs,
		oldThreshold,
		newThreshold,
		p.thisNodeID,
		keyData,
	)
	if err != nil {
		return nil, errors.Wrap(err, "execute resharing failed")
	}

	// 3. 处理结果
	keyShare, publicKey, err := convertTSSKeyData(keyID, newKeyData, p.thisNodeID)
	if err != nil {
		return nil, errors.Wrap(err, "convert key data failed")
	}

	// 4. 更新本地记录
	newRecord := &gg18KeyRecord{
		KeyData:    newKeyData,
		PublicKey:  publicKey,
		Threshold:  newThreshold,
		TotalNodes: len(newNodeIDs),
		NodeIDs:    newNodeIDs,
	}
	p.saveKeyRecord(keyID, newRecord)

	// 5. 持久化新分片
	if p.keyShareStorage != nil {
		bytes, err := serializeLocalPartySaveData(newKeyData)
		if err != nil {
			return nil, errors.Wrap(err, "serialize new key data failed")
		}
		if err := p.keyShareStorage.StoreKeyData(ctx, keyID, p.thisNodeID, bytes); err != nil {
			return nil, errors.Wrap(err, "store new key data failed")
		}
	}

	return &KeyGenResponse{
		KeyShares: map[string]*KeyShare{p.thisNodeID: keyShare},
		PublicKey: publicKey,
	}, nil
}

// ProcessIncomingResharingMessage 处理接收到的 Resharing 消息
func (p *GG20Protocol) ProcessIncomingResharingMessage(ctx context.Context, sessionID string, fromNodeID string, msgBytes []byte, isBroadcast bool) error {
	return p.partyManager.ProcessIncomingResharingMessage(ctx, sessionID, fromNodeID, msgBytes, isBroadcast)
}

# MPCVault 技术方案分析与项目实施指南

**版本**: v1.0  
**文档类型**: 技术方案分析与实施指南  
**创建日期**: 2025-01-XX  
**基于**: MPCVault 技术文档 + go-mpc-wallet 项目代码

---

## 目录

- [1. MPCVault 技术方案分析](#1-mpcvault-技术方案分析)
- [2. TSS 与 SSS 技术对比](#2-tss-与-sss-技术对比)
- [3. 核心技术特性详解](#3-核心技术特性详解)
- [4. 在本项目中的实施方案](#4-在本项目中的实施方案)
- [5. 实施路线图](#5-实施路线图)
- [6. 技术实现细节](#6-技术实现细节)

---

## 1. MPCVault 技术方案分析

### 1.1 架构设计

MPCVault 采用 **3-of-3 MPC 配置**，密钥分片分布如下：

```
密钥分片分布：
├── 用户端：持有 1 个密钥分片
├── MPCVault 云环境 1：持有 1 个密钥分片（多个加密备份）
└── MPCVault 云环境 2：持有 1 个密钥分片（多个加密备份）

签名要求：需要所有 3 个分片才能签名
```

**核心优势**：
- **无对手方风险**：MPCVault 不持有所有密钥分片，无法单独控制资产
- **分布式安全**：密钥分片存储在不同云环境，无单点故障
- **用户控制**：用户始终持有 1 个分片，保持对资产的控制权

### 1.2 核心技术栈

| 技术 | 说明 | 用途 |
|------|------|------|
| **MPC (TSS)** | 阈值签名方案 | 在线签名服务，密钥永不完整存在 |
| **Hardened Derivation** | 强化密钥派生 | 每个地址使用独立派生密钥，隔离不同链 |
| **Key Refresh** | 密钥分片刷新 | 定期更新分片值，防止渐进式攻击 |
| **End-to-End Encryption** | 端到端加密 | Noise 协议 + ChaCha20-Poly1305 |
| **Personal Key Certificate** | 个人密钥证书 | Ed25519 密钥对，用于身份认证 |
| **Shamir Secret Sharing** | 密钥分片方案 | 备份恢复场景，管理加密私钥 |

### 1.3 与 Gnosis Safe 对比

| 特性 | Gnosis Safe | MPCVault |
|------|-------------|----------|
| **多地址管理** | ❌ 需要创建新的 Safe | ✅ 单个组织内多地址 |
| **多链支持** | ❌ 仅 EVM | ✅ 所有链（Bitcoin、Solana、Aptos 等） |
| **eth_sign 支持** | ❌ 不支持 | ✅ 支持（可用于 zk 应用） |
| **EVM 兼容性** | ⚠️ 网络错误会丢失资产 | ✅ 跨链桥支持 |
| **交易追踪** | ⚠️ 需要手动追踪 | ✅ 银行级交易历史 |

---

## 2. TSS 与 SSS 技术对比

### 2.1 技术原理对比

#### TSS (Threshold Signature Scheme) - 阈值签名方案

**原理**：
- 使用密码学协议（GG18/GG20/FROST）实现多方计算
- 密钥分片存储在多个节点
- 签名时节点协作，**无需恢复完整私钥**
- 密钥始终处于分片状态，永不完整存在

**数学基础**：
```
私钥 = share1 + share2 + share3 (在有限域上的加法)
签名 = MPC_Protocol(share1, share2, share3, message)
```

#### SSS (Shamir Secret Sharing) - 密钥分片方案

**原理**：
- 使用多项式插值实现密钥分片
- 需要恢复完整私钥才能使用
- 适合离线存储和备份场景

**数学基础**：
```
f(x) = a₀ + a₁x + a₂x² + ... + aₖ₋₁xᵏ⁻¹
其中 a₀ = 秘密值（私钥）
分片 = (x₁, f(x₁)), (x₂, f(x₂)), ..., (xₙ, f(xₙ))
恢复：使用 k 个分片通过拉格朗日插值恢复 f(0) = a₀
```

### 2.2 使用场景对比

| 维度 | TSS | SSS |
|------|-----|-----|
| **主要用途** | 在线签名服务 | 密钥备份恢复 |
| **密钥状态** | 永不完整存在 | 需要恢复完整私钥 |
| **使用场景** | 热钱包、实时签名 | 冷存储、灾难恢复 |
| **性能** | 实时签名（毫秒级） | 恢复需要时间 |
| **安全性** | 密钥始终分片 | 恢复时密钥完整存在 |
| **容错性** | 部分节点故障仍可签名 | 部分分片丢失可恢复 |
| **复杂度** | 高（密码学协议） | 低（多项式插值） |

### 2.3 混合使用方案

**推荐架构**：

```
日常使用：TSS（热钱包）
├── 3-of-3 MPC 配置
├── 实时签名服务
├── 密钥永不完整存在
└── 支持阈值容错

备份方案：SSS + 加密（冷存储）
├── 导出时用 Ed25519 公钥加密分片
├── 加密私钥可以用 SSS 分片管理
└── 实现 3-of-5 内部控制
```

---

## 3. 核心技术特性详解

### 3.1 Hardened Key Derivation（强化密钥派生）

**问题**：
- 非 MPC 钱包已普遍使用强化派生
- MPC 世界中，MPCVault 是唯一实现强化派生的提供商

**重要性**：
1. **资产隔离**：前团队成员无法追踪新添加的资产
2. **跨链安全**：子密钥泄露不影响主密钥和其他链资产
3. **地址隔离**：每个地址使用独立派生密钥，防止跨链签名重用攻击

**实现原理**：
```
根密钥 → chaincode → 派生密钥 1 → 地址 1
                → 派生密钥 2 → 地址 2
                → 派生密钥 3 → 地址 3
```

**在本项目中的实现**：

```go
// internal/mpc/key/derivation.go
package key

import (
    "crypto/hmac"
    "crypto/sha512"
    "encoding/binary"
)

// HardenedDeriveKey 强化派生密钥
func HardenedDeriveKey(masterKey []byte, chaincode []byte, index uint32) ([]byte, []byte, error) {
    // 使用 HMAC-SHA512 进行强化派生
    h := hmac.New(sha512.New, chaincode)
    
    // 写入索引（大端序，最高位设为 1 表示强化派生）
    indexBytes := make([]byte, 4)
    binary.BigEndian.PutUint32(indexBytes, index|0x80000000)
    
    h.Write([]byte{0x00}) // 主密钥前缀
    h.Write(masterKey)
    h.Write(indexBytes)
    
    result := h.Sum(nil)
    
    // 前 32 字节是派生密钥，后 32 字节是新的 chaincode
    derivedKey := result[:32]
    newChaincode := result[32:]
    
    return derivedKey, newChaincode, nil
}

// DeriveAddress 派生地址
func (s *Service) DeriveAddress(ctx context.Context, keyID string, chainType string, index uint32) (string, error) {
    // 1. 获取根密钥元数据
    keyMetadata, err := s.metadataStore.GetKeyMetadata(ctx, keyID)
    if err != nil {
        return "", errors.Wrap(err, "failed to get key metadata")
    }
    
    // 2. 使用 MPC 协议派生密钥（不恢复完整私钥）
    derivedKey, err := s.protocolEngine.DeriveKey(ctx, keyID, index)
    if err != nil {
        return "", errors.Wrap(err, "failed to derive key")
    }
    
    // 3. 根据链类型生成地址
    address, err := s.chainAdapter.GenerateAddress(chainType, derivedKey.PublicKey)
    if err != nil {
        return "", errors.Wrap(err, "failed to generate address")
    }
    
    return address, nil
}
```

### 3.2 Key Refresh（密钥分片刷新）

**原理**：
- **不是更换私钥**，而是**私钥重新分片**
- 公钥保持不变，私钥本身不变
- 分片值定期更新，但数学关系保持不变

**数学关系**：
```
原始状态：私钥 = share1 + share2 + share3
刷新后：  私钥 = share1' + share2' + share3'（新的分片值）
```

**安全意义**：
1. 防止渐进式攻击：旧分片失效
2. 无需更换地址：公钥不变
3. 无缝升级：用户无感知

**在本项目中的实现**：

```go
// internal/mpc/key/rotation.go
package key

// RotateKey 密钥分片刷新（Key Refresh）
func (s *Service) RotateKey(ctx context.Context, keyID string) (*KeyMetadata, error) {
    // 1. 获取当前密钥元数据
    keyMetadata, err := s.metadataStore.GetKeyMetadata(ctx, keyID)
    if err != nil {
        return nil, errors.Wrap(err, "failed to get key metadata")
    }
    
    // 2. 执行密钥刷新协议（MPC 协议内完成）
    // 注意：公钥保持不变，只是分片值更新
    newKeyShares, err := s.protocolEngine.RefreshKeyShares(ctx, keyID)
    if err != nil {
        return nil, errors.Wrap(err, "failed to refresh key shares")
    }
    
    // 3. 更新密钥分片存储
    for nodeID, share := range newKeyShares {
        if err := s.keyShareStorage.StoreKeyShare(ctx, keyID, nodeID, share.Share); err != nil {
            return nil, errors.Wrapf(err, "failed to store refreshed share for node %s", nodeID)
        }
    }
    
    // 4. 更新元数据（公钥不变，只更新时间戳）
    keyMetadata.UpdatedAt = time.Now()
    if err := s.metadataStore.UpdateKeyMetadata(ctx, keyMetadata); err != nil {
        return nil, errors.Wrap(err, "failed to update key metadata")
    }
    
    // 5. 记录审计日志
    s.auditLogger.LogEvent(ctx, &audit.Event{
        EventType: "KeyRefreshed",
        KeyID:     keyID,
        Operation: "rotate_key",
        Result:    "Success",
    })
    
    return keyMetadata, nil
}
```

### 3.3 End-to-End Encryption（端到端加密）

**技术栈**：
- **协议**：Noise Protocol IK（Interactive Key）
- **加密算法**：ChaCha20-Poly1305 AEAD
- **哈希算法**：Blake2s
- **架构**：零信任架构

**实现要点**：
- 所有节点间通信点对点加密
- 中继服务器无法获知实际消息内容
- 公钥固定（Public Key Pinning）

**在本项目中的实现**：

```go
// internal/mpc/communication/noise.go
package communication

import (
    "github.com/flynn/noise"
)

// NoiseTransport 实现 Noise 协议传输
type NoiseTransport struct {
    keyPair noise.DHKey
    handshake *noise.HandshakeState
}

// NewNoiseTransport 创建 Noise 传输实例
func NewNoiseTransport(initiator bool) (*NoiseTransport, error) {
    // 生成密钥对
    keyPair, err := noise.DH25519.GenerateKeypair(nil)
    if err != nil {
        return nil, errors.Wrap(err, "failed to generate keypair")
    }
    
    // 配置 Noise 协议（IK 模式）
    config := noise.Config{
        CipherSuite: noise.NewCipherSuite(
            noise.DH25519,
            noise.CipherChaChaPoly,
            noise.HashBLAKE2s,
        ),
        Pattern:   noise.HandshakeIK,
        Initiator: initiator,
        StaticKeypair: keyPair,
    }
    
    handshake, err := noise.NewHandshakeState(config)
    if err != nil {
        return nil, errors.Wrap(err, "failed to create handshake")
    }
    
    return &NoiseTransport{
        keyPair:   keyPair,
        handshake: handshake,
    }, nil
}

// Encrypt 加密消息
func (t *NoiseTransport) Encrypt(plaintext []byte) ([]byte, error) {
    ciphertext, _, _, err := t.handshake.WriteMessage(nil, plaintext)
    return ciphertext, err
}

// Decrypt 解密消息
func (t *NoiseTransport) Decrypt(ciphertext []byte) ([]byte, error) {
    plaintext, _, _, err := t.handshake.ReadMessage(nil, ciphertext)
    return plaintext, err
}
```

### 3.4 Personal Key Certificate（个人密钥证书）

**用途**：
- 每个用户拥有 Ed25519 密钥对
- 用于加密身份认证
- 支持零信任端到端加密架构
- 支持密钥分片在用户间安全传递

**在本项目中的实现**：

```go
// internal/mpc/auth/personal_cert.go
package auth

import (
    "crypto/ed25519"
    "crypto/rand"
)

// PersonalKeyCertificate 个人密钥证书
type PersonalKeyCertificate struct {
    PublicKey  ed25519.PublicKey
    PrivateKey ed25519.PrivateKey
}

// GeneratePersonalKeyCertificate 生成个人密钥证书
func GeneratePersonalKeyCertificate() (*PersonalKeyCertificate, error) {
    publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        return nil, errors.Wrap(err, "failed to generate ed25519 keypair")
    }
    
    return &PersonalKeyCertificate{
        PublicKey:  publicKey,
        PrivateKey: privateKey,
    }, nil
}

// Sign 使用个人密钥证书签名
func (c *PersonalKeyCertificate) Sign(message []byte) ([]byte, error) {
    return ed25519.Sign(c.PrivateKey, message), nil
}

// Verify 验证个人密钥证书签名
func (c *PersonalKeyCertificate) Verify(message, signature []byte) bool {
    return ed25519.Verify(c.PublicKey, message, signature)
}
```

### 3.5 Key Share Backup（密钥分片备份）

**核心问题**：
- 直接导出 3 个密钥分片不安全（参与人员都能看到）
- 难以建立内部控制（如 3-of-5 恢复）

**解决方案**：
1. 客户端生成 3 个 Ed25519 密钥对
2. 将 3 个公钥发送给服务端
3. 服务端使用 MPC 协议，用公钥加密密钥分片
4. 返回加密后的备份包
5. 客户端使用私钥解密

**备份包结构**：

```json
{
  "version": "1.0",
  "exported_key_shares": [
    {
      "key_id": "1a6bd986-aea3-47dd-9486-db4f42835599",
      "key_type": "KEY_TYPE_ECC_SECP256K1",
      "chaincode": "z8/koYVGF3m4rZqaMzqgf0ZRksopKgPQbRasqvRbjiI=",
      "encryption_pubkeys": [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPYXt2yGRW+ownNRH1f1Q2oGgewTxmVYehbrrjzqytMu",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBvsnVgHhbqUaD+xkkBF007E3YrESufbv2TB10e71+kk",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB0jeVUSmh17yVfBtsXdq5cxTqXlnHwwmXUjxqPMOx2v"
      ],
      "encrypted_shares": [
        "a6PXeNis/BmSI9JZ7riKEwRd+C56fjRu5zVxQtJiKU/CJXsi9LPKkf6e0ow67vVxNEIU2pGy6rCts1rEH1yWD0ONXUBop01fmHtwdt/Q=",
        "kudskDteKthLymwjs8Z+AC9nQRv/3XuvN4eocJEl9vmqS65fY5iiDYy8jlhrFwq+hQ51Gm9pwr9+3jGq/tgwzvaOgqxpk33r2HX3YLFlQ=",
        "ROR2iRgUyvW5zwqCZHkC6rk/zbPe8aNB2na4PKA16PsRHNHjBABN5mfVxOZXXM9yUF9zm7Gldw5NWUjthpah9vFFGGEfFilBatBqIyny0="
      ]
    }
  ],
  "timestamp": 1707118991467
}
```

**在本项目中的实现**：

```go
// internal/mpc/key/backup.go
package key

import (
    "crypto/ed25519"
    "encoding/json"
)

// BackupRequest 备份请求
type BackupRequest struct {
    EncryptionPubKeys []string // 客户端提供的 Ed25519 公钥列表
}

// BackupPackage 备份包
type BackupPackage struct {
    Version          string            `json:"version"`
    ExportedKeyShares []ExportedKeyShare `json:"exported_key_shares"`
    Timestamp        int64             `json:"timestamp"`
}

// ExportedKeyShare 导出的密钥分片
type ExportedKeyShare struct {
    KeyID           string   `json:"key_id"`
    KeyType         string   `json:"key_type"`
    Chaincode       string   `json:"chaincode"`
    EncryptionPubKeys []string `json:"encryption_pubkeys"`
    EncryptedShares []string  `json:"encrypted_shares"`
}

// ExportKeyShares 导出密钥分片（使用 MPC 协议加密）
func (s *Service) ExportKeyShares(ctx context.Context, req *BackupRequest) (*BackupPackage, error) {
    // 1. 验证权限（需要所有活跃成员批准）
    if err := s.verifyBackupPermission(ctx); err != nil {
        return nil, errors.Wrap(err, "backup permission denied")
    }
    
    // 2. 获取所有根密钥
    keys, err := s.metadataStore.ListRootKeys(ctx)
    if err != nil {
        return nil, errors.Wrap(err, "failed to list root keys")
    }
    
    // 3. 对每个密钥执行 MPC 加密导出
    var exportedShares []ExportedKeyShare
    for _, keyMetadata := range keys {
        // 使用 MPC 协议加密密钥分片
        encryptedShares, err := s.protocolEngine.EncryptKeyShares(ctx, keyMetadata.KeyID, req.EncryptionPubKeys)
        if err != nil {
            return nil, errors.Wrapf(err, "failed to encrypt key shares for key %s", keyMetadata.KeyID)
        }
        
        exportedShare := ExportedKeyShare{
            KeyID:            keyMetadata.KeyID,
            KeyType:          keyMetadata.KeyType,
            Chaincode:        keyMetadata.Chaincode,
            EncryptionPubKeys: req.EncryptionPubKeys,
            EncryptedShares:  encryptedShares,
        }
        exportedShares = append(exportedShares, exportedShare)
    }
    
    // 4. 构建备份包
    backupPackage := &BackupPackage{
        Version:          "1.0",
        ExportedKeyShares: exportedShares,
        Timestamp:        time.Now().UnixMilli(),
    }
    
    // 5. 记录审计日志
    s.auditLogger.LogEvent(ctx, &audit.Event{
        EventType: "KeySharesExported",
        Operation: "export_key_shares",
        Result:    "Success",
    })
    
    return backupPackage, nil
}

// 使用 Shamir Secret Sharing 管理加密私钥（可选）
func (s *Service) CreateBackupWithShamir(ctx context.Context, req *BackupRequest, shamirParts, shamirThreshold int) (*BackupPackage, error) {
    // 1. 导出密钥分片
    backupPackage, err := s.ExportKeyShares(ctx, req)
    if err != nil {
        return nil, err
    }
    
    // 2. 对每个加密私钥使用 Shamir 分片
    // 注意：这里是对 Ed25519 私钥进行 Shamir 分片，不是对密钥分片本身
    for i, pubKey := range req.EncryptionPubKeys {
        // 假设客户端提供了对应的私钥（实际应该由客户端管理）
        // 这里只是示例，实际实现需要客户端配合
        // privKey := getPrivateKeyForPublicKey(pubKey)
        // shamirShares, err := shamir.Split(privKey, shamirParts, shamirThreshold)
        // ...
    }
    
    return backupPackage, nil
}
```

---

## 4. 在本项目中的实施方案

### 4.1 架构对齐

**当前项目架构**：
```
Coordinator 节点（协调签名流程）
├── 创建签名会话
├── 选择参与节点
├── 协调签名协议
└── 聚合签名分片

Participant 节点（存储分片，参与签名）
├── 存储密钥分片（加密）
├── 参与 DKG 协议
├── 参与签名协议
└── 提供签名分片
```

**MPCVault 架构对齐**：
- **Coordinator** = MPCVault 服务端（2 个云环境）
- **Participant** = 用户端 + MPCVault 服务端节点
- **3-of-3 配置** = 用户 1 个分片 + MPCVault 2 个分片

### 4.2 技术栈对齐

| MPCVault 技术 | 本项目实现 | 状态 |
|--------------|-----------|------|
| **TSS (GG18/GG20/FROST)** | `internal/mpc/protocol/` | ✅ 已实现 |
| **Hardened Derivation** | 需要实现 | ⚠️ 待实现 |
| **Key Refresh** | `internal/mpc/key/rotation.go` | ⚠️ 待完善 |
| **End-to-End Encryption** | 需要实现 Noise 协议 | ⚠️ 待实现 |
| **Personal Key Certificate** | 需要实现 | ⚠️ 待实现 |
| **Key Share Backup** | 需要实现 | ⚠️ 待实现 |
| **Shamir Secret Sharing** | 需要引入库 | ⚠️ 待实现 |

### 4.3 实施优先级

**Phase 1: 核心功能（已完成）**
- ✅ TSS 协议实现（GG18/GG20/FROST）
- ✅ DKG 分布式密钥生成
- ✅ 阈值签名服务
- ✅ 密钥分片加密存储

**Phase 2: 安全增强（高优先级）**
- ⚠️ Hardened Key Derivation
- ⚠️ Key Refresh（密钥分片刷新）
- ⚠️ End-to-End Encryption（Noise 协议）

**Phase 3: 用户体验（中优先级）**
- ⚠️ Personal Key Certificate
- ⚠️ Key Share Backup（加密导出）
- ⚠️ Shamir Secret Sharing（备份管理）

**Phase 4: 高级特性（低优先级）**
- ⚠️ 多链地址管理
- ⚠️ 交易历史追踪
- ⚠️ 策略引擎增强

---

## 5. 实施路线图

### 5.1 短期目标（1-2 个月）

1. **Hardened Key Derivation**
   - 实现强化密钥派生算法
   - 支持多地址生成
   - 每个地址独立派生密钥

2. **Key Refresh**
   - 实现密钥分片刷新协议
   - 支持定期自动刷新
   - 公钥保持不变

3. **End-to-End Encryption**
   - 集成 Noise 协议库
   - 实现节点间加密通信
   - 替换现有 gRPC 传输

### 5.2 中期目标（3-4 个月）

1. **Personal Key Certificate**
   - 实现 Ed25519 密钥对生成
   - 集成到用户认证系统
   - 支持加密身份认证

2. **Key Share Backup**
   - 实现 MPC 加密导出
   - 支持备份包生成
   - 提供恢复工具

3. **Shamir Secret Sharing**
   - 集成 Shamir 库
   - 实现加密私钥分片管理
   - 支持内部控制方案

### 5.3 长期目标（5-6 个月）

1. **多链支持增强**
   - 支持 Bitcoin、Solana、Aptos 等
   - 统一的地址管理
   - 跨链桥支持

2. **企业级功能**
   - 交易历史追踪
   - 策略引擎增强
   - 审计日志完善

---

## 6. 技术实现细节

### 6.1 Hardened Derivation 实现

```go
// internal/mpc/key/derivation.go
package key

import (
    "crypto/hmac"
    "crypto/sha512"
    "encoding/binary"
    "math/big"
)

// HDKey 分层确定性密钥
type HDKey struct {
    Key       []byte
    Chaincode []byte
    Depth     uint8
    Index     uint32
}

// DeriveHardened 强化派生
func (k *HDKey) DeriveHardened(index uint32) (*HDKey, error) {
    // 使用 HMAC-SHA512
    h := hmac.New(sha512.New, k.Chaincode)
    
    // 写入 0x00 + 主密钥 + 索引（最高位设为 1）
    h.Write([]byte{0x00})
    h.Write(k.Key)
    
    indexBytes := make([]byte, 4)
    binary.BigEndian.PutUint32(indexBytes, index|0x80000000)
    h.Write(indexBytes)
    
    result := h.Sum(nil)
    
    return &HDKey{
        Key:       result[:32],
        Chaincode: result[32:],
        Depth:     k.Depth + 1,
        Index:     index,
    }, nil
}

// DeriveAddress 派生地址
func (s *Service) DeriveAddress(ctx context.Context, keyID string, chainType string, index uint32) (string, error) {
    // 1. 获取根密钥元数据
    keyMetadata, err := s.metadataStore.GetKeyMetadata(ctx, keyID)
    if err != nil {
        return "", errors.Wrap(err, "failed to get key metadata")
    }
    
    // 2. 使用 MPC 协议派生密钥（不恢复完整私钥）
    derivedPubKey, err := s.protocolEngine.DerivePublicKey(ctx, keyID, index)
    if err != nil {
        return "", errors.Wrap(err, "failed to derive public key")
    }
    
    // 3. 根据链类型生成地址
    address, err := s.chainAdapter.GenerateAddress(chainType, derivedPubKey)
    if err != nil {
        return "", errors.Wrap(err, "failed to generate address")
    }
    
    return address, nil
}
```

### 6.2 Key Refresh 实现

```go
// internal/mpc/protocol/key_refresh.go
package protocol

// RefreshKeyShares 刷新密钥分片（MPC 协议内完成）
func (e *Engine) RefreshKeyShares(ctx context.Context, keyID string) (map[string]*KeyShare, error) {
    // 1. 获取当前密钥分片信息
    keyMetadata, err := e.metadataStore.GetKeyMetadata(ctx, keyID)
    if err != nil {
        return nil, errors.Wrap(err, "failed to get key metadata")
    }
    
    // 2. 执行密钥刷新协议
    // 协议原理：
    // - 每个节点生成随机数 r_i
    // - 计算新的分片：share_i' = share_i + r_i - r_{i-1}
    // - 公钥保持不变：sum(share_i') = sum(share_i) = 私钥
    
    refreshReq := &KeyRefreshRequest{
        KeyID:      keyID,
        Threshold:  keyMetadata.Threshold,
        TotalNodes: keyMetadata.TotalNodes,
        NodeIDs:    keyMetadata.NodeIDs,
    }
    
    newShares, err := e.executeKeyRefreshProtocol(ctx, refreshReq)
    if err != nil {
        return nil, errors.Wrap(err, "failed to execute key refresh protocol")
    }
    
    return newShares, nil
}

// executeKeyRefreshProtocol 执行密钥刷新协议
func (e *Engine) executeKeyRefreshProtocol(ctx context.Context, req *KeyRefreshRequest) (map[string]*KeyShare, error) {
    // Round 1: 每个节点生成随机数并交换承诺
    // Round 2: 交换随机数并验证承诺
    // Round 3: 计算新的分片值
    // Round 4: 验证新分片有效性
    
    // 实现细节...
    return nil, nil
}
```

### 6.3 Noise 协议集成

```go
// internal/mpc/communication/noise_transport.go
package communication

import (
    "github.com/flynn/noise"
    "io"
)

// NoiseTransport 实现 Noise 协议传输层
type NoiseTransport struct {
    conn      io.ReadWriteCloser
    handshake *noise.HandshakeState
    cipher    *noise.CipherState
    isReady   bool
}

// NewNoiseTransport 创建 Noise 传输实例
func NewNoiseTransport(conn io.ReadWriteCloser, initiator bool, remotePubKey []byte) (*NoiseTransport, error) {
    // 生成本地密钥对
    keyPair, err := noise.DH25519.GenerateKeypair(nil)
    if err != nil {
        return nil, errors.Wrap(err, "failed to generate keypair")
    }
    
    // 配置 Noise 协议（IK 模式）
    config := noise.Config{
        CipherSuite: noise.NewCipherSuite(
            noise.DH25519,        // 密钥交换
            noise.CipherChaChaPoly, // 加密算法
            noise.HashBLAKE2s,    // 哈希算法
        ),
        Pattern:   noise.HandshakeIK,
        Initiator: initiator,
        StaticKeypair: keyPair,
        PeerStatic:    remotePubKey,
    }
    
    handshake, err := noise.NewHandshakeState(config)
    if err != nil {
        return nil, errors.Wrap(err, "failed to create handshake")
    }
    
    return &NoiseTransport{
        conn:      conn,
        handshake: handshake,
        isReady:   false,
    }, nil
}

// Handshake 执行握手
func (t *NoiseTransport) Handshake() error {
    // 发送握手消息
    message, cs1, cs2, err := t.handshake.WriteMessage(nil, nil)
    if err != nil {
        return errors.Wrap(err, "failed to write handshake message")
    }
    
    if _, err := t.conn.Write(message); err != nil {
        return errors.Wrap(err, "failed to send handshake message")
    }
    
    // 接收响应
    response := make([]byte, 1024)
    n, err := t.conn.Read(response)
    if err != nil {
        return errors.Wrap(err, "failed to read handshake response")
    }
    
    _, cs1, cs2, err = t.handshake.ReadMessage(nil, response[:n])
    if err != nil {
        return errors.Wrap(err, "failed to read handshake message")
    }
    
    // 设置加密状态
    if t.handshake.Config.Initiator {
        t.cipher = cs1
    } else {
        t.cipher = cs2
    }
    
    t.isReady = true
    return nil
}

// Write 加密写入
func (t *NoiseTransport) Write(data []byte) (int, error) {
    if !t.isReady {
        return 0, errors.New("handshake not completed")
    }
    
    ciphertext := t.cipher.Encrypt(nil, nil, data)
    return t.conn.Write(ciphertext)
}

// Read 解密读取
func (t *NoiseTransport) Read(data []byte) (int, error) {
    if !t.isReady {
        return 0, errors.New("handshake not completed")
    }
    
    ciphertext := make([]byte, len(data)+16) // +16 for AEAD tag
    n, err := t.conn.Read(ciphertext)
    if err != nil {
        return 0, err
    }
    
    plaintext, err := t.cipher.Decrypt(nil, nil, ciphertext[:n])
    if err != nil {
        return 0, errors.Wrap(err, "failed to decrypt")
    }
    
    copy(data, plaintext)
    return len(plaintext), nil
}
```

### 6.4 Shamir Secret Sharing 集成

```go
// internal/mpc/key/shamir.go
package key

import (
    "github.com/hashicorp/vault/shamir"
)

// SplitEncryptionKey 使用 Shamir 分片加密私钥
func SplitEncryptionKey(privateKey []byte, parts, threshold int) ([][]byte, error) {
    if parts < threshold {
        return nil, errors.New("parts must be >= threshold")
    }
    
    shares, err := shamir.Split(privateKey, parts, threshold)
    if err != nil {
        return nil, errors.Wrap(err, "failed to split key using Shamir")
    }
    
    return shares, nil
}

// CombineEncryptionKey 恢复加密私钥
func CombineEncryptionKey(shares [][]byte) ([]byte, error) {
    if len(shares) < 2 {
        return nil, errors.New("need at least 2 shares to combine")
    }
    
    key, err := shamir.Combine(shares)
    if err != nil {
        return nil, errors.Wrap(err, "failed to combine shares")
    }
    
    return key, nil
}

// CreateBackupWithShamir 创建带 Shamir 控制的备份
func (s *Service) CreateBackupWithShamir(ctx context.Context, req *BackupRequest, shamirParts, shamirThreshold int) (*BackupPackage, error) {
    // 1. 导出密钥分片（加密）
    backupPackage, err := s.ExportKeyShares(ctx, req)
    if err != nil {
        return nil, err
    }
    
    // 2. 对每个 Ed25519 私钥使用 Shamir 分片
    // 注意：实际实现中，私钥应该由客户端管理
    // 这里只是展示如何使用 Shamir 管理加密私钥
    
    // 示例：假设客户端提供了私钥（实际不应该）
    // for i, pubKey := range req.EncryptionPubKeys {
    //     privKey := getPrivateKeyForPublicKey(pubKey) // 客户端提供
    //     shamirShares, err := SplitEncryptionKey(privKey, shamirParts, shamirThreshold)
    //     // 分发给多个人员，需要 shamirThreshold 个人合作才能恢复私钥
    // }
    
    return backupPackage, nil
}
```

---

## 7. 总结

### 7.1 核心技术要点

1. **TSS vs SSS**：
   - TSS 用于在线签名（密钥永不完整存在）
   - SSS 用于备份恢复（需要恢复完整私钥）
   - 两者互补，共同构建安全体系

2. **Hardened Derivation**：
   - 每个地址使用独立派生密钥
   - 防止跨链攻击和资产追踪
   - MPCVault 的专利技术

3. **Key Refresh**：
   - 定期刷新分片值，不改变私钥
   - 防止渐进式攻击
   - 公钥和地址保持不变

4. **End-to-End Encryption**：
   - Noise 协议 + ChaCha20-Poly1305
   - 零信任架构
   - 中继服务器无法获知消息内容

5. **Key Share Backup**：
   - 使用客户端公钥加密分片
   - 支持 Shamir 内部控制
   - 实现安全的密钥导出

### 7.2 实施建议

1. **优先级排序**：
   - 先实现 Hardened Derivation 和 Key Refresh（安全核心）
   - 再实现 End-to-End Encryption（通信安全）
   - 最后实现备份和恢复功能（用户体验）

2. **技术选型**：
   - Noise 协议：使用 `github.com/flynn/noise`
   - Shamir：使用 `github.com/hashicorp/vault/shamir`
   - Ed25519：使用标准库 `crypto/ed25519`

3. **测试策略**：
   - 单元测试：每个功能模块
   - 集成测试：端到端流程
   - 安全测试：密钥分片安全性验证

---

**文档维护**：
- 本文档应随代码实现同步更新
- 每次重大功能实现后，更新相应章节
- 技术选型变更时，及时更新文档

**参考资源**：
- [MPCVault 技术文档](https://docs.mpcvault.com/)
- [Noise 协议规范](https://noiseprotocol.org/)
- [Shamir Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
- **TSS 协议论文**：
  - [GG18: Fast Multiparty Threshold ECDSA](https://eprint.iacr.org/2019/114.pdf)
  - [GG20: One Round Threshold ECDSA](https://eprint.iacr.org/2020/540.pdf)
  - [FROST: Two-Round Threshold Schnorr](https://eprint.iacr.org/2020/852.pdf)

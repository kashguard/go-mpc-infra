# MPC 钱包分层架构技术方案

**版本**: v2.1  
**创建日期**: 2025-01-XX  
**状态**: 技术方案设计阶段  
**参考**: [MPCVault 文档](https://docs.mpcvault.com/docs/)

---

## 目录

- [1. 概述](#1-概述)
- [2. 分层架构设计](#2-分层架构设计)
- [3. MPC 基础设施层](#3-mpc-基础设施层)
- [4. 应用层：MPCVault Server (2B)](#4-应用层mpcvault-server-2b)
- [5. 应用层：个人钱包 (2C)](#5-应用层个人钱包-2c)
- [6. 认证系统设计](#6-认证系统设计)
- [7. 需要修改完善的地方](#7-需要修改完善的地方)
- [8. 实施路线图](#8-实施路线图)

---

## 1. 概述

### 1.1 设计目标

将 MPC 相关功能分层设计：

- **MPC 基础设施层**：提供 DKG、签名、密钥管理等核心能力
- **应用层（2B）**：MPCVault Server，面向团队的资产管理
- **应用层（2C）**：个人钱包，面向个人用户

### 1.2 核心特性

- ✅ **分层架构**：基础设施层与应用层分离
- ✅ **MPC 基础设施**：DKG、阈值签名、密钥管理（2-of-3）
- ✅ **SSS 备份方案（分片式备份）**：对每个MPC分片分别进行SSS备份，密钥永不完整存在
- ✅ **MPCVault Server (2B)**：Organization → Vault → Wallet 层级结构
- ✅ **个人钱包 (2C)**：简化的个人用户钱包
- ✅ **Google/Apple 登录**：支持 OAuth2 和 Passkey 认证
- ✅ **密钥备份分片下发**：服务器端生成SSS备份分片，安全下发到客户端

### 1.3 架构分层

| 层级 | 职责 | 模块 |
|------|------|------|
| **应用层 (2B)** | MPCVault Server | Organization, Vault, Wallet, Team, SigningRequest |
| **应用层 (2C)** | 个人钱包 | PersonalWallet, User |
| **基础设施层** | MPC 核心能力 | Protocol, Key, Signing, Session, Node, Storage |

---

## 2. 分层架构设计

### 2.1 整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        客户端 APP                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Google/Apple 登录 (OAuth2 + Passkey)                      │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  密钥分片存储 (Secure Enclave/TrustZone)                  │  │
│  │  - 分片1：客户端持有                                       │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  MPC 客户端 SDK                                           │  │
│  │  - 参与 DKG                                                │  │
│  │  - 参与阈值签名                                            │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                          ↕ HTTPS/gRPC
┌─────────────────────────────────────────────────────────────────┐
│                   应用层：MPCVault Server (2B)                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Organization 管理                                        │  │
│  │  - 创建组织                                                │  │
│  │  - 成员管理                                                │  │
│  │  - 角色权限                                                │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Vault 管理                                               │  │
│  │  - 创建 Vault（对应根密钥，通过DKG生成）                   │  │
│  │  - Vault 成员管理                                         │  │
│  │  - 审批策略                                                │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Wallet 管理                                              │  │
│  │  - 从 Vault 派生 Wallet（Hardened Derivation）            │  │
│  │  - 多链地址管理                                            │  │
│  │  - 交易管理                                                │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  SigningRequest 管理                                      │  │
│  │  - 创建签名请求                                            │  │
│  │  - 审批流程                                                │  │
│  │  - 触发 MPC 签名                                           │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                          ↕ 调用
┌─────────────────────────────────────────────────────────────────┐
│                  MPC 基础设施层                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Protocol Engine (GG18/GG20/FROST)                        │  │
│  │  - DKG 协议执行                                            │  │
│  │  - 阈值签名协议执行                                        │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Key Service                                              │  │
│  │  - 密钥生成（DKG）                                         │  │
│  │  - 密钥管理                                                │  │
│  │  - 密钥派生（Hardened Derivation）                        │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Signing Service                                          │  │
│  │  - 阈值签名                                                │  │
│  │  - 签名验证                                                │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Session Manager                                          │  │
│  │  - DKG 会话管理                                           │  │
│  │  - 签名会话管理                                            │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Node Manager                                             │  │
│  │  - 节点注册                                                │  │
│  │  - 节点发现                                                │  │
│  │  - 客户端节点管理                                          │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Storage                                                  │  │
│  │  - 密钥元数据存储                                          │  │
│  │  - 密钥分片存储（加密）                                    │  │
│  │  - 会话存储                                                │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 2-of-3 MPC 分片分配

**核心设计**：签名由服务器2个代理节点完成，客户端分片仅用于备份

```
密钥分片分配（2-of-3 MPC）：
├── 分片1：服务器代理1（参与签名）
│   ├── 存储位置：服务器 TEE 环境或加密存储
│   ├── 保护方式：TLS 加密传输 + 加密存储
│   ├── 用途：参与阈值签名（必须）
│   └── 控制方：服务提供商
│
├── 分片2：服务器代理2（参与签名）
│   ├── 存储位置：另一个服务器 TEE 环境或加密存储
│   ├── 保护方式：TLS 加密传输 + 加密存储
│   ├── 用途：参与阈值签名（必须）
│   └── 控制方：服务提供商
│
└── 分片3：客户端APP（仅备份，不参与签名）
    ├── 存储位置：设备 Secure Enclave/TrustZone
    ├── 保护方式：生物认证（FaceID/TouchID/指纹）
    ├── 用途：备份恢复（不参与签名）
    └── 控制方：用户本人
```

**签名流程**：
- ✅ 签名时只需要服务器2个代理节点参与
- ✅ 客户端不需要在线，用户体验更好
- ✅ 客户端分片仅用于备份恢复场景

### 2.3 SSS 备份方案

**为什么使用 SSS 而不是 MPC 分片作为备份**：

1. **SSS 更适合备份场景**：
   - 不需要参与签名协议
   - 只需要存储分片，恢复时组合即可
   - 可以分成更多分片（如 3-of-5），提高容错性

2. **MPC 分片不适合备份**：
   - MPC 分片是协议相关的，不能直接用于恢复
   - 需要参与完整的 MPC 协议才能使用

**SSS 备份架构**：

```
密钥备份方案（SSS 3-of-5）：
├── 备份分片1：客户端APP
│   ├── 存储位置：设备 Secure Enclave/TrustZone
│   ├── 保护方式：生物认证
│   └── 用途：用户备份
│
├── 备份分片2：服务器备份存储1
│   ├── 存储位置：服务器加密存储
│   └── 用途：服务器备份
│
├── 备份分片3：服务器备份存储2
│   ├── 存储位置：另一个服务器加密存储
│   └── 用途：服务器备份
│
├── 备份分片4：云存储（可选）
│   ├── 存储位置：加密云存储
│   └── 用途：额外备份
│
└── 备份分片5：用户邮箱/密码管理器（可选）
    ├── 存储位置：加密后存储
    └── 用途：用户额外备份
```

**密钥生命周期**：

```
1. 密钥生成阶段
   ├── 执行 2-of-3 MPC DKG
   │   ├── 分片1：server-proxy-1（参与签名）
   │   ├── 分片2：server-proxy-2（参与签名）
   │   └── 分片3：client-{userID}（不参与签名，仅备份）
   │
   └── 生成 SSS 备份分片（分片式备份）
       ├── 对每个MPC分片分别进行SSS备份（3-of-5）
       ├── server-proxy-1 的分片 → 5个SSS备份分片
       ├── server-proxy-2 的分片 → 5个SSS备份分片
       ├── client-{userID} 的分片 → 5个SSS备份分片
       └── 每个MPC分片的备份分片1 → 客户端APP（下发）

2. 签名阶段
   └── 使用 2-of-3 MPC TSS
       ├── server-proxy-1 参与
       ├── server-proxy-2 参与
       └── 客户端不参与（离线也可签名）

3. 恢复阶段（分片式恢复）
   └── 使用 SSS 恢复每个MPC分片
       ├── 恢复 server-proxy-1 的分片（收集至少3个备份分片）
       ├── 恢复 server-proxy-2 的分片（收集至少3个备份分片）
       └── 恢复 client-{userID} 的分片（可选，收集至少3个备份分片）
       └── 密钥永不完整存在，只恢复需要的MPC分片
```

### 2.4 Vault 和 Wallet 层级关系

参考 [MPCVault 架构](https://docs.mpcvault.com/docs/)，设计如下层级：

```
Organization (组织)
    ├── Vault 1 (金库1)
    │   ├── 根密钥 (通过DKG生成，2-of-3)
    │   ├── SSS备份分片 (3-of-5)
    │   ├── Wallet 1 (从Vault派生，Ethereum地址)
    │   ├── Wallet 2 (从Vault派生，Bitcoin地址)
    │   └── Wallet 3 (从Vault派生，Solana地址)
    │
    └── Vault 2 (金库2)
        ├── 根密钥 (通过DKG生成，2-of-3)
        ├── SSS备份分片 (3-of-5)
        ├── Wallet 1 (从Vault派生)
        └── Wallet 2 (从Vault派生)
```

**关键概念**：
- **Vault**：对应一个根密钥（通过2-of-3 DKG生成），使用Hardened Derivation派生多个Wallet
- **Wallet**：从Vault派生的地址，每个Wallet对应一个链类型和地址
- **Hardened Derivation**：每个Wallet使用独立的派生密钥，隔离不同链的资产
- **SSS备份**：使用Shamir Secret Sharing生成备份分片，用于密钥恢复

---

## 3. MPC 基础设施层

### 3.1 基础设施层职责

**核心原则**：基础设施层只提供 MPC 核心能力，不涉及业务逻辑

**主要模块**：

| 模块 | 职责 | 位置 |
|------|------|------|
| **Protocol Engine** | DKG和签名协议执行 | `internal/mpc/protocol/` |
| **Key Service** | 密钥生成、管理、派生 | `internal/mpc/key/` |
| **Signing Service** | 阈值签名、验证 | `internal/mpc/signing/` |
| **Session Manager** | DKG和签名会话管理 | `internal/mpc/session/` |
| **Node Manager** | 节点注册、发现、管理 | `internal/mpc/node/` |
| **Storage** | 密钥元数据、分片、会话存储 | `internal/mpc/storage/` |

### 3.2 基础设施层接口设计

#### 3.2.1 Key Service 接口

```go
// KeyService 密钥服务接口（基础设施层）
type KeyService interface {
    // CreateRootKey 创建根密钥（执行DKG）
    // 返回：keyID, publicKey, keyShares
    CreateRootKey(ctx context.Context, req *CreateRootKeyRequest) (*RootKeyMetadata, error)
    
    // GetRootKey 获取根密钥信息
    GetRootKey(ctx context.Context, keyID string) (*RootKeyMetadata, error)
    
    // DeriveWalletKey 从根密钥派生钱包密钥
    // 使用 Hardened Derivation，每个Wallet独立派生
    DeriveWalletKey(ctx context.Context, rootKeyID string, chainType string, index uint32) (*WalletKeyMetadata, error)
    
    // DeleteRootKey 删除根密钥
    DeleteRootKey(ctx context.Context, keyID string) error
}
```

#### 3.2.2 Signing Service 接口

```go
// SigningService 签名服务接口（基础设施层）
type SigningService interface {
    // ThresholdSign 阈值签名
    // 不涉及业务逻辑，只执行MPC签名协议
    ThresholdSign(ctx context.Context, req *SignRequest) (*SignResponse, error)
    
    // VerifySignature 验证签名
    VerifySignature(ctx context.Context, sig *Signature, msg []byte, pubKey *PublicKey) (bool, error)
}
```

### 3.3 基础设施层数据模型

**RootKeyMetadata**（根密钥元数据）：
```go
type RootKeyMetadata struct {
    KeyID        string    // 根密钥ID
    PublicKey    string    // 公钥
    Algorithm    string    // 算法（ECDSA, EdDSA）
    Curve        string    // 曲线（secp256k1, Ed25519）
    Protocol     string    // 协议（gg18, gg20, frost）
    Threshold    int       // 阈值（2-of-3）
    TotalNodes   int       // 总节点数（3）
    Status       string    // 状态（Active, Inactive, Deleted）
    CreatedAt    time.Time
    UpdatedAt    time.Time
}
```

**WalletKeyMetadata**（钱包密钥元数据）：
```go
type WalletKeyMetadata struct {
    WalletID     string    // 钱包ID
    RootKeyID    string    // 关联的根密钥ID
    ChainType    string    // 链类型（ethereum, bitcoin, solana）
    Address      string    // 区块链地址
    DeriveIndex  uint32    // 派生索引
    PublicKey    string    // 派生后的公钥
    CreatedAt    time.Time
}
```

### 3.4 基础设施层与应用层的交互

#### 3.4.1 通信方式

**架构设计**：基础设施层和应用层完全分离，独立代码库和独立部署，通过 gRPC 通信

**核心特点**：
- 基础设施层作为独立服务运行
- 应用层通过 gRPC 调用基础设施层
- 使用 mTLS 双向认证保证安全
- 支持多应用层共享基础设施层

**部署架构**：
```
┌─────────────────────────────────────┐
│  应用层 Server (MPCVault Server)    │
│  ┌───────────────────────────────┐ │
│  │  Vault Service                │ │
│  │  Wallet Service                │ │
│  └───────────────────────────────┘ │
└─────────────────────────────────────┘
              ↕ gRPC/HTTP (认证)
┌─────────────────────────────────────┐
│  MPC 基础设施层 Service              │
│  ┌───────────────────────────────┐ │
│  │  Key Service (gRPC Server)     │ │
│  │  Signing Service (gRPC Server) │ │
│  └───────────────────────────────┘ │
└─────────────────────────────────────┘
```

**认证机制**：

**推荐方案：mTLS + JWT 双重认证（最佳安全性和灵活性）**

对于支持多个应用层应用且重点考虑安全性的场景，推荐使用 **mTLS + JWT 双重认证**：

- **mTLS（Mutual TLS）**：作为第一层认证，验证应用层身份
- **JWT Token**：作为第二层授权，支持细粒度权限控制

**架构优势**：
- ✅ **最高安全性**：mTLS 提供双向认证，防止中间人攻击
- ✅ **多应用层支持**：每个应用层有独立的客户端证书，便于管理和审计
- ✅ **细粒度授权**：JWT Token 可以携带应用层ID、权限范围等信息
- ✅ **证书撤销**：可以快速撤销特定应用层的访问权限
- ✅ **审计追踪**：可以精确追踪每个应用层的操作

**实现方案**：

```go
// 1. mTLS 认证（基础设施层服务端）
func NewGRPCServer(cfg config.Server) (*grpc.Server, error) {
    // 加载服务器证书
    serverCert, err := tls.LoadX509KeyPair(cfg.TLS.ServerCert, cfg.TLS.ServerKey)
    if err != nil {
        return nil, err
    }
    
    // 加载CA证书（用于验证客户端证书）
    caCert, err := os.ReadFile(cfg.TLS.CACert)
    if err != nil {
        return nil, err
    }
    caCertPool := x509.NewCertPool()
    if !caCertPool.AppendCertsFromPEM(caCert) {
        return nil, errors.New("failed to append CA cert")
    }
    
    // 配置 mTLS
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{serverCert},
        ClientAuth:   tls.RequireAndVerifyClientCert, // 要求客户端证书
        ClientCAs:    caCertPool,
        MinVersion:   tls.VersionTLS13, // 使用 TLS 1.3
    }
    
    creds := credentials.NewTLS(tlsConfig)
    
    // 创建 gRPC 服务器，添加认证拦截器
    server := grpc.NewServer(
        grpc.Creds(creds),
        grpc.UnaryInterceptor(authInterceptor), // mTLS + JWT 双重认证
    )
    
    // 注册服务
    pb.RegisterKeyServiceServer(server, keyService)
    pb.RegisterSigningServiceServer(server, signingService)
    
    return server, nil
}

// 2. 认证拦截器（mTLS + JWT 双重验证）
func authInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
    // 第一步：验证 mTLS 客户端证书
    peer, ok := peer.FromContext(ctx)
    if !ok {
        return nil, status.Error(codes.Unauthenticated, "failed to get peer")
    }
    
    tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
    if !ok {
        return nil, status.Error(codes.Unauthenticated, "failed to get TLS info")
    }
    
    if len(tlsInfo.State.PeerCertificates) == 0 {
        return nil, status.Error(codes.Unauthenticated, "no client certificate")
    }
    
    clientCert := tlsInfo.State.PeerCertificates[0]
    
    // 验证证书CN（Common Name）或SAN（Subject Alternative Name）
    // 从证书中提取应用层标识
    appLayerID := clientCert.Subject.CommonName
    if appLayerID == "" {
        // 尝试从 SAN 中获取
        for _, san := range clientCert.DNSNames {
            if strings.HasPrefix(san, "app-") {
                appLayerID = san
                break
            }
        }
    }
    
    // 验证应用层是否在允许列表中
    allowedAppLayers, err := getAllowedAppLayers(ctx)
    if err != nil {
        return nil, status.Error(codes.Internal, "failed to get allowed app layers")
    }
    
    if !contains(allowedAppLayers, appLayerID) {
        return nil, status.Error(codes.PermissionDenied, fmt.Sprintf("unauthorized app layer: %s", appLayerID))
    }
    
    // 第二步：验证 JWT Token（可选，用于细粒度授权）
    md, ok := metadata.FromIncomingContext(ctx)
    if ok {
        authHeaders := md.Get("authorization")
        if len(authHeaders) > 0 {
            token := strings.TrimPrefix(authHeaders[0], "Bearer ")
            claims, err := validateJWTToken(ctx, token, appLayerID)
            if err != nil {
                return nil, status.Error(codes.Unauthenticated, fmt.Sprintf("invalid JWT token: %v", err))
            }
            
            // 将应用层信息和权限信息添加到 context
            ctx = context.WithValue(ctx, "app_layer_id", appLayerID)
            ctx = context.WithValue(ctx, "app_permissions", claims.Permissions)
            ctx = context.WithValue(ctx, "app_tenant_id", claims.TenantID)
        }
    }
    
    // 将应用层ID添加到 context（即使没有JWT）
    ctx = context.WithValue(ctx, "app_layer_id", appLayerID)
    
    return handler(ctx, req)
}

// 3. JWT Token 验证（支持多租户和权限控制）
func validateJWTToken(ctx context.Context, token string, appLayerID string) (*JWTClaims, error) {
    // 解析和验证 JWT Token
    claims := &JWTClaims{}
    jwtToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
        // 根据应用层ID获取对应的公钥
        publicKey, err := getAppLayerPublicKey(ctx, appLayerID)
        if err != nil {
            return nil, err
        }
        return publicKey, nil
    })
    
    if err != nil {
        return nil, err
    }
    
    if !jwtToken.Valid {
        return nil, errors.New("invalid token")
    }
    
    // 验证应用层ID是否匹配
    if claims.AppLayerID != appLayerID {
        return nil, errors.New("app layer ID mismatch")
    }
    
    // 验证 Token 是否过期
    if claims.ExpiresAt < time.Now().Unix() {
        return nil, errors.New("token expired")
    }
    
    return claims, nil
}

// JWT Claims 结构
type JWTClaims struct {
    jwt.StandardClaims
    AppLayerID  string   `json:"app_layer_id"`  // 应用层ID（必须与证书CN匹配）
    TenantID    string   `json:"tenant_id"`     // 租户ID（支持多租户）
    Permissions []string `json:"permissions"`    // 权限列表（如：["keys:create", "keys:read"]）
}
```

**应用层客户端配置**：

```go
// 应用层：基础设施层客户端
type Client struct {
    keyServiceClient    pb.KeyServiceClient
    signingServiceClient pb.SigningServiceClient
    conn                *grpc.ClientConn
    appLayerID          string
    jwtToken            string // 可选，用于细粒度授权
}

func NewClient(endpoint string, tlsConfig *TLSConfig, appLayerID string) (*Client, error) {
    // 加载客户端证书（每个应用层有独立的证书）
    clientCert, err := tls.LoadX509KeyPair(tlsConfig.ClientCert, tlsConfig.ClientKey)
    if err != nil {
        return nil, err
    }
    
    // 加载CA证书（用于验证服务器证书）
    caCert, err := os.ReadFile(tlsConfig.CACert)
    if err != nil {
        return nil, err
    }
    caCertPool := x509.NewCertPool()
    if !caCertPool.AppendCertsFromPEM(caCert) {
        return nil, errors.New("failed to append CA cert")
    }
    
    // 配置 mTLS
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{clientCert},
        RootCAs:      caCertPool,
        ServerName:   "mpc-infrastructure",
        MinVersion:   tls.VersionTLS13,
    }
    
    creds := credentials.NewTLS(tlsConfig)
    
    // 创建 gRPC 连接
    conn, err := grpc.Dial(endpoint, grpc.WithTransportCredentials(creds))
    if err != nil {
        return nil, err
    }
    
    return &Client{
        keyServiceClient:    pb.NewKeyServiceClient(conn),
        signingServiceClient: pb.NewSigningServiceClient(conn),
        conn:                conn,
        appLayerID:          appLayerID,
    }, nil
}

// 调用基础设施层（自动携带 JWT Token）
func (c *Client) CreateRootKey(ctx context.Context, req *pb.CreateRootKeyRequest) (*pb.CreateRootKeyResponse, error) {
    // 如果有 JWT Token，添加到 metadata
    if c.jwtToken != "" {
        md := metadata.New(map[string]string{
            "authorization": "Bearer " + c.jwtToken,
        })
        ctx = metadata.NewOutgoingContext(ctx, md)
    }
    
    return c.keyServiceClient.CreateRootKey(ctx, req)
}
```

**证书管理**：

```go
// 证书配置结构
type TLSConfig struct {
    // 服务器证书（基础设施层）
    ServerCert string
    ServerKey  string
    
    // CA 证书（用于验证客户端证书）
    CACert string
    
    // 客户端证书（应用层）
    ClientCert string
    ClientKey  string
    
    // 允许的应用层列表（从证书CN或SAN中提取）
    AllowedAppLayers []string
}

// 证书生成和管理
// 1. 为每个应用层生成独立的客户端证书
// 2. 证书CN或SAN包含应用层ID（如：mpcvault-server, personal-wallet）
// 3. 所有证书由同一个CA签发
// 4. 支持证书撤销列表（CRL）或OCSP
```

**权限控制示例**：

```go
// 在基础设施层服务中检查权限
func (s *KeyService) CreateRootKey(ctx context.Context, req *pb.CreateRootKeyRequest) (*pb.CreateRootKeyResponse, error) {
    // 获取应用层ID（从 mTLS 证书中提取）
    appLayerID := ctx.Value("app_layer_id").(string)
    
    // 获取权限列表（从 JWT Token 中提取，如果有）
    permissions, ok := ctx.Value("app_permissions").([]string)
    if ok {
        // 检查是否有创建密钥的权限
        if !contains(permissions, "keys:create") {
            return nil, status.Error(codes.PermissionDenied, "insufficient permissions")
        }
    }
    
    // 记录审计日志（包含应用层ID）
    s.auditLogger.Log(ctx, &AuditLog{
        AppLayerID: appLayerID,
        Operation:  "CreateRootKey",
        // ...
    })
    
    // 执行创建密钥逻辑
    // ...
}
```

**安全优势总结**：

| 特性 | mTLS | JWT | mTLS + JWT |
|------|------|-----|------------|
| **身份验证** | ✅ 强（证书） | ⚠️ 中（Token） | ✅ 强（双重） |
| **防中间人攻击** | ✅ 是 | ❌ 否 | ✅ 是 |
| **多应用层支持** | ✅ 是（独立证书） | ✅ 是 | ✅ 是 |
| **细粒度权限** | ❌ 否 | ✅ 是 | ✅ 是 |
| **证书撤销** | ✅ 支持 | ❌ 不支持 | ✅ 支持 |
| **审计追踪** | ✅ 精确 | ⚠️ 一般 | ✅ 精确 |
| **性能开销** | 低 | 低 | 低 |

**实施建议**：

1. **必须使用 mTLS**：作为基础认证层，保证通信安全
2. **可选使用 JWT**：如果需要细粒度权限控制或多租户支持
3. **证书管理**：
   - 使用统一的 CA 签发所有证书
   - 定期轮换证书（建议每90天）
   - 维护证书撤销列表（CRL）
4. **监控和告警**：
   - 监控证书过期时间
   - 告警异常访问模式
   - 记录所有认证失败事件

**gRPC 接口定义**：
```protobuf
// internal/pb/mpc/infrastructure/v1/key.proto
syntax = "proto3";

package mpc.infrastructure.v1;

service KeyService {
    rpc CreateRootKey(CreateRootKeyRequest) returns (CreateRootKeyResponse);
    rpc GetRootKey(GetRootKeyRequest) returns (GetRootKeyResponse);
    rpc DeriveWalletKey(DeriveWalletKeyRequest) returns (DeriveWalletKeyResponse);
}

message CreateRootKeyRequest {
    string algorithm = 1;
    string curve = 2;
    int32 threshold = 3;
    int32 total_nodes = 4;
    string protocol = 5;
}

message CreateRootKeyResponse {
    string key_id = 1;
    string public_key = 2;
}
```

**HTTP REST 接口（可选）**：
```go
// 基础设施层提供 HTTP REST API
POST /api/v1/infrastructure/keys
  Headers:
    Authorization: Bearer <jwt-token>
    X-API-Key: <api-key>
  Body:
    {
      "algorithm": "ECDSA",
      "curve": "secp256k1",
      ...
    }
```

**架构优势**：
- ✅ 基础设施层和应用层可以独立部署和扩展
- ✅ 支持多应用层共享基础设施层
- ✅ 更好的隔离性和安全性
- ✅ 清晰的接口定义（Protobuf）
- ✅ 支持不同技术栈的应用层（未来可扩展）

**注意事项**：
- ⚠️ 需要考虑网络延迟和性能开销（可通过连接池和批量操作优化）
- ⚠️ 需要实现认证机制（使用 mTLS 双向认证）
- ⚠️ 需要处理网络故障和重试（gRPC 内置重试机制）

#### 3.4.2 代码库分离方案

**架构设计**：基础设施层和应用层完全分离，独立代码库和独立部署

**代码库结构**：

```
# 代码库1：MPC 基础设施层
go-mpc-infrastructure/
├── cmd/
│   └── server/
│       └── main.go              # 基础设施层服务入口
├── internal/
│   ├── mpc/
│   │   ├── protocol/            # 协议引擎
│   │   ├── key/                 # 密钥服务
│   │   ├── signing/             # 签名服务
│   │   ├── session/             # 会话管理
│   │   ├── node/                # 节点管理
│   │   └── storage/             # 存储接口
│   ├── grpc/
│   │   └── server.go            # gRPC 服务器
│   ├── config/
│   └── persistence/
├── proto/
│   └── infrastructure/
│       └── v1/
│           ├── key.proto        # 密钥服务接口
│           ├── signing.proto    # 签名服务接口
│           └── common.proto     # 通用类型
├── go.mod
└── README.md

# 代码库2：MPCVault Server (应用层 2B)
go-mpcvault-server/
├── cmd/
│   └── server/
│       └── main.go              # 应用层服务入口
├── internal/
│   ├── vault/                   # Vault 服务
│   ├── wallet/                  # Wallet 服务
│   ├── organization/            # Organization 服务
│   ├── signingrequest/         # 签名请求服务
│   ├── client/
│   │   └── infrastructure/     # 基础设施层客户端
│   ├── api/
│   │   └── handlers/           # API Handlers
│   └── config/
├── proto/
│   └── infrastructure/
│       └── v1/                  # 从基础设施层复制或引用
│           ├── key.pb.go
│           └── signing.pb.go
├── go.mod
└── README.md

# 代码库3：个人钱包 (应用层 2C)
go-personal-wallet/
├── cmd/
│   └── server/
│       └── main.go
├── internal/
│   ├── personalwallet/         # 个人钱包服务
│   ├── client/
│   │   └── infrastructure/     # 基础设施层客户端
│   └── api/
├── go.mod
└── README.md
```

**依赖关系**：
- 应用层依赖基础设施层的 protobuf 定义
- 应用层通过 gRPC 客户端调用基础设施层
- 基础设施层不依赖应用层

**go.mod 配置**：

```go
// go-mpcvault-server/go.mod
module github.com/kashguard/go-mpcvault-server

require (
    github.com/kashguard/go-mpc-infrastructure v0.1.0
    // 或者直接引用 protobuf
    github.com/kashguard/go-mpc-infrastructure/proto/infrastructure/v1 v0.1.0
)
```

#### 3.4.3 独立部署架构

**部署架构**：

```
┌─────────────────────────────────────────┐
│  MPC 基础设施层服务                      │
│  - 端口: 9090 (gRPC)                    │
│  - 端口: 8080 (HTTP/健康检查)            │
│  - 数据库: PostgreSQL (密钥元数据)       │
│  - 存储: 文件系统/HSM (密钥分片)         │
└─────────────────────────────────────────┘
              ↕ gRPC (mTLS认证)
┌─────────────────────────────────────────┐
│  MPCVault Server (应用层 2B)            │
│  - 端口: 8080 (HTTP API)                │
│  - 数据库: PostgreSQL (业务数据)         │
│  - 调用基础设施层 gRPC 服务              │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│  个人钱包服务 (应用层 2C)                │
│  - 端口: 8080 (HTTP API)                │
│  - 数据库: PostgreSQL (业务数据)         │
│  - 调用基础设施层 gRPC 服务              │
└─────────────────────────────────────────┘
```

**部署配置**：

```yaml
# docker-compose.yml (基础设施层)
version: '3.8'
services:
  mpc-infrastructure:
    image: mpc-infrastructure:latest
    ports:
      - "9090:9090"  # gRPC
      - "8080:8080"  # HTTP
    environment:
      - GRPC_PORT=9090
      - HTTP_PORT=8080
      - DB_HOST=postgres
      - DB_NAME=mpc_infrastructure
    volumes:
      - ./key-shares:/var/lib/mpc/key-shares
    networks:
      - mpc-network

# docker-compose.yml (应用层)
version: '3.8'
services:
  mpcvault-server:
    image: mpcvault-server:latest
    ports:
      - "8080:8080"
    environment:
      - HTTP_PORT=8080
      - MPC_INFRASTRUCTURE_ENDPOINT=mpc-infrastructure:9090
      - MPC_INFRASTRUCTURE_TLS_ENABLED=true
      - MPC_INFRASTRUCTURE_CA_CERT=/certs/ca.crt
      - MPC_INFRASTRUCTURE_CLIENT_CERT=/certs/client.crt
      - MPC_INFRASTRUCTURE_CLIENT_KEY=/certs/client.key
      - DB_HOST=postgres
      - DB_NAME=mpcvault
    volumes:
      - ./certs:/certs
    networks:
      - mpc-network
    depends_on:
      - mpc-infrastructure
```

#### 3.4.4 接口定义（Protobuf）

**基础设施层接口定义**：

```protobuf
// proto/infrastructure/v1/key.proto
syntax = "proto3";

package mpc.infrastructure.v1;

option go_package = "github.com/kashguard/go-mpc-infrastructure/proto/infrastructure/v1";

// KeyService 密钥服务
service KeyService {
    // CreateRootKey 创建根密钥（执行DKG）
    rpc CreateRootKey(CreateRootKeyRequest) returns (CreateRootKeyResponse);
    
    // GetRootKey 获取根密钥信息
    rpc GetRootKey(GetRootKeyRequest) returns (GetRootKeyResponse);
    
    // DeriveWalletKey 从根密钥派生钱包密钥
    rpc DeriveWalletKey(DeriveWalletKeyRequest) returns (DeriveWalletKeyResponse);
    
    // DeleteRootKey 删除根密钥
    rpc DeleteRootKey(DeleteRootKeyRequest) returns (DeleteRootKeyResponse);
}

message CreateRootKeyRequest {
    string algorithm = 1;      // ECDSA, EdDSA
    string curve = 2;          // secp256k1, Ed25519
    int32 threshold = 2;       // 阈值（2-of-3）
    int32 total_nodes = 3;      // 总节点数（3）
    string protocol = 5;        // gg18, gg20, frost
    repeated string node_ids = 6; // 参与节点ID列表
}

message CreateRootKeyResponse {
    string key_id = 1;
    string public_key = 2;
    string algorithm = 3;
    string curve = 4;
    string protocol = 5;
}

message GetRootKeyRequest {
    string key_id = 1;
}

message GetRootKeyResponse {
    string key_id = 1;
    string public_key = 2;
    string algorithm = 3;
    string curve = 4;
    string protocol = 5;
    string status = 6;
}

message DeriveWalletKeyRequest {
    string root_key_id = 1;
    string chain_type = 2;     // ethereum, bitcoin, solana
    uint32 derive_index = 3;   // 派生索引
}

message DeriveWalletKeyResponse {
    string wallet_key_id = 1;
    string root_key_id = 2;
    string chain_type = 3;
    uint32 derive_index = 4;
    string public_key = 5;
    string address = 6;
}

message DeleteRootKeyRequest {
    string key_id = 1;
}

message DeleteRootKeyResponse {
    bool success = 1;
}
```

```protobuf
// proto/infrastructure/v1/signing.proto
syntax = "proto3";

package mpc.infrastructure.v1;

option go_package = "github.com/kashguard/go-mpc-infrastructure/proto/infrastructure/v1";

// SigningService 签名服务
service SigningService {
    // ThresholdSign 阈值签名
    rpc ThresholdSign(ThresholdSignRequest) returns (ThresholdSignResponse);
    
    // VerifySignature 验证签名
    rpc VerifySignature(VerifySignatureRequest) returns (VerifySignatureResponse);
}

message ThresholdSignRequest {
    string key_id = 1;         // 根密钥ID或钱包密钥ID
    bytes message = 2;          // 待签名消息
    string chain_type = 3;      // 链类型（可选，用于钱包密钥）
    uint32 derive_index = 4;   // 派生索引（可选，用于钱包密钥）
}

message ThresholdSignResponse {
    bytes signature = 1;
    string key_id = 2;
}

message VerifySignatureRequest {
    bytes signature = 1;
    bytes message = 2;
    string public_key = 3;
}

message VerifySignatureResponse {
    bool valid = 1;
}
```

#### 3.4.5 认证机制（mTLS）

**基础设施层服务端配置**：

```go
// internal/grpc/server.go
func NewGRPCServer(cfg config.Server) (*grpc.Server, error) {
    // 加载服务器证书
    serverCert, err := tls.LoadX509KeyPair(cfg.TLS.ServerCert, cfg.TLS.ServerKey)
    if err != nil {
        return nil, err
    }
    
    // 加载CA证书（用于验证客户端证书）
    caCert, err := os.ReadFile(cfg.TLS.CACert)
    if err != nil {
        return nil, err
    }
    caCertPool := x509.NewCertPool()
    if !caCertPool.AppendCertsFromPEM(caCert) {
        return nil, errors.New("failed to append CA cert")
    }
    
    // 配置 mTLS
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{serverCert},
        ClientAuth:   tls.RequireAndVerifyClientCert, // 要求客户端证书
        ClientCAs:    caCertPool,
        MinVersion:   tls.VersionTLS13,
    }
    
    creds := credentials.NewTLS(tlsConfig)
    
    // 创建 gRPC 服务器
    server := grpc.NewServer(
        grpc.Creds(creds),
        grpc.UnaryInterceptor(authInterceptor), // 认证拦截器
    )
    
    // 注册服务
    pb.RegisterKeyServiceServer(server, keyService)
    pb.RegisterSigningServiceServer(server, signingService)
    
    return server, nil
}

// 认证拦截器
func authInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
    // 从 context 中获取客户端证书
    peer, ok := peer.FromContext(ctx)
    if !ok {
        return nil, status.Error(codes.Unauthenticated, "failed to get peer")
    }
    
    tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
    if !ok {
        return nil, status.Error(codes.Unauthenticated, "failed to get TLS info")
    }
    
    // 验证客户端证书
    if len(tlsInfo.State.PeerCertificates) == 0 {
        return nil, status.Error(codes.Unauthenticated, "no client certificate")
    }
    
    clientCert := tlsInfo.State.PeerCertificates[0]
    
    // 验证证书CN（Common Name）或SAN（Subject Alternative Name）
    // 可以配置允许的应用层服务列表
    allowedCNs := []string{"mpcvault-server", "personal-wallet"}
    if !contains(allowedCNs, clientCert.Subject.CommonName) {
        return nil, status.Error(codes.PermissionDenied, "unauthorized client")
    }
    
    // 将客户端信息添加到 context
    ctx = context.WithValue(ctx, "client_cn", clientCert.Subject.CommonName)
    
    return handler(ctx, req)
}
```

**应用层客户端配置**：

```go
// internal/client/infrastructure/client.go
type Client struct {
    keyServiceClient    pb.KeyServiceClient
    signingServiceClient pb.SigningServiceClient
    conn                *grpc.ClientConn
}

func NewClient(endpoint string, tlsConfig *TLSConfig) (*Client, error) {
    // 加载客户端证书
    clientCert, err := tls.LoadX509KeyPair(tlsConfig.ClientCert, tlsConfig.ClientKey)
    if err != nil {
        return nil, err
    }
    
    // 加载CA证书（用于验证服务器证书）
    caCert, err := os.ReadFile(tlsConfig.CACert)
    if err != nil {
        return nil, err
    }
    caCertPool := x509.NewCertPool()
    if !caCertPool.AppendCertsFromPEM(caCert) {
        return nil, errors.New("failed to append CA cert")
    }
    
    // 配置 mTLS
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{clientCert},
        RootCAs:      caCertPool,
        ServerName:   "mpc-infrastructure", // 服务器名称
        MinVersion:   tls.VersionTLS13,
    }
    
    creds := credentials.NewTLS(tlsConfig)
    
    // 创建 gRPC 连接
    conn, err := grpc.Dial(endpoint, grpc.WithTransportCredentials(creds))
    if err != nil {
        return nil, err
    }
    
    return &Client{
        keyServiceClient:    pb.NewKeyServiceClient(conn),
        signingServiceClient: pb.NewSigningServiceClient(conn),
        conn:                conn,
    }, nil
}

// 调用基础设施层
func (c *Client) CreateRootKey(ctx context.Context, req *pb.CreateRootKeyRequest) (*pb.CreateRootKeyResponse, error) {
    return c.keyServiceClient.CreateRootKey(ctx, req)
}
```

#### 3.4.6 应用层使用示例

```go
// internal/vault/service.go
type VaultService struct {
    infrastructureClient *infrastructure.Client
    metadataStore       storage.MetadataStore
}

func NewVaultService(client *infrastructure.Client, store storage.MetadataStore) *VaultService {
    return &VaultService{
        infrastructureClient: client,
        metadataStore:         store,
    }
}

func (s *VaultService) CreateVault(ctx context.Context, req *CreateVaultRequest) (*Vault, error) {
    // 1. 调用基础设施层创建根密钥
    rootKeyReq := &pb.CreateRootKeyRequest{
        Algorithm:  "ECDSA",
        Curve:      "secp256k1",
        Threshold:  3,
        TotalNodes: 3,
        Protocol:   "gg20",
        NodeIds:    []string{"client-" + req.UserID, "server-proxy-1", "server-proxy-2"},
    }
    
    rootKeyResp, err := s.infrastructureClient.CreateRootKey(ctx, rootKeyReq)
    if err != nil {
        return nil, errors.Wrap(err, "failed to create root key")
    }
    
    // 2. 保存 Vault 元数据（应用层）
    vault := &Vault{
        ID:        generateVaultID(),
        Name:      req.Name,
        RootKeyID: rootKeyResp.KeyId, // 关联根密钥
        // ...
    }
    
    if err := s.metadataStore.SaveVault(ctx, vault); err != nil {
        return nil, errors.Wrap(err, "failed to save vault")
    }
    
    return vault, nil
}
```

#### 3.4.7 架构优势

**采用跨进程调用，独立代码库架构的优势**：
- ✅ 基础设施层和应用层完全分离，独立代码库
- ✅ 可以独立部署和扩展
- ✅ 支持多应用层共享基础设施层
- ✅ 使用 gRPC + mTLS 认证，保证安全性
- ✅ 清晰的接口定义（Protobuf）
- ✅ 更好的隔离性和可维护性
- ✅ 支持不同技术栈的应用层（未来可扩展）

#### 3.4.3 数据隔离

**数据隔离原则**：
- 基础设施层只管理密钥和签名，不管理业务数据
- 应用层管理业务数据（Organization, Vault, Wallet, Team等）
- 通过 keyID 关联：应用层的 Vault 关联基础设施层的 rootKeyID

**数据模型关联**：
```go
// 应用层：Vault 表
type Vault struct {
    ID        string  // Vault ID（应用层）
    RootKeyID string  // 关联基础设施层的根密钥ID
    // ...
}

// 基础设施层：RootKey 表
type RootKeyMetadata struct {
    KeyID     string  // 根密钥ID（基础设施层）
    PublicKey string
    // ...
}
```

**接口调用示例**：

```go
// 应用层：Vault Service 创建 Vault
func (s *VaultService) CreateVault(ctx context.Context, req *CreateVaultRequest) (*Vault, error) {
    // 1. 调用基础设施层创建根密钥
    rootKeyReq := &key.CreateRootKeyRequest{
        Algorithm:  "ECDSA",
        Curve:      "secp256k1",
        Threshold:  3,
        TotalNodes: 3,
        Protocol:   "gg20",
    }
    rootKey, err := s.keyService.CreateRootKey(ctx, rootKeyReq)
    if err != nil {
        return nil, errors.Wrap(err, "failed to create root key")
    }
    
    // 2. 保存 Vault 元数据（应用层）
    vault := &Vault{
        ID:        generateVaultID(),
        Name:      req.Name,
        RootKeyID: rootKey.KeyID, // 关联根密钥
        // ...
    }
    if err := s.metadataStore.SaveVault(ctx, vault); err != nil {
        return nil, errors.Wrap(err, "failed to save vault")
    }
    
    return vault, nil
}

// 应用层：Wallet Service 创建 Wallet
func (s *WalletService) CreateWallet(ctx context.Context, vaultID string, chainType string) (*Wallet, error) {
    // 1. 获取 Vault 信息（应用层）
    vault, err := s.vaultService.GetVault(ctx, vaultID)
    if err != nil {
        return nil, errors.Wrap(err, "failed to get vault")
    }
    
    // 2. 调用基础设施层派生钱包密钥
    walletKey, err := s.keyService.DeriveWalletKey(ctx, vault.RootKeyID, chainType, nextIndex)
    if err != nil {
        return nil, errors.Wrap(err, "failed to derive wallet key")
    }
    
    // 3. 生成区块链地址（使用 Chain Adapter）
    address, err := s.chainAdapter.GenerateAddress(chainType, walletKey.PublicKey)
    if err != nil {
        return nil, errors.Wrap(err, "failed to generate address")
    }
    
    // 4. 保存 Wallet 元数据（应用层）
    wallet := &Wallet{
        ID:         generateWalletID(),
        VaultID:    vaultID,
        ChainType:  chainType,
        Address:    address,
        DeriveIndex: walletKey.DeriveIndex,
        // ...
    }
    if err := s.metadataStore.SaveWallet(ctx, wallet); err != nil {
        return nil, errors.Wrap(err, "failed to save wallet")
    }
    
    return wallet, nil
}

// 应用层：SigningRequest Service 处理已批准的请求
func (s *SigningRequestService) ProcessApprovedRequests(ctx context.Context) error {
    // 1. 查询已批准的请求（应用层）
    requests, err := s.metadataStore.ListApprovedRequests(ctx)
    if err != nil {
        return errors.Wrap(err, "failed to list approved requests")
    }
    
    for _, req := range requests {
        // 2. 获取 Wallet 信息（应用层）
        wallet, err := s.walletService.GetWallet(ctx, req.WalletID)
        if err != nil {
            continue
        }
        
        // 3. 获取 Vault 信息（应用层）
        vault, err := s.vaultService.GetVault(ctx, req.VaultID)
        if err != nil {
            continue
        }
        
        // 4. 调用基础设施层执行阈值签名
        signReq := &signing.SignRequest{
            KeyID:   vault.RootKeyID, // 使用根密钥
            Message: req.Message,
            // 使用 Hardened Derivation 派生到 Wallet 的密钥
            DeriveIndex: wallet.DeriveIndex,
        }
        signResp, err := s.signingService.ThresholdSign(ctx, signReq)
        if err != nil {
            // 更新请求状态为失败
            req.Status = "failed"
            s.metadataStore.UpdateSigningRequest(ctx, req)
            continue
        }
        
        // 5. 更新请求状态（应用层）
        req.Status = "signed"
        req.Signature = signResp.Signature
        req.SignedAt = time.Now()
        s.metadataStore.UpdateSigningRequest(ctx, req)
    }
    
    return nil
}
```

---

## 4. 应用层：MPCVault Server (2B)

### 4.1 MPCVault Server 架构

参考 [MPCVault 文档](https://docs.mpcvault.com/docs/)，设计如下架构：

```
MPCVault Server (应用层)
├── Organization Service
│   ├── 组织管理
│   ├── 成员管理
│   └── 权限管理
│
├── Vault Service
│   ├── 创建 Vault（调用基础设施层 CreateRootKey）
│   ├── Vault 成员管理
│   ├── 审批策略管理
│   └── Vault 备份导出
│
├── Wallet Service
│   ├── 从 Vault 派生 Wallet（调用基础设施层 DeriveWalletKey）
│   ├── 多链地址管理
│   ├── 余额查询
│   └── 交易历史
│
└── SigningRequest Service
    ├── 创建签名请求
    ├── 审批流程（应用层实现）
    ├── 触发 MPC 签名（调用基础设施层 ThresholdSign）
    └── 交易管理
```

### 4.2 Organization 和 Vault 关系

**层级结构**：
```
Organization (组织)
    ├── 成员管理（Owner, Manager, Member）
    ├── Vault 1
    │   ├── 根密钥（通过DKG生成）
    │   ├── 成员管理（Vault级别）
    │   ├── 审批策略（Vault级别）
    │   └── Wallet 列表
    └── Vault 2
        └── ...
```

**关键设计**：
- **Organization**：组织级别，管理成员和Vault
- **Vault**：对应一个根密钥（通过DKG生成），可以派生多个Wallet
- **Wallet**：从Vault派生，每个Wallet对应一个链类型和地址

### 4.3 Vault Service 设计

**新增模块**: `internal/vault/`

**职责**:
- Vault 管理（创建、删除、查询）
- Vault 成员管理
- 审批策略管理
- 调用基础设施层创建根密钥

**关键接口**:

```go
// VaultService Vault 服务接口
type VaultService interface {
    // CreateVault 创建 Vault
    // 内部调用基础设施层 CreateRootKey
    CreateVault(ctx context.Context, req *CreateVaultRequest) (*Vault, error)
    
    // GetVault 获取 Vault 信息
    GetVault(ctx context.Context, vaultID string) (*Vault, error)
    
    // AddVaultMember 添加 Vault 成员
    AddVaultMember(ctx context.Context, vaultID string, userID string, role string) error
    
    // SetApprovalPolicy 设置审批策略
    SetApprovalPolicy(ctx context.Context, vaultID string, policy *ApprovalPolicy) error
}
```

### 4.4 Wallet Service 设计

**新增模块**: `internal/wallet/`

**职责**:
- Wallet 管理（创建、查询、删除）
- 从 Vault 派生 Wallet（调用基础设施层 DeriveWalletKey）
- 多链地址管理
- 余额查询和交易历史

**关键接口**:

```go
// WalletService Wallet 服务接口
type WalletService interface {
    // CreateWallet 从 Vault 创建 Wallet
    // 内部调用基础设施层 DeriveWalletKey
    CreateWallet(ctx context.Context, vaultID string, chainType string) (*Wallet, error)
    
    // GetWallet 获取 Wallet 信息
    GetWallet(ctx context.Context, walletID string) (*Wallet, error)
    
    // ListWallets 列出 Vault 下的所有 Wallet
    ListWallets(ctx context.Context, vaultID string) ([]*Wallet, error)
    
    // GetBalance 获取 Wallet 余额
    GetBalance(ctx context.Context, walletID string, tokenAddress string) (*Balance, error)
}
```

### 4.5 SigningRequest Service 设计

**新增模块**: `internal/signingrequest/`

**职责**:
- 创建签名请求
- 审批流程管理（应用层实现）
- 触发 MPC 签名（调用基础设施层）
- 交易状态管理

**关键接口**:

```go
// SigningRequestService 签名请求服务接口
type SigningRequestService interface {
    // CreateSigningRequest 创建签名请求
    CreateSigningRequest(ctx context.Context, req *CreateSigningRequestRequest) (*SigningRequest, error)
    
    // ApproveSigningRequest 审批签名请求
    ApproveSigningRequest(ctx context.Context, requestID string, userID string) error
    
    // ProcessApprovedRequests 处理已批准的请求
    // 内部调用基础设施层 ThresholdSign
    ProcessApprovedRequests(ctx context.Context) error
}
```

### 4.6 数据库设计

**新增表**: `organizations`, `vaults`, `wallets`, `vault_members`, `signing_requests`, `signing_approvals`

```sql
-- 组织表
CREATE TABLE organizations (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 组织成员表
CREATE TABLE organization_members (
    id VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL, -- 'owner', 'admin', 'member'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(organization_id, user_id)
);

-- Vault 表（对应根密钥）
CREATE TABLE vaults (
    id VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    root_key_id VARCHAR(255) NOT NULL, -- 关联基础设施层的根密钥
    threshold INTEGER NOT NULL, -- 审批阈值（如2-of-5）
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (root_key_id) REFERENCES keys(key_id) ON DELETE CASCADE
);

-- Vault 成员表
CREATE TABLE vault_members (
    id VARCHAR(255) PRIMARY KEY,
    vault_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL, -- 'owner', 'manager', 'member'
    can_approve BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(vault_id, user_id)
);

-- Wallet 表（从Vault派生）
CREATE TABLE wallets (
    id VARCHAR(255) PRIMARY KEY,
    vault_id VARCHAR(255) NOT NULL,
    chain_type VARCHAR(50) NOT NULL, -- 'ethereum', 'bitcoin', 'solana'
    address VARCHAR(255) NOT NULL,
    derive_index INTEGER NOT NULL, -- 派生索引
    wallet_key_id VARCHAR(255), -- 关联基础设施层的钱包密钥（可选）
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE,
    UNIQUE(vault_id, chain_type, derive_index)
);

-- 签名请求表
CREATE TABLE signing_requests (
    id VARCHAR(255) PRIMARY KEY,
    vault_id VARCHAR(255) NOT NULL,
    wallet_id VARCHAR(255) NOT NULL,
    requester_id VARCHAR(255) NOT NULL,
    message TEXT NOT NULL, -- 待签名消息（hex编码）
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    required_approvals INTEGER NOT NULL,
    current_approvals INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    signed_at TIMESTAMPTZ,
    FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE,
    FOREIGN KEY (wallet_id) REFERENCES wallets(id) ON DELETE CASCADE,
    FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 签名审批表
CREATE TABLE signing_approvals (
    id VARCHAR(255) PRIMARY KEY,
    request_id VARCHAR(255) NOT NULL,
    approver_id VARCHAR(255) NOT NULL,
    approved BOOLEAN NOT NULL,
    comment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (request_id) REFERENCES signing_requests(id) ON DELETE CASCADE,
    FOREIGN KEY (approver_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(request_id, approver_id)
);
```

### 4.7 Vault 创建流程

```
1. 用户创建 Vault 请求
   ↓
2. Vault Service 接收请求
   ↓
3. 调用基础设施层 CreateRootKey
   - 执行 DKG（2-of-3）
   - 生成根密钥
   - 生成SSS备份分片
   ↓
4. 保存 Vault 元数据
   - vaults 表：关联 root_key_id
   - 保存 Vault 成员和审批策略
   ↓
5. 返回 Vault 信息
```

### 4.8 Wallet 创建流程

```
1. 用户创建 Wallet 请求（指定 Vault 和链类型）
   ↓
2. Wallet Service 接收请求
   ↓
3. 调用基础设施层 DeriveWalletKey
   - 使用 Hardened Derivation
   - 从 Vault 的根密钥派生
   ↓
4. 生成区块链地址
   - 根据链类型选择适配器
   - 生成地址
   ↓
5. 保存 Wallet 元数据
   - wallets 表：关联 vault_id, chain_type, address
   ↓
6. 返回 Wallet 信息
```

---

## 5. 应用层：个人钱包 (2C)

### 5.1 个人钱包架构

**简化设计**：个人钱包不需要 Organization 和 Vault 层级，直接使用 Wallet

```
个人钱包 (应用层)
├── PersonalWallet Service
│   ├── 创建钱包（直接调用基础设施层 CreateRootKey）
│   ├── 多链地址管理
│   └── 交易管理
│
└── User Service
    ├── 用户管理
    └── 钱包关联
```

### 5.2 个人钱包数据模型

**简化设计**：
- 不需要 Organization 和 Vault
- 用户直接拥有 Wallet
- Wallet 直接关联根密钥

```sql
-- 个人钱包表（简化版）
CREATE TABLE personal_wallets (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    root_key_id VARCHAR(255) NOT NULL, -- 关联基础设施层的根密钥
    name VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (root_key_id) REFERENCES keys(key_id) ON DELETE CASCADE
);

-- 个人钱包地址表
CREATE TABLE personal_wallet_addresses (
    id VARCHAR(255) PRIMARY KEY,
    wallet_id VARCHAR(255) NOT NULL,
    chain_type VARCHAR(50) NOT NULL,
    address VARCHAR(255) NOT NULL,
    derive_index INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (wallet_id) REFERENCES personal_wallets(id) ON DELETE CASCADE,
    UNIQUE(wallet_id, chain_type, derive_index)
);
```

---

## 6. 认证系统设计

### 3.1 Google/Apple 登录架构

#### 3.1.1 OAuth2 流程

```
客户端APP → Google/Apple OAuth → 获取 ID Token
    ↓
服务器端验证 ID Token
    ↓
创建/关联用户账户
    ↓
生成 AccessToken + RefreshToken
    ↓
返回给客户端APP
```

#### 3.1.2 Passkey 流程

```
客户端APP → 生成 Passkey 密钥对
    ↓
服务器端注册 Public Key
    ↓
后续登录使用 Passkey 挑战-响应
    ↓
验证通过后生成 AccessToken
```

### 3.2 服务器端认证服务设计

**新增模块**: `internal/auth/oauth/`

**职责**:
- Google OAuth2 验证
- Apple Sign In 验证
- Passkey 注册和验证
- 用户账户关联

**关键接口**:

```go
// OAuthProvider OAuth 提供商接口
type OAuthProvider interface {
    // VerifyIDToken 验证 ID Token
    VerifyIDToken(ctx context.Context, idToken string) (*IDTokenClaims, error)
    
    // GetUserInfo 获取用户信息
    GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error)
}

// PasskeyService Passkey 服务接口
type PasskeyService interface {
    // RegisterPasskey 注册 Passkey
    RegisterPasskey(ctx context.Context, userID string, publicKey []byte) error
    
    // VerifyPasskey 验证 Passkey 挑战
    VerifyPasskey(ctx context.Context, userID string, challenge []byte, signature []byte) (bool, error)
}
```

### 3.3 数据库设计

**新增表**: `oauth_providers`

```sql
CREATE TABLE oauth_providers (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL, -- 'google', 'apple'
    provider_user_id VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(provider, provider_user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE passkeys (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    credential_id VARCHAR(255) NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

### 3.4 需要修改的地方

**当前实现** (`internal/auth/service.go`):
- ❌ 只支持用户名密码登录
- ❌ 没有 OAuth2 支持
- ❌ 没有 Passkey 支持

**需要新增**:
1. `internal/auth/oauth/google.go` - Google OAuth2 验证
2. `internal/auth/oauth/apple.go` - Apple Sign In 验证
3. `internal/auth/passkey/service.go` - Passkey 服务
4. `internal/api/handlers/auth/post_oauth_login.go` - OAuth 登录接口
5. `internal/api/handlers/auth/post_passkey_register.go` - Passkey 注册接口
6. `internal/api/handlers/auth/post_passkey_login.go` - Passkey 登录接口

---

## 7. 2-of-3 MPC 实现方案（基础设施层）

### 7.1 DKG 流程设计

#### 7.1.1 参与方识别

**2-of-3 DKG 参与方**:
1. **服务器代理1** (nodeID: `server-proxy-1`) - 参与签名
2. **服务器代理2** (nodeID: `server-proxy-2`) - 参与签名
3. **客户端APP** (nodeID: `client-{userID}`) - 仅备份，不参与签名

#### 7.1.2 DKG 执行流程

```
1. 应用层发起创建密钥请求
   ↓
2. 基础设施层创建 DKG 会话
   - 固定参与节点：[server-proxy-1, server-proxy-2, client-{userID}]
   - 阈值：2-of-3（只需要2个分片即可签名）
   ↓
3. 执行 DKG 协议（3 方参与）
   - Round 1: 生成随机数，交换承诺
   - Round 2: 交换随机数，验证承诺
   - Round 3: 计算密钥分片
   - Round 4: 验证分片有效性
   ↓
4. DKG 完成，生成公钥
   ↓
5. 服务器端存储分片1和分片2（用于签名）
   ↓
6. 生成 SSS 备份分片
   - 从完整密钥生成 SSS 分片（3-of-5）
   - 分片1 → 下发到客户端APP
   - 分片2-5 → 存储在服务器备份存储
   ↓
7. 下发SSS备份分片到客户端APP
   - 使用 TLS 加密传输
   - 客户端存储到 Secure Enclave
```

### 7.2 SSS 备份分片生成和下发

#### 7.2.1 SSS 备份分片生成（分片式备份方案）

**核心原则**：对每个MPC分片分别进行SSS备份，密钥永不完整存在

**生成流程**：

```
DKG 完成后：
1. 对每个MPC分片分别进行SSS备份
   ├── MPC分片1 (server-proxy-1)
   │   └── SSS备份分片 (3-of-5)
   │       ├── 备份分片1-1 → 服务器备份存储1
   │       ├── 备份分片1-2 → 服务器备份存储2
   │       ├── 备份分片1-3 → 客户端APP（下发）
   │       ├── 备份分片1-4 → 服务器备份存储3
   │       └── 备份分片1-5 → 云存储（可选）
   │
   ├── MPC分片2 (server-proxy-2)
   │   └── SSS备份分片 (3-of-5)
   │       ├── 备份分片2-1 → 服务器备份存储1
   │       ├── 备份分片2-2 → 服务器备份存储2
   │       ├── 备份分片2-3 → 客户端APP（下发）
   │       ├── 备份分片2-4 → 服务器备份存储3
   │       └── 备份分片2-5 → 云存储（可选）
   │
   └── MPC分片3 (client-{userID})
       └── SSS备份分片 (3-of-5)
           ├── 备份分片3-1 → 客户端APP（本地存储）
           ├── 备份分片3-2 → 服务器备份存储1
           ├── 备份分片3-3 → 服务器备份存储2
           ├── 备份分片3-4 → 服务器备份存储3
           └── 备份分片3-5 → 云存储（可选）
```

**关键优势**：
- ✅ **密钥永不完整存在**：符合MPC设计原则
- ✅ **安全性更高**：即使部分备份分片泄露，也无法恢复完整密钥
- ✅ **容错性更好**：每个MPC分片独立备份，互不影响
- ✅ **恢复灵活**：可以只恢复需要的MPC分片（如只恢复服务器分片用于签名）

#### 7.2.2 备份分片下发流程

```
服务器端 (SSS 备份分片生成后):
1. 获取客户端备份分片（SSS 分片1）
2. 使用客户端公钥加密分片
   - 客户端在注册时提供临时公钥
   - 或使用 OAuth 关联的密钥
3. 通过安全通道下发
   - HTTPS API 或 gRPC
4. 客户端接收并存储
   - 解密分片
   - 存储到 Secure Enclave/TrustZone
5. 客户端确认接收
6. 服务器端记录下发日志
```

#### 7.2.3 密钥恢复流程（分片式恢复）

**恢复原则**：分别恢复每个MPC分片，不需要重构完整密钥

**场景1：服务器分片丢失（最常见）**

```
1. 恢复 server-proxy-1 的MPC分片
   - 收集 server-proxy-1 的至少3个SSS备份分片
   - 使用SSS算法恢复 server-proxy-1 的MPC分片
   ↓
2. 恢复 server-proxy-2 的MPC分片
   - 收集 server-proxy-2 的至少3个SSS备份分片
   - 使用SSS算法恢复 server-proxy-2 的MPC分片
   ↓
3. 存储恢复的MPC分片
   - 将恢复的2个服务器分片存储到服务器
   - 即可用于签名（2-of-3，只需要2个分片）
   ↓
4. 客户端分片恢复（可选）
   - 如果需要恢复客户端分片，收集 client-{userID} 的至少3个SSS备份分片
   - 恢复客户端MPC分片并下发到客户端
```

**场景2：客户端分片丢失**

```
1. 客户端分片丢失不影响签名
   - 签名只需要服务器2个分片（2-of-3）
   ↓
2. 恢复客户端分片（可选）
   - 收集 client-{userID} 的至少3个SSS备份分片
   - 使用SSS算法恢复客户端MPC分片
   - 下发到客户端APP
```

**场景3：部分备份分片丢失**

```
1. 检查每个MPC分片的备份分片可用性
   - server-proxy-1: 需要至少3个备份分片可用
   - server-proxy-2: 需要至少3个备份分片可用
   - client-{userID}: 需要至少3个备份分片可用（可选）
   ↓
2. 如果某个MPC分片的备份分片不足3个
   - 该MPC分片无法恢复
   - 但其他MPC分片仍可恢复
   ↓
3. 对于2-of-3 MPC
   - 只要恢复2个MPC分片即可签名
   - 不需要恢复所有3个分片
```

**关键优势**：
- ✅ **无需重构完整密钥**：只恢复MPC分片，密钥永不完整存在
- ✅ **灵活恢复**：可以只恢复需要的MPC分片
- ✅ **容错性强**：每个MPC分片独立备份和恢复

#### 7.2.4 安全考虑

- ✅ **密钥永不完整存在**：符合MPC设计原则，密钥在任何时候都不完整存在
- ✅ **分片式备份**：每个MPC分片独立备份，即使部分备份分片泄露也无法恢复完整密钥
- ✅ **加密传输**：使用 TLS 1.3
- ✅ **端到端加密**：使用客户端公钥加密备份分片
- ✅ **一次性传输**：备份分片只传输一次
- ✅ **SSS 阈值保护**：每个MPC分片的备份需要至少3个分片才能恢复
- ✅ **分片隔离**：备份分片和MPC分片完全分离，互不影响

### 7.3 服务器端实现要点

#### 7.3.1 DKG 服务修改

**当前实现** (`internal/mpc/key/dkg.go`):
- 节点发现和选择是动态的
- 节点列表从会话中获取

**需要修改**:
1. **固定参与节点列表**：2-of-3 模式下，固定为 `[server-proxy-1, server-proxy-2, client-{userID}]`
2. **阈值配置**：threshold = 2, totalNodes = 3
3. **客户端节点注册**：客户端APP需要注册为MPC节点（用于备份）
4. **SSS备份生成**：DKG完成后，生成SSS备份分片
5. **备份分片下发**：下发SSS备份分片到客户端

#### 7.3.2 节点管理修改

**当前实现** (`internal/mpc/node/manager.go`):
- 节点注册和发现

**需要新增**:
1. **客户端节点类型**：区分客户端节点和服务器节点
2. **客户端节点注册接口**：客户端APP注册为MPC节点（用于备份）
3. **节点状态管理**：客户端节点在线/离线状态（备份场景不需要在线）
4. **节点用途标识**：标记节点是否参与签名（服务器节点参与，客户端节点不参与）

#### 7.3.3 密钥服务修改

**当前实现** (`internal/mpc/key/service.go`):
- `CreateKey` 执行 DKG，存储所有节点的分片

**需要修改**:
1. **分片存储策略**：
   - 服务器节点分片：存储在服务器端（用于签名）
   - 客户端节点分片：不存储在服务器端（仅参与DKG，不参与签名）
2. **SSS备份服务集成**：DKG完成后，对每个MPC分片分别进行SSS备份
3. **备份分片下发接口**：新增 `DeliverBackupShareToClient` 方法
4. **客户端备份分片验证**：客户端确认接收备份分片

**关键实现**：
```go
// 对每个MPC分片分别进行SSS备份
for nodeID, mpcShare := range dkgResp.KeyShares {
    // 对单个MPC分片进行SSS备份（不是完整密钥）
    backupShares, err := s.sssBackupService.GenerateBackupShares(
        ctx, 
        mpcShare.Share, // 只备份单个分片
        3,              // 阈值：3-of-5
        5,              // 总分片数：5
    )
    
    // 存储备份分片
    for i, backupShare := range backupShares {
        if nodeID == "client-"+req.UserID && i == 0 {
            // 客户端分片的第一个备份分片 → 下发到客户端
            deliverBackupShareToClient(ctx, keyID, req.UserID, nodeID, i+1, backupShare)
        } else {
            // 其他备份分片 → 存储在服务器
            storeBackupShare(ctx, keyID, nodeID, i+1, backupShare)
        }
    }
}
```

### 7.4 签名服务修改

**当前实现** (`internal/mpc/signing/service.go`):
- 动态选择参与节点

**需要修改**:
1. **固定签名节点**：签名时只选择服务器代理节点 `[server-proxy-1, server-proxy-2]`
2. **不需要客户端参与**：客户端分片不参与签名流程
3. **阈值配置**：2-of-3，只需要2个服务器节点即可签名

### 7.5 需要新增的模块

**SSS 备份服务** (`internal/mpc/backup/sss.go`):
- [ ] `sss.go` - SSS 算法实现
- [ ] `service.go` - 备份服务
- [ ] `types.go` - 备份分片类型定义

**关键接口**:
```go
// SSSBackupService SSS 备份服务接口
type SSSBackupService interface {
    // GenerateBackupShares 对单个MPC分片生成SSS备份分片
    // 注意：输入是单个MPC分片，不是完整密钥
    // 这确保了密钥永不完整存在，符合MPC设计原则
    GenerateBackupShares(ctx context.Context, mpcShare []byte, threshold int, totalShares int) ([]*BackupShare, error)
    
    // RecoverMPCShareFromBackup 从备份分片恢复单个MPC分片
    // 注意：恢复的是MPC分片，不是完整密钥
    // 需要至少threshold个备份分片才能恢复
    RecoverMPCShareFromBackup(ctx context.Context, shares []*BackupShare) ([]byte, error)
    
    // DeliverBackupShareToClient 下发备份分片到客户端
    // 使用客户端公钥加密备份分片，通过安全通道下发
    DeliverBackupShareToClient(ctx context.Context, keyID string, userID string, nodeID string, shareIndex int, share *BackupShare) error
}

// BackupShare 备份分片结构
type BackupShare struct {
    KeyID      string    // 根密钥ID
    NodeID     string    // 对应的MPC节点ID（server-proxy-1, server-proxy-2, client-{userID}）
    ShareIndex int       // 备份分片索引（1-5）
    ShareData  []byte    // 备份分片数据（加密存储）
    CreatedAt  time.Time
}
```

**实现示例**：
```go
// internal/mpc/backup/service.go
func (s *SSSBackupService) GenerateBackupShares(
    ctx context.Context, 
    mpcShare []byte,  // 单个MPC分片，不是完整密钥
    threshold int,     // 阈值（3）
    totalShares int,   // 总分片数（5）
) ([]*BackupShare, error) {
    // 使用SSS算法对单个MPC分片进行分割
    shares, err := s.sss.Split(mpcShare, totalShares, threshold)
    if err != nil {
        return nil, errors.Wrap(err, "failed to split MPC share using SSS")
    }
    
    // 转换为BackupShare结构
    backupShares := make([]*BackupShare, len(shares))
    for i, shareData := range shares {
        backupShares[i] = &BackupShare{
            ShareIndex: i + 1,
            ShareData:  shareData,
            CreatedAt:  time.Now(),
        }
    }
    
    return backupShares, nil
}

func (s *SSSBackupService) RecoverMPCShareFromBackup(
    ctx context.Context, 
    shares []*BackupShare,
) ([]byte, error) {
    // 验证备份分片数量
    if len(shares) < 3 {
        return nil, errors.New("insufficient backup shares: need at least 3")
    }
    
    // 提取备份分片数据
    shareData := make([][]byte, len(shares))
    for i, share := range shares {
        shareData[i] = share.ShareData
    }
    
    // 使用SSS算法恢复MPC分片（不是完整密钥）
    mpcShare, err := s.sss.Combine(shareData)
    if err != nil {
        return nil, errors.Wrap(err, "failed to recover MPC share from backup")
    }
    
    return mpcShare, nil
}
```

### 7.6 需要修改的地方

**DKG 服务** (`internal/mpc/key/dkg.go`):
- ⚠️ 修改节点选择逻辑：固定为 2-of-3 模式
- ⚠️ 修改阈值配置：threshold = 2, totalNodes = 3
- ⚠️ 添加客户端节点识别（用于备份）
- ⚠️ 集成SSS备份生成逻辑

**密钥服务** (`internal/mpc/key/service.go`):
- ⚠️ 修改分片存储逻辑：服务器分片用于签名，客户端分片仅备份
- ⚠️ 新增SSS备份生成接口
- ⚠️ 新增备份分片下发接口

**签名服务** (`internal/mpc/signing/service.go`):
- ⚠️ 修改节点选择：只选择服务器代理节点
- ⚠️ 不需要客户端参与签名

**节点管理** (`internal/mpc/node/manager.go`):
- ⚠️ 新增客户端节点类型
- ⚠️ 新增客户端节点注册接口
- ⚠️ 新增节点用途标识（是否参与签名）

**存储接口** (`internal/mpc/storage/interface.go`):
- ⚠️ 新增备份分片存储接口
- ⚠️ 新增备份分片下发记录表（用于审计）

---

## 8. 客户端节点和SSS备份

### 8.1 客户端节点支持

#### 8.1.1 节点类型

**服务器节点**（参与签名）：
- `server-proxy-1` - 服务器代理1
- `server-proxy-2` - 服务器代理2

**客户端节点**（仅备份，不参与签名）：
- `client-{userID}` - 客户端APP节点

#### 8.1.2 客户端节点注册

**注册流程**：
```
1. 客户端APP登录后，注册为MPC节点
   ↓
2. 服务器端创建客户端节点记录
   - 节点类型：client
   - 节点ID：client-{userID}
   - 用途：backup（不参与签名）
   ↓
3. 节点状态管理
   - 在线/离线状态跟踪（备份场景不需要在线）
   - 心跳机制（可选）
```

### 8.2 SSS 备份机制

#### 8.2.1 SSS 算法选择

**推荐库**：
- `github.com/hashicorp/vault/shamir` - HashiCorp 的 SSS 实现
- `github.com/codahale/sss` - 另一个 Go 实现

**配置建议**：
- 默认配置：3-of-5（需要3个分片才能恢复）
- 可选配置：2-of-3（简化版，容错性较低）

#### 8.2.2 备份分片生成流程（分片式备份方案）

**核心原则**：对每个MPC分片分别进行SSS备份，密钥永不完整存在

```
DKG 完成后：
1. 对每个MPC分片分别进行SSS备份（密钥永不完整存在）
   ├── server-proxy-1 的分片 → SSS备份 (3-of-5)
   │   ├── 备份分片1-1 → 服务器备份存储1
   │   ├── 备份分片1-2 → 服务器备份存储2
   │   ├── 备份分片1-3 → 客户端APP（下发）
   │   ├── 备份分片1-4 → 服务器备份存储3
   │   └── 备份分片1-5 → 云存储（可选）
   │
   ├── server-proxy-2 的分片 → SSS备份 (3-of-5)
   │   ├── 备份分片2-1 → 服务器备份存储1
   │   ├── 备份分片2-2 → 服务器备份存储2
   │   ├── 备份分片2-3 → 客户端APP（下发）
   │   ├── 备份分片2-4 → 服务器备份存储3
   │   └── 备份分片2-5 → 云存储（可选）
   │
   └── client-{userID} 的分片 → SSS备份 (3-of-5)
       ├── 备份分片3-1 → 客户端APP（本地存储）
       ├── 备份分片3-2 → 服务器备份存储1
       ├── 备份分片3-3 → 服务器备份存储2
       ├── 备份分片3-4 → 服务器备份存储3
       └── 备份分片3-5 → 云存储（可选）
```

**关键优势**：
- ✅ **密钥永不完整存在**：符合MPC设计原则，密钥在任何时候都不完整存在
- ✅ **安全性更高**：即使部分备份分片泄露，也无法恢复完整密钥
- ✅ **容错性更好**：每个MPC分片独立备份，互不影响
- ✅ **恢复灵活**：可以只恢复需要的MPC分片（如只恢复服务器分片用于签名）

#### 8.2.3 备份分片下发流程

```
SSS 备份分片生成后：
1. 服务器端获取客户端备份分片（SSS 分片1）
2. 使用客户端公钥加密备份分片
3. 通过安全通道下发（HTTPS API）
4. 客户端接收并存储到 Secure Enclave
5. 客户端确认接收
6. 服务器端记录下发日志
```

#### 8.2.4 密钥恢复流程

```
密钥恢复场景（服务器端分片丢失）：
1. 收集 SSS 备份分片
   - 至少需要3个分片（3-of-5配置）
   - 可以从以下来源获取：
     * 客户端APP（分片1）
     * 服务器备份存储1（分片2）
     * 服务器备份存储2（分片3）
     * 云存储（分片4，可选）
     * 用户邮箱/密码管理器（分片5，可选）
   ↓
2. 使用 SSS 算法恢复完整密钥
   - 组合至少3个备份分片
   - 恢复完整密钥
   ↓
3. 重新执行 DKG（可选）
   - 如果需要重新生成新的MPC分片
   - 或直接使用恢复的密钥（需要重新生成SSS备份）
```

#### 8.2.5 安全机制

- ✅ **端到端加密**：使用客户端公钥加密备份分片
- ✅ **TLS 传输**：通过 TLS 1.3 传输
- ✅ **一次性传输**：备份分片只传输一次
- ✅ **SSS 阈值保护**：需要至少3个分片才能恢复
- ✅ **分片隔离**：备份分片和MPC分片完全分离
- ✅ **审计日志**：记录所有备份分片生成、下发、恢复操作

```sql
-- 团队表
CREATE TABLE teams (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    wallet_id VARCHAR(255) NOT NULL, -- 关联的钱包ID
    threshold INTEGER NOT NULL, -- 审批阈值（如2-of-5）
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (wallet_id) REFERENCES keys(key_id) ON DELETE CASCADE
);

-- 团队成员表
CREATE TABLE team_members (
    id VARCHAR(255) PRIMARY KEY,
    team_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL, -- 'owner', 'manager', 'member'
    can_approve BOOLEAN NOT NULL DEFAULT false, -- 是否可以审批
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(team_id, user_id)
);

-- 签名请求表
CREATE TABLE signing_requests (
    id VARCHAR(255) PRIMARY KEY,
    team_id VARCHAR(255) NOT NULL,
    key_id VARCHAR(255) NOT NULL,
    requester_id VARCHAR(255) NOT NULL, -- 发起人
    message TEXT NOT NULL, -- 待签名消息（hex编码）
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- 'pending', 'approved', 'rejected', 'signed', 'failed'
    required_approvals INTEGER NOT NULL, -- 需要的审批数量
    current_approvals INTEGER NOT NULL DEFAULT 0, -- 当前审批数量
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    signed_at TIMESTAMPTZ,
    FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
    FOREIGN KEY (key_id) REFERENCES keys(key_id) ON DELETE CASCADE,
    FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 签名审批表
CREATE TABLE signing_approvals (
    id VARCHAR(255) PRIMARY KEY,
    request_id VARCHAR(255) NOT NULL,
    approver_id VARCHAR(255) NOT NULL, -- 审批人
    approved BOOLEAN NOT NULL, -- true=批准, false=拒绝
    comment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (request_id) REFERENCES signing_requests(id) ON DELETE CASCADE,
    FOREIGN KEY (approver_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(request_id, approver_id) -- 每个审批人只能审批一次
);
```

---

## 9. 服务器端实现要点

### 6.1 认证系统增强

#### 6.1.1 OAuth2 集成

**实现位置**: `internal/auth/oauth/`

**关键组件**:
1. **Google OAuth2 验证器**
   - 验证 Google ID Token
   - 获取用户信息
   - 关联用户账户

2. **Apple Sign In 验证器**
   - 验证 Apple ID Token
   - 处理 Apple 特有的用户标识符
   - 关联用户账户

3. **OAuth 登录服务**
   - 统一处理 OAuth 登录流程
   - 创建或关联用户账户
   - 生成访问令牌

#### 6.1.2 Passkey 集成

**实现位置**: `internal/auth/passkey/`

**关键组件**:
1. **Passkey 注册服务**
   - 接收客户端公钥
   - 存储到数据库
   - 关联用户账户

2. **Passkey 验证服务**
   - 生成挑战
   - 验证签名
   - 生成访问令牌

### 6.2 MPC 服务增强

#### 6.2.1 客户端节点支持

**修改位置**: `internal/mpc/node/manager.go`

**关键功能**:
1. **客户端节点注册**
   - 客户端APP注册为MPC节点
   - 节点类型：`client`
   - 节点ID格式：`client-{userID}`

2. **客户端节点管理**
   - 在线/离线状态跟踪
   - 节点能力声明（支持DKG、签名）

#### 6.2.2 DKG 流程调整

**修改位置**: `internal/mpc/key/dkg.go`

**关键修改**:
1. **固定参与节点**
   - 2-of-3 模式：固定为 `[server-proxy-1, server-proxy-2, client-{userID}]`
   - 不再动态选择节点

2. **客户端节点通知**
   - DKG 开始时，通知客户端APP参与
   - 通过 gRPC 或 WebSocket 推送

3. **分片下发**
   - DKG 完成后，获取客户端分片
   - 加密后下发到客户端
   - 记录下发日志

#### 6.2.3 密钥服务调整

**修改位置**: `internal/mpc/key/service.go`

**关键修改**:
1. **分片存储策略**
   ```go
   // 伪代码示例
   for nodeID, share := range dkgResp.KeyShares {
       if strings.HasPrefix(nodeID, "client-") {
           // 客户端分片：不下发到服务器存储，直接下发到客户端
           deliverToClient(ctx, nodeID, share)
       } else {
           // 服务器分片：存储在服务器端
           storeKeyShare(ctx, keyID, nodeID, share)
       }
   }
   ```

2. **分片下发接口**
   - `DeliverKeyShareToClient(ctx, keyID, userID, share)` - 下发分片到客户端
   - `ConfirmKeyShareDelivery(ctx, keyID, userID)` - 客户端确认接收

### 6.3 团队角色阈值签名

#### 6.3.1 团队服务实现

**新增位置**: `internal/mpc/team/service.go`

**关键功能**:
1. **团队管理**
   - 创建团队
   - 添加/删除成员
   - 角色权限管理

2. **审批策略评估**
   - 根据交易金额、地址等评估需要的审批数量
   - 支持自定义策略规则

#### 6.3.2 签名请求服务实现

**新增位置**: `internal/mpc/signing/request.go`

**关键功能**:
1. **签名请求管理**
   - 创建签名请求
   - 查询请求状态
   - 取消请求

2. **审批处理**
   - 记录审批
   - 检查阈值
   - 触发MPC签名

3. **后台处理**
   - 定时检查已批准的请求
   - 自动触发MPC签名
   - 更新请求状态

### 6.4 API 接口设计

#### 6.4.1 认证相关接口

```
POST /api/v1/auth/oauth/google
  - 请求体：{ id_token: string }
  - 响应：{ access_token, refresh_token, user }

POST /api/v1/auth/oauth/apple
  - 请求体：{ id_token: string, user_identifier: string }
  - 响应：{ access_token, refresh_token, user }

POST /api/v1/auth/passkey/register
  - 请求体：{ credential_id, public_key }
  - 响应：{ success }

POST /api/v1/auth/passkey/login
  - 请求体：{ credential_id, challenge, signature }
  - 响应：{ access_token, refresh_token }
```

#### 6.4.2 MPC 相关接口

```
POST /api/v1/mpc/keys
  - 创建密钥（2-of-3 DKG）
  - 自动生成SSS备份分片并下发到客户端

GET /api/v1/mpc/keys/{keyID}/share
  - 获取客户端分片（如果丢失）

POST /api/v1/mpc/sign
  - 阈值签名（2个服务器代理节点参与，不需要客户端）
```

#### 6.4.3 团队相关接口

```
POST /api/v1/mpc/teams
  - 创建团队

POST /api/v1/mpc/teams/{teamID}/members
  - 添加成员

POST /api/v1/mpc/signing/requests
  - 创建签名请求

POST /api/v1/mpc/signing/requests/{requestID}/approve
  - 审批签名请求
```

---

## 10. 需要修改完善的地方

### 10.1 代码库分离实施

#### 10.1.1 创建独立代码库

**步骤1：创建基础设施层代码库**

```bash
# 创建新代码库
mkdir go-mpc-infrastructure
cd go-mpc-infrastructure

# 初始化 Go 模块
go mod init github.com/kashguard/go-mpc-infrastructure

# 从当前代码库复制基础设施层代码
# - internal/mpc/ (protocol, key, signing, session, node, storage)
# - proto/infrastructure/v1/ (protobuf 定义)
# - cmd/server/ (服务入口)
```

**步骤2：创建应用层代码库**

```bash
# 创建 MPCVault Server 代码库
mkdir go-mpcvault-server
cd go-mpcvault-server
go mod init github.com/kashguard/go-mpcvault-server

# 创建个人钱包代码库
mkdir go-personal-wallet
cd go-personal-wallet
go mod init github.com/kashguard/go-personal-wallet
```

#### 10.1.2 Protobuf 定义共享

**方案一：Git Submodule（推荐）**

```bash
# 在应用层代码库中添加基础设施层作为 submodule
cd go-mpcvault-server
git submodule add https://github.com/kashguard/go-mpc-infrastructure.git proto/infrastructure

# 在 go.mod 中引用
replace github.com/kashguard/go-mpc-infrastructure/proto => ./proto/infrastructure/proto
```

**方案二：Go Module 依赖**

```go
// go-mpcvault-server/go.mod
module github.com/kashguard/go-mpcvault-server

require (
    github.com/kashguard/go-mpc-infrastructure v0.1.0
)

// 使用生成的 protobuf 代码
import (
    pb "github.com/kashguard/go-mpc-infrastructure/proto/infrastructure/v1"
)
```

**方案三：独立 Protobuf 仓库**

```bash
# 创建独立的 protobuf 定义仓库
mkdir go-mpc-proto
cd go-mpc-proto
go mod init github.com/kashguard/go-mpc-proto

# 基础设施层和应用层都依赖这个仓库
```

#### 10.1.3 代码迁移清单

**基础设施层代码库需要包含**：
- [ ] `internal/mpc/protocol/` - 协议引擎
- [ ] `internal/mpc/key/` - 密钥服务
- [ ] `internal/mpc/signing/` - 签名服务
- [ ] `internal/mpc/session/` - 会话管理
- [ ] `internal/mpc/node/` - 节点管理
- [ ] `internal/mpc/storage/` - 存储接口
- [ ] `internal/mpc/grpc/` - gRPC 服务器
- [ ] `proto/infrastructure/v1/` - Protobuf 定义
- [ ] `cmd/server/` - 服务入口
- [ ] `internal/config/` - 配置管理
- [ ] `internal/persistence/` - 数据库连接

**应用层代码库需要包含**：
- [ ] `internal/vault/` - Vault 服务（MPCVault Server）
- [ ] `internal/wallet/` - Wallet 服务（MPCVault Server）
- [ ] `internal/organization/` - Organization 服务（MPCVault Server）
- [ ] `internal/signingrequest/` - 签名请求服务（MPCVault Server）
- [ ] `internal/personalwallet/` - 个人钱包服务（个人钱包）
- [ ] `internal/client/infrastructure/` - 基础设施层客户端
- [ ] `internal/api/` - API Handlers
- [ ] `internal/config/` - 配置管理
- [ ] `internal/persistence/` - 数据库连接

#### 10.1.4 部署和运维

**基础设施层部署**：

```yaml
# kubernetes/mpc-infrastructure/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mpc-infrastructure
spec:
  replicas: 3  # 高可用
  selector:
    matchLabels:
      app: mpc-infrastructure
  template:
    metadata:
      labels:
        app: mpc-infrastructure
    spec:
      containers:
      - name: mpc-infrastructure
        image: mpc-infrastructure:latest
        ports:
        - containerPort: 9090  # gRPC
        - containerPort: 8080  # HTTP
        env:
        - name: GRPC_PORT
          value: "9090"
        - name: HTTP_PORT
          value: "8080"
        - name: DB_HOST
          value: postgres
        volumeMounts:
        - name: key-shares
          mountPath: /var/lib/mpc/key-shares
        - name: tls-certs
          mountPath: /etc/tls
      volumes:
      - name: key-shares
        persistentVolumeClaim:
          claimName: mpc-key-shares-pvc
      - name: tls-certs
        secret:
          secretName: mpc-infrastructure-tls
```

**应用层部署**：

```yaml
# kubernetes/mpcvault-server/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mpcvault-server
spec:
  replicas: 5  # 根据负载扩展
  selector:
    matchLabels:
      app: mpcvault-server
  template:
    metadata:
      labels:
        app: mpcvault-server
    spec:
      containers:
      - name: mpcvault-server
        image: mpcvault-server:latest
        ports:
        - containerPort: 8080
        env:
        - name: HTTP_PORT
          value: "8080"
        - name: MPC_INFRASTRUCTURE_ENDPOINT
          value: "mpc-infrastructure:9090"
        - name: MPC_INFRASTRUCTURE_TLS_ENABLED
          value: "true"
        volumeMounts:
        - name: tls-certs
          mountPath: /etc/tls
      volumes:
      - name: tls-certs
        secret:
          secretName: mpcvault-client-tls
```

**服务发现和负载均衡**：

```yaml
# kubernetes/mpc-infrastructure/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: mpc-infrastructure
spec:
  selector:
    app: mpc-infrastructure
  ports:
  - name: grpc
    port: 9090
    targetPort: 9090
  - name: http
    port: 8080
    targetPort: 8080
  type: ClusterIP
```

**监控和日志**：

- 基础设施层和应用层分别配置 Prometheus metrics
- 使用统一的日志收集系统（如 ELK、Loki）
- 分别配置告警规则

**版本管理**：

- 基础设施层版本：`v1.0.0`, `v1.1.0`（向后兼容）
- 应用层版本：独立版本号
- 使用语义化版本控制
- Protobuf 接口保持向后兼容

### 10.2 MPC 基础设施层改动

**基础设施层代码库需要包含**：
- [ ] `internal/mpc/protocol/` - 协议引擎
- [ ] `internal/mpc/key/` - 密钥服务
- [ ] `internal/mpc/signing/` - 签名服务
- [ ] `internal/mpc/session/` - 会话管理
- [ ] `internal/mpc/node/` - 节点管理
- [ ] `internal/mpc/storage/` - 存储接口
- [ ] `internal/mpc/grpc/` - gRPC 服务器
- [ ] `proto/infrastructure/v1/` - Protobuf 定义
- [ ] `cmd/server/` - 服务入口
- [ ] `internal/config/` - 配置管理
- [ ] `internal/persistence/` - 数据库连接

**应用层代码库需要包含**：
- [ ] `internal/vault/` - Vault 服务（MPCVault Server）
- [ ] `internal/wallet/` - Wallet 服务（MPCVault Server）
- [ ] `internal/organization/` - Organization 服务（MPCVault Server）
- [ ] `internal/signingrequest/` - 签名请求服务（MPCVault Server）
- [ ] `internal/personalwallet/` - 个人钱包服务（个人钱包）
- [ ] `internal/client/infrastructure/` - 基础设施层客户端
- [ ] `internal/api/` - API Handlers
- [ ] `internal/config/` - 配置管理
- [ ] `internal/persistence/` - 数据库连接

### 10.2 MPC 基础设施层改动

#### 10.2.1 当前状态分析

**已实现**：
- ✅ Protocol Engine (GG18/GG20/FROST)
- ✅ Key Service (DKG, 密钥管理)
- ✅ Signing Service (阈值签名)
- ✅ Session Manager
- ✅ Node Manager
- ✅ Storage (元数据、分片、会话)

**需要调整**：
- ⚠️ Key Service 需要区分根密钥和钱包密钥
- ⚠️ 需要支持 Hardened Derivation
- ⚠️ 需要支持客户端节点（用于备份）
- ⚠️ 需要支持 2-of-3 MPC（而不是3-of-3）
- ⚠️ 需要新增 SSS 备份服务
- ⚠️ 需要支持备份分片生成和下发

#### 10.1.2 Key Service 重构

**当前实现** (`internal/mpc/key/service.go`):
- `CreateKey` - 创建密钥（执行DKG）
- `GetKey` - 获取密钥信息
- `GenerateAddress` - 生成地址

**需要重构**:
1. **分离根密钥和钱包密钥**
   ```go
   // 根密钥操作（基础设施层）
   CreateRootKey(ctx, req) (*RootKeyMetadata, error)
   GetRootKey(ctx, keyID) (*RootKeyMetadata, error)
   DeleteRootKey(ctx, keyID) error
   
   // 钱包密钥派生（基础设施层）
   DeriveWalletKey(ctx, rootKeyID, chainType, index) (*WalletKeyMetadata, error)
   ```

2. **支持 Hardened Derivation**
   - 在 `DeriveWalletKey` 中实现 Hardened Derivation
   - 使用 HMAC-SHA512 派生
   - 每个 Wallet 使用独立的派生密钥

3. **修改数据模型**
   - `KeyMetadata` → `RootKeyMetadata`（根密钥）
   - 新增 `WalletKeyMetadata`（钱包密钥）

#### 10.1.3 节点管理增强

**当前实现** (`internal/mpc/node/manager.go`):
- 节点注册和发现
- 服务器节点管理

**需要新增**:
1. **客户端节点支持**
   - 节点类型：`client` vs `server`
   - 客户端节点注册接口
   - 客户端节点在线状态管理

2. **节点ID规范**
   - 客户端节点：`client-{userID}`
   - 服务器节点：`server-proxy-1`, `server-proxy-2`

#### 10.1.4 DKG 服务调整

**当前实现** (`internal/mpc/key/dkg.go`):
- 动态节点选择
- 从会话获取节点列表

**需要修改**:
1. **固定2-of-3节点列表**
   - 固定参与节点：`[server-proxy-1, server-proxy-2, client-{userID}]`
   - 阈值配置：threshold = 2, totalNodes = 3
   - 不再动态选择节点

2. **客户端节点通知**
   - DKG开始时通知客户端APP
   - 通过gRPC或WebSocket推送

3. **分片下发逻辑**
   - DKG完成后获取客户端分片
   - 加密后下发到客户端
   - 记录下发日志

#### 10.2.5 存储接口调整

**当前实现** (`internal/mpc/storage/interface.go`):
- `KeyMetadata` - 密钥元数据
- `KeyShareStorage` - 密钥分片存储

**需要调整**:
1. **分离根密钥和钱包密钥存储**
   ```go
   // 根密钥存储
   SaveRootKeyMetadata(ctx, key *RootKeyMetadata) error
   GetRootKeyMetadata(ctx, keyID string) (*RootKeyMetadata, error)
   
   // 钱包密钥存储
   SaveWalletKeyMetadata(ctx, key *WalletKeyMetadata) error
   GetWalletKeyMetadata(ctx, walletID string) (*WalletKeyMetadata, error)
   ```

2. **SSS备份分片存储**
   ```go
   // 备份分片存储（每个MPC分片有多个SSS备份分片）
   SaveBackupShare(ctx, keyID string, nodeID string, shareIndex int, share []byte) error
   GetBackupShare(ctx, keyID string, nodeID string, shareIndex int) ([]byte, error)
   ListBackupShares(ctx, keyID string, nodeID string) ([]*BackupShare, error)
   ListAllBackupShares(ctx, keyID string) (map[string][]*BackupShare, error) // 按nodeID分组
   ```
   
   **数据结构**：
   ```go
   type BackupShare struct {
       KeyID      string    // 根密钥ID
       NodeID     string    // 对应的MPC节点ID（server-proxy-1, server-proxy-2, client-{userID}）
       ShareIndex int       // 备份分片索引（1-5）
       ShareData  []byte    // 备份分片数据（加密存储）
       CreatedAt  time.Time
   }
   ```

3. **备份分片下发记录**
   - 新增 `backup_share_deliveries` 表（用于审计）
   - 记录备份分片生成时间、下发时间、状态、确认时间
   - 包含node_id字段，标识是哪个MPC分片的备份分片
   
   **存储接口扩展**：
   ```go
   // 备份分片存储接口
   type BackupShareStorage interface {
       // SaveBackupShare 保存备份分片
       SaveBackupShare(ctx context.Context, keyID string, nodeID string, shareIndex int, shareData []byte) error
       
       // GetBackupShare 获取备份分片
       GetBackupShare(ctx context.Context, keyID string, nodeID string, shareIndex int) ([]byte, error)
       
       // ListBackupShares 列出某个MPC分片的所有备份分片
       ListBackupShares(ctx context.Context, keyID string, nodeID string) ([]*BackupShare, error)
       
       // ListAllBackupShares 列出根密钥的所有备份分片（按nodeID分组）
       ListAllBackupShares(ctx context.Context, keyID string) (map[string][]*BackupShare, error)
   }
   ```

### 10.2 应用层：MPCVault Server (2B) 新增

#### 10.2.1 当前状态
- ❌ 未实现 Organization 管理
- ❌ 未实现 Vault 管理
- ❌ 未实现 Wallet 管理（应用层）
- ❌ 未实现 SigningRequest 管理

#### 10.2.2 需要新增模块

1. **Organization Service** (`internal/vault/organization/`)
   - [ ] `service.go` - 组织管理服务
   - [ ] `types.go` - 组织相关类型定义
   - [ ] `member.go` - 成员管理

2. **Vault Service** (`internal/vault/service.go`)
   - [ ] `service.go` - Vault 管理服务
   - [ ] `types.go` - Vault 相关类型定义
   - [ ] `policy.go` - 审批策略管理
   - [ ] `backup.go` - Vault 备份导出

3. **Wallet Service** (`internal/wallet/service.go`)
   - [ ] `service.go` - Wallet 管理服务
   - [ ] `types.go` - Wallet 相关类型定义
   - [ ] `balance.go` - 余额查询
   - [ ] `transaction.go` - 交易管理

4. **SigningRequest Service** (`internal/signingrequest/service.go`)
   - [ ] `service.go` - 签名请求服务
   - [ ] `types.go` - 签名请求相关类型定义
   - [ ] `approval.go` - 审批处理
   - [ ] `processor.go` - 后台处理已批准的请求

#### 10.2.3 数据库迁移

**新增表**:
- [ ] `organizations` - 组织表
- [ ] `organization_members` - 组织成员表
- [ ] `vaults` - Vault表（关联根密钥）
- [ ] `vault_members` - Vault成员表
- [ ] `wallets` - Wallet表（从Vault派生）
- [ ] `signing_requests` - 签名请求表
- [ ] `signing_approvals` - 签名审批表

#### 10.2.4 API 接口

**Organization 相关**:
- [ ] `POST /api/v1/organizations` - 创建组织
- [ ] `GET /api/v1/organizations/{orgID}` - 获取组织信息
- [ ] `POST /api/v1/organizations/{orgID}/members` - 添加成员

**Vault 相关**:
- [ ] `POST /api/v1/vaults` - 创建 Vault
- [ ] `GET /api/v1/vaults/{vaultID}` - 获取 Vault 信息
- [ ] `POST /api/v1/vaults/{vaultID}/members` - 添加成员
- [ ] `PUT /api/v1/vaults/{vaultID}/policy` - 设置审批策略

**Wallet 相关**:
- [ ] `POST /api/v1/vaults/{vaultID}/wallets` - 创建 Wallet
- [ ] `GET /api/v1/wallets/{walletID}` - 获取 Wallet 信息
- [ ] `GET /api/v1/wallets/{walletID}/balance` - 获取余额

**SigningRequest 相关**:
- [ ] `POST /api/v1/signing/requests` - 创建签名请求
- [ ] `POST /api/v1/signing/requests/{requestID}/approve` - 审批
- [ ] `GET /api/v1/signing/requests/{requestID}` - 获取请求详情

### 10.3 应用层：个人钱包 (2C) 新增

#### 10.3.1 当前状态
- ❌ 未实现个人钱包管理
- ❌ 未实现个人钱包地址管理

#### 10.3.2 需要新增模块

1. **PersonalWallet Service** (`internal/personalwallet/service.go`)
   - [ ] `service.go` - 个人钱包管理服务
   - [ ] `types.go` - 个人钱包相关类型定义
   - [ ] `address.go` - 地址管理

2. **数据库迁移**
   - [ ] `personal_wallets` - 个人钱包表
   - [ ] `personal_wallet_addresses` - 个人钱包地址表

3. **API 接口**
   - [ ] `POST /api/v1/personal/wallets` - 创建个人钱包
   - [ ] `GET /api/v1/personal/wallets/{walletID}` - 获取钱包信息
   - [ ] `POST /api/v1/personal/wallets/{walletID}/addresses` - 添加地址

### 10.4 SSS 备份服务新增

#### 10.4.1 当前状态
- ❌ 未实现 SSS 备份服务
- ❌ 未实现密钥恢复机制

#### 10.4.2 需要新增模块

1. **SSS 备份服务** (`internal/mpc/backup/`)
   - [ ] `sss.go` - SSS 算法实现
   - [ ] `service.go` - 备份服务
   - [ ] `types.go` - 备份分片类型定义
   - [ ] `recovery.go` - 密钥恢复服务

2. **数据库迁移**
   - [ ] `backup_shares` - 备份分片表（包含node_id字段，标识是哪个MPC分片的备份）
   - [ ] `backup_share_deliveries` - 备份分片下发记录表
   
   **数据库表设计**：
   ```sql
   -- 备份分片表（每个MPC分片有多个SSS备份分片）
   CREATE TABLE backup_shares (
       id BIGSERIAL PRIMARY KEY,
       key_id VARCHAR(255) NOT NULL,
       node_id VARCHAR(255) NOT NULL, -- MPC节点ID（server-proxy-1, server-proxy-2, client-{userID}）
       share_index INTEGER NOT NULL,  -- 备份分片索引（1-5）
       share_data BYTEA NOT NULL,      -- 备份分片数据（加密存储）
       created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
       FOREIGN KEY (key_id) REFERENCES root_keys(key_id) ON DELETE CASCADE,
       UNIQUE(key_id, node_id, share_index)
   );
   
   CREATE INDEX idx_backup_shares_key_node ON backup_shares(key_id, node_id);
   CREATE INDEX idx_backup_shares_key ON backup_shares(key_id);
   
   -- 备份分片下发记录表
   CREATE TABLE backup_share_deliveries (
       id BIGSERIAL PRIMARY KEY,
       key_id VARCHAR(255) NOT NULL,
       node_id VARCHAR(255) NOT NULL, -- MPC节点ID
       user_id VARCHAR(255) NOT NULL,
       share_index INTEGER NOT NULL,
       status VARCHAR(50) NOT NULL, -- pending, delivered, confirmed, failed
       delivered_at TIMESTAMPTZ,
       confirmed_at TIMESTAMPTZ,
       created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
       FOREIGN KEY (key_id) REFERENCES root_keys(key_id) ON DELETE CASCADE,
       UNIQUE(key_id, node_id, share_index, user_id)
   );
   
   CREATE INDEX idx_backup_deliveries_key_node ON backup_share_deliveries(key_id, node_id);
   CREATE INDEX idx_backup_deliveries_user ON backup_share_deliveries(user_id);
   ```

3. **API 接口**
   - [ ] `POST /api/v1/infrastructure/keys/{keyID}/backup/recover` - 恢复密钥
   - [ ] `GET /api/v1/infrastructure/keys/{keyID}/backup/shares` - 查询备份分片状态

### 10.5 认证系统增强

#### 10.4.1 当前状态
- ✅ 基础认证框架已实现
- ❌ 不支持 OAuth2
- ❌ 不支持 Passkey

#### 10.4.2 需要新增

1. **OAuth2 模块** (`internal/auth/oauth/`)
   - [ ] `google.go` - Google OAuth2 验证
   - [ ] `apple.go` - Apple Sign In 验证
   - [ ] `service.go` - OAuth 统一服务

2. **Passkey 模块** (`internal/auth/passkey/`)
   - [ ] `service.go` - Passkey 服务
   - [ ] `challenge.go` - 挑战生成和验证

3. **数据库迁移**
   - [ ] `oauth_providers` 表
   - [ ] `passkeys` 表

4. **API 接口**
   - [ ] `POST /api/v1/auth/oauth/google`
   - [ ] `POST /api/v1/auth/oauth/apple`
   - [ ] `POST /api/v1/auth/passkey/register`
   - [ ] `POST /api/v1/auth/passkey/login`

### 10.6 配置和依赖

#### 10.5.1 需要新增配置

1. **OAuth2 配置** (`internal/config/server_config.go`)
   ```go
   type OAuth struct {
       GoogleClientID     string
       GoogleClientSecret string
       AppleClientID      string
       AppleTeamID        string
       AppleKeyID         string
       ApplePrivateKey    string
   }
   ```

2. **MPC 客户端配置**
   ```go
   type MPC struct {
       // ... 现有配置
       ClientNodeEnabled bool // 是否启用客户端节点
       KeyShareDeliveryTimeout time.Duration // 分片下发超时时间
   }
   ```

3. **应用层配置**
   ```go
   type Application struct {
       EnableMPCVaultServer bool // 是否启用MPCVault Server (2B)
       EnablePersonalWallet bool // 是否启用个人钱包 (2C)
   }
   ```

#### 10.6.2 需要新增依赖
- Google OAuth2 库：`golang.org/x/oauth2`
- Apple Sign In 验证库：`github.com/golang-jwt/jwt/v5`
- Passkey 相关库：`github.com/go-webauthn/webauthn`
- SSS 库：`github.com/hashicorp/vault/shamir` 或 `github.com/codahale/sss`

---

## 11. 实施路线图

### 阶段1：认证系统增强（优先级：高）

**目标**：支持 Google/Apple 登录和 Passkey

**任务清单**:
1. 实现 OAuth2 模块（Google + Apple）
2. 实现 Passkey 服务
3. 数据库迁移（oauth_providers, passkeys）
4. API 接口实现
5. 测试和验证

**预计工作量**：5-7 天

### 阶段2：2-of-3 MPC 和 SSS 备份（优先级：高）

**目标**：实现2-of-3 MPC签名和SSS备份机制

**任务清单**:
1. 修改DKG服务，支持2-of-3模式
2. 修改签名服务，只使用服务器代理节点
3. 实现SSS备份服务
4. 实现备份分片生成和下发
5. 实现密钥恢复机制
6. 测试2-of-3签名流程
7. 测试SSS备份和恢复流程

**预计工作量**：10-14 天

### 阶段3：客户端节点和备份分片下发（优先级：高）

**目标**：支持客户端节点注册和备份分片下发

**任务清单**:
1. 修改节点管理，支持客户端节点类型（用于备份）
2. 实现客户端节点注册接口
3. 实现备份分片下发接口
4. 实现备份分片加密传输
5. 实现备份分片下发确认机制
6. 实现备份分片下发审计日志
7. 测试备份分片下发流程

**预计工作量**：5-7 天

### 阶段4：团队角色阈值签名（优先级：中）

**目标**：实现应用层的团队审批和阈值签名

**任务清单**:
1. 实现团队管理服务
2. 实现签名请求服务
3. 实现审批策略评估
4. 数据库迁移（teams, team_members, signing_requests, signing_approvals）
5. API 接口实现
6. 后台任务：处理已批准的请求
7. 测试完整流程

**预计工作量**：10-14 天

### 阶段5：集成测试和优化（优先级：中）

**目标**：端到端测试和性能优化

**任务清单**:
1. 端到端测试（客户端APP + 服务器）
2. 性能测试和优化
3. 安全审计
4. 文档完善

**预计工作量**：7-10 天

---

## 12. 关键技术决策

### 9.1 客户端节点通信方式

**决策**：使用 gRPC + WebSocket 混合方案

**理由**:
- gRPC：用于DKG和签名协议消息（高效、可靠）
- WebSocket：用于实时通知（客户端在线状态、审批通知）

### 9.2 备份分片下发安全机制

**决策**：端到端加密 + TLS + SSS 阈值保护

**理由**:
- 使用客户端公钥加密备份分片（端到端加密）
- 通过 TLS 传输（传输层加密）
- SSS 阈值保护：需要至少3个分片才能恢复
- 双重保护，确保备份分片安全

### 9.3 团队审批与MPC签名分离

**决策**：应用层审批 + 技术层签名

**理由**:
- 审批是业务逻辑，通过数据库实现
- 签名是技术实现，通过MPC协议实现
- 两者完全独立，降低复杂度

### 9.4 客户端备份分片存储

**决策**：客户端备份分片存储在客户端设备，服务器端存储其他备份分片

**理由**:
- 客户端备份分片只存储在客户端设备
- 服务器端存储其他备份分片（分片2-5）
- 使用SSS 3-of-5配置，需要至少3个分片才能恢复
- 如果客户端备份分片丢失，可以从服务器备份分片恢复

---

## 13. 安全考虑

### 10.1 认证安全

- ✅ OAuth2 ID Token 验证（防止伪造）
- ✅ Passkey 挑战-响应机制（防止重放攻击）
- ✅ 访问令牌过期和刷新机制

### 10.2 分片安全

- ✅ MPC分片加密存储（服务器端）
- ✅ 备份分片加密存储（客户端和服务器端）
- ✅ 分片加密传输（TLS + 端到端加密）
- ✅ 分片不完整存在（2-of-3 MPC模式）
- ✅ SSS备份阈值保护（3-of-5，需要至少3个分片才能恢复）

### 10.3 团队审批安全

- ✅ 审批记录不可篡改（数据库事务）
- ✅ 审批阈值验证（防止绕过）
- ✅ 审批审计日志

---

## 14. 总结

### 14.1 架构重构核心

**分层架构**：
1. **MPC 基础设施层**：提供 DKG、签名、密钥管理等核心能力
2. **应用层 (2B)**：MPCVault Server，面向团队的资产管理
3. **应用层 (2C)**：个人钱包，面向个人用户

**关键设计**：
- Vault 对应根密钥（通过2-of-3 DKG生成）
- Wallet 从 Vault 派生（使用 Hardened Derivation）
- 签名由服务器2个代理节点完成，不需要客户端参与
- 使用SSS备份方案，客户端保存备份分片用于恢复
- 应用层通过接口调用基础设施层

### 14.2 核心改动清单

#### 基础设施层改动（高优先级）

1. **Key Service 重构**
   - [ ] 分离根密钥和钱包密钥
   - [ ] 实现 Hardened Derivation
   - [ ] 修改数据模型（RootKeyMetadata, WalletKeyMetadata）

2. **节点管理增强**
   - [ ] 支持客户端节点类型
   - [ ] 客户端节点注册接口
   - [ ] 客户端节点在线状态管理

3. **DKG 服务调整**
   - [ ] 固定2-of-3节点列表
   - [ ] 客户端节点通知机制
   - [ ] 分片下发逻辑

4. **存储接口调整**
   - [ ] 分离根密钥和钱包密钥存储
   - [ ] 分片下发记录表

#### 应用层新增（高优先级）

1. **MPCVault Server (2B)**
   - [ ] Organization Service
   - [ ] Vault Service
   - [ ] Wallet Service
   - [ ] SigningRequest Service
   - [ ] 数据库迁移（organizations, vaults, wallets等）

2. **个人钱包 (2C)**
   - [ ] PersonalWallet Service
   - [ ] 数据库迁移（personal_wallets, personal_wallet_addresses）

#### 认证系统增强（中优先级）

1. **OAuth2 和 Passkey**
   - [ ] OAuth2 模块（Google + Apple）
   - [ ] Passkey 服务
   - [ ] 数据库迁移（oauth_providers, passkeys）

### 14.3 实施优先级

**阶段1：基础设施层重构（最高优先级）**
- Key Service 重构（分离根密钥和钱包密钥）
- 支持 Hardened Derivation
- 客户端节点支持
- 分片下发机制

**阶段2：MPCVault Server 应用层（高优先级）**
- Organization Service
- Vault Service
- Wallet Service
- SigningRequest Service

**阶段3：认证系统增强（中优先级）**
- OAuth2 和 Passkey 支持

**阶段4：个人钱包应用层（中优先级）**
- PersonalWallet Service

### 14.4 关键技术要点

1. **Vault 和 Wallet 关系**
   - Vault = 根密钥（通过DKG生成）
   - Wallet = 从Vault派生（使用Hardened Derivation）
   - 一个Vault可以派生多个Wallet（不同链）

2. **应用层与基础设施层分离**
   - 应用层管理业务数据（Organization, Vault, Wallet）
   - 基础设施层管理密钥和签名
   - 通过接口调用，保持解耦

3. **2-of-3 MPC 分片分配**
   - 服务器2个分片参与签名
   - 客户端1个分片仅用于备份，不参与签名
   - SSS备份分片：3-of-5配置，客户端保存1个，服务器保存其他

### 14.5 技术债务

- 客户端SDK开发（需要单独规划）
- 客户端设备安全存储（Secure Enclave/TrustZone集成）
- 多设备同步机制（用户更换设备时的备份分片恢复）
- Hardened Derivation 的完整实现和测试
- SSS备份分片的密钥恢复流程测试

---

**文档版本**: v2.0  
**最后更新**: 2025-01-XX  
**维护团队**: MPC 技术团队  
**参考文档**: [MPCVault 文档](https://docs.mpcvault.com/docs/)



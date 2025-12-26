# 详细设计文档：2-of-3 Delegated Guardian 与 团队多签实现

## 1. 概述
本文档基于 `docs/design/2_of_3_delegated_guardian.md` 的架构设计，结合 `go-mpc-wallet` 现有代码库，提供具体的落地实施细节。

核心目标：
1.  实现 **Delegated Guardian + Passkey (WebAuthn)** 模式：用户通过设备 Passkey 生成 Assertion 授权，Guardian 节点验证通过后才参与 MPC 签名。
2.  支持 **团队多签**：Guardian 支持配置“N-of-M”策略，收集齐 N 个团队成员的 Passkey Assertion 后才放行。

## 2. 系统架构变更

### 2.1 现有架构 (AS-IS)
*   **API Layer**: 接收 `POST /sign` 请求。
*   **MPC Coordinator**: 协调各节点启动签名会话。
*   **MPC Node**: 收到 `StartSign` gRPC 请求后，直接加载密钥分片进行计算。
*   **Database**: 存储密钥元数据、用户信息。

### 2.2 目标架构 (TO-BE)
*   **MPC Node (Guardian)**:
    *   新增 **策略引擎 (Policy Engine)**：拦截 `StartSign` 请求。
    *   新增 **鉴权模块 (Auth Module)**：验证 `AuthToken`（Passkey Assertion）。
*   **Database**:
    *   新增 `user_credentials` 表：存储用户/团队成员的 Passkey 凭证（credential_id/public_key/aaguid 等）。
    *   新增 `signing_policies` 表：存储钱包的鉴权策略（单人 vs 团队，阈值等）。
*   **API Protocol**:
    *   `StartSignRequest` (gRPC) 新增 `auth_tokens` 字段。

## 3. 数据库设计 (PostgreSQL)

### 3.1 用户 Passkey 凭证表 (`user_credentials`)
用于存储用户/团队成员的 WebAuthn 凭证（非 MPC 分片）。

```sql
CREATE TABLE user_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id VARCHAR(255) NOT NULL,            -- 关联的 MPC 钱包 ID (KeyID)
    credential_id TEXT NOT NULL,                -- WebAuthn Credential ID (Base64URL)
    public_key_cose TEXT NOT NULL,              -- COSE Key (Base64URL)
    aaguid UUID,                                -- Authenticator Attestation GUID
    attestation_type VARCHAR(50),               -- "none", "direct", "indirect"
    sign_count INT DEFAULT 0,                   -- 签名计数器
    device_name VARCHAR(100),                   -- 设备标识（可选）
    member_name VARCHAR(100),                   -- 团队成员名称（可选，用于审计）
    role VARCHAR(50) DEFAULT 'member',          -- 角色: owner, admin, member
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (wallet_id, credential_id)
);
CREATE INDEX idx_user_credentials_wallet ON user_credentials(wallet_id);
```

### 3.2 签名策略表 (`signing_policies`)
定义每个钱包的鉴权规则（单人/团队，阈值）。

```sql
CREATE TABLE signing_policies (
    wallet_id VARCHAR(255) PRIMARY KEY, -- 关联 KeyID
    policy_type VARCHAR(50) NOT NULL DEFAULT 'single', -- 'single' (单人), 'team' (团队多签)
    min_signatures INT NOT NULL DEFAULT 1, -- 最小所需签名数
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

## 4. 接口协议变更 (Protobuf)

### 4.1 修改 `mpc.proto`

文件路径: `internal/pb/mpc/v1/mpc.proto`

需要在 `StartSignRequest` 中增加 Passkey 鉴权令牌字段。为了支持团队多签，使用 `repeated` 列表。

```protobuf
message PasskeyAuthToken {
    string credential_id = 1;         // WebAuthn Credential ID (Base64URL)
    bytes passkey_signature = 2;      // Assertion signature
    bytes authenticator_data = 3;     // AuthenticatorData
    string client_data_json = 4;      // ClientDataJSON
    string member_id = 5;             // 可选：成员标识
}

message StartSignRequest {
    string session_id = 1;
    string key_id = 2;
    bytes message = 3;                // 交易原文或规范化哈希
    repeated PasskeyAuthToken auth_tokens = 11;
}
```

## 5. 核心逻辑实现

### 5.1 策略引擎 (Policy Engine)
位于 `internal/mpc/grpc/server.go` 的 `StartSign` 方法中。

**伪代码逻辑：**

```go
func (s *GRPCServer) StartSign(ctx context.Context, req *pb.StartSignRequest) (*pb.StartSignResponse, error) {
    if s.config.IsGuardianNode {
        policy, err := s.store.GetPolicy(req.KeyId)
        if err != nil {
            return nil, status.Errorf(codes.Internal, "failed to load policy")
        }
        // 允许的 Passkey 凭证
        allowedCreds, err := s.store.ListUserCredentials(req.KeyId) // credential_id/public_key_cose/role
        validSigCount := 0
        visited := map[string]bool{}
        for _, token := range req.AuthTokens {
            // A. 白名单 & 去重
            if !isAllowedCredential(token.CredentialId, allowedCreds) || visited[token.CredentialId] {
                continue
            }
            // B. WebAuthn 验证：origin/rpId、challenge(req.Message)、authenticatorData、clientDataJSON、signature、公钥(COSE)
            if verifyWebAuthnAssertion(token, req.Message, allowedCreds) {
                validSigCount++
                visited[token.CredentialId] = true
            }
        }
        if validSigCount < policy.MinSignatures {
            return &pb.StartSignResponse{
                Started: false,
                Message: fmt.Sprintf("Access Denied: need %d signatures, got %d", policy.MinSignatures, validSigCount),
            }, nil
        }
    }
    // ... 继续执行原有的 MPC StartSign 逻辑 ...
}
```

### 5.2 API 层变更
用户提交交易时，需要先在 APP 端完成 WebAuthn Assertion，然后通过 API 传给后端。

**请求结构体 (`internal/types`) 更新：**

```go
type SignTransactionRequest struct {
    // ... 现有字段 ...
    AuthTokens []struct {
        CredentialID       string `json:"credential_id"`
        PasskeySignature   string `json:"passkey_signature"`   // Base64URL
        AuthenticatorData  string `json:"authenticator_data"`  // Base64URL
        ClientDataJSON     string `json:"client_data_json"`    // JSON (string)
    } `json:"auth_tokens"`
}
```

**协调者 (`Coordinator`) 逻辑：**
Coordinator 收到 API 请求后，将 `AuthTokens` 封装进 `StartSignRequest`，然后广播给所有 MPC 节点（包括 Guardian 节点）。

## 6. 开发计划与步骤

1.  **Phase 1: 数据层 (Day 1)**
    *   创建 SQL 迁移脚本，建立 `user_auth_keys` 和 `signing_policies` 表。
    *   使用 SQLBoiler 生成 Go Model 代码。

2.  **Phase 2: 协议层 (Day 1)**
    *   修改 `mpc.proto`，添加 `AuthToken` 定义。
    *   重新编译 Protobuf 生成 Go 代码。

3.  **Phase 3: 业务逻辑 (Day 2-3)**
    *   在 `StartSign` 中实现拦截逻辑。
    *   实现 `verify` 函数（支持 Ed25519 和 Secp256k1 普通验签）。
    *   修改 API Handler 和 Coordinator，透传 `AuthTokens`。

4.  **Phase 4: 测试 (Day 4)**
    *   单元测试：测试策略引擎在不同阈值下的行为。
    *   集成测试：模拟 APP 端签名，验证端到端流程。

## 7. 安全注意事项
1.  **重放防护**：WebAuthn Challenge 必须绑定唯一交易 Hash + 时间窗/随机 ID，Guardian 校验 Challenge 与交易内容一致。
2.  **凭证绑定**：用户 Passkey 注册需进行严格身份验证（KYC/设备绑定），防止凭证被冒用。
3.  **来源校验**：Guardian 验证 `origin`/`rpId`，确保 Assertion 来源合法应用。
4.  **日志脱敏**：不要在日志中打印完整 `AuthToken` 内容，仅记录摘要与调用链路。

# MPCVault Server (2B) 设计与开发文档

**版本**: v1.0
**日期**: 2025-12-20
**建议项目路径**: `/Users/caimin/Desktop/kms/go-mpc-vault`
**目标**: 构建面向 B 端团队的 MPC 钱包管理服务（应用层），基于 `go-mpc-infra` 基础设施层。

---

## 1. 项目概述

`MPCVault Server` 是 MPC 钱包系统的应用层服务，专为 B 端企业/团队设计。它负责业务逻辑、用户管理、审批流控制、组织架构管理，并通过 gRPC 与底层的 MPC 基础设施（`go-mpc-infra`）交互以执行密钥生成和签名操作。

**核心职责**:
- **组织管理**: Organization -> Vault -> Wallet 层级结构。
- **权限控制**: 基于角色的访问控制 (RBAC) 和多级审批策略。
- **业务流程**: 处理开户、交易请求、审批、交易上链。
- **基础设施交互**: 调用 MPC 节点进行 DKG（密钥生成）和 TssSign（阈值签名）。

---

## 2. 技术栈与架构

- **语言**: Go (Golang) 1.23+
- **框架**: Echo (HTTP), gRPC (Client)
- **数据库**: PostgreSQL
- **ORM**: GORM 或 sqlx
- **配置**: Viper
- **日志**: Zap
- **文档**: Swagger/OpenAPI
- **外部服务**: 
  - **Alchemy**: 区块链数据节点 (余额, 交易, Notify).

### 2.1 分层架构 (Clean Architecture)

```
go-mpc-vault/
├── cmd/
│   └── server/
│       └── main.go              # 服务入口
├── internal/
│   ├── api/                     # HTTP 接口层 (Echo Handlers)
│   │   ├── middleware/          # 中间件 (Auth, CORS)
│   │   ├── v1/                  # V1 API
│   │   └── router.go            # 路由配置
│   ├── service/                 # 业务逻辑层
│   │   ├── auth.go              # 认证服务
│   │   ├── organization.go      # 组织/成员服务
│   │   ├── vault.go             # 金库服务
│   │   ├── wallet.go            # 钱包服务
│   │   └── signing.go           # 签名/审批服务
│   ├── repository/              # 数据访问层 (DB 操作)
│   ├── infrastructure/          # 基础设施交互
│   │   └── mpc_client.go        # gRPC 客户端封装
│   ├── model/                   # 领域模型与 DTO
│   └── config/                  # 配置加载
├── pkg/
│   ├── utils/                   # 通用工具
│   └── errors/                  # 错误定义
├── migrations/                  # SQL 迁移文件
├── go.mod
└── config.yaml
```

---

## 3. 核心数据模型 (Database Schema)

### 3.1 用户与认证 (Passkey / WebAuthn)

```sql
-- 用户表
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(100),
    avatar_url TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Passkey 凭证表 (FIDO2 / WebAuthn)
CREATE TABLE user_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    credential_id TEXT NOT NULL,       -- WebAuthn Credential ID (Base64)
    public_key TEXT NOT NULL,          -- 公钥 (COSE Key 格式)
    attestation_type VARCHAR(50),      -- e.g. "none", "direct"
    aaguid UUID,                       -- Authenticator Attestation GUID
    sign_count INT DEFAULT 0,          -- 签名计数器 (防克隆)
    device_name VARCHAR(100),          -- e.g. "iPhone 15 Pro"
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, credential_id)
);

-- 组织表
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    owner_id UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 组织成员表
CREATE TABLE organization_members (
    organization_id UUID REFERENCES organizations(id),
    user_id UUID REFERENCES users(id),
    role VARCHAR(50) NOT NULL, -- 'admin', 'operator', 'auditor'
    PRIMARY KEY (organization_id, user_id)
);
```

### 3.2 支持的链 (Chains)

```sql
-- 链配置表
CREATE TABLE chains (
    id VARCHAR(50) PRIMARY KEY,        -- e.g. 'ETH', 'BTC', 'SOL_MAINNET'
    name VARCHAR(100) NOT NULL,        -- e.g. 'Ethereum Mainnet'
    type VARCHAR(20) NOT NULL,         -- 'EVM', 'UTXO', 'SOLANA'
    chain_id VARCHAR(50),              -- 链 ID, e.g. '1', 'solana-mainnet'
    algorithm VARCHAR(50) NOT NULL,    -- 'ECDSA', 'EdDSA', 'Schnorr' (用于自动匹配 Vault Key)
    curve VARCHAR(50) NOT NULL,        -- 'secp256k1', 'ed25519'
    currency_symbol VARCHAR(20) NOT NULL, -- 'ETH', 'BTC', 'SOL'
    rpc_url TEXT,
    explorer_url TEXT,
    icon_url TEXT,                     -- 链 Logo URL
    is_testnet BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

### 3.3 资产配置 (Assets)

```sql
-- 资产配置表 (Token/Coin 支持)
-- 初始数据可由 Alchemy Token API 自动填充
CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_id VARCHAR(50) REFERENCES chains(id),
    symbol VARCHAR(20) NOT NULL,       -- 'USDT', 'USDC', 'ETH'
    name VARCHAR(100) NOT NULL,        -- 'Tether USD'
    type VARCHAR(20) NOT NULL,         -- 'NATIVE', 'ERC20', 'TRC20', 'SPL'
    contract_address VARCHAR(255),     -- 代币合约地址 (Native 币为 NULL)
    decimals INT NOT NULL DEFAULT 18,  -- 精度 (自动同步)
    icon_url TEXT,                     -- (自动同步)
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(chain_id, contract_address) -- 确保同链下代币唯一
);
```

### 3.4 金库与钱包 (Vault & Wallet)

```sql
-- 金库表 (逻辑容器)
CREATE TABLE vaults (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id),
    name VARCHAR(100) NOT NULL,
    threshold INT NOT NULL DEFAULT 2,  -- 审批阈值 (业务层)
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 金库密钥表 (关联 MPC 基础设施层的 KeyID)
-- 一个金库通常包含一对密钥：ECDSA (BTC/ETH) + EdDSA (SOL/APT)
CREATE TABLE vault_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vault_id UUID REFERENCES vaults(id),
    key_id VARCHAR(255) NOT NULL,       -- MPC Infra KeyID
    algorithm VARCHAR(50) NOT NULL,     -- 'ECDSA', 'EdDSA'
    curve VARCHAR(50) NOT NULL,         -- 'secp256k1', 'ed25519'
    public_key_hex TEXT NOT NULL,       -- 聚合公钥
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(vault_id, algorithm)
);

-- 钱包表 (从金库派生的具体链地址)
CREATE TABLE wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vault_id UUID REFERENCES vaults(id),
    chain_id VARCHAR(50) REFERENCES chains(id), -- 关联具体的链配置
    key_id VARCHAR(255) NOT NULL,      -- 关联具体使用的密钥 (vault_keys.key_id)
    address VARCHAR(255) NOT NULL,
    derive_path VARCHAR(255) NOT NULL, -- e.g. "m/44'/60'/0'/0/0"
    derive_index INT NOT NULL,         -- 派生索引
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(vault_id, chain_id, derive_index)
);

-- 钱包余额缓存表 (通过 Alchemy Notify 或 定时轮询更新)
CREATE TABLE wallet_balances (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id UUID REFERENCES wallets(id),
    asset_id UUID REFERENCES assets(id), -- 关联资产定义
    balance DECIMAL(36, 18) DEFAULT 0,   -- 可读余额
    raw_balance VARCHAR(100),            -- 链上原始数值 (Wei/Lamports)
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(wallet_id, asset_id)
);
```

### 3.5 风险控制 (Risk Control)

```sql
-- 地址白名单表
CREATE TABLE address_book (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id),
    chain_id VARCHAR(50) REFERENCES chains(id),
    address VARCHAR(255) NOT NULL,
    name VARCHAR(100) NOT NULL,        -- e.g. "Binance Cold Wallet"
    is_whitelisted BOOLEAN DEFAULT TRUE,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(organization_id, chain_id, address)
);

-- 交易限额策略表
CREATE TABLE spending_limits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vault_id UUID REFERENCES vaults(id),
    asset_id UUID REFERENCES assets(id), -- 具体限制哪个资产，NULL 表示按 USD 本位总额限制
    amount DECIMAL(36, 18) NOT NULL,
    window_seconds INT NOT NULL,       -- 时间窗口: 3600(1h), 86400(24h)
    action VARCHAR(20) DEFAULT 'REJECT', -- 'REJECT', 'REQUIRE_ADMIN'
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

### 3.6 审计日志 (Audit Logs)

```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id),
    user_id UUID REFERENCES users(id),
    action VARCHAR(50) NOT NULL,       -- 'LOGIN', 'CREATE_VAULT', 'APPROVE_TX', 'MODIFY_POLICY'
    resource_type VARCHAR(50),         -- 'vault', 'wallet', 'user'
    resource_id VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSONB,                     -- 变更详情快照
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

### 3.7 签名请求与审批

```sql
-- 签名请求表
CREATE TABLE signing_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vault_id UUID REFERENCES vaults(id),
    wallet_id UUID REFERENCES wallets(id),
    initiator_id UUID REFERENCES users(id),
    
    tx_data TEXT NOT NULL,             -- 原始交易数据 (Hex)
    tx_hash VARCHAR(255),              -- 交易哈希
    amount DECIMAL(36, 18),
    to_address VARCHAR(255),
    
    status VARCHAR(50) DEFAULT 'pending', -- pending, approved, signing, signed, rejected, failed
    mpc_session_id VARCHAR(255),       -- 关联的 MPC 签名会话 ID
    signature TEXT,                    -- 最终签名结果
    
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 审批记录表
CREATE TABLE approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID REFERENCES signing_requests(id),
    user_id UUID REFERENCES users(id),
    action VARCHAR(50) NOT NULL,       -- 'approve', 'reject'
    comment TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(request_id, user_id)
);
```

---

## 4. 接口设计 (REST API)

### 4.1 认证 (Passkey / WebAuthn)

采用标准的 WebAuthn 流程，替代传统的密码登录。

- `POST /api/v1/auth/register/challenge`: 注册开始
  - **返回**: `publicKeyCredentialCreationOptions` (包含 challenge, user info)。
- `POST /api/v1/auth/register/verify`: 注册完成
  - **输入**: 前端 `navigator.credentials.create()` 的返回结果。
  - **逻辑**: 验证 attestation，保存公钥到 `user_credentials` 表。

- `POST /api/v1/auth/login/challenge`: 登录开始
  - **返回**: `publicKeyCredentialRequestOptions` (包含 challenge)。
- `POST /api/v1/auth/login/verify`: 登录完成
  - **输入**: 前端 `navigator.credentials.get()` 的返回结果。
  - **逻辑**: 验证 assertion 签名，更新 `sign_count`，发放 JWT Session。

### 4.2 组织管理
> **注意**: 关键操作需使用 Passkey 进行 **二次验证 (Re-auth)**。
> 前端调用 `navigator.credentials.get()` 对关键数据 Hash 进行签名。
> Header: `X-Passkey-Signature`, `X-Passkey-Credential-ID`

- `POST /api/v1/orgs`: 创建组织 (Requires Passkey)
- `GET /api/v1/orgs`: 列出我的组织
- `POST /api/v1/orgs/:id/members`: 添加成员 (Requires Passkey)

### 4.3 金库与密钥 (Vaults)
- `POST /api/v1/vaults`: 创建金库 (Requires Passkey)
  - **后端逻辑**: 
    1. **验签**: 验证 Passkey 签名。
    2. 创建 Vault 记录。
    3. 并发调用 MPC Infra `StartDKG`。
- `GET /api/v1/vaults`: 列出金库
- `POST /api/v1/vaults/:id/wallets`: 创建/派生钱包 (Requires Passkey)
  - **请求参数**: `chain_id` (关联 `chains` 表)。

### 4.4 链与资产配置 (Chains & Assets)
- `GET /api/v1/chains`: 获取支持的链列表。
- `GET /api/v1/assets`: 获取支持的资产列表。
- `POST /api/v1/assets`: (Admin Only, Requires Passkey) 添加新资产支持。

### 4.5 风险控制 (Risk Control)
- `POST /api/v1/address-book`: 添加白名单地址 (Requires Passkey)。
- `GET /api/v1/address-book`: 获取地址簿。
- `POST /api/v1/vaults/:id/limits`: 设置金库限额策略 (Requires Passkey)。

### 4.6 交易与审批 (Transactions)
- `POST /api/v1/vaults/:id/sign`: 发起签名请求 (Requires Passkey)
  - **签名内容**: 必须包含交易关键信息 (金额, 地址) 的 Hash。
- `POST /api/v1/requests/:id/approve`: 审批请求 (Requires Passkey)
  - **关键逻辑**: 使用 Passkey 对交易 Hash 签名，确保审批的不可抵赖性。

### 4.7 安全性设计 (Security & Passkey)

为了确保端到端安全，所有敏感操作必须使用 **Passkey (WebAuthn)** 进行签名。MPCVault Server 仅作为签名的搬运工，最终验证由 MPC Infra 执行。

#### A. Challenge 构造规范
前端 (APP) 和 后端 (Infra) 必须遵循完全一致的 Challenge 构造规则，否则验签将失败。

1.  **交易签名 (Transaction Signing)**
    *   **Challenge**: `Base64URL(SHA256(RawTransactionBytes))`
    *   *注: 交易本身包含 Nonce，保证了唯一性。*

2.  **管理操作 (Admin Actions)**
    为了防止重放攻击，管理操作的 Challenge 必须包含时间戳或随机 ID。
    *   **修改策略**: `Base64URL(SHA256(key_id + "|" + policy_type + "|" + min_signatures))` (建议增加 timestamp)
    *   **创建金库**: `Base64URL(SHA256(key_id + "|" + session_id + "|" + algorithm + "|" + curve + "|" + threshold + "|" + total_nodes + "|" + sorted_node_ids))`

#### B. Origin 校验
MPC Infra 将校验 Passkey 签名中的 `origin` 字段，确保签名是由合法的 APP 生成的。
*   **Allowed Origins**: `android:apk-key-hash:xxx`, `https://vault.yourcompany.com`

---

## 5. 与基础设施层 (MPC Infra) 的集成

### 5.1 gRPC 客户端配置与协议升级
项目需引入 `go-mpc-infra` 的 Protobuf 定义，并建议对 Infra 层进行以下升级以支持端到端 Passkey 验证。

**Proto 文件参考**: `github.com/kashguard/go-mpc-infra/proto/mpc/v1/mpc.proto`

**建议升级 (Infra Layer)**:
为了防止应用层被攻破后导致 MPC 节点被滥用，MPC 节点应直接验证用户的 Passkey 签名。

```protobuf
// 升级后的 AuthToken
message AuthToken {
    string user_id = 1;
    // WebAuthn/Passkey 验证数据
    bytes passkey_signature = 2;     // assertion signature
    bytes authenticator_data = 3;    // authData
    bytes client_data_json = 4;      // clientDataJSON
    string credential_id = 5;        // credential ID
}

service MPCManagement {
    // 新增: 同步用户的 Passkey 公钥到 MPC 节点
    rpc AddUserPasskey(AddUserPasskeyRequest) returns (AddUserPasskeyResponse);
}
```

**关键服务**:
1.  **MPCManagement**: 
    - `AddUserPasskey`: 当用户在 App 注册/添加 Passkey 时，同步调用此接口将公钥下沉到 Infra 层。
    - `SetSigningPolicy`: 设置策略（如需 2/3 用户 Passkey 签名）。
2.  **MPCNode / MPCCoordinator**: 
    - `StartDKG`: 创建 Vault 时调用。
    - `StartSign`: 审批通过后调用，**必须传入收集到的 Passkey 签名列表**。

### 5.2 核心流程交互

#### A. 创建 Vault (DKG 流程)
1.  用户调用 `POST /api/v1/vaults`。
2.  **MPCVault Server** 生成两个唯一的 `session_id` (分别用于 ECDSA 和 EdDSA)。
3.  **MPCVault Server** 并发调用 Coordinator 的 `StartDKG`。
    - 调用 1: `algorithm=ECDSA`, `curve=secp256k1`。
    - 调用 2: `algorithm=EdDSA`, `curve=ed25519`。
4.  等待 DKG 完成。
5.  DKG 成功后，将两个 `key_id` 和 `public_key` 存入 `vault_keys` 表。

### 5.3 区块链数据集成 (Alchemy)

项目将深度集成 [Alchemy](https://www.alchemy.com/)，以减少自建索引器 (Indexer) 的开发和维护成本。

**核心功能集成**:

1.  **资产元数据 (Metadata)**:
    - 使用 `alchemy_getTokenMetadata` 自动获取 Token 的名称、精度、Logo。
    - 优势: 无需手动维护庞大的 Token 列表。

2.  **余额查询 (Balances)**:
    - 使用 `alchemy_getTokenBalances` (EVM) 和 `getTokenAccountsByOwner` (Solana) 实时获取余额。
    - 优势: 支持所有 ERC20/SPL 代币，无需逐个合约查询。

3.  **交易历史 (History)**:
    - 使用 Alchemy **Transfers API** (`alchemy_getAssetTransfers`) 获取充值和提现记录。
    - **设计决策**: 本地仅存储 MPC 发起的 `signing_requests` (用于审批审计)，完整的流水（包括外部充值）直接查询 Alchemy，不在本地数据库通过扫块构建。

4.  **实时通知 (Notify)**:
    - 配置 Webhooks 监听钱包地址的 `ADDRESS_ACTIVITY`。
    - 收到回调后，仅需更新 `wallet_balances` 缓存，并推送消息给前端。

5.  **Gas 估算**:
    - 使用 Alchemy **Gas Station** 或 `eth_feeHistory` 获取推荐费率，确保交易快速上链。

**不支持的链**:
对于 Alchemy 尚未支持的链 (如 BTC, TRON)，需通过适配器模式接入其他节点服务 (如 Blockstream, TronGrid)。

#### B. 发起交易与签名 (Sign 流程)
1.  用户 A 发起提现请求 -> 写入 `signing_requests`，状态 `pending`。
2.  用户 B, C 进行审批 -> **前端调用 Passkey 签名** -> 后端验证并写入 `approvals`。
3.  当审批数 >= 阈值 (如 2/3):
    - **MPCVault Server** 锁定请求状态为 `signing`。
    - 查找 Wallet 对应的 `key_id` (从 `wallets` 表或 `vault_keys` 表)。
    - 构造待签名消息 `message_hash`。
    - **聚合 Passkey 签名**: 从 `approvals` 表中提取所有审批人的 Passkey 签名数据。
    - 通过 gRPC 调用 Coordinator 的 `StartSign`。
        - `key_id`: 对应的 `key_id`。
        - `message`: 交易 Hash。
        - `derivation_path`: 钱包的派生路径。
        - `auth_tokens`: **传入聚合的 Passkey 签名列表**。
4.  **MPC Coordinator 验证**: Coordinator 使用同步的 Passkey 公钥验证每个 `auth_token`。验证失败则拒绝签名。
5.  等待签名完成。
6.  获取 `signature`，更新 `signing_requests` 状态为 `signed`。
7.  (可选) 广播交易到区块链网络。

---

## 6. 开发步骤指南

请 AI 助手按照以下步骤生成代码：

1.  **初始化项目**:
    - 创建目录结构。
    - 初始化 `go.mod`。
    - 配置 `Makefile` (lint, build, run)。

2.  **数据层实现**:
    - 定义 `internal/model` 中的结构体。
    - 编写 SQL 迁移脚本或 GORM AutoMigrate。
    - 实现 `internal/repository`，封装 CRUD 操作。

3.  **基础设施客户端**:
    - 复制或引用 `mpc.proto`。
    - 生成 Go gRPC 代码。
    - 实现 `internal/infrastructure/mpc_client.go`，封装 `StartDKG`, `StartSign` 等调用。

4.  **业务服务层**:
    - 实现 `AuthService` (JWT)。
    - 实现 `VaultService` (包含 DKG 调用逻辑)。
    - 实现 `SigningService` (包含 审批逻辑 和 触发签名逻辑)。

5.  **API 接口层**:
    - 使用 Echo 编写 Handler。
    - 绑定 Request DTO，验证参数。
    - 调用 Service 层，返回 Response DTO。

6.  **集成测试**:
    - 编写 Mock MPC Server 用于测试。
    - 测试完整的 开户 -> 审批 -> 签名 流程。

---

## 7. 注意事项

- **安全性**: 所有私钥操作仅在 MPC Infra 层进行，MPCVault Server **不接触** 私钥分片。
- **幂等性**: DKG 和 Sign 操作应当设计为幂等，防止网络重试导致重复执行。
- **异步处理**: 签名过程可能较慢，建议使用 任务队列 + 轮询/WebSocket 通知前端结果。

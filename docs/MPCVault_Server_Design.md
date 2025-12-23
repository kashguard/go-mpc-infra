# MPCVault Server (2B) 设计与开发文档

**版本**: v1.1
**日期**: 2025-12-23
**建议项目路径**: `/Users/caimin/Desktop/kms/go-mpc-Vault`
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

## 2. 技术栈与架构（与当前实现对齐）

- **语言**: Go (Golang) 1.25.x
- **框架**: gRPC（Server/Client），Echo（HTTP 可选）
- **数据库**: PostgreSQL
- **ORM**: GORM 或 sqlx
- **配置**: Viper
- **日志**: Zerolog
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

### 5.1 gRPC 接口与安全通信
项目直接引入本仓库的 Protobuf 定义并通过 gRPC 与 Infra 层交互；节点间通信全面启用 mTLS。

**Proto 文件参考（当前实现）**: 
- `proto/infra/v1/signing.proto`
- `proto/infra/v1/common.proto`
- `proto/infra/v1/key.proto`（如存在）

**安全通信（mTLS）**:
- 节点间 gRPC 使用自签 CA 与服务端证书，必要时携带客户端证书。
- 证书路径（参见 `docker-compose.yml`）：
  - `MPC_TLS_CERT_FILE`: `/app/certs/server.crt`（docker-compose.yml:69-73）
  - `MPC_TLS_KEY_FILE`: `/app/certs/server.key`
  - `MPC_TLS_CA_CERT_FILE`: `/app/certs/ca.crt`
- 客户端加载 CA 与（可选）客户端证书（见 `internal/mpc/grpc/client.go` 中 TLS 配置，`internal/mpc/grpc/client.go:146-186`）。

**关键服务（Infra 层 gRPC，当前实现）**:
- `infra.v1.SigningService`（`proto/infra/v1/signing.proto:9-25`）
  - `CreateSigningSession`，`ThresholdSign`，`GetSigningSession`，`BatchSign`，`VerifySignature`
- `infra.v1.KeyService`（文件路径如存在）
  - `CreateRootKey`，`GetRootKey`，`ListRootKeys`，`DeriveWalletKey` 等（实现见 `internal/infra/grpc/key_service.go:15-68`, `internal/infra/grpc/key_service.go:113-165`, `internal/infra/grpc/key_service.go:167-200`）

**鉴权令牌（Passkey，当前实现）**:
- `AuthToken` 字段（`proto/infra/v1/signing.proto:117-123`）
  - `passkey_signature`, `authenticator_data`, `client_data_json`, `credential_id`
  - 由应用层在审批完成后聚合并随签名请求一同提交到 Infra 层进行验证。

### 5.2 核心流程交互

#### A. 创建 Vault (DKG 流程)
1.  用户调用 `POST /api/v1/vaults`。
2.  **MPCVault Server** 生成两个唯一的 `session_id` (分别用于 ECDSA 和 EdDSA)。
3.  **MPCVault Server** 并发调用 Infra `KeyService.CreateRootKey`（底层触发 DKG）。
    - 调用 1: `algorithm=ECDSA`, `curve=secp256k1`（聚合公钥用于 EVM/BTC 等）。
    - 调用 2: `algorithm=EdDSA`, `curve=ed25519`（聚合公钥用于 SOL/APT 等）。
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
    - 通过 gRPC 调用 Infra `SigningService.ThresholdSign`。
        - `key_id`: 对应的 `key_id`
        - `message`: 交易 Hash
        - `auth_tokens`: **传入聚合的 Passkey 签名列表**
4.  **Infra 层验证**: 使用同步的 Passkey 公钥验证每个 `auth_token`。验证失败则拒绝签名。
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

---

## 8. 业务层细化（审批、风控、Passkey 交互）

### 8.1 审批流程详解（状态机与触发）
- 状态机：`pending → approved → signing → signed | rejected | failed`
- 触发条件：当 `approvals` 数量满足阈值（如 2/3）且风控检查通过，进入 `signing`。
- 服务端流程：
  - 创建 `signing_requests`，持久化 `tx_data` 与 `message_hash`。
  - 审批动作需二次验证（Passkey），将验签后的审批记录写入 `approvals`。
  - 聚合审批人的 Passkey 验证数据为 `AuthToken[]`（见 `proto/infra/v1/signing.proto:117-123`）。
  - 调用 Infra `SigningService.ThresholdSign` 完成阈值签名（见 `proto/infra/v1/signing.proto:38-58`，实现映射见 `internal/infra/grpc/signing_service.go:70-81` 与 调用见 `internal/infra/grpc/signing_service.go:83-103`）。

### 8.2 风控策略执行（白名单与限额）
- 白名单：对 `to_address` 基于组织与链维度进行匹配，非白名单可直接拒绝或升级审批。
- 限额：按资产维度或按 USD 总额进行滑动窗口统计与限制（参考 `spending_limits` 表）。
- 执行策略：
  - `REJECT`：直接拒绝签名请求。
  - `REQUIRE_ADMIN`：升级为管理员审批，提升阈值或增加必选审批人。
- 签名前检查顺序：
  - 地址白名单 → 限额策略 → 交易合规性（黑名单、已知风险地址）→ 通过后进入 `signing`。

### 8.3 Passkey 前后端交互样例（WebAuthn）

#### A. 前端发起关键操作时的二次验证（Re-auth）
```javascript
const challenge = await fetch("/api/v1/auth/login/challenge").then(r => r.json());
const assertion = await navigator.credentials.get({
  publicKey: {
    challenge: Uint8Array.from(atob(challenge.base64), c => c.charCodeAt(0)),
    allowCredentials: challenge.allowCredentials,
    timeout: 60000,
    userVerification: "required"
  }
});
```

将以下头加入后端关键接口请求（如创建金库、审批、发起签名）：
```http
X-Passkey-Signature: <Base64URL(assertion.response.signature)>
X-Passkey-Credential-ID: <Base64URL(assertion.id)>
X-Passkey-Authenticator-Data: <Base64URL(assertion.response.authenticatorData)>
X-Passkey-Client-Data-JSON: <Base64URL(assertion.response.clientDataJSON)>
```

#### B. 后端校验示例（REST 层）
```bash
curl -X POST https://vault.example.com/api/v1/requests/{id}/approve \
  -H "Authorization: Bearer <jwt>" \
  -H "X-Passkey-Signature: <...>" \
  -H "X-Passkey-Credential-ID: <...>" \
  -H "X-Passkey-Authenticator-Data: <...>" \
  -H "X-Passkey-Client-Data-JSON: <...>" \
  -d '{"comment":"approve"}'
```

后端校验步骤：
- 解析 `clientDataJSON` 并校验 `challenge` 与 `origin`。
- 使用存储的 Passkey 公钥验证 `signature` 与 `authenticatorData`。
- 校验通过后写入 `approvals` 并更新 `sign_count`。

#### C. 聚合审批并触发阈值签名（与 Infra 对接）
应用层在满足阈值后构造 `AuthToken[]` 并调用 Infra：
```json
{
  "key_id": "key-abc123",
  "message_hex": "0x...",
  "chain_type": "EVM",
  "auth_tokens": [
    {
      "passkey_signature": "<Base64URL>",
      "authenticator_data": "<Base64URL>",
      "client_data_json": "<Base64URL>",
      "credential_id": "<Base64URL>"
    },
    {
      "passkey_signature": "<Base64URL>",
      "authenticator_data": "<Base64URL>",
      "client_data_json": "<Base64URL>",
      "credential_id": "<Base64URL>"
    }
  ]
}
```
服务端会将该结构映射到内部类型并转发到 Infra（参见 `internal/infra/grpc/signing_service.go:70-81`）。

#### D. mTLS 配置与校验要点
- 所有节点间 gRPC 启用 TLS，证书在 `docker-compose.yml` 中配置（`MPC_TLS_*`，见 `docker-compose.yml:69-73`）。
- 客户端加载 CA 与可选客户端证书（见 `internal/mpc/grpc/client.go:146-186`）。
- 若缺少客户端证书，确保服务端仅要求单向 TLS；若启用 mTLS，必须提供客户端证书与私钥。

### 8.4 REST 接口示例与字段规范
- 创建金库
  - `POST /api/v1/vaults`
  - 请求体：
    - `name`: 金库名称
    - `threshold`: 审批阈值（业务层）
    - `chains`: 需要支持的链集合（用于派生钱包）
  - 头部需携带 Passkey 验证头（见 8.3）
  - 结果：返回 `vault_id`，并异步跟踪 DKG 产生的 `key_id`（通过后台调用 `KeyService.CreateRootKey`，参考 `internal/infra/grpc/key_service.go:15-68`）
- 派生钱包
  - `POST /api/v1/vaults/:id/wallets`
  - 请求体：
    - `chain_id`, `derive_index`
  - 结果：返回 `wallet_id`, `address`, `key_id`
- 发起签名请求
  - `POST /api/v1/vaults/:id/sign`
  - 请求体：
    - `wallet_id`, `tx_data`（或 `message_hex`）, `to_address`, `amount`
  - 结果：返回 `request_id`，状态为 `pending`
- 审批签名请求
  - `POST /api/v1/requests/:id/approve`
  - 请求体：`action` = `approve | reject`, `comment`
  - 头部需携带 Passkey 验证头（见 8.3）
  - 结果：返回当前累计审批数与是否达到阈值
- 触发阈值签名（由服务端在达到阈值与风控通过后触发）
  - 后端聚合 `AuthToken[]` 并调用 Infra `SigningService.ThresholdSign`（`proto/infra/v1/signing.proto:38-58`；实现调用见 `internal/infra/grpc/signing_service.go:83-103`）
  - 结果：`signature`, `public_key`, `participating_nodes`

字段设计建议：
- `amount` 使用 `DECIMAL(36,18)` 存储，接口层采用字符串表示以避免浮点误差。
- `tx_data` 推荐使用十六进制字符串或原始字节的 Base64URL。
- 所有返回时间字段使用 ISO8601 字符串（`time.RFC3339`，参考 `internal/infra/grpc/*:41-47` 等）。

### 8.5 风控执行伪代码
```go
func CheckRiskAndTransition(ctx context.Context, reqID UUID) error {
  req := LoadSigningRequest(ctx, reqID)
  // 1. 白名单
  if !IsWhitelisted(req.OrganizationID, req.ChainID, req.ToAddress) {
    if Policy(req.VaultID).ActionOnNonWhitelist == "REJECT" {
      UpdateStatus(reqID, "rejected")
      return ErrNonWhitelist
    }
    RequireRoleApproval(reqID, "admin")
  }
  // 2. 限额窗口
  limits := LoadSpendingLimits(req.VaultID, req.AssetOrUSD)
  sum := SumWithdrawalsInWindow(req.VaultID, req.AssetOrUSD, limits.WindowSeconds)
  if sum+req.Amount > limits.Amount {
    if limits.Action == "REJECT" {
      UpdateStatus(reqID, "rejected")
      return ErrLimitExceeded
    }
    RequireRoleApproval(reqID, "admin")
  }
  // 3. 合规检查（黑名单等）
  if IsRiskAddress(req.ToAddress) {
    RequireRoleApproval(reqID, "admin")
  }
  // 4. 阈值满足则进入 signing
  if ApprovalsSatisfied(reqID, Threshold(req.VaultID)) {
    UpdateStatus(reqID, "signing")
    tokens := AggregateAuthTokens(reqID)
    // 调用 Infra 阈值签名
    resp := Infra.SigningService.ThresholdSign({
      KeyId: ResolveKeyID(req.WalletID),
      MessageHex: req.MessageHex,
      ChainType: req.ChainType,
      AuthTokens: tokens,
    })
    PersistSignature(reqID, resp.Signature, resp.SignedAt)
    UpdateStatus(reqID, "signed")
    return nil
  }
  return nil
}
```
实现参考：
- gRPC 错误码与映射：`google.golang.org/grpc/codes` 使用见 `internal/infra/grpc/signing_service.go:86-88`, `internal/infra/grpc/key_service.go:41-43, 74-75`。
- 时间与格式化：`time.RFC3339` 使用见 `internal/infra/grpc/*:41-47, 58-65, 89-96`。

### 8.6 Challenge 规范强化与防重放
- 交易类：`Base64URL(SHA256(RawTransactionBytes))`（见 4.7）
- 管理类（含时间戳/随机数）：`Base64URL(SHA256(key_id|session_id|algorithm|curve|threshold|total_nodes|sorted_node_ids|timestamp))`
- 服务端维护 `challenge` 的使用窗口与一次性标记（nonce 存储），过期或复用则拒绝。
- 校验 `origin`（允许来源列表），并记录设备指纹与 `credential_id`。

### 8.7 错误处理与返回码约定
- REST：
  - 401 未认证，403 无权限，400 参数错误，409 并发/幂等冲突，422 验证失败（Passkey/风控），500 服务异常。
- gRPC：
  - 使用 `codes.InvalidArgument`（参数错误）、`codes.PermissionDenied`（权限）、`codes.Unauthenticated`（认证）、`codes.FailedPrecondition`（风控不通过）、`codes.Internal`（服务异常）。
  - 参考实现：`internal/infra/grpc/signing_service.go:86-88`, `internal/infra/grpc/key_service.go:41-43, 74-75, 131-132, 179-180`。

### 8.8 审计日志扩展
- 记录字段：`action`, `resource_type`, `resource_id`, `user_id`, `origin`, `device_info`, `details(JSONB)`。
- 对关键动作（创建金库、审批、签名触发）记录请求上下文与策略命中情况（如白名单命中、限额超额、风控升级）。

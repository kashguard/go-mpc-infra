# 重构方案：用户管理解耦与固定节点角色

**日期**: 2025-12-18
**状态**: 待实施
**关联文档**: `docs/design/2_of_3_delegated_guardian.md`

## 1. 核心目标

1.  **用户管理解耦**：基础设施层（Infrastructure Layer）不再感知或存储用户信息（`user_id`），仅提供纯粹的 MPC 密钥生成与签名能力。用户身份、租户关系、组织架构完全由应用层（Application Layer）管理。
2.  **固定节点角色**：废弃动态生成 `client-{userID}` 节点的模式，改为系统级固定的 3 个 MPC 参与方，对应 **2-of-3 Delegated Guardian** 模型。
3.  **端到端认证**：应用层与基础设施层之间采用 E2E 认证（mTLS + 可选 JWT），而非传递用户 ID；用户层面的操作确认改为 **Passkey (WebAuthn)**，由 Guardian 验证 Assertion 后再参与签名。

## 2. 架构变更

### 2.1 节点角色重定义

所有 MPC 会话（DKG 和 TSS）将由以下三个固定节点参与，不再随用户变化：

| 分片编号 | 节点 ID (Internal) | 角色 (Design) | 职责 | 部署位置 |
| :--- | :--- | :--- | :--- | :--- |
| **Share 1** | `server-proxy-1` | **运营方 (Operator)** | 业务发起方，参与 DKG 与 TSS | 云端 A / 业务服务器 |
| **Share 2** | `server-proxy-2` | **鉴权代理 (Guardian)** | 用户代理人，验证指令后参与 TSS | 云端 B / TEE / 独立环境 |
| **Share 3** | `server-backup-1` | **冷备份 (Cold Backup)** | 灾难恢复，仅参与 DKG，**不参与 TSS** | 离线存储 / 隔离环境 |

> **注意**：原 `client-{userID}` 节点逻辑将被移除。基础设施层不再为每个用户维护独立的 MPC 节点。

### 2.2 责任边界

*   **应用层 (Application Layer)**
    *   管理用户系统（User, Tenant, Organization）。
    *   维护 `user_id` <-> `key_id` / `vault_id` / `wallet_id` 的映射关系。
    *   处理业务鉴权（OAuth, RBAC）。
    *   向基础设施层发起请求时，使用服务级凭证（mTLS 证书）。

*   **基础设施层 (Infrastructure Layer)**
    *   管理 MPC 密钥（Key Metadata, Key Shares）。
    *   执行 DKG 和 TSS 协议。
    *   **不存储**任何 `user_id` 字段。
    *   **不验证**用户维度的权限（只验证调用方服务的 mTLS/JWT）。

## 3. 详细修改计划

### 3.1 接口定义 (Protobuf)

**文件**: `proto/infra/v1/key.proto`

*   **移除** `CreateRootKeyRequest` 中的 `user_id` 字段。
*   **移除** `CreateRootKeyRequest` 中的 `user_public_key` 字段（在 2-of-3 Delegated Guardian 模式下，用户不持有分片，无需公钥加密下发）。
*   **移除** 任何其他请求中用于传递用户身份的字段。

```protobuf
// 修改前
message CreateRootKeyRequest {
    // ...
    string user_id = 7; // 移除此字段
    string user_public_key = 8; // 移除此字段
    // ...
}

// 修改后
message CreateRootKeyRequest {
    string algorithm = 1;
    string curve = 2;
    // ... 仅保留算法参数
}
```

### 3.2 密钥服务 (Key Service)

**文件**: `internal/infra/grpc/key_service.go`, `internal/infra/key/service.go`

1.  **RPC 层**：`CreateRootKey` 方法不再接收 `user_id`，也不再将其透传给内部服务。
2.  **Service 层**：
    *   `CreateRootKey` 内部逻辑不再依赖 `req.UserID`。
    *   不再生成或查找 `client-{userID}` 节点。

### 3.3 DKG 逻辑 (DKG Service)

**文件**: `internal/infra/key/dkg.go`

1.  **固定节点列表**：
    *   将 2-of-3 模式下的参与节点列表硬编码为：`["server-proxy-1", "server-proxy-2", "server-backup-1"]`。
    *   移除所有涉及 `client-` 前缀节点的逻辑。
    *   移除 "placeholder" 节点逻辑。

### 3.4 备份服务 (Backup Service)

**文件**: `internal/infra/backup/service.go`

1.  **数据模型**：`BackupShareDelivery` 结构体移除 `UserID`。
2.  **下发逻辑**：
    *   备份分片的生成与存储仅关联 `key_id` 和 `node_id`。
    *   不再根据 `user_id` 过滤或推送分片（应用层需通过 key_id 自行查询状态）。

### 3.5 应用层适配 (API Handlers)

**文件**: `internal/api/handlers/infra/keys/post_create_key.go`

1.  **流程变更**：
    *   Handler 依然从中间件获取当前登录用户（`auth.UserFromEchoContext`）。
    *   调用 `KeyService.CreateRootKey` 时，**不传递** 用户信息。
    *   获得 `key_id` 后，在**应用层数据库**中创建记录：`INSERT INTO user_keys (user_id, key_id, ...) VALUES (...)`。

### 3.6 认证机制

1.  **mTLS**：基础设施层 gRPC Server 强制开启 mTLS，验证客户端证书。
2.  **拦截器**：基础设施层通过拦截器提取证书中的 Common Name (CN) 作为 `app_id`，用于审计日志，而非记录 `user_id`。

## 4. 数据流对比

**修改前**:
1. User -> App API (带 Token)
2. App API 解析 Token -> 得到 UserID
3. App API -> Infra gRPC (CreateRootKey, UserID)
4. Infra DKG -> 包含节点 `client-{UserID}`
5. Infra DB -> 记录 Key 属于 UserID

**修改后**:
1. User -> App API (带 Token)
2. App API 解析 Token -> 得到 UserID
3. App API -> Infra gRPC (CreateRootKey, **无 UserID**)
4. Infra DKG -> 固定节点 `server-proxy-1`, `server-proxy-2`, `server-backup-1`
5. Infra DB -> 记录 Key (无 User 信息)
6. App API -> App DB -> 记录 `UserID` 拥有 `KeyID`

## 5. 实施步骤

1.  **Proto 修改**: 修改 `.proto` 文件并重新生成 Go 代码。
2.  **Service 改造**: 修改 `DKGService` 和 `KeyService` 适配固定节点，移除用户字段。
3.  **App 适配**: 修改 API Handler，增加应用层关联表的写入逻辑（如暂无关联表，需新增 Migration）。
4.  **测试验证**:
    *   验证 DKG 流程是否能正确使用 3 个固定节点完成。
    *   验证签名流程是否仅需前两个节点参与。
    *   验证应用层能否正确关联新创建的密钥。

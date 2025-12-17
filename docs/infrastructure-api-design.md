# MPC 钱包基础设施层 API 设计规范

## 1. 概述

本文档定义了 MPC 钱包基础设施层（Infrastructure Layer）的全新对外接口。
设计目标是提供一套全面、安全、易于集成的接口，支持 MPCVault Server、管理后台以及客户端（App/SDK）的交互。

### 1.1 设计原则
*   **RPC First**: 核心业务逻辑优先定义为 gRPC 接口 (Protobuf)，确保高性能和类型安全。
*   **RESTful Gateway**: 所有 gRPC 接口均通过 HTTP/JSON 网关暴露 REST API，方便 Web 端和轻量级客户端调用。
*   **安全优先**: 
    *   **mTLS**: 节点间和服务器间通信强制使用双向 TLS。
    *   **JWT**: 应用层接口强制校验 JWT Token（包含 TenantID, UserID, Permissions）。
*   **基础设施导向**: 废弃旧的通用 MPC API，API 设计紧贴“密钥管理”、“签名服务”、“节点调度”等基础设施需求。

---

## 2. 服务模块定义

基础设施层对外暴露以下核心服务：

1.  **NodeService**: 节点注册、发现与状态管理。
2.  **KeyService**: 根密钥生成 (DKG)、钱包密钥派生、密钥查询。
3.  **SigningService**: 交易签名 (MPC Sign)。
4.  **BackupService**: SSS 分片备份、下发与恢复。

---

## 3. 详细接口定义

### 3.1 节点服务 (NodeService)

负责管理参与 MPC 计算的所有节点（Server Proxy 和 Client App）。

**Protobuf 定义**:
```protobuf
service NodeService {
    // 注册新节点 (Client App 首次初始化时调用)
    rpc RegisterNode(RegisterNodeRequest) returns (RegisterNodeResponse);
    
    // 节点心跳上报 (维持在线状态)
    rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
    
    // 查询节点列表 (Admin/Coordinator 使用)
    rpc ListNodes(ListNodesRequest) returns (ListNodesResponse);
    
    // 获取节点连接信息 (用于建立 P2P 连接)
    rpc GetNodeConnectionInfo(GetNodeConnectionInfoRequest) returns (GetNodeConnectionInfoResponse);
}
```

**REST API 映射**:

| 方法 | 路径 | 描述 | 请求体/参数 |
| :--- | :--- | :--- | :--- |
| POST | `/v1/nodes/register` | 注册节点 | `{ "device_id": "...", "public_key": "...", "type": "client" }` |
| POST | `/v1/nodes/heartbeat` | 发送心跳 | `{ "node_id": "client-123", "status": "online" }` |
| GET | `/v1/nodes` | 获取节点列表 | `?type=server&status=active` |
| GET | `/v1/nodes/{node_id}/connection` | 获取连接信息 | - |

---

### 3.2 密钥服务 (KeyService)

负责密钥生命周期管理。采用“根密钥 + 派生密钥”的双层模型。

**Protobuf 定义**:
```protobuf
service KeyService {
    // 创建根密钥 (执行 DKG)
    // 对应旧 API: POST /keys (重构后)
    rpc CreateRootKey(CreateRootKeyRequest) returns (RootKeyMetadata);
    
    // 派生钱包密钥 (基于 BIP32 路径)
    rpc DeriveWalletKey(DeriveWalletKeyRequest) returns (WalletKeyMetadata);
    
    // 查询根密钥详情
    rpc GetRootKey(GetRootKeyRequest) returns (RootKeyMetadata);
    
    // 查询钱包密钥详情
    rpc GetWalletKey(GetWalletKeyRequest) returns (WalletKeyMetadata);
    
    // 归档/删除密钥
    rpc ArchiveKey(ArchiveKeyRequest) returns (ArchiveKeyResponse);
}
```

**REST API 映射**:

| 方法 | 路径 | 描述 | 请求体/参数 |
| :--- | :--- | :--- | :--- |
| POST | `/v1/keys/root` | 创建根密钥 | `{ "algorithm": "ecdsa", "curve": "secp256k1", "threshold": 2, "total_nodes": 3, "user_id": "..." }` |
| POST | `/v1/keys/derived` | 派生钱包密钥 | `{ "root_key_id": "...", "chain_type": "eth", "path": "m/44'/60'/0'/0/0" }` |
| GET | `/v1/keys/root/{key_id}` | 获取根密钥 | - |
| GET | `/v1/keys/derived/{wallet_id}` | 获取钱包密钥 | - |
| DELETE | `/v1/keys/{key_id}` | 归档密钥 | - |

---

### 3.3 签名服务 (SigningService)

负责协调 MPC 签名流程。

**Protobuf 定义**:
```protobuf
service SigningService {
    // 发起预签名 (Pre-Sign, 可选优化)
    rpc PreSign(PreSignRequest) returns (PreSignResponse);
    
    // 发起交易签名
    rpc SignTransaction(SignTransactionRequest) returns (SignTransactionResponse);
    
    // 查询签名任务状态
    rpc GetSignSession(GetSignSessionRequest) returns (SignSessionMetadata);
}
```

**REST API 映射**:

| 方法 | 路径 | 描述 | 请求体/参数 |
| :--- | :--- | :--- | :--- |
| POST | `/v1/sign` | 发起签名 | `{ "wallet_id": "...", "message_hash": "...", "participants": [...] }` |
| POST | `/v1/sign/presign` | 发起预签名 | `{ "root_key_id": "..." }` |
| GET | `/v1/sign/sessions/{session_id}` | 查询状态 | - |

---

### 3.4 备份服务 (BackupService)

负责密钥分片的备份与恢复。

**Protobuf 定义**:
```protobuf
service BackupService {
    // 查询当前用户的备份分片列表
    rpc ListBackupShares(ListBackupSharesRequest) returns (ListBackupSharesResponse);
    
    // 请求下发备份分片 (Client 恢复或新设备登录时使用)
    rpc RequestShareDelivery(RequestShareDeliveryRequest) returns (RequestShareDeliveryResponse);
    
    // 确认分片接收 (更新下发状态)
    rpc ConfirmShareDelivery(ConfirmShareDeliveryRequest) returns (ConfirmShareDeliveryResponse);
    
    // 触发密钥恢复流程 (从备份恢复 MPC 分片)
    rpc RecoverKey(RecoverKeyRequest) returns (RecoverKeyResponse);
}
```

**REST API 映射**:

| 方法 | 路径 | 描述 | 请求体/参数 |
| :--- | :--- | :--- | :--- |
| GET | `/v1/backup/shares` | 获取备份列表 | `?key_id=...` |
| POST | `/v1/backup/delivery/request` | 请求分片下发 | `{ "key_id": "..." }` |
| POST | `/v1/backup/delivery/confirm` | 确认接收 | `{ "delivery_id": "..." }` |
| POST | `/v1/recovery` | 恢复密钥 | `{ "key_id": "...", "mnemonic": "..." }` |

---

## 4. 废弃计划 (Deprecation Plan)

为了平滑迁移，将执行以下步骤：

1.  **v1 (Current)**:
    *   保留 `internal/api/handlers/mpc` 下的接口，但底层逻辑逐步替换为调用新的 Service。
    *   `POST /v1/mpc/keys` -> 已重定向至 `KeyService.CreateRootKey`。
    
2.  **v2 (New Infrastructure API)**:
    *   实现上述 `NodeService`。
    *   在 `internal/api/router` 中注册新的 `/v2` 路由组。
    *   `/v2` 路由直接映射到 gRPC Service 方法（或通过 HTTP Gateway 自动生成）。

3.  **Cleanup**:
    *   删除 `internal/api/handlers` 中旧的业务逻辑代码。
    *   删除 `internal/types` 中为旧 API 定义的 Swagger 模型，统一使用 Protobuf 生成的 Go 结构体。

## 5. 数据模型变更

*   **Node**: 新增 `status` (Online/Offline), `last_heartbeat`, `client_version`, `device_info` 字段。
*   **Key**: 严格区分 `RootKey` (无地址，有 Threshold) 和 `WalletKey` (有地址，有 Path)。


# 重构计划 V3: MPC 钱包架构分层与通信重构

## 1. 核心目标
1.  **明确分层**: 建立严格的 `API Gateway -> Infrastructure (Biz) -> MPC Core` 调用链。
2.  **通信分离**: 
    *   **MPC 节点间**: 仅通过 gRPC 双向流 (Bi-di Stream) 通信。
    *   **应用层**: 通过标准的 Unary gRPC 或直接服务调用处理业务逻辑。
3.  **目录规范**: 统一命名为 `infra`，清晰划分核心算法与基础设施业务。

## 2. 目录结构变更 (Directory Structure)

| 当前路径 | 目标路径 | 说明 |
| :--- | :--- | :--- |
| `proto/infrastructure/v1` | **`proto/infra/v1`** | 应用层 RPC 定义 (Key, Signing, Backup) |
| `proto/mpc/v1` | `proto/mpc/v1` | **保留并精简**。仅定义节点间通信协议 (Stream) |
| `internal/mpc/` | **`internal/mpc/`** | **核心保留**。仅保留核心算法引擎与节点通信底层实现。 |
| `internal/infrastructure/` | **`internal/infra/`** | **合并目标**。存放所有业务基础设施逻辑。 |
| `internal/mpc/key/` | `internal/infra/key/` | 密钥管理业务逻辑迁移至 infra |
| `internal/mpc/backup/` | `internal/infra/backup/` | 备份业务逻辑迁移至 infra |
| `internal/mpc/signing/` | `internal/infra/signing/` | 签名业务流程控制迁移至 infra |
| `internal/mpc/storage/` | `internal/infra/storage/` | 存储实现迁移至 infra |
| `internal/api/` | `internal/api/` | **保持**。作为 REST Gateway，负责 Auth 和转发。 |

## 3. 架构与调用流 (Architecture & Call Flow)

### 调用链规则
> **Strict Rule**: `internal/api` 禁止直接引用 `internal/mpc`。必须通过 `internal/infra` 进行调用。

```mermaid
graph TD
    User[Client / Frontend] -->|REST / JSON| API[internal/api (Gateway)]
    API -->|Auth & Validation| Infra[internal/infra (Business Logic)]
    Infra -->|Orchestration| MPC[internal/mpc (Core Engine)]
    MPC <-->|gRPC Stream| Network[Other MPC Nodes]
```

### 职责划分
1.  **`internal/api`**:
    *   处理 HTTP 请求/响应。
    *   执行用户认证 (JWT/Auth)。
    *   参数校验。
    *   **动作**: 调用 `internal/infra` 提供的 Service 接口。

2.  **`internal/infra` (原 internal/infrastructure + 业务逻辑)**:
    *   **KeyService**: 处理生成密钥、派生地址、备份恢复等业务组合逻辑。
    *   **SigningService**: 处理签名请求的业务状态管理（如数据库记录、权限检查）。
    *   **BackupService**: 处理 SSS 分片存储与恢复策略。
    *   **动作**: 协调存储层 (DB)，并调用 `internal/mpc` 启动具体的协议流程。

3.  **`internal/mpc` (Core)**:
    *   **Protocol Engines**: GG18, GG20, FROST 算法实现。
    *   **Node Communication**: 处理底层的 gRPC 连接和消息分发。
    *   **动作**: 仅关注协议执行，不处理用户业务逻辑。

## 4. Proto 定义变更详情

### A. `proto/mpc/v1/mpc.proto` (节点通信)
*   **保留**: `MPCNode` 服务。
*   **修改**: 移除所有 Unary 接口（如 `StartDKG`, `SubmitSignatureShare` 等，如果它们不再被直接使用），或者保留 `Start` 接口仅作为触发器。
*   **核心**: 确保所有协议交互通过双向流进行。
    *   *注: 根据用户指示，协调者与参与者交互现状保持，仅移除不需要的 P2P 逻辑。*

### B. `proto/infra/v1/*.proto` (应用服务)
*   重命名 package 为 `infrastructure.v1` -> `infra.v1`。
*   定义清晰的业务 RPC，如 `CreateKey`, `SignTransaction`。

## 5. 执行步骤 (Execution Plan)

### Phase 1: Proto 重构
1.  重命名 `proto/infrastructure` -> `proto/infra`。
2.  修改 `proto/infra` 下所有文件的 `package` 声明。
3.  清理 `proto/mpc/v1`，移除废弃的 P2P RPC 定义，确保仅保留 Coordinator-Participant 必要的流或控制接口。

### Phase 2: Internal 目录重组
1.  创建 `internal/infra`。
2.  迁移 `internal/mpc/{key,backup,signing,storage}` -> `internal/infra/`。
3.  迁移 `internal/infrastructure/*` -> `internal/infra/`。
4.  保留 `internal/mpc/protocol`, `internal/mpc/grpc` (核心通信), `internal/mpc/node` (节点管理) 在 `internal/mpc` 中（或者根据依赖关系适当调整，核心算法建议保留在 core）。

### Phase 3: 逻辑与调用链修正
1.  **Refactor `internal/api`**: 修改 Handler，使其引用 `internal/infra` 的 Service，而不是直接引用 mpc 包。
2.  **Refactor `internal/infra`**: 确保它依赖 `internal/mpc` 的核心接口来执行实际的密码学操作。
3.  **Fix Imports**: 修复全项目的包引用路径。

### Phase 4: 清理与验证
1.  删除空的 `internal/mpc` 子目录。
2.  运行 `go mod tidy`。
3.  编译检查。

## 6. 待确认事项
*   确认 `internal/mpc/protocol` (算法) 是留在 `internal/mpc` 还是也移入 `infra`？
    *   *建议*: 留在 `internal/mpc` 作为 Core 依赖，`infra` 依赖它。

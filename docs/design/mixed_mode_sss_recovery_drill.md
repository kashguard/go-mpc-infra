# 混合模式 SSS 恢复演练脚本草案

## 1. 演练目标
- 验证“仅外部分片”即可成功恢复单节点 `MPC share` 并再生 `.keydata.enc`，不依赖服务端备份。
- 验证“混合来源”（外部 + 服务端持有）在部分外部分片缺失时仍可恢复。
- 输出可复用的操作清单、示例调用与验收标准，形成演练报告与审计留痕。

## 2. 前置准备
- 确认阈值与份数：推荐 `total=5, threshold=3`。
- 识别目标：`key_id`、目标 `node_id`（如 `server-proxy-1`）。
- 收集至少 3 份外部 SSS 分片（来源分散、独立托管），并以 base64 编码表述。
- 确认恢复接口与实现：
  - RPC 定义：`proto/infra/v1/backup.proto:12` `RecoverMPCShare`
  - 服务端实现：`internal/infra/grpc/backup_service.go:15`（入口）、`60`（合成）、`71`（回写）
  - SSS 算法：生成 `internal/infra/backup/service.go:40`；合成 `internal/infra/backup/service.go:75`
  - 存储：分片主存 `internal/infra/storage/key_share_storage.go:106`；协议存档 `internal/infra/storage/key_share_storage.go:209`

## 3. 验收标准
- 恢复调用返回 `success=true`，消息指明恢复与回写完成（参考 `internal/infra/grpc/backup_service.go:76-81`）。
- 目标节点的 `MPC share` 与 `.keydata.enc` 生成并可加载。
- 节点协议自检与签名/聚合操作成功。
- 审计记录完整：分片来源、数量、操作者、审批、时间戳与结果。

## 4. 演练步骤（仅外部分片）
- 步骤 4.1：列出服务端持有（用于对照，不使用）
  - 调用 `ListBackupShares`（`proto/infra/v1/backup.proto:18`）获取服务端分片清单，仅用于记录，不参与恢复。
- 步骤 4.2：准备外部分片
  - 将至少 3 份外部分片转为 base64（bytes 字段需要 base64），保留对应 `share_index`。
- 步骤 4.3：执行恢复（示例以 `grpcurl` 形式，按环境调整地址与凭证）
  - 单次传入一份外部分片，可重复调用累计聚合；或服务端支持批量聚合的实现则一次提交多份。
  - 示例（JSON 内 bytes 使用 base64）：
    ```
    grpcurl -plaintext \
      -d '{
        "key_id": "KEY_ID",
        "node_id": "server-proxy-1",
        "share_data": "BASE64_SSS_SHARE_1"
      }' \
      localhost:PORT infra.v1.BackupService/RecoverMPCShare
    ```
  - 至少三次调用（或一次批量），直至返回消息不再提示“Insufficient shares”（参考 `internal/infra/grpc/backup_service.go:51-58`）。
- 步骤 4.4：结果验证
  - 确认 RPC 返回 `success=true` 与成功消息。
  - 验证生成的分片与协议存档：
    - 分片：`internal/infra/storage/key_share_storage.go:106` 所写入的 `${base}/${key_id}/${node_id}.enc`
    - 协议存档：`internal/infra/storage/key_share_storage.go:209` 所写入的 `${base}/${key_id}/${node_id}.keydata.enc`
- 步骤 4.5：协议功能验证
  - 在目标节点加载恢复后的数据，执行签名或阈值聚合测试，确认正常。
- 步骤 4.6：审计与演练报告
  - 记录演练参数、外部分片来源（匿名化或代号）、调用与结果、耗时与问题。

## 5. 演练步骤（混合来源）
- 步骤 5.1：列出服务端分片：`ListBackupShares` 与 `GetBackupStatus`（`proto/infra/v1/backup.proto:15`）。
- 步骤 5.2：收集 1-2 份外部分片 + 服务端已有 1-2 份分片，满足阈值。
- 步骤 5.3：执行恢复
  - 调用 `RecoverMPCShare`，服务端会自动聚合请求体分片与库中分片（`internal/infra/grpc/backup_service.go:38-49`）。
- 步骤 5.4：验证与报告（同 4.4 - 4.6）。

## 6. 变体：零保留演练
- 目的：验证在“服务端零保留”策略下，仅凭外部分片可完整恢复。
- 步骤：
  - 仅使用外部 ≥3 份分片，完成 4.1 - 4.6 全流程。
  - 通过后方可进入删除与零保留 SOP（参考 `docs/design/mixed_mode_sss_backup_sop.md` 第 6 章）。

## 7. 常见问题（FAQ）
- Q：`Insufficient shares` 提示恢复失败？
  - A：外部分片不足或索引/版本不一致，至少需要 3 份；检查分片来源与封装版本。
- Q：恢复成功但协议操作失败？
  - A：检查 `.keydata.enc` 是否已再生且与当前节点上下文一致；必要时重新生成并加载。
- Q：bytes 如何在 gRPC 请求体中表示？
  - A：使用 base64 字符串作为 JSON 字段值，`grpcurl` 会自动转换为 bytes。

## 8. 输出物与留痕
- 演练报告（日期、参与人、授权、参数与结果）。
- 审计条目（分片来源、数量、时间戳、操作者与审批人）。
- 失败案例与改进项（版本/封装/流程问题）。

---

本草案用于指导恢复演练的落地操作，实际地址、端口与认证方式请按环境规范替换；如采用 HTTP 网关或专用 CLI，可将示例调用替换为相应形式。当前阶段不进行代码改动。 

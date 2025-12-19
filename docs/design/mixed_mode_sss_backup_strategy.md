# 混合模式 SSS 备份与恢复方案（设计草案）

## 文档索引
- 方案设计：`docs/design/mixed_mode_sss_backup_strategy.md`（当前文档）
- 运维指引：`docs/design/mixed_mode_sss_backup_sop.md`（标准作业流程与检查表）
- 演练脚本：`docs/design/mixed_mode_sss_recovery_drill.md`（可执行演练步骤与示例调用）

## 目标与范围
- 目标：在不增加实现复杂度的前提下，提供“混合模式”分片备份与恢复方案，兼顾可恢复性、安全合规与运营可控性。
- 范围：MPC Root Key 的单节点 `MPC share` 与本地协议存档 `LocalPartySaveData`（`.keydata.enc`）的备份、分发、恢复与审计流程。
- 不做的事：本方案为设计文档，暂不进行代码改动或接口新增。

## 术语
- MPC share：阈值密钥生成中每个参与方持有的本地分片。
- SSS 分片：对单个 `MPC share` 使用 Shamir’s Secret Sharing 拆分得到的备份分片。
- 混合模式：服务端加密保留部分备份分片，同时将分片分发到外部多方托管，阈值满足任意一侧缺失仍可恢复。

## 架构与现状
- 现有备份服务与 RPC：
  - `proto/infra/v1/backup.proto:12` 提供 `RecoverMPCShare`（恢复单节点 MPC 分片）。
  - `proto/infra/v1/backup.proto:15` 提供 `GetBackupStatus`（查询备份状态）。
  - `proto/infra/v1/backup.proto:18` 提供 `ListBackupShares`（枚举分片清单）。
  - 扩展的下发服务接口已定义（`BackupDeliveryService`），用于分片下发/接收确认/状态查询。
- 服务端恢复实现：
  - `internal/infra/grpc/backup_service.go:15` 接收恢复请求，聚合用户提供分片与服务端存储分片。
  - `internal/infra/grpc/backup_service.go:60` 调用备份服务合成单节点 `MPC share`。
  - `internal/infra/grpc/backup_service.go:71` 将恢复出的 `MPC share` 写入密钥分片存储。
- SSS 备份算法实现：
  - `internal/infra/backup/service.go:40` 生成 SSS 备份分片（输入为单个 `MPC share`）。
  - `internal/infra/backup/service.go:75` 从至少 3 份备份分片合成单个 `MPC share`。
- 文件系统加密存储：
  - `internal/infra/storage/key_share_storage.go:106` 存储单节点 `MPC share`（AES-GCM）。
  - `internal/infra/storage/key_share_storage.go:209` 存储 `.keydata.enc`（序列化 `LocalPartySaveData`，AES-GCM）。

## 混合模式策略
- 推荐参数：`total=5, threshold=3`
  - 服务端受控保留：2 份（严格加密、最小权限、审计）。
  - 外部分发：3 份（用户安全团队、独立托管机构、公司冷备）。
  - 任意一侧缺失仍可满足 3 份阈值，提升韧性。
- 安全性与合规：
  - 服务端分片加密存储（信封加密/KMS/HSM 作为理想形态），访问需审批与审计。
  - 外部分片采用离线加密封装与验签，交付留痕（时间戳、签名、收件方）。
  - 删除策略遵循“软删除 + 冷却期 + 审计留痕”，满足零保留要求时可切换策略。

## 数据对象与存储
- 单节点 `MPC share`：
  - 主存：`internal/infra/storage/key_share_storage.go:106`，文件名形如 `${base}/${key_id}/${node_id}.enc`。
  - 备份：SSS 拆分得到若干分片，按 `key_id + node_id + share_index` 归档存储或外部分发。
- `LocalPartySaveData`（协议运行态本地存档）：
  - 主存：`internal/infra/storage/key_share_storage.go:209`，文件名形如 `${base}/${key_id}/${node_id}.keydata.enc`。
  - 恢复时需确保该文件可再生成或从备份中再生，以支撑后续协议流程与签名。

## 生成与分发流程
- 触发时机：DKG 完成并持久化本地 `MPC share` 后，执行 SSS 备份生成与分发。
- 流程描述：
  - 1）服务端读取单节点 `MPC share`（已加密持久化后解密读取）。
  - 2）调用 SSS 生成分片（`internal/infra/backup/service.go:40`），参数 `threshold=3, total=5`。
  - 3）存储 2 份到服务端备份库（加密、审计），3 份走 `BackupDeliveryService` 下发：
    - `RequestShareDelivery`（加密封装 + 服务端签名 + 时间戳）
    - `ConfirmShareDelivery`（收件方确认或失败原因）
    - `QueryShareStatus`（后续状态查询）
  - 4）为每份分片生成交付凭证与审计记录（含 `key_id`, `node_id`, `share_index`, 收件方、时间戳、签名、状态）。

## 恢复流程（仅使用外部分片或混合来源）
- 输入：满足阈值的 SSS 分片集合（可来自用户提交与服务端备份库）。
- 服务端执行：
  - A）聚合分片：`internal/infra/grpc/backup_service.go:38-49` + 请求体分片。
  - B）阈值检查：`internal/infra/grpc/backup_service.go:51-58`（至少 3 份）。
  - C）合成 `MPC share`：`internal/infra/grpc/backup_service.go:60-69` → `internal/infra/backup/service.go:75-97`。
  - D）回写分片：`internal/infra/grpc/backup_service.go:71-74` 使用加密存储。
- `LocalPartySaveData` 再生：
  - 若协议需要，将恢复的 `MPC share` 与节点上下文生成新的 `.keydata.enc`（与运行态一致）。
  - 主存路径参考：`internal/infra/storage/key_share_storage.go:217-236`。

## 审计与运维
- 审计日志：
  - 备份生成事件：`key_id`, `node_id`, 分片总数与阈值、生成者、时间戳。
  - 分片交付事件：目标实体、加密封装哈希、签名、时间戳、确认状态。
  - 恢复事件：分片来源（用户/服务端）、数量、操作者、审批记录、结果。
  - 删除事件：软删除与硬删除的审批与时间戳、关联凭证。
- 指标监控：
  - 备份覆盖率（每节点分片数、可恢复性标志）。
  - 恢复演练成功率与耗时。
  - 交付确认率与失败原因分布。
  - 服务端访问频度与异常读写告警。

## 生命周期与删除策略
- 混合模式默认保留：
  - 服务端：保留 2 份分片，统一加密与最小权限访问。
  - 外部：3 份分片分散托管，保持更新与盘点。
- 轮换与销毁：
  - 软删除 → 冷却期（如 7 天）→ 硬删除，期间允许回滚。
  - 零保留场景：仅在演练验证“仅外部分片可成功恢复”后执行硬删除。

## 风险评估与缓解
- 风险：外部分片丢失且服务端也删除，导致不可恢复。
  - 缓解：删除前进行仅外部分片恢复演练；分片去相关性分发；多方托管。
- 风险：服务端被攻陷导致集中泄漏风险。
  - 缓解：强加密（信封加密/KMS/HSM）、最小权限、双人审批与审计。
- 风险：分片版本不一致导致恢复失败。
  - 缓解：分片封装包含版本、时间戳与校验；强制演练与定期轮换。

## 推进计划（不开发，仅流程化准备）
- 明确参数与角色清单（5/3 阈值、外部分发对象与联系人）。
- 制定下发与确认的操作规程、审计模板与留痕规范。
- 设计恢复演练脚本与演练日程（隔离环境、全流程演练）。
- 设定删除策略与审批门槛（软删/硬删/回滚窗口），对零保留场景制定额外验收。
- 建立监控指标面板与告警项（覆盖率、成功率、耗时、失败原因）。

## 备份/恢复接口参考
- 恢复 RPC：
  - `proto/infra/v1/backup.proto:12` `RecoverMPCShare`
  - 服务端实现入口：`internal/infra/grpc/backup_service.go:15`
- 状态与清单：
  - `proto/infra/v1/backup.proto:15` `GetBackupStatus`
  - `proto/infra/v1/backup.proto:18` `ListBackupShares`
- 备份生成/合成：
  - 生成：`internal/infra/backup/service.go:40`
  - 合成：`internal/infra/backup/service.go:75`
- 存储：
  - `MPC share`：`internal/infra/storage/key_share_storage.go:106`
  - `.keydata.enc`：`internal/infra/storage/key_share_storage.go:209`

---

此文档为混合模式的设计草案，旨在指导后续实现与流程落地；当前阶段不进行代码变更。后续如需进入开发，将基于本方案细化接口、安全控制与审计实现。 

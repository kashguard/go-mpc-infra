# 混合模式 SSS 备份运维标准作业指引（SOP）

## 1. 目的与范围
- 目的：规范 MPC Root Key 的单节点 `MPC share` 与 `LocalPartySaveData`（`.keydata.enc`）的备份、分发、恢复、删除与审计操作，保证高可用与合规。
- 范围：备份生成与保留、分片下发与确认、状态巡检、恢复演练、紧急恢复、删除与轮换。

## 2. 角色与职责
- 运维（Ops）：执行备份、分发、巡检、恢复与删除；维护审计与监控。
- 安全（Sec）：审批敏感操作与零保留策略；监督密钥封装与访问控制。
- 合规（Compliance）：审核留痕与证据；确认满足外部/内部规范。
- 业务负责人：在恢复或删除前进行风险评估与授权。

## 3. 前置条件与环境
- 阈值与总份数：推荐 `total=5, threshold=3`（混合模式）。
- 恢复接口与实现：
  - `proto/infra/v1/backup.proto:12` `RecoverMPCShare`
  - 服务端实现入口：`internal/infra/grpc/backup_service.go:15`
  - 合成调用：`internal/infra/grpc/backup_service.go:60`
  - 回写分片：`internal/infra/grpc/backup_service.go:71`
- 备份生成与合成算法：
  - 生成：`internal/infra/backup/service.go:40`
  - 合成：`internal/infra/backup/service.go:75`
- 存储与文件：
  - 分片主存：`internal/infra/storage/key_share_storage.go:106`
  - 协议存档：`internal/infra/storage/key_share_storage.go:209`

## 4. 日常操作流程
- 4.1 DKG 完成后备份生成与保留
  - 读取本地已持久化的单节点 `MPC share`，调用 SSS 生成分片（`threshold=3, total=5`）。
  - 服务端加密保留 2 份（最小权限、审批、审计）。
  - 外部分发 3 份（用户安全团队、独立托管机构、公司冷备）。
  - 记录审计：`key_id`, `node_id`, `share_index`, 生成时间戳、操作者、阈值与总数。
- 4.2 分片下发与确认
  - 加密封装分片，包含版本、校验与时间戳；服务端签名。
  - 交付后收集接收确认与失败原因，形成交付凭证。
  - 建立映射清单：分片索引 → 托管实体与联系方式。
- 4.3 状态巡检与盘点
  - 周期性查询备份覆盖率与可恢复性：
    - 列表：`proto/infra/v1/backup.proto:18` `ListBackupShares`（服务端持有）
    - 状态：`proto/infra/v1/backup.proto:15` `GetBackupStatus`
  - 外部分片盘点：核对托管到位与加密容器可读性；更新清单。
- 4.4 恢复演练（季度或变更后）
  - 使用仅外部分片进行完整恢复演练（不依赖服务端备份）。
  - 演练成功标准：
    - `RecoverMPCShare` 返回 `success=true`（`internal/infra/grpc/backup_service.go:76-81`）。
    - 新生成并加载 `.keydata.enc`，协议签名/聚合正常。
  - 记录演练报告与耗时。
- 4.5 版本轮换
  - 触发条件：协议升级、密钥轮换或合规要求。
  - 新版本生成与分发重复 4.1-4.3；旧版本走 7 天冷却期后软删/硬删。

## 5. 紧急恢复流程（Incident）
- 触发条件：节点分片丢失、文件损坏、不可读取或节点重建需要。
- 审批与授权：业务负责人 + 安全两人复核；记录工单与风险评估。
- 操作步骤：
  - 1）收集分片：向托管方收集 ≥3 份 SSS 分片；可同时查询服务端备份库。
  - 2）提交恢复请求：使用 `RecoverMPCShare`（`proto/infra/v1/backup.proto:12`），将用户分片放入 `share_data`（可多次调用或聚合提交）。
  - 3）合成与回写：服务端聚合（`internal/infra/grpc/backup_service.go:38-49`），阈值检查（`51-58`），合成并回写（`60-74`）。
  - 4）再生 `LocalPartySaveData`：生成并写入 `.keydata.enc`（参考：`internal/infra/storage/key_share_storage.go:217-236`）。
  - 5）验证：节点加载后执行协议自检与签名/聚合测试。
  - 6）事后审计：记录来源、数量、操作者、审批、时间戳与结果。

## 6. 删除与零保留策略
- 适用：客户或合规要求“服务器零保留”场景。
- 先决条件：
  - 已分发外部 ≥3 份，且分散于独立实体；交付凭证齐全。
  - 已完成仅外部分片的恢复演练并通过。
- 操作步骤：
  - 软删除登记：标记要删除的 `key_id/node_id/share_index`；生成审计条目。
  - 冷却期：建议 7 天；若出现异常可回滚。
  - 硬删除：执行删除并记录证据与时间戳；更新覆盖率状态。
  - 零保留确认：形成书面确认与合规存档。

## 7. 审计与证据
- 必备字段：`key_id`, `node_id`, `share_index`, 分片封装哈希、签名、版本、时间戳、操作者、审批人、目标实体、结果与失败原因。
- 事件类型：生成、交付、确认、巡检、演练、恢复、删除、回滚。
- 存储与访问：只读审计库与归档；访问最小权限与双人复核。

## 8. 安全控制
- 密钥封装：服务端存储建议使用信封加密（KMS/HSM）；外部分片采用离线加密容器。
- 访问控制：分片读取与恢复请求需要审批与审计；速率限制与异常告警。
- 人员控制：双人复核与分工；离任交接与授权回收。

## 9. 指标与告警
- 覆盖率：每节点持有分片数、可恢复标志（≥阈值）。
- 交付确认率：分片交付成功比例与失败原因。
- 恢复演练：成功率、耗时、异常类型。
- 存储访问：异常读写、权限越权与高频访问。

## 10. 清单与检查表
- 备份生成检查表：
  - DKG 完成并持久化 `MPC share`（`internal/infra/storage/key_share_storage.go:106`）
  - SSS 生成：`threshold=3, total=5`（`internal/infra/backup/service.go:40`）
  - 服务端保留与外部分发比例达成
  - 审计记录与交付凭证完整
- 恢复演练检查表：
  - 仅外部分片 ≥3
  - `RecoverMPCShare` 成功并回写
  - `.keydata.enc` 再生与加载成功（`internal/infra/storage/key_share_storage.go:209`）
  - 协议功能验证通过
- 删除与零保留检查表：
  - 演练报告通过
  - 冷却期与回滚窗口配置
  - 审批与合规确认完成

## 11. 变更管理
- 任何策略或流程调整需通过变更评审与灰度演练后生效。
- 重大变更（阈值、分发比例、密钥封装方式）需更新审计模板与监控面板。

---

本 SOP 适用于“混合模式”下的 SSS 备份与恢复的运维操作规范，确保在满足恢复性与安全合规的同时，流程可控、可审计、可演练。当前阶段不进行代码改动。 

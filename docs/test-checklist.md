# GG18 签名测试检查清单

## ✅ 环境准备（已完成）

- [x] Docker 环境已启动
- [x] Coordinator 容器运行中
- [x] Participant 1-3 容器运行中
- [x] PostgreSQL、Redis、Consul 健康

## 📋 测试前检查

### 1. 检查节点注册状态

```bash
# 进入 coordinator 容器
docker compose exec coordinator bash

# 检查节点是否已注册
psql -h postgres -U dbuser -d mpc-dev-db -c "SELECT node_id, node_type, status, endpoint FROM nodes WHERE status = 'active';"
```

预期结果：应该看到 3 个 participant 节点状态为 `active`

### 2. 检查是否有已生成的密钥

```bash
# 在 coordinator 容器中
psql -h postgres -U dbuser -d mpc-dev-db -c "SELECT key_id, algorithm, curve, threshold, total_nodes, status FROM keys WHERE status = 'Active' LIMIT 5;"
```

如果没有密钥，需要先运行 DKG 生成密钥。

## 🧪 执行签名测试

### 方法1：通过 API 测试

```bash
# 在 coordinator 容器外（或使用 curl）
curl -X POST http://localhost:8080/api/v1/mpc/sign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "key_id": "your-key-id",
    "message": "test message",
    "chain_type": "evm"
  }'
```

### 方法2：查看实时日志

```bash
# Coordinator 日志
docker compose logs -f coordinator | grep -E "(DIAGNOSTIC|signing|session)"

# Participant 1 日志
docker compose logs -f participant-1 | grep -E "(DIAGNOSTIC|signing|session)"

# Participant 2 日志
docker compose logs -f participant-2 | grep -E "(DIAGNOSTIC|signing|session)"

# Participant 3 日志
docker compose logs -f participant-3 | grep -E "(DIAGNOSTIC|signing|session)"
```

## 🔍 关键诊断点检查

### 1. 协议启动 ✅
查找：`🔍 [DIAGNOSTIC] Starting LocalParty (party.Start() called)`
- 应该出现在所有 3 个参与者节点
- 确认协议已启动

### 2. 消息生成 📤
查找：`🔍 [DIAGNOSTIC] Received message from tss-lib outCh in executeSigning`
- **关键指标**：`out_message_count` 应该 > 1（不仅限于 round=0）
- **检查项**：
  - `is_broadcast`: 是否有 `true` 值（广播消息）
  - `target_count`: 目标节点数量
  - `msg_bytes_len`: 消息长度

### 3. 消息发送 📡
查找：`🔍 [DIAGNOSTIC] Sending signing message via gRPC`
- **检查项**：
  - `round`: 应该看到多个轮次（0, 1, 2, ...）
  - `target_node_id`: 目标节点ID
  - `accepted`: 应该为 `true`

### 4. 消息接收 📥
查找：`🔍 [DIAGNOSTIC] Received message in signing processing loop`
- **关键指标**：`message_count` 应该递增
- **检查项**：
  - `from_node_id`: 发送方节点ID
  - `is_broadcast`: 广播状态

### 5. 消息注入 💉
查找：`🔍 [DIAGNOSTIC] Successfully updated LocalParty from bytes`
- **关键**：确认消息成功注入
- 如果看到失败，检查 `UpdateFromBytes` 的错误

### 6. 签名完成 ✅
查找：`🔍 [DIAGNOSTIC] Received signature from endCh (signing completed successfully)`
- 应该出现在至少一个参与者节点
- 检查 `out_message_count`: 总消息数

### 7. 会话更新 💾
查找：`🔍 [DIAGNOSTIC] Session completed successfully`
- 确认会话状态已更新为 `completed`
- 协调者应该能检测到签名完成

## ⚠️ 问题诊断

### 问题1：只有 round=0 消息
**症状**：日志中只看到 `out_message_count=1`，且 `round=0`

**检查步骤**：
1. 查看所有参与者的 `UpdateFromBytes` 日志
2. 检查是否有错误：`Failed to update LocalParty from bytes`
3. 检查消息是否成功发送：`Successfully routed signing message`

**可能原因**：
- 消息未正确注入到 LocalParty
- 协议阻塞在等待消息

### 问题2：消息发送失败
**症状**：看到 `Failed to send signing message via gRPC`

**检查步骤**：
1. 验证节点端点配置
2. 检查 gRPC 连接：`docker compose logs participant-1 | grep "gRPC"`
3. 检查网络连接

### 问题3：会话未更新
**症状**：参与者完成签名但协调者仍等待

**检查步骤**：
1. 查看 `CompleteSession` 调用日志
2. 检查数据库连接
3. 验证会话状态：`SELECT session_id, status, signature FROM signing_sessions WHERE session_id = 'xxx';`

## 📊 成功标准

✅ **测试通过的标准**：
1. 所有参与者都启动协议（看到 `party.Start()` 日志）
2. 看到多个轮次的消息（`out_message_count > 1`）
3. 至少一个参与者完成签名（看到 `Received signature from endCh`）
4. 会话状态更新为 `completed`（看到 `Session completed successfully`）
5. 协调者返回签名结果（API 响应包含 `signature` 字段）

## 📝 测试记录模板

```
测试时间：2025-12-10 XX:XX
测试密钥ID：xxx
会话ID：xxx

结果：
- [ ] 协议启动成功
- [ ] 消息生成（out_message_count: X）
- [ ] 消息发送成功
- [ ] 消息接收成功
- [ ] 消息注入成功
- [ ] 签名完成
- [ ] 会话更新成功
- [ ] 协调者返回签名

问题记录：
1. 
2. 
```

## 🚀 快速测试命令

```bash
# 一键查看所有诊断日志
docker compose logs coordinator participant-1 participant-2 participant-3 | grep "DIAGNOSTIC" | tail -100

# 查看签名相关日志
docker compose logs coordinator participant-1 participant-2 participant-3 | grep -E "(signing|signature|session)" | tail -100

# 查看错误日志
docker compose logs coordinator participant-1 participant-2 participant-3 | grep -E "(ERROR|Failed)" | tail -50
```

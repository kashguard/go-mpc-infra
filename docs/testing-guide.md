# GG18 签名测试指南

## 测试前准备

### 1. 确保所有节点运行
- 协调者节点（Coordinator）
- 3个参与者节点（Participant 1, 2, 3）

### 2. 检查节点状态
确保所有节点在 `nodes` 表中状态为 `active`：
```sql
SELECT node_id, node_type, status, endpoint FROM nodes WHERE status = 'active';
```

### 3. 确保已有密钥
确保已经通过 DKG 生成了密钥，并且密钥状态为 `Active`。

## 运行签名测试

### 方法1：通过 API 测试

```bash
# 1. 创建签名请求
curl -X POST http://localhost:8080/api/v1/mpc/sign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "key_id": "your-key-id",
    "message": "test message",
    "chain_type": "evm"
  }'
```

### 方法2：查看日志输出

启动所有节点后，观察日志中的诊断信息：

```bash
# 协调者日志
tail -f coordinator.log | grep "DIAGNOSTIC"

# 参与者日志
tail -f participant1.log | grep "DIAGNOSTIC"
tail -f participant2.log | grep "DIAGNOSTIC"
tail -f participant3.log | grep "DIAGNOSTIC"
```

## 关键诊断日志点

### 1. 协议启动
查找：`🔍 [DIAGNOSTIC] Starting LocalParty (party.Start() called)`
- 应该出现在每个参与者节点
- 确认协议已启动

### 2. 消息生成
查找：`🔍 [DIAGNOSTIC] Received message from tss-lib outCh in executeSigning`
- 检查 `out_message_count`：应该看到多个消息（不仅限于 round=0）
- 检查 `is_broadcast`：是否有广播消息（round=-1）
- 检查 `target_count`：目标节点数量

### 3. 消息发送
查找：`🔍 [DIAGNOSTIC] Sending signing message via gRPC`
- 确认消息成功发送到目标节点
- 检查 `round` 值：应该看到多个轮次

### 4. 消息接收
查找：`🔍 [DIAGNOSTIC] Received message in signing processing loop`
- 检查 `message_count`：应该递增
- 确认消息被正确接收

### 5. 消息注入
查找：`🔍 [DIAGNOSTIC] Successfully updated LocalParty from bytes`
- 确认消息成功注入到 LocalParty
- 如果看到失败，检查 `UpdateFromBytes` 的错误

### 6. 签名完成
查找：`🔍 [DIAGNOSTIC] Received signature from endCh (signing completed successfully)`
- 应该出现在至少一个参与者节点
- 检查 `out_message_count`：总消息数

### 7. 会话更新
查找：`🔍 [DIAGNOSTIC] Session completed successfully`
- 确认会话状态已更新为 `completed`
- 协调者应该能检测到签名完成

## 预期行为

### 正常流程
1. 协调者创建签名会话
2. 协调者调用所有参与者的 `StartSign` RPC
3. 每个参与者启动 `LocalParty.Start()`
4. 参与者生成并发送多个轮次的消息（round 0, 1, 2, ...）
5. 消息在节点间交换
6. 至少一个参与者完成签名并更新会话状态
7. 协调者检测到会话完成并返回签名

### 问题诊断

#### 问题1：只有 round=0 消息
- **症状**：日志中只看到 `out_message_count=1`，且 `round=0`
- **可能原因**：
  - tss-lib LocalParty 未正确推进
  - 消息未正确注入，导致协议阻塞
- **检查**：
  - 查看 `UpdateFromBytes` 的返回值
  - 检查是否有错误日志

#### 问题2：消息发送失败
- **症状**：看到 `Failed to send signing message via gRPC`
- **可能原因**：
  - gRPC 连接问题
  - 节点不可达
- **检查**：
  - 验证节点端点配置
  - 检查网络连接

#### 问题3：会话未更新
- **症状**：参与者完成签名但协调者仍等待
- **可能原因**：
  - `CompleteSession` 调用失败
  - 数据库更新失败
- **检查**：
  - 查看 `CompleteSession` 的错误日志
  - 验证数据库连接

## 运行单元测试

```bash
# 运行所有测试
make test

# 运行 MPC 协议测试
go test ./internal/mpc/protocol/... -v

# 运行特定测试
go test ./internal/mpc/protocol/... -run TestGG18ThresholdSign -v
```

## 日志过滤命令

```bash
# 只看诊断日志
grep "DIAGNOSTIC" logfile.log

# 只看签名相关日志
grep -E "(signing|signature|session)" logfile.log | grep "DIAGNOSTIC"

# 只看错误
grep "ERROR" logfile.log | grep "DIAGNOSTIC"

# 统计消息数量
grep "out_message_count" logfile.log | tail -1
```

## 下一步

如果测试通过：
- ✅ 签名成功完成
- ✅ 会话状态正确更新
- ✅ 协调者返回签名

如果测试失败：
1. 收集所有诊断日志
2. 检查 `out_message_count` 和消息轮次
3. 检查 `UpdateFromBytes` 的返回值
4. 检查会话状态更新
5. 根据日志定位问题点

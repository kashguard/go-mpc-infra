# GG18 2-of-3 签名问题调查记录（截至 2025-12-11）

## 14. 签名问题修复进展（2025-12-11）

### 已完成的修复

1. ✅ **GG20 协议密钥加载修复**：
   - 问题：GG20 协议的 `ThresholdSign` 没有实现从 `keyShareStorage` 加载密钥的逻辑
   - 修复：添加了与 GG18 相同的密钥加载逻辑（从内存或 keyShareStorage 加载）
   - 文件：`internal/mpc/protocol/gg20.go`

2. ✅ **FROST 协议密钥加载修复**：
   - 问题：FROST 协议的 `ThresholdSign` 没有实现从 `keyShareStorage` 加载密钥的逻辑
   - 修复：添加了密钥加载逻辑（从内存或 keyShareStorage 加载）
   - 文件：`internal/mpc/protocol/frost.go`

3. ✅ **协议动态选择修复**：
   - 问题：Participant 节点使用默认协议引擎（FROST），无法处理 GG20 生成的密钥
   - 修复：修改 `GRPCServer` 使其能够根据 `StartSignRequest.Protocol` 动态选择协议引擎
   - 实现：创建协议注册表，注册所有支持的协议引擎（GG18、GG20、FROST）
   - 文件：`internal/mpc/grpc/server.go`, `internal/api/providers.go`

### 测试结果

**测试密钥**：`key-26cdb9c7-0af9-456f-8690-5a526554dcb0`（GG20 协议生成，ECDSA + secp256k1）

**成功部分**：
- ✅ Participant 节点成功从协议注册表选择了 GG20 协议（"Using protocol from registry based on request"）
- ✅ 密钥成功从 keyShareStorage 加载（"GetKeyData: file read successfully, decrypting"）
- ✅ 签名协议已启动（"Received message from outCh (protocol is progressing)"）
- ✅ 消息正在发送（"Signing message sent successfully via gRPC"）
- ✅ 有广播消息（"Broadcasting signing message to all nodes", round=-1）
- ✅ 收到了来自其他节点的消息（"Received SubmitSignatureShare request"）

**仍存在的问题**：
- ❌ 签名仍然超时（"Signing timeout - no signature received"）
- ❌ 协议没有完成（没有收到 endCh 的签名数据）

**下一步调查**：
1. 检查消息是否成功注入到 LocalParty（UpdateFromBytes 结果）
   - 从日志看，消息处理循环显示 `total_messages_processed=0`，说明消息没有被处理
   - 需要检查消息是否被正确放入队列，以及消息处理循环是否正常启动
2. 检查是否有后续轮次的消息（round=1, round=2 等）
   - 当前只看到 round=0 和 round=-1（广播）的消息
   - 需要检查是否有后续轮次的消息生成
3. 检查协议是否卡在某个轮次
   - 协议可能在等待某些消息或条件
4. 检查是否有错误消息或协议中止
   - 需要检查是否有 tss.Error 或其他错误

---

## 15. 消息队列竞态条件问题（2025-12-11）

### 问题描述

**症状**：
- 签名协议启动后，消息处理循环显示 `total_messages_processed=0`
- 消息虽然成功入队（"message enqueued successfully"），但没有被处理
- 签名最终超时

**根本原因**：
**竞态条件**：`executeSigning` 创建消息队列后，消息处理循环从 map 重新获取队列引用。但 `ProcessIncomingSigningMessage` 可能在消息处理循环获取引用之前创建了一个新队列，导致消息被放入不同的队列，而消息处理循环监听的是另一个队列。

### 修复方案

**关键修复**：`executeSigning` 创建队列后，直接使用这个队列引用传递给消息处理循环，而不是让消息处理循环从 map 重新获取。这样可以确保消息处理循环使用的是 `executeSigning` 创建的队列，而不是 `ProcessIncomingSigningMessage` 创建的新队列。

**代码变更**：
1. `executeSigning` 创建队列后，保存队列引用到 `messageQueueForProcessing`
2. 消息处理循环直接使用 `messageQueueForProcessing`，而不是从 map 重新获取
3. 移除了消息处理循环中的等待逻辑（不再需要等待队列创建）

### 修复状态
- ✅ 代码已修复并部署
- ✅ **最新修复**（2025-12-11）：优化 `ProcessIncomingSigningMessage` 的等待机制

### 最新修复（2025-12-11）

**问题**：`ProcessIncomingSigningMessage` 等待队列创建时，即使 `executeSigning` 已经创建了队列，等待循环也没有及时检测到队列的存在。

**观察**：
- `executeSigning` 在 05:36:38 创建了队列
- `ProcessIncomingSigningMessage` 在 05:36:39 开始等待
- 等待了约 5 秒（49 次迭代，每次 100ms）后超时，创建了后备队列
- 之后才找到队列（05:36:44）

**根本原因**：
- 等待循环使用 `time.After(100 * time.Millisecond)`，检查间隔太长（100ms）
- 如果 `executeSigning` 在两次检查之间创建了队列，`ProcessIncomingSigningMessage` 要等到下次检查才能发现
- 这导致即使队列已经创建，也要等待最多 100ms 才能检测到

**修复方案**：
1. 使用 `time.Ticker(10 * time.Millisecond)` 替代 `time.After(100 * time.Millisecond)`，将检查间隔从 100ms 缩短到 10ms
2. 先做一次快速检查（不等待），如果队列已存在则直接使用
3. 超时时间从 5 秒增加到 10 秒，给节点更多启动时间
4. 优化日志输出，每 1 秒记录一次（而不是每 10 次迭代）

**预期效果**：
- 队列创建后，最多 10ms 内就能被检测到（而不是最多 100ms）
- 减少不必要的等待时间，提高签名协议的响应速度
- 降低超时创建后备队列的概率

**代码变更**：
- `internal/mpc/protocol/tss_adapter.go`：`ProcessIncomingSigningMessage` 函数
  - 使用 `time.Ticker(10 * time.Millisecond)` 替代 `time.After(100 * time.Millisecond)`
  - 添加快速检查逻辑（在等待循环前先检查一次）
  - 超时时间从 5 秒增加到 10 秒
  - 优化日志输出频率

**下一步修复**（2025-12-11）：
1. ✅ **让消息处理循环动态检测队列变化**
   - 问题：如果 `ProcessIncomingSigningMessage` 创建了后备队列，消息会被放入后备队列，但消息处理循环监听的是 `executeSigning` 创建的队列，导致消息丢失
   - 修复：让消息处理循环能够动态检测队列变化，如果当前队列被关闭或无效，从 map 重新获取队列
   - 代码变更：
     - 消息处理循环在每次迭代时检查队列是否有效
     - 如果队列被关闭，从 map 重新获取队列（可能是 `ProcessIncomingSigningMessage` 创建的后备队列）
     - 如果队列为 nil，从 map 重新获取队列
     - 这样可以确保即使 `ProcessIncomingSigningMessage` 创建了后备队列，消息也能被处理

**测试状态**：
- ✅ 代码已更新（使用 `time.Ticker(10 * time.Millisecond)`）
- ✅ 消息处理循环已优化（动态检测队列变化）
- ✅ 代码已编译（2025-12-11 06:03）
- ✅ 所有节点已重启
- ⏳ 等待新的签名测试验证修复效果

**测试建议**：
1. 执行签名测试（需要认证）
2. 观察日志，检查以下关键指标：
   - `executeSigning: creating new message queue` 的时间戳
   - `ProcessIncomingSigningMessage: found existing message queue` 的时间戳和 `wait_iterations`
   - 两者之间的时间差应该明显缩短：
     - **之前**：5 秒（49 次迭代 × 100ms）
     - **现在**：应该 < 100ms（< 10 次迭代 × 10ms）
   - `total_messages_processed` 应该 > 0，表示消息被正确处理
   - 如果出现 "Message queue closed, attempting to retrieve new queue from map" 日志，说明消息处理循环成功切换到了后备队列
   - 签名协议应该能够正常完成，不再出现超时

**预期结果**：
- 队列创建后，`ProcessIncomingSigningMessage` 应该在 10-100ms 内检测到队列（而不是之前的 5 秒）
- `wait_iterations` 应该 < 10（而不是之前的 49）
- 签名协议应该能够正常完成，不再出现超时
- `total_messages_processed` 应该显示有消息被处理（而不是 0）
- 即使 `ProcessIncomingSigningMessage` 创建了后备队列，消息也能被正确处理

### 潜在问题分析

**问题1：后备队列导致消息丢失**
- 如果 `ProcessIncomingSigningMessage` 超时后创建了后备队列，消息会被放入后备队列
- 但消息处理循环监听的是 `executeSigning` 创建的队列（`messageQueueForProcessing`）
- 这会导致消息丢失，`total_messages_processed=0`

**问题2：第一次快速检查未找到队列**
- 从日志看，`executeSigning` 在 05:36:38 创建了队列
- `ProcessIncomingSigningMessage` 在 05:36:39 开始等待（说明第一次快速检查未找到队列）
- 可能原因：
  1. 时序问题：`ProcessIncomingSigningMessage` 在队列创建之前就被调用了
  2. 内存可见性问题：虽然不太可能，但 Go 的内存模型可能导致读取不一致

**解决方案**：
1. ✅ 已优化等待机制（10ms ticker）
2. ✅ 已修复后备队列问题（消息处理循环动态检测队列变化）
3. ⚠️ 需要确保 `ProcessIncomingSigningMessage` 能够及时找到队列

---

## 16. 最终修复总结（2025-12-11 06:03）

### 所有修复

1. ✅ **优化 `ProcessIncomingSigningMessage` 的等待机制**
   - 使用 `time.Ticker(10 * time.Millisecond)` 替代 `time.After(100 * time.Millisecond)`
   - 检查间隔从 100ms 缩短到 10ms
   - 超时时间从 5 秒增加到 10 秒
   - 添加快速检查逻辑

2. ✅ **修复后备队列导致的消息丢失问题**
   - 让消息处理循环能够动态检测队列变化
   - 如果队列被关闭或无效，从 map 重新获取队列
   - 确保即使 `ProcessIncomingSigningMessage` 创建了后备队列，消息也能被处理

### 部署状态

- ✅ 代码已更新并复制到所有容器
- ✅ 所有节点已重新编译（2025-12-11 06:03）
- ✅ 所有节点已重启并运行正常
- ✅ 所有节点健康检查通过

### 测试准备

**当前时间**：2025-12-11 06:05

**准备就绪**：
- ✅ Coordinator: http://localhost:8080 (健康检查通过)
- ✅ Participant-1: http://localhost:8081 (健康检查通过)
- ✅ Participant-2: http://localhost:8082 (健康检查通过)
- ✅ Participant-3: http://localhost:8083 (健康检查通过)
- ✅ 所有节点已编译最新代码（2025-12-11 06:05）
- ✅ 所有节点已重启并运行正常

**测试步骤**：
1. 执行签名 API 调用（POST /api/v1/mpc/sign）
   - 需要提供认证 token
   - 请求体：`{"key_id": "key-xxx", "message": "base64_encoded_message", "message_type": "raw", "chain_type": "ethereum"}`
2. 在另一个终端监控日志：
   ```bash
   docker compose logs -f participant-1 participant-2 participant-3 | grep -E '(DIAGNOSTIC|executeSigning|ProcessIncomingSigningMessage|total_messages_processed|Signing timeout|signature)'
   ```
3. 观察关键指标，验证修复效果

**关键日志指标**：
- ✅ `wait_iterations` < 10（而不是之前的 49）
- ✅ 等待时间 < 100ms（而不是之前的 5 秒）
- ✅ `total_messages_processed` > 0（而不是 0）
- ✅ 签名协议正常完成（不再超时）
- ✅ 如果出现 "Message queue closed, attempting to retrieve new queue from map"，说明消息处理循环成功切换到了后备队列

**测试脚本**：
已创建 `test-signing.sh` 脚本，可以参考使用（需要提供认证token）

---

## 17. 最新问题现状与分布式/协议层面排查计划（2025-12-11 07:05）

### 现状复盘（关键日志）
- 签名仍超时：`execute GG20 signing: GG20 signing timeout`，`total_messages_processed=0`。
- `ProcessIncomingSigningMessage` 一直 “waiting for message queue creation…” 到 10 秒超时返回，未再创建后备队列。
- 队列检查大量重复 “Queue check: using same queue … total_messages_processed=0”，没有出现 “Received message in signing processing loop”。
- 有 outCh 日志（从 tss-lib 发出）但 inCh 处理端一直未消费，说明执行端队列/处理循环与入队侧脱节。
- 有过 StartSign RPC 连接拒绝（coordinator → participants），重启后节点可能未 ready 就发起了签名。

### 分布式视角的可能断点
1) **StartSign 未真正下发**：节点 gRPC 未 ready（connection refused），或 StartSign 入口早期报错（密钥加载/party 创建失败），导致 executeSigning 未创建队列。
2) **executeSigning 未创建/未写入队列**：若缺少 “message queue created and added to map” 日志，说明阈值签名入口未走到队列创建处。
3) **tss-lib Party 未启动**：`party.Start()` 报错或未执行，outCh/inCh 不流转，处理循环自然读不到消息。
4) **队列可见性/时序**：即便 executeSigning 创建队列，`ProcessIncomingSigningMessage` 在 10 秒内仍看不到 map 中的队列，需确认 map 状态和 activeSigning 是否存在。
5) **DKG/密钥状态**：key 仍 Pending 或节点缺少 `.keydata.enc`，导致 ThresholdSign 早期失败。

### 需要补的诊断点（建议加日志后再测）
- 在 **ProcessIncomingSigningMessage** 超时前，加一次 map 状态诊断：`incomingSigningMessages` 是否包含该 session，activeSigning 是否有 LocalParty。
- 在 **executeSigning** 成功前后，记录队列创建、party.Start 成功/错误。
- 在 StartSign 入口记录密钥加载/参数校验/party 创建是否报错。

### 下一轮调查计划（只读排查顺序）
1. **确认 StartSign 是否成功下发**  
   - 看 coordinator 日志有无 connection refused；若有，先确保节点 ready，再发起签名（或在 coordinator 做重试/延时）。
2. **确认 executeSigning 是否创建队列**（每个参与者）  
   - 必须看到该 session 的 “executeSigning: message queue created and added to map / Starting message processing loop / Entering main signing loop”。缺失则回溯 StartSign/ThresholdSign 报错。
3. **确认 map 和 activeSigning 状态**  
   - 在超时前检查 map 是否含有该 session 的队列；activeSigning 是否有 LocalParty。若二者缺失，说明 executeSigning 根本未成功。
4. **确认 party.Start 是否报错**  
   - 如果 party 未启动或 start 报错，outCh/inCh 都不会流转；需要日志捕捉 start 的错误。
5. **确认 DKG/密钥文件与状态**  
   - 三节点是否都有对应 key 的 `.keydata.enc`，key 状态非 Pending。
6. **重新发起签名并对齐三节点时间线**  
   - 对同一 session，在三节点日志中对齐：队列创建、消息入队、消息消费、outCh 生成、签名完成/错误。找缺口。

### 预期验证信号
- 每个参与者都打印了队列创建+处理循环启动的日志。
- `ProcessIncomingSigningMessage` 不再超时，能找到队列；`total_messages_processed > 0`。
- 无 connection refused；StartSign 能走到 party.Start。
- endCh 产出签名或明确错误，而不是静默超时。

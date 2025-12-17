# 备份分片下发（Backup Delivery）逻辑实现计划

## 1. 概述

本计划详细描述了如何实现备份分片下发逻辑，确保密钥分片能够安全、可靠地从服务端分发到客户端。整个流程涉及加密传输、状态管理、接口设计和测试验证等关键环节。

## 2. 核心组件设计

### 2.1 加密机制

**目标**：确保分片在传输过程中的机密性和完整性

**技术方案**：
- 使用ECIES（Elliptic Curve Integrated Encryption Scheme）加密算法
- 客户端生成EC密钥对，公钥注册到服务端
- 服务端使用客户端公钥加密分片数据
- 客户端使用私钥解密接收到的分片

**实现步骤**：
1. 定义加密接口：`EncryptShare(share []byte, publicKey *ecdsa.PublicKey) ([]byte, error)`
2. 定义解密接口：`DecryptShare(encryptedShare []byte, privateKey *ecdsa.PrivateKey) ([]byte, error)`
3. 添加完整性校验：使用HMAC-SHA256对加密数据进行签名
4. 实现密钥派生函数：从共享密钥派生加密密钥和HMAC密钥

### 2.2 传输接口设计

**目标**：提供标准化的分片接收接口

**gRPC接口定义**：
```protobuf
service BackupDeliveryService {
    // 请求分片下发
    rpc RequestShareDelivery(ShareDeliveryRequest) returns (ShareDeliveryResponse);
    // 确认分片接收
    rpc ConfirmShareDelivery(ShareConfirmationRequest) returns (ShareConfirmationResponse);
    // 查询分片状态
    rpc QueryShareStatus(ShareStatusQuery) returns (ShareStatusResponse);
}

message ShareDeliveryRequest {
    string client_id = 1;
    string backup_id = 2;
    bytes client_public_key = 3;  // 客户端公钥
}

message ShareDeliveryResponse {
    string delivery_id = 1;
    bytes encrypted_share = 2;
    bytes signature = 3;  // 服务端签名
    int64 timestamp = 4;
}

message ShareConfirmationRequest {
    string delivery_id = 1;
    string client_id = 2;
    bool received_successfully = 3;
}

message ShareConfirmationResponse {
    bool confirmed = 1;
    string message = 2;
}
```

**HTTP RESTful接口**（备选方案）：
- `POST /api/v1/backup/delivery/request` - 请求分片下发
- `POST /api/v1/backup/delivery/confirm` - 确认分片接收
- `GET /api/v1/backup/delivery/status/{delivery_id}` - 查询分片状态

### 2.3 状态机设计

**状态流转**：
```
PENDING → DELIVERED → CONFIRMED
   ↓         ↓
FAILED    FAILED
```

**状态定义**：
- `PENDING`：分片已准备就绪，等待客户端请求
- `DELIVERED`：分片已成功发送到客户端
- `CONFIRMED`：客户端确认成功接收并验证分片
- `FAILED`：分发过程中出现错误

**状态转换触发条件**：
1. PENDING → DELIVERED：服务端成功发送加密分片给客户端
2. DELIVERED → CONFIRMED：客户端成功解密并验证分片完整性
3. 任意状态 → FAILED：超时、网络错误、验证失败等异常情况

**状态存储结构**：
```go
type ShareDeliveryStatus struct {
    DeliveryID      string    `json:"delivery_id"`
    ClientID        string    `json:"client_id"`
    BackupID        string    `json:"backup_id"`
    Status          string    `json:"status"`
    EncryptedShare  []byte    `json:"encrypted_share"`
    CreatedAt       time.Time `json:"created_at"`
    DeliveredAt     time.Time `json:"delivered_at"`
    ConfirmedAt     time.Time `json:"confirmed_at"`
    RetryCount      int       `json:"retry_count"`
    LastError       string    `json:"last_error"`
}
```

## 3. 实现步骤分解

### 3.1 第一阶段：基础加密模块（1-2天）

**任务1.1**：实现ECIES加密算法
- 使用secp256k1曲线
- 实现密钥派生函数（KDF）
- 添加AES-256-GCM对称加密
- 实现HMAC-SHA256完整性校验

**任务1.2**：单元测试
- 测试加密解密正确性
- 测试密钥派生一致性
- 测试完整性校验失败情况
- 性能基准测试

### 3.2 第二阶段：状态管理模块（1天）

**任务2.1**：状态机实现
- 定义状态常量
- 实现状态转换逻辑
- 添加状态验证函数
- 实现超时处理机制

**任务2.2**：状态存储
- 设计数据库表结构
- 实现状态CRUD操作
- 添加状态历史记录
- 实现状态查询索引

### 3.3 第三阶段：传输接口实现（2天）

**任务3.1**：gRPC服务端实现
- 实现分片请求处理
- 实现分片确认处理
- 实现状态查询功能
- 添加请求验证和错误处理

**任务3.2**：HTTP接口实现（可选）
- 实现RESTful API
- 添加中间件（认证、日志、限流）
- 实现Swagger文档
- 添加接口版本控制

### 3.4 第四阶段：客户端SDK（1-2天）

**任务4.1**：客户端库实现
- 实现分片请求函数
- 实现分片解密函数
- 实现分片验证函数
- 实现状态确认函数

**任务4.2**：客户端配置
- 支持服务端地址配置
- 支持超时时间配置
- 支持重试策略配置
- 支持日志级别配置

### 3.5 第五阶段：Mock客户端（1天）

**任务5.1**：Mock服务端实现
- 模拟分片生成
- 模拟加密过程
- 模拟状态管理
- 模拟错误场景

**任务5.2**：Mock客户端实现
- 模拟密钥生成
- 模拟分片请求
- 模拟分片解密
- 模拟状态确认

### 3.6 第六阶段：集成测试（1天）

**任务6.1**：端到端测试
- 测试完整分发流程
- 测试异常处理
- 测试并发场景
- 测试网络中断恢复

**任务6.2**：性能测试
- 测试分片加密性能
- 测试接口响应时间
- 测试并发处理能力
- 测试内存使用情况

## 4. 错误处理与重试机制

### 4.1 错误分类

**可重试错误**：
- 网络超时
- 服务端临时不可用
- 数据库连接失败
- 加密服务异常

**不可重试错误**：
- 客户端认证失败
- 分片不存在
- 加密密钥无效
- 数据格式错误

### 4.2 重试策略

**指数退避算法**：
```go
func calculateBackoff(attempt int) time.Duration {
    baseDelay := 100 * time.Millisecond
    maxDelay := 30 * time.Second
    
    delay := baseDelay * time.Duration(math.Pow(2, float64(attempt)))
    if delay > maxDelay {
        delay = maxDelay
    }
    
    // 添加随机抖动
    jitter := time.Duration(rand.Int63n(int64(delay / 4)))
    return delay + jitter
}
```

**重试限制**：
- 最大重试次数：5次
- 总超时时间：5分钟
- 重试间隔：指数增长，最大30秒

## 5. 安全考虑

### 5.1 加密安全
- 使用强随机数生成器生成临时密钥
- 定期轮换服务端密钥
- 实现前向保密性
- 添加时间戳防止重放攻击

### 5.2 传输安全
- 强制使用TLS 1.3
- 实现证书固定（Certificate Pinning）
- 添加请求签名验证
- 实现请求限流和防DDoS

### 5.3 存储安全
- 加密存储敏感数据
- 实现数据脱敏
- 添加访问审计日志
- 定期清理过期数据

## 6. 监控与日志

### 6.1 关键指标
- 分片分发成功率
- 平均分发耗时
- 重试次数统计
- 错误类型分布

### 6.2 日志规范
```go
type DeliveryLog struct {
    Timestamp   time.Time `json:"timestamp"`
    Level       string    `json:"level"`
    DeliveryID  string    `json:"delivery_id"`
    ClientID    string    `json:"client_id"`
    Status      string    `json:"status"`
    Duration    int64     `json:"duration_ms"`
    Error       string    `json:"error,omitempty"`
}
```

### 6.3 告警规则
- 分发成功率低于95%
- 平均耗时超过10秒
- 连续失败次数超过10次
- 内存使用率超过80%

## 7. 部署与运维

### 7.1 部署策略
- 蓝绿部署
- 滚动更新
- 健康检查
- 自动扩缩容

### 7.2 备份策略
- 状态数据定期备份
- 密钥安全存储
- 灾难恢复方案
- 数据一致性检查

### 7.3 运维工具
- 状态查询CLI
- 手动重试工具
- 数据修复脚本
- 性能分析工具

## 8. 测试验证计划

### 8.1 单元测试覆盖率
- 加密模块：>95%
- 状态机：>90%
- 接口处理：>85%
- 错误处理：>90%

### 8.2 集成测试场景
- 正常分发流程
- 网络中断恢复
- 服务端重启
- 并发分发
- 密钥轮换

### 8.3 性能基准
- 单分片加密：<100ms
- 接口响应时间：<500ms
- 并发处理能力：>1000 QPS
- 内存使用：<1GB

## 9. 后续优化方向

### 9.1 性能优化
- 批量分发支持
- 缓存机制优化
- 异步处理改进
- 网络传输优化

### 9.2 功能扩展
- 多算法支持
- 分片压缩
- 增量更新
- 客户端缓存

### 9.3 安全增强
- 零知识证明
- 多方安全计算
- 同态加密
- 量子安全算法
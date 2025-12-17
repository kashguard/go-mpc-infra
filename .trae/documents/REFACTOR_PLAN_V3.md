# MPC钱包重构计划 V3

## 1. 目录结构变更

### 1.1 Protobuf定义目录调整
```
proto/
├── mpc/v1/                    # 保留，仅用于节点间通信
│   ├── mpc.proto             # 移除双stream RPC定义
│   └── ...
└── infra/v1/                  # 重命名：infrastructure/v1 -> infra/v1
    ├── key.proto             # 应用层RPC定义
    ├── backup.proto          # 应用层RPC定义
    └── ...
```

### 1.2 内部代码目录调整
```
internal/
├── mpc/                       # 保持不变
│   ├── coordinator/
│   ├── participant/
│   └── ...
├── infra/                     # 重命名：infrastructure -> infra
│   ├── key/                   # 移动key服务
│   ├── backup/                # 移动backup服务
│   └── ...
├── api/                       # 保留，RESTful API Gateway
└── pb/                        # 保留，生成的代码存放处
```

## 2. Proto定义变更

### 2.1 移除内容
- 从 `proto/mpc/v1/mpc.proto` 中移除 `JoinSigningSession` 双stream RPC定义
- 移除相关的请求/响应消息类型

### 2.2 保留内容
- 保留其他节点间通信所需的RPC定义
- 保留协调者与参与者之间的基本通信机制

### 2.3 重命名路径
- `proto/infrastructure/v1/` -> `proto/infra/v1/`
- 更新所有相关的import路径

## 3. 代码重构步骤

### 3.1 第一阶段：目录结构调整
1. 创建新目录 `proto/infra/v1/`
2. 将 `proto/infrastructure/v1/` 下的文件移动到新目录
3. 更新所有proto文件中的import路径
4. 重命名 `internal/infrastructure/` 为 `internal/infra/`

### 3.2 第二阶段：服务迁移
1. 将key服务从原位置迁移到 `internal/infra/key/`
2. 将backup服务从原位置迁移到 `internal/infra/backup/`
3. 更新所有相关的import路径和引用

### 3.3 第三阶段：RPC定义清理
1. 编辑 `proto/mpc/v1/mpc.proto`
2. 移除 `JoinSigningSession` RPC定义
3. 移除相关的双stream逻辑代码
4. 重新生成protobuf代码

### 3.4 第四阶段：代码生成更新
1. 运行protobuf代码生成
2. 更新 `internal/pb/` 目录下的生成代码
3. 修复所有编译错误

## 4. 逻辑/RPC变更详情

### 4.1 协调者与参与者通信
- **保持现状**：协调者与参与者之间的基本通信机制不变
- **移除内容**：仅移除 `JoinSigningSession` 双stream RPC
- **影响范围**：不影响现有的签名流程和节点协调逻辑

### 4.2 内部/mpc目录
- **保持不变**：`internal/mpc/` 目录下的所有代码保持原样
- **协调者逻辑**：维持现有的协调者实现
- **参与者逻辑**：维持现有的参与者实现

### 4.3 API Gateway
- **保留现状**：`internal/api/` 继续负责认证和请求转发
- **功能不变**：RESTful API Gateway的功能不受影响

### 4.4 服务迁移影响
- **Key服务**：从原位置迁移到 `internal/infra/key/`
- **Backup服务**：从原位置迁移到 `internal/infra/backup/`
- **功能保持**：服务功能保持不变，仅调整目录位置

## 5. 验证清单

### 5.1 编译验证
- [ ] 所有protobuf文件能正确生成代码
- [ ] 项目能正常编译通过
- [ ] 所有import路径正确更新

### 5.2 功能验证
- [ ] 协调者功能正常
- [ ] 参与者功能正常
- [ ] API Gateway功能正常
- [ ] Key服务功能正常
- [ ] Backup服务功能正常

### 5.3 通信验证
- [ ] 节点间通信正常
- [ ] 协调者与参与者通信正常
- [ ] 双stream RPC已完全移除

## 6. 注意事项

1. **逐步重构**：建议按阶段进行，每个阶段完成后进行验证
2. **版本控制**：在每个主要步骤后进行代码提交
3. **测试覆盖**：确保有足够的测试覆盖关键功能
4. **回滚准备**：准备好回滚方案，以防出现问题
5. **文档更新**：同步更新相关文档和README文件
# 2-of-3 分离式鉴权代理 (Delegated Guardian) 方案设计

## 1. 方案概述

本方案旨在解决在 **2-of-3 门限签名** 场景下，用户端（APP）**不具备运行完整 MPC 协议能力**（无法参与 DKG 和 MPC 签名计算），但仍需保证**资金控制权**属于用户，且运营方无法单方挪用资产的问题。

方案的核心思想是引入 **“鉴权代理 (Guardian Node)”** 角色，将用户对资产的控制权转化为“数字签名指令”，由代理节点验证指令后代为执行 MPC 计算。

## 2. 角色与分片架构

系统采用 `2-of-3` 门限方案，至少需要 2 个分片参与才能完成签名。分片分配如下：

| 分片编号 | 持有者 | 部署位置 | 角色性质 | 关键职责 |
| :--- | :--- | :--- | :--- | :--- |
| **Share 1** | **运营方 (Operator)** | 运营方服务器 (云端 A) | 业务发起方 | 负责构建交易、发起 MPC 会话、持有业务分片。即使被攻破，攻击者仅获得 1/3 控制权。 |
| **Share 2** | **鉴权代理 (Guardian)** | 独立安全环境 (云端 B / TEE) | **用户代理人** | **方案核心**。不处理具体业务逻辑，**只验证用户指令**。只有在验证通过后，才加载 Share 2 参与计算。 |
| **Share 3** | **冷备份 (Cold Backup)** | 离线存储 / 银行保管箱 | 灾难恢复 | 平时不在线。仅在 Share 1 或 Share 2 丢失/损坏时取出用于重置系统。 |

## 3. 核心流程设计

### 3.1 注册绑定流程 (Setup)

用户首次使用时，需将 APP 生成的控制密钥与鉴权代理进行绑定。

```mermaid
sequenceDiagram
    participant User as 用户 (APP)
    participant Operator as 运营方服务 (Node A)
    participant Guardian as 鉴权代理 (Node B)
    participant Chain as 存证/数据库

    Note over User: 1. 生成控制密钥对 (User_Auth_Key)<br/>(普通非对称密钥，如 Ed25519)
    User->>Operator: 2. 提交注册请求 (含 User_Auth_Pub)
    Operator->>Guardian: 3. 同步用户注册信息
    Guardian->>Guardian: 4. 绑定策略: WalletID <-> User_Auth_Pub
    Guardian-->>Operator: 确认绑定成功
    Operator-->>User: 注册完成
    
    Note right of Guardian: 此后 Node B 只认<br/>该公钥签名的指令
```

### 3.2 交易签名流程 (Transaction Signing)

这是日常转账的核心流程。用户仅需进行轻量级签名，复杂的 MPC 计算在云端完成。

```mermaid
sequenceDiagram
    autonumber
    actor User as 用户 (APP)
    participant Operator as 运营方 (Share 1)
    participant Guardian as 鉴权代理 (Share 2)
    participant Network as 区块链网络

    Note over User: 用户发起转账请求

    User->>User: 1. 签署交易指令<br/>Sign(TxHash) -> Auth_Token<br/>(使用 User_Auth_Key)
    User->>Operator: 2. 发送交易请求 + Auth_Token

    Note over Operator: 3. 业务检查 (余额/风控)
    Operator->>Operator: 准备 MPC 会话 (Share 1)

    Operator->>Guardian: 4. 请求协同签名 (TxInfo + Auth_Token)
    
    rect rgb(240, 248, 255)
        Note over Guardian: **安全核心步骤**
        Guardian->>Guardian: A. 验证 Auth_Token 签名有效性
        Guardian->>Guardian: B. 验证 TxInfo 与 Token 内容一致
        Guardian->>Guardian: C. 执行风控策略 (限额/白名单)
    end

    alt 验证失败
        Guardian-->>Operator: 拒绝请求 (Access Denied)
        Operator-->>User: 交易失败
    else 验证成功
        Note over Guardian: 加载 Share 2
        Operator->>Guardian: 5. 执行 MPC 签名协议 (2-of-3)
        Note right of Guardian: 生成最终链上签名 (Signature)
    end

    Operator->>Network: 6. 广播交易
    Network-->>Operator: 交易确认
    Operator-->>User: 通知交易成功
```

### 3.3 灾难恢复流程 (Recovery)

当用户丢失手机（丢失 `User_Auth_Key`）或运营方服务器故障时的恢复机制。

```mermaid
flowchart TD
    Start((开始恢复)) --> Check[故障类型判断]
    
    Check -->|用户手机/私钥丢失| UserLost
    Check -->|运营方数据丢失| OperatorLost
    
    subgraph UserRecovery [用户端恢复流程]
        UserLost[用户发起重置请求] --> KYC[严格身份认证 (视频/证件/生物识别)]
        KYC -->|认证通过| Admin[管理员介入]
        Admin --> Retrieve3[取出 Share 3 (冷备份)]
        Retrieve3 --> MPC_Reshare[执行 MPC Reshare (刷新所有分片)]
        MPC_Reshare --> NewShares[生成新 Share 1, 2, 3]
        NewShares --> BindNew[用户绑定新手机 Key]
        BindNew --> Finish1((恢复完成))
    end
    
    subgraph SysRecovery [系统级恢复流程]
        OperatorLost[启用灾备预案]
        OperatorLost --> Retrieve3_Sys[取出 Share 3]
        Retrieve3_Sys --> Combine[Node B (Share 2) + Share 3]
        Combine --> MPC_Reshare_Sys[执行 MPC Reshare]
        MPC_Reshare_Sys --> Restore[恢复服务]
        Restore --> Finish2((恢复完成))
    end
```

## 4. 安全性分析

### 4.1 为什么运营方无法作恶？
虽然运营方持有 **Share 1** 并可能拥有 **Node B** 的基础设施权限，但我们通过以下层级保证安全：

1.  **协议层隔离**：Node B 的代码逻辑强制要求 `Auth_Token`。没有用户私钥生成的签名，程序逻辑走不通。
2.  **基础设施隔离**：
    *   建议 Node A 和 Node B 部署在不同的云服务商或不同的 Kubernetes 集群。
    *   权限分离，Node A 的管理员无法登录 Node B。
3.  **可信执行环境 (TEE) 增强 (推荐)**：
    *   将 Node B 部署在 Intel SGX / AWS Nitro Enclaves 中。
    *   **效果**：即使拥有服务器 Root 权限，也无法读取内存中的 Share 2，也无法篡改验证代码逻辑。

### 4.2 为什么用户端是安全的？
*   **私钥不离身**：`User_Auth_Key` 始终在用户手机的安全区域（Secure Enclave / KeyStore）中，仅用于签署指令，不参与复杂的 MPC 交互。
*   **所见即所签**：APP 端展示交易详情供用户确认，签名针对该特定交易，防止重放攻击。

## 5. 方案优缺点总结

| 维度 | 优势 | 劣势/挑战 |
| :--- | :--- | :--- |
| **用户体验** | **极佳**。用户无感知 MPC 复杂性，操作习惯与传统钱包一致（指纹/FaceID 确认）。 | 需要依赖网络，无离线签名能力。 |
| **兼容性** | **完美**。产出标准 EOA 签名，支持所有 EVM 链及 BTC 等异构链，无需智能合约支持。 | 无。 |
| **安全性** | **高**。实现了“不信任单一运营方”，攻击成本需同时攻破用户端和代理节点。 | 依赖 Node B 的代码完整性和执行环境安全 (建议上 TEE)。 |
| **成本** | **低**。链上 Gas 费与普通转账一致（无多签合约开销）。 | 需维护两套独立的节点设施 (Node A & Node B)。 |

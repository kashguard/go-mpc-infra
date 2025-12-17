# 未实现功能清单（基础设施层）

记录当前代码中的未实现或待完善功能，便于后续规划与拆解。

## 备份与下发
- **客户端分片下发闭环**（加密 → 传输 → 确认）(已完成)：
  - 用客户端公钥加密 SSS 备份分片。(已完成)
  - 通过 HTTPS/gRPC 向客户端应用下发并等待确认。(已完成 - 采用客户端拉取模式)
  - 下发成功/失败/确认的状态机更新（`backup_share_deliveries` 记录状态流转）。(已完成)
- **交付接口落地**：实际的客户端通信、回执验证、错误重试仍需实现。(已完成)

## 密钥与派生
- **Hardened Derivation**：强化派生逻辑、路径规范、公钥生成已实现。
  - 支持 `m/44'/60'/0'/0/0` 格式路径解析。(已完成)
  - 支持 Ed25519 非强化派生 (MPC 兼容模式)。(已完成)
  - 新增 `DeriveWalletKeyByPath` 接口。(已完成)
- **密钥轮换协议**：GG18/GG20 的轮换流程、元数据更新，以及旧签名验证兼容性。
  - `GG20Protocol` 支持 `ExecuteResharing`。(已完成)
  - `Coordinator` 和 `GRPCServer` 增加 `StartResharing` RPC。(已完成)
  - `KeyService` 增加 `RotateKey` 方法。(已完成 - 暂不支持分布式协调，仅支持本地/测试模式，待完善 DKGService 支持)

## 协议与验证
- **协议鲁棒性**：
  - 定义了结构化的 `ProtocolError` 类型（超时、恶意节点、网络错误）。(已完成)
  - 实现了 `retryProtocol` 机制，在 DKG/签名失败时自动重试（针对超时/网络错误）。(已完成)
  - 增强了 Session 管理，增加了定期清理过期会话的机制。(已完成)
- **Schnorr/BIP-340 验证**：
  - FROST 签名验证已支持标准 Ed25519 (RFC 8032)。(已完成)
  - FROST 签名验证已支持 Secp256k1 Schnorr (BIP-340)。(已完成)
  - 移除了非标准的 ECDSA 回退逻辑，统一使用 Schnorr 验证。(已完成)
- **签名会话完善**：超时处理（已集成到重试机制）、故障恢复。

## 鉴权与安全
- **架构安全加固**：
  - 实施了基于角色的服务启动策略：参与者节点不再启动应用层接口 (Infrastructure gRPC & REST API)，仅保留节点间通信接口。(已完成)
  - 确认了分层认证体系：应用层使用 mTLS+JWT，节点层使用 mTLS。(已完成)
- **JWT 校验细化**：
  - mTLS 就绪。(已完成)
  - 引入了 `golang-jwt/jwt/v5` 库，实现了 JWT 生成与校验逻辑 (`internal/auth/jwt.go`)。(已完成)
  - 在 gRPC `authInterceptor` 中集成了 JWT 校验，支持细粒度权限 (Claims)。(已完成)
  - 添加了 JWT 相关配置 (`MPC_JWT_SECRET`, `MPC_JWT_DURATION_MINUTES`)。(已完成)
- **分片下发安全**：客户端分片的加密策略、重放防护、确认签名等安全措施未落地。(已完成 - ECIES+HMAC)

## 存储与接口
- **BackupShareDelivery 业务串联**：存储层已实现，服务层已接入 KeyGen 流程。(已完成)
- **客户端 API/SDK**：备份分片交付与确认的接口约定及实现尚未完成。(已完成 - Go SDK Ready)

## 测试与文档
- **端到端集成测试**：含 mTLS + JWT 的 E2E 流程未覆盖。
- **性能/压力/故障注入测试**：尚未开展。
- **接口文档同步**：备份下发与确认相关的 Swagger/gRPC 文档未更新。

## 部署与配置
- **TLS 证书分发与校验**：
  - 实现了 `cert` CLI 工具，用于生成开发/测试用的 CA、Server、Client 证书 (`cmd/cert`)。(已完成)
  - 实现了 `VerifyTLSConfig` 工具函数，用于校验 TLS 证书的有效性、匹配性和过期时间 (`internal/util/cert`)。(已完成)
  - 在 gRPC 服务启动时集成了证书校验逻辑，确保配置的证书有效。(已完成)



# `/docs`

该目录汇总 MPC 基础设施相关的设计、计划与实施文档。

## 📚 推荐阅读顺序

### 产品与业务视角
- `mpc-wallet-user-scenarios.md` – **用户使用场景产品文档**：个人和团队使用场景、详细流程图、最佳实践、常见问题解答（**推荐产品经理和业务人员阅读**）
- `mpc-wallet-technical-solution.md` – **完整技术方案文档**：综合技术方案、应用场景、实施路线图、风险评估
- `mpcvault-product-overview.md` – **产品方案文档（产品经理版）**：业务价值、功能特性、竞品对比、商业分析

### 技术实施视角
1. `mpc-development-plan.md` – **开发计划**：阶段拆解、任务列表、验收标准
2. `mpc-detailed-design.md` – **详细设计**：架构、流程图、协议与数据结构
3. `mpcvault-implementation-guide.md` – **MPCVault 技术方案分析**：MPCVault 技术栈分析、TSS/SSS 对比、实施方案
4. `mpc-implementation-methodology.md` – **实施方法论**：开发流程、测试策略、CI/CD、风险管理
5. `mpc-implementation-strategy.md` – **总体实施策略**：多阶段路线、架构选型、演进路径
6. `server-initialization.md` – **部署/初始化指南**

## 📝 文档说明

- `mpcvault-product-overview.md` - 面向产品经理和业务决策者，重点关注商业价值和产品特性
- `mpc-development-plan.md` - 任务状态需与代码实现保持同步
- `mpcvault-implementation-guide.md` - 包含 MPCVault 技术方案分析和在本项目中的实施方案
- 需要示例或模板时，可参考 https://github.com/golang-standards/project-layout/tree/master/docs

每次迭代完成后，请同步更新相关文档，确保设计与实现一致。

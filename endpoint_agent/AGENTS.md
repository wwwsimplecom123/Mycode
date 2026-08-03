# ShieldDome Endpoint Agent 协作指南

本文件适用于 `endpoint_agent/` 及其全部子目录。根目录 `AGENTS.md` 的仓库级规则仍然有效；发生冲突时，优先遵守更严格的安全、隐私和目录隔离要求。

## 1. 开始工作前

按顺序完整阅读：

1. 根目录 `AGENTS.md`；
2. 根目录 `CONTEXT.md`；
3. `endpoint_agent/README.md`；
4. `endpoint_agent/DEVELOPMENT_PLAN.md`；
5. `endpoint_agent/docs/USAGE.md`；
6. 当前阶段直接引用的规范和计划。

检查 `git status --short`、未提交差异和 `endpoint_agent/` 的实际文件。保护用户已有修改，不得覆盖、删除、还原或批量格式化无法确认来源的内容。

## 2. 当前实现状态

当前已实现 **Phase 0：脚手架与约束测试**、**Phase 1：Feature Pipeline 与数据集治理**、开发期 **Phase 2：基线模型与评估**、**Phase 4A：模型无关 Detection Kernel**、**Phase 4A.1：本地规则评估与 Local Detection Service**，以及 **Phase 5A：Native Messaging 协议、本地 Host 与独立 MV3 插件基础链路**。Phase 3 因没有 Approved Training Corpus 而被有意暂缓并保持 `pending`；Phase 4 总状态为 `in_progress`，Phase 4B 保持 `pending`；Phase 5 总状态为 `in_progress`，Phase 5B 保持 `pending`。

现有生产包只包含：

- 包版本和公开导出；
- `MailObservation`、`FeatureVector`、`ModelAssessment`、`DetectionOutcome`；
- 对应 schema/version 字段；
- 训练和 Endpoint 共用的确定性 `FeaturePipeline.transform`；
- Feature Pipeline 对文本、URL、附件元数据和认证观察的固定资源边界；
- Approved Training Corpus 的不可变候选、split policy、manifest、snapshot 类型和 `CorpusGovernance.prepare`；
- 跨样本标签冲突拒绝、来源/时间 test 留出、版本化近重复分组和非敏感训练溯源；
- `FeatureVector` 与 corpus manifest 的 `PrivacyScanner`。
- 稳定的 `LocalInference.infer(FeatureVector, InferenceContext) -> ModelAssessment` seam 和无文件/网络副作用的 `UnavailableModelAdapter`；
- 完整验证 Feature Schema 2.0 的 `LocalRuleEvaluator.evaluate(FeatureVector) -> tuple[RuleAssessment, ...]`，以及集中、保守、稳定的本地规则策略；
- 固定执行 observation 验证、Feature Pipeline、本地规则和 Detection Kernel 的 `LocalDetectionService.detect(...) -> DetectionOutcome`；
- 不可变的 `RuleAssessment`、模型输出校验、确定性风险融合和强证据风险下限；
- `DetectionKernel.detect(...) -> DetectionOutcome`、规则模式/拒判/故障降级、私密证据投影和精确四字段插件投影；
- 严格 Native Messaging framing、固定协议版本、集中资源上限、payload 白名单与稳定错误码；
- 固定开发 extension origin 校验、可通过 `BytesIO` 测试的 Host 循环，以及只返回四字段投影的检测 handler；
- 位于 `endpoint_agent/extension/`、仅匹配 chinaccs Webmail、只用 Native Messaging 的独立 MV3 插件；
- `MODEL_ASSESSMENT_SCHEMA_VERSION = "1.0"` 与 `DETECTION_OUTCOME_SCHEMA_VERSION = "2.0"`。

独立训练侧 `training/shielddome_training/` 提供固定 140 维 Feature Assembler、合成数据 Logistic Regression、validation-only sigmoid 候选与 Brier 质量门禁、validation-only 拒判阈值、test-only 拒判感知分组评估、JSON/Markdown 报告和 identity/sigmoid 两条 ONNX Runtime CPU 一致性验证。训练依赖只存在于被忽略的 `.venv-training/`，训练代码和依赖均不得进入生产 Wheel。

现有测试还覆盖 FeatureVector 边界拒绝、本地规则稳定性/强度/资源上限、Local Detection Service 信任边界、Local Inference unavailable、Model Assessment 非法输出、规则/模型融合、Kernel 降级、Native Messaging 异常载荷/origin/数据隔离、插件静态离线约束和 DetectionOutcome 隐私扫描。插件只能提供 `MailObservation` 事实，不能提供规则、分数、强证据、模型状态或最终结果。当前仍没有 Approved Training Corpus、正式训练数据、可发布 Unified Model Release、生产 ONNX Runtime adapter、Host 可执行文件/浏览器注册、数据库、加密存储或桌面 UI；不得把少量合成实验指标、Phase 4A/4A.1 interface 或 `README.md` 的目标能力误认为正式模型已经交付。

## 3. 目录边界

- Endpoint Agent 的新增和修改默认只能位于 `endpoint_agent/`。
- 不得为了 Endpoint Agent 修改 `app/`、`shielddome/`、`frontend/`、`extension/`、`web/`、`deploy/` 或现有部署脚本。
- 现有 ShieldDome 解析、链接、规则和证据模块仅可按当前阶段授权只读研究或导入；不得复制、迁移或修改它们。
- 根目录 `CONTEXT.md` 和 `.gitignore` 不属于 Endpoint Agent 的普通修改范围。
- Endpoint Agent 运行产物必须由 `endpoint_agent/.gitignore` 管理。

如任务明确扩大目录范围，先检查其是否改变产品方向、隐私边界或安全模型。没有明确授权时保持目录隔离。

## 4. 架构与领域语言

使用根目录 `CONTEXT.md` 中的统一术语：

- Endpoint Agent
- Local Mail Risk Model
- Unified Model Release
- Endpoint Release
- Model Assessment
- Endpoint Evidence Record
- Confirmed Example Library
- Attachment Metadata Assessment
- Mail Intake
- Personal Security Dashboard
- Protection Mode
- Offline Operation

避免使用被文档明确排除的替代称谓。当前领域类型是跨模块契约，修改公开字段、字段含义或版本值时，必须同步更新测试和使用文档。

## 5. Python 与模块规则

- 目标 Python 版本为 3.12。
- 测试框架使用标准库 `unittest`，不引入 pytest。
- 生产代码放在 `endpoint_agent/src/shielddome_endpoint/`。
- 测试放在 `endpoint_agent/tests/`。
- wheel 构建使用项目内置的零外部依赖 PEP 517 后端；没有明确授权和离线复现证据时，不得重新引入第三方 build backend requirement。
- 领域数据优先使用明确类型和不可变结构，不用松散字典替代稳定公共契约。
- 每个文件保持单一职责；业务逻辑不要堆积在包入口或未来 UI 中。
- 不为了未来阶段创建空 service、adapter、database、model 或 UI 占位实现。
- 中文文档统一使用 UTF-8；修改已有文件时保留其换行和末尾空行。

## 6. TDD 与阶段执行

新增约束行为必须按红绿循环实施：

1. 在已确认 seam 编写一个会失败的测试；
2. 运行最小相关命令，确认失败原因是目标行为尚未实现；
3. 编写使该测试通过的最小实现；
4. 重新运行并确认通过；
5. 再进入下一个垂直切片。

不要一次写完全部测试再统一实现，也不要为了覆盖率提前实现后续阶段功能。

阶段开发通常从 `DEVELOPMENT_PLAN.md` 中最早的可实施阶段开始。Phase 3 被明确暂缓时，Phase 5 可以依赖已完成的 Phase 4A.1 Local Detection Service seam 开发，但不能让浏览器提供可信风险判断，不能把 Phase 3 或 Phase 4B 标记为完成，也不能绕过正式 Endpoint Release 的模型和发布门禁。只有当前子阶段全部验收条件获得新鲜验证证据后，才能把对应状态改为 `complete`。

## 7. 离线与安全硬约束

Endpoint Agent 生产代码必须：

- 完全离线，不连接中心后台；
- 不调用外部模型、Embedding、信誉、遥测或更新服务；
- 不提供或依赖 HTTP/WebSocket 服务；
- 不监听 TCP/UDP 端口；
- 不引入网络客户端和服务框架；
- 不要求管理员权限处理普通用户数据；
- 不跨 Windows 用户共享数据库、密钥、日志、样本或模型运行上下文。

发现新增网络 import、endpoint 字面量或运行依赖时，离线约束测试必须失败。不得通过缩小测试扫描范围绕过约束。

## 8. 邮件、附件和本地数据

- 原始 `.eml`、完整正文和附件内容不得持久化或提交 Git。
- 附件只允许使用客户端已暴露的元数据；不得下载、打开、预览、解压、解析或执行附件。
- 不读取邮件客户端私有数据库，不注入进程，不截获凭据或邮件流量。
- 密钥、日志、SQLite 数据、诊断包、模型和训练数据必须保持忽略状态。
- 禁止把真实 API Key、Token、密码、生产数据库、用户邮件或模型二进制写入源码、测试 fixture、计划或文档。

Phase 0-2 没有实现生产持久化、加密或留存逻辑。后续实现必须以当前阶段的明确验收条件为准，不能用占位代码宣称安全能力存在。

## 9. 常用验证命令

在仓库根目录执行完整 Endpoint Agent 测试：

```powershell
python -m unittest discover -s endpoint_agent/tests -v
```

Phase 2 训练测试必须使用隔离环境：

```powershell
.\endpoint_agent\.venv-training\Scripts\python.exe -m unittest discover -s endpoint_agent/training_tests -v
```

离线验证构建配置：

```powershell
python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist
```

检查修改范围：

```powershell
git status --short
git status --porcelain=v1 -uall
git diff --name-status
git diff --stat
git diff
```

如果 `endpoint_agent/` 在任务开始时整体未跟踪，普通 `git diff` 不会展示新文件内容；必须额外枚举并阅读全部新增文件，并把任务结束状态与开始时的 Git 基线逐项比较。

## 10. 完成前检查

- 阅读完整测试输出并确认退出码；
- 运行与修改范围匹配的最小测试和完整阶段测试；
- 检查生产源码和运行依赖仍满足 Offline Operation；
- 使用 `git check-ignore` 验证新增运行产物类别；
- 清理测试和构建生成的临时目录；
- 检查 Git 状态、tracked diff、staged diff 和全部未跟踪文件；
- 确认现有 ShieldDome 目录和用户基线文件没有意外变化；
- 确认未实现当前任务范围之外的能力；
- 没有用户明确要求时，不提交、推送、创建分支或 PR。

任何完成声明都必须引用本次工作结束前刚刚执行的验证命令、测试数量、失败和跳过数量以及退出码。

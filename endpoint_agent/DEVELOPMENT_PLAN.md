# ShieldDome Endpoint Agent 详细开发方案

## 1. 文档用途

本文档是 ShieldDome Endpoint Agent 的开发交接基线。后续 Codex 开发任务应先阅读本文档、项目根目录 `AGENTS.md`、`CONTEXT.md` 和 `endpoint_agent/README.md`，然后从尚未完成的阶段继续实施。

推荐的后续任务提示词：

```text
请阅读 AGENTS.md、CONTEXT.md、endpoint_agent/README.md 和
endpoint_agent/DEVELOPMENT_PLAN.md，严格保持现有 ShieldDome 代码不变，
只在 endpoint_agent/ 中实施当前最早的未完成阶段。完成代码、测试、构建验证
和阶段状态更新，不要提前实现后续阶段。
```

## 2. 已确认且不得自行改变的产品决策

### 2.1 产品与隔离

- 现有 `app/`、`shielddome/`、`frontend/`、`extension/`、`web/`、部署脚本和服务器版本保持原封不动。
- 新产品仅在 `endpoint_agent/` 目录开发。
- Endpoint Agent 是每个 Windows 用户独立运行的本地产品。
- 不同用户的数据库、密钥、日志、已确认样本库和模型运行上下文互不共享。
- 不接中心后台，不提供跨用户数据看板，不上传用户邮件或检测日志。
- 允许在构建和测试时只读导入现有纯模块，例如邮件解析、链接分析、规则和证据聚合；不得为了 Endpoint Agent 修改这些现有模块。

### 2.2 操作系统与资源门槛

- Windows 10/11 64 位。
- 最低 4 核 CPU、8 GB 内存。
- 不要求独立显卡。
- 模型包硬上限 2 GB，目标约 500 MB。
- Agent 常驻内存不超过 1.5 GB。
- 检测期间峰值内存不超过 2.5 GB。
- 单封邮件规则检测低于 300 ms。
- 本地模型推理目标低于 3 秒。
- 资源不足、模型损坏、模型不兼容、推理失败或超时时自动降级为纯规则模式。
- Agent 不得明显影响浏览器、邮箱客户端和办公软件。

### 2.3 模型定义

- 模型是非生成式 Local Mail Risk Model，不是聊天模型。
- 可使用许可明确的中英文预训练文本编码器。
- ShieldDome 自研训练集治理、邮件特征、分类头、概率校准、拒判、风险融合和评估体系。
- 模型输出钓鱼概率、置信状态、模型版本、特征版本、耗时和执行状态。
- 模型不生成自然语言原因，不直接输出最终风险等级。
- 模型采用二分类概率，并支持不确定拒判。
- 所有员工使用同一 Unified Model Release。
- 终端只推理，不训练、不微调、不进行在线学习和个人模型适配。

### 2.4 训练数据

- 使用许可允许的公开正常邮件和钓鱼邮件数据。
- 使用 ShieldDome 自建仿真正常邮件和仿真钓鱼邮件。
- 使用经过人工确认的真实钓鱼案例。
- 不使用未经审核的个人邮箱作为训练数据。
- 个人邮件可作为本地验收样本，但不自动进入训练集。
- RAG、反馈和用户标记只能成为候选样本，人工审核后才能进入 Approved Training Corpus。
- 原始训练数据、模型文件、向量、数据集快照和训练输出禁止提交 Git。

### 2.5 语言范围

- 中文优先。
- 支持英文和中英文混合邮件。
- 邮件认证、域名、URL、附件元数据规则不受语言限制。
- 其他语言允许模型拒判，并降级为结构化规则检测。
- 中文、英文和中英文混合必须分别评估。

### 2.6 本地数据

- 邮件正文只在检测期间存在于内存，不持久化。
- 不保存原始 `.eml`、完整正文或附件内容。
- Endpoint Evidence Record 使用本地加密保存 15 天，到期自动删除。
- 证据记录不包含完整收件人列表、密码、Token、身份证号、银行卡号等敏感内容。
- Agent 不自动上传证据、崩溃日志、统计或诊断信息。
- 用户可以主动删除全部本地数据。
- 用户主动导出时才生成一次性脱敏诊断包。

### 2.7 已确认样本库

- 每个用户拥有独立 Confirmed Example Library。
- 只保存脱敏特征、向量、人工标签、来源摘要和内容哈希。
- 不保存原始邮件。
- 只用于相似案例有限校准，不改变模型权重。
- 用户误标最多影响当前用户自己的 Agent。
- 相似正常样本不能抵消黑名单、危险 URL、认证失败等强风险证据。
- 经用户主动导出和人工审核后，样本才可能进入下一版 Approved Training Corpus。

### 2.8 附件安全

- 首版只做 Attachment Metadata Assessment。
- 插件和 Agent 不自动下载附件。
- 不打开、预览、解压、解析或执行附件。
- 不调用 Office、PDF 阅读器、系统预览器或 Shell 文件处理器。
- 只使用邮件客户端已经展示的文件名、声明类型、大小、扩展名等元数据。
- 检查双扩展名、危险扩展名、宏文档声明、加密压缩包提示等元数据风险。
- 隔离附件检查属于未来独立项目，不得在 Agent 主进程中预留危险解析实现。

### 2.9 邮件接入

- 首版使用 Chrome/Edge Manifest V3 插件。
- 插件通过 Native Messaging 与当前用户 Agent 通信。
- 取消服务器地址、插件 Token、本机 HTTP 和公网 HTTP。
- Agent 仅允许预先配置的企业插件 ID 通信。
- 第二阶段增加通用 `.eml` 拖入和 Windows 右键检测。
- 后续仅在邮件客户端存在稳定、受支持的接入方式时开发 Outlook、Foxmail、QQ 邮箱等专用 adapter。
- 禁止读取客户端私有数据库、注入进程、截获账号密码、代理或解密邮件流量。

### 2.10 用户界面

- Windows 托盘 Agent，随当前用户登录启动。
- 精简个人控制台，不提供多用户、角色、全局策略和跨用户管理。
- 显示 Agent、模型、规则模式和降级状态。
- 支持 `.eml` 拖入检测。
- 个人数据看板包含今日检测数量、最近 15 天趋势、风险分布、接入来源、模型拒判和降级次数。
- 支持最近 15 天证据记录、已确认样本库、误报/漏报标记、诊断导出和全部数据删除。
- 插件只显示风险等级、状态、通用操作建议和本地事件 ID。
- 插件不显示模型 reason、模型名、RAG 内容、规则权重、名单配置和内部证据详情。

### 2.11 处置方式

- 首版采用 Protection Mode，不自动删除、隔离或移动邮件。
- 低风险只提示。
- 中风险提醒核实发件人。
- 高风险和严重风险可在点击危险操作前增加一次确认。
- 只有强规则证据可以触发额外确认。
- 模型概率本身不得触发强制干预。
- Agent 故障不得阻断邮箱正常使用。

### 2.12 离线与发布

- Agent 完全离线运行。
- 不调用外部模型、Embedding、URL 信誉、遥测和更新接口。
- 模型、策略、黑名单和插件随完整 Endpoint Release 发布。
- 不单独热更新模型。
- 模型更新时重新发布完整 Agent 安装包。
- 启动时校验 release manifest、模型 SHA-256、模型大小、特征版本和兼容版本。
- 普通用户不能修改安装目录中的模型和公司策略。
- 模型校验或兼容性失败时进入规则模式。
- 保留上一完整版本用于回滚。

## 3. 架构原则

### 3.1 模块深度

- Detection Kernel 是顶层 deep module。
- 插件、EML 导入和未来邮件客户端只依赖一个检测 interface。
- Feature Pipeline 是训练与终端推理共同的 seam。
- Phase 4A 的 `UnavailableModelAdapter` 与测试目录中的 deterministic fake adapter 共同证明 Local Inference seam 是真实的；生产 ONNX Runtime adapter 只在 Phase 4B 接入正式 Unified Model Release 时实现。
- 存储加密、保留期和清理顺序隐藏在 Local Evidence Store implementation 内。
- 不为尚未存在的隔离附件扫描器提前创建空 adapter。

### 3.2 Locality

- 所有特征定义集中在 Feature Pipeline。
- 所有模型权重上限、拒判和规则融合集中在 Risk Fusion。
- 所有结果脱敏和插件最小展示集中在 Result Projection。
- 所有 DPAPI、AES-GCM、保留期和销毁逻辑集中在 Local Evidence Store。
- 所有版本、哈希、兼容性和回滚集中在 Endpoint Release。

### 3.3 Leverage

- 一套 Feature Pipeline 同时支持训练、评估和终端推理。
- 一个 MailObservation 支持浏览器、EML 和未来桌面客户端。
- 一个 ModelAssessment 支持 ONNX Runtime 和测试 fake。
- 一个 DetectionOutcome 支持插件最小展示、本地控制台和加密证据记录。

## 4. 推荐技术栈

以下是首版推荐，不得在没有性能或兼容性证据时随意增加框架：

- Python 3.12。
- ONNX Runtime CPU。
- NumPy、scikit-learn；需要时使用许可明确的文本编码训练工具，仅作为开发依赖。
- PySide6 托盘和本地桌面界面。
- PyInstaller 或等价的 Windows 独立打包工具。
- Chrome/Edge Native Messaging。
- Windows DPAPI 保护本地数据密钥。
- AES-GCM 加密结构化证据。
- SQLite 保存小规模结构化记录；敏感字段在写入前加密。
- `unittest` 延续项目现有测试风格。

不得通过启动本地 HTTP 服务器实现插件通信或桌面界面。

## 5. 目录规划

```text
endpoint_agent/
  README.md
  DEVELOPMENT_PLAN.md
  pyproject.toml
  src/shielddome_endpoint/
    __init__.py
    app.py
    domain.py
    intake/
      __init__.py
      normalized_mail.py
      native_host.py
      eml_import.py
    detection/
      __init__.py
      kernel.py
      feature_pipeline.py
      local_inference.py
      risk_fusion.py
      result_projection.py
      attachment_metadata.py
    storage/
      __init__.py
      crypto.py
      evidence_store.py
      example_library.py
      retention.py
    release/
      __init__.py
      manifest.py
      integrity.py
      compatibility.py
    ui/
      __init__.py
      tray.py
      dashboard.py
  extension/
    manifest.json
    background.js
    content.js
    adapters/
  training/
    dataset.py
    deduplicate.py
    feature_snapshot.py
    train_baseline.py
    train_encoder.py
    calibrate.py
    evaluate.py
    export_onnx.py
    release_manifest.py
  policies/
    default-policy.json
  models/
    README.md
  packaging/
  tests/
```

## 6. 核心领域类型

首版应先定义稳定领域类型，再写 UI 或模型代码。

### MailObservation

统一的邮件观察输入：

- source kind 和 source message ID；
- subject、sender、reply-to、recipient 摘要；
- sanitized body text；
- authentication observations；
- normalized links；
- attachment metadata；
- language hint；
- observation timestamp。

不得包含浏览器页面完整 URL 查询参数、插件 Token、账号密码或客户端私有路径。

### FeatureVector

- 固定 schema version；
- 数值和类别结构特征；
- 可选文本编码输入或文本向量；
- 缺失值掩码；
- 不包含原始正文和原始附件。

### ModelAssessment

- probability；
- confidence state：confident-benign、uncertain、confident-phishing；
- execution status；
- model version；
- feature schema version；
- duration；
- non-sensitive error code。

### DetectionOutcome

- local event ID；
- final risk score 和 risk level；
- generic action；
- execution/degradation state；
- structured private evidence；
- minimal plugin projection；
- evidence retention timestamp。

## 7. 模型结构与训练路线

### 7.1 Baseline

先实现不依赖文本编码器的基线：

- 结构化特征；
- 字符/词级 TF-IDF 或 hashing 特征；
- logistic regression 或 gradient-boosted tree；
- 概率校准；
- 不确定拒判。

基线用于验证数据、特征、切分、评估和 ONNX 运行链路，不因指标不足而直接发布。

### 7.2 文本编码增强

- 选择许可证允许公司离线部署的中英文文本编码器候选。
- 固定相同数据切分对比模型文件、内存、耗时和质量。
- 首先使用冻结编码器生成向量并训练分类器。
- 只有数据量和指标证明必要时才微调编码器。
- 最终导出 ONNX，并验证 int8 或其他量化不会突破指标门槛。
- 禁止 custom operator 和不受控 external-data 路径。

### 7.3 风险融合

- 模型概率映射为有限 model evidence。
- uncertain 不增加强证据。
- 模型单独不得产生 critical。
- Confirmed Example Library 的相似正常和钓鱼证据均设置上限。
- 现有确定性强规则优先。
- 输出最终 low、medium、high、critical 和通用操作建议。

## 8. Approved Training Corpus

每个样本至少包含：

- corpus item ID；
- benign/phishing 标签；
- 标签来源与审核状态；
- 数据许可证或公司授权来源；
- raw hash、normalized hash、template/campaign group；
- language group；
- source group；
- ingestion time；
- feature schema version；
- dataset split；
- sanitized training representation。

必须执行：

- 精确重复去重；
- 规范化重复去重；
- 模板与近重复聚类；
- 同一活动或模板分配到同一 split；
- 按来源和时间保留独立测试集；
- 删除无许可证、标签冲突和来源不明样本；
- 记录每版 corpus manifest，但不把数据本体提交 Git。

## 9. 发布指标

Unified Model Release 必须同时满足：

- phishing recall >= 95%；
- benign false-positive rate <= 1%；
- high-confidence phishing precision >= 90%；
- abstention rate <= 25%；
- 中文、英文和混合语言分别通过；
- 浏览器、EML 和公开来源分别报告；
- 最低硬件推理 < 3 秒；
- 规则检测 < 300 ms；
- 模型包 <= 2 GB；
- 常驻内存 <= 1.5 GB；
- 峰值内存 <= 2.5 GB；
- 损坏、超时、资源不足和不兼容场景全部成功降级；
- 不得无审批降低当前发布版本的任何关键指标。

## 10. 安全门槛

- Native Messaging 只允许固定扩展 ID。
- Native Messaging 输入做类型、长度和字段白名单验证。
- Native host 的 stdout 只写协议帧，日志写受限本地文件。
- 不监听任何 TCP/UDP 端口。
- Agent 进程不需要管理员权限。
- 安装目录 ACL 阻止普通用户修改模型和策略。
- 数据目录只允许当前 Windows 用户访问。
- 模型加载前验证大小、哈希、格式、opset、feature schema 和 compatibility version。
- 禁止 ONNX custom operators 和未验证的 external data 文件。
- 推理限制线程、输入长度、内存和超时。
- 原始正文在分析结束后释放，不写日志和异常堆栈。
- 数据清理任务幂等，到期记录不可恢复地删除。
- 卸载提供保留或删除本地数据的明确选项。

## 11. 开发阶段与完成条件

状态约定：`pending`、`in_progress`、`complete`。

### Phase 0：脚手架与约束测试

Status: complete

- 创建独立 Python package、测试目录和最小构建配置。
- 建立禁止修改现有目录的差异检查。
- 定义核心领域类型和版本字段。
- 配置模型、数据、密钥、日志和诊断包忽略规则。

完成条件：package 可导入，基础测试通过，Git 不包含运行数据。

### Phase 1：Feature Pipeline 与数据集治理

Status: complete

- 复用现有纯解析、链接、规则和证据函数。
- 建立版本化 Feature Pipeline。
- 对文本、URL、附件元数据和认证观察建立确定性资源边界。
- 实现训练和推理使用同一 transform 的一致性测试。
- 实现 corpus manifest、许可元数据、跨样本标签冲突、去重和版本化近重复聚类。
- 实现来源/时间 test 留出与 duplicate/template/campaign/near-duplicate split 隔离。
- manifest 只保存规范 digest、UTC 时间和非敏感训练溯源标识。
- 实现隐私扫描，确保 FeatureVector 不包含禁止字段。

完成条件：同一邮件在训练和 endpoint adapter 产生完全一致且有界的 FeatureVector；Approved Training Corpus 的标签、来源/时间留出、重复组隔离和非敏感训练溯源可确定性复现。

### Phase 2：基线模型与评估

Status: complete

- 训练结构化基线模型。
- 实现概率校准和不确定拒判。
- 实现分语言、分来源、分时间评估。
- 生成机器可读和人工可读评估报告。
- 导出并在 ONNX Runtime adapter 中验证。

完成条件：训练、导出、加载和评估链路可重复；不要求此阶段达到正式发布门槛。

### Phase 3：文本编码模型

Status: pending

本阶段因 Approved Training Corpus 尚不存在而被有意暂缓，不是已经完成，也不能用 Phase 2 合成 ONNX 或 Phase 4A 的模型接口替代。正式模型选择、训练、量化、发布指标和最低硬件验证仍全部属于本阶段及其发布门禁。

- 建立候选模型许可证和来源清单。
- 在固定 corpus snapshot 上基准测试。
- 评估冻结向量和必要时的微调方案。
- 完成量化、ONNX 导出和最低硬件测试。
- 选择满足质量、资源和许可门槛的 Unified Model Release。

完成条件：全部发布指标达标，模型来源证据完整。

### Phase 4：Detection Kernel 与风险融合

Status: in_progress

#### Phase 4A：模型无关 Detection Kernel

Status: complete

- 已实现稳定 `LocalInference` seam、明确推理预算、生产可用的 `UnavailableModelAdapter` 和仅位于测试目录的 fake adapter。
- 已实现不可变 `RuleAssessment`、确定性去重、强证据风险下限、有限模型加减分和集中式 0–100 风险映射。
- 已实现 `DetectionKernel.detect(...)` 作为完整检测结果的唯一编排入口，覆盖拒判、模型不可用、超时、错误、adapter 异常、非法输出和主动纯规则模式。
- 已实现只含四个允许字段的插件投影，以及不含邮件原文、完整地址、URL query、Token、密码和私有路径的内存私密证据投影。
- 已实现 Model Assessment schema/概率/状态/模型版本/Feature Schema/耗时/error code 校验；非法输出安全降级，不阻断规则结果。
- Phase 4A 首次引入 `DETECTION_OUTCOME_SCHEMA_VERSION = "2.0"`；Phase 6B 为私密样本校准摘要把当前版本提升为 `3.0`，`FEATURE_SCHEMA_VERSION = "2.0"` 与 `CORPUS_SCHEMA_VERSION = "3.0"` 保持不变。
- Phase 4A 没有生产模型，因此只通过测试 fake 模拟耗时、超时和异常；没有声称完成真实 3 秒推理验证。

#### Phase 4A.1：本地规则评估与端到端 Local Detection Service

Status: complete

- 已实现只消费完整兼容 Feature Schema 2.0 `FeatureVector` 的 `LocalRuleEvaluator`，在公开 seam 拒绝 schema 不兼容、字段缺失/未知/重复、非有限值、布尔数值和非法负数。
- 已实现认证、发件人/Reply-To、链接结构、附件元数据和组合意图的最小本地规则策略；分数、严重度、强证据、证据码和通用动作集中定义且顺序稳定。
- 危险附件扩展、IP 字面量链接与凭据组合、多项认证失败与仿冒组合形成强证据；单一普通意图词、认证缺失、发件人不一致和国际化域名单独不形成强证据。
- 已实现 `LocalDetectionService.detect(MailObservation, *, local_event_id, observed_now) -> DetectionOutcome`，内部固定执行 observation 验证、Feature Pipeline、本地规则评估和 Detection Kernel。
- Local Inference adapter 只能在 Service 构造时注入，默认 `UnavailableModelAdapter`；模型不可用或 adapter 异常仍返回完整规则结果与稳定降级状态。
- 已验证规则和最终结果不包含主题、正文、地址、完整 URL/query、附件名、Token、密码或私有路径；RuleEvaluator 只处理 Feature Pipeline 的有界输出。
- Phase 4A.1 是 Phase 5 的安全前置条件：未来插件只提交邮件观察事实，不得提交规则、分数、强证据、模型结果、执行状态、动作、留存、角色/权限或事件所有权结论。
- 本阶段没有实现 Native Messaging、浏览器插件、数据库、UI、模型训练或生产模型 adapter。

#### Phase 4B：正式 ONNX Runtime 与 Unified Model Release 接入

Status: pending

- 依赖 Phase 3 产生满足许可、质量、资源和发布门禁的正式 Unified Model Release。
- 实现生产 ONNX Runtime CPU adapter、模型加载、真实执行超时/资源控制和兼容性验证。
- 在最低支持硬件上验证真实模型推理低于 3 秒，并完成损坏、不兼容和资源不足降级验证。
- 不得把 Phase 2 合成 ONNX、测试 fake 或 `UnavailableModelAdapter` 解释为正式模型接入。

Phase 4 总完成条件：Phase 4A、Phase 4A.1 与 Phase 4B 均完成，测试通过本地检测 interface 覆盖完整风险结果，并取得正式模型与硬件验证证据。Phase 4A.1 完成后 Phase 4 总状态保持 `in_progress`。

Phase 5–7 的系统框架可依赖稳定的 Phase 4A interface 继续开发，不必伪造 Phase 3 已完成；正式 Endpoint Release 仍受 Phase 3、Phase 4B 和全部发布门禁约束。Confirmed Example Library 的持久化和相似样本有限校准仍属于 Phase 6，不在 Phase 4A 中实现。

### Phase 5：Native Messaging 与新浏览器插件

Status: in_progress

#### Phase 5A：Native Messaging 协议、本地 Host 与独立 MV3 插件

Status: complete

- 在 `endpoint_agent/extension/` 建立独立 MV3 插件。
- 实现 chinaccs 专用 DOM adapter，但不修改现有 `extension/`。
- 实现固定开发扩展 origin allowlist、严格 Native Messaging framing/payload protocol 和稳定错误码。
- 删除服务器地址、Token、HTTP 轮询和外部连接。
- Host 自行执行 `MailObservation → LocalDetectionService → DetectionOutcome → minimal_plugin_projection`。
- 实现 Agent/Host/协议/超限/正文未识别、拒判和降级展示。

完成条件：Python 协议/Host/插件静态测试、完整 Endpoint Agent 回归、JavaScript 语法检查和离线 Wheel 构建通过。

#### Phase 5B：Host 可执行文件、浏览器注册和真实 Edge/Chrome 验收

Status: in_progress

- 已提交公开 manifest key 并固定开发验收扩展 ID `hchaloelgnennaojaiikeebhajcoccih`；该身份不等于未来商店或企业正式发布身份，仓库不保存私钥。
- 已提供固定开发依赖的 PyInstaller one-file console Host 构建脚本，输出到被忽略的 `dist/native-host/` 并生成 SHA-256 build metadata；PyInstaller 不进入生产 Wheel。
- 已提供实际绝对 Host 路径的 Chrome/Edge Native Host manifests 生成，以及当前用户 HKCU 安装、状态、重复安装和自有项卸载脚本；安装与卸载均拒绝覆盖或删除非 ShieldDome 自有的同名注册。
- 已通过源码 Host 子进程 ping、最小检测、连续请求隔离、异常帧、stdout 隐私和零 TCP/UDP socket 自动化验证；打包 Host 的同一契约因当前环境没有 PyInstaller/`.exe` 而明确跳过。
- 已通过隔离 ShieldDome 测试注册表路径的 Chrome/Edge manifest、中文/空格路径、幂等安装/卸载和拒绝删除非自有注册项测试。
- 仍需在具备批准的离线 PyInstaller 环境构建真实 `.exe`，再执行默认 Chrome/Edge 注册并分别完成真实 chinaccs 在线/断网/Network 面板验收；在这些证据齐全前本阶段保持 `in_progress`。

Phase 5 总完成条件：Phase 5A 与 Phase 5B 均完成，真实浏览器邮件检测全程无网络请求，插件只显示最小结果。Phase 5A 完成后 Phase 5 总状态保持 `in_progress`。

### Phase 6：加密存储、样本库和留存

Status: complete

#### Phase 6A：加密证据存储、15 天留存、全部删除

Status: complete

- 已实现严格、不可变、版本化的 Endpoint Evidence Record，只投影事件 ID、UTC 时间、风险等级、检测状态、通用动作、来源类型、规则代码摘要、拒判、模型执行、降级和稳定错误码。
- 已实现 `%LOCALAPPDATA%\ShieldDome\EndpointAgent` 当前用户目录边界；显式拒绝系统共享目录和位于当前用户 `LOCALAPPDATA` 之外的数据目录。
- 已使用 Windows `CryptProtectData`/`CryptUnprotectData` 当前用户范围保护随机 256 位数据密钥；固定 `CRYPTPROTECT_UI_FORBIDDEN` 且不设置 `CRYPTPROTECT_LOCAL_MACHINE`，并用当前用户 SID 摘要拒绝跨用户作用域保护包。
- 已使用成熟的 `cryptography==49.0.0` `AESGCM` 为每条记录生成独立 96 位 nonce，以 AES-256-GCM 加密规范 JSON，并把 SQLite 明文索引字段绑定为 associated data。
- SQLite 只保存事件 ID、检测/过期 UTC 索引、schema、nonce、密文和认证标签；不保存主题、正文、完整地址、URL、附件名/内容或原始邮件。
- 已实现按事件读取、稳定分页、未知 schema 拒绝、篡改/错误密钥安全失败、精确 `expires_at <= now` 的 15 天清理和 Native Host 每次检测时的自动清理触发。
- 已实现 SQLite `secure_delete`、WAL checkpoint/truncate、VACUUM、已知 WAL/SHM/journal/temp 文件覆写删除，以及删除 DPAPI 保护密钥的密码学销毁；全部删除幂等。
- Native Host 在检测完成后尽力保存证据；存储初始化、清理、投影或写入失败都不改变四字段检测结果，也不向协议 stdout 输出异常文本或存储材料。
- Windows 当前用户真实 DPAPI、用户作用域、AES-GCM 随机化/篡改、数据库原文搜索、15 天边界、全部删除、连续事件隔离、离线约束和完整 Endpoint Agent 回归均已有自动化测试。
- 生产运行依赖固定为 `cryptography==49.0.0`；构建与部署必须从批准的离线缓存提供匹配的 Windows wheel 及其传递依赖，Agent 运行时不下载依赖。Phase 7B.1 另固定 `PySide6-Essentials==6.8.3` 与 `tzdata==2026.3`，后者为 Windows 的真实命名时区和本地日历边界提供 IANA 数据库。

#### Phase 6B：Confirmed Example Library 与有限校准

Status: complete

- 已实现只允许明确“确认正常/确认钓鱼”动作写入的每用户 Confirmed Example Library；检测、低风险邮件、邮箱和证据记录不会自动入库。
- 已实现严格不可变样本契约，只含脱敏 FeatureVector、Feature/Example schema、人工标签、固定来源枚举、带时区确认时间和本地密钥 HMAC-SHA-256 fingerprint；没有主题、正文、地址、完整 URL、附件内容/名称、source message ID 或 `.eml` 字段。
- 已在 `%LOCALAPPDATA%\ShieldDome\EndpointAgent\examples` 使用独立当前用户 DPAPI 保护的随机 256 位密钥、逐记录 AES-256-GCM 和认证索引；跨用户作用域、损坏密钥、密文/标签/索引篡改均安全失败。
- 已实现 256 个唯一 fingerprint 容量、最多 50 条分页、标签筛选、同标签去重、冲突标签保留、删除单条、清空数据库/sidecar/独立密钥，以及最多 512 个加密行的校准扫描上限。
- 已实现一条无冲突精确样本可校准；近似匹配要求相似度至少 `0.94`、至少三条不同 fingerprint 的一致标签且不存在冲突。低相似度、样本不足和任何冲突均返回零调整。
- 正常/钓鱼样本调整分别固定为 `-8/+18`；正常样本不能降低认证、危险 URL、黑名单/策略、危险附件等强规则下限，样本证据不能单独把结果推为 `critical`。
- 校准异常不阻断规则/模型检测；Native Host 只组合默认本地校准器，没有新增确认协议，插件仍只显示四字段结果且不含样本、相似度、规则或内部原因。
- 已验证无网络连接、无监听端口、无上传、无模型训练或模型权重修改。

#### Phase 6C：脱敏诊断包导出

Status: complete

- 已实现 `DiagnosticExporter.export(output_path, confirmed=True, overwrite=False)`；调用方必须明确选择输出路径并确认，默认拒绝覆盖，覆盖需要第二个显式参数。
- 已实现固定 `diagnostics.json`、`compatibility.json`、`manifest.json` 白名单、相对单段归档名、逐 payload 大小/SHA-256 manifest 和归档完成后复核。
- 已实现最近 15 天日期/风险/来源、规则模式、模型可用/拒判/降级、稳定错误码、Evidence Store/Confirmed Example Library 健康，以及样本/标签/冲突的聚合统计。
- 已限制 4,096 条证据、512 行样本、32 种来源、32 种错误码、单文件 256 KiB 和归档 1 MiB；超限安全失败且不截断成误导性结果。
- 已验证邮件原文、地址、URL/query、附件、FeatureVector、fingerprint、数据库/sidecar、密钥、nonce、认证标签、密文、用户/主机/路径/环境、模型原因、规则权重、异常文本和堆栈均不进入归档。
- 已使用当前用户目录内的临时构建目录并在成功/失败后清理；安全发布失败不破坏已有诊断包、证据库、样本库或正常检测。
- 诊断导出不定时运行、不自动上传、不进入训练/样本库、不连接网络，也不接入 Native Messaging 或浏览器插件。

Phase 6 总完成条件已满足：Phase 6A、Phase 6B 与 Phase 6C 全部完成，原文不落盘，越权 Windows 用户不能读取本地记录或聚合数据，清理、有限校准和诊断导出隐私测试均已通过。

### Phase 7：托盘、个人控制台和数据看板

Status: complete

#### Phase 7A：个人控制台应用服务与数据 ViewModel

Status: complete

- 已实现与具体 GUI 框架无关的深模块 `PersonalConsoleService`；UI 调用方无需且不得直接访问 SQLite、DPAPI 或 AES-GCM。
- 已实现不可变、版本化的 Dashboard、事件、样本分页和稳定操作结果 ViewModel，字段白名单不包含邮件原文、地址、URL、附件名、FeatureVector、fingerprint、密钥或密文。
- 已实现严格按注入本地时区日历边界计算的今日数量和最近 15 天补零趋势，以及风险、来源、模型拒判、模型故障和纯规则降级统计。
- 已实现最近 15 天事件的有界分页与脱敏详情，以及 Confirmed Example Library 的有界分页、标签筛选和不暴露 fingerprint 的临时不透明删除 ID。
- 已实现明确确认正常/钓鱼、删除单条/清空样本、明确确认且由用户选择路径的诊断导出，以及协调证据库、样本库、两套密钥、SQLite sidecar 和当前用户诊断临时目录的全部删除命令。
- 所有查询使用当前 Windows 用户的加密存储；空存储读取不创建数据库或密钥，跨用户或损坏记录返回受控健康状态且不泄露异常文本。
- 查询上限固定为 15 天、最多 4,096 条证据、事件页最多 50 条、最多 512 行样本、样本页最多 50 条且 offset 最多 256；命令只返回稳定状态码、受控 ViewModel 和安全计数。
- 生产实现不包含网络客户端、HTTP、WebSocket、RPC、监听端口、浏览器控制台、PySide6、托盘、图表、`.eml` 解析、自动确认或自动上传。

#### Phase 7B：Windows 托盘和桌面控制台 UI

Status: complete

##### Phase 7B.1：Windows 托盘与只读个人安全控制台

Status: complete

- 已使用固定 `PySide6-Essentials==6.8.3` 与 `tzdata==2026.3` 建立独立桌面入口、主窗口、页面导航、系统托盘、Presenter/UI adapter、稳定错误边界、真实命名时区支持和可测试生命周期；核心包在没有 PySide6 时仍可导入。
- UI 只调用 Phase 7A `PersonalConsoleService`，不直接导入 SQLite、EvidenceStore、ExampleStore、DPAPI、AES-GCM、密钥、密文或任何写命令。
- 已实现今日检测、15 天补零趋势、风险/来源分布、模型拒判/故障/纯规则降级计数、最近事件分页和脱敏详情；空库、损坏存储和降级状态使用固定安全文案。
- 已实现托盘本地状态、打开、隐藏和显式退出；普通窗口关闭只隐藏到托盘。
- 已使用 Qt Widgets 与 `QPainter` 自绘轻量图表，不引入 Qt Charts、浏览器页面、Electron、本地 HTTP、网络客户端或监听端口。
- 已在真实 PySide6 Windows 环境启动并检查 1366x768 与最低 1024x720 截图；表格、图表、按钮和状态区域尺寸稳定，无重叠或截断。

##### Phase 7B.2A：当前用户启动集成与安全本地数据管理界面

Status: complete

- 已实现 HKCU 当前用户启动管理，只接受绝对路径、冻结且名为 `ShieldDomeEndpoint.exe` 的打包入口；开发环境明确显示安装版提供开机启动。
- 安装、查询、重复安装和卸载幂等；同名非自有值不会被覆盖或删除；不使用 HKLM、计划任务、管理员权限、shell 或 PowerShell。
- 已增加脱敏样本分页/标签筛选/冲突状态/单条删除/确认清空、用户选路且覆盖二次确认的诊断导出，以及固定文本双重确认的全部本地数据删除。
- 所有写操作只通过 `PersonalConsoleService`；不添加网络、监听、上传、预览、自动打开或敏感路径记忆。

##### Phase 7B.2B：误报/漏报确认安全设计

Status: complete

- 独立 Pending Confirmation Context 只保存可信 Feature Pipeline 生成并通过隐私扫描的向量，使用当前用户 DPAPI 独立密钥、逐记录 AES-256-GCM 和最长 15 天留存。
- 桌面仅提交事件 ID、标签和明确确认；样本成功写入后删除上下文，失败时保留，且不修改 Evidence Record 或 Native Messaging 协议。

#### Phase 7C：安全 `.eml` 拖入检测

Status: complete

##### Phase 7C.1：安全、显式、本地 `.eml` 读取与检测内核

Status: complete

- 用户明确确认后，只读处理一个普通本地 `.eml`；拒绝网络/设备/ADS/重解析路径，并在读取前后复核文件身份。
- 标准库 MIME 解析、集中资源上限、惰性 HTML 纯文本化、附件元数据最小化以及既有检测/加密证据/待确认上下文编排全部隐藏在两个深模块后。

##### Phase 7C.2：安全 `.eml` 拖入 UI

Status: complete

- 已通过 Phase 7C.1 `LocalMailIntakeService` interface 接入一个 Qt 本地文件 URL 拖入和受 `.eml` 筛选的文件选择；UI 不导入 MIME、Feature Pipeline、存储或加密实现。
- 拖入或选择只产生临时选择，用户每次都必须确认本地处理、不上传、不打开/预览/解压/执行附件及只保存加密结构化结果；取消不读取文件。
- 已使用单个受控 `QThread` 在非 UI 线程执行检测，同时最多一个任务；检测期间禁用拖入/选择，窗口退出等待任务自然完成或丢弃 UI 回调，不强制终止解析。
- 成功只显示风险等级、检测状态、通用建议和本地事件 ID，并刷新 Dashboard 与最近事件；固定错误文案不包含路径、文件名、异常或内部实现。
- 已在真实 Windows Qt 下检查 1366x768 初始页和 1024x720 待确认、运行、完成、文件过大状态；不复用浏览器作为控制台，也未扩展目录扫描、邮件客户端 adapter、跨用户、管理员或中心后台功能。

Phase 7 总完成条件已满足：Phase 7A、Phase 7B 与 Phase 7C 均完成；桌面界面在最低分辨率下无重叠，本地 `.eml` 检测不阻塞 Qt 主线程，数据全部来自当前用户本地加密记录。

### Phase 8：Endpoint Release

Status: pending

- 生成 release manifest 和 SHA-256。
- 兼容性检查、规则模式降级和上一版本回滚。
- Windows 安装、升级、卸载和 ACL。
- 完整 Agent、模型、策略和插件整包发布。

完成条件：干净 Windows 环境可安装、运行、升级、回滚和卸载，不需要 Python 开发环境。

### Phase 9：桌面邮件扩展

Status: pending

- 通用 `.eml` 文件和 Windows 右键检测。
- 根据实际需求和官方支持情况增加邮件客户端 adapter。
- 隔离附件检查单独立项，不属于本阶段默认范围。

完成条件：新增 adapter 不修改 Detection Kernel interface。

## 12. 测试清单

### 数据与模型

- 许可和来源缺失样本拒绝进入 corpus。
- 精确、规范化和近重复不跨 split。
- 同一活动模板不跨训练和测试。
- 特征 schema 不兼容时拒绝模型。
- 训练与推理特征逐项一致。
- 概率校准、拒判和指标计算正确。
- 中文、英文、混合和其他语言降级测试。

### 检测

- 强规则不会被模型或样本库抵消。
- 模型单独不能产生 critical。
- uncertain 不产生强模型证据。
- 模型失败、超时、损坏和 OOM 降级。
- 附件只分析元数据，不发生文件访问。
- 插件结果不包含内部 reason、规则权重和模型信息。

### 隔离与隐私

- 不产生网络连接。
- 不监听本地端口。
- 用户 A 无法读取用户 B 数据。
- 原文、Token 和敏感信息不进入日志、数据库和诊断包。
- 15 天清理、全部删除和卸载删除正确。
- Native Messaging 拒绝未知扩展和异常载荷。

### 发布与性能

- 模型哈希、大小和 compatibility 校验。
- 普通用户不能替换模型。
- 上一版本回滚。
- 4 核、8 GB、无独显环境性能。
- 长邮件、大量链接和异常输入资源限制。
- Agent 故障不影响邮箱正常使用。

## 13. 明确禁止事项

- 不修改现有 ShieldDome 业务代码来迁就 Endpoint Agent。
- 不复制真实生产密钥、数据库、邮件和模型到 Git。
- 不引入外部模型或云端推理作为隐式降级。
- 不启动本地 HTTP server。
- 不允许终端训练或自动学习。
- 不自动下载、打开、解压、预览或执行附件。
- 不读取邮件客户端私有数据库。
- 不截获邮件协议或用户凭据。
- 不把插件最小结果等同于删除内部证据。
- 不因模型指标优秀而绕过确定性规则。
- 不在 Phase 4A 的稳定 Detection Kernel interface 完成前优先制作复杂 UI。

## 14. 下一步

Phase 3 因缺少真实、许可明确、人工审核且完成去重/泄漏隔离的 Approved Training Corpus 而有意暂缓，继续保持 `pending`；不得用 Phase 2 合成 fixture 选择正式文本编码模型。Phase 4A 已完成，Phase 4 总状态为 `in_progress`，Phase 4B 继续等待 Phase 3 的正式模型。

Phase 5A 已基于 Phase 4A.1 的可信本地检测 seam 完成严格 Native Messaging protocol、可测试 Host 和独立 chinaccs MV3 插件基础链路。Phase 5B 已完成稳定开发身份、可复现构建配置、注册生命周期脚本和源码 Host 自动化准备，但当前环境缺少离线 PyInstaller，尚无 `.exe`、默认 Chrome/Edge 注册或真实 chinaccs 验收，因此 Phase 5B 与 Phase 5 均保持 `in_progress`。下一步是在批准的离线构建环境产生 Host 后按 `docs/BROWSER_ACCEPTANCE.md` 完成两种浏览器验收。正式 Endpoint Release 仍被 Phase 3、Phase 4B 和发布门禁阻塞。

Phase 6 与 Phase 7 已完成。Phase 7C.1 和 Phase 7C.2 均保持 `complete`；Phase 8 保持 `pending`，桌面邮件客户端 adapter 仍属于 Phase 9。

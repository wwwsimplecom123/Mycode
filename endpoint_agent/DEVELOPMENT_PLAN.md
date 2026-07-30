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
- ONNX Runtime adapter 和 deterministic fake adapter 共同证明 Local Inference seam 是真实的。
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

Status: pending

- 训练结构化基线模型。
- 实现概率校准和不确定拒判。
- 实现分语言、分来源、分时间评估。
- 生成机器可读和人工可读评估报告。
- 导出并在 ONNX Runtime adapter 中验证。

完成条件：训练、导出、加载和评估链路可重复；不要求此阶段达到正式发布门槛。

### Phase 3：文本编码模型

Status: pending

- 建立候选模型许可证和来源清单。
- 在固定 corpus snapshot 上基准测试。
- 评估冻结向量和必要时的微调方案。
- 完成量化、ONNX 导出和最低硬件测试。
- 选择满足质量、资源和许可门槛的 Unified Model Release。

完成条件：全部发布指标达标，模型来源证据完整。

### Phase 4：Detection Kernel 与风险融合

Status: pending

- 实现 Local Inference seam 及 ONNX/fake adapters。
- 实现规则、Model Assessment 和相似样本融合。
- 实现拒判、超时、损坏和规则模式降级。
- 实现最小插件投影与私密证据投影。

完成条件：测试只通过 Detection Kernel interface 覆盖完整风险结果。

### Phase 5：Native Messaging 与新浏览器插件

Status: pending

- 在 `endpoint_agent/extension/` 建立独立 MV3 插件。
- 移植必要 DOM adapters，但不修改现有 `extension/`。
- 实现固定扩展 ID allowlist 和 Native Messaging protocol。
- 删除服务器地址、Token、HTTP 轮询和外部连接。
- 实现 Agent 未启动、超时、拒判和降级展示。

完成条件：浏览器邮件检测全程无网络请求，插件只显示最小结果。

### Phase 6：加密存储、样本库和留存

Status: pending

- DPAPI 保护数据密钥。
- AES-GCM 保存 Endpoint Evidence Record。
- 实现 15 天清理、全部删除和卸载策略。
- 实现 Confirmed Example Library 和有限校准。
- 实现脱敏诊断包导出。

完成条件：原文不落盘，越权 Windows 用户不能读取本地记录，清理测试通过。

### Phase 7：托盘、个人控制台和数据看板

Status: pending

- 托盘状态与开机启动。
- EML 拖入检测。
- 今日数量、15 天趋势、风险分布、来源、拒判和降级统计。
- 15 天记录、反馈、样本库、诊断导出和数据删除。
- 不出现多用户或中心管理功能。

完成条件：最低分辨率下无重叠，低配置电脑交互流畅，数据全部来自本地记录。

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
- 不在 Phase 0-4 完成前优先制作复杂 UI。

## 14. 下一步

下一次开发从 **Phase 2：基线模型与评估** 开始。一次只完成一个阶段；阶段完成后运行相关测试、更新本文件的 Status，并检查 `git diff` 确保现有目录没有被修改。

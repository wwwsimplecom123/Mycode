# ShieldDome Endpoint Agent 使用说明

## 1. 当前可用范围

当前仓库已完成 Phase 7B、Phase 7C.1 和 Phase 7C.2，因此 Phase 7C 与 Phase 7 均为 `complete`。Phase 3、Phase 4B 与 Phase 5B 的既有状态不因本阶段改变；Phase 8 保持 `pending`，桌面邮件客户端 adapter 仍属于 Phase 9。当前提供：

- 可离线构建、导入的独立 Python 包 `shielddome_endpoint`；
- Phase 0 的不可变领域类型和版本字段；
- 训练与 Endpoint 共用的 `FeaturePipeline.transform`；
- Approved Training Corpus 的 `CorpusGovernance.prepare`；
- 不可变的来源/时间 test 留出 `CorpusSplitPolicy`；
- 只含 digest 和稳定标识的训练溯源 manifest；
- `CorpusCandidate`、`FeatureVector` 和 corpus manifest 的 `PrivacyScanner`；
- 离线能力、隐私边界、数据产物忽略和 Wheel 构建测试；
- 独立训练侧固定 140 维 Feature Assembler；
- 合成数据 Logistic Regression、validation-only 校准候选质量门禁和不确定拒判；
- test-only 分语言、来源和时间评估及 JSON/Markdown 报告；
- 标准 ONNX 导出与 ONNX Runtime CPU 概率一致性验证。
- 生产包中的稳定 `LocalInference` seam、明确推理预算和无副作用 `UnavailableModelAdapter`；
- 不可变结构化 `RuleAssessment`、规则去重、强证据风险下限和有限模型调整；
- `DetectionKernel.detect(...) -> DetectionOutcome` 唯一编排入口；
- model success/uncertain/unavailable/timeout/error/invalid-output 和主动 rules-only 状态；
- 精确四字段插件投影、内存私密证据投影和 DetectionOutcome 隐私扫描。
- Feature Schema 2.0 完整边界验证、集中式本地规则策略和稳定不可变 `RuleAssessment` tuple；
- 从 `MailObservation` 到 `DetectionOutcome` 的固定内存链路 `LocalDetectionService.detect(...)`。
- `SafeEmlReader.read_explicit(...)` 与 `LocalMailIntakeService.detect_file(...)`：只处理用户明确确认的单个普通本地 `.eml`，使用 25 MiB 文件上限、64 KiB Header 总上限、8 KiB 单行 Header、256 Part、16 层、64 附件、100 收件人、32 KiB 正文和 256 URL 上限。
- HTML 仅由标准库做有界纯文本化；附件不解码、不解压、不打开、不预览、不写盘，嵌套邮件附件不递归；认证结果仅作为 Header 声明观察值。
- “本地检测”桌面页只接受一个 Qt 本地 `.eml` URL，或通过只显示 `.eml` 的文件选择器临时选择一个文件；拖入/选择不会自动检测，也不长期显示或记忆绝对路径。
- 每次检测都显示本地处理确认，明确不上传、不打开/预览/解压/执行附件及只保存加密结构化结果；确认后由单个受控 Qt worker 调用 `LocalMailIntakeService.detect_file(path, confirmed_by_user=True)`，不阻塞 UI 且同时最多处理一个文件。
- 桌面结果只显示风险等级、检测状态、通用建议和本地事件 ID；完成后刷新 Dashboard 和最近事件，固定错误文案不回显路径、文件名、异常或内部实现。
- 4 字节 little-endian + UTF-8 JSON Native Messaging 协议、严格 payload 白名单、集中资源上限和稳定错误码；
- `run_native_host(input_stream, output_stream, handler)` BytesIO seam、固定开发 extension origin 与四字段最小结果；
- `endpoint_agent/extension/` 下只匹配 `https://webmail.chinaccs.cn/*`、不含网络客户端、服务器地址或插件 Token 的独立 MV3 插件。
- 由公开 manifest key 固定的开发扩展 ID `hchaloelgnennaojaiikeebhajcoccih`，不提交私钥；
- 开发期 PyInstaller Host 构建脚本、SHA-256 build metadata、Chrome/Edge 当前用户 manifest/注册/检查/卸载脚本；
- 源码 Host 真实子进程协议、隐私、连续请求隔离和零 TCP/UDP socket 验证，以及隔离测试注册表路径下的浏览器注册生命周期测试。
- 严格 Endpoint Evidence Record、当前用户 `%LOCALAPPDATA%` 数据目录、DPAPI 保护的随机 256 位数据密钥；
- 使用 `cryptography==49.0.0` AESGCM 的逐记录 AES-256-GCM、最小 SQLite 索引、按事件读取和稳定分页；
- 精确 15 天清理、Native Host 检测时自动触发过期清理、SQLite/WAL 处理和全部本地证据数据删除；
- 密文/标签/密钥/schema 损坏安全失败、数据库原文缺失和存储失败不阻断检测结果。
- 只允许用户明确“确认正常/确认钓鱼”写入的 Confirmed Example 契约，禁止检测或低风险结果自动入库；
- 当前 Windows 用户独立 DPAPI 密钥、AES-256-GCM 记录加密和本地密钥 HMAC-SHA-256 fingerprint；
- 256 个唯一 fingerprint 容量上限、50 条分页上限、标签筛选、去重、冲突保留、单条删除和清空；
- 精确重复单样本与至少 3 条、相似度至少 0.94 的一致近似样本校准，冲突/低相似度/证据不足均拒绝；
- 正常样本最多减 8 分且不得突破强规则风险下限，钓鱼样本最多加 18 分且不能单独产生 `critical`；校准失败保留规则结果。
- 必须由调用方选择输出路径并传入 `confirmed=True` 的一次性脱敏诊断包；默认拒绝覆盖，覆盖要求额外 `overwrite=True`；
- 固定三文件 ZIP 白名单、15 天有界聚合、Evidence Store/Confirmed Example Library 受控健康状态、粗化系统兼容信息和逐 payload SHA-256 manifest；
- 诊断临时目录成功/失败清理、跨用户作用域拒绝、内容隐私扫描、数量/大小上限、无网络和检测失败隔离。
- 不依赖 GUI 框架的 `PersonalConsoleService` 和不可变、版本化的控制台 ViewModel；
- 当前用户本地时区今日统计、15 天补零趋势、风险/来源/模型拒判/故障/纯规则降级统计，以及有界事件和样本查询；
- 只经服务执行的明确样本确认、样本删除/清空、用户选路诊断导出和协调全部本地数据删除命令。

生产包 `shielddome_endpoint` 负责 Phase 0–1 契约/特征/Corpus 治理、Phase 4A/4A.1 本地检测链路、Phase 5A Native Messaging protocol/Host seam、Phase 6 的加密证据/明确确认样本库/有限校准/一次性脱敏诊断导出，以及 Phase 7 的个人控制台、托盘和安全 `.eml` 桌面交互。Phase 2 能力和 PyInstaller 都只存在于开发侧，不会进入生产 Wheel。当前不会加载生产模型；插件只从已打开的 chinaccs 邮件详情页读取专用 DOM 事实，不能触发诊断导出或获得包内容/路径。当前环境没有可离线使用的 PyInstaller，因此尚未生成 Host `.exe`，没有写入默认 Chrome/Edge 注册，也没有完成真实浏览器验收。

## 2. 环境要求

- Windows 10/11 64 位；
- Python 3.12；
- Git，可执行 `git check-ignore`；
- 在仓库根目录 `C:\Users\huohuo\Desktop\project1\ShieldDome` 执行命令。

生产 Wheel 的固定第三方运行时依赖是 `cryptography==49.0.0`、`PySide6-Essentials==6.8.3` 与 `tzdata==2026.3`。`cryptography` 用于 Phase 6A/6B AES-256-GCM，PySide6 Essentials 用于 Phase 7B.1 桌面界面，`tzdata` 在 Windows 上提供 `ZoneInfo` 验证真实命名时区和本地日历边界所需的 IANA 数据库。构建和部署必须从批准的离线缓存提供匹配的 Windows wheel 及其传递依赖；`pip wheel --no-index --no-deps` 只构建 ShieldDome Wheel，不会下载或封装这些依赖，Agent 运行时也不得下载。Phase 2 训练环境使用 `requirements-training.txt` 的固定依赖，并且只能安装到被忽略的 `.venv-training/`；详见 `docs/TRAINING.md`。Host `.exe` 构建另使用 `requirements-packaging.txt` 中固定的 PyInstaller 开发依赖，必须从批准的离线缓存提供，且不得写入 `pyproject.toml`。Phase 4A 不下载模型、数据集或 NLTK 资源，也不引入 ONNX Runtime 生产依赖。

## 3. 目录概览

```text
endpoint_agent/
  AGENTS.md                         Endpoint Agent 开发约束
  README.md                         产品定义与目标架构
  DEVELOPMENT_PLAN.md               分阶段开发基线
  pyproject.toml                    Python 3.12 与 PEP 517 构建配置
  _build_backend.py                 零外部依赖的本地 Wheel 构建后端
  .gitignore                        敏感数据、corpus 和构建产物忽略规则
  requirements-training.txt         固定的开发期训练依赖
  docs/
    USAGE.md                        本文档
    TRAINING.md                     Phase 2 训练、许可证和 ONNX 验证
    plans/                          分阶段实施计划
  src/shielddome_endpoint/
    __init__.py                     包版本与公开导出
    domain.py                       核心领域类型
    inference.py                    Local Inference seam、预算和输出校验
    risk_fusion.py                  确定性规则/模型风险融合
    detection_kernel.py             DetectionOutcome 唯一编排入口
    rule_evaluator.py               FeatureVector 验证与集中式本地规则
    local_detection.py              observation 到 outcome 的可信检测 seam
    native_protocol.py              Native Messaging framing 与集中资源上限
    native_payload.py               严格 request 白名单与 MailObservation 转换
    native_host.py                  origin 校验、Host handler 与 stdio 循环
    evidence_record.py              严格 Endpoint Evidence Record 契约与规范序列化
    key_protection.py               当前用户 SID/DPAPI 与随机数据密钥生命周期
    evidence_crypto.py              AES-256-GCM 逐记录加解密和认证失败处理
    evidence_store.py               每用户 SQLite、读取、分页、留存与全部删除
    confirmed_examples.py           严格确认样本契约与 keyed fingerprint
    example_store.py                每用户加密样本库与容量/查询上限
    example_calibration.py          精确/近似样本的保守校准
    diagnostics.py                  15 天受控聚合、稳定健康状态和固定诊断 schema
    diagnostic_export.py            明确确认、固定白名单 ZIP、manifest 与安全发布
    feature_pipeline.py             确定性特征转换
    corpus.py                       Corpus Governance 深模块
    privacy.py                      candidate/FeatureVector/manifest 隐私扫描
  tests/
    test_feature_pipeline.py        Feature Pipeline 公开行为
    test_corpus_governance.py       corpus 准入、去重和 split
    test_privacy.py                 隐私扫描
    test_inference.py               unavailable 和 Model Assessment 校验
    test_risk_fusion.py             规则/模型融合与强证据下限
    test_detection_kernel.py        Kernel、降级和投影边界
    test_offline_constraints.py     离线边界
    test_confirmed_examples.py      样本契约、字段白名单与 fingerprint
    test_example_store.py           用户隔离、加密、CRUD、去重与容量
    test_example_calibration.py     校准阈值、冲突与证据不足
    test_diagnostics.py             聚合、健康、上限、损坏和用户隔离
    test_diagnostic_export.py       确认/覆盖、白名单、隐私、manifest、清理和无网络
    test_repository_hygiene.py      Git 忽略规则
    test_native_protocol.py         framing、UTF-8/JSON 与资源边界
    test_native_payload.py          payload 白名单、注入拒绝与长度边界
    test_native_host.py             BytesIO Host、origin、投影与错误隔离
    test_key_protection.py          真实 DPAPI、用户作用域、目录和损坏密钥
    test_evidence_crypto.py         AES-GCM 随机化、往返和篡改拒绝
    test_evidence_store.py          SQLite 隐私、分页、15 天清理和全部删除
    test_extension_static.py        MV3 权限、源码离线和 chinaccs/UI 约束
  extension/                        独立 Phase 5A chinaccs MV3 插件
  native_host/                      开发期 manifest 与 Phase 5B 边界说明
    identity.json                   公开开发扩展 ID/origin 与 Host 名称
    build-host.ps1                  被忽略的一文件 Host 构建和 SHA-256 metadata
    install-host.ps1                当前用户 Chrome/Edge 注册
    check-host.ps1                  Host、manifest、origin 与注册自检
    uninstall-host.ps1              仅清理 ShieldDome 自有项
  packaging/native_host_entry.py    PyInstaller stdio Host 入口
  training/shielddome_training/     Phase 2 独立训练侧深模块
  training/run_synthetic_experiment.py  合成链路 CLI
  training_tests/                   Phase 2 unittest
```

## 4. Feature Pipeline

稳定入口：

```python
FeaturePipeline.transform(observation: MailObservation) -> FeatureVector
```

训练和 Endpoint 推理准备必须直接调用同一入口，不能各自实现第二套转换逻辑。

```python
from datetime import datetime, timezone

from shielddome_endpoint import FeaturePipeline, MailObservation


observation = MailObservation(
    source_kind="browser",
    source_message_id="synthetic-message-001",
    subject="紧急 Account notice",
    sender="security@example.test",
    reply_to="helpdesk@example.test",
    recipient_summary=("current-user",),
    sanitized_body_text="请通过正常公司渠道 verify this request.",
    authentication_observations=(
        ("spf", "pass"),
        ("dkim", "pass"),
        ("dmarc", "pass"),
    ),
    normalized_links=("https://portal.example.test/notice",),
    attachment_metadata=(("name", "notice.pdf"),),
    language_hint="mixed",
    observed_at=datetime(2026, 7, 30, tzinfo=timezone.utc),
)

vector = FeaturePipeline().transform(observation)
```

转换具有以下性质：

- 纯内存、确定性、无网络、无文件写入；
- 不依赖根目录 `shielddome/` 或 `phishingDP-main/`；
- 数值和类别特征名称、顺序固定；
- 覆盖主题/正文/发件人/Reply-To、认证、URL、附件元数据、语言和有限意图；
- 缺失字段写入稳定的 `missing_value_mask`；
- 文本使用 SHA-256 signed hashing，固定 64 维并执行 L2 规范化；
- Hashing 输入最多 8192 个规范化字符，维度不会随 corpus 增长；
- 主题/正文分析总输入最多 8192 字符，长度特征采用饱和计数；
- 每封观察最多处理 256 个 URL、256 条附件元数据和 64 条认证观察；
- 超限项按原 tuple 顺序确定性截断，不影响边界内结果；
- `text_input` 始终为 `None`，不保留原始正文或 Token；
- 附件只读取传入的名称等元数据，不打开或读取附件。

当前 `FEATURE_SCHEMA_VERSION` 为 `2.0`。本版本记录了上述截断和饱和语义；修改特征名称、顺序、含义、Hashing 维度、规范化或资源边界时，必须显式升级版本并同步训练、测试和 manifest。

## 5. Local Detection Service

Phase 5A Native Messaging Host 使用的唯一检测 seam：

```python
from datetime import datetime, timezone

from shielddome_endpoint import LocalDetectionService


outcome = LocalDetectionService().detect(
    observation,
    local_event_id="event-20260731-001",
    observed_now=datetime(2026, 7, 31, tzinfo=timezone.utc),
)
```

内部顺序固定为：

```text
MailObservation
→ FeaturePipeline.transform
→ LocalRuleEvaluator.evaluate
→ DetectionKernel.detect
→ DetectionOutcome
```

调用方不能传入 `RuleAssessment`、`score_contribution`、`strong_evidence`、`final_risk_score`、`risk_level`、`ModelAssessment`、`execution_state`、`generic_action`、retention deadline、用户角色/权限或本地事件 ID 的可信归属结论。Local Inference adapter 只能在 `LocalDetectionService` 构造时注入，默认是 `UnavailableModelAdapter`；因此没有正式模型时仍返回完整规则检测结果，并标记 `model_unavailable` / `model_not_configured`。Adapter 抛异常时返回同一规则结果并标记稳定模型错误，不回显异常内容。

`LocalRuleEvaluator` 只接受完整兼容 Feature Schema 2.0 的 `FeatureVector`，拒绝字段缺失、未知、重复、NaN、Infinity、布尔数值和负数。规则只读取 Feature Pipeline 已有的有界结构化字段，不重新读取正文、URL 集合、附件集合或认证集合，也不检查附件内容。

未来浏览器插件仅是 observation fact source。即使未来 payload 带有风险分数、规则、模型或权限字段，Phase 5 的 Native Messaging intake 也必须拒绝或忽略；Phase 4A.1 只建立和测试 Service interface，没有实现协议解析、host 或插件。

## 6. Detection Kernel

稳定入口：

```python
from datetime import datetime, timezone

from shielddome_endpoint import (
    DetectionKernel,
    GenericAction,
    InferenceContext,
    RuleAssessment,
    RuleCategory,
    RuleSeverity,
    UnavailableModelAdapter,
)


outcome = DetectionKernel(UnavailableModelAdapter()).detect(
    vector,
    (
        RuleAssessment(
            rule_id="dmarc_deterministic_failure",
            category=RuleCategory.AUTHENTICATION,
            severity=RuleSeverity.HIGH,
            score_contribution=45,
            strong_evidence=True,
            evidence_code="dmarc_failure",
            generic_action=GenericAction.CONTACT_SECURITY,
        ),
    ),
    local_event_id="event-20260730-001",
    detected_at=datetime(2026, 7, 30, tzinfo=timezone.utc),
    inference_context=InferenceContext(max_duration_ms=3_000),
)
```

调用方负责提供已经形成的 `FeatureVector`、结构化规则评估、本地事件 ID、带时区检测时间和 1–60,000 ms 的明确推理预算。Kernel 不解析邮件、不生成规则、不加载模型、不读写文件，也不访问数据库或网络。

`UnavailableModelAdapter` 返回 `unavailable`，不伪造 probability、confidence state、model version 或 Feature Schema。未注入 adapter 时状态为 `rules_only`；adapter 返回拒判、unavailable、timeout、error、非法输出或抛异常时，Kernel 都保留纯规则结果，并使用稳定执行状态与非敏感错误码说明降级。

风险融合固定为：

- 相同 rule ID 只计分一次，并按与输入顺序无关的保守顺序选择；
- strong low/medium/high/critical 分别建立 20/40/70/90 风险下限；
- confident phishing 最多增加 25 分，confident benign 最多减少 5 分且不能低于强规则下限；
- 已通过冲突门禁的正常/钓鱼样本分别固定调整 -8/+18 分，任何异常都按 0 分降级；
- 正常样本调整不得低于强规则下限；样本校准前低于 80 分时，不得仅靠钓鱼样本进入 `critical`；
- uncertain 和全部故障/规则模式不产生模型调整；无规则的 uncertain 仍给出 `verify_sender`，不投影为安全放行；
- 最终分数限制为 0–100，0–24/25–49/50–79/80–100 分别映射 low/medium/high/critical。

`minimal_plugin_projection` 的允许字段精确为 `local_event_id`、`risk_level`、`execution_state` 和 `generic_action`。`structured_private_evidence` 只包含稳定 evidence code/类别/状态、分数组成、执行/降级状态、样本调整/稳定状态/支持数和版本摘要；两者都不包含样本内容、相似度、fingerprint、内部规则原因、正文、完整地址、URL query、Token、密码或私有路径。

`MODEL_ASSESSMENT_SCHEMA_VERSION` 为 `1.0`，`DETECTION_OUTCOME_SCHEMA_VERSION` 为 `3.0`；Feature Schema 继续为 `2.0`，Corpus Schema 继续为 `3.0`。

## 7. Local Evidence Store

Phase 6A 的公开契约：

```python
from datetime import datetime, timezone

from shielddome_endpoint import EndpointEvidenceRecord, EvidenceStore


now = datetime.now(timezone.utc)
record = EndpointEvidenceRecord.from_detection_outcome(
    outcome,
    detected_at=now,
    source_kind="browser_native",
)
store = EvidenceStore()
store.put(record)

same_record = store.get(record.local_event_id)
latest_page = store.list_page(offset=0, limit=50)
deleted_expired = store.cleanup_expired(now=now)
deleted_all = store.delete_all()
```

生产默认目录固定为：

```text
%LOCALAPPDATA%\ShieldDome\EndpointAgent\
  keys\evidence.key
  data\evidence.sqlite3
```

`EvidenceStore()` 不接受来自 Native Messaging payload 的路径、密钥、nonce、事件所有权或留存结论。默认目录来自当前 Windows 用户的 `LOCALAPPDATA`；系统共享路径或位于当前用户 `LOCALAPPDATA` 外的显式路径会被拒绝。显式路径参数只用于当前用户目录内的测试/受控集成，不能用于跨用户数据库。

密钥和加密边界：

- 首次写入生成随机 32 字节数据密钥；只把 DPAPI 保护包写入 `keys\evidence.key`；
- DPAPI 固定当前用户范围和禁止 UI 标志，不使用 LocalMachine；保护包还绑定当前用户 SID 摘要；
- 已存在数据库但密钥缺失、保护包损坏、SID 作用域不匹配或解密失败时不会静默生成新密钥；
- 每条记录用 `cryptography` `AESGCM`、32 字节密钥、12 字节随机 nonce 和 16 字节认证标签独立加密；
- event ID、检测/过期 UTC 和 schema 作为 associated data 绑定，索引被修改也会导致认证失败；
- nonce、密文、标签、密钥和异常堆栈不会写到 Native Messaging stdout。

Endpoint Evidence Record 只允许：事件 ID、检测/过期时间、风险等级、检测状态、通用动作、来源类型、稳定规则代码、拒判布尔值、降级布尔值、模型执行状态、稳定错误码和 schema。未知字段、未来 schema、超长字段、非法 enum、naive 时间、重复规则代码和非 15 天留存窗口全部拒绝。邮件主题、正文、完整地址、URL、附件名/内容、原始 `.eml`、Token 和密码没有持久化字段。

SQLite 表只包含：

```text
local_event_id
detected_at_utc
expires_at_utc
schema_version
nonce
ciphertext
authentication_tag
```

读取顺序固定为 `detected_at_utc DESC, local_event_id DESC`，单页 1–100 条。任一页中一条记录认证、schema 或索引绑定失败时，整个读取安全失败，不返回部分结果。

留存边界是 `expires_at <= now`；`now` 和默认 clock 都可注入测试。Native Host 每次成功检测后先尽力触发过期清理，再尽力写入当前记录。清理使用 SQLite `secure_delete` 和 WAL checkpoint/truncate；全部删除还执行 VACUUM，关闭连接，覆写后删除自有 database/WAL/SHM/journal/temp 与 DPAPI 保护密钥。覆写不替代底层存储介质保证，删除保护密钥同时提供密码学销毁边界。

存储初始化、清理、投影或写入失败都不会阻断现有检测结果；Native Host 仍只返回 `local_event_id`、`risk_level`、`execution_state` 和 `generic_action`。

### 7.1 Confirmed Example Library

Phase 6B 只接受本地用户明确确认，不存在检测结果自动入库入口：

```python
from datetime import datetime, timezone

from shielddome_endpoint import (
    ExampleSource,
    ExampleStore,
    UserConfirmationAction,
)


examples = ExampleStore()
status = examples.confirm(
    vector,
    action=UserConfirmationAction.CONFIRM_PHISHING,
    source=ExampleSource.BROWSER_NATIVE,
    confirmed_at=datetime.now(timezone.utc),
)
page = examples.list_page(offset=0, limit=50)
```

样本目录与 Phase 6A 证据库分离：

```text
%LOCALAPPDATA%\ShieldDome\EndpointAgent\examples\
  keys\evidence.key
  data\confirmed_examples.sqlite3
```

样本记录仅含严格验证的脱敏 `FeatureVector`、Feature/Example schema、人工标签、来源枚举、UTC 确认时间和本地密钥 HMAC-SHA-256 fingerprint。主题、正文、地址、完整 URL、附件或 `.eml` 没有字段；未知字段、未知枚举、超长输入和非规范特征均被拒绝。fingerprint 由每用户的 32 字节数据密钥 HMAC 生成，不可用于跨用户关联。

存储限制为 256 个唯一 fingerprint，单页最多 50 条、offset 最大 256，校准最多扫描 512 行。同 fingerprint/同标签返回 `duplicate`；相反标签被保留为 `conflict`，不会静默覆盖，也不参与校准。`delete(fingerprint, label)` 删除单条，`clear()` 清空数据库/侧车文件并删除该样本库的 DPAPI 保护密钥。

有限校准仅有两条应用路径：精确 fingerprint 匹配可使用 1 条无冲突人工样本；近似匹配要求至少 3 个不同 fingerprint、相似度至少 0.94、标签一致且不存在冲突。相似度只在本地内存计算，不保存也不投影给插件。该功能不训练模型、不修改权重、不上传样本、不使用网络或监听端口。

### 7.2 一次性脱敏诊断包

Phase 6C 的公开入口只接受调用方明确选择的输出文件，不提供默认输出目的地：

```python
from pathlib import Path

from shielddome_endpoint import DiagnosticExporter


result = DiagnosticExporter().export(
    Path(r"C:\Users\current-user\Documents\shielddome-support.diag.zip"),
    confirmed=True,
)
```

如果目标已经存在，默认返回稳定错误 `diagnostic_output_exists`，不会覆盖。只有用户再次明确同意后才传入：

```python
result = DiagnosticExporter().export(
    Path(r"C:\Users\current-user\Documents\shielddome-support.diag.zip"),
    confirmed=True,
    overwrite=True,
)
```

上述路径仅是调用示例，不会写入诊断包。ZIP 内部文件名固定为：

```text
diagnostics.json
compatibility.json
manifest.json
```

`diagnostics.json` 只包含 Agent/Native Messaging/领域 schema 版本、最近 15 天按 UTC 日期/风险等级/来源的计数、检测/模型执行状态、规则模式、模型可用/拒判/降级数量、稳定错误码计数、Evidence Store/Confirmed Example Library 的 `healthy`/`empty`/`unavailable` 健康状态，以及样本总行数、唯一样本数、正常/钓鱼标签数和冲突数。损坏数据库、密钥作用域不匹配或部分读取失败只输出固定健康错误码，不输出异常类型、异常文本或堆栈，也不返回部分统计。

`compatibility.json` 只包含 Windows 主版本、Python 主/次版本、允许的 Python implementation、源码/冻结打包类别和 Agent 包版本；不读取或保存用户名、SID、主机名、绝对路径、环境变量或注册表导出。

`manifest.json` 固定列出 `diagnostics.json` 和 `compatibility.json` 的文件名、实际字节数和 SHA-256。归档白名单另行固定包含 manifest 本身，从而避免自引用哈希。写出前会重新打开 ZIP，验证条目白名单、路径安全、大小和全部 manifest 哈希。

固定资源边界：

- 回看窗口恰好 15 天；
- 最多读取 4,096 条 Endpoint Evidence Record；
- Confirmed Example Library 最多认证并聚合 512 行；
- 最多 32 种来源和 32 种稳定错误码；
- 每个 JSON 文件最多 256 KiB；
- 整个 ZIP 最多 1 MiB。

超过任一边界时整体安全失败，不截断为可能误导的诊断结果。构建目录位于当前用户 `%LOCALAPPDATA%\ShieldDome\EndpointAgent\diagnostic-temp`，成功和失败后都会删除本次临时子目录；安全覆盖通过同目录临时文件和原子替换保护已有包。导出只调用 Evidence Store 的分页读取和 Example Store 的 aggregate-only 查询，不复制 SQLite/WAL/SHM、密钥、nonce、认证标签或密文，不序列化 FeatureVector、fingerprint 或相似样本。

诊断包不会自动生成、定时生成、上传、发送、进入训练或进入 Confirmed Example Library。Native Messaging 和浏览器插件没有诊断命令，不能获得诊断内容或输出路径；该功能不添加 HTTP、WebSocket、TCP/UDP 连接或监听端口。

### 7.3 Personal Console Service

Phase 7A 提供 GUI 无关的 `PersonalConsoleService`。Phase 7B 的桌面界面只能通过此服务读取或执行操作，不能直接访问 SQLite、DPAPI、AES-GCM、密钥或密文：

```python
from shielddome_endpoint import PersonalConsoleService


console = PersonalConsoleService()
dashboard_result = console.get_dashboard()
events_result = console.list_recent_events(offset=0, limit=50)
examples_result = console.list_confirmed_examples(offset=0, limit=50)
```

Dashboard 使用注入的时钟和本地时区：存储时间保持 UTC，“今日”按当前 Windows 用户本地日历边界计算；趋势固定返回最近 15 个本地日期并对缺失日期补零。统计包含总检测量、风险等级、检测来源、模型拒判、模型故障和纯规则降级数量，以及受控 Evidence Store/Confirmed Example Library 健康状态。默认最多扫描 4,096 条证据；事件页最多 50 条。样本查询最多扫描 512 行、页大小最多 50、offset 最多 256。

事件列表只返回本地事件 ID、UTC 检测时间、风险等级、检测状态、通用动作、来源类型、模型拒判/执行状态、降级状态和稳定错误码；详情只额外返回规则代码。样本页只返回临时不透明命令 ID、人工标签、固定来源、确认 UTC 时间、Feature/Example schema 版本和冲突标志。所有 ViewModel 都不包含主题、正文、地址、URL、附件名、FeatureVector、样本 fingerprint、数据库/sidecar、密钥、nonce、认证标签、密文、路径、异常文本或堆栈。

写操作必须显式调用服务命令。确认样本只有在 `confirmed is True` 时才写入；检测和查询永不自动确认。样本删除使用当前服务实例最近分页产生的不透明 ID，不能从该 ID 推导 fingerprint。清空样本、诊断导出和全部删除同样要求精确布尔确认；诊断导出还要求用户选择输出路径，服务结果不会回显该路径或归档哈希。

全部删除会分别尝试删除 Evidence Store、Confirmed Example Library、各自当前用户密钥、SQLite WAL/SHM/journal/temp sidecar，以及当前用户 Agent 根目录内的 `diagnostic-temp`。任一层失败后仍继续尝试其余层，并返回稳定 `local_data_delete_partial_failure`，不泄露失败路径或异常文本。空存储查询先检查文件存在性，不会创建数据库或密钥；跨 Windows 用户作用域、损坏密文或数据库均返回受控不可用健康状态和零数据，不返回部分结果。

Phase 7A 服务本身没有 HTTP、WebSocket、RPC、网络客户端、监听端口、浏览器控制台、PySide6、托盘、图表、线程调度、`.eml` 解析、自动上传或中心后台能力。Phase 7B.1 的桌面 UI 只在该服务边界之外读取这些 ViewModel。

### 7.4 Windows 托盘与只读个人安全控制台

Phase 7B.1 使用 `PySide6-Essentials==6.8.3` 与 `tzdata==2026.3`。该固定 PySide6 版本支持 Python 3.12，提供 Qt Core/Gui/Widgets 与系统托盘所需模块；图表由 `QPainter` 自绘，因此不引入 PySide6 Addons 或 Qt Charts。Qt for Python 上游提供 LGPLv3、GPLv3 和商业许可选项。PyPI `tzdata` 包采用 PSF-2.0 许可，包含 IANA 时区数据库；发布方仍须对所选依赖许可完成自身合规复核和材料随附，本文不替代法律意见。

UI 开发环境固定在已忽略的 `endpoint_agent/.venv-ui/`：

```powershell
python -m venv endpoint_agent/.venv-ui
.\endpoint_agent\.venv-ui\Scripts\python.exe -m pip install -r endpoint_agent\requirements-ui.txt
```

上面的联网安装只用于受控开发机准备。生产构建和安装必须从批准的离线 wheel 缓存提供依赖；运行中的 Agent 不调用 pip，也不下载依赖：

```powershell
.\endpoint_agent\.venv-ui\Scripts\python.exe -m pip install `
  --no-index --find-links C:\approved-wheel-cache `
  -r endpoint_agent\requirements-ui.txt
```

源码开发运行：

```powershell
$env:PYTHONPATH = (Resolve-Path endpoint_agent\src)
.\endpoint_agent\.venv-ui\Scripts\python.exe -m shielddome_endpoint.desktop_app
```

主窗口只显示 Phase 7A 真实 ViewModel：今日检测数量、15 天补零趋势、风险/来源分布、模型拒判/故障/纯规则降级数量、最近事件分页和脱敏详情。托盘显示本地 Agent 状态并提供打开、隐藏、退出；普通关闭窗口只隐藏到托盘。空库、损坏存储和降级均显示固定安全状态，不呈现异常文本。

UI/Presenter 不直接导入 SQLite、EvidenceStore、ExampleStore、DPAPI、AES-GCM、密钥或密文；7B.2A 写操作只通过 `PersonalConsoleService`。Phase 7C.2 的桌面 intake 只调用 `LocalMailIntakeService`，不接触 MIME parser、Feature Pipeline、存储或 `MailObservation` 构造；界面不创建网络连接或监听端口。核心包没有 PySide6 时仍可导入。

### 7.5 当前用户启动与本地数据管理

Phase 7B.2A 增加“已确认样本”和“本地数据”页面。样本表只显示确认时间、正常/钓鱼标签、固定来源和冲突状态；删除单条与清空全部都要求明确确认，成功后重新通过 `PersonalConsoleService` 读取。界面不显示 FeatureVector、fingerprint、正文、地址、URL 或附件信息。

开机启动仅使用 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`，不需要管理员权限，也不使用 HKLM、计划任务、shell 或 PowerShell。只有冻结打包且绝对路径指向 `ShieldDomeEndpoint.exe` 的安装版可以注册；源码开发和普通 `python.exe` 显示“安装版提供开机启动”。同名非自有值不会被覆盖或删除。

诊断导出必须由用户点击、选择输出路径并确认；默认不覆盖，目标存在时要求独立二次确认。界面不读取、预览、打开、上传或记忆诊断包及路径。删除全部本地数据先说明证据、样本、密钥和诊断临时文件类别，再要求精确输入 `删除全部本地数据`；应用程序文件与浏览器插件不受影响。

Phase 7B.2B 已完成：可信 Local Detection/Native Host 在检测时把通过隐私扫描的 `FeatureVector` 写入独立 Pending Confirmation Context。该存储使用当前用户独立 DPAPI 密钥和逐记录 AES-256-GCM，明文索引仅含事件 ID、版本和过期时间，最长保留 15 天。事件详情的“确认正常/确认钓鱼”必须先显示确认对话框；桌面只提交事件 ID、目标标签和明确确认，不接收向量或 fingerprint。样本写入成功后上下文立即删除，写入失败时保留；不存在、过期、损坏或不可用状态只显示固定提示。

真实 Windows Qt 截图保存在被忽略的验证目录；Phase 7C.2 另包含初始、待确认、运行、完成和文件过大状态：

```text
endpoint_agent/dist/phase7b1/screenshots/1366x768.png
endpoint_agent/dist/phase7b1/screenshots/1024x720.png
endpoint_agent/dist/phase7c2/screenshots/1366x768-initial.png
endpoint_agent/dist/phase7c2/screenshots/1024x720-selected-confirmation.png
endpoint_agent/dist/phase7c2/screenshots/1024x720-running.png
endpoint_agent/dist/phase7c2/screenshots/1024x720-complete.png
endpoint_agent/dist/phase7c2/screenshots/1024x720-file-too-large.png
```

## 8. Corpus Governance

稳定入口：

```python
CorpusGovernance.prepare(
    candidates: tuple[CorpusCandidate, ...],
    split_policy: CorpusSplitPolicy = CorpusSplitPolicy(),
) -> CorpusSnapshot
```

候选和输出均为 `frozen=True, slots=True` 的不可变类型：

```python
from datetime import datetime, timezone
import hashlib

from shielddome_endpoint import (
    FEATURE_SCHEMA_VERSION,
    AuthorizationStatus,
    CorpusCandidate,
    CorpusGovernance,
    CorpusLabel,
    CorpusSplitPolicy,
    PrivacyReviewStatus,
    ReviewStatus,
    SourceLabel,
)


representation = "sanitized synthetic representation"
candidate = CorpusCandidate(
    item_id="synthetic-item-001",
    final_label=CorpusLabel.PHISHING,
    original_label=SourceLabel.PHISHING,
    label_source="human-review",
    label_guideline_version="label-guide-v1",
    label_evidence_id="label-evidence-synthetic-001",
    reviewer_id="reviewer-fictional-001",
    reviewed_at=datetime(2026, 7, 29, tzinfo=timezone.utc),
    review_status=ReviewStatus.APPROVED,
    review_policy_version="review-policy-v1",
    license_source="license-fictional-001",
    source_dataset_id="dataset-fictional-001",
    source_version="dataset-version-v1",
    source_evidence_digest=hashlib.sha256(b"source-evidence-001").hexdigest(),
    authorization_basis_id="authorization-fictional-001",
    authorization_status=AuthorizationStatus.ACTIVE,
    internal_training_allowed=True,
    endpoint_weight_distribution_allowed=True,
    authorization_approved_at=datetime(2026, 7, 28, tzinfo=timezone.utc),
    authorization_expires_at=datetime(2027, 7, 30, tzinfo=timezone.utc),
    authorization_no_expiry=False,
    privacy_review_status=PrivacyReviewStatus.APPROVED,
    sanitization_policy_version="sanitization-policy-v1",
    privacy_reviewed_at=datetime(2026, 7, 29, 12, tzinfo=timezone.utc),
    privacy_evidence_digest=hashlib.sha256(b"privacy-evidence-001").hexdigest(),
    raw_hash=hashlib.sha256(b"synthetic-raw-001").hexdigest(),
    normalized_hash=hashlib.sha256(b"synthetic-normalized-001").hexdigest(),
    template_group="synthetic-template-001",
    campaign_group="synthetic-campaign-001",
    language_group="mixed",
    source_group="synthetic",
    ingested_at=datetime(2026, 7, 30, tzinfo=timezone.utc),
    feature_schema_version=FEATURE_SCHEMA_VERSION,
    sanitized_training_representation=representation,
    sanitized_representation_digest=hashlib.sha256(
        representation.encode("utf-8")
    ).hexdigest(),
)

policy = CorpusSplitPolicy(
    test_source_groups=("independent-test-source",),
    test_after=datetime(2026, 8, 1, tzinfo=timezone.utc),
)
snapshot = CorpusGovernance().prepare((candidate,), split_policy=policy)
```

`prepare` 隐藏并统一执行：

- 标签指南、非敏感标签证据、稳定审核人 ID、审核时间/政策和人工批准状态准入；
- 来源数据集 ID/版本、来源证据 SHA-256、许可证标识和 feature schema 准入；
- 授权依据、approved/active 状态、批准时间、到期或明确无期限状态准入；到期时间必须严格晚于确定性的 `ingested_at` 准入时点；
- 内部训练权和终端模型权重分发权必须分别显式为 `True`；
- 隐私批准、脱敏政策、隐私审核时间/证据和 sanitized representation SHA-256 准入；
- benign/phishing 最终标签与 spam/ham/phishing/benign 原始语义检查；
- spam/ham 非人工来源禁止自动升级；
- 明确 phishing/benign 标签冲突拒绝；
- 相同 raw 或 normalized SHA-256 的不同最终标签整组拒绝；
- raw/normalized digest 必须是 64 位小写规范 SHA-256；
- 许可证和所有进入 manifest 的 group/source 标识不得是路径、网络地址或数据内容；
- ingestion、人工审核、授权批准/到期和隐私审核时间必须带时区，manifest 统一序列化为 UTC；
- raw hash 精确去重，并按 item ID 稳定选择 canonical；
- normalized hash 转换为不暴露原 hash 的稳定 duplicate group；
- 仅基于前 4096 字符 sanitized representation 的保守 `near-v1` 指纹；
- template、campaign、duplicate、near-duplicate group 的连通分量隔离；
- 指定 source group 或严格晚于 cutoff 的任一组员会使整个连通分量进入 test；
- 使用 SHA-256 稳定分配 70% train、15% validation、15% test；
- 单次最多接收 4096 个候选；超限批次整体以稳定错误码拒绝；
- manifest 记录稳定 ID、版本、状态、权利布尔结论、UTC 时间、raw/normalized/representation/evidence SHA-256、全部分组、schema 和 split；
- manifest 的规范 SHA-256 `digest` 覆盖全部条目和新增治理事实；相同输入可复现，候选顺序不影响结果；
- manifest 不保存 sanitized representation 正文、密码、Token、完整 URL query 或私有路径。

稳定拒绝码按类别包括：

- 标签审核：`missing_label_guideline_version`、`invalid_label_guideline_version`、`missing_label_evidence_id`、`invalid_label_evidence_id`、`missing_reviewer_id`、`invalid_reviewer_id`、`invalid_review_time`、`missing_review_policy_version`、`invalid_review_policy_version`；
- 来源和授权：`missing_source_dataset_id`、`invalid_source_dataset_id`、`missing_source_version`、`invalid_source_version`、`invalid_source_evidence_digest`、`missing_authorization_basis_id`、`invalid_authorization_basis_id`、`authorization_not_active`；
- 权利和时间：`internal_training_not_allowed`、`endpoint_weight_distribution_not_allowed`、`invalid_authorization_approval_time`、`missing_authorization_expiry`、`conflicting_authorization_expiry`、`invalid_authorization_expiry`、`authorization_expired`；
- 隐私：`privacy_not_approved`、`missing_sanitization_policy_version`、`invalid_sanitization_policy_version`、`invalid_privacy_review_time`、`invalid_privacy_evidence_digest`、`invalid_sanitized_representation_digest`、`sanitized_representation_digest_mismatch`。

拒绝记录只包含 `item_id` 和一个稳定 code，不回显非法字段值。当前 `CORPUS_SCHEMA_VERSION` 为 `3.0`。`CorpusSplitPolicy.test_after` 的语义是“严格晚于截止点”；等于截止点的样本继续使用默认确定性 split。默认 policy 不强制留出，保持原调用方式兼容。

`CorpusSnapshot` 只是内存领域结果。本阶段不提供文件导入、snapshot 持久化、数据加载器或训练入口。

## 9. 隐私扫描

```python
from shielddome_endpoint import PrivacyScanner


scanner = PrivacyScanner()
candidate_result = scanner.scan_candidate(candidate)
feature_result = scanner.scan_feature_vector(vector)
manifest_result = scanner.scan_manifest(snapshot.manifest)
outcome_result = scanner.scan_detection_outcome(outcome)
rule_result = scanner.scan_rule_assessments(rules)
```

扫描结果只包含 `safe` 和稳定违规代码，不回显命中内容。可在测试或调用边界通过 `forbidden_values` 传入不得出现的原文、地址或完整 URL，确认其未进入输出。

扫描范围包括：

- 非空 `FeatureVector.text_input`；
- 调用方给定的禁止值；
- password、Token、API Key、Authorization 等赋值形态；
- 带完整 query 的 URL；
- 邮箱地址和换行；
- Windows 绝对路径和典型 Linux 私有路径。

所有 violation code 都排序并去重；结果不会包含命中原值、内容片段或身份信息。隐私扫描是结构化输出的防回归门禁，不替代候选数据的人工脱敏和审核，也不是邮件脱敏器。

## 10. 测试与包导入

在仓库根目录运行完整 Endpoint Agent 测试：

```powershell
python -m unittest discover -s endpoint_agent/tests -v
```

当前无打包 Host 的开发环境完整 Endpoint Agent 回归应运行 221 项测试：220 项通过，打包 Host 契约因 `.exe` 不存在明确跳过 1 项；不得把该跳过解释为 Phase 5B 已完成。具备有效 `.exe` 后，打包 Host 契约必须运行且不再跳过，命令仍须以退出码 0 结束且没有 failure 或 error。

运行 Phase 6A 单个测试模块：

```powershell
python -m unittest discover -s endpoint_agent/tests -p "test_key_protection.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_evidence_crypto.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_evidence_store.py" -v
```

运行 Phase 6B 单个测试模块：

```powershell
python -m unittest discover -s endpoint_agent/tests -p "test_confirmed_examples.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_example_store.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_example_calibration.py" -v
```

运行 Phase 6C 单个测试模块：

```powershell
python -m unittest discover -s endpoint_agent/tests -p "test_diagnostics.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_diagnostic_export.py" -v
```

运行 Phase 1 单个测试模块：

```powershell
python -m unittest discover -s endpoint_agent/tests -p "test_feature_pipeline.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_corpus_governance.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_privacy.py" -v
```

运行 Phase 2 训练测试和完整合成实验：

```powershell
.\endpoint_agent\.venv-training\Scripts\python.exe -m unittest discover -s endpoint_agent/training_tests -v
.\endpoint_agent\.venv-training\Scripts\python.exe endpoint_agent\training\run_synthetic_experiment.py --artifact-directory endpoint_agent\training\artifacts\acceptance
```

训练环境、数据边界、拒判感知指标语义、校准 candidate/selected 门禁、依赖许可证和 ONNX 验证见 `docs/TRAINING.md`。合成实验固定不可发布，不能作为 Phase 3 模型选型或发布指标。

无需安装即可验证根包导入：

```powershell
$env:PYTHONPATH = (Resolve-Path endpoint_agent\src).Path
python -c "import shielddome_endpoint as s; print(s.__version__, s.FEATURE_SCHEMA_VERSION, s.CORPUS_SCHEMA_VERSION, s.DETECTION_OUTCOME_SCHEMA_VERSION)"
```

## 11. 离线构建 Wheel

```powershell
python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist
```

构建由 `endpoint_agent/_build_backend.py` 完成，不要求 setuptools、wheel、Flit 或 Hatchling。`--no-index` 阻止访问包索引；Wheel metadata 会声明 `Requires-Dist: cryptography==49.0.0`、`Requires-Dist: PySide6-Essentials==6.8.3` 与 `Requires-Dist: tzdata==2026.3`，但 `--no-deps` 不会下载或打包这些依赖。批准的离线 Host/Endpoint Release 构建环境必须另行提供匹配 wheel。

成功时生成：

```text
endpoint_agent/dist/shielddome_endpoint-0.1.0-py3-none-any.whl
```

`dist/` 属于可再生成且已忽略的本地产物。

### 11.1 Windows Native Messaging Host

Host 使用现有 `shielddome_endpoint.native_host.main()`，不会创建 HTTP/WebSocket/TCP/UDP 服务：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File endpoint_agent\native_host\build-host.ps1
python -m unittest discover -s endpoint_agent/tests -p "test_native_host_process.py" -v
```

成功时生成：

```text
endpoint_agent/dist/native-host/ShieldDomeEndpointHost.exe
endpoint_agent/dist/native-host/build-metadata.json
```

构建输出均被 Git 忽略。`build-metadata.json` 绑定 Host SHA-256、绝对路径、Host 名称、开发扩展 ID/origin 和 PyInstaller 版本；注册前必须全部一致。当前环境的构建命令因没有离线 PyInstaller 而返回非零，因此不能执行默认浏览器注册。

具备有效构建后，当前用户注册与自检命令为：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File endpoint_agent\native_host\install-host.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File endpoint_agent\native_host\check-host.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File endpoint_agent\native_host\uninstall-host.ps1
```

脚本只使用两个 HKCU Native Messaging Host 键，不要求管理员权限；路径中的空格和中文由自动化测试覆盖。完整 Chrome/Edge 人工验收见 `docs/BROWSER_ACCEPTANCE.md`。

## 12. 数据和离线边界

以下内容必须保留在 Git 之外：

- 模型文件和模型包；
- 原始训练数据、Approved Training Corpus 数据和 snapshot；
- 训练 artifacts、指标和输出；
- 本地密钥、日志、SQLite 数据库及临时文件；
- 诊断包、缓存、虚拟环境和构建产物。

生产包必须保持：

- 不导入网络客户端或 socket；
- 不依赖 Flask、FastAPI、Uvicorn、aiohttp 或 WebSocket 框架；
- 不监听 TCP/UDP 端口；
- 不调用中心后台、外部模型、信誉服务、遥测或更新服务；
- 不下载、打开、解压、预览或执行附件。

## 13. 尚未实现

当前明确尚未交付：

- Approved Training Corpus、正式模型训练或生产模型；
- Phase 3 文本编码器、微调、量化或最低硬件发布评测；
- Phase 3 正式文本编码模型、模型选择、正式训练、量化、发布指标或最低硬件验证；
- Phase 4B 生产 ONNX Runtime adapter、正式模型加载、真实执行超时或资源控制；
- 当前环境实际构建的 Host 可执行文件、默认 Chrome/Edge Native Host 注册或真实浏览器联调；
- Phase 8 Endpoint Release 安装、升级、ACL、完整性和回滚。
- Phase 9 的 Windows 右键检测和 Outlook、Foxmail、QQ 邮箱等桌面邮件客户端 adapter。

Phase 3 继续受 Approved Training Corpus 阻塞并保持 `pending`。Phase 6、Phase 7B、Phase 7C.1、Phase 7C.2、Phase 7C 与 Phase 7 已完成。Phase 8 保持 `pending`；正式 Endpoint Release 仍被 Phase 3、Phase 4B 和发布门禁阻塞，桌面邮件客户端 adapter 仍属于 Phase 9。

## 14. 修改后的最低验证

```powershell
python -m unittest discover -s endpoint_agent/tests -v
python -m unittest discover -s endpoint_agent/tests -p "test_desktop_*.py" -v
$env:QT_QPA_PLATFORM='offscreen'; .\endpoint_agent\.venv-ui\Scripts\python.exe -m unittest discover -s endpoint_agent/tests -p "test_desktop_qt.py" -v
.\endpoint_agent\.venv-ui\Scripts\python.exe -c "import PySide6, tzdata; print(PySide6.__version__); print(tzdata.__version__)"
python -m unittest discover -s endpoint_agent/tests -p "test_key_protection.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_evidence_crypto.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_evidence_store.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_confirmed_examples.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_example_store.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_example_calibration.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_diagnostics.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_diagnostic_export.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_native_protocol.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_native_payload.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_native_host.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_native_host_process.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_native_packaging.py" -v
node --check endpoint_agent/extension/background.js
node --check endpoint_agent/extension/content.js
node --check endpoint_agent/extension/adapters/chinaccs.js
python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist\phase7b1
git status --short
git diff --stat
git diff -- endpoint_agent
git status --short -- app shielddome frontend extension web deploy scripts
```

同时确认生产源码仍由离线 guard 全量扫描，corpus 数据/snapshot/训练输出被忽略，且业务代码修改只位于 `endpoint_agent/`。

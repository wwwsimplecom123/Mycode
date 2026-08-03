# ShieldDome Endpoint Agent 使用说明

## 1. 当前可用范围

当前仓库已完成开发期 **Phase 2：基线模型与评估**、模型无关的 **Phase 4A：Detection Kernel**、**Phase 4A.1：本地规则评估与端到端 Local Detection Service**，以及 **Phase 5A：Native Messaging 协议、本地 Host 与独立 MV3 插件基础链路**。Phase 3 因缺少 Approved Training Corpus 而有意暂缓并保持 `pending`；Phase 4 总状态为 `in_progress`、Phase 4B 为 `pending`；Phase 5 总状态为 `in_progress`、Phase 5B 已进入 `in_progress`。当前提供：

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
- 4 字节 little-endian + UTF-8 JSON Native Messaging 协议、严格 payload 白名单、集中资源上限和稳定错误码；
- `run_native_host(input_stream, output_stream, handler)` BytesIO seam、固定开发 extension origin 与四字段最小结果；
- `endpoint_agent/extension/` 下只匹配 `https://webmail.chinaccs.cn/*`、不含网络客户端、服务器地址或插件 Token 的独立 MV3 插件。
- 由公开 manifest key 固定的开发扩展 ID `hchaloelgnennaojaiikeebhajcoccih`，不提交私钥；
- 开发期 PyInstaller Host 构建脚本、SHA-256 build metadata、Chrome/Edge 当前用户 manifest/注册/检查/卸载脚本；
- 源码 Host 真实子进程协议、隐私、连续请求隔离和零 TCP/UDP socket 验证，以及隔离测试注册表路径下的浏览器注册生命周期测试。

生产包 `shielddome_endpoint` 负责 Phase 0–1 契约/特征/Corpus 治理、Phase 4A/4A.1 本地检测链路，以及 Phase 5A Native Messaging protocol/Host seam。Phase 2 能力和 PyInstaller 都只存在于开发侧，不会进入生产 Wheel。当前不会解析 `.eml`、加载生产模型、持久化结果或提供桌面 UI；插件只从已打开的 chinaccs 邮件详情页读取专用 DOM 事实。当前环境没有可离线使用的 PyInstaller，因此尚未生成 Host `.exe`，没有写入默认 Chrome/Edge 注册，也没有完成真实浏览器验收。

## 2. 环境要求

- Windows 10/11 64 位；
- Python 3.12；
- Git，可执行 `git check-ignore`；
- 在仓库根目录 `C:\Users\huohuo\Desktop\project1\ShieldDome` 执行命令。

生产 Wheel 没有第三方运行时依赖。Phase 2 训练环境使用 `requirements-training.txt` 的固定依赖，并且只能安装到被忽略的 `.venv-training/`；详见 `docs/TRAINING.md`。Host `.exe` 构建另使用 `requirements-packaging.txt` 中固定的 PyInstaller 开发依赖，必须从批准的离线缓存提供，且不得写入 `pyproject.toml`。Phase 4A 不下载模型、数据集或 NLTK 资源，也不引入 ONNX Runtime 生产依赖。

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
    test_repository_hygiene.py      Git 忽略规则
    test_native_protocol.py         framing、UTF-8/JSON 与资源边界
    test_native_payload.py          payload 白名单、注入拒绝与长度边界
    test_native_host.py             BytesIO Host、origin、投影与错误隔离
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
- uncertain 和全部故障/规则模式不产生模型调整；无规则的 uncertain 仍给出 `verify_sender`，不投影为安全放行；
- 最终分数限制为 0–100，0–24/25–49/50–79/80–100 分别映射 low/medium/high/critical。

`minimal_plugin_projection` 的允许字段精确为 `local_event_id`、`risk_level`、`execution_state` 和 `generic_action`。`structured_private_evidence` 只包含稳定 evidence code/类别/状态、分数组成、执行/降级状态和版本摘要；两者都不包含正文、完整地址、URL query、Token、密码或私有路径。本阶段结果只存在于内存，不落盘。

`MODEL_ASSESSMENT_SCHEMA_VERSION` 为 `1.0`，`DETECTION_OUTCOME_SCHEMA_VERSION` 为 `2.0`；Feature Schema 继续为 `2.0`，Corpus Schema 继续为 `3.0`。

## 7. Corpus Governance

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

## 8. 隐私扫描

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

## 9. 测试与包导入

在仓库根目录运行完整 Endpoint Agent 测试：

```powershell
python -m unittest discover -s endpoint_agent/tests -v
```

当前无打包 Host 的开发环境完整 Endpoint Agent 回归应运行 155 项测试：154 项通过，打包 Host 契约因 `.exe` 不存在明确跳过 1 项；不得把该跳过解释为 Phase 5B 已完成。具备有效 `.exe` 后，打包 Host 契约必须运行且不再跳过，命令仍须以退出码 0 结束且没有 failure 或 error。

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

## 10. 离线构建 Wheel

```powershell
python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist
```

构建由 `endpoint_agent/_build_backend.py` 完成，不要求 setuptools、wheel、Flit 或 Hatchling。`--no-index` 阻止访问包索引，`pyproject.toml` 没有第三方运行时依赖。

成功时生成：

```text
endpoint_agent/dist/shielddome_endpoint-0.1.0-py3-none-any.whl
```

`dist/` 属于可再生成且已忽略的本地产物。

### 10.1 Windows Native Messaging Host

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

## 11. 数据和离线边界

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

## 12. 尚未实现

Phase 5A/当前 Phase 5B 明确尚未交付：

- Approved Training Corpus、正式模型训练或生产模型；
- Phase 3 文本编码器、微调、量化或最低硬件发布评测；
- Phase 3 正式文本编码模型、模型选择、正式训练、量化、发布指标或最低硬件验证；
- Phase 4B 生产 ONNX Runtime adapter、正式模型加载、真实执行超时或资源控制；
- 当前环境实际构建的 Host 可执行文件、默认 Chrome/Edge Native Host 注册或真实浏览器联调；
- 数据库、DPAPI、AES-GCM、15 天留存；
- 托盘、控制台、`.eml` 或邮件客户端 adapter。

Phase 3 继续受真实、许可完整、人工审核且去泄漏的 Approved Training Corpus 阻塞并保持 `pending`。Phase 5B 已进入 `in_progress`：自动化构建/身份/注册准备已完成，但仍需批准的离线 PyInstaller 产生真实 Host，并分别完成 Chrome/Edge chinaccs 验收；这不代表绕过模型合规要求。正式 Endpoint Release 仍被 Phase 3、Phase 4B 和发布门禁阻塞。

## 13. 修改后的最低验证

```powershell
python -m unittest discover -s endpoint_agent/tests -v
python -m unittest discover -s endpoint_agent/tests -p "test_native_protocol.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_native_payload.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_native_host.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_native_host_process.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_native_packaging.py" -v
node --check endpoint_agent/extension/background.js
node --check endpoint_agent/extension/content.js
node --check endpoint_agent/extension/adapters/chinaccs.js
powershell -NoProfile -ExecutionPolicy Bypass -File endpoint_agent\native_host\build-host.ps1
python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist\phase5b
git status --short
git diff --stat
git diff -- endpoint_agent
```

同时确认生产源码仍由离线 guard 全量扫描，corpus 数据/snapshot/训练输出被忽略，且业务代码修改只位于 `endpoint_agent/`。

# ShieldDome Endpoint Agent 使用说明

## 1. 当前可用范围

当前仓库实现到开发期 **Phase 2：基线模型与评估**，提供：

- 可离线构建、导入的独立 Python 包 `shielddome_endpoint`；
- Phase 0 的不可变领域类型和版本字段；
- 训练与 Endpoint 共用的 `FeaturePipeline.transform`；
- Approved Training Corpus 的 `CorpusGovernance.prepare`；
- 不可变的来源/时间 test 留出 `CorpusSplitPolicy`；
- 只含 digest 和稳定标识的训练溯源 manifest；
- `FeatureVector` 和 corpus manifest 的 `PrivacyScanner`；
- 离线能力、隐私边界、数据产物忽略和 Wheel 构建测试；
- 独立训练侧固定 140 维 Feature Assembler；
- 合成数据 Logistic Regression、validation-only 校准候选质量门禁和不确定拒判；
- test-only 分语言、来源和时间评估及 JSON/Markdown 报告；
- 标准 ONNX 导出与 ONNX Runtime CPU 概率一致性验证。

生产包 `shielddome_endpoint` 仍只负责 Phase 0–1 契约和特征/Corpus 治理。Phase 2 能力只存在于开发期训练目录，不会进入生产 Wheel。当前不会读取邮箱、解析 `.eml`、加载生产模型或输出最终风险，也不是可交付的终端检测程序。

## 2. 环境要求

- Windows 10/11 64 位；
- Python 3.12；
- Git，可执行 `git check-ignore`；
- 在仓库根目录 `C:\Users\huohuo\Desktop\project1\ShieldDome` 执行命令。

生产 Wheel 没有第三方运行时依赖。Phase 2 训练环境使用 `requirements-training.txt` 的固定依赖，并且只能安装到被忽略的 `.venv-training/`；详见 `docs/TRAINING.md`。本阶段不下载模型、数据集或 NLTK 资源。

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
    feature_pipeline.py             确定性特征转换
    corpus.py                       Corpus Governance 深模块
    privacy.py                      FeatureVector/manifest 隐私扫描
  tests/
    test_feature_pipeline.py        Feature Pipeline 公开行为
    test_corpus_governance.py       corpus 准入、去重和 split
    test_privacy.py                 隐私扫描
    test_offline_constraints.py     离线边界
    test_repository_hygiene.py      Git 忽略规则
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

## 5. Corpus Governance

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
    CorpusCandidate,
    CorpusGovernance,
    CorpusLabel,
    CorpusSplitPolicy,
    ReviewStatus,
    SourceLabel,
)


candidate = CorpusCandidate(
    item_id="synthetic-item-001",
    final_label=CorpusLabel.PHISHING,
    original_label=SourceLabel.PHISHING,
    label_source="human-review",
    review_status=ReviewStatus.APPROVED,
    license_source="company-authorized-synthetic",
    raw_hash=hashlib.sha256(b"synthetic-raw-001").hexdigest(),
    normalized_hash=hashlib.sha256(b"synthetic-normalized-001").hexdigest(),
    template_group="synthetic-template-001",
    campaign_group="synthetic-campaign-001",
    language_group="mixed",
    source_group="synthetic",
    ingested_at=datetime(2026, 7, 30, tzinfo=timezone.utc),
    feature_schema_version=FEATURE_SCHEMA_VERSION,
    sanitized_training_representation="sanitized synthetic representation",
)

policy = CorpusSplitPolicy(
    test_source_groups=("independent-test-source",),
    test_after=datetime(2026, 8, 1, tzinfo=timezone.utc),
)
snapshot = CorpusGovernance().prepare((candidate,), split_policy=policy)
```

`prepare` 隐藏并统一执行：

- 来源、许可证、审核状态、必填元数据和 feature schema 准入；
- benign/phishing 最终标签与 spam/ham/phishing/benign 原始语义检查；
- spam/ham 非人工来源禁止自动升级；
- 明确 phishing/benign 标签冲突拒绝；
- 相同 raw 或 normalized SHA-256 的不同最终标签整组拒绝；
- raw/normalized digest 必须是 64 位小写规范 SHA-256；
- 许可证和所有进入 manifest 的 group/source 标识不得是路径、网络地址或数据内容；
- ingestion time 必须带时区，manifest 统一序列化为 UTC；
- raw hash 精确去重，并按 item ID 稳定选择 canonical；
- normalized hash 转换为不暴露原 hash 的稳定 duplicate group；
- 仅基于前 4096 字符 sanitized representation 的保守 `near-v1` 指纹；
- template、campaign、duplicate、near-duplicate group 的连通分量隔离；
- 指定 source group 或严格晚于 cutoff 的任一组员会使整个连通分量进入 test；
- 使用 SHA-256 稳定分配 70% train、15% validation、15% test；
- 单次最多接收 4096 个候选；超限批次整体以稳定错误码拒绝；
- manifest 记录原始/最终标签、标签来源、审核、许可证标识、UTC 时间、raw/normalized/representation SHA-256、全部分组、schema 和 split；
- manifest 不保存 sanitized representation 正文、密码、Token、完整 URL query 或私有路径。

当前 `CORPUS_SCHEMA_VERSION` 为 `2.0`。`CorpusSplitPolicy.test_after` 的语义是“严格晚于截止点”；等于截止点的样本继续使用默认确定性 split。默认 policy 不强制留出，保持原调用方式兼容。

`CorpusSnapshot` 只是内存领域结果。本阶段不提供文件导入、snapshot 持久化、数据加载器或训练入口。

## 6. 隐私扫描

```python
from shielddome_endpoint import PrivacyScanner


scanner = PrivacyScanner()
feature_result = scanner.scan_feature_vector(vector)
manifest_result = scanner.scan_manifest(snapshot.manifest)
```

扫描结果只包含 `safe` 和稳定违规代码，不回显命中内容。可在测试或调用边界通过 `forbidden_values` 传入不得出现的原文、地址或完整 URL，确认其未进入输出。

扫描范围包括：

- 非空 `FeatureVector.text_input`；
- 调用方给定的禁止值；
- password、Token、API Key、Authorization 等赋值形态；
- 带完整 query 的 URL；
- 典型 Windows/Linux 用户私有路径。

隐私扫描是结构化输出的防回归门禁，不替代候选数据的人工脱敏和审核。

## 7. 测试与包导入

在仓库根目录运行完整 Endpoint Agent 测试：

```powershell
python -m unittest discover -s endpoint_agent/tests -v
```

当前生产/Phase 0–1 回归应发现 51 项测试。验收时命令必须以退出码 0 结束，且没有 failure、error 或 skip。

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
python -c "import shielddome_endpoint as s; print(s.__version__, s.FEATURE_SCHEMA_VERSION, s.CORPUS_SCHEMA_VERSION)"
```

## 8. 离线构建 Wheel

```powershell
python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist
```

构建由 `endpoint_agent/_build_backend.py` 完成，不要求 setuptools、wheel、Flit 或 Hatchling。`--no-index` 阻止访问包索引，`pyproject.toml` 没有第三方运行时依赖。

成功时生成：

```text
endpoint_agent/dist/shielddome_endpoint-0.1.0-py3-none-any.whl
```

`dist/` 属于可再生成且已忽略的本地产物。

## 9. 数据和离线边界

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

## 10. 尚未实现

Phase 2 明确不包含：

- Approved Training Corpus、正式模型训练或生产模型；
- Phase 3 文本编码器、微调、量化或最低硬件发布评测；
- 生产 ONNX Runtime adapter、模型加载或端点推理；
- Detection Kernel、风险融合或 DetectionOutcome 生成；
- Native Messaging、浏览器插件或本地网络服务；
- 数据库、DPAPI、AES-GCM、15 天留存；
- 托盘、控制台、`.eml` 或邮件客户端 adapter。

计划中的下一阶段是 **Phase 3：文本编码模型**，但当前受真实、许可完整、人工审核且去泄漏的 Approved Training Corpus 阻塞。在该前置条件落实前不能开始正式模型选择，也不能产生可发布 Unified Model Release；不得从本使用文档或合成指标推断 Phase 3 能力已经存在。

## 11. 修改后的最低验证

```powershell
python -m unittest discover -s endpoint_agent/tests -v
.\endpoint_agent\.venv-training\Scripts\python.exe -m unittest discover -s endpoint_agent/training_tests -v
.\endpoint_agent\.venv-training\Scripts\python.exe endpoint_agent\training\run_synthetic_experiment.py --artifact-directory endpoint_agent\training\artifacts\acceptance
python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist
git status --short
git diff --stat
git diff -- endpoint_agent
```

同时确认生产源码仍由离线 guard 全量扫描，corpus 数据/snapshot/训练输出被忽略，且业务代码修改只位于 `endpoint_agent/`。

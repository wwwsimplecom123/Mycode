# Phase 2 基线模型、校准、拒判、评估与 ONNX 验证 Implementation Plan

> **Execution requirement:** 按 `$executing-plans` 在当前工作树内逐项执行，并对每个公开行为使用 `$tdd` 的 red → green 循环。用户已明确要求 Inline Execution；不创建 branch/worktree，不 commit、push 或创建 PR。

**Goal:** 仅完成 Phase 2，使用纯合成、无真实身份信息的数据证明固定 FeatureVector 布局、Logistic Regression、validation-only 概率校准与拒判阈值、test-only 分组评估、报告生成以及标准 ONNX 导出/ONNX Runtime CPU 一致性验证可重复运行。

**Architecture:** Phase 2 代码放在独立训练侧包 `endpoint_agent/training/shielddome_training/`，直接消费生产包的 Phase 1 `FeatureVector`，但不进入生产 Wheel。`BaselineExperiment.run` 是训练侧深模块入口，隐藏数据边界校验、特征组装、训练、校准、阈值、评估、报告和 ONNX 验证。生产 `shielddome_endpoint` 包不导入 NumPy、SciPy、scikit-learn 或 ONNX 依赖，也不新增 Phase 4 Local Inference adapter。

**Tech Stack:** Python 3.12；训练虚拟环境中的固定版本 NumPy、SciPy、scikit-learn、ONNX、ONNX Runtime CPU、skl2onnx；标准库 `dataclasses`、`datetime`、`enum`、`hashlib`、`json`、`pathlib`、`time`；标准库 `unittest`。生产 Wheel 继续使用项目内零外部依赖 PEP 517 backend。

## Global Constraints

- 只能修改 `endpoint_agent/`；`app/`、`shielddome/`、`frontend/`、`extension/`、`web/`、`deploy/`、`scripts/`、`phishingDP-main/` 保持基线不变。
- 只实施 Phase 2。Phase 3 保持 `pending`；不实现文本编码器、量化、正式模型选择、Detection Kernel、生产 ONNX Runtime adapter、Risk Fusion、Native Messaging、插件、数据库、加密或 UI。
- 只使用合成 `FeatureVector` 和虚构 `.test` 上下文；不下载、读取或提交任何训练数据，不使用 `phishingDP-main` 的日志、NPZ、CSV、图表或指标作为数据或发布证据。
- 合成实验只证明链路可运行；报告必须写明 `synthetic_only=true`、`release_eligible=false`，不得宣称达到生产发布门槛。
- 训练依赖只安装到被忽略的 `endpoint_agent/.venv-training/`；不得修改全局 Python，不得写入 `[project].dependencies`，生产 Wheel 必须保持零第三方运行依赖。
- 模型、JSON/Markdown 报告和实验输出只写到测试临时目录或被忽略的 `endpoint_agent/training/artifacts/`；不得提交实际产物。
- 训练、校准和阈值只分别使用 train、validation；test 只用于最终指标。任何 item/duplicate/near-duplicate/template/campaign group 不得跨 split。
- ONNX 必须由 `skl2onnx`/`onnx` 标准 API 产生，并由 ONNX Runtime CPU 加载验证；禁止 custom operator、未经验证 external data 或手写二进制冒充模型。
- 测试不得建立网络连接、监听端口或持久化邮件原文、Token、完整 URL 查询参数、私有路径。

## Public Interfaces

训练侧包公开以下不可变契约；Phase 1 的生产公开类型不变：

```python
class TrainingLabel(StrEnum):
    BENIGN = "benign"
    PHISHING = "phishing"

class ConfidenceState(StrEnum):
    CONFIDENT_BENIGN = "confident-benign"
    UNCERTAIN = "uncertain"
    CONFIDENT_PHISHING = "confident-phishing"

@dataclass(frozen=True, slots=True)
class TrainingSample:
    item_id: str
    feature_vector: FeatureVector
    label: TrainingLabel
    split: DatasetSplit
    language_group: str
    source_group: str
    ingested_at: datetime
    feature_schema_version: str
    corpus_schema_version: str
    duplicate_group: str
    near_duplicate_group: str
    template_group: str
    campaign_group: str

@dataclass(frozen=True, slots=True)
class TrainingDataset:
    samples: tuple[TrainingSample, ...]
    synthetic_only: bool

@dataclass(frozen=True, slots=True)
class BaselineExperimentConfig:
    artifact_directory: Path
    random_seed: int = 20260730
    max_iterations: int = 1000
    onnx_opset: int = 17
    onnx_probability_tolerance: float = 1e-6
    time_test_cutoff: datetime | None = None

class FeatureAssembler:
    @property
    def feature_names(self) -> tuple[str, ...]: ...
    @property
    def output_dimension(self) -> int: ...
    def transform(self, vector: FeatureVector) -> numpy.ndarray: ...
    def transform_many(self, vectors: tuple[FeatureVector, ...]) -> numpy.ndarray: ...

@dataclass(frozen=True, slots=True)
class AbstentionThresholds:
    benign_threshold: float
    phishing_threshold: float
    selection_objective: str
    def classify(self, probability: float) -> ConfidenceState: ...

class CalibratedProbabilityModel:
    def predict_probabilities(
        self,
        vectors: tuple[FeatureVector, ...],
    ) -> tuple[float, ...]: ...

@dataclass(frozen=True, slots=True)
class EvaluationMetrics:
    status: str
    sample_count: int
    classified_count: int
    phishing_recall: float | None
    benign_false_positive_rate: float | None
    precision: float | None
    f1: float | None
    roc_auc: float | None
    pr_auc: float | None
    brier_score: float | None
    high_confidence_phishing_precision: float | None
    abstention_rate: float | None
    confusion_matrix: tuple[tuple[int, int], tuple[int, int]] | None
    inference_duration_ms: tuple[tuple[str, float], ...] | None

@dataclass(frozen=True, slots=True)
class EvaluationReport:
    synthetic_only: bool
    release_eligible: bool
    disclaimer: str
    groups: tuple[tuple[str, EvaluationMetrics], ...]
    def to_json(self) -> str: ...
    def to_markdown(self) -> str: ...

@dataclass(frozen=True, slots=True)
class BaselineModelMetadata:
    model_type: str
    feature_schema_version: str
    corpus_schema_version: str
    assembler_schema_version: str
    feature_names: tuple[str, ...]
    input_dimension: int
    random_seed: int
    max_iterations: int
    class_weight: str
    calibration_method: str
    calibration_parameters: tuple[tuple[str, float], ...]
    validation_brier_before: float
    validation_brier_after: float
    thresholds: AbstentionThresholds
    onnx_opset: int
    onnx_sha256: str
    onnx_size_bytes: int
    synthetic_only: bool

@dataclass(frozen=True, slots=True)
class OnnxValidationResult:
    runtime_provider: str
    input_name: str
    input_dimension: int
    compared_sample_count: int
    maximum_absolute_error: float
    tolerance: float
    consistent: bool

@dataclass(frozen=True, slots=True)
class BaselineExperimentResult:
    probability_model: CalibratedProbabilityModel
    metadata: BaselineModelMetadata
    evaluation_report: EvaluationReport
    onnx_validation: OnnxValidationResult
    onnx_model_path: Path
    json_report_path: Path
    markdown_report_path: Path

class BaselineExperiment:
    def run(
        self,
        dataset: TrainingDataset,
        config: BaselineExperimentConfig,
    ) -> BaselineExperimentResult: ...
```

`FeatureAssembler` 使用固定 26 个 numeric 名称、固定 categorical one-hot 表、64 个 text bucket 和固定 missing-mask 名称/unknown 位。不存在动态 vocabulary 或全数据 `fit_transform`。未知类别只进入显式 `unknown` bucket。

## File Map

- Create `endpoint_agent/requirements-training.txt`: 仅训练环境的精确版本依赖，不进入生产项目依赖。
- Modify `endpoint_agent/.gitignore`: 忽略 `.venv-training/` 和 Phase 2 实验输出。
- Create `endpoint_agent/training/shielddome_training/__init__.py`: 只导出上列训练侧公开接口。
- Create `endpoint_agent/training/shielddome_training/contracts.py`: 不可变训练样本、配置、阈值、指标、元数据和结果类型。
- Create `endpoint_agent/training/shielddome_training/feature_assembler.py`: 固定、版本化 FeatureVector 数组布局。
- Create `endpoint_agent/training/shielddome_training/baseline_experiment.py`: 深入口，隐藏 split 校验、Logistic Regression、validation-only 校准/阈值、test-only 评估、报告和 ONNX 导出/验证。
- Create `endpoint_agent/training/shielddome_training/synthetic.py`: 构造有界、无身份信息的链路验收 dataset；不伪装真实 corpus。
- Create `endpoint_agent/training/run_synthetic_experiment.py`: 明确的开发期 CLI，仅调用训练深入口并输出非敏感 artifact 摘要，不提供服务或端口。
- Create `endpoint_agent/training_tests/_fixtures.py`: 合成 FeatureVector/TrainingDataset helper，不包含真实邮件正文。
- Create `endpoint_agent/training_tests/test_feature_assembler.py`: 公开布局、unknown、schema、隐私测试。
- Create `endpoint_agent/training_tests/test_training_boundaries.py`: split/group/schema 边界和 test 泄漏测试。
- Create `endpoint_agent/training_tests/test_calibration_abstention.py`: validation-only 校准、概率范围、阈值和拒判测试。
- Create `endpoint_agent/training_tests/test_evaluation_reporting.py`: 分组、空组、指标、JSON/Markdown 隐私与合成声明测试。
- Create `endpoint_agent/training_tests/test_onnx_validation.py`: 标准导出、SHA/大小、CPU Runtime 和 Python/ONNX 概率一致性测试。
- Modify `endpoint_agent/tests/test_repository_hygiene.py`: 验证训练 venv 和 artifacts 被忽略。
- Modify `endpoint_agent/tests/test_build.py`: 明确生产 Wheel 不包含训练侧代码或第三方依赖。
- Create `endpoint_agent/docs/TRAINING.md`: 实际固定版本、许可证、环境创建、测试、合成实验、报告与 ONNX 验证说明。
- Modify `endpoint_agent/docs/USAGE.md`: 加入 Phase 2 训练侧用法和“仅合成链路、非发布模型”边界。
- Modify `endpoint_agent/AGENTS.md`: 更新 Phase 0–2 实际状态及训练/生产依赖隔离规则。
- Modify `endpoint_agent/DEVELOPMENT_PLAN.md`: 仅在全部门禁通过后把 Phase 2 改为 `complete`，保持 Phase 3 `pending`，下一步改为 Phase 3。

## Task 1: 隔离且可复现的训练环境

**Files:** `requirements-training.txt`, `.gitignore`, `docs/TRAINING.md`, `tests/test_repository_hygiene.py`

- [ ] 写失败测试：`endpoint_agent/.venv-training/` 与 `endpoint_agent/training/artifacts/` 由 `git check-ignore` 忽略。
- [ ] Red: `python -m unittest endpoint_agent.tests.test_repository_hygiene.RepositoryHygieneTests.test_training_environment_and_phase_two_artifacts_are_ignored -v`；预期 `.venv-training` 尚未被忽略。
- [ ] 最小实现：只补 Endpoint Agent `.gitignore`；创建精确固定训练依赖清单和许可证文档骨架，不修改 `pyproject.toml` dependencies。
- [ ] Green: 重跑相同命令，预期 PASS、退出码 0。
- [ ] 创建 `.venv-training` 并仅在其中安装固定依赖；用 `importlib.metadata` 记录实际版本和许可证。若安装失败，保留已验证切片、Phase 2 维持 `in_progress` 并报告阻塞，不伪造 ONNX。

## Task 2: 固定 Feature Assembler

**Files:** `training/shielddome_training/contracts.py`, `feature_assembler.py`, `__init__.py`, `training_tests/test_feature_assembler.py`, `_fixtures.py`

- [ ] 写失败测试：同一 `FeatureVector` 重复转换数组完全一致，feature names/dimension 固定，训练/验证调用同一 assembler 得到相同结果，未知 categorical/missing 名称进入固定 unknown bucket。
- [ ] Red: `endpoint_agent\.venv-training\Scripts\python.exe -m unittest discover -s endpoint_agent/training_tests -p "test_feature_assembler.py" -v`；预期训练包或接口尚不存在。
- [ ] 最小实现：按 Phase 1 名称固定布局；严格校验 numeric/categorical 名称集合、64 维 text vector、有限数值；unknown 类别只编码到预定义 bucket，不 fit vocabulary。
- [ ] Green: 重跑同命令至 PASS。
- [ ] 新增一个独立失败测试：Feature/corpus schema 非 `2.0` 时由训练契约/assembler 拒绝为稳定 `ValueError`；最小实现后单测转绿。
- [ ] 新增隐私断言：assembled names/array/repr 不含 raw body、Token、URL query 或私有路径。

## Task 3: 训练数据边界与可重复 Logistic Regression

**Files:** `contracts.py`, `baseline_experiment.py`, `training_tests/test_training_boundaries.py`

- [ ] 写失败测试：重复 item 或 duplicate/near-duplicate/template/campaign group 跨 split 时 `BaselineExperiment.run` 在训练前拒绝；aware UTC 时间和 schema 必须有效。
- [ ] Red: 运行目标 test method；预期入口缺失或错误接受。
- [ ] 最小实现：集中校验 dataset，要求每个 split 同时存在两类且 validation 每类满足校准下限；Phase 2 拒绝 `synthetic_only=False`。
- [ ] Green: 重跑目标测试。
- [ ] 写失败测试：固定 seed 两次运行的 Python 概率、模型参数、校准参数和阈值一致且概率均在 `[0, 1]`。
- [ ] 最小实现：只在 train 上用 `LogisticRegression(class_weight="balanced", random_state=..., max_iter=...)` 拟合；不使用 test 选择任何参数。
- [ ] Green: 运行 `test_training_boundaries.py` 全文件。

## Task 4: Validation-only 概率校准

**Files:** `baseline_experiment.py`, `contracts.py`, `training_tests/test_calibration_abstention.py`

- [ ] 写失败测试：校准器只在 validation 上拟合，输出确定且限制在 `[0,1]`，metadata 同时记录 validation 的校准前/后 Brier Score 和 sigmoid 参数。
- [ ] Red: 运行目标 test method；预期校准接口或 metadata 尚不存在。
- [ ] 最小实现：冻结 train 模型；只用 validation decision score 拟合一维 sigmoid/Platt Logistic Regression，并通过公开 `CalibratedProbabilityModel` 组合预测。
- [ ] Green: 重跑目标测试。
- [ ] 写失败测试：只改变 test 标签后，训练模型概率、校准参数和阈值不变；最小修正任何泄漏并重跑。小样本不足必须抛稳定错误，不回退使用 test。

## Task 5: Validation-only 不确定拒判

**Files:** `contracts.py`, `baseline_experiment.py`, `training_tests/test_calibration_abstention.py`

- [ ] 写失败测试：`AbstentionThresholds` 拒绝 `benign_threshold >= phishing_threshold` 或越界值；边界使用 `<=` confident-benign、`>=` confident-phishing，中间为 uncertain。
- [ ] Red: 运行目标 test；预期阈值类型或分类行为缺失。
- [ ] 最小实现：不可变类型在 `__post_init__` 校验，`classify` 不把 uncertain 映射到任一二分类标签。
- [ ] Green: 重跑目标测试。
- [ ] 写失败测试：阈值只由 validation 概率/标签确定，metadata 记录固定 selection objective 与 validation 指标；最小实现以确定性候选搜索选择“先最少高置信错误、再最大覆盖、最后稳定阈值顺序”的阈值对。

## Task 6: Test-only 分组评估与安全报告

**Files:** `contracts.py`, `baseline_experiment.py`, `training_tests/test_evaluation_reporting.py`

- [ ] 写失败测试：最终 `EvaluationReport` 只对 test 样本计算 overall、zh、en、mixed、各存在 source group 和命中 cutoff 的 time-test；train/validation 标签变化不得作为 test 指标输入。
- [ ] Red: 运行目标 test；预期 report/groups 尚不存在。
- [ ] 最小实现：计算 sample count、phishing recall、benign FPR、precision、F1、ROC AUC、PR AUC、Brier、high-confidence phishing precision、abstention、confusion matrix 和推理耗时摘要。uncertain 从二分类 confusion/precision/recall/F1 中排除并单独计 abstention。
- [ ] Green: 重跑目标测试。
- [ ] 写失败测试：空 zh/en/mixed/time 组为 `status="not_evaluated"` 且数值为 `None`，不伪造 0；只有存在的 source group（含 browser/eml/public-source）才报告。
- [ ] 最小实现后重跑至 PASS。
- [ ] 写失败测试：JSON/Markdown 均明确合成数据、不可发布，并且不含 fixture 中的正文、密码、Token、完整 URL query、私有路径或 FeatureVector text input；最小实现稳定序列化并写入 config artifact 目录。

## Task 7: 标准 ONNX 导出与 CPU Runtime 一致性

**Files:** `baseline_experiment.py`, `contracts.py`, `training_tests/test_onnx_validation.py`

- [ ] 写失败测试：`BaselineExperiment.run` 产出有效 ONNX，metadata 的 SHA-256/size/opset/input dimension 与文件一致，size 小于 2 GB，模型无 custom domain/operator 和 external data。
- [ ] Red: 运行目标 test；预期 ONNX artifact/metadata 尚不存在。
- [ ] 最小实现：用 `skl2onnx` 导出 train Logistic Regression，并用 `onnx` 标准 graph API 串接 validation-only sigmoid 校准算子；调用 ONNX checker，拒绝 external data/custom domain，写入临时或 ignored artifacts。
- [ ] Green: 重跑目标测试。
- [ ] 写失败测试：固定合成输入上 Python 与 ONNX Runtime CPU phishing probability 最大绝对误差不超过 config tolerance，输入维度和 feature schema metadata 一致；最小实现固定 ORT 单线程/CPU provider 并验证输出。
- [ ] Green: 运行 `test_onnx_validation.py` 全文件。

## Task 8: 完整合成实验 CLI、依赖记录与生产 Wheel 隔离

**Files:** `synthetic.py`, `run_synthetic_experiment.py`, `docs/TRAINING.md`, `docs/USAGE.md`, `tests/test_build.py`

- [ ] 写失败测试：生产 Wheel 不包含 `shielddome_training`/training code，METADATA 无第三方 Requires-Dist；Red 先增加断言并确认当前构建边界的实际结果（若已通过，记录为 characterization，而非伪造红灯；新增约束改为 `.venv-training` ignore 的真实红绿证据）。
- [ ] 最小实现仅在需要时收紧 `_build_backend.py`；预期现有 `src/` allowlist 已满足，不做无必要改动。
- [ ] 运行合成 CLI 两次到被忽略 artifacts 目录；验证生成 JSON/Markdown/ONNX、概率链路与 SHA 一致，并记录报告仅为 synthetic smoke evidence。
- [ ] 完成 `docs/TRAINING.md`：实际安装版本与许可证、环境创建/测试/实验命令、split 纪律、指标语义、ONNX 验证、产物忽略和非发布限制。更新 `USAGE.md`，不写 Phase 3 能力。

## Task 9: 离线/隐私约束与 Phase 2 最终门禁

**Files:** `training_tests/test_training_boundaries.py`, `test_evaluation_reporting.py`, `DEVELOPMENT_PLAN.md`, `AGENTS.md`

- [ ] 写失败测试：在 patch `socket.socket.connect/connect_ex/bind/listen` 为失败的上下文中运行完整合成实验仍成功；artifact 扫描不含虚构敏感值。最小修正后运行训练测试全套。
- [ ] 用 `$verification-before-completion` 执行：

```powershell
python -m unittest discover -s endpoint_agent/tests -v
endpoint_agent\.venv-training\Scripts\python.exe -m unittest discover -s endpoint_agent/training_tests -v
endpoint_agent\.venv-training\Scripts\python.exe endpoint_agent\training\run_synthetic_experiment.py --artifact-directory endpoint_agent\training\artifacts\acceptance
python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist
git status --short
git diff --stat
git diff -- endpoint_agent
git diff --cached
git status --short -- app shielddome frontend extension web deploy scripts phishingDP-main
```

- [ ] 完整读取每个输出和退出码；检查新增训练 Python 文件、生产 offline guard 扫描范围、Wheel 内容、artifact ignore、模型 SHA/size/opset、ONNX CPU 一致性、JSON/Markdown 合成声明与隐私扫描。
- [ ] 只有全部门禁通过时，将 Phase 2 `Status: pending` 改为 `complete`，Phase 3 保持 `pending`，“下一步”改为 Phase 3；同步 `AGENTS.md` 当前实现状态。任一依赖/ONNX/隔离门禁失败则 Phase 2 改为 `in_progress` 并记录真实阻塞。
- [ ] 状态更新后重新运行两套完整 unittest、合成实验、离线 Wheel 和全部 Git/目录隔离命令。不得 commit 或 push。

## Completion Criteria

- 固定 Feature Assembler 的名称、顺序、类别 unknown、64 维 text 和 missing mask 布局有公开测试，且只接受 feature/corpus schema `2.0`。
- group split 泄漏检查先于训练；train/validation/test 分别只用于拟合、校准/阈值和最终评估。只改 test 标签不改变模型、校准器或阈值。
- Logistic Regression 固定 seed、类别平衡和迭代上限；概率在 `[0,1]` 且重复训练的实质结果一致。
- validation-only sigmoid 校准同时记录校准前/后 Brier；validation-only 阈值满足严格顺序和三态拒判边界。
- test 报告包含要求的整体、语言、来源、时间指标；空组为 not_evaluated；JSON/Markdown 明确只使用合成数据且不可作为发布指标。
- 标准 ONNX 无 custom operator/external data，模型小于 2 GB，SHA/size/opset/input dimension 记录正确；ONNX Runtime CPU 与 Python 概率在明确 tolerance 内一致。
- 实验过程不连接网络、不监听端口、不写入邮件原文；模型/报告/venv/训练数据全部保持 Git 忽略。
- Phase 0–1 测试继续通过；Phase 2 训练测试、完整合成实验和离线生产 Wheel 获得新鲜退出码 0。
- 生产 Wheel 无第三方运行依赖、无训练代码；Phase 3 仍 pending；受保护目录相对基线无修改。
- 没有提交、推送、创建 branch/worktree/PR；由于无 Approved Training Corpus，不产生或宣称可发布生产模型。

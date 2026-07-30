# Phase 2 校准门禁与拒判评估口径收尾 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `$executing-plans` to implement this plan task-by-task in the current working tree. Every behavioral change follows `$tdd` red → green. The user requires Inline Execution: do not create a branch/worktree, commit, push, or PR.

**Goal:** 只修复 Phase 2 的 validation-only 校准选择、拒判感知指标和合成评估发布资格表达，使后续模型比较不会被劣化校准或选择性指标误导。

**Architecture:** `BaselineExperiment.run` 继续是唯一实验深入口。它同时拟合 identity 与 validation sigmoid 两个校准候选，只根据 validation Brier 和明确容差选择最终概率链路；阈值、ONNX 和 test-only 报告都消费该最终链路。`EvaluationMetrics.from_predictions` 成为公开纯计算 seam，以三态预测保留 uncertain 计数，并让实验分组与直接指标测试共享同一口径。

**Tech Stack:** Python 3.12；标准库 `dataclasses`/`enum`/`json`；隔离训练环境中的 NumPy 2.2.6、SciPy 1.15.3、scikit-learn 1.7.2、ONNX 1.18.0、ONNX Runtime 1.22.1、skl2onnx 1.19.1；标准库 `unittest`。

## Global Constraints

- 只能修改 `endpoint_agent/`；`app/`、`shielddome/`、`frontend/`、`extension/`、`web/`、`deploy/`、`scripts/`、`phishingDP-main/` 保持基线不变。
- 只收尾 Phase 2；不实施 Phase 3，不下载编码器或数据集，不训练生产模型。
- 不修改 `FEATURE_SCHEMA_VERSION = "2.0"` 或 `CORPUS_SCHEMA_VERSION = "2.0"`，不改变 140 维 Feature Assembler 布局。
- 校准选择、阈值选择都只能读取 validation；test 只能生成最终评估，改变 test 标签不能改变模型、校准选择、阈值或 ONNX SHA。
- 合成数据始终 `release_eligible=false`；没有 Approved Training Corpus 时不得输出发布达标结论。
- ONNX 只使用标准算子、CPU Runtime、无 external data；identity 与 sigmoid 两条路径都必须验证 Python/ONNX 概率一致。
- 生产 Wheel 保持零第三方运行依赖且不包含训练代码；不新增网络、监听端口、遥测或邮件原文写入。
- 不提交、不推送、不创建 branch、worktree 或 PR；以测试和差异检查点代替提交步骤。

## File Map

- Create `endpoint_agent/docs/plans/2026-07-30-phase-2-calibration-metrics-audit.md`: 本次 Phase 2 收尾的可执行 TDD 计划和验收门禁。
- Modify `endpoint_agent/training/shielddome_training/contracts.py`: 增加不可变校准选择记录、校准容差/评估资格配置、拒判感知计数与公开指标构造器、发布资格原因。
- Modify `endpoint_agent/training/shielddome_training/baseline_experiment.py`: validation-only 校准候选选择、identity/sigmoid 统一概率模型、三态分组指标、两种 ONNX 图和 metadata。
- Modify `endpoint_agent/training/shielddome_training/__init__.py`: 导出新的 `CalibrationSelection` 公开契约。
- Modify `endpoint_agent/training/run_synthetic_experiment.py`: 输出实际选中校准方式、Brier 三值和发布资格状态。
- Modify `endpoint_agent/training_tests/test_calibration_abstention.py`: 校准改善/劣化、test 隔离、重复性和两条 ONNX 路径的公开行为测试。
- Modify `endpoint_agent/training_tests/test_evaluation_reporting.py`: 三态 confusion、总体/分组拒判口径、可复算计数和发布资格测试。
- Modify `endpoint_agent/training_tests/test_onnx_validation.py`: ONNX metadata 接受并核对最终选中校准方式。
- Modify `endpoint_agent/training_tests/test_training_boundaries.py`: 配置容差和显式最小评估样本数的验证与重复性断言。
- Modify `endpoint_agent/docs/TRAINING.md`: 校准选择规则、指标公式、三态 confusion、样本资格状态和真实 Approved Corpus 阻塞。
- Modify `endpoint_agent/docs/USAGE.md`: 补充 Phase 2 收尾后的非发布边界和 Phase 3 数据前置条件。
- Modify `endpoint_agent/AGENTS.md`: 更新训练侧实际校准/指标语义，避免继续描述“无条件 sigmoid”。
- Modify `endpoint_agent/DEVELOPMENT_PLAN.md`: Phase 2 门禁通过时保持 `complete`、Phase 3 保持 `pending`，并在下一步明确 Approved Training Corpus 是阻塞条件。

## Public Interfaces

```python
@dataclass(frozen=True, slots=True)
class CalibrationSelection:
    candidate_method: str
    selected_method: str
    selection_reason: str
    improvement_tolerance: float
    brier_before: float
    brier_candidate: float
    brier_selected: float
    fitted_split: DatasetSplit
    validation_sample_count: int
    candidate_parameters: tuple[tuple[str, float], ...]

@dataclass(frozen=True, slots=True)
class BaselineExperimentConfig:
    artifact_directory: Path
    random_seed: int = 20260730
    max_iterations: int = 1000
    onnx_opset: int = 17
    onnx_probability_tolerance: float = 1e-6
    calibration_improvement_tolerance: float = 1e-12
    minimum_release_evaluation_group_size: int | None = None
    time_test_cutoff: datetime | None = None

@dataclass(frozen=True, slots=True)
class EvaluationMetrics:
    status: str
    sample_count: int
    classified_count: int
    total_phishing_count: int
    total_benign_count: int
    confident_benign_count: int
    confident_phishing_count: int
    uncertain_count: int
    uncertain_phishing_count: int
    uncertain_benign_count: int
    phishing_recall: float | None
    benign_false_positive_rate: float | None
    precision: float | None
    f1: float | None
    roc_auc: float | None
    pr_auc: float | None
    brier_score: float | None
    high_confidence_phishing_precision: float | None
    abstention_rate: float | None
    phishing_abstention_rate: float | None
    benign_abstention_rate: float | None
    confusion_matrix: tuple[tuple[int, int, int], tuple[int, int, int]] | None
    inference_duration_ms: tuple[tuple[str, float], ...] | None

    @classmethod
    def from_predictions(
        cls,
        labels: tuple[TrainingLabel, ...],
        probabilities: tuple[float, ...],
        states: tuple[ConfidenceState, ...],
        inference_durations_ms: tuple[float, ...],
        *,
        status: str,
    ) -> "EvaluationMetrics": ...

@dataclass(frozen=True, slots=True)
class EvaluationReport:
    synthetic_only: bool
    release_eligible: bool
    release_eligibility_status: str
    release_eligibility_reason: str
    disclaimer: str
    groups: tuple[tuple[str, EvaluationMetrics], ...]
```

`confusion_matrix` 的行依次为真实 benign/phishing，列依次为 predicted confident-benign/uncertain/confident-phishing。`BaselineModelMetadata.calibration` 保存 `CalibrationSelection`；`CalibratedProbabilityModel.calibration_method` 决定 `predict_probabilities` 使用 identity 或 sigmoid。

## Task 1: 劣化校准回退 identity

**Files:** `training_tests/test_calibration_abstention.py`, `training/shielddome_training/contracts.py`, `training/shielddome_training/baseline_experiment.py`, `training/shielddome_training/__init__.py`

- [ ] **Red:** 新增 `test_worse_validation_brier_selects_identity`，用当前合成 dataset 调用 `BaselineExperiment.run`，断言 `metadata.calibration.selected_method == "identity"`、`brier_selected == brier_before`、reason 为稳定非敏感码、最终 Python 概率等于 `predict_uncalibrated_probabilities`。
- [ ] 运行 `endpoint_agent\.venv-training\Scripts\python.exe -m unittest endpoint_agent.training_tests.test_calibration_abstention.CalibrationAndAbstentionTests.test_worse_validation_brier_selects_identity -v`；预期因 `BaselineModelMetadata` 没有 `calibration` 或仍无条件选择 sigmoid 而 FAIL。
- [ ] **Green:** 增加 `CalibrationSelection`、config 的 `calibration_improvement_tolerance=1e-12` 及有限非负校验。拟合 sigmoid candidate 后只在 `candidate_brier + tolerance < raw_brier` 时选择 `sigmoid_on_validation_probability`，否则选择 `identity`；identity 预测直接返回 raw probability。阈值使用 selected validation probabilities。
- [ ] 重跑目标测试，预期 PASS、退出码 0；再运行 `test_calibration_abstention.py` 观察旧契约断言的真实失败并只按新公开契约更新。
- [ ] **差异检查点:** `git diff -- endpoint_agent/training/shielddome_training/contracts.py endpoint_agent/training/shielddome_training/baseline_experiment.py endpoint_agent/training_tests/test_calibration_abstention.py`，确认没有读取 test 进行选择。

## Task 2: 校准改善路径、test 隔离和重复性

**Files:** `training_tests/test_calibration_abstention.py`, `training/shielddome_training/baseline_experiment.py`

- [ ] **Red:** 新增 `test_better_validation_brier_selects_sigmoid`，仅翻转 validation 标签构造校准确实改善的合成样本，断言 candidate Brier 小于 before、selected 为 sigmoid、selected Brier 等于 candidate。
- [ ] 运行该单测；预期在改善路径尚未完整记录或选择时 FAIL。
- [ ] **Green:** 让 `CalibrationSelection` 完整记录 candidate method、selected method、reason、before/candidate/selected Brier、fitted split、validation count、容差和 candidate 参数；所有字段由 validation 结果产生。
- [ ] 重跑该单测至 PASS。
- [ ] **Red:** 扩展 test 标签变化测试，断言 calibration selection、candidate parameters、selected probabilities、thresholds 和 ONNX SHA 均不变；新增两次相同运行的 selection 完全相等断言。
- [ ] 运行两个目标测试；预期旧 metadata 名称或选择记录不完整导致 FAIL。
- [ ] **Green:** 报告/metadata 只序列化选定结果和 validation 候选记录，不从 test 路径回写任何模型状态。
- [ ] 重跑 `test_calibration_abstention.py` 全文件至 PASS。

## Task 3: identity 与 sigmoid ONNX 一致性

**Files:** `training_tests/test_calibration_abstention.py`, `training_tests/test_onnx_validation.py`, `training/shielddome_training/baseline_experiment.py`

- [ ] **Red:** 在 identity dataset 和 validation 标签翻转的 sigmoid dataset 上分别运行实验，断言两者 `onnx_validation.consistent`、最大误差小于容差，ONNX metadata 的 `calibration_method` 等于最终选择。
- [ ] 运行新增单测；预期 identity 图仍强制串接 sigmoid 或 metadata 固定为 sigmoid 而 FAIL。
- [ ] **Green:** ONNX 先统一 Gather phishing probability；identity 路径直接用标准 `Identity` 暴露选定概率，sigmoid 路径串接现有 Mul/Add/Sigmoid；两者都输出固定 `[N,2]` `selected_probabilities`，metadata 记录 selected method，validation 按同值核对。
- [ ] 重跑目标测试至 PASS，再运行 `test_onnx_validation.py` 全文件，确认标准算子、无 external data、SHA/size/opset 约束继续通过。

## Task 4: 拒判感知正式指标与三态 confusion

**Files:** `training_tests/test_evaluation_reporting.py`, `training/shielddome_training/contracts.py`, `training/shielddome_training/baseline_experiment.py`

- [ ] **Red:** 通过公开 `EvaluationMetrics.from_predictions` 写一个 worked-example：真实标签 `(phishing, phishing, benign, benign)`，状态 `(uncertain, confident-benign, uncertain, confident-phishing)`。断言 recall `0.0`、benign FPR `0.5`、uncertain phishing/benign 各 1、三态 confusion 为 `((0,1,1),(1,1,0))`。
- [ ] 运行该单测；预期公开构造器或三态字段不存在而 FAIL。
- [ ] **Green:** 最小实现公开纯计算构造器；formal recall 分母为全部真实 phishing，formal benign FPR 分母为全部真实 benign，high-confidence precision 只以 confident-phishing 为预测正类，uncertain 保留在计数和三态 confusion 中。
- [ ] 重跑该单测至 PASS。
- [ ] **Red:** 分别增加“全部 phishing uncertain 时 recall=0”“部分 phishing uncertain 仍在分母”“uncertain benign 不计 FP”“confident-benign phishing 是漏检”“HC precision 只看 confident-phishing”的独立 public examples，并断言计数可复算 abstention 比率。
- [ ] 每新增一个测试即单独运行确认 RED，再补最小计算分支并运行至 GREEN；不得一次写完全部测试后再实现。
- [ ] 改造 `BaselineExperiment` 分组评估只调用该公开构造器；运行 `test_evaluation_reporting.py` 全文件。

## Task 5: 分组同口径和评估发布资格

**Files:** `training_tests/test_evaluation_reporting.py`, `training_tests/test_training_boundaries.py`, `training/shielddome_training/contracts.py`, `training/shielddome_training/baseline_experiment.py`

- [ ] **Red:** 运行合成实验并断言 overall、语言、来源、time:test 的每个非空组都满足 `sample_count == total_phishing_count + total_benign_count`、`uncertain_count == uncertain_phishing_count + uncertain_benign_count`，比率可以从计数复算；空组仍为 `not_evaluated`。
- [ ] 运行目标测试；预期现有分组缺少计数而 FAIL。
- [ ] **Green:** group filter 保持 test-only，只把标签/概率/状态/耗时传给统一构造器；不复制第二套指标公式。
- [ ] 重跑目标测试至 PASS。
- [ ] **Red:** 默认 config 下断言所有非空合成分组为 `not_release_evaluable`、report `release_eligible=false` 且 reason 为 `synthetic_dataset_no_approved_corpus`；显式 `minimum_release_evaluation_group_size=10` 时 8 样本 overall 为 `insufficient_sample` 但仍保留指标；0 或负值配置被拒绝。
- [ ] 运行目标测试；预期 status/资格字段不存在或仍为 `evaluated` 而 FAIL。
- [ ] **Green:** config 默认 `None` 表示没有经批准的发布样本门槛，非空组为 `not_release_evaluable`；显式正整数且组样本不足时为 `insufficient_sample`，达到时为 `evaluated`，但 synthetic report 始终不具发布资格。
- [ ] 重跑 `test_evaluation_reporting.py` 和 `test_training_boundaries.py` 至 PASS。

## Task 6: JSON、Markdown、CLI 与文档同步

**Files:** `contracts.py`, `baseline_experiment.py`, `run_synthetic_experiment.py`, `docs/TRAINING.md`, `docs/USAGE.md`, `AGENTS.md`, `DEVELOPMENT_PLAN.md`, `training_tests/test_evaluation_reporting.py`

- [ ] **Red:** 扩展报告测试，断言 JSON/Markdown 包含校准 candidate/selected/reason、Brier before/candidate/selected、三态计数/比率、confusion 列定义、release eligibility status/reason 和合成免责声明；同时继续扫描正文、密码、Token、完整 URL 查询参数和私有路径。
- [ ] 运行目标测试；预期缺少新字段/定义而 FAIL。
- [ ] **Green:** 更新稳定 JSON 和 Markdown 输出；CLI 摘要输出选中方法、三项 Brier 和资格状态，不输出样本内容。
- [ ] 重跑目标测试至 PASS，并运行一次 CLI 到 `endpoint_agent/training/artifacts/phase2-calibration-audit` 人工核对输出。
- [ ] 更新 `TRAINING.md` 精确定义 formal recall/FPR/HC precision、三态 confusion 和校准门禁；更新 `USAGE.md`/`AGENTS.md` 的实际行为。`DEVELOPMENT_PLAN.md` 保持 Phase 2 complete、Phase 3 pending，并将下一步说明改为“Phase 3 以真实 Approved Training Corpus 为阻塞条件”。
- [ ] **文档差异检查点:** `git diff -- endpoint_agent/docs endpoint_agent/AGENTS.md endpoint_agent/DEVELOPMENT_PLAN.md endpoint_agent/training/run_synthetic_experiment.py`。

## Task 7: Phase 2 最终门禁

**Files:** 仅在发现本计划范围内失败时修改对应 `endpoint_agent/` 文件。

- [ ] Announce and use `$verification-before-completion`；运行并完整读取：

```powershell
python -m unittest discover -s endpoint_agent/tests -v
.\endpoint_agent\.venv-training\Scripts\python.exe -m unittest discover -s endpoint_agent/training_tests -v
.\endpoint_agent\.venv-training\Scripts\python.exe endpoint_agent\training\run_synthetic_experiment.py --artifact-directory endpoint_agent\training\artifacts\phase2-calibration-audit
python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist
git status --short
git diff --stat
git diff -- endpoint_agent
git diff --cached
git status --short -- app shielddome frontend extension web deploy scripts phishingDP-main
```

- [ ] 核对生产/训练 unittest 的运行数、failure/error/skip 和退出码；记录 CLI 的 selected calibration、三项 Brier、release eligibility、ONNX SHA/size/max error/tolerance。
- [ ] 检查 `evaluation.json`/`evaluation.md` 的三态计数可复算、合成免责声明、资格状态和敏感内容扫描；检查 `baseline_model.onnx` metadata 与 Python 选择一致。
- [ ] 核对 Wheel 退出码 0、无训练包/Requires-Dist；检查 artifacts、venv、模型、报告仍被 ignore。
- [ ] 核对 Phase 2 为 `complete`、Phase 3 为 `pending`、下一步注明 Approved Training Corpus 阻塞；受保护目录状态与任务基线一致。
- [ ] 任一门禁失败时将 Phase 2 改为 `in_progress` 并记录真实阻塞；全部门禁通过时保持 `complete`。不得 commit 或 push。

## Completion Criteria

- validation sigmoid 只有在 `candidate_brier + tolerance < raw_brier` 时被选中，否则 identity；选择记录完整、稳定且与 test 无关。
- identity 与 sigmoid 两条 Python/ONNX 路径都在 CPU Runtime 明确容差内一致，ONNX metadata 是最终选择而非固定声明。
- formal phishing recall、benign FPR 和 HC phishing precision 使用本计划定义；uncertain 不从真实标签分母或 confusion 中消失。
- 每个非空分组都有可复算的三态计数；空分组为 `not_evaluated`。
- synthetic fixture 始终不可发布；未配置经批准样本门槛时为 `not_release_evaluable`，显式门槛不足时为 `insufficient_sample`。
- JSON/Markdown/CLI/docs 使用一致口径且不含原始邮件、凭据、完整 URL 查询参数或私有路径。
- 两套 unittest、合成实验、ONNX 验证和离线生产 Wheel 均有新鲜退出码 0；受保护目录无新增修改。
- Phase 2 保持 `complete` 仅在全部门禁通过后；Phase 3 保持 `pending`，没有下载数据/编码器、没有实现 Phase 3、没有 commit/push。

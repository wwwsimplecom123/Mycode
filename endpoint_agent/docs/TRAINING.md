# ShieldDome Endpoint Agent Phase 2 训练说明

## 适用范围

本文只描述 Phase 2 的开发期基线链路：固定 FeatureVector 组装、Logistic Regression、validation-only sigmoid 校准候选与质量门禁、validation-only 不确定拒判阈值、test-only 拒判感知评估、JSON/Markdown 报告和 ONNX Runtime CPU 一致性验证。

仓库当前没有 Approved Training Corpus。内置实验只使用 24 个纯合成样本，用于证明代码链路可运行；其指标不是生产质量证据，生成模型不是 Unified Model Release，也不得发布到终端。

训练代码位于 `endpoint_agent/training/shielddome_training/`，不会进入生产 Wheel。生产 `shielddome_endpoint` Wheel 继续保持零第三方运行依赖。

## 隔离环境

在仓库根目录执行：

```powershell
python -m venv endpoint_agent\.venv-training
.\endpoint_agent\.venv-training\Scripts\python.exe -m pip install -r .\endpoint_agent\requirements-training.txt
```

`.venv-training/` 已由 `endpoint_agent/.gitignore` 忽略。不要把这些包安装为 Endpoint Agent 生产运行依赖，也不要修改根目录或全局 Python 环境来迁就训练代码。

## 固定版本与许可证

下表来自 2026-07-30 实际安装环境的 distribution metadata。许可证名称是顶层包声明摘要；Wheel 内随附的完整 LICENSE/NOTICE 和第三方组件说明仍是分发审计依据。

| Distribution | Version | Declared license |
| --- | --- | --- |
| NumPy | 2.2.6 | BSD |
| SciPy | 1.15.3 | BSD |
| scikit-learn | 1.7.2 | BSD-3-Clause |
| ONNX | 1.18.0 | Apache-2.0 |
| ONNX Runtime | 1.22.1 | MIT |
| skl2onnx | 1.19.1 | Apache-2.0 |
| coloredlogs | 15.0.1 | MIT |
| flatbuffers | 25.12.19 | Apache-2.0 |
| humanfriendly | 10.0 | MIT |
| joblib | 1.5.3 | BSD-3-Clause |
| mpmath | 1.3.0 | BSD |
| packaging | 26.2 | Apache-2.0 OR BSD-2-Clause |
| protobuf | 7.35.1 | BSD-3-Clause |
| pyreadline3 | 3.5.6 | BSD |
| sympy | 1.14.0 | BSD |
| threadpoolctl | 3.6.0 | BSD |
| typing_extensions | 4.16.0 | PSF-2.0 |

`requirements-training.txt` 固定直接和已解析的传递依赖；更新任何版本前必须重新运行训练测试、许可证核对和 ONNX 一致性验证。生产 `pyproject.toml` 的 `dependencies = []` 不得因此改变。

## 数据边界

`TrainingDataset` 只接受 `FEATURE_SCHEMA_VERSION = "2.0"` 和 `CORPUS_SCHEMA_VERSION = "3.0"`。同一 item、duplicate、near-duplicate、template 或 campaign 不得跨 train、validation、test。`3.0` corpus manifest 要求完整的人工审核、来源证据、授权期限、隐私批准，以及分别显式允许内部训练和终端模型权重分发；manifest digest 覆盖这些事实。

- train 只拟合带 `class_weight="balanced"` 和固定 seed 的 Logistic Regression；
- validation 只拟合一维 sigmoid 校准候选、按 Brier Score 选择 identity 或 sigmoid，并选择 benign/phishing 阈值；
- test 只生成最终分语言、分来源、分时间指标；
- 改变 test 标签不得改变模型、校准候选、校准选择、阈值或 ONNX SHA；
- validation 每个标签少于两个样本时明确失败，不回退使用 test；
- Phase 2 入口拒绝 `synthetic_only=false`，避免把当前链路误用于未治理真实数据。

上述准入加固仍不代表 Approved Training Corpus 已存在。Phase 2 合成 fixture 没有真实语料授权证据，只能验证链路；不得因 schema 更新而用于 Phase 3 模型选择、训练或发布。

Feature Assembler 使用固定 140 维布局：26 个 numeric、固定 one-hot categorical、64 个 Phase 1 text Hashing bucket 和 9 个 missing-mask 位。未知类别进入固定 `unknown` bucket，不拟合 vocabulary，不保存正文或 Token。

## 运行测试

生产包与 Phase 0–1 回归：

```powershell
python -m unittest discover -s endpoint_agent/tests -v
```

Phase 2 训练测试：

```powershell
.\endpoint_agent\.venv-training\Scripts\python.exe -m unittest discover -s endpoint_agent/training_tests -v
```

训练测试覆盖 split 泄漏、schema、固定布局、unknown bucket、重复训练、validation-only 校准与阈值、test 标签隔离、分组指标、空组、报告隐私、socket 禁止、ONNX metadata、模型大小/SHA 和 Python/ONNX 概率容差。

## 运行合成实验

```powershell
.\endpoint_agent\.venv-training\Scripts\python.exe endpoint_agent\training\run_synthetic_experiment.py `
  --artifact-directory endpoint_agent\training\artifacts\acceptance
```

命令生成：

- `baseline_model.onnx`；
- `evaluation.json`；
- `evaluation.md`。

`training/artifacts/` 已忽略。报告固定声明 `synthetic_only=true` 和 `release_eligible=false`，并记录模型/feature/corpus/assembler 版本、校准 candidate/selected/reason、validation Brier before/candidate/selected、拒判阈值、分组指标、ONNX opset/SHA/大小和 Runtime 一致性结果。不得提交这些实际 artifacts。

## 校准质量门禁

基线候选是 Logistic Regression 的未校准 phishing probability，方法名为 `identity`。校准候选是只在 validation probability 上拟合的一维 sigmoid，方法名为 `sigmoid_on_validation_probability`。

选择只比较 validation Brier Score：仅当 `candidate_brier + calibration_improvement_tolerance < raw_brier` 时采用 sigmoid；否则使用 identity。默认 tolerance 为 `1e-12`，用于屏蔽浮点噪声，可通过 `BaselineExperimentConfig` 显式调整。阈值选择、test 评估和 ONNX 都使用最终选中的概率，不读取 test 标签决定校准方式。

metadata 同时保留 candidate method、selected method、稳定 selection reason、Brier before/candidate/selected、candidate 参数、validation split、validation 样本数和 tolerance。identity 被选中时，Python 与 ONNX 都直接输出未校准概率；不会把成功拟合等同于应该采用。

## 指标语义

报告包含 sample count、真实 phishing/benign 总数、三种 confidence state 计数、phishing recall、benign false-positive rate、precision、F1、ROC AUC、PR AUC、Brier Score、high-confidence phishing precision、整体/分标签 abstention rate、三态 confusion matrix 和推理耗时摘要。

正式口径如下：

- `phishing_recall = 真实 phishing 且 confident-phishing / 全部真实 phishing`；uncertain phishing 和 confident-benign phishing 都留在分母中。
- `benign_false_positive_rate = 真实 benign 且 confident-phishing / 全部真实 benign`；uncertain benign 不算 false positive，但仍留在 benign 分母并单独计数。
- `high_confidence_phishing_precision = 真实 phishing 且 confident-phishing / 全部 confident-phishing`。
- `phishing_abstention_rate` 和 `benign_abstention_rate` 分别以全部真实 phishing/benign 为分母。

confusion matrix 的两行依次是实际 benign、实际 phishing；三列依次是 predicted confident-benign、uncertain、confident-phishing。这样 uncertain 不会从 confusion 或正式 recall 分母中静默消失。ROC AUC、PR AUC 和 Brier 使用全部概率样本。空分组使用 `not_evaluated` 和 `null`，不会用 0 冒充指标。

合成 fixture 始终 `release_eligible=false`，reason 为 `synthetic_dataset_no_approved_corpus`。默认未配置经批准的最小发布评估样本数时，非空分组为 `not_release_evaluable`；显式配置 `minimum_release_evaluation_group_size` 后，小于该值的分组为 `insufficient_sample`，但仍展示可复算指标。Phase 2 不自行规定正式样本下限，也不会因为少量合成样本指标为 1.0 而标记发布达标。

## ONNX 边界

基线 Logistic Regression 由 skl2onnx 转换；identity 使用标准 `Identity`，sigmoid 校准链路使用标准 `Mul`、`Add` 和 `Sigmoid` 算子。模型不使用 custom operator 或 external data。ONNX metadata 记录最终选中的 calibration method。ONNX Runtime 固定 CPU provider 和单线程顺序执行，对固定合成输入比较 Python/ONNX phishing probability，默认最大绝对误差容差为 `1e-6`。模型必须小于 2 GB，并记录规范 SHA-256。

本代码是训练侧验证，不是 Phase 4B 的生产 Local Inference adapter。Phase 4A 已实现模型无关的 Local Inference seam、Model Assessment 校验、失败/超时降级和 Risk Fusion，但没有加载这里生成的 ONNX，也没有声称完成真实模型 3 秒推理验证。Phase 3 仍受真实、许可明确、人工审核且去泄漏的 Approved Training Corpus 阻塞并保持 `pending`；不能用当前合成 fixture 选择正式文本编码模型或满足 Phase 4B。

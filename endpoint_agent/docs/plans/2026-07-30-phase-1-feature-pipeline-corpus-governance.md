# Phase 1 Feature Pipeline 与 Corpus Governance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. 本任务已明确使用 Inline Execution，不创建或切换分支、不创建 worktree、不提交或推送 Git。

**Goal:** 仅完成 Phase 1，以一个确定性 `FeaturePipeline` 统一训练与 Endpoint 特征转换，并以一个 `CorpusGovernance.prepare` 入口完成 Approved Training Corpus 的准入、标签语义、去重、分组、确定性 split 与安全 manifest。

**Architecture:** `FeaturePipeline` 直接消费 Phase 0 的 `MailObservation`，返回原有 `FeatureVector`；结构特征使用固定顺序，文本表示使用标准库 SHA-256 构造固定 64 维、L2 规范化且不保留 Token 的 Hashing 向量，`text_input` 始终为 `None`。`CorpusGovernance` 使用不可变候选、批准项、拒绝项、manifest 和 snapshot 类型，将准入到 split 的全部策略隐藏在 `prepare` 后；`PrivacyScanner` 只返回稳定违规代码，不回显敏感值。

**Tech Stack:** Python 3.12 标准库（`dataclasses`、`enum.StrEnum`、`hashlib`、`email.utils`、`ipaddress`、`math`、`re`、`unicodedata`）、`unittest`、现有零外部依赖 PEP 517 wheel 后端。

## Global Constraints

- 只能修改 `endpoint_agent/`；`app/`、`shielddome/`、`frontend/`、`extension/`、`web/`、`deploy/`、`scripts/`、`phishingDP-main/` 保持原封不动。
- 只实施 Phase 1；不训练或加载模型，不实现 Logistic Regression、TensorFlow、Keras、ONNX、概率校准、拒判、Detection Kernel、Native Messaging、数据库、加密、托盘或控制台。
- 不添加 HTTP、WebSocket、网络客户端、监听端口、遥测或外部数据下载。
- 不导入或运行 `phishingDP-main`；不复制其代码、日志、预测结果、指标静态文件或 NumPy 产物。
- 测试只使用合成邮件、`.test` 虚构域名和虚构 corpus 元数据。
- 继续使用 `unittest`；所有新增行为通过已确认公开 seam 做单个红绿循环，不测试私有辅助函数。
- `FeaturePipeline.transform(observation: MailObservation) -> FeatureVector` 是训练与 Endpoint 共用的唯一转换逻辑；转换无网络、无文件写入、无随机状态。
- 文本 Hashing 使用 SHA-256、固定 64 维、固定 L2 规范化和有界 8192 字符输入；不使用 Python `hash()`、TF-IDF vocabulary、NLTK 或英文专用停用词。
- `FeatureVector.text_input` 必须为 `None`；原始正文、原始 Token、完整 URL、附件内容不得进入输出。
- corpus 原始数据、snapshot、训练输出继续由 `endpoint_agent/.gitignore` 排除；不创建任何真实数据文件。
- 不包含 commit、push、branch 或 PR 步骤；每个任务以测试和差异检查点结束。

## Public Interfaces

```python
class FeaturePipeline:
    def transform(self, observation: MailObservation) -> FeatureVector: ...

class CorpusLabel(StrEnum):
    BENIGN = "benign"
    PHISHING = "phishing"

class SourceLabel(StrEnum):
    SPAM = "spam"
    HAM = "ham"
    PHISHING = "phishing"
    BENIGN = "benign"

class ReviewStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"

class DatasetSplit(StrEnum):
    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"

@dataclass(frozen=True, slots=True)
class CorpusCandidate:
    item_id: str
    final_label: CorpusLabel
    original_label: SourceLabel
    label_source: str
    review_status: ReviewStatus
    license_source: str
    raw_hash: str
    normalized_hash: str
    template_group: str
    campaign_group: str
    language_group: str
    source_group: str
    ingested_at: datetime
    feature_schema_version: str
    sanitized_training_representation: str

@dataclass(frozen=True, slots=True)
class CorpusRejection:
    item_id: str
    reason: str

@dataclass(frozen=True, slots=True)
class ApprovedCorpusItem:
    candidate: CorpusCandidate
    duplicate_group: str
    split: DatasetSplit

@dataclass(frozen=True, slots=True)
class CorpusManifestEntry:
    item_id: str
    final_label: CorpusLabel
    split: DatasetSplit
    duplicate_group: str
    template_group: str
    campaign_group: str
    language_group: str
    source_group: str
    feature_schema_version: str

@dataclass(frozen=True, slots=True)
class CorpusManifest:
    entries: tuple[CorpusManifestEntry, ...]
    schema_version: str = CORPUS_SCHEMA_VERSION

@dataclass(frozen=True, slots=True)
class CorpusSnapshot:
    approved_items: tuple[ApprovedCorpusItem, ...]
    rejections: tuple[CorpusRejection, ...]
    manifest: CorpusManifest
    schema_version: str = CORPUS_SCHEMA_VERSION

class CorpusGovernance:
    def prepare(self, candidates: tuple[CorpusCandidate, ...]) -> CorpusSnapshot: ...

@dataclass(frozen=True, slots=True)
class PrivacyScanResult:
    safe: bool
    violations: tuple[str, ...]

class PrivacyScanner:
    def scan_feature_vector(
        self,
        vector: FeatureVector,
        forbidden_values: tuple[str, ...] = (),
    ) -> PrivacyScanResult: ...

    def scan_manifest(
        self,
        manifest: CorpusManifest,
        forbidden_values: tuple[str, ...] = (),
    ) -> PrivacyScanResult: ...
```

## File Map

- Create `endpoint_agent/src/shielddome_endpoint/feature_pipeline.py`: `FeaturePipeline` 与固定顺序特征/Hashing 实现；不持久化、不进行 I/O。
- Create `endpoint_agent/src/shielddome_endpoint/corpus.py`: corpus 枚举、不可变公开类型和 `CorpusGovernance.prepare`。
- Create `endpoint_agent/src/shielddome_endpoint/privacy.py`: `PrivacyScanResult` 与 FeatureVector/manifest 隐私扫描。
- Modify `endpoint_agent/src/shielddome_endpoint/__init__.py`: 公开导出 Phase 1 interface 和版本常量。
- Test `endpoint_agent/tests/test_feature_pipeline.py`: 只通过 `FeaturePipeline.transform` 验证确定性、结构特征、跨进程 Hashing 和训练/Endpoint 一致性。
- Test `endpoint_agent/tests/test_corpus_governance.py`: 只通过 `CorpusGovernance.prepare` 验证准入、标签、去重和 split。
- Test `endpoint_agent/tests/test_privacy.py`: 只通过 `PrivacyScanner` 验证 FeatureVector 与 manifest 不泄漏。
- Modify `endpoint_agent/tests/test_package.py`: 验证 Phase 1 public interface 可从根包导入。
- Modify `endpoint_agent/tests/test_build.py`: 验证离线 wheel 包含 Phase 1 模块。
- Modify `endpoint_agent/AGENTS.md`: 验收通过后把“当前只完成 Phase 0”改为 Phase 0-1 实际范围。
- Modify `endpoint_agent/docs/USAGE.md`: 增加 Phase 1 API、合成示例、数据治理和验证说明。
- Modify `endpoint_agent/DEVELOPMENT_PLAN.md`: 仅在最终门禁通过后将 Phase 1 改为 complete，保持 Phase 2 pending，下一步改为 Phase 2。

---

### Task 1: FeaturePipeline 确定性基础与隐私安全表示

**Files:**
- Create: `endpoint_agent/tests/test_feature_pipeline.py`
- Create: `endpoint_agent/src/shielddome_endpoint/feature_pipeline.py`

**Interfaces:**
- Consumes: `MailObservation`, `FeatureVector`, `FEATURE_SCHEMA_VERSION`。
- Produces: `FeaturePipeline.transform(observation) -> FeatureVector`；`TEXT_HASH_DIMENSION = 64`。

- [ ] **Step 1: 写一个失败测试：相同观察的固定 Hashing 表示在当前进程与子进程中一致，且 schema/顺序/隐私字段稳定**

```python
def test_transform_is_deterministic_versioned_ordered_and_drops_raw_text(self):
    observation = make_observation(subject="Ab", sanitized_body_text="中")
    first = FeaturePipeline().transform(observation)
    second = FeaturePipeline().transform(observation)
    self.assertEqual(first, second)
    self.assertEqual(first.schema_version, FEATURE_SCHEMA_VERSION)
    self.assertEqual(first.text_input, None)
    self.assertEqual(len(first.text_vector), 64)
    self.assertEqual(tuple(name for name, _ in first.numeric_features), EXPECTED_NUMERIC_NAMES)
    self.assertEqual(tuple(name for name, _ in first.categorical_features), EXPECTED_CATEGORICAL_NAMES)
    self.assertEqual(
        sha256(json.dumps(first.text_vector, separators=(",", ":")).encode()).hexdigest(),
        "b8ff6c2a6cace9575743ec9a70e0084433342fb4fc22cdb6c275d0f3745e32a4",
    )
    self.assertEqual(run_same_transform_in_subprocess(), first.text_vector)
```

- [ ] **Step 2: 运行红灯**

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_feature_pipeline.py" -v`

Expected: FAIL/ERROR，因为 `shielddome_endpoint.feature_pipeline` 尚不存在。

- [ ] **Step 3: 写最小实现**

实现无状态 `FeaturePipeline`，按公开常量规定的 tuple 顺序输出；拼接 subject/body 后做 NFKC + casefold + 空白归一化，最多处理 8192 字符；生成字符 2/3/4-gram，使用 `hashlib.sha256` 的固定 bucket 和符号，输出 64 维 L2 规范化 tuple；`text_input=None`。本切片其余数值先由输入的直接属性安全计算，不能预先加入 corpus 能力。

- [ ] **Step 4: 运行绿灯**

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_feature_pipeline.py" -v`

Expected: 1 test PASS，退出码 0。

- [ ] **Step 5: 测试和差异检查点**

Run: `git diff -- endpoint_agent/src/shielddome_endpoint endpoint_agent/tests/test_feature_pipeline.py`

### Task 2: FeaturePipeline 结构化邮件特征

**Files:**
- Modify: `endpoint_agent/tests/test_feature_pipeline.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/feature_pipeline.py`

**Interfaces:**
- Consumes/Produces: Task 1 的同一 `FeaturePipeline.transform`，不增加 adapter。

- [ ] **Step 1: 写失败测试：URL、认证、附件、语言和意图特征为已知字面量**

构造 `.test` 合成观察：不同 sender/reply-to 域、SPF pass、DKIM fail、DMARC 缺失，HTTPS/HTTP/IP/可疑端口链接，`invoice.pdf.exe` 和 `notice.txt` 附件，中英混合主题/正文包含凭据、付款、紧急和冒充短语。断言公开 `numeric_features`/`categorical_features` 转 dict 后的具体计数，并断言 `missing_value_mask == ("auth_dmarc",)` 或包含按固定顺序定义的缺失项。

- [ ] **Step 2: 运行红灯**

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_feature_pipeline.py" -v`

Expected: 新测试 FAIL，因为目标特征尚未全部计算。

- [ ] **Step 3: 写最小实现**

使用 `email.utils.parseaddr` 提取邮箱域，使用纯字符串/正则解析已规范化 URL host/port，使用 `ipaddress.ip_address` 判断 IP 字面量；认证值限制为稳定类别；附件只读取重复 `name`/`filename` 元数据；危险扩展名为固定有限集合；语言输出 `zh`、`en`、`mixed`、`other`；意图词表为有限中英文常量。禁止读取附件或文件系统。

- [ ] **Step 4: 运行绿灯**

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_feature_pipeline.py" -v`

Expected: 当前文件全部 PASS。

### Task 3: 训练/Endpoint 共用 seam 与根包导出

**Files:**
- Modify: `endpoint_agent/tests/test_feature_pipeline.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`

**Interfaces:**
- Consumes: `FeaturePipeline.transform`。
- Produces: 不新增生产接口；训练和 Endpoint 都直接调用同一方法。

- [ ] **Step 1: 写失败测试：训练与 Endpoint 从根包调用相同 transform，结果逐项一致**

```python
endpoint_vector = FeaturePipeline().transform(observation)
training_vectors = tuple(FeaturePipeline().transform(item) for item in (observation,))
self.assertEqual(training_vectors[0], endpoint_vector)
```

测试使用 `from shielddome_endpoint import FeaturePipeline`；同时验证两者来自独立 pipeline 实例，且 `text_input is None`。此测试只证明同一公开 seam，不创建仅转发参数的 wrapper。

- [ ] **Step 2: 运行红灯并最小绿灯**

先让测试要求根包公开 `FeaturePipeline` 而当前导出缺失时失败；随后只补根包导出并重跑同一命令至 PASS。

### Task 4: Corpus 不可变契约与准入门禁

**Files:**
- Create: `endpoint_agent/tests/test_corpus_governance.py`
- Create: `endpoint_agent/src/shielddome_endpoint/corpus.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`

**Interfaces:**
- Produces: 本计划 Public Interfaces 中的枚举、dataclass、`CORPUS_SCHEMA_VERSION = "1.0"` 和 `CorpusGovernance.prepare`。

- [ ] **Step 1: 写失败测试：缺少来源、许可证或人工批准分别拒绝**

使用三个 `CorpusCandidate` 合成候选，分别让 `source_group/label_source`、`license_source` 为空或 `review_status=PENDING`；断言 `approved_items == ()`，拒绝 reason 按 item ID 为 `missing_source`、`missing_license`、`not_human_approved`。

- [ ] **Step 2: 运行红灯**

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_corpus_governance.py" -v`

Expected: FAIL/ERROR，因为 corpus public types 尚不存在。

- [ ] **Step 3: 写最小实现**

定义不可变枚举/dataclass；`prepare` 按 `item_id` 排序，先执行必填字段、`ReviewStatus.APPROVED` 和 `FEATURE_SCHEMA_VERSION` 检查，返回按 item ID 稳定排序的批准/拒绝 tuple 和安全 manifest。

- [ ] **Step 4: 运行绿灯**

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_corpus_governance.py" -v`

Expected: 1 test PASS。

### Task 5: Corpus 标签语义

**Files:**
- Modify: `endpoint_agent/tests/test_corpus_governance.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/corpus.py`

**Interfaces:**
- Consumes/Produces: 同一 `CorpusGovernance.prepare`。

- [ ] **Step 1: 写失败测试：spam/ham 来源标签不能自动升级**

构造 `review_status=APPROVED` 但 `label_source="source-label"` 的 spam→phishing 和 ham→benign 候选，断言两者以 `ambiguous_source_label` 拒绝；再加入 `label_source="human-review"` 的人工复核候选并断言允许进入批准项。

- [ ] **Step 2: 红灯、最小实现、绿灯**

Run before/after: `python -m unittest discover -s endpoint_agent/tests -p "test_corpus_governance.py" -v`

Minimal implementation: 仅 `human-review`、`analyst-confirmed`、`security-review` 被视为人工标签来源；spam/ham 的非人工映射拒绝。

- [ ] **Step 3: 写失败测试：明确标签冲突拒绝**

构造 phishing→benign 与 benign→phishing，断言 reason 为 `label_conflict`，即使 label source 声称人工审核也不自动覆盖明确来源语义。

- [ ] **Step 4: 红灯、最小实现、绿灯**

Run before/after: 同上。实现只增加明确冲突判断。

### Task 6: 精确去重与规范化重复组

**Files:**
- Modify: `endpoint_agent/tests/test_corpus_governance.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/corpus.py`

**Interfaces:**
- Consumes/Produces: `CorpusSnapshot.approved_items`、`rejections`、`duplicate_group`。

- [ ] **Step 1: 写失败测试：同 raw hash 只保留稳定规范记录**

输入顺序故意逆序的两个相同 `raw_hash` 候选，断言按 item ID 最小者被保留，另一项 reason 为 `exact_duplicate`；反转输入顺序结果不变。

- [ ] **Step 2: 红灯、最小实现、绿灯**

Run before/after: `python -m unittest discover -s endpoint_agent/tests -p "test_corpus_governance.py" -v`

Minimal implementation: 在已准入候选按 item ID 排序后以 raw hash 首项为 canonical。

- [ ] **Step 3: 写失败测试：同 normalized hash 进入同一非敏感 duplicate group**

两个 raw hash 不同、normalized hash 相同的批准项都保留；断言 `duplicate_group` 相同、以 `dup-` 开头且不等于输入 normalized hash。

- [ ] **Step 4: 红灯、最小实现、绿灯**

Run before/after: 同上。使用 SHA-256 的前 16 个十六进制字符形成稳定 `dup-...` 标识。

### Task 7: 模板、活动、重复组的确定性 split 隔离

**Files:**
- Modify: `endpoint_agent/tests/test_corpus_governance.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/corpus.py`

**Interfaces:**
- Consumes/Produces: `ApprovedCorpusItem.split: DatasetSplit`。

- [ ] **Step 1: 写失败测试：任一共享 template/campaign/duplicate group 的连通项不跨 split**

构造 A/B 同模板、B/C 同活动、D/E 同 normalized hash 的合成项；断言各连通组 split 集合大小均为 1。

- [ ] **Step 2: 红灯、最小实现、绿灯**

Run before/after: `python -m unittest discover -s endpoint_agent/tests -p "test_corpus_governance.py" -v`

Minimal implementation: 在内存中按相同非空 template、campaign、duplicate group 建立 union-find 连通分量；对分量稳定键做 SHA-256，按 70/15/15 映射到 train/validation/test。

- [ ] **Step 3: 写失败测试：输入顺序变化和重复运行的 snapshot/split 完全一致**

同一 tuple 连续 prepare 两次并对逆序 tuple prepare，按 item ID 比较 `(item_id, split, duplicate_group)` 字面结果一致。

- [ ] **Step 4: 红灯、最小实现、绿灯**

Run before/after: 同上。所有候选、分量和 manifest entry 在输出前按 item ID 排序，禁止使用 set/dict 遍历顺序或 Python `hash()` 决定 split。

### Task 8: FeatureVector 与 Corpus manifest 隐私扫描

**Files:**
- Create: `endpoint_agent/tests/test_privacy.py`
- Create: `endpoint_agent/src/shielddome_endpoint/privacy.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`

**Interfaces:**
- Produces: `PrivacyScanResult`、`PrivacyScanner.scan_feature_vector`、`PrivacyScanner.scan_manifest`。

- [ ] **Step 1: 写失败测试：FeatureVector 扫描不发现原文、sender、完整 URL 或禁止字段**

用包含虚构密码赋值和带 query 的 `.test` URL 合成观察，先通过 `FeaturePipeline.transform`，再把原正文、sender、完整 URL 作为 `forbidden_values` 传给扫描器；断言 `safe is True`、`violations == ()`、`vector.text_input is None`。

- [ ] **Step 2: 红灯、最小实现、绿灯**

Run before/after: `python -m unittest discover -s endpoint_agent/tests -p "test_privacy.py" -v`

Minimal implementation: 扫描 FeatureVector 的公开结构；只返回 `raw_text_field`、`forbidden_value`、`credential_assignment`、`url_query`、`private_path` 等稳定代码，不返回命中内容。

- [ ] **Step 3: 写失败测试：manifest 不包含 representation、hash、密码/Token、完整 query URL 或私有路径**

候选把这些虚构敏感串放在 `sanitized_training_representation`、hash 和许可来源中；`prepare` 后扫描 `snapshot.manifest` 并断言安全，同时断言 manifest dataclass 字段不包含 candidate 或 representation。

- [ ] **Step 4: 红灯、最小实现、绿灯**

Run before/after: 同上。manifest 仅投影 Public Interfaces 列出的安全分组元数据；扫描器递归枚举 dataclass/tuple/enum 的公开值。

### Task 9: Public package、离线 wheel 与文档状态

**Files:**
- Modify: `endpoint_agent/tests/test_package.py`
- Modify: `endpoint_agent/tests/test_build.py`
- Modify: `endpoint_agent/AGENTS.md`
- Modify: `endpoint_agent/docs/USAGE.md`
- Modify: `endpoint_agent/DEVELOPMENT_PLAN.md`（仅最终门禁通过后）

**Interfaces:**
- Produces: 根包导出本计划全部 Phase 1 public interface。

- [ ] **Step 1: 写失败测试：根包公开导出和 wheel 内容完整**

在 `test_package.py` 导入 `FeaturePipeline`、corpus 类型、`PrivacyScanner` 与版本常量；在 `test_build.py` 的 `expected_names` 加入 `feature_pipeline.py`、`corpus.py`、`privacy.py`。

- [ ] **Step 2: 运行红灯**

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_package.py" -v`

Expected: 若任何公开导出缺失则 FAIL；只补缺失导出后重跑至 PASS。wheel 测试应由现有递归构建后端通过，不修改构建依赖。

- [ ] **Step 3: 运行 Phase 1 相关绿灯**

Run:

```powershell
python -m unittest discover -s endpoint_agent/tests -p "test_feature_pipeline.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_corpus_governance.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_privacy.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_package.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_build.py" -v
```

- [ ] **Step 4: 更新使用文档和协作状态说明**

`AGENTS.md` 只把当前状态改为 Phase 0-1，并列出现有 `FeaturePipeline`、Corpus Governance、Privacy Scanner；明确尚无模型、推理或持久化。`USAGE.md` 使用 `.test` 合成例子说明 transform、prepare、隐私扫描、测试和离线构建，不声称可检测真实邮件。

- [ ] **Step 5: 使用 `$verification-before-completion` 执行最终门禁**

Run:

```powershell
python -m unittest discover -s endpoint_agent/tests -v
python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist
git status --short
git diff --stat
git diff -- endpoint_agent
git status --short -- app shielddome frontend extension web deploy scripts phishingDP-main
```

额外检查：离线 guard 扫描的生产 `.py` 文件清单包含 `feature_pipeline.py`、`corpus.py`、`privacy.py`；隐私测试不输出敏感测试值；`git check-ignore` 覆盖 corpus snapshot、原始数据和训练输出。

- [ ] **Step 6: 仅在全部门禁退出码为 0 后更新阶段状态**

把 `DEVELOPMENT_PLAN.md` 的 Phase 1 `Status: pending` 改为 `Status: complete`；Phase 2 保持 `pending`；“下一步”改为 `Phase 2：基线模型与评估`。随后再次运行完整 unittest、离线 wheel 和 Git 状态检查。

## Completion Criteria

- `FeaturePipeline.transform` 对相同 MailObservation 重复/跨进程完全确定，训练与 Endpoint 直接复用同一方法。
- Feature schema version、固定特征名称和顺序、URL/认证/附件/语言/意图/缺失掩码均有公开行为测试。
- 文本表示固定 64 维、L2 规范化、稳定 SHA-256 Hashing；`FeatureVector` 不含原始正文或 Token。
- `CorpusGovernance.prepare` 拒绝缺来源、许可证、人工审核、标签冲突及自动 spam/ham 升级。
- 精确重复只保留一个 canonical；规范化重复同组；模板、活动、duplicate 连通组不跨 split；重复运行与输入逆序结果一致。
- manifest 只含安全投影；FeatureVector/manifest 隐私扫描不发现原文、凭据赋值、Token、完整查询 URL 或私有路径。
- 新增生产 Python 文件全部被离线 guard 扫描；无网络 import、endpoint、端口或第三方运行依赖。
- Phase 0 测试继续通过，完整 Phase 0-1 测试无 failure/error/skip，离线 wheel 构建退出码 0。
- 所有业务修改仅位于 `endpoint_agent/`；`phishingDP-main/` 和受保护目录相对开始基线无变化。
- Phase 1 为 complete、Phase 2 仍 pending、下一步为 Phase 2；未实施 Phase 2 或后续能力。
- 本任务未提交、未推送、未创建分支或 PR。

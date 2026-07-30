# Phase 1 验收加固 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` inline to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. 用户已明确授权在当前工作树和当前分支直接实施；不创建 worktree/branch，不提交、不推送，也不调用后续阶段或分支收尾 Skill。

**Goal:** 仅修复 Phase 1 的训练可信度、溯源、泄漏隔离和资源边界验收缺口，使 Phase 1 的 `complete` 状态有可重复的测试与离线构建证据。

**Architecture:** 保持 `FeaturePipeline.transform` 与 `CorpusGovernance.prepare` 两个深模块入口。Corpus 先执行有界准入和跨样本冲突检查，再建立 exact/normalized/near-duplicate、template、campaign 连通分量；不可变 `CorpusSplitPolicy` 只表达来源和 UTC 时间留出，test 留出在分量级优先于稳定 70/15/15 哈希分配。Manifest 只投影规范 SHA-256、稳定标识和 UTC 时间，不保存训练 representation；Feature Pipeline 在现有 64 维 hashing 前统一截断所有可能无界输入。

**Tech Stack:** Python 3.12 标准库（`dataclasses`、`datetime`、`enum`、`hashlib`、`re`、`unicodedata`）、`unittest`、项目内零外部依赖 PEP 517 backend。

## Global Constraints

- 只能修改 `endpoint_agent/`；`app/`、`shielddome/`、`frontend/`、`extension/`、`web/`、`deploy/`、`scripts/`、`phishingDP-main/` 保持任务开始基线不变。
- 保护全部既有未提交 Phase 1 修改，不覆盖、回退、删除或仓库级格式化。
- 只修复 Phase 1；Phase 2 保持 `pending`，不训练/加载模型，不实现分类器、校准、拒判、ONNX、Detection Kernel、插件、Native Messaging、数据库、加密或 UI。
- 不增加第三方依赖、网络客户端、HTTP/WebSocket 服务、监听端口、外部数据集、真实邮件或大型二进制。
- 测试继续使用 `unittest`，仅使用合成内容和 `.test` 虚构域名；测试只通过用户确认的公开 seam。
- 每个任务严格执行一个公开行为测试的 red → 最小实现 → green；不得先批量写完测试。
- `FeaturePipeline` 保持 64 维稳定 SHA-256 signed hashing，不使用 Python `hash()`，不打开附件，不进行网络或文件写入。
- Corpus 原始数据、snapshot、训练输出和 wheel 产物保持 Git 忽略；本计划不创建真实 corpus 文件。
- 不包含 commit、push、branch、worktree 或 PR 步骤；每项使用测试和差异检查点代替。

## Public Interfaces

```python
@dataclass(frozen=True, slots=True)
class CorpusSplitPolicy:
    test_source_groups: tuple[str, ...] = ()
    test_after: datetime | None = None

class CorpusGovernance:
    def prepare(
        self,
        candidates: tuple[CorpusCandidate, ...],
        split_policy: CorpusSplitPolicy = CorpusSplitPolicy(),
    ) -> CorpusSnapshot: ...

@dataclass(frozen=True, slots=True)
class ApprovedCorpusItem:
    candidate: CorpusCandidate
    duplicate_group: str
    near_duplicate_group: str
    split: DatasetSplit

@dataclass(frozen=True, slots=True)
class CorpusManifestEntry:
    item_id: str
    original_label: SourceLabel
    final_label: CorpusLabel
    label_source: str
    review_status: ReviewStatus
    license_identifier: str
    ingested_at_utc: str
    raw_content_digest: str
    normalized_content_digest: str
    sanitized_representation_digest: str
    source_group: str
    language_group: str
    template_group: str
    campaign_group: str
    duplicate_group: str
    near_duplicate_group: str
    feature_schema_version: str
    corpus_schema_version: str
    split: DatasetSplit
```

`CorpusCandidate` 保留既有字段名以兼容当前调用方；其中 `raw_hash`、`normalized_hash` 在准入时必须是 64 位小写规范 SHA-256，`license_source` 被解释为稳定许可证/公司授权标识。`CorpusSnapshot`、`CorpusManifest`、`PrivacyScanner` 的现有入口保持不变。公开资源常量为：

```python
FEATURE_TEXT_MAX_CHARACTERS = 8192
FEATURE_URL_MAX_ITEMS = 256
FEATURE_ATTACHMENT_MAX_ITEMS = 256
FEATURE_AUTHENTICATION_MAX_ITEMS = 64
NEAR_DUPLICATE_MAX_CHARACTERS = 4096
CORPUS_MAX_CANDIDATES = 4096
NEAR_DUPLICATE_FINGERPRINT_VERSION = "1.0"
```

`FEATURE_SCHEMA_VERSION` 因截断和饱和语义变化从 `1.0` 升为 `2.0`；`CORPUS_SCHEMA_VERSION` 因 manifest 和分组契约变化从 `1.0` 升为 `2.0`。

## File Map

- Modify `endpoint_agent/src/shielddome_endpoint/domain.py`: 将 feature schema 升到 `2.0`。
- Modify `endpoint_agent/src/shielddome_endpoint/feature_pipeline.py`: 对文本、URL、附件元数据、认证观察统一实施确定性上限并公开边界常量。
- Modify `endpoint_agent/src/shielddome_endpoint/corpus.py`: 跨样本标签冲突、不可变 split policy、规范 digest/许可证/UTC 校验、近重复指纹、分量级 test 留出和完整 manifest。
- Modify `endpoint_agent/src/shielddome_endpoint/__init__.py`: 导出 split policy、版本化近重复/资源边界常量及更新后的契约。
- Modify `endpoint_agent/src/shielddome_endpoint/privacy.py`: 保持对扩展 manifest 的全字段递归扫描，不回显敏感值。
- Modify `endpoint_agent/tests/test_feature_pipeline.py`: 只通过 `FeaturePipeline.transform` 验证资源上限、确定性截断和 schema 版本。
- Modify `endpoint_agent/tests/test_corpus_governance.py`: 使用真实合成 SHA-256，通过 `prepare` 验证冲突、policy、溯源、近重复、上限和 split 隔离。
- Modify `endpoint_agent/tests/test_privacy.py`: 验证 manifest 只含 digest/非敏感溯源字段并拒绝不安全许可证标识。
- Modify `endpoint_agent/tests/test_domain.py`: 同步 `FEATURE_SCHEMA_VERSION == "2.0"` 的公开领域契约。
- Modify `endpoint_agent/tests/test_package.py`: 验证新增公开类型/常量和 schema 版本可从根包导入。
- Modify `endpoint_agent/AGENTS.md`: 补充 Phase 1 加固后的公开边界与限制。
- Modify `endpoint_agent/docs/USAGE.md`: 更新 digest 示例、split policy、manifest、近重复和资源边界说明。
- Modify `endpoint_agent/DEVELOPMENT_PLAN.md`: 只有最终门禁全部通过时保留 Phase 1 `complete`；Phase 2 继续 `pending`。

---

### Task 1: 跨样本 raw/normalized 标签冲突

**Files:**
- Modify: `endpoint_agent/tests/test_corpus_governance.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/corpus.py`

**Interfaces:**
- Consumes/Produces: 既有 `CorpusGovernance.prepare(...) -> CorpusSnapshot`、`CorpusSnapshot.rejections`。

- [ ] **Step 1: 写失败测试——同 raw digest 的不同最终标签整组拒绝**

以同一个合成 raw digest 构造 `raw-phishing` 和 `raw-benign`，各自使用与 final label 一致的明确 original label；断言 `approved_items == ()`，两项均为稳定错误码 `raw_label_conflict`，反转输入顺序结果不变。

- [ ] **Step 2: 运行红灯**

Run: `python -m unittest endpoint_agent.tests.test_corpus_governance.CorpusGovernanceTests.test_prepare_rejects_entire_raw_duplicate_group_with_conflicting_final_labels -v`

Expected: FAIL；当前实现按 item ID 留下一个候选，另一项仅为 `exact_duplicate`。

- [ ] **Step 3: 写最小实现并运行绿灯**

在单项准入后、选择 exact canonical 前，按 `raw_hash` 聚合最终标签；标签集合大于 1 时将组内所有项拒绝为 `raw_label_conflict`。按 item ID 输出，不根据输入顺序或 item ID 选择某个标签。

Run: 同 Step 2。Expected: PASS，退出码 0。

- [ ] **Step 4: 独立红绿循环——同 normalized digest 的不同最终标签整组拒绝**

新增公开行为测试，使用不同 raw digest、同一 normalized digest 和不同最终标签，期望两项均为 `normalized_label_conflict`；先运行并确认当前实现错误批准两项，再最小增加 normalized 聚合检查并重跑至 PASS。若候选同时命中两类冲突，固定 raw 错误码优先。

- [ ] **Step 5: 回归相同内容相同标签行为**

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_corpus_governance.py" -v`

Expected: 现有 exact canonical 与 normalized duplicate group 测试仍 PASS。

### Task 2: 来源/时间 test 留出 policy 与分量级优先级

**Files:**
- Modify: `endpoint_agent/tests/test_corpus_governance.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/corpus.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`

**Interfaces:**
- Produces: 不可变 `CorpusSplitPolicy(test_source_groups=(), test_after=None)`；`prepare(..., split_policy=CorpusSplitPolicy())` 保持旧调用兼容。

- [ ] **Step 1: 写失败测试——指定 source group 强制整个连通组进入 test**

构造 A/B 同 template，B 的 `source_group="held-out-source"`；传入 `CorpusSplitPolicy(test_source_groups=("held-out-source",))`，断言 A/B 均为 `DatasetSplit.TEST`，且 frozen policy 不能修改。

- [ ] **Step 2: 运行红灯、写最小实现、运行绿灯**

Run: `python -m unittest endpoint_agent.tests.test_corpus_governance.CorpusGovernanceTests.test_source_holdout_forces_entire_connected_group_to_test -v`

Expected red: ERROR/FAIL，因为 split policy 尚不存在或 `prepare` 不接受该参数。最小实现对 policy source identifiers 排序去重；任一 admissible 组员命中时，在 union-find 分量分配阶段强制整个分量为 test。重跑同命令至 PASS。

- [ ] **Step 3: 独立红绿循环——UTC 截止点之后的样本强制整个组进入 test**

新增测试：截止点前后的两个候选通过 campaign 连通，后者时刻严格大于带时区 cutoff；断言全组 test。先确认 FAIL，再实现 aware datetime 校验与 UTC 比较；等于 cutoff 不视为“之后”。重跑至 PASS。

- [ ] **Step 4: 独立红绿循环——默认 policy 保持 70/15/15 与完全确定性**

新增测试比较省略 policy、显式默认 policy、重复输入和逆序输入的完整 snapshot；先确认新 policy 下若有不一致则 FAIL，再确保未命中留出时仍使用现有 SHA-256 分量键映射，test 优先于 validation/train。

- [ ] **Step 5: policy 数据边界检查**

通过 `prepare` 测试带路径分隔符、网络 scheme 或超长 source group 的 policy 被稳定拒绝为 `ValueError("invalid_split_policy")`，且 policy 不包含文件路径、网络地址或数据正文。

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_corpus_governance.py" -v`

### Task 3: Manifest 训练溯源与规范输入校验

**Files:**
- Modify: `endpoint_agent/tests/test_corpus_governance.py`
- Modify: `endpoint_agent/tests/test_privacy.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/corpus.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/privacy.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`

**Interfaces:**
- Produces: 本计划 Public Interfaces 中完整 `CorpusManifestEntry`；`CORPUS_SCHEMA_VERSION = "2.0"`。

- [ ] **Step 1: 写失败测试——manifest 包含确定的非敏感训练溯源**

先把 corpus 测试 helper 的 raw/normalized 值改为 `sha256(f"raw:{item_id}".encode()).hexdigest()` 等真实合成 SHA-256。用 `+08:00` aware 时间构造候选，断言 manifest 的字段名和已知字面量：original/final label、label source、review status、license identifier、UTC ISO 时间、raw/normalized digest、`sha256(representation)`、所有分组、feature/corpus schema、split；断言 entry 没有 representation 字段，重复/逆序输入 manifest 完全一致。

- [ ] **Step 2: 运行红灯、写最小实现、运行绿灯**

Run: `python -m unittest endpoint_agent.tests.test_corpus_governance.CorpusGovernanceTests.test_manifest_contains_deterministic_non_sensitive_training_provenance -v`

Expected red: FAIL，因为现有 manifest 缺少字段且 corpus schema 仍为 `1.0`。最小实现投影完整字段，representation 只写 SHA-256；UTC 使用 `astimezone(timezone.utc).isoformat()`；schema 升为 `2.0`。重跑至 PASS。

- [ ] **Step 3: 独立红绿循环——hash 必须是规范 SHA-256**

新增公开准入测试，分别传入短值、大写 64 hex、非 hex 值，期望稳定 `invalid_raw_digest` 或 `invalid_normalized_digest`；先确认现有实现错误批准，再使用完整匹配 `[0-9a-f]{64}` 的最小校验并重跑至 PASS。现有虚构 hash fixture 全部替换为真正合成 SHA-256，不降低标准。

- [ ] **Step 4: 独立红绿循环——许可证标识和时间必须安全规范**

新增测试：Windows 私有路径/URL 许可证标识拒绝为 `invalid_license_identifier`；naive datetime 拒绝为 `invalid_ingestion_time`。先确认当前实现错误批准，再加入长度有界的稳定 identifier 和 timezone-aware 校验，重跑至 PASS。

- [ ] **Step 5: 独立红绿循环——PrivacyScanner 验证扩展 manifest**

更新 privacy 测试，只使用有效许可证标识和 SHA-256；把 representation、密码/Token、带 query 的完整 URL、私有路径作为 forbidden values，断言安全 manifest 不包含它们且 scanner 返回 `safe=True`。手工构造完整 unsafe entry，通过 `PrivacyScanner.scan_manifest` 验证稳定违规码，不测试私有 helper。

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_privacy.py" -v`

### Task 4: 保守、版本化且有界的近重复分组

**Files:**
- Modify: `endpoint_agent/tests/test_corpus_governance.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/corpus.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`

**Interfaces:**
- Produces: `ApprovedCorpusItem.near_duplicate_group`、`CorpusManifestEntry.near_duplicate_group`、`NEAR_DUPLICATE_FINGERPRINT_VERSION`、`NEAR_DUPLICATE_MAX_CHARACTERS`、`CORPUS_MAX_CANDIDATES`。

- [ ] **Step 1: 写失败测试——高度相似的脱敏模板同组且不跨 split**

两个 representation 只在长订单号、UUID、邮箱或完整 `.test` URL 等变量位不同；template/campaign/normalized digest 均不同。通过 `prepare` 断言相同 `near_duplicate_group`、组名含算法版本且 split 相同，manifest 不保存 Token 或 representation。

- [ ] **Step 2: 运行红灯、写最小实现、运行绿灯**

Run: `python -m unittest endpoint_agent.tests.test_corpus_governance.CorpusGovernanceTests.test_conservative_near_duplicates_share_group_and_split -v`

Expected red: FAIL/ERROR，因为公开项没有 near-duplicate group。最小实现只对 representation 前 4096 字符做 NFKC/casefold、空白折叠，并把 URL、邮箱、UUID、长数字/十六进制变量替换成固定占位符；对规范串 SHA-256，生成带 `v1` 的非敏感 group。该组加入 union-find，但不保存规范串或 Token。重跑至 PASS。

- [ ] **Step 3: 独立红绿循环——明显不同样本不能误合并**

新增两个主题和结构明显不同的合成 representation，断言 near group 不同；先运行确认任何过宽归一化会 FAIL，只收紧变量替换规则，不增加语义库或模糊大聚类，重跑至 PASS。

- [ ] **Step 4: 独立红绿循环——输入长度和候选数量有稳定边界**

通过 `prepare` 验证变量出现在 4096 字符之后不影响 fingerprint；再构造 `CORPUS_MAX_CANDIDATES + 1` 个轻量合成候选，断言整个超限批次按 item ID 稳定返回 `candidate_limit_exceeded`，不批准一个无法完成全量冲突检查的部分 corpus，且 near-duplicate 处理项数不超过常量。先确认当前无边界行为 FAIL，再实现确定性拒绝并重跑至 PASS。

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_corpus_governance.py" -v`

### Task 5: Feature Pipeline 资源边界和 feature schema 升级

**Files:**
- Modify: `endpoint_agent/tests/test_feature_pipeline.py`
- Modify: `endpoint_agent/tests/test_domain.py`
- Modify: `endpoint_agent/tests/test_package.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/domain.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/feature_pipeline.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`

**Interfaces:**
- Consumes/Produces: 同一 `FeaturePipeline.transform`；公开四个资源边界常量；`FEATURE_SCHEMA_VERSION = "2.0"`；64 维和特征顺序不变。

- [ ] **Step 1: 写失败测试——超长文本确定性截断且计数饱和**

构造正文前 8192 字符无意图词、边界后包含凭据/紧急词；断言 body length 饱和为 8192、边界后词不影响 intent/language/text vector，相同有效前缀与不同超额尾部得到相同相关特征和 vector。

- [ ] **Step 2: 运行红灯、写最小实现、运行绿灯**

Run: `python -m unittest endpoint_agent.tests.test_feature_pipeline.FeaturePipelineTests.test_transform_bounds_all_text_processing -v`

Expected red: FAIL，因为 body length、language 和 intent 当前处理完整输入。最小实现创建一个 8192 字符的统一规范/分析视图供 hashing、language、intent 使用，并让 subject/body 长度计数饱和；重跑至 PASS。

- [ ] **Step 3: 独立红绿循环——URL 数量和风险计数饱和**

前 256 个使用安全 `.test` HTTPS URL，边界后加入 IP 字面量/可疑端口；断言 `url_count == 256` 且边界后项不改变 IP/端口/域名计数。先确认 FAIL，再只处理 tuple 前 256 项并重跑至 PASS。

- [ ] **Step 4: 独立红绿循环——附件元数据数量有界**

前 256 个为普通合成文件名，边界后放双扩展危险名；断言 attachment count 饱和且超额项不改变危险计数。先确认 FAIL，再只检查前 256 条元数据；不得打开、下载或读取路径，重跑至 PASS。

- [ ] **Step 5: 独立红绿循环——认证观察数量有界**

前 64 项为无关合成认证键，边界后加入 SPF/DKIM/DMARC；断言三项仍缺失。先确认 FAIL，再只处理前 64 项并重跑至 PASS。

- [ ] **Step 6: 升级 schema 并回归固定契约**

把 `FEATURE_SCHEMA_VERSION` 升为 `2.0`，同步 domain/package/corpus helper 断言和根包导出；保留 64 维、特征名称/顺序及短输入已知 vector digest。

Run:

```powershell
python -m unittest discover -s endpoint_agent/tests -p "test_feature_pipeline.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_domain.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_package.py" -v
```

### Task 6: 文档一致性与 Phase 1 最终门禁

**Files:**
- Modify: `endpoint_agent/AGENTS.md`
- Modify: `endpoint_agent/docs/USAGE.md`
- Modify: `endpoint_agent/DEVELOPMENT_PLAN.md`（只在全部门禁通过时保留 `complete`）

**Interfaces:**
- Documents: schema `2.0`、split policy、真实 SHA-256 示例、manifest 溯源、近重复算法边界和 Feature Pipeline 资源上限。

- [ ] **Step 1: 更新文档但不扩大阶段**

更新 `USAGE.md` 示例，使用运行时计算或已知真实合成 SHA-256；记录 `CorpusSplitPolicy` 的 source/time test 留出、严格大于 UTC cutoff 语义、manifest 只保存 representation digest、near-duplicate 保守算法和所有资源上限。更新 `AGENTS.md` 当前实现说明；明确仍无模型训练、推理或 Phase 2 能力。

- [ ] **Step 2: 使用 `$verification-before-completion` 运行完整新鲜门禁**

Run:

```powershell
python -m unittest discover -s endpoint_agent/tests -v
python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist
git status --short
git diff --stat
git diff -- endpoint_agent
git diff --cached
git status --short -- app shielddome frontend extension web deploy scripts phishingDP-main
```

完整读取输出并记录 unittest 的 tests/failures/errors/skips 与各命令退出码。额外枚举 `endpoint_agent/src/shielddome_endpoint/*.py`，确认离线 guard 扫描根包含全部新增生产模块；使用现有 repository hygiene 测试确认 corpus、训练输出、模型、密钥、日志、SQLite、诊断包和构建产物仍被忽略。

- [ ] **Step 3: 核对阶段状态**

若且仅若跨样本冲突、source/time 留出、所有 group split 隔离、manifest 溯源、近重复、资源边界、隐私、离线、wheel 和目录隔离全部通过，保持 Phase 1 `Status: complete`、Phase 2 `Status: pending` 和“下一步 Phase 2”。任何一项未满足时把 Phase 1 改为 `in_progress` 并记录具体阻塞。

- [ ] **Step 4: 状态确认后的最终新鲜验证**

再次运行完整 unittest 和 `git status --short`；检查完整 `git diff -- endpoint_agent`，确认文档状态调整没有引入其他修改。不得提交或推送。

## Completion Criteria

- 同 raw/normalized SHA-256 的不同最终标签整组拒绝，错误码稳定且不泄露内容；相同标签的 exact/normalized 行为保持确定。
- 默认兼容的不可变 split policy 支持 source 和 aware UTC cutoff test 留出；任一成员命中时整个 duplicate/template/campaign/near-duplicate 连通分量进入 test。
- Manifest 包含要求的非敏感训练溯源，只保存 representation SHA-256；所有 digest、许可证标识和 UTC 时间通过严格校验且输出确定。
- 保守版本化 near-duplicate fingerprint 仅处理有界 sanitized representation，明显不同内容不合并，且参与 split 隔离。
- Feature Pipeline 对文本、URL、附件元数据和认证观察有固定上限；计数截断/饱和确定，64 维 hashing 不扩大，无网络、文件写入或附件内容访问。
- `FEATURE_SCHEMA_VERSION == "2.0"`、`CORPUS_SCHEMA_VERSION == "2.0"`，公开导出、测试和文档一致。
- 全部 Phase 0-1 测试、离线 wheel、隐私/离线/忽略规则及受保护目录差异检查获得本轮新鲜退出码 0 证据。
- Phase 1 仅在全部门禁满足时保持 `complete`；Phase 2 仍为 `pending`，未实现 Phase 2 或后续功能。
- 没有创建分支/worktree，没有提交、推送或创建 PR。

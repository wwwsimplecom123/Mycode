# Approved Training Corpus 数据准入材料包

## 1. 用途与边界

本目录提供 ShieldDome Endpoint Agent 的 Approved Training Corpus 数据准入记录模板。材料供公司数据所有者、安全、隐私、法务和模型治理负责人在受控系统中完成真实审核；Git 中的空白模板本身不构成法律意见、公司授权、数据批准或 Phase 3 GO 决定。

Codex 只完成工程材料和代码字段映射，不能代替任何责任人批准数据。任何示例 ID 都是虚构值，示例状态均保持 `pending` 或 `NO-GO`。不得把模板、公开可下载状态、源码许可证或技术扫描通过解释为训练授权。

本材料包不导入真实邮件、不创建真实 corpus snapshot、不训练或下载模型，也不改变 `DEVELOPMENT_PLAN.md` 中 Phase 3 的 `pending` 状态。当前 readiness audit 结论仍为 `NO-GO`。

## 2. 统一术语

**Approved Training Corpus**：符合来源、权利、人工标签、隐私、去重和 split 隔离要求，具有版本化 manifest，并完成 snapshot 审批的训练语料集合。候选记录或 `CorpusGovernance.prepare` 的内存输出不因单独存在而自动成为已批准语料。

**来源记录**：描述一个数据来源的身份、版本、取得方式、许可证据、权利限制和撤回机制的受控记录。

**数据授权**：责任人针对明确目的分别作出的内部训练、corpus 再分发和终端权重分发决定。三项权利互不推导。

**标签审核处置**：`benign`、`phishing`、`reject` 或 `unresolved`。其中只有 `benign` 和 `phishing` 可成为代码中的 `CorpusLabel`；`reject`、`unresolved` 表示不得构造 `CorpusCandidate`。

**Corpus Snapshot 审批**：责任人对固定 manifest、split、统计、权利状态和撤回映射作出的整体决定。它不是 `CorpusSnapshot` dataclass 自动产生的法律或公司审批。

## 3. 材料、责任人与填写顺序

| 顺序 | 材料 | 主填人 | 必要复核人 | 通过后产出 |
| --- | --- | --- | --- | --- |
| 1 | [SOURCE_REGISTER_TEMPLATE.md](SOURCE_REGISTER_TEMPLATE.md) | 数据来源负责人或数据管理员 | 数据所有者、法务 | 版本化来源记录及证据 digest |
| 2 | [DATA_AUTHORIZATION_TEMPLATE.md](DATA_AUTHORIZATION_TEMPLATE.md) | 数据所有者 | 安全、隐私、法务、模型治理负责人 | 明确且分离的用途与分发决定 |
| 3 | [LABEL_REVIEW_TEMPLATE.md](LABEL_REVIEW_TEMPLATE.md) | 具备授权的标签审核人 | 冲突复核人或安全负责人 | 每个样本的最终标签或拒绝处置 |
| 4 | [PRIVACY_REVIEW_TEMPLATE.md](PRIVACY_REVIEW_TEMPLATE.md) | 隐私审核人 | 安全负责人、必要时法务 | 脱敏与隐私审核结论及证据 digest |
| 5 | `CorpusGovernance.prepare(...)` | 受控数据处理执行人 | 工程复核人 | 内存 `CorpusSnapshot`、manifest 和稳定拒绝码 |
| 6 | [CORPUS_SNAPSHOT_APPROVAL_TEMPLATE.md](CORPUS_SNAPSHOT_APPROVAL_TEMPLATE.md) | Corpus 负责人 | 数据、安全、隐私、法务、模型治理负责人 | 固定 snapshot 的整体审批记录 |
| 7 | [PHASE3_GO_NO_GO_CHECKLIST.md](PHASE3_GO_NO_GO_CHECKLIST.md) | Phase 3 决策主持人 | 所有硬门禁责任人 | 单一 `GO` 或 `NO-GO` 结论 |

推荐流转顺序：来源登记 → 数据授权 → 标签人工审核 → 隐私审核 → `CorpusGovernance.prepare` → Snapshot 审批 → Phase 3 GO/NO-GO。

任何前序材料缺失、空白、待定、拒绝、撤销、到期或证据不可核验时，停止流转并按 `NO-GO` 处理。不得使用“暂时通过”“默认同意”或口头同意绕过门禁。

## 4. 存储与 Git 边界

真实材料必须保存在公司批准的受控系统中，包括：原始邮件和附件、来源文件、许可或合同全文、授权签署材料、审核人身份、自然人信息、完整审批证据、真实路径、访问凭据、删除证明、样本级审核证据和可还原正文的任何数据。

经过分类确认的下列非敏感值可进入 corpus manifest 或工程报告：稳定 ID、版本号、状态枚举、显式权利布尔值、带时区的 UTC 时间、规范小写 SHA-256 digest、非敏感 group ID、schema version、split、计数和稳定拒绝码。进入 manifest 前仍须通过最小化审查；“可进入”不代表“必须进入”。

禁止进入 Git：真实邮件正文、完整邮件头、真实邮箱或联系方式、附件内容、可识别人员信息、URL 查询参数、内部路径、Token、密钥、密码、生产数据、真实 corpus/snapshot、模型文件、许可或合同全文、签名、审批证据正文和任何可用于恢复原始材料的内容。

## 5. 到 `CorpusCandidate` 的映射

只有来源、授权、标签和隐私记录全部满足各自门禁的样本，才可在受控环境构造 `CorpusCandidate`。下表以当前代码的 Corpus Schema `3.0` 为准。

| 治理材料字段 | 当前代码字段 | Manifest 字段 | 映射规则 |
| --- | --- | --- | --- |
| 样本稳定 ID | `CorpusCandidate.item_id` | `item_id` | 只使用非敏感稳定 ID，不使用消息主题、地址或文件名 |
| `source_dataset_id` | `CorpusCandidate.source_dataset_id` | `source_dataset_id` | 使用稳定非敏感 ID |
| `source_version` | `source_version` | `source_version` | 固定到不可变来源版本 |
| `source_group` | `source_group` | `source_group` | 用于来源统计和 holdout |
| `license_identifier` | `license_source` | `license_identifier` | 仅传递许可证/授权类别标识，不传许可正文 |
| 来源证据包规范 SHA-256 | `source_evidence_digest` | `source_evidence_digest` | 证据包应覆盖来源记录版本；`license_text_digest` 和 license evidence ID 保留在受控记录中 |
| 授权记录稳定 ID | `authorization_basis_id` | `authorization_basis_id` | 不得放签名或授权正文 |
| 授权当前状态 | `authorization_status` | `authorization_status` | 仅 `approved` 或 `active` 可准入 |
| 内部训练决定 | `internal_training_allowed` | 同名 | 必须严格为 `true` |
| 终端权重分发决定 | `endpoint_weight_distribution_allowed` | 同名 | 必须单独严格为 `true` |
| 批准时间 | `authorization_approved_at` | `authorization_approved_at_utc` | 必须带时区且不晚于 `ingested_at` |
| 到期/无期限 | `authorization_expires_at`、`authorization_no_expiry` | 对应 `_utc` 字段和同名字段 | 两种方式互斥；空白不是无期限 |
| `original_label` | `original_label` | `original_label` | 允许 `spam`、`ham`、`phishing`、`benign` |
| `final_label` | `final_label` | `final_label` | 只允许 `benign` 或 `phishing` |
| `label_source` | `label_source` | `label_source` | spam/ham 不得自动映射 |
| 标签指南、证据、审核人、时间、政策、状态 | 对应 `label_guideline_version`、`label_evidence_id`、`reviewer_id`、`reviewed_at`、`review_policy_version`、`review_status` | 对应字段，时间为 `reviewed_at_utc` | `review_status` 必须为 `approved` |
| 模板/活动归属 | `template_group`、`campaign_group` | 同名 | 使用稳定非敏感 group ID |
| 语言分组 | `language_group` | `language_group` | 使用批准的 `zh`、`en`、`mixed` 等稳定组 ID |
| 原始内容 digest | `raw_hash` | `raw_content_digest` | 规范 64 位小写 SHA-256；正文不进入 manifest |
| 规范化内容 digest | `normalized_hash` | `normalized_content_digest` | 规范 64 位小写 SHA-256；用于冲突与重复检查 |
| 准入时间 | `ingested_at` | `ingested_at_utc` | 必须带时区；manifest 统一为 UTC |
| feature schema | `feature_schema_version` | `feature_schema_version` | 必须等于当前 `FEATURE_SCHEMA_VERSION` |
| 隐私状态、政策、时间、证据 digest | `privacy_review_status`、`sanitization_policy_version`、`privacy_reviewed_at`、`privacy_evidence_digest` | 对应字段，时间为 `_utc` | 隐私状态必须为 `approved` |
| 脱敏训练表示 | `sanitized_training_representation` | **不存在** | 只在受控数据环境中使用，非空且不得进入 manifest、审批模板或 Git |
| 脱敏表示 digest | `sanitized_representation_digest` | 同名 | 必须与受控环境中的脱敏表示正文匹配 |

`CorpusGovernance.prepare` 还生成下列 manifest 字段：`duplicate_group` 来自规范化 digest 的非暴露分组；`near_duplicate_group` 来自版本化保守指纹；`split` 来自关联组隔离、holdout 和确定性分配；`corpus_schema_version` 固定为 `3.0`。时间字段映射为 `reviewed_at_utc`、`authorization_approved_at_utc`、`authorization_expires_at_utc`、`privacy_reviewed_at_utc` 和 `ingested_at_utc`。

`CorpusManifest` 根对象包含 `entries`、`schema_version` 和规范 `digest`。`CorpusSnapshot` 包含 `approved_items`、`rejections`、`manifest` 和 `schema_version`；`ApprovedCorpusItem` 包含原始 `candidate`、`duplicate_group`、`near_duplicate_group` 和 `split`；`CorpusRejection` 只包含 `item_id` 与稳定 `reason`，不得回显被拒绝值。

以下必需治理事实没有对应的 Schema 3.0 字段，必须留在受控系统并通过稳定 ID/digest 关联：取得方式和日期、文件清单、许可全文 digest、license evidence ID、数据所有者、地域/产品限制、corpus 再分发权、原始材料访问范围、留存/删除要求、敏感类别明细、匿名化判断、snapshot ID、split policy digest、source/time holdout 冻结证明、test 不可见性证明、撤回/到期到 snapshot/release 的映射、最终签署记录。

特别说明：审计建议中的 `privacy_status` 对应当前代码的 `privacy_review_status`；`sanitization_reviewed_at` 对应 `privacy_reviewed_at`；`license_source` 在 `CorpusCandidate` 中映射为 manifest 的 `license_identifier`。当前 `CorpusSnapshot` 只有 `approved_items`、`rejections`、`manifest` 和 `schema_version`，没有 `snapshot_id` 或 `split_policy_digest`；模板不得声称这些字段由代码自动生成。

## 6. 运行准入与重新决策

1. 在受控环境读取获批记录和经脱敏的训练表示，计算规范 digest；不要把正文带入审批模板或 Git。
2. 仅为满足全部先决条件且最终标签为 `benign`/`phishing` 的记录构造不可变 `CorpusCandidate`。
3. 预先冻结 `CorpusSplitPolicy.test_source_groups` 和带时区的 `test_after`，记录政策版本及规范 digest。
4. 调用 `CorpusGovernance.prepare(candidates, split_policy)`。任何 rejection 都必须保留 `item_id` 和稳定 code 的计数，并在受控系统中处理；不得回显被拒绝值。
5. 从 `CorpusManifest.entries` 计算 snapshot 审批模板中的计数与分组统计；保存 `CorpusManifest.digest`，不要保存样本正文。
6. 完成 snapshot 审批后逐项重跑 Phase 3 硬门禁。授权、许可、隐私、撤回映射、候选模型许可或样本下限发生变化时必须重新执行。
7. 任一门禁未通过，结论固定为 `NO-GO`。只有全部硬门禁获得可复核证据后，责任人才能记录 `GO`；工程脚本或 Codex 不得代签。

## 7. 稳定拒绝码与隐私违规码

`CorpusGovernance.prepare` 当前可能产生的 `CorpusRejection.reason` 包括：

- 基础准入：`missing_source`、`missing_license`、`invalid_license_identifier`、`invalid_ingestion_time`、`missing_metadata`、`feature_schema_mismatch`、`invalid_raw_digest`、`invalid_normalized_digest`、`invalid_manifest_identifier`；
- 标签审核：`missing_label_guideline_version`、`invalid_label_guideline_version`、`missing_label_evidence_id`、`invalid_label_evidence_id`、`missing_reviewer_id`、`invalid_reviewer_id`、`invalid_review_time`、`missing_review_policy_version`、`invalid_review_policy_version`、`not_human_approved`、`ambiguous_source_label`、`label_conflict`；
- 来源和授权：`missing_source_dataset_id`、`invalid_source_dataset_id`、`missing_source_version`、`invalid_source_version`、`invalid_source_evidence_digest`、`missing_authorization_basis_id`、`invalid_authorization_basis_id`、`authorization_not_active`；
- 权利和时间：`internal_training_not_allowed`、`endpoint_weight_distribution_not_allowed`、`invalid_authorization_approval_time`、`missing_authorization_expiry`、`conflicting_authorization_expiry`、`invalid_authorization_expiry`、`authorization_expired`；
- 隐私：`privacy_not_approved`、`missing_sanitization_policy_version`、`invalid_sanitization_policy_version`、`invalid_privacy_review_time`、`invalid_privacy_evidence_digest`、`invalid_sanitized_representation_digest`、`sanitized_representation_digest_mismatch`；
- 批次和冲突：`candidate_limit_exceeded`、`raw_label_conflict`、`normalized_label_conflict`、`exact_duplicate`。

无效 `CorpusSplitPolicy` 通过 `ValueError("invalid_split_policy")` 失败，不会形成 `CorpusRejection`。Snapshot 拒绝统计不得把它误报为样本拒绝码。

`PrivacyScanner` 当前违规码为 `forbidden_value`、`credential_assignment`、`url_query`、`private_path`、`email_address`、`line_break` 和 `raw_text_field`。它只检查结构化输出边界并返回稳定代码，不执行邮件脱敏，也不能代替人工隐私审核、权利确认或 snapshot 审批。

## 8. 模板维护规则

- 代码是字段名、枚举和拒绝码的事实来源。Corpus Schema 变化时，逐字段重新核对全部模板。
- 模板的扩展治理字段不得伪装成 dataclass 字段；必须标明“受控系统字段”或“由 manifest 派生”。
- 模板只记录 ID、digest、版本、计数、状态和必要决定，不复制真实正文或证据内容。
- 模板本身可以进入 Git；任何填写后的真实版本均不得进入 Git。

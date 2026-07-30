# Corpus Snapshot 审批模板

> 本模板只允许记录计数、稳定 ID、digest、版本、时间和状态。不得保存或链接可公开访问的样本正文、完整邮件头、附件内容或敏感证据。

## 1. Snapshot 身份与契约

| 字段 | 填写值 | 来源 |
| --- | --- | --- |
| snapshot ID | `[受控系统生成的不可变 ID]` | 受控系统字段；当前 `CorpusSnapshot` 无此字段 |
| snapshot record version | `[不可变版本]` | 受控系统字段 |
| corpus schema version | `3.0` | `CorpusSnapshot.schema_version` / `CorpusManifest.schema_version` |
| feature schema version | `[所有 manifest entry 的唯一版本]` | `CorpusManifestEntry.feature_schema_version` |
| manifest digest | `[64 位小写 SHA-256]` | `CorpusManifest.digest` |
| manifest entry count | `[计数]` | `len(CorpusManifest.entries)` |
| split policy version | `[稳定版本]` | 受控系统字段 |
| split policy digest | `[规范政策记录的 64 位小写 SHA-256]` | 受控系统字段；当前代码不生成 |
| source register version | `[版本或版本集合 digest]` | 受控系统字段 |
| label guideline version | `[单一版本或批准的版本集合 digest]` | manifest entry / 受控系统 |
| sanitization policy version | `[单一版本或批准的版本集合 digest]` | manifest entry / 受控系统 |
| snapshot prepared_at | `[带时区时间]` | 受控系统字段 |
| preparation code revision ID | `[稳定代码版本 ID]` | 受控系统字段 |

如果 manifest entries 出现未经批准的 schema、label guideline 或 sanitization policy 混用，必须拒绝 snapshot，不能只记录“混合版本”。

## 2. Split 与标签计数

所有计数必须由同一固定 manifest 派生；总数不一致即 `NO-GO`。

| 维度 | train | validation | test | total |
| --- | ---: | ---: | ---: | ---: |
| 全部样本 | `[计数]` | `[计数]` | `[计数]` | `[计数]` |
| benign | `[计数]` | `[计数]` | `[计数]` | `[计数]` |
| phishing | `[计数]` | `[计数]` | `[计数]` | `[计数]` |
| zh | `[计数]` | `[计数]` | `[计数]` | `[计数]` |
| en | `[计数]` | `[计数]` | `[计数]` | `[计数]` |
| mixed | `[计数]` | `[计数]` | `[计数]` | `[计数]` |
| other / unsupported | `[计数]` | `[计数]` | `[计数]` | `[计数]` |

一致性：split 总计 = 标签总计 = 语言总计 = manifest entry count。任何未知标签都不得进入 manifest；`reject` 和 `unresolved` 只计入拒绝/审核统计。

## 3. 来源与时间分组统计

只写稳定 group ID 和计数，不写来源 URL、路径、名称或样本内容。

| `source_group` | train | validation | test | total | source register version | rights status |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| `[稳定非敏感 ID]` | `[计数]` | `[计数]` | `[计数]` | `[计数]` | `[版本]` | `[active / expired / revoked / unresolved]` |

| time group ID | 预先冻结的时间范围 | train | validation | test | total | basis field |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `[稳定 ID]` | `[起止时间及时区]` | `[计数]` | `[计数]` | `[计数]` | `[计数]` | `[ingested_at / approved external event time]` |

当前 `CorpusSplitPolicy.test_after` 和代码中的时间 holdout 使用 `CorpusCandidate.ingested_at`，语义为严格晚于 cutoff 才进入 test。若正式政策使用原始消息事件时间，必须在受控政策和派生统计中明确记录，不能声称当前字段自动实现该政策。

## 4. 去重与泄漏隔离

| 检查 | 算法/政策版本 | 检查组数量 | 跨 split 违规组数量 | 结果 | evidence ID / digest |
| --- | --- | ---: | ---: | --- | --- |
| exact duplicate (`raw_hash`) | `[版本]` | `[计数]` | `[计数]` | `pending` | `[受控 ID / SHA-256]` |
| normalized duplicate (`duplicate_group`) | `[版本]` | `[计数]` | `[计数]` | `pending` | `[受控 ID / SHA-256]` |
| near duplicate (`near_duplicate_group`) | `near-v1` | `[计数]` | `[计数]` | `pending` | `[受控 ID / SHA-256]` |
| template (`template_group`) | `[政策版本]` | `[计数]` | `[计数]` | `pending` | `[受控 ID / SHA-256]` |
| campaign (`campaign_group`) | `[政策版本]` | `[计数]` | `[计数]` | `pending` | `[受控 ID / SHA-256]` |
| connected-component isolation | `[政策版本]` | `[计数]` | `[计数]` | `pending` | `[受控 ID / SHA-256]` |

通过要求：每项跨 split 违规组数量必须为 `0`，结果必须为 `passed`。空白、`pending`、扫描未运行或抽样检查不能替代全量隔离检查。

## 5. Holdout 冻结与 test 不可见性

| 门禁 | 冻结配置/状态 | evidence ID / digest | 结果 |
| --- | --- | --- | --- |
| source holdout | `[冻结的 test_source_groups 规范摘要]` | `[受控 ID / SHA-256]` | `pending` |
| time holdout | `[冻结的带时区 test_after 与严格比较语义]` | `[受控 ID / SHA-256]` | `pending` |
| holdout 关联组整体进入 test | `[违规组计数]` | `[受控 ID / SHA-256]` | `pending` |
| test labels hidden before candidate selection | `[hidden / exposed / unresolved]` | `[访问审计 ID / digest]` | `pending` |
| test metrics hidden before model/threshold/calibration choice | `[hidden / exposed / unresolved]` | `[访问审计 ID / digest]` | `pending` |

任一 test 暴露或状态不明：当前 snapshot 不得用于 Phase 3 模型选型，应重新建立独立 test 或保持 `NO-GO`。

## 6. 拒绝统计

| 类别 | 稳定拒绝码 | count |
| --- | --- | ---: |
| 基础 | `missing_source` | `[计数]` |
| 基础 | `missing_license` | `[计数]` |
| 基础 | `invalid_license_identifier` | `[计数]` |
| 基础 | `invalid_ingestion_time` | `[计数]` |
| 基础 | `missing_metadata` | `[计数]` |
| 基础 | `feature_schema_mismatch` | `[计数]` |
| 基础 | `invalid_raw_digest` | `[计数]` |
| 基础 | `invalid_normalized_digest` | `[计数]` |
| 基础 | `invalid_manifest_identifier` | `[计数]` |
| 标签 | `missing_label_guideline_version` | `[计数]` |
| 标签 | `invalid_label_guideline_version` | `[计数]` |
| 标签 | `missing_label_evidence_id` | `[计数]` |
| 标签 | `invalid_label_evidence_id` | `[计数]` |
| 标签 | `missing_reviewer_id` | `[计数]` |
| 标签 | `invalid_reviewer_id` | `[计数]` |
| 标签 | `invalid_review_time` | `[计数]` |
| 标签 | `missing_review_policy_version` | `[计数]` |
| 标签 | `invalid_review_policy_version` | `[计数]` |
| 标签 | `not_human_approved` | `[计数]` |
| 标签 | `ambiguous_source_label` | `[计数]` |
| 标签 | `label_conflict` | `[计数]` |
| 来源/授权 | `missing_source_dataset_id` | `[计数]` |
| 来源/授权 | `invalid_source_dataset_id` | `[计数]` |
| 来源/授权 | `missing_source_version` | `[计数]` |
| 来源/授权 | `invalid_source_version` | `[计数]` |
| 来源/授权 | `invalid_source_evidence_digest` | `[计数]` |
| 来源/授权 | `missing_authorization_basis_id` | `[计数]` |
| 来源/授权 | `invalid_authorization_basis_id` | `[计数]` |
| 来源/授权 | `authorization_not_active` | `[计数]` |
| 权利/时间 | `internal_training_not_allowed` | `[计数]` |
| 权利/时间 | `endpoint_weight_distribution_not_allowed` | `[计数]` |
| 权利/时间 | `invalid_authorization_approval_time` | `[计数]` |
| 权利/时间 | `missing_authorization_expiry` | `[计数]` |
| 权利/时间 | `conflicting_authorization_expiry` | `[计数]` |
| 权利/时间 | `invalid_authorization_expiry` | `[计数]` |
| 权利/时间 | `authorization_expired` | `[计数]` |
| 隐私 | `privacy_not_approved` | `[计数]` |
| 隐私 | `missing_sanitization_policy_version` | `[计数]` |
| 隐私 | `invalid_sanitization_policy_version` | `[计数]` |
| 隐私 | `invalid_privacy_review_time` | `[计数]` |
| 隐私 | `invalid_privacy_evidence_digest` | `[计数]` |
| 隐私 | `invalid_sanitized_representation_digest` | `[计数]` |
| 隐私 | `sanitized_representation_digest_mismatch` | `[计数]` |
| 批次/冲突 | `candidate_limit_exceeded` | `[计数]` |
| 批次/冲突 | `raw_label_conflict` | `[计数]` |
| 批次/冲突 | `normalized_label_conflict` | `[计数]` |
| 批次/冲突 | `exact_duplicate` | `[计数]` |

| 汇总字段 | 填写值 |
| --- | --- |
| rejected sample count | `[所有 CorpusRejection 的总数]` |
| rejection code count sum | `[上表 count 总和]` |
| reconciliation result | `[passed / failed]` |

`invalid_split_policy` 是调用级 `ValueError`，不属于样本 rejection；如发生，应将整个准备运行标记失败并重新冻结政策。

## 7. 权利、到期和撤回

| 检查 | 状态 | affected item count | evidence ID / digest |
| --- | --- | ---: | --- |
| 所有来源授权当前仍有效 | `pending` | `[计数]` | `[受控 ID / SHA-256]` |
| `internal_training_allowed=true` 全量成立 | `pending` | `[例外计数]` | `[受控 ID / SHA-256]` |
| `endpoint_weight_distribution_allowed=true` 全量成立 | `pending` | `[例外计数]` | `[受控 ID / SHA-256]` |
| 地域和产品限制与计划一致 | `pending` | `[例外计数]` | `[受控 ID / SHA-256]` |
| 权利到期检查时间 | `[带时区时间]` | `[到期/临期计数]` | `[受控 ID / SHA-256]` |
| 撤回映射完整 | `pending` | `[未映射计数]` | `[mapping ID / digest]` |
| 删除和回滚路径可执行 | `pending` | `[例外计数]` | `[流程 ID / digest]` |

撤回映射必须能从 source/authorization/item ID 定位受影响 snapshot，并进一步定位已训练模型和 Endpoint Release（若未来存在）。当前没有已批准 snapshot 或 Unified Model Release 时也要记录明确的空映射状态，不能省略机制。

## 8. Snapshot 审批

| 角色 | 稳定审批人 ID | 决定 | decided_at | evidence ID / digest |
| --- | --- | --- | --- | --- |
| 数据所有者 | `[受控 ID]` | `pending` | `[带时区时间]` | `[受控 ID / SHA-256]` |
| 安全负责人 | `[受控 ID]` | `pending` | `[带时区时间]` | `[受控 ID / SHA-256]` |
| 隐私负责人 | `[受控 ID]` | `pending` | `[带时区时间]` | `[受控 ID / SHA-256]` |
| 法务 | `[受控 ID]` | `pending` | `[带时区时间]` | `[受控 ID / SHA-256]` |
| 模型治理负责人 | `[受控 ID]` | `pending` | `[带时区时间]` | `[受控 ID / SHA-256]` |

| 最终字段 | 填写值 |
| --- | --- |
| final approval status | `pending` |
| final decision | `NO-GO` |
| approved manifest digest | `[批准时固定；当前留空]` |
| approval evidence ID / digest | `[受控 ID / SHA-256]` |
| next mandatory review time | `[带时区时间]` |

只有全部统计一致、隔离与 holdout 通过、test 未暴露、权利有效、撤回映射完整且全部必要责任人批准时，final approval status 才能设为 `approved`。空白、`pending`、条件未满足或证据不可核验一律为 `NO-GO`。

## 9. 完全虚构的未批准示例

`snapshot ID=snapshot-fictional-001`，manifest digest 未填写，所有检查为 `pending`，最终决定为 `NO-GO`。该示例不是 Approved Training Corpus。

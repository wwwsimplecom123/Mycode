# 标签人工审核模板

> 只记录受控系统中的非敏感引用 ID，不得在表格、批注、导出或 Git 中填写完整邮件正文、完整邮件头、附件内容或可识别人员信息。

## 1. 标签定义

| 审核处置 | 定义 | 是否可映射到 `CorpusCandidate.final_label` |
| --- | --- | --- |
| `benign` | 证据支持该样本不是用于欺骗收件人泄露信息、执行危险操作或转移资产的钓鱼邮件，且标签指南允许纳入正常类 | 是，映射为 `CorpusLabel.BENIGN` |
| `phishing` | 证据支持该样本通过冒充、欺骗或社会工程诱导收件人泄露信息、执行危险操作或转移资产 | 是，映射为 `CorpusLabel.PHISHING` |
| `reject` | 样本存在来源、权利、隐私、质量、冲突、污染或审核证据问题，不得进入候选集 | 否，不构造 `CorpusCandidate` |
| `unresolved` | 现有证据不足以可靠确定 `benign` 或 `phishing`，需补充证据或升级复核 | 否，不构造 `CorpusCandidate` |

`spam` 和 `ham` 只是可能出现的原始标签语义，不得自动映射为 `phishing` 和 `benign`。必须根据当前标签指南逐样本人工复核；广告垃圾邮件可能不是钓鱼邮件，ham 也不自动满足正常类准入条件。

## 2. 审核批次控制

| 字段 | 填写值 |
| --- | --- |
| review batch ID | `[稳定非敏感 ID]` |
| `label_guideline_version` | `[稳定版本]` |
| `review_policy_version` | `[稳定版本]` |
| linked source register ID / version | `[受控系统 ID / 版本]` |
| reviewer qualification policy version | `[稳定版本]` |
| batch status | `pending` |
| test visibility status | `[hidden / exposed / not_applicable]` |

如果审核人因模型选择或 test 指标而获知预期标签，必须标记潜在污染并升级独立复核；不得为改善指标修改标签。

## 3. 样本审核记录

每行只使用稳定 ID。受控系统中的审核证据可以指向最小必要的查看界面，但导出记录不得包含正文片段。

| `item_id` | `original_label` | review disposition / `final_label` | `label_source` | `label_evidence_id` | `reviewer_id` | `reviewed_at` | `review_status` | template group | campaign group | potential contamination | reject reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `[稳定 ID]` | `[spam / ham / phishing / benign]` | `unresolved` | `[稳定来源代码]` | `[受控非敏感 ID]` | `[稳定审核人 ID]` | `[带时区时间]` | `pending` | `[稳定 ID]` | `[稳定 ID]` | `[yes / no / unknown]` | `[稳定原因代码]` |

代码字段映射：

- `review disposition=benign/phishing` 分别映射到 `CorpusCandidate.final_label`；`reject/unresolved` 不映射。
- `review_status` 只有 `approved` 可被 `CorpusGovernance.prepare` 接受；`pending`、`rejected` 或空白均拒绝。
- `reviewed_at` 必须带时区，且不得晚于候选的 `ingested_at`。
- `label_source`、`label_guideline_version`、`label_evidence_id`、`reviewer_id` 和 `review_policy_version` 必须是安全的非敏感稳定标识。
- template/campaign 归属分别映射为 `template_group` 和 `campaign_group`，用于 split 连通分量隔离。

## 4. 标签判断证据

在受控系统按标签指南核对，不在本模板复制证据内容：

- 发件身份与所声称身份是否一致；
- 是否存在凭据、付款、紧迫、冒充或其他社会工程意图；
- 链接、认证和附件元数据证据是否支持标签；
- 原始标签的定义是否与本项目 `benign`/`phishing` 定义一致；
- 是否属于仿真模板、重复模板、同一 campaign 或近重复组；
- 是否可能被既有模型结果、test 指标、来源先验或审核人协商污染。

标签证据只填写 `label_evidence_id`。不得填写正文摘录、真实地址、完整 URL、附件文件名、人员姓名或内部项目名。

## 5. 冲突复核

以下情况必须进入冲突复核：不同审核人结论不一致；明确 `phishing`/`benign` 原始标签与拟定最终标签冲突；相同 raw/normalized digest 出现不同最终标签；template/campaign 内出现无法解释的标签差异；潜在污染为 `yes` 或 `unknown`。

| 字段 | 填写值 |
| --- | --- |
| conflict review ID | `[受控非敏感 ID]` |
| conflict type | `[reviewer / source_semantics / raw_digest / normalized_digest / group / contamination]` |
| independent reviewer ID | `[稳定 ID]` |
| conflict evidence ID | `[受控 ID]` |
| decision | `[benign / phishing / reject / unresolved]` |
| decided_at | `[带时区时间]` |
| decision policy version | `[稳定版本]` |
| reason code | `[稳定代码]` |

冲突未解决时必须保持 `unresolved` 或 `reject`。代码还会以 `label_conflict`、`raw_label_conflict` 或 `normalized_label_conflict` 拒绝不一致记录，不能靠手工删除拒绝统计掩盖冲突。

## 6. 拒绝原因代码建议

治理层可使用：`insufficient_evidence`、`ambiguous_source_semantics`、`privacy_issue`、`rights_issue`、`quality_issue`、`potential_test_contamination`、`group_label_conflict`、`duplicate_label_conflict`、`out_of_scope`。这些是模板工作流代码，不是当前 `CorpusGovernance` 稳定拒绝码；导出时必须分栏统计。

## 7. 审核完成门禁

- [ ] 标签指南和审核政策版本已冻结。
- [ ] 每个样本都有 original label、最终处置、label source 和非敏感 evidence ID。
- [ ] 每个 `benign`/`phishing` 样本都有稳定 reviewer ID、带时区时间和 `approved` 状态。
- [ ] spam/ham 已逐样本人工复核，没有自动映射。
- [ ] template/campaign 归属已记录。
- [ ] 潜在污染已判断；所有冲突由独立复核解决。
- [ ] reject/unresolved 样本没有被构造成 `CorpusCandidate`。
- [ ] 模板和 Git 中没有真实正文或敏感证据。

任一项未通过：该批次不得标记完成。

## 8. 完全虚构的未批准示例

`item_id=item-fictional-001`，`original_label=spam`，审核处置为 `unresolved`，`review_status=pending`。该示例不映射到 `CorpusCandidate`，也不代表真实邮件或审核结论。

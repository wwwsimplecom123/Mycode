# Phase 3 GO/NO-GO 硬门禁清单

> 本清单只接受最终 `GO` 或 `NO-GO`。不存在 `CONDITIONAL GO`、暂时通过或默认同意。任何空白、`pending`、`unresolved`、过期、撤回、条件未满足或证据不可核验项均视为失败，最终结论必须为 `NO-GO`。

## 1. 决策记录

| 字段 | 填写值 |
| --- | --- |
| decision record ID | `[受控系统稳定 ID]` |
| decision record version | `[不可变版本]` |
| decision time | `[带时区时间]` |
| snapshot ID | `[已完成审批的 snapshot ID]` |
| manifest digest | `[64 位小写 SHA-256]` |
| corpus schema version | `3.0` |
| feature schema version | `[固定版本]` |
| snapshot approval evidence ID / digest | `[受控 ID / SHA-256]` |
| decision status | `NO-GO` |

## 2. 硬门禁

每行必须由指定责任人核验证据。`result` 只允许 `passed` 或 `failed`；未填写按 `failed`。

| # | 硬门禁 | 通过标准 | evidence ID / digest | owner role | result |
| ---: | --- | --- | --- | --- | --- |
| 1 | 存在真实 corpus snapshot | 受控系统存在非合成、不可变 snapshot ID，manifest digest 可复现，且 snapshot 已正式批准 | `[受控 ID / SHA-256]` | Corpus 负责人 | `failed` |
| 2 | 来源可追溯 | 每个 `source_dataset_id` 均绑定来源版本、取得方式/日期、文件摘要和来源证据 digest | `[受控 ID / SHA-256]` | 数据负责人 | `failed` |
| 3 | 数据许可明确 | 数据集许可文本、版本、适用范围和证据可核验；公开可下载不被视为许可 | `[受控 ID / SHA-256]` | 法务 | `failed` |
| 4 | 邮件内容处理合法 | 邮件内容权利、处理基础、目的、必要性和通信/隐私要求获得明确结论 | `[受控 ID / SHA-256]` | 法务与隐私负责人 | `failed` |
| 5 | 人工标签审核完成 | 所有准入样本为人工 `approved` 的 benign/phishing；spam/ham 未自动映射；冲突已解决 | `[受控 ID / SHA-256]` | 安全负责人 | `failed` |
| 6 | 隐私审核完成 | 所有准入样本隐私状态为 `approved`，脱敏表示 digest 匹配，敏感类别与原始材料生命周期已复核 | `[受控 ID / SHA-256]` | 隐私负责人 | `failed` |
| 7 | `internal_training_allowed=true` | 对 snapshot 中每个来源和样本均为显式 true，且范围覆盖本次 Phase 3 目的 | `[受控 ID / SHA-256]` | 数据所有者与法务 | `failed` |
| 8 | `endpoint_weight_distribution_allowed=true` | 与内部训练分开批准，显式允许衍生模型权重随公司 Endpoint Release 分发 | `[受控 ID / SHA-256]` | 法务与模型治理负责人 | `failed` |
| 9 | 授权未到期 | 按本次决策时间复核无到期、撤销或范围外记录；临期处理计划已获批准 | `[受控 ID / SHA-256]` | 数据所有者 | `failed` |
| 10 | split 无重复组泄漏 | exact、normalized、near-duplicate、template、campaign 连通分量跨 split 违规均为 0 | `[受控 ID / SHA-256]` | 工程复核人 | `failed` |
| 11 | source/time holdout 已冻结 | source groups、time cutoff、比较语义、政策版本和 digest 在模型比较前不可变 | `[受控 ID / SHA-256]` | 模型治理负责人 | `failed` |
| 12 | test 在选型前不可见 | test 标签和指标未被用于模型、特征、校准、阈值、停止规则或样本下限选择 | `[访问审计 ID / SHA-256]` | 独立评估负责人 | `failed` |
| 13 | 模型候选许可可接受 | 每个候选的官方来源、代码许可、权重许可、模型卡、使用限制和训练数据披露已核对 | `[受控 ID / SHA-256]` | 法务与模型治理负责人 | `failed` |
| 14 | 模型权重可在公司终端分发 | 候选预训练权重及未来衍生权重的公司终端分发权明确，地域/产品限制兼容 | `[受控 ID / SHA-256]` | 法务 | `failed` |
| 15 | 最低样本数已在查看 test 指标前批准 | 整体及 zh/en/mixed、来源、时间等必需分组的精确下限已预先签署，snapshot 全部达到 | `[受控 ID / SHA-256]` | 模型治理负责人 | `failed` |
| 16 | 撤回、到期、删除和回滚机制存在 | 可从来源/授权映射到 item、snapshot、模型和 release；流程、责任人、SLA 与证据已批准 | `[受控 ID / SHA-256]` | 数据、安全、隐私负责人 | `failed` |

## 3. 补充一致性核验

- [ ] snapshot 的 corpus schema version 为当前代码接受的 `3.0`。
- [ ] 所有 manifest entry 使用同一获批 feature schema version。
- [ ] manifest digest、split policy digest、source register version、label guideline version 和 sanitization policy version 与审批记录完全一致。
- [ ] train/validation/test、benign/phishing、zh/en/mixed、来源和时间统计已对账。
- [ ] 所有 `CorpusGovernance` rejection 均按稳定 code 统计并已隔离，不存在被静默补录的拒绝样本。
- [ ] `PrivacyScanner` 违规只以稳定 code/计数报告，且人工隐私审核独立完成。
- [ ] corpus、原始邮件、真实审批材料、模型和训练产物均未进入 Git。
- [ ] Phase 3 尚未在本次 GO 决定前开始模型下载、训练、微调、量化或 test 评估。

任一项未勾选即新增一个失败门禁，不得被前 16 项的通过结果抵消。

## 4. 决策算法

```text
if every hard gate is passed
   and every consistency check is complete
   and all evidence is current and verifiable:
    decision = GO
else:
    decision = NO-GO
```

禁止对结果加权、投票或用风险接受备忘录自动覆盖硬门禁。若公司决定改变某个门禁，必须先通过正式政策变更重新定义并版本化本清单，不能在单次审批中临时豁免。

## 5. 最终责任人确认

| 角色 | 稳定审批人 ID | decision | decided_at | evidence ID / digest |
| --- | --- | --- | --- | --- |
| 数据所有者 | `[受控 ID]` | `pending` | `[带时区时间]` | `[受控 ID / SHA-256]` |
| 安全负责人 | `[受控 ID]` | `pending` | `[带时区时间]` | `[受控 ID / SHA-256]` |
| 隐私负责人 | `[受控 ID]` | `pending` | `[带时区时间]` | `[受控 ID / SHA-256]` |
| 法务 | `[受控 ID]` | `pending` | `[带时区时间]` | `[受控 ID / SHA-256]` |
| 模型治理负责人 | `[受控 ID]` | `pending` | `[带时区时间]` | `[受控 ID / SHA-256]` |

| 汇总字段 | 填写值 |
| --- | --- |
| passed hard gate count | `0` |
| failed hard gate count | `16` |
| blank/unresolved count | `[计数]` |
| final decision | `NO-GO` |
| final decision evidence ID / digest | `[受控 ID / SHA-256]` |

只有责任人完成真实核验后才能改变各自决定。Codex、工程测试、模板作者或自动化脚本均无权将 `NO-GO` 改为 `GO`。

## 6. 完全虚构的未批准示例

`decision record ID=phase3-decision-fictional-001`，16 项硬门禁均为 `failed`，最终决定为 `NO-GO`。该示例不对应任何公司、人员、数据、模型或审批。

# 数据授权审批模板

> 本模板用于真实数据用途审批，不是法律意见。真实签署版只保存在受控系统。未经全部必要批准，不得创建 Approved Training Corpus。

## 1. 授权记录

| 字段 | 填写值 |
| --- | --- |
| authorization record ID / `authorization_basis_id` | `[稳定非敏感 ID]` |
| authorization record version | `[不可变版本]` |
| linked source register ID / version | `[受控系统 ID / 版本]` |
| `source_dataset_id` / `source_version` | `[稳定 ID / 版本]` |
| authorization status | `pending` |
| prepared_at | `[带时区时间]` |
| authorization evidence ID | `[受控系统稳定 ID]` |
| authorization evidence digest | `[签署证据包的 64 位小写 SHA-256]` |

代码中的 `AuthorizationStatus` 为 `pending`、`approved`、`active`、`expired`、`revoked`。只有所有必要批准完成且状态为 `approved` 或 `active` 时，才可映射到 `CorpusCandidate.authorization_status`；模板空白不得映射为批准。

## 2. 处理目的与必要性

| 字段 | 填写值 |
| --- | --- |
| 处理目的 | `[仅描述 ShieldDome Endpoint Agent Unified Model Release 的明确目的]` |
| 必要性说明 | `[为何该来源对既定目的必要，以及不用真实内容的替代方案为何不足]` |
| 数据最小化范围 | `[允许的字段、时间范围、语言和样本范围]` |
| 预期处理活动 | `[取得、脱敏、审核、特征生成、训练、评估、删除]` |
| 排除数据 | `[不允许处理的类别或范围]` |
| 禁止用途 | `[例如用户画像、营销、身份推断、终端个性化训练]` |

## 3. 分离的权利决定

每项必须单独选择。空白、`unresolved` 或带条件但条件尚未证明的决定均按 `false` 处理。

| 决定 | 选择 | 范围与条件 | 证据 ID |
| --- | --- | --- | --- |
| `internal_training_allowed` | `[true / false / unresolved]` | `[允许的训练目的、方法和数据范围]` | `[受控 ID]` |
| corpus redistribution allowed | `[true / false / unresolved]` | `[允许的接收方和形式；通常为 false]` | `[受控 ID]` |
| `endpoint_weight_distribution_allowed` | `[true / false / unresolved]` | `[允许将衍生权重随 Endpoint Release 分发的范围]` | `[受控 ID]` |

`internal_training_allowed=true` 不推出 corpus 再分发或终端权重分发；数据集许可也不自动推出邮件内容处理权或衍生权重分发权。

## 4. 范围、期限和生命周期

| 字段 | 填写值 |
| --- | --- |
| 地域范围 | `[允许和禁止的处理/分发地域]` |
| 产品范围 | `[仅允许的产品、模型和 release 范围]` |
| `authorization_approved_at` | `[带时区批准时间；批准完成前不填]` |
| `authorization_expires_at` | `[带时区到期时间]` |
| `authorization_no_expiry` | `[true / false]` |
| 有效期说明 | `[起始、生效、复审周期]` |
| 撤回机制 | `[流程 ID、责任人、处理 SLA]` |
| 到期处理 | `[停止准入、隔离 snapshot、release 影响评估]` |
| 留存要求 | `[原始、脱敏、审核和日志的分别期限]` |
| 删除要求 | `[触发条件、方法、删除证明 ID]` |
| 回滚要求 | `[受影响 snapshot/model/release 的禁用或替换流程]` |

到期与明确无期限必须互斥。空白不等于无期限。当前代码在准入时仅相对 `ingested_at` 检查授权期限；公司流程仍须在 snapshot 审批和每次 GO/NO-GO 时按实际时间重新检查到期、撤销和范围变化。

## 5. 访问和保护

| 字段 | 填写值 |
| --- | --- |
| 原始材料访问范围 | `[最小角色集合和访问控制 ID]` |
| 脱敏材料访问范围 | `[最小角色集合]` |
| 审批证据访问范围 | `[最小角色集合]` |
| 存储控制 | `[受控系统和加密/审计控制 ID]` |
| 导出限制 | `[允许的非敏感 ID、digest、计数和状态]` |
| 安全事件处理 | `[流程 ID]` |

## 6. 必要责任人审批

每一角色必须记录独立决定。`approved_with_unmet_conditions`、`pending`、空白或无法核验证据均不属于批准。

| 角色 | 稳定审批人 ID | 决定 | decided_at | approval evidence ID | evidence digest | 限制/理由代码 |
| --- | --- | --- | --- | --- | --- | --- |
| 数据所有者 | `[受控 ID]` | `pending` | `[带时区时间]` | `[受控 ID]` | `[SHA-256]` | `[代码]` |
| 安全负责人 | `[受控 ID]` | `pending` | `[带时区时间]` | `[受控 ID]` | `[SHA-256]` | `[代码]` |
| 隐私负责人 | `[受控 ID]` | `pending` | `[带时区时间]` | `[受控 ID]` | `[SHA-256]` | `[代码]` |
| 法务 | `[受控 ID]` | `pending` | `[带时区时间]` | `[受控 ID]` | `[SHA-256]` | `[代码]` |
| 模型治理负责人 | `[受控 ID]` | `pending` | `[带时区时间]` | `[受控 ID]` | `[SHA-256]` | `[代码]` |

允许角色决定：`approved`、`rejected`、`pending`、`withdrawn`。具体公司政策若允许某角色标记 `not_applicable`，必须另有政策版本和证据证明该角色确实非必要；模板不得自行跳过。

## 7. 汇总结论

| 字段 | 填写值 |
| --- | --- |
| all required approvals verified | `false` |
| authorization status | `pending` |
| `internal_training_allowed` | `unresolved` |
| `endpoint_weight_distribution_allowed` | `unresolved` |
| final decision | `NO-GO` |
| decision evidence ID / digest | `[受控 ID / SHA-256]` |

只有全部必要角色为 `approved`、证据可核验、两项代码要求的权利均严格为 `true`、授权有效且所有范围条件满足时，授权状态才可设为 `approved` 或 `active`。否则不得构造可准入的 `CorpusCandidate`。

## 8. 完全虚构的未批准示例

`authorization_basis_id=authorization-fictional-001`，所有角色决定均为 `pending`，两项权利均为 `unresolved`，最终决定为 `NO-GO`。该示例不是公司审批记录。

# 隐私审核模板

> 真实正文不得复制到本模板、审批导出或 Git。只记录类别代码、计数、稳定 ID、digest、政策版本和状态。

## 1. 审核记录控制

| 字段 | 填写值 |
| --- | --- |
| privacy review record ID | `[受控系统稳定 ID]` |
| review scope | `[source_dataset_id / source_version / item ID 集合的受控引用]` |
| `sanitization_policy_version` | `[稳定版本]` |
| privacy review policy version | `[稳定版本]` |
| `privacy_review_status` | `pending` |
| privacy reviewer ID | `[稳定非敏感 ID]` |
| `privacy_reviewed_at` | `[带时区时间；审核完成前不填]` |
| `privacy_evidence_digest` | `[证据包的 64 位小写 SHA-256]` |
| `sanitized_representation_digest` | `[脱敏表示的 64 位小写 SHA-256]` |

只有 `privacy_review_status=approved`、时间与 digest 均有效且脱敏表示 digest 匹配时，才可映射为可准入的 `CorpusCandidate`。`pending`、`rejected`、空白或无法核验证据均按未批准处理。

## 2. 敏感类别检查

每类记录 `present`、`not_detected`、`removed`、`generalized`、`retained_with_approved_necessity` 或 `unresolved`，并仅附受控 evidence ID；不得复制命中值。

| 类别 | 状态 | 数量 | 处理方法代码 | evidence ID | 是否仍进入脱敏表示 |
| --- | --- | ---: | --- | --- | --- |
| 姓名 | `unresolved` | `[计数]` | `[代码]` | `[受控 ID]` | `[yes / no / unresolved]` |
| 邮箱和联系方式 | `unresolved` | `[计数]` | `[代码]` | `[受控 ID]` | `[yes / no / unresolved]` |
| 身份信息 | `unresolved` | `[计数]` | `[代码]` | `[受控 ID]` | `[yes / no / unresolved]` |
| 账号和凭据 | `unresolved` | `[计数]` | `[代码]` | `[受控 ID]` | `no` |
| Token 和密钥 | `unresolved` | `[计数]` | `[代码]` | `[受控 ID]` | `no` |
| 内部项目及商业秘密 | `unresolved` | `[计数]` | `[代码]` | `[受控 ID]` | `[yes / no / unresolved]` |
| 合同和财务信息 | `unresolved` | `[计数]` | `[代码]` | `[受控 ID]` | `[yes / no / unresolved]` |
| 通信秘密 | `unresolved` | `[计数]` | `[代码]` | `[受控 ID]` | `[yes / no / unresolved]` |
| URL 查询参数 | `unresolved` | `[计数]` | `[代码]` | `[受控 ID]` | `no` |
| 附件风险 | `unresolved` | `[计数]` | `[仅元数据/内容隔离/拒绝等代码]` | `[受控 ID]` | `[yes / no / unresolved]` |

附件风险审核必须区分附件元数据与附件内容。未经单独授权和安全流程，不得打开、预览、解析、解压或执行附件来填写本模板。

## 3. 去标识化与匿名化判断

| 字段 | 填写值 |
| --- | --- |
| 去标识化状态 | `[not_started / partial / complete / failed]` |
| 去标识化方法和政策版本 | `[稳定代码 / 版本]` |
| 是否达到匿名化 | `[yes / no / unresolved]` |
| 匿名化判断依据 ID | `[受控证据 ID]` |
| 重识别风险 | `[low / medium / high / unresolved]` |
| 稀有模板/签名记忆风险 | `[low / medium / high / unresolved]` |
| data minimization verified | `[true / false]` |

去标识化不等于匿名化，也不自动获得训练授权。即使匿名化判断为 `yes`，仍须完成来源、内容权利、内部训练和终端权重分发审批。

## 4. 原始材料与生命周期

| 字段 | 填写值 |
| --- | --- |
| 原始材料留存状态 | `[not_retained / retained_controlled / deletion_pending / deleted / unresolved]` |
| 原始材料存储控制 ID | `[受控系统 ID]` |
| 原始材料访问角色 | `[最小角色集合]` |
| 留存期限 | `[期限和依据 ID]` |
| 删除触发条件 | `[到期、撤回、拒绝、目的完成等]` |
| 删除证明 ID / digest | `[受控 ID / SHA-256]` |
| 脱敏材料留存要求 | `[期限和范围]` |
| snapshot/release 撤回映射 ID | `[受控 ID]` |

## 5. PrivacyScanner 辅助检查

`PrivacyScanner` 只检查 `CorpusCandidate`、`FeatureVector` 和 `CorpusManifest` 的结构化输出边界，不能代替人工隐私审核，也不是邮件脱敏器。当前 violation code：

- `forbidden_value`
- `credential_assignment`
- `url_query`
- `private_path`
- `email_address`
- `line_break`
- `raw_text_field`

| 字段 | 填写值 |
| --- | --- |
| scanner version / code revision ID | `[稳定版本]` |
| scanned object type | `[candidate / feature_vector / manifest]` |
| scan status | `[safe / violations_found / not_run]` |
| violation code counts | `[只写 code: count]` |
| scan evidence digest | `[输出的 SHA-256；不含命中内容]` |
| manual follow-up status | `[pending / complete / rejected]` |

自动扫描为 `safe` 也不能把 `privacy_review_status` 自动设置为 `approved`。

## 6. 隐私结论

| 字段 | 填写值 |
| --- | --- |
| all categories resolved | `false` |
| data minimization accepted | `false` |
| de-identification accepted | `false` |
| raw retention accepted | `false` |
| `privacy_review_status` | `pending` |
| reviewer ID | `[稳定 ID]` |
| reviewed_at | `[带时区时间]` |
| privacy evidence ID / digest | `[受控 ID / SHA-256]` |
| restrictions / reason codes | `[稳定代码]` |

任一类别为 `unresolved`、必要性未证明、凭据/密钥/查询参数仍进入表示、原始材料状态不明或撤回删除机制缺失时，结论不得为 `approved`。

## 7. 完全虚构的未批准示例

`privacy review record ID=privacy-fictional-001`，所有类别为 `unresolved`，`privacy_review_status=pending`。该示例不包含邮件内容，不是隐私批准。

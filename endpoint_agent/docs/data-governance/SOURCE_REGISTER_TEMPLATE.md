# 数据来源登记模板

> 仅在公司批准的受控系统中填写真实记录。Git 版本保持空白或使用明确虚构、未批准的示例。公开可下载不等于允许训练。

## 1. 记录控制

| 字段 | 填写值 |
| --- | --- |
| source register record ID | `[受控系统稳定 ID]` |
| source register version | `[不可变版本]` |
| record status | `pending` |
| created_at | `[带时区时间]` |
| last_reviewed_at | `[带时区时间]` |
| supersedes record ID | `[无则写 none]` |

允许状态：`draft`、`pending_review`、`approved_for_authorization_review`、`rejected`、`withdrawn`、`expired`。除 `approved_for_authorization_review` 外均不得进入数据授权流程；该状态本身也不代表已获训练授权。

## 2. 来源身份与取得

| 字段 | 填写值 |
| --- | --- |
| `source_dataset_id` | `[稳定非敏感 ID]` |
| `source_version` | `[不可变版本或发布日期]` |
| `source_group` | `[稳定非敏感分组 ID]` |
| source origin type | `[official_public / internal / third_party]` |
| 官方或内部来源 | `[受控系统引用 ID，不填 URL 或路径]` |
| 取得方式 | `[受控流程 ID 与简述]` |
| 取得日期 | `[YYYY-MM-DD]` |
| 文件清单摘要 | `[仅文件数量、类型、总大小和清单 digest；不填文件名或路径]` |
| `source_evidence_digest` | `[来源证据包的 64 位小写 SHA-256]` |
| 原始标签语义 | `[原来源如何定义每个标签]` |
| 数据时间范围 | `[起止时间、时区、未知范围说明]` |
| 语言范围 | `[zh / en / mixed / other 及计数]` |

## 3. 许可证与内容权利

以下各项必须分别核对，不能相互推导：

| 权利对象 | 证据字段 | 决定 | 说明 |
| --- | --- | --- | --- |
| 源代码许可 | source code license ID、版本、evidence ID、digest | `[allowed / denied / not_applicable / unresolved]` | 只覆盖实际被许可的软件源码 |
| 数据集许可 | `license_identifier`、`license_text_digest`、license evidence ID | `[allowed / denied / unresolved]` | 许可证文本与适用数据版本必须绑定 |
| 邮件内容权利 | content-rights evidence ID、digest | `[allowed / denied / unresolved]` | 数据集或源码许可不自动覆盖邮件作者、收发方或通信内容权利 |
| 内部训练权 | authorization evidence ID | `[allowed / denied / unresolved]` | 必须由数据授权模板另行批准 |
| corpus 再分发权 | redistribution evidence ID | `[allowed / denied / unresolved]` | 通常与内部训练和权重分发不同 |
| 模型权重分发权 | weight-distribution evidence ID | `[allowed / denied / unresolved]` | 必须明确允许公司终端分发衍生权重 |

许可详情：

| 字段 | 填写值 |
| --- | --- |
| `license_identifier` | `[稳定非敏感 ID；映射到 CorpusCandidate.license_source]` |
| `license_text_digest` | `[许可文本受控副本的 64 位小写 SHA-256]` |
| license evidence ID | `[受控系统稳定 ID]` |
| license version / effective date | `[版本及生效日期]` |
| attribution / notice obligations | `[义务摘要及证据 ID]` |
| additional restrictions | `[限制摘要；无则写 none]` |

## 4. 责任、范围与期限

| 字段 | 填写值 |
| --- | --- |
| 数据所有者 | `[受控系统角色或稳定 ID]` |
| 授权责任人稳定 ID | `[非姓名、非邮箱的稳定 ID]` |
| 授权期限 | `[起止时间，或经明确批准的 no_expiry]` |
| 撤回机制 | `[撤回流程 ID、通知渠道类型、处理 SLA]` |
| 是否允许内部训练 | `[true / false / unresolved]` |
| 是否允许 corpus 再分发 | `[true / false / unresolved]` |
| 是否允许终端权重分发 | `[true / false / unresolved]` |
| 数据地域限制 | `[允许/禁止地域及证据 ID]` |
| 产品范围限制 | `[允许的产品、模型用途和版本范围]` |
| 禁止用途 | `[明确列出]` |
| 原始材料访问范围 | `[最小角色集合及访问控制 ID]` |
| 留存和删除要求 | `[期限、触发条件、删除证明 ID]` |
| 当前状态 | `pending_review` |

`true` 只表示来源登记中的初步权利结论，不能替代 [DATA_AUTHORIZATION_TEMPLATE.md](DATA_AUTHORIZATION_TEMPLATE.md) 的必要责任人审批。任何 `unresolved`、空白、过期或证据不可核验状态均按不允许处理。

## 5. 来源准入复核

- [ ] 来源身份、版本、取得方式和日期可追溯。
- [ ] 文件清单摘要和 `source_evidence_digest` 可在受控系统复核。
- [ ] 原始标签语义清楚；没有把 spam/ham 直接解释为 phishing/benign。
- [ ] 源代码许可、数据集许可和邮件内容权利已分别核对。
- [ ] 内部训练、corpus 再分发和终端权重分发已分别判断。
- [ ] 地域、产品、期限、撤回、留存和删除限制已记录。
- [ ] 真实材料、正文、人员信息、路径和凭据未复制到本记录导出版或 Git。

任一项未勾选：记录状态不得变为 `approved_for_authorization_review`。

## 6. 完全虚构的未批准示例

| 字段 | 示例 |
| --- | --- |
| `source_dataset_id` | `dataset-fictional-001` |
| `source_version` | `version-fictional-001` |
| `source_group` | `source-fictional-public-001` |
| `license_identifier` | `license-fictional-review-required` |
| record status | `pending_review` |
| 内部训练权 | `unresolved` |
| corpus 再分发权 | `unresolved` |
| 终端权重分发权 | `unresolved` |

该示例不对应任何公司、人员、数据集、邮件或许可，也不是批准结果。

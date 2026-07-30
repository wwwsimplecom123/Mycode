# ShieldDome Endpoint Agent Phase 3 前置准入审计

核对日期：2026-07-30

审计范围：Phase 3 的真实语料、许可、人工审核、隐私处理和泄漏隔离前置条件；只读审计 `phishingDP-main/`，不实施文本编码模型、训练、下载、模型导出或服务启动。

## 1. 执行摘要

**审计结论：NO-GO。当前不允许开始正式文本编码模型选型，也不允许选择 Unified Model Release。**

直接阻塞原因如下：

- 仓库中没有 Approved Training Corpus，也没有可核验的真实 corpus snapshot 或持久化 manifest。
- `phishingDP-main/` 声称依赖的 `spam_assassin.csv` 不存在；没有数据版本、下载来源、转换脚本、校验和、标签说明或授权证据。
- SpamAssassin 官方 public corpus 页面说明邮件文本版权仍归原始发件人，且页面没有给出覆盖公司训练和终端权重分发的明确数据集许可。因此“公开可下载”不能替代许可审查。
- `phishingDP-main/LICENSE` 声明 Apache License 2.0，只能初步覆盖该参考项目源码；不能扩张到缺失的 CSV、邮件内容、预训练模型或未来训练权重。
- `phishingDP-main/` 没有预训练编码器、可用模型权重或模型来源清单。现有静态评估数组缺少与数据、代码、模型和运行环境绑定的 manifest。
- Phase 1 的 `CorpusCandidate` 已覆盖基本人工批准、许可标识、哈希、分组和 split，但还不能表达并强制执行授权依据、隐私处理、审核责任、内部训练权和终端权重分发权。
- Phase 2 的 24 个合成样本及其 ignored ONNX/报告产物明确为 `synthetic_only=true`、`release_eligible=false`，不得用于 Phase 3 正式候选选择。

本次没有读取或展示 `prediction_results.log` 的邮件正文，只核对了文件类型、大小（7,700 字节）和 SHA-256。没有启动 Flask/FastAPI/HTTP 服务，没有执行训练，也没有下载模型或数据集。

## 2. 当前阶段状态

| 阶段 | `DEVELOPMENT_PLAN.md` 状态 | Git/实现证据 | 本次结论 |
| --- | --- | --- | --- |
| Phase 0 | `complete` | `911498c chore: complete endpoint agent phase 0` | 保持 complete |
| Phase 1 | `complete` | `272dc6c feat: complete endpoint agent phase 1`；存在 `CorpusGovernance.prepare`、manifest、去重和 split 测试 | 保持 complete |
| Phase 2 | `complete` | `9564dd0 feat: complete endpoint agent baseline model evaluation`；训练侧仅接受合成数据 | 保持 complete |
| Phase 3 | `pending` | 无 Approved Training Corpus、候选编码器清单或正式 benchmark | 必须保持 pending |

Phase 2 当前在 ignored 的 `endpoint_agent/training/artifacts/` 下存在 9 份小型 ONNX 和对应 JSON/Markdown 合成实验产物。这些是既有开发产物，不是可发布模型，也不是 Approved Training Corpus 存在的证据。

## 3. `phishingDP-main` 可借鉴内容

### 3.1 静态盘点

参考目录共盘点到 26 个文件，包括：

- 一个 `app.py`；
- `LICENSE`、中英文 README 和未锁版本的 `requirements.txt`；
- 三个 Flask/Jinja 模板及十一张界面/指标图片；
- 一个 `prediction_results.log`；
- 一个训练历史 CSV、一个混淆矩阵 NPY，以及 ROC、PR、test predictions 三个 NPZ。

未发现：

- `spam_assassin.csv`；
- `phishing_model.h5`；
- ONNX、PyTorch、TensorFlow SavedModel、safetensors 或其他模型权重；
- 数据下载脚本、数据转换脚本、数据 manifest、模型卡或 SBOM；
- 可定位原始仓库和提交的有效 provenance 信息。README 的 clone URL 仍是占位值。

仅检查数组结构而未输出数组内容：

- `confusion_matrix.npy`：`(2, 2)`，`int64`；
- `roc_data.npz`：`fpr`、`tpr` 和标量 `auc`；
- `pr_data.npz`：`precision`、`recall`；
- `test_predictions.npz`：1,160 条 `y_test`、`y_pred`、`y_pred_proba`。

### 3.2 可以借鉴的思想

- 以文本基线验证端到端分类链路，而不是一开始就微调大型编码器。
- 将概率、混淆矩阵、ROC、PR 和训练历史保存为可复算的结构化评估材料。
- 将文本预处理和分类器推理封装成一条本地链路。
- 对展示层和训练逻辑进行目录区分的基本意图。

这些只属于一般设计思想。若后续采用，应由 ShieldDome 现有深模块重新实现：Feature Pipeline 继续作为训练/推理共享 seam，评估继续使用 Phase 2 的 validation-only 校准、拒判感知指标和 test-only 报告，不复制参考项目的 Flask、日志或训练代码。

## 4. 不可直接复用内容

### 4.1 数据与标签

- `app.py:33` 直接读取缺失的 `spam_assassin.csv`，没有版本、来源 URL、哈希、许可、schema 或复现步骤。
- README 把 `0/1` 描述为正常/钓鱼，代码注释又描述为正常/垃圾邮件。Spam/ham 不能自动等同于 phishing/benign；Phase 1 正确要求这类标签经人工来源确认。
- 没有人工审核状态、标签证据、语言/来源分组、事件时间、模板/活动组或隐私状态。

### 4.2 预处理、训练和模型

- `app.py:42` 使用不存在的 `TfidfVectoriozer` 名称，当前代码会在导入阶段失败。
- `app.py:43` 在 split 前对全量文本 `fit_transform`，测试集参与 TF-IDF vocabulary/IDF 拟合，构成预处理泄漏；随后又将稀疏矩阵整体转成稠密数组。
- `app.py:47` 只做样本级随机 80/20 切分，没有 `stratify`，也没有 source/time/template/campaign/duplicate/near-duplicate 隔离。
- `app.py:65` 把 `X_test/y_test` 同时作为训练期间的 validation 和最终指标集，测试集被用于训练过程观察，评估不再独立。
- 只固定 `train_test_split` 的 seed，没有固定 TensorFlow/Keras 的随机状态，结果不可确定性复现。
- 固定阈值 0.5，没有 validation-only 校准、拒判、分语言/来源/时间指标或发布资格门禁。
- 保存的 HDF5 模型不包含与 TF-IDF vocabulary、数据版本和 feature schema 的兼容 manifest；重新加载时可能把旧权重与新拟合的 TF-IDF 配对。
- 依赖全部未锁版本；代码直接导入 SciPy 但 requirements 未直接声明，Keras/TensorFlow 兼容组合也未固定。

### 4.3 可靠性与安全

- 模块导入会立即读取数据、拟合 TF-IDF、检查/训练模型并访问本地文件，无法作为可测试的纯训练模块复用。
- 代码中的 `/pdredict`、`/retrasin`、`predict_emil`、`p8rediction_results.log`、`phishsing_model.h5`、`saefig` 和 `sstatic` 等拼写与模板请求路径不一致，不能形成可运行的可复现基线。
- `app.py:279-282` 把完整用户输入邮件写入明文日志；模板又显示邮件和历史日志。这违反 Endpoint Agent 不持久化原文、证据最小化和本地加密方向。
- `app.py:327` 以 `0.0.0.0`、debug 模式启动 Flask，与 Endpoint Agent 的 Offline Operation、禁止 HTTP/监听端口约束冲突。
- 静态评估文件没有 dataset/model/code/environment digest，无法证明由当前代码和哪一版数据生成；代码也没有保存现有 `confusion_matrix.npy` 的语句，进一步表明产物与当前实现不可建立完整链路。
- `prediction_results.log` 按代码语义可能含邮件正文，不得作为训练语料、测试 fixture 或文档证据；本次未读取其内容。

## 5. 源码、数据、模型许可证矩阵

以下是工程准入判断，不替代公司法务的正式法律意见。

| 对象 | 当前证据 | 源码/数据/模型许可结论 | 公司内部训练 | 终端分发/权重再分发 |
| --- | --- | --- | --- | --- |
| `phishingDP-main` 源码 | 本地完整 Apache-2.0 文本；无 NOTICE、明确版权主体、有效上游 URL 或 commit provenance | **声明为 Apache-2.0，但来源链仍需补证。** 若复用源码，需确认授权主体并履行许可证、修改声明和归属义务 | 源码工具使用可初步按 Apache-2.0 评估，不代表数据获批 | 源码分发可初步按 Apache-2.0 评估；依赖和第三方材料另审 |
| `spam_assassin.csv` | README 声称使用；本地不存在；无转换脚本、版本、哈希或来源 | **未建立许可。** 不能证明它等同于某个官方 corpus，也不能证明 CSV 转换及邮件内容授权 | 不允许 | 不允许据此训练或分发权重 |
| Apache SpamAssassin 软件 | ASF 软件采用 Apache-2.0 | 软件许可不能外推到 public corpus 邮件文本 | 与本次数据权利无关 | 与本次权重权利无关 |
| SpamAssassin public mail corpus | 官方 README 称邮件来自公开论坛、知情提供、本人发送或公开 newsletter，同时明确邮件文本版权仍归原始发件人；未见覆盖训练/权重分发的统一数据许可 | **来源说明不等于公司训练及衍生权重分发许可。** 还存在老旧、spam≠phishing、头部可能保留真实信息等问题 | 法务、隐私和标签复核前不允许 | 未取得明确书面结论前不允许 |
| 预训练文本编码器 | 参考项目没有候选、模型卡、权重或下载来源 | 不适用；Phase 3 每个候选必须单独核对代码许可证、权重许可证、使用限制和模型卡 | 当前不允许选型 | 当前无权重可分发 |
| `phishing_model.h5` | 文件不存在；代码拟从缺失数据训练 | 无可审计权重；即使重新生成，权利仍取决于训练数据、依赖和公司批准 | 当前不允许生成正式权重 | 不允许 |
| `static/*.npy`、`*.npz`、图表 | 只有指标/预测结构；缺少数据、模型和运行 manifest | 来源和衍生权限不明，不是训练 corpus | 不作为训练输入 | 不作为模型来源或发布证据 |
| `prediction_results.log` | 文件存在；代码设计为记录完整邮件 | 邮件内容的版权、个人信息、通信秘密和公司数据授权均未建立 | 禁止作为训练数据 | 禁止复制或分发 |
| Phase 2 合成 fixture/ONNX | ShieldDome 文档明确 `synthetic_only=true`、`release_eligible=false` | 仅开发链路证据 | 可用于测试训练代码，不可用于正式模型选择 | 不得作为 Unified Model Release |

Apache-2.0 本身允许在满足条件时使用、修改和分发被许可的 Work，但许可证范围取决于实际授权的 Work。把许可证文本放在源码目录中，不会自动给缺失数据集、第三方邮件或训练权重授予同样权利。

## 6. 数据隐私和安全风险

### 6.1 邮件内容不是普通无主文本

- 邮件头和正文可能包含姓名、电子邮箱、电话、地址、账号、组织关系、内部项目、合同、财务、健康、身份或未成年人信息。
- 即使邮件公开可获得，也只能在合法、正当、必要、目的直接相关和最小范围内处理；公开性本身不是无限用途授权。
- 真实邮件训练可能构成与原收件/安全处置目的不同的二次处理，需要逐来源确认合法基础、告知/同意或其他适用依据，以及公司内部数据授权。
- 邮件可能属于私密信息和通信秘密。去标识化降低风险，但不等同于匿名化，也不能补救缺失的来源和使用授权。
- 模型可能记忆稀有姓名、地址、签名、账号或模板。正式 corpus 必须禁止秘密、凭据和不必要身份信息，并对候选表示和最终权重执行隐私测试。

### 6.2 参考项目的具体风险

- 明文 `prediction_results.log` 形成无期限原文留存和历史聚合面。
- Web 页面回显邮件与历史日志，debug/全网卡监听会扩大暴露面。
- `test_predictions.npz` 含逐样本标签和概率，但没有来源/授权/去标识化说明。
- 老旧 public corpus 的头部在多数情况下按原样保留，官方页面只说明进行了部分地址/主机名处理，不能假定完全匿名。
- 将 spam 标签自动转换为 phishing 会产生系统性标签污染；把同模板/同活动随机拆分会产生评估污染。

### 6.3 最低治理要求

- 在读取真实正文前完成数据保护影响评估、处理目的、最小字段、访问角色、存储位置、留存和删除方案审批。
- 原始材料进入受控的非 Git 数据区；训练人员默认只接触经审核的 sanitized representation。
- 扫描结果只能输出稳定违规码、计数、哈希和非敏感标识，不在报告、日志或异常中回显命中内容。
- 对撤回、许可到期或授权变更建立从 corpus snapshot 到模型 release 的追踪和禁用流程。
- 对公司邮件同时取得公司数据所有者/安全负责人授权，并由隐私/法务确认自然人个人信息和通信内容的处理依据。

## 7. Approved Training Corpus 缺口

### 7.1 现有 Phase 1 已具备的字段和约束

`CorpusCandidate` 当前具备：

- `item_id`；
- `final_label`、`original_label`、`label_source`；
- `review_status`，且仅 `approved` 可准入；
- `license_source`（manifest 中为 `license_identifier`）；
- `raw_hash`、`normalized_hash`；
- `template_group`、`campaign_group`；
- `language_group`、`source_group`；
- `ingested_at`；
- `feature_schema_version`；
- `sanitized_training_representation`。

`CorpusGovernance.prepare` 还会生成 `duplicate_group`、版本化 `near_duplicate_group` 和 `train/validation/test`，并执行 raw/normalized 标签冲突拒绝、精确去重、连通分量隔离、指定来源/严格晚于 cutoff 的 test 留出，以及不含训练正文的 manifest digest。

### 7.2 真实语料必须补齐的准入字段

下表中的字段必须在进入 Approved Training Corpus 前具备；括号内为建议的稳定字段名，最终命名可在下一窗口通过 TDD 固化。

| 准入事实 | 必需字段 | 当前状态 |
| --- | --- | --- |
| 标签及来源 | `original_label`、`final_label`、`label_source`、`label_guideline_version`、`label_evidence_id` | 前三项已有；指南版本和非敏感证据引用缺失 |
| 人工审核 | `review_status`、`reviewer_id`、`reviewed_at`、`review_policy_version`；冲突样本的复核结论 | 只有状态；责任、时间和政策版本缺失 |
| 数据来源 | `source_group`、`source_dataset_id`、`source_version`、`acquisition_method`、`source_evidence_digest` | 只有 source group；来源版本和证据缺失 |
| 授权依据 | `authorization_basis_id`、`authorization_owner`、`authorization_approved_at`、`authorization_expires_at` 或明确无期限标识 | 缺失 |
| 许可证 | `license_identifier`、`license_text_digest`、`license_source_evidence_id`、适用范围/附加限制 | 只有一个受限字符串标识，不能证明许可内容与范围 |
| 时间信息 | 原始消息/事件时间 `observed_at`、采集时间 `ingested_at`、审核时间 `reviewed_at`、授权时间；全部带时区 | 只有 ingestion time |
| 分组 | `language_group`、`source_group` | 已有；真实值仍未提供 |
| 内容指纹 | `raw_hash`、`normalized_hash`、`sanitized_representation_digest`、哈希/规范化算法版本 | 哈希已有；算法版本和真实 digest 未形成 corpus |
| 污染分组 | `template_group`、`campaign_group`、`duplicate_group`、`near_duplicate_group`、分组算法版本 | 机制已有；真实分组未执行 |
| split 隔离 | `split`、`split_policy_version`、`split_policy_digest`、source/time holdout 理由、冻结 snapshot ID | entry split 已有；政策证据、整体 snapshot ID/持久化缺失 |
| 隐私处理 | `privacy_status`、`sanitization_policy_version`、`sanitization_reviewed_at`、`sensitive_category_codes`、`raw_retention_status`、`privacy_evidence_digest` | 缺失；现有 PrivacyScanner 只扫描输出，不代替人工脱敏 |
| 内部训练权 | `internal_training_allowed`、决定人/时间、适用模型目的和限制 | 缺失；必须显式为 true 才能准入 |
| 终端权重分发权 | `endpoint_weight_distribution_allowed`、允许地区/产品/期限、决定人/时间 | 缺失；必须显式为 true 才能用于 Unified Model Release |
| 数据再分发权 | `corpus_redistribution_allowed` 及限制 | 缺失；通常应为 false，且与权重分发权分开判断 |
| 撤回与到期 | `rights_status`、`withdrawal_or_expiry_id`、受影响 snapshot/release 映射 | 缺失 |

### 7.3 结构性缺口

- 当前 `CorpusSnapshot` 只是内存结果，没有受控持久化 snapshot、不可变数据版本或签署过的 corpus manifest。
- 当前 `license_source` 只校验为安全标识，不能验证标识背后的证据、权利范围或到期状态。
- 当前 split 的时间依据是 `ingested_at`；正式时间外推评估还需要明确采用消息事件时间还是采集时间，并把政策写入 manifest。
- Phase 2 `TrainingDataset` 只接受合成数据，尚无从 Approved `CorpusSnapshot` 到训练数据的 release-grade loader/interface。
- 没有经批准的整体和分语言/来源/时间最小样本数，当前不能解释某个真实 snapshot 是否足以支撑模型比较。

## 8. GO / CONDITIONAL GO / NO-GO 结论

### NO-GO

当前不得：

- 下载或选择正式文本编码器；
- 使用 Phase 2 合成 fixture 排名候选；
- 把 `spam_assassin.csv` 的名称、静态指标或 README 声称当作真实 corpus 证据；
- 使用 `prediction_results.log`、`test_predictions.npz` 或未知来源邮件作为训练输入；
- 训练、微调、量化或导出 Unified Model Release；
- 将 Phase 3 改为 `in_progress` 或 `complete`。

只有第 9 节所有开始前门禁获得可复核证据后，才可重新审计并把结论改为 GO。满足部分条件不代表 CONDITIONAL GO；在 corpus 本体和权利证据仍不存在时，正式模型选型保持 NO-GO。

## 9. Phase 3 开始前检查表

- [ ] 至少一个真实来源已经公司数据所有者、安全、隐私/法务按用途批准；原始证据保存在受控系统，manifest 只保存非敏感 ID/digest。
- [ ] 每个数据来源有原始/官方 URL 或内部授权记录、版本、取得日期、校验和、转换步骤和许可文本快照。
- [ ] 每个候选都有明确的 `internal_training_allowed=true` 和 `endpoint_weight_distribution_allowed=true`；两项分别决策。
- [ ] 所有样本均有 benign/phishing 最终标签、标签来源、指南版本、人工审核人、审核时间和 approved 状态。
- [ ] Spam/ham 等模糊源标签均已人工复核，未自动映射为 phishing/benign。
- [ ] 已执行最小化、去标识化/匿名化判断和人工脱敏复核；无凭据、Token、秘密、完整个人地址或不必要身份信息进入训练表示。
- [ ] raw、normalized、sanitized representation 的 digest 和算法版本齐全；原始材料不进入 Git、报告或模型包。
- [ ] template/campaign/exact/normalized/near-duplicate 连通分量均未跨 split。
- [ ] 独立 source holdout 和严格 time holdout 已冻结；test 在模型/阈值/校准选择前不可见。
- [ ] corpus snapshot、manifest、split policy 和 feature schema 均有不可变版本与 digest，可从受控数据确定性复现。
- [ ] 已由模型治理方批准整体及 zh/en/mixed、来源和时间分组的精确最小样本数；每个发布必需分组均达到门槛。
- [ ] 已完成个人信息保护影响评估、访问控制、留存/删除、撤回/到期和安全事件流程。
- [ ] 每个候选编码器的官方来源、代码许可证、权重许可证、模型卡、使用限制、训练数据披露和终端再分发权已分别记录。
- [ ] 预先冻结 benchmark 协议、主次指标、拒判口径、硬件、资源限制和停止规则；不得使用 test 选择候选。
- [ ] 数据/模型/训练产物保持 Git ignore；Phase 3 实施仍只修改 `endpoint_agent/`。

## 10. 下一窗口可执行任务

下一窗口仍是“数据准入修复”，不是 Phase 3 模型开发。只有任务 1–5 全部通过后，才编写并执行 Phase 3 模型计划。

### 目标、架构与约束

**Goal：** 产生一个权利明确、人工审核、隐私合格、去重隔离且可复现的 Approved Training Corpus snapshot，供新的 GO/NO-GO 复审。

**Architecture：** 深化现有 `CorpusGovernance` 模块，但保持一个小 interface：`prepare(candidates, split_policy) -> CorpusSnapshot`。调用方只提交不可变候选事实；实现内部统一执行授权、隐私、标签、哈希、去重、连通分量和 split 门禁。训练模块只能消费获批 snapshot，不能直接读取原始来源或绕过治理。

**Seam 与 adapter：** 原始公开数据导入和公司确认案例导入将来可成为同一 intake seam 的两个 adapter；只有对应来源完成授权且确实要导入时才实现，当前不创建空 adapter。原始材料 I/O 是受控本地依赖，测试使用纯合成且无个人信息的内存替身；公开 interface 不暴露文件路径、正文或法务文件。

**Global Constraints：** Python 3.12、标准库 `unittest`、Offline Operation、仅修改 `endpoint_agent/`、不把 corpus/模型/权重/原文提交 Git、不启动网络服务、不降低 Phase 1/2 门禁、不在 GO 前使用 `$executing-plans` 实施 Phase 3。

### Task 1：建立来源与权利登记册（非代码）

- [ ] 为每个拟用来源记录唯一 ID、原始/官方位置、版本/日期、文件清单、SHA-256、标签原义和取得方式。
- [ ] 保存许可文本或内部授权决定的受控副本及 digest；分别作出内部训练、corpus 再分发、终端权重分发决定。
- [ ] 由数据所有者、安全、隐私/法务签署使用目的、地域、期限、撤回和删除要求。
- [ ] 拒绝来源不明、仅转载说明、无权利主体、只有“公开”表述或 spam/phishing 语义无法复核的来源。

**验收产物：** 不进 Git 的受控 source register；进入代码的只有非敏感来源 ID、政策版本和测试用虚构值。

### Task 2：深化 Corpus Governance interface（TDD）

计划文件范围：

- 修改 `endpoint_agent/src/shielddome_endpoint/corpus.py`：为 immutable candidate/manifest 增加权利、审核、隐私和政策证据字段；缺失或非 true 的训练/权重权利必须稳定拒绝。
- 修改 `endpoint_agent/src/shielddome_endpoint/privacy.py`：只扫描和返回稳定违规码，不回显真实值。
- 修改 `endpoint_agent/tests/test_corpus_governance.py`、`test_privacy.py`：以完全虚构数据覆盖权利缺失、到期、隐私未批准、审核不完整和 manifest 不含敏感证据内容。

按单个公开行为执行 red → green：

```powershell
python -m unittest discover -s endpoint_agent/tests -p "test_corpus_governance.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_privacy.py" -v
```

**验收结果：** `CorpusGovernance.prepare` 仍是唯一外部 seam；授权、隐私和审核复杂性没有散落到训练调用方。

### Task 3：受控导入、人工审核和隐私处理

- [ ] 只对 Task 1 获批来源编写最小 intake adapter；下载/导入命令、凭据和原始路径不进入源码或报告。
- [ ] 在受控数据区计算 raw/normalized hash，执行最小化和脱敏，记录 sanitized policy version。
- [ ] 按批准的标签指南进行人工复核；spam/ham 必须重新判断 phishing/benign，不批量自动升级。
- [ ] 对秘密、凭据、个人信息和通信内容执行人工抽检与自动扫描；不合格项拒绝而不是弱化规则。

**验收产物：** 候选记录、拒绝记录和非敏感计数；不展示任何真实正文、账号或地址。

### Task 4：冻结 split 与 corpus snapshot

- [ ] 在完整候选集上执行 raw/normalized/near-duplicate、template、campaign 连通分量分组。
- [ ] 应用预先批准的 source/time holdout；确认任一关联组不跨 train/validation/test。
- [ ] 生成不可变 snapshot ID、manifest digest、split policy digest、feature/corpus schema version 和非敏感统计。
- [ ] 由独立复核人检查随机抽样的分组与拒绝原因，不查看 test 指标选择模型。

**验收命令：**

```powershell
python -m unittest discover -s endpoint_agent/tests -v
```

真实 snapshot 的复现命令只能在受控数据环境运行，并且输出限制为 ID、digest、计数和稳定状态码。

### Task 5：重新执行 Phase 3 准入决策

- [ ] 对照第 9 节逐项附证；任何一项缺失即保持 NO-GO。
- [ ] 核对各必需分组达到事先批准的精确样本下限，不能看到指标后再降低门槛。
- [ ] 核对 source register、PIPIA、manifest、split audit 和撤回/到期映射均获批准。
- [ ] 重新检查 Git 范围、ignore 和受保护目录。

**验收结果：** 新的独立 GO/NO-GO 审计。只有 GO 后，Phase 3 才可依次执行候选编码器官方许可登记、固定 snapshot 上的冻结向量 benchmark、必要性证据充分时的微调、ONNX/量化和最低硬件测试；test 只用于最终评估。

### 计划自检

- Spec coverage：上述任务覆盖来源/许可、标签/审核、隐私、哈希/分组、split、snapshot、权重分发权和重新决策。
- Placeholder scan：没有把许可、隐私或样本门槛留给训练代码临时解释；精确样本下限必须在看 test 指标前由模型治理方正式批准。
- Type consistency：所有后续训练只消费 `CorpusGovernance.prepare(...)` 产生的获批 snapshot；intake adapter 不直接调用训练入口。

## 11. 参考来源及核对日期

以下公开来源均于 **2026-07-30** 核对；只采用官方或原始来源：

1. Apache Software Foundation，[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)：核对许可证的版权、专利和再分发条件。另参见 ASF [Applying the Apache License, Version 2.0](https://www.apache.org/legal/apply-license)，用于确认 LICENSE/NOTICE/归属不能替代第三方材料的单独权利审查。
2. Apache SpamAssassin，[Public Mail Corpus README](https://spamassassin.apache.org/old/publiccorpus/readme.html)：核对 corpus 构成、部分去标识化说明、禁止用于 live system 的警告，以及邮件文本版权仍归原始发件人的声明。
3. 全国人民代表大会常务委员会，[《中华人民共和国个人信息保护法》](https://www.npc.gov.cn/npc/c2/c30834/202108/t20210820_313088.html)：核对目的明确、最小必要、处理合法基础、公开信息的合理范围、敏感个人信息、保护措施及事前个人信息保护影响评估要求。
4. 最高人民法院，[《中华人民共和国民法典》](https://www.court.gov.cn/zixun/xiangqing/233181.html)：核对隐私、私密信息、电子邮箱个人信息以及个人信息处理的合法、正当、必要要求。
5. 中国人大网，[宪法第四十条释义](https://www.npc.gov.cn/WZWSREL3pncmR3L25wYy8vLy8vZmxzeXl3ZC94aWFuZmEvMjAxMC0wNC8xNC9jb250ZW50XzE1NjcwODQuaHRt)：核对通信自由和通信秘密保护及电子邮件内容属于通信秘密范畴的说明。

本地证据来源：`AGENTS.md`、`CONTEXT.md`、`endpoint_agent/AGENTS.md`、`README.md`、`DEVELOPMENT_PLAN.md`、`docs/USAGE.md`、`docs/TRAINING.md`、两份 Phase 2 计划、Phase 1 `corpus.py`/`privacy.py`/测试、Phase 2 训练契约，以及 `phishingDP-main/` 的 LICENSE、README、requirements、`app.py`、模板和非敏感文件/数组结构元数据。

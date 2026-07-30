# ShieldDome Endpoint Agent 使用说明

## 1. 当前可用范围

ShieldDome Endpoint Agent 是面向单个 Windows 用户、完全离线运行的本地钓鱼邮件检测产品。目前仓库只完成了 **Phase 0：脚手架与约束测试**，可用于：

- 构建并导入独立 Python 包 `shielddome_endpoint`；
- 使用首批不可变领域类型定义后续模块之间的数据契约；
- 运行离线能力、目录隔离和运行产物忽略规则测试；
- 构建最小 Python wheel，验证打包配置。

当前版本还不能分析真实邮件，也没有模型推理、Native Messaging、本地数据库、加密存储、托盘或控制台界面。请勿把当前包作为可交付的终端检测程序使用。

## 2. 环境要求

- Windows 10/11 64 位；
- Python 3.12；
- Git，可执行 `git check-ignore`；
- 在仓库根目录 `C:\Users\huohuo\Desktop\project1\ShieldDome` 执行下列命令。

当前 Phase 0 没有第三方运行时依赖，不需要访问互联网安装依赖。

## 3. 目录概览

```text
endpoint_agent/
  AGENTS.md                         Endpoint Agent 开发约束
  README.md                         产品定义与目标架构
  DEVELOPMENT_PLAN.md               分阶段开发基线
  pyproject.toml                    Python 3.12 与 PEP 517 构建配置
  _build_backend.py                 零外部依赖的本地 wheel 构建后端
  .gitignore                        本地敏感数据和构建产物忽略规则
  docs/
    USAGE.md                        本文档
    plans/2026-07-29-phase-0.md      Phase 0 实施计划
  src/shielddome_endpoint/
    __init__.py                     包版本与公开导出
    domain.py                       Phase 0 领域类型
  tests/
    test_package.py                 包导入测试
    test_domain.py                  领域契约测试
    test_offline_constraints.py     离线边界测试
    test_repository_hygiene.py      Git 忽略规则测试
```

## 4. 运行测试

在仓库根目录运行完整 Phase 0 测试：

```powershell
python -m unittest discover -s endpoint_agent/tests -v
```

预期结果是发现并运行 18 项测试。命令必须以退出码 0 结束，且没有 failure、error 或 skip，才能认为当前 Phase 0 验证通过。

运行单个测试模块：

```powershell
python -m unittest discover -s endpoint_agent/tests -p "test_package.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_domain.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_offline_constraints.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_repository_hygiene.py" -v
```

如果系统 PATH 中没有 `python`，请使用已安装的 Python 3.12 可执行文件替换命令中的 `python`。不要为了运行 Phase 0 测试引入 pytest。

## 5. 验证包导入

源码采用 `src` 布局。无需安装即可在 PowerShell 中执行导入检查：

```powershell
$env:PYTHONPATH = (Resolve-Path endpoint_agent\src).Path
python -c "import shielddome_endpoint; print(shielddome_endpoint.__version__)"
```

预期输出：

```text
0.1.0
```

根包公开导出：

- `MailObservation`
- `FeatureVector`
- `ModelAssessment`
- `DetectionOutcome`
- `MAIL_OBSERVATION_SCHEMA_VERSION`
- `FEATURE_SCHEMA_VERSION`
- `DETECTION_OUTCOME_SCHEMA_VERSION`
- `__version__`

## 6. 领域类型示例

领域类型使用 `frozen=True` 和 `slots=True`，集合字段使用 tuple。构造完成后不能修改字段。

```python
from datetime import datetime, timezone

from shielddome_endpoint import MailObservation


observation = MailObservation(
    source_kind="browser",
    source_message_id="local-message-001",
    subject="Account notice",
    sender="security@example.test",
    reply_to=None,
    recipient_summary=("current-user",),
    sanitized_body_text="Verify through the usual company channel.",
    authentication_observations=(("spf", "pass"),),
    normalized_links=("https://example.test/notice",),
    attachment_metadata=(("name", "notice.pdf"),),
    language_hint="en",
    observed_at=datetime.now(timezone.utc),
)
```

这些类型当前只提供数据契约，不执行字段验证、邮件解析、风险计算、持久化或网络通信。

## 7. 构建 wheel

使用本地源码和项目内置的零外部依赖 PEP 517 后端进行离线构建：

```powershell
python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist
```

该命令需要当前 Python 环境可执行 `python -m pip`，但不要求预装或在线下载 setuptools、wheel、flit 或 hatchling。`--no-index` 会阻止构建过程访问包索引；`pyproject.toml` 的 `[build-system].requires` 为空，构建由 `endpoint_agent/_build_backend.py` 完成。

成功时会生成类似文件：

```text
endpoint_agent/dist/shielddome_endpoint-0.1.0-py3-none-any.whl
```

`dist/`、`build/` 和 `*.egg-info/` 均已由 `endpoint_agent/.gitignore` 忽略。构建验证完成后可以删除这些可再生成产物。

## 8. 离线和数据边界

生产源码目录 `endpoint_agent/src/shielddome_endpoint/` 必须保持：

- 不导入网络客户端或 socket 能力；
- 不依赖 FastAPI、Flask、Uvicorn、aiohttp 等服务框架；
- 不包含 HTTP 或 WebSocket endpoint；
- 不监听 TCP/UDP 端口；
- 不调用中心后台、外部模型、遥测或更新服务。

下列内容必须保留在 Git 之外：

- 模型文件和模型包；
- 训练数据和训练输出；
- 本地密钥与证书私钥；
- 日志；
- SQLite 数据库及 WAL、SHM、journal 文件；
- 诊断包；
- Python 缓存、虚拟环境和构建产物。

Phase 0 不创建邮件、证据或用户数据库。原始邮件、正文和附件内容不得加入仓库。

## 9. 修改后的最低验证

每次修改 Endpoint Agent 后至少执行：

```powershell
python -m unittest discover -s endpoint_agent/tests -v
git status --short
git diff --name-status
git diff
```

检查以下事项：

1. 测试输出和退出码与修改范围一致；
2. 新增生产依赖和 import 没有突破离线边界；
3. 模型、数据、密钥、日志、数据库和构建产物未进入 Git 状态；
4. 业务代码修改只位于 `endpoint_agent/`；
5. 没有提前加入尚未进入当前开发阶段的实现。

## 10. 进一步阅读

- `endpoint_agent/README.md`：产品定义、目标架构和非目标；
- `endpoint_agent/DEVELOPMENT_PLAN.md`：已确认产品决策、阶段顺序和完成条件；
- `endpoint_agent/AGENTS.md`：参与开发的工程师和编码代理必须遵守的约束；
- 根目录 `CONTEXT.md`：Endpoint Agent 统一领域语言；
- 根目录 `AGENTS.md`：ShieldDome 仓库级协作和安全要求。

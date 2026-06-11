# 盾穹 ShieldDome Enterprise

ShieldDome 是面向 Linux 私有化部署的企业钓鱼邮件检测平台。它支持 `.eml` 上传和 RFC822 API 接入，结合确定性规则、邮件认证、附件静态分析、RAG 与外部 LLM API 生成可解释风险判定。

## 核心能力

- FastAPI 企业 API 与独立持久化 Analysis Worker。
- PostgreSQL + pgvector；开发环境可零依赖回退到 SQLite。mkdir git  && cd git
- `.eml` 解析、SPF/DKIM/DMARC 结果提取、链接伪装和附件静态特征。
- 可审核 RAG 知识库、Embedding API、LLM API 与故障降级。
- Vue 3 + Element Plus + ECharts 企业管理控制台。
- Linux systemd、Nginx、安装、升级、备份和恢复交付。

## 本地核心测试

```powershell
python.exe -m unittest discover -s tests -v
```

## Windows 本地网页测试

当前工作区已经包含 `.deps` 和构建后的 `web/` 时，直接执行：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start-windows.ps1
```

打开 `http://127.0.0.1:8000`，使用本地测试管理员账号登录：

```text
用户名：admin
密码：ShieldDome-Local-Admin-2026
```

然后进入“EML 检测”，上传 `samples/phishing-internal.eml`。停止服务：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\stop-windows.ps1
```

如需重新安装本地验证依赖：

```powershell
python.exe -m pip install --target .deps -r requirements.txt
```

安装 `requirements.txt` 后运行企业 API 与 Worker：

```bash
uvicorn app.api:app --host 127.0.0.1 --port 8000
python app/worker.py
```

Linux 生产部署和完整操作说明位于 [`docs/`](docs/)。

> 已经在聊天中暴露的硅基流动 API Key 必须撤销。新 Key 只能配置在 `/etc/shielddome/shielddome.env`。

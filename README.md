# ShieldDome Enterprise

ShieldDome 是面向 Linux 私有化部署的企业钓鱼邮件检测平台。系统支持 `.eml` 上传、浏览器邮件安全插件、规则快检、持久化 Worker 深度分析、RAG 知识库、OpenAI 兼容 Chat/Embedding 模型、用户权限、审计日志和策略管理。

## 核心能力

- FastAPI 企业 API 与独立 Analysis Worker。
- PostgreSQL + pgvector，开发环境可回退到 SQLite。
- 邮件头、正文、链接、附件、SPF/DKIM/DMARC 解析。
- 可信域名/IP、黑名单域名、高风险关键词和风险阈值策略。
- Vue 3 + Element Plus + ECharts 管理控制台。
- 浏览器插件支持个人 Token 绑定和检测结果入库。
- systemd、Nginx、安装、升级、备份、恢复和自检脚本。

## 本地测试

```powershell
python.exe -m unittest discover -s tests -v
```

Windows 本地网页测试：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start-windows.ps1
```

打开 `http://127.0.0.1:8000`，使用本地测试管理员登录：

```text
用户名：admin
密码：ShieldDome-Local-Admin-2026
```

停止服务：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\stop-windows.ps1
```

## Linux 运维

部署、升级、备份、恢复和故障排查说明位于 `docs/`。部署后可执行：

```bash
bash scripts/self-check-linux.sh http://127.0.0.1
```

备份：

```bash
bash scripts/backup.sh /var/backups/shielddome
```

恢复演练：

```bash
bash scripts/restore.sh /var/backups/shielddome/shielddome-YYYYmmdd-HHMMSS.dump /var/backups/shielddome/raw-YYYYmmdd-HHMMSS.tar.gz
```

## 安全提醒

不要把真实 API Key、数据库密码、插件 Token、生产数据库或原始邮件样本提交到 Git。已经暴露过的模型 API Key 必须撤销并重新签发，新 Key 只应配置在 `/etc/shielddome/shielddome.env` 或管理端加密配置中。

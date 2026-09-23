# 多邮箱适配 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** 完善网站版配套插件对 QQ、网易和 Gmail 邮件详情的采集与动态检测。

**Architecture:** 将邮件 DOM 读取隔离到 `extension/adapters.js`，内容脚本管理页面变化、请求和横幅。保持现有服务端协议和网站应用中心动态打包机制。

**Tech Stack:** Manifest V3、原生 JavaScript、Node test runner、jsdom。

## Global Constraints

- 不修改 endpoint_agent 或已有未提交文件。
- 仅采集识别出的邮件正文，不回退到整个邮箱页面。
- 页面 URL 不含查询和片段，消息标识仅本地摘要后提交。
- 保留 Outlook 和中通服邮箱的适配入口。
- 模拟 DOM 验证不能替代真实登录邮箱的兼容性验收。

### Task 1: 独立邮箱适配层

Files: 新增 `extension/adapters.js`，修改 `extension/manifest.json`；新增 `tests/browser/package.json` 和 `tests/browser/adapters.test.cjs`。

Interface: `globalThis.ShieldDomeMail.extract(document, location)` 返回邮件对象或 null；`documents(document)` 返回可读取的可见同源文档。

- [x] 实现 QQ、网易 163/126/yeah/企业邮箱、Gmail 和既有邮箱的正文定位、发件人/主题读取。
- [x] 同源 iframe 递归读取，跨域安全跳过；多邮件会话选择最后一封可见消息；缺少正文不提交。
- [x] 加入 jsdom 夹具，执行 `node --test tests/browser/*.test.cjs`，检查列表页、iframe、会话与敏感 URL。

### Task 2: 动态页面和结果隔离

Files: 修改 `extension/content.js`；新增 `tests/browser/content.test.cjs`。

Interface: 内容脚本消费上述 `extract`，保留现有 quick/status API。

- [x] 定期检查延迟加载和路由切换，内容稳定后提交；相同邮件不重复提交。
- [x] 页面变化立即作废旧请求和轮询结果；使用串行轮询避免重叠。
- [x] 测试切换、列表返回、旧请求迟到与重复检测。

### Task 3: 交付验证

Files: 修改 `extension/README.md`。

- [x] 更新支持范围、限制、安装和真实邮箱验收步骤。
- [x] 运行插件测试、JavaScript 语法检查和现有 Python 测试；核对差异及清单加载顺序。
- [x] 不提交 Git，不重建未修改的网站前端；由应用中心提供新版插件。

## 验证记录

- Node DOM/生命周期回归 18 项全部通过，两个插件脚本语法检查通过。
- 使用应用中心原始打包函数验证 1.8.0 包，含 adapters.js，未包含测试依赖。
- 使用项目 .deps 执行 Python 完整测试：68 项，67 通过；test_team_visibility_allows_same_security_team_only 失败（预期拒绝访问但未抛出 HTTPException）。本次未修改 Python 权限代码及测试。
- 真实账号下的 QQ、网易、Gmail 兼容性验收尚未进行，步骤见 extension/README.md。

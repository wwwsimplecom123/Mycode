# Phase 5B Chrome / Edge 真实浏览器验收

本文档只用于 ShieldDome Endpoint Agent Phase 5B 开发验收。必须分别在真实 Google Chrome 和 Microsoft Edge 中执行；单元测试、静态检查或源码 Host 子进程不能替代本流程。

## 1. 验收前提

- Windows 10/11 x64 当前用户会话；不使用管理员权限。
- 已安装 Python 3.12 和经批准离线提供的 `pyinstaller==6.15.0` 开发依赖。
- 已能登录 `https://webmail.chinaccs.cn/`，并准备一封可用于测试的邮件详情页。
- 扩展目录为仓库中的 `endpoint_agent/extension/`，不是根目录 `extension/`。
- 当前开发验收扩展 ID 固定为 `hchaloelgnennaojaiikeebhajcoccih`，origin 固定为 `chrome-extension://hchaloelgnennaojaiikeebhajcoccih/`。

该 ID 来自 `endpoint_agent/extension/manifest.json` 中提交的公开 `key`。仓库不包含私钥。未来 Chrome Web Store、Edge Add-ons 或企业正式签名身份必须单独确定，并同步正式发布 manifest；不得把当前开发 ID 描述为正式发布身份。

## 2. 构建并检查 Host

在仓库根目录运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File endpoint_agent\native_host\build-host.ps1
python -m unittest discover -s endpoint_agent/tests -p "test_native_host_process.py" -v
```

必须确认：

- `endpoint_agent/dist/native-host/ShieldDomeEndpointHost.exe` 存在；
- 同目录 `build-metadata.json` 的 SHA-256 与 `.exe` 一致；
- 打包 Host 测试没有 `packaged Host unavailable` 跳过；
- ping、`detect_mail`、异常帧、连续请求隔离、stdout 隐私和零 TCP/UDP socket 测试全部通过。

若 PyInstaller 不存在，不得联网临时下载或跳过 `.exe` 验证；停止真实浏览器验收并保持 Phase 5B `in_progress`。

## 3. 注册当前用户的 Chrome 与 Edge Host

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File endpoint_agent\native_host\install-host.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File endpoint_agent\native_host\check-host.ps1
```

检查命令必须返回 `"ready": true`，并列出 `Chrome` 和 `Edge`。默认只写入：

```text
HKCU\Software\Google\Chrome\NativeMessagingHosts\cn.shielddome.endpoint_agent
HKCU\Software\Microsoft\Edge\NativeMessagingHosts\cn.shielddome.endpoint_agent
```

两个注册值分别指向 `%LOCALAPPDATA%\ShieldDome\EndpointAgent\NativeMessagingHosts\Chrome` 和 `Edge` 下的 manifest。两个 manifest 必须满足：

- `name` 为 `cn.shielddome.endpoint_agent`；
- `type` 为 `stdio`；
- `path` 是已验证 Host `.exe` 的绝对路径；
- `allowed_origins` 只有 `chrome-extension://hchaloelgnennaojaiikeebhajcoccih/`；
- 没有通配符、HTTP(S) origin 或第二个扩展 origin。

重复运行安装和检查命令，结果必须保持一致。

## 4. Chrome 验收

1. 打开 `chrome://extensions`，启用“开发者模式”。
2. 选择“加载已解压的扩展程序”，选择绝对目录 `endpoint_agent/extension/`。
3. 记录 Chrome 显示的扩展 ID；必须精确等于 `hchaloelgnennaojaiikeebhajcoccih`。不一致时立即停止，不修改 allowlist 来迁就错误 ID。
4. 打开 chinaccs 邮件详情页和该页面的 DevTools Network 面板，清空现有记录。
5. 确认邮件正文上方出现 ShieldDome 状态条，并最终显示且只显示：风险等级、执行状态、通用建议、本地事件 ID。
6. 确认页面没有规则 ID、分数构成、模型概率、模型名、内部 evidence、邮件正文副本或服务器信息。
7. 在 Network 面板搜索 `shielddome`，确认没有 ShieldDome HTTP(S)、WebSocket、遥测、信誉或模型请求；Native Messaging 不会作为页面网络请求出现。
8. 断开网络或在 Windows 网络层禁用当前连接，保持浏览器与 Host 运行，重新打开一封已可访问的邮件详情并重复检测。结果必须仍能通过本地规则完成；若页面本身因断网无法提供邮件 DOM，应先使用邮箱已缓存/可离线查看的详情页，不能把页面未加载误记为 Host 失败。
9. 恢复网络，记录浏览器版本、扩展 ID、测试时间、风险/状态/建议/事件 ID 和 Network 面板结论，不记录邮件正文、完整地址或 Token。

## 5. Edge 验收

1. 完全关闭 Chrome 中的测试页，打开 `edge://extensions`，启用“开发人员模式”。
2. 选择“加载解压缩的扩展”，选择同一绝对目录 `endpoint_agent/extension/`。
3. 确认 Edge 显示的扩展 ID同样精确等于 `hchaloelgnennaojaiikeebhajcoccih`。
4. 按 Chrome 的第 4–9 步，在 Edge 中独立完成在线、本地离线和 Network 面板检查。
5. 单独记录 Edge 版本和可观察结果；Chrome 通过不能替代 Edge 通过。

## 6. 故障与隐私检查

- 临时退出 Host 或移除测试注册后，插件应显示“Agent 未启动”或“Host 不存在”，不得回退到 HTTP。
- 发送超限或非法请求时，页面只显示通用协议/超限状态；协议 stdout 只包含 framing 后的稳定错误码。
- 邮件正文、地址、Token、异常文本和 traceback 不得出现在 Host stdout、浏览器页面状态或验收记录中。
- 浏览器和 Host 进程不得创建 ShieldDome TCP/UDP 监听或外部连接。

## 7. 卸载与清理确认

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File endpoint_agent\native_host\uninstall-host.ps1

Test-Path -LiteralPath 'HKCU:\Software\Google\Chrome\NativeMessagingHosts\cn.shielddome.endpoint_agent'
Test-Path -LiteralPath 'HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\cn.shielddome.endpoint_agent'
```

两个 `Test-Path` 都必须返回 `False`，两个 ShieldDome manifest 文件应消失。卸载脚本若发现注册值或 manifest 不属于 ShieldDome，会拒绝删除并返回非零；此时必须人工核对，不能扩大删除范围。最后在 `chrome://extensions` 和 `edge://extensions` 移除开发扩展。

## 8. 完成记录

只有下列项目都有新鲜证据时，Phase 5B 才能标记为 `complete`：

- Host `.exe` 构建成功且打包 Host 全部协议/安全测试通过，无打包 Host 跳过；
- Chrome 与 Edge 当前用户注册、状态、重复安装和卸载验证通过；
- Chrome 与 Edge 各自在真实 chinaccs 邮件详情完成在线与断网检测；
- 两个浏览器的 Network 面板均无 ShieldDome 外部请求；
- 页面只显示四类最小结果；
- 卸载只清理 ShieldDome 自己的注册项和 manifest。

任何一项未执行或无法观察时，都应写为“未验收/阻塞”，Phase 5B 与 Phase 5 继续保持 `in_progress`。

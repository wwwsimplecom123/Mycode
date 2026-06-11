const input = document.querySelector("#api-base");
const message = document.querySelector("#message");

chrome.storage.local.get(["shielddomeApiBase"], ({ shielddomeApiBase }) => {
  input.value = shielddomeApiBase || "";
  if (!shielddomeApiBase) {
    message.textContent = "首次使用前，请填写服务器地址。";
  }
});

document.querySelector("#save").addEventListener("click", async () => {
  const apiBase = input.value.trim().replace(/\/+$/, "");
  try {
    const parsed = new URL(apiBase);
    if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("地址必须使用 HTTP 或 HTTPS");
    const granted = await chrome.permissions.request({ origins: [`${parsed.origin}/*`] });
    if (!granted) throw new Error("未授予站点访问权限");
    message.textContent = "正在测试连接...";
    const response = await chrome.runtime.sendMessage({
      type: "shielddome-api-request",
      apiBase: parsed.origin,
      path: "/api/email/auth/me",
      method: "GET",
    });
    if (!response || !response.ok) {
      throw new Error(response && response.error ? response.error : "插件后台未响应");
    }
    await chrome.storage.local.set({
      shielddomeApiBase: parsed.origin,
      shielddomeApiConfiguredByUser: true,
    });
    const loopback = ["127.0.0.1", "localhost", "::1"].includes(parsed.hostname);
    message.textContent = loopback
      ? `连接成功，身份：${response.data.display_name}（${response.data.username}）。注意：该地址仅适用于 ShieldDome 与浏览器运行在同一台设备。`
      : `远程连接成功，身份：${response.data.display_name}（${response.data.username}）。刷新邮件详情页后生效。`;
  } catch (error) {
    message.textContent = `保存失败：${error.message}`;
  }
});

function normalizeApiBase(value) {
  if (!String(value || "").trim()) {
    throw new Error("尚未配置 ShieldDome 服务地址");
  }
  const parsed = new URL(String(value).trim());
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("ShieldDome 服务地址必须使用 HTTP 或 HTTPS");
  }
  return parsed.origin;
}

function statusHint(status, detail) {
  if (status === 401 || status === 403) return `插件 Token 无效或无权访问（${status}）：${detail || "请重新签发 Token"}`;
  if (status === 413) return `提交内容过大（${status}）：${detail || "请缩短邮件正文后重试"}`;
  if (status === 429) return `请求过于频繁（${status}）：${detail || "请稍后再试"}`;
  if (status >= 500) return `ShieldDome 服务端异常（${status}）：${detail || "请查看服务器日志"}`;
  return `ShieldDome 接口返回 ${status}${detail ? `：${detail}` : ""}`;
}

async function apiRequest(message) {
  const apiBase = normalizeApiBase(message.apiBase);
  const target = new URL(String(message.path || "/"), `${apiBase}/`);
  if (target.origin !== apiBase) {
    throw new Error("拒绝访问 ShieldDome 服务地址之外的接口");
  }

  const method = String(message.method || "GET").toUpperCase();
  const options = {
    method,
    cache: "no-store",
    credentials: "omit",
    headers: {},
  };
  const pluginToken = String(message.pluginToken || "").trim();
  if (pluginToken) options.headers["X-ShieldDome-Plugin-Token"] = pluginToken;
  if (message.payload !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(message.payload);
  }

  const response = await fetch(target.href, options);
  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch (_error) {
      data = text;
    }
  }
  if (!response.ok) {
    const detail = data && typeof data === "object" ? data.detail : data;
    throw new Error(statusHint(response.status, detail));
  }
  return data;
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message) return false;
  if (message.type === "shielddome-open-options") {
    chrome.runtime.openOptionsPage();
    sendResponse({ ok: true });
    return false;
  }
  if (message.type !== "shielddome-api-request") return false;

  apiRequest(message)
    .then((data) => sendResponse({ ok: true, data }))
    .catch((error) => {
      const apiBase = String(message.apiBase || "未配置地址");
      const hint = error instanceof TypeError
        ? `无法连接 ${apiBase}，请确认 ShieldDome 服务已启动且插件已获得访问权限`
        : error.message;
      sendResponse({ ok: false, error: hint });
    });
  return true;
});

chrome.action.onClicked.addListener(() => {
  chrome.runtime.openOptionsPage();
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(["shielddomeApiBase", "shielddomeApiConfiguredByUser", "shielddomePluginToken"], (settings) => {
    const apiBase = String(settings.shielddomeApiBase || "").trim();
    const legacyLoopbackDefault = !settings.shielddomeApiConfiguredByUser && /^http:\/\/(?:127\.0\.0\.1|localhost):8000$/i.test(apiBase);
    if (legacyLoopbackDefault) chrome.storage.local.remove(["shielddomeApiBase"]);
    if (!apiBase || !settings.shielddomePluginToken || legacyLoopbackDefault) chrome.runtime.openOptionsPage();
  });
});

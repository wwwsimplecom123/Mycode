(function () {
  const POLL_INTERVAL_MS = 2000;
  const MAX_POLL_ATTEMPTS = 45;
  const MAX_POLL_ERRORS = 3;
  let generation = 0;
  let pollTimer = null;

  function injectBanner() {
    let banner = document.querySelector("#shielddome-risk-banner");
    if (banner) return banner;
    banner = document.createElement("div");
    banner.id = "shielddome-risk-banner";
    banner.style.cssText = [
      "position:fixed",
      "top:0",
      "left:0",
      "right:0",
      "z-index:2147483647",
      "font:14px/1.4 Arial,'Microsoft YaHei',sans-serif",
      "padding:12px 16px",
      "background:#eef2f6",
      "color:#3f4854",
      "border-bottom:1px solid #cfd8e3",
      "box-shadow:0 2px 8px rgba(0,0,0,.08)",
    ].join(";");
    document.documentElement.appendChild(banner);
    return banner;
  }

  function setBanner(level, title, message, code = "") {
    const colors = {
      scanning: ["#eef2f6", "#3f4854"],
      low: ["#eaf7f0", "#217a55"],
      medium: ["#fff7df", "#8a5a00"],
      high: ["#fff0ed", "#b42318"],
      critical: ["#fff0ed", "#b42318"],
    };
    const [bg, color] = colors[level] || colors.scanning;
    const banner = injectBanner();
    banner.style.background = bg;
    banner.style.color = color;
    banner.replaceChildren();
    const strong = document.createElement("strong");
    const span = document.createElement("span");
    strong.textContent = `${title} `;
    span.textContent = `${message || ""}${code ? `（${code}）` : ""}`;
    banner.append(strong, span);
  }

  function setConfigurationBanner() {
    setBanner("medium", "ShieldDome 尚未配置", "请先填写服务器地址和用户插件 Token");
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "打开插件设置";
    button.style.cssText = "margin-left:12px;padding:4px 10px;border:1px solid #c99219;border-radius:4px;background:#fff;color:#8a5a00;cursor:pointer";
    button.addEventListener("click", () => chrome.runtime.sendMessage({ type: "shielddome-open-options" }));
    injectBanner().appendChild(button);
  }

  async function apiRequest(apiBase, pluginToken, path, method = "GET", payload) {
    const response = await chrome.runtime.sendMessage({ type: "shielddome-api-request", apiBase, pluginToken, path, method, payload });
    if (!response || !response.ok) {
      throw new Error(response && response.error ? response.error : "ShieldDome 插件后台未响应");
    }
    return response.data;
  }

  function fingerprint(payload) {
    return payload ? JSON.stringify([payload, location.pathname, location.search, location.hash]) : "";
  }

  async function analyze(apiBase, pluginToken, payload, version) {
    const current = () => version === generation && fingerprint(ShieldDomeMail.extract(document, location)) === candidate;
    try {
      if (!current()) return;
      setBanner("scanning", "ShieldDome 正在检测", "已识别当前邮件，正在进行快速规则初筛");
      const quick = await apiRequest(apiBase, pluginToken, "/api/email/analyze/quick", "POST", payload);
      if (!current()) return;
      setBanner(quick.risk_level, `快速检测：${quick.risk_level}`, quick.reason);
      if (!quick.deep_scan_required) return;
      let attempts = 0;
      let errors = 0;
      async function poll() {
        if (!current()) return;
        attempts += 1;
        try {
          const status = await apiRequest(apiBase, pluginToken, `/api/email/analyze/status/${quick.analysis_id}`);
          if (!current()) return;
          errors = 0;
          if (status.deep_status === "completed") {
            const result = status.deep_result || status.quick_result || quick;
            setBanner(result.risk_level || quick.risk_level, `深度检测：${result.risk_level || quick.risk_level}`, result.reason || quick.reason);
            return;
          }
          if (status.deep_status === "failed") {
            setBanner("medium", "ShieldDome 深度检测失败", status.error || "请在控制台查看任务错误", "DEEP_FAILED");
            return;
          }
        } catch (error) {
          if (!current()) return;
          errors += 1;
          if (errors >= MAX_POLL_ERRORS) {
            setBanner("medium", "ShieldDome 状态查询失败", error.message, "POLL_ERROR");
            return;
          }
        }
        if (attempts >= MAX_POLL_ATTEMPTS) {
          setBanner("medium", "ShieldDome 深度检测超时", "请在控制台查看队列状态", "POLL_TIMEOUT");
          return;
        }
        pollTimer = setTimeout(poll, POLL_INTERVAL_MS);
      }
      pollTimer = setTimeout(poll, POLL_INTERVAL_MS);
    } catch (error) {
      if (current()) setBanner("medium", "ShieldDome 检测异常", error.message, "QUICK_ERROR");
    }
  }

  let candidate = "";
  let submitted = false;
  let checking = false;
  async function checkPage() {
    if (checking) return;
    checking = true;
    try {
      const payload = ShieldDomeMail.extract(document, location);
      const signature = fingerprint(payload);
      if (signature !== candidate) {
        generation += 1;
        clearTimeout(pollTimer);
        document.querySelector("#shielddome-risk-banner")?.remove();
        candidate = signature;
        submitted = false;
        return; // Wait for a second stable sample after asynchronous rendering.
      }
      if (!payload || submitted) return;
      submitted = true;
      const version = generation;
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(signature));
      if (version !== generation || fingerprint(ShieldDomeMail.extract(document, location)) !== candidate) { if (version === generation) submitted = false; return; }
      payload.message_id = 'browser-' + Array.from(new Uint8Array(digest), value => value.toString(16).padStart(2, '0')).join('');
      chrome.storage.local.get(["shielddomeApiBase", "shielddomePluginToken"], settings => {
        if (version !== generation || fingerprint(ShieldDomeMail.extract(document, location)) !== candidate) { if (version === generation) submitted = false; return; }
        const apiBase = String(settings.shielddomeApiBase || "").trim().replace(/\/+$/, "");
        const pluginToken = String(settings.shielddomePluginToken || "").trim();
        if (!apiBase || !pluginToken) { setConfigurationBanner(); return; }
        analyze(apiBase, pluginToken, payload, version);
      });
    } finally { checking = false; }
  }
  chrome.storage.onChanged.addListener((_changes, area) => {
    if (area === "local") {
      generation += 1;
      clearTimeout(pollTimer);
      submitted = false;
    }
  });
  // Also catches same-origin iframe loads and SPA DOM changes without observing our banner.
  setInterval(checkPage, 1000);
  checkPage();
})();

(function () {
  const POLL_INTERVAL_MS = 2000;
  const MAX_POLL_ATTEMPTS = 45;
  const MAX_POLL_ERRORS = 3;
  const MIN_BODY_LENGTH = 20;

  const COMMON_SUBJECT_SELECTORS = [
    "[data-testid='message-subject']",
    "[aria-label*='subject' i]",
    "[aria-label*='主题']",
    "#subject",
    ".subject",
    "[id*='subject' i]",
    "[class*='subject' i]",
  ];
  const COMMON_SENDER_SELECTORS = [
    "[email]",
    "[data-email]",
    "[data-testid='message-from']",
    ".sender",
    ".from",
    "[aria-label*='from' i]",
    "[aria-label*='发件人']",
  ];
  const COMMON_BODY_SELECTORS = [
    "[data-testid='message-body']",
    "[role='main'] [role='document']",
    "#messageBody",
    "#mailContent",
    ".message-body",
    ".mail-content",
    ".mailBody",
    "[id*='mailContent' i]",
    "[class*='messageBody' i]",
  ];

  const ADAPTERS = [
    {
      name: "gmail",
      hosts: ["mail.google.com"],
      detail: () => Boolean(document.querySelector(".adn, .a3s")),
      subject: [".hP", "[data-legacy-message-id] .hP"],
      sender: [".gD[email]", ".go"],
      body: [".a3s.aiL", ".adn .a3s"],
    },
    {
      name: "outlook",
      hosts: ["outlook.live.com", "outlook.office.com", "outlook.office365.com"],
      detail: () => Boolean(document.querySelector("[role='document'], [aria-label*='Message body' i]")),
      subject: ["[role='heading']", "[aria-label*='Subject' i]"],
      sender: ["[aria-label*='From' i]", "[data-testid='SenderPersona']"],
      body: ["[aria-label*='Message body' i]", "[role='document']"],
    },
    {
      name: "qq-mail",
      hosts: ["mail.qq.com", "exmail.qq.com"],
      detail: (text) => /发件人|收件人|主题|From|To|Subject/.test(text),
      subject: ["#subject", ".subject", "[class*='subject' i]"],
      sender: ["[email]", "[data-email]", ".sender", ".from"],
      body: ["#mailContent", ".mailContent", ".mail-body", "iframe"],
    },
    {
      name: "netease-mail",
      hosts: ["mail.163.com", "mail.126.com", "qiye.163.com"],
      detail: (text) => /发件人|收件人|主题|From|To|Subject/.test(text),
      subject: [".subject", "[class*='subject' i]"],
      sender: ["[email]", "[data-email]", ".sender", ".from"],
      body: [".mail-content", ".mailBody", "[class*='mailContent' i]", "iframe"],
    },
    {
      name: "chinaccs-webmail",
      hosts: ["webmail.chinaccs.cn"],
      detail: (text) => /readMail\.do|messageid=/i.test(location.href) || /发件人|收件人|主题|From|To|Subject/.test(text),
      subject: ["#subject", ".subject", "[name='subject']", "b", "strong"],
      sender: ["[email]", "[data-email]", ".sender", ".from"],
      body: ["#mailContent", "#content", ".mail-content", ".mailBody", "td", "iframe"],
    },
  ];

  let pollTimer = null;

  function documents() {
    const items = [document];
    for (const frame of document.querySelectorAll("iframe")) {
      try {
        if (frame.contentDocument && frame.contentDocument.body) items.push(frame.contentDocument);
      } catch (_error) {
        // Cross-origin frames cannot be inspected by a content script.
      }
    }
    return items;
  }

  function visibleText(node) {
    return String((node && (node.innerText || node.textContent)) || "").trim();
  }

  function queryFirst(selectors) {
    for (const doc of documents()) {
      for (const selector of selectors) {
        const node = doc.querySelector(selector);
        if (node && (selector === "iframe" || visibleText(node))) return node;
      }
    }
    return null;
  }

  function queryAll(selectors) {
    const nodes = [];
    for (const doc of documents()) {
      for (const selector of selectors) {
        nodes.push(...Array.from(doc.querySelectorAll(selector)));
      }
    }
    return nodes;
  }

  function pageText() {
    return documents().map((doc) => visibleText(doc.body)).filter(Boolean).join("\n").slice(0, 12000);
  }

  function fieldFromText(text, labels) {
    for (const label of labels) {
      const match = text.match(new RegExp(`(?:^|\\n)\\s*${label}\\s*[:：]\\s*([^\\n]+)`, "i"));
      if (match) return match[1].trim();
    }
    return "";
  }

  function activeAdapter(text) {
    const host = location.hostname.toLowerCase();
    return ADAPTERS.find((adapter) => adapter.hosts.some((item) => host === item || host.endsWith(`.${item}`)) && adapter.detail(text)) || null;
  }

  function messageRoots(adapter, text) {
    const selectors = [...(adapter ? adapter.body : []), ...COMMON_BODY_SELECTORS];
    let roots = queryAll(selectors).filter((node) => visibleText(node).length >= MIN_BODY_LENGTH);
    if (adapter?.name === "chinaccs-webmail") {
      roots = roots
        .filter((node) => {
          const value = visibleText(node);
          return /发件人|收件人|主题|From|To|Subject|附件|时间/.test(value) || value.length >= 80;
        })
        .sort((left, right) => visibleText(right).length - visibleText(left).length)
        .slice(0, 3);
    }
    if (roots.length) return Array.from(new Set(roots));
    return text.length >= MIN_BODY_LENGTH ? documents().map((doc) => doc.body).filter(Boolean) : [];
  }

  function extractSubject(adapter, text) {
    const node = queryFirst([...(adapter ? adapter.subject : []), ...COMMON_SUBJECT_SELECTORS]);
    const selected = visibleText(node).replace(/^主题\s*[:：]\s*/i, "");
    return (selected || fieldFromText(text, ["主题", "Subject"]) || document.title || "浏览器邮件").slice(0, 300);
  }

  function extractSender(adapter, text) {
    const node = queryFirst([...(adapter ? adapter.sender : []), ...COMMON_SENDER_SELECTORS]);
    const selected = node ? node.getAttribute("email") || node.getAttribute("data-email") || visibleText(node) : "";
    return String(selected || fieldFromText(text, ["发件人", "From"])).trim().slice(0, 500);
  }

  function contextAround(anchor) {
    const text = visibleText(anchor.parentElement);
    const label = visibleText(anchor);
    const index = text.indexOf(label);
    return {
      before: index >= 0 ? text.slice(Math.max(0, index - 50), index) : text.slice(0, 50),
      after: index >= 0 ? text.slice(index + label.length, index + label.length + 50) : text.slice(-50),
    };
  }

  function stableMessageId() {
    const url = new URL(location.href);
    const source = url.searchParams.get("messageid") || url.searchParams.get("messageId") || url.searchParams.get("id") || url.hash;
    const value = `${url.origin}${url.pathname}|${source}`;
    let hash = 2166136261;
    for (let index = 0; index < value.length; index += 1) {
      hash ^= value.charCodeAt(index);
      hash = Math.imul(hash, 16777619);
    }
    return `browser-${location.host}-${(hash >>> 0).toString(16).padStart(8, "0")}`;
  }

  function extractPayload(adapter, text) {
    const roots = messageRoots(adapter, text);
    const anchors = roots.flatMap((root) => Array.from(root.querySelectorAll("a[href]")));
    const bodyParts = [];
    for (const root of roots) {
      const value = visibleText(root);
      if (value && !bodyParts.includes(value)) bodyParts.push(value);
    }
    const bodyText = (bodyParts.join("\n") || text).slice(0, 12000);
    const links = Array.from(new Set(anchors)).slice(0, 50).map((anchor) => {
      const context = contextAround(anchor);
      return {
        display_text: visibleText(anchor),
        href: anchor.href,
        context_before: context.before,
        context_after: context.after,
        html_snippet: anchor.outerHTML.slice(0, 300),
      };
    });
    return {
      message_id: stableMessageId(),
      subject: extractSubject(adapter, text),
      sender: extractSender(adapter, text),
      recipient: fieldFromText(text, ["收件人", "To"]).slice(0, 1000),
      body_summary: bodyText.slice(0, 1000),
      body_text: bodyText,
      links,
      mail_client: `browser-extension:${adapter ? adapter.name : location.host}`,
      page_url: `${location.origin}${location.pathname}`,
    };
  }

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

  async function analyze(apiBase, pluginToken, payload) {
    try {
      setBanner("scanning", "ShieldDome 正在检测", "已识别当前邮件，正在进行快速规则初筛");
      const quick = await apiRequest(apiBase, pluginToken, "/api/email/analyze/quick", "POST", payload);
      setBanner(quick.risk_level, `快速检测：${quick.risk_level}`, quick.reason);
      if (!quick.deep_scan_required) return;

      let attempts = 0;
      let errors = 0;
      pollTimer = setInterval(async () => {
        attempts += 1;
        try {
          const status = await apiRequest(apiBase, pluginToken, `/api/email/analyze/status/${quick.analysis_id}`);
          errors = 0;
          if (status.deep_status === "completed") {
            clearInterval(pollTimer);
            const result = status.deep_result || status.quick_result || quick;
            setBanner(result.risk_level || quick.risk_level, `深度检测：${result.risk_level || quick.risk_level}`, result.reason || quick.reason);
          } else if (status.deep_status === "failed") {
            clearInterval(pollTimer);
            setBanner("medium", "ShieldDome 深度检测失败", status.error || "请在控制台查看任务错误", "DEEP_FAILED");
          } else if (attempts >= MAX_POLL_ATTEMPTS) {
            clearInterval(pollTimer);
            setBanner("medium", "ShieldDome 深度检测超时", "深度任务仍未完成，请在控制台查看队列状态", "POLL_TIMEOUT");
          }
        } catch (error) {
          errors += 1;
          if (errors >= MAX_POLL_ERRORS) {
            clearInterval(pollTimer);
            setBanner("medium", "ShieldDome 状态查询失败", error.message, "POLL_ERROR");
          }
        }
      }, POLL_INTERVAL_MS);
    } catch (error) {
      setBanner("medium", "ShieldDome 检测异常", error.message, "QUICK_ERROR");
    }
  }

  const text = pageText();
  const adapter = activeAdapter(text);
  if (!adapter) return;
  const payload = extractPayload(adapter, text);
  if (!payload.body_text || payload.body_text.length < MIN_BODY_LENGTH) {
    setBanner("medium", "ShieldDome 未识别邮件正文", "当前页面可能不是邮件详情页，或该邮箱需要新增 DOM 适配器", "NO_BODY");
    return;
  }

  chrome.storage.local.get(["shielddomeApiBase", "shielddomePluginToken"], ({ shielddomeApiBase, shielddomePluginToken }) => {
    const apiBase = String(shielddomeApiBase || "").trim().replace(/\/+$/, "");
    const pluginToken = String(shielddomePluginToken || "").trim();
    if (!apiBase || !pluginToken) {
      setConfigurationBanner();
      return;
    }
    analyze(apiBase, pluginToken, payload);
  });
})();

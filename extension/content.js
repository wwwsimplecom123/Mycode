(function () {
  const DETAIL_URL_PATTERN = /readmail|readmessage|viewmail|showmail|messageid=|\/message\/|[?&#]id=[^&]+/i;
  const MAIL_PAGE_PATTERN = /mail|outlook|owa|gmail|foxmail|邮箱|邮件/i;
  const GENERIC_TITLES = /^(邮件内容|邮件详情|webmail|mail|outlook|个人)(\s*[-|·].*)?$/i;
  const SUBJECT_SELECTORS = [
    "[data-testid='message-subject']",
    "[aria-label*='subject' i]",
    "[aria-label*='主题']",
    "#subject",
    ".subject",
    "[id*='subject' i]",
    "[class*='subject' i]",
  ];
  const SENDER_SELECTORS = [
    "[email]",
    "[data-email]",
    "[data-testid='message-from']",
    ".sender",
    ".from",
    "[aria-label*='from' i]",
    "[aria-label*='发件人']",
  ];
  const MESSAGE_ROOT_SELECTORS = [
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

  let analysisId = null;
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
    return String(node && (node.innerText || node.textContent) || "").trim();
  }

  function queryFirst(selectors) {
    for (const doc of documents()) {
      for (const selector of selectors) {
        const node = doc.querySelector(selector);
        if (node && visibleText(node)) return node;
      }
    }
    return null;
  }

  function pageText() {
    return documents()
      .map((doc) => visibleText(doc.body))
      .filter(Boolean)
      .join("\n")
      .slice(0, 12000);
  }

  function fieldFromText(text, labels) {
    for (const label of labels) {
      const match = text.match(new RegExp(`(?:^|\\n)\\s*${label}\\s*[:：]\\s*([^\\n]+)`, "i"));
      if (match) return match[1].trim();
    }
    return "";
  }

  function subjectFromPage(text) {
    const subjectNode = queryFirst(SUBJECT_SELECTORS);
    const selected = visibleText(subjectNode).replace(/^主题\s*[:：]\s*/i, "");
    if (selected && selected.length <= 300) return selected;

    const labeled = fieldFromText(text, ["主题", "Subject"]);
    if (labeled) return labeled.slice(0, 300);

    const title = String(document.title || "").trim();
    if (title && !GENERIC_TITLES.test(title)) return title.slice(0, 300);

    return text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .find((line) => (
        line.length >= 4 &&
        line.length <= 300 &&
        !/^(发件人|收件人|抄送|时间|附件|From|To|Cc|Date)\s*[:：]/i.test(line) &&
        !/^(删除|转发|回复|收信|写信|通讯录|收件箱)/.test(line)
      )) || "浏览器邮件";
  }

  function senderFromPage(text) {
    const senderNode = queryFirst(SENDER_SELECTORS);
    const selected = senderNode
      ? senderNode.getAttribute("email") || senderNode.getAttribute("data-email") || visibleText(senderNode)
      : "";
    return String(selected || fieldFromText(text, ["发件人", "From"])).trim().slice(0, 500);
  }

  function isMessageDetail(text) {
    if (!MAIL_PAGE_PATTERN.test(`${location.href} ${document.title}`)) return false;
    if (DETAIL_URL_PATTERN.test(location.href)) return true;
    const hasSender = /(?:^|\n)\s*(?:发件人|From)\s*[:：]/i.test(text);
    const hasRecipient = /(?:^|\n)\s*(?:收件人|To)\s*[:：]/i.test(text);
    const hasSubject = /(?:^|\n)\s*(?:主题|Subject)\s*[:：]/i.test(text) || Boolean(queryFirst(SUBJECT_SELECTORS));
    return hasSender && (hasRecipient || hasSubject);
  }

  function messageRoots() {
    const roots = [];
    for (const doc of documents()) {
      for (const selector of MESSAGE_ROOT_SELECTORS) {
        const node = doc.querySelector(selector);
        if (node && visibleText(node).length >= 20) roots.push(node);
      }
    }
    return roots.length ? roots : documents().map((doc) => doc.body).filter(Boolean);
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

  function setBanner(level, title, message) {
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
    span.textContent = String(message || "");
    banner.append(strong, span);
  }

  function setConfigurationBanner() {
    setBanner("medium", "盾穹尚未配置", "请先设置可访问的 ShieldDome 服务器地址。");
    const banner = injectBanner();
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "打开插件设置";
    button.style.cssText = [
      "margin-left:12px",
      "padding:4px 10px",
      "border:1px solid #c99219",
      "border-radius:4px",
      "background:#fff",
      "color:#8a5a00",
      "cursor:pointer",
    ].join(";");
    button.addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "shielddome-open-options" });
    });
    banner.appendChild(button);
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
    const source = url.searchParams.get("messageid") || url.searchParams.get("messageId") || url.searchParams.get("id");
    const value = `${url.origin}${url.pathname}|${source || url.hash}`;
    let hash = 2166136261;
    for (let index = 0; index < value.length; index += 1) {
      hash ^= value.charCodeAt(index);
      hash = Math.imul(hash, 16777619);
    }
    return `browser-${location.host}-${(hash >>> 0).toString(16).padStart(8, "0")}`;
  }

  function extractPayload(text) {
    const anchors = messageRoots().flatMap((root) => Array.from(root.querySelectorAll("a[href]")));
    const links = Array.from(new Set(anchors))
      .slice(0, 50)
      .map((anchor) => {
        const context = contextAround(anchor);
        return {
          display_text: visibleText(anchor),
          href: anchor.href,
          context_before: context.before,
          context_after: context.after,
          html_snippet: anchor.outerHTML.slice(0, 300),
        };
      });

    const bodyText = messageRoots()
      .map((root) => visibleText(root))
      .filter(Boolean)
      .join("\n")
      .slice(0, 12000) || text.slice(0, 12000);

    return {
      message_id: stableMessageId(),
      subject: subjectFromPage(text),
      sender: senderFromPage(text),
      recipient: fieldFromText(text, ["收件人", "To"]).slice(0, 1000),
      body_summary: bodyText.slice(0, 1000),
      body_text: bodyText,
      links,
      mail_client: `browser-extension:${location.host}`,
      page_url: `${location.origin}${location.pathname}`,
    };
  }

  async function apiRequest(apiBase, path, method = "GET", payload) {
    const response = await chrome.runtime.sendMessage({
      type: "shielddome-api-request",
      apiBase,
      path,
      method,
      payload,
    });
    if (!response || !response.ok) {
      throw new Error(response && response.error ? response.error : "ShieldDome 插件后台未响应");
    }
    return response.data;
  }

  async function analyze(apiBase, text) {
    try {
      setBanner("scanning", "盾穹正在检测", "已读取当前邮件，正在进行快速规则初筛");
      const quick = await apiRequest(apiBase, "/api/email/analyze/quick", "POST", extractPayload(text));
      analysisId = quick.analysis_id;
      setBanner(quick.risk_level, `快速检测：${quick.risk_level}`, quick.reason);
      if (quick.deep_scan_required) {
        let attempts = 0;
        pollTimer = setInterval(async () => {
          try {
            attempts += 1;
            const status = await apiRequest(apiBase, `/api/email/analyze/status/${analysisId}`);
            if (status.deep_status === "completed") {
              clearInterval(pollTimer);
              const result = status.deep_result;
              setBanner(result.risk_level, `深度检测：${result.risk_level}`, result.reason);
            } else if (attempts >= 60) {
              clearInterval(pollTimer);
              setBanner("medium", "盾穹检测超时", "深度检测超过 60 秒，请在控制台查看任务状态");
            }
          } catch (error) {
            clearInterval(pollTimer);
            setBanner("medium", "盾穹检测异常", error.message);
          }
        }, 1000);
      }
    } catch (error) {
      setBanner("medium", "盾穹检测异常", error.message);
    }
  }

  const text = pageText();
  if (!isMessageDetail(text)) return;
  chrome.storage.local.get(["shielddomeApiBase"], ({ shielddomeApiBase }) => {
    const apiBase = String(shielddomeApiBase || "").trim().replace(/\/+$/, "");
    if (!apiBase) {
      setConfigurationBanner();
      return;
    }
    analyze(apiBase, text);
  });
})();

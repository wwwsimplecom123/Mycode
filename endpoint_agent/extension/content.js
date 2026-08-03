(function () {
  const STATUS_ID = "shielddome-endpoint-status";
  const adapter = globalThis.ShieldDomeChinaccsAdapter;
  let activeIdentity = "";
  let closedIdentity = "";
  let scheduled = 0;

  const riskLabels = { low: "低", medium: "中", high: "高", critical: "严重" };
  const actionLabels = {
    continue: "可继续阅读，仍请留意异常请求",
    verify_sender: "请通过可信渠道核实发件人",
    avoid_credentials: "不要在邮件链接中输入账号密码",
    contact_security: "请联系安全人员复核",
  };

  function mountBar(bar, preferredMount) {
    const mount = preferredMount || adapter.findStatusMount() || document.body;
    if (mount && mount.parentElement) mount.parentElement.insertBefore(bar, mount);
    else if (mount) mount.prepend(bar);
  }

  function render(state, details = {}, preferredMount = null) {
    const previous = document.getElementById(STATUS_ID);
    if (previous) previous.remove();
    const bar = document.createElement("section");
    bar.id = STATUS_ID;
    bar.dataset.state = state;
    bar.setAttribute("role", state === "detecting" ? "status" : "alert");
    bar.setAttribute("aria-live", "polite");

    const icon = document.createElement("span");
    icon.className = "shielddome-status-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = state === "detecting" ? "◌" : "◆";
    const copy = document.createElement("div");
    copy.className = "shielddome-status-copy";

    const stateCopy = {
      detecting: ["检测中", "正在进行本地邮件检测"],
      body_not_recognized: ["当前页面未识别正文", "未提交任何邮件内容"],
      agent_not_running: ["Agent 未启动", "请启动 ShieldDome Endpoint Agent 后重试"],
      host_missing: ["Host 不存在", "本机尚未注册 Native Host"],
      protocol_error: ["协议错误", "本地通信未能完成"],
      request_too_large: ["请求超限", "当前邮件超出本地检测资源上限"],
    };
    const [title, message] = stateCopy[state] || ["ShieldDome", "本地检测状态未知"];
    const strong = document.createElement("strong");
    strong.textContent = details.risk_level
      ? `风险等级：${riskLabels[details.risk_level] || "未知"}`
      : title;
    const summary = document.createElement("span");
    if (details.risk_level) {
      const mode = details.execution_state === "model_unavailable"
        ? "纯规则模式 · 模型未安装"
        : details.execution_state === "rules_only"
          ? "纯规则模式"
          : details.execution_state === "model_uncertain"
            ? "不确定"
            : "本地检测完成";
      summary.textContent = `${mode} · 通用建议：${actionLabels[details.generic_action] || "请谨慎处理"}`;
    } else {
      summary.textContent = message;
    }
    copy.append(strong, summary);
    if (details.local_event_id) {
      const event = document.createElement("code");
      event.textContent = `local event ID: ${details.local_event_id}`;
      copy.appendChild(event);
    }
    const close = document.createElement("button");
    close.type = "button";
    close.className = "shielddome-status-close";
    close.setAttribute("aria-label", "关闭 ShieldDome 状态");
    close.textContent = "×";
    close.addEventListener("click", () => {
      closedIdentity = activeIdentity;
      bar.remove();
    });
    bar.append(icon, copy, close);
    mountBar(bar, preferredMount);
  }

  async function detectCurrentMail() {
    const extracted = await adapter.extractCurrentMail();
    if (!extracted.ok) {
      const pageIdentity = `${location.origin}${location.pathname}`;
      if (activeIdentity === pageIdentity && document.getElementById(STATUS_ID)) return;
      activeIdentity = pageIdentity;
      if (closedIdentity !== activeIdentity) render("body_not_recognized");
      return;
    }
    if (extracted.mail.source_message_id === activeIdentity) return;
    activeIdentity = extracted.mail.source_message_id;
    closedIdentity = "";
    render("detecting", {}, extracted.mount);
    const response = await chrome.runtime.sendMessage({
      type: "shielddome-detect-mail",
      request: {
        protocol_version: "1.0",
        message_type: "detect_mail",
        mail: extracted.mail,
      },
    });
    if (!response || !response.ok) {
      render((response && response.error_code) || "protocol_error", {}, extracted.mount);
      return;
    }
    render(response.data.risk_level, response.data, extracted.mount);
  }

  function scheduleDetection() {
    clearTimeout(scheduled);
    scheduled = setTimeout(() => {
      detectCurrentMail().catch(() => render("protocol_error"));
    }, 500);
  }

  new MutationObserver(scheduleDetection).observe(document.documentElement, {
    childList: true,
    subtree: true,
  });
  scheduleDetection();
})();

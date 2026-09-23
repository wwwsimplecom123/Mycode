(function () {
  const adapters = [
    { name: 'gmail', hosts: ['mail.google.com'], containers: ['.adn'],
      body: ['.a3s.aiL', '.a3s'], subject: ['.hP'], sender: ['.gD[email]'], recipient: ['.g2[email]'] },
    { name: 'qq-mail', hosts: ['mail.qq.com', 'wx.mail.qq.com', 'exmail.qq.com'],
      body: ['#mailContentContainer', '#mailContent', '.mailContent', '.mail-body', '.mail-detail-content'],
      subject: ['#subject', '.mail-detail-subject .mail-subject-text', '.mail-detail-subject', '.subject'],
      sender: ['#fromaddr', '.mail-detail-basic .basic-body-item:first-child .cmp-account-email', '.mail-detail-sender [email]', '.sender [email]', '.sender', '.from'],
      recipient: ['#toaddr', '.receiver'], frames: ['#mailContent', '#contentFrame', 'iframe[name="mailContent"]'] },
    { name: 'netease-mail', hosts: ['mail.163.com', 'mail.126.com', 'mail.yeah.net', 'qiye.163.com'],
      body: ['.mail-detail-content', '.mail-content', '.mailBody', '.mailContent', '.js-component-email-body'],
      subject: ['.nui-mail-detail-subject', '.mail-detail-subject', '.subject', 'h1'],
      sender: ['.nui-mail-detail-sender', '.mail-detail-sender', '.sender', '.from'],
      recipient: ['.nui-mail-detail-recipient', '.receiver'],
      frames: ['iframe[id^="_mail_emailcontent_"]', 'iframe[id^="mailContent"]', 'iframe.mailContent'] },
    { name: 'outlook', hosts: ['outlook.live.com', 'outlook.office.com', 'outlook.office365.com'],
      body: ['[aria-label*="Message body" i]', '[role="document"]'],
      subject: ['[role="heading"]', '[aria-label*="Subject" i]'],
      sender: ['[data-testid="SenderPersona"]', '[aria-label*="From" i]'], recipient: [] },
    { name: 'chinaccs-webmail', hosts: ['webmail.chinaccs.cn'],
      body: ['#mailContent', '#content', '.mail-content', '.mailBody', '.mailContent'],
      subject: ['#subject', '.subject', '[name="subject"]'], sender: ['.sender', '.from', '[email]'],
      recipient: [], frames: ['iframe#mailContent', 'iframe[name="mailContent"]'] },
  ];
  function visible(node) {
    if (!node || node.closest('[hidden], [aria-hidden="true"], #shielddome-risk-banner')) return false;
    for (let item = node; item; item = item.parentElement) {
      const style = item.ownerDocument.defaultView?.getComputedStyle(item);
      if (style?.display === 'none' || style?.visibility === 'hidden') return false;
    }
    return true;
  }
  function documents(doc, seen = new Set()) {
    if (!doc || seen.has(doc) || seen.size >= 20) return [];
    seen.add(doc);
    const result = [doc];
    for (const frame of doc.querySelectorAll('iframe, frame')) {
      try {
        if (visible(frame) && frame.contentDocument?.body) result.push(...documents(frame.contentDocument, seen));
      } catch (_) { /* Cross-origin mail frames are intentionally not read. */ }
    }
    return result;
  }
  function text(node) { return String(node?.innerText || node?.textContent || '').trim(); }
  function first(root, selectors) {
    for (const selector of selectors) {
      const match = Array.from(root.querySelectorAll(selector)).find(visible);
      if (match) return match;
    }
    return null;
  }
  function field(node) {
    return String(node?.getAttribute('email') || node?.getAttribute('data-email') || node?.getAttribute('addr') || text(node)).trim();
  }
  function extract(doc, location) {
    const adapter = adapters.find(item => item.hosts.includes(location.hostname.toLowerCase()));
    if (!adapter) return null;
    let selected = null;
    const docs = documents(doc);
    for (const current of docs) {
      const containers = adapter.containers
        ? Array.from(current.querySelectorAll(adapter.containers.join(','))).filter(visible) : [current];
      for (const container of containers) {
        let body = first(container, adapter.body);
        if (body?.matches('iframe, frame')) body = null;
        if (!body && adapter.frames) {
          const frame = first(container, adapter.frames);
          try { body = frame?.contentDocument?.body; } catch (_) { /* Unavailable frame. */ }
        }
        if (body && text(body)) selected = { body, container, current };
      }
    }
    if (!selected) return null;
    const { body, container, current } = selected;
    // Header lookup never searches the email HTML, where a sender can forge UI selectors.
    const headerFirst = (selectors, localOnly = false) => {
      for (const root of (localOnly ? [container] : [container, current, ...docs]).filter((value, index, all) => all.indexOf(value) === index)) {
        if (root === body || body.contains(root.documentElement || root)) continue;
        for (const selector of selectors) {
          const node = Array.from(root.querySelectorAll(selector)).find(item => visible(item) && !body.contains(item));
          if (node) return node;
        }
      }
      return null;
    };
    const subject = text(headerFirst(adapter.subject)).replace(/^主题\s*[:：]\s*/, '').slice(0, 300);
    const sender = field(headerFirst(adapter.sender, Boolean(adapter.containers))).slice(0, 500);
    // Require a header and a body: inbox, compose and login screens must not be submitted.
    if (!subject || !sender) return null;
    const bodyText = text(body).slice(0, 12000);
    const links = Array.from(body.querySelectorAll('a[href]')).slice(0, 50).map(anchor => {
      const label = text(anchor);
      const surrounding = text(anchor.parentElement);
      const index = surrounding.indexOf(label);
      return { display_text: label, href: anchor.href,
        context_before: index < 0 ? '' : surrounding.slice(Math.max(0, index - 50), index),
        context_after: index < 0 ? '' : surrounding.slice(index + label.length, index + label.length + 50),
        html_snippet: anchor.outerHTML.slice(0, 300) };
    });
    const url = new URL(location.href);
    return {
      subject, sender, recipient: field(headerFirst(adapter.recipient, Boolean(adapter.containers))).slice(0, 1000),
      body_summary: bodyText.slice(0, 1000), body_text: bodyText, links,
      mail_client: 'browser-extension:' + adapter.name,
      page_url: url.origin + url.pathname,
    };
  }
  globalThis.ShieldDomeMail = { extract, documents };
})();

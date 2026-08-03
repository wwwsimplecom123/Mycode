(function () {
  const BODY_SELECTORS = [
    "#mailContent",
    ".mailContent",
    ".mail-body",
    ".readMailContent",
    "[data-role='mail-body']",
  ];
  const SUBJECT_SELECTORS = ["#subject", ".mailSubject", "[name='subject']"];
  const SENDER_SELECTORS = [".mailFrom", ".sender", "[data-role='sender']"];
  const REPLY_TO_SELECTORS = [".mailReplyTo", "[data-role='reply-to']"];
  const RECIPIENT_SELECTORS = [".mailTo", ".recipient", "[data-role='recipient']"];
  const ATTACHMENT_SELECTORS = [
    "#attachmentList .attachment",
    ".attachment-item",
    "[data-role='attachment']",
  ];
  const MAX_BODY = 16384;
  const MAX_LINKS = 256;
  const MAX_ATTACHMENTS = 128;

  function readableDocuments() {
    const documents = [document];
    for (const selector of ["iframe#mailContentFrame", "iframe[name='mailContentFrame']"]) {
      const frame = document.querySelector(selector);
      try {
        if (frame && frame.contentDocument) documents.push(frame.contentDocument);
      } catch (_error) {
        // A cross-origin detail frame is not an authorized observation source.
      }
    }
    return documents;
  }

  function first(selectors, roots = readableDocuments()) {
    for (const root of roots) {
      for (const selector of selectors) {
        const node = root.querySelector(selector);
        if (node) return node;
      }
    }
    return null;
  }

  function cleanText(node, limit) {
    const value = String((node && (node.innerText || node.textContent)) || "")
      .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, " ")
      .replace(/\s+/g, " ")
      .trim();
    return value.slice(0, limit);
  }

  function selectedBody() {
    const node = first(BODY_SELECTORS);
    return node && cleanText(node, MAX_BODY) ? node : null;
  }

  function normalizeLinks(body) {
    const seen = new Set();
    const links = [];
    for (const anchor of body.querySelectorAll("a[href]")) {
      let value;
      try {
        const parsed = new URL(anchor.getAttribute("href"), document.baseURI);
        if (!["http:", "https:"].includes(parsed.protocol)) continue;
        parsed.hash = "";
        value = parsed.toString().slice(0, 2048);
      } catch (_error) {
        continue;
      }
      if (!seen.has(value)) {
        seen.add(value);
        links.push(value);
      }
      if (links.length >= MAX_LINKS) break;
    }
    return links;
  }

  function attachmentFacts() {
    const nodes = [];
    for (const doc of readableDocuments()) {
      for (const selector of ATTACHMENT_SELECTORS) {
        nodes.push(...doc.querySelectorAll(selector));
      }
    }
    return Array.from(new Set(nodes)).slice(0, MAX_ATTACHMENTS).map((node) => ({
      name: String(node.getAttribute("data-filename") || cleanText(first([
        ".attachment-name", ".filename", "[data-role='filename']",
      ], [node]), 512)).slice(0, 512),
      declared_type: String(node.getAttribute("data-mime-type") || "").slice(0, 255) || null,
      displayed_size: cleanText(first([
        ".attachment-size", ".filesize", "[data-role='filesize']",
      ], [node]), 64) || null,
    })).filter((item) => item.name);
  }

  function recipientSummary() {
    const text = cleanText(first(RECIPIENT_SELECTORS), 8192);
    return text.split(/[;,，；]+/).map((item) => item.trim().slice(0, 256)).filter(Boolean).slice(0, 32);
  }

  function languageHint(text) {
    const chinese = /[\u3400-\u9fff]/.test(text);
    const latin = /[A-Za-z]/.test(text);
    if (chinese && latin) return "mixed";
    if (chinese) return "zh";
    if (latin) return "en";
    return "other";
  }

  async function sourceDigest(subject, sender, bodyText) {
    const messageNode = first(["[data-message-id]", "#messageId", "[name='messageId']"]);
    const localIdentity = [
      location.origin,
      location.pathname,
      messageNode ? messageNode.getAttribute("data-message-id") || messageNode.getAttribute("value") || "" : "",
      subject,
      sender,
      bodyText,
    ].join("|");
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(localIdentity));
    return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  async function extractCurrentMail() {
    const body = selectedBody();
    if (!body) return { ok: false, error_code: "body_not_recognized" };
    const subject = cleanText(first(SUBJECT_SELECTORS), 512);
    const sender = cleanText(first(SENDER_SELECTORS), 512);
    const replyTo = cleanText(first(REPLY_TO_SELECTORS), 512) || null;
    const bodyText = cleanText(body, MAX_BODY);
    return {
      ok: true,
      mount: body.parentElement || body,
      mail: {
        source_message_id: await sourceDigest(subject, sender, bodyText),
        subject,
        sender,
        reply_to: replyTo,
        recipient_summary: recipientSummary(),
        sanitized_body_text: bodyText,
        normalized_links: normalizeLinks(body),
        attachment_metadata: attachmentFacts(),
        language_hint: languageHint(`${subject} ${bodyText}`),
      },
    };
  }

  function findStatusMount() {
    const body = selectedBody();
    return body ? body.parentElement || body : null;
  }

  globalThis.ShieldDomeChinaccsAdapter = { extractCurrentMail, findStatusMount };
})();

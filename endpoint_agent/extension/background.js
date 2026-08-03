const HOST_NAME = "cn.shielddome.endpoint_agent";
const RESPONSE_FIELDS = [
  "local_event_id",
  "risk_level",
  "execution_state",
  "generic_action",
];

function nativeFailureCode(message) {
  const normalized = String(message || "").toLowerCase();
  if (normalized.includes("host not found")) return "host_missing";
  if (normalized.includes("native host has exited")) return "agent_not_running";
  return "protocol_error";
}

function safeResponse(response) {
  if (!response || typeof response !== "object" || Array.isArray(response)) {
    return { ok: false, error_code: "protocol_error" };
  }
  if (typeof response.error_code === "string") {
    const code = ["frame_too_large", "payload_limit_exceeded"].includes(response.error_code)
      ? "request_too_large"
      : "protocol_error";
    return { ok: false, error_code: code };
  }
  const keys = Object.keys(response).sort();
  if (keys.join("|") !== [...RESPONSE_FIELDS].sort().join("|") ||
      RESPONSE_FIELDS.some((field) => typeof response[field] !== "string")) {
    return { ok: false, error_code: "protocol_error" };
  }
  return {
    ok: true,
    data: Object.fromEntries(RESPONSE_FIELDS.map((field) => [field, response[field]])),
  };
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || message.type !== "shielddome-detect-mail") return false;
  chrome.runtime.sendNativeMessage(HOST_NAME, message.request, (response) => {
    if (chrome.runtime.lastError) {
      sendResponse({
        ok: false,
        error_code: nativeFailureCode(chrome.runtime.lastError.message),
      });
      return;
    }
    sendResponse(safeResponse(response));
  });
  return true;
});

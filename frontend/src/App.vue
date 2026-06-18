<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";
import * as echarts from "echarts";

const view = ref("dashboard");
const dashboard = ref({ total: 0, risk: {}, pending: 0, degraded: 0, trend: [] });
const analyses = ref([]);
const knowledge = ref([]);
const selectedKnowledge = ref(null);
const selectedApprovalIds = ref([]);
const users = ref([]);
const auditLogs = ref([]);
const applications = ref([]);
const systemStatus = ref({ queue: {}, workers: [], provider: {}, database: {}, storage: {}, service: {} });
const selected = ref(null);
const eventFilter = ref({ type: "all", value: "", label: "全部邮件事件" });
const busy = ref(false);
const isDraggingEml = ref(false);
const emlDragDepth = ref(0);
const uploadMessage = ref("");
const knowledgeType = ref("phishing_case");
const knowledgeMessage = ref("");
const knowledgeBusy = ref(false);
const knowledgeActionId = ref("");
const approvalBusy = ref(false);
const knowledgeImportProgress = ref({ total: 0, done: 0, failed: 0 });
const providers = ref({ chat_endpoint: "", chat_model: "", embedding_endpoint: "", embedding_model: "", timeout: 25 });
const providerKey = ref("");
const providerMessage = ref("");
const providerBusy = ref(false);
const detectionPolicy = ref({ trusted_domains: [], trusted_ip_ranges: [], blacklisted_domains: [], high_risk_keywords: [], risk_thresholds: { medium: 35, high: 65, critical: 85 }, trusted_include_subdomains: true });
const policyForm = ref({ trusted_domains: "", trusted_ip_ranges: "", blacklisted_domains: "", high_risk_keywords: "", medium: 35, high: 65, critical: 85, trusted_include_subdomains: true });
const policyMessage = ref("");
const policyBusy = ref(false);
const token = ref("");
const user = ref(null);
const loginForm = ref({ username: "admin", password: "" });
const loginError = ref("");
const loginBusy = ref(false);
const authReady = ref(false);
const serviceWarning = ref("");
const actionMessage = ref("");
const issuedPluginToken = ref(null);
const userForm = ref({ username: "", display_name: "", password: "", role: "analyst" });
const headers = computed(() => (token.value ? { Authorization: `Bearer ${token.value}` } : {}));
let refreshTimer = null;
const filteredAnalyses = computed(() => {
  const filter = eventFilter.value;
  if (filter.type === "risk") return analyses.value.filter((item) => item.risk_level === filter.value);
  if (filter.type === "high") return analyses.value.filter((item) => ["high", "critical"].includes(item.risk_level));
  if (filter.type === "status") return analyses.value.filter((item) => item.status === filter.value);
  if (filter.type === "pending") return analyses.value.filter((item) => ["queued", "running"].includes(item.status));
  if (filter.type === "date") return analyses.value.filter((item) => String(item.created_at || "").startsWith(filter.value));
  return analyses.value;
});
const knowledgeStats = computed(() => ({
  total: knowledge.value.length,
  pending: knowledge.value.filter((item) => item.status === "pending").length,
  published: knowledge.value.filter((item) => item.status === "published").length,
  disabled: knowledge.value.filter((item) => item.status === "disabled").length,
}));
const pendingKnowledge = computed(() => knowledge.value.filter((item) => item.status === "pending"));
const allPendingSelected = computed(() => pendingKnowledge.value.length > 0 && pendingKnowledge.value.every((item) => selectedApprovalIds.value.includes(item.id)));
const policyStats = computed(() => ({
  trustedDomains: policyLines(policyForm.value.trusted_domains).length,
  trustedIpRanges: policyLines(policyForm.value.trusted_ip_ranges).length,
  blacklistedDomains: policyLines(policyForm.value.blacklisted_domains).length,
  keywords: policyLines(policyForm.value.high_risk_keywords).length,
}));
const viewScopeLabel = computed(() => (user.value?.role === "admin" ? "全局视图" : "个人视图"));
const navItems = computed(() => {
  const allItems = [
    ["dashboard", "首页"], ["upload", "EML 检测"], ["events", "邮件事件"],
    ["internal", "内部钓鱼"], ["knowledge", "RAG 知识库"], ["approvals", "审批中心"], ["applications", "应用中心"],
    ["policy", "策略管理"], ["users", "用户管理"], ["settings", "模型 API 设置"],
    ["audit", "审计日志"], ["system", "系统状态"],
  ];
  if (user.value?.role === "admin") return allItems;
  if (user.value?.role === "auditor") return allItems.filter((item) => ["dashboard", "events", "internal", "applications", "audit", "system"].includes(item[0]));
  return allItems.filter((item) => ["dashboard", "upload", "events", "internal", "knowledge", "applications", "system"].includes(item[0]));
});
const labels = {
  critical: "严重",
  high: "高风险",
  medium: "中风险",
  low: "低风险",
  queued: "排队中",
  running: "检测中",
  completed: "已完成",
  degraded: "降级完成",
  failed: "检测失败",
  pending: "待审核",
  published: "已发布",
  disabled: "已停用",
  phishing_case: "钓鱼案例",
  trusted_email: "可信邮件",
  security_rule: "安全规则",
  soc_review: "SOC 结论",
  admin: "系统管理员",
  analyst: "安全分析员",
  auditor: "审计员",
  environment: "服务器环境变量",
  encrypted_database: "网页加密配置",
  encrypted_database_error: "网页密钥解密失败",
  not_configured: "未配置",
  local_key_file: "本机受限主密钥",
  completed: "已完成",
};

function label(value) {
  return labels[value] || value || "-";
}

async function api(path, options = {}) {
  const response = await fetch(path, { credentials: "same-origin", ...options, headers: { ...headers.value, ...(options.headers || {}) } });
  if (response.status === 401 && !path.includes("/auth/login")) {
    clearSession();
  }
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}

async function login() {
  loginBusy.value = true;
  loginError.value = "";
  try {
    const result = await api("/api/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(loginForm.value),
    });
    token.value = "";
    user.value = result.user;
    await refresh();
    startAutoRefresh();
  } catch (error) {
    loginError.value = "登录失败，请检查用户名和密码。";
  } finally {
    loginBusy.value = false;
  }
}

async function logout() {
  try { await api("/api/v1/auth/logout", { method: "POST" }); } catch {}
  clearSession();
}

function clearSession() {
  token.value = "";
  user.value = null;
  stopAutoRefresh();
}

async function refresh() {
  serviceWarning.value = "";
  const results = await Promise.allSettled([
    api("/api/v1/dashboard"),
    api("/api/v1/analyses").then((x) => x.items),
    api("/api/v1/knowledge").then((x) => x.items),
    api("/api/v1/settings/providers"),
    api("/api/v1/apps").then((x) => x.items),
    api("/api/v1/audit").then((x) => x.items),
    api("/api/v1/system/status"),
  ]);
  const targets = [dashboard, analyses, knowledge, providers, applications, auditLogs, systemStatus];
  results.forEach((result, index) => {
    if (result.status === "fulfilled") targets[index].value = result.value;
  });
  const failed = results.filter((result) => result.status === "rejected").length;
  if (failed) serviceWarning.value = `${failed} 个模块暂时无法加载，登录会话仍保持有效。`;
  if (user.value?.role === "admin") {
    try {
      const [managedUsers, policy] = await Promise.all([
        api("/api/v1/users").then((x) => x.items),
        api("/api/v1/settings/detection-policy"),
      ]);
      users.value = managedUsers;
      setPolicyForm(policy);
    } catch {
      serviceWarning.value = "管理员设置模块暂时无法加载，登录会话仍保持有效。";
    }
  }
  await nextTick();
  renderChart();
}

function startAutoRefresh() {
  stopAutoRefresh();
  refreshTimer = window.setInterval(() => {
    if (user.value) refresh();
  }, 15000);
}

function stopAutoRefresh() {
  if (refreshTimer) window.clearInterval(refreshTimer);
  refreshTimer = null;
}

function openView(name) {
  if (name === "events" || name === "internal") clearEventFilter();
  view.value = name;
}

function drillToEvents(type, value, filterLabel) {
  eventFilter.value = { type, value, label: filterLabel };
  selected.value = null;
  view.value = "events";
}

function clearEventFilter() {
  eventFilter.value = { type: "all", value: "", label: "全部邮件事件" };
}

async function submitEml(file) {
  uploadMessage.value = "";
  if (!file) {
    uploadMessage.value = "未检测到可上传的文件。";
    return;
  }
  if (!file.name.toLowerCase().endsWith(".eml")) {
    uploadMessage.value = "仅支持上传 .eml 邮件文件。";
    return;
  }
  if (file.size > 50 * 1024 * 1024) {
    uploadMessage.value = "文件超过 50 MB 限制。";
    return;
  }
  busy.value = true;
  uploadMessage.value = `正在提交 ${file.name}...`;
  try {
    const form = new FormData();
    form.append("file", file);
    const result = await api("/api/v1/messages/analyze", { method: "POST", body: form });
    selected.value = result;
    view.value = "events";
    await refresh();
  } catch (error) {
    uploadMessage.value = `提交失败：${readError(error)}`;
  } finally {
    busy.value = false;
  }
}

async function uploadEml(event) {
  await submitEml(event.target.files?.[0]);
  event.target.value = "";
}

function dragEmlOver(event) {
  event.dataTransfer.dropEffect = "copy";
  isDraggingEml.value = true;
}

function enterEmlDropZone() {
  if (busy.value) return;
  emlDragDepth.value += 1;
  isDraggingEml.value = true;
}

function leaveEmlDropZone() {
  emlDragDepth.value = Math.max(0, emlDragDepth.value - 1);
  if (!emlDragDepth.value) isDraggingEml.value = false;
}

async function dropEml(event) {
  emlDragDepth.value = 0;
  isDraggingEml.value = false;
  if (busy.value) return;
  await submitEml(event.dataTransfer?.files?.[0]);
}

async function uploadKnowledge(event) {
  const files = Array.from(event.target.files || []);
  event.target.value = "";
  if (!files.length) return;
  knowledgeBusy.value = true;
  knowledgeImportProgress.value = { total: files.length, done: 0, failed: 0 };
  const failures = [];
  try {
    for (const file of files) {
      knowledgeMessage.value = `正在导入 ${knowledgeImportProgress.value.done + 1}/${files.length}：${file.name}`;
      const form = new FormData();
      form.append("file", file);
      form.append("source_type", knowledgeType.value);
      try {
        await api("/api/v1/knowledge/import", { method: "POST", body: form });
      } catch (error) {
        knowledgeImportProgress.value.failed += 1;
        failures.push(`${file.name}：${readError(error)}`);
      } finally {
        knowledgeImportProgress.value.done += 1;
      }
    }
    const success = files.length - knowledgeImportProgress.value.failed;
    knowledgeMessage.value = knowledgeImportProgress.value.failed
      ? `批量导入完成：成功 ${success} 个，失败 ${knowledgeImportProgress.value.failed} 个。${failures.slice(0, 3).join("；")}`
      : `批量导入完成：成功 ${success} 个，均已进入待审核。发布后才会参与后续深度检测。`;
    await refresh();
  } finally {
    knowledgeBusy.value = false;
  }
}

async function openAnalysis(item) {
  selected.value = await api(`/api/v1/analyses/${item.id}`);
}

function evidenceSource() {
  return selected.value?.result || selected.value?.quick_result || {};
}

function evidenceLinks() {
  return evidenceSource().quick_result?.evidence?.links || evidenceSource().evidence?.links || [];
}

function evidenceRules() {
  return evidenceSource().quick_result?.matched_rules || evidenceSource().matched_rules || [];
}

async function retrySelectedAnalysis() {
  if (!selected.value?.id) return;
  const analysisId = selected.value.id;
  try {
    await api(`/api/v1/analyses/${analysisId}/retry`, { method: "POST" });
    actionMessage.value = "已重新加入深度分析队列。";
    await refresh();
    selected.value = await api(`/api/v1/analyses/${analysisId}`);
  } catch (error) {
    actionMessage.value = `重试失败：${readError(error)}`;
  }
}

async function submitFeedback(verdict) {
  if (!selected.value?.id) return;
  const comment = window.prompt("请输入简短说明，系统会创建待审核知识用于后续闭环。") || "";
  try {
    const result = await api(`/api/v1/analyses/${selected.value.id}/feedback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ verdict, comment }),
    });
    actionMessage.value = result.knowledge_id ? "反馈已记录，并已生成待审核知识。" : "反馈已记录。";
    await refresh();
  } catch (error) {
    actionMessage.value = `反馈失败：${readError(error)}`;
  }
}

function formatBytes(value) {
  const size = Number(value || 0);
  if (size >= 1024 * 1024 * 1024) return `${(size / 1024 / 1024 / 1024).toFixed(1)} GB`;
  if (size >= 1024 * 1024) return `${(size / 1024 / 1024).toFixed(1)} MB`;
  if (size >= 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${size} B`;
}

function openKnowledge(item) {
  selectedKnowledge.value = item;
}

function isApprovalSelected(item) {
  return selectedApprovalIds.value.includes(item.id);
}

function toggleApprovalSelection(item) {
  selectedApprovalIds.value = isApprovalSelected(item)
    ? selectedApprovalIds.value.filter((id) => id !== item.id)
    : [...selectedApprovalIds.value, item.id];
}

function toggleAllPendingApprovals() {
  selectedApprovalIds.value = allPendingSelected.value ? [] : pendingKnowledge.value.map((item) => item.id);
}

function knowledgePreview(item) {
  return String(item?.content || item?.generalized_content || "").slice(0, 6000);
}

async function refreshAndKeepKnowledge(itemId = selectedKnowledge.value?.id) {
  await refresh();
  selectedKnowledge.value = itemId ? knowledge.value.find((item) => item.id === itemId) || null : null;
  const pendingIds = new Set(pendingKnowledge.value.map((item) => item.id));
  selectedApprovalIds.value = selectedApprovalIds.value.filter((id) => pendingIds.has(id));
}

async function approve(item) {
  knowledgeMessage.value = "";
  if (!item?.id || knowledgeActionId.value || approvalBusy.value) return;
  knowledgeActionId.value = item.id;
  try {
    await api(`/api/v1/knowledge/${item.id}/approve`, { method: "POST" });
    knowledgeMessage.value = "知识已发布，新的邮件深度检测会检索该知识。";
    await refreshAndKeepKnowledge(item.id);
  } catch (error) {
    knowledgeMessage.value = `发布失败：${readError(error)}`;
  } finally {
    knowledgeActionId.value = "";
  }
}

async function disableKnowledge(item) {
  knowledgeMessage.value = "";
  if (!item?.id || knowledgeActionId.value || approvalBusy.value) return;
  knowledgeActionId.value = item.id;
  try {
    await api(`/api/v1/knowledge/${item.id}/disable`, { method: "POST" });
    knowledgeMessage.value = "知识已停用，不再参与后续 RAG 检索。";
    await refreshAndKeepKnowledge(item.id);
  } catch (error) {
    knowledgeMessage.value = `停用失败：${readError(error)}`;
  } finally {
    knowledgeActionId.value = "";
  }
}

async function bulkKnowledgeAction(action) {
  const ids = [...selectedApprovalIds.value];
  if (!ids.length || approvalBusy.value) return;
  const isApprove = action === "approve";
  const text = isApprove ? "发布" : "停用";
  if (!window.confirm(`确定批量${text}选中的 ${ids.length} 条知识？`)) return;
  approvalBusy.value = true;
  knowledgeMessage.value = `正在批量${text} ${ids.length} 条知识...`;
  try {
    const result = await api(`/api/v1/knowledge/bulk-${isApprove ? "approve" : "disable"}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ids }),
    });
    knowledgeMessage.value = result.failed?.length
      ? `批量${text}完成：成功 ${result.completed} 条，失败 ${result.failed.length} 条。`
      : `批量${text}完成：成功 ${result.completed} 条。`;
    selectedApprovalIds.value = [];
    await refreshAndKeepKnowledge();
  } catch (error) {
    knowledgeMessage.value = `批量${text}失败：${readError(error)}`;
  } finally {
    approvalBusy.value = false;
  }
}

async function reindexKnowledge() {
  if (!window.confirm("确定重建已导入知识的向量索引？该操作可能需要一些时间。")) return;
  knowledgeBusy.value = true;
  knowledgeMessage.value = "正在重建知识向量索引...";
  try {
    const result = await api("/api/v1/knowledge/reindex", { method: "POST" });
    knowledgeMessage.value = `重建完成：成功 ${result.completed} 条，失败 ${result.failed} 条。`;
    await refresh();
  } catch (error) {
    knowledgeMessage.value = `重建失败：${readError(error)}`;
  } finally {
    knowledgeBusy.value = false;
  }
}

function setPolicyForm(policy) {
  detectionPolicy.value = policy;
  policyForm.value = {
    trusted_domains: (policy.trusted_domains || []).join("\n"),
    trusted_ip_ranges: (policy.trusted_ip_ranges || []).join("\n"),
    blacklisted_domains: (policy.blacklisted_domains || []).join("\n"),
    high_risk_keywords: (policy.high_risk_keywords || []).join("\n"),
    medium: policy.risk_thresholds?.medium ?? 35,
    high: policy.risk_thresholds?.high ?? 65,
    critical: policy.risk_thresholds?.critical ?? 85,
    trusted_include_subdomains: policy.trusted_include_subdomains !== false,
  };
}

function policyLines(value) {
  return [...new Set(String(value || "").split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean))];
}

async function saveDetectionPolicy() {
  policyBusy.value = true;
  policyMessage.value = "";
  try {
    const saved = await api("/api/v1/settings/detection-policy", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        trusted_domains: policyLines(policyForm.value.trusted_domains),
        trusted_ip_ranges: policyLines(policyForm.value.trusted_ip_ranges),
        blacklisted_domains: policyLines(policyForm.value.blacklisted_domains),
        high_risk_keywords: policyLines(policyForm.value.high_risk_keywords),
        trusted_include_subdomains: Boolean(policyForm.value.trusted_include_subdomains),
        risk_thresholds: {
          medium: Number(policyForm.value.medium),
          high: Number(policyForm.value.high),
          critical: Number(policyForm.value.critical),
        },
      }),
    });
    setPolicyForm(saved);
    policyMessage.value = "检测策略已保存，新提交的邮件将立即使用该策略。";
  } catch (error) {
    policyMessage.value = `保存失败：${readError(error)}`;
  } finally {
    policyBusy.value = false;
  }
}

function validateProviderForm() {
  const chatEndpoint = String(providers.value.chat_endpoint || "").toLowerCase();
  const chatModel = String(providers.value.chat_model || "").toLowerCase();
  const embeddingEndpoint = String(providers.value.embedding_endpoint || "").toLowerCase();
  const embeddingModel = String(providers.value.embedding_model || "").toLowerCase();
  if (chatEndpoint.includes("/rerank")) return "Chat API 不能使用 /rerank，请填写 /v1/chat/completions。";
  if (["rerank", "embedding", "captioner"].some((marker) => chatModel.includes(marker))) return "Chat 模型不能使用 Reranker、Embedding 或 Captioner，请选择对话生成模型。";
  if (!embeddingEndpoint.includes("/embeddings")) return "Embedding API 地址必须使用 /v1/embeddings。";
  if (embeddingModel.includes("rerank")) return "Embedding 模型不能使用 Reranker，请选择文本嵌入模型。";
  return "";
}

async function saveProviders() {
  const validationError = validateProviderForm();
  if (validationError) {
    providerMessage.value = validationError;
    return;
  }
  providerBusy.value = true;
  providerMessage.value = "";
  try {
    providers.value = await api("/api/v1/settings/providers", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_endpoint: providers.value.chat_endpoint,
        chat_model: providers.value.chat_model,
        embedding_endpoint: providers.value.embedding_endpoint,
        embedding_model: providers.value.embedding_model,
        timeout: providers.value.timeout,
        api_key: providerKey.value || undefined,
      }),
    });
    providerKey.value = "";
    providerMessage.value = "模型配置已安全保存。";
  } catch (error) {
    providerMessage.value = `保存失败：${readError(error)}`;
  } finally {
    providerBusy.value = false;
  }
}

async function testProviders() {
  providerBusy.value = true;
  providerMessage.value = "正在测试 Chat 与 Embedding API...";
  try {
    const result = await api("/api/v1/settings/providers/test", { method: "POST" });
    const chat = label(result.chat?.status) || "未知";
    const embedding = label(result.embedding?.status) || "未知";
    const failure = result.ok ? "" : `；原因：${result.chat?.reason || result.embedding?.error || "请检查模型名称、超时和供应商状态"}`;
    const compatibility = result.chat?.compatibility_fallbacks?.length ? "；已自动启用模型兼容模式" : "";
    providerMessage.value = `${result.ok ? "连接测试通过" : "连接测试未通过"}：Chat ${chat}，Embedding ${embedding}${result.embedding?.dimensions ? `（${result.embedding.dimensions} 维）` : ""}${compatibility}${failure}`;
  } catch (error) {
    providerMessage.value = `测试失败：${readError(error)}`;
  } finally {
    providerBusy.value = false;
  }
}

async function clearProviderKey() {
  if (!window.confirm("确定清除网页保存的模型 API Key？清除后模型分析会降级。")) return;
  providerBusy.value = true;
  try {
    providers.value = await api("/api/v1/settings/providers", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ clear_api_key: true }),
    });
    providerKey.value = "";
    providerMessage.value = "网页保存的 API Key 已清除。";
  } catch (error) {
    providerMessage.value = `清除失败：${readError(error)}`;
  } finally {
    providerBusy.value = false;
  }
}

async function createUser() {
  actionMessage.value = "";
  issuedPluginToken.value = null;
  try {
    const created = await api("/api/v1/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(userForm.value),
    });
    issuedPluginToken.value = { username: created.username, token: created.plugin_token };
    userForm.value = { username: "", display_name: "", password: "", role: "analyst" };
    users.value = await api("/api/v1/users").then((x) => x.items);
    actionMessage.value = "用户已创建，并已签发个人插件 Token。Token 仅显示一次。";
  } catch (error) {
    actionMessage.value = `操作失败：${readError(error)}`;
  }
}

async function rotatePluginToken(item) {
  if (!window.confirm(`确定轮换 ${item.username} 的插件 Token？旧 Token 将立即失效。`)) return;
  actionMessage.value = "";
  issuedPluginToken.value = null;
  try {
    const issued = await api(`/api/v1/users/${item.id}/plugin-token`, { method: "POST" });
    issuedPluginToken.value = { username: item.username, token: issued.token };
    users.value = await api("/api/v1/users").then((x) => x.items);
    actionMessage.value = "插件 Token 已轮换，旧 Token 已失效。新 Token 仅显示一次。";
  } catch (error) {
    actionMessage.value = `操作失败：${readError(error)}`;
  }
}

async function revokePluginToken(item) {
  if (!window.confirm(`确定撤销 ${item.username} 的插件 Token？该用户插件将无法继续检测。`)) return;
  actionMessage.value = "";
  issuedPluginToken.value = null;
  try {
    await api(`/api/v1/users/${item.id}/plugin-token`, { method: "DELETE" });
    users.value = await api("/api/v1/users").then((x) => x.items);
    actionMessage.value = "插件 Token 已撤销。";
  } catch (error) {
    actionMessage.value = `操作失败：${readError(error)}`;
  }
}

async function copyIssuedPluginToken() {
  if (!issuedPluginToken.value?.token) return;
  await navigator.clipboard.writeText(issuedPluginToken.value.token);
  actionMessage.value = "插件 Token 已复制，请通过安全渠道交付给对应用户。";
}

async function updateUserAccount(item, disabled = item.disabled) {
  actionMessage.value = "";
  try {
    await api(`/api/v1/users/${item.id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ display_name: item.display_name, role: item.role, disabled }),
    });
    users.value = await api("/api/v1/users").then((x) => x.items);
    actionMessage.value = "用户信息已更新。";
  } catch (error) {
    actionMessage.value = `操作失败：${readError(error)}`;
  }
}

async function resetUserPassword(item) {
  const password = window.prompt(`请输入 ${item.username} 的新密码（至少 12 位）`);
  if (!password) return;
  try {
    await api(`/api/v1/users/${item.id}/reset-password`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });
    actionMessage.value = "密码已重置，该用户的既有会话已撤销。";
  } catch (error) {
    actionMessage.value = `操作失败：${readError(error)}`;
  }
}

async function downloadApplication(item) {
  actionMessage.value = "";
  try {
    const response = await fetch(item.download_url, { headers: headers.value });
    if (!response.ok) throw new Error(await response.text());
    const link = document.createElement("a");
    link.href = URL.createObjectURL(await response.blob());
    link.download = item.package;
    link.click();
    URL.revokeObjectURL(link.href);
    actionMessage.value = `已下载 ${item.name} v${item.version}。`;
  } catch (error) {
    actionMessage.value = `下载失败：${readError(error)}`;
  }
}

function readError(error) {
  try {
    const parsed = JSON.parse(error.message);
    return parsed.detail || error.message;
  } catch {
    return error.message || "未知错误";
  }
}

let trendChart = null;

function renderChart() {
  requestAnimationFrame(() => {
    const node = document.querySelector("#trend");
    if (!node) return;
    trendChart = echarts.getInstanceByDom(node) || echarts.init(node);
    trendChart.setOption({
      tooltip: {
        trigger: "axis",
        formatter: (items) => `${items[0].axisValue}<br>检测数量：<b>${items[0].value}</b><br><small>点击数据点查看当天事件</small>`,
      },
      grid: { left: 46, right: 24, top: 24, bottom: 42 },
      xAxis: {
        type: "category",
        boundaryGap: false,
        data: dashboard.value.trend.map((x) => x.date),
        axisLabel: { formatter: (value) => value.slice(5), color: "#7d899b" },
        axisLine: { lineStyle: { color: "#d9e1ec" } },
      },
      yAxis: {
        type: "value",
        minInterval: 1,
        axisLabel: { color: "#7d899b" },
        splitLine: { lineStyle: { color: "#edf1f6" } },
      },
      series: [{
        name: "检测数量",
        type: "line",
        smooth: 0.25,
        symbol: "circle",
        symbolSize: 8,
        showSymbol: true,
        lineStyle: { width: 3, color: "#5b91f5" },
        itemStyle: { color: "#fff", borderColor: "#5b91f5", borderWidth: 3 },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: "rgba(91,145,245,.30)" },
            { offset: 1, color: "rgba(91,145,245,.02)" },
          ]),
        },
        data: dashboard.value.trend.map((x) => x.count),
      }],
    });
    trendChart.off("click");
    trendChart.on("click", (params) => drillToEvents("date", params.name, `${params.name} 的检测事件`));
    trendChart.resize();
  });
}

onMounted(async () => {
  try {
    user.value = await api("/api/v1/auth/me");
    await refresh();
    startAutoRefresh();
  } catch {
    clearSession();
  } finally {
    authReady.value = true;
  }
});

watch(view, async (name) => {
  if (name === "approvals" && user.value?.role === "admin") {
    if (!selectedKnowledge.value || selectedKnowledge.value.status !== "pending") {
      selectedKnowledge.value = pendingKnowledge.value[0] || null;
    }
  }
  if (name === "dashboard") {
    await nextTick();
    renderChart();
  }
});

onBeforeUnmount(() => {
  stopAutoRefresh();
  trendChart?.dispose();
});
</script>

<template>
  <div v-if="!authReady" class="loading-page"><span class="logo">S</span><b>正在恢复安全会话...</b></div>
  <div v-else-if="!user" class="login-page">
    <section class="login-card">
      <div class="login-brand"><span class="logo">S</span><div><b>盾穹 ShieldDome</b><small>企业钓鱼邮件检测平台</small></div></div>
      <div class="login-heading"><h1>登录管理控制台</h1><p>请输入系统管理员账号继续访问。</p></div>
      <form @submit.prevent="login">
        <label>用户名<input v-model.trim="loginForm.username" autocomplete="username" required></label>
        <label>密码<input v-model="loginForm.password" type="password" autocomplete="current-password" required></label>
        <p v-if="loginError" class="login-error">{{ loginError }}</p>
        <button class="primary login-button" type="submit" :disabled="loginBusy">{{ loginBusy ? "正在登录..." : "登录" }}</button>
      </form>
      <small class="login-note">连续失败 5 次将锁定账号 15 分钟。</small>
    </section>
  </div>
  <div v-else class="shell">
    <aside>
      <div class="brand"><span class="logo">S</span><div><b>盾穹</b><small>ShieldDome</small></div></div>
      <button v-for="item in navItems" :key="item[0]" :class="{active:view===item[0]}" @click="openView(item[0])">{{ item[1] }}</button>
    </aside>
    <main>
      <header><b>{{ {dashboard:'首页',upload:'EML 检测',events:'邮件事件',internal:'内部钓鱼',knowledge:'RAG 知识库',approvals:'审批中心',applications:'应用中心',policy:'策略管理',users:'用户管理',settings:'模型 API 设置',audit:'审计日志'}[view] || 'ShieldDome 控制台' }}</b><div class="user-area"><span>{{ viewScopeLabel }} · 观察模式 · 不自动隔离</span><b>{{ user.display_name }}</b><small>{{ label(user.role) }}</small><button @click="logout">退出登录</button></div></header>
      <section class="content">
        <p v-if="serviceWarning" class="service-warning">{{ serviceWarning }}</p>
        <p v-if="user.role !== 'admin' && ['dashboard','events','internal','audit'].includes(view)" class="scope-note">当前为个人视图，仅显示你本人提交或产生的邮件检测与审计记录。</p>
        <template v-if="view==='dashboard'">
          <div class="stats">
            <article class="stat-card clickable" role="button" tabindex="0" @click="drillToEvents('all','','全部邮件事件')" @keyup.enter="drillToEvents('all','','全部邮件事件')"><small>检测总量</small><strong>{{ dashboard.total }}</strong><span>查看全部事件 →</span></article>
            <article class="stat-card clickable" role="button" tabindex="0" @click="drillToEvents('high','','高风险与严重事件')" @keyup.enter="drillToEvents('high','','高风险与严重事件')"><small>高风险</small><strong class="orange">{{ (dashboard.risk.high||0)+(dashboard.risk.critical||0) }}</strong><span>查看风险事件 →</span></article>
            <article class="stat-card clickable" role="button" tabindex="0" @click="drillToEvents('pending','','待处理任务')" @keyup.enter="drillToEvents('pending','','待处理任务')"><small>待处理任务</small><strong>{{ dashboard.pending }}</strong><span>查看任务队列 →</span></article>
            <article class="stat-card clickable" role="button" tabindex="0" @click="drillToEvents('status','degraded','降级完成事件')" @keyup.enter="drillToEvents('status','degraded','降级完成事件')"><small>降级完成</small><strong>{{ dashboard.degraded }}</strong><span>查看降级事件 →</span></article>
          </div>
          <div class="grid"><article class="panel wide"><div class="panel-heading"><h3>检测趋势</h3><small>最近 14 天 · 点击数据点查看详情</small></div><div id="trend" class="chart"></div></article><article class="panel"><h3>风险分布</h3><button class="risk-row clickable" v-for="level in ['critical','high','medium','low']" :key="level" @click="drillToEvents('risk',level,`${label(level)}事件`)"><span>{{ label(level) }}</span><b>{{ dashboard.risk[level] || 0 }}</b><small>查看详情 →</small></button></article></div>
        </template>
        <template v-else-if="view==='upload'">
          <article class="panel upload"><h2>上传 EML 文件检测</h2><p>邮件将进入规则、RAG 与 LLM 分析链路，原文件默认保存 72 小时。</p><label :class="['drop',{dragging:isDraggingEml,busy}]" @dragenter.prevent="enterEmlDropZone" @dragover.prevent="dragEmlOver" @dragleave.prevent="leaveEmlDropZone" @drop.prevent.stop="dropEml"><input type="file" accept=".eml,message/rfc822" @change="uploadEml" :disabled="busy"><b>{{ busy ? '正在提交并开始检测...' : isDraggingEml ? '松开鼠标立即开始检测' : '点击选择或拖拽 .eml 文件' }}</b><span :class="{error:uploadMessage.startsWith('提交失败') || uploadMessage.startsWith('仅支持') || uploadMessage.startsWith('文件超过') || uploadMessage.startsWith('未检测到')}">{{ uploadMessage || '最大 50 MB，拖放后自动开始检测' }}</span></label></article>
        </template>
        <template v-else-if="view==='events' || view==='internal'">
          <div class="grid events"><article class="panel"><div class="event-heading"><div><h3>{{ eventFilter.label }}</h3><small>共 {{ filteredAnalyses.length }} 条结果</small></div><button v-if="eventFilter.type!=='all'" @click="clearEventFilter">清除筛选</button></div><table><thead><tr><th>时间</th><th>来源</th><th>状态</th><th>风险</th></tr></thead><tbody><tr v-for="item in filteredAnalyses" :key="item.id" @click="openAnalysis(item)"><td>{{ item.created_at?.slice(0,19) }}</td><td>{{ item.source_name }}</td><td>{{ label(item.status) }}</td><td><span :class="'tag '+item.risk_level">{{ label(item.risk_level) }}</span></td></tr><tr v-if="!filteredAnalyses.length"><td colspan="4" class="empty-row">当前筛选条件下暂无事件</td></tr></tbody></table></article><article class="panel detail"><div class="title-row"><div><h3>检测详情</h3><small>{{ selected?.id || '请选择左侧事件' }}</small></div><button v-if="selected && ['failed','degraded'].includes(selected.status)" @click="retrySelectedAnalysis">重新分析</button></div><p v-if="actionMessage" class="action-message">{{ actionMessage }}</p><template v-if="selected"><div class="detail-summary"><span :class="'tag '+selected.risk_level">{{ label(selected.risk_level) }}</span><b>{{ label(selected.status) }}</b><small>{{ selected.source_name }}</small></div><section class="evidence-block"><h4>判定依据</h4><p>{{ evidenceSource().reason || selected.quick_result?.reason || '暂无解释' }}</p><div class="evidence-grid"><div><b>命中规则</b><code>{{ evidenceRules().join(', ') || '-' }}</code></div><div><b>认证结果</b><code>{{ JSON.stringify(evidenceSource().authentication || selected.parsed_message?.authentication || {}) }}</code></div><div><b>模型状态</b><code>{{ evidenceSource().llm?.status || '-' }} {{ evidenceSource().llm?.error_type || '' }}</code></div><div><b>RAG 引用</b><code>{{ evidenceSource().rag?.references?.length || 0 }} 条</code></div></div><h4>链接风险</h4><table><thead><tr><th>显示域名</th><th>真实域名</th><th>错配</th><th>可信</th></tr></thead><tbody><tr v-for="(link,index) in evidenceLinks().slice(0,8)" :key="index"><td>{{ link.display_domain || '-' }}</td><td>{{ link.href_domain || '-' }}</td><td>{{ link.display_href_mismatch ? '是' : '否' }}</td><td>{{ link.trusted_href ? '是' : '否' }}</td></tr><tr v-if="!evidenceLinks().length"><td colspan="4" class="empty-row">暂无链接证据</td></tr></tbody></table><div class="settings-actions"><button @click="submitFeedback('false_positive')">标记误报</button><button @click="submitFeedback('confirmed_phishing')">确认钓鱼</button><button @click="submitFeedback('uncertain')">标记不确定</button></div></section><details><summary>原始 JSON</summary><pre>{{ JSON.stringify(selected || {}, null, 2) }}</pre></details></template><p v-else class="empty-row">请选择一条邮件事件查看详情</p></article></div>
        </template>
        <template v-else-if="view==='knowledge'">
          <div class="knowledge-page">
            <article class="panel knowledge-heading">
              <div><h2>RAG 知识库</h2><p>深度检测会检索已发布知识，为模型提供相似案例、可信样本和安全规则；待审核知识不会进入正式研判。</p></div>
              <div class="import-tools"><select v-model="knowledgeType"><option value="phishing_case">钓鱼案例</option><option value="trusted_email">可信邮件</option><option value="security_rule">安全规则</option><option value="soc_review">SOC 结论</option></select><label :class="['primary',{disabled:knowledgeBusy}]">{{ knowledgeBusy ? '导入中...' : '批量导入' }}<input type="file" multiple accept=".eml,.txt,.md,.csv,.pdf" @change="uploadKnowledge" :disabled="knowledgeBusy"></label><button @click="reindexKnowledge" :disabled="knowledgeBusy || !knowledge.length">重建索引</button></div>
            </article>
            <div class="knowledge-flow">
              <span>导入</span><b>→</b><span>待审核</span><b>→</b><span>发布</span><b>→</b><span>参与 RAG 检索</span>
            </div>
            <div class="stats compact knowledge-stats">
              <article><small>全部知识</small><strong>{{ knowledgeStats.total }}</strong><span>含待审核与停用</span></article>
              <article><small>参与检测</small><strong>{{ knowledgeStats.published }}</strong><span>仅已发布状态</span></article>
              <article><small>待审核</small><strong>{{ knowledgeStats.pending }}</strong><span>需人工发布</span></article>
              <article><small>已停用</small><strong>{{ knowledgeStats.disabled }}</strong><span>不参与检索</span></article>
            </div>
            <p v-if="knowledgeMessage" class="action-message">{{ knowledgeMessage }}</p>
            <div v-if="knowledgeBusy && knowledgeImportProgress.total" class="knowledge-progress"><span :style="{width: `${Math.round((knowledgeImportProgress.done / knowledgeImportProgress.total) * 100)}%`}"></span><small>{{ knowledgeImportProgress.done }} / {{ knowledgeImportProgress.total }}</small></div>
            <article class="panel knowledge-list">
              <div class="panel-heading"><h3>知识条目</h3><small>导入 .eml/.txt/.md/.csv/.pdf 后，先审核再发布</small></div>
              <table>
                <thead><tr><th>标题</th><th>类型</th><th>状态</th><th>版本</th><th>更新时间</th><th>操作</th></tr></thead>
                <tbody>
                  <tr v-for="item in knowledge" :key="item.id" @click="openKnowledge(item)">
                    <td><b>{{ item.title }}</b><small class="subtext">{{ item.metadata?.filename || item.id }}</small></td>
                    <td>{{ label(item.source_type) }}</td>
                    <td><span :class="['status-pill', item.status === 'published' ? 'on' : 'off']">{{ label(item.status) }}</span></td>
                    <td>v{{ item.version }}</td>
                    <td>{{ item.updated_at?.slice(0,19).replace('T',' ') || '-' }}</td>
                    <td class="actions" @click.stop>
                      <button type="button" @click.stop="openKnowledge(item)">查看</button>
                      <template v-if="user.role==='admin'">
                        <button type="button" @click.stop="approve(item)" :disabled="item.status==='published' || knowledgeActionId===item.id || approvalBusy">{{ knowledgeActionId===item.id ? '处理中' : '发布' }}</button>
                        <button type="button" class="danger" @click.stop="disableKnowledge(item)" :disabled="item.status==='disabled' || knowledgeActionId===item.id || approvalBusy">{{ knowledgeActionId===item.id ? '处理中' : '停用' }}</button>
                      </template>
                      <small v-else class="subtext">仅管理员审批</small>
                    </td>
                  </tr>
                  <tr v-if="!knowledge.length"><td colspan="6" class="empty-row">暂无知识。导入后会先进入待审核，发布后才会被深度检测检索。</td></tr>
                </tbody>
              </table>
            </article>
            <article v-if="selectedKnowledge" class="panel knowledge-detail"><div class="title-row"><div><h3>知识详情</h3><small>{{ selectedKnowledge.id }}</small></div><div class="actions"><template v-if="user.role==='admin'"><button type="button" @click="approve(selectedKnowledge)" :disabled="selectedKnowledge.status==='published' || knowledgeActionId===selectedKnowledge.id || approvalBusy">{{ knowledgeActionId===selectedKnowledge.id ? '处理中' : '发布' }}</button><button type="button" class="danger" @click="disableKnowledge(selectedKnowledge)" :disabled="selectedKnowledge.status==='disabled' || knowledgeActionId===selectedKnowledge.id || approvalBusy">{{ knowledgeActionId===selectedKnowledge.id ? '处理中' : '停用' }}</button></template><button type="button" @click="selectedKnowledge=null">关闭</button></div></div><div class="evidence-grid"><div><b>标题</b><code>{{ selectedKnowledge.title }}</code></div><div><b>类型 / 状态</b><code>{{ label(selectedKnowledge.source_type) }} / {{ label(selectedKnowledge.status) }}</code></div><div><b>来源文件</b><code>{{ selectedKnowledge.metadata?.filename || '-' }}</code></div><div><b>更新时间</b><code>{{ selectedKnowledge.updated_at?.slice(0,19).replace('T',' ') || '-' }}</code></div></div><h4>内容预览</h4><pre>{{ knowledgePreview(selectedKnowledge) || '暂无可预览内容' }}</pre></article>
          </div>
        </template>
        <template v-else-if="view==='approvals' && user.role==='admin'">
          <div class="approval-page">
            <article class="panel approval-heading"><div><h2>审批中心</h2><p>集中审核待发布知识。发布后才会进入 RAG 检索，停用后不会参与后续检测。</p></div><div class="approval-summary"><b>{{ pendingKnowledge.length }} 项待审核</b><small>已选择 {{ selectedApprovalIds.length }} 项</small></div></article>
            <div class="approval-grid">
              <article class="panel approval-list">
                <div class="panel-heading">
                  <div><h3>待审核知识</h3><small>点击查看内容后再决定发布</small></div>
                  <div class="actions">
                    <button type="button" @click="toggleAllPendingApprovals" :disabled="approvalBusy || !pendingKnowledge.length">{{ allPendingSelected ? '取消全选' : '全选' }}</button>
                    <button type="button" @click="bulkKnowledgeAction('approve')" :disabled="approvalBusy || !selectedApprovalIds.length">{{ approvalBusy ? '处理中' : '批量发布' }}</button>
                    <button type="button" class="danger" @click="bulkKnowledgeAction('disable')" :disabled="approvalBusy || !selectedApprovalIds.length">{{ approvalBusy ? '处理中' : '批量停用' }}</button>
                  </div>
                </div>
                <table>
                  <thead><tr><th class="check-col">选择</th><th>标题</th><th>类型</th><th>来源</th><th>导入时间</th><th>操作</th></tr></thead>
                  <tbody>
                    <tr v-for="item in pendingKnowledge" :key="item.id" @click="openKnowledge(item)">
                      <td class="check-col" @click.stop><input type="checkbox" :checked="isApprovalSelected(item)" @change="toggleApprovalSelection(item)"></td>
                      <td><b>{{ item.title }}</b><small class="subtext">{{ item.id }}</small></td>
                      <td>{{ label(item.source_type) }}</td>
                      <td>{{ item.metadata?.filename || '-' }}</td>
                      <td>{{ item.created_at?.slice(0,19).replace('T',' ') || '-' }}</td>
                      <td class="actions" @click.stop>
                        <button type="button" @click.stop="openKnowledge(item)">查看</button>
                        <button type="button" @click.stop="approve(item)" :disabled="knowledgeActionId===item.id || approvalBusy">{{ knowledgeActionId===item.id ? '处理中' : '发布' }}</button>
                        <button type="button" class="danger" @click.stop="disableKnowledge(item)" :disabled="knowledgeActionId===item.id || approvalBusy">{{ knowledgeActionId===item.id ? '处理中' : '停用' }}</button>
                      </td>
                    </tr>
                    <tr v-if="!pendingKnowledge.length"><td colspan="6" class="empty-row">当前没有待审核知识。</td></tr>
                  </tbody>
                </table>
              </article>
              <article class="panel approval-detail"><template v-if="selectedKnowledge"><div class="title-row"><div><h3>{{ selectedKnowledge.title }}</h3><small>{{ label(selectedKnowledge.source_type) }} · {{ label(selectedKnowledge.status) }}</small></div><div class="actions"><button type="button" @click="approve(selectedKnowledge)" :disabled="selectedKnowledge.status==='published' || knowledgeActionId===selectedKnowledge.id || approvalBusy">{{ knowledgeActionId===selectedKnowledge.id ? '处理中' : '发布' }}</button><button type="button" class="danger" @click="disableKnowledge(selectedKnowledge)" :disabled="selectedKnowledge.status==='disabled' || knowledgeActionId===selectedKnowledge.id || approvalBusy">{{ knowledgeActionId===selectedKnowledge.id ? '处理中' : '停用' }}</button></div></div><div class="evidence-grid"><div><b>来源文件</b><code>{{ selectedKnowledge.metadata?.filename || '-' }}</code></div><div><b>版本</b><code>v{{ selectedKnowledge.version }}</code></div></div><h4>内容预览</h4><pre>{{ knowledgePreview(selectedKnowledge) || '暂无可预览内容' }}</pre></template><p v-else class="empty-row">请选择左侧知识查看详情。</p></article>
            </div>
          </div>
        </template>
        <template v-else-if="view==='policy' && user.role==='admin'">
          <div class="policy-page">
            <article class="panel policy-heading">
              <div><h2>检测策略管理</h2><p>策略保存后立即影响新提交邮件。可信项降低误报，黑名单和关键词提供规则证据，阈值决定最终风险等级。</p></div>
              <button class="primary" @click="saveDetectionPolicy" :disabled="policyBusy">{{ policyBusy ? "正在保存..." : "保存并启用策略" }}</button>
            </article>
            <p v-if="policyMessage" class="action-message">{{ policyMessage }}</p>
            <div class="policy-summary">
              <div><small>可信域名</small><b>{{ policyStats.trustedDomains }}</b></div>
              <div><small>可信 IP/CIDR</small><b>{{ policyStats.trustedIpRanges }}</b></div>
              <div><small>黑名单域名</small><b>{{ policyStats.blacklistedDomains }}</b></div>
              <div><small>高风险关键词</small><b>{{ policyStats.keywords }}</b></div>
              <div><small>当前阈值</small><b>{{ policyForm.medium }} / {{ policyForm.high }} / {{ policyForm.critical }}</b></div>
            </div>
            <div class="policy-grid refined">
              <article class="panel policy-card">
                <div class="policy-card-head"><span class="policy-kind trust">放行</span><div><h3>可信域名</h3><p>每行一个根域名。匹配后降低外链和发件人域风险。</p></div></div>
                <textarea v-model="policyForm.trusted_domains" rows="9" spellcheck="false" placeholder="company.com&#10;mail.company.com"></textarea>
                <label class="checkbox-line"><input v-model="policyForm.trusted_include_subdomains" type="checkbox"> 子域名继承可信</label>
                <small>{{ policyLines(policyForm.trusted_domains).length }} 项</small>
              </article>
              <article class="panel policy-card">
                <div class="policy-card-head"><span class="policy-kind trust">放行</span><div><h3>可信 IP / CIDR</h3><p>仅这里配置的 IP 或网段会被视为内部可信地址。</p></div></div>
                <textarea v-model="policyForm.trusted_ip_ranges" rows="9" spellcheck="false" placeholder="10.24.0.0/16&#10;192.168.10.8/32"></textarea>
                <small>{{ policyLines(policyForm.trusted_ip_ranges).length }} 项</small>
              </article>
              <article class="panel policy-card">
                <div class="policy-card-head"><span class="policy-kind block">拦截</span><div><h3>黑名单域名</h3><p>命中域名或其子域名时直接产生强风险证据。</p></div></div>
                <textarea v-model="policyForm.blacklisted_domains" rows="9" spellcheck="false" placeholder="evil-login.example&#10;phish.example"></textarea>
                <small>{{ policyLines(policyForm.blacklisted_domains).length }} 项</small>
              </article>
              <article class="panel policy-card">
                <div class="policy-card-head"><span class="policy-kind score">评分</span><div><h3>高风险关键词</h3><p>关键词本身只提供弱信号，需要与外链等证据组合判断。</p></div></div>
                <textarea v-model="policyForm.high_risk_keywords" rows="9" spellcheck="false" placeholder="密码&#10;付款&#10;password"></textarea>
                <small>{{ policyLines(policyForm.high_risk_keywords).length }} 项</small>
              </article>
            </div>
            <article class="panel threshold-panel">
              <div><h3>风险等级阈值</h3><p>必须满足：低风险 &lt; 中风险 &lt; 高风险 &lt; 严重风险，严重风险阈值不超过 100。</p></div>
              <div class="threshold-fields">
                <label>中风险<input v-model.number="policyForm.medium" type="number" min="1" max="98"></label>
                <label>高风险<input v-model.number="policyForm.high" type="number" min="2" max="99"></label>
                <label>严重风险<input v-model.number="policyForm.critical" type="number" min="3" max="100"></label>
              </div>
            </article>
          </div>
        </template>
        <template v-else-if="view==='settings'">
          <article class="panel settings">
            <h2>模型与接口设置</h2>
            <p>管理员可直接配置硅基流动 API Key。Key 仅提交给后端并加密保存，页面不会回显明文；同一个 Key 同时用于 Chat 与 Embedding。</p>
            <p v-if="providers.configuration_error" class="configuration-warning">当前模型配置无效：{{ providers.configuration_error }}</p>
            <div :class="['secret-status', providers.configured ? 'configured' : 'unconfigured']"><b>{{ providers.configured ? '密钥已配置' : '密钥未配置' }}</b><span>{{ providers.api_key_masked || '尚未保存 API Key' }}</span><small>来源：{{ label(providers.secret_source) }} · 主密钥：{{ label(providers.secret_encryption) }}</small></div>
            <label>硅基流动 API Key<input v-model.trim="providerKey" type="password" autocomplete="new-password" placeholder="输入新 Key；留空则保留现有 Key"></label>
            <label>Chat API 地址<input v-model="providers.chat_endpoint"><small>使用 /v1/chat/completions，不能填写 /v1/rerank。</small></label>
              <label>Chat 模型<input v-model="providers.chat_model"><small>请选择支持 Chat Completions 的生成模型。部分模型不支持 JSON Mode，系统会自动切换兼容模式；Reranker、Embedding 和 Captioner 不能用于邮件研判。</small></label>
            <label>Embedding API 地址<input v-model="providers.embedding_endpoint"><small>使用 /v1/embeddings。</small></label>
            <label>Embedding 模型<input v-model="providers.embedding_model"><small>推荐 Pro/BAAI/bge-m3；不要选择名称含 Reranker 的模型。</small></label>
              <label>超时（秒）<input v-model.number="providers.timeout" type="number" min="1" max="120"><small>生成式 Chat 模型通常比 Embedding 慢；GLM-5.1 等较慢模型建议设置为 60–120 秒。</small></label>
            <div class="settings-actions"><button class="primary" @click="saveProviders" :disabled="providerBusy">{{ providerBusy ? '处理中...' : '保存模型配置' }}</button><button @click="testProviders" :disabled="providerBusy || !providers.configured">测试连接</button><button class="danger-button" @click="clearProviderKey" :disabled="providerBusy || !providers.configured">清除密钥</button></div>
            <p v-if="providerMessage" class="action-message">{{ providerMessage }}</p>
          </article>
        </template>
        <template v-else-if="view==='users' && user.role==='admin'">
          <div class="management-grid">
            <article class="panel user-create">
              <h2>创建用户</h2><p>为安全运营、审计或系统管理人员创建独立账号。</p>
              <form @submit.prevent="createUser">
                <label>用户名<input v-model.trim="userForm.username" required minlength="3" maxlength="64" placeholder="例如 zhangsan"></label>
                <label>显示名称<input v-model.trim="userForm.display_name" required maxlength="100" placeholder="例如 张三"></label>
                <label>初始密码<input v-model="userForm.password" type="password" required minlength="12" autocomplete="new-password" placeholder="至少 12 位"></label>
                <label>角色<select v-model="userForm.role"><option value="analyst">安全分析员</option><option value="auditor">审计员</option><option value="admin">系统管理员</option></select></label>
                <button class="primary" type="submit">创建用户</button>
              </form>
            </article>
            <article class="panel">
              <div class="title-row"><div><h2>用户账号</h2><p>每位用户使用独立插件 Token。停用账号会立即撤销登录会话和插件 Token。</p></div><b>{{ users.length }} 个账号</b></div>
              <p v-if="actionMessage" class="action-message">{{ actionMessage }}</p>
              <div v-if="issuedPluginToken" class="issued-token"><b>{{ issuedPluginToken.username }} 的插件 Token，仅显示一次</b><code>{{ issuedPluginToken.token }}</code><button @click="copyIssuedPluginToken">复制 Token</button></div>
              <table><thead><tr><th>用户</th><th>角色</th><th>状态</th><th>插件 Token</th><th>最近使用</th><th>操作</th></tr></thead>
                <tbody><tr v-for="item in users" :key="item.id">
                  <td><input v-model="item.display_name" class="table-input"><small class="subtext">{{ item.username }}</small></td>
                  <td><select v-model="item.role" class="table-input"><option value="admin">系统管理员</option><option value="analyst">安全分析员</option><option value="auditor">审计员</option></select></td>
                  <td><span :class="['status-pill', item.disabled ? 'off' : 'on']">{{ item.disabled ? '已停用' : '正常' }}</span></td>
                  <td><span :class="['status-pill', item.plugin_token_configured ? 'on' : 'off']">{{ item.plugin_token_configured ? item.plugin_token_prefix + '...' : '未签发' }}</span></td>
                  <td>{{ item.plugin_token_last_used_at?.slice(0,16).replace('T',' ') || '-' }}</td>
                  <td class="actions"><button @click="updateUserAccount(item)">保存</button><button @click="resetUserPassword(item)">重置密码</button><button @click="rotatePluginToken(item)" :disabled="item.disabled">{{ item.plugin_token_configured ? '轮换 Token' : '签发 Token' }}</button><button v-if="item.plugin_token_configured" class="danger" @click="revokePluginToken(item)">撤销 Token</button><button :class="{danger:!item.disabled}" @click="updateUserAccount(item,!item.disabled)">{{ item.disabled ? '启用' : '停用' }}</button></td>
                </tr></tbody>
              </table>
            </article>
          </div>
        </template>
        <template v-else-if="view==='audit'">
          <article class="panel">
            <div class="title-row"><div><h2>审计日志</h2><p>浏览器插件检测会记录责任用户、用户 ID、邮件摘要 ID 与来源页面。</p></div><b>{{ auditLogs.length }} 条记录</b></div>
            <table><thead><tr><th>时间</th><th>责任用户</th><th>动作</th><th>目标</th><th>详情</th></tr></thead>
              <tbody><tr v-for="item in auditLogs" :key="item.id"><td>{{ item.created_at?.slice(0,19).replace('T',' ') }}</td><td>{{ item.actor }}</td><td>{{ item.action }}</td><td>{{ item.target }}</td><td><code>{{ JSON.stringify(item.details) }}</code></td></tr><tr v-if="!auditLogs.length"><td colspan="5" class="empty-row">暂无审计记录</td></tr></tbody>
            </table>
          </article>
        </template>
        <template v-else-if="view==='applications'">
          <article class="panel">
            <div class="title-row"><div><h2>应用中心</h2><p>从当前 ShieldDome 网站下载最新版客户端应用与浏览器插件。</p></div><span class="status-pill on">网站发行源正常</span></div>
            <p v-if="actionMessage" class="action-message">{{ actionMessage }}</p>
            <div class="app-cards">
              <section class="app-card" v-for="item in applications" :key="item.id">
                <div class="app-icon">S</div><div class="app-info"><h3>{{ item.name }}</h3><p>{{ item.description }}</p><div class="app-meta"><span>版本 v{{ item.version }}</span><span>{{ item.platforms.join(' / ') }}</span><span>ZIP 安装包</span></div><code>SHA-256 {{ item.sha256 }}</code></div>
                <div class="app-actions"><button class="primary" @click="downloadApplication(item)">下载最新版</button><small>{{ item.update_mode }}</small></div>
              </section>
            </div>
            <div class="install-guide"><h3>安装与更新说明</h3><ol><li>下载并解压最新版 ZIP。</li><li>在 Chrome 或 Edge 扩展管理页开启开发者模式。</li><li>选择“加载已解压的扩展程序”，打开解压后的 <code>extension</code> 目录。</li><li>打开插件的“扩展程序选项”，填写 ShieldDome 服务地址并授权连接。</li><li>更新时重新下载最新版并覆盖原目录，然后在扩展管理页点击“重新加载”。</li></ol><p>企业批量部署时，可使用 Chrome/Edge 企业策略配置托管自动更新。</p></div>
          </article>
        </template>
        <template v-else-if="view==='system'">
          <div class="system-grid">
            <article class="panel"><h2>系统状态</h2><div class="evidence-grid"><div><b>服务</b><code>{{ systemStatus.service?.status || '-' }} v{{ systemStatus.service?.version || '-' }}</code></div><div><b>数据库</b><code>{{ systemStatus.database?.backend || '-' }} / {{ systemStatus.database?.status || '-' }}</code></div><div><b>pgvector</b><code>{{ systemStatus.database?.pgvector_expected ? '生产环境需要' : '本地 SQLite 不需要' }}</code></div><div><b>磁盘可用</b><code>{{ formatBytes(systemStatus.storage?.free_bytes) }} / {{ formatBytes(systemStatus.storage?.total_bytes) }}</code></div></div></article>
            <article class="panel"><h2>任务队列</h2><div class="stats compact"><article class="stat-card"><small>排队</small><strong>{{ systemStatus.queue?.queued || 0 }}</strong></article><article class="stat-card"><small>运行中</small><strong>{{ systemStatus.queue?.running || 0 }}</strong></article><article class="stat-card"><small>失败</small><strong>{{ systemStatus.queue?.failed || 0 }}</strong></article><article class="stat-card"><small>已完成</small><strong>{{ systemStatus.queue?.completed || 0 }}</strong></article></div></article>
            <article class="panel"><h2>Worker 心跳</h2><table><thead><tr><th>Worker</th><th>最近心跳</th></tr></thead><tbody><tr v-for="item in systemStatus.workers" :key="item.worker_id"><td>{{ item.worker_id }}</td><td>{{ item.last_seen_at?.slice(0,19).replace('T',' ') }}</td></tr><tr v-if="!systemStatus.workers?.length"><td colspan="2" class="empty-row">暂无 Worker 心跳</td></tr></tbody></table></article>
            <article class="panel"><h2>模型配置</h2><div class="evidence-grid"><div><b>状态</b><code>{{ systemStatus.provider?.configured ? '已配置' : '未配置' }}</code></div><div><b>Chat</b><code>{{ systemStatus.provider?.chat_model || '-' }}</code></div><div><b>Embedding</b><code>{{ systemStatus.provider?.embedding_model || '-' }}</code></div><div><b>错误</b><code>{{ systemStatus.provider?.configuration_error || '-' }}</code></div></div></article>
          </div>
        </template>
        <article v-else class="panel"><h2>功能已接入后端 API</h2><p>该管理页面将在后续策略配置与运维数据产生后展示对应内容。</p></article>
      </section>
    </main>
  </div>
</template>

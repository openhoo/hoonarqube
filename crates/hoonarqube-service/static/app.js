(() => {
  "use strict";

  const API_PREFIX = "/api/v1";
  const HISTORY_PAGE_SIZE = 25;
  const FINDINGS_PAGE_SIZE = 100;
  const state = {
    token: null,
    projects: [],
    branches: [],
    analyses: [],
    project: "",
    branch: "",
    analysis: null,
    findings: [],
    analysisPages: newPager(),
    findingPages: newPager(),
    selectedFinding: null,
    selectedReview: null,
    reviewAnalysisId: null,
    sessionRequest: 0,
    branchRequest: 0,
    analysisRequest: 0,
    reviewRequest: 0,
    historyRequest: 0,

    busy: 0,
    savingReview: null,
  };
  const byId = (id) => document.getElementById(id);
  const elements = {
    sessionStatus: byId("session-status"),
    authBadge: byId("auth-badge"),
    connectionForm: byId("connection-form"),
    token: byId("token"),
    disconnect: byId("disconnect-button"),
    connectionError: byId("connection-error"),
    scopeForm: byId("scope-form"),
    project: byId("project"),
    branch: byId("branch"),
    loadScope: byId("load-scope-button"),
    scopeBadge: byId("scope-badge"),
    scopeError: byId("scope-error"),
    historyPanel: byId("history-panel"),
    historyBody: byId("history-body"),
    historyCount: byId("history-count"),
    historyEmpty: byId("history-empty"),
    historyError: byId("history-error"),
    historyLoading: byId("history-loading"),
    analysisError: byId("analysis-error"),
    detailPanel: byId("detail-panel"),
    detailCompleteness: byId("detail-completeness"),
    detailWarning: byId("detail-warning"),
    metadata: byId("analysis-metadata"),
    metricsGrid: byId("metrics-grid"),
    metricsEmpty: byId("metrics-empty"),
    gateSummary: byId("gate-summary"),
    gatesList: byId("gates-list"),
    gatesEmpty: byId("gates-empty"),
    findingsIncomplete: byId("findings-incomplete"),
    findingsError: byId("findings-error"),
    findingsEmpty: byId("findings-empty"),
    findingsList: byId("findings-list"),
    findingsCount: byId("findings-count"),
    reviewPanel: byId("review-panel"),
    reviewTarget: byId("review-target"),
    reviewContext: byId("review-context"),
    reviewMessage: byId("review-message"),
    reviewError: byId("review-error"),
    ordinaryForm: byId("ordinary-review-form"),
    hotspotForm: byId("hotspot-review-form"),
    auditList: byId("audit-list"),
    auditEmpty: byId("audit-empty"),
    refreshHistory: byId("refresh-history-button"),
    globalError: byId("global-error"),
    loading: byId("loading"),
    findingsLoading: byId("findings-loading"),
    findingsRetry: byId("findings-retry"),
    ordinarySave: byId("ordinary-save-button"),
    hotspotSave: byId("hotspot-save-button"),
  };

  const historyPager = pagination("history", elements.historyBody, elements.historyCount);
  const findingsPager = pagination("findings", elements.findingsList, elements.findingsCount);

  function pagination(id, list, count) {
    return { container: byId(`${id}-pagination`), previous: byId(`${id}-previous`),
      next: byId(`${id}-next`), list, count };
  }

  function newPager() {
    return { index: 0, cursors: [null], next: null, pending: false, loaded: false };
  }

  function cursorFor(pager, index) {
    return index === pager.index + 1 ? pager.next : pager.cursors[index];
  }

  function pageQuery(limit, cursor) {
    const query = new URLSearchParams({ limit });
    if (cursor !== null) query.set("cursor", cursor);
    return query;
  }

  function readPage(payload, key, limit, currentCursor) {
    const items = responseList(payload, key);
    const next = payload.next_cursor;
    if (items.length > limit || (next !== null &&
      (typeof next !== "string" || !next || next === currentCursor || items.length !== limit))) {
      throw new ApiError(502, "The service returned an invalid page. Try the request again.");
    }
    return { items, next };
  }

  function acceptPage(pager, index, cursor, next) {
    pager.index = index;
    pager.cursors.length = index + 1;
    pager.cursors[index] = cursor;
    pager.next = next;
    pager.loaded = true;
  }

  function showPageCount(count, pager, length, singular, plural) {
    const label = `Page ${pager.index + 1} · ${length} ${length === 1 ? singular : plural} shown`;
    if (count.textContent !== label) count.textContent = label;
  }

  function updatePagination(controls, pager, trigger) {
    const hadFocus = trigger && document.activeElement === trigger;
    controls.container.hidden = !pager.loaded || (pager.index === 0 && pager.next === null);
    controls.previous.disabled = pager.index === 0;
    controls.next.disabled = pager.next === null;
    for (const button of [controls.previous, controls.next]) {
      button.setAttribute("aria-disabled", String(button.disabled || pager.pending));
    }
    controls.list.setAttribute("aria-busy", String(pager.pending));
    if (hadFocus && (controls.container.hidden || trigger.disabled)) controls.count.focus();
  }

  function text(value, fallback = "—") {
    if (value === null || value === undefined || value === "") return fallback;
    return String(value);
  }


  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function appendText(node, value, fallback) {
    node.appendChild(document.createTextNode(text(value, fallback)));
  }

  function setHidden(node, hidden) {
    node.hidden = hidden;
  }

  function showNotice(node, message, kind = "error") {
    node.className = `notice notice-${kind}`;
    clear(node);
    appendText(node, message);
    node.hidden = false;
  }

  function hideNotice(node) {
    node.hidden = true;
    clear(node);
  }

  function setBusy(busy) {
    state.busy += busy ? 1 : -1;
    state.busy = Math.max(0, state.busy);
    elements.loading.hidden = state.busy === 0;
  }

  function displayError(error) {
    const message = error instanceof ApiError
      ? error.message
      : (error && error.message) || "The service request failed.";
    showNotice(elements.globalError, message);
  }

  function normalizeErrorMessage(payload, fallback) {
    if (!payload || typeof payload !== "object") return fallback;
    if (typeof payload.error === "string") return payload.error;
    if (payload.error && typeof payload.error.message === "string") return payload.error.message;
    if (typeof payload.message === "string") return payload.message;
    return fallback;
  }

  class ApiError extends Error {
    constructor(status, message, payload) {
      super(message);
      this.name = "ApiError";
      this.status = status;
      this.payload = payload;
    }
  }

  async function apiRequest(path, options = {}) {
    if (!state.token) throw new ApiError(401, "Enter a bearer token before connecting.");
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");
    headers.set("Authorization", `Bearer ${state.token}`);
    if (options.body !== undefined) headers.set("Content-Type", "application/json");
    setBusy(true);
    try {
      const response = await fetch(`${API_PREFIX}${path}`, { ...options, cache: "no-store", headers });
      const raw = await response.text();
      let payload = null;
      if (raw) {
        try {
          payload = JSON.parse(raw);
        } catch {
          payload = null;
        }
      }
      if (!response.ok) {
        const fallback = response.status === 401 || response.status === 403
          ? "The token is not authorized for this project or action."
          : `The service returned HTTP ${response.status}.`;
        throw new ApiError(response.status, normalizeErrorMessage(payload, fallback), payload);
      }
      if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
        throw new ApiError(502, "The service returned an invalid JSON response. Try the request again.");
      }
      return payload;
    } finally {
      setBusy(false);
    }
  }

  function responseList(payload, key) {
    if (!Array.isArray(payload[key])) throw new ApiError(502, `The service response is missing the ${key} list. Try the request again.`);
    return payload[key];
  }

  function pathPart(value) {
    return encodeURIComponent(String(value));
  }

  function apiPath(project, suffix = "") {
    return `/projects/${pathPart(project)}${suffix}`;
  }

  function projectId(project) {
    return project && project.project;
  }

  function projectLabel(project) {
    return project && project.project;
  }

  function branchName(branch) {
    return branch && branch.name;
  }

  function analysisId(analysis) {
    return analysis && analysis.id;
  }

  function analysisField(analysis, field, fallback = null) {
    if (!analysis || typeof analysis !== "object") return fallback;
    return analysis[field] === undefined ? fallback : analysis[field];
  }

  function completenessOf(analysis) {
    if (analysis && analysis.complete === true) return "complete";
    if (analysis && analysis.complete === false) return "incomplete";
    return "unknown";
  }

  function statusClass(status) {
    const value = String(status || "").toLowerCase();
    if (["pass", "passed", "complete", "accepted", "resolved", "safe"].includes(value)) return "success";
    if (["incomplete", "missing", "invalid", "unavailable", "unknown", "to_review", "existing"].includes(value)) return "warning";
    if (["fail", "failed", "confirmed_risk", "error"].includes(value)) return "danger";
    return "muted";
  }

  function setBadge(node, value, fallback = "Unknown") {
    clear(node);
    appendText(node, value, fallback);
    node.className = `badge badge-${statusClass(value)}`;
  }

  function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
  }

  function formatNumber(value) {
    if (typeof value !== "number" || !Number.isFinite(value)) return null;
    return new Intl.NumberFormat().format(value);
  }

  function setSession(connected) {
    clear(elements.sessionStatus);
    appendText(elements.sessionStatus, connected ? "Connected (token held in memory)" : "Not connected");
    setBadge(elements.authBadge, connected ? "Authenticated" : "No credentials");
    elements.project.disabled = !connected || state.projects.length === 0;
    elements.branch.disabled = true;
    elements.loadScope.disabled = true;
    elements.disconnect.disabled = !connected;
  }

  function resetSelect(node, prompt) {
    clear(node);
    const option = document.createElement("option");
    option.value = "";
    appendText(option, prompt);
    node.appendChild(option);
  }

  function fillProjects(projects) {
    state.projects = Array.isArray(projects) ? projects : [];
    resetSelect(elements.project, state.projects.length ? "Select a project" : "No projects available");
    for (const project of state.projects) {
      const value = projectId(project);
      if (!value) continue;
      const option = document.createElement("option");
      option.value = String(value);
      appendText(option, projectLabel(project), value);
      elements.project.appendChild(option);
    }
    elements.project.disabled = !state.token || state.projects.length === 0;
  }

  function fillBranches(branches) {
    state.branches = Array.isArray(branches) ? branches : [];
    resetSelect(elements.branch, state.branches.length ? "Select a branch" : "No branches available");
    for (const branch of state.branches) {
      const value = branchName(branch);
      if (!value) continue;
      const option = document.createElement("option");
      option.value = String(value);
      appendText(option, value);
      elements.branch.appendChild(option);
    }
    elements.branch.disabled = !state.project || state.branches.length === 0;
    elements.loadScope.disabled = !state.project || !elements.branch.value;
  }

  function clearReviewSelection() {
    state.reviewRequest += 1;
    state.savingReview = null;
    elements.ordinarySave.disabled = false;
    elements.hotspotSave.disabled = false;
    state.historyRequest += 1;
    state.selectedFinding = null;
    state.selectedReview = null;
    state.reviewAnalysisId = null;
    setHidden(elements.reviewPanel, true);
    clear(elements.auditList);
    setHidden(elements.auditEmpty, true);
    hideNotice(elements.reviewMessage);
    hideNotice(elements.reviewError);
  }

  function resetAnalysis() {
    state.analysisRequest += 1;
    setHidden(elements.detailPanel, true);
    state.analysis = null;
    state.findings = [];
    state.findingPages = newPager();
    updatePagination(findingsPager, state.findingPages);
    clear(elements.findingsList);
    elements.findingsCount.textContent = "Not loaded";
    setHidden(elements.findingsEmpty, true);
    setHidden(elements.findingsLoading, true);
    setHidden(elements.findingsRetry, true);
    hideNotice(elements.findingsError);
    hideNotice(elements.findingsIncomplete);
    clearReviewSelection();
  }

  function hideResults() {
    state.analysisPages = newPager();
    state.analyses = [];
    updatePagination(historyPager, state.analysisPages);
    setHidden(elements.historyPanel, true);
    setHidden(elements.historyEmpty, true);
    setHidden(elements.historyLoading, true);
    hideNotice(elements.historyError);
    hideNotice(elements.analysisError);
    clear(elements.historyBody);
    elements.historyCount.textContent = "Not loaded";
    resetAnalysis();
  }

  async function loadProjects() {
    const requestToken = state.sessionRequest;
    hideNotice(elements.connectionError);
    hideNotice(elements.globalError);
    try {
      const payload = await apiRequest("/projects");
      if (requestToken !== state.sessionRequest) return;
      fillProjects(responseList(payload, "projects"));
      setSession(true);
      if (!state.projects.length) showNotice(elements.connectionError, "This token can authenticate, but it has no visible projects.", "warning");
    } catch (error) {
      if (requestToken !== state.sessionRequest) return;
      if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
        state.token = null;
        elements.token.value = "";
        fillProjects([]);
        setSession(false);
      }
      resetSelect(elements.project, "Reconnect to load projects");
      showNotice(elements.connectionError, error.message || "Unable to load projects.");
    }
  }

  async function loadBranches() {
    const requestToken = ++state.branchRequest;
    const sessionToken = state.sessionRequest;
    state.project = elements.project.value;
    state.branch = "";
    fillBranches([]);
    hideNotice(elements.scopeError);
    hideResults();
    if (!state.project) {
      elements.scopeBadge.textContent = "No project selected";
      return;
    }
    setBadge(elements.scopeBadge, state.project);
    resetSelect(elements.branch, "Loading branches…");
    try {
      const payload = await apiRequest(apiPath(state.project, "/branches"));
      if (requestToken !== state.branchRequest || sessionToken !== state.sessionRequest) return;
      fillBranches(responseList(payload, "branches"));
      setBadge(elements.scopeBadge, state.project, "Project selected");
    } catch (error) {
      if (requestToken !== state.branchRequest || sessionToken !== state.sessionRequest) return;
      resetSelect(elements.branch, "Select the project again to retry");
      showNotice(elements.scopeError, error.message || "Unable to load branches.");
      displayError(error);
    }
  }


  function renderHistory() {
    clear(elements.historyBody);
    const analyses = state.analyses;
    setHidden(elements.historyEmpty, analyses.length !== 0);
    elements.historyEmpty.textContent = state.analysisPages.index === 0
      ? "No analyses are stored for this branch."
      : "No more analyses on this page. Go back or reload the branch.";
    showPageCount(elements.historyCount, state.analysisPages, analyses.length, "analysis", "analyses");
    for (const summary of analyses) {
      const id = analysisId(summary);
      if (!id) continue;
      const row = document.createElement("tr");
      row.analysisId = id;
      const selected = state.analysis && analysisId(state.analysis) === id;
      row.className = selected ? "analysis-selected" : "";
      row.addEventListener("click", () => selectAnalysis(id));
      const cells = [
        ["commit", analysisField(summary, "commit", null)],
        ["analyzed", formatDate(analysisField(summary, "analyzed_at", null))],
        ["id", analysisId(summary)],
        ["completeness", completenessOf(summary)],
        ["version", analysisField(summary, "report_schema_version", null)],
      ];
      for (const [kind, value] of cells) {
        const cell = document.createElement("td");
        if (kind === "commit") cell.className = "mono";
        if (kind === "commit") {
          const button = document.createElement("button");
          button.type = "button";
          button.className = "analysis-button";
          button.setAttribute("aria-label", `View analysis ${id}, commit ${text(value)}`);
          button.setAttribute("aria-pressed", selected ? "true" : "false");
          appendText(button, value, `Analysis ${id}`);
          cell.appendChild(button);
        } else {
          appendText(cell, value, kind === "completeness" ? "unknown" : "—");
        }
        row.appendChild(cell);
      }
      elements.historyBody.appendChild(row);
    }
  }

  function updateHistorySelection() {
    for (const row of elements.historyBody.children) {
      const selected = state.analysis && analysisId(state.analysis) === row.analysisId;
      row.className = selected ? "analysis-selected" : "";
      row.children[0].children[0].setAttribute("aria-pressed", selected ? "true" : "false");
    }
  }

  async function loadAnalyses() {
    state.branch = elements.branch.value;
    hideNotice(elements.scopeError);
    hideResults();
    await loadAnalysisPage(0);
  }

  async function loadAnalysisPage(index, trigger) {
    const pager = state.analysisPages;
    if (!state.project || !state.branch) return;
    const cursor = cursorFor(pager, index);
    if (pager.pending || index < 0 || cursor === undefined || (index > 0 && cursor === null)) return;
    pager.pending = true;
    updatePagination(historyPager, pager);
    setHidden(elements.historyPanel, false);
    setHidden(elements.historyLoading, pager.loaded);
    hideNotice(elements.historyError);
    hideNotice(elements.globalError);
    const query = pageQuery(HISTORY_PAGE_SIZE, cursor);
    query.set("branch", state.branch);
    let firstId;
    try {
      const payload = await apiRequest(`${apiPath(state.project, "/analyses/page")}?${query}`);
      if (pager !== state.analysisPages) return;
      const { items, next } = readPage(payload, "analyses", HISTORY_PAGE_SIZE, cursor);
      acceptPage(pager, index, cursor, next);
      state.analyses = items;
      firstId = analysisId(items[0]);
      if (!firstId) resetAnalysis();
      hideNotice(elements.analysisError);
      renderHistory();
      clear(elements.scopeBadge);
      appendText(elements.scopeBadge, `${state.project} / ${state.branch}`);
    } catch (error) {
      if (pager !== state.analysisPages) return;
      showNotice(elements.historyError, error.message || "Unable to load analysis history.");
      displayError(error);
    } finally {
      if (pager === state.analysisPages) {
        pager.pending = false;
        setHidden(elements.historyLoading, true);
        updatePagination(historyPager, pager, trigger);
      }
    }
    if (firstId && pager === state.analysisPages) await selectAnalysis(firstId);
  }

  function metadataItem(label, value, className = "") {
    const wrapper = document.createElement("div");
    wrapper.className = "metadata-item";
    const term = document.createElement("dt");
    appendText(term, label);
    const description = document.createElement("dd");
    if (className) description.className = className;
    appendText(description, value);
    wrapper.append(term, description);
    return wrapper;
  }

  function renderAnalysisDetail() {
    const analysis = state.analysis;
    if (!analysis) return;
    setHidden(elements.detailPanel, false);
    const completeness = completenessOf(analysis);
    setBadge(elements.detailCompleteness, completeness);
    clear(elements.metadata);
    elements.metadata.append(
      metadataItem("Project", state.project),
      metadataItem("Branch", state.branch),
      metadataItem("Commit", analysisField(analysis, "commit", null), "mono"),
      metadataItem("Analyzed", formatDate(analysisField(analysis, "analyzed_at", null))),
      metadataItem("Analysis id", analysisId(analysis), "mono"),
      metadataItem("Report version", analysisField(analysis, "report_schema_version", null)),
      metadataItem("Completeness", completeness),
    );
    const warnings = Array.isArray(analysis.warnings) ? analysis.warnings : [];
    if (completeness !== "complete") {
      const reason = warnings.length ? ` ${warnings.join(" ")}` : "";
      showNotice(elements.detailWarning, `This analysis is ${completeness}; metrics and findings may be incomplete.${reason}`, "warning");
    } else {
      hideNotice(elements.detailWarning);
    }
    renderMetrics(analysis);
    renderGates(analysis);
  }

  const metricLabels = new Map([
    ["code_lines", "Code lines"], ["comment_lines", "Comment lines"],
    ["files", "Files"], ["lines", "Lines"],
    ["duplication", "Duplication"],
    ["duplication.duplicated_blocks", "Duplicated blocks"],
    ["duplication.duplicated_files", "Duplicated files"],
    ["duplication.duplicated_lines", "Duplicated lines"],
    ["duplication.duplicated_lines_density", "Duplication density"],
  ]);

  function renderMetrics(analysis) {
    clear(elements.metricsGrid);
    const metrics = analysis && analysis.metrics && typeof analysis.metrics === "object"
      ? { ...analysis.metrics }
      : {};
    const duplication = analysis ? analysis.duplication : undefined;
    if (duplication && typeof duplication === "object") {
      for (const [name, value] of Object.entries(duplication)) metrics[`duplication.${name}`] = value;
    } else {
      metrics.duplication = null;
    }
    const entries = Object.entries(metrics);
    setHidden(elements.metricsEmpty, entries.length !== 0);
    for (const [name, raw] of entries) {
      const card = document.createElement("div");
      card.className = "metric-card";
      const metricName = document.createElement("span");
      metricName.className = "metric-name";
      appendText(metricName, metricLabels.get(name) || name);
      const metricValue = document.createElement("span");
      metricValue.className = "metric-value";
      const value = raw && typeof raw === "object" && Object.prototype.hasOwnProperty.call(raw, "value") ? raw.value : raw;
      const formatted = formatNumber(value);
      if (value === null || value === undefined) {
        metricValue.className += " metric-missing";
        appendText(metricValue, "Not measured");
      } else {
        if (name === "duplication.duplicated_lines_density" && formatted !== null) {
          // Native reports store density in percentage units already (0–100).
          appendText(metricValue, `${new Intl.NumberFormat(undefined, {maximumFractionDigits: 2}).format(value)}%`);
        } else {
          appendText(metricValue, formatted === null ? value : formatted);
        }
      }
      card.append(metricName, metricValue);
      elements.metricsGrid.appendChild(card);
    }
  }

  function renderGates(analysis) {
    clear(elements.gatesList);
    const gate = analysis && analysis.gate;
    const conditions = gate && Array.isArray(gate.conditions) ? gate.conditions : [];
    setHidden(elements.gatesEmpty, conditions.length !== 0);
    setBadge(elements.gateSummary, gate ? gate.status : "unavailable");
    for (const condition of conditions) {
      const item = document.createElement("li");
      item.className = "gate-item";
      const copy = document.createElement("div");
      const label = document.createElement("div");
      label.className = "gate-label";
      appendText(label, `${condition.scope || "Gate"}: ${condition.metric || "metric"}`);
      const detail = document.createElement("div");
      detail.className = "gate-detail";
      const actual = condition.actual === null || condition.actual === undefined ? "not measured" : condition.actual;
      const precision = condition.precision === "one_decimal" ? " (rounded to one decimal place)" : "";
      appendText(detail, `${actual}${precision} ${condition.operator || ""} ${condition.threshold === undefined ? "—" : condition.threshold}${condition.diagnostic ? ` — ${condition.diagnostic}` : ""}`);
      copy.append(label, detail);
      const status = document.createElement("span");
      setBadge(status, condition.status || "unavailable");
      item.append(copy, status);
      elements.gatesList.appendChild(item);
    }
  }

  function findingIdentity(finding) {
    return finding && finding.identity;
  }

  function findingKind(finding) {
    return finding && finding.kind === "hotspot" ? "hotspot" : "ordinary";
  }

  function findingReview(finding) {
    return finding && finding.review ? finding.review : null;
  }

  function replaceFindingReview(identity, kind, review) {
    for (const finding of state.findings) {
      if (findingIdentity(finding) === identity && finding && finding.kind === kind) {
        finding.review = review;
      }
    }
  }

  function findingLocation(finding) {
    const range = finding.range;
    const start = range && range.start;
    const end = range && range.end ? range.end : start;
    if (!start) return `${finding.path || "Unknown file"}:?`;
    const startText = `${start.line}:${start.column}`;
    const endText = end ? `${end.line}:${end.column}` : startText;
    return `${finding.path || "Unknown file"}:${startText}${endText === startText ? "" : `–${endText}`}`;
  }

  function renderFindings() {
    clear(elements.findingsList);
    const findings = Array.isArray(state.findings) ? state.findings : [];
    showPageCount(elements.findingsCount, state.findingPages, findings.length, "finding", "findings");
    setHidden(elements.findingsEmpty, findings.length !== 0);
    for (const finding of findings) {
      const identity = findingIdentity(finding);
      if (!identity) continue;
      const kind = findingKind(finding);
      const card = document.createElement("article");
      card.className = `finding-card ${kind}`;
      const copy = document.createElement("div");
      const kindLabel = document.createElement("div");
      kindLabel.className = "finding-kind";
      appendText(kindLabel, kind === "hotspot" ? "Security hotspot" : "Ordinary finding");
      const message = document.createElement("div");
      message.className = "finding-message";
      appendText(message, finding.message, "No message supplied");
      const detail = document.createElement("p");
      detail.className = "finding-detail";
      appendText(detail, `${findingLocation(finding)} · ${finding.rule_key || "Unclassified"} · status: ${finding.status || "unknown"}${finding.ambiguous ? " · identity ambiguous" : ""}`);
      const review = findingReview(finding);
      const reviewStatus = review && review.state;
      if (reviewStatus) {
        const stateText = document.createElement("div");
        stateText.className = "finding-detail";
        appendText(stateText, `Review: ${reviewStatus} (version ${review.version === undefined ? "?" : review.version})`);
        copy.append(kindLabel, message, detail, stateText);
      } else {
        copy.append(kindLabel, message, detail);
      }
      const actions = document.createElement("div");
      actions.className = "finding-actions";
      const button = document.createElement("button");
      button.type = "button";
      button.className = "button button-secondary";
      appendText(button, kind === "hotspot" ? "Review hotspot" : "Review finding");
      button.addEventListener("click", () => selectFinding(finding));
      actions.appendChild(button);
      card.append(copy, actions);
      elements.findingsList.appendChild(card);
    }
  }

  async function fetchFindingPage(id, cursor) {
    const query = pageQuery(FINDINGS_PAGE_SIZE, cursor);
    query.set("include_review_versions", "true");
    const payload = await apiRequest(`${apiPath(state.project, `/analyses/${pathPart(id)}/findings/page`)}?${query}`);
    return readPage(payload, "findings", FINDINGS_PAGE_SIZE, cursor);
  }

  async function loadFindingsPage(index, trigger) {
    const pager = state.findingPages;
    const id = analysisId(state.analysis);
    const cursor = cursorFor(pager, index);
    if (!id || pager.pending || index < 0 || cursor === undefined || (index > 0 && cursor === null)) return;
    pager.pending = true;
    updatePagination(findingsPager, pager);
    setHidden(elements.findingsLoading, pager.loaded);
    hideNotice(elements.globalError);
    hideNotice(elements.findingsError);
    try {
      const { items, next } = await fetchFindingPage(id, cursor);
      if (pager !== state.findingPages) return;
      const retryFocused = document.activeElement === elements.findingsRetry;
      setHidden(elements.findingsRetry, true);
      acceptPage(pager, index, cursor, next);
      state.findings = items;
      clearReviewSelection();
      renderFindings();
      if (retryFocused) elements.findingsCount.focus();
    } catch (error) {
      if (pager !== state.findingPages) return;
      if (!pager.loaded) setHidden(elements.findingsRetry, false);
      showNotice(elements.findingsError, error.message || "Unable to load findings.");
      displayError(error);
    } finally {
      if (pager === state.findingPages) {
        pager.pending = false;
        setHidden(elements.findingsLoading, true);
        updatePagination(findingsPager, pager, trigger);
      }
    }
  }

  async function selectAnalysis(id) {
    resetAnalysis();
    const requestToken = state.analysisRequest;
    updateHistorySelection();
    hideNotice(elements.analysisError);
    if (!id) return;
    hideNotice(elements.globalError);
    try {
      const payload = await apiRequest(`${apiPath(state.project, `/analyses/${pathPart(id)}/overview`)}`);
      if (requestToken !== state.analysisRequest) return;
      if (!payload.analysis || analysisId(payload.analysis) !== id) {
        throw new ApiError(502, "The service returned a different analysis record than requested.");
      }
      state.analysis = payload.analysis;
      updateHistorySelection();
      renderAnalysisDetail();
      if (completenessOf(state.analysis) !== "complete") {
        showNotice(elements.findingsIncomplete, "Findings are shown for an incomplete analysis. Existing reviews are not automatically resolved.", "warning");
      }
      await loadFindingsPage(0);
    } catch (error) {
      if (requestToken !== state.analysisRequest) return;
      showNotice(elements.analysisError, error.message || "Unable to load this analysis.");
      displayError(error);
    }
  }

  function reviewVersion(review) {
    if (!review) return 0;
    return review.version === undefined || review.version === null ? 0 : review.version;
  }
  function formValue(form, name) {
    const control = form.elements.namedItem(name);
    return control ? control.value : "";
  }

  function fillReviewForm(form, finding) {
    const review = findingReview(finding);
    const version = review ? reviewVersion(review) : (finding.review_version ?? 0);
    form.elements.namedItem("identity").value = findingIdentity(finding);
    form.elements.namedItem("expected_version").value = String(version);
    const stateControl = form.elements.namedItem("state");
    const current = review && review.state;
    const validCurrent = current && Array.from(stateControl.options).some((option) => option.value === current);
    stateControl.value = validCurrent ? current : stateControl.options[0].value;
    form.elements.namedItem("reason").value = "";
  }
  function reviewContextCurrent(analysisIdValue, requestToken) {
    return requestToken === state.reviewRequest
      && state.reviewAnalysisId === analysisIdValue
      && state.analysis !== null
      && analysisId(state.analysis) === analysisIdValue;
  }

  async function selectFinding(finding) {
    const identity = findingIdentity(finding);
    const contextId = analysisId(state.analysis);
    if (!identity || !contextId) return;
    clearReviewSelection();
    const requestToken = state.reviewRequest;
    state.reviewAnalysisId = contextId;
    state.selectedFinding = finding;
    const review = findingReview(finding);
    state.selectedReview = review;
    setHidden(elements.reviewPanel, false);
    clear(elements.reviewTarget);
    appendText(elements.reviewTarget, findingKind(finding) === "hotspot" ? "Hotspot" : "Ordinary finding");
    clear(elements.reviewContext);
    appendText(elements.reviewContext, `${findingLocation(finding)} · ${finding.message || "No message supplied"}`);
    hideNotice(elements.reviewMessage);
    hideNotice(elements.reviewError);
    const hotspot = findingKind(finding) === "hotspot";
    setHidden(elements.ordinaryForm, hotspot);
    setHidden(elements.hotspotForm, !hotspot);
    fillReviewForm(hotspot ? elements.hotspotForm : elements.ordinaryForm, finding);
    const form = hotspot ? elements.hotspotForm : elements.ordinaryForm;
    form.elements.namedItem("state").focus();
    elements.reviewPanel.scrollIntoView({ block: "nearest" });
    await loadReviewHistory(requestToken, contextId);
  }

  async function loadReviewHistory(requestToken = state.reviewRequest, contextId = state.reviewAnalysisId) {
    if (!reviewContextCurrent(contextId, requestToken)) return;
    const historyToken = ++state.historyRequest;
    hideNotice(elements.reviewError);
    clear(elements.auditList);
    setHidden(elements.auditEmpty, true);
    if (!state.selectedFinding || !state.project || !state.branch) return;
    const review = findingReview(state.selectedFinding);
    if (!review || !review.id) {
      setHidden(elements.auditEmpty, false);
      return;
    }
    try {
      const payload = await apiRequest(`${apiPath(state.project, `/reviews/${pathPart(review.id)}/history`)}`);
      if (!reviewContextCurrent(contextId, requestToken) || historyToken !== state.historyRequest) return;
      const history = responseList(payload, "history");
      setHidden(elements.auditEmpty, history.length !== 0);
      for (const record of history) {
        const item = document.createElement("li");
        item.className = "audit-item";
        const copy = document.createElement("div");
        const transition = document.createElement("div");
        transition.className = "audit-transition";
        appendText(transition, `${record.previous_state || "—"} → ${record.new_state || "—"}`);
        const detail = document.createElement("p");
        detail.className = "audit-detail";
        appendText(detail, `${record.actor || "Unknown reviewer"} · ${record.reason || "No reason recorded"} · version ${record.version === undefined ? "?" : record.version}`);
        copy.append(transition, detail);
        const timestamp = document.createElement("time");
        timestamp.className = "audit-time";
        if (record.created_at) timestamp.dateTime = record.created_at;
        appendText(timestamp, formatDate(record.created_at));
        item.append(copy, timestamp);
        elements.auditList.appendChild(item);
      }
    } catch (error) {
      if (!reviewContextCurrent(contextId, requestToken) || historyToken !== state.historyRequest) return;
      showNotice(elements.reviewError, error.message || "Unable to load review history.");
      displayError(error);
    }
  }

  async function refreshSelectedReview(contextId, requestToken) {
    if (!reviewContextCurrent(contextId, requestToken)) return;
    const identity = findingIdentity(state.selectedFinding);
    const kind = state.selectedFinding && state.selectedFinding.kind;
    const pager = state.findingPages;
    const { items } = await fetchFindingPage(contextId, pager.cursors[pager.index]);
    if (!reviewContextCurrent(contextId, requestToken)) return;
    const refreshedFinding = items.find(
      (finding) => findingIdentity(finding) === identity && finding && finding.kind === kind,
    );
    if (!refreshedFinding) {
      throw new ApiError(502, "The selected finding is missing from this page. Select it again.");
    }
    state.findings = items;
    state.selectedFinding = refreshedFinding;
    state.selectedReview = findingReview(refreshedFinding);
    renderFindings();
    const form = findingKind(refreshedFinding) === "hotspot" ? elements.hotspotForm : elements.ordinaryForm;
    const reason = formValue(form, "reason");
    fillReviewForm(form, refreshedFinding);
    form.elements.namedItem("reason").value = reason;
  }

  async function submitReview(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const contextId = state.reviewAnalysisId;
    const requestToken = state.reviewRequest;
    if (!state.selectedFinding || !reviewContextCurrent(contextId, requestToken)) {
      showNotice(elements.reviewError, "This review form is no longer bound to the selected analysis. Select the finding again.");
      return;
    }
    if (state.savingReview === requestToken) return;
    if (!form.reportValidity()) return;
    if (!formValue(form, "reason").trim()) {
      showNotice(elements.reviewError, "Enter a reason with at least one non-space character.");
      form.elements.namedItem("reason").focus();
      return;
    }
    hideNotice(elements.reviewError);
    hideNotice(elements.reviewMessage);
    const submittedReason = formValue(form, "reason");
    const body = {
      schema_version: 1,
      analysis_id: contextId,
      identity: formValue(form, "identity"),
      kind: findingKind(state.selectedFinding) === "hotspot" ? "hotspot" : "finding",
      state: formValue(form, "state"),
      reason: formValue(form, "reason").trim(),
      expected_version: Number(formValue(form, "expected_version")),
    };
    state.savingReview = requestToken;
    const saveButton = form === elements.hotspotForm ? elements.hotspotSave : elements.ordinarySave;
    saveButton.disabled = true;
    try {
      const payload = await apiRequest(apiPath(state.project, "/reviews"), {
        method: "POST",
        body: JSON.stringify(body),
      });
      if (!reviewContextCurrent(contextId, requestToken)) return;
      const updated = payload.review;
      if (!updated || updated.identity !== body.identity || updated.kind !== body.kind
          || updated.analysis_id !== contextId || !Number.isSafeInteger(updated.version)
          || updated.version <= body.expected_version) {
        throw new ApiError(502, "The service accepted the request but returned an invalid review record. Refresh the finding before retrying to verify whether it was saved.");
      }
      replaceFindingReview(body.identity, body.kind, updated);
      renderFindings();
      state.selectedReview = findingReview(state.selectedFinding);
      form.elements.namedItem("expected_version").value = String(reviewVersion(state.selectedReview));
      if (formValue(form, "reason") === submittedReason) form.elements.namedItem("reason").value = "";
      showNotice(elements.reviewMessage, "Review saved. The new version and audit entry are immutable records.", "success");
      await loadReviewHistory(requestToken, contextId);
    } catch (error) {
      if (!reviewContextCurrent(contextId, requestToken)) return;
      if (error instanceof ApiError && error.status === 409) {
        try {
          await refreshSelectedReview(contextId, requestToken);
          if (!reviewContextCurrent(contextId, requestToken)) return;
          await loadReviewHistory(requestToken, contextId);
          if (!reviewContextCurrent(contextId, requestToken)) return;
          showNotice(elements.reviewError, "This review changed since it was loaded (version conflict). The current version is loaded; review it and submit again.");
        } catch (refreshError) {
          if (!reviewContextCurrent(contextId, requestToken)) return;
          showNotice(elements.reviewError, `This review changed since it was loaded, and the current version could not be refreshed: ${refreshError.message}`);
        }
      } else {
        showNotice(elements.reviewError, error.message || "Unable to save the review.");
      }
      displayError(error);
    } finally {
      if (state.savingReview === requestToken) {
        state.savingReview = null;
        saveButton.disabled = false;
      }
    }
  }
  function disconnect() {
    state.sessionRequest += 1;
    state.token = null;
    state.projects = [];
    state.branches = [];
    state.project = "";
    state.branch = "";
    elements.token.value = "";
    resetSelect(elements.project, "Connect to load projects");
    resetSelect(elements.branch, "Select a project first");
    setBadge(elements.scopeBadge, "No project selected");
    hideNotice(elements.connectionError);
    hideNotice(elements.scopeError);
    hideNotice(elements.globalError);
    setSession(false);
    hideResults();
  }

  elements.connectionForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const token = elements.token.value.trim();
    if (!token) {
      showNotice(elements.connectionError, "Enter a bearer token to connect.");
      elements.token.focus();
      return;
    }
    state.sessionRequest += 1;
    state.projects = [];
    state.branches = [];
    state.project = "";
    state.branch = "";
    setSession(false);
    resetSelect(elements.project, "Loading projects…");
    elements.project.disabled = true;
    resetSelect(elements.branch, "Select a project first");
    setBadge(elements.scopeBadge, "No project selected");
    hideResults();
    state.token = token;
    elements.disconnect.disabled = false;
    loadProjects();
  });
  elements.disconnect.addEventListener("click", disconnect);
  elements.project.addEventListener("change", loadBranches);
  elements.branch.addEventListener("change", () => {
    state.branch = elements.branch.value;
    setBadge(elements.scopeBadge, state.branch ? `${state.project} / ${state.branch}` : state.project);
    hideResults();
    elements.loadScope.disabled = !elements.project.value || !elements.branch.value;
  });
  elements.scopeForm.addEventListener("submit", (event) => {
    event.preventDefault();
    loadAnalyses();
  });
  historyPager.previous.addEventListener("click", () => loadAnalysisPage(state.analysisPages.index - 1, historyPager.previous));
  historyPager.next.addEventListener("click", () => loadAnalysisPage(state.analysisPages.index + 1, historyPager.next));
  findingsPager.previous.addEventListener("click", () => loadFindingsPage(state.findingPages.index - 1, findingsPager.previous));
  findingsPager.next.addEventListener("click", () => loadFindingsPage(state.findingPages.index + 1, findingsPager.next));
  elements.findingsRetry.addEventListener("click", () => loadFindingsPage(0));
  elements.ordinaryForm.addEventListener("submit", submitReview);
  elements.hotspotForm.addEventListener("submit", submitReview);
  elements.refreshHistory.addEventListener("click", () => loadReviewHistory());

  setSession(false);
})();

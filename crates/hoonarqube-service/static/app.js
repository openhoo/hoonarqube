(() => {
  "use strict";

  const API_PREFIX = "/api/v1";
  const state = {
    token: null,
    projects: [],
    branches: [],
    analyses: [],
    project: "",
    branch: "",
    analysis: null,
    findings: [],
    reviews: [],
    selectedFinding: null,
    selectedReview: null,
    reviewAnalysisId: null,
    analysisRequest: 0,
    reviewRequest: 0,

    busy: 0,
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
  };

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
      return payload || {};
    } finally {
      setBusy(false);
    }
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
    state.selectedFinding = null;
    state.selectedReview = null;
    state.reviewAnalysisId = null;
    setHidden(elements.reviewPanel, true);
    clear(elements.auditList);
    setHidden(elements.auditEmpty, true);
    hideNotice(elements.reviewMessage);
    hideNotice(elements.reviewError);
  }

  function hideResults() {
    state.analysisRequest += 1;
    setHidden(elements.historyPanel, true);
    setHidden(elements.detailPanel, true);
    state.analysis = null;
    state.findings = [];
    state.reviews = [];
    clearReviewSelection();
  }

  async function loadProjects() {
    hideNotice(elements.connectionError);
    hideNotice(elements.globalError);
    try {
      const payload = await apiRequest("/projects");
      fillProjects(payload.projects);
      setSession(true);
      if (!state.projects.length) showNotice(elements.connectionError, "This token can authenticate, but it has no visible projects.", "warning");
    } catch (error) {
      if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
        state.token = null;
        elements.token.value = "";
        fillProjects([]);
        setSession(false);
      }
      showNotice(elements.connectionError, error.message || "Unable to load projects.");
    }
  }

  async function loadBranches() {
    state.project = elements.project.value;
    state.branch = "";
    fillBranches([]);
    hideNotice(elements.scopeError);
    hideResults();
    if (!state.project) {
      elements.scopeBadge.textContent = "No project selected";
      return;
    }
    try {
      const payload = await apiRequest(apiPath(state.project, "/branches"));
      fillBranches(payload.branches);
      setBadge(elements.scopeBadge, state.project, "Project selected");
    } catch (error) {
      showNotice(elements.scopeError, error.message || "Unable to load branches.");
      displayError(error);
    }
  }


  function renderHistory() {
    clear(elements.historyBody);
    hideNotice(elements.historyError);
    const analyses = state.analyses.slice();
    analyses.sort((left, right) => String(analysisField(right, "analyzed_at", "")).localeCompare(String(analysisField(left, "analyzed_at", ""))));
    setHidden(elements.historyPanel, false);
    setHidden(elements.historyEmpty, analyses.length !== 0);
    clear(elements.historyCount);
    appendText(elements.historyCount, `${analyses.length} ${analyses.length === 1 ? "analysis" : "analyses"}`);
    for (const summary of analyses) {
      const id = analysisId(summary);
      if (!id) continue;
      const row = document.createElement("tr");
      row.tabIndex = 0;
      row.setAttribute("role", "button");
      row.setAttribute("aria-selected", state.analysis && analysisId(state.analysis) === id ? "true" : "false");
      row.addEventListener("click", () => selectAnalysis(id));
      row.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          selectAnalysis(id);
        }
      });
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
        appendText(cell, value, kind === "completeness" ? "unknown" : "—");
        row.appendChild(cell);
      }
      elements.historyBody.appendChild(row);
    }
  }

  async function loadAnalyses() {
    state.branch = elements.branch.value;
    hideNotice(elements.scopeError);
    hideNotice(elements.historyError);
    hideResults();
    if (!state.project || !state.branch) return;
    try {
      const payload = await apiRequest(`${apiPath(state.project, "/analyses")}?branch=${encodeURIComponent(state.branch)}`);
      state.analyses = Array.isArray(payload.analyses) ? payload.analyses : [];
      renderHistory();
      clear(elements.scopeBadge);
      appendText(elements.scopeBadge, `${state.project} / ${state.branch}`);
      if (state.analyses.length) await selectAnalysis(analysisId(state.analyses[0]));
    } catch (error) {
      showNotice(elements.historyError, error.message || "Unable to load analysis history.");
      setHidden(elements.historyPanel, false);
      displayError(error);
    }
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
    const report = analysis.report;
    const warnings = report && report.project && Array.isArray(report.project.warnings) ? report.project.warnings : [];
    if (completeness !== "complete") {
      const reason = warnings.length ? ` ${warnings.join(" ")}` : "";
      showNotice(elements.detailWarning, `This analysis is ${completeness}; metrics and findings may be incomplete.${reason}`, "warning");
    } else {
      hideNotice(elements.detailWarning);
    }
    renderMetrics(analysis);
    renderGates(analysis);
  }

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
      appendText(metricName, name);
      const metricValue = document.createElement("span");
      metricValue.className = "metric-value";
      const value = raw && typeof raw === "object" && Object.prototype.hasOwnProperty.call(raw, "value") ? raw.value : raw;
      const formatted = formatNumber(value);
      if (value === null || value === undefined) {
        metricValue.className += " metric-missing";
        appendText(metricValue, "Not measured");
      } else {
        appendText(metricValue, formatted === null ? value : formatted);
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
      appendText(detail, `${actual} ${condition.operator || ""} ${condition.threshold === undefined ? "—" : condition.threshold}${condition.diagnostic ? ` — ${condition.diagnostic}` : ""}`);
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
    clear(elements.findingsCount);
    appendText(elements.findingsCount, `${findings.length} ${findings.length === 1 ? "finding" : "findings"}`);
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

  async function loadFindingsAndReviews(id, requestToken) {
    hideNotice(elements.findingsError);
    hideNotice(elements.findingsIncomplete);
    if (requestToken !== state.analysisRequest) return;
    try {
      const suffix = `/analyses/${pathPart(id)}`;
      const [findingPayload, reviewPayload] = await Promise.all([
        apiRequest(`${apiPath(state.project, `${suffix}/findings`)}`),
        apiRequest(`${apiPath(state.project, "/reviews")}?branch=${encodeURIComponent(state.branch)}`),
      ]);
      if (requestToken !== state.analysisRequest || !state.analysis || analysisId(state.analysis) !== id) return;
      state.findings = Array.isArray(findingPayload.findings) ? findingPayload.findings : [];
      state.reviews = Array.isArray(reviewPayload.reviews) ? reviewPayload.reviews : [];
      if (completenessOf(state.analysis) !== "complete") {
        showNotice(elements.findingsIncomplete, "Findings are shown for an incomplete analysis. Existing reviews are not automatically resolved.", "warning");
      }
      renderFindings();
    } catch (error) {
      if (requestToken !== state.analysisRequest) return;
      state.findings = [];
      state.reviews = [];
      showNotice(elements.findingsError, error.message || "Unable to load findings.");
      displayError(error);
    }
  }

  async function selectAnalysis(id) {
    const requestToken = ++state.analysisRequest;
    clearReviewSelection();
    state.analysis = null;
    state.findings = [];
    state.reviews = [];
    setHidden(elements.detailPanel, true);
    if (!id) return;
    hideNotice(elements.globalError);
    try {
      const payload = await apiRequest(`${apiPath(state.project, `/analyses/${pathPart(id)}`)}`);
      if (requestToken !== state.analysisRequest) return;
      if (!payload.analysis || analysisId(payload.analysis) !== id) {
        throw new ApiError(502, "The service returned a different analysis record than requested.");
      }
      state.analysis = payload.analysis;
      renderHistory();
      renderAnalysisDetail();
      await loadFindingsAndReviews(id, requestToken);
    } catch (error) {
      if (requestToken !== state.analysisRequest) return;
      showNotice(elements.historyError, error.message || "Unable to load this analysis.");
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

  function branchReview(finding) {
    const identity = findingIdentity(finding);
    const kind = finding && finding.kind;
    return state.reviews.find((review) => review.identity === identity && review.kind === kind) || null;
  }

  function fillReviewForm(form, finding, currentReview = findingReview(finding), versionReview = branchReview(finding)) {
    const review = currentReview;
    const reviewForVersion = review || versionReview;
    form.elements.namedItem("identity").value = findingIdentity(finding);
    form.elements.namedItem("expected_version").value = String(reviewVersion(reviewForVersion));
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
    const requestToken = ++state.reviewRequest;
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
    fillReviewForm(hotspot ? elements.hotspotForm : elements.ordinaryForm, finding, review, branchReview(finding));
    await loadReviewHistory(requestToken, contextId);
    if (!reviewContextCurrent(contextId, requestToken)) return;
    elements.reviewPanel.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  async function loadReviewHistory(requestToken = state.reviewRequest, contextId = state.reviewAnalysisId) {
    if (!reviewContextCurrent(contextId, requestToken)) return;
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
      if (!reviewContextCurrent(contextId, requestToken)) return;
      const history = Array.isArray(payload.history) ? payload.history : [];
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
      if (!reviewContextCurrent(contextId, requestToken)) return;
      showNotice(elements.reviewError, error.message || "Unable to load review history.");
      displayError(error);
    }
  }

  async function refreshSelectedReview(contextId, requestToken) {
    if (!reviewContextCurrent(contextId, requestToken)) return;
    const id = analysisId(state.analysis);
    if (!id) return;
    const identity = findingIdentity(state.selectedFinding);
    const kind = state.selectedFinding && state.selectedFinding.kind;
    const [findingPayload, reviewPayload] = await Promise.all([
      apiRequest(`${apiPath(state.project, `/analyses/${pathPart(id)}/findings`)}`),
      apiRequest(`${apiPath(state.project, "/reviews")}?branch=${encodeURIComponent(state.branch)}`),
    ]);
    if (!reviewContextCurrent(contextId, requestToken)) return;
    state.findings = Array.isArray(findingPayload.findings) ? findingPayload.findings : [];
    state.reviews = Array.isArray(reviewPayload.reviews) ? reviewPayload.reviews : [];
    const refreshedFinding = state.findings.find(
      (finding) => findingIdentity(finding) === identity && finding && finding.kind === kind,
    );
    if (refreshedFinding) {
      state.selectedFinding = refreshedFinding;
    } else if (state.selectedFinding) {
      state.selectedFinding.review = null;
    }
    state.selectedReview = findingReview(state.selectedFinding);
    renderFindings();
    if (state.selectedFinding) {
      const form = findingKind(state.selectedFinding) === "hotspot" ? elements.hotspotForm : elements.ordinaryForm;
      fillReviewForm(form, state.selectedFinding, state.selectedReview, branchReview(state.selectedFinding));
    }
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
    if (!form.reportValidity()) return;
    hideNotice(elements.reviewError);
    hideNotice(elements.reviewMessage);
    const body = {
      schema_version: 1,
      analysis_id: contextId,
      identity: formValue(form, "identity"),
      kind: findingKind(state.selectedFinding) === "hotspot" ? "hotspot" : "finding",
      state: formValue(form, "state"),
      reason: formValue(form, "reason").trim(),
      expected_version: Number(formValue(form, "expected_version")),
    };
    try {
      const payload = await apiRequest(apiPath(state.project, "/reviews"), {
        method: "POST",
        body: JSON.stringify(body),
      });
      if (!reviewContextCurrent(contextId, requestToken)) return;
      const updated = payload.review;
      const updatedReview = updated && typeof updated === "object" ? updated : null;
      state.reviews = state.reviews.filter((review) => !(review.identity === body.identity && review.kind === body.kind));
      if (updatedReview) state.reviews.push(updatedReview);
      replaceFindingReview(body.identity, body.kind, updatedReview);
      renderFindings();
      state.selectedReview = findingReview(state.selectedFinding);
      form.elements.namedItem("expected_version").value = String(reviewVersion(state.selectedReview));
      form.elements.namedItem("reason").value = "";
      showNotice(elements.reviewMessage, "Review saved. The new version and audit entry are immutable records.", "success");
      await loadReviewHistory(requestToken, contextId);
    } catch (error) {
      if (!reviewContextCurrent(contextId, requestToken)) return;
      if (error instanceof ApiError && error.status === 409) {
        try {
          await refreshSelectedReview(contextId, requestToken);
          if (!reviewContextCurrent(contextId, requestToken)) return;
          await loadReviewHistory(requestToken, contextId);
          showNotice(elements.reviewError, "This review changed since it was loaded (version conflict). The current version is loaded; review it and submit again.");
        } catch (refreshError) {
          if (!reviewContextCurrent(contextId, requestToken)) return;
          showNotice(elements.reviewError, `This review changed since it was loaded, and the current version could not be refreshed: ${refreshError.message}`);
        }
      } else {
        showNotice(elements.reviewError, error.message || "Unable to save the review.");
      }
      displayError(error);
    }
  }
  function disconnect() {
    state.token = null;
    state.projects = [];
    state.branches = [];
    state.project = "";
    state.branch = "";
    elements.token.value = "";
    resetSelect(elements.project, "Connect to load projects");
    resetSelect(elements.branch, "Select a project first");
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
    state.project = "";
    state.branch = "";
    resetSelect(elements.project, "Loading projects…");
    elements.project.disabled = true;
    resetSelect(elements.branch, "Select a project first");
    setBadge(elements.scopeBadge, "No project selected");
    hideResults();
    state.token = token;
    loadProjects();
  });
  elements.disconnect.addEventListener("click", disconnect);
  elements.project.addEventListener("change", loadBranches);
  elements.branch.addEventListener("change", () => {
    state.branch = elements.branch.value;
    hideResults();
    elements.loadScope.disabled = !elements.project.value || !elements.branch.value;
  });
  elements.scopeForm.addEventListener("submit", (event) => {
    event.preventDefault();
    loadAnalyses();
  });
  elements.ordinaryForm.addEventListener("submit", submitReview);
  elements.hotspotForm.addEventListener("submit", submitReview);
  elements.refreshHistory.addEventListener("click", () => loadReviewHistory());

  setSession(false);
})();

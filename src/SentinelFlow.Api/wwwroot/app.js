"use strict";

const state = { view: "overview", summary: null, projects: [], runs: [], findings: [], policies: [], exceptions: [] };
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const elements = {
  title: $("#page-title"), metrics: $("#metrics"), trend: $("#trend-chart"), severity: $("#severity-chart"),
  recentRuns: $("#recent-runs"), priority: $("#priority-findings"), runsTable: $("#runs-table"),
  findingsTable: $("#findings-table"), policies: $("#policies-list"), exceptions: $("#exceptions-list"),
  projectFilter: $("#run-project-filter"), severityFilter: $("#severity-filter"), statusFilter: $("#status-filter"),
  drawer: $("#drawer"), drawerTitle: $("#drawer-title"), drawerEyebrow: $("#drawer-eyebrow"),
  drawerBody: $("#drawer-body"), scrim: $("#scrim"), toast: $("#toast")
};
const date = new Intl.DateTimeFormat("en-US", { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
const titles = { overview: "Security overview", pipelines: "Pipeline runs", findings: "Finding backlog", policies: "Security policies", exceptions: "Risk exceptions" };
const allowedStates = new Set(["critical", "high", "medium", "low", "info", "open", "in_progress", "accepted", "resolved", "false_positive", "passed", "blocked", "pending", "approved", "rejected", "review"]);

function safeDate(value) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "Unavailable" : date.format(parsed);
}
function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = String(text);
  return element;
}
function badge(value) {
  const normalized = allowedStates.has(value) ? value : "unknown";
  return node("span", `badge badge-${normalized}`, String(normalized).replace("_", " "));
}
function appendCell(row, content, className) {
  const cell = node("div", className || "");
  if (content instanceof Node) cell.appendChild(content); else cell.textContent = String(content ?? "-");
  row.appendChild(cell);
  return cell;
}
function mainCell(title, subtitle) {
  const cell = node("div", "cell-main");
  cell.append(node("strong", "", title), node("small", "", subtitle));
  return cell;
}
function scaleClass(value, maximum) {
  const safeValue = Math.max(0, Number(value) || 0);
  const safeMax = Math.max(1, Number(maximum) || 1);
  return `scale-${Math.max(1, Math.min(10, Math.ceil((safeValue / safeMax) * 10)))}`;
}

async function api(path) {
  const response = await fetch(`/api${path}`, { headers: { Accept: "application/json" } });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error("Request unavailable.");
  return payload;
}

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.classList.remove("hidden");
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => elements.toast.classList.add("hidden"), 3000);
}
function openDrawer(eyebrow, title) {
  elements.drawerEyebrow.textContent = eyebrow;
  elements.drawerTitle.textContent = title;
  elements.drawerBody.replaceChildren();
  elements.drawer.classList.remove("hidden");
  elements.scrim.classList.remove("hidden");
}
function closeDrawer() { elements.drawer.classList.add("hidden"); elements.scrim.classList.add("hidden"); }

function renderMetrics() {
  const items = [
    ["Protected projects", state.summary.projects, "Synthetic repositories", ""],
    ["Open findings", state.summary.openFindings, `${state.summary.overdueFindings} overdue SLA`, ""],
    ["Critical exposure", state.summary.criticalFindings, "Requires immediate action", "alert"],
    ["Blocked runs", state.summary.blockedRuns, "Current policy evaluation", "alert"],
    ["Scanner coverage", `${state.summary.coverage}%`, "Successful security jobs", "good"]
  ];
  elements.metrics.replaceChildren();
  for (const [label, value, note, tone] of items) {
    const card = node("article", `metric ${tone}`.trim());
    card.append(node("span", "", label), node("strong", "", value), node("small", "", note));
    elements.metrics.appendChild(card);
  }
}

function renderCharts() {
  const trend = Array.isArray(state.summary.trend) ? state.summary.trend : [];
  const maxTrend = Math.max(...trend.flatMap((item) => [Number(item.opened) || 0, Number(item.resolved) || 0]), 1);
  elements.trend.replaceChildren();
  for (const item of trend.slice(0, 12)) {
    const group = node("div", "trend-group");
    const opened = node("div", `bar bar-opened ${scaleClass(item.opened, maxTrend)}`);
    const resolved = node("div", `bar bar-resolved ${scaleClass(item.resolved, maxTrend)}`);
    opened.title = `${Number(item.opened) || 0} opened`;
    resolved.title = `${Number(item.resolved) || 0} resolved`;
    group.append(opened, resolved, node("span", "trend-label", String(item.label ?? "-").slice(0, 20)));
    elements.trend.appendChild(group);
  }
  const severity = Array.isArray(state.summary.severity) ? state.summary.severity : [];
  const maxSeverity = Math.max(...severity.map((item) => Number(item.count) || 0), 1);
  elements.severity.replaceChildren();
  for (const item of severity.slice(0, 5)) {
    const row = node("div", "severity-row");
    const track = node("div", "severity-track");
    const level = allowedStates.has(item.severity) ? item.severity : "info";
    track.appendChild(node("div", `severity-fill severity-${level} ${scaleClass(item.count, maxSeverity)}`));
    row.append(node("span", "", level), track, node("strong", "", Number(item.count) || 0));
    elements.severity.appendChild(row);
  }
}

function runRow(run, compact = false) {
  const row = node("div", compact ? "compact-row" : "table-row run-row");
  const project = mainCell(String(run.projectLabel ?? "Project").slice(0, 40), `${String(run.id ?? "run").slice(-18)} · ${safeDate(run.createdAt)}`);
  if (compact) {
    row.append(project, mainCell("Metadata redacted", `${Number(run.durationSeconds) || 0}s`), badge(run.decision?.decision));
  } else {
    const passed = (run.scanners || []).filter((item) => item.status === "passed").length;
    row.append(project, node("span", "", "Branch and commit redacted"), node("span", "", `${passed}/${(run.scanners || []).length} gates`),
      node("strong", "", Number(run.decision?.riskScore) || 0), badge(run.decision?.decision));
  }
  const button = node("button", "row-button", compact ? "Inspect" : "Open");
  button.type = "button"; button.dataset.runId = String(run.id ?? "").slice(0, 120); row.appendChild(button);
  return row;
}

function findingLabel(finding) { return `Finding ${String(finding.id ?? "").slice(-12)}`; }
function renderOverviewLists() {
  elements.recentRuns.replaceChildren(...state.runs.slice(0, 4).map((run) => runRow(run, true)));
  const ordered = [...state.findings].filter((item) => item.status !== "resolved")
    .sort((a, b) => ["critical", "high", "medium", "low"].indexOf(a.severity) - ["critical", "high", "medium", "low"].indexOf(b.severity)).slice(0, 5);
  elements.priority.replaceChildren();
  for (const finding of ordered) {
    const button = node("button", "priority-item row-button");
    button.type = "button"; button.dataset.findingId = String(finding.id ?? "").slice(0, 120);
    const dot = node("span", "priority-dot"); if (allowedStates.has(finding.severity)) dot.classList.add(`severity-${finding.severity}`);
    const detail = document.createElement("span"); detail.append(node("strong", "", findingLabel(finding)), node("p", "", `${String(finding.projectLabel ?? "Project").slice(0, 40)} · ownership redacted`));
    button.append(dot, detail); elements.priority.appendChild(button);
  }
}

function renderRuns() {
  const filter = elements.projectFilter.value;
  const runs = state.runs.filter((run) => !filter || run.projectId === filter);
  const head = node("div", "table-row table-head run-row");
  for (const value of ["Project / run", "Source metadata", "Coverage", "Risk score", "Decision", ""]) head.appendChild(node("span", "", value));
  elements.runsTable.replaceChildren(head, ...runs.slice(0, 500).map((run) => runRow(run)));
}

function findingRow(finding) {
  const row = node("div", "table-row finding-row");
  row.append(mainCell(findingLabel(finding), `${String(finding.scanner ?? "scanner").slice(0, 32)} · ${String(finding.category ?? "unknown").slice(0, 32)}`),
    badge(finding.severity), badge(finding.status), node("span", "", String(finding.projectLabel ?? "Project").slice(0, 40)),
    mainCell("Ownership redacted", `Due ${safeDate(finding.slaDueAt)}`));
  const button = node("button", "row-button", "Open"); button.type = "button"; button.dataset.findingId = String(finding.id ?? "").slice(0, 120); row.appendChild(button);
  return row;
}
function renderFindings() {
  const severity = elements.severityFilter.value; const status = elements.statusFilter.value;
  const findings = state.findings.filter((item) => (!severity || item.severity === severity) && (!status || item.status === status));
  const head = node("div", "table-row table-head finding-row");
  for (const value of ["Finding", "Severity", "Status", "Project", "Owner / SLA", ""]) head.appendChild(node("span", "", value));
  elements.findingsTable.replaceChildren(head, ...findings.slice(0, 1000).map(findingRow));
}

function renderPolicies() {
  elements.policies.replaceChildren();
  for (const policy of state.policies.slice(0, 100)) {
    const card = node("article", "policy-card");
    const detail = document.createElement("div");
    detail.append(node("h3", "", String(policy.name ?? "Policy").slice(0, 120)), node("p", "", String(policy.description ?? "").slice(0, 240)));
    const scanners = node("div", "scanner-list");
    for (const scanner of (policy.requiredScanners || []).slice(0, 20)) scanners.appendChild(node("span", "scanner-chip", String(scanner).slice(0, 32)));
    detail.appendChild(scanners);
    const thresholds = node("div", "policy-thresholds");
    for (const key of ["critical", "high", "secrets"]) thresholds.appendChild(mainCell(`Maximum ${key}`, Number(policy.thresholds?.[key]) || 0));
    card.append(detail, thresholds); elements.policies.appendChild(card);
  }
}

function renderExceptions() {
  elements.exceptions.replaceChildren();
  if (!state.exceptions.length) { elements.exceptions.appendChild(node("div", "empty-state", "No risk exceptions.")); return; }
  for (const exception of state.exceptions.slice(0, 500)) {
    const card = node("article", "exception-card");
    const detail = document.createElement("div");
    detail.append(node("h3", "", `Exception ${String(exception.id ?? "").slice(-12)}`), node("p", "", "Reason and compensating control redacted from the frontend."));
    const meta = node("div", "exception-meta");
    meta.append(node("span", "", String(exception.projectLabel ?? "Project").slice(0, 40)), node("span", "", `Expires ${safeDate(exception.expiresAt)}`));
    const actions = node("div", "exception-actions"); actions.appendChild(badge(exception.status));
    card.append(detail, meta, actions); elements.exceptions.appendChild(card);
  }
}

function renderAll() { renderMetrics(); renderCharts(); renderOverviewLists(); renderRuns(); renderFindings(); renderPolicies(); renderExceptions(); }
async function load() {
  const [summary, projects, runs, findings, policies, exceptions] = await Promise.all([api("/summary"), api("/projects"), api("/runs"), api("/findings"), api("/policies"), api("/exceptions")]);
  state.summary = summary;
  state.projects = Array.isArray(projects.projects) ? projects.projects : [];
  state.runs = Array.isArray(runs.runs) ? runs.runs : [];
  state.findings = Array.isArray(findings.findings) ? findings.findings : [];
  state.policies = Array.isArray(policies.policies) ? policies.policies : [];
  state.exceptions = Array.isArray(exceptions.exceptions) ? exceptions.exceptions : [];
  for (const item of state.projects) {
    const option = node("option", "", String(item.label ?? "Project").slice(0, 40));
    option.value = String(item.id ?? "").slice(0, 120); elements.projectFilter.appendChild(option);
  }
  renderAll();
}

function switchView(view) {
  state.view = view;
  $$(".view").forEach((section) => section.classList.add("hidden"));
  $(`#view-${view}`).classList.remove("hidden");
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === view));
  elements.title.textContent = titles[view];
}

function detailSection(title) { const section = node("section", "detail-section"); section.appendChild(node("h3", "", title)); return section; }
function detailGrid(entries) {
  const grid = node("div", "detail-grid");
  for (const [label, value] of entries) { const field = node("div", "detail-field"); field.append(node("span", "", label), node("strong", "", value)); grid.appendChild(field); }
  return grid;
}
function runDetail(runId) {
  const run = state.runs.find((item) => item.id === runId); if (!run) return;
  openDrawer("Pipeline execution", `${String(run.projectLabel ?? "Project").slice(0, 40)} · ${String(run.id).slice(-18)}`);
  const summary = detailSection("Projected metadata");
  summary.appendChild(detailGrid([["Source", "Branch, commit and author redacted"], ["Duration", `${Number(run.durationSeconds) || 0}s`], ["Risk", Number(run.decision?.riskScore) || 0], ["Decision", String(run.decision?.decision ?? "unknown")]]));
  elements.drawerBody.appendChild(summary);
  const gates = detailSection("Security gates");
  for (const scanner of (run.scanners || []).slice(0, 20)) {
    const row = node("div", "gate-row"); row.append(node("strong", "", String(scanner.type ?? "scanner").toUpperCase().slice(0, 32)), badge(scanner.status), node("span", "", `${Number(scanner.findings) || 0} findings`), node("small", "", `${Number(scanner.durationSeconds) || 0}s`)); gates.appendChild(row);
  }
  elements.drawerBody.appendChild(gates);
  const policy = detailSection("Policy decision");
  const violations = Array.isArray(run.decision?.violations) ? run.decision.violations : [];
  if (!violations.length) policy.appendChild(node("p", "", "All configured policy gates passed."));
  else { const list = node("ul", "violation-list"); for (const violation of violations.slice(0, 30)) list.appendChild(node("li", "", String(violation).slice(0, 240))); policy.appendChild(list); }
  elements.drawerBody.appendChild(policy);
}
function findingDetail(findingId) {
  const finding = state.findings.find((item) => item.id === findingId); if (!finding) return;
  openDrawer("Finding detail", findingLabel(finding));
  const section = detailSection("Projected classification");
  section.appendChild(detailGrid([["Severity", String(finding.severity)], ["Status", String(finding.status).replace("_", " ")], ["Scanner", String(finding.scanner)], ["Category", String(finding.category)], ["Project", String(finding.projectLabel)], ["SLA due", safeDate(finding.slaDueAt)]]));
  section.appendChild(node("p", "", "Title, source location, repository metadata and ownership are redacted from the frontend."));
  elements.drawerBody.appendChild(section);
}

document.addEventListener("click", (event) => {
  const nav = event.target.closest("[data-view]"); if (nav) { switchView(nav.dataset.view); return; }
  const viewButton = event.target.closest("[data-open-view]"); if (viewButton) { switchView(viewButton.dataset.openView); return; }
  const runButton = event.target.closest("[data-run-id]"); if (runButton) { runDetail(runButton.dataset.runId); return; }
  const findingButton = event.target.closest("[data-finding-id]"); if (findingButton) { findingDetail(findingButton.dataset.findingId); return; }
});
elements.projectFilter.addEventListener("change", renderRuns);
elements.severityFilter.addEventListener("change", renderFindings);
elements.statusFilter.addEventListener("change", renderFindings);
$("#drawer-close").addEventListener("click", closeDrawer);
elements.scrim.addEventListener("click", closeDrawer);

load().catch(() => showToast("Unable to load projected security data."));

const state = { role: "security", view: "overview", summary: null, projects: [], runs: [], findings: [], policies: [], exceptions: [] };
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);
const elements = {
  title: $("#page-title"), metrics: $("#metrics"), trend: $("#trend-chart"), severity: $("#severity-chart"), recentRuns: $("#recent-runs"), priority: $("#priority-findings"),
  runsTable: $("#runs-table"), findingsTable: $("#findings-table"), policies: $("#policies-list"), exceptions: $("#exceptions-list"),
  role: $("#role-select"), projectFilter: $("#run-project-filter"), severityFilter: $("#severity-filter"), statusFilter: $("#status-filter"),
  drawer: $("#drawer"), drawerTitle: $("#drawer-title"), drawerEyebrow: $("#drawer-eyebrow"), drawerBody: $("#drawer-body"), scrim: $("#scrim"), toast: $("#toast"),
  ingestDialog: $("#ingest-dialog"), ingestProject: $("#ingest-project"), ingestTool: $("#ingest-tool"), ingestReport: $("#ingest-report"), ingestMessage: $("#ingest-message"),
  exceptionDialog: $("#exception-dialog"), exceptionFinding: $("#exception-finding"), exceptionMessage: $("#exception-message")
};

const date = new Intl.DateTimeFormat("en-US", { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
const titles = { overview: "Security overview", pipelines: "Pipeline runs", findings: "Finding backlog", policies: "Security policies", exceptions: "Risk exceptions" };
const e = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" })[character]);
const scaleClass = (value, maximum) => `scale-${Math.max(1, Math.min(10, Math.ceil((value / maximum) * 10)))}`;

async function api(path, options = {}) {
  const response = await fetch(`/api${path}`, { ...options, headers: { "Content-Type": "application/json", "X-Demo-Role": state.role, ...(options.headers || {}) } });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || "Request failed.");
  return payload;
}

function showToast(message) { elements.toast.textContent = message; elements.toast.classList.remove("hidden"); clearTimeout(showToast.timer); showToast.timer = setTimeout(() => elements.toast.classList.add("hidden"), 3000); }
function project(id) { return state.projects.find((item) => item.id === id); }
function badge(value) { return `<span class="badge badge-${e(value)}">${e(String(value).replace("_", " "))}</span>`; }
function openDrawer(eyebrow, title, html) { elements.drawerEyebrow.textContent = eyebrow; elements.drawerTitle.textContent = title; elements.drawerBody.innerHTML = html; elements.drawer.classList.remove("hidden"); elements.scrim.classList.remove("hidden"); }
function closeDrawer() { elements.drawer.classList.add("hidden"); elements.scrim.classList.add("hidden"); }

function renderMetrics() {
  const items = [
    ["Protected projects", state.summary.projects, "Repositories onboarded", ""],
    ["Open findings", state.summary.openFindings, `${state.summary.overdueFindings} overdue SLA`, ""],
    ["Critical exposure", state.summary.criticalFindings, "Requires immediate action", "alert"],
    ["Blocked runs", state.summary.blockedRuns, "Current policy evaluation", "alert"],
    ["Scanner coverage", `${state.summary.coverage}%`, "Successful security jobs", "good"]
  ];
  elements.metrics.innerHTML = items.map(([label, value, note, cls]) => `<article class="metric ${cls}"><span>${label}</span><strong>${value}</strong><small>${note}</small></article>`).join("");
}

function renderCharts() {
  const maxTrend = Math.max(...state.summary.trend.flatMap((item) => [item.opened, item.resolved]), 1);
  elements.trend.innerHTML = state.summary.trend.map((item) => `<div class="trend-group"><div class="bar bar-opened ${scaleClass(item.opened, maxTrend)}" title="${item.opened} opened"></div><div class="bar bar-resolved ${scaleClass(item.resolved, maxTrend)}" title="${item.resolved} resolved"></div><span class="trend-label">${e(item.label)}</span></div>`).join("");
  const maxSeverity = Math.max(...state.summary.severity.map((item) => item.count), 1);
  elements.severity.innerHTML = state.summary.severity.map((item) => `<div class="severity-row"><span>${e(item.severity)}</span><div class="severity-track"><div class="severity-fill severity-${e(item.severity)} ${scaleClass(item.count, maxSeverity)}"></div></div><strong>${item.count}</strong></div>`).join("");
}

function renderOverviewLists() {
  elements.recentRuns.innerHTML = state.runs.slice(0, 4).map((run) => `<div class="compact-row"><div><strong>${e(run.project.name)}</strong><small>${e(run.branch)} · ${e(run.commit)}</small></div><div><strong>${e(run.author)}</strong><small>${e(date.format(new Date(run.createdAt)))}</small></div>${badge(run.decision.decision)}<button class="row-button" data-run-id="${e(run.id)}" type="button">Inspect</button></div>`).join("");
  const ordered = [...state.findings].filter((item) => item.status !== "resolved").sort((a, b) => ["critical","high","medium","low"].indexOf(a.severity) - ["critical","high","medium","low"].indexOf(b.severity)).slice(0, 5);
  elements.priority.innerHTML = ordered.map((finding) => `<button class="priority-item row-button" data-finding-id="${e(finding.id)}" type="button"><span class="priority-dot severity-${e(finding.severity)}"></span><span><strong>${e(finding.title)}</strong><p>${e(project(finding.projectId).name)} · ${e(finding.owner)}</p></span></button>`).join("");
}

function renderRuns() {
  const filter = elements.projectFilter.value;
  const runs = state.runs.filter((run) => !filter || run.projectId === filter);
  elements.runsTable.innerHTML = `<div class="table-row table-head run-row"><span>Project / run</span><span>Branch</span><span>Coverage</span><span>Risk score</span><span>Decision</span><span></span></div>` + runs.map((run) => `<div class="table-row run-row"><div class="cell-main"><strong>${e(run.project.name)}</strong><small>${e(run.id)} · ${e(date.format(new Date(run.createdAt)))}</small></div><div class="cell-main"><strong>${e(run.branch)}</strong><small>${e(run.commit)} · ${e(run.author)}</small></div><span>${run.scanners.filter((item) => item.status === "passed").length}/${run.scanners.length} gates</span><strong>${run.decision.riskScore}</strong>${badge(run.decision.decision)}<button class="row-button" data-run-id="${e(run.id)}" type="button">Open</button></div>`).join("");
}

function renderFindings() {
  const severity = elements.severityFilter.value; const status = elements.statusFilter.value;
  const findings = state.findings.filter((finding) => (!severity || finding.severity === severity) && (!status || finding.status === status));
  elements.findingsTable.innerHTML = `<div class="table-row table-head finding-row"><span>Finding</span><span>Severity</span><span>Status</span><span>Project</span><span>Owner / SLA</span><span></span></div>` + findings.map((finding) => `<div class="table-row finding-row"><div class="cell-main"><strong>${e(finding.title)}</strong><small>${e(finding.scanner.toUpperCase())} · ${e(finding.ruleId)}</small></div>${badge(finding.severity)}${badge(finding.status)}<span>${e(project(finding.projectId).name)}</span><div class="cell-main"><strong>${e(finding.owner)}</strong><small>Due ${e(date.format(new Date(finding.slaDueAt)))}</small></div><button class="row-button" data-finding-id="${e(finding.id)}" type="button">Open</button></div>`).join("");
}

function renderPolicies() {
  elements.policies.innerHTML = state.policies.map((policy) => `<article class="policy-card"><div><h3>${e(policy.name)}</h3><p>${e(policy.description)}</p><div class="scanner-list">${policy.requiredScanners.map((scanner) => `<span class="scanner-chip">${e(scanner)}</span>`).join("")}</div></div><form class="policy-form" data-policy-id="${e(policy.id)}"><div class="policy-thresholds"><div class="threshold"><label>Maximum critical<input name="critical" type="number" min="0" value="${Number(policy.thresholds.critical)}"></label></div><div class="threshold"><label>Maximum high<input name="high" type="number" min="0" value="${Number(policy.thresholds.high)}"></label></div><div class="threshold"><label>Maximum secrets<input name="secrets" type="number" min="0" value="${Number(policy.thresholds.secrets)}"></label></div></div><div class="policy-actions"><button class="button button-primary" type="submit">Save policy</button></div></form></article>`).join("");
}

function renderExceptions() {
  elements.exceptions.innerHTML = state.exceptions.length ? state.exceptions.map((exception) => { const finding = state.findings.find((item) => item.id === exception.findingId); return `<article class="exception-card"><div><h3>${e(finding?.title || exception.findingId)}</h3><p>${e(exception.reason)}</p></div><div class="exception-meta"><span>Control: ${e(exception.compensatingControl)}</span><span>Requested by ${e(exception.requestedBy)} · expires ${e(date.format(new Date(exception.expiresAt)))}</span></div><div class="exception-actions">${badge(exception.status)}${exception.status === "pending" ? `<button class="button button-primary" data-exception-action="approve" data-exception-id="${e(exception.id)}" type="button">Approve</button><button class="button button-secondary" data-exception-action="reject" data-exception-id="${e(exception.id)}" type="button">Reject</button>` : ""}</div></article>`; }).join("") : '<div class="empty-state">No risk exceptions.</div>';
}

function renderFindingOptions() {
  elements.exceptionFinding.innerHTML = state.findings
    .filter((item) => item.status !== "resolved")
    .map((item) => `<option value="${e(item.id)}">${e(item.title)}</option>`)
    .join("");
}

function renderAll() { renderMetrics(); renderCharts(); renderOverviewLists(); renderRuns(); renderFindings(); renderPolicies(); renderExceptions(); renderFindingOptions(); }

async function load() {
  const [summary, projects, runs, findings, policies, exceptions] = await Promise.all([api("/summary"), api("/projects"), api("/runs"), api("/findings"), api("/policies"), api("/exceptions")]);
  state.summary = summary; state.projects = projects.projects; state.runs = runs.runs; state.findings = findings.findings; state.policies = policies.policies; state.exceptions = exceptions.exceptions;
  const projectOptions = state.projects.map((item) => `<option value="${e(item.id)}">${e(item.name)}</option>`).join("");
  elements.projectFilter.insertAdjacentHTML("beforeend", projectOptions); elements.ingestProject.innerHTML = projectOptions;
  renderAll();
}

function switchView(view) { state.view = view; $$(".view").forEach((section) => section.classList.add("hidden")); $(`#view-${view}`).classList.remove("hidden"); $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === view)); elements.title.textContent = titles[view]; }

function runDetail(runId) {
  const run = state.runs.find((item) => item.id === runId); if (!run) return;
  const violations = run.decision.violations.length ? `<ul class="violation-list">${run.decision.violations.map((item) => `<li>${e(item)}</li>`).join("")}</ul>` : `<p>All configured policy gates passed.</p>`;
  openDrawer("Pipeline execution", `${run.project.name} · ${run.id}`, `<section class="detail-section"><div class="detail-grid"><div class="detail-field"><span>Branch</span><strong>${e(run.branch)}</strong></div><div class="detail-field"><span>Commit</span><strong>${e(run.commit)}</strong></div><div class="detail-field"><span>Author</span><strong>${e(run.author)}</strong></div><div class="detail-field"><span>Duration</span><strong>${Number(run.durationSeconds)}s</strong></div></div></section><section class="detail-section"><h3>Security gates</h3>${run.scanners.map((scanner) => `<div class="gate-row"><strong>${e(scanner.type.toUpperCase())}</strong>${badge(scanner.status)}<span>${Number(scanner.findings)} findings</span><small>${Number(scanner.durationSeconds)}s</small></div>`).join("")}</section><section class="detail-section"><h3>Policy decision ${badge(run.decision.decision)}</h3>${violations}</section>`);
}

function findingDetail(findingId) {
  const finding = state.findings.find((item) => item.id === findingId); if (!finding) return;
  openDrawer("Security finding", finding.title, `<div class="finding-detail"><section class="detail-section"><div class="detail-grid"><div class="detail-field"><span>Severity</span><strong>${e(finding.severity)}</strong></div><div class="detail-field"><span>Scanner</span><strong>${e(finding.scanner)}</strong></div><div class="detail-field"><span>Rule</span><strong>${e(finding.ruleId)}</strong></div><div class="detail-field"><span>Location</span><strong>${e(finding.file)}:${Number(finding.line)}</strong></div></div></section><section class="detail-section"><h3>Description</h3><p>${e(finding.description)}</p><h3>Remediation</h3><p>${e(finding.remediation)}</p></section><form class="detail-form" id="finding-update-form"><label>Status<select name="status"><option value="open">Open</option><option value="in_progress">In progress</option><option value="resolved">Resolved</option><option value="accepted">Accepted</option><option value="false_positive">False positive</option></select></label><label>Owner<input name="owner" value="${e(finding.owner)}"></label><button class="button button-primary" type="submit">Update finding</button></form></div>`);
  const form = $("#finding-update-form"); form.status.value = finding.status;
  form.addEventListener("submit", async (event) => { event.preventDefault(); const data = new FormData(form); try { await api(`/findings/${finding.id}`, { method: "PATCH", body: JSON.stringify({ status: data.get("status"), owner: data.get("owner") }) }); await refresh(); closeDrawer(); showToast("Finding updated."); } catch (error) { showToast(error.message); } });
}

async function refresh() { const [summary, runs, findings, policies, exceptions] = await Promise.all([api("/summary"), api("/runs"), api("/findings"), api("/policies"), api("/exceptions")]); state.summary = summary; state.runs = runs.runs; state.findings = findings.findings; state.policies = policies.policies; state.exceptions = exceptions.exceptions; renderAll(); }

document.addEventListener("click", async (event) => {
  const viewButton = event.target.closest("[data-view], [data-open-view]"); if (viewButton) switchView(viewButton.dataset.view || viewButton.dataset.openView);
  const runButton = event.target.closest("[data-run-id]"); if (runButton) runDetail(runButton.dataset.runId);
  const findingButton = event.target.closest("[data-finding-id]"); if (findingButton) findingDetail(findingButton.dataset.findingId);
  const exceptionButton = event.target.closest("[data-exception-action]");
  if (exceptionButton) { try { await api(`/exceptions/${exceptionButton.dataset.exceptionId}`, { method: "PATCH", body: JSON.stringify({ status: exceptionButton.dataset.exceptionAction === "approve" ? "approved" : "rejected", approvedBy: "Security engineer" }) }); await refresh(); showToast("Exception reviewed."); } catch (error) { showToast(error.message); } }
});

elements.role.addEventListener("change", () => { state.role = elements.role.value; showToast(`Role changed to ${elements.role.selectedOptions[0].textContent}.`); });
elements.projectFilter.addEventListener("change", renderRuns); elements.severityFilter.addEventListener("change", renderFindings); elements.statusFilter.addEventListener("change", renderFindings);
$("#drawer-close").addEventListener("click", closeDrawer); elements.scrim.addEventListener("click", closeDrawer);
$("#ingest-button").addEventListener("click", () => { elements.ingestReport.value = JSON.stringify({ results: [{ check_id: "javascript.security.demo-rule", path: "src/demo.js", start: { line: 24 }, extra: { severity: "WARNING", message: "Untrusted input reaches a sensitive operation." } }] }, null, 2); elements.ingestMessage.textContent = ""; elements.ingestDialog.showModal(); });
$("#request-exception-button").addEventListener("click", () => { const expiry = new Date(); expiry.setDate(expiry.getDate() + 14); $("#exception-expiration").value = expiry.toISOString().slice(0,10); elements.exceptionMessage.textContent = ""; elements.exceptionDialog.showModal(); });

$("#ingest-form").addEventListener("submit", async (event) => { event.preventDefault(); try { const report = JSON.parse(elements.ingestReport.value); const result = await api("/ingest", { method: "POST", body: JSON.stringify({ projectId: elements.ingestProject.value, tool: elements.ingestTool.value, report }) }); elements.ingestDialog.close(); await refresh(); showToast(`${result.imported} finding(s) imported; run ${result.run.decision.decision}.`); } catch (error) { elements.ingestMessage.textContent = error.message; } });
$("#exception-form").addEventListener("submit", async (event) => { event.preventDefault(); try { await api("/exceptions", { method: "POST", body: JSON.stringify({ findingId: elements.exceptionFinding.value, reason: $("#exception-reason").value, compensatingControl: $("#exception-control").value, expiresAt: $("#exception-expiration").value, requestedBy: "Current user" }) }); elements.exceptionDialog.close(); await refresh(); showToast("Exception request submitted."); } catch (error) { elements.exceptionMessage.textContent = error.message; } });

document.addEventListener("submit", async (event) => { const form = event.target.closest(".policy-form"); if (!form) return; event.preventDefault(); const data = new FormData(form); try { await api(`/policies/${form.dataset.policyId}`, { method: "PUT", body: JSON.stringify({ thresholds: { critical: data.get("critical"), high: data.get("high"), secrets: data.get("secrets") } }) }); await refresh(); showToast("Policy updated and runs re-evaluated."); } catch (error) { showToast(error.message); } });

load().catch((error) => showToast(error.message));

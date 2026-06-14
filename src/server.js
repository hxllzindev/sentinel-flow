import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { createStore } from "./data.js";
import { normalizeReport } from "./normalizers.js";
import { evaluatePolicy } from "./policy-engine.js";

const PUBLIC_DIR = fileURLToPath(new URL("./public", import.meta.url));
const contentTypes = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8" };
const validRoles = new Set(["security", "developer", "manager"]);
const writeRoles = new Set(["security", "developer"]);

function sendJson(res, status, payload, headers = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers });
  res.end(body);
}

async function body(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 2 * 1024 * 1024) throw Object.assign(new Error("Payload too large."), { statusCode: 413 });
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { throw Object.assign(new Error("Invalid JSON."), { statusCode: 400 }); }
}

function role(req) {
  const value = String(req.headers["x-demo-role"] ?? "security");
  return validRoles.has(value) ? value : "security";
}

function requireRole(req, res, allowed) {
  const current = role(req);
  if (!allowed.has(current)) {
    sendJson(res, 403, { error: "Your current role cannot perform this action." });
    return null;
  }
  return current;
}

function audit(store, action, actorRole, details = {}) {
  store.audit.unshift({ id: randomUUID(), action, actorRole, details, createdAt: new Date().toISOString() });
  store.audit.splice(100);
}

function enrichedRun(store, run) {
  const project = store.projects.find((item) => item.id === run.projectId);
  const findings = store.findings.filter((item) => item.runId === run.id);
  const exceptions = store.exceptions.filter((item) => item.projectId === run.projectId);
  const policy = store.policies.find((item) => item.enabled) ?? store.policies[0];
  return { ...run, project, decision: evaluatePolicy({ findings, scanners: run.scanners, exceptions, policy }) };
}

function summary(store) {
  const openFindings = store.findings.filter((finding) => finding.status !== "resolved");
  const blockedRuns = store.runs.filter((run) => enrichedRun(store, run).decision.decision === "blocked");
  const overdue = openFindings.filter((finding) => new Date(finding.slaDueAt) < new Date());
  const scannerExecutions = store.runs.flatMap((run) => run.scanners);
  const passedScanners = scannerExecutions.filter((scanner) => scanner.status === "passed").length;
  return {
    projects: store.projects.length,
    openFindings: openFindings.length,
    criticalFindings: openFindings.filter((finding) => finding.severity === "critical").length,
    blockedRuns: blockedRuns.length,
    overdueFindings: overdue.length,
    coverage: scannerExecutions.length ? Math.round((passedScanners / scannerExecutions.length) * 100) : 0,
    severity: ["critical", "high", "medium", "low"].map((severity) => ({ severity, count: openFindings.filter((finding) => finding.severity === severity).length })),
    trend: [
      { label: "May 20", opened: 7, resolved: 3 }, { label: "May 27", opened: 5, resolved: 6 },
      { label: "Jun 03", opened: 8, resolved: 5 }, { label: "Jun 10", opened: 4, resolved: 7 }
    ]
  };
}

async function serveStatic(res, pathname) {
  const relative = pathname === "/" ? "index.html" : pathname.slice(1);
  const safe = normalize(relative).replace(/^(\.\.(\/|\\|$))+/, "");
  try {
    const file = await readFile(join(PUBLIC_DIR, safe));
    res.writeHead(200, { "Content-Type": contentTypes[extname(safe)] ?? "application/octet-stream", "Cache-Control": "no-cache" });
    res.end(file);
  } catch { sendJson(res, 404, { error: "Not found." }); }
}

async function api(req, res, url, store) {
  const segments = url.pathname.split("/").filter(Boolean).slice(1);
  const resource = segments[0];

  if (req.method === "GET" && resource === "health") return sendJson(res, 200, { status: "ok" });
  if (req.method === "GET" && resource === "summary") return sendJson(res, 200, summary(store));
  if (req.method === "GET" && resource === "projects") return sendJson(res, 200, { projects: store.projects });
  if (req.method === "GET" && resource === "runs" && segments[1]) {
    const run = store.runs.find((item) => item.id === segments[1]);
    if (!run) return sendJson(res, 404, { error: "Run not found." });
    return sendJson(res, 200, { run: enrichedRun(store, run), findings: store.findings.filter((item) => item.runId === run.id) });
  }
  if (req.method === "GET" && resource === "runs") return sendJson(res, 200, { runs: store.runs.map((run) => enrichedRun(store, run)) });
  if (req.method === "GET" && resource === "findings") {
    const filtered = store.findings.filter((finding) => {
      if (url.searchParams.get("severity") && finding.severity !== url.searchParams.get("severity")) return false;
      if (url.searchParams.get("status") && finding.status !== url.searchParams.get("status")) return false;
      if (url.searchParams.get("projectId") && finding.projectId !== url.searchParams.get("projectId")) return false;
      return true;
    });
    return sendJson(res, 200, { findings: filtered });
  }
  if (req.method === "PATCH" && resource === "findings" && segments[1]) {
    const actorRole = requireRole(req, res, writeRoles); if (!actorRole) return;
    const finding = store.findings.find((item) => item.id === segments[1]);
    if (!finding) return sendJson(res, 404, { error: "Finding not found." });
    const input = await body(req);
    if (input.status && !["open", "in_progress", "resolved", "accepted", "false_positive"].includes(input.status)) return sendJson(res, 422, { error: "Invalid status." });
    if (input.status) finding.status = input.status;
    if (input.owner) finding.owner = String(input.owner).slice(0, 120);
    audit(store, "finding_updated", actorRole, { findingId: finding.id, status: finding.status, owner: finding.owner });
    return sendJson(res, 200, { finding });
  }
  if (req.method === "GET" && resource === "policies") return sendJson(res, 200, { policies: store.policies });
  if (req.method === "PUT" && resource === "policies" && segments[1]) {
    const actorRole = requireRole(req, res, new Set(["security"])); if (!actorRole) return;
    const policy = store.policies.find((item) => item.id === segments[1]);
    if (!policy) return sendJson(res, 404, { error: "Policy not found." });
    const input = await body(req);
    for (const key of ["critical", "high", "secrets"]) {
      if (input.thresholds?.[key] !== undefined) {
        const value = Number(input.thresholds[key]);
        if (!Number.isFinite(value) || value < 0 || !Number.isInteger(value)) return sendJson(res, 422, { error: `Invalid ${key} threshold.` });
        policy.thresholds[key] = value;
      }
    }
    audit(store, "policy_updated", actorRole, { policyId: policy.id, thresholds: policy.thresholds });
    return sendJson(res, 200, { policy });
  }
  if (req.method === "POST" && resource === "evaluate" && segments[1]) {
    const run = store.runs.find((item) => item.id === segments[1]);
    if (!run) return sendJson(res, 404, { error: "Run not found." });
    return sendJson(res, 200, { run: enrichedRun(store, run) });
  }
  if (req.method === "GET" && resource === "exceptions") return sendJson(res, 200, { exceptions: store.exceptions });
  if (req.method === "POST" && resource === "exceptions") {
    const actorRole = requireRole(req, res, writeRoles); if (!actorRole) return;
    const input = await body(req);
    const finding = store.findings.find((item) => item.id === input.findingId);
    if (!finding) return sendJson(res, 422, { error: "A valid finding is required." });
    if (!input.reason || !input.compensatingControl || !input.expiresAt) return sendJson(res, 422, { error: "Reason, compensating control and expiration are required." });
    const expiresAt = new Date(input.expiresAt);
    if (Number.isNaN(expiresAt.getTime()) || expiresAt <= new Date()) return sendJson(res, 422, { error: "Expiration must be a valid future date." });
    const exception = {
      id: `exception-${randomUUID()}`, findingId: finding.id, projectId: finding.projectId, status: "pending",
      requestedBy: String(input.requestedBy || "Current user").slice(0, 120), approvedBy: null,
      reason: String(input.reason).slice(0, 600), compensatingControl: String(input.compensatingControl).slice(0, 600),
      createdAt: new Date().toISOString(), expiresAt: expiresAt.toISOString()
    };
    store.exceptions.unshift(exception);
    audit(store, "exception_requested", actorRole, { exceptionId: exception.id, findingId: finding.id });
    return sendJson(res, 201, { exception });
  }
  if (req.method === "PATCH" && resource === "exceptions" && segments[1]) {
    const actorRole = requireRole(req, res, new Set(["security"])); if (!actorRole) return;
    const exception = store.exceptions.find((item) => item.id === segments[1]);
    if (!exception) return sendJson(res, 404, { error: "Exception not found." });
    const input = await body(req);
    if (!["approved", "rejected"].includes(input.status)) return sendJson(res, 422, { error: "Status must be approved or rejected." });
    exception.status = input.status;
    exception.approvedBy = String(input.approvedBy || "Security reviewer").slice(0, 120);
    audit(store, "exception_reviewed", actorRole, { exceptionId: exception.id, status: exception.status });
    return sendJson(res, 200, { exception });
  }
  if (req.method === "POST" && resource === "ingest") {
    const actorRole = requireRole(req, res, new Set(["security"])); if (!actorRole) return;
    const input = await body(req);
    const project = store.projects.find((item) => item.id === input.projectId);
    if (!project) return sendJson(res, 422, { error: "A valid project is required." });
    const runId = input.runId || `run-${randomUUID()}`;
    let run = store.runs.find((item) => item.id === runId);
    if (!run) {
      run = { id: runId, projectId: project.id, branch: input.branch || project.defaultBranch, commit: input.commit || "manual", author: input.author || "Scanner ingestion", status: "review", createdAt: new Date().toISOString(), durationSeconds: 0, scanners: [] };
      store.runs.unshift(run);
    }
    const imported = normalizeReport(input.tool, input.report, { projectId: project.id, runId, owner: project.owner });
    store.findings.unshift(...imported);
    const scannerType = imported[0]?.scanner || ({ semgrep: "sast", "trivy-sca": "sca", "trivy-container": "container", gitleaks: "secrets" }[input.tool]);
    const scanner = run.scanners.find((item) => item.type === scannerType);
    if (scanner) { scanner.status = "passed"; scanner.findings += imported.length; }
    else run.scanners.push({ type: scannerType, status: "passed", findings: imported.length, durationSeconds: Number(input.durationSeconds || 0) });
    run.status = enrichedRun(store, run).decision.decision;
    audit(store, "report_ingested", actorRole, { tool: input.tool, runId, findings: imported.length });
    return sendJson(res, 201, { run: enrichedRun(store, run), imported: imported.length });
  }
  if (req.method === "GET" && resource === "audit") return sendJson(res, 200, { events: store.audit.slice(0, 50) });
  return sendJson(res, 404, { error: "Endpoint not found." });
}

export function createApp(options = {}) {
  const store = options.store ?? createStore();
  const server = createServer(async (req, res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    try {
      const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
      if (url.pathname.startsWith("/api/")) await api(req, res, url, store);
      else await serveStatic(res, url.pathname);
    } catch (error) {
      sendJson(res, error.statusCode ?? 500, { error: error.statusCode ? error.message : "Internal server error." });
    }
  });
  return { server, store };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 4000);
  createApp().server.listen(port, "0.0.0.0", () => console.log(`Sentinel Flow: http://127.0.0.1:${port}`));
}

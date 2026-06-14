import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { createApp } from "../src/server.js";

let server;
let baseUrl;

async function request(path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers ?? {}) }
  });
  return { response, payload: await response.json() };
}

before(async () => {
  server = createApp().server;
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

test("serves dashboard with defensive headers", async () => {
  const response = await fetch(baseUrl);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.match(response.headers.get("content-security-policy"), /frame-ancestors 'none'/);
});

test("summary exposes operational security metrics", async () => {
  const { response, payload } = await request("/api/summary");
  assert.equal(response.status, 200);
  assert.equal(payload.projects, 3);
  assert.ok(payload.openFindings > 0);
  assert.ok(payload.coverage > 0);
});

test("run detail route returns policy decision and findings", async () => {
  const { response, payload } = await request("/api/runs/run-1042");
  assert.equal(response.status, 200);
  assert.equal(payload.run.id, "run-1042");
  assert.equal(payload.run.decision.decision, "blocked");
  assert.ok(payload.findings.length > 0);
});

test("manager role cannot update a finding", async () => {
  const { response } = await request("/api/findings/finding-sqli", {
    method: "PATCH",
    headers: { "X-Demo-Role": "manager" },
    body: JSON.stringify({ status: "resolved" })
  });
  assert.equal(response.status, 403);
});

test("developer role can triage a finding", async () => {
  const { response, payload } = await request("/api/findings/finding-sqli", {
    method: "PATCH",
    headers: { "X-Demo-Role": "developer" },
    body: JSON.stringify({ status: "in_progress", owner: "Payments remediation squad" })
  });
  assert.equal(response.status, 200);
  assert.equal(payload.finding.owner, "Payments remediation squad");
});

test("only security role can change policy thresholds", async () => {
  const denied = await request("/api/policies/policy-default", {
    method: "PUT", headers: { "X-Demo-Role": "developer" }, body: JSON.stringify({ thresholds: { high: 5 } })
  });
  assert.equal(denied.response.status, 403);

  const allowed = await request("/api/policies/policy-default", {
    method: "PUT", headers: { "X-Demo-Role": "security" }, body: JSON.stringify({ thresholds: { high: 4 } })
  });
  assert.equal(allowed.response.status, 200);
  assert.equal(allowed.payload.policy.thresholds.high, 4);

  const invalid = await request("/api/policies/policy-default", {
    method: "PUT", headers: { "X-Demo-Role": "security" }, body: JSON.stringify({ thresholds: { high: "not-a-number" } })
  });
  assert.equal(invalid.response.status, 422);
});

test("ingests and normalizes a Semgrep report", async () => {
  const { response, payload } = await request("/api/ingest", {
    method: "POST",
    headers: { "X-Demo-Role": "security" },
    body: JSON.stringify({
      projectId: "project-payments",
      tool: "semgrep",
      branch: "feature/report-import",
      commit: "d312a9f",
      report: { results: [{ check_id: "demo.xss", path: "src/view.js", start: { line: 12 }, extra: { severity: "ERROR", message: "<img src=x onerror=alert(1)>" } }] }
    })
  });
  assert.equal(response.status, 201);
  assert.equal(payload.imported, 1);
  assert.equal(payload.run.project.id, "project-payments");
});

test("risk exception follows request and approval lifecycle", async () => {
  const created = await request("/api/exceptions", {
    method: "POST",
    headers: { "X-Demo-Role": "developer" },
    body: JSON.stringify({
      findingId: "finding-openssl",
      requestedBy: "Billing team",
      reason: "Patched base image is undergoing compatibility tests.",
      compensatingControl: "Workload egress is restricted and the service is not internet-facing.",
      expiresAt: "2099-01-01"
    })
  });
  assert.equal(created.response.status, 201);
  assert.equal(created.payload.exception.status, "pending");

  const approved = await request(`/api/exceptions/${created.payload.exception.id}`, {
    method: "PATCH",
    headers: { "X-Demo-Role": "security" },
    body: JSON.stringify({ status: "approved", approvedBy: "Security lead" })
  });
  assert.equal(approved.response.status, 200);
  assert.equal(approved.payload.exception.status, "approved");
});

test("risk exception rejects invalid or past expiration", async () => {
  const result = await request("/api/exceptions", {
    method: "POST",
    headers: { "X-Demo-Role": "developer" },
    body: JSON.stringify({
      findingId: "finding-openssl",
      reason: "Invalid request",
      compensatingControl: "None",
      expiresAt: "2020-01-01"
    })
  });
  assert.equal(result.response.status, 422);
});

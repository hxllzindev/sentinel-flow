import test from "node:test";
import assert from "node:assert/strict";
import { defaultPolicy, evaluatePolicy } from "../src/policy-engine.js";

const scanners = defaultPolicy.requiredScanners.map((type) => ({ type, status: "passed" }));
const finding = (overrides = {}) => ({ id: "finding-1", severity: "high", category: "code", status: "open", ...overrides });

test("policy blocks a critical finding", () => {
  const result = evaluatePolicy({ findings: [finding({ severity: "critical" })], scanners });
  assert.equal(result.decision, "blocked");
  assert.match(result.violations[0], /critical/);
});

test("approved active exception removes a finding from evaluation", () => {
  const result = evaluatePolicy({
    findings: [finding({ severity: "critical" })], scanners,
    exceptions: [{ findingId: "finding-1", status: "approved", expiresAt: "2099-01-01T00:00:00.000Z" }]
  });
  assert.equal(result.decision, "passed");
  assert.equal(result.exemptedFindings, 1);
});

test("expired exception blocks the policy and restores the finding", () => {
  const result = evaluatePolicy({
    findings: [finding({ severity: "critical" })], scanners,
    exceptions: [{ findingId: "finding-1", status: "approved", expiresAt: "2020-01-01T00:00:00.000Z" }]
  });
  assert.equal(result.decision, "blocked");
  assert.ok(result.violations.some((violation) => violation.includes("expired")));
  assert.equal(result.evaluatedFindings, 1);
});

test("missing scanner blocks a run even without findings", () => {
  const result = evaluatePolicy({ findings: [], scanners: scanners.filter((scanner) => scanner.type !== "dast") });
  assert.equal(result.decision, "blocked");
  assert.deepEqual(result.missingScanners, ["dast"]);
});

test("resolved findings do not consume the threshold", () => {
  const result = evaluatePolicy({ findings: [finding({ severity: "critical", status: "resolved" })], scanners });
  assert.equal(result.decision, "passed");
  assert.equal(result.riskScore, 0);
});

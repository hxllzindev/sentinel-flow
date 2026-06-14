import { defaultPolicy } from "./policy-engine.js";

const now = Date.now();
const isoDaysAgo = (days) => new Date(now - days * 86_400_000).toISOString();
const isoDaysAhead = (days) => new Date(now + days * 86_400_000).toISOString();

export function createStore() {
  const projects = [
    { id: "project-payments", name: "Payments API", repository: "acme/payments-api", owner: "Platform Payments", tier: "critical", defaultBranch: "main" },
    { id: "project-portal", name: "Customer Portal", repository: "acme/customer-portal", owner: "Digital Experience", tier: "high", defaultBranch: "main" },
    { id: "project-worker", name: "Invoice Worker", repository: "acme/invoice-worker", owner: "Billing Operations", tier: "medium", defaultBranch: "main" }
  ];

  const runs = [
    {
      id: "run-1042", projectId: "project-payments", branch: "feature/token-rotation", commit: "a82f91c", author: "Ana Silva",
      status: "blocked", createdAt: isoDaysAgo(0.08), durationSeconds: 214,
      scanners: [
        { type: "sast", status: "passed", findings: 2, durationSeconds: 31 },
        { type: "sca", status: "passed", findings: 1, durationSeconds: 26 },
        { type: "secrets", status: "failed", findings: 1, durationSeconds: 8 },
        { type: "container", status: "passed", findings: 0, durationSeconds: 42 },
        { type: "dast", status: "passed", findings: 1, durationSeconds: 97 }
      ]
    },
    {
      id: "run-1041", projectId: "project-portal", branch: "main", commit: "1bf027a", author: "Caio Mendes",
      status: "passed", createdAt: isoDaysAgo(0.45), durationSeconds: 187,
      scanners: [
        { type: "sast", status: "passed", findings: 1, durationSeconds: 34 },
        { type: "sca", status: "passed", findings: 0, durationSeconds: 22 },
        { type: "secrets", status: "passed", findings: 0, durationSeconds: 7 },
        { type: "container", status: "passed", findings: 0, durationSeconds: 39 },
        { type: "dast", status: "passed", findings: 0, durationSeconds: 85 }
      ]
    },
    {
      id: "run-1040", projectId: "project-worker", branch: "chore/runtime-update", commit: "c019ed4", author: "Bruno Lima",
      status: "review", createdAt: isoDaysAgo(1.2), durationSeconds: 156,
      scanners: [
        { type: "sast", status: "passed", findings: 0, durationSeconds: 27 },
        { type: "sca", status: "passed", findings: 2, durationSeconds: 18 },
        { type: "secrets", status: "passed", findings: 0, durationSeconds: 6 },
        { type: "container", status: "passed", findings: 1, durationSeconds: 33 },
        { type: "dast", status: "passed", findings: 0, durationSeconds: 72 }
      ]
    },
    {
      id: "run-1039", projectId: "project-payments", branch: "main", commit: "749b31d", author: "Ana Silva",
      status: "passed", createdAt: isoDaysAgo(2.1), durationSeconds: 201,
      scanners: [
        { type: "sast", status: "passed", findings: 0, durationSeconds: 29 },
        { type: "sca", status: "passed", findings: 0, durationSeconds: 21 },
        { type: "secrets", status: "passed", findings: 0, durationSeconds: 7 },
        { type: "container", status: "passed", findings: 0, durationSeconds: 40 },
        { type: "dast", status: "passed", findings: 0, durationSeconds: 92 }
      ]
    }
  ];

  const findings = [
    {
      id: "finding-secret", projectId: "project-payments", runId: "run-1042", scanner: "secrets", title: "AWS access key committed in test fixture",
      severity: "critical", category: "secret", status: "open", owner: "Platform Payments", file: "test/fixtures/account.json", line: 18,
      ruleId: "gitleaks/aws-access-token", description: "A credential matching an AWS access key pattern is present in the commit.",
      remediation: "Revoke the key, remove it from Git history and use the CI secret store.", createdAt: isoDaysAgo(0.08), slaDueAt: isoDaysAhead(0.92)
    },
    {
      id: "finding-sqli", projectId: "project-payments", runId: "run-1042", scanner: "sast", title: "User input reaches SQL query without parameterization",
      severity: "high", category: "code", status: "in_progress", owner: "Ana Silva", file: "src/repositories/refunds.js", line: 74,
      ruleId: "javascript.lang.security.audit.sqli", description: "A template literal builds a query with request-controlled input.",
      remediation: "Use a parameterized statement and add a regression test for malicious input.", createdAt: isoDaysAgo(0.08), slaDueAt: isoDaysAhead(6.92)
    },
    {
      id: "finding-csrf", projectId: "project-portal", runId: "run-1041", scanner: "sast", title: "State-changing route lacks CSRF validation",
      severity: "medium", category: "code", status: "accepted", owner: "Digital Experience", file: "src/routes/preferences.ts", line: 41,
      ruleId: "custom/csrf-missing", description: "The preference endpoint accepts cookie authentication without a CSRF token.",
      remediation: "Require an anti-CSRF token and use SameSite cookies.", createdAt: isoDaysAgo(0.45), slaDueAt: isoDaysAhead(29.55)
    },
    {
      id: "finding-openssl", projectId: "project-worker", runId: "run-1040", scanner: "sca", title: "CVE-2026-1842 in libssl3",
      severity: "high", category: "dependency", status: "open", owner: "Billing Operations", file: "Dockerfile", line: 1,
      ruleId: "CVE-2026-1842", description: "The runtime image contains a vulnerable OpenSSL package.",
      remediation: "Rebuild with the latest patched Alpine base image.", createdAt: isoDaysAgo(1.2), slaDueAt: isoDaysAhead(5.8)
    },
    {
      id: "finding-header", projectId: "project-payments", runId: "run-1042", scanner: "dast", title: "Cross-Origin-Resource-Policy header missing",
      severity: "low", category: "configuration", status: "open", owner: "Platform Payments", file: "https://staging.payments.test", line: 0,
      ruleId: "zap/10098", description: "Responses do not define a resource isolation policy.",
      remediation: "Set Cross-Origin-Resource-Policy to same-origin where applicable.", createdAt: isoDaysAgo(0.08), slaDueAt: isoDaysAhead(89.92)
    },
    {
      id: "finding-image", projectId: "project-worker", runId: "run-1040", scanner: "container", title: "Container runs with writable root filesystem",
      severity: "medium", category: "container", status: "open", owner: "Billing Operations", file: "deploy/worker.yaml", line: 33,
      ruleId: "KSV014", description: "The workload does not enable readOnlyRootFilesystem.",
      remediation: "Set securityContext.readOnlyRootFilesystem to true and mount explicit writable volumes.", createdAt: isoDaysAgo(1.2), slaDueAt: isoDaysAhead(28.8)
    }
  ];

  const exceptions = [
    {
      id: "exception-17", findingId: "finding-csrf", projectId: "project-portal", status: "approved", requestedBy: "Caio Mendes",
      approvedBy: "Marina Costa", reason: "Endpoint is behind an internal gateway while the CSRF migration is completed.",
      compensatingControl: "Gateway restricts origins and requires step-up authentication.", createdAt: isoDaysAgo(0.3), expiresAt: isoDaysAhead(12)
    }
  ];

  return { projects, runs, findings, exceptions, policies: [{ ...defaultPolicy }], audit: [] };
}

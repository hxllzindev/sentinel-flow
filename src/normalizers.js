import { randomUUID } from "node:crypto";
import { calculateSlaDueDate } from "./policy-engine.js";

function severity(value = "medium") {
  const normalized = String(value).toLowerCase();
  if (normalized === "error") return "high";
  if (normalized === "warning" || normalized === "warn") return "medium";
  return ["critical", "high", "medium", "low", "info"].includes(normalized)
    ? normalized
    : "medium";
}

function baseFinding(input, context) {
  const createdAt = new Date().toISOString();
  const findingSeverity = severity(input.severity);
  return {
    id: `finding-${randomUUID()}`,
    projectId: context.projectId,
    runId: context.runId,
    scanner: context.scanner,
    title: input.title || "Untitled security finding",
    severity: findingSeverity,
    category: input.category || "code",
    status: "open",
    owner: context.owner || "Unassigned",
    file: input.file || "unknown",
    line: Number(input.line || 0),
    ruleId: input.ruleId || "unknown",
    description: input.description || "Imported from security scanner.",
    remediation: input.remediation || "Review the scanner guidance and remove the vulnerable pattern.",
    createdAt,
    slaDueAt: calculateSlaDueDate(findingSeverity, createdAt)
  };
}

function normalizeSemgrep(report, context) {
  return (report.results ?? []).map((result) => baseFinding({
    title: result.extra?.message || result.check_id,
    severity: result.extra?.severity,
    category: "code",
    file: result.path,
    line: result.start?.line,
    ruleId: result.check_id,
    description: result.extra?.metadata?.description || result.extra?.message,
    remediation: result.extra?.metadata?.fix || "Apply the secure coding recommendation for this rule."
  }, context));
}

function normalizeTrivy(report, context) {
  const findings = [];
  for (const result of report.Results ?? []) {
    for (const vulnerability of result.Vulnerabilities ?? []) {
      findings.push(baseFinding({
        title: `${vulnerability.VulnerabilityID} in ${vulnerability.PkgName}`,
        severity: vulnerability.Severity,
        category: context.scanner === "container" ? "container" : "dependency",
        file: result.Target,
        ruleId: vulnerability.VulnerabilityID,
        description: vulnerability.Description || vulnerability.Title,
        remediation: vulnerability.FixedVersion
          ? `Upgrade ${vulnerability.PkgName} to ${vulnerability.FixedVersion}.`
          : "No fixed version is currently available; evaluate compensating controls."
      }, context));
    }
  }
  return findings;
}

function normalizeGitleaks(report, context) {
  const entries = Array.isArray(report) ? report : report.findings ?? [];
  return entries.map((finding) => baseFinding({
    title: finding.Description || "Potential secret detected",
    severity: "critical",
    category: "secret",
    file: finding.File,
    line: finding.StartLine,
    ruleId: finding.RuleID,
    description: "A credential-like value was committed to source control.",
    remediation: "Revoke the credential, remove it from history and migrate it to a secret manager."
  }, context));
}

export function normalizeReport(tool, report, context) {
  if (tool === "semgrep") return normalizeSemgrep(report, { ...context, scanner: "sast" });
  if (tool === "trivy-sca") return normalizeTrivy(report, { ...context, scanner: "sca" });
  if (tool === "trivy-container") return normalizeTrivy(report, { ...context, scanner: "container" });
  if (tool === "gitleaks") return normalizeGitleaks(report, { ...context, scanner: "secrets" });
  throw Object.assign(new Error("Unsupported scanner report."), { statusCode: 422 });
}

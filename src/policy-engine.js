const severityWeight = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export const defaultPolicy = {
  id: "policy-default",
  name: "Production merge policy",
  description: "Blocks releases with exploitable risk or incomplete security coverage.",
  enabled: true,
  thresholds: {
    critical: 0,
    high: 2,
    secrets: 0
  },
  requiredScanners: ["sast", "sca", "secrets", "container", "dast"],
  blockOnExpiredException: true
};

function activeException(findingId, exceptions, now = new Date()) {
  return exceptions.some((exception) => (
    exception.findingId === findingId
    && exception.status === "approved"
    && new Date(exception.expiresAt) > now
  ));
}

export function evaluatePolicy({ findings, scanners, policy = defaultPolicy, exceptions = [], now = new Date() }) {
  const applicable = findings.filter((finding) => (
    finding.status !== "resolved" && !activeException(finding.id, exceptions, now)
  ));
  const counts = applicable.reduce((summary, finding) => {
    summary[finding.severity] = (summary[finding.severity] ?? 0) + 1;
    if (finding.category === "secret") summary.secrets += 1;
    return summary;
  }, { critical: 0, high: 0, medium: 0, low: 0, info: 0, secrets: 0 });

  const scannerMap = new Map(scanners.map((scanner) => [scanner.type, scanner.status]));
  const missingScanners = policy.requiredScanners.filter((type) => scannerMap.get(type) !== "passed");
  const violations = [];

  if (counts.critical > policy.thresholds.critical) {
    violations.push(`${counts.critical} critical finding(s); maximum ${policy.thresholds.critical}`);
  }
  if (counts.high > policy.thresholds.high) {
    violations.push(`${counts.high} high finding(s); maximum ${policy.thresholds.high}`);
  }
  if (counts.secrets > policy.thresholds.secrets) {
    violations.push(`${counts.secrets} exposed secret(s); maximum ${policy.thresholds.secrets}`);
  }
  if (missingScanners.length > 0) {
    violations.push(`Required scanners incomplete: ${missingScanners.join(", ")}`);
  }

  const expiredExceptions = exceptions.filter((exception) => (
    exception.status === "approved" && new Date(exception.expiresAt) <= now
  ));
  if (policy.blockOnExpiredException && expiredExceptions.length > 0) {
    violations.push(`${expiredExceptions.length} risk exception(s) expired`);
  }

  return {
    decision: violations.length === 0 ? "passed" : "blocked",
    counts,
    missingScanners,
    violations,
    evaluatedFindings: applicable.length,
    exemptedFindings: findings.length - applicable.length,
    riskScore: applicable.reduce((score, finding) => score + severityWeight[finding.severity], 0)
  };
}

export function calculateSlaDueDate(severity, createdAt) {
  const days = { critical: 1, high: 7, medium: 30, low: 90, info: 180 }[severity] ?? 30;
  const due = new Date(createdAt);
  due.setUTCDate(due.getUTCDate() + days);
  return due.toISOString();
}

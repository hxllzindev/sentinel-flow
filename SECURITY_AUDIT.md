# Security audit — 2026-07-11

## Result

The repository was reviewed as a local DevSecOps demonstration. Five concrete integrity, exposure and availability issues were fixed and verified.

## Fixed findings

- The demo role header could protect writes but the full findings API was deployable in Production. Production now fails closed unless the operator explicitly opts into the insecure demo; Compose is loopback-only.
- Unsupported scanner names could be recorded as successful executions with zero findings. Ingestion now accepts only the actually implemented Semgrep format.
- A supplied run ID could attach one project's findings to another project's run. Existing run IDs must now match the requested project.
- Scanner reports and imported strings were broadly unbounded and malformed nested values could cause server errors. Body, JSON depth, result count, field lengths and numeric inputs are bounded; parsing is defensive and errors are generic.
- Singleton lists were mutable across concurrent requests and several collections grew without limits. API access is serialized and runs, findings, exceptions and audit history have retention ceilings.

Additional hardening adds secret-pattern redaction, API `no-store`, generic health output, defensive headers and sanitized exception/finding text.

## Verification

- Linux .NET 10 SDK: 12/12 xUnit tests passed, including unsupported scanner rejection, cross-project run rejection, text redaction, missing-role denial and the Production gate.
- NuGet audit: no known vulnerable packages from the configured source.
- Docker build and runtime hardening are validated by the existing non-root/read-only image definition and the final container smoke test.

## Residual boundary

The role header is not identity. The seed and dashboard are synthetic. Real operation requires OIDC, TLS, project-level authorization, durable encrypted storage, managed secrets, stronger audit guarantees and formal LGPD governance.

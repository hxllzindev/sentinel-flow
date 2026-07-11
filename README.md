# Sentinel Flow

Sentinel Flow is a DevSecOps security orchestration platform built in **ASP.NET Core/.NET 10** as an independent portfolio project. It centralizes pipeline runs, normalizes scanner findings, evaluates merge policies, tracks remediation SLAs and manages time-bound risk exceptions.

## Product capabilities

- Executive security overview with risk and delivery metrics
- Pipeline runs with SAST, SCA, secrets, container and DAST gates
- Finding backlog with severity, ownership, SLA and remediation state
- C# policy engine for critical, high and exposed-secret thresholds
- Required-scanner coverage rules
- Risk exception request, approval, rejection and expiration
- Semgrep report normalization
- Demo RBAC for security engineer, developer and manager roles
- Audit trail for policy, finding, ingestion and exception changes

## Run locally

Requires .NET 10 SDK:

```bash
dotnet restore SentinelFlow.sln
dotnet run --project src/SentinelFlow.Api/SentinelFlow.Api.csproj
```

Open `http://127.0.0.1:4000`.

With Docker:

```bash
docker compose up -d --build
```

O Compose habilita explicitamente o modelo demonstrativo, mas publica somente em `127.0.0.1`. Em `Production`, a API fica bloqueada sem `ALLOW_INSECURE_DEMO=true`; uma implantação real não deve definir essa variável.

## Tests

```bash
dotnet test SentinelFlow.sln
```

The suite covers policy decisions, API headers, run details, RBAC, triage, policy updates, Semgrep ingestion and the risk exception lifecycle.

## Policy model

A run is blocked when any configured rule fails:

- Critical findings exceed the maximum
- High findings exceed the maximum
- Exposed secrets exceed the maximum
- A required scanner did not pass
- An approved exception expired

Resolved findings and active approved exceptions are removed from evaluation. Every remaining finding contributes to the run risk score.

## Demo roles

The role selector exists to demonstrate server-side authorization decisions without adding an identity provider to this portfolio app.

| Role | Capabilities |
| --- | --- |
| Security engineer | Ingest, change policies, triage and review exceptions |
| Developer | Triage findings and request exceptions |
| Engineering manager | Read-only visibility |

Production deployment would replace `X-Demo-Role` with claims from an OIDC identity provider.

`X-Demo-Role` is never authentication. Use only the synthetic seed and sanitized scanner samples; do not paste real reports, credentials, repository URLs, author identities or secret values into the demo. See [PRIVACY.md](PRIVACY.md) and [SECURITY.md](SECURITY.md).

## Delivery pipeline

- .NET build and xUnit tests
- Semgrep OWASP C# SAST
- GitHub CodeQL C#
- Gitleaks secret scanning
- Trivy container scanning
- SPDX SBOM generation
- Docker smoke test

## Current scope

Data is intentionally stored in memory to keep the demo deterministic and dependency-free. The repository boundary is designed so a PostgreSQL adapter, OIDC provider and real GitHub/GitLab webhooks can be added without changing the policy engine.

The verified security changes and residual limits are recorded in [SECURITY_AUDIT.md](SECURITY_AUDIT.md).

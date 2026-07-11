# API reference

All write examples use `X-Demo-Role`. Valid values are `security`, `developer` and `manager`; missing or invalid values are read-only. The header is a demo mechanism, not authentication. In `Production`, only `/api/health` remains available unless the insecure demo is explicitly enabled.

## Overview

- `GET /api/health`
- `GET /api/summary`
- `GET /api/projects`
- `GET /api/audit`

## Pipeline runs

- `GET /api/runs`
- `GET /api/runs/:id`
- `POST /api/evaluate/:id`

Run responses include the project, scanners and current policy decision.

## Findings

- `GET /api/findings?severity=high&status=open&projectId=project-payments`
- `PATCH /api/findings/:id`

```json
{
  "status": "in_progress",
  "owner": "Payments remediation squad"
}
```

## Policies

- `GET /api/policies`
- `PUT /api/policies/:id` - security role only

```json
{
  "thresholds": {
    "critical": 0,
    "high": 2,
    "secrets": 0
  }
}
```

## Risk exceptions

- `GET /api/exceptions`
- `POST /api/exceptions` - developer or security
- `PATCH /api/exceptions/:id` - security only

```json
{
  "findingId": "finding-openssl",
  "reason": "Patched image is under compatibility testing.",
  "compensatingControl": "The workload is isolated from the internet.",
  "expiresAt": "2026-07-01"
}
```

## Scanner ingestion

`POST /api/ingest` - security role only

```json
{
  "projectId": "project-payments",
  "tool": "semgrep",
  "branch": "feature/refunds",
  "commit": "d312a9f",
  "report": {
    "results": []
  }
}
```

Supported tool value: `semgrep`. Reports must contain a `results` array with at most 1,000 objects and fit inside the 512 KiB request limit. Unsupported scanners are rejected instead of being recorded as passed. Branch, commit, author, path and message text are bounded, stripped of control characters and redact common inline secret patterns.

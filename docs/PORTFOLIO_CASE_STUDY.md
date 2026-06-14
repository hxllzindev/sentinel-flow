# Portfolio case study

## Title

Sentinel Flow: turning security scanners into enforceable delivery policy

## Problem

Security tools often produce isolated reports. Teams still need one place to understand release risk, assign remediation, enforce policy and document temporary exceptions.

## Solution

I built a DevSecOps control plane that normalizes Semgrep, Trivy and Gitleaks results into a shared finding model. A deterministic policy engine evaluates severity thresholds, secrets, scanner coverage and exception expiration before returning a pass or block decision.

## Engineering highlights

- Pure policy engine with focused unit tests
- Normalization layer for multiple scanner schemas
- Server-side role authorization
- Finding ownership and SLA workflow
- Time-bound exception governance
- Responsive operational dashboard
- Hardened container and security-focused CI

## Evidence

- 13 automated tests
- 5 security gate types
- 3 role profiles
- 3 scanner formats
- Pass/block decisions with human-readable violations
- Container scan and SBOM generation in CI

## Resume bullet

Built a DevSecOps orchestration platform that normalizes SAST, SCA, secrets and container findings, enforces merge policies, tracks remediation SLAs and manages time-bound risk exceptions with RBAC and automated security gates.

## Interview pitch

"Most teams already have scanners; the hard part is operationalizing their output. Sentinel Flow receives reports, normalizes them, assigns ownership and evaluates release policy. I separated the policy engine from HTTP and storage so decisions are deterministic and testable. The exception workflow is time-bound, which prevents accepted risk from becoming permanent invisible debt."

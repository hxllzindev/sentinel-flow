# Security policy

## Scope

Sentinel Flow is a local portfolio demonstration. `X-Demo-Role` is not authentication. The supplied Compose enables the demo only on `127.0.0.1`; without explicit opt-in, a Production process exposes health only.

Use synthetic scanner data. Never submit real secrets, credentials, private repository metadata, employee identities, customer data or production findings through the dashboard or API.

## Implemented controls

- Production fail-closed gate and loopback-only Compose exposure.
- Non-root, read-only container with all capabilities removed and `no-new-privileges`.
- Defensive browser headers and `no-store` API responses.
- 512 KiB body and JSON-depth limits.
- Semgrep-only allowlist, result-count limit and project/run binding.
- Bounded/redacted text and bounded runs, findings, exceptions and audit records.
- Server-side role checks and serialized access to mutable in-memory state.
- CI build, tests, SAST, secret scanning, container scanning and SBOM.
- Frontend read-only sem ingestao/edicao livre, sem sinks HTML ou armazenamento
  persistente, alimentado somente por DTOs que removem metadados de repositorio,
  identidade, evidencias livres e detalhes de excecao/auditoria.

## Reporting and incidents

Report vulnerabilities privately with sanitized evidence. Do not place exploit details, secrets or personal data in a public issue.

For a personal-data incident, contain access, rotate affected credentials, preserve sanitized evidence, identify affected data and people, and assess relevant risk or harm. When required by the LGPD and Resolução CD/ANPD nº 15/2024, notify the ANPD and affected data subjects within the applicable three-business-day period and retain the incident record for the regulatory period.

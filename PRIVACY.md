# Privacy and LGPD

Security findings and pipeline metadata can identify developers, repositories, branches, commits, owners, systems and weaknesses. Secret-scanner output may itself contain credentials. Sentinel Flow therefore accepts only synthetic demonstration data.

## Current safeguards

- The only accepted report format is bounded Semgrep JSON.
- Imported branch, commit, author, path and message fields are length-limited, stripped of control characters and redact common password, token, secret, authorization and API-key patterns.
- Production fails closed without explicit demo opt-in, and Compose binds to loopback.
- API responses use `no-store`; mutable in-memory collections have retention ceilings and disappear when the process stops.
- O frontend e somente leitura e recebe projecoes allowlisted. Nomes/owners de projeto,
  branches, commits, autores, titulos/localizacoes/owners de achados, reports, motivos,
  controles compensatorios, solicitantes/aprovadores e detalhes de auditoria nao sao
  enviados ao navegador.

Automated redaction is not a guarantee. A ingestao permanece API-only; nao envie reports
reais ou dados pessoais/confidenciais pela API.

## Requirements before real use

A real deployment needs documented controller, purpose and legal basis; OIDC identity; least-privilege authorization; tenant/project isolation; TLS; encrypted persistent storage and backups; managed keys; field-level minimization; retention/deletion jobs; access audit; and a channel for data-subject rights.

Official references:

- https://www2.camara.leg.br/legin/fed/lei/2018/lei-13709-14-agosto-2018-787077-normaatualizada-pl.html
- https://www.gov.br/anpd/pt-br/assuntos/titular-de-dados-1/direito-dos-titulares
- https://www.gov.br/anpd/pt-br/centrais-de-conteudo/materiais-educativos-e-publicacoes/processo-guia-orientativo-sobre-seguranca-da-informacao-para-agentes-de-tratamento-de-pequeno-porte.pdf

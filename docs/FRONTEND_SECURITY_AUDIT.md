# Frontend security pass — 2026-07-11

O dashboard deixou de receber ou renderizar nomes/owners de projetos, branch, commit,
autor, titulo/localizacao/owner de finding, report de scanner, motivo/controle/solicitante
de excecao e detalhes de auditoria. Ingestao de report, mudanca de papel, triagem,
edicao de policy e solicitacao/aprovacao de excecao permanecem API-only.

A interface agora e estritamente read-only, usa apenas nos DOM e `textContent`, nao
persiste estado no navegador e recebe DTOs allowlisted com rotulos anonimos, contagens,
classificacao, datas, cobertura e decisoes de policy.

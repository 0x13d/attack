# Trust Report — attack

_Generated 2026-06-18T18:17:14Z_

Static supply-chain checks. Re-run via `bash scripts/trust-report.sh`.
Artifacts in `reports/trust/`; only this `summary.md` is committed.

| Status | Check | Detail |
|--------|-------|--------|
| OK | SBOM (syft) | 151 components — sbom.cyclonedx.json, sbom.spdx.json |
| OK | npm audit (root) | 0 vulnerabilities — audit-npm-root.json |
| OK | npm audit (apps/vscode) | 0 vulnerabilities — audit-npm-apps_vscode.json |
| OK | npm audit (apps/web) | 0 vulnerabilities — audit-npm-apps_web.json |
| OK | npm audit (packages/rule-schema) | 0 vulnerabilities — audit-npm-packages_rule-schema.json |
| OK | npm audit (src) | 0 vulnerabilities — audit-npm-src.json |
| OK | Licenses | 151 components, 7 distinct — licenses.csv |
| INFO | Network-call inventory | 129 source matches — network-calls.txt (review for outbound) |

## Artifacts

- audit-npm-apps_vscode.json
- audit-npm-apps_web.json
- audit-npm-packages_rule-schema.json
- audit-npm-root.json
- audit-npm-src.json
- licenses.csv
- network-calls.txt
- sbom.cyclonedx.json
- sbom.spdx.json

## Reproduce

```sh
bash scripts/trust-report.sh
```

Tools used (when present): syft, npm/pnpm audit, cargo-audit, cargo-deny, jq.

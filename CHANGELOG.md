# Changelog

## 0.1.0 — 2026-07-04

Initial public release of the community edition.

- **16 MITRE ATT&CK techniques** live: T1176.001 (+T1176 tamper), T1566.001/.002/.003, T1539, T1550.004,
  T1185, T1528, T1105, T1204.001/.002, T1189, T1656, T1606.002, T1217 — each with a rule, pure detection
  logic, unit tests, and a reproducible demo target + runbook under `targets/`.
- **Zero host permissions, zero network egress**, enforced by the build's trust self-check (the build fails
  on any `fetch(`, network API reference, content script, or host permission).
- **`0x13d-attack-rules-community`** — the rule set as a standalone npm package (`rules/`).
- **Declarative user rules** (`@attack/rule-schema`): JSON conditions interpreted — never executed — by the
  engine, with a VS Code authoring extension (`apps/vscode`).

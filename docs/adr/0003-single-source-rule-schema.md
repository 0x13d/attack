---
status: "superseded by ADR-004"
date: 2026-06-16
decision-makers: architect
consulted: security (CSO), frontend-dev
informed: team
---

> **Superseded by [ADR-004](0004-rule-schema-workspace-package.md) (2026-06-16).** The owner chose the npm
> workspace package over the generator-mirror bridge. The `SCOPES` decouple and the JSON-Schema generator
> described here are **kept and reused**; only the "generate TS mirrors for brochure/VSCode" mechanism is
> replaced by direct package imports.

# The rule schema has one canonical source; mirrors + the JSON Schema are generated and drift-checked

## Context and Problem Statement

ADR-0002 introduced the declarative rule schema and asserted "the brochure editor and the extension can't
drift." They did. By v0.8.0 the schema lived in **three hand-synced TypeScript copies** — the engine
(`apps/extension/src/schema`), the brochure (`apps/web/src/ruleSchema.ts`), the VSCode extension
(`apps/vscode/src/validate.ts`) — **plus** a hand-written JSON Schema (`apps/vscode/schemas/`). Planning v0.8.1
found real drift: the VSCode validator hardcoded `RESPONSE_IDS = {alert, disableExtension, closeTab}`, **missing
`removeCookie` (T1539) and `cancelDownload` (T1105)** — it would reject valid authored rules. The repo is **not
an npm workspace**, and the trust posture forbids casual new dependencies, so "just publish a package" isn't free.

## Decision Drivers

* **No silent drift** — a divergence between any consumer and the engine must fail a check, not ship.
* **Zero new runtime deps; no build-infra upheaval** (no workspace conversion at this stage).
* **`tsc` reality** — the VSCode extension *emits* JS under a `rootDir`; importing a `.ts` file from a sibling
  package (`../../src/...`) trips `TS6059`. The brochure (Vite, bundled) has no such constraint.

## Decision Outcome

**The engine's `apps/extension/src/schema` is the single canonical source.** It is decoupled from the engine's
chrome-coupled `../types` (scopes are now portable `SCOPES` data, pinned to the `Scope` enum by a guard test),
so it is importable by tooling. From it:

- **The JSON Schema is generated** by `src/tools/gen-rule-schema.ts` (`npm run gen:schema`), with a `--check`
  mode (`npm run check:schema`) that fails if the committed `apps/vscode/schemas/attack-rule.schema.json` is
  stale. The op/scope/response-id enums come from `OPS` / `SCOPES` / `RESPONSE_IDS` (the last derived from the
  live `buildResponseRegistry()`) — no hand-maintained list.
- **The brochure** (Vite, no `rootDir`) consumes the canonical module directly.
- **The VSCode validator** consumes generated data + the generated JSON Schema — it cannot relative-
  import across `rootDir`, so generation (not import) is the bridge there.
- **A drift guard test** asserts every consumer + the JSON Schema agree with the canonical source;
  the shipped-count guard folds in alongside it.

### Consequences

- Good — the v0.8.0 class of drift (the VSCode `RESPONSE_IDS` bug, fixed here) can't recur silently: `gen`/check
  + the guard test catch it. One source of truth, mechanically enforced.
- Good — no workspace conversion, no new runtime deps; generation is dev-only tooling (not shipped).
- Cost — generation is asymmetric (brochure imports; VSCode generates) because of the `tsc rootDir` constraint;
  two bridges instead of one. Revisit if/when the repo adopts workspaces (a clean `@attack/rule-schema` package
  would let all three import directly).
- Follow-up — brochure consume; VSCode consume + generated JSON Schema; drift guard folding in the
  shipped-count guard.

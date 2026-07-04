# CLAUDE.md — 0x13d::att&ck (community edition)

Browser EDR as an MV3 extension: browser events → MITRE ATT&CK-mapped signatures → local alert + bounded
response. **The trust posture is the product**: zero host permissions, zero network egress, both enforced by
the build self-check in `apps/extension/build.mjs` — a build that gains a `fetch(` or a host permission fails.

## Layout

- `rules/` — the 16 community rules + pure detection + responses; published as `0x13d-attack-rules-community`.
- `apps/extension/` — the MV3 extension (engine, signal sources, popup/options). Consumes the rules package.
- `packages/rule-schema/` — `@attack/rule-schema`: declarative user-rule schema (types/validator/evaluator).
- `apps/vscode/` — rule-authoring VS Code extension; its JSON schema is **generated** (`npm run gen:schema`).
- `targets/` — benign per-technique demo targets + runbooks. A technique isn't done without its runbook.

## Build / verify

```bash
npm install            # links workspaces, builds rule-schema + rules dists (prepare)
npm run typecheck      # all workspaces
npm test               # rules package tests + extension tests
npm run build:extension  # → apps/extension/dist/ + trust self-check (must pass)
npm run check:schema   # fails if the generated VS Code schema drifted
```

## The detection model

`Signal<T>` (browser event) → `Rule<T>` = `technique` + `scope[]` + `signatures[]` + `responses[]` +
TTL/cascade. The engine (`apps/extension/src/engine.ts`) pumps signals to rules whose scope matches.
Detection logic stays **pure** (no `chrome.*`) in `rules/src/detection/` so it's unit-testable; only
responses and signal sources touch `chrome.*`.

## Gotchas

1. **Never add egress or host permissions** — the self-check will fail the build, and that's correct.
2. **Authored rules are data, never code** (ADR-002). Schema changes go in `packages/rule-schema` (single
   source, ADR-004); then `npm run build:schema && npm run gen:schema` — drift tests fail otherwise.
3. **Rules on the same `Scope` see the same signals.** Overlapping coverage is a feature, but check every
   same-scope rule when adding one: either both fire deliberately (document the `relationship`) or dedup by
   precedence (precedent: T1176.001 defers to T1176-tamper). When a rule changes an existing flow, update the
   affected `targets/` runbook in the same change.
4. **`Scope.WEB_REQUEST` / `Scope.CONTENT` are reserved** — no signal source feeds them in this repo; don't
   remove them from the schema (declarative-rule compatibility).

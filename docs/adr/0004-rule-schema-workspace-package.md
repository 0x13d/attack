---
status: "accepted"
date: 2026-06-16
decision-makers: architect
consulted: owner
informed: team
supersedes: ADR-003
---

# The rule schema is an npm workspace package consumed by all tools

## Context and Problem Statement

ADR-003 (one canonical module + a generator that emits mirrors, with a drift check) was the *pragmatic* answer
under a PATCH scope with no workspace. The owner chose to instead spend the structural change and adopt **npm
workspaces** — the cleaner long-term strategy that *eliminates* the duplicate copies rather than generating and
checking them. This supersedes ADR-003 (its `SCOPES` decouple + the JSON-Schema generator are kept and reused).

## Decision Drivers

* **No copies at all** — engine, brochure, and VSCode import one package; nothing to keep in sync by hand.
* **Zero new third-party runtime deps; trust posture intact** — the package is first-party, bundled into the
  consumers; it ships no external dependency.
* **Cross-toolchain reality** — esbuild (engine), Vite (brochure), tsx (engine tests), and tsc-emit-to-CJS
  (VSCode) must all resolve it; VSCode runs compiled CommonJS and can't relative-import a sibling `.ts`.

## Decision Outcome

A workspace package **`@attack/rule-schema`** (`packages/rule-schema`) holds the portable canonical schema:
`types` (incl. `OPS`/`SCOPES`/`SCHEMA_LIMITS`), `validate`, the safe `evaluate` (`resolveField`/
`evaluateCondition`), and `buildRuleJsonSchema`. The repo root gains a `package.json` with
`workspaces: [packages/*, src, apps/web, apps/vscode]`.

- **Engine + brochure** (esbuild / Vite / tsx — all bundle or transform TS) consume the package **source** via
  the `"import"`/`"types"` export condition → no package build needed, no build-order coupling.
- **VSCode** (tsc → CommonJS, runs `out/`) consumes the built **`dist`** (CJS + `.d.ts`) via the `"require"`
  condition — the only consumer that needs the package built, isolated from the site build.
- Engine-coupled glue (`signalView`, `compileAuthoredRule`) stays in the engine and imports the package. The
  engine's `apps/extension/src/schema/*` become thin re-export shims, so existing engine imports are unchanged.
- The JSON-Schema **generator** (from ADR-003) is kept; it now calls the package's `buildRuleJsonSchema`.

### Consequences

- Good — the schema genuinely has one source; the v0.8.0 VSCode `RESPONSE_IDS` drift can't recur. The
  ADR-0002 "can't drift" promise is finally structurally true.
- Good — no third-party runtime dependency; first-party package bundled into each consumer.
- Cost — build-infra churn: a root install/workspace, a `dist` build for the VSCode consumer, Makefile +
  trust-report/SBOM adjustments. A newly-disclosed `vite`/`esbuild` dev-toolchain advisory in `apps/web`
  surfaced during the install (tracked separately; build-time only).
- Follow-up — brochure consume; VSCode consume via `dist`; drift guard folding in the shipped-count guard +
  Makefile/trust-report updates.

# attack — extension (`src/`)

The Manifest V3 extension: a hand-rolled detection engine (zero runtime deps) that turns browser events into
`Signal`s, matches them against ATT&CK-mapped `Rule`s, and runs `Response`s (alert + active prevention).

## Build

```bash
npm install        # devDeps only: typescript, esbuild, @types/chrome (no runtime deps)
npm run typecheck  # tsc --noEmit (strict)
npm run build      # → dist/ (background.js + manifest.json)
```

## Load unpacked

- **Chrome:** `chrome://extensions/` → Developer mode → **Load unpacked** → `dist/`
- **Edge:** `edge://extensions/` → Developer mode → **Load unpacked** → `dist/`

## Layout

```
src/
  background.ts        service-worker entry — builds the engine, wires signal sources
  engine.ts            the idle→processing detection machine (cascade/TTL correlation)
  types.ts             the contracts — Scope, Signal, Signature, Rule, Response, Hit
  signals/             one module per Chrome event source → normalized Signals
    management.ts       chrome.management onInstalled/onEnabled (feeds T1176.001)
  rules/index.ts       the active rule set (flagship rule lands in ATK-003)
manifest.json          MV3 — scoped to only what shipped rules need (currently: management, notifications)
build.mjs              esbuild bundle + manifest copy → dist/
```

## Trust posture

Zero runtime dependencies; the manifest requests **only** the permissions a shipped rule needs. The only
network egress (added with the alert response) is the operator-configured SIEM/LME sink. See
[`../CLAUDE.md`](../CLAUDE.md) and ADR-001.

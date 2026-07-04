# 0x13d::att&ck — Rule Authoring (VSCode)

Author and validate **0x13d::att&ck** (Browser EDR) detection rules in VSCode. Rules are the same
**declarative schema** the extension loads (ADR-002) — data the engine interprets, never code it executes.

## Features

- **Live validation + completion + hover** for `*.attackrule.json` files (via a bundled JSON Schema).
- **0x13d::att&ck: New rule from template** — scaffold a rule.
- **0x13d::att&ck: Validate rule in active editor** — runs the semantic validator (response-id registry +
  DoS/size/depth caps) the JSON Schema can't express.
- **0x13d::att&ck: Run scenario harness** — runs the community corpus (`0x13d-attack-rules-community`) against
  the community rule set and renders a detection / false-positive report per technique in a panel. The same
  loop the CLI harness runs (`npm run scenarios`), surfaced in the editor for tuning.
- **0x13d::att&ck: Tune rule in active editor against the corpus** — validates and **compiles** the authored
  rule you're editing, runs it against the corpus cases for its scope, and reports how many known-malicious
  cases of its technique it catches and whether it trips any benign case. Narrow the condition to kill a false
  positive, broaden it to catch a missed case, re-run — a live tuning loop for the rule you're writing.
- An `attackrule` snippet.

## Use

1. Run **New rule from template** (or type `attackrule` and pick the snippet) and save as `something.attackrule.json`.
2. Edit with completion + inline validation.
3. **Validate**, then import the JSON in the extension's admin dashboard (the **Rules** page).

## Develop

```bash
npm install
npm run compile     # tsc → out/extension.js
# Press F5 in VSCode to launch an Extension Development Host.
```

## Source of truth

The authoritative validator is the extension's `src/src/schema/validate.ts`; `src/validate.ts` here is a
hand-synced port, and `schemas/attack-rule.schema.json` mirrors the structure. Single rule schema across
Blockly (brochure), this extension, and the engine loader.

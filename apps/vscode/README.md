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

## Install

Build the `.vsix` and install it into VS Code:

```bash
npm install
npm run package   # typecheck + bundle (esbuild) + vsce → _releases/vsix/attack-rule-authoring-<version>.vsix
code --install-extension ../../../../_releases/vsix/attack-rule-authoring-0.1.0.vsix
```

`npm run package` publishes the versioned `.vsix` into the central [`_releases/vsix/`](../../../../_releases)
local feed (the same feed the npm artifacts use), so it's not left loose in the repo. Or install from VS Code:
**Extensions** view → **⋯** menu → **Install from VSIX…** → pick the file. The extension is bundled into a
single self-contained `out/extension.js` (the workspace packages are inlined by esbuild), so the `.vsix` has
no `node_modules` and installs cleanly anywhere.

## Develop

```bash
npm install
npm run watch       # esbuild rebuild loop → out/extension.js
# Press F5 in VS Code to launch an Extension Development Host with the extension loaded.
npm run typecheck   # tsc --noEmit (esbuild does not type-check)
```

## Source of truth

The validator + rule schema are single-sourced in `@attack/rule-schema`, and the corpus + scenario runner come
from `0x13d-attack-rules-community` — both consumed directly, not re-copied. `schemas/attack-rule.schema.json`
is generated from the engine (`npm run gen:schema` at the repo root). One rule schema across the brochure
editor, this extension, and the engine loader.

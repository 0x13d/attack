<!-- Images use absolute raw URLs so they render on the VS Code Marketplace (relative paths don't). -->
<p align="center">
  <img src="https://raw.githubusercontent.com/0x13d/attack/main/apps/vscode/assets/logo.png" alt="0x13d::att&ck — Browser EDR rule authoring" width="460">
</p>

<p align="center">
  <a href="https://marketplace.visualstudio.com/items?itemName=ariugwu.attack-rule-authoring"><img src="https://img.shields.io/visual-studio-marketplace/v/ariugwu.attack-rule-authoring?label=VS%20Code%20Marketplace&logo=visualstudiocode&color=3A465F" alt="VS Code Marketplace"></a>
  <a href="https://www.npmjs.com/package/0x13d-attack-rules-community"><img src="https://img.shields.io/npm/v/0x13d-attack-rules-community?logo=npm&label=rules%20package&color=cb3837" alt="npm"></a>
  <a href="https://github.com/0x13d/attack/releases"><img src="https://img.shields.io/github/v/release/0x13d/attack?label=release&logo=github&color=3A465F" alt="Releases"></a>
  <a href="https://github.com/0x13d/attack/actions/workflows/ci.yml"><img src="https://github.com/0x13d/attack/actions/workflows/ci.yml/badge.svg" alt="Tests"></a>
  <a href="https://github.com/0x13d/attack/blob/main/apps/vscode/package.json"><img src="https://img.shields.io/github/package-json/v/0x13d/attack?filename=apps%2Fvscode%2Fpackage.json&label=version&color=3A465F" alt="Version"></a>
  <!-- Register the project at https://www.bestpractices.dev to get the real badge id, then swap this. -->
  <a href="https://www.bestpractices.dev/projects"><img src="https://img.shields.io/badge/OpenSSF_Best_Practices-in_progress-lightgrey" alt="OpenSSF Best Practices"></a>
  <a href="https://github.com/0x13d/attack/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-3A465F" alt="License: AGPL-3.0"></a>
</p>

<p align="center"><b>Author, validate, and tune 0x13d::att&ck (Browser EDR) detection rules — right in your editor.</b></p>

Detection rules for the [0x13d::att&ck](https://github.com/0x13d/attack) browser EDR are **declarative JSON**,
interpreted by the engine and never executed as code. This extension is the authoring surface for them: schema
validation and completion as you type, plus a **scenario harness** that runs your rule against a labeled corpus
and tells you what it catches and what it wrongly trips — a tuning loop without leaving VS Code.

<p align="center">
  <img src="https://raw.githubusercontent.com/0x13d/attack/main/apps/vscode/media/tuning-loop.png" alt="Tuning loop (placeholder — replace with an animated capture)" width="720">
</p>

## Features

- **Schema validation + completion + hover** for any `*.attackrule.json` file — scopes, ops, response ids, and
  the condition grammar, live as you type.
- **Validate** — the semantic checks a JSON Schema can't express (valid response ids, size/depth caps).
- **Tune against the corpus** — compiles the rule you're editing and runs it against the community scenario
  corpus for its scope: how many known-malicious cases it catches, and any benign case it trips (false
  positives). Narrow to kill an FP, broaden to catch a miss, re-run.
- **Run scenario harness** — the full community rule set vs. the corpus, per-technique detection / false-positive
  report in a panel.
- A **template command** and an `attackrule` snippet to start from.

## Quick start

### 1. Install

Grab the `.vsix` from the [`_releases/vsix`](https://github.com/0x13d/attack/tree/main/_releases) feed (or build
it with `npm run package` in `apps/vscode`), then:

```bash
code --install-extension attack-rule-authoring-0.1.0.vsix
```

Or in VS Code: **Extensions** view → **⋯** → **Install from VSIX…**.

### 2. Scaffold a rule

Command Palette (`⌘⇧P` / `Ctrl⇧P`) → **“0x13d::att&ck: New rule from template”**. **Save it with a
`.attackrule.json` suffix** — that's what turns on validation, completion, and hover.

### 3. Understand the shape

A rule is a small JSON object. An authored rule is **declarative data**, not code — it matches a `condition`
against the raw browser signal (the engine interprets it, never `eval`s it). Here's a working download rule:

```json
{
  "id": "user.flag-hta",
  "name": "Flag .hta downloads",
  "technique": "T1105",
  "scope": "download",
  "condition": { "field": "payload.filename", "op": "contains", "value": ".hta" },
  "responses": ["alert", "cancelDownload"],
  "enabled": true
}
```

A `field` is a dot-path over the signal — top-level `name` / `scope` / `tabId` / `windowId`, plus `payload.*`:

| scope | payload fields you can match |
|---|---|
| `download` | `payload.filename`, `payload.finalUrl`, `payload.mime`, `payload.referrer` |
| `management` | `payload.installType`, `payload.permissions` (array), `payload.hostPermissions` (array), `payload.name` |
| `webNavigation` | `payload.url`, `payload.transitionType` |
| `cookie` | `payload.cookie.name`, `payload.cookie.secure`, `payload.cookie.httpOnly`, `payload.cookie.sameSite`, `payload.cookie.session` |

> Stick to those four scopes — they have live signal sources in the community edition. `webRequest` / `content`
> are reserved for the commercial edition; `tab` / `window` aren't wired.

**Ops:** `eq` `ne` `exists` `in` `nin` `contains` `containsAny` `gt` `lt` `gte` `lte`
**Responses:** `alert` · `cancelDownload` · `closeTab` · `disableExtension` · `removeCookie` (pick ones that fit the scope)

Nest conditions with `all` / `any` / `not`:

```json
{
  "id": "user.webmail-macro-doc",
  "name": "Macro doc from webmail",
  "technique": "T1566.001",
  "scope": "download",
  "condition": {
    "all": [
      { "field": "payload.filename", "op": "contains", "value": ".docm" },
      { "field": "payload.referrer", "op": "contains", "value": "mail.google.com" }
    ]
  },
  "responses": ["alert"],
  "enabled": true
}
```

(Limits: ≤ 32 KB, ≤ 200 condition nodes — enforced by the validator.)

### 4. Validate & tune

- **“0x13d::att&ck: Validate rule in active editor”** — semantic check.
- **“0x13d::att&ck: Tune rule in active editor against the corpus”** — runs your rule against the corpus cases
  for its scope and shows detections + false positives. Your no-browser feedback loop.

<p align="center">
  <img src="https://raw.githubusercontent.com/0x13d/attack/main/apps/vscode/media/scenario-report.png" alt="Scenario report panel (placeholder)" width="720">
</p>

### 5. Load it into the EDR

Rules run in the **browser EDR extension** (`apps/extension`), not this authoring tool:

1. Load `apps/extension/dist/` unpacked in Chrome (`chrome://extensions` → **Load unpacked**).
2. Open its **Options** page → **“Add a rule”** → paste your JSON → **“Validate & add”**.

To watch it fire, run the matching demo under [`targets/`](https://github.com/0x13d/attack/tree/main/targets)
and follow its runbook.

## Commands

| Command | What it does |
|---|---|
| `0x13d::att&ck: New rule from template` | Scaffold a starter rule (save as `*.attackrule.json`). |
| `0x13d::att&ck: Validate rule in active editor` | Semantic validation of the open rule. |
| `0x13d::att&ck: Tune rule … against the corpus` | Compile + run the open rule vs. the corpus; detection / FP report. |
| `0x13d::att&ck: Run scenario harness …` | Full community rule set vs. the corpus; per-technique report. |

## Screenshots

| Authoring | Scenario report |
|---|---|
| ![authoring](https://raw.githubusercontent.com/0x13d/attack/main/apps/vscode/media/authoring.png) | ![report](https://raw.githubusercontent.com/0x13d/attack/main/apps/vscode/media/scenario-report.png) |

> The images above are placeholders — real captures land in [`apps/vscode/media/`](media/).

## Develop

```bash
npm install
npm run watch       # esbuild rebuild loop → out/extension.js
# Press F5 in VS Code to launch an Extension Development Host with the extension loaded.
npm run typecheck   # tsc --noEmit (esbuild doesn't type-check)
npm run package     # → _releases/vsix/attack-rule-authoring-<version>.vsix
```

The extension is bundled into a single self-contained `out/extension.js` (the workspace packages
`@attack/rule-schema` and `0x13d-attack-rules-community` are inlined by esbuild), so the `.vsix` carries no
`node_modules`. The rule schema, corpus, and scenario runner are single-sourced from those packages — never
re-copied.

## Links

- **Repo:** https://github.com/0x13d/attack · **Releases:** https://github.com/0x13d/attack/releases
- **Rules package (npm):** [`0x13d-attack-rules-community`](https://www.npmjs.com/package/0x13d-attack-rules-community)
- **Docs / wiki:** https://github.com/0x13d/attack/wiki

## License

[AGPL-3.0-only](LICENSE). Fully open, fully functional.

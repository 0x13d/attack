# 0x13d::att&ck — Browser EDR, community edition

**16 MITRE ATT&CK techniques detected (and where MV3 allows it, stopped) from inside the browser — with
zero host permissions and zero network egress, enforced by the build itself.**

A host EDR agent sits *outside* the browser and is blind to a whole class of modern initial-access and
persistence techniques that live *inside* it: rogue extension installs, OAuth consent phishing,
lookalike-login navigation, session-cookie theft. `att&ck` watches from inside — a Manifest V3 extension
that matches browser events against ATT&CK-mapped signatures, **alerts locally**, and **responds**: disable
a rogue extension, cancel a malicious download, kill a stolen session, close a phishing tab.

## The trust posture (the whole point)

- **Zero host permissions.** The manifest requests no `host_permissions`, no optional ones, no content scripts.
- **Zero network egress.** No telemetry, no analytics, no "check for updates", no alert shipping. Alerts stay
  in your browser (badge + popup + OS notification).
- **Mechanically enforced.** `build.mjs` fails the build if the bundle contains `fetch(`, any network API
  reference, or the manifest gains a host permission. Trust is a build gate, not a promise.
- **Rules are auditable data.** The 16 built-in rules are plain TypeScript in [`rules/`](rules/); user-authored
  rules are declarative JSON interpreted by the engine — never `eval`'d code ([ADR-002](docs/adr/0002-declarative-rule-schema.md)).

## Repository layout

| Path | What it is |
|---|---|
| [`rules/`](rules/) | **The community rule set** — 16 rules + pure detection logic + bounded responses. Published to npm as [`0x13d-attack-rules-community`](rules/README.md). Start here. |
| [`apps/extension/`](apps/extension/) | The MV3 extension (engine, signal sources, popup, admin/options page). |
| [`apps/vscode/`](apps/vscode/) | VS Code extension for authoring declarative user rules (schema + snippets). |
| [`packages/rule-schema/`](packages/rule-schema/) | `@attack/rule-schema` — the declarative rule schema: types, validator, safe evaluator. |
| [`targets/`](targets/) | Benign, reproducible demo targets + a runbook per technique — reproduce every detection locally. |
| [`docs/`](docs/) | [Coverage matrix](docs/MITRE-COVERAGE.md), [ADRs](docs/adr/), store-listing notes. |

## The 16 techniques

T1176.001 rogue extensions (+ T1176 tamper/re-enable) · T1566.002 spearphishing link ·
T1566.001 spearphishing attachment · T1566.003 spearphishing via service · T1539 session-cookie theft ·
T1550.004 web-session-cookie reuse · T1185 browser session hijacking · T1528 illicit OAuth consent ·
T1105 ingress tool transfer · T1204.001/.002 user execution (link/file) · T1189 drive-by compromise ·
T1656 impersonation · T1606.002 SAML web credentials · T1217 browser information discovery.

Full matrix with each rule's signal source, response, and overlap notes: [docs/MITRE-COVERAGE.md](docs/MITRE-COVERAGE.md).
Overlapping coverage across techniques is deliberate — each rule documents its relationship to its siblings
so you can mix, match, and tune instead of being locked into one vendor's labeling.

## Quick start

```bash
npm install                      # links workspaces + builds @attack/rule-schema and the rules package
npm test                         # rule/detection tests + extension tests
cd apps/extension && npm run build   # → dist/ — passes the trust self-check or fails loudly
```

Then load `apps/extension/dist/` via `chrome://extensions` → *Load unpacked* (Chrome or Edge). To see a
detection fire, pick any technique under [`targets/`](targets/) and follow its runbook.

## Using the rules without the extension

```bash
npm install 0x13d-attack-rules-community
```

Detection logic is pure and dependency-free (`assess*` functions under
`0x13d-attack-rules-community/detection/*`) — usable in any pipeline. The rule factories and responses
target an MV3 extension context. See [`rules/README.md`](rules/README.md).

## Licensing

[AGPL-3.0](LICENSE). Fully functional, fully open — nothing in this repo is crippled. A commercial edition
with additional techniques (requiring network- and page-level observation permissions that cross the
zero-host-permission trust line above) is available separately and is not part of this repository.

---
status: "accepted"
date: 2026-06-14
decision-makers: architect, security (CSO)
consulted: CPO, CMO, Chief Ethics
informed: team
---

# Detect-vs-prevent in MV3, the scoped manifest, an owned zero-dep engine, and replay-via-trace

## Context and Problem Statement

`attack` is a Browser EDR: an MV3 extension that turns browser events into signals, matches them against
MITRE ATT&CK signatures, and on a hit both **alerts** (to a SIEM/LME sink) and, where it can, **actively
responds**. Four foundational questions gate every technique and must be settled before the flagship
is built:

1. What can a Manifest V3 extension actually **prevent**, vs. only **detect**? "EDR" implies the "R"
   (response) — we must not oversell it.
2. What **permissions** should the extension request, given it's a security product whose own posture is the
   pitch?
3. What runs the detection — the lab's **xstate** engine, or something we own?
4. xstate was originally chosen partly for its **inspector/replay** (seeing the event sequence that led to an
   alert). If we drop it, how do we keep that?

## Decision Drivers

* **Trust signature** (CSO) — verifiable, offline, no telemetry, minimal supply chain, least privilege. The
  product *markets* security competence; its own hygiene must be exemplary.
* **Honest framing** (Ethics/CMO) — claims must match what MV3 can really do.
* **The real deployment** (owner) — in practice a client ships detection data to a SIEM; the shipped extension
  must be lean and auditable above all.
* **Legibility / "sell the concept"** (CMO) — a buyer needs to *see* the detection story, including replay.

## Decision Outcome

### 1. Detect everywhere; prevent through a bounded, enumerated set of MV3 levers

Detection is universal. **Active prevention** is only claimed where a concrete MV3 API stops the action.
Every rule states which it is and via which lever:

| Lever | API | Technique |
|---|---|---|
| Disable a rogue extension | `management.setEnabled(id, false)` | T1176.001 (flagship) |
| Block / redirect a request | `declarativeNetRequest` (static/dynamic ruleset) | T1566.002, T1528 |
| Kill / redirect a tab | `tabs.remove` / `tabs.update` | T1566.002 |
| Cancel / erase a download | `downloads.cancel` / `.erase` | T1105 |
| Kill a stolen session | `cookies.remove` | T1539 |

Everything else is **detect + alert**. ClickFix (T1204+T1059) is detect-only and needs a content script +
`clipboardRead` — deferred. No rule claims "prevention" without a lever in this table.

### 2. Scoped manifest — least privilege, per shipped technique

The extension requests **only** the permissions a *shipped* rule needs, each justified on its card. v0.1.0
ships `management` + `notifications` and **no `host_permissions`**. We do **not** carry the lab's
`<all_urls>` + everything. Adding a technique that needs a new permission is a reviewed change (security),
documented for the store-listing privacy justification (see `docs/PUBLISHING.md`).

### 3. Own the engine — hand-rolled, zero runtime dependencies

The detection engine is **our own** `idle → processing` machine (~60 lines, cascade/TTL correlation), with
**zero runtime dependencies**. We drop **xstate**.

* Good, because for a product whose pitch is "verifiable, auditable supply chain," the strongest possible
  claim is *nothing to audit but our own code*. The shipped artifact stays tiny (a ~2.6 kb worker).
* Good, because least-dependency is least-attack-surface — fitting for a security agent.
* Neutral, because the engine's logic is simple enough that a framework added ceremony, not safety.
* Cost, because we give up xstate's **inspector/replay** — addressed in (4).

### 4. Preserve replay with an engine event-trace; put all viz tooling on the brochure

xstate's real value here was *visualizing the event/attack sequence that led to an alert, and replaying it*.
We keep that value **without** the dependency, and **without** putting any visualization weight in the
shipped extension:

* The engine emits a **serializable, append-only event trace** — the ordered `Signal`s it processed and the
  `Hit`s they produced, with timestamps — bounded in memory and exportable as JSON. This is data,
  not code: zero new deps in the extension.
* **All rich tooling lives on the demo/brochure site**, never bundled into the extension: the
  Blockly visual rule editor and the amCharts 5 **detection-chain Gantt + replay** / **serpentine
  timeline** / **correlated story dashboard**. They consume the rule schema and the
  event-trace JSON — the two clean boundaries between the lean product and the sales surface.

This is the **owner architecture**: the extension is the clean, vetted core (it just ships detection data to
a SIEM); the brochure is where we *sell the concept* with replayable, correlated storytelling.

### Consequences

* Good — exemplary trust posture: zero-runtime-dep extension, least-privilege manifest, single declared
  egress (the operator-configured alert sink).
* Good — honest, enumerable prevention claims; marketing can't outrun the code.
* Good — replay/visualization is preserved and actually *better* for selling (Gantt + timeline + linked
  cursor), while the shipped artifact stays minimal.
* Cost — we maintain our own engine (small) and must keep the event-trace schema stable as a contract the
  brochure depends on (versioned, like the rule schema).
* Follow-up — the engine event-trace, the T1176.001 flagship rule, and the store-listing privacy
  justification (`docs/PUBLISHING.md`) all build on these decisions.

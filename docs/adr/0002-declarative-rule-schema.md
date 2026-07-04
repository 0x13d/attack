---
status: "accepted"
date: 2026-06-14
decision-makers: architect, security (CSO)
consulted: CPO
informed: team
---

# Authored rules are a declarative schema the engine safely evaluates — never executed code

## Context and Problem Statement

Users will author detection rules (a Blockly editor, a VSCode extension) and load them
into the extension through an admin dashboard. How should an authored rule be represented and run?
The lab's original schema stored the signature's `process` as a **string of JavaScript** that gets `eval`'d —
acceptable for a skunkworks, unacceptable for a shipped security product: importing and executing arbitrary
code is the exact attack class this extension exists to detect.

## Decision Drivers

* **Trust posture (CSO).** No `eval` / `new Function` / dynamic code, ever. A rule a user imports must not be
  able to run code in the extension's privileged context.
* **One schema, many authors.** Blockly, VSCode, and the engine loader must share a single rule format.
* **Auditable + bounded.** A malformed or hostile rule must be rejected with a reason; evaluation must not
  hang or blow the stack.
* **Expressive enough** for the real techniques (field comparisons, set membership, AND/OR/NOT).

## Decision Outcome

An authored rule is **declarative data**. Its condition is a small AST the engine **interprets**; its
responses and scope are **ids resolved against a fixed registry**. The extension never executes authored code.

### The rule schema

```jsonc
{
  "id": "...", "name": "...", "technique": "T1176.001",
  "scope": "management",
  "condition": {                       // a Condition AST (below)
    "any": [
      { "field": "payload.installType", "op": "in", "value": ["development", "sideload"] },
      { "field": "payload.permissions", "op": "containsAny", "value": ["debugger", "cookies"] }
    ]
  },
  "responses": ["alert", "disableExtension"],   // ids from the response registry — NOT code
  "enabled": true
}
```

**Condition AST** (recursive): `{ all: Condition[] }` · `{ any: Condition[] }` · `{ not: Condition }` · or a
leaf `{ field, op, value }`. **Ops** (a fixed, safe set): `eq ne exists in nin contains containsAny gt lt gte
lte`. No regex/code in v1 (regex deferred — ReDoS surface; code never).

### How it's evaluated (the safe interpreter)

- `field` is a dot-path resolved over a **normalized view** of the signal (`{ name, scope, tabId, windowId,
  payload }`). Path resolution **blocks `__proto__` / `constructor` / `prototype`** so a rule can't walk into
  the prototype chain.
- Each op is a plain comparison in a `switch` — no dynamic dispatch, no code from the rule.
- The compiler turns an authored rule into a runtime `Rule` whose `signature.process = (signal) =>
  evaluateCondition(condition, view(signal))`, and whose `responses` are looked up in the **response
  registry** (`alert`, `disableExtension`, …). Unknown response ids → the rule is rejected.

### Validation (before anything loads)

`validateAuthoredRule` rejects with reasons when: required fields missing; `scope` not a known `Scope`; a
response id not in the registry; the condition is malformed; the **condition exceeds a node/`depth` cap**
(stack-safety) or the **JSON exceeds a size cap**. Only validated rules are stored or compiled.

### Persistence + provenance

User rules live in `chrome.storage.local` (`userRules`), separate from the built-in code rules. The engine
loads built-ins first, then compiles + registers enabled user rules. In **managed-policy mode**
`allowUserRules:false` disables import + ignores stored user rules.

### Consequences

- Good — importing a rule can never execute code; the worst a hostile rule does is match weirdly, bounded by
  validation. The trust story stays intact for the headline authoring feature.
- Good — one schema is the contract shared by the Blockly editor, the VSCode extension, the admin dashboard,
  and the engine. The editors and the extension can't drift.
- Cost — the condition language is less expressive than arbitrary code (no regex yet); real techniques needing
  more (lookalike-domain regex for T1566.002) ship as **built-in code rules**, not user-authored, until the
  schema grows a safe `matches`.
- Follow-up — the admin page implements validate/evaluate/compile; managed-policy mode gates user rules; the
  Blockly and VSCode editors emit this schema.

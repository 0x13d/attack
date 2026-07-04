# 0x13d-attack-rules-community

The **0x13d::att&ck community rule set**: 16 MITRE ATT&CK browser-EDR detection rules — each one a rule
definition, pure detection logic, and a bounded response — extracted as a standalone package so you can
consume the rules without the extension.

```bash
npm install 0x13d-attack-rules-community
```

## What's inside

- **`buildRules(policy)`** — the full 16-rule community set for an effective `Policy`.
- **`makeT…Rule(policy)`** — every rule individually (`makeT1566Rule`, `makeT1539Rule`, …). Mix and match.
- **Pure detection logic** — `0x13d-attack-rules-community/detection/*` exposes the `assess*` functions
  (lookalike-domain scoring, cookie-flag analysis, redirect-chain detection, …). No `chrome.*` calls, no DOM,
  no dependencies — they run anywhere JS runs, which is also how the test suite exercises them.
- **Responses** — `alert` (local notification + log), `closeTab`, `cancelDownload`, `disableExtension`,
  `removeCookie`. These run in an MV3 extension context (they call `chrome.*` APIs).
- **`Policy` / `DEFAULT_POLICY`** — the tuning surface: protected domains, risky download extensions,
  OAuth scope lists, thresholds. Every rule reads its knobs from here; overriding the policy is how you
  tune for your environment.

## The contract

```ts
import { buildRules, DEFAULT_POLICY, Scope, type Signal } from '0x13d-attack-rules-community';

const rules = buildRules({ ...DEFAULT_POLICY, protectedDomains: ['acme.com'] });
// Feed rules signals: { id, name, scope, payload, tabId, windowId, timestamp, hits } —
// each rule declares the Scope[] it listens on; signature.process(signal) decides a match.
```

A `Rule` = `technique` (ATT&CK id) + `scope[]` + `signatures[]` + `responses[]` + TTL/cascade metadata.
The reference engine that pumps browser events through the rules lives in the
[extension](../apps/extension/) in this repo; the rules themselves don't depend on it.

## Trust posture

The community rule set requires **zero host permissions** and performs **zero network egress** — detection
is local, alerts are local. That claim is enforced mechanically by the extension's build self-check.

## Tuning & overlap

Some techniques intentionally overlap (e.g. the three phishing rules key on different signals: host
lookalike vs. delivery referrer vs. open-redirect). Each rule's doc comment states its `relationship` to
its siblings so you can dedup by precedence or ship breadth and tune downstream. The per-technique demo
targets + runbooks in [`targets/`](../targets/) reproduce every detection — and are the fixture set for
false-positive tuning.

## Autonomous scenario harness

The package ships a labeled **corpus** (`CORPUS`) covering all 16 techniques — malicious cases that should fire
and benign false-positive tripwires that must not — and a **runner** (`runScenarios`) that drives the real
`buildRules()` engine and reports per-technique detection and false-positive rates. No browser, no human:

```bash
npm run scenarios            # summary table (from rules/)
npm run scenarios -- --verbose   # + every misclassified case
npm run scenarios -- --json      # machine-readable ScenarioReport (for tooling / CI)
```

```
  technique     detect(TP/mal)   false-pos(FP/benign)
  T1105               3/3               0/3
  T1528               2/2               0/2
  T1566.002           3/3               0/3
  ...
  TOTAL: 59 cases — detection 33/33, false positives 0/26
  ✓ clean: every malicious case fired, every benign case stayed silent.
```

Both are exported from the package, so any tool can drive the same loop:

```ts
import { buildRules, runScenarios, CORPUS } from '0x13d-attack-rules-community';
const report = runScenarios(buildRules(), CORPUS);   // report.byTechnique, report.results, report.clean
```

This is the tuning loop: add a realistic benign case that trips a rule, watch the FP count rise, tighten the
policy or heuristic, and re-run until detections hold and false positives return to zero. The corpus is plain
JSON-serializable data (`src/scenarios/corpus.ts`) — grow it to harden a rule, or ship your own. A unit test
(`scenarios.test.ts`) keeps the shipped corpus clean in CI.

### Tuning your own authored rules

The package also compiles a declarative **authored rule** (the `@attack/rule-schema` format) into a runnable
`Rule`, so you can drive *your* rule through the same corpus:

```ts
import { compileAuthoredRule } from '0x13d-attack-rules-community/compile';
import { buildResponseRegistry, runScenarios, CORPUS } from '0x13d-attack-rules-community';

const rule = compileAuthoredRule(myAuthoredRule, buildResponseRegistry());
const forMyScope = CORPUS.filter((c) => rule.scope.includes(c.scope));
const report = runScenarios([rule], forMyScope);   // did it catch the malicious cases? trip any benign one?
```

The **VS Code rule-authoring extension** wraps exactly this: *"Run scenario harness"* shows the full community
report, and *"Tune rule against the corpus"* compiles the rule in your editor and reports its detections and
false positives live — so authoring and tuning share one engine.

## License

AGPL-3.0-only. Commercial licensing is available for organizations that can't accept AGPL terms.

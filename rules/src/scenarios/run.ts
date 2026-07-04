/**
 * The scenario runner — the shared engine behind both the CLI harness (`npm run scenarios`) and any tool that
 * wants a feedback loop (e.g. the VS Code rule builder). Drives a set of rules with a labeled corpus of
 * synthetic signals and reports, per technique, detection and false-positive rates. No browser, no human.
 *
 * A malicious case counts as DETECTED when the rule for its labeled technique fires. A benign case counts as
 * a FALSE POSITIVE when *any* rule fires. That split is what lets you tune: add a realistic benign case that
 * trips a rule, watch the FP rise, tighten the policy or heuristic, and re-run until it's silent again.
 */
import { Scope, type Rule, type Signal } from '../types';
import { markDisabledByEdr, __resetTamperState } from '../tamperState';

/** The signal name each scope's real source emits — several rules gate on the exact name. */
export const SIGNAL_NAME: Record<string, string> = {
  [Scope.WEB_NAVIGATION]: 'webNavigation.committed',
  [Scope.DOWNLOAD]: 'download.created',
  [Scope.MANAGEMENT]: 'management.installed',
  [Scope.COOKIE]: 'cookie.set',
  [Scope.WEB_REQUEST]: 'webRequest.beforeRequest',
  [Scope.CONTENT]: 'content.observation',
};

/** One labeled corpus case — plain data, JSON-serializable so a corpus can be shipped, shared, and loaded. */
export interface ScenarioCase {
  /** Human label shown in reports. */
  label: string;
  /** The scope the signal arrives on. */
  scope: Scope;
  /** The signal payload the rule inspects. */
  payload: unknown;
  /** True if a rule is EXPECTED to fire; false if this is a benign false-positive tripwire. */
  malicious: boolean;
  /** The technique this case exercises (its rule is the one expected to fire when malicious). */
  technique: string;
  /** Override the default signal name for the scope (e.g. 'webNavigation.reverseTabnab', 'management.enabled'). */
  name?: string;
  /** Seed this extension id into the EDR-disabled set before running (for the T1176 tamper re-enable path). */
  seedEdrDisabledId?: string;
}

export interface TechniqueStat {
  technique: string;
  detected: number; // true positives
  missed: number; // false negatives
  falsePositives: number;
  benign: number; // total benign cases for this technique
  malicious: number; // total malicious cases for this technique
}

export interface CaseResult {
  label: string;
  technique: string;
  malicious: boolean;
  fired: string[]; // techniques whose rule fired
  outcome: 'detected' | 'missed' | 'false-positive' | 'clean';
}

export interface ScenarioReport {
  cases: number;
  detected: number;
  missed: number;
  falsePositives: number;
  clean: boolean;
  byTechnique: TechniqueStat[];
  results: CaseResult[];
}

/** Ensure the minimal `chrome` a few rules touch (`chrome.runtime.id`) exists outside a browser. */
function ensureChromeStub(): void {
  const g = globalThis as unknown as { chrome?: { runtime?: { id?: string } } };
  g.chrome ??= { runtime: { id: 'self-edr-id' } };
}

let uuid = 0;

/** Which techniques' rules fire on a single case, running it through the given rule set. */
function firedTechniques(rules: Rule<unknown>[], c: ScenarioCase): string[] {
  if (c.seedEdrDisabledId) markDisabledByEdr(c.seedEdrDisabledId);
  const signal: Signal<unknown> = {
    id: `s${uuid++}`,
    name: c.name ?? SIGNAL_NAME[c.scope] ?? c.scope,
    scope: c.scope,
    payload: c.payload,
    tabId: 1,
    windowId: 1,
    timestamp: 1,
    hits: [],
  };
  const fired = new Set<string>();
  for (const rule of rules) {
    if (!rule.scope.includes(c.scope)) continue;
    for (const sig of rule.signatures) {
      if (sig.scope !== c.scope) continue;
      try {
        if (sig.process(signal)) fired.add(rule.technique);
      } catch {
        /* detection must never throw; a throw is treated as no-match */
      }
    }
  }
  if (c.seedEdrDisabledId) __resetTamperState();
  return [...fired];
}

/** Run a corpus against a rule set and return a structured report. */
export function runScenarios(rules: Rule<unknown>[], corpus: ScenarioCase[]): ScenarioReport {
  ensureChromeStub();
  const stats = new Map<string, TechniqueStat>();
  const stat = (t: string): TechniqueStat =>
    stats.get(t) ?? stats.set(t, { technique: t, detected: 0, missed: 0, falsePositives: 0, benign: 0, malicious: 0 }).get(t)!;

  const results: CaseResult[] = [];
  for (const c of corpus) {
    const fired = firedTechniques(rules, c);
    const s = stat(c.technique);
    let outcome: CaseResult['outcome'];
    if (c.malicious) {
      s.malicious++;
      if (fired.includes(c.technique)) { s.detected++; outcome = 'detected'; }
      else { s.missed++; outcome = 'missed'; }
    } else {
      s.benign++;
      if (fired.length > 0) { s.falsePositives++; outcome = 'false-positive'; }
      else outcome = 'clean';
    }
    results.push({ label: c.label, technique: c.technique, malicious: c.malicious, fired, outcome });
  }

  const byTechnique = [...stats.values()].sort((a, b) => a.technique.localeCompare(b.technique));
  const detected = byTechnique.reduce((n, s) => n + s.detected, 0);
  const missed = byTechnique.reduce((n, s) => n + s.missed, 0);
  const falsePositives = byTechnique.reduce((n, s) => n + s.falsePositives, 0);
  return { cases: corpus.length, detected, missed, falsePositives, clean: missed + falsePositives === 0, byTechnique, results };
}

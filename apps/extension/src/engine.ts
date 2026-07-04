import { Rule, Scope, Signal } from '0x13d-attack-rules-community';
import { Tracer, TraceDocument } from './trace';

/** A serializable summary of a rule for the admin dashboard (no functions). */
export interface RuleSummary {
  id: string;
  name: string;
  technique: string;
  scope: Scope[];
}

/**
 * The detection engine — a hand-rolled `idle → processing` machine (zero runtime deps).
 *
 * Flow: a signal source calls {@link Engine.processSignal}; every rule whose scope includes the signal's
 * scope is evaluated; a matched signature records a `Hit` and fires the rule's responses. A **cascade** rule
 * only fires once every correlated rule has been hit within its `timeToLive`.
 *
 * Signature predicates and response actions are sandboxed in try/catch so one bad rule can't crash the
 * service worker — a security agent must stay up.
 */
export class Engine {
  /** Built-in (code) rules — registered once at startup. */
  private rules: Rule<unknown>[] = [];
  /** Compiled user rules (from the declarative schema) — hot-swappable from the admin dashboard. */
  private userRules: Rule<unknown>[] = [];
  /** ruleId → first-hit timestamp, for cascade TTL correlation. */
  private cascadeCache: Record<string, number> = {};

  constructor(private readonly tracer: Tracer = new Tracer()) {}

  registerRules(rules: Rule<unknown>[]): void {
    this.rules.push(...rules);
  }

  /** Replace the user-rule set (ADR-002 / ATK-207). Called at startup and on a reload from the admin page. */
  setUserRules(rules: Rule<unknown>[]): void {
    this.userRules = rules;
  }

  /** A safe summary of the active rules for the admin dashboard (no functions). */
  describeRules(): { builtin: RuleSummary[]; user: RuleSummary[] } {
    const sum = (r: Rule<unknown>): RuleSummary => ({ id: r.id, name: r.name, technique: r.technique, scope: r.scope });
    return { builtin: this.rules.map(sum), user: this.userRules.map(sum) };
  }

  processSignal(signal: Signal<unknown>): void {
    this.tracer.recordSignal(signal);
    for (const rule of [...this.rules, ...this.userRules]) {
      if (!rule.scope.includes(signal.scope)) continue;
      for (const signature of rule.signatures) {
        if (signature.scope !== signal.scope) continue;
        let matched = false;
        try {
          matched = signature.process(signal);
        } catch (err) {
          console.error(`[attack] signature ${signature.id} threw`, err);
          continue;
        }
        if (!matched) continue;
        signal.hits.push({ ruleId: rule.id, signatureId: signature.id, signalId: signal.id });
        this.tracer.recordHit(signal, rule, signature);
        this.fire(rule, signal);
      }
    }
  }

  /** A serializable snapshot of the recent Signal→Hit chain — the replay input (ATK-203/204/205, ATK-207). */
  getTrace(): TraceDocument {
    return this.tracer.snapshot();
  }

  /** Run a rule's responses, honoring cascade/TTL correlation. */
  private fire(rule: Rule<unknown>, signal: Signal<unknown>): void {
    if (rule.cascade.enabled) {
      const now = Date.now();
      if (this.cascadeCache[rule.id] === undefined) this.cascadeCache[rule.id] = now;
      const allFreshlyHit = rule.cascade.ruleIds.every((id) => {
        const firstHit = this.cascadeCache[id];
        return firstHit !== undefined && now - firstHit <= rule.timeToLive;
      });
      if (!allFreshlyHit) return;
      // Correlation satisfied — reset so the cascade must re-accumulate before firing again.
      for (const id of rule.cascade.ruleIds) delete this.cascadeCache[id];
    }

    for (const response of rule.responses) {
      try {
        response.action(rule, signal);
      } catch (err) {
        console.error(`[attack] response ${response.id} threw`, err);
      }
    }
  }
}

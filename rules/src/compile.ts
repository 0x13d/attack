/**
 * Compile a **validated** authored rule (the declarative `@attack/rule-schema` format) into a runtime `Rule`
 * (ADR-002). The signature is a thunk over the schema package's safe condition interpreter; the responses are
 * resolved from a registry by id. No authored code is ever produced or executed.
 *
 * This bridges the two packages — the declarative data format (`@attack/rule-schema`) and the runtime
 * detection contracts (this package) — so it lives here, on the runtime side. It's exposed as a subpath
 * (`0x13d-attack-rules-community/compile`) so the core rule set doesn't pull the schema package unless a
 * consumer actually compiles authored rules. Both the extension (real responses) and the scenario harness /
 * VS Code builder (tuning, where responses never fire) use it.
 */
import { evaluateCondition, type AuthoredRule } from '@attack/rule-schema';
import { Response, Rule, Scope, Signal, Signature } from './types';

/** The normalized object an authored rule's `field` dot-path resolves over. */
export function signalView(signal: Signal<unknown>): Record<string, unknown> {
  return {
    name: signal.name,
    scope: signal.scope,
    tabId: signal.tabId,
    windowId: signal.windowId,
    payload: signal.payload,
  };
}

/** Compile a validated authored rule into a runtime `Rule`, resolving responses from the given registry. */
export function compileAuthoredRule(authored: AuthoredRule, registry: Map<string, Response<unknown>>): Rule<unknown> {
  const scope = authored.scope as Scope;

  const signature: Signature<unknown> = {
    id: `${authored.id}.sig`,
    name: authored.name,
    scope,
    process: (signal: Signal<unknown>) => evaluateCondition(authored.condition, signalView(signal)),
  };

  const responses = authored.responses
    .map((id) => registry.get(id))
    .filter((r): r is Response<unknown> => r !== undefined);

  return {
    id: authored.id,
    name: authored.name,
    technique: authored.technique,
    scope: [scope],
    signatures: [signature],
    responses,
    timeToLive: 3_600_000,
    cascade: { enabled: false, ruleIds: [] },
  };
}

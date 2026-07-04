import { Response, Rule, Scope, Signal, Signature } from '0x13d-attack-rules-community';
import { evaluateCondition, signalView } from './evaluate';
import { AuthoredRule } from './types';

/**
 * Compile a **validated** authored rule into a runtime `Rule` (ADR-002). The signature is a thunk over the
 * safe interpreter; the responses are resolved from the registry by id. No authored code is ever produced.
 */
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

import { Signal } from '0x13d-attack-rules-community';

/**
 * Engine-side glue for the safe interpreter. The interpreter itself (`resolveField`, `evaluateCondition`) lives
 * in `@attack/rule-schema` (ADR-004); only `signalView` is engine-specific (it reads a `Signal`), so it stays
 * here. Re-exported so `compile.ts` and callers keep importing from `./evaluate`.
 */
export { resolveField, evaluateCondition } from '@attack/rule-schema';

/** The normalized object a `field` dot-path resolves over. */
export function signalView(signal: Signal<unknown>): Record<string, unknown> {
  return {
    name: signal.name,
    scope: signal.scope,
    tabId: signal.tabId,
    windowId: signal.windowId,
    payload: signal.payload,
  };
}

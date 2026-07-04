/**
 * Re-export the safe interpreter (`resolveField`, `evaluateCondition` from `@attack/rule-schema`) plus the
 * `signalView` glue, which now lives with the compiler in `0x13d-attack-rules-community/compile` (it reads a
 * rules-package `Signal`). Thin shim so `compile.ts` and the tests keep importing from `./evaluate`.
 */
export { resolveField, evaluateCondition } from '@attack/rule-schema';
export { signalView } from '0x13d-attack-rules-community/compile';

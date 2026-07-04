/**
 * Re-export the canonical validator from `@attack/rule-schema` (ADR-004). The engine calls
 * `validateAuthoredRule(input, RESPONSE_IDS)` (see `userRules.ts`), passing the response ids derived from its
 * live registry.
 */
export { validateAuthoredRule } from '@attack/rule-schema';
export type { ValidationResult } from '@attack/rule-schema';
export type { AuthoredRule } from '@attack/rule-schema';

/**
 * Authored-rule validator for the VSCode extension. A thin wrapper over the **canonical** validator in
 * `@attack/rule-schema` (ADR-004) — no duplicated logic, no hand-maintained scope/op/limit lists. The valid
 * response ids come from the generated `responseIds.generated.ts` (derived from the engine's live response
 * registry), so the editor and the engine can't drift (this fixes the v0.8.0 `RESPONSE_IDS` drift).
 */
import { validateAuthoredRule as validateCore, type ValidationResult } from '@attack/rule-schema';
import { RESPONSE_IDS } from './responseIds.generated';

const RESPONSE_ID_SET = new Set<string>(RESPONSE_IDS);

export type { ValidationResult };

export function validateAuthoredRule(input: unknown): ValidationResult {
  return validateCore(input, RESPONSE_ID_SET);
}

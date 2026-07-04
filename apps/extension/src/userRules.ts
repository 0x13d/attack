import { Policy, DEFAULT_POLICY } from '0x13d-attack-rules-community';
import { Engine } from './engine';
import { buildResponseRegistry, RESPONSE_IDS } from '0x13d-attack-rules-community';
import { compileAuthoredRule } from './schema/compile';
import { AuthoredRule } from './schema/types';
import { validateAuthoredRule, ValidationResult } from './schema/validate';

/**
 * User-authored (declarative) rules — stored in `chrome.storage.local`, separate from the built-in code
 * rules. The engine loads built-ins, then compiles + installs the enabled, valid user rules (ADR-002 /
 * ATK-207). In enterprise managed mode (`ATK-208`) `allowUserRules:false` will skip this entirely.
 */
const KEY = 'userRules';

export async function getUserRules(): Promise<AuthoredRule[]> {
  const stored = await chrome.storage.local.get(KEY);
  return (stored[KEY] as AuthoredRule[] | undefined) ?? [];
}

export async function setUserRules(rules: AuthoredRule[]): Promise<void> {
  await chrome.storage.local.set({ [KEY]: rules });
}

/** Validate an imported rule against the response registry (the admin page calls this before saving). */
export function validateRule(input: unknown): ValidationResult {
  return validateAuthoredRule(input, RESPONSE_IDS);
}

/** Compile the enabled, valid user rules and install them into the engine (startup + reload). */
export async function loadUserRulesInto(engine: Engine, policy: Policy = DEFAULT_POLICY): Promise<void> {
  const registry = buildResponseRegistry(policy);
  const authored = await getUserRules();
  const compiled = authored
    .filter((r) => r.enabled !== false)
    .filter((r) => validateAuthoredRule(r, RESPONSE_IDS).ok)
    .map((r) => compileAuthoredRule(r, registry));
  engine.setUserRules(compiled);
}

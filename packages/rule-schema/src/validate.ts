import { AuthoredRule, LeafCondition, OPS, Op, SCHEMA_LIMITS, SCOPES } from './types';

/**
 * Validate an authored rule **before** it is stored or compiled (ADR-002). Rejects malformed, oversized, or
 * unsafe rules with human-readable reasons. This is the gate that keeps a hostile import bounded. The valid
 * response ids are passed in by the caller (the engine derives them from its live response registry) so this
 * module stays free of engine code.
 */
export interface ValidationResult {
  ok: boolean;
  errors: string[];
}

const SCOPE_SET = new Set<string>(SCOPES);

export function validateAuthoredRule(input: unknown, knownResponseIds: ReadonlySet<string>): ValidationResult {
  const errors: string[] = [];

  // Size cap first — cheap DoS guard before we walk anything.
  if (byteLength(safeStringify(input)) > SCHEMA_LIMITS.maxJsonBytes) {
    return { ok: false, errors: [`rule exceeds ${SCHEMA_LIMITS.maxJsonBytes} bytes`] };
  }

  if (!isObject(input)) return { ok: false, errors: ['rule must be an object'] };
  const rule = input as Partial<AuthoredRule>;

  for (const key of ['id', 'name', 'technique', 'scope'] as const) {
    if (typeof rule[key] !== 'string' || (rule[key] as string).length === 0) errors.push(`"${key}" must be a non-empty string`);
  }
  if (typeof rule.scope === 'string' && !SCOPE_SET.has(rule.scope)) errors.push(`"scope" is not a known scope: ${rule.scope}`);

  if (!Array.isArray(rule.responses) || rule.responses.length === 0) {
    errors.push('"responses" must be a non-empty array of response ids');
  } else {
    for (const r of rule.responses) {
      if (typeof r !== 'string' || !knownResponseIds.has(r)) errors.push(`unknown response id: ${JSON.stringify(r)}`);
    }
  }

  if (rule.enabled !== undefined && typeof rule.enabled !== 'boolean') errors.push('"enabled" must be a boolean');

  if (rule.condition === undefined) {
    errors.push('"condition" is required');
  } else {
    const counter = { nodes: 0 };
    validateCondition(rule.condition, 0, counter, errors);
  }

  return { ok: errors.length === 0, errors };
}

function validateCondition(cond: unknown, depth: number, counter: { nodes: number }, errors: string[]): void {
  if (depth > SCHEMA_LIMITS.maxConditionDepth) {
    errors.push(`condition nesting exceeds depth ${SCHEMA_LIMITS.maxConditionDepth}`);
    return;
  }
  if (++counter.nodes > SCHEMA_LIMITS.maxConditionNodes) {
    errors.push(`condition exceeds ${SCHEMA_LIMITS.maxConditionNodes} nodes`);
    return;
  }
  if (!isObject(cond)) {
    errors.push('each condition must be an object');
    return;
  }
  const c = cond as Record<string, unknown>;

  if ('all' in c || 'any' in c) {
    const arr = (c.all ?? c.any) as unknown;
    if (!Array.isArray(arr) || arr.length === 0) {
      errors.push('"all"/"any" must be a non-empty array');
      return;
    }
    for (const sub of arr) validateCondition(sub, depth + 1, counter, errors);
    return;
  }
  if ('not' in c) {
    validateCondition(c.not, depth + 1, counter, errors);
    return;
  }

  // Leaf
  const leaf = c as Partial<LeafCondition>;
  if (typeof leaf.field !== 'string' || leaf.field.length === 0) errors.push('leaf condition needs a "field" string');
  if (typeof leaf.op !== 'string' || !OPS.includes(leaf.op as Op)) errors.push(`leaf condition has an unknown op: ${JSON.stringify(leaf.op)}`);
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function safeStringify(v: unknown): string {
  try {
    return JSON.stringify(v) ?? '';
  } catch {
    return '';
  }
}

function byteLength(s: string): number {
  return new TextEncoder().encode(s).length;
}

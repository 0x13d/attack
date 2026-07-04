import { Condition, JsonValue, LeafCondition, Op } from './types';

/**
 * The safe interpreter for a declarative `Condition` (ADR-002). Pure, dependency-free, no code execution.
 * Operates on a plain normalized view object — the engine builds that view (`signalView`) from a `Signal`;
 * this module stays free of any engine/chrome types so it can be shared.
 */

const BLOCKED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/** Resolve a dot-path, blocking any walk into the prototype chain. Returns undefined on a miss. */
export function resolveField(path: string, root: unknown): unknown {
  let cur: unknown = root;
  for (const key of path.split('.')) {
    if (cur === null || cur === undefined) return undefined;
    if (BLOCKED_KEYS.has(key)) return undefined;
    if (typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[key];
  }
  return cur;
}

function applyOp(op: Op, actual: unknown, value: JsonValue | undefined): boolean {
  switch (op) {
    case 'eq':
      return actual === value;
    case 'ne':
      return actual !== value;
    case 'exists':
      return actual !== undefined && actual !== null;
    case 'in':
      return Array.isArray(value) && (value as unknown[]).includes(actual);
    case 'nin':
      return Array.isArray(value) && !(value as unknown[]).includes(actual);
    case 'contains':
      if (Array.isArray(actual)) return (actual as unknown[]).includes(value);
      if (typeof actual === 'string') return actual.includes(String(value));
      return false;
    case 'containsAny':
      if (Array.isArray(actual) && Array.isArray(value)) {
        const set = new Set(value as unknown[]);
        return (actual as unknown[]).some((a) => set.has(a));
      }
      return false;
    case 'gt':
      return typeof actual === 'number' && actual > Number(value);
    case 'lt':
      return typeof actual === 'number' && actual < Number(value);
    case 'gte':
      return typeof actual === 'number' && actual >= Number(value);
    case 'lte':
      return typeof actual === 'number' && actual <= Number(value);
    default:
      return false;
  }
}

/** Evaluate a condition AST against a normalized view. Assumes the condition was validated. */
export function evaluateCondition(cond: Condition, view: Record<string, unknown>): boolean {
  if ('all' in cond) return cond.all.every((c) => evaluateCondition(c, view));
  if ('any' in cond) return cond.any.some((c) => evaluateCondition(c, view));
  if ('not' in cond) return !evaluateCondition(cond.not, view);
  const leaf = cond as LeafCondition;
  return applyOp(leaf.op, resolveField(leaf.field, view), leaf.value);
}

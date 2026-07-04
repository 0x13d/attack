/**
 * `@attack/rule-schema` — the single canonical declarative rule schema (ADR-004). Imported directly by the
 * engine, the brochure, and (via the built `dist`) the VSCode extension. No engine/chrome deps.
 */
export type { JsonValue, Op, LeafCondition, Condition, AuthoredRule, ScopeName } from './types';
export { OPS, SCOPES, SCHEMA_LIMITS } from './types';
export { validateAuthoredRule } from './validate';
export type { ValidationResult } from './validate';
export { resolveField, evaluateCondition } from './evaluate';
export { buildRuleJsonSchema } from './json-schema';

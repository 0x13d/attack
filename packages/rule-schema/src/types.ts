/**
 * The declarative rule schema (ADR-002) — the **single canonical source** (ADR-004), shared by the engine,
 * the brochure, and VSCode. An authored rule is **data**: a condition AST the engine safely interprets, plus
 * scope + response *ids* resolved against fixed registries. No code is ever carried or run.
 *
 * Portable + dependency-free on purpose — nothing here imports the engine's chrome-coupled types, so every
 * consumer can import it directly.
 */

export type JsonValue = string | number | boolean | null | JsonValue[];

/** The fixed, safe comparison operators. No regex/code. */
export type Op = 'eq' | 'ne' | 'exists' | 'in' | 'nin' | 'contains' | 'containsAny' | 'gt' | 'lt' | 'gte' | 'lte';

export const OPS: readonly Op[] = ['eq', 'ne', 'exists', 'in', 'nin', 'contains', 'containsAny', 'gt', 'lt', 'gte', 'lte'];

/**
 * The valid rule scopes as portable data — the string values of the engine `Scope` enum. A guard test in the
 * engine (`scope-sync.test.ts`) pins this to `Object.values(Scope)` so it can't drift from the enum (ADR-003/004).
 * Add a member here **and** to the engine `Scope` when a new signal source is wired.
 */
export const SCOPES = ['management', 'webNavigation', 'cookie', 'download', 'tab', 'window', 'webRequest', 'content'] as const;
export type ScopeName = (typeof SCOPES)[number];

export interface LeafCondition {
  /** Dot-path over the normalized signal view, e.g. `payload.installType`, `payload.permissions`, `name`. */
  field: string;
  op: Op;
  value?: JsonValue;
}

export type Condition =
  | { all: Condition[] }
  | { any: Condition[] }
  | { not: Condition }
  | LeafCondition;

export interface AuthoredRule {
  id: string;
  name: string;
  technique: string;
  scope: string;
  condition: Condition;
  /** Ids resolved against the response registry — never code. */
  responses: string[];
  enabled?: boolean;
}

/** Limits that keep evaluation bounded + stack-safe (enforced by the validator). */
export const SCHEMA_LIMITS = {
  maxJsonBytes: 32 * 1024,
  maxConditionNodes: 200,
  maxConditionDepth: 24,
} as const;

/**
 * Re-export the canonical rule-schema types from `@attack/rule-schema` (ADR-004). The schema used to be
 * hand-synced across the engine, brochure, and VSCode; it now has one source. Engine code keeps importing
 * from `./types`/`./validate`/`./evaluate` — these are thin shims over the shared package.
 */
export type { JsonValue, Op, LeafCondition, Condition, AuthoredRule, ScopeName } from '@attack/rule-schema';
export { OPS, SCOPES, SCHEMA_LIMITS } from '@attack/rule-schema';

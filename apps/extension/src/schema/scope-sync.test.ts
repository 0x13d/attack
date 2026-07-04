import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SCOPES } from './types';
import { Scope } from '0x13d-attack-rules-community';

// ADR-003 guard: the portable SCOPES data (used by the validator + the generated JSON Schema/mirrors) must
// stay equal to the engine's chrome-coupled Scope enum. Add a signal source ⇒ update both; this fails otherwise.
test('schema SCOPES data matches the engine Scope enum', () => {
  assert.deepEqual([...SCOPES].sort(), Object.values(Scope).sort());
});

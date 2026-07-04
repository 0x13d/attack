import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mergePolicy, userRulesAllowed } from './managed';
import { DEFAULT_POLICY } from '0x13d-attack-rules-community';

test('no managed policy → base unchanged (individual mode)', () => {
  assert.deepEqual(mergePolicy(DEFAULT_POLICY, null), DEFAULT_POLICY);
  assert.equal(userRulesAllowed(null), true);
});

test('protectedDomains can be org-overridden', () => {
  const eff = mergePolicy(DEFAULT_POLICY, { protectedDomains: ['acme.com'] });
  assert.deepEqual(eff.protectedDomains, ['acme.com']);
});

test('managed policy without overrides leaves the base policy intact', () => {
  const eff = mergePolicy(DEFAULT_POLICY, { orgName: 'Acme' });
  assert.deepEqual(eff.protectedDomains, DEFAULT_POLICY.protectedDomains);
});

test('allowUserRules:false disables user rules; omitted/true allows them', () => {
  assert.equal(userRulesAllowed({ allowUserRules: false }), false);
  assert.equal(userRulesAllowed({ allowUserRules: true }), true);
  assert.equal(userRulesAllowed({ orgName: 'Acme' }), true); // default
});

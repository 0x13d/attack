import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compileAuthoredRule } from './compile';
import { buildResponseRegistry, RESPONSE_IDS } from './responses/registry';
import { runScenarios } from './scenarios/run';
import { CORPUS } from './scenarios/corpus';
import { Scope } from './types';
import { validateAuthoredRule } from '@attack/rule-schema';

const sideloadRule = {
  id: 'user.sideload-flag',
  name: 'Flag sideloaded extensions',
  technique: 'T1176.001',
  scope: 'management',
  condition: { field: 'payload.installType', op: 'eq', value: 'sideload' },
  responses: ['alert'],
  enabled: true,
};

test('an authored rule validates, compiles, and runs against the corpus', () => {
  assert.ok(validateAuthoredRule(sideloadRule, RESPONSE_IDS).ok);
  const rule = compileAuthoredRule(sideloadRule as never, buildResponseRegistry());
  assert.equal(rule.technique, 'T1176.001');
  assert.deepEqual(rule.scope, [Scope.MANAGEMENT]);

  const subset = CORPUS.filter((c) => rule.scope.includes(c.scope));
  const report = runScenarios([rule], subset);

  // The narrow rule catches the sideloaded case and trips no benign case (the tuning signal the builder shows).
  const detected = report.results.filter((r) => r.malicious && r.technique === 'T1176.001' && r.fired.length > 0);
  const falsePositives = report.results.filter((r) => !r.malicious && r.fired.length > 0);
  assert.ok(detected.length >= 1, 'should catch at least the sideloaded case');
  assert.equal(falsePositives.length, 0, 'should trip no benign management case');
});

test('compiled authored rule responses resolve from the registry (unknown ids dropped)', () => {
  const rule = compileAuthoredRule(sideloadRule as never, buildResponseRegistry());
  assert.equal(rule.responses.length, 1);
  assert.equal(rule.signatures.length, 1);
});

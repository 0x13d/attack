import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateCondition, resolveField, signalView } from './evaluate';
import { validateAuthoredRule } from './validate';
import { compileAuthoredRule } from './compile';
import { AuthoredRule, Condition, SCHEMA_LIMITS } from './types';
import { Engine } from '../engine';
import { Response, Rule, Scope, Signal } from '0x13d-attack-rules-community';

const RESPONSE_IDS = new Set(['alert', 'disableExtension']);

function mgmtSignal(payload: Record<string, unknown>): Signal<unknown> {
  return { id: crypto.randomUUID(), name: 'management.installed', tabId: -1, windowId: -1, payload, scope: Scope.MANAGEMENT, timestamp: 0, hits: [] };
}

// ---- evaluator -------------------------------------------------------------

test('resolveField reads nested payload fields and blocks the prototype chain', () => {
  const view = signalView(mgmtSignal({ installType: 'development', permissions: ['cookies'] }));
  assert.equal(resolveField('payload.installType', view), 'development');
  assert.deepEqual(resolveField('payload.permissions', view), ['cookies']);
  assert.equal(resolveField('payload.__proto__.polluted', view), undefined);
  assert.equal(resolveField('constructor.name', view), undefined);
});

test('ops: eq/ne/in/containsAny/exists', () => {
  const v = signalView(mgmtSignal({ installType: 'development', permissions: ['cookies', 'webRequest'] }));
  assert.equal(evaluateCondition({ field: 'payload.installType', op: 'eq', value: 'development' }, v), true);
  assert.equal(evaluateCondition({ field: 'payload.installType', op: 'ne', value: 'normal' }, v), true);
  assert.equal(evaluateCondition({ field: 'payload.installType', op: 'in', value: ['development', 'sideload'] }, v), true);
  assert.equal(evaluateCondition({ field: 'payload.permissions', op: 'containsAny', value: ['debugger', 'cookies'] }, v), true);
  assert.equal(evaluateCondition({ field: 'payload.permissions', op: 'containsAny', value: ['debugger'] }, v), false);
  assert.equal(evaluateCondition({ field: 'payload.missing', op: 'exists' }, v), false);
});

test('boolean composition all/any/not', () => {
  const v = signalView(mgmtSignal({ installType: 'development', permissions: [] }));
  const cond: Condition = {
    all: [
      { field: 'payload.installType', op: 'eq', value: 'development' },
      { not: { field: 'payload.permissions', op: 'containsAny', value: ['debugger'] } },
      { any: [{ field: 'scope', op: 'eq', value: 'management' }, { field: 'scope', op: 'eq', value: 'cookie' }] },
    ],
  };
  assert.equal(evaluateCondition(cond, v), true);
});

// ---- validator -------------------------------------------------------------

test('valid rule passes', () => {
  const rule: AuthoredRule = { id: 'r', name: 'R', technique: 'T1', scope: 'management', condition: { field: 'name', op: 'exists' }, responses: ['alert'] };
  assert.equal(validateAuthoredRule(rule, RESPONSE_IDS).ok, true);
});

test('rejects unknown scope, unknown response, missing fields, unknown op', () => {
  assert.match(validateAuthoredRule({ id: 'r', name: 'R', technique: 'T1', scope: 'nope', condition: { field: 'name', op: 'exists' }, responses: ['alert'] }, RESPONSE_IDS).errors.join(' '), /not a known scope/);
  assert.match(validateAuthoredRule({ id: 'r', name: 'R', technique: 'T1', scope: 'management', condition: { field: 'name', op: 'exists' }, responses: ['ohno'] }, RESPONSE_IDS).errors.join(' '), /unknown response id/);
  assert.match(validateAuthoredRule({ id: 'r', name: 'R', technique: 'T1', scope: 'management', condition: { field: 'name', op: 'bogus' }, responses: ['alert'] }, RESPONSE_IDS).errors.join(' '), /unknown op/);
  assert.equal(validateAuthoredRule({ name: 'R' }, RESPONSE_IDS).ok, false);
});

test('rejects oversize and over-deep conditions (DoS guards)', () => {
  const big = { id: 'r', name: 'x'.repeat(SCHEMA_LIMITS.maxJsonBytes), technique: 'T1', scope: 'management', condition: { field: 'name', op: 'exists' }, responses: ['alert'] };
  assert.equal(validateAuthoredRule(big, RESPONSE_IDS).ok, false);

  let deep: Condition = { field: 'name', op: 'exists' };
  for (let i = 0; i < SCHEMA_LIMITS.maxConditionDepth + 5; i++) deep = { not: deep };
  assert.match(validateAuthoredRule({ id: 'r', name: 'R', technique: 'T1', scope: 'management', condition: deep, responses: ['alert'] }, RESPONSE_IDS).errors.join(' '), /depth/);
});

// ---- compile + run end to end ----------------------------------------------

test('a compiled user rule fires in the engine on a matching signal only', () => {
  const noop: Response<unknown> = { id: 'noop', name: 'noop', action: () => {} };
  const registry = new Map<string, Response<unknown>>([['alert', noop], ['disableExtension', noop]]);
  const authored: AuthoredRule = {
    id: 'user.dev', name: 'Dev extensions', technique: 'T1176.001', scope: 'management',
    condition: { field: 'payload.installType', op: 'eq', value: 'development' }, responses: ['alert'],
  };
  assert.equal(validateAuthoredRule(authored, RESPONSE_IDS).ok, true);

  const engine = new Engine();
  engine.setUserRules([compileAuthoredRule(authored, registry) as Rule<unknown>]);

  const hit = mgmtSignal({ installType: 'development' });
  engine.processSignal(hit);
  assert.equal(hit.hits.length, 1);
  assert.equal(hit.hits[0].ruleId, 'user.dev');

  const miss = mgmtSignal({ installType: 'normal' });
  engine.processSignal(miss);
  assert.equal(miss.hits.length, 0);
});

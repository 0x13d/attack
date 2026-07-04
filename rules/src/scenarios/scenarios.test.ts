import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildRules } from '../rules';
import { DEFAULT_POLICY } from '../config';
import { runScenarios } from './run';
import { CORPUS } from './corpus';

test('the community corpus is clean against the community rule set (0 misses, 0 false positives)', () => {
  const report = runScenarios(buildRules(DEFAULT_POLICY), CORPUS);
  const misses = report.results.filter((r) => r.outcome === 'missed').map((r) => `${r.technique}:${r.label}`);
  const fps = report.results.filter((r) => r.outcome === 'false-positive').map((r) => `${r.technique}:${r.label}`);
  assert.deepEqual(misses, [], `false negatives: ${misses.join(', ')}`);
  assert.deepEqual(fps, [], `false positives: ${fps.join(', ')}`);
  assert.ok(report.clean);
});

test('every one of the 16 techniques has at least one malicious and one benign case', () => {
  const TECHNIQUES = [
    'T1176.001', 'T1176', 'T1217', 'T1566.002', 'T1528', 'T1189', 'T1656', 'T1566.003',
    'T1204.001', 'T1606.002', 'T1185', 'T1105', 'T1204.002', 'T1566.001', 'T1539', 'T1550.004',
  ];
  for (const t of TECHNIQUES) {
    const cases = CORPUS.filter((c) => c.technique === t);
    assert.ok(cases.some((c) => c.malicious), `no malicious case for ${t}`);
    assert.ok(cases.some((c) => !c.malicious), `no benign case for ${t}`);
  }
});

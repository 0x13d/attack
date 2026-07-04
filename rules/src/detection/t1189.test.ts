import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessDriveBy } from './t1189';

test('a redirect chain at/above the threshold is flagged', () => {
  assert.equal(assessDriveBy(3, 3).driveBy, true);
  const r = assessDriveBy(5, 3);
  assert.equal(r.driveBy, true);
  assert.match(r.reasons.join(' '), /chain of 5 hops/);
});

test('a chain below the threshold is not flagged', () => {
  assert.equal(assessDriveBy(2, 3).driveBy, false);
  assert.equal(assessDriveBy(0, 3).driveBy, false);
});

test('threshold is tunable', () => {
  assert.equal(assessDriveBy(2, 2).driveBy, true);
  assert.equal(assessDriveBy(1, 2).driveBy, false);
});

test('non-finite chain length is ignored', () => {
  assert.equal(assessDriveBy(NaN, 3).driveBy, false);
});

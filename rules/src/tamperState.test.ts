import { test } from 'node:test';
import assert from 'node:assert/strict';
import { markDisabledByEdr, wasDisabledByEdr, getEdrDisabledIds, __resetTamperState } from './tamperState';

// persist() is guarded on chrome.storage, so mark/was work chrome-free in the test runner.
test('marks and recalls EDR-disabled extension ids', () => {
  __resetTamperState();
  assert.equal(wasDisabledByEdr('abc'), false);
  markDisabledByEdr('abc');
  assert.equal(wasDisabledByEdr('abc'), true);
  assert.ok(getEdrDisabledIds().has('abc'));
});

test('ignores empty ids', () => {
  __resetTamperState();
  markDisabledByEdr('');
  assert.equal(getEdrDisabledIds().size, 0);
});

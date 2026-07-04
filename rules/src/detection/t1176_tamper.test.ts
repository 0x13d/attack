import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isReEnableTamper } from './t1176_tamper';

const disabled = new Set<string>(['rogue-ext-id']);

test('fires on re-enable of an EDR-disabled extension', () => {
  assert.equal(isReEnableTamper('management.enabled', 'rogue-ext-id', disabled), true);
});

test('does NOT fire on install (only re-enable is tamper)', () => {
  assert.equal(isReEnableTamper('management.installed', 'rogue-ext-id', disabled), false);
});

test('does NOT fire for an extension the EDR never disabled', () => {
  assert.equal(isReEnableTamper('management.enabled', 'some-other-id', disabled), false);
});

test('does NOT fire on an empty id', () => {
  assert.equal(isReEnableTamper('management.enabled', '', disabled), false);
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectReverseTabnab, originOf } from './t1185';

test('originOf extracts origin, null on garbage', () => {
  assert.equal(originOf('https://evil.example/login?x=1'), 'https://evil.example');
  assert.equal(originOf('nonsense'), null);
});

test('flags an opener tab client-redirected to a different origin', () => {
  const r = detectReverseTabnab({ isOpener: true, fromOrigin: 'https://bank.example', toOrigin: 'https://evil.example', isClientRedirect: true });
  assert.equal(r.detected, true);
  assert.match(r.reason!, /reverse tabnabbing/);
});

test('does not flag a non-opener tab', () => {
  assert.equal(detectReverseTabnab({ isOpener: false, fromOrigin: 'https://a.example', toOrigin: 'https://b.example', isClientRedirect: true }).detected, false);
});

test('does not flag a user-initiated navigation (not a client redirect)', () => {
  assert.equal(detectReverseTabnab({ isOpener: true, fromOrigin: 'https://a.example', toOrigin: 'https://b.example', isClientRedirect: false }).detected, false);
});

test('does not flag a same-origin redirect', () => {
  assert.equal(detectReverseTabnab({ isOpener: true, fromOrigin: 'https://a.example', toOrigin: 'https://a.example', isClientRedirect: true }).detected, false);
});

test('does not flag when the prior origin is unknown', () => {
  assert.equal(detectReverseTabnab({ isOpener: true, fromOrigin: null, toOrigin: 'https://b.example', isClientRedirect: true }).detected, false);
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessMaliciousLink } from './t1204_001';

const BLOCKLIST = ['known-bad.test', 'malware-delivery.example'];
const a = (url: string) => assessMaliciousLink(url, BLOCKLIST);

test('navigation to a blocklisted host is flagged', () => {
  const r = a('https://known-bad.test/login');
  assert.equal(r.malicious, true);
  assert.equal(r.matchedIndicator, 'known-bad.test');
  assert.match(r.reasons.join(' '), /threat-IOC match: known-bad\.test/);
});

test('a subdomain of a blocklisted domain is flagged', () => {
  assert.equal(a('https://cdn.known-bad.test/x').malicious, true);
});

test('a normal destination is not flagged', () => {
  assert.equal(a('https://github.com/login').malicious, false);
  assert.equal(a('https://example.com/').malicious, false);
});

test('IOC match is case-insensitive', () => {
  assert.equal(a('https://KNOWN-BAD.test/').malicious, true);
});

test('a host that merely contains the IOC string is NOT flagged (no substring false-positive)', () => {
  // not-known-bad.test endsWith 'known-bad.test'? no — endsWith requires the dot boundary
  assert.equal(a('https://notknown-bad.test.evil.example/').malicious, false);
  assert.equal(a('https://known-bad.test.evil.example/').malicious, false); // different registrable parent
});

test('localhost / unparseable are ignored', () => {
  assert.equal(a('http://localhost:8000/known-bad.test').malicious, false);
  assert.equal(a('nonsense').malicious, false);
});

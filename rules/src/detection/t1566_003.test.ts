import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessViaService } from './t1566_003';

const PARAMS = ['url', 'redirect', 'redirect_uri', 'next', 'returnurl', 'dest', 'continue', 'target'];
const a = (url: string) => assessViaService(url, PARAMS);

test('off-domain open-redirect is flagged', () => {
  const r = a('https://service.example/login?next=https://evil.test/steal');
  assert.equal(r.viaService, true);
  assert.equal(r.redirectTo, 'evil.test');
  assert.match(r.reasons.join(' '), /open-redirect via service\.example/);
});

test('percent-encoded redirect value is decoded + flagged', () => {
  assert.equal(a('https://trusted.example/r?url=https%3A%2F%2Fphish.test%2Fp').viaService, true);
});

test('redirect-param key match is case-insensitive', () => {
  assert.equal(a('https://trusted.example/r?ReturnUrl=https://phish.test/').viaService, true);
});

test('same-domain redirect is NOT flagged (benign return path)', () => {
  assert.equal(a('https://app.example/login?next=https://app.example/dashboard').viaService, false);
  // subdomain of the same registrable domain is still same-site
  assert.equal(a('https://auth.example.com/r?url=https://www.example.com/home').viaService, false);
});

test('a relative redirect value (no host) is NOT flagged', () => {
  assert.equal(a('https://app.example/login?next=/dashboard').viaService, false);
});

test('no redirect param → not flagged', () => {
  assert.equal(a('https://service.example/page?q=hello').viaService, false);
});

test('localhost / unparseable urls are ignored', () => {
  assert.equal(a('http://localhost:8000/?next=https://evil.test/').viaService, false);
  assert.equal(a('not a url').viaService, false);
});

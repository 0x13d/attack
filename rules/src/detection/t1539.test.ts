import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessCookie, CookieLike } from './t1539';

const PATTERNS = ['session', 'sess', 'sid', 'auth', 'token', 'jwt', 'sso', 'login'];
const a = (c: Partial<CookieLike>) => assessCookie({ name: 'x', secure: true, httpOnly: true, sameSite: 'lax', ...c }, PATTERNS);

test('a non-session cookie is never flagged, even with weak flags', () => {
  const r = a({ name: 'theme', secure: false, httpOnly: false, sameSite: 'no_restriction' });
  assert.equal(r.theftRisk, false);
  assert.equal(r.isSession, false);
});

test('a properly-secured session cookie is not flagged', () => {
  const r = a({ name: 'sessionid', secure: true, httpOnly: true, sameSite: 'lax' });
  assert.equal(r.isSession, true);
  assert.equal(r.theftRisk, false);
});

test('session cookie not Secure is flagged', () => {
  const r = a({ name: 'JSESSIONID', secure: false });
  assert.equal(r.theftRisk, true);
  assert.match(r.reasons.join(' '), /not Secure/);
});

test('session cookie not HttpOnly is flagged (XSS-readable)', () => {
  const r = a({ name: 'auth_token', httpOnly: false });
  assert.equal(r.theftRisk, true);
  assert.match(r.reasons.join(' '), /HttpOnly/);
});

test('session cookie SameSite=None is flagged', () => {
  const r = a({ name: 'sid', sameSite: 'no_restriction' });
  assert.equal(r.theftRisk, true);
  assert.match(r.reasons.join(' '), /SameSite=None/);
});

test('multiple weak flags accumulate reasons', () => {
  const r = a({ name: 'jwt', secure: false, httpOnly: false, sameSite: 'no_restriction' });
  assert.equal(r.theftRisk, true);
  assert.equal(r.reasons.length, 3);
});

test('name matching is case-insensitive and substring', () => {
  assert.equal(a({ name: 'X-Auth-Token', secure: false }).isSession, true);
  assert.equal(a({ name: 'connect.sid', httpOnly: false }).isSession, true);
});

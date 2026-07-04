import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessSessionReuse, SessionCookieLike } from './t1550_004';

const PATTERNS = ['session', 'sess', 'sid', 'auth', 'token', 'jwt', 'sso', 'login'];
const a = (c: Partial<SessionCookieLike>) =>
  assessSessionReuse({ name: 'sessionid', session: true, domain: 'app.example', ...c }, PATTERNS);

test('a session/auth cookie made persistent is flagged (reuse)', () => {
  const r = a({ name: 'sessionid', session: false, expirationDate: 1893456000 });
  assert.equal(r.reuse, true);
  assert.match(r.reasons.join(' '), /made persistent/);
});

test('a true session cookie (expire-on-close) is NOT flagged', () => {
  assert.equal(a({ name: 'sessionid', session: true }).reuse, false);
});

test('a persistent NON-session cookie is not flagged', () => {
  assert.equal(a({ name: 'theme', session: false, expirationDate: 1893456000 }).reuse, false);
});

test('matches auth-ish names case-insensitively', () => {
  assert.equal(a({ name: 'X-Auth-Token', session: false }).reuse, true);
  assert.equal(a({ name: 'JSESSIONID', session: false }).reuse, true);
});

test('falls back gracefully when expirationDate is absent', () => {
  const r = a({ name: 'jwt', session: false });
  assert.equal(r.reuse, true);
  assert.match(r.reasons.join(' '), /a future date/);
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessOAuthConsent } from './t1528';

const SCOPES = ['offline_access', 'mail.read', 'files.read.all', 'https://mail.google.com/'];
const a = (url: string, approved: string[] = []) => assessOAuthConsent(url, SCOPES, approved);

test('flags a Microsoft authorize URL requesting offline_access + mail.read', () => {
  const r = a('https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=evil&scope=offline_access%20mail.read&redirect_uri=https://evil.example');
  assert.equal(r.risk, true);
  assert.deepEqual(r.riskyScopes, ['offline_access', 'mail.read']);
  assert.match(r.reasons.join(' '), /high-risk scopes/);
});

test('flags a Google OAuth consent for full mail access', () => {
  const r = a('https://accounts.google.com/o/oauth2/v2/auth?client_id=x&scope=https://mail.google.com/');
  assert.equal(r.risk, true);
});

test('does not flag a benign sign-in (openid profile email)', () => {
  const r = a('https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=x&scope=openid%20profile%20email');
  assert.equal(r.risk, false);
});

test('does not flag a non-authorize URL even with scope-like params', () => {
  assert.equal(a('https://example.com/search?scope=offline_access').risk, false);
});

test('adds an unknown-client reason when an allowlist is set', () => {
  const r = a('https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=sketchy&scope=mail.read', ['trusted-app-id']);
  assert.equal(r.risk, true);
  assert.match(r.reasons.join(' '), /unknown OAuth client_id: sketchy/);
});

test('an approved client still flags on scopes but without the client reason', () => {
  const r = a('https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=trusted&scope=mail.read', ['trusted']);
  assert.equal(r.risk, true);
  assert.doesNotMatch(r.reasons.join(' '), /unknown OAuth client/);
});

test('invalid url does not throw', () => {
  assert.equal(a('not a url').risk, false);
});

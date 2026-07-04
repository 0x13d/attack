import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessSamlFlow } from './t1606_002';

const a = (url: string, trusted: string[] = []) => assessSamlFlow(url, trusted);

test('a SAMLResponse param to a non-allowlisted host is flagged', () => {
  const r = a('https://sp.evil.example/acs?SAMLResponse=PHN...');
  assert.equal(r.saml, true);
  assert.match(r.reasons.join(' '), /SAML assertion param "SAMLResponse"/i);
});

test('an ACS/SSO path is flagged even without a param', () => {
  assert.equal(a('https://app.evil.example/saml2/acs').saml, true);
  assert.equal(a('https://app.evil.example/adfs/ls/').saml, true);
});

test('SAML param key match is case-insensitive', () => {
  assert.equal(a('https://x.example/sso?samlresponse=abc').saml, true);
});

test('a host on the allowlist is not flagged (expected IdP/SP)', () => {
  assert.equal(a('https://login.microsoftonline.com/saml2?SAMLResponse=x', ['microsoftonline.com']).saml, false);
  // subdomain of an allowlisted host is also trusted
  assert.equal(a('https://eu.okta.com/app/acs?SAMLResponse=x', ['okta.com']).saml, false);
});

test('a normal navigation with no SAML indicator is not flagged', () => {
  assert.equal(a('https://example.com/login?next=/home').saml, false);
});

test('localhost / unparseable are ignored', () => {
  assert.equal(a('http://localhost:8000/saml?SAMLResponse=x').saml, false);
  assert.equal(a('nonsense').saml, false);
});

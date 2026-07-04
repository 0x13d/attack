import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessNavigation, hostnameOf } from './t1566';

const BRANDS = ['paypal.com', 'google.com', 'github.com', 'microsoft.com'];
const a = (url: string) => assessNavigation(url, BRANDS);

test('hostnameOf parses and lowercases, returns null on garbage', () => {
  assert.equal(hostnameOf('https://PayPal.com/login'), 'paypal.com');
  assert.equal(hostnameOf('not a url'), null);
});

test('legitimate brand domains are never flagged', () => {
  assert.equal(a('https://www.paypal.com/signin').phishing, false);
  assert.equal(a('https://accounts.google.com/').phishing, false);
  assert.equal(a('https://github.com/login').phishing, false);
});

test('an unrelated domain is not flagged', () => {
  assert.equal(a('https://example.com/').phishing, false);
  assert.equal(a('https://news.ycombinator.com/').phishing, false);
});

test('homoglyph lookalike is flagged (paypa1.com → paypal)', () => {
  const r = a('http://paypa1.com/login');
  assert.equal(r.phishing, true);
  assert.equal(r.matchedBrand, 'paypal.com');
  assert.match(r.reasons.join(' '), /homoglyph/);
});

test('typosquat is flagged (paypall.com, githb.com)', () => {
  assert.equal(a('http://paypall.com/').phishing, true);
  const g = a('http://githb.com/');
  assert.equal(g.phishing, true);
  assert.match(g.reasons.join(' '), /typosquat of github\.com/);
});

test('subdomain impersonation is flagged (paypal.com.evil.net, login-at github sub)', () => {
  const r = a('http://paypal.com.secure-login.net/');
  assert.equal(r.phishing, true);
  assert.match(r.reasons.join(' '), /subdomain/);
  assert.equal(a('https://github.attacker.io/login').phishing, true);
});

test('localhost and the legit registrable domain with brand subdomain are safe', () => {
  assert.equal(a('http://localhost:8080/').phishing, false);
  // brand as a subdomain *of its own domain* is legit
  assert.equal(a('https://signin.paypal.com/').phishing, false);
});

test('invalid url does not throw and is not phishing', () => {
  assert.equal(a('javascript:void(0)').phishing, false);
  assert.equal(a('').phishing, false);
});

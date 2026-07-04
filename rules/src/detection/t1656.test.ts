import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessImpersonation } from './t1656';

const BRANDS = ['paypal.com', 'microsoft.com', 'github.com'];
const AUTH = ['login', 'signin', 'verify', 'secure', 'account'];
const a = (url: string) => assessImpersonation(url, BRANDS, AUTH);

test('brand term + auth keyword in the host on a non-brand domain is flagged', () => {
  const r = a('https://paypal-login.evil.com/verify');
  assert.equal(r.impersonation, true);
  assert.equal(r.matchedBrand, 'paypal');
});

test('brand term + auth keyword in the PATH on an unrelated domain is flagged', () => {
  assert.equal(a('https://cdn.example/microsoft/signin').impersonation, true);
});

test('the legit brand domain (and its subdomains) is never flagged', () => {
  assert.equal(a('https://accounts.paypal.com/login').impersonation, false);
  assert.equal(a('https://github.com/login').impersonation, false);
});

test('a brand term WITHOUT an auth keyword is not flagged (low FP)', () => {
  // a news article mentioning a brand shouldn't trip it
  assert.equal(a('https://news.example/articles/paypal-earnings-2026').impersonation, false);
});

test('an auth keyword WITHOUT a brand term is not flagged', () => {
  assert.equal(a('https://myapp.example/login').impersonation, false);
});

test('localhost / unparseable are ignored', () => {
  assert.equal(a('http://localhost:8000/paypal/login').impersonation, false);
  assert.equal(a('not a url').impersonation, false);
});

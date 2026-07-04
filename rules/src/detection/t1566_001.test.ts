import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessAttachment, AttachmentLike } from './t1566_001';

const EXTS = ['docm', 'dotm', 'xlsm', 'xltm', 'xlsb', 'pptm', 'potm', 'html', 'htm', 'svg', 'xhtml'];
const ORIGINS = ['mail.google.com', 'outlook.office.com', 'dropbox.com', 'wetransfer.com'];
const a = (d: Partial<AttachmentLike>) =>
  assessAttachment({ filename: 'f.docm', url: 'https://x.example/f.docm', referrer: '', ...d }, EXTS, ORIGINS);

test('attachment lure from a webmail/file-share referrer is flagged', () => {
  assert.equal(a({ filename: 'invoice.docm', referrer: 'https://mail.google.com/mail/u/0' }).spearphish, true);
  assert.equal(a({ filename: 'report.xlsm', referrer: 'https://outlook.office.com/mail/' }).spearphish, true);
  assert.equal(a({ filename: 'shared.html', referrer: 'https://www.dropbox.com/s/abc' }).spearphish, true);
});

test('subdomains of a delivery origin still match', () => {
  assert.equal(a({ filename: 'x.docm', referrer: 'https://eu.dropbox.com/s/x' }).spearphish, true);
});

test('attachment lure from a suspicious (http / bare-IP) referrer is flagged', () => {
  assert.equal(a({ filename: 'x.xlsm', referrer: 'http://phish.example/page' }).spearphish, true);
  assert.equal(a({ filename: 'x.svg', referrer: 'https://10.0.0.5/p' }).spearphish, true);
});

test('attachment lure with NO referrer (direct download) is NOT spearphishing', () => {
  assert.equal(a({ filename: 'macro.docm', referrer: '' }).spearphish, false);
});

test('attachment lure from a normal https site (not a delivery origin) is NOT flagged', () => {
  assert.equal(a({ filename: 'template.docm', referrer: 'https://docs.mycompany.example/templates' }).spearphish, false);
});

test('a non-attachment file from a delivery origin is NOT flagged here', () => {
  // a plain pdf/zip from webmail isn't this rule's lure class (disjoint from T1105/T1204.002)
  assert.equal(a({ filename: 'photo.png', referrer: 'https://mail.google.com/' }).spearphish, false);
  assert.equal(a({ filename: 'archive.zip', referrer: 'https://mail.google.com/' }).spearphish, false);
});

test('reason names the type and the delivery context', () => {
  const r = a({ filename: 'x.docm', referrer: 'https://mail.google.com/' });
  assert.match(r.reasons.join(' '), /spearphishing attachment: \.docm/);
  assert.match(r.reasons.join(' '), /mail\.google\.com/);
});

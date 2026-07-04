import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessDownload, DownloadLike } from './t1105';

const RISKY = ['hta', 'scr', 'pif', 'vbs', 'vbe', 'jse', 'wsf', 'bat', 'cmd', 'ps1', 'com', 'jar'];
const a = (d: Partial<DownloadLike>) => assessDownload({ filename: 'file', url: 'https://example.com/x', ...d }, RISKY);

test('a normal document/archive/image download is not flagged', () => {
  assert.equal(a({ filename: 'report.pdf' }).transferRisk, false);
  assert.equal(a({ filename: 'photos.zip' }).transferRisk, false);
  assert.equal(a({ filename: 'logo.png' }).transferRisk, false);
  assert.equal(a({ filename: 'notes.docx' }).transferRisk, false);
});

test('a plain .exe/.msi from https is NOT flagged on its own (too common)', () => {
  assert.equal(a({ filename: 'setup.exe' }).transferRisk, false);
  assert.equal(a({ filename: 'tool.msi' }).transferRisk, false);
});

test('a standalone .hta / .scr artifact is flagged', () => {
  const hta = a({ filename: 'invoice.hta' });
  assert.equal(hta.transferRisk, true);
  assert.equal(hta.extension, 'hta');
  assert.match(hta.reasons.join(' '), /executable\/script artifact/);
  assert.equal(a({ filename: 'screensaver.scr' }).transferRisk, true);
});

test('a double extension masking an executable is flagged (incl. .exe)', () => {
  const r = a({ filename: 'report.pdf.exe' });
  assert.equal(r.transferRisk, true);
  assert.match(r.reasons.join(' '), /double extension masks an executable \(\.pdf\.exe\)/);
  assert.equal(a({ filename: 'photo.jpg.scr' }).transferRisk, true);
});

test('detection is case-insensitive on the extension', () => {
  assert.equal(a({ filename: 'PAYLOAD.HTA' }).transferRisk, true);
  assert.equal(a({ filename: 'Report.PDF.Exe' }).transferRisk, true);
});

test('a suspicious origin adds an aggravating reason on a risky artifact', () => {
  const http = a({ filename: 'x.hta', url: 'http://1.2.3.4/x.hta' });
  assert.equal(http.transferRisk, true);
  // bare-IP host is checked before protocol; either insecure-HTTP or bare-IP reason is acceptable
  assert.match(http.reasons.join(' '), /insecure HTTP|bare IP host/);
});

test('a suspicious origin alone (benign artifact) does NOT trigger', () => {
  const r = a({ filename: 'readme.txt', url: 'http://1.2.3.4/readme.txt' });
  assert.equal(r.transferRisk, false);
});

test('userinfo in the URL is surfaced as a reason on a risky artifact', () => {
  const r = a({ filename: 'a.bat', url: 'https://user:pw@evil.example/a.bat' });
  assert.equal(r.transferRisk, true);
  assert.match(r.reasons.join(' '), /credentials\/userinfo/);
});

test('falls back to the URL path when filename is empty', () => {
  assert.equal(a({ filename: '', url: 'https://x.example/drop/run.scr' }).transferRisk, true);
});

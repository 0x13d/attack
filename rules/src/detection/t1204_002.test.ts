import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessMaliciousFile, FileLike } from './t1204_002';
import { assessDownload } from './t1105';

const LURES = ['lnk', 'iso', 'img', 'vhd', 'vhdx', 'msi', 'msix', 'appx', 'chm'];
const T1105_RISKY = ['hta', 'scr', 'pif', 'vbs', 'vbe', 'jse', 'wsf', 'bat', 'cmd', 'ps1', 'com', 'jar'];
const a = (d: Partial<FileLike>) => assessMaliciousFile({ filename: 'f', url: 'https://x.example/f', ...d }, LURES);

test('lure containers/shortcuts/installers are flagged', () => {
  for (const f of ['invoice.iso', 'photos.img', 'setup.msi', 'resume.lnk', 'help.chm', 'app.appx']) {
    assert.equal(a({ filename: f }).malicious, true, `${f} should flag`);
  }
});

test('mark-of-the-web bypass containers get the MOTW reason', () => {
  assert.match(a({ filename: 'x.iso' }).reasons.join(' '), /mark-of-the-web/);
  assert.match(a({ filename: 'x.lnk' }).reasons.join(' '), /double-clicked to run/);
});

test('normal downloads are not flagged', () => {
  for (const f of ['report.pdf', 'photos.zip', 'logo.png', 'setup.exe', 'notes.docx']) {
    assert.equal(a({ filename: f }).malicious, false, `${f} should not flag`);
  }
});

test('case-insensitive on extension', () => {
  assert.equal(a({ filename: 'Payload.ISO' }).malicious, true);
});

test('falls back to URL path when filename is empty', () => {
  assert.equal(a({ filename: '', url: 'https://x.example/drop/run.lnk' }).malicious, true);
});

// Honest-framing boundary: T1204.002 (lure containers) and T1105 (script/quasi-exe + double-ext) are disjoint —
// a single artifact must never trip both rules. (No relabeling the same hit with a different ATT&CK id.)
test('T1204.002 and T1105 do not double-fire on the same artifact', () => {
  // a lure container: T1204.002 yes, T1105 no
  assert.equal(a({ filename: 'malware.iso' }).malicious, true);
  assert.equal(assessDownload({ filename: 'malware.iso', url: 'https://x.example/malware.iso' }, T1105_RISKY).transferRisk, false);

  // a script artifact: T1105 yes, T1204.002 no
  assert.equal(assessDownload({ filename: 'evil.hta', url: 'https://x.example/evil.hta' }, T1105_RISKY).transferRisk, true);
  assert.equal(a({ filename: 'evil.hta' }).malicious, false);
});

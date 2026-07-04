import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessReconExtension, ReconAssessable } from './t1217';

const RECON = ['bookmarks', 'history', 'topSites'];
const a = (ext: Partial<ReconAssessable>, approved: string[] = []) =>
  assessReconExtension({ id: 'ext1', name: 'Demo', permissions: [], ...ext }, RECON, approved, 'self-id');

test('an extension holding a recon permission is flagged', () => {
  const r = a({ permissions: ['history', 'storage'] });
  assert.equal(r.recon, true);
  assert.deepEqual(r.reconPermissions, ['history']);
  assert.match(r.reasons.join(' '), /browser-data-discovery permissions \(history\)/);
});

test('multiple recon permissions are all reported', () => {
  assert.deepEqual(a({ permissions: ['bookmarks', 'topSites', 'tabs'] }).reconPermissions, ['bookmarks', 'topSites']);
});

test('an extension with no recon permissions is not flagged', () => {
  assert.equal(a({ permissions: ['storage', 'notifications'] }).recon, false);
});

test('self and approved extensions are never flagged', () => {
  assert.equal(a({ id: 'self-id', permissions: ['history'] }).recon, false);
  assert.equal(a({ id: 'ext1', permissions: ['history'] }, ['ext1']).recon, false);
});

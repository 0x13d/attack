import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessExtension, AssessableExtension } from './t1176';
import { DEFAULT_POLICY } from '../config';

const SELF = 'self-extension-id-0000000000000000';

function ext(over: Partial<AssessableExtension>): AssessableExtension {
  return {
    id: 'abcdefghijklmnopabcdefghijklmnop',
    name: 'Some Extension',
    installType: 'normal',
    permissions: [],
    hostPermissions: [],
    ...over,
  };
}

test('does not flag itself', () => {
  const a = assessExtension(ext({ id: SELF, installType: 'development', permissions: ['debugger'] }), DEFAULT_POLICY, SELF);
  assert.equal(a.rogue, false);
});

test('does not flag an approved extension even if risky', () => {
  const policy = { ...DEFAULT_POLICY, approvedExtensionIds: ['approved-id'] };
  const a = assessExtension(ext({ id: 'approved-id', installType: 'development', permissions: ['cookies'] }), policy, SELF);
  assert.equal(a.rogue, false);
});

test('does not flag a normal Web Store extension with ordinary permissions', () => {
  const a = assessExtension(ext({ installType: 'normal', permissions: ['storage', 'alarms'], hostPermissions: [] }), DEFAULT_POLICY, SELF);
  assert.equal(a.rogue, false);
  assert.deepEqual(a.reasons, []);
});

test('flags a sideloaded/unpacked extension (unmanaged install source)', () => {
  const a = assessExtension(ext({ installType: 'development', permissions: [] }), DEFAULT_POLICY, SELF);
  assert.equal(a.rogue, true);
  assert.match(a.reasons.join(' '), /unmanaged install source/);
});

test('flags high-risk permissions and lists them', () => {
  const a = assessExtension(ext({ installType: 'normal', permissions: ['cookies', 'webRequest', 'storage'] }), DEFAULT_POLICY, SELF);
  assert.equal(a.rogue, true);
  assert.deepEqual(a.riskyPermissions, ['cookies', 'webRequest']);
  assert.match(a.reasons.join(' '), /high-risk permissions/);
});

test('flags broad host access', () => {
  const a = assessExtension(ext({ installType: 'normal', permissions: [], hostPermissions: ['<all_urls>'] }), DEFAULT_POLICY, SELF);
  assert.equal(a.rogue, true);
  assert.match(a.reasons.join(' '), /broad host access/);
});

test('the demo target trips all three signals', () => {
  // Mirrors targets/t1176/evil-extension: dev-loaded, risky perms, all-urls.
  const a = assessExtension(
    ext({ installType: 'development', permissions: ['cookies', 'webRequest', 'scripting', 'tabs'], hostPermissions: ['<all_urls>'] }),
    DEFAULT_POLICY,
    SELF,
  );
  assert.equal(a.rogue, true);
  assert.equal(a.reasons.length, 3);
});

test('admin-installed (managed) is not flagged for install source alone', () => {
  const a = assessExtension(ext({ installType: 'admin', permissions: ['storage'] }), DEFAULT_POLICY, SELF);
  assert.equal(a.rogue, false);
});

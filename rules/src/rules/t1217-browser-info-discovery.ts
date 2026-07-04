import { Policy, DEFAULT_POLICY } from '../config';
import { assessReconExtension } from '../detection/t1217';
import { makeAlertResponse } from '../responses/alert';
import { Rule, Scope, Signal, Signature } from '../types';

type ExtInfo = chrome.management.ExtensionInfo;

/**
 * **T1217 — Browser Information Discovery.** Fires when a non-approved extension **holds browser-data-discovery
 * permissions** (`bookmarks`/`history`/`topSites`) — positioned to enumerate them for recon. **Detect + alert**
 * (legit extensions hold these too, so no auto-disable; operators allowlist via `approvedExtensionIds`). Reuses
 * the `management` signal; no new permission.
 *
 * **Relationship:** distinct from T1176.001 (recon perms aren't in `highRiskPermissions`); a sideloaded ext with
 * recon perms fires both — one cause, two angles, by design.
 */
export function makeT1217Rule(policy: Policy = DEFAULT_POLICY): Rule<ExtInfo> {
  const signature: Signature<ExtInfo> = {
    id: 'sig.t1217.recon-extension',
    name: 'Extension with browser-data-discovery permissions',
    scope: Scope.MANAGEMENT,
    process: (signal: Signal<ExtInfo>) => {
      const ext = signal.payload;
      const assessment = assessReconExtension(
        { id: ext.id, name: ext.name, permissions: ext.permissions ?? [] },
        policy.reconPermissions,
        policy.approvedExtensionIds,
        chrome.runtime.id,
      );
      if (!assessment.recon) return false;
      signal.meta = {
        technique: 'T1217',
        extensionId: ext.id,
        extensionName: ext.name,
        reconPermissions: assessment.reconPermissions,
        reasons: assessment.reasons,
        relationship: 'recon-capability angle (bookmarks/history/topSites) — distinct from T1176.001; both can fire on a sideloaded recon extension',
      };
      return true;
    },
  };

  return {
    id: 'rule.t1217.browser-info-discovery',
    name: 'Browser Information Discovery (extension with recon permissions)',
    technique: 'T1217',
    scope: [Scope.MANAGEMENT],
    signatures: [signature],
    responses: [makeAlertResponse<ExtInfo>()],
    timeToLive: 3_600_000,
    cascade: { enabled: false, ruleIds: [] },
  };
}

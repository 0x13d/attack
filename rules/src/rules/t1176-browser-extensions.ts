import { Policy, DEFAULT_POLICY } from '../config';
import { assessExtension } from '../detection/t1176';
import { isReEnableTamper } from '../detection/t1176_tamper';
import { makeAlertResponse } from '../responses/alert';
import { disableExtensionResponse } from '../responses/disableExtension';
import { getEdrDisabledIds } from '../tamperState';
import { Rule, Scope, Signal, Signature } from '../types';

type ExtInfo = chrome.management.ExtensionInfo;

/**
 * **T1176.001 — Browser Extensions.** Fires when a non-approved extension is installed or enabled with a
 * rogue risk signal (sideloaded, high-risk permissions, or broad host access). On a hit it **alerts** and
 * **disables** the offending extension — detection + a real MV3 prevention lever.
 */
export function makeT1176Rule(policy: Policy = DEFAULT_POLICY): Rule<ExtInfo> {
  const signature: Signature<ExtInfo> = {
    id: 'sig.t1176.rogue-extension',
    name: 'Rogue / sideloaded browser extension',
    scope: Scope.MANAGEMENT,
    process: (signal: Signal<ExtInfo>) => {
      const ext = signal.payload;
      // Dedup: a re-enable of an extension the EDR disabled is T1176 *tamper* (ATK-223), not a fresh .001 hit.
      if (isReEnableTamper(signal.name, ext.id, getEdrDisabledIds())) return false;
      const assessment = assessExtension(
        {
          id: ext.id,
          name: ext.name,
          installType: ext.installType,
          permissions: ext.permissions ?? [],
          hostPermissions: ext.hostPermissions ?? [],
        },
        policy,
        chrome.runtime.id,
      );
      if (!assessment.rogue) return false;
      // Annotate the signal so the alert (and the ATK-206 trace) can explain *why* it fired.
      signal.meta = {
        technique: 'T1176.001',
        extensionId: ext.id,
        extensionName: ext.name,
        installType: ext.installType,
        reasons: assessment.reasons,
        riskyPermissions: assessment.riskyPermissions,
      };
      return true;
    },
  };

  return {
    id: 'rule.t1176.browser-extensions',
    name: 'Browser Extensions (rogue install/enable)',
    technique: 'T1176.001',
    scope: [Scope.MANAGEMENT],
    signatures: [signature],
    responses: [makeAlertResponse<ExtInfo>(), disableExtensionResponse],
    timeToLive: 3_600_000,
    cascade: { enabled: false, ruleIds: [] },
  };
}

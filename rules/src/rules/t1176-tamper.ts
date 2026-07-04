import { Policy, DEFAULT_POLICY } from '../config';
import { isReEnableTamper } from '../detection/t1176_tamper';
import { makeAlertResponse } from '../responses/alert';
import { disableExtensionResponse } from '../responses/disableExtension';
import { getEdrDisabledIds } from '../tamperState';
import { Rule, Scope, Signal, Signature } from '../types';

type ExtInfo = chrome.management.ExtensionInfo;

/**
 * **T1176 — Browser Extensions (tamper / persistence).** Fires when an extension the **EDR previously disabled**
 * is **re-enabled** — an attacker or another extension reviving a killed rogue to keep persistence. Distinct
 * from T1176.001 (rogue install/enable): keyed on the EDR-disabled → re-enabled **state transition**, not the
 * extension's rogue-ness, so it never relabels a .001 hit (T1176.001 defers this case). On a hit it **alerts**
 * and **re-disables** the extension — the EDR re-asserts the kill. Reuses `management`; no new permission.
 */
export function makeT1176TamperRule(_policy: Policy = DEFAULT_POLICY): Rule<ExtInfo> {
  const signature: Signature<ExtInfo> = {
    id: 'sig.t1176.tamper-re-enable',
    name: 'EDR-disabled extension re-enabled (persistence / tamper)',
    scope: Scope.MANAGEMENT,
    process: (signal: Signal<ExtInfo>) => {
      const ext = signal.payload;
      if (!isReEnableTamper(signal.name, ext.id, getEdrDisabledIds())) return false;
      signal.meta = {
        technique: 'T1176',
        extensionId: ext.id,
        extensionName: ext.name,
        reasons: ['an extension the EDR disabled was re-enabled — persistence / EDR-evasion'],
      };
      return true;
    },
  };

  return {
    id: 'rule.t1176.tamper',
    name: 'Browser Extensions (tamper — re-enable of an EDR-disabled extension)',
    technique: 'T1176',
    scope: [Scope.MANAGEMENT],
    signatures: [signature],
    responses: [makeAlertResponse<ExtInfo>(), disableExtensionResponse],
    timeToLive: 3_600_000,
    cascade: { enabled: false, ruleIds: [] },
  };
}

import { Policy, DEFAULT_POLICY } from '../config';
import { assessDriveBy } from '../detection/t1189';
import { makeAlertResponse } from '../responses/alert';
import { closeTabResponse } from '../responses/closeTab';
import { Response, Rule, Scope, Signal, Signature } from '../types';

type Nav = { url: string; transitionType: string; redirectChainLength?: number };

/**
 * **T1189 — Drive-by Compromise.** Fires when a tab is bounced through an **automatic client-redirect chain**
 * of `driveByRedirectThreshold`+ hops with no user interaction (the webNavigation signal counts the chain per
 * tab; a user-initiated navigation resets it). On a hit it **alerts** and **closes the tab**. Reuses
 * `webNavigation`; no new permission.
 *
 * **Relationship:** keyed on redirect *behavior*, distinct from the destination-keyed rules (T1566.002 / .003 /
 * T1204.001). Heuristic only — exploit/payload analysis is out of scope.
 */
export function makeT1189Rule(policy: Policy = DEFAULT_POLICY): Rule<Nav> {
  const signature: Signature<Nav> = {
    id: 'sig.t1189.redirect-chain',
    name: 'Automatic client-redirect chain (drive-by delivery)',
    scope: Scope.WEB_NAVIGATION,
    process: (signal: Signal<Nav>) => {
      const len = signal.payload.redirectChainLength ?? 0;
      const assessment = assessDriveBy(len, policy.driveByRedirectThreshold);
      if (!assessment.driveBy) return false;
      signal.meta = {
        technique: 'T1189',
        url: signal.payload.url,
        redirectChainLength: len,
        reasons: assessment.reasons,
        relationship: 'keyed on redirect-chain behavior — distinct from the destination-keyed webNavigation rules (T1566.002/.003, T1204.001)',
      };
      return true;
    },
  };

  return {
    id: 'rule.t1189.drive-by',
    name: 'Drive-by Compromise (client-redirect chain)',
    technique: 'T1189',
    scope: [Scope.WEB_NAVIGATION],
    signatures: [signature],
    responses: [makeAlertResponse<Nav>(), closeTabResponse as unknown as Response<Nav>],
    timeToLive: 3_600_000,
    cascade: { enabled: false, ruleIds: [] },
  };
}

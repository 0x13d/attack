import { Policy, DEFAULT_POLICY } from '../config';
import { makeAlertResponse } from '../responses/alert';
import { closeTabResponse } from '../responses/closeTab';
import { Response, Rule, Scope, Signal, Signature } from '../types';

type Nav = { url: string; transitionType: string; fromOrigin?: string | null; toOrigin?: string };

/**
 * **T1185 — Browser Session Hijacking (reverse tabnabbing).** A cross-tab attack: the webNavigation signal
 * source flags when an *opener* tab is script-redirected to a new origin (detection in `t1185.ts`). This rule
 * matches that flagged signal, alerts, and closes the hijacked tab. Needs only `webNavigation`.
 */
export function makeT1185Rule(_policy: Policy = DEFAULT_POLICY): Rule<Nav> {
  const signature: Signature<Nav> = {
    id: 'sig.t1185.reverse-tabnab',
    name: 'Reverse tabnabbing (opener tab rewritten)',
    scope: Scope.WEB_NAVIGATION,
    process: (signal: Signal<Nav>) => {
      if (signal.name !== 'webNavigation.reverseTabnab') return false;
      signal.meta = {
        technique: 'T1185',
        url: signal.payload.url,
        reasons: [`opener tab rewritten ${signal.payload.fromOrigin ?? '?'} → ${signal.payload.toOrigin ?? '?'} via client redirect`],
      };
      return true;
    },
  };

  return {
    id: 'rule.t1185.reverse-tabnabbing',
    name: 'Browser Session Hijacking (reverse tabnabbing)',
    technique: 'T1185',
    scope: [Scope.WEB_NAVIGATION],
    signatures: [signature],
    responses: [makeAlertResponse<Nav>(), closeTabResponse as unknown as Response<Nav>],
    timeToLive: 3_600_000,
    cascade: { enabled: false, ruleIds: [] },
  };
}

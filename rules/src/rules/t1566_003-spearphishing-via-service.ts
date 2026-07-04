import { Policy, DEFAULT_POLICY } from '../config';
import { assessViaService } from '../detection/t1566_003';
import { makeAlertResponse } from '../responses/alert';
import { Rule, Scope, Signal, Signature } from '../types';

type Nav = { url: string; transitionType: string };

/**
 * **T1566.003 — Spearphishing via Service.** Fires when a navigation is laundered through a trusted service's
 * **open-redirect** — a redirect parameter pointing **off-domain**. Detect + alert (the destination may be
 * legitimate in benign open-redirects; low-FP, no auto-block). Reuses `webNavigation`; no new permission.
 *
 * **Relationship:** distinct signal from the shipped T1566.002 (brand-lookalike *domain*) — here a *legit*
 * service is *abused* to redirect off-domain. Both can fire on one crafted URL (open-redirect → a lookalike);
 * that's two real findings by design (clients mix/tune). See `detection/t1566_003.ts`.
 */
export function makeT1566_003Rule(policy: Policy = DEFAULT_POLICY): Rule<Nav> {
  const signature: Signature<Nav> = {
    id: 'sig.t1566_003.via-service-open-redirect',
    name: 'Spearphishing via service (off-domain open-redirect)',
    scope: Scope.WEB_NAVIGATION,
    process: (signal: Signal<Nav>) => {
      const assessment = assessViaService(signal.payload.url, policy.openRedirectParams);
      if (!assessment.viaService) return false;
      signal.meta = {
        technique: 'T1566.003',
        url: signal.payload.url,
        redirectTo: assessment.redirectTo,
        reasons: assessment.reasons,
        relationship: 'distinct from T1566.002 (lookalike domain) — keyed on an abused open-redirect, not brand similarity',
      };
      return true;
    },
  };

  return {
    id: 'rule.t1566_003.spearphishing-via-service',
    name: 'Spearphishing via Service (open-redirect off-domain)',
    technique: 'T1566.003',
    scope: [Scope.WEB_NAVIGATION],
    signatures: [signature],
    responses: [makeAlertResponse<Nav>()],
    timeToLive: 3_600_000,
    cascade: { enabled: false, ruleIds: [] },
  };
}

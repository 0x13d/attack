import { Policy, DEFAULT_POLICY } from '../config';
import { assessNavigation } from '../detection/t1566';
import { makeAlertResponse } from '../responses/alert';
import { closeTabResponse } from '../responses/closeTab';
import { Response, Rule, Scope, Signal, Signature } from '../types';

type Nav = { url: string; transitionType: string };

/**
 * **T1566.002 — Spearphishing Link.** Fires when a top-frame navigation lands on a lookalike / typosquat of a
 * protected login domain. On a hit it **alerts** and **closes the tab** (active prevention).
 */
export function makeT1566Rule(policy: Policy = DEFAULT_POLICY): Rule<Nav> {
  const signature: Signature<Nav> = {
    id: 'sig.t1566.lookalike-login',
    name: 'Lookalike / typosquat login domain',
    scope: Scope.WEB_NAVIGATION,
    process: (signal: Signal<Nav>) => {
      const assessment = assessNavigation(signal.payload.url, policy.protectedDomains);
      if (!assessment.phishing) return false;
      signal.meta = {
        technique: 'T1566.002',
        url: signal.payload.url,
        matchedBrand: assessment.matchedBrand,
        reasons: assessment.reasons,
      };
      return true;
    },
  };

  return {
    id: 'rule.t1566.spearphishing-link',
    name: 'Spearphishing Link (lookalike login)',
    technique: 'T1566.002',
    scope: [Scope.WEB_NAVIGATION],
    signatures: [signature],
    responses: [makeAlertResponse<Nav>(), closeTabResponse as unknown as Response<Nav>],
    timeToLive: 3_600_000,
    cascade: { enabled: false, ruleIds: [] },
  };
}

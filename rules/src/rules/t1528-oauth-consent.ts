import { Policy, DEFAULT_POLICY } from '../config';
import { assessOAuthConsent } from '../detection/t1528';
import { makeAlertResponse } from '../responses/alert';
import { closeTabResponse } from '../responses/closeTab';
import { Response, Rule, Scope, Signal, Signature } from '../types';

type Nav = { url: string; transitionType: string };

/**
 * **T1528 — Illicit OAuth Consent.** Fires on a navigation to an OAuth authorize endpoint requesting
 * high-risk scopes (consent phishing) → alert + close the tab. Reuses the `webNavigation` signal — no new
 * permission. Fills the identity-attack parity gap.
 */
export function makeT1528Rule(policy: Policy = DEFAULT_POLICY): Rule<Nav> {
  const signature: Signature<Nav> = {
    id: 'sig.t1528.oauth-consent',
    name: 'Illicit OAuth consent (high-risk scopes)',
    scope: Scope.WEB_NAVIGATION,
    process: (signal: Signal<Nav>) => {
      if (signal.name !== 'webNavigation.committed') return false;
      const assessment = assessOAuthConsent(signal.payload.url, policy.highRiskOAuthScopes, policy.approvedOAuthClients);
      if (!assessment.risk) return false;
      signal.meta = {
        technique: 'T1528',
        url: signal.payload.url,
        riskyScopes: assessment.riskyScopes,
        reasons: assessment.reasons,
      };
      return true;
    },
  };

  return {
    id: 'rule.t1528.oauth-consent',
    name: 'Illicit OAuth Consent (steal access token)',
    technique: 'T1528',
    scope: [Scope.WEB_NAVIGATION],
    signatures: [signature],
    responses: [makeAlertResponse<Nav>(), closeTabResponse as unknown as Response<Nav>],
    timeToLive: 3_600_000,
    cascade: { enabled: false, ruleIds: [] },
  };
}

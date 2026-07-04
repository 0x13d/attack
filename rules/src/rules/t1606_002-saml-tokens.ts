import { Policy, DEFAULT_POLICY } from '../config';
import { assessSamlFlow } from '../detection/t1606_002';
import { makeAlertResponse } from '../responses/alert';
import { Rule, Scope, Signal, Signature } from '../types';

type Nav = { url: string; transitionType: string };

/**
 * **T1606.002 — Forge Web Credentials: SAML Tokens.** Fires when a navigation carries a SAML assertion indicator
 * (a `SAMLResponse`/`SAMLRequest`/`SAMLart` param, or an ACS/SSO path) to a host not in `policy.samlTrustedHosts`
 * — a SAML flow to an unexpected endpoint worth scrutiny for forged / golden-SAML. **Detect + alert** (heuristic;
 * the browser can't validate the assertion). Reuses `webNavigation`; no new permission.
 *
 * **Relationship:** an SSO/credential-forging signal, distinct from the phishing-nav rules (lookalike / redirect
 * / blocklist / impersonation). Operator allowlists IdP/SP hosts to tune; empty default = SAML-flow visibility.
 */
export function makeT1606_002Rule(policy: Policy = DEFAULT_POLICY): Rule<Nav> {
  const signature: Signature<Nav> = {
    id: 'sig.t1606_002.saml-token-flow',
    name: 'SAML-token flow to a non-allowlisted endpoint',
    scope: Scope.WEB_NAVIGATION,
    process: (signal: Signal<Nav>) => {
      const assessment = assessSamlFlow(signal.payload.url, policy.samlTrustedHosts);
      if (!assessment.saml) return false;
      signal.meta = {
        technique: 'T1606.002',
        url: signal.payload.url,
        reasons: assessment.reasons,
        relationship: 'SSO/credential-forging visibility signal — distinct from the phishing-nav rules (lookalike/redirect/blocklist/impersonation)',
      };
      return true;
    },
  };

  return {
    id: 'rule.t1606_002.saml-tokens',
    name: 'Forge Web Credentials: SAML Tokens (SAML flow to an unexpected host)',
    technique: 'T1606.002',
    scope: [Scope.WEB_NAVIGATION],
    signatures: [signature],
    responses: [makeAlertResponse<Nav>()],
    timeToLive: 3_600_000,
    cascade: { enabled: false, ruleIds: [] },
  };
}

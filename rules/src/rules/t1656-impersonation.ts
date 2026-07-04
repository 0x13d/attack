import { Policy, DEFAULT_POLICY } from '../config';
import { assessImpersonation } from '../detection/t1656';
import { makeAlertResponse } from '../responses/alert';
import { Rule, Scope, Signal, Signature } from '../types';

type Nav = { url: string; transitionType: string };

/**
 * **T1656 — Impersonation.** Fires when a page impersonates a protected brand's login on a **non-brand domain**
 * — a brand term in the host/path together with an auth-context keyword. **Detect + alert** (brand+keyword is a
 * heuristic with more FP surface than a domain lookalike, so no auto-block). Reuses `webNavigation`; no new perm.
 *
 * **Relationship:** complements T1566.002 — .002 inspects the *host* (lookalike/typosquat/subdomain), T1656 the
 * *path + auth context*. Catches `paypal-login.evil.com/verify`-style URLs .002's exact-label logic misses; both
 * can fire on one URL by design.
 */
export function makeT1656Rule(policy: Policy = DEFAULT_POLICY): Rule<Nav> {
  const signature: Signature<Nav> = {
    id: 'sig.t1656.brand-login-impersonation',
    name: 'Brand login impersonation on a non-brand domain',
    scope: Scope.WEB_NAVIGATION,
    process: (signal: Signal<Nav>) => {
      const assessment = assessImpersonation(signal.payload.url, policy.protectedDomains, policy.impersonationAuthKeywords);
      if (!assessment.impersonation) return false;
      signal.meta = {
        technique: 'T1656',
        url: signal.payload.url,
        matchedBrand: assessment.matchedBrand,
        reasons: assessment.reasons,
        relationship: 'complements T1566.002 — keyed on brand term + auth context in the host/path, not a host lookalike',
      };
      return true;
    },
  };

  return {
    id: 'rule.t1656.impersonation',
    name: 'Impersonation (brand login on a non-brand domain)',
    technique: 'T1656',
    scope: [Scope.WEB_NAVIGATION],
    signatures: [signature],
    responses: [makeAlertResponse<Nav>()],
    timeToLive: 3_600_000,
    cascade: { enabled: false, ruleIds: [] },
  };
}
